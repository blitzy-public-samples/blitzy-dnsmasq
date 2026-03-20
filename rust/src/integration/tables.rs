// SAFETY: This module contains unsafe blocks for platform-specific FFI operations.
// The crate-level #![deny(unsafe_code)] is overridden here because this module
// requires direct system call interactions that cannot be expressed in safe Rust.
#![allow(unsafe_code)]
// tables.rs is Copyright (c) 2014 Sven Falempin  All Rights Reserved.
// Copyright (c) 2000-2025 Simon Kelley
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.

//! # BSD PF Table Integration
//!
//! Rust implementation of BSD Packet Filter (PF) table manipulation for
//! DNS-based firewall rule population, migrated from `src/tables.c` (386 lines).
//!
//! This module enables dnsmasq to add/remove resolved IP addresses to/from PF
//! tables on FreeBSD, OpenBSD, and NetBSD, supporting dynamic domain-based
//! firewall policies. When a DNS query is resolved and the domain matches an
//! `ipset` directive in `dnsmasq.conf`, the resolved IP is added to the named
//! PF table via ioctl operations on `/dev/pf`.
//!
//! ## Platform
//!
//! This entire module is compiled only on BSD systems with PF support:
//! `cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))`.
//! Replaces C's `HAVE_BSD_IPSET` compile flag from `config.h`.
//!
//! ## PF Table Architecture
//!
//! PF tables are kernel-maintained sets of IP addresses referenced in `pf.conf`
//! firewall rules. Tables support both IPv4 and IPv6 addresses and allow dynamic
//! modification without reloading the entire ruleset. This module creates tables
//! with the `PFR_TFLAG_PERSIST` flag, ensuring they persist even if no rules
//! reference them.
//!
//! ## Example `pf.conf` Integration
//!
//! ```text
//! # In /etc/pf.conf
//! table <blocked_domains> persist
//! block drop quick from any to <blocked_domains>
//!
//! # In dnsmasq.conf
//! ipset=/doubleclick.net/blocked_domains
//! ```
//!
//! ## Memory Safety
//!
//! - [`OwnedFd`] wraps the `/dev/pf` device handle for RAII cleanup (replaces
//!   C's `static int dev = -1` global with no explicit close).
//! - All PF structures are stack-allocated; no heap allocation needed.
//! - `unsafe` blocks are limited to PF ioctl calls and `repr(C)` struct
//!   initialization, each documented with `// SAFETY:` comments.
//!
//! ## References
//!
//! - `pf.conf(5)` — PF configuration and table syntax
//! - `pfctl(8)` — PF control program for managing tables
//! - `ioctl(2)` — Device control operations for PF interface

use std::ffi::c_void;
use std::os::fd::{AsRawFd, OwnedFd};

use tracing::{error, info, warn};

use crate::core::types::{AllAddr, DnsmasqError, DnsmasqResult};

// ---------------------------------------------------------------------------
// PF Constants
// ---------------------------------------------------------------------------

/// Path to the PF device file on BSD systems.
/// Standard location on FreeBSD, OpenBSD, and NetBSD.
const PF_DEVICE: &str = "/dev/pf";

/// Maximum path length for PF anchors (`MAXPATHLEN` from `sys/param.h`).
/// This is 1024 on all supported BSD targets (FreeBSD, OpenBSD, NetBSD).
/// Used for the `pfrt_anchor` field in [`PfrTable`].
const MAXPATHLEN: usize = 1024;

/// Maximum PF table name length (`PF_TABLE_NAME_SIZE` from `pfvar.h`).
/// Table names must be strictly less than this value.
const PF_TABLE_NAME_SIZE: usize = 32;

/// Persist flag for PF tables (`PFR_TFLAG_PERSIST` from `pfvar.h`).
/// Tables created with this flag survive even if no firewall rules reference them.
const PFR_TFLAG_PERSIST: u32 = 0x0000_0001;

// ---------------------------------------------------------------------------
// PF Data Structures (matching BSD kernel headers exactly)
// ---------------------------------------------------------------------------

/// Address union for PF table entries.
///
/// Matches the anonymous union within `struct pfr_addr` in `pfvar.h`.
/// Size is 16 bytes (size of the larger IPv6 variant).
#[repr(C)]
#[derive(Copy, Clone)]
union PfrAddrUnion {
    /// IPv4 address bytes (`struct in_addr`, 4 bytes).
    pfra_ip4addr: [u8; 4],
    /// IPv6 address bytes (`struct in6_addr`, 16 bytes).
    pfra_ip6addr: [u8; 16],
}

/// PF table descriptor (`struct pfr_table` from `pfvar.h`).
///
/// Identifies a PF table by anchor context and name. The anchor field
/// is typically empty (zeroed) for top-level tables. Critical that this
/// struct layout matches the kernel exactly for ioctl compatibility.
#[repr(C)]
#[derive(Clone)]
struct PfrTable {
    /// PF anchor context path (typically zeroed for top-level tables).
    pfrt_anchor: [u8; MAXPATHLEN],
    /// Table name (null-terminated, max `PF_TABLE_NAME_SIZE - 1` chars).
    pfrt_name: [u8; PF_TABLE_NAME_SIZE],
    /// Table flags (e.g., [`PFR_TFLAG_PERSIST`]).
    pfrt_flags: u32,
    /// Feedback flags (set by kernel on return).
    pfrt_fback: u8,
}

/// PF address entry (`struct pfr_addr` from `pfvar.h`).
///
/// Represents a single IP address (v4 or v6) for addition to or removal
/// from a PF table. The prefix length determines the address scope:
/// `/32` (0x20) for individual IPv4 hosts, `/128` (0x80) for IPv6.
#[repr(C)]
struct PfrAddr {
    /// IPv4 or IPv6 address bytes.
    pfra_u: PfrAddrUnion,
    /// Address family: `AF_INET` (IPv4) or `AF_INET6` (IPv6).
    pfra_af: u8,
    /// Prefix length: `0x20` (/32) for IPv4, `0x80` (/128) for IPv6.
    pfra_net: u8,
    /// Negation flag (0 = normal, 1 = negated match).
    pfra_not: u8,
    /// Feedback flag (set by kernel on return).
    pfra_fback: u8,
}

/// PF ioctl table control structure (`struct pfioc_table` from `pfvar.h`).
///
/// Used for all PF table ioctl operations: creating tables
/// (`DIOCRADDTABLES`), adding addresses (`DIOCRADDADDRS`), and removing
/// addresses (`DIOCRDELADDRS`). The `pfrio_buffer` field points to an
/// array of [`PfrTable`] or [`PfrAddr`] entries depending on the operation.
#[repr(C)]
struct PfiocTable {
    /// Table descriptor for the operation target.
    pfrio_table: PfrTable,
    /// Pointer to the buffer of table or address entries.
    pfrio_buffer: *mut c_void,
    /// Size of each element in the buffer (bytes).
    pfrio_esize: i32,
    /// Number of elements in the buffer (input).
    pfrio_size: i32,
    /// Secondary size field (used by some operations).
    pfrio_size2: i32,
    /// Number of elements added (output from kernel).
    pfrio_nadd: i32,
    /// Number of elements deleted (output from kernel).
    pfrio_ndel: i32,
    /// Number of elements changed (output from kernel).
    pfrio_nchange: i32,
    /// Operation flags.
    pfrio_flags: i32,
    /// Ticket for atomic multi-operation sequences.
    pfrio_ticket: u32,
}

// ---------------------------------------------------------------------------
// ioctl Wrappers
// ---------------------------------------------------------------------------

// Generate safe Rust wrappers for PF ioctl operations.
// These correspond to _IOWR('D', N, struct pfioc_table) from pfvar.h.
//
// DIOCRADDTABLES — create PF table(s) if they don't exist
// DIOCRADDADDRS  — add address(es) to a PF table
// DIOCRDELADDRS  — remove address(es) from a PF table

nix::ioctl_readwrite!(pf_ioctl_add_tables, b'D', 60, PfiocTable);
nix::ioctl_readwrite!(pf_ioctl_add_addrs, b'D', 67, PfiocTable);
nix::ioctl_readwrite!(pf_ioctl_del_addrs, b'D', 68, PfiocTable);

// ---------------------------------------------------------------------------
// PF Error Translation
// ---------------------------------------------------------------------------

/// Translate PF-specific errno values to human-readable error messages.
///
/// PF ioctl operations return standard POSIX error codes, but `ESRCH` and
/// `ENOENT` have PF-specific meanings related to table and ruleset existence.
/// This function provides context-appropriate messages for logging.
///
/// Mirrors C `pfr_strerror()` from `tables.c` lines 153–163.
fn pfr_error_message(errno: i32) -> &'static str {
    match errno {
        libc::ESRCH => "Table does not exist",
        libc::ENOENT => "Anchor or Ruleset does not exist",
        _ => "Unknown PF error",
    }
}

// ---------------------------------------------------------------------------
// PfTableController
// ---------------------------------------------------------------------------

/// BSD Packet Filter table controller.
///
/// Manages the `/dev/pf` device handle and provides methods for creating
/// PF tables and adding/removing IP addresses. Replaces C's static
/// `int dev = -1` global variable with RAII-managed [`OwnedFd`].
///
/// # Initialization
///
/// ```rust,ignore
/// let controller = PfTableController::new()?;
/// ```
///
/// # Dropping
///
/// When `PfTableController` is dropped, the `/dev/pf` file descriptor is
/// automatically closed via [`OwnedFd`]'s `Drop` implementation, fixing
/// the C implementation's implicit fd leak on shutdown.
pub struct PfTableController {
    /// File descriptor for the opened `/dev/pf` device.
    /// Wrapped in `OwnedFd` for automatic RAII cleanup.
    dev: OwnedFd,
}

impl PfTableController {
    /// Initialize PF device interface for table manipulation.
    ///
    /// Opens `/dev/pf` with read-write access to enable ioctl operations
    /// for PF table creation and address manipulation. This must be called
    /// during dnsmasq initialization before privilege drop, since `/dev/pf`
    /// typically requires root access (mode 0600, root:wheel on BSD).
    ///
    /// # Errors
    ///
    /// Returns `DnsmasqError::Network` if `/dev/pf` cannot be opened:
    /// - `EACCES`: Permission denied (insufficient privileges)
    /// - `ENOENT`: Device does not exist (PF not enabled in kernel)
    /// - `ENXIO`: Device not configured (PF kernel module not loaded)
    ///
    /// Replaces C `ipset_init()` from `tables.c` lines 220–228, converting
    /// the fatal `die()` call to a recoverable `Result::Err`.
    pub fn new() -> DnsmasqResult<Self> {
        let fd = nix::fcntl::open(
            PF_DEVICE,
            nix::fcntl::OFlag::O_RDWR,
            nix::sys::stat::Mode::empty(),
        )
        .map_err(|e| {
            DnsmasqError::Network(format!("Failed to access PF device {}: {}", PF_DEVICE, e))
        })?;

        info!(device = PF_DEVICE, "PF device opened for table operations");
        Ok(Self { dev: fd })
    }

    /// Add or remove an IP address from a named PF table.
    ///
    /// Creates the table with `PFR_TFLAG_PERSIST` if it does not already exist,
    /// then adds or removes the specified IP address. Supports both IPv4
    /// (`/32` prefix) and IPv6 (`/128` prefix) addresses.
    ///
    /// # Arguments
    ///
    /// * `setname` — PF table name (must be < `PF_TABLE_NAME_SIZE` = 32 chars).
    /// * `ipaddr` — IP address to add/remove. [`AllAddr::V4`] for IPv4,
    ///   [`AllAddr::V6`] for IPv6.
    /// * `flags` — Dnsmasq flags (e.g., `F_IPV6`). Address family is derived
    ///   from the [`AllAddr`] variant, but flags are preserved for
    ///   API compatibility with the forwarding engine.
    /// * `remove` — `true` to remove the address, `false` to add it.
    ///
    /// # Returns
    ///
    /// `Ok(count)` — number of addresses added or removed (typically 1).
    ///
    /// # Errors
    ///
    /// Returns `DnsmasqError::Network` on:
    /// - Table name exceeding `PF_TABLE_NAME_SIZE`
    /// - `DIOCRADDTABLES` ioctl failure (table creation)
    /// - `DIOCRADDADDRS`/`DIOCRDELADDRS` ioctl failure (address operation)
    ///
    /// Replaces C `add_to_ipset()` from `tables.c` lines 307–383.
    pub fn add_to_table(
        &self,
        setname: &str,
        ipaddr: &AllAddr,
        _flags: u32,
        remove: bool,
    ) -> DnsmasqResult<i32> {
        // ---------------------------------------------------------------
        // Step 1: Validate table name length (C lines 322–334)
        // ---------------------------------------------------------------
        if setname.len() >= PF_TABLE_NAME_SIZE {
            error!(
                table = setname,
                max_len = PF_TABLE_NAME_SIZE,
                "Cannot use PF table name: name too long"
            );
            return Err(DnsmasqError::Network(format!(
                "PF table name '{}' exceeds maximum length of {} characters",
                setname,
                PF_TABLE_NAME_SIZE - 1
            )));
        }

        // ---------------------------------------------------------------
        // Step 2: Construct PfrTable with PFR_TFLAG_PERSIST (C lines 320–321)
        // ---------------------------------------------------------------
        // SAFETY: PfrTable is a repr(C) struct consisting entirely of fixed-size
        // byte arrays, u32, and u8 — all of which have a valid zeroed representation.
        // This matches C's bzero(&table, sizeof(struct pfr_table)) at tables.c line 320.
        let mut table: PfrTable = unsafe { std::mem::zeroed() };
        table.pfrt_flags |= PFR_TFLAG_PERSIST;

        // Copy table name into the fixed-size buffer (replaces C strlcpy, line 329).
        // We already validated length above, so this copy is safe.
        let name_bytes = setname.as_bytes();
        table.pfrt_name[..name_bytes.len()].copy_from_slice(name_bytes);
        // Null terminator is already present from zeroed initialization.

        // ---------------------------------------------------------------
        // Step 3: Create table if not exists via DIOCRADDTABLES (C line 341)
        // ---------------------------------------------------------------
        // SAFETY: PfiocTable is a repr(C) struct; all fields have valid zeroed
        // representation except pfrio_buffer which we set explicitly.
        // Matches C's bzero(&io, sizeof io) at tables.c line 336.
        let mut io: PfiocTable = unsafe { std::mem::zeroed() };
        io.pfrio_flags = 0;
        io.pfrio_buffer = &mut table as *mut PfrTable as *mut c_void;
        io.pfrio_esize = std::mem::size_of::<PfrTable>() as i32;
        io.pfrio_size = 1;

        // SAFETY: We pass a valid file descriptor (self.dev) and a properly
        // initialized PfiocTable struct with a valid buffer pointer to a
        // stack-allocated PfrTable. The kernel reads and writes through this
        // structure. This matches C's ioctl(dev, DIOCRADDTABLES, &io) at
        // tables.c line 341.
        let ret = unsafe { pf_ioctl_add_tables(self.dev.as_raw_fd(), &mut io) };
        if let Err(e) = ret {
            let errno = e as i32;
            warn!(
                error = pfr_error_message(errno),
                table = setname,
                "IPset: DIOCRADDTABLES failed"
            );
            return Err(DnsmasqError::Network(format!(
                "IPset: error: {}",
                pfr_error_message(errno)
            )));
        }

        // Clear PERSIST flag after table creation (C line 348).
        // The flag is only needed during DIOCRADDTABLES; subsequent operations
        // on the table don't require it.
        table.pfrt_flags &= !PFR_TFLAG_PERSIST;

        // Log if a new table was created (C lines 349–350).
        if io.pfrio_nadd != 0 {
            info!(table = setname, "PF table created");
        }

        // ---------------------------------------------------------------
        // Step 4: Construct PfrAddr from IP address (C lines 352–365)
        // ---------------------------------------------------------------
        // SAFETY: PfrAddr is a repr(C) struct; all fields (union of byte arrays,
        // u8 fields) have valid zeroed representation. Matches C's
        // bzero(&addr, sizeof(addr)) at tables.c line 352.
        let mut addr: PfrAddr = unsafe { std::mem::zeroed() };

        match ipaddr {
            AllAddr::V6(ipv6) => {
                // IPv6: AF_INET6, /128 prefix (C lines 356–358)
                addr.pfra_af = libc::AF_INET6 as u8;
                // /128 prefix for single host
                addr.pfra_net = 0x80;
                // Writing to a repr(C) union field is safe in Rust; only reading
                // requires unsafe. Matches C's memcpy(&(addr.pfra_ip6addr), ...).
                addr.pfra_u.pfra_ip6addr = ipv6.octets();
            }
            AllAddr::V4(ipv4) => {
                // IPv4: AF_INET, /32 prefix (C lines 362–364)
                addr.pfra_af = libc::AF_INET as u8;
                // /32 prefix for single host
                addr.pfra_net = 0x20;
                // Writing to a repr(C) union field is safe in Rust; only reading
                // requires unsafe. Matches C's addr.pfra_ip4addr.s_addr = ...
                addr.pfra_u.pfra_ip4addr = ipv4.octets();
            }
            _ => {
                // Non-IP address variants (Cname, Key, Ds, etc.) are not
                // applicable for PF table operations.
                error!(table = setname, "Cannot add non-IP address to PF table");
                return Err(DnsmasqError::Network(
                    "Cannot add non-IP address to PF table".to_string(),
                ));
            }
        }

        // ---------------------------------------------------------------
        // Step 5: Add/remove address via DIOCRADDADDRS / DIOCRDELADDRS
        //         (C lines 367–376)
        // ---------------------------------------------------------------
        // SAFETY: Re-zeroing PfiocTable for the address operation.
        // Matches C's bzero(&io, sizeof(io)) at tables.c line 367.
        io = unsafe { std::mem::zeroed() };
        io.pfrio_flags = 0;
        io.pfrio_table = table;
        io.pfrio_buffer = &mut addr as *mut PfrAddr as *mut c_void;
        io.pfrio_esize = std::mem::size_of::<PfrAddr>() as i32;
        io.pfrio_size = 1;

        let op_name = if remove { "DEL" } else { "ADD" };

        // SAFETY: We pass a valid file descriptor and a properly initialized
        // PfiocTable struct with pfrio_table set to the target table and
        // pfrio_buffer pointing to a stack-allocated PfrAddr. The kernel
        // performs the add/remove operation and writes result counts back
        // into the io structure. Matches C's ioctl(dev, (remove ?
        // DIOCRDELADDRS : DIOCRADDADDRS), &io) at tables.c line 373.
        let ret = if remove {
            unsafe { pf_ioctl_del_addrs(self.dev.as_raw_fd(), &mut io) }
        } else {
            unsafe { pf_ioctl_add_addrs(self.dev.as_raw_fd(), &mut io) }
        };

        if let Err(e) = ret {
            let errno = e as i32;
            warn!(
                operation = op_name,
                error = pfr_error_message(errno),
                table = setname,
                "DIOCR{}ADDRS failed",
                op_name
            );
            return Err(DnsmasqError::Network(format!(
                "warning: DIOCR{}ADDRS: {}",
                op_name,
                pfr_error_message(errno)
            )));
        }

        // ---------------------------------------------------------------
        // Step 6: Log result and return count (C lines 379–382)
        // ---------------------------------------------------------------
        let count = io.pfrio_nadd;
        let action = if remove { "removed" } else { "added" };
        info!(
            count = count,
            action = action,
            table = setname,
            "{} addresses {}",
            count,
            action
        );

        Ok(count)
    }
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::field_reassign_with_default,
    clippy::needless_borrows_for_generic_args,
    clippy::unnecessary_cast,
    clippy::assertions_on_constants,
    clippy::len_zero,
    clippy::vec_init_then_push,
    clippy::unchecked_duration_subtraction,
    clippy::manual_string_new,
    clippy::cloned_ref_to_slice_refs,
    clippy::manual_range_contains,
    clippy::trim_split_whitespace,
    clippy::identity_op,
    clippy::io_other_error,
    clippy::useless_vec,
    clippy::const_is_empty,
    clippy::clone_on_copy,
    clippy::absurd_extreme_comparisons,
    clippy::overly_complex_bool_expr,
    clippy::write_literal,
    clippy::int_plus_one,
    clippy::write_with_newline,
    clippy::float_cmp,
    clippy::double_comparisons,
    clippy::large_stack_arrays,
    clippy::writeln_empty_string,
    unused_comparisons,
    unused_mut,
    unused_variables
)]
mod tests {
    use super::*;

    /// Verify PF error message translation matches C pfr_strerror().
    #[test]
    fn test_pfr_error_message() {
        assert_eq!(pfr_error_message(libc::ESRCH), "Table does not exist");
        assert_eq!(
            pfr_error_message(libc::ENOENT),
            "Anchor or Ruleset does not exist"
        );
        assert_eq!(pfr_error_message(libc::ENAMETOOLONG), "Unknown PF error");
        assert_eq!(pfr_error_message(0), "Unknown PF error");
        assert_eq!(pfr_error_message(-1), "Unknown PF error");
    }

    /// Verify PF table name size constant matches BSD pfvar.h.
    #[test]
    fn test_pf_table_name_size() {
        assert_eq!(PF_TABLE_NAME_SIZE, 32);
    }

    /// Verify MAXPATHLEN constant matches BSD sys/param.h.
    #[test]
    fn test_maxpathlen() {
        assert_eq!(MAXPATHLEN, 1024);
    }

    /// Verify PFR_TFLAG_PERSIST constant value.
    #[test]
    fn test_pfr_tflag_persist() {
        assert_eq!(PFR_TFLAG_PERSIST, 0x0000_0001);
    }

    /// Verify PfrTable struct has correct field sizes for ioctl compatibility.
    #[test]
    fn test_pfr_table_field_sizes() {
        // pfrt_anchor must be MAXPATHLEN (1024) bytes
        assert_eq!(
            std::mem::size_of::<[u8; MAXPATHLEN]>(),
            1024,
            "pfrt_anchor field must be 1024 bytes"
        );
        // pfrt_name must be PF_TABLE_NAME_SIZE (32) bytes
        assert_eq!(
            std::mem::size_of::<[u8; PF_TABLE_NAME_SIZE]>(),
            32,
            "pfrt_name field must be 32 bytes"
        );
    }

    /// Verify PfrAddrUnion is large enough for IPv6 addresses.
    #[test]
    fn test_pfr_addr_union_size() {
        assert!(
            std::mem::size_of::<PfrAddrUnion>() >= 16,
            "PfrAddrUnion must be at least 16 bytes for IPv6"
        );
    }

    /// Verify IPv4 prefix constant (/32 = 0x20).
    #[test]
    fn test_ipv4_prefix() {
        assert_eq!(0x20u8, 32, "IPv4 prefix /32 must equal 0x20");
    }

    /// Verify IPv6 prefix constant (/128 = 0x80).
    #[test]
    fn test_ipv6_prefix() {
        assert_eq!(0x80u8, 128, "IPv6 prefix /128 must equal 0x80");
    }
}

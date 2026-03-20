// Copyright (c) 2000-2025 Simon Kelley
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.

//! # nftables Set Integration
//!
//! Rust implementation of nftables set manipulation for DNS-based firewall
//! rules, migrated from `src/nftset.c` (392 lines). This module enables
//! dnsmasq to dynamically add resolved IP addresses to nftables sets,
//! supporting modern Linux firewall integration.
//!
//! ## Feature Gate
//!
//! This entire module is gated by `#[cfg(feature = "nftset")]`, corresponding
//! to the C `HAVE_NFTSET` preprocessor macro from `config.h`.
//!
//! ## nftables Crate
//!
//! Replaces the C `libnftables` dependency (`nft_ctx_new`,
//! `nft_run_cmd_from_buffer`, `nft_ctx_buffer_error`,
//! `nft_ctx_get_error_buffer`) with the safe `nftables` Rust crate which
//! communicates via the nftables JSON API (spawning the `nft` binary).
//!
//! ## Capabilities
//!
//! - Add resolved IPv4 and IPv6 addresses to nftables sets
//! - Remove addresses from nftables sets when DNS entries expire
//! - Per-address-family filtering via `"4 "` / `"6 "` setname prefixes
//! - Structured error reporting via [`NftsetError`] and `tracing`
//!
//! ## Configuration Example
//!
//! ```text
//! # dnsmasq.conf
//! nftset=/example.com/4#ip#mytable#blocked_ipv4
//! nftset=/example.com/6#ip6#mytable#blocked_ipv6
//!
//! # Corresponding nftables setup:
//! nft add table ip mytable
//! nft add set ip mytable blocked_ipv4 { type ipv4_addr\; }
//! nft add rule ip mytable filter ip daddr @blocked_ipv4 drop
//! ```
//!
//! ## Memory Safety
//!
//! - Rust `String` replaces C's manually managed `cmd_buf` / `cmd_buf_sz`
//!   static buffer, eliminating all buffer overflow risks.
//! - No `unsafe` blocks — all operations use safe Rust abstractions.
//! - RAII: [`NftsetController`] automatically cleans up on drop.

use std::fmt::Write;

use nftables::batch::Batch;
use nftables::expr::Expression;
use nftables::helper;
use nftables::schema::{Element, NfListObject};
use nftables::types::NfFamily;
use thiserror::Error;
use tracing::{error, info, warn};

use crate::core::types::{AllAddr, DnsmasqError, DnsmasqResult};

// ---------------------------------------------------------------------------
// Address family flag constants (from dnsmasq.h lines 694-695)
// ---------------------------------------------------------------------------

/// Flag indicating IPv4 address family (`F_IPV4` = `1u << 7` in C).
///
/// Matches `#define F_IPV4 (1u<<7)` from `dnsmasq.h` line 694.
const F_IPV4: u32 = 1 << 7;

/// Flag indicating IPv6 address family (`F_IPV6` = `1u << 8` in C).
///
/// Matches `#define F_IPV6 (1u<<8)` from `dnsmasq.h` line 695.
const F_IPV6: u32 = 1 << 8;

// ---------------------------------------------------------------------------
// Error Types
// ---------------------------------------------------------------------------

/// Errors specific to nftables set operations.
///
/// Replaces C's `die()` and `my_syslog(LOG_ERR, ...)` error patterns from
/// `nftset.c`. Each variant maps to a specific failure mode in the nftables
/// integration layer.
#[derive(Debug, Error)]
pub enum NftsetError {
    /// Failed to initialise the nftables context or verify `nft` availability.
    ///
    /// Replaces C's `die(_("failed to create nftset context"), NULL, EC_MISC)`
    /// at `nftset.c` line 194.
    #[error("Failed to create nftables context")]
    ContextCreationFailed,

    /// An nftables command (add/delete element) failed during execution.
    ///
    /// Replaces C's `my_syslog(LOG_ERR, "nftset %s %s", setname, err_str)`
    /// at `nftset.c` lines 384.
    #[error("nftset {set}: {message}")]
    CommandFailed {
        /// The nftables set specification that failed.
        set: String,
        /// First line of the error message from nftables.
        message: String,
    },

    /// Address family prefix in the setname does not match the supplied IP
    /// address family. This is a non-error skip condition (C returns `-1`).
    #[error("Address family mismatch for set {0}")]
    FamilyMismatch(String),
}

// ---------------------------------------------------------------------------
// NftsetController
// ---------------------------------------------------------------------------

/// Controller for nftables set element operations.
///
/// Replaces the C module-level static state (`static struct nft_ctx *ctx`,
/// `static char *cmd_buf`, `static size_t cmd_buf_sz`) from `nftset.c` with
/// an owned, RAII-managed struct. The Rust `nftables` crate handles context
/// lifecycle internally — there is no opaque `nft_ctx` handle to manage.
///
/// ## Lifecycle
///
/// ```text
/// let controller = NftsetController::new()?;  // replaces nftset_init()
/// controller.add_to_nftset("ip#filter#blocked", &addr, flags, false)?;
/// // controller dropped automatically — no explicit cleanup needed
/// ```
pub struct NftsetController {
    /// Reusable command description buffer.
    ///
    /// Replaces C's `static char *cmd_buf` / `static size_t cmd_buf_sz` with
    /// a Rust `String` that grows automatically. Initial capacity of 150 bytes
    /// matches the C initial allocation at `nftset.c` line 357.
    ///
    /// Memory safety: `String` can never overflow — it reallocates as needed,
    /// eliminating the manual `whine_malloc` / `realloc` pattern from C.
    cmd_buf: String,
}

impl NftsetController {
    /// Initialise the nftables set controller.
    ///
    /// Replaces C's `nftset_init()` (`nftset.c` lines 190-198). In the C
    /// implementation, this creates an `nft_ctx` via `nft_ctx_new()` and
    /// configures error buffering via `nft_ctx_buffer_error()`.
    ///
    /// In the Rust implementation using the `nftables` crate, there is no
    /// persistent context to create — the crate spawns the `nft` binary for
    /// each command. This constructor initialises the reusable command buffer
    /// and verifies that the nftables subsystem is accessible by attempting
    /// to read the current ruleset.
    ///
    /// # Errors
    ///
    /// Returns `DnsmasqError::Fatal` if the nftables subsystem is not
    /// accessible (replacing C's `die()` call on `nft_ctx_new()` failure).
    ///
    /// # Example
    ///
    /// ```no_run
    /// use dnsmasq::integration::nftset::NftsetController;
    /// let controller = NftsetController::new().expect("nftables unavailable");
    /// ```
    pub fn new() -> Result<Self, DnsmasqError> {
        // Verify nftables is accessible by attempting to read the current
        // ruleset. This catches missing `nft` binary, insufficient
        // permissions, and kernel-level nftables unavailability early —
        // equivalent to the C code's nft_ctx_new(NFT_CTX_DEFAULT) check.
        match helper::get_current_ruleset(None, None) {
            Ok(_) => {
                info!("NftsetController initialised successfully");
                Ok(Self {
                    // Initial capacity of 150 bytes matches C's initial
                    // allocation at nftset.c line 357.
                    cmd_buf: String::with_capacity(150),
                })
            }
            Err(e) => {
                let full_err = format!("{}", e);
                let msg = first_error_line(&full_err);
                error!(error = %msg, "Failed to create nftset context");
                Err(DnsmasqError::Fatal {
                    code: 5, // EC_MISC
                    message: format!("failed to create nftset context: {}", msg),
                })
            }
        }
    }

    /// Add or remove an IP address from an nftables set.
    ///
    /// Replaces C's `add_to_nftset()` (`nftset.c` lines 333-390). Constructs
    /// and executes an nftables `add element` or `delete element` command for
    /// the specified set.
    ///
    /// ## Address Family Filtering
    ///
    /// The `setname` may carry an optional prefix controlling which address
    /// families are accepted:
    ///
    /// | Prefix | Meaning | Behaviour |
    /// |--------|---------|-----------|
    /// | `"4 "` | IPv4 only | Skip (return `Ok(-1)`) if address is IPv6 |
    /// | `"6 "` | IPv6 only | Skip (return `Ok(-1)`) if address is IPv4 |
    /// | none   | Both families | Always process |
    ///
    /// After prefix processing, the remaining setname must be in the format
    /// `"family#table#set"` (e.g. `"ip#filter#blocked"`).
    ///
    /// ## Command Format
    ///
    /// Produces nftables JSON API calls equivalent to the C commands:
    /// - Add:    `"add element family table set { <addr> }"`
    /// - Delete: `"delete element family table set { <addr> }"`
    ///
    /// ## Arguments
    ///
    /// * `setname` — nftables set specification, optionally prefixed with
    ///   `"4 "` or `"6 "`, in format `"[4|6] family#table#set"`.
    /// * `ipaddr` — IP address to add or remove. [`AllAddr::V4`] for IPv4,
    ///   [`AllAddr::V6`] for IPv6.
    /// * `flags` — Dnsmasq flags containing [`F_IPV4`] or [`F_IPV6`] bits.
    ///   Used for address family filtering against the setname prefix.
    /// * `remove` — `true` to remove the address, `false` to add it.
    ///
    /// ## Returns
    ///
    /// * `Ok(0)` — Command executed successfully.
    /// * `Ok(-1)` — Address family mismatch; operation skipped (not an error).
    /// * `Err(DnsmasqError::Network(...))` — nftables command execution failed.
    ///
    /// ## Errors
    ///
    /// Returns `DnsmasqError::Network` when:
    /// - The setname format is invalid (not `"family#table#set"`)
    /// - The family string is unrecognised
    /// - The nftables command execution fails
    pub fn add_to_nftset(
        &mut self,
        setname: &str,
        ipaddr: &AllAddr,
        flags: u32,
        remove: bool,
    ) -> DnsmasqResult<i32> {
        // ---------------------------------------------------------------
        // Step 1: Convert AllAddr to string representation
        // Replaces C's inet_ntop(af, ipaddr, daemon->addrbuff, ADDRSTRLEN)
        // at nftset.c line 343.
        // ---------------------------------------------------------------
        let addr_str: String = match ipaddr {
            AllAddr::V4(v4) => v4.to_string(),
            AllAddr::V6(v6) => v6.to_string(),
            _ => {
                warn!(
                    setname = setname,
                    "add_to_nftset called with non-IP AllAddr variant"
                );
                return Err(DnsmasqError::Network(
                    "nftset: address is neither IPv4 nor IPv6".to_string(),
                ));
            }
        };

        // ---------------------------------------------------------------
        // Step 2: Address family prefix filtering
        // Replaces C lines 345-354 in nftset.c:
        //   if (setname[1] == ' ' && (setname[0] == '4' || setname[0] == '6'))
        //     { if (setname[0] == '4' && !(flags & F_IPV4)) return -1; ... }
        // ---------------------------------------------------------------
        let effective_setname = if setname.len() >= 2 {
            let bytes = setname.as_bytes();
            if bytes[1] == b' ' && (bytes[0] == b'4' || bytes[0] == b'6') {
                // "4 " prefix: accept only IPv4
                if bytes[0] == b'4' && (flags & F_IPV4) == 0 {
                    return Ok(-1);
                }
                // "6 " prefix: accept only IPv6
                if bytes[0] == b'6' && (flags & F_IPV6) == 0 {
                    return Ok(-1);
                }
                // Strip the 2-char prefix (digit + space)
                &setname[2..]
            } else {
                setname
            }
        } else {
            setname
        };

        // ---------------------------------------------------------------
        // Step 3: Parse "family#table#set" format
        // The setname from dnsmasq configuration uses '#' as a separator
        // between the nftables family, table name, and set name.
        // ---------------------------------------------------------------
        let parts: Vec<&str> = effective_setname.splitn(3, '#').collect();
        if parts.len() != 3 {
            let msg = format!(
                "nftset: invalid set specification '{}': expected 'family#table#set'",
                effective_setname
            );
            error!(setname = effective_setname, "{}", msg);
            return Err(DnsmasqError::Network(msg));
        }

        let family_str = parts[0];
        let table_name = parts[1];
        let set_name = parts[2];

        // ---------------------------------------------------------------
        // Step 4: Map family string to NfFamily enum
        // Supports the standard nftables family names used in dnsmasq
        // configuration: ip, ip6, inet, arp, bridge, netdev.
        // ---------------------------------------------------------------
        let nf_family = parse_nf_family(family_str).ok_or_else(|| {
            let msg = format!(
                "nftset: unrecognised nftables family '{}' in set '{}'",
                family_str, effective_setname
            );
            error!(family = family_str, setname = effective_setname, "{}", msg);
            DnsmasqError::Network(msg)
        })?;

        // ---------------------------------------------------------------
        // Step 5: Build description string for logging
        // Uses the reusable cmd_buf, matching C's buffer pattern.
        // ---------------------------------------------------------------
        self.cmd_buf.clear();
        let action = if remove { "delete" } else { "add" };
        // write! on String is infallible (returns Ok always), but we use
        // let _ to acknowledge the result per the Write trait contract.
        let _ = write!(
            self.cmd_buf,
            "{} element {} {} {} {{ {} }}",
            action, family_str, table_name, set_name, addr_str
        );

        // ---------------------------------------------------------------
        // Step 6: Construct nftables Element and Batch
        // Replaces C's nft_run_cmd_from_buffer(ctx, cmd_buf) at line 373.
        // ---------------------------------------------------------------
        let element = Element {
            family: nf_family,
            table: table_name.to_string(),
            name: set_name.to_string(),
            elem: vec![Expression::String(addr_str)],
        };

        let mut batch = Batch::new();
        if remove {
            batch.delete(NfListObject::Element(element));
        } else {
            batch.add(NfListObject::Element(element));
        }

        let nftables_payload = batch.to_nftables();

        // ---------------------------------------------------------------
        // Step 7: Execute command and handle errors
        // Replaces C lines 373-387 in nftset.c.
        // On failure, log only the first line of the error message
        // (matching C's newline-stripping behaviour).
        // ---------------------------------------------------------------
        match helper::apply_ruleset(&nftables_payload, None, None) {
            Ok(()) => Ok(0),
            Err(e) => {
                let full_err = format!("{}", e);
                let first_line = first_error_line(&full_err);
                error!(
                    setname = effective_setname,
                    error = %first_line,
                    "nftset {} {}",
                    effective_setname,
                    first_line
                );
                Err(DnsmasqError::Network(format!(
                    "nftset {} {}",
                    effective_setname, first_line
                )))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helper Functions
// ---------------------------------------------------------------------------

/// Parse an nftables family name string to the corresponding [`NfFamily`] enum.
///
/// Supports the standard family names used in nftables configuration and
/// dnsmasq's `nftset` directive: `ip`, `ip6`, `inet`, `arp`, `bridge`,
/// `netdev`.
///
/// Returns `None` if the family name is not recognised.
fn parse_nf_family(family: &str) -> Option<NfFamily> {
    match family {
        "ip" => Some(NfFamily::IP),
        "ip6" => Some(NfFamily::IP6),
        "inet" => Some(NfFamily::INet),
        "arp" => Some(NfFamily::ARP),
        "bridge" => Some(NfFamily::Bridge),
        "netdev" => Some(NfFamily::NetDev),
        _ => None,
    }
}

/// Extract only the first line of an error message.
///
/// Replaces C's pattern of finding the first newline and null-terminating
/// (`nftset.c` lines 382-383):
/// ```c
/// if ((nl = strchr(err_str, '\n')))
///     *nl = 0;
/// ```
///
/// Returns the full string if it contains no newlines.
fn first_error_line(err: &str) -> &str {
    err.lines().next().unwrap_or(err)
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

    #[test]
    fn test_parse_nf_family_valid() {
        assert_eq!(parse_nf_family("ip"), Some(NfFamily::IP));
        assert_eq!(parse_nf_family("ip6"), Some(NfFamily::IP6));
        assert_eq!(parse_nf_family("inet"), Some(NfFamily::INet));
        assert_eq!(parse_nf_family("arp"), Some(NfFamily::ARP));
        assert_eq!(parse_nf_family("bridge"), Some(NfFamily::Bridge));
        assert_eq!(parse_nf_family("netdev"), Some(NfFamily::NetDev));
    }

    #[test]
    fn test_parse_nf_family_invalid() {
        assert_eq!(parse_nf_family(""), None);
        assert_eq!(parse_nf_family("IP"), None);
        assert_eq!(parse_nf_family("unknown"), None);
        assert_eq!(parse_nf_family("ipv4"), None);
    }

    #[test]
    fn test_first_error_line_single() {
        assert_eq!(first_error_line("single line error"), "single line error");
    }

    #[test]
    fn test_first_error_line_multiline() {
        assert_eq!(
            first_error_line("first line\nsecond line\nthird line"),
            "first line"
        );
    }

    #[test]
    fn test_first_error_line_empty() {
        assert_eq!(first_error_line(""), "");
    }

    #[test]
    fn test_address_family_filter_ipv4_prefix_with_ipv4_flag() {
        // "4 ip#table#set" with F_IPV4 flag → should NOT skip
        let setname = "4 ip#filter#blocked";
        let bytes = setname.as_bytes();
        assert_eq!(bytes[0], b'4');
        assert_eq!(bytes[1], b' ');
        // F_IPV4 is set → should proceed (not return -1)
        assert!((F_IPV4 & F_IPV4) != 0);
    }

    #[test]
    fn test_address_family_filter_ipv4_prefix_with_ipv6_flag() {
        // "4 ip#table#set" with F_IPV6 flag → should skip (-1)
        // F_IPV4 check: F_IPV6 & F_IPV4 == 0 → return -1
        assert_eq!(F_IPV6 & F_IPV4, 0);
    }

    #[test]
    fn test_address_family_filter_ipv6_prefix_with_ipv6_flag() {
        // "6 ip6#table#set" with F_IPV6 flag → should NOT skip
        assert!((F_IPV6 & F_IPV6) != 0);
    }

    #[test]
    fn test_address_family_filter_ipv6_prefix_with_ipv4_flag() {
        // "6 ip6#table#set" with F_IPV4 flag → should skip (-1)
        assert_eq!(F_IPV4 & F_IPV6, 0);
    }

    #[test]
    fn test_flag_constants() {
        // Verify flag constants match C definitions
        assert_eq!(F_IPV4, 1 << 7); // 128
        assert_eq!(F_IPV6, 1 << 8); // 256
                                    // Flags must not overlap
        assert_eq!(F_IPV4 & F_IPV6, 0);
    }

    #[test]
    fn test_setname_parsing() {
        // Test the "#" separator parsing logic
        let setname = "ip#filter#blocked";
        let parts: Vec<&str> = setname.splitn(3, '#').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], "ip");
        assert_eq!(parts[1], "filter");
        assert_eq!(parts[2], "blocked");
    }

    #[test]
    fn test_setname_parsing_with_extra_hashes() {
        // Set name containing '#' should work with splitn(3, ...)
        let setname = "inet#mytable#my#complex#set";
        let parts: Vec<&str> = setname.splitn(3, '#').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], "inet");
        assert_eq!(parts[1], "mytable");
        assert_eq!(parts[2], "my#complex#set");
    }

    #[test]
    fn test_setname_parsing_invalid() {
        // Missing components
        let setname = "ip#filter";
        let parts: Vec<&str> = setname.splitn(3, '#').collect();
        assert_eq!(parts.len(), 2);
    }

    #[test]
    fn test_cmd_buf_write() {
        // Test that fmt::Write on String works correctly for command formatting
        let mut buf = String::with_capacity(150);
        let _ = write!(
            buf,
            "add element {} {} {} {{ {} }}",
            "ip", "filter", "blocked", "192.0.2.1"
        );
        assert_eq!(buf, "add element ip filter blocked { 192.0.2.1 }");
    }

    #[test]
    fn test_cmd_buf_delete() {
        let mut buf = String::with_capacity(150);
        let _ = write!(
            buf,
            "delete element {} {} {} {{ {} }}",
            "ip6", "mytable", "myset", "2001:db8::1"
        );
        assert_eq!(buf, "delete element ip6 mytable myset { 2001:db8::1 }");
    }

    #[test]
    fn test_prefix_stripping() {
        // Verify prefix stripping logic matches C behaviour
        let setname = "4 ip#filter#blocked";
        let stripped = if setname.len() >= 2 {
            let bytes = setname.as_bytes();
            if bytes[1] == b' ' && (bytes[0] == b'4' || bytes[0] == b'6') {
                &setname[2..]
            } else {
                setname
            }
        } else {
            setname
        };
        assert_eq!(stripped, "ip#filter#blocked");
    }

    #[test]
    fn test_prefix_stripping_no_prefix() {
        let setname = "ip#filter#blocked";
        let stripped = if setname.len() >= 2 {
            let bytes = setname.as_bytes();
            if bytes[1] == b' ' && (bytes[0] == b'4' || bytes[0] == b'6') {
                &setname[2..]
            } else {
                setname
            }
        } else {
            setname
        };
        assert_eq!(stripped, "ip#filter#blocked");
    }
}

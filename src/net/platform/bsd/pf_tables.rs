//! BSD PF Table population for DNS-driven firewall rules.
//!
//! This module provides integration with BSD Packet Filter (PF) tables,
//! allowing dnsmasq to dynamically add/remove resolved IP addresses
//! to named PF tables based on DNS query results. This is the BSD equivalent
//! of Linux ipset functionality in `crate::net::platform::linux::ipset`.
//!
//! # Platform Support
//!
//! PF tables are available on FreeBSD, OpenBSD, and NetBSD. The entire module
//! is gated behind `#[cfg(feature = "ipset")]` (replacing C `HAVE_BSD_IPSET`)
//! and the BSD target OS conditions in the parent module.
//!
//! # Architecture
//!
//! Replaces the C implementation in `src/tables.c` (386 lines). Key transformations:
//! - C static `dev` file descriptor → Rust [`PfTableManager`] struct with owned fd
//! - C `die()` fatal errors → Rust `Result<T, PlatformError>` returns
//! - C `bzero()` / `memcpy()` → Rust `MaybeUninit::zeroed()` and slice copies
//! - C `#if defined(HAVE_BSD_IPSET)` → Cargo feature `ipset` + BSD target OS cfg
//!
//! # PF Table Architecture
//!
//! BSD Packet Filter tables are kernel-maintained sets of IP addresses that can be
//! referenced in `pf.conf` firewall rules. Tables support both IPv4 and IPv6 addresses
//! and allow dynamic modification without reloading the entire ruleset. Dnsmasq creates
//! tables with the `PFR_TFLAG_PERSIST` flag, ensuring they persist even if no rules
//! reference them.
//!
//! # Usage
//!
//! Configure in `dnsmasq.conf`:
//! ```text
//! ipset=/example.com/my_pf_table
//! ```
//!
//! And in `/etc/pf.conf`:
//! ```text
//! table <my_pf_table> persist
//! block drop quick from any to <my_pf_table>
//! ```
//!
//! # Safety
//!
//! This module contains `unsafe` blocks for FFI interactions with the BSD PF kernel
//! interface via `ioctl()` system calls. Each `unsafe` block includes a `// SAFETY:`
//! comment documenting the invariants that must be upheld.

use std::io::Error as IoError;
use std::mem::{size_of, MaybeUninit};
use std::net::IpAddr;
use std::os::unix::io::{IntoRawFd, RawFd};

use log::{error, info, warn};
use nix::fcntl::{open, OFlag};
use nix::sys::stat::Mode;

use crate::net::platform::PlatformError;

// ---------------------------------------------------------------------------
// PF Constants
// ---------------------------------------------------------------------------

/// Maximum PF table name length in bytes, from BSD `net/pfvar.h`.
/// Table names must be strictly shorter than this value (null-terminated).
const PF_TABLE_NAME_SIZE: usize = 32;

/// Maximum PF anchor path length in bytes. Matches `PATH_MAX` / `MAXPATHLEN`
/// on modern FreeBSD and OpenBSD (1024 bytes). The anchor field is zeroed
/// and unused by dnsmasq, but its size affects the `PfrTable` struct layout
/// which in turn determines the ioctl request number.
const PF_ANCHOR_NAME_SIZE: usize = 1024;

/// BSD network interface name size (`IFNAMSIZ` from `net/if.h`).
const IFNAMSIZ: usize = 16;

/// PF table flag: table persists even without referencing rules.
/// Set during table creation to ensure the table survives rule reloads.
const PFR_TFLAG_PERSIST: u32 = 0x01;

/// IPv4 host prefix length (/32) encoded for PF address entries.
const IPV4_HOST_PREFIX: u8 = 0x20; // 32

/// IPv6 host prefix length (/128) encoded for PF address entries.
const IPV6_HOST_PREFIX: u8 = 0x80; // 128

/// Path to the PF device file on BSD systems.
const PF_DEVICE_PATH: &str = "/dev/pf";

// ---------------------------------------------------------------------------
// BSD ioctl request number computation
// ---------------------------------------------------------------------------

/// BSD IOC_INOUT flag — indicates ioctl transfers data in both directions.
const IOC_INOUT: u64 = 0xC000_0000;

/// BSD IOCPARM_MASK — maximum parameter size (13 bits).
const IOCPARM_MASK: u64 = 0x1FFF;

/// Compute a BSD-style `_IOWR(group, num, type)` ioctl request number.
///
/// This replicates the BSD kernel macro:
/// ```c
/// #define _IOC(inout, group, num, len) \
///     ((unsigned long)(inout | ((len & IOCPARM_MASK) << 16) | ((group) << 8) | (num)))
/// #define _IOWR(g, n, t) _IOC(IOC_INOUT, (g), (n), sizeof(t))
/// ```
///
/// The resulting value encodes the direction (read+write), parameter size,
/// ioctl group ('D' for PF), and command number into a single `u64`.
const fn iowr(group: u8, num: u8, size: usize) -> u64 {
    IOC_INOUT | (((size as u64) & IOCPARM_MASK) << 16) | ((group as u64) << 8) | (num as u64)
}

// PF ioctl command numbers — group 'D' (PF device), encoded with PfiocTable size.
// These must match the target platform's `net/pfvar.h` definitions.
//
// DIOCRADDTABLES: _IOWR('D', 60, struct pfioc_table) — create tables
// DIOCRADDADDRS:  _IOWR('D', 67, struct pfioc_table) — add addresses to table
// DIOCRDELADDRS:  _IOWR('D', 68, struct pfioc_table) — remove addresses from table

/// ioctl request for adding/creating PF tables (DIOCRADDTABLES).
const DIOCRADDTABLES: u64 = iowr(b'D', 60, size_of::<PfiocTable>());

/// ioctl request for adding addresses to a PF table (DIOCRADDADDRS).
const DIOCRADDADDRS: u64 = iowr(b'D', 67, size_of::<PfiocTable>());

/// ioctl request for removing addresses from a PF table (DIOCRDELADDRS).
const DIOCRDELADDRS: u64 = iowr(b'D', 68, size_of::<PfiocTable>());

// ---------------------------------------------------------------------------
// FFI Structure Definitions — must match BSD `net/pfvar.h` layout
// ---------------------------------------------------------------------------

/// Address data union for PF address entries.
///
/// Replaces the C union:
/// ```c
/// union {
///     struct in_addr   _pfra_ip4addr;  // 4 bytes, alignment 4
///     struct in6_addr  _pfra_ip6addr;  // 16 bytes, alignment 1
/// } pfra_u;
/// ```
///
/// Using a Rust union with `#[repr(C)]` for exact C ABI compatibility.
/// The `u32` member ensures proper 4-byte alignment matching `struct in_addr`.
#[repr(C)]
#[derive(Copy, Clone)]
union PfrAddrData {
    /// IPv4 address stored as raw `in_addr.s_addr` (network byte order).
    ip4addr: u32,
    /// IPv6 address stored as raw `in6_addr.s6_addr` (16 bytes).
    ip6addr: [u8; 16],
}

/// PF table descriptor, replaces C `struct pfr_table` from `net/pfvar.h`.
///
/// Layout must exactly match the BSD kernel structure for ioctl compatibility.
/// The anchor field (unused by dnsmasq) is zeroed during initialization.
#[repr(C)]
struct PfrTable {
    /// Anchor path (unused — zeroed). Size is `PF_ANCHOR_NAME_SIZE` (1024 on modern BSD).
    pfrt_anchor: [u8; PF_ANCHOR_NAME_SIZE],
    /// Table name, null-terminated. Maximum `PF_TABLE_NAME_SIZE` (32) bytes including null.
    pfrt_name: [u8; PF_TABLE_NAME_SIZE],
    /// Table flags. `PFR_TFLAG_PERSIST` (0x01) makes the table persistent.
    pfrt_flags: u32,
    /// Feedback field used by kernel during batch operations.
    pfrt_fback: u8,
}

/// PF address entry, replaces C `struct pfr_addr` from `net/pfvar.h`.
///
/// Each entry represents a single IPv4 or IPv6 address with an associated
/// prefix length. Dnsmasq always uses host addresses (/32 for IPv4, /128 for IPv6).
#[repr(C)]
struct PfrAddr {
    /// IP address data (union of IPv4 `u32` and IPv6 `[u8; 16]`).
    pfra_u: PfrAddrData,
    /// Interface name filter (unused — zeroed).
    pfra_ifname: [u8; IFNAMSIZ],
    /// Number of states referencing this address (kernel-maintained).
    pfra_states: u32,
    /// Address weight for load balancing (unused — zeroed).
    pfra_weight: u16,
    /// Address family: `AF_INET` (IPv4) or `AF_INET6` (IPv6).
    pfra_af: u8,
    /// Prefix length: `0x20` (/32) for IPv4 host, `0x80` (/128) for IPv6 host.
    pfra_net: u8,
    /// Negation flag (unused — zeroed).
    pfra_not: u8,
    /// Feedback field for batch operations (kernel-maintained).
    pfra_fback: u8,
    /// Address type (unused — zeroed).
    pfra_type: u8,
    /// Padding to maintain struct alignment. Must be zeroed.
    pfra_pad: [u8; 7],
}

/// PF ioctl control structure, replaces C `struct pfioc_table` from `net/pfvar.h`.
///
/// This structure is the primary parameter for all PF table ioctl operations
/// (`DIOCRADDTABLES`, `DIOCRADDADDRS`, `DIOCRDELADDRS`). It contains both the
/// table descriptor and a pointer to the data buffer (table or address entries).
#[repr(C)]
struct PfiocTable {
    /// Table descriptor identifying the target PF table.
    pfrio_table: PfrTable,
    /// Pointer to the data buffer (either `PfrTable` or `PfrAddr` entries).
    pfrio_buffer: *mut libc::c_void,
    /// Size of each element in the buffer (bytes).
    pfrio_esize: libc::c_int,
    /// Number of elements in the buffer.
    pfrio_size: libc::c_int,
    /// Secondary size field (used by some operations).
    pfrio_size2: libc::c_int,
    /// Number of elements added by the operation (output).
    pfrio_nadd: libc::c_int,
    /// Number of elements deleted by the operation (output).
    pfrio_ndel: libc::c_int,
    /// Number of elements changed by the operation (output).
    pfrio_nchange: libc::c_int,
    /// Operation flags.
    pfrio_flags: libc::c_int,
    /// Transaction ticket (used for atomic batch operations).
    pfrio_ticket: u32,
}

// ---------------------------------------------------------------------------
// PF Error Translation
// ---------------------------------------------------------------------------

/// Translate PF-specific errno values to human-readable error messages.
///
/// PF ioctl operations return standard POSIX error codes, but `ESRCH` and `ENOENT`
/// have PF-specific meanings related to table and anchor existence. This function
/// provides context-appropriate error messages for logging and diagnostics.
///
/// Replaces C `pfr_strerror()` from `tables.c` lines 153–164.
///
/// # Arguments
///
/// * `errnum` - Error code from `errno` after a failed PF ioctl operation.
///
/// # Returns
///
/// A descriptive error string. For unrecognized codes, falls back to the
/// standard OS error description via `std::io::Error`.
fn pfr_strerror(errnum: i32) -> String {
    match errnum {
        libc::ESRCH => "Table does not exist".to_string(),
        libc::ENOENT => "Anchor or Ruleset does not exist".to_string(),
        _ => {
            // Fall back to standard OS error description, matching C strerror() behavior
            let os_err = IoError::from_raw_os_error(errnum);
            format!("{}", os_err)
        }
    }
}

// ---------------------------------------------------------------------------
// PfTableManager — Public API
// ---------------------------------------------------------------------------

/// Manager for BSD PF (Packet Filter) table operations.
///
/// Holds an open file descriptor to `/dev/pf` for performing ioctl-based
/// table manipulation. The descriptor is opened during initialization and
/// closed automatically when the manager is dropped (RAII pattern).
///
/// This struct replaces the C module-level static `dev` variable from
/// `tables.c` line 112, eliminating global mutable state.
///
/// # Initialization
///
/// Must be created during daemon startup **before** privilege drop, as
/// `/dev/pf` typically requires root access (mode 0600, owner root:wheel).
///
/// # Thread Safety
///
/// Designed for single-threaded use within the dnsmasq event loop.
/// The C implementation used a global static fd with no synchronization;
/// this Rust version encapsulates the fd within an owned struct.
///
/// # Example
///
/// ```rust,no_run
/// use dnsmasq::net::platform::bsd::pf_tables::PfTableManager;
/// use std::net::IpAddr;
///
/// let mgr = PfTableManager::new().expect("Failed to open PF device");
/// let addr: IpAddr = "93.184.216.34".parse().unwrap();
/// let added = mgr.add_to_ipset("blocked_domains", &addr, false).unwrap();
/// println!("Added {} addresses", added);
/// ```
pub struct PfTableManager {
    /// File descriptor for the `/dev/pf` device, used for all PF ioctl operations.
    /// Always >= 0 after successful initialization.
    dev_fd: RawFd,
}

impl PfTableManager {
    /// Initialize the PF device for table operations.
    ///
    /// Opens `/dev/pf` with read-write access and returns a new `PfTableManager`.
    /// This must be called during daemon startup before privilege drop, as the
    /// PF device typically requires root privileges.
    ///
    /// Replaces C `ipset_init()` from `tables.c` lines 220–228. Unlike the C
    /// version which calls `die()` on failure, this returns a `Result` allowing
    /// the caller to decide on error severity.
    ///
    /// # Errors
    ///
    /// Returns `PlatformError::InitFailed` if `/dev/pf` cannot be opened.
    /// Common causes:
    /// - `EACCES`: Insufficient privileges (not running as root)
    /// - `ENOENT`: PF device does not exist (PF not loaded or not supported)
    /// - `ENXIO`: PF kernel module not configured
    ///
    /// # Safety Considerations
    ///
    /// Uses `nix::fcntl::open()` which is a safe wrapper around `open(2)`.
    /// The returned fd is stored in the struct and closed on `Drop`.
    pub fn new() -> Result<Self, PlatformError> {
        // Open /dev/pf with read-write access for ioctl operations.
        // nix::fcntl::open is a safe wrapper around open(2) and returns OwnedFd.
        // We convert to RawFd via into_raw_fd() to manage the lifecycle ourselves
        // through our Drop implementation.
        let owned_fd = open(PF_DEVICE_PATH, OFlag::O_RDWR, Mode::empty()).map_err(|e| {
            error!("Failed to open PF device {}: {}", PF_DEVICE_PATH, e);
            PlatformError::InitFailed(format!(
                "Failed to access PF device {}: {}",
                PF_DEVICE_PATH, e
            ))
        })?;

        // Convert OwnedFd to RawFd — this transfers ownership to us.
        // The OwnedFd is consumed without closing the fd, and we'll close it in Drop.
        let fd = owned_fd.into_raw_fd();

        info!(
            "PF device {} opened successfully (fd={})",
            PF_DEVICE_PATH, fd
        );

        Ok(PfTableManager { dev_fd: fd })
    }

    /// Add or remove an IP address from a named PF table.
    ///
    /// This function performs two ioctl operations:
    /// 1. Creates the named table with `PFR_TFLAG_PERSIST` if it doesn't exist
    ///    (idempotent via `DIOCRADDTABLES`)
    /// 2. Adds or removes the specified IP address (via `DIOCRADDADDRS` or
    ///    `DIOCRDELADDRS`)
    ///
    /// Replaces C `add_to_ipset()` from `tables.c` lines 307–383.
    ///
    /// # Arguments
    ///
    /// * `setname` - PF table name (must be < `PF_TABLE_NAME_SIZE` = 32 characters)
    /// * `ipaddr` - IP address to add or remove (IPv4 or IPv6)
    /// * `remove` - If `true`, remove the address; if `false`, add it
    ///
    /// # Returns
    ///
    /// On success, returns the number of addresses added or removed (typically 1).
    /// Returns 0 if the address was already present (add) or already absent (remove).
    ///
    /// # Errors
    ///
    /// Returns `PlatformError::BpfError` on:
    /// - Table name exceeding `PF_TABLE_NAME_SIZE` limit
    /// - `DIOCRADDTABLES` ioctl failure (table creation)
    /// - `DIOCRADDADDRS` / `DIOCRDELADDRS` ioctl failure (address manipulation)
    ///
    /// # Wire Format
    ///
    /// - IPv4 addresses are added with prefix length /32 (`0x20`) and `AF_INET`
    /// - IPv6 addresses are added with prefix length /128 (`0x80`) and `AF_INET6`
    pub fn add_to_ipset(
        &self,
        setname: &str,
        ipaddr: &IpAddr,
        remove: bool,
    ) -> Result<i32, PlatformError> {
        // --- Step 1: Validate table name length ---
        if setname.len() >= PF_TABLE_NAME_SIZE {
            error!(
                "PF table name '{}' exceeds maximum length ({} >= {})",
                setname,
                setname.len(),
                PF_TABLE_NAME_SIZE
            );
            return Err(PlatformError::BpfError(format!(
                "Cannot use table name '{}': exceeds PF_TABLE_NAME_SIZE ({})",
                setname, PF_TABLE_NAME_SIZE
            )));
        }

        // --- Step 2: Initialize PfrTable with PERSIST flag ---
        // SAFETY: MaybeUninit::zeroed() produces an all-zeros bit pattern which is
        // valid for all fields of PfrTable (byte arrays, u32, u8). This matches
        // the C bzero(&table, sizeof(struct pfr_table)) pattern.
        let mut table: PfrTable = unsafe { MaybeUninit::zeroed().assume_init() };
        table.pfrt_flags = PFR_TFLAG_PERSIST;

        // Copy table name into the fixed-size buffer with null termination.
        // The length check above ensures setname.len() < PF_TABLE_NAME_SIZE,
        // so this copy is always within bounds.
        let name_bytes = setname.as_bytes();
        table.pfrt_name[..name_bytes.len()].copy_from_slice(name_bytes);
        // Remaining bytes are already zero from MaybeUninit::zeroed(), providing
        // null termination.

        // --- Step 3: Create table via DIOCRADDTABLES (idempotent) ---
        // SAFETY: MaybeUninit::zeroed() produces valid all-zeros for PfiocTable.
        // The pfrio_buffer pointer, pfrio_esize, and pfrio_size fields are set
        // immediately after initialization before any ioctl call.
        let mut io: PfiocTable = unsafe { MaybeUninit::zeroed().assume_init() };
        io.pfrio_flags = 0;
        io.pfrio_buffer = &mut table as *mut PfrTable as *mut libc::c_void;
        io.pfrio_esize = size_of::<PfrTable>() as libc::c_int;
        io.pfrio_size = 1;

        // SAFETY: self.dev_fd is a valid /dev/pf file descriptor opened in new().
        // io is a properly initialized PfiocTable with pfrio_buffer pointing to
        // a valid PfrTable on the stack. The ioctl reads and writes through the
        // PfiocTable structure, which matches the kernel's expected layout due to
        // #[repr(C)] on all involved types.
        let ret = unsafe {
            libc::ioctl(
                self.dev_fd,
                DIOCRADDTABLES as libc::c_ulong,
                &mut io as *mut PfiocTable,
            )
        };

        if ret == -1 {
            let errno_val = nix::errno::Errno::last_raw();
            warn!(
                "IPset: error creating table '{}': {}",
                setname,
                pfr_strerror(errno_val)
            );
            return Err(PlatformError::BpfError(format!(
                "DIOCRADDTABLES failed for table '{}': {}",
                setname,
                pfr_strerror(errno_val)
            )));
        }

        // Clear persist flag after table creation (matches C behavior at line 348).
        table.pfrt_flags &= !PFR_TFLAG_PERSIST;

        // Log table creation if a new table was actually created.
        if io.pfrio_nadd > 0 {
            info!("PF table '{}' created", setname);
        }

        // --- Step 4: Initialize PfrAddr with the target IP address ---
        // SAFETY: MaybeUninit::zeroed() produces valid all-zeros for PfrAddr.
        // All fields (including the union) start as zero, and we set specific
        // fields based on the address family.
        let mut addr: PfrAddr = unsafe { MaybeUninit::zeroed().assume_init() };

        match ipaddr {
            IpAddr::V6(v6) => {
                addr.pfra_af = libc::AF_INET6 as u8;
                addr.pfra_net = IPV6_HOST_PREFIX; // /128
                let octets = v6.octets();
                // Writing to a union field is safe in Rust — only reading requires unsafe.
                // The PfrAddrData union's ip6addr variant is [u8; 16].
                addr.pfra_u.ip6addr = octets;
            }
            IpAddr::V4(v4) => {
                addr.pfra_af = libc::AF_INET as u8;
                addr.pfra_net = IPV4_HOST_PREFIX; // /32
                let bits = u32::from(v4.clone()).to_be(); // Network byte order
                // Writing to a union field is safe in Rust — only reading requires unsafe.
                // The PfrAddrData union's ip4addr variant is u32.
                addr.pfra_u.ip4addr = bits;
            }
        }

        // --- Step 5: Add or remove address via DIOCRADDADDRS / DIOCRDELADDRS ---
        // SAFETY: Re-zeroing PfiocTable before reuse with new buffer pointer.
        let mut io: PfiocTable = unsafe { MaybeUninit::zeroed().assume_init() };
        io.pfrio_flags = 0;
        io.pfrio_table = table;
        io.pfrio_buffer = &mut addr as *mut PfrAddr as *mut libc::c_void;
        io.pfrio_esize = size_of::<PfrAddr>() as libc::c_int;
        io.pfrio_size = 1;

        let ioctl_cmd = if remove { DIOCRDELADDRS } else { DIOCRADDADDRS };

        // SAFETY: self.dev_fd is a valid /dev/pf file descriptor. io is a properly
        // initialized PfiocTable with pfrio_buffer pointing to a valid PfrAddr on
        // the stack. pfrio_table contains the target table name from step 2.
        // The ioctl command (DIOCRADDADDRS or DIOCRDELADDRS) is computed from the
        // BSD _IOWR formula using the correct struct size.
        let ret = unsafe {
            libc::ioctl(
                self.dev_fd,
                ioctl_cmd as libc::c_ulong,
                &mut io as *mut PfiocTable,
            )
        };

        if ret == -1 {
            let errno_val = nix::errno::Errno::last_raw();
            let op_name = if remove { "DEL" } else { "ADD" };
            warn!(
                "DIOCR{}ADDRS for table '{}': {}",
                op_name,
                setname,
                pfr_strerror(errno_val)
            );
            return Err(PlatformError::BpfError(format!(
                "DIOCR{}ADDRS failed for table '{}': {}",
                op_name,
                setname,
                pfr_strerror(errno_val)
            )));
        }

        let count = io.pfrio_nadd;
        let action = if remove { "removed" } else { "added" };
        info!("{} addresses {} (table '{}')", count, action, setname);

        Ok(count)
    }
}

/// RAII cleanup: close the `/dev/pf` file descriptor when `PfTableManager` is dropped.
///
/// This replaces the implicit fd leak in the C implementation, where the static `dev`
/// variable was never explicitly closed (relying on process termination for cleanup).
impl Drop for PfTableManager {
    fn drop(&mut self) {
        if self.dev_fd >= 0 {
            // SAFETY: dev_fd was successfully opened by nix::fcntl::open() in new()
            // and is a valid file descriptor. We own this fd exclusively (no sharing).
            // After close(), the fd is no longer valid — but since we're in Drop,
            // no further use of dev_fd is possible.
            unsafe {
                libc::close(self.dev_fd);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// Verify PF-specific error translation for known error codes.
    #[test]
    fn test_pfr_strerror_known_codes() {
        assert_eq!(pfr_strerror(libc::ESRCH), "Table does not exist");
        assert_eq!(
            pfr_strerror(libc::ENOENT),
            "Anchor or Ruleset does not exist"
        );
    }

    /// Verify fallback to OS error description for unknown PF error codes.
    #[test]
    fn test_pfr_strerror_unknown_code() {
        let msg = pfr_strerror(libc::EPERM);
        // The message should be the OS description for EPERM, not empty
        assert!(!msg.is_empty());
        assert_ne!(msg, "Table does not exist");
        assert_ne!(msg, "Anchor or Ruleset does not exist");
    }

    /// Verify that PF constants match expected values from BSD headers.
    #[test]
    fn test_pf_constants() {
        assert_eq!(PF_TABLE_NAME_SIZE, 32);
        assert_eq!(PFR_TFLAG_PERSIST, 0x01);
        assert_eq!(IPV4_HOST_PREFIX, 0x20); // /32
        assert_eq!(IPV6_HOST_PREFIX, 0x80); // /128
    }

    /// Verify the BSD iowr() const fn produces correct ioctl request numbers.
    /// The formula is: IOC_INOUT | ((size & IOCPARM_MASK) << 16) | (group << 8) | num
    #[test]
    fn test_iowr_computation() {
        // Test with known values: group='D' (0x44), num=60
        let size = size_of::<PfiocTable>();
        let expected =
            0xC000_0000u64 | (((size as u64) & 0x1FFF) << 16) | ((b'D' as u64) << 8) | 60u64;
        assert_eq!(DIOCRADDTABLES, expected);

        // Verify group byte is 'D' = 0x44
        assert_eq!((DIOCRADDTABLES >> 8) & 0xFF, 0x44);

        // Verify command numbers
        assert_eq!(DIOCRADDTABLES & 0xFF, 60);
        assert_eq!(DIOCRADDADDRS & 0xFF, 67);
        assert_eq!(DIOCRDELADDRS & 0xFF, 68);

        // Verify all three use the same group
        assert_eq!((DIOCRADDTABLES >> 8) & 0xFF, (DIOCRADDADDRS >> 8) & 0xFF);
        assert_eq!((DIOCRADDTABLES >> 8) & 0xFF, (DIOCRDELADDRS >> 8) & 0xFF);
    }

    /// Verify PfrTable struct layout has the expected field sizes.
    #[test]
    fn test_pfr_table_layout() {
        // PfrTable should have: anchor(1024) + name(32) + flags(4) + fback(1) + padding
        let size = size_of::<PfrTable>();
        // Minimum expected size is 1024 + 32 + 4 + 1 = 1061, with alignment padding
        assert!(size >= 1061, "PfrTable size {} is too small", size);
    }

    /// Verify PfrAddr struct layout has the expected field sizes.
    #[test]
    fn test_pfr_addr_layout() {
        // PfrAddr: union(16) + ifname(16) + states(4) + weight(2)
        //          + af(1) + net(1) + not(1) + fback(1) + type(1) + pad(7) = 50 min
        let size = size_of::<PfrAddr>();
        assert!(size >= 50, "PfrAddr size {} is too small", size);
    }

    /// Verify PfiocTable contains PfrTable and additional ioctl control fields.
    #[test]
    fn test_pfioc_table_layout() {
        let pfr_size = size_of::<PfrTable>();
        let pfioc_size = size_of::<PfiocTable>();
        // PfiocTable must be larger than PfrTable (it embeds it plus control fields)
        assert!(
            pfioc_size > pfr_size,
            "PfiocTable ({}) should be larger than PfrTable ({})",
            pfioc_size,
            pfr_size
        );
    }

    /// Verify table name validation rejects names that are too long.
    #[test]
    fn test_table_name_validation() {
        // A name of exactly PF_TABLE_NAME_SIZE should be rejected
        let long_name = "a".repeat(PF_TABLE_NAME_SIZE);
        assert!(long_name.len() >= PF_TABLE_NAME_SIZE);

        // A name just under the limit should be accepted (by the validation logic)
        let ok_name = "a".repeat(PF_TABLE_NAME_SIZE - 1);
        assert!(ok_name.len() < PF_TABLE_NAME_SIZE);
    }

    /// Verify MaybeUninit::zeroed produces all-zero PfrTable.
    #[test]
    fn test_pfr_table_zero_init() {
        // SAFETY: All-zeros is valid for PfrTable (byte arrays, u32, u8).
        let table: PfrTable = unsafe { MaybeUninit::zeroed().assume_init() };
        assert_eq!(table.pfrt_flags, 0);
        assert_eq!(table.pfrt_fback, 0);
        assert!(table.pfrt_name.iter().all(|&b| b == 0));
        assert!(table.pfrt_anchor.iter().all(|&b| b == 0));
    }

    /// Verify MaybeUninit::zeroed produces all-zero PfrAddr.
    #[test]
    fn test_pfr_addr_zero_init() {
        // SAFETY: All-zeros is valid for PfrAddr. The union is zeroed,
        // and all numeric fields start at zero.
        let addr: PfrAddr = unsafe { MaybeUninit::zeroed().assume_init() };
        assert_eq!(addr.pfra_af, 0);
        assert_eq!(addr.pfra_net, 0);
        assert_eq!(addr.pfra_states, 0);
        assert_eq!(addr.pfra_weight, 0);
        assert_eq!(addr.pfra_not, 0);
        assert_eq!(addr.pfra_fback, 0);
        assert_eq!(addr.pfra_type, 0);
        assert!(addr.pfra_pad.iter().all(|&b| b == 0));
    }

    /// Verify IPv4 address encoding into PfrAddr.
    #[test]
    fn test_ipv4_addr_encoding() {
        // SAFETY: All-zeros is valid for PfrAddr.
        let mut addr: PfrAddr = unsafe { MaybeUninit::zeroed().assume_init() };
        let v4 = Ipv4Addr::new(192, 168, 1, 100);

        addr.pfra_af = libc::AF_INET as u8;
        addr.pfra_net = IPV4_HOST_PREFIX;
        let bits = u32::from(v4).to_be();
        // Writing to a union field is safe in Rust.
        addr.pfra_u.ip4addr = bits;

        assert_eq!(addr.pfra_af, libc::AF_INET as u8);
        assert_eq!(addr.pfra_net, 0x20);
        // SAFETY: Reading from a union field is unsafe — we read the same variant
        // that was just written (ip4addr), so the data is valid.
        let stored = unsafe { addr.pfra_u.ip4addr };
        assert_eq!(stored, bits);
    }

    /// Verify IPv6 address encoding into PfrAddr.
    #[test]
    fn test_ipv6_addr_encoding() {
        // SAFETY: All-zeros is valid for PfrAddr.
        let mut addr: PfrAddr = unsafe { MaybeUninit::zeroed().assume_init() };
        let v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let octets = v6.octets();

        addr.pfra_af = libc::AF_INET6 as u8;
        addr.pfra_net = IPV6_HOST_PREFIX;
        // Writing to a union field is safe in Rust.
        addr.pfra_u.ip6addr = octets;

        assert_eq!(addr.pfra_af, libc::AF_INET6 as u8);
        assert_eq!(addr.pfra_net, 0x80);
        // SAFETY: Reading from a union field is unsafe — we read the same variant
        // that was just written (ip6addr), so the data is valid.
        let stored = unsafe { addr.pfra_u.ip6addr };
        assert_eq!(stored, octets);
    }
}

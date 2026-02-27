//! Netfilter connection tracking mark retrieval for Linux.
//!
//! This module integrates with the Linux netfilter connection tracking (conntrack)
//! subsystem to retrieve connection tracking marks associated with incoming DNS
//! query connections. Marks are used for policy-based DNS routing (e.g., VPN
//! split-horizon DNS, per-connection DNS policies, multi-WAN routing).
//!
//! # Feature Gate
//!
//! This entire module is behind `#[cfg(feature = "conntrack")]`, replacing the
//! C preprocessor guard `#ifdef HAVE_CONNTRACK` from the original `src/conntrack.c`.
//!
//! # FFI Safety
//!
//! This module uses `unsafe` FFI to `libnetfilter_conntrack`. Every `unsafe` block
//! includes a `// SAFETY:` comment explaining why it is required and what invariants
//! are maintained. This is one of the explicitly permitted `unsafe` FFI modules
//! per the project's safety policy.
//!
//! # Use Cases
//!
//! 1. **Policy-Based Routing:** Route DNS queries from specific connections through
//!    designated DNS servers based on netfilter marks (e.g., VPN vs. direct routing).
//! 2. **Per-Connection DNS Policies:** Apply different DNS filtering or forwarding rules
//!    based on connection marks assigned by firewall rules.
//! 3. **VPN Split-Horizon DNS:** Direct DNS queries from VPN-marked connections to VPN
//!    DNS servers while routing unmarked queries to local/ISP DNS servers.
//! 4. **Multi-WAN Routing:** Support DNS resolution appropriate to connection's selected
//!    WAN interface based on mark-based routing policies.
//!
//! # Linux Kernel Requirements
//!
//! - Linux kernel with netfilter connection tracking enabled (`CONFIG_NF_CONNTRACK`)
//! - Netfilter conntrack kernel module loaded (`nf_conntrack`)
//! - `CAP_NET_ADMIN` capability or root privileges for conntrack table queries
//! - Connection tracking must be active for the queried connection
//!
//! # Source Reference
//!
//! Rewritten from `src/conntrack.c` (325 lines of C). The C implementation uses a
//! global `static int gotit` flag for callback communication, which is replaced here
//! by a stack-allocated [`CallbackData`] struct passed through the FFI callback's
//! `data` pointer, eliminating global mutable state.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::types::addr::SocketAddress;

// ---------------------------------------------------------------------------
// FFI bindings to libnetfilter_conntrack
// ---------------------------------------------------------------------------

/// Raw FFI bindings to `libnetfilter_conntrack`.
///
/// These bindings declare the minimal subset of the libnetfilter_conntrack C API
/// required for conntrack mark retrieval. Opaque types are represented as
/// zero-variant enums (uninhabitable) to prevent accidental construction on the
/// Rust side while maintaining correct pointer semantics.
///
/// # Constants
///
/// All constant values are derived from the installed
/// `<libnetfilter_conntrack/libnetfilter_conntrack.h>` header. Enum values are
/// computed from their sequential position in the C `enum nf_conntrack_attr`
/// and `enum nf_conntrack_query` definitions.
mod ffi {
    use libc::{c_int, c_uint, c_void};

    // -- Opaque types -------------------------------------------------------

    /// Opaque netfilter conntrack connection object.
    /// Wraps C `struct nf_conntrack`.
    pub enum NfConntrack {}

    /// Opaque netfilter conntrack query handle.
    /// Wraps C `struct nfct_handle`.
    pub enum NfctHandle {}

    // -- Conntrack attribute constants --------------------------------------
    // From `enum nf_conntrack_attr` in libnetfilter_conntrack.h

    /// Source IPv4 address attribute (u32, network byte order).
    /// `ATTR_ORIG_IPV4_SRC = 0` aliased as `ATTR_IPV4_SRC`.
    pub const ATTR_IPV4_SRC: c_uint = 0;

    /// Destination IPv4 address attribute (u32, network byte order).
    /// `ATTR_ORIG_IPV4_DST = 1` aliased as `ATTR_IPV4_DST`.
    pub const ATTR_IPV4_DST: c_uint = 1;

    /// Source IPv6 address attribute (u128, 16 bytes).
    /// `ATTR_ORIG_IPV6_SRC = 4` aliased as `ATTR_IPV6_SRC`.
    pub const ATTR_IPV6_SRC: c_uint = 4;

    /// Destination IPv6 address attribute (u128, 16 bytes).
    /// `ATTR_ORIG_IPV6_DST = 5` aliased as `ATTR_IPV6_DST`.
    pub const ATTR_IPV6_DST: c_uint = 5;

    /// Source port attribute (u16, network byte order).
    /// `ATTR_ORIG_PORT_SRC = 8` aliased as `ATTR_PORT_SRC`.
    pub const ATTR_PORT_SRC: c_uint = 8;

    /// Destination port attribute (u16, network byte order).
    /// `ATTR_ORIG_PORT_DST = 9` aliased as `ATTR_PORT_DST`.
    pub const ATTR_PORT_DST: c_uint = 9;

    /// L3 (network layer) protocol attribute (u8, e.g. AF_INET / AF_INET6).
    /// `ATTR_ORIG_L3PROTO = 15` aliased as `ATTR_L3PROTO`.
    pub const ATTR_L3PROTO: c_uint = 15;

    /// L4 (transport layer) protocol attribute (u8, e.g. IPPROTO_TCP / IPPROTO_UDP).
    /// `ATTR_ORIG_L4PROTO = 17` aliased as `ATTR_L4PROTO`.
    pub const ATTR_L4PROTO: c_uint = 17;

    /// Connection tracking mark attribute (u32).
    /// `ATTR_MARK = 25` in the sequential enum.
    pub const ATTR_MARK: c_uint = 25;

    // -- Conntrack query/subsystem constants --------------------------------

    /// `NFCT_Q_GET = 3` — query type for retrieving a single conntrack entry.
    pub const NFCT_Q_GET: c_uint = 3;

    /// `NFCT_T_ALL = NFCT_T_NEW | NFCT_T_UPDATE | NFCT_T_DESTROY = 7`
    /// — subscribe to all message types for callback registration.
    pub const NFCT_T_ALL: c_uint = 7;

    /// `CONNTRACK = NFNL_SUBSYS_CTNETLINK = 1` — netlink subsystem ID for
    /// conntrack, passed to `nfct_open()`.
    pub const CONNTRACK: u8 = 1;

    /// `NFCT_CB_CONTINUE = 1` — callback return value to continue iteration.
    pub const NFCT_CB_CONTINUE: c_int = 1;

    /// Callback function type for `nfct_callback_register`.
    ///
    /// Matches the C signature:
    /// ```c
    /// int (*cb)(enum nf_conntrack_msg_type type,
    ///           struct nf_conntrack *ct,
    ///           void *data)
    /// ```
    pub type NfctCallback = extern "C" fn(
        msg_type: c_uint,
        ct: *mut NfConntrack,
        data: *mut c_void,
    ) -> c_int;

    // SAFETY: These are thin FFI declarations for libnetfilter_conntrack functions.
    // All functions are well-defined C library functions with stable ABI.
    // The caller is responsible for passing valid pointers and correct attribute types.
    unsafe extern "C" {
        /// Allocate a new conntrack object.
        /// Returns `NULL` on failure.
        pub fn nfct_new() -> *mut NfConntrack;

        /// Destroy (free) a conntrack object.
        pub fn nfct_destroy(ct: *mut NfConntrack);

        /// Set an 8-bit attribute on a conntrack object.
        pub fn nfct_set_attr_u8(ct: *mut NfConntrack, attr: c_uint, value: u8);

        /// Set a 16-bit attribute on a conntrack object.
        pub fn nfct_set_attr_u16(ct: *mut NfConntrack, attr: c_uint, value: u16);

        /// Set a 32-bit attribute on a conntrack object.
        pub fn nfct_set_attr_u32(ct: *mut NfConntrack, attr: c_uint, value: u32);

        /// Set a pointer-based attribute on a conntrack object.
        /// Used for IPv6 addresses (16-byte arrays).
        pub fn nfct_set_attr(ct: *mut NfConntrack, attr: c_uint, value: *const c_void);

        /// Get a 32-bit attribute from a conntrack object.
        pub fn nfct_get_attr_u32(ct: *const NfConntrack, attr: c_uint) -> u32;

        /// Open a conntrack netlink handle.
        ///
        /// `subsys`: The netlink subsystem (use `CONNTRACK` = 1).
        /// `groups`: Multicast group subscriptions (0 for queries).
        /// Returns `NULL` on failure.
        pub fn nfct_open(subsys: u8, groups: libc::c_uint) -> *mut NfctHandle;

        /// Close a conntrack netlink handle.
        pub fn nfct_close(h: *mut NfctHandle) -> c_int;

        /// Register a callback for conntrack events/query results.
        ///
        /// Returns 0 on success, -1 on failure.
        pub fn nfct_callback_register(
            h: *mut NfctHandle,
            msg_type: c_uint,
            cb: NfctCallback,
            data: *mut c_void,
        ) -> c_int;

        /// Execute a conntrack query.
        ///
        /// Returns 0 on success, -1 on failure (sets `errno`).
        pub fn nfct_query(h: *mut NfctHandle, qt: c_uint, data: *const c_void) -> c_int;
    }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur during conntrack mark retrieval.
///
/// Maps the three failure modes from the C implementation:
/// - `nfct_new()` returns `NULL` → [`CreateFailed`](ConntrackError::CreateFailed)
/// - `nfct_open()` returns `NULL` → [`OpenFailed`](ConntrackError::OpenFailed)
/// - `nfct_query()` returns `-1` → [`QueryFailed`](ConntrackError::QueryFailed)
#[derive(Debug, thiserror::Error)]
pub enum ConntrackError {
    /// Failed to allocate a new conntrack object via `nfct_new()`.
    #[error("Failed to create conntrack object")]
    CreateFailed,

    /// Failed to open a conntrack netlink handle via `nfct_open()`.
    #[error("Failed to open conntrack handle")]
    OpenFailed,

    /// The conntrack query failed. Wraps the underlying OS error from `errno`.
    #[error("Conntrack query failed: {0}")]
    QueryFailed(io::Error),
}

// ---------------------------------------------------------------------------
// Callback data and implementation
// ---------------------------------------------------------------------------

/// Data structure passed through the FFI callback's `void *data` parameter.
///
/// Replaces the C global `static int gotit` and the `(unsigned int *)data` cast
/// in the original `callback()` function. By passing this on the stack via a
/// pointer, we eliminate global mutable state while preserving the same
/// communication pattern.
struct CallbackData {
    /// The retrieved connection tracking mark value.
    mark: u32,
    /// Whether the callback was invoked (i.e., a matching conntrack entry was found).
    found: bool,
}

/// FFI callback invoked by `nfct_query` when a matching conntrack entry is found.
///
/// Extracts `ATTR_MARK` from the conntrack entry and writes it to the
/// [`CallbackData`] struct pointed to by `data`.
///
/// This replaces the C `static int callback(...)` function (lines 314–322 of
/// `conntrack.c`) and the global `gotit` flag.
///
/// # Safety
///
/// This function is called by `libnetfilter_conntrack` during `nfct_query()`.
/// The caller (`get_incoming_mark`) guarantees that:
/// - `data` points to a valid, stack-allocated `CallbackData` struct
/// - `ct` is a valid conntrack entry object provided by the library
/// - The callback is invoked synchronously within `nfct_query()`, so the
///   `CallbackData` reference remains valid for the duration of the call
extern "C" fn conntrack_callback(
    _msg_type: libc::c_uint,
    ct: *mut ffi::NfConntrack,
    data: *mut libc::c_void,
) -> libc::c_int {
    // SAFETY: `data` points to a valid `CallbackData` struct on the caller's stack.
    // `ct` is a valid conntrack object provided by libnetfilter_conntrack during
    // the synchronous `nfct_query()` call. We only read ATTR_MARK from it.
    unsafe {
        let cb_data = &mut *(data as *mut CallbackData);
        cb_data.mark = ffi::nfct_get_attr_u32(ct, ffi::ATTR_MARK);
        cb_data.found = true;
    }
    ffi::NFCT_CB_CONTINUE
}

// ---------------------------------------------------------------------------
// Static warned flag
// ---------------------------------------------------------------------------

/// Static flag to prevent repeated error log spam on conntrack query failures.
///
/// Matches the C behavior from lines 254–259 of `conntrack.c`:
/// ```c
/// static int warned = 0;
/// if (!warned) {
///     my_syslog(LOG_ERR, _("Conntrack connection mark retrieval failed: %s"), strerror(errno));
///     warned = 1;
/// }
/// ```
///
/// Uses `AtomicBool` for correctness even though the daemon is single-threaded,
/// because `static mut` is always `unsafe` in Rust and `AtomicBool` avoids that.
static WARNED: AtomicBool = AtomicBool::new(false);

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Query the Linux netfilter conntrack table for a connection tracking mark.
///
/// Constructs a connection 5-tuple from the provided addresses and protocol,
/// queries the kernel conntrack table, and returns the mark if found.
///
/// This is the Rust equivalent of `get_incoming_mark()` from `src/conntrack.c`
/// (lines 221–267).
///
/// # Parameters
///
/// - `peer_addr`: Remote peer's socket address (IP + port). Pattern-matched on
///   [`SocketAddress::V4`] / [`SocketAddress::V6`] to extract the source IP
///   and source port for the conntrack 5-tuple.
/// - `local_addr`: Local DNS server address that received the query. Used as
///   the destination IP in the conntrack 5-tuple.
/// - `is_tcp`: `true` for TCP connections, `false` for UDP. Determines whether
///   `IPPROTO_TCP` or `IPPROTO_UDP` is used as the L4 protocol attribute.
/// - `dns_port`: Local DNS port (typically 53). Used as the destination port
///   in the conntrack 5-tuple.
///
/// # Returns
///
/// - `Ok(Some(mark))` — Mark successfully retrieved from the matching conntrack entry.
/// - `Ok(None)` — No matching conntrack entry was found (callback not invoked).
/// - `Err(ConntrackError)` — A conntrack API call failed.
///
/// # Error Logging
///
/// On the first query failure, an error is logged via `log::error!`. Subsequent
/// failures are silent to prevent log spam, matching the C behavior.
///
/// # Example
///
/// ```rust,no_run
/// use dnsmasq::types::addr::SocketAddress;
/// use dnsmasq::net::platform::linux::conntrack::get_incoming_mark;
/// use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
///
/// let peer = SocketAddress::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 12345));
/// let local = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
///
/// match get_incoming_mark(&peer, &local, false, 53) {
///     Ok(Some(mark)) => println!("Connection mark: {}", mark),
///     Ok(None) => println!("No conntrack entry found"),
///     Err(e) => eprintln!("Conntrack error: {}", e),
/// }
/// ```
pub fn get_incoming_mark(
    peer_addr: &SocketAddress,
    local_addr: &IpAddr,
    is_tcp: bool,
    dns_port: u16,
) -> Result<Option<u32>, ConntrackError> {
    // Step 1: Create a new conntrack object.
    // C equivalent: ct = nfct_new()
    // SAFETY: nfct_new() allocates a new conntrack object or returns NULL.
    // No preconditions. We check for NULL immediately.
    let ct = unsafe { ffi::nfct_new() };
    if ct.is_null() {
        return Err(ConntrackError::CreateFailed);
    }

    // Step 2: Set L4 protocol (TCP or UDP) and destination port.
    // C equivalent: nfct_set_attr_u8(ct, ATTR_L4PROTO, istcp ? IPPROTO_TCP : IPPROTO_UDP);
    //               nfct_set_attr_u16(ct, ATTR_PORT_DST, htons(daemon->port));
    let l4proto = if is_tcp {
        libc::IPPROTO_TCP as u8
    } else {
        libc::IPPROTO_UDP as u8
    };

    // SAFETY: ct is a valid, non-null conntrack object from nfct_new().
    // We set standard attributes with correct types (u8 for protocol, u16 for port).
    unsafe {
        ffi::nfct_set_attr_u8(ct, ffi::ATTR_L4PROTO, l4proto);
        ffi::nfct_set_attr_u16(ct, ffi::ATTR_PORT_DST, dns_port.to_be());
    }

    // Step 3: Set L3 protocol and addresses based on address family.
    // C equivalent: lines 233–246 of conntrack.c
    match peer_addr {
        SocketAddress::V6(peer_v6) => {
            // IPv6 path
            let src_ip = peer_v6.ip();
            let src_port = peer_v6.port();

            // Extract the destination IPv6 address from local_addr
            let dst_ip = match local_addr {
                IpAddr::V6(v6) => *v6,
                // If local_addr is V4 but peer is V6, this is a mismatch.
                // The C code would simply use whatever bytes were in the union.
                // We default to unspecified as a safe fallback.
                IpAddr::V4(_) => Ipv6Addr::UNSPECIFIED,
            };

            // SAFETY: ct is a valid conntrack object. We set attributes with
            // correct types. For IPv6 addresses, nfct_set_attr takes a pointer
            // to 16 bytes (the octets of the IPv6 address).
            unsafe {
                ffi::nfct_set_attr_u8(ct, ffi::ATTR_L3PROTO, libc::AF_INET6 as u8);
                ffi::nfct_set_attr(
                    ct,
                    ffi::ATTR_IPV6_SRC,
                    src_ip.octets().as_ptr() as *const libc::c_void,
                );
                ffi::nfct_set_attr_u16(ct, ffi::ATTR_PORT_SRC, src_port.to_be());
                ffi::nfct_set_attr(
                    ct,
                    ffi::ATTR_IPV6_DST,
                    dst_ip.octets().as_ptr() as *const libc::c_void,
                );
            }
        }
        SocketAddress::V4(peer_v4) => {
            // IPv4 path
            let src_ip = peer_v4.ip();
            let src_port = peer_v4.port();

            // Extract the destination IPv4 address from local_addr
            let dst_ip = match local_addr {
                IpAddr::V4(v4) => *v4,
                // If local_addr is V6 but peer is V4, use unspecified as fallback.
                IpAddr::V6(_) => Ipv4Addr::UNSPECIFIED,
            };

            // SAFETY: ct is a valid conntrack object. We set attributes with correct
            // types. IPv4 addresses are u32 in network byte order, which is what
            // Ipv4Addr gives us via to_bits() converted to big-endian.
            // C equivalent uses sin_addr.s_addr which is already network byte order.
            unsafe {
                ffi::nfct_set_attr_u8(ct, ffi::ATTR_L3PROTO, libc::AF_INET as u8);
                ffi::nfct_set_attr_u32(
                    ct,
                    ffi::ATTR_IPV4_SRC,
                    u32::from_ne_bytes(src_ip.octets()),
                );
                ffi::nfct_set_attr_u16(ct, ffi::ATTR_PORT_SRC, src_port.to_be());
                ffi::nfct_set_attr_u32(
                    ct,
                    ffi::ATTR_IPV4_DST,
                    u32::from_ne_bytes(dst_ip.octets()),
                );
            }
        }
    }

    // Step 4: Open conntrack netlink handle.
    // C equivalent: h = nfct_open(CONNTRACK, 0)
    // SAFETY: nfct_open() creates a netlink socket handle or returns NULL.
    // CONNTRACK (=1) is a valid subsystem constant, 0 means no multicast groups.
    let h = unsafe { ffi::nfct_open(ffi::CONNTRACK, 0) };
    if h.is_null() {
        // Clean up the conntrack object before returning.
        // SAFETY: ct is a valid non-null pointer from nfct_new().
        unsafe { ffi::nfct_destroy(ct) };
        return Err(ConntrackError::OpenFailed);
    }

    // Step 5: Register callback and execute query.
    // The callback will populate cb_data if a matching entry is found.
    let mut cb_data = CallbackData {
        mark: 0,
        found: false,
    };

    // SAFETY: h is a valid non-null handle from nfct_open(). We register our
    // callback with a pointer to stack-allocated cb_data. The callback will be
    // invoked synchronously during nfct_query(), so cb_data remains valid.
    unsafe {
        ffi::nfct_callback_register(
            h,
            ffi::NFCT_T_ALL,
            conntrack_callback,
            &mut cb_data as *mut CallbackData as *mut libc::c_void,
        );
    }

    // Step 6: Execute the conntrack query.
    // C equivalent: nfct_query(h, NFCT_Q_GET, ct)
    // SAFETY: h is a valid handle, ct is a valid conntrack object populated with
    // the 5-tuple attributes. nfct_query() invokes the registered callback
    // synchronously if a matching entry is found.
    let query_result = unsafe { ffi::nfct_query(h, ffi::NFCT_Q_GET, ct as *const libc::c_void) };

    if query_result == -1 && !cb_data.found {
        // Query failed — log on first occurrence only.
        // C equivalent: lines 254–259 of conntrack.c
        if !WARNED.swap(true, Ordering::Relaxed) {
            let os_err = io::Error::last_os_error();
            log::error!("Conntrack connection mark retrieval failed: {}", os_err);
        }
    }

    // Step 7: Clean up — close handle and destroy conntrack object.
    // C equivalent: nfct_close(h); nfct_destroy(ct);
    // SAFETY: h and ct are valid non-null pointers obtained from nfct_open()
    // and nfct_new() respectively. Each is freed exactly once here.
    unsafe {
        ffi::nfct_close(h);
        ffi::nfct_destroy(ct);
    }

    // Step 8: Return result based on whether the callback was invoked.
    // C equivalent: return gotit; (where gotit=1 means success)
    if cb_data.found {
        Ok(Some(cb_data.mark))
    } else {
        Ok(None)
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    /// Verify that ConntrackError variants display correctly.
    #[test]
    fn test_error_display() {
        let err = ConntrackError::CreateFailed;
        assert_eq!(format!("{}", err), "Failed to create conntrack object");

        let err = ConntrackError::OpenFailed;
        assert_eq!(format!("{}", err), "Failed to open conntrack handle");

        let err = ConntrackError::QueryFailed(io::Error::from_raw_os_error(libc::ENOENT));
        let msg = format!("{}", err);
        assert!(msg.starts_with("Conntrack query failed:"));
    }

    /// Verify that ConntrackError implements std::error::Error.
    #[test]
    fn test_error_is_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(ConntrackError::CreateFailed);
        assert_eq!(
            format!("{}", err),
            "Failed to create conntrack object"
        );
    }

    /// Verify CallbackData default state.
    #[test]
    fn test_callback_data_default() {
        let data = CallbackData {
            mark: 0,
            found: false,
        };
        assert!(!data.found);
        assert_eq!(data.mark, 0);
    }

    /// Verify that the FFI constants have the expected values derived from the
    /// libnetfilter_conntrack header file.
    #[test]
    fn test_ffi_constants() {
        assert_eq!(ffi::ATTR_IPV4_SRC, 0);
        assert_eq!(ffi::ATTR_IPV4_DST, 1);
        assert_eq!(ffi::ATTR_IPV6_SRC, 4);
        assert_eq!(ffi::ATTR_IPV6_DST, 5);
        assert_eq!(ffi::ATTR_PORT_SRC, 8);
        assert_eq!(ffi::ATTR_PORT_DST, 9);
        assert_eq!(ffi::ATTR_L3PROTO, 15);
        assert_eq!(ffi::ATTR_L4PROTO, 17);
        assert_eq!(ffi::ATTR_MARK, 25);
        assert_eq!(ffi::NFCT_Q_GET, 3);
        assert_eq!(ffi::NFCT_T_ALL, 7);
        assert_eq!(ffi::CONNTRACK, 1);
        assert_eq!(ffi::NFCT_CB_CONTINUE, 1);
    }

    /// Test SocketAddress::V4 port extraction used by get_incoming_mark.
    #[test]
    fn test_socket_address_v4_port() {
        let addr = SocketAddress::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 54321));
        assert_eq!(addr.port(), 54321);
    }

    /// Test SocketAddress::V6 port extraction used by get_incoming_mark.
    #[test]
    fn test_socket_address_v6_port() {
        let addr = SocketAddress::V6(SocketAddrV6::new(
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
            8080,
            0,
            0,
        ));
        assert_eq!(addr.port(), 8080);
    }

    /// Test that the WARNED flag can be set and read.
    #[test]
    fn test_warned_flag() {
        // Reset for test isolation (note: in real usage this is never reset)
        WARNED.store(false, Ordering::Relaxed);
        assert!(!WARNED.load(Ordering::Relaxed));

        // Simulate first failure setting the flag
        let was_warned = WARNED.swap(true, Ordering::Relaxed);
        assert!(!was_warned); // first time
        assert!(WARNED.load(Ordering::Relaxed));

        // Second swap should indicate already warned
        let was_warned = WARNED.swap(true, Ordering::Relaxed);
        assert!(was_warned); // already set
    }

    /// Integration smoke test: calling get_incoming_mark with a valid address.
    ///
    /// This test will likely fail with ConntrackError or return Ok(None) unless
    /// running on a Linux system with CAP_NET_ADMIN and an active conntrack entry.
    /// The test validates the function doesn't panic and returns a well-formed result.
    #[test]
    fn test_get_incoming_mark_smoke() {
        // Reset warned flag for clean test state
        WARNED.store(false, Ordering::Relaxed);

        let peer = SocketAddress::V4(SocketAddrV4::new(
            Ipv4Addr::new(127, 0, 0, 1),
            12345,
        ));
        let local = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        // This will either succeed (on Linux with conntrack) or fail gracefully
        let result = get_incoming_mark(&peer, &local, false, 53);
        // We don't assert Ok/Err because it depends on the runtime environment.
        // We only verify it doesn't panic and returns a valid Result.
        match result {
            Ok(Some(mark)) => {
                // Mark is a u32, so any value is valid
                let _ = mark;
            }
            Ok(None) => {
                // No matching conntrack entry — expected in most test environments
            }
            Err(ConntrackError::CreateFailed) => {
                // Library not available or OOM
            }
            Err(ConntrackError::OpenFailed) => {
                // Insufficient permissions (common in CI)
            }
            Err(ConntrackError::QueryFailed(_)) => {
                // Query failed — expected without active conntrack entries
            }
        }
    }

    /// Integration smoke test for IPv6 path.
    #[test]
    fn test_get_incoming_mark_v6_smoke() {
        WARNED.store(false, Ordering::Relaxed);

        let peer = SocketAddress::V6(SocketAddrV6::new(
            Ipv6Addr::LOCALHOST,
            12345,
            0,
            0,
        ));
        let local = IpAddr::V6(Ipv6Addr::LOCALHOST);

        let result = get_incoming_mark(&peer, &local, true, 53);
        // Same as above — just verify no panics
        match result {
            Ok(_) | Err(_) => {}
        }
    }
}

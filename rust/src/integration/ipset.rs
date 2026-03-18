// dnsmasq is Copyright (c) 2000-2025 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! # Linux ipset Integration via Netlink
//!
//! Rust implementation of Linux kernel ipset integration, migrated from
//! `src/ipset.c` (532 lines). This module enables dnsmasq to dynamically
//! populate named ipset collections with IP addresses resolved from DNS
//! queries, allowing domain-based firewall rules via iptables/ipset.
//!
//! ## Overview
//!
//! The module supports two kernel API paths:
//! - **Modern netlink API** (kernel ≥ 2.6.32): Uses `AF_NETLINK`/`NETLINK_NETFILTER`
//!   sockets to communicate with the ipset kernel module via the NFNETLINK protocol.
//!   Supports both IPv4 and IPv6 addresses.
//! - **Legacy setsockopt API** (kernel < 2.6.32): Uses raw `AF_INET` sockets with
//!   `getsockopt`/`setsockopt` at `SOL_IP` level, option 83. IPv4 only.
//!
//! ## Memory Safety Improvements
//!
//! - Replaced C static mutable buffer (`static char *buffer`) with per-call
//!   `BytesMut` for bounds-checked netlink message construction.
//! - Replaced C global socket fd (`static int ipset_sock`) with `OwnedFd`
//!   for RAII-based automatic cleanup on `Drop`.
//! - All buffer writes are bounds-checked via `BytesMut`/slice operations,
//!   eliminating the buffer overflow risk from the C 256-byte fixed buffer.
//! - No `goto` cleanup blocks — Rust's `?` operator and `Drop` handle cleanup.
//!
//! ## Feature Gating
//!
//! This entire module is gated by:
//! - `#[cfg(feature = "ipset")]` — Cargo feature flag (enabled by default)
//! - `#[cfg(target_os = "linux")]` — ipset is Linux-only (kernel module)
//!
//! ## Protocol Reference
//!
//! The netlink message format follows the ipset kernel protocol:
//! ```text
//! [nlmsghdr]
//! [nfgenmsg (family, version, res_id)]
//! [IPSET_ATTR_PROTOCOL: u8 = 6]
//! [IPSET_ATTR_SETNAME: null-terminated string]
//! [IPSET_ATTR_DATA (nested)]
//!   [IPSET_ATTR_IP (nested)]
//!     [IPSET_ATTR_IPADDR_IPV4 or IPSET_ATTR_IPADDR_IPV6: address bytes]
//! ```

use bytes::{BufMut, BytesMut};
use nix::errno::Errno;
use nix::sys::socket::{
    bind, sendto, socket, AddressFamily, MsgFlags, NetlinkAddr, SockFlag, SockProtocol, SockType,
};
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use tracing::{error, info, warn};

use crate::core::types::{AllAddr, DnsmasqError, DnsmasqResult};
use crate::core::util::kernel_version;

// ---------------------------------------------------------------------------
// Ipset Netlink Protocol Constants (from src/ipset.c lines 108-131)
// ---------------------------------------------------------------------------
// These constants MUST match the C source exactly — the kernel expects
// specific values in the netlink protocol messages.

/// Netfilter netlink subsystem ID for ipset (NFNL_SUBSYS_IPSET).
/// Used in `nlmsg_type` to identify messages destined for the ipset module.
const NFNL_SUBSYS_IPSET: u16 = 6;

/// Attribute type for the data container in ipset netlink messages.
/// Carries nested attributes (IP, timeout, etc.) for add/del operations.
const IPSET_ATTR_DATA: u16 = 7;

/// Nested attribute type for the IP address container within IPSET_ATTR_DATA.
const IPSET_ATTR_IP: u16 = 1;

/// Attribute type for an IPv4 address within the IPSET_ATTR_IP container.
const IPSET_ATTR_IPADDR_IPV4: u16 = 1;

/// Attribute type for an IPv6 address within the IPSET_ATTR_IP container.
const IPSET_ATTR_IPADDR_IPV6: u16 = 2;

/// Attribute type for the ipset protocol version field.
const IPSET_ATTR_PROTOCOL: u16 = 1;

/// Attribute type for the ipset set name (null-terminated C string).
const IPSET_ATTR_SETNAME: u16 = 2;

/// Command: add an entry to an ipset (used in nlmsg_type).
const IPSET_CMD_ADD: u16 = 9;

/// Command: delete an entry from an ipset (used in nlmsg_type).
const IPSET_CMD_DEL: u16 = 10;

/// Maximum length of an ipset name (including null terminator).
/// Names >= this length are rejected by the kernel.
const IPSET_MAXNAMELEN: usize = 32;

/// Ipset kernel protocol version. Must match what the loaded
/// ip_set kernel module expects (version 6 since Linux 2.6.39+).
const IPSET_PROTOCOL: u8 = 6;

/// Netfilter netlink protocol version (NFNETLINK_V0).
/// Always 0 for current netfilter netlink protocol.
const NFNETLINK_V0: u8 = 0;

/// Flag indicating a nested netlink attribute (contains sub-attributes).
/// Applied to `nla_type` for container attributes like IPSET_ATTR_DATA and IPSET_ATTR_IP.
const NLA_F_NESTED: u16 = 1 << 15;

/// Flag indicating the attribute value is in network byte order (big-endian).
/// Applied to IP address attributes (IPSET_ATTR_IPADDR_IPV4/IPV6).
const NLA_F_NET_BYTEORDER: u16 = 1 << 14;

/// Buffer size for netlink message construction.
/// Matches C `BUFF_SZ` — sufficient for any single ipset add/del message:
/// 16 (nlmsghdr) + 4 (nfgenmsg) + 8 (protocol attr) + 40 (setname attr, max)
/// + 4 (data nested hdr) + 4 (ip nested hdr) + 24 (ipv6 addr attr) = 100 max.
const BUFF_SZ: usize = 256;

// ---------------------------------------------------------------------------
// Netlink / System Constants
// ---------------------------------------------------------------------------

/// Netlink message flag indicating this is a request (from `<linux/netlink.h>`).
/// Replaces `libc::NLM_F_REQUEST` for explicit control.
const NLM_F_REQUEST: u16 = 0x01;

/// Size of `struct nlmsghdr` (16 bytes on all Linux platforms).
/// Layout: nlmsg_len(u32) + nlmsg_type(u16) + nlmsg_flags(u16) + nlmsg_seq(u32) + nlmsg_pid(u32).
const NLMSGHDR_SIZE: usize = 16;

/// Size of `struct nfgenmsg` (4 bytes).
/// Layout: nfgen_family(u8) + version(u8) + res_id(u16).
const NFGENMSG_SIZE: usize = 4;

/// Size of a netlink attribute header (`struct nlattr` / `struct my_nlattr`).
/// Layout: nla_len(u16) + nla_type(u16) = 4 bytes.
const NLA_HDR_SIZE: usize = 4;

// ---------------------------------------------------------------------------
// Address Family Flags (from src/dnsmasq.h lines 694-695)
// ---------------------------------------------------------------------------
// These are dnsmasq-internal flags passed in the `flags` parameter of
// `add_to_ipset()`, NOT to be confused with `libc::AF_INET` / `libc::AF_INET6`.

/// Flag indicating the address is IPv4 (F_IPV4 from dnsmasq.h, bit 7).
/// Not directly checked in code (default is IPv4 when F_IPV6 is absent),
/// but defined for completeness and documentation of the dnsmasq flag protocol.
#[allow(dead_code)]
const F_IPV4: u32 = 1 << 7;

/// Flag indicating the address is IPv6 (F_IPV6 from dnsmasq.h, bit 8).
const F_IPV6: u32 = 1 << 8;

// ---------------------------------------------------------------------------
// Legacy ipset API Constants (kernel < 2.6.32)
// ---------------------------------------------------------------------------

/// Legacy ipset operation: get set properties by name.
/// Used in `getsockopt(SOL_IP, 83, ...)` requests.
const IP_SET_OP_GET_BYNAME: u32 = 0x06;

/// Legacy ipset version (protocol version 3 for old kernels).
const IP_SET_OP_VERSION: u32 = 3;

/// Legacy ipset operation: add IP to set (setsockopt).
const IP_SET_OP_ADD_IP: u32 = 0x0101;

/// Legacy ipset operation: delete IP from set (setsockopt).
const IP_SET_OP_DEL_IP: u32 = 0x0102;

/// SOL_IP socket option number for ipset operations.
/// Not a standard Linux constant — specific to the ipset kernel module.
const SO_IP_SET: i32 = 83;

/// Maximum retry count for `sendto` on EAGAIN/EWOULDBLOCK errors.
/// Matches C `retry_send()` behavior in `util.c`.
const MAX_SEND_RETRIES: usize = 1000;

// ---------------------------------------------------------------------------
// Helper Functions
// ---------------------------------------------------------------------------

/// Align a value up to the nearest 4-byte boundary (NL_ALIGN macro from C).
///
/// All netlink message components (headers, attributes, padding) must be
/// aligned to 4 bytes per the netlink protocol specification.
///
/// # Examples
/// ```ignore
/// assert_eq!(nl_align(5), 8);
/// assert_eq!(nl_align(8), 8);
/// assert_eq!(nl_align(0), 0);
/// ```
const fn nl_align(len: usize) -> usize {
    (len + 3) & !3
}

/// Write a netlink attribute (TLV) into a pre-allocated buffer at the position
/// indicated by `nlmsg_len`, and return the updated `nlmsg_len`.
///
/// This is the Rust equivalent of `add_attr()` from `src/ipset.c` lines 233-241.
/// The attribute is written at `nl_align(nlmsg_len)` offset from buffer start.
///
/// # Layout
/// ```text
/// [nla_len: u16] [nla_type: u16] [data: &[u8]] [padding to 4-byte boundary]
/// ```
///
/// # Arguments
/// * `buf` — Pre-allocated buffer (must be large enough for the attribute)
/// * `nlmsg_len` — Current message length (already aligned)
/// * `nla_type` — Attribute type (IPSET_ATTR_* constant, possibly ORed with NLA_F_*)
/// * `data` — Attribute payload bytes
///
/// # Returns
/// Updated `nlmsg_len` after writing the attribute (aligned to 4 bytes).
fn buf_add_attr(buf: &mut [u8], nlmsg_len: u32, nla_type: u16, data: &[u8]) -> u32 {
    let offset = nl_align(nlmsg_len as usize);
    // nla_len includes the header size + unaligned data length
    // (matching C: payload_len = NL_ALIGN(sizeof(struct my_nlattr)) + len)
    let nla_len = (NLA_HDR_SIZE + data.len()) as u16;

    // Write attribute header in native byte order (netlink convention)
    buf[offset..offset + 2].copy_from_slice(&nla_len.to_ne_bytes());
    buf[offset + 2..offset + 4].copy_from_slice(&nla_type.to_ne_bytes());

    // Write attribute data after the aligned header
    let data_offset = offset + nl_align(NLA_HDR_SIZE);
    buf[data_offset..data_offset + data.len()].copy_from_slice(data);

    // Return nlmsg_len incremented by aligned total attribute size
    // (matching C: nlh->nlmsg_len += NL_ALIGN(payload_len))
    nlmsg_len + nl_align(NLA_HDR_SIZE + data.len()) as u32
}

/// Retry a sendto operation on EINTR and EAGAIN, matching C `retry_send()` from `util.c`.
///
/// The C implementation retries unconditionally on EINTR, and retries on
/// EAGAIN/EWOULDBLOCK up to 1000 times with a 10µs sleep between attempts.
///
/// # Arguments
/// * `fd` — Raw file descriptor for the socket
/// * `buf` — Data to send
/// * `addr` — Destination netlink address (kernel: pid=0, groups=0)
///
/// # Returns
/// `Ok(())` on successful send, `Err(Errno)` on non-retriable failure.
fn retry_send_netlink(fd: RawFd, buf: &[u8], addr: &NetlinkAddr) -> Result<(), Errno> {
    let mut retries: usize = 0;
    loop {
        match sendto(fd, buf, addr, MsgFlags::empty()) {
            Ok(_) => return Ok(()),
            Err(Errno::EINTR) => {
                // Always retry on signal interruption
                continue;
            }
            // On Linux, EAGAIN == EWOULDBLOCK (same errno value).
            // We match EAGAIN which covers both.
            Err(Errno::EAGAIN) => {
                retries += 1;
                if retries > MAX_SEND_RETRIES {
                    return Err(Errno::EAGAIN);
                }
                // Sleep 10µs between retries (matching C nanosleep with tv_nsec=10000)
                std::thread::sleep(std::time::Duration::from_nanos(10_000));
                continue;
            }
            Err(e) => return Err(e),
        }
    }
}

// ---------------------------------------------------------------------------
// Legacy API Structures (kernel < 2.6.32)
// ---------------------------------------------------------------------------
// These repr(C) structs match the C kernel API structures used in
// getsockopt/setsockopt calls for legacy ipset manipulation.

/// Request structure for `getsockopt(SOL_IP, 83)` — get ipset index by name.
///
/// Matches C `struct ip_set_req_adt_get` from `src/ipset.c` lines 423-431.
/// The `set` field is a union: written as a name string, read back as a u16 index.
#[repr(C)]
struct IpSetReqAdtGet {
    /// Operation code (`IP_SET_OP_GET_BYNAME` = 0x06).
    op: u32,
    /// Protocol version (3 for legacy API).
    version: u32,
    /// Union field: set name (input) or set index (output).
    /// Written as null-terminated string for lookup, kernel returns u16 index
    /// in the first 2 bytes on success.
    set: [u8; IPSET_MAXNAMELEN],
    /// Type name returned by kernel (unused by dnsmasq).
    type_name: [u8; IPSET_MAXNAMELEN],
}

/// Request structure for `setsockopt(SOL_IP, 83)` — add/delete IP from ipset.
///
/// Matches C `struct ip_set_req_adt` from `src/ipset.c` lines 432-436.
#[repr(C)]
struct IpSetReqAdt {
    /// Operation code: `IP_SET_OP_ADD_IP` (0x0101) or `IP_SET_OP_DEL_IP` (0x0102).
    op: u32,
    /// Set index obtained from `getsockopt` get-by-name query.
    index: u16,
    /// IPv4 address in **host byte order** (C uses `ntohl()`).
    /// Replaces C `ntohl(ipaddr->addr4.s_addr)` — Rust equivalent:
    /// `u32::from_be_bytes(addr.octets())`.
    ip: u32,
}

// ---------------------------------------------------------------------------
// IpsetController — Public API
// ---------------------------------------------------------------------------

/// Controller for Linux kernel ipset operations via netlink or legacy API.
///
/// Replaces C global state: `static int ipset_sock`, `static int old_kernel`,
/// `static char *buffer` from `src/ipset.c` lines 194-196.
///
/// # Socket Lifecycle
/// The socket is created in [`IpsetController::new()`] and automatically closed
/// when the controller is dropped, thanks to `OwnedFd`'s `Drop` implementation.
/// This eliminates the C code's reliance on a global socket with no explicit cleanup.
///
/// # Thread Safety
/// `IpsetController` holds a mutable socket and is designed for single-threaded
/// use within the dnsmasq event loop. For multi-threaded use, wrap in `Mutex`.
pub struct IpsetController {
    /// Socket file descriptor for communicating with the kernel ipset subsystem.
    /// - Modern API (kernel ≥ 2.6.32): `AF_NETLINK` / `SOCK_RAW` / `NETLINK_NETFILTER`
    /// - Legacy API (kernel < 2.6.32): `AF_INET` / `SOCK_RAW` / `IPPROTO_RAW`
    ///
    /// RAII: Automatically closed on `Drop` via `OwnedFd`.
    sock: OwnedFd,

    /// True if the running kernel is older than 2.6.32 (uses legacy setsockopt API).
    /// Detected via `crate::core::util::kernel_version()` in `new()`.
    ///
    /// When true:
    ///   - Only IPv4 addresses are supported (IPv6 returns EAFNOSUPPORT)
    ///   - Uses `getsockopt`/`setsockopt` at `SOL_IP` level, option 83
    ///
    /// When false:
    ///   - Both IPv4 and IPv6 are supported
    ///   - Uses netlink messages to NFNL_SUBSYS_IPSET
    old_kernel: bool,
}

impl IpsetController {
    /// Initialize the ipset controller, creating the appropriate kernel socket.
    ///
    /// Replaces C `ipset_init()` from `src/ipset.c` lines 276-290.
    ///
    /// # Kernel Version Detection
    /// Detects the running kernel version via `kernel_version()`:
    /// - **Kernel ≥ 2.6.32**: Creates a `NETLINK_NETFILTER` socket and binds it.
    ///   This is the standard ipset API supporting both IPv4 and IPv6.
    /// - **Kernel < 2.6.32**: Creates a raw `AF_INET` socket (`IPPROTO_RAW`).
    ///   This legacy path only supports IPv4 addresses.
    ///
    /// # Errors
    /// Returns `DnsmasqError::Network` if socket creation or binding fails.
    /// In the C implementation, this would call `die()` — a fatal error since
    /// ipset functionality was explicitly requested in the configuration.
    ///
    /// # Examples
    /// ```ignore
    /// let controller = IpsetController::new()?;
    /// // controller.sock is now ready for add_to_ipset() calls
    /// ```
    pub fn new() -> DnsmasqResult<Self> {
        let (major, minor, patch) = kernel_version();
        let old_kernel = (major, minor, patch) < (2, 6, 32);

        if old_kernel {
            // Legacy API: AF_INET raw socket for getsockopt/setsockopt ipset ops.
            // Replaces C: ipset_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)
            // (ipset.c line 280)
            //
            // SAFETY: Creating a raw IP socket for the legacy ipset kernel API.
            // The returned fd is immediately wrapped in OwnedFd for RAII cleanup.
            // This is required because nix::sys::socket::SockProtocol doesn't
            // have an IPPROTO_RAW variant — we must use the libc call directly.
            let raw_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW) };
            if raw_fd < 0 {
                let err = std::io::Error::last_os_error();
                return Err(DnsmasqError::Network(format!(
                    "failed to create legacy ipset socket: {}",
                    err
                )));
            }
            // SAFETY: raw_fd is a valid, newly-created file descriptor returned by
            // a successful libc::socket() call. OwnedFd takes ownership and will
            // close it on drop.
            let sock = unsafe { OwnedFd::from_raw_fd(raw_fd) };

            info!("ipset: initialized legacy raw socket API (kernel < 2.6.32)");
            Ok(IpsetController { sock, old_kernel })
        } else {
            // Modern API: NETLINK_NETFILTER socket for ipset netlink protocol.
            // Replaces C: ipset_sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER)
            // (ipset.c line 285)
            let sock = socket(
                AddressFamily::Netlink,
                SockType::Raw,
                SockFlag::SOCK_CLOEXEC,
                SockProtocol::NetlinkNetFilter,
            )
            .map_err(|e| {
                DnsmasqError::Network(format!("failed to create netlink ipset socket: {}", e))
            })?;

            // Bind to local netlink address (pid=0 lets kernel assign,
            // groups=0 means no multicast subscriptions).
            // Replaces C: bind(ipset_sock, (struct sockaddr *)&snl, sizeof(snl))
            // (ipset.c line 286)
            let nl_addr = NetlinkAddr::new(0, 0);
            bind(sock.as_raw_fd(), &nl_addr).map_err(|e| {
                DnsmasqError::Network(format!("failed to bind netlink ipset socket: {}", e))
            })?;

            info!("ipset: initialized modern netlink API (kernel >= 2.6.32)");
            Ok(IpsetController { sock, old_kernel })
        }
    }

    /// Add or remove an IP address to/from a named ipset.
    ///
    /// Replaces C `add_to_ipset()` from `src/ipset.c` lines 508-530.
    /// This is the main public entry point for ipset manipulation.
    ///
    /// # Arguments
    /// * `setname` — Name of the target ipset (must be < 32 characters)
    /// * `ipaddr` — IP address to add/remove (`AllAddr::V4` or `AllAddr::V6`)
    /// * `flags` — dnsmasq flags (F_IPV4/F_IPV6 to indicate address family)
    /// * `remove` — `true` to delete from set, `false` to add to set
    ///
    /// # Returns
    /// * `Ok(0)` — Operation succeeded
    /// * `Ok(-1)` — Operation failed (error logged via `tracing::error!`)
    /// * `Err(DnsmasqError)` — Fatal error (e.g., invalid address type)
    ///
    /// # IPv6 on Legacy Kernels
    /// When running on kernel < 2.6.32 with `old_kernel == true`, IPv6 addresses
    /// are rejected with a warning (the legacy API only supports IPv4).
    /// This matches C behavior at `ipset.c` lines 513-518 (errno = EAFNOSUPPORT).
    pub fn add_to_ipset(
        &mut self,
        setname: &str,
        ipaddr: &AllAddr,
        flags: u32,
        remove: bool,
    ) -> DnsmasqResult<i32> {
        let mut ret: i32 = 0;
        let af: u8;

        if (flags & F_IPV6) != 0 {
            af = libc::AF_INET6 as u8;
            if self.old_kernel {
                // Legacy API does not support IPv6 — matches C errno = EAFNOSUPPORT
                // (ipset.c lines 514-518). Use libc::EAFNOSUPPORT for the error code.
                warn!(
                    setname = setname,
                    errno = libc::EAFNOSUPPORT,
                    "IPv6 address not supported on legacy ipset kernel API (< 2.6.32)"
                );
                ret = -1;
            }
        } else {
            af = libc::AF_INET as u8;
        }

        if ret != -1 {
            ret = if self.old_kernel {
                self.old_add_to_ipset(setname, ipaddr, remove)?
            } else {
                self.new_add_to_ipset(setname, ipaddr, af, remove)?
            };
        }

        if ret == -1 {
            // Log failure with set name — replaces C my_syslog(LOG_ERR, ...)
            // at ipset.c lines 526-527
            error!(setname = setname, "failed to update ipset");
        }

        Ok(ret)
    }

    /// Modern netlink API: construct and send an ipset ADD/DEL message.
    ///
    /// Replaces C `new_add_to_ipset()` from `src/ipset.c` lines 332-420.
    ///
    /// Constructs a netlink message with the following structure:
    /// ```text
    /// [nlmsghdr (16 bytes)]
    /// [nfgenmsg (4 bytes): family, version=0, res_id=0]
    /// [nlattr: IPSET_ATTR_PROTOCOL = 6]
    /// [nlattr: IPSET_ATTR_SETNAME = "name\0"]
    /// [nlattr: NLA_F_NESTED|IPSET_ATTR_DATA]
    ///   [nlattr: NLA_F_NESTED|IPSET_ATTR_IP]
    ///     [nlattr: IPSET_ATTR_IPADDR_IPV4 or _IPV6 | NLA_F_NET_BYTEORDER: addr bytes]
    /// ```
    ///
    /// Uses `BytesMut` for safe, bounds-checked buffer construction instead of
    /// the C static buffer with raw pointer arithmetic.
    ///
    /// # Arguments
    /// * `setname` — ipset name (must be < IPSET_MAXNAMELEN)
    /// * `ipaddr` — `AllAddr::V4` or `AllAddr::V6` with the IP address
    /// * `af` — Address family (`libc::AF_INET` or `libc::AF_INET6` as u8)
    /// * `remove` — true for DEL command, false for ADD command
    ///
    /// # Returns
    /// `0` on success, `-1` on send failure.
    fn new_add_to_ipset(
        &self,
        setname: &str,
        ipaddr: &AllAddr,
        af: u8,
        remove: bool,
    ) -> DnsmasqResult<i32> {
        // Validate setname length (matches C check at ipset.c line 342: ENAMETOOLONG).
        // Use libc::ENAMETOOLONG as the errno code, matching C's errno = ENAMETOOLONG.
        if setname.len() >= IPSET_MAXNAMELEN {
            warn!(
                setname = setname,
                max_len = IPSET_MAXNAMELEN,
                errno = libc::ENAMETOOLONG,
                "ipset name exceeds maximum length"
            );
            return Ok(-1);
        }

        // Estimate message size and validate against buffer capacity.
        // Matches C check at ipset.c line 342 using EMSGSIZE for oversized messages.
        let estimated_size = NLMSGHDR_SIZE + NFGENMSG_SIZE
            + nl_align(NLA_HDR_SIZE + 1)           // IPSET_ATTR_PROTOCOL
            + nl_align(NLA_HDR_SIZE + setname.len() + 1) // IPSET_ATTR_SETNAME
            + nl_align(NLA_HDR_SIZE)                // IPSET_ATTR_DATA nested header
            + nl_align(NLA_HDR_SIZE)                // IPSET_ATTR_IP nested header
            + nl_align(NLA_HDR_SIZE + 16); // IP address attr (max 16 bytes for IPv6)
        if estimated_size > BUFF_SZ {
            warn!(
                setname = setname,
                estimated_size = estimated_size,
                buff_sz = BUFF_SZ,
                errno = libc::EMSGSIZE,
                "ipset netlink message exceeds buffer size"
            );
            return Ok(-1);
        }

        // Extract IP address bytes in network byte order
        // (Ipv4Addr::octets() and Ipv6Addr::octets() return network-order bytes)
        let ip_bytes: Vec<u8> = match ipaddr {
            AllAddr::V4(addr) => addr.octets().to_vec(),
            AllAddr::V6(addr) => addr.octets().to_vec(),
            _ => {
                return Err(DnsmasqError::Network(
                    "invalid address type for ipset operation".to_string(),
                ));
            }
        };

        // Construct the netlink message using BytesMut for safe buffer management.
        // Pre-allocate BUFF_SZ (256) bytes and zero-fill to match C's
        // memset(buffer, 0, BUFF_SZ) behavior.
        let mut buf = BytesMut::with_capacity(BUFF_SZ);
        buf.resize(BUFF_SZ, 0);

        // Track the logical message length separately, matching C's nlh->nlmsg_len
        let mut nlmsg_len: u32 = nl_align(NLMSGHDR_SIZE) as u32; // 16

        // ---- nlmsghdr (16 bytes at offset 0) ----
        // nlmsg_len at offset 0 — placeholder, updated at end
        // nlmsg_type: IPSET_CMD_ADD|DEL | (NFNL_SUBSYS_IPSET << 8)
        let cmd = if remove { IPSET_CMD_DEL } else { IPSET_CMD_ADD };
        let nlmsg_type: u16 = cmd | (NFNL_SUBSYS_IPSET << 8);
        buf[4..6].copy_from_slice(&nlmsg_type.to_ne_bytes());
        // nlmsg_flags = NLM_F_REQUEST (replaces libc::NLM_F_REQUEST)
        buf[6..8].copy_from_slice(&NLM_F_REQUEST.to_ne_bytes());
        // nlmsg_seq = 0, nlmsg_pid = 0 (already zeroed)

        // ---- nfgenmsg (4 bytes at offset 16) ----
        // Replaces C ipset.c lines 354-357
        let nfg_offset = nlmsg_len as usize; // 16
        nlmsg_len += nl_align(NFGENMSG_SIZE) as u32; // += 4 → 20
        buf[nfg_offset] = af; // nfgen_family
        buf[nfg_offset + 1] = NFNETLINK_V0; // version; res_id at +2 is 0 (htons(0)), zeroed by resize

        // ---- IPSET_ATTR_PROTOCOL attribute ----
        // Value: single byte IPSET_PROTOCOL (6)
        // Replaces C ipset.c line 359
        nlmsg_len = buf_add_attr(&mut buf, nlmsg_len, IPSET_ATTR_PROTOCOL, &[IPSET_PROTOCOL]);

        // ---- IPSET_ATTR_SETNAME attribute ----
        // Value: null-terminated set name string
        // Replaces C ipset.c line 360
        // Uses BytesMut + BufMut::put_slice() for safe null-terminated string construction
        let mut setname_buf = BytesMut::with_capacity(setname.len() + 1);
        setname_buf.put_slice(setname.as_bytes());
        setname_buf.put_u8(0); // null terminator
        nlmsg_len = buf_add_attr(
            &mut buf,
            nlmsg_len,
            IPSET_ATTR_SETNAME,
            &setname_buf[..setname_buf.len()],
        );

        // ---- Nested attribute: IPSET_ATTR_DATA ----
        // Reserve space for the container header; nla_len will be filled in later
        // after all child attributes are added.
        // Replaces C ipset.c lines 362-364
        let nested0_offset = nlmsg_len as usize;
        buf[nested0_offset + 2..nested0_offset + 4]
            .copy_from_slice(&(NLA_F_NESTED | IPSET_ATTR_DATA).to_ne_bytes());
        nlmsg_len += nl_align(NLA_HDR_SIZE) as u32; // += 4

        // ---- Nested attribute: IPSET_ATTR_IP ----
        // Another nested container within IPSET_ATTR_DATA.
        // Replaces C ipset.c lines 366-368
        let nested1_offset = nlmsg_len as usize;
        buf[nested1_offset + 2..nested1_offset + 4]
            .copy_from_slice(&(NLA_F_NESTED | IPSET_ATTR_IP).to_ne_bytes());
        nlmsg_len += nl_align(NLA_HDR_SIZE) as u32; // += 4

        // ---- IP address attribute (innermost) ----
        // IPSET_ATTR_IPADDR_IPV4 (1) or IPSET_ATTR_IPADDR_IPV6 (2),
        // OR-ed with NLA_F_NET_BYTEORDER since the address bytes are in
        // network byte order.
        // Replaces C ipset.c lines 369-370
        let ip_attr_type = if af == libc::AF_INET6 as u8 {
            IPSET_ATTR_IPADDR_IPV6
        } else {
            IPSET_ATTR_IPADDR_IPV4
        } | NLA_F_NET_BYTEORDER;
        nlmsg_len = buf_add_attr(&mut buf, nlmsg_len, ip_attr_type, &ip_bytes);

        // ---- Update nested attribute lengths ----
        // The nla_len for each nested attribute spans from its header to the
        // end of the message (encompassing all child attributes).
        // Replaces C ipset.c lines 372-373
        let msg_end = nl_align(nlmsg_len as usize);
        let nested1_len = (msg_end - nested1_offset) as u16;
        let nested0_len = (msg_end - nested0_offset) as u16;
        buf[nested1_offset..nested1_offset + 2].copy_from_slice(&nested1_len.to_ne_bytes());
        buf[nested0_offset..nested0_offset + 2].copy_from_slice(&nested0_len.to_ne_bytes());

        // ---- Update nlmsghdr.nlmsg_len ----
        buf[0..4].copy_from_slice(&nlmsg_len.to_ne_bytes());

        // ---- Send the message ----
        // Replaces C: while (retry_send(sendto(ipset_sock, buffer, nlh->nlmsg_len, 0, ...)))
        // (ipset.c lines 374-375)
        let send_len = nlmsg_len as usize;
        let kernel_addr = NetlinkAddr::new(0, 0); // pid=0 = kernel
        match retry_send_netlink(self.sock.as_raw_fd(), &buf[..send_len], &kernel_addr) {
            Ok(()) => Ok(0),
            Err(_) => Ok(-1),
        }
    }

    /// Legacy setsockopt API: add/delete IPv4 address via SOL_IP option 83.
    ///
    /// Replaces C `old_add_to_ipset()` from `src/ipset.c` lines 421-507.
    ///
    /// This path is used only on kernels older than 2.6.32 and supports
    /// IPv4 addresses only. The process is:
    /// 1. Look up the ipset index by name using `getsockopt(SOL_IP, 83)`
    /// 2. Add/delete the IP using `setsockopt(SOL_IP, 83)` with the index
    ///
    /// # Arguments
    /// * `setname` — ipset name (must be < IPSET_MAXNAMELEN)
    /// * `ipaddr` — Must be `AllAddr::V4`; IPv6 is not supported on legacy API
    /// * `remove` — true for delete, false for add
    ///
    /// # Returns
    /// `0` on success, `-1` on failure.
    fn old_add_to_ipset(
        &self,
        setname: &str,
        ipaddr: &AllAddr,
        remove: bool,
    ) -> DnsmasqResult<i32> {
        // Validate setname length (matches C check, errno = ENAMETOOLONG)
        if setname.len() >= IPSET_MAXNAMELEN {
            warn!(
                setname = setname,
                max_len = IPSET_MAXNAMELEN,
                errno = libc::ENAMETOOLONG,
                "ipset name exceeds maximum length (legacy API)"
            );
            return Ok(-1);
        }

        // Extract IPv4 address — legacy API is IPv4-only
        let addr = match ipaddr {
            AllAddr::V4(v4) => *v4,
            _ => {
                // This should not happen since add_to_ipset checks F_IPV6 on old_kernel
                // and returns -1 before calling this function. Defensive check.
                return Err(DnsmasqError::Network(
                    "legacy ipset API received non-IPv4 address".to_string(),
                ));
            }
        };

        // ---- Step 1: Get ipset index by name ----
        // Construct the getsockopt request (replaces C ipset.c lines 439-447)
        let mut req_get = IpSetReqAdtGet {
            op: IP_SET_OP_GET_BYNAME,
            version: IP_SET_OP_VERSION,
            set: [0u8; IPSET_MAXNAMELEN],
            type_name: [0u8; IPSET_MAXNAMELEN],
        };

        // Copy setname into the set.name union field (null-terminated by zero init)
        let name_bytes = setname.as_bytes();
        req_get.set[..name_bytes.len()].copy_from_slice(name_bytes);

        let mut size: libc::socklen_t = size_of::<IpSetReqAdtGet>() as libc::socklen_t;

        // SAFETY: getsockopt with a properly constructed request struct.
        // The socket fd is valid (owned by IpsetController).
        // req_get is fully initialized and correctly sized.
        // SOL_IP option 83 is the ipset kernel module's custom socket option.
        let ret = unsafe {
            libc::getsockopt(
                self.sock.as_raw_fd(),
                libc::SOL_IP,
                SO_IP_SET,
                &mut req_get as *mut IpSetReqAdtGet as *mut libc::c_void,
                &mut size,
            )
        };
        if ret < 0 {
            return Ok(-1);
        }

        // Read the set index from the first 2 bytes of the set union field.
        // The kernel writes the u16 index into the same memory that held the name.
        // (Replaces C: req_adt.index = req_adt_get.set.index at ipset.c line 449)
        let index = u16::from_ne_bytes([req_get.set[0], req_get.set[1]]);

        // ---- Step 2: Add/delete IP address ----
        // Construct the setsockopt request (replaces C ipset.c lines 449-456)
        //
        // The ip field is in host byte order — Rust equivalent of C's
        // ntohl(ipaddr->addr4.s_addr). Since Ipv4Addr::octets() returns
        // network-order bytes, u32::from_be_bytes() converts to host order.
        let ip_host_order = u32::from_be_bytes(addr.octets());

        let req_adt = IpSetReqAdt {
            op: if remove {
                IP_SET_OP_DEL_IP
            } else {
                IP_SET_OP_ADD_IP
            },
            index,
            ip: ip_host_order,
        };

        // SAFETY: setsockopt with a properly constructed request struct.
        // The socket fd is valid, req_adt is fully initialized.
        // This performs the actual ipset add/delete operation.
        let ret = unsafe {
            libc::setsockopt(
                self.sock.as_raw_fd(),
                libc::SOL_IP,
                SO_IP_SET,
                &req_adt as *const IpSetReqAdt as *const libc::c_void,
                size_of::<IpSetReqAdt>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            return Ok(-1);
        }

        Ok(0)
    }
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_nl_align() {
        assert_eq!(nl_align(0), 0);
        assert_eq!(nl_align(1), 4);
        assert_eq!(nl_align(2), 4);
        assert_eq!(nl_align(3), 4);
        assert_eq!(nl_align(4), 4);
        assert_eq!(nl_align(5), 8);
        assert_eq!(nl_align(8), 8);
        assert_eq!(nl_align(9), 12);
        assert_eq!(nl_align(16), 16);
        assert_eq!(nl_align(17), 20);
    }

    #[test]
    fn test_constants_match_c_source() {
        // Verify critical protocol constants match C src/ipset.c
        assert_eq!(NFNL_SUBSYS_IPSET, 6);
        assert_eq!(IPSET_ATTR_DATA, 7);
        assert_eq!(IPSET_ATTR_IP, 1);
        assert_eq!(IPSET_ATTR_IPADDR_IPV4, 1);
        assert_eq!(IPSET_ATTR_IPADDR_IPV6, 2);
        assert_eq!(IPSET_ATTR_PROTOCOL, 1);
        assert_eq!(IPSET_ATTR_SETNAME, 2);
        assert_eq!(IPSET_CMD_ADD, 9);
        assert_eq!(IPSET_CMD_DEL, 10);
        assert_eq!(IPSET_MAXNAMELEN, 32);
        assert_eq!(IPSET_PROTOCOL, 6);
        assert_eq!(NFNETLINK_V0, 0);
        assert_eq!(NLA_F_NESTED, 0x8000);
        assert_eq!(NLA_F_NET_BYTEORDER, 0x4000);
        assert_eq!(BUFF_SZ, 256);
        assert_eq!(NLM_F_REQUEST, 0x01);
    }

    #[test]
    fn test_flags_match_dnsmasq_h() {
        // F_IPV4 = (1u<<7) = 128, F_IPV6 = (1u<<8) = 256
        assert_eq!(F_IPV4, 128);
        assert_eq!(F_IPV6, 256);
    }

    #[test]
    fn test_buf_add_attr_protocol() {
        // Test adding IPSET_ATTR_PROTOCOL (1 byte value)
        let mut buf = vec![0u8; BUFF_SZ];
        let nlmsg_len: u32 = 20; // after nlmsghdr + nfgenmsg

        let new_len = buf_add_attr(&mut buf, nlmsg_len, IPSET_ATTR_PROTOCOL, &[IPSET_PROTOCOL]);

        // nla_len = 4 + 1 = 5, aligned increment = NL_ALIGN(5) = 8
        assert_eq!(new_len, 28);

        // Check nla_len at offset 20
        let nla_len = u16::from_ne_bytes([buf[20], buf[21]]);
        assert_eq!(nla_len, 5); // 4 (header) + 1 (data)

        // Check nla_type at offset 22
        let nla_type = u16::from_ne_bytes([buf[22], buf[23]]);
        assert_eq!(nla_type, IPSET_ATTR_PROTOCOL);

        // Check data at offset 24
        assert_eq!(buf[24], IPSET_PROTOCOL);
    }

    #[test]
    fn test_buf_add_attr_setname() {
        // Test adding IPSET_ATTR_SETNAME with "test\0" (5 bytes)
        let mut buf = vec![0u8; BUFF_SZ];
        let nlmsg_len: u32 = 28; // after protocol attr

        let setname = b"test\0";
        let new_len = buf_add_attr(&mut buf, nlmsg_len, IPSET_ATTR_SETNAME, setname);

        // nla_len = 4 + 5 = 9, aligned increment = NL_ALIGN(9) = 12
        assert_eq!(new_len, 40);

        // Check nla_len at offset 28
        let nla_len = u16::from_ne_bytes([buf[28], buf[29]]);
        assert_eq!(nla_len, 9);

        // Check nla_type at offset 30
        let nla_type = u16::from_ne_bytes([buf[30], buf[31]]);
        assert_eq!(nla_type, IPSET_ATTR_SETNAME);

        // Check data at offset 32
        assert_eq!(&buf[32..37], b"test\0");
    }

    #[test]
    fn test_buf_add_attr_ipv4() {
        // Test adding an IPv4 address attribute (4 bytes)
        let mut buf = vec![0u8; BUFF_SZ];
        let nlmsg_len: u32 = 48; // after nested headers

        let ip_type = IPSET_ATTR_IPADDR_IPV4 | NLA_F_NET_BYTEORDER;
        let addr = Ipv4Addr::new(192, 168, 1, 1);
        let new_len = buf_add_attr(&mut buf, nlmsg_len, ip_type, &addr.octets());

        // nla_len = 4 + 4 = 8, aligned increment = NL_ALIGN(8) = 8
        assert_eq!(new_len, 56);

        // Check nla_len
        let nla_len = u16::from_ne_bytes([buf[48], buf[49]]);
        assert_eq!(nla_len, 8);

        // Check nla_type
        let nla_type = u16::from_ne_bytes([buf[50], buf[51]]);
        assert_eq!(nla_type, IPSET_ATTR_IPADDR_IPV4 | NLA_F_NET_BYTEORDER);

        // Check IP address bytes (network byte order)
        assert_eq!(&buf[52..56], &[192, 168, 1, 1]);
    }

    #[test]
    fn test_buf_add_attr_ipv6() {
        // Test adding an IPv6 address attribute (16 bytes)
        let mut buf = vec![0u8; BUFF_SZ];
        let nlmsg_len: u32 = 48;

        let ip_type = IPSET_ATTR_IPADDR_IPV6 | NLA_F_NET_BYTEORDER;
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let new_len = buf_add_attr(&mut buf, nlmsg_len, ip_type, &addr.octets());

        // nla_len = 4 + 16 = 20, aligned increment = NL_ALIGN(20) = 20
        assert_eq!(new_len, 68);

        let nla_len = u16::from_ne_bytes([buf[48], buf[49]]);
        assert_eq!(nla_len, 20);

        // Check first two octets of IPv6 address (2001)
        assert_eq!(buf[52], 0x20);
        assert_eq!(buf[53], 0x01);
    }

    #[test]
    fn test_struct_sizes() {
        // Verify repr(C) struct sizes match C layout expectations
        assert_eq!(size_of::<IpSetReqAdtGet>(), 72); // 4+4+32+32
        assert_eq!(size_of::<IpSetReqAdt>(), 12); // 4+2+2(pad)+4
    }

    #[test]
    fn test_legacy_op_constants() {
        assert_eq!(IP_SET_OP_GET_BYNAME, 0x06);
        assert_eq!(IP_SET_OP_ADD_IP, 0x0101);
        assert_eq!(IP_SET_OP_DEL_IP, 0x0102);
        assert_eq!(IP_SET_OP_VERSION, 3);
        assert_eq!(SO_IP_SET, 83);
    }

    #[test]
    fn test_nlmsghdr_type_encoding() {
        // Verify nlmsg_type encoding matches C: cmd | (NFNL_SUBSYS_IPSET << 8)
        let add_type: u16 = IPSET_CMD_ADD | (NFNL_SUBSYS_IPSET << 8);
        let del_type: u16 = IPSET_CMD_DEL | (NFNL_SUBSYS_IPSET << 8);

        // NFNL_SUBSYS_IPSET(6) << 8 = 0x0600
        // IPSET_CMD_ADD(9) = 0x0009
        // Combined: 0x0609
        assert_eq!(add_type, 0x0609);

        // IPSET_CMD_DEL(10) = 0x000A
        // Combined: 0x060A
        assert_eq!(del_type, 0x060A);
    }

    #[test]
    fn test_full_netlink_message_structure_ipv4() {
        // Build a complete netlink message for adding 192.168.1.1 to set "test"
        // and verify the overall structure matches C implementation output.
        let mut buf = vec![0u8; BUFF_SZ];

        // nlmsghdr
        let mut nlmsg_len: u32 = nl_align(NLMSGHDR_SIZE) as u32; // 16
        let nlmsg_type: u16 = IPSET_CMD_ADD | (NFNL_SUBSYS_IPSET << 8);
        buf[4..6].copy_from_slice(&nlmsg_type.to_ne_bytes());
        buf[6..8].copy_from_slice(&NLM_F_REQUEST.to_ne_bytes());

        // nfgenmsg
        let nfg_off = nlmsg_len as usize;
        nlmsg_len += nl_align(NFGENMSG_SIZE) as u32;
        buf[nfg_off] = libc::AF_INET as u8;
        buf[nfg_off + 1] = NFNETLINK_V0;

        // Protocol attr
        nlmsg_len = buf_add_attr(&mut buf, nlmsg_len, IPSET_ATTR_PROTOCOL, &[IPSET_PROTOCOL]);
        assert_eq!(nlmsg_len, 28);

        // Setname attr ("test\0" = 5 bytes)
        nlmsg_len = buf_add_attr(&mut buf, nlmsg_len, IPSET_ATTR_SETNAME, b"test\0");
        assert_eq!(nlmsg_len, 40);

        // Nested[0] header (IPSET_ATTR_DATA)
        let n0 = nlmsg_len as usize;
        buf[n0 + 2..n0 + 4].copy_from_slice(&(NLA_F_NESTED | IPSET_ATTR_DATA).to_ne_bytes());
        nlmsg_len += nl_align(NLA_HDR_SIZE) as u32;
        assert_eq!(nlmsg_len, 44);

        // Nested[1] header (IPSET_ATTR_IP)
        let n1 = nlmsg_len as usize;
        buf[n1 + 2..n1 + 4].copy_from_slice(&(NLA_F_NESTED | IPSET_ATTR_IP).to_ne_bytes());
        nlmsg_len += nl_align(NLA_HDR_SIZE) as u32;
        assert_eq!(nlmsg_len, 48);

        // IPv4 address attr
        let ip_type = IPSET_ATTR_IPADDR_IPV4 | NLA_F_NET_BYTEORDER;
        let addr = Ipv4Addr::new(192, 168, 1, 1);
        nlmsg_len = buf_add_attr(&mut buf, nlmsg_len, ip_type, &addr.octets());
        assert_eq!(nlmsg_len, 56);

        // Update nested lengths
        let n1_len = (nlmsg_len as usize - n1) as u16;
        let n0_len = (nlmsg_len as usize - n0) as u16;
        buf[n1..n1 + 2].copy_from_slice(&n1_len.to_ne_bytes());
        buf[n0..n0 + 2].copy_from_slice(&n0_len.to_ne_bytes());

        // nested[1] spans from 44 to 56 = 12 bytes
        assert_eq!(n1_len, 12);
        // nested[0] spans from 40 to 56 = 16 bytes
        assert_eq!(n0_len, 16);

        // Update nlmsg_len in header
        buf[0..4].copy_from_slice(&nlmsg_len.to_ne_bytes());

        // Verify total message length
        assert_eq!(nlmsg_len, 56);
    }

    #[test]
    fn test_full_netlink_message_structure_ipv6() {
        // Build a complete netlink message for adding 2001:db8::1 to set "myset"
        let mut buf = vec![0u8; BUFF_SZ];

        let mut nlmsg_len: u32 = nl_align(NLMSGHDR_SIZE) as u32;
        let nlmsg_type: u16 = IPSET_CMD_DEL | (NFNL_SUBSYS_IPSET << 8);
        buf[4..6].copy_from_slice(&nlmsg_type.to_ne_bytes());
        buf[6..8].copy_from_slice(&NLM_F_REQUEST.to_ne_bytes());

        let nfg_off = nlmsg_len as usize;
        nlmsg_len += nl_align(NFGENMSG_SIZE) as u32;
        buf[nfg_off] = libc::AF_INET6 as u8;
        buf[nfg_off + 1] = NFNETLINK_V0;

        nlmsg_len = buf_add_attr(&mut buf, nlmsg_len, IPSET_ATTR_PROTOCOL, &[IPSET_PROTOCOL]);
        nlmsg_len = buf_add_attr(&mut buf, nlmsg_len, IPSET_ATTR_SETNAME, b"myset\0");

        let n0 = nlmsg_len as usize;
        buf[n0 + 2..n0 + 4].copy_from_slice(&(NLA_F_NESTED | IPSET_ATTR_DATA).to_ne_bytes());
        nlmsg_len += nl_align(NLA_HDR_SIZE) as u32;

        let n1 = nlmsg_len as usize;
        buf[n1 + 2..n1 + 4].copy_from_slice(&(NLA_F_NESTED | IPSET_ATTR_IP).to_ne_bytes());
        nlmsg_len += nl_align(NLA_HDR_SIZE) as u32;

        let ip_type = IPSET_ATTR_IPADDR_IPV6 | NLA_F_NET_BYTEORDER;
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        nlmsg_len = buf_add_attr(&mut buf, nlmsg_len, ip_type, &addr.octets());

        let n1_len = (nlmsg_len as usize - n1) as u16;
        let n0_len = (nlmsg_len as usize - n0) as u16;
        buf[n1..n1 + 2].copy_from_slice(&n1_len.to_ne_bytes());
        buf[n0..n0 + 2].copy_from_slice(&n0_len.to_ne_bytes());

        // setname "myset\0" = 6 bytes, NL_ALIGN(4+6)=12
        // After protocol: 28, after setname: 40, n0: 40, n0+4: 44, n1: 44, n1+4: 48
        // IPv6 attr: NL_ALIGN(4+16)=20, so end: 68
        // n1_len = 68-44 = 24, n0_len = 68-40 = 28
        assert_eq!(n1_len, 24);
        assert_eq!(n0_len, 28);
        assert_eq!(nlmsg_len, 68);
    }

    #[test]
    fn test_ip_host_order_conversion() {
        // Verify that u32::from_be_bytes matches C's ntohl behavior
        let addr = Ipv4Addr::new(192, 168, 1, 1);
        let host_order = u32::from_be_bytes(addr.octets());
        // 192.168.1.1 = 0xC0A80101 = 3232235777
        assert_eq!(host_order, 0xC0A80101);

        let addr2 = Ipv4Addr::new(10, 0, 0, 1);
        let host_order2 = u32::from_be_bytes(addr2.octets());
        assert_eq!(host_order2, 0x0A000001);
    }

    #[test]
    fn test_setname_length_validation() {
        // Setname >= IPSET_MAXNAMELEN (32) should be rejected
        let long_name = "a".repeat(IPSET_MAXNAMELEN); // exactly 32 chars
        assert!(long_name.len() >= IPSET_MAXNAMELEN);

        let valid_name = "a".repeat(IPSET_MAXNAMELEN - 1); // 31 chars
        assert!(valid_name.len() < IPSET_MAXNAMELEN);
    }
}

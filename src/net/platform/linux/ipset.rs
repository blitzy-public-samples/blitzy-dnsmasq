//! Linux ipset integration via netlink for dynamic firewall rule population.
//!
//! Complete Rust rewrite of `src/ipset.c` (532 lines of C). This module provides
//! integration with the Linux kernel's ipset infrastructure, enabling dnsmasq to
//! automatically populate named ipset collections with IP addresses resolved from
//! DNS queries. This functionality enables dynamic firewall rules, content filtering,
//! and policy-based routing based on domain-name-to-IP-address mappings.
//!
//! # Kernel API Support
//!
//! Two kernel APIs are supported, selected at runtime based on kernel version:
//!
//! - **Modern API** (kernel ≥ 2.6.32): Uses `NETLINK_NETFILTER` socket with ipset
//!   protocol v6 netlink messages. Supports both IPv4 and IPv6 addresses.
//! - **Legacy API** (kernel < 2.6.32): Uses raw `IPPROTO_RAW` socket with
//!   `setsockopt`/`getsockopt` on `SOL_IP` option 83. IPv4 only.
//!
//! # Wire Protocol
//!
//! Modern netlink messages are constructed manually in a 256-byte buffer matching
//! the exact wire format from the C implementation:
//!
//! ```text
//! [nlmsghdr (16 bytes)]
//! [nfgenmsg (4 bytes)]
//! [nlattr: PROTOCOL = 6]
//! [nlattr: SETNAME = "name\0"]
//! [nlattr: DATA (nested)]
//!   [nlattr: IP (nested)]
//!     [nlattr: IPADDR_IPV4/IPV6 = address bytes]
//! ```
//!
//! # Threading Model
//!
//! Single-threaded event-driven architecture. Ipset operations are synchronous
//! fire-and-forget netlink writes that do not block the event loop.
//!
//! # Feature Gate
//!
//! This module is compiled only when `feature = "ipset"` is enabled, replacing
//! the C `#ifdef HAVE_LINUX_IPSET` preprocessor guard.
//!
//! # Source
//!
//! Port of `src/ipset.c` lines 96–532.

use std::io::{self, ErrorKind};
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};

use nix::sys::socket::{
    self, AddressFamily, MsgFlags, NetlinkAddr, SockFlag, SockProtocol, SockType,
};

use crate::core::util::retry_send;

// ---------------------------------------------------------------------------
// Ipset protocol constants (matching C ipset.c lines 108–131)
// ---------------------------------------------------------------------------

/// Netfilter netlink subsystem ID for ipset.
/// C: `#define NFNL_SUBSYS_IPSET 6` (line 108).
const NFNL_SUBSYS_IPSET: u16 = 6;

/// Attribute type for the nested data payload in ipset commands.
/// C: `#define IPSET_ATTR_DATA 7` (line 110).
const IPSET_ATTR_DATA: u16 = 7;

/// Attribute type for the nested IP address container.
/// C: `#define IPSET_ATTR_IP 1` (line 111).
const IPSET_ATTR_IP: u16 = 1;

/// Attribute type for an IPv4 address within the IP container.
/// C: `#define IPSET_ATTR_IPADDR_IPV4 1` (line 112).
const IPSET_ATTR_IPADDR_IPV4: u16 = 1;

/// Attribute type for an IPv6 address within the IP container.
/// C: `#define IPSET_ATTR_IPADDR_IPV6 2` (line 113).
const IPSET_ATTR_IPADDR_IPV6: u16 = 2;

/// Attribute type for the ipset protocol version.
/// C: `#define IPSET_ATTR_PROTOCOL 1` (line 114).
const IPSET_ATTR_PROTOCOL: u16 = 1;

/// Attribute type for the ipset collection name (null-terminated string).
/// C: `#define IPSET_ATTR_SETNAME 2` (line 115).
const IPSET_ATTR_SETNAME: u16 = 2;

/// Ipset command: add an entry to a set.
/// C: `#define IPSET_CMD_ADD 9` (line 116).
const IPSET_CMD_ADD: u16 = 9;

/// Ipset command: delete an entry from a set.
/// C: `#define IPSET_CMD_DEL 10` (line 117).
const IPSET_CMD_DEL: u16 = 10;

/// Maximum length of an ipset name including null terminator.
/// C: `#define IPSET_MAXNAMELEN 32` (line 118).
const IPSET_MAXNAMELEN: usize = 32;

/// Ipset protocol version supported by this implementation.
/// C: `#define IPSET_PROTOCOL 6` (line 119).
const IPSET_PROTOCOL: u8 = 6;

/// Netfilter netlink protocol version.
/// C: `#define NFNETLINK_V0 0` (line 122).
const NFNETLINK_V0: u8 = 0;

/// Netlink attribute flag: this attribute contains nested attributes.
/// C: `#define NLA_F_NESTED (1 << 15)` (line 126).
const NLA_F_NESTED: u16 = 1 << 15;

/// Netlink attribute flag: payload is in network byte order.
/// C: `#define NLA_F_NET_BYTEORDER (1 << 14)` (line 130).
const NLA_F_NET_BYTEORDER: u16 = 1 << 14;

/// Size of the netlink message construction buffer in bytes.
/// C: `#define BUFF_SZ 256` (line 191).
const BUFF_SZ: usize = 256;

// ---------------------------------------------------------------------------
// Wire-format layout constants
// ---------------------------------------------------------------------------

/// Size of struct nlmsghdr: nlmsg_len(4) + nlmsg_type(2) + nlmsg_flags(2)
/// + nlmsg_seq(4) + nlmsg_pid(4) = 16 bytes.
const NLMSGHDR_SIZE: usize = 16;

/// Size of the netlink attribute header: nla_len(2) + nla_type(2) = 4 bytes.
/// Matches C `sizeof(struct my_nlattr)`.
const NL_ATTR_HDR_SIZE: usize = 4;

/// Size of the netfilter generic message header: nfgen_family(1) + version(1)
/// + res_id(2) = 4 bytes. Matches C `sizeof(struct my_nfgenmsg)`.
const NFGENMSG_SIZE: usize = 4;

// ---------------------------------------------------------------------------
// Kernel version encoding
// ---------------------------------------------------------------------------

/// Encode a Linux kernel version triple into a comparable u32.
///
/// Uses the same encoding as the Linux `KERNEL_VERSION(a,b,c)` macro from
/// `<linux/version.h>`: `(major << 16) | (minor << 8) | patch`.
///
/// Also matches the encoding produced by the dnsmasq `kernel_version()`
/// function in `src/util.c` lines 2714–2731.
const fn kernel_version_encode(major: u32, minor: u32, patch: u32) -> u32 {
    (major << 16) | (minor << 8) | (patch & 0xFF)
}

/// Kernel version threshold for modern netlink API: 2.6.32.
/// C: `KERNEL_VERSION(2,6,32)` at ipset.c line 278.
const KERNEL_VERSION_2_6_32: u32 = kernel_version_encode(2, 6, 32);

// ---------------------------------------------------------------------------
// Legacy API constants (kernel < 2.6.32)
// ---------------------------------------------------------------------------

/// Legacy ipset operation: get set index by name.
/// C: `req_adt_get.op = 0x10` (line 445).
const IP_SET_OP_GET_BYNAME: u32 = 0x10;

/// Legacy ipset operation: add IP to set.
/// C: `req_adt.op = remove ? 0x102 : 0x101` (line 451).
const IP_SET_OP_ADD_IP: u32 = 0x101;

/// Legacy ipset operation: delete IP from set.
const IP_SET_OP_DEL_IP: u32 = 0x102;

/// Legacy ipset protocol version.
/// C: `req_adt_get.version = 3` (line 446).
const IP_SET_PROTOCOL_VERSION: u32 = 3;

/// Socket option number for legacy ipset operations.
/// C: `getsockopt(..., SOL_IP, 83, ...)` (line 449).
const SO_IP_SET: libc::c_int = 83;

/// Size of legacy `ip_set_req_adt_get` struct:
/// op(4) + version(4) + union{name[32]/index(2)}(32) + typename[32](32) = 72.
const IP_SET_REQ_ADT_GET_SIZE: usize = 72;

/// Size of legacy `ip_set_req_adt` struct:
/// op(4) + index(2) + padding(2) + ip(4) = 12.
const IP_SET_REQ_ADT_SIZE: usize = 12;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from ipset operations.
///
/// Each variant maps to a distinct failure mode in the ipset integration layer.
/// Uses `thiserror` for automatic `Display` and `Error` trait implementations.
///
/// # Source
/// Replaces C errno-based error handling from `src/ipset.c`.
#[derive(Debug, thiserror::Error)]
pub enum IpsetError {
    /// Failed to create the ipset control socket (netlink or raw).
    /// Wraps the underlying OS error from `socket()` or `bind()`.
    #[error("Failed to create ipset control socket: {0}")]
    SocketCreationFailed(io::Error),

    /// The ipset collection name exceeds [`IPSET_MAXNAMELEN`] (32 characters).
    /// C: `errno = ENAMETOOLONG` at lines 341, 440.
    #[error("Set name too long: {name} (max {IPSET_MAXNAMELEN} chars)")]
    SetNameTooLong {
        /// The offending set name.
        name: String,
    },

    /// IPv6 addresses are not supported by the legacy kernel API (< 2.6.32).
    /// C: `errno = EAFNOSUPPORT` at line 518.
    #[error("IPv6 not supported on legacy kernel API")]
    Ipv6NotSupported,

    /// A netlink send or legacy setsockopt operation failed.
    /// C: `my_syslog(LOG_ERR, ...)` at line 527.
    #[error("Failed to update ipset {setname}: {source}")]
    UpdateFailed {
        /// Name of the ipset being updated.
        setname: String,
        /// Underlying OS error.
        source: io::Error,
    },

    /// The netlink message exceeded the fixed 256-byte buffer.
    /// Should not occur with valid set names under 32 characters.
    #[error("Netlink message construction overflow")]
    BufferOverflow,

    /// The legacy `getsockopt` call to look up a set by name failed.
    /// C: `getsockopt(ipset_sock, SOL_IP, 83, ...)` returning -1 at line 449.
    #[error("Legacy API set lookup failed: {0}")]
    LegacyLookupFailed(io::Error),
}

// ---------------------------------------------------------------------------
// IpsetManager — main public struct
// ---------------------------------------------------------------------------

/// Manager for Linux kernel ipset operations.
///
/// Encapsulates the control socket and kernel version state that were
/// previously held as C static globals (`ipset_sock`, `old_kernel`, `buffer`).
/// The socket is owned via [`OwnedFd`] for automatic RAII cleanup on drop.
///
/// # Initialization
///
/// Create with [`IpsetManager::new()`], passing the kernel version obtained
/// from `uname()`. The constructor creates the appropriate socket type and
/// binds it to the kernel ipset subsystem.
///
/// # Usage
///
/// ```rust,no_run
/// # use dnsmasq::net::platform::linux::ipset::IpsetManager;
/// # use std::net::IpAddr;
/// let mgr = IpsetManager::new(0x050F00).unwrap(); // kernel 5.15.0
/// let addr: IpAddr = "192.168.1.100".parse().unwrap();
/// mgr.add_to_ipset("blocked_hosts", &addr, false).unwrap();
/// ```
///
/// # Source
///
/// Port of C static state at `src/ipset.c` lines 191–196 and `ipset_init()`
/// at lines 276–290.
pub struct IpsetManager {
    /// Control socket file descriptor with RAII ownership.
    /// - Modern API: `AF_NETLINK` / `SOCK_RAW` / `NETLINK_NETFILTER`
    /// - Legacy API: `AF_INET` / `SOCK_RAW` / `IPPROTO_RAW`
    socket: OwnedFd,

    /// `true` if the running kernel predates version 2.6.32, requiring the
    /// legacy setsockopt-based ipset API (IPv4 only).
    old_kernel: bool,
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Align a byte length to a 4-byte boundary per netlink protocol requirements.
///
/// Replaces the C macro `#define NL_ALIGN(len) (((len)+3) & ~(3))` from
/// `src/ipset.c` line 193.
#[inline]
const fn nl_align(len: usize) -> usize {
    (len + 3) & !3
}

/// Append a netlink attribute (TLV) to a message buffer.
///
/// Constructs a netlink attribute header (`nla_len` + `nla_type`) followed by
/// the payload data, respecting 4-byte alignment. Updates `msg_len` to reflect
/// the new total message length.
///
/// Pure safe Rust — no `unsafe` code needed.
///
/// # Source
///
/// Port of C `add_attr()` at `src/ipset.c` lines 233–241.
fn add_attr(
    buffer: &mut [u8],
    msg_len: &mut usize,
    attr_type: u16,
    data: &[u8],
) -> Result<(), IpsetError> {
    let attr_start = nl_align(*msg_len);
    let nla_len = (NL_ATTR_HDR_SIZE + data.len()) as u16;
    let total_aligned = nl_align(NL_ATTR_HDR_SIZE + data.len());

    let new_end = attr_start + total_aligned;
    if new_end > buffer.len() {
        return Err(IpsetError::BufferOverflow);
    }

    // Write NlAttr header in native byte order:
    //   [0..2] nla_len  — total attribute length (header + payload), unpadded
    //   [2..4] nla_type — attribute type with optional flags
    buffer[attr_start..attr_start + 2].copy_from_slice(&nla_len.to_ne_bytes());
    buffer[attr_start + 2..attr_start + 4].copy_from_slice(&attr_type.to_ne_bytes());

    // Write payload data immediately after the header.
    let data_start = attr_start + NL_ATTR_HDR_SIZE;
    buffer[data_start..data_start + data.len()].copy_from_slice(data);

    // Advance message length by the aligned attribute size.
    *msg_len = new_end;

    Ok(())
}

// ---------------------------------------------------------------------------
// IpsetManager implementation
// ---------------------------------------------------------------------------

impl IpsetManager {
    /// Create a new ipset manager, initializing the control socket.
    ///
    /// Detects the kernel API version and creates the appropriate socket:
    /// - Kernel ≥ 2.6.32: `AF_NETLINK` / `SOCK_RAW` / `NETLINK_NETFILTER`,
    ///   bound to the kernel netfilter subsystem.
    /// - Kernel < 2.6.32: `AF_INET` / `SOCK_RAW` / `IPPROTO_RAW` for the
    ///   legacy setsockopt-based interface.
    ///
    /// # Arguments
    ///
    /// * `kernel_version` — Encoded kernel version from `uname()`, using the
    ///   standard `KERNEL_VERSION(major, minor, patch)` encoding:
    ///   `(major << 16) | (minor << 8) | patch`.
    ///
    /// # Errors
    ///
    /// Returns [`IpsetError::SocketCreationFailed`] if socket creation or
    /// binding fails.
    ///
    /// # Source
    ///
    /// Port of C `ipset_init()` at `src/ipset.c` lines 276–290.
    pub fn new(kernel_version: u32) -> Result<Self, IpsetError> {
        let old_kernel = kernel_version < KERNEL_VERSION_2_6_32;

        let socket_fd = if old_kernel {
            // Legacy API: raw IPv4 socket for setsockopt/getsockopt operations.
            // C: socket(AF_INET, SOCK_RAW, IPPROTO_RAW) at line 280.
            // SAFETY: socket() is a standard POSIX syscall; return value checked below.
            let raw_fd = unsafe {
                libc::socket(
                    libc::AF_INET,
                    libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                    libc::IPPROTO_RAW,
                )
            };
            if raw_fd < 0 {
                return Err(IpsetError::SocketCreationFailed(io::Error::last_os_error()));
            }
            // SAFETY: raw_fd is a valid fd (non-negative, checked above).
            // OwnedFd takes exclusive ownership and closes it on drop.
            unsafe { OwnedFd::from_raw_fd(raw_fd) }
        } else {
            // Modern API: netlink socket for NETLINK_NETFILTER ipset protocol.
            // C: socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER) at line 285,
            //    then bind(ipset_sock, &snl, sizeof(snl)) at line 286.
            let fd = socket::socket(
                AddressFamily::Netlink,
                SockType::Raw,
                SockFlag::SOCK_CLOEXEC,
                SockProtocol::NetlinkNetFilter,
            )
            .map_err(|e| IpsetError::SocketCreationFailed(e.into()))?;

            // Bind to kernel (pid=0, groups=0 — we only send, never receive).
            let snl = NetlinkAddr::new(0, 0);
            socket::bind(fd.as_raw_fd(), &snl)
                .map_err(|e| IpsetError::SocketCreationFailed(e.into()))?;

            fd
        };

        Ok(IpsetManager {
            socket: socket_fd,
            old_kernel,
        })
    }

    /// Add or remove an IP address to/from an ipset collection.
    ///
    /// Primary public interface called by the DNS forwarding engine when a
    /// domain matches an ipset configuration directive. Automatically selects
    /// the appropriate kernel API based on the kernel version.
    ///
    /// # Arguments
    ///
    /// * `setname` — Name of the ipset collection (max 31 characters).
    /// * `ipaddr` — IPv4 or IPv6 address to add/remove.
    /// * `remove` — `true` to remove the address; `false` to add.
    ///
    /// # Errors
    ///
    /// Returns an error on failure. Errors are logged via `log::error!`
    /// matching the C `my_syslog(LOG_ERR, ...)` behavior at line 527.
    ///
    /// # Source
    ///
    /// Port of C `add_to_ipset()` at `src/ipset.c` lines 508–530.
    pub fn add_to_ipset(
        &self,
        setname: &str,
        ipaddr: &IpAddr,
        remove: bool,
    ) -> Result<(), IpsetError> {
        let result = if ipaddr.is_ipv6() && self.old_kernel {
            // Legacy API does not support IPv6.
            // C: errno = EAFNOSUPPORT; ret = -1; (lines 516–520)
            Err(IpsetError::Ipv6NotSupported)
        } else if self.old_kernel {
            // Legacy setsockopt path (IPv4 only).
            let v4_addr = match ipaddr {
                IpAddr::V4(v4) => *v4,
                IpAddr::V6(_) => unreachable!("IPv6 on old kernel handled above"),
            };
            self.old_add_to_ipset(setname, &v4_addr, remove)
        } else {
            // Modern netlink path (IPv4 and IPv6).
            self.new_add_to_ipset(setname, ipaddr, remove)
        };

        // Log errors matching C my_syslog(LOG_ERR, ...) at line 527.
        if let Err(ref e) = result {
            log::error!("failed to update ipset {}: {}", setname, e);
        }

        result
    }

    // -----------------------------------------------------------------------
    // Modern netlink API (kernel ≥ 2.6.32)
    // -----------------------------------------------------------------------

    /// Add or remove an IP address using the modern netlink ipset API.
    ///
    /// Constructs a complete netlink message in a local 256-byte buffer with
    /// nested attributes for protocol version, set name, and IP address, then
    /// sends it to the kernel via the NETLINK_NETFILTER socket.
    ///
    /// The message is fire-and-forget: no response is read from the kernel.
    /// The [`retry_send()`](crate::core::util::retry_send) helper handles
    /// EINTR retries.
    ///
    /// # Source
    ///
    /// Port of C `new_add_to_ipset()` at `src/ipset.c` lines 332–378.
    fn new_add_to_ipset(
        &self,
        setname: &str,
        ipaddr: &IpAddr,
        remove: bool,
    ) -> Result<(), IpsetError> {
        // Validate set name length (C line 340).
        if setname.len() >= IPSET_MAXNAMELEN {
            return Err(IpsetError::SetNameTooLong {
                name: setname.to_string(),
            });
        }

        // Determine address family, raw address bytes, and attribute type.
        let v4_octets;
        let v6_octets;
        let (af, addr_slice, ip_attr_type): (u8, &[u8], u16) = match ipaddr {
            IpAddr::V4(v4) => {
                v4_octets = v4.octets();
                (libc::AF_INET as u8, &v4_octets as &[u8], IPSET_ATTR_IPADDR_IPV4)
            }
            IpAddr::V6(v6) => {
                v6_octets = v6.octets();
                (libc::AF_INET6 as u8, &v6_octets as &[u8], IPSET_ATTR_IPADDR_IPV6)
            }
        };

        // Zero the local message buffer (C: memset(buffer, 0, BUFF_SZ) line 346).
        let mut buffer = [0u8; BUFF_SZ];
        let mut msg_len: usize;

        // === nlmsghdr (16 bytes) ===
        // C lines 348–351.
        let cmd = if remove { IPSET_CMD_DEL } else { IPSET_CMD_ADD };
        let nlmsg_type: u16 = cmd | (NFNL_SUBSYS_IPSET << 8);
        let nlmsg_flags: u16 = libc::NLM_F_REQUEST as u16;

        // nlmsg_len placeholder at [0..4] — set at the end.
        buffer[4..6].copy_from_slice(&nlmsg_type.to_ne_bytes());
        buffer[6..8].copy_from_slice(&nlmsg_flags.to_ne_bytes());
        // nlmsg_seq = 0 at [8..12], nlmsg_pid = 0 at [12..16] — already zero.
        msg_len = nl_align(NLMSGHDR_SIZE); // 16

        // === nfgenmsg (4 bytes) ===
        // C lines 353–357.
        buffer[msg_len] = af; // nfgen_family
        buffer[msg_len + 1] = NFNETLINK_V0; // version
        buffer[msg_len + 2..msg_len + 4].copy_from_slice(&0u16.to_be_bytes()); // res_id
        msg_len += nl_align(NFGENMSG_SIZE); // += 4 → 20

        // === IPSET_ATTR_PROTOCOL attribute ===
        // C lines 359–360.
        add_attr(&mut buffer, &mut msg_len, IPSET_ATTR_PROTOCOL, &[IPSET_PROTOCOL])?;

        // === IPSET_ATTR_SETNAME attribute (null-terminated) ===
        // C line 361.
        let mut name_bytes = Vec::with_capacity(setname.len() + 1);
        name_bytes.extend_from_slice(setname.as_bytes());
        name_bytes.push(0); // null terminator
        add_attr(&mut buffer, &mut msg_len, IPSET_ATTR_SETNAME, &name_bytes)?;

        // === Nested DATA attribute header (reserve space) ===
        // C lines 362–364.
        let nested0_offset = nl_align(msg_len);
        if nested0_offset + NL_ATTR_HDR_SIZE > BUFF_SZ {
            return Err(IpsetError::BufferOverflow);
        }
        buffer[nested0_offset + 2..nested0_offset + 4]
            .copy_from_slice(&(NLA_F_NESTED | IPSET_ATTR_DATA).to_ne_bytes());
        msg_len = nested0_offset + nl_align(NL_ATTR_HDR_SIZE);

        // === Nested IP attribute header (reserve space) ===
        // C lines 365–367.
        let nested1_offset = nl_align(msg_len);
        if nested1_offset + NL_ATTR_HDR_SIZE > BUFF_SZ {
            return Err(IpsetError::BufferOverflow);
        }
        buffer[nested1_offset + 2..nested1_offset + 4]
            .copy_from_slice(&(NLA_F_NESTED | IPSET_ATTR_IP).to_ne_bytes());
        msg_len = nested1_offset + nl_align(NL_ATTR_HDR_SIZE);

        // === IP address attribute ===
        // C lines 368–370.
        add_attr(
            &mut buffer,
            &mut msg_len,
            ip_attr_type | NLA_F_NET_BYTEORDER,
            addr_slice,
        )?;

        // === Fix up nested attribute lengths ===
        // C lines 371–372.
        let end_offset = nl_align(msg_len);
        let nested1_len = (end_offset - nested1_offset) as u16;
        buffer[nested1_offset..nested1_offset + 2]
            .copy_from_slice(&nested1_len.to_ne_bytes());
        let nested0_len = (end_offset - nested0_offset) as u16;
        buffer[nested0_offset..nested0_offset + 2]
            .copy_from_slice(&nested0_len.to_ne_bytes());

        // === Set final nlmsg_len in the header ===
        buffer[0..4].copy_from_slice(&(msg_len as u32).to_ne_bytes());

        // === Send the netlink message ===
        // C lines 374–375: fire-and-forget sendto with retry_send on EINTR.
        let snl = NetlinkAddr::new(0, 0);
        let fd = self.socket.as_raw_fd();
        loop {
            let result = socket::sendto(fd, &buffer[..msg_len], &snl, MsgFlags::empty())
                .map_err(io::Error::from);
            match retry_send(result) {
                Ok(_) => return Ok(()),
                Err(ref e)
                    if e.kind() == ErrorKind::Interrupted
                        || e.kind() == ErrorKind::WouldBlock =>
                {
                    continue;
                }
                Err(e) => {
                    return Err(IpsetError::UpdateFailed {
                        setname: setname.to_string(),
                        source: e,
                    });
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Legacy setsockopt API (kernel < 2.6.32)
    // -----------------------------------------------------------------------

    /// Add or remove an IPv4 address using the legacy kernel ipset API.
    ///
    /// Uses `getsockopt(SOL_IP, 83)` to look up the set index by name, then
    /// `setsockopt(SOL_IP, 83)` to perform the add/delete operation. This
    /// API predates the netlink-based interface and is limited to IPv4.
    ///
    /// # Source
    ///
    /// Port of C `old_add_to_ipset()` at `src/ipset.c` lines 421–458.
    fn old_add_to_ipset(
        &self,
        setname: &str,
        ipaddr: &Ipv4Addr,
        remove: bool,
    ) -> Result<(), IpsetError> {
        // Validate set name length (C line 439).
        if setname.len() >= IPSET_MAXNAMELEN {
            return Err(IpsetError::SetNameTooLong {
                name: setname.to_string(),
            });
        }

        let fd = self.socket.as_raw_fd();

        // ---------------------------------------------------------------
        // Step 1: Look up set index by name via getsockopt.
        //
        // C lines 445–450: struct ip_set_req_adt_get layout (72 bytes):
        //   [0..4]   op       = 0x10 (IP_SET_OP_GET_BYNAME)
        //   [4..8]   version  = 3
        //   [8..40]  set.name = setname (null-padded, 32 bytes)
        //   [40..72] typename = zeroed (32 bytes)
        //
        // After getsockopt, [8..10] contains the uint16_t set index.
        // ---------------------------------------------------------------
        let mut req_get = [0u8; IP_SET_REQ_ADT_GET_SIZE];
        req_get[0..4].copy_from_slice(&IP_SET_OP_GET_BYNAME.to_ne_bytes());
        req_get[4..8].copy_from_slice(&IP_SET_PROTOCOL_VERSION.to_ne_bytes());
        // Copy setname into [8..8+len], rest remains zeroed (null-padded).
        req_get[8..8 + setname.len()].copy_from_slice(setname.as_bytes());

        let mut size = IP_SET_REQ_ADT_GET_SIZE as libc::socklen_t;
        // SAFETY: fd is a valid socket owned by IpsetManager. req_get matches
        // the kernel ip_set_req_adt_get layout. size is initialized correctly.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_IP,
                SO_IP_SET,
                req_get.as_mut_ptr() as *mut libc::c_void,
                &mut size,
            )
        };
        if rc < 0 {
            return Err(IpsetError::LegacyLookupFailed(io::Error::last_os_error()));
        }

        // Extract set index from offset 8 (uint16_t, native order).
        // C line 452: req_adt.index = req_adt_get.set.index
        let set_index = u16::from_ne_bytes([req_get[8], req_get[9]]);

        // ---------------------------------------------------------------
        // Step 2: Add or delete via setsockopt.
        //
        // C lines 451–455: struct ip_set_req_adt layout (12 bytes):
        //   [0..4]   op    = 0x101 (add) or 0x102 (delete)
        //   [4..6]   index = set_index
        //   [6..8]   (padding — zero)
        //   [8..12]  ip    = ntohl(ipaddr->addr4.s_addr)
        // ---------------------------------------------------------------
        let mut req_adt = [0u8; IP_SET_REQ_ADT_SIZE];
        let op: u32 = if remove {
            IP_SET_OP_DEL_IP
        } else {
            IP_SET_OP_ADD_IP
        };
        req_adt[0..4].copy_from_slice(&op.to_ne_bytes());
        req_adt[4..6].copy_from_slice(&set_index.to_ne_bytes());
        // [6..8] padding — already zero.
        // IP in host byte order: u32::from(Ipv4Addr) gives host-order value.
        let ip_host: u32 = u32::from(*ipaddr);
        req_adt[8..12].copy_from_slice(&ip_host.to_ne_bytes());

        // SAFETY: fd is a valid socket owned by IpsetManager. req_adt matches
        // the kernel ip_set_req_adt layout for add/delete operations.
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_IP,
                SO_IP_SET,
                req_adt.as_ptr() as *const libc::c_void,
                IP_SET_REQ_ADT_SIZE as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(IpsetError::UpdateFailed {
                setname: setname.to_string(),
                source: io::Error::last_os_error(),
            });
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nl_align() {
        assert_eq!(nl_align(0), 0);
        assert_eq!(nl_align(1), 4);
        assert_eq!(nl_align(2), 4);
        assert_eq!(nl_align(3), 4);
        assert_eq!(nl_align(4), 4);
        assert_eq!(nl_align(5), 8);
        assert_eq!(nl_align(16), 16);
        assert_eq!(nl_align(17), 20);
    }

    #[test]
    fn test_kernel_version_encode() {
        assert_eq!(kernel_version_encode(2, 6, 32), (2 << 16) | (6 << 8) | 32);
        assert_eq!(kernel_version_encode(5, 15, 0), (5 << 16) | (15 << 8));
        assert_eq!(kernel_version_encode(2, 6, 31), (2 << 16) | (6 << 8) | 31);
        assert_eq!(KERNEL_VERSION_2_6_32, kernel_version_encode(2, 6, 32));
    }

    #[test]
    fn test_add_attr_basic() {
        let mut buffer = [0u8; 64];
        let mut msg_len: usize = 0;

        add_attr(&mut buffer, &mut msg_len, IPSET_ATTR_PROTOCOL, &[6]).unwrap();

        let nla_len = u16::from_ne_bytes([buffer[0], buffer[1]]);
        assert_eq!(nla_len, 5); // 4 header + 1 data

        let nla_type = u16::from_ne_bytes([buffer[2], buffer[3]]);
        assert_eq!(nla_type, IPSET_ATTR_PROTOCOL);

        assert_eq!(buffer[4], 6);
        assert_eq!(msg_len, 8); // nl_align(5) = 8
    }

    #[test]
    fn test_add_attr_setname() {
        let mut buffer = [0u8; 64];
        let mut msg_len: usize = 0;

        add_attr(&mut buffer, &mut msg_len, IPSET_ATTR_SETNAME, b"test\0").unwrap();

        let nla_len = u16::from_ne_bytes([buffer[0], buffer[1]]);
        assert_eq!(nla_len, 9); // 4 + 5
        assert_eq!(&buffer[4..9], b"test\0");
        assert_eq!(msg_len, 12); // nl_align(9)
    }

    #[test]
    fn test_add_attr_overflow() {
        let mut buffer = [0u8; 8];
        let mut msg_len: usize = 0;

        let result = add_attr(&mut buffer, &mut msg_len, 1, &[0u8; 10]);
        assert!(result.is_err());
        match result.unwrap_err() {
            IpsetError::BufferOverflow => {}
            other => panic!("Expected BufferOverflow, got: {other}"),
        }
    }

    #[test]
    fn test_add_attr_sequential() {
        let mut buffer = [0u8; 64];
        let mut msg_len: usize = 0;

        add_attr(&mut buffer, &mut msg_len, IPSET_ATTR_PROTOCOL, &[6]).unwrap();
        assert_eq!(msg_len, 8);

        add_attr(&mut buffer, &mut msg_len, IPSET_ATTR_SETNAME, b"test\0").unwrap();
        assert_eq!(msg_len, 20); // 8 + nl_align(9) = 20

        let nla_len = u16::from_ne_bytes([buffer[8], buffer[9]]);
        assert_eq!(nla_len, 9);
        let nla_type = u16::from_ne_bytes([buffer[10], buffer[11]]);
        assert_eq!(nla_type, IPSET_ATTR_SETNAME);
    }

    #[test]
    fn test_ipset_error_display() {
        let err = IpsetError::Ipv6NotSupported;
        assert_eq!(err.to_string(), "IPv6 not supported on legacy kernel API");

        let err = IpsetError::SetNameTooLong {
            name: "toolong".to_string(),
        };
        assert!(err.to_string().contains("toolong"));
        assert!(err.to_string().contains("32"));

        let err = IpsetError::BufferOverflow;
        let msg = err.to_string().to_lowercase();
        assert!(msg.contains("overflow"), "Expected 'overflow' in: {msg}");
    }

    #[test]
    fn test_constants_match_c_values() {
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
        assert_eq!(NLA_F_NESTED, 1 << 15);
        assert_eq!(NLA_F_NET_BYTEORDER, 1 << 14);
        assert_eq!(BUFF_SZ, 256);
    }

    #[test]
    fn test_wire_format_sizes() {
        assert_eq!(NLMSGHDR_SIZE, 16);
        assert_eq!(NL_ATTR_HDR_SIZE, 4);
        assert_eq!(NFGENMSG_SIZE, 4);
    }

    #[test]
    fn test_legacy_constants() {
        assert_eq!(IP_SET_OP_GET_BYNAME, 0x10);
        assert_eq!(IP_SET_OP_ADD_IP, 0x101);
        assert_eq!(IP_SET_OP_DEL_IP, 0x102);
        assert_eq!(IP_SET_PROTOCOL_VERSION, 3);
        assert_eq!(SO_IP_SET, 83);
        assert_eq!(IP_SET_REQ_ADT_GET_SIZE, 72);
        assert_eq!(IP_SET_REQ_ADT_SIZE, 12);
    }

    #[test]
    fn test_netlink_message_layout_ipv4() {
        let mut buffer = [0u8; BUFF_SZ];
        let mut msg_len: usize;

        // nlmsghdr
        let nlmsg_type: u16 = IPSET_CMD_ADD | (NFNL_SUBSYS_IPSET << 8);
        let nlmsg_flags: u16 = libc::NLM_F_REQUEST as u16;
        buffer[4..6].copy_from_slice(&nlmsg_type.to_ne_bytes());
        buffer[6..8].copy_from_slice(&nlmsg_flags.to_ne_bytes());
        msg_len = nl_align(NLMSGHDR_SIZE);
        assert_eq!(msg_len, 16);

        // nfgenmsg
        buffer[msg_len] = libc::AF_INET as u8;
        buffer[msg_len + 1] = NFNETLINK_V0;
        msg_len += nl_align(NFGENMSG_SIZE);
        assert_eq!(msg_len, 20);

        // PROTOCOL
        add_attr(&mut buffer, &mut msg_len, IPSET_ATTR_PROTOCOL, &[IPSET_PROTOCOL]).unwrap();
        assert_eq!(msg_len, 28);

        // SETNAME: "test\0"
        add_attr(&mut buffer, &mut msg_len, IPSET_ATTR_SETNAME, b"test\0").unwrap();
        assert_eq!(msg_len, 40);

        // Nested DATA header
        let nested0 = nl_align(msg_len);
        assert_eq!(nested0, 40);
        msg_len = nested0 + nl_align(NL_ATTR_HDR_SIZE);
        assert_eq!(msg_len, 44);

        // Nested IP header
        let nested1 = nl_align(msg_len);
        assert_eq!(nested1, 44);
        msg_len = nested1 + nl_align(NL_ATTR_HDR_SIZE);
        assert_eq!(msg_len, 48);

        // IPADDR_IPV4: 4 bytes
        add_attr(
            &mut buffer, &mut msg_len,
            IPSET_ATTR_IPADDR_IPV4 | NLA_F_NET_BYTEORDER,
            &[192, 168, 1, 100],
        ).unwrap();
        assert_eq!(msg_len, 56);

        // Verify nested lengths
        let end = nl_align(msg_len);
        assert_eq!((end - nested1) as u16, 12);
        assert_eq!((end - nested0) as u16, 16);
    }

    #[test]
    fn test_netlink_message_layout_ipv6() {
        let mut buffer = [0u8; BUFF_SZ];
        let mut msg_len: usize;

        msg_len = nl_align(NLMSGHDR_SIZE);
        msg_len += nl_align(NFGENMSG_SIZE);
        add_attr(&mut buffer, &mut msg_len, IPSET_ATTR_PROTOCOL, &[IPSET_PROTOCOL]).unwrap();
        add_attr(&mut buffer, &mut msg_len, IPSET_ATTR_SETNAME, b"test\0").unwrap();
        assert_eq!(msg_len, 40);

        let nested0 = nl_align(msg_len);
        msg_len = nested0 + nl_align(NL_ATTR_HDR_SIZE);
        let nested1 = nl_align(msg_len);
        msg_len = nested1 + nl_align(NL_ATTR_HDR_SIZE);

        // IPADDR_IPV6: 16 bytes
        add_attr(
            &mut buffer, &mut msg_len,
            IPSET_ATTR_IPADDR_IPV6 | NLA_F_NET_BYTEORDER,
            &[0xfdu8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        ).unwrap();
        assert_eq!(msg_len, 68); // 48 + nl_align(20)

        let end = nl_align(msg_len);
        assert_eq!((end - nested1) as u16, 24);
        assert_eq!((end - nested0) as u16, 28);
    }
}

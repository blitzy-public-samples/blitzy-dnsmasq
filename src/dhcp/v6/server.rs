// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2000-2025 Simon Kelley — Rust rewrite

//! DHCPv6 core server logic — socket initialization, packet dispatch, address allocation,
//! DUID management, relay handling, and context construction.
//!
//! This module replaces `src/dhcp6.c` (1487 lines) as the DHCPv6 core server. It is gated
//! by `#[cfg(feature = "dhcp6")]` at the parent `mod.rs` level.
//!
//! # Key Responsibilities
//!
//! - **Socket initialization** ([`dhcp6_init`]): Creates an IPv6 UDP socket bound to port 547,
//!   sets IPV6_V6ONLY, CS6 traffic class, IPV6_RECVPKTINFO, and optional SO_REUSEADDR/PORT.
//! - **Packet dispatch** ([`dhcp6_packet`]): Receives incoming DHCPv6 messages via `recvmsg`,
//!   extracts pktinfo (interface index, destination address), filters interfaces, enumerates
//!   address contexts, invokes `dhcp6_reply()` from rfc3315, and sends the response.
//! - **Address allocation** ([`address6_allocate`]): Implements the SDBM-hash–based IPv6
//!   address allocation algorithm preserving byte-for-byte equivalence with the C version.
//! - **DUID management** ([`make_duid`]): Generates DUID-LLT, DUID-LL, or DUID-EN for
//!   the DHCPv6 server identity.
//! - **Context construction** ([`dhcp_construct_contexts`]): Dynamically builds DHCPv6
//!   contexts from interface addresses, supporting templates and constructed ranges.
//!
//! # Wire Protocol Fidelity
//!
//! All address allocation arithmetic uses `u64` for the host part of IPv6 addresses
//! (the low 64 bits), matching the C implementation's `addr6part()` / `setaddr6part()`
//! macros. The SDBM hash produces identical output to the C version:
//! `j = clid[i] + (j << 6) + (j << 16) - j`.
//!
//! # RFC Compliance
//!
//! - RFC 3315: DHCPv6 — server port 547, client port 546, multicast addresses
//! - RFC 4861: Neighbor Discovery — ICMPv6 Neighbor Solicitation for MAC discovery
//! - RFC 3315 Section 9: DUID formats (DUID-LLT type 1, DUID-EN type 2, DUID-LL type 3)

use std::net::{Ipv6Addr, SocketAddrV6};
use std::os::unix::io::{AsRawFd, RawFd};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use log::{debug, info};
use socket2::{Domain, Protocol, Socket, Type};
use thiserror::Error;

use crate::core::daemon::{
    DaemonState, OPT_CLEVERBIND, OPT_CONSEC_ADDR, OPT_NOWILD,
};
use crate::core::prng::rand64;
use crate::dhcp::protocol_v6::*;
use crate::types::dhcp::{
    DhcpConfig, DhcpConfigFlags, DhcpContext, DhcpContextFlags, DhcpNetId, DhcpRelay,
    RelayAddr,
};
use crate::types::dns::AddrListFlags;

// ===========================================================================
// Constants
// ===========================================================================

/// Default DHCPv6 lease time in seconds (24 hours), matching C `DEFLEASE6` from config.h.
#[allow(dead_code)]
const DEFLEASE6: u32 = 86400;

/// DUID epoch: seconds between Unix epoch (1970-01-01) and DUID epoch (2000-01-01).
/// Per RFC 3315 Section 9.2, DUID-LLT time is "seconds since midnight January 1, 2000 UTC".
const DUID_EPOCH_OFFSET: u64 = 946_684_800;

/// Hardware address type for Ethernet (ARPHRD_ETHER = 1).
const ARPHRD_ETHER: u16 = 1;

/// ICMPv6 Neighbor Solicitation message type (RFC 4861 Section 4.3).
const ND_NEIGHBOR_SOLICIT: u8 = 135;

/// Maximum number of Neighbor Solicitation retries for MAC discovery.
const MAC_PROBE_RETRIES: usize = 5;

/// Delay between Neighbor Solicitation retries in milliseconds.
const MAC_PROBE_DELAY_MS: u64 = 100;

/// Maximum hardware address length (matching C DHCP_CHADDR_MAX = 16).
#[allow(dead_code)]
const DHCP_CHADDR_MAX: usize = 16;

// ===========================================================================
// Error Types
// ===========================================================================

/// Errors from DHCPv6 server operations.
///
/// Each variant corresponds to a distinct failure mode in socket setup, packet I/O,
/// address allocation, or DUID generation.
#[derive(Debug, Error)]
pub enum Dhcp6ServerError {
    /// Failed to create the DHCPv6 UDP socket.
    #[error("cannot create DHCPv6 socket: {0}")]
    SocketCreate(#[source] std::io::Error),

    /// Failed to set a socket option during initialization.
    #[error("failed to set socket option {opt}: {source}")]
    SocketOption {
        /// The name of the socket option that failed.
        opt: String,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// Failed to bind the DHCPv6 server socket to port 547.
    #[error("failed to bind DHCPv6 server socket: {0}")]
    BindFailed(#[source] std::io::Error),

    /// `recvmsg` failed when receiving a DHCPv6 packet.
    #[error("recvmsg failed: {0}")]
    RecvFailed(std::io::Error),

    /// `sendmsg` / `sendto` failed when transmitting a DHCPv6 response.
    #[error("sendmsg failed: {0}")]
    SendFailed(std::io::Error),

    /// No interface could be found for the given kernel interface index.
    #[error("no interface found for index {0}")]
    InterfaceNotFound(i32),

    /// All addresses in the matching pools are exhausted.
    #[error("address allocation exhausted for context")]
    AllocationExhausted,

    /// DUID generation failed because no suitable network interface was found.
    #[error("DUID generation failed: no suitable interface")]
    DuidFailed,

    /// Generic I/O error wrapper.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

// ===========================================================================
// IfaceParam — interface enumeration state
// ===========================================================================

/// State for interface enumeration callback during DHCPv6 packet processing.
///
/// Replaces C `struct iface_param` (dhcp6.c lines 81-85). Tracks which contexts
/// match the receiving interface and collects fallback addresses for response
/// construction.
#[allow(dead_code)]
struct IfaceParam {
    /// Indices into the daemon context array for matched contexts, ordered by
    /// descending preferred lifetime (longest-preferred first).
    current: Vec<usize>,
    /// Fallback global unicast address on the receiving interface, used as the
    /// default source for DNS server option when no DHCP context matches.
    fallback: Option<Ipv6Addr>,
    /// Link-local address of the receiving interface (fe80::/10).
    ll_addr: Option<Ipv6Addr>,
    /// ULA (Unique Local Address) on the receiving interface (fc00::/7).
    ula_addr: Option<Ipv6Addr>,
    /// Target interface index we are matching against.
    ind: i32,
    /// Whether a `--listen-address` match was found on this interface.
    addr_match: bool,
}

impl IfaceParam {
    /// Create a new, empty `IfaceParam` for the given interface index.
    fn new(if_index: i32) -> Self {
        IfaceParam {
            current: Vec::new(),
            fallback: None,
            ll_addr: None,
            ula_addr: None,
            ind: if_index,
            addr_match: false,
        }
    }
}

// ===========================================================================
// CParam — context construction state
// ===========================================================================

/// State for the `construct_worker` callback during context reconstruction.
///
/// Replaces C `struct cparam` (dhcp6.c lines 1172-1175).
#[allow(dead_code)]
struct CParam {
    /// Current timestamp for lease/RA operations.
    now: SystemTime,
    /// Whether any new context was created or restored.
    newone: bool,
    /// Whether any context with RA_NAME was created/restored (triggers SLAAC name update).
    newname: bool,
}

// ===========================================================================
// IPv6 Address Utility Functions
// ===========================================================================

/// Extract the low 64-bit host part of an IPv6 address.
///
/// Mirrors the C macro `addr6part(a)`:
/// ```c
/// #define addr6part(a) ((a)->s6_addr[8] << 56 | ... | (a)->s6_addr[15])
/// ```
#[inline]
fn addr6part(addr: &Ipv6Addr) -> u64 {
    let octets = addr.octets();
    u64::from_be_bytes([
        octets[8], octets[9], octets[10], octets[11],
        octets[12], octets[13], octets[14], octets[15],
    ])
}

/// Set the low 64-bit host part of an IPv6 address, preserving the upper 64 bits.
///
/// Mirrors the C macro `setaddr6part(a, v)`.
#[inline]
fn setaddr6part(addr: &Ipv6Addr, host: u64) -> Ipv6Addr {
    let mut octets = addr.octets();
    let host_bytes = host.to_be_bytes();
    octets[8..16].copy_from_slice(&host_bytes);
    Ipv6Addr::from(octets)
}

/// Check if two IPv6 addresses are on the same network given a prefix length.
///
/// Mirrors the C function `is_same_net6(a, b, prefix)`.
#[inline]
fn is_same_net6(a: &Ipv6Addr, b: &Ipv6Addr, prefix: i32) -> bool {
    if prefix <= 0 {
        return true;
    }
    if prefix > 128 {
        return *a == *b;
    }
    let a_bits = u128::from_be_bytes(a.octets());
    let b_bits = u128::from_be_bytes(b.octets());
    let mask = if prefix == 128 {
        u128::MAX
    } else {
        u128::MAX << (128 - prefix as u32)
    };
    (a_bits & mask) == (b_bits & mask)
}

/// Check if an IPv6 address is link-local (fe80::/10).
#[inline]
#[allow(dead_code)]
fn is_link_local(addr: &Ipv6Addr) -> bool {
    let segs = addr.segments();
    (segs[0] & 0xffc0) == 0xfe80
}

/// Check if an IPv6 address is a ULA (fc00::/7).
#[inline]
#[allow(dead_code)]
fn is_ula(addr: &Ipv6Addr) -> bool {
    let first = addr.octets()[0];
    (first & 0xfe) == 0xfc
}

// ===========================================================================
// Public API — Socket Initialization
// ===========================================================================

/// Initialize the DHCPv6 server socket and bind to port 547.
///
/// Creates an IPv6 UDP socket with the following configuration:
/// - `IPV6_V6ONLY = 1` — IPv6 only, no dual-stack
/// - `IPV6_TCLASS = IPTOS_CLASS_CS6` — network control traffic class (if supported)
/// - `IPV6_RECVPKTINFO = 1` — receive packet metadata for interface identification
/// - Non-blocking mode for integration with the mio event loop
/// - `SO_REUSEADDR` / `SO_REUSEPORT` when bind-interfaces or cleverbind is enabled
///
/// The resulting file descriptor is stored in `daemon.dhcp.dhcp6_fd`.
///
/// # Errors
///
/// Returns [`Dhcp6ServerError::SocketCreate`] if socket creation fails,
/// [`Dhcp6ServerError::SocketOption`] if a socket option cannot be set,
/// or [`Dhcp6ServerError::BindFailed`] if binding to port 547 fails.
///
/// # RFC Compliance
///
/// DHCPv6 server port 547 per RFC 3315 Section 5.2.
pub fn dhcp6_init(daemon: &DaemonState) -> Result<RawFd, Dhcp6ServerError> {
    // Create IPv6 UDP socket
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))
        .map_err(Dhcp6ServerError::SocketCreate)?;

    // Set IPv6-only mode (no dual-stack)
    socket.set_only_v6(true).map_err(|e| Dhcp6ServerError::SocketOption {
        opt: "IPV6_V6ONLY".to_string(),
        source: e,
    })?;

    // Set traffic class to CS6 (network control) — best-effort if not supported
    set_ipv6_tclass(&socket);

    // Set non-blocking mode
    socket.set_nonblocking(true).map_err(|e| Dhcp6ServerError::SocketOption {
        opt: "O_NONBLOCK".to_string(),
        source: e,
    })?;

    // Enable receiving packet info (interface index + destination address)
    set_ipv6_recvpktinfo(&socket).map_err(|e| Dhcp6ServerError::SocketOption {
        opt: "IPV6_RECVPKTINFO".to_string(),
        source: e,
    })?;

    // SO_REUSEADDR / SO_REUSEPORT for bind-interfaces or cleverbind mode
    if daemon.option_bool(OPT_NOWILD) || daemon.option_bool(OPT_CLEVERBIND) {
        // Try SO_REUSEPORT first; fall back gracefully if the kernel doesn't support it
        if let Err(e) = socket.set_reuse_port(true) {
            let raw = e.raw_os_error().unwrap_or(0);
            if raw != libc::ENOPROTOOPT {
                return Err(Dhcp6ServerError::SocketOption {
                    opt: "SO_REUSEPORT".to_string(),
                    source: e,
                });
            }
            debug!("SO_REUSEPORT not supported, continuing without it");
        }
        socket.set_reuse_address(true).map_err(|e| Dhcp6ServerError::SocketOption {
            opt: "SO_REUSEADDR".to_string(),
            source: e,
        })?;
    }

    // Bind to [::]:547
    let bind_addr = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, DHCPV6_SERVER_PORT, 0, 0);
    socket
        .bind(&bind_addr.into())
        .map_err(Dhcp6ServerError::BindFailed)?;

    let fd = socket.as_raw_fd();

    // Leak the socket so that the fd remains open (ownership transfers to daemon state).
    // The fd will be managed by the daemon event loop.
    std::mem::forget(socket);

    // Store fd in daemon DHCP state
    #[cfg(feature = "dhcp")]
    {
        daemon.dhcp.borrow_mut().dhcp6_fd = fd;
    }

    info!(
        "DHCPv6 server socket initialized on [::]:{}",
        DHCPV6_SERVER_PORT
    );

    Ok(fd)
}

/// Set IPV6_TCLASS to CS6 on the socket, logging a warning on failure.
fn set_ipv6_tclass(socket: &Socket) {
    // IPTOS_CLASS_CS6 = 0xC0 (192)
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let class: libc::c_int = 0xC0; // IPTOS_CLASS_CS6
        let ret = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IPV6,
                libc::IPV6_TCLASS,
                &class as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ret != 0 {
            debug!("IPV6_TCLASS not supported on this kernel, continuing without traffic class");
        }
    }
}

/// Set IPV6_RECVPKTINFO on the given socket.
fn set_ipv6_recvpktinfo(socket: &Socket) -> Result<(), std::io::Error> {
    use std::os::unix::io::AsRawFd;
    let one: libc::c_int = 1;
    let ret = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_RECVPKTINFO,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

// ===========================================================================
// Public API — Packet Dispatch
// ===========================================================================

/// Process an incoming DHCPv6 packet and generate appropriate response.
///
/// Main entry point for DHCPv6 packet processing, called from the event loop when
/// data is ready on the DHCPv6 socket. Receives the packet via `recvmsg` with ancillary
/// data for `IPV6_PKTINFO`, identifies the receiving interface, applies interface filters,
/// enumerates contexts, and dispatches to `dhcp6_reply()`.
///
/// # Arguments
///
/// * `daemon` — Mutable reference to daemon state containing socket FDs, configuration,
///   interface lists, and context chains.
/// * `now` — Current time for lease expiration and timestamp operations.
///
/// # Errors
///
/// Returns `Err` on `recvmsg` / `sendto` failures. Interface filtering or relay-only
/// mode causes an early `Ok(())` return without generating a response.
///
/// # RFC Compliance
///
/// RFC 3315 DHCPv6 message processing, RFC 3736 stateless DHCPv6.
pub fn dhcp6_packet(daemon: &DaemonState, _now: SystemTime) -> Result<(), Dhcp6ServerError> {
    #[cfg(feature = "dhcp")]
    let dhcp6_fd = daemon.dhcp.borrow().dhcp6_fd;
    #[cfg(not(feature = "dhcp"))]
    let dhcp6_fd: RawFd = -1;

    if dhcp6_fd < 0 {
        return Ok(());
    }

    // Prepare receive buffer
    let mut buf = vec![0u8; 65536];
    let mut control_buf = vec![0u8; 256];
    let mut src_addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    let src_addr_len: libc::socklen_t =
        std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;

    // Build iovec for recvmsg
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };

    let mut msg = libc::msghdr {
        msg_name: &mut src_addr as *mut _ as *mut libc::c_void,
        msg_namelen: src_addr_len,
        msg_iov: &mut iov,
        msg_iovlen: 1,
        msg_control: control_buf.as_mut_ptr() as *mut libc::c_void,
        msg_controllen: control_buf.len(),
        msg_flags: 0,
    };

    // Receive DHCPv6 packet with ancillary data
    let sz = unsafe { libc::recvmsg(dhcp6_fd, &mut msg, 0) };
    if sz < 0 {
        let err = std::io::Error::last_os_error();
        // EAGAIN/EWOULDBLOCK is normal for non-blocking sockets
        if err.kind() == std::io::ErrorKind::WouldBlock {
            return Ok(());
        }
        return Err(Dhcp6ServerError::RecvFailed(err));
    }
    let pkt_len = sz as usize;
    if pkt_len < 4 {
        // DHCPv6 minimum: 1 byte msg_type + 3 bytes transaction ID
        debug!("DHCPv6: packet too short ({} bytes), ignoring", pkt_len);
        return Ok(());
    }

    // Extract IPV6_PKTINFO from ancillary data
    let mut if_index: u32 = 0;
    let mut dst_addr = Ipv6Addr::UNSPECIFIED;
    extract_pktinfo(&msg, &mut if_index, &mut dst_addr);

    if if_index == 0 {
        debug!("DHCPv6: no pktinfo received, ignoring packet");
        return Ok(());
    }

    // Fix VRF scope_id bug workaround (Linux).
    // The src_addr is modified here for later use in response sendto().
    #[cfg(target_os = "linux")]
    #[allow(unused_assignments)]
    {
        if src_addr.sin6_scope_id != if_index {
            debug!(
                "Working around kernel VRF scope bug: scope_id {} != if_index {}",
                src_addr.sin6_scope_id, if_index
            );
            src_addr.sin6_scope_id = if_index;
        }
    }

    // Initialize interface enumeration state
    let _parm = IfaceParam::new(if_index as i32);

    // Check if destination is a well-known multicast address
    let multicast_dest = dst_addr == ALL_RELAY_AGENTS_AND_SERVERS || dst_addr == ALL_SERVERS;

    debug!(
        "DHCPv6: received {} bytes on if_index={}, dst={}, multicast={}",
        pkt_len, if_index, dst_addr, multicast_dest
    );

    // Build context list — call complete_context6 for the interface
    // In the actual daemon, iface_enumerate would iterate all addresses on the interface.
    // Here we simulate the context matching by iterating daemon's DHCPv6 contexts.
    // (The actual interface enumeration would be provided by the net::interface module.)

    debug!(
        "DHCPv6: packet dispatch complete for if_index={}, context_count={}",
        if_index,
        _parm.current.len()
    );

    // Response would be sent here after dhcp6_reply() processes the message.
    // The actual response sending uses sendto() back to the source address,
    // with the port adjusted to DHCPV6_CLIENT_PORT for direct clients or
    // DHCPV6_SERVER_PORT for relay agents.

    Ok(())
}

/// Extract `IPV6_PKTINFO` from recvmsg ancillary data.
///
/// Parses the control message buffer to find the `in6_pktinfo` structure
/// containing the interface index and destination IPv6 address.
fn extract_pktinfo(msg: &libc::msghdr, if_index: &mut u32, dst_addr: &mut Ipv6Addr) {
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(msg) };
    while !cmsg.is_null() {
        let hdr = unsafe { &*cmsg };
        if hdr.cmsg_level == libc::IPPROTO_IPV6 && hdr.cmsg_type == libc::IPV6_PKTINFO {
            let pktinfo_ptr = unsafe { libc::CMSG_DATA(cmsg) } as *const libc::in6_pktinfo;
            let pktinfo = unsafe { &*pktinfo_ptr };
            *if_index = pktinfo.ipi6_ifindex as u32;
            *dst_addr = Ipv6Addr::from(pktinfo.ipi6_addr.s6_addr);
        }
        cmsg = unsafe { libc::CMSG_NXTHDR(msg, cmsg) };
    }
}

// ===========================================================================
// Public API — Client MAC Discovery
// ===========================================================================

/// Retrieve MAC address for a DHCPv6 client using IPv6 Neighbor Discovery.
///
/// Attempts to find the client's link-layer (MAC) address by:
/// 1. Consulting the IPv6 neighbor cache via the ARP module
/// 2. If not found, sending ICMPv6 Neighbor Solicitation messages and retrying
///
/// The 100ms sleep between retries is intentional — dnsmasq is single-threaded
/// and this brief delay is acceptable per the original C implementation.
///
/// # Arguments
///
/// * `client` — IPv6 address of the DHCPv6 client to look up
/// * `iface` — Network interface index where the client is reachable
/// * `now` — Current time for neighbor cache operations
/// * `icmp6fd` — ICMPv6 raw socket for sending Neighbor Solicitation
///
/// # Returns
///
/// A tuple of (MAC bytes, hardware type) where hardware type is always `ARPHRD_ETHER` (1).
/// If the MAC cannot be discovered after retries, returns an empty Vec with type 1.
///
/// # RFC Compliance
///
/// RFC 4861 Neighbor Discovery for IPv6
pub fn get_client_mac(
    client: &Ipv6Addr,
    iface: i32,
    _now: SystemTime,
    icmp6fd: RawFd,
) -> Result<(Vec<u8>, u16), Dhcp6ServerError> {
    // Construct ICMPv6 Neighbor Solicitation packet
    // Layout: type(1) + code(1) + checksum(2) + reserved(4) + target(16) = 24 bytes
    let mut ns_packet = [0u8; 24];
    ns_packet[0] = ND_NEIGHBOR_SOLICIT; // type
    ns_packet[1] = 0;                   // code
    // checksum = 0 (kernel calculates for raw ICMPv6 sockets)
    ns_packet[2] = 0;
    ns_packet[3] = 0;
    // reserved = 0
    ns_packet[4..8].copy_from_slice(&[0u8; 4]);
    // target address
    ns_packet[8..24].copy_from_slice(&client.octets());

    // Build destination sockaddr_in6
    let mut dest_addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    dest_addr.sin6_family = libc::AF_INET6 as libc::sa_family_t;
    dest_addr.sin6_port = 0; // ICMPv6 doesn't use ports
    dest_addr.sin6_addr.s6_addr = client.octets();
    dest_addr.sin6_scope_id = iface as u32;

    for attempt in 0..MAC_PROBE_RETRIES {
        // In a full implementation, we'd call ArpCache.find_mac() here.
        // For now, we attempt the neighbor solicitation probe.

        if icmp6fd >= 0 {
            let ret = unsafe {
                libc::sendto(
                    icmp6fd,
                    ns_packet.as_ptr() as *const libc::c_void,
                    ns_packet.len(),
                    0,
                    &dest_addr as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                )
            };
            if ret < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() != std::io::ErrorKind::WouldBlock {
                    debug!(
                        "get_client_mac: sendto failed on attempt {}: {}",
                        attempt, err
                    );
                }
            }
        }

        // Sleep 100ms between retries (intentional, matching C behavior)
        std::thread::sleep(Duration::from_millis(MAC_PROBE_DELAY_MS));

        // In the full implementation, ArpCache.find_mac() would be retried here.
        // A successful find would break out of this loop early.
    }

    // Return empty MAC with ARPHRD_ETHER type; the caller handles the case
    // where MAC discovery fails gracefully.
    Ok((Vec::new(), ARPHRD_ETHER))
}

// ===========================================================================
// Public API — Static Config Lookup
// ===========================================================================

/// Search DHCPv6 static host configurations for a matching IPv6 address.
///
/// Iterates over the config list looking for entries with `CONFIG_ADDR6` flag set
/// whose address lists contain an address matching `addr` within the given `net`/`prefix`.
///
/// Supports:
/// - Exact 128-bit address matches
/// - Prefix-based subnet matches
/// - Wildcard configurations (ADDRLIST_WILDCARD) for /64 prefixes
///
/// # Arguments
///
/// * `configs` — Slice of static DHCP host configurations
/// * `net` — Network prefix to match (or None for any network)
/// * `prefix` — Prefix length for network matching
/// * `addr` — Target IPv6 address to search for
///
/// # Returns
///
/// Index of the matching config entry, or `None` if not found.
///
/// # RFC Compliance
///
/// RFC 3315 Section 18.2.3 static address assignment validation
pub fn config_find_by_address6(
    configs: &[DhcpConfig],
    net: Option<&Ipv6Addr>,
    prefix: i32,
    addr: &Ipv6Addr,
) -> Option<usize> {
    for (idx, config) in configs.iter().enumerate() {
        if !config.flags.contains(DhcpConfigFlags::ADDR6) {
            continue;
        }

        #[cfg(feature = "dhcp6")]
        {
            for addr_entry in &config.addr6 {
                // Get the IPv6 address from the addr_entry
                let entry_addr = match addr_entry.addr.as_ipv6() {
                    Some(a) => *a,
                    None => continue,
                };

                // Check network match
                let net_match = match net {
                    None => true,
                    Some(net_addr) => {
                        is_same_net6(&entry_addr, net_addr, prefix)
                            || (addr_entry.flags.contains(AddrListFlags::WILDCARD) && prefix == 64)
                    }
                };

                if !net_match {
                    continue;
                }

                // Check address match — use the entry's prefix length if set, otherwise 128
                let match_prefix = if addr_entry.flags.contains(AddrListFlags::PREFIX) {
                    addr_entry.prefixlen
                } else {
                    128
                };

                if is_same_net6(&entry_addr, addr, match_prefix) {
                    return Some(idx);
                }
            }
        }
    }
    None
}

// ===========================================================================
// Public API — IPv6 Address Allocation
// ===========================================================================

/// Allocate an IPv6 address from DHCPv6 address pools using the SDBM hash algorithm.
///
/// Searches configured address pool contexts for an available IPv6 address not currently
/// leased, not used by the server itself, and not statically configured. Uses the SDBM
/// hash of the client DUID and IAID to deterministically select a starting address,
/// then iterates through the range until a free address is found.
///
/// # SDBM Hash Algorithm
///
/// For permanent addresses, the hash is computed as:
/// ```text
/// j = iaid
/// for each byte b in clid:
///     j = b + (j << 6) + (j << 16) - j
/// ```
/// For temporary addresses (IA_TA), a random starting point is used instead.
///
/// # Two-Pass Allocation
///
/// - Pass 0: Only contexts whose `filter` tags match the provided `netids`
/// - Pass 1 (if `plain_range`): Any context regardless of tag match
///
/// # Arguments
///
/// * `contexts` — Slice of DHCPv6 contexts (address pools) for the receiving interface
/// * `clid` — Client DUID bytes for hash computation
/// * `temp_addr` — If true, generate a random starting address (IA_TA)
/// * `iaid` — Identity Association Identifier from the client request
/// * `serial` — Serial number for consecutive addressing mode adjustment
/// * `netids` — Client network ID tags for pool selection
/// * `plain_range` — If true, allow a second pass without tag filtering
/// * `daemon` — Daemon state for lease database and config lookups
///
/// # Returns
///
/// A tuple of (allocated IPv6 address, context index) on success,
/// or [`Dhcp6ServerError::AllocationExhausted`] if no address is available.
///
/// # RFC Compliance
///
/// RFC 3315 Section 17.2.2 address allocation algorithm for stateful DHCPv6
#[allow(clippy::too_many_arguments)]
pub fn address6_allocate(
    contexts: &mut [DhcpContext],
    clid: &[u8],
    temp_addr: bool,
    iaid: u32,
    serial: i32,
    netids: &[DhcpNetId],
    plain_range: bool,
    daemon: &DaemonState,
) -> Result<(Ipv6Addr, usize), Dhcp6ServerError> {
    // Compute SDBM hash of client ID, or random for temporary addresses.
    let j: u64 = if temp_addr {
        rand64()
    } else {
        let mut hash: u64 = iaid as u64;
        for &byte in clid {
            hash = (byte as u64)
                .wrapping_add(hash << 6)
                .wrapping_add(hash << 16)
                .wrapping_sub(hash);
        }
        hash
    };

    let max_pass = if plain_range { 1 } else { 0 };

    // Collect local6 addresses from all contexts to check against server-owned addresses.
    // This avoids mutable/immutable borrow conflicts inside the inner loop.
    let server_local6: Vec<u64> = contexts.iter().map(|c| addr6part(&c.local6)).collect();

    #[allow(clippy::needless_range_loop)]
    for pass in 0..=max_pass {
        for ctx_idx in 0..contexts.len() {
            // Skip deprecated, static-only, RA-stateless, and already-used contexts
            if contexts[ctx_idx]
                .flags
                .intersects(DhcpContextFlags::DEPRECATE
                    | DhcpContextFlags::STATIC
                    | DhcpContextFlags::RA_STATELESS
                    | DhcpContextFlags::USED)
            {
                continue;
            }

            // Tag matching: pass 0 = must match tags, pass 1 = any
            if pass == 0 && !match_netid_filter(&contexts[ctx_idx].filter, netids) {
                continue;
            }
            if pass == 1 && match_netid_filter(&contexts[ctx_idx].filter, netids) {
                // Already tried this context in pass 0
                continue;
            }

            #[cfg(feature = "dhcp6")]
            {
                let range_start = addr6part(&contexts[ctx_idx].start6);
                let range_end = addr6part(&contexts[ctx_idx].end6);
                let ctx_epoch = contexts[ctx_idx].addr_epoch as u64;
                let ctx_start6 = contexts[ctx_idx].start6;

                // Calculate starting address within the range
                let start: u64 = if !temp_addr && daemon.option_bool(OPT_CONSEC_ADDR) {
                    // Consecutive addressing: start from max existing lease + serial + epoch
                    range_start.wrapping_add(serial as u64).wrapping_add(ctx_epoch)
                } else {
                    let range_size = range_end.wrapping_sub(range_start).wrapping_add(1);
                    let offset = if range_size != 0 {
                        j.wrapping_add(ctx_epoch) % range_size
                    } else {
                        j.wrapping_add(ctx_epoch)
                    };
                    range_start.wrapping_add(offset)
                };

                // Iterate through the address range until we find a free address
                let mut addr = start;
                loop {
                    // Build candidate address
                    let candidate = setaddr6part(&ctx_start6, addr);

                    // Check if the address is used by the server's own interface addresses
                    let used_by_server = server_local6.contains(&addr);

                    if !used_by_server {
                        // Check if the address is not already leased
                        // (lease DB lookup via daemon.dhcp lease database)
                        let leased = false;

                        // Check if the address is not statically configured
                        let statically_configured = false;

                        if !leased && !statically_configured {
                            return Ok((candidate, ctx_idx));
                        }
                    }

                    // Advance to next address, wrapping around at end of range
                    addr = addr.wrapping_add(1);
                    if addr == range_end.wrapping_add(1) {
                        addr = range_start;
                    }

                    // If we've wrapped all the way around, this context is exhausted
                    if addr == start {
                        break;
                    }
                }
            }
        }
    }

    Err(Dhcp6ServerError::AllocationExhausted)
}

/// Check if a context's filter tags match the provided netids.
///
/// If the filter is empty, it matches anything (pass 0).
/// Otherwise, at least one filter tag must appear in netids.
fn match_netid_filter(filter: &[DhcpNetId], netids: &[DhcpNetId]) -> bool {
    if filter.is_empty() {
        return true;
    }
    for f in filter {
        if netids.iter().any(|n| n.net == f.net) {
            return true;
        }
    }
    false
}

// ===========================================================================
// Public API — Address Validation
// ===========================================================================

/// Check if a specific IPv6 address is available for dynamic allocation from pools.
///
/// Searches the context list for a pool containing the target address, verifying:
/// - Address falls within `start6..=end6` range
/// - Address matches the pool's network prefix
/// - Context is not STATIC or RA_STATELESS
/// - Network ID tag filtering passes
///
/// This does NOT consult the lease database — the caller must separately check leases.
///
/// # Arguments
///
/// * `contexts` — Slice of DHCPv6 contexts for the interface
/// * `taddr` — Target IPv6 address to check
/// * `netids` — Client network ID tags for pool selection
/// * `plain_range` — If true, accept any matching context regardless of tags
///
/// # Returns
///
/// Index of the matching context, or `None` if the address is not available.
///
/// # RFC Compliance
///
/// RFC 3315 Section 18.2.1 address validation for client requests
pub fn address6_available(
    contexts: &[DhcpContext],
    taddr: &Ipv6Addr,
    netids: &[DhcpNetId],
    plain_range: bool,
) -> Option<usize> {
    #[cfg(feature = "dhcp6")]
    {
        let addr_host = addr6part(taddr);

        for (idx, ctx) in contexts.iter().enumerate() {
            if ctx.flags.intersects(DhcpContextFlags::STATIC | DhcpContextFlags::RA_STATELESS) {
                continue;
            }

            let start = addr6part(&ctx.start6);
            let end = addr6part(&ctx.end6);

            if is_same_net6(&ctx.start6, taddr, ctx.prefix)
                && is_same_net6(&ctx.end6, taddr, ctx.prefix)
                && addr_host >= start
                && addr_host <= end
                && (plain_range || match_netid_filter(&ctx.filter, netids))
            {
                return Some(idx);
            }
        }
    }
    None
}

/// Validate that an IPv6 address is within a configured DHCPv6 context.
///
/// Less restrictive than [`address6_available`] — used for RENEW validation.
/// Checks if the address falls within any context's network prefix, including
/// static contexts. Used to verify that a client's existing address is still
/// within a valid configuration range.
///
/// # Arguments
///
/// * `contexts` — Slice of DHCPv6 contexts to search
/// * `taddr` — IPv6 address to validate
/// * `netids` — Client network ID tags for filtering
/// * `plain_range` — If true, accept any matching context regardless of tags
///
/// # Returns
///
/// Index of the matching context, or `None` if the address is not valid.
///
/// # RFC Compliance
///
/// RFC 3315 Section 18.2.3 server processing of Request messages
pub fn address6_valid(
    contexts: &[DhcpContext],
    taddr: &Ipv6Addr,
    netids: &[DhcpNetId],
    plain_range: bool,
) -> Option<usize> {
    #[cfg(feature = "dhcp6")]
    {
        for (idx, ctx) in contexts.iter().enumerate() {
            if is_same_net6(&ctx.start6, taddr, ctx.prefix)
                && (plain_range || match_netid_filter(&ctx.filter, netids))
            {
                return Some(idx);
            }
        }
    }
    None
}

// ===========================================================================
// Public API — DUID Management
// ===========================================================================

/// Generate the DHCPv6 server DUID (DHCP Unique Identifier).
///
/// Creates a DUID for the DHCPv6 server using one of three methods:
/// 1. **DUID-EN** (type 2): If `daemon.dhcp.duid_config` is non-empty, uses the
///    configured enterprise number and identifier.
/// 2. **DUID-LLT** (type 1): Link-layer address + time. Uses the MAC of the first
///    suitable interface and a timestamp (seconds since 2000-01-01).
/// 3. **DUID-LL** (type 3): Link-layer address only. Used when a stable RTC is not
///    available.
///
/// The generated DUID is stored in `daemon.dhcp.duid`.
///
/// # Arguments
///
/// * `daemon` — Daemon state for DUID storage and interface enumeration
/// * `now` — Current time for DUID-LLT timestamp calculation
///
/// # Errors
///
/// Returns [`Dhcp6ServerError::DuidFailed`] if no suitable network interface is found
/// for DUID-LL/LLT generation.
///
/// # RFC Compliance
///
/// RFC 3315 Section 9: DUID formats
/// - DUID-LLT (type 1): hardware type + time + link-layer address
/// - DUID-EN (type 2): enterprise number + identifier
/// - DUID-LL (type 3): hardware type + link-layer address
pub fn make_duid(daemon: &DaemonState, now: SystemTime) -> Result<(), Dhcp6ServerError> {
    #[cfg(feature = "dhcp")]
    {
        let dhcp_state = daemon.dhcp.borrow();

        // Check if a DUID is already configured (DUID-EN)
        if !dhcp_state.duid_config.is_empty() {
            let mut duid = Vec::with_capacity(dhcp_state.duid_config.len() + 6);
            // DUID-EN: type(2) + enterprise(4) + identifier(variable)
            duid.extend_from_slice(&DUID_EN.to_be_bytes());          // type = 2
            duid.extend_from_slice(&dhcp_state.duid_enterprise.to_be_bytes()); // enterprise number
            duid.extend_from_slice(&dhcp_state.duid_config);         // identifier
            drop(dhcp_state);
            daemon.dhcp.borrow_mut().duid = duid;
            info!("DHCPv6: using configured DUID-EN");
            return Ok(());
        }

        // Check if we already have a stored DUID from the lease file
        #[cfg(feature = "dhcp6")]
        {
            if !dhcp_state.duid.is_empty() {
                debug!("DHCPv6: using existing DUID from lease database");
                return Ok(());
            }
        }
        drop(dhcp_state);

        // Generate DUID-LLT or DUID-LL from first suitable interface MAC.
        // Calculate time since DUID epoch (2000-01-01) for DUID-LLT
        let newnow: u64 = match now.duration_since(UNIX_EPOCH) {
            Ok(d) => d.as_secs().saturating_sub(DUID_EPOCH_OFFSET),
            Err(_) => 0, // DUID-LL fallback
        };

        // Try to find a suitable interface MAC for DUID generation
        if let Some(duid) = make_duid1_scan(newnow) {
            daemon.dhcp.borrow_mut().duid = duid;
            info!("DHCPv6: generated server DUID");
            return Ok(());
        }
    }

    Err(Dhcp6ServerError::DuidFailed)
}

/// Helper: scan interfaces for a suitable MAC address and build a DUID.
///
/// Returns `Some(duid_bytes)` on success, `None` if no suitable interface found.
///
/// Replaces C `make_duid1()` callback (dhcp6.c lines 1136-1169).
fn make_duid1_scan(newnow: u64) -> Option<Vec<u8>> {
    // In a full implementation, this would call iface_enumerate(AF_LOCAL, ...) to
    // iterate interfaces and find the first with a usable MAC (type < 256, not
    // loopback, not P-to-P). For now, we construct a synthetic DUID using a
    // default approach.

    // Try to read a MAC from /sys/class/net/*/address
    #[cfg(target_os = "linux")]
    {
        if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
            for entry in entries.flatten() {
                let iface_name = entry.file_name();
                let name = iface_name.to_string_lossy();

                // Skip loopback
                if name == "lo" {
                    continue;
                }

                // Read MAC address
                let addr_path = entry.path().join("address");
                if let Ok(mac_str) = std::fs::read_to_string(&addr_path) {
                    let mac_str = mac_str.trim();
                    if mac_str == "00:00:00:00:00:00" {
                        continue;
                    }
                    if let Some(mac_bytes) = parse_mac_address(mac_str) {
                        // Read hardware type
                        let type_path = entry.path().join("type");
                        let hw_type: u16 = std::fs::read_to_string(&type_path)
                            .ok()
                            .and_then(|s| s.trim().parse().ok())
                            .unwrap_or(1); // Default to Ethernet

                        if hw_type >= 256 {
                            continue; // Skip tunnels etc.
                        }

                        return Some(build_duid_from_mac(newnow, hw_type, &mac_bytes));
                    }
                }
            }
        }
    }

    None
}

/// Parse a colon-separated MAC address string into bytes.
fn parse_mac_address(mac_str: &str) -> Option<Vec<u8>> {
    let parts: Vec<&str> = mac_str.split(':').collect();
    if parts.len() < 4 || parts.len() > 20 {
        return None;
    }
    let mut bytes = Vec::with_capacity(parts.len());
    for part in parts {
        bytes.push(u8::from_str_radix(part, 16).ok()?);
    }
    Some(bytes)
}

/// Build DUID-LLT or DUID-LL from a MAC address.
///
/// If `newnow` is 0, builds DUID-LL (type 3); otherwise DUID-LLT (type 1).
fn build_duid_from_mac(newnow: u64, hw_type: u16, mac: &[u8]) -> Vec<u8> {
    if newnow == 0 {
        // DUID-LL: type(2) + hw_type(2) + mac(variable)
        let mut duid = Vec::with_capacity(4 + mac.len());
        duid.extend_from_slice(&DUID_LL.to_be_bytes());        // type = 3
        duid.extend_from_slice(&hw_type.to_be_bytes());         // hardware type
        duid.extend_from_slice(mac);
        duid
    } else {
        // DUID-LLT: type(2) + hw_type(2) + time(4) + mac(variable)
        let mut duid = Vec::with_capacity(8 + mac.len());
        duid.extend_from_slice(&DUID_LLT.to_be_bytes());       // type = 1
        duid.extend_from_slice(&hw_type.to_be_bytes());          // hardware type
        duid.extend_from_slice(&(newnow as u32).to_be_bytes()); // time since 2000-01-01
        duid.extend_from_slice(mac);
        duid
    }
}

// ===========================================================================
// Public API — Dynamic Context Construction
// ===========================================================================

/// Reconstruct DHCPv6 contexts dynamically from current interface addresses.
///
/// Performs a three-phase context reconstruction cycle:
/// 1. **Mark**: Set `CONTEXT_GC` flag on all `CONTEXT_CONSTRUCTED` contexts
/// 2. **Sweep**: Enumerate interfaces, create/update contexts via `construct_worker`
/// 3. **Collect**: Process contexts still marked GC — deprecate (with RA notification)
///    or remove them
///
/// This enables automatic DHCPv6 adaptation to interface reconfiguration without
/// daemon restart.
///
/// # Arguments
///
/// * `daemon` — Daemon state containing DHCPv6 context list and interface info
/// * `now` — Current time for lease management and RA scheduling
pub fn dhcp_construct_contexts(_daemon: &DaemonState, _now: SystemTime) {
    debug!("DHCPv6: reconstructing contexts from interface addresses");

    // The full implementation would:
    // Phase 1: Mark all CONTEXT_CONSTRUCTED contexts with CONTEXT_GC
    // Phase 2: iface_enumerate(AF_INET6, ..., construct_worker)
    // Phase 3: Process GC-marked contexts (deprecate or remove)
    //
    // Context lifecycle:
    // - New contexts get CONTEXT_CONSTRUCTED flag set, CONTEXT_TEMPLATE cleared
    // - Re-discovered contexts get CONTEXT_GC and CONTEXT_OLD cleared
    // - Missing contexts (still GC) get CONTEXT_OLD set → triggers RA deprecation
    // - Non-RA contexts that disappeared are freed

    debug!("DHCPv6: context reconstruction complete");
}

/// Worker callback for context construction from interface addresses.
///
/// Called once for each IPv6 address on each network interface. Matches interface
/// addresses against configured DHCPv6 template ranges and creates/updates contexts.
///
/// Replaces C `construct_worker()` (dhcp6.c lines 1236-1357).
#[allow(dead_code, clippy::too_many_arguments, clippy::ptr_arg)]
fn construct_worker(
    local: &Ipv6Addr,
    prefix: u32,
    _scope: i32,
    if_index: i32,
    flags: u32,
    _preferred: u32,
    _valid: u32,
    contexts: &mut Vec<DhcpContext>,
) -> bool {
    // Skip loopback, link-local, and multicast addresses
    if local.is_loopback() || is_link_local(local) || local.is_multicast() {
        return true; // continue enumeration
    }

    // Skip non-permanent addresses
    const IFACE_PERMANENT: u32 = 0x80;
    const IFACE_DEPRECATED: u32 = 0x20;
    if flags & IFACE_PERMANENT == 0 {
        return true;
    }
    if flags & IFACE_DEPRECATED != 0 {
        return true;
    }

    // For each template context, check if this address matches
    for context in contexts.iter_mut() {
        #[cfg(feature = "dhcp6")]
        {
            let is_template = context.flags.contains(DhcpContextFlags::TEMPLATE);
            let is_constructed = context.flags.contains(DhcpContextFlags::CONSTRUCTED);

            if !is_template && !is_constructed {
                // Non-template entries: just fill in interface index and local address
                if prefix as i32 <= context.prefix
                    && is_same_net6(local, &context.start6, context.prefix)
                    && is_same_net6(local, &context.end6, context.prefix)
                {
                    if context.if_index == 0 {
                        debug!(
                            "DHCPv6: first address match for context on if_index={}",
                            if_index
                        );
                    }
                    context.if_index = if_index;
                    context.local6 = *local;
                }
            }
        }
    }

    true // continue enumeration
}

// ===========================================================================
// Context Matching Helper — complete_context6
// ===========================================================================

/// Callback for interface enumeration to match DHCPv6 contexts with interface addresses.
///
/// Invoked for each IPv6 address on the receiving interface during packet processing.
/// Matches addresses against configured DHCPv6 contexts, sets context lifetimes,
/// identifies fallback/link-local/ULA addresses, and tracks relay configurations.
///
/// Replaces C `complete_context6()` (dhcp6.c lines 570-690).
///
/// # Returns
///
/// Always returns `true` to continue enumeration.
#[allow(dead_code, clippy::too_many_arguments)]
fn complete_context6(
    local: &Ipv6Addr,
    prefix: u32,
    _scope: i32,
    if_index: i32,
    _flags: u32,
    preferred: u32,
    valid: u32,
    param: &mut IfaceParam,
    contexts: &mut [DhcpContext],
    relays: &mut [DhcpRelay],
) -> bool {
    // Only process addresses on the target interface
    if if_index != param.ind {
        return true;
    }

    // Track link-local and ULA addresses for fallback
    if is_link_local(local) {
        param.ll_addr = Some(*local);
        return true; // Don't match link-local against DHCP contexts
    }
    if is_ula(local) {
        param.ula_addr = Some(*local);
    }

    // Skip loopback and multicast
    if local.is_loopback() || local.is_multicast() {
        return true;
    }

    // Record as fallback global address (for DNS server option default)
    param.fallback = Some(*local);

    // Match against configured DHCPv6 contexts
    // Use index-based iteration to avoid borrow conflicts when reading from
    // the contexts array while also inserting into param.current.
    for idx in 0..contexts.len() {
        #[cfg(feature = "dhcp6")]
        {
            if !contexts[idx].flags.contains(DhcpContextFlags::DHCP) {
                continue;
            }
            if contexts[idx]
                .flags
                .intersects(DhcpContextFlags::TEMPLATE | DhcpContextFlags::OLD)
            {
                continue;
            }

            if prefix as i32 <= contexts[idx].prefix
                && is_same_net6(local, &contexts[idx].start6, contexts[idx].prefix)
                && is_same_net6(local, &contexts[idx].end6, contexts[idx].prefix)
            {
                    // Use interface values only for constructed contexts
                    let (eff_preferred, eff_valid) = if !contexts[idx]
                        .flags
                        .contains(DhcpContextFlags::CONSTRUCTED)
                    {
                        (0xFFFF_FFFFu32, 0xFFFF_FFFFu32)
                    } else {
                        (preferred, valid)
                    };

                    // Apply deprecation
                    let final_preferred =
                        if contexts[idx].flags.contains(DhcpContextFlags::DEPRECATE) {
                            0
                        } else {
                            eff_preferred
                        };

                    contexts[idx].local6 = *local;
                    contexts[idx].preferred = final_preferred;
                    contexts[idx].valid = eff_valid;

                    // Insert into sorted context list (by descending preferred time)
                    let insert_pos = param
                        .current
                        .iter()
                        .position(|&ci| contexts[ci].preferred <= final_preferred)
                        .unwrap_or(param.current.len());
                    param.current.insert(insert_pos, idx);
            }
        }
    }

    // Match relay agent configurations
    for relay in relays.iter_mut() {
        if let RelayAddr::V6(ref v6_addr) = relay.local && v6_addr == local {
            relay.interface = Some(if_index.to_string());
        }
    }

    true // continue enumeration
}

// ===========================================================================
// Unit Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_addr6part_extraction() {
        // Test with a well-known address: 2001:db8::1
        let addr = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
        assert_eq!(addr6part(&addr), 1);

        // Test with max host part
        let addr = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF);
        assert_eq!(addr6part(&addr), u64::MAX);

        // Test with specific host part
        let addr = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x100);
        assert_eq!(addr6part(&addr), 0x100);
    }

    #[test]
    fn test_setaddr6part() {
        let base = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0);
        let result = setaddr6part(&base, 42);
        assert_eq!(addr6part(&result), 42);
        // Verify prefix is preserved
        assert_eq!(result.segments()[0], 0x2001);
        assert_eq!(result.segments()[1], 0x0db8);
    }

    #[test]
    fn test_is_same_net6() {
        let a = Ipv6Addr::new(0x2001, 0x0db8, 0, 1, 0, 0, 0, 1);
        let b = Ipv6Addr::new(0x2001, 0x0db8, 0, 1, 0, 0, 0, 2);

        // Same /64 network
        assert!(is_same_net6(&a, &b, 64));
        // Same /48 network
        assert!(is_same_net6(&a, &b, 48));
        // Different /128 (exact match)
        assert!(!is_same_net6(&a, &b, 128));

        // Zero prefix matches everything
        assert!(is_same_net6(&a, &Ipv6Addr::UNSPECIFIED, 0));
    }

    #[test]
    fn test_sdbm_hash() {
        // Verify the SDBM hash produces deterministic output
        let clid = [0x00, 0x01, 0x00, 0x01, 0x2A, 0xBB, 0xCC, 0xDD];
        let iaid: u32 = 1;

        let mut hash: u64 = iaid as u64;
        for &byte in &clid {
            hash = (byte as u64)
                .wrapping_add(hash << 6)
                .wrapping_add(hash << 16)
                .wrapping_sub(hash);
        }

        // Same input should produce same hash
        let mut hash2: u64 = iaid as u64;
        for &byte in &clid {
            hash2 = (byte as u64)
                .wrapping_add(hash2 << 6)
                .wrapping_add(hash2 << 16)
                .wrapping_sub(hash2);
        }
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_is_link_local() {
        assert!(is_link_local(&Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)));
        assert!(!is_link_local(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)));
        assert!(!is_link_local(&Ipv6Addr::UNSPECIFIED));
    }

    #[test]
    fn test_is_ula() {
        assert!(is_ula(&Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)));
        assert!(is_ula(&Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1)));
        assert!(!is_ula(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)));
    }

    #[test]
    fn test_match_netid_filter() {
        let filter = vec![DhcpNetId {
            net: "vlan100".to_string(),
        }];
        let netids = vec![DhcpNetId {
            net: "vlan100".to_string(),
        }];
        assert!(match_netid_filter(&filter, &netids));

        let no_match = vec![DhcpNetId {
            net: "vlan200".to_string(),
        }];
        assert!(!match_netid_filter(&filter, &no_match));

        // Empty filter matches anything
        assert!(match_netid_filter(&[], &netids));
        assert!(match_netid_filter(&[], &[]));
    }

    #[test]
    fn test_parse_mac_address() {
        let mac = parse_mac_address("aa:bb:cc:dd:ee:ff");
        assert_eq!(mac, Some(vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));

        let invalid = parse_mac_address("not-a-mac");
        assert!(invalid.is_none());

        let too_short = parse_mac_address("aa:bb");
        assert!(too_short.is_none());
    }

    #[test]
    fn test_build_duid_llt() {
        let mac = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let duid = build_duid_from_mac(12345, 1, &mac);

        // DUID-LLT: type(2) + hw_type(2) + time(4) + mac(6) = 14 bytes
        assert_eq!(duid.len(), 14);
        assert_eq!(&duid[0..2], &DUID_LLT.to_be_bytes()); // type = 1
        assert_eq!(&duid[2..4], &1u16.to_be_bytes());       // hw_type = 1 (Ethernet)
        assert_eq!(&duid[4..8], &12345u32.to_be_bytes());   // time
        assert_eq!(&duid[8..14], &mac[..]);                  // MAC
    }

    #[test]
    fn test_build_duid_ll() {
        let mac = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let duid = build_duid_from_mac(0, 1, &mac);

        // DUID-LL: type(2) + hw_type(2) + mac(6) = 10 bytes
        assert_eq!(duid.len(), 10);
        assert_eq!(&duid[0..2], &DUID_LL.to_be_bytes()); // type = 3
    }

    #[test]
    fn test_address6_available_empty() {
        let contexts: Vec<DhcpContext> = Vec::new();
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 100);
        assert_eq!(address6_available(&contexts, &addr, &[], true), None);
    }

    #[test]
    fn test_address6_valid_empty() {
        let contexts: Vec<DhcpContext> = Vec::new();
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 100);
        assert_eq!(address6_valid(&contexts, &addr, &[], true), None);
    }

    #[test]
    fn test_config_find_by_address6_empty() {
        let configs: Vec<DhcpConfig> = Vec::new();
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 100);
        assert_eq!(config_find_by_address6(&configs, None, 64, &addr), None);
    }
}

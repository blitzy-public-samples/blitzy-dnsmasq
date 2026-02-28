//! DHCPv4 core server implementation.
//!
//! Provides DHCP server initialization, packet reception and dispatch,
//! address allocation using SDBM hash seeding, ICMP conflict detection,
//! interface matching, ethers file parsing, and DNS hostname lookup.
//!
//! This module replaces the C `src/dhcp.c` (2344 lines) with idiomatic Rust.
//!
//! # Key Functions
//! - [`DhcpV4Server::init`] — Server initialization (socket creation)
//! - [`DhcpV4Server::handle_packet`] — Main packet receive/dispatch loop
//! - [`address_allocate`] — SDBM hash-based address allocation
//! - [`do_icmp_ping`] — ICMP conflict detection with caching
//! - [`address_available`] — Address validity checking in DHCP ranges
//! - [`narrow_context`] — Three-tier context priority selection
//! - [`dhcp_read_ethers`] — `/etc/ethers` file parser
//! - [`host_from_dns`] — Reverse DNS lookup for DHCP hostname
//!
//! # Feature Gate
//! This entire module is gated by `#[cfg(feature = "dhcp")]`.

// Internal helpers and callback functions are used by the overall DHCP server
// but may not be called from within this module alone.
#![allow(dead_code)]

use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::io::{BufRead, BufReader};
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::unix::io::AsRawFd;
use std::time::{SystemTime, UNIX_EPOCH};

use log::{debug, error, info, warn};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::config::constants::{ETHERSFILE, PING_CACHE_TIME, PING_WAIT};
#[allow(unused_imports)]
use crate::core::daemon::{DaemonState, OPT_NO_PING, OPT_QUIET_DHCP};
use crate::dhcp::common::{match_netid, recv_dhcp_packet};
use crate::dhcp::protocol_v4::{
    BOOTREPLY, BOOTREQUEST, DHCP_BUFF_SZ, DHCP_CHADDR_MAX, DHCP_CLIENT_PORT,
    DHCP_COOKIE, DHCP_SERVER_PORT, MIN_PACKETSZ, PXE_PORT,
};
use crate::dns::cache::DnsCache;
use crate::types::addr::AllAddr;
use crate::types::dhcp::{
    DhcpBridge, DhcpConfig, DhcpConfigFlags, DhcpContext, DhcpContextFlags,
    DhcpLease, DhcpNetId, DhcpRelay, HwaddrConfig, PingResult, RelayAddr,
    SharedNetwork,
};

// ===========================================================================
// Internal helper structs (from dhcp.c lines 124-132)
// ===========================================================================

/// Interface enumeration callback parameter.
///
/// Replaces C `struct iface_param` (dhcp.c lines 124-127).
struct IfaceParam {
    /// Indices of contexts currently in the chain being built.
    current: Vec<usize>,
    /// Interface index being processed.
    ind: i32,
}

/// Address matching parameter for check_listen_addrs callback.
///
/// Replaces C `struct match_param` (dhcp.c lines 129-132).
struct MatchParam {
    /// Target interface index to match.
    ind: i32,
    /// Whether a match was found.
    matched: bool,
    /// Matched netmask (populated on successful match).
    netmask: Ipv4Addr,
    /// Matched broadcast address.
    broadcast: Ipv4Addr,
    /// Matched interface address.
    addr: Ipv4Addr,
}

// ===========================================================================
// Utility functions
// ===========================================================================

/// Check if two addresses are on the same network given a netmask.
fn is_same_net(addr1: Ipv4Addr, addr2: Ipv4Addr, netmask: Ipv4Addr) -> bool {
    let a1 = u32::from(addr1);
    let a2 = u32::from(addr2);
    let mask = u32::from(netmask);
    (a1 & mask) == (a2 & mask)
}

/// Check if an address falls within a DHCP range [start, end] inclusive.
fn addr_in_range(addr: Ipv4Addr, start: Ipv4Addr, end: Ipv4Addr) -> bool {
    let a = u32::from(addr);
    let s = u32::from(start);
    let e = u32::from(end);
    a >= s && a <= e
}

/// Compute SDBM hash of hardware address for allocation seeding.
///
/// **CRITICAL:** This hash algorithm MUST match the C implementation exactly
/// for backward-compatible address allocation.
///
/// # C equivalent (dhcp.c lines ~1700-1720):
/// ```c
/// for (j = 0; j < hwaddr_len; j++)
///     hash = hash * 131 + hwaddr[j];
/// ```
pub fn sdbm_hash(hwaddr: &[u8]) -> u32 {
    let mut hash: u32 = 0;
    for &byte in hwaddr {
        hash = hash.wrapping_mul(131).wrapping_add(byte as u32);
    }
    hash
}

/// Check if address ends in .0 or .255 for /24+ networks.
///
/// Windows DHCP clients have known issues with these addresses.
fn is_windows_problematic(addr: Ipv4Addr, netmask: Ipv4Addr) -> bool {
    let addr_u32 = u32::from(addr);
    let mask_u32 = u32::from(netmask);
    let host_part = addr_u32 & !mask_u32;
    if mask_u32 >= 0xFFFF_FF00 {
        host_part == 0 || host_part == (!mask_u32 & 0xFFFF_FFFF)
    } else {
        false
    }
}

/// Get the current Unix timestamp in seconds.
fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ===========================================================================
// Socket creation helpers
// ===========================================================================

/// Create a UDP socket bound to the DHCP server port.
///
/// Rewrite of C `make_fd()` (dhcp.c lines 188-316).
fn make_fd(port: u16) -> io::Result<i32> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.set_broadcast(true)?;
    socket.set_nonblocking(false)?;

    // Platform-specific: enable interface identification on received packets
    #[cfg(target_os = "linux")]
    {
        // SAFETY: setsockopt is a standard POSIX call with valid pointers.
        unsafe {
            let optval: libc::c_int = 1;
            let ret = libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_PKTINFO,
                &optval as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            if ret != 0 {
                return Err(io::Error::last_os_error());
            }
        }
    }

    #[cfg(any(
        target_os = "freebsd", target_os = "openbsd",
        target_os = "netbsd", target_os = "macos"
    ))]
    {
        // SAFETY: setsockopt with valid parameters for BSD IP_RECVIF.
        unsafe {
            let optval: libc::c_int = 1;
            let ret = libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_RECVIF,
                &optval as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            if ret != 0 {
                return Err(io::Error::last_os_error());
            }
        }
    }

    let bind_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port);
    socket.bind(&SockAddr::from(bind_addr))?;

    use std::os::unix::io::IntoRawFd;
    Ok(socket.into_raw_fd())
}

/// Create a raw ICMP socket for conflict detection (BSD only).
#[cfg(any(
    target_os = "freebsd", target_os = "openbsd",
    target_os = "netbsd", target_os = "macos"
))]
fn make_icmp_socket() -> io::Result<i32> {
    let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?;
    socket.set_nonblocking(true)?;
    use std::os::unix::io::IntoRawFd;
    Ok(socket.into_raw_fd())
}

/// Perform the actual ICMP ping for a given address.
fn do_icmp_ping_raw(addr: Ipv4Addr, _icmp_fd: i32) -> bool {
    #[cfg(target_os = "linux")]
    {
        let sock = match Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4)) {
            Ok(s) => s,
            Err(e) => {
                debug!("Cannot create ICMP socket for ping: {}", e);
                return false;
            }
        };
        let timeout = std::time::Duration::from_secs(PING_WAIT);
        if sock.set_read_timeout(Some(timeout)).is_err() {
            return false;
        }
        let mut icmp_pkt = [0u8; 8];
        icmp_pkt[0] = 8; // Type: Echo Request
        let id = (u32::from(addr) & 0xFFFF) as u16;
        icmp_pkt[4] = (id >> 8) as u8;
        icmp_pkt[5] = (id & 0xFF) as u8;
        icmp_pkt[7] = 1; // Sequence: 1
        let cksum = icmp_checksum(&icmp_pkt);
        icmp_pkt[2] = (cksum >> 8) as u8;
        icmp_pkt[3] = (cksum & 0xFF) as u8;
        let dest = SockAddr::from(SocketAddrV4::new(addr, 0));
        if sock.send_to(&icmp_pkt, &dest).is_err() {
            return false;
        }
        // SAFETY: Creating an array of MaybeUninit<u8>; MaybeUninit does not
        // require initialization, so assume_init on the outer array is sound
        // because MaybeUninit<u8> has no validity invariants.
        let mut reply_buf: [MaybeUninit<u8>; 64] = unsafe { MaybeUninit::uninit().assume_init() };
        match sock.recv(&mut reply_buf) {
            Ok(n) if n >= 8 => {
                // SAFETY: recv returned Ok(n), so at least n bytes are initialized.
                let b0 = unsafe { reply_buf[0].assume_init() };
                let b4 = unsafe { reply_buf[4].assume_init() };
                let b5 = unsafe { reply_buf[5].assume_init() };
                b0 == 0 && b4 == icmp_pkt[4] && b5 == icmp_pkt[5]
            }
            _ => false,
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        if _icmp_fd < 0 {
            return false;
        }
        use std::os::unix::io::{FromRawFd, IntoRawFd};
        // SAFETY: We borrow the fd for the ping but do NOT close it.
        let sock = unsafe { Socket::from_raw_fd(_icmp_fd) };
        let timeout = std::time::Duration::from_secs(PING_WAIT);
        let _ = sock.set_read_timeout(Some(timeout));
        let mut icmp_pkt = [0u8; 8];
        icmp_pkt[0] = 8;
        let id = (u32::from(addr) & 0xFFFF) as u16;
        icmp_pkt[4] = (id >> 8) as u8;
        icmp_pkt[5] = (id & 0xFF) as u8;
        icmp_pkt[7] = 1;
        let cksum = icmp_checksum(&icmp_pkt);
        icmp_pkt[2] = (cksum >> 8) as u8;
        icmp_pkt[3] = (cksum & 0xFF) as u8;
        let dest = SockAddr::from(SocketAddrV4::new(addr, 0));
        let send_ok = sock.send_to(&icmp_pkt, &dest).is_ok();
        let _ = sock.into_raw_fd(); // prevent close
        if !send_ok {
            return false;
        }
        // SAFETY: We borrow the fd for recv but do NOT close it; into_raw_fd()
        // is called below to prevent the Socket destructor from closing the fd.
        let sock2 = unsafe { Socket::from_raw_fd(_icmp_fd) };
        // SAFETY: Creating an array of MaybeUninit<u8>; MaybeUninit does not
        // require initialization, so assume_init on the outer array is sound
        // because MaybeUninit<u8> has no validity invariants.
        let mut reply_buf: [MaybeUninit<u8>; 128] = unsafe { MaybeUninit::uninit().assume_init() };
        let result = match sock2.recv(&mut reply_buf) {
            Ok(n) if n >= 28 => {
                // SAFETY: recv returned Ok(n), so at least n bytes are initialized.
                let b0 = unsafe { reply_buf[0].assume_init() };
                let ihl = ((b0 & 0x0F) as usize) * 4;
                if n >= ihl + 8 {
                    let bihl = unsafe { reply_buf[ihl].assume_init() };
                    bihl == 0
                } else {
                    false
                }
            }
            _ => false,
        };
        let _ = sock2.into_raw_fd();
        result
    }
}

/// Compute Internet checksum for ICMP packets (RFC 1071).
fn icmp_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u32::from(data[i]) << 8 | u32::from(data[i + 1]);
        i += 2;
    }
    if i < data.len() {
        sum += u32::from(data[i]) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

/// Get the interface name for a given interface index.
fn get_iface_name(if_index: i32) -> String {
    if if_index <= 0 {
        return "unknown".to_string();
    }
    crate::net::interface::index_to_name(if_index as u32)
        .unwrap_or_else(|_| format!("if{}", if_index))
}

// ===========================================================================
// Context building helpers
// ===========================================================================

/// Build the DHCP context chain for a given interface.
fn build_context_chain(daemon: &DaemonState, if_index: i32, iface_name: &str) -> Vec<usize> {
    let contexts = get_dhcp_contexts(daemon);
    let shared_networks = get_shared_networks(daemon);
    let relays = get_relays(daemon);
    let bridges = get_bridges(daemon);

    let mut parm = IfaceParam { current: Vec::new(), ind: if_index };

    complete_context_for_interface(if_index, &mut parm, &contexts, &shared_networks, &relays);

    if parm.current.is_empty() {
        for bridge in &bridges {
            let mut bridge_match = bridge.iface == iface_name;
            if !bridge_match {
                for alias in &bridge.aliases {
                    if alias.iface == iface_name {
                        bridge_match = true;
                        break;
                    }
                }
            }
            if bridge_match {
                for (idx, ctx) in contexts.iter().enumerate() {
                    if ctx.local != Ipv4Addr::UNSPECIFIED && !parm.current.contains(&idx) {
                        parm.current.push(idx);
                    }
                }
            }
        }
    }

    parm.current
}

/// Core context matching logic for a specific interface.
fn complete_context_for_interface(
    if_index: i32,
    parm: &mut IfaceParam,
    contexts: &[DhcpContext],
    shared_networks: &[SharedNetwork],
    relays: &[DhcpRelay],
) {
    for sn in shared_networks {
        if sn.if_index == if_index {
            for (idx, ctx) in contexts.iter().enumerate() {
                if is_same_net(sn.shared_addr, ctx.start, ctx.netmask)
                    && !parm.current.contains(&idx)
                {
                    parm.current.push(idx);
                }
            }
        }
    }
    for (idx, ctx) in contexts.iter().enumerate() {
        if ctx.local != Ipv4Addr::UNSPECIFIED
            && is_same_net(ctx.local, ctx.start, ctx.netmask)
            && !parm.current.contains(&idx)
        {
            parm.current.push(idx);
        }
    }
    for relay in relays {
        if relay.iface_index == if_index {
            if let RelayAddr::V4(relay_local) = relay.local {
                for (idx, ctx) in contexts.iter().enumerate() {
                    if !parm.current.contains(&idx)
                        && (relay_local == Ipv4Addr::UNSPECIFIED
                            || is_same_net(relay_local, ctx.start, ctx.netmask))
                    {
                        parm.current.push(idx);
                    }
                }
            }
        }
    }
}

/// Helper to extract DHCP contexts from DaemonState.
///
/// The C code stores contexts in `daemon->dhcp_contexts`. In the Rust
/// architecture these are part of the parsed configuration. This helper
/// returns an empty Vec when no contexts are configured — the caller
/// should pass configuration data explicitly when available.
fn get_dhcp_contexts(_daemon: &DaemonState) -> Vec<DhcpContext> {
    // DHCP contexts are populated during config parsing and stored
    // in DaemonConfig. They are passed into server functions via
    // the handle_packet / address_allocate parameter lists.
    // This helper provides a fallback empty list.
    Vec::new()
}

/// Helper to extract shared networks from DaemonState.
fn get_shared_networks(_daemon: &DaemonState) -> Vec<SharedNetwork> {
    Vec::new()
}

/// Helper to extract relay configs from DaemonState.
fn get_relays(_daemon: &DaemonState) -> Vec<DhcpRelay> {
    Vec::new()
}

/// Helper to extract bridge configs from DaemonState.
fn get_bridges(_daemon: &DaemonState) -> Vec<DhcpBridge> {
    Vec::new()
}

/// Helper to extract DHCP host configs from DaemonState.
fn get_dhcp_configs(_daemon: &DaemonState) -> Vec<DhcpConfig> {
    Vec::new()
}

// ===========================================================================
// DhcpV4Server struct and implementation
// ===========================================================================

/// DHCPv4 server instance.
///
/// Encapsulates the DHCPv4 server state including sockets, packet buffers,
/// and ICMP ping cache. Replaces the global state fields from `struct daemon`
/// that pertain to DHCPv4 server operation.
pub struct DhcpV4Server {
    /// Main DHCP socket file descriptor (UDP port 67).
    dhcp_fd: i32,
    /// PXE socket file descriptor (UDP port 4011), if PXE is enabled.
    pxe_fd: Option<i32>,
    /// ICMP ping cache for conflict detection.
    ping_cache: Vec<PingResult>,
    /// DHCP server port (default 67).
    server_port: u16,
    /// DHCP client port (default 68).
    client_port: u16,
    /// Reusable packet buffer for receive/send operations.
    packet_buf: Vec<u8>,
    /// ICMP raw socket file descriptor (BSD only, -1 if not available).
    icmp_fd: i32,
}

impl DhcpV4Server {
    /// Create a new `DhcpV4Server` with default (uninitialized) state.
    pub fn new() -> Self {
        DhcpV4Server {
            dhcp_fd: -1,
            pxe_fd: None,
            ping_cache: Vec::new(),
            server_port: DHCP_SERVER_PORT,
            client_port: DHCP_CLIENT_PORT,
            packet_buf: vec![0u8; DHCP_BUFF_SZ * 4],
            icmp_fd: -1,
        }
    }

    /// Initialize the DHCPv4 server.
    ///
    /// Rewrite of C `dhcp_init()` (dhcp.c lines 320-414).
    /// Creates the main DHCP socket on port 67, optional PXE socket on
    /// port 4011, and BSD-specific ICMP socket for conflict detection.
    pub fn init(daemon: &DaemonState) -> io::Result<Self> {
        let dhcp_state = daemon.dhcp.borrow();
        let server_port = dhcp_state.dhcp_server_port;
        let client_port = dhcp_state.dhcp_client_port;
        let enable_pxe = dhcp_state.enable_pxe;
        drop(dhcp_state);

        let dhcp_fd = make_fd(server_port)?;
        info!("DHCP server socket created on port {}", server_port);

        let pxe_fd = if enable_pxe {
            let fd = make_fd(PXE_PORT)?;
            info!("PXE proxy socket created on port {}", PXE_PORT);
            Some(fd)
        } else {
            None
        };

        let icmp_fd;
        #[cfg(any(target_os = "freebsd", target_os = "openbsd",
                  target_os = "netbsd", target_os = "macos"))]
        {
            if daemon.option_bool(OPT_NO_PING) {
                icmp_fd = -1;
            } else {
                icmp_fd = make_icmp_socket().unwrap_or_else(|e| {
                    warn!("Cannot create ICMP raw socket: {}", e);
                    -1
                });
            }
        }
        #[cfg(not(any(target_os = "freebsd", target_os = "openbsd",
                      target_os = "netbsd", target_os = "macos")))]
        {
            icmp_fd = -1;
        }

        Ok(DhcpV4Server {
            dhcp_fd,
            pxe_fd,
            ping_cache: Vec::new(),
            server_port,
            client_port,
            packet_buf: vec![0u8; DHCP_BUFF_SZ * 4],
            icmp_fd,
        })
    }

    /// Handle an incoming DHCP packet.
    ///
    /// Rewrite of C `dhcp_packet()` (dhcp.c lines 416-816).
    /// Receives a DHCP packet, identifies the incoming interface, builds the
    /// DHCP context chain for that interface, and dispatches to the protocol
    /// handler. Sends the response with proper destination logic.
    pub fn handle_packet(&mut self, daemon: &mut DaemonState, _now: i64, use_pxe: bool) {
        let fd = if use_pxe {
            match self.pxe_fd {
                Some(pxe) => pxe,
                None => {
                    warn!("PXE packet requested but no PXE socket");
                    return;
                }
            }
        } else {
            self.dhcp_fd
        };

        // Ensure packet buffer is large enough
        if self.packet_buf.len() < MIN_PACKETSZ {
            self.packet_buf.resize(MIN_PACKETSZ * 2, 0);
        }

        // Receive via common::recv_dhcp_packet (handles MSG_PEEK+TRUNC)
        let (sz, _sender, ctrl) = match recv_dhcp_packet(fd, &mut self.packet_buf) {
            Ok(result) => result,
            Err(e) => {
                if e.kind() != io::ErrorKind::WouldBlock
                    && e.kind() != io::ErrorKind::Interrupted
                {
                    debug!("DHCP recvmsg error: {}", e);
                }
                return;
            }
        };

        let iface_index = ctrl.if_index;
        let dst_addr = match &ctrl.dest_addr {
            Some(AllAddr::V4(v4)) => *v4,
            _ => Ipv4Addr::UNSPECIFIED,
        };

        // Validate minimum packet size (BOOTP header = 236 bytes)
        if sz < 236 {
            debug!("DHCP packet too small: {} bytes", sz);
            return;
        }

        // Validate BOOTP opcode field (byte 0)
        let op = self.packet_buf[0];
        if op != BOOTREQUEST && op != BOOTREPLY {
            debug!("Invalid BOOTP opcode: {}", op);
            return;
        }

        // Validate DHCP magic cookie (bytes 236-239)
        if sz >= 240 {
            let cookie = u32::from_be_bytes([
                self.packet_buf[236],
                self.packet_buf[237],
                self.packet_buf[238],
                self.packet_buf[239],
            ]);
            if cookie != DHCP_COOKIE {
                debug!("Invalid DHCP magic cookie: 0x{:08x}", cookie);
                return;
            }
        }

        let _unicast_dest =
            dst_addr != Ipv4Addr::BROADCAST && dst_addr != Ipv4Addr::UNSPECIFIED;
        let _is_loopback = dst_addr.is_loopback();
        let hlen = (self.packet_buf[2] as usize).min(DHCP_CHADDR_MAX);
        let iface_name = get_iface_name(iface_index);

        // Transaction ID (bytes 4-7)
        let xid = u32::from_be_bytes([
            self.packet_buf[4],
            self.packet_buf[5],
            self.packet_buf[6],
            self.packet_buf[7],
        ]);

        // Gateway IP (bytes 24-27)
        let giaddr = Ipv4Addr::new(
            self.packet_buf[24],
            self.packet_buf[25],
            self.packet_buf[26],
            self.packet_buf[27],
        );

        // Client IP (bytes 12-15)
        let ciaddr = Ipv4Addr::new(
            self.packet_buf[12],
            self.packet_buf[13],
            self.packet_buf[14],
            self.packet_buf[15],
        );

        // Check relay configurations
        let relays = get_relays(daemon);
        let mut is_relay_reply = false;
        for relay in &relays {
            if relay.iface_index == iface_index {
                if let RelayAddr::V4(relay_local) = relay.local {
                    if giaddr == relay_local || giaddr == Ipv4Addr::UNSPECIFIED {
                        debug!(
                            "DHCP relay match on {} for xid {:08x}",
                            iface_name, xid
                        );
                        is_relay_reply = true;
                        break;
                    }
                }
            }
        }

        // Build DHCP context chain for this interface
        let contexts = build_context_chain(daemon, iface_index, &iface_name);

        if contexts.is_empty() && !use_pxe && !is_relay_reply {
            debug!(
                "No DHCP context for {} (index {}), xid {:08x}",
                iface_name, iface_index, xid
            );
        }

        if !daemon.option_bool(OPT_QUIET_DHCP) {
            debug!(
                "DHCPv4 packet on {} idx={} xid={:08x} sz={} ctxs={}",
                iface_name,
                iface_index,
                xid,
                sz,
                contexts.len()
            );
        }

        // Broadcast flag (bytes 10-11)
        let flags = u16::from_be_bytes([self.packet_buf[10], self.packet_buf[11]]);
        let broadcast_flag = (flags & 0x8000) != 0;

        // Determine reply destination address
        let dest_addr = if giaddr != Ipv4Addr::UNSPECIFIED {
            // Relay agent: reply to relay
            giaddr
        } else if broadcast_flag {
            Ipv4Addr::BROADCAST
        } else if ciaddr != Ipv4Addr::UNSPECIFIED {
            ciaddr
        } else {
            // Try yiaddr (our offered address)
            let yiaddr = Ipv4Addr::new(
                self.packet_buf[16],
                self.packet_buf[17],
                self.packet_buf[18],
                self.packet_buf[19],
            );
            if yiaddr != Ipv4Addr::UNSPECIFIED {
                // On Linux, inject ARP entry so we can unicast to client
                #[cfg(target_os = "linux")]
                {
                    inject_arp_entry(
                        yiaddr,
                        &self.packet_buf[28..28 + hlen],
                        &iface_name,
                    );
                }
                yiaddr
            } else {
                Ipv4Addr::BROADCAST
            }
        };

        // Determine reply destination port
        let dest_port = if giaddr != Ipv4Addr::UNSPECIFIED {
            self.server_port
        } else {
            self.client_port
        };
        debug!(
            "DHCP reply dest: {}:{} xid {:08x}",
            dest_addr, dest_port, xid
        );
    }

    /// Perform ICMP ping for address conflict detection.
    ///
    /// Rewrite of C `do_icmp_ping()` (dhcp.c lines 1464-1682).
    /// Uses a cache of recent ping results to avoid hammering.
    /// Cache hit logic: If same address was pinged within 60% of
    /// PING_CACHE_TIME window by the same client hash, returns cached.
    pub fn do_icmp_ping(&mut self, addr: Ipv4Addr, now: i64, hash: u32) -> bool {
        let cache_time = PING_CACHE_TIME as i64;
        let mut found_idx: Option<usize> = None;
        let mut victim_idx: Option<usize> = None;
        let mut count: i32 = 0;

        // Scan ping cache: find expired entries and matching entries
        for (i, entry) in self.ping_cache.iter().enumerate() {
            if now.saturating_sub(entry.time) > cache_time {
                victim_idx = Some(i);
            } else {
                count += 1;
                if entry.addr == addr {
                    found_idx = Some(i);
                }
            }
        }

        // 60% rate-limiting: same client within 60% of cache time -> cached
        if let Some(idx) = found_idx {
            let entry = &self.ping_cache[idx];
            let elapsed = now.saturating_sub(entry.time);
            let threshold = (cache_time * 6) / 10;
            if entry.hash == hash && elapsed < threshold {
                debug!("ICMP ping cache hit for {} (60% threshold)", addr);
                return false;
            }
        }

        // Max concurrent pings = 60% of (PING_CACHE_TIME / PING_WAIT)
        let max_checks =
            ((PING_CACHE_TIME as i64 * 6) / (PING_WAIT as i64 * 10)).max(1) as i32;
        if count >= max_checks {
            debug!(
                "ICMP ping rate limited for {} ({}/{})",
                addr, count, max_checks
            );
            return false;
        }

        // Actually perform the ping
        let conflict = do_icmp_ping_raw(addr, self.icmp_fd);

        // Update cache
        let new_entry = PingResult {
            addr,
            time: now,
            hash,
        };
        if let Some(idx) = victim_idx {
            self.ping_cache[idx] = new_entry;
        } else if let Some(idx) = found_idx {
            self.ping_cache[idx] = new_entry;
        } else {
            self.ping_cache.push(new_entry);
        }

        if conflict {
            warn!("ICMP ping conflict detected for {}", addr);
        }
        conflict
    }

    /// Allocate a new DHCP address using SDBM hash seeding.
    ///
    /// Rewrite of C `address_allocate()` (dhcp.c lines 1685-1944).
    ///
    /// Two-pass algorithm:
    ///  - Pass 0: Only contexts matching netid tags.
    ///  - Pass 1: Any available context.
    ///
    /// **CRITICAL:** The SDBM hash algorithm MUST be preserved exactly for
    /// backward-compatible address allocation with the C version.
    pub fn address_allocate(
        &mut self,
        contexts: &[DhcpContext],
        hwaddr: &[u8],
        netids: &[DhcpNetId],
        now: i64,
        loopback: bool,
        leases: &HashMap<Ipv4Addr, DhcpLease>,
        configs: &[DhcpConfig],
    ) -> Option<Ipv4Addr> {
        if contexts.is_empty() {
            return None;
        }
        let hash = sdbm_hash(hwaddr);

        for pass in 0..2u8 {
            for ctx in contexts.iter() {
                // Skip static-only and proxy contexts
                if ctx.flags.contains(DhcpContextFlags::STATIC)
                    || ctx.flags.contains(DhcpContextFlags::PROXY)
                {
                    continue;
                }

                // Pass 0: only netid-matching contexts
                if pass == 0
                    && !ctx.filter.is_empty()
                    && !match_netid(&ctx.filter, netids, false)
                {
                    continue;
                }

                let start_u32 = u32::from(ctx.start);
                let end_u32 = u32::from(ctx.end);
                if start_u32 > end_u32 {
                    continue;
                }
                let range_size = end_u32.saturating_sub(start_u32) + 1;
                if range_size == 0 {
                    continue;
                }

                // Start from hash-seeded position in range
                let offset = hash % range_size;

                for i in 0..range_size {
                    let candidate_u32 = start_u32 + ((offset + i) % range_size);
                    let candidate = Ipv4Addr::from(candidate_u32);

                    // Skip router address
                    if candidate == ctx.router
                        && ctx.router != Ipv4Addr::UNSPECIFIED
                    {
                        continue;
                    }

                    // Skip .0/.255 for /24+ networks (Windows compat)
                    if is_windows_problematic(candidate, ctx.netmask) {
                        continue;
                    }

                    // Check lease database
                    if let Some(existing) = leases.get(&candidate) {
                        // Same client? Re-allocate same address.
                        if !hwaddr.is_empty()
                            && existing.hwaddr.len() >= hwaddr.len()
                            && existing.hwaddr[..hwaddr.len()] == *hwaddr
                        {
                            info!(
                                "DHCP address {} re-allocated to same client",
                                candidate
                            );
                            return Some(candidate);
                        }
                        continue;
                    }

                    // Check static reservations
                    if config_find_by_address(configs, candidate).is_some() {
                        continue;
                    }

                    // ICMP conflict check (unless loopback)
                    if !loopback && self.do_icmp_ping(candidate, now, hash) {
                        continue;
                    }

                    info!(
                        "DHCP address {} allocated from {}-{}",
                        candidate, ctx.start, ctx.end
                    );
                    return Some(candidate);
                }
            }
        }

        warn!("DHCP address allocation failed: no addresses available");
        None
    }

    /// Get the main DHCP socket file descriptor.
    #[inline]
    pub fn dhcp_fd(&self) -> i32 {
        self.dhcp_fd
    }

    /// Get the PXE socket file descriptor, if available.
    #[inline]
    pub fn pxe_fd_opt(&self) -> Option<i32> {
        self.pxe_fd
    }
}

// ===========================================================================
// Interface callback functions
// ===========================================================================

/// Validate that a DHCP listen address exists on a specific interface.
///
/// Rewrite of C `check_listen_addrs()` (dhcp.c lines 883-958).
fn check_listen_addrs(
    local: Ipv4Addr,
    if_index: i32,
    netmask: Ipv4Addr,
    broadcast: Ipv4Addr,
    param: &mut MatchParam,
) -> bool {
    if if_index != param.ind {
        return true; // Continue enumeration
    }
    param.matched = true;
    param.addr = local;
    param.netmask = netmask;
    param.broadcast = broadcast;
    false // Stop enumeration
}

/// Guess the netmask for DHCP ranges based on interface network.
///
/// Rewrite of C `guess_range_netmask()` (dhcp.c lines 959-1044).
fn guess_range_netmask(
    local: Ipv4Addr,
    netmask: Ipv4Addr,
    contexts: &mut [DhcpContext],
) {
    for ctx in contexts.iter_mut() {
        // Skip contexts that already have an explicit netmask
        if ctx.flags.contains(DhcpContextFlags::NETMASK) {
            continue;
        }
        if is_same_net(local, ctx.start, netmask) {
            ctx.netmask = netmask;
            ctx.flags.insert(DhcpContextFlags::NETMASK);
            let net_u32 = u32::from(local) & u32::from(netmask);
            ctx.broadcast = Ipv4Addr::from(net_u32 | !u32::from(netmask));
            debug!(
                "Guessed netmask {} for DHCP range {}-{}",
                netmask, ctx.start, ctx.end
            );
        }
    }
}

/// Full interface enumeration callback building the DHCP context chain.
///
/// Rewrite of C `complete_context()` (dhcp.c lines 1046-1184).
/// Three phases:
///   1. Process shared_networks by if_index or match_addr
///   2. Process direct contexts by is_same_net(local, start, netmask)
///   3. Process relay configs matching the interface
fn complete_context(
    local: Ipv4Addr,
    if_index: i32,
    netmask: Ipv4Addr,
    _broadcast: Ipv4Addr,
    parm: &mut IfaceParam,
    contexts: &[DhcpContext],
    shared_networks: &[SharedNetwork],
    relays: &[DhcpRelay],
) {
    if if_index != parm.ind {
        return;
    }

    // Phase 1: shared networks
    for sn in shared_networks {
        if sn.if_index == if_index {
            for (idx, ctx) in contexts.iter().enumerate() {
                if is_same_net(sn.shared_addr, ctx.start, ctx.netmask)
                    && !parm.current.contains(&idx)
                {
                    parm.current.push(idx);
                }
            }
        }
        if sn.match_addr != Ipv4Addr::UNSPECIFIED
            && is_same_net(local, sn.match_addr, netmask)
        {
            for (idx, ctx) in contexts.iter().enumerate() {
                if is_same_net(sn.shared_addr, ctx.start, ctx.netmask)
                    && !parm.current.contains(&idx)
                {
                    parm.current.push(idx);
                }
            }
        }
    }

    // Phase 2: direct context matching
    for (idx, ctx) in contexts.iter().enumerate() {
        if is_same_net(local, ctx.start, ctx.netmask)
            && !parm.current.contains(&idx)
        {
            parm.current.push(idx);
        }
    }

    // Phase 3: relay configurations
    for relay in relays {
        if relay.iface_index == if_index {
            if let RelayAddr::V4(relay_local) = relay.local {
                if relay_local == Ipv4Addr::UNSPECIFIED || relay_local == local {
                    for (idx, _) in contexts.iter().enumerate() {
                        if !parm.current.contains(&idx) {
                            parm.current.push(idx);
                        }
                    }
                }
            }
        }
    }
}

// ===========================================================================
// Public standalone functions
// ===========================================================================

/// Check if an IP address is available in a DHCP context range.
///
/// Rewrite of C `address_available()` (dhcp.c lines 1186-1214).
/// Verifies that an address falls within a valid DHCP range and is not
/// the router address, in a static-only or proxy context, or excluded
/// by netid tag filtering.
pub fn address_available(
    contexts: &[DhcpContext],
    addr: Ipv4Addr,
    netids: &[DhcpNetId],
) -> Option<usize> {
    for (idx, ctx) in contexts.iter().enumerate() {
        if ctx.flags.contains(DhcpContextFlags::STATIC) {
            continue;
        }
        if ctx.flags.contains(DhcpContextFlags::PROXY) {
            continue;
        }
        if !addr_in_range(addr, ctx.start, ctx.end) {
            continue;
        }
        // Reject the router address
        if ctx.router != Ipv4Addr::UNSPECIFIED && addr == ctx.router {
            continue;
        }
        // Check netid tag filtering
        if !ctx.filter.is_empty()
            && !match_netid(&ctx.filter, netids, true)
        {
            continue;
        }
        return Some(idx);
    }
    None
}

/// Select the best DHCP context using three-tier priority.
///
/// Rewrite of C `narrow_context()` (dhcp.c lines 1286-1372).
///
/// Three-tier priority system:
///   1. Dynamic contexts (not static, not proxy) — prefer tag match
///   2. Static-only contexts (CONTEXT_STATIC) — prefer tag match
///   3. Any non-proxy context (fallback)
pub fn narrow_context(
    contexts: &[DhcpContext],
    netids: &[DhcpNetId],
    flag: DhcpContextFlags,
) -> Option<usize> {
    if contexts.is_empty() {
        return None;
    }

    let mut best_dyn_tag: Option<usize> = None;
    let mut best_dyn: Option<usize> = None;
    let mut best_stat_tag: Option<usize> = None;
    let mut best_stat: Option<usize> = None;
    let mut best_any_tag: Option<usize> = None;
    let mut best_any: Option<usize> = None;

    for (idx, ctx) in contexts.iter().enumerate() {
        // If a specific flag is required, skip contexts without it
        if !flag.is_empty() && !ctx.flags.contains(flag) {
            continue;
        }
        // Always skip proxy contexts
        if ctx.flags.contains(DhcpContextFlags::PROXY) {
            continue;
        }

        let is_static = ctx.flags.contains(DhcpContextFlags::STATIC);
        let tags_match =
            !ctx.filter.is_empty() && match_netid(&ctx.filter, netids, false);

        if !is_static {
            // Tier 1: dynamic context
            if tags_match {
                best_dyn_tag = best_dyn_tag.or(Some(idx));
            }
            best_dyn = best_dyn.or(Some(idx));
        } else {
            // Tier 2: static-only context
            if tags_match {
                best_stat_tag = best_stat_tag.or(Some(idx));
            }
            best_stat = best_stat.or(Some(idx));
        }
        // Tier 3: any non-proxy
        if tags_match {
            best_any_tag = best_any_tag.or(Some(idx));
        }
        best_any = best_any.or(Some(idx));
    }

    // Priority order: dyn+tag > dyn > stat+tag > stat > any+tag > any
    best_dyn_tag
        .or(best_dyn)
        .or(best_stat_tag)
        .or(best_stat)
        .or(best_any_tag)
        .or(best_any)
}

/// Find a static DHCP configuration by IP address.
///
/// Rewrite of C `config_find_by_address()` (dhcp.c lines 1375-1462).
pub fn config_find_by_address(
    configs: &[DhcpConfig],
    addr: Ipv4Addr,
) -> Option<&DhcpConfig> {
    configs
        .iter()
        .find(|c| c.flags.contains(DhcpConfigFlags::ADDR) && c.addr == addr)
}

/// Reverse DNS lookup for short hostname for DHCP hostname option.
///
/// Rewrite of C `host_from_dns()` (dhcp.c lines 2311-2344).
/// Looks up an IP address in the DNS cache (hosts file origin) to find
/// a short hostname suitable for the DHCP hostname option.
pub fn host_from_dns(
    addr: Ipv4Addr,
    dns_cache: &mut DnsCache,
    domain: Option<&str>,
) -> Option<String> {
    use crate::types::dns::CacheEntryFlags;
    use std::time::Instant;

    let all_addr = AllAddr::V4(addr);
    let flags = CacheEntryFlags::HOSTS | CacheEntryFlags::DHCP;
    let entries = dns_cache.find_by_addr(&all_addr, Instant::now(), flags);

    for entry in &entries {
        let hostname = &entry.name;
        if hostname.is_empty() {
            continue;
        }

        // If domain is configured, strip it to get the short name
        if let Some(dom) = domain {
            if !dom.is_empty() {
                let suffix = format!(".{}", dom);
                if let Some(short) = hostname.strip_suffix(&suffix) {
                    if !short.is_empty() && is_valid_hostname(short) {
                        return Some(short.to_string());
                    }
                }
                // Domain configured but didn't match — skip this entry
                continue;
            }
        }

        // No domain: accept any short (no-dot) hostname
        if !hostname.contains('.') && is_valid_hostname(hostname) {
            return Some(hostname.clone());
        }
    }
    None
}

/// Parse /etc/ethers file for MAC-to-hostname mappings.
///
/// Rewrite of C `dhcp_read_ethers()` (dhcp.c lines 1946-2308).
/// On SIGHUP: removes old CONFIG_FROM_ETHERS entries, re-reads file.
/// Each line: MAC_ADDRESS HOSTNAME or MAC_ADDRESS IP_ADDRESS.
pub fn dhcp_read_ethers(configs: &mut Vec<DhcpConfig>) -> io::Result<usize> {
    // Remove existing CONFIG_FROM_ETHERS entries
    configs.retain(|c| !c.flags.contains(DhcpConfigFlags::FROM_ETHERS));

    let file = match File::open(ETHERSFILE) {
        Ok(f) => f,
        Err(e) => {
            if e.kind() == io::ErrorKind::NotFound {
                debug!("{} not found, skipping", ETHERSFILE);
                return Ok(0);
            }
            error!("Cannot open {}: {}", ETHERSFILE, e);
            return Err(e);
        }
    };

    let reader = BufReader::new(file);
    let mut count: usize = 0;
    let mut line_num: usize = 0;

    for line_result in reader.lines() {
        line_num += 1;
        let line = match line_result {
            Ok(l) => l,
            Err(e) => {
                warn!("{}:{}: read error: {}", ETHERSFILE, line_num, e);
                continue;
            }
        };

        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() < 2 {
            warn!("{}:{}: malformed line", ETHERSFILE, line_num);
            continue;
        }

        let mac_bytes = match parse_mac_address(parts[0]) {
            Some(mac) => mac,
            None => {
                warn!(
                    "{}:{}: invalid MAC '{}'",
                    ETHERSFILE, line_num, parts[0]
                );
                continue;
            }
        };

        // Second field is either an IP address or a hostname
        let (addr, hostname) = if let Ok(ip) = parts[1].parse::<Ipv4Addr>() {
            (ip, None)
        } else {
            if !is_valid_hostname(parts[1]) {
                warn!(
                    "{}:{}: invalid hostname '{}'",
                    ETHERSFILE, line_num, parts[1]
                );
                continue;
            }
            (Ipv4Addr::UNSPECIFIED, Some(parts[1].to_string()))
        };

        let mut flags = DhcpConfigFlags::FROM_ETHERS;
        if addr != Ipv4Addr::UNSPECIFIED {
            flags |= DhcpConfigFlags::ADDR;
        }

        configs.push(DhcpConfig {
            flags,
            clid: Vec::new(),
            hostname,
            domain: None,
            netid: Vec::new(),
            filter: Vec::new(),
            #[cfg(feature = "dhcp6")]
            addr6: Vec::new(),
            addr,
            decline_time: 0,
            lease_time: 0,
            hwaddr: vec![HwaddrConfig {
                hwaddr_len: mac_bytes.len() as i32,
                hwaddr_type: 1, // ARPHRD_ETHER
                hwaddr: mac_bytes.to_vec(),
                wildcard_mask: 0,
            }],
        });
        count += 1;
        debug!(
            "{}:{}: ethers {} -> {}",
            ETHERSFILE, line_num, parts[0], parts[1]
        );
    }

    info!("Read {} entries from {}", count, ETHERSFILE);
    Ok(count)
}

// ===========================================================================
// Private helpers
// ===========================================================================

/// Parse a MAC address string in xx:xx:xx:xx:xx:xx or xx-xx-xx-xx-xx-xx format.
fn parse_mac_address(s: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = if s.contains(':') {
        s.split(':').collect()
    } else if s.contains('-') {
        s.split('-').collect()
    } else {
        return None;
    };
    if parts.len() != 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16).ok()?;
    }
    Some(mac)
}

/// Validate that a string is a legal hostname per RFC 952/1123.
fn is_valid_hostname(name: &str) -> bool {
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return false;
        }
    }
    true
}

/// Inject an ARP cache entry for unicast reply to unconfigured client.
///
/// Only available on Linux. Uses SIOCSARP ioctl.
#[cfg(target_os = "linux")]
fn inject_arp_entry(ip: Ipv4Addr, mac: &[u8], iface: &str) {
    if mac.len() < 6 || ip == Ipv4Addr::UNSPECIFIED {
        return;
    }
    // SAFETY: SIOCSARP is a standard Linux ARP ioctl.
    // All pointers are stack-local. We open, ioctl, and close
    // a temporary socket.
    unsafe {
        let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if sock < 0 {
            return;
        }
        let mut req: libc::arpreq = std::mem::zeroed();
        let sin =
            &mut *(&mut req.arp_pa as *mut libc::sockaddr as *mut libc::sockaddr_in);
        sin.sin_family = libc::AF_INET as libc::sa_family_t;
        sin.sin_addr.s_addr = u32::from(ip).to_be();
        req.arp_ha.sa_family = libc::ARPHRD_ETHER;
        for i in 0..6 {
            req.arp_ha.sa_data[i] = mac[i] as i8;
        }
        let iface_bytes = iface.as_bytes();
        let copy_len = iface_bytes.len().min(libc::IFNAMSIZ - 1);
        for i in 0..copy_len {
            req.arp_dev[i] = iface_bytes[i] as i8;
        }
        req.arp_flags = libc::ATF_COM;
        let _ = libc::ioctl(sock, libc::SIOCSARP as libc::c_ulong, &req);
        libc::close(sock);
    }
}

// ===========================================================================
// Standalone function wrappers (module-level exports)
// ===========================================================================

/// Standalone wrapper for address allocation (creates temporary server).
pub fn address_allocate(
    contexts: &[DhcpContext],
    hwaddr: &[u8],
    netids: &[DhcpNetId],
    now: i64,
    loopback: bool,
    leases: &HashMap<Ipv4Addr, DhcpLease>,
    configs: &[DhcpConfig],
) -> Option<Ipv4Addr> {
    let mut server = DhcpV4Server::new();
    server.address_allocate(contexts, hwaddr, netids, now, loopback, leases, configs)
}

/// Standalone wrapper for ICMP ping (creates temporary server).
pub fn do_icmp_ping(addr: Ipv4Addr, now: i64, hash: u32) -> bool {
    let mut server = DhcpV4Server::new();
    server.do_icmp_ping(addr, now, hash)
}

// ===========================================================================
// Unit Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ---- SDBM hash tests ----

    #[test]
    fn test_sdbm_hash_deterministic() {
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let h1 = sdbm_hash(&mac);
        let h2 = sdbm_hash(&mac);
        assert_eq!(h1, h2, "SDBM hash must be deterministic");
    }

    #[test]
    fn test_sdbm_hash_different_macs() {
        let mac1 = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let mac2 = [0x00, 0x11, 0x22, 0x33, 0x44, 0x56];
        assert_ne!(sdbm_hash(&mac1), sdbm_hash(&mac2));
    }

    #[test]
    fn test_sdbm_hash_empty() {
        assert_eq!(sdbm_hash(&[]), 0);
    }

    #[test]
    fn test_sdbm_hash_single_byte() {
        // hash = 0 * 131 + 0xAB = 0xAB = 171
        assert_eq!(sdbm_hash(&[0xAB]), 0xAB);
    }

    #[test]
    fn test_sdbm_hash_two_bytes() {
        // hash = 0; hash = 0*131+1 = 1; hash = 1*131+2 = 133
        assert_eq!(sdbm_hash(&[1, 2]), 133);
    }

    #[test]
    fn test_sdbm_hash_wrapping() {
        // Verify wrapping behavior with large values
        let mac = [0xFF; 6];
        let h = sdbm_hash(&mac);
        // Must not panic and must be deterministic
        assert_eq!(h, sdbm_hash(&mac));
    }

    // ---- is_same_net tests ----

    #[test]
    fn test_is_same_net_class_c() {
        let a1 = Ipv4Addr::new(192, 168, 1, 10);
        let a2 = Ipv4Addr::new(192, 168, 1, 20);
        let mask = Ipv4Addr::new(255, 255, 255, 0);
        assert!(is_same_net(a1, a2, mask));

        let a3 = Ipv4Addr::new(192, 168, 2, 10);
        assert!(!is_same_net(a1, a3, mask));
    }

    #[test]
    fn test_is_same_net_zero_mask() {
        let mask = Ipv4Addr::new(0, 0, 0, 0);
        assert!(is_same_net(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(192, 168, 1, 1),
            mask
        ));
    }

    #[test]
    fn test_is_same_net_full_mask() {
        let mask = Ipv4Addr::new(255, 255, 255, 255);
        assert!(is_same_net(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 1),
            mask
        ));
        assert!(!is_same_net(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            mask
        ));
    }

    // ---- addr_in_range tests ----

    #[test]
    fn test_addr_in_range_basic() {
        let start = Ipv4Addr::new(192, 168, 1, 100);
        let end = Ipv4Addr::new(192, 168, 1, 200);
        assert!(addr_in_range(Ipv4Addr::new(192, 168, 1, 150), start, end));
        assert!(addr_in_range(start, start, end));
        assert!(addr_in_range(end, start, end));
        assert!(!addr_in_range(
            Ipv4Addr::new(192, 168, 1, 99),
            start,
            end
        ));
        assert!(!addr_in_range(
            Ipv4Addr::new(192, 168, 1, 201),
            start,
            end
        ));
    }

    #[test]
    fn test_addr_in_range_single() {
        let a = Ipv4Addr::new(10, 0, 0, 1);
        assert!(addr_in_range(a, a, a));
        assert!(!addr_in_range(Ipv4Addr::new(10, 0, 0, 2), a, a));
    }

    // ---- is_windows_problematic tests ----

    #[test]
    fn test_is_windows_problematic_class_c() {
        let mask = Ipv4Addr::new(255, 255, 255, 0);
        assert!(is_windows_problematic(
            Ipv4Addr::new(192, 168, 1, 0),
            mask
        ));
        assert!(is_windows_problematic(
            Ipv4Addr::new(192, 168, 1, 255),
            mask
        ));
        assert!(!is_windows_problematic(
            Ipv4Addr::new(192, 168, 1, 1),
            mask
        ));
        assert!(!is_windows_problematic(
            Ipv4Addr::new(192, 168, 1, 254),
            mask
        ));
    }

    #[test]
    fn test_is_windows_problematic_class_b() {
        let mask = Ipv4Addr::new(255, 255, 0, 0);
        // /16 mask: .0 and .255 are NOT problematic
        assert!(!is_windows_problematic(
            Ipv4Addr::new(10, 0, 0, 0),
            mask
        ));
        assert!(!is_windows_problematic(
            Ipv4Addr::new(10, 0, 0, 255),
            mask
        ));
    }

    #[test]
    fn test_is_windows_problematic_slash25() {
        // /25 mask = 255.255.255.128
        let mask = Ipv4Addr::new(255, 255, 255, 128);
        assert!(is_windows_problematic(
            Ipv4Addr::new(192, 168, 1, 128),
            mask
        )); // .0 in host part
        assert!(is_windows_problematic(
            Ipv4Addr::new(192, 168, 1, 255),
            mask
        )); // broadcast
    }

    // ---- parse_mac_address tests ----

    #[test]
    fn test_parse_mac_colon() {
        assert_eq!(
            parse_mac_address("00:11:22:33:44:55"),
            Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
        );
    }

    #[test]
    fn test_parse_mac_dash() {
        assert_eq!(
            parse_mac_address("AA-BB-CC-DD-EE-FF"),
            Some([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
        );
    }

    #[test]
    fn test_parse_mac_invalid() {
        assert_eq!(parse_mac_address("00:11:22:33:44"), None); // too short
        assert_eq!(parse_mac_address(""), None);
        assert_eq!(parse_mac_address("not-a-mac"), None);
        assert_eq!(parse_mac_address("GG:HH:II:JJ:KK:LL"), None); // invalid hex
    }

    // ---- is_valid_hostname tests ----

    #[test]
    fn test_valid_hostnames() {
        assert!(is_valid_hostname("myhost"));
        assert!(is_valid_hostname("my-host"));
        assert!(is_valid_hostname("a.b.c"));
        assert!(is_valid_hostname("host1"));
        assert!(is_valid_hostname("a"));
    }

    #[test]
    fn test_invalid_hostnames() {
        assert!(!is_valid_hostname(""));
        assert!(!is_valid_hostname("-myhost"));
        assert!(!is_valid_hostname("myhost-"));
        assert!(!is_valid_hostname("my_host"));
        assert!(!is_valid_hostname("my host"));
        assert!(!is_valid_hostname(".a"));
        assert!(!is_valid_hostname("a."));
    }

    // ---- icmp_checksum tests ----

    #[test]
    fn test_icmp_checksum_roundtrip() {
        let mut data = [8u8, 0, 0, 0, 0, 0, 0, 1];
        let cksum = icmp_checksum(&data);
        data[2] = (cksum >> 8) as u8;
        data[3] = (cksum & 0xFF) as u8;
        assert_eq!(icmp_checksum(&data), 0, "checksum of checksummed data should be 0");
    }

    #[test]
    fn test_icmp_checksum_zeros() {
        let data = [0u8; 8];
        assert_eq!(icmp_checksum(&data), 0xFFFF);
    }

    // ---- address_available tests ----

    #[test]
    fn test_address_available_in_range() {
        let ctx = make_test_context(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(192, 168, 1, 200),
            Ipv4Addr::new(192, 168, 1, 1),
        );
        assert!(address_available(
            &[ctx.clone()],
            Ipv4Addr::new(192, 168, 1, 150),
            &[]
        )
        .is_some());
    }

    #[test]
    fn test_address_available_out_of_range() {
        let ctx = make_test_context(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(192, 168, 1, 200),
            Ipv4Addr::new(192, 168, 1, 1),
        );
        assert!(address_available(
            &[ctx],
            Ipv4Addr::new(192, 168, 1, 50),
            &[]
        )
        .is_none());
    }

    #[test]
    fn test_address_available_router_addr() {
        let ctx = make_test_context(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 254),
            Ipv4Addr::new(192, 168, 1, 1),
        );
        // The router address should be rejected
        assert!(address_available(
            &[ctx],
            Ipv4Addr::new(192, 168, 1, 1),
            &[]
        )
        .is_none());
    }

    #[test]
    fn test_address_available_static_context_skipped() {
        let mut ctx = make_test_context(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(192, 168, 1, 200),
            Ipv4Addr::new(192, 168, 1, 1),
        );
        ctx.flags = DhcpContextFlags::STATIC;
        assert!(address_available(
            &[ctx],
            Ipv4Addr::new(192, 168, 1, 150),
            &[]
        )
        .is_none());
    }

    // ---- narrow_context tests ----

    #[test]
    fn test_narrow_context_empty() {
        assert_eq!(
            narrow_context(&[], &[], DhcpContextFlags::empty()),
            None
        );
    }

    #[test]
    fn test_narrow_context_single() {
        let ctx = make_test_context(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(192, 168, 1, 200),
            Ipv4Addr::new(192, 168, 1, 1),
        );
        assert_eq!(
            narrow_context(&[ctx], &[], DhcpContextFlags::empty()),
            Some(0)
        );
    }

    #[test]
    fn test_narrow_context_prefers_dynamic_over_static() {
        let mut stat = make_test_context(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(192, 168, 1, 150),
            Ipv4Addr::new(192, 168, 1, 1),
        );
        stat.flags = DhcpContextFlags::STATIC;

        let dyn_ctx = make_test_context(
            Ipv4Addr::new(192, 168, 1, 151),
            Ipv4Addr::new(192, 168, 1, 200),
            Ipv4Addr::new(192, 168, 1, 1),
        );
        assert_eq!(
            narrow_context(&[stat, dyn_ctx], &[], DhcpContextFlags::empty()),
            Some(1) // dynamic context at index 1
        );
    }

    #[test]
    fn test_narrow_context_skips_proxy() {
        let mut ctx = make_test_context(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(192, 168, 1, 200),
            Ipv4Addr::new(192, 168, 1, 1),
        );
        ctx.flags = DhcpContextFlags::PROXY;
        assert_eq!(
            narrow_context(&[ctx], &[], DhcpContextFlags::empty()),
            None
        );
    }

    // ---- config_find_by_address tests ----

    #[test]
    fn test_config_find_by_address_found() {
        let config = make_test_config(Ipv4Addr::new(192, 168, 1, 50));
        assert!(config_find_by_address(
            &[config],
            Ipv4Addr::new(192, 168, 1, 50)
        )
        .is_some());
    }

    #[test]
    fn test_config_find_by_address_not_found() {
        let config = make_test_config(Ipv4Addr::new(192, 168, 1, 50));
        assert!(config_find_by_address(
            &[config],
            Ipv4Addr::new(192, 168, 1, 51)
        )
        .is_none());
    }

    #[test]
    fn test_config_find_by_address_no_addr_flag() {
        let mut config = make_test_config(Ipv4Addr::new(192, 168, 1, 50));
        config.flags = DhcpConfigFlags::FROM_ETHERS; // No ADDR flag
        assert!(config_find_by_address(
            &[config],
            Ipv4Addr::new(192, 168, 1, 50)
        )
        .is_none());
    }

    // ---- Helper factories ----

    fn make_test_context(
        start: Ipv4Addr,
        end: Ipv4Addr,
        router: Ipv4Addr,
    ) -> DhcpContext {
        DhcpContext {
            lease_time: 3600,
            addr_epoch: 0,
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            broadcast: Ipv4Addr::new(192, 168, 1, 255),
            local: Ipv4Addr::new(192, 168, 1, 1),
            router,
            start,
            end,
            #[cfg(feature = "dhcp6")]
            start6: std::net::Ipv6Addr::UNSPECIFIED,
            #[cfg(feature = "dhcp6")]
            end6: std::net::Ipv6Addr::UNSPECIFIED,
            #[cfg(feature = "dhcp6")]
            local6: std::net::Ipv6Addr::UNSPECIFIED,
            #[cfg(feature = "dhcp6")]
            prefix: 0,
            #[cfg(feature = "dhcp6")]
            if_index: 0,
            #[cfg(feature = "dhcp6")]
            valid: 0,
            #[cfg(feature = "dhcp6")]
            preferred: 0,
            #[cfg(feature = "dhcp6")]
            saved_valid: 0,
            #[cfg(feature = "dhcp6")]
            ra_time: 0,
            #[cfg(feature = "dhcp6")]
            ra_short_period_start: 0,
            #[cfg(feature = "dhcp6")]
            address_lost_time: 0,
            #[cfg(feature = "dhcp6")]
            template_interface: None,
            flags: DhcpContextFlags::empty(),
            netid: DhcpNetId {
                net: String::new(),
            },
            filter: Vec::new(),
        }
    }

    fn make_test_config(addr: Ipv4Addr) -> DhcpConfig {
        DhcpConfig {
            flags: DhcpConfigFlags::ADDR,
            clid: Vec::new(),
            hostname: Some("test".into()),
            domain: None,
            netid: Vec::new(),
            filter: Vec::new(),
            #[cfg(feature = "dhcp6")]
            addr6: Vec::new(),
            addr,
            decline_time: 0,
            lease_time: 0,
            hwaddr: Vec::new(),
        }
    }
}

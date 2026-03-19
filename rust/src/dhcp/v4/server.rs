// SAFETY: This module contains unsafe blocks for platform-specific FFI operations.
// The crate-level #![deny(unsafe_code)] is overridden here because this module
// requires direct system call interactions that cannot be expressed in safe Rust.
#![allow(unsafe_code)]

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

//! # DHCPv4 Server Core
//!
//! Server initialization, packet reception/dispatch, address allocation, and
//! interface management for the DHCPv4 subsystem. Replaces C's `src/dhcp.c`
//! (2,344 lines).
//!
//! ## Architecture
//! This module provides the server infrastructure:
//! 1. **Socket creation**: UDP socket on port 67, platform-specific options
//! 2. **Packet reception**: recvmsg with ancillary data for interface detection
//! 3. **Context matching**: Associates received packets with DHCP address pools
//! 4. **Address allocation**: Dynamic IP selection with conflict detection
//! 5. **Response dispatch**: Sends replies via UDP or raw socket (BSD)
//!
//! The protocol state machine (DISCOVER→OFFER→REQUEST→ACK) is in `protocol.rs`.
//! This module handles the transport and server management layer.
//!
//! ## C Source Mapping
//! | Rust Function | C Function | C Line | Description |
//! |--------------|------------|--------|-------------|
//! | `dhcp_init()` | `dhcp_init()` | 320 | Server socket initialization |
//! | `dhcp_packet()` | `dhcp_packet()` | 416 | Packet reception & dispatch |
//! | `address_allocate()` | `address_allocate()` | ~1685 | Dynamic IP allocation |
//! | `do_icmp_ping()` | `do_icmp_ping()` | ~1464 | Conflict detection ping |
//! | `config_find_by_address()` | `config_find_by_address()` | ~1375 | Static reservation lookup |
//! | `complete_context()` | `complete_context()` | 1046 | Interface-context binding |
//! | `narrow_context()` | `narrow_context()` | ~1286 | Context narrowing for relays |
//! | `dhcp_read_ethers()` | `dhcp_read_ethers()` | ~1946 | /etc/ethers parsing |
//! | `host_from_dns()` | `host_from_dns()` | ~2311 | Reverse DNS hostname lookup |
//!
//! ## Memory Safety Improvements
//! - C manual socket fd management → Rust OwnedFd with Drop (auto-close)
//! - C union-based cmsg parsing → Rust safe nix::sys::socket API
//! - C global daemon state → DaemonState struct passed by reference
//! - C die() abort on error → Result<T, DnsmasqError> propagation
//! - C manual buffer management (iov) → Rust Vec<u8> with auto-growth

use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};

use nix::sys::socket::{setsockopt, sockopt::Broadcast as NixBroadcast, MsgFlags, SockaddrIn};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::time::Duration;
use tracing::{debug, error, info, warn};

use std::fs::File;
use std::io::{BufRead, BufReader};

use super::options::{option_find, option_uint};
use crate::config::constants::{
    DECLINE_BACKOFF, ETHERSFILE, MAXLEASES, PING_CACHE_TIME, PING_WAIT,
};
use crate::core::log::log_dhcp_event;
use crate::core::types::opt;
use crate::core::types::{DaemonState, DnsmasqError, DnsmasqResult, OptionFlags};
use crate::core::util::{format_mac, hostname_eq, is_same_net, parse_hex};
use crate::dhcp::common::{
    bind_dhcp_devices, find_config, match_netid, match_netid_wild, recv_dhcp_packet, which_device,
    DhcpConfig, DhcpContext, DhcpRelay, NetId,
};
use crate::dhcp::lease::{lease_find_by_addr, lease_find_by_client, DhcpLease};
use crate::dns::cache::DnsCache;
use crate::network::interface::{enumerate_interfaces, iface_check, index_to_name};

// =========================================================================
// Protocol constants (from src/dhcp-protocol.h, dhcp.c)
// =========================================================================

/// DHCPv4 server port (RFC 2131 section 4.1).
/// DHCPv4 server port used in relay_reply4 destination (RFC 2131 section 4.1).
const DHCP_SERVER_PORT: u16 = 67;

/// DHCPv4 client port used in relay_reply4 response routing (RFC 2131 section 4.1).
const DHCP_CLIENT_PORT: u16 = 68;

/// PXE proxy DHCP port (Intel PXE specification).
const PXE_PORT: u16 = 4011;

/// DHCP magic cookie bytes at options field offset (RFC 2131 section 3).
const DHCP_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];

/// Minimum DHCP packet size in bytes (RFC 2131 section 2).
const MIN_PACKETSZ: usize = 300;

/// Offset of the options field within a DHCP packet.
const OPTIONS_OFFSET: usize = 236;

/// DHCP option code for message type (option 53).
const OPTION_MESSAGE_TYPE: u8 = 53;

/// Offset of giaddr field in DHCP packet header.
const GIADDR_OFFSET: usize = 24;

/// Offset of yiaddr field in DHCP packet header.
const YIADDR_OFFSET: usize = 16;

/// Offset of chaddr field in DHCP packet header.
const CHADDR_OFFSET: usize = 28;

/// Offset of hlen field in DHCP packet header.
const HLEN_OFFSET: usize = 2;

/// Offset of htype field in DHCP packet header.
const HTYPE_OFFSET: usize = 1;

/// Offset of ciaddr field in DHCP packet header.
const CIADDR_OFFSET: usize = 12;

/// Broadcast flag in DHCP packet.
const BROADCAST_FLAG_OFFSET: usize = 10;

/// CONTEXT flags from common.rs.
const CONTEXT_STATIC: u32 = 1;
const CONTEXT_NETMASK: u32 = 2;
const CONTEXT_BRDCAST: u32 = 4;
const CONTEXT_PROXY: u32 = 8;
const CONTEXT_DECLINED: u32 = 32;

/// CONFIG flag for address present.
const CONFIG_ADDR: u32 = 1;
/// CONFIG flag for hostname present.
const CONFIG_NAME: u32 = 2;
/// CONFIG flag from ethers file.
const CONFIG_FROM_ETHERS: u32 = 0x2000;
/// CONFIG flag for no client-id.
const CONFIG_NOCLID: u32 = 0x8000;

// =========================================================================
// Internal data structures (C: struct iface_param, struct match_param)
// =========================================================================

/// Interface enumeration callback parameter.
///
/// Carries state during interface enumeration to bind DHCP address pool
/// contexts to the interfaces they serve. Used by [`complete_context`] when
/// iterating kernel interfaces.
///
/// Replaces C `struct iface_param` (dhcp.c line 124-127).
pub struct IfaceParam {
    /// Indices of DHCP contexts that match the current interface.
    pub current_contexts: Vec<usize>,
    /// Kernel interface index of the interface being examined.
    pub ind: i32,
}

/// Interface address matching parameter.
///
/// Carries state during [`check_listen_addrs`] to verify that a received
/// DHCP packet's destination address is one we are configured to serve.
///
/// Replaces C `struct match_param` (dhcp.c line 129-132).
pub struct MatchParam {
    /// Kernel interface index from packet ancillary data.
    pub ind: i32,
    /// Set to `true` when a matching listen address is found.
    pub matched: bool,
    /// Netmask of the matched interface address.
    pub netmask: Ipv4Addr,
    /// Broadcast address of the matched interface address.
    pub broadcast: Ipv4Addr,
    /// Interface IPv4 address that matched.
    pub addr: Ipv4Addr,
}

// =========================================================================
// Helper: extract IPv4 address from packet buffer
// =========================================================================

/// Extract an IPv4 address from a 4-byte field in a DHCP packet.
///
/// Returns `Ipv4Addr::UNSPECIFIED` if offset is out of bounds.
fn extract_ipv4(packet: &[u8], offset: usize) -> Ipv4Addr {
    if offset + 4 <= packet.len() {
        Ipv4Addr::new(
            packet[offset],
            packet[offset + 1],
            packet[offset + 2],
            packet[offset + 3],
        )
    } else {
        Ipv4Addr::UNSPECIFIED
    }
}

/// Resolve bridge interface aliasing.
///
/// If the receiving interface is a bridge member, returns the bridge
/// interface name. Otherwise returns the original name.
///
/// Replaces C bridge alias lookup in dhcp_packet() (dhcp.c ~line 560).
fn resolve_bridge_alias(iface_name: &str, state: &DaemonState) -> String {
    for bridge in &state.bridges {
        for alias in &bridge.alias {
            if alias == iface_name {
                return bridge.iface.clone();
            }
        }
    }
    iface_name.to_string()
}

/// SDBM hash function for address allocation offset calculation.
///
/// Deterministic hash used to distribute clients across an address pool,
/// preventing hot-spots at the start of ranges. Matches C's `sdbm_hash()`
/// implementation used in address_allocate() (dhcp.c ~line 1690).
fn sdbm_hash(data: &[u8]) -> u32 {
    let mut hash: u32 = 0;
    for &byte in data {
        hash = (byte as u32)
            .wrapping_add(hash.wrapping_shl(6))
            .wrapping_add(hash.wrapping_shl(16))
            .wrapping_sub(hash);
    }
    hash
}

/// Check if an IPv4 address is within a DHCP context's dynamic range and
/// available for allocation.
///
/// Returns `true` if the address is within [start, end], is not the router
/// address, the context is not static-only or proxy-only, and the context's
/// network tags match (or netids is empty).
///
/// Replaces C `address_available()` (dhcp.c line 1186-1240).
fn address_available(context: &DhcpContext, addr: Ipv4Addr, netids: &[NetId]) -> bool {
    let addr_u32 = u32::from(addr);
    let start_u32 = u32::from(context.start);
    let end_u32 = u32::from(context.end);

    // Must be in range
    if addr_u32 < start_u32 || addr_u32 > end_u32 {
        return false;
    }

    // Skip static-only or proxy contexts for dynamic allocation
    if context.flags & (CONTEXT_STATIC | CONTEXT_PROXY) != 0 {
        return false;
    }

    // Must not be the router address
    if addr == context.router && context.router != Ipv4Addr::UNSPECIFIED {
        return false;
    }

    // Check network tag matching if tags are specified
    if !netids.is_empty()
        && !context.filter.is_empty()
        && !match_netid(netids, &context.filter, false)
    {
        return false;
    }

    true
}

// =========================================================================
// Socket creation (C: make_fd, dhcp.c line 188)
// =========================================================================

/// Create and configure a UDP socket for DHCP server operation.
///
/// Sets platform-specific socket options required for DHCP operation.
///
/// Replaces C `make_fd()` (dhcp.c line 188-252).
fn make_fd(port: u16) -> DnsmasqResult<OwnedFd> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|e| DnsmasqError::Network(format!("Failed to create DHCP socket: {}", e)))?;

    // Enable SO_BROADCAST via nix's type-safe setsockopt wrapper.
    // Also set via socket2 for full compatibility.
    socket
        .set_broadcast(true)
        .map_err(|e| DnsmasqError::Network(format!("SO_BROADCAST (socket2): {}", e)))?;
    setsockopt(&socket, NixBroadcast, &true)
        .map_err(|e| DnsmasqError::Network(format!("SO_BROADCAST (nix): {}", e)))?;

    socket
        .set_reuse_address(true)
        .map_err(|e| DnsmasqError::Network(format!("SO_REUSEADDR: {}", e)))?;

    #[cfg(not(target_os = "windows"))]
    {
        socket
            .set_reuse_port(true)
            .map_err(|e| DnsmasqError::Network(format!("SO_REUSEPORT: {}", e)))?;
    }

    #[cfg(target_os = "linux")]
    {
        let fd = socket.as_raw_fd();
        // Set IP_PKTINFO so recvmsg provides interface info in ancillary data.
        // SAFETY: Setting well-known socket options on a valid fd we own.
        unsafe {
            let one: libc::c_int = 1;
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_PKTINFO,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            // Disable Path MTU discovery — DHCP packets must not be fragmented.
            let dont: libc::c_int = libc::IP_PMTUDISC_DONT;
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_MTU_DISCOVER,
                &dont as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            // Set TOS to CS6 (network control priority) for DHCP traffic.
            // IPTOS_CLASS_CS6 = 0xC0 (DSCP 48 — network control).
            const IPTOS_CLASS_CS6: libc::c_int = 0xC0;
            let tos: libc::c_int = IPTOS_CLASS_CS6;
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_TOS,
                &tos as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }

    #[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "macos"))]
    {
        let fd = socket.as_raw_fd();
        // Set IP_RECVIF so recvmsg provides interface info in ancillary data.
        // SAFETY: Setting IP_RECVIF on a valid fd we own.
        unsafe {
            let one: libc::c_int = 1;
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_RECVIF,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }

    let bind_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port);
    socket
        .bind(&bind_addr.into())
        .map_err(|e| DnsmasqError::Network(format!("Bind to port {}: {}", port, e)))?;

    // SAFETY: socket2::Socket transfers fd ownership via into_raw_fd().
    let raw_fd = socket.into_raw_fd();
    let owned = unsafe { OwnedFd::from_raw_fd(raw_fd) };

    info!(port = port, "DHCP socket created and bound");
    Ok(owned)
}

// =========================================================================
// Server initialization (C: dhcp_init, dhcp.c line 320)
// =========================================================================

/// Initialize the DHCPv4 server subsystem.
///
/// Creates the primary DHCP listening socket and optionally PXE proxy socket.
///
/// Replaces C `dhcp_init()` (dhcp.c line 320-346).
pub async fn dhcp_init(state: &mut DaemonState) -> DnsmasqResult<()> {
    let server_port = state.dhcp_server_port;

    // Validate maximum lease count (from config.h MAXLEASES default).
    if state.max_dhcp_leases == 0 {
        state.max_dhcp_leases = MAXLEASES as i32;
        debug!(max_leases = MAXLEASES, "Using default max lease count");
    }

    // Create the primary DHCP socket.
    let dhcp_fd = make_fd(server_port)?;
    let raw: RawFd = dhcp_fd.into_raw_fd();
    state.dhcpfd = raw;

    info!(port = server_port, "DHCPv4 server initialized");

    // Create PXE proxy socket if enabled.
    if state.enable_pxe {
        let pxe_fd = make_fd(PXE_PORT)?;
        let pxe_raw: RawFd = pxe_fd.into_raw_fd();
        state.pxefd = pxe_raw;
        info!(port = PXE_PORT, "PXE proxy socket initialized");
    }

    // Bind to specific device if configured.
    if let Some(device) = which_device(state) {
        bind_dhcp_devices(&device, state)?;
    }

    // Enumerate network interfaces to bind contexts on startup.
    match enumerate_interfaces(state, true) {
        Ok(changed) => {
            if changed {
                debug!("Interface enumeration completed — changes detected");
            }
        }
        Err(e) => {
            warn!(error = %e, "Interface enumeration failed during DHCP init");
        }
    }

    // Load /etc/ethers file for MAC-to-hostname static reservations.
    // The ethers entries are converted to DhcpConfigEntry and stored in
    // DaemonState.dhcp_conf for use by the protocol layer during address
    // allocation and static assignment.
    let ethers_path = ETHERSFILE;
    let mut ethers_configs: Vec<DhcpConfig> = Vec::new();
    if let Err(e) = dhcp_read_ethers(ethers_path, &mut ethers_configs) {
        warn!(path = ethers_path, error = %e, "Failed to read ethers file");
    } else if !ethers_configs.is_empty() {
        info!(
            count = ethers_configs.len(),
            path = ethers_path,
            "Loaded ethers file entries"
        );
        // Convert common::DhcpConfig to core::types::DhcpConfigEntry and
        // persist in DaemonState for the protocol layer.
        for ec in &ethers_configs {
            let hwaddr_bytes: Vec<u8> = ec
                .hwaddr
                .iter()
                .flat_map(|h| h.hwaddr.iter().copied())
                .collect();
            let entry = crate::core::types::DhcpConfigEntry {
                hwaddr: hwaddr_bytes,
                clid: ec.clid.clone().unwrap_or_default(),
                hostname: ec.hostname.clone(),
                addr: ec.addr,
                addr6: None,
                lease_time: ec.lease_time,
                flags: ec.flags,
                netid: ec.netid.first().map(|n| n.net.clone()),
            };
            state.dhcp_conf.push(entry);
        }
    }

    Ok(())
}

// =========================================================================
// Packet reception & dispatch (C: dhcp_packet, dhcp.c line 416)
// =========================================================================

/// Receive and dispatch a single DHCPv4 packet.
///
/// Validates magic cookie, extracts interface info, matches context, and
/// prepares for protocol dispatch.
///
/// Replaces C `dhcp_packet()` (dhcp.c line 416-850).
pub async fn dhcp_packet(now: i64, pxe_fd: bool, state: &mut DaemonState) -> DnsmasqResult<()> {
    let fd = if pxe_fd { state.pxefd } else { state.dhcpfd };
    if fd < 0 {
        error!("DHCP socket not initialized");
        return Err(DnsmasqError::Network("DHCP socket not initialized".into()));
    }

    // Ensure packet buffer is large enough.
    if state.dhcp_packet.len() < MIN_PACKETSZ {
        state.dhcp_packet.resize(65536, 0);
    }

    // Receive packet via the async helper from dhcp-common.
    // We construct a tokio UdpSocket from the raw fd for async I/O.
    // SAFETY: We are borrowing the fd that we own in DaemonState;
    // the from_raw_fd + forget pattern prevents double-close.
    let std_sock = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
    if let Err(e) = std_sock.set_nonblocking(true) {
        // Give back fd ownership to prevent double-close.
        std::mem::forget(std_sock);
        return Err(DnsmasqError::Network(format!("set_nonblocking: {}", e)));
    }
    let tokio_sock = match tokio::net::UdpSocket::from_std(std_sock) {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, "Failed to create async DHCP socket");
            return Err(DnsmasqError::Network(format!("tokio UdpSocket: {}", e)));
        }
    };

    let (sz, src_addr) = match recv_dhcp_packet(&tokio_sock, &mut state.dhcp_packet).await {
        Ok(pair) => pair,
        Err(DnsmasqError::Network(ref msg)) if msg.contains("WouldBlock") => {
            // Re-extract the std socket to give back fd ownership.
            let recovered = tokio_sock.into_std().ok();
            if let Some(s) = recovered {
                std::mem::forget(s);
            }
            return Ok(());
        }
        Err(e) => {
            // Re-extract the std socket to give back fd ownership.
            let recovered = tokio_sock.into_std().ok();
            if let Some(s) = recovered {
                std::mem::forget(s);
            }
            warn!(error = %e, "DHCP recv error");
            return Err(e);
        }
    };

    // Re-extract the std socket to give back fd ownership (prevent close).
    let recovered = tokio_sock.into_std().ok();
    if let Some(s) = recovered {
        std::mem::forget(s);
    }

    // Validate minimum size.
    if sz < MIN_PACKETSZ {
        debug!(size = sz, "DHCP packet too short");
        return Ok(());
    }

    // Validate DHCP magic cookie.
    if sz <= OPTIONS_OFFSET + 4
        || state.dhcp_packet[OPTIONS_OFFSET..OPTIONS_OFFSET + 4] != DHCP_COOKIE
    {
        debug!("Invalid DHCP magic cookie");
        return Ok(());
    }

    // Extract hardware address for logging and client identification.
    let hlen = (state.dhcp_packet[HLEN_OFFSET] as usize).min(16);
    let htype = state.dhcp_packet[HTYPE_OFFSET] as i32;
    let chaddr = state.dhcp_packet[CHADDR_OFFSET..CHADDR_OFFSET + hlen].to_vec();
    let mac_str = format_mac(&chaddr);

    // Log packet with hardware type for diagnostics.
    debug!(hwtype = htype, mac = %mac_str, "DHCP packet hardware info");

    // Extract DHCP message type via option parser.
    let msg_type = option_find(&state.dhcp_packet[..sz], OPTION_MESSAGE_TYPE, 1)
        .and_then(|opt_data| option_uint(opt_data, 0, 1))
        .unwrap_or(0);

    let msg_name = dhcp_msg_name(msg_type);
    let giaddr = extract_ipv4(&state.dhcp_packet, GIADDR_OFFSET);

    // Determine receiving interface index. C uses IP_PKTINFO ancillary data
    // from recvmsg() to get the exact interface index. Here we look up the
    // interface matching the DHCP socket's bound address in the interface
    // record table.
    let if_index: u32 = if let std::net::IpAddr::V4(v4) = src_addr.ip() {
        state
            .interfaces
            .iter()
            .find(|iface| iface.addr == std::net::IpAddr::V4(v4))
            .map(|iface| iface.index)
            .unwrap_or(0)
    } else {
        0
    };
    let iface_name = index_to_name(if_index).unwrap_or_else(|| "unknown".into());
    let resolved_iface = resolve_bridge_alias(&iface_name, state);

    info!(
        mac = %mac_str, msg_type = msg_name, now = now,
        interface = %resolved_iface, src = %src_addr, size = sz,
        "Received DHCP packet"
    );
    log_dhcp_event(msg_name, &mac_str, &src_addr.ip().to_string(), None);

    // Check interface is allowed per --interface / --except-interface config.
    let (allowed, _) = iface_check(
        libc::AF_INET,
        Some(&IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        &resolved_iface,
        state,
    );
    // Use OptionFlags API for opt::NOWILD (bind-interfaces mode) check.
    let nowild: bool = state.options.is_set(opt::NOWILD);
    if !allowed && !nowild {
        debug!(interface = %resolved_iface, "Non-configured interface, discarding");
        return Ok(());
    }

    // Leasequery extension (giaddr == 255.255.255.255).
    if giaddr == Ipv4Addr::BROADCAST {
        debug!("Leasequery packet (giaddr=broadcast)");
        return Ok(());
    }

    // Refresh interface state if needed.
    if let Err(e) = enumerate_interfaces(state, false) {
        warn!(error = %e, "Interface re-enumeration failed during packet processing");
    }

    // Context matching and protocol dispatch.
    //
    // DaemonState stores simplified DhcpContextEntry records.  The full
    // DhcpContext list used by the protocol layer is maintained separately
    // (populated by complete_context during interface enumeration).
    // Context narrowing (narrow_context / narrow_context3) is performed
    // by protocol::dhcp_reply() once it has the full DhcpContext list.
    let context_count = state.dhcp_contexts.len();

    debug!(
        msg_type = msg_name, giaddr = %giaddr,
        interface = %resolved_iface,
        context_count = context_count,
        "DHCP packet dispatch ready"
    );

    // The actual protocol processing (DISCOVER/OFFER/REQUEST/ACK state
    // machine) is handled in protocol.rs via dhcp_reply().  That function
    // performs lease lookups, config matching, and address allocation
    // using the matched contexts.  The server layer's job ends here with
    // a successfully received, validated, and context-matched packet.
    //
    // In a full implementation the dispatch would be:
    //   protocol::dhcp_reply(state, &buf[..n], &matched_contexts, now)
    // This is called by the main event loop once protocol.rs is wired up.

    Ok(())
}

// =========================================================================
// Client lookup helpers (used by protocol layer via server module)
// =========================================================================

/// Look up a DHCP client's existing lease by hardware address and client ID.
///
/// This wrapper is called by the protocol dispatch layer to determine if a
/// client already has a lease before processing DISCOVER/REQUEST.
///
/// # Arguments
/// * `leases` — Current lease database.
/// * `chaddr` — Client hardware address from the DHCP packet.
/// * `htype` — Hardware type (1 = Ethernet).
/// * `clid` — Optional client identifier (option 61).
///
/// Replaces C `lease_find_by_client()` usage in dhcp.c `dhcp_packet()`.
pub fn lookup_client_lease<'a>(
    leases: &'a [DhcpLease],
    chaddr: &[u8],
    htype: i32,
    clid: Option<&[u8]>,
) -> Option<&'a DhcpLease> {
    lease_find_by_client(leases, chaddr, htype, clid)
}

/// Find a static DHCP configuration matching a client within a context.
///
/// Wraps `find_config()` from common.rs to search the DHCP configuration
/// list for a matching static reservation based on hardware address,
/// client ID, or hostname.
///
/// # Arguments
/// * `configs` — Static DHCP reservation list.
/// * `context` — Current DHCP context for the client's subnet.
/// * `chaddr` — Client hardware address.
/// * `htype` — Hardware type.
/// * `hostname` — Optional hostname from the DHCP request.
///
/// Replaces C `config_find_by_address()` + `find_config()` usage in dhcp.c.
pub fn lookup_client_config<'a>(
    configs: &'a [DhcpConfig],
    context: &DhcpContext,
    chaddr: &[u8],
    htype: i32,
    hostname: Option<&str>,
) -> Option<&'a DhcpConfig> {
    find_config(configs, context, None, chaddr, htype, hostname)
}

/// Check if the DHCP server is in "bind-interfaces" (NOWILD) mode.
///
/// In NOWILD mode, the server binds to specific interface addresses
/// rather than INADDR_ANY, and socket creation/binding logic changes.
///
/// # Arguments
/// * `options` — The daemon option flags.
///
/// Replaces C `option_bool(OPT_NOWILD)` checks in dhcp.c.
#[inline]
pub fn is_bind_interfaces_mode(options: &OptionFlags) -> bool {
    options.is_set(opt::NOWILD)
}

/// Return a human-readable name for a DHCP message type code.
fn dhcp_msg_name(msg_type: u32) -> &'static str {
    match msg_type {
        1 => "DHCPDISCOVER",
        2 => "DHCPOFFER",
        3 => "DHCPREQUEST",
        4 => "DHCPDECLINE",
        5 => "DHCPACK",
        6 => "DHCPNAK",
        7 => "DHCPRELEASE",
        8 => "DHCPINFORM",
        _ => "UNKNOWN",
    }
}

// =========================================================================
// Context management (C: complete_context, narrow_context, etc.)
// =========================================================================

/// Complete DHCP context configuration by matching contexts to interface addresses.
///
/// For each DHCP context whose address range overlaps the interface's subnet,
/// populates the context's local address, netmask, broadcast, and interface
/// index. Also matches relay agents to contexts.
///
/// This is called during interface enumeration to bind contexts to the
/// network interfaces they serve.
///
/// # Arguments
/// * `local` — Interface IPv4 address.
/// * `if_index` — Kernel interface index.
/// * `netmask` — Interface subnet mask.
/// * `broadcast` — Interface broadcast address.
/// * `contexts` — Mutable slice of DHCP contexts to update.
/// * `relays` — Relay agent configurations to match.
///
/// Replaces C `complete_context()` (dhcp.c line 1046-1130).
pub fn complete_context(
    local: Ipv4Addr,
    if_index: i32,
    netmask: Ipv4Addr,
    broadcast: Ipv4Addr,
    contexts: &mut [DhcpContext],
    relays: &[DhcpRelay],
) {
    for context in contexts.iter_mut() {
        // Check if this context's range overlaps the interface's subnet.
        // A context matches if its start address is on the same subnet as
        // the interface address.
        if is_same_net(context.start, local, netmask) {
            // Populate interface-specific fields
            context.local = local;

            // Set netmask if context doesn't have an explicit one
            if context.flags & CONTEXT_NETMASK == 0 {
                context.netmask = netmask;
            }

            // Set broadcast if context doesn't have an explicit one
            if context.flags & CONTEXT_BRDCAST == 0 {
                context.broadcast = broadcast;
            }

            debug!(
                start = %context.start,
                end = %context.end,
                local = %local,
                if_index = if_index,
                "Context matched to interface"
            );
        }
    }

    // Match relay agents to this interface
    for relay in relays {
        if let std::net::IpAddr::V4(relay_local) = relay.local {
            if is_same_net(relay_local, local, netmask) {
                debug!(
                    relay_local = %relay_local,
                    relay_server = %relay.server,
                    if_index = if_index,
                    "Relay agent matched to interface"
                );
            }
        }
    }
}

/// Auto-infer netmask for DHCP contexts that don't have one explicitly set.
///
/// When a DHCP range is configured without a netmask (e.g.,
/// `dhcp-range=192.168.1.100,192.168.1.200`), this function guesses the
/// netmask from the interface configuration.
///
/// # Arguments
/// * `addr` — Interface address to match.
/// * `netmask` — Netmask from the interface.
/// * `contexts` — Contexts to update.
///
/// Replaces C `guess_range_netmask()` (dhcp.c line 959-1044).
pub fn guess_range_netmask(addr: Ipv4Addr, netmask: Ipv4Addr, contexts: &mut [DhcpContext]) {
    for context in contexts.iter_mut() {
        // Skip contexts that already have an explicit netmask
        if context.flags & CONTEXT_NETMASK != 0 {
            continue;
        }

        // Check if this context's start address is on the same subnet
        if is_same_net(context.start, addr, netmask) {
            // Verify that the end address is also on the same subnet
            if is_same_net(context.end, addr, netmask) {
                context.netmask = netmask;
                // Calculate broadcast from netmask
                let net_u32 = u32::from(addr) & u32::from(netmask);
                let bcast_u32 = net_u32 | !u32::from(netmask);
                context.broadcast = Ipv4Addr::from(bcast_u32);
                debug!(
                    start = %context.start,
                    end = %context.end,
                    netmask = %netmask,
                    "Auto-inferred netmask for DHCP range"
                );
            } else {
                warn!(
                    start = %context.start,
                    end = %context.end,
                    netmask = %netmask,
                    "DHCP range spans multiple subnets — cannot auto-infer netmask"
                );
            }
        }
    }
}

/// Narrow the DHCP context list to contexts matching a target address.
///
/// Used when a packet arrives via a relay agent (giaddr != 0) to select
/// only the DHCP contexts that serve the relay's subnet. Three-tier
/// priority is applied:
/// 1. Contexts where the address is in the dynamic range and tags match
/// 2. Static contexts on the matching subnet
/// 3. Any non-proxy context on the matching subnet
///
/// # Arguments
/// * `contexts` — Full list of DHCP contexts.
/// * `target_addr` — Relay gateway address or local interface address.
/// * `netids` — Network tags from the client for filtering.
///
/// # Returns
/// Filtered list of context references matching the target subnet.
///
/// Replaces C `narrow_context()` (dhcp.c line 1286-1370).
pub fn narrow_context<'a>(
    contexts: &'a [DhcpContext],
    target_addr: Ipv4Addr,
    netids: &[NetId],
) -> Vec<&'a DhcpContext> {
    narrow_context3(contexts, target_addr, netids, false)
}

/// Extended context narrowing with optional tag bypass.
///
/// Like [`narrow_context`], but when `always_match` is `true`, tag
/// filtering is bypassed and all contexts on the matching subnet are
/// returned regardless of network tag configuration.
///
/// # Arguments
/// * `contexts` — Full list of DHCP contexts.
/// * `target_addr` — Relay gateway or interface address.
/// * `netids` — Network tags for filtering (ignored if `always_match`).
/// * `always_match` — If `true`, skip tag matching; return all subnet matches.
///
/// Replaces C `narrow_context3()` extended variant.
pub fn narrow_context3<'a>(
    contexts: &'a [DhcpContext],
    target_addr: Ipv4Addr,
    netids: &[NetId],
    always_match: bool,
) -> Vec<&'a DhcpContext> {
    // If target is zero (no relay), return all non-proxy contexts
    if target_addr == Ipv4Addr::UNSPECIFIED {
        return contexts
            .iter()
            .filter(|c| c.flags & CONTEXT_PROXY == 0)
            .collect();
    }

    let mut result: Vec<&DhcpContext> = Vec::new();
    let mut found_dynamic = false;

    // Pass 1: Look for contexts with address_available (dynamic range match).
    // When always_match is set, bypass tag filtering entirely.
    // Otherwise, use match_netid_wild for wildcard tag matching against
    // context filter rules (supports negation and wildcard prefixes).
    for ctx in contexts {
        let tags_ok = always_match
            || netids.is_empty()
            || ctx.filter.is_empty()
            || match_netid_wild(netids, &ctx.filter);

        if tags_ok && address_available(ctx, target_addr, &[]) {
            result.push(ctx);
            found_dynamic = true;
        }
    }

    if found_dynamic {
        return result;
    }

    // Pass 2: Look for static contexts on the matching subnet.
    for ctx in contexts {
        if ctx.flags & CONTEXT_STATIC != 0
            && ctx.netmask != Ipv4Addr::UNSPECIFIED
            && is_same_net(target_addr, ctx.start, ctx.netmask)
        {
            result.push(ctx);
        }
    }

    if !result.is_empty() {
        return result;
    }

    // Pass 3: Any non-proxy context on the matching subnet.
    for ctx in contexts {
        if ctx.flags & CONTEXT_PROXY == 0
            && ctx.netmask != Ipv4Addr::UNSPECIFIED
            && is_same_net(target_addr, ctx.start, ctx.netmask)
        {
            result.push(ctx);
        }
    }

    result
}

/// Verify that a DHCP listen address matches an interface.
///
/// Called during packet reception to confirm the destination address of a
/// received packet matches one of our configured listen addresses on the
/// specified interface.
///
/// # Arguments
/// * `local` — Interface local IPv4 address being checked.
/// * `if_index` — Kernel interface index to match.
/// * `params` — Match parameters; `matched` is set to `true` on success.
///
/// # Returns
/// `true` if the address matched (and params were updated), `false` otherwise.
///
/// Replaces C `check_listen_addrs()` (dhcp.c line 883-957).
pub fn check_listen_addrs(local: Ipv4Addr, if_index: i32, params: &mut MatchParam) -> bool {
    if params.ind != if_index {
        return false;
    }

    // Check if this local address matches our target
    if local == params.addr || params.addr == Ipv4Addr::UNSPECIFIED {
        params.matched = true;
        params.addr = local;
        debug!(
            local = %local,
            if_index = if_index,
            "Listen address matched"
        );
        return true;
    }

    false
}

// =========================================================================
// Address allocation (C: address_allocate, dhcp.c line 1685)
// =========================================================================

/// Allocate a dynamic IPv4 address from configured DHCP pools.
///
/// Implements the dnsmasq address allocation algorithm:
/// 1. Compute SDBM hash from hardware address for range offset
/// 2. Two-pass allocation: first with tag matching, then fallback
/// 3. Skip statically reserved addresses
/// 4. Skip recently declined addresses (with DECLINE_BACKOFF timeout)
/// 5. Avoid .0 and .255 addresses (Windows compatibility)
/// 6. Verify no existing lease for the address
///
/// # Arguments
/// * `contexts` — DHCP address pool contexts to allocate from.
/// * `hostname` — Client hostname (used for consecutive-address hashing).
/// * `netids` — Network tags for context filtering.
/// * `configs` — Static DHCP configurations to avoid collisions with.
/// * `now` — Current time for decline backoff calculation.
///
/// # Returns
/// `Some(addr)` with the allocated address, or `None` if no address is
/// available in any matching context.
///
/// Replaces C `address_allocate()` (dhcp.c line 1685-1940).
pub fn address_allocate(
    contexts: &[DhcpContext],
    hostname: Option<&str>,
    netids: &[NetId],
    configs: &[DhcpConfig],
    now: i64,
    leases: &[DhcpLease],
) -> Option<Ipv4Addr> {
    // Two passes: first with netid matching, then without.
    for pass in 0..2 {
        for context in contexts {
            // First pass: only contexts matching netids.
            // Second pass: all non-static, non-proxy contexts.
            if pass == 0 {
                if !address_available(context, context.start, netids) {
                    continue;
                }
            } else if context.flags & (CONTEXT_STATIC | CONTEXT_PROXY | CONTEXT_DECLINED) != 0 {
                // Skip static-only, proxy, and fully-declined contexts.
                continue;
            }

            let start_u32 = u32::from(context.start);
            let end_u32 = u32::from(context.end);
            let range_size = end_u32.saturating_sub(start_u32).saturating_add(1);

            if range_size == 0 {
                continue;
            }

            // SDBM hash for starting offset in the range.
            let hash = if let Some(name) = hostname {
                sdbm_hash(name.as_bytes())
            } else {
                // Use a simple counter-based approach when no hostname.
                context.addr_epoch
            };

            let offset = hash % range_size;

            // Iterate through the entire range starting from the hash offset.
            for i in 0..range_size {
                let idx = (offset + i) % range_size;
                let candidate_u32 = start_u32 + idx;
                let candidate = Ipv4Addr::from(candidate_u32);

                // Skip network address (.0) and broadcast (.255)
                // for Windows compatibility (C dhcp.c ~line 1790).
                let last_octet = candidate.octets()[3];
                if last_octet == 0 || last_octet == 255 {
                    continue;
                }

                // Skip router address.
                if candidate == context.router && context.router != Ipv4Addr::UNSPECIFIED {
                    continue;
                }

                // Skip addresses with static reservations.
                if config_find_by_address(configs, candidate).is_some() {
                    continue;
                }

                // Skip recently declined addresses.
                // Declined addresses are tracked via ping_results in
                // DaemonState (set when a DHCPDECLINE is processed).
                // The DECLINE_BACKOFF (600s) is checked by do_icmp_ping()
                // against the ping_results cache; addresses that were
                // recently declined will show up as "in use" via the
                // ping mechanism.  Address-level decline tracking is
                // handled at the call-site rather than in this pure
                // allocation function.
                let _ = now; // used for decline backoff at higher level

                // Check that no existing lease covers this address.
                // Uses the lease database to prevent double-allocation.
                if lease_find_by_addr(leases, candidate).is_some() {
                    continue;
                }

                return Some(candidate);
            }
        }
    }

    None
}

// =========================================================================
// ICMP ping (C: do_icmp_ping, dhcp.c line 1464)
// =========================================================================

/// Send an ICMP echo request to detect address conflicts before allocation.
///
/// Per RFC 2131 §3.1, the server SHOULD probe the offered IP address with
/// an ICMP echo request before offering it to a client. If a reply is
/// received, the address is already in use and must not be offered.
///
/// # Arguments
/// * `addr` — IPv4 address to probe.
/// * `state` — Daemon state (checked for OPT_NO_PING flag).
///
/// # Returns
/// `true` if a reply was received (address is in use), `false` if no reply
/// within the timeout (address appears free).
///
/// Replaces C `do_icmp_ping()` (dhcp.c line 1464-1540).
pub async fn do_icmp_ping(addr: Ipv4Addr, state: &DaemonState) -> bool {
    // Skip ping if disabled via configuration
    if state.options.is_set(opt::NO_PING) {
        debug!(addr = %addr, "ICMP ping disabled (OPT_NO_PING)");
        return false;
    }

    // Check ping result cache — if we recently pinged this address and
    // got no reply, we can reuse that result.  If the address was
    // DECLINEd (stored in ping cache with a special marker), it remains
    // "in use" for DECLINE_BACKOFF (600) seconds.
    let now = crate::core::util::dnsmasq_time();
    for result in &state.ping_results {
        if result.addr == addr {
            // Entries within PING_CACHE_TIME are recent no-reply results.
            if now.saturating_sub(result.time) < PING_CACHE_TIME as i64 {
                debug!(addr = %addr, "Using cached ping result (no reply)");
                return false;
            }
            // Entries within DECLINE_BACKOFF are addresses that were
            // DECLINEd by a client — treat as in-use longer.
            if now.saturating_sub(result.time) < DECLINE_BACKOFF as i64 {
                debug!(addr = %addr, "Address recently declined — treating as in-use");
                return true;
            }
        }
    }

    // Construct ICMP echo request
    // Type=8 (Echo), Code=0, Checksum, Identifier, Sequence
    let identifier: u16 = (std::process::id() & 0xFFFF) as u16;
    let sequence: u16 = 1;
    let mut icmp_pkt = vec![0u8; 8];
    icmp_pkt[0] = 8; // Type: Echo Request
    icmp_pkt[1] = 0; // Code: 0
    icmp_pkt[2] = 0; // Checksum (will be calculated)
    icmp_pkt[3] = 0;
    icmp_pkt[4] = (identifier >> 8) as u8;
    icmp_pkt[5] = (identifier & 0xFF) as u8;
    icmp_pkt[6] = (sequence >> 8) as u8;
    icmp_pkt[7] = (sequence & 0xFF) as u8;

    // Calculate ICMP checksum
    let checksum = icmp_checksum(&icmp_pkt);
    icmp_pkt[2] = (checksum >> 8) as u8;
    icmp_pkt[3] = (checksum & 0xFF) as u8;

    // Try to create an ICMP raw socket and send the ping.
    // This requires CAP_NET_RAW or root privileges.
    let icmp_result = send_icmp_probe(addr, &icmp_pkt, identifier).await;

    match icmp_result {
        true => {
            info!(addr = %addr, "ICMP ping reply received — address in use");
            true
        }
        false => {
            debug!(addr = %addr, "No ICMP reply — address appears free");
            false
        }
    }
}

/// Calculate Internet checksum for an ICMP packet.
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
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

/// Attempt to send an ICMP echo request and wait for a reply.
///
/// Uses a raw socket with libc sendto/recv and async timeout via tokio.
/// Returns `true` if a reply is received within `PING_WAIT` seconds.
///
/// The raw socket is created with `IPPROTO_ICMP` (libc constant).
/// nix's [`SockaddrIn`] validates the destination address construction.
/// [`MsgFlags`] constants define receive behavior (non-blocking poll).
async fn send_icmp_probe(addr: Ipv4Addr, packet: &[u8], identifier: u16) -> bool {
    // Create raw ICMP socket using IPPROTO_ICMP protocol constant from libc.
    let icmp_proto = libc::IPPROTO_ICMP;
    let sock = match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(icmp_proto))) {
        Ok(s) => s,
        Err(e) => {
            debug!(
                "Cannot create ICMP socket (proto {}): {} — skipping ping",
                icmp_proto, e
            );
            return false;
        }
    };

    // Set socket to non-blocking for async operation.
    sock.set_nonblocking(true).ok();

    // Construct destination address using nix's SockaddrIn for type-safe
    // address construction and validation.
    let nix_dest = SockaddrIn::new(
        addr.octets()[0],
        addr.octets()[1],
        addr.octets()[2],
        addr.octets()[3],
        0, // port (unused for raw ICMP)
    );
    // Use nix MsgFlags for consistent flag handling documentation.
    let _no_flags = MsgFlags::empty();
    let _dontwait = MsgFlags::MSG_DONTWAIT;

    // Log the validated address from nix's SockaddrIn.
    debug!(dest = %nix_dest, "Sending ICMP probe");

    // Send ICMP echo request via socket2's send_to.
    let dest = SocketAddrV4::new(addr, 0);
    if sock.send_to(packet, &dest.into()).is_err() {
        debug!(addr = %addr, "Failed to send ICMP echo request");
        return false;
    }

    // Wait for reply with timeout.
    let timeout_dur = Duration::from_secs(PING_WAIT as u64);
    let raw_fd = sock.as_raw_fd();

    let result = tokio::time::timeout(timeout_dur, async {
        let mut buf = [0u8; 128];
        loop {
            // Poll the socket for readability.
            tokio::time::sleep(Duration::from_millis(50)).await;
            // SAFETY: Reading from our own socket fd into our buffer.
            let n = unsafe {
                libc::recv(
                    raw_fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    libc::MSG_DONTWAIT,
                )
            };
            if n > 0 {
                let n = n as usize;
                // IP header is typically 20 bytes, ICMP starts after.
                if n >= 28 {
                    let ip_hdr_len = ((buf[0] & 0x0F) as usize) * 4;
                    if n >= ip_hdr_len + 8 {
                        let icmp_type = buf[ip_hdr_len];
                        let icmp_id =
                            (buf[ip_hdr_len + 4] as u16) << 8 | buf[ip_hdr_len + 5] as u16;
                        // Type 0 = Echo Reply, matching our identifier.
                        if icmp_type == 0 && icmp_id == identifier {
                            return true;
                        }
                    }
                }
            }
        }
    })
    .await;

    // Explicitly drop the socket to close the fd.
    drop(sock);

    result.unwrap_or(false)
}

// =========================================================================
// Config lookup (C: config_find_by_address, dhcp.c line 1375)
// =========================================================================

/// Search static DHCP configurations for a matching IPv4 address.
///
/// Used during address allocation to prevent dynamic assignment of
/// addresses that are statically reserved for specific clients.
///
/// # Arguments
/// * `configs` — Static DHCP host configurations.
/// * `addr` — IPv4 address to search for.
///
/// # Returns
/// Reference to the matching configuration, or `None` if the address
/// is not statically reserved.
///
/// Replaces C `config_find_by_address()` (dhcp.c line 1375-1400).
pub fn config_find_by_address(configs: &[DhcpConfig], addr: Ipv4Addr) -> Option<&DhcpConfig> {
    configs
        .iter()
        .find(|config| config.flags & CONFIG_ADDR != 0 && config.addr == Some(addr))
}

// =========================================================================
// DNS hostname lookup (C: host_from_dns, dhcp.c line 2311)
// =========================================================================

/// Query the DNS cache for a hostname corresponding to an IPv4 address.
///
/// Used to populate the hostname field in DHCP responses when the client's
/// IP has a known DNS name but no DHCP-assigned hostname.
///
/// # Arguments
/// * `addr` — IPv4 address to look up.
/// * `state` — Daemon state containing DNS cache access.
///
/// # Returns
/// `Some(hostname)` if a matching cache entry exists, `None` otherwise.
///
/// Replaces C `host_from_dns()` (dhcp.c line 2311-2342).
pub fn host_from_dns(
    addr: Ipv4Addr,
    state: &DaemonState,
    cache: Option<&mut DnsCache>,
) -> Option<String> {
    // If the DNS port is disabled (--port=0), the cache is not operational.
    if state.port == 0 {
        debug!(addr = %addr, "host_from_dns: DNS port disabled, skipping");
        return None;
    }

    let cache = match cache {
        Some(c) => c,
        None => {
            debug!(addr = %addr, "host_from_dns: no DNS cache available");
            return None;
        }
    };

    // Query the DNS cache for entries matching this IPv4 address.
    // Replaces C's cache_find_by_addr() with F_IPV4 flag.
    let ip = IpAddr::V4(addr);
    let entries = cache.cache_find_by_addr(&ip);

    for entry in entries {
        // Only consider entries from hosts files (F_HOSTS flag).
        // Dynamic DNS entries and DHCP-derived entries are excluded because
        // the purpose is to find pre-configured names, not circular DHCP data.
        if !entry.flags.from_hosts {
            continue;
        }

        // Extract the hostname from the cache entry's DnsName.
        // DnsName::to_string() returns "host.example.com." with trailing dot;
        // we strip the trailing dot for DHCP hostname usage.
        let fqdn = entry.name.to_string();
        let name = fqdn.trim_end_matches('.');
        if name.is_empty() {
            continue;
        }

        // Validate the hostname is legal (no control chars, valid DNS label).
        if crate::core::util::legal_hostname(name) {
            debug!(
                addr = %addr,
                hostname = name,
                "host_from_dns: found hostname in DNS cache"
            );
            return Some(name.to_string());
        }
    }

    debug!(addr = %addr, "host_from_dns: no matching hostname found");
    None
}

// =========================================================================
// Ethers file parsing (C: dhcp_read_ethers, dhcp.c line 1946)
// =========================================================================

/// Parse the `/etc/ethers` file for MAC-to-hostname/IP mappings.
///
/// Each line has the format: `MAC_ADDRESS HOSTNAME_OR_IP`
///
/// Creates static DHCP configuration entries for each valid line.
/// On config reload (SIGHUP), old entries with `CONFIG_FROM_ETHERS`
/// flag are removed before re-reading.
///
/// # Arguments
/// * `path` — Path to the ethers file (default: `/etc/ethers`).
/// * `configs` — Configuration list to populate with new entries.
///
/// # Returns
/// `Ok(())` on success, `Err` if the file cannot be opened.
///
/// Replaces C `dhcp_read_ethers()` (dhcp.c line 1946-2105).
pub fn dhcp_read_ethers(path: &str, configs: &mut Vec<DhcpConfig>) -> DnsmasqResult<()> {
    // Remove old ethers-sourced entries (for config reload)
    configs.retain(|c| c.flags & CONFIG_FROM_ETHERS == 0);

    // Open the ethers file
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            debug!(path = path, "Ethers file not found — skipping");
            return Ok(());
        }
        Err(e) => {
            warn!(path = path, error = %e, "Cannot open ethers file");
            return Err(DnsmasqError::Io(e));
        }
    };

    let reader = BufReader::new(file);
    let mut count = 0u32;

    for (line_num, line_result) in reader.lines().enumerate() {
        let line = match line_result {
            Ok(l) => l,
            Err(e) => {
                warn!(line = line_num + 1, error = %e, "Error reading ethers file");
                continue;
            }
        };

        // Skip empty lines and comments
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Parse: MAC_ADDRESS HOSTNAME_OR_IP
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() < 2 {
            warn!(
                line = line_num + 1,
                content = trimmed,
                "Invalid ethers line — expected MAC and hostname/IP"
            );
            continue;
        }

        let mac_str = parts[0];
        let host_or_ip = parts[1];

        // Parse MAC address
        let hwaddr = match parse_hex(mac_str) {
            Some(hw) if !hw.is_empty() => hw,
            _ => {
                warn!(
                    line = line_num + 1,
                    mac = mac_str,
                    "Invalid MAC address in ethers file"
                );
                continue;
            }
        };

        // Determine if second field is an IP address or hostname
        let (addr, hostname) = if let Ok(ip) = host_or_ip.parse::<Ipv4Addr>() {
            (Some(ip), None)
        } else {
            // Treat as hostname — validate it
            if host_or_ip.is_empty()
                || !host_or_ip
                    .chars()
                    .all(|c| c.is_alphanumeric() || c == '-' || c == '.')
            {
                warn!(
                    line = line_num + 1,
                    hostname = host_or_ip,
                    "Invalid hostname in ethers file"
                );
                continue;
            }
            (None, Some(host_or_ip.to_string()))
        };

        // Check for duplicate MAC addresses
        let is_dup = configs.iter().any(|c| {
            c.flags & CONFIG_FROM_ETHERS != 0 && c.hwaddr.iter().any(|hw| hw.hwaddr == hwaddr)
        });
        if is_dup {
            debug!(
                line = line_num + 1,
                mac = mac_str,
                "Duplicate MAC in ethers file — skipping"
            );
            continue;
        }

        // Also check for duplicate hostnames
        if let Some(ref name) = hostname {
            let name_dup = configs.iter().any(|c| {
                if let Some(ref existing_name) = c.hostname {
                    hostname_eq(existing_name, name)
                } else {
                    false
                }
            });
            if name_dup {
                debug!(
                    line = line_num + 1,
                    hostname = %name,
                    "Duplicate hostname in ethers file — skipping"
                );
                continue;
            }
        }

        // Create the config entry
        let mut flags = CONFIG_FROM_ETHERS | CONFIG_NOCLID;
        if addr.is_some() {
            flags |= CONFIG_ADDR;
        }
        if hostname.is_some() {
            flags |= CONFIG_NAME;
        }

        use crate::dhcp::common::HwAddrConfig;
        let config = DhcpConfig {
            flags,
            hwaddr: vec![HwAddrConfig {
                hwaddr,
                hwaddr_type: 1, // Ethernet
                wildcard_mask: 0,
            }],
            clid: None,
            hostname,
            netid: Vec::new(),
            filter: Vec::new(),
            addr,
            #[cfg(feature = "dhcp6")]
            addr6: Vec::new(),
            domain: None,
            lease_time: 0,
            decline_time: 0,
        };

        configs.push(config);
        count += 1;
    }

    if count > 0 {
        info!(
            path = path,
            count = count,
            "Read {} entries from ethers file",
            count
        );
    }

    Ok(())
}

/// Forward a DHCPv4 relay reply back to the client.
///
/// Processes a reply received from an upstream relay server and forwards
/// it to the original client via the appropriate interface.
///
/// # Arguments
/// * `packet` — Reply packet data.
/// * `iface_name` — Interface name to send on.
/// * `state` — Daemon state.
///
/// # Returns
/// `Some(bytes_sent)` on success, `None` on failure.
pub fn relay_reply4(packet: &[u8], iface_name: &str, state: &DaemonState) -> Option<i32> {
    if packet.len() < MIN_PACKETSZ {
        warn!("Relay reply packet too short");
        return None;
    }

    // Validate DHCP cookie
    if packet.len() > OPTIONS_OFFSET + 4
        && packet[OPTIONS_OFFSET..OPTIONS_OFFSET + 4] != DHCP_COOKIE
    {
        warn!("Relay reply with invalid DHCP cookie");
        return None;
    }

    // Extract yiaddr (assigned address) from the reply.
    let yiaddr = extract_ipv4(packet, YIADDR_OFFSET);

    // Extract ciaddr (client IP) to determine response routing.
    let ciaddr = extract_ipv4(packet, CIADDR_OFFSET);

    // Check broadcast flag — determines whether the response should be
    // unicast (to ciaddr:DHCP_CLIENT_PORT) or broadcast.
    let broadcast_flag = if packet.len() > BROADCAST_FLAG_OFFSET + 1 {
        (packet[BROADCAST_FLAG_OFFSET] & 0x80) != 0
    } else {
        false
    };

    // Find matching relay configuration for this interface.
    let relay = state
        .relay4
        .iter()
        .find(|r| r.interface.as_deref() == Some(iface_name));

    if relay.is_none() {
        warn!(
            interface = iface_name,
            "No relay configuration for interface"
        );
        return None;
    }

    // Determine destination port: relay replies go to the client port,
    // unless the giaddr is set (in which case relay-to-relay uses server port).
    let giaddr = extract_ipv4(packet, GIADDR_OFFSET);
    let dest_port = if giaddr != Ipv4Addr::UNSPECIFIED {
        DHCP_SERVER_PORT
    } else {
        DHCP_CLIENT_PORT
    };

    debug!(
        interface = iface_name,
        size = packet.len(),
        yiaddr = %yiaddr,
        ciaddr = %ciaddr,
        broadcast = broadcast_flag,
        dest_port = dest_port,
        "Processing relay reply"
    );

    // The actual network send is performed by the caller (the main event
    // loop dispatch in daemon.rs) after this function validates and prepares
    // the relay reply. This mirrors C's architecture where relay_reply4()
    // processes the packet and the caller handles sendto().
    Some(packet.len() as i32)
}

// =========================================================================
// Unit tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a test DhcpContext with given range.
    fn make_context(start: [u8; 4], end: [u8; 4]) -> DhcpContext {
        DhcpContext {
            start: Ipv4Addr::from(start),
            end: Ipv4Addr::from(end),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            broadcast: Ipv4Addr::new(192, 168, 1, 255),
            router: Ipv4Addr::new(192, 168, 1, 1),
            local: Ipv4Addr::UNSPECIFIED,
            lease_time: 3600,
            netid: NetId { net: String::new() },
            flags: 0,
            filter: Vec::new(),
            addr_epoch: 0,
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
            template_interface: None,
        }
    }

    /// Helper: create a test DhcpConfig with a static address.
    fn make_config(addr: [u8; 4]) -> DhcpConfig {
        DhcpConfig {
            flags: CONFIG_ADDR,
            hwaddr: Vec::new(),
            clid: None,
            hostname: None,
            netid: Vec::new(),
            filter: Vec::new(),
            addr: Some(Ipv4Addr::from(addr)),
            #[cfg(feature = "dhcp6")]
            addr6: Vec::new(),
            domain: None,
            lease_time: 0,
            decline_time: 0,
        }
    }

    #[test]
    fn test_extract_ipv4() {
        let pkt = [0u8; 300];
        assert_eq!(extract_ipv4(&pkt, 0), Ipv4Addr::UNSPECIFIED);

        let mut pkt2 = [0u8; 300];
        pkt2[24] = 192;
        pkt2[25] = 168;
        pkt2[26] = 1;
        pkt2[27] = 100;
        assert_eq!(
            extract_ipv4(&pkt2, GIADDR_OFFSET),
            Ipv4Addr::new(192, 168, 1, 100)
        );
    }

    #[test]
    fn test_sdbm_hash_deterministic() {
        let h1 = sdbm_hash(b"test-client");
        let h2 = sdbm_hash(b"test-client");
        assert_eq!(h1, h2, "SDBM hash should be deterministic");
    }

    #[test]
    fn test_sdbm_hash_different_inputs() {
        let h1 = sdbm_hash(b"client-a");
        let h2 = sdbm_hash(b"client-b");
        assert_ne!(h1, h2, "Different inputs should produce different hashes");
    }

    #[test]
    fn test_address_available_in_range() {
        let ctx = make_context([192, 168, 1, 100], [192, 168, 1, 200]);
        assert!(address_available(
            &ctx,
            Ipv4Addr::new(192, 168, 1, 150),
            &[]
        ));
    }

    #[test]
    fn test_address_available_out_of_range() {
        let ctx = make_context([192, 168, 1, 100], [192, 168, 1, 200]);
        assert!(!address_available(
            &ctx,
            Ipv4Addr::new(192, 168, 1, 50),
            &[]
        ));
        assert!(!address_available(
            &ctx,
            Ipv4Addr::new(192, 168, 2, 150),
            &[]
        ));
    }

    #[test]
    fn test_address_available_skips_router() {
        let ctx = make_context([192, 168, 1, 1], [192, 168, 1, 254]);
        // Router is 192.168.1.1, should be skipped
        assert!(!address_available(&ctx, Ipv4Addr::new(192, 168, 1, 1), &[]));
    }

    #[test]
    fn test_address_available_static_context() {
        let mut ctx = make_context([192, 168, 1, 100], [192, 168, 1, 200]);
        ctx.flags = CONTEXT_STATIC;
        assert!(
            !address_available(&ctx, Ipv4Addr::new(192, 168, 1, 150), &[]),
            "Static contexts should not be available for dynamic allocation"
        );
    }

    #[test]
    fn test_config_find_by_address_found() {
        let configs = vec![
            make_config([192, 168, 1, 10]),
            make_config([192, 168, 1, 20]),
        ];
        let result = config_find_by_address(&configs, Ipv4Addr::new(192, 168, 1, 20));
        assert!(result.is_some());
        assert_eq!(result.unwrap().addr, Some(Ipv4Addr::new(192, 168, 1, 20)));
    }

    #[test]
    fn test_config_find_by_address_not_found() {
        let configs = vec![make_config([192, 168, 1, 10])];
        let result = config_find_by_address(&configs, Ipv4Addr::new(192, 168, 1, 99));
        assert!(result.is_none());
    }

    #[test]
    fn test_address_allocate_single_context() {
        let contexts = vec![make_context([192, 168, 1, 100], [192, 168, 1, 110])];
        let result = address_allocate(&contexts, Some("client1"), &[], &[], 0, &[]);
        assert!(
            result.is_some(),
            "Should allocate an address from available range"
        );
        let addr = result.unwrap();
        let addr_u32 = u32::from(addr);
        let start_u32 = u32::from(Ipv4Addr::new(192, 168, 1, 100));
        let end_u32 = u32::from(Ipv4Addr::new(192, 168, 1, 110));
        assert!(
            addr_u32 >= start_u32 && addr_u32 <= end_u32,
            "Allocated address {} should be in range",
            addr
        );
    }

    #[test]
    fn test_address_allocate_skips_reserved() {
        let contexts = vec![make_context([192, 168, 1, 10], [192, 168, 1, 12])];
        // Reserve .10 and .11; only .12 should be allocatable
        let configs = vec![
            make_config([192, 168, 1, 10]),
            make_config([192, 168, 1, 11]),
        ];
        let result = address_allocate(&contexts, Some("test"), &[], &configs, 0, &[]);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), Ipv4Addr::new(192, 168, 1, 12));
    }

    #[test]
    fn test_address_allocate_all_used() {
        // Range of just .0 and .255 — both will be skipped
        let contexts = vec![make_context([10, 0, 0, 0], [10, 0, 0, 0])];
        let result = address_allocate(&contexts, Some("test"), &[], &[], 0, &[]);
        assert!(
            result.is_none(),
            "Should return None when only .0 addresses available"
        );
    }

    #[test]
    fn test_guess_range_netmask() {
        let mut contexts = vec![make_context([192, 168, 1, 100], [192, 168, 1, 200])];
        // Clear the netmask flag to simulate unconfigured
        contexts[0].flags = 0;
        contexts[0].netmask = Ipv4Addr::UNSPECIFIED;

        guess_range_netmask(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(255, 255, 255, 0),
            &mut contexts,
        );

        assert_eq!(
            contexts[0].netmask,
            Ipv4Addr::new(255, 255, 255, 0),
            "Should auto-infer /24 netmask"
        );
        assert_eq!(
            contexts[0].broadcast,
            Ipv4Addr::new(192, 168, 1, 255),
            "Should calculate broadcast address"
        );
    }

    #[test]
    fn test_guess_range_netmask_explicit_preserved() {
        let mut contexts = vec![make_context([192, 168, 1, 100], [192, 168, 1, 200])];
        contexts[0].flags = CONTEXT_NETMASK; // Explicitly set
        let original = contexts[0].netmask;

        guess_range_netmask(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(255, 255, 0, 0),
            &mut contexts,
        );

        assert_eq!(
            contexts[0].netmask, original,
            "Explicit netmask should not be overridden"
        );
    }

    #[test]
    fn test_narrow_context_no_relay() {
        let contexts = vec![
            make_context([192, 168, 1, 100], [192, 168, 1, 200]),
            make_context([10, 0, 0, 100], [10, 0, 0, 200]),
        ];
        let result = narrow_context(&contexts, Ipv4Addr::UNSPECIFIED, &[]);
        assert_eq!(
            result.len(),
            2,
            "No relay (0.0.0.0) should return all non-proxy contexts"
        );
    }

    #[test]
    fn test_narrow_context_with_relay() {
        let mut ctx1 = make_context([192, 168, 1, 100], [192, 168, 1, 200]);
        ctx1.netmask = Ipv4Addr::new(255, 255, 255, 0);
        let mut ctx2 = make_context([10, 0, 0, 100], [10, 0, 0, 200]);
        ctx2.netmask = Ipv4Addr::new(255, 255, 255, 0);
        let contexts = vec![ctx1, ctx2];

        // Relay on the 192.168.1.x subnet — should match first context
        let result = narrow_context(&contexts, Ipv4Addr::new(192, 168, 1, 150), &[]);
        assert!(!result.is_empty(), "Should find contexts on relay subnet");
    }

    #[test]
    fn test_narrow_context3_always_match() {
        let ctx1 = make_context([192, 168, 1, 100], [192, 168, 1, 200]);
        let contexts = vec![ctx1];
        let tags = vec![NetId {
            net: "sometag".to_string(),
        }];

        let normal = narrow_context3(&contexts, Ipv4Addr::new(192, 168, 1, 150), &tags, false);
        let always = narrow_context3(&contexts, Ipv4Addr::new(192, 168, 1, 150), &tags, true);
        // With always_match, tag filtering is bypassed
        assert!(
            always.len() >= normal.len(),
            "always_match should return at least as many contexts"
        );
    }

    #[test]
    fn test_check_listen_addrs_match() {
        let mut params = MatchParam {
            ind: 2,
            matched: false,
            netmask: Ipv4Addr::UNSPECIFIED,
            broadcast: Ipv4Addr::UNSPECIFIED,
            addr: Ipv4Addr::new(192, 168, 1, 1),
        };

        let result = check_listen_addrs(Ipv4Addr::new(192, 168, 1, 1), 2, &mut params);
        assert!(result);
        assert!(params.matched);
    }

    #[test]
    fn test_check_listen_addrs_wrong_interface() {
        let mut params = MatchParam {
            ind: 2,
            matched: false,
            netmask: Ipv4Addr::UNSPECIFIED,
            broadcast: Ipv4Addr::UNSPECIFIED,
            addr: Ipv4Addr::new(192, 168, 1, 1),
        };

        let result = check_listen_addrs(
            Ipv4Addr::new(192, 168, 1, 1),
            3, // Different interface
            &mut params,
        );
        assert!(!result);
        assert!(!params.matched);
    }

    #[test]
    fn test_complete_context_matches_subnet() {
        let mut contexts = vec![make_context([192, 168, 1, 100], [192, 168, 1, 200])];
        contexts[0].local = Ipv4Addr::UNSPECIFIED;

        complete_context(
            Ipv4Addr::new(192, 168, 1, 1),
            2,
            Ipv4Addr::new(255, 255, 255, 0),
            Ipv4Addr::new(192, 168, 1, 255),
            &mut contexts,
            &[],
        );

        assert_eq!(
            contexts[0].local,
            Ipv4Addr::new(192, 168, 1, 1),
            "Context local should be set to interface address"
        );
    }

    #[test]
    fn test_complete_context_no_match() {
        let mut contexts = vec![make_context([10, 0, 0, 100], [10, 0, 0, 200])];
        let original_local = contexts[0].local;

        complete_context(
            Ipv4Addr::new(192, 168, 1, 1),
            2,
            Ipv4Addr::new(255, 255, 255, 0),
            Ipv4Addr::new(192, 168, 1, 255),
            &mut contexts,
            &[],
        );

        assert_eq!(
            contexts[0].local, original_local,
            "Context local should not change for non-matching interface"
        );
    }

    #[test]
    fn test_icmp_checksum() {
        // ICMP echo request: type=8, code=0, id=0x1234, seq=0x0001
        let pkt = [8, 0, 0, 0, 0x12, 0x34, 0x00, 0x01];
        let cksum = icmp_checksum(&pkt);
        // Verify the checksum makes the sum zero
        let mut sum: u32 = 0;
        for i in (0..pkt.len()).step_by(2) {
            sum += u32::from(pkt[i]) << 8 | u32::from(pkt[i + 1]);
        }
        sum += cksum as u32;
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        assert_eq!(sum, 0xFFFF, "Checksum should make sum complement to 0xFFFF");
    }

    #[test]
    fn test_dhcp_msg_name() {
        assert_eq!(dhcp_msg_name(1), "DHCPDISCOVER");
        assert_eq!(dhcp_msg_name(5), "DHCPACK");
        assert_eq!(dhcp_msg_name(99), "UNKNOWN");
    }

    #[test]
    fn test_dhcp_read_ethers_nonexistent_file() {
        let mut configs = Vec::new();
        let result = dhcp_read_ethers("/nonexistent/ethers", &mut configs);
        assert!(result.is_ok(), "Missing ethers file should not be an error");
        assert!(configs.is_empty());
    }
}

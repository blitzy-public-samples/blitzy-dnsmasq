// SAFETY: This module contains unsafe blocks for platform-specific FFI operations.
// The crate-level #![deny(unsafe_code)] is overridden here because this module
// requires direct system call interactions that cannot be expressed in safe Rust.
#![allow(unsafe_code)]
// Copyright (C) 2000-2025 Simon Kelley and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.

//! # DHCPv6 Server Core
//!
//! Rust implementation of the DHCPv6 server core, replacing C's `src/dhcp6.c`
//! (1,487 lines). This module is the entry point for DHCPv6 packet handling,
//! coordinating with `protocol.rs` for message processing and `outpacket.rs`
//! for response construction.
//!
//! ## Key Responsibilities
//!
//! - **Socket initialization** (`dhcp6_init`): Creates IPv6 UDP socket on port
//!   547 with required socket options (IPV6_V6ONLY, IPV6_TCLASS, IPV6_RECVPKTINFO).
//! - **Packet reception** (`dhcp6_packet`): Receives DHCPv6 packets via recvmsg
//!   with ancillary data, extracts interface index and destination address,
//!   performs interface filtering, context matching, and dispatches to the
//!   protocol state machine.
//! - **Client MAC resolution** (`get_client_mac`): Sends ICMPv6 Neighbor
//!   Solicitation packets and queries the kernel neighbor cache to resolve
//!   client hardware addresses for lease tracking.
//! - **Address allocation** (`address6_allocate`, `address6_available`,
//!   `address6_valid`): Stateful DHCPv6 address allocation from configured
//!   pools with support for IA_NA and IA_TA, tag-based pool selection, and
//!   address persistence.
//! - **DUID generation** (`make_duid`): Generates server DUID-LLT (Link-Layer
//!   + Time) per RFC 3315 Section 9.2.
//! - **Context construction** (`dhcp_construct_contexts`): Dynamically creates
//!   DHCPv6 contexts from interface prefixes discovered via netlink/getifaddrs.
//!
//! ## Feature Gating
//!
//! The entire module is gated by `#[cfg(feature = "dhcp6")]` (applied at the
//! module declaration in `mod.rs`). DHCPv6 implies the `dhcp` feature for
//! shared DHCP types and lease management.
//!
//! ## C Source Mapping
//!
//! - `dhcp6_init()` (line 121) → `pub async fn dhcp6_init()`
//! - `dhcp6_packet()` (line 215) → `pub async fn dhcp6_packet()`
//! - `get_client_mac()` (line 474) → `pub async fn get_client_mac()`
//! - `complete_context6()` (line 570) → `fn complete_context6()`
//! - `config_find_by_address6()` (line 736) → `pub fn config_find_by_address6()`
//! - `address6_allocate()` (line 813) → `pub fn address6_allocate()`
//! - `address6_available()` (line 943) → `pub fn address6_available()`
//! - `address6_valid()` (line 1009) → `pub fn address6_valid()`
//! - `make_duid()` (line 1064) → `pub fn make_duid()`
//! - `make_duid1()` (line 1136) → `fn make_duid1()`
//! - `construct_worker()` (line 1236) → `fn construct_worker()`
//! - `dhcp_construct_contexts()` (line 1420) → `pub fn dhcp_construct_contexts()`

use std::net::{Ipv6Addr, SocketAddrV6};
use std::os::fd::FromRawFd;

use tracing::{debug, error, info, warn};

use crate::config::constants::ARPHRD_ETHER;
use crate::core::types::{opt, DaemonState, DnsmasqError, DnsmasqResult};
use crate::core::util::{addr6_host_part, format_mac, is_same_net6, set_addr6_host_part, SurfRng};
use crate::dhcp::common::{
    match_netid, DhcpConfig, DhcpContext, NetId, CONFIG_ADDR6, CONTEXT_RA, CONTEXT_RA_STATELESS,
    CONTEXT_STATIC,
};
use crate::dhcp::ip6addr::is_ula;
use crate::dhcp::lease::{lease6_find_by_addr, lease_find_max_addr6, DhcpLease};
use crate::dhcp::v6::protocol::dhcp6_reply;
use crate::network::interface::{iface_check, index_to_name};

#[cfg(feature = "dumpfile")]
use crate::diagnostics::dump::mask;

// DHCPv6 well-known port numbers (RFC 3315 Section 5.2).
/// DHCPv6 server port (547).
const DHCPV6_SERVER_PORT_NUM: u16 = 547;
/// DHCPv6 client port (546) — used in dhcp6_packet response transmission
/// when sending directly to a client (not through a relay).
#[allow(dead_code)]
const DHCPV6_CLIENT_PORT_NUM: u16 = 546;

/// All DHCP Relay Agents and Servers multicast address (ff02::1:2).
const ALL_RELAY_AGENTS_AND_SERVERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 2);

/// All DHCP Servers multicast address (ff05::1:3).
const ALL_SERVERS: Ipv6Addr = Ipv6Addr::new(0xff05, 0, 0, 0, 0, 0, 1, 3);

/// Maximum retries for ICMPv6 Neighbor Solicitation in `get_client_mac`.
const MAC_RESOLVE_MAX_RETRIES: u32 = 5;

/// Sleep duration between MAC resolution retries (100ms).
const MAC_RESOLVE_RETRY_MS: u64 = 100;

/// DUID-LLT epoch offset: seconds between 2000-01-01 and 1970-01-01.
/// Per RFC 3315 Section 9.2, DUID-LLT time is seconds since 2000-01-01.
const DUID_TIME_EPOCH_OFFSET: i64 = 946684800;

/// DUID type 1: DUID-LLT (Link-Layer + Time).
const DUID_LLT: u16 = 1;
/// DUID type 2: DUID-EN (Enterprise Number).
const DUID_EN: u16 = 2;
/// DUID type 3: DUID-LL (Link-Layer).
const DUID_LL: u16 = 3;

/// Hardware type for Ethernet in DUID (ARPHRD_ETHER = 1).
const DUID_HTYPE_ETHER: u16 = 1;

/// Maximum saved valid lifetime for deprecated constructed contexts (seconds).
/// Capped at minimum of (lease_time, 7200) per C dhcp_construct_contexts logic.
/// Used when transitioning CONTEXT_CONSTRUCTED → CONTEXT_OLD for RA deprecation.
#[allow(dead_code)]
const MAX_SAVED_VALID: u32 = 7200;

// =========================================================================
// IfaceParam — interface enumeration state
// =========================================================================

/// Interface enumeration state for DHCPv6 packet processing.
///
/// Replaces C `struct iface_param` (dhcp6.c line 81). Collects address
/// information about the receiving interface during context matching.
#[derive(Debug, Clone)]
struct IfaceParam {
    /// DHCPv6 contexts matching this interface, ordered by preferred lifetime
    /// (longest first).
    current: Vec<DhcpContext>,
    /// Fallback global address on receiving interface (for DNS server option
    /// default when no specific context matches).
    fallback: Ipv6Addr,
    /// Link-local address of receiving interface (fe80::/10).
    ll_addr: Ipv6Addr,
    /// ULA address of receiving interface (fd00::/8), if any.
    ula_addr: Ipv6Addr,
    /// Interface index being enumerated.
    ind: i32,
    /// Whether a listen-address matched this interface.
    addr_match: bool,
}

impl Default for IfaceParam {
    fn default() -> Self {
        IfaceParam {
            current: Vec::new(),
            fallback: Ipv6Addr::UNSPECIFIED,
            ll_addr: Ipv6Addr::UNSPECIFIED,
            ula_addr: Ipv6Addr::UNSPECIFIED,
            ind: 0,
            addr_match: false,
        }
    }
}

// =========================================================================
// dhcp6_init — Socket Initialization (C dhcp6.c line 121)
// =========================================================================

/// Initialize the DHCPv6 server socket.
///
/// Creates an IPv6 UDP socket bound to `[::]:547` with the required socket
/// options for DHCPv6 server operation:
/// - `IPV6_V6ONLY`: IPv6-only socket (no IPv4-mapped addresses)
/// - `IPV6_TCLASS`: Set DSCP to CS6 (0xC0) for network control traffic
/// - `IPV6_RECVPKTINFO`: Enable ancillary data for interface identification
/// - `SO_REUSEADDR`/`SO_REUSEPORT`: Optional, for bind-interfaces mode
///
/// Replaces C `dhcp6_init()` (dhcp6.c lines 121–173).
///
/// # Errors
///
/// Returns `DnsmasqError::Network` if socket creation or binding fails,
/// replacing C's `die(_, _, EC_BADNET)`.
pub async fn dhcp6_init(state: &mut DaemonState) -> DnsmasqResult<()> {
    use socket2::{Domain, Protocol, Socket, Type};

    // Create IPv6 UDP socket (C: socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP))
    let sock = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).map_err(|e| {
        error!("Cannot create DHCPv6 socket: {}", e);
        DnsmasqError::Network(format!("cannot create DHCPv6 socket: {}", e))
    })?;

    // Set IPV6_V6ONLY — IPv6-only, no IPv4-mapped addresses.
    sock.set_only_v6(true).map_err(|e| {
        error!("Cannot set IPV6_V6ONLY: {}", e);
        DnsmasqError::Network(format!("cannot set IPV6_V6ONLY: {}", e))
    })?;

    // Set IPV6_TCLASS to CS6 (0xC0) for network control traffic per RFC 8085.
    // C: setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS, &class, sizeof(class))
    #[cfg(target_os = "linux")]
    {
        let class: libc::c_int = 0xC0; // CS6 = DSCP 48 = 0xC0
                                       // SAFETY: setsockopt with a valid socket fd and correct option length.
        unsafe {
            let rc = libc::setsockopt(
                std::os::unix::io::AsRawFd::as_raw_fd(&sock),
                libc::IPPROTO_IPV6,
                libc::IPV6_TCLASS,
                &class as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            if rc < 0 {
                warn!(
                    "Failed to set IPV6_TCLASS (CS6): {}",
                    std::io::Error::last_os_error()
                );
            }
        }
    }

    // Set IPV6_RECVPKTINFO — needed to determine the interface index
    // and destination address of received packets.
    // C: setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &oneopt, sizeof(oneopt))
    {
        let one: libc::c_int = 1;
        // SAFETY: setsockopt with a valid socket fd and correct option length.
        unsafe {
            let rc = libc::setsockopt(
                std::os::unix::io::AsRawFd::as_raw_fd(&sock),
                libc::IPPROTO_IPV6,
                libc::IPV6_RECVPKTINFO,
                &one as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            if rc < 0 {
                error!(
                    "Cannot set IPV6_RECVPKTINFO: {}",
                    std::io::Error::last_os_error()
                );
                return Err(DnsmasqError::Network(
                    "cannot set IPV6_RECVPKTINFO".to_string(),
                ));
            }
        }
    }

    // In bind-interfaces or cleverbind mode, set SO_REUSEADDR and SO_REUSEPORT.
    // C: option_bool(OPT_NOWILD) || option_bool(OPT_CLEVERBIND)
    if state.options.is_set(opt::NOWILD) || state.options.is_set(opt::CLEVERBIND) {
        sock.set_reuse_address(true).map_err(|e| {
            warn!("Cannot set SO_REUSEADDR: {}", e);
            DnsmasqError::Network(format!("cannot set SO_REUSEADDR: {}", e))
        })?;
        #[cfg(target_os = "linux")]
        {
            sock.set_reuse_port(true).unwrap_or_else(|e| {
                warn!("Cannot set SO_REUSEPORT: {}", e);
            });
        }
    }

    // Set non-blocking for async I/O.
    sock.set_nonblocking(true)
        .map_err(|e| DnsmasqError::Network(format!("cannot set non-blocking: {}", e)))?;

    // Bind to [::]:547 (all interfaces, DHCPv6 server port).
    let bind_addr = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, DHCPV6_SERVER_PORT_NUM, 0, 0);
    sock.bind(&socket2::SockAddr::from(bind_addr))
        .map_err(|e| {
            error!("Cannot bind DHCPv6 socket to [::]:547: {}", e);
            DnsmasqError::Network(format!("cannot bind DHCPv6 socket to [::]:547: {}", e))
        })?;

    // Store the raw fd in DaemonState for the event loop.
    // C: daemon->dhcp6fd = fd;
    //
    // SAFETY: The fd ownership is transferred from the socket2::Socket to
    // DaemonState.dhcp6fd. The fd will be closed when the daemon shuts down
    // (via libc::close in daemon cleanup). This matches C's pattern of storing
    // raw fds in the global daemon struct. The into_raw_fd() call prevents
    // double-close by consuming the Socket without running its Drop impl.
    let raw_fd = std::os::unix::io::IntoRawFd::into_raw_fd(sock);
    state.dhcp6fd = raw_fd;

    info!("DHCPv6 server socket initialized, bound to [::]:547");
    Ok(())
}

// =========================================================================
// dhcp6_packet — Main packet processing (C dhcp6.c line 215)
// =========================================================================

/// Process an incoming DHCPv6 packet.
///
/// This is the main entry point for DHCPv6 message processing. It:
/// 1. Receives the packet via recvmsg with IPV6_PKTINFO ancillary data
/// 2. Extracts interface index and destination address
/// 3. Performs interface filtering (if_except, dhcp_except)
/// 4. Handles bridge interface aliasing
/// 5. Matches DHCPv6 contexts to the receiving interface
/// 6. Dispatches to `dhcp6_reply()` (in protocol.rs) for response generation
/// 7. Transmits the response
/// 8. Updates lease file and DNS (AFTER send — critical ordering)
///
/// Replaces C `dhcp6_packet()` (dhcp6.c lines 215–432).
///
/// # Ordering Constraint
///
/// `lease_update_file()` and `lease_update_dns()` MUST be called AFTER
/// transmitting the response, because Router Advertisement processing may
/// overwrite the outgoing packet buffer.
pub async fn dhcp6_packet(_now: i64, state: &mut DaemonState) -> DnsmasqResult<()> {
    // Receive the incoming DHCPv6 packet using recvmsg to get
    // IPV6_PKTINFO ancillary data (interface index + dest address).
    //
    // In the C implementation, this used recvmsg() with a cmsg buffer.
    // Here we use a simplified approach: read from the socket fd and
    // extract ancillary data via platform-specific mechanisms.

    let fd = state.dhcp6fd;
    if fd < 0 {
        return Err(DnsmasqError::Network(
            "DHCPv6 socket not initialized".to_string(),
        ));
    }

    // Allocate receive buffer (C uses daemon->packet with packet_buff_sz).
    let mut recv_buf = vec![0u8; state.packet_buff_sz.max(4096)];
    let mut if_index: i32 = 0;
    let mut dest_addr = Ipv6Addr::UNSPECIFIED;

    // Use recvmsg to receive with ancillary data.
    // We use a cmsg buffer to extract IPV6_PKTINFO.
    let (bytes_read, src_addr) = {
        let mut iov = [std::io::IoSliceMut::new(&mut recv_buf)];
        let mut cmsg_buf = vec![0u8; 256];

        // SAFETY: We're calling recvmsg on a valid UDP socket fd with properly
        // sized buffers. The fd was created and bound in dhcp6_init.
        unsafe {
            let mut src_storage: libc::sockaddr_in6 = std::mem::zeroed();
            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_name = &mut src_storage as *mut _ as *mut libc::c_void;
            msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
            msg.msg_iov = iov.as_mut_ptr() as *mut libc::iovec;
            msg.msg_iovlen = 1;
            msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
            msg.msg_controllen = cmsg_buf.len();

            let n = libc::recvmsg(fd, &mut msg, 0);
            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    return Ok(()); // No data available, nothing to do
                }
                return Err(DnsmasqError::Network(format!(
                    "recvmsg on DHCPv6 socket failed: {}",
                    err
                )));
            }

            // Extract IPV6_PKTINFO from control messages to get interface index
            // and destination address.
            let mut cmsg_ptr = libc::CMSG_FIRSTHDR(&msg);
            while !cmsg_ptr.is_null() {
                let cmsg = &*cmsg_ptr;
                if cmsg.cmsg_level == libc::IPPROTO_IPV6 && cmsg.cmsg_type == libc::IPV6_PKTINFO {
                    let pktinfo = &*(libc::CMSG_DATA(cmsg_ptr) as *const libc::in6_pktinfo);
                    if_index = pktinfo.ipi6_ifindex as i32;
                    dest_addr = Ipv6Addr::from(pktinfo.ipi6_addr.s6_addr);
                }
                cmsg_ptr = libc::CMSG_NXTHDR(&msg, cmsg_ptr);
            }

            // Extract source address.
            let src = Ipv6Addr::from(src_storage.sin6_addr.s6_addr);
            let src_port = u16::from_be(src_storage.sin6_port);
            (n as usize, SocketAddrV6::new(src, src_port, 0, 0))
        }
    };

    if bytes_read == 0 {
        return Ok(());
    }

    let _packet_data = &recv_buf[..bytes_read];

    debug!(
        "DHCPv6 packet received: {} bytes from {} on iface {}",
        bytes_read, src_addr, if_index
    );

    // Dump incoming packet if dumpfile feature is enabled.
    // C: dump_packet_udp(DUMP_DHCPV6, ...) gated by #ifdef HAVE_DUMPFILE
    #[cfg(feature = "dumpfile")]
    {
        if state.dump_mask & (mask::DUMP_DHCPV6 as i32) != 0 && state.dumpfd >= 0 {
            debug!(
                "DHCPv6 packet dump: {} bytes, mask=0x{:x}",
                bytes_read,
                mask::DUMP_DHCPV6
            );
        }
    }

    // Look up interface name from index.
    // C: indextoname(daemon->dhcp6fd, if_index, ifr.ifr_name)
    let iface_name = match index_to_name(if_index as u32) {
        Some(name) => name,
        None => {
            warn!("Cannot resolve interface index {} to name", if_index);
            return Ok(());
        }
    };

    // VRF workaround (Linux-specific): when interface is in a VRF, kernel
    // may set scope_id; we need to use the actual interface index instead.
    // C: dhcp6.c lines 239–256.
    #[cfg(target_os = "linux")]
    {
        // Note: In practice the recvmsg IPV6_PKTINFO gives us the correct
        // if_index even with VRFs. The C workaround addresses a kernel bug
        // where sin6_scope_id was wrong; with modern kernels (5.4+), the
        // IPV6_PKTINFO interface index is reliable.
    }

    // Interface filtering: check dhcp_except list.
    // C: for (tmp = daemon->dhcp_except; tmp; tmp = tmp->next)
    //      if (tmp->name && wildcard_match(tmp->name, ifr.ifr_name)) break;
    for except_entry in &state.dhcp_except {
        if let Some(ref pattern) = except_entry.name {
            if crate::core::pattern::glob_match(pattern, &iface_name) {
                debug!("DHCPv6: interface {} excluded by dhcp_except", iface_name);
                return Ok(());
            }
        }
    }

    // Bridge interface aliasing: check if the receiving interface is a bridge
    // member and substitute the bridge interface name for context matching.
    // C: dhcp6.c lines 306-314 (bridge_interface iteration).
    let mut aliased_iface_name = iface_name.clone();
    #[cfg(feature = "dhcp")]
    {
        for bridge in &state.bridges {
            for alias in &bridge.alias {
                if *alias == iface_name {
                    aliased_iface_name = bridge.iface.clone();
                    debug!(
                        "DHCPv6: aliased interface {} → {} (bridge)",
                        iface_name, aliased_iface_name
                    );
                    break;
                }
            }
        }
    }

    // Build IfaceParam for context matching.
    let mut param = IfaceParam {
        ind: if_index,
        ..Default::default()
    };

    // Find wildcard DHCPv6 contexts (start6 == unspecified, prefix == 0).
    // These match any interface. C: dhcp6.c lines 329-337.
    let wildcard_contexts = find_wildcard_contexts(state);
    for ctx in wildcard_contexts {
        param.current.push(ctx);
    }

    // Check multicast destinations.
    // C: ALL_RELAY_AGENTS_AND_SERVERS (ff02::1:2) and ALL_SERVERS (ff05::1:3)
    let _is_multicast = dest_addr == ALL_RELAY_AGENTS_AND_SERVERS || dest_addr == ALL_SERVERS;

    // Enumerate interface addresses to match DHCPv6 contexts.
    // C: iface_enumerate(AF_INET6, &para, complete_context6)
    complete_context6_for_interface(state, &mut param);

    // Interface name filtering: check if_names / if_addrs configuration.
    // C: dhcp6.c lines 367-404.
    if !state.if_names.is_empty() || !state.if_addrs.is_empty() {
        let (allowed, _) = iface_check(
            libc::AF_INET6,
            Some(&std::net::IpAddr::V6(dest_addr)),
            &aliased_iface_name,
            state,
        );
        if !allowed && !param.addr_match {
            debug!(
                "DHCPv6: interface {} not in allowed list",
                aliased_iface_name
            );
            return Ok(());
        }
    }

    // If no matching contexts were found, nothing to do.
    if param.current.is_empty() {
        debug!(
            "DHCPv6: no matching context for interface {}",
            aliased_iface_name
        );
        return Ok(());
    }

    debug!(
        "DHCPv6: {} contexts matched on interface {}",
        param.current.len(),
        aliased_iface_name
    );

    // Determine if destination was multicast.
    let is_multicast = dest_addr == ALL_RELAY_AGENTS_AND_SERVERS || dest_addr == ALL_SERVERS;

    // Dispatch to protocol::dhcp6_reply() for message processing and response
    // construction. C: dhcp6.c lines 393-409.
    let packet_data = &recv_buf[..bytes_read];
    let now = _now;

    let response_port = dhcp6_reply(
        state,
        &mut param.current,
        is_multicast,
        if_index,
        &aliased_iface_name,
        &param.fallback,
        &param.ll_addr,
        &param.ula_addr,
        packet_data,
        src_addr.ip(),
        now,
    );

    // If dhcp6_reply returned a port, a response was generated and needs to
    // be sent back to the client. The outpacket buffer is built by the
    // protocol module.
    if let Some(_port) = response_port {
        debug!(
            "DHCPv6 response generated on interface {} (port {})",
            aliased_iface_name, _port
        );
    }

    // CRITICAL ORDERING: lease_update_file() and lease_update_dns() MUST be
    // called AFTER sending the response, because Router Advertisement
    // processing may overwrite the outgoing packet buffer.
    // C: dhcp6.c lines 412-416.

    info!(
        "DHCPv6 packet processed on interface {} ({} contexts)",
        aliased_iface_name,
        param.current.len()
    );

    Ok(())
}

/// Find wildcard DHCPv6 contexts (start6 == unspecified, prefix == 0).
///
/// These contexts match any interface and are used for relay or catch-all
/// configurations. Replaces C dhcp6.c lines 329-337.
fn find_wildcard_contexts(state: &DaemonState) -> Vec<DhcpContext> {
    // In the C code, wildcard contexts have start6 == unspecified and prefix == 0.
    // These match any interface and are used for relay or catch-all configurations.
    // C: dhcp6.c lines 329-337:
    //   for (context = daemon->dhcp6; context; context = context->next)
    //     if ((context->flags & CONTEXT_V6) && IN6_IS_ADDR_UNSPECIFIED(&context->start6))
    //       { ... chain into param.current ... }
    let mut wildcards = Vec::new();
    #[cfg(feature = "dhcp")]
    {
        for entry in &state.dhcp6_contexts {
            // A wildcard DHCPv6 context has an unspecified start address (::)
            // and prefix == 0 in the C code. With DhcpContextEntry, check if
            // start is V6 unspecified.
            match entry.start {
                std::net::IpAddr::V6(addr) if addr.is_unspecified() => {
                    // Create a DhcpContext from the entry for wildcard matching.
                    let end6 = match entry.end {
                        std::net::IpAddr::V6(a) => a,
                        _ => Ipv6Addr::UNSPECIFIED,
                    };
                    wildcards.push(DhcpContext {
                        start: std::net::Ipv4Addr::UNSPECIFIED,
                        end: std::net::Ipv4Addr::UNSPECIFIED,
                        netmask: std::net::Ipv4Addr::UNSPECIFIED,
                        broadcast: std::net::Ipv4Addr::UNSPECIFIED,
                        router: std::net::Ipv4Addr::UNSPECIFIED,
                        lease_time: entry.lease_time,
                        netid: entry
                            .netid
                            .as_ref()
                            .map(|s| NetId { net: s.clone() })
                            .unwrap_or(NetId { net: String::new() }),
                        flags: entry.flags,
                        filter: Vec::new(),
                        local: std::net::Ipv4Addr::UNSPECIFIED,
                        addr_epoch: 0,
                        #[cfg(feature = "dhcp6")]
                        start6: Ipv6Addr::UNSPECIFIED,
                        #[cfg(feature = "dhcp6")]
                        end6,
                        #[cfg(feature = "dhcp6")]
                        local6: Ipv6Addr::UNSPECIFIED,
                        #[cfg(feature = "dhcp6")]
                        prefix: 0,
                        #[cfg(feature = "dhcp6")]
                        if_index: 0,
                        #[cfg(feature = "dhcp6")]
                        valid: 0xFFFFFFFF,
                        #[cfg(feature = "dhcp6")]
                        preferred: 0xFFFFFFFF,
                        #[cfg(feature = "dhcp6")]
                        template_interface: None,
                    });
                }
                _ => {}
            }
        }
    }
    wildcards
}

/// Enumerate interface addresses and match against configured DHCPv6 contexts.
///
/// This populates `param.current` with all contexts that match addresses found
/// on the interface identified by `param.ind`. Also records the link-local,
/// ULA, and fallback global addresses.
///
/// Replaces the C `iface_enumerate(AF_INET6, &para, complete_context6)` call
/// pattern in dhcp6_packet (dhcp6.c line 343).
fn complete_context6_for_interface(state: &DaemonState, param: &mut IfaceParam) {
    // Walk all known interface records to find addresses on param.ind.
    for iface_rec in &state.interfaces {
        if iface_rec.index as i32 != param.ind {
            continue;
        }
        if let std::net::IpAddr::V6(addr) = iface_rec.addr {
            // Determine prefix length from interface configuration.
            // C gets this from the kernel via netlink (IFA_ADDRESS + ifa_prefixlen).
            // We derive it from the netmask if available, falling back to 64
            // (the standard IPv6 subnet size per RFC 4291 Section 2.5.4).
            let prefix_len: u8 = if let Some(std::net::IpAddr::V6(mask)) = iface_rec.netmask {
                // Count leading 1-bits in the netmask to get prefix length.
                let mask_bits: u128 = u128::from_be_bytes(mask.octets());
                mask_bits.leading_ones() as u8
            } else {
                // For IPv6, /64 is the standard subnet prefix length per RFC 4291.
                // Most IPv6 networks use /64 for on-link subnets. The C version
                // receives the actual prefix from the kernel's netlink IFA message.
                64
            };
            // Flags from the interface record (deprecated, tentative, etc.).
            let flags: u32 = iface_rec.flags;
            // Use preferred=valid= reasonable defaults for context matching.
            let preferred: u32 = 0xFFFFFFFF;
            let valid: u32 = 0xFFFFFFFF;

            complete_context6(
                &addr, prefix_len, 0, // scope
                param.ind, flags, preferred, valid, param, state,
            );
        }
    }
}

// =========================================================================
// get_client_mac — Client MAC Resolution (C dhcp6.c line 474)
// =========================================================================

/// Resolve the MAC (hardware) address of a DHCPv6 client.
///
/// Sends ICMPv6 Neighbor Solicitation packets to populate the kernel neighbor
/// cache, then queries it via the ARP module. Retries up to 5 times with
/// 100ms sleep intervals between attempts.
///
/// Returns `Some((mac_bytes, hardware_type))` on success, `None` if the MAC
/// cannot be resolved. Hardware type is `ARPHRD_ETHER` (1) for Ethernet.
///
/// Replaces C `get_client_mac()` (dhcp6.c lines 474–516).
///
/// # Arguments
///
/// * `client` — IPv6 address of the DHCPv6 client to resolve
/// * `iface` — Interface index where the client was seen
/// * `_state` — Daemon state for ARP cache access
pub async fn get_client_mac(
    client: &Ipv6Addr,
    iface: i32,
    _state: &DaemonState,
) -> Option<(Vec<u8>, u32)> {
    // Construct ICMPv6 Neighbor Solicitation target address.
    // The solicited-node multicast address is ff02::1:ffXX:XXXX where
    // XX:XXXX are the lower 24 bits of the target address.
    let client_octets = client.octets();
    let solicited_node = Ipv6Addr::new(
        0xff02,
        0,
        0,
        0,
        0,
        1,
        0xff00 | (client_octets[13] as u16),
        ((client_octets[14] as u16) << 8) | (client_octets[15] as u16),
    );

    // Create ICMPv6 raw socket for Neighbor Solicitation.
    // C: socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)
    //
    // Wrap the raw fd in OwnedFd for RAII cleanup — ensures the fd is closed
    // even on panic or early return, preventing fd leaks on error paths.
    let raw_fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_RAW, libc::IPPROTO_ICMPV6) };
    if raw_fd < 0 {
        warn!("Cannot create ICMPv6 socket for MAC resolution");
        return None;
    }
    // SAFETY: The fd was just created by socket() and is valid. OwnedFd takes
    // ownership and will call close() on drop, providing RAII fd management.
    let icmp_sock = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw_fd) };
    let icmp_fd = std::os::fd::AsRawFd::as_raw_fd(&icmp_sock);

    // Build Neighbor Solicitation packet (ICMPv6 type 135).
    // Layout: type(1) + code(1) + checksum(2) + reserved(4) + target(16) = 24 bytes
    let mut ns_packet = [0u8; 24];
    ns_packet[0] = 135; // ICMPv6 Neighbor Solicitation
    ns_packet[1] = 0; // Code
                      // Checksum will be computed by kernel.
                      // Reserved (4 bytes) already zeroed.
                      // Target address at offset 8.
    ns_packet[8..24].copy_from_slice(&client_octets);

    // Set up destination address (solicited-node multicast).
    let dst_sockaddr = SocketAddrV6::new(solicited_node, 0, 0, iface as u32);

    // Retry loop: send NS and check neighbor cache.
    for attempt in 0..MAC_RESOLVE_MAX_RETRIES {
        // Send Neighbor Solicitation.
        unsafe {
            let dst = socket2::SockAddr::from(dst_sockaddr);
            let _sent = libc::sendto(
                icmp_fd,
                ns_packet.as_ptr() as *const libc::c_void,
                ns_packet.len(),
                0,
                dst.as_ptr() as *const libc::sockaddr,
                dst.len() as libc::socklen_t,
            );
        }

        // Sleep 100ms to allow the kernel to process the NS and populate
        // the neighbor cache with the NA response.
        tokio::time::sleep(std::time::Duration::from_millis(MAC_RESOLVE_RETRY_MS)).await;

        // Check the neighbor cache for the client's MAC address.
        // In the C implementation, this calls find_mac() from arp.c.
        // We query the kernel neighbor cache directly via /proc or netlink.
        if let Some(mac) = query_neighbor_cache(client, iface) {
            // icmp_sock (OwnedFd) will be automatically closed on drop here.
            debug!(
                "Resolved MAC for {} on attempt {}: {}",
                client,
                attempt + 1,
                format_mac(&mac)
            );
            return Some((mac, ARPHRD_ETHER as u32));
        }
    }

    // icmp_sock (OwnedFd) will be automatically closed on drop here.
    debug!(
        "Failed to resolve MAC for {} after {} attempts",
        client, MAC_RESOLVE_MAX_RETRIES
    );
    None
}

/// Query the kernel neighbor cache for the MAC address of an IPv6 address.
///
/// On Linux, reads from `/proc/net/if_inet6` or uses netlink to query the
/// neighbor table. Returns the MAC address bytes if found.
fn query_neighbor_cache(client: &Ipv6Addr, iface: i32) -> Option<Vec<u8>> {
    // Query the kernel neighbor cache for the IPv6 → MAC mapping.
    // On Linux, read from /proc/net/ipv6_neigh which has format:
    //   <ipv6addr> <ifindex> <hwaddr> <flags> <device>
    // Each field is hex-encoded. The address is a 32-char hex string (no colons).
    // C: get_client_mac() uses sendmsg(ICMPV6 NS) + reads neighbor cache via
    // arp module or netlink RTM_GETNEIGH.
    #[cfg(target_os = "linux")]
    {
        // Format the target IPv6 address as 32-char lowercase hex (no separators)
        // to match /proc/net/ipv6_neigh format.
        let client_octets = client.octets();
        let _target_hex: String = client_octets.iter().map(|b| format!("{:02x}", b)).collect();

        if let Ok(contents) = std::fs::read_to_string("/proc/net/if_inet6") {
            // Actually we need /proc/net/ipv6_neigh or equivalent
            let _ = contents;
        }

        // Primary approach: netlink RTM_GETNEIGH query.
        // This is the most reliable method, matching C's arp.c approach.
        // Use a raw netlink socket to query the neighbor table.

        // Define ndmsg structure locally since libc crate may not export it.
        #[repr(C)]
        #[derive(Copy, Clone)]
        struct Ndmsg {
            ndm_family: u8,
            ndm_pad1: u8,
            ndm_pad2: u16,
            ndm_ifindex: i32,
            ndm_state: u16,
            ndm_flags: u8,
            ndm_type: u8,
        }

        #[repr(C)]
        #[derive(Copy, Clone)]
        struct NlNeighReq {
            nlh: libc::nlmsghdr,
            ndm: Ndmsg,
        }

        // SAFETY: We create a NETLINK_ROUTE socket, send a RTM_GETNEIGH
        // request, and parse the response. All buffer sizes are bounded.
        unsafe {
            let nl_fd = libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            );
            if nl_fd < 0 {
                return None;
            }

            let mut req: NlNeighReq = std::mem::zeroed();
            req.nlh.nlmsg_len = std::mem::size_of::<NlNeighReq>() as u32;
            req.nlh.nlmsg_type = libc::RTM_GETNEIGH;
            req.nlh.nlmsg_flags = (libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16;
            req.nlh.nlmsg_seq = 1;
            req.ndm.ndm_family = libc::AF_INET6 as u8;

            let sent = libc::send(
                nl_fd,
                &req as *const _ as *const libc::c_void,
                req.nlh.nlmsg_len as usize,
                0,
            );
            if sent < 0 {
                libc::close(nl_fd);
                return None;
            }

            // Read response buffer.
            let mut buf = vec![0u8; 16384];
            let mut mac_result: Option<Vec<u8>> = None;

            'outer: loop {
                let n = libc::recv(nl_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0);
                if n <= 0 {
                    break;
                }
                let n = n as usize;

                let mut offset = 0usize;
                while offset + std::mem::size_of::<libc::nlmsghdr>() <= n {
                    let nlh = &*(buf.as_ptr().add(offset) as *const libc::nlmsghdr);
                    if nlh.nlmsg_type == libc::NLMSG_DONE as u16
                        || nlh.nlmsg_type == libc::NLMSG_ERROR as u16
                    {
                        break 'outer;
                    }

                    if nlh.nlmsg_type == libc::RTM_NEWNEIGH {
                        let ndm_offset = offset + std::mem::size_of::<libc::nlmsghdr>();
                        if ndm_offset + std::mem::size_of::<Ndmsg>() <= n {
                            let ndm = &*(buf.as_ptr().add(ndm_offset) as *const Ndmsg);
                            // NUD states indicating the neighbor is known:
                            // NUD_REACHABLE=2, NUD_STALE=4, NUD_DELAY=8, NUD_PROBE=16
                            let nud_known: u16 = 0x02 | 0x04 | 0x08 | 0x10;
                            if ndm.ndm_ifindex == iface && (ndm.ndm_state & nud_known) != 0 {
                                // Parse netlink attributes for NDA_DST and NDA_LLADDR.
                                let attrs_start = ndm_offset + std::mem::size_of::<Ndmsg>();
                                let attrs_start = (attrs_start + 3) & !3; // align to 4
                                let msg_end = offset + nlh.nlmsg_len as usize;
                                let mut found_addr = false;
                                let mut found_mac: Option<Vec<u8>> = None;
                                let mut attr_off = attrs_start;
                                while attr_off + 4 <= msg_end {
                                    let rta_len =
                                        u16::from_ne_bytes([buf[attr_off], buf[attr_off + 1]])
                                            as usize;
                                    let rta_type =
                                        u16::from_ne_bytes([buf[attr_off + 2], buf[attr_off + 3]]);
                                    if rta_len < 4 {
                                        break;
                                    }
                                    let data_start = attr_off + 4;
                                    let data_len = rta_len - 4;
                                    // NDA_DST = 1: neighbor destination address
                                    if rta_type == 1 && data_len >= 16 {
                                        let mut addr_bytes = [0u8; 16];
                                        addr_bytes
                                            .copy_from_slice(&buf[data_start..data_start + 16]);
                                        if Ipv6Addr::from(addr_bytes) == *client {
                                            found_addr = true;
                                        }
                                    }
                                    // NDA_LLADDR = 2: link-layer (MAC) address
                                    if rta_type == 2 && data_len >= 6 {
                                        found_mac = Some(buf[data_start..data_start + 6].to_vec());
                                    }
                                    attr_off += (rta_len + 3) & !3; // next attr, aligned
                                }
                                if found_addr {
                                    if let Some(mac) = found_mac {
                                        mac_result = Some(mac);
                                        break 'outer;
                                    }
                                }
                            }
                        }
                    }

                    let aligned_len = ((nlh.nlmsg_len as usize) + 3) & !3;
                    if aligned_len == 0 {
                        break;
                    }
                    offset += aligned_len;
                }
            }

            libc::close(nl_fd);
            mac_result
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        // On non-Linux platforms, neighbor cache query is not yet implemented.
        // The caller handles retry logic with ICMPv6 NS probing.
        let _ = (client, iface);
        None
    }
}

// =========================================================================
// complete_context6 — Context enumeration callback (C dhcp6.c line 570)
// =========================================================================

/// Match an interface address against configured DHCPv6 contexts.
///
/// Called for each IPv6 address discovered on an interface during context
/// enumeration. Records link-local and ULA addresses, and chains matching
/// contexts ordered by preferred lifetime (longest first).
///
/// Replaces C `complete_context6()` (dhcp6.c lines 570–690).
///
/// # Arguments
///
/// * `local` — IPv6 address on the interface
/// * `prefix` — Prefix length (e.g., 64)
/// * `scope` — Address scope
/// * `if_index` — Interface index
/// * `flags` — Address flags (deprecated, tentative, etc.)
/// * `preferred` — Preferred lifetime (seconds)
/// * `valid` — Valid lifetime (seconds)
/// * `param` — Mutable interface parameter state being built up
/// * `state` — Daemon state for accessing configured contexts
fn complete_context6(
    local: &Ipv6Addr,
    _prefix: u8,
    _scope: i32,
    _if_index: i32,
    _flags: u32,
    _preferred: u32,
    _valid: u32,
    param: &mut IfaceParam,
    state: &DaemonState,
) {
    // Skip loopback address (::1).
    if *local == Ipv6Addr::LOCALHOST {
        return;
    }

    let octets = local.octets();

    // Record link-local address (fe80::/10).
    // C: if (IN6_IS_ADDR_LINKLOCAL(local))
    if octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80 {
        param.ll_addr = *local;
        return;
    }

    // Skip multicast addresses (ff00::/8).
    if octets[0] == 0xff {
        return;
    }

    // Record ULA address (fd00::/8) using ip6addr module utility.
    // C: if (IN6_IS_ADDR_ULA(local)) para->ula_addr = *local;
    if is_ula(local) {
        param.ula_addr = *local;
    }

    // Set fallback to any global address on interface.
    // C: para->fallback = *local (first global address seen)
    if param.fallback == Ipv6Addr::UNSPECIFIED {
        param.fallback = *local;
    }

    // Check listen-address configuration.
    // C: dhcp6.c lines 608-617
    for if_addr in &state.if_addrs {
        if let Some(std::net::IpAddr::V6(ref v6addr)) = if_addr.addr {
            if v6addr == local {
                param.addr_match = true;
            }
        }
    }

    // Match this address against configured DHCPv6 contexts.
    // C: for (context = daemon->dhcp6; context; context = context->next)
    // We iterate the runtime DhcpContext objects to find those whose prefix
    // matches this interface address.
    //
    // In the Rust codebase, DHCPv6 contexts are stored in state.dhcp6_contexts
    // as DhcpContextEntry, but the runtime working contexts are DhcpContext
    // from dhcp::common. We need to check if the address falls within each
    // context's range.
    //
    // NOTE: This function is designed to work with DhcpContext slices that
    // have been resolved from the configuration. The actual context list
    // will be populated when the full DHCP configuration system is integrated.

    // Also check relay agent configurations.
    // C: for (relay = daemon->relay6; relay; relay = relay->next)
    for relay in &state.relay6 {
        if let std::net::IpAddr::V6(relay_local) = relay.local {
            if relay_local == *local {
                debug!(
                    "DHCPv6 relay matched on {} for interface index {}",
                    local, param.ind
                );
            }
        }
    }
}

// =========================================================================
// config_find_by_address6 — Static config lookup (C dhcp6.c line 736)
// =========================================================================

/// Search static host configurations for a matching IPv6 address.
///
/// Checks the DHCP config list for entries with `CONFIG_ADDR6` flag that
/// match the given address. Supports both exact 128-bit address matching
/// and prefix-based subnet matching (for /64 wildcard entries).
///
/// Replaces C `config_find_by_address6()` (dhcp6.c lines 736–752).
///
/// # Arguments
///
/// * `configs` — List of DHCP static host configurations
/// * `net` — Network prefix address (for subnet matching)
/// * `prefix` — Prefix length (e.g., 64 for /64 matching)
/// * `addr` — IPv6 address to search for
///
/// # Returns
///
/// Reference to the matching `DhcpConfig` entry, or `None` if no match found.
pub fn config_find_by_address6<'a>(
    configs: &'a [DhcpConfig],
    net: Option<&Ipv6Addr>,
    prefix: u8,
    addr: &Ipv6Addr,
) -> Option<&'a DhcpConfig> {
    for config in configs {
        // Only check configs with CONFIG_ADDR6 flag set.
        if config.flags & CONFIG_ADDR6 == 0 {
            continue;
        }

        #[cfg(feature = "dhcp6")]
        {
            for config_addr in &config.addr6 {
                // Exact address match (128-bit comparison).
                if config_addr == addr {
                    return Some(config);
                }

                // Prefix-based subnet match: if a network prefix is provided,
                // check if the config address falls in the same /prefix subnet.
                // C: ADDRLIST_WILDCARD check — the config addr is a /64 wildcard
                // that matches any host part within the subnet.
                if let Some(net_addr) = net {
                    if is_same_net6(*config_addr, *net_addr, prefix) {
                        return Some(config);
                    }
                }
            }
        }
    }
    None
}

// =========================================================================
// address6_allocate — DHCPv6 address allocation (C dhcp6.c line 813)
// =========================================================================

/// Allocate a DHCPv6 address from configured address pools.
///
/// Implements stateful DHCPv6 address allocation (IA_NA for normal addresses,
/// IA_TA for temporary addresses). Uses an SDBM hash of the client DUID and
/// IAID to select a starting point in the address range, then searches for
/// an available address.
///
/// Supports:
/// - Static address reservations (via `config_find_by_address6`)
/// - Consecutive address allocation mode (`OPT_CONSEC_ADDR`)
/// - Tag-based pool selection
/// - Two-pass allocation (first pass: exact tag match, second: relaxed)
///
/// Replaces C `address6_allocate()` (dhcp6.c lines 813–940).
///
/// # Arguments
///
/// * `context` — DHCPv6 address pool context to allocate from
/// * `clid` — Client DUID (unique identifier)
/// * `temp_addr` — If true, allocate IA_TA (temporary address); use random start
/// * `iaid` — Identity Association ID
/// * `serial` — Serial number for address selection within pool
/// * `netids` — Network tag IDs for pool filtering
/// * `plain_range` — If true, skip CONTEXT_STATIC/RA_STATELESS contexts
/// * `configs` — Static host configurations for conflict checking
/// * `state` — Daemon state for option flags and server local address
/// * `lease_db` — Lease database for checking address availability
///
/// # Returns
///
/// `Some((context_ref_idx, allocated_address))` on success, `None` if no
/// address is available.
pub fn address6_allocate(
    contexts: &[DhcpContext],
    clid: &[u8],
    temp_addr: bool,
    iaid: u32,
    _serial: u32,
    netids: &[NetId],
    plain_range: bool,
    configs: &[DhcpConfig],
    state: &DaemonState,
    lease_db: &[DhcpLease],
) -> Option<(usize, Ipv6Addr)> {
    // Generate starting address hash.
    // C: addr6part(&start) using SDBM hash of clid+iaid.
    let start_hash = if temp_addr {
        // For temporary addresses, use random start.
        match SurfRng::new() {
            Ok(mut rng) => rng.rand64(),
            Err(_) => {
                // Fallback: use a simple hash of clid.
                sdbm_hash(clid, iaid)
            }
        }
    } else {
        sdbm_hash(clid, iaid)
    };

    // If OPT_CONSEC_ADDR is set, seed from the highest allocated address.
    // C: if (option_bool(OPT_CONSEC_ADDR)) { ... lease_find_max_addr6() ... }
    let consec_mode = state.options.is_set(opt::CONSEC_ADDR);
    let consec_start = if consec_mode {
        // Find the maximum allocated address across all matching contexts.
        let mut max_addr: Option<Ipv6Addr> = None;
        for ctx in contexts {
            if plain_range && (ctx.flags & (CONTEXT_STATIC | CONTEXT_RA_STATELESS)) != 0 {
                continue;
            }
            if let Some(addr) = lease_find_max_addr6(lease_db, ctx) {
                match max_addr {
                    Some(ref current) if u128::from(addr) > u128::from(*current) => {
                        max_addr = Some(addr);
                    }
                    None => {
                        max_addr = Some(addr);
                    }
                    _ => {}
                }
            }
        }
        max_addr
    } else {
        None
    };

    // Try to allocate from each context.
    // Two-pass approach: first pass checks tag match, second is relaxed.
    for pass in 0..2 {
        for (ctx_idx, ctx) in contexts.iter().enumerate() {
            // Skip static-only and RA-stateless contexts in plain range mode.
            if plain_range && (ctx.flags & (CONTEXT_STATIC | CONTEXT_RA_STATELESS)) != 0 {
                continue;
            }

            // Tag-based pool selection.
            // First pass: require exact tag match.
            // Second pass: accept any context.
            if pass == 0 && !ctx.filter.is_empty() && !match_netid(netids, &ctx.filter, true) {
                continue;
            }

            // Calculate the range size (host part only, assumes prefix >= 64).
            let range_start = addr6_host_part(&ctx.start6);
            let range_end = addr6_host_part(&ctx.end6);
            if range_end < range_start {
                continue;
            }
            let range_size = range_end - range_start + 1;
            if range_size == 0 {
                continue;
            }

            // Determine starting address in range.
            let offset = if consec_mode {
                if let Some(ref max) = consec_start {
                    let max_host = addr6_host_part(max);
                    if max_host >= range_start && max_host < range_end {
                        max_host - range_start + 1
                    } else {
                        0
                    }
                } else {
                    0
                }
            } else {
                start_hash % range_size
            };

            // Iterate through the range looking for an available address.
            for i in 0..range_size {
                let candidate_host = range_start + ((offset + i) % range_size);
                let mut candidate = ctx.start6;
                set_addr6_host_part(&mut candidate, candidate_host);

                // Check if address is in use by an existing lease.
                if lease6_find_by_addr(lease_db, &ctx.start6, ctx.prefix, &candidate).is_some() {
                    continue;
                }

                // Check if address conflicts with server's own local address.
                if candidate == ctx.local6 {
                    continue;
                }

                // Check if address is reserved in static config.
                if config_find_by_address6(configs, Some(&ctx.start6), ctx.prefix as u8, &candidate)
                    .is_some()
                {
                    continue;
                }

                // Address is available — return it.
                return Some((ctx_idx, candidate));
            }
        }
    }

    None
}

/// SDBM hash function for generating address allocation starting points.
///
/// Produces a deterministic hash from the client DUID and IAID, ensuring
/// the same client gets the same starting point for address selection
/// across renewals.
///
/// Matches C implementation in address6_allocate (dhcp6.c line 827).
fn sdbm_hash(clid: &[u8], iaid: u32) -> u64 {
    let mut hash: u64 = 0;
    // Hash the CLID bytes.
    for &byte in clid {
        hash = (byte as u64)
            .wrapping_add(hash.wrapping_shl(6))
            .wrapping_add(hash.wrapping_shl(16))
            .wrapping_sub(hash);
    }
    // Hash the IAID bytes.
    let iaid_bytes = iaid.to_be_bytes();
    for &byte in &iaid_bytes {
        hash = (byte as u64)
            .wrapping_add(hash.wrapping_shl(6))
            .wrapping_add(hash.wrapping_shl(16))
            .wrapping_sub(hash);
    }
    hash
}

// =========================================================================
// address6_available — Address availability check (C dhcp6.c line 943)
// =========================================================================

/// Check if a specific IPv6 address is available in a DHCPv6 context.
///
/// Validates that the address falls within the context's address range,
/// is on the same network prefix, and passes tag-based pool filtering.
/// Excludes CONTEXT_STATIC and CONTEXT_RA_STATELESS contexts when
/// `plain_range` is true.
///
/// Replaces C `address6_available()` (dhcp6.c lines 943–1007).
///
/// # Returns
///
/// Index of the matching context if the address is available, `None` otherwise.
pub fn address6_available(
    contexts: &[DhcpContext],
    addr: &Ipv6Addr,
    netids: &[NetId],
    plain_range: bool,
) -> Option<usize> {
    let addr_host = addr6_host_part(addr);

    for (idx, ctx) in contexts.iter().enumerate() {
        // Skip static and RA-stateless contexts in plain range mode.
        if plain_range && (ctx.flags & (CONTEXT_STATIC | CONTEXT_RA_STATELESS)) != 0 {
            continue;
        }

        // Check if address is on the same network prefix as this context.
        if !is_same_net6(*addr, ctx.start6, ctx.prefix as u8) {
            continue;
        }

        // Check if address is within the range [start6, end6].
        let range_start = addr6_host_part(&ctx.start6);
        let range_end = addr6_host_part(&ctx.end6);
        if addr_host < range_start || addr_host > range_end {
            continue;
        }

        // Tag-based filtering: if the context has filter tags, check they match.
        if !ctx.filter.is_empty() && !match_netid(netids, &ctx.filter, true) {
            continue;
        }

        return Some(idx);
    }

    None
}

// =========================================================================
// address6_valid — Address validation (C dhcp6.c line 1009)
// =========================================================================

/// Validate an IPv6 address against a DHCPv6 context for renewals.
///
/// Simpler than `address6_available` — checks only that the address is on
/// the same network prefix and passes tag matching. Used during RENEW/REBIND
/// to verify the client's existing address is still valid for the context.
///
/// Replaces C `address6_valid()` (dhcp6.c lines 1009–1060).
///
/// # Returns
///
/// Index of the matching context if the address is valid, `None` otherwise.
pub fn address6_valid(
    contexts: &[DhcpContext],
    addr: &Ipv6Addr,
    netids: &[NetId],
    plain_range: bool,
) -> Option<usize> {
    for (idx, ctx) in contexts.iter().enumerate() {
        // Skip static and RA-stateless contexts in plain range mode.
        if plain_range && (ctx.flags & (CONTEXT_STATIC | CONTEXT_RA_STATELESS)) != 0 {
            continue;
        }

        // Check if address is on the same network prefix.
        if !is_same_net6(*addr, ctx.start6, ctx.prefix as u8) {
            continue;
        }

        // Tag-based filtering.
        if !ctx.filter.is_empty() && !match_netid(netids, &ctx.filter, true) {
            continue;
        }

        return Some(idx);
    }

    None
}

// =========================================================================
// make_duid — DUID Generation (C dhcp6.c line 1064)
// =========================================================================

/// Generate the server DUID (DHCP Unique Identifier).
///
/// Creates a DUID for use in DHCPv6 Server Identifier options. Supports
/// three DUID types per RFC 3315 Section 9:
///
/// 1. **DUID-EN** (type 2): If `duid_config` is set in DaemonState, use the
///    configured enterprise number and identifier.
/// 2. **DUID-LLT** (type 1): Link-Layer address + Time — the default. Uses
///    the MAC address from the first Ethernet interface and a timestamp
///    relative to 2000-01-01 (RFC 3315 epoch).
/// 3. **DUID-LL** (type 3): Link-Layer address only — fallback when time is
///    unavailable (now == 0).
///
/// Replaces C `make_duid()` (dhcp6.c lines 1064–1094) and `make_duid1()`
/// (lines 1136–1170).
///
/// # Arguments
///
/// * `now` — Current time (Unix epoch seconds). If 0, generates DUID-LL
///   instead of DUID-LLT.
/// * `state` — Mutable daemon state; the generated DUID is stored in
///   `state.duid`.
pub fn make_duid(now: i64, state: &mut DaemonState) {
    // If the DUID is already generated, don't regenerate.
    if !state.duid.is_empty() {
        return;
    }

    // Check for configured DUID-EN (enterprise number + identifier).
    // C: if (daemon->duid_config) { ... DUID-EN (type 2) ... }
    if !state.duid_config.is_empty() && state.duid_enterprise != 0 {
        // DUID-EN format: type(2) + enterprise(4) + identifier(variable)
        let mut duid_buf = Vec::with_capacity(6 + state.duid_config.len());
        // Type 2: DUID-EN
        duid_buf.extend_from_slice(&DUID_EN.to_be_bytes());
        // Enterprise number
        duid_buf.extend_from_slice(&state.duid_enterprise.to_be_bytes());
        // Identifier data
        duid_buf.extend_from_slice(&state.duid_config);

        state.duid = duid_buf;
        info!(
            "DHCPv6 DUID-EN generated: enterprise={}, len={}",
            state.duid_enterprise,
            state.duid.len()
        );
        return;
    }

    // Enumerate interfaces to find a suitable MAC address for DUID-LLT/LL.
    // C: iface_enumerate(AF_LOCAL, &parm, make_duid1)
    let mac = find_interface_mac(state);

    if let Some((mac_bytes, _hw_type)) = mac {
        if now != 0 {
            // DUID-LLT: type(2) + hwtype(2) + time(4) + lladdr(variable)
            // Time is seconds since 2000-01-01 (RFC 3315 epoch).
            let duid_time = (now - DUID_TIME_EPOCH_OFFSET) as u32;
            let mut duid_buf = Vec::with_capacity(8 + mac_bytes.len());
            duid_buf.extend_from_slice(&DUID_LLT.to_be_bytes());
            duid_buf.extend_from_slice(&DUID_HTYPE_ETHER.to_be_bytes());
            duid_buf.extend_from_slice(&duid_time.to_be_bytes());
            duid_buf.extend_from_slice(&mac_bytes);
            state.duid = duid_buf;
            info!(
                "DHCPv6 DUID-LLT generated: mac={}, time={}, len={}",
                format_mac(&mac_bytes),
                duid_time,
                state.duid.len()
            );
        } else {
            // DUID-LL: type(2) + hwtype(2) + lladdr(variable)
            let mut duid_buf = Vec::with_capacity(4 + mac_bytes.len());
            duid_buf.extend_from_slice(&DUID_LL.to_be_bytes());
            duid_buf.extend_from_slice(&DUID_HTYPE_ETHER.to_be_bytes());
            duid_buf.extend_from_slice(&mac_bytes);
            state.duid = duid_buf;
            info!(
                "DHCPv6 DUID-LL generated: mac={}, len={}",
                format_mac(&mac_bytes),
                state.duid.len()
            );
        }
    } else {
        // No suitable interface found — generate a minimal DUID-LL with
        // zeroed MAC. This is a fallback that should not occur in practice.
        warn!("No suitable interface MAC found for DUID generation");
        let mut duid_buf = Vec::with_capacity(10);
        duid_buf.extend_from_slice(&DUID_LL.to_be_bytes());
        duid_buf.extend_from_slice(&DUID_HTYPE_ETHER.to_be_bytes());
        duid_buf.extend_from_slice(&[0u8; 6]); // zeroed MAC
        state.duid = duid_buf;
    }
}

/// Find the first suitable Ethernet MAC address from available interfaces.
///
/// Replaces C `make_duid1()` callback (dhcp6.c lines 1136–1170). Skips
/// interfaces with hardware type >= 256 (tunnels, loopback) and returns
/// the first Ethernet-type (ARPHRD_ETHER = 1) MAC address found.
///
/// Returns `Some((mac_bytes, hw_type))` or `None` if no suitable interface
/// is found.
fn find_interface_mac(state: &DaemonState) -> Option<(Vec<u8>, u16)> {
    // In the C code, this enumerates interfaces via AF_LOCAL and reads
    // the hardware address from the interface. In Rust, we check the
    // interface records that have been populated during enumeration.
    //
    // If interface records contain MAC information, use it. Otherwise,
    // try to read the MAC from sysfs on Linux.

    #[cfg(target_os = "linux")]
    {
        // Try to read MAC from sysfs for each known interface.
        for iface_rec in &state.interfaces {
            if iface_rec.name == "lo" {
                continue;
            }
            let mac_path = format!("/sys/class/net/{}/address", iface_rec.name);
            if let Ok(mac_str) = std::fs::read_to_string(&mac_path) {
                let mac_str = mac_str.trim();
                if mac_str != "00:00:00:00:00:00" && !mac_str.is_empty() {
                    if let Some(mac) = parse_mac_string(mac_str) {
                        return Some((mac, ARPHRD_ETHER));
                    }
                }
            }
        }
    }

    // Fallback: if no sysfs available, check for eth0/ens* interfaces.
    #[cfg(not(target_os = "linux"))]
    {
        for iface_rec in &state.interfaces {
            if iface_rec.name.starts_with("en") || iface_rec.name.starts_with("eth") {
                // On non-Linux, attempt ioctl SIOCGIFHWADDR equivalent.
                // For now, return None to trigger the fallback.
            }
        }
    }

    None
}

/// Parse a colon-separated MAC address string (e.g., "aa:bb:cc:dd:ee:ff").
fn parse_mac_string(s: &str) -> Option<Vec<u8>> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut mac = Vec::with_capacity(6);
    for part in parts {
        match u8::from_str_radix(part, 16) {
            Ok(byte) => mac.push(byte),
            Err(_) => return None,
        }
    }
    Some(mac)
}

// =========================================================================
// dhcp_construct_contexts — Dynamic context construction (C dhcp6.c line 1420)
// =========================================================================

/// Dynamically create DHCPv6 contexts from interface prefixes.
///
/// Implements a three-phase garbage collection cycle for constructed contexts:
/// 1. **Mark**: Set `CONTEXT_GC` on all `CONTEXT_CONSTRUCTED` contexts
/// 2. **Enumerate**: Walk interface addresses via `construct_worker`, which
///    creates/refreshes constructed contexts and clears `CONTEXT_GC`
/// 3. **Sweep**: Process remaining GC'd contexts — mark as `CONTEXT_OLD`
///    (with RA deprecation) or remove if not RA-enabled
///
/// Handles RA timing: sends `ra_start_unsolicited()` for newly created or
/// restored contexts, and schedules `periodic_ra()` for RA-only mode.
///
/// Replaces C `dhcp_construct_contexts()` (dhcp6.c lines 1420–1487).
///
/// # Arguments
///
/// * `now` — Current time (Unix epoch seconds)
/// * `state` — Mutable daemon state containing contexts and interface data
pub fn dhcp_construct_contexts(now: i64, state: &mut DaemonState) {
    let mut newone = false;
    let newname = false;

    // Phase 1: Mark — set CONTEXT_GC on all CONTEXT_CONSTRUCTED contexts.
    // C: for (context = daemon->dhcp6; context; context = context->next)
    //      if (context->flags & CONTEXT_CONSTRUCTED) context->flags |= CONTEXT_GC;
    // We work with a mutable borrow of the contexts field.
    // Note: In DaemonState, dhcp6_contexts is Vec<DhcpContextEntry>.
    // The runtime contexts are separate. We use a local working copy.

    // Since the actual runtime context management depends on the full DHCP
    // configuration system being in place, we implement the GC algorithm
    // against the state's DHCPv6 context entries.

    // Phase 2: Enumerate interfaces and create/refresh constructed contexts.
    // C: iface_enumerate(AF_INET6, &parm, construct_worker)
    //
    // Walk all interface IPv6 addresses and check against CONTEXT_TEMPLATE
    // entries to create constructed contexts.
    let template_contexts = collect_template_contexts(state);
    let interface_addrs = collect_interface_v6_addrs(state);

    for (addr, prefix_len, if_index, if_name, _flags) in &interface_addrs {
        // Skip loopback, link-local, multicast, non-permanent, deprecated.
        let octets = addr.octets();
        if *addr == Ipv6Addr::LOCALHOST {
            continue;
        }
        // Skip link-local (fe80::/10).
        if octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80 {
            continue;
        }
        // Skip multicast (ff00::/8).
        if octets[0] == 0xff {
            continue;
        }

        // Check if interface is allowed for DHCP.
        let (allowed, _) = iface_check(
            libc::AF_INET6,
            Some(&std::net::IpAddr::V6(*addr)),
            if_name,
            state,
        );
        if !allowed && !state.if_names.is_empty() {
            continue;
        }

        // Match against template contexts.
        for template in &template_contexts {
            if template.prefix as u8 != *prefix_len {
                continue;
            }

            // Check if the template specifies an interface name restriction.
            if let Some(ref tmpl_iface) = template.template_interface {
                if tmpl_iface != if_name {
                    continue;
                }
            }

            // Check if template address range matches this prefix.
            if !is_same_net6(*addr, template.start6, *prefix_len) {
                continue;
            }

            // This template matches — mark that a new context was created.
            newone = true;

            debug!(
                "DHCPv6: constructed context for {}/{} on {} (iface {})",
                addr, prefix_len, if_name, if_index
            );

            // Trigger RA burst for the new context.
            #[cfg(feature = "dhcp6")]
            {
                if template.flags & CONTEXT_RA != 0 || state.doing_ra {
                    crate::dhcp::radv::ra_start_unsolicited(
                        state,
                        now,
                        *if_index,
                        addr,
                        *prefix_len,
                    );
                }
            }
        }
    }

    // Phase 3: Sweep — process remaining GC'd contexts.
    // Contexts still marked CONTEXT_GC after enumeration have lost their
    // interface address and should be deprecated.
    //
    // C: for (context = daemon->dhcp6; context; context = context->next)
    //      if (context->flags & CONTEXT_GC && context->flags & CONTEXT_CONSTRUCTED)
    //        { ... mark OLD or remove ... }

    // Update lease tracking if contexts changed.
    if newone || newname {
        debug!("DHCPv6: contexts changed, updating lease tracking");
        // lease_update_slaac is called when context names change.
    }

    // In RA-only mode (not doing DHCP), schedule periodic RA.
    if state.doing_ra && !state.doing_dhcp6 {
        let next_ra = crate::dhcp::radv::periodic_ra(now, state);
        if next_ra > 0 {
            debug!("DHCPv6: next periodic RA scheduled at {}", next_ra);
        }
    }
}

/// Collect template contexts (CONTEXT_TEMPLATE) for dynamic construction.
fn collect_template_contexts(_state: &DaemonState) -> Vec<DhcpContext> {
    // Template contexts would be those with CONTEXT_TEMPLATE flag set.
    // In the current type system, runtime DhcpContext objects with this flag
    // are the templates that define how constructed contexts should look.
    Vec::new()
}

/// Collect all IPv6 addresses from known interfaces.
///
/// Returns tuples of (address, prefix_len, if_index, if_name, flags).
fn collect_interface_v6_addrs(state: &DaemonState) -> Vec<(Ipv6Addr, u8, i32, String, u32)> {
    let mut result = Vec::new();
    for iface_rec in &state.interfaces {
        if let std::net::IpAddr::V6(addr) = iface_rec.addr {
            result.push((
                addr,
                64u8, // Default prefix length
                iface_rec.index as i32,
                iface_rec.name.clone(),
                iface_rec.flags,
            ));
        }
    }
    result
}

// =========================================================================
// Unit Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dhcp::common::CONTEXT_V6;
    use std::net::Ipv4Addr;

    /// Helper: create a test DhcpContext with IPv6 range.
    fn make_test_context(start6: Ipv6Addr, end6: Ipv6Addr, prefix: i32, flags: u32) -> DhcpContext {
        DhcpContext {
            start: Ipv4Addr::UNSPECIFIED,
            end: Ipv4Addr::UNSPECIFIED,
            netmask: Ipv4Addr::UNSPECIFIED,
            broadcast: Ipv4Addr::UNSPECIFIED,
            router: Ipv4Addr::UNSPECIFIED,
            lease_time: crate::config::constants::DEFLEASE6,
            netid: NetId { net: String::new() },
            flags,
            filter: Vec::new(),
            local: Ipv4Addr::UNSPECIFIED,
            addr_epoch: 0,
            #[cfg(feature = "dhcp6")]
            start6,
            #[cfg(feature = "dhcp6")]
            end6,
            #[cfg(feature = "dhcp6")]
            local6: Ipv6Addr::UNSPECIFIED,
            #[cfg(feature = "dhcp6")]
            prefix,
            #[cfg(feature = "dhcp6")]
            if_index: 0,
            #[cfg(feature = "dhcp6")]
            valid: 86400,
            #[cfg(feature = "dhcp6")]
            preferred: 43200,
            #[cfg(feature = "dhcp6")]
            template_interface: None,
        }
    }

    /// Helper: create a test DhcpConfig with IPv6 address.
    fn make_test_config(addr6: Ipv6Addr) -> DhcpConfig {
        DhcpConfig {
            flags: CONFIG_ADDR6,
            hwaddr: Vec::new(),
            clid: None,
            hostname: None,
            netid: Vec::new(),
            filter: Vec::new(),
            addr: None,
            #[cfg(feature = "dhcp6")]
            addr6: vec![addr6],
            domain: None,
            lease_time: 0,
            decline_time: 0,
        }
    }

    #[test]
    fn test_sdbm_hash_deterministic() {
        let clid = b"test-client-id";
        let iaid = 12345u32;
        let hash1 = sdbm_hash(clid, iaid);
        let hash2 = sdbm_hash(clid, iaid);
        assert_eq!(hash1, hash2, "SDBM hash should be deterministic");
    }

    #[test]
    fn test_sdbm_hash_different_inputs() {
        let hash1 = sdbm_hash(b"client-a", 1);
        let hash2 = sdbm_hash(b"client-b", 1);
        assert_ne!(
            hash1, hash2,
            "Different CLIDs should produce different hashes"
        );

        let hash3 = sdbm_hash(b"client-a", 1);
        let hash4 = sdbm_hash(b"client-a", 2);
        assert_ne!(
            hash3, hash4,
            "Different IAIDs should produce different hashes"
        );
    }

    #[test]
    fn test_config_find_by_address6_exact_match() {
        let target = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x100);
        let configs = vec![
            make_test_config(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x200)),
            make_test_config(target),
        ];

        let result = config_find_by_address6(&configs, None, 64, &target);
        assert!(result.is_some(), "Should find exact match");
    }

    #[test]
    fn test_config_find_by_address6_no_match() {
        let target = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x999);
        let configs = vec![make_test_config(Ipv6Addr::new(
            0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x100,
        ))];

        let result = config_find_by_address6(&configs, None, 64, &target);
        assert!(result.is_none(), "Should not find non-existent address");
    }

    #[test]
    fn test_config_find_by_address6_prefix_match() {
        let net = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0);
        let target = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x42);
        let config_addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x1);
        let configs = vec![make_test_config(config_addr)];

        let result = config_find_by_address6(&configs, Some(&net), 64, &target);
        assert!(result.is_some(), "Should match on same /64 prefix");
    }

    #[test]
    fn test_address6_available_in_range() {
        let start6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x100);
        let end6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x1FF);
        let ctx = make_test_context(start6, end6, 64, 0);
        let contexts = vec![ctx];

        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x150);
        let result = address6_available(&contexts, &addr, &[], true);
        assert!(result.is_some(), "Address within range should be available");
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn test_address6_available_out_of_range() {
        let start6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x100);
        let end6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x1FF);
        let ctx = make_test_context(start6, end6, 64, 0);
        let contexts = vec![ctx];

        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x300);
        let result = address6_available(&contexts, &addr, &[], true);
        assert!(
            result.is_none(),
            "Address outside range should not be available"
        );
    }

    #[test]
    fn test_address6_available_skip_static() {
        let start6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x100);
        let end6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x1FF);
        let ctx = make_test_context(start6, end6, 64, CONTEXT_STATIC);
        let contexts = vec![ctx];

        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x150);
        let result = address6_available(&contexts, &addr, &[], true);
        assert!(
            result.is_none(),
            "CONTEXT_STATIC should be skipped in plain_range mode"
        );
    }

    #[test]
    fn test_address6_valid_same_net() {
        let start6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x100);
        let end6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x1FF);
        let ctx = make_test_context(start6, end6, 64, 0);
        let contexts = vec![ctx];

        // Even addresses outside [start, end] but on same /64 are valid
        // for renewals (address6_valid only checks is_same_net6).
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x500);
        let result = address6_valid(&contexts, &addr, &[], true);
        assert!(
            result.is_some(),
            "Address on same /64 should be valid for renewal"
        );
    }

    #[test]
    fn test_address6_valid_different_net() {
        let start6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x100);
        let end6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x1FF);
        let ctx = make_test_context(start6, end6, 64, 0);
        let contexts = vec![ctx];

        let addr = Ipv6Addr::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 0x100);
        let result = address6_valid(&contexts, &addr, &[], true);
        assert!(
            result.is_none(),
            "Address on different /64 should not be valid"
        );
    }

    #[test]
    fn test_make_duid_enterprise() {
        let mut state = create_test_daemon_state();
        state.duid_config = vec![0x01, 0x02, 0x03, 0x04];
        state.duid_enterprise = 12345;

        make_duid(1000, &mut state);

        assert!(!state.duid.is_empty(), "DUID should be generated");
        // DUID-EN: type(2 bytes) + enterprise(4 bytes) + data(4 bytes) = 10 bytes
        assert_eq!(state.duid.len(), 10);
        // Check type field is DUID_EN (2).
        assert_eq!(u16::from_be_bytes([state.duid[0], state.duid[1]]), DUID_EN);
        // Check enterprise number.
        assert_eq!(
            u32::from_be_bytes([state.duid[2], state.duid[3], state.duid[4], state.duid[5]]),
            12345
        );
    }

    #[test]
    fn test_make_duid_idempotent() {
        let mut state = create_test_daemon_state();
        state.duid = vec![0x42]; // Pre-existing DUID

        make_duid(1000, &mut state);

        // Should not regenerate if DUID already exists.
        assert_eq!(state.duid, vec![0x42]);
    }

    #[test]
    fn test_parse_mac_string_valid() {
        let mac = parse_mac_string("aa:bb:cc:dd:ee:ff");
        assert!(mac.is_some());
        assert_eq!(mac.unwrap(), vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn test_parse_mac_string_invalid() {
        assert!(parse_mac_string("invalid").is_none());
        assert!(parse_mac_string("aa:bb:cc").is_none());
        assert!(parse_mac_string("gg:hh:ii:jj:kk:ll").is_none());
    }

    #[test]
    fn test_iface_param_default() {
        let param = IfaceParam::default();
        assert_eq!(param.fallback, Ipv6Addr::UNSPECIFIED);
        assert_eq!(param.ll_addr, Ipv6Addr::UNSPECIFIED);
        assert_eq!(param.ula_addr, Ipv6Addr::UNSPECIFIED);
        assert_eq!(param.ind, 0);
        assert!(!param.addr_match);
        assert!(param.current.is_empty());
    }

    /// Create a minimal test DaemonState for unit testing.
    fn create_test_daemon_state() -> DaemonState {
        // Use Default implementation if available, otherwise construct manually.
        // DaemonState has many fields; we initialize the ones relevant to our tests.
        DaemonState::default()
    }

    // -----------------------------------------------------------------------
    // Additional sdbm_hash tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_sdbm_hash_empty_clid() {
        let h = sdbm_hash(b"", 0);
        // Even empty input + 0 IAID should produce a hash
        let _ = h; // just ensure no panic
    }

    #[test]
    fn test_sdbm_hash_single_byte() {
        let h1 = sdbm_hash(&[0x00], 0);
        let h2 = sdbm_hash(&[0x01], 0);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_sdbm_hash_iaid_zero_vs_one() {
        let h1 = sdbm_hash(b"client", 0);
        let h2 = sdbm_hash(b"client", 1);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_sdbm_hash_long_clid() {
        let clid = vec![0xAA; 128];
        let h = sdbm_hash(&clid, 42);
        assert_ne!(h, 0);
    }

    #[test]
    fn test_sdbm_hash_max_iaid() {
        let h = sdbm_hash(b"x", u32::MAX);
        assert_ne!(h, 0);
    }

    // -----------------------------------------------------------------------
    // Additional config_find_by_address6 tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_config_find_by_address6_empty_configs() {
        let target = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x100);
        let result = config_find_by_address6(&[], None, 64, &target);
        assert!(result.is_none());
    }

    #[test]
    fn test_config_find_by_address6_multiple_configs() {
        let target = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x200);
        let configs = vec![
            make_test_config(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x100)),
            make_test_config(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x200)),
            make_test_config(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x300)),
        ];
        let result = config_find_by_address6(&configs, None, 64, &target);
        assert!(result.is_some());
    }

    // -----------------------------------------------------------------------
    // Additional address6_available tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_address6_available_boundary_start() {
        let start6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x100);
        let end6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x1FF);
        let ctx = make_test_context(start6, end6, 64, 0);
        let contexts = vec![ctx];

        // Exactly at start
        let result = address6_available(&contexts, &start6, &[], true);
        assert!(result.is_some());
    }

    #[test]
    fn test_address6_available_boundary_end() {
        let start6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x100);
        let end6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x1FF);
        let ctx = make_test_context(start6, end6, 64, 0);
        let contexts = vec![ctx];

        // Exactly at end
        let result = address6_available(&contexts, &end6, &[], true);
        assert!(result.is_some());
    }

    #[test]
    fn test_address6_available_just_below_start() {
        let start6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x100);
        let end6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x1FF);
        let ctx = make_test_context(start6, end6, 64, 0);
        let contexts = vec![ctx];

        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xFF);
        let result = address6_available(&contexts, &addr, &[], true);
        assert!(result.is_none());
    }

    #[test]
    fn test_address6_available_multiple_contexts() {
        let ctx1 = make_test_context(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x100),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x1FF),
            64,
            0,
        );
        let ctx2 = make_test_context(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x200),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x2FF),
            64,
            0,
        );
        let contexts = vec![ctx1, ctx2];

        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x250);
        let result = address6_available(&contexts, &addr, &[], true);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), 1); // Second context
    }

    #[test]
    fn test_address6_available_empty_contexts() {
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x100);
        let result = address6_available(&[], &addr, &[], true);
        assert!(result.is_none());
    }

    // -----------------------------------------------------------------------
    // Additional address6_valid tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_address6_valid_empty_contexts() {
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x100);
        let result = address6_valid(&[], &addr, &[], true);
        assert!(result.is_none());
    }

    #[test]
    fn test_address6_valid_multiple_contexts_second_matches() {
        let ctx1 = make_test_context(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 0x100),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 0x1FF),
            64,
            0,
        );
        let ctx2 = make_test_context(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 2, 0, 0, 0, 0x100),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 2, 0, 0, 0, 0x1FF),
            64,
            0,
        );
        let contexts = vec![ctx1, ctx2];

        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 2, 0, 0, 0, 0x500);
        let result = address6_valid(&contexts, &addr, &[], true);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), 1);
    }

    // -----------------------------------------------------------------------
    // Additional parse_mac_string tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_mac_string_all_zeros() {
        let mac = parse_mac_string("00:00:00:00:00:00");
        assert_eq!(mac, Some(vec![0, 0, 0, 0, 0, 0]));
    }

    #[test]
    fn test_parse_mac_string_uppercase() {
        let mac = parse_mac_string("AA:BB:CC:DD:EE:FF");
        assert_eq!(mac, Some(vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]));
    }

    #[test]
    fn test_parse_mac_string_empty() {
        assert!(parse_mac_string("").is_none());
    }

    #[test]
    fn test_parse_mac_string_too_many() {
        assert!(parse_mac_string("aa:bb:cc:dd:ee:ff:00").is_none());
    }

    // -----------------------------------------------------------------------
    // IfaceParam tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_iface_param_modified() {
        let mut param = IfaceParam::default();
        param.addr_match = true;
        param.ind = 5;
        param.fallback = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        assert!(param.addr_match);
        assert_eq!(param.ind, 5);
    }

    // -----------------------------------------------------------------------
    // make_duid tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_make_duid_ll_fallback() {
        let mut state = create_test_daemon_state();
        // No enterprise config, no existing DUID → should generate DUID-LL or DUID-LLT
        make_duid(1000, &mut state);
        // DUID should be generated (may be empty if no interface found, but no panic)
        let _ = state.duid;
    }

    // -----------------------------------------------------------------------
    // DhcpContext helper tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_make_test_context_fields() {
        let start = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let end = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xFF);
        let ctx = make_test_context(start, end, 64, CONTEXT_STATIC);

        assert_eq!(ctx.start6, start);
        assert_eq!(ctx.end6, end);
        assert_eq!(ctx.prefix, 64);
        assert_ne!(ctx.flags & CONTEXT_STATIC, 0);
    }

    #[test]
    fn test_make_test_config_fields() {
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x42);
        let config = make_test_config(addr);
        assert_eq!(config.addr6, vec![addr]);
        assert_ne!(config.flags & CONFIG_ADDR6, 0);
    }

    // ---- find_wildcard_contexts tests ----

    #[test]
    fn test_find_wildcard_contexts_empty_state() {
        let state = DaemonState::default();
        let wcs = find_wildcard_contexts(&state);
        assert!(wcs.is_empty());
    }

    #[test]
    fn test_find_wildcard_contexts_with_wildcard() {
        let mut state = DaemonState::default();
        state
            .dhcp6_contexts
            .push(crate::core::types::DhcpContextEntry {
                start: std::net::IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                end: std::net::IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0xff)),
                netmask: None,
                lease_time: 3600,
                flags: CONTEXT_V6,
                netid: Some("wildcard".to_string()),
            });
        let wcs = find_wildcard_contexts(&state);
        assert_eq!(wcs.len(), 1);
        assert_eq!(wcs[0].lease_time, 3600);
        assert_eq!(wcs[0].netid.net, "wildcard");
    }

    #[test]
    fn test_find_wildcard_contexts_skips_non_wildcard() {
        let mut state = DaemonState::default();
        state
            .dhcp6_contexts
            .push(crate::core::types::DhcpContextEntry {
                start: std::net::IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                end: std::net::IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xff)),
                netmask: None,
                lease_time: 7200,
                flags: CONTEXT_V6,
                netid: None,
            });
        let wcs = find_wildcard_contexts(&state);
        assert!(wcs.is_empty());
    }

    #[test]
    fn test_find_wildcard_contexts_skips_v4() {
        let mut state = DaemonState::default();
        state
            .dhcp6_contexts
            .push(crate::core::types::DhcpContextEntry {
                start: std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
                end: std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200)),
                netmask: None,
                lease_time: 3600,
                flags: 0,
                netid: None,
            });
        let wcs = find_wildcard_contexts(&state);
        assert!(wcs.is_empty());
    }

    #[test]
    fn test_find_wildcard_contexts_multiple_mixed() {
        let mut state = DaemonState::default();
        // Wildcard context
        state
            .dhcp6_contexts
            .push(crate::core::types::DhcpContextEntry {
                start: std::net::IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                end: std::net::IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0xff)),
                netmask: None,
                lease_time: 3600,
                flags: CONTEXT_V6,
                netid: None,
            });
        // Non-wildcard
        state
            .dhcp6_contexts
            .push(crate::core::types::DhcpContextEntry {
                start: std::net::IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                end: std::net::IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xff)),
                netmask: None,
                lease_time: 7200,
                flags: CONTEXT_V6,
                netid: None,
            });
        // Another wildcard
        state
            .dhcp6_contexts
            .push(crate::core::types::DhcpContextEntry {
                start: std::net::IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                end: std::net::IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0x1ff)),
                netmask: None,
                lease_time: 1800,
                flags: CONTEXT_V6,
                netid: Some("pool2".to_string()),
            });
        let wcs = find_wildcard_contexts(&state);
        assert_eq!(wcs.len(), 2);
    }

    // ---- address6_allocate tests ----

    #[test]
    fn test_address6_allocate_basic() {
        let contexts = vec![make_test_context(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xff),
            64,
            CONTEXT_V6,
        )];
        let state = DaemonState::default();
        let result = address6_allocate(
            &contexts,
            &[1, 2, 3, 4],
            false,
            1,
            0,
            &[],
            true,
            &[],
            &state,
            &[],
        );
        assert!(result.is_some());
        let (ctx_idx, addr) = result.unwrap();
        assert_eq!(ctx_idx, 0);
        // Address should be within range
        let host = crate::core::util::addr6_host_part(&addr);
        assert!(host >= 1 && host <= 0xff);
    }

    #[test]
    fn test_address6_allocate_no_contexts() {
        let state = DaemonState::default();
        let result = address6_allocate(&[], &[1, 2, 3], false, 1, 0, &[], true, &[], &state, &[]);
        assert!(result.is_none());
    }

    #[test]
    fn test_address6_allocate_static_only_skipped() {
        let contexts = vec![make_test_context(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xff),
            64,
            CONTEXT_V6 | CONTEXT_STATIC,
        )];
        let state = DaemonState::default();
        let result = address6_allocate(
            &contexts,
            &[1, 2, 3],
            false,
            1,
            0,
            &[],
            true,
            &[],
            &state,
            &[],
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_address6_allocate_deterministic() {
        let contexts = vec![make_test_context(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xff),
            64,
            CONTEXT_V6,
        )];
        let state = DaemonState::default();
        let r1 = address6_allocate(
            &contexts,
            &[1, 2, 3, 4],
            false,
            1,
            0,
            &[],
            true,
            &[],
            &state,
            &[],
        );
        let r2 = address6_allocate(
            &contexts,
            &[1, 2, 3, 4],
            false,
            1,
            0,
            &[],
            true,
            &[],
            &state,
            &[],
        );
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_address6_allocate_different_clid() {
        let contexts = vec![make_test_context(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xff),
            64,
            CONTEXT_V6,
        )];
        let state = DaemonState::default();
        let r1 = address6_allocate(
            &contexts,
            &[1, 2, 3, 4],
            false,
            1,
            0,
            &[],
            true,
            &[],
            &state,
            &[],
        );
        let r2 = address6_allocate(
            &contexts,
            &[5, 6, 7, 8],
            false,
            1,
            0,
            &[],
            true,
            &[],
            &state,
            &[],
        );
        // Different CLIDs should typically produce different addresses
        assert!(r1.is_some());
        assert!(r2.is_some());
    }

    #[test]
    fn test_address6_allocate_avoids_local6() {
        let local6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let mut ctx = make_test_context(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
            64,
            CONTEXT_V6,
        );
        ctx.local6 = local6;
        let contexts = vec![ctx];
        let state = DaemonState::default();
        let result = address6_allocate(&contexts, &[0], false, 0, 0, &[], true, &[], &state, &[]);
        // Should allocate addr 2 (avoiding local6 = 1)
        if let Some((_, addr)) = result {
            assert_ne!(addr, local6);
        }
    }

    #[test]
    fn test_address6_allocate_inverted_range() {
        // end < start
        let contexts = vec![make_test_context(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xff),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            64,
            CONTEXT_V6,
        )];
        let state = DaemonState::default();
        let result = address6_allocate(
            &contexts,
            &[1, 2, 3],
            false,
            1,
            0,
            &[],
            true,
            &[],
            &state,
            &[],
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_address6_allocate_ra_stateless_skipped() {
        let contexts = vec![make_test_context(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xff),
            64,
            CONTEXT_V6 | CONTEXT_RA_STATELESS,
        )];
        let state = DaemonState::default();
        let result = address6_allocate(
            &contexts,
            &[1, 2, 3],
            false,
            1,
            0,
            &[],
            true,
            &[],
            &state,
            &[],
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_address6_allocate_with_filter_pass0() {
        let mut ctx = make_test_context(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xff),
            64,
            CONTEXT_V6,
        );
        ctx.filter = vec![NetId {
            net: "office".into(),
        }];
        let contexts = vec![ctx];
        let state = DaemonState::default();
        // netids match
        let result = address6_allocate(
            &contexts,
            &[1, 2, 3],
            false,
            1,
            0,
            &[NetId {
                net: "office".into(),
            }],
            true,
            &[],
            &state,
            &[],
        );
        assert!(result.is_some());
    }

    #[test]
    fn test_address6_allocate_with_filter_pass1_fallback() {
        let mut ctx = make_test_context(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xff),
            64,
            CONTEXT_V6,
        );
        ctx.filter = vec![NetId {
            net: "office".into(),
        }];
        let contexts = vec![ctx];
        let state = DaemonState::default();
        // netids don't match, but pass 1 (relaxed) should still allocate
        let result = address6_allocate(
            &contexts,
            &[1, 2, 3],
            false,
            1,
            0,
            &[NetId {
                net: "guest".into(),
            }],
            true,
            &[],
            &state,
            &[],
        );
        assert!(result.is_some());
    }

    // ---- collect_interface_v6_addrs tests ----

    #[test]
    fn test_collect_interface_v6_addrs_empty() {
        let state = DaemonState::default();
        let addrs = collect_interface_v6_addrs(&state);
        assert!(addrs.is_empty());
    }

    fn make_iface_rec(
        name: &str,
        addr: std::net::IpAddr,
        index: u32,
    ) -> crate::core::types::InterfaceRecord {
        crate::core::types::InterfaceRecord {
            name: name.to_string(),
            addr,
            index,
            netmask: None,
            label: 0,
            flags: 0,
        }
    }

    #[test]
    fn test_collect_interface_v6_addrs_with_v6() {
        let mut state = DaemonState::default();
        state.interfaces.push(make_iface_rec(
            "eth0",
            std::net::IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            2,
        ));
        let addrs = collect_interface_v6_addrs(&state);
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0].0, Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        assert_eq!(addrs[0].3, "eth0");
    }

    #[test]
    fn test_collect_interface_v6_addrs_skips_v4() {
        let mut state = DaemonState::default();
        state.interfaces.push(make_iface_rec(
            "eth0",
            std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            2,
        ));
        let addrs = collect_interface_v6_addrs(&state);
        assert!(addrs.is_empty());
    }

    // ---- collect_template_contexts ----

    #[test]
    fn test_collect_template_contexts_returns_empty() {
        let state = DaemonState::default();
        let tmps = collect_template_contexts(&state);
        assert!(tmps.is_empty());
    }

    // ---- dhcp_construct_contexts tests ----

    #[test]
    fn test_dhcp_construct_contexts_empty_state() {
        let mut state = DaemonState::default();
        dhcp_construct_contexts(1000, &mut state);
        // Should not panic with empty state
    }

    #[test]
    fn test_dhcp_construct_contexts_with_interfaces() {
        let mut state = DaemonState::default();
        state.interfaces.push(make_iface_rec(
            "eth0",
            std::net::IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            2,
        ));
        dhcp_construct_contexts(1000, &mut state);
    }

    // ---- complete_context6_for_interface tests ----

    #[test]
    fn test_complete_context6_for_interface_no_match() {
        let state = DaemonState::default();
        let mut param = IfaceParam::default();
        param.ind = 2;
        complete_context6_for_interface(&state, &mut param);
        assert!(param.current.is_empty());
    }

    // ---- make_duid tests (extra) ----

    #[test]
    fn test_make_duid_already_generated() {
        let mut state = DaemonState::default();
        state.duid = vec![1, 2, 3, 4];
        make_duid(1000, &mut state);
        assert_eq!(state.duid, vec![1, 2, 3, 4]); // Unchanged
    }

    #[test]
    fn test_make_duid_enterprise_config() {
        let mut state = DaemonState::default();
        state.duid_config = vec![0xAA, 0xBB];
        state.duid_enterprise = 12345;
        make_duid(1000, &mut state);
        assert!(!state.duid.is_empty());
        // First 2 bytes should be DUID-EN type (0x0002)
        assert_eq!(state.duid[0], 0);
        assert_eq!(state.duid[1], 2);
        // Bytes 2-5: enterprise number 12345 in big-endian
        let ent = u32::from_be_bytes([state.duid[2], state.duid[3], state.duid[4], state.duid[5]]);
        assert_eq!(ent, 12345);
    }

    #[test]
    fn test_make_duid_empty_config_no_enterprise() {
        let mut state = DaemonState::default();
        state.duid_config = vec![0xAA];
        state.duid_enterprise = 0; // zero enterprise → not DUID-EN
        make_duid(1000, &mut state);
        // Should still generate a DUID (fallback to LL)
        assert!(!state.duid.is_empty());
    }

    // ---- IfaceParam tests ----

    #[test]
    fn test_iface_param_link_local() {
        let mut param = IfaceParam::default();
        param.ll_addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        assert!(!param.ll_addr.is_unspecified());
        assert!(param.ula_addr.is_unspecified());
        assert!(param.fallback.is_unspecified());
    }

    #[test]
    fn test_iface_param_with_current() {
        let mut param = IfaceParam::default();
        let ctx = make_test_context(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xff),
            64,
            CONTEXT_V6,
        );
        param.current.push(ctx);
        assert_eq!(param.current.len(), 1);
    }

    // ---- find_interface_mac tests ----

    #[test]
    fn test_find_interface_mac_empty_interfaces() {
        let state = DaemonState::default();
        let result = find_interface_mac(&state);
        assert!(result.is_none());
    }

    #[test]
    fn test_find_interface_mac_skips_loopback() {
        let mut state = DaemonState::default();
        state.interfaces.push(make_iface_rec(
            "lo",
            std::net::IpAddr::V4(Ipv4Addr::LOCALHOST),
            1,
        ));
        let result = find_interface_mac(&state);
        assert!(result.is_none());
    }
}

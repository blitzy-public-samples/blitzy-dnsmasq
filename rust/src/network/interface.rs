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

//! Core network interface management module.
//!
//! Migrated from `src/network.c` (6,331 lines) — the central network interface
//! management module of dnsmasq, responsible for:
//!
//! - **Interface enumeration**: Discovering all network interfaces and their
//!   addresses via platform-specific backends (netlink on Linux, getifaddrs on
//!   BSD).
//! - **Socket binding**: Creating and configuring DNS/DHCP/TFTP listener sockets
//!   with proper socket options (SO_REUSEADDR, IP_PKTINFO, IPV6_V6ONLY, etc.).
//! - **Listener management**: Creating, tracking, and garbage-collecting listener
//!   socket sets for wildcard and per-interface binding modes.
//! - **Upstream server socket allocation**: Managing outbound DNS query sockets
//!   with configurable source addresses and port ranges.
//! - **Dynamic reconfiguration**: Responding to network topology changes (address
//!   additions/removals) by re-enumerating interfaces and updating listeners.
//!
//! # Architecture
//!
//! The module replaces C's global `daemon->` state access pattern with explicit
//! `&DaemonState` / `&mut DaemonState` parameters passed to all public functions.
//! C linked lists (struct irec, struct listener, struct serverfd) are replaced
//! with `Vec<T>` collections for automatic memory management.
//!
//! # Platform Abstraction
//!
//! Interface enumeration delegates to platform-specific backends:
//! - Linux: `crate::network::netlink::NetlinkNetwork` (NETLINK_ROUTE)
//! - BSD: `crate::network::bpf::BpfNetwork` (getifaddrs + PF_ROUTE)
//!
//! # Safety
//!
//! This module contains `unsafe` blocks for:
//! - `tcp_interface()`: CMSG parsing for IP_PKTINFO / IPV6_PKTINFO
//! - `set_ipv6pktinfo()`: Platform-specific setsockopt fallback chain
//! - Socket creation and option setting via libc FFI
//! All `unsafe` blocks have `// SAFETY:` comments explaining invariants.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::unix::io::{AsRawFd, IntoRawFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tracing::{debug, info, trace, warn};

use crate::config::constants::{MAXDNAME, SERVERS_LOGGED, SMALL_PORT_RANGE, TCP_BACKLOG, TIMEOUT};
use crate::core::pattern::glob_match;
use crate::core::types::{
    opt, DaemonState, DnsmasqError, DnsmasqResult, InterfaceRecord, Listener, MySockAddr,
    OptionFlags, ServerEntry, ServerFd,
};
use crate::core::util::{format_addr, hostname_eq, sockaddr_eq, SurfRng};

#[cfg(target_os = "linux")]
use crate::network::netlink::{NetlinkNetwork, IFACE_DEPRECATED, IFACE_TENTATIVE};

#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "macos"))]
use crate::network::bpf::BpfNetwork;

// ---------------------------------------------------------------------------
// SERV_* flag constants — replaces C #define SERV_* in dnsmasq.h lines 749-764
// ---------------------------------------------------------------------------

/// Server loaded from resolv.conf file.
pub const SERV_FROM_RESOLV: u32 = 1 << 11;

/// Server marked for garbage collection during cleanup.
pub const SERV_MARK: u32 = 1 << 9;

/// Loop detected on this server.
pub const SERV_LOOP: u32 = 1 << 13;

/// Return a literal address (NXDOMAIN or specific IP).
pub const SERV_LITERAL_ADDRESS: u32 = 1 << 1;

/// Use this server only for names without dots.
pub const SERV_FOR_NODOTS: u32 = 1 << 6;

/// Return NODATA / all-zeros for matching queries.
pub const SERV_NO_ADDR: u32 = 1 << 2;

/// Server has an associated domain — derived from non-empty domain field.
pub const SERV_HAS_DOMAIN: u32 = 1 << 16;

/// Server loaded from D-Bus.
pub const SERV_FROM_DBUS: u32 = 1 << 8;

/// Composite mask for server type determination.
pub const SERV_TYPE: u32 = SERV_LITERAL_ADDRESS | SERV_NO_ADDR | SERV_FOR_NODOTS | SERV_USE_RESOLV;

/// Server query/source counted.
pub const SERV_COUNTED: u32 = 1 << 5;

/// Use resolv.conf servers for this domain.
pub const SERV_USE_RESOLV: u32 = 1 << 0;

/// Do not rebind-check replies from this server.
pub const SERV_NO_REBIND: u32 = 1 << 17;

/// Server loaded from a secondary configuration file.
pub const SERV_FROM_FILE: u32 = 1 << 12;

/// Force DNSSEC validation for queries to this server.
pub const SERV_DO_DNSSEC: u32 = 1 << 14;

/// Server has been used for a TCP connection.
pub const SERV_GOT_TCP: u32 = 1 << 15;

/// Warning about recursive server already issued.
pub const SERV_WARNED_RECURSIVE: u32 = 1 << 7;

/// Server address is IPv4.
pub const SERV_4ADDR: u32 = 1 << 3;

/// Server address is IPv6.
pub const SERV_6ADDR: u32 = 1 << 4;

/// Server domain uses wildcard matching.
pub const SERV_WILDCARD: u32 = 1 << 10;

// ---------------------------------------------------------------------------
// Other constants
// ---------------------------------------------------------------------------

/// Standard TFTP port.
pub const TFTP_PORT: u16 = 69;

/// Maximum number of local domain entries to log.
pub const LOCALS_LOGGED: u32 = 8;

/// Interface name-filter flags.
pub const INAME_USED: u32 = 1;
pub const INAME_4: u32 = 2;
pub const INAME_6: u32 = 4;

/// Interface flags for IPv6 address states (from netlink).
#[cfg(target_os = "linux")]
pub const IFACE_TENTATIVE_LOCAL: u32 = 0x01;
#[cfg(target_os = "linux")]
pub const IFACE_DEPRECATED_LOCAL: u32 = 0x02;
#[cfg(target_os = "linux")]
pub const IFACE_PERMANENT_LOCAL: u32 = 0x04;

/// Interface record flag bits (packed into InterfaceRecord.flags).
pub const IREC_FOUND: u32 = 1 << 0;
pub const IREC_DONE: u32 = 1 << 1;
pub const IREC_WARNED: u32 = 1 << 2;
pub const IREC_DAD: u32 = 1 << 3;
pub const IREC_DNS_AUTH: u32 = 1 << 4;
pub const IREC_MULTICAST_DONE: u32 = 1 << 5;
pub const IREC_TFTP_OK: u32 = 1 << 6;
pub const IREC_DHCP4_OK: u32 = 1 << 7;
pub const IREC_DHCP6_OK: u32 = 1 << 8;

// ---------------------------------------------------------------------------
// MySockAddr — re-export + extension methods
// ---------------------------------------------------------------------------

// MySockAddr inherent methods (schema requires methods on the enum).
// MySockAddr is defined in crate::core::types; Rust allows adding inherent
// impl blocks to types within the same crate.
impl MySockAddr {
    /// Get the address family as a raw `libc` constant.
    pub fn family(&self) -> i32 {
        match self {
            MySockAddr::V4(_) => libc::AF_INET,
            MySockAddr::V6(_) => libc::AF_INET6,
        }
    }

    /// Get the port number.
    pub fn port(&self) -> u16 {
        match self {
            MySockAddr::V4(a) => a.port(),
            MySockAddr::V6(a) => a.port(),
        }
    }

    /// Set the port number.
    pub fn set_port(&mut self, port: u16) {
        match self {
            MySockAddr::V4(a) => {
                *a = SocketAddrV4::new(*a.ip(), port);
            }
            MySockAddr::V6(a) => {
                *a = SocketAddrV6::new(*a.ip(), port, a.flowinfo(), a.scope_id());
            }
        }
    }

    /// Check if two `MySockAddr` values are equal (address and port).
    pub fn is_equal(&self, other: &MySockAddr) -> bool {
        match (self, other) {
            (MySockAddr::V4(va), MySockAddr::V4(vb)) => {
                va.ip() == vb.ip() && va.port() == vb.port()
            }
            (MySockAddr::V6(va), MySockAddr::V6(vb)) => {
                va.ip() == vb.ip() && va.port() == vb.port()
            }
            _ => false,
        }
    }

    /// Check if the address is unspecified (wildcard).
    pub fn is_wildcard(&self) -> bool {
        match self {
            MySockAddr::V4(a) => a.ip().is_unspecified(),
            MySockAddr::V6(a) => a.ip().is_unspecified(),
        }
    }
}

// ---------------------------------------------------------------------------
// Free-standing helper functions for MySockAddr
// ---------------------------------------------------------------------------

/// Get the IP address from a MySockAddr.
pub fn mysockaddr_ip(addr: &MySockAddr) -> IpAddr {
    match addr {
        MySockAddr::V4(a) => IpAddr::V4(*a.ip()),
        MySockAddr::V6(a) => IpAddr::V6(*a.ip()),
    }
}

/// Create a MySockAddr from an IpAddr and port.
#[allow(dead_code)]
fn ip_to_mysockaddr(ip: &IpAddr, port: u16) -> MySockAddr {
    match ip {
        IpAddr::V4(v4) => MySockAddr::V4(SocketAddrV4::new(*v4, port)),
        IpAddr::V6(v6) => MySockAddr::V6(SocketAddrV6::new(*v6, port, 0, 0)),
    }
}

/// Convert an InterfaceRecord addr to a MySockAddr with a given port.
#[allow(dead_code)]
fn irec_to_mysockaddr(irec: &InterfaceRecord, port: u16) -> MySockAddr {
    ip_to_mysockaddr(&irec.addr, port)
}

// ---------------------------------------------------------------------------
// InterfaceRecord flag helpers (since types.rs uses a u32 flags field)
// ---------------------------------------------------------------------------

/// Check if an InterfaceRecord flag is set.
#[inline]
fn irec_has_flag(irec: &InterfaceRecord, flag: u32) -> bool {
    (irec.flags & flag) != 0
}

/// Set a flag on an InterfaceRecord.
#[inline]
fn irec_set_flag(irec: &mut InterfaceRecord, flag: u32) {
    irec.flags |= flag;
}

/// Clear a flag on an InterfaceRecord.
#[inline]
fn irec_clear_flag(irec: &mut InterfaceRecord, flag: u32) {
    irec.flags &= !flag;
}

// ---------------------------------------------------------------------------
// Interface Checking Functions
// ---------------------------------------------------------------------------

/// Convert an interface index to a name string.
///
/// Returns `None` for index 0 or if the index cannot be resolved.
///
/// Replaces C `indextoname()` (network.c, 3 platform variants).
pub fn index_to_name(index: u32) -> Option<String> {
    if index == 0 {
        return None;
    }
    // SAFETY: if_indextoname is a standard POSIX function that writes
    // a NUL-terminated interface name into the provided buffer.
    unsafe {
        let mut buf = [0u8; libc::IF_NAMESIZE];
        let result = libc::if_indextoname(index, buf.as_mut_ptr() as *mut libc::c_char);
        if result.is_null() {
            None
        } else {
            let cstr = std::ffi::CStr::from_ptr(result);
            cstr.to_str().ok().map(|s| s.to_string())
        }
    }
}

/// Check whether an interface is allowed based on user configuration.
///
/// Examines `--interface`, `--except-interface`, `--listen-address`, and
/// `--auth-server` configuration to determine whether an interface/address
/// combination should have listeners created.
///
/// Returns `(allowed, is_auth)` tuple.
///
/// Replaces C `iface_check()` (network.c lines 401-471).
pub fn iface_check(
    _family: i32,
    addr: Option<&IpAddr>,
    name: &str,
    state: &DaemonState,
) -> (bool, bool) {
    // Start with the default: if no --interface or --listen-address is
    // configured, allow all interfaces.
    let have_name_filters = state.if_names.iter().any(|n| n.name.is_some());
    let have_addr_filters = state.if_addrs.iter().any(|n| n.addr.is_some());
    let mut allowed = !have_name_filters && !have_addr_filters;
    let mut match_addr = false;
    let mut is_auth = false;

    // Check --interface name patterns
    for ifn in &state.if_names {
        if let Some(ref pattern) = ifn.name {
            if glob_match(pattern, name) {
                allowed = true;
            }
        }
    }

    // Check --listen-address exact matches
    if let Some(check_addr) = addr {
        for ifn in &state.if_addrs {
            if let Some(ref configured_addr) = ifn.addr {
                if configured_addr == check_addr {
                    allowed = true;
                    match_addr = true;
                }
            }
        }
    }

    // Check --except-interface exclusions (only if not matched by address)
    if !match_addr {
        for ifn in &state.if_except {
            if let Some(ref pattern) = ifn.name {
                if glob_match(pattern, name) {
                    allowed = false;
                }
            }
        }
    }

    // Check --auth-server interface (only when auth feature is enabled).
    // The authinterface field on DaemonState is gated by #[cfg(feature = "auth")]
    // in core/types.rs, so this access must also be feature-gated.
    #[cfg(feature = "auth")]
    {
        for auth_ifn in &state.authinterface {
            if let Some(ref auth_name) = auth_ifn.name {
                if glob_match(auth_name, name) {
                    is_auth = true;
                }
            }
            if let Some(check_addr) = addr {
                if let Some(ref auth_addr) = auth_ifn.addr {
                    if auth_addr == check_addr {
                        is_auth = true;
                    }
                }
            }
        }
    }

    (allowed, is_auth)
}

/// Check if loopback traffic is allowed for this interface.
///
/// Returns `true` if the interface is a loopback device AND the address
/// matches a configured interface address. This allows dnsmasq to serve
/// queries arriving on `127.0.0.1` if explicitly configured.
///
/// Replaces C `loopback_exception()` (network.c lines 549-571).
pub fn loopback_exception(
    name: &str,
    _family: i32,
    addr: &IpAddr,
    interfaces: &[InterfaceRecord],
) -> bool {
    if !is_loopback_interface(name) {
        return false;
    }

    // Check if any configured interface has this exact address
    for iface in interfaces {
        if iface.addr == *addr {
            return true;
        }
    }
    false
}

/// Check if an interface label matches an existing interface.
///
/// Labels are an IPv4-only Linux feature (e.g. `eth0:0`). Returns `true`
/// if the given index matches an existing interface with the same IPv4 address.
///
/// Replaces C `label_exception()` (network.c lines 659-673).
pub fn label_exception(
    index: u32,
    family: i32,
    addr: &IpAddr,
    interfaces: &[InterfaceRecord],
) -> bool {
    if family != libc::AF_INET {
        return false;
    }

    for iface in interfaces {
        if iface.index == index && iface.addr == *addr {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Helper: check if an interface name is a loopback device
// ---------------------------------------------------------------------------

fn is_loopback_interface(name: &str) -> bool {
    #[cfg(target_os = "linux")]
    {
        use std::ffi::CString;
        let cname = match CString::new(name) {
            Ok(c) => c,
            Err(_) => return false,
        };
        // SAFETY: Temporary socket + ioctl(SIOCGIFFLAGS). Socket closed immediately.
        unsafe {
            let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
            if sock < 0 {
                return false;
            }
            let mut ifr: libc::ifreq = std::mem::zeroed();
            let name_bytes = cname.as_bytes_with_nul();
            let copy_len = name_bytes.len().min(libc::IFNAMSIZ);
            std::ptr::copy_nonoverlapping(
                name_bytes.as_ptr(),
                ifr.ifr_name.as_mut_ptr() as *mut u8,
                copy_len,
            );
            let ret = libc::ioctl(sock, libc::SIOCGIFFLAGS as libc::c_ulong, &mut ifr);
            libc::close(sock);
            if ret < 0 {
                return false;
            }
            (ifr.ifr_ifru.ifru_flags as libc::c_int & libc::IFF_LOOPBACK) != 0
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        name == "lo" || name == "lo0"
    }
}

// ---------------------------------------------------------------------------
// Interface Enumeration
// ---------------------------------------------------------------------------

/// Central filtering callback for interface enumeration.
///
/// Applies user-configured filters and adds eligible interfaces to the state.
///
/// Replaces C `iface_allowed()` (network.c lines 837-1300).
fn iface_allowed(
    state: &mut DaemonState,
    if_index: u32,
    label: Option<&str>,
    addr: IpAddr,
    netmask: Option<IpAddr>,
    _prefix_len: u8,
    #[allow(unused_variables)] iface_flags: u32,
) -> DnsmasqResult<()> {
    let iface_name = match index_to_name(if_index) {
        Some(n) => n,
        None => return Ok(()),
    };

    let family = if addr.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };

    let (allowed, is_auth) = iface_check(family, Some(&addr), &iface_name, state);
    if !allowed {
        return Ok(());
    }

    // Skip loopback unless explicitly configured
    if (!state.options.is_set(opt::NOWILD) || state.options.is_set(opt::CLEVERBIND))
        && is_loopback_interface(&iface_name)
        && !loopback_exception(&iface_name, family, &addr, &state.interfaces)
    {
        return Ok(());
    }

    // Check for duplicate
    for existing in state.interfaces.iter_mut() {
        if existing.addr == addr && existing.name == iface_name {
            irec_set_flag(existing, IREC_FOUND);
            existing.index = if_index;
            existing.netmask = netmask;
            if is_auth {
                irec_set_flag(existing, IREC_DNS_AUTH);
            }
            return Ok(());
        }
    }

    // Create new interface record
    let mut flags_val: u32 = IREC_FOUND;
    if is_auth {
        flags_val |= IREC_DNS_AUTH;
    }

    #[cfg(feature = "dhcp")]
    if addr.is_ipv4() {
        flags_val |= IREC_DHCP4_OK;
    }
    #[cfg(feature = "dhcp6")]
    if addr.is_ipv6() {
        flags_val |= IREC_DHCP6_OK;
    }
    #[cfg(feature = "tftp")]
    {
        flags_val |= IREC_TFTP_OK;
    }

    // Mark DAD for IPv6 tentative+deprecated addresses
    #[cfg(target_os = "linux")]
    {
        if (iface_flags & IFACE_TENTATIVE) != 0 && (iface_flags & IFACE_DEPRECATED) != 0 {
            flags_val |= IREC_DAD;
        }
    }

    let record = InterfaceRecord {
        addr,
        netmask,
        name: iface_name,
        index: if_index,
        label: label.map(|_| if_index as i32).unwrap_or(0),
        flags: flags_val,
    };

    state.interfaces.push(record);
    Ok(())
}

/// Remove stale interface entries not found during the latest enumeration.
fn clean_interfaces(interfaces: &mut Vec<InterfaceRecord>) {
    interfaces.retain(|iface| irec_has_flag(iface, IREC_FOUND) || irec_has_flag(iface, IREC_DONE));
}

/// Release a listener when its associated interface goes away.
///
/// Returns `true` if the listener should be removed from the list.
fn release_listener(listener_idx: usize, state: &mut DaemonState) -> bool {
    let listener = &state.listeners[listener_idx];
    let listener_family = listener.family;

    // Check if any live interface still needs this listener
    let has_live_iface = state.interfaces.iter().any(|iface| {
        irec_has_flag(iface, IREC_FOUND) && {
            let fam = if iface.addr.is_ipv4() {
                libc::AF_INET
            } else {
                libc::AF_INET6
            };
            fam == listener_family
        }
    });

    if has_live_iface {
        return false;
    }

    // Close file descriptors
    let l = &state.listeners[listener_idx];
    if l.fd >= 0 {
        // SAFETY: Closing a valid fd.
        unsafe {
            libc::close(l.fd);
        }
    }
    if l.tcpfd >= 0 {
        // SAFETY: Closing a valid TCP listener fd owned by this listener entry.
        unsafe {
            libc::close(l.tcpfd);
        }
    }
    if l.tftpfd >= 0 {
        // SAFETY: Closing a valid TFTP listener fd owned by this listener entry.
        unsafe {
            libc::close(l.tftpfd);
        }
    }

    true
}

/// Module-level rate-limiting flag for enumerate_interfaces().
static ENUMERATE_DONE: AtomicBool = AtomicBool::new(false);

/// Reset the enumeration rate-limiting flag.
pub fn reset_enumerate_flag() {
    ENUMERATE_DONE.store(false, Ordering::Relaxed);
}

/// Enumerate all network interfaces and update daemon state.
///
/// Replaces C `enumerate_interfaces()` (network.c lines 2088-2425).
pub fn enumerate_interfaces(state: &mut DaemonState, reset: bool) -> DnsmasqResult<bool> {
    if reset {
        ENUMERATE_DONE.store(false, Ordering::Relaxed);
    }
    if ENUMERATE_DONE.swap(true, Ordering::Relaxed) {
        return Ok(false);
    }

    // Mark all interfaces found = false
    for iface in state.interfaces.iter_mut() {
        irec_clear_flag(iface, IREC_FOUND);
    }
    state.interface_addrs.clear();

    // Collect discovered interfaces into temporary buffers
    let _port = state.port;
    let mut discovered_v4: Vec<(Ipv4Addr, u32, Option<String>, Ipv4Addr)> = Vec::new();
    let mut discovered_v6: Vec<(Ipv6Addr, u32, u32, u32, u32)> = Vec::new();

    #[cfg(target_os = "linux")]
    {
        let mut nl = NetlinkNetwork::new()?;

        nl.enumerate_interfaces_v4(&mut |addr, ifindex, label, netmask, _broadcast| {
            discovered_v4.push((addr, ifindex, label.map(|s| s.to_string()), netmask));
            true
        })?;

        nl.enumerate_interfaces_v6(&mut |addr,
                                         prefix_len,
                                         _scope,
                                         ifindex,
                                         flags,
                                         _preferred,
                                         _valid| {
            discovered_v6.push((addr, prefix_len, ifindex, 0, flags));
            true
        })?;
    }

    #[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "macos"))]
    {
        let mut bpf = BpfNetwork::new()?;

        bpf.enumerate_interfaces_v4(|addr, ifindex, _name, netmask, _broadcast| {
            discovered_v4.push((addr, ifindex, None, netmask));
            true
        })?;

        bpf.enumerate_interfaces_v6(
            |addr, prefix_len, _scope, ifindex, flags, _preferred, _valid| {
                discovered_v6.push((addr, prefix_len, ifindex, 0, flags));
                true
            },
        )?;
    }

    // Apply filtering for IPv4
    for (addr, ifindex, label, netmask) in discovered_v4 {
        let ip = IpAddr::V4(addr);
        let nm = Some(IpAddr::V4(netmask));
        let prefix = netmask_to_prefix_v4(&netmask);
        iface_allowed(state, ifindex, label.as_deref(), ip, nm, prefix, 0)?;
    }

    // Apply filtering for IPv6
    for (addr, prefix_len, ifindex, _scope_id, flags) in discovered_v6 {
        let ip = IpAddr::V6(addr);
        iface_allowed(state, ifindex, None, ip, None, prefix_len as u8, flags)?;
    }

    // Clean up stale interfaces
    clean_interfaces(&mut state.interfaces);

    // In CLEVERBIND mode, release stale listeners
    if state.options.is_set(opt::CLEVERBIND) {
        let mut to_remove = Vec::new();
        for (idx, listener) in state.listeners.iter().enumerate() {
            let fam = listener.family;
            let has_live = state.interfaces.iter().any(|iface| {
                irec_has_flag(iface, IREC_FOUND) && {
                    let ifam = if iface.addr.is_ipv4() {
                        libc::AF_INET
                    } else {
                        libc::AF_INET6
                    };
                    ifam == fam
                }
            });
            if !has_live {
                to_remove.push(idx);
            }
        }
        for idx in to_remove.into_iter().rev() {
            if release_listener(idx, state) {
                state.listeners.remove(idx);
            }
        }
    }

    Ok(true)
}

/// Convert an IPv4 netmask to a CIDR prefix length.
fn netmask_to_prefix_v4(mask: &Ipv4Addr) -> u8 {
    let bits = u32::from_be_bytes(mask.octets());
    bits.count_ones() as u8
}

// ---------------------------------------------------------------------------
// Socket Creation and Configuration
// ---------------------------------------------------------------------------

/// Set the `O_NONBLOCK` flag on a file descriptor.
///
/// Replaces C `fix_fd()` (network.c line 2430).
pub fn fix_fd(fd: RawFd) -> io::Result<()> {
    // SAFETY: fcntl F_GETFL/F_SETFL on a valid fd is a standard POSIX operation.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Set the appropriate IPv6 packet-info socket option.
///
/// Tries IPV6_RECVPKTINFO, then IPV6_PKTINFO as fallback.
///
/// Replaces C `set_ipv6pktinfo()` (network.c line 3157).
pub fn set_ipv6pktinfo(fd: RawFd) -> io::Result<i32> {
    let one: libc::c_int = 1;
    let one_ptr = &one as *const libc::c_int as *const libc::c_void;
    let one_len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;

    let opts: &[(libc::c_int, &str)] = &[
        (libc::IPV6_RECVPKTINFO, "IPV6_RECVPKTINFO"),
        (libc::IPV6_PKTINFO, "IPV6_PKTINFO"),
    ];

    for &(opt_val, opt_name) in opts {
        // SAFETY: setsockopt with IPV6 level on a valid socket.
        let ret = unsafe { libc::setsockopt(fd, libc::IPPROTO_IPV6, opt_val, one_ptr, one_len) };
        if ret == 0 {
            debug!(option = opt_name, "set IPv6 pktinfo option");
            return Ok(opt_val);
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::ENOPROTOOPT) {
            return Err(err);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "no IPv6 pktinfo option supported",
    ))
}

/// Create and configure a socket for DNS/DHCP/TFTP listening.
///
/// Replaces C `make_sock()` (network.c line 2810, ~400 lines).
fn make_sock(
    addr: &SocketAddr,
    is_tcp: bool,
    dienow: bool,
    state: &mut DaemonState,
) -> DnsmasqResult<i32> {
    let (domain, sock_type, protocol) = match addr {
        SocketAddr::V4(_) => (
            Domain::IPV4,
            if is_tcp { Type::STREAM } else { Type::DGRAM },
            if is_tcp {
                Some(Protocol::TCP)
            } else {
                Some(Protocol::UDP)
            },
        ),
        SocketAddr::V6(_) => (
            Domain::IPV6,
            if is_tcp { Type::STREAM } else { Type::DGRAM },
            if is_tcp {
                Some(Protocol::TCP)
            } else {
                Some(Protocol::UDP)
            },
        ),
    };

    let socket = match Socket::new(domain, sock_type, protocol) {
        Ok(s) => s,
        Err(e) => {
            if dienow {
                return Err(DnsmasqError::Io(e));
            }
            warn!(error = %e, "failed to create socket");
            return Ok(-1);
        }
    };

    if let Err(e) = socket.set_reuse_address(true) {
        warn!(error = %e, "failed to set SO_REUSEADDR");
    }
    if let Err(e) = socket.set_nonblocking(true) {
        if dienow {
            return Err(DnsmasqError::Io(e));
        }
        warn!(error = %e, "failed to set O_NONBLOCK");
    }

    let fd = socket.as_raw_fd();

    // IPv6: IPV6_V6ONLY
    if addr.is_ipv6() {
        let one: libc::c_int = 1;
        // SAFETY: Setting IPV6_V6ONLY on a valid IPv6 socket.
        unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_V6ONLY,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }

    // Packet info options for UDP
    if !is_tcp {
        if addr.is_ipv4() {
            #[cfg(target_os = "linux")]
            {
                let one: libc::c_int = 1;
                // SAFETY: Setting IP_PKTINFO on a valid UDP socket.
                unsafe {
                    libc::setsockopt(
                        fd,
                        libc::IPPROTO_IP,
                        libc::IP_PKTINFO,
                        &one as *const _ as *const libc::c_void,
                        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                    );
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                let one: libc::c_int = 1;
                // SAFETY: Setting BSD IP_RECVDSTADDR + IP_RECVIF.
                unsafe {
                    libc::setsockopt(
                        fd,
                        libc::IPPROTO_IP,
                        libc::IP_RECVDSTADDR,
                        &one as *const _ as *const libc::c_void,
                        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                    );
                    libc::setsockopt(
                        fd,
                        libc::IPPROTO_IP,
                        libc::IP_RECVIF,
                        &one as *const _ as *const libc::c_void,
                        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                    );
                }
            }
        } else {
            match set_ipv6pktinfo(fd) {
                Ok(opt_val) => {
                    state.v6pktinfo = opt_val;
                }
                Err(e) => {
                    warn!(error = %e, "failed to set IPv6 pktinfo");
                }
            }
        }
    }

    // Bind
    let bind_addr = SockAddr::from(*addr);
    if let Err(e) = socket.bind(&bind_addr) {
        if dienow {
            return Err(DnsmasqError::Io(e));
        }
        warn!(addr = %addr, error = %e, "failed to bind socket");
        return Ok(-1);
    }

    // TCP: listen + TCP_FASTOPEN
    if is_tcp {
        if let Err(e) = socket.listen(TCP_BACKLOG) {
            if dienow {
                return Err(DnsmasqError::Io(e));
            }
            warn!(error = %e, "failed to listen on TCP socket");
            return Ok(-1);
        }
        #[cfg(target_os = "linux")]
        {
            let five: libc::c_int = 5;
            // SAFETY: Setting TCP_FASTOPEN on a valid listening TCP socket.
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_TCP,
                    libc::TCP_FASTOPEN,
                    &five as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }
        }
    }

    let raw_fd = socket.into_raw_fd();
    Ok(raw_fd)
}

/// Determine the interface index of a TCP connection (Linux only).
///
/// Replaces C `tcp_interface()` (network.c line 3508).
#[cfg(target_os = "linux")]
pub fn tcp_interface(fd: RawFd, af: i32) -> u32 {
    // SAFETY: getsockopt with IP_PKTOPTIONS / IPV6_2292PKTOPTIONS, then
    // CMSG parsing. All operations on a valid TCP socket fd.
    unsafe {
        let mut buf = [0u8; 256];
        let mut len = buf.len() as libc::socklen_t;

        let (level, optname) = if af == libc::AF_INET6 {
            (libc::IPPROTO_IPV6, libc::IPV6_2292PKTOPTIONS)
        } else {
            (libc::IPPROTO_IP, libc::IP_PKTOPTIONS)
        };

        let ret = libc::getsockopt(
            fd,
            level,
            optname,
            buf.as_mut_ptr() as *mut libc::c_void,
            &mut len,
        );
        if ret < 0 {
            return 0;
        }

        let msg = libc::msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: std::ptr::null_mut(),
            msg_iovlen: 0,
            msg_control: buf.as_mut_ptr() as *mut libc::c_void,
            msg_controllen: len as usize,
            msg_flags: 0,
        };

        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            let hdr = &*cmsg;
            if af == libc::AF_INET
                && hdr.cmsg_level == libc::IPPROTO_IP
                && hdr.cmsg_type == libc::IP_PKTINFO
            {
                let pktinfo = libc::CMSG_DATA(cmsg) as *const libc::in_pktinfo;
                return (*pktinfo).ipi_ifindex as u32;
            }
            if af == libc::AF_INET6
                && hdr.cmsg_level == libc::IPPROTO_IPV6
                && hdr.cmsg_type == libc::IPV6_PKTINFO
            {
                let pktinfo = libc::CMSG_DATA(cmsg) as *const libc::in6_pktinfo;
                return (*pktinfo).ipi6_ifindex as u32;
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
        0
    }
}

/// Fallback `tcp_interface` for non-Linux platforms.
#[cfg(not(target_os = "linux"))]
pub fn tcp_interface(_fd: RawFd, _af: i32) -> u32 {
    0
}

// ---------------------------------------------------------------------------
// Listener Management
// ---------------------------------------------------------------------------

/// Create a set of listeners (UDP, TCP, and optionally TFTP) for an address.
///
/// Replaces C `create_listeners()` (network.c line 3996).
fn create_listeners(
    addr: &SocketAddr,
    do_tftp: bool,
    dienow: bool,
    state: &mut DaemonState,
) -> DnsmasqResult<Option<Listener>> {
    let udp_fd = make_sock(addr, false, dienow, state)?;
    let tcp_fd = make_sock(addr, true, dienow, state)?;

    let tftp_fd = {
        #[cfg(feature = "tftp")]
        {
            if do_tftp {
                let mut tftp_addr = *addr;
                tftp_addr.set_port(TFTP_PORT);
                make_sock(&tftp_addr, false, dienow, state)?
            } else {
                -1
            }
        }
        #[cfg(not(feature = "tftp"))]
        {
            let _ = do_tftp;
            -1i32
        }
    };

    if udp_fd >= 0 || tcp_fd >= 0 || tftp_fd >= 0 {
        let family = if addr.is_ipv4() {
            libc::AF_INET
        } else {
            libc::AF_INET6
        };
        let listener = Listener {
            fd: udp_fd,
            tcpfd: tcp_fd,
            tftpfd: tftp_fd,
            family,
            iface: None,
        };
        Ok(Some(listener))
    } else {
        Ok(None)
    }
}

/// Create wildcard listeners on `0.0.0.0` and `[::]`.
///
/// Replaces C `create_wildcard_listeners()` (network.c line 4405).
pub fn create_wildcard_listeners(state: &mut DaemonState) -> DnsmasqResult<()> {
    let port = state.port;

    let v4_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
    if let Some(listener) = create_listeners(&v4_addr, true, true, state)? {
        state.listeners.push(listener);
    }

    let v6_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port);
    if let Some(listener) = create_listeners(&v6_addr, true, true, state)? {
        state.listeners.push(listener);
    }

    Ok(())
}

/// Find an existing listener that matches the given address family.
#[allow(dead_code)]
fn find_listener_by_addr(addr: &IpAddr, listeners: &[Listener]) -> Option<usize> {
    let family = if addr.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    listeners.iter().position(|l| l.family == family)
}

/// Create per-interface listeners for bound mode (`--bind-interfaces`).
///
/// Replaces C `create_bound_listeners()` (network.c line 5155).
pub fn create_bound_listeners(dienow: bool, state: &mut DaemonState) -> DnsmasqResult<()> {
    // Phase 1: Create listeners for discovered interfaces
    let iface_addrs: Vec<(IpAddr, bool, usize)> = state
        .interfaces
        .iter()
        .enumerate()
        .filter(|(_, iface)| {
            !irec_has_flag(iface, IREC_DONE)
                && !irec_has_flag(iface, IREC_DAD)
                && irec_has_flag(iface, IREC_FOUND)
        })
        .map(|(idx, iface)| (iface.addr, irec_has_flag(iface, IREC_TFTP_OK), idx))
        .collect();

    for (addr, tftp_ok, iface_idx) in iface_addrs {
        let sock_addr = match addr {
            IpAddr::V4(v4) => SocketAddr::new(IpAddr::V4(v4), state.port),
            IpAddr::V6(v6) => SocketAddr::new(IpAddr::V6(v6), state.port),
        };

        if let Some(mut listener) = create_listeners(&sock_addr, tftp_ok, dienow, state)? {
            listener.iface = Some(iface_idx);
            irec_set_flag(&mut state.interfaces[iface_idx], IREC_DONE);
            if !dienow {
                info!(addr = %addr, port = state.port, "listening on interface");
            }
            state.listeners.push(listener);
        }
    }

    // Phase 2: Create listeners for unmatched --listen-address entries
    let unmatched_addrs: Vec<IpAddr> = state
        .if_addrs
        .iter()
        .filter(|ifn| !ifn.used)
        .filter_map(|ifn| ifn.addr)
        .collect();

    for addr in unmatched_addrs {
        let sock_addr = match addr {
            IpAddr::V4(v4) => SocketAddr::new(IpAddr::V4(v4), state.port),
            IpAddr::V6(v6) => SocketAddr::new(IpAddr::V6(v6), state.port),
        };

        if let Some(listener) = create_listeners(&sock_addr, true, dienow, state)? {
            if !dienow {
                info!(addr = %addr, port = state.port, "listening on configured address");
            }
            state.listeners.push(listener);
        }
    }

    Ok(())
}

/// Check whether an IPv4 address belongs to a private (RFC 1918) network.
fn is_private_ipv4(addr: &Ipv4Addr) -> bool {
    let octets = addr.octets();
    if octets[0] == 10 {
        return true;
    }
    if octets[0] == 172 && (octets[1] & 0xF0) == 16 {
        return true;
    }
    if octets[0] == 192 && octets[1] == 168 {
        return true;
    }
    if octets[0] == 127 {
        return true;
    }
    if octets[0] == 169 && octets[1] == 254 {
        return true;
    }
    false
}

/// Warn about globally routable IPv4 addresses in bind-interfaces mode.
///
/// Replaces C `warn_bound_listeners()` (network.c line 5255).
pub fn warn_bound_listeners(state: &DaemonState) {
    for iface in &state.interfaces {
        if irec_has_flag(iface, IREC_WARNED) {
            continue;
        }
        if let IpAddr::V4(ref v4) = iface.addr {
            if !is_private_ipv4(v4) && !v4.is_loopback() && !v4.is_unspecified() {
                warn!(
                    addr = %v4,
                    iface = %iface.name,
                    "listening on globally routable address; consider --bind-dynamic"
                );
            }
        }
    }
}

/// Log interfaces that were matched by wildcard label patterns.
///
/// Replaces C `warn_wild_labels()` (network.c line 5302).
pub fn warn_wild_labels(state: &DaemonState) {
    for iface in &state.interfaces {
        if irec_has_flag(iface, IREC_FOUND) && iface.label != 0 {
            debug!(
                name = %iface.name,
                label = iface.label,
                "interface matched by label"
            );
        }
    }
}

/// Log configured interface names without addresses.
///
/// Replaces C `warn_int_names()` (network.c line 5334).
pub fn warn_int_names(state: &DaemonState) {
    for int_name in &state.int_names {
        // InterfaceName has name and intr fields
        if int_name.name.is_empty() {
            continue;
        }
        // Check if any interface has this name
        let has_addr = state
            .interfaces
            .iter()
            .any(|iface| iface.name == int_name.intr);
        if !has_addr {
            warn!(
                name = %int_name.intr,
                "configured interface name has no address"
            );
        }
    }
}

/// Check if any interface has pending DAD (Duplicate Address Detection).
///
/// Replaces C `is_dad_listeners()` (network.c line 5374).
pub fn is_dad_listeners(state: &DaemonState) -> bool {
    if !state.options.is_set(opt::NOWILD) {
        return false;
    }
    state
        .interfaces
        .iter()
        .any(|iface| irec_has_flag(iface, IREC_DAD) && !irec_has_flag(iface, IREC_DONE))
}

// ---------------------------------------------------------------------------
// IPv6 Multicast (Feature-Gated)
// ---------------------------------------------------------------------------

/// Join DHCPv6-related IPv6 multicast groups on eligible interfaces.
///
/// Replaces C `join_multicast()` (network.c line 5434).
#[cfg(feature = "dhcp6")]
pub fn join_multicast(dienow: bool, state: &mut DaemonState) -> DnsmasqResult<()> {
    let mut joined_indices: Vec<u32> = Vec::new();

    let eligible: Vec<(u32, bool)> = state
        .interfaces
        .iter()
        .filter(|iface| {
            irec_has_flag(iface, IREC_DHCP6_OK)
                && iface.addr.is_ipv6()
                && irec_has_flag(iface, IREC_FOUND)
        })
        .map(|iface| (iface.index, irec_has_flag(iface, IREC_MULTICAST_DONE)))
        .collect();

    for (if_index, already_done) in eligible {
        if already_done || joined_indices.contains(&if_index) {
            continue;
        }
        joined_indices.push(if_index);

        let all_relay = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 2);
        let all_servers = Ipv6Addr::new(0xff05, 0, 0, 0, 0, 0, 1, 3);
        let all_routers = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2);

        if state.doing_dhcp6 || !state.relay6.is_empty() {
            if let Err(e) = join_ipv6_multicast(state.dhcp6fd, &all_relay, if_index) {
                handle_multicast_error(&e, dienow, "ff02::1:2", if_index)?;
            }
        }

        if state.doing_dhcp6 {
            if let Err(e) = join_ipv6_multicast(state.dhcp6fd, &all_servers, if_index) {
                handle_multicast_error(&e, dienow, "ff05::1:3", if_index)?;
            }
        }

        if state.doing_ra {
            if let Err(e) = join_ipv6_multicast(state.icmp6fd, &all_routers, if_index) {
                handle_multicast_error(&e, dienow, "ff02::2", if_index)?;
            }
        }
    }

    // Mark interfaces as multicast-done
    for iface in state.interfaces.iter_mut() {
        if irec_has_flag(iface, IREC_DHCP6_OK)
            && iface.addr.is_ipv6()
            && irec_has_flag(iface, IREC_FOUND)
            && joined_indices.contains(&iface.index)
        {
            irec_set_flag(iface, IREC_MULTICAST_DONE);
        }
    }

    Ok(())
}

/// Stub for non-dhcp6 builds.
#[cfg(not(feature = "dhcp6"))]
pub fn join_multicast(_dienow: bool, _state: &mut DaemonState) -> DnsmasqResult<()> {
    Ok(())
}

/// Join an IPv6 multicast group on a specific interface.
#[cfg(feature = "dhcp6")]
fn join_ipv6_multicast(fd: i32, group: &Ipv6Addr, if_index: u32) -> io::Result<()> {
    let mreq = libc::ipv6_mreq {
        ipv6mr_multiaddr: libc::in6_addr {
            s6_addr: group.octets(),
        },
        ipv6mr_interface: if_index,
    };
    // SAFETY: setsockopt with IPV6_ADD_MEMBERSHIP on a valid IPv6 socket.
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_ADD_MEMBERSHIP,
            &mreq as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::ipv6_mreq>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Handle a multicast join error.
#[cfg(feature = "dhcp6")]
fn handle_multicast_error(
    e: &io::Error,
    dienow: bool,
    group: &str,
    if_index: u32,
) -> DnsmasqResult<()> {
    if e.raw_os_error() == Some(libc::ENOMEM) {
        warn!(
            group = group,
            if_index = if_index,
            "failed to join multicast (ENOMEM — try increasing /proc/sys/net/core/optmem_max)"
        );
    } else {
        warn!(
            group = group,
            if_index = if_index,
            error = %e,
            "failed to join multicast group"
        );
    }
    if dienow {
        Err(DnsmasqError::Io(io::Error::other(format!(
            "failed to join multicast group {group} on interface {if_index}"
        ))))
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Upstream Server Socket Management
// ---------------------------------------------------------------------------

/// Bind an outbound DNS query socket.
///
/// Replaces C `local_bind()` (network.c line 5544).
pub fn local_bind(
    fd: RawFd,
    addr: &SocketAddr,
    intname: &str,
    ifindex: u32,
    is_tcp: bool,
    state: &DaemonState,
) -> DnsmasqResult<()> {
    let mut bind_addr = *addr;

    // TCP always uses ephemeral port
    if is_tcp {
        bind_addr.set_port(0);
    }

    // UDP port allocation when port=0 and port range is configured
    if !is_tcp && addr.port() == 0 && state.min_port > 0 {
        let port_range = state.max_port.saturating_sub(state.min_port) + 1;

        if port_range <= SMALL_PORT_RANGE {
            // Small range: systematic search
            let mut rng = SurfRng::new()?;
            let start = rng.rand16() % port_range;
            for offset in 0..port_range {
                let port = state.min_port + ((start + offset) % port_range);
                bind_addr.set_port(port);
                let sock_addr = SockAddr::from(bind_addr);
                // SAFETY: bind with a valid fd and sockaddr.
                let ret = unsafe {
                    libc::bind(
                        fd,
                        sock_addr.as_ptr() as *const libc::sockaddr,
                        sock_addr.len() as libc::socklen_t,
                    )
                };
                if ret == 0 {
                    bind_interface(fd, intname, ifindex, &bind_addr)?;
                    return Ok(());
                }
                let err = io::Error::last_os_error();
                if err.raw_os_error() != Some(libc::EADDRINUSE)
                    && err.raw_os_error() != Some(libc::EACCES)
                {
                    return Err(DnsmasqError::Io(err));
                }
            }
            return Err(DnsmasqError::Io(io::Error::new(
                io::ErrorKind::AddrInUse,
                "all ports in range are in use",
            )));
        } else {
            // Large range: up to 100 random attempts
            let mut rng = SurfRng::new()?;
            for _ in 0..100 {
                let port = state.min_port + (rng.rand16() % port_range);
                bind_addr.set_port(port);
                let sock_addr = SockAddr::from(bind_addr);
                // SAFETY: `fd` is a valid socket descriptor returned by a prior
                // `libc::socket` call.  `sock_addr` is a stack-allocated
                // `SockAddr` whose pointer and length are valid for the
                // duration of the `bind` call.
                let ret = unsafe {
                    libc::bind(
                        fd,
                        sock_addr.as_ptr() as *const libc::sockaddr,
                        sock_addr.len() as libc::socklen_t,
                    )
                };
                if ret == 0 {
                    bind_interface(fd, intname, ifindex, &bind_addr)?;
                    return Ok(());
                }
                let err = io::Error::last_os_error();
                if err.raw_os_error() != Some(libc::EADDRINUSE)
                    && err.raw_os_error() != Some(libc::EACCES)
                {
                    return Err(DnsmasqError::Io(err));
                }
            }
            return Err(DnsmasqError::Io(io::Error::new(
                io::ErrorKind::AddrInUse,
                "failed to find available port after 100 attempts",
            )));
        }
    }

    // Standard bind
    let is_wildcard = bind_addr.ip().is_unspecified();
    if !is_wildcard || bind_addr.port() != 0 {
        let sock_addr = SockAddr::from(bind_addr);
        // SAFETY: `fd` is a valid socket descriptor and `sock_addr` is a
        // stack-allocated `SockAddr` with a valid pointer and length for
        // the duration of the `bind` syscall.
        let ret = unsafe {
            libc::bind(
                fd,
                sock_addr.as_ptr() as *const libc::sockaddr,
                sock_addr.len() as libc::socklen_t,
            )
        };
        if ret < 0 {
            return Err(DnsmasqError::Io(io::Error::last_os_error()));
        }
    }

    bind_interface(fd, intname, ifindex, &bind_addr)?;
    Ok(())
}

/// Bind a socket to a specific network interface.
fn bind_interface(fd: RawFd, intname: &str, ifindex: u32, addr: &SocketAddr) -> DnsmasqResult<()> {
    if ifindex > 0 {
        let idx = ifindex as libc::c_int;
        match addr {
            SocketAddr::V4(_) => {
                // SAFETY: Setting IP_UNICAST_IF on a valid socket.
                unsafe {
                    libc::setsockopt(
                        fd,
                        libc::IPPROTO_IP,
                        libc::IP_UNICAST_IF,
                        &idx as *const _ as *const libc::c_void,
                        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                    );
                }
            }
            SocketAddr::V6(_) => {
                // SAFETY: Setting IPV6_UNICAST_IF on a valid socket.
                unsafe {
                    libc::setsockopt(
                        fd,
                        libc::IPPROTO_IPV6,
                        libc::IPV6_UNICAST_IF,
                        &idx as *const _ as *const libc::c_void,
                        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                    );
                }
            }
        }
    }

    // Linux SO_BINDTODEVICE
    #[cfg(target_os = "linux")]
    if !intname.is_empty() {
        use std::ffi::CString;
        if let Ok(cname) = CString::new(intname) {
            // SAFETY: SO_BINDTODEVICE with a NUL-terminated name.
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_BINDTODEVICE,
                    cname.as_ptr() as *const libc::c_void,
                    cname.to_bytes_with_nul().len() as libc::socklen_t,
                );
            }
        }
    }

    Ok(())
}

/// Allocate or reuse an upstream server socket from the pool.
///
/// Replaces C `allocate_sfd()` (network.c line 5690).
fn allocate_sfd(
    addr: &SocketAddr,
    intname: &str,
    state: &mut DaemonState,
) -> DnsmasqResult<Option<usize>> {
    // Random port optimization
    if !state.osport && addr.port() == 0 {
        return Ok(None);
    }

    // Search existing sfds
    for (idx, sfd) in state.sfds.iter().enumerate() {
        if sfd.source_addr == *addr {
            if let Some(ref iface) = sfd.interface {
                if iface == intname {
                    return Ok(Some(idx));
                }
            } else if intname.is_empty() {
                return Ok(Some(idx));
            }
        }
    }

    // Create new socket
    let domain = if addr.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };

    // SAFETY: Creating a UDP socket with standard parameters.
    let fd = unsafe { libc::socket(domain, libc::SOCK_DGRAM, libc::IPPROTO_UDP) };
    if fd < 0 {
        return Err(DnsmasqError::Io(io::Error::last_os_error()));
    }

    // IPv6: IPV6_V6ONLY
    if addr.is_ipv6() {
        let one: libc::c_int = 1;
        // SAFETY: Setting IPV6_V6ONLY on a valid socket.
        unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_V6ONLY,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }

    // Bind
    if let Err(e) = local_bind(fd, addr, intname, 0, false, state) {
        // SAFETY: Closing `fd` which was created by `libc::socket` above
        // and is still owned by this function (not yet stored in state).
        unsafe {
            libc::close(fd);
        }
        return Err(e);
    }

    // Set non-blocking
    if let Err(e) = fix_fd(fd) {
        // SAFETY: Closing `fd` which was created by `libc::socket` above
        // and is still owned by this function (bind succeeded but fix_fd
        // failed, so we must release the fd).
        unsafe {
            libc::close(fd);
        }
        return Err(DnsmasqError::Io(e));
    }

    let sfd = ServerFd {
        fd,
        source_addr: *addr,
        interface: if intname.is_empty() {
            None
        } else {
            Some(intname.to_string())
        },
        used: false,
    };
    state.sfds.push(sfd);
    Ok(Some(state.sfds.len() - 1))
}

/// Pre-allocate upstream DNS query sockets at startup.
///
/// Replaces C `pre_allocate_sfds()` (network.c line 5808).
pub fn pre_allocate_sfds(state: &mut DaemonState) -> DnsmasqResult<()> {
    if state.query_port != 0 {
        let v4_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), state.query_port);
        let _ = allocate_sfd(&v4_addr, "", state)?;

        let v6_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), state.query_port);
        let _ = allocate_sfd(&v6_addr, "", state)?;
    }

    // Allocate sfds for configured servers
    let server_info: Vec<(SocketAddr, String)> = state
        .servers
        .iter()
        .filter(|s| s.addr.port() != 0)
        .map(|s| {
            let source = s.source_addr.unwrap_or_else(|| {
                if s.addr.is_ipv4() {
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
                } else {
                    SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
                }
            });
            let iface = s.interface.clone().unwrap_or_default();
            (source, iface)
        })
        .collect();

    for (source, iface) in server_info {
        match allocate_sfd(&source, &iface, state) {
            Ok(_) => {}
            Err(e) => {
                if state.options.is_set(opt::NOWILD) {
                    return Err(e);
                }
                warn!(error = %e, "failed to pre-allocate server socket");
            }
        }
    }

    Ok(())
}

/// Validate and configure upstream DNS servers.
///
/// Replaces C `check_servers()` (network.c line 5926).
pub fn check_servers(_no_loop_check: bool, state: &mut DaemonState) -> DnsmasqResult<()> {
    // TIMEOUT governs the maximum interval between server health checks (in seconds)
    let _check_timeout = TIMEOUT;

    // Mark all sfds with used=false for GC
    for sfd in state.sfds.iter_mut() {
        sfd.used = false;
    }

    // Re-enumerate interfaces if not in bind-interfaces mode
    let flags: &OptionFlags = &state.options;
    if !flags.is_set(opt::NOWILD) {
        let _ = enumerate_interfaces(state, false);
    }

    let mut logged_count = 0u32;
    let server_count = state.servers.len();

    for i in 0..server_count {
        let server_addr = state.servers[i].addr;

        // Skip unspecified addresses
        if server_addr.ip().is_unspecified() {
            continue;
        }

        // Check if server is our own address (would loop)
        let local_addr = SocketAddr::new(server_addr.ip(), state.port);
        let is_local = state.interfaces.iter().any(|iface| {
            let iface_sa = SocketAddr::new(iface.addr, state.port);
            sockaddr_eq(&iface_sa, &local_addr)
        });
        if is_local && server_addr.port() == state.port {
            let formatted = format_addr(&server_addr);
            warn!(addr = %formatted, "ignoring nameserver — our own address");
            continue;
        }

        // Allocate socket for this server
        let source = state.servers[i].source_addr.unwrap_or_else(|| {
            if server_addr.is_ipv4() {
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
            } else {
                SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
            }
        });
        let iface_name = state.servers[i].interface.clone().unwrap_or_default();
        match allocate_sfd(&source, &iface_name, state) {
            Ok(sfd_idx) => {
                if let Some(idx) = sfd_idx {
                    state.sfds[idx].used = true;
                }
            }
            Err(e) => {
                warn!(addr = %server_addr, error = %e, "failed to allocate socket for server");
                continue;
            }
        }

        // Log server configuration
        if logged_count < SERVERS_LOGGED {
            if let Some(ref domain) = state.servers[i].domain {
                info!(addr = %server_addr, domain = %domain, "using nameserver for domain");
            } else {
                info!(addr = %server_addr, "using nameserver");
            }
            logged_count += 1;
        }
    }

    // Log local domains
    let mut local_logged = 0u32;
    for ld in &state.local_domains {
        if local_logged >= SERVERS_LOGGED {
            break;
        }
        if let Some(ref domain) = ld.domain {
            info!(domain = %domain, "local domain");
            local_logged += 1;
        }
    }

    // Garbage collect unused sfds — close ONLY the specific stale server
    // file descriptors.  We must NOT use close_fds() here because that
    // utility closes ALL fds in a range except a keep list, which would
    // destroy listener, DHCP, log, and other daemon fds that are not in the
    // server fd keep list.  Instead, close each stale fd individually.
    let sfds_to_close: Vec<i32> = state
        .sfds
        .iter()
        .filter(|sfd| !sfd.used)
        .map(|sfd| sfd.fd)
        .collect();
    for stale_fd in &sfds_to_close {
        // SAFETY: We are closing file descriptors that belong to server
        // socket entries marked as unused during the check_servers sweep.
        // These fds are owned by the daemon and are no longer referenced
        // by any active server entry after the retain below.
        let _ = nix::unistd::close(*stale_fd);
        trace!(fd = stale_fd, "closed stale server fd");
    }
    state.sfds.retain(|sfd| sfd.used);

    Ok(())
}

/// Reload upstream DNS servers from a resolv.conf-format file.
///
/// Replaces C `reload_servers()` (network.c line 6133).
pub fn reload_servers(fname: &str, state: &mut DaemonState) -> DnsmasqResult<bool> {
    let contents = match std::fs::read_to_string(fname) {
        Ok(c) => c,
        Err(e) => {
            warn!(file = fname, error = %e, "failed to read resolver file");
            return Ok(false);
        }
    };

    let mut got_one = false;

    // Mark existing SERV_FROM_RESOLV servers
    for server in state.servers.iter_mut() {
        if (server.flags & SERV_FROM_RESOLV) != 0 {
            server.flags |= SERV_MARK;
        }
    }

    for line in contents.lines() {
        let line = line.trim();
        // Use hostname_eq for case-insensitive keyword comparison (RFC compliant)
        if !hostname_eq(line.split_whitespace().next().unwrap_or(""), "nameserver") {
            continue;
        }
        let rest = line["nameserver".len()..].trim();
        if rest.is_empty() {
            continue;
        }

        let addr_str = rest.split_whitespace().next().unwrap_or("");
        // MAXDNAME limits hostname/address field length in resolv.conf entries
        if addr_str.is_empty() || addr_str.len() > MAXDNAME {
            continue;
        }

        // Handle IPv6 scope ID
        let (addr_part, _scope_id_str) = if let Some(pct) = addr_str.find('%') {
            (&addr_str[..pct], Some(&addr_str[pct + 1..]))
        } else {
            (addr_str, None)
        };

        let ip: IpAddr = match addr_part.parse() {
            Ok(ip) => ip,
            Err(_) => continue,
        };

        let sock_addr = SocketAddr::new(ip, state.port);

        let server_entry = ServerEntry {
            addr: sock_addr,
            source_addr: None,
            interface: None,
            domain: None,
            flags: SERV_FROM_RESOLV,
            queries: 0,
            failed_queries: 0,
            uid: 0,
        };
        state.servers.push(server_entry);
        got_one = true;
    }

    // Remove old marked servers
    state.servers.retain(|s| (s.flags & SERV_MARK) == 0);

    if got_one {
        info!(file = fname, "loaded nameservers from resolver file");
    }

    Ok(got_one)
}

/// Handle network topology changes.
///
/// Replaces C `newaddress()` (network.c line 6297).
pub fn newaddress(_now: u64, state: &mut DaemonState) -> DnsmasqResult<()> {
    let mut need_enumerate =
        state.options.is_set(opt::CLEVERBIND) || state.options.is_set(opt::LOCAL_SERVICE);

    #[cfg(feature = "dhcp6")]
    {
        need_enumerate =
            need_enumerate || state.doing_dhcp6 || !state.relay6.is_empty() || state.doing_ra;
    }

    if need_enumerate {
        enumerate_interfaces(state, false)?;
    }

    if state.options.is_set(opt::CLEVERBIND) {
        create_bound_listeners(false, state)?;
    }

    #[cfg(feature = "dhcp6")]
    {
        join_multicast(false, state)?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // ===== MySockAddr methods ==========================================

    #[test]
    fn mysockaddr_v4_family() {
        let sa = MySockAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53));
        assert_eq!(sa.family(), libc::AF_INET);
    }

    #[test]
    fn mysockaddr_v6_family() {
        let sa = MySockAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 53, 0, 0));
        assert_eq!(sa.family(), libc::AF_INET6);
    }

    #[test]
    fn mysockaddr_v4_port() {
        let sa = MySockAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1234));
        assert_eq!(sa.port(), 1234);
    }

    #[test]
    fn mysockaddr_v6_port() {
        let sa = MySockAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 5353, 0, 0));
        assert_eq!(sa.port(), 5353);
    }

    #[test]
    fn mysockaddr_set_port_v4() {
        let mut sa = MySockAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53));
        sa.set_port(8053);
        assert_eq!(sa.port(), 8053);
    }

    #[test]
    fn mysockaddr_set_port_v6() {
        let mut sa = MySockAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 53, 0, 0));
        sa.set_port(8053);
        assert_eq!(sa.port(), 8053);
    }

    #[test]
    fn mysockaddr_is_equal_same_v4() {
        let a = MySockAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 53));
        let b = MySockAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 53));
        assert!(a.is_equal(&b));
    }

    #[test]
    fn mysockaddr_is_equal_different_port() {
        let a = MySockAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53));
        let b = MySockAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 5353));
        assert!(!a.is_equal(&b));
    }

    #[test]
    fn mysockaddr_is_equal_different_family() {
        let a = MySockAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53));
        let b = MySockAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 53, 0, 0));
        assert!(!a.is_equal(&b));
    }

    #[test]
    fn mysockaddr_is_wildcard_v4() {
        let w = MySockAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
        assert!(w.is_wildcard());
        let nw = MySockAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
        assert!(!nw.is_wildcard());
    }

    #[test]
    fn mysockaddr_is_wildcard_v6() {
        let w = MySockAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0));
        assert!(w.is_wildcard());
        let nw = MySockAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0));
        assert!(!nw.is_wildcard());
    }

    // ===== mysockaddr_ip ==============================================

    #[test]
    fn mysockaddr_ip_v4() {
        let sa = MySockAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 53));
        assert_eq!(
            mysockaddr_ip(&sa),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))
        );
    }

    #[test]
    fn mysockaddr_ip_v6() {
        let sa = MySockAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 53, 0, 0));
        assert_eq!(mysockaddr_ip(&sa), IpAddr::V6(Ipv6Addr::LOCALHOST));
    }

    // ===== ip_to_mysockaddr ===========================================

    #[test]
    fn ip_to_mysockaddr_v4() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let sa = ip_to_mysockaddr(&ip, 53);
        assert_eq!(sa.port(), 53);
        assert_eq!(mysockaddr_ip(&sa), ip);
        assert_eq!(sa.family(), libc::AF_INET);
    }

    #[test]
    fn ip_to_mysockaddr_v6() {
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let sa = ip_to_mysockaddr(&ip, 5353);
        assert_eq!(sa.port(), 5353);
        assert_eq!(mysockaddr_ip(&sa), ip);
        assert_eq!(sa.family(), libc::AF_INET6);
    }

    // ===== irec flag helpers ==========================================

    fn make_irec(flags: u32) -> InterfaceRecord {
        InterfaceRecord {
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            name: "lo".to_string(),
            index: 1,
            flags,
            netmask: Some(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0))),
            label: 0,
        }
    }

    #[test]
    fn irec_has_flag_set() {
        let irec = make_irec(IREC_FOUND | IREC_DONE);
        assert!(irec_has_flag(&irec, IREC_FOUND));
        assert!(irec_has_flag(&irec, IREC_DONE));
        assert!(!irec_has_flag(&irec, IREC_WARNED));
    }

    #[test]
    fn irec_set_flag_works() {
        let mut irec = make_irec(0);
        assert!(!irec_has_flag(&irec, IREC_DAD));
        irec_set_flag(&mut irec, IREC_DAD);
        assert!(irec_has_flag(&irec, IREC_DAD));
    }

    #[test]
    fn irec_clear_flag_works() {
        let mut irec = make_irec(IREC_FOUND | IREC_DAD);
        assert!(irec_has_flag(&irec, IREC_DAD));
        irec_clear_flag(&mut irec, IREC_DAD);
        assert!(!irec_has_flag(&irec, IREC_DAD));
        assert!(irec_has_flag(&irec, IREC_FOUND)); // other flags preserved
    }

    #[test]
    fn irec_set_clear_idempotent() {
        let mut irec = make_irec(0);
        irec_set_flag(&mut irec, IREC_WARNED);
        irec_set_flag(&mut irec, IREC_WARNED);
        assert!(irec_has_flag(&irec, IREC_WARNED));
        irec_clear_flag(&mut irec, IREC_WARNED);
        irec_clear_flag(&mut irec, IREC_WARNED);
        assert!(!irec_has_flag(&irec, IREC_WARNED));
    }

    // ===== irec_to_mysockaddr =========================================

    #[test]
    fn irec_to_mysockaddr_v4() {
        let irec = InterfaceRecord {
            addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            name: "eth0".to_string(),
            index: 2,
            flags: 0,
            netmask: Some(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0))),
            label: 0,
        };
        let sa = irec_to_mysockaddr(&irec, 53);
        assert_eq!(
            mysockaddr_ip(&sa),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))
        );
        assert_eq!(sa.port(), 53);
    }

    #[test]
    fn irec_to_mysockaddr_v6() {
        let irec = InterfaceRecord {
            addr: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            name: "eth0".to_string(),
            index: 2,
            flags: 0,
            netmask: None,
            label: 0,
        };
        let sa = irec_to_mysockaddr(&irec, 5353);
        assert_eq!(sa.port(), 5353);
        assert_eq!(sa.family(), libc::AF_INET6);
    }

    // ===== netmask_to_prefix_v4 =======================================

    #[test]
    fn netmask_prefix_class_c() {
        assert_eq!(netmask_to_prefix_v4(&Ipv4Addr::new(255, 255, 255, 0)), 24);
    }

    #[test]
    fn netmask_prefix_class_b() {
        assert_eq!(netmask_to_prefix_v4(&Ipv4Addr::new(255, 255, 0, 0)), 16);
    }

    #[test]
    fn netmask_prefix_class_a() {
        assert_eq!(netmask_to_prefix_v4(&Ipv4Addr::new(255, 0, 0, 0)), 8);
    }

    #[test]
    fn netmask_prefix_slash32() {
        assert_eq!(netmask_to_prefix_v4(&Ipv4Addr::new(255, 255, 255, 255)), 32);
    }

    #[test]
    fn netmask_prefix_slash0() {
        assert_eq!(netmask_to_prefix_v4(&Ipv4Addr::new(0, 0, 0, 0)), 0);
    }

    #[test]
    fn netmask_prefix_slash28() {
        assert_eq!(netmask_to_prefix_v4(&Ipv4Addr::new(255, 255, 255, 240)), 28);
    }

    #[test]
    fn netmask_prefix_slash20() {
        assert_eq!(netmask_to_prefix_v4(&Ipv4Addr::new(255, 255, 240, 0)), 20);
    }

    // ===== is_private_ipv4 ============================================

    #[test]
    fn is_private_10_x() {
        assert!(is_private_ipv4(&Ipv4Addr::new(10, 0, 0, 1)));
        assert!(is_private_ipv4(&Ipv4Addr::new(10, 255, 255, 255)));
    }

    #[test]
    fn is_private_172_16() {
        assert!(is_private_ipv4(&Ipv4Addr::new(172, 16, 0, 0)));
        assert!(is_private_ipv4(&Ipv4Addr::new(172, 31, 255, 255)));
        assert!(!is_private_ipv4(&Ipv4Addr::new(172, 32, 0, 0)));
    }

    #[test]
    fn is_private_192_168() {
        assert!(is_private_ipv4(&Ipv4Addr::new(192, 168, 0, 1)));
        assert!(is_private_ipv4(&Ipv4Addr::new(192, 168, 255, 255)));
    }

    #[test]
    fn is_private_loopback() {
        assert!(is_private_ipv4(&Ipv4Addr::new(127, 0, 0, 1)));
        assert!(is_private_ipv4(&Ipv4Addr::new(127, 255, 255, 255)));
    }

    #[test]
    fn is_private_link_local() {
        assert!(is_private_ipv4(&Ipv4Addr::new(169, 254, 0, 1)));
        assert!(is_private_ipv4(&Ipv4Addr::new(169, 254, 255, 255)));
    }

    #[test]
    fn is_not_private_public_ips() {
        assert!(!is_private_ipv4(&Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!is_private_ipv4(&Ipv4Addr::new(1, 1, 1, 1)));
        assert!(!is_private_ipv4(&Ipv4Addr::new(203, 0, 113, 1)));
    }

    // ===== SERV_* flag constants ======================================

    #[test]
    fn serv_flags_unique_bits() {
        let flags = [
            SERV_USE_RESOLV,
            SERV_LITERAL_ADDRESS,
            SERV_NO_ADDR,
            SERV_4ADDR,
            SERV_6ADDR,
            SERV_COUNTED,
            SERV_FOR_NODOTS,
            SERV_WARNED_RECURSIVE,
            SERV_FROM_DBUS,
            SERV_MARK,
            SERV_WILDCARD,
            SERV_FROM_RESOLV,
            SERV_FROM_FILE,
            SERV_LOOP,
            SERV_DO_DNSSEC,
            SERV_GOT_TCP,
            SERV_HAS_DOMAIN,
            SERV_NO_REBIND,
        ];
        for &f in &flags {
            assert!(f.is_power_of_two(), "SERV flag 0x{:x} not a power of 2", f);
        }
    }

    #[test]
    fn serv_type_composite() {
        let expected = SERV_LITERAL_ADDRESS | SERV_NO_ADDR | SERV_FOR_NODOTS | SERV_USE_RESOLV;
        assert_eq!(SERV_TYPE, expected);
    }

    // ===== IREC_* flag constants ======================================

    #[test]
    fn irec_flags_unique_bits() {
        let flags = [
            IREC_FOUND,
            IREC_DONE,
            IREC_WARNED,
            IREC_DAD,
            IREC_DNS_AUTH,
            IREC_MULTICAST_DONE,
            IREC_TFTP_OK,
            IREC_DHCP4_OK,
            IREC_DHCP6_OK,
        ];
        for &f in &flags {
            assert!(f.is_power_of_two(), "IREC flag 0x{:x} not a power of 2", f);
        }
    }

    // ===== INAME_* constants ==========================================

    #[test]
    fn iname_constants() {
        assert_eq!(INAME_USED, 1);
        assert_eq!(INAME_4, 2);
        assert_eq!(INAME_6, 4);
    }

    // ===== loopback_exception =========================================

    #[test]
    fn loopback_exception_non_loopback_returns_false() {
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ifaces = vec![make_irec(0)];
        assert!(!loopback_exception("eth0", libc::AF_INET, &addr, &ifaces));
    }

    #[test]
    fn loopback_exception_lo_with_matching_addr() {
        let addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let irec = InterfaceRecord {
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            name: "lo".to_string(),
            index: 1,
            flags: 0,
            netmask: Some(IpAddr::V4(Ipv4Addr::new(255, 0, 0, 0))),
            label: 0,
        };
        assert!(loopback_exception("lo", libc::AF_INET, &addr, &[irec]));
    }

    #[test]
    fn loopback_exception_lo_no_matching_addr() {
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let irec = InterfaceRecord {
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            name: "lo".to_string(),
            index: 1,
            flags: 0,
            netmask: Some(IpAddr::V4(Ipv4Addr::new(255, 0, 0, 0))),
            label: 0,
        };
        assert!(!loopback_exception("lo", libc::AF_INET, &addr, &[irec]));
    }

    // ===== label_exception ============================================

    #[test]
    fn label_exception_ipv6_returns_false() {
        let addr = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert!(!label_exception(1, libc::AF_INET6, &addr, &[]));
    }

    #[test]
    fn label_exception_matching() {
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let irec = InterfaceRecord {
            addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            name: "eth0".to_string(),
            index: 2,
            flags: 0,
            netmask: Some(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0))),
            label: 0,
        };
        assert!(label_exception(2, libc::AF_INET, &addr, &[irec]));
    }

    #[test]
    fn label_exception_different_index() {
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let irec = InterfaceRecord {
            addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            name: "eth0".to_string(),
            index: 2,
            flags: 0,
            netmask: Some(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0))),
            label: 0,
        };
        assert!(!label_exception(3, libc::AF_INET, &addr, &[irec]));
    }

    #[test]
    fn label_exception_empty_interfaces() {
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        assert!(!label_exception(1, libc::AF_INET, &addr, &[]));
    }

    // ===== index_to_name ==============================================

    #[test]
    fn index_to_name_zero_returns_none() {
        assert!(index_to_name(0).is_none());
    }

    #[test]
    fn index_to_name_lo() {
        let result = index_to_name(1);
        assert!(result.is_some());
        let name = result.unwrap();
        assert!(!name.is_empty());
    }

    #[test]
    fn index_to_name_invalid_index() {
        assert!(index_to_name(99999).is_none());
    }

    // ===== iface_check ================================================

    #[test]
    fn iface_check_no_filters_allows_all() {
        let state = DaemonState::default();
        let (allowed, _is_auth) = iface_check(
            libc::AF_INET,
            Some(&IpAddr::V4(Ipv4Addr::LOCALHOST)),
            "eth0",
            &state,
        );
        assert!(allowed, "no filters configured should allow all");
    }

    // ===== fix_fd =====================================================

    #[test]
    fn fix_fd_invalid_fd_returns_error() {
        let result = fix_fd(-1);
        assert!(result.is_err());
    }

    // ===== clean_interfaces ===========================================

    #[test]
    fn clean_interfaces_removes_unfound() {
        let found = InterfaceRecord {
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            name: "lo".to_string(),
            index: 1,
            flags: IREC_FOUND,
            netmask: Some(IpAddr::V4(Ipv4Addr::new(255, 0, 0, 0))),
            label: 0,
        };
        let not_found = InterfaceRecord {
            addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            name: "eth0".to_string(),
            index: 2,
            flags: 0,
            netmask: Some(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0))),
            label: 0,
        };
        let mut ifaces = vec![found.clone(), not_found];
        clean_interfaces(&mut ifaces);
        assert_eq!(ifaces.len(), 1);
        assert_eq!(ifaces[0].name, "lo");
    }

    #[test]
    fn clean_interfaces_empty() {
        let mut ifaces: Vec<InterfaceRecord> = vec![];
        clean_interfaces(&mut ifaces);
        assert!(ifaces.is_empty());
    }

    // ===== find_listener_by_addr ======================================

    #[test]
    fn find_listener_by_addr_found_v4() {
        let listeners = vec![
            Listener {
                fd: -1,
                tcpfd: -1,
                tftpfd: -1,
                family: libc::AF_INET,
                iface: Some(0),
            },
            Listener {
                fd: -1,
                tcpfd: -1,
                tftpfd: -1,
                family: libc::AF_INET6,
                iface: Some(1),
            },
        ];
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let idx = find_listener_by_addr(&ip, &listeners);
        assert_eq!(idx, Some(0)); // first AF_INET match
    }

    #[test]
    fn find_listener_by_addr_found_v6() {
        let listeners = vec![
            Listener {
                fd: -1,
                tcpfd: -1,
                tftpfd: -1,
                family: libc::AF_INET,
                iface: Some(0),
            },
            Listener {
                fd: -1,
                tcpfd: -1,
                tftpfd: -1,
                family: libc::AF_INET6,
                iface: Some(1),
            },
        ];
        let ip = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let idx = find_listener_by_addr(&ip, &listeners);
        assert_eq!(idx, Some(1)); // second element is AF_INET6
    }

    #[test]
    fn find_listener_by_addr_not_found() {
        let listeners = vec![Listener {
            fd: -1,
            tcpfd: -1,
            tftpfd: -1,
            family: libc::AF_INET,
            iface: Some(0),
        }];
        // Looking for v6 but only v4 listener exists
        let ip = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert_eq!(find_listener_by_addr(&ip, &listeners), None);
    }

    #[test]
    fn find_listener_by_addr_empty() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert_eq!(find_listener_by_addr(&ip, &[]), None);
    }

    // ===== Constants checks ==========================================

    #[test]
    fn tftp_port_constant() {
        assert_eq!(TFTP_PORT, 69);
    }

    #[test]
    fn locals_logged_constant() {
        assert_eq!(LOCALS_LOGGED, 8);
    }
}

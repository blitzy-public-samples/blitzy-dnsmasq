// Copyright (c) 2000-2025 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

//! BSD/Solaris BPF (Berkeley Packet Filter) interface for raw DHCP packet
//! transmission and PF_ROUTE interface monitoring.
//!
//! This module is the BSD counterpart to `netlink.rs` (Linux). It provides:
//!
//! - **BPF**: Raw packet I/O for DHCP. When a DHCP client first boots, it has
//!   no IP address and cannot use the kernel IP stack. BPF allows constructing
//!   and sending complete Ethernet + IP + UDP frames directly on the wire.
//! - **PF_ROUTE**: Interface monitoring via BSD routing sockets, equivalent to
//!   Linux's netlink `RTMGRP_IPV4_IFADDR` / `RTMGRP_IPV6_IFADDR` multicast
//!   groups. Receives `RTM_NEWADDR` and `RTM_DELADDR` notifications when
//!   interface addresses change.
//! - **`getifaddrs(3)`**: Interface enumeration, equivalent to Linux's
//!   `RTM_GETADDR` netlink dump.
//!
//! Migrated from `src/bpf.c` (805 lines) in the C dnsmasq implementation.
//!
//! # Platform Gating
//!
//! This entire module is compiled only on BSD-family operating systems:
//! `cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "macos"))`.
//! The equivalent Linux functionality is provided by `netlink.rs`.
//!
//! # Safety
//!
//! This module contains `unsafe` blocks for:
//! - Parsing BSD routing socket messages (`rt_msghdr`, `ifa_msghdr`)
//! - BPF device ioctl operations (`BIOCSETIF`)
//! - Raw Ethernet frame construction and transmission via `writev()`
//! - BSD `sysctl`-based ARP table enumeration (non-macOS)
//! - Interface address extraction from `getifaddrs` linked list
//! All unsafe blocks have `// SAFETY:` comments explaining invariants.

// ---------------------------------------------------------------------------
// Imports
// ---------------------------------------------------------------------------

use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::io::{AsRawFd, RawFd};

use nix::net::if_::if_nametoindex;
#[cfg(not(target_os = "macos"))]
use nix::sys::socket::{socket, AddressFamily, SockFlag, SockType};
use tracing::{debug, error, warn};

use crate::core::types::{DnsmasqError, DnsmasqResult, EventCode};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Ethernet address length in bytes.
const ETHER_ADDR_LEN: usize = 6;

/// EtherType for IPv4 (0x0800).
const ETHERTYPE_IP: u16 = 0x0800;

/// IPv4 protocol number for UDP.
const IPPROTO_UDP: u8 = 17;

/// Default IPv4 Time-To-Live.
const IPDEFTTL: u8 = 64;

/// IPv4 version number.
const IPVERSION: u8 = 4;

/// ARP hardware type: Ethernet (10 Mbit).
/// Matches C `ARPHRD_ETHER` — only hardware type supported for BPF DHCP.
const ARPHRD_ETHER: u16 = 1;

/// DHCP server port (bootps).
const DHCP_SERVER_PORT: u16 = 67;

/// DHCP client port (bootpc).
const DHCP_CLIENT_PORT: u16 = 68;

/// Ethernet header size in bytes (dst MAC + src MAC + EtherType).
const ETHER_HDR_LEN: usize = 14;

/// IPv4 header size in bytes (no options).
const IP_HDR_LEN: usize = 20;

/// UDP header size in bytes.
const UDP_HDR_LEN: usize = 8;

/// IPv4 Don't Fragment flag (bit 14 of flags/fragment offset field).
const IP_DF: u16 = 0x4000;

/// Maximum number of BPF devices to try opening (`/dev/bpf0` .. `/dev/bpfN`).
const BPF_MAX_DEVICES: usize = 256;

/// BPF device path prefix on BSD.
const BPF_DEV_PREFIX: &str = "/dev/bpf";

// DHCP packet field offsets (RFC 2131 §2):
// op(1) htype(1) hlen(1) hops(1) xid(4) secs(2) flags(2) ciaddr(4) yiaddr(4) ...
const DHCP_HTYPE_OFFSET: usize = 1;
const DHCP_HLEN_OFFSET: usize = 2;
const DHCP_FLAGS_OFFSET: usize = 10;
const DHCP_YIADDR_OFFSET: usize = 16;
const DHCP_CHADDR_OFFSET: usize = 28;

/// DHCP broadcast flag (bit 15 of the flags field).
const DHCP_BROADCAST_FLAG: u16 = 0x8000;

/// RTA_IFA bit mask — identifies the interface address in PF_ROUTE messages.
/// Used when walking the address mask vector in `ifa_msghdr.ifam_addrs`.
const RTA_IFA_BIT: i32 = 0x20;

/// Interface flag: address is in tentative state (IPv6 DAD in progress).
#[cfg(not(target_os = "macos"))]
const IFACE_TENTATIVE: u32 = 1;
/// Interface flag: address is deprecated.
#[cfg(not(target_os = "macos"))]
const IFACE_DEPRECATED: u32 = 2;
/// Interface flag: address is permanent (not dynamically assigned).
const IFACE_PERMANENT: u32 = 4;

// ---------------------------------------------------------------------------
// BSD routing message header definitions
// ---------------------------------------------------------------------------
// `libc::rt_msghdr` is only available on macOS; FreeBSD/OpenBSD need local
// definitions. We define the struct ourselves for cross-BSD portability.

/// BSD routing message header (mirrors C `struct rt_msghdr`).
/// Used to parse sysctl ARP table responses in [`arp_enumerate_bsd()`].
#[repr(C)]
#[allow(non_camel_case_types, dead_code)]
struct rt_msghdr_local {
    rtm_msglen: libc::c_ushort,
    rtm_version: libc::c_uchar,
    rtm_type: libc::c_uchar,
    rtm_index: libc::c_ushort,
    rtm_flags: libc::c_int,
    rtm_addrs: libc::c_int,
    rtm_pid: libc::pid_t,
    rtm_seq: libc::c_int,
    rtm_errno: libc::c_int,
    rtm_fmask: libc::c_int,
    _rtm_inits: libc::c_ulong,
    // rt_metrics follows but we don't need it
}

// ---------------------------------------------------------------------------
// Helper: SA_SIZE equivalent
// ---------------------------------------------------------------------------

/// Compute aligned socket address size for PF_ROUTE message parsing.
///
/// Replaces C's `SA_SIZE` macro from `bpf.c` lines 103–107:
/// ```c
/// #define SA_SIZE(sa) \
///     (sa->sa_len ? (1 + ((sa->sa_len - 1) | (sizeof(long) - 1))) \
///                  : sizeof(long))
/// ```
///
/// Socket addresses in PF_ROUTE messages are padded to `sizeof(long)` boundary.
/// If `sa_len` is 0 (minimal address), return `sizeof(long)`.
/// Otherwise, round up to the next `long` boundary.
fn sa_size(sa_len: usize) -> usize {
    if sa_len == 0 {
        mem::size_of::<usize>()
    } else {
        1 + ((sa_len - 1) | (mem::size_of::<usize>() - 1))
    }
}

// ---------------------------------------------------------------------------
// Helper: Internet Checksum (RFC 1071)
// ---------------------------------------------------------------------------

/// Compute the RFC 1071 Internet Checksum over a byte slice.
///
/// Used for IPv4 header checksum in [`send_via_bpf()`].
/// Algorithm: one's complement sum of 16-bit words, then one's complement of
/// the result.
fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    // Handle odd-length data by padding with a trailing zero byte.
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    // Fold 32-bit sum to 16 bits.
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Compute UDP checksum with pseudo-header per RFC 768.
///
/// The UDP checksum covers a 12-byte pseudo-header (src IP, dst IP, zero,
/// protocol, UDP length), followed by the UDP header and payload.
fn udp_checksum(src: Ipv4Addr, dst: Ipv4Addr, udp_header: &[u8], payload: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Pseudo-header: source IP (4 bytes as two 16-bit words).
    let s = src.octets();
    sum += u16::from_be_bytes([s[0], s[1]]) as u32;
    sum += u16::from_be_bytes([s[2], s[3]]) as u32;

    // Pseudo-header: destination IP.
    let d = dst.octets();
    sum += u16::from_be_bytes([d[0], d[1]]) as u32;
    sum += u16::from_be_bytes([d[2], d[3]]) as u32;

    // Pseudo-header: zero + protocol (UDP=17) + UDP length.
    sum += IPPROTO_UDP as u32;
    sum += (udp_header.len() + payload.len()) as u32;

    // Sum UDP header words.
    let mut i = 0;
    while i + 1 < udp_header.len() {
        sum += u16::from_be_bytes([udp_header[i], udp_header[i + 1]]) as u32;
        i += 2;
    }

    // Sum payload words.
    i = 0;
    while i + 1 < payload.len() {
        sum += u16::from_be_bytes([payload[i], payload[i + 1]]) as u32;
        i += 2;
    }
    if i < payload.len() {
        sum += (payload[i] as u32) << 8;
    }

    // Fold 32-bit sum to 16 bits.
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    let result = !(sum as u16);
    // RFC 768: transmit 0xFFFF instead of 0x0000 for a computed-zero checksum.
    if result == 0 {
        0xFFFF
    } else {
        result
    }
}

// ---------------------------------------------------------------------------
// DeletionFilter — BSD kernel race condition workaround
// ---------------------------------------------------------------------------

/// Tracks recently deleted addresses to work around a BSD kernel race condition.
///
/// After `RTM_DELADDR`, the deleted address may still appear in `getifaddrs()`
/// results for a brief period. We store the deleted address and filter it from
/// enumeration results until the next `RTM_NEWADDR` clears the filter.
///
/// Replaces C static variables `del_family` and `del_addr` (`bpf.c` lines 110–111).
#[derive(Debug)]
struct DeletionFilter {
    /// Address family of the deleted address (`AF_INET` or `AF_INET6`), or `None`.
    family: Option<i32>,
    /// The recently-deleted IP address to filter from enumeration.
    addr: Option<IpAddr>,
}

impl DeletionFilter {
    /// Create a new empty (inactive) deletion filter.
    fn new() -> Self {
        Self {
            family: None,
            addr: None,
        }
    }

    /// Clear the filter. Called on `RTM_NEWADDR` to stop filtering.
    fn clear(&mut self) {
        self.family = None;
        self.addr = None;
    }

    /// Arm the filter with a deleted address. Called on `RTM_DELADDR`.
    fn set(&mut self, family: i32, addr: IpAddr) {
        self.family = Some(family);
        self.addr = Some(addr);
    }

    /// Returns `true` if the given address matches the active filter.
    fn matches(&self, family: i32, addr: &IpAddr) -> bool {
        match (self.family, &self.addr) {
            (Some(f), Some(a)) => f == family && a == addr,
            _ => false,
        }
    }
}

// ---------------------------------------------------------------------------
// IfAddrsGuard — RAII cleanup for libc::getifaddrs
// ---------------------------------------------------------------------------

/// RAII guard that calls `freeifaddrs()` on drop.
/// Replaces C's manual `freeifaddrs()` call at end of `iface_enumerate()`.
struct IfAddrsGuard(*mut libc::ifaddrs);

impl Drop for IfAddrsGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: self.0 was returned by libc::getifaddrs() and has not been
            // freed yet. freeifaddrs() frees the entire linked list.
            unsafe {
                libc::freeifaddrs(self.0);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// BpfNetwork — main public struct
// ---------------------------------------------------------------------------

/// BSD network interface abstraction providing raw packet I/O, routing socket
/// monitoring, and interface enumeration via `getifaddrs(3)`.
///
/// This struct encapsulates the state previously held in C static variables
/// and the `daemon` struct. It is the BSD counterpart to `NetlinkNetwork` on
/// Linux and implements the same logical interface for the platform abstraction
/// layer in [`super::mod.rs`].
///
/// # State Management
///
/// - `route_fd`: PF_ROUTE socket for receiving `RTM_NEWADDR`/`RTM_DELADDR`
/// - `bpf_fd`: BPF device for raw DHCP packet transmission (DHCP feature only)
/// - `del_filter`: Tracks recently deleted addresses for kernel race workaround
/// - `version_warned`: Prevents repeated `RTM_VERSION` mismatch log warnings
pub struct BpfNetwork {
    /// PF_ROUTE socket for monitoring interface changes.
    /// Replaces `daemon->routefd` in C.
    route_fd: RawFd,

    /// BPF device file descriptor for raw DHCP packet transmission.
    /// Replaces `daemon->dhcp_raw_fd` in C.
    #[cfg(feature = "dhcp")]
    bpf_fd: Option<RawFd>,

    /// Deletion filter for BSD kernel race condition workaround.
    del_filter: DeletionFilter,

    /// Whether we have already warned about `RTM_VERSION` mismatch.
    /// Prevents log spam; matches C's `static int warned` flag in `route_sock()`.
    version_warned: bool,
}

impl BpfNetwork {
    /// Create a new BSD network interface manager.
    ///
    /// Initializes the PF_ROUTE socket for interface change monitoring.
    /// The BPF device is **not** opened until [`init_bpf()`] is called explicitly.
    pub fn new() -> DnsmasqResult<Self> {
        let route_fd = route_init()?;
        debug!(fd = route_fd, "BpfNetwork: initialized PF_ROUTE socket");
        Ok(Self {
            route_fd,
            #[cfg(feature = "dhcp")]
            bpf_fd: None,
            del_filter: DeletionFilter::new(),
            version_warned: false,
        })
    }

    /// Enumerate IPv4 network interfaces via `getifaddrs(3)`.
    ///
    /// Calls `callback` for each IPv4 address found on an interface. The
    /// callback receives `(addr, if_index, iface_name, netmask, broadcast)`
    /// and returns `true` to continue enumeration or `false` to stop.
    ///
    /// Applies the deletion filter to skip addresses recently removed by
    /// `RTM_DELADDR` that may still appear in `getifaddrs()` results.
    ///
    /// Replaces the `AF_INET` branch of C's `iface_enumerate()` (`bpf.c` line 275).
    pub fn enumerate_interfaces_v4<F>(&mut self, mut callback: F) -> DnsmasqResult<bool>
    where
        F: FnMut(Ipv4Addr, u32, &str, Ipv4Addr, Ipv4Addr) -> bool,
    {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();

        // SAFETY: getifaddrs allocates a linked list of interface addresses.
        // We must call freeifaddrs() when done (handled by IfAddrsGuard).
        let rc = unsafe { libc::getifaddrs(&mut ifap) };
        if rc != 0 {
            return Err(DnsmasqError::Network(format!(
                "getifaddrs failed: {}",
                io::Error::last_os_error()
            )));
        }
        let _guard = IfAddrsGuard(ifap);

        let mut ifa = ifap;
        while !ifa.is_null() {
            // SAFETY: ifa is a valid pointer from the getifaddrs linked list.
            // We check for null before dereferencing and advance via ifa_next.
            let (addr, if_name, netmask, broadcast, next) = unsafe {
                let ifaddr = &*ifa;
                let next = ifaddr.ifa_next;

                // Skip entries without an address or non-IPv4 addresses.
                if ifaddr.ifa_addr.is_null() {
                    ifa = next;
                    continue;
                }
                let sa = &*ifaddr.ifa_addr;
                if sa.sa_family as i32 != libc::AF_INET {
                    ifa = next;
                    continue;
                }

                // Extract IPv4 address from sockaddr_in.
                let sin = &*(ifaddr.ifa_addr as *const libc::sockaddr_in);
                let b = sin.sin_addr.s_addr.to_ne_bytes();
                let addr = Ipv4Addr::new(b[0], b[1], b[2], b[3]);

                // Extract interface name.
                let name_cstr = std::ffi::CStr::from_ptr(ifaddr.ifa_name);
                let name = name_cstr.to_string_lossy().into_owned();

                // Extract netmask.
                let netmask = if !ifaddr.ifa_netmask.is_null() {
                    let nm_sa = &*ifaddr.ifa_netmask;
                    if nm_sa.sa_family as i32 == libc::AF_INET {
                        let nm_sin = &*(ifaddr.ifa_netmask as *const libc::sockaddr_in);
                        let nb = nm_sin.sin_addr.s_addr.to_ne_bytes();
                        Ipv4Addr::new(nb[0], nb[1], nb[2], nb[3])
                    } else {
                        Ipv4Addr::UNSPECIFIED
                    }
                } else {
                    Ipv4Addr::UNSPECIFIED
                };

                // Extract broadcast / destination address.
                // On BSD, ifa_broadaddr and ifa_dstaddr are a union; libc crate
                // exposes it as ifa_dstaddr on all BSDs.
                let broadcast = if !ifaddr.ifa_dstaddr.is_null() {
                    let bc_sa = &*ifaddr.ifa_dstaddr;
                    if bc_sa.sa_family as i32 == libc::AF_INET {
                        let bc_sin = &*(ifaddr.ifa_dstaddr as *const libc::sockaddr_in);
                        let bb = bc_sin.sin_addr.s_addr.to_ne_bytes();
                        Ipv4Addr::new(bb[0], bb[1], bb[2], bb[3])
                    } else {
                        Ipv4Addr::BROADCAST
                    }
                } else {
                    Ipv4Addr::BROADCAST
                };

                (addr, name, netmask, broadcast, next)
            };

            // Apply deletion filter (skip recently deleted addresses).
            if self.del_filter.matches(libc::AF_INET, &IpAddr::V4(addr)) {
                debug!(addr = %addr, iface = %if_name, "skipping deleted IPv4 addr");
                ifa = next;
                continue;
            }

            // Resolve interface index from name.
            let if_index = if_nametoindex(if_name.as_str()).unwrap_or(0);

            if !callback(addr, if_index, &if_name, netmask, broadcast) {
                return Ok(false);
            }
            ifa = next;
        }

        Ok(true)
    }

    /// Enumerate IPv6 network interfaces via `getifaddrs(3)`.
    ///
    /// Calls `callback` for each IPv6 address found. Parameters:
    /// `(addr, prefix_len, scope_id, if_index, flags, preferred, valid)`.
    ///
    /// On non-Apple BSD, retrieves additional IPv6 address flags
    /// (`TENTATIVE`/`DEPRECATED`/`PERMANENT`) and lifetimes via ioctls.
    ///
    /// Replaces the `AF_INET6` branch of C's `iface_enumerate()` (`bpf.c` line 275).
    pub fn enumerate_interfaces_v6<F>(&mut self, mut callback: F) -> DnsmasqResult<bool>
    where
        F: FnMut(Ipv6Addr, u32, u32, u32, u32, u32, u32) -> bool,
    {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();

        // SAFETY: getifaddrs allocates a linked list; IfAddrsGuard frees it.
        let rc = unsafe { libc::getifaddrs(&mut ifap) };
        if rc != 0 {
            return Err(DnsmasqError::Network(format!(
                "getifaddrs failed: {}",
                io::Error::last_os_error()
            )));
        }
        let _guard = IfAddrsGuard(ifap);

        let mut ifa = ifap;
        while !ifa.is_null() {
            // SAFETY: ifa is a valid node in the getifaddrs linked list.
            let (addr, scope_id, prefix_len, if_name, next) = unsafe {
                let ifaddr = &*ifa;
                let next = ifaddr.ifa_next;

                if ifaddr.ifa_addr.is_null() {
                    ifa = next;
                    continue;
                }
                let sa = &*ifaddr.ifa_addr;
                if sa.sa_family as i32 != libc::AF_INET6 {
                    ifa = next;
                    continue;
                }

                let sin6 = &*(ifaddr.ifa_addr as *const libc::sockaddr_in6);
                let addr = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                let scope_id = sin6.sin6_scope_id;

                let name_cstr = std::ffi::CStr::from_ptr(ifaddr.ifa_name);
                let name = name_cstr.to_string_lossy().into_owned();

                // Compute prefix length from netmask (count set bits).
                let prefix_len = if !ifaddr.ifa_netmask.is_null() {
                    let nm_sa = &*ifaddr.ifa_netmask;
                    if nm_sa.sa_family as i32 == libc::AF_INET6 {
                        let nm6 = &*(ifaddr.ifa_netmask as *const libc::sockaddr_in6);
                        nm6.sin6_addr
                            .s6_addr
                            .iter()
                            .map(|b| b.count_ones())
                            .sum::<u32>()
                    } else {
                        128
                    }
                } else {
                    128
                };

                (addr, scope_id, prefix_len, name, next)
            };

            // Apply deletion filter.
            if self.del_filter.matches(libc::AF_INET6, &IpAddr::V6(addr)) {
                debug!(addr = %addr, iface = %if_name, "skipping deleted IPv6 addr");
                ifa = next;
                continue;
            }

            let if_index = if_nametoindex(if_name.as_str()).unwrap_or(0);

            // Get IPv6 address flags and lifetimes (platform-specific).
            let (flags, preferred, valid) = get_ipv6_addr_info(&if_name, &addr);

            if !callback(
                addr, prefix_len, scope_id, if_index, flags, preferred, valid,
            ) {
                return Ok(false);
            }
            ifa = next;
        }

        Ok(true)
    }

    /// Initialize interface-change monitoring.
    ///
    /// The PF_ROUTE socket is already created during [`BpfNetwork::new()`], so
    /// this method is effectively a no-op. It exists to satisfy the
    /// `PlatformNetwork` trait interface defined in [`super::mod`].
    pub fn init_monitoring(&mut self) -> DnsmasqResult<()> {
        debug!(fd = self.route_fd, "BpfNetwork: init_monitoring complete");
        Ok(())
    }

    /// Read and process a message from the PF_ROUTE socket.
    ///
    /// Called from the main event loop when the routing socket is readable.
    /// Updates the internal deletion filter and returns an event code.
    ///
    /// - `RTM_NEWADDR` → clears deletion filter, returns `EventCode::NewAddr`
    /// - `RTM_DELADDR` → extracts deleted address into filter, returns `EventCode::NewAddr`
    /// - Other messages → returns `None`
    ///
    /// Replaces C's `route_sock()` from `bpf.c` line 740.
    fn process_route_message(&mut self, buf: &mut [u8]) -> Option<EventCode> {
        // SAFETY: self.route_fd is a valid non-blocking PF_ROUTE socket created
        // in route_init(). read() will return immediately (O_NONBLOCK) with the
        // next routing message or -1/EAGAIN if none available.
        let n = unsafe {
            libc::read(
                self.route_fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
            )
        };

        if n <= 0 {
            return None;
        }
        let n = n as usize;

        // Need at least a complete if_msghdr to parse message type + version.
        if n < mem::size_of::<libc::if_msghdr>() {
            return None;
        }

        // SAFETY: We verified n >= size_of::<if_msghdr>(), and the buffer was
        // filled by the kernel routing socket producing properly-structured
        // if_msghdr / ifa_msghdr messages.
        unsafe {
            let msg = &*(buf.as_ptr() as *const libc::if_msghdr);

            // Version check: warn once if mismatched (bpf.c line 758).
            if !self.version_warned && msg.ifm_version as i32 != libc::RTM_VERSION {
                warn!(
                    expected = libc::RTM_VERSION,
                    actual = msg.ifm_version as i32,
                    "routing socket message version mismatch"
                );
                self.version_warned = true;
            }

            match msg.ifm_type as i32 {
                libc::RTM_NEWADDR => {
                    // New address added — clear the deletion filter and notify.
                    self.del_filter.clear();
                    debug!("route_sock: RTM_NEWADDR");
                    Some(EventCode::NewAddr)
                }

                libc::RTM_DELADDR => {
                    // Address deleted — extract and store in filter, then notify.
                    self.extract_deleted_address(buf, n);
                    debug!("route_sock: RTM_DELADDR");
                    Some(EventCode::NewAddr)
                }

                _ => None,
            }
        }
    }

    /// Extract the deleted address from an `RTM_DELADDR` routing message and
    /// store it in the deletion filter.
    ///
    /// Walks the address mask vector in `ifa_msghdr` to find `RTA_IFA`, then
    /// reads the `AF_INET` or `AF_INET6` address from that position.
    ///
    /// Replaces C code from `bpf.c` lines 770–803.
    fn extract_deleted_address(&mut self, buf: &[u8], len: usize) {
        if len < mem::size_of::<libc::ifa_msghdr>() {
            return;
        }

        // SAFETY: We verified len >= size_of::<ifa_msghdr>() and the buffer
        // was written by the kernel routing socket.
        unsafe {
            let ifa = &*(buf.as_ptr() as *const libc::ifa_msghdr);
            let addrs_mask = ifa.ifam_addrs;

            // Addresses follow the ifa_msghdr in order of their bit position.
            let mut offset = mem::size_of::<libc::ifa_msghdr>();
            let mut bit: i32 = 1;

            while bit <= addrs_mask && offset < len {
                if addrs_mask & bit != 0 {
                    if offset + mem::size_of::<libc::sockaddr>() > len {
                        break;
                    }

                    let sa = &*(buf.as_ptr().add(offset) as *const libc::sockaddr);

                    if bit == RTA_IFA_BIT {
                        // Found the RTA_IFA address — the one being deleted.
                        let family = sa.sa_family as i32;

                        if family == libc::AF_INET
                            && offset + mem::size_of::<libc::sockaddr_in>() <= len
                        {
                            let sin = &*(buf.as_ptr().add(offset) as *const libc::sockaddr_in);
                            let b = sin.sin_addr.s_addr.to_ne_bytes();
                            let addr = IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3]));
                            self.del_filter.set(libc::AF_INET, addr);
                            debug!(addr = %addr, "stored deleted IPv4 address");
                        } else if family == libc::AF_INET6
                            && offset + mem::size_of::<libc::sockaddr_in6>() <= len
                        {
                            let sin6 = &*(buf.as_ptr().add(offset) as *const libc::sockaddr_in6);
                            let addr = IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr));
                            self.del_filter.set(libc::AF_INET6, addr);
                            debug!(addr = %addr, "stored deleted IPv6 address");
                        }
                        return;
                    }

                    // Advance past this address using SA_SIZE alignment.
                    offset += sa_size(sa.sa_len as usize);
                }
                bit <<= 1;
            }
        }
    }
}

impl Drop for BpfNetwork {
    fn drop(&mut self) {
        if self.route_fd >= 0 {
            // SAFETY: route_fd is a valid fd created in route_init().
            unsafe {
                libc::close(self.route_fd);
            }
        }
        #[cfg(feature = "dhcp")]
        if let Some(fd) = self.bpf_fd {
            if fd >= 0 {
                // SAFETY: bpf_fd is a valid fd opened in init_bpf().
                unsafe {
                    libc::close(fd);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// IPv6 address flag helpers (platform-specific)
// ---------------------------------------------------------------------------

/// Get IPv6 address flags and lifetimes.
///
/// On non-Apple BSD (FreeBSD, OpenBSD): uses `SIOCGIFAFLAG_IN6` and
/// `SIOCGIFALIFETIME_IN6` ioctls to retrieve tentative/deprecated/permanent
/// flags and preferred/valid lifetimes.
///
/// On macOS: returns defaults (PERMANENT, infinite lifetimes) because these
/// ioctls are not available.
///
/// Returns `(flags, preferred_lifetime, valid_lifetime)`.
#[cfg(target_os = "macos")]
fn get_ipv6_addr_info(_iface_name: &str, _addr: &Ipv6Addr) -> (u32, u32, u32) {
    // macOS does not expose per-address flags via ioctl.
    // Default to PERMANENT with infinite (0) lifetimes.
    (IFACE_PERMANENT, 0, 0)
}

/// FreeBSD / OpenBSD variant — retrieves real IPv6 address flags and lifetimes.
#[cfg(not(target_os = "macos"))]
fn get_ipv6_addr_info(iface_name: &str, addr: &Ipv6Addr) -> (u32, u32, u32) {
    // Open a temporary IPv6 datagram socket for ioctl queries.
    let fd = match socket(
        AddressFamily::Inet6,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC,
        None,
    ) {
        Ok(fd) => fd,
        Err(_) => return (IFACE_PERMANENT, 0, 0),
    };

    let raw_fd = fd.as_raw_fd();
    let mut flags: u32 = IFACE_PERMANENT;
    let mut preferred: u32 = 0;
    let mut valid: u32 = 0;

    // SAFETY: We construct properly-initialized in6_ifreq-style structures and
    // pass them to ioctl. The fd is a valid IPv6 datagram socket. We check
    // return values before reading results.
    unsafe {
        // --- SIOCGIFAFLAG_IN6: get IPv6 address flags ---
        #[repr(C)]
        struct In6AddrLifetime {
            ia6t_expire: libc::time_t,
            ia6t_preferred: libc::time_t,
            ia6t_vltime: u32,
            ia6t_pltime: u32,
        }

        #[repr(C)]
        struct In6Ifreq {
            ifr_name: [u8; libc::IFNAMSIZ],
            ifr_addr: libc::sockaddr_in6,
            ifr_flags: i32,
        }

        let mut req: In6Ifreq = mem::zeroed();
        let name_bytes = iface_name.as_bytes();
        let copy_len = name_bytes.len().min(libc::IFNAMSIZ - 1);
        req.ifr_name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);
        req.ifr_addr.sin6_family = libc::AF_INET6 as libc::sa_family_t;
        req.ifr_addr.sin6_addr = libc::in6_addr {
            s6_addr: addr.octets(),
        };

        // Platform-specific ioctl numbers.
        // SIOCGIFAFLAG_IN6 value for FreeBSD/OpenBSD.
        #[cfg(target_os = "freebsd")]
        const SIOCGIFAFLAG_IN6: libc::c_ulong = 0xC0906949;
        #[cfg(target_os = "openbsd")]
        const SIOCGIFAFLAG_IN6: libc::c_ulong = 0xC0906949;
        // Provide a fallback for other BSDs to avoid compile error.
        #[cfg(not(any(target_os = "freebsd", target_os = "openbsd")))]
        const SIOCGIFAFLAG_IN6: libc::c_ulong = 0;

        if SIOCGIFAFLAG_IN6 != 0 && libc::ioctl(raw_fd, SIOCGIFAFLAG_IN6, &mut req) == 0 {
            flags = 0;
            // IN6_IFF_TENTATIVE = 0x02
            if req.ifr_flags & 0x02 != 0 {
                flags |= IFACE_TENTATIVE;
            }
            // IN6_IFF_DEPRECATED = 0x10
            if req.ifr_flags & 0x10 != 0 {
                flags |= IFACE_DEPRECATED;
            }
            // !IN6_IFF_TEMPORARY (0x80) → PERMANENT
            if req.ifr_flags & 0x80 == 0 {
                flags |= IFACE_PERMANENT;
            }
        }

        // --- SIOCGIFALIFETIME_IN6: get address lifetime ---
        #[repr(C)]
        struct In6IfreqLifetime {
            ifr_name: [u8; libc::IFNAMSIZ],
            ifr_addr: libc::sockaddr_in6,
            ifr_lifetime: In6AddrLifetime,
        }

        #[cfg(target_os = "freebsd")]
        const SIOCGIFALIFETIME_IN6: libc::c_ulong = 0xC1186981;
        #[cfg(target_os = "openbsd")]
        const SIOCGIFALIFETIME_IN6: libc::c_ulong = 0xC1186981;
        #[cfg(not(any(target_os = "freebsd", target_os = "openbsd")))]
        const SIOCGIFALIFETIME_IN6: libc::c_ulong = 0;

        if SIOCGIFALIFETIME_IN6 != 0 {
            let mut lt_req: In6IfreqLifetime = mem::zeroed();
            lt_req.ifr_name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);
            lt_req.ifr_addr.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            lt_req.ifr_addr.sin6_addr = libc::in6_addr {
                s6_addr: addr.octets(),
            };

            if libc::ioctl(raw_fd, SIOCGIFALIFETIME_IN6, &mut lt_req) == 0 {
                preferred = lt_req.ifr_lifetime.ia6t_pltime;
                valid = lt_req.ifr_lifetime.ia6t_vltime;
            }
        }

        // Close temporary socket.
        libc::close(raw_fd);
    }

    (flags, preferred, valid)
}

// ---------------------------------------------------------------------------
// ARP enumeration (BSD sysctl, non-macOS only)
// ---------------------------------------------------------------------------

/// Enumerate the kernel ARP table via BSD `sysctl` (non-macOS only).
///
/// Uses the MIB path `CTL_NET → PF_ROUTE → 0 → AF_INET → NET_RT_FLAGS → RTF_LLINFO`
/// to retrieve ARP cache entries. Parses `rt_msghdr` + `sockaddr_inarp` +
/// `sockaddr_dl` structures from the returned buffer.
///
/// Replaces C's `arp_enumerate()` from `bpf.c` line 160.
///
/// # macOS Note
///
/// macOS does not support `sysctl`-based ARP enumeration via this MIB path.
/// Calling this on macOS returns `Ok(false)`.
#[cfg(not(target_os = "macos"))]
#[allow(dead_code)]
pub fn arp_enumerate_bsd<F>(mut callback: F) -> DnsmasqResult<bool>
where
    F: FnMut(IpAddr, &[u8]) -> bool,
{
    let mib: [libc::c_int; 6] = [
        libc::CTL_NET,
        libc::PF_ROUTE,
        0,
        libc::AF_INET,
        libc::NET_RT_FLAGS,
        libc::RTF_LLINFO,
    ];

    // First call: determine required buffer size.
    let mut buf_len: libc::size_t = 0;

    // SAFETY: sysctl with null buffer returns the required size in buf_len.
    // The MIB array is properly sized (6 ints) and initialized with valid constants.
    let rc = unsafe {
        libc::sysctl(
            mib.as_ptr(),
            mib.len() as libc::c_uint,
            std::ptr::null_mut(),
            &mut buf_len,
            std::ptr::null(),
            0,
        )
    };
    if rc != 0 {
        return Err(DnsmasqError::Network(format!(
            "sysctl(NET_RT_FLAGS) size query failed: {}",
            io::Error::last_os_error()
        )));
    }
    if buf_len == 0 {
        return Ok(false);
    }

    // Allocate buffer (C's expand_buf → Rust Vec::resize).
    let mut buf: Vec<u8> = vec![0u8; buf_len];

    // SAFETY: buf has buf_len bytes allocated. sysctl writes at most buf_len bytes.
    let rc = unsafe {
        libc::sysctl(
            mib.as_ptr(),
            mib.len() as libc::c_uint,
            buf.as_mut_ptr() as *mut libc::c_void,
            &mut buf_len,
            std::ptr::null(),
            0,
        )
    };
    if rc != 0 {
        return Err(DnsmasqError::Network(format!(
            "sysctl(NET_RT_FLAGS) data query failed: {}",
            io::Error::last_os_error()
        )));
    }

    // Parse the buffer: sequence of rt_msghdr followed by sockaddr structures.
    let mut offset: usize = 0;
    while offset + mem::size_of::<rt_msghdr_local>() <= buf_len {
        // SAFETY: We verified bounds. Data written by kernel sysctl handler
        // produces properly-aligned rt_msghdr structures.
        let (ip_addr, mac, msg_len) = unsafe {
            let rtm = &*(buf.as_ptr().add(offset) as *const rt_msghdr_local);
            let msg_len = rtm.rtm_msglen as usize;

            if msg_len == 0 || offset + msg_len > buf_len {
                break;
            }

            // Skip past rt_msghdr to the first sockaddr.
            let sa_off = offset + mem::size_of::<rt_msghdr_local>();
            if sa_off >= offset + msg_len {
                (None, Vec::new(), msg_len)
            } else {
                // First sockaddr: sockaddr_inarp (IP address).
                let sin = &*(buf.as_ptr().add(sa_off) as *const libc::sockaddr);
                if sin.sa_family as i32 != libc::AF_INET {
                    (None, Vec::new(), msg_len)
                } else {
                    let sin_in = &*(buf.as_ptr().add(sa_off) as *const libc::sockaddr_in);
                    let ib = sin_in.sin_addr.s_addr.to_ne_bytes();
                    let ip = Ipv4Addr::new(ib[0], ib[1], ib[2], ib[3]);

                    // Second sockaddr: sockaddr_dl (MAC address).
                    let sin_size = sa_size(sin.sa_len as usize);
                    let sdl_off = sa_off + sin_size;

                    if sdl_off + mem::size_of::<libc::sockaddr_dl>() > offset + msg_len {
                        (Some(IpAddr::V4(ip)), Vec::new(), msg_len)
                    } else {
                        let sdl = &*(buf.as_ptr().add(sdl_off) as *const libc::sockaddr_dl);
                        let alen = sdl.sdl_alen as usize;
                        if alen == 0 || alen > 8 {
                            (None, Vec::new(), msg_len)
                        } else {
                            // LLADDR(sdl) = sdl->sdl_data + sdl->sdl_nlen
                            let nlen = sdl.sdl_nlen as usize;
                            let data_ptr = sdl.sdl_data.as_ptr().add(nlen) as *const u8;
                            let mac = std::slice::from_raw_parts(data_ptr, alen).to_vec();
                            (Some(IpAddr::V4(ip)), mac, msg_len)
                        }
                    }
                }
            }
        };

        offset += msg_len;

        if let Some(ip) = ip_addr {
            if !mac.is_empty() && !callback(ip, &mac) {
                return Ok(false);
            }
        }
    }

    Ok(true)
}

// ---------------------------------------------------------------------------
// Free Functions — C-compatible API
// ---------------------------------------------------------------------------

/// Open a BPF device for raw DHCP packet transmission.
///
/// Tries `/dev/bpf0`, `/dev/bpf1`, … successively until one opens. Skips
/// devices that return `EBUSY` (in use by another process).
///
/// Returns the BPF file descriptor on success.
///
/// Replaces C's `init_bpf()` from `bpf.c` line 466.
///
/// # Errors
///
/// Returns [`DnsmasqError::Fatal`] (code 2 / `EC_BADNET`) if no BPF device
/// can be opened after trying [`BPF_MAX_DEVICES`] devices.
#[cfg(feature = "dhcp")]
pub fn init_bpf() -> DnsmasqResult<RawFd> {
    use std::fs::OpenOptions;

    for i in 0..BPF_MAX_DEVICES {
        let path = format!("{}{}", BPF_DEV_PREFIX, i);
        match OpenOptions::new().read(true).write(true).open(&path) {
            Ok(file) => {
                let fd = file.as_raw_fd();
                // Prevent the File from closing the fd when dropped; we own it now.
                std::mem::forget(file);
                debug!(path = %path, fd = fd, "init_bpf: opened BPF device");
                return Ok(fd);
            }
            Err(e) => {
                if e.raw_os_error() == Some(libc::EBUSY) {
                    // Device busy — try the next one.
                    continue;
                }
                // Other errors (ENOENT after all devices exhausted, etc.) —
                // try next; we'll error out after the loop.
                debug!(path = %path, error = %e, "init_bpf: cannot open");
                continue;
            }
        }
    }

    error!(
        devices_tried = BPF_MAX_DEVICES,
        "init_bpf: no BPF device available"
    );
    Err(DnsmasqError::Fatal {
        code: 2, // EC_BADNET
        message: "cannot open any BPF device for DHCP raw packet I/O".to_string(),
    })
}

/// Send a raw DHCP packet via BPF, bypassing the kernel IP stack.
///
/// Constructs a complete Ethernet + IPv4 + UDP frame and transmits it via the
/// BPF device using `writev()` with 4 scatter-gather segments.
///
/// Only Ethernet interfaces (`ARPHRD_ETHER`, `hlen=6`) are supported. Other
/// hardware types are silently skipped with a warning.
///
/// # Broadcast vs. Unicast
///
/// - If the DHCP packet's broadcast flag (bit 15 of `flags` field) is set,
///   the frame is sent to Ethernet broadcast (`FF:FF:FF:FF:FF:FF`) and IP
///   broadcast (`255.255.255.255`).
/// - Otherwise, the frame is sent to the client's MAC (`chaddr`) and offered
///   IP address (`yiaddr`).
///
/// Replaces C's `send_via_bpf()` from `bpf.c` line 557.
#[cfg(feature = "dhcp")]
pub fn send_via_bpf(
    bpf_fd: RawFd,
    packet: &[u8],
    packet_len: usize,
    iface_addr: Ipv4Addr,
    iface_name: &str,
) -> DnsmasqResult<()> {
    let actual_len = packet_len.min(packet.len());

    if actual_len < DHCP_CHADDR_OFFSET + ETHER_ADDR_LEN {
        return Err(DnsmasqError::Network(
            "DHCP packet too short for BPF transmission".to_string(),
        ));
    }

    // Validate hardware type — only Ethernet supported (bpf.c line 581).
    let htype = packet[DHCP_HTYPE_OFFSET] as u16;
    let hlen = packet[DHCP_HLEN_OFFSET] as usize;
    if htype != ARPHRD_ETHER || hlen != ETHER_ADDR_LEN {
        warn!(
            htype = htype,
            hlen = hlen,
            "send_via_bpf: unsupported hardware type (only Ethernet supported)"
        );
        return Ok(());
    }

    // Get source MAC address from interface (via getifaddrs AF_LINK lookup).
    let src_mac = get_interface_mac(iface_name)?;

    // Determine destination: broadcast vs unicast based on DHCP flags.
    let flags = u16::from_be_bytes([packet[DHCP_FLAGS_OFFSET], packet[DHCP_FLAGS_OFFSET + 1]]);
    let is_broadcast = (flags & DHCP_BROADCAST_FLAG) != 0;

    let (dst_mac, dst_ip) = if is_broadcast {
        ([0xFFu8; ETHER_ADDR_LEN], Ipv4Addr::BROADCAST)
    } else {
        let mut mac = [0u8; ETHER_ADDR_LEN];
        mac.copy_from_slice(&packet[DHCP_CHADDR_OFFSET..DHCP_CHADDR_OFFSET + ETHER_ADDR_LEN]);
        let yb = &packet[DHCP_YIADDR_OFFSET..DHCP_YIADDR_OFFSET + 4];
        (mac, Ipv4Addr::new(yb[0], yb[1], yb[2], yb[3]))
    };

    // --- Build Ethernet header (14 bytes) ---
    let mut ether_hdr = [0u8; ETHER_HDR_LEN];
    ether_hdr[0..6].copy_from_slice(&dst_mac);
    ether_hdr[6..12].copy_from_slice(&src_mac);
    ether_hdr[12..14].copy_from_slice(&ETHERTYPE_IP.to_be_bytes());

    // --- Build IPv4 header (20 bytes, no options) ---
    let total_len = (IP_HDR_LEN + UDP_HDR_LEN + actual_len) as u16;
    let mut ip_hdr = [0u8; IP_HDR_LEN];
    ip_hdr[0] = (IPVERSION << 4) | (IP_HDR_LEN as u8 / 4); // version + IHL
    ip_hdr[2..4].copy_from_slice(&total_len.to_be_bytes());
    ip_hdr[6..8].copy_from_slice(&IP_DF.to_be_bytes()); // DF flag
    ip_hdr[8] = IPDEFTTL;
    ip_hdr[9] = IPPROTO_UDP;
    ip_hdr[12..16].copy_from_slice(&iface_addr.octets());
    ip_hdr[16..20].copy_from_slice(&dst_ip.octets());
    // Compute IP header checksum (RFC 1071).
    let ip_cksum = internet_checksum(&ip_hdr);
    ip_hdr[10..12].copy_from_slice(&ip_cksum.to_be_bytes());

    // --- Build UDP header (8 bytes) ---
    let udp_len = (UDP_HDR_LEN + actual_len) as u16;
    let mut udp_hdr = [0u8; UDP_HDR_LEN];
    udp_hdr[0..2].copy_from_slice(&DHCP_SERVER_PORT.to_be_bytes());
    udp_hdr[2..4].copy_from_slice(&DHCP_CLIENT_PORT.to_be_bytes());
    udp_hdr[4..6].copy_from_slice(&udp_len.to_be_bytes());
    // Compute UDP checksum (RFC 768 with pseudo-header).
    let udp_cksum = udp_checksum(iface_addr, dst_ip, &udp_hdr, &packet[..actual_len]);
    udp_hdr[6..8].copy_from_slice(&udp_cksum.to_be_bytes());

    // --- Bind BPF to interface via BIOCSETIF ---
    bind_bpf_to_interface(bpf_fd, iface_name)?;

    // --- Send via writev (4 scatter-gather segments) ---
    // Retry on EINTR/EAGAIN matching C's retry_send() pattern (bpf.c line 652).
    // SAFETY: All iov buffers point to valid, initialized stack arrays. bpf_fd
    // is a valid open BPF device. writev is atomic for BPF (one complete frame).
    unsafe {
        let iov = [
            libc::iovec {
                iov_base: ether_hdr.as_ptr() as *mut libc::c_void,
                iov_len: ether_hdr.len(),
            },
            libc::iovec {
                iov_base: ip_hdr.as_ptr() as *mut libc::c_void,
                iov_len: ip_hdr.len(),
            },
            libc::iovec {
                iov_base: udp_hdr.as_ptr() as *mut libc::c_void,
                iov_len: udp_hdr.len(),
            },
            libc::iovec {
                iov_base: packet.as_ptr() as *mut libc::c_void,
                iov_len: actual_len,
            },
        ];

        loop {
            let result = libc::writev(bpf_fd, iov.as_ptr(), iov.len() as libc::c_int);
            if result >= 0 {
                return Ok(());
            }
            let err = io::Error::last_os_error();
            match err.kind() {
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock => continue,
                _ => {
                    return Err(DnsmasqError::Network(format!("BPF writev failed: {}", err)));
                }
            }
        }
    }
}

/// Get the MAC (Ethernet) address of a network interface via `getifaddrs`.
///
/// Searches the `AF_LINK` addresses in the `getifaddrs` linked list for the
/// specified interface name and extracts the 6-byte Ethernet MAC address from
/// the `sockaddr_dl` structure.
#[cfg(feature = "dhcp")]
fn get_interface_mac(iface_name: &str) -> DnsmasqResult<[u8; ETHER_ADDR_LEN]> {
    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();

    // SAFETY: getifaddrs allocates the linked list; IfAddrsGuard frees it.
    let rc = unsafe { libc::getifaddrs(&mut ifap) };
    if rc != 0 {
        return Err(DnsmasqError::Network(format!(
            "getifaddrs (MAC lookup) failed: {}",
            io::Error::last_os_error()
        )));
    }
    let _guard = IfAddrsGuard(ifap);

    let mut ifa = ifap;
    while !ifa.is_null() {
        // SAFETY: ifa is a valid node in the getifaddrs linked list.
        unsafe {
            let ifaddr = &*ifa;
            ifa = ifaddr.ifa_next;

            if ifaddr.ifa_addr.is_null() {
                continue;
            }
            let sa = &*ifaddr.ifa_addr;
            if sa.sa_family as i32 != libc::AF_LINK {
                continue;
            }

            let name_cstr = std::ffi::CStr::from_ptr(ifaddr.ifa_name);
            let name = name_cstr.to_string_lossy();
            if name.as_ref() != iface_name {
                continue;
            }

            let sdl = &*(ifaddr.ifa_addr as *const libc::sockaddr_dl);
            let alen = sdl.sdl_alen as usize;
            if alen != ETHER_ADDR_LEN {
                continue;
            }

            // LLADDR(sdl) = sdl->sdl_data + sdl->sdl_nlen
            let nlen = sdl.sdl_nlen as usize;
            let data_ptr = sdl.sdl_data.as_ptr().add(nlen) as *const u8;
            let mut mac = [0u8; ETHER_ADDR_LEN];
            std::ptr::copy_nonoverlapping(data_ptr, mac.as_mut_ptr(), ETHER_ADDR_LEN);
            return Ok(mac);
        }
    }

    Err(DnsmasqError::Network(format!(
        "cannot find MAC address for interface '{}'",
        iface_name
    )))
}

/// Bind a BPF device to a named network interface via `BIOCSETIF` ioctl.
#[cfg(feature = "dhcp")]
fn bind_bpf_to_interface(bpf_fd: RawFd, iface_name: &str) -> DnsmasqResult<()> {
    // SAFETY: ifreq is zero-initialized. We copy the interface name into
    // ifr_name (null-terminated by zero init). bpf_fd is a valid BPF device.
    // BIOCSETIF is a standard BSD BPF ioctl.
    unsafe {
        let mut ifr: libc::ifreq = mem::zeroed();
        let name_bytes = iface_name.as_bytes();
        let copy_len = name_bytes.len().min(libc::IFNAMSIZ - 1);
        std::ptr::copy_nonoverlapping(
            name_bytes.as_ptr(),
            ifr.ifr_name.as_mut_ptr() as *mut u8,
            copy_len,
        );

        // BIOCSETIF ioctl number. The value 0x8020426C is the standard encoding
        // on FreeBSD, OpenBSD, and macOS: _IOW('B', 108, struct ifreq).
        const BIOCSETIF: libc::c_ulong = 0x8020426C;

        if libc::ioctl(bpf_fd, BIOCSETIF, &ifr) < 0 {
            return Err(DnsmasqError::Network(format!(
                "BIOCSETIF failed for '{}': {}",
                iface_name,
                io::Error::last_os_error()
            )));
        }
    }
    Ok(())
}

/// Create a PF_ROUTE socket for BSD interface change monitoring.
///
/// Creates a raw routing socket (`PF_ROUTE`, `SOCK_RAW`, `AF_UNSPEC`) and
/// sets it to close-on-exec and non-blocking mode.
///
/// Replaces C's `route_init()` from `bpf.c` line 690.
///
/// # Errors
///
/// Returns [`DnsmasqError::Fatal`] (code 2 / `EC_BADNET`) if the socket
/// cannot be created.
pub fn route_init() -> DnsmasqResult<RawFd> {
    // SAFETY: PF_ROUTE is a well-defined BSD socket family. SOCK_RAW is the
    // only valid type for routing sockets. AF_UNSPEC subscribes to all address
    // family notifications (RTM_NEWADDR, RTM_DELADDR, etc.).
    let fd = unsafe { libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, libc::AF_UNSPEC) };

    if fd < 0 {
        let err = io::Error::last_os_error();
        error!(error = %err, "route_init: failed to create PF_ROUTE socket");
        return Err(DnsmasqError::Fatal {
            code: 2, // EC_BADNET
            message: format!("cannot create PF_ROUTE socket: {}", err),
        });
    }

    // Set close-on-exec and non-blocking (replaces C `fix_fd()`).
    // SAFETY: fd is a valid file descriptor just created by socket().
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags >= 0 {
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
        libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
    }

    debug!(fd = fd, "route_init: created PF_ROUTE socket");
    Ok(fd)
}

/// Process a PF_ROUTE routing socket message.
///
/// Reads from the routing socket via the provided [`BpfNetwork`] instance,
/// dispatches based on message type, and returns the appropriate event code.
///
/// This function is the public C-compatible API entry point. Internally it
/// delegates to [`BpfNetwork::process_route_message()`].
///
/// Replaces C's `route_sock()` from `bpf.c` line 740.
pub fn route_sock(bpf: &mut BpfNetwork, buf: &mut [u8]) -> Option<EventCode> {
    bpf.process_route_message(buf)
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ------ SA_SIZE tests ------

    #[test]
    fn test_sa_size_zero_returns_sizeof_long() {
        // SA_SIZE(0) = sizeof(long) on the platform.
        assert_eq!(sa_size(0), mem::size_of::<usize>());
    }

    #[test]
    fn test_sa_size_one_rounds_up() {
        // sa_len=1 should round up to sizeof(long).
        assert_eq!(sa_size(1), mem::size_of::<usize>());
    }

    #[test]
    fn test_sa_size_aligned() {
        let long_size = mem::size_of::<usize>();
        // sa_len == long_size is already aligned.
        assert_eq!(sa_size(long_size), long_size);
    }

    #[test]
    fn test_sa_size_needs_rounding() {
        let long_size = mem::size_of::<usize>();
        // sa_len == long_size + 1 rounds up to 2 * long_size.
        assert_eq!(sa_size(long_size + 1), long_size * 2);
    }

    #[test]
    fn test_sa_size_typical_sockaddr_in() {
        // struct sockaddr_in = 16 bytes on most platforms.
        let long_size = mem::size_of::<usize>();
        let result = sa_size(16);
        assert_eq!(result % long_size, 0, "result must be long-aligned");
        assert!(result >= 16, "result must be >= sa_len");
    }

    // ------ Checksum tests ------

    #[test]
    fn test_internet_checksum_all_zeros() {
        let data = [0u8; 20];
        assert_eq!(internet_checksum(&data), 0xFFFF);
    }

    #[test]
    fn test_internet_checksum_rfc1071_example() {
        // Manual calculation: 0x0001 + 0xF203 + 0xF4F5 + 0xF6F7
        let data: [u8; 8] = [0x00, 0x01, 0xF2, 0x03, 0xF4, 0xF5, 0xF6, 0xF7];
        let cksum = internet_checksum(&data);
        // Sum = 0x2DDF0, fold = 0xDDF2, complement = 0x220D
        assert_eq!(cksum, 0x220D);
    }

    #[test]
    fn test_internet_checksum_odd_length() {
        let data: [u8; 3] = [0x00, 0x01, 0x02];
        // Words: 0x0001, 0x0200 (padded). Sum = 0x0201, complement = 0xFDFE
        assert_eq!(internet_checksum(&data), 0xFDFE);
    }

    #[test]
    fn test_internet_checksum_self_verifying() {
        // If we append the checksum to the data, the checksum of the whole
        // thing should be 0x0000 (or 0xFFFF before complement).
        let mut data = vec![0x45u8, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00];
        data.extend_from_slice(&[0x40, 0x06, 0x00, 0x00]); // checksum placeholder
        data.extend_from_slice(&[0xac, 0x10, 0x0a, 0x63]);
        data.extend_from_slice(&[0xac, 0x10, 0x0a, 0x0c]);

        let cksum = internet_checksum(&data);
        // Put checksum into header
        data[10] = (cksum >> 8) as u8;
        data[11] = (cksum & 0xFF) as u8;
        // Verify: checksum of entire header with valid checksum should be 0
        let verify = internet_checksum(&data);
        assert_eq!(verify, 0, "header with valid checksum should verify to 0");
    }

    #[test]
    fn test_udp_checksum_nonzero() {
        let src = Ipv4Addr::new(192, 168, 1, 1);
        let dst = Ipv4Addr::new(192, 168, 1, 255);
        let udp_hdr = [0x00, 0x43, 0x00, 0x44, 0x00, 0x0C, 0x00, 0x00];
        let payload = [0x01, 0x02, 0x03, 0x04];
        let cksum = udp_checksum(src, dst, &udp_hdr, &payload);
        assert_ne!(cksum, 0, "UDP checksum should be non-zero");
    }

    // ------ DeletionFilter tests ------

    #[test]
    fn test_deletion_filter_new_is_inactive() {
        let filter = DeletionFilter::new();
        assert!(filter.family.is_none());
        assert!(filter.addr.is_none());
        // Should not match anything.
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        assert!(!filter.matches(libc::AF_INET, &addr));
    }

    #[test]
    fn test_deletion_filter_set_and_match_ipv4() {
        let mut filter = DeletionFilter::new();
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        filter.set(libc::AF_INET, addr);

        assert!(filter.matches(libc::AF_INET, &addr));
        // Different address — should not match.
        assert!(!filter.matches(libc::AF_INET, &IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        // Different family — should not match.
        assert!(!filter.matches(libc::AF_INET6, &IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn test_deletion_filter_set_and_match_ipv6() {
        let mut filter = DeletionFilter::new();
        let addr = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        filter.set(libc::AF_INET6, addr);

        assert!(filter.matches(libc::AF_INET6, &addr));
        assert!(!filter.matches(libc::AF_INET, &IpAddr::V4(Ipv4Addr::LOCALHOST)));
    }

    #[test]
    fn test_deletion_filter_clear_deactivates() {
        let mut filter = DeletionFilter::new();
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        filter.set(libc::AF_INET, addr);
        assert!(filter.matches(libc::AF_INET, &addr));

        filter.clear();
        assert!(!filter.matches(libc::AF_INET, &addr));
    }

    #[test]
    fn test_deletion_filter_overwrite() {
        let mut filter = DeletionFilter::new();
        let addr1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let addr2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));

        filter.set(libc::AF_INET, addr1);
        assert!(filter.matches(libc::AF_INET, &addr1));

        // Overwrite with a new address.
        filter.set(libc::AF_INET, addr2);
        assert!(!filter.matches(libc::AF_INET, &addr1));
        assert!(filter.matches(libc::AF_INET, &addr2));
    }
}

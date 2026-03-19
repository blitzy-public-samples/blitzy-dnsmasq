// SAFETY: This module contains unsafe blocks for platform-specific FFI operations.
// The crate-level #![deny(unsafe_code)] is overridden here because this module
// requires direct system call interactions that cannot be expressed in safe Rust.
#![allow(unsafe_code)]
// Copyright (c) 2024 dnsmasq contributors
// SPDX-License-Identifier: GPL-2.0-or-later
//
// This file is part of dnsmasq, a lightweight DNS/DHCP/TFTP server.
// Ported from C (src/netlink.c) to Rust as part of the memory-safety migration.
//
// Platform gate: This module is Linux-only. It is gated by
// `#[cfg(target_os = "linux")]` on the module declaration in `network/mod.rs`,
// preventing compilation on non-Linux platforms. Netlink is a Linux kernel
// interface with no equivalent on BSD or macOS.

//! Linux netlink socket interface for real-time kernel network monitoring.
//!
//! This module provides the Linux-specific backend for detecting network topology
//! changes (address additions/removals, route changes) via the kernel's netlink
//! subsystem. It replaces the C `netlink.c` implementation (`HAVE_LINUX_NETWORK`).
//!
//! ## Architecture
//!
//! The netlink interface uses a push-based event model: the kernel sends multicast
//! notifications whenever network state changes, eliminating the need for periodic
//! polling. This module creates a `NETLINK_ROUTE` socket subscribed to IPv4/IPv6
//! address and route change groups.
//!
//! ## BSD Equivalent
//!
//! On BSD systems, the equivalent functionality is provided by `bpf.rs` using
//! `PF_ROUTE` sockets.
//!
//! ## Safety
//!
//! This module contains `unsafe` blocks for netlink message parsing through libc
//! FFI. Each `unsafe` block has a `// SAFETY:` comment explaining the invariant.
//! All pointer arithmetic is bounds-checked before access.

use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::io::{AsRawFd, OwnedFd, RawFd};

use nix::errno::Errno;
use nix::sys::socket::{
    bind, getsockname, socket, AddressFamily, NetlinkAddr, SockFlag, SockProtocol, SockType,
};
use tracing::{debug, error, trace, warn};

use crate::core::types::{DnsmasqError, DnsmasqResult, EventCode};

// ---------------------------------------------------------------------------
// Interface address flags (from dnsmasq.h, matching C IFACE_TENTATIVE etc.)
// ---------------------------------------------------------------------------

/// IPv6 address is tentative (DAD in progress).
pub const IFACE_TENTATIVE: u32 = 1;

/// IPv6 address is deprecated (prefer other addresses).
pub const IFACE_DEPRECATED: u32 = 2;

/// IPv6 address is permanent (not a temporary/privacy address).
pub const IFACE_PERMANENT: u32 = 4;

// ---------------------------------------------------------------------------
// Async event deduplication state flags (from C enum async_states, lines 112-115)
// ---------------------------------------------------------------------------

/// Bit flag: EVENT_NEWADDR has been queued in this batch.
const STATE_NEWADDR: u32 = 1 << 0;

/// Bit flag: EVENT_NEWROUTE has been queued in this batch.
const STATE_NEWROUTE: u32 = 1 << 1;

// ---------------------------------------------------------------------------
// Netlink socket option constants (from C netlink.c lines 91-96)
// ---------------------------------------------------------------------------

/// Socket option level for netlink sockets.
const SOL_NETLINK: libc::c_int = 270;

/// Socket option to suppress ENOBUFS errors on netlink multicast.
const NETLINK_NO_ENOBUFS: libc::c_int = 5;

// ---------------------------------------------------------------------------
// Netlink alignment constants
// ---------------------------------------------------------------------------

/// Alignment boundary for netlink messages (NLMSG_ALIGNTO).
const NLMSG_ALIGNTO: usize = 4;

/// Alignment boundary for rtnetlink attributes (RTA_ALIGNTO).
const RTA_ALIGNTO: usize = 4;

// ---------------------------------------------------------------------------
// Netlink/rtnetlink attribute type constants (from linux/if_addr.h,
// linux/neighbour.h, linux/if_link.h, linux/rtnetlink.h)
// Defined locally to avoid dependency on specific libc versions.
// ---------------------------------------------------------------------------

/// Address attribute: local address (preferred over IFA_ADDRESS for p2p).
const IFA_ADDRESS: u16 = 1;
/// Address attribute: local interface address.
const IFA_LOCAL: u16 = 2;
/// Address attribute: interface label string.
const IFA_LABEL: u16 = 3;
/// Address attribute: broadcast address.
const IFA_BROADCAST: u16 = 4;
/// Address attribute: cache info (lifetimes).
const IFA_CACHEINFO: u16 = 6;

/// Neighbor attribute: destination IP address.
const NDA_DST: u16 = 1;
/// Neighbor attribute: link-layer (MAC) address.
const NDA_LLADDR: u16 = 2;

/// Link attribute: hardware (MAC) address.
const IFLA_ADDRESS: u16 = 1;

/// IPv6 address flag: tentative (DAD in progress).
const IFA_F_TENTATIVE: u32 = 0x40;
/// IPv6 address flag: deprecated.
const IFA_F_DEPRECATED: u32 = 0x20;
/// IPv6 address flag: temporary (RFC 4941 privacy address).
const IFA_F_TEMPORARY: u32 = 0x01;

/// Neighbor state: does not need ARP.
const NUD_NOARP: u16 = 0x40;
/// Neighbor state: resolution in progress.
const NUD_INCOMPLETE: u16 = 0x01;
/// Neighbor state: resolution failed.
const NUD_FAILED: u16 = 0x20;

/// Route type: unicast (normal forwarding).
const RTN_UNICAST: u8 = 1;
/// Route scope: link-local.
const RT_SCOPE_LINK: u8 = 253;
/// Route table: main routing table.
const RT_TABLE_MAIN: u8 = 254;
/// Route table: local routing table.
const RT_TABLE_LOCAL: u8 = 255;

// ---------------------------------------------------------------------------
// Local FFI struct definitions — repr(C) for safe casting from raw bytes.
// These mirror the Linux kernel headers and may not all be present in
// the libc crate.
// ---------------------------------------------------------------------------

/// Generic netlink request body (linux/rtnetlink.h: struct rtgenmsg).
#[repr(C)]
#[derive(Clone, Copy)]
struct RtGenMsg {
    rtgen_family: u8,
}

/// Netlink route attribute header (linux/rtnetlink.h: struct rtattr).
#[repr(C)]
#[derive(Clone, Copy)]
struct RtAttr {
    rta_len: u16,
    rta_type: u16,
}

/// Interface address message (linux/if_addr.h: struct ifaddrmsg).
#[repr(C)]
#[derive(Clone, Copy)]
struct IfAddrMsg {
    ifa_family: u8,
    ifa_prefixlen: u8,
    ifa_flags: u8,
    ifa_scope: u8,
    ifa_index: u32,
}

/// Neighbor discovery message (linux/neighbour.h: struct ndmsg).
#[repr(C)]
#[derive(Clone, Copy)]
struct NdMsg {
    ndm_family: u8,
    ndm_pad1: u8,
    ndm_pad2: u16,
    ndm_ifindex: i32,
    ndm_state: u16,
    ndm_flags: u8,
    ndm_type: u8,
}

/// Interface info message (linux/if.h: struct ifinfomsg).
#[repr(C)]
#[derive(Clone, Copy)]
struct IfInfoMsg {
    ifi_family: u8,
    _ifi_pad: u8,
    ifi_type: u16,
    ifi_index: i32,
    ifi_flags: u32,
    ifi_change: u32,
}

/// Netlink error response (linux/netlink.h: struct nlmsgerr).
#[repr(C)]
#[derive(Clone, Copy)]
struct NlMsgErr {
    error: i32,
    msg: libc::nlmsghdr,
}

/// IPv6 address cache info (linux/if_addr.h: struct ifa_cacheinfo).
#[repr(C)]
#[derive(Clone, Copy)]
struct IfaCacheInfo {
    ifa_prefered: u32,
    ifa_valid: u32,
    cstamp: u32,
    tstamp: u32,
}

/// Route message (linux/rtnetlink.h: struct rtmsg).
#[repr(C)]
#[derive(Clone, Copy)]
struct RtMsg {
    rtm_family: u8,
    rtm_dst_len: u8,
    rtm_src_len: u8,
    rtm_tos: u8,
    rtm_table: u8,
    rtm_protocol: u8,
    rtm_scope: u8,
    rtm_type: u8,
    rtm_flags: u32,
}

// ---------------------------------------------------------------------------
// Netlink request structure — nlmsghdr + rtgenmsg packed together.
// ---------------------------------------------------------------------------

/// Combined netlink request for interface/address/neighbor dump.
#[repr(C)]
struct NetlinkRequest {
    nlh: libc::nlmsghdr,
    gen: RtGenMsg,
}

// ---------------------------------------------------------------------------
// IfaceCallback — callback enum for interface enumeration results
// ---------------------------------------------------------------------------

/// Callback variants for [`NetlinkNetwork::enumerate_interfaces`].
///
/// Each variant wraps a closure matching the corresponding address family:
/// - `Inet`: IPv4 address information
/// - `Inet6`: IPv6 address information with flags and lifetimes
/// - `Unspec`: Neighbor (ARP) table entries
/// - `Local`: Link-layer (MAC) address information
pub enum IfaceCallback<'a> {
    /// AF_INET callback: `(addr, if_index, label, netmask, broadcast) -> continue?`
    Inet(&'a mut dyn FnMut(Ipv4Addr, u32, Option<&str>, Ipv4Addr, Ipv4Addr) -> bool),
    /// AF_INET6 callback: `(addr, prefix_len, scope, if_index, flags, preferred, valid) -> continue?`
    Inet6(&'a mut dyn FnMut(Ipv6Addr, u32, u32, u32, u32, u32, u32) -> bool),
    /// AF_UNSPEC callback (neighbor table): `(family, addr, mac) -> continue?`
    Unspec(&'a mut dyn FnMut(u16, IpAddr, &[u8]) -> bool),
    /// AF_LOCAL callback (link-layer): `(if_index, hw_type, mac) -> continue?`
    Local(&'a mut dyn FnMut(u32, u32, &[u8]) -> bool),
}

// ---------------------------------------------------------------------------
// NetlinkNetwork — main netlink socket interface struct
// ---------------------------------------------------------------------------

/// Linux netlink socket interface for kernel network monitoring.
///
/// Encapsulates a `NETLINK_ROUTE` socket, receive buffer, and PID tracking.
/// Replaces C static variables (`iov`, `netlink_pid`) from `netlink.c` lines 118-119.
///
/// # Resource Management
///
/// The socket is automatically closed when `NetlinkNetwork` is dropped (RAII via
/// `OwnedFd`). The receive buffer is a `Vec<u8>` that auto-expands on truncation,
/// replacing C's `safe_malloc`/`expand_buf` pattern with zero risk of memory leaks.
pub struct NetlinkNetwork {
    /// Owned socket file descriptor — closed on drop (RAII).
    _socket_fd: OwnedFd,

    /// Raw file descriptor for external use (e.g., poll/select registration).
    /// Valid for the lifetime of this struct.
    pub fd: RawFd,

    /// Kernel-assigned netlink PID for message correlation.
    /// Note: The C code stores this but never reads it; preserved for parity.
    #[allow(dead_code)]
    nl_pid: u32,

    /// Auto-expanding receive buffer. Starts at 100 bytes, grows on truncation.
    /// Replaces C `iov.iov_base` + `expand_buf()`.
    recv_buf: Vec<u8>,

    /// Monotonically increasing sequence number for request/response correlation.
    seq: u32,
}

// ===========================================================================
// Alignment and parsing helper functions
// ===========================================================================

/// Align a length to the netlink alignment boundary (4 bytes).
#[inline]
fn nlmsg_align(len: usize) -> usize {
    (len + NLMSG_ALIGNTO - 1) & !(NLMSG_ALIGNTO - 1)
}

/// Size of the netlink message header, aligned.
#[inline]
fn nlmsg_hdrlen() -> usize {
    nlmsg_align(mem::size_of::<libc::nlmsghdr>())
}

/// Align a length to the rtattr alignment boundary (4 bytes).
#[inline]
fn rta_align(len: usize) -> usize {
    (len + RTA_ALIGNTO - 1) & !(RTA_ALIGNTO - 1)
}

/// Size of the rtattr header, aligned.
#[inline]
fn rta_hdrlen() -> usize {
    rta_align(mem::size_of::<RtAttr>())
}

/// Retry a libc call on EINTR. Returns the result of the call.
fn retry_eintr<F: FnMut() -> isize>(mut f: F) -> isize {
    loop {
        let rc = f();
        if rc != -1 || Errno::last() != Errno::EINTR {
            return rc;
        }
    }
}

// ===========================================================================
// Safe netlink message iterator
// ===========================================================================

/// Iterator over netlink messages in a raw byte buffer.
///
/// Validates message boundaries before yielding each `(nlmsghdr, payload)` pair,
/// preventing the buffer overreads possible with C's `NLMSG_OK`/`NLMSG_NEXT` macros.
struct NlMsgIter<'a> {
    buf: &'a [u8],
    offset: usize,
}

impl<'a> NlMsgIter<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, offset: 0 }
    }
}

impl<'a> Iterator for NlMsgIter<'a> {
    type Item = (&'a libc::nlmsghdr, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        let remaining = self.buf.len().checked_sub(self.offset)?;
        let hdr_size = mem::size_of::<libc::nlmsghdr>();

        if remaining < hdr_size {
            return None;
        }

        // SAFETY: We verified that at least sizeof(nlmsghdr) bytes are available
        // SAFETY: We verified nlmsg_len >= sizeof(nlmsghdr) and offset + nlmsg_len <= buf.len()
        // at self.offset. The buffer comes from kernel recvmsg which guarantees
        // proper alignment for netlink message headers.
        let nlh_ptr = self.buf.as_ptr().wrapping_add(self.offset) as *const libc::nlmsghdr;
        let nlh = unsafe { &*nlh_ptr };

        let nlmsg_len = nlh.nlmsg_len as usize;

        if nlmsg_len < hdr_size || nlmsg_len > remaining {
            return None;
        }

        let msg_data = &self.buf[self.offset..self.offset + nlmsg_len];
        self.offset += nlmsg_align(nlmsg_len);

        Some((nlh, msg_data))
    }
}

// ===========================================================================
// Safe rtattr iterator
// ===========================================================================

/// Iterator over rtattr entries in a netlink message payload.
struct RtAttrIter<'a> {
    buf: &'a [u8],
    offset: usize,
}

impl<'a> RtAttrIter<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, offset: 0 }
    }
}

impl<'a> Iterator for RtAttrIter<'a> {
    type Item = (u16, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        let remaining = self.buf.len().checked_sub(self.offset)?;
        let rta_hdr_size = mem::size_of::<RtAttr>();

        if remaining < rta_hdr_size {
            return None;
        }

        // SAFETY: We verified at least sizeof(RtAttr) bytes are available.
        let rta_ptr = self.buf.as_ptr().wrapping_add(self.offset) as *const RtAttr;
        let rta = unsafe { &*rta_ptr };

        let rta_len = rta.rta_len as usize;

        if rta_len < rta_hdr_size || rta_len > remaining {
            return None;
        }

        let data_start = self.offset + rta_hdrlen();
        let data_end = self.offset + rta_len;

        let data = if data_start <= data_end && data_end <= self.buf.len() {
            &self.buf[data_start..data_end]
        } else {
            self.offset += rta_align(rta_len);
            return self.next();
        };

        let rta_type = rta.rta_type;
        self.offset += rta_align(rta_len);

        Some((rta_type, data))
    }
}

// ===========================================================================
// NetlinkNetwork implementation
// ===========================================================================

impl NetlinkNetwork {
    /// Create a new netlink socket interface for network monitoring.
    ///
    /// Creates a `NETLINK_ROUTE` socket and subscribes to multicast groups for
    /// IPv4/IPv6 address and route change notifications. If binding with multicast
    /// groups fails with `EPERM` (unprivileged), falls back to binding without groups.
    ///
    /// Replaces C `netlink_init()` (netlink.c line 165).
    pub fn new() -> DnsmasqResult<Self> {
        let socket_fd = socket(
            AddressFamily::Netlink,
            SockType::Raw,
            SockFlag::SOCK_CLOEXEC,
            SockProtocol::NetlinkRoute,
        )
        .map_err(|e| DnsmasqError::Fatal {
            code: 1,
            message: format!("cannot create netlink socket: {}", e),
        })?;

        let raw_fd = socket_fd.as_raw_fd();

        // Multicast groups: IPv4 route/addr + IPv6 route/addr
        let groups: u32 = libc::RTMGRP_IPV4_ROUTE as u32
            | libc::RTMGRP_IPV4_IFADDR as u32
            | libc::RTMGRP_IPV6_ROUTE as u32
            | libc::RTMGRP_IPV6_IFADDR as u32;

        // Bind with multicast groups — graceful EPERM fallback
        let addr_with_groups = NetlinkAddr::new(0, groups);
        let bind_result = bind(raw_fd, &addr_with_groups);

        if let Err(e) = bind_result {
            if e == Errno::EPERM {
                warn!("netlink bind with multicast groups failed (EPERM), retrying without");
                let addr_no_groups = NetlinkAddr::new(0, 0);
                bind(raw_fd, &addr_no_groups).map_err(|e2| DnsmasqError::Fatal {
                    code: 1,
                    message: format!("cannot bind netlink socket: {}", e2),
                })?;
            } else {
                return Err(DnsmasqError::Fatal {
                    code: 1,
                    message: format!("cannot bind netlink socket: {}", e),
                });
            }
        }

        // Retrieve kernel-assigned PID via getsockname()
        let bound_addr: NetlinkAddr = getsockname(raw_fd).map_err(|e| DnsmasqError::Fatal {
            code: 1,
            message: format!("netlink getsockname: {}", e),
        })?;
        let nl_pid = bound_addr.pid();

        debug!(nl_pid = nl_pid, fd = raw_fd, "netlink socket initialized");

        Ok(Self {
            _socket_fd: socket_fd,
            fd: raw_fd,
            nl_pid,
            recv_buf: vec![0u8; 100],
            seq: 0,
        })
    }

    /// Receive a single netlink message with auto-buffer expansion.
    ///
    /// Uses MSG_PEEK + MSG_TRUNC to detect truncation, expands the receive buffer,
    /// then reads the full message. Only accepts messages from the kernel (nl_pid == 0).
    ///
    /// Replaces C `netlink_recv()` (netlink.c line 245).
    fn recv_message(&mut self, flags: libc::c_int) -> DnsmasqResult<Option<usize>> {
        loop {
            // Phase 1: Peek to detect message size and truncation
            let (peek_len, peek_truncated) = {
                // SAFETY: sockaddr_nl and msghdr are plain C structs; zeroing produces valid empty state.
                let mut nladdr: libc::sockaddr_nl = unsafe { mem::zeroed() };
                let mut iov = libc::iovec {
                    iov_base: self.recv_buf.as_mut_ptr() as *mut libc::c_void,
                    iov_len: self.recv_buf.len(),
                };
                let mut msg: libc::msghdr = unsafe { mem::zeroed() };
                msg.msg_name = &mut nladdr as *mut _ as *mut libc::c_void;
                msg.msg_namelen = mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
                msg.msg_iov = &mut iov;
                msg.msg_iovlen = 1;

                // SAFETY: All pointers in msg/iov reference valid stack/heap memory.
                let rc = retry_eintr(|| unsafe {
                    libc::recvmsg(self.fd, &mut msg, libc::MSG_PEEK | libc::MSG_TRUNC | flags)
                });

                if rc == -1 {
                    let errno = Errno::last();
                    if errno == Errno::EAGAIN || errno == Errno::EWOULDBLOCK {
                        return Ok(None);
                    }
                    if errno == Errno::ENOBUFS {
                        return Err(DnsmasqError::Network("ENOBUFS".to_string()));
                    }
                    return Err(DnsmasqError::Network(format!("netlink peek: {}", errno)));
                }

                let truncated = (msg.msg_flags & libc::MSG_TRUNC) != 0;
                (rc as usize, truncated)
            };

            // Phase 2: Expand buffer if truncated
            if peek_truncated || peek_len > self.recv_buf.len() {
                let new_size = peek_len + 100;
                self.recv_buf.resize(new_size, 0);
                trace!(new_size = new_size, "expanded netlink receive buffer");
            }

            // Phase 3: Read for real (consume from socket buffer)
            let (real_len, real_truncated, from_kernel) = {
                // SAFETY: sockaddr_nl and msghdr are plain C structs; zeroing produces valid empty state.
                let mut nladdr: libc::sockaddr_nl = unsafe { mem::zeroed() };
                let mut iov = libc::iovec {
                    iov_base: self.recv_buf.as_mut_ptr() as *mut libc::c_void,
                    iov_len: self.recv_buf.len(),
                };
                let mut msg: libc::msghdr = unsafe { mem::zeroed() };
                msg.msg_name = &mut nladdr as *mut _ as *mut libc::c_void;
                msg.msg_namelen = mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
                msg.msg_iov = &mut iov;
                msg.msg_iovlen = 1;

                // SAFETY: All pointers reference valid stack/heap memory.
                let rc = retry_eintr(|| unsafe { libc::recvmsg(self.fd, &mut msg, flags) });

                if rc == -1 {
                    let errno = Errno::last();
                    if errno == Errno::EAGAIN || errno == Errno::EWOULDBLOCK {
                        return Ok(None);
                    }
                    if errno == Errno::ENOBUFS {
                        return Err(DnsmasqError::Network("ENOBUFS".to_string()));
                    }
                    return Err(DnsmasqError::Network(format!("netlink recv: {}", errno)));
                }

                let truncated = (msg.msg_flags & libc::MSG_TRUNC) != 0;
                (rc as usize, truncated, nladdr.nl_pid == 0)
            };

            // Phase 4: Still truncated — expand and discard (retry loop)
            if real_truncated {
                let new_size = real_len + 100;
                self.recv_buf.resize(new_size, 0);
                trace!(
                    new_size = new_size,
                    "still truncated, expanding and retrying"
                );
                continue;
            }

            // Phase 5: Filter — only accept kernel messages (nl_pid == 0)
            if from_kernel {
                return Ok(Some(real_len));
            }

            trace!("skipping non-kernel netlink message");
        }
    }

    /// Send a netlink dump request for the given address family and message type.
    fn send_dump_request(&mut self, family: u8, msg_type: u16) -> DnsmasqResult<u32> {
        self.seq = self.seq.wrapping_add(1);

        let req = NetlinkRequest {
            nlh: libc::nlmsghdr {
                nlmsg_len: mem::size_of::<NetlinkRequest>() as u32,
                nlmsg_type: msg_type,
                nlmsg_flags: (libc::NLM_F_ROOT
                    | libc::NLM_F_MATCH
                    | libc::NLM_F_REQUEST
                    | libc::NLM_F_ACK) as u16,
                nlmsg_seq: self.seq,
                nlmsg_pid: 0,
            },
            gen: RtGenMsg {
                rtgen_family: family,
            },
        };

        // SAFETY: sockaddr_nl is a plain C struct with no invariants;
        // zeroing all bytes produces a valid representation (nl_family=0, nl_pad=0, nl_pid=0, nl_groups=0).
        // We then set the public fields to the desired values.
        let mut dest_addr: libc::sockaddr_nl = unsafe { mem::zeroed() };
        dest_addr.nl_family = libc::AF_NETLINK as u16;
        dest_addr.nl_pid = 0; // kernel
        dest_addr.nl_groups = 0;

        // SAFETY: req and dest_addr are valid repr(C) structs on the stack.
        let rc = unsafe {
            libc::sendto(
                self.fd,
                &req as *const _ as *const libc::c_void,
                mem::size_of::<NetlinkRequest>(),
                0,
                &dest_addr as *const _ as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };

        if rc == -1 {
            let errno = Errno::last();
            return Err(DnsmasqError::Network(format!(
                "netlink sendto (type={}, family={}): {}",
                msg_type, family, errno
            )));
        }

        debug!(
            seq = self.seq,
            msg_type = msg_type,
            family = family,
            "sent netlink dump request"
        );
        Ok(self.seq)
    }

    /// Enumerate network interfaces, addresses, or neighbor entries via netlink dump.
    ///
    /// Sends a netlink dump request for the specified address family and processes
    /// all response messages through the provided callback. Handles interleaved
    /// multicast messages and ENOBUFS conditions.
    ///
    /// Replaces C `iface_enumerate()` (netlink.c line 370).
    ///
    /// # Address Families
    ///
    /// - `AF_INET` → RTM_GETADDR: IPv4 addresses with netmask and broadcast
    /// - `AF_INET6` → RTM_GETADDR: IPv6 addresses with flags and lifetimes
    /// - `AF_UNSPEC` → RTM_GETNEIGH: Neighbor (ARP) table entries
    /// - `AF_LOCAL` → RTM_GETLINK: Link-layer (MAC) addresses
    ///
    /// # Returns
    ///
    /// - `Ok(1)`: Success (all entries enumerated)
    /// - `Ok(0)`: Send failure
    /// - `Ok(-1)`: ENOBUFS (caller should restart enumeration)
    pub fn enumerate_interfaces(
        &mut self,
        family: libc::c_int,
        callback: &mut IfaceCallback<'_>,
    ) -> DnsmasqResult<i32> {
        // Determine the netlink message type based on address family
        let msg_type: u16 = match family {
            libc::AF_UNSPEC => libc::RTM_GETNEIGH,
            libc::AF_LOCAL => libc::RTM_GETLINK,
            _ => libc::RTM_GETADDR,
        };

        // Expected response message type
        let expected_type: u16 = match family {
            libc::AF_UNSPEC => libc::RTM_NEWNEIGH,
            libc::AF_LOCAL => libc::RTM_NEWLINK,
            _ => libc::RTM_NEWADDR,
        };

        // Send the dump request
        let seq = match self.send_dump_request(family as u8, msg_type) {
            Ok(s) => s,
            Err(_) => return Ok(0), // Send failure
        };

        let mut callback_ok = true;
        let mut async_state: u32 = 0;

        // Read response messages until NLMSG_DONE
        loop {
            let msg_len = match self.recv_message(0) {
                Ok(Some(len)) => len,
                Ok(None) => continue,
                Err(ref e) if e.to_string().contains("ENOBUFS") => {
                    // ENOBUFS: tell caller to restart enumeration
                    return Ok(-1);
                }
                Err(_) => return Ok(0),
            };

            // Iterate over all netlink messages in this receive buffer
            let buf_snapshot = self.recv_buf[..msg_len].to_vec();
            for (nlh, msg_data) in NlMsgIter::new(&buf_snapshot) {
                // Check sequence number for request/response correlation
                if nlh.nlmsg_seq != seq {
                    // Interleaved multicast message — process via nl_async
                    nl_async_process(nlh, msg_data, &mut async_state);
                    continue;
                }

                // Handle error responses
                if nlh.nlmsg_type == libc::NLMSG_ERROR as u16 {
                    let err_hdr_size = nlmsg_hdrlen() + mem::size_of::<NlMsgErr>();
                    if msg_data.len() >= err_hdr_size {
                        // SAFETY: We verified sufficient bytes for NlMsgErr.
                        let err = unsafe {
                            &*(msg_data.as_ptr().wrapping_add(nlmsg_hdrlen()) as *const NlMsgErr)
                        };
                        if err.error != 0 {
                            error!(
                                error = err.error,
                                "netlink returns error during enumeration"
                            );
                        }
                    }
                    continue;
                }

                // NLMSG_DONE signals end of dump
                if nlh.nlmsg_type == libc::NLMSG_DONE as u16 {
                    return Ok(1);
                }

                // Only process messages of the expected type
                if nlh.nlmsg_type != expected_type {
                    continue;
                }

                // Parse based on address family
                if !callback_ok {
                    continue; // Callback signaled stop, but keep draining
                }

                match family {
                    libc::AF_INET => {
                        if let IfaceCallback::Inet(ref mut cb) = callback {
                            callback_ok = Self::parse_inet_addr(msg_data, cb);
                        }
                    }
                    libc::AF_INET6 => {
                        if let IfaceCallback::Inet6(ref mut cb) = callback {
                            callback_ok = Self::parse_inet6_addr(msg_data, cb);
                        }
                    }
                    libc::AF_UNSPEC => {
                        if let IfaceCallback::Unspec(ref mut cb) = callback {
                            callback_ok = Self::parse_neigh_entry(msg_data, cb);
                        }
                    }
                    libc::AF_LOCAL => {
                        if let IfaceCallback::Local(ref mut cb) = callback {
                            callback_ok = Self::parse_link_entry(msg_data, cb);
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    /// Parse an RTM_NEWADDR message for AF_INET (IPv4 address).
    ///
    /// Extracts IFA_LOCAL, IFA_BROADCAST, IFA_LABEL from the rtattr chain.
    /// Computes the netmask from the prefix length.
    ///
    /// Corresponds to C netlink.c lines 437-468.
    fn parse_inet_addr(
        msg_data: &[u8],
        cb: &mut dyn FnMut(Ipv4Addr, u32, Option<&str>, Ipv4Addr, Ipv4Addr) -> bool,
    ) -> bool {
        let ifa_offset = nlmsg_hdrlen();
        let ifa_size = mem::size_of::<IfAddrMsg>();

        if msg_data.len() < ifa_offset + ifa_size {
            return true; // Skip malformed message
        }

        // SAFETY: We verified sufficient bytes for IfAddrMsg after nlmsghdr.
        let ifa = unsafe { &*(msg_data.as_ptr().wrapping_add(ifa_offset) as *const IfAddrMsg) };

        // Compute netmask from prefix length: ~0u32 << (32 - prefixlen)
        let prefixlen = ifa.ifa_prefixlen as u32;
        let netmask_bits = if prefixlen == 0 {
            0u32
        } else if prefixlen >= 32 {
            !0u32
        } else {
            !0u32 << (32 - prefixlen)
        };
        let netmask = Ipv4Addr::from(netmask_bits.to_be_bytes());

        let mut addr = Ipv4Addr::UNSPECIFIED;
        let mut broadcast = Ipv4Addr::UNSPECIFIED;
        let mut label: Option<String> = None;

        // Parse rtattr chain following ifaddrmsg
        let attr_offset = ifa_offset + nlmsg_align(ifa_size);
        if attr_offset <= msg_data.len() {
            let attr_buf = &msg_data[attr_offset..];
            for (rta_type, rta_data) in RtAttrIter::new(attr_buf) {
                match rta_type {
                    IFA_LOCAL => {
                        if rta_data.len() >= 4 {
                            let octets: [u8; 4] =
                                [rta_data[0], rta_data[1], rta_data[2], rta_data[3]];
                            addr = Ipv4Addr::from(octets);
                        }
                    }
                    IFA_BROADCAST => {
                        if rta_data.len() >= 4 {
                            let octets: [u8; 4] =
                                [rta_data[0], rta_data[1], rta_data[2], rta_data[3]];
                            broadcast = Ipv4Addr::from(octets);
                        }
                    }
                    IFA_LABEL => {
                        // Label is a null-terminated C string
                        let s = rta_data.split(|&b| b == 0).next().unwrap_or(rta_data);
                        label = std::str::from_utf8(s).ok().map(String::from);
                    }
                    _ => {}
                }
            }
        }

        // Only invoke callback if we got a valid address
        if !addr.is_unspecified() {
            trace!(
                addr = %addr,
                if_index = ifa.ifa_index,
                prefix_len = prefixlen,
                "enumerated IPv4 address"
            );
            return cb(addr, ifa.ifa_index, label.as_deref(), netmask, broadcast);
        }

        true // Continue enumeration
    }

    /// Parse an RTM_NEWADDR message for AF_INET6 (IPv6 address).
    ///
    /// Extracts IFA_LOCAL/IFA_ADDRESS and IFA_CACHEINFO from the rtattr chain.
    /// Maps kernel address flags to IFACE_TENTATIVE/DEPRECATED/PERMANENT.
    ///
    /// Corresponds to C netlink.c lines 469-511.
    fn parse_inet6_addr(
        msg_data: &[u8],
        cb: &mut dyn FnMut(Ipv6Addr, u32, u32, u32, u32, u32, u32) -> bool,
    ) -> bool {
        let ifa_offset = nlmsg_hdrlen();
        let ifa_size = mem::size_of::<IfAddrMsg>();

        if msg_data.len() < ifa_offset + ifa_size {
            return true;
        }

        // SAFETY: We verified sufficient bytes for IfAddrMsg.
        let ifa = unsafe { &*(msg_data.as_ptr().wrapping_add(ifa_offset) as *const IfAddrMsg) };

        let mut addrp: Option<Ipv6Addr> = None;
        let mut have_local = false;
        let mut preferred: u32 = 0;
        let mut valid: u32 = 0;

        // Parse rtattr chain.
        // IFA_LOCAL takes precedence over IFA_ADDRESS for point-to-point
        // interfaces. C's netlink.c checks IFA_LOCAL first and only uses
        // IFA_ADDRESS as fallback. Since attribute order in the kernel
        // message is not guaranteed, we track whether IFA_LOCAL was seen
        // and skip IFA_ADDRESS when it was.
        let attr_offset = ifa_offset + nlmsg_align(ifa_size);
        if attr_offset <= msg_data.len() {
            let attr_buf = &msg_data[attr_offset..];
            for (rta_type, rta_data) in RtAttrIter::new(attr_buf) {
                match rta_type {
                    IFA_LOCAL => {
                        // IFA_LOCAL: the local (source) address. On point-to-point
                        // interfaces this is the correct address to use. Always
                        // takes precedence over IFA_ADDRESS regardless of order.
                        if rta_data.len() >= 16 {
                            let mut octets = [0u8; 16];
                            octets.copy_from_slice(&rta_data[..16]);
                            addrp = Some(Ipv6Addr::from(octets));
                            have_local = true;
                        }
                    }
                    IFA_ADDRESS => {
                        // IFA_ADDRESS: the peer/broadcast address on point-to-point
                        // interfaces, or the interface address on broadcast links.
                        // Only used as fallback when no IFA_LOCAL has been seen,
                        // matching C's netlink.c behavior.
                        if !have_local && rta_data.len() >= 16 {
                            let mut octets = [0u8; 16];
                            octets.copy_from_slice(&rta_data[..16]);
                            addrp = Some(Ipv6Addr::from(octets));
                        }
                    }
                    IFA_CACHEINFO => {
                        let cache_size = mem::size_of::<IfaCacheInfo>();
                        if rta_data.len() >= cache_size {
                            // SAFETY: We verified sufficient bytes for IfaCacheInfo.
                            let cache = unsafe { &*(rta_data.as_ptr() as *const IfaCacheInfo) };
                            preferred = cache.ifa_prefered;
                            valid = cache.ifa_valid;
                        }
                    }
                    _ => {}
                }
            }
        }

        // Map kernel flags to dnsmasq interface flags
        let ifa_flags = ifa.ifa_flags as u32;
        let mut flags: u32 = 0;

        if ifa_flags & IFA_F_TENTATIVE != 0 {
            flags |= IFACE_TENTATIVE;
        }
        if ifa_flags & IFA_F_DEPRECATED != 0 {
            flags |= IFACE_DEPRECATED;
        }
        if ifa_flags & IFA_F_TEMPORARY == 0 {
            flags |= IFACE_PERMANENT;
        }

        if let Some(addr) = addrp {
            trace!(
                addr = %addr,
                if_index = ifa.ifa_index,
                prefix_len = ifa.ifa_prefixlen,
                flags = flags,
                "enumerated IPv6 address"
            );
            return cb(
                addr,
                ifa.ifa_prefixlen as u32,
                ifa.ifa_scope as u32,
                ifa.ifa_index,
                flags,
                preferred,
                valid,
            );
        }

        true
    }

    /// Parse an RTM_NEWNEIGH message (neighbor/ARP table entry).
    ///
    /// Extracts NDA_DST and NDA_LLADDR. Skips entries with NUD_NOARP,
    /// NUD_INCOMPLETE, or NUD_FAILED states.
    ///
    /// Corresponds to C netlink.c lines 514-539.
    fn parse_neigh_entry(msg_data: &[u8], cb: &mut dyn FnMut(u16, IpAddr, &[u8]) -> bool) -> bool {
        let nd_offset = nlmsg_hdrlen();
        let nd_size = mem::size_of::<NdMsg>();

        if msg_data.len() < nd_offset + nd_size {
            return true;
        }

        // SAFETY: We verified sufficient bytes for NdMsg.
        let ndm = unsafe { &*(msg_data.as_ptr().wrapping_add(nd_offset) as *const NdMsg) };

        // Skip bad neighbor states (NUD_NOARP | NUD_INCOMPLETE | NUD_FAILED)
        if ndm.ndm_state & (NUD_NOARP | NUD_INCOMPLETE | NUD_FAILED) != 0 {
            return true;
        }

        let mut dest_addr: Option<IpAddr> = None;
        let mut mac: Option<&[u8]> = None;

        // Parse rtattr chain following ndmsg
        let attr_offset = nd_offset + nlmsg_align(nd_size);
        if attr_offset <= msg_data.len() {
            let attr_buf = &msg_data[attr_offset..];
            for (rta_type, rta_data) in RtAttrIter::new(attr_buf) {
                match rta_type {
                    NDA_DST => {
                        if ndm.ndm_family == libc::AF_INET as u8 && rta_data.len() >= 4 {
                            let octets: [u8; 4] =
                                [rta_data[0], rta_data[1], rta_data[2], rta_data[3]];
                            dest_addr = Some(IpAddr::V4(Ipv4Addr::from(octets)));
                        } else if ndm.ndm_family == libc::AF_INET6 as u8 && rta_data.len() >= 16 {
                            let mut octets = [0u8; 16];
                            octets.copy_from_slice(&rta_data[..16]);
                            dest_addr = Some(IpAddr::V6(Ipv6Addr::from(octets)));
                        }
                    }
                    NDA_LLADDR => {
                        mac = Some(rta_data);
                    }
                    _ => {}
                }
            }
        }

        if let (Some(addr), Some(mac_data)) = (dest_addr, mac) {
            trace!(
                family = ndm.ndm_family,
                addr = %addr,
                mac_len = mac_data.len(),
                "enumerated neighbor entry"
            );
            return cb(ndm.ndm_family as u16, addr, mac_data);
        }

        true
    }

    /// Parse an RTM_NEWLINK message (link-layer/MAC address).
    ///
    /// Extracts IFLA_ADDRESS (MAC address). Skips loopback and point-to-point
    /// interfaces (IFF_LOOPBACK | IFF_POINTOPOINT).
    ///
    /// Corresponds to C netlink.c lines 541-563 (HAVE_DHCP6 gated).
    fn parse_link_entry(msg_data: &[u8], cb: &mut dyn FnMut(u32, u32, &[u8]) -> bool) -> bool {
        let ifi_offset = nlmsg_hdrlen();
        let ifi_size = mem::size_of::<IfInfoMsg>();

        if msg_data.len() < ifi_offset + ifi_size {
            return true;
        }

        // SAFETY: We verified sufficient bytes for IfInfoMsg.
        let info = unsafe { &*(msg_data.as_ptr().wrapping_add(ifi_offset) as *const IfInfoMsg) };

        // Skip loopback and point-to-point interfaces
        if info.ifi_flags & (libc::IFF_LOOPBACK | libc::IFF_POINTOPOINT) as u32 != 0 {
            return true;
        }

        // Parse rtattr chain following ifinfomsg
        let attr_offset = ifi_offset + nlmsg_align(ifi_size);
        if attr_offset <= msg_data.len() {
            let attr_buf = &msg_data[attr_offset..];
            for (rta_type, rta_data) in RtAttrIter::new(attr_buf) {
                if rta_type == IFLA_ADDRESS {
                    trace!(
                        if_index = info.ifi_index,
                        hw_type = info.ifi_type,
                        mac_len = rta_data.len(),
                        "enumerated link entry"
                    );
                    return cb(info.ifi_index as u32, info.ifi_type as u32, rta_data);
                }
            }
        }

        true
    }

    /// Convenience method: enumerate IPv4 interfaces.
    ///
    /// Calls [`enumerate_interfaces`] with `AF_INET` and an `IfaceCallback::Inet`.
    pub fn enumerate_interfaces_v4(
        &mut self,
        cb: &mut dyn FnMut(Ipv4Addr, u32, Option<&str>, Ipv4Addr, Ipv4Addr) -> bool,
    ) -> DnsmasqResult<i32> {
        let mut callback = IfaceCallback::Inet(cb);
        self.enumerate_interfaces(libc::AF_INET, &mut callback)
    }

    /// Convenience method: enumerate IPv6 interfaces.
    ///
    /// Calls [`enumerate_interfaces`] with `AF_INET6` and an `IfaceCallback::Inet6`.
    pub fn enumerate_interfaces_v6(
        &mut self,
        cb: &mut dyn FnMut(Ipv6Addr, u32, u32, u32, u32, u32, u32) -> bool,
    ) -> DnsmasqResult<i32> {
        let mut callback = IfaceCallback::Inet6(cb);
        self.enumerate_interfaces(libc::AF_INET6, &mut callback)
    }

    /// Drain all pending multicast messages and return generated events.
    ///
    /// Performs non-blocking reads (MSG_DONTWAIT) to drain all pending netlink
    /// multicast messages. Retries on ENOBUFS (matching the C do-while loop in
    /// `nl_multicast_state()`, netlink.c line 606).
    ///
    /// Each unique event type is generated at most once per batch (deduplication
    /// via the async state bitmask, matching C `STATE_NEWADDR`/`STATE_NEWROUTE`).
    ///
    /// Replaces C `netlink_multicast()` (netlink.c line 651) and
    /// `nl_multicast_state()` (netlink.c line 606).
    pub fn process_multicast(&mut self) -> Vec<EventCode> {
        let mut events = Vec::new();
        let mut state: u32 = 0;

        // do-while ENOBUFS loop (matches C nl_multicast_state behavior)
        loop {
            let mut had_enobufs = false;

            // Drain all pending messages with non-blocking reads
            loop {
                match self.recv_message(libc::MSG_DONTWAIT) {
                    Ok(Some(msg_len)) => {
                        // Process all netlink messages in this buffer
                        let buf_snapshot = self.recv_buf[..msg_len].to_vec();
                        for (nlh, msg_data) in NlMsgIter::new(&buf_snapshot) {
                            if let Some(event) = nl_async_process(nlh, msg_data, &mut state) {
                                events.push(event);
                            }
                        }
                    }
                    Ok(None) => {
                        // No more messages (EAGAIN/EWOULDBLOCK)
                        break;
                    }
                    Err(ref e) if e.to_string().contains("ENOBUFS") => {
                        // ENOBUFS: kernel dropped messages. We need to retry
                        // the entire drain after processing what we have.
                        had_enobufs = true;
                        warn!("netlink multicast ENOBUFS, retrying drain");
                        break;
                    }
                    Err(e) => {
                        error!(error = %e, "netlink multicast recv error");
                        break;
                    }
                }
            }

            // Continue the do-while loop if we got ENOBUFS
            if !had_enobufs {
                break;
            }
        }

        if !events.is_empty() {
            debug!(count = events.len(), "generated netlink multicast events");
        }

        events
    }

    /// Enable NETLINK_NO_ENOBUFS socket option to suppress ENOBUFS errors.
    ///
    /// This is a best-effort operation — if the setsockopt fails (e.g., on
    /// older kernels), we continue without it.
    pub fn init_monitoring(&self) {
        let one: libc::c_int = 1;
        // SAFETY: one is a valid c_int on the stack, sizeof(c_int) is correct.
        let rc = unsafe {
            libc::setsockopt(
                self.fd,
                SOL_NETLINK,
                NETLINK_NO_ENOBUFS,
                &one as *const _ as *const libc::c_void,
                mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };

        if rc == -1 {
            debug!(
                errno = %Errno::last(),
                "NETLINK_NO_ENOBUFS not supported (older kernel), continuing"
            );
        } else {
            debug!("enabled NETLINK_NO_ENOBUFS on netlink socket");
        }
    }
}

// ===========================================================================
// Internal nl_async message processing
// ===========================================================================

/// Process a single netlink multicast message for asynchronous event generation.
///
/// Handles NLMSG_ERROR, RTM_NEWROUTE, RTM_NEWADDR, and RTM_DELADDR messages.
/// Uses the state bitmask for deduplication (each event type generated at most
/// once per batch).
///
/// Replaces C `nl_async()` (netlink.c line 706).
///
/// # Arguments
///
/// * `nlh` - The netlink message header
/// * `msg_data` - The full message data (including header)
/// * `state` - Mutable deduplication state bitmask
///
/// # Returns
///
/// `Some(EventCode)` if a new event should be queued, `None` otherwise.
fn nl_async_process(nlh: &libc::nlmsghdr, msg_data: &[u8], state: &mut u32) -> Option<EventCode> {
    let msg_type = nlh.nlmsg_type;
    let msg_pid = nlh.nlmsg_pid;

    // Handle NLMSG_ERROR — log and discard
    if msg_type == libc::NLMSG_ERROR as u16 {
        let err_offset = nlmsg_hdrlen();
        let err_size = mem::size_of::<NlMsgErr>();

        if msg_data.len() >= err_offset + err_size {
            // SAFETY: We verified sufficient bytes for NlMsgErr after header.
            let err = unsafe { &*(msg_data.as_ptr().wrapping_add(err_offset) as *const NlMsgErr) };
            if err.error != 0 {
                // Convert negative errno to string
                let errno_val = if err.error < 0 { -err.error } else { err.error };
                error!(
                    errno = errno_val,
                    "netlink returns error: {}",
                    std::io::Error::from_raw_os_error(errno_val)
                );
            }
        }
        return None;
    }

    // Handle RTM_NEWROUTE — detect new routes for DoD (Dial-on-Demand) support
    if msg_type == libc::RTM_NEWROUTE && msg_pid == 0 {
        let rtm_offset = nlmsg_hdrlen();
        let rtm_size = mem::size_of::<RtMsg>();

        if msg_data.len() >= rtm_offset + rtm_size {
            // SAFETY: We verified sufficient bytes for RtMsg after header.
            let rtm = unsafe { &*(msg_data.as_ptr().wrapping_add(rtm_offset) as *const RtMsg) };

            // Only unicast routes with link scope in main or local table
            if rtm.rtm_type == RTN_UNICAST
                && rtm.rtm_scope == RT_SCOPE_LINK
                && (rtm.rtm_table == RT_TABLE_MAIN || rtm.rtm_table == RT_TABLE_LOCAL)
                && *state & STATE_NEWROUTE == 0
            {
                *state |= STATE_NEWROUTE;
                debug!("detected new route, generating EVENT_NEWROUTE");
                return Some(EventCode::NewRoute);
            }
        }
        return None;
    }

    // Handle RTM_NEWADDR / RTM_DELADDR — address changes
    if msg_type == libc::RTM_NEWADDR || msg_type == libc::RTM_DELADDR {
        if *state & STATE_NEWADDR == 0 {
            *state |= STATE_NEWADDR;
            debug!(
                msg_type = msg_type,
                "detected address change, generating EVENT_NEWADDR"
            );
            return Some(EventCode::NewAddr);
        }
        return None;
    }

    None
}

// ===========================================================================
// Standalone public functions (matching C API)
// ===========================================================================

/// Initialize the netlink socket interface.
///
/// Creates a new `NetlinkNetwork` instance. This is the standalone function
/// equivalent of `NetlinkNetwork::new()`, matching the C `netlink_init()` API.
pub fn netlink_init() -> DnsmasqResult<NetlinkNetwork> {
    NetlinkNetwork::new()
}

/// Process pending netlink multicast messages and return generated events.
///
/// Drains all pending multicast messages from the netlink socket, processing
/// each through the async event handler. Returns a list of deduplicated events.
///
/// This is the standalone function equivalent of `NetlinkNetwork::process_multicast()`,
/// matching the C `netlink_multicast()` API.
pub fn netlink_multicast(network: &mut NetlinkNetwork) -> Vec<EventCode> {
    network.process_multicast()
}

/// Process a single netlink message for asynchronous event generation.
///
/// This is the standalone function equivalent of the internal `nl_async_process()`,
/// exposed for use by other modules that may need to process individual netlink
/// messages (e.g., during interface enumeration).
///
/// # Arguments
///
/// * `msg_type` - Netlink message type (nlmsg_type)
/// * `msg_pid` - Sender PID (nlmsg_pid, 0 = kernel)
/// * `data` - Full message data including header
/// * `state` - Mutable deduplication state bitmask
///
/// # Returns
///
/// `Some(EventCode)` if a new event should be queued, `None` otherwise.
pub fn nl_async(msg_type: u16, msg_pid: u32, data: &[u8], state: &mut u32) -> Option<EventCode> {
    // Construct a minimal nlmsghdr for the process function
    if data.len() < mem::size_of::<libc::nlmsghdr>() {
        return None;
    }

    // SAFETY: We verified sufficient bytes for nlmsghdr.
    let nlh = unsafe { &*(data.as_ptr() as *const libc::nlmsghdr) };

    // Verify the msg_type and msg_pid match the header (or use provided values)
    let effective_nlh = libc::nlmsghdr {
        nlmsg_len: nlh.nlmsg_len,
        nlmsg_type: msg_type,
        nlmsg_flags: nlh.nlmsg_flags,
        nlmsg_seq: nlh.nlmsg_seq,
        nlmsg_pid: msg_pid,
    };

    // Use a temporary reference — construct on stack and process
    nl_async_process(&effective_nlh, data, state)
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Alignment helper tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_nlmsg_align() {
        assert_eq!(nlmsg_align(0), 0);
        assert_eq!(nlmsg_align(1), 4);
        assert_eq!(nlmsg_align(2), 4);
        assert_eq!(nlmsg_align(3), 4);
        assert_eq!(nlmsg_align(4), 4);
        assert_eq!(nlmsg_align(5), 8);
        assert_eq!(nlmsg_align(16), 16);
        assert_eq!(nlmsg_align(17), 20);
    }

    #[test]
    fn test_rta_align() {
        assert_eq!(rta_align(0), 0);
        assert_eq!(rta_align(1), 4);
        assert_eq!(rta_align(4), 4);
        assert_eq!(rta_align(5), 8);
    }

    #[test]
    fn test_nlmsg_hdrlen() {
        // nlmsghdr is 16 bytes on Linux; aligned to 4 = 16
        let hdrlen = nlmsg_hdrlen();
        assert!(hdrlen >= 16);
        assert_eq!(hdrlen % NLMSG_ALIGNTO, 0);
    }

    #[test]
    fn test_rta_hdrlen() {
        // RtAttr is 4 bytes; aligned to 4 = 4
        let hdrlen = rta_hdrlen();
        assert_eq!(hdrlen, 4);
    }

    // -----------------------------------------------------------------------
    // Netmask calculation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_netmask_from_prefix() {
        // /24 -> 255.255.255.0
        let prefix: u32 = 24;
        let mask_bits = !0u32 << (32 - prefix);
        let mask = Ipv4Addr::from(mask_bits.to_be_bytes());
        assert_eq!(mask, Ipv4Addr::new(255, 255, 255, 0));

        // /32 -> 255.255.255.255
        let mask_bits = !0u32;
        let mask = Ipv4Addr::from(mask_bits.to_be_bytes());
        assert_eq!(mask, Ipv4Addr::new(255, 255, 255, 255));

        // /0 -> 0.0.0.0
        let mask = Ipv4Addr::from(0u32.to_be_bytes());
        assert_eq!(mask, Ipv4Addr::UNSPECIFIED);

        // /16 -> 255.255.0.0
        let prefix: u32 = 16;
        let mask_bits = !0u32 << (32 - prefix);
        let mask = Ipv4Addr::from(mask_bits.to_be_bytes());
        assert_eq!(mask, Ipv4Addr::new(255, 255, 0, 0));

        // /8 -> 255.0.0.0
        let prefix: u32 = 8;
        let mask_bits = !0u32 << (32 - prefix);
        let mask = Ipv4Addr::from(mask_bits.to_be_bytes());
        assert_eq!(mask, Ipv4Addr::new(255, 0, 0, 0));
    }

    // -----------------------------------------------------------------------
    // IPv6 flag mapping tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_ipv6_flag_tentative() {
        let ifa_flags: u32 = IFA_F_TENTATIVE;
        let mut flags: u32 = 0;
        if ifa_flags & IFA_F_TENTATIVE != 0 {
            flags |= IFACE_TENTATIVE;
        }
        if ifa_flags & IFA_F_DEPRECATED != 0 {
            flags |= IFACE_DEPRECATED;
        }
        if ifa_flags & IFA_F_TEMPORARY == 0 {
            flags |= IFACE_PERMANENT;
        }
        assert_eq!(flags, IFACE_TENTATIVE | IFACE_PERMANENT);
    }

    #[test]
    fn test_ipv6_flag_deprecated() {
        let ifa_flags: u32 = IFA_F_DEPRECATED;
        let mut flags: u32 = 0;
        if ifa_flags & IFA_F_TENTATIVE != 0 {
            flags |= IFACE_TENTATIVE;
        }
        if ifa_flags & IFA_F_DEPRECATED != 0 {
            flags |= IFACE_DEPRECATED;
        }
        if ifa_flags & IFA_F_TEMPORARY == 0 {
            flags |= IFACE_PERMANENT;
        }
        assert_eq!(flags, IFACE_DEPRECATED | IFACE_PERMANENT);
    }

    #[test]
    fn test_ipv6_flag_temporary() {
        // Temporary address: has IFA_F_TEMPORARY set, so NOT permanent
        let ifa_flags: u32 = IFA_F_TEMPORARY;
        let mut flags: u32 = 0;
        if ifa_flags & IFA_F_TENTATIVE != 0 {
            flags |= IFACE_TENTATIVE;
        }
        if ifa_flags & IFA_F_DEPRECATED != 0 {
            flags |= IFACE_DEPRECATED;
        }
        if ifa_flags & IFA_F_TEMPORARY == 0 {
            flags |= IFACE_PERMANENT;
        }
        assert_eq!(flags, 0); // temporary = not permanent, not tentative, not deprecated
    }

    #[test]
    fn test_ipv6_flag_permanent_normal() {
        // Normal permanent address: no flags set
        let ifa_flags: u32 = 0;
        let mut flags: u32 = 0;
        if ifa_flags & IFA_F_TENTATIVE != 0 {
            flags |= IFACE_TENTATIVE;
        }
        if ifa_flags & IFA_F_DEPRECATED != 0 {
            flags |= IFACE_DEPRECATED;
        }
        if ifa_flags & IFA_F_TEMPORARY == 0 {
            flags |= IFACE_PERMANENT;
        }
        assert_eq!(flags, IFACE_PERMANENT);
    }

    // -----------------------------------------------------------------------
    // Async state deduplication tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_state_dedup_newaddr() {
        let mut state: u32 = 0;

        // First NEWADDR event should be generated
        assert_eq!(state & STATE_NEWADDR, 0);
        state |= STATE_NEWADDR;
        assert_ne!(state & STATE_NEWADDR, 0);

        // Second NEWADDR should be suppressed
        assert_ne!(state & STATE_NEWADDR, 0);
    }

    #[test]
    fn test_state_dedup_newroute() {
        let mut state: u32 = 0;

        // First NEWROUTE event should be generated
        assert_eq!(state & STATE_NEWROUTE, 0);
        state |= STATE_NEWROUTE;
        assert_ne!(state & STATE_NEWROUTE, 0);
    }

    #[test]
    fn test_state_dedup_independent() {
        let mut state: u32 = 0;

        // NEWADDR and NEWROUTE are independent
        state |= STATE_NEWADDR;
        assert_ne!(state & STATE_NEWADDR, 0);
        assert_eq!(state & STATE_NEWROUTE, 0);

        state |= STATE_NEWROUTE;
        assert_ne!(state & STATE_NEWADDR, 0);
        assert_ne!(state & STATE_NEWROUTE, 0);
    }

    // -----------------------------------------------------------------------
    // NlMsgIter tests with synthetic messages
    // -----------------------------------------------------------------------

    /// Build a minimal nlmsghdr in a byte buffer.
    fn build_nlmsghdr(buf: &mut Vec<u8>, msg_type: u16, msg_len: u32) {
        let nlh = libc::nlmsghdr {
            nlmsg_len: msg_len,
            nlmsg_type: msg_type,
            nlmsg_flags: 0,
            nlmsg_seq: 0,
            nlmsg_pid: 0,
        };
        let bytes = unsafe {
            std::slice::from_raw_parts(
                &nlh as *const _ as *const u8,
                mem::size_of::<libc::nlmsghdr>(),
            )
        };
        buf.extend_from_slice(bytes);
    }

    #[test]
    fn test_nlmsg_iter_empty() {
        let buf: &[u8] = &[];
        let mut iter = NlMsgIter::new(buf);
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_nlmsg_iter_too_short() {
        let buf: &[u8] = &[0, 0, 0]; // Less than sizeof(nlmsghdr)
        let mut iter = NlMsgIter::new(buf);
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_nlmsg_iter_single_message() {
        let hdr_size = mem::size_of::<libc::nlmsghdr>() as u32;
        let mut buf = Vec::new();
        build_nlmsghdr(&mut buf, libc::NLMSG_DONE as u16, hdr_size);

        let msgs: Vec<_> = NlMsgIter::new(&buf).collect();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].0.nlmsg_type, libc::NLMSG_DONE as u16);
    }

    #[test]
    fn test_nlmsg_iter_two_messages() {
        let hdr_size = mem::size_of::<libc::nlmsghdr>() as u32;
        let aligned = nlmsg_align(hdr_size as usize);
        let mut buf = Vec::new();
        build_nlmsghdr(&mut buf, 1, hdr_size);
        // Pad to alignment
        buf.resize(aligned, 0);
        build_nlmsghdr(&mut buf, 2, hdr_size);

        let msgs: Vec<_> = NlMsgIter::new(&buf).collect();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].0.nlmsg_type, 1);
        assert_eq!(msgs[1].0.nlmsg_type, 2);
    }

    // -----------------------------------------------------------------------
    // RtAttrIter tests with synthetic attributes
    // -----------------------------------------------------------------------

    /// Build a minimal rtattr in a byte buffer.
    fn build_rtattr(buf: &mut Vec<u8>, rta_type: u16, data: &[u8]) {
        let rta_len = (mem::size_of::<RtAttr>() + data.len()) as u16;
        let rta = RtAttr { rta_len, rta_type };
        let hdr_bytes = unsafe {
            std::slice::from_raw_parts(&rta as *const _ as *const u8, mem::size_of::<RtAttr>())
        };
        buf.extend_from_slice(hdr_bytes);
        buf.extend_from_slice(data);
        // Pad to RTA_ALIGNTO
        let padded = rta_align(rta_len as usize);
        buf.resize(padded.max(buf.len()), 0);
    }

    #[test]
    fn test_rtattr_iter_empty() {
        let buf: &[u8] = &[];
        let mut iter = RtAttrIter::new(buf);
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_rtattr_iter_single() {
        let mut buf = Vec::new();
        let data = [192u8, 168, 1, 1]; // 192.168.1.1
        build_rtattr(&mut buf, IFA_LOCAL, &data);

        let attrs: Vec<_> = RtAttrIter::new(&buf).collect();
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].0, IFA_LOCAL);
        assert_eq!(attrs[0].1, &data);
    }

    #[test]
    fn test_rtattr_iter_multiple() {
        let mut buf = Vec::new();
        let addr_data = [192u8, 168, 1, 1];
        let bcast_data = [192u8, 168, 1, 255];
        build_rtattr(&mut buf, IFA_LOCAL, &addr_data);
        build_rtattr(&mut buf, IFA_BROADCAST, &bcast_data);

        let attrs: Vec<_> = RtAttrIter::new(&buf).collect();
        assert_eq!(attrs.len(), 2);
        assert_eq!(attrs[0].0, IFA_LOCAL);
        assert_eq!(attrs[0].1, &addr_data);
        assert_eq!(attrs[1].0, IFA_BROADCAST);
        assert_eq!(attrs[1].1, &bcast_data);
    }

    // -----------------------------------------------------------------------
    // nl_async_process tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_nl_async_error_message() {
        let mut state: u32 = 0;

        // Build NLMSG_ERROR message with error=-2 (ENOENT)
        let hdr_size = mem::size_of::<libc::nlmsghdr>();
        let err_size = mem::size_of::<NlMsgErr>();
        let msg_len = nlmsg_align(hdr_size) + err_size;

        let nlh = libc::nlmsghdr {
            nlmsg_len: msg_len as u32,
            nlmsg_type: libc::NLMSG_ERROR as u16,
            nlmsg_flags: 0,
            nlmsg_seq: 0,
            nlmsg_pid: 0,
        };

        let mut msg_data = vec![0u8; msg_len];
        unsafe {
            std::ptr::copy_nonoverlapping(
                &nlh as *const _ as *const u8,
                msg_data.as_mut_ptr(),
                hdr_size,
            );
        }
        // Set error field to -2
        let err_offset = nlmsg_hdrlen();
        if msg_data.len() >= err_offset + 4 {
            let err_val: i32 = -2;
            msg_data[err_offset..err_offset + 4].copy_from_slice(&err_val.to_ne_bytes());
        }

        let result = nl_async_process(&nlh, &msg_data, &mut state);
        assert!(result.is_none()); // NLMSG_ERROR returns None
    }

    #[test]
    fn test_nl_async_newaddr() {
        let mut state: u32 = 0;

        let nlh = libc::nlmsghdr {
            nlmsg_len: mem::size_of::<libc::nlmsghdr>() as u32,
            nlmsg_type: libc::RTM_NEWADDR as u16,
            nlmsg_flags: 0,
            nlmsg_seq: 0,
            nlmsg_pid: 0,
        };

        let msg_data = unsafe {
            std::slice::from_raw_parts(
                &nlh as *const _ as *const u8,
                mem::size_of::<libc::nlmsghdr>(),
            )
        };

        // First call should generate event
        let result = nl_async_process(&nlh, msg_data, &mut state);
        assert!(matches!(result, Some(EventCode::NewAddr)));

        // Second call should be deduplicated
        let result = nl_async_process(&nlh, msg_data, &mut state);
        assert!(result.is_none());
    }

    #[test]
    fn test_nl_async_deladdr() {
        let mut state: u32 = 0;

        let nlh = libc::nlmsghdr {
            nlmsg_len: mem::size_of::<libc::nlmsghdr>() as u32,
            nlmsg_type: libc::RTM_DELADDR as u16,
            nlmsg_flags: 0,
            nlmsg_seq: 0,
            nlmsg_pid: 0,
        };

        let msg_data = unsafe {
            std::slice::from_raw_parts(
                &nlh as *const _ as *const u8,
                mem::size_of::<libc::nlmsghdr>(),
            )
        };

        let result = nl_async_process(&nlh, msg_data, &mut state);
        assert!(matches!(result, Some(EventCode::NewAddr)));
    }

    #[test]
    fn test_nl_async_newroute_with_valid_route() {
        let mut state: u32 = 0;

        // Build RTM_NEWROUTE message with valid rtmsg payload
        let hdr_size = mem::size_of::<libc::nlmsghdr>();
        let rtm_size = mem::size_of::<RtMsg>();
        let msg_len = nlmsg_align(hdr_size) + rtm_size;

        let nlh = libc::nlmsghdr {
            nlmsg_len: msg_len as u32,
            nlmsg_type: libc::RTM_NEWROUTE as u16,
            nlmsg_flags: 0,
            nlmsg_seq: 0,
            nlmsg_pid: 0, // from kernel
        };

        let rtm = RtMsg {
            rtm_family: libc::AF_INET as u8,
            rtm_dst_len: 0,
            rtm_src_len: 0,
            rtm_tos: 0,
            rtm_table: RT_TABLE_MAIN,
            rtm_protocol: 0,
            rtm_scope: RT_SCOPE_LINK,
            rtm_type: RTN_UNICAST,
            rtm_flags: 0,
        };

        let mut msg_data = vec![0u8; msg_len];
        unsafe {
            std::ptr::copy_nonoverlapping(
                &nlh as *const _ as *const u8,
                msg_data.as_mut_ptr(),
                hdr_size,
            );
            std::ptr::copy_nonoverlapping(
                &rtm as *const _ as *const u8,
                msg_data.as_mut_ptr().add(nlmsg_hdrlen()),
                rtm_size,
            );
        }

        let result = nl_async_process(&nlh, &msg_data, &mut state);
        assert!(matches!(result, Some(EventCode::NewRoute)));

        // Dedup check
        let result = nl_async_process(&nlh, &msg_data, &mut state);
        assert!(result.is_none());
    }

    #[test]
    fn test_nl_async_newroute_non_kernel() {
        let mut state: u32 = 0;

        let hdr_size = mem::size_of::<libc::nlmsghdr>();
        let rtm_size = mem::size_of::<RtMsg>();
        let msg_len = nlmsg_align(hdr_size) + rtm_size;

        // Non-kernel PID (should NOT generate event)
        let nlh = libc::nlmsghdr {
            nlmsg_len: msg_len as u32,
            nlmsg_type: libc::RTM_NEWROUTE as u16,
            nlmsg_flags: 0,
            nlmsg_seq: 0,
            nlmsg_pid: 12345, // NOT kernel
        };

        let rtm = RtMsg {
            rtm_family: libc::AF_INET as u8,
            rtm_dst_len: 0,
            rtm_src_len: 0,
            rtm_tos: 0,
            rtm_table: RT_TABLE_MAIN,
            rtm_protocol: 0,
            rtm_scope: RT_SCOPE_LINK,
            rtm_type: RTN_UNICAST,
            rtm_flags: 0,
        };

        let mut msg_data = vec![0u8; msg_len];
        unsafe {
            std::ptr::copy_nonoverlapping(
                &nlh as *const _ as *const u8,
                msg_data.as_mut_ptr(),
                hdr_size,
            );
            std::ptr::copy_nonoverlapping(
                &rtm as *const _ as *const u8,
                msg_data.as_mut_ptr().add(nlmsg_hdrlen()),
                rtm_size,
            );
        }

        let result = nl_async_process(&nlh, &msg_data, &mut state);
        assert!(result.is_none()); // Non-kernel route should be ignored
    }

    // -----------------------------------------------------------------------
    // Neighbor state filtering tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_neighbor_state_filter() {
        // Verify that bad states are correctly filtered
        let bad_states: u16 = NUD_NOARP | NUD_INCOMPLETE | NUD_FAILED;

        assert_ne!(NUD_NOARP & bad_states, 0);
        assert_ne!(NUD_INCOMPLETE & bad_states, 0);
        assert_ne!(NUD_FAILED & bad_states, 0);

        // Good states (not matching filter)
        let nud_reachable: u16 = 0x02;
        let nud_stale: u16 = 0x04;
        assert_eq!(nud_reachable & bad_states, 0);
        assert_eq!(nud_stale & bad_states, 0);
    }

    // -----------------------------------------------------------------------
    // Interface flag constant tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_iface_flag_values() {
        assert_eq!(IFACE_TENTATIVE, 1);
        assert_eq!(IFACE_DEPRECATED, 2);
        assert_eq!(IFACE_PERMANENT, 4);
        // Verify no overlapping bits
        assert_eq!(IFACE_TENTATIVE & IFACE_DEPRECATED, 0);
        assert_eq!(IFACE_TENTATIVE & IFACE_PERMANENT, 0);
        assert_eq!(IFACE_DEPRECATED & IFACE_PERMANENT, 0);
    }

    // -----------------------------------------------------------------------
    // Standalone function tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_nl_async_standalone_too_short() {
        let mut state: u32 = 0;
        let data: &[u8] = &[0, 0]; // Too short for nlmsghdr
        let result = nl_async(libc::RTM_NEWADDR as u16, 0, data, &mut state);
        assert!(result.is_none());
    }

    // -----------------------------------------------------------------------
    // Buffer expansion logic test
    // -----------------------------------------------------------------------

    #[test]
    fn test_buffer_expansion_math() {
        // Verify the buffer expansion formula: new_size = peek_len + 100
        let peek_len: usize = 4096;
        let new_size = peek_len + 100;
        assert_eq!(new_size, 4196);

        // Edge case: very small message
        let peek_len: usize = 16;
        let new_size = peek_len + 100;
        assert_eq!(new_size, 116);
    }
}

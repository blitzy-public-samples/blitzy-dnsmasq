// Copyright (C) 2024 Simon Kelley
// SPDX-License-Identifier: GPL-2.0-or-later
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.

//! # Linux Netfilter Conntrack Mark Retrieval
//!
//! Rust implementation of Linux netfilter connection tracking mark retrieval,
//! migrated from `src/conntrack.c` (324 lines). This module queries the Linux
//! kernel's netfilter connection tracking (conntrack) table to retrieve
//! connection marks associated with incoming DNS queries, enabling:
//!
//! - **Policy-based DNS routing** — route DNS queries through specific upstream
//!   servers based on netfilter marks assigned by firewall rules.
//! - **VPN split-horizon DNS** — direct DNS queries from VPN-marked connections
//!   to VPN-specific DNS servers.
//! - **Per-connection DNS policies** — apply different DNS filtering or forwarding
//!   rules based on connection marks.
//!
//! ## Implementation Approach
//!
//! Uses raw netlink sockets via the `nix` crate to communicate directly with
//! the kernel's `NFNL_SUBSYS_CTNETLINK` subsystem (Option A from the design).
//! This avoids requiring `libnetfilter_conntrack` C library bindings and
//! eliminates the C library dependency entirely.
//!
//! ## Feature Gate
//!
//! This module is gated by both the `conntrack` Cargo feature and
//! `target_os = "linux"`, matching C's `#ifdef HAVE_CONNTRACK` conditional.
//!
//! ## Safety
//!
//! No `unsafe` blocks — all system calls are mediated through the `nix` crate's
//! safe wrappers. The `OwnedFd` from `nix::sys::socket::socket()` provides
//! RAII-based deterministic socket cleanup, replacing C's manual
//! `nfct_open()`/`nfct_close()` pattern.
//!
//! ## Linux Kernel Requirements
//!
//! - Linux kernel with `CONFIG_NF_CONNTRACK` enabled
//! - `nf_conntrack` kernel module loaded
//! - `CAP_NET_ADMIN` capability or root privileges for conntrack table queries
//! - Active connection tracking for the queried connection

use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};

use thiserror::Error;
use tracing::error;

use nix::sys::socket::{
    bind, recvfrom, sendto, socket, AddressFamily, MsgFlags, NetlinkAddr, SockFlag, SockProtocol,
    SockType,
};

use crate::core::types::{AllAddr, DnsmasqError, MySockAddr};

// ---------------------------------------------------------------------------
// Public Types
// ---------------------------------------------------------------------------

/// Error type for conntrack mark retrieval operations.
///
/// Replaces C's `errno` + `my_syslog(LOG_ERR, ...)` error reporting pattern
/// from `conntrack.c` with typed Rust error variants. Each variant corresponds
/// to a specific failure mode in the conntrack query pipeline.
#[derive(Debug, Error)]
pub enum ConntrackError {
    /// Failed to create the netlink socket or conntrack query message.
    ///
    /// Corresponds to C's `nfct_new()` returning `NULL` (conntrack.c line 228).
    #[error("Failed to create conntrack entry: {0}")]
    CreateFailed(String),

    /// Failed to open the netlink/conntrack communication channel.
    ///
    /// Corresponds to C's `nfct_open(CONNTRACK, 0)` returning `NULL`
    /// (conntrack.c line 249).
    #[error("Failed to open conntrack handle: {0}")]
    OpenFailed(String),

    /// The conntrack query to the kernel failed.
    ///
    /// Corresponds to C's `nfct_query(h, NFCT_Q_GET, ct) == -1`
    /// (conntrack.c line 252).
    #[error("Conntrack query failed: {0}")]
    QueryFailed(String),

    /// No matching conntrack entry was found for the connection tuple.
    ///
    /// Corresponds to the C `gotit == 0` case (conntrack.c line 266) where
    /// the callback was never invoked because no conntrack entry matches
    /// the 5-tuple.
    #[error("No matching conntrack entry found")]
    NoMatch,
}

/// Conversion from [`ConntrackError`] to the crate-wide [`DnsmasqError`].
///
/// Maps conntrack failures to `DnsmasqError::Network` since conntrack
/// is a network-layer operation.
impl From<ConntrackError> for DnsmasqError {
    fn from(err: ConntrackError) -> Self {
        DnsmasqError::Network(err.to_string())
    }
}

// ---------------------------------------------------------------------------
// Warn-Once State (replaces C static int warned, conntrack.c line 254)
// ---------------------------------------------------------------------------

/// Global flag implementing the "warn once" error logging pattern.
///
/// Matches C's `static int warned = 0` from `conntrack.c` lines 254-259.
/// On the first conntrack query failure, an error is logged via `tracing::error!`.
/// Subsequent failures are silently ignored to prevent syslog spam when the
/// conntrack subsystem is persistently unavailable.
///
/// `Ordering::Relaxed` is sufficient because this is a best-effort logging
/// optimisation, not a synchronisation primitive.
static WARNED: AtomicBool = AtomicBool::new(false);

// ---------------------------------------------------------------------------
// Netfilter Conntrack Netlink Protocol Constants
// ---------------------------------------------------------------------------
//
// These constants define the Linux netfilter conntrack netlink wire protocol.
// They are not exposed by the `nix` or `libc` crates, so we define them here
// from the kernel headers <linux/netfilter/nfnetlink.h> and
// <linux/netfilter/nfnetlink_conntrack.h>.

/// Netfilter netlink subsystem ID for connection tracking.
/// From `<linux/netfilter/nfnetlink.h>`: `NFNL_SUBSYS_CTNETLINK = 1`.
const NFNL_SUBSYS_CTNETLINK: u16 = 1;

/// Message type for retrieving a specific conntrack entry by tuple.
/// From `<linux/netfilter/nfnetlink_conntrack.h>`: `IPCTNL_MSG_CT_GET = 1`.
const IPCTNL_MSG_CT_GET: u16 = 1;

/// Message type for a conntrack entry returned by the kernel.
/// From `<linux/netfilter/nfnetlink_conntrack.h>`: `IPCTNL_MSG_CT_NEW = 0`.
const IPCTNL_MSG_CT_NEW: u16 = 0;

/// Conntrack attribute: original direction tuple (nested).
/// From `<linux/netfilter/nfnetlink_conntrack.h>`: `CTA_TUPLE_ORIG = 1`.
const CTA_TUPLE_ORIG: u16 = 1;

/// Conntrack attribute: connection mark.
/// From `<linux/netfilter/nfnetlink_conntrack.h>`: `CTA_MARK = 8`.
const CTA_MARK: u16 = 8;

/// Tuple sub-attribute: IP addresses (nested).
/// From `<linux/netfilter/nfnetlink_conntrack.h>`: `CTA_TUPLE_IP = 1`.
const CTA_TUPLE_IP: u16 = 1;

/// Tuple sub-attribute: protocol information (nested).
/// From `<linux/netfilter/nfnetlink_conntrack.h>`: `CTA_TUPLE_PROTO = 2`.
const CTA_TUPLE_PROTO: u16 = 2;

/// IP sub-attribute: IPv4 source address (4 bytes, network byte order).
/// From `<linux/netfilter/nfnetlink_conntrack.h>`: `CTA_IP_V4_SRC = 1`.
const CTA_IP_V4_SRC: u16 = 1;

/// IP sub-attribute: IPv4 destination address (4 bytes, network byte order).
/// From `<linux/netfilter/nfnetlink_conntrack.h>`: `CTA_IP_V4_DST = 2`.
const CTA_IP_V4_DST: u16 = 2;

/// IP sub-attribute: IPv6 source address (16 bytes, network byte order).
/// From `<linux/netfilter/nfnetlink_conntrack.h>`: `CTA_IP_V6_SRC = 3`.
const CTA_IP_V6_SRC: u16 = 3;

/// IP sub-attribute: IPv6 destination address (16 bytes, network byte order).
/// From `<linux/netfilter/nfnetlink_conntrack.h>`: `CTA_IP_V6_DST = 4`.
const CTA_IP_V6_DST: u16 = 4;

/// Protocol sub-attribute: L4 protocol number (u8).
/// From `<linux/netfilter/nfnetlink_conntrack.h>`: `CTA_PROTO_NUM = 1`.
const CTA_PROTO_NUM: u16 = 1;

/// Protocol sub-attribute: source port (u16, network byte order).
/// From `<linux/netfilter/nfnetlink_conntrack.h>`: `CTA_PROTO_SRC_PORT = 2`.
const CTA_PROTO_SRC_PORT: u16 = 2;

/// Protocol sub-attribute: destination port (u16, network byte order).
/// From `<linux/netfilter/nfnetlink_conntrack.h>`: `CTA_PROTO_DST_PORT = 3`.
const CTA_PROTO_DST_PORT: u16 = 3;

/// NLA flag indicating a nested attribute containing child attributes.
/// From `<linux/netlink.h>`: `NLA_F_NESTED = (1 << 15)`.
const NLA_F_NESTED: u16 = 1 << 15;

/// Netlink message type for error/ACK responses.
/// From `<linux/netlink.h>`: `NLMSG_ERROR = 2`.
const NLMSG_ERROR: u16 = 2;

/// Netlink message flag: this is a request message.
/// From `<linux/netlink.h>`: `NLM_F_REQUEST = 0x01`.
const NLM_F_REQUEST: u16 = 0x01;

/// Netlink message flag: request an acknowledgement.
/// From `<linux/netlink.h>`: `NLM_F_ACK = 0x04`.
const NLM_F_ACK: u16 = 0x04;

/// Size of a netlink message header (`struct nlmsghdr`): 16 bytes.
const NLMSG_HDRLEN: usize = 16;

/// Size of a netlink attribute header (`struct nlattr`): 4 bytes.
const NLA_HDRLEN: usize = 4;

/// Size of a netfilter generic message header (`struct nfgenmsg`): 4 bytes.
const NFGENMSG_LEN: usize = 4;

/// Netfilter netlink version 0.
/// From `<linux/netfilter/nfnetlink.h>`: `NFNETLINK_V0 = 0`.
const NFNETLINK_V0: u8 = 0;

/// Maximum size of the receive buffer for netlink responses.
/// 4096 bytes is sufficient for a single conntrack entry response.
const RECV_BUF_SIZE: usize = 4096;

// ---------------------------------------------------------------------------
// Helper: NLA alignment
// ---------------------------------------------------------------------------

/// Align a byte offset up to the nearest 4-byte boundary.
///
/// Matches the kernel's `NLA_ALIGN()` / `NLMSG_ALIGN()` macros from
/// `<linux/netlink.h>`. All netlink attributes and messages must be
/// aligned to 4-byte boundaries.
#[inline]
fn nla_align(len: usize) -> usize {
    (len + 3) & !3
}

// ---------------------------------------------------------------------------
// Netlink Message Builder
// ---------------------------------------------------------------------------

/// Builder for constructing netlink messages with proper alignment.
///
/// Provides methods for writing netlink headers, nfgenmsg headers, and
/// netlink attributes (NLA) in the correct wire format. Handles the
/// NLA alignment requirements automatically.
///
/// This replaces the C pattern of calling `nfct_new()` + `nfct_set_attr_*()`
/// functions to construct the conntrack query.
struct NlMsgBuilder {
    /// Internal byte buffer holding the message under construction.
    buf: Vec<u8>,
}

impl NlMsgBuilder {
    /// Create a new builder with pre-allocated capacity.
    fn new() -> Self {
        Self {
            buf: Vec::with_capacity(256),
        }
    }

    /// Pad the buffer to 4-byte alignment with zero bytes.
    fn pad_to_alignment(&mut self) {
        while !self.buf.len().is_multiple_of(4) {
            self.buf.push(0);
        }
    }

    /// Write the netlink message header (`struct nlmsghdr`).
    ///
    /// The `nlmsg_len` field is written as a placeholder (0) and must be
    /// finalised by calling [`Self::finalize()`] after the complete message
    /// is built.
    ///
    /// Wire format (16 bytes, native endian):
    /// ```text
    /// [0..4]   nlmsg_len   — total message length (placeholder)
    /// [4..6]   nlmsg_type  — message type
    /// [6..8]   nlmsg_flags — request flags
    /// [8..12]  nlmsg_seq   — sequence number
    /// [12..16] nlmsg_pid   — sender port ID (0 = kernel-assigned)
    /// ```
    fn write_nlmsghdr(&mut self, msg_type: u16, flags: u16, seq: u32) {
        self.buf.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_len (placeholder)
        self.buf.extend_from_slice(&msg_type.to_ne_bytes()); // nlmsg_type
        self.buf.extend_from_slice(&flags.to_ne_bytes()); // nlmsg_flags
        self.buf.extend_from_slice(&seq.to_ne_bytes()); // nlmsg_seq
        self.buf.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_pid
    }

    /// Write the netfilter generic message header (`struct nfgenmsg`).
    ///
    /// Wire format (4 bytes):
    /// ```text
    /// [0]     nfgen_family — AF_INET or AF_INET6
    /// [1]     version      — NFNETLINK_V0 (0)
    /// [2..4]  res_id       — resource ID (0, big-endian)
    /// ```
    fn write_nfgenmsg(&mut self, family: u8) {
        self.buf.push(family); // nfgen_family
        self.buf.push(NFNETLINK_V0); // version
        self.buf.extend_from_slice(&0u16.to_be_bytes()); // res_id
    }

    /// Begin a nested NLA attribute.
    ///
    /// Writes a placeholder NLA header with `NLA_F_NESTED` flag set.
    /// Returns the buffer position of the NLA header so that
    /// [`Self::end_nested()`] can finalise the length.
    fn begin_nested(&mut self, nla_type: u16) -> usize {
        let pos = self.buf.len();
        self.buf.extend_from_slice(&0u16.to_ne_bytes()); // nla_len (placeholder)
        self.buf
            .extend_from_slice(&(nla_type | NLA_F_NESTED).to_ne_bytes()); // nla_type
        pos
    }

    /// Finalise a nested NLA attribute by setting its `nla_len` field.
    ///
    /// `pos` is the buffer position returned by [`Self::begin_nested()`].
    /// The length includes the NLA header (4 bytes) + all child payload.
    fn end_nested(&mut self, pos: usize) {
        let len = (self.buf.len() - pos) as u16;
        self.buf[pos..pos + 2].copy_from_slice(&len.to_ne_bytes());
        // Nested attributes are already aligned by their children, but pad
        // defensively to ensure the next sibling starts at a 4-byte boundary.
        self.pad_to_alignment();
    }

    /// Write a `u8` NLA attribute.
    ///
    /// Wire format: NLA header (4 bytes) + 1 byte payload + 3 bytes padding.
    fn write_u8_attr(&mut self, nla_type: u16, value: u8) {
        let len: u16 = NLA_HDRLEN as u16 + 1;
        self.buf.extend_from_slice(&len.to_ne_bytes()); // nla_len
        self.buf.extend_from_slice(&nla_type.to_ne_bytes()); // nla_type
        self.buf.push(value); // payload
        self.pad_to_alignment(); // pad to 4 bytes
    }

    /// Write a `u16` NLA attribute in big-endian (network byte order).
    ///
    /// Used for port numbers which are stored in network byte order
    /// in conntrack attributes. Matches C's `nfct_set_attr_u16()` which
    /// stores `htons(port)` for `ATTR_PORT_SRC` / `ATTR_PORT_DST`.
    ///
    /// Wire format: NLA header (4 bytes) + 2 bytes payload + 2 bytes padding.
    fn write_u16_be_attr(&mut self, nla_type: u16, value: u16) {
        let len: u16 = NLA_HDRLEN as u16 + 2;
        self.buf.extend_from_slice(&len.to_ne_bytes()); // nla_len
        self.buf.extend_from_slice(&nla_type.to_ne_bytes()); // nla_type
        self.buf.extend_from_slice(&value.to_be_bytes()); // payload (big-endian)
        self.pad_to_alignment(); // pad to 4 bytes
    }

    /// Write an IPv4 address NLA attribute (4 bytes, network byte order).
    ///
    /// Matches C's `nfct_set_attr_u32(ct, ATTR_IPV4_SRC, addr.s_addr)` where
    /// `s_addr` is already in network byte order. `Ipv4Addr::octets()` returns
    /// bytes in network byte order (big-endian).
    ///
    /// Wire format: NLA header (4 bytes) + 4 bytes payload (no padding needed).
    fn write_ipv4_attr(&mut self, nla_type: u16, addr: &Ipv4Addr) {
        let len: u16 = NLA_HDRLEN as u16 + 4;
        self.buf.extend_from_slice(&len.to_ne_bytes()); // nla_len
        self.buf.extend_from_slice(&nla_type.to_ne_bytes()); // nla_type
        self.buf.extend_from_slice(&addr.octets()); // payload (4 bytes, network order)
                                                    // 4 + 4 = 8 bytes, already 4-byte aligned
    }

    /// Write an IPv6 address NLA attribute (16 bytes, network byte order).
    ///
    /// Matches C's `nfct_set_attr(ct, ATTR_IPV6_SRC, addr.s6_addr)` where
    /// the address bytes are in network byte order. `Ipv6Addr::octets()`
    /// returns bytes in network byte order (big-endian).
    ///
    /// Wire format: NLA header (4 bytes) + 16 bytes payload (no padding needed).
    fn write_ipv6_attr(&mut self, nla_type: u16, addr: &Ipv6Addr) {
        let len: u16 = NLA_HDRLEN as u16 + 16;
        self.buf.extend_from_slice(&len.to_ne_bytes()); // nla_len
        self.buf.extend_from_slice(&nla_type.to_ne_bytes()); // nla_type
        self.buf.extend_from_slice(&addr.octets()); // payload (16 bytes, network order)
                                                    // 4 + 16 = 20 bytes, already 4-byte aligned
    }

    /// Finalise the message by setting `nlmsg_len` to the total buffer size.
    ///
    /// Must be called exactly once after all attributes have been written.
    /// Returns the complete netlink message as a byte vector.
    fn finalize(mut self) -> Vec<u8> {
        let len = self.buf.len() as u32;
        self.buf[0..4].copy_from_slice(&len.to_ne_bytes());
        self.buf
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Query the Linux netfilter conntrack table for the connection mark
/// associated with an incoming DNS query.
///
/// Constructs a connection 5-tuple (source IP, source port, destination IP,
/// destination port, L4 protocol) from the provided addresses, queries the
/// kernel conntrack table for a matching established connection, and returns
/// the connection's `ATTR_MARK` value.
///
/// # Arguments
///
/// * `peer_addr` — Remote peer's socket address (source IP + port).
///   `MySockAddr::V4` for IPv4, `MySockAddr::V6` for IPv6.
/// * `local_addr` — Local DNS server address (destination IP).
///   Must match the address family of `peer_addr`.
/// * `is_tcp` — `true` for TCP connections (`IPPROTO_TCP`),
///   `false` for UDP (`IPPROTO_UDP`).
/// * `dns_port` — Local DNS listening port (typically 53).
///   Passed as host byte order; converted to network byte order internally.
///
/// # Returns
///
/// * `Ok(mark)` — The `u32` connection tracking mark from the matched entry.
/// * `Err(ConntrackError::CreateFailed)` — Address family mismatch or message
///   construction failure.
/// * `Err(ConntrackError::OpenFailed)` — Failed to open netlink socket.
/// * `Err(ConntrackError::QueryFailed)` — Kernel query failed (first failure
///   is logged via `tracing::error!`, subsequent failures are silent).
/// * `Err(ConntrackError::NoMatch)` — No matching conntrack entry found.
///
/// # Example
///
/// ```rust,no_run
/// use std::net::{Ipv4Addr, SocketAddrV4};
/// use dnsmasq::core::types::{MySockAddr, AllAddr};
/// use dnsmasq::integration::conntrack::get_incoming_mark;
///
/// let peer = MySockAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 12345));
/// let local = AllAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
/// match get_incoming_mark(&peer, &local, false, 53) {
///     Ok(mark) => println!("Connection mark: {}", mark),
///     Err(e) => eprintln!("Conntrack query failed: {}", e),
/// }
/// ```
///
/// # Linux Requirements
///
/// - Kernel with `CONFIG_NF_CONNTRACK` enabled
/// - `nf_conntrack` module loaded
/// - `CAP_NET_ADMIN` capability or root privileges
pub fn get_incoming_mark(
    peer_addr: &MySockAddr,
    local_addr: &AllAddr,
    is_tcp: bool,
    dns_port: u16,
) -> Result<u32, ConntrackError> {
    let result = query_conntrack_mark(peer_addr, local_addr, is_tcp, dns_port);

    // Implement the "warn once" pattern from C (conntrack.c lines 254-259):
    //   static int warned = 0;
    //   if (!warned) { my_syslog(LOG_ERR, ...); warned = 1; }
    //
    // Only log the FIRST query failure to prevent syslog spam when the
    // conntrack subsystem is persistently unavailable.
    if let Err(ConntrackError::QueryFailed(ref msg)) = result {
        if !WARNED.swap(true, Ordering::Relaxed) {
            error!("Conntrack connection mark retrieval failed: {}", msg);
        }
    }

    result
}

// ---------------------------------------------------------------------------
// Internal Implementation
// ---------------------------------------------------------------------------

/// Perform the actual conntrack mark query via raw netlink.
///
/// This is the internal implementation called by [`get_incoming_mark()`].
/// Separated to keep the warn-once logging logic distinct from the query logic.
///
/// Replaces C's `get_incoming_mark()` body (conntrack.c lines 221-267):
/// 1. `nfct_new()` + `nfct_set_attr_*()` → [`build_ct_get_message()`]
/// 2. `nfct_open()` → `nix::sys::socket::socket()` + `bind()`
/// 3. `nfct_query()` → `sendto()` + `recvfrom()`
/// 4. `callback()` mark extraction → [`parse_ct_response()`]
/// 5. `nfct_destroy()` + `nfct_close()` → `OwnedFd` RAII drop
fn query_conntrack_mark(
    peer_addr: &MySockAddr,
    local_addr: &AllAddr,
    is_tcp: bool,
    dns_port: u16,
) -> Result<u32, ConntrackError> {
    // Step 1: Build the conntrack GET netlink message (replaces nfct_new + nfct_set_attr_*)
    let msg = build_ct_get_message(peer_addr, local_addr, is_tcp, dns_port)?;

    // Step 2: Open a NETLINK_NETFILTER socket (replaces nfct_open)
    // The returned OwnedFd provides RAII cleanup — the socket is automatically
    // closed when `fd` goes out of scope, replacing C's nfct_close().
    let fd = socket(
        AddressFamily::Netlink,
        SockType::Raw,
        SockFlag::SOCK_CLOEXEC,
        SockProtocol::NetlinkNetFilter,
    )
    .map_err(|e| ConntrackError::OpenFailed(e.to_string()))?;

    // Bind to a local netlink address (pid=0 lets the kernel assign,
    // groups=0 means no multicast subscriptions).
    let local_nl_addr = NetlinkAddr::new(0, 0);
    bind(fd.as_raw_fd(), &local_nl_addr).map_err(|e| ConntrackError::OpenFailed(e.to_string()))?;

    // Step 3: Send the query to the kernel (replaces nfct_query)
    let kernel_addr = NetlinkAddr::new(0, 0); // pid=0 = kernel
    sendto(fd.as_raw_fd(), &msg, &kernel_addr, MsgFlags::empty())
        .map_err(|e| ConntrackError::QueryFailed(e.to_string()))?;

    // Step 4: Receive the response (replaces nfct_query callback mechanism)
    let mut buf = [0u8; RECV_BUF_SIZE];
    let (n, _sender) = recvfrom::<NetlinkAddr>(fd.as_raw_fd(), &mut buf)
        .map_err(|e| ConntrackError::QueryFailed(e.to_string()))?;

    if n == 0 {
        return Err(ConntrackError::QueryFailed(
            "Empty response from kernel".to_string(),
        ));
    }

    // Step 5: Parse the response and extract CTA_MARK (replaces callback())
    // The OwnedFd is dropped here, closing the socket (replaces nfct_close + nfct_destroy).
    parse_ct_response(&buf[..n])
}

/// Build a `NFNL_SUBSYS_CTNETLINK` / `IPCTNL_MSG_CT_GET` netlink message.
///
/// Constructs the complete netlink message containing the connection 5-tuple
/// for querying the conntrack table. The message format matches what
/// `libnetfilter_conntrack`'s `nfct_query(h, NFCT_Q_GET, ct)` sends internally.
///
/// ## Message Structure
///
/// ```text
/// nlmsghdr (16 bytes)
///   nlmsg_type = (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_GET
///   nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK
/// nfgenmsg (4 bytes)
///   nfgen_family = AF_INET or AF_INET6
/// CTA_TUPLE_ORIG (nested)
///   CTA_TUPLE_IP (nested)
///     CTA_IP_V4_SRC / CTA_IP_V6_SRC (source IP)
///     CTA_IP_V4_DST / CTA_IP_V6_DST (destination IP)
///   CTA_TUPLE_PROTO (nested)
///     CTA_PROTO_NUM (TCP or UDP)
///     CTA_PROTO_SRC_PORT (peer port)
///     CTA_PROTO_DST_PORT (DNS port)
/// ```
fn build_ct_get_message(
    peer_addr: &MySockAddr,
    local_addr: &AllAddr,
    is_tcp: bool,
    dns_port: u16,
) -> Result<Vec<u8>, ConntrackError> {
    // Determine address family and extract addresses/ports, matching C's
    // peer_addr->sa.sa_family check at conntrack.c line 233.
    let (af, src_port) = match peer_addr {
        MySockAddr::V4(sa) => (libc::AF_INET as u8, sa.port()),
        MySockAddr::V6(sa) => (libc::AF_INET6 as u8, sa.port()),
    };

    // Determine L4 protocol (conntrack.c line 230: IPPROTO_TCP or IPPROTO_UDP)
    let l4_proto: u8 = if is_tcp {
        libc::IPPROTO_TCP as u8
    } else {
        libc::IPPROTO_UDP as u8
    };

    // Construct the netlink message type:
    // (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_GET
    let msg_type = (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_GET;

    let mut builder = NlMsgBuilder::new();

    // Write netlink message header
    builder.write_nlmsghdr(msg_type, NLM_F_REQUEST | NLM_F_ACK, 1);

    // Write netfilter generic message header
    builder.write_nfgenmsg(af);

    // --- CTA_TUPLE_ORIG (nested) ---
    let tuple_orig_pos = builder.begin_nested(CTA_TUPLE_ORIG);

    // --- CTA_TUPLE_IP (nested) ---
    let tuple_ip_pos = builder.begin_nested(CTA_TUPLE_IP);

    match (peer_addr, local_addr) {
        // IPv4 tuple construction (conntrack.c lines 241-245)
        (MySockAddr::V4(sa), AllAddr::V4(dst_addr)) => {
            // ATTR_IPV4_SRC = peer_addr->in.sin_addr.s_addr
            builder.write_ipv4_attr(CTA_IP_V4_SRC, sa.ip());
            // ATTR_IPV4_DST = local_addr->addr4.s_addr
            builder.write_ipv4_attr(CTA_IP_V4_DST, dst_addr);
        }

        // IPv6 tuple construction (conntrack.c lines 234-238)
        (MySockAddr::V6(sa), AllAddr::V6(dst_addr)) => {
            // ATTR_IPV6_SRC = peer_addr->in6.sin6_addr.s6_addr
            builder.write_ipv6_attr(CTA_IP_V6_SRC, sa.ip());
            // ATTR_IPV6_DST = local_addr->addr6.s6_addr
            builder.write_ipv6_attr(CTA_IP_V6_DST, dst_addr);
        }

        // Address family mismatch — peer is IPv4 but local is IPv6 or vice versa.
        // This should never happen in normal operation, but we handle it gracefully.
        _ => {
            return Err(ConntrackError::CreateFailed(
                "Address family mismatch between peer and local address, \
                 or unsupported AllAddr variant for conntrack query"
                    .to_string(),
            ));
        }
    }

    builder.end_nested(tuple_ip_pos);

    // --- CTA_TUPLE_PROTO (nested) ---
    let tuple_proto_pos = builder.begin_nested(CTA_TUPLE_PROTO);

    // ATTR_L4PROTO (conntrack.c line 230)
    builder.write_u8_attr(CTA_PROTO_NUM, l4_proto);

    // ATTR_PORT_SRC = peer_addr->in.sin_port (conntrack.c line 244)
    // C stores sin_port in network byte order; Rust SocketAddrV4::port() returns
    // host byte order. write_u16_be_attr converts to network byte order.
    builder.write_u16_be_attr(CTA_PROTO_SRC_PORT, src_port);

    // ATTR_PORT_DST = htons(daemon->port) (conntrack.c line 231)
    // dns_port is in host byte order; convert to network byte order.
    builder.write_u16_be_attr(CTA_PROTO_DST_PORT, dns_port);

    builder.end_nested(tuple_proto_pos);

    builder.end_nested(tuple_orig_pos);

    Ok(builder.finalize())
}

/// Parse the kernel's netlink response and extract the `CTA_MARK` attribute.
///
/// The kernel responds to `IPCTNL_MSG_CT_GET` with either:
/// - A `CT_NEW` message containing the conntrack entry (if found), followed
///   by an ACK (`NLMSG_ERROR` with `error == 0`).
/// - An `NLMSG_ERROR` with a negative error code (if not found or error):
///   - `-ENOENT` → no matching conntrack entry.
///   - Other → kernel-level failure.
///
/// This function iterates through all netlink messages in the buffer to handle
/// both single-message and multi-message responses.
///
/// Replaces C's `callback()` function (conntrack.c lines 314-322) which was
/// invoked by `nfct_query()` on match, extracting `ATTR_MARK` via
/// `nfct_get_attr_u32(ct, ATTR_MARK)`.
fn parse_ct_response(data: &[u8]) -> Result<u32, ConntrackError> {
    let ct_new_type: u16 = (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_NEW;
    let mut offset: usize = 0;

    // Iterate through netlink messages in the response buffer.
    // Multiple messages may be present (e.g., CT entry + ACK).
    while offset + NLMSG_HDRLEN <= data.len() {
        let msg_data = &data[offset..];

        // Parse nlmsghdr fields (native byte order)
        let nlmsg_len = u32::from_ne_bytes(msg_data[0..4].try_into().unwrap_or([0; 4])) as usize;
        let nlmsg_type = u16::from_ne_bytes(msg_data[4..6].try_into().unwrap_or([0; 2]));

        // Validate message length
        if nlmsg_len < NLMSG_HDRLEN || offset + nlmsg_len > data.len() {
            break;
        }

        if nlmsg_type == NLMSG_ERROR {
            // Parse the error code from the nlmsgerr structure.
            // struct nlmsgerr { int error; struct nlmsghdr msg; }
            if nlmsg_len >= NLMSG_HDRLEN + 4 {
                let error_code = i32::from_ne_bytes(
                    msg_data[NLMSG_HDRLEN..NLMSG_HDRLEN + 4]
                        .try_into()
                        .unwrap_or([0; 4]),
                );

                if error_code == 0 {
                    // ACK (error_code == 0): this is a success acknowledgement.
                    // The actual CT data should be in a preceding message.
                    // Continue scanning for the CT_NEW message.
                } else {
                    // Negative error code → kernel error.
                    let errno = -error_code;
                    if errno == libc::ENOENT {
                        return Err(ConntrackError::NoMatch);
                    }
                    return Err(ConntrackError::QueryFailed(format!(
                        "Kernel returned error: {}",
                        std::io::Error::from_raw_os_error(errno)
                    )));
                }
            }
        } else if nlmsg_type == ct_new_type {
            // This is the conntrack entry response. Parse attributes for CTA_MARK.
            let attr_start = NLMSG_HDRLEN + NFGENMSG_LEN;
            if attr_start <= nlmsg_len {
                let attr_data = &msg_data[attr_start..nlmsg_len];
                return find_mark_in_attrs(attr_data);
            }
        }
        // Skip other message types (e.g., NLMSG_DONE)

        // Advance to next message, aligned to 4-byte boundary
        offset += nla_align(nlmsg_len);
    }

    // No matching CT_NEW message found in the response
    Err(ConntrackError::NoMatch)
}

/// Search top-level netlink attributes for `CTA_MARK` and extract its value.
///
/// Iterates through the NLA attribute list at the top level of a `CT_NEW`
/// response message. The `CTA_MARK` attribute contains the connection tracking
/// mark as a `u32` in big-endian (network byte order) — the kernel encodes it
/// via `nla_put_be32(skb, CTA_MARK, htonl(ct->mark))`.
///
/// This replaces C's `callback()` function body:
/// ```c
/// *ret = nfct_get_attr_u32(ct, ATTR_MARK);
/// gotit = 1;
/// ```
fn find_mark_in_attrs(data: &[u8]) -> Result<u32, ConntrackError> {
    let mut offset: usize = 0;

    while offset + NLA_HDRLEN <= data.len() {
        // Parse NLA header (native byte order)
        let nla_len =
            u16::from_ne_bytes(data[offset..offset + 2].try_into().unwrap_or([0; 2])) as usize;
        let nla_type =
            u16::from_ne_bytes(data[offset + 2..offset + 4].try_into().unwrap_or([0; 2]));

        // Validate attribute length
        if nla_len < NLA_HDRLEN || offset + nla_len > data.len() {
            break;
        }

        // Strip NLA_F_NESTED flag for type comparison
        let attr_type = nla_type & !NLA_F_NESTED;

        // Check for CTA_MARK (u32, big-endian in the kernel's wire format)
        if attr_type == CTA_MARK && nla_len >= NLA_HDRLEN + 4 {
            // The kernel encodes the mark via nla_put_be32(), so it is in
            // big-endian (network byte order). Convert to host byte order.
            let mark = u32::from_be_bytes(
                data[offset + NLA_HDRLEN..offset + NLA_HDRLEN + 4]
                    .try_into()
                    .unwrap_or([0; 4]),
            );
            return Ok(mark);
        }

        // Advance to next attribute, aligned to 4-byte boundary
        offset += nla_align(nla_len);
    }

    // CTA_MARK not found in the attribute list — the conntrack entry exists
    // but has no mark set (mark == 0 by default).
    // Return 0 as the default mark, matching C behaviour where an unmarked
    // connection would have mark == 0.
    Ok(0)
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::field_reassign_with_default,
    clippy::needless_borrows_for_generic_args,
    clippy::unnecessary_cast,
    clippy::assertions_on_constants,
    clippy::len_zero,
    clippy::vec_init_then_push,
    clippy::unchecked_duration_subtraction,
    clippy::manual_string_new,
    clippy::cloned_ref_to_slice_refs,
    clippy::manual_range_contains,
    clippy::trim_split_whitespace,
    clippy::identity_op,
    clippy::io_other_error,
    clippy::useless_vec,
    clippy::const_is_empty,
    clippy::clone_on_copy,
    clippy::absurd_extreme_comparisons,
    clippy::overly_complex_bool_expr,
    clippy::write_literal,
    clippy::int_plus_one,
    clippy::write_with_newline,
    clippy::float_cmp,
    clippy::double_comparisons,
    clippy::large_stack_arrays,
    clippy::writeln_empty_string,
    unused_comparisons,
    unused_mut,
    unused_variables
)]
mod tests {
    use super::*;
    use crate::core::types::DnsmasqResult;
    use std::net::SocketAddrV4;

    /// Verify that `nla_align` correctly aligns values to 4-byte boundaries.
    #[test]
    fn test_nla_align() {
        assert_eq!(nla_align(0), 0);
        assert_eq!(nla_align(1), 4);
        assert_eq!(nla_align(2), 4);
        assert_eq!(nla_align(3), 4);
        assert_eq!(nla_align(4), 4);
        assert_eq!(nla_align(5), 8);
        assert_eq!(nla_align(16), 16);
        assert_eq!(nla_align(17), 20);
    }

    /// Verify that `NlMsgBuilder` produces correctly formatted messages.
    #[test]
    fn test_nlmsg_builder_basic() {
        let mut builder = NlMsgBuilder::new();
        builder.write_nlmsghdr(257, NLM_F_REQUEST | NLM_F_ACK, 42);
        builder.write_nfgenmsg(libc::AF_INET as u8);
        let msg = builder.finalize();

        // Total length = 16 (nlmsghdr) + 4 (nfgenmsg) = 20
        assert_eq!(msg.len(), 20);

        // Verify nlmsg_len
        let nlmsg_len = u32::from_ne_bytes(msg[0..4].try_into().unwrap());
        assert_eq!(nlmsg_len, 20);

        // Verify nlmsg_type
        let nlmsg_type = u16::from_ne_bytes(msg[4..6].try_into().unwrap());
        assert_eq!(nlmsg_type, 257); // (1 << 8) | 1

        // Verify nlmsg_flags
        let nlmsg_flags = u16::from_ne_bytes(msg[6..8].try_into().unwrap());
        assert_eq!(nlmsg_flags, NLM_F_REQUEST | NLM_F_ACK);

        // Verify nlmsg_seq
        let nlmsg_seq = u32::from_ne_bytes(msg[8..12].try_into().unwrap());
        assert_eq!(nlmsg_seq, 42);

        // Verify nfgen_family
        assert_eq!(msg[16], libc::AF_INET as u8);

        // Verify version
        assert_eq!(msg[17], NFNETLINK_V0);
    }

    /// Verify that u8 attributes are correctly padded.
    #[test]
    fn test_u8_attr_padding() {
        let mut builder = NlMsgBuilder::new();
        builder.write_nlmsghdr(0, 0, 0);
        builder.write_nfgenmsg(0);
        builder.write_u8_attr(CTA_PROTO_NUM, libc::IPPROTO_UDP as u8);
        let msg = builder.finalize();

        // 16 (hdr) + 4 (nfgenmsg) + 4 (nla hdr) + 1 (payload) + 3 (pad) = 28
        assert_eq!(msg.len(), 28);

        // Verify NLA length (4 + 1 = 5)
        let nla_len = u16::from_ne_bytes(msg[20..22].try_into().unwrap());
        assert_eq!(nla_len, 5);
    }

    /// Verify that u16 big-endian attributes are correctly formatted.
    #[test]
    fn test_u16_be_attr() {
        let mut builder = NlMsgBuilder::new();
        builder.write_nlmsghdr(0, 0, 0);
        builder.write_nfgenmsg(0);
        builder.write_u16_be_attr(CTA_PROTO_DST_PORT, 53);
        let msg = builder.finalize();

        // 16 + 4 + 4 (nla hdr) + 2 (payload) + 2 (pad) = 28
        assert_eq!(msg.len(), 28);

        // Verify port is in big-endian: 53 = 0x0035
        assert_eq!(msg[24], 0x00);
        assert_eq!(msg[25], 0x35);
    }

    /// Verify IPv4 address attributes.
    #[test]
    fn test_ipv4_attr() {
        let mut builder = NlMsgBuilder::new();
        builder.write_nlmsghdr(0, 0, 0);
        builder.write_nfgenmsg(0);
        builder.write_ipv4_attr(CTA_IP_V4_SRC, &Ipv4Addr::new(192, 168, 1, 100));
        let msg = builder.finalize();

        // 16 + 4 + 4 (nla hdr) + 4 (addr) = 28
        assert_eq!(msg.len(), 28);

        // Verify address bytes
        assert_eq!(&msg[24..28], &[192, 168, 1, 100]);
    }

    /// Verify that `build_ct_get_message` produces a valid IPv4 message.
    #[test]
    fn test_build_ipv4_message() {
        let peer = MySockAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 12345));
        let local = AllAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        let msg = build_ct_get_message(&peer, &local, false, 53).unwrap();

        // Verify basic structure
        assert!(msg.len() > NLMSG_HDRLEN + NFGENMSG_LEN);

        // Verify nlmsg_type = (1 << 8) | 1 = 257
        let nlmsg_type = u16::from_ne_bytes(msg[4..6].try_into().unwrap());
        assert_eq!(nlmsg_type, 257);

        // Verify nfgen_family = AF_INET
        assert_eq!(msg[16], libc::AF_INET as u8);
    }

    /// Verify that address family mismatch returns CreateFailed.
    #[test]
    fn test_address_family_mismatch() {
        let peer = MySockAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1234));
        let local = AllAddr::V6(Ipv6Addr::LOCALHOST);

        let result = build_ct_get_message(&peer, &local, false, 53);
        assert!(matches!(result, Err(ConntrackError::CreateFailed(_))));
    }

    /// Verify that `parse_ct_response` handles NLMSG_ERROR with ENOENT.
    #[test]
    fn test_parse_enoent_response() {
        let mut buf = vec![0u8; 36]; // nlmsghdr (16) + error (4) + original nlmsghdr (16)

        // nlmsg_len = 36
        buf[0..4].copy_from_slice(&36u32.to_ne_bytes());
        // nlmsg_type = NLMSG_ERROR
        buf[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
        // nlmsg_flags = 0
        // nlmsg_seq = 1
        buf[8..12].copy_from_slice(&1u32.to_ne_bytes());
        // error = -ENOENT
        let neg_enoent = -(libc::ENOENT as i32);
        buf[16..20].copy_from_slice(&neg_enoent.to_ne_bytes());

        let result = parse_ct_response(&buf);
        assert!(matches!(result, Err(ConntrackError::NoMatch)));
    }

    /// Verify that `parse_ct_response` handles ACK (error == 0) without CT data.
    #[test]
    fn test_parse_ack_only_response() {
        let mut buf = vec![0u8; 36];

        // nlmsg_len = 36
        buf[0..4].copy_from_slice(&36u32.to_ne_bytes());
        // nlmsg_type = NLMSG_ERROR
        buf[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
        // error = 0 (ACK)
        buf[16..20].copy_from_slice(&0i32.to_ne_bytes());

        let result = parse_ct_response(&buf);
        // No CT_NEW message, so NoMatch
        assert!(matches!(result, Err(ConntrackError::NoMatch)));
    }

    /// Verify that `find_mark_in_attrs` extracts CTA_MARK correctly.
    #[test]
    fn test_find_mark_in_attrs() {
        // Build a fake attribute list with CTA_MARK = 42
        let mut attrs = Vec::new();

        // First, a dummy attribute (CTA_TUPLE_ORIG, nested, 8 bytes total)
        let dummy_len: u16 = 8;
        attrs.extend_from_slice(&dummy_len.to_ne_bytes()); // nla_len
        attrs.extend_from_slice(&(CTA_TUPLE_ORIG | NLA_F_NESTED).to_ne_bytes()); // nla_type
        attrs.extend_from_slice(&[0u8; 4]); // dummy nested content

        // CTA_MARK attribute: nla_len = 8, nla_type = 8, value = 42 (big-endian)
        let mark_len: u16 = NLA_HDRLEN as u16 + 4;
        attrs.extend_from_slice(&mark_len.to_ne_bytes()); // nla_len = 8
        attrs.extend_from_slice(&CTA_MARK.to_ne_bytes()); // nla_type = 8
        attrs.extend_from_slice(&42u32.to_be_bytes()); // mark value (big-endian)

        let result = find_mark_in_attrs(&attrs).unwrap();
        assert_eq!(result, 42);
    }

    /// Verify that `find_mark_in_attrs` returns 0 when no CTA_MARK is present.
    #[test]
    fn test_find_mark_in_attrs_missing() {
        // Build an attribute list without CTA_MARK
        let mut attrs = Vec::new();

        // A dummy attribute (e.g., CTA_TUPLE_ORIG)
        let dummy_len: u16 = 8;
        attrs.extend_from_slice(&dummy_len.to_ne_bytes());
        attrs.extend_from_slice(&(CTA_TUPLE_ORIG | NLA_F_NESTED).to_ne_bytes());
        attrs.extend_from_slice(&[0u8; 4]);

        // No CTA_MARK → should return 0 (default mark)
        let result = find_mark_in_attrs(&attrs).unwrap();
        assert_eq!(result, 0);
    }

    /// Verify that `ConntrackError` Display formatting works correctly.
    #[test]
    fn test_error_display() {
        let err = ConntrackError::NoMatch;
        assert_eq!(format!("{}", err), "No matching conntrack entry found");

        let err = ConntrackError::CreateFailed("test".to_string());
        assert_eq!(format!("{}", err), "Failed to create conntrack entry: test");

        let err = ConntrackError::OpenFailed("test".to_string());
        assert_eq!(format!("{}", err), "Failed to open conntrack handle: test");

        let err = ConntrackError::QueryFailed("test".to_string());
        assert_eq!(format!("{}", err), "Conntrack query failed: test");
    }

    /// Verify conversion from ConntrackError to DnsmasqError via DnsmasqResult.
    #[test]
    fn test_conntrack_to_dnsmasq_error() {
        let ct_err = ConntrackError::NoMatch;
        // Use DnsmasqResult type alias to demonstrate the From trait conversion
        let result: DnsmasqResult<u32> = Err(ct_err.into());
        match result {
            Err(DnsmasqError::Network(msg)) => {
                assert!(msg.contains("No matching conntrack entry"));
            }
            other => panic!("Expected Err(Network) variant, got: {:?}", other),
        }
    }

    /// Verify a complete CT_NEW + ACK multi-message response is parsed.
    #[test]
    fn test_parse_ct_new_with_ack() {
        let ct_new_type: u16 = (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_NEW;
        let mut buf = Vec::new();

        // --- Message 1: CT_NEW with CTA_MARK = 99 ---
        let ct_msg_start = buf.len();

        // nlmsghdr placeholder
        buf.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_len (placeholder)
        buf.extend_from_slice(&ct_new_type.to_ne_bytes()); // nlmsg_type
        buf.extend_from_slice(&0u16.to_ne_bytes()); // nlmsg_flags
        buf.extend_from_slice(&1u32.to_ne_bytes()); // nlmsg_seq
        buf.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_pid

        // nfgenmsg
        buf.push(libc::AF_INET as u8); // nfgen_family
        buf.push(0); // version
        buf.extend_from_slice(&0u16.to_be_bytes()); // res_id

        // CTA_MARK attribute
        let mark_nla_len: u16 = NLA_HDRLEN as u16 + 4;
        buf.extend_from_slice(&mark_nla_len.to_ne_bytes());
        buf.extend_from_slice(&CTA_MARK.to_ne_bytes());
        buf.extend_from_slice(&99u32.to_be_bytes());

        // Fix nlmsg_len for CT_NEW
        let ct_msg_len = (buf.len() - ct_msg_start) as u32;
        buf[ct_msg_start..ct_msg_start + 4].copy_from_slice(&ct_msg_len.to_ne_bytes());

        // --- Message 2: ACK (NLMSG_ERROR with error=0) ---
        let ack_start = buf.len();
        let ack_len: u32 = 36; // 16 (hdr) + 4 (error) + 16 (original hdr)
        buf.extend_from_slice(&ack_len.to_ne_bytes()); // nlmsg_len
        buf.extend_from_slice(&NLMSG_ERROR.to_ne_bytes()); // nlmsg_type
        buf.extend_from_slice(&0u16.to_ne_bytes()); // nlmsg_flags
        buf.extend_from_slice(&1u32.to_ne_bytes()); // nlmsg_seq
        buf.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_pid
        buf.extend_from_slice(&0i32.to_ne_bytes()); // error = 0 (ACK)
        buf.resize(ack_start + ack_len as usize, 0); // pad remaining

        let result = parse_ct_response(&buf).unwrap();
        assert_eq!(result, 99);
    }
}

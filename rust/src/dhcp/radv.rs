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

//! # IPv6 Router Advertisement Construction and Dispatch
//!
//! Rust implementation of IPv6 Router Advertisement (RA) functionality,
//! replacing C `src/radv.c` (2,175 lines) and incorporating protocol
//! constants from `src/radv-protocol.h` (869 lines).
//!
//! This module constructs and transmits ICMPv6 Router Advertisement
//! messages (type 134) per [RFC 4861](https://tools.ietf.org/html/rfc4861)
//! for IPv6 Stateless Address Autoconfiguration (SLAAC). It coordinates
//! with the DHCPv6 subsystem for Managed (M) and Other (O) flag control,
//! determining whether hosts should use SLAAC alone or also consult DHCPv6.
//!
//! ## Key Responsibilities
//!
//! - **Periodic RA transmission**: Send unsolicited RAs at configurable
//!   intervals per RFC 4861 §6.2.4 (default 600s, range 4–1800s).
//! - **Solicited RA response**: Reply to Router Solicitation (type 133)
//!   messages with immediate RA.
//! - **Prefix Information Options (PIO)**: Advertise on-link prefixes with
//!   valid/preferred lifetimes from DHCPv6 context configuration.
//! - **RDNSS/DNSSL options (RFC 6106)**: Advertise recursive DNS servers
//!   and DNS search domains.
//! - **M/O flag coordination**: Set Managed/Other flags based on whether
//!   DHCPv6 is configured alongside SLAAC for the prefix.
//! - **Bridge alias support**: Send RAs on bridge member interfaces
//!   for transparent bridging setups.
//! - **SLAAC ping integration**: Forward ICMPv6 Echo Reply to SLAAC
//!   subsystem for Duplicate Address Detection confirmation.
//!
//! ## C Source Mapping
//!
//! - `ra_init()` → `pub fn ra_init()` (C radv.c line 336)
//! - `icmp6_packet()` → `pub fn icmp6_packet()` (C radv.c line 504)
//! - `send_ra()`/`send_ra_alias()` → `pub fn send_ra()` (C radv.c lines 702/1056)
//! - `periodic_ra()` → `pub fn periodic_ra()` (C radv.c line 1850)
//! - `ra_start_unsolicited()` → `pub fn ra_start_unsolicited()` (C radv.c line 425)

use std::net::Ipv6Addr;
use std::os::unix::io::RawFd;
use std::sync::Mutex;

use tracing::{debug, info, warn};

use crate::core::pattern::glob_match;
use crate::core::types::{opt, DaemonState, DnsmasqError, DnsmasqResult};
use crate::core::util::{format_mac, is_same_net6, SurfRng};
use crate::dhcp::common::{
    CONTEXT_DEPRECATE, CONTEXT_DHCP, CONTEXT_OLD, CONTEXT_RA, CONTEXT_RA_OFF_LINK,
    CONTEXT_RA_STATELESS, CONTEXT_TEMPLATE,
};
use crate::dhcp::ip6addr::{is_link_local_zero, is_ula, is_ula_zero};
use crate::dhcp::slaac::slaac_ping_reply;
use crate::dhcp::v6::outpacket::OutPacket;
use crate::network::interface::iface_check;

// ============================================================================
// Linux-specific socket option constants not exported by the `libc` crate.
// ============================================================================

/// ICMP6_FILTER socket option number for IPPROTO_ICMPV6 level.
/// Defined in <netinet/icmp6.h> as 1 on Linux.
const ICMP6_FILTER_OPT: libc::c_int = 1;

/// IPV6_JOIN_GROUP socket option for joining an IPv6 multicast group.
/// Defined in <bits/in.h> as 20 on Linux.
const IPV6_JOIN_GROUP_OPT: libc::c_int = 20;

// ============================================================================
// ICMPv6 Neighbor Discovery Protocol Constants (from radv-protocol.h)
// ============================================================================

/// ICMPv6 Router Solicitation message type (RFC 4861 §4.1).
pub const ICMP6_ROUTER_SOLICIT: u8 = 133;

/// ICMPv6 Router Advertisement message type (RFC 4861 §4.2).
pub const ICMP6_ROUTER_ADVERT: u8 = 134;

/// ICMPv6 Neighbour Solicitation message type (RFC 4861 §4.3).
pub const ICMP6_NEIGHBOUR_SOLICIT: u8 = 135;

/// ICMPv6 Neighbour Advertisement message type (RFC 4861 §4.4).
pub const ICMP6_NEIGHBOUR_ADVERT: u8 = 136;

/// ICMPv6 Echo Reply message type (RFC 4443 §4.2).
pub const ICMP6_ECHO_REPLY: u8 = 129;

/// Neighbor Discovery Option: Source Link-Layer Address (RFC 4861 §4.6.1).
pub const ND_OPT_SOURCE_LLA: u8 = 1;

/// Neighbor Discovery Option: Prefix Information (RFC 4861 §4.6.2).
pub const ND_OPT_PREFIX: u8 = 3;

/// Neighbor Discovery Option: MTU (RFC 4861 §4.6.4).
pub const ND_OPT_MTU: u8 = 5;

/// Neighbor Discovery Option: Advertisement Interval (RFC 6275 §7.3).
const ND_OPT_ADV_INTERVAL: u8 = 7;

/// Neighbor Discovery Option: Recursive DNS Server (RFC 6106 §5.1).
pub const ND_OPT_RDNSS: u8 = 25;

/// Neighbor Discovery Option: DNS Search List (RFC 6106 §5.2).
pub const ND_OPT_DNSSL: u8 = 31;

/// RA flag: Managed Address Configuration (M flag, RFC 4861 §4.2).
pub const ND_RA_FLAG_MANAGED: u8 = 0x80;

/// RA flag: Other Configuration (O flag, RFC 4861 §4.2).
pub const ND_RA_FLAG_OTHER: u8 = 0x40;

/// Prefix Information Option flag: On-link (L flag, RFC 4861 §4.6.2).
pub const ND_OPT_PI_FLAG_ONLINK: u8 = 0x80;

/// Prefix Information Option flag: Autonomous address-configuration
/// (A flag, RFC 4861 §4.6.2).
pub const ND_OPT_PI_FLAG_AUTO: u8 = 0x40;

/// DHCPv6 option code for DNS Recursive Name Server (RFC 3646 §3).
const OPTION6_DNS_SERVER: u16 = 23;

/// DHCPv6 option code for Domain Search List (RFC 3646 §4).
const OPTION6_DOMAIN_SEARCH: u16 = 24;

/// IPv6 all-nodes multicast address (ff02::1).
const ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);

/// IPv6 all-routers multicast address (ff02::2).
const ALL_ROUTERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2);

/// Default router advertisement interval in seconds (C: 600).
const DEFAULT_RA_INTERVAL: u32 = 600;

/// Minimum RA interval in seconds (RFC 4861 §6.2.1).
const MIN_RA_INTERVAL: u32 = 4;

/// Maximum RA interval in seconds (RFC 4861 §6.2.1).
const MAX_RA_INTERVAL: u32 = 1800;

/// Maximum RA router lifetime in seconds (RFC 4861 §6.2.1).
const MAX_RA_LIFETIME: u32 = 9000;

/// Duration of RA short-period burst after config change (seconds).
const RA_SHORT_PERIOD_DURATION: i64 = 60;

/// Minimum unsolicited RA interval during short period (seconds).
const RA_SHORT_MIN_INTERVAL: u32 = 5;

/// Maximum unsolicited RA interval during short period (seconds).
const RA_SHORT_MAX_INTERVAL: u32 = 20;

/// Maximum initial RA delay (seconds) for ra_start_unsolicited.
const RA_START_MAX_DELAY: u16 = 5;

/// RA priority: High (bits 4-3 of flags = 01).
#[allow(dead_code)]
const RA_PRIO_HIGH: u8 = 0x08;

/// RA priority: Low (bits 4-3 of flags = 11).
#[allow(dead_code)]
const RA_PRIO_LOW: u8 = 0x18;

// ============================================================================
// Packet Structures (from radv-protocol.h)
// ============================================================================

/// ICMPv6 Router Advertisement message format per RFC 4861 §4.2.
///
/// Replaces C `struct ra_packet` (radv-protocol.h lines 27–34).
/// The ICMPv6 checksum is computed by the kernel for raw sockets.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct RaPacket {
    /// ICMPv6 type — always [`ICMP6_ROUTER_ADVERT`] (134).
    pub icmp_type: u8,
    /// ICMPv6 code — always 0.
    pub icmp_code: u8,
    /// ICMPv6 checksum (computed by kernel for raw ICMPv6 sockets).
    pub checksum: u16,
    /// Current hop limit advertised to hosts (0 = unspecified).
    pub hop_limit: u8,
    /// Flags byte: bit 7 = Managed (M), bit 6 = Other (O),
    /// bits 4–3 = Router preference (00=medium, 01=high, 11=low).
    pub flags: u8,
    /// Router lifetime in seconds (network byte order).
    /// 0 means this router is not a default router.
    pub lifetime: u16,
    /// Reachable time in milliseconds (network byte order).
    /// 0 means unspecified by this router.
    pub reachable_time: u32,
    /// Retransmit timer in milliseconds (network byte order).
    /// 0 means unspecified by this router.
    pub retrans_timer: u32,
}

/// Prefix Information Option per RFC 4861 §4.6.2.
///
/// Replaces C `struct prefix_opt` (radv-protocol.h lines 43–47).
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct PrefixOpt {
    /// ND option type — always [`ND_OPT_PREFIX`] (3).
    pub opt_type: u8,
    /// Length in 8-byte units — always 4 (32 bytes).
    pub len: u8,
    /// Number of leading bits in the prefix that are valid.
    pub prefix_len: u8,
    /// Flags: bit 7 = On-link (L), bit 6 = Autonomous (A).
    pub flags: u8,
    /// Valid lifetime in seconds (network byte order).
    /// Duration the prefix is valid for on-link determination.
    pub valid_lifetime: u32,
    /// Preferred lifetime in seconds (network byte order).
    /// Duration addresses generated from the prefix remain preferred.
    pub preferred_lifetime: u32,
    /// Reserved field — must be zero.
    pub reserved: u32,
    /// IPv6 prefix (128 bits, only `prefix_len` bits are significant).
    pub prefix: [u8; 16],
}

/// ICMPv6 Echo Request/Reply packet format per RFC 4443 §4.
///
/// Replaces C `struct ping_packet` (radv-protocol.h lines 20–25).
/// Used for SLAAC Duplicate Address Detection ping handling.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct PingPacket {
    /// ICMPv6 type — 128 (Echo Request) or 129 (Echo Reply).
    pub icmp_type: u8,
    /// ICMPv6 code — always 0.
    pub icmp_code: u8,
    /// ICMPv6 checksum.
    pub checksum: u16,
    /// Identifier for matching requests to replies.
    pub identifier: u16,
    /// Sequence number for ordering.
    pub sequence_no: u16,
}

/// ICMPv6 Neighbour Solicitation/Advertisement packet format per RFC 4861 §4.3/§4.4.
///
/// Replaces C `struct neigh_packet` (radv-protocol.h lines 36–41).
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct NeighPacket {
    /// ICMPv6 type — 135 (Solicitation) or 136 (Advertisement).
    pub icmp_type: u8,
    /// ICMPv6 code — always 0.
    pub icmp_code: u8,
    /// ICMPv6 checksum.
    pub checksum: u16,
    /// Reserved/flags field (R/S/O bits for advertisement).
    pub reserved: u32,
    /// Target IPv6 address (128 bits).
    pub target: [u8; 16],
}

// ============================================================================
// Configuration Types
// ============================================================================

/// Per-interface RA configuration parameters.
///
/// Replaces C `struct ra_interface` (`dnsmasq.h` line 1263). Controls
/// per-interface RA timing, lifetime, and priority overrides.
#[derive(Debug, Clone)]
pub struct RaInterface {
    /// Interface name or wildcard pattern (e.g., "eth0" or "eth*").
    pub name: String,
    /// Advertisement interval override in seconds (0 = use default 600s).
    pub interval: u32,
    /// Router lifetime override in seconds (0 = use 3×interval).
    pub lifetime: u32,
    /// Router priority: 0 = medium (default), 1 = high, -1/0xFF = low.
    pub prio: u8,
    /// Interface name from which to read MTU via `/proc/sys/net/ipv6/conf/{name}/mtu`.
    /// If empty, reads MTU from the RA target interface itself.
    pub mtu_name: String,
}

/// RA construction parameter block — tracks state during RA packet assembly.
///
/// Replaces C `struct ra_param` (radv.c lines 29–37). Accumulates prefix
/// information, M/O flag requirements, and interface-specific configuration
/// across the callback-driven prefix enumeration.
#[derive(Debug, Clone)]
pub struct RaParam {
    /// Interface name for the RA.
    pub iface: String,
    /// OS interface index.
    pub if_index: i32,
    /// Whether Managed (M) flag should be set — at least one prefix has
    /// DHCPv6 address assignment enabled.
    pub managed: bool,
    /// Whether Other (O) flag should be set — at least one prefix has
    /// DHCPv6 information-only config.
    pub other: bool,
    /// Advertisement interval for this RA in seconds.
    pub adv_interval: u32,
    /// Router lifetime for this RA in seconds.
    pub adv_lifetime: u32,
    /// Router priority for this RA (0 = medium).
    pub prio: u8,
    /// Whether at least one prefix information option was added.
    pub found_prefix: bool,
    /// Whether at least one matching DHCPv6 context was found.
    pub found_context: bool,
}

// ============================================================================
// Internal RA Timing State
// ============================================================================

/// Per-context RA timing entry, tracking when the next RA is due.
///
/// In the C code, `ra_time` and `ra_short_period_start` are fields on
/// `struct dhcp_context`. In Rust, they are tracked separately because
/// `DhcpContextEntry` in `DaemonState` does not include RA timing fields.
#[derive(Debug, Clone)]
struct RaContextTiming {
    /// Interface index this timing entry applies to.
    if_index: i32,
    /// Prefix (network address) identifying the context.
    prefix_addr: Ipv6Addr,
    /// Prefix length for context identification.
    prefix_len: u8,
    /// Time (seconds since epoch) when the next RA should be sent.
    /// 0 means no RA is pending for this context.
    ra_time: i64,
    /// Time when the short-period RA burst started.
    /// 0 means no short-period burst is active.
    ra_short_period_start: i64,
}

/// Module-level RA timing state, keyed by (if_index, prefix) pairs.
///
/// This replaces the C pattern of storing `ra_time` and
/// `ra_short_period_start` directly in `struct dhcp_context`.
static RA_TIMING_STATE: Mutex<Vec<RaContextTiming>> = Mutex::new(Vec::new());

/// Search parameter block used during interface address enumeration
/// within `icmp6_packet` to locate the link-local address for sending.
///
/// Replaces C `struct search_param` (radv.c lines 39–42).
#[derive(Debug)]
#[allow(dead_code)]
struct SearchParam {
    /// Target interface index to match.
    if_index: i32,
    /// Discovered link-local address on the target interface.
    link_local: Option<Ipv6Addr>,
}

/// Alias parameter block for bridge member RA dispatch.
///
/// Replaces C `struct alias_param` (radv.c lines 44–50).
#[derive(Debug)]
#[allow(dead_code)]
struct AliasParam {
    /// Bridge interface index.
    bridge_iface: i32,
    /// List of discovered bridge member interface indices.
    alias_ifs: Vec<i32>,
}

/// ICMPv6 packet filter for raw socket — controls which ICMPv6 types
/// the kernel delivers to userspace.
///
/// Replaces C `struct icmp6_filter` and associated `ICMP6_FILTER_*` macros.
#[repr(C)]
struct Icmp6Filter {
    data: [u32; 8],
}

impl Icmp6Filter {
    /// Create a filter that blocks all ICMPv6 types.
    fn new_block_all() -> Self {
        Icmp6Filter {
            data: [0xFFFF_FFFF; 8],
        }
    }

    /// Allow a specific ICMPv6 type through the filter.
    ///
    /// Mirrors the C `ICMP6_FILTER_SETPASS` macro.
    fn set_pass(&mut self, msg_type: u8) {
        let idx = (msg_type >> 5) as usize;
        let bit = msg_type & 0x1f;
        self.data[idx] &= !(1u32 << bit);
    }
}

/// IPv6 multicast group join request structure for `IPV6_JOIN_GROUP`.
///
/// Mirrors C `struct ipv6_mreq`.
#[repr(C)]
struct Ipv6Mreq {
    multiaddr: libc::in6_addr,
    interface: libc::c_uint,
}

// ============================================================================
// Core Functions
// ============================================================================

/// Initialize the ICMPv6 raw socket for Router Advertisement operations.
///
/// Creates a non-blocking ICMPv6 raw socket, configures it with:
/// - ICMP6_FILTER to accept only Router Solicitation and Echo Reply
/// - Hop limit 255 (required by RFC 4861 §6.1.2)
/// - IPV6_RECVPKTINFO for interface identification on received packets
/// - IPV6_TCLASS = CS6 (DSCP network control)
/// - Joins the ff02::2 (all-routers) multicast group
///
/// Stores the socket fd in `state.icmp6fd`.
///
/// Replaces C `ra_init()` (radv.c line 336).
pub fn ra_init(state: &mut DaemonState) -> DnsmasqResult<()> {
    // SAFETY: Creating an ICMPv6 raw socket requires root/CAP_NET_RAW.
    // All pointers passed to setsockopt point to valid stack-allocated data
    // with correct sizes. The socket fd is stored in DaemonState for the
    // daemon's lifetime.
    let fd: RawFd = unsafe {
        libc::socket(
            libc::AF_INET6,
            libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            libc::IPPROTO_ICMPV6,
        )
    };
    if fd < 0 {
        return Err(DnsmasqError::Io(std::io::Error::last_os_error()));
    }

    // Set ICMPv6 filter: block everything, then allow RS and Echo Reply.
    let mut filter = Icmp6Filter::new_block_all();
    filter.set_pass(ICMP6_ROUTER_SOLICIT);
    filter.set_pass(ICMP6_ECHO_REPLY);

    // SAFETY: filter is a valid repr(C) struct; ICMP6_FILTER=1 is the
    // correct option for IPPROTO_ICMPV6 level on Linux.
    unsafe {
        let ret = libc::setsockopt(
            fd,
            libc::IPPROTO_ICMPV6,
            ICMP6_FILTER_OPT,
            &filter as *const Icmp6Filter as *const libc::c_void,
            std::mem::size_of::<Icmp6Filter>() as libc::socklen_t,
        );
        if ret < 0 {
            libc::close(fd);
            return Err(DnsmasqError::Io(std::io::Error::last_os_error()));
        }
    }

    // Set hop limit to 255 for both unicast and multicast — required by
    // RFC 4861 §6.1.2 ("MUST be 255").
    let hop_limit: libc::c_int = 255;
    // SAFETY: hop_limit is a valid c_int on the stack.
    unsafe {
        setsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_UNICAST_HOPS, hop_limit);
        setsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_HOPS, hop_limit);
    }

    // Enable IPV6_RECVPKTINFO to receive the destination address and
    // interface index for incoming packets.
    // SAFETY: on_val is a valid c_int.
    unsafe {
        setsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO, 1);
    }

    // Set DSCP to CS6 (0xC0 = 192) — network control traffic class.
    // SAFETY: tclass is a valid c_int.
    unsafe {
        setsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_TCLASS, 0xC0);
    }

    // Join the all-routers multicast group (ff02::2) on all interfaces.
    let mreq = Ipv6Mreq {
        multiaddr: libc::in6_addr {
            s6_addr: ALL_ROUTERS.octets(),
        },
        interface: 0, // all interfaces
    };
    // SAFETY: mreq is a valid repr(C) struct; IPV6_JOIN_GROUP is the
    // correct option for joining an IPv6 multicast group.
    unsafe {
        let ret = libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            IPV6_JOIN_GROUP_OPT,
            &mreq as *const Ipv6Mreq as *const libc::c_void,
            std::mem::size_of::<Ipv6Mreq>() as libc::socklen_t,
        );
        if ret < 0 {
            warn!(target: "dnsmasq::dhcp",
                "Failed to join all-routers multicast group: {}",
                std::io::Error::last_os_error()
            );
            // Non-fatal: RAs can still be sent, just won't receive RS on
            // interfaces where the group join failed.
        }
    }

    state.icmp6fd = fd;
    debug!(target: "dnsmasq::dhcp", "RA socket initialized: fd={}", fd);
    Ok(())
}

/// Receive and dispatch an incoming ICMPv6 packet on the RA socket.
///
/// Handles two ICMPv6 message types:
/// - **Router Solicitation (133)**: Triggers an immediate RA response to the
///   requesting interface. Logs the source MAC if `OPT_QUIET_RA` is not set.
/// - **Echo Reply (129)**: Forwards to [`slaac_ping_reply`] for SLAAC
///   address reachability confirmation.
///
/// Replaces C `icmp6_packet()` (radv.c line 504).
pub fn icmp6_packet(state: &mut DaemonState) -> DnsmasqResult<()> {
    let fd = state.icmp6fd;
    if fd < 0 {
        return Ok(());
    }

    let mut buf = [0u8; 1500];
    let mut cmsg_buf = [0u8; 256];
    // SAFETY: Constructing iovec and msghdr for recvmsg. All pointed-to
    // buffers are valid stack-allocated arrays with correct lifetimes.
    let (sz, src_addr, if_index) = unsafe {
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };
        let mut src: libc::sockaddr_in6 = std::mem::zeroed();
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_name = &mut src as *mut _ as *mut libc::c_void;
        msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in6>() as u32;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = cmsg_buf.len();

        let ret = libc::recvmsg(fd, &mut msg, 0);
        if ret < 1 {
            return Ok(());
        }

        let if_idx = extract_pktinfo_ifindex(&msg);
        let src_ip = Ipv6Addr::from(src.sin6_addr.s6_addr);
        (ret as usize, src_ip, if_idx)
    };

    if sz < 1 {
        return Ok(());
    }

    // Get interface name from index.
    let if_name = get_iface_name(if_index);
    if if_name.is_empty() {
        debug!(target: "dnsmasq::dhcp", "RA: no interface name for index {}", if_index);
        return Ok(());
    }

    // Check that this interface is allowed for RA/DHCP.
    let (allowed, _is_auth) = iface_check(
        libc::AF_INET6,
        Some(&std::net::IpAddr::V6(src_addr)),
        &if_name,
        state,
    );
    if !allowed {
        debug!(target: "dnsmasq::dhcp", "RA: interface {} not permitted", if_name);
        return Ok(());
    }

    let icmp_type = buf[0];
    match icmp_type {
        ICMP6_ROUTER_SOLICIT => {
            // Router Solicitation — respond with RA.
            // RS minimum size: 8 bytes (type + code + checksum + reserved).
            if sz < 8 {
                return Ok(());
            }

            // Extract source link-layer address from RS options (if present)
            // for logging purposes. The option starts at byte 8 of the RS.
            let mac = extract_source_lla(&buf[8..sz]);

            if !state.options.is_set(opt::QUIET_RA) {
                if let Some(ref mac_bytes) = mac {
                    info!(target: "dnsmasq::dhcp",
                        "RTR-SOLICIT({}): from {} on {}",
                        if_name, format_mac(mac_bytes), if_name
                    );
                } else {
                    info!(target: "dnsmasq::dhcp",
                        "RTR-SOLICIT({}): from {} on {}",
                        if_name, src_addr, if_name
                    );
                }
            }

            // Check if this interface is a bridge member and send to aliases.
            let aliases = find_bridge_aliases(if_index, state);
            if aliases.is_empty() {
                // Direct interface — send RA on the same interface.
                send_ra_on_interface(state, if_index, &if_name, Some(&src_addr), if_index);
            } else {
                // Bridge interface — send RA on each bridge member.
                for &alias_idx in &aliases {
                    send_ra_on_interface(state, if_index, &if_name, Some(&src_addr), alias_idx);
                }
            }
        }
        ICMP6_ECHO_REPLY => {
            // Echo Reply — forward to SLAAC for address confirmation.
            if sz < std::mem::size_of::<PingPacket>() {
                return Ok(());
            }
            slaac_ping_reply(
                &src_addr,
                &buf[..sz],
                &if_name,
                &mut state.slaac_leases,
                &state.options,
            );
        }
        _ => {
            debug!(target: "dnsmasq::dhcp",
                "RA: ignoring ICMPv6 type {} on {}", icmp_type, if_name
            );
        }
    }

    Ok(())
}

/// Construct and send a Router Advertisement to the specified destination.
///
/// This is the main public entry point for sending RAs, both solicited
/// (in response to RS) and unsolicited (periodic timer). The destination
/// can be a specific host address (solicited) or `None` for all-nodes
/// multicast (unsolicited).
///
/// Replaces C `send_ra()` (radv.c line 1056).
pub fn send_ra(state: &mut DaemonState, if_index: i32, iface: &str, dest: Option<&Ipv6Addr>) {
    send_ra_on_interface(state, if_index, iface, dest, if_index);
}

/// Construct and send a Router Advertisement, potentially on a different
/// send interface (for bridge alias support).
///
/// This is the core RA construction and transmission function. It:
/// 1. Builds the RA header with hop limit, M/O flags, router lifetime
/// 2. Enumerates interface IPv6 addresses and adds Prefix Information Options
/// 3. Adds RDNSS option (RFC 6106) with DNS server addresses
/// 4. Adds DNSSL option with DNS search domain list
/// 5. Reads and adds MTU option from /proc
/// 6. Adds Source Link-Layer Address option
/// 7. Adds Advertisement Interval option
/// 8. Sends the assembled packet via the ICMPv6 raw socket
///
/// Replaces C `send_ra_alias()` (radv.c line 702).
fn send_ra_on_interface(
    state: &mut DaemonState,
    if_index: i32,
    iface: &str,
    dest: Option<&Ipv6Addr>,
    send_iface: i32,
) {
    let fd = state.icmp6fd;
    if fd < 0 {
        return;
    }

    // Look up per-interface RA configuration.
    let ra_config = find_iface_param(iface, state);
    let interval = calc_interval(ra_config.as_ref());
    let lifetime = calc_lifetime(ra_config.as_ref());
    let prio = calc_prio(ra_config.as_ref());

    // Initialize RA construction parameter block.
    let mut parm = RaParam {
        iface: iface.to_string(),
        if_index,
        managed: false,
        other: false,
        adv_interval: interval,
        adv_lifetime: lifetime,
        prio,
        found_prefix: false,
        found_context: false,
    };

    // Tracking addresses discovered during prefix enumeration.
    let mut link_local: Option<Ipv6Addr> = None;
    let mut link_global: Option<Ipv6Addr> = None;
    let mut ula_addr: Option<Ipv6Addr> = None;
    let mut glob_pref_time: u32 = 0;
    let mut link_pref_time: u32 = 0;
    let mut ula_pref_time: u32 = 0;

    // Build the RA packet using OutPacket.
    let mut pkt = OutPacket::new();
    pkt.reset();

    // Reserve space for RA header by writing zeroes; we'll fill it later.
    let ra_header_size = std::mem::size_of::<RaPacket>();
    pkt.put_opt6_raw(ra_header_size);

    // Enumerate interface IPv6 addresses and add Prefix Information Options.
    add_prefixes_for_iface(
        state,
        &mut pkt,
        &mut parm,
        &mut link_local,
        &mut link_global,
        &mut ula_addr,
        &mut glob_pref_time,
        &mut link_pref_time,
        &mut ula_pref_time,
    );

    // Determine final M/O flags from DHCPv6 context analysis.
    // If OPT_RA is enabled globally but no CONTEXT_RA was found for this
    // interface, default to managed+other (full DHCPv6).
    if state.options.is_set(opt::RA) && !parm.found_context {
        parm.managed = true;
        parm.other = true;
    }

    // Build flags byte: M flag (bit 7), O flag (bit 6), priority (bits 4-3).
    let mut flags: u8 = 0;
    if parm.managed {
        flags |= ND_RA_FLAG_MANAGED;
    }
    if parm.other {
        flags |= ND_RA_FLAG_OTHER;
    }
    flags |= parm.prio;

    // Write RA header.
    let header_bytes = pkt.as_mut_bytes();
    if header_bytes.len() >= ra_header_size {
        header_bytes[0] = ICMP6_ROUTER_ADVERT;
        header_bytes[1] = 0; // code
        header_bytes[2] = 0; // checksum (kernel-computed)
        header_bytes[3] = 0;
        header_bytes[4] = read_hop_limit(iface); // hop limit from kernel, fallback 64
        header_bytes[5] = flags;
        // Router lifetime (network byte order).
        let lt = parm.adv_lifetime.min(0xFFFF) as u16;
        header_bytes[6] = (lt >> 8) as u8;
        header_bytes[7] = (lt & 0xFF) as u8;
        // Reachable time = 0 (unspecified).
        header_bytes[8] = 0;
        header_bytes[9] = 0;
        header_bytes[10] = 0;
        header_bytes[11] = 0;
        // Retransmit timer = 0 (unspecified).
        header_bytes[12] = 0;
        header_bytes[13] = 0;
        header_bytes[14] = 0;
        header_bytes[15] = 0;
    }

    // Add RDNSS option (RFC 6106 §5.1) — recursive DNS server addresses.
    add_rdnss_option(
        state,
        &mut pkt,
        parm.adv_lifetime,
        &link_local,
        &link_global,
        &ula_addr,
        glob_pref_time,
        link_pref_time,
        ula_pref_time,
    );

    // Add DNSSL option (RFC 6106 §5.2) — DNS search list.
    add_dnssl_option(state, &mut pkt, parm.adv_lifetime);

    // Add MTU option (RFC 4861 §4.6.4).
    add_mtu_option(&mut pkt, iface, ra_config.as_ref());

    // Add Source Link-Layer Address option (RFC 4861 §4.6.1).
    add_source_lla_option(&mut pkt, send_iface);

    // Add Advertisement Interval option (RFC 6275 §7.3).
    add_adv_interval_option(&mut pkt, parm.adv_interval);

    // Determine destination address: specific host (solicited) or all-nodes
    // multicast (unsolicited).
    let dest_addr = dest.unwrap_or(&ALL_NODES);

    // Capture the packet for debugging before sending.
    #[cfg(feature = "dumpfile")]
    {
        if state.dump_mask != 0 {
            let pkt_bytes = pkt.as_bytes();
            // Note: dump_packet_icmp is a method; we simulate with a
            // standalone call pattern matching the C code's
            // dump_packet_icmp(DUMP_RA, ...).
            debug!(target: "dnsmasq::dhcp",
                "RA dump: {} bytes to {} on iface {}",
                pkt_bytes.len(), dest_addr, iface
            );
        }
    }

    // Send the RA packet via raw socket.
    let pkt_bytes = pkt.as_bytes();
    send_icmp6_packet(fd, pkt_bytes, dest_addr, send_iface as u32);

    if !state.options.is_set(opt::QUIET_RA) {
        info!(target: "dnsmasq::dhcp",
            "RTR-ADVERT({}) {}", iface, dest_addr
        );
    }
}

/// Periodic RA timer — send unsolicited RAs when their interval expires.
///
/// Iterates all DHCPv6 contexts, checks each context's RA timing state,
/// sends an RA if the interval has elapsed, and schedules the next
/// transmission. Returns the timestamp (seconds since epoch) of the next
/// required RA, or 0 if no RAs are pending.
///
/// For bridge interfaces, performs a two-pass enumeration: first discovers
/// bridge members, then sends RAs on each member interface.
///
/// Replaces C `periodic_ra()` (radv.c line 1850).
pub fn periodic_ra(now: i64, state: &mut DaemonState) -> i64 {
    let mut next_event: i64 = 0;

    // Collect unique (if_index, iface_name) pairs that need RA from contexts.
    let mut ra_targets: Vec<(i32, String)> = Vec::new();

    // Find all interfaces with IPv6 addresses that match DHCPv6 contexts.
    for iface_rec in &state.interfaces {
        if let std::net::IpAddr::V6(addr) = iface_rec.addr {
            // Skip link-local addresses for context matching.
            if addr.segments()[0] == 0xfe80 {
                continue;
            }
            let idx = iface_rec.index as i32;
            let name = iface_rec.name.clone();
            if !ra_targets.iter().any(|(i, _)| *i == idx) {
                // Check if interface is allowed for DHCP/RA.
                let (allowed, _) = iface_check(libc::AF_INET6, Some(&iface_rec.addr), &name, state);
                if allowed {
                    ra_targets.push((idx, name));
                }
            }
        }
    }

    let mut timing = RA_TIMING_STATE.lock().unwrap_or_else(|e| e.into_inner());

    for (idx, name) in &ra_targets {
        // Find or create timing entry for this interface.
        let timing_entry = timing.iter_mut().find(|t| t.if_index == *idx);

        if let Some(entry) = timing_entry {
            if entry.ra_time != 0 && entry.ra_time <= now {
                // RA is due — send it.
                let aliases = find_bridge_aliases(*idx, state);
                if aliases.is_empty() {
                    send_ra_on_interface(state, *idx, name, None, *idx);
                } else {
                    for &alias_idx in &aliases {
                        send_ra_on_interface(state, *idx, name, None, alias_idx);
                    }
                }

                // Schedule next RA.
                let interval = new_timeout(now, name, state, entry.ra_short_period_start);
                entry.ra_time = now + interval;
            }

            // Track the nearest upcoming event.
            if entry.ra_time != 0 && (next_event == 0 || entry.ra_time < next_event) {
                next_event = entry.ra_time;
            }
        } else {
            // No timing entry yet — this interface hasn't been started.
            // It will be initialized by ra_start_unsolicited when contexts
            // are configured.
        }
    }

    next_event
}

/// Trigger a rapid RA burst for a newly configured or changed context.
///
/// Sets the context's RA timer to fire within 0–5 seconds (random jitter)
/// and enters short-period mode (frequent RAs for 60 seconds) as required
/// by RFC 4861 §6.2.4 for topology changes.
///
/// Replaces C `ra_start_unsolicited()` (radv.c line 425).
pub fn ra_start_unsolicited(
    _state: &mut DaemonState,
    now: i64,
    if_index: i32,
    prefix: &Ipv6Addr,
    prefix_len: u8,
) {
    let mut timing = RA_TIMING_STATE.lock().unwrap_or_else(|e| e.into_inner());

    // Generate random delay 0–5 seconds; fallback to 0 if RNG init fails.
    let delay = match SurfRng::new() {
        Ok(mut rng) => (rng.rand16() % (RA_START_MAX_DELAY + 1)) as i64,
        Err(_) => 0,
    };

    // Find existing entry or create new one.
    if let Some(entry) = timing
        .iter_mut()
        .find(|t| t.if_index == if_index && t.prefix_addr == *prefix && t.prefix_len == prefix_len)
    {
        entry.ra_time = now + delay;
        entry.ra_short_period_start = now;
    } else {
        timing.push(RaContextTiming {
            if_index,
            prefix_addr: *prefix,
            prefix_len,
            ra_time: now + delay,
            ra_short_period_start: now,
        });
    }

    debug!(target: "dnsmasq::dhcp",
        "RA: start unsolicited for {}/{} on iface {}, delay {}s",
        prefix, prefix_len, if_index, delay
    );
}

// ============================================================================
// RA Option Construction Helpers
// ============================================================================

/// Add Prefix Information Options to the RA packet for all IPv6 addresses
/// on the target interface that match DHCPv6 contexts.
///
/// For each matching context, determines the on-link (L) and autonomous (A)
/// flags, valid and preferred lifetimes, and writes a 32-byte PIO into the
/// packet buffer.
///
/// Replaces C `add_prefixes()` callback (radv.c line 1492).
fn add_prefixes_for_iface(
    state: &mut DaemonState,
    pkt: &mut OutPacket,
    parm: &mut RaParam,
    link_local: &mut Option<Ipv6Addr>,
    link_global: &mut Option<Ipv6Addr>,
    ula_addr: &mut Option<Ipv6Addr>,
    glob_pref_time: &mut u32,
    link_pref_time: &mut u32,
    ula_pref_time: &mut u32,
) {
    // Collect interface IPv6 addresses for the target interface.
    let iface_addrs: Vec<(Ipv6Addr, u8)> = state
        .interfaces
        .iter()
        .filter(|r| r.index as i32 == parm.if_index)
        .filter_map(|r| {
            if let std::net::IpAddr::V6(addr) = r.addr {
                let prefix_len = r
                    .netmask
                    .as_ref()
                    .and_then(|m| match m {
                        std::net::IpAddr::V6(mask) => Some(prefix_from_netmask6(mask)),
                        _ => None,
                    })
                    .unwrap_or(64);
                Some((addr, prefix_len))
            } else {
                None
            }
        })
        .collect();

    // Track link-local, global, and ULA addresses for RDNSS substitution.
    for &(addr, _plen) in &iface_addrs {
        let segs = addr.segments();
        if segs[0] == 0xfe80 {
            // Link-local address.
            *link_local = Some(addr);
            *link_pref_time = parm.adv_lifetime;
        } else if is_ula(&addr) {
            // Unique Local Address (ULA).
            *ula_addr = Some(addr);
            *ula_pref_time = parm.adv_lifetime;
        } else if segs[0] & 0xE000 == 0x2000 {
            // Global unicast address.
            *link_global = Some(addr);
            *glob_pref_time = parm.adv_lifetime;
        }
    }

    // For each non-link-local address, check against DHCPv6 contexts and
    // add a Prefix Information Option if a match is found.
    for &(addr, iface_prefix_len) in &iface_addrs {
        if addr.segments()[0] == 0xfe80 {
            continue; // Skip link-local for PIOs.
        }

        let mut found_match = false;

        // Check each DHCPv6 context for a match.
        for ctx_entry in &state.dhcp6_contexts {
            // Extract IPv6 start address from context.
            let ctx_start = match ctx_entry.start {
                std::net::IpAddr::V6(a) => a,
                _ => continue,
            };

            // Derive prefix length from context netmask.
            let ctx_prefix_len = ctx_entry
                .netmask
                .as_ref()
                .and_then(|m| match m {
                    std::net::IpAddr::V6(mask) => Some(prefix_from_netmask6(mask)),
                    _ => None,
                })
                .unwrap_or(64);

            // Check if interface address is in this context's prefix.
            if ctx_prefix_len == iface_prefix_len && is_same_net6(addr, ctx_start, ctx_prefix_len) {
                found_match = true;
                parm.found_context = true;
                let ctx_flags = ctx_entry.flags;

                // Determine M/O flags from context type.
                if ctx_flags & CONTEXT_RA != 0 && ctx_flags & CONTEXT_DHCP != 0 {
                    parm.other = true;
                    if ctx_flags & CONTEXT_RA_STATELESS == 0 {
                        parm.managed = true;
                    }
                } else if ctx_flags & CONTEXT_RA == 0 && state.options.is_set(opt::RA) {
                    parm.managed = true;
                    parm.other = true;
                }

                // Don't add PIO for template or old contexts.
                if ctx_flags & (CONTEXT_TEMPLATE | CONTEXT_OLD) != 0 {
                    continue;
                }

                // Calculate PIO flags.
                let mut pio_flags: u8 = 0;
                if ctx_flags & CONTEXT_RA_OFF_LINK == 0 {
                    pio_flags |= ND_OPT_PI_FLAG_ONLINK;
                }
                // Set autonomous flag unless this is a DHCPv6-only context.
                if ctx_flags & CONTEXT_RA != 0 || (ctx_flags & CONTEXT_DHCP == 0) {
                    pio_flags |= ND_OPT_PI_FLAG_AUTO;
                }

                // Determine lifetimes.
                let valid = ctx_entry.lease_time.max(300);
                let preferred = if ctx_flags & CONTEXT_DEPRECATE != 0 {
                    0
                } else {
                    valid
                };

                // Write PIO.
                write_prefix_option(pkt, ctx_prefix_len, pio_flags, valid, preferred, &addr);
                parm.found_prefix = true;
            }
        }

        // If no context matched but OPT_RA is enabled, add a default PIO.
        if !found_match && state.options.is_set(opt::RA) {
            write_prefix_option(
                pkt,
                iface_prefix_len,
                ND_OPT_PI_FLAG_ONLINK | ND_OPT_PI_FLAG_AUTO,
                parm.adv_lifetime,
                parm.adv_lifetime,
                &addr,
            );
            parm.found_prefix = true;
        }
    }
}

/// Write a single Prefix Information Option (32 bytes) into the packet.
fn write_prefix_option(
    pkt: &mut OutPacket,
    prefix_len: u8,
    flags: u8,
    valid_lifetime: u32,
    preferred_lifetime: u32,
    addr: &Ipv6Addr,
) {
    // PIO is 32 bytes = 4 × 8-byte units (len field = 4).
    let _start = pkt.save_counter(None);
    pkt.put_opt6_char(ND_OPT_PREFIX); // type
    pkt.put_opt6_char(4); // length (in 8-byte units)
    pkt.put_opt6_char(prefix_len); // prefix length
    pkt.put_opt6_char(flags); // L/A flags
    pkt.put_opt6_long(valid_lifetime); // valid lifetime
    pkt.put_opt6_long(preferred_lifetime); // preferred lifetime
    pkt.put_opt6_long(0); // reserved
    pkt.put_opt6(&addr.octets()); // 128-bit prefix
                                  // PIO is fixed-size (32 bytes = 4 × 8-byte units), no end_opt6 needed.
}

/// Add RDNSS option (RFC 6106 §5.1) to the RA packet.
///
/// Looks up DHCPv6 option 23 (DNS servers) from the daemon's option list
/// and encodes each server address as a 16-byte entry. Handles address
/// substitution for sentinel values:
/// - `::` (unspecified) → replaced with the global unicast address
/// - `fd00::` (ULA zero) → replaced with the interface ULA
/// - `fe80::` (link-local zero) → replaced with the interface link-local
///
/// Replaces the RDNSS encoding section of C `send_ra_alias()` (radv.c ~lines 800–900).
fn add_rdnss_option(
    state: &DaemonState,
    pkt: &mut OutPacket,
    lifetime: u32,
    link_local: &Option<Ipv6Addr>,
    link_global: &Option<Ipv6Addr>,
    ula_addr: &Option<Ipv6Addr>,
    glob_pref_time: u32,
    link_pref_time: u32,
    ula_pref_time: u32,
) {
    // Collect DNS server addresses from DHCPv6 option 23.
    let mut dns_addrs: Vec<Ipv6Addr> = Vec::new();
    for opt_entry in &state.dhcp_opts6 {
        if opt_entry.opt == OPTION6_DNS_SERVER && opt_entry.val.len() >= 16 {
            // Each address is 16 bytes.
            let mut offset = 0;
            while offset + 16 <= opt_entry.val.len() {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&opt_entry.val[offset..offset + 16]);
                let addr = Ipv6Addr::from(octets);
                dns_addrs.push(addr);
                offset += 16;
            }
        }
    }

    if dns_addrs.is_empty() {
        return;
    }

    // Perform address substitution for sentinel values.
    let mut resolved: Vec<Ipv6Addr> = Vec::new();
    for addr in &dns_addrs {
        if addr.is_unspecified() {
            // :: → use global unicast address (if available).
            if glob_pref_time != 0 {
                if let Some(global) = link_global {
                    resolved.push(*global);
                    continue;
                }
            }
        } else if is_ula_zero(addr) {
            // fd00:: → use interface ULA address (if available).
            if ula_pref_time != 0 {
                if let Some(ula) = ula_addr {
                    resolved.push(*ula);
                    continue;
                }
            }
        } else if is_link_local_zero(addr) {
            // fe80:: → use interface link-local address (if available).
            if link_pref_time != 0 {
                if let Some(ll) = link_local {
                    resolved.push(*ll);
                    continue;
                }
            }
        } else {
            resolved.push(*addr);
            continue;
        }
        // Sentinel couldn't be resolved — skip this address.
    }

    if resolved.is_empty() {
        return;
    }

    // RDNSS option format (RFC 6106 §5.1):
    //   Type (1 byte) = 25
    //   Length (1 byte) = 1 + 2*N (in 8-byte units, where N = number of addresses)
    //   Reserved (2 bytes) = 0
    //   Lifetime (4 bytes)
    //   Address[0] (16 bytes)
    //   ...
    //   Address[N-1] (16 bytes)
    let num_addrs = resolved.len();
    let len_units = 1 + (num_addrs * 2) as u8; // in 8-byte units
    pkt.put_opt6_char(ND_OPT_RDNSS);
    pkt.put_opt6_char(len_units);
    pkt.put_opt6_short(0); // reserved
    pkt.put_opt6_long(lifetime);
    for addr in &resolved {
        pkt.put_opt6(&addr.octets());
    }
}

/// Add DNSSL option (RFC 6106 §5.2) to the RA packet.
///
/// Looks up DHCPv6 option 24 (domain search list) and encodes domain names
/// in DNS wire format (length-prefixed labels, null terminated, padded to
/// 8-byte boundary).
///
/// Replaces the DNSSL encoding section of C `send_ra_alias()` (radv.c ~lines 900–1000).
fn add_dnssl_option(state: &DaemonState, pkt: &mut OutPacket, lifetime: u32) {
    // Collect domain names from DHCPv6 option 24.
    let mut domains: Vec<String> = Vec::new();
    for opt_entry in &state.dhcp_opts6 {
        if opt_entry.opt == OPTION6_DOMAIN_SEARCH {
            // The value is a DNS-encoded domain list. Parse it.
            let parsed = parse_dns_domain_list(&opt_entry.val);
            domains.extend(parsed);
        }
    }

    if domains.is_empty() {
        return;
    }

    // Encode domains into DNS wire format.
    let mut encoded = Vec::new();
    for domain in &domains {
        encode_dns_name(domain, &mut encoded);
    }
    if encoded.is_empty() {
        return;
    }

    // Pad to 8-byte boundary.
    while encoded.len() % 8 != 0 {
        encoded.push(0);
    }

    // DNSSL option format (RFC 6106 §5.2):
    //   Type (1 byte) = 31
    //   Length (1 byte) = 1 + domain_data_len/8 (in 8-byte units)
    //   Reserved (2 bytes) = 0
    //   Lifetime (4 bytes)
    //   Domain Names (variable, padded to 8-byte boundary)
    let len_units = 1 + (encoded.len() / 8) as u8;
    pkt.put_opt6_char(ND_OPT_DNSSL);
    pkt.put_opt6_char(len_units);
    pkt.put_opt6_short(0); // reserved
    pkt.put_opt6_long(lifetime);
    pkt.put_opt6(&encoded);
}

/// Add MTU option (RFC 4861 §4.6.4) to the RA packet.
///
/// Reads the interface MTU from `/proc/sys/net/ipv6/conf/{iface}/mtu`.
/// If a custom `mtu_name` is configured for this interface, reads from
/// that interface name instead.
///
/// Replaces the MTU option section of C `send_ra_alias()` (radv.c ~lines 1010–1040).
fn add_mtu_option(pkt: &mut OutPacket, iface: &str, ra_config: Option<&RaInterface>) {
    let mtu_iface = ra_config
        .and_then(|r| {
            if r.mtu_name.is_empty() {
                None
            } else {
                Some(r.mtu_name.as_str())
            }
        })
        .unwrap_or(iface);

    if let Some(mtu) = read_interface_mtu(mtu_iface) {
        if mtu > 0 {
            // MTU option: type (1) + length (1) + reserved (2) + MTU (4) = 8 bytes.
            pkt.put_opt6_char(ND_OPT_MTU);
            pkt.put_opt6_char(1); // length in 8-byte units
            pkt.put_opt6_short(0); // reserved
            pkt.put_opt6_long(mtu);
        }
    }
}

/// Add Source Link-Layer Address option (RFC 4861 §4.6.1) to the RA packet.
///
/// Reads the MAC address from `/sys/class/net/{iface}/address` and encodes
/// it as a 8-byte option (type + length + 6-byte MAC, padded to 8 bytes).
///
/// Replaces C `add_lla()` callback (radv.c line 1787).
fn add_source_lla_option(pkt: &mut OutPacket, if_index: i32) {
    let if_name = get_iface_name(if_index);
    if if_name.is_empty() {
        return;
    }

    if let Some(mac) = read_interface_mac(&if_name) {
        if mac.len() == 6 {
            // Source LLA option: type (1) + length (1) + MAC (6) = 8 bytes = 1 unit.
            pkt.put_opt6_char(ND_OPT_SOURCE_LLA);
            pkt.put_opt6_char(1); // length in 8-byte units
            pkt.put_opt6(&mac);
        }
    }
}

/// Add Advertisement Interval option (RFC 6275 §7.3) to the RA packet.
///
/// Encodes the advertisement interval in milliseconds so that hosts can
/// determine if the router is still reachable.
fn add_adv_interval_option(pkt: &mut OutPacket, interval_secs: u32) {
    // Advertisement Interval option: type (1) + length (1) + reserved (2) +
    // interval_ms (4) = 8 bytes = 1 unit.
    let interval_ms = interval_secs.saturating_mul(1000);
    pkt.put_opt6_char(ND_OPT_ADV_INTERVAL);
    pkt.put_opt6_char(1); // length in 8-byte units
    pkt.put_opt6_short(0); // reserved
    pkt.put_opt6_long(interval_ms);
}

// ============================================================================
// Timing Calculation Functions
// ============================================================================

/// Calculate the RA advertisement interval for an interface.
///
/// Returns the configured interval from `RaInterface`, clamped to
/// [4, 1800] seconds. Defaults to 600 seconds if not configured.
///
/// Replaces C `calc_interval()` (radv.c line 2062).
fn calc_interval(ra: Option<&RaInterface>) -> u32 {
    match ra {
        Some(r) if r.interval > 0 => r.interval.clamp(MIN_RA_INTERVAL, MAX_RA_INTERVAL),
        _ => DEFAULT_RA_INTERVAL,
    }
}

/// Calculate the router lifetime for an interface.
///
/// Returns 3× the interval by default, capped at 9000 seconds.
/// If explicitly configured and non-zero, uses the configured value
/// (but if less than the interval, uses the interval).
///
/// Replaces C `calc_lifetime()` (radv.c line 2117).
fn calc_lifetime(ra: Option<&RaInterface>) -> u32 {
    let interval = calc_interval(ra);
    match ra {
        Some(r) if r.lifetime > 0 => {
            let lt = r.lifetime;
            if lt < interval {
                interval
            } else {
                lt.min(MAX_RA_LIFETIME)
            }
        }
        _ => (interval * 3).min(MAX_RA_LIFETIME),
    }
}

/// Calculate the router priority for an interface.
///
/// Returns the priority bits (bits 4–3 of the RA flags byte).
/// 0 = medium (default), 0x08 = high, 0x18 = low.
///
/// Replaces C `calc_prio()` (radv.c line 2167).
fn calc_prio(ra: Option<&RaInterface>) -> u8 {
    match ra {
        Some(r) => r.prio,
        None => 0, // medium priority
    }
}

/// Calculate the timeout for the next RA transmission.
///
/// During the short-period burst (first 60 seconds after start),
/// uses a random interval between 5–20 seconds. Otherwise uses
/// 0.75–1.0× the configured interval with random jitter.
///
/// Replaces C `new_timeout()` (radv.c line 1321).
fn new_timeout(now: i64, iface: &str, state: &DaemonState, ra_short_period_start: i64) -> i64 {
    let ra_config = find_iface_param(iface, state);
    let interval = calc_interval(ra_config.as_ref());

    let mut rng = match SurfRng::new() {
        Ok(r) => r,
        Err(_) => {
            // Fallback: return the full interval without jitter.
            return interval as i64;
        }
    };

    // Check if we're in the short-period burst.
    if ra_short_period_start != 0 && (now - ra_short_period_start) < RA_SHORT_PERIOD_DURATION {
        // Random interval between MIN and MAX short period.
        let range = RA_SHORT_MAX_INTERVAL - RA_SHORT_MIN_INTERVAL + 1;
        let jitter = (rng.rand16() % range as u16) as i64;
        return (RA_SHORT_MIN_INTERVAL as i64) + jitter;
    }

    // Normal mode: 0.75 to 1.0 times the interval with random jitter.
    let three_quarter = (interval as i64 * 3) / 4;
    let quarter = (interval as i64) / 4;
    let jitter = if quarter > 0 {
        (rng.rand16() as i64) % quarter
    } else {
        0
    };
    three_quarter + jitter
}

// ============================================================================
// Interface Configuration Lookup
// ============================================================================

/// Find per-interface RA configuration matching the given interface name.
///
/// Searches `state.ra_interfaces` for an entry whose name matches
/// (supports wildcard/glob patterns). Returns `None` if no match found.
///
/// Replaces C `find_iface_param()` (radv.c line 1383).
fn find_iface_param(iface: &str, state: &DaemonState) -> Option<RaInterface> {
    for ra_iface in &state.ra_interfaces {
        if glob_match(iface, &ra_iface.name) || ra_iface.name == iface {
            // Convert from types::RaInterface to radv::RaInterface.
            return Some(RaInterface {
                name: ra_iface.name.clone(),
                interval: ra_iface.interval,
                lifetime: ra_iface.lifetime,
                prio: ra_iface.priority as u8,
                mtu_name: ra_iface.mtu_name.clone(),
            });
        }
    }
    None
}

// ============================================================================
// Bridge Alias Support
// ============================================================================

/// Find bridge member interface indices for bridge alias RA dispatch.
///
/// If the given interface index corresponds to a bridge listed in
/// `state.bridges`, returns the list of bridge member interface indices.
/// Returns an empty vector if the interface is not a bridge.
///
/// Replaces C `send_ra_to_aliases()` callback (radv.c line 1180).
fn find_bridge_aliases(if_index: i32, state: &DaemonState) -> Vec<i32> {
    let if_name = get_iface_name(if_index);
    if if_name.is_empty() {
        return Vec::new();
    }

    for bridge in &state.bridges {
        if bridge.iface == if_name {
            // Resolve alias names to interface indices.
            let mut alias_indices = Vec::new();
            for alias_name in &bridge.alias {
                if let Some(idx) = name_to_index(alias_name) {
                    alias_indices.push(idx);
                }
            }
            return alias_indices;
        }
    }

    Vec::new()
}

// ============================================================================
// Low-Level Socket and System Helpers
// ============================================================================

/// Send an ICMPv6 packet via the raw socket to the specified destination.
///
/// Constructs a `sockaddr_in6` with the destination address and interface
/// scope ID, then calls `sendto` in a retry loop (retrying on `EINTR`).
fn send_icmp6_packet(fd: RawFd, data: &[u8], dest: &Ipv6Addr, scope_id: u32) {
    // SAFETY: sockaddr_in6 is zeroed then populated with valid data.
    // The data slice has a valid lifetime for the duration of the sendto call.
    // We retry on EINTR per standard Unix practice.
    unsafe {
        let mut addr: libc::sockaddr_in6 = std::mem::zeroed();
        addr.sin6_family = libc::AF_INET6 as u16;
        addr.sin6_addr.s6_addr = dest.octets();
        addr.sin6_scope_id = scope_id;

        loop {
            let ret = libc::sendto(
                fd,
                data.as_ptr() as *const libc::c_void,
                data.len(),
                0,
                &addr as *const libc::sockaddr_in6 as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            );
            if ret >= 0 {
                break;
            }
            let err = *libc::__errno_location();
            if err != libc::EINTR {
                debug!(target: "dnsmasq::dhcp",
                    "RA send failed: {}", std::io::Error::from_raw_os_error(err)
                );
                break;
            }
        }
    }
}

/// Extract the interface index from IPV6_PKTINFO ancillary data in a
/// received message.
///
/// Parses the cmsg chain from `recvmsg` looking for `IPV6_PKTINFO`
/// and returns the `ipi6_ifindex` field. Returns 0 if not found.
///
/// # Safety
/// Caller must ensure `msg` points to a valid `msghdr` with valid
/// `msg_control` and `msg_controllen` from a successful `recvmsg` call.
unsafe fn extract_pktinfo_ifindex(msg: &libc::msghdr) -> i32 {
    let mut cmsg = libc::CMSG_FIRSTHDR(msg);
    while !cmsg.is_null() {
        let hdr = &*cmsg;
        if hdr.cmsg_level == libc::IPPROTO_IPV6 && hdr.cmsg_type == libc::IPV6_PKTINFO {
            let pktinfo = libc::CMSG_DATA(cmsg) as *const libc::in6_pktinfo;
            return (*pktinfo).ipi6_ifindex as i32;
        }
        cmsg = libc::CMSG_NXTHDR(msg, cmsg);
    }
    0
}

/// Set an integer socket option via `setsockopt`.
///
/// # Safety
/// Caller must ensure `fd` is a valid open socket and `level`/`optname`
/// are valid for the socket type.
unsafe fn setsockopt_int(fd: RawFd, level: libc::c_int, optname: libc::c_int, val: libc::c_int) {
    libc::setsockopt(
        fd,
        level,
        optname,
        &val as *const libc::c_int as *const libc::c_void,
        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
    );
}

/// Get the interface name for a given interface index.
///
/// Reads from `/sys/class/net/` or uses `if_indextoname()`.
fn get_iface_name(if_index: i32) -> String {
    if if_index <= 0 {
        return String::new();
    }

    let mut name_buf = [0u8; libc::IF_NAMESIZE];
    // SAFETY: name_buf is a valid buffer of IF_NAMESIZE bytes.
    // if_indextoname returns null on failure (handled below).
    let result = unsafe { libc::if_indextoname(if_index as u32, name_buf.as_mut_ptr() as *mut i8) };
    if result.is_null() {
        return String::new();
    }

    // Find the null terminator.
    let len = name_buf
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(name_buf.len());
    String::from_utf8_lossy(&name_buf[..len]).to_string()
}

/// Resolve an interface name to its OS index.
fn name_to_index(name: &str) -> Option<i32> {
    let c_name = std::ffi::CString::new(name).ok()?;
    // SAFETY: c_name is a valid null-terminated C string.
    // if_nametoindex returns 0 on failure.
    let idx = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if idx == 0 {
        None
    } else {
        Some(idx as i32)
    }
}

/// Read the IPv6 MTU for an interface from `/proc/sys/net/ipv6/conf/{iface}/mtu`.
fn read_interface_mtu(iface: &str) -> Option<u32> {
    let path = format!("/proc/sys/net/ipv6/conf/{}/mtu", iface);
    match std::fs::read_to_string(&path) {
        Ok(contents) => contents.trim().parse::<u32>().ok(),
        Err(_) => {
            debug!(target: "dnsmasq::dhcp", "RA: cannot read MTU from {}", path);
            None
        }
    }
}

/// Read the hop limit for an interface from the kernel sysctl.
///
/// The C code reads `/proc/sys/net/ipv6/conf/{iface}/hop_limit` and uses the
/// result as the Cur Hop Limit field in Router Advertisements.  Falls back to
/// the default value of 64 if the sysctl file cannot be read.
///
/// Source: C `radv.c` — hop_limit set from `/proc/sys/net/ipv6/conf/`.
fn read_hop_limit(iface: &str) -> u8 {
    let path = format!("/proc/sys/net/ipv6/conf/{}/hop_limit", iface);
    match std::fs::read_to_string(&path) {
        Ok(contents) => contents.trim().parse::<u8>().unwrap_or(64),
        Err(_) => {
            debug!(target: "dnsmasq::dhcp", "RA: cannot read hop_limit from {}, using default 64", path);
            64
        }
    }
}

/// Read the MAC address for an interface from `/sys/class/net/{iface}/address`.
fn read_interface_mac(iface: &str) -> Option<Vec<u8>> {
    let path = format!("/sys/class/net/{}/address", iface);
    match std::fs::read_to_string(&path) {
        Ok(contents) => {
            let mac_str = contents.trim();
            parse_mac_address(mac_str)
        }
        Err(_) => None,
    }
}

/// Parse a MAC address string "aa:bb:cc:dd:ee:ff" into bytes.
fn parse_mac_address(s: &str) -> Option<Vec<u8>> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut mac = Vec::with_capacity(6);
    for part in parts {
        match u8::from_str_radix(part, 16) {
            Ok(b) => mac.push(b),
            Err(_) => return None,
        }
    }
    Some(mac)
}

/// Extract source link-layer address option from Router Solicitation options.
///
/// Parses ND options starting at the given offset, looking for type 1
/// (Source LLA). Returns the MAC bytes if found.
fn extract_source_lla(options: &[u8]) -> Option<Vec<u8>> {
    let mut offset = 0;
    while offset + 2 <= options.len() {
        let opt_type = options[offset];
        let opt_len = options[offset + 1] as usize;
        if opt_len == 0 {
            break; // Prevent infinite loop on malformed options.
        }
        let opt_bytes = opt_len * 8; // Length in 8-byte units.
        if offset + opt_bytes > options.len() {
            break;
        }
        if opt_type == ND_OPT_SOURCE_LLA && opt_bytes >= 8 {
            // MAC starts at offset+2, length = opt_bytes - 2.
            let mac_len = opt_bytes - 2;
            return Some(options[offset + 2..offset + 2 + mac_len].to_vec());
        }
        offset += opt_bytes;
    }
    None
}

/// Calculate IPv6 prefix length from a netmask address.
///
/// Counts the number of leading 1-bits in the netmask octets.
fn prefix_from_netmask6(mask: &Ipv6Addr) -> u8 {
    let octets = mask.octets();
    let mut prefix: u32 = 0;
    for &b in &octets {
        prefix += b.count_ones();
    }
    prefix as u8
}

/// Parse a DNS-encoded domain list from raw bytes.
///
/// Each domain is encoded as a sequence of length-prefixed labels
/// terminated by a zero byte. Multiple domains are concatenated.
fn parse_dns_domain_list(data: &[u8]) -> Vec<String> {
    let mut domains = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        let mut labels = Vec::new();
        loop {
            if offset >= data.len() {
                break;
            }
            let label_len = data[offset] as usize;
            offset += 1;
            if label_len == 0 {
                break; // End of domain name.
            }
            if offset + label_len > data.len() {
                break;
            }
            if let Ok(label) = std::str::from_utf8(&data[offset..offset + label_len]) {
                labels.push(label.to_string());
            }
            offset += label_len;
        }
        if !labels.is_empty() {
            domains.push(labels.join("."));
        }
    }

    domains
}

/// Encode a domain name in DNS wire format (length-prefixed labels).
fn encode_dns_name(name: &str, buf: &mut Vec<u8>) {
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        let bytes = label.as_bytes();
        if bytes.len() > 63 {
            return; // Label too long — skip entire name.
        }
        buf.push(bytes.len() as u8);
        buf.extend_from_slice(bytes);
    }
    buf.push(0); // Terminating zero.
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ra_packet_size() {
        // RaPacket must be exactly 16 bytes (4 × 4 = 16 for the fixed header).
        assert_eq!(std::mem::size_of::<RaPacket>(), 16);
    }

    #[test]
    fn test_prefix_opt_size() {
        // PrefixOpt must be exactly 32 bytes (4 × 8 = 32).
        assert_eq!(std::mem::size_of::<PrefixOpt>(), 32);
    }

    #[test]
    fn test_ping_packet_size() {
        // PingPacket must be exactly 8 bytes.
        assert_eq!(std::mem::size_of::<PingPacket>(), 8);
    }

    #[test]
    fn test_neigh_packet_size() {
        // NeighPacket must be exactly 24 bytes.
        assert_eq!(std::mem::size_of::<NeighPacket>(), 24);
    }

    #[test]
    fn test_icmp6_filter_block_all() {
        let filter = Icmp6Filter::new_block_all();
        for &word in &filter.data {
            assert_eq!(word, 0xFFFF_FFFF);
        }
    }

    #[test]
    fn test_icmp6_filter_set_pass() {
        let mut filter = Icmp6Filter::new_block_all();

        // Pass Router Solicitation (133).
        filter.set_pass(ICMP6_ROUTER_SOLICIT);
        // 133 / 32 = 4 (index), 133 % 32 = 5 (bit).
        assert_eq!(filter.data[4], 0xFFFF_FFFF & !(1u32 << 5));

        // Other entries unchanged.
        for (i, &word) in filter.data.iter().enumerate() {
            if i != 4 {
                assert_eq!(word, 0xFFFF_FFFF);
            }
        }

        // Pass Echo Reply (129).
        filter.set_pass(ICMP6_ECHO_REPLY);
        // 129 / 32 = 4 (index), 129 % 32 = 1 (bit).
        assert_eq!(filter.data[4], 0xFFFF_FFFF & !(1u32 << 5) & !(1u32 << 1));
    }

    #[test]
    fn test_protocol_constants() {
        assert_eq!(ICMP6_ROUTER_SOLICIT, 133);
        assert_eq!(ICMP6_ROUTER_ADVERT, 134);
        assert_eq!(ICMP6_NEIGHBOUR_SOLICIT, 135);
        assert_eq!(ICMP6_NEIGHBOUR_ADVERT, 136);
        assert_eq!(ICMP6_ECHO_REPLY, 129);

        assert_eq!(ND_OPT_SOURCE_LLA, 1);
        assert_eq!(ND_OPT_PREFIX, 3);
        assert_eq!(ND_OPT_MTU, 5);
        assert_eq!(ND_OPT_RDNSS, 25);
        assert_eq!(ND_OPT_DNSSL, 31);

        assert_eq!(ND_RA_FLAG_MANAGED, 0x80);
        assert_eq!(ND_RA_FLAG_OTHER, 0x40);
        assert_eq!(ND_OPT_PI_FLAG_ONLINK, 0x80);
        assert_eq!(ND_OPT_PI_FLAG_AUTO, 0x40);
    }

    #[test]
    fn test_calc_interval_default() {
        assert_eq!(calc_interval(None), DEFAULT_RA_INTERVAL);
    }

    #[test]
    fn test_calc_interval_configured() {
        let ra = RaInterface {
            name: "eth0".into(),
            interval: 100,
            lifetime: 0,
            prio: 0,
            mtu_name: String::new(),
        };
        assert_eq!(calc_interval(Some(&ra)), 100);
    }

    #[test]
    fn test_calc_interval_clamped_low() {
        let ra = RaInterface {
            name: "eth0".into(),
            interval: 1, // below minimum of 4
            lifetime: 0,
            prio: 0,
            mtu_name: String::new(),
        };
        assert_eq!(calc_interval(Some(&ra)), MIN_RA_INTERVAL);
    }

    #[test]
    fn test_calc_interval_clamped_high() {
        let ra = RaInterface {
            name: "eth0".into(),
            interval: 5000, // above maximum of 1800
            lifetime: 0,
            prio: 0,
            mtu_name: String::new(),
        };
        assert_eq!(calc_interval(Some(&ra)), MAX_RA_INTERVAL);
    }

    #[test]
    fn test_calc_lifetime_default() {
        // Default lifetime = 3 × default interval (600) = 1800.
        assert_eq!(calc_lifetime(None), 1800);
    }

    #[test]
    fn test_calc_lifetime_configured() {
        let ra = RaInterface {
            name: "eth0".into(),
            interval: 100,
            lifetime: 500,
            prio: 0,
            mtu_name: String::new(),
        };
        assert_eq!(calc_lifetime(Some(&ra)), 500);
    }

    #[test]
    fn test_calc_lifetime_less_than_interval() {
        let ra = RaInterface {
            name: "eth0".into(),
            interval: 300,
            lifetime: 100, // less than interval → use interval
            prio: 0,
            mtu_name: String::new(),
        };
        assert_eq!(calc_lifetime(Some(&ra)), 300);
    }

    #[test]
    fn test_calc_lifetime_capped() {
        let ra = RaInterface {
            name: "eth0".into(),
            interval: 100,
            lifetime: 20000, // above MAX_RA_LIFETIME
            prio: 0,
            mtu_name: String::new(),
        };
        assert_eq!(calc_lifetime(Some(&ra)), MAX_RA_LIFETIME);
    }

    #[test]
    fn test_calc_prio_default() {
        assert_eq!(calc_prio(None), 0);
    }

    #[test]
    fn test_calc_prio_configured() {
        let ra = RaInterface {
            name: "eth0".into(),
            interval: 0,
            lifetime: 0,
            prio: RA_PRIO_HIGH,
            mtu_name: String::new(),
        };
        assert_eq!(calc_prio(Some(&ra)), RA_PRIO_HIGH);
    }

    #[test]
    fn test_prefix_from_netmask6() {
        // /64 netmask
        let mask = Ipv6Addr::new(0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0, 0, 0, 0);
        assert_eq!(prefix_from_netmask6(&mask), 64);

        // /128 (all ones)
        let mask = Ipv6Addr::new(
            0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
        );
        assert_eq!(prefix_from_netmask6(&mask), 128);

        // /48
        let mask = Ipv6Addr::new(0xFFFF, 0xFFFF, 0xFFFF, 0, 0, 0, 0, 0);
        assert_eq!(prefix_from_netmask6(&mask), 48);
    }

    #[test]
    fn test_encode_dns_name() {
        let mut buf = Vec::new();
        encode_dns_name("example.com", &mut buf);
        assert_eq!(
            buf,
            vec![7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0]
        );
    }

    #[test]
    fn test_encode_dns_name_subdomain() {
        let mut buf = Vec::new();
        encode_dns_name("sub.example.com", &mut buf);
        assert_eq!(
            buf,
            vec![
                3, b's', b'u', b'b', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o',
                b'm', 0
            ]
        );
    }

    #[test]
    fn test_parse_dns_domain_list() {
        // Encode "example.com" followed by "test.org".
        let data = vec![
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 4, b't', b'e',
            b's', b't', 3, b'o', b'r', b'g', 0,
        ];
        let domains = parse_dns_domain_list(&data);
        assert_eq!(domains, vec!["example.com", "test.org"]);
    }

    #[test]
    fn test_parse_mac_address_valid() {
        let mac = parse_mac_address("aa:bb:cc:dd:ee:ff");
        assert_eq!(mac, Some(vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
    }

    #[test]
    fn test_parse_mac_address_invalid() {
        assert!(parse_mac_address("invalid").is_none());
        assert!(parse_mac_address("aa:bb:cc").is_none());
        assert!(parse_mac_address("zz:bb:cc:dd:ee:ff").is_none());
    }

    #[test]
    fn test_extract_source_lla() {
        // Valid Source LLA option: type=1, len=1 (8 bytes), MAC=6 bytes.
        let options = vec![
            1, 1, // type=1, len=1 (8 bytes)
            0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, // MAC
        ];
        let lla = extract_source_lla(&options);
        assert_eq!(lla, Some(vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]));
    }

    #[test]
    fn test_extract_source_lla_not_present() {
        // MTU option only: type=5, len=1 (8 bytes).
        let options = vec![5, 1, 0, 0, 0, 0, 0x05, 0xDC];
        let lla = extract_source_lla(&options);
        assert!(lla.is_none());
    }

    #[test]
    fn test_write_prefix_option() {
        let mut pkt = OutPacket::new();
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0);
        write_prefix_option(
            &mut pkt,
            64,
            ND_OPT_PI_FLAG_ONLINK | ND_OPT_PI_FLAG_AUTO,
            3600,
            1800,
            &addr,
        );
        let bytes = pkt.as_bytes();
        assert_eq!(bytes.len(), 32); // PIO is always 32 bytes.
        assert_eq!(bytes[0], ND_OPT_PREFIX); // type
        assert_eq!(bytes[1], 4); // length in 8-byte units
        assert_eq!(bytes[2], 64); // prefix length
        assert_eq!(bytes[3], 0xC0); // L + A flags
    }

    #[test]
    fn test_ra_param_default() {
        let parm = RaParam {
            iface: "eth0".into(),
            if_index: 2,
            managed: false,
            other: false,
            adv_interval: 600,
            adv_lifetime: 1800,
            prio: 0,
            found_prefix: false,
            found_context: false,
        };
        assert!(!parm.managed);
        assert!(!parm.other);
        assert!(!parm.found_prefix);
        assert!(!parm.found_context);
    }

    // -----------------------------------------------------------------------
    // Additional calc_interval edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_calc_interval_zero_means_default() {
        let ra = RaInterface {
            name: "eth0".into(),
            interval: 0,
            lifetime: 0,
            prio: 0,
            mtu_name: String::new(),
        };
        assert_eq!(calc_interval(Some(&ra)), DEFAULT_RA_INTERVAL);
    }

    #[test]
    fn test_calc_interval_exactly_min() {
        let ra = RaInterface {
            name: "eth0".into(),
            interval: MIN_RA_INTERVAL,
            lifetime: 0,
            prio: 0,
            mtu_name: String::new(),
        };
        assert_eq!(calc_interval(Some(&ra)), MIN_RA_INTERVAL);
    }

    #[test]
    fn test_calc_interval_exactly_max() {
        let ra = RaInterface {
            name: "eth0".into(),
            interval: MAX_RA_INTERVAL,
            lifetime: 0,
            prio: 0,
            mtu_name: String::new(),
        };
        assert_eq!(calc_interval(Some(&ra)), MAX_RA_INTERVAL);
    }

    // -----------------------------------------------------------------------
    // Additional calc_lifetime edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_calc_lifetime_default_calc() {
        // Default = interval * 3
        assert_eq!(calc_lifetime(None), DEFAULT_RA_INTERVAL * 3);
    }

    #[test]
    fn test_calc_lifetime_zero_means_default() {
        let ra = RaInterface {
            name: "eth0".into(),
            interval: 100,
            lifetime: 0,
            prio: 0,
            mtu_name: String::new(),
        };
        // lifetime 0 → use default: interval * 3
        assert_eq!(calc_lifetime(Some(&ra)), 300);
    }

    #[test]
    fn test_calc_lifetime_exactly_max() {
        let ra = RaInterface {
            name: "eth0".into(),
            interval: 100,
            lifetime: MAX_RA_LIFETIME,
            prio: 0,
            mtu_name: String::new(),
        };
        assert_eq!(calc_lifetime(Some(&ra)), MAX_RA_LIFETIME);
    }

    // -----------------------------------------------------------------------
    // calc_prio additional tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_calc_prio_low() {
        let ra = RaInterface {
            name: "eth0".into(),
            interval: 0,
            lifetime: 0,
            prio: RA_PRIO_LOW,
            mtu_name: String::new(),
        };
        assert_eq!(calc_prio(Some(&ra)), RA_PRIO_LOW);
    }

    #[test]
    fn test_calc_prio_medium_explicit() {
        let ra = RaInterface {
            name: "eth0".into(),
            interval: 0,
            lifetime: 0,
            prio: 0, // medium
            mtu_name: String::new(),
        };
        assert_eq!(calc_prio(Some(&ra)), 0);
    }

    // -----------------------------------------------------------------------
    // prefix_from_netmask6 edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_prefix_from_netmask6_zero() {
        let mask = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0);
        assert_eq!(prefix_from_netmask6(&mask), 0);
    }

    #[test]
    fn test_prefix_from_netmask6_single_bit() {
        let mask = Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0);
        assert_eq!(prefix_from_netmask6(&mask), 1);
    }

    #[test]
    fn test_prefix_from_netmask6_96() {
        let mask = Ipv6Addr::new(0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0, 0);
        assert_eq!(prefix_from_netmask6(&mask), 96);
    }

    // -----------------------------------------------------------------------
    // parse_mac_address edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_mac_address_all_zeros() {
        let mac = parse_mac_address("00:00:00:00:00:00");
        assert_eq!(mac, Some(vec![0, 0, 0, 0, 0, 0]));
    }

    #[test]
    fn test_parse_mac_address_all_ff() {
        let mac = parse_mac_address("ff:ff:ff:ff:ff:ff");
        assert_eq!(mac, Some(vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff]));
    }

    #[test]
    fn test_parse_mac_address_empty() {
        assert!(parse_mac_address("").is_none());
    }

    #[test]
    fn test_parse_mac_address_too_many_octets() {
        assert!(parse_mac_address("aa:bb:cc:dd:ee:ff:00").is_none());
    }

    #[test]
    fn test_parse_mac_address_uppercase() {
        let mac = parse_mac_address("AA:BB:CC:DD:EE:FF");
        assert_eq!(mac, Some(vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]));
    }

    #[test]
    fn test_parse_mac_address_mixed_case() {
        let mac = parse_mac_address("aA:Bb:cC:dD:eE:fF");
        assert_eq!(mac, Some(vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]));
    }

    // -----------------------------------------------------------------------
    // extract_source_lla additional tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_source_lla_multiple_options() {
        // MTU option first, then Source LLA
        let mut options = vec![
            5, 1, 0, 0, 0, 0, 0x05, 0xDC, // MTU option: type=5, len=1 (8 bytes)
            1, 1, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, // Source LLA: type=1, len=1 (8 bytes)
        ];
        let lla = extract_source_lla(&options);
        assert_eq!(lla, Some(vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]));
    }

    #[test]
    fn test_extract_source_lla_zero_length_stops() {
        // Zero-length option should stop parsing
        let options = vec![1, 0, 0xDE, 0xAD]; // len=0 → break
        let lla = extract_source_lla(&options);
        assert!(lla.is_none());
    }

    #[test]
    fn test_extract_source_lla_empty() {
        let lla = extract_source_lla(&[]);
        assert!(lla.is_none());
    }

    #[test]
    fn test_extract_source_lla_truncated() {
        // Single byte — not enough for type+len
        let lla = extract_source_lla(&[1]);
        assert!(lla.is_none());
    }

    // -----------------------------------------------------------------------
    // encode_dns_name edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_encode_dns_name_root() {
        let mut buf = Vec::new();
        encode_dns_name("", &mut buf);
        assert_eq!(buf, vec![0]); // Just terminator
    }

    #[test]
    fn test_encode_dns_name_trailing_dot() {
        let mut buf = Vec::new();
        encode_dns_name("example.com.", &mut buf);
        // Trailing dot → empty label → skipped; result same as without trailing dot
        assert_eq!(
            buf,
            vec![7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0]
        );
    }

    #[test]
    fn test_encode_dns_name_single_label() {
        let mut buf = Vec::new();
        encode_dns_name("localhost", &mut buf);
        assert_eq!(
            buf,
            vec![9, b'l', b'o', b'c', b'a', b'l', b'h', b'o', b's', b't', 0]
        );
    }

    #[test]
    fn test_encode_dns_name_long_label() {
        // Label > 63 chars → skip entire name
        let long_label = "a".repeat(64);
        let name = format!("{}.com", long_label);
        let mut buf = Vec::new();
        encode_dns_name(&name, &mut buf);
        // Label too long returns early, only gets the terminator from before the skip
        // Actually the function returns before appending anything if the label is too long
        assert!(buf.is_empty() || buf == vec![0]);
    }

    // -----------------------------------------------------------------------
    // parse_dns_domain_list edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_dns_domain_list_empty() {
        let domains = parse_dns_domain_list(&[]);
        assert!(domains.is_empty());
    }

    #[test]
    fn test_parse_dns_domain_list_single() {
        let data = vec![3, b'c', b'o', b'm', 0];
        let domains = parse_dns_domain_list(&data);
        assert_eq!(domains, vec!["com"]);
    }

    #[test]
    fn test_parse_dns_domain_list_root_only() {
        let data = vec![0]; // Just root label
        let domains = parse_dns_domain_list(&data);
        assert!(domains.is_empty()); // No labels in the name
    }

    #[test]
    fn test_parse_dns_domain_list_truncated() {
        let data = vec![5, b'h', b'e']; // Label says 5 bytes but only 2 available
        let domains = parse_dns_domain_list(&data);
        assert!(domains.is_empty()); // Incomplete
    }

    // -----------------------------------------------------------------------
    // write_prefix_option additional tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_write_prefix_option_no_flags() {
        let mut pkt = OutPacket::new();
        let addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0);
        write_prefix_option(&mut pkt, 48, 0, 7200, 3600, &addr);
        let bytes = pkt.as_bytes();
        assert_eq!(bytes.len(), 32);
        assert_eq!(bytes[0], ND_OPT_PREFIX);
        assert_eq!(bytes[1], 4);
        assert_eq!(bytes[2], 48);
        assert_eq!(bytes[3], 0); // no flags
    }

    #[test]
    fn test_write_prefix_option_128() {
        let mut pkt = OutPacket::new();
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        write_prefix_option(
            &mut pkt,
            128,
            ND_OPT_PI_FLAG_ONLINK | ND_OPT_PI_FLAG_AUTO,
            3600,
            1800,
            &addr,
        );
        let bytes = pkt.as_bytes();
        assert_eq!(bytes[2], 128);
    }

    // -----------------------------------------------------------------------
    // IcmpFilter tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_icmp6_filter_all_blocked_then_selective_pass() {
        let mut filter = Icmp6Filter::new_block_all();
        // All blocked = all bits set to 1
        for &word in &filter.data {
            assert_eq!(word, 0xFFFF_FFFF);
        }

        filter.set_pass(ICMP6_ROUTER_SOLICIT);
        filter.set_pass(ICMP6_ECHO_REPLY);

        // Some bits should now be cleared
        assert!(filter.data.iter().any(|&x| x != 0xFFFF_FFFF));
    }

    #[test]
    fn test_icmp6_filter_set_pass_all_types() {
        let mut filter = Icmp6Filter::new_block_all();
        for t in 0..=255u8 {
            filter.set_pass(t);
        }
        // All bits cleared → all u32 words should be 0
        for &word in &filter.data {
            assert_eq!(word, 0);
        }
    }

    // -----------------------------------------------------------------------
    // RaPacket structure tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_ra_packet_fields() {
        let pkt = RaPacket {
            icmp_type: ICMP6_ROUTER_ADVERT,
            icmp_code: 0,
            checksum: 0,
            hop_limit: 64,
            flags: ND_RA_FLAG_MANAGED | ND_RA_FLAG_OTHER,
            lifetime: 1800u16.to_be(),
            reachable_time: 0,
            retrans_timer: 0,
        };
        assert_eq!(pkt.icmp_type, 134);
        assert_eq!(pkt.flags & ND_RA_FLAG_MANAGED, ND_RA_FLAG_MANAGED);
        assert_eq!(pkt.flags & ND_RA_FLAG_OTHER, ND_RA_FLAG_OTHER);
    }

    #[test]
    fn test_ra_packet_prio_bits() {
        let pkt = RaPacket {
            icmp_type: ICMP6_ROUTER_ADVERT,
            icmp_code: 0,
            checksum: 0,
            hop_limit: 64,
            flags: RA_PRIO_HIGH,
            lifetime: 0,
            reachable_time: 0,
            retrans_timer: 0,
        };
        // Priority bits are in positions 4-3
        assert_eq!(pkt.flags & 0x18, RA_PRIO_HIGH);
    }

    // -----------------------------------------------------------------------
    // PrefixOpt structure tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_prefix_opt_fields() {
        let po = PrefixOpt {
            opt_type: ND_OPT_PREFIX,
            len: 4,
            prefix_len: 64,
            flags: ND_OPT_PI_FLAG_ONLINK | ND_OPT_PI_FLAG_AUTO,
            valid_lifetime: 3600u32.to_be(),
            preferred_lifetime: 1800u32.to_be(),
            reserved: 0,
            prefix: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        };
        assert_eq!(po.opt_type, 3);
        assert_eq!(po.len, 4);
        assert_eq!(po.prefix_len, 64);
        assert_eq!(po.flags, 0xC0);
    }

    // -----------------------------------------------------------------------
    // Protocol constant verification
    // -----------------------------------------------------------------------

    #[test]
    fn test_icmpv6_constants_comprehensive() {
        assert_eq!(ICMP6_ROUTER_SOLICIT, 133);
        assert_eq!(ICMP6_ROUTER_ADVERT, 134);
        assert_eq!(ICMP6_NEIGHBOUR_SOLICIT, 135);
        assert_eq!(ICMP6_NEIGHBOUR_ADVERT, 136);
        assert_eq!(ICMP6_ECHO_REPLY, 129);
    }

    #[test]
    fn test_nd_opt_constants() {
        assert_eq!(ND_OPT_SOURCE_LLA, 1);
        assert_eq!(ND_OPT_PREFIX, 3);
        assert_eq!(ND_OPT_MTU, 5);
        assert_eq!(ND_OPT_ADV_INTERVAL, 7);
        assert_eq!(ND_OPT_RDNSS, 25);
        assert_eq!(ND_OPT_DNSSL, 31);
    }

    #[test]
    fn test_ra_flag_constants() {
        assert_eq!(ND_RA_FLAG_MANAGED, 0x80);
        assert_eq!(ND_RA_FLAG_OTHER, 0x40);
        assert_eq!(ND_OPT_PI_FLAG_ONLINK, 0x80);
        assert_eq!(ND_OPT_PI_FLAG_AUTO, 0x40);
    }

    #[test]
    fn test_timing_constants() {
        assert_eq!(DEFAULT_RA_INTERVAL, 600);
        assert_eq!(MIN_RA_INTERVAL, 4);
        assert_eq!(MAX_RA_INTERVAL, 1800);
        assert_eq!(MAX_RA_LIFETIME, 9000);
        assert_eq!(RA_SHORT_PERIOD_DURATION, 60);
        assert_eq!(RA_SHORT_MIN_INTERVAL, 5);
        assert_eq!(RA_SHORT_MAX_INTERVAL, 20);
    }

    #[test]
    fn test_multicast_addresses() {
        assert_eq!(ALL_NODES, Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1));
        assert_eq!(ALL_ROUTERS, Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2));
    }

    // -----------------------------------------------------------------------
    // RaParam additional tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_ra_param_managed_and_other() {
        let parm = RaParam {
            iface: "br0".into(),
            if_index: 5,
            managed: true,
            other: true,
            adv_interval: 200,
            adv_lifetime: 3600,
            prio: RA_PRIO_LOW,
            found_prefix: true,
            found_context: true,
        };
        assert!(parm.managed);
        assert!(parm.other);
        assert!(parm.found_prefix);
        assert!(parm.found_context);
        assert_eq!(parm.prio, RA_PRIO_LOW);
    }

    // -----------------------------------------------------------------------
    // RaInterface structure tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_ra_interface_fields() {
        let ri = RaInterface {
            name: "wlan0".into(),
            interval: 400,
            lifetime: 1200,
            prio: RA_PRIO_HIGH,
            mtu_name: "eth0".into(),
        };
        assert_eq!(ri.name, "wlan0");
        assert_eq!(ri.interval, 400);
        assert_eq!(ri.lifetime, 1200);
        assert_eq!(ri.prio, RA_PRIO_HIGH);
        assert_eq!(ri.mtu_name, "eth0");
    }

    // -----------------------------------------------------------------------
    // find_iface_param tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_find_iface_param_not_found() {
        let state = DaemonState::new();
        assert!(find_iface_param("eth0", &state).is_none());
    }

    #[test]
    fn test_find_iface_param_exact_match() {
        let mut state = DaemonState::new();
        state.ra_interfaces.push(crate::core::types::RaInterface {
            name: "eth0".into(),
            interval: 300,
            lifetime: 900,
            priority: 8,
            mtu: 0,
            mtu_name: String::new(),
        });
        let result = find_iface_param("eth0", &state);
        assert!(result.is_some());
        let ri = result.unwrap();
        assert_eq!(ri.interval, 300);
        assert_eq!(ri.lifetime, 900);
    }

    #[test]
    fn test_find_iface_param_no_match() {
        let mut state = DaemonState::new();
        state.ra_interfaces.push(crate::core::types::RaInterface {
            name: "eth0".into(),
            interval: 300,
            lifetime: 900,
            priority: 8,
            mtu: 0,
            mtu_name: String::new(),
        });
        assert!(find_iface_param("eth1", &state).is_none());
    }

    // -----------------------------------------------------------------------
    // add_adv_interval_option tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_add_adv_interval_option_basic() {
        let mut pkt = OutPacket::new();
        add_adv_interval_option(&mut pkt, 600);
        let bytes = pkt.as_bytes();
        assert_eq!(bytes.len(), 8); // 1 unit = 8 bytes
        assert_eq!(bytes[0], ND_OPT_ADV_INTERVAL); // type = 7
        assert_eq!(bytes[1], 1); // length = 1 unit
                                 // reserved = 0
        assert_eq!(bytes[2], 0);
        assert_eq!(bytes[3], 0);
        // interval_ms = 600 * 1000 = 600000 = 0x000927C0
        let ms = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        assert_eq!(ms, 600_000);
    }

    #[test]
    fn test_add_adv_interval_option_zero() {
        let mut pkt = OutPacket::new();
        add_adv_interval_option(&mut pkt, 0);
        let bytes = pkt.as_bytes();
        assert_eq!(bytes.len(), 8);
        let ms = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        assert_eq!(ms, 0);
    }

    #[test]
    fn test_add_adv_interval_option_max() {
        let mut pkt = OutPacket::new();
        add_adv_interval_option(&mut pkt, MAX_RA_INTERVAL);
        let bytes = pkt.as_bytes();
        let ms = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        assert_eq!(ms, MAX_RA_INTERVAL * 1000);
    }

    #[test]
    fn test_add_adv_interval_option_saturating() {
        let mut pkt = OutPacket::new();
        // u32::MAX / 1000 would overflow when multiplied
        add_adv_interval_option(&mut pkt, u32::MAX);
        let bytes = pkt.as_bytes();
        let ms = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        assert_eq!(ms, u32::MAX); // saturating_mul caps at u32::MAX
    }

    // -----------------------------------------------------------------------
    // add_rdnss_option tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_add_rdnss_option_empty_opts() {
        let state = DaemonState::new();
        let mut pkt = OutPacket::new();
        add_rdnss_option(&state, &mut pkt, 3600, &None, &None, &None, 0, 0, 0);
        // No DNS server options → packet should be empty
        assert_eq!(pkt.as_bytes().len(), 0);
    }

    #[test]
    fn test_add_rdnss_option_single_dns_server() {
        let mut state = DaemonState::new();
        // Add DNS server option 23 with one IPv6 address
        let addr = Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888);
        state.dhcp_opts6.push(crate::core::types::DhcpOptEntry {
            opt: OPTION6_DNS_SERVER,
            val: addr.octets().to_vec(),
            flags: 0,
            netid: None,
        });
        let mut pkt = OutPacket::new();
        add_rdnss_option(&state, &mut pkt, 3600, &None, &None, &None, 0, 0, 0);
        let bytes = pkt.as_bytes();
        // RDNSS: type(1) + len(1) + reserved(2) + lifetime(4) + addr(16) = 24 bytes
        assert_eq!(bytes.len(), 24);
        assert_eq!(bytes[0], ND_OPT_RDNSS); // type = 25
        assert_eq!(bytes[1], 3); // len = 1 + 2*1 = 3 units
        let lifetime = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        assert_eq!(lifetime, 3600);
    }

    #[test]
    fn test_add_rdnss_option_two_dns_servers() {
        let mut state = DaemonState::new();
        let addr1 = Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888);
        let addr2 = Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844);
        let mut val = addr1.octets().to_vec();
        val.extend_from_slice(&addr2.octets());
        state.dhcp_opts6.push(crate::core::types::DhcpOptEntry {
            opt: OPTION6_DNS_SERVER,
            val,
            flags: 0,
            netid: None,
        });
        let mut pkt = OutPacket::new();
        add_rdnss_option(&state, &mut pkt, 7200, &None, &None, &None, 0, 0, 0);
        let bytes = pkt.as_bytes();
        // RDNSS: 8 + 16*2 = 40 bytes
        assert_eq!(bytes.len(), 40);
        assert_eq!(bytes[1], 5); // len = 1 + 2*2 = 5 units
    }

    #[test]
    fn test_add_rdnss_option_sentinel_unspecified_resolved() {
        let mut state = DaemonState::new();
        // Add :: (unspecified) sentinel
        let sentinel = Ipv6Addr::UNSPECIFIED;
        state.dhcp_opts6.push(crate::core::types::DhcpOptEntry {
            opt: OPTION6_DNS_SERVER,
            val: sentinel.octets().to_vec(),
            flags: 0,
            netid: None,
        });
        let global = Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let mut pkt = OutPacket::new();
        add_rdnss_option(&state, &mut pkt, 3600, &None, &global, &None, 3600, 0, 0);
        let bytes = pkt.as_bytes();
        // Sentinel resolved to global address → should have RDNSS option
        assert_eq!(bytes.len(), 24);
        // Verify the address in the packet is the global address
        let mut addr_bytes = [0u8; 16];
        addr_bytes.copy_from_slice(&bytes[8..24]);
        let resolved = Ipv6Addr::from(addr_bytes);
        assert_eq!(resolved, Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    }

    #[test]
    fn test_add_rdnss_option_sentinel_unspecified_no_global() {
        let mut state = DaemonState::new();
        let sentinel = Ipv6Addr::UNSPECIFIED;
        state.dhcp_opts6.push(crate::core::types::DhcpOptEntry {
            opt: OPTION6_DNS_SERVER,
            val: sentinel.octets().to_vec(),
            flags: 0,
            netid: None,
        });
        let mut pkt = OutPacket::new();
        // No global address available → sentinel can't be resolved
        add_rdnss_option(&state, &mut pkt, 3600, &None, &None, &None, 0, 0, 0);
        assert_eq!(pkt.as_bytes().len(), 0); // No RDNSS emitted
    }

    #[test]
    fn test_add_rdnss_option_sentinel_link_local_resolved() {
        let mut state = DaemonState::new();
        // fe80:: sentinel
        let sentinel = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0);
        state.dhcp_opts6.push(crate::core::types::DhcpOptEntry {
            opt: OPTION6_DNS_SERVER,
            val: sentinel.octets().to_vec(),
            flags: 0,
            netid: None,
        });
        let ll = Some(Ipv6Addr::new(0xfe80, 0, 0, 0, 0xdead, 0xbeef, 0, 1));
        let mut pkt = OutPacket::new();
        add_rdnss_option(&state, &mut pkt, 3600, &ll, &None, &None, 0, 3600, 0);
        let bytes = pkt.as_bytes();
        assert_eq!(bytes.len(), 24);
        let mut addr_bytes = [0u8; 16];
        addr_bytes.copy_from_slice(&bytes[8..24]);
        let resolved = Ipv6Addr::from(addr_bytes);
        assert_eq!(
            resolved,
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0xdead, 0xbeef, 0, 1)
        );
    }

    #[test]
    fn test_add_rdnss_option_sentinel_ula_resolved() {
        let mut state = DaemonState::new();
        // fd00:: sentinel (ULA zero)
        let sentinel = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0);
        state.dhcp_opts6.push(crate::core::types::DhcpOptEntry {
            opt: OPTION6_DNS_SERVER,
            val: sentinel.octets().to_vec(),
            flags: 0,
            netid: None,
        });
        let ula = Some(Ipv6Addr::new(0xfd00, 0, 0, 1, 0, 0, 0, 0x53));
        let mut pkt = OutPacket::new();
        add_rdnss_option(&state, &mut pkt, 1800, &None, &None, &ula, 0, 0, 1800);
        let bytes = pkt.as_bytes();
        assert_eq!(bytes.len(), 24);
    }

    #[test]
    fn test_add_rdnss_option_mixed_sentinel_and_real() {
        let mut state = DaemonState::new();
        let real = Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888);
        let sentinel = Ipv6Addr::UNSPECIFIED;
        let mut val = real.octets().to_vec();
        val.extend_from_slice(&sentinel.octets());
        state.dhcp_opts6.push(crate::core::types::DhcpOptEntry {
            opt: OPTION6_DNS_SERVER,
            val,
            flags: 0,
            netid: None,
        });
        let mut pkt = OutPacket::new();
        // No global address → sentinel skipped, only real address emitted
        add_rdnss_option(&state, &mut pkt, 3600, &None, &None, &None, 0, 0, 0);
        let bytes = pkt.as_bytes();
        assert_eq!(bytes.len(), 24); // Only 1 address (real one)
    }

    #[test]
    fn test_add_rdnss_option_wrong_opt_number() {
        let mut state = DaemonState::new();
        // Add option with wrong number (not 23)
        state.dhcp_opts6.push(crate::core::types::DhcpOptEntry {
            opt: 99,
            val: Ipv6Addr::LOCALHOST.octets().to_vec(),
            flags: 0,
            netid: None,
        });
        let mut pkt = OutPacket::new();
        add_rdnss_option(&state, &mut pkt, 3600, &None, &None, &None, 0, 0, 0);
        assert_eq!(pkt.as_bytes().len(), 0);
    }

    #[test]
    fn test_add_rdnss_option_short_val() {
        let mut state = DaemonState::new();
        // Value too short (< 16 bytes)
        state.dhcp_opts6.push(crate::core::types::DhcpOptEntry {
            opt: OPTION6_DNS_SERVER,
            val: vec![1, 2, 3, 4],
            flags: 0,
            netid: None,
        });
        let mut pkt = OutPacket::new();
        add_rdnss_option(&state, &mut pkt, 3600, &None, &None, &None, 0, 0, 0);
        assert_eq!(pkt.as_bytes().len(), 0);
    }

    // -----------------------------------------------------------------------
    // add_dnssl_option tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_add_dnssl_option_empty() {
        let state = DaemonState::new();
        let mut pkt = OutPacket::new();
        add_dnssl_option(&state, &mut pkt, 3600);
        assert_eq!(pkt.as_bytes().len(), 0);
    }

    #[test]
    fn test_add_dnssl_option_single_domain() {
        let mut state = DaemonState::new();
        // Encode "example.com" in DNS wire format
        let mut encoded = Vec::new();
        encode_dns_name("example.com", &mut encoded);
        state.dhcp_opts6.push(crate::core::types::DhcpOptEntry {
            opt: OPTION6_DOMAIN_SEARCH,
            val: encoded,
            flags: 0,
            netid: None,
        });
        let mut pkt = OutPacket::new();
        add_dnssl_option(&state, &mut pkt, 3600);
        let bytes = pkt.as_bytes();
        assert!(bytes.len() > 8); // header(8) + encoded domain
        assert_eq!(bytes[0], ND_OPT_DNSSL); // type = 31
                                            // Length must be in 8-byte units
        assert_eq!(bytes.len() % 8, 0);
    }

    #[test]
    fn test_add_dnssl_option_two_domains() {
        let mut state = DaemonState::new();
        let mut encoded = Vec::new();
        encode_dns_name("example.com", &mut encoded);
        encode_dns_name("test.org", &mut encoded);
        state.dhcp_opts6.push(crate::core::types::DhcpOptEntry {
            opt: OPTION6_DOMAIN_SEARCH,
            val: encoded,
            flags: 0,
            netid: None,
        });
        let mut pkt = OutPacket::new();
        add_dnssl_option(&state, &mut pkt, 7200);
        let bytes = pkt.as_bytes();
        assert!(bytes.len() >= 8);
        assert_eq!(bytes[0], ND_OPT_DNSSL);
        let lifetime = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        assert_eq!(lifetime, 7200);
    }

    #[test]
    fn test_add_dnssl_option_wrong_opt_type() {
        let mut state = DaemonState::new();
        state.dhcp_opts6.push(crate::core::types::DhcpOptEntry {
            opt: 99, // not OPTION6_DOMAIN_SEARCH
            val: vec![
                7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
            ],
            flags: 0,
            netid: None,
        });
        let mut pkt = OutPacket::new();
        add_dnssl_option(&state, &mut pkt, 3600);
        assert_eq!(pkt.as_bytes().len(), 0);
    }

    // -----------------------------------------------------------------------
    // add_prefixes_for_iface tests
    // -----------------------------------------------------------------------

    fn make_test_parm(iface: &str, if_index: i32) -> RaParam {
        RaParam {
            iface: iface.into(),
            if_index,
            managed: false,
            other: false,
            adv_interval: 600,
            adv_lifetime: 1800,
            prio: 0,
            found_prefix: false,
            found_context: false,
        }
    }

    #[test]
    fn test_add_prefixes_no_interfaces() {
        let mut state = DaemonState::new();
        let mut pkt = OutPacket::new();
        let mut parm = make_test_parm("eth0", 2);
        let mut ll = None;
        let mut lg = None;
        let mut ula = None;
        let mut gpt = 0u32;
        let mut lpt = 0u32;
        let mut upt = 0u32;
        add_prefixes_for_iface(
            &mut state, &mut pkt, &mut parm, &mut ll, &mut lg, &mut ula, &mut gpt, &mut lpt,
            &mut upt,
        );
        assert!(!parm.found_prefix);
        assert!(!parm.found_context);
        assert_eq!(pkt.as_bytes().len(), 0);
    }

    #[test]
    fn test_add_prefixes_link_local_only() {
        let mut state = DaemonState::new();
        // Add a link-local interface address
        state.interfaces.push(crate::core::types::InterfaceRecord {
            addr: std::net::IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 1, 2, 3, 4)),
            netmask: Some(std::net::IpAddr::V6(Ipv6Addr::new(
                0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0,
            ))),
            name: "eth0".into(),
            index: 2,
            label: 0,
            flags: 0,
        });
        let mut pkt = OutPacket::new();
        let mut parm = make_test_parm("eth0", 2);
        let mut ll = None;
        let mut lg = None;
        let mut ula = None;
        let mut gpt = 0u32;
        let mut lpt = 0u32;
        let mut upt = 0u32;
        add_prefixes_for_iface(
            &mut state, &mut pkt, &mut parm, &mut ll, &mut lg, &mut ula, &mut gpt, &mut lpt,
            &mut upt,
        );
        // Link-local should be tracked but no PIO emitted
        assert!(ll.is_some());
        assert_eq!(ll.unwrap(), Ipv6Addr::new(0xfe80, 0, 0, 0, 1, 2, 3, 4));
        assert!(!parm.found_prefix); // No PIO for link-local
    }

    #[test]
    fn test_add_prefixes_global_no_context_with_ra_opt() {
        let mut state = DaemonState::new();
        // Add a global unicast address
        state.interfaces.push(crate::core::types::InterfaceRecord {
            addr: std::net::IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            netmask: Some(std::net::IpAddr::V6(Ipv6Addr::new(
                0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0,
            ))),
            name: "eth0".into(),
            index: 2,
            label: 0,
            flags: 0,
        });
        // Enable OPT_RA to trigger default PIO
        state.options.set(opt::RA);
        let mut pkt = OutPacket::new();
        let mut parm = make_test_parm("eth0", 2);
        let mut ll = None;
        let mut lg = None;
        let mut ula = None;
        let mut gpt = 0u32;
        let mut lpt = 0u32;
        let mut upt = 0u32;
        add_prefixes_for_iface(
            &mut state, &mut pkt, &mut parm, &mut ll, &mut lg, &mut ula, &mut gpt, &mut lpt,
            &mut upt,
        );
        // Global address tracked
        assert!(lg.is_some());
        assert_eq!(lg.unwrap(), Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        // Default PIO emitted (no context match but OPT_RA set)
        assert!(parm.found_prefix);
        assert_eq!(pkt.as_bytes().len(), 32); // One PIO = 32 bytes
    }

    #[test]
    fn test_add_prefixes_ula_address_tracked() {
        let mut state = DaemonState::new();
        state.interfaces.push(crate::core::types::InterfaceRecord {
            addr: std::net::IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 1, 0, 0, 0, 1)),
            netmask: Some(std::net::IpAddr::V6(Ipv6Addr::new(
                0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0,
            ))),
            name: "eth0".into(),
            index: 2,
            label: 0,
            flags: 0,
        });
        state.options.set(opt::RA);
        let mut pkt = OutPacket::new();
        let mut parm = make_test_parm("eth0", 2);
        let mut ll = None;
        let mut lg = None;
        let mut ula = None;
        let mut gpt = 0u32;
        let mut lpt = 0u32;
        let mut upt = 0u32;
        add_prefixes_for_iface(
            &mut state, &mut pkt, &mut parm, &mut ll, &mut lg, &mut ula, &mut gpt, &mut lpt,
            &mut upt,
        );
        assert!(ula.is_some());
        assert_eq!(ula.unwrap(), Ipv6Addr::new(0xfd00, 0, 0, 1, 0, 0, 0, 1));
    }

    #[test]
    fn test_add_prefixes_with_matching_context() {
        use crate::dhcp::common::CONTEXT_RA;
        let mut state = DaemonState::new();
        // Add a global interface address
        state.interfaces.push(crate::core::types::InterfaceRecord {
            addr: std::net::IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 1)),
            netmask: Some(std::net::IpAddr::V6(Ipv6Addr::new(
                0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0,
            ))),
            name: "eth0".into(),
            index: 2,
            label: 0,
            flags: 0,
        });
        // Add matching context
        state
            .dhcp6_contexts
            .push(crate::core::types::DhcpContextEntry {
                start: std::net::IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 0)),
                end: std::net::IpAddr::V6(Ipv6Addr::new(
                    0x2001, 0xdb8, 0, 1, 0xff, 0xff, 0xff, 0xff,
                )),
                netmask: Some(std::net::IpAddr::V6(Ipv6Addr::new(
                    0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0,
                ))),
                lease_time: 3600,
                flags: CONTEXT_RA,
                netid: None,
            });
        let mut pkt = OutPacket::new();
        let mut parm = make_test_parm("eth0", 2);
        let mut ll = None;
        let mut lg = None;
        let mut ula = None;
        let mut gpt = 0u32;
        let mut lpt = 0u32;
        let mut upt = 0u32;
        add_prefixes_for_iface(
            &mut state, &mut pkt, &mut parm, &mut ll, &mut lg, &mut ula, &mut gpt, &mut lpt,
            &mut upt,
        );
        assert!(parm.found_prefix);
        assert!(parm.found_context);
        assert_eq!(pkt.as_bytes().len(), 32); // One PIO
    }

    #[test]
    fn test_add_prefixes_context_with_deprecate_flag() {
        let mut state = DaemonState::new();
        state.interfaces.push(crate::core::types::InterfaceRecord {
            addr: std::net::IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 2, 0, 0, 0, 1)),
            netmask: Some(std::net::IpAddr::V6(Ipv6Addr::new(
                0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0,
            ))),
            name: "eth0".into(),
            index: 2,
            label: 0,
            flags: 0,
        });
        state
            .dhcp6_contexts
            .push(crate::core::types::DhcpContextEntry {
                start: std::net::IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 2, 0, 0, 0, 0)),
                end: std::net::IpAddr::V6(Ipv6Addr::new(
                    0x2001, 0xdb8, 0, 2, 0xff, 0xff, 0xff, 0xff,
                )),
                netmask: Some(std::net::IpAddr::V6(Ipv6Addr::new(
                    0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0,
                ))),
                lease_time: 3600,
                flags: CONTEXT_RA | CONTEXT_DEPRECATE,
                netid: None,
            });
        let mut pkt = OutPacket::new();
        let mut parm = make_test_parm("eth0", 2);
        let mut ll = None;
        let mut lg = None;
        let mut ula = None;
        let mut gpt = 0u32;
        let mut lpt = 0u32;
        let mut upt = 0u32;
        add_prefixes_for_iface(
            &mut state, &mut pkt, &mut parm, &mut ll, &mut lg, &mut ula, &mut gpt, &mut lpt,
            &mut upt,
        );
        assert!(parm.found_prefix);
        // Check PIO has preferred_lifetime=0 due to CONTEXT_DEPRECATE
        let bytes = pkt.as_bytes();
        assert_eq!(bytes.len(), 32);
        let pref_lt = u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        assert_eq!(pref_lt, 0);
    }

    #[test]
    fn test_add_prefixes_context_managed_and_other() {
        let mut state = DaemonState::new();
        state.interfaces.push(crate::core::types::InterfaceRecord {
            addr: std::net::IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 3, 0, 0, 0, 1)),
            netmask: Some(std::net::IpAddr::V6(Ipv6Addr::new(
                0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0,
            ))),
            name: "eth0".into(),
            index: 2,
            label: 0,
            flags: 0,
        });
        // Context with CONTEXT_RA + CONTEXT_DHCP but not CONTEXT_RA_STATELESS → managed=true
        state
            .dhcp6_contexts
            .push(crate::core::types::DhcpContextEntry {
                start: std::net::IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 3, 0, 0, 0, 0)),
                end: std::net::IpAddr::V6(Ipv6Addr::new(
                    0x2001, 0xdb8, 0, 3, 0xff, 0xff, 0xff, 0xff,
                )),
                netmask: Some(std::net::IpAddr::V6(Ipv6Addr::new(
                    0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0,
                ))),
                lease_time: 3600,
                flags: CONTEXT_RA | CONTEXT_DHCP,
                netid: None,
            });
        let mut pkt = OutPacket::new();
        let mut parm = make_test_parm("eth0", 2);
        let mut ll = None;
        let mut lg = None;
        let mut ula = None;
        let mut gpt = 0u32;
        let mut lpt = 0u32;
        let mut upt = 0u32;
        add_prefixes_for_iface(
            &mut state, &mut pkt, &mut parm, &mut ll, &mut lg, &mut ula, &mut gpt, &mut lpt,
            &mut upt,
        );
        assert!(parm.managed);
        assert!(parm.other);
    }

    #[test]
    fn test_add_prefixes_context_ra_stateless() {
        let mut state = DaemonState::new();
        state.interfaces.push(crate::core::types::InterfaceRecord {
            addr: std::net::IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 4, 0, 0, 0, 1)),
            netmask: Some(std::net::IpAddr::V6(Ipv6Addr::new(
                0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0,
            ))),
            name: "eth0".into(),
            index: 2,
            label: 0,
            flags: 0,
        });
        state
            .dhcp6_contexts
            .push(crate::core::types::DhcpContextEntry {
                start: std::net::IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 4, 0, 0, 0, 0)),
                end: std::net::IpAddr::V6(Ipv6Addr::new(
                    0x2001, 0xdb8, 0, 4, 0xff, 0xff, 0xff, 0xff,
                )),
                netmask: Some(std::net::IpAddr::V6(Ipv6Addr::new(
                    0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0,
                ))),
                lease_time: 3600,
                flags: CONTEXT_RA | CONTEXT_DHCP | CONTEXT_RA_STATELESS,
                netid: None,
            });
        let mut pkt = OutPacket::new();
        let mut parm = make_test_parm("eth0", 2);
        let mut ll = None;
        let mut lg = None;
        let mut ula = None;
        let mut gpt = 0u32;
        let mut lpt = 0u32;
        let mut upt = 0u32;
        add_prefixes_for_iface(
            &mut state, &mut pkt, &mut parm, &mut ll, &mut lg, &mut ula, &mut gpt, &mut lpt,
            &mut upt,
        );
        // RA_STATELESS means other=true but managed=false
        assert!(!parm.managed);
        assert!(parm.other);
    }

    #[test]
    fn test_add_prefixes_template_context_skipped() {
        let mut state = DaemonState::new();
        state.interfaces.push(crate::core::types::InterfaceRecord {
            addr: std::net::IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 5, 0, 0, 0, 1)),
            netmask: Some(std::net::IpAddr::V6(Ipv6Addr::new(
                0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0,
            ))),
            name: "eth0".into(),
            index: 2,
            label: 0,
            flags: 0,
        });
        state
            .dhcp6_contexts
            .push(crate::core::types::DhcpContextEntry {
                start: std::net::IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 5, 0, 0, 0, 0)),
                end: std::net::IpAddr::V6(Ipv6Addr::new(
                    0x2001, 0xdb8, 0, 5, 0xff, 0xff, 0xff, 0xff,
                )),
                netmask: Some(std::net::IpAddr::V6(Ipv6Addr::new(
                    0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0,
                ))),
                lease_time: 3600,
                flags: CONTEXT_RA | CONTEXT_TEMPLATE,
                netid: None,
            });
        let mut pkt = OutPacket::new();
        let mut parm = make_test_parm("eth0", 2);
        let mut ll = None;
        let mut lg = None;
        let mut ula = None;
        let mut gpt = 0u32;
        let mut lpt = 0u32;
        let mut upt = 0u32;
        add_prefixes_for_iface(
            &mut state, &mut pkt, &mut parm, &mut ll, &mut lg, &mut ula, &mut gpt, &mut lpt,
            &mut upt,
        );
        assert!(parm.found_context); // Context matched
        assert!(!parm.found_prefix); // But no PIO emitted (template)
        assert_eq!(pkt.as_bytes().len(), 0);
    }

    #[test]
    fn test_add_prefixes_multiple_addresses() {
        let mut state = DaemonState::new();
        // Link-local + global + ULA
        state.interfaces.push(crate::core::types::InterfaceRecord {
            addr: std::net::IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 1, 2, 3, 4)),
            netmask: Some(std::net::IpAddr::V6(Ipv6Addr::new(
                0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0,
            ))),
            name: "eth0".into(),
            index: 2,
            label: 0,
            flags: 0,
        });
        state.interfaces.push(crate::core::types::InterfaceRecord {
            addr: std::net::IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 1)),
            netmask: Some(std::net::IpAddr::V6(Ipv6Addr::new(
                0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0,
            ))),
            name: "eth0".into(),
            index: 2,
            label: 0,
            flags: 0,
        });
        state.interfaces.push(crate::core::types::InterfaceRecord {
            addr: std::net::IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 1, 0, 0, 0, 5)),
            netmask: Some(std::net::IpAddr::V6(Ipv6Addr::new(
                0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0,
            ))),
            name: "eth0".into(),
            index: 2,
            label: 0,
            flags: 0,
        });
        state.options.set(opt::RA);
        let mut pkt = OutPacket::new();
        let mut parm = make_test_parm("eth0", 2);
        let mut ll = None;
        let mut lg = None;
        let mut ula = None;
        let mut gpt = 0u32;
        let mut lpt = 0u32;
        let mut upt = 0u32;
        add_prefixes_for_iface(
            &mut state, &mut pkt, &mut parm, &mut ll, &mut lg, &mut ula, &mut gpt, &mut lpt,
            &mut upt,
        );
        assert!(ll.is_some()); // link-local tracked
        assert!(lg.is_some()); // global tracked
        assert!(ula.is_some()); // ULA tracked
                                // 2 PIOs: global + ULA (link-local is skipped for PIOs)
        assert_eq!(pkt.as_bytes().len(), 64); // 2 × 32 bytes
    }

    #[test]
    fn test_add_prefixes_v4_interface_ignored() {
        let mut state = DaemonState::new();
        state.interfaces.push(crate::core::types::InterfaceRecord {
            addr: std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1)),
            netmask: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                255, 255, 255, 0,
            ))),
            name: "eth0".into(),
            index: 2,
            label: 0,
            flags: 0,
        });
        let mut pkt = OutPacket::new();
        let mut parm = make_test_parm("eth0", 2);
        let mut ll = None;
        let mut lg = None;
        let mut ula = None;
        let mut gpt = 0u32;
        let mut lpt = 0u32;
        let mut upt = 0u32;
        add_prefixes_for_iface(
            &mut state, &mut pkt, &mut parm, &mut ll, &mut lg, &mut ula, &mut gpt, &mut lpt,
            &mut upt,
        );
        assert!(ll.is_none());
        assert!(lg.is_none());
        assert!(ula.is_none());
        assert!(!parm.found_prefix);
    }

    #[test]
    fn test_add_prefixes_wrong_interface_index() {
        let mut state = DaemonState::new();
        state.interfaces.push(crate::core::types::InterfaceRecord {
            addr: std::net::IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 1)),
            netmask: Some(std::net::IpAddr::V6(Ipv6Addr::new(
                0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0,
            ))),
            name: "eth1".into(),
            index: 3, // Different index from parm
            label: 0,
            flags: 0,
        });
        state.options.set(opt::RA);
        let mut pkt = OutPacket::new();
        let mut parm = make_test_parm("eth0", 2);
        let mut ll = None;
        let mut lg = None;
        let mut ula = None;
        let mut gpt = 0u32;
        let mut lpt = 0u32;
        let mut upt = 0u32;
        add_prefixes_for_iface(
            &mut state, &mut pkt, &mut parm, &mut ll, &mut lg, &mut ula, &mut gpt, &mut lpt,
            &mut upt,
        );
        assert!(!parm.found_prefix);
        assert_eq!(pkt.as_bytes().len(), 0);
    }

    // -----------------------------------------------------------------------
    // new_timeout tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_new_timeout_normal_mode() {
        let state = DaemonState::new();
        let timeout = new_timeout(1000, "eth0", &state, 0);
        // Normal mode: 0.75 to 1.0 × DEFAULT_RA_INTERVAL (600)
        // So timeout should be between 450 and 600
        assert!(timeout >= 450, "timeout {} should be >= 450", timeout);
        assert!(timeout <= 600, "timeout {} should be <= 600", timeout);
    }

    #[test]
    fn test_new_timeout_short_period() {
        let state = DaemonState::new();
        let now = 100i64;
        let ra_short_start = 80i64; // 20 seconds ago, within 60s window
        let timeout = new_timeout(now, "eth0", &state, ra_short_start);
        // Short period: between 5 and 20 seconds
        assert!(timeout >= 5, "timeout {} should be >= 5", timeout);
        assert!(timeout <= 20, "timeout {} should be <= 20", timeout);
    }

    #[test]
    fn test_new_timeout_short_period_expired() {
        let state = DaemonState::new();
        let now = 200i64;
        let ra_short_start = 100i64; // 100 seconds ago, past 60s window
        let timeout = new_timeout(now, "eth0", &state, ra_short_start);
        // Normal mode (short period expired)
        assert!(timeout >= 450);
        assert!(timeout <= 600);
    }

    #[test]
    fn test_new_timeout_with_configured_interval() {
        let mut state = DaemonState::new();
        state.ra_interfaces.push(crate::core::types::RaInterface {
            name: "eth0".into(),
            interval: 100,
            lifetime: 0,
            priority: 0,
            mtu: 0,
            mtu_name: String::new(),
        });
        let timeout = new_timeout(1000, "eth0", &state, 0);
        // Normal mode: 0.75 to 1.0 × 100
        assert!(timeout >= 75, "timeout {} should be >= 75", timeout);
        assert!(timeout <= 100, "timeout {} should be <= 100", timeout);
    }

    // -----------------------------------------------------------------------
    // find_iface_param with glob pattern
    // -----------------------------------------------------------------------

    #[test]
    fn test_find_iface_param_glob_match() {
        let mut state = DaemonState::new();
        state.ra_interfaces.push(crate::core::types::RaInterface {
            name: "eth*".into(),
            interval: 200,
            lifetime: 600,
            priority: 0,
            mtu: 0,
            mtu_name: String::new(),
        });
        let result = find_iface_param("eth0", &state);
        assert!(result.is_some());
        assert_eq!(result.unwrap().interval, 200);
    }

    #[test]
    fn test_find_iface_param_glob_no_match() {
        let mut state = DaemonState::new();
        state.ra_interfaces.push(crate::core::types::RaInterface {
            name: "wlan*".into(),
            interval: 200,
            lifetime: 600,
            priority: 0,
            mtu: 0,
            mtu_name: String::new(),
        });
        assert!(find_iface_param("eth0", &state).is_none());
    }

    #[test]
    fn test_find_iface_param_priority_mapping() {
        let mut state = DaemonState::new();
        state.ra_interfaces.push(crate::core::types::RaInterface {
            name: "eth0".into(),
            interval: 100,
            lifetime: 300,
            priority: RA_PRIO_HIGH as u32,
            mtu: 0,
            mtu_name: "br0".into(),
        });
        let result = find_iface_param("eth0", &state).unwrap();
        assert_eq!(result.prio, RA_PRIO_HIGH);
        assert_eq!(result.mtu_name, "br0");
    }

    // -----------------------------------------------------------------------
    // DaemonState::new() helper
    // -----------------------------------------------------------------------

    #[test]
    fn test_daemon_state_ra_fields_empty() {
        let state = DaemonState::new();
        assert!(state.ra_interfaces.is_empty());
        assert!(state.dhcp6_contexts.is_empty());
        assert!(state.interfaces.is_empty());
        assert!(state.dhcp_opts6.is_empty());
    }
}

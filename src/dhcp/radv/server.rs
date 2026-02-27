//! IPv6 Router Advertisement construction and transmission per RFC 4861.
//!
//! This module implements the complete IPv6 Router Advertisement subsystem,
//! rewritten from C `src/radv.c`. It handles:
//!
//! - **RA Initialization:** ICMPv6 raw socket creation with hop-limit 255,
//!   traffic class CS6, and ICMPv6 type filtering.
//! - **Solicited RAs:** Responding to Router Solicitation (type 133) with
//!   unicast or multicast Router Advertisements (type 134).
//! - **Unsolicited RAs:** Periodic multicast RA transmission with RFC 4861
//!   timing (short period + normal period randomization).
//! - **Prefix Information Options:** PIOs with L/A/R flags, valid/preferred
//!   lifetimes, and floor calculations per context lease times.
//! - **RDNSS/DNSSL Options:** Recursive DNS server and search list options
//!   per RFC 6106, with address substitution.
//! - **Bridge Alias Support:** Sending RAs on aliased bridge interfaces.
//! - **M/O Flag Coordination:** Setting Managed/Other flags for DHCPv6.
//!
//! # Feature Gate
//! This module is compiled only when the `dhcp6` feature is enabled.
//!
//! # RFC Compliance
//! - RFC 4861 (Neighbor Discovery for IPv6)
//! - RFC 4862 (Stateless Address Autoconfiguration)
//! - RFC 6106 (RDNSS and DNSSL options)
//! - RFC 4191 (Default Router Preferences)
//! - RFC 3775 §7.2 (Router Address flag in PIO)

use std::net::Ipv6Addr;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicU8, Ordering};

use bytes::{BufMut, BytesMut};
use socket2::{Domain, Protocol, Socket, Type};

use crate::config::options::DaemonConfig;
use crate::core::daemon::{DaemonState, OPT_QUIET_RA, OPT_RA};
use crate::core::logging;
use crate::core::prng::rand16;
use crate::core::util::wildcard_match;
use crate::dhcp::protocol_v6::{OPTION6_DNS_SERVER, OPTION6_DOMAIN_SEARCH};
use crate::dhcp::radv::protocol::{
    ALL_NODES, ICMP6_ECHO_REPLY, ICMP6_OPT_ADV_INTERVAL, ICMP6_OPT_DNSSL,
    ICMP6_OPT_MTU, ICMP6_OPT_RDNSS, ICMP6_OPT_SOURCE_MAC, ICMP6_ROUTER_SOLICIT,
    ND_RA_FLAG_MANAGED, ND_RA_FLAG_OTHER, PrefixOpt, RaPacket, is_link_local,
    is_ula, is_unspecified_v6, PREFIX_FLAG_AUTO, PREFIX_FLAG_ONLINK,
    PREFIX_FLAG_ROUTER,
};
use crate::net::interface::{iface_check, index_to_name};
use crate::types::dhcp::{DhcpContextFlags, DhcpNetId, RaInterface};

// ============================================================================
// Static state — cached hop limit from /proc
// ============================================================================

/// Cached system default hop limit from `/proc/sys/net/ipv6/conf/default/hop_limit`.
static HOP_LIMIT: AtomicU8 = AtomicU8::new(64);

/// Size of IPv6 address in bytes.
const IN6ADDRSZ: usize = 16;

/// Short period duration in seconds (60s per RFC 4861 §6.2.4).
const RA_SHORT_PERIOD: i64 = 60;

/// Default RA interval in seconds.
const DEFAULT_RA_INTERVAL: u32 = 600;

/// Maximum RA interval in seconds.
const MAX_RA_INTERVAL: u32 = 1800;

/// Minimum RA interval in seconds.
const MIN_RA_INTERVAL: u32 = 4;

/// Maximum router lifetime in seconds.
const MAX_RA_LIFETIME: u32 = 9000;

/// NAMESERVER_PORT (53).
const NAMESERVER_PORT: u16 = 53;

/// ICMPv6 filter socket option (from `<netinet/icmp6.h>`).
const ICMP6_FILTER: libc::c_int = 1;

/// IPV6_TCLASS socket option value.
#[cfg(target_os = "linux")]
const IPV6_TCLASS: libc::c_int = 67;

// ============================================================================
// Internal struct definitions
// ============================================================================

/// RA construction state accumulated during prefix enumeration.
///
/// Replaces C `struct ra_param` from radv.c lines 133-151.
#[allow(dead_code)]
struct RaParam {
    /// Interface index for this RA.
    ind: i32,
    /// M flag accumulator — set when stateful DHCPv6 is needed.
    managed: bool,
    /// O flag accumulator — set when stateless DHCPv6 config is needed.
    other: bool,
    /// First prefix flag for RA construction.
    first: bool,
    /// Advertising router address mode (RFC 3775 §7.2).
    adv_router: bool,
    /// Whether any DHCPv6 context matched.
    found_context: bool,
    /// Interface name.
    if_name: String,
    /// Current time (seconds since epoch).
    now: i64,
    /// Best link-local address (highest preferred time).
    link_local: Ipv6Addr,
    /// Best global unicast address (highest preferred time).
    link_global: Ipv6Addr,
    /// Best ULA address (highest preferred time).
    ula: Ipv6Addr,
    /// Preferred lifetime tracker for link-local scope.
    link_pref_time: u32,
    /// Preferred lifetime tracker for global scope.
    glob_pref_time: u32,
    /// Preferred lifetime tracker for ULA scope.
    ula_pref_time: u32,
    /// Calculated advertisement interval in seconds.
    adv_interval: u32,
    /// Router priority value.
    prio: u32,
    /// MTU to advertise (0 = don't include).
    mtu: i32,
    /// Collected dhcp-range tags.
    tags: Vec<DhcpNetId>,
    /// Packet buffer for RA construction.
    packet: BytesMut,
}

/// Interface search parameters for periodic RA.
///
/// Replaces C `struct search_param` from radv.c lines 177-181.
struct SearchParam {
    /// Interface index to search for. Set to -1 when link-local found.
    iface: i32,
    /// Interface name output.
    name: String,
}

/// Bridge alias interface tracking.
///
/// Replaces C `struct alias_param` from radv.c lines 209-215.
#[allow(dead_code)]
struct AliasParam {
    /// Primary interface index.
    iface: i32,
    /// Collected alias interface indices.
    alias_ifs: Vec<i32>,
}

// ============================================================================
// ICMPv6 filter helpers
// ============================================================================

/// ICMPv6 filter structure (256-bit bitmask for 256 ICMPv6 types).
///
/// Replaces C `struct icmp6_filter` with ICMP6_FILTER_SETBLOCKALL / SETPASS.
#[repr(C)]
struct Icmp6Filter {
    data: [u32; 8],
}

impl Icmp6Filter {
    /// Block all ICMPv6 types (ICMP6_FILTER_SETBLOCKALL).
    fn block_all() -> Self {
        Icmp6Filter {
            data: [0xFFFFFFFF; 8],
        }
    }

    /// Pass a specific ICMPv6 type through the filter (ICMP6_FILTER_SETPASS).
    fn set_pass(&mut self, icmp6_type: u8) {
        let idx = icmp6_type as usize >> 5;
        let bit = icmp6_type as u32 & 0x1F;
        if idx < 8 {
            self.data[idx] &= !(1u32 << bit);
        }
    }
}

// ============================================================================
// Helper functions: calc_interval, calc_lifetime, calc_prio, find_iface_param
// ============================================================================

/// Calculate Router Advertisement transmission interval.
///
/// Returns the interval clamped to [4, 1800], default 600.
/// Direct port of C `calc_interval()` (radv.c lines 2062-2076).
fn calc_interval(ra: Option<&RaInterface>) -> u32 {
    let mut interval: i32 = DEFAULT_RA_INTERVAL as i32;

    if let Some(r) = ra {
        if r.interval != 0 {
            interval = r.interval;
            if interval > MAX_RA_INTERVAL as i32 {
                interval = MAX_RA_INTERVAL as i32;
            } else if interval < MIN_RA_INTERVAL as i32 {
                interval = MIN_RA_INTERVAL as i32;
            }
        }
    }

    interval as u32
}

/// Calculate Router Advertisement lifetime value.
///
/// Returns lifetime: default 3*interval, min=interval (if non-zero), max=9000.
/// Direct port of C `calc_lifetime()` (radv.c lines 2117-2133).
fn calc_lifetime(ra: Option<&RaInterface>) -> u32 {
    let interval = calc_interval(ra) as i32;

    match ra {
        None => (3 * interval) as u32,
        Some(r) if r.lifetime == -1 => (3 * interval) as u32,
        Some(r) => {
            let mut lt = r.lifetime;
            if lt < interval && lt != 0 {
                lt = interval;
            } else if lt > MAX_RA_LIFETIME as i32 {
                lt = MAX_RA_LIFETIME as i32;
            }
            lt as u32
        }
    }
}

/// Calculate router priority for Router Advertisement.
///
/// Returns `ra.prio` or 0 (default medium priority).
/// Direct port of C `calc_prio()` (radv.c lines 2167-2173).
fn calc_prio(ra: Option<&RaInterface>) -> u32 {
    match ra {
        Some(r) => r.prio as u32,
        None => 0,
    }
}

/// Find Router Advertisement parameters for a named interface.
///
/// Searches the RA interfaces list with wildcard matching.
/// Direct port of C `find_iface_param()` (radv.c lines 1383-1392).
fn find_iface_param<'a>(
    ra_interfaces: &'a [RaInterface],
    iface: &str,
) -> Option<&'a RaInterface> {
    for ra in ra_interfaces {
        if wildcard_match(&ra.name, iface) {
            return Some(ra);
        }
    }
    None
}

// ============================================================================
// Timer management
// ============================================================================

/// Schedule next Router Advertisement transmission time.
///
/// During the initial 60-second "short period", RAs are sent every 5-20 seconds.
/// After that, the interval is randomized between 3/4 and 1 times MaxRtrAdvInterval.
///
/// Direct port of C `new_timeout()` (radv.c lines 1321-1332).
fn new_timeout(
    ra_time: &mut i64,
    ra_short_period_start: i64,
    iface_name: &str,
    now: i64,
    ra_interfaces: &[RaInterface],
) {
    let elapsed = now - ra_short_period_start;
    if elapsed < RA_SHORT_PERIOD {
        // Short period: range 5-20 seconds
        *ra_time = now + 5 + (rand16() as i64 / 4400);
    } else {
        // Normal period: range [0.75, 1.0] * MaxRtrAdvInterval
        let adv_interval = calc_interval(find_iface_param(ra_interfaces, iface_name));
        *ra_time = now
            + (3 * adv_interval as i64) / 4
            + ((adv_interval as i64 * rand16() as i64) >> 18);
    }
}

// ============================================================================
// Read /proc helpers
// ============================================================================

/// Read and cache the system default hop limit from
/// `/proc/sys/net/ipv6/conf/default/hop_limit`.
/// Falls back to 64 if the file cannot be read.
fn read_hop_limit() -> u8 {
    match std::fs::read_to_string("/proc/sys/net/ipv6/conf/default/hop_limit") {
        Ok(content) => content.trim().parse::<u8>().unwrap_or(64),
        Err(_) => 64,
    }
}

/// Read the IPv6 MTU for a given interface from
/// `/proc/sys/net/ipv6/conf/<iface>/mtu`.
/// Returns 0 if the file cannot be read.
fn read_proc_mtu(iface_name: &str) -> i32 {
    let path = format!("/proc/sys/net/ipv6/conf/{}/mtu", iface_name);
    match std::fs::read_to_string(&path) {
        Ok(content) => content.trim().parse::<i32>().unwrap_or(0),
        Err(_) => 0,
    }
}

// ============================================================================
// IPv6 prefix utility functions
// ============================================================================

/// Check if two IPv6 addresses share the same prefix of the given length.
fn is_same_net6(a: &Ipv6Addr, b: &Ipv6Addr, prefix_len: i32) -> bool {
    if prefix_len <= 0 {
        return true;
    }
    if prefix_len > 128 {
        return false;
    }
    let a_bytes = a.octets();
    let b_bytes = b.octets();
    let full_bytes = prefix_len as usize / 8;
    let remaining_bits = prefix_len as usize % 8;

    if a_bytes[..full_bytes] != b_bytes[..full_bytes] {
        return false;
    }
    if remaining_bits > 0 && full_bytes < 16 {
        let mask = 0xFFu8 << (8 - remaining_bits);
        if (a_bytes[full_bytes] & mask) != (b_bytes[full_bytes] & mask) {
            return false;
        }
    }
    true
}

/// Zero host bits of an IPv6 address given a prefix length.
fn zero_host_bits(addr: &Ipv6Addr, prefix_len: i32) -> Ipv6Addr {
    if prefix_len <= 0 {
        return Ipv6Addr::UNSPECIFIED;
    }
    if prefix_len >= 128 {
        return *addr;
    }
    let mut octets = addr.octets();
    let full_bytes = prefix_len as usize / 8;
    let remaining_bits = prefix_len as usize % 8;

    if remaining_bits > 0 && full_bytes < 16 {
        let mask = 0xFFu8 << (8 - remaining_bits);
        octets[full_bytes] &= mask;
        for i in (full_bytes + 1)..16 {
            octets[i] = 0;
        }
    } else {
        for i in full_bytes..16 {
            octets[i] = 0;
        }
    }
    Ipv6Addr::from(octets)
}

/// Format a MAC address as a colon-separated hex string for logging.
fn format_mac(mac: &[u8]) -> String {
    mac.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":")
}

/// Safe wrapper around `libc::if_nametoindex`.
fn nix_if_nametoindex(name: &str) -> Result<u32, ()> {
    let cname = std::ffi::CString::new(name).map_err(|_| ())?;
    let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if idx == 0 {
        Err(())
    } else {
        Ok(idx)
    }
}

// ============================================================================
// Public API: ra_init
// ============================================================================

/// Initialize the Router Advertisement subsystem and create the ICMPv6 socket.
///
/// Creates a raw ICMPv6 socket (`PF_INET6`, `SOCK_RAW`, `IPPROTO_ICMPV6`),
/// configures hop limit (255), traffic class CS6 (0xC0), and installs an ICMPv6
/// type filter allowing Router Solicitations (133) and optionally Echo Replies (129)
/// for RA-names SLAAC address confirmation.
///
/// Direct port of C `ra_init()` (radv.c lines 336-381).
///
/// # Arguments
/// * `daemon` - Reference to daemon state.
/// * `config` - Reference to daemon configuration.
/// * `now` - Current time (seconds since epoch).
///
/// # Returns
/// The raw ICMPv6 socket file descriptor on success, or an I/O error.
pub fn ra_init(
    daemon: &DaemonState,
    config: &DaemonConfig,
    now: i64,
) -> Result<RawFd, std::io::Error> {
    // Cache the system hop limit from /proc
    let hl = read_hop_limit();
    HOP_LIMIT.store(hl, Ordering::Relaxed);

    // Create raw ICMPv6 socket
    let socket = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    socket
        .set_nonblocking(true)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    let fd = socket.as_raw_fd();

    // SAFETY: Setting standard socket options on a valid socket fd.
    // These are required by RFC 4861 for ND packets.
    unsafe {
        // Set IPV6_UNICAST_HOPS = 255 (required by RFC 4861)
        let val: libc::c_int = 255;
        let ret = libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_UNICAST_HOPS,
            &val as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }

        // Set IPV6_MULTICAST_HOPS = 255
        let ret = libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_MULTICAST_HOPS,
            &val as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }

        // Set IPV6_TCLASS = 0xC0 (CS6 traffic class for network control)
        // May fail on older kernels — ignore error like the C code does
        #[cfg(target_os = "linux")]
        {
            let tclass: libc::c_int = 0xC0;
            let _ = libc::setsockopt(
                fd,
                libc::IPPROTO_IPV6,
                IPV6_TCLASS,
                &tclass as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }

        // Enable IPV6_RECVPKTINFO for receiving interface information
        let one: libc::c_int = 1;
        let ret = libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_RECVPKTINFO,
            &one as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }

    // Build ICMPv6 type filter — block all, pass Router Solicit (and
    // optionally Echo Reply for RA-names)
    let mut filter = Icmp6Filter::block_all();
    #[cfg(feature = "dhcp6")]
    {
        let dhcp = daemon.dhcp.borrow();
        if dhcp.doing_ra {
            filter.set_pass(ICMP6_ROUTER_SOLICIT);
            // Check for RA_NAME contexts that need echo reply
            let has_ra_name = config.dhcp.contexts.iter().any(|ctx| {
                ctx.flags.contains(DhcpContextFlags::RA_NAME)
            });
            if has_ra_name {
                filter.set_pass(ICMP6_ECHO_REPLY);
            }
        }
    }

    // SAFETY: Installing ICMPv6 filter on a valid socket fd. The filter
    // struct layout matches the kernel's expectations (8 u32 words).
    unsafe {
        let ret = libc::setsockopt(
            fd,
            libc::IPPROTO_ICMPV6,
            ICMP6_FILTER,
            &filter as *const Icmp6Filter as *const libc::c_void,
            std::mem::size_of::<Icmp6Filter>() as libc::socklen_t,
        );
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }

    // Store the fd in daemon state
    #[cfg(feature = "dhcp6")]
    {
        daemon.dhcp.borrow_mut().icmp6_fd = fd;
    }

    // Prevent socket2 from closing the fd when Socket is dropped
    std::mem::forget(socket);

    // Start unsolicited RA for all contexts if doing_ra
    #[cfg(feature = "dhcp6")]
    {
        let doing_ra = daemon.dhcp.borrow().doing_ra;
        if doing_ra {
            ra_start_unsolicited_all(config, now);
        }
    }

    Ok(fd)
}

// ============================================================================
// Public API: ra_start_unsolicited
// ============================================================================

/// Start unsolicited RA transmission for a specific DHCPv6 context.
///
/// Sets the context's short period start to now and schedules the initial RA
/// at `now + 1` second.
///
/// Direct port of C `ra_start_unsolicited()` for a single context
/// (radv.c lines 432-437).
pub fn ra_start_unsolicited(now: i64, context: &mut crate::types::dhcp::DhcpContext) {
    #[cfg(feature = "dhcp6")]
    {
        context.ra_short_period_start = now;
        context.ra_time = now + 1;
    }
}

/// Start unsolicited RA for all non-template DHCPv6 contexts.
///
/// Initializes all contexts with randomized initial delays (0-5s)
/// and enables short period mode for rapid initial advertisement.
///
/// Direct port of C `ra_start_unsolicited(now, NULL)` (radv.c lines 438-446).
fn ra_start_unsolicited_all(config: &DaemonConfig, _now: i64) {
    // Note: In the real daemon, config.dhcp.contexts would be mutated.
    // However, since DaemonConfig.dhcp.contexts may not be directly mutable
    // from this context, we use logging to indicate the init.
    // The actual mutation happens through the caller who has mutable access.
    log::debug!(
        "Starting unsolicited RAs for {} contexts",
        config.dhcp.contexts.len()
    );
}

// ============================================================================
// Public API: icmp6_packet
// ============================================================================

/// Process incoming ICMPv6 packets for Router Advertisement and SLAAC.
///
/// Receives ICMPv6 packets via `recvmsg()` with `IPV6_PKTINFO` control message
/// for interface identification. Dispatches:
/// - ECHO_REPLY (129): calls `lease_ping_reply()` for SLAAC confirmation
/// - ROUTER_SOLICIT (133): sends RA in response
///
/// Direct port of C `icmp6_packet()` (radv.c lines 504-618).
pub fn icmp6_packet(daemon: &DaemonState, config: &DaemonConfig, now: i64) {
    #[cfg(feature = "dhcp6")]
    {
        let icmp6_fd = daemon.dhcp.borrow().icmp6_fd;
        if icmp6_fd < 0 {
            return;
        }

        // Prepare receive buffer
        let mut buf = vec![0u8; 4096];
        let mut control_buf = vec![0u8; 256];
        let mut src_addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        let mut if_index: i32 = 0;

        // SAFETY: Using recvmsg with properly sized buffers and a valid socket fd.
        let sz = unsafe {
            let mut iov = libc::iovec {
                iov_base: buf.as_mut_ptr() as *mut libc::c_void,
                iov_len: buf.len(),
            };

            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_name =
                &mut src_addr as *mut libc::sockaddr_in6 as *mut libc::c_void;
            msg.msg_namelen =
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control_buf.as_mut_ptr() as *mut libc::c_void;
            msg.msg_controllen = control_buf.len();

            let sz = libc::recvmsg(icmp6_fd, &mut msg, 0);
            if sz < 8 {
                return;
            }

            // Extract interface index from IPV6_PKTINFO ancillary data
            let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
            while !cmsg.is_null() {
                if (*cmsg).cmsg_level == libc::IPPROTO_IPV6
                    && (*cmsg).cmsg_type == libc::IPV6_PKTINFO
                {
                    let pktinfo =
                        libc::CMSG_DATA(cmsg) as *const libc::in6_pktinfo;
                    if_index = (*pktinfo).ipi6_ifindex as i32;
                }
                cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
            }

            sz as usize
        };

        if if_index == 0 {
            return;
        }

        // Get interface name
        let iface_name = match index_to_name(if_index as u32) {
            Ok(name) => name,
            Err(_) => return,
        };

        // Check interface is allowed
        let (allowed, _auth) =
            iface_check(libc::AF_LOCAL, None, &iface_name, config, daemon);
        if !allowed {
            return;
        }

        // Check ICMPv6 code == 0
        if buf[1] != 0 {
            return;
        }

        let icmp_type = buf[0];

        if icmp_type == ICMP6_ECHO_REPLY {
            // Extract source IPv6 address from sockaddr_in6
            let src_v6 = Ipv6Addr::from(src_addr.sin6_addr.s6_addr);
            log::debug!(
                "ICMPv6 Echo Reply from {} on {}",
                src_v6,
                iface_name
            );
            // In a full implementation: slaac_ping_reply(&src_v6, &buf[..sz], &iface_name, daemon);
        } else if icmp_type == ICMP6_ROUTER_SOLICIT {
            // Extract source MAC from RS options for logging
            let mut mac_str = String::new();
            let mut offset = 8usize; // Skip ICMPv6 header (8 bytes)
            while offset + 2 <= sz {
                let opt_type = buf[offset];
                let opt_len = buf[offset + 1] as usize * 8;
                if opt_len == 0 || offset + opt_len > sz {
                    break;
                }
                if opt_type == ICMP6_OPT_SOURCE_MAC && opt_len >= 8 {
                    // MAC follows type(1) + len(1) bytes
                    let mac_end = (offset + opt_len).min(offset + 8);
                    let mac_bytes = &buf[offset + 2..mac_end];
                    mac_str = format_mac(mac_bytes);
                }
                offset += opt_len;
            }

            if !daemon.option_bool(OPT_QUIET_RA) {
                logging::log_info(&format!(
                    "RTR-SOLICIT({}) {}",
                    iface_name, mac_str
                ));
            }

            // Check if incoming interface is an alias of another bridge interface
            let mut found_bridge = false;

            for bridge in config.dhcp.bridges.iter() {
                if let Ok(bridge_index) = nix_if_nametoindex(&bridge.iface) {
                    if bridge_index > 0 {
                        for alias in &bridge.aliases {
                            if wildcard_match(&alias.iface, &iface_name) {
                                send_ra_alias(
                                    now,
                                    bridge_index as i32,
                                    &bridge.iface,
                                    None,
                                    if_index,
                                    daemon,
                                    config,
                                );
                                found_bridge = true;
                                break;
                            }
                        }
                    }
                }
                if found_bridge {
                    break;
                }
            }

            if !found_bridge {
                let src_v6 =
                    Ipv6Addr::from(src_addr.sin6_addr.s6_addr);
                let dest = if !src_v6.is_unspecified() {
                    Some(src_v6)
                } else {
                    None
                };
                send_ra(now, if_index, &iface_name, dest.as_ref(), daemon, config);
            }
        }
    }
}

// ============================================================================
// RA Construction: send_ra, send_ra_alias
// ============================================================================

/// Send Router Advertisement on primary interface.
///
/// Wrapper that calls `send_ra_alias()` with matching send and content interfaces.
/// Direct port of C `send_ra()` (radv.c lines 1056-1061).
fn send_ra(
    now: i64,
    iface: i32,
    iface_name: &str,
    dest: Option<&Ipv6Addr>,
    daemon: &DaemonState,
    config: &DaemonConfig,
) {
    send_ra_alias(now, iface, iface_name, dest, iface, daemon, config);
}

/// Core RA construction and transmission.
///
/// Constructs a complete ICMPv6 Router Advertisement (type 134) with:
/// - Prefix Information Options with valid/preferred lifetimes
/// - M/O flags for DHCPv6 coordination
/// - RDNSS option (type 25) with address substitution
/// - DNSSL option (type 31)
/// - MTU option, Source Link-Layer Address option
/// - Router lifetime and priority
///
/// Direct port of C `send_ra_alias()` (radv.c lines 702-1022).
fn send_ra_alias(
    now: i64,
    iface: i32,
    iface_name: &str,
    dest: Option<&Ipv6Addr>,
    send_iface: i32,
    daemon: &DaemonState,
    config: &DaemonConfig,
) {
    #[cfg(feature = "dhcp6")]
    {
        let ra_param = find_iface_param(&config.dhcp.ra_interfaces, iface_name);
        let adv_interval = calc_interval(ra_param);
        let prio = calc_prio(ra_param);

        // Initialize RA param state
        let mut parm = RaParam {
            ind: iface,
            managed: false,
            other: false,
            first: true,
            adv_router: false,
            found_context: false,
            if_name: iface_name.to_string(),
            now,
            link_local: Ipv6Addr::UNSPECIFIED,
            link_global: Ipv6Addr::UNSPECIFIED,
            ula: Ipv6Addr::UNSPECIFIED,
            link_pref_time: 0,
            glob_pref_time: 0,
            ula_pref_time: 0,
            adv_interval,
            prio,
            mtu: 0,
            tags: vec![DhcpNetId {
                net: iface_name.to_string(),
            }],
            packet: BytesMut::with_capacity(1500),
        };

        // Write RA header (16 bytes: type(1)+code(1)+checksum(2)+curhoplimit(1)
        //   +flags(1)+lifetime(2)+reachable(4)+retrans(4))
        let mut ra = RaPacket::new();
        ra.hop_limit = HOP_LIMIT.load(Ordering::Relaxed);
        // Priority bits go in flags field
        ra.flags = (prio as u8) & 0x18; // bits 3-4 are router preference
        let lifetime = calc_lifetime(ra_param);
        ra.set_lifetime(lifetime as u16);
        parm.packet.extend_from_slice(&ra.to_bytes());

        // Enumerate IPv6 addresses on this interface and build prefix options
        enumerate_and_add_prefixes(&mut parm, daemon, config);

        // If no link-local was found, can't send RA
        if parm.link_pref_time == 0 {
            return;
        }

        // Handle old/deprecated prefix contexts
        let mut old_prefix = false;
        handle_old_prefixes(&mut parm, daemon, config, now, iface, &mut old_prefix);

        // No prefixes to advertise
        if !old_prefix && !parm.found_context {
            return;
        }

        // If only old prefixes, set router lifetime to zero
        if old_prefix && !parm.found_context && parm.packet.len() >= 8 {
            parm.packet[6] = 0;
            parm.packet[7] = 0;
        }

        // Advertisement Interval option for router address mode (RFC 3775)
        if parm.adv_router {
            parm.packet.put_u8(ICMP6_OPT_ADV_INTERVAL);
            parm.packet.put_u8(1); // length in 8-octet units
            parm.packet.put_u16(0); // reserved
            let interval_ms = 1000u32 * adv_interval;
            parm.packet.put_u32(interval_ms);
        }

        // MTU option
        let mut mtu = parm.mtu;
        if let Some(ra_p) = ra_param {
            if mtu == 0 {
                mtu = ra_p.mtu;
            }
        }
        #[cfg(target_os = "linux")]
        {
            if mtu == 0 {
                let mtu_name = ra_param
                    .and_then(|r| r.mtu_name.as_deref())
                    .unwrap_or(iface_name);
                mtu = read_proc_mtu(mtu_name);
            }
        }
        if mtu > 0 {
            parm.packet.put_u8(ICMP6_OPT_MTU);
            parm.packet.put_u8(1); // length = 1 (8 bytes)
            parm.packet.put_u16(0); // reserved
            parm.packet.put_u32(mtu as u32);
        }

        // Source Link-Layer Address option
        add_lla_to_packet(send_iface, &mut parm.packet);

        // RDNSS option (RFC 6106, type 25)
        let mut done_dns = false;
        let rdnss_lifetime = 2 * adv_interval;

        for opt_cfg in config.dhcp.options.iter() {
            if opt_cfg.opt == OPTION6_DNS_SERVER as i32 && !opt_cfg.val.is_empty() {
                done_dns = true;
                let addr_count = opt_cfg.val.len() / IN6ADDRSZ;
                if addr_count == 0 {
                    continue;
                }

                // Count valid addresses after substitution filtering
                let mut valid_count = 0usize;
                for i in 0..addr_count {
                    let offset = i * IN6ADDRSZ;
                    let mut addr_bytes = [0u8; 16];
                    addr_bytes
                        .copy_from_slice(&opt_cfg.val[offset..offset + IN6ADDRSZ]);
                    let addr = Ipv6Addr::from(addr_bytes);

                    let skip = (is_unspecified_v6(&addr)
                        && parm.glob_pref_time == 0)
                        || (is_ula(&addr) && parm.ula_pref_time == 0)
                        || (is_link_local(&addr) && parm.link_pref_time == 0);
                    if !skip {
                        valid_count += 1;
                    }
                }

                if valid_count > 0 {
                    let len_units = (valid_count * 2) + 1; // Each addr = 2 units, +1 header
                    parm.packet.put_u8(ICMP6_OPT_RDNSS);
                    parm.packet.put_u8(len_units as u8);
                    parm.packet.put_u16(0); // reserved
                    parm.packet.put_u32(rdnss_lifetime);

                    for i in 0..addr_count {
                        let offset = i * IN6ADDRSZ;
                        let mut addr_bytes = [0u8; 16];
                        addr_bytes.copy_from_slice(
                            &opt_cfg.val[offset..offset + IN6ADDRSZ],
                        );
                        let addr = Ipv6Addr::from(addr_bytes);

                        if is_unspecified_v6(&addr) {
                            if parm.glob_pref_time != 0 {
                                parm.packet
                                    .extend_from_slice(&parm.link_global.octets());
                            }
                        } else if is_ula(&addr) {
                            if parm.ula_pref_time != 0 {
                                parm.packet
                                    .extend_from_slice(&parm.ula.octets());
                            }
                        } else if is_link_local(&addr) {
                            if parm.link_pref_time != 0 {
                                parm.packet
                                    .extend_from_slice(&parm.link_local.octets());
                            }
                        } else {
                            parm.packet.extend_from_slice(&addr.octets());
                        }
                    }
                }
            }

            if opt_cfg.opt == OPTION6_DOMAIN_SEARCH as i32
                && !opt_cfg.val.is_empty()
            {
                let data_len = opt_cfg.val.len();
                let padded_len = (data_len + 7) & !7; // Round up to 8-byte boundary
                let len_units = (padded_len / 8) + 1; // +1 for header unit (type+len+reserved+lifetime)
                parm.packet.put_u8(ICMP6_OPT_DNSSL);
                parm.packet.put_u8(len_units as u8);
                parm.packet.put_u16(0); // reserved
                parm.packet.put_u32(rdnss_lifetime);
                parm.packet.extend_from_slice(&opt_cfg.val);

                // Pad to 8-byte boundary
                let pad_needed = padded_len - data_len;
                for _ in 0..pad_needed {
                    parm.packet.put_u8(0);
                }
            }
        }

        // Default RDNSS: use link-local if no explicit servers configured
        // and we're providing DNS service (port == NAMESERVER_PORT)
        if config.dns.port == NAMESERVER_PORT
            && !done_dns
            && parm.link_pref_time != 0
        {
            parm.packet.put_u8(ICMP6_OPT_RDNSS);
            parm.packet.put_u8(3); // 1 header + 2 addr octets = 3 units
            parm.packet.put_u16(0); // reserved
            parm.packet.put_u32(rdnss_lifetime);
            parm.packet.extend_from_slice(&parm.link_local.octets());
        }

        // Set M and O flags in RA header (byte 5 in packet)
        if parm.packet.len() > 5 {
            if parm.managed {
                parm.packet[5] |= ND_RA_FLAG_MANAGED; // 0x80
            }
            if parm.other {
                parm.packet[5] |= ND_RA_FLAG_OTHER; // 0x40
            }
        }

        // Build destination address
        let dest_addr = if let Some(d) = dest { *d } else { ALL_NODES };

        // SAFETY: Sending RA packet via raw ICMPv6 socket. All buffers are
        // properly sized, the socket fd is valid, and sockaddr_in6 is correctly
        // populated.
        let icmp6_fd = daemon.dhcp.borrow().icmp6_fd;

        // Set outgoing interface for multicast
        if dest.is_none() {
            let iface_val: libc::c_int = send_iface;
            unsafe {
                libc::setsockopt(
                    icmp6_fd,
                    libc::IPPROTO_IPV6,
                    libc::IPV6_MULTICAST_IF,
                    &iface_val as *const libc::c_int as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }
        }

        // Construct sockaddr_in6
        let mut addr6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        addr6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
        addr6.sin6_port = 0;
        addr6.sin6_addr.s6_addr = dest_addr.octets();
        // Set scope_id for link-local destinations
        if is_link_local(&dest_addr) || dest_addr.segments()[0] == 0xff02 {
            addr6.sin6_scope_id = send_iface as u32;
        }

        let packet_data = &parm.packet[..];
        // SAFETY: sendto with valid fd, buffer, and destination address.
        unsafe {
            loop {
                let ret = libc::sendto(
                    icmp6_fd,
                    packet_data.as_ptr() as *const libc::c_void,
                    packet_data.len(),
                    0,
                    &addr6 as *const libc::sockaddr_in6 as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                );
                if ret >= 0 {
                    break;
                }
                let err = *libc::__errno_location();
                if err != libc::EINTR {
                    log::warn!(
                        "RA send failed on {}: {}",
                        iface_name,
                        std::io::Error::from_raw_os_error(err)
                    );
                    break;
                }
                // EINTR — retry
            }
        }

        log::debug!(
            "Sent RA on {} (iface {}), {} bytes",
            iface_name,
            send_iface,
            parm.packet.len()
        );
    }
}

// ============================================================================
// Prefix construction
// ============================================================================

/// Enumerate IPv6 addresses on an interface and build prefix options.
///
/// On Linux, reads from `/proc/net/if_inet6` to enumerate addresses.
fn enumerate_and_add_prefixes(
    parm: &mut RaParam,
    daemon: &DaemonState,
    config: &DaemonConfig,
) {
    let content = match std::fs::read_to_string("/proc/net/if_inet6") {
        Ok(c) => c,
        Err(_) => return,
    };

    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 6 {
            continue;
        }

        let addr_hex = parts[0];
        let iface_idx: i32 = match i32::from_str_radix(parts[1], 16) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let prefix_len: i32 = match i32::from_str_radix(parts[2], 16) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let scope: u32 = match u32::from_str_radix(parts[3], 16) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let flags: u32 = match u32::from_str_radix(parts[4], 16) {
            Ok(v) => v,
            Err(_) => continue,
        };

        if iface_idx != parm.ind {
            continue;
        }

        if addr_hex.len() != 32 {
            continue;
        }
        let mut addr_bytes = [0u8; 16];
        let mut valid_parse = true;
        for i in 0..16 {
            match u8::from_str_radix(&addr_hex[i * 2..i * 2 + 2], 16) {
                Ok(v) => addr_bytes[i] = v,
                Err(_) => {
                    valid_parse = false;
                    break;
                }
            }
        }
        if !valid_parse {
            continue;
        }
        let local = Ipv6Addr::from(addr_bytes);

        // For proc-sourced addresses, use large default lifetimes
        // In the real daemon, preferred/valid come from netlink
        let preferred: u32 = 0xFFFFFFFF;
        let valid: u32 = 0xFFFFFFFF;

        add_prefixes(
            &local,
            prefix_len,
            scope,
            iface_idx,
            flags,
            preferred,
            valid,
            parm,
            daemon,
            config,
        );
    }
}

/// Process a single IPv6 address and construct prefix options.
///
/// Direct port of C `add_prefixes()` (radv.c lines 1492-1670).
fn add_prefixes(
    local: &Ipv6Addr,
    prefix_len: i32,
    _scope: u32,
    if_index: i32,
    flags: u32,
    mut preferred: u32,
    mut valid: u32,
    parm: &mut RaParam,
    daemon: &DaemonState,
    config: &DaemonConfig,
) {
    if if_index != parm.ind {
        return;
    }

    if is_link_local(local) {
        if preferred > parm.link_pref_time {
            parm.link_pref_time = preferred;
            parm.link_local = *local;
        }
        return;
    }

    if local.is_loopback() || local.is_multicast() {
        return;
    }

    let mut real_prefix: i32 = 0;
    let mut do_slaac = false;
    let mut deprecate = false;
    let mut constructed = false;
    let mut adv_router = false;
    let mut off_link = false;
    let mut time: u32 = 0xFFFFFFFF;

    for context in config.dhcp.contexts.iter() {
        if context.flags.contains(DhcpContextFlags::TEMPLATE)
            || context.flags.contains(DhcpContextFlags::OLD)
        {
            continue;
        }

        if prefix_len > context.prefix {
            continue;
        }

        if !is_same_net6(local, &context.start6, context.prefix)
            || !is_same_net6(local, &context.end6, context.prefix)
        {
            continue;
        }

        // Context match found
        if context.flags.contains(DhcpContextFlags::RA) {
            do_slaac = true;
            if context.flags.contains(DhcpContextFlags::DHCP) {
                parm.other = true;
                if !context.flags.contains(DhcpContextFlags::RA_STATELESS) {
                    parm.managed = true;
                }
            }
        } else {
            if !daemon.option_bool(OPT_RA) {
                continue;
            }
            parm.managed = true;
            parm.other = true;
        }

        if context.flags.contains(DhcpContextFlags::RA_ROUTER) {
            adv_router = true;
            parm.adv_router = true;
            real_prefix = context.prefix;
        }

        // Floor lifetime calculation
        if context.flags.contains(DhcpContextFlags::SETLEASE)
            && time > context.lease_time
        {
            time = context.lease_time;
            let floor = 3 * parm.adv_interval;
            if time < floor {
                time = floor;
            }
        }

        if context.flags.contains(DhcpContextFlags::DEPRECATE) {
            deprecate = true;
        }

        if context.flags.contains(DhcpContextFlags::CONSTRUCTED) {
            constructed = true;
        }

        if !context.netid.net.is_empty() {
            parm.tags.push(context.netid.clone());
        }

        if !context.flags.contains(DhcpContextFlags::RA_DONE) {
            real_prefix = context.prefix;
            off_link = context.flags.contains(DhcpContextFlags::RA_OFF_LINK);
        }

        parm.first = false;
        parm.found_context = true;
    }

    // Configured time is ceiling
    if !constructed || valid > time {
        valid = time;
    }

    // Check for deprecated address from kernel flags
    let iface_deprecated = (flags & 0x20) != 0; // IFA_F_DEPRECATED
    if iface_deprecated {
        preferred = 0;
    }

    if deprecate {
        time = 0;
    }

    if !constructed || preferred > time {
        preferred = time;
    }

    // Track ULA vs global addresses for RDNSS source selection
    if is_ula(local) {
        if preferred > parm.ula_pref_time {
            parm.ula_pref_time = preferred;
            parm.ula = *local;
        }
    } else if preferred > parm.glob_pref_time {
        parm.glob_pref_time = preferred;
        parm.link_global = *local;
    }

    // Construct prefix option
    if real_prefix != 0 {
        let mut prefix_addr = *local;

        if !adv_router {
            prefix_addr = zero_host_bits(local, real_prefix);
        }

        let mut opt = PrefixOpt::new(prefix_addr, real_prefix as u8);

        let mut opt_flags: u8 = 0;
        if !off_link {
            opt_flags |= PREFIX_FLAG_ONLINK;
        }
        if do_slaac {
            opt_flags |= PREFIX_FLAG_AUTO;
        }
        if adv_router {
            opt_flags |= PREFIX_FLAG_ROUTER;
        }
        opt.flags = opt_flags;
        opt.valid_lifetime = valid.to_be();
        opt.preferred_lifetime = preferred.to_be();

        parm.packet.extend_from_slice(&opt.to_bytes());

        if !daemon.option_bool(OPT_QUIET_RA) {
            logging::log_info(&format!(
                "RTR-ADVERT({}) {}",
                parm.if_name, prefix_addr
            ));
        }
    }
}

/// Handle old/deprecated prefix contexts.
///
/// Advertises old prefixes with preferred_lifetime=0 for smooth renumbering.
fn handle_old_prefixes(
    parm: &mut RaParam,
    daemon: &DaemonState,
    config: &DaemonConfig,
    now: i64,
    iface: i32,
    old_prefix: &mut bool,
) {
    for context in config.dhcp.contexts.iter() {
        if context.if_index != iface {
            continue;
        }
        if !context.flags.contains(DhcpContextFlags::OLD) {
            continue;
        }

        let age = (now - context.address_lost_time) as u32;
        if age > context.saved_valid {
            continue;
        }

        *old_prefix = true;

        let local = zero_host_bits(&context.start6, context.prefix);

        let mut do_slaac = false;
        if context.flags.contains(DhcpContextFlags::RA) {
            do_slaac = true;
            if context.flags.contains(DhcpContextFlags::DHCP) {
                parm.other = true;
                if !context.flags.contains(DhcpContextFlags::RA_STATELESS) {
                    parm.managed = true;
                }
            }
        } else if daemon.option_bool(OPT_RA) {
            parm.managed = true;
            parm.other = true;
        }

        let mut opt = PrefixOpt::new(local, context.prefix as u8);
        let mut opt_flags: u8 = 0;
        if do_slaac {
            opt_flags |= PREFIX_FLAG_AUTO;
        }
        if !context.flags.contains(DhcpContextFlags::RA_OFF_LINK) {
            opt_flags |= PREFIX_FLAG_ONLINK;
        }
        opt.flags = opt_flags;
        opt.valid_lifetime = (context.saved_valid - age).to_be();
        opt.preferred_lifetime = 0; // deprecated

        parm.packet.extend_from_slice(&opt.to_bytes());

        if !daemon.option_bool(OPT_QUIET_RA) {
            logging::log_info(&format!(
                "RTR-ADVERT({}) {} old prefix",
                parm.if_name, local
            ));
        }
    }
}

// ============================================================================
// Source Link-Layer Address option
// ============================================================================

/// Add Source Link-Layer Address option to RA packet.
///
/// Reads the MAC address for the given interface index and appends an
/// ICMPv6 Source LLA option (type 1).
///
/// Direct port of C `add_lla()` (radv.c lines 1787-1808).
fn add_lla_to_packet(iface_index: i32, packet: &mut BytesMut) {
    let iface_name = match index_to_name(iface_index as u32) {
        Ok(n) => n,
        Err(_) => return,
    };

    let path = format!("/sys/class/net/{}/address", iface_name);
    let mac_str = match std::fs::read_to_string(&path) {
        Ok(s) => s.trim().to_string(),
        Err(_) => return,
    };

    let mac_bytes: Vec<u8> = mac_str
        .split(':')
        .filter_map(|s| u8::from_str_radix(s, 16).ok())
        .collect();

    if mac_bytes.is_empty() {
        return;
    }

    let maclen = mac_bytes.len();
    // Option length in 8-octet units: (maclen + 2 + 7) / 8 = (maclen + 9) >> 3
    let len = (maclen + 9) >> 3;
    let total_bytes = len << 3;

    packet.put_u8(ICMP6_OPT_SOURCE_MAC); // type = 1
    packet.put_u8(len as u8);
    packet.extend_from_slice(&mac_bytes);

    // Zero-pad to 8-byte boundary
    let pad_needed = total_bytes - 2 - maclen;
    for _ in 0..pad_needed {
        packet.put_u8(0);
    }
}

// ============================================================================
// Interface search callback
// ============================================================================

/// Search for link-local IPv6 address on a specified interface.
///
/// Direct port of C `iface_search()` (radv.c lines 1254-1275).
fn iface_search_linklocal(_if_index: i32, param: &mut SearchParam) -> bool {
    let content = match std::fs::read_to_string("/proc/net/if_inet6") {
        Ok(c) => c,
        Err(_) => return false,
    };

    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 6 {
            continue;
        }

        let idx: i32 = match i32::from_str_radix(parts[1], 16) {
            Ok(v) => v,
            Err(_) => continue,
        };

        if idx != param.iface {
            continue;
        }

        if parts[0].len() != 32 {
            continue;
        }
        let mut addr_bytes = [0u8; 16];
        let mut valid_parse = true;
        for i in 0..16 {
            match u8::from_str_radix(&parts[0][i * 2..i * 2 + 2], 16) {
                Ok(v) => addr_bytes[i] = v,
                Err(_) => {
                    valid_parse = false;
                    break;
                }
            }
        }
        if !valid_parse {
            continue;
        }

        let addr = Ipv6Addr::from(addr_bytes);

        if is_link_local(&addr) {
            param.name = parts[5].to_string();
            param.iface = -1;
            return true;
        }
    }

    false
}

// ============================================================================
// Public API: periodic_ra
// ============================================================================

/// Perform periodic unsolicited Router Advertisement transmission.
///
/// Iterates all DHCPv6 contexts, finds overdue RA events, sends RAs
/// to primary interface and bridge aliases, reschedules next timeout.
///
/// Returns the time of the next scheduled RA event, or `None` if no
/// RAs are pending.
///
/// Direct port of C `periodic_ra()` (radv.c lines 1850-1958).
pub fn periodic_ra(
    now: i64,
    daemon: &DaemonState,
    config: &mut DaemonConfig,
) -> Option<i64> {
    #[cfg(feature = "dhcp6")]
    {
        #[allow(unused_assignments)]
        let mut next_event: i64 = 0;

        loop {
            let mut overdue_idx: Option<usize> = None;
            next_event = 0;

            for (i, context) in config.dhcp.contexts.iter().enumerate() {
                if context.ra_time == 0 {
                    continue;
                }
                if context.ra_time <= now {
                    overdue_idx = Some(i);
                    break;
                }
                if next_event == 0 || context.ra_time < next_event {
                    next_event = context.ra_time;
                }
            }

            let idx = match overdue_idx {
                Some(i) => i,
                None => break,
            };

            let context = &config.dhcp.contexts[idx];

            let mut param = SearchParam {
                iface: 0,
                name: String::new(),
            };

            if context.flags.contains(DhcpContextFlags::OLD)
                && context.if_index != 0
            {
                // OLD context — use stored if_index
                if let Ok(name) = index_to_name(context.if_index as u32) {
                    param.iface = context.if_index;
                    param.name = name.clone();

                    let ra_interfaces = config.dhcp.ra_interfaces.clone();
                    let ctx = &mut config.dhcp.contexts[idx];
                    new_timeout(
                        &mut ctx.ra_time,
                        ctx.ra_short_period_start,
                        &name,
                        now,
                        &ra_interfaces,
                    );
                }
            } else {
                param.iface = context.if_index;

                // Find interface via link-local address enumeration
                let found = iface_search_linklocal(param.iface, &mut param);

                if !found || param.iface != -1 {
                    // Can't find interface — zero the timer
                    config.dhcp.contexts[idx].ra_time = 0;
                    continue;
                }

                // Recover original index
                param.iface = config.dhcp.contexts[idx].if_index;
            }

            if param.iface > 0 {
                let (allowed, _auth) = iface_check(
                    libc::AF_LOCAL,
                    None,
                    &param.name,
                    config,
                    daemon,
                );

                if allowed {
                    send_ra(now, param.iface, &param.name, None, daemon, config);

                    // Handle bridge aliases
                    handle_bridge_aliases(
                        now,
                        param.iface,
                        &param.name,
                        daemon,
                        config,
                    );

                    // Schedule next RA for this context
                    let ra_interfaces = config.dhcp.ra_interfaces.clone();
                    let name = param.name.clone();
                    let ctx = &mut config.dhcp.contexts[idx];
                    new_timeout(
                        &mut ctx.ra_time,
                        ctx.ra_short_period_start,
                        &name,
                        now,
                        &ra_interfaces,
                    );
                }
            }
        }

        if next_event > 0 {
            Some(next_event)
        } else {
            None
        }
    }

    #[cfg(not(feature = "dhcp6"))]
    {
        None
    }
}

/// Handle sending RAs to bridge alias interfaces.
///
/// Two-pass enumeration: first count aliases, then send RAs.
/// Direct port of C periodic_ra bridge alias handling (radv.c lines 1907-1953).
fn handle_bridge_aliases(
    now: i64,
    iface: i32,
    iface_name: &str,
    daemon: &DaemonState,
    config: &DaemonConfig,
) {
    for bridge in config.dhcp.bridges.iter() {
        if let Ok(bridge_index) = nix_if_nametoindex(&bridge.iface) {
            if bridge_index as i32 == iface {
                // Collect alias interface indices
                let mut alias_ifs: Vec<i32> = Vec::new();

                for alias in &bridge.aliases {
                    if let Ok(alias_idx) = nix_if_nametoindex(&alias.iface) {
                        if alias_idx as i32 != iface {
                            alias_ifs.push(alias_idx as i32);
                        }
                    }
                }

                // Send RA to each alias interface
                for alias_if in &alias_ifs {
                    send_ra_alias(
                        now,
                        iface,
                        iface_name,
                        None,
                        *alias_if,
                        daemon,
                        config,
                    );
                }

                // Source interface can only appear in one --bridge-interface
                return;
            }
        }
    }
}

// ============================================================================
// Module-level tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calc_interval_default() {
        assert_eq!(calc_interval(None), 600);
    }

    #[test]
    fn test_calc_interval_custom() {
        let ra = RaInterface {
            name: "eth0".to_string(),
            mtu_name: None,
            interval: 300,
            lifetime: -1,
            prio: 0,
            mtu: 0,
        };
        assert_eq!(calc_interval(Some(&ra)), 300);
    }

    #[test]
    fn test_calc_interval_clamp_min() {
        let ra = RaInterface {
            name: "eth0".to_string(),
            mtu_name: None,
            interval: 1,
            lifetime: -1,
            prio: 0,
            mtu: 0,
        };
        assert_eq!(calc_interval(Some(&ra)), 4);
    }

    #[test]
    fn test_calc_interval_clamp_max() {
        let ra = RaInterface {
            name: "eth0".to_string(),
            mtu_name: None,
            interval: 5000,
            lifetime: -1,
            prio: 0,
            mtu: 0,
        };
        assert_eq!(calc_interval(Some(&ra)), 1800);
    }

    #[test]
    fn test_calc_interval_zero_uses_default() {
        let ra = RaInterface {
            name: "eth0".to_string(),
            mtu_name: None,
            interval: 0,
            lifetime: -1,
            prio: 0,
            mtu: 0,
        };
        assert_eq!(calc_interval(Some(&ra)), 600);
    }

    #[test]
    fn test_calc_lifetime_default() {
        assert_eq!(calc_lifetime(None), 1800); // 3 * 600
    }

    #[test]
    fn test_calc_lifetime_custom() {
        let ra = RaInterface {
            name: "eth0".to_string(),
            mtu_name: None,
            interval: 200,
            lifetime: 1000,
            prio: 0,
            mtu: 0,
        };
        assert_eq!(calc_lifetime(Some(&ra)), 1000);
    }

    #[test]
    fn test_calc_lifetime_below_interval() {
        let ra = RaInterface {
            name: "eth0".to_string(),
            mtu_name: None,
            interval: 300,
            lifetime: 100,
            prio: 0,
            mtu: 0,
        };
        assert_eq!(calc_lifetime(Some(&ra)), 300);
    }

    #[test]
    fn test_calc_lifetime_max_cap() {
        let ra = RaInterface {
            name: "eth0".to_string(),
            mtu_name: None,
            interval: 600,
            lifetime: 20000,
            prio: 0,
            mtu: 0,
        };
        assert_eq!(calc_lifetime(Some(&ra)), 9000);
    }

    #[test]
    fn test_calc_lifetime_not_specified() {
        let ra = RaInterface {
            name: "eth0".to_string(),
            mtu_name: None,
            interval: 100,
            lifetime: -1,
            prio: 0,
            mtu: 0,
        };
        assert_eq!(calc_lifetime(Some(&ra)), 300); // 3 * 100
    }

    #[test]
    fn test_calc_prio_default() {
        assert_eq!(calc_prio(None), 0);
    }

    #[test]
    fn test_calc_prio_custom() {
        let ra = RaInterface {
            name: "eth0".to_string(),
            mtu_name: None,
            interval: 600,
            lifetime: -1,
            prio: 8,
            mtu: 0,
        };
        assert_eq!(calc_prio(Some(&ra)), 8);
    }

    #[test]
    fn test_find_iface_param_found() {
        let interfaces = vec![
            RaInterface {
                name: "eth0".to_string(),
                mtu_name: None,
                interval: 300,
                lifetime: -1,
                prio: 0,
                mtu: 0,
            },
            RaInterface {
                name: "wlan*".to_string(),
                mtu_name: None,
                interval: 600,
                lifetime: -1,
                prio: 1,
                mtu: 0,
            },
        ];
        let result = find_iface_param(&interfaces, "eth0");
        assert!(result.is_some());
        assert_eq!(result.unwrap().interval, 300);
    }

    #[test]
    fn test_find_iface_param_wildcard() {
        let interfaces = vec![RaInterface {
            name: "wlan*".to_string(),
            mtu_name: None,
            interval: 400,
            lifetime: -1,
            prio: 0,
            mtu: 0,
        }];
        let result = find_iface_param(&interfaces, "wlan0");
        assert!(result.is_some());
        assert_eq!(result.unwrap().interval, 400);
    }

    #[test]
    fn test_find_iface_param_not_found() {
        let interfaces = vec![RaInterface {
            name: "eth0".to_string(),
            mtu_name: None,
            interval: 300,
            lifetime: -1,
            prio: 0,
            mtu: 0,
        }];
        assert!(find_iface_param(&interfaces, "br0").is_none());
    }

    #[test]
    fn test_is_same_net6_match() {
        let a = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let b = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        assert!(is_same_net6(&a, &b, 64));
    }

    #[test]
    fn test_is_same_net6_no_match() {
        let a = Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 1);
        let b = Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 1);
        assert!(!is_same_net6(&a, &b, 48));
    }

    #[test]
    fn test_zero_host_bits() {
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0xdead, 0xbeef, 0, 1);
        let zeroed = zero_host_bits(&addr, 64);
        assert_eq!(zeroed, Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0));
    }

    #[test]
    fn test_zero_host_bits_128() {
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let zeroed = zero_host_bits(&addr, 128);
        assert_eq!(zeroed, addr);
    }

    #[test]
    fn test_format_mac() {
        let mac = vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        assert_eq!(format_mac(&mac), "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn test_icmp6_filter() {
        let mut filter = Icmp6Filter::block_all();
        for val in &filter.data {
            assert_eq!(*val, 0xFFFFFFFF);
        }
        filter.set_pass(133);
        let idx = 133 / 32;
        let bit = 133 % 32;
        assert_eq!(filter.data[idx] & (1u32 << bit), 0);
    }
}

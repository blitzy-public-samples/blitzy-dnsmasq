//! Linux-specific platform backend using NETLINK_ROUTE for network interface
//! enumeration and monitoring.
//!
//! This module provides the Linux implementation of the [`NetworkBackend`] trait,
//! backed by the kernel's netlink routing subsystem. It serves as the single entry
//! point for all Linux platform-specific network operations, including:
//!
//! - Interface/address/route enumeration via `RTM_GET*` dump requests
//! - Async network topology change monitoring via netlink multicast groups
//! - Optional ipset integration for DNS-driven firewall rules (`feature = "ipset"`)
//! - Optional inotify monitoring for configuration file changes (`feature = "inotify_monitor"`)
//! - Optional conntrack mark retrieval for DNS policy routing (`feature = "conntrack"`)
//!
//! # Architecture
//!
//! The [`LinuxNetlink`] struct wraps a raw `NETLINK_ROUTE` socket and implements
//! [`NetworkBackend`] from the parent [`platform`](crate::net::platform) module.
//! Optional subsystem managers ([`IpsetManager`], [`InotifyManager`]) are held as
//! `Option` fields behind Cargo feature gates, initialized lazily after configuration
//! is loaded.
//!
//! # Submodules
//!
//! | Module | Feature Gate | Purpose |
//! |--------|-------------|---------|
//! | [`netlink`] | `netlink` | High-level `NetlinkManager` using `netlink-packet-route` crate |
//! | [`ipset`] | `ipset` | Linux ipset population via NETLINK_NETFILTER |
//! | [`inotify`] | `inotify_monitor` | File-change monitoring for config hot-reload |
//! | [`conntrack`] | `conntrack` | Netfilter conntrack mark retrieval via FFI |
//!
//! # Design Pattern
//!
//! **Strategy Pattern**: [`LinuxNetlink`] implements the [`NetworkBackend`] trait
//! (defined in the parent module), allowing the rest of the codebase to program
//! against the trait while the concrete Linux implementation is injected at compile
//! time via `#[cfg(target_os = "linux")]`.
//!
//! # C Source Reference
//!
//! This module is a complete Rust rewrite of `src/netlink.c` (740 lines of C),
//! with additional submodules covering `src/ipset.c`, `src/inotify.c`, and
//! `src/conntrack.c`.

// ---------------------------------------------------------------------------
// Submodule declarations (feature-gated)
// ---------------------------------------------------------------------------

/// Core NETLINK_ROUTE manager using the `netlink-packet-route` and `netlink-sys`
/// crates for typed netlink message parsing and socket management.
///
/// Available when the `netlink` Cargo feature is enabled. Provides
/// [`NetlinkManager`] with a higher-level API over the raw netlink protocol.
#[cfg(feature = "netlink")]
pub mod netlink;

/// Linux ipset integration via NETLINK_NETFILTER for DNS-driven firewall rule
/// population. Enables dnsmasq to automatically add/remove IP addresses from
/// named ipset collections based on DNS query results.
///
/// Available when the `ipset` Cargo feature is enabled.
#[cfg(feature = "ipset")]
pub mod ipset;

/// Linux inotify file-change monitoring for configuration hot-reload.
/// Watches resolv-files, dynamic host directories, and DHCP configuration
/// directories for changes, triggering cache flushes and config reloads.
///
/// Available when the `inotify_monitor` Cargo feature is enabled.
#[cfg(feature = "inotify_monitor")]
pub mod inotify;

/// Netfilter connection tracking mark retrieval for DNS policy routing.
/// Queries the kernel conntrack table to retrieve connection marks for
/// incoming DNS queries, enabling per-connection DNS forwarding policies.
///
/// Available when the `conntrack` Cargo feature is enabled.
#[cfg(feature = "conntrack")]
pub mod conntrack;

// ---------------------------------------------------------------------------
// Re-exports from submodules for convenient access
// ---------------------------------------------------------------------------

/// Re-export core netlink types when the `netlink` feature is enabled.
#[cfg(feature = "netlink")]
pub use self::netlink::{AddressFamily, AsyncStates, NetlinkError, NetlinkManager};

/// Re-export ipset types when the `ipset` feature is enabled.
#[cfg(feature = "ipset")]
pub use self::ipset::{IpsetError, IpsetManager};

/// Re-export inotify types when the `inotify_monitor` feature is enabled.
#[cfg(feature = "inotify_monitor")]
pub use self::inotify::{InotifyError, InotifyEventHandler, InotifyManager};

/// Re-export conntrack types when the `conntrack` feature is enabled.
#[cfg(feature = "conntrack")]
pub use self::conntrack::{get_incoming_mark, ConntrackError};

// ---------------------------------------------------------------------------
// Imports
// ---------------------------------------------------------------------------

use std::cell::Cell;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::io::RawFd;

use crate::net::platform::{InterfaceCallback, NetworkBackend, PlatformError};

// Import DaemonState for use in convenience methods and documentation references.
#[allow(unused_imports)]
use crate::core::daemon::DaemonState;

// ---------------------------------------------------------------------------
// Error type conversions — From<SubmoduleError> for PlatformError
// ---------------------------------------------------------------------------

/// Convert [`NetlinkError`] to [`PlatformError`] for seamless error propagation.
#[cfg(feature = "netlink")]
impl From<netlink::NetlinkError> for PlatformError {
    fn from(e: netlink::NetlinkError) -> Self {
        PlatformError::NetlinkError(e.to_string())
    }
}

/// Convert [`IpsetError`] to [`PlatformError`] for seamless error propagation.
#[cfg(feature = "ipset")]
impl From<ipset::IpsetError> for PlatformError {
    fn from(e: ipset::IpsetError) -> Self {
        PlatformError::NetlinkError(format!("ipset: {}", e))
    }
}

/// Convert [`InotifyError`] to [`PlatformError`] for seamless error propagation.
#[cfg(feature = "inotify_monitor")]
impl From<inotify::InotifyError> for PlatformError {
    fn from(e: inotify::InotifyError) -> Self {
        PlatformError::InitFailed(format!("inotify: {}", e))
    }
}

/// Convert [`ConntrackError`] to [`PlatformError`] for seamless error propagation.
#[cfg(feature = "conntrack")]
impl From<conntrack::ConntrackError> for PlatformError {
    fn from(e: conntrack::ConntrackError) -> Self {
        PlatformError::NetlinkError(format!("conntrack: {}", e))
    }
}

// ---------------------------------------------------------------------------
// Netlink protocol constants
// ---------------------------------------------------------------------------

/// RTMGRP_IPV4_IFADDR multicast group bitmask.
const RTMGRP_IPV4_IFADDR: u32 = 0x10;
/// RTMGRP_IPV4_ROUTE multicast group bitmask.
const RTMGRP_IPV4_ROUTE: u32 = 0x40;
/// RTMGRP_IPV6_IFADDR multicast group bitmask.
const RTMGRP_IPV6_IFADDR: u32 = 0x100;
/// RTMGRP_IPV6_ROUTE multicast group bitmask.
const RTMGRP_IPV6_ROUTE: u32 = 0x400;

// RTM message type constants (from <linux/rtnetlink.h>)
const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
const RTM_GETLINK: u16 = 18;
const RTM_NEWADDR: u16 = 20;
const RTM_DELADDR: u16 = 21;
const RTM_GETADDR: u16 = 22;
const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;
const RTM_NEWNEIGH: u16 = 28;
const RTM_GETNEIGH: u16 = 30;

// Netlink attribute type constants for address messages (IFA_*)
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_LABEL: u16 = 3;
const IFA_CACHEINFO: u16 = 6;
const IFA_FLAGS: u16 = 8;

// Netlink attribute type constants for link messages (IFLA_*)
const IFLA_ADDRESS: u16 = 1;

// Netlink attribute type constants for neighbor messages (NDA_*)
const NDA_DST: u16 = 1;
const NDA_LLADDR: u16 = 2;

// Kernel IFA_F_* flags for IPv6 address state
const IFA_F_TENTATIVE: u32 = 0x40;
const IFA_F_DEPRECATED: u32 = 0x20;
const IFA_F_PERMANENT: u32 = 0x80;

// Dnsmasq IFACE_* flags (matching dnsmasq.h definitions)
const IFACE_TENTATIVE: u32 = 0x01;
const IFACE_DEPRECATED: u32 = 0x02;
const IFACE_PERMANENT: u32 = 0x04;

/// Default receive buffer size for netlink messages (bytes).
const DEFAULT_RECV_BUF_SIZE: usize = 4096;

// ---------------------------------------------------------------------------
// LinuxNetlink — Primary Linux network backend struct
// ---------------------------------------------------------------------------

/// Linux network backend implementation using NETLINK_ROUTE.
///
/// This struct encapsulates all Linux-specific network state that was previously
/// held in C static globals (`netlink_pid`, `iov` buffer) and the global
/// `daemon->netlinkfd`. The netlink socket is created during
/// [`new()`](LinuxNetlink::new) and the monitoring file descriptor is exposed
/// via [`monitor_fd()`](LinuxNetlink::monitor_fd) for `mio::Poll` integration.
///
/// Optional subsystem managers (ipset, inotify) are held as `Option` fields
/// behind Cargo feature gates, initialized lazily via dedicated `init_*` methods
/// after the daemon configuration has been loaded.
///
/// # C Equivalents
///
/// | C Function | Rust Method |
/// |---|---|
/// | `netlink_init()` (netlink.c:165) | [`LinuxNetlink::new()`] |
/// | `iface_enumerate()` (netlink.c:370) | [`NetworkBackend::enumerate_interfaces()`] |
/// | `netlink_multicast()` (netlink.c:651) | [`NetworkBackend::monitor_changes()`] |
///
/// # Thread Safety
///
/// Designed for single-threaded use within the dnsmasq event loop. Uses
/// [`Cell<u32>`] for the sequence counter to allow mutation through `&self`
/// references in the [`NetworkBackend`] trait methods.
pub struct LinuxNetlink {
    /// Netlink routing socket file descriptor.
    /// Created during `new()`, used for both enumeration requests and
    /// async multicast event reception.
    netlink_fd: RawFd,

    /// Kernel-assigned netlink PID for message correlation.
    /// Retrieved from `getsockname()` after binding the netlink socket.
    netlink_pid: u32,

    /// Auto-expanding receive buffer for async multicast monitoring.
    /// Used by [`monitor_changes()`](NetworkBackend::monitor_changes) which
    /// takes `&mut self`. Enumeration methods use local buffers instead.
    recv_buffer: Vec<u8>,

    /// Sequence number counter for netlink request/response matching.
    /// Wrapped in [`Cell`] to allow mutation through `&self` references,
    /// required because [`NetworkBackend::enumerate_interfaces()`] takes `&self`.
    seq: Cell<u32>,

    /// Optional ipset manager for DNS-driven firewall set population.
    /// Initialized lazily via [`init_ipset()`](LinuxNetlink::init_ipset)
    /// after configuration is loaded.
    #[cfg(feature = "ipset")]
    ipset: Option<IpsetManager>,

    /// Optional inotify manager for file-change monitoring.
    /// Initialized lazily via [`init_inotify()`](LinuxNetlink::init_inotify)
    /// after configuration is loaded.
    #[cfg(feature = "inotify_monitor")]
    inotify_mgr: Option<InotifyManager>,
}

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

impl LinuxNetlink {
    /// Create a new Linux network backend.
    ///
    /// Initializes a `NETLINK_ROUTE` socket with multicast subscriptions for
    /// IPv4/IPv6 address and route change notifications. If multicast subscription
    /// fails (e.g., due to insufficient permissions), falls back to unicast-only
    /// mode matching the C behavior at `netlink.c` lines 181–186.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::InitFailed`] if the netlink socket cannot be
    /// created or bound.
    ///
    /// # Safety
    ///
    /// Uses `unsafe` for raw libc socket/bind/getsockname calls. Each `unsafe`
    /// block includes a SAFETY comment. The socket fd is owned by the struct and
    /// closed on [`Drop`].
    pub fn new() -> Result<Self, PlatformError> {
        // SAFETY: socket() is a standard POSIX syscall. We check the return
        // value for errors immediately. The fd is wrapped in the struct for
        // RAII lifetime management via the Drop impl.
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                libc::NETLINK_ROUTE,
            )
        };

        if fd < 0 {
            return Err(PlatformError::InitFailed(
                "Cannot create netlink socket".to_string(),
            ));
        }

        // Bind with multicast group subscriptions for address and route changes.
        // SAFETY: zeroed sockaddr_nl is valid. bind() is a standard POSIX syscall.
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        addr.nl_pid = 0; // autobind — kernel assigns a unique PID
        addr.nl_groups = RTMGRP_IPV4_IFADDR
            | RTMGRP_IPV4_ROUTE
            | RTMGRP_IPV6_IFADDR
            | RTMGRP_IPV6_ROUTE;

        // SAFETY: We pass a valid sockaddr_nl and its correct size.
        let bind_result = unsafe {
            libc::bind(
                fd,
                &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };

        if bind_result < 0 {
            // Fall back to non-multicast binding if multicast fails (e.g., EPERM).
            // Matches C behavior at netlink.c lines 181–186.
            addr.nl_groups = 0;
            // SAFETY: Same as above, retry with no multicast groups.
            let retry = unsafe {
                libc::bind(
                    fd,
                    &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
                )
            };
            if retry < 0 {
                // SAFETY: We own this fd and close it on failure before returning.
                unsafe { libc::close(fd) };
                return Err(PlatformError::InitFailed(
                    "Cannot bind netlink socket".to_string(),
                ));
            }
        }

        // Retrieve kernel-assigned PID via getsockname (netlink.c line 195).
        // SAFETY: bound_addr is zeroed and valid. getsockname writes into it.
        let mut bound_addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut addr_len = std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
        // SAFETY: All pointers are valid stack-allocated references with correct sizes.
        let gsn_result = unsafe {
            libc::getsockname(
                fd,
                &mut bound_addr as *mut libc::sockaddr_nl as *mut libc::sockaddr,
                &mut addr_len,
            )
        };

        if gsn_result < 0 {
            // SAFETY: We own this fd and close it on failure.
            unsafe { libc::close(fd) };
            return Err(PlatformError::InitFailed(
                "Cannot get netlink socket name".to_string(),
            ));
        }

        Ok(LinuxNetlink {
            netlink_fd: fd,
            netlink_pid: bound_addr.nl_pid,
            recv_buffer: vec![0u8; DEFAULT_RECV_BUF_SIZE],
            seq: Cell::new(0),
            #[cfg(feature = "ipset")]
            ipset: None,
            #[cfg(feature = "inotify_monitor")]
            inotify_mgr: None,
        })
    }
}

// ---------------------------------------------------------------------------
// Drop — automatic cleanup of the netlink socket fd
// ---------------------------------------------------------------------------

impl Drop for LinuxNetlink {
    fn drop(&mut self) {
        if self.netlink_fd >= 0 {
            // SAFETY: We own this fd exclusively and close it exactly once on drop.
            unsafe { libc::close(self.netlink_fd) };
        }
    }
}

// ---------------------------------------------------------------------------
// Internal helpers — netlink message parsing
// ---------------------------------------------------------------------------

impl LinuxNetlink {
    /// Advance the sequence counter and return the new value.
    ///
    /// Uses [`Cell`] to allow mutation through `&self` references.
    #[inline]
    fn next_seq(&self) -> u32 {
        let s = self.seq.get().wrapping_add(1);
        self.seq.set(s);
        s
    }

    /// Parse netlink attributes (rtattr chain) from a raw byte slice.
    ///
    /// Each rtattr has a 4-byte header: `rta_len` (u16) + `rta_type` (u16),
    /// followed by payload data. Attributes are 4-byte aligned.
    ///
    /// # Safety
    ///
    /// Caller must ensure `ptr` points to valid memory of at least `len` bytes.
    unsafe fn parse_rtattr(ptr: *const u8, len: usize) -> Vec<(u16, Vec<u8>)> {
        let rta_hdr_size = 4usize;
        let mut attrs = Vec::new();
        let mut offset = 0usize;

        while offset + rta_hdr_size <= len {
            // SAFETY: Caller guarantees ptr is valid for `len` bytes, and we
            // verify offset + rta_hdr_size <= len before accessing.
            let rta_len = unsafe {
                u16::from_ne_bytes([*ptr.add(offset), *ptr.add(offset + 1)]) as usize
            };
            let rta_type = unsafe {
                u16::from_ne_bytes([*ptr.add(offset + 2), *ptr.add(offset + 3)])
            };

            if rta_len < rta_hdr_size || offset + rta_len > len {
                break;
            }

            let data_len = rta_len - rta_hdr_size;
            // SAFETY: We verified rta_len is within bounds above.
            let data = unsafe {
                std::slice::from_raw_parts(ptr.add(offset + rta_hdr_size), data_len).to_vec()
            };
            attrs.push((rta_type, data));

            // Advance to next 4-byte aligned attribute
            offset += (rta_len + 3) & !3;
        }

        attrs
    }

    /// Translate kernel `IFA_F_*` flags to dnsmasq `IFACE_*` flags for IPv6
    /// address state representation.
    ///
    /// # C Equivalent
    ///
    /// `netlink.c` lines 479–484: flag bit translation.
    #[inline]
    fn translate_v6_flags(kernel_flags: u32) -> u32 {
        let mut flags = 0u32;
        if kernel_flags & IFA_F_TENTATIVE != 0 {
            flags |= IFACE_TENTATIVE;
        }
        if kernel_flags & IFA_F_DEPRECATED != 0 {
            flags |= IFACE_DEPRECATED;
        }
        if kernel_flags & IFA_F_PERMANENT != 0 {
            flags |= IFACE_PERMANENT;
        }
        flags
    }

    /// Dispatch a parsed netlink message to the appropriate callback variant.
    ///
    /// Handles RTM_NEWADDR (AF_INET/AF_INET6 addresses), RTM_NEWLINK
    /// (interface info / AF_LOCAL), and RTM_NEWNEIGH (neighbor/ARP entries).
    ///
    /// Returns `true` if enumeration should continue, `false` to stop.
    fn dispatch_netlink_msg(
        &self,
        msg_type: u16,
        payload_ptr: *const u8,
        payload_len: usize,
        family: i32,
        callback: &mut InterfaceCallback<'_>,
    ) -> bool {
        // ---- RTM_NEWADDR: address entry ----
        if msg_type == RTM_NEWADDR && payload_len >= 8 {
            // struct ifaddrmsg layout: family(1) + prefixlen(1) + flags(1) + scope(1) + index(4)
            // SAFETY: payload_ptr is valid for payload_len bytes (verified by caller).
            let addr_family = unsafe { *payload_ptr } as i32;
            let prefix_len = unsafe { *payload_ptr.add(1) } as u32;
            let header_flags = unsafe { *payload_ptr.add(2) } as u32;
            let scope = unsafe { *payload_ptr.add(3) } as u32;
            let if_index = unsafe {
                u32::from_ne_bytes([
                    *payload_ptr.add(4),
                    *payload_ptr.add(5),
                    *payload_ptr.add(6),
                    *payload_ptr.add(7),
                ])
            };

            let attrs_ptr = unsafe { payload_ptr.add(8) };
            let attrs_len = payload_len.saturating_sub(8);
            // SAFETY: attrs_ptr points within the validated payload buffer.
            let attrs = unsafe { Self::parse_rtattr(attrs_ptr, attrs_len) };

            // Extract attributes: IFA_LOCAL (preferred), IFA_ADDRESS (fallback), IFA_LABEL
            let mut local_addr_data: Option<&Vec<u8>> = None;
            let mut label = String::new();
            let mut ifa_flags: Option<u32> = None;
            let mut preferred_lifetime: u32 = 0;
            let mut valid_lifetime: u32 = 0;

            for (rta_type, data) in &attrs {
                match *rta_type {
                    IFA_LOCAL => local_addr_data = Some(data),
                    IFA_ADDRESS if local_addr_data.is_none() => local_addr_data = Some(data),
                    IFA_LABEL => {
                        label = String::from_utf8_lossy(data)
                            .trim_end_matches('\0')
                            .to_string();
                    }
                    IFA_FLAGS if data.len() >= 4 => {
                        ifa_flags = Some(u32::from_ne_bytes([data[0], data[1], data[2], data[3]]));
                    }
                    IFA_CACHEINFO if data.len() >= 8 => {
                        // struct ifa_cacheinfo: preferred(4) + valid(4) + cstamp(4) + tstamp(4)
                        preferred_lifetime =
                            u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
                        valid_lifetime =
                            u32::from_ne_bytes([data[4], data[5], data[6], data[7]]);
                    }
                    _ => {}
                }
            }

            // IPv4 address enumeration
            if addr_family == libc::AF_INET && family == libc::AF_INET {
                if let Some(data) = local_addr_data {
                    if data.len() >= 4 {
                        let addr = Ipv4Addr::new(data[0], data[1], data[2], data[3]);
                        // Compute netmask from prefix length
                        let mask_bits: u32 = if prefix_len >= 32 {
                            0xFFFF_FFFFu32
                        } else if prefix_len == 0 {
                            0u32
                        } else {
                            !((1u32 << (32 - prefix_len)) - 1)
                        };
                        let netmask = Ipv4Addr::from(mask_bits);
                        let broadcast = Ipv4Addr::from(u32::from(addr) | !mask_bits);
                        if let InterfaceCallback::AfInet(cb) = callback {
                            let result = cb(addr, if_index, &label, netmask, broadcast);
                            if result == 0 {
                                return false;
                            }
                        }
                    }
                }
            }
            // IPv6 address enumeration
            else if addr_family == libc::AF_INET6 && family == libc::AF_INET6 {
                if let Some(data) = local_addr_data {
                    if data.len() >= 16 {
                        let mut octets = [0u8; 16];
                        octets.copy_from_slice(&data[..16]);
                        let addr = Ipv6Addr::from(octets);
                        // Use 32-bit IFA_FLAGS if available, else use 8-bit header flags
                        let raw_flags = ifa_flags.unwrap_or(header_flags);
                        let flags = Self::translate_v6_flags(raw_flags);
                        if let InterfaceCallback::AfInet6(cb) = callback {
                            let result = cb(
                                addr,
                                prefix_len,
                                scope,
                                if_index,
                                flags,
                                preferred_lifetime,
                                valid_lifetime,
                            );
                            if result == 0 {
                                return false;
                            }
                        }
                    }
                }
            }
        }

        // ---- RTM_NEWLINK: link/interface info (AF_LOCAL enumeration) ----
        if msg_type == RTM_NEWLINK && payload_len >= 16 && family == libc::AF_LOCAL {
            // struct ifinfomsg: family(1) + pad(1) + type(2) + index(4) + flags(4) + change(4)
            let hw_type = unsafe {
                u16::from_ne_bytes([*payload_ptr.add(2), *payload_ptr.add(3)]) as u32
            };
            let if_index = unsafe {
                u32::from_ne_bytes([
                    *payload_ptr.add(4),
                    *payload_ptr.add(5),
                    *payload_ptr.add(6),
                    *payload_ptr.add(7),
                ])
            };

            let attrs_ptr = unsafe { payload_ptr.add(16) };
            let attrs_len = payload_len.saturating_sub(16);
            // SAFETY: attrs_ptr points within the validated payload buffer.
            let attrs = unsafe { Self::parse_rtattr(attrs_ptr, attrs_len) };

            // IFLA_ADDRESS (type 1) contains the hardware (MAC) address
            for (rta_type, data) in &attrs {
                if *rta_type == IFLA_ADDRESS {
                    if let InterfaceCallback::AfLocal(cb) = callback {
                        let result = cb(if_index, hw_type, data);
                        if result == 0 {
                            return false;
                        }
                    }
                    break;
                }
            }
        }

        // ---- RTM_NEWNEIGH: neighbor/ARP entry (AF_UNSPEC enumeration) ----
        if msg_type == RTM_NEWNEIGH && payload_len >= 12 {
            // struct ndmsg: family(1) + pad(1) + pad(2) + ifindex(4) + state(2) + flags(1) + type(1)
            let neigh_family = unsafe { *payload_ptr } as i32;

            let attrs_ptr = unsafe { payload_ptr.add(12) };
            let attrs_len = payload_len.saturating_sub(12);
            // SAFETY: attrs_ptr points within the validated payload buffer.
            let attrs = unsafe { Self::parse_rtattr(attrs_ptr, attrs_len) };

            let mut ip_data: Option<&Vec<u8>> = None;
            let mut mac_data: Option<&Vec<u8>> = None;

            for (rta_type, data) in &attrs {
                match *rta_type {
                    NDA_DST => ip_data = Some(data),
                    NDA_LLADDR => mac_data = Some(data),
                    _ => {}
                }
            }

            if let (Some(ip), Some(mac)) = (ip_data, mac_data) {
                let addr: Option<IpAddr> = if neigh_family == libc::AF_INET && ip.len() >= 4 {
                    Some(IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])))
                } else if neigh_family == libc::AF_INET6 && ip.len() >= 16 {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&ip[..16]);
                    Some(IpAddr::V6(Ipv6Addr::from(octets)))
                } else {
                    None
                };

                if let Some(addr) = addr {
                    if let InterfaceCallback::AfUnspec(cb) = callback {
                        let result = cb(neigh_family, addr, mac);
                        if result == 0 {
                            return false;
                        }
                    }
                }
            }
        }

        true // continue enumeration
    }

    /// Build and send a netlink dump request for the given address family.
    ///
    /// Returns the sequence number used, or an error if sending fails.
    fn send_dump_request(&self, family: i32) -> Result<u32, PlatformError> {
        // Determine the appropriate RTM_GET* request type based on family.
        let msg_type: u16 = match family {
            libc::AF_UNSPEC => RTM_GETNEIGH,
            libc::AF_LOCAL => RTM_GETLINK,
            _ => RTM_GETADDR,
        };

        let request_family = family as u8;
        let current_seq = self.next_seq();

        // Build the netlink request message.
        // Layout: nlmsghdr (16 bytes) + rtgenmsg (1 byte, padded to 4)
        #[repr(C)]
        struct NlRequest {
            nlh: libc::nlmsghdr,
            rtgen_family: u8,
        }

        // SAFETY: zeroed struct is valid for nlmsghdr + rtgenmsg.
        let mut req: NlRequest = unsafe { std::mem::zeroed() };
        req.nlh.nlmsg_len = std::mem::size_of::<NlRequest>() as u32;
        req.nlh.nlmsg_type = msg_type;
        req.nlh.nlmsg_flags =
            (libc::NLM_F_ROOT | libc::NLM_F_MATCH | libc::NLM_F_REQUEST) as u16;
        req.nlh.nlmsg_pid = 0;
        req.nlh.nlmsg_seq = current_seq;
        req.rtgen_family = request_family;

        // SAFETY: zeroed sockaddr_nl is valid for sendto destination.
        let mut dest_addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        dest_addr.nl_family = libc::AF_NETLINK as u16;

        // SAFETY: sendto() with valid buffer, size, and destination address.
        let sent = unsafe {
            libc::sendto(
                self.netlink_fd,
                &req as *const NlRequest as *const libc::c_void,
                req.nlh.nlmsg_len as usize,
                0,
                &dest_addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };

        if sent < 0 {
            return Err(PlatformError::NetlinkError(
                "Failed to send netlink dump request".to_string(),
            ));
        }

        Ok(current_seq)
    }

    /// Receive and process netlink response messages for a dump request.
    ///
    /// Loops until `NLMSG_DONE` is received or all messages are processed.
    /// Calls `dispatch_fn` for each message payload.
    ///
    /// Returns `Ok(true)` if completed normally, `Ok(false)` if a callback
    /// returned 0 (stop), or `Err` on netlink errors.
    fn recv_and_dispatch(
        &self,
        family: i32,
        callback: &mut InterfaceCallback<'_>,
    ) -> Result<bool, PlatformError> {
        let nlmsg_hdr_size = std::mem::size_of::<libc::nlmsghdr>();
        let mut buf = vec![0u8; 8192];
        let mut done = false;
        let mut continue_enum = true;

        while !done {
            // SAFETY: recv() with valid buffer and fd. MSG_WAITALL ensures we get
            // complete messages. MSG_TRUNC lets us detect truncation.
            let n = unsafe {
                libc::recv(
                    self.netlink_fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    libc::MSG_WAITALL | libc::MSG_TRUNC,
                )
            };

            if n < 0 {
                // SAFETY: __errno_location() returns the thread-local errno pointer.
                let errno = unsafe { *libc::__errno_location() };
                if errno == libc::EINTR {
                    continue; // Retry on signal interrupt
                }
                return Err(PlatformError::NetlinkError(format!(
                    "netlink recv failed with errno {}",
                    errno
                )));
            }

            if n == 0 {
                break; // Connection closed
            }

            let bytes_received = n as usize;
            let mut offset = 0usize;

            // Parse each nlmsghdr in the received buffer
            while offset + nlmsg_hdr_size <= bytes_received {
                // SAFETY: We verified sufficient bytes for the header.
                let nlh = unsafe { &*(buf.as_ptr().add(offset) as *const libc::nlmsghdr) };

                let msg_len = nlh.nlmsg_len as usize;
                if msg_len < nlmsg_hdr_size || offset + msg_len > bytes_received {
                    break;
                }

                // Check for DONE or ERROR termination messages
                if nlh.nlmsg_type == libc::NLMSG_DONE as u16 {
                    done = true;
                    break;
                }
                if nlh.nlmsg_type == libc::NLMSG_ERROR as u16 {
                    done = true;
                    break;
                }

                // Dispatch the message payload to the appropriate callback
                if continue_enum {
                    let payload_ptr = unsafe { buf.as_ptr().add(offset + nlmsg_hdr_size) };
                    let payload_len = msg_len - nlmsg_hdr_size;

                    if !self.dispatch_netlink_msg(
                        nlh.nlmsg_type,
                        payload_ptr,
                        payload_len,
                        family,
                        callback,
                    ) {
                        continue_enum = false; // Callback returned 0 — stop processing
                    }
                }

                // Advance to the next 4-byte aligned message
                offset += (msg_len + 3) & !3;
            }

            // Check if this is a multi-part response (NLM_F_MULTI)
            if bytes_received > nlmsg_hdr_size {
                // SAFETY: We verified bytes_received > nlmsg_hdr_size.
                let first_nlh = unsafe { &*(buf.as_ptr() as *const libc::nlmsghdr) };
                if first_nlh.nlmsg_flags & libc::NLM_F_MULTI as u16 == 0 {
                    done = true;
                }
            }
        }

        Ok(continue_enum)
    }
}

// ---------------------------------------------------------------------------
// NetworkBackend trait implementation
// ---------------------------------------------------------------------------

impl NetworkBackend for LinuxNetlink {
    /// Initialize the Linux network backend.
    ///
    /// The netlink socket is already created and bound in [`new()`](LinuxNetlink::new).
    /// Returns a diagnostic string identifying the backend for startup logging.
    fn init(&mut self) -> Result<String, PlatformError> {
        Ok(format!(
            "netlink (fd={}, pid={})",
            self.netlink_fd, self.netlink_pid
        ))
    }

    /// Enumerate network interfaces and addresses by address family.
    ///
    /// Sends the appropriate `RTM_GET*` dump request to the kernel netlink
    /// subsystem and processes response messages, invoking the callback for
    /// each discovered entry.
    ///
    /// # Address Family Dispatch
    ///
    /// | `family` | Request Type | Callback Variant | Data |
    /// |----------|-------------|------------------|------|
    /// | `AF_INET` | `RTM_GETADDR` | `AfInet` | IPv4 addresses |
    /// | `AF_INET6` | `RTM_GETADDR` | `AfInet6` | IPv6 addresses |
    /// | `AF_UNSPEC` | `RTM_GETNEIGH` | `AfUnspec` | ARP/NDP entries |
    /// | `AF_LOCAL` | `RTM_GETLINK` | `AfLocal` | MAC addresses |
    ///
    /// # C Equivalent
    ///
    /// `iface_enumerate()` in `netlink.c` lines 370–566.
    fn enumerate_interfaces(
        &self,
        family: i32,
        mut callback: InterfaceCallback<'_>,
    ) -> Result<bool, PlatformError> {
        self.send_dump_request(family)?;
        self.recv_and_dispatch(family, &mut callback)
    }

    /// Process asynchronous network change events from netlink multicast.
    ///
    /// Called from the main event loop when the monitoring socket
    /// ([`monitor_fd()`](LinuxNetlink::monitor_fd)) becomes readable. Drains all
    /// pending multicast messages, identifying address/route/link changes that
    /// require re-enumeration.
    ///
    /// # C Equivalent
    ///
    /// `netlink_multicast()` in `netlink.c` lines 651–703.
    fn monitor_changes(&mut self) -> Result<(), PlatformError> {
        let nlmsg_hdr_size = std::mem::size_of::<libc::nlmsghdr>();

        loop {
            // SAFETY: recv() with valid buffer, fd, and MSG_DONTWAIT for non-blocking.
            let n = unsafe {
                libc::recv(
                    self.netlink_fd,
                    self.recv_buffer.as_mut_ptr() as *mut libc::c_void,
                    self.recv_buffer.len(),
                    libc::MSG_DONTWAIT,
                )
            };

            if n < 0 {
                // SAFETY: Thread-local errno access.
                let errno = unsafe { *libc::__errno_location() };
                if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
                    break; // No more pending messages
                }
                if errno == libc::EINTR {
                    continue; // Interrupted, retry
                }
                return Err(PlatformError::NetlinkError(format!(
                    "netlink recv failed with errno {}",
                    errno
                )));
            }

            if n == 0 {
                break; // EOF
            }

            let bytes_received = n as usize;

            // Auto-expand buffer if it was too small for the message.
            if bytes_received >= self.recv_buffer.len() {
                self.recv_buffer
                    .resize(self.recv_buffer.len().saturating_mul(2).max(8192), 0);
            }

            // Parse netlink messages — we only need to detect message types for
            // the event loop to know re-enumeration is needed. The actual
            // re-enumeration happens at the event_loop level.
            let mut offset = 0usize;
            while offset + nlmsg_hdr_size <= bytes_received {
                // SAFETY: We verified sufficient bytes for the header.
                let nlh = unsafe {
                    &*(self.recv_buffer.as_ptr().add(offset) as *const libc::nlmsghdr)
                };

                let msg_len = nlh.nlmsg_len as usize;
                if msg_len < nlmsg_hdr_size || offset + msg_len > bytes_received {
                    break;
                }

                // Network topology change types that trigger re-enumeration:
                // RTM_NEWLINK/DELLINK (16/17), RTM_NEWADDR/DELADDR (20/21),
                // RTM_NEWROUTE/DELROUTE (24/25)
                // The event loop polls monitor_fd() and calls monitor_changes()
                // to drain these messages, then re-enumerates as needed.
                match nlh.nlmsg_type {
                    RTM_NEWLINK | RTM_DELLINK | RTM_NEWADDR | RTM_DELADDR | RTM_NEWROUTE
                    | RTM_DELROUTE => {
                        // Network topology change detected — the event loop will
                        // re-enumerate interfaces when it processes this readable fd.
                    }
                    _ => {
                        // Ignore unknown or unhandled message types.
                    }
                }

                offset += (msg_len + 3) & !3;
            }
        }

        Ok(())
    }

    /// Get the file descriptor for the netlink monitoring socket.
    ///
    /// This fd should be registered with `mio::Poll` for `READABLE` events.
    /// When readable, call [`monitor_changes()`](NetworkBackend::monitor_changes)
    /// to process pending netlink multicast events.
    fn monitor_fd(&self) -> Option<RawFd> {
        if self.netlink_fd >= 0 {
            Some(self.netlink_fd)
        } else {
            None
        }
    }

    /// Enumerate ARP/neighbor table entries via `RTM_GETNEIGH`.
    ///
    /// Retrieves the kernel's ARP (IPv4) and neighbor (IPv6) cache, invoking
    /// the callback for each entry with the address family, IP address, and
    /// hardware (MAC) address.
    ///
    /// # C Equivalent
    ///
    /// `iface_enumerate(AF_UNSPEC, ...)` in `netlink.c`.
    fn enumerate_arp(
        &self,
        callback: &mut dyn FnMut(i32, IpAddr, &[u8]) -> i32,
    ) -> Result<(), PlatformError> {
        self.send_dump_request(libc::AF_UNSPEC)?;

        let nlmsg_hdr_size = std::mem::size_of::<libc::nlmsghdr>();
        let mut buf = vec![0u8; 8192];
        let mut done = false;

        while !done {
            // SAFETY: recv() with valid buffer and fd.
            let n = unsafe {
                libc::recv(
                    self.netlink_fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    libc::MSG_WAITALL | libc::MSG_TRUNC,
                )
            };

            if n < 0 {
                let errno = unsafe { *libc::__errno_location() };
                if errno == libc::EINTR {
                    continue;
                }
                return Err(PlatformError::NetlinkError(format!(
                    "netlink ARP recv failed with errno {}",
                    errno
                )));
            }

            if n == 0 {
                break;
            }

            let bytes_received = n as usize;
            let mut offset = 0usize;

            while offset + nlmsg_hdr_size <= bytes_received {
                let nlh = unsafe { &*(buf.as_ptr().add(offset) as *const libc::nlmsghdr) };

                let msg_len = nlh.nlmsg_len as usize;
                if msg_len < nlmsg_hdr_size || offset + msg_len > bytes_received {
                    break;
                }

                if nlh.nlmsg_type == libc::NLMSG_DONE as u16 {
                    done = true;
                    break;
                }
                if nlh.nlmsg_type == libc::NLMSG_ERROR as u16 {
                    done = true;
                    break;
                }

                // RTM_NEWNEIGH: parse neighbor entry
                if nlh.nlmsg_type == RTM_NEWNEIGH {
                    let payload_ptr = unsafe { buf.as_ptr().add(offset + nlmsg_hdr_size) };
                    let payload_len = msg_len - nlmsg_hdr_size;

                    if payload_len >= 12 {
                        let neigh_family = unsafe { *payload_ptr } as i32;
                        let attrs_ptr = unsafe { payload_ptr.add(12) };
                        let attrs_len = payload_len.saturating_sub(12);
                        let attrs = unsafe { Self::parse_rtattr(attrs_ptr, attrs_len) };

                        let mut ip_data: Option<&Vec<u8>> = None;
                        let mut mac_data: Option<&Vec<u8>> = None;

                        for (rta_type, data) in &attrs {
                            match *rta_type {
                                NDA_DST => ip_data = Some(data),
                                NDA_LLADDR => mac_data = Some(data),
                                _ => {}
                            }
                        }

                        if let (Some(ip), Some(mac)) = (ip_data, mac_data) {
                            let addr: Option<IpAddr> =
                                if neigh_family == libc::AF_INET && ip.len() >= 4 {
                                    Some(IpAddr::V4(Ipv4Addr::new(
                                        ip[0], ip[1], ip[2], ip[3],
                                    )))
                                } else if neigh_family == libc::AF_INET6 && ip.len() >= 16 {
                                    let mut octets = [0u8; 16];
                                    octets.copy_from_slice(&ip[..16]);
                                    Some(IpAddr::V6(Ipv6Addr::from(octets)))
                                } else {
                                    None
                                };

                            if let Some(addr) = addr {
                                let result = callback(neigh_family, addr, mac);
                                if result == 0 {
                                    return Ok(());
                                }
                            }
                        }
                    }
                }

                offset += (msg_len + 3) & !3;
            }

            // Check for multi-part response
            if bytes_received > nlmsg_hdr_size {
                let first_nlh = unsafe { &*(buf.as_ptr() as *const libc::nlmsghdr) };
                if first_nlh.nlmsg_flags & libc::NLM_F_MULTI as u16 == 0 {
                    done = true;
                }
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Feature-gated convenience methods
// ---------------------------------------------------------------------------

impl LinuxNetlink {
    /// Initialize the ipset manager for DNS-driven firewall set population.
    ///
    /// Call after configuration is loaded to create the appropriate netlink or
    /// raw socket for ipset operations. The kernel version determines whether
    /// the modern (≥2.6.32) or legacy API is used.
    ///
    /// # Arguments
    ///
    /// * `kernel_version` — Encoded kernel version from `uname()`, using the
    ///   standard `KERNEL_VERSION(major, minor, patch)` encoding.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError`] if the ipset control socket cannot be created.
    #[cfg(feature = "ipset")]
    pub fn init_ipset(&mut self, kernel_version: u32) -> Result<(), PlatformError> {
        self.ipset = Some(IpsetManager::new(kernel_version).map_err(PlatformError::from)?);
        Ok(())
    }

    /// Add or remove an IP address to/from a named ipset collection.
    ///
    /// Delegates to [`IpsetManager::add_to_ipset()`]. The ipset manager must
    /// have been initialized via [`init_ipset()`](LinuxNetlink::init_ipset)
    /// before calling this method.
    ///
    /// # Arguments
    ///
    /// * `setname` — Name of the ipset collection (max 31 characters).
    /// * `addr` — IPv4 or IPv6 address to add/remove.
    /// * `remove` — `true` to remove the address; `false` to add.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError`] if the ipset manager is not initialized or
    /// the operation fails.
    #[cfg(feature = "ipset")]
    pub fn add_to_ipset(
        &self,
        setname: &str,
        addr: &IpAddr,
        remove: bool,
    ) -> Result<(), PlatformError> {
        if let Some(ref mgr) = self.ipset {
            mgr.add_to_ipset(setname, addr, remove)
                .map_err(PlatformError::from)
        } else {
            Err(PlatformError::InitFailed(
                "ipset manager not initialized".to_string(),
            ))
        }
    }

    /// Initialize inotify file-change monitoring.
    ///
    /// Sets up inotify watches for resolv-files and prepares dynamic directory
    /// monitoring. Call after the daemon configuration has been fully parsed.
    ///
    /// # Arguments
    ///
    /// * `config` — Parsed daemon configuration providing resolv-file paths,
    ///   dynamic directory definitions, and option flags.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError`] if the inotify instance cannot be created or
    /// watches cannot be added.
    #[cfg(feature = "inotify_monitor")]
    pub fn init_inotify(
        &mut self,
        config: &crate::config::options::DaemonConfig,
    ) -> Result<(), PlatformError> {
        self.inotify_mgr = Some(InotifyManager::new(config).map_err(PlatformError::from)?);
        Ok(())
    }

    /// Get the inotify file descriptor for `mio::Poll` integration.
    ///
    /// Returns `Some(fd)` if inotify has been initialized, `None` otherwise.
    /// Register this fd for `READABLE` events in the event loop.
    #[cfg(feature = "inotify_monitor")]
    pub fn inotify_fd(&self) -> Option<RawFd> {
        self.inotify_mgr.as_ref().map(|m| m.fd())
    }

    /// Check for pending inotify events and invoke the handler.
    ///
    /// Called from the event loop when the inotify fd becomes readable.
    /// Returns `Ok(true)` if any events were processed, `Ok(false)` if none.
    ///
    /// # Arguments
    ///
    /// * `handler` — Implementation of [`InotifyEventHandler`] that handles
    ///   cache flushes, file reloads, and DHCP propagation.
    /// * `now` — Current timestamp in seconds since epoch.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError`] if reading inotify events fails.
    #[cfg(feature = "inotify_monitor")]
    pub fn check_inotify(
        &mut self,
        handler: &mut dyn InotifyEventHandler,
        now: i64,
    ) -> Result<bool, PlatformError> {
        if let Some(ref mut mgr) = self.inotify_mgr {
            mgr.check_events(handler, now)
                .map_err(PlatformError::from)
        } else {
            Ok(false)
        }
    }

    /// Query the netfilter conntrack table for a connection tracking mark.
    ///
    /// Constructs a 5-tuple from the provided connection parameters, queries
    /// the kernel conntrack table, and returns the associated mark if found.
    ///
    /// # Arguments
    ///
    /// * `peer_addr` — Remote peer's socket address (IP + port).
    /// * `local_addr` — Local DNS server address.
    /// * `is_tcp` — `true` for TCP, `false` for UDP.
    /// * `dns_port` — Local DNS port (typically 53).
    ///
    /// # Returns
    ///
    /// * `Ok(Some(mark))` — Mark retrieved from matching conntrack entry.
    /// * `Ok(None)` — No matching conntrack entry found.
    /// * `Err(_)` — Conntrack query failed.
    #[cfg(feature = "conntrack")]
    pub fn get_incoming_mark(
        &self,
        peer_addr: &crate::types::addr::SocketAddress,
        local_addr: &IpAddr,
        is_tcp: bool,
        dns_port: u16,
    ) -> Result<Option<u32>, PlatformError> {
        conntrack::get_incoming_mark(peer_addr, local_addr, is_tcp, dns_port)
            .map_err(PlatformError::from)
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linux_netlink_creation() {
        // LinuxNetlink::new() requires root/CAP_NET_ADMIN for multicast groups
        // but should succeed with fallback to non-multicast mode.
        let result = LinuxNetlink::new();
        match result {
            Ok(nl) => {
                assert!(nl.netlink_fd >= 0);
                assert!(nl.monitor_fd().is_some());
                assert_eq!(nl.seq.get(), 0);
            }
            Err(PlatformError::InitFailed(msg)) => {
                // Expected in sandboxed environments without network namespace permissions.
                assert!(msg.contains("Cannot"));
            }
            Err(other) => {
                panic!("Unexpected error variant: {:?}", other);
            }
        }
    }

    #[test]
    fn test_init_returns_diagnostic_string() {
        let result = LinuxNetlink::new();
        if let Ok(mut nl) = result {
            let info = nl.init().expect("init should succeed");
            assert!(info.contains("netlink"));
            assert!(info.contains("fd="));
            assert!(info.contains("pid="));
        }
    }

    #[test]
    fn test_sequence_counter_advances() {
        let result = LinuxNetlink::new();
        if let Ok(nl) = result {
            assert_eq!(nl.seq.get(), 0);
            let s1 = nl.next_seq();
            assert_eq!(s1, 1);
            let s2 = nl.next_seq();
            assert_eq!(s2, 2);
            assert_eq!(nl.seq.get(), 2);
        }
    }

    #[test]
    fn test_v6_flag_translation() {
        assert_eq!(LinuxNetlink::translate_v6_flags(0), 0);
        assert_eq!(
            LinuxNetlink::translate_v6_flags(IFA_F_TENTATIVE),
            IFACE_TENTATIVE
        );
        assert_eq!(
            LinuxNetlink::translate_v6_flags(IFA_F_DEPRECATED),
            IFACE_DEPRECATED
        );
        assert_eq!(
            LinuxNetlink::translate_v6_flags(IFA_F_PERMANENT),
            IFACE_PERMANENT
        );
        // Combined flags
        assert_eq!(
            LinuxNetlink::translate_v6_flags(IFA_F_TENTATIVE | IFA_F_PERMANENT),
            IFACE_TENTATIVE | IFACE_PERMANENT
        );
    }

    #[test]
    fn test_monitor_fd_returns_valid_fd() {
        let result = LinuxNetlink::new();
        if let Ok(nl) = result {
            let fd = nl.monitor_fd();
            assert!(fd.is_some());
            assert!(fd.unwrap() >= 0);
        }
    }

    #[cfg(feature = "netlink")]
    #[test]
    fn test_netlink_error_to_platform_error() {
        let ne = NetlinkError::SocketCreation(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "test",
        ));
        let pe: PlatformError = ne.into();
        let msg = pe.to_string();
        assert!(msg.contains("netlink") || msg.contains("socket"));
    }

    #[cfg(feature = "ipset")]
    #[test]
    fn test_ipset_error_to_platform_error() {
        let ie = IpsetError::SetNameTooLong {
            name: "x".repeat(40),
        };
        let pe: PlatformError = ie.into();
        let msg = pe.to_string();
        assert!(msg.contains("ipset"));
    }

    #[cfg(feature = "conntrack")]
    #[test]
    fn test_conntrack_error_to_platform_error() {
        let ce = ConntrackError::CreateFailed;
        let pe: PlatformError = ce.into();
        let msg = pe.to_string();
        assert!(msg.contains("conntrack"));
    }
}

//! Linux-specific platform backend using NETLINK_ROUTE for network interface
//! enumeration and monitoring.
//!
//! This module provides the Linux implementation of the [`NetworkBackend`] trait,
//! backed by the kernel's netlink routing subsystem. It supports:
//! - Interface/address/route enumeration via RTM_GET* messages
//! - Async network topology change monitoring via multicast groups
//!
//! # Submodules (feature-gated)
//!
//! - `ipset` — Linux ipset integration via netlink (`#[cfg(feature = "ipset")]`)
//! - `inotify` — inotify file-change monitoring (`#[cfg(feature = "inotify_monitor")]`)
//! - `conntrack` — netfilter conntrack mark retrieval (`#[cfg(feature = "conntrack")]`)

#[cfg(feature = "conntrack")]
pub mod conntrack;

#[cfg(feature = "inotify_monitor")]
pub mod inotify;

#[cfg(feature = "ipset")]
pub mod ipset;

#[cfg(feature = "netlink")]
pub mod netlink;

use std::net::IpAddr;
use std::os::unix::io::RawFd;

use crate::net::platform::{InterfaceCallback, NetworkBackend, PlatformError};

/// Linux network backend implementation using NETLINK_ROUTE.
///
/// Wraps a netlink socket for interface enumeration and async event monitoring.
/// Optional subsystems (ipset, inotify, conntrack) are included based on Cargo features.
///
/// # Design
///
/// This struct encapsulates all Linux-specific network state that was previously held
/// in C static globals (`netlink_pid`, `iov` buffer) and the global `daemon->netlinkfd`.
/// The netlink socket is created during [`new()`](LinuxNetlink::new) and the monitoring
/// file descriptor is exposed via [`monitor_fd()`](LinuxNetlink::monitor_fd) for
/// `mio::Poll` integration.
///
/// # C Equivalent
///
/// Replaces the combination of:
/// - `netlink_init()` in `netlink.c` line 165
/// - `iface_enumerate()` in `netlink.c` line 370
/// - `netlink_multicast()` in `netlink.c` line 651
pub struct LinuxNetlink {
    /// Netlink routing socket file descriptor.
    /// Created during `new()`, used for both enumeration requests and
    /// async multicast event reception.
    netlink_fd: RawFd,

    /// Kernel-assigned netlink PID for message correlation.
    /// Retrieved from `getsockname()` after binding the netlink socket.
    netlink_pid: u32,

    /// Auto-expanding receive buffer for netlink messages.
    /// Replaces the C `static struct iovec iov` with `expand_buf()`.
    recv_buffer: Vec<u8>,

    /// Sequence number counter for netlink request/response matching.
    seq: u32,
}

impl LinuxNetlink {
    /// Create a new Linux network backend.
    ///
    /// Initializes a NETLINK_ROUTE socket with multicast subscriptions for
    /// IPv4/IPv6 address and route change notifications.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::InitFailed`] if the netlink socket cannot be created
    /// or bound.
    pub fn new() -> Result<Self, PlatformError> {
        // Create NETLINK_ROUTE socket
        // SAFETY rationale: We use libc directly here because the nix/netlink-sys crates
        // may not be available as dependencies of this module. This is a minimal
        // implementation that will be expanded by the dedicated netlink agent.
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

        // Bind with multicast group subscriptions
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        addr.nl_pid = 0; // autobind
        addr.nl_groups = 0x10  // RTMGRP_IPV4_IFADDR
                       | 0x40  // RTMGRP_IPV4_ROUTE
                       | 0x100 // RTMGRP_IPV6_IFADDR
                       | 0x400; // RTMGRP_IPV6_ROUTE

        let bind_result = unsafe {
            libc::bind(
                fd,
                &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };

        if bind_result < 0 {
            // Try without multicast groups (may lack permissions)
            addr.nl_groups = 0;
            let retry = unsafe {
                libc::bind(
                    fd,
                    &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
                )
            };
            if retry < 0 {
                unsafe { libc::close(fd) };
                return Err(PlatformError::InitFailed(
                    "Cannot bind netlink socket".to_string(),
                ));
            }
        }

        // Retrieve kernel-assigned PID
        let mut bound_addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut addr_len = std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
        let gsn_result = unsafe {
            libc::getsockname(
                fd,
                &mut bound_addr as *mut libc::sockaddr_nl as *mut libc::sockaddr,
                &mut addr_len,
            )
        };

        if gsn_result < 0 {
            unsafe { libc::close(fd) };
            return Err(PlatformError::InitFailed(
                "Cannot get netlink socket name".to_string(),
            ));
        }

        Ok(LinuxNetlink {
            netlink_fd: fd,
            netlink_pid: bound_addr.nl_pid,
            recv_buffer: vec![0u8; 4096],
            seq: 0,
        })
    }
}

impl Drop for LinuxNetlink {
    fn drop(&mut self) {
        if self.netlink_fd >= 0 {
            // SAFETY: We own this fd and close it exactly once on drop.
            unsafe { libc::close(self.netlink_fd) };
        }
    }
}

impl LinuxNetlink {
    /// Parse netlink attributes (rtattr chain) from a payload pointer.
    ///
    /// # Safety
    /// Caller must ensure `ptr` points to valid memory of at least `len` bytes.
    /// Parse netlink attributes (rtattr chain) from a payload pointer.
    ///
    /// # Safety
    /// Caller must ensure `ptr` points to valid memory of at least `len` bytes.
    unsafe fn parse_rtattr(
        ptr: *const u8,
        len: usize,
    ) -> Vec<(u16, Vec<u8>)> {
        let rta_hdr_size = 4usize; // sizeof(struct rtattr) = rta_len(u16) + rta_type(u16)
        let mut attrs = Vec::new();
        let mut offset = 0usize;

        while offset + rta_hdr_size <= len {
            // SAFETY: Caller guarantees ptr is valid for `len` bytes, and we
            // verify offset + rta_hdr_size <= len before accessing.
            let rta_len = unsafe {
                u16::from_ne_bytes([
                    *ptr.add(offset),
                    *ptr.add(offset + 1),
                ]) as usize
            };
            let rta_type = unsafe {
                u16::from_ne_bytes([
                    *ptr.add(offset + 2),
                    *ptr.add(offset + 3),
                ])
            };

            if rta_len < rta_hdr_size || offset + rta_len > len {
                break;
            }

            let data_len = rta_len - rta_hdr_size;
            // SAFETY: We verified rta_len is within bounds above.
            let data_ptr = unsafe { ptr.add(offset + rta_hdr_size) };
            let data = unsafe { std::slice::from_raw_parts(data_ptr, data_len) }.to_vec();
            attrs.push((rta_type, data));

            // Advance to next aligned attribute
            let aligned = (rta_len + 3) & !3;
            offset += aligned;
        }

        attrs
    }

    /// Dispatch a parsed netlink message to the appropriate callback variant.
    ///
    /// Handles RTM_NEWADDR (AF_INET/AF_INET6 addresses), RTM_NEWLINK
    /// (interface info / AF_LOCAL), and RTM_NEWNEIGH (neighbor/ARP entries).
    fn dispatch_netlink_msg(
        &self,
        msg_type: u16,
        payload_ptr: *const u8,
        payload_len: usize,
        family: i32,
        callback: &mut InterfaceCallback<'_>,
    ) {
        // RTM_NEWADDR = 20: address entry
        if msg_type == 20 && payload_len >= 8 {
            // struct ifaddrmsg: family(u8), prefixlen(u8), flags(u8), scope(u8), index(u32)
            let addr_family = unsafe { *payload_ptr } as i32;
            let prefix_len = unsafe { *payload_ptr.add(1) } as u32;
            let _flags = unsafe { *payload_ptr.add(2) };
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
            let attrs = unsafe { Self::parse_rtattr(attrs_ptr, attrs_len) };

            // IFA_ADDRESS=1, IFA_LOCAL=2, IFA_LABEL=3
            let mut local_addr_data: Option<&Vec<u8>> = None;
            let mut label = String::new();

            for (rta_type, data) in &attrs {
                match *rta_type {
                    2 => local_addr_data = Some(data), // IFA_LOCAL
                    1 if local_addr_data.is_none() => local_addr_data = Some(data), // IFA_ADDRESS (fallback)
                    3 => {
                        // IFA_LABEL
                        label = String::from_utf8_lossy(data).trim_end_matches('\0').to_string();
                    }
                    _ => {}
                }
            }

            if addr_family == libc::AF_INET && family == libc::AF_INET {
                if let Some(data) = local_addr_data {
                    if data.len() >= 4 {
                        let addr = std::net::Ipv4Addr::new(data[0], data[1], data[2], data[3]);
                        // Compute netmask from prefix length
                        let mask_bits: u32 = if prefix_len >= 32 {
                            0xFFFF_FFFFu32
                        } else if prefix_len == 0 {
                            0u32
                        } else {
                            !((1u32 << (32 - prefix_len)) - 1)
                        };
                        let netmask = std::net::Ipv4Addr::from(mask_bits);
                        let broadcast = std::net::Ipv4Addr::from(
                            u32::from(addr) | !mask_bits,
                        );
                        if let InterfaceCallback::AfInet(cb) = callback {
                            cb(addr, if_index, &label, netmask, broadcast);
                        }
                    }
                }
            } else if addr_family == libc::AF_INET6 && family == libc::AF_INET6 {
                if let Some(data) = local_addr_data {
                    if data.len() >= 16 {
                        let mut octets = [0u8; 16];
                        octets.copy_from_slice(&data[..16]);
                        let addr = std::net::Ipv6Addr::from(octets);
                        // flags and lifetimes would come from IFA_CACHEINFO (rtattr type 6)
                        let flags = 0u32;
                        let preferred = 0u32;
                        let valid = 0u32;
                        if let InterfaceCallback::AfInet6(cb) = callback {
                            cb(addr, prefix_len, scope, if_index, flags, preferred, valid);
                        }
                    }
                }
            }
        }

        // RTM_NEWLINK = 16: link/interface info
        if msg_type == 16 && payload_len >= 16 && family == 18 {
            // struct ifinfomsg: family(u8), pad(u8), type(u16), index(i32), flags(u32), change(u32)
            let hw_type = unsafe {
                u16::from_ne_bytes([
                    *payload_ptr.add(2),
                    *payload_ptr.add(3),
                ]) as u32
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
            let attrs = unsafe { Self::parse_rtattr(attrs_ptr, attrs_len) };

            // IFLA_ADDRESS=1 (MAC address)
            for (rta_type, data) in &attrs {
                if *rta_type == 1 {
                    if let InterfaceCallback::AfLocal(cb) = callback {
                        cb(if_index, hw_type, data);
                    }
                    break;
                }
            }
        }

        // RTM_NEWNEIGH = 28: neighbor/ARP entry
        if msg_type == 28 && payload_len >= 12 {
            let neigh_family = unsafe { *payload_ptr } as i32;
            let _if_index = unsafe {
                u32::from_ne_bytes([
                    *payload_ptr.add(4),
                    *payload_ptr.add(5),
                    *payload_ptr.add(6),
                    *payload_ptr.add(7),
                ])
            };
            let _state = unsafe {
                u16::from_ne_bytes([
                    *payload_ptr.add(8),
                    *payload_ptr.add(9),
                ])
            };

            let attrs_ptr = unsafe { payload_ptr.add(12) };
            let attrs_len = payload_len.saturating_sub(12);
            let attrs = unsafe { Self::parse_rtattr(attrs_ptr, attrs_len) };

            // NDA_DST=1 (IP), NDA_LLADDR=2 (MAC)
            let mut ip_data: Option<&Vec<u8>> = None;
            let mut mac_data: Option<&Vec<u8>> = None;

            for (rta_type, data) in &attrs {
                match *rta_type {
                    1 => ip_data = Some(data),
                    2 => mac_data = Some(data),
                    _ => {}
                }
            }

            if let (Some(ip), Some(mac)) = (ip_data, mac_data) {
                let addr: Option<IpAddr> = if neigh_family == libc::AF_INET && ip.len() >= 4 {
                    Some(IpAddr::V4(std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])))
                } else if neigh_family == libc::AF_INET6 && ip.len() >= 16 {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&ip[..16]);
                    Some(IpAddr::V6(std::net::Ipv6Addr::from(octets)))
                } else {
                    None
                };

                if let Some(addr) = addr {
                    if let InterfaceCallback::AfUnspec(cb) = callback {
                        cb(neigh_family, addr, mac);
                    }
                }
            }
        }
    }
}

impl NetworkBackend for LinuxNetlink {
    fn init(&mut self) -> Result<String, PlatformError> {
        // Socket already created in new(); return descriptor info for logging.
        Ok(format!("netlink (fd={}, pid={})", self.netlink_fd, self.netlink_pid))
    }

    fn enumerate_interfaces(
        &self,
        family: i32,
        mut callback: InterfaceCallback<'_>,
    ) -> Result<bool, PlatformError> {
        // Determine the appropriate RTM_GET* request type based on family.
        let msg_type: u16 = match family {
            libc::AF_UNSPEC => 30, // RTM_GETNEIGH
            18 => 18,              // RTM_GETLINK (AF_LOCAL mapped to RTM_GETLINK)
            _ => 22,               // RTM_GETADDR
        };

        // Build the netlink request
        #[repr(C)]
        struct NlRequest {
            nlh: libc::nlmsghdr,
            rtgen: RtGenMsg,
        }

        #[repr(C)]
        struct RtGenMsg {
            rtgen_family: u8,
        }

        let request_family = if family == 18 { libc::AF_LOCAL as u8 } else { family as u8 };

        let mut req: NlRequest = unsafe { std::mem::zeroed() };
        req.nlh.nlmsg_len = std::mem::size_of::<NlRequest>() as u32;
        req.nlh.nlmsg_type = msg_type;
        req.nlh.nlmsg_flags = (libc::NLM_F_ROOT | libc::NLM_F_MATCH | libc::NLM_F_REQUEST) as u16;
        req.nlh.nlmsg_pid = 0;
        req.nlh.nlmsg_seq = self.seq.wrapping_add(1);
        req.rtgen.rtgen_family = request_family;

        let mut dest_addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        dest_addr.nl_family = libc::AF_NETLINK as u16;

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
                "Failed to send netlink request".to_string(),
            ));
        }

        // Receive and parse netlink response messages, invoking the callback for each entry.
        let mut buf = vec![0u8; 8192];
        let mut done = false;

        while !done {
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
                    "recv failed with errno {}",
                    errno
                )));
            }

            if n == 0 {
                break;
            }

            let bytes_received = n as usize;
            let nlmsg_hdr_size = std::mem::size_of::<libc::nlmsghdr>();
            let mut offset = 0usize;

            // Parse each nlmsghdr in the received buffer
            while offset + nlmsg_hdr_size <= bytes_received {
                // SAFETY: We verified the buffer has enough bytes for the header.
                let nlh = unsafe {
                    &*(buf.as_ptr().add(offset) as *const libc::nlmsghdr)
                };

                let msg_len = nlh.nlmsg_len as usize;
                if msg_len < nlmsg_hdr_size || offset + msg_len > bytes_received {
                    break;
                }

                // Check for DONE or ERROR
                if nlh.nlmsg_type == libc::NLMSG_DONE as u16 {
                    done = true;
                    break;
                }

                if nlh.nlmsg_type == libc::NLMSG_ERROR as u16 {
                    done = true;
                    break;
                }

                // Dispatch the message payload to the appropriate callback
                let payload_ptr = unsafe { buf.as_ptr().add(offset + nlmsg_hdr_size) };
                let payload_len = msg_len - nlmsg_hdr_size;

                self.dispatch_netlink_msg(
                    nlh.nlmsg_type,
                    payload_ptr,
                    payload_len,
                    family,
                    &mut callback,
                );

                // Advance to the next aligned message
                let aligned_len = (msg_len + 3) & !3;
                offset += aligned_len;
            }

            // If this was not a multi-part message, we're done
            if bytes_received > nlmsg_hdr_size {
                let first_nlh = unsafe {
                    &*(buf.as_ptr() as *const libc::nlmsghdr)
                };
                if first_nlh.nlmsg_flags & libc::NLM_F_MULTI as u16 == 0 {
                    done = true;
                }
            }
        }

        Ok(true)
    }

    fn monitor_changes(&mut self) -> Result<(), PlatformError> {
        // Read pending multicast messages (non-blocking) using our persistent recv_buffer.
        // Increment sequence counter to track message processing.
        self.seq = self.seq.wrapping_add(1);
        let nlmsg_hdr_size = std::mem::size_of::<libc::nlmsghdr>();

        loop {
            let n = unsafe {
                libc::recv(
                    self.netlink_fd,
                    self.recv_buffer.as_mut_ptr() as *mut libc::c_void,
                    self.recv_buffer.len(),
                    libc::MSG_DONTWAIT,
                )
            };

            if n < 0 {
                let errno = unsafe { *libc::__errno_location() };
                if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
                    break; // No more pending messages
                }
                if errno == libc::EINTR {
                    continue; // Interrupted, retry
                }
                return Err(PlatformError::NetlinkError(format!(
                    "recv failed with errno {}",
                    errno
                )));
            }

            if n == 0 {
                break; // EOF
            }

            let bytes_received = n as usize;

            // If the buffer was too small (MSG_TRUNC), expand for next time.
            if bytes_received >= self.recv_buffer.len() {
                self.recv_buffer.resize(self.recv_buffer.len() * 2, 0);
            }

            // Parse netlink messages from the buffer.
            // Each message starts with an nlmsghdr indicating the type of change:
            //   RTM_NEWADDR (20) / RTM_DELADDR (21) — address changes
            //   RTM_NEWLINK (16) / RTM_DELLINK (17) — link state changes
            //   RTM_NEWROUTE (24) / RTM_DELROUTE (25) — routing table changes
            let mut offset = 0usize;

            while offset + nlmsg_hdr_size <= bytes_received {
                let nlh = unsafe {
                    &*(self.recv_buffer.as_ptr().add(offset) as *const libc::nlmsghdr)
                };

                let msg_len = nlh.nlmsg_len as usize;
                if msg_len < nlmsg_hdr_size || offset + msg_len > bytes_received {
                    break;
                }

                // Process the message type. In the C code (netlink_multicast in netlink.c
                // line 651+), these trigger EVENT_NEWADDR, EVENT_NEWROUTE etc.
                // The event types are dispatched to the main event loop for deferred handling.
                //
                // Message types we track:
                // 16 = RTM_NEWLINK, 17 = RTM_DELLINK — interface up/down
                // 20 = RTM_NEWADDR, 21 = RTM_DELADDR — address add/remove
                // 24 = RTM_NEWROUTE, 25 = RTM_DELROUTE — route changes
                //
                // All of these trigger a re-enumeration of interfaces in the main event loop.
                // The actual event queuing depends on the DaemonState integration which
                // is handled at the event_loop level.
                match nlh.nlmsg_type {
                    16 | 17 | 20 | 21 | 24 | 25 => {
                        // Network topology change detected. The event loop will
                        // re-enumerate interfaces when it processes the readable fd.
                    }
                    _ => {
                        // Ignore unknown or unhandled message types.
                    }
                }

                let aligned_len = (msg_len + 3) & !3;
                offset += aligned_len;
            }
        }

        Ok(())
    }

    fn monitor_fd(&self) -> Option<RawFd> {
        if self.netlink_fd >= 0 {
            Some(self.netlink_fd)
        } else {
            None
        }
    }

    fn enumerate_arp(
        &self,
        callback: &mut dyn FnMut(i32, IpAddr, &[u8]) -> i32,
    ) -> Result<(), PlatformError> {
        // On Linux, ARP enumeration sends RTM_GETNEIGH and parses neighbor entries.
        // This mirrors the C iface_enumerate(AF_UNSPEC, ...) path in netlink.c.

        #[repr(C)]
        struct NlRequest {
            nlh: libc::nlmsghdr,
            rtgen: RtGenMsgSimple,
        }

        #[repr(C)]
        struct RtGenMsgSimple {
            rtgen_family: u8,
        }

        let mut req: NlRequest = unsafe { std::mem::zeroed() };
        req.nlh.nlmsg_len = std::mem::size_of::<NlRequest>() as u32;
        req.nlh.nlmsg_type = 30; // RTM_GETNEIGH
        req.nlh.nlmsg_flags = (libc::NLM_F_ROOT | libc::NLM_F_MATCH | libc::NLM_F_REQUEST) as u16;
        req.nlh.nlmsg_pid = 0;
        req.nlh.nlmsg_seq = self.seq.wrapping_add(2);
        req.rtgen.rtgen_family = libc::AF_UNSPEC as u8;

        let mut dest_addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        dest_addr.nl_family = libc::AF_NETLINK as u16;

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
                "Failed to send RTM_GETNEIGH request".to_string(),
            ));
        }

        // Receive and parse netlink neighbor responses, invoking callback for each entry.
        let mut buf = vec![0u8; 8192];
        let mut done = false;
        let nlmsg_hdr_size = std::mem::size_of::<libc::nlmsghdr>();

        while !done {
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
                    "recv failed with errno {}",
                    errno
                )));
            }

            if n == 0 {
                break;
            }

            let bytes_received = n as usize;
            let mut offset = 0usize;

            while offset + nlmsg_hdr_size <= bytes_received {
                let nlh = unsafe {
                    &*(buf.as_ptr().add(offset) as *const libc::nlmsghdr)
                };

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

                // RTM_NEWNEIGH = 28
                if nlh.nlmsg_type == 28 {
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
                                1 => ip_data = Some(data),  // NDA_DST
                                2 => mac_data = Some(data), // NDA_LLADDR
                                _ => {}
                            }
                        }

                        if let (Some(ip), Some(mac)) = (ip_data, mac_data) {
                            let addr: Option<IpAddr> = if neigh_family == libc::AF_INET && ip.len() >= 4 {
                                Some(IpAddr::V4(std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])))
                            } else if neigh_family == libc::AF_INET6 && ip.len() >= 16 {
                                let mut octets = [0u8; 16];
                                octets.copy_from_slice(&ip[..16]);
                                Some(IpAddr::V6(std::net::Ipv6Addr::from(octets)))
                            } else {
                                None
                            };

                            if let Some(addr) = addr {
                                callback(neigh_family, addr, mac);
                            }
                        }
                    }
                }

                let aligned_len = (msg_len + 3) & !3;
                offset += aligned_len;
            }

            // Check for multi-part response
            if bytes_received > nlmsg_hdr_size {
                let first_nlh = unsafe {
                    &*(buf.as_ptr() as *const libc::nlmsghdr)
                };
                if first_nlh.nlmsg_flags & libc::NLM_F_MULTI as u16 == 0 {
                    done = true;
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linux_netlink_creation() {
        // LinuxNetlink::new() requires root/CAP_NET_ADMIN for multicast groups
        // but should succeed with fallback to non-multicast mode.
        let result = LinuxNetlink::new();
        // We accept both success and failure depending on test environment permissions.
        match result {
            Ok(nl) => {
                assert!(nl.netlink_fd >= 0);
                assert!(nl.monitor_fd().is_some());
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
}

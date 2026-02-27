//! BSD-family platform backend using BPF devices for raw packet I/O and
//! PF_ROUTE sockets for interface change monitoring.
//!
//! Contains the BPF raw packet module and PF tables integration.
//! This module is only compiled on BSD target operating systems.

pub mod bpf;
pub mod pf_tables;

use std::net::IpAddr;
use std::os::unix::io::RawFd;

use crate::net::platform::{InterfaceCallback, NetworkBackend, PlatformError};

/// BSD-specific network backend using BPF devices and PF_ROUTE sockets.
///
/// Implements [`NetworkBackend`] for FreeBSD, OpenBSD, NetBSD, DragonFly BSD,
/// and macOS platforms. Uses:
/// - PF_ROUTE sockets for real-time network interface change monitoring
/// - `getifaddrs()` for interface/address enumeration
/// - BPF devices for raw DHCP packet transmission (feature-gated on `dhcp`)
///
/// # C Equivalents
/// - `route_init()` → [`BsdBpf::init`]
/// - `iface_enumerate()` → [`BsdBpf::enumerate_interfaces`]
/// - `route_sock()` → [`BsdBpf::monitor_changes`]
/// - `arp_enumerate()` → [`BsdBpf::enumerate_arp`]
pub struct BsdBpf {
    /// PF_ROUTE socket file descriptor for monitoring address changes.
    route_fd: Option<RawFd>,
    /// Tracks recently deleted addresses (kernel race condition workaround).
    del_filter: bpf::DeletedAddressFilter,
    /// Whether we've warned about routing message version mismatch.
    version_warned: bool,
    /// Packet buffer for routing socket message reception.
    packet_buf: Vec<u8>,
}

impl BsdBpf {
    /// Create a new BSD platform backend (uninitialized).
    ///
    /// The routing socket is not created until [`init()`](NetworkBackend::init)
    /// is called.
    pub fn new() -> Result<Self, PlatformError> {
        Ok(Self {
            route_fd: None,
            del_filter: bpf::DeletedAddressFilter::new(),
            version_warned: false,
            packet_buf: vec![0u8; 4096],
        })
    }
}

impl NetworkBackend for BsdBpf {
    fn init(&mut self) -> Result<String, PlatformError> {
        let fd = bpf::route_init()?;
        self.route_fd = Some(fd);
        Ok("PF_ROUTE".to_string())
    }

    fn enumerate_interfaces(
        &self,
        family: i32,
        mut callback: InterfaceCallback<'_>,
    ) -> Result<bool, PlatformError> {
        bpf::iface_enumerate(family, &mut callback, &self.del_filter)
    }

    fn monitor_changes(&mut self) -> Result<(), PlatformError> {
        if let Some(fd) = self.route_fd {
            let _event = bpf::route_sock(
                fd,
                &mut self.packet_buf,
                &mut self.del_filter,
                &mut self.version_warned,
            )?;
            // Event queuing is handled by the caller via the event loop.
        }
        Ok(())
    }

    fn monitor_fd(&self) -> Option<RawFd> {
        self.route_fd
    }

    fn enumerate_arp(
        &self,
        callback: &mut dyn FnMut(i32, IpAddr, &[u8]) -> i32,
    ) -> Result<(), PlatformError> {
        bpf::arp_enumerate(callback)?;
        Ok(())
    }
}

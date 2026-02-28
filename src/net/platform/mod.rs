//! Platform abstraction layer for OS-specific network operations.
//!
//! This module provides the trait-based platform abstraction that replaces the C
//! preprocessor-based platform selection (`#ifdef HAVE_LINUX_NETWORK` / `#ifdef HAVE_BSD_NETWORK`)
//! with Rust's `#[cfg(target_os)]` conditional compilation and the Strategy design pattern.
//!
//! # Architecture
//!
//! The core abstraction is the [`NetworkBackend`] trait, which defines the interface for:
//! - Network interface enumeration (getifaddrs on BSD, netlink on Linux)
//! - Real-time network change monitoring (PF_ROUTE on BSD, NETLINK_ROUTE on Linux)
//! - ARP/neighbor table enumeration (sysctl on BSD, netlink on Linux)
//!
//! Two concrete implementations exist:
//! - [`LinuxNetlink`] (in [`linux`] submodule) — uses Linux netlink sockets
//! - [`BsdBpf`] (in [`bsd`] submodule) — uses BSD BPF devices and routing sockets
//!
//! The concrete implementation is selected at compile time via `#[cfg(target_os)]`,
//! and the [`create_backend`] factory function returns a trait object for runtime dispatch.
//!
//! # Design Pattern
//!
//! **Strategy Pattern via Traits**: The `NetworkBackend` trait defines a uniform interface
//! for platform-specific network operations. Callers program against the trait, and the
//! concrete implementation (Linux or BSD) is injected at compile time. This replaces the
//! C pattern of `#ifdef HAVE_LINUX_NETWORK` / `#ifdef HAVE_BSD_NETWORK` scattered
//! throughout the codebase.
//!
//! # Callback Model
//!
//! The C `callback_t` union from `dnsmasq.h` (4 function pointer variants dispatched by
//! address family) is replaced by the [`InterfaceCallback`] enum, which wraps typed closures
//! for each address family context. This provides compile-time type safety while preserving
//! the same dispatch semantics.
//!
//! # Platform Support
//!
//! | Platform | Backend | Module |
//! |----------|---------|--------|
//! | Linux | `LinuxNetlink` | `platform::linux` |
//! | FreeBSD, OpenBSD, NetBSD, DragonFly, macOS | `BsdBpf` | `platform::bsd` |
//!
//! # Error Handling
//!
//! All trait methods return `Result<T, PlatformError>` instead of C-style integer
//! error codes, enabling idiomatic Rust error propagation via the `?` operator.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::io::RawFd;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Platform-gated submodule declarations
// ---------------------------------------------------------------------------

/// Linux-specific platform backend using NETLINK_ROUTE for network interface
/// enumeration and monitoring. Contains `LinuxNetlink`, `NetlinkManager`, and
/// optional subsystems (ipset, inotify, conntrack).
#[cfg(target_os = "linux")]
pub mod linux;

/// BSD-family platform backend using BPF devices for raw packet I/O and
/// PF_ROUTE sockets for interface change monitoring. Contains `BsdBpf`
/// and related types.
#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
    target_os = "macos"
))]
pub mod bsd;

// ---------------------------------------------------------------------------
// Error type — PlatformError
// ---------------------------------------------------------------------------

/// Errors from platform-specific network operations.
///
/// Each variant covers a distinct failure mode in the platform abstraction layer.
/// The `EnumerationFailed` variant supports automatic conversion from `std::io::Error`
/// via the `#[from]` attribute.
///
/// # Examples
///
/// ```rust,no_run
/// use dnsmasq::net::platform::PlatformError;
///
/// fn example() -> Result<(), PlatformError> {
///     Err(PlatformError::Unsupported)
/// }
/// ```
#[derive(Debug, Error)]
pub enum PlatformError {
    /// Platform-level initialization failed (socket creation, binding, etc.).
    #[error("Platform initialization failed: {0}")]
    InitFailed(String),

    /// Interface enumeration failed due to an I/O error.
    /// Automatically converts from `std::io::Error`.
    #[error("Interface enumeration failed: {0}")]
    EnumerationFailed(#[from] std::io::Error),

    /// Linux netlink communication error (send, receive, or parse failure).
    #[error("Netlink communication error: {0}")]
    NetlinkError(String),

    /// BSD routing socket communication error.
    #[error("Routing socket error: {0}")]
    RoutingSocketError(String),

    /// BSD BPF device error (open, configure, or transmit failure).
    #[error("BPF device error: {0}")]
    BpfError(String),

    /// ARP/neighbor table enumeration failed.
    #[error("ARP enumeration failed: {0}")]
    ArpEnumerationFailed(String),

    /// The requested operation is not supported on this platform.
    #[error("Unsupported operation on this platform")]
    Unsupported,
}

// ---------------------------------------------------------------------------
// Callback type — InterfaceCallback (replaces C `callback_t` union)
// ---------------------------------------------------------------------------

/// Callback variants for interface enumeration, replacing the C `callback_t` union.
///
/// The C codebase (dnsmasq.h lines 1985-1990) uses a union of four function pointers,
/// dispatched by address family during `iface_enumerate()`. Rust replaces this with an
/// enum of mutable closures, providing compile-time type safety for each callback variant.
///
/// # Variants
///
/// | Variant | C Equivalent | Address Family | Use Case |
/// |---------|-------------|----------------|----------|
/// | `AfUnspec` | `callback_t.af_unspec` | `AF_UNSPEC` | ARP/NDP neighbor enumeration |
/// | `AfInet` | `callback_t.af_inet` | `AF_INET` | IPv4 address enumeration |
/// | `AfInet6` | `callback_t.af_inet6` | `AF_INET6` | IPv6 address enumeration |
/// | `AfLocal` | `callback_t.af_local` | `AF_LOCAL` | Link-layer (MAC) enumeration |
///
/// # Return Value Convention
///
/// All callbacks return `i32`:
/// - **Non-zero (typically 1)**: Continue enumeration
/// - **Zero (0)**: Stop enumeration early (callback-initiated abort)
///
/// This matches the C convention where `iface_enumerate()` checks the callback
/// return value and stops on zero.
pub enum InterfaceCallback<'a> {
    /// Neighbor table enumeration (ARP/NDP) — replaces `callback_t.af_unspec`.
    ///
    /// # Parameters
    /// - `family`: Address family of the neighbor entry (`AF_INET` or `AF_INET6`)
    /// - `addr`: IP address of the neighbor
    /// - `mac`: Hardware (MAC) address bytes
    ///
    /// # C Equivalent
    /// ```c
    /// int (*af_unspec)(int family, void *addrp, char *mac, size_t maclen, void *parmv);
    /// ```
    AfUnspec(&'a mut dyn FnMut(i32, IpAddr, &[u8]) -> i32),

    /// IPv4 address enumeration — replaces `callback_t.af_inet`.
    ///
    /// # Parameters
    /// - `local_addr`: IPv4 address assigned to the interface
    /// - `if_index`: Interface index (ifindex)
    /// - `label`: Interface label/alias name (e.g., `"eth0:1"`)
    /// - `netmask`: IPv4 subnet mask
    /// - `broadcast`: IPv4 broadcast address
    ///
    /// # C Equivalent
    /// ```c
    /// int (*af_inet)(struct in_addr local, int if_index, char *label,
    ///                struct in_addr netmask, struct in_addr broadcast, void *vparam);
    /// ```
    AfInet(&'a mut dyn FnMut(Ipv4Addr, u32, &str, Ipv4Addr, Ipv4Addr) -> i32),

    /// IPv6 address enumeration — replaces `callback_t.af_inet6`.
    ///
    /// # Parameters
    /// - `local_addr`: IPv6 address assigned to the interface
    /// - `prefix_len`: Prefix length (e.g., 64 for /64)
    /// - `scope`: IPv6 address scope (link-local, site, global)
    /// - `if_index`: Interface index
    /// - `flags`: Address flags (TENTATIVE, DEPRECATED, PERMANENT, etc.)
    /// - `preferred_lifetime`: Preferred lifetime in seconds (0xFFFFFFFF = infinity)
    /// - `valid_lifetime`: Valid lifetime in seconds (0xFFFFFFFF = infinity)
    ///
    /// # C Equivalent
    /// ```c
    /// int (*af_inet6)(struct in6_addr *local, int prefix, int scope,
    ///                 int if_index, int flags, unsigned int preferred,
    ///                 unsigned int valid, void *vparam);
    /// ```
    AfInet6(&'a mut dyn FnMut(Ipv6Addr, u32, u32, u32, u32, u32, u32) -> i32),

    /// Link-layer interface enumeration — replaces `callback_t.af_local`.
    ///
    /// # Parameters
    /// - `if_index`: Interface index
    /// - `hw_type`: Hardware type (e.g., `ARPHRD_ETHER` for Ethernet)
    /// - `mac`: Hardware (MAC) address bytes
    ///
    /// # C Equivalent
    /// ```c
    /// int (*af_local)(int index, unsigned int type, char *mac,
    ///                 size_t maclen, void *parm);
    /// ```
    AfLocal(&'a mut dyn FnMut(u32, u32, &[u8]) -> i32),
}

// ---------------------------------------------------------------------------
// Core trait — NetworkBackend
// ---------------------------------------------------------------------------

/// Platform-specific network backend trait.
///
/// This trait abstracts the OS-specific mechanisms for network interface management,
/// providing a uniform API consumed by `InterfaceManager` and the main event loop.
///
/// # Implementations
///
/// - [`LinuxNetlink`] (in `platform::linux`) — uses Linux NETLINK_ROUTE sockets
///   for efficient kernel-push notification of network changes
/// - [`BsdBpf`] (in `platform::bsd`) — uses BSD BPF devices and PF_ROUTE routing
///   sockets for interface monitoring
///
/// # Design
///
/// Implements the **Strategy pattern**: the concrete backend is selected at compile time
/// via `#[cfg(target_os)]` conditional compilation, replacing the C `#ifdef HAVE_LINUX_NETWORK`
/// / `#ifdef HAVE_BSD_NETWORK` preprocessor guards. The [`create_backend`] factory function
/// returns a `Box<dyn NetworkBackend>` for runtime polymorphism.
///
/// # Thread Safety
///
/// All implementations assume single-threaded operation within the dnsmasq event loop.
/// The monitoring file descriptor ([`monitor_fd`](NetworkBackend::monitor_fd)) is registered
/// with `mio::Poll` for event-driven notification.
pub trait NetworkBackend {
    /// Initialize the platform-specific networking subsystem.
    ///
    /// Creates and configures the monitoring socket (netlink on Linux, PF_ROUTE on BSD),
    /// subscribing to relevant network change event groups.
    ///
    /// # Returns
    ///
    /// A descriptive string identifying the initialized subsystem (e.g., `"netlink"`)
    /// for diagnostic logging during daemon startup.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::InitFailed`] if socket creation or binding fails.
    ///
    /// # Platform Details
    ///
    /// - **Linux**: Creates NETLINK_ROUTE socket, subscribes to multicast groups
    ///   (RTMGRP_IPV4_ROUTE, RTMGRP_IPV4_IFADDR, RTMGRP_IPV6_ROUTE, RTMGRP_IPV6_IFADDR,
    ///   RTMGRP_LINK). Replaces `netlink_init()` in `netlink.c` line 165.
    /// - **BSD**: Opens PF_ROUTE routing socket, configures for address change events.
    ///   Replaces `route_init()` in `bpf.c` line 690.
    fn init(&mut self) -> Result<String, PlatformError>;

    /// Enumerate network interfaces and addresses by address family.
    ///
    /// Iterates over all discovered interfaces/addresses matching the requested
    /// address family, invoking the provided callback for each entry. This is the
    /// core enumeration function used by `InterfaceManager::enumerate_interfaces()`.
    ///
    /// # Parameters
    ///
    /// - `family`: Address family filter
    ///   - `libc::AF_INET` — enumerate IPv4 addresses (callback: [`InterfaceCallback::AfInet`])
    ///   - `libc::AF_INET6` — enumerate IPv6 addresses (callback: [`InterfaceCallback::AfInet6`])
    ///   - `libc::AF_UNSPEC` — enumerate ARP/neighbor entries (callback: [`InterfaceCallback::AfUnspec`])
    ///   - `libc::AF_LOCAL` — enumerate link-layer addresses (callback: [`InterfaceCallback::AfLocal`])
    /// - `callback`: The family-appropriate callback variant
    ///
    /// # Returns
    ///
    /// - `Ok(true)` — enumeration completed successfully
    /// - `Ok(false)` — enumeration was aborted by a callback returning 0
    /// - `Err(_)` — a platform error occurred during enumeration
    ///
    /// # Platform Details
    ///
    /// - **Linux**: Sends RTM_GETADDR / RTM_GETLINK / RTM_GETNEIGH netlink requests
    ///   and processes responses. Replaces `iface_enumerate()` in `netlink.c` line 370.
    /// - **BSD**: Uses `getifaddrs()` to enumerate all interface addresses.
    ///   Replaces `iface_enumerate()` in `bpf.c` line 275.
    fn enumerate_interfaces(
        &self,
        family: i32,
        callback: InterfaceCallback<'_>,
    ) -> Result<bool, PlatformError>;

    /// Process asynchronous network change events.
    ///
    /// Called from the main event loop when the monitoring socket
    /// ([`monitor_fd`](NetworkBackend::monitor_fd)) becomes readable. Parses incoming
    /// messages and queues appropriate events (EVENT_NEWADDR, EVENT_NEWROUTE) for
    /// deferred processing.
    ///
    /// # Platform Details
    ///
    /// - **Linux**: Reads and parses netlink multicast messages (RTM_NEWADDR, RTM_DELADDR,
    ///   RTM_NEWLINK, RTM_NEWROUTE). Replaces `netlink_multicast()` in `netlink.c` line 651.
    /// - **BSD**: Reads routing socket messages (RTM_NEWADDR, RTM_DELADDR).
    ///   Replaces `route_sock()` in `bpf.c` line 740.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::NetlinkError`] or [`PlatformError::RoutingSocketError`]
    /// if reading or parsing the monitoring socket fails.
    fn monitor_changes(&mut self) -> Result<(), PlatformError>;

    /// Get the file descriptor for the monitoring socket.
    ///
    /// This fd is registered with `mio::Poll` for event-driven monitoring in the
    /// main event loop. Returns `None` if the monitoring subsystem was not
    /// successfully initialized (e.g., insufficient permissions).
    ///
    /// # Returns
    ///
    /// - `Some(fd)` — the raw file descriptor for the netlink (Linux) or routing (BSD) socket
    /// - `None` — monitoring is not available
    fn monitor_fd(&self) -> Option<RawFd>;

    /// Enumerate ARP/neighbor table entries.
    ///
    /// Retrieves the kernel's ARP (IPv4) and neighbor (IPv6) cache, invoking the
    /// callback for each entry with the address family, IP address, and hardware
    /// (MAC) address.
    ///
    /// # Parameters
    ///
    /// - `callback`: Invoked for each ARP/neighbor entry. Parameters:
    ///   - `family` (`i32`): `AF_INET` or `AF_INET6`
    ///   - `addr` ([`IpAddr`]): IP address of the neighbor
    ///   - `mac` (`&[u8]`): Hardware address bytes (typically 6 for Ethernet)
    ///   Returns `i32`: non-zero to continue, zero to stop.
    ///
    /// # Platform Details
    ///
    /// - **BSD**: Uses `sysctl(NET_RT_FLAGS, RTF_LLINFO)` to enumerate ARP table.
    ///   Replaces `arp_enumerate()` in `bpf.c` line 160.
    /// - **Linux**: Uses netlink `RTM_GETNEIGH` to enumerate neighbor table.
    ///   Replaces `iface_enumerate(AF_UNSPEC, ...)` in `netlink.c`.
    fn enumerate_arp(
        &self,
        callback: &mut dyn FnMut(i32, IpAddr, &[u8]) -> i32,
    ) -> Result<(), PlatformError>;
}

// ---------------------------------------------------------------------------
// BSD-specific trait — RawPacketSender
// ---------------------------------------------------------------------------

/// Trait for raw packet transmission, used by the DHCP server on BSD platforms.
///
/// On BSD, DHCP requires BPF (Berkeley Packet Filter) devices for raw Ethernet frame
/// injection, because DHCP clients may not yet have valid IP addresses and cannot
/// respond to ARP requests. On Linux, raw sockets handle this directly in the DHCP
/// module without needing BPF.
///
/// # Implementations
///
/// Only [`BsdBpf`] implements this trait, gated behind BSD target OS detection.
///
/// # C Equivalents
///
/// - `init_bpf()` in `bpf.c` line 466 → [`RawPacketSender::init_bpf`]
/// - `send_via_bpf()` in `bpf.c` line 557 → [`RawPacketSender::send_raw_packet`]
#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
    target_os = "macos"
))]
pub trait RawPacketSender {
    /// Initialize BPF device for raw packet transmission.
    ///
    /// Opens `/dev/bpfN` (iterating through available devices), configures the
    /// BPF filter program, and stores the descriptor for subsequent sends.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::BpfError`] if no BPF device is available or
    /// configuration fails.
    fn init_bpf(&mut self) -> Result<(), PlatformError>;

    /// Send a raw DHCP packet via BPF, constructing Ethernet and IP headers.
    ///
    /// Builds a complete Ethernet frame with:
    /// 1. Ethernet header (source MAC from interface, destination MAC or broadcast)
    /// 2. IPv4 header with manual checksum calculation
    /// 3. UDP header (source port 67, destination port 68) with pseudo-header checksum
    /// 4. DHCP payload
    ///
    /// # Parameters
    ///
    /// - `data`: Raw DHCP payload bytes
    /// - `dest_addr`: Destination IP address (client yiaddr or broadcast)
    /// - `dest_port`: Destination UDP port (typically 68 for DHCP client)
    /// - `iface_addr`: Source IP address (server interface address)
    /// - `iface_name`: Network interface name (e.g., `"eth0"`)
    ///
    /// # Returns
    ///
    /// The number of bytes written to the BPF device on success.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::BpfError`] if the write to the BPF device fails.
    fn send_raw_packet(
        &self,
        data: &[u8],
        dest_addr: IpAddr,
        dest_port: u16,
        iface_addr: IpAddr,
        iface_name: &str,
    ) -> Result<usize, PlatformError>;
}

// ---------------------------------------------------------------------------
// Platform-specific re-exports
// ---------------------------------------------------------------------------

/// Convenience re-export of the Linux-specific network backend.
///
/// `LinuxNetlink` implements [`NetworkBackend`] using NETLINK_ROUTE sockets
/// for interface enumeration and async network change monitoring.
#[cfg(target_os = "linux")]
pub use self::linux::LinuxNetlink;

/// Convenience re-export of the BSD-specific network backend.
///
/// `BsdBpf` implements both [`NetworkBackend`] and [`RawPacketSender`],
/// using BPF devices for raw packets and PF_ROUTE sockets for monitoring.
#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
    target_os = "macos"
))]
pub use self::bsd::BsdBpf;

// ---------------------------------------------------------------------------
// Factory function — create_backend()
// ---------------------------------------------------------------------------

/// Create the platform-appropriate network backend.
///
/// Returns a boxed trait object implementing [`NetworkBackend`] for the current
/// target OS. This is the primary entry point for obtaining a platform backend
/// instance during daemon initialization.
///
/// # Supported Platforms
///
/// - **Linux**: Returns a [`LinuxNetlink`] instance backed by NETLINK_ROUTE
/// - **BSD/macOS**: Returns a [`BsdBpf`] instance backed by BPF and PF_ROUTE
///
/// # Errors
///
/// - [`PlatformError::InitFailed`] — backend construction failed (socket error, etc.)
/// - [`PlatformError::Unsupported`] — compiled for an unsupported platform
///
/// # Examples
///
/// ```rust,no_run
/// use dnsmasq::net::platform::{create_backend, NetworkBackend};
///
/// let mut backend = create_backend().expect("platform init failed");
/// let name = backend.init().expect("backend init failed");
/// println!("Initialized platform backend: {}", name);
/// ```
pub fn create_backend() -> Result<Box<dyn NetworkBackend>, PlatformError> {
    #[cfg(target_os = "linux")]
    {
        Ok(Box::new(linux::LinuxNetlink::new()?))
    }

    #[cfg(any(
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
        target_os = "macos"
    ))]
    {
        Ok(Box::new(bsd::BsdBpf::new()?))
    }

    #[cfg(not(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
        target_os = "macos"
    )))]
    {
        Err(PlatformError::Unsupported)
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_error_display() {
        let err = PlatformError::InitFailed("socket creation failed".to_string());
        assert_eq!(
            err.to_string(),
            "Platform initialization failed: socket creation failed"
        );

        let err = PlatformError::NetlinkError("send timeout".to_string());
        assert_eq!(
            err.to_string(),
            "Netlink communication error: send timeout"
        );

        let err = PlatformError::RoutingSocketError("read failed".to_string());
        assert_eq!(err.to_string(), "Routing socket error: read failed");

        let err = PlatformError::BpfError("device busy".to_string());
        assert_eq!(err.to_string(), "BPF device error: device busy");

        let err = PlatformError::ArpEnumerationFailed("sysctl error".to_string());
        assert_eq!(err.to_string(), "ARP enumeration failed: sysctl error");

        let err = PlatformError::Unsupported;
        assert_eq!(
            err.to_string(),
            "Unsupported operation on this platform"
        );
    }

    #[test]
    fn test_platform_error_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "test");
        let platform_err: PlatformError = io_err.into();
        match platform_err {
            PlatformError::EnumerationFailed(ref e) => {
                assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied);
            }
            _ => panic!("Expected EnumerationFailed variant"),
        }
    }

    #[test]
    fn test_platform_error_debug() {
        let err = PlatformError::Unsupported;
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("Unsupported"));
    }

    #[test]
    fn test_interface_callback_variants_exist() {
        // Verify each callback variant can be constructed with a closure.
        let mut called = false;

        let mut cb_unspec = |_family: i32, _addr: IpAddr, _mac: &[u8]| -> i32 {
            called = true;
            1
        };
        let _variant = InterfaceCallback::AfUnspec(&mut cb_unspec);

        let mut cb_inet =
            |_addr: Ipv4Addr, _idx: u32, _label: &str, _mask: Ipv4Addr, _bcast: Ipv4Addr| -> i32 {
                1
            };
        let _variant = InterfaceCallback::AfInet(&mut cb_inet);

        let mut cb_inet6 =
            |_addr: Ipv6Addr, _prefix: u32, _scope: u32, _idx: u32, _flags: u32, _pref: u32, _valid: u32| -> i32 {
                1
            };
        let _variant = InterfaceCallback::AfInet6(&mut cb_inet6);

        let mut cb_local = |_idx: u32, _hw_type: u32, _mac: &[u8]| -> i32 { 1 };
        let _variant = InterfaceCallback::AfLocal(&mut cb_local);

        // Ensure the test infrastructure works (not testing runtime behavior here).
        assert!(!called);
    }
}

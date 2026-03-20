// Copyright (C) 2024 Simon Kelley and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.

//! Network interface management and platform abstraction layer.
//!
//! Migrated from `src/network.c`, `src/netlink.c`, `src/bpf.c`, `src/arp.c`
//! (8,351 lines total of C source code).
//!
//! # Architecture
//!
//! This module provides the network interface management and platform
//! abstraction layer for the dnsmasq Rust implementation.  It replaces the C
//! `HAVE_LINUX_NETWORK` / `HAVE_BSD_NETWORK` preprocessor guards with Rust's
//! `cfg(target_os)` conditional compilation attributes.
//!
//! ## Capabilities
//!
//! - **Interface enumeration and address discovery**: Detecting network
//!   interfaces and their assigned IPv4/IPv6 addresses via platform-native
//!   APIs (netlink on Linux, `getifaddrs` on BSD/macOS).
//! - **Socket creation, binding, and listener management**: Creating and
//!   managing listening sockets for DNS, DHCP, and TFTP services.
//! - **Platform-specific network monitoring**: Real-time kernel notifications
//!   for address and route changes (NETLINK_ROUTE on Linux, PF_ROUTE on BSD).
//! - **ARP/neighbor cache management**: Cross-platform ARP cache inspection
//!   for DHCP conflict detection.
//! - **Upstream DNS server socket pooling and management**: Pre-allocating and
//!   reusing server file descriptors for upstream DNS forwarding.
//!
//! ## Module hierarchy
//!
//! ```text
//! network/
//! ├── mod.rs       ← This file: module root, re-exports, traits, constants
//! ├── interface.rs ← From network.c: platform-independent core (interface
//! │                   enum, listeners, servers)
//! ├── netlink.rs   ← From netlink.c: Linux netlink (cfg(linux))
//! ├── bpf.rs       ← From bpf.c: BSD BPF + routing socket (cfg(bsd/macos))
//! └── arp.rs       ← From arp.c: ARP cache management (cross-platform)
//! ```
//!
//! ## Design decisions
//!
//! 1. `interface.rs` is the primary file — it contains all the functions that
//!    other modules call for interface enumeration, listener creation, and
//!    server socket management.
//! 2. `netlink.rs` and `bpf.rs` are platform backends consumed by
//!    `interface.rs` during enumeration and monitoring.
//! 3. `arp.rs` is semi-independent — used by the DHCP module for conflict
//!    detection.
//! 4. `mod.rs` ties everything together with re-exports and shared
//!    constants/traits.
//! 5. Platform-specific modules are conditionally compiled via
//!    `#[cfg(target_os = "...")]`, ensuring zero-cost abstraction with no
//!    dead code on any platform.

use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr};

use thiserror::Error;

// ---------------------------------------------------------------------------
// Sub-module declarations
// ---------------------------------------------------------------------------

/// Linux netlink socket interface for network interface monitoring.
/// Provides real-time kernel notifications for address and route changes.
/// Replaces C `HAVE_LINUX_NETWORK` gating on `netlink.c`.
#[cfg(target_os = "linux")]
pub mod netlink;

/// BSD BPF raw packet I/O and PF_ROUTE interface monitoring.
/// Compiled only on FreeBSD, OpenBSD, and macOS.
/// Replaces C `HAVE_BSD_NETWORK` gating on `bpf.c`.
#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "macos"))]
pub mod bpf;

/// Core network interface management: enumeration, socket binding, listeners.
/// Migrated from `network.c` — the platform-independent network management core.
pub mod interface;

/// ARP/neighbor cache management for DHCP address conflict detection.
/// Migrated from `arp.c` — maintains internal ARP cache with periodic
/// kernel synchronization, MAC lookup API, and script notifications.
pub mod arp;

// ---------------------------------------------------------------------------
// Module-level constants
// ---------------------------------------------------------------------------
// These constants are shared across sub-modules and exposed to the rest of the
// crate.  Values match the original C definitions from `dnsmasq.h` and
// `config.h`.

/// Interface address is in tentative state (IPv6 DAD in progress).
///
/// Corresponds to `IFA_F_TENTATIVE` in the Linux kernel.  Used by the
/// interface enumeration logic to detect addresses undergoing duplicate
/// address detection.
///
/// Value `1` matches the C `IFACE_TENTATIVE` constant (also defined in
/// `netlink.rs` for Linux-specific code paths).
pub const IFACE_TENTATIVE: u32 = 1;

/// Interface address is deprecated (still usable, but not preferred for new
/// connections).
///
/// Corresponds to `IFA_F_DEPRECATED` in the Linux kernel.
pub const IFACE_DEPRECATED: u32 = 2;

/// Interface address is permanent (not dynamically assigned via DHCP/SLAAC).
///
/// Corresponds to `IFA_F_PERMANENT` in the Linux kernel.
pub const IFACE_PERMANENT: u32 = 4;

/// Interface name has been matched to an actual interface.
///
/// Set by `--interface` / `--except-interface` processing when the named
/// interface is discovered during enumeration.  Re-exported from
/// `interface.rs` for module-level access.
pub const INAME_USED: u32 = 1;

/// IPv4 address is configured on the named interface.
pub const INAME_4: u32 = 2;

/// IPv6 address is configured on the named interface.
pub const INAME_6: u32 = 4;

/// Network address change event from netlink/routing socket.
///
/// Emitted when a new address is added to or removed from an interface.
/// This is a module-level event state bit used for deduplication during
/// multicast message batching (distinct from `EventCode::NewAddr` = 22
/// used in the pipe-based event system).
pub const EVENT_NEWADDR: u32 = 1;

/// Network route change event from netlink/routing socket.
///
/// Emitted when a route is added or removed.  Used for deduplication during
/// multicast message batching (distinct from `EventCode::NewRoute` = 23
/// used in the pipe-based event system).
pub const EVENT_NEWROUTE: u32 = 2;

// ---------------------------------------------------------------------------
// Re-exports — Core types
// ---------------------------------------------------------------------------
// The canonical struct/enum definitions live in `crate::core::types`.
// `interface.rs` adds `impl` blocks with additional methods (family, port,
// set_port, etc.).  We re-export from `core::types` so consumers can write
// `use crate::network::{MySockAddr, InterfaceRecord, ...}` for convenience.

pub use crate::core::types::{InterfaceName, InterfaceRecord, Listener, MySockAddr, ServerFd};

// ---------------------------------------------------------------------------
// Re-exports — Public functions from interface module
// ---------------------------------------------------------------------------

pub use interface::{
    check_servers,
    create_bound_listeners,
    // Listener management
    create_wildcard_listeners,
    // Interface enumeration
    enumerate_interfaces,
    // Socket utilities
    fix_fd,
    iface_check,
    // Interface checking
    index_to_name,
    is_dad_listeners,

    label_exception,

    // Server socket management
    local_bind,
    loopback_exception,
    // Helper
    mysockaddr_ip,

    // Dynamic reconfiguration
    newaddress,
    pre_allocate_sfds,
    reload_servers,

    reset_enumerate_flag,

    set_ipv6pktinfo,
    tcp_interface,

    warn_bound_listeners,
    warn_int_names,
    warn_wild_labels,
};

/// Conditionally re-export `join_multicast` from `interface` — only available
/// when the DHCPv6 feature is enabled, as multicast is required for DHCPv6
/// solicitation/advertisement on link-local addresses.
#[cfg(feature = "dhcp6")]
pub use interface::join_multicast;

// ---------------------------------------------------------------------------
// Re-exports — ARP types and functions from arp module
// ---------------------------------------------------------------------------

pub use arp::{
    // Functions
    do_arp_script_run,
    find_mac,
    // Types
    ArpCache,
    ArpEnumerator,
    ArpRecord,
    ArpStatus,
    // Constants
    DHCP_CHADDR_MAX,
};

// ---------------------------------------------------------------------------
// Conditional re-exports — Linux netlink (cfg(target_os = "linux"))
// ---------------------------------------------------------------------------

/// Netlink interface callback enum — platform-specific to Linux.
#[cfg(target_os = "linux")]
pub use netlink::IfaceCallback;

/// Netlink-based network implementation — platform-specific to Linux.
#[cfg(target_os = "linux")]
pub use netlink::NetlinkNetwork;

/// Initialize the netlink socket for interface enumeration and monitoring.
#[cfg(target_os = "linux")]
pub use netlink::netlink_init;

/// Process pending netlink multicast messages, returning batched events.
#[cfg(target_os = "linux")]
pub use netlink::netlink_multicast;

/// Asynchronous netlink message handler — called from the main event loop
/// when the netlink socket is readable.
#[cfg(target_os = "linux")]
pub use netlink::nl_async;

// ---------------------------------------------------------------------------
// Conditional re-exports — BSD/macOS BPF and routing socket
// ---------------------------------------------------------------------------

/// BPF-based network implementation — platform-specific to BSD/macOS.
#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "macos"))]
pub use bpf::BpfNetwork;

/// Initialize BPF device for raw packet I/O (DHCP).
#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "macos"))]
pub use bpf::init_bpf;

/// Send an Ethernet frame via BPF device.
#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "macos"))]
pub use bpf::send_via_bpf;

/// Initialize the PF_ROUTE socket for route/address change notifications.
#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "macos"))]
pub use bpf::route_init;

/// Read and process a message from the PF_ROUTE socket.
#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "macos"))]
pub use bpf::route_sock;

// ---------------------------------------------------------------------------
// Network-specific error types
// ---------------------------------------------------------------------------

/// Network-specific errors extending [`crate::core::types::DnsmasqError`].
///
/// These error variants cover failures in network socket operations, interface
/// discovery, multicast group membership, and platform-specific monitoring
/// initialization.  Can be converted into `DnsmasqError::Network(...)` via
/// the `From` impl.
#[derive(Error, Debug)]
pub enum NetworkError {
    /// Socket creation failed (`socket(2)` returned an error).
    #[error("socket creation failed: {0}")]
    SocketCreate(#[source] std::io::Error),

    /// Socket bind failed (`bind(2)` returned an error).
    #[error("socket bind failed: {0}")]
    BindFailed(#[source] std::io::Error),

    /// Requested network interface was not found during enumeration.
    #[error("interface not found: {0}")]
    InterfaceNotFound(String),

    /// Multicast group join failed on a specific interface.
    #[error("multicast join failed on interface {interface}: {error}")]
    MulticastJoinFailed {
        /// The interface name on which the join was attempted.
        interface: String,
        /// The underlying I/O error from `setsockopt`.
        #[source]
        error: std::io::Error,
    },

    /// Platform network monitoring initialization failed.
    #[error("monitoring initialization failed: {0}")]
    MonitoringInitFailed(#[source] std::io::Error),
}

/// Convert [`NetworkError`] into [`DnsmasqError::Network`] for seamless
/// propagation with the `?` operator in functions returning `DnsmasqResult<T>`.
impl From<NetworkError> for crate::core::types::DnsmasqError {
    fn from(err: NetworkError) -> Self {
        crate::core::types::DnsmasqError::Network(err.to_string())
    }
}

// ---------------------------------------------------------------------------
// Platform abstraction trait
// ---------------------------------------------------------------------------

/// Trait for platform-specific network operations.
///
/// Linux implementation uses netlink sockets, BSD uses `getifaddrs()` + BPF +
/// PF_ROUTE routing sockets.  This trait provides a unified interface for
/// platform-independent code in `interface.rs` and `crate::core::daemon`.
///
/// # Object Safety
///
/// This trait is object-safe so it can be used behind `Box<dyn PlatformNetwork>`.
/// Callback parameters use `&mut dyn FnMut(...)` instead of generic type
/// parameters to maintain object safety.
///
/// # Thread Safety
///
/// Implementations are NOT required to be `Send` or `Sync` — the dnsmasq
/// architecture is single-threaded (single async task with `tokio::select!`).
pub trait PlatformNetwork {
    /// Enumerate IPv4 network interfaces and their addresses.
    ///
    /// Calls the provided callback for each discovered interface/address pair.
    /// The callback receives:
    /// - `Ipv4Addr` — the interface address
    /// - `u32` — the interface index
    /// - `Option<&str>` — the interface name (if available)
    /// - `Ipv4Addr` — the network mask
    /// - `Ipv4Addr` — the broadcast address
    ///
    /// The callback returns `true` to continue enumeration or `false` to stop.
    ///
    /// Returns the number of interfaces enumerated, or an I/O error.
    fn enumerate_interfaces_v4(
        &mut self,
        callback: &mut dyn FnMut(Ipv4Addr, u32, Option<&str>, Ipv4Addr, Ipv4Addr) -> bool,
    ) -> std::io::Result<i32>;

    /// Enumerate IPv6 network interfaces and their addresses.
    ///
    /// Calls the provided callback for each discovered interface/address pair.
    /// The callback receives:
    /// - `Ipv6Addr` — the interface address
    /// - `u32` — the interface index
    /// - `u32` — the prefix length
    /// - `u32` — the scope ID
    /// - `u32` — the interface flags (`IFACE_TENTATIVE`, `IFACE_DEPRECATED`, etc.)
    /// - `u32` — the preferred lifetime
    /// - `u32` — the valid lifetime
    ///
    /// The callback returns `true` to continue enumeration or `false` to stop.
    ///
    /// Returns the number of interfaces enumerated, or an I/O error.
    fn enumerate_interfaces_v6(
        &mut self,
        callback: &mut dyn FnMut(Ipv6Addr, u32, u32, u32, u32, u32, u32) -> bool,
    ) -> std::io::Result<i32>;

    /// Initialize platform-specific network monitoring.
    ///
    /// On Linux, this sets `NETLINK_NO_ENOBUFS` on the multicast netlink
    /// socket to avoid losing events under heavy load.
    ///
    /// On BSD, this is a no-op (the PF_ROUTE socket is set up during
    /// construction).
    fn init_monitoring(&mut self) -> std::io::Result<()>;
}

// ---------------------------------------------------------------------------
// Platform factory function
// ---------------------------------------------------------------------------

/// Create a platform-appropriate [`PlatformNetwork`] implementation.
///
/// Returns a `NetlinkNetwork` on Linux or `BpfNetwork` on BSD/macOS.
///
/// # Errors
///
/// Returns an `std::io::Error` if the underlying platform socket cannot be
/// created (e.g., insufficient privileges or exhausted file descriptors).
///
/// # Platform dispatch
///
/// This function uses compile-time `cfg` dispatch — there is no runtime
/// overhead from dynamic dispatch beyond the `Box<dyn PlatformNetwork>`
/// vtable indirection.
pub fn create_platform_network() -> std::io::Result<Box<dyn PlatformNetwork>> {
    #[cfg(target_os = "linux")]
    {
        netlink::NetlinkNetwork::new()
            .map(|n| Box::new(n) as Box<dyn PlatformNetwork>)
            .map_err(|e| std::io::Error::other(e.to_string()))
    }

    #[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "macos"))]
    {
        bpf::BpfNetwork::new()
            .map(|b| Box::new(b) as Box<dyn PlatformNetwork>)
            .map_err(|e| std::io::Error::other(e.to_string()))
    }

    // Fallback for unsupported platforms — compile error at build time if
    // neither Linux nor BSD is detected.
    #[cfg(not(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "macos"
    )))]
    {
        compile_error!("Unsupported platform: dnsmasq requires Linux or BSD network stack");
    }
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

/// Returns the size of the C `sockaddr` structure for the given address family.
///
/// This is used for system calls that require the `addrlen` parameter
/// (e.g., `bind`, `connect`, `sendto`).  The sizes correspond to the C
/// `sizeof(struct sockaddr_in)` and `sizeof(struct sockaddr_in6)`.
///
/// Replaces the C `sa_len()` macro from `dnsmasq.h`.
///
/// # Arguments
///
/// * `addr` — A reference to a [`MySockAddr`] whose address family determines
///   the returned size.
///
/// # Returns
///
/// The byte size of the corresponding C `sockaddr_in` or `sockaddr_in6`
/// structure.
pub fn sa_len(addr: &MySockAddr) -> usize {
    match addr {
        MySockAddr::V4(_) => mem::size_of::<libc::sockaddr_in>(),
        MySockAddr::V6(_) => mem::size_of::<libc::sockaddr_in6>(),
    }
}

/// Format a [`MySockAddr`] as a human-readable address string and extract the
/// port number.
///
/// Replaces C `prettyprint_addr()` from `util.c`, which wrote into a global
/// static buffer.  This Rust version returns an owned `String` for thread
/// safety.
///
/// # Returns
///
/// A tuple of `(formatted_address, port)`:
/// - IPv4 example: `("192.168.1.1", 53)`
/// - IPv6 example: `("2001:db8::1", 547)` (compressed form)
/// - IPv6 with scope example: `("fe80::1%3", 0)` — scope ID appended when
///   non-zero
pub fn prettyprint_addr(addr: &MySockAddr) -> (String, u16) {
    match addr {
        MySockAddr::V4(sa) => (sa.ip().to_string(), sa.port()),
        MySockAddr::V6(sa) => {
            let ip = sa.ip();
            let port = sa.port();
            let scope = sa.scope_id();
            if scope != 0 {
                (format!("{}%{}", ip, scope), port)
            } else {
                (ip.to_string(), port)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// PlatformNetwork trait implementations
// ---------------------------------------------------------------------------
// These impl blocks implement the PlatformNetwork trait for the concrete
// platform types, adapting their native method signatures (which may use
// DnsmasqResult, generics, etc.) to the trait's object-safe signature
// (which uses std::io::Result and &mut dyn FnMut).

#[cfg(target_os = "linux")]
impl PlatformNetwork for netlink::NetlinkNetwork {
    fn enumerate_interfaces_v4(
        &mut self,
        callback: &mut dyn FnMut(Ipv4Addr, u32, Option<&str>, Ipv4Addr, Ipv4Addr) -> bool,
    ) -> std::io::Result<i32> {
        // Use UFCS to call the inherent method (not the trait method) to avoid
        // infinite recursion.  The inherent method returns DnsmasqResult<i32>
        // which we convert to std::io::Result<i32>.
        netlink::NetlinkNetwork::enumerate_interfaces_v4(self, callback)
            .map_err(|e| std::io::Error::other(e.to_string()))
    }

    fn enumerate_interfaces_v6(
        &mut self,
        callback: &mut dyn FnMut(Ipv6Addr, u32, u32, u32, u32, u32, u32) -> bool,
    ) -> std::io::Result<i32> {
        netlink::NetlinkNetwork::enumerate_interfaces_v6(self, callback)
            .map_err(|e| std::io::Error::other(e.to_string()))
    }

    fn init_monitoring(&mut self) -> std::io::Result<()> {
        // NetlinkNetwork::init_monitoring takes &self (not &mut self),
        // sets NETLINK_NO_ENOBUFS on the socket.  Returns void.
        netlink::NetlinkNetwork::init_monitoring(self);
        Ok(())
    }
}

#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "macos"))]
impl PlatformNetwork for bpf::BpfNetwork {
    fn enumerate_interfaces_v4(
        &mut self,
        callback: &mut dyn FnMut(Ipv4Addr, u32, Option<&str>, Ipv4Addr, Ipv4Addr) -> bool,
    ) -> std::io::Result<i32> {
        // BpfNetwork's inherent method uses a generic closure taking
        // `(Ipv4Addr, u32, &str, Ipv4Addr, Ipv4Addr) -> bool`.
        // We wrap the interface name in `Some()` to match the trait's
        // `Option<&str>` parameter.
        let result =
            bpf::BpfNetwork::enumerate_interfaces_v4(self, |addr, index, name, mask, bcast| {
                callback(addr, index, Some(name), mask, bcast)
            });
        match result {
            Ok(_) => Ok(0), // BSD returns bool, trait returns count
            Err(e) => Err(std::io::Error::other(e.to_string())),
        }
    }

    fn enumerate_interfaces_v6(
        &mut self,
        callback: &mut dyn FnMut(Ipv6Addr, u32, u32, u32, u32, u32, u32) -> bool,
    ) -> std::io::Result<i32> {
        let result = bpf::BpfNetwork::enumerate_interfaces_v6(
            self,
            |addr, index, prefix_len, scope_id, flags, pref_lt, valid_lt| {
                callback(addr, index, prefix_len, scope_id, flags, pref_lt, valid_lt)
            },
        );
        match result {
            Ok(_) => Ok(0),
            Err(e) => Err(std::io::Error::other(e.to_string())),
        }
    }

    fn init_monitoring(&mut self) -> std::io::Result<()> {
        bpf::BpfNetwork::init_monitoring(self).map_err(|e| std::io::Error::other(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Unit tests
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
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    // -- Constant correctness tests --

    #[test]
    fn test_iface_constants_values() {
        assert_eq!(IFACE_TENTATIVE, 1);
        assert_eq!(IFACE_DEPRECATED, 2);
        assert_eq!(IFACE_PERMANENT, 4);
    }

    #[test]
    fn test_iface_constants_no_overlap() {
        assert_eq!(IFACE_TENTATIVE & IFACE_DEPRECATED, 0);
        assert_eq!(IFACE_TENTATIVE & IFACE_PERMANENT, 0);
        assert_eq!(IFACE_DEPRECATED & IFACE_PERMANENT, 0);
    }

    #[test]
    fn test_iname_constants_values() {
        assert_eq!(INAME_USED, 1);
        assert_eq!(INAME_4, 2);
        assert_eq!(INAME_6, 4);
    }

    #[test]
    fn test_iname_constants_no_overlap() {
        assert_eq!(INAME_USED & INAME_4, 0);
        assert_eq!(INAME_USED & INAME_6, 0);
        assert_eq!(INAME_4 & INAME_6, 0);
    }

    #[test]
    fn test_event_constants_values() {
        assert_eq!(EVENT_NEWADDR, 1);
        assert_eq!(EVENT_NEWROUTE, 2);
        assert_ne!(EVENT_NEWADDR, EVENT_NEWROUTE);
    }

    // -- sa_len tests --

    #[test]
    fn test_sa_len_v4() {
        let addr = MySockAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53));
        let len = sa_len(&addr);
        assert_eq!(len, mem::size_of::<libc::sockaddr_in>());
        // sockaddr_in is at least 16 bytes on all POSIX platforms
        assert!(len >= 16);
    }

    #[test]
    fn test_sa_len_v6() {
        let addr = MySockAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 53, 0, 0));
        let len = sa_len(&addr);
        assert_eq!(len, mem::size_of::<libc::sockaddr_in6>());
        // sockaddr_in6 is at least 28 bytes on all POSIX platforms
        assert!(len >= 28);
    }

    #[test]
    fn test_sa_len_v6_larger_than_v4() {
        let v4 = MySockAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
        let v6 = MySockAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0));
        assert!(sa_len(&v6) > sa_len(&v4));
    }

    // -- prettyprint_addr tests --

    #[test]
    fn test_prettyprint_addr_v4_basic() {
        let addr = MySockAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 53));
        let (formatted, port) = prettyprint_addr(&addr);
        assert_eq!(formatted, "192.168.1.1");
        assert_eq!(port, 53);
    }

    #[test]
    fn test_prettyprint_addr_v4_unspecified() {
        let addr = MySockAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
        let (formatted, port) = prettyprint_addr(&addr);
        assert_eq!(formatted, "0.0.0.0");
        assert_eq!(port, 0);
    }

    #[test]
    fn test_prettyprint_addr_v4_localhost() {
        let addr = MySockAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8053));
        let (formatted, port) = prettyprint_addr(&addr);
        assert_eq!(formatted, "127.0.0.1");
        assert_eq!(port, 8053);
    }

    #[test]
    fn test_prettyprint_addr_v6_basic() {
        let addr = MySockAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            547,
            0,
            0,
        ));
        let (formatted, port) = prettyprint_addr(&addr);
        assert_eq!(formatted, "2001:db8::1");
        assert_eq!(port, 547);
    }

    #[test]
    fn test_prettyprint_addr_v6_with_scope() {
        let addr = MySockAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
            0,
            0,
            3,
        ));
        let (formatted, port) = prettyprint_addr(&addr);
        assert_eq!(formatted, "fe80::1%3");
        assert_eq!(port, 0);
    }

    #[test]
    fn test_prettyprint_addr_v6_loopback() {
        let addr = MySockAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 8053, 0, 0));
        let (formatted, port) = prettyprint_addr(&addr);
        assert_eq!(formatted, "::1");
        assert_eq!(port, 8053);
    }

    #[test]
    fn test_prettyprint_addr_v6_no_scope() {
        let addr = MySockAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
            547,
            0,
            0, // scope_id = 0 → no %scope suffix
        ));
        let (formatted, port) = prettyprint_addr(&addr);
        assert_eq!(formatted, "fe80::1");
        assert_eq!(port, 547);
    }

    // -- NetworkError tests --

    #[test]
    fn test_network_error_socket_create_display() {
        let err = NetworkError::SocketCreate(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "access denied",
        ));
        let msg = format!("{}", err);
        assert!(msg.contains("socket creation failed"));
        assert!(msg.contains("access denied"));
    }

    #[test]
    fn test_network_error_bind_display() {
        let err = NetworkError::BindFailed(std::io::Error::new(
            std::io::ErrorKind::AddrInUse,
            "address in use",
        ));
        let msg = format!("{}", err);
        assert!(msg.contains("socket bind failed"));
        assert!(msg.contains("address in use"));
    }

    #[test]
    fn test_network_error_interface_not_found_display() {
        let err = NetworkError::InterfaceNotFound("eth99".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("interface not found"));
        assert!(msg.contains("eth99"));
    }

    #[test]
    fn test_network_error_multicast_join_display() {
        let err = NetworkError::MulticastJoinFailed {
            interface: "eth0".to_string(),
            error: std::io::Error::new(std::io::ErrorKind::Other, "no such device"),
        };
        let msg = format!("{}", err);
        assert!(msg.contains("multicast join failed"));
        assert!(msg.contains("eth0"));
    }

    #[test]
    fn test_network_error_monitoring_init_display() {
        let err = NetworkError::MonitoringInitFailed(std::io::Error::new(
            std::io::ErrorKind::Other,
            "netlink socket failed",
        ));
        let msg = format!("{}", err);
        assert!(msg.contains("monitoring initialization failed"));
    }

    #[test]
    fn test_network_error_to_dnsmasq_error() {
        let err = NetworkError::InterfaceNotFound("lo0".to_string());
        let dnsmasq_err: crate::core::types::DnsmasqError = err.into();
        match dnsmasq_err {
            crate::core::types::DnsmasqError::Network(msg) => {
                assert!(msg.contains("interface not found"));
                assert!(msg.contains("lo0"));
            }
            other => panic!("Expected DnsmasqError::Network, got {:?}", other),
        }
    }

    #[test]
    fn test_network_error_socket_create_to_dnsmasq() {
        let err = NetworkError::SocketCreate(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "EPERM",
        ));
        let dnsmasq_err: crate::core::types::DnsmasqError = err.into();
        match dnsmasq_err {
            crate::core::types::DnsmasqError::Network(msg) => {
                assert!(msg.contains("socket creation failed"));
            }
            other => panic!("Expected DnsmasqError::Network, got {:?}", other),
        }
    }

    // -- Re-export accessibility tests --

    #[test]
    fn test_reexported_types_accessible() {
        // Verify that re-exported types from core::types are accessible
        // through the network module.  These are compile-time checks that
        // the `pub use` statements work correctly.
        let _addr = MySockAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));

        // Verify InterfaceRecord fields are accessible
        let _rec = InterfaceRecord {
            addr: std::net::IpAddr::V4(Ipv4Addr::LOCALHOST),
            netmask: None,
            name: "lo".to_string(),
            index: 1,
            label: 0,
            flags: 0,
        };

        // Verify Listener fields are accessible
        let _listener = Listener {
            fd: -1,
            tcpfd: -1,
            tftpfd: -1,
            family: libc::AF_INET,
            iface: None,
        };
    }

    // -- PlatformNetwork trait tests (compile-time) --

    #[test]
    fn test_platform_network_trait_is_object_safe() {
        // This test verifies that PlatformNetwork is object-safe by
        // attempting to create a trait object reference.  If the trait
        // is not object-safe, this will fail at compile time.
        fn _accept_trait_object(_net: &dyn PlatformNetwork) {}
        fn _accept_boxed(_net: Box<dyn PlatformNetwork>) {}
    }
}

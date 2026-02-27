//! Network interface management, socket pooling, and platform abstraction.
//!
//! This module provides the networking infrastructure for dnsmasq, handling:
//!
//! - **Interface discovery and monitoring** ([`interface`]) — enumerates system network
//!   interfaces, creates and binds listener sockets for DNS, DHCP, and TFTP services,
//!   and supports runtime interface reloading on SIGHUP.
//!
//! - **Upstream DNS server socket pool** ([`socket`]) — manages the pool of UDP sockets
//!   used for forwarding DNS queries to upstream servers, with randomized source port
//!   allocation (`RANDOM_SOCKS = 64`) as a defense against DNS cache poisoning (RFC 5452).
//!
//! - **ARP/neighbor cache** ([`arp`]) — maintains an internal cache of IP-to-MAC address
//!   mappings by periodically reading the kernel ARP/neighbor table (90-second refresh
//!   interval), primarily for DHCP address-in-use testing and client identification.
//!
//! - **Platform-specific networking backends** ([`platform`]) — provides trait-based
//!   abstraction for OS-specific network operations (interface enumeration, route/address
//!   change monitoring, ARP table reads) with concrete implementations for Linux (netlink
//!   sockets) and BSD (BPF devices and routing sockets).
//!
//! # Architecture
//!
//! The `net` module replaces the flat C source files with a hierarchical Rust module tree
//! organized by functional domain:
//!
//! | C Source File    | Rust Module                          | Transformation |
//! |------------------|--------------------------------------|----------------|
//! | `network.c`      | [`interface`] + [`socket`]           | Split by responsibility: interface/listener management vs. upstream socket pool |
//! | `arp.c`          | [`arp`]                              | Direct 1:1 rewrite with `Vec<ArpRecord>` replacing intrusive linked list |
//! | `netlink.c`      | `platform::linux::netlink`           | Linux NETLINK_ROUTE interface and route events |
//! | `bpf.c`          | `platform::bsd::bpf`                 | BSD BPF raw packet I/O and PF_ROUTE monitoring |
//! | `ipset.c`        | `platform::linux::ipset`             | Linux ipset via netlink (`#[cfg(feature = "ipset")]`) |
//! | `inotify.c`      | `platform::linux::inotify`           | File-change monitoring (`#[cfg(feature = "inotify_monitor")]`) |
//! | `conntrack.c`    | `platform::linux::conntrack`         | Conntrack mark retrieval (`#[cfg(feature = "conntrack")]`) |
//! | `tables.c`       | `platform::bsd::pf_tables`           | BSD PF table population |
//!
//! # Platform Abstraction
//!
//! The [`platform::NetworkBackend`] trait implements the **Strategy Pattern** to replace
//! the C preprocessor-based platform selection (`#ifdef HAVE_LINUX_NETWORK` /
//! `#ifdef HAVE_BSD_NETWORK`). All platform-specific behavior is abstracted behind a
//! uniform trait interface, with concrete implementations selected at compile time via
//! `#[cfg(target_os)]` guards.
//!
//! ```text
//! ┌─────────────────────────────────┐
//! │      NetworkBackend (trait)      │
//! │  init(), enumerate_interfaces() │
//! │  monitor_changes(), monitor_fd()│
//! │  enumerate_arp()                │
//! └──────────┬──────────┬───────────┘
//!            │          │
//!   ┌────────▼──┐  ┌───▼─────────┐
//!   │LinuxNetlink│  │   BsdBpf    │
//!   │(netlink.rs)│  │  (bpf.rs)   │
//!   └───────────┘  └─────────────┘
//! ```
//!
//! # Feature Gates
//!
//! Feature gating is applied **inside** individual submodules at the function and `impl`
//! level, not on the submodule declarations themselves. The relevant Cargo features are:
//!
//! - `dhcp` / `dhcp6` — DHCP-related socket and interface operations
//! - `tftp` — TFTP listener socket creation
//! - `ipset` — Linux ipset population via netlink
//! - `inotify_monitor` — Linux inotify file-change monitoring
//! - `conntrack` — Linux netfilter conntrack mark retrieval
//! - `dump` — Pcap packet capture on listener sockets
//!
//! # Cross-Module Dependencies
//!
//! This module is consumed by several other subsystems:
//!
//! - [`crate::dns::forward`] → uses [`SocketPool`] for upstream query dispatch
//! - [`crate::core::event_loop`] → uses [`InterfaceManager`] for listener socket
//!   registration and [`platform::NetworkBackend`] for change monitoring
//! - [`crate::dhcp`] → uses [`InterfaceManager`] for DHCP interface binding and
//!   [`ArpCache`] for address-in-use testing
//! - [`crate::core::daemon`] → owns instances of all primary types in this module

// ---------------------------------------------------------------------------
// Submodule declarations
// ---------------------------------------------------------------------------

/// Network interface enumeration and listener socket management.
///
/// Provides [`InterfaceManager`] which replaces the interface and listener
/// management portions of C `network.c`. Handles interface discovery,
/// wildcard vs. specific binding, listener socket creation for DNS/DHCP/TFTP,
/// and runtime interface reloading.
pub mod interface;

/// Upstream DNS server socket pool and randomized source port allocation.
///
/// Provides [`SocketPool`] which replaces the socket management portion of
/// C `network.c`. Manages server file descriptor pooling, random source port
/// allocation (`RANDOM_SOCKS = 64`), and server socket lifecycle operations.
pub mod socket;

/// ARP/neighbor cache for IP-to-MAC address resolution.
///
/// Provides [`ArpCache`] which is a complete rewrite of C `arp.c`. Maintains
/// an internal cache with 90-second kernel refresh interval and supports
/// MAC lookup for DHCP operations and script-driven ARP event notifications.
pub mod arp;

/// Platform abstraction layer for OS-specific network operations.
///
/// Provides the [`NetworkBackend`] trait with compile-time selected
/// implementations: `LinuxNetlink` on Linux (via netlink sockets) and
/// `BsdBpf` on BSD-family systems (via BPF devices and routing sockets).
/// Also contains platform-gated subsystem modules for ipset, inotify,
/// conntrack (Linux) and PF tables (BSD).
pub mod platform;

// ---------------------------------------------------------------------------
// Re-exports — primary public types for convenient cross-module access
// ---------------------------------------------------------------------------

/// Re-export [`interface::InterfaceManager`] for convenient access.
///
/// `InterfaceManager` is the primary entry point for interface enumeration
/// and listener socket management. Most callers import via `crate::net::InterfaceManager`.
pub use interface::InterfaceManager;

/// Re-export [`socket::SocketPool`] for convenient access.
///
/// `SocketPool` manages the upstream DNS server socket pool with randomized
/// source port allocation. Most callers import via `crate::net::SocketPool`.
pub use socket::SocketPool;

/// Re-export [`arp::ArpCache`] for convenient access.
///
/// `ArpCache` provides IP-to-MAC address resolution from the kernel ARP/neighbor
/// table. Most callers import via `crate::net::ArpCache`.
pub use arp::ArpCache;

/// Re-export [`platform::NetworkBackend`] for convenient access.
///
/// `NetworkBackend` is the trait defining platform-abstracted network operations.
/// Most callers import via `crate::net::NetworkBackend`.
pub use platform::NetworkBackend;

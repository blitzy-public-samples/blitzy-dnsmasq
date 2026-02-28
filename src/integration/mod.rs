//! External system integration modules for dnsmasq.
//!
//! This module provides interfaces to external services and protocols that extend
//! dnsmasq's core DNS/DHCP functionality. Each submodule is independently feature-gated,
//! allowing optional compilation of external integrations based on Cargo feature flags.
//!
//! # Submodules
//!
//! - [`dbus`] — D-Bus system bus control interface (feature: `dbus`)
//!   Provides programmatic management and monitoring of dnsmasq via the D-Bus system bus,
//!   including server reconfiguration, metrics retrieval, cache management, and DHCP lease
//!   signals. Requires `libdbus-1` at link time.
//!
//! - [`ubus`] — OpenWrt UBus control interface (feature: `ubus`)
//!   Provides lightweight IPC for OpenWrt and embedded Linux distributions, exposing
//!   metrics, DHCP events, and connmark allowlist management via the UBus protocol.
//!   Requires `libubus`/`libubox` at link time.
//!
//! - [`nftset`] — nftables set population for DNS-driven firewall rules (feature: `nftset`)
//!   Populates nftables sets dynamically based on DNS resolution results, enabling
//!   DNS-driven firewall policies. Requires `libnftables` at link time.
//!
//! - [`tftp`] — Read-only TFTP server for PXE network boot (feature: `tftp`)
//!   Implements a read-only TFTP server conforming to RFC 1350, RFC 2349 (option
//!   negotiation), and RFC 7440 (windowsize). Pure Rust implementation with no external
//!   library dependencies.
//!
//! # Feature Gates
//!
//! Each submodule maps to a C compile-time flag from the original dnsmasq codebase:
//!
//! | Cargo Feature | C Flag        | Module   | External Library  |
//! |---------------|---------------|----------|-------------------|
//! | `dbus`        | `HAVE_DBUS`   | `dbus`   | libdbus-1         |
//! | `ubus`        | `HAVE_UBUS`   | `ubus`   | libubus/libubox   |
//! | `nftset`      | `HAVE_NFTSET` | `nftset` | libnftables       |
//! | `tftp`        | `HAVE_TFTP`   | `tftp`   | none (pure Rust)  |
//!
//! When no integration features are enabled, this module compiles as an empty module
//! with no code generation overhead.
//!
//! # Architecture
//!
//! These modules form the outermost integration layer of dnsmasq. The D-Bus, UBus,
//! and nftset modules contain the only permitted `unsafe` blocks in the codebase
//! (for FFI to external C libraries). The TFTP module is a pure Rust implementation
//! requiring no `unsafe` code.
//!
//! The integration layer depends on the core runtime (`crate::core`), type definitions
//! (`crate::types`), and optionally the DHCP subsystem (`crate::dhcp`) for lease
//! management signals. It does not depend on the DNS forwarding or caching layers
//! directly — those interactions are mediated through the `DaemonState` struct.
//!
//! # Event Loop Integration
//!
//! Each integration module that requires I/O (D-Bus, UBus, TFTP) participates in the
//! central `mio`-based event loop via the `EventSource` trait pattern:
//!
//! - `set_*_listeners()` — Registers file descriptors with the poll set
//! - `check_*_listeners()` — Dispatches events when poll indicates readiness
//!
//! The nftset module is fire-and-forget (no persistent connections) and does not
//! participate in the event loop.

// ---------------------------------------------------------------------------
// Feature-gated submodule declarations
//
// Each submodule is compiled only when its corresponding Cargo feature is enabled.
// This mirrors the C codebase's `#ifdef HAVE_*` conditional compilation guards
// from src/config.h.
// ---------------------------------------------------------------------------

/// D-Bus system bus control interface.
///
/// Provides programmatic management of dnsmasq via the D-Bus system bus,
/// including upstream server reconfiguration (`SetServers`, `SetServersEx`),
/// metrics retrieval (`GetMetrics`, `GetServerMetrics`), cache management
/// (`ClearCache`), and DHCP lease lifecycle signals (`DhcpLeaseAdded`,
/// `DhcpLeaseDeleted`, `DhcpLeaseUpdated`).
///
/// Replaces the C implementation in `src/dbus.c` (2175 lines).
/// Requires `libdbus-1` at link time.
///
/// Enabled by the `dbus` Cargo feature (equivalent to C's `HAVE_DBUS`).
#[cfg(feature = "dbus")]
pub mod dbus;

/// OpenWrt UBus lightweight IPC interface.
///
/// Provides metrics export, DHCP lease event broadcasting, and connmark
/// allowlist management for OpenWrt and embedded Linux deployments via
/// the UBus protocol.
///
/// Replaces the C implementation in `src/ubus.c` (968 lines).
/// Requires `libubus` and `libubox` at link time.
///
/// Enabled by the `ubus` Cargo feature (equivalent to C's `HAVE_UBUS`).
#[cfg(feature = "ubus")]
pub mod ubus;

/// nftables set population for DNS-driven firewall rules.
///
/// Dynamically adds and removes IP addresses from nftables sets based on
/// DNS resolution results, enabling transparent DNS-driven firewall policies.
/// Uses fire-and-forget command execution via `libnftables`.
///
/// Replaces the C implementation in `src/nftset.c` (392 lines).
/// Requires `libnftables` at link time.
///
/// Enabled by the `nftset` Cargo feature (equivalent to C's `HAVE_NFTSET`).
#[cfg(feature = "nftset")]
pub mod nftset;

/// Read-only TFTP server for PXE network boot.
///
/// Implements a standards-compliant TFTP server supporting RFC 1350 (base protocol),
/// RFC 2349 (blksize, tsize, timeout option negotiation), and RFC 7440 (windowsize
/// extension). Designed primarily for PXE/UEFI network boot scenarios.
///
/// Replaces the C implementation in `src/tftp.c` (1647 lines).
/// Pure Rust implementation — no external library dependencies.
///
/// Enabled by the `tftp` Cargo feature (equivalent to C's `HAVE_TFTP`).
#[cfg(feature = "tftp")]
pub mod tftp;

// ---------------------------------------------------------------------------
// Re-exports for ergonomic access
//
// Key types from each submodule are re-exported at the integration module level
// so consumers can use `crate::integration::DbusState` instead of
// `crate::integration::dbus::DbusState`.
// ---------------------------------------------------------------------------

/// Re-export [`DbusState`](dbus::DbusState) for convenient access when the
/// `dbus` feature is enabled.
#[cfg(feature = "dbus")]
pub use self::dbus::DbusState;

/// Re-export [`UbusState`](ubus::UbusState) for convenient access when the
/// `ubus` feature is enabled.
#[cfg(feature = "ubus")]
pub use self::ubus::UbusState;

/// Re-export [`NftsetState`](nftset::NftsetState) for convenient access when the
/// `nftset` feature is enabled.
#[cfg(feature = "nftset")]
pub use self::nftset::NftsetState;

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

//! # External Integrations Module
//!
//! This module provides dnsmasq's external system integration interfaces,
//! migrated from 7 C source files totaling 6,305 lines.
//!
//! Each integration is independently feature-gated via Cargo features,
//! matching the C `HAVE_*` preprocessor macro pattern from `config.h`.
//!
//! ## Sub-modules:
//! - [`dbus`] — D-Bus interface for NetworkManager (from `dbus.c`, `cfg(feature = "dbus")`)
//! - [`ubus`] — OpenWrt UBus interface (from `ubus.c`, `cfg(feature = "ubus")`)
//! - [`helper`] — Script execution for lease events (from `helper.c`, `cfg(feature = "script")`)
//! - [`conntrack`] — Linux conntrack marks (from `conntrack.c`, `cfg(feature = "conntrack")`)
//! - [`ipset`] — Linux ipset via netlink (from `ipset.c`, `cfg(feature = "ipset")`)
//! - [`nftset`] — nftables sets (from `nftset.c`, `cfg(feature = "nftset")`)
//! - [`tables`] — BSD PF tables (from `tables.c`, `cfg(target_os = "freebsd")`)
//!
//! ## Feature Flag Mapping (C `HAVE_*` → Cargo features):
//! - `HAVE_DBUS`      → `cfg(feature = "dbus")`       (disabled by default)
//! - `HAVE_UBUS`      → `cfg(feature = "ubus")`       (disabled by default)
//! - `HAVE_SCRIPT`    → `cfg(feature = "script")`      (enabled by default)
//! - `HAVE_CONNTRACK` → `cfg(feature = "conntrack")`   (disabled by default)
//! - `HAVE_IPSET`     → `cfg(feature = "ipset")`       (enabled by default)
//! - `HAVE_NFTSET`    → `cfg(feature = "nftset")`      (disabled by default)
//! - BSD PF tables    → `cfg(target_os = "freebsd")`   (auto-detected)
//!
//! ## Architecture
//! - Each integration independently feature-gated via Cargo features
//! - Script execution uses async process spawning via tokio
//! - D-Bus interface maintains identical API contract for NetworkManager compatibility
//! - Firewall integrations (ipset, nftset, tables) use platform-native kernel APIs

// ---------------------------------------------------------------------------
// Feature-gated sub-module declarations
// ---------------------------------------------------------------------------

/// D-Bus message bus integration for NetworkManager compatibility.
///
/// Provides [`DbusController`] for programmatic dnsmasq management via the
/// system D-Bus message bus. Exposes server reconfiguration, cache management,
/// metrics retrieval, and DHCP lease event signalling to external clients.
///
/// Migrated from `src/dbus.c` (2,175 lines).
#[cfg(feature = "dbus")]
pub mod dbus;

/// OpenWrt UBus message bus integration.
///
/// Provides [`UbusController`] for OpenWrt embedded system integration,
/// including metrics export, cache management, and DHCP event broadcasting
/// via [`UbusController::event_bcast`].
///
/// Migrated from `src/ubus.c` (968 lines).
#[cfg(feature = "ubus")]
pub mod ubus;

/// Script execution helper for DHCP/TFTP/ARP event callbacks.
///
/// Provides [`ScriptHelper`] for async process spawning of user-configured
/// lease-change scripts, [`EventAction`] enum for event types, [`ScriptEvent`]
/// data structure, and convenience wrappers [`queue_script`] and [`queue_arp`].
/// Supports optional Lua scripting via the `luascript` feature.
///
/// Migrated from `src/helper.c` (1,528 lines).
#[cfg(feature = "script")]
pub mod helper;

/// Linux netfilter conntrack mark retrieval for DNS policy routing.
///
/// Provides [`get_incoming_mark`] for querying the Linux kernel's conntrack
/// table to retrieve connection marks associated with incoming DNS queries,
/// enabling VPN split-horizon and per-connection DNS policies.
/// Error conditions are reported via [`ConntrackError`].
///
/// Migrated from `src/conntrack.c` (324 lines).
#[cfg(all(feature = "conntrack", target_os = "linux"))]
pub mod conntrack;

/// Linux ipset integration via netlink for DNS-based firewall rules.
///
/// Provides [`IpsetController`] for dynamically populating named ipset
/// collections with IP addresses resolved from DNS queries, enabling
/// domain-based firewall rules via iptables/ipset.
///
/// Migrated from `src/ipset.c` (532 lines).
#[cfg(all(feature = "ipset", target_os = "linux"))]
pub mod ipset;

/// nftables set manipulation for modern Linux firewall integration.
///
/// Provides [`NftsetController`] for adding/removing IP addresses in nftables
/// sets, enabling domain-based firewall policies on modern Linux systems.
/// Error conditions are reported via [`NftsetError`].
///
/// Migrated from `src/nftset.c` (392 lines).
#[cfg(all(feature = "nftset", target_os = "linux"))]
pub mod nftset;

/// BSD PF table integration for DNS-based firewall rule population.
///
/// Provides [`PfTableController`] for creating PF tables and adding/removing
/// IP addresses via ioctl on `/dev/pf`. Platform-gated to FreeBSD/OpenBSD/NetBSD.
///
/// Migrated from `src/tables.c` (386 lines).
#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
pub mod tables;

// ---------------------------------------------------------------------------
// Public re-exports for ergonomic access
// ---------------------------------------------------------------------------
// Re-export commonly-used types when features are enabled, allowing callers
// to use `crate::integration::DbusController` instead of
// `crate::integration::dbus::DbusController`.

/// D-Bus controller, error type, service constants, and signal emission.
#[cfg(feature = "dbus")]
pub use dbus::{emit_signal, DbusController, DbusError, DBUS_OBJECT_PATH, DBUS_SERVICE_NAME};

/// OpenWrt UBus controller (event broadcasting via [`UbusController::event_bcast`]).
#[cfg(feature = "ubus")]
pub use ubus::UbusController;

/// Script helper, event types, and convenience queue functions.
#[cfg(feature = "script")]
pub use helper::{EventAction, ScriptEvent, ScriptHelper};

/// Convenience re-export of [`queue_script`] for DHCP lease events.
/// Only available when both `script` and `dhcp` features are enabled,
/// since the function signature references [`DhcpLease`].
#[cfg(all(feature = "script", feature = "dhcp"))]
pub use helper::queue_script;

/// Convenience re-export of [`queue_arp`] for ARP table change events.
#[cfg(feature = "script")]
pub use helper::queue_arp;

/// Conntrack mark retrieval function and error type.
#[cfg(all(feature = "conntrack", target_os = "linux"))]
pub use conntrack::{get_incoming_mark, ConntrackError};

/// Linux ipset controller for DNS-based firewall rule population.
#[cfg(all(feature = "ipset", target_os = "linux"))]
pub use ipset::IpsetController;

/// nftables set controller and error type.
#[cfg(all(feature = "nftset", target_os = "linux"))]
pub use nftset::{NftsetController, NftsetError};

/// BSD PF table controller for DNS-based firewall rules.
#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
pub use tables::PfTableController;

// ---------------------------------------------------------------------------
// Feature flag mapping from C HAVE_* macros to Cargo features:
//
// HAVE_DBUS      → cfg(feature = "dbus")       (disabled by default)
// HAVE_UBUS      → cfg(feature = "ubus")       (disabled by default)
// HAVE_SCRIPT    → cfg(feature = "script")      (enabled by default)
// HAVE_CONNTRACK → cfg(feature = "conntrack")   (disabled by default)
// HAVE_IPSET     → cfg(feature = "ipset")       (enabled by default)
// HAVE_NFTSET    → cfg(feature = "nftset")      (disabled by default)
// HAVE_BSD_IPSET → cfg(target_os = "freebsd")   (auto-detected)
//
// Platform-specific modules use target_os gates replacing the C
// #ifdef HAVE_LINUX_NETWORK / HAVE_BSD_NETWORK preprocessor guards:
//   - conntrack, ipset, nftset → cfg(target_os = "linux")
//   - tables                   → cfg(any(target_os = "freebsd",
//                                        target_os = "openbsd",
//                                        target_os = "netbsd"))
// ---------------------------------------------------------------------------

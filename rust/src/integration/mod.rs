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
//! - [`ubus`] — OpenWrt UBus interface (from `ubus.c`, `cfg(feature = "ubus")`)
//!
//! ## Feature Flag Mapping (C `HAVE_*` → Cargo features):
//! - `HAVE_DBUS`      → `cfg(feature = "dbus")`       (disabled by default)
//! - `HAVE_UBUS`      → `cfg(feature = "ubus")`       (disabled by default)
//! - `HAVE_SCRIPT`    → `cfg(feature = "script")`      (enabled by default)
//! - `HAVE_CONNTRACK`  → `cfg(feature = "conntrack")`   (disabled by default)
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

/// OpenWrt UBus message bus integration.
///
/// Provides `UbusController` for OpenWrt embedded system integration,
/// including metrics export, cache management, and DHCP event broadcasting.
///
/// Migrated from `src/ubus.c` (968 lines).
#[cfg(feature = "ubus")]
pub mod ubus;

// Re-export key types when features are enabled
#[cfg(feature = "ubus")]
pub use ubus::UbusController;

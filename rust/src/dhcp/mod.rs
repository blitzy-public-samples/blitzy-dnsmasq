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

//! # DHCP Subsystem Module
//!
//! Complete DHCP implementation for dnsmasq, providing DHCPv4, DHCPv6,
//! Router Advertisement, SLAAC address tracking, and lease management.
//! Migrated from 13 C source files totaling 20,569 lines.
//!
//! ## Sub-modules
//! - [`v4`] — DHCPv4 implementation (DISCOVER/OFFER/REQUEST/ACK state machine)
//! - [`v6`] — DHCPv6 implementation (SOLICIT/ADVERTISE/REQUEST/REPLY), gated by `dhcp6` feature
//! - [`common`] — Shared DHCP utilities, option tables, tag matching
//! - [`lease`] — Lease management with persistent storage (identical file format for migration)
//! - [`radv`] — IPv6 Router Advertisement (RFC 4861), gated by `dhcp6` feature
//! - [`slaac`] — SLAAC address confirmation (RFC 4862), gated by `dhcp6` feature
//! - [`ip6addr`] — IPv6 address classification utilities
//!
//! ## Architecture
//! The DHCP subsystem uses a shared lease database (`lease.rs`) accessed by both
//! DHCPv4 and DHCPv6 servers. The tag-based client classification system (`common.rs`)
//! enables flexible per-client configuration. Router Advertisement (`radv.rs`)
//! coordinates with DHCPv6 via M/O flags for unified IPv6 address management.
//!
//! ## Feature Flags
//! - `dhcp` — Enable entire DHCP subsystem (lib.rs gates this module)
//! - `dhcp6` — Enable DHCPv6, Router Advertisement, SLAAC (implies `dhcp`)
//!
//! ## C Source Mapping
//! | Rust Module | C Source Files | Total Lines | Description |
//! |------------|----------------|-------------|-------------|
//! | `v4/server.rs` | `dhcp.c` | 2,344 | DHCPv4 server core |
//! | `v4/protocol.rs` | `rfc2131.c`, `dhcp-protocol.h` | 6,145 | DHCPv4 protocol |
//! | `v4/options.rs` | `dhcp-common.c` | (shared) | DHCPv4 option encode/decode |
//! | `v6/server.rs` | `dhcp6.c` | 1,487 | DHCPv6 server core |
//! | `v6/protocol.rs` | `rfc3315.c`, `dhcp6-protocol.h` | 4,901 | DHCPv6 protocol |
//! | `v6/outpacket.rs` | `outpacket.c` | 702 | DHCPv6 packet construction |
//! | `common.rs` | `dhcp-common.c` | 2,337 | Shared utilities |
//! | `lease.rs` | `lease.c` | 3,364 | Lease management |
//! | `radv.rs` | `radv.c`, `radv-protocol.h` | 3,044 | Router Advertisement |
//! | `slaac.rs` | `slaac.c` | 537 | SLAAC tracking |
//! | `ip6addr.rs` | `ip6addr.h` | 183 | IPv6 address utilities |

// ============================================================================
// Sub-module Declarations
// ============================================================================

/// DHCPv4 implementation: server, protocol state machine, option handling.
/// Migrated from dhcp.c (2,344 lines), rfc2131.c (5,209 lines), dhcp-protocol.h (936 lines).
pub mod v4;

/// DHCPv6 implementation: server, protocol state machine, packet construction.
/// Migrated from dhcp6.c (1,487 lines), rfc3315.c (4,216 lines), dhcp6-protocol.h (685 lines).
/// Requires `dhcp6` feature flag (maps to C's HAVE_DHCP6).
#[cfg(feature = "dhcp6")]
pub mod v6;

/// Shared DHCP utilities for both v4 and v6.
/// Tag matching, option tables, config lookup, device binding.
/// Migrated from dhcp-common.c (2,337 lines).
pub mod common;

/// DHCP lease management with persistent storage.
/// Supports both v4 and v6 leases with identical file format to C version.
/// Migrated from lease.c (3,364 lines).
pub mod lease;

/// IPv6 Router Advertisement construction and dispatch per RFC 4861.
/// Coordinates with DHCPv6 via M/O flags.
/// Migrated from radv.c (2,175 lines) + radv-protocol.h (869 lines).
/// Requires `dhcp6` feature flag.
#[cfg(feature = "dhcp6")]
pub mod radv;

/// SLAAC address tracking and duplicate address detection.
/// Derives addresses from MAC+prefix via EUI-64, confirms with ICMPv6 ping.
/// Migrated from slaac.c (537 lines).
/// Requires `dhcp6` feature flag.
#[cfg(feature = "dhcp6")]
pub mod slaac;

/// IPv6 address classification utilities.
/// ULA detection (RFC 4193), link-local zero prefix detection.
/// Migrated from ip6addr.h (183 lines).
pub mod ip6addr;

// ============================================================================
// Public Re-exports — Lease Types
//
// These re-exports allow other modules to use `crate::dhcp::DhcpLease`
// instead of the more verbose `crate::dhcp::lease::DhcpLease`.
// ============================================================================

/// DHCP lease record (DHCPv4 and DHCPv6).
pub use lease::DhcpLease;
/// Lease change tracking flags for script notification and persistence.
pub use lease::LeaseFlags;
/// DHCPv6 lease type discriminator (Na/Ta/Pd/V4).
pub use lease::LeaseType;

// ============================================================================
// Public Re-exports — Common DHCP Types
//
// Core types used by the configuration parser, DNS cache integration,
// and other subsystems outside the DHCP module.
// ============================================================================

/// Static per-client DHCP configuration.
pub use common::DhcpConfig;
/// DHCP address pool / context configuration.
pub use common::DhcpContext;
/// DHCP option configuration entry.
pub use common::DhcpOpt;
/// DHCP protocol version selector (V4/V6).
pub use common::DhcpProtocol;
/// Network identifier tag for client classification.
pub use common::NetId;

// ============================================================================
// Public Re-exports — IPv6 Address Utilities
//
// Pure functions used by radv, slaac, and v6 modules for address
// classification during prefix delegation and RA construction.
// ============================================================================

/// Test if an IPv6 address has a link-local zero prefix (fe80:: with zero interface ID).
pub use ip6addr::is_link_local_zero;
/// Test if an IPv6 address is a Unique Local Address (ULA, fd00::/8) per RFC 4193.
pub use ip6addr::is_ula;
/// Test if an IPv6 address is exactly the ULA zero address (fd00::).
pub use ip6addr::is_ula_zero;

// ============================================================================
// Module-Level Constants
//
// Cross-cutting DHCP constants shared between v4 and v6 modules.
// Values match C's config.h exactly for behavioral compatibility.
// ============================================================================

/// Default DHCP lease time (1 hour = 3600 seconds).
///
/// From config.h `DEFLEASE` constant (line 551). Applied as the default
/// lease duration when no explicit `--dhcp-lease-max` is configured.
/// Used by both the DHCPv4 server (v4/protocol.rs) and the lease
/// management module (lease.rs) for expiry calculation.
pub const DEFAULT_LEASE_TIME: u32 = 3600;

/// Default DHCPv6 lease time (24 hours = 86400 seconds).
///
/// From config.h `DEFLEASE6` constant (line 566, defined as `3600*24`).
/// DHCPv6 uses a longer default lease time than DHCPv4 because IPv6
/// address space is larger and lease renewals are more expensive over
/// multicast. Used by the DHCPv6 server (v6/protocol.rs) and lease
/// management module (lease.rs).
#[cfg(feature = "dhcp6")]
pub const DEFAULT_LEASE_TIME_V6: u32 = 86400;

/// Maximum number of DHCP leases (default).
///
/// From config.h `MAXLEASES` constant (line 407). Limits the total
/// number of active DHCP leases (combined v4 and v6) to prevent
/// unbounded memory growth. Configurable via `--dhcp-lease-max`.
pub const MAX_LEASES: usize = 1000;

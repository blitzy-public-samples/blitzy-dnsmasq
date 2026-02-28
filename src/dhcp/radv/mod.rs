//! IPv6 Router Advertisement subsystem per RFC 4861.
//!
//! This module implements the IPv6 Router Advertisement (RA) subsystem, providing
//! Stateless Address Autoconfiguration (SLAAC) support and coordinated DHCPv6
//! operation for IPv6 network autoconfiguration. It is derived from the C source
//! files:
//!
//! - `src/radv.c` — RA construction, transmission, and timer management
//! - `src/slaac.c` — SLAAC address probing via ICMPv6 echo
//! - `src/radv-protocol.h` — ICMPv6/ND wire-format constants and structures
//!
//! # Submodules
//!
//! - [`protocol`] — Wire-format constants, packet structures, and IPv6 address
//!   helper functions for ICMPv6 Router Advertisement and Neighbor Discovery
//!   protocols. Includes ICMPv6 type codes (Echo, RS, RA, NS, NA), ND option
//!   types (Prefix, RDNSS, DNSSL, MTU, PREF64), RA/prefix flags (M, O, H,
//!   on-link, autonomous, router-address), hardware type constants (Ethernet,
//!   Token Ring, FireWire, EUI-64), multicast addresses (all-nodes, all-routers),
//!   and packet structures ([`RaPacket`], [`PrefixOpt`], [`PingPacket`],
//!   [`NeighPacket`]).
//!
//! - [`server`] — Core RA server: raw ICMPv6 socket initialization
//!   ([`ra_init`]), incoming Router Solicitation and echo reply processing
//!   ([`icmp6_packet`]), periodic unsolicited RA transmission ([`periodic_ra`]),
//!   and timer setup for new DHCPv6 contexts ([`ra_start_unsolicited`]).
//!
//! - [`slaac`] — SLAAC address probing: EUI-64 address derivation from DHCP
//!   lease MAC addresses ([`slaac::derive_eui64_address`]), ICMPv6 echo-based
//!   duplicate address detection ([`periodic_slaac`]), address tracking and
//!   management ([`slaac_add_addrs`]), and DNS hostname registration upon
//!   probe reply confirmation ([`slaac_ping_reply`]).
//!
//! # Feature Gate
//!
//! This module is compiled only when the `dhcp6` Cargo feature is enabled.
//! The parent module (`src/dhcp/mod.rs`) applies the feature gate:
//!
//! ```rust,ignore
//! #[cfg(feature = "dhcp6")]
//! pub mod radv;
//! ```
//!
//! No additional feature gate is needed inside this file.
//!
//! # Operational Modes
//!
//! The RA subsystem coordinates with the DHCPv6 server to support several
//! IPv6 addressing models:
//!
//! - **SLAAC-only (`ra-stateless`):** M=0, O=0 — addresses via SLAAC, RDNSS
//!   provides DNS servers.
//! - **SLAAC + stateless DHCPv6 (`ra-only`):** M=0, O=1 — addresses via SLAAC,
//!   DHCPv6 provides other configuration (DNS, NTP, etc.).
//! - **SLAAC with DNS (`ra-names`):** SLAAC addressing with ping confirmation
//!   and automatic DNS hostname registration for confirmed addresses.
//! - **Stateful DHCPv6:** M=1 — clients use DHCPv6 for address assignment;
//!   RA still provides on-link prefix and router information.
//!
//! # RFC Compliance
//!
//! - RFC 4861 — Neighbor Discovery for IPv6 (Router Advertisement format and
//!   processing, Neighbor Solicitation/Advertisement)
//! - RFC 4862 — IPv6 Stateless Address Autoconfiguration
//! - RFC 6106 — IPv6 Router Advertisement Options for DNS Configuration
//!   (RDNSS, DNSSL)
//! - RFC 4191 — Default Router Preferences and More-Specific Routes
//! - RFC 4443 — ICMPv6 for IPv6 (Echo Request/Reply for SLAAC probing)
//! - RFC 4291 Appendix A — EUI-64 interface identifier derivation
//! - RFC 8781 — Discovering PREF64 in Router Advertisements

// ---------------------------------------------------------------------------
// Submodule declarations
// ---------------------------------------------------------------------------

/// ICMPv6 Router Advertisement and Neighbor Discovery protocol constants
/// and packet structures.
///
/// Provides all wire-format definitions needed by the RA server and SLAAC
/// probing subsystems, including:
///
/// - **ICMPv6 type codes:** Echo Request/Reply, Router Solicitation/Advertisement,
///   Neighbor Solicitation/Advertisement
/// - **ND option types:** Source MAC, Prefix Information, MTU, Advertisement
///   Interval, Route Info, RDNSS, DNSSL, PREF64
/// - **RA flags:** Managed (M), Other (O), Home Agent (H), Default Router
///   Preference (Prf)
/// - **Prefix flags:** On-link (L), Autonomous (A), Router Address (R)
/// - **Hardware type constants:** Ethernet, IEEE 802, IEEE 1394, EUI-64
/// - **Multicast addresses:** All-nodes (`FF02::1`), All-routers (`FF02::2`)
/// - **Packet structures:** [`RaPacket`], [`PrefixOpt`], [`PingPacket`],
///   [`NeighPacket`]
/// - **IPv6 helpers:** [`is_link_local`], [`is_ula`], [`is_unspecified_v6`]
pub mod protocol;

/// Router Advertisement construction, transmission, and timer management.
///
/// Core RA server functionality providing:
///
/// - [`ra_init`] — Creates the raw ICMPv6 socket with hop-limit 255 and
///   traffic class CS6, configures ICMPv6 type filtering.
/// - [`icmp6_packet`] — Processes incoming Router Solicitations (type 133)
///   and ICMPv6 Echo Replies (type 129, for SLAAC confirmation).
/// - [`periodic_ra`] — Sends periodic unsolicited Router Advertisements
///   with RFC 4861 timing (short period + normal period randomization).
/// - [`ra_start_unsolicited`] — Initializes RA timers for newly activated
///   DHCPv6 contexts to begin sending unsolicited RAs immediately.
pub mod server;

/// SLAAC (Stateless Address Autoconfiguration) address probing and confirmation.
///
/// Implements IPv6 duplicate address detection by sending ICMPv6 echo requests
/// to EUI-64-derived addresses and monitoring for replies:
///
/// - [`slaac_add_addrs`] — Derives EUI-64 IPv6 addresses from DHCP lease MAC
///   addresses and adds them to the probe tracking list.
/// - [`periodic_slaac`] — Sends ICMPv6 echo requests to unconfirmed addresses
///   using exponential backoff with jitter.
/// - [`slaac_ping_reply`] — Processes incoming echo replies, marks matching
///   addresses as confirmed, and triggers DNS registration.
/// - [`derive_eui64_address`](slaac::derive_eui64_address) — Pure helper that
///   constructs an IPv6 address from a prefix and MAC address using EUI-64
///   conversion per RFC 4291 Appendix A.
pub mod slaac;

// ---------------------------------------------------------------------------
// Public re-exports — protocol constants, types, and helper functions
// ---------------------------------------------------------------------------

// Re-export all protocol constants, packet structures, and helper functions
// for convenient access via `crate::dhcp::radv::*`. This includes:
//
// Constants:
//   ALL_NODES, ALL_ROUTERS,
//   ICMP6_ECHO_REQUEST, ICMP6_ECHO_REPLY,
//   ICMP6_ROUTER_SOLICIT, ICMP6_ROUTER_ADVERT,
//   ICMP6_NEIGHBOUR_SOLICIT, ICMP6_NEIGHBOUR_ADVERT,
//   ICMP6_OPT_SOURCE_MAC, ICMP6_OPT_PREFIX, ICMP6_OPT_MTU,
//   ICMP6_OPT_ADV_INTERVAL, ICMP6_OPT_RT_INFO, ICMP6_OPT_RDNSS,
//   ICMP6_OPT_DNSSL, ICMP6_OPT_PREF64,
//   ND_RA_FLAG_MANAGED, ND_RA_FLAG_OTHER, ND_RA_FLAG_HA, ND_RA_FLAG_PREF,
//   PREFIX_FLAG_ONLINK, PREFIX_FLAG_AUTO, PREFIX_FLAG_ROUTER,
//   ARPHRD_ETHER, ARPHRD_IEEE802, ARPHRD_IEEE1394, ARPHRD_EUI64
//
// Packet structures:
//   RaPacket, PrefixOpt, PingPacket, NeighPacket
//
// Helper functions:
//   is_link_local(), is_ula(), is_unspecified_v6()
pub use protocol::*;

// ---------------------------------------------------------------------------
// Public re-exports — server functions
// ---------------------------------------------------------------------------

// Re-export the four primary RA server entry points for convenient access
// via `crate::dhcp::radv::ra_init`, etc., without requiring callers to
// navigate through the `server` submodule.
pub use server::{icmp6_packet, periodic_ra, ra_init, ra_start_unsolicited};

// ---------------------------------------------------------------------------
// Public re-exports — SLAAC functions
// ---------------------------------------------------------------------------

// Re-export the three primary SLAAC entry points for convenient access
// via `crate::dhcp::radv::slaac_add_addrs`, etc. The `derive_eui64_address`
// helper remains accessible via `crate::dhcp::radv::slaac::derive_eui64_address`
// through the public `slaac` submodule declaration above.
pub use slaac::{periodic_slaac, slaac_add_addrs, slaac_ping_reply};

//! Shared type definitions for the dnsmasq Rust implementation.
//!
//! This module contains all core data structures used across the dnsmasq codebase,
//! organized by functional domain. These types replace the struct, union, and typedef
//! declarations from the C `dnsmasq.h` header file (approximately 1,800 lines of type
//! definitions covering DNS, DHCP, network, and address types).
//!
//! # Organization
//!
//! The types module decomposes the monolithic `dnsmasq.h` header into five
//! domain-specific submodules:
//!
//! - [`addr`] — Core address types replacing C unions:
//!   - [`AllAddr`] — Unified address enum replacing `union all_addr`
//!   - [`SocketAddress`] — Socket address enum replacing `union mysockaddr`
//!   - [`CnameTarget`] — CNAME target discriminated union
//!   - [`RR_IMDATALEN`] — Inline RR data size constant
//!
//! - [`dns`] — DNS-specific record types:
//!   - [`DnsHeader`] — 12-byte DNS message header (RFC 1035 Section 4.1.1)
//!   - [`DnsName`] — Wire-format DNS name newtype
//!   - [`CacheEntry`] — DNS cache record replacing `struct crec`
//!   - [`ForwardRecord`] — Upstream query tracking replacing `struct frec`
//!   - [`ServerEntry`] — Upstream DNS server config replacing `struct server`
//!   - Plus flags, events, DNSSEC types, zone types, and record types
//!
//! - [`dhcp`] — DHCP types (feature-gated by `dhcp` or `dhcp6`):
//!   - [`DhcpLease`] — Lease database entry replacing `struct dhcp_lease`
//!   - [`DhcpConfig`] — Static host config replacing `struct dhcp_config`
//!   - [`DhcpContext`] — Address pool config replacing `struct dhcp_context`
//!   - [`DhcpOption`] — DHCP option encoding replacing `struct dhcp_opt`
//!   - Plus lease flags, context flags, config flags, relay, TFTP, and RA types
//!
//! - [`network`] — Network interface and socket types:
//!   - [`InterfaceRecord`] — Interface info replacing `struct irec`
//!   - [`Listener`] — Socket listener replacing `struct listener`
//!   - [`InterfaceName`] — Domain-to-interface mapping replacing `struct interface_name`
//!   - Plus server fd, random fd, and address list types
//!
//! - [`ipv6`] — IPv6 address classification helpers:
//!   - [`Ipv6AddrExt`] — Extension trait on `std::net::Ipv6Addr`
//!   - Multicast scope constants and well-known addresses
//!
//! # Key Design Decisions
//!
//! - **C `union all_addr` → Rust `enum AllAddr`** with exhaustive pattern matching,
//!   eliminating undefined behavior from reading the wrong union member.
//! - **C `union mysockaddr` → Rust `enum SocketAddress`** leveraging `std::net` types
//!   for type-safe IPv4/IPv6 socket address handling.
//! - **Intrusive linked lists removed** — C structs like `struct crec`, `struct frec`,
//!   `struct dhcp_lease` had `next`, `prev`, `hash_next` pointer fields. In Rust,
//!   these are eliminated; collections (`HashMap`, `Vec`, `VecDeque`) manage
//!   relationships externally.
//! - **C `typedef unsigned char u8` etc. → Rust native primitive types** — No custom
//!   type aliases needed since Rust has built-in `u8`, `u16`, `u32`, `u64`.
//! - **All types derive standard traits** (`Debug`, `Clone`) where appropriate. Types
//!   used as `HashMap` keys also derive `Hash`, `Eq`, `PartialEq`.
//! - **Feature-gated DHCP module** — The `dhcp` submodule is only compiled when the
//!   `dhcp` or `dhcp6` Cargo feature is enabled, mirroring the C `#ifdef HAVE_DHCP`
//!   compile-time guards.
//! - **No `unsafe` code** — This is a pure type definitions module with no raw
//!   pointers, no FFI, and no `unsafe` blocks.
//!
//! # Source References
//!
//! - `src/dnsmasq.h` — Primary source for all struct/union/typedef declarations
//! - `src/ip6addr.h` — IPv6 address utility macros replaced by [`Ipv6AddrExt`] trait

// ===========================================================================
// Submodule Declarations
// ===========================================================================

/// Core address type definitions replacing C `union all_addr` and `union mysockaddr`.
///
/// Contains [`AllAddr`] (unified address enum), [`SocketAddress`] (socket address enum),
/// [`CnameTarget`] (CNAME discriminated union), and the [`RR_IMDATALEN`] constant.
pub mod addr;

/// DNS-specific type definitions replacing DNS-related structs from `dnsmasq.h`.
///
/// Contains [`DnsHeader`], [`DnsName`], [`CacheEntry`], [`ForwardRecord`],
/// [`ServerEntry`], and all associated flag types, event definitions, zone types,
/// DNSSEC types, and record structures used by the DNS forwarding and caching engine.
pub mod dns;

/// DHCP-specific type definitions for DHCPv4, DHCPv6, Router Advertisement,
/// TFTP, and lease management.
///
/// This module is feature-gated: it is compiled when the `dhcp`, `dhcp6`, or
/// `tftp` Cargo feature is enabled. The `tftp` feature requires access to
/// TFTP-specific types ([`TftpPrefix`], `ACTION_TFTP`) that reside in this
/// module because TFTP prefix configuration and helper actions are defined
/// alongside DHCP types in the C source (`dnsmasq.h`).
///
/// Contains [`DhcpLease`], [`DhcpConfig`], [`DhcpContext`], [`DhcpOption`],
/// and all associated flag types, relay types, TFTP transfer types, and
/// Router Advertisement interface types.
#[cfg(any(feature = "dhcp", feature = "dhcp6", feature = "tftp"))]
pub mod dhcp;

/// Network-related type definitions for interface enumeration, socket management,
/// and listener configuration.
///
/// Contains [`InterfaceRecord`], [`Listener`], [`InterfaceName`],
/// [`InterfaceNameBinding`], and associated flag types and file descriptor types.
pub mod network;

/// IPv6 address classification and manipulation helpers.
///
/// Provides the [`Ipv6AddrExt`] extension trait on `std::net::Ipv6Addr` with
/// dnsmasq-specific predicates (ULA detection, link-local zero, prefix matching,
/// SLAAC EUI-64 derivation) replacing C macros from `ip6addr.h`.
///
/// Also contains multicast scope constants and well-known DHCPv6/RA multicast
/// address definitions.
pub mod ipv6;

// ===========================================================================
// Re-exports — Address Types
// ===========================================================================

// Address types used by virtually every module in the crate.
// From addr.rs: AllAddr enum (replacing union all_addr), SocketAddress enum
// (replacing union mysockaddr), CnameTarget enum, and RR_IMDATALEN constant.
pub use addr::{AllAddr, CnameTarget, SocketAddress, RR_IMDATALEN};

// ===========================================================================
// Re-exports — DNS Types
// ===========================================================================

// Core DNS types used by dns::*, dhcp::*, core::*, and net::* modules.
// From dns.rs: DnsHeader (12-byte wire-format header), DnsName (wire-format
// newtype), CacheEntry (cache record), CacheEntryFlags (cache entry bitflags),
// ForwardRecord (upstream query tracking), ForwardRecordFlags (forward record
// bitflags), ServerEntry (upstream DNS server config), and ServerFlags.
pub use dns::{
    CacheEntry, CacheEntryFlags, DnsHeader, DnsName, ForwardRecord,
    ForwardRecordFlags, ServerEntry, ServerFlags,
};

// Additional DNS types re-exported for convenience across the crate.
// These include DNSSEC status types, address list types, DNS record types,
// zone types, event types, and dump flags.
pub use dns::{
    AddrList, AuthZone, BogusAddr, CnameRecord, DnsDoctor, DsConfig,
    Event, EventDesc, HostRecord, MxSrvRecord, PtrRecord, TxtRecord,
};

// DNSSEC-specific types, gated by the dnssec feature.
#[cfg(feature = "dnssec")]
pub use dns::{DnssecFailFlags, DnssecStatus};

// Dump flags for packet capture diagnostics, gated by the dump feature.
#[cfg(feature = "dump")]
pub use dns::DumpFlags;

// ===========================================================================
// Re-exports — Network Types
// ===========================================================================

// Network types used by net::*, core::*, dns::*, and dhcp::* modules.
// From network.rs: InterfaceRecord (interface info), Listener (socket listener),
// InterfaceName (domain-to-interface mapping), InterfaceNameBinding (CLI
// interface spec), IfaceFlags (IPv6 address state), InameFlags (interface
// binding state), ServerFd (server socket), RandFd (random source port fd),
// RandFdRef (borrowed random fd), SimpleAddrList (simple address list),
// and ReadWriteDirection (I/O direction enum).
pub use network::{
    IfaceFlags, InameFlags, InterfaceName, InterfaceNameBinding,
    InterfaceRecord, Listener, RandFd, RandFdRef, ReadWriteDirection,
    ServerFd, SimpleAddrList,
};

// ===========================================================================
// Re-exports — DHCP Types (feature-gated)
// ===========================================================================

// DHCP types conditionally available when dhcp or dhcp6 features are enabled.
// From dhcp.rs: DhcpLease (lease database entry), DhcpConfig (static host
// config), DhcpContext (address pool), DhcpOption (option encoding), and
// all associated flag types, relay types, and TFTP/RA types.
#[cfg(any(feature = "dhcp", feature = "dhcp6"))]
pub use dhcp::{
    CondDomain, DhcpBoot, DhcpConfig, DhcpConfigFlags, DhcpContext,
    DhcpContextFlags, DhcpLease, DhcpNetId, DhcpOption, DhcpRelay,
    LeaseFlags, PxeService, RaInterface,
};

// TFTP types from the dhcp module. Available when tftp feature is enabled,
// since the dhcp module is now also compiled for tftp-only builds to provide
// TFTP-specific types (TftpPrefix, TftpFile, TftpTransfer, ACTION_TFTP).
#[cfg(feature = "tftp")]
pub use dhcp::{TftpFile, TftpTransfer};

// ===========================================================================
// Re-exports — IPv6 Helpers
// ===========================================================================

// IPv6 extension trait used by dhcp6, radv, slaac, and network modules.
// From ipv6.rs: Ipv6AddrExt trait providing is_ula(), is_ula_zero(),
// is_link_local_zero(), matches_prefix(), from_prefix_and_mac(), and
// is_multicast_scope() methods on std::net::Ipv6Addr.
pub use ipv6::Ipv6AddrExt;

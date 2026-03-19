// Copyright (c) 2000-2025 Simon Kelley
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

//! # DNS Subsystem
//!
//! Complete DNS subsystem implementation for dnsmasq, providing DNS forwarding,
//! caching, wire format parsing, DNSSEC validation, and authoritative serving.
//!
//! This module is the root of the DNS subsystem and is **always present** (not
//! feature-gated) since DNS forwarding is core dnsmasq functionality.  It
//! declares all sub-modules and provides public re-exports of key DNS types and
//! protocol constants for convenient access by the rest of the crate.
//!
//! ## Module Organization
//!
//! - [`protocol`] — DNS wire format constants, packet parsing/construction
//!   (from `rfc1035.c` + `dns-protocol.h`)
//! - [`forward`] — Async query forwarding engine (from `forward.c`)
//! - [`cache`] — DNS cache with TTL eviction (from `cache.c`)
//! - [`edns`] — EDNS0 extensions (from `edns0.c`)
//! - [`rrfilter`] — Resource record filtering (from `rrfilter.c`)
//! - [`domain_match`] — Domain matching for server selection (from `domain-match.c`)
//! - [`domain`] — Domain name utilities and synthesis (from `domain.c`)
//! - [`dnssec`] — DNSSEC validation (from `dnssec.c`, feature-gated)
//! - [`crypto`] — Cryptographic operations (from `crypto.c`, feature-gated)
//! - [`blockdata`] — DNSSEC record storage (from `blockdata.c`, feature-gated)
//! - [`auth`] — Authoritative DNS zones (from `auth.c`, feature-gated)
//! - [`loop_detect`] — Forwarding loop detection (from `loop.c`, feature-gated)
//!
//! ## Architecture
//!
//! - DNS cache: `HashMap<DnsName, Vec<CacheEntry>>` with TTL-ordered eviction
//! - Query forwarding: async tokio UDP/TCP with configurable timeouts
//! - Wire format: `bytes::BytesMut` for zero-copy packet parsing
//! - DNSSEC: chain validation with configurable trust anchors
//! - All C pointer arithmetic replaced with Rust slice indexing
//!
//! ## Re-Export Strategy
//!
//! This module re-exports key types from sub-modules at the `dns` level,
//! mirroring how the C `dns-protocol.h` header was universally included by
//! every `.c` file.  Downstream modules can use either the full path
//! (`crate::dns::protocol::DnsHeader`) or the shorthand (`crate::dns::DnsHeader`).

// ===========================================================================
// Always-present sub-module declarations
// ===========================================================================

/// DNS wire format constants, packet parsing and construction.
///
/// Combines C `src/rfc1035.c` (3,622 lines) and `src/dns-protocol.h` (873 lines)
/// into a unified Rust module providing:
/// - Protocol constants (port numbers, size limits, RR type codes)
/// - [`DnsHeader`] and [`DnsHeaderFlags`] for header parsing
/// - [`DnsName`] for domain name compression/decompression
/// - [`DnsPacket`] and [`DnsPacketBuilder`] for packet handling
/// - [`RRType`], [`DnsClass`], [`ResponseCode`] enums
/// - Byte-order helper functions ([`get_u16`], [`get_u32`], [`put_u16`], [`put_u32`])
/// - [`edns0`](protocol::edns0) and [`ede`](protocol::ede) constant sub-modules
/// - [`RRSet`] for DNSSEC RRset grouping
pub mod protocol;

/// Async DNS query forwarding engine.
///
/// Migrated from C `src/forward.c` (6,068 lines).  Manages the full lifecycle
/// of DNS queries: client reception → cache lookup → upstream forwarding →
/// response validation → cache population → client response.
///
/// Key types:
/// - [`ForwardRecord`] — Tracks an outstanding forwarded query
/// - [`ForwardTable`] — Manages the forwarding state table (max FTABSIZ entries)
/// - [`UpstreamServer`] — Upstream DNS server with failure tracking
/// - [`ServerSelector`] — Trait for pluggable server selection algorithms
///
/// Key functions:
/// - [`receive_query`](forward::receive_query) — Process incoming DNS queries
/// - [`forward_query`](forward::forward_query) — Forward a query to upstream servers
/// - [`reply_query`](forward::reply_query) — Process upstream DNS replies
/// - [`tcp_request`](forward::tcp_request) — Handle DNS-over-TCP connections
pub mod forward;

/// DNS cache with HashMap, TTL eviction, and LRU replacement.
///
/// Migrated from C `src/cache.c` (4,119 lines).  Provides high-performance
/// in-memory DNS caching with automatic TTL-based expiration.
///
/// Key types:
/// - [`DnsCache`] — The main cache structure (default capacity CACHESIZ=150)
/// - [`CacheEntry`] — Individual cache records (replaces C `struct crec`)
/// - [`CacheData`] — Enum for different record types (replaces C `union all_addr`)
/// - [`CacheFlags`] — Named boolean flags (replaces C `F_*` bitmask)
pub mod cache;

/// EDNS0 extension mechanism (OPT pseudo-RR, client subnet, DNS cookies).
///
/// Migrated from C `src/edns0.c` (1,340 lines).  Implements RFC 6891 EDNS0
/// for extending DNS beyond its original 512-byte UDP limit.
///
/// Key types:
/// - [`EdnsHandler`] — OPT pseudo-RR processing
/// - [`EdnsData`] — Parsed EDNS0 options collection
/// - [`EdnsFlags`] — EDNS0 state (DO bit, UDP payload size)
/// - [`EdnsOption`](edns::EdnsOption) — Individual EDNS0 option representation
///
/// Sub-modules:
/// - [`option_codes`](edns::option_codes) — EDNS0 option code constants
/// - [`ede_codes`](edns::ede_codes) — Extended DNS Error code constants
pub mod edns;

/// DNS resource record type filtering.
///
/// Migrated from C `src/rrfilter.c` (918 lines).  Provides a four-pass RR
/// filtering algorithm with compression pointer safety for removing EDNS0,
/// DNSSEC, address, and type-specific records from DNS response packets.
///
/// Key types and functions:
/// - [`rrfilter`](rrfilter::rrfilter) — Main filtering function
/// - [`RRFilterMode`] — Filter mode selection (Edns0, Dnssec, Address, ByType)
/// - [`check_name`](rrfilter::check_name) — Validate a DNS name in packet context
/// - [`check_rrs`](rrfilter::check_rrs) — Validate resource records in a packet
/// - [`to_wire`](rrfilter::to_wire) — Convert presentation name to wire format
/// - [`from_wire`](rrfilter::from_wire) — Convert wire format name to presentation
pub mod rrfilter;

/// Domain name matching algorithms and server selection.
///
/// Migrated from C `src/domain-match.c` (1,591 lines).  Implements
/// longest-match-wins semantics with O(log n) binary search for split-horizon
/// DNS and VPN routing configurations.
///
/// Key types:
/// - [`DomainMatcher`] — Sorted array of server configurations with binary search
/// - [`ServerConfig`](domain_match::ServerConfig) — Individual server routing rule
/// - [`ServerMatchFlags`](domain_match::ServerMatchFlags) — Server property flags
pub mod domain_match;

/// Domain name utilities, reverse DNS synthesis, and conditional domains.
///
/// Migrated from C `src/domain.c` (707 lines).  Provides synthetic name
/// generation from IP addresses and conditional domain selection for
/// split-horizon DNS configurations.
///
/// Key types and functions:
/// - [`ConditionalDomain`] — Split-horizon domain configuration
/// - [`is_name_synthetic`](domain::is_name_synthetic) — Check if a name was generated synthetically
/// - [`is_rev_synth`](domain::is_rev_synth) — Check/generate reverse DNS synthetic names
/// - [`get_domain`](domain::get_domain) — Get domain suffix for an IPv4 address
/// - [`get_domain6`](domain::get_domain6) — Get domain suffix for an IPv6 address
pub mod domain;

// ===========================================================================
// Feature-gated sub-module declarations
// ===========================================================================

/// DNSSEC validation engine — chain of trust, signature verification.
///
/// Migrated from C `src/dnssec.c` (4,009 lines).  Implements RFC 4033/4034/4035
/// DNSSEC validation with DoS protection resource limits.
///
/// Key types:
/// - [`DnssecStatus`] — Validation result (Secure/Insecure/Bogus)
/// - [`DnssecValidator`] — Chain-of-trust validation engine
/// - [`TrustAnchor`] — Root zone trust anchor configuration
/// - [`DnssecLimits`](dnssec::DnssecLimits) — Resource limits for DoS protection
///
/// Gated by `cfg(feature = "dnssec")`, mapping to C's `HAVE_DNSSEC`.
#[cfg(feature = "dnssec")]
pub mod dnssec;

/// Cryptographic operations for DNSSEC (Nettle crate integration).
///
/// Migrated from C `src/crypto.c` (1,295 lines).  Provides a thin abstraction
/// over the `nettle` crate for RSA, ECDSA, and EdDSA signature verification.
///
/// Key types:
/// - [`CryptoVerifier`] — Signature verification dispatcher
/// - [`DnssecAlgorithm`](crypto::DnssecAlgorithm) — IANA DNSSEC algorithm identifiers
/// - [`DigestAlgorithm`](crypto::DigestAlgorithm) — DS record digest algorithms
/// - [`HashFunction`](crypto::HashFunction) — Trait for hash function dispatch
///
/// Gated by `cfg(feature = "dnssec")`, mapping to C's `HAVE_DNSSEC`.
#[cfg(feature = "dnssec")]
pub mod crypto;

/// Block-allocated storage for DNSSEC records.
///
/// Migrated from C `src/blockdata.c` (810 lines).  Provides memory-efficient
/// storage for variable-length DNSSEC data (RRSIG signatures, DNSKEY public
/// keys, DS records) using `Vec<u8>` instead of C's fixed-size block chain.
///
/// Key types:
/// - [`BlockData`] — Variable-length DNSSEC data container
/// - [`BlockDataPool`](blockdata::BlockDataPool) — Pool statistics and management
///
/// Gated by `cfg(feature = "dnssec")`, mapping to C's `HAVE_DNSSEC`.
#[cfg(feature = "dnssec")]
pub mod blockdata;

/// Authoritative DNS zone serving.
///
/// Migrated from C `src/auth.c` (1,284 lines).  Enables dnsmasq to respond
/// authoritatively (AA flag set) to queries for configured local zones.
///
/// Key types and functions:
/// - [`AuthZone`] — Zone configuration with domain/subnet/exclude filters
/// - [`AuthRecord`] — Authoritative DNS record variants (A, AAAA, CNAME, etc.)
/// - [`AuthNameEntry`](auth::AuthNameEntry) — Named records within a zone
/// - [`AuthSubnet`](auth::AuthSubnet) — Zone subnet membership filtering
/// - [`in_zone`](auth::in_zone) — Check if a hostname belongs to a zone
/// - [`answer_auth`](auth::answer_auth) — Process authoritative DNS queries
///
/// Gated by `cfg(feature = "auth")`, mapping to C's `HAVE_AUTH`.
#[cfg(feature = "auth")]
pub mod auth;

/// DNS forwarding loop detection via probe queries.
///
/// Migrated from C `src/loop.c` (539 lines).  Sends specially crafted DNS
/// queries with unique UIDs to upstream servers and detects if they loop back.
///
/// Key types:
/// - [`LoopDetector`] — Probe-based circular forwarding detection
///
/// Gated by `cfg(feature = "loop-detect")`, mapping to C's `HAVE_LOOP`.
#[cfg(feature = "loop-detect")]
pub mod loop_detect;

// ===========================================================================
// Public re-exports — key DNS types for convenient access by other modules
//
// This mirrors how C's dns-protocol.h was included universally. Downstream
// modules can use `crate::dns::DnsHeader` instead of the full path
// `crate::dns::protocol::DnsHeader`.
// ===========================================================================

// --- protocol module re-exports ---

pub use protocol::{
    // Byte order helpers
    get_u16,
    get_u32,
    put_u16,
    put_u32,
    // Types
    DnsClass,
    DnsHeader,
    DnsHeaderFlags,
    DnsName,
    DnsPacket,
    DnsPacketBuilder,
    DnsQuestion,
    DnsResourceRecord,
    RRType,
    ResponseCode,
    // Constants
    MAXDNAME,
    MAXLABEL,
    NAMESERVER_PORT,
    PACKETSZ,
    RRFIXEDSZ,
};

// --- cache module re-exports ---

pub use cache::{CacheData, CacheEntry, CacheFlags, DnsCache};

// --- forward module re-exports ---

pub use forward::{ForwardRecord, ForwardTable, ServerSelector, UpstreamServer};

// --- edns module re-exports ---

pub use edns::{EdnsData, EdnsFlags, EdnsHandler};

// --- domain_match module re-exports ---

pub use domain_match::DomainMatcher;

// --- domain module re-exports ---

pub use domain::ConditionalDomain;

// --- dnssec module re-exports (feature-gated) ---

#[cfg(feature = "dnssec")]
pub use dnssec::{DnssecStatus, DnssecValidator, TrustAnchor};

#[cfg(feature = "dnssec")]
pub use crypto::CryptoVerifier;

#[cfg(feature = "dnssec")]
pub use blockdata::BlockData;

// --- auth module re-exports (feature-gated) ---

#[cfg(feature = "auth")]
pub use auth::{AuthRecord, AuthZone};

// --- loop_detect module re-exports (feature-gated) ---

#[cfg(feature = "loop-detect")]
pub use loop_detect::LoopDetector;

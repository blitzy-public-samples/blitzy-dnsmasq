//! # DNS Stack
//!
//! Complete DNS forwarding, caching, wire-format codec, and validation stack for
//! the dnsmasq Rust rewrite. This module replaces the flat C source file organization
//! (`forward.c`, `cache.c`, `rfc1035.c`, `dnssec.c`, `edns0.c`, `rrfilter.c`,
//! `auth.c`, `domain.c`, `domain-match.c`, `loop.c`, `dns-protocol.h`) with a
//! structured Rust module hierarchy grouped by functional responsibility.
//!
//! ## Module Organization
//!
//! ### Always-Available Modules (no feature gate)
//!
//! - [`protocol`] — DNS wire-format constants (RR types, classes, opcodes, response codes,
//!   EDNS0 option codes, Extended DNS Error codes per RFC 8914, header flag accessors,
//!   and byte-order conversion helpers). Derived from `src/dns-protocol.h`.
//!
//! - [`wire`] — DNS packet parsing and construction (name compression with 0xC0 pointer
//!   following, RR serialization, `answer_request()` for local query resolution, and
//!   safe zero-copy buffer handling with Rust slices). Derived from `src/rfc1035.c`.
//!
//! - [`cache`] — DNS cache with `HashMap`-based lookup and `VecDeque` LRU eviction,
//!   replacing the C intrusive hash table + doubly-linked list. Handles hosts file
//!   parsing, DHCP hostname registration, and DNSSEC record caching.
//!   Derived from `src/cache.c` + `src/blockdata.c`.
//!
//! - [`forward`] — DNS query forwarding engine implementing the query lifecycle state
//!   machine: receive client queries, check cache, forward to upstream servers, process
//!   responses, and return answers. The largest and most complex DNS module.
//!   Derived from `src/forward.c`.
//!
//! - [`server_match`] — Domain pattern matching for split-horizon DNS with O(log n)
//!   binary search, longest-suffix-wins server selection, and dynamic server lifecycle
//!   management. Derived from `src/domain-match.c`.
//!
//! - [`edns`] — EDNS0 OPT pseudo-record handling per RFC 6891: EDNS Client Subnet
//!   (ECS) per RFC 7871, DNSSEC OK bit, Extended DNS Errors (EDE) per RFC 8914,
//!   MAC address options, and Cisco Umbrella identity. Derived from `src/edns0.c`.
//!
//! - [`rrfilter`] — Resource record filtering and compression pointer rewriting using
//!   a safe four-pass algorithm (mark, validate, fixup, compact). Also provides
//!   `to_wire()`/`from_wire()` name format conversion. Derived from `src/rrfilter.c`.
//!
//! - [`domain`] — Synthetic hostname generation and conditional domain selection based
//!   on client IP addresses, supporting both IPv4 and IPv6 with parallel implementations.
//!   Derived from `src/domain.c`.
//!
//! ### Feature-Gated Modules
//!
//! - [`auth`] — Authoritative DNS zone serving with AA flag, SOA generation, and AXFR
//!   zone transfers. Gated by `#[cfg(feature = "auth")]`. Derived from `src/auth.c`.
//!
//! - [`loop_detect`] — DNS forwarding loop detection via periodic probe TXT queries
//!   with unique hex UIDs. Gated by `#[cfg(feature = "loop_detect")]`.
//!   Derived from `src/loop.c`.
//!
//! - [`dnssec`] — DNSSEC validation subfolder containing trust chain validation
//!   (`validation.rs`) and cryptographic verification (`crypto.rs`) using the `ring`
//!   crate. Gated by `#[cfg(feature = "dnssec")]`. Derived from `src/dnssec.c` +
//!   `src/crypto.c`.
//!
//! ## Architecture Notes
//!
//! The DNS module is always available — it is declared in `src/lib.rs` without any
//! feature gate, as DNS forwarding and caching is the core functionality of dnsmasq.
//! Individual submodules use Cargo feature gates where they correspond to optional
//! C `HAVE_*` compile-time flags from `config.h`.
//!
//! All inter-module communication uses typed Rust imports rather than the C pattern
//! of a single monolithic `dnsmasq.h` header. Shared types are defined in
//! `crate::types::*` and referenced via `use crate::types::{...}` imports in each
//! submodule.

// ============================================================================
// Always-available modules (DNS core — no feature gate)
// ============================================================================

/// DNS wire-format constants: RR types, classes, opcodes, response codes,
/// EDNS0 option codes, EDE codes, header flag accessors, and byte-order helpers.
/// Replaces `src/dns-protocol.h`.
pub mod protocol;

/// DNS wire-format codec: name compression parsing, packet construction,
/// `answer_request()` for local query resolution, and safe buffer handling.
/// Replaces `src/rfc1035.c`.
pub mod wire;

/// DNS cache: `HashMap`-based lookup with `VecDeque` LRU eviction, hosts file
/// parsing, DHCP hostname registration, and DNSSEC record caching.
/// Replaces `src/cache.c` + `src/blockdata.c`.
pub mod cache;

/// DNS forwarding engine: query lifecycle state machine with upstream server
/// dispatch, response validation, caching, and client delivery.
/// Replaces `src/forward.c`.
pub mod forward;

/// Domain pattern matching: sorted server array with O(log n) binary search,
/// longest-suffix-wins semantics, and server lifecycle management.
/// Replaces `src/domain-match.c`.
pub mod server_match;

/// EDNS0 OPT record handling: ECS (RFC 7871), DNSSEC OK bit, Extended DNS
/// Errors (RFC 8914), MAC options, and Cisco Umbrella identity.
/// Replaces `src/edns0.c`.
pub mod edns;

/// Resource record filtering: four-pass algorithm for safe RR removal with
/// compression pointer rewriting, plus `to_wire()`/`from_wire()` conversion.
/// Replaces `src/rrfilter.c`.
pub mod rrfilter;

/// Synthetic hostname generation and conditional domain selection for both
/// IPv4 and IPv6 address ranges.
/// Replaces `src/domain.c`.
pub mod domain;

// ============================================================================
// Feature-gated modules (optional DNS subsystems)
// ============================================================================

/// Authoritative DNS zone serving: AA flag, SOA generation, AXFR zone transfers,
/// and peer ACL enforcement.
/// Replaces `src/auth.c`.
///
/// Enabled by Cargo feature `auth` (corresponds to C `HAVE_AUTH`).
#[cfg(feature = "auth")]
pub mod auth;

/// DNS forwarding loop detection: periodic probe TXT queries with unique hex UIDs
/// to detect and mark looping upstream servers.
/// Replaces `src/loop.c`.
///
/// Enabled by Cargo feature `loop_detect` (corresponds to C `HAVE_LOOP`).
#[cfg(feature = "loop_detect")]
pub mod loop_detect;

/// DNSSEC validation and cryptographic verification subfolder containing
/// trust chain validation and `ring`-based crypto (RSA, ECDSA, Ed25519).
/// Replaces `src/dnssec.c` + `src/crypto.c`.
///
/// Enabled by Cargo feature `dnssec` (corresponds to C `HAVE_DNSSEC`).
#[cfg(feature = "dnssec")]
pub mod dnssec;

// ============================================================================
// Convenient re-exports for common usage across the crate
// ============================================================================

// Re-export commonly used DNS protocol enums for ergonomic imports.
// Consumers can use `crate::dns::RrType` instead of `crate::dns::protocol::RrType`.
pub use protocol::{DnsClass, EdeCode, Rcode, RrType};

// Re-export the DNS wire-format error type.
pub use wire::WireError;

// Re-export the DNS cache struct for crate-wide access.
pub use cache::DnsCache;

// Re-export the forwarding engine for event loop integration.
pub use forward::ForwardingEngine;

// Re-export the server array for domain-based server selection.
pub use server_match::ServerArray;

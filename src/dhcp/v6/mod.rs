// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2000-2025 Simon Kelley — Rust rewrite

//! DHCPv6 server implementation (RFC 3315).
//!
//! This module provides the complete DHCPv6 server stack including:
//! - Core server initialization and packet dispatch ([`server`])
//! - Full RFC 3315 protocol message processing ([`rfc3315`])
//! - DHCPv6 option serialization buffer builder ([`outpacket`])
//!
//! # Feature Gate
//!
//! This module is compiled only when the `dhcp6` feature is enabled,
//! controlled by the parent `dhcp` module's conditional compilation
//! (`#[cfg(feature = "dhcp6")] pub mod v6;` in `src/dhcp/mod.rs`).
//! Therefore, no additional feature gate is applied here — all items
//! in this module tree are implicitly gated by the parent.
//!
//! # Architecture
//!
//! The DHCPv6 stack follows the same architecture as the C implementation:
//!
//! - **[`server`]** handles socket initialization, packet dispatch, DUID
//!   management, and IPv6 address allocation (from `dhcp6.c`). The
//!   [`dhcp6_init`] function creates the UDP server socket bound to port 547
//!   with all required IPv6 socket options. [`dhcp6_packet`] is the main
//!   event-loop entry point that receives incoming DHCPv6 messages via
//!   `recvmsg`, extracts interface/destination information, and dispatches
//!   to the protocol engine. Address allocation uses the same SDBM-hash
//!   algorithm as the C version for byte-for-byte equivalence.
//!
//! - **[`rfc3315`]** implements the full DHCPv6 message processing state
//!   machine for SOLICIT/ADVERTISE/REQUEST/REPLY/RENEW/REBIND/RELEASE/
//!   DECLINE/INFORMATION-REQUEST with IA_NA/IA_TA/IA_PD management
//!   (from `rfc3315.c`). The [`dhcp6_reply`] function is the main protocol
//!   entry point called from [`dhcp6_packet`]. Processing state is tracked
//!   in [`Dhcpv6State`], relay chains in [`RelayMessage`], and errors
//!   reported via [`Dhcpv6Error`].
//!
//! - **[`outpacket`]** provides the growable buffer for constructing nested
//!   DHCPv6 option structures (from `outpacket.c`). The [`Dhcpv6OutPacket`]
//!   struct replaces the C global `daemon->outpacket` with an encapsulated
//!   buffer that supports nested option construction with automatic length
//!   backpatching.
//!
//! # Wire Protocol Fidelity
//!
//! All DHCPv6 responses maintain byte-for-byte compatibility with the C
//! implementation for the same input and configuration. Option ordering,
//! T1/T2 calculation, DUID generation, and address allocation arithmetic
//! exactly match the original. The SDBM hash for address allocation produces
//! identical output: `j = clid[i] + (j << 6) + (j << 16) - j`.
//!
//! # RFC Compliance
//!
//! - RFC 3315: Dynamic Host Configuration Protocol for IPv6 (DHCPv6)
//! - RFC 3633: IPv6 Prefix Options for DHCPv6 (IA_PD)
//! - RFC 3646: DNS Configuration options for DHCPv6
//! - RFC 4704: The DHCPv6 Client FQDN Option
//! - RFC 4861: Neighbor Discovery Protocol (MAC discovery for leases)
//! - RFC 6939: Client Link-Layer Address Option in DHCPv6
//!
//! # Module Hierarchy
//!
//! ```text
//! dhcp::v6 (this module)
//! ├── server     — Socket init, packet dispatch, address allocation, DUID
//! ├── rfc3315    — Protocol engine, message state machine, IA management
//! └── outpacket  — Option serialization buffer builder
//! ```

// ---------------------------------------------------------------------------
// Submodule declarations
// ---------------------------------------------------------------------------

/// DHCPv6 core server: socket initialization, packet dispatch, DUID management,
/// and IPv6 address allocation.
///
/// Corresponds to the C `dhcp6.c` source file. Provides [`dhcp6_init`] for
/// daemon startup and [`dhcp6_packet`] as the main event-loop entry point.
pub mod server;

/// DHCPv6 protocol engine implementing RFC 3315 message processing.
///
/// Corresponds to the C `rfc3315.c` source file. Implements the full DHCPv6
/// message exchange state machine including SOLICIT, REQUEST, RENEW, REBIND,
/// RELEASE, DECLINE, and INFORMATION-REQUEST processing with Identity
/// Association (IA_NA/IA_TA/IA_PD) management and relay chain traversal.
pub mod rfc3315;

/// DHCPv6 option serialization buffer builder.
///
/// Corresponds to the C `outpacket.c` source file. Provides the
/// [`Dhcpv6OutPacket`] growable buffer for constructing nested DHCPv6 option
/// structures with automatic length backpatching and network byte order
/// encoding.
pub mod outpacket;

// ---------------------------------------------------------------------------
// Re-exports — primary public API surface
// ---------------------------------------------------------------------------
// These re-exports provide convenient access to the most commonly used items
// from submodules. External consumers can use either the fully-qualified path
// (e.g., `crate::dhcp::v6::server::dhcp6_init`) or the short form
// (e.g., `crate::dhcp::v6::dhcp6_init`).

// -- server.rs re-exports --

/// Initialize the DHCPv6 server socket (UDP port 547) with required IPv6
/// socket options. Called once during daemon startup.
pub use server::dhcp6_init;

/// Main event-loop entry point: receive and dispatch an incoming DHCPv6
/// packet. Called whenever `mio` signals readability on the DHCPv6 socket.
pub use server::dhcp6_packet;

/// Error type for DHCPv6 server operations (socket creation, I/O, allocation).
pub use server::Dhcp6ServerError;

// -- rfc3315.rs re-exports --

/// Process and reply to a DHCPv6 message per the RFC 3315 state machine.
/// Called from [`dhcp6_packet`] after packet reception and interface matching.
pub use rfc3315::dhcp6_reply;

/// Aggregated request-processing state for a single DHCPv6 transaction.
pub use rfc3315::Dhcpv6State;

/// Error type for DHCPv6 protocol processing (malformed packets, missing
/// options, relay depth exceeded).
pub use rfc3315::Dhcpv6Error;

/// Decoded relay-forward message envelope from a DHCPv6 relay agent chain.
pub use rfc3315::RelayMessage;

// -- outpacket.rs re-exports --

/// Growable buffer for constructing DHCPv6 response packets with nested
/// option support and automatic length backpatching.
pub use outpacket::Dhcpv6OutPacket;

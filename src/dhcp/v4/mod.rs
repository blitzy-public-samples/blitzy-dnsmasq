//! DHCPv4 server implementation.
//!
//! This module provides a complete DHCPv4 server implementing RFC 2131,
//! including the DORA state machine (DISCOVER → OFFER → REQUEST → ACK),
//! SDBM hash-based address allocation, ICMP conflict detection, PXE/UEFI
//! boot support, relay agent processing (RFC 3046), and full option
//! encoding/decoding.
//!
//! # Module Structure
//!
//! - [`server`] — Core server logic: initialization, packet reception/dispatch,
//!   address allocation, interface management, ethers file parsing
//!   (rewrite of `src/dhcp.c`)
//! - [`rfc2131`] — Protocol engine: DORA state machine, option assembly,
//!   PXE boot support, relay agent forwarding, lease time negotiation
//!   (rewrite of `src/rfc2131.c`)
//!
//! # Feature Gate
//!
//! This entire module is conditionally compiled with the `dhcp` feature flag:
//! ```toml
//! [features]
//! dhcp = []
//! ```
//!
//! # Architecture
//!
//! The DHCPv4 server follows the event-driven architecture of dnsmasq:
//! 1. The main event loop detects activity on the DHCP socket
//! 2. [`DhcpV4Server::handle_packet()`] receives and validates the raw packet
//! 3. Interface context matching builds the context chain for the receiving interface
//! 4. [`dhcp_reply()`] processes the DHCP message and builds the response
//! 5. Response options are assembled via the protocol engine
//! 6. The response is sent back via raw socket or BPF
//!
//! # Dependencies
//!
//! - `crate::dhcp::common` — Shared DHCP utilities (tag matching, option filtering)
//! - `crate::dhcp::protocol_v4` — DHCPv4 protocol constants and option codes
//! - `crate::dhcp::lease` — Lease persistence and DNS registration
//! - `crate::types::dhcp` — Shared type definitions (DhcpLease, DhcpContext, etc.)
//! - `crate::types::addr` — Address types (AllAddr, SocketAddress)
//! - `crate::core::daemon` — DaemonState for global configuration access
//! - `crate::net::interface` — Interface enumeration and management
//! - `crate::dns::cache` — DNS cache for DHCP hostname registration
//!
//! # Examples
//!
//! ```rust,no_run
//! use dnsmasq::dhcp::v4::DhcpV4Server;
//! use dnsmasq::core::daemon::DaemonState;
//!
//! // Initialize the DHCPv4 server from daemon configuration
//! let daemon = DaemonState::new();
//! let server = DhcpV4Server::init(&daemon)
//!     .expect("Failed to initialize DHCPv4 server");
//! ```

/// DHCPv4 core server logic: initialization, packet reception, address allocation,
/// ICMP conflict detection, interface matching, ethers file parsing, and DNS
/// hostname lookup integration.
///
/// This submodule is the Rust rewrite of `src/dhcp.c` and provides the
/// [`DhcpV4Server`] struct as the primary server abstraction, along with
/// standalone utility functions for address management:
///
/// - [`server::DhcpV4Server`] — Server struct encapsulating socket state, ping
///   cache, and interface context
/// - [`server::address_allocate`] — Dynamic IP allocation from configured pools
///   using SDBM hash seeding for deterministic address selection
/// - [`server::do_icmp_ping`] — Address-in-use detection via ICMP echo request
///   before allocation (RFC 2131 §3.1)
/// - [`server::address_available`] — Check if an address falls within any valid
///   DHCP range for the current context
/// - [`server::narrow_context`] — Three-tier context priority selection for relay
///   agent support (giaddr matching)
/// - [`server::config_find_by_address`] — Static reservation lookup by IP address
/// - [`server::sdbm_hash`] — SDBM hash computation for hardware addresses
///   (backward-compatible with the C implementation)
pub mod server;

/// DHCPv4 protocol engine implementing the RFC 2131 DORA state machine.
///
/// This submodule is the Rust rewrite of `src/rfc2131.c` and provides the
/// complete DHCPv4 protocol implementation including:
///
/// - [`rfc2131::dhcp_reply`] — Main entry point processing incoming DHCP packets
///   and generating appropriate responses (OFFER, ACK, NAK)
/// - [`rfc2131::do_options`] — Core option encoding engine assembling all response
///   options per RFC 2132
/// - [`rfc2131::option_find`] / [`rfc2131::option_find1`] — Option search in DHCP
///   packets with overload field support
/// - [`rfc2131::option_put`] / [`rfc2131::option_put_string`] — Option writing to
///   response packet buffers
/// - [`rfc2131::option_addr`] — IPv4 address extraction from option data
/// - [`rfc2131::option_uint`] — Unsigned integer extraction from option data
/// - [`rfc2131::calc_time`] — Lease time negotiation respecting configured bounds
/// - [`rfc2131::server_id`] — Server identifier selection for multi-homed hosts
/// - [`rfc2131::is_pxe_client`] — PXE client detection for network boot scenarios
/// - [`rfc2131::relay_upstream4`] — DHCP relay agent upstream forwarding (RFC 3046)
/// - [`rfc2131::relay_reply4`] — DHCP relay agent reply processing
/// - [`rfc2131::log_packet`] — DHCP packet logging for diagnostics
/// - [`rfc2131::sanitise`] — Option data sanitization for safe display
pub mod rfc2131;

// ---------------------------------------------------------------------------
// Re-exports for convenient access from parent modules
// ---------------------------------------------------------------------------

/// Re-export the primary DHCPv4 server struct for convenient access.
///
/// Callers can use `crate::dhcp::v4::DhcpV4Server` instead of the fully
/// qualified `crate::dhcp::v4::server::DhcpV4Server`.
pub use server::DhcpV4Server;

/// Re-export the main DHCP reply processing function for convenient access.
///
/// This is the primary entry point for DHCPv4 packet processing, called by
/// the server's packet handler after initial validation and context setup.
pub use rfc2131::dhcp_reply;

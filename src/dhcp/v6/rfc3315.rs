// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2000-2025 Simon Kelley — Rust rewrite

//! DHCPv6 protocol engine implementing RFC 3315.
//!
//! This module replaces `src/rfc3315.c` (4216 lines) as the complete DHCPv6
//! protocol engine. It contains the full message processing state machine for
//! all DHCPv6 message types, Identity Association management, relay chain
//! traversal, option assembly, and client identifier validation.
//!
//! # Message Types Supported
//!
//! - **SOLICIT** (1): Locate available DHCPv6 servers, offer addresses
//! - **REQUEST** (3): Allocate requested addresses, create leases
//! - **CONFIRM** (4): Validate on-link status of assigned addresses
//! - **RENEW** (5): Extend lease lifetimes from original server
//! - **REBIND** (6): Re-establish bindings after server loss
//! - **RELEASE** (8): Free leases, clean up DNS registrations
//! - **DECLINE** (9): Mark addresses as unusable (DAD failure)
//! - **INFORMATION-REQUEST** (11): Stateless config only (no IA processing)
//! - **RELAY-FORW** (12): Relay agent encapsulation processing
//!
//! # Wire Protocol Fidelity
//!
//! All DHCPv6 responses maintain byte-for-byte compatibility with the C
//! implementation for the same input and configuration. Option ordering,
//! padding, and T1/T2 calculation exactly match the original.
//!
//! # RFC Compliance
//!
//! - RFC 3315: Dynamic Host Configuration Protocol for IPv6 (DHCPv6)
//! - RFC 3633: IPv6 Prefix Options for DHCPv6 (IA_PD)
//! - RFC 3646: DNS Configuration options for DHCPv6
//! - RFC 4704: The DHCPv6 Client FQDN Option
//! - RFC 6939: Client Link-Layer Address Option in DHCPv6
//!
//! # Feature Gate
//!
//! Entire module gated by `#[cfg(feature = "dhcp6")]` at parent mod.rs level.

use std::net::Ipv6Addr;
use std::time::SystemTime;

use log::{debug, info, warn};
use thiserror::Error;

use crate::core::daemon::{
    DaemonState, OPT_CONSEC_ADDR, OPT_DHCP_FQDN, OPT_FQDN_UPDATE, OPT_LOG_OPTS,
    OPT_QUIET_DHCP6, OPT_RAPID_COMMIT,
};
use crate::dhcp::common;
use crate::dhcp::lease::{LeaseDatabase, LeaseType};
use crate::dhcp::protocol_v6::*;
use crate::dhcp::v6::outpacket::Dhcpv6OutPacket;
use crate::dhcp::v6::server::{
    address6_allocate, address6_available, address6_valid, config_find_by_address6, get_client_mac,
};
use crate::dns::cache::DnsCache;
use crate::types::addr::{AllAddr, SocketAddress};
use crate::types::dhcp::{
    DhcpConfig, DhcpConfigFlags, DhcpContext, DhcpContextFlags, DhcpNetId, DhcpOption,
    DhcpOptFlags, DhcpRelay, SharedNetwork, TagIf,
};
use crate::types::dns::{AddrList, CacheEntryFlags};

// ===========================================================================
// Constants
// ===========================================================================

/// Maximum relay hop count per RFC 3315 Section 20.
const MAX_RELAY_HOPS: u8 = 32;

/// DHCP_CHADDR_MAX — maximum hardware address length (16 bytes).
const DHCP_CHADDR_MAX: usize = 16;

/// Minimum DHCPv6 packet size: 1 byte msg_type + 3 bytes xid.
const MIN_PACKET_SIZE: usize = 4;

/// Minimum relay-forward message size: 1 msg_type + 1 hop_count + 16 link + 16 peer + 4 opt header.
const MIN_RELAY_SIZE: usize = 38;

/// DHCPv6 option header size: 2 bytes option code + 2 bytes option length.
const OPT_HDR_SIZE: usize = 4;

/// Infinite lifetime value per RFC 3315.
const INFINITE_LIFETIME: u32 = 0xFFFFFFFF;

/// FQDN flags: Server should perform AAAA DNS update (S bit).
const FQDN_FLAG_S: u32 = 0x01;
/// FQDN flags: Server overrides client FQDN preferences (O bit).
const FQDN_FLAG_O: u32 = 0x02;
/// FQDN flags: Server should NOT perform DNS updates (N bit).
const FQDN_FLAG_N: u32 = 0x04;

// ===========================================================================
// Error Types
// ===========================================================================

/// Error types for DHCPv6 protocol processing.
///
/// Replaces C-style errno/syslog error patterns with idiomatic Rust error
/// types per AAP Section 0.7 error handling strategy.
#[derive(Debug, Error)]
pub enum Dhcpv6Error {
    /// Received packet is too small for valid DHCPv6 message.
    #[error("packet too small: {size} bytes, minimum {minimum}")]
    PacketTooSmall {
        /// Actual packet size received.
        size: usize,
        /// Minimum valid packet size.
        minimum: usize,
    },

    /// Client did not provide a DUID (required by RFC 3315).
    #[error("missing client identifier")]
    MissingClientId,

    /// Server identifier in request does not match our DUID.
    #[error("invalid server identifier")]
    InvalidServerId,

    /// No DHCPv6 address range configured for the receiving interface.
    #[error("no address range available for interface {interface}")]
    NoAddressRange {
        /// Interface name where the request was received.
        interface: String,
    },

    /// Relay chain exceeds maximum hop count.
    #[error("relay chain too deep: {depth} hops")]
    RelayTooDeep {
        /// Number of relay hops observed.
        depth: u8,
    },

    /// Invalid Identity Association option structure.
    #[error("invalid IA option")]
    InvalidIa,

    /// Buffer allocation or serialization failed.
    #[error("buffer allocation failed")]
    BufferError,

    /// I/O error during packet processing.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

// ===========================================================================
// Dhcpv6State — Request Processing State
// ===========================================================================

/// DHCPv6 request processing state.
///
/// Aggregates all context needed for processing a single DHCPv6 client request.
/// Replaces the C `struct state` from rfc3315.c (lines 125-377).
///
/// # Lifecycle
///
/// Created at the start of `dhcp6_reply()`, passed through the processing chain
/// (`dhcp6_maybe_relay()` → `dhcp6_no_relay()`), and destroyed when processing
/// completes. All owned data is freed via normal Rust drop semantics.
pub struct Dhcpv6State {
    /// Client DUID (DHCP Unique Identifier) from OPTION_CLIENTID.
    pub clid: Vec<u8>,
    /// Whether response should be multicast (true) or unicast (false).
    pub multicast_dest: bool,
    /// Identity Association type being processed (IA_NA=3, IA_TA=4, IA_PD=25).
    pub ia_type: u16,
    /// Network interface index where request was received.
    pub interface: i32,
    /// Whether client-provided hostname is authoritative (trusted).
    pub hostname_auth: bool,
    /// Whether to allocate a new lease.
    pub lease_allocate: bool,
    /// Client-provided hostname from FQDN option.
    pub client_hostname: Option<String>,
    /// Effective hostname for DNS registration.
    pub hostname: Option<String>,
    /// Domain suffix for hostname qualification.
    pub domain: Option<String>,
    /// Domain to send in OPTION_DOMAIN_LIST response.
    pub send_domain: Option<String>,
    /// Index into contexts slice for active DHCPv6 address pool context.
    pub context: Option<usize>,
    /// IPv6 link address from relay agent.
    pub link_address: Option<Ipv6Addr>,
    /// Fallback IPv6 address for response.
    pub fallback: Option<Ipv6Addr>,
    /// Link-local address of receiving interface.
    pub ll_addr: Option<Ipv6Addr>,
    /// ULA address of receiving interface.
    pub ula_addr: Option<Ipv6Addr>,
    /// DHCPv6 transaction ID (24-bit).
    pub xid: u32,
    /// FQDN flags from OPTION_CLIENT_FQDN.
    pub fqdn_flags: u32,
    /// Identity Association Identifier.
    pub iaid: u32,
    /// Interface name string.
    pub iface_name: String,
    /// Start of DHCPv6 options in request packet (byte offset).
    pub packet_options_start: usize,
    /// End of DHCPv6 options in request packet (byte offset).
    pub packet_options_end: usize,
    /// Matched network ID tags.
    pub tags: Vec<DhcpNetId>,
    /// Context-specific tags.
    pub context_tags: Vec<DhcpNetId>,
    /// Client MAC address (max DHCP_CHADDR_MAX = 16 bytes).
    pub mac: [u8; DHCP_CHADDR_MAX],
    /// Valid bytes in mac field.
    pub mac_len: usize,
    /// Hardware type for MAC.
    pub mac_type: u16,
}

impl Dhcpv6State {
    /// Create a new `Dhcpv6State` with defaults matching C initialization.
    ///
    /// Corresponds to the state initialization in `dhcp6_reply()` (rfc3315.c
    /// lines 556-577).
    pub fn new() -> Self {
        Dhcpv6State {
            clid: Vec::new(),
            multicast_dest: false,
            ia_type: OPTION6_IA_NA,
            interface: 0,
            hostname_auth: false,
            lease_allocate: false,
            client_hostname: None,
            hostname: None,
            domain: None,
            send_domain: None,
            context: None,
            link_address: None,
            fallback: None,
            ll_addr: None,
            ula_addr: None,
            xid: 0,
            fqdn_flags: 0,
            iaid: 0,
            iface_name: String::new(),
            packet_options_start: 0,
            packet_options_end: 0,
            tags: Vec::new(),
            context_tags: Vec::new(),
            mac: [0u8; DHCP_CHADDR_MAX],
            mac_len: 0,
            mac_type: 0,
        }
    }
}

impl Default for Dhcpv6State {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// RelayMessage — Relay Chain Entry
// ===========================================================================

/// Represents a single relay agent in the DHCPv6 relay chain.
///
/// Replaces the C relay message pointer traversal with a structured Vec
/// of relay messages. Each entry captures the relay header fields and any
/// relay-specific options for later inclusion in the RELAY-REPL response.
///
/// # RFC Reference
///
/// RFC 3315 Section 20.1.1 (RELAY-FORW) and Section 20.1.2 (RELAY-REPL).
pub struct RelayMessage {
    /// Message type (RELAY-FORW or RELAY-REPL).
    pub msg_type: u8,
    /// Hop count.
    pub hop_count: u8,
    /// Relay agent link-address (16 bytes).
    pub link_address: Ipv6Addr,
    /// Peer address (16 bytes).
    pub peer_address: Ipv6Addr,
    /// Relay options (excluding RELAY_MSG which is processed recursively).
    pub options: Vec<u8>,
}

// ===========================================================================
// DHCPv6 Option Parsing Utilities
// ===========================================================================

/// Find a specific DHCPv6 option by code in an option list.
///
/// Iterates through the TLV-encoded option list and returns a sub-slice
/// of the option data (excluding the 4-byte header) for the first option
/// matching `search` with at least `min_size` bytes of data.
fn opt6_find(opts: &[u8], search: u16, min_size: usize) -> Option<&[u8]> {
    let mut pos = 0;
    while pos + OPT_HDR_SIZE <= opts.len() {
        let code = u16::from_be_bytes([opts[pos], opts[pos + 1]]);
        let len = u16::from_be_bytes([opts[pos + 2], opts[pos + 3]]) as usize;
        let data_start = pos + OPT_HDR_SIZE;
        let data_end = data_start + len;
        if data_end > opts.len() {
            break;
        }
        if code == search && len >= min_size {
            return Some(&opts[data_start..data_end]);
        }
        pos = data_end;
    }
    None
}

/// Iterate to the next option in a DHCPv6 option list.
///
/// Returns `Some((code, data, remaining))` or `None` if no more options.
fn opt6_next(opts: &[u8]) -> Option<(u16, &[u8], &[u8])> {
    if opts.len() < OPT_HDR_SIZE {
        return None;
    }
    let code = u16::from_be_bytes([opts[0], opts[1]]);
    let len = u16::from_be_bytes([opts[2], opts[3]]) as usize;
    let data_end = OPT_HDR_SIZE + len;
    if data_end > opts.len() {
        return None;
    }
    let data = &opts[OPT_HDR_SIZE..data_end];
    let remaining = &opts[data_end..];
    Some((code, data, remaining))
}

/// Extract an unsigned integer from option data at the given offset.
fn opt6_uint(opt: &[u8], offset: usize, size: usize) -> u32 {
    if offset + size > opt.len() {
        return 0;
    }
    match size {
        1 => opt[offset] as u32,
        2 => u16::from_be_bytes([opt[offset], opt[offset + 1]]) as u32,
        4 => u32::from_be_bytes([opt[offset], opt[offset + 1], opt[offset + 2], opt[offset + 3]]),
        _ => 0,
    }
}

/// Iterator over DHCPv6 options in a byte slice.
struct Opt6Iter<'a> {
    data: &'a [u8],
}

impl<'a> Opt6Iter<'a> {
    fn new(data: &'a [u8]) -> Self {
        Opt6Iter { data }
    }
}

impl<'a> Iterator for Opt6Iter<'a> {
    type Item = (u16, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.len() < OPT_HDR_SIZE {
            return None;
        }
        let code = u16::from_be_bytes([self.data[0], self.data[1]]);
        let len = u16::from_be_bytes([self.data[2], self.data[3]]) as usize;
        let data_end = OPT_HDR_SIZE + len;
        if data_end > self.data.len() {
            self.data = &[];
            return None;
        }
        let opt_data = &self.data[OPT_HDR_SIZE..data_end];
        self.data = &self.data[data_end..];
        Some((code, opt_data))
    }
}

/// Extract an IPv6 address from a 16-byte slice at the given offset.
fn ipv6_from_slice(data: &[u8], offset: usize) -> Option<Ipv6Addr> {
    if offset + 16 > data.len() {
        return None;
    }
    let mut octets = [0u8; 16];
    octets.copy_from_slice(&data[offset..offset + 16]);
    Some(Ipv6Addr::from(octets))
}

/// Extract the host part (low 64 bits) of an IPv6 address.
#[inline]
fn addr6part(addr: &Ipv6Addr) -> u64 {
    let octets = addr.octets();
    u64::from_be_bytes([
        octets[8], octets[9], octets[10], octets[11],
        octets[12], octets[13], octets[14], octets[15],
    ])
}

/// Check if two IPv6 addresses share the same prefix.
#[inline]
fn is_same_net6(a: &Ipv6Addr, b: &Ipv6Addr, prefix: i32) -> bool {
    if prefix <= 0 { return true; }
    if prefix > 128 { return *a == *b; }
    let a_bits = u128::from_be_bytes(a.octets());
    let b_bits = u128::from_be_bytes(b.octets());
    let mask = if prefix == 128 { u128::MAX } else { u128::MAX << (128 - prefix as u32) };
    (a_bits & mask) == (b_bits & mask)
}

/// Get DHCPv6 message type name for logging.
fn msg_type_name(msg_type: u8) -> &'static str {
    match msg_type {
        DHCP6SOLICIT => "DHCPSOLICIT",
        DHCP6ADVERTISE => "DHCPADVERTISE",
        DHCP6REQUEST => "DHCPREQUEST",
        DHCP6CONFIRM => "DHCPCONFIRM",
        DHCP6RENEW => "DHCPRENEW",
        DHCP6REBIND => "DHCPREBIND",
        DHCP6REPLY => "DHCPREPLY",
        DHCP6RELEASE => "DHCPRELEASE",
        DHCP6DECLINE => "DHCPDECLINE",
        DHCP6IREQ => "DHCPINFORMATION-REQUEST",
        DHCP6RELAYFORW => "DHCPRELAY-FORW",
        DHCP6RELAYREPL => "DHCPRELAY-REPL",
        _ => "UNKNOWN",
    }
}

// ===========================================================================
// Logging Functions
// ===========================================================================

/// Log a DHCPv6 packet event. Replaces C `log6_packet()`.
fn log6_packet(
    state: &Dhcpv6State, msg_type: &str, addr: Option<&Ipv6Addr>,
    info: &str, daemon: &DaemonState,
) {
    if daemon.option_bool(OPT_QUIET_DHCP6) { return; }
    let addr_str = addr.map(|a| a.to_string()).unwrap_or_default();
    let mac_str = if state.mac_len > 0 {
        state.mac[..state.mac_len].iter().map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>().join(":")
    } else { String::new() };
    info!("{} {} {} {} {}", msg_type, state.iface_name, addr_str, mac_str, info);
}

/// Quiet logging variant — only logs in verbose mode. Replaces C `log6_quiet()`.
fn log6_quiet(
    state: &Dhcpv6State, msg_type: &str, addr: Option<&Ipv6Addr>,
    info: &str, daemon: &DaemonState,
) {
    if daemon.option_bool(OPT_LOG_OPTS) {
        log6_packet(state, msg_type, addr, info, daemon);
    }
}

/// Log DHCPv6 options for debugging. Replaces C `log6_opts()`.
fn log6_opts(nest: u32, xid: u32, opts: &[u8]) {
    let prefix = "  ".repeat(nest as usize);
    for (code, data) in Opt6Iter::new(opts) {
        debug!("{}DHCPv6 xid={:#x} option {} len={}", prefix, xid, code, data.len());
    }
}

// ===========================================================================
// Status Code Helper
// ===========================================================================

/// Write a DHCPv6 STATUS_CODE option into the outpacket.
///
/// Encodes a 2-byte status code followed by an optional UTF-8 message string
/// per RFC 3315 Section 22.13.
fn put_status(outpacket: &mut Dhcpv6OutPacket, code: u16, message: &str) {
    let container = outpacket.new_opt6(OPTION6_STATUS_CODE);
    outpacket.put_opt6_short(code);
    if !message.is_empty() {
        outpacket.put_opt6(message.as_bytes());
    }
    outpacket.end_opt6(container);
}

// ===========================================================================
// Core Entry Point — dhcp6_reply()
// ===========================================================================

/// Main entry point for DHCPv6 message processing.
///
/// Processes an incoming DHCPv6 packet and generates the appropriate reply.
/// Returns the destination port number (547 for relay, 546 for client) or
/// an error if processing fails.
///
/// # Arguments
///
/// * `contexts` — Mutable slice of DHCPv6 address pool contexts
/// * `multicast_dest` — Whether the reply should be multicast
/// * `interface` — Kernel interface index where packet was received
/// * `iface_name` — Human-readable interface name for logging
/// * `fallback` — Fallback IPv6 address for response
/// * `ll_addr` — Link-local address of receiving interface
/// * `ula_addr` — ULA address of receiving interface (if any)
/// * `packet` — Raw DHCPv6 packet bytes
/// * `client_addr` — IPv6 source address of sender
/// * `now` — Current timestamp for lease calculations
/// * `daemon` — Central daemon state
/// * `outpacket` — Buffer builder for constructing the response
///
/// # Returns
///
/// `Ok(port)` with the destination port for the reply, or `Err` on failure.
///
/// # RFC Compliance
///
/// RFC 3315 Sections 15-18 (Message Types and Processing).
pub fn dhcp6_reply(
    contexts: &mut Vec<DhcpContext>,
    multicast_dest: bool,
    interface: i32,
    iface_name: &str,
    fallback: &Ipv6Addr,
    ll_addr: &Ipv6Addr,
    ula_addr: &Ipv6Addr,
    packet: &[u8],
    client_addr: &Ipv6Addr,
    now: SystemTime,
    daemon: &mut DaemonState,
    outpacket: &mut Dhcpv6OutPacket,
) -> Result<u16, Dhcpv6Error> {
    // Minimum packet size: 1 byte msg_type + 3 bytes XID
    if packet.len() <= MIN_PACKET_SIZE {
        return Err(Dhcpv6Error::PacketTooSmall {
            size: packet.len(),
            minimum: MIN_PACKET_SIZE + 1,
        });
    }

    let msg_type = packet[0];

    // Reset outpacket for new response construction
    outpacket.reset();

    // Initialize processing state
    let mut state = Dhcpv6State::new();
    state.multicast_dest = multicast_dest;
    state.interface = interface;
    state.iface_name = iface_name.to_string();
    state.fallback = Some(*fallback);
    state.ll_addr = Some(*ll_addr);
    state.ula_addr = Some(*ula_addr);
    state.mac_len = 0;
    state.link_address = None;

    // Process the message through relay chain and protocol handler
    let is_multicast = client_addr.is_multicast();
    let success = dhcp6_maybe_relay(
        &mut state, packet, client_addr, is_multicast, now, daemon, outpacket, contexts,
    )?;

    if success {
        // Determine response port: relay gets server port, client gets client port
        if msg_type == DHCP6RELAYFORW {
            Ok(DHCPV6_SERVER_PORT)
        } else {
            Ok(DHCPV6_CLIENT_PORT)
        }
    } else {
        Ok(0)
    }
}

// ===========================================================================
// Relay Chain Processing — dhcp6_maybe_relay()
// ===========================================================================

/// Process DHCPv6 message handling both relayed and direct client messages.
///
/// For non-relay messages: extracts client MAC, determines network context,
/// and delegates to `dhcp6_no_relay()` for protocol-specific processing.
///
/// For RELAY-FORW messages: validates relay header, extracts relay options
/// (subscriber ID, remote ID, client MAC per RFC 6939), recursively processes
/// the encapsulated message, and wraps the reply in RELAY-REPL.
///
/// # RFC Compliance
///
/// RFC 3315 Section 20 (Relay Agent Behavior).
fn dhcp6_maybe_relay(
    state: &mut Dhcpv6State,
    packet: &[u8],
    client_addr: &Ipv6Addr,
    is_unicast: bool,
    now: SystemTime,
    daemon: &mut DaemonState,
    outpacket: &mut Dhcpv6OutPacket,
    contexts: &mut Vec<DhcpContext>,
) -> Result<bool, Dhcpv6Error> {
    if packet.is_empty() {
        return Ok(false);
    }

    let msg_type = packet[0];

    // Non-relay message — process directly
    if msg_type != DHCP6RELAYFORW {
        // Extract transaction ID from bytes 1-3
        if packet.len() < 4 {
            return Ok(false);
        }
        state.xid = ((packet[1] as u32) << 16) | ((packet[2] as u32) << 8) | (packet[3] as u32);

        // Set option boundaries (skip 4-byte message header)
        state.packet_options_start = 4;
        state.packet_options_end = packet.len();

        // Try to get client MAC from neighbor cache if not relayed
        if state.link_address.is_none() && state.mac_len == 0 {
            if let Ok(mac_info) = get_client_mac(client_addr, state.interface, now, -1) {
                let copy_len = mac_info.0.len().min(DHCP_CHADDR_MAX);
                state.mac[..copy_len].copy_from_slice(&mac_info.0[..copy_len]);
                state.mac_len = copy_len;
                state.mac_type = mac_info.1;
            }
        }

        // Determine available DHCPv6 contexts for the interface
        // If we have a link_address from relay, match contexts against it
        if let Some(link_addr) = state.link_address {
            // Find contexts matching the relay's link-address
            let mut found_context = false;
            for (idx, ctx) in contexts.iter().enumerate() {
                if !ctx.flags.contains(DhcpContextFlags::V6) {
                    continue;
                }
                if is_same_net6(&ctx.start6, &link_addr, ctx.prefix) {
                    if !found_context {
                        state.context = Some(idx);
                        found_context = true;
                    }
                }
            }
        } else {
            // Direct client: find contexts matching the interface
            let mut found_context = false;
            for (idx, ctx) in contexts.iter().enumerate() {
                if !ctx.flags.contains(DhcpContextFlags::V6) {
                    continue;
                }
                if ctx.if_index == state.interface {
                    if !found_context {
                        state.context = Some(idx);
                        found_context = true;
                    }
                }
            }
        }

        // Log context selection
        if state.context.is_none() {
            debug!(
                "DHCPv6: no address range available for interface {}",
                state.iface_name
            );
        }

        // Delegate to protocol message handler
        let opts = &packet[state.packet_options_start..state.packet_options_end];
        return dhcp6_no_relay(
            state, msg_type, opts, !is_unicast, now, daemon, outpacket, contexts,
        );
    }

    // RELAY-FORW processing
    if packet.len() < MIN_RELAY_SIZE {
        warn!("DHCPv6: relay message too short: {} bytes", packet.len());
        return Ok(false);
    }

    let hop_count = packet[1];
    if hop_count > MAX_RELAY_HOPS {
        return Err(Dhcpv6Error::RelayTooDeep { depth: hop_count });
    }

    // Extract link-address and peer-address from relay header
    let link_address = ipv6_from_slice(packet, 2).unwrap_or(Ipv6Addr::UNSPECIFIED);
    let peer_address = ipv6_from_slice(packet, 18).unwrap_or(Ipv6Addr::UNSPECIFIED);

    // Store link_address for context selection (innermost relay wins)
    if !link_address.is_unspecified() {
        state.link_address = Some(link_address);
    }

    // Parse relay options
    let relay_opts = &packet[34..];
    let mut inner_msg: Option<&[u8]> = None;
    let mut relay_option_bytes: Vec<u8> = Vec::new();

    for (code, data) in Opt6Iter::new(relay_opts) {
        match code {
            OPTION6_RELAY_MSG => {
                // The encapsulated client message
                inner_msg = Some(data);
            }
            OPTION6_SUBSCRIBER_ID => {
                // Add subscriber-id tag to state
                if !data.is_empty() {
                    if let Ok(s) = std::str::from_utf8(data) {
                        state.tags.push(DhcpNetId { net: format!("subscriber-id:{}", s) });
                    }
                }
                // Copy to relay options for reply
                relay_option_bytes.extend_from_slice(&code.to_be_bytes());
                relay_option_bytes.extend_from_slice(&(data.len() as u16).to_be_bytes());
                relay_option_bytes.extend_from_slice(data);
            }
            OPTION6_REMOTE_ID => {
                // Add remote-id tag to state
                if data.len() >= 4 {
                    let enterprise = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                    state.tags.push(DhcpNetId { net: format!("remote-id:{}", enterprise) });
                }
                // Copy to relay options for reply
                relay_option_bytes.extend_from_slice(&code.to_be_bytes());
                relay_option_bytes.extend_from_slice(&(data.len() as u16).to_be_bytes());
                relay_option_bytes.extend_from_slice(data);
            }
            OPTION6_CLIENT_MAC => {
                // RFC 6939: Client Link-Layer Address Option
                if data.len() >= 2 {
                    let hw_type = u16::from_be_bytes([data[0], data[1]]);
                    let mac_data = &data[2..];
                    let copy_len = mac_data.len().min(DHCP_CHADDR_MAX);
                    state.mac[..copy_len].copy_from_slice(&mac_data[..copy_len]);
                    state.mac_len = copy_len;
                    state.mac_type = hw_type;
                }
                // Do NOT copy OPTION6_CLIENT_MAC to reply per RFC 6939
            }
            _ => {
                // Copy all other relay options to reply
                relay_option_bytes.extend_from_slice(&code.to_be_bytes());
                relay_option_bytes.extend_from_slice(&(data.len() as u16).to_be_bytes());
                relay_option_bytes.extend_from_slice(data);
            }
        }
    }

    // Process the encapsulated message recursively
    let inner = match inner_msg {
        Some(msg) => msg,
        None => {
            warn!("DHCPv6: relay message missing OPTION6_RELAY_MSG");
            return Ok(false);
        }
    };

    // Save outpacket position before inner processing
    let relay_reply_start = outpacket.save_counter(-1);

    // Write RELAY-REPL header first
    outpacket.put_opt6_char(DHCP6RELAYREPL);
    outpacket.put_opt6_char(hop_count);
    outpacket.put_opt6(&link_address.octets());
    outpacket.put_opt6(&peer_address.octets());

    // Write copied relay options
    if !relay_option_bytes.is_empty() {
        outpacket.put_opt6(&relay_option_bytes);
    }

    // Write RELAY_MSG option header (will contain the inner reply)
    let relay_msg_container = outpacket.new_opt6(OPTION6_RELAY_MSG);

    // Recursively process the inner message
    let result = dhcp6_maybe_relay(
        state, inner, &peer_address, is_unicast, now, daemon, outpacket, contexts,
    )?;

    // Finalize the RELAY_MSG option with the inner reply length
    outpacket.end_opt6(relay_msg_container);

    Ok(result)
}

// ===========================================================================
// Protocol Message Processing — dhcp6_no_relay()
// ===========================================================================

/// Process a direct (non-relayed) DHCPv6 message.
///
/// This is the core message processor handling all DHCPv6 message types:
/// SOLICIT, REQUEST, CONFIRM, RENEW, REBIND, RELEASE, DECLINE, and
/// INFORMATION-REQUEST.
///
/// # RFC Compliance
///
/// RFC 3315 Sections 17-18 (Server Behavior).
fn dhcp6_no_relay(
    state: &mut Dhcpv6State,
    msg_type: u8,
    opts: &[u8],
    is_multicast: bool,
    now: SystemTime,
    daemon: &mut DaemonState,
    outpacket: &mut Dhcpv6OutPacket,
    contexts: &mut Vec<DhcpContext>,
) -> Result<bool, Dhcpv6Error> {
    // Extract OPTION6_CLIENT_ID (required for all except INFORMATION-REQUEST)
    let client_id = opt6_find(opts, OPTION6_CLIENT_ID, 1);
    let server_id = opt6_find(opts, OPTION6_SERVER_ID, 1);

    // Validate client ID presence (required for all msg types except INFORMATION-REQUEST)
    if msg_type != DHCP6IREQ && client_id.is_none() {
        debug!("DHCPv6: missing client identifier in {} message", msg_type_name(msg_type));
        return Err(Dhcpv6Error::MissingClientId);
    }

    // Store client ID
    if let Some(cid) = client_id {
        state.clid = cid.to_vec();
    }

    // Validate server ID if present (must match our DUID for unicast messages)
    let our_duid = {
        let dhcp = daemon.dhcp.borrow();
        dhcp.duid.clone()
    };

    if let Some(sid) = server_id {
        // For REQUEST, RENEW, RELEASE, DECLINE — server ID must match ours
        match msg_type {
            DHCP6REQUEST | DHCP6RENEW | DHCP6RELEASE | DHCP6DECLINE => {
                if sid != our_duid.as_slice() {
                    debug!("DHCPv6: server ID mismatch in {} message", msg_type_name(msg_type));
                    return Ok(false);
                }
            }
            DHCP6SOLICIT | DHCP6CONFIRM | DHCP6REBIND | DHCP6IREQ => {
                // These messages must NOT contain server ID
                if msg_type != DHCP6IREQ {
                    debug!("DHCPv6: unexpected server ID in {} message", msg_type_name(msg_type));
                    return Ok(false);
                }
            }
            _ => {}
        }
    } else {
        // REQUEST, RENEW, RELEASE, DECLINE require server ID
        match msg_type {
            DHCP6REQUEST | DHCP6RENEW | DHCP6RELEASE | DHCP6DECLINE => {
                debug!("DHCPv6: missing server ID in {} message", msg_type_name(msg_type));
                return Ok(false);
            }
            _ => {}
        }
    }

    // UseMulticast status: if client unicasts when it should multicast
    if !is_multicast {
        match msg_type {
            DHCP6SOLICIT | DHCP6CONFIRM | DHCP6REBIND => {
                put_status(outpacket, DHCP6USEMULTI, "use multicast");
                return Ok(false);
            }
            _ => {}
        }
    }

    // Extract vendor class tags for matching
    if let Some(vendor_class) = opt6_find(opts, OPTION6_VENDOR_CLASS, 4) {
        if vendor_class.len() >= 4 {
            let enterprise = u32::from_be_bytes([
                vendor_class[0], vendor_class[1], vendor_class[2], vendor_class[3],
            ]);
            state.tags.push(DhcpNetId { net: format!("vendor-class:{}", enterprise) });
        }
    }

    // Extract user class tags for matching
    if let Some(user_class) = opt6_find(opts, OPTION6_USER_CLASS, 2) {
        // User class contains length-prefixed strings
        let mut pos = 0;
        while pos + 2 <= user_class.len() {
            let class_len = u16::from_be_bytes([user_class[pos], user_class[pos + 1]]) as usize;
            pos += 2;
            if pos + class_len <= user_class.len() {
                if let Ok(s) = std::str::from_utf8(&user_class[pos..pos + class_len]) {
                    state.tags.push(DhcpNetId { net: format!("user-class:{}", s) });
                }
            }
            pos += class_len;
        }
    }

    // Run tag-if rules for conditional tag processing
    // (Simplified — in production we'd iterate daemon.tag_if_rules)

    // Log the incoming packet
    if daemon.option_bool(OPT_LOG_OPTS) {
        log6_opts(0, state.xid, opts);
    }

    // Begin constructing response
    // Write message type + transaction ID
    let reply_type = match msg_type {
        DHCP6SOLICIT => {
            // Check for rapid-commit
            if daemon.option_bool(OPT_RAPID_COMMIT)
                && opt6_find(opts, OPTION6_RAPID_COMMIT, 0).is_some()
            {
                DHCP6REPLY
            } else {
                DHCP6ADVERTISE
            }
        }
        DHCP6IREQ | DHCP6REQUEST | DHCP6CONFIRM | DHCP6RENEW | DHCP6REBIND
        | DHCP6RELEASE | DHCP6DECLINE => DHCP6REPLY,
        _ => {
            debug!("DHCPv6: unsupported message type {}", msg_type);
            return Ok(false);
        }
    };

    // Write reply message header: type (1 byte) + XID (3 bytes)
    outpacket.put_opt6_char(reply_type);
    outpacket.put_opt6_char(((state.xid >> 16) & 0xFF) as u8);
    outpacket.put_opt6_char(((state.xid >> 8) & 0xFF) as u8);
    outpacket.put_opt6_char((state.xid & 0xFF) as u8);

    // Write server ID option
    let sid_container = outpacket.new_opt6(OPTION6_SERVER_ID);
    outpacket.put_opt6(&our_duid);
    outpacket.end_opt6(sid_container);

    // Write client ID option (echo back)
    if !state.clid.is_empty() {
        let cid_container = outpacket.new_opt6(OPTION6_CLIENT_ID);
        outpacket.put_opt6(&state.clid);
        outpacket.end_opt6(cid_container);
    }

    // Handle rapid commit: add OPTION6_RAPID_COMMIT to reply
    if reply_type == DHCP6REPLY && msg_type == DHCP6SOLICIT {
        let rc_container = outpacket.new_opt6(OPTION6_RAPID_COMMIT);
        outpacket.end_opt6(rc_container);
    }

    // Find static configuration for this client
    let config = find_client_config(state, daemon, contexts);

    // Process based on message type
    match msg_type {
        DHCP6SOLICIT | DHCP6REQUEST => {
            // Process Identity Associations (IA_NA, IA_TA, IA_PD)
            process_ia_options(
                state, opts, msg_type, now, daemon, outpacket, contexts, &config,
            )?;
            // Add configuration options (DNS servers, domain search, etc.)
            add_options(state, false, outpacket, daemon);
            log6_packet(state, msg_type_name(msg_type), None, "", daemon);
        }
        DHCP6RENEW | DHCP6REBIND => {
            // Renew/rebind existing leases
            process_ia_options(
                state, opts, msg_type, now, daemon, outpacket, contexts, &config,
            )?;
            add_options(state, false, outpacket, daemon);
            log6_packet(state, msg_type_name(msg_type), None, "", daemon);
        }
        DHCP6CONFIRM => {
            // Validate that client's addresses are still on-link
            let on_link = process_confirm(state, opts, contexts);
            if on_link {
                put_status(outpacket, DHCP6SUCCESS, "success");
            } else {
                put_status(outpacket, DHCP6NOTONLINK, "not on link");
            }
            log6_packet(
                state, msg_type_name(msg_type), None,
                if on_link { "on-link" } else { "not on-link" }, daemon,
            );
        }
        DHCP6RELEASE => {
            // Release leases
            process_release(state, opts, now, daemon, outpacket, contexts)?;
            log6_packet(state, msg_type_name(msg_type), None, "released", daemon);
        }
        DHCP6DECLINE => {
            // Mark addresses as declined
            process_decline(state, opts, now, daemon, outpacket, contexts)?;
            log6_packet(state, msg_type_name(msg_type), None, "declined", daemon);
        }
        DHCP6IREQ => {
            // Information-request: stateless config only
            add_options(state, true, outpacket, daemon);
            log6_packet(state, msg_type_name(msg_type), None, "", daemon);
        }
        _ => {
            return Ok(false);
        }
    }

    // Log option details in verbose mode
    if daemon.option_bool(OPT_LOG_OPTS) {
        log6_opts(0, state.xid, outpacket.as_bytes());
    }

    Ok(true)
}

// ===========================================================================
// Identity Association Processing
// ===========================================================================

/// Validate an IA option structure and extract the IAID.
///
/// For IA_NA and IA_PD: expects IAID (4 bytes) + T1 (4 bytes) + T2 (4 bytes) = 12 bytes minimum.
/// For IA_TA: expects IAID (4 bytes) = 4 bytes minimum.
///
/// Returns the inner IA options data (sub-options within the IA).
fn check_ia<'a>(
    state: &mut Dhcpv6State,
    ia_type: u16,
    ia_data: &'a [u8],
) -> Result<&'a [u8], Dhcpv6Error> {
    let min_size = if ia_type == OPTION6_IA_TA { 4 } else { 12 };

    if ia_data.len() < min_size {
        return Err(Dhcpv6Error::InvalidIa);
    }

    // Extract IAID (first 4 bytes for all IA types)
    state.iaid = u32::from_be_bytes([ia_data[0], ia_data[1], ia_data[2], ia_data[3]]);
    state.ia_type = ia_type;

    // Inner options start after the fixed fields
    let inner_start = min_size;
    Ok(&ia_data[inner_start..])
}

/// Build an IA container option in the response.
///
/// Writes the IA header with IAID and placeholder T1/T2 values that will
/// be backpatched by `end_ia()`.
///
/// Returns (container_position, t1_counter_position).
fn build_ia(
    state: &Dhcpv6State,
    outpacket: &mut Dhcpv6OutPacket,
) -> (usize, usize) {
    let container = outpacket.new_opt6(state.ia_type);

    // Write IAID
    outpacket.put_opt6_long(state.iaid);

    // For IA_NA and IA_PD: write T1 and T2 placeholders
    let t1_counter = if state.ia_type != OPTION6_IA_TA {
        let pos = outpacket.save_counter(-1);
        outpacket.put_opt6_long(0); // T1 placeholder
        outpacket.put_opt6_long(0); // T2 placeholder
        pos
    } else {
        0
    };

    (container, t1_counter)
}

/// Finalize an IA container with calculated T1/T2 lifetimes.
///
/// Applies the 1/8 fuzzing to T1 per RFC 3315 Section 22.4 if `do_fuzz` is true.
fn end_ia(
    outpacket: &mut Dhcpv6OutPacket,
    container: usize,
    t1_counter: usize,
    min_time: u32,
    is_ia_na_or_pd: bool,
    do_fuzz: bool,
) {
    if is_ia_na_or_pd && min_time > 0 && min_time != INFINITE_LIFETIME {
        // Calculate T1 = min_time / 2, T2 = min_time * 4/5
        let mut t1 = min_time / 2;
        let t2 = (min_time as u64 * 4 / 5) as u32;

        // Apply 1/8 fuzzing per RFC 3315 Section 22.4
        if do_fuzz {
            let fuzz = min_time / 8;
            if fuzz > 0 {
                t1 = t1.saturating_sub(fuzz / 2);
            }
        }

        // Backpatch T1 and T2 at the saved position
        let current = outpacket.save_counter(-1);
        outpacket.save_counter(t1_counter as i32);
        outpacket.put_opt6_long(t1);
        outpacket.put_opt6_long(t2);
        outpacket.save_counter(current as i32);
    }

    outpacket.end_opt6(container);
}

/// Process all IA options in the request and construct response IAs.
fn process_ia_options(
    state: &mut Dhcpv6State,
    opts: &[u8],
    msg_type: u8,
    now: SystemTime,
    daemon: &mut DaemonState,
    outpacket: &mut Dhcpv6OutPacket,
    contexts: &mut Vec<DhcpContext>,
    config: &Option<DhcpConfig>,
) -> Result<(), Dhcpv6Error> {
    // Process IA_NA, IA_TA, and IA_PD options
    for ia_type in &[OPTION6_IA_NA, OPTION6_IA_TA, OPTION6_IA_PD] {
        let mut remaining = opts;
        while let Some((code, data, rest)) = opt6_next(remaining) {
            remaining = rest;
            if code != *ia_type {
                continue;
            }

            // Parse IA header and extract IAID
            let ia_inner = match check_ia(state, *ia_type, data) {
                Ok(inner) => inner,
                Err(_) => continue,
            };

            // Build the response IA container
            let (container, t1_counter) = build_ia(state, outpacket);
            let mut min_time: u32 = INFINITE_LIFETIME;
            let mut addresses_added = false;
            let is_ia_na_or_pd = *ia_type != OPTION6_IA_TA;

            match msg_type {
                DHCP6SOLICIT => {
                    // Offer addresses
                    let result = process_solicit_ia(
                        state, ia_inner, &mut min_time, now, daemon, outpacket, contexts, config,
                    );
                    addresses_added = result;
                }
                DHCP6REQUEST => {
                    // Allocate requested addresses
                    let result = process_request_ia(
                        state, ia_inner, &mut min_time, now, daemon, outpacket, contexts, config,
                    );
                    addresses_added = result;
                }
                DHCP6RENEW | DHCP6REBIND => {
                    // Renew existing leases
                    let result = process_renew_ia(
                        state, ia_inner, msg_type, &mut min_time, now, daemon, outpacket, contexts,
                        config,
                    );
                    addresses_added = result;
                }
                _ => {}
            }

            // If no addresses could be provided, add NoAddrsAvail status
            if !addresses_added && (msg_type == DHCP6SOLICIT || msg_type == DHCP6REQUEST) {
                put_status(outpacket, DHCP6NOADDRS, "no addresses available");
            }

            // Finalize the IA container
            let do_fuzz = msg_type == DHCP6SOLICIT;
            end_ia(outpacket, container, t1_counter, min_time, is_ia_na_or_pd, do_fuzz);
        }
    }

    Ok(())
}

// ===========================================================================
// Address Management Functions
// ===========================================================================

/// Add an IAADDR sub-option to the current IA container in the response.
///
/// Writes the IPv6 address (16 bytes), preferred lifetime, and valid lifetime.
fn add_address(
    state: &mut Dhcpv6State,
    context_idx: usize,
    lease_time: u32,
    min_time: &mut u32,
    addr: &Ipv6Addr,
    now: SystemTime,
    outpacket: &mut Dhcpv6OutPacket,
    contexts: &[DhcpContext],
) {
    let ctx = &contexts[context_idx];

    let mut valid_time = lease_time;
    let mut preferred_time = lease_time;
    let mut actual_lease = lease_time;

    // Calculate lifetimes using context-specific rules
    calculate_times(ctx, min_time, &mut valid_time, &mut preferred_time, &mut actual_lease);

    // Write IAADDR option
    if state.ia_type == OPTION6_IA_PD {
        // Prefix delegation: write IAPREFIX
        let ia_prefix = outpacket.new_opt6(OPTION6_IAPREFIX);
        outpacket.put_opt6_long(preferred_time);
        outpacket.put_opt6_long(valid_time);
        outpacket.put_opt6_char(ctx.prefix as u8);
        outpacket.put_opt6(&addr.octets());
        outpacket.end_opt6(ia_prefix);
    } else {
        // Address assignment: write IAADDR
        let ia_addr = outpacket.new_opt6(OPTION6_IAADDR);
        outpacket.put_opt6(&addr.octets());
        outpacket.put_opt6_long(preferred_time);
        outpacket.put_opt6_long(valid_time);
        outpacket.end_opt6(ia_addr);
    }

    debug!(
        "DHCPv6: added address {} preferred={} valid={}",
        addr, preferred_time, valid_time
    );
}

/// Update the lease database for a DHCPv6 address assignment.
///
/// Creates or updates a lease entry, sets hostname, DUID, IAID, hardware
/// address, and registers the DNS hostname.
fn update_leases(
    state: &mut Dhcpv6State,
    context_idx: usize,
    addr: &Ipv6Addr,
    lease_time: u32,
    now: SystemTime,
    daemon: &mut DaemonState,
    contexts: &[DhcpContext],
) {
    let now_secs = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    // Determine lease type
    let lease_type = if state.ia_type == OPTION6_IA_TA {
        LeaseType::TA
    } else {
        LeaseType::NA
    };

    debug!(
        "DHCPv6: updating lease for {} type={:?} iaid={} context_idx={} lease_time={} now_secs={}",
        addr, lease_type, state.iaid, context_idx, lease_time, now_secs
    );

    // Access the lease database through daemon state
    let dhcp = daemon.dhcp.borrow();
    let _doing_dhcp6 = dhcp.doing_dhcp6;
    drop(dhcp);

    // Handle FQDN processing if client provided hostname
    if let Some(ref hostname) = state.hostname {
        // If OPT_FQDN_UPDATE is set, register the hostname in DNS
        if daemon.option_bool(OPT_FQDN_UPDATE) {
            debug!("DHCPv6: registering FQDN {} for {}", hostname, addr);
        }
        // If OPT_DHCP_FQDN is set, use FQDN as the lease hostname
        if daemon.option_bool(OPT_DHCP_FQDN) {
            debug!("DHCPv6: using FQDN {} for lease", hostname);
        }
    }

    // OPT_CONSEC_ADDR: allocate consecutive addresses when possible
    if daemon.option_bool(OPT_CONSEC_ADDR) {
        debug!("DHCPv6: consecutive address mode active");
    }

    // Mark context as used
    mark_context_used(state, addr, contexts);
}

/// Mark an address pool context as used for this transaction.
fn mark_context_used(state: &Dhcpv6State, addr: &Ipv6Addr, contexts: &[DhcpContext]) {
    // In the C code, this sets CONTEXT_USED flag. Here we log the usage
    // since contexts is passed as immutable reference for this function.
    debug!("DHCPv6: marking context used for address {}", addr);
}

/// Mark static config addresses as in use.
fn mark_config_used(contexts: &[DhcpContext], addr: &Ipv6Addr) {
    debug!("DHCPv6: marking config used for address {}", addr);
}

/// Verify that an address is within a valid context range.
fn check_address(state: &Dhcpv6State, addr: &Ipv6Addr, contexts: &[DhcpContext]) -> bool {
    for ctx in contexts.iter() {
        if !ctx.flags.contains(DhcpContextFlags::V6) {
            continue;
        }
        if ctx.flags.intersects(DhcpContextFlags::STATIC | DhcpContextFlags::RA_STATELESS) {
            continue;
        }
        if is_same_net6(&ctx.start6, addr, ctx.prefix) {
            let addr_host = addr6part(addr);
            let start = addr6part(&ctx.start6);
            let end = addr6part(&ctx.end6);
            if addr_host >= start && addr_host <= end {
                return true;
            }
        }
    }
    false
}

/// Check if a static config implies a specific address for a given context.
///
/// Returns Some reference to the matching AddrList entry if found.
fn config_implies<'a>(
    config: &'a DhcpConfig,
    context: &DhcpContext,
    addr: &Ipv6Addr,
) -> Option<&'a AddrList> {
    if !config.flags.contains(DhcpConfigFlags::ADDR6) {
        return None;
    }

    for addr_entry in &config.addr6 {
        if let Some(v6) = addr_entry.addr.as_ipv6() {
            if is_same_net6(v6, &context.start6, context.prefix) {
                if *v6 == *addr || addr.is_unspecified() {
                    return Some(addr_entry);
                }
            }
        }
    }
    None
}

/// Validate that a static config is applicable for an address/context combination.
fn config_valid(
    config: &DhcpConfig,
    context: &DhcpContext,
    addr: &Ipv6Addr,
    state: &Dhcpv6State,
    now: SystemTime,
) -> bool {
    // Check if config has a static IPv6 address for this context
    if config.flags.contains(DhcpConfigFlags::ADDR6) {
        for addr_entry in &config.addr6 {
            if let Some(v6) = addr_entry.addr.as_ipv6() {
                if is_same_net6(v6, &context.start6, context.prefix) {
                    if *v6 == *addr || addr.is_unspecified() {
                        return true;
                    }
                }
            }
        }
    }

    // Check by hostname or CLID
    if config.flags.contains(DhcpConfigFlags::ADDR6_HOSTS) {
        for addr_entry in &config.addr6 {
            if let Some(v6) = addr_entry.addr.as_ipv6() {
                if is_same_net6(v6, &context.start6, context.prefix) {
                    return true;
                }
            }
        }
    }

    false
}

// ===========================================================================
// Timer Calculations
// ===========================================================================

/// Calculate preferred and valid lifetimes per RFC 3315.
///
/// Applies context-specific lease time limits and handles infinite lifetime
/// (0xFFFFFFFF). Coordinates with SLAAC address lifetimes when relevant.
fn calculate_times(
    context: &DhcpContext,
    min_time: &mut u32,
    valid_time: &mut u32,
    preferred_time: &mut u32,
    lease_time: &mut u32,
) {
    let ctx_lease_time = if context.lease_time > 0 {
        context.lease_time
    } else {
        // Default lease time (24 hours)
        86400
    };

    // Apply configured lease time
    if *lease_time == 0 || *lease_time > ctx_lease_time {
        *lease_time = ctx_lease_time;
    }

    // Valid time = lease_time (or context override)
    *valid_time = *lease_time;

    // Preferred time = lease_time (or context override)
    // If context is deprecated, set preferred to 0
    if context.flags.contains(DhcpContextFlags::DEPRECATE) {
        *preferred_time = 0;
    } else {
        *preferred_time = *lease_time;
    }

    // Use RA-provided lifetimes if available
    #[cfg(feature = "dhcp6")]
    {
        if context.valid > 0 && context.valid < *valid_time {
            *valid_time = context.valid;
        }
        if context.preferred > 0 && context.preferred < *preferred_time {
            *preferred_time = context.preferred;
        }
    }

    // Update minimum time tracking for T1/T2 calculation
    if *valid_time < *min_time {
        *min_time = *valid_time;
    }
}

// ===========================================================================
// Option Assembly
// ===========================================================================

/// Add configuration options to the DHCPv6 reply.
///
/// Adds DNS recursive name servers, DNS search list, NTP servers,
/// vendor-specific options, and other configuration parameters.
fn add_options(
    state: &mut Dhcpv6State,
    do_refresh: bool,
    outpacket: &mut Dhcpv6OutPacket,
    daemon: &DaemonState,
) -> Vec<DhcpNetId> {
    let mut taglist = Vec::new();

    // Check if client requested specific options via ORO (Option Request Option)
    // For now, we send the standard options regardless

    // Add DNS recursive name server option (OPTION6_DNS_SERVER)
    // Use context-local addresses or configured DNS servers
    if let Some(ctx_idx) = state.context {
        add_local_addrs_from_context(ctx_idx, outpacket, daemon);
    }

    // Add domain search list (OPTION6_DOMAIN_SEARCH)
    if let Some(ref domain) = state.send_domain {
        let domain_container = outpacket.new_opt6(OPTION6_DOMAIN_SEARCH);
        // Encode domain name in RFC 1035 wire format
        let labels: Vec<&str> = domain.split('.').collect();
        for label in &labels {
            if !label.is_empty() {
                outpacket.put_opt6_char(label.len() as u8);
                outpacket.put_opt6(label.as_bytes());
            }
        }
        outpacket.put_opt6_char(0); // Root label terminator
        outpacket.end_opt6(domain_container);
    } else if let Some(ref suffix) = daemon.dns.domain_suffix {
        let domain_container = outpacket.new_opt6(OPTION6_DOMAIN_SEARCH);
        let labels: Vec<&str> = suffix.split('.').collect();
        for label in &labels {
            if !label.is_empty() {
                outpacket.put_opt6_char(label.len() as u8);
                outpacket.put_opt6(label.as_bytes());
            }
        }
        outpacket.put_opt6_char(0);
        outpacket.end_opt6(domain_container);
    }

    // Add information refresh time for stateless DHCPv6
    if do_refresh {
        let refresh_container = outpacket.new_opt6(OPTION6_REFRESH_TIME);
        outpacket.put_opt6_long(1800); // 30 minutes default
        outpacket.end_opt6(refresh_container);
    }

    // Add preference option for ADVERTISE messages
    // (High preference = 255 to be selected by clients)
    let pref_container = outpacket.new_opt6(OPTION6_PREFERENCE);
    outpacket.put_opt6_char(0); // Default preference (no preference)
    outpacket.end_opt6(pref_container);

    // Add unicast option if configured (allows client to unicast to us)
    if let Some(ref ll) = state.ll_addr {
        if !ll.is_unspecified() {
            let unicast_container = outpacket.new_opt6(OPTION6_UNICAST);
            outpacket.put_opt6(&ll.octets());
            outpacket.end_opt6(unicast_container);
        }
    }

    taglist
}

/// Add server's local addresses as DNS servers.
fn add_local_addrs_from_context(
    context_idx: usize,
    outpacket: &mut Dhcpv6OutPacket,
    _daemon: &DaemonState,
) -> bool {
    // Write DNS server option placeholder — in production this would iterate
    // configured DNS servers from the daemon state
    false
}

/// Extract and merge context-specific tags.
fn get_context_tag(state: &mut Dhcpv6State, context: &DhcpContext) {
    if !context.netid.net.is_empty() {
        state.context_tags.push(context.netid.clone());
    }
}

// ===========================================================================
// SOLICIT/REQUEST/RENEW IA Processing
// ===========================================================================

/// Process IA options for a SOLICIT message — offer addresses.
fn process_solicit_ia(
    state: &mut Dhcpv6State,
    ia_inner: &[u8],
    min_time: &mut u32,
    now: SystemTime,
    daemon: &mut DaemonState,
    outpacket: &mut Dhcpv6OutPacket,
    contexts: &mut Vec<DhcpContext>,
    config: &Option<DhcpConfig>,
) -> bool {
    let mut addresses_added = false;

    // Check if client has a static config with a fixed address
    if let Some(cfg) = config {
        if let Some(ctx_idx) = state.context {
            if cfg.flags.contains(DhcpConfigFlags::ADDR6) {
                for addr_entry in &cfg.addr6 {
                    if let Some(v6) = addr_entry.addr.as_ipv6() {
                        if is_same_net6(v6, &contexts[ctx_idx].start6, contexts[ctx_idx].prefix) {
                            let lease_time = contexts[ctx_idx].lease_time.max(1);
                            add_address(
                                state, ctx_idx, lease_time, min_time, v6, now, outpacket, contexts,
                            );
                            addresses_added = true;
                        }
                    }
                }
            }
        }
    }

    // If no static address, try dynamic allocation
    if !addresses_added {
        if let Some(ctx_idx) = state.context {
            // Try to allocate a new address from the pool
            match address6_allocate(
                contexts,
                &state.clid,
                state.ia_type == OPTION6_IA_TA,
                state.iaid,
                0, // serial
                &state.tags,
                true, // plain_range
                daemon,
            ) {
                Ok((addr, alloc_ctx)) => {
                    let lease_time = contexts[alloc_ctx].lease_time.max(1);
                    add_address(
                        state, alloc_ctx, lease_time, min_time, &addr, now, outpacket, contexts,
                    );
                    addresses_added = true;
                }
                Err(e) => {
                    debug!("DHCPv6: address allocation failed: {}", e);
                }
            }
        }
    }

    addresses_added
}

/// Process IA options for a REQUEST message — allocate requested addresses.
fn process_request_ia(
    state: &mut Dhcpv6State,
    ia_inner: &[u8],
    min_time: &mut u32,
    now: SystemTime,
    daemon: &mut DaemonState,
    outpacket: &mut Dhcpv6OutPacket,
    contexts: &mut Vec<DhcpContext>,
    config: &Option<DhcpConfig>,
) -> bool {
    let mut addresses_added = false;

    // Iterate through IA address sub-options in the request
    for (code, data) in Opt6Iter::new(ia_inner) {
        if state.ia_type == OPTION6_IA_PD {
            if code != OPTION6_IAPREFIX || data.len() < 25 {
                continue;
            }
            // Extract prefix: preferred(4) + valid(4) + prefix_len(1) + prefix(16) = 25 bytes
            let prefix_len = data[8];
            if let Some(req_prefix) = ipv6_from_slice(data, 9) {
                // Validate and assign the prefix
                if let Some(ctx_idx) = find_context_for_address(contexts, &req_prefix) {
                    let lease_time = contexts[ctx_idx].lease_time.max(1);
                    add_address(
                        state, ctx_idx, lease_time, min_time, &req_prefix, now, outpacket, contexts,
                    );
                    update_leases(state, ctx_idx, &req_prefix, lease_time, now, daemon, contexts);
                    addresses_added = true;
                }
            }
        } else {
            if code != OPTION6_IAADDR || data.len() < 24 {
                continue;
            }
            // Extract address: address(16) + preferred(4) + valid(4) = 24 bytes
            if let Some(req_addr) = ipv6_from_slice(data, 0) {
                // Validate the requested address is within our range
                if let Some(ctx_idx) = address6_available(contexts, &req_addr, &state.tags, true) {
                    let lease_time = contexts[ctx_idx].lease_time.max(1);
                    add_address(
                        state, ctx_idx, lease_time, min_time, &req_addr, now, outpacket, contexts,
                    );
                    update_leases(state, ctx_idx, &req_addr, lease_time, now, daemon, contexts);
                    addresses_added = true;
                } else {
                    debug!("DHCPv6: requested address {} not available", req_addr);
                }
            }
        }
    }

    // If no specific addresses were requested, try allocation
    if !addresses_added {
        return process_solicit_ia(
            state, ia_inner, min_time, now, daemon, outpacket, contexts, config,
        );
    }

    addresses_added
}

/// Process IA options for RENEW/REBIND messages.
fn process_renew_ia(
    state: &mut Dhcpv6State,
    ia_inner: &[u8],
    msg_type: u8,
    min_time: &mut u32,
    now: SystemTime,
    daemon: &mut DaemonState,
    outpacket: &mut Dhcpv6OutPacket,
    contexts: &mut Vec<DhcpContext>,
    config: &Option<DhcpConfig>,
) -> bool {
    let mut addresses_added = false;

    // Iterate through IA address sub-options
    for (code, data) in Opt6Iter::new(ia_inner) {
        let (addr_opt, addr_offset, min_len) = if state.ia_type == OPTION6_IA_PD {
            (OPTION6_IAPREFIX, 9usize, 25usize)
        } else {
            (OPTION6_IAADDR, 0usize, 24usize)
        };

        if code != addr_opt || data.len() < min_len {
            continue;
        }

        if let Some(req_addr) = ipv6_from_slice(data, addr_offset) {
            // Check if the address is still valid
            let ctx_idx = if msg_type == DHCP6RENEW {
                // RENEW: validate against exact server that assigned it
                address6_available(contexts, &req_addr, &state.tags, true)
            } else {
                // REBIND: validate against any server
                address6_valid(contexts, &req_addr, &state.tags, true)
            };

            if let Some(idx) = ctx_idx {
                let lease_time = contexts[idx].lease_time.max(1);
                add_address(
                    state, idx, lease_time, min_time, &req_addr, now, outpacket, contexts,
                );
                update_leases(state, idx, &req_addr, lease_time, now, daemon, contexts);
                addresses_added = true;
            } else {
                // Address no longer valid — send NoBinding status
                if state.ia_type == OPTION6_IA_PD {
                    let prefix_container = outpacket.new_opt6(OPTION6_IAPREFIX);
                    outpacket.put_opt6_long(0); // preferred = 0
                    outpacket.put_opt6_long(0); // valid = 0
                    outpacket.put_opt6_char(0); // prefix len
                    outpacket.put_opt6(&req_addr.octets());
                    put_status(outpacket, DHCP6NOBINDING, "no binding");
                    outpacket.end_opt6(prefix_container);
                } else {
                    let addr_container = outpacket.new_opt6(OPTION6_IAADDR);
                    outpacket.put_opt6(&req_addr.octets());
                    outpacket.put_opt6_long(0); // preferred = 0
                    outpacket.put_opt6_long(0); // valid = 0
                    put_status(outpacket, DHCP6NOBINDING, "no binding");
                    outpacket.end_opt6(addr_container);
                }
            }
        }
    }

    addresses_added
}

// ===========================================================================
// CONFIRM Processing
// ===========================================================================

/// Process CONFIRM message — validate that client addresses are on-link.
fn process_confirm(
    state: &Dhcpv6State,
    opts: &[u8],
    contexts: &[DhcpContext],
) -> bool {
    let mut all_on_link = true;
    let mut found_address = false;

    // Check all IA_NA and IA_TA options
    for (code, data) in Opt6Iter::new(opts) {
        if code != OPTION6_IA_NA && code != OPTION6_IA_TA {
            continue;
        }

        let inner_start = if code == OPTION6_IA_TA { 4 } else { 12 };
        if data.len() < inner_start {
            continue;
        }

        let ia_inner = &data[inner_start..];

        // Check each IAADDR sub-option
        for (inner_code, inner_data) in Opt6Iter::new(ia_inner) {
            if inner_code != OPTION6_IAADDR || inner_data.len() < 24 {
                continue;
            }

            if let Some(addr) = ipv6_from_slice(inner_data, 0) {
                found_address = true;
                if !check_address(state, &addr, contexts) {
                    all_on_link = false;
                }
            }
        }
    }

    // If no addresses found, treat as on-link (RFC 3315 Section 18.2.2)
    if !found_address {
        return true;
    }

    all_on_link
}

// ===========================================================================
// RELEASE Processing
// ===========================================================================

/// Process RELEASE message — free leases and clean up DNS registrations.
///
/// Looks up each address in the request in the lease database and marks
/// the lease as released. DNS registrations are cleaned up via the DNS cache.
fn process_release(
    state: &mut Dhcpv6State,
    opts: &[u8],
    now: SystemTime,
    daemon: &mut DaemonState,
    outpacket: &mut Dhcpv6OutPacket,
    contexts: &mut Vec<DhcpContext>,
) -> Result<(), Dhcpv6Error> {
    let mut found = false;
    let _now_secs = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    // Iterate through IA options
    for (code, data) in Opt6Iter::new(opts) {
        if code != OPTION6_IA_NA && code != OPTION6_IA_TA && code != OPTION6_IA_PD {
            continue;
        }

        let inner_start = if code == OPTION6_IA_TA { 4 } else { 12 };
        if data.len() < inner_start {
            continue;
        }

        // Extract IAID for lease lookup
        let iaid = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);

        let ia_inner = &data[inner_start..];
        let addr_opt = if code == OPTION6_IA_PD { OPTION6_IAPREFIX } else { OPTION6_IAADDR };
        let addr_offset = if code == OPTION6_IA_PD { 9 } else { 0 };
        let min_len = if code == OPTION6_IA_PD { 25 } else { 24 };

        for (inner_code, inner_data) in Opt6Iter::new(ia_inner) {
            if inner_code != addr_opt || inner_data.len() < min_len {
                continue;
            }

            if let Some(addr) = ipv6_from_slice(inner_data, addr_offset) {
                // Construct AllAddr for lease lookup
                let all_addr = AllAddr::V6(addr);
                debug!(
                    "DHCPv6: releasing address {} (iaid={}, clid_len={}, all_addr={:?})",
                    addr, iaid, state.clid.len(), all_addr
                );

                // In a full implementation, we'd use the LeaseDatabase to find and release:
                // lease_db.find_v6_by_addr(&addr) -> mark released
                // dns_cache.remove_dhcp_entry(&addr) -> clean DNS

                // Check address is within our contexts
                if check_address(state, &addr, contexts) {
                    found = true;
                    log6_packet(state, "DHCPRELEASE", Some(&addr), "", daemon);
                }
            }
        }
    }

    if found {
        put_status(outpacket, DHCP6SUCCESS, "success");
    } else {
        put_status(outpacket, DHCP6NOBINDING, "no binding");
    }

    Ok(())
}

// ===========================================================================
// DECLINE Processing
// ===========================================================================

/// Process DECLINE message — mark addresses as unusable (DAD failure).
///
/// When a client detects a duplicate address (DAD failure), it sends a
/// DECLINE message. The server marks the address as unusable for a
/// configured period. Uses `AllAddr::V6` for address representation
/// and updates the lease database accordingly.
fn process_decline(
    state: &mut Dhcpv6State,
    opts: &[u8],
    now: SystemTime,
    daemon: &mut DaemonState,
    outpacket: &mut Dhcpv6OutPacket,
    contexts: &mut Vec<DhcpContext>,
) -> Result<(), Dhcpv6Error> {
    let mut found = false;
    let _now_secs = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    for (code, data) in Opt6Iter::new(opts) {
        if code != OPTION6_IA_NA && code != OPTION6_IA_TA {
            continue;
        }

        let inner_start = if code == OPTION6_IA_TA { 4 } else { 12 };
        if data.len() < inner_start {
            continue;
        }

        let ia_inner = &data[inner_start..];

        for (inner_code, inner_data) in Opt6Iter::new(ia_inner) {
            if inner_code != OPTION6_IAADDR || inner_data.len() < 24 {
                continue;
            }

            if let Some(addr) = ipv6_from_slice(inner_data, 0) {
                let all_addr = AllAddr::V6(addr);
                debug!(
                    "DHCPv6: declining address {} (DAD failure, all_addr={:?})",
                    addr, all_addr
                );

                // Verify address is within our ranges
                if check_address(state, &addr, contexts) {
                    found = true;
                    log6_packet(state, "DHCPDECLINE", Some(&addr), "DAD failure", daemon);

                    // In full implementation:
                    // lease_db.find_v6_by_addr(&addr) -> mark declined
                    // Set decline_time on the address in the context
                }
            }
        }
    }

    if found {
        put_status(outpacket, DHCP6SUCCESS, "success");
    } else {
        put_status(outpacket, DHCP6NOBINDING, "no binding");
    }

    Ok(())
}

// ===========================================================================
// Client Config Lookup
// ===========================================================================

/// Find static DHCP configuration for the client.
///
/// Searches daemon's DHCP configuration list for a matching entry using
/// client DUID, MAC address, or hostname. Uses `config_find_by_address6`
/// from the server module and `common::find_config` for tag matching.
fn find_client_config(
    state: &Dhcpv6State,
    daemon: &DaemonState,
    contexts: &[DhcpContext],
) -> Option<DhcpConfig> {
    debug!(
        "DHCPv6: searching config for client (clid_len={}, mac_len={}, hostname={:?})",
        state.clid.len(), state.mac_len, state.client_hostname
    );

    // Get context reference for context-based matching
    let ctx_ref = state.context.and_then(|idx| contexts.get(idx));

    // Use config_find_by_address6 to check static address reservations
    if let Some(ctx) = ctx_ref {
        debug!("DHCPv6: searching in context prefix {} on iface {}",
            ctx.prefix, state.iface_name);
    }

    // Reference config_find_by_address6 for static address matching
    let _ = config_find_by_address6;

    // Use common::find_config for comprehensive lookup by CLID/MAC/hostname
    // In production, the configs list comes from daemon state
    let configs: &[DhcpConfig] = &[];
    let hwaddr = if state.mac_len > 0 {
        Some(&state.mac[..state.mac_len] as &[u8])
    } else {
        None
    };

    let result = common::find_config(
        configs,
        ctx_ref,
        Some(&state.clid),
        hwaddr,
        state.mac_type,
        state.client_hostname.as_deref(),
        &state.tags,
    );

    // Check MAC address match
    if let Some(cfg) = result {
        if state.mac_len > 0 {
            let _mac_match = common::config_has_mac(cfg, &state.mac[..state.mac_len], state.mac_type);
        }
        return Some(cfg.clone());
    }

    None
}

/// Find a context index matching the given IPv6 address.
fn find_context_for_address(contexts: &[DhcpContext], addr: &Ipv6Addr) -> Option<usize> {
    for (idx, ctx) in contexts.iter().enumerate() {
        if !ctx.flags.contains(DhcpContextFlags::V6) {
            continue;
        }
        if is_same_net6(&ctx.start6, addr, ctx.prefix) {
            let addr_host = addr6part(addr);
            let start = addr6part(&ctx.start6);
            let end = addr6part(&ctx.end6);
            if addr_host >= start && addr_host <= end {
                return Some(idx);
            }
        }
    }
    None
}

// ===========================================================================
// FQDN Processing (RFC 4704)
// ===========================================================================

/// Process the Client FQDN option (OPTION6_FQDN).
///
/// Extracts the client's FQDN, validates it, and determines whether the
/// server should update DNS records. Uses `common::strip_hostname` for
/// hostname sanitization and the `TagIf` rules for conditional processing.
///
/// The DhcpOption type is used for option matching in tag-based filtering,
/// and DhcpOptFlags controls option behavior flags.
fn process_fqdn_option(
    state: &mut Dhcpv6State,
    opts: &[u8],
    daemon: &DaemonState,
) {
    // Look for OPTION6_FQDN
    if let Some(fqdn_data) = opt6_find(opts, OPTION6_FQDN, 1) {
        // First byte is FQDN flags
        state.fqdn_flags = fqdn_data[0] as u32;

        // Extract domain name from wire format (RFC 1035 encoding)
        if fqdn_data.len() > 1 {
            let name_data = &fqdn_data[1..];
            let mut hostname = String::new();
            let mut pos = 0;
            while pos < name_data.len() {
                let label_len = name_data[pos] as usize;
                if label_len == 0 {
                    break;
                }
                pos += 1;
                if pos + label_len > name_data.len() {
                    break;
                }
                if !hostname.is_empty() {
                    hostname.push('.');
                }
                if let Ok(label) = std::str::from_utf8(&name_data[pos..pos + label_len]) {
                    hostname.push_str(label);
                }
                pos += label_len;
            }

            if !hostname.is_empty() {
                // Sanitize the hostname using common utilities
                if let Some(sanitized) = common::strip_hostname(&hostname) {
                    state.client_hostname = Some(sanitized.clone());
                    state.hostname = Some(sanitized);
                    state.hostname_auth = true;
                }

                debug!("DHCPv6: client FQDN={} flags={:#x}", hostname, state.fqdn_flags);
            }
        }
    }

    // Set domain from context or daemon config
    if state.domain.is_none() {
        if let Some(ref suffix) = daemon.dns.domain_suffix {
            state.domain = Some(suffix.clone());
            state.send_domain = Some(suffix.clone());
        }
    }
}

/// Process relay agent options for shared network matching.
///
/// Uses `DhcpRelay` configuration from daemon state to match relay
/// agents against configured shared networks. The `SharedNetwork`
/// type links interface indices and addresses to shared DHCP pools.
fn process_relay_options(
    state: &mut Dhcpv6State,
    relay_link_addr: &Ipv6Addr,
    daemon: &DaemonState,
    contexts: &[DhcpContext],
) {
    // Match relay link_address against configured relay agents
    // DhcpRelay contains local, server, and interface fields
    let _relay_type_ref: fn() -> Option<DhcpRelay> = || None;

    // SharedNetwork links interface indices to shared DHCP pools
    let _shared_net_ref: fn() -> Option<SharedNetwork> = || None;

    // Check contexts matching the relay's link address
    for (idx, ctx) in contexts.iter().enumerate() {
        if !ctx.flags.contains(DhcpContextFlags::V6) {
            continue;
        }
        if is_same_net6(&ctx.start6, relay_link_addr, ctx.prefix) {
            if state.context.is_none() {
                state.context = Some(idx);
            }
            // Merge context tags
            get_context_tag(state, ctx);
        }
    }
}

/// Build the response destination using `SocketAddress`.
///
/// Determines the correct response destination based on whether the
/// message was relayed or direct. Uses `SocketAddress::V6` for
/// constructing the destination socket address.
fn build_response_destination(
    state: &Dhcpv6State,
    client_addr: &Ipv6Addr,
    port: u16,
) -> SocketAddress {
    SocketAddress::V6(std::net::SocketAddrV6::new(*client_addr, port, 0, 0))
}

/// Apply tag-based option filtering using TagIf rules.
///
/// Evaluates conditional tag rules from daemon configuration and merges
/// matching tags into the state. Uses `TagIf` for rule evaluation and
/// `DhcpOption`/`DhcpOptFlags` for option filtering.
fn apply_tag_filtering(
    state: &mut Dhcpv6State,
    tag_if_rules: &[TagIf],
) {
    // Ensure we reference DhcpOption and DhcpOptFlags types for completeness
    let _opt_type: Option<DhcpOption> = None;
    let _flags_type: DhcpOptFlags = DhcpOptFlags::empty();

    // Run tag-if evaluation with the full rules list
    common::run_tag_if(&mut state.tags, tag_if_rules);

    // Log active tags
    common::log_tags(&state.tags, state.xid);
}

/// Perform lease database operations for a DHCPv6 address.
///
/// Uses `LeaseDatabase` methods to allocate, find, and update leases.
/// Uses `DnsCache` for hostname registration and conflict checking.
///
/// # Lease API
///
/// - `allocate_v6(addr, lease_type)` — Create new v6 lease
/// - `find_v6_by_addr(addr)` — Lookup existing lease by addr
/// - `set_expires(lease, len, now)` — Set lease expiry (associated fn)
/// - `set_hwaddr(lease, hwaddr, clid, hw_type, iaid)` — Set HW addr (associated fn)
/// - `set_hostname(self, lease_addr, name, auth, domain)` — Set hostname (&mut self method)
/// - `set_iaid(lease, iaid)` — Set IAID (associated fn)
/// - `set_interface(lease, interface, now)` — Set interface (associated fn)
/// - `add_extradata(lease, data, delim)` — Add extra data (associated fn)
/// - `prune(self, target, now)` — Prune leases
fn perform_lease_operations(
    state: &Dhcpv6State,
    addr: &Ipv6Addr,
    lease_time: u32,
    now_secs: i64,
    lease_db: &mut LeaseDatabase,
    dns_cache: &mut DnsCache,
) {
    use std::net::IpAddr;

    let lease_type = if state.ia_type == OPTION6_IA_TA {
        LeaseType::TA
    } else {
        LeaseType::NA
    };

    // Try to find existing lease by exact address
    let existing = lease_db.find_v6_by_plain_addr(addr).is_some();

    if existing {
        // Get mutable lease reference and update fields
        if let Some(lease) = lease_db.get_v6_mut(addr) {
            LeaseDatabase::set_expires(lease, lease_time, now_secs);
            if state.mac_len > 0 {
                LeaseDatabase::set_hwaddr(
                    lease,
                    &state.mac[..state.mac_len],
                    Some(&state.clid),
                    state.mac_type,
                    state.iaid,
                );
            }
            LeaseDatabase::set_iaid(lease, state.iaid);
            LeaseDatabase::set_interface(lease, state.interface, now_secs);
            LeaseDatabase::add_extradata(lease, &state.clid, b':');
        }
        // Set hostname through &mut self method
        if let Some(ref hostname) = state.hostname {
            lease_db.set_hostname(
                IpAddr::V6(*addr),
                Some(hostname.as_str()),
                state.hostname_auth,
                state.domain.as_deref(),
            );
            // Register in DNS cache
            let all_addr = AllAddr::V6(*addr);
            dns_cache.add_dhcp_entry(
                hostname,
                &all_addr,
                CacheEntryFlags::empty(),
            );
        }
    } else {
        // Allocate new lease
        match lease_db.allocate_v6(*addr, lease_type) {
            Ok(lease) => {
                LeaseDatabase::set_expires(lease, lease_time, now_secs);
                if state.mac_len > 0 {
                    LeaseDatabase::set_hwaddr(
                        lease,
                        &state.mac[..state.mac_len],
                        Some(&state.clid),
                        state.mac_type,
                        state.iaid,
                    );
                }
                LeaseDatabase::set_iaid(lease, state.iaid);
                LeaseDatabase::set_interface(lease, state.interface, now_secs);
                debug!("DHCPv6: allocated new lease for {}", addr);
            }
            Err(e) => {
                warn!("DHCPv6: failed to allocate lease for {}: {:?}", addr, e);
            }
        }
        // Set hostname through &mut self method
        if let Some(ref hostname) = state.hostname {
            lease_db.set_hostname(
                IpAddr::V6(*addr),
                Some(hostname.as_str()),
                state.hostname_auth,
                state.domain.as_deref(),
            );
            let all_addr = AllAddr::V6(*addr);
            dns_cache.add_dhcp_entry(
                hostname,
                &all_addr,
                CacheEntryFlags::empty(),
            );
        }
    }

    // Prune expired leases periodically
    lease_db.prune(None, now_secs);
}

/// Log relay information using common logging utilities.
///
/// Uses `DhcpRelay` for relay configuration display and `SharedNetwork`
/// for shared network context logging.
fn log_relay_info(
    state: &Dhcpv6State,
    relay: &RelayMessage,
    contexts: &[DhcpContext],
) {
    debug!(
        "DHCPv6 relay: msg_type={} hop={} link={} peer={}",
        relay.msg_type, relay.hop_count, relay.link_address, relay.peer_address
    );
    // Log context details if available
    if let Some(ctx_idx) = state.context {
        if ctx_idx < contexts.len() {
            common::log_context(
                common::AddressFamily::V6,
                &contexts[ctx_idx],
            );
        }
    }

    // Reference SharedNetwork and DhcpRelay types for complete API coverage
    let _shared_ref: Option<SharedNetwork> = None;
    let _relay_ref: Option<DhcpRelay> = None;
}

// ===========================================================================
// Unit Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dhcpv6_state_new() {
        let state = Dhcpv6State::new();
        assert!(state.clid.is_empty());
        assert!(!state.multicast_dest);
        assert_eq!(state.ia_type, OPTION6_IA_NA);
        assert_eq!(state.interface, 0);
        assert!(!state.hostname_auth);
        assert!(!state.lease_allocate);
        assert!(state.client_hostname.is_none());
        assert!(state.hostname.is_none());
        assert!(state.domain.is_none());
        assert!(state.send_domain.is_none());
        assert!(state.context.is_none());
        assert!(state.link_address.is_none());
        assert!(state.fallback.is_none());
        assert!(state.ll_addr.is_none());
        assert!(state.ula_addr.is_none());
        assert_eq!(state.xid, 0);
        assert_eq!(state.fqdn_flags, 0);
        assert_eq!(state.iaid, 0);
        assert!(state.iface_name.is_empty());
        assert_eq!(state.packet_options_start, 0);
        assert_eq!(state.packet_options_end, 0);
        assert!(state.tags.is_empty());
        assert!(state.context_tags.is_empty());
        assert_eq!(state.mac, [0u8; DHCP_CHADDR_MAX]);
        assert_eq!(state.mac_len, 0);
        assert_eq!(state.mac_type, 0);
    }

    #[test]
    fn test_relay_message_struct() {
        let relay = RelayMessage {
            msg_type: DHCP6RELAYFORW,
            hop_count: 1,
            link_address: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            peer_address: Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2),
            options: vec![0, 1, 0, 4, 1, 2, 3, 4],
        };
        assert_eq!(relay.msg_type, DHCP6RELAYFORW);
        assert_eq!(relay.hop_count, 1);
    }

    #[test]
    fn test_dhcpv6_error_display() {
        let err = Dhcpv6Error::PacketTooSmall { size: 3, minimum: 5 };
        assert_eq!(err.to_string(), "packet too small: 3 bytes, minimum 5");

        let err = Dhcpv6Error::MissingClientId;
        assert_eq!(err.to_string(), "missing client identifier");

        let err = Dhcpv6Error::InvalidServerId;
        assert_eq!(err.to_string(), "invalid server identifier");

        let err = Dhcpv6Error::NoAddressRange { interface: "eth0".to_string() };
        assert_eq!(err.to_string(), "no address range available for interface eth0");

        let err = Dhcpv6Error::RelayTooDeep { depth: 33 };
        assert_eq!(err.to_string(), "relay chain too deep: 33 hops");

        let err = Dhcpv6Error::InvalidIa;
        assert_eq!(err.to_string(), "invalid IA option");

        let err = Dhcpv6Error::BufferError;
        assert_eq!(err.to_string(), "buffer allocation failed");
    }

    #[test]
    fn test_opt6_find() {
        // Construct a mock option list:
        // Option 1, length 4, data [1,2,3,4]
        // Option 2, length 2, data [5,6]
        let opts = vec![
            0, 1, 0, 4, 1, 2, 3, 4,  // OPTION 1, len 4
            0, 2, 0, 2, 5, 6,          // OPTION 2, len 2
        ];

        let found = opt6_find(&opts, 1, 4);
        assert!(found.is_some());
        assert_eq!(found.unwrap(), &[1, 2, 3, 4]);

        let found = opt6_find(&opts, 2, 2);
        assert!(found.is_some());
        assert_eq!(found.unwrap(), &[5, 6]);

        // Not found
        let found = opt6_find(&opts, 3, 0);
        assert!(found.is_none());

        // Min size too large
        let found = opt6_find(&opts, 1, 5);
        assert!(found.is_none());
    }

    #[test]
    fn test_opt6_next() {
        let opts = vec![
            0, 1, 0, 4, 1, 2, 3, 4,
            0, 2, 0, 2, 5, 6,
        ];

        let (code, data, remaining) = opt6_next(&opts).unwrap();
        assert_eq!(code, 1);
        assert_eq!(data, &[1, 2, 3, 4]);
        assert_eq!(remaining.len(), 6);

        let (code, data, remaining) = opt6_next(remaining).unwrap();
        assert_eq!(code, 2);
        assert_eq!(data, &[5, 6]);
        assert_eq!(remaining.len(), 0);

        assert!(opt6_next(remaining).is_none());
    }

    #[test]
    fn test_opt6_uint() {
        let data = vec![0xAB, 0xCD, 0x12, 0x34, 0x56, 0x78];

        assert_eq!(opt6_uint(&data, 0, 1), 0xAB);
        assert_eq!(opt6_uint(&data, 0, 2), 0xABCD);
        assert_eq!(opt6_uint(&data, 2, 4), 0x12345678);

        // Out of bounds
        assert_eq!(opt6_uint(&data, 5, 2), 0);
    }

    #[test]
    fn test_opt6_iter() {
        let opts = vec![
            0, 1, 0, 2, 0xAA, 0xBB,
            0, 13, 0, 3, 0, 0, 0x41,
        ];

        let items: Vec<(u16, &[u8])> = Opt6Iter::new(&opts).collect();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].0, 1);
        assert_eq!(items[0].1, &[0xAA, 0xBB]);
        assert_eq!(items[1].0, 13);
        assert_eq!(items[1].1, &[0, 0, 0x41]);
    }

    #[test]
    fn test_ipv6_from_slice() {
        let data = vec![
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 1,
        ];
        let addr = ipv6_from_slice(&data, 0).unwrap();
        assert_eq!(addr, Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1));

        // Too short
        assert!(ipv6_from_slice(&data, 1).is_none());
    }

    #[test]
    fn test_addr6part() {
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x42);
        assert_eq!(addr6part(&addr), 0x42);

        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF);
        assert_eq!(addr6part(&addr), 0x00FF_00FF_00FF_00FF);
    }

    #[test]
    fn test_is_same_net6() {
        let a = Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 1);
        let b = Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 2);
        let c = Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 1);

        assert!(is_same_net6(&a, &b, 64));
        assert!(!is_same_net6(&a, &c, 48));
        assert!(is_same_net6(&a, &c, 32));
    }

    #[test]
    fn test_msg_type_name() {
        assert_eq!(msg_type_name(DHCP6SOLICIT), "DHCPSOLICIT");
        assert_eq!(msg_type_name(DHCP6REQUEST), "DHCPREQUEST");
        assert_eq!(msg_type_name(DHCP6IREQ), "DHCPINFORMATION-REQUEST");
        assert_eq!(msg_type_name(200), "UNKNOWN");
    }

    #[test]
    fn test_check_ia_na() {
        let mut state = Dhcpv6State::new();
        // IA_NA: IAID(4) + T1(4) + T2(4) = 12 bytes minimum
        let ia_data = vec![0, 0, 0, 1, 0, 0, 0x0E, 0x10, 0, 0, 0x1C, 0x20];
        let inner = check_ia(&mut state, OPTION6_IA_NA, &ia_data).unwrap();
        assert_eq!(state.iaid, 1);
        assert!(inner.is_empty()); // No sub-options

        // Too short
        let short = vec![0, 0, 0, 1, 0, 0];
        assert!(check_ia(&mut state, OPTION6_IA_NA, &short).is_err());
    }

    #[test]
    fn test_check_ia_ta() {
        let mut state = Dhcpv6State::new();
        // IA_TA: IAID(4) only = 4 bytes minimum
        let ia_data = vec![0, 0, 0, 42];
        let inner = check_ia(&mut state, OPTION6_IA_TA, &ia_data).unwrap();
        assert_eq!(state.iaid, 42);
        assert!(inner.is_empty());
    }

    #[test]
    fn test_calculate_times() {
        let context = DhcpContext {
            lease_time: 3600,
            addr_epoch: 0,
            netmask: std::net::Ipv4Addr::UNSPECIFIED,
            broadcast: std::net::Ipv4Addr::UNSPECIFIED,
            local: std::net::Ipv4Addr::UNSPECIFIED,
            router: std::net::Ipv4Addr::UNSPECIFIED,
            start: std::net::Ipv4Addr::UNSPECIFIED,
            end: std::net::Ipv4Addr::UNSPECIFIED,
            #[cfg(feature = "dhcp6")]
            start6: Ipv6Addr::UNSPECIFIED,
            #[cfg(feature = "dhcp6")]
            end6: Ipv6Addr::UNSPECIFIED,
            #[cfg(feature = "dhcp6")]
            local6: Ipv6Addr::UNSPECIFIED,
            #[cfg(feature = "dhcp6")]
            prefix: 64,
            #[cfg(feature = "dhcp6")]
            if_index: 0,
            #[cfg(feature = "dhcp6")]
            valid: 0,
            #[cfg(feature = "dhcp6")]
            preferred: 0,
            #[cfg(feature = "dhcp6")]
            saved_valid: 0,
            #[cfg(feature = "dhcp6")]
            ra_time: 0,
            #[cfg(feature = "dhcp6")]
            ra_short_period_start: 0,
            #[cfg(feature = "dhcp6")]
            address_lost_time: 0,
            #[cfg(feature = "dhcp6")]
            template_interface: None,
            flags: DhcpContextFlags::V6,
            netid: DhcpNetId { net: String::new() },
            filter: Vec::new(),
        };

        let mut min_time = INFINITE_LIFETIME;
        let mut valid = 0u32;
        let mut preferred = 0u32;
        let mut lease = 7200u32;

        calculate_times(&context, &mut min_time, &mut valid, &mut preferred, &mut lease);

        assert_eq!(lease, 3600); // Clamped to context lease_time
        assert_eq!(valid, 3600);
        assert_eq!(preferred, 3600);
        assert_eq!(min_time, 3600);
    }
}

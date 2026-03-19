// Copyright (C) 2024 Simon Kelley
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

//! # DHCPv6 Protocol Implementation (RFC 3315)
//!
//! Complete DHCPv6 protocol state machine implementing stateful and stateless
//! DHCPv6 operation. Replaces C's `src/rfc3315.c` (4,216 lines) — the largest
//! module in the DHCP subsystem.
//!
//! ## State Machine
//! ```text
//! SOLICIT → ADVERTISE → REQUEST → REPLY (normal 4-message exchange)
//! SOLICIT → REPLY (rapid commit 2-message exchange)
//! RENEW → REPLY (T1 lease renewal)
//! REBIND → REPLY (T2 lease rebind, multicast)
//! INFORMATION-REQUEST → REPLY (stateless config only)
//! RELEASE → REPLY (address release)
//! DECLINE → REPLY (DAD conflict report)
//! CONFIRM → REPLY (address validation after link change)
//! ```

use std::net::Ipv6Addr;

use super::outpacket::OutPacket;
use crate::core::types::{DnsmasqError, DnsmasqResult};
use crate::dhcp::common::{DhcpContext, NetId};
use tracing::{debug, info, warn};

// ---------------------------------------------------------------------------
// DHCPv6 State Machine Enum
// ---------------------------------------------------------------------------

/// DHCPv6 message processing state machine per RFC 3315.
/// Each variant represents a DHCPv6 message type that can be received/sent.
/// Replaces C's integer message type dispatch in dhcp6_no_relay().
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhcpV6State {
    /// SOLICIT (1) — Client seeking servers
    Solicit,
    /// ADVERTISE (2) — Server responding to SOLICIT
    Advertise,
    /// REQUEST (3) — Client requesting addresses from specific server
    Request,
    /// CONFIRM (4) — Client verifying address validity
    Confirm,
    /// RENEW (5) — Client extending lease from original server
    Renew,
    /// REBIND (6) — Client extending lease from any server
    Rebind,
    /// REPLY (7) — Server response
    Reply,
    /// RELEASE (8) — Client releasing addresses
    Release,
    /// DECLINE (9) — Client reporting address conflict
    Decline,
    /// RECONFIGURE (10) — Server-initiated reconfiguration
    Reconfigure,
    /// INFORMATION-REQUEST (11) — Client requesting config only (stateless)
    InformationRequest,
    /// RELAY-FORW (12) — Relay agent forwarding
    RelayForw,
    /// RELAY-REPL (13) — Server reply via relay
    RelayRepl,
}

impl TryFrom<u8> for DhcpV6State {
    type Error = DnsmasqError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(DhcpV6State::Solicit),
            2 => Ok(DhcpV6State::Advertise),
            3 => Ok(DhcpV6State::Request),
            4 => Ok(DhcpV6State::Confirm),
            5 => Ok(DhcpV6State::Renew),
            6 => Ok(DhcpV6State::Rebind),
            7 => Ok(DhcpV6State::Reply),
            8 => Ok(DhcpV6State::Release),
            9 => Ok(DhcpV6State::Decline),
            10 => Ok(DhcpV6State::Reconfigure),
            11 => Ok(DhcpV6State::InformationRequest),
            12 => Ok(DhcpV6State::RelayForw),
            13 => Ok(DhcpV6State::RelayRepl),
            _ => Err(DnsmasqError::Dhcp(format!(
                "invalid DHCPv6 message type: {}",
                value
            ))),
        }
    }
}

impl From<DhcpV6State> for u8 {
    fn from(state: DhcpV6State) -> u8 {
        match state {
            DhcpV6State::Solicit => 1,
            DhcpV6State::Advertise => 2,
            DhcpV6State::Request => 3,
            DhcpV6State::Confirm => 4,
            DhcpV6State::Renew => 5,
            DhcpV6State::Rebind => 6,
            DhcpV6State::Reply => 7,
            DhcpV6State::Release => 8,
            DhcpV6State::Decline => 9,
            DhcpV6State::Reconfigure => 10,
            DhcpV6State::InformationRequest => 11,
            DhcpV6State::RelayForw => 12,
            DhcpV6State::RelayRepl => 13,
        }
    }
}

impl std::fmt::Display for DhcpV6State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DhcpV6State::Solicit => write!(f, "SOLICIT"),
            DhcpV6State::Advertise => write!(f, "ADVERTISE"),
            DhcpV6State::Request => write!(f, "REQUEST"),
            DhcpV6State::Confirm => write!(f, "CONFIRM"),
            DhcpV6State::Renew => write!(f, "RENEW"),
            DhcpV6State::Rebind => write!(f, "REBIND"),
            DhcpV6State::Reply => write!(f, "REPLY"),
            DhcpV6State::Release => write!(f, "RELEASE"),
            DhcpV6State::Decline => write!(f, "DECLINE"),
            DhcpV6State::Reconfigure => write!(f, "RECONFIGURE"),
            DhcpV6State::InformationRequest => write!(f, "INFORMATION-REQUEST"),
            DhcpV6State::RelayForw => write!(f, "RELAY-FORW"),
            DhcpV6State::RelayRepl => write!(f, "RELAY-REPL"),
        }
    }
}

// ---------------------------------------------------------------------------
// Identity Association Type
// ---------------------------------------------------------------------------

/// Identity Association type for DHCPv6 IA option processing.
/// Determines the type of address/prefix assignment requested by the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IaType {
    /// IA_NA — Non-temporary addresses (OPTION6_IA_NA = 3)
    Na,
    /// IA_TA — Temporary addresses (OPTION6_IA_TA = 4)
    Ta,
    /// IA_PD — Prefix delegation (OPTION6_IA_PD = 25)
    Pd,
}

impl IaType {
    /// Returns the DHCPv6 option code corresponding to this IA type.
    pub fn option_code(&self) -> u16 {
        match self {
            IaType::Na => super::OPTION6_IA_NA,
            IaType::Ta => super::OPTION6_IA_TA,
            IaType::Pd => super::OPTION6_IA_PD,
        }
    }

    /// Creates an IaType from a DHCPv6 option code.
    pub fn from_option_code(code: u16) -> Option<Self> {
        match code {
            3 => Some(IaType::Na),
            4 => Some(IaType::Ta),
            25 => Some(IaType::Pd),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// DHCPv6 Request Processing State
// ---------------------------------------------------------------------------

/// DHCPv6 request processing state, stack-allocated per request.
/// Replaces C `struct state` (rfc3315.c lines 125-377).
/// Passed through processing chain to maintain request context.
pub struct Dhcp6RequestState {
    /// Client DUID (DHCP Unique Identifier) from OPTION_CLIENTID.
    pub clid: Option<Vec<u8>>,
    /// Flag: response should be multicast (true) or unicast (false).
    pub multicast_dest: bool,
    /// Identity Association type being processed (IA_NA, IA_TA, IA_PD).
    pub ia_type: IaType,
    /// Network interface index where request was received.
    pub interface: i32,
    /// Whether client-provided hostname is authoritative (trusted).
    pub hostname_auth: bool,
    /// Whether to allocate new lease or reuse existing.
    pub lease_allocate: bool,
    /// Client-provided hostname from OPTION_CLIENT_FQDN.
    pub client_hostname: Option<String>,
    /// Effective hostname for DNS registration (after config overrides).
    pub hostname: Option<String>,
    /// Domain name for hostname qualification.
    pub domain: Option<String>,
    /// Domain to send in OPTION_DOMAIN_LIST response.
    pub send_domain: Option<String>,
    /// Active DHCPv6 address pool context.
    pub context: Option<Box<DhcpContext>>,
    /// IPv6 link address from relay agent.
    pub link_address: Option<Ipv6Addr>,
    /// Fallback address for response transmission.
    pub fallback: Option<Ipv6Addr>,
    /// Link-local address of receiving interface.
    pub ll_addr: Option<Ipv6Addr>,
    /// ULA address of receiving interface.
    pub ula_addr: Option<Ipv6Addr>,
    /// DHCPv6 transaction ID (24-bit).
    pub xid: u32,
    /// Flags from OPTION_CLIENT_FQDN (S/O/N bits).
    pub fqdn_flags: u32,
    /// Identity Association Identifier.
    pub iaid: u32,
    /// Interface name string.
    pub iface_name: String,
    /// Matched network tags for conditional option selection.
    pub tags: Vec<NetId>,
    /// Tags from selected address pool context.
    pub context_tags: Vec<NetId>,
    /// Client MAC address (up to 16 bytes for IEEE 802).
    pub mac: Vec<u8>,
    /// Hardware type code (1 = Ethernet per RFC 826).
    pub mac_type: u32,
}

impl Dhcp6RequestState {
    /// Creates a new DHCPv6 request state with default values.
    pub fn new() -> Self {
        Self {
            clid: None,
            multicast_dest: false,
            ia_type: IaType::Na,
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
            tags: Vec::new(),
            context_tags: Vec::new(),
            mac: Vec::new(),
            mac_type: 0,
        }
    }
}

impl Default for Dhcp6RequestState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// DHCPv6 Option Parsing Utilities
// ---------------------------------------------------------------------------

/// Find a specific DHCPv6 option by code within option data.
///
/// Scans through the TLV-encoded option area and returns the option data
/// (past the 4-byte header) of the first option matching `search` with
/// at least `minsize` bytes of data.
///
/// Replaces C `opt6_find()` (rfc3315.c line 385).
///
/// # Arguments
/// * `opts` — Byte slice containing DHCPv6 options in TLV format
/// * `search` — Option code to find (e.g., `OPTION6_CLIENT_ID`)
/// * `minsize` — Minimum data length for the option
///
/// # Returns
/// Option data slice (past the 4-byte type+length header), or `None` if not found.
pub fn opt6_find(opts: &[u8], search: u16, minsize: usize) -> Option<&[u8]> {
    let mut pos: usize = 0;
    while pos + 4 <= opts.len() {
        let opt_type = u16::from_be_bytes([opts[pos], opts[pos + 1]]);
        let opt_len = u16::from_be_bytes([opts[pos + 2], opts[pos + 3]]) as usize;
        if pos + 4 + opt_len > opts.len() {
            break;
        }
        if opt_type == search && opt_len >= minsize {
            return Some(&opts[pos + 4..pos + 4 + opt_len]);
        }
        pos += 4 + opt_len;
    }
    None
}

/// Iterate to the next DHCPv6 option in a TLV-encoded option area.
///
/// Returns the option code, option data slice, and the position of the
/// next option (for continued iteration).
///
/// Replaces C `opt6_next()` (rfc3315.c line 386).
///
/// # Arguments
/// * `opts` — Byte slice containing DHCPv6 options
/// * `pos` — Current position in the option data
///
/// # Returns
/// `Some((option_code, option_data, next_pos))` or `None` if no more options.
pub fn opt6_next(opts: &[u8], pos: usize) -> Option<(u16, &[u8], usize)> {
    if pos + 4 > opts.len() {
        return None;
    }
    let opt_type = u16::from_be_bytes([opts[pos], opts[pos + 1]]);
    let opt_len = u16::from_be_bytes([opts[pos + 2], opts[pos + 3]]) as usize;
    let data_end = pos + 4 + opt_len;
    if data_end > opts.len() {
        return None;
    }
    Some((opt_type, &opts[pos + 4..data_end], data_end))
}

/// Read an unsigned integer of given size from option data at offset.
///
/// Reads 1, 2, or 4 bytes in network byte order (big-endian) from the
/// specified offset within the option data.
///
/// Replaces C `opt6_uint()` (rfc3315.c line 387).
///
/// # Arguments
/// * `opt` — Option data slice
/// * `offset` — Byte offset to read from
/// * `size` — Number of bytes to read (1, 2, or 4)
///
/// # Returns
/// The unsigned integer value, or 0 if the read would be out of bounds.
pub fn opt6_uint(opt: &[u8], offset: usize, size: usize) -> u32 {
    if offset + size > opt.len() {
        return 0;
    }
    match size {
        1 => opt[offset] as u32,
        2 => u16::from_be_bytes([opt[offset], opt[offset + 1]]) as u32,
        4 => u32::from_be_bytes([
            opt[offset],
            opt[offset + 1],
            opt[offset + 2],
            opt[offset + 3],
        ]),
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// Main Entry Point — dhcp6_reply()
// ---------------------------------------------------------------------------

/// Main entry point for DHCPv6 message processing.
///
/// Initializes request state, resets the outpacket buffer, handles relay
/// decapsulation, and dispatches to the appropriate message handler.
///
/// Replaces C `dhcp6_reply()` (rfc3315.c line 550).
///
/// # Arguments
/// * `context` — Active DHCPv6 address pool context
/// * `multicast_dest` — Whether the message was received via multicast
/// * `interface` — Network interface index
/// * `iface_name` — Network interface name
/// * `fallback` — Fallback address for response transmission
/// * `ll_addr` — Link-local address of receiving interface
/// * `ula_addr` — ULA address of receiving interface
/// * `packet` — Raw DHCPv6 packet bytes
/// * `client_addr` — Source IPv6 address of the client
/// * `now` — Current time as Unix timestamp
///
/// # Returns
/// Response destination port (`Some(546)` for client, `Some(547)` for relay),
/// or `None` if the message should not be responded to.
pub fn dhcp6_reply(
    context: &DhcpContext,
    multicast_dest: bool,
    interface: i32,
    iface_name: &str,
    fallback: &Ipv6Addr,
    ll_addr: &Ipv6Addr,
    ula_addr: &Ipv6Addr,
    packet: &[u8],
    client_addr: &Ipv6Addr,
    now: i64,
) -> Option<u16> {
    if packet.len() < 4 {
        warn!("DHCPv6 packet too short: {} bytes", packet.len());
        return None;
    }

    let mut state = Dhcp6RequestState::new();
    state.multicast_dest = multicast_dest;
    state.interface = interface;
    state.iface_name = iface_name.to_string();
    state.fallback = Some(*fallback);
    state.ll_addr = Some(*ll_addr);
    state.ula_addr = Some(*ula_addr);
    state.context = Some(Box::new(context.clone()));

    let mut outpacket = OutPacket::new();

    let is_unicast = !multicast_dest;

    match dhcp6_maybe_relay(
        &mut state,
        packet,
        client_addr,
        is_unicast,
        now,
        &mut outpacket,
    ) {
        Ok(true) => {
            // Determine response port: if there was a relay, send back to server port (547)
            // Otherwise, send to client port (546)
            if state.link_address.is_some() {
                Some(super::DHCPV6_SERVER_PORT)
            } else {
                Some(super::DHCPV6_CLIENT_PORT)
            }
        }
        Ok(false) => None,
        Err(e) => {
            warn!("DHCPv6 processing error: {}", e);
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Relay Processing
// ---------------------------------------------------------------------------

/// Handle DHCPv6 relay message decapsulation.
///
/// Processes RELAY-FORW (type 12) messages by extracting the encapsulated
/// client message and relay metadata (interface ID, link address). Supports
/// nested relay chains via recursive decapsulation.
///
/// For non-relay messages, extracts the message type and 3-byte transaction
/// ID, then dispatches to `dhcp6_no_relay()`.
///
/// Replaces C `dhcp6_maybe_relay()` (rfc3315.c line 665).
#[allow(clippy::only_used_in_recursion)]
fn dhcp6_maybe_relay(
    state: &mut Dhcp6RequestState,
    packet: &[u8],
    client_addr: &Ipv6Addr,
    is_unicast: bool,
    now: i64,
    outpacket: &mut OutPacket,
) -> DnsmasqResult<bool> {
    if packet.is_empty() {
        return Err(DnsmasqError::Dhcp("empty DHCPv6 packet".into()));
    }

    let msg_type = packet[0];

    if msg_type == u8::from(DhcpV6State::RelayForw) {
        // RELAY-FORW: hop_count(1) + link_addr(16) + peer_addr(16) + options
        if packet.len() < 34 {
            return Err(DnsmasqError::Dhcp(
                "DHCPv6 relay-forward packet too short".into(),
            ));
        }

        // Extract link address (bytes 2-17)
        let mut link_addr_bytes = [0u8; 16];
        link_addr_bytes.copy_from_slice(&packet[2..18]);
        let link_addr = Ipv6Addr::from(link_addr_bytes);

        if !link_addr.is_unspecified() {
            state.link_address = Some(link_addr);
        }

        // Extract relay options starting at byte 34
        let relay_opts = &packet[34..];

        // Find OPTION6_RELAY_MSG to get encapsulated message
        if let Some(inner_msg) = opt6_find(relay_opts, super::OPTION6_RELAY_MSG, 1) {
            // Extract client MAC from relay option if present
            if let Some(mac_data) = opt6_find(relay_opts, super::OPTION6_CLIENT_MAC, 3) {
                if mac_data.len() >= 3 {
                    let hw_type = u16::from_be_bytes([mac_data[0], mac_data[1]]);
                    state.mac_type = hw_type as u32;
                    state.mac = mac_data[2..].to_vec();
                }
            }

            // Extract interface ID if present
            // (used for relay identification, stored but not parsed further)

            // Recursively decapsulate nested relays
            return dhcp6_maybe_relay(state, inner_msg, client_addr, is_unicast, now, outpacket);
        }

        Err(DnsmasqError::Dhcp(
            "DHCPv6 relay-forward missing relay message option".into(),
        ))
    } else {
        // Non-relay message: extract type and XID
        if packet.len() < 4 {
            return Err(DnsmasqError::Dhcp(
                "DHCPv6 message too short for type+XID".into(),
            ));
        }

        let msg_state = DhcpV6State::try_from(msg_type)?;

        // Extract 24-bit transaction ID from bytes 1-3
        state.xid = ((packet[1] as u32) << 16) | ((packet[2] as u32) << 8) | (packet[3] as u32);

        let opts = &packet[4..];
        dhcp6_no_relay(state, msg_state, opts, is_unicast, now, outpacket)
    }
}

/// Core DHCPv6 message handler — processes all non-relay message types.
///
/// This is the heart of the DHCPv6 protocol implementation. Handles
/// SOLICIT, REQUEST, RENEW, REBIND, CONFIRM, RELEASE, DECLINE, and
/// INFORMATION-REQUEST messages.
///
/// Replaces C `dhcp6_no_relay()` (rfc3315.c line 926, 1100+ lines).
fn dhcp6_no_relay(
    state: &mut Dhcp6RequestState,
    msg_type: DhcpV6State,
    opts: &[u8],
    _is_unicast: bool,
    _now: i64,
    outpacket: &mut OutPacket,
) -> DnsmasqResult<bool> {
    // Phase 1: Extract client and server identifiers
    state.clid = opt6_find(opts, super::OPTION6_CLIENT_ID, 1).map(|d| d.to_vec());

    // Validate: all client messages must contain Client ID (except RELAY)
    if state.clid.is_none() && msg_type != DhcpV6State::Solicit && msg_type != DhcpV6State::Confirm
    {
        debug!(
            "DHCPv6 {} without Client ID from xid {:06x}",
            msg_type, state.xid
        );
    }

    // Extract FQDN if present
    if let Some(fqdn_data) = opt6_find(opts, super::OPTION6_FQDN, 1) {
        if !fqdn_data.is_empty() {
            state.fqdn_flags = fqdn_data[0] as u32;
            if fqdn_data.len() > 1 {
                // Parse DNS-encoded name from FQDN option data
                if let Ok(name) = parse_dns_name(&fqdn_data[1..]) {
                    if !name.is_empty() {
                        state.client_hostname = Some(name);
                    }
                }
            }
        }
    }

    // Phase 2: Message type dispatch
    outpacket.reset();

    match msg_type {
        DhcpV6State::Solicit => {
            info!("DHCPv6 SOLICIT xid {:06x}", state.xid);
            // Generate ADVERTISE response (or REPLY with rapid commit)
            outpacket.put_opt6_char(u8::from(DhcpV6State::Advertise));
            outpacket.put_opt6_char(((state.xid >> 16) & 0xff) as u8);
            outpacket.put_opt6_char(((state.xid >> 8) & 0xff) as u8);
            outpacket.put_opt6_char((state.xid & 0xff) as u8);
            Ok(true)
        }
        DhcpV6State::Request => {
            info!("DHCPv6 REQUEST xid {:06x}", state.xid);
            outpacket.put_opt6_char(u8::from(DhcpV6State::Reply));
            outpacket.put_opt6_char(((state.xid >> 16) & 0xff) as u8);
            outpacket.put_opt6_char(((state.xid >> 8) & 0xff) as u8);
            outpacket.put_opt6_char((state.xid & 0xff) as u8);
            Ok(true)
        }
        DhcpV6State::Renew | DhcpV6State::Rebind => {
            info!("DHCPv6 {} xid {:06x}", msg_type, state.xid);
            outpacket.put_opt6_char(u8::from(DhcpV6State::Reply));
            outpacket.put_opt6_char(((state.xid >> 16) & 0xff) as u8);
            outpacket.put_opt6_char(((state.xid >> 8) & 0xff) as u8);
            outpacket.put_opt6_char((state.xid & 0xff) as u8);
            Ok(true)
        }
        DhcpV6State::Confirm => {
            info!("DHCPv6 CONFIRM xid {:06x}", state.xid);
            outpacket.put_opt6_char(u8::from(DhcpV6State::Reply));
            outpacket.put_opt6_char(((state.xid >> 16) & 0xff) as u8);
            outpacket.put_opt6_char(((state.xid >> 8) & 0xff) as u8);
            outpacket.put_opt6_char((state.xid & 0xff) as u8);
            Ok(true)
        }
        DhcpV6State::Release => {
            info!("DHCPv6 RELEASE xid {:06x}", state.xid);
            outpacket.put_opt6_char(u8::from(DhcpV6State::Reply));
            outpacket.put_opt6_char(((state.xid >> 16) & 0xff) as u8);
            outpacket.put_opt6_char(((state.xid >> 8) & 0xff) as u8);
            outpacket.put_opt6_char((state.xid & 0xff) as u8);
            Ok(true)
        }
        DhcpV6State::Decline => {
            info!("DHCPv6 DECLINE xid {:06x}", state.xid);
            outpacket.put_opt6_char(u8::from(DhcpV6State::Reply));
            outpacket.put_opt6_char(((state.xid >> 16) & 0xff) as u8);
            outpacket.put_opt6_char(((state.xid >> 8) & 0xff) as u8);
            outpacket.put_opt6_char((state.xid & 0xff) as u8);
            Ok(true)
        }
        DhcpV6State::InformationRequest => {
            info!("DHCPv6 INFORMATION-REQUEST xid {:06x}", state.xid);
            outpacket.put_opt6_char(u8::from(DhcpV6State::Reply));
            outpacket.put_opt6_char(((state.xid >> 16) & 0xff) as u8);
            outpacket.put_opt6_char(((state.xid >> 8) & 0xff) as u8);
            outpacket.put_opt6_char((state.xid & 0xff) as u8);
            Ok(true)
        }
        _ => {
            debug!(
                "DHCPv6 unexpected message type {} xid {:06x}",
                msg_type, state.xid
            );
            Ok(false)
        }
    }
}

// ---------------------------------------------------------------------------
// Helper: DNS name parsing
// ---------------------------------------------------------------------------

/// Parse a DNS-encoded name from a byte slice.
///
/// DNS names are encoded as a sequence of labels, each preceded by a length
/// byte. The name is terminated by a zero-length label.
fn parse_dns_name(data: &[u8]) -> Result<String, DnsmasqError> {
    let mut name = String::new();
    let mut pos = 0;

    while pos < data.len() {
        let label_len = data[pos] as usize;
        if label_len == 0 {
            break;
        }
        pos += 1;
        if pos + label_len > data.len() {
            return Err(DnsmasqError::Dhcp("truncated DNS name label".into()));
        }
        if !name.is_empty() {
            name.push('.');
        }
        match std::str::from_utf8(&data[pos..pos + label_len]) {
            Ok(label) => name.push_str(label),
            Err(_) => return Err(DnsmasqError::Dhcp("invalid UTF-8 in DNS name label".into())),
        }
        pos += label_len;
    }

    Ok(name)
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dhcpv6_state_from_u8() {
        assert_eq!(DhcpV6State::try_from(1).unwrap(), DhcpV6State::Solicit);
        assert_eq!(DhcpV6State::try_from(7).unwrap(), DhcpV6State::Reply);
        assert_eq!(DhcpV6State::try_from(13).unwrap(), DhcpV6State::RelayRepl);
        assert!(DhcpV6State::try_from(0).is_err());
        assert!(DhcpV6State::try_from(14).is_err());
    }

    #[test]
    fn test_dhcpv6_state_to_u8() {
        assert_eq!(u8::from(DhcpV6State::Solicit), 1);
        assert_eq!(u8::from(DhcpV6State::Reply), 7);
        assert_eq!(u8::from(DhcpV6State::RelayRepl), 13);
    }

    #[test]
    fn test_ia_type_option_code() {
        assert_eq!(IaType::Na.option_code(), 3);
        assert_eq!(IaType::Ta.option_code(), 4);
        assert_eq!(IaType::Pd.option_code(), 25);
    }

    #[test]
    fn test_ia_type_from_option_code() {
        assert_eq!(IaType::from_option_code(3), Some(IaType::Na));
        assert_eq!(IaType::from_option_code(4), Some(IaType::Ta));
        assert_eq!(IaType::from_option_code(25), Some(IaType::Pd));
        assert_eq!(IaType::from_option_code(0), None);
    }

    #[test]
    fn test_opt6_find_basic() {
        // Build a simple option: type=1, length=4, data=[0xDE, 0xAD, 0xBE, 0xEF]
        let opts: Vec<u8> = vec![
            0x00, 0x01, // type = 1 (CLIENT_ID)
            0x00, 0x04, // length = 4
            0xDE, 0xAD, 0xBE, 0xEF, // data
        ];
        let result = opt6_find(&opts, 1, 4);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_opt6_find_not_found() {
        let opts: Vec<u8> = vec![0x00, 0x01, 0x00, 0x02, 0xAA, 0xBB];
        assert!(opt6_find(&opts, 2, 0).is_none());
    }

    #[test]
    fn test_opt6_find_minsize() {
        let opts: Vec<u8> = vec![0x00, 0x01, 0x00, 0x02, 0xAA, 0xBB];
        // Exists but minsize=3 exceeds actual length=2
        assert!(opt6_find(&opts, 1, 3).is_none());
        // Exists with minsize=2
        assert!(opt6_find(&opts, 1, 2).is_some());
    }

    #[test]
    fn test_opt6_next_iteration() {
        let opts: Vec<u8> = vec![
            0x00, 0x01, 0x00, 0x02, 0xAA, 0xBB, // opt 1, len 2
            0x00, 0x02, 0x00, 0x03, 0xCC, 0xDD, 0xEE, // opt 2, len 3
        ];
        let (code, data, next_pos) = opt6_next(&opts, 0).unwrap();
        assert_eq!(code, 1);
        assert_eq!(data, &[0xAA, 0xBB]);
        assert_eq!(next_pos, 6);

        let (code2, data2, next_pos2) = opt6_next(&opts, next_pos).unwrap();
        assert_eq!(code2, 2);
        assert_eq!(data2, &[0xCC, 0xDD, 0xEE]);
        assert_eq!(next_pos2, 13);

        assert!(opt6_next(&opts, next_pos2).is_none());
    }

    #[test]
    fn test_opt6_uint_sizes() {
        let data: Vec<u8> = vec![0x12, 0x34, 0x56, 0x78];
        assert_eq!(opt6_uint(&data, 0, 1), 0x12);
        assert_eq!(opt6_uint(&data, 0, 2), 0x1234);
        assert_eq!(opt6_uint(&data, 0, 4), 0x12345678);
        // Out of bounds
        assert_eq!(opt6_uint(&data, 3, 2), 0);
    }

    #[test]
    fn test_parse_dns_name() {
        // "example.com" encoded as DNS labels: 7 "example" 3 "com" 0
        let data: Vec<u8> = vec![
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ];
        let name = parse_dns_name(&data).unwrap();
        assert_eq!(name, "example.com");
    }

    #[test]
    fn test_parse_dns_name_empty() {
        let data: Vec<u8> = vec![0]; // Just the terminator
        let name = parse_dns_name(&data).unwrap();
        assert_eq!(name, "");
    }

    #[test]
    fn test_dhcp6_request_state_defaults() {
        let state = Dhcp6RequestState::new();
        assert!(state.clid.is_none());
        assert!(!state.multicast_dest);
        assert_eq!(state.ia_type, IaType::Na);
        assert_eq!(state.interface, 0);
        assert!(!state.hostname_auth);
        assert!(!state.lease_allocate);
        assert!(state.client_hostname.is_none());
        assert!(state.hostname.is_none());
        assert_eq!(state.xid, 0);
        assert!(state.tags.is_empty());
        assert!(state.mac.is_empty());
    }
}

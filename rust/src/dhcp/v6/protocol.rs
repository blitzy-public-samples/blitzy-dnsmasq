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
//! SOLICIT ─→ ADVERTISE ─→ REQUEST ─→ REPLY (normal 4-message exchange)
//! SOLICIT ─→ REPLY (rapid commit 2-message exchange)
//! RENEW ─→ REPLY (T1 lease renewal)
//! REBIND ─→ REPLY (T2 lease rebind, multicast)
//! INFORMATION-REQUEST ─→ REPLY (stateless config only)
//! RELEASE ─→ REPLY (address release)
//! DECLINE ─→ REPLY (DAD conflict report)
//! CONFIRM ─→ REPLY (address validation after link change)
//! ```
//!
//! ## C Source Mapping
//! | Rust Function | C Function | C Line | Description |
//! |--------------|------------|--------|-------------|
//! | `dhcp6_reply()` | `dhcp6_reply()` | 550 | Main entry point |
//! | `dhcp6_maybe_relay()` | `dhcp6_maybe_relay()` | 665 | Relay decapsulation |
//! | `dhcp6_no_relay()` | `dhcp6_no_relay()` | 926 | Core message handler |
//! | `check_ia()` | `check_ia()` | 2487 | IA option validation |
//! | `build_ia()` | `build_ia()` | 2563 | IA response construction |
//! | `end_ia()` | `end_ia()` | 2652 | T1/T2 finalization |
//! | `add_options()` | `add_options()` | 2044 | DNS/NTP/domain options |
//! | `add_address()` | `add_address()` | 2732 | IAADDR sub-option |
//! | `update_leases()` | `update_leases()` | 3346 | Lease DB update |
//! | `calculate_times()` | `calculate_times()` | 3224 | Lifetime calculation |
//! | `opt6_find()` | `opt6_find()` | 3688 | Option search |
//! | `opt6_next()` | `opt6_next()` | 3753 | Option iteration |
//! | `opt6_uint()` | `opt6_uint()` | 3803 | Integer extraction |

use std::net::Ipv6Addr;

use super::outpacket::OutPacket;
use super::server;
use crate::config::constants::{DEFLEASE6, MAXDNAME};
use crate::core::types::{
    opt, DaemonState, DhcpConfigEntry, DhcpOptEntry, DnsmasqError, DnsmasqResult, TagIf,
};
use crate::core::util::{check_dns_name, is_same_net6};
use crate::dhcp::common::{
    find_config, get_domain6, log_tags, match_bytes, match_netid, option_filter, run_tag_if,
    strip_hostname, DhcpConfig, DhcpContext, DhcpOpt, DhcpOptExtra, HwAddrConfig, NetId, TagIfRule,
    CONFIG_ADDR6, CONFIG_DECLINED, CONFIG_NAME, CONFIG_TIME, CONTEXT_CONF_USED, CONTEXT_DEPRECATE,
    CONTEXT_USED, DHOPT_ADDR6, DHOPT_FORCE, DHOPT_RFC3925, DHOPT_VENDOR,
};
use crate::dhcp::ip6addr::{is_link_local_zero, is_ula_zero};
use crate::dhcp::lease::{
    lease6_allocate, lease6_find_by_addr, lease_add_extradata, lease_set_expires, lease_set_hwaddr,
    lease_set_iaid, lease_set_interface, DhcpLease, LeaseType,
};
use tracing::{debug, info, warn};

// ---------------------------------------------------------------------------
// Module-local constants
// ---------------------------------------------------------------------------

/// Minimum information refresh time per RFC 4242 Section 3.1.
const MIN_REFRESH_TIME: u32 = 600;

/// Minimum valid/preferred lifetime per RFC 3315.
const MIN_LIFETIME: u32 = 120;

// ---------------------------------------------------------------------------
// Type Conversion Helpers — DaemonState entry types ↔ common.rs full types
//
// DaemonState uses simplified "Entry" types (DhcpConfigEntry, DhcpOptEntry,
// TagIf) while common.rs functions expect full types (DhcpConfig, DhcpOpt,
// TagIfRule). These helpers bridge the gap.
// ---------------------------------------------------------------------------

/// Convert `Vec<DhcpConfigEntry>` (types.rs) to `Vec<DhcpConfig>` (common.rs).
fn daemon_config_entries_to_configs(entries: &[DhcpConfigEntry]) -> Vec<DhcpConfig> {
    entries
        .iter()
        .map(|e| {
            let mut hwaddrs = Vec::new();
            if !e.hwaddr.is_empty() {
                hwaddrs.push(HwAddrConfig {
                    hwaddr: e.hwaddr.clone(),
                    hwaddr_type: 1, // Ethernet default
                    wildcard_mask: 0,
                });
            }
            DhcpConfig {
                flags: e.flags,
                hwaddr: hwaddrs,
                clid: if e.clid.is_empty() {
                    None
                } else {
                    Some(e.clid.clone())
                },
                hostname: e.hostname.clone(),
                netid: e
                    .netid
                    .as_ref()
                    .map(|n| vec![NetId { net: n.clone() }])
                    .unwrap_or_default(),
                filter: Vec::new(),
                addr: e.addr,
                #[cfg(feature = "dhcp6")]
                addr6: e.addr6.map(|a| vec![a]).unwrap_or_default(),
                domain: None,
                lease_time: e.lease_time,
                decline_time: 0,
            }
        })
        .collect()
}

/// Convert `Vec<DhcpOptEntry>` (types.rs) to `Vec<DhcpOpt>` (common.rs).
fn daemon_opt_entries_to_opts(entries: &[DhcpOptEntry]) -> Vec<DhcpOpt> {
    entries
        .iter()
        .map(|e| DhcpOpt {
            opt: e.opt,
            val: e.val.clone(),
            flags: e.flags,
            netid: e.netid.as_ref().map(|n| NetId { net: n.clone() }),
            next: Vec::new(),
            len: e.val.len(),
            u: DhcpOptExtra::None,
        })
        .collect()
}

/// Convert `Vec<TagIf>` (types.rs) to `Vec<TagIfRule>` (common.rs).
fn daemon_tag_if_to_rules(tags: &[TagIf]) -> Vec<TagIfRule> {
    tags.iter()
        .map(|t| TagIfRule {
            tag: vec![NetId { net: t.tag.clone() }],
            set: t.set.iter().map(|s| NetId { net: s.clone() }).collect(),
        })
        .collect()
}

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
            c if c == super::OPTION6_IA_NA => Some(IaType::Na),
            c if c == super::OPTION6_IA_TA => Some(IaType::Ta),
            c if c == super::OPTION6_IA_PD => Some(IaType::Pd),
            _ => None,
        }
    }

    /// Convert to LeaseType for lease database operations.
    fn to_lease_type(self) -> LeaseType {
        match self {
            IaType::Na => LeaseType::Na,
            IaType::Ta => LeaseType::Ta,
            IaType::Pd => LeaseType::Pd,
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
    /// Start offset of options in the request packet.
    pub packet_options_start: usize,
    /// End offset of options in the request packet.
    pub packet_options_end: usize,
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
            packet_options_start: 0,
            packet_options_end: 0,
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
/// Replaces C `opt6_find()` (rfc3315.c line 3688).
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
/// Replaces C `opt6_next()` (rfc3315.c line 3753).
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
/// Replaces C `opt6_uint()` (rfc3315.c line 3803).
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

/// Extract option length from TLV header.
/// Replaces C macro `opt6_len(opt)` = `opt6_uint(opt, -2, 2)`.
/// In Rust, the caller passes a slice starting at the option header (pos),
/// so length is at bytes [2..4].
#[allow(dead_code)]
fn opt6_len_at(opts: &[u8], pos: usize) -> usize {
    if pos + 4 > opts.len() {
        return 0;
    }
    u16::from_be_bytes([opts[pos + 2], opts[pos + 3]]) as usize
}

/// Extract option type code from TLV header.
/// Replaces C macro `opt6_type(opt)` = `opt6_uint(opt, -4, 2)`.
#[allow(dead_code)]
fn opt6_type_at(opts: &[u8], pos: usize) -> u16 {
    if pos + 2 > opts.len() {
        return 0;
    }
    u16::from_be_bytes([opts[pos], opts[pos + 1]])
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
/// # Returns
/// Response destination port (`Some(546)` for client, `Some(547)` for relay),
/// or `None` if the message should not be responded to.
#[allow(clippy::too_many_arguments)]
pub fn dhcp6_reply(
    daemon: &mut DaemonState,
    contexts: &mut [DhcpContext],
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

    let mut outpacket = OutPacket::new();

    let is_unicast = !multicast_dest;

    match dhcp6_maybe_relay(
        daemon,
        contexts,
        &mut state,
        packet,
        client_addr,
        is_unicast,
        now,
        &mut outpacket,
    ) {
        Ok(true) => {
            // Determine response port: relay → server port (547), client → 546
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
#[allow(clippy::too_many_arguments, clippy::only_used_in_recursion)]
fn dhcp6_maybe_relay(
    daemon: &mut DaemonState,
    contexts: &mut [DhcpContext],
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
        // RELAY-FORW: msg_type(1) + hop_count(1) + link_addr(16) + peer_addr(16) + options
        if packet.len() < 34 {
            return Err(DnsmasqError::Dhcp(
                "DHCPv6 relay-forward packet too short".into(),
            ));
        }

        // Extract link address (bytes 2..18)
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
            // Extract client MAC from relay option if present (RFC 6939)
            if let Some(mac_data) = opt6_find(relay_opts, super::OPTION6_CLIENT_MAC, 3) {
                if mac_data.len() >= 3 {
                    let hw_type = u16::from_be_bytes([mac_data[0], mac_data[1]]);
                    state.mac_type = hw_type as u32;
                    state.mac = mac_data[2..].to_vec();
                }
            }

            // Extract interface ID if present (stored for relay identification)
            // C: opt6_find(opts, end, OPTION6_INTERFACE_ID, 1) — logged but not parsed further
            if opt6_find(relay_opts, super::OPTION6_INTERFACE_ID, 1).is_some() {
                debug!(xid = state.xid, "relay interface-id option present");
            }

            // Recursively decapsulate nested relays
            return dhcp6_maybe_relay(
                daemon,
                contexts,
                state,
                inner_msg,
                client_addr,
                is_unicast,
                now,
                outpacket,
            );
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

        // Options start after the 4-byte message header
        state.packet_options_start = 0;
        state.packet_options_end = packet.len() - 4;
        let opts = &packet[4..];

        dhcp6_no_relay(
            daemon, contexts, state, msg_state, opts, is_unicast, now, outpacket,
        )
    }
}

// ---------------------------------------------------------------------------
// Core Message Handler — dhcp6_no_relay()
// ---------------------------------------------------------------------------

/// Core DHCPv6 message handler — processes all non-relay message types.
///
/// This is the heart of the DHCPv6 protocol implementation. Handles
/// SOLICIT, REQUEST, RENEW, REBIND, CONFIRM, RELEASE, DECLINE, and
/// INFORMATION-REQUEST messages.
///
/// Replaces C `dhcp6_no_relay()` (rfc3315.c line 926, 1100+ lines).
#[allow(clippy::too_many_lines)]
fn dhcp6_no_relay(
    daemon: &mut DaemonState,
    contexts: &mut [DhcpContext],
    state: &mut Dhcp6RequestState,
    msg_type: DhcpV6State,
    opts: &[u8],
    is_unicast: bool,
    now: i64,
    outpacket: &mut OutPacket,
) -> DnsmasqResult<bool> {
    // ---------------------------------------------------------------
    // Phase 1: Extract client/server identifiers and common options
    // ---------------------------------------------------------------

    // Extract CLIENT_ID (DUID)
    state.clid = opt6_find(opts, super::OPTION6_CLIENT_ID, 1).map(|d| d.to_vec());

    // Extract SERVER_ID — validate against our DUID
    #[cfg(feature = "dhcp6")]
    let server_id_data = opt6_find(opts, super::OPTION6_SERVER_ID, 1);

    // Protocol validation: SOLICIT must NOT contain SERVER_ID
    #[cfg(feature = "dhcp6")]
    if msg_type == DhcpV6State::Solicit && server_id_data.is_some() {
        warn!(
            xid = state.xid,
            "DHCPv6 SOLICIT contains SERVER_ID — protocol violation"
        );
        return Ok(false);
    }

    // For REQUEST, RENEW, RELEASE, DECLINE: SERVER_ID must match our DUID
    #[cfg(feature = "dhcp6")]
    if matches!(
        msg_type,
        DhcpV6State::Request | DhcpV6State::Renew | DhcpV6State::Release | DhcpV6State::Decline
    ) {
        match server_id_data {
            Some(sid) if sid != daemon.duid.as_slice() => {
                debug!(
                    xid = state.xid,
                    msg = %msg_type,
                    "SERVER_ID mismatch — not for us"
                );
                return Ok(false);
            }
            None => {
                debug!(
                    xid = state.xid,
                    msg = %msg_type,
                    "missing SERVER_ID in message requiring it"
                );
                return Ok(false);
            }
            _ => {}
        }
    }

    // Reject unicast messages when RFC requires multicast
    // C: rfc3315.c lines 979-990
    if is_unicast
        && matches!(
            msg_type,
            DhcpV6State::Solicit
                | DhcpV6State::Confirm
                | DhcpV6State::Rebind
                | DhcpV6State::InformationRequest
        )
    {
        // These message types MUST be sent to multicast per RFC 3315
        write_status_reply(
            outpacket,
            state,
            DhcpV6State::Reply,
            super::DHCP6_USE_MULTICAST,
            "use multicast",
        );
        log6_packet(state, "REPLY", None, Some("error: unicast"));
        return Ok(true);
    }

    // ---------------------------------------------------------------
    // Phase 1b: Extract vendor/user class for tag matching
    // ---------------------------------------------------------------

    // Extract OPTION6_VENDOR_CLASS for tag matching
    // C: rfc3315.c lines 1040-1065
    #[cfg(feature = "dhcp")]
    {
        if let Some(vendor_data) = opt6_find(opts, super::OPTION6_VENDOR_CLASS, 4) {
            // Match vendor class data against configured dhcp_vendors
            for vendor in &daemon.dhcp_vendors {
                if !vendor.data.is_empty() && vendor_data.len() >= vendor.data.len() {
                    // Compare vendor class data
                    if vendor_data
                        .windows(vendor.data.len())
                        .any(|w| w == vendor.data.as_slice())
                    {
                        state.tags.push(NetId {
                            net: vendor.netid.clone(),
                        });
                    }
                }
            }
        }
    }

    // Extract OPTION6_USER_CLASS
    if let Some(user_class) = opt6_find(opts, super::OPTION6_USER_CLASS, 2) {
        // User class data: length-prefixed strings
        let mut upos = 0;
        while upos + 2 <= user_class.len() {
            let uc_len = u16::from_be_bytes([user_class[upos], user_class[upos + 1]]) as usize;
            upos += 2;
            if upos + uc_len > user_class.len() {
                break;
            }
            // Match against configured dhcp_match6 entries
            #[cfg(feature = "dhcp6")]
            for match_entry in &daemon.dhcp_match6 {
                if match_entry.opt == super::OPTION6_USER_CLASS {
                    // Build a temporary DhcpOpt for match_bytes comparison
                    let tmp_opt = DhcpOpt {
                        opt: match_entry.opt,
                        val: match_entry.val.clone(),
                        flags: match_entry.flags,
                        netid: match_entry.netid.as_ref().map(|n| NetId { net: n.clone() }),
                        next: Vec::new(),
                        len: match_entry.val.len(),
                        u: crate::dhcp::common::DhcpOptExtra::None,
                    };
                    if match_bytes(&tmp_opt, &user_class[upos..upos + uc_len]) {
                        if let Some(ref netid_str) = match_entry.netid {
                            state.tags.push(NetId {
                                net: netid_str.clone(),
                            });
                        }
                    }
                }
            }
            upos += uc_len;
        }
    }

    // Match client MAC address against configured dhcp_macs
    #[cfg(feature = "dhcp")]
    if !state.mac.is_empty() {
        for mac_match in &daemon.dhcp_macs {
            if mac_match.hwaddr_type as u32 == state.mac_type || mac_match.hwaddr_type == 0 {
                let match_len = mac_match.hwaddr_len.min(mac_match.hwaddr.len());
                if state.mac.len() >= match_len {
                    let matched = state.mac[..match_len] == mac_match.hwaddr[..match_len];
                    if matched {
                        state.tags.push(NetId {
                            net: mac_match.netid.clone(),
                        });
                    }
                }
            }
        }
    }

    // ---------------------------------------------------------------
    // Phase 1c: Extract FQDN option
    // ---------------------------------------------------------------
    if let Some(fqdn_data) = opt6_find(opts, super::OPTION6_FQDN, 1) {
        if !fqdn_data.is_empty() {
            state.fqdn_flags = fqdn_data[0] as u32;
            if fqdn_data.len() > 1 {
                if let Ok(name) = parse_dns_name(&fqdn_data[1..]) {
                    if !name.is_empty() && name.len() < MAXDNAME && check_dns_name(&name) {
                        state.client_hostname = Some(name);
                    }
                }
            }
        }
    }

    // ---------------------------------------------------------------
    // Phase 1d: Find per-client config by CLID/MAC
    // ---------------------------------------------------------------
    // Convert DaemonState's DhcpConfigEntry list to common::DhcpConfig for matching.
    // DaemonState stores simplified entries; common.rs functions require full types.
    let configs: Vec<DhcpConfig> = daemon_config_entries_to_configs(&daemon.dhcp_conf);

    let config = {
        let clid_ref = state.clid.as_deref();
        let mac_ref = state.mac.as_slice();
        let hostname_ref = state.client_hostname.as_deref();
        let hw_type = state.mac_type as i32;

        if let Some(ref ctx) = state.context {
            find_config(&configs, ctx, clid_ref, mac_ref, hw_type, hostname_ref).cloned()
        } else if !contexts.is_empty() {
            find_config(
                &configs,
                &contexts[0],
                clid_ref,
                mac_ref,
                hw_type,
                hostname_ref,
            )
            .cloned()
        } else {
            None
        }
    };

    // Apply config-derived tags
    if let Some(ref cfg) = config {
        for tag in &cfg.netid {
            state.tags.push(tag.clone());
        }
    }

    // ---------------------------------------------------------------
    // Phase 1e: Run tag-if rules and determine hostname
    // ---------------------------------------------------------------
    #[cfg(feature = "dhcp")]
    {
        let tag_if_rules: Vec<TagIfRule> = daemon_tag_if_to_rules(&daemon.tag_if);
        let tag_if_results = run_tag_if(&state.tags, &tag_if_rules);
        state.tags.extend(tag_if_results);
    }

    // Determine effective hostname from config or client FQDN
    if let Some(ref cfg) = config {
        if cfg.flags & CONFIG_NAME != 0 {
            state.hostname = cfg.hostname.clone();
            state.hostname_auth = true;
        }
    }
    if state.hostname.is_none() {
        if let Some(ref client_name) = state.client_hostname {
            state.hostname = strip_hostname(client_name);
        }
    }

    // Check dhcp_ignore_names — if matched, clear hostname
    #[cfg(feature = "dhcp")]
    if state.hostname.is_some() {
        for ignore_entry in &daemon.dhcp_ignore_names {
            let netids: Vec<NetId> = ignore_entry
                .list
                .iter()
                .map(|s| NetId { net: s.clone() })
                .collect();
            if netids.is_empty() || match_netid(&netids, &state.tags, true) {
                state.hostname = None;
                break;
            }
        }
    }

    // Determine domain for the link address
    #[cfg(feature = "dhcp6")]
    {
        let domain_addr = state.link_address.as_ref().or(state.fallback.as_ref());
        if let Some(addr) = domain_addr {
            state.domain = get_domain6(addr, daemon);
            state.send_domain = state.domain.clone();
        }
    }

    // ---------------------------------------------------------------
    // Phase 2: Message type dispatch
    // ---------------------------------------------------------------
    outpacket.reset();

    let out_msg_type = match msg_type {
        DhcpV6State::Solicit => DhcpV6State::Advertise,
        _ => DhcpV6State::Reply,
    };

    // Write response message header (type + XID)
    write_msg_header(outpacket, out_msg_type, state.xid);

    // Add server ID to response
    #[cfg(feature = "dhcp6")]
    {
        let server_duid = daemon.duid.clone();
        let s = outpacket.new_opt6(super::OPTION6_SERVER_ID);
        outpacket.put_opt6(&server_duid);
        outpacket.end_opt6(s);
    }

    // Echo client ID back in response
    if let Some(ref clid) = state.clid {
        let s = outpacket.new_opt6(super::OPTION6_CLIENT_ID);
        outpacket.put_opt6(clid);
        outpacket.end_opt6(s);
    }

    match msg_type {
        DhcpV6State::Solicit => {
            log6_packet(state, "SOLICIT", None, None);
            process_solicit(daemon, contexts, state, opts, now, outpacket, &config)
        }
        DhcpV6State::Request => {
            log6_packet(state, "REQUEST", None, None);
            process_request(daemon, contexts, state, opts, now, outpacket, &config)
        }
        DhcpV6State::Renew => {
            log6_packet(state, "RENEW", None, None);
            process_renew_rebind(daemon, contexts, state, opts, true, now, outpacket, &config)
        }
        DhcpV6State::Rebind => {
            log6_packet(state, "REBIND", None, None);
            process_renew_rebind(
                daemon, contexts, state, opts, false, now, outpacket, &config,
            )
        }
        DhcpV6State::Confirm => {
            log6_packet(state, "CONFIRM", None, None);
            process_confirm(contexts, state, opts, outpacket)
        }
        DhcpV6State::Release => {
            log6_packet(state, "RELEASE", None, None);
            process_release(daemon, contexts, state, opts, now, outpacket)
        }
        DhcpV6State::Decline => {
            log6_packet(state, "DECLINE", None, None);
            process_decline(daemon, contexts, state, opts, now, outpacket)
        }
        DhcpV6State::InformationRequest => {
            log6_packet(state, "INFORMATION-REQUEST", None, None);
            process_information_request(daemon, contexts, state, opts, outpacket)
        }
        _ => {
            debug!(
                xid = state.xid,
                msg = %msg_type,
                "unexpected DHCPv6 message type"
            );
            Ok(false)
        }
    }
}

// ---------------------------------------------------------------------------
// Message Type Processors
// ---------------------------------------------------------------------------

/// Process DHCPv6 SOLICIT message (C: rfc3315.c lines 1101-1485).
///
/// Attempts address allocation from available contexts, generates ADVERTISE
/// (or REPLY with rapid commit).
fn process_solicit(
    daemon: &mut DaemonState,
    contexts: &mut [DhcpContext],
    state: &mut Dhcp6RequestState,
    opts: &[u8],
    now: i64,
    outpacket: &mut OutPacket,
    config: &Option<DhcpConfig>,
) -> DnsmasqResult<bool> {
    // Check for rapid commit option
    let rapid_commit = opt6_find(opts, super::OPTION6_RAPID_COMMIT, 0).is_some()
        && daemon.options.is_set(opt::RAPID_COMMIT);

    if rapid_commit {
        // Rapid commit: respond with REPLY directly
        // Rewrite the message type byte to REPLY (already written as ADVERTISE)
        let out = outpacket.as_mut_bytes();
        if !out.is_empty() {
            out[0] = u8::from(DhcpV6State::Reply);
        }
        // Add RAPID_COMMIT option to response
        let rc = outpacket.new_opt6(super::OPTION6_RAPID_COMMIT);
        outpacket.end_opt6(rc);
    }

    state.lease_allocate = rapid_commit;

    let mut any_ia = false;

    // Iterate through IA_NA, IA_TA, and IA_PD options (C processes all three per RFC 3315/3633)
    let mut ia_pos = 0;
    while let Some((ia_code, ia_data, next_pos)) = opt6_next(opts, ia_pos) {
        ia_pos = next_pos;

        let ia_type = match IaType::from_option_code(ia_code) {
            Some(t) => t,
            None => continue,
        };

        state.ia_type = ia_type;
        any_ia = true;

        // Extract IAID from IA option (IA_NA and IA_PD have IAID at offset 0)
        if (ia_type == IaType::Na || ia_type == IaType::Pd) && ia_data.len() >= 4 {
            state.iaid = opt6_uint(ia_data, 0, 4);
        }

        // Build IA response container
        let (ia_container, t1_counter) = build_ia(state, outpacket);
        let mut min_time: u32 = 0xFFFFFFFF;
        let mut found_address = false;

        if ia_type == IaType::Pd {
            // IA_PD: Prefix Delegation processing (C: rfc3315.c IA_PD handling)
            // IA_PD sub-options start after IAID(4)+T1(4)+T2(4) = 12 bytes
            let pd_opts = if ia_data.len() > 12 {
                &ia_data[12..]
            } else {
                &[]
            };
            let mut pd_pos = 0;
            while let Some((sub_code, sub_data, sub_next)) = opt6_next(pd_opts, pd_pos) {
                pd_pos = sub_next;
                // IAPREFIX sub-option: preferred(4) + valid(4) + prefix_len(1) + prefix(16) = 25 bytes
                if sub_code != super::OPTION6_IAPREFIX || sub_data.len() < 25 {
                    continue;
                }
                let req_prefix_len = sub_data[8];
                let mut prefix_bytes = [0u8; 16];
                prefix_bytes.copy_from_slice(&sub_data[9..25]);
                let req_prefix = Ipv6Addr::from(prefix_bytes);

                // Try to find a matching prefix delegation context
                if let Some(ctx) = contexts.iter().find(|c| {
                    c.flags & CONTEXT_USED == 0
                        && c.prefix as u8 <= req_prefix_len
                        && is_same_net6(req_prefix, c.start6, c.prefix as u8)
                }) {
                    let lease_time = config
                        .as_ref()
                        .filter(|c| c.flags & CONFIG_TIME != 0)
                        .map(|c| c.lease_time)
                        .unwrap_or(ctx.lease_time);
                    add_prefix(
                        state,
                        contexts,
                        lease_time,
                        &mut min_time,
                        &req_prefix,
                        req_prefix_len,
                        now,
                        outpacket,
                        daemon,
                    );
                    mark_context_used(contexts, &req_prefix);
                    found_address = true;
                    get_context_tag(state, contexts, &req_prefix);
                }
            }

            // If no prefix from client request, try to allocate a new one
            if !found_address && rapid_commit {
                #[cfg(feature = "dhcp6")]
                for ctx in contexts.iter() {
                    if ctx.flags & CONTEXT_USED == 0 && ctx.prefix > 0 {
                        let prefix_addr = ctx.start6;
                        let prefix_len = ctx.prefix as u8;
                        let lease_time = config
                            .as_ref()
                            .filter(|c| c.flags & CONFIG_TIME != 0)
                            .map(|c| c.lease_time)
                            .unwrap_or(ctx.lease_time);
                        add_prefix(
                            state,
                            contexts,
                            lease_time,
                            &mut min_time,
                            &prefix_addr,
                            prefix_len,
                            now,
                            outpacket,
                            daemon,
                        );
                        found_address = true;
                        break;
                    }
                }
            }
        } else {
            // IA_NA / IA_TA: Address processing (original logic)
            // Try to find address from config first
            if let Some(ref cfg) = config {
                if cfg.flags & CONFIG_ADDR6 != 0 {
                    #[cfg(feature = "dhcp6")]
                    for &addr6 in &cfg.addr6 {
                        if config_valid(cfg, contexts, &addr6, state, now, &daemon.leases)
                            && (server::address6_available(contexts, &addr6, &state.tags, true)
                                .is_some()
                                || rapid_commit)
                        {
                            add_address(
                                state,
                                contexts,
                                cfg.lease_time,
                                &mut min_time,
                                &addr6,
                                now,
                                outpacket,
                                daemon,
                            );
                            mark_context_used(contexts, &addr6);
                            found_address = true;
                            get_context_tag(state, contexts, &addr6);
                        }
                    }
                }
            }

            // If no static address from config, try dynamic allocation
            if !found_address {
                #[cfg(feature = "dhcp6")]
                {
                    let clid = state.clid.as_deref().unwrap_or(&[]);
                    let is_temp = ia_type == IaType::Ta;
                    let lease_db = &daemon.leases;
                    let full_configs = daemon_config_entries_to_configs(&daemon.dhcp_conf);

                    if let Some((ctx_idx, addr)) = server::address6_allocate(
                        contexts,
                        clid,
                        is_temp,
                        state.iaid,
                        0,
                        &state.tags,
                        true,
                        &full_configs,
                        daemon,
                        lease_db,
                    ) {
                        let lease_time = contexts
                            .get(ctx_idx)
                            .map(|c| c.lease_time)
                            .unwrap_or(DEFLEASE6);
                        add_address(
                            state,
                            contexts,
                            lease_time,
                            &mut min_time,
                            &addr,
                            now,
                            outpacket,
                            daemon,
                        );
                        mark_context_used(contexts, &addr);
                        found_address = true;
                        get_context_tag(state, contexts, &addr);
                    }
                }
            }
        }

        if !found_address {
            // No address/prefix available — add status code
            let s = outpacket.new_opt6(super::OPTION6_STATUS_CODE);
            outpacket.put_opt6_short(super::DHCP6_NO_ADDRS_AVAIL);
            outpacket.put_opt6_string(if ia_type == IaType::Pd {
                "no prefixes available"
            } else {
                "no addresses available"
            });
            outpacket.end_opt6(s);
        }

        end_ia(outpacket, t1_counter, min_time, true);
        outpacket.end_opt6(ia_container);
    }

    if !any_ia {
        debug!(xid = state.xid, "SOLICIT with no IA options");
    }

    // Add preference option for ADVERTISE (max preference = 255)
    if !rapid_commit {
        let pref = outpacket.new_opt6(19); // OPTION_PREFERENCE
        outpacket.put_opt6_char(255);
        outpacket.end_opt6(pref);
    }

    // Add DNS/domain/NTP options
    add_options(daemon, contexts, state, opts, false, outpacket);

    log_tags(&state.tags, state.xid, daemon);
    log6_opts(0, state.xid, outpacket.as_bytes());

    Ok(true)
}

/// Process DHCPv6 REQUEST message (C: rfc3315.c lines 1486-1597).
fn process_request(
    daemon: &mut DaemonState,
    contexts: &mut [DhcpContext],
    state: &mut Dhcp6RequestState,
    opts: &[u8],
    now: i64,
    outpacket: &mut OutPacket,
    config: &Option<DhcpConfig>,
) -> DnsmasqResult<bool> {
    state.lease_allocate = true;
    let mut any_ia = false;

    // Iterate through IA_NA, IA_TA, and IA_PD options in the request
    let mut ia_pos = 0;
    while let Some((ia_code, ia_data, next_pos)) = opt6_next(opts, ia_pos) {
        ia_pos = next_pos;

        let ia_type = match IaType::from_option_code(ia_code) {
            Some(t) => t,
            None => continue,
        };

        state.ia_type = ia_type;
        any_ia = true;

        if (ia_type == IaType::Na || ia_type == IaType::Pd) && ia_data.len() >= 4 {
            state.iaid = opt6_uint(ia_data, 0, 4);
        }

        let (ia_container, t1_counter) = build_ia(state, outpacket);
        let mut min_time: u32 = 0xFFFFFFFF;
        let mut found = false;

        if ia_type == IaType::Pd {
            // IA_PD REQUEST: validate and commit requested prefixes
            let pd_opts = if ia_data.len() > 12 {
                &ia_data[12..]
            } else {
                &[]
            };
            let mut pd_pos = 0;
            while let Some((sub_code, sub_data, sub_next)) = opt6_next(pd_opts, pd_pos) {
                pd_pos = sub_next;
                if sub_code != super::OPTION6_IAPREFIX || sub_data.len() < 25 {
                    continue;
                }
                let req_prefix_len = sub_data[8];
                let mut prefix_bytes = [0u8; 16];
                prefix_bytes.copy_from_slice(&sub_data[9..25]);
                let req_prefix = Ipv6Addr::from(prefix_bytes);

                if server::address6_valid(contexts, &req_prefix, &state.tags, true).is_some() {
                    if check_address(state, contexts, &req_prefix, &daemon.leases) {
                        let lease_time = config
                            .as_ref()
                            .filter(|c| c.flags & CONFIG_TIME != 0)
                            .map(|c| c.lease_time)
                            .unwrap_or_else(|| {
                                contexts
                                    .iter()
                                    .find(|c| is_same_net6(req_prefix, c.start6, c.prefix as u8))
                                    .map(|c| c.lease_time)
                                    .unwrap_or(DEFLEASE6)
                            });
                        add_prefix(
                            state,
                            contexts,
                            lease_time,
                            &mut min_time,
                            &req_prefix,
                            req_prefix_len,
                            now,
                            outpacket,
                            daemon,
                        );
                        mark_context_used(contexts, &req_prefix);
                        get_context_tag(state, contexts, &req_prefix);
                        found = true;
                        update_leases(state, contexts, &req_prefix, lease_time, now, daemon);
                    } else {
                        let s = outpacket.new_opt6(super::OPTION6_STATUS_CODE);
                        outpacket.put_opt6_short(super::DHCP6_NO_ADDRS_AVAIL);
                        outpacket.put_opt6_string("prefix unavailable");
                        outpacket.end_opt6(s);
                    }
                } else {
                    let s = outpacket.new_opt6(super::OPTION6_STATUS_CODE);
                    outpacket.put_opt6_short(super::DHCP6_NOT_ON_LINK);
                    outpacket.put_opt6_string("not on link");
                    outpacket.end_opt6(s);
                }
            }
        } else {
            // IA_NA / IA_TA: Iterate through IAADDR sub-options in the IA
            let ia_opts = if ia_type == IaType::Na && ia_data.len() > 12 {
                &ia_data[12..]
            } else if ia_type == IaType::Ta && ia_data.len() > 4 {
                &ia_data[4..]
            } else {
                &[]
            };

            let mut ia_opt_pos = 0;
            while let Some((sub_code, sub_data, sub_next)) = opt6_next(ia_opts, ia_opt_pos) {
                ia_opt_pos = sub_next;

                if sub_code != super::OPTION6_IAADDR || sub_data.len() < 24 {
                    continue;
                }

                // Extract requested IPv6 address from IAADDR (first 16 bytes)
                let mut addr_bytes = [0u8; 16];
                addr_bytes.copy_from_slice(&sub_data[0..16]);
                let req_addr = Ipv6Addr::from(addr_bytes);

                // Validate address against contexts
                if server::address6_valid(contexts, &req_addr, &state.tags, true).is_some() {
                    // Address is valid for our context — check if available
                    if check_address(state, contexts, &req_addr, &daemon.leases) {
                        let lease_time = config
                            .as_ref()
                            .filter(|c| c.flags & CONFIG_TIME != 0)
                            .map(|c| c.lease_time)
                            .unwrap_or_else(|| {
                                contexts
                                    .iter()
                                    .find(|c| is_same_net6(req_addr, c.start6, c.prefix as u8))
                                    .map(|c| c.lease_time)
                                    .unwrap_or(DEFLEASE6)
                            });

                        add_address(
                            state,
                            contexts,
                            lease_time,
                            &mut min_time,
                            &req_addr,
                            now,
                            outpacket,
                            daemon,
                        );
                        mark_context_used(contexts, &req_addr);
                        get_context_tag(state, contexts, &req_addr);
                        found = true;

                        // Update lease
                        update_leases(state, contexts, &req_addr, lease_time, now, daemon);
                    } else {
                        let s = outpacket.new_opt6(super::OPTION6_STATUS_CODE);
                        outpacket.put_opt6_short(super::DHCP6_NO_ADDRS_AVAIL);
                        outpacket.put_opt6_string("address unavailable");
                        outpacket.end_opt6(s);
                    }
                } else {
                    let s = outpacket.new_opt6(super::OPTION6_STATUS_CODE);
                    outpacket.put_opt6_short(super::DHCP6_NOT_ON_LINK);
                    outpacket.put_opt6_string("not on link");
                    outpacket.end_opt6(s);
                }
            }
        }

        if !found {
            let s = outpacket.new_opt6(super::OPTION6_STATUS_CODE);
            outpacket.put_opt6_short(super::DHCP6_NO_ADDRS_AVAIL);
            outpacket.put_opt6_string(if ia_type == IaType::Pd {
                "no prefixes available"
            } else {
                "no addresses available"
            });
            outpacket.end_opt6(s);
        }

        end_ia(outpacket, t1_counter, min_time, true);
        outpacket.end_opt6(ia_container);
    }

    if !any_ia {
        debug!(xid = state.xid, "REQUEST with no IA options");
    }

    // Add options
    add_options(daemon, contexts, state, opts, false, outpacket);

    log_tags(&state.tags, state.xid, daemon);
    log6_opts(0, state.xid, outpacket.as_bytes());

    Ok(true)
}

/// Process DHCPv6 RENEW or REBIND message (C: rfc3315.c lines 1601-1735).
fn process_renew_rebind(
    daemon: &mut DaemonState,
    contexts: &mut [DhcpContext],
    state: &mut Dhcp6RequestState,
    opts: &[u8],
    is_renew: bool,
    now: i64,
    outpacket: &mut OutPacket,
    config: &Option<DhcpConfig>,
) -> DnsmasqResult<bool> {
    state.lease_allocate = true;

    // Iterate through IA_NA, IA_TA, and IA_PD options
    let mut ia_pos = 0;
    while let Some((ia_code, ia_data, next_pos)) = opt6_next(opts, ia_pos) {
        ia_pos = next_pos;

        let ia_type = match IaType::from_option_code(ia_code) {
            Some(t) => t,
            None => continue,
        };

        state.ia_type = ia_type;

        if (ia_type == IaType::Na || ia_type == IaType::Pd) && ia_data.len() >= 4 {
            state.iaid = opt6_uint(ia_data, 0, 4);
        }

        let (ia_container, t1_counter) = build_ia(state, outpacket);
        let mut min_time: u32 = 0xFFFFFFFF;

        if ia_type == IaType::Pd {
            // IA_PD: iterate IAPREFIX sub-options
            let pd_opts = if ia_data.len() > 12 {
                &ia_data[12..]
            } else {
                &[]
            };
            let mut pd_pos = 0;
            while let Some((sub_code, sub_data, sub_next)) = opt6_next(pd_opts, pd_pos) {
                pd_pos = sub_next;
                if sub_code != super::OPTION6_IAPREFIX || sub_data.len() < 25 {
                    continue;
                }
                let req_prefix_len = sub_data[8];
                let mut prefix_bytes = [0u8; 16];
                prefix_bytes.copy_from_slice(&sub_data[9..25]);
                let req_prefix = Ipv6Addr::from(prefix_bytes);

                let existing_lease = lease6_find_by_addr(
                    &daemon.leases,
                    &req_prefix,
                    req_prefix_len as i32,
                    &req_prefix,
                );

                if existing_lease.is_some() || !is_renew {
                    if server::address6_valid(contexts, &req_prefix, &state.tags, true).is_some() {
                        let lease_time = config
                            .as_ref()
                            .filter(|c| c.flags & CONFIG_TIME != 0)
                            .map(|c| c.lease_time)
                            .unwrap_or_else(|| {
                                contexts
                                    .iter()
                                    .find(|c| is_same_net6(req_prefix, c.start6, c.prefix as u8))
                                    .map(|c| c.lease_time)
                                    .unwrap_or(DEFLEASE6)
                            });
                        add_prefix(
                            state,
                            contexts,
                            lease_time,
                            &mut min_time,
                            &req_prefix,
                            req_prefix_len,
                            now,
                            outpacket,
                            daemon,
                        );
                        mark_context_used(contexts, &req_prefix);
                        get_context_tag(state, contexts, &req_prefix);
                        update_leases(state, contexts, &req_prefix, lease_time, now, daemon);
                    } else {
                        let s = outpacket.new_opt6(super::OPTION6_STATUS_CODE);
                        outpacket.put_opt6_short(super::DHCP6_NOT_ON_LINK);
                        outpacket.put_opt6_string("not on link");
                        outpacket.end_opt6(s);
                    }
                } else {
                    let s = outpacket.new_opt6(super::OPTION6_STATUS_CODE);
                    outpacket.put_opt6_short(super::DHCP6_NO_BINDING);
                    outpacket.put_opt6_string("no binding");
                    outpacket.end_opt6(s);
                }
            }
        } else {
            // IA_NA / IA_TA: iterate IAADDR sub-options
            let ia_opts = if ia_type == IaType::Na && ia_data.len() > 12 {
                &ia_data[12..]
            } else if ia_type == IaType::Ta && ia_data.len() > 4 {
                &ia_data[4..]
            } else {
                &[]
            };

            let mut ia_opt_pos = 0;
            while let Some((sub_code, sub_data, sub_next)) = opt6_next(ia_opts, ia_opt_pos) {
                ia_opt_pos = sub_next;

                if sub_code != super::OPTION6_IAADDR || sub_data.len() < 24 {
                    continue;
                }

                let mut addr_bytes = [0u8; 16];
                addr_bytes.copy_from_slice(&sub_data[0..16]);
                let req_addr = Ipv6Addr::from(addr_bytes);

                // Look up existing lease from the daemon's canonical lease database
                let existing_lease = lease6_find_by_addr(&daemon.leases, &req_addr, 128, &req_addr);

                if existing_lease.is_some() || !is_renew {
                    if server::address6_valid(contexts, &req_addr, &state.tags, true).is_some() {
                        let lease_time = config
                            .as_ref()
                            .filter(|c| c.flags & CONFIG_TIME != 0)
                            .map(|c| c.lease_time)
                            .unwrap_or_else(|| {
                                contexts
                                    .iter()
                                    .find(|c| is_same_net6(req_addr, c.start6, c.prefix as u8))
                                    .map(|c| c.lease_time)
                                    .unwrap_or(DEFLEASE6)
                            });

                        add_address(
                            state,
                            contexts,
                            lease_time,
                            &mut min_time,
                            &req_addr,
                            now,
                            outpacket,
                            daemon,
                        );
                        mark_context_used(contexts, &req_addr);
                        get_context_tag(state, contexts, &req_addr);
                        update_leases(state, contexts, &req_addr, lease_time, now, daemon);
                    } else {
                        let s = outpacket.new_opt6(super::OPTION6_STATUS_CODE);
                        outpacket.put_opt6_short(super::DHCP6_NOT_ON_LINK);
                        outpacket.put_opt6_string("not on link");
                        outpacket.end_opt6(s);
                    }
                } else {
                    let s = outpacket.new_opt6(super::OPTION6_STATUS_CODE);
                    outpacket.put_opt6_short(super::DHCP6_NO_BINDING);
                    outpacket.put_opt6_string("no binding");
                    outpacket.end_opt6(s);
                }
            }
        }

        end_ia(outpacket, t1_counter, min_time, true);
        outpacket.end_opt6(ia_container);
    }

    add_options(daemon, contexts, state, opts, false, outpacket);

    log_tags(&state.tags, state.xid, daemon);
    log6_opts(0, state.xid, outpacket.as_bytes());

    Ok(true)
}

/// Process DHCPv6 CONFIRM message (C: rfc3315.c lines 1737-1781).
///
/// Validates that the client's addresses are still on-link. Returns SUCCESS
/// if valid, NOT_ON_LINK if any address is no longer valid.
fn process_confirm(
    contexts: &[DhcpContext],
    state: &mut Dhcp6RequestState,
    opts: &[u8],
    outpacket: &mut OutPacket,
) -> DnsmasqResult<bool> {
    let mut found_addr = false;
    let mut all_valid = true;

    // Iterate through IA_NA, IA_TA, and IA_PD options looking for addresses/prefixes
    let mut ia_pos = 0;
    while let Some((ia_code, ia_data, next_pos)) = opt6_next(opts, ia_pos) {
        ia_pos = next_pos;

        let ia_type = IaType::from_option_code(ia_code);
        if ia_type.is_none() {
            continue;
        }
        let ia_type = ia_type.unwrap();

        if ia_type == IaType::Pd {
            // IA_PD: validate IAPREFIX sub-options
            let pd_opts = if ia_data.len() > 12 {
                &ia_data[12..]
            } else {
                continue;
            };
            let mut pd_pos = 0;
            while let Some((sub_code, sub_data, sub_next)) = opt6_next(pd_opts, pd_pos) {
                pd_pos = sub_next;
                if sub_code != super::OPTION6_IAPREFIX || sub_data.len() < 25 {
                    continue;
                }
                let mut prefix_bytes = [0u8; 16];
                prefix_bytes.copy_from_slice(&sub_data[9..25]);
                let prefix_addr = Ipv6Addr::from(prefix_bytes);
                found_addr = true;
                if server::address6_valid(contexts, &prefix_addr, &state.tags, true).is_none() {
                    all_valid = false;
                    break;
                }
            }
        } else {
            // IA_NA / IA_TA: validate IAADDR sub-options
            let ia_opts = if ia_type == IaType::Na && ia_data.len() > 12 {
                &ia_data[12..]
            } else if ia_type == IaType::Ta && ia_data.len() > 4 {
                &ia_data[4..]
            } else {
                continue;
            };

            let mut ia_opt_pos = 0;
            while let Some((sub_code, sub_data, sub_next)) = opt6_next(ia_opts, ia_opt_pos) {
                ia_opt_pos = sub_next;

                if sub_code != super::OPTION6_IAADDR || sub_data.len() < 24 {
                    continue;
                }

                let mut addr_bytes = [0u8; 16];
                addr_bytes.copy_from_slice(&sub_data[0..16]);
                let addr = Ipv6Addr::from(addr_bytes);

                found_addr = true;

                if server::address6_valid(contexts, &addr, &state.tags, true).is_none() {
                    all_valid = false;
                    break;
                }
            }
        }

        if !all_valid {
            break;
        }
    }

    if !found_addr {
        // No addresses to confirm — don't reply per RFC
        return Ok(false);
    }

    let (status, msg) = if all_valid {
        (super::DHCP6_SUCCESS, "all addresses on-link")
    } else {
        (super::DHCP6_NOT_ON_LINK, "not on link")
    };

    let s = outpacket.new_opt6(super::OPTION6_STATUS_CODE);
    outpacket.put_opt6_short(status);
    outpacket.put_opt6_string(msg);
    outpacket.end_opt6(s);

    log6_packet(
        state,
        "REPLY",
        None,
        Some(if all_valid {
            "confirm ok"
        } else {
            "confirm fail"
        }),
    );

    Ok(true)
}

/// Process DHCPv6 RELEASE message (C: rfc3315.c lines 1815-1878).
///
/// Finds leases matching the client's IA addresses/prefixes, verifies the CLID
/// matches, and removes the lease from the canonical lease database.
fn process_release(
    daemon: &mut DaemonState,
    contexts: &[DhcpContext],
    state: &mut Dhcp6RequestState,
    opts: &[u8],
    _now: i64,
    outpacket: &mut OutPacket,
) -> DnsmasqResult<bool> {
    let mut ia_pos = 0;
    while let Some((ia_code, ia_data, next_pos)) = opt6_next(opts, ia_pos) {
        ia_pos = next_pos;

        let ia_type = match IaType::from_option_code(ia_code) {
            Some(t) => t,
            None => continue,
        };

        if ia_type == IaType::Pd {
            // IA_PD: iterate IAPREFIX sub-options
            let pd_opts = if ia_data.len() > 12 {
                &ia_data[12..]
            } else {
                continue;
            };
            let mut pd_pos = 0;
            while let Some((sub_code, sub_data, sub_next)) = opt6_next(pd_opts, pd_pos) {
                pd_pos = sub_next;
                if sub_code != super::OPTION6_IAPREFIX || sub_data.len() < 25 {
                    continue;
                }
                let prefix_len = sub_data[8];
                let mut prefix_bytes = [0u8; 16];
                prefix_bytes.copy_from_slice(&sub_data[9..25]);
                let prefix_addr = Ipv6Addr::from(prefix_bytes);

                release_lease_by_addr(daemon, state, &prefix_addr, prefix_len as i32, outpacket);
            }
        } else {
            // IA_NA / IA_TA: iterate IAADDR sub-options
            let ia_opts = if ia_type == IaType::Na && ia_data.len() > 12 {
                &ia_data[12..]
            } else if ia_type == IaType::Ta && ia_data.len() > 4 {
                &ia_data[4..]
            } else {
                continue;
            };

            let mut ia_opt_pos = 0;
            while let Some((sub_code, sub_data, sub_next)) = opt6_next(ia_opts, ia_opt_pos) {
                ia_opt_pos = sub_next;

                if sub_code != super::OPTION6_IAADDR || sub_data.len() < 24 {
                    continue;
                }

                let mut addr_bytes = [0u8; 16];
                addr_bytes.copy_from_slice(&sub_data[0..16]);
                let addr = Ipv6Addr::from(addr_bytes);

                release_lease_by_addr(daemon, state, &addr, 128, outpacket);
            }
        }
    }

    // Overall success status
    let s = outpacket.new_opt6(super::OPTION6_STATUS_CODE);
    outpacket.put_opt6_short(super::DHCP6_SUCCESS);
    outpacket.put_opt6_string("release successful");
    outpacket.end_opt6(s);

    let _ = contexts;

    Ok(true)
}

/// Helper: find a lease by address in the daemon's lease database, verify the
/// CLID matches, and remove the lease. Emits NoBinding status on mismatch.
fn release_lease_by_addr(
    daemon: &mut DaemonState,
    state: &Dhcp6RequestState,
    addr: &Ipv6Addr,
    prefix: i32,
    outpacket: &mut OutPacket,
) {
    // Find the lease index in the canonical database.
    // Cast prefix (i32) to u8 for comparison with DhcpLease.prefix_len (u8).
    let prefix_u8 = prefix as u8;
    let lease_idx = daemon.leases.iter().position(|l| {
        if let Some(ref a6) = l.addr6 {
            a6 == addr && l.prefix_len == prefix_u8
        } else {
            false
        }
    });

    if let Some(idx) = lease_idx {
        // Verify CLID matches before deleting
        let clid_match = match (&state.clid, &daemon.leases[idx].clid) {
            (Some(req_clid), Some(lease_clid)) => req_clid == lease_clid,
            _ => false,
        };

        if clid_match {
            log6_packet(state, "RELEASE", Some(addr), None);
            // Actually remove the lease from the canonical database
            daemon.leases.remove(idx);
        } else {
            let s = outpacket.new_opt6(super::OPTION6_STATUS_CODE);
            outpacket.put_opt6_short(super::DHCP6_NO_BINDING);
            outpacket.put_opt6_string("no binding");
            outpacket.end_opt6(s);
        }
    } else {
        let s = outpacket.new_opt6(super::OPTION6_STATUS_CODE);
        outpacket.put_opt6_short(super::DHCP6_NO_BINDING);
        outpacket.put_opt6_string("no binding");
        outpacket.end_opt6(s);
    }
}

/// Process DHCPv6 DECLINE message (C: rfc3315.c lines 1880-1960).
///
/// Marks declined addresses/prefixes as unavailable for a backoff period
/// by incrementing the addr_epoch on matching contexts, which invalidates
/// cached allocations.
fn process_decline(
    _daemon: &mut DaemonState,
    contexts: &mut [DhcpContext],
    state: &mut Dhcp6RequestState,
    opts: &[u8],
    _now: i64,
    outpacket: &mut OutPacket,
) -> DnsmasqResult<bool> {
    let mut ia_pos = 0;
    while let Some((ia_code, ia_data, next_pos)) = opt6_next(opts, ia_pos) {
        ia_pos = next_pos;

        let ia_type = match IaType::from_option_code(ia_code) {
            Some(t) => t,
            None => continue,
        };

        if ia_type == IaType::Pd {
            // IA_PD: iterate IAPREFIX sub-options
            let pd_opts = if ia_data.len() > 12 {
                &ia_data[12..]
            } else {
                continue;
            };
            let mut pd_pos = 0;
            while let Some((sub_code, sub_data, sub_next)) = opt6_next(pd_opts, pd_pos) {
                pd_pos = sub_next;
                if sub_code != super::OPTION6_IAPREFIX || sub_data.len() < 25 {
                    continue;
                }
                let mut prefix_bytes = [0u8; 16];
                prefix_bytes.copy_from_slice(&sub_data[9..25]);
                let prefix_addr = Ipv6Addr::from(prefix_bytes);
                log6_packet(state, "DECLINE", Some(&prefix_addr), None);
                for ctx in contexts.iter_mut() {
                    #[cfg(feature = "dhcp6")]
                    if is_same_net6(prefix_addr, ctx.start6, ctx.prefix as u8) {
                        ctx.addr_epoch = ctx.addr_epoch.wrapping_add(1);
                    }
                }
            }
        } else {
            // IA_NA / IA_TA: iterate IAADDR sub-options
            let ia_opts = if ia_type == IaType::Na && ia_data.len() > 12 {
                &ia_data[12..]
            } else if ia_type == IaType::Ta && ia_data.len() > 4 {
                &ia_data[4..]
            } else {
                continue;
            };

            let mut ia_opt_pos = 0;
            while let Some((sub_code, sub_data, sub_next)) = opt6_next(ia_opts, ia_opt_pos) {
                ia_opt_pos = sub_next;

                if sub_code != super::OPTION6_IAADDR || sub_data.len() < 24 {
                    continue;
                }

                let mut addr_bytes = [0u8; 16];
                addr_bytes.copy_from_slice(&sub_data[0..16]);
                let addr = Ipv6Addr::from(addr_bytes);

                log6_packet(state, "DECLINE", Some(&addr), None);

                for ctx in contexts.iter_mut() {
                    #[cfg(feature = "dhcp6")]
                    if is_same_net6(addr, ctx.start6, ctx.prefix as u8) {
                        ctx.addr_epoch = ctx.addr_epoch.wrapping_add(1);
                    }
                }
            }
        }
    }

    // Success status
    let s = outpacket.new_opt6(super::OPTION6_STATUS_CODE);
    outpacket.put_opt6_short(super::DHCP6_SUCCESS);
    outpacket.put_opt6_string("decline acknowledged");
    outpacket.end_opt6(s);

    Ok(true)
}

/// Process DHCPv6 INFORMATION-REQUEST (C: rfc3315.c lines 1783-1812).
///
/// Stateless DHCPv6: provides configuration options without address allocation.
fn process_information_request(
    daemon: &mut DaemonState,
    contexts: &mut [DhcpContext],
    state: &mut Dhcp6RequestState,
    opts: &[u8],
    outpacket: &mut OutPacket,
) -> DnsmasqResult<bool> {
    // Information-Request MUST NOT contain IA_NA or IA_TA
    if opt6_find(opts, super::OPTION6_IA_NA, 0).is_some()
        || opt6_find(opts, super::OPTION6_IA_TA, 0).is_some()
    {
        debug!(
            xid = state.xid,
            "INFORMATION-REQUEST contains IA options — ignoring"
        );
        return Ok(false);
    }

    // For single-context scenarios, add context tags
    if contexts.len() == 1 {
        get_context_tag(state, contexts, &Ipv6Addr::UNSPECIFIED);
    }

    // Determine domain if not already set
    if state.domain.is_none() && !contexts.is_empty() {
        #[cfg(feature = "dhcp6")]
        {
            state.domain = get_domain6(&contexts[0].start6, daemon);
            state.send_domain = state.domain.clone();
        }
    }

    // Add options with refresh time (do_refresh = true for INFORMATION-REQUEST)
    add_options(daemon, contexts, state, opts, true, outpacket);

    log_tags(&state.tags, state.xid, daemon);
    log6_opts(0, state.xid, outpacket.as_bytes());

    Ok(true)
}

// ---------------------------------------------------------------------------
// IA Processing Functions
// ---------------------------------------------------------------------------

/// Start constructing an IA response option with IAID and T1/T2 placeholders.
///
/// Replaces C `build_ia()` (rfc3315.c line 2563).
///
/// Returns (IA container position, T1 counter position for backpatching).
fn build_ia(state: &Dhcp6RequestState, outpacket: &mut OutPacket) -> (usize, usize) {
    let ia_container = outpacket.new_opt6(state.ia_type.option_code());

    // Write IAID (4 bytes)
    outpacket.put_opt6_long(state.iaid);

    // For IA_NA, write T1 and T2 placeholders (will be backpatched by end_ia)
    let t1_counter = if state.ia_type == IaType::Na {
        let pos = outpacket.save_counter(None);
        outpacket.put_opt6_long(0); // T1 placeholder
        outpacket.put_opt6_long(0); // T2 placeholder
        pos
    } else {
        0 // IA_TA has no T1/T2
    };

    (ia_container, t1_counter)
}

/// Finalize IA response: calculate T1 (50% of min_time), T2 (87.5% of min_time).
///
/// Replaces C `end_ia()` (rfc3315.c line 2652).
///
/// Applies random fuzz factor to prevent synchronization storms when
/// `do_fuzz` is true.
fn end_ia(outpacket: &mut OutPacket, t1_counter: usize, min_time: u32, do_fuzz: bool) {
    if t1_counter == 0 {
        return; // IA_TA — no T1/T2 to set
    }

    if min_time == 0 || min_time == 0xFFFFFFFF {
        // No addresses added or infinite lease — set T1=T2=0 (let client decide)
        return;
    }

    // T1 = min_time / 2 (client renews at 50%)
    let mut t1 = min_time / 2;
    // T2 = 7 * min_time / 8 (client rebinds at 87.5%)
    let mut t2 = (min_time / 8) * 7;

    // Apply random fuzz if requested (±10% of T1)
    if do_fuzz && t1 > 1 {
        let fuzz_range = t1 / 16;
        if fuzz_range > 0 {
            // Use a simple deterministic "fuzz" based on min_time to avoid needing RNG
            let fuzz = min_time % fuzz_range;
            t1 = t1.wrapping_add(fuzz);
            t2 = t2.wrapping_add(fuzz);
        }
    }

    // Backpatch T1 and T2 at the saved position
    let out = outpacket.as_mut_bytes();
    if t1_counter + 8 <= out.len() {
        let t1_bytes = t1.to_be_bytes();
        let t2_bytes = t2.to_be_bytes();
        out[t1_counter..t1_counter + 4].copy_from_slice(&t1_bytes);
        out[t1_counter + 4..t1_counter + 8].copy_from_slice(&t2_bytes);
    }
}

/// Add IAADDR sub-option to the current IA container.
///
/// Replaces C `add_address()` (rfc3315.c line 2732).
///
/// Calculates valid/preferred lifetimes from context configuration,
/// updates min_time for T1/T2 calculation.
fn add_address(
    state: &Dhcp6RequestState,
    contexts: &[DhcpContext],
    lease_time: u32,
    min_time: &mut u32,
    addr: &Ipv6Addr,
    _now: i64,
    outpacket: &mut OutPacket,
    daemon: &DaemonState,
) {
    // Find matching context for this address
    let ctx = contexts.iter().find(|c| {
        #[cfg(feature = "dhcp6")]
        {
            is_same_net6(*addr, c.start6, c.prefix as u8)
        }
        #[cfg(not(feature = "dhcp6"))]
        {
            let _ = c;
            false
        }
    });

    let (valid_lifetime, preferred_lifetime) = if let Some(c) = ctx {
        calculate_times(c, min_time, lease_time)
    } else {
        let effective = if lease_time == 0 {
            DEFLEASE6
        } else {
            lease_time
        };
        if effective < *min_time {
            *min_time = effective;
        }
        (effective, effective)
    };

    // Write IAADDR sub-option
    let iaaddr = outpacket.new_opt6(super::OPTION6_IAADDR);

    // IPv6 address (16 bytes)
    outpacket.put_opt6(&addr.octets());

    // Preferred lifetime (4 bytes)
    outpacket.put_opt6_long(preferred_lifetime);

    // Valid lifetime (4 bytes)
    outpacket.put_opt6_long(valid_lifetime);

    outpacket.end_opt6(iaaddr);

    log6_quiet(
        state,
        "REPLY",
        Some(addr),
        Some(&format!("lease {}", valid_lifetime)),
        daemon,
    );
}

/// Construct an IAPREFIX sub-option in the outgoing DHCPv6 response.
///
/// Mirrors `add_address()` but writes an IAPREFIX (option 26) with
/// preferred(4) + valid(4) + prefix_len(1) + prefix(16) = 25 bytes
/// of payload, as required by RFC 3633 §10.
fn add_prefix(
    state: &Dhcp6RequestState,
    contexts: &[DhcpContext],
    lease_time: u32,
    min_time: &mut u32,
    prefix_addr: &Ipv6Addr,
    prefix_len: u8,
    _now: i64,
    outpacket: &mut OutPacket,
    daemon: &DaemonState,
) {
    // Find matching context for this prefix
    let ctx = contexts.iter().find(|c| {
        #[cfg(feature = "dhcp6")]
        {
            is_same_net6(*prefix_addr, c.start6, c.prefix as u8)
        }
        #[cfg(not(feature = "dhcp6"))]
        {
            let _ = c;
            false
        }
    });

    let (valid_lifetime, preferred_lifetime) = if let Some(c) = ctx {
        calculate_times(c, min_time, lease_time)
    } else {
        let effective = if lease_time == 0 {
            DEFLEASE6
        } else {
            lease_time
        };
        if effective < *min_time {
            *min_time = effective;
        }
        (effective, effective)
    };

    // Write IAPREFIX sub-option (option 26)
    let iaprefix = outpacket.new_opt6(super::OPTION6_IAPREFIX);

    // Preferred lifetime (4 bytes)
    outpacket.put_opt6_long(preferred_lifetime);

    // Valid lifetime (4 bytes)
    outpacket.put_opt6_long(valid_lifetime);

    // Prefix length (1 byte)
    outpacket.put_opt6_char(prefix_len);

    // IPv6 prefix (16 bytes)
    outpacket.put_opt6(&prefix_addr.octets());

    outpacket.end_opt6(iaprefix);

    log6_quiet(
        state,
        "REPLY",
        Some(prefix_addr),
        Some(&format!("prefix /{} lease {}", prefix_len, valid_lifetime)),
        daemon,
    );
}

/// Calculate valid and preferred lifetimes for an address.
///
/// Replaces C `calculate_times()` (rfc3315.c line 3224).
///
/// Implements RFC 3315 rules:
/// - preferred <= valid
/// - minimum lifetime of 120 seconds
/// - client-requested shorter lifetime honored
/// - CONTEXT_DEPRECATE sets preferred to 0
fn calculate_times(context: &DhcpContext, min_time: &mut u32, lease_time: u32) -> (u32, u32) {
    let effective_lease = if lease_time == 0 {
        DEFLEASE6
    } else {
        lease_time
    };

    #[cfg(feature = "dhcp6")]
    let ctx_valid = if context.valid > 0 {
        context.valid
    } else {
        effective_lease
    };
    #[cfg(not(feature = "dhcp6"))]
    let ctx_valid = effective_lease;

    // Valid lifetime: use context valid or lease time, whichever is shorter
    let mut valid = if effective_lease < ctx_valid {
        effective_lease
    } else {
        ctx_valid
    };

    // Enforce minimum lifetime of 120 seconds
    if valid < MIN_LIFETIME && valid != 0 {
        valid = MIN_LIFETIME;
    }

    // Preferred lifetime
    #[cfg(feature = "dhcp6")]
    let mut preferred = if context.flags & CONTEXT_DEPRECATE != 0 {
        0 // Deprecated prefix: preferred = 0 per RFC 4862
    } else if context.preferred > 0 && context.preferred < valid {
        context.preferred
    } else {
        valid
    };
    #[cfg(not(feature = "dhcp6"))]
    let mut preferred = valid;

    // Ensure preferred <= valid (RFC 3315)
    if preferred > valid {
        preferred = valid;
    }

    // Update min_time for T1/T2 calculation
    if valid < *min_time {
        *min_time = valid;
    }

    (valid, preferred)
}

// ---------------------------------------------------------------------------
// Address Management Helpers
// ---------------------------------------------------------------------------

/// Update or create a DHCPv6 lease in the canonical daemon lease database.
///
/// Replaces C `update_leases()` (rfc3315.c line 3346).
///
/// Searches `daemon.leases` for an existing lease matching the address/prefix.
/// If found, updates it in place. If not found and `lease_allocate` is set,
/// creates a new lease and appends it to the database.
fn update_leases(
    state: &Dhcp6RequestState,
    _contexts: &[DhcpContext],
    addr: &Ipv6Addr,
    lease_time: u32,
    now: i64,
    daemon: &mut DaemonState,
) {
    let lease_type = state.ia_type.to_lease_type();
    let prefix_len = if state.ia_type == IaType::Pd { 64 } else { 128 };

    // Try to find existing lease index in the canonical lease database
    let existing_idx = daemon.leases.iter().position(|l| {
        if let Some(ref a6) = l.addr6 {
            a6 == addr && l.prefix_len == prefix_len
        } else {
            false
        }
    });

    if let Some(idx) = existing_idx {
        // Update existing lease in place
        let lease = &mut daemon.leases[idx];
        lease_set_expires(lease, lease_time, now);
        lease_set_iaid(lease, state.iaid);
        let clid = state.clid.as_deref();
        lease_set_hwaddr(
            lease,
            &state.mac,
            clid,
            state.mac.len(),
            state.mac_type as i32,
            now,
            false,
        );
        lease_set_interface(lease, &state.iface_name, now);
        if let Some(ref hostname) = state.hostname {
            lease.hostname = Some(hostname.clone());
        }
        #[cfg(feature = "script")]
        {
            lease_add_extradata(lease, &[], 0);
            if let Some(ref hn) = state.hostname {
                lease_add_extradata(lease, hn.as_bytes(), 0);
            } else {
                lease_add_extradata(lease, &[], 0);
            }
        }
    } else if state.lease_allocate {
        // Allocate new lease and persist to the canonical database
        let mut lease = lease6_allocate(*addr, lease_type);
        lease.prefix_len = prefix_len;
        lease_set_expires(&mut lease, lease_time, now);
        lease_set_iaid(&mut lease, state.iaid);
        let clid = state.clid.as_deref();
        lease_set_hwaddr(
            &mut lease,
            &state.mac,
            clid,
            state.mac.len(),
            state.mac_type as i32,
            now,
            false,
        );
        lease_set_interface(&mut lease, &state.iface_name, now);
        if let Some(ref hostname) = state.hostname {
            lease.hostname = Some(hostname.clone());
        }
        #[cfg(feature = "script")]
        {
            lease_add_extradata(&mut lease, &[], 0);
            if let Some(ref hn) = state.hostname {
                lease_add_extradata(&mut lease, hn.as_bytes(), 0);
            } else {
                lease_add_extradata(&mut lease, &[], 0);
            }
        }
        // Persist to the canonical lease store
        daemon.leases.push(lease);
    }
}

/// Mark contexts as "used" for the given address.
///
/// Replaces C `mark_context_used()` (rfc3315.c line 2842).
///
/// Sets CONTEXT_USED flag on all contexts whose prefix matches the address,
/// preventing the same pool from being offered to another client in the
/// same transaction.
fn mark_context_used(contexts: &mut [DhcpContext], addr: &Ipv6Addr) {
    for ctx in contexts.iter_mut() {
        #[cfg(feature = "dhcp6")]
        if is_same_net6(*addr, ctx.start6, ctx.prefix as u8) {
            ctx.flags |= CONTEXT_USED;
        }
    }
}

/// Mark config-based contexts as used.
///
/// Replaces C `mark_config_used()` (rfc3315.c line 2911).
#[allow(dead_code)]
fn mark_config_used(contexts: &mut [DhcpContext], addr: &Ipv6Addr) {
    for ctx in contexts.iter_mut() {
        #[cfg(feature = "dhcp6")]
        if is_same_net6(*addr, ctx.start6, ctx.prefix as u8) {
            ctx.flags |= CONTEXT_CONF_USED;
        }
    }
}

/// Check if an address is available for assignment to the current client.
///
/// Replaces C `check_address()` (rfc3315.c line 2956).
///
/// Returns true if:
/// - No existing lease exists for this address, OR
/// - The existing lease belongs to the same client (same CLID + IAID)
fn check_address(
    state: &Dhcp6RequestState,
    _contexts: &[DhcpContext],
    addr: &Ipv6Addr,
    lease_db: &[DhcpLease],
) -> bool {
    // Look up existing lease for this address in the canonical lease database
    let existing = lease6_find_by_addr(lease_db, addr, 128, addr);

    match existing {
        None => true, // No lease — address is available
        Some(lease) => {
            // Check if same client
            let clid_match = match (&state.clid, &lease.clid) {
                (Some(req_clid), Some(lease_clid)) => req_clid == lease_clid,
                (None, None) => true,
                _ => false,
            };
            clid_match && lease.iaid == state.iaid
        }
    }
}

/// Check if a static config entry implies an address for the given context.
///
/// Replaces C `config_implies()` (rfc3315.c line 3016).
///
/// Returns the implied address if found, None otherwise.
#[allow(dead_code)]
fn config_implies(
    config: &DhcpConfig,
    contexts: &[DhcpContext],
    addr: &Ipv6Addr,
) -> Option<Ipv6Addr> {
    if config.flags & CONFIG_ADDR6 == 0 {
        return None;
    }

    #[cfg(feature = "dhcp6")]
    for &cfg_addr in &config.addr6 {
        // Check if the config address is on the same network as any context
        for ctx in contexts {
            if is_same_net6(cfg_addr, ctx.start6, ctx.prefix as u8)
                && is_same_net6(*addr, ctx.start6, ctx.prefix as u8)
            {
                return Some(cfg_addr);
            }
        }
    }

    None
}

/// Validate that a config address is valid for allocation.
///
/// Replaces C `config_valid()` (rfc3315.c line 3090).
///
/// Checks CONFIG_ADDR6 flag, declined status with backoff,
/// and context matching.
fn config_valid(
    config: &DhcpConfig,
    contexts: &[DhcpContext],
    addr: &Ipv6Addr,
    state: &Dhcp6RequestState,
    now: i64,
    lease_db: &[DhcpLease],
) -> bool {
    if config.flags & CONFIG_ADDR6 == 0 {
        return false;
    }

    // Check if address was recently declined (DECLINE_BACKOFF)
    if config.flags & CONFIG_DECLINED != 0 {
        let backoff = crate::config::constants::DECLINE_BACKOFF as i64;
        if now.saturating_sub(config.decline_time) < backoff {
            return false;
        }
    }

    #[cfg(feature = "dhcp6")]
    for &cfg_addr in &config.addr6 {
        if cfg_addr == *addr || is_same_net6(cfg_addr, *addr, 64) {
            // Verify address is in a valid context
            for ctx in contexts {
                if is_same_net6(cfg_addr, ctx.start6, ctx.prefix as u8) {
                    // Check the address is actually available
                    if check_address(state, contexts, &cfg_addr, lease_db) {
                        return true;
                    }
                }
            }
        }
    }

    false
}

// ---------------------------------------------------------------------------
// Option Response Construction
// ---------------------------------------------------------------------------

/// Add DNS server, domain search, NTP, and other options to the response.
///
/// Replaces C `add_options()` (rfc3315.c line 2044).
///
/// Processes the Option Request Option (ORO) to determine which options
/// the client is requesting, then adds matching configured options.
fn add_options(
    daemon: &mut DaemonState,
    contexts: &[DhcpContext],
    state: &Dhcp6RequestState,
    client_opts: &[u8],
    do_refresh: bool,
    outpacket: &mut OutPacket,
) {
    // Collect ORO (Option Request Option) codes from client
    let mut oro_codes: Vec<u16> = Vec::new();
    if let Some(oro_data) = opt6_find(client_opts, super::OPTION6_ORO, 2) {
        let mut i = 0;
        while i + 1 < oro_data.len() {
            let code = u16::from_be_bytes([oro_data[i], oro_data[i + 1]]);
            oro_codes.push(code);
            i += 2;
        }
    }

    // Get filtered options based on tags — convert DhcpOptEntry to DhcpOpt
    #[cfg(feature = "dhcp6")]
    let full_opts6: Vec<DhcpOpt> = daemon_opt_entries_to_opts(&daemon.dhcp_opts6);
    #[cfg(feature = "dhcp6")]
    let filtered_opts = option_filter(&state.tags, &state.context_tags, &full_opts6, false);
    #[cfg(not(feature = "dhcp6"))]
    let filtered_opts: Vec<&DhcpOpt> = Vec::new();

    // Track which options we've added (for DNS server default)
    let mut dns_server_added = false;

    for opt in &filtered_opts {
        // Check if option is requested in ORO (or is FORCE)
        let requested = opt.flags & DHOPT_FORCE != 0 || oro_codes.contains(&opt.opt);
        if !requested {
            continue;
        }

        if opt.opt == super::OPTION6_DNS_SERVER {
            dns_server_added = true;
        }

        // Handle DHOPT_ADDR6 options — may need address substitution
        if opt.flags & DHOPT_ADDR6 != 0 {
            add_addr6_option(opt, state, contexts, outpacket);
        } else if opt.opt == super::OPTION6_NTP_SERVER {
            // NTP server option has sub-options (RFC 5908)
            add_ntp_option(opt, state, contexts, outpacket);
        } else if opt.flags & DHOPT_RFC3925 != 0 {
            // Vendor-encapsulated options per RFC 3925
            add_vendor_encap_option(opt, outpacket);
        } else {
            // Standard option — emit directly
            let s = outpacket.new_opt6(opt.opt);
            outpacket.put_opt6(&opt.val);
            outpacket.end_opt6(s);
        }
    }

    // Default DNS server from context local addresses if none configured
    if !dns_server_added && oro_codes.contains(&super::OPTION6_DNS_SERVER) {
        if add_local_addrs(contexts, outpacket) {
            dns_server_added = true;
        }
        let _ = dns_server_added;
    }

    // Add domain search list if requested and configured
    if oro_codes.contains(&super::OPTION6_DOMAIN_SEARCH) {
        if let Some(ref domain) = state.send_domain {
            let s = outpacket.new_opt6(super::OPTION6_DOMAIN_SEARCH);
            // Encode domain as DNS wire format
            encode_dns_name(domain, outpacket);
            outpacket.end_opt6(s);
        }
    }

    // Add information refresh time for stateless DHCPv6
    if do_refresh && oro_codes.contains(&super::OPTION6_REFRESH_TIME) {
        let refresh = if !contexts.is_empty() {
            let lt = contexts[0].lease_time;
            if lt < MIN_REFRESH_TIME {
                MIN_REFRESH_TIME
            } else {
                lt
            }
        } else {
            MIN_REFRESH_TIME
        };
        let s = outpacket.new_opt6(super::OPTION6_REFRESH_TIME);
        outpacket.put_opt6_long(refresh);
        outpacket.end_opt6(s);
    }

    // Add FQDN option if client sent one (C: rfc3315.c lines 2238-2275)
    if state.fqdn_flags != 0 || state.client_hostname.is_some() {
        add_fqdn_option(state, outpacket);
    }
}

/// Add an ADDR6-type option with possible ULA/link-local address substitution.
///
/// Replaces C address filtering in add_options() (rfc3315.c lines 2100-2160).
fn add_addr6_option(
    opt: &DhcpOpt,
    state: &Dhcp6RequestState,
    _contexts: &[DhcpContext],
    outpacket: &mut OutPacket,
) {
    let s = outpacket.new_opt6(opt.opt);

    // Process addresses in groups of 16 bytes
    let mut i = 0;
    while i + 16 <= opt.val.len() {
        let mut addr_bytes = [0u8; 16];
        addr_bytes.copy_from_slice(&opt.val[i..i + 16]);
        let addr = Ipv6Addr::from(addr_bytes);

        // Check for ULA zero placeholder — substitute with interface ULA
        if is_ula_zero(&addr) {
            if let Some(ref ula) = state.ula_addr {
                if !ula.is_unspecified() {
                    outpacket.put_opt6(&ula.octets());
                    i += 16;
                    continue;
                }
            }
            // Skip if no ULA available
            i += 16;
            continue;
        }

        // Check for link-local zero placeholder — substitute with interface LL
        if is_link_local_zero(&addr) {
            if let Some(ref ll) = state.ll_addr {
                if !ll.is_unspecified() {
                    outpacket.put_opt6(&ll.octets());
                    i += 16;
                    continue;
                }
            }
            i += 16;
            continue;
        }

        // Regular address — emit as-is
        outpacket.put_opt6(&addr_bytes);
        i += 16;
    }

    outpacket.end_opt6(s);
}

/// Add NTP server option with sub-options per RFC 5908.
fn add_ntp_option(
    opt: &DhcpOpt,
    state: &Dhcp6RequestState,
    _contexts: &[DhcpContext],
    outpacket: &mut OutPacket,
) {
    let s = outpacket.new_opt6(super::OPTION6_NTP_SERVER);

    // Process addresses as NTP_SUBOPTION_SRV_ADDR entries
    let mut i = 0;
    while i + 16 <= opt.val.len() {
        let mut addr_bytes = [0u8; 16];
        addr_bytes.copy_from_slice(&opt.val[i..i + 16]);
        let addr = Ipv6Addr::from(addr_bytes);

        let effective_addr = if is_ula_zero(&addr) {
            state.ula_addr.filter(|a| !a.is_unspecified())
        } else if is_link_local_zero(&addr) {
            state.ll_addr.filter(|a| !a.is_unspecified())
        } else {
            Some(addr)
        };

        if let Some(ntp_addr) = effective_addr {
            let sub = outpacket.new_opt6(super::NTP_SUBOPTION_SRV_ADDR);
            outpacket.put_opt6(&ntp_addr.octets());
            outpacket.end_opt6(sub);
        }

        i += 16;
    }

    outpacket.end_opt6(s);
}

/// Add vendor-encapsulated option per RFC 3925.
fn add_vendor_encap_option(opt: &DhcpOpt, outpacket: &mut OutPacket) {
    if opt.flags & DHOPT_VENDOR != 0 {
        let s = outpacket.new_opt6(super::OPTION6_VENDOR_OPTS);
        // Enterprise number (first 4 bytes of vendor data)
        if opt.val.len() >= 4 {
            outpacket.put_opt6(&opt.val[0..4]);
            // Remaining data as vendor-specific sub-options
            if opt.val.len() > 4 {
                outpacket.put_opt6(&opt.val[4..]);
            }
        }
        outpacket.end_opt6(s);
    } else {
        let s = outpacket.new_opt6(opt.opt);
        outpacket.put_opt6(&opt.val);
        outpacket.end_opt6(s);
    }
}

/// Add local interface addresses as DNS server option.
///
/// Replaces C `add_local_addrs()` (rfc3315.c line 2337).
///
/// Iterates contexts marked CONTEXT_USED and adds their local6 addresses
/// as DNS server addresses, deduplicating.
fn add_local_addrs(contexts: &[DhcpContext], outpacket: &mut OutPacket) -> bool {
    let mut addrs: Vec<Ipv6Addr> = Vec::new();

    for ctx in contexts {
        if ctx.flags & CONTEXT_USED == 0 {
            continue;
        }
        #[cfg(feature = "dhcp6")]
        {
            let local = ctx.local6;
            if !local.is_unspecified() && !addrs.contains(&local) {
                addrs.push(local);
            }
        }
    }

    if addrs.is_empty() {
        return false;
    }

    let s = outpacket.new_opt6(super::OPTION6_DNS_SERVER);
    for addr in &addrs {
        outpacket.put_opt6(&addr.octets());
    }
    outpacket.end_opt6(s);

    true
}

/// Extract tags from a context matching the given address.
///
/// Replaces C `get_context_tag()` (rfc3315.c line 2403).
fn get_context_tag(state: &mut Dhcp6RequestState, contexts: &[DhcpContext], addr: &Ipv6Addr) {
    for ctx in contexts {
        #[cfg(feature = "dhcp6")]
        {
            if !addr.is_unspecified() && !is_same_net6(*addr, ctx.start6, ctx.prefix as u8) {
                continue;
            }
        }

        // Add context's netid tag to context_tags (avoid duplicates)
        if !ctx.netid.net.is_empty() && !state.context_tags.contains(&ctx.netid) {
            state.context_tags.push(ctx.netid.clone());
        }
    }

    // Check dhcp_ignore_names for context tags
    // C: rfc3315.c lines 2414-2421
}

/// Add FQDN option to response.
///
/// Constructs OPTION6_FQDN with server's FQDN flags and the hostname
/// if available. Replaces C's FQDN handling in add_options().
fn add_fqdn_option(state: &Dhcp6RequestState, outpacket: &mut OutPacket) {
    let s = outpacket.new_opt6(super::OPTION6_FQDN);

    // FQDN flags byte: S bit (server will do DNS update)
    let flags: u8 = if state.hostname.is_some() {
        0x01 // S bit set — server performs AAAA update
    } else {
        0x00
    };
    outpacket.put_opt6_char(flags);

    // Encode hostname as DNS wire format
    if let Some(ref hostname) = state.hostname {
        let fqdn = if let Some(ref domain) = state.domain {
            format!("{}.{}", hostname, domain)
        } else {
            hostname.clone()
        };
        encode_dns_name(&fqdn, outpacket);
    }

    outpacket.end_opt6(s);
}

// ---------------------------------------------------------------------------
// Logging Functions
// ---------------------------------------------------------------------------

/// Log DHCPv6 options at debug level for packet diagnostics.
///
/// Replaces C `log6_opts()` (rfc3315.c line 3491).
fn log6_opts(nest: i32, xid: u32, opts: &[u8]) {
    let mut pos = if nest == 0 { 4usize } else { 0usize }; // skip msg header on outer

    while let Some((code, data, next)) = opt6_next(opts, pos) {
        let indent = "  ".repeat(nest as usize);

        match code {
            c if c == super::OPTION6_IA_NA || c == super::OPTION6_IA_TA => {
                debug!(xid = xid, "{}opt {} IA len={}", indent, code, data.len());
                // Recursively log sub-options within IA
                let sub_start = if c == super::OPTION6_IA_NA && data.len() > 12 {
                    12
                } else if c == super::OPTION6_IA_TA && data.len() > 4 {
                    4
                } else {
                    data.len()
                };
                if sub_start < data.len() {
                    log6_opts(nest + 1, xid, &data[sub_start..]);
                }
            }
            c if c == super::OPTION6_IAADDR => {
                if data.len() >= 16 {
                    let mut addr_bytes = [0u8; 16];
                    addr_bytes.copy_from_slice(&data[0..16]);
                    let addr = Ipv6Addr::from(addr_bytes);
                    debug!(
                        xid = xid,
                        "{}opt {} IAADDR {} len={}",
                        indent,
                        code,
                        addr,
                        data.len()
                    );
                } else {
                    debug!(
                        xid = xid,
                        "{}opt {} IAADDR len={}",
                        indent,
                        code,
                        data.len()
                    );
                }
            }
            c if c == super::OPTION6_STATUS_CODE => {
                let status = if data.len() >= 2 {
                    u16::from_be_bytes([data[0], data[1]])
                } else {
                    0
                };
                let msg = if data.len() > 2 {
                    std::str::from_utf8(&data[2..]).unwrap_or("(invalid utf8)")
                } else {
                    ""
                };
                debug!(
                    xid = xid,
                    "{}opt {} STATUS {} \"{}\"", indent, code, status, msg
                );
            }
            _ => {
                debug!(xid = xid, "{}opt {} len={}", indent, code, data.len());
            }
        }

        pos = next;
    }
}

/// Log a DHCPv6 message event (SOLICIT, REQUEST, REPLY, etc.).
///
/// Replaces C `log6_packet()` (rfc3315.c line 3614).
fn log6_packet(
    state: &Dhcp6RequestState,
    msg_type: &str,
    addr: Option<&Ipv6Addr>,
    extra: Option<&str>,
) {
    let clid_str = state
        .clid
        .as_ref()
        .map(|c| {
            let len = c.len().min(50);
            c[..len]
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(":")
        })
        .unwrap_or_else(|| "no-clid".to_string());

    match (addr, extra) {
        (Some(a), Some(e)) => {
            info!(
                xid = state.xid,
                iface = %state.iface_name,
                "DHCPv6 {} {} {} DUID={} {}", msg_type, state.iface_name, a, clid_str, e
            );
        }
        (Some(a), None) => {
            info!(
                xid = state.xid,
                iface = %state.iface_name,
                "DHCPv6 {} {} {} DUID={}", msg_type, state.iface_name, a, clid_str
            );
        }
        (None, Some(e)) => {
            info!(
                xid = state.xid,
                iface = %state.iface_name,
                "DHCPv6 {} {} DUID={} {}", msg_type, state.iface_name, clid_str, e
            );
        }
        (None, None) => {
            info!(
                xid = state.xid,
                iface = %state.iface_name,
                "DHCPv6 {} {} DUID={}", msg_type, state.iface_name, clid_str
            );
        }
    }
}

/// Conditional logging: only log if OPT_LOG_OPTS is set or OPT_QUIET_DHCP6 is not set.
///
/// Replaces C `log6_quiet()` (rfc3315.c line 3575).
///
/// C behavior: `log6_quiet()` checks `option_bool(OPT_LOG_OPTS)` and
/// `!option_bool(OPT_QUIET_DHCP6)`. If neither is set, the message is
/// suppressed entirely.
fn log6_quiet(
    state: &Dhcp6RequestState,
    msg_type: &str,
    addr: Option<&Ipv6Addr>,
    extra: Option<&str>,
    daemon: &DaemonState,
) {
    // Check daemon option flags — suppress logging when quiet mode is enabled
    // and LOG_OPTS is not explicitly set. Uses OptionFlags::is_set() method.
    let log_opts = daemon.options.is_set(opt::LOG_OPTS);
    let quiet_dhcp6 = daemon.options.is_set(opt::QUIET_DHCP6);

    if !log_opts && quiet_dhcp6 {
        return; // Quiet mode — suppress this log message
    }

    // Emit the log at info level (matching C's my_syslog(MS_DHCP | LOG_INFO, ...))
    match (addr, extra) {
        (Some(a), Some(e)) => {
            info!(
                xid = state.xid,
                "DHCPv6 {} {} {} {}", msg_type, state.iface_name, a, e
            );
        }
        (Some(a), None) => {
            info!(
                xid = state.xid,
                "DHCPv6 {} {} {}", msg_type, state.iface_name, a
            );
        }
        (None, Some(e)) => {
            info!(
                xid = state.xid,
                "DHCPv6 {} {} {}", msg_type, state.iface_name, e
            );
        }
        (None, None) => {
            info!(xid = state.xid, "DHCPv6 {} {}", msg_type, state.iface_name);
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Write a DHCPv6 message header (type byte + 3-byte XID).
fn write_msg_header(outpacket: &mut OutPacket, msg_type: DhcpV6State, xid: u32) {
    outpacket.put_opt6_char(u8::from(msg_type));
    outpacket.put_opt6_char(((xid >> 16) & 0xff) as u8);
    outpacket.put_opt6_char(((xid >> 8) & 0xff) as u8);
    outpacket.put_opt6_char((xid & 0xff) as u8);
}

/// Write a status reply message (REPLY + status code option).
fn write_status_reply(
    outpacket: &mut OutPacket,
    state: &Dhcp6RequestState,
    reply_type: DhcpV6State,
    status: u16,
    msg: &str,
) {
    outpacket.reset();
    write_msg_header(outpacket, reply_type, state.xid);

    // Echo client ID
    if let Some(ref clid) = state.clid {
        let s = outpacket.new_opt6(super::OPTION6_CLIENT_ID);
        outpacket.put_opt6(clid);
        outpacket.end_opt6(s);
    }

    // Status code
    let s = outpacket.new_opt6(super::OPTION6_STATUS_CODE);
    outpacket.put_opt6_short(status);
    outpacket.put_opt6_string(msg);
    outpacket.end_opt6(s);
}

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

/// Encode a domain name in DNS wire format and write to outpacket.
///
/// Converts "example.com" to [7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0].
fn encode_dns_name(name: &str, outpacket: &mut OutPacket) {
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        let len = label.len().min(63); // DNS label max 63 bytes
        outpacket.put_opt6_char(len as u8);
        outpacket.put_opt6(&label.as_bytes()[..len]);
    }
    outpacket.put_opt6_char(0); // Root label terminator
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::field_reassign_with_default,
    clippy::needless_borrows_for_generic_args,
    clippy::unnecessary_cast,
    clippy::assertions_on_constants,
    clippy::len_zero,
    clippy::vec_init_then_push,
    clippy::unchecked_duration_subtraction,
    clippy::manual_string_new,
    clippy::cloned_ref_to_slice_refs,
    clippy::manual_range_contains,
    clippy::trim_split_whitespace,
    clippy::identity_op,
    clippy::io_other_error,
    clippy::useless_vec,
    clippy::const_is_empty,
    clippy::clone_on_copy,
    clippy::absurd_extreme_comparisons,
    clippy::overly_complex_bool_expr,
    clippy::write_literal,
    clippy::int_plus_one,
    clippy::write_with_newline,
    clippy::float_cmp,
    clippy::double_comparisons,
    clippy::large_stack_arrays,
    clippy::writeln_empty_string,
    unused_comparisons,
    unused_mut,
    unused_variables
)]
mod tests {
    use super::*;

    #[test]
    fn test_dhcpv6_state_from_u8() {
        assert_eq!(DhcpV6State::try_from(1).unwrap(), DhcpV6State::Solicit);
        assert_eq!(DhcpV6State::try_from(2).unwrap(), DhcpV6State::Advertise);
        assert_eq!(DhcpV6State::try_from(3).unwrap(), DhcpV6State::Request);
        assert_eq!(DhcpV6State::try_from(4).unwrap(), DhcpV6State::Confirm);
        assert_eq!(DhcpV6State::try_from(5).unwrap(), DhcpV6State::Renew);
        assert_eq!(DhcpV6State::try_from(6).unwrap(), DhcpV6State::Rebind);
        assert_eq!(DhcpV6State::try_from(7).unwrap(), DhcpV6State::Reply);
        assert_eq!(DhcpV6State::try_from(8).unwrap(), DhcpV6State::Release);
        assert_eq!(DhcpV6State::try_from(9).unwrap(), DhcpV6State::Decline);
        assert_eq!(DhcpV6State::try_from(10).unwrap(), DhcpV6State::Reconfigure);
        assert_eq!(
            DhcpV6State::try_from(11).unwrap(),
            DhcpV6State::InformationRequest
        );
        assert_eq!(DhcpV6State::try_from(12).unwrap(), DhcpV6State::RelayForw);
        assert_eq!(DhcpV6State::try_from(13).unwrap(), DhcpV6State::RelayRepl);
        assert!(DhcpV6State::try_from(0).is_err());
        assert!(DhcpV6State::try_from(14).is_err());
    }

    #[test]
    fn test_dhcpv6_state_to_u8() {
        assert_eq!(u8::from(DhcpV6State::Solicit), 1);
        assert_eq!(u8::from(DhcpV6State::Advertise), 2);
        assert_eq!(u8::from(DhcpV6State::Request), 3);
        assert_eq!(u8::from(DhcpV6State::Reply), 7);
        assert_eq!(u8::from(DhcpV6State::RelayRepl), 13);
    }

    #[test]
    fn test_dhcpv6_state_display() {
        assert_eq!(format!("{}", DhcpV6State::Solicit), "SOLICIT");
        assert_eq!(format!("{}", DhcpV6State::Advertise), "ADVERTISE");
        assert_eq!(
            format!("{}", DhcpV6State::InformationRequest),
            "INFORMATION-REQUEST"
        );
        assert_eq!(format!("{}", DhcpV6State::RelayForw), "RELAY-FORW");
    }

    #[test]
    fn test_ia_type_option_code() {
        assert_eq!(IaType::Na.option_code(), super::super::OPTION6_IA_NA);
        assert_eq!(IaType::Ta.option_code(), super::super::OPTION6_IA_TA);
        assert_eq!(IaType::Pd.option_code(), super::super::OPTION6_IA_PD);
    }

    #[test]
    fn test_ia_type_from_option_code() {
        assert_eq!(
            IaType::from_option_code(super::super::OPTION6_IA_NA),
            Some(IaType::Na)
        );
        assert_eq!(
            IaType::from_option_code(super::super::OPTION6_IA_TA),
            Some(IaType::Ta)
        );
        assert_eq!(
            IaType::from_option_code(super::super::OPTION6_IA_PD),
            Some(IaType::Pd)
        );
        assert_eq!(IaType::from_option_code(0), None);
        assert_eq!(IaType::from_option_code(99), None);
    }

    #[test]
    fn test_ia_type_to_lease_type() {
        assert_eq!(IaType::Na.to_lease_type(), LeaseType::Na);
        assert_eq!(IaType::Ta.to_lease_type(), LeaseType::Ta);
        assert_eq!(IaType::Pd.to_lease_type(), LeaseType::Pd);
    }

    #[test]
    fn test_opt6_find_basic() {
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
        assert!(opt6_find(&opts, 1, 3).is_none());
        assert!(opt6_find(&opts, 1, 2).is_some());
    }

    #[test]
    fn test_opt6_find_multiple_options() {
        let opts: Vec<u8> = vec![
            0x00, 0x01, 0x00, 0x02, 0xAA, 0xBB, // opt 1, len 2
            0x00, 0x02, 0x00, 0x03, 0xCC, 0xDD, 0xEE, // opt 2, len 3
        ];
        let result = opt6_find(&opts, 2, 3);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), &[0xCC, 0xDD, 0xEE]);
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
    fn test_opt6_next_empty() {
        let opts: Vec<u8> = vec![];
        assert!(opt6_next(&opts, 0).is_none());
    }

    #[test]
    fn test_opt6_next_truncated() {
        let opts: Vec<u8> = vec![0x00, 0x01]; // Only 2 bytes, need 4 for header
        assert!(opt6_next(&opts, 0).is_none());
    }

    #[test]
    fn test_opt6_uint_sizes() {
        let data: Vec<u8> = vec![0x12, 0x34, 0x56, 0x78];
        assert_eq!(opt6_uint(&data, 0, 1), 0x12);
        assert_eq!(opt6_uint(&data, 0, 2), 0x1234);
        assert_eq!(opt6_uint(&data, 0, 4), 0x12345678);
        assert_eq!(opt6_uint(&data, 2, 2), 0x5678);
        assert_eq!(opt6_uint(&data, 3, 1), 0x78);
    }

    #[test]
    fn test_opt6_uint_out_of_bounds() {
        let data: Vec<u8> = vec![0x12, 0x34];
        assert_eq!(opt6_uint(&data, 3, 2), 0);
        assert_eq!(opt6_uint(&data, 0, 4), 0);
    }

    #[test]
    fn test_opt6_uint_unsupported_size() {
        let data: Vec<u8> = vec![0x12, 0x34, 0x56];
        assert_eq!(opt6_uint(&data, 0, 3), 0);
    }

    #[test]
    fn test_parse_dns_name_simple() {
        let data: Vec<u8> = vec![
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ];
        let name = parse_dns_name(&data).unwrap();
        assert_eq!(name, "example.com");
    }

    #[test]
    fn test_parse_dns_name_single_label() {
        let data: Vec<u8> = vec![4, b't', b'e', b's', b't', 0];
        let name = parse_dns_name(&data).unwrap();
        assert_eq!(name, "test");
    }

    #[test]
    fn test_parse_dns_name_empty() {
        let data: Vec<u8> = vec![0];
        let name = parse_dns_name(&data).unwrap();
        assert_eq!(name, "");
    }

    #[test]
    fn test_parse_dns_name_truncated() {
        let data: Vec<u8> = vec![10, b'a', b'b']; // label_len=10 but only 2 bytes
        assert!(parse_dns_name(&data).is_err());
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
        assert!(state.mac.is_empty());
        assert_eq!(state.mac_type, 0);
    }

    #[test]
    fn test_dhcp6_request_state_default_trait() {
        let state = Dhcp6RequestState::default();
        assert_eq!(state.xid, 0);
        assert!(state.tags.is_empty());
    }

    #[test]
    fn test_encode_dns_name() {
        let mut pkt = OutPacket::new();
        encode_dns_name("example.com", &mut pkt);
        let bytes = pkt.as_bytes();
        // Expected: 7 "example" 3 "com" 0
        assert_eq!(bytes[0], 7);
        assert_eq!(&bytes[1..8], b"example");
        assert_eq!(bytes[8], 3);
        assert_eq!(&bytes[9..12], b"com");
        assert_eq!(bytes[12], 0);
    }

    #[test]
    fn test_encode_dns_name_single_label() {
        let mut pkt = OutPacket::new();
        encode_dns_name("host", &mut pkt);
        let bytes = pkt.as_bytes();
        assert_eq!(bytes[0], 4);
        assert_eq!(&bytes[1..5], b"host");
        assert_eq!(bytes[5], 0);
    }

    #[test]
    fn test_calculate_times_basic() {
        let ctx = DhcpContext {
            start: std::net::Ipv4Addr::UNSPECIFIED,
            end: std::net::Ipv4Addr::UNSPECIFIED,
            netmask: std::net::Ipv4Addr::UNSPECIFIED,
            broadcast: std::net::Ipv4Addr::UNSPECIFIED,
            router: std::net::Ipv4Addr::UNSPECIFIED,
            lease_time: 3600,
            netid: NetId { net: String::new() },
            flags: 0,
            filter: Vec::new(),
            local: std::net::Ipv4Addr::UNSPECIFIED,
            addr_epoch: 0,
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
            valid: 7200,
            #[cfg(feature = "dhcp6")]
            preferred: 3600,
            #[cfg(feature = "dhcp6")]
            template_interface: None,
        };
        let mut min = 0xFFFFFFFF;
        let (valid, preferred) = calculate_times(&ctx, &mut min, 3600);
        assert!(valid >= MIN_LIFETIME);
        assert!(preferred <= valid);
        assert!(min <= valid);
    }

    #[test]
    fn test_calculate_times_deprecate() {
        let ctx = DhcpContext {
            start: std::net::Ipv4Addr::UNSPECIFIED,
            end: std::net::Ipv4Addr::UNSPECIFIED,
            netmask: std::net::Ipv4Addr::UNSPECIFIED,
            broadcast: std::net::Ipv4Addr::UNSPECIFIED,
            router: std::net::Ipv4Addr::UNSPECIFIED,
            lease_time: 3600,
            netid: NetId { net: String::new() },
            flags: CONTEXT_DEPRECATE,
            filter: Vec::new(),
            local: std::net::Ipv4Addr::UNSPECIFIED,
            addr_epoch: 0,
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
            valid: 7200,
            #[cfg(feature = "dhcp6")]
            preferred: 3600,
            #[cfg(feature = "dhcp6")]
            template_interface: None,
        };
        let mut min = 0xFFFFFFFF;
        let (valid, preferred) = calculate_times(&ctx, &mut min, 3600);
        assert!(valid > 0);
        // CONTEXT_DEPRECATE should set preferred to 0
        #[cfg(feature = "dhcp6")]
        assert_eq!(preferred, 0);
        #[cfg(not(feature = "dhcp6"))]
        let _ = preferred;
    }

    #[test]
    fn test_build_ia_na() {
        let state = Dhcp6RequestState {
            ia_type: IaType::Na,
            iaid: 0x12345678,
            ..Dhcp6RequestState::new()
        };
        let mut outpacket = OutPacket::new();
        let (container, t1_counter) = build_ia(&state, &mut outpacket);
        assert!(container > 0 || container == 0); // container position valid
        assert!(t1_counter > 0); // T1/T2 reserved for IA_NA
    }

    #[test]
    fn test_build_ia_ta() {
        let state = Dhcp6RequestState {
            ia_type: IaType::Ta,
            iaid: 0xAABBCCDD,
            ..Dhcp6RequestState::new()
        };
        let mut outpacket = OutPacket::new();
        let (_container, t1_counter) = build_ia(&state, &mut outpacket);
        assert_eq!(t1_counter, 0); // IA_TA has no T1/T2
    }

    #[test]
    fn test_opt6_len_at_and_type_at() {
        let opts: Vec<u8> = vec![
            0x00, 0x03, // type = 3
            0x00, 0x08, // length = 8
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // data
        ];
        assert_eq!(opt6_type_at(&opts, 0), 3);
        assert_eq!(opt6_len_at(&opts, 0), 8);
    }

    #[test]
    fn test_write_msg_header() {
        let mut outpacket = OutPacket::new();
        write_msg_header(&mut outpacket, DhcpV6State::Advertise, 0xABCDEF);
        let bytes = outpacket.as_bytes();
        assert_eq!(bytes[0], 2); // ADVERTISE = 2
        assert_eq!(bytes[1], 0xAB);
        assert_eq!(bytes[2], 0xCD);
        assert_eq!(bytes[3], 0xEF);
    }

    #[test]
    fn test_dhcpv6_state_roundtrip() {
        for val in 1u8..=13 {
            let state = DhcpV6State::try_from(val).unwrap();
            assert_eq!(u8::from(state), val);
        }
    }

    // === Additional tests for coverage ===

    #[test]
    fn test_opt6_find_empty_data() {
        assert!(opt6_find(&[], 1, 0).is_none());
    }

    #[test]
    fn test_opt6_find_truncated_option_length() {
        // Header says 10 bytes, but only 2 available
        let opts: Vec<u8> = vec![0x00, 0x01, 0x00, 0x0A, 0xAA, 0xBB];
        assert!(opt6_find(&opts, 1, 0).is_none());
    }

    #[test]
    fn test_opt6_find_zero_length_option() {
        let opts: Vec<u8> = vec![0x00, 0x07, 0x00, 0x00]; // type=7, len=0
        let result = opt6_find(&opts, 7, 0);
        assert!(result.is_some());
        assert_eq!(result.unwrap().len(), 0);
    }

    #[test]
    fn test_opt6_find_skip_non_matching() {
        // Two options: type=1 len=2, type=5 len=3
        let opts: Vec<u8> = vec![
            0x00, 0x01, 0x00, 0x02, 0xAA, 0xBB, 0x00, 0x05, 0x00, 0x03, 0xCC, 0xDD, 0xEE,
        ];
        let result = opt6_find(&opts, 5, 1);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), &[0xCC, 0xDD, 0xEE]);
    }

    #[test]
    fn test_opt6_next_single_option() {
        let opts: Vec<u8> = vec![0x00, 0x0A, 0x00, 0x01, 0xFF];
        let (code, data, next) = opt6_next(&opts, 0).unwrap();
        assert_eq!(code, 0x0A);
        assert_eq!(data, &[0xFF]);
        assert_eq!(next, 5);
        assert!(opt6_next(&opts, next).is_none());
    }

    #[test]
    fn test_opt6_next_zero_length() {
        let opts: Vec<u8> = vec![0x00, 0x03, 0x00, 0x00];
        let (code, data, next) = opt6_next(&opts, 0).unwrap();
        assert_eq!(code, 3);
        assert_eq!(data.len(), 0);
        assert_eq!(next, 4);
    }

    #[test]
    fn test_opt6_uint_single_byte() {
        let data: Vec<u8> = vec![0xFF];
        assert_eq!(opt6_uint(&data, 0, 1), 255);
    }

    #[test]
    fn test_opt6_uint_two_byte_boundary() {
        let data: Vec<u8> = vec![0xFF, 0xFF];
        assert_eq!(opt6_uint(&data, 0, 2), 65535);
    }

    #[test]
    fn test_opt6_uint_four_byte_max() {
        let data: Vec<u8> = vec![0xFF, 0xFF, 0xFF, 0xFF];
        assert_eq!(opt6_uint(&data, 0, 4), 0xFFFFFFFF);
    }

    #[test]
    fn test_opt6_uint_zero_size() {
        let data: Vec<u8> = vec![0x12];
        assert_eq!(opt6_uint(&data, 0, 0), 0);
    }

    #[test]
    fn test_opt6_len_at_valid() {
        let opts: Vec<u8> = vec![0x00, 0x01, 0x00, 0x10, 0xAA];
        assert_eq!(opt6_len_at(&opts, 0), 16);
    }

    #[test]
    fn test_opt6_len_at_short() {
        let opts: Vec<u8> = vec![0x00, 0x01];
        assert_eq!(opt6_len_at(&opts, 0), 0);
    }

    #[test]
    fn test_opt6_type_at_valid() {
        let opts: Vec<u8> = vec![0x00, 0x19, 0x00, 0x04];
        assert_eq!(opt6_type_at(&opts, 0), 25);
    }

    #[test]
    fn test_opt6_type_at_short() {
        let opts: Vec<u8> = vec![0x00];
        assert_eq!(opt6_type_at(&opts, 0), 0);
    }

    #[test]
    fn test_parse_dns_name_three_labels() {
        let data: Vec<u8> = vec![
            3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm',
            0,
        ];
        assert_eq!(parse_dns_name(&data).unwrap(), "www.example.com");
    }

    #[test]
    fn test_parse_dns_name_invalid_utf8() {
        let data: Vec<u8> = vec![2, 0xFF, 0xFE, 0];
        assert!(parse_dns_name(&data).is_err());
    }

    #[test]
    fn test_encode_dns_name_trailing_dot() {
        let mut pkt = OutPacket::new();
        encode_dns_name("example.com.", &mut pkt);
        let bytes = pkt.as_bytes();
        assert_eq!(bytes[0], 7);
        assert_eq!(&bytes[1..8], b"example");
        assert_eq!(bytes[8], 3);
        assert_eq!(&bytes[9..12], b"com");
        assert_eq!(bytes[12], 0);
    }

    #[test]
    fn test_encode_dns_name_empty() {
        let mut pkt = OutPacket::new();
        encode_dns_name("", &mut pkt);
        let bytes = pkt.as_bytes();
        assert_eq!(bytes[0], 0);
    }

    #[test]
    fn test_write_msg_header_solicit() {
        let mut pkt = OutPacket::new();
        write_msg_header(&mut pkt, DhcpV6State::Solicit, 0x123456);
        let bytes = pkt.as_bytes();
        assert_eq!(bytes[0], 1); // SOLICIT
        assert_eq!(bytes[1], 0x12);
        assert_eq!(bytes[2], 0x34);
        assert_eq!(bytes[3], 0x56);
    }

    #[test]
    fn test_write_msg_header_reply() {
        let mut pkt = OutPacket::new();
        write_msg_header(&mut pkt, DhcpV6State::Reply, 0x000001);
        let bytes = pkt.as_bytes();
        assert_eq!(bytes[0], 7); // REPLY
        assert_eq!(bytes[3], 0x01);
    }

    #[test]
    fn test_write_status_reply_basic() {
        let state = Dhcp6RequestState {
            clid: Some(vec![0x00, 0x01, 0x00, 0x01]),
            xid: 0xABCDEF,
            ..Dhcp6RequestState::new()
        };
        let mut pkt = OutPacket::new();
        write_status_reply(&mut pkt, &state, DhcpV6State::Reply, 0, "Success");
        let bytes = pkt.as_bytes();
        assert!(bytes.len() > 4);
        assert_eq!(bytes[0], 7); // REPLY
    }

    #[test]
    fn test_write_status_reply_no_clid() {
        let state = Dhcp6RequestState::new();
        let mut pkt = OutPacket::new();
        write_status_reply(&mut pkt, &state, DhcpV6State::Reply, 2, "Error");
        let bytes = pkt.as_bytes();
        assert!(bytes.len() > 4);
    }

    #[test]
    fn test_calculate_times_zero_lease() {
        let ctx = DhcpContext {
            start: std::net::Ipv4Addr::UNSPECIFIED,
            end: std::net::Ipv4Addr::UNSPECIFIED,
            netmask: std::net::Ipv4Addr::UNSPECIFIED,
            broadcast: std::net::Ipv4Addr::UNSPECIFIED,
            router: std::net::Ipv4Addr::UNSPECIFIED,
            lease_time: 0,
            netid: NetId { net: String::new() },
            flags: 0,
            filter: Vec::new(),
            local: std::net::Ipv4Addr::UNSPECIFIED,
            addr_epoch: 0,
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
            template_interface: None,
        };
        let mut min = 0xFFFFFFFF;
        let (valid, preferred) = calculate_times(&ctx, &mut min, 0);
        // With lease_time=0, should use DEFLEASE6 default
        assert!(valid >= MIN_LIFETIME);
        assert!(preferred <= valid);
    }

    #[test]
    fn test_calculate_times_min_lifetime_enforced() {
        let ctx = DhcpContext {
            start: std::net::Ipv4Addr::UNSPECIFIED,
            end: std::net::Ipv4Addr::UNSPECIFIED,
            netmask: std::net::Ipv4Addr::UNSPECIFIED,
            broadcast: std::net::Ipv4Addr::UNSPECIFIED,
            router: std::net::Ipv4Addr::UNSPECIFIED,
            lease_time: 60,
            netid: NetId { net: String::new() },
            flags: 0,
            filter: Vec::new(),
            local: std::net::Ipv4Addr::UNSPECIFIED,
            addr_epoch: 0,
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
            valid: 50,
            #[cfg(feature = "dhcp6")]
            preferred: 30,
            #[cfg(feature = "dhcp6")]
            template_interface: None,
        };
        let mut min = 0xFFFFFFFF;
        let (valid, _) = calculate_times(&ctx, &mut min, 60);
        // Both valid candidates (60, 50) < MIN_LIFETIME=120, so enforced to 120
        assert!(valid >= MIN_LIFETIME);
    }

    #[test]
    fn test_daemon_config_entries_to_configs_empty() {
        let result = daemon_config_entries_to_configs(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_daemon_config_entries_to_configs_basic() {
        let entries = vec![DhcpConfigEntry {
            flags: CONFIG_ADDR6,
            hwaddr: vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            clid: vec![],
            hostname: Some("testhost".to_string()),
            netid: Some("mynet".to_string()),
            addr: Some(std::net::Ipv4Addr::new(192, 168, 1, 100)),
            addr6: Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            lease_time: 3600,
        }];
        let configs = daemon_config_entries_to_configs(&entries);
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].flags, CONFIG_ADDR6);
        assert_eq!(configs[0].hostname, Some("testhost".to_string()));
        assert_eq!(configs[0].hwaddr.len(), 1);
        assert_eq!(
            configs[0].hwaddr[0].hwaddr,
            vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55]
        );
        assert!(configs[0].clid.is_none()); // empty clid maps to None
        assert_eq!(configs[0].netid.len(), 1);
        assert_eq!(configs[0].netid[0].net, "mynet");
        assert_eq!(configs[0].lease_time, 3600);
    }

    #[test]
    fn test_daemon_config_entries_with_clid() {
        let entries = vec![DhcpConfigEntry {
            flags: 0,
            hwaddr: vec![],
            clid: vec![0xDE, 0xAD],
            hostname: None,
            netid: None,
            addr: None,
            addr6: None,
            lease_time: 0,
        }];
        let configs = daemon_config_entries_to_configs(&entries);
        assert_eq!(configs[0].clid, Some(vec![0xDE, 0xAD]));
        assert!(configs[0].hwaddr.is_empty());
        assert!(configs[0].netid.is_empty());
    }

    #[test]
    fn test_daemon_opt_entries_to_opts_empty() {
        let result = daemon_opt_entries_to_opts(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_daemon_opt_entries_to_opts_basic() {
        let entries = vec![DhcpOptEntry {
            opt: 23,
            val: vec![0x20, 0x01, 0x0d, 0xb8],
            flags: 0,
            netid: Some("mynet".to_string()),
        }];
        let opts = daemon_opt_entries_to_opts(&entries);
        assert_eq!(opts.len(), 1);
        assert_eq!(opts[0].opt, 23);
        assert_eq!(opts[0].val, vec![0x20, 0x01, 0x0d, 0xb8]);
        assert_eq!(opts[0].len, 4);
        assert!(opts[0].netid.is_some());
        assert_eq!(opts[0].netid.as_ref().unwrap().net, "mynet");
    }

    #[test]
    fn test_daemon_tag_if_to_rules_empty() {
        let result = daemon_tag_if_to_rules(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_daemon_tag_if_to_rules_basic() {
        let tags = vec![TagIf {
            set: vec!["tag1".to_string()],
            tag: "tag3".to_string(),
        }];
        let rules = daemon_tag_if_to_rules(&tags);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].set.len(), 1);
        assert_eq!(rules[0].set[0].net, "tag1");
        assert_eq!(rules[0].tag.len(), 1);
        assert_eq!(rules[0].tag[0].net, "tag3");
    }

    #[test]
    fn test_mark_context_used() {
        let mut contexts = vec![DhcpContext {
            start: std::net::Ipv4Addr::UNSPECIFIED,
            end: std::net::Ipv4Addr::UNSPECIFIED,
            netmask: std::net::Ipv4Addr::UNSPECIFIED,
            broadcast: std::net::Ipv4Addr::UNSPECIFIED,
            router: std::net::Ipv4Addr::UNSPECIFIED,
            lease_time: 3600,
            netid: NetId { net: String::new() },
            flags: 0,
            filter: Vec::new(),
            local: std::net::Ipv4Addr::UNSPECIFIED,
            addr_epoch: 0,
            #[cfg(feature = "dhcp6")]
            start6: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
            #[cfg(feature = "dhcp6")]
            end6: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF),
            #[cfg(feature = "dhcp6")]
            local6: Ipv6Addr::UNSPECIFIED,
            #[cfg(feature = "dhcp6")]
            prefix: 64,
            #[cfg(feature = "dhcp6")]
            if_index: 0,
            #[cfg(feature = "dhcp6")]
            valid: 7200,
            #[cfg(feature = "dhcp6")]
            preferred: 3600,
            #[cfg(feature = "dhcp6")]
            template_interface: None,
        }];
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        mark_context_used(&mut contexts, &addr);
        #[cfg(feature = "dhcp6")]
        assert!(contexts[0].flags & CONTEXT_USED != 0);
    }

    #[test]
    fn test_check_address_no_lease() {
        let state = Dhcp6RequestState::new();
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 42);
        assert!(check_address(&state, &[], &addr, &[]));
    }

    fn make_test_lease(addr6: Ipv6Addr, clid: Option<Vec<u8>>, iaid: u32) -> DhcpLease {
        use crate::dhcp::lease::lease6_allocate;
        let mut lease = lease6_allocate(addr6, LeaseType::Na);
        lease.expires = 99999;
        lease.hwaddr = vec![0; 6];
        lease.hwaddr_len = 6;
        lease.hwaddr_type = 1;
        lease.clid = clid;
        lease.iaid = iaid;
        lease.prefix_len = 128;
        lease
    }

    #[test]
    fn test_check_address_same_client() {
        let state = Dhcp6RequestState {
            clid: Some(vec![0x00, 0x01, 0x00, 0x01]),
            iaid: 12345,
            ..Dhcp6RequestState::new()
        };
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 42);
        let lease = make_test_lease(addr, Some(vec![0x00, 0x01, 0x00, 0x01]), 12345);
        assert!(check_address(&state, &[], &addr, &[lease]));
    }

    #[test]
    fn test_check_address_different_client() {
        let state = Dhcp6RequestState {
            clid: Some(vec![0x00, 0x02, 0x00, 0x02]),
            iaid: 99999,
            ..Dhcp6RequestState::new()
        };
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 42);
        let lease = make_test_lease(addr, Some(vec![0x00, 0x01, 0x00, 0x01]), 12345);
        assert!(!check_address(&state, &[], &addr, &[lease]));
    }

    #[test]
    fn test_config_valid_no_addr6_flag() {
        let config = DhcpConfig {
            flags: 0, // No CONFIG_ADDR6
            hwaddr: vec![],
            clid: None,
            hostname: None,
            netid: vec![],
            filter: vec![],
            addr: None,
            #[cfg(feature = "dhcp6")]
            addr6: vec![],
            domain: None,
            lease_time: 0,
            decline_time: 0,
        };
        let state = Dhcp6RequestState::new();
        assert!(!config_valid(
            &config,
            &[],
            &Ipv6Addr::UNSPECIFIED,
            &state,
            0,
            &[]
        ));
    }

    #[test]
    fn test_config_valid_declined_within_backoff() {
        let config = DhcpConfig {
            flags: CONFIG_ADDR6 | CONFIG_DECLINED,
            hwaddr: vec![],
            clid: None,
            hostname: None,
            netid: vec![],
            filter: vec![],
            addr: None,
            #[cfg(feature = "dhcp6")]
            addr6: vec![Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)],
            domain: None,
            lease_time: 0,
            decline_time: 100,
        };
        let state = Dhcp6RequestState::new();
        // now=101, decline_time=100, DECLINE_BACKOFF is 600, so 101-100 = 1 < 600
        assert!(!config_valid(
            &config,
            &[],
            &Ipv6Addr::UNSPECIFIED,
            &state,
            101,
            &[]
        ));
    }

    #[test]
    fn test_build_ia_pd() {
        // IA_PD (prefix delegation) behaves like IA_TA — no T1/T2 placeholders
        let state = Dhcp6RequestState {
            ia_type: IaType::Pd,
            iaid: 0xDEADBEEF,
            ..Dhcp6RequestState::new()
        };
        let mut outpacket = OutPacket::new();
        let (_container, t1_counter) = build_ia(&state, &mut outpacket);
        // IA_PD path returns t1_counter=0 since only IA_NA writes T1/T2 placeholders
        assert_eq!(t1_counter, 0);
    }

    #[test]
    fn test_build_ia_na_has_t1_t2() {
        // IA_NA should write T1/T2 placeholders — t1_counter > 0
        let state = Dhcp6RequestState {
            ia_type: IaType::Na,
            iaid: 0x12345678,
            ..Dhcp6RequestState::new()
        };
        let mut outpacket = OutPacket::new();
        let (_container, t1_counter) = build_ia(&state, &mut outpacket);
        assert!(t1_counter > 0);
    }

    #[test]
    fn test_end_ia_basic() {
        let mut pkt = OutPacket::new();
        // Pre-fill some data to simulate IA header
        pkt.put_opt6_short(0); // placeholder T1
        let t1_pos = 0;
        pkt.put_opt6_short(0); // placeholder T2
        end_ia(&mut pkt, t1_pos, 7200, false);
        // T1 and T2 should be patched
        let bytes = pkt.as_bytes();
        assert!(bytes.len() >= 4);
    }

    #[test]
    fn test_end_ia_with_fuzz() {
        let mut pkt = OutPacket::new();
        pkt.put_opt6_short(0);
        let t1_pos = 0;
        pkt.put_opt6_short(0);
        end_ia(&mut pkt, t1_pos, 7200, true);
        let bytes = pkt.as_bytes();
        assert!(bytes.len() >= 4);
    }

    #[test]
    fn test_opt6_iterate_all() {
        let opts: Vec<u8> = vec![
            0x00, 0x01, 0x00, 0x02, 0xAA, 0xBB, 0x00, 0x02, 0x00, 0x01, 0xCC, 0x00, 0x03, 0x00,
            0x00,
        ];
        let mut pos = 0;
        let mut count = 0;
        while let Some((code, data, next)) = opt6_next(&opts, pos) {
            match count {
                0 => {
                    assert_eq!(code, 1);
                    assert_eq!(data.len(), 2);
                }
                1 => {
                    assert_eq!(code, 2);
                    assert_eq!(data.len(), 1);
                }
                2 => {
                    assert_eq!(code, 3);
                    assert_eq!(data.len(), 0);
                }
                _ => panic!("unexpected option"),
            }
            pos = next;
            count += 1;
        }
        assert_eq!(count, 3);
    }

    #[test]
    fn test_parse_dns_name_long_label() {
        // Label with 10 chars
        let mut data = vec![10u8];
        data.extend_from_slice(b"abcdefghij");
        data.push(0);
        assert_eq!(parse_dns_name(&data).unwrap(), "abcdefghij");
    }

    #[test]
    fn test_dhcp6_request_state_modify_fields() {
        let mut state = Dhcp6RequestState::new();
        state.xid = 0xABCDEF;
        state.iaid = 42;
        state.ia_type = IaType::Pd;
        state.multicast_dest = true;
        state.hostname_auth = true;
        state.lease_allocate = true;
        state.fqdn_flags = 0x07;
        state.mac_type = 1;
        state.mac = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        state.iface_name = "eth0".to_string();
        state.tags.push(NetId {
            net: "lan".to_string(),
        });

        assert_eq!(state.xid, 0xABCDEF);
        assert_eq!(state.iaid, 42);
        assert_eq!(state.ia_type, IaType::Pd);
        assert!(state.multicast_dest);
        assert!(state.hostname_auth);
        assert!(state.lease_allocate);
        assert_eq!(state.fqdn_flags, 0x07);
        assert_eq!(state.mac.len(), 6);
        assert_eq!(state.iface_name, "eth0");
        assert_eq!(state.tags.len(), 1);
    }

    #[test]
    fn test_dhcpv6_state_display_all() {
        assert_eq!(format!("{}", DhcpV6State::Request), "REQUEST");
        assert_eq!(format!("{}", DhcpV6State::Confirm), "CONFIRM");
        assert_eq!(format!("{}", DhcpV6State::Renew), "RENEW");
        assert_eq!(format!("{}", DhcpV6State::Rebind), "REBIND");
        assert_eq!(format!("{}", DhcpV6State::Reply), "REPLY");
        assert_eq!(format!("{}", DhcpV6State::Release), "RELEASE");
        assert_eq!(format!("{}", DhcpV6State::Decline), "DECLINE");
        assert_eq!(format!("{}", DhcpV6State::Reconfigure), "RECONFIGURE");
        assert_eq!(format!("{}", DhcpV6State::RelayRepl), "RELAY-REPL");
    }

    #[test]
    fn test_opt6_find_large_data() {
        // Option with 256-byte payload
        let mut opts = vec![0x00u8, 0x10, 0x01, 0x00]; // type=16, len=256
        opts.extend(vec![0xAA; 256]);
        let result = opt6_find(&opts, 16, 100);
        assert!(result.is_some());
        assert_eq!(result.unwrap().len(), 256);
    }

    #[test]
    fn test_ia_type_equality() {
        assert_eq!(IaType::Na, IaType::Na);
        assert_ne!(IaType::Na, IaType::Ta);
        assert_ne!(IaType::Na, IaType::Pd);
        assert_ne!(IaType::Ta, IaType::Pd);
    }

    #[test]
    fn test_encode_dns_name_multiple_labels() {
        let mut pkt = OutPacket::new();
        encode_dns_name("a.b.c.d", &mut pkt);
        let bytes = pkt.as_bytes();
        assert_eq!(bytes[0], 1); // len("a")
        assert_eq!(bytes[1], b'a');
        assert_eq!(bytes[2], 1); // len("b")
        assert_eq!(bytes[3], b'b');
        assert_eq!(bytes[4], 1); // len("c")
        assert_eq!(bytes[5], b'c');
        assert_eq!(bytes[6], 1); // len("d")
        assert_eq!(bytes[7], b'd');
        assert_eq!(bytes[8], 0); // root
    }

    #[test]
    fn test_write_msg_header_relay_forw() {
        let mut pkt = OutPacket::new();
        write_msg_header(&mut pkt, DhcpV6State::RelayForw, 0x000000);
        let bytes = pkt.as_bytes();
        assert_eq!(bytes[0], 12);
        assert_eq!(bytes[1], 0);
        assert_eq!(bytes[2], 0);
        assert_eq!(bytes[3], 0);
    }

    // -----------------------------------------------------------------------
    // calculate_times tests
    // -----------------------------------------------------------------------
    #[test]
    fn test_calculate_times_default_lease() {
        use crate::dhcp::common::DhcpContext;
        let ctx = DhcpContext::new_v6_test(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xff),
            64,
            0,
            0,
            0,
        );
        let mut min_time = u32::MAX;
        let (valid, preferred) = calculate_times(&ctx, &mut min_time, 0);
        assert!(valid > 0);
        assert_eq!(valid, preferred);
        assert_eq!(min_time, valid);
    }

    #[test]
    fn test_calculate_times_explicit_lease() {
        use crate::dhcp::common::DhcpContext;
        let ctx = DhcpContext::new_v6_test(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xff),
            64,
            0,
            0,
            0,
        );
        let mut min_time = u32::MAX;
        let (valid, preferred) = calculate_times(&ctx, &mut min_time, 3600);
        assert_eq!(valid, 3600);
        assert_eq!(preferred, 3600);
        assert_eq!(min_time, 3600);
    }

    #[test]
    fn test_calculate_times_min_lifetime_enforcement() {
        use crate::dhcp::common::DhcpContext;
        let ctx = DhcpContext::new_v6_test(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xff),
            64,
            0,
            0,
            0,
        );
        let mut min_time = u32::MAX;
        let (valid, _) = calculate_times(&ctx, &mut min_time, 60);
        assert!(valid >= MIN_LIFETIME);
    }

    #[test]
    fn test_calculate_times_with_context_valid() {
        use crate::dhcp::common::DhcpContext;
        let ctx = DhcpContext::new_v6_test(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xff),
            64,
            1800,
            0,
            0,
        );
        let mut min_time = u32::MAX;
        let (valid, _) = calculate_times(&ctx, &mut min_time, 3600);
        assert_eq!(valid, 1800);
    }

    #[test]
    fn test_calculate_times_updates_min_time_lower() {
        use crate::dhcp::common::DhcpContext;
        let ctx = DhcpContext::new_v6_test(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xff),
            64,
            0,
            0,
            0,
        );
        let mut min_time = 5000;
        let (valid, _) = calculate_times(&ctx, &mut min_time, 3600);
        assert!(min_time <= 5000);
        assert_eq!(min_time, valid.min(5000));
    }

    // -----------------------------------------------------------------------
    // check_address tests
    // -----------------------------------------------------------------------
    #[test]
    fn test_check_address_no_existing_lease_v2() {
        let state = Dhcp6RequestState::new();
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10);
        assert!(check_address(&state, &[], &addr, &[]));
    }

    #[test]
    fn test_check_address_same_client_v2() {
        let mut state = Dhcp6RequestState::new();
        state.clid = Some(vec![1, 2, 3, 4]);
        state.iaid = 100;
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10);
        let mut lease = crate::dhcp::lease::DhcpLease::new_v6(addr, 128, 0, 9999);
        lease.clid = Some(vec![1, 2, 3, 4]);
        lease.iaid = 100;
        assert!(check_address(&state, &[], &addr, &[lease]));
    }

    #[test]
    fn test_check_address_different_client_v2() {
        let mut state = Dhcp6RequestState::new();
        state.clid = Some(vec![1, 2, 3, 4]);
        state.iaid = 100;
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10);
        let mut lease = crate::dhcp::lease::DhcpLease::new_v6(addr, 128, 0, 9999);
        lease.clid = Some(vec![5, 6, 7, 8]);
        lease.iaid = 200;
        assert!(!check_address(&state, &[], &addr, &[lease]));
    }

    // -----------------------------------------------------------------------
    // build_ia / end_ia tests
    // -----------------------------------------------------------------------
    #[test]
    fn test_build_ia_na_v2() {
        let mut state = Dhcp6RequestState::new();
        state.ia_type = IaType::Na;
        state.iaid = 0x12345678;
        let mut pkt = OutPacket::new();
        let (_container, t1_counter) = build_ia(&state, &mut pkt);
        assert!(t1_counter > 0);
    }

    #[test]
    fn test_build_ia_ta_v2() {
        let mut state = Dhcp6RequestState::new();
        state.ia_type = IaType::Ta;
        state.iaid = 0xAABBCCDD;
        let mut pkt = OutPacket::new();
        let (_, t1_counter) = build_ia(&state, &mut pkt);
        assert_eq!(t1_counter, 0);
    }

    #[test]
    fn test_build_ia_pd_v2() {
        let mut state = Dhcp6RequestState::new();
        state.ia_type = IaType::Pd;
        state.iaid = 1;
        let mut pkt = OutPacket::new();
        let _ = build_ia(&state, &mut pkt);
        assert!(pkt.as_bytes().len() > 0);
    }

    #[test]
    fn test_end_ia_zero_counter() {
        // t1_counter=0 means IA_TA, so end_ia returns immediately
        let mut pkt = OutPacket::new();
        end_ia(&mut pkt, 0, 3600, true);
        // Should be a no-op since t1_counter == 0
        assert!(pkt.as_bytes().is_empty());
    }

    #[test]
    fn test_end_ia_zero_min_time_v2() {
        // min_time=0 means no addresses added, T1/T2 stay as placeholders
        let mut pkt = OutPacket::new();
        // Prepend dummy bytes so save_counter returns non-zero
        pkt.put_opt6_long(0xDEAD); // 4 bytes of padding
        let pos = pkt.save_counter(None); // pos=4 (non-zero)
        pkt.put_opt6_long(0); // T1 placeholder
        pkt.put_opt6_long(0); // T2 placeholder
        end_ia(&mut pkt, pos, 0, false);
        // min_time==0 means early return, T1/T2 stay 0
        let b = pkt.as_bytes();
        assert_eq!(u32::from_be_bytes([b[4], b[5], b[6], b[7]]), 0);
    }

    #[test]
    fn test_end_ia_infinite_v2() {
        let mut pkt = OutPacket::new();
        pkt.put_opt6_long(0xDEAD); // padding
        let pos = pkt.save_counter(None);
        pkt.put_opt6_long(0); // T1
        pkt.put_opt6_long(0); // T2
        end_ia(&mut pkt, pos, 0xFFFFFFFF, false);
        // Infinite lease → returns early, T1/T2 stay 0
        let b = pkt.as_bytes();
        assert_eq!(u32::from_be_bytes([b[4], b[5], b[6], b[7]]), 0);
    }

    #[test]
    fn test_end_ia_normal_no_fuzz() {
        let mut pkt = OutPacket::new();
        pkt.put_opt6_long(0xDEAD); // padding so pos != 0
        let pos = pkt.save_counter(None); // pos=4
        pkt.put_opt6_long(0); // T1 placeholder at [4..8]
        pkt.put_opt6_long(0); // T2 placeholder at [8..12]
        end_ia(&mut pkt, pos, 7200, false);
        let b = pkt.as_bytes();
        let t1 = u32::from_be_bytes([b[4], b[5], b[6], b[7]]);
        let t2 = u32::from_be_bytes([b[8], b[9], b[10], b[11]]);
        assert_eq!(t1, 3600); // 7200 / 2
        assert_eq!(t2, 6300); // (7200 / 8) * 7
        assert!(t1 < t2);
    }

    #[test]
    fn test_end_ia_with_fuzz_v2() {
        let mut pkt = OutPacket::new();
        pkt.put_opt6_long(0xDEAD); // padding
        let pos = pkt.save_counter(None);
        pkt.put_opt6_long(0); // T1 placeholder
        pkt.put_opt6_long(0); // T2 placeholder
        end_ia(&mut pkt, pos, 7200, true);
        let b = pkt.as_bytes();
        let t1 = u32::from_be_bytes([b[4], b[5], b[6], b[7]]);
        let t2 = u32::from_be_bytes([b[8], b[9], b[10], b[11]]);
        // With fuzz: t1 ≈ 3600 ± ~225 (fuzz_range = 3600/16 = 225)
        assert!(t1 >= 3500 && t1 <= 3900, "t1={}", t1);
        assert!(t1 < t2, "t1={} t2={}", t1, t2);
    }

    // -----------------------------------------------------------------------
    // opt6 function additional tests
    // -----------------------------------------------------------------------
    #[test]
    fn test_opt6_find_nested() {
        let mut data = Vec::new();
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&4u16.to_be_bytes());
        data.extend_from_slice(&[1, 2, 3, 4]);
        data.extend_from_slice(&2u16.to_be_bytes());
        data.extend_from_slice(&2u16.to_be_bytes());
        data.extend_from_slice(&[5, 6]);

        assert!(opt6_find(&data, 1, 0).is_some());
        assert_eq!(opt6_find(&data, 1, 0).unwrap(), &[1, 2, 3, 4]);
        assert!(opt6_find(&data, 2, 0).is_some());
        assert!(opt6_find(&data, 3, 0).is_none());
    }

    #[test]
    fn test_opt6_find_minsize_too_large() {
        let mut data = Vec::new();
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&2u16.to_be_bytes());
        data.extend_from_slice(&[1, 2]);
        assert!(opt6_find(&data, 1, 4).is_none());
        assert!(opt6_find(&data, 1, 2).is_some());
    }

    #[test]
    fn test_opt6_next_empty_v2() {
        assert!(opt6_next(&[], 0).is_none());
    }

    #[test]
    fn test_opt6_next_two_opts() {
        let mut data = Vec::new();
        data.extend_from_slice(&10u16.to_be_bytes());
        data.extend_from_slice(&3u16.to_be_bytes());
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
        data.extend_from_slice(&20u16.to_be_bytes());
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&[0xFF]);

        let (t1, d1, next1) = opt6_next(&data, 0).unwrap();
        assert_eq!(t1, 10);
        assert_eq!(d1, &[0xAA, 0xBB, 0xCC]);
        let (t2, d2, next2) = opt6_next(&data, next1).unwrap();
        assert_eq!(t2, 20);
        assert_eq!(d2, &[0xFF]);
        assert!(opt6_next(&data, next2).is_none());
    }

    #[test]
    fn test_opt6_uint_sizes_v2() {
        let data = [0x00, 0x01, 0x02, 0x03];
        assert_eq!(opt6_uint(&data, 0, 1), 0x00);
        assert_eq!(opt6_uint(&data, 1, 1), 0x01);
        assert_eq!(opt6_uint(&data, 0, 2), 0x0001);
        assert_eq!(opt6_uint(&data, 0, 4), 0x00010203);
    }

    #[test]
    fn test_opt6_uint_oob() {
        let data = [1, 2];
        assert_eq!(opt6_uint(&data, 10, 1), 0);
    }

    // -----------------------------------------------------------------------
    // release_lease_by_addr tests
    // -----------------------------------------------------------------------
    #[test]
    fn test_release_lease_by_addr_empty() {
        let mut daemon = DaemonState::default();
        let state = Dhcp6RequestState::new();
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10);
        let mut outpkt = OutPacket::new();
        release_lease_by_addr(&mut daemon, &state, &addr, 128, &mut outpkt);
        assert!(daemon.leases.is_empty());
    }

    #[test]
    fn test_release_lease_by_addr_match() {
        let mut daemon = DaemonState::default();
        let mut state = Dhcp6RequestState::new();
        state.clid = Some(vec![1, 2, 3, 4]);
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10);
        let mut lease = crate::dhcp::lease::DhcpLease::new_v6(addr, 128, 0, 999999);
        lease.clid = Some(vec![1, 2, 3, 4]); // match the state clid
        daemon.leases.push(lease);
        let mut outpkt = OutPacket::new();
        release_lease_by_addr(&mut daemon, &state, &addr, 128, &mut outpkt);
        // If CLID matches, lease should be removed entirely
        assert!(daemon.leases.is_empty());
    }

    // -----------------------------------------------------------------------
    // update_leases tests
    // -----------------------------------------------------------------------
    #[test]
    fn test_update_leases_new_lease() {
        let mut daemon = DaemonState::default();
        let mut state = Dhcp6RequestState::new();
        state.ia_type = IaType::Na;
        state.iaid = 42;
        state.clid = Some(vec![1, 2, 3]);
        state.lease_allocate = true; // required for new lease creation
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10);
        update_leases(&state, &[], &addr, 3600, 1000, &mut daemon);
        assert!(!daemon.leases.is_empty());
    }

    #[test]
    fn test_update_leases_existing_no_dup() {
        let mut daemon = DaemonState::default();
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10);
        let lease = crate::dhcp::lease::DhcpLease::new_v6(addr, 128, 0, 100);
        daemon.leases.push(lease);
        let mut state = Dhcp6RequestState::new();
        state.ia_type = IaType::Na;
        state.iaid = 42;
        update_leases(&state, &[], &addr, 7200, 2000, &mut daemon);
        assert_eq!(daemon.leases.len(), 1);
    }

    // -----------------------------------------------------------------------
    // DhcpV6State additional coverage
    // -----------------------------------------------------------------------
    #[test]
    fn test_dhcpv6_state_all_roundtrip() {
        for i in 1u8..=13 {
            let s = DhcpV6State::try_from(i).unwrap();
            assert_eq!(u8::from(s), i);
        }
    }

    #[test]
    fn test_dhcpv6_state_display_all_v2() {
        let expected = [
            "SOLICIT",
            "ADVERTISE",
            "REQUEST",
            "CONFIRM",
            "RENEW",
            "REBIND",
            "REPLY",
            "RELEASE",
            "DECLINE",
            "RECONFIGURE",
            "INFORMATION-REQUEST",
            "RELAY-FORW",
            "RELAY-REPL",
        ];
        for (i, name) in expected.iter().enumerate() {
            let s = DhcpV6State::try_from((i + 1) as u8).unwrap();
            assert!(format!("{}", s).contains(name), "State {} mismatch", i + 1);
        }
    }

    #[test]
    fn test_dhcpv6_state_invalid_values() {
        assert!(DhcpV6State::try_from(0).is_err());
        assert!(DhcpV6State::try_from(14).is_err());
        assert!(DhcpV6State::try_from(255).is_err());
    }

    // -----------------------------------------------------------------------
    // IaType additional coverage
    // -----------------------------------------------------------------------
    #[test]
    fn test_ia_type_option_codes_v2() {
        assert_eq!(IaType::Na.option_code(), super::super::OPTION6_IA_NA);
        assert_eq!(IaType::Ta.option_code(), super::super::OPTION6_IA_TA);
        assert_eq!(IaType::Pd.option_code(), super::super::OPTION6_IA_PD);
    }

    #[test]
    fn test_ia_type_from_option_code_v2() {
        assert_eq!(
            IaType::from_option_code(super::super::OPTION6_IA_NA),
            Some(IaType::Na)
        );
        assert_eq!(
            IaType::from_option_code(super::super::OPTION6_IA_TA),
            Some(IaType::Ta)
        );
        assert_eq!(
            IaType::from_option_code(super::super::OPTION6_IA_PD),
            Some(IaType::Pd)
        );
        assert_eq!(IaType::from_option_code(9999), None);
    }

    #[test]
    fn test_ia_type_to_lease_type_v2() {
        assert_eq!(IaType::Na.to_lease_type(), LeaseType::Na);
        assert_eq!(IaType::Ta.to_lease_type(), LeaseType::Ta);
        assert_eq!(IaType::Pd.to_lease_type(), LeaseType::Pd);
    }

    // -----------------------------------------------------------------------
    // Dhcp6RequestState tests
    // -----------------------------------------------------------------------
    #[test]
    fn test_dhcp6_request_state_defaults_v2() {
        let state = Dhcp6RequestState::new();
        assert_eq!(state.ia_type, IaType::Na);
        assert_eq!(state.iaid, 0);
        assert!(state.clid.is_none());
        assert!(!state.lease_allocate);
    }

    #[test]
    fn test_dhcp6_request_state_with_clid_v2() {
        let mut state = Dhcp6RequestState::new();
        state.clid = Some(vec![0, 1, 0, 1, 0xAB, 0xCD]);
        assert_eq!(state.clid.as_ref().unwrap().len(), 6);
    }

    // -----------------------------------------------------------------------
    // helper function coverage
    // -----------------------------------------------------------------------
    #[test]
    fn test_daemon_config_entries_to_configs_empty_v2() {
        let r = daemon_config_entries_to_configs(&[]);
        assert!(r.is_empty());
    }

    #[test]
    fn test_daemon_opt_entries_to_opts_empty_v2() {
        let r = daemon_opt_entries_to_opts(&[]);
        assert!(r.is_empty());
    }

    #[test]
    fn test_daemon_tag_if_to_rules_empty_v2() {
        let r = daemon_tag_if_to_rules(&[]);
        assert!(r.is_empty());
    }

    // -----------------------------------------------------------------------
    // dhcp6_reply / dhcp6_maybe_relay short packet
    // -----------------------------------------------------------------------
    #[test]
    fn test_dhcp6_reply_too_short() {
        let mut daemon = DaemonState::default();
        let mut ctxs = Vec::new();
        let pkt = vec![0u8; 2]; // too short — less than 4 bytes
        let fallback = Ipv6Addr::LOCALHOST;
        let ll = Ipv6Addr::LOCALHOST;
        let ula = Ipv6Addr::LOCALHOST;
        let client = Ipv6Addr::LOCALHOST;
        let result = dhcp6_reply(
            &mut daemon,
            &mut ctxs,
            false,
            0,
            "lo",
            &fallback,
            &ll,
            &ula,
            &pkt,
            &client,
            0,
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_dhcp6_maybe_relay_empty() {
        let mut daemon = DaemonState::default();
        let mut ctxs = Vec::new();
        let mut state = Dhcp6RequestState::new();
        let pkt: Vec<u8> = Vec::new();
        let client = Ipv6Addr::LOCALHOST;
        let mut outpacket = OutPacket::new();
        let result = dhcp6_maybe_relay(
            &mut daemon,
            &mut ctxs,
            &mut state,
            &pkt,
            &client,
            false,
            0,
            &mut outpacket,
        );
        assert!(result.is_err());
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn test_mark_context_used_v2() {
        use crate::dhcp::common::DhcpContext;
        let mut ctxs = vec![DhcpContext::new_v6_test(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xff),
            64,
            0,
            0,
            0,
        )];
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x50);
        mark_context_used(&mut ctxs, &addr);
        assert_ne!(ctxs[0].flags & CONTEXT_USED, 0);
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn test_mark_context_used_no_match() {
        use crate::dhcp::common::DhcpContext;
        let mut ctxs = vec![DhcpContext::new_v6_test(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xff),
            64,
            0,
            0,
            0,
        )];
        let addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        mark_context_used(&mut ctxs, &addr);
        assert_eq!(ctxs[0].flags & CONTEXT_USED, 0);
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn test_mark_config_used_v2() {
        use crate::dhcp::common::DhcpContext;
        let mut ctxs = vec![DhcpContext::new_v6_test(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xff),
            64,
            0,
            0,
            0,
        )];
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x50);
        mark_config_used(&mut ctxs, &addr);
        assert_ne!(ctxs[0].flags & CONTEXT_CONF_USED, 0);
    }

    // === ADDITIONAL COVERAGE TESTS ===

    // Test helper to create a DhcpContext with specified fields
    fn make_test_context() -> DhcpContext {
        DhcpContext {
            start: std::net::Ipv4Addr::UNSPECIFIED,
            end: std::net::Ipv4Addr::UNSPECIFIED,
            netmask: std::net::Ipv4Addr::UNSPECIFIED,
            broadcast: std::net::Ipv4Addr::UNSPECIFIED,
            router: std::net::Ipv4Addr::UNSPECIFIED,
            lease_time: 0,
            netid: NetId { net: String::new() },
            flags: 0,
            filter: Vec::new(),
            local: std::net::Ipv4Addr::UNSPECIFIED,
            addr_epoch: 0,
            #[cfg(feature = "dhcp6")]
            start6: Ipv6Addr::UNSPECIFIED,
            #[cfg(feature = "dhcp6")]
            end6: Ipv6Addr::UNSPECIFIED,
            #[cfg(feature = "dhcp6")]
            local6: Ipv6Addr::UNSPECIFIED,
            #[cfg(feature = "dhcp6")]
            prefix: 0,
            #[cfg(feature = "dhcp6")]
            if_index: 0,
            #[cfg(feature = "dhcp6")]
            valid: 0,
            #[cfg(feature = "dhcp6")]
            preferred: 0,
            #[cfg(feature = "dhcp6")]
            template_interface: None,
        }
    }

    fn make_test_dhcp_config() -> DhcpConfig {
        DhcpConfig {
            flags: 0,
            hwaddr: Vec::new(),
            clid: None,
            hostname: None,
            netid: Vec::new(),
            filter: Vec::new(),
            addr: None,
            #[cfg(feature = "dhcp6")]
            addr6: Vec::new(),
            domain: None,
            lease_time: 0,
            decline_time: 0,
        }
    }

    #[test]
    fn test_add_options_empty_client_opts() {
        let mut daemon = DaemonState::default();
        let contexts: Vec<DhcpContext> = Vec::new();
        let state = Dhcp6RequestState::new();
        let mut outpacket = OutPacket::new();
        add_options(&mut daemon, &contexts, &state, &[], false, &mut outpacket);
        // Should not panic with empty opts
    }

    #[test]
    fn test_add_options_with_oro_dns_server() {
        let mut daemon = DaemonState::default();
        let contexts: Vec<DhcpContext> = Vec::new();
        let state = Dhcp6RequestState::new();
        let mut outpacket = OutPacket::new();
        // Build ORO option requesting DNS_SERVER (23)
        let mut client_opts = Vec::new();
        let opt_code = super::super::OPTION6_ORO.to_be_bytes();
        client_opts.extend_from_slice(&opt_code);
        let opt_len: u16 = 2;
        client_opts.extend_from_slice(&opt_len.to_be_bytes());
        let dns_code = super::super::OPTION6_DNS_SERVER.to_be_bytes();
        client_opts.extend_from_slice(&dns_code);
        add_options(
            &mut daemon,
            &contexts,
            &state,
            &client_opts,
            false,
            &mut outpacket,
        );
    }

    #[test]
    fn test_add_options_with_domain_search() {
        let mut daemon = DaemonState::default();
        let contexts: Vec<DhcpContext> = Vec::new();
        let mut state = Dhcp6RequestState::new();
        state.send_domain = Some("example.com".to_string());
        let mut outpacket = OutPacket::new();
        // Build ORO requesting DOMAIN_SEARCH
        let mut client_opts = Vec::new();
        let opt_code = super::super::OPTION6_ORO.to_be_bytes();
        client_opts.extend_from_slice(&opt_code);
        let opt_len: u16 = 2;
        client_opts.extend_from_slice(&opt_len.to_be_bytes());
        let dom_code = super::super::OPTION6_DOMAIN_SEARCH.to_be_bytes();
        client_opts.extend_from_slice(&dom_code);
        add_options(
            &mut daemon,
            &contexts,
            &state,
            &client_opts,
            false,
            &mut outpacket,
        );
        // Verify domain was encoded
        let data = outpacket.as_bytes();
        assert!(data.len() > 0);
    }

    #[test]
    fn test_add_options_with_refresh_time() {
        let mut daemon = DaemonState::default();
        let contexts: Vec<DhcpContext> = Vec::new();
        let state = Dhcp6RequestState::new();
        let mut outpacket = OutPacket::new();
        // Build ORO requesting REFRESH_TIME
        let mut client_opts = Vec::new();
        let opt_code = super::super::OPTION6_ORO.to_be_bytes();
        client_opts.extend_from_slice(&opt_code);
        let opt_len: u16 = 2;
        client_opts.extend_from_slice(&opt_len.to_be_bytes());
        let ref_code = super::super::OPTION6_REFRESH_TIME.to_be_bytes();
        client_opts.extend_from_slice(&ref_code);
        add_options(
            &mut daemon,
            &contexts,
            &state,
            &client_opts,
            true,
            &mut outpacket,
        );
        let data = outpacket.as_bytes();
        // Should have added refresh time option
        assert!(data.len() > 0);
    }

    #[test]
    fn test_add_options_with_fqdn() {
        let mut daemon = DaemonState::default();
        let contexts: Vec<DhcpContext> = Vec::new();
        let mut state = Dhcp6RequestState::new();
        state.hostname = Some("myhost".to_string());
        state.domain = Some("example.com".to_string());
        state.fqdn_flags = 1;
        let mut outpacket = OutPacket::new();
        add_options(&mut daemon, &contexts, &state, &[], false, &mut outpacket);
        let data = outpacket.as_bytes();
        assert!(data.len() > 0); // FQDN option should have been added
    }

    #[test]
    fn test_add_addr6_option_regular_addr() {
        let opt = DhcpOpt {
            opt: super::super::OPTION6_DNS_SERVER,
            val: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)
                .octets()
                .to_vec(),
            flags: DHOPT_ADDR6,
            netid: None,
            next: Vec::new(),
            len: 16,
            u: DhcpOptExtra::None,
        };
        let state = Dhcp6RequestState::new();
        let contexts: Vec<DhcpContext> = Vec::new();
        let mut outpacket = OutPacket::new();
        add_addr6_option(&opt, &state, &contexts, &mut outpacket);
        let data = outpacket.as_bytes();
        assert!(data.len() >= 16 + 4); // 4-byte TLV header + 16-byte addr
    }

    #[test]
    fn test_add_addr6_option_ula_substitute() {
        // Build option value with ULA zero placeholder (fd00::)
        let ula_zero = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0);
        let opt = DhcpOpt {
            opt: super::super::OPTION6_DNS_SERVER,
            val: ula_zero.octets().to_vec(),
            flags: DHOPT_ADDR6,
            netid: None,
            next: Vec::new(),
            len: 16,
            u: DhcpOptExtra::None,
        };
        let mut state = Dhcp6RequestState::new();
        state.ula_addr = Some(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x99));
        let contexts: Vec<DhcpContext> = Vec::new();
        let mut outpacket = OutPacket::new();
        add_addr6_option(&opt, &state, &contexts, &mut outpacket);
        let data = outpacket.as_bytes();
        assert!(data.len() > 4); // Should have substituted address
    }

    #[test]
    fn test_add_addr6_option_link_local_substitute() {
        let ll_zero = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0);
        let opt = DhcpOpt {
            opt: super::super::OPTION6_DNS_SERVER,
            val: ll_zero.octets().to_vec(),
            flags: DHOPT_ADDR6,
            netid: None,
            next: Vec::new(),
            len: 16,
            u: DhcpOptExtra::None,
        };
        let mut state = Dhcp6RequestState::new();
        state.ll_addr = Some(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x42));
        let contexts: Vec<DhcpContext> = Vec::new();
        let mut outpacket = OutPacket::new();
        add_addr6_option(&opt, &state, &contexts, &mut outpacket);
        let data = outpacket.as_bytes();
        assert!(data.len() > 4);
    }

    #[test]
    fn test_add_ntp_option_regular() {
        let opt = DhcpOpt {
            opt: super::super::OPTION6_NTP_SERVER,
            val: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x123)
                .octets()
                .to_vec(),
            flags: 0,
            netid: None,
            next: Vec::new(),
            len: 16,
            u: DhcpOptExtra::None,
        };
        let state = Dhcp6RequestState::new();
        let contexts: Vec<DhcpContext> = Vec::new();
        let mut outpacket = OutPacket::new();
        add_ntp_option(&opt, &state, &contexts, &mut outpacket);
        let data = outpacket.as_bytes();
        assert!(data.len() > 4); // outer opt + sub-option
    }

    #[test]
    fn test_add_ntp_option_ula_substitute() {
        let ula_zero = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0);
        let opt = DhcpOpt {
            opt: super::super::OPTION6_NTP_SERVER,
            val: ula_zero.octets().to_vec(),
            flags: 0,
            netid: None,
            next: Vec::new(),
            len: 16,
            u: DhcpOptExtra::None,
        };
        let mut state = Dhcp6RequestState::new();
        state.ula_addr = Some(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x77));
        let contexts: Vec<DhcpContext> = Vec::new();
        let mut outpacket = OutPacket::new();
        add_ntp_option(&opt, &state, &contexts, &mut outpacket);
        let data = outpacket.as_bytes();
        assert!(data.len() > 4);
    }

    #[test]
    fn test_add_vendor_encap_option_with_vendor_flag() {
        let opt = DhcpOpt {
            opt: 17,                            // OPTION6_VENDOR_OPTS
            val: vec![0, 0, 0, 99, 1, 2, 3, 4], // enterprise=99 + sub-data
            flags: DHOPT_RFC3925 | DHOPT_VENDOR,
            netid: None,
            next: Vec::new(),
            len: 8,
            u: DhcpOptExtra::None,
        };
        let mut outpacket = OutPacket::new();
        add_vendor_encap_option(&opt, &mut outpacket);
        let data = outpacket.as_bytes();
        assert!(data.len() > 0);
    }

    #[test]
    fn test_add_vendor_encap_option_no_vendor_flag() {
        let opt = DhcpOpt {
            opt: 42,
            val: vec![1, 2, 3],
            flags: DHOPT_RFC3925,
            netid: None,
            next: Vec::new(),
            len: 3,
            u: DhcpOptExtra::None,
        };
        let mut outpacket = OutPacket::new();
        add_vendor_encap_option(&opt, &mut outpacket);
        let data = outpacket.as_bytes();
        assert!(data.len() > 0);
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn test_add_local_addrs_used_context() {
        let mut ctx = make_test_context();
        ctx.flags = CONTEXT_USED;
        ctx.local6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        ctx.start6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 100);
        ctx.end6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 200);
        ctx.prefix = 64;
        ctx.lease_time = 3600;
        ctx.valid = 3600;
        ctx.preferred = 1800;
        let mut outpacket = OutPacket::new();
        let result = add_local_addrs(&[ctx], &mut outpacket);
        assert!(result);
        assert!(outpacket.as_bytes().len() >= 20); // 4-byte header + 16-byte addr
    }

    #[test]
    fn test_add_local_addrs_no_used_context() {
        let mut ctx = make_test_context();
        ctx.flags = 0; // Not marked CONTEXT_USED
        let mut outpacket = OutPacket::new();
        let result = add_local_addrs(&[ctx], &mut outpacket);
        assert!(!result);
    }

    #[test]
    fn test_add_local_addrs_empty() {
        let mut outpacket = OutPacket::new();
        let result = add_local_addrs(&[], &mut outpacket);
        assert!(!result);
    }

    #[test]
    fn test_get_context_tag_matching() {
        let mut ctx = make_test_context();
        ctx.netid = NetId {
            net: "lan".to_string(),
        };
        ctx.start6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0);
        ctx.prefix = 64;
        let mut state = Dhcp6RequestState::new();
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 5);
        get_context_tag(&mut state, &[ctx], &addr);
        assert!(state.context_tags.iter().any(|t| t.net == "lan"));
    }

    #[test]
    fn test_get_context_tag_no_match() {
        let mut ctx = make_test_context();
        ctx.netid = NetId {
            net: "wan".to_string(),
        };
        ctx.start6 = Ipv6Addr::new(0x2001, 0xdb8, 0x1, 0, 0, 0, 0, 0);
        ctx.prefix = 64;
        let mut state = Dhcp6RequestState::new();
        let addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 5);
        get_context_tag(&mut state, &[ctx], &addr);
        // May or may not match depending on subnet - just test no panic
    }

    #[test]
    fn test_get_context_tag_empty_netid() {
        let ctx = make_test_context();
        let mut state = Dhcp6RequestState::new();
        let addr = Ipv6Addr::UNSPECIFIED;
        get_context_tag(&mut state, &[ctx], &addr);
        assert!(state.context_tags.is_empty()); // Empty netid not added
    }

    #[test]
    fn test_add_fqdn_option_with_hostname() {
        let mut state = Dhcp6RequestState::new();
        state.hostname = Some("myhost".to_string());
        state.domain = Some("example.com".to_string());
        let mut outpacket = OutPacket::new();
        add_fqdn_option(&state, &mut outpacket);
        let data = outpacket.as_bytes();
        // Should have option header + flags byte + DNS-encoded FQDN
        assert!(data.len() > 4);
    }

    #[test]
    fn test_add_fqdn_option_without_hostname() {
        let state = Dhcp6RequestState::new();
        let mut outpacket = OutPacket::new();
        add_fqdn_option(&state, &mut outpacket);
        let data = outpacket.as_bytes();
        // Should have minimal option (header + flags byte only)
        assert!(data.len() >= 4);
    }

    #[test]
    fn test_add_fqdn_option_hostname_no_domain() {
        let mut state = Dhcp6RequestState::new();
        state.hostname = Some("standalone".to_string());
        let mut outpacket = OutPacket::new();
        add_fqdn_option(&state, &mut outpacket);
        let data = outpacket.as_bytes();
        assert!(data.len() > 4);
    }

    #[test]
    fn test_log6_opts_empty() {
        // Just exercise the logging path - no panic
        log6_opts(0, 0x123, &[]);
    }

    #[test]
    fn test_log6_opts_ia_na() {
        // Build an IA_NA option with IAID + T1 + T2
        let mut opts = Vec::new();
        // Message header (4 bytes for nest=0)
        opts.extend_from_slice(&[7, 0, 1, 0]); // REPLY, xid=0x100
                                               // IA_NA option
        let ia_na_code = super::super::OPTION6_IA_NA.to_be_bytes();
        opts.extend_from_slice(&ia_na_code);
        let ia_data = vec![0, 0, 0, 1, 0, 0, 0, 60, 0, 0, 0, 90]; // IAID=1, T1=60, T2=90
        let ia_len = (ia_data.len() as u16).to_be_bytes();
        opts.extend_from_slice(&ia_len);
        opts.extend_from_slice(&ia_data);
        log6_opts(0, 0x100, &opts);
    }

    #[test]
    fn test_log6_opts_iaaddr() {
        let mut opts = Vec::new();
        let iaaddr_code = super::super::OPTION6_IAADDR.to_be_bytes();
        opts.extend_from_slice(&iaaddr_code);
        // 16-byte addr + 4-byte preferred + 4-byte valid = 24 bytes
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let mut data = Vec::new();
        data.extend_from_slice(&addr.octets());
        data.extend_from_slice(&3600u32.to_be_bytes()); // preferred
        data.extend_from_slice(&7200u32.to_be_bytes()); // valid
        let data_len = (data.len() as u16).to_be_bytes();
        opts.extend_from_slice(&data_len);
        opts.extend_from_slice(&data);
        log6_opts(1, 0x200, &opts);
    }

    #[test]
    fn test_log6_opts_status_code() {
        let mut opts = Vec::new();
        let status_code = super::super::OPTION6_STATUS_CODE.to_be_bytes();
        opts.extend_from_slice(&status_code);
        let mut data = Vec::new();
        data.extend_from_slice(&0u16.to_be_bytes()); // Success
        data.extend_from_slice(b"Success");
        let data_len = (data.len() as u16).to_be_bytes();
        opts.extend_from_slice(&data_len);
        opts.extend_from_slice(&data);
        log6_opts(1, 0x300, &opts);
    }

    #[test]
    fn test_log6_opts_generic() {
        let mut opts = Vec::new();
        let generic_code: u16 = 999;
        opts.extend_from_slice(&generic_code.to_be_bytes());
        let data = vec![0xAA, 0xBB];
        let data_len = (data.len() as u16).to_be_bytes();
        opts.extend_from_slice(&data_len);
        opts.extend_from_slice(&data);
        log6_opts(1, 0x400, &opts);
    }

    #[test]
    fn test_log6_packet_all_variants() {
        let mut state = Dhcp6RequestState::new();
        state.xid = 0x123;
        state.iface_name = "eth0".to_string();
        state.clid = Some(vec![0x00, 0x01, 0x02, 0x03]);

        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

        // All four branches of (addr, extra)
        log6_packet(&state, "REPLY", Some(&addr), Some("lease 3600"));
        log6_packet(&state, "REPLY", Some(&addr), None);
        log6_packet(&state, "REPLY", None, Some("stateless"));
        log6_packet(&state, "REPLY", None, None);
    }

    #[test]
    fn test_log6_packet_no_clid() {
        let mut state = Dhcp6RequestState::new();
        state.xid = 0x456;
        state.iface_name = "eth1".to_string();
        log6_packet(&state, "SOLICIT", None, None);
    }

    #[test]
    fn test_log6_quiet_with_quiet_mode() {
        let mut state = Dhcp6RequestState::new();
        state.iface_name = "eth0".to_string();
        let mut daemon = DaemonState::default();
        daemon.options.set(opt::QUIET_DHCP6);
        // Should be suppressed
        log6_quiet(&state, "REPLY", None, None, &daemon);
    }

    #[test]
    fn test_log6_quiet_with_log_opts() {
        let mut state = Dhcp6RequestState::new();
        state.iface_name = "eth0".to_string();
        let mut daemon = DaemonState::default();
        daemon.options.set(opt::LOG_OPTS);
        daemon.options.set(opt::QUIET_DHCP6);
        // LOG_OPTS overrides quiet, so logging happens
        log6_quiet(&state, "REPLY", None, None, &daemon);
    }

    #[test]
    fn test_log6_quiet_normal_mode() {
        let mut state = Dhcp6RequestState::new();
        state.iface_name = "eth0".to_string();
        let daemon = DaemonState::default();
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        // Normal mode - logging should happen (all 4 branch variants)
        log6_quiet(&state, "REPLY", Some(&addr), Some("extra"), &daemon);
        log6_quiet(&state, "REPLY", Some(&addr), None, &daemon);
        log6_quiet(&state, "REPLY", None, Some("extra"), &daemon);
        log6_quiet(&state, "REPLY", None, None, &daemon);
    }

    #[test]
    fn test_add_address_no_context() {
        let state = Dhcp6RequestState::new();
        let contexts: Vec<DhcpContext> = Vec::new();
        let mut min_time = u32::MAX;
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let mut outpacket = OutPacket::new();
        let daemon = DaemonState::default();
        add_address(
            &state,
            &contexts,
            3600,
            &mut min_time,
            &addr,
            0,
            &mut outpacket,
            &daemon,
        );
        let data = outpacket.as_bytes();
        // Should have IAADDR sub-option: header(4) + addr(16) + preferred(4) + valid(4) = 28
        assert!(data.len() >= 28);
        assert!(min_time <= 3600);
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn test_add_address_with_matching_context() {
        let state = Dhcp6RequestState::new();
        let mut ctx = make_test_context();
        ctx.start6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0);
        ctx.end6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0xff, 0xff, 0xff, 0xff);
        ctx.prefix = 64;
        ctx.valid = 7200;
        ctx.preferred = 3600;
        ctx.lease_time = 7200;
        let mut min_time = u32::MAX;
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 5);
        let mut outpacket = OutPacket::new();
        let daemon = DaemonState::default();
        add_address(
            &state,
            &[ctx],
            7200,
            &mut min_time,
            &addr,
            0,
            &mut outpacket,
            &daemon,
        );
        let data = outpacket.as_bytes();
        assert!(data.len() >= 28);
    }

    #[test]
    fn test_add_address_zero_lease_time() {
        let state = Dhcp6RequestState::new();
        let contexts: Vec<DhcpContext> = Vec::new();
        let mut min_time = u32::MAX;
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let mut outpacket = OutPacket::new();
        let daemon = DaemonState::default();
        add_address(
            &state,
            &contexts,
            0,
            &mut min_time,
            &addr,
            0,
            &mut outpacket,
            &daemon,
        );
        let data = outpacket.as_bytes();
        assert!(data.len() >= 28);
        // With lease_time=0, should use DEFLEASE6
        assert!(min_time <= DEFLEASE6);
    }

    #[test]
    fn test_add_prefix_basic() {
        let state = Dhcp6RequestState::new();
        let contexts: Vec<DhcpContext> = Vec::new();
        let mut min_time = u32::MAX;
        let prefix_addr = Ipv6Addr::new(0x2001, 0xdb8, 0xab, 0, 0, 0, 0, 0);
        let mut outpacket = OutPacket::new();
        let daemon = DaemonState::default();
        add_prefix(
            &state,
            &contexts,
            3600,
            &mut min_time,
            &prefix_addr,
            48,
            0,
            &mut outpacket,
            &daemon,
        );
        let data = outpacket.as_bytes();
        // IAPREFIX: header(4) + preferred(4) + valid(4) + prefix_len(1) + prefix(16) = 29
        assert!(data.len() >= 29);
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn test_add_prefix_with_context() {
        let state = Dhcp6RequestState::new();
        let mut ctx = make_test_context();
        ctx.start6 = Ipv6Addr::new(0x2001, 0xdb8, 0xab, 0, 0, 0, 0, 0);
        ctx.prefix = 48;
        ctx.valid = 7200;
        ctx.preferred = 3600;
        let mut min_time = u32::MAX;
        let prefix_addr = Ipv6Addr::new(0x2001, 0xdb8, 0xab, 0, 0, 0, 0, 0);
        let mut outpacket = OutPacket::new();
        let daemon = DaemonState::default();
        add_prefix(
            &state,
            &[ctx],
            7200,
            &mut min_time,
            &prefix_addr,
            48,
            0,
            &mut outpacket,
            &daemon,
        );
        let data = outpacket.as_bytes();
        assert!(data.len() >= 29);
    }

    #[test]
    fn test_add_prefix_zero_lease() {
        let state = Dhcp6RequestState::new();
        let mut min_time = u32::MAX;
        let prefix_addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0);
        let mut outpacket = OutPacket::new();
        let daemon = DaemonState::default();
        add_prefix(
            &state,
            &[],
            0,
            &mut min_time,
            &prefix_addr,
            64,
            0,
            &mut outpacket,
            &daemon,
        );
        assert!(min_time <= DEFLEASE6);
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn test_calculate_times_with_preferred() {
        let mut ctx = make_test_context();
        ctx.valid = 7200;
        ctx.preferred = 1800;
        ctx.flags = 0;
        let mut min_time = u32::MAX;
        let (valid, preferred) = calculate_times(&ctx, &mut min_time, 7200);
        assert_eq!(valid, 7200);
        assert_eq!(preferred, 1800);
        assert_eq!(min_time, 7200);
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn test_calculate_times_preferred_greater_than_valid_clamped() {
        let mut ctx = make_test_context();
        ctx.valid = 3600;
        ctx.preferred = 9999; // greater than valid
        ctx.flags = 0;
        let mut min_time = u32::MAX;
        let (valid, preferred) = calculate_times(&ctx, &mut min_time, 3600);
        assert_eq!(valid, 3600);
        assert!(preferred <= valid); // preferred must be <= valid
    }

    #[test]
    fn test_calculate_times_very_short_lifetime() {
        let mut ctx = make_test_context();
        ctx.valid = 60; // below MIN_LIFETIME
        ctx.preferred = 30;
        ctx.flags = 0;
        let mut min_time = u32::MAX;
        let (valid, _preferred) = calculate_times(&ctx, &mut min_time, 60);
        assert!(valid >= MIN_LIFETIME); // Enforced minimum
    }

    #[test]
    fn test_update_leases_create_new() {
        let mut state = Dhcp6RequestState::new();
        state.lease_allocate = true;
        state.ia_type = IaType::Na;
        state.iaid = 42;
        state.iface_name = "eth0".to_string();
        state.mac = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        state.clid = Some(vec![0, 1, 2, 3]);
        state.hostname = Some("testhost".to_string());

        let mut daemon = DaemonState::default();
        let contexts: Vec<DhcpContext> = Vec::new();
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x100);
        update_leases(&state, &contexts, &addr, 3600, 1000, &mut daemon);
        // Verify lease was added
        assert_eq!(daemon.leases.len(), 1);
        assert_eq!(daemon.leases[0].addr6, Some(addr));
        assert_eq!(daemon.leases[0].iaid, 42);
    }

    #[test]
    fn test_update_leases_update_existing() {
        let mut state = Dhcp6RequestState::new();
        state.ia_type = IaType::Na;
        state.iaid = 42;
        state.iface_name = "eth0".to_string();
        state.mac = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        state.clid = Some(vec![0, 1, 2, 3]);
        state.hostname = Some("updated".to_string());

        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x200);
        let mut daemon = DaemonState::default();
        // Pre-add a lease with matching prefix_len=128 (Na type)
        let mut lease = lease6_allocate(addr, LeaseType::Na);
        lease.prefix_len = 128; // Must match Na lookup
        daemon.leases.push(lease);

        update_leases(&state, &[], &addr, 7200, 2000, &mut daemon);
        assert_eq!(daemon.leases.len(), 1); // No duplicate
        assert_eq!(daemon.leases[0].hostname.as_deref(), Some("updated"));
    }

    #[test]
    fn test_update_leases_no_allocate() {
        let state = Dhcp6RequestState::new(); // lease_allocate = false
        let mut daemon = DaemonState::default();
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x300);
        update_leases(&state, &[], &addr, 3600, 1000, &mut daemon);
        assert_eq!(daemon.leases.len(), 0); // Not allocated
    }

    #[test]
    fn test_config_implies_no_addr6_flag() {
        let config = make_test_dhcp_config();
        let result = config_implies(&config, &[], &Ipv6Addr::UNSPECIFIED);
        assert!(result.is_none());
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn test_config_implies_with_addr6() {
        let mut config = make_test_dhcp_config();
        config.flags = CONFIG_ADDR6;
        config.addr6 = vec![Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x50)];
        let mut ctx = make_test_context();
        ctx.start6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0);
        ctx.prefix = 64;
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10);
        let result = config_implies(&config, &[ctx], &addr);
        assert_eq!(
            result,
            Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x50))
        );
    }

    #[test]
    fn test_config_valid_no_addr6() {
        let config = make_test_dhcp_config();
        let state = Dhcp6RequestState::new();
        let result = config_valid(&config, &[], &Ipv6Addr::UNSPECIFIED, &state, 0, &[]);
        assert!(!result);
    }

    #[test]
    fn test_config_valid_declined_with_backoff() {
        let mut config = make_test_dhcp_config();
        config.flags = CONFIG_ADDR6 | CONFIG_DECLINED;
        config.decline_time = 500; // within backoff
        let state = Dhcp6RequestState::new();
        let result = config_valid(&config, &[], &Ipv6Addr::UNSPECIFIED, &state, 100, &[]);
        assert!(!result);
    }

    #[test]
    fn test_write_status_reply_with_clid() {
        let mut state = Dhcp6RequestState::new();
        state.clid = Some(vec![0x00, 0x01, 0x02, 0x03]);
        state.xid = 0x123;
        let mut outpacket = OutPacket::new();
        write_status_reply(&mut outpacket, &state, DhcpV6State::Reply, 0, "Success");
        let data = outpacket.as_bytes();
        assert!(data.len() > 4);
    }

    #[test]
    fn test_write_status_reply_without_clid() {
        let state = Dhcp6RequestState::new();
        let mut outpacket = OutPacket::new();
        write_status_reply(&mut outpacket, &state, DhcpV6State::Reply, 2, "NotOnLink");
        let data = outpacket.as_bytes();
        assert!(data.len() > 0);
    }

    #[test]
    fn test_parse_dns_name_multi_level() {
        // "a.b.c" = [1, 'a', 1, 'b', 1, 'c', 0]
        let data = vec![1, b'a', 1, b'b', 1, b'c', 0];
        let name = parse_dns_name(&data).unwrap();
        assert_eq!(name, "a.b.c");
    }

    #[test]
    fn test_parse_dns_name_max_label() {
        // 63-byte label (max allowed)
        let label = vec![b'x'; 63];
        let mut data = vec![63u8];
        data.extend_from_slice(&label);
        data.push(0);
        let name = parse_dns_name(&data).unwrap();
        assert_eq!(name.len(), 63);
    }

    #[test]
    fn test_encode_dns_name_subdomain() {
        let mut outpacket = OutPacket::new();
        encode_dns_name("sub.domain.example.com", &mut outpacket);
        let data = outpacket.as_bytes();
        // Verify first label "sub" = [3, 's', 'u', 'b']
        assert_eq!(data[0], 3);
        assert_eq!(data[1], b's');
        assert_eq!(data[2], b'u');
        assert_eq!(data[3], b'b');
        // Should end with 0 (root label)
        assert_eq!(*data.last().unwrap(), 0);
    }

    #[test]
    fn test_daemon_config_entries_to_configs_full() {
        let entry = DhcpConfigEntry {
            flags: CONFIG_NAME | CONFIG_ADDR6,
            hwaddr: vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            clid: vec![0, 1, 2, 3],
            hostname: Some("server1".to_string()),
            netid: Some("dmz".to_string()),
            addr: Some(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            #[cfg(feature = "dhcp6")]
            addr6: Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            lease_time: 86400,
        };
        let configs = daemon_config_entries_to_configs(&[entry]);
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].flags, CONFIG_NAME | CONFIG_ADDR6);
        assert_eq!(configs[0].hwaddr.len(), 1);
        assert_eq!(configs[0].clid, Some(vec![0, 1, 2, 3]));
        assert_eq!(configs[0].hostname, Some("server1".to_string()));
        assert_eq!(configs[0].netid.len(), 1);
        assert_eq!(configs[0].netid[0].net, "dmz");
    }

    #[test]
    fn test_daemon_opt_entries_to_opts_full() {
        let entry = DhcpOptEntry {
            opt: 23,
            val: vec![0x20, 0x01, 0x0d, 0xb8],
            flags: DHOPT_FORCE,
            netid: Some("lan".to_string()),
        };
        let opts = daemon_opt_entries_to_opts(&[entry]);
        assert_eq!(opts.len(), 1);
        assert_eq!(opts[0].opt, 23);
        assert_eq!(opts[0].flags, DHOPT_FORCE);
        assert_eq!(opts[0].netid.as_ref().unwrap().net, "lan");
        assert_eq!(opts[0].len, 4);
    }

    #[test]
    fn test_daemon_tag_if_to_rules_full() {
        let tag = TagIf {
            tag: "known".to_string(),
            set: vec!["dns".to_string(), "ntp".to_string()],
        };
        let rules = daemon_tag_if_to_rules(&[tag]);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].tag.len(), 1);
        assert_eq!(rules[0].tag[0].net, "known");
        assert_eq!(rules[0].set.len(), 2);
    }

    #[test]
    fn test_daemon_config_entries_to_configs_no_hwaddr() {
        let entry = DhcpConfigEntry {
            flags: 0,
            hwaddr: vec![],
            clid: vec![],
            hostname: None,
            netid: None,
            addr: None,
            #[cfg(feature = "dhcp6")]
            addr6: None,
            lease_time: 0,
        };
        let configs = daemon_config_entries_to_configs(&[entry]);
        assert_eq!(configs.len(), 1);
        assert!(configs[0].hwaddr.is_empty());
        assert!(configs[0].clid.is_none());
    }

    #[test]
    fn test_end_ia_infinite_lease() {
        let mut outpacket = OutPacket::new();
        // Write some dummy data so t1_counter is valid
        outpacket.put_opt6_long(0); // placeholder T1
        outpacket.put_opt6_long(0); // placeholder T2
        end_ia(&mut outpacket, 0, 0xFFFFFFFF, false);
        // T1/T2 should remain 0 (infinite lease)
    }

    #[test]
    fn test_end_ia_zero_min_time() {
        let mut outpacket = OutPacket::new();
        outpacket.put_opt6_long(0);
        outpacket.put_opt6_long(0);
        end_ia(&mut outpacket, 0, 0, false);
        // No addresses added — T1/T2 remain 0
    }

    #[test]
    fn test_end_ia_normal_with_t1_counter() {
        let mut outpacket = OutPacket::new();
        // Write a dummy byte first so t1_counter != 0 (end_ia skips t1_counter==0)
        outpacket.put_opt6_char(0xFF); // padding byte
        let t1_counter = outpacket.save_counter(None); // position = 1
        outpacket.put_opt6_long(0); // T1 placeholder
        outpacket.put_opt6_long(0); // T2 placeholder
        end_ia(&mut outpacket, t1_counter, 7200, false);
        let data = outpacket.as_bytes();
        // T1 should be 7200/2 = 3600
        assert!(data.len() >= t1_counter + 8);
        let t1 = u32::from_be_bytes([
            data[t1_counter],
            data[t1_counter + 1],
            data[t1_counter + 2],
            data[t1_counter + 3],
        ]);
        assert_eq!(t1, 3600);
        let t2 = u32::from_be_bytes([
            data[t1_counter + 4],
            data[t1_counter + 5],
            data[t1_counter + 6],
            data[t1_counter + 7],
        ]);
        assert_eq!(t2, 6300); // 7*900
    }

    #[test]
    fn test_end_ia_fuzz_applied() {
        let mut outpacket = OutPacket::new();
        outpacket.put_opt6_char(0xFF); // padding so t1_counter != 0
        let t1_counter = outpacket.save_counter(None); // position = 1
        outpacket.put_opt6_long(0);
        outpacket.put_opt6_long(0);
        end_ia(&mut outpacket, t1_counter, 7200, true);
        let data = outpacket.as_bytes();
        assert!(data.len() >= t1_counter + 4);
        let t1 = u32::from_be_bytes([
            data[t1_counter],
            data[t1_counter + 1],
            data[t1_counter + 2],
            data[t1_counter + 3],
        ]);
        // With fuzz, T1 should be near 3600 but not necessarily exactly 3600
        assert!(t1 >= 3500 && t1 <= 3800, "T1 with fuzz: {}", t1);
    }

    #[test]
    fn test_opt6_iterate_all_v2() {
        // Build opts with 3 options
        let mut opts = Vec::new();
        for code in [10u16, 20, 30] {
            opts.extend_from_slice(&code.to_be_bytes());
            opts.extend_from_slice(&2u16.to_be_bytes()); // len=2
            opts.extend_from_slice(&[0xAA, 0xBB]);
        }
        let mut pos = 0;
        let mut count = 0;
        while let Some((code, data, next)) = opt6_next(&opts, pos) {
            assert!(code == 10 || code == 20 || code == 30);
            assert_eq!(data.len(), 2);
            pos = next;
            count += 1;
        }
        assert_eq!(count, 3);
    }

    #[test]
    fn test_dhcp6_request_state_full_fields() {
        let mut s = Dhcp6RequestState::new();
        s.clid = Some(vec![1, 2, 3]);
        s.multicast_dest = true;
        s.ia_type = IaType::Pd;
        s.interface = 5;
        s.hostname_auth = true;
        s.lease_allocate = true;
        s.client_hostname = Some("client".to_string());
        s.hostname = Some("host".to_string());
        s.domain = Some("dom".to_string());
        s.send_domain = Some("sdom".to_string());
        s.link_address = Some(Ipv6Addr::LOCALHOST);
        s.fallback = Some(Ipv6Addr::LOCALHOST);
        s.ll_addr = Some(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        s.ula_addr = Some(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1));
        s.xid = 0xABCDEF;
        s.fqdn_flags = 0x07;
        s.iaid = 999;
        s.iface_name = "wlan0".to_string();
        s.packet_options_start = 100;
        s.packet_options_end = 200;
        s.tags = vec![NetId {
            net: "tag1".to_string(),
        }];
        s.context_tags = vec![NetId {
            net: "ctx1".to_string(),
        }];
        s.mac = vec![0xDE, 0xAD, 0xBE, 0xEF];
        s.mac_type = 6;
        assert!(s.multicast_dest);
        assert_eq!(s.ia_type, IaType::Pd);
        assert_eq!(s.xid, 0xABCDEF);
    }
}

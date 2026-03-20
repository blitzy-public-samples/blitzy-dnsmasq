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

//! # Authoritative DNS Zone Serving
//!
//! This module implements authoritative DNS server mode, enabling dnsmasq to
//! respond authoritatively (AA flag set) to queries for configured local zones.
//! Migrated from C `src/auth.c` (1,284 lines).
//!
//! ## Feature Gate
//!
//! This entire module is gated by `#[cfg(feature = "auth")]`, corresponding
//! to C's `HAVE_AUTH` preprocessor macro.
//!
//! ## Capabilities
//!
//! - **Zone Matching** — Case-insensitive domain suffix matching with
//!   dot-boundary verification via [`in_zone()`].
//! - **Split-Horizon DNS** — Subnet-based response filtering using
//!   [`AuthSubnet`] with IPv4 and IPv6 support.
//! - **Record Types** — Serves A, AAAA, CNAME, MX, SRV, TXT, NAPTR, PTR,
//!   SOA, and NS records for authoritative zones.
//! - **AXFR Zone Transfer** — Full zone transfer support for secondary
//!   nameservers with peer authorization.
//! - **Cache Integration** — Queries DNS cache for DHCP lease and `/etc/hosts`
//!   entries within the zone.
//! - **Synthetic Names** — Integrates with [`crate::dns::domain`] for
//!   automatic reverse/forward DNS name generation.
//!
//! ## Memory Safety
//!
//! Zero `unsafe` blocks. All C `malloc`/`free` patterns replaced with Rust
//! ownership. Buffer management uses `Vec<u8>`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use tracing::{debug, info, warn};

use crate::config::constants::{AUTH_TTL, CNAME_CHAIN, SOA_EXPIRY, SOA_REFRESH, SOA_RETRY};
use crate::core::log::log_dns_query;
use crate::core::types::{opt, DaemonState, DnsmasqResult};
use crate::core::util::{hostname_eq, is_same_net, is_same_net6, is_subdomain};
use crate::dns::cache::{CacheData, DnsCache};
use crate::dns::domain::ConditionalDomain;
use crate::dns::protocol::{
    DnsClass, DnsHeader, DnsName, DnsPacket, DnsPacketBuilder, DnsQuestion, RRType, ResponseCode,
};

// ---------------------------------------------------------------------------
// Data Structures
// ---------------------------------------------------------------------------

/// Subnet entry for authoritative zone filtering.
///
/// Replaces C `struct addrlist` entries used in `auth_zone.subnet` and
/// `auth_zone.exclude` lists. Supports both IPv4 (netmask-based) and IPv6
/// (prefix-length-based) subnet specifications for split-horizon DNS.
#[derive(Debug, Clone)]
pub struct AuthSubnet {
    /// Network address (IPv4 or IPv6).
    pub addr: IpAddr,
    /// CIDR prefix length (0-32 for IPv4, 0-128 for IPv6).
    pub prefix_len: u8,
    /// Whether this is an IPv6 subnet.
    pub is_v6: bool,
    /// If true, this subnet is only used for reverse DNS (PTR) zone matching,
    /// not for forward record filtering. Maps to C `ADDRLIST_REVONLY` flag.
    pub revonly: bool,
}

impl AuthSubnet {
    /// Create a new IPv4 subnet specification.
    pub fn new_v4(addr: Ipv4Addr, prefix_len: u8) -> Self {
        Self {
            addr: IpAddr::V4(addr),
            prefix_len,
            is_v6: false,
            revonly: false,
        }
    }

    /// Create a new IPv6 subnet specification.
    pub fn new_v6(addr: Ipv6Addr, prefix_len: u8) -> Self {
        Self {
            addr: IpAddr::V6(addr),
            prefix_len,
            is_v6: true,
            revonly: false,
        }
    }

    /// Convert prefix length to an IPv4 netmask.
    /// Returns `Ipv4Addr::UNSPECIFIED` if prefix_len is 0.
    fn to_v4_mask(&self) -> Ipv4Addr {
        if self.prefix_len == 0 {
            return Ipv4Addr::UNSPECIFIED;
        }
        if self.prefix_len >= 32 {
            return Ipv4Addr::new(255, 255, 255, 255);
        }
        let mask_bits: u32 = !((1u32 << (32 - self.prefix_len)) - 1);
        Ipv4Addr::from(mask_bits)
    }
}

/// Individual authoritative DNS record within a zone.
///
/// Replaces C's scattered record types (mx_srv_record, txt_record, naptr,
/// cname aliases) unified into a single enum for type-safe pattern matching.
#[derive(Debug, Clone)]
pub enum AuthRecord {
    /// IPv4 address record (A).
    A(Ipv4Addr),
    /// IPv6 address record (AAAA).
    Aaaa(Ipv6Addr),
    /// Canonical name alias (CNAME).
    Cname(String),
    /// Mail exchange record (MX).
    Mx {
        /// MX preference value (lower = higher priority).
        preference: u16,
        /// Mail exchange hostname.
        exchange: String,
    },
    /// Service location record (SRV).
    Srv {
        /// Priority (lower = preferred).
        priority: u16,
        /// Weight for load balancing among equal-priority targets.
        weight: u16,
        /// TCP/UDP port number.
        port: u16,
        /// Target hostname providing the service.
        target: String,
    },
    /// Text record (TXT).
    Txt(String),
    /// Naming Authority Pointer record (NAPTR).
    Naptr {
        /// NAPTR order (lower processed first).
        order: u16,
        /// NAPTR preference within same order.
        preference: u16,
        /// NAPTR flags (e.g., "u", "s", "a").
        flags: String,
        /// NAPTR service field.
        service: String,
        /// NAPTR regexp field.
        regexp: String,
        /// NAPTR replacement domain.
        replacement: String,
    },
    /// Pointer record for reverse DNS (PTR).
    Ptr(String),
}

/// Named entry within an authoritative zone.
///
/// Groups all records associated with a single domain name within the zone.
/// Used in [`AuthZone::name_list`] for pre-configured static records.
#[derive(Debug, Clone)]
pub struct AuthNameEntry {
    /// Fully qualified domain name for this entry.
    pub name: String,
    /// All DNS records associated with this name.
    pub records: Vec<AuthRecord>,
}

/// Authoritative DNS zone configuration.
///
/// Replaces C `struct auth_zone` (dnsmasq.h lines 614-623). Each zone
/// defines a domain, optional subnet filters for split-horizon DNS,
/// and associated name entries.
#[derive(Debug, Clone)]
pub struct AuthZone {
    /// Zone domain name (e.g., `"example.local"`).
    pub domain: String,
    /// Subnet inclusion filters for split-horizon DNS.
    /// An address must match at least one subnet to be included.
    /// Empty means no subnet filtering (include all).
    pub subnet: Vec<AuthSubnet>,
    /// Subnet exclusion filters. Addresses matching any exclude entry
    /// are omitted from authoritative responses.
    pub exclude: Vec<AuthSubnet>,
    /// Whether this zone uses interface-based membership.
    pub interface_names: bool,
    /// Pre-configured name entries (static records) in this zone.
    pub name_list: Vec<AuthNameEntry>,
}

impl AuthZone {
    /// Create a new empty authoritative zone for the given domain.
    pub fn new(domain: String) -> Self {
        Self {
            domain,
            subnet: Vec::new(),
            exclude: Vec::new(),
            interface_names: false,
            name_list: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Zone Matching — in_zone()
// ---------------------------------------------------------------------------

/// Check if a domain name belongs to an authoritative zone.
///
/// Performs case-insensitive domain suffix matching with dot-boundary
/// verification. Returns `Some(cut_position)` indicating where the zone
/// suffix begins in `name`, or `None` if the name is not in the zone.
///
/// If the name equals the zone domain exactly, returns `Some(0)` (apex).
/// If the name is a subdomain, returns `Some(position)` where position
/// is the index just before the dot separator.
///
/// Replaces C `in_zone()` (`auth.c` lines 351-375).
///
/// # Examples
///
/// ```ignore
/// let zone = AuthZone::new("example.com".to_string());
/// assert_eq!(in_zone(&zone, "host.example.com"), Some(4));
/// assert_eq!(in_zone(&zone, "example.com"), Some(0));
/// assert_eq!(in_zone(&zone, "other.net"), None);
/// assert_eq!(in_zone(&zone, "notexample.com"), None);
/// ```
pub fn in_zone(zone: &AuthZone, name: &str) -> Option<usize> {
    let zone_domain = &zone.domain;

    // Exact match (zone apex).
    if hostname_eq(name, zone_domain) {
        debug!(name, zone = %zone_domain, "in_zone: exact match (apex)");
        return Some(0);
    }

    // Subdomain check: name must end with ".zone_domain" (case-insensitive).
    let name_len = name.len();
    let zone_len = zone_domain.len();

    // Name must be longer than zone_domain + 1 (for the dot separator).
    if name_len <= zone_len + 1 {
        return None;
    }

    // Check that the separator is a dot at the expected position.
    let dot_pos = name_len - zone_len - 1;
    if name.as_bytes()[dot_pos] != b'.' {
        return None;
    }

    // Compare the suffix (after the dot) with the zone domain.
    let suffix = &name[dot_pos + 1..];
    if hostname_eq(suffix, zone_domain) {
        debug!(
            name,
            zone = %zone_domain,
            cut = dot_pos,
            "in_zone: subdomain match"
        );
        Some(dot_pos)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Subnet Filtering — find_addrlist / filter_zone helpers
// ---------------------------------------------------------------------------

/// Check if an IP address matches any entry in an address list.
///
/// Replaces C `find_addrlist()` (`auth.c` lines 119-140).
fn find_addrlist(addr: &IpAddr, list: &[AuthSubnet]) -> bool {
    for entry in list {
        match (addr, &entry.addr) {
            (IpAddr::V4(a), IpAddr::V4(net)) => {
                let mask = entry.to_v4_mask();
                if is_same_net(*a, *net, mask) {
                    return true;
                }
            }
            (IpAddr::V6(a), IpAddr::V6(net)) => {
                if is_same_net6(*a, *net, entry.prefix_len) {
                    return true;
                }
            }
            _ => continue,
        }
    }
    false
}

/// Three-tier zone filtering for split-horizon DNS.
///
/// Replaces C `filter_zone()` (`auth.c` lines 273-283).
///
/// Returns `true` if the address should be included in the response:
/// 1. If `addr` matches any exclude entry → excluded (false)
/// 2. If zone has no subnet filters → included (true)
/// 3. If `addr` matches a non-revonly subnet entry → included (true)
/// 4. Otherwise → excluded (false)
fn filter_zone(
    addr: &IpAddr,
    subnet: &[AuthSubnet],
    exclude: &[AuthSubnet],
    flag: FilterFlag,
) -> bool {
    // Step 1: Check exclusion list.
    if find_addrlist(addr, exclude) {
        debug!(%addr, "filter_zone: excluded by exclude list");
        return false;
    }

    // Step 2: If no subnet filters defined, include everything.
    if subnet.is_empty() {
        return true;
    }

    // Step 3: Check subnet inclusion list.
    for entry in subnet {
        // Skip revonly entries when doing forward lookups.
        if entry.revonly && flag == FilterFlag::Forward {
            continue;
        }
        match (addr, &entry.addr) {
            (IpAddr::V4(a), IpAddr::V4(net)) => {
                let mask = entry.to_v4_mask();
                if is_same_net(*a, *net, mask) {
                    return true;
                }
            }
            (IpAddr::V6(a), IpAddr::V6(net)) => {
                if is_same_net6(*a, *net, entry.prefix_len) {
                    return true;
                }
            }
            _ => continue,
        }
    }

    false
}

/// Flag indicating the direction of zone filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FilterFlag {
    /// Filtering for forward DNS lookups (A/AAAA records).
    Forward,
    /// Filtering for reverse DNS lookups (PTR records).
    #[allow(dead_code)]
    Reverse,
}

// ---------------------------------------------------------------------------
// Conversion Helpers
// ---------------------------------------------------------------------------

/// Parse a subnet specification string in CIDR notation.
///
/// Accepts formats: "192.168.1.0/24", "2001:db8::/32", or bare "10.0.0.1".
fn parse_subnet_spec(spec: &str) -> Option<AuthSubnet> {
    let parts: Vec<&str> = spec.split('/').collect();
    if parts.len() == 2 {
        let addr: IpAddr = parts[0].parse().ok()?;
        let prefix_len: u8 = parts[1].parse().ok()?;
        let is_v6 = addr.is_ipv6();
        return Some(AuthSubnet {
            addr,
            prefix_len,
            is_v6,
            revonly: false,
        });
    }
    // Try parsing as a plain address (host route).
    if let Ok(addr) = spec.parse::<IpAddr>() {
        let (prefix_len, is_v6) = match addr {
            IpAddr::V4(_) => (32u8, false),
            IpAddr::V6(_) => (128u8, true),
        };
        return Some(AuthSubnet {
            addr,
            prefix_len,
            is_v6,
            revonly: false,
        });
    }
    None
}

/// Convert string-based subnet list from types::AuthZone to AuthSubnet.
fn zone_to_auth_subnet(strings: &[String]) -> Vec<AuthSubnet> {
    strings
        .iter()
        .filter_map(|s| parse_subnet_spec(s))
        .collect()
}

/// Convert a `CondDomain` (from types.rs) to a `ConditionalDomain` (from domain.rs).
///
/// These are structurally similar but defined in different modules; this
/// bridge function enables auth.rs to call domain.rs functions with
/// daemon state data.
fn cond_domain_to_conditional(cd: &crate::core::types::CondDomain) -> ConditionalDomain {
    let addr4_range = if let (Some(IpAddr::V4(s)), Some(IpAddr::V4(e))) = (&cd.start, &cd.end) {
        if !cd.is6 {
            Some((*s, *e))
        } else {
            None
        }
    } else {
        None
    };

    let addr6_range = if let (Some(IpAddr::V6(s)), Some(IpAddr::V6(e))) = (&cd.start, &cd.end) {
        if cd.is6 {
            Some((*s, *e))
        } else {
            None
        }
    } else {
        None
    };

    ConditionalDomain {
        domain: cd.domain.clone(),
        prefix: cd.prefix.clone(),
        addr4_range,
        addr6_range,
        is_synthetic: false,
        index: 0,
        prefixlen: 0,
    }
}

/// Convert a slice of `CondDomain` into a `Vec<ConditionalDomain>`.
fn convert_synth_domains(domains: &[crate::core::types::CondDomain]) -> Vec<ConditionalDomain> {
    domains.iter().map(cond_domain_to_conditional).collect()
}

// ---------------------------------------------------------------------------
// SOA / NS Record Construction
// ---------------------------------------------------------------------------

/// Generate SOA record RDATA bytes.
///
/// SOA RDATA format (RFC 1035 Section 3.3.13):
///   MNAME (primary nameserver), RNAME (hostmaster email),
///   SERIAL, REFRESH, RETRY, EXPIRE, MINIMUM — all u32 big-endian.
fn build_soa_rdata(
    authserver: &str,
    hostmaster: &str,
    serial: u32,
    refresh: u32,
    retry: u32,
    expiry: u32,
    ttl: u32,
) -> Vec<u8> {
    let mut rdata = Vec::with_capacity(256);
    encode_name_wire(&mut rdata, authserver);
    let rname = hostmaster.replace('@', ".");
    encode_name_wire(&mut rdata, &rname);
    rdata.extend_from_slice(&serial.to_be_bytes());
    rdata.extend_from_slice(&refresh.to_be_bytes());
    rdata.extend_from_slice(&retry.to_be_bytes());
    rdata.extend_from_slice(&expiry.to_be_bytes());
    rdata.extend_from_slice(&ttl.to_be_bytes());
    rdata
}

/// Encode a domain name in DNS wire format (uncompressed).
fn encode_name_wire(buf: &mut Vec<u8>, name: &str) {
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        let bytes = label.as_bytes();
        let len = bytes.len().min(63);
        buf.push(len as u8);
        buf.extend_from_slice(&bytes[..len]);
    }
    buf.push(0);
}

/// Build NS record RDATA (domain name in wire format).
fn build_ns_rdata(nameserver: &str) -> Vec<u8> {
    let mut rdata = Vec::with_capacity(128);
    encode_name_wire(&mut rdata, nameserver);
    rdata
}

/// Build MX record RDATA: 2-byte preference + exchange name in wire format.
fn build_mx_rdata(preference: u16, exchange: &str) -> Vec<u8> {
    let mut rdata = Vec::with_capacity(128);
    rdata.extend_from_slice(&preference.to_be_bytes());
    encode_name_wire(&mut rdata, exchange);
    rdata
}

/// Build SRV record RDATA: priority(2) + weight(2) + port(2) + target name.
fn build_srv_rdata(priority: u16, weight: u16, port: u16, target: &str) -> Vec<u8> {
    let mut rdata = Vec::with_capacity(128);
    rdata.extend_from_slice(&priority.to_be_bytes());
    rdata.extend_from_slice(&weight.to_be_bytes());
    rdata.extend_from_slice(&port.to_be_bytes());
    encode_name_wire(&mut rdata, target);
    rdata
}

/// Build NAPTR record RDATA per RFC 2915.
fn build_naptr_rdata(
    order: u16,
    preference: u16,
    flags: &str,
    service: &str,
    regexp: &str,
    replacement: &str,
) -> Vec<u8> {
    let mut rdata = Vec::with_capacity(256);
    rdata.extend_from_slice(&order.to_be_bytes());
    rdata.extend_from_slice(&preference.to_be_bytes());
    encode_character_string(&mut rdata, flags);
    encode_character_string(&mut rdata, service);
    encode_character_string(&mut rdata, regexp);
    encode_name_wire(&mut rdata, replacement);
    rdata
}

/// Encode a character-string (length byte + data) per RFC 1035 Section 3.3.
fn encode_character_string(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    let len = bytes.len().min(255);
    buf.push(len as u8);
    buf.extend_from_slice(&bytes[..len]);
}

/// Build TXT record RDATA: one or more character-strings.
fn build_txt_rdata(txt: &[u8]) -> Vec<u8> {
    let mut rdata = Vec::with_capacity(txt.len() + 2);
    if txt.is_empty() {
        rdata.push(0);
    } else {
        for chunk in txt.chunks(255) {
            rdata.push(chunk.len() as u8);
            rdata.extend_from_slice(chunk);
        }
    }
    rdata
}

/// Build CNAME record RDATA (target domain name in wire format).
fn build_cname_rdata(target: &str) -> Vec<u8> {
    let mut rdata = Vec::with_capacity(128);
    encode_name_wire(&mut rdata, target);
    rdata
}

/// Build PTR record RDATA (target domain name in wire format).
fn build_ptr_rdata(target: &str) -> Vec<u8> {
    let mut rdata = Vec::with_capacity(128);
    encode_name_wire(&mut rdata, target);
    rdata
}

/// Build SOA RDATA from zone config and daemon state.
fn build_soa_record(zone: &crate::core::types::AuthZone, state: &DaemonState, ttl: u32) -> Vec<u8> {
    let authserver = state.authserver.as_deref().unwrap_or(&zone.domain);
    let hostmaster = state.hostmaster.as_deref().unwrap_or("hostmaster");
    let serial = state.soa_sn;
    let refresh = if state.soa_refresh > 0 {
        state.soa_refresh
    } else {
        SOA_REFRESH
    };
    let retry = if state.soa_retry > 0 {
        state.soa_retry
    } else {
        SOA_RETRY
    };
    let expiry = if state.soa_expiry > 0 {
        state.soa_expiry
    } else {
        SOA_EXPIRY
    };
    build_soa_rdata(authserver, hostmaster, serial, refresh, retry, expiry, ttl)
}

/// Build NS records for the authority section.
fn build_ns_records(
    zone: &crate::core::types::AuthZone,
    state: &DaemonState,
    ttl: u32,
) -> Vec<(DnsName, RRType, u32, Vec<u8>)> {
    let mut records = Vec::new();
    let zone_name = DnsName::from_str_unchecked(&zone.domain);

    if let Some(ref authserver) = state.authserver {
        let rdata = build_ns_rdata(authserver);
        records.push((zone_name.clone(), RRType::NS, ttl, rdata));
    }
    for iface in &state.authinterface {
        if let Some(ref name) = iface.name {
            let rdata = build_ns_rdata(name);
            records.push((zone_name.clone(), RRType::NS, ttl, rdata));
        }
    }
    for server in &state.secondary_forward_server {
        let rdata = build_ns_rdata(server);
        records.push((zone_name.clone(), RRType::NS, ttl, rdata));
    }
    records
}

// ---------------------------------------------------------------------------
// Result type
// ---------------------------------------------------------------------------

/// Result type for answer_auth indicating how the response was handled.
#[derive(Debug)]
pub enum AuthResult {
    /// Normal authoritative response. Contains the response packet bytes.
    Response(Vec<u8>),
    /// AXFR zone transfer response. Contains all packets to send.
    AxfrTransfer(Vec<Vec<u8>>),
    /// Query was refused (out-of-zone, bad opcode, etc.).
    Refused,
}

// ---------------------------------------------------------------------------
// Packet RCODE patching
// ---------------------------------------------------------------------------

/// Patch the RCODE bits in a raw DNS packet byte buffer.
///
/// The RCODE occupies the lower 4 bits of byte 3 (the second flags byte).
/// This avoids needing access to the private `DnsHeaderFlags::to_bytes()`.
fn patch_rcode(raw: &mut [u8], rcode: ResponseCode) {
    if raw.len() >= 4 {
        let rcode_val = rcode.to_u8() & 0x0f;
        raw[3] = (raw[3] & 0xf0) | rcode_val;
    }
}

// ---------------------------------------------------------------------------
// Main Entry Point — answer_auth()
// ---------------------------------------------------------------------------

/// Process an incoming DNS query and generate an authoritative response.
///
/// This is the main entry point for authoritative DNS serving, replacing
/// C `answer_auth()` (`auth.c` lines 468-1284). It handles:
///
/// - Query parsing and zone matching
/// - Record type routing (PTR, A, AAAA, CNAME, MX, SRV, TXT, NAPTR, SOA, NS)
/// - AXFR zone transfer with peer authorization
/// - Authority section SOA/NS generation
/// - Split-horizon DNS via subnet filtering
/// - Cache integration for DHCP/hosts entries
/// - NXDOMAIN vs NODATA determination via `cache_find_non_terminal()`
///
/// # Arguments
///
/// * `query_data` — Raw DNS query packet bytes.
/// * `state` — Daemon configuration state.
/// * `cache` — DNS cache for DHCP/hosts record lookup.
/// * `peer_addr` — Client socket address (for AXFR authorization).
/// * `_local_query` — Whether the query originated locally.
///
/// # Returns
///
/// `Ok(AuthResult)` on success, `Err` on protocol errors.
pub fn answer_auth(
    query_data: &[u8],
    state: &DaemonState,
    cache: &mut DnsCache,
    peer_addr: &std::net::SocketAddr,
    _local_query: bool,
) -> DnsmasqResult<AuthResult> {
    // Parse the incoming DNS packet.
    let packet = DnsPacket::parse(query_data)?;
    let header = &packet.header;

    // Must have exactly one question.
    if header.qdcount != 1 || packet.questions.is_empty() {
        warn!("auth query with qdcount != 1, refusing");
        return Ok(AuthResult::Refused);
    }

    // Check opcode — only standard query (0) is supported.
    if header.opcode() != 0 {
        debug!(
            opcode = header.opcode(),
            "auth query with unsupported opcode"
        );
        return build_error_response(header, &packet.questions[0], ResponseCode::NotImp);
    }

    let question = &packet.questions[0];
    let qname_str = question.name.to_string().trim_end_matches('.').to_string();
    let qtype = question.qtype;
    let qclass = question.qclass;

    // Only IN class queries are supported.
    if qclass != DnsClass::IN && qclass != DnsClass::Any {
        debug!(class = ?qclass, "auth query with unsupported class");
        return build_error_response(header, question, ResponseCode::Refused);
    }

    // Log the incoming query.
    log_dns_query(&qname_str, qtype.to_u16(), "auth", 0);

    // Find the matching authoritative zone.
    let zone_match = find_matching_zone(&qname_str, &state.auth_zones);

    let (zone, cut) = match zone_match {
        Some((z, c)) => (z, c),
        None => {
            debug!(name = %qname_str, "no authoritative zone found, refusing");
            return build_error_response(header, question, ResponseCode::Refused);
        }
    };

    info!(
        name = %qname_str,
        zone = %zone.domain,
        qtype = %qtype,
        "processing authoritative query"
    );

    // Pre-parse zone subnets for filtering.
    let auth_subnets = zone_to_auth_subnet(&zone.subnet);
    let auth_excludes = zone_to_auth_subnet(&zone.exclude);

    // Determine effective TTL.
    let ttl = if state.auth_ttl > 0 {
        state.auth_ttl
    } else {
        AUTH_TTL
    };

    // Handle AXFR zone transfer requests.
    if qtype == RRType::AXFR {
        return handle_axfr(header, question, zone, state, cache, peer_addr, ttl);
    }

    // Handle SOA queries at zone apex (cut == 0).
    if cut == 0 && (qtype == RRType::SOA || qtype == RRType::ANY) {
        return handle_soa_query(header, question, zone, state, ttl);
    }

    // Handle NS queries at zone apex.
    if cut == 0 && qtype == RRType::NS {
        return handle_ns_query(header, question, zone, state, ttl);
    }

    // Build the answer section based on query type.
    let mut answers: Vec<(DnsName, RRType, u32, Vec<u8>)> = Vec::new();
    let mut nxdomain = true;
    let mut found_record = false;

    // --- PTR record handling ---
    if qtype == RRType::PTR || qtype == RRType::ANY {
        if let Some(ptr_results) = handle_ptr_lookup(&qname_str, zone, state, cache, ttl) {
            for item in ptr_results {
                answers.push(item);
                found_record = true;
                nxdomain = false;
            }
        }
    }

    // --- Check MX records from daemon state ---
    if qtype == RRType::MX || qtype == RRType::ANY {
        for mx in &state.mxnames {
            if mx.is_mx && hostname_eq(&mx.name, &qname_str) {
                nxdomain = false;
                let rdata = build_mx_rdata(mx.priority, &mx.target);
                answers.push((question.name.clone(), RRType::MX, ttl, rdata));
                found_record = true;
            }
        }
    }

    // --- Check SRV records from daemon state ---
    if qtype == RRType::SRV || qtype == RRType::ANY {
        for srv in &state.mxnames {
            if !srv.is_mx && hostname_eq(&srv.name, &qname_str) {
                nxdomain = false;
                let rdata = build_srv_rdata(srv.priority, srv.weight, srv.port, &srv.target);
                answers.push((question.name.clone(), RRType::SRV, ttl, rdata));
                found_record = true;
            }
        }
    }

    // --- Check TXT records from daemon state ---
    if qtype == RRType::TXT || qtype == RRType::ANY {
        for txt in &state.txt_records {
            if hostname_eq(&txt.name, &qname_str) && txt.class == DnsClass::IN.to_u16() {
                nxdomain = false;
                let rdata = build_txt_rdata(&txt.txt);
                answers.push((question.name.clone(), RRType::TXT, ttl, rdata));
                found_record = true;
            }
        }
    }

    // --- Check NAPTR records from daemon state ---
    if qtype == RRType::NAPTR || qtype == RRType::ANY {
        for naptr in &state.naptr {
            if hostname_eq(&naptr.name, &qname_str) {
                nxdomain = false;
                let rdata = build_naptr_rdata(
                    naptr.order,
                    naptr.pref,
                    &naptr.flags,
                    &naptr.services,
                    &naptr.regexp,
                    &naptr.replace,
                );
                answers.push((question.name.clone(), RRType::NAPTR, ttl, rdata));
                found_record = true;
            }
        }
    }

    // --- Check interface name records (A/AAAA from interface addresses) ---
    if qtype == RRType::A || qtype == RRType::AAAA || qtype == RRType::ANY {
        for int_name in &state.int_names {
            if hostname_eq(&int_name.name, &qname_str) {
                nxdomain = false;
                let dns_name = DnsName::from_str_unchecked(&qname_str);
                let entries = cache.cache_find_by_name(&dns_name, None);
                for ce in entries {
                    match &ce.data {
                        CacheData::Addr4(v4) if qtype == RRType::A || qtype == RRType::ANY => {
                            let addr_ip = IpAddr::V4(*v4);
                            if filter_zone(
                                &addr_ip,
                                &auth_subnets,
                                &auth_excludes,
                                FilterFlag::Forward,
                            ) {
                                answers.push((
                                    question.name.clone(),
                                    RRType::A,
                                    ttl,
                                    v4.octets().to_vec(),
                                ));
                                found_record = true;
                            }
                        }
                        CacheData::Addr6(v6) if qtype == RRType::AAAA || qtype == RRType::ANY => {
                            let addr_ip = IpAddr::V6(*v6);
                            if filter_zone(
                                &addr_ip,
                                &auth_subnets,
                                &auth_excludes,
                                FilterFlag::Forward,
                            ) {
                                answers.push((
                                    question.name.clone(),
                                    RRType::AAAA,
                                    ttl,
                                    v6.octets().to_vec(),
                                ));
                                found_record = true;
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    // --- Check synthetic forward names ---
    if (qtype == RRType::A || qtype == RRType::AAAA || qtype == RRType::ANY) && !found_record {
        let synth_domains = convert_synth_domains(&state.synth_domains);
        if let Ok(Some((synth_addr, _idx))) =
            crate::dns::domain::is_name_synthetic(&qname_str, &synth_domains)
        {
            nxdomain = false;
            match synth_addr {
                IpAddr::V4(v4) if qtype == RRType::A || qtype == RRType::ANY => {
                    if filter_zone(
                        &synth_addr,
                        &auth_subnets,
                        &auth_excludes,
                        FilterFlag::Forward,
                    ) {
                        answers.push((question.name.clone(), RRType::A, ttl, v4.octets().to_vec()));
                        found_record = true;
                    }
                }
                IpAddr::V6(v6) if qtype == RRType::AAAA || qtype == RRType::ANY => {
                    if filter_zone(
                        &synth_addr,
                        &auth_subnets,
                        &auth_excludes,
                        FilterFlag::Forward,
                    ) {
                        answers.push((
                            question.name.clone(),
                            RRType::AAAA,
                            ttl,
                            v6.octets().to_vec(),
                        ));
                        found_record = true;
                    }
                }
                _ => {}
            }
        }
    }

    // --- Check DHCP/hosts cache entries ---
    if !found_record {
        let dns_name = DnsName::from_str_unchecked(&qname_str);
        let cache_results = lookup_cache_for_zone(
            &dns_name,
            qtype,
            zone,
            state,
            cache,
            &auth_subnets,
            &auth_excludes,
            ttl,
        );
        if !cache_results.is_empty() {
            nxdomain = false;
            for item in cache_results {
                answers.push(item);
                found_record = true;
            }
        }
    }

    // --- Check CNAME aliases with wildcard matching ---
    if !found_record {
        if let Some(cname_results) = resolve_cname_chain(
            &qname_str,
            qtype,
            zone,
            state,
            cache,
            &auth_subnets,
            &auth_excludes,
            ttl,
        ) {
            for item in cname_results {
                if item.1 != RRType::CNAME {
                    found_record = true;
                }
                nxdomain = false;
                answers.push(item);
            }
        }
    }

    // --- Determine NXDOMAIN vs NODATA ---
    if !found_record && nxdomain {
        let dns_name = DnsName::from_str_unchecked(&qname_str);
        if cache.cache_find_non_terminal(&dns_name) {
            nxdomain = false;
        }
    }

    let rcode = if nxdomain {
        ResponseCode::NxDomain
    } else {
        ResponseCode::NoError
    };

    build_auth_response(header, question, &answers, zone, state, ttl, rcode)
}

// ---------------------------------------------------------------------------
// Private Helper Functions
// ---------------------------------------------------------------------------

/// Find the matching authoritative zone for a query name (longest match).
fn find_matching_zone<'a>(
    name: &str,
    zones: &'a [crate::core::types::AuthZone],
) -> Option<(&'a crate::core::types::AuthZone, usize)> {
    let mut best_match: Option<(&crate::core::types::AuthZone, usize)> = None;
    let mut best_len: usize = 0;

    for zone in zones {
        if hostname_eq(name, &zone.domain) {
            let zone_len = zone.domain.len();
            if zone_len > best_len {
                best_len = zone_len;
                best_match = Some((zone, 0));
            }
            continue;
        }

        let name_len = name.len();
        let zone_len = zone.domain.len();
        if name_len > zone_len + 1 {
            let dot_pos = name_len - zone_len - 1;
            if name.as_bytes()[dot_pos] == b'.' {
                let suffix = &name[dot_pos + 1..];
                if hostname_eq(suffix, &zone.domain) && zone_len > best_len {
                    best_len = zone_len;
                    best_match = Some((zone, dot_pos));
                }
            }
        }
    }
    best_match
}

/// Handle PTR (reverse DNS) lookups within an authoritative zone.
fn handle_ptr_lookup(
    qname: &str,
    zone: &crate::core::types::AuthZone,
    state: &DaemonState,
    cache: &mut DnsCache,
    ttl: u32,
) -> Option<Vec<(DnsName, RRType, u32, Vec<u8>)>> {
    let mut results = Vec::new();
    let dns_name = DnsName::from_str_unchecked(qname);

    // Look up PTR records in cache.
    let cache_entries = cache.cache_find_by_name(&dns_name, Some(RRType::PTR));
    for ce in &cache_entries {
        if let CacheData::Ptr(target) = &ce.data {
            let target_str = target.to_string().trim_end_matches('.').to_string();
            if is_subdomain(&target_str, &zone.domain) || hostname_eq(&target_str, &zone.domain) {
                let rdata = build_ptr_rdata(&target_str);
                results.push((dns_name.clone(), RRType::PTR, ttl, rdata));
            }
        }
    }

    // Check A/AAAA entries by address for reverse lookups.
    if let Some(addr) = parse_reverse_name(qname) {
        let addr_entries = cache.cache_find_by_addr(&addr);
        for ce in &addr_entries {
            if ce.flags.from_dhcp || ce.flags.from_hosts {
                let target_str = ce.name.to_string().trim_end_matches('.').to_string();
                if is_subdomain(&target_str, &zone.domain) || hostname_eq(&target_str, &zone.domain)
                {
                    let rdata = build_ptr_rdata(&target_str);
                    results.push((dns_name.clone(), RRType::PTR, ttl, rdata));
                }
            }
        }

        // Check synthetic reverse names.
        if results.is_empty() {
            let synth_domains = convert_synth_domains(&state.synth_domains);
            if let Ok(Some(synth_name)) = crate::dns::domain::is_rev_synth(&addr, &synth_domains) {
                if is_subdomain(&synth_name, &zone.domain) || hostname_eq(&synth_name, &zone.domain)
                {
                    let rdata = build_ptr_rdata(&synth_name);
                    results.push((dns_name.clone(), RRType::PTR, ttl, rdata));
                }
            }
        }
    }

    if results.is_empty() {
        None
    } else {
        Some(results)
    }
}

/// Parse an in-addr.arpa or ip6.arpa name back to an IP address.
fn parse_reverse_name(name: &str) -> Option<IpAddr> {
    let lower = name.to_ascii_lowercase();

    if let Some(v4_part) = lower.strip_suffix(".in-addr.arpa") {
        let octets: Vec<&str> = v4_part.split('.').collect();
        if octets.len() == 4 {
            let a: u8 = octets[3].parse().ok()?;
            let b: u8 = octets[2].parse().ok()?;
            let c: u8 = octets[1].parse().ok()?;
            let d: u8 = octets[0].parse().ok()?;
            return Some(IpAddr::V4(Ipv4Addr::new(a, b, c, d)));
        }
    }

    if let Some(v6_part) = lower.strip_suffix(".ip6.arpa") {
        let nibbles: Vec<&str> = v6_part.split('.').collect();
        if nibbles.len() == 32 {
            let mut octets = [0u8; 16];
            for (i, octet) in octets.iter_mut().enumerate() {
                let hi_idx = 31 - (i * 2);
                let lo_idx = 31 - (i * 2 + 1);
                let hi = u8::from_str_radix(nibbles[hi_idx], 16).ok()?;
                let lo = u8::from_str_radix(nibbles[lo_idx], 16).ok()?;
                *octet = (hi << 4) | lo;
            }
            return Some(IpAddr::V6(Ipv6Addr::from(octets)));
        }
    }

    None
}

/// Convert an AuthRecord to an RR (type, rdata) tuple if it matches the query type.
pub fn record_to_rr(record: &AuthRecord, qtype: RRType) -> Option<(RRType, Vec<u8>)> {
    match record {
        AuthRecord::A(v4) if qtype == RRType::A || qtype == RRType::ANY => {
            Some((RRType::A, v4.octets().to_vec()))
        }
        AuthRecord::Aaaa(v6) if qtype == RRType::AAAA || qtype == RRType::ANY => {
            Some((RRType::AAAA, v6.octets().to_vec()))
        }
        AuthRecord::Cname(target) if qtype == RRType::CNAME || qtype == RRType::ANY => {
            Some((RRType::CNAME, build_cname_rdata(target)))
        }
        AuthRecord::Mx {
            preference,
            exchange,
        } if qtype == RRType::MX || qtype == RRType::ANY => {
            Some((RRType::MX, build_mx_rdata(*preference, exchange)))
        }
        AuthRecord::Srv {
            priority,
            weight,
            port,
            target,
        } if qtype == RRType::SRV || qtype == RRType::ANY => Some((
            RRType::SRV,
            build_srv_rdata(*priority, *weight, *port, target),
        )),
        AuthRecord::Txt(text) if qtype == RRType::TXT || qtype == RRType::ANY => {
            Some((RRType::TXT, build_txt_rdata(text.as_bytes())))
        }
        AuthRecord::Naptr {
            order,
            preference,
            flags,
            service,
            regexp,
            replacement,
        } if qtype == RRType::NAPTR || qtype == RRType::ANY => Some((
            RRType::NAPTR,
            build_naptr_rdata(*order, *preference, flags, service, regexp, replacement),
        )),
        AuthRecord::Ptr(target) if qtype == RRType::PTR || qtype == RRType::ANY => {
            Some((RRType::PTR, build_ptr_rdata(target)))
        }
        _ => None,
    }
}

/// Look up DNS cache entries (DHCP/hosts) belonging to the authoritative zone.
fn lookup_cache_for_zone(
    dns_name: &DnsName,
    qtype: RRType,
    zone: &crate::core::types::AuthZone,
    state: &DaemonState,
    cache: &mut DnsCache,
    auth_subnets: &[AuthSubnet],
    auth_excludes: &[AuthSubnet],
    ttl: u32,
) -> Vec<(DnsName, RRType, u32, Vec<u8>)> {
    let mut results = Vec::new();
    let name_str = dns_name.to_string().trim_end_matches('.').to_string();

    if !hostname_eq(&name_str, &zone.domain) && !is_subdomain(&name_str, &zone.domain) {
        return results;
    }

    let rr_filter = match qtype {
        RRType::A => Some(RRType::A),
        RRType::AAAA => Some(RRType::AAAA),
        RRType::ANY => None,
        _ => return results,
    };

    let entries = cache.cache_find_by_name(dns_name, rr_filter);
    for ce in entries {
        if !ce.flags.from_dhcp && !ce.flags.from_hosts {
            continue;
        }
        match &ce.data {
            CacheData::Addr4(v4) if qtype == RRType::A || qtype == RRType::ANY => {
                let addr_ip = IpAddr::V4(*v4);
                if filter_zone(&addr_ip, auth_subnets, auth_excludes, FilterFlag::Forward) {
                    results.push((dns_name.clone(), RRType::A, ttl, v4.octets().to_vec()));
                }
            }
            CacheData::Addr6(v6) if qtype == RRType::AAAA || qtype == RRType::ANY => {
                let addr_ip = IpAddr::V6(*v6);
                if filter_zone(&addr_ip, auth_subnets, auth_excludes, FilterFlag::Forward) {
                    results.push((dns_name.clone(), RRType::AAAA, ttl, v6.octets().to_vec()));
                }
            }
            _ => {}
        }
    }

    // Also look up bare hostnames when DHCP_FQDN is not set.
    if results.is_empty() && !state.options.is_set(opt::DHCP_FQDN) {
        let trimmed = name_str.trim_end_matches('.');
        if let Some(dot_pos) = trimmed.find('.') {
            let bare_name = &trimmed[..dot_pos];
            let suffix = &trimmed[dot_pos + 1..];
            if hostname_eq(suffix, &zone.domain) {
                let bare_dns_name = DnsName::from_str_unchecked(bare_name);
                let bare_entries = cache.cache_find_by_name(&bare_dns_name, rr_filter);
                for ce in bare_entries {
                    if !ce.flags.from_dhcp {
                        continue;
                    }
                    match &ce.data {
                        CacheData::Addr4(v4) if qtype == RRType::A || qtype == RRType::ANY => {
                            results.push((dns_name.clone(), RRType::A, ttl, v4.octets().to_vec()));
                        }
                        CacheData::Addr6(v6) if qtype == RRType::AAAA || qtype == RRType::ANY => {
                            results.push((
                                dns_name.clone(),
                                RRType::AAAA,
                                ttl,
                                v6.octets().to_vec(),
                            ));
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    results
}

/// Resolve CNAME chain for wildcard matching.
fn resolve_cname_chain(
    qname: &str,
    qtype: RRType,
    zone: &crate::core::types::AuthZone,
    state: &DaemonState,
    cache: &mut DnsCache,
    auth_subnets: &[AuthSubnet],
    auth_excludes: &[AuthSubnet],
    ttl: u32,
) -> Option<Vec<(DnsName, RRType, u32, Vec<u8>)>> {
    let mut results = Vec::new();
    let mut current_name = qname.to_string();
    let mut depth = 0;

    loop {
        if depth >= CNAME_CHAIN as usize {
            warn!(
                name = %qname,
                depth,
                "CNAME chain depth exceeded (max {})",
                CNAME_CHAIN
            );
            break;
        }

        let mut found_cname = false;
        let mut best_match: Option<&crate::core::types::CnameRecord> = None;
        let mut best_match_len = 0usize;

        for cname in &state.cnames {
            let alias = &cname.alias;
            if hostname_eq(alias, &current_name) {
                best_match = Some(cname);
                let _ = alias.len(); // exact match always wins
                break;
            }
            // Wildcard: "*.domain" matches "anything.domain"
            if let Some(wildcard_domain) = alias.strip_prefix("*.") {
                if is_subdomain(&current_name, wildcard_domain) {
                    let match_len = wildcard_domain.len();
                    if match_len > best_match_len {
                        best_match = Some(cname);
                        best_match_len = match_len;
                    }
                }
            }
        }

        if let Some(cname_record) = best_match {
            found_cname = true;
            let cname_target = &cname_record.target;
            let cname_ttl = if cname_record.ttl > 0 {
                cname_record.ttl
            } else {
                ttl
            };

            let cname_dns_name = DnsName::from_str_unchecked(&current_name);
            let rdata = build_cname_rdata(cname_target);
            results.push((cname_dns_name, RRType::CNAME, cname_ttl, rdata));

            if qtype == RRType::CNAME {
                return if results.is_empty() {
                    None
                } else {
                    Some(results)
                };
            }

            current_name = cname_target.clone();
            depth += 1;

            let target_dns_name = DnsName::from_str_unchecked(&current_name);
            let target_results = lookup_cache_for_zone(
                &target_dns_name,
                qtype,
                zone,
                state,
                cache,
                auth_subnets,
                auth_excludes,
                ttl,
            );
            if !target_results.is_empty() {
                results.extend(target_results);
                return Some(results);
            }
        }

        if !found_cname {
            break;
        }
    }

    if results.is_empty() {
        None
    } else {
        Some(results)
    }
}

/// Handle AXFR (full zone transfer) requests.
fn handle_axfr(
    header: &DnsHeader,
    question: &DnsQuestion,
    zone: &crate::core::types::AuthZone,
    state: &DaemonState,
    cache: &mut DnsCache,
    peer_addr: &std::net::SocketAddr,
    ttl: u32,
) -> DnsmasqResult<AuthResult> {
    // Authorization check.
    if !state.auth_peers.is_empty() {
        let authorized = state.auth_peers.iter().any(|peer| {
            if let Some(ref peer_ip) = peer.addr {
                match (peer_ip, peer_addr.ip()) {
                    (IpAddr::V4(a), IpAddr::V4(b)) => *a == b,
                    (IpAddr::V6(a), IpAddr::V6(b)) => *a == b,
                    _ => false,
                }
            } else {
                false
            }
        });

        if !authorized {
            warn!(
                peer = %peer_addr,
                zone = %zone.domain,
                "AXFR transfer refused: unauthorized peer"
            );
            return build_error_response(header, question, ResponseCode::Refused);
        }
    }

    info!(
        peer = %peer_addr,
        zone = %zone.domain,
        "processing AXFR zone transfer"
    );

    let zone_name = DnsName::from_str_unchecked(&zone.domain);
    let mut transfer_records: Vec<(DnsName, RRType, u32, Vec<u8>)> = Vec::new();

    // MX records.
    for mx in &state.mxnames {
        if mx.is_mx && (hostname_eq(&mx.name, &zone.domain) || is_subdomain(&mx.name, &zone.domain))
        {
            let rdata = build_mx_rdata(mx.priority, &mx.target);
            let name = DnsName::from_str_unchecked(&mx.name);
            transfer_records.push((name, RRType::MX, ttl, rdata));
        }
    }

    // SRV records.
    for srv in &state.mxnames {
        if !srv.is_mx
            && (hostname_eq(&srv.name, &zone.domain) || is_subdomain(&srv.name, &zone.domain))
        {
            let rdata = build_srv_rdata(srv.priority, srv.weight, srv.port, &srv.target);
            let name = DnsName::from_str_unchecked(&srv.name);
            transfer_records.push((name, RRType::SRV, ttl, rdata));
        }
    }

    // Custom RR records.
    for rr in &state.rr_records {
        if hostname_eq(&rr.name, &zone.domain) || is_subdomain(&rr.name, &zone.domain) {
            let rr_type = RRType::from_u16(rr.rr_type);
            let name = DnsName::from_str_unchecked(&rr.name);
            transfer_records.push((name, rr_type, ttl, rr.txt.clone()));
        }
    }

    // TXT records.
    for txt in &state.txt_records {
        if (hostname_eq(&txt.name, &zone.domain) || is_subdomain(&txt.name, &zone.domain))
            && txt.class == DnsClass::IN.to_u16()
        {
            let rdata = build_txt_rdata(&txt.txt);
            let name = DnsName::from_str_unchecked(&txt.name);
            transfer_records.push((name, RRType::TXT, ttl, rdata));
        }
    }

    // NAPTR records.
    for naptr in &state.naptr {
        if hostname_eq(&naptr.name, &zone.domain) || is_subdomain(&naptr.name, &zone.domain) {
            let rdata = build_naptr_rdata(
                naptr.order,
                naptr.pref,
                &naptr.flags,
                &naptr.services,
                &naptr.regexp,
                &naptr.replace,
            );
            let name = DnsName::from_str_unchecked(&naptr.name);
            transfer_records.push((name, RRType::NAPTR, ttl, rdata));
        }
    }

    // CNAME aliases.
    for cname in &state.cnames {
        if hostname_eq(&cname.alias, &zone.domain) || is_subdomain(&cname.alias, &zone.domain) {
            let rdata = build_cname_rdata(&cname.target);
            let name = DnsName::from_str_unchecked(&cname.alias);
            let cname_ttl = if cname.ttl > 0 { cname.ttl } else { ttl };
            transfer_records.push((name, RRType::CNAME, cname_ttl, rdata));
        }
    }

    // Cache entries (DHCP/hosts) within the zone.
    let all_cache = cache.cache_enumerate();
    for ce in all_cache {
        if !ce.flags.from_dhcp && !ce.flags.from_hosts {
            continue;
        }
        let entry_name_str = ce.name.to_string().trim_end_matches('.').to_string();
        if !hostname_eq(&entry_name_str, &zone.domain)
            && !is_subdomain(&entry_name_str, &zone.domain)
        {
            continue;
        }
        match &ce.data {
            CacheData::Addr4(v4) => {
                transfer_records.push((ce.name.clone(), RRType::A, ttl, v4.octets().to_vec()));
            }
            CacheData::Addr6(v6) => {
                transfer_records.push((ce.name.clone(), RRType::AAAA, ttl, v6.octets().to_vec()));
            }
            _ => {}
        }
    }

    // Build AXFR: SOA, NS records, all zone records, SOA.
    let soa_rdata = build_soa_record(zone, state, ttl);
    let ns_records = build_ns_records(zone, state, ttl);

    let mut all_records = Vec::new();
    all_records.push((zone_name.clone(), RRType::SOA, ttl, soa_rdata.clone()));
    for (name, rr_type, ns_ttl, rdata) in &ns_records {
        all_records.push((name.clone(), *rr_type, *ns_ttl, rdata.clone()));
    }
    all_records.extend(transfer_records);
    all_records.push((zone_name, RRType::SOA, ttl, soa_rdata));

    let mut builder = DnsPacketBuilder::new(header.id)
        .set_response()
        .set_authoritative();
    builder = builder.add_question(&question.name, question.qtype, question.qclass);
    for (name, rr_type, rr_ttl, rdata) in &all_records {
        builder = builder.add_answer(name, *rr_type, DnsClass::IN, *rr_ttl, rdata);
    }

    let pkt = builder.build()?;
    let packets = vec![pkt.raw.to_vec()];

    Ok(AuthResult::AxfrTransfer(packets))
}

/// Handle SOA query at zone apex.
fn handle_soa_query(
    header: &DnsHeader,
    question: &DnsQuestion,
    zone: &crate::core::types::AuthZone,
    state: &DaemonState,
    ttl: u32,
) -> DnsmasqResult<AuthResult> {
    let zone_name = DnsName::from_str_unchecked(&zone.domain);
    let soa_rdata = build_soa_record(zone, state, ttl);
    let answers = vec![(zone_name, RRType::SOA, ttl, soa_rdata)];
    build_auth_response(
        header,
        question,
        &answers,
        zone,
        state,
        ttl,
        ResponseCode::NoError,
    )
}

/// Handle NS query at zone apex.
fn handle_ns_query(
    header: &DnsHeader,
    question: &DnsQuestion,
    zone: &crate::core::types::AuthZone,
    state: &DaemonState,
    ttl: u32,
) -> DnsmasqResult<AuthResult> {
    let answers = build_ns_records(zone, state, ttl);
    build_auth_response(
        header,
        question,
        &answers,
        zone,
        state,
        ttl,
        ResponseCode::NoError,
    )
}

/// Build the final authoritative DNS response packet.
fn build_auth_response(
    original_header: &DnsHeader,
    question: &DnsQuestion,
    answers: &[(DnsName, RRType, u32, Vec<u8>)],
    zone: &crate::core::types::AuthZone,
    state: &DaemonState,
    ttl: u32,
    rcode: ResponseCode,
) -> DnsmasqResult<AuthResult> {
    let mut builder = DnsPacketBuilder::new(original_header.id)
        .set_response()
        .set_authoritative();

    builder = builder.add_question(&question.name, question.qtype, question.qclass);

    for (name, rr_type, rr_ttl, rdata) in answers {
        builder = builder.add_answer(name, *rr_type, DnsClass::IN, *rr_ttl, rdata);
    }

    // Authority section: SOA + NS records.
    let zone_name = DnsName::from_str_unchecked(&zone.domain);
    let soa_rdata = build_soa_record(zone, state, ttl);
    builder = builder.add_authority(&zone_name, RRType::SOA, DnsClass::IN, ttl, &soa_rdata);

    let ns_records = build_ns_records(zone, state, ttl);
    for (name, rr_type, ns_ttl, rdata) in &ns_records {
        builder = builder.add_authority(name, *rr_type, DnsClass::IN, *ns_ttl, rdata);
    }

    let pkt = builder.build()?;
    let mut raw = pkt.raw.to_vec();

    // Patch the RCODE in the raw bytes.
    patch_rcode(&mut raw, rcode);

    debug!(
        id = original_header.id,
        rcode = %rcode,
        answers = answers.len(),
        "auth response built"
    );

    Ok(AuthResult::Response(raw))
}

/// Build error response for refused/not-implemented queries.
fn build_error_response(
    header: &DnsHeader,
    question: &DnsQuestion,
    rcode: ResponseCode,
) -> DnsmasqResult<AuthResult> {
    let builder = DnsPacketBuilder::new(header.id)
        .set_response()
        .set_authoritative()
        .add_question(&question.name, question.qtype, question.qclass);

    let pkt = builder.build()?;
    let mut raw = pkt.raw.to_vec();
    patch_rcode(&mut raw, rcode);

    warn!(
        id = header.id,
        rcode = %rcode,
        name = %question.name,
        "auth error response"
    );

    Ok(AuthResult::Response(raw))
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_in_zone_exact_match() {
        let zone = AuthZone::new("example.com".to_string());
        assert_eq!(in_zone(&zone, "example.com"), Some(0));
    }

    #[test]
    fn test_in_zone_subdomain() {
        let zone = AuthZone::new("example.com".to_string());
        assert_eq!(in_zone(&zone, "host.example.com"), Some(4));
    }

    #[test]
    fn test_in_zone_deep_subdomain() {
        let zone = AuthZone::new("example.com".to_string());
        assert_eq!(in_zone(&zone, "a.b.example.com"), Some(3));
    }

    #[test]
    fn test_in_zone_no_match() {
        let zone = AuthZone::new("example.com".to_string());
        assert_eq!(in_zone(&zone, "other.net"), None);
    }

    #[test]
    fn test_in_zone_not_subdomain() {
        let zone = AuthZone::new("example.com".to_string());
        assert_eq!(in_zone(&zone, "notexample.com"), None);
    }

    #[test]
    fn test_in_zone_case_insensitive() {
        let zone = AuthZone::new("Example.COM".to_string());
        assert_eq!(in_zone(&zone, "host.example.com"), Some(4));
        assert_eq!(in_zone(&zone, "EXAMPLE.COM"), Some(0));
    }

    #[test]
    fn test_auth_subnet_v4() {
        let subnet = AuthSubnet::new_v4(Ipv4Addr::new(192, 168, 1, 0), 24);
        assert!(!subnet.is_v6);
        assert_eq!(subnet.prefix_len, 24);
        let mask = subnet.to_v4_mask();
        assert_eq!(mask, Ipv4Addr::new(255, 255, 255, 0));
    }

    #[test]
    fn test_auth_subnet_v6() {
        let subnet = AuthSubnet::new_v6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 48);
        assert!(subnet.is_v6);
        assert_eq!(subnet.prefix_len, 48);
    }

    #[test]
    fn test_filter_zone_empty_subnets() {
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        assert!(filter_zone(&addr, &[], &[], FilterFlag::Forward));
    }

    #[test]
    fn test_filter_zone_excluded() {
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let exclude = vec![AuthSubnet::new_v4(Ipv4Addr::new(192, 168, 1, 0), 24)];
        assert!(!filter_zone(&addr, &[], &exclude, FilterFlag::Forward));
    }

    #[test]
    fn test_filter_zone_included() {
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let subnet = vec![AuthSubnet::new_v4(Ipv4Addr::new(192, 168, 1, 0), 24)];
        assert!(filter_zone(&addr, &subnet, &[], FilterFlag::Forward));
    }

    #[test]
    fn test_filter_zone_not_in_subnet() {
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let subnet = vec![AuthSubnet::new_v4(Ipv4Addr::new(192, 168, 1, 0), 24)];
        assert!(!filter_zone(&addr, &subnet, &[], FilterFlag::Forward));
    }

    #[test]
    fn test_parse_reverse_name_v4() {
        let name = "1.0.168.192.in-addr.arpa";
        let addr = parse_reverse_name(name);
        assert_eq!(addr, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1))));
    }

    #[test]
    fn test_parse_reverse_name_invalid() {
        let name = "not.a.reverse.name";
        assert_eq!(parse_reverse_name(name), None);
    }

    #[test]
    fn test_build_soa_rdata() {
        let rdata = build_soa_rdata(
            "ns1.example.com",
            "hostmaster.example.com",
            2024010100,
            SOA_REFRESH,
            SOA_RETRY,
            SOA_EXPIRY,
            AUTH_TTL,
        );
        assert!(!rdata.is_empty());
        assert!(rdata.len() >= 24);
    }

    #[test]
    fn test_encode_name_wire() {
        let mut buf = Vec::new();
        encode_name_wire(&mut buf, "example.com");
        assert_eq!(buf[0], 7);
        assert_eq!(&buf[1..8], b"example");
        assert_eq!(buf[8], 3);
        assert_eq!(&buf[9..12], b"com");
        assert_eq!(buf[12], 0);
    }

    #[test]
    fn test_build_mx_rdata() {
        let rdata = build_mx_rdata(10, "mail.example.com");
        assert_eq!(rdata[0], 0);
        assert_eq!(rdata[1], 10);
    }

    #[test]
    fn test_auth_record_variants() {
        let a = AuthRecord::A(Ipv4Addr::new(192, 168, 1, 1));
        let aaaa = AuthRecord::Aaaa(Ipv6Addr::LOCALHOST);
        let cname = AuthRecord::Cname("alias.example.com".to_string());
        let mx = AuthRecord::Mx {
            preference: 10,
            exchange: "mail.example.com".to_string(),
        };
        let srv = AuthRecord::Srv {
            priority: 0,
            weight: 5,
            port: 443,
            target: "www.example.com".to_string(),
        };
        let txt = AuthRecord::Txt("v=spf1 +mx".to_string());
        let naptr = AuthRecord::Naptr {
            order: 100,
            preference: 10,
            flags: "u".to_string(),
            service: "E2U+sip".to_string(),
            regexp: "!^.*$!sip:info@example.com!".to_string(),
            replacement: ".".to_string(),
        };
        let ptr = AuthRecord::Ptr("host.example.com".to_string());

        assert!(record_to_rr(&a, RRType::A).is_some());
        assert!(record_to_rr(&a, RRType::AAAA).is_none());
        assert!(record_to_rr(&aaaa, RRType::AAAA).is_some());
        assert!(record_to_rr(&cname, RRType::CNAME).is_some());
        assert!(record_to_rr(&mx, RRType::MX).is_some());
        assert!(record_to_rr(&srv, RRType::SRV).is_some());
        assert!(record_to_rr(&txt, RRType::TXT).is_some());
        assert!(record_to_rr(&naptr, RRType::NAPTR).is_some());
        assert!(record_to_rr(&ptr, RRType::PTR).is_some());

        assert!(record_to_rr(&a, RRType::ANY).is_some());
        assert!(record_to_rr(&aaaa, RRType::ANY).is_some());
    }

    #[test]
    fn test_auth_name_entry() {
        let entry = AuthNameEntry {
            name: "host.example.com".to_string(),
            records: vec![
                AuthRecord::A(Ipv4Addr::new(192, 168, 1, 1)),
                AuthRecord::Aaaa(Ipv6Addr::LOCALHOST),
            ],
        };
        assert_eq!(entry.name, "host.example.com");
        assert_eq!(entry.records.len(), 2);
    }

    #[test]
    fn test_parse_subnet_spec() {
        let subnet = parse_subnet_spec("192.168.1.0/24").unwrap();
        assert_eq!(subnet.addr, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)));
        assert_eq!(subnet.prefix_len, 24);
        assert!(!subnet.is_v6);

        let subnet6 = parse_subnet_spec("2001:db8::/32").unwrap();
        assert!(subnet6.is_v6);
        assert_eq!(subnet6.prefix_len, 32);

        let host = parse_subnet_spec("10.0.0.1").unwrap();
        assert_eq!(host.prefix_len, 32);

        assert!(parse_subnet_spec("not-an-addr/24").is_none());
    }

    #[test]
    fn test_build_txt_rdata() {
        let rdata = build_txt_rdata(b"hello world");
        assert_eq!(rdata[0], 11);
        assert_eq!(&rdata[1..], b"hello world");
    }

    #[test]
    fn test_build_txt_rdata_empty() {
        let rdata = build_txt_rdata(b"");
        assert_eq!(rdata, vec![0]);
    }

    #[test]
    fn test_build_srv_rdata() {
        let rdata = build_srv_rdata(10, 20, 443, "www.example.com");
        assert_eq!(rdata[0], 0);
        assert_eq!(rdata[1], 10);
        assert_eq!(rdata[2], 0);
        assert_eq!(rdata[3], 20);
        assert_eq!(rdata[4], 1);
        assert_eq!(rdata[5], 187);
    }

    #[test]
    fn test_build_naptr_rdata() {
        let rdata = build_naptr_rdata(100, 10, "u", "E2U+sip", "!^.*$!sip:info!", ".");
        assert!(!rdata.is_empty());
        assert_eq!(rdata[0], 0);
        assert_eq!(rdata[1], 100);
        assert_eq!(rdata[2], 0);
        assert_eq!(rdata[3], 10);
    }

    #[test]
    fn test_patch_rcode() {
        let mut raw = vec![0u8; 12]; // minimal DNS header
        patch_rcode(&mut raw, ResponseCode::NxDomain);
        assert_eq!(raw[3] & 0x0f, 3); // NXDOMAIN = 3

        patch_rcode(&mut raw, ResponseCode::Refused);
        assert_eq!(raw[3] & 0x0f, 5); // REFUSED = 5

        patch_rcode(&mut raw, ResponseCode::NoError);
        assert_eq!(raw[3] & 0x0f, 0); // NOERROR = 0
    }

    #[test]
    fn test_zone_to_auth_subnet() {
        let strings = vec![
            "192.168.1.0/24".to_string(),
            "10.0.0.0/8".to_string(),
            "invalid-addr".to_string(),
        ];
        let subnets = zone_to_auth_subnet(&strings);
        assert_eq!(subnets.len(), 2);
        assert_eq!(subnets[0].prefix_len, 24);
        assert_eq!(subnets[1].prefix_len, 8);
    }

    #[test]
    fn test_auth_zone_new() {
        let zone = AuthZone::new("test.local".to_string());
        assert_eq!(zone.domain, "test.local");
        assert!(zone.subnet.is_empty());
        assert!(zone.exclude.is_empty());
        assert!(!zone.interface_names);
        assert!(zone.name_list.is_empty());
    }

    #[test]
    fn test_auth_subnet_mask_boundaries() {
        let subnet_0 = AuthSubnet::new_v4(Ipv4Addr::UNSPECIFIED, 0);
        assert_eq!(subnet_0.to_v4_mask(), Ipv4Addr::UNSPECIFIED);

        let subnet_32 = AuthSubnet::new_v4(Ipv4Addr::LOCALHOST, 32);
        assert_eq!(subnet_32.to_v4_mask(), Ipv4Addr::new(255, 255, 255, 255));

        let subnet_16 = AuthSubnet::new_v4(Ipv4Addr::new(172, 16, 0, 0), 16);
        assert_eq!(subnet_16.to_v4_mask(), Ipv4Addr::new(255, 255, 0, 0));
    }

    #[test]
    fn test_build_cname_rdata() {
        let rdata = build_cname_rdata("target.example.com");
        // Should be wire-encoded name
        assert_eq!(rdata[0], 6); // "target" = 6 bytes
        assert_eq!(&rdata[1..7], b"target");
    }

    #[test]
    fn test_build_ptr_rdata() {
        let rdata = build_ptr_rdata("host.example.com");
        assert_eq!(rdata[0], 4); // "host" = 4 bytes
        assert_eq!(&rdata[1..5], b"host");
    }

    #[test]
    fn test_encode_character_string() {
        let mut buf = Vec::new();
        encode_character_string(&mut buf, "hello");
        assert_eq!(buf, vec![5, b'h', b'e', b'l', b'l', b'o']);
    }

    // -----------------------------------------------------------------------
    // record_to_rr comprehensive tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_record_to_rr_a_record() {
        let rec = AuthRecord::A(Ipv4Addr::new(192, 168, 1, 1));
        let result = record_to_rr(&rec, RRType::A);
        assert!(result.is_some());
        let (rr_type, rdata) = result.unwrap();
        assert_eq!(rr_type, RRType::A);
        assert_eq!(rdata, vec![192, 168, 1, 1]);
    }

    #[test]
    fn test_record_to_rr_a_record_any() {
        let rec = AuthRecord::A(Ipv4Addr::new(10, 0, 0, 1));
        let result = record_to_rr(&rec, RRType::ANY);
        assert!(result.is_some());
        let (rr_type, _) = result.unwrap();
        assert_eq!(rr_type, RRType::A);
    }

    #[test]
    fn test_record_to_rr_a_record_wrong_type() {
        let rec = AuthRecord::A(Ipv4Addr::new(10, 0, 0, 1));
        assert!(record_to_rr(&rec, RRType::AAAA).is_none());
        assert!(record_to_rr(&rec, RRType::MX).is_none());
    }

    #[test]
    fn test_record_to_rr_aaaa_record() {
        let rec = AuthRecord::Aaaa(Ipv6Addr::LOCALHOST);
        let result = record_to_rr(&rec, RRType::AAAA);
        assert!(result.is_some());
        let (rr_type, rdata) = result.unwrap();
        assert_eq!(rr_type, RRType::AAAA);
        assert_eq!(rdata.len(), 16);
    }

    #[test]
    fn test_record_to_rr_aaaa_any() {
        let rec = AuthRecord::Aaaa(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let result = record_to_rr(&rec, RRType::ANY);
        assert!(result.is_some());
    }

    #[test]
    fn test_record_to_rr_aaaa_wrong_type() {
        let rec = AuthRecord::Aaaa(Ipv6Addr::LOCALHOST);
        assert!(record_to_rr(&rec, RRType::A).is_none());
    }

    #[test]
    fn test_record_to_rr_cname() {
        let rec = AuthRecord::Cname("alias.example.com".to_string());
        let result = record_to_rr(&rec, RRType::CNAME);
        assert!(result.is_some());
        let (rr_type, rdata) = result.unwrap();
        assert_eq!(rr_type, RRType::CNAME);
        assert!(!rdata.is_empty());
        // Wire format should start with label length
        assert_eq!(rdata[0], 5); // "alias" = 5 bytes
    }

    #[test]
    fn test_record_to_rr_cname_wrong_type() {
        let rec = AuthRecord::Cname("alias.example.com".to_string());
        assert!(record_to_rr(&rec, RRType::A).is_none());
    }

    #[test]
    fn test_record_to_rr_mx() {
        let rec = AuthRecord::Mx {
            preference: 10,
            exchange: "mail.example.com".to_string(),
        };
        let result = record_to_rr(&rec, RRType::MX);
        assert!(result.is_some());
        let (rr_type, rdata) = result.unwrap();
        assert_eq!(rr_type, RRType::MX);
        // First 2 bytes = preference in big-endian
        assert_eq!(u16::from_be_bytes([rdata[0], rdata[1]]), 10);
    }

    #[test]
    fn test_record_to_rr_mx_any() {
        let rec = AuthRecord::Mx {
            preference: 20,
            exchange: "mx.test.com".to_string(),
        };
        assert!(record_to_rr(&rec, RRType::ANY).is_some());
    }

    #[test]
    fn test_record_to_rr_srv() {
        let rec = AuthRecord::Srv {
            priority: 10,
            weight: 60,
            port: 5060,
            target: "sip.example.com".to_string(),
        };
        let result = record_to_rr(&rec, RRType::SRV);
        assert!(result.is_some());
        let (rr_type, rdata) = result.unwrap();
        assert_eq!(rr_type, RRType::SRV);
        assert_eq!(u16::from_be_bytes([rdata[0], rdata[1]]), 10); // priority
        assert_eq!(u16::from_be_bytes([rdata[2], rdata[3]]), 60); // weight
        assert_eq!(u16::from_be_bytes([rdata[4], rdata[5]]), 5060); // port
    }

    #[test]
    fn test_record_to_rr_txt() {
        let rec = AuthRecord::Txt("v=spf1 include:_spf.example.com ~all".to_string());
        let result = record_to_rr(&rec, RRType::TXT);
        assert!(result.is_some());
        let (rr_type, rdata) = result.unwrap();
        assert_eq!(rr_type, RRType::TXT);
        // First byte is length of character-string
        assert!(!rdata.is_empty());
    }

    #[test]
    fn test_record_to_rr_naptr() {
        let rec = AuthRecord::Naptr {
            order: 100,
            preference: 10,
            flags: "u".to_string(),
            service: "E2U+sip".to_string(),
            regexp: "!^.*$!sip:info@example.com!".to_string(),
            replacement: ".".to_string(),
        };
        let result = record_to_rr(&rec, RRType::NAPTR);
        assert!(result.is_some());
        let (rr_type, rdata) = result.unwrap();
        assert_eq!(rr_type, RRType::NAPTR);
        assert_eq!(u16::from_be_bytes([rdata[0], rdata[1]]), 100);
        assert_eq!(u16::from_be_bytes([rdata[2], rdata[3]]), 10);
    }

    #[test]
    fn test_record_to_rr_ptr() {
        let rec = AuthRecord::Ptr("host.example.com".to_string());
        let result = record_to_rr(&rec, RRType::PTR);
        assert!(result.is_some());
        let (rr_type, rdata) = result.unwrap();
        assert_eq!(rr_type, RRType::PTR);
        assert_eq!(rdata[0], 4); // "host" = 4 bytes
    }

    #[test]
    fn test_record_to_rr_ptr_any() {
        let rec = AuthRecord::Ptr("host.example.com".to_string());
        assert!(record_to_rr(&rec, RRType::ANY).is_some());
    }

    #[test]
    fn test_record_to_rr_ptr_wrong_type() {
        let rec = AuthRecord::Ptr("host.example.com".to_string());
        assert!(record_to_rr(&rec, RRType::A).is_none());
    }

    // -----------------------------------------------------------------------
    // parse_reverse_name comprehensive tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_reverse_name_v4_loopback() {
        let result = parse_reverse_name("1.0.0.127.in-addr.arpa");
        assert_eq!(result, Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
    }

    #[test]
    fn test_parse_reverse_name_v4_network() {
        let result = parse_reverse_name("100.1.168.192.in-addr.arpa");
        assert_eq!(result, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
    }

    #[test]
    fn test_parse_reverse_name_v4_case_insensitive() {
        let result = parse_reverse_name("1.0.0.10.IN-ADDR.ARPA");
        assert_eq!(result, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    #[test]
    fn test_parse_reverse_name_v4_too_few_octets() {
        assert!(parse_reverse_name("1.0.0.in-addr.arpa").is_none());
    }

    #[test]
    fn test_parse_reverse_name_v4_too_many_octets() {
        assert!(parse_reverse_name("1.2.3.4.5.in-addr.arpa").is_none());
    }

    #[test]
    fn test_parse_reverse_name_v6_all_zeros() {
        // All-zeros address: every nibble is 0
        let name = "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa";
        let result = parse_reverse_name(name);
        assert_eq!(result, Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
    }

    #[test]
    fn test_parse_reverse_name_v6_returns_addr() {
        // Verify the function returns a V6 address for a valid 32-nibble ip6.arpa name
        let name = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa";
        let result = parse_reverse_name(name);
        assert!(result.is_some());
        assert!(matches!(result, Some(IpAddr::V6(_))));
    }

    #[test]
    fn test_parse_reverse_name_v6_case_insensitive() {
        let name = "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.IP6.ARPA";
        let result = parse_reverse_name(name);
        assert!(result.is_some());
    }

    #[test]
    fn test_parse_reverse_name_garbage() {
        assert!(parse_reverse_name("not.a.reverse.name").is_none());
        assert!(parse_reverse_name("").is_none());
        assert!(parse_reverse_name("in-addr.arpa").is_none());
    }

    // -----------------------------------------------------------------------
    // find_addrlist comprehensive tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_find_addrlist_v4_match() {
        let list = vec![AuthSubnet::new_v4(Ipv4Addr::new(192, 168, 1, 0), 24)];
        assert!(find_addrlist(
            &IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            &list
        ));
    }

    #[test]
    fn test_find_addrlist_v4_no_match() {
        let list = vec![AuthSubnet::new_v4(Ipv4Addr::new(192, 168, 1, 0), 24)];
        assert!(!find_addrlist(
            &IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            &list
        ));
    }

    #[test]
    fn test_find_addrlist_v6_match() {
        let list = vec![AuthSubnet::new_v6(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
            32,
        )];
        assert!(find_addrlist(
            &IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            &list
        ));
    }

    #[test]
    fn test_find_addrlist_v6_no_match() {
        let list = vec![AuthSubnet::new_v6(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
            32,
        )];
        assert!(!find_addrlist(
            &IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
            &list
        ));
    }

    #[test]
    fn test_find_addrlist_empty_list() {
        assert!(!find_addrlist(&IpAddr::V4(Ipv4Addr::LOCALHOST), &[]));
    }

    #[test]
    fn test_find_addrlist_mixed_families() {
        let list = vec![
            AuthSubnet::new_v4(Ipv4Addr::new(10, 0, 0, 0), 8),
            AuthSubnet::new_v6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10),
        ];
        // V4 addr matches v4 subnet
        assert!(find_addrlist(
            &IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)),
            &list
        ));
        // V6 addr matches v6 subnet
        assert!(find_addrlist(
            &IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
            &list
        ));
        // V4 addr doesn't match v4 subnet
        assert!(!find_addrlist(
            &IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            &list
        ));
    }

    // -----------------------------------------------------------------------
    // filter_zone comprehensive tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_filter_zone_revonly_forward_skip() {
        let mut subnet = AuthSubnet::new_v4(Ipv4Addr::new(192, 168, 1, 0), 24);
        subnet.revonly = true;
        let subnets = vec![subnet];
        // Forward lookup should skip revonly entries
        assert!(!filter_zone(
            &IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            &subnets,
            &[],
            FilterFlag::Forward
        ));
    }

    #[test]
    fn test_filter_zone_revonly_reverse_match() {
        let mut subnet = AuthSubnet::new_v4(Ipv4Addr::new(192, 168, 1, 0), 24);
        subnet.revonly = true;
        let subnets = vec![subnet];
        // Reverse lookup should match revonly entries
        assert!(filter_zone(
            &IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            &subnets,
            &[],
            FilterFlag::Reverse
        ));
    }

    #[test]
    fn test_filter_zone_exclude_takes_precedence() {
        let subnets = vec![AuthSubnet::new_v4(Ipv4Addr::new(10, 0, 0, 0), 8)];
        let excludes = vec![AuthSubnet::new_v4(Ipv4Addr::new(10, 0, 0, 0), 8)];
        // Exclude takes precedence over include
        assert!(!filter_zone(
            &IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)),
            &subnets,
            &excludes,
            FilterFlag::Forward
        ));
    }

    #[test]
    fn test_filter_zone_v6_included() {
        let subnets = vec![AuthSubnet::new_v6(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
            32,
        )];
        assert!(filter_zone(
            &IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            &subnets,
            &[],
            FilterFlag::Forward
        ));
    }

    #[test]
    fn test_filter_zone_v6_excluded() {
        let subnets = vec![AuthSubnet::new_v6(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
            32,
        )];
        assert!(!filter_zone(
            &IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
            &subnets,
            &[],
            FilterFlag::Forward
        ));
    }

    // -----------------------------------------------------------------------
    // build_ns_rdata tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_ns_rdata() {
        let rdata = build_ns_rdata("ns1.example.com");
        assert_eq!(rdata[0], 3); // "ns1" = 3 bytes
        assert_eq!(&rdata[1..4], b"ns1");
    }

    #[test]
    fn test_build_ns_rdata_short_name() {
        let rdata = build_ns_rdata("a.b");
        assert_eq!(rdata[0], 1); // "a" = 1 byte
        assert_eq!(rdata[1], b'a');
        assert_eq!(rdata[2], 1); // "b" = 1 byte
        assert_eq!(rdata[3], b'b');
        assert_eq!(rdata[4], 0); // null terminator
    }

    // -----------------------------------------------------------------------
    // in_zone additional edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_in_zone_empty_name() {
        let zone = AuthZone::new("example.com".to_string());
        assert!(in_zone(&zone, "").is_none());
    }

    #[test]
    fn test_in_zone_very_long_subdomain() {
        let zone = AuthZone::new("example.com".to_string());
        let result = in_zone(&zone, "a.b.c.d.e.f.example.com");
        assert!(result.is_some());
    }

    #[test]
    fn test_in_zone_partial_match() {
        let zone = AuthZone::new("example.com".to_string());
        // "fooexample.com" should NOT match — dot boundary required
        assert!(in_zone(&zone, "fooexample.com").is_none());
    }

    #[test]
    fn test_in_zone_zone_only_dot_diff() {
        let zone = AuthZone::new("com".to_string());
        let result = in_zone(&zone, "example.com");
        assert!(result.is_some());
    }

    // -----------------------------------------------------------------------
    // parse_subnet_spec additional tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_subnet_spec_v6_cidr() {
        let result = parse_subnet_spec("2001:db8::/32");
        assert!(result.is_some());
        let subnet = result.unwrap();
        assert!(subnet.is_v6);
        assert_eq!(subnet.prefix_len, 32);
    }

    #[test]
    fn test_parse_subnet_spec_v6_host() {
        let result = parse_subnet_spec("::1");
        assert!(result.is_some());
        let subnet = result.unwrap();
        assert!(subnet.is_v6);
        assert_eq!(subnet.prefix_len, 128);
    }

    #[test]
    fn test_parse_subnet_spec_invalid() {
        assert!(parse_subnet_spec("not-an-address").is_none());
        assert!(parse_subnet_spec("192.168.1.0/abc").is_none());
        assert!(parse_subnet_spec("").is_none());
    }

    // -----------------------------------------------------------------------
    // zone_to_auth_subnet additional tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_zone_to_auth_subnet_mixed() {
        let specs = vec![
            "10.0.0.0/8".to_string(),
            "2001:db8::/32".to_string(),
            "invalid".to_string(),
            "192.168.1.0/24".to_string(),
        ];
        let result = zone_to_auth_subnet(&specs);
        assert_eq!(result.len(), 3); // invalid is filtered out
    }

    #[test]
    fn test_zone_to_auth_subnet_empty() {
        let result = zone_to_auth_subnet(&[]);
        assert!(result.is_empty());
    }

    // -----------------------------------------------------------------------
    // patch_rcode additional tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_patch_rcode_nxdomain() {
        let mut packet = vec![0u8; 12];
        patch_rcode(&mut packet, ResponseCode::NxDomain);
        assert_eq!(packet[3] & 0x0f, 3); // NXDOMAIN = 3
    }

    #[test]
    fn test_patch_rcode_servfail() {
        let mut packet = vec![0u8; 12];
        patch_rcode(&mut packet, ResponseCode::ServFail);
        assert_eq!(packet[3] & 0x0f, 2);
    }

    #[test]
    fn test_patch_rcode_refused() {
        let mut packet = vec![0u8; 12];
        patch_rcode(&mut packet, ResponseCode::Refused);
        assert_eq!(packet[3] & 0x0f, 5);
    }

    #[test]
    fn test_patch_rcode_preserves_upper_bits() {
        let mut packet = vec![0u8; 12];
        packet[3] = 0xF0; // Set upper 4 bits
        patch_rcode(&mut packet, ResponseCode::NoError);
        assert_eq!(packet[3], 0xF0); // Upper bits preserved, lower = 0
    }

    #[test]
    fn test_patch_rcode_short_packet() {
        let mut packet = vec![0u8; 2]; // Too short
        patch_rcode(&mut packet, ResponseCode::NxDomain);
        // Should not panic, no change
        assert_eq!(packet, vec![0u8; 2]);
    }

    // -----------------------------------------------------------------------
    // encode_name_wire additional tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_encode_name_wire_root() {
        let mut buf = Vec::new();
        encode_name_wire(&mut buf, "");
        assert_eq!(buf, vec![0]); // Just null terminator
    }

    #[test]
    fn test_encode_name_wire_single_label() {
        let mut buf = Vec::new();
        encode_name_wire(&mut buf, "localhost");
        assert_eq!(buf[0], 9); // "localhost" = 9 bytes
        assert_eq!(&buf[1..10], b"localhost");
        assert_eq!(buf[10], 0);
    }

    #[test]
    fn test_encode_name_wire_multiple_labels() {
        let mut buf = Vec::new();
        encode_name_wire(&mut buf, "a.b.c");
        assert_eq!(buf, vec![1, b'a', 1, b'b', 1, b'c', 0]);
    }

    // -----------------------------------------------------------------------
    // build_txt_rdata additional tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_txt_rdata_long() {
        // Longer than 255 bytes - should be split into chunks
        let long_txt = vec![b'A'; 300];
        let rdata = build_txt_rdata(&long_txt);
        // First chunk: 255 bytes
        assert_eq!(rdata[0], 255);
        // Second chunk: 45 bytes
        assert_eq!(rdata[256], 45);
    }

    #[test]
    fn test_build_txt_rdata_exactly_255() {
        let txt = vec![b'B'; 255];
        let rdata = build_txt_rdata(&txt);
        assert_eq!(rdata[0], 255);
        assert_eq!(rdata.len(), 256); // 1 length byte + 255 data
    }

    // -----------------------------------------------------------------------
    // build_soa_rdata additional tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_soa_rdata_with_hostmaster_at() {
        let rdata = build_soa_rdata(
            "ns1.example.com",
            "admin@example.com",
            1,
            3600,
            900,
            604800,
            86400,
        );
        // The hostmaster '@' should be converted to '.'
        // Verify it contains the wire-encoded names plus 5 u32 values (20 bytes)
        assert!(rdata.len() > 20);
    }

    #[test]
    fn test_build_soa_rdata_serial_values() {
        let rdata = build_soa_rdata("ns.test", "admin.test", 12345678, 7200, 1800, 86400, 3600);
        // Find the serial after the two encoded names
        // The encoded names: "ns.test" = [2,n,s,4,t,e,s,t,0] = 9 bytes
        //                    "admin.test" = [5,a,d,m,i,n,4,t,e,s,t,0] = 12 bytes
        // Total name bytes = 21, serial starts at offset 21
        let serial_offset = 9 + 12; // 21
        let serial = u32::from_be_bytes([
            rdata[serial_offset],
            rdata[serial_offset + 1],
            rdata[serial_offset + 2],
            rdata[serial_offset + 3],
        ]);
        assert_eq!(serial, 12345678);
    }

    // -----------------------------------------------------------------------
    // AuthSubnet to_v4_mask comprehensive tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_auth_subnet_mask_zero() {
        let subnet = AuthSubnet::new_v4(Ipv4Addr::UNSPECIFIED, 0);
        assert_eq!(subnet.to_v4_mask(), Ipv4Addr::UNSPECIFIED);
    }

    #[test]
    fn test_auth_subnet_mask_8() {
        let subnet = AuthSubnet::new_v4(Ipv4Addr::new(10, 0, 0, 0), 8);
        assert_eq!(subnet.to_v4_mask(), Ipv4Addr::new(255, 0, 0, 0));
    }

    #[test]
    fn test_auth_subnet_mask_24() {
        let subnet = AuthSubnet::new_v4(Ipv4Addr::new(192, 168, 1, 0), 24);
        assert_eq!(subnet.to_v4_mask(), Ipv4Addr::new(255, 255, 255, 0));
    }

    #[test]
    fn test_auth_subnet_mask_33_clamps() {
        // Prefix > 32 should produce all-ones mask
        let subnet = AuthSubnet::new_v4(Ipv4Addr::LOCALHOST, 33);
        assert_eq!(subnet.to_v4_mask(), Ipv4Addr::new(255, 255, 255, 255));
    }

    // -----------------------------------------------------------------------
    // AuthNameEntry and AuthZone structure tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_auth_zone_with_name_list() {
        let mut zone = AuthZone::new("example.local".to_string());
        zone.name_list.push(AuthNameEntry {
            name: "host1.example.local".to_string(),
            records: vec![
                AuthRecord::A(Ipv4Addr::new(192, 168, 1, 10)),
                AuthRecord::Aaaa(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 10)),
            ],
        });
        zone.name_list.push(AuthNameEntry {
            name: "mail.example.local".to_string(),
            records: vec![AuthRecord::Mx {
                preference: 10,
                exchange: "host1.example.local".to_string(),
            }],
        });
        assert_eq!(zone.name_list.len(), 2);
        assert_eq!(zone.name_list[0].records.len(), 2);
    }

    #[test]
    fn test_auth_zone_with_subnets() {
        let mut zone = AuthZone::new("test.local".to_string());
        zone.subnet
            .push(AuthSubnet::new_v4(Ipv4Addr::new(10, 0, 0, 0), 8));
        zone.exclude
            .push(AuthSubnet::new_v4(Ipv4Addr::new(10, 0, 1, 0), 24));
        assert_eq!(zone.subnet.len(), 1);
        assert_eq!(zone.exclude.len(), 1);
    }

    // -----------------------------------------------------------------------
    // build_srv_rdata edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_srv_rdata_zero_values() {
        let rdata = build_srv_rdata(0, 0, 0, "target.example.com");
        assert_eq!(u16::from_be_bytes([rdata[0], rdata[1]]), 0);
        assert_eq!(u16::from_be_bytes([rdata[2], rdata[3]]), 0);
        assert_eq!(u16::from_be_bytes([rdata[4], rdata[5]]), 0);
    }

    #[test]
    fn test_build_srv_rdata_max_values() {
        let rdata = build_srv_rdata(u16::MAX, u16::MAX, u16::MAX, "t.com");
        assert_eq!(u16::from_be_bytes([rdata[0], rdata[1]]), u16::MAX);
        assert_eq!(u16::from_be_bytes([rdata[2], rdata[3]]), u16::MAX);
        assert_eq!(u16::from_be_bytes([rdata[4], rdata[5]]), u16::MAX);
    }

    // -----------------------------------------------------------------------
    // build_naptr_rdata edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_naptr_rdata_empty_fields() {
        let rdata = build_naptr_rdata(0, 0, "", "", "", ".");
        // order(2) + pref(2) + 3 char-strings + 1 wire name
        assert!(rdata.len() >= 4);
    }

    // -----------------------------------------------------------------------
    // encode_character_string edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_encode_character_string_empty() {
        let mut buf = Vec::new();
        encode_character_string(&mut buf, "");
        assert_eq!(buf, vec![0]);
    }

    #[test]
    fn test_encode_character_string_max_length() {
        let long_str = "A".repeat(300);
        let mut buf = Vec::new();
        encode_character_string(&mut buf, &long_str);
        // Capped at 255
        assert_eq!(buf[0], 255);
        assert_eq!(buf.len(), 256);
    }

    // -----------------------------------------------------------------------
    // AuthSubnet new constructors
    // -----------------------------------------------------------------------

    #[test]
    fn test_auth_subnet_new_v4_fields() {
        let subnet = AuthSubnet::new_v4(Ipv4Addr::new(172, 16, 0, 0), 12);
        assert_eq!(subnet.addr, IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0)));
        assert_eq!(subnet.prefix_len, 12);
        assert!(!subnet.is_v6);
        assert!(!subnet.revonly);
    }

    #[test]
    fn test_auth_subnet_new_v6_fields() {
        let subnet = AuthSubnet::new_v6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0), 7);
        assert_eq!(
            subnet.addr,
            IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0))
        );
        assert_eq!(subnet.prefix_len, 7);
        assert!(subnet.is_v6);
        assert!(!subnet.revonly);
    }

    // -----------------------------------------------------------------------
    // find_matching_zone tests
    // -----------------------------------------------------------------------

    fn make_types_auth_zone(domain: &str) -> crate::core::types::AuthZone {
        crate::core::types::AuthZone {
            domain: domain.to_string(),
            subnet: vec![],
            interface_names: vec![],
            exclude: vec![],
        }
    }

    #[test]
    fn test_find_matching_zone_exact() {
        let zones = vec![make_types_auth_zone("example.com")];
        let result = find_matching_zone("example.com", &zones);
        assert!(result.is_some());
        let (zone, offset) = result.unwrap();
        assert_eq!(zone.domain, "example.com");
        assert_eq!(offset, 0);
    }

    #[test]
    fn test_find_matching_zone_subdomain() {
        let zones = vec![make_types_auth_zone("example.com")];
        let result = find_matching_zone("host.example.com", &zones);
        assert!(result.is_some());
        let (zone, offset) = result.unwrap();
        assert_eq!(zone.domain, "example.com");
        assert!(offset > 0);
    }

    #[test]
    fn test_find_matching_zone_deep_sub() {
        let zones = vec![make_types_auth_zone("example.com")];
        let result = find_matching_zone("a.b.c.example.com", &zones);
        assert!(result.is_some());
    }

    #[test]
    fn test_find_matching_zone_no_match() {
        let zones = vec![make_types_auth_zone("example.com")];
        assert!(find_matching_zone("other.net", &zones).is_none());
    }

    #[test]
    fn test_find_matching_zone_longest_match() {
        let zones = vec![
            make_types_auth_zone("example.com"),
            make_types_auth_zone("sub.example.com"),
        ];
        let result = find_matching_zone("host.sub.example.com", &zones);
        assert!(result.is_some());
        let (zone, _) = result.unwrap();
        assert_eq!(zone.domain, "sub.example.com");
    }

    #[test]
    fn test_find_matching_zone_empty_zones() {
        let zones: Vec<crate::core::types::AuthZone> = vec![];
        assert!(find_matching_zone("example.com", &zones).is_none());
    }

    #[test]
    fn test_find_matching_zone_case_insensitive() {
        let zones = vec![make_types_auth_zone("Example.COM")];
        let result = find_matching_zone("host.example.com", &zones);
        assert!(result.is_some());
    }

    #[test]
    fn test_find_matching_zone_partial_no_dot_boundary() {
        let zones = vec![make_types_auth_zone("ample.com")];
        // "example.com" is NOT a subdomain of "ample.com" (no dot boundary)
        assert!(find_matching_zone("example.com", &zones).is_none());
    }

    #[test]
    fn test_find_matching_zone_multiple_zones_pick_longest() {
        let zones = vec![
            make_types_auth_zone("com"),
            make_types_auth_zone("example.com"),
            make_types_auth_zone("sub.example.com"),
        ];
        let result = find_matching_zone("host.sub.example.com", &zones);
        assert!(result.is_some());
        let (zone, _) = result.unwrap();
        assert_eq!(zone.domain, "sub.example.com");
    }

    #[test]
    fn test_find_matching_zone_single_label() {
        let zones = vec![make_types_auth_zone("local")];
        let result = find_matching_zone("host.local", &zones);
        assert!(result.is_some());
    }

    // -----------------------------------------------------------------------
    // build_soa_record tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_soa_record_defaults() {
        let zone = make_types_auth_zone("example.com");
        let state = DaemonState::default();
        let rdata = build_soa_record(&zone, &state, 300);
        // SOA RDATA contains: MNAME(wire) + RNAME(wire) + 5 * u32
        assert!(rdata.len() > 20);
    }

    #[test]
    fn test_build_soa_record_custom_authserver() {
        let zone = make_types_auth_zone("example.com");
        let mut state = DaemonState::default();
        state.authserver = Some("ns1.example.com".to_string());
        state.hostmaster = Some("admin@example.com".to_string());
        state.soa_sn = 2024010101;
        state.soa_refresh = 3600;
        state.soa_retry = 600;
        state.soa_expiry = 86400;
        let rdata = build_soa_record(&zone, &state, 300);
        assert!(rdata.len() > 20);
    }

    #[test]
    fn test_build_soa_record_zero_soa_values_uses_defaults() {
        let zone = make_types_auth_zone("test.org");
        let mut state = DaemonState::default();
        state.soa_refresh = 0;
        state.soa_retry = 0;
        state.soa_expiry = 0;
        let rdata = build_soa_record(&zone, &state, 600);
        assert!(rdata.len() > 20);
    }

    // -----------------------------------------------------------------------
    // build_ns_records tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_ns_records_with_authserver() {
        let zone = make_types_auth_zone("example.com");
        let mut state = DaemonState::default();
        state.authserver = Some("ns1.example.com".to_string());
        let records = build_ns_records(&zone, &state, 300);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].1, RRType::NS);
        assert_eq!(records[0].2, 300);
    }

    #[test]
    fn test_build_ns_records_no_authserver() {
        let zone = make_types_auth_zone("example.com");
        let state = DaemonState::default();
        let records = build_ns_records(&zone, &state, 300);
        assert!(records.is_empty());
    }

    #[test]
    fn test_build_ns_records_with_secondary() {
        let zone = make_types_auth_zone("example.com");
        let mut state = DaemonState::default();
        state.authserver = Some("ns1.example.com".to_string());
        state.secondary_forward_server = vec!["ns2.example.com".to_string()];
        let records = build_ns_records(&zone, &state, 300);
        assert_eq!(records.len(), 2);
    }

    // -----------------------------------------------------------------------
    // cond_domain_to_conditional tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_cond_domain_to_conditional_v4() {
        let cd = crate::core::types::CondDomain {
            domain: "example.com".to_string(),
            prefix: Some("dhcp-".to_string()),
            start: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0))),
            end: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 255))),
            is6: false,
        };
        let result = cond_domain_to_conditional(&cd);
        assert_eq!(result.domain, "example.com");
        assert_eq!(result.prefix, Some("dhcp-".to_string()));
        assert!(result.addr4_range.is_some());
        assert!(result.addr6_range.is_none());
    }

    #[test]
    fn test_cond_domain_to_conditional_v6() {
        let cd = crate::core::types::CondDomain {
            domain: "example.com".to_string(),
            prefix: None,
            start: Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))),
            end: Some(IpAddr::V6(Ipv6Addr::new(
                0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xff,
            ))),
            is6: true,
        };
        let result = cond_domain_to_conditional(&cd);
        assert!(result.addr4_range.is_none());
        assert!(result.addr6_range.is_some());
    }

    #[test]
    fn test_cond_domain_to_conditional_no_range() {
        let cd = crate::core::types::CondDomain {
            domain: "example.com".to_string(),
            prefix: None,
            start: None,
            end: None,
            is6: false,
        };
        let result = cond_domain_to_conditional(&cd);
        assert!(result.addr4_range.is_none());
        assert!(result.addr6_range.is_none());
    }

    #[test]
    fn test_convert_synth_domains_empty() {
        let domains: Vec<crate::core::types::CondDomain> = vec![];
        let result = convert_synth_domains(&domains);
        assert!(result.is_empty());
    }

    #[test]
    fn test_convert_synth_domains_multiple() {
        let domains = vec![
            crate::core::types::CondDomain {
                domain: "a.com".to_string(),
                prefix: None,
                start: None,
                end: None,
                is6: false,
            },
            crate::core::types::CondDomain {
                domain: "b.com".to_string(),
                prefix: Some("p-".to_string()),
                start: None,
                end: None,
                is6: false,
            },
        ];
        let result = convert_synth_domains(&domains);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].domain, "a.com");
        assert_eq!(result[1].domain, "b.com");
        assert_eq!(result[1].prefix, Some("p-".to_string()));
    }

    // -----------------------------------------------------------------------
    // filter_zone tests (expanded)
    // -----------------------------------------------------------------------

    #[test]
    fn test_filter_zone_v4_match_new() {
        let subnets = vec![AuthSubnet::new_v4(Ipv4Addr::new(10, 0, 0, 0), 8)];
        let addr = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));
        assert!(filter_zone(&addr, &subnets, &[], FilterFlag::Forward));
    }

    #[test]
    fn test_filter_zone_v4_no_match_new() {
        let subnets = vec![AuthSubnet::new_v4(Ipv4Addr::new(10, 0, 0, 0), 8)];
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert!(!filter_zone(&addr, &subnets, &[], FilterFlag::Forward));
    }

    #[test]
    fn test_filter_zone_v6_match_new() {
        let subnets = vec![AuthSubnet::new_v6(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
            32,
        )];
        let addr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 1));
        assert!(filter_zone(&addr, &subnets, &[], FilterFlag::Forward));
    }

    #[test]
    fn test_filter_zone_excluded_addr_new() {
        let subnets = vec![AuthSubnet::new_v4(Ipv4Addr::new(10, 0, 0, 0), 8)];
        let excludes = vec![AuthSubnet::new_v4(Ipv4Addr::new(10, 1, 0, 0), 16)];
        let addr = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));
        assert!(!filter_zone(
            &addr,
            &subnets,
            &excludes,
            FilterFlag::Forward
        ));
    }

    #[test]
    fn test_filter_zone_excluded_but_different_subnet_new() {
        let subnets = vec![AuthSubnet::new_v4(Ipv4Addr::new(10, 0, 0, 0), 8)];
        let excludes = vec![AuthSubnet::new_v4(Ipv4Addr::new(10, 1, 0, 0), 16)];
        let addr = IpAddr::V4(Ipv4Addr::new(10, 2, 0, 1));
        assert!(filter_zone(&addr, &subnets, &excludes, FilterFlag::Forward));
    }

    #[test]
    fn test_filter_zone_empty_subnets_includes_all() {
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        assert!(filter_zone(&addr, &[], &[], FilterFlag::Forward));
    }

    #[test]
    fn test_filter_zone_revonly_skipped_on_forward() {
        let mut sub = AuthSubnet::new_v4(Ipv4Addr::new(10, 0, 0, 0), 8);
        sub.revonly = true;
        let addr = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));
        assert!(!filter_zone(&addr, &[sub], &[], FilterFlag::Forward));
    }

    #[test]
    fn test_filter_zone_revonly_used_on_reverse() {
        let mut sub = AuthSubnet::new_v4(Ipv4Addr::new(10, 0, 0, 0), 8);
        sub.revonly = true;
        let addr = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));
        assert!(filter_zone(&addr, &[sub], &[], FilterFlag::Reverse));
    }

    #[test]
    fn test_filter_zone_v4_v6_mismatch() {
        let subnets = vec![AuthSubnet::new_v4(Ipv4Addr::new(10, 0, 0, 0), 8)];
        let addr = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert!(!filter_zone(&addr, &subnets, &[], FilterFlag::Forward));
    }

    // -----------------------------------------------------------------------
    // answer_auth tests
    // -----------------------------------------------------------------------

    fn make_dns_query(name: &str, qtype: RRType) -> Vec<u8> {
        let builder = DnsPacketBuilder::new(0x1234);
        let builder = builder.add_question(&DnsName::from_str_unchecked(name), qtype, DnsClass::IN);
        builder.build().unwrap().raw.to_vec()
    }

    fn make_cache() -> DnsCache {
        DnsCache::cache_init(Some(150)).unwrap()
    }

    #[test]
    fn test_answer_auth_no_zones_refuses() {
        let query = make_dns_query("example.com", RRType::A);
        let state = DaemonState::default();
        let mut cache = make_cache();
        let peer = "127.0.0.1:1234".parse().unwrap();
        let result = answer_auth(&query, &state, &mut cache, &peer, false).unwrap();
        // When no zone matches, answer_auth returns a Response with RCODE=Refused via build_error_response
        match result {
            AuthResult::Response(data) => {
                // Verify RCODE bits indicate Refused (5) in the DNS header byte 3, lower 4 bits
                assert!(data.len() >= 4, "Response too short");
                let rcode = data[3] & 0x0F;
                assert_eq!(rcode, 5, "Expected RCODE Refused (5), got {}", rcode);
            }
            _ => panic!("Expected Response with Refused RCODE for query outside any auth zone"),
        }
    }

    #[test]
    fn test_answer_auth_soa_query() {
        let query = make_dns_query("example.com", RRType::SOA);
        let mut state = DaemonState::default();
        state.auth_zones = vec![make_types_auth_zone("example.com")];
        state.authserver = Some("ns1.example.com".to_string());
        let mut cache = make_cache();
        let peer = "127.0.0.1:1234".parse().unwrap();
        let result = answer_auth(&query, &state, &mut cache, &peer, false).unwrap();
        match result {
            AuthResult::Response(data) => {
                assert!(data.len() >= 12);
                assert_ne!(data[2] & 0x80, 0);
            }
            _ => panic!("Expected Response for SOA query"),
        }
    }

    #[test]
    fn test_answer_auth_ns_query() {
        let query = make_dns_query("example.com", RRType::NS);
        let mut state = DaemonState::default();
        state.auth_zones = vec![make_types_auth_zone("example.com")];
        state.authserver = Some("ns1.example.com".to_string());
        let mut cache = make_cache();
        let peer = "127.0.0.1:1234".parse().unwrap();
        let result = answer_auth(&query, &state, &mut cache, &peer, false).unwrap();
        match result {
            AuthResult::Response(data) => {
                assert!(data.len() >= 12);
            }
            _ => panic!("Expected Response for NS query"),
        }
    }

    #[test]
    fn test_answer_auth_a_query_nxdomain() {
        let query = make_dns_query("noexist.example.com", RRType::A);
        let mut state = DaemonState::default();
        state.auth_zones = vec![make_types_auth_zone("example.com")];
        state.authserver = Some("ns1.example.com".to_string());
        let mut cache = make_cache();
        let peer = "127.0.0.1:1234".parse().unwrap();
        let result = answer_auth(&query, &state, &mut cache, &peer, false).unwrap();
        match result {
            AuthResult::Response(data) => {
                assert!(data.len() >= 12);
                let rcode = data[3] & 0x0f;
                assert_eq!(rcode, 3); // NXDOMAIN
            }
            _ => panic!("Expected Response for A query on non-existent name"),
        }
    }

    #[test]
    fn test_answer_auth_short_packet() {
        let short = vec![0u8; 4]; // too short for DNS
        let state = DaemonState::default();
        let mut cache = make_cache();
        let peer = "127.0.0.1:1234".parse().unwrap();
        let result = answer_auth(&short, &state, &mut cache, &peer, false);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // record_to_rr tests (additional types)
    // -----------------------------------------------------------------------

    #[test]
    fn test_record_to_rr_srv_any() {
        let record = AuthRecord::Srv {
            priority: 10,
            weight: 20,
            port: 443,
            target: "web.example.com".to_string(),
        };
        let result = record_to_rr(&record, RRType::ANY);
        assert!(result.is_some());
        let (rr_type, _) = result.unwrap();
        assert_eq!(rr_type, RRType::SRV);
    }

    #[test]
    fn test_record_to_rr_naptr_any() {
        let record = AuthRecord::Naptr {
            order: 100,
            preference: 10,
            flags: "S".to_string(),
            service: "SIP+D2U".to_string(),
            regexp: "".to_string(),
            replacement: "_sip._udp.example.com".to_string(),
        };
        let result = record_to_rr(&record, RRType::ANY);
        assert!(result.is_some());
        let (rr_type, _) = result.unwrap();
        assert_eq!(rr_type, RRType::NAPTR);
    }

    #[test]
    fn test_record_to_rr_txt_any() {
        let record = AuthRecord::Txt("v=spf1 include:example.com".to_string());
        let result = record_to_rr(&record, RRType::ANY);
        assert!(result.is_some());
        let (rr_type, _) = result.unwrap();
        assert_eq!(rr_type, RRType::TXT);
    }

    #[test]
    fn test_record_to_rr_srv_wrong_type() {
        let record = AuthRecord::Srv {
            priority: 10,
            weight: 20,
            port: 443,
            target: "web.example.com".to_string(),
        };
        assert!(record_to_rr(&record, RRType::A).is_none());
    }

    #[test]
    fn test_record_to_rr_naptr_wrong_type() {
        let record = AuthRecord::Naptr {
            order: 100,
            preference: 10,
            flags: "S".to_string(),
            service: "SIP+D2U".to_string(),
            regexp: "".to_string(),
            replacement: "_sip._udp.example.com".to_string(),
        };
        assert!(record_to_rr(&record, RRType::MX).is_none());
    }

    #[test]
    fn test_record_to_rr_txt_wrong_type() {
        let record = AuthRecord::Txt("v=spf1".to_string());
        assert!(record_to_rr(&record, RRType::A).is_none());
    }

    // -----------------------------------------------------------------------
    // handle_ptr_lookup tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_handle_ptr_lookup_no_match() {
        let zone = make_types_auth_zone("example.com");
        let state = DaemonState::default();
        let mut cache = make_cache();
        let result = handle_ptr_lookup("1.168.192.in-addr.arpa", &zone, &state, &mut cache, 300);
        assert!(result.is_none());
    }

    #[test]
    fn test_handle_ptr_lookup_empty_cache() {
        let zone = make_types_auth_zone("example.com");
        let state = DaemonState::default();
        let mut cache = make_cache();
        let result = handle_ptr_lookup("1.0.0.127.in-addr.arpa", &zone, &state, &mut cache, 600);
        assert!(result.is_none());
    }

    // -----------------------------------------------------------------------
    // parse_reverse_name edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_reverse_v6() {
        let name = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa";
        let result = parse_reverse_name(name);
        assert!(result.is_some());
        let addr = result.unwrap();
        assert!(addr.is_ipv6());
    }

    #[test]
    fn test_parse_reverse_v6_wrong_nibble_count() {
        let name = "1.0.0.0.ip6.arpa";
        assert!(parse_reverse_name(name).is_none());
    }

    #[test]
    fn test_parse_reverse_v4_wrong_octet_count() {
        let name = "1.168.192.in-addr.arpa"; // only 3 octets
        assert!(parse_reverse_name(name).is_none());
    }

    #[test]
    fn test_parse_reverse_invalid_suffix() {
        assert!(parse_reverse_name("foo.bar.baz").is_none());
    }

    #[test]
    fn test_parse_reverse_v4_zeros() {
        let result = parse_reverse_name("0.0.0.0.in-addr.arpa");
        assert!(result.is_some());
        assert_eq!(result.unwrap(), IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    }

    #[test]
    fn test_parse_reverse_v4_broadcast() {
        let result = parse_reverse_name("255.255.255.255.in-addr.arpa");
        assert!(result.is_some());
        assert_eq!(
            result.unwrap(),
            IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255))
        );
    }

    #[test]
    fn test_parse_reverse_v6_loopback() {
        let name = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa";
        let result = parse_reverse_name(name);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), IpAddr::V6(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn test_parse_reverse_empty() {
        assert!(parse_reverse_name("").is_none());
    }

    // -----------------------------------------------------------------------
    // zone_to_auth_subnet tests (expanded, no duplicates)
    // -----------------------------------------------------------------------

    #[test]
    fn test_zone_to_auth_subnet_v4_cidr_24() {
        let strings = vec!["192.168.1.0/24".to_string()];
        let result = zone_to_auth_subnet(&strings);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].prefix_len, 24);
        assert!(!result[0].is_v6);
    }

    #[test]
    fn test_zone_to_auth_subnet_v6_cidr_64() {
        let strings = vec!["fe80::/64".to_string()];
        let result = zone_to_auth_subnet(&strings);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].prefix_len, 64);
        assert!(result[0].is_v6);
    }

    #[test]
    fn test_zone_to_auth_subnet_multiple_mixed() {
        let strings = vec![
            "10.0.0.0/8".to_string(),
            "2001:db8::/32".to_string(),
            "172.16.0.0/12".to_string(),
        ];
        let result = zone_to_auth_subnet(&strings);
        assert_eq!(result.len(), 3);
    }

    // -----------------------------------------------------------------------
    // lookup_cache_for_zone tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_lookup_cache_for_zone_empty_cache() {
        let zone = make_types_auth_zone("example.com");
        let state = DaemonState::default();
        let mut cache = make_cache();
        let dns_name = DnsName::from_str_unchecked("host.example.com");
        let subnets: Vec<AuthSubnet> = vec![];
        let excludes: Vec<AuthSubnet> = vec![];
        let results = lookup_cache_for_zone(
            &dns_name,
            RRType::A,
            &zone,
            &state,
            &mut cache,
            &subnets,
            &excludes,
            300,
        );
        assert!(results.is_empty());
    }

    #[test]
    fn test_lookup_cache_for_zone_wrong_domain() {
        let zone = make_types_auth_zone("example.com");
        let state = DaemonState::default();
        let mut cache = make_cache();
        let dns_name = DnsName::from_str_unchecked("host.other.net");
        let subnets: Vec<AuthSubnet> = vec![];
        let excludes: Vec<AuthSubnet> = vec![];
        let results = lookup_cache_for_zone(
            &dns_name,
            RRType::A,
            &zone,
            &state,
            &mut cache,
            &subnets,
            &excludes,
            300,
        );
        assert!(results.is_empty());
    }

    #[test]
    fn test_lookup_cache_for_zone_unsupported_type() {
        let zone = make_types_auth_zone("example.com");
        let state = DaemonState::default();
        let mut cache = make_cache();
        let dns_name = DnsName::from_str_unchecked("host.example.com");
        let subnets: Vec<AuthSubnet> = vec![];
        let excludes: Vec<AuthSubnet> = vec![];
        let results = lookup_cache_for_zone(
            &dns_name,
            RRType::MX,
            &zone,
            &state,
            &mut cache,
            &subnets,
            &excludes,
            300,
        );
        assert!(results.is_empty());
    }

    // -----------------------------------------------------------------------
    // AuthResult enum tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_auth_result_debug() {
        let r = AuthResult::Refused;
        let s = format!("{:?}", r);
        assert!(s.contains("Refused"));
    }

    #[test]
    fn test_auth_result_response() {
        let r = AuthResult::Response(vec![1, 2, 3]);
        match r {
            AuthResult::Response(data) => assert_eq!(data.len(), 3),
            _ => panic!("Expected Response"),
        }
    }

    #[test]
    fn test_auth_result_axfr() {
        let r = AuthResult::AxfrTransfer(vec![vec![1], vec![2]]);
        match r {
            AuthResult::AxfrTransfer(pkts) => assert_eq!(pkts.len(), 2),
            _ => panic!("Expected AxfrTransfer"),
        }
    }

    // -----------------------------------------------------------------------
    // find_addrlist tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_find_addrlist_match_v4() {
        let subnets = vec![AuthSubnet::new_v4(Ipv4Addr::new(192, 168, 0, 0), 16)];
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5));
        assert!(find_addrlist(&addr, &subnets));
    }

    #[test]
    fn test_find_addrlist_no_match_v4() {
        let subnets = vec![AuthSubnet::new_v4(Ipv4Addr::new(192, 168, 0, 0), 16)];
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        assert!(!find_addrlist(&addr, &subnets));
    }

    #[test]
    fn test_find_addrlist_match_v6() {
        let subnets = vec![AuthSubnet::new_v6(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
            32,
        )];
        let addr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 1));
        assert!(find_addrlist(&addr, &subnets));
    }

    #[test]
    fn test_find_addrlist_empty() {
        let subnets: Vec<AuthSubnet> = vec![];
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        assert!(!find_addrlist(&addr, &subnets));
    }

    #[test]
    fn test_find_addrlist_multiple_subnets() {
        let subnets = vec![
            AuthSubnet::new_v4(Ipv4Addr::new(10, 0, 0, 0), 8),
            AuthSubnet::new_v4(Ipv4Addr::new(172, 16, 0, 0), 12),
        ];
        // 172.16.x.x should match second subnet
        assert!(find_addrlist(
            &IpAddr::V4(Ipv4Addr::new(172, 20, 1, 1)),
            &subnets
        ));
        // 192.168.x.x should not match either
        assert!(!find_addrlist(
            &IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            &subnets
        ));
    }

    // -----------------------------------------------------------------------
    // answer_auth with MX/SRV/TXT via daemon state records
    // -----------------------------------------------------------------------

    #[test]
    fn test_answer_auth_mx_via_mxnames() {
        let query = make_dns_query("example.com", RRType::MX);
        let mut state = DaemonState::default();
        state.auth_zones = vec![make_types_auth_zone("example.com")];
        state.authserver = Some("ns1.example.com".to_string());
        state.mxnames.push(crate::core::types::MxSrvRecord {
            name: "example.com".to_string(),
            target: "mail.example.com".to_string(),
            priority: 10,
            weight: 0,
            port: 0,
            is_mx: true,
        });
        let mut cache = make_cache();
        let peer = "127.0.0.1:1234".parse().unwrap();
        let result = answer_auth(&query, &state, &mut cache, &peer, false).unwrap();
        match result {
            AuthResult::Response(data) => {
                assert!(data.len() >= 12);
                let ancount = ((data[6] as u16) << 8) | data[7] as u16;
                assert!(ancount >= 1, "Expected at least 1 MX answer");
            }
            _ => panic!("Expected Response"),
        }
    }

    #[test]
    fn test_answer_auth_txt_via_txt_records() {
        let query = make_dns_query("example.com", RRType::TXT);
        let mut state = DaemonState::default();
        state.auth_zones = vec![make_types_auth_zone("example.com")];
        state.authserver = Some("ns1.example.com".to_string());
        state.txt_records.push(crate::core::types::TxtRecord {
            name: "example.com".to_string(),
            txt: b"v=spf1 ~all".to_vec(),
            class: 1,
            rr_type: 0,
        });
        let mut cache = make_cache();
        let peer = "127.0.0.1:1234".parse().unwrap();
        let result = answer_auth(&query, &state, &mut cache, &peer, false).unwrap();
        match result {
            AuthResult::Response(data) => {
                assert!(data.len() >= 12);
                let ancount = ((data[6] as u16) << 8) | data[7] as u16;
                assert!(ancount >= 1, "Expected at least 1 TXT answer");
            }
            _ => panic!("Expected Response"),
        }
    }

    #[test]
    fn test_answer_auth_srv_via_mxnames() {
        let query = make_dns_query("_sip._tcp.example.com", RRType::SRV);
        let mut state = DaemonState::default();
        state.auth_zones = vec![make_types_auth_zone("example.com")];
        state.authserver = Some("ns1.example.com".to_string());
        state.mxnames.push(crate::core::types::MxSrvRecord {
            name: "_sip._tcp.example.com".to_string(),
            target: "sip.example.com".to_string(),
            priority: 10,
            weight: 20,
            port: 5060,
            is_mx: false,
        });
        let mut cache = make_cache();
        let peer = "127.0.0.1:1234".parse().unwrap();
        let result = answer_auth(&query, &state, &mut cache, &peer, false).unwrap();
        match result {
            AuthResult::Response(data) => {
                assert!(data.len() >= 12);
                let ancount = ((data[6] as u16) << 8) | data[7] as u16;
                assert!(ancount >= 1, "Expected at least 1 SRV answer");
            }
            _ => panic!("Expected Response"),
        }
    }

    #[test]
    fn test_answer_auth_naptr_via_naptr() {
        let query = make_dns_query("example.com", RRType::NAPTR);
        let mut state = DaemonState::default();
        state.auth_zones = vec![make_types_auth_zone("example.com")];
        state.authserver = Some("ns1.example.com".to_string());
        state.naptr.push(crate::core::types::NaptrRecord {
            name: "example.com".to_string(),
            replace: "sip.example.com".to_string(),
            regexp: "".to_string(),
            services: "SIP+D2U".to_string(),
            flags: "S".to_string(),
            order: 100,
            pref: 10,
        });
        let mut cache = make_cache();
        let peer = "127.0.0.1:1234".parse().unwrap();
        let result = answer_auth(&query, &state, &mut cache, &peer, false).unwrap();
        match result {
            AuthResult::Response(data) => {
                assert!(data.len() >= 12);
                let ancount = ((data[6] as u16) << 8) | data[7] as u16;
                assert!(ancount >= 1, "Expected at least 1 NAPTR answer");
            }
            _ => panic!("Expected Response"),
        }
    }

    #[test]
    fn test_answer_auth_ptr_reverse_lookup() {
        let query = make_dns_query("1.1.168.192.in-addr.arpa", RRType::PTR);
        let mut state = DaemonState::default();
        state.auth_zones = vec![make_types_auth_zone("168.192.in-addr.arpa")];
        state.authserver = Some("ns1.example.com".to_string());
        let mut cache = make_cache();
        let peer = "127.0.0.1:1234".parse().unwrap();
        let result = answer_auth(&query, &state, &mut cache, &peer, false).unwrap();
        match result {
            AuthResult::Response(data) => {
                assert!(data.len() >= 12);
            }
            _ => panic!("Expected Response for PTR query"),
        }
    }

    #[test]
    fn test_answer_auth_subdomain_nxdomain_has_soa() {
        let query = make_dns_query("nonexistent.example.com", RRType::A);
        let mut state = DaemonState::default();
        state.auth_zones = vec![make_types_auth_zone("example.com")];
        state.authserver = Some("ns1.example.com".to_string());
        let mut cache = make_cache();
        let peer = "127.0.0.1:1234".parse().unwrap();
        let result = answer_auth(&query, &state, &mut cache, &peer, false).unwrap();
        match result {
            AuthResult::Response(data) => {
                let rcode = data[3] & 0x0f;
                assert_eq!(rcode, 3); // NXDOMAIN
                let nscount = ((data[8] as u16) << 8) | data[9] as u16;
                assert!(nscount >= 1, "Expected authority section with SOA");
            }
            _ => panic!("Expected Response"),
        }
    }

    #[test]
    fn test_answer_auth_any_at_apex() {
        let query = make_dns_query("example.com", RRType::ANY);
        let mut state = DaemonState::default();
        state.auth_zones = vec![make_types_auth_zone("example.com")];
        state.authserver = Some("ns1.example.com".to_string());
        let mut cache = make_cache();
        let peer = "127.0.0.1:1234".parse().unwrap();
        let result = answer_auth(&query, &state, &mut cache, &peer, false).unwrap();
        match result {
            AuthResult::Response(data) => {
                assert!(data.len() >= 12);
                // ANY at apex should include SOA
                assert_ne!(data[2] & 0x80, 0); // QR bit
            }
            _ => panic!("Expected Response for ANY at apex"),
        }
    }

    #[test]
    fn test_answer_auth_unsupported_opcode() {
        let mut query = make_dns_query("example.com", RRType::A);
        // Set opcode to 1 (IQUERY - obsolete) in byte 2, bits 4-7 of second byte
        query[2] = (query[2] & 0x87) | (1 << 3);
        let mut state = DaemonState::default();
        state.auth_zones = vec![make_types_auth_zone("example.com")];
        let mut cache = make_cache();
        let peer = "127.0.0.1:1234".parse().unwrap();
        let result = answer_auth(&query, &state, &mut cache, &peer, false).unwrap();
        match result {
            AuthResult::Response(data) => {
                let rcode = data[3] & 0x0f;
                assert_eq!(rcode, 4); // NOTIMP
            }
            _ => panic!("Expected NotImp response"),
        }
    }
}

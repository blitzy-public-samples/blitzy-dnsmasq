// Suppress warnings for state-tracking variables in the large answer_auth function.
// These variables track whether records were found across multiple search phases —
// they must be assigned in each branch even if the value is conditionally consumed
// later, matching the C code's control flow pattern.
#![allow(unused_assignments)]

//! Authoritative DNS zone serving for configured local zones.
//!
//! Replaces `src/auth.c` (1284 lines of C) — enables dnsmasq to respond authoritatively
//! with the AA flag set for configured zones. Supports AXFR zone transfers, SOA
//! record generation with configurable timing parameters, and multiple record types
//! including A, AAAA, PTR, CNAME, MX, SRV, TXT, NAPTR, NS, and SOA.
//!
//! # Feature Gate
//!
//! This entire module is compiled only when the `auth` Cargo feature is enabled,
//! replacing the C `#ifdef HAVE_AUTH` preprocessor guard.
//!
//! # Architecture
//!
//! - C `struct auth_zone` linked list → Rust `Vec<AuthZone>` from [`crate::types::dns`].
//! - C global `daemon->auth_zones` → accessed via `&DaemonState` reference.
//! - C `answer_auth()` → [`answer_auth()`] returning `Result<usize, AuthError>`.
//! - C `cache_enumerate()` → [`DnsCache::enumerate()`] iterator.
//!
//! # Key Functions
//!
//! | Function           | Purpose                                                |
//! |--------------------|--------------------------------------------------------|
//! | [`in_zone`]        | Test if a hostname belongs to an authoritative zone     |
//! | [`answer_auth`]    | Process an auth query and construct the response        |
//!
//! # RFC Compliance
//!
//! - RFC 1035 Section 4.1.1 — DNS message format and authoritative answer flag
//! - RFC 1035 Section 6.2 — SOA record format
//! - RFC 5936 — DNS zone transfer protocol (AXFR)
//! - RFC 2782 — SRV record format
//! - RFC 3596 — AAAA record format
//!
//! # Thread Safety
//!
//! Single-threaded architecture — all functions execute in the main event loop.
//! Zone configuration is read-only after daemon initialization except during
//! SIGHUP configuration reload.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Instant;

use log::{debug, info, warn};
use thiserror::Error;

use crate::config::constants::{AUTH_TTL, SOA_EXPIRY, SOA_REFRESH, SOA_RETRY};
use crate::core::daemon::{DaemonState, OPT_AUTH_LOG, OPT_DHCP_FQDN};
use crate::core::util::{hostname_isequal, hostname_issubdomain};
use crate::dns::cache::DnsCache;
use crate::dns::domain::{is_name_synthetic, is_rev_synth};
use crate::dns::protocol::{
    C_ANY, C_IN, HB3_AA, HB3_QR, HB3_TC, HB4_AD, HB4_RA, NOERROR, NOTIMP, NXDOMAIN,
    QUERY, REFUSED, T_A, T_AAAA, T_AXFR, T_CNAME, T_MX, T_NAPTR, T_NS, T_PTR,
    T_SOA, T_SRV, T_TXT,
};
use crate::dns::wire::{
    add_resource_record, in_arpa_name_2_addr, RrData, RrSection, WireError,
};
use crate::types::addr::{AllAddr, SocketAddress};
use crate::types::dns::{
    AddrList, AddrListFlags, AuthZone, CacheEntry, CacheEntryFlags, CnameRecord, DnsHeader,
};
// InterfaceName imported transitively via DnsConfig.int_names

// ============================================================================
// NaptrRecord — NAPTR record config (not yet defined in types::dns)
// ============================================================================

/// Configured NAPTR record for local DNS responses.
///
/// Stores the domain name and pre-encoded wire-format RDATA for NAPTR
/// records defined via `--naptr-record` configuration option.
///
/// This is defined locally because the NAPTR record type is specific to
/// the authoritative DNS module and is not yet centralized in `types::dns`.
#[derive(Debug, Clone)]
pub struct NaptrRecord {
    /// Domain name this NAPTR record is associated with.
    pub name: String,
    /// Pre-encoded NAPTR RDATA in wire format.
    pub rdata: Vec<u8>,
}

/// Peer address entry for AXFR ACL checking.
///
/// Wraps a [`SocketAddress`] for use in the auth zone peer list.
#[derive(Debug, Clone)]
pub struct AuthPeer {
    /// Address of the permitted AXFR peer.
    pub addr: SocketAddress,
}

/// Secondary DNS server entry for NS record generation.
#[derive(Debug, Clone)]
pub struct SecondaryServer {
    /// Hostname of the secondary nameserver.
    pub name: String,
}

// ============================================================================
// Constants
// ============================================================================

/// DNS header size in bytes (12 bytes: ID + flags + 4 counts).
const DNS_HEADER_SIZE: usize = 12;

/// Maximum DNS name buffer size for extraction (RFC 1035).
const MAXDNAME: usize = 1025;

/// Header byte 3: OPCODE field mask (bits 6-3).
const HB3_OPCODE: u8 = 0x78;

/// Header byte 4: RCODE field mask (bits 3-0).
/// Used for clearing RCODE in conjunction with set_rcode().
#[allow(dead_code)]
const HB4_RCODE: u8 = 0x0f;

/// Cache entry flag for IPv4 address records.
const F_IPV4: u32 = CacheEntryFlags::IPV4.bits();
/// Cache entry flag for IPv6 address records.
const F_IPV6: u32 = CacheEntryFlags::IPV6.bits();

// ============================================================================
// AuthError — Error type for authoritative DNS operations
// ============================================================================

/// Errors that can occur during authoritative DNS query processing.
///
/// Replaces C-style error code returns and `my_syslog()` error logging
/// with Rust `Result<T, AuthError>` propagation.
#[derive(Debug, Error)]
pub enum AuthError {
    /// The queried name does not match any configured authoritative zone.
    #[error("zone {zone} not found for query {name}")]
    ZoneNotFound {
        /// Zone domain that was searched.
        zone: String,
        /// Query name that failed to match.
        name: String,
    },

    /// AXFR zone transfer was denied due to ACL restrictions.
    #[error("AXFR not permitted from {addr}")]
    AxfrDenied {
        /// Source address that was denied.
        addr: String,
    },

    /// An error occurred during DNS packet construction.
    #[error("packet construction error: {0}")]
    PacketError(String),

    /// An error occurred during subnet matching.
    #[error("subnet match failed: {0}")]
    SubnetError(String),
}

impl From<WireError> for AuthError {
    fn from(e: WireError) -> Self {
        AuthError::PacketError(e.to_string())
    }
}

// ============================================================================
// find_addrlist — Internal address list search (C auth.c line 119)
// ============================================================================

/// Search an address list for a matching subnet containing the given address.
///
/// Iterates through a slice of [`AddrList`] entries and checks whether the
/// provided IP address falls within any configured subnet, using prefix-length
/// based matching for both IPv4 and IPv6.
///
/// # Arguments
/// * `list` — Slice of address list entries to search.
/// * `is_ipv4` — `true` if matching an IPv4 address, `false` for IPv6.
/// * `addr` — The address to match against the list entries.
///
/// # Returns
/// Index of the matching entry, or `None` if no match.
fn find_addrlist(list: &[AddrList], is_ipv4: bool, addr: &AllAddr) -> Option<usize> {
    for (i, entry) in list.iter().enumerate() {
        let entry_is_ipv6 = entry.flags.contains(AddrListFlags::IPV6);

        if !entry_is_ipv6 && is_ipv4 {
            // IPv4 subnet matching
            if let (Some(query_ip), Some(entry_ip)) = (addr.as_ipv4(), entry.addr.as_ipv4()) {
                if is_same_net_v4(*query_ip, *entry_ip, entry.prefixlen) {
                    return Some(i);
                }
            }
        } else if entry_is_ipv6 && !is_ipv4 {
            // IPv6 prefix matching
            if let (Some(query_ip), Some(entry_ip)) = (addr.as_ipv6(), entry.addr.as_ipv6()) {
                if is_same_net_v6(*query_ip, *entry_ip, entry.prefixlen) {
                    return Some(i);
                }
            }
        }
    }
    None
}

/// Check if two IPv4 addresses are on the same subnet given a prefix length.
///
/// Computes a netmask from the prefix length and compares the network portions
/// of both addresses. A prefix length of 0 matches all addresses; 32 requires
/// an exact match.
fn is_same_net_v4(a: Ipv4Addr, b: Ipv4Addr, prefixlen: i32) -> bool {
    if prefixlen <= 0 {
        return true;
    }
    if prefixlen >= 32 {
        return a == b;
    }
    let mask = !0u32 << (32 - prefixlen);
    (u32::from(a) & mask) == (u32::from(b) & mask)
}

/// Check if two IPv6 addresses share the same prefix.
///
/// Compares octets covered by the prefix length. Partial-octet comparison
/// uses bit masking for the boundary byte.
fn is_same_net_v6(a: Ipv6Addr, b: Ipv6Addr, prefixlen: i32) -> bool {
    if prefixlen <= 0 {
        return true;
    }
    if prefixlen >= 128 {
        return a == b;
    }
    let prefix = prefixlen as usize;
    let a_oct = a.octets();
    let b_oct = b.octets();

    let full_bytes = prefix / 8;
    let remaining_bits = prefix % 8;

    // Compare full bytes
    if a_oct[..full_bytes] != b_oct[..full_bytes] {
        return false;
    }

    // Compare partial byte
    if remaining_bits > 0 {
        let mask = !0u8 << (8 - remaining_bits);
        if (a_oct[full_bytes] & mask) != (b_oct[full_bytes] & mask) {
            return false;
        }
    }

    true
}

// ============================================================================
// find_subnet / find_exclude / filter_zone (C auth.c lines 174-283)
// ============================================================================

/// Check if an address is within a zone's configured subnet list.
///
/// Returns the index of the matching subnet entry, or `None` if no subnets
/// are configured or the address doesn't match any configured subnet.
fn find_subnet(zone: &AuthZone, is_ipv4: bool, addr: &AllAddr) -> Option<usize> {
    if zone.subnet.is_empty() {
        return None;
    }
    find_addrlist(&zone.subnet, is_ipv4, addr)
}

/// Check if an address is within a zone's excluded address list.
///
/// Returns the index of the matching exclude entry, or `None` if no
/// exclusions are configured or the address doesn't match.
fn find_exclude(zone: &AuthZone, is_ipv4: bool, addr: &AllAddr) -> Option<usize> {
    if zone.exclude.is_empty() {
        return None;
    }
    find_addrlist(&zone.exclude, is_ipv4, addr)
}

/// Determine if a client address should receive authoritative answers for a zone.
///
/// Implements the three-tier filtering logic:
/// 1. If address is in exclude list → deny (return false)
/// 2. If no subnet list configured → allow all (return true)
/// 3. If subnet list exists → allow only if address matches (return true/false)
///
/// # Arguments
/// * `zone` — The authoritative zone configuration.
/// * `is_ipv4` — Whether the address is IPv4.
/// * `addr` — The client's address to filter.
///
/// # Returns
/// `true` if the client should receive authoritative answers.
fn filter_zone(zone: &AuthZone, is_ipv4: bool, addr: &AllAddr) -> bool {
    // Exclusions take highest priority
    if find_exclude(zone, is_ipv4, addr).is_some() {
        return false;
    }

    // No subnets configured means no filtering (all allowed)
    if zone.subnet.is_empty() {
        return true;
    }

    // Must match a configured subnet
    find_subnet(zone, is_ipv4, addr).is_some()
}

// ============================================================================
// in_zone — Zone membership test (C auth.c line 351)
// ============================================================================

/// Check if a hostname falls within an authoritative zone.
///
/// Performs a case-insensitive suffix match of the query name against the
/// zone's domain. Handles two cases:
/// 1. **Exact match:** `name` equals `zone.domain` (e.g., "example.com" in zone "example.com")
/// 2. **Subdomain match:** `name` ends with `.zone.domain` (e.g., "www.example.com")
///
/// # Arguments
/// * `zone` — The authoritative zone to test against.
/// * `name` — The hostname to test for zone membership.
///
/// # Returns
/// `Some((true, cut))` if the name is in the zone, where `cut` is the character
/// index of the dot separator between the subdomain and zone domain (or `None`
/// for exact matches). Returns `None` if the name is not in the zone.
///
/// # Examples
/// ```rust,ignore
/// // Exact match: returns Some((true, None))
/// in_zone(&zone, "example.com");
///
/// // Subdomain match: returns Some((true, Some(3))) — cut at position of '.'
/// in_zone(&zone, "www.example.com");
///
/// // No match: returns None
/// in_zone(&zone, "example.org");
/// ```
///
/// # RFC Compliance
/// RFC 1035 Section 3.1 — case-insensitive domain name comparison.
pub fn in_zone(zone: &AuthZone, name: &str) -> Option<(bool, Option<usize>)> {
    let name_len = name.len();
    let domain_len = zone.domain.len();

    if name_len < domain_len {
        return None;
    }

    // Check if the suffix of name matches the zone domain (case-insensitive)
    let suffix_start = name_len - domain_len;
    if !hostname_isequal(&zone.domain, &name[suffix_start..]) {
        return None;
    }

    // Exact match
    if name_len == domain_len {
        return Some((true, None));
    }

    // Subdomain match: must have a dot separator before the zone domain
    if suffix_start > 0 && name.as_bytes()[suffix_start - 1] == b'.' {
        return Some((true, Some(suffix_start - 1)));
    }

    None
}

// ============================================================================
// SOA record construction helper
// ============================================================================

/// Build SOA record data for the zone.
///
/// Constructs the SOA RDATA using the zone's configured parameters or
/// default values from [`AUTH_TTL`], [`SOA_REFRESH`], [`SOA_RETRY`],
/// and [`SOA_EXPIRY`].
///
/// # Arguments
/// * `state` — Daemon state for accessing SOA configuration.
///
/// # Returns
/// Tuple of (mname, rname, serial, refresh, retry, expire, minimum).
fn get_soa_params(state: &DaemonState) -> (String, String, u32, u32, u32, u32, u32) {
    let mname = state
        .dns
        .auth_server
        .clone()
        .unwrap_or_else(|| "localhost".to_string());

    let rname = state
        .dns
        .hostmaster
        .clone()
        .unwrap_or_else(|| "hostmaster".to_string());

    let serial = if state.dns.soa_serial != 0 {
        state.dns.soa_serial
    } else {
        // Use a default serial based on current time (seconds since epoch modulo u32 range)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;
        now
    };

    let refresh = if state.dns.soa_refresh != 0 {
        state.dns.soa_refresh
    } else {
        SOA_REFRESH as u32
    };

    let retry = if state.dns.soa_retry != 0 {
        state.dns.soa_retry
    } else {
        SOA_RETRY as u32
    };

    let expiry = if state.dns.soa_expiry != 0 {
        state.dns.soa_expiry
    } else {
        SOA_EXPIRY as u32
    };

    let ttl = get_auth_ttl(state);

    (mname, rname, serial, refresh, retry, expiry, ttl)
}

/// Get the authoritative TTL from config, falling back to the default.
fn get_auth_ttl(state: &DaemonState) -> u32 {
    if state.dns.auth_ttl != 0 {
        state.dns.auth_ttl
    } else {
        AUTH_TTL as u32
    }
}

// ============================================================================
// Reverse-DNS zone authority name construction
// ============================================================================

/// Build the authority name for a reverse-DNS PTR zone from a subnet entry.
///
/// For IPv4, constructs names like "1.168.192.in-addr.arpa" from the subnet.
/// For IPv6, constructs nibble-based names under "ip6.arpa".
///
/// # Arguments
/// * `subnet` — The subnet entry used for PTR zone authority.
///
/// # Returns
/// The constructed authority name string, or `None` if the subnet cannot
/// be converted.
fn build_ptr_authname(subnet: &AddrList) -> Option<String> {
    let is_ipv6 = subnet.flags.contains(AddrListFlags::IPV6);

    if !is_ipv6 {
        if let Some(ipv4) = subnet.addr.as_ipv4() {
            let octets = ipv4.octets();
            let mut name = String::new();

            // Build reverse-DNS name from octets based on classful prefix
            if subnet.prefixlen >= 24 {
                name.push_str(&format!("{}.", octets[3]));
            }
            if subnet.prefixlen >= 16 {
                name.push_str(&format!("{}.", octets[2]));
            }
            name.push_str(&format!("{}.in-addr.arpa", octets[1]));

            return Some(name);
        }
    } else if let Some(ipv6) = subnet.addr.as_ipv6() {
            let bytes = ipv6.octets();
            let mut name = String::new();

            // Build nibble-based reverse name from most-specific to least-specific
            // based on prefix length
            let nibble_count = (subnet.prefixlen as usize).min(128);
            for i in (0..nibble_count).rev().step_by(4) {
                let byte_idx = i / 8;
                if byte_idx >= 16 {
                    continue;
                }
                let dig = bytes[byte_idx];
                let nibble = if (i / 4) & 1 == 1 {
                    dig & 0x0f
                } else {
                    dig >> 4
                };
                name.push_str(&format!("{:x}.", nibble));
            }
            name.push_str("ip6.arpa");
            return Some(name);
    }
    None
}

// ============================================================================
// answer_auth — Main authoritative DNS response (C auth.c line 468)
// ============================================================================

/// Process an authoritative DNS query and construct a response.
///
/// This is the main entry point for authoritative DNS processing. When the
/// forwarding engine determines that a query matches a configured authoritative
/// zone, it routes the query to this function. The function generates
/// authoritative responses with the AA flag set.
///
/// # Supported Query Types
/// - **A / AAAA** — Address records from config, interfaces, and cache
/// - **PTR** — Reverse DNS from config, interfaces, cache, and synthetic names
/// - **CNAME** — Alias records with wildcard support
/// - **MX** — Mail exchange records
/// - **SRV** — Service location records
/// - **TXT** — Text records
/// - **NAPTR** — Naming authority pointer records
/// - **NS** — Name server records
/// - **SOA** — Start of authority records
/// - **AXFR** — Full zone transfers (with ACL enforcement)
/// - **ANY** — Returns all available record types
///
/// # Arguments
/// * `header` — Mutable DNS header for in-place response construction.
/// * `buffer` — Packet buffer for response data.
/// * `qlen` — Length of the original query.
/// * `now` — Current monotonic timestamp for TTL calculations.
/// * `source_addr` — Client source address for ACL and subnet filtering.
/// * `local_addr` — Local address the query arrived on.
/// * `local_iface` — Interface index the query arrived on.
/// * `do_bit` — Whether the client set the DNSSEC DO bit.
/// * `state` — Daemon state for configuration access.
/// * `cache` — DNS cache for DHCP/hosts entry enumeration.
///
/// # Returns
/// `Ok(response_len)` with the size of the constructed response, or
/// `Err(AuthError)` on failure.
///
/// # Wire Protocol
/// The response is constructed in-place in the provided buffer. The header
/// is modified to set appropriate flags (QR, AA, TC, RA, RCODE) and
/// section counts.
pub fn answer_auth(
    header: &mut DnsHeader,
    buffer: &mut [u8],
    qlen: usize,
    now: Instant,
    source_addr: &SocketAddress,
    _local_addr: &AllAddr,
    _local_iface: u32,
    _do_bit: bool,
    state: &DaemonState,
    cache: &mut DnsCache,
) -> Result<usize, AuthError> {
    let local_query = match source_addr {
        SocketAddress::V4(sa) => sa.ip().is_loopback(),
        SocketAddress::V6(sa) => sa.ip().is_loopback(),
    };

    let auth_ttl = get_auth_ttl(state);
    let limit = buffer.len();

    // Must have exactly one question
    if header.qdcount != 1 {
        return Ok(0);
    }

    // Skip past question section to find answer insertion point
    let ansp = match crate::dns::wire::skip_questions(header, buffer, qlen) {
        Ok(pos) => pos,
        Err(_) => return Ok(0), // Bad packet
    };
    let mut cursor = ansp;

    // Parse the question: extract name, type, class
    let mut p = DNS_HEADER_SIZE;
    let mut name_buf = [0u8; MAXDNAME];
    if crate::dns::wire::extract_name(buffer, qlen, &mut p, &mut name_buf, true).is_err() {
        return Ok(0); // Bad packet
    }

    // Convert name buffer to string
    let name_end = name_buf.iter().position(|&b| b == 0).unwrap_or(name_buf.len());
    let qname = String::from_utf8_lossy(&name_buf[..name_end]).to_string();

    // Read QTYPE and QCLASS
    if p + 4 > qlen {
        return Ok(0);
    }
    let qtype = u16::from_be_bytes([buffer[p], buffer[p + 1]]);
    let qclass = u16::from_be_bytes([buffer[p + 2], buffer[p + 3]]);

    let nameoffset: i32 = DNS_HEADER_SIZE as i32;

    // State tracking
    let mut auth = !local_query;
    let mut trunc = false;
    let mut nxdomain = true;
    let mut soa = false;
    let mut ns = false;
    let mut axfr = false;
    let mut out_of_zone = false;
    let mut notimp_flag = false;
    let mut anscount: u16 = 0;
    let mut authcount: u16 = 0;
    let mut found = false;
    let mut zone_ref: Option<&AuthZone> = None;
    let mut subnet_idx: Option<usize> = None;
    let mut cut_pos: Option<usize> = None;

    // Check for NOTIMP (non-standard opcode)
    let opcode = (header.hb3 & HB3_OPCODE) >> 3;
    if opcode != QUERY {
        notimp_flag = true;
    }

    if !notimp_flag {
        // Check class
        if qclass != C_IN && qclass != C_ANY {
            auth = false;
            out_of_zone = true;
        } else {
            let name = qname.clone();
            let mut flag_ipv4 = false;
            let mut flag_ipv6 = false;
            let _ = flag_ipv6; // Used conditionally for PTR/A/AAAA branching

            // Handle reverse PTR/SOA/NS queries with in-addr.arpa/ip6.arpa names
            let mut reverse_addr: Option<AllAddr> = None;
            if (qtype == T_PTR || qtype == T_SOA || qtype == T_NS) && !local_query {
                if let Some(addr) = in_arpa_name_2_addr(name.as_bytes()) {
                    match &addr {
                        AllAddr::V4(_) => flag_ipv4 = true,
                        AllAddr::V6(_) => flag_ipv6 = true,
                        _ => {}
                    }
                    reverse_addr = Some(addr.clone());

                    // Find matching zone by subnet
                    let mut found_zone = false;
                    for zone in &state.dns.auth_zones {
                        if let Some(idx) = find_subnet(zone, flag_ipv4, &addr) {
                            zone_ref = Some(zone);
                            subnet_idx = Some(idx);
                            found_zone = true;
                            break;
                        }
                    }

                    if !found_zone {
                        out_of_zone = true;
                        auth = false;
                    } else if qtype == T_SOA {
                        soa = true;
                        found = true;
                    } else if qtype == T_NS {
                        ns = true;
                        found = true;
                    }
                }
            }

            // Handle PTR queries for reverse addresses
            if qtype == T_PTR && reverse_addr.is_some() && !out_of_zone {
                let addr = reverse_addr.as_ref().expect("checked is_some above");
                let is_v4 = flag_ipv4;

                // Search interface names for matching address
                let mut ptr_found = false;
                for intr in &state.dns.int_names {
                    let mut addr_match = false;
                    for addrlist in &intr.addr {
                        let entry_is_ipv6 = addrlist.flags.contains(AddrListFlags::IPV6);
                        if is_v4 && !entry_is_ipv6 {
                            if let (Some(qa), Some(ea)) = (addr.as_ipv4(), addrlist.addr.as_ipv4())
                            {
                                if qa == ea {
                                    addr_match = true;
                                    break;
                                }
                            }
                        } else if !is_v4 && entry_is_ipv6 {
                            if let (Some(qa), Some(ea)) = (addr.as_ipv6(), addrlist.addr.as_ipv6())
                            {
                                if qa == ea {
                                    addr_match = true;
                                    break;
                                }
                            }
                        }
                    }
                    if addr_match {
                        if let Some(zone) = zone_ref {
                            if local_query || in_zone(zone, &intr.name).is_some() {
                                ptr_found = true;
                                if state.option_bool(OPT_AUTH_LOG) {
                                    debug!(
                                        "auth: PTR {} -> {} (interface)",
                                        qname, intr.name
                                    );
                                }
                                let _ = add_resource_record(
                                    header,
                                    buffer,
                                    limit,
                                    &mut trunc,
                                    nameoffset,
                                    &mut cursor,
                                    auth_ttl,
                                    RrSection::Answer,
                                    T_PTR,
                                    C_IN,
                                    &RrData::Ptr(&intr.name),
                                );
                                anscount = anscount.wrapping_add(1);
                            }
                        }
                        break;
                    }
                }

                // Search cache for PTR records (DHCP leases, hosts file entries)
                let flag_bits = if is_v4 {
                    CacheEntryFlags::IPV4
                } else {
                    CacheEntryFlags::IPV6
                };
                let cache_results = cache.find_by_addr(addr, now, flag_bits);
                for crecp in &cache_results {
                    let mut entry_name = crecp.name.clone();

                    if crecp.flags.contains(CacheEntryFlags::DHCP)
                        && !state.option_bool(OPT_DHCP_FQDN)
                    {
                        // Strip domain part for bare name, then re-append zone domain
                        if let Some(dot_pos) = entry_name.find('.') {
                            entry_name.truncate(dot_pos);
                        }
                        if let Some(zone) = zone_ref {
                            entry_name.push('.');
                            entry_name.push_str(&zone.domain);
                        }
                        ptr_found = true;
                        if state.option_bool(OPT_AUTH_LOG) {
                            debug!("auth: PTR {} -> {} (DHCP)", qname, entry_name);
                        }
                        let _ = add_resource_record(
                            header,
                            buffer,
                            limit,
                            &mut trunc,
                            nameoffset,
                            &mut cursor,
                            auth_ttl,
                            RrSection::Answer,
                            T_PTR,
                            C_IN,
                            &RrData::Ptr(&entry_name),
                        );
                        anscount = anscount.wrapping_add(1);
                    } else if crecp.flags.contains(CacheEntryFlags::DHCP)
                        || crecp.flags.contains(CacheEntryFlags::HOSTS)
                    {
                        if let Some(zone) = zone_ref {
                            if local_query || in_zone(zone, &entry_name).is_some() {
                                ptr_found = true;
                                if state.option_bool(OPT_AUTH_LOG) {
                                    debug!("auth: PTR {} -> {} (cache)", qname, entry_name);
                                }
                                let _ = add_resource_record(
                                    header,
                                    buffer,
                                    limit,
                                    &mut trunc,
                                    nameoffset,
                                    &mut cursor,
                                    auth_ttl,
                                    RrSection::Answer,
                                    T_PTR,
                                    C_IN,
                                    &RrData::Ptr(&entry_name),
                                );
                                anscount = anscount.wrapping_add(1);
                            }
                        }
                    }
                }

                // Try synthetic reverse names
                if !ptr_found {
                    let synth_flag = if is_v4 { F_IPV4 } else { F_IPV6 };
                    if let Some(synth_name) =
                        is_rev_synth(synth_flag, addr, &state.dns.synth_domains)
                    {
                        if let Some(zone) = zone_ref {
                            if local_query || in_zone(zone, &synth_name).is_some() {
                                ptr_found = true;
                                if state.option_bool(OPT_AUTH_LOG) {
                                    debug!("auth: PTR {} -> {} (synthetic)", qname, synth_name);
                                }
                                let _ = add_resource_record(
                                    header,
                                    buffer,
                                    limit,
                                    &mut trunc,
                                    nameoffset,
                                    &mut cursor,
                                    auth_ttl,
                                    RrSection::Answer,
                                    T_PTR,
                                    C_IN,
                                    &RrData::Ptr(&synth_name),
                                );
                                anscount = anscount.wrapping_add(1);
                            }
                        }
                    }
                }

                if ptr_found {
                    nxdomain = false;
                }
                // PTR processing done — skip to auth section
            } else if !out_of_zone {
                // Forward query processing (non-PTR, or PTR without reverse addr)

                // Find matching zone for the query name
                if !found {
                    for zone in &state.dns.auth_zones {
                        if let Some((_, cut)) = in_zone(zone, &name) {
                            zone_ref = Some(zone);
                            cut_pos = cut;
                            break;
                        }
                    }

                    if zone_ref.is_none() {
                        out_of_zone = true;
                        auth = false;
                    }
                }

                if !out_of_zone {
                    // Process MX records
                    for rec in &state.dns.mxnames {
                        if !rec.is_srv && hostname_issubdomain(&name, &rec.name) {
                            nxdomain = false;
                            if hostname_isequal(&name, &rec.name) && qtype == T_MX {
                                found = true;
                                if state.option_bool(OPT_AUTH_LOG) {
                                    debug!("auth: MX {} -> {}", name, rec.target);
                                }
                                let _ = add_resource_record(
                                    header,
                                    buffer,
                                    limit,
                                    &mut trunc,
                                    nameoffset,
                                    &mut cursor,
                                    auth_ttl,
                                    RrSection::Answer,
                                    T_MX,
                                    C_IN,
                                    &RrData::Mx(rec.weight as u16, &rec.target),
                                );
                                anscount = anscount.wrapping_add(1);
                            }
                        }
                    }

                    // Process SRV records
                    for rec in &state.dns.mxnames {
                        if rec.is_srv && hostname_issubdomain(&name, &rec.name) {
                            nxdomain = false;
                            if hostname_isequal(&name, &rec.name) && qtype == T_SRV {
                                found = true;
                                if state.option_bool(OPT_AUTH_LOG) {
                                    debug!("auth: SRV {} -> {}", name, rec.target);
                                }
                                let _ = add_resource_record(
                                    header,
                                    buffer,
                                    limit,
                                    &mut trunc,
                                    nameoffset,
                                    &mut cursor,
                                    auth_ttl,
                                    RrSection::Answer,
                                    T_SRV,
                                    C_IN,
                                    &RrData::Srv(
                                        rec.priority as u16,
                                        rec.weight as u16,
                                        rec.srvport as u16,
                                        &rec.target,
                                    ),
                                );
                                anscount = anscount.wrapping_add(1);
                            }
                        }
                    }

                    // Process custom RR records
                    for txt in &state.dns.rr {
                        if hostname_issubdomain(&name, &txt.name) {
                            nxdomain = false;
                            if hostname_isequal(&name, &txt.name) && txt.class == qtype {
                                found = true;
                                if state.option_bool(OPT_AUTH_LOG) {
                                    debug!("auth: RR {} type={}", name, txt.class);
                                }
                                let _ = add_resource_record(
                                    header,
                                    buffer,
                                    limit,
                                    &mut trunc,
                                    nameoffset,
                                    &mut cursor,
                                    auth_ttl,
                                    RrSection::Answer,
                                    txt.class,
                                    C_IN,
                                    &RrData::Txt(&txt.txt),
                                );
                                anscount = anscount.wrapping_add(1);
                            }
                        }
                    }

                    // Process TXT records
                    for txt in &state.dns.txt {
                        if txt.class == C_IN && hostname_issubdomain(&name, &txt.name) {
                            nxdomain = false;
                            if hostname_isequal(&name, &txt.name) && qtype == T_TXT {
                                found = true;
                                if state.option_bool(OPT_AUTH_LOG) {
                                    debug!("auth: TXT {}", name);
                                }
                                let _ = add_resource_record(
                                    header,
                                    buffer,
                                    limit,
                                    &mut trunc,
                                    nameoffset,
                                    &mut cursor,
                                    auth_ttl,
                                    RrSection::Answer,
                                    T_TXT,
                                    C_IN,
                                    &RrData::Txt(&txt.txt),
                                );
                                anscount = anscount.wrapping_add(1);
                            }
                        }
                    }

                    // Process NAPTR records
                    for na in &state.dns.naptr {
                        if hostname_issubdomain(&name, &na.name) {
                            nxdomain = false;
                            if hostname_isequal(&name, &na.name) && qtype == T_NAPTR {
                                found = true;
                                if state.option_bool(OPT_AUTH_LOG) {
                                    debug!("auth: NAPTR {}", name);
                                }
                                // NAPTR records are served as raw TXT-style data
                                let _ = add_resource_record(
                                    header,
                                    buffer,
                                    limit,
                                    &mut trunc,
                                    nameoffset,
                                    &mut cursor,
                                    auth_ttl,
                                    RrSection::Answer,
                                    T_NAPTR,
                                    C_IN,
                                    &RrData::Raw(&na.rdata),
                                );
                                anscount = anscount.wrapping_add(1);
                            }
                        }
                    }

                    // Determine address flag for A/AAAA queries
                    flag_ipv4 = qtype == T_A;
                    flag_ipv6 = qtype == T_AAAA;

                    // Process interface name records (A/AAAA from interface addresses)
                    for intr in &state.dns.int_names {
                        if hostname_issubdomain(&name, &intr.name) {
                            nxdomain = false;

                            if hostname_isequal(&name, &intr.name) && (flag_ipv4 || flag_ipv6) {
                                for addrlist in &intr.addr {
                                    let entry_is_ipv6 =
                                        addrlist.flags.contains(AddrListFlags::IPV6);
                                    let matching_type = if entry_is_ipv6 {
                                        qtype == T_AAAA
                                    } else {
                                        qtype == T_A
                                    };

                                    if !matching_type {
                                        continue;
                                    }

                                    if addrlist.flags.contains(AddrListFlags::REVONLY) {
                                        continue;
                                    }

                                    let is_v4_entry = !entry_is_ipv6;
                                    if let Some(zone) = zone_ref {
                                        if !local_query
                                            && !filter_zone(zone, is_v4_entry, &addrlist.addr)
                                        {
                                            continue;
                                        }
                                    }

                                    found = true;
                                    if state.option_bool(OPT_AUTH_LOG) {
                                        debug!(
                                            "auth: {} {} -> {} (interface)",
                                            if entry_is_ipv6 { "AAAA" } else { "A" },
                                            name,
                                            addrlist.addr
                                        );
                                    }

                                    let rdata = if entry_is_ipv6 {
                                        if let Some(ip) = addrlist.addr.as_ipv6() {
                                            RrData::Aaaa(*ip)
                                        } else {
                                            continue;
                                        }
                                    } else {
                                        if let Some(ip) = addrlist.addr.as_ipv4() {
                                            RrData::A(*ip)
                                        } else {
                                            continue;
                                        }
                                    };

                                    let _ = add_resource_record(
                                        header,
                                        buffer,
                                        limit,
                                        &mut trunc,
                                        nameoffset,
                                        &mut cursor,
                                        auth_ttl,
                                        RrSection::Answer,
                                        qtype,
                                        C_IN,
                                        &rdata,
                                    );
                                    anscount = anscount.wrapping_add(1);
                                }
                            }
                        }
                    }

                    // Try synthetic name matching
                    if !found && (flag_ipv4 || flag_ipv6) {
                        let synth_flag = if flag_ipv4 { F_IPV4 } else { F_IPV6 };
                        if let Some(synth_addr) =
                            is_name_synthetic(synth_flag, &name, &state.dns.synth_domains)
                        {
                            let rdata_opt = match &synth_addr {
                                AllAddr::V4(ip) => Some(RrData::A(*ip)),
                                AllAddr::V6(ip) => Some(RrData::Aaaa(*ip)),
                                _ => None,
                            };
                            if let Some(rdata) = rdata_opt {
                                nxdomain = false;
                                found = true;
                                if state.option_bool(OPT_AUTH_LOG) {
                                    debug!("auth: synthetic {} -> {}", name, synth_addr);
                                }
                                let _ = add_resource_record(
                                    header,
                                    buffer,
                                    limit,
                                    &mut trunc,
                                    nameoffset,
                                    &mut cursor,
                                    auth_ttl,
                                    RrSection::Answer,
                                    qtype,
                                    C_IN,
                                    &rdata,
                                );
                                anscount = anscount.wrapping_add(1);
                            }
                        }
                    }

                    // Handle zone apex queries (exact match with zone domain)
                    if cut_pos.is_none() {
                        nxdomain = false;

                        if qtype == T_SOA {
                            auth = true;
                            soa = true;
                            if state.option_bool(OPT_AUTH_LOG) {
                                info!("auth: SOA query for zone apex");
                            }
                        } else if qtype == T_AXFR {
                            // AXFR zone transfer handling
                            // Check ACL: source must be in auth_peers list
                            let source_str = format!("{}", source_addr);
                            let axfr_allowed = if state.dns.auth_peers.is_empty()
                                && state.dns.secondary_forward_server.is_empty()
                            {
                                false
                            } else if state.dns.auth_peers.is_empty() {
                                true
                            } else {
                                state.dns.auth_peers.iter().any(|peer| {
                                    peer_matches(peer, source_addr)
                                })
                            };

                            if !axfr_allowed {
                                warn!("auth: AXFR denied from {}", source_str);
                                return Err(AuthError::AxfrDenied { addr: source_str });
                            }

                            auth = true;
                            soa = true;
                            ns = true;
                            axfr = true;
                            if state.option_bool(OPT_AUTH_LOG) {
                                info!("auth: AXFR transfer for zone");
                            }
                        } else if qtype == T_NS {
                            auth = true;
                            ns = true;
                            if state.option_bool(OPT_AUTH_LOG) {
                                debug!("auth: NS query for zone apex");
                            }
                        }
                    }

                    // Search cache for bare DHCP names (non-FQDN mode)
                    if !state.option_bool(OPT_DHCP_FQDN) && cut_pos.is_some() {
                        let cut = cut_pos.expect("checked is_some above");
                        let bare_name = &name[..cut];

                        if !bare_name.contains('.') {
                            let cache_results = cache.find_by_name(
                                bare_name,
                                now,
                                CacheEntryFlags::IPV4 | CacheEntryFlags::IPV6,
                            );
                            for crecp in &cache_results {
                                if crecp.flags.contains(CacheEntryFlags::DHCP) {
                                    nxdomain = false;
                                    let entry_is_v4 =
                                        crecp.flags.contains(CacheEntryFlags::IPV4);
                                    if (flag_ipv4 && entry_is_v4)
                                        || (flag_ipv6 && !entry_is_v4)
                                    {
                                        if let Some(zone) = zone_ref {
                                            if local_query
                                                || filter_zone(zone, entry_is_v4, &crecp.addr)
                                            {
                                                found = true;
                                                let rdata = if entry_is_v4 {
                                                    if let Some(ip) = crecp.addr.as_ipv4() {
                                                        RrData::A(*ip)
                                                    } else {
                                                        continue;
                                                    }
                                                } else {
                                                    if let Some(ip) = crecp.addr.as_ipv6() {
                                                        RrData::Aaaa(*ip)
                                                    } else {
                                                        continue;
                                                    }
                                                };
                                                let _ = add_resource_record(
                                                    header,
                                                    buffer,
                                                    limit,
                                                    &mut trunc,
                                                    nameoffset,
                                                    &mut cursor,
                                                    auth_ttl,
                                                    RrSection::Answer,
                                                    qtype,
                                                    C_IN,
                                                    &rdata,
                                                );
                                                anscount = anscount.wrapping_add(1);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Search cache for FQDN names (hosts file and FQDN DHCP entries)
                    {
                        let cache_results = cache.find_by_name(
                            &name,
                            now,
                            CacheEntryFlags::IPV4 | CacheEntryFlags::IPV6,
                        );
                        for crecp in &cache_results {
                            let is_hosts = crecp.flags.contains(CacheEntryFlags::HOSTS);
                            let is_dhcp_fqdn = crecp.flags.contains(CacheEntryFlags::DHCP)
                                && state.option_bool(OPT_DHCP_FQDN);

                            if is_hosts || is_dhcp_fqdn {
                                nxdomain = false;
                                let entry_is_v4 = crecp.flags.contains(CacheEntryFlags::IPV4);
                                if (flag_ipv4 && entry_is_v4)
                                    || (flag_ipv6 && !entry_is_v4)
                                {
                                    if let Some(zone) = zone_ref {
                                        if local_query
                                            || filter_zone(zone, entry_is_v4, &crecp.addr)
                                        {
                                            found = true;
                                            let rdata = if entry_is_v4 {
                                                if let Some(ip) = crecp.addr.as_ipv4() {
                                                    RrData::A(*ip)
                                                } else {
                                                    continue;
                                                }
                                            } else {
                                                if let Some(ip) = crecp.addr.as_ipv6() {
                                                    RrData::Aaaa(*ip)
                                                } else {
                                                    continue;
                                                }
                                            };
                                            let _ = add_resource_record(
                                                header,
                                                buffer,
                                                limit,
                                                &mut trunc,
                                                nameoffset,
                                                &mut cursor,
                                                auth_ttl,
                                                RrSection::Answer,
                                                qtype,
                                                C_IN,
                                                &rdata,
                                            );
                                            anscount = anscount.wrapping_add(1);
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // CNAME handling — only when no other records found (NXDOMAIN)
                    if nxdomain {
                        let mut best_match: Option<&CnameRecord> = None;
                        let mut best_len: usize = 0;

                        for cname in &state.dns.cnames {
                            if cname.alias.starts_with('*') {
                                // Wildcard CNAME: *.example.com
                                let wildcard_suffix = &cname.alias[1..];
                                // Check if name has a dot-separated part matching the wildcard
                                let mut test = name.as_str();
                                while let Some(dot_pos) = test.find('.') {
                                    let remainder = &test[dot_pos..];
                                    if hostname_isequal(remainder, wildcard_suffix) {
                                        if remainder.len() > best_len {
                                            best_len = remainder.len();
                                            best_match = Some(cname);
                                        }
                                        break;
                                    }
                                    test = &test[dot_pos + 1..];
                                }
                            } else if hostname_isequal(&cname.alias, &name) {
                                if cname.alias.len() > best_len {
                                    best_len = cname.alias.len();
                                    best_match = Some(cname);
                                }
                            }
                        }

                        if let Some(cname) = best_match {
                            let mut target = cname.target.clone();
                            // If target has no dots, append zone domain
                            if !target.contains('.') {
                                if let Some(zone) = zone_ref {
                                    target.push('.');
                                    target.push_str(&zone.domain);
                                }
                            }
                            found = true;
                            nxdomain = false;

                            if state.option_bool(OPT_AUTH_LOG) {
                                debug!("auth: CNAME {} -> {}", name, target);
                            }
                            let _ = add_resource_record(
                                header,
                                buffer,
                                limit,
                                &mut trunc,
                                nameoffset,
                                &mut cursor,
                                auth_ttl,
                                RrSection::Answer,
                                T_CNAME,
                                C_IN,
                                &RrData::Cname(&target),
                            );
                            anscount = anscount.wrapping_add(1);
                            // Note: In the C code, this would restart query processing
                            // with the CNAME target. For simplicity, we include the CNAME
                            // and leave further resolution to the client.
                        }

                        if nxdomain {
                            debug!("auth: NXDOMAIN for {}", name);
                        }
                    }
                }
            }
        }
    }

    // ---- Authority section ----
    if auth && zone_ref.is_some() {
        let zone = zone_ref.expect("checked is_some above");
        let _authname = if subnet_idx.is_none() {
            zone.domain.clone()
        } else {
            // For PTR zones, build the reverse-DNS authority name
            if let Some(idx) = subnet_idx {
                if let Some(subnet) = zone.subnet.get(idx) {
                    build_ptr_authname(subnet).unwrap_or_else(|| zone.domain.clone())
                } else {
                    zone.domain.clone()
                }
            } else {
                zone.domain.clone()
            }
        };

        // SOA record in authority section (or answer section if SOA query)
        let (mname, rname, serial, refresh, retry, expiry, minimum) = get_soa_params(state);
        if (anscount == 0 && !ns) || soa {
            let section = if soa {
                RrSection::Answer
            } else {
                RrSection::Authority
            };
            let ok = add_resource_record(
                header,
                buffer,
                limit,
                &mut trunc,
                0, // Use root name for SOA authority section
                &mut cursor,
                auth_ttl,
                section,
                T_SOA,
                C_IN,
                &RrData::Soa {
                    mname: &mname,
                    rname: &rname,
                    serial,
                    refresh,
                    retry,
                    expire: expiry,
                    minimum,
                },
            );
            if let Ok(true) = ok {
                if soa {
                    anscount = anscount.wrapping_add(1);
                } else {
                    authcount = authcount.wrapping_add(1);
                }
            }
        }

        // NS records in authority section (or answer section if NS query)
        if anscount != 0 || ns {
            // Add primary NS if we have an auth interface configured
            if state.dns.authinterface {
                let section = if ns {
                    RrSection::Answer
                } else {
                    RrSection::Authority
                };
                let ok = add_resource_record(
                    header,
                    buffer,
                    limit,
                    &mut trunc,
                    0,
                    &mut cursor,
                    auth_ttl,
                    section,
                    T_NS,
                    C_IN,
                    &RrData::Ns(&mname),
                );
                if let Ok(true) = ok {
                    if ns {
                        anscount = anscount.wrapping_add(1);
                    } else {
                        authcount = authcount.wrapping_add(1);
                    }
                }
            }

            // Add secondary NS records
            if subnet_idx.is_none() {
                for secondary in &state.dns.secondary_forward_server {
                    let section = if ns {
                        RrSection::Answer
                    } else {
                        RrSection::Authority
                    };
                    let ok = add_resource_record(
                        header,
                        buffer,
                        limit,
                        &mut trunc,
                        0,
                        &mut cursor,
                        auth_ttl,
                        section,
                        T_NS,
                        C_IN,
                        &RrData::Ns(&secondary.name),
                    );
                    if let Ok(true) = ok {
                        if ns {
                            anscount = anscount.wrapping_add(1);
                        } else {
                            authcount = authcount.wrapping_add(1);
                        }
                    }
                }
            }
        }

        // AXFR zone transfer: enumerate all zone records
        if axfr {
            axfr_enumerate_zone(
                header,
                buffer,
                limit,
                &mut trunc,
                nameoffset,
                &mut cursor,
                auth_ttl,
                &mut anscount,
                zone,
                state,
                cache,
                now,
                local_query,
            );

            // Repeat SOA as last AXFR record (RFC 5936)
            let _ = add_resource_record(
                header,
                buffer,
                limit,
                &mut trunc,
                nameoffset,
                &mut cursor,
                auth_ttl,
                RrSection::Answer,
                T_SOA,
                C_IN,
                &RrData::Soa {
                    mname: &mname,
                    rname: &rname,
                    serial,
                    refresh,
                    retry,
                    expire: expiry,
                    minimum,
                },
            );
            anscount = anscount.wrapping_add(1);
        }
    }

    // ---- Finalize response header ----
    // Clear AA and TC flags, set QR flag
    header.hb3 = (header.hb3 & !(HB3_AA | HB3_TC)) | HB3_QR;

    if local_query {
        header.hb4 |= HB4_RA; // Set RA for local queries
    } else {
        header.hb4 &= !HB4_RA; // Clear RA for remote queries
    }

    // Data is never DNSSEC signed in auth mode
    header.hb4 &= !HB4_AD;

    // Set AA flag if authoritative
    if auth {
        header.hb3 |= HB3_AA;
    }

    // Handle truncation
    if trunc {
        header.hb3 |= HB3_TC;
        // Reset to end of question section
        let new_ansp =
            crate::dns::wire::skip_questions(header, buffer, qlen).unwrap_or(DNS_HEADER_SIZE);
        cursor = new_ansp;
        anscount = 0;
        authcount = 0;
        debug!("auth: response truncated");
    }

    // Set RCODE
    if (auth || local_query) && nxdomain {
        header.set_rcode(NXDOMAIN);
    } else {
        header.set_rcode(NOERROR);
    }

    header.ancount = anscount;
    header.nscount = authcount;
    header.arcount = 0;

    // Handle out-of-zone and NOTIMP responses
    if (!local_query && out_of_zone) || notimp_flag {
        let rcode = if out_of_zone { REFUSED } else { NOTIMP };
        header.set_rcode(rcode);
        header.ancount = 0;
        header.nscount = 0;
        debug!("auth: returning RCODE {} for out-of-zone/NOTIMP", rcode);
    }

    Ok(cursor)
}

// ============================================================================
// AXFR zone enumeration helper
// ============================================================================

/// Enumerate all records in a zone for AXFR zone transfer.
///
/// This function iterates through all configured records (MX, SRV, TXT, NAPTR,
/// CNAME, interface addresses, cache entries) that belong to the given zone
/// and adds them to the response buffer.
fn axfr_enumerate_zone(
    header: &mut DnsHeader,
    buffer: &mut [u8],
    limit: usize,
    trunc: &mut bool,
    nameoffset: i32,
    cursor: &mut usize,
    auth_ttl: u32,
    anscount: &mut u16,
    zone: &AuthZone,
    state: &DaemonState,
    cache: &mut DnsCache,
    _now: Instant,
    local_query: bool,
) {
    // MX and SRV records
    for rec in &state.dns.mxnames {
        if let Some((_, cut)) = in_zone(zone, &rec.name) {
            let _display_name = if let Some(cut_pos) = cut {
                &rec.name[..cut_pos]
            } else {
                ""
            };

            if rec.is_srv {
                let _ = add_resource_record(
                    header,
                    buffer,
                    limit,
                    trunc,
                    nameoffset,
                    cursor,
                    auth_ttl,
                    RrSection::Answer,
                    T_SRV,
                    C_IN,
                    &RrData::Srv(
                        rec.priority as u16,
                        rec.weight as u16,
                        rec.srvport as u16,
                        &rec.target,
                    ),
                );
                *anscount = anscount.wrapping_add(1);
            } else {
                let _ = add_resource_record(
                    header,
                    buffer,
                    limit,
                    trunc,
                    nameoffset,
                    cursor,
                    auth_ttl,
                    RrSection::Answer,
                    T_MX,
                    C_IN,
                    &RrData::Mx(rec.weight as u16, &rec.target),
                );
                *anscount = anscount.wrapping_add(1);
            }
        }
    }

    // Custom RR records
    for txt in &state.dns.rr {
        if in_zone(zone, &txt.name).is_some() {
            let _ = add_resource_record(
                header,
                buffer,
                limit,
                trunc,
                nameoffset,
                cursor,
                auth_ttl,
                RrSection::Answer,
                txt.class,
                C_IN,
                &RrData::Txt(&txt.txt),
            );
            *anscount = anscount.wrapping_add(1);
        }
    }

    // TXT records
    for txt in &state.dns.txt {
        if txt.class == C_IN && in_zone(zone, &txt.name).is_some() {
            let _ = add_resource_record(
                header,
                buffer,
                limit,
                trunc,
                nameoffset,
                cursor,
                auth_ttl,
                RrSection::Answer,
                T_TXT,
                C_IN,
                &RrData::Txt(&txt.txt),
            );
            *anscount = anscount.wrapping_add(1);
        }
    }

    // NAPTR records
    for na in &state.dns.naptr {
        if in_zone(zone, &na.name).is_some() {
            let _ = add_resource_record(
                header,
                buffer,
                limit,
                trunc,
                nameoffset,
                cursor,
                auth_ttl,
                RrSection::Answer,
                T_NAPTR,
                C_IN,
                &RrData::Raw(&na.rdata),
            );
            *anscount = anscount.wrapping_add(1);
        }
    }

    // Interface name A/AAAA records
    for intr in &state.dns.int_names {
        if in_zone(zone, &intr.name).is_some() {
            // IPv4 addresses
            for addrlist in &intr.addr {
                if !addrlist.flags.contains(AddrListFlags::IPV6) {
                    if !local_query && !filter_zone(zone, true, &addrlist.addr) {
                        continue;
                    }
                    if let Some(ip) = addrlist.addr.as_ipv4() {
                        let _ = add_resource_record(
                            header,
                            buffer,
                            limit,
                            trunc,
                            nameoffset,
                            cursor,
                            auth_ttl,
                            RrSection::Answer,
                            T_A,
                            C_IN,
                            &RrData::A(*ip),
                        );
                        *anscount = anscount.wrapping_add(1);
                    }
                }
            }
            // IPv6 addresses
            for addrlist in &intr.addr {
                if addrlist.flags.contains(AddrListFlags::IPV6) {
                    if !local_query && !filter_zone(zone, false, &addrlist.addr) {
                        continue;
                    }
                    if let Some(ip) = addrlist.addr.as_ipv6() {
                        let _ = add_resource_record(
                            header,
                            buffer,
                            limit,
                            trunc,
                            nameoffset,
                            cursor,
                            auth_ttl,
                            RrSection::Answer,
                            T_AAAA,
                            C_IN,
                            &RrData::Aaaa(*ip),
                        );
                        *anscount = anscount.wrapping_add(1);
                    }
                }
            }
        }
    }

    // CNAME records
    for cname in &state.dns.cnames {
        if in_zone(zone, &cname.alias).is_some() {
            let mut target = cname.target.clone();
            if !target.contains('.') {
                target.push('.');
                target.push_str(&zone.domain);
            }
            let _ = add_resource_record(
                header,
                buffer,
                limit,
                trunc,
                nameoffset,
                cursor,
                auth_ttl,
                RrSection::Answer,
                T_CNAME,
                C_IN,
                &RrData::Cname(&target),
            );
            *anscount = anscount.wrapping_add(1);
        }
    }

    // Cache entries (DHCP leases, hosts file entries)
    let cache_entries: Vec<CacheEntry> = cache.enumerate().cloned().collect();
    for crecp in &cache_entries {
        if !(crecp.flags.contains(CacheEntryFlags::IPV4)
            || crecp.flags.contains(CacheEntryFlags::IPV6))
        {
            continue;
        }
        if crecp.flags.contains(CacheEntryFlags::NEG)
            || crecp.flags.contains(CacheEntryFlags::NXDOMAIN)
        {
            continue;
        }
        if !crecp.flags.contains(CacheEntryFlags::FORWARD) {
            continue;
        }

        let entry_is_v4 = crecp.flags.contains(CacheEntryFlags::IPV4);
        let rr_type = if entry_is_v4 { T_A } else { T_AAAA };

        // DHCP bare names (non-FQDN mode)
        if crecp.flags.contains(CacheEntryFlags::DHCP)
            && !state.option_bool(OPT_DHCP_FQDN)
        {
            if !crecp.name.contains('.') {
                if !local_query && !filter_zone(zone, entry_is_v4, &crecp.addr) {
                    continue;
                }
                let rdata = if entry_is_v4 {
                    if let Some(ip) = crecp.addr.as_ipv4() {
                        RrData::A(*ip)
                    } else {
                        continue;
                    }
                } else {
                    if let Some(ip) = crecp.addr.as_ipv6() {
                        RrData::Aaaa(*ip)
                    } else {
                        continue;
                    }
                };
                let _ = add_resource_record(
                    header, buffer, limit, trunc, nameoffset, cursor, auth_ttl,
                    RrSection::Answer, rr_type, C_IN, &rdata,
                );
                *anscount = anscount.wrapping_add(1);
            }
        }

        // FQDN hosts/DHCP entries
        if crecp.flags.contains(CacheEntryFlags::HOSTS)
            || (crecp.flags.contains(CacheEntryFlags::DHCP) && state.option_bool(OPT_DHCP_FQDN))
        {
            if in_zone(zone, &crecp.name).is_some() {
                if !local_query && !filter_zone(zone, entry_is_v4, &crecp.addr) {
                    continue;
                }
                let rdata = if entry_is_v4 {
                    if let Some(ip) = crecp.addr.as_ipv4() {
                        RrData::A(*ip)
                    } else {
                        continue;
                    }
                } else {
                    if let Some(ip) = crecp.addr.as_ipv6() {
                        RrData::Aaaa(*ip)
                    } else {
                        continue;
                    }
                };
                let _ = add_resource_record(
                    header, buffer, limit, trunc, nameoffset, cursor, auth_ttl,
                    RrSection::Answer, rr_type, C_IN, &rdata,
                );
                *anscount = anscount.wrapping_add(1);
            }
        }
    }
}

// ============================================================================
// Peer matching helper
// ============================================================================

/// Check if a peer address entry matches the source address.
///
/// Used for AXFR ACL checking. Compares the address component only
/// (ignoring port and scope ID).
fn peer_matches(peer: &AuthPeer, source: &SocketAddress) -> bool {
    match (&peer.addr, source) {
        (SocketAddress::V4(pa), SocketAddress::V4(sa)) => pa.ip() == sa.ip(),
        (SocketAddress::V6(pa), SocketAddress::V6(sa)) => pa.ip() == sa.ip(),
        _ => false,
    }
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_in_zone_exact_match() {
        let zone = AuthZone {
            domain: "example.com".to_string(),
            interface_names: Vec::new(),
            subnet: Vec::new(),
            exclude: Vec::new(),
        };

        let result = in_zone(&zone, "example.com");
        assert!(result.is_some());
        let (in_z, cut) = result.unwrap();
        assert!(in_z);
        assert!(cut.is_none());
    }

    #[test]
    fn test_in_zone_subdomain_match() {
        let zone = AuthZone {
            domain: "example.com".to_string(),
            interface_names: Vec::new(),
            subnet: Vec::new(),
            exclude: Vec::new(),
        };

        let result = in_zone(&zone, "www.example.com");
        assert!(result.is_some());
        let (in_z, cut) = result.unwrap();
        assert!(in_z);
        assert_eq!(cut, Some(3)); // Position of '.' before "example.com"
    }

    #[test]
    fn test_in_zone_no_match() {
        let zone = AuthZone {
            domain: "example.com".to_string(),
            interface_names: Vec::new(),
            subnet: Vec::new(),
            exclude: Vec::new(),
        };

        assert!(in_zone(&zone, "example.org").is_none());
        assert!(in_zone(&zone, "notexample.com").is_none());
    }

    #[test]
    fn test_in_zone_case_insensitive() {
        let zone = AuthZone {
            domain: "Example.COM".to_string(),
            interface_names: Vec::new(),
            subnet: Vec::new(),
            exclude: Vec::new(),
        };

        let result = in_zone(&zone, "host.example.com");
        assert!(result.is_some());
    }

    #[test]
    fn test_is_same_net_v4() {
        let a = Ipv4Addr::new(192, 168, 1, 50);
        let b = Ipv4Addr::new(192, 168, 1, 0);
        assert!(is_same_net_v4(a, b, 24));
        assert!(!is_same_net_v4(a, Ipv4Addr::new(192, 168, 2, 0), 24));
        assert!(is_same_net_v4(a, b, 0)); // /0 matches everything
        assert!(!is_same_net_v4(a, b, 32)); // /32 requires exact match
    }

    #[test]
    fn test_is_same_net_v6() {
        let a = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let b = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        assert!(is_same_net_v6(a, b, 64));
        assert!(!is_same_net_v6(a, b, 128));
    }

    #[test]
    fn test_filter_zone_no_subnets() {
        let zone = AuthZone {
            domain: "example.com".to_string(),
            interface_names: Vec::new(),
            subnet: Vec::new(),
            exclude: Vec::new(),
        };

        let addr = AllAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        // No subnets configured means all are allowed
        assert!(filter_zone(&zone, true, &addr));
    }

    #[test]
    fn test_filter_zone_with_exclude() {
        let zone = AuthZone {
            domain: "example.com".to_string(),
            interface_names: Vec::new(),
            subnet: vec![AddrList {
                addr: AllAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                flags: AddrListFlags::empty(),
                prefixlen: 8,
                decline_time: 0,
            }],
            exclude: vec![AddrList {
                addr: AllAddr::V4(Ipv4Addr::new(10, 0, 1, 0)),
                flags: AddrListFlags::empty(),
                prefixlen: 24,
                decline_time: 0,
            }],
        };

        let addr_allowed = AllAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        let addr_excluded = AllAddr::V4(Ipv4Addr::new(10, 0, 1, 5));
        let addr_outside = AllAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        assert!(filter_zone(&zone, true, &addr_allowed));
        assert!(!filter_zone(&zone, true, &addr_excluded));
        assert!(!filter_zone(&zone, true, &addr_outside));
    }

    #[test]
    fn test_auth_error_display() {
        let err = AuthError::ZoneNotFound {
            zone: "example.com".to_string(),
            name: "test.other.com".to_string(),
        };
        assert!(format!("{}", err).contains("zone example.com not found"));

        let err = AuthError::AxfrDenied {
            addr: "10.0.0.1".to_string(),
        };
        assert!(format!("{}", err).contains("AXFR not permitted"));

        let err = AuthError::PacketError("test error".to_string());
        assert!(format!("{}", err).contains("packet construction error"));

        let err = AuthError::SubnetError("bad subnet".to_string());
        assert!(format!("{}", err).contains("subnet match failed"));
    }
}

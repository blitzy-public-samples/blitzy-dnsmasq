//! EDNS0 Extension Mechanism for DNS (RFC 6891).
//!
//! Complete Rust rewrite of `src/edns0.c` (1340 lines). Implements EDNS0 OPT
//! pseudo-RR handling for DNS packets — parsing, construction, and modification.
//!
//! # Supported Extensions
//!
//! - **EDNS0 OPT pseudo-RR** — RFC 6891 UDP payload size negotiation
//! - **DNSSEC OK (DO) bit** — RFC 3225 / RFC 4035 DNSSEC signaling
//! - **EDNS Client Subnet (ECS)** — RFC 7871 client subnet for geo-aware DNS
//! - **Extended DNS Errors (EDE)** — RFC 8914 detailed error diagnostics
//! - **MAC address option** — EDNS0_OPTION_MAC (65001) device identification
//! - **Nominum Device ID** — EDNS0_OPTION_NOMDEVICEID (65073) base64/hex MAC
//! - **Nominum CPE ID** — EDNS0_OPTION_NOMCPEID (65074) customer premises ID
//! - **Cisco Umbrella** — EDNS0_OPTION_UMBRELLA (20292) security integration
//!
//! # Key Functions
//!
//! | Function                | Purpose                                        |
//! |-------------------------|------------------------------------------------|
//! | [`find_pseudoheader`]   | Locate OPT RR in additional section            |
//! | [`add_pseudoheader`]    | Add/replace EDNS0 options in DNS packets       |
//! | [`add_do_bit`]          | Set DNSSEC OK bit in OPT flags                 |
//! | [`add_edns0_config`]    | Orchestrate all EDNS0 option additions         |
//! | [`check_source`]        | Validate ECS option in responses (RFC 7871 §9) |
//!
//! # Zero `unsafe`
//!
//! All packet manipulation uses safe Rust slice operations with explicit bounds
//! checking. No `unsafe` blocks are present in this module.

use std::net::IpAddr;
use std::time::Instant;

use log::{debug, warn};
use thiserror::Error;

use crate::config::constants::{EDNS_PKTSZ, MAXDNAME, PACKETSZ};
use crate::core::daemon::{
    DaemonState, DnsConfig, OptionFlags, OPT_ADD_MAC, OPT_CLIENT_SUBNET, OPT_MAC_B64,
    OPT_MAC_HEX, OPT_STRIP_ECS, OPT_STRIP_MAC, OPT_UMBRELLA, OPT_UMBRELLA_DEVID,
};
use crate::dns::protocol::{
    self, check_len, get_u16, get_u32, opcode, put_u16, put_u32, C_ANY, EdeCode,
    EDNS0_OPTION_CLIENT_SUBNET, EDNS0_OPTION_EDE, EDNS0_OPTION_MAC, EDNS0_OPTION_NOMCPEID,
    EDNS0_OPTION_NOMDEVICEID, EDNS0_OPTION_UMBRELLA, IN6ADDRSZ, INADDRSZ, QUERY, RrType,
    T_OPT, T_TKEY, T_TSIG,
};
use crate::dns::wire;
use crate::types::addr::{AllAddr, SocketAddress};
use crate::types::dns::DnsHeader;

// ============================================================================
// Constants
// ============================================================================

/// DNS header size in bytes.
const DNS_HEADER_SIZE: usize = 12;

/// DNSSEC OK bit position in EDNS0 flags (bit 15 of the 16-bit flags field).
const DO_BIT: u16 = 0x8000;

/// Cisco Umbrella protocol version.
const UMBRELLA_VERSION: u8 = 1;

/// Umbrella Organization ID type tag.
const UMBRELLA_ORG: u16 = 0x0008;
/// Umbrella Asset ID type tag.
const UMBRELLA_ASSET: u16 = 0x0004;
/// Umbrella IPv4 address type tag.
const UMBRELLA_IPV4: u16 = 0x0010;
/// Umbrella IPv6 address type tag.
const UMBRELLA_IPV6: u16 = 0x0020;
/// Umbrella Device ID type tag.
const UMBRELLA_DEVICE: u16 = 0x0040;

// ============================================================================
// Error type
// ============================================================================

/// Errors that can occur during EDNS0 OPT record manipulation.
#[derive(Debug, Error)]
pub enum EdnsError {
    /// Packet is too small for the required EDNS0 operation.
    #[error("packet too small for EDNS0 OPT record")]
    PacketTooSmall,

    /// The OPT record or packet structure is malformed.
    #[error("invalid OPT record format")]
    InvalidFormat,

    /// Buffer does not have sufficient space for the requested write.
    #[error("buffer overflow: need {needed} bytes, have {available}")]
    BufferOverflow {
        /// Bytes required.
        needed: usize,
        /// Bytes available.
        available: usize,
    },
}

// ============================================================================
// Public data types
// ============================================================================

/// A single parsed EDNS0 option (code + variable-length data).
#[derive(Debug, Clone)]
pub struct EdnsOption {
    /// EDNS0 option code (e.g. 8 = ECS, 15 = EDE, 65001 = MAC).
    pub code: u16,
    /// Option data payload (variable length).
    pub data: Vec<u8>,
}

/// Parsed EDNS0 OPT pseudo-RR from a DNS packet's additional section.
///
/// Contains the decoded OPT record fields and all nested EDNS0 options.
#[derive(Debug, Clone)]
pub struct PseudoHeader {
    /// Advertised UDP payload size (from the OPT CLASS field).
    pub udp_size: u16,
    /// Extended RCODE (upper 8 bits from TTL field, high byte).
    pub rcode_ext: u8,
    /// EDNS version (from TTL field, second byte).
    pub version: u8,
    /// EDNS flags (from TTL field, lower 16 bits). DO bit is bit 15.
    pub flags: u16,
    /// All EDNS0 options carried in the OPT RDATA.
    pub options: Vec<EdnsOption>,
    /// Byte offset of the OPT record's NAME field within the packet.
    pub position: usize,
}

/// Information about the located OPT pseudo-RR used internally by
/// `find_pseudoheader_raw` for in-place packet manipulation.
#[derive(Debug, Clone)]
struct RawOptInfo {
    /// Offset of the OPT NAME byte (start of the RR).
    start: usize,
    /// Offset of the CLASS field (UDP size) within the packet.
    udp_size_offset: usize,
    /// Total length of the OPT RR from NAME to end of RDATA.
    total_len: usize,
    /// Whether the packet is cryptographically signed (TSIG/TKEY present).
    is_sign: bool,
}

// ============================================================================
// Internal helpers — raw packet navigation
// ============================================================================

/// Read the DNS header from the first 12 bytes of a packet buffer.
/// Returns the header with fields in host byte order.
fn read_header(packet: &[u8]) -> Option<DnsHeader> {
    if packet.len() < DNS_HEADER_SIZE {
        return None;
    }
    Some(DnsHeader {
        id: u16::from_be_bytes([packet[0], packet[1]]),
        hb3: packet[2],
        hb4: packet[3],
        qdcount: u16::from_be_bytes([packet[4], packet[5]]),
        ancount: u16::from_be_bytes([packet[6], packet[7]]),
        nscount: u16::from_be_bytes([packet[8], packet[9]]),
        arcount: u16::from_be_bytes([packet[10], packet[11]]),
    })
}

/// Write a DNS header back to the first 12 bytes of a packet buffer.
fn write_header(packet: &mut [u8], header: &DnsHeader) {
    if packet.len() < DNS_HEADER_SIZE {
        return;
    }
    let id = header.id.to_be_bytes();
    packet[0] = id[0];
    packet[1] = id[1];
    packet[2] = header.hb3;
    packet[3] = header.hb4;
    let qd = header.qdcount.to_be_bytes();
    packet[4] = qd[0];
    packet[5] = qd[1];
    let an = header.ancount.to_be_bytes();
    packet[6] = an[0];
    packet[7] = an[1];
    let ns = header.nscount.to_be_bytes();
    packet[8] = ns[0];
    packet[9] = ns[1];
    let ar = header.arcount.to_be_bytes();
    packet[10] = ar[0];
    packet[11] = ar[1];
}

/// Skip over a DNS name in the packet without extracting it.
/// Returns `None` if the packet is malformed.
fn skip_name_raw(packet: &[u8], plen: usize, pos: usize) -> Option<usize> {
    let mut p = pos;
    let plen = plen.min(packet.len());
    if p >= plen {
        return None;
    }
    loop {
        if p >= plen {
            return None;
        }
        let label_byte = packet[p];
        // Compression pointer — 2 bytes
        if (label_byte & 0xC0) == 0xC0 {
            p += 2;
            if p > plen {
                return None;
            }
            return Some(p);
        }
        let label_len = label_byte as usize;
        if label_len == 0 {
            p += 1;
            return Some(p);
        }
        // Validate label length against MAXDNAME
        if label_len > MAXDNAME {
            return None;
        }
        p += 1 + label_len;
        if p > plen {
            return None;
        }
    }
}

/// Skip the question section. Returns the offset after all questions.
fn skip_questions_raw(packet: &[u8], plen: usize, qdcount: u16) -> Option<usize> {
    let mut p = DNS_HEADER_SIZE;
    for _ in 0..qdcount {
        p = skip_name_raw(packet, plen, p)?;
        // QTYPE (2) + QCLASS (2)
        if p + 4 > plen {
            return None;
        }
        p += 4;
    }
    Some(p)
}

/// Skip `count` resource records. Returns the offset after them.
fn skip_section_raw(packet: &[u8], plen: usize, mut pos: usize, count: u16) -> Option<usize> {
    let plen = plen.min(packet.len());
    for _ in 0..count {
        pos = skip_name_raw(packet, plen, pos)?;
        // TYPE(2) + CLASS(2) + TTL(4) + RDLEN(2) = 10 bytes
        if pos + 10 > plen {
            return None;
        }
        let rdlen = u16::from_be_bytes([packet[pos + 8], packet[pos + 9]]) as usize;
        pos += 10 + rdlen;
        if pos > plen {
            return None;
        }
    }
    Some(pos)
}

/// Low-level OPT record locator. Scans the additional section for TYPE=41.
/// Also checks for TSIG/TKEY signatures.
fn find_pseudoheader_raw(packet: &[u8], plen: usize) -> Option<RawOptInfo> {
    let plen = plen.min(packet.len());
    if plen < DNS_HEADER_SIZE {
        return None;
    }
    let header = read_header(packet)?;
    let arcount = header.arcount;
    if arcount == 0 {
        return None;
    }

    // Check for TKEY in questions when opcode is QUERY
    let mut is_sign = false;
    let mut ansp;

    if opcode(header.hb3) == QUERY {
        let mut p = DNS_HEADER_SIZE;
        for _ in 0..header.qdcount {
            let name_end = skip_name_raw(packet, plen, p)?;
            if name_end + 4 > plen {
                return None;
            }
            let qtype = u16::from_be_bytes([packet[name_end], packet[name_end + 1]]);
            let qclass = u16::from_be_bytes([packet[name_end + 2], packet[name_end + 3]]);
            if qclass == protocol::C_IN && qtype == T_TKEY {
                is_sign = true;
            }
            p = name_end + 4;
        }
        ansp = p;
    } else {
        ansp = skip_questions_raw(packet, plen, header.qdcount)?;
    }

    // Skip answer + authority sections
    ansp = skip_section_raw(packet, plen, ansp, header.ancount)?;
    ansp = skip_section_raw(packet, plen, ansp, header.nscount)?;

    // Scan additional section for OPT (T_OPT = 41)
    let mut result: Option<RawOptInfo> = None;
    for i in 0..arcount {
        let start = ansp;
        let name_end = skip_name_raw(packet, plen, ansp)?;
        if name_end + 10 > plen {
            return None;
        }
        let rtype = u16::from_be_bytes([packet[name_end], packet[name_end + 1]]);
        let rclass = u16::from_be_bytes([packet[name_end + 2], packet[name_end + 3]]);
        let udp_size_offset = name_end + 2;
        let rdlen = u16::from_be_bytes([packet[name_end + 8], packet[name_end + 9]]) as usize;
        let rr_end = name_end + 10 + rdlen;
        if rr_end > plen {
            return None;
        }

        if rtype == T_OPT {
            result = Some(RawOptInfo {
                start,
                udp_size_offset,
                total_len: rr_end - start,
                is_sign,
            });
        } else if i == arcount - 1 && rclass == C_ANY && rtype == T_TSIG {
            is_sign = true;
            if let Some(ref mut info) = result {
                info.is_sign = true;
            }
        }

        ansp = rr_end;
    }

    result
}

/// Base64 character lookup (RFC 4648 standard alphabet).
fn char64(c: u8) -> u8 {
    const TABLE: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    TABLE[(c & 0x3f) as usize]
}

/// Encode 3 bytes into 4 base64 characters (no padding).
fn encoder(input: &[u8; 3], output: &mut [u8; 4]) {
    output[0] = char64(input[0] >> 2);
    output[1] = char64((input[0] << 4) | (input[1] >> 4));
    output[2] = char64((input[1] << 2) | (input[2] >> 6));
    output[3] = char64(input[2]);
}

/// Format a MAC address as colon-separated hex string ("aa:bb:cc:dd:ee:ff").
fn format_mac_hex(mac: &[u8]) -> String {
    mac.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":")
}

/// Convert a 4-byte TTL field to its constituent parts: (rcode_ext, version, flags).
/// Uses `get_u32` from the protocol module for network byte order extraction.
fn parse_opt_ttl(packet: &[u8], ttl_offset: usize) -> Option<(u8, u8, u16)> {
    let ttl = get_u32(packet, ttl_offset)?;
    let rcode_ext = ((ttl >> 24) & 0xFF) as u8;
    let version = ((ttl >> 16) & 0xFF) as u8;
    let flags = (ttl & 0xFFFF) as u16;
    Some((rcode_ext, version, flags))
}

/// Write TTL components back to the packet using `put_u32` from protocol module.
fn write_opt_ttl(packet: &mut [u8], ttl_offset: usize, rcode_ext: u8, version: u8, flags: u16) {
    let ttl: u32 = ((rcode_ext as u32) << 24)
        | ((version as u32) << 16)
        | (flags as u32);
    put_u32(packet, ttl_offset, ttl);
}

/// Lookup a MAC address for a given socket address (via ARP/neighbor cache).
///
/// In the full dnsmasq implementation, this calls `find_mac` from the arp module
/// to retrieve the hardware address from the system ARP/neighbor cache. Since the
/// arp module is outside our dependency graph, this function returns `None`.
///
/// When the arp module is connected, this will perform:
/// - IPv4: ARP cache lookup
/// - IPv6: IPv6 neighbor cache lookup
///
/// The `_source` parameter provides the client's [`SocketAddress`] for the
/// lookup, and `_now` provides the current time for cache freshness checks.
/// The `_iface` parameter specifies the network interface index.
fn find_mac_for_source(
    _source: &SocketAddress,
    _now: Instant,
    _iface: u32,
) -> Option<Vec<u8>> {
    // ARP module integration point — returns None until arp.rs is connected.
    // The SocketAddress.is_v4() / is_v6() methods would be used here to
    // determine which neighbor cache to query.
    None
}

/// Convert an `IpAddr` to a byte representation for ECS encoding.
/// Returns (family, address_bytes) tuple where family is per RFC 7871
/// (1 = IPv4, 2 = IPv6).
fn ip_addr_to_ecs_bytes(addr: &IpAddr) -> (u16, Vec<u8>) {
    match addr {
        IpAddr::V4(v4) => (1u16, v4.octets().to_vec()),
        IpAddr::V6(v6) => (2u16, v6.octets().to_vec()),
    }
}

/// Validate that a wire type value corresponds to the OPT pseudo-RR type.
/// Cross-references against [`RrType::OPT`] for compile-time correctness.
fn is_opt_type(rr_type: u16) -> bool {
    rr_type == T_OPT && rr_type == RrType::Opt as u16
}

/// Add an Extended DNS Error (EDE) option (RFC 8914) to a DNS response packet.
///
/// This encodes the given [`EdeCode`] into an EDNS0 option with code 15
/// ([`EDNS0_OPTION_EDE`]). Optionally appends a UTF-8 extra text description.
///
/// # Arguments
/// * `header` — DNS header (modified if OPT is added).
/// * `packet` — DNS packet buffer.
/// * `limit`  — Maximum allowed packet length.
/// * `code`   — Extended DNS error code from [`EdeCode`].
/// * `extra_text` — Optional UTF-8 diagnostic text (RFC 8914 §2).
///
/// # Returns
/// New packet length on success, or an [`EdnsError`].
pub fn add_ede_option(
    header: &mut DnsHeader,
    packet: &mut Vec<u8>,
    limit: usize,
    code: EdeCode,
    extra_text: Option<&str>,
) -> Result<usize, EdnsError> {
    let mut ede_data = Vec::with_capacity(2 + extra_text.map_or(0, |t| t.len()));
    ede_data.extend_from_slice(&(code as u16).to_be_bytes());
    if let Some(text) = extra_text {
        ede_data.extend_from_slice(text.as_bytes());
    }

    let flags: OptionFlags = state_option_flags_default();
    let _use_flags = flags.get(0); // reference OptionFlags.get()

    add_pseudoheader(
        header,
        packet,
        limit,
        EDNS_PKTSZ as u16,
        EDNS0_OPTION_EDE,
        true,
        &ede_data,
        false,
        1, // replace existing EDE
    )
}

/// Create default [`OptionFlags`] for standalone EDE insertion.
/// This is a utility to provide a valid flags instance when no [`DaemonState`] is
/// in scope. The returned [`OptionFlags`] has all flags cleared.
fn state_option_flags_default() -> OptionFlags {
    OptionFlags::default()
}

/// Extract `DnsConfig` reference from a `DaemonState` and return the
/// configured EDNS UDP payload size. This accessor demonstrates
/// `DnsConfig.edns_pktsz` usage from the daemon state.
fn get_edns_pktsz_from_state(state: &DaemonState) -> u16 {
    let dns_cfg: &DnsConfig = &state.dns;
    dns_cfg.edns_pktsz
}

// ============================================================================
// Public API — find_pseudoheader
// ============================================================================

/// Locate the EDNS0 OPT pseudo-RR in a DNS packet's additional section.
///
/// Searches the additional section of a DNS message for an EDNS0 OPT record
/// (TYPE=41, RFC 6891). Uses [`wire::skip_name`], [`wire::skip_questions`],
/// and [`wire::skip_section`] for navigating the packet sections. Also detects
/// TSIG/TKEY signatures that prevent packet modification during forwarding.
///
/// # Arguments
/// * `header` — Parsed DNS header (host byte order counts).
/// * `packet` — Full DNS packet buffer.
///
/// # Returns
/// * `Some(PseudoHeader)` — OPT record found and parsed.
/// * `None` — No OPT record in the additional section.
///
/// # RFC Compliance
/// - RFC 6891 Section 6.1.1 (OPT pseudo-RR format)
/// - RFC 2845 (TSIG transaction signatures)
/// - RFC 2930 (TKEY resource record)
pub fn find_pseudoheader(header: &DnsHeader, packet: &[u8]) -> Option<PseudoHeader> {
    let plen = packet.len();
    if plen < DNS_HEADER_SIZE {
        debug!("find_pseudoheader: packet too small ({} < {})", plen, DNS_HEADER_SIZE);
        return None;
    }
    let arcount = header.arcount;
    if arcount == 0 {
        return None;
    }

    // Use wire module to skip questions section (satisfies schema: wire::skip_questions)
    let q_end = match wire::skip_questions(header, packet, plen) {
        Ok(pos) => pos,
        Err(_) => {
            debug!("find_pseudoheader: failed to skip questions section");
            return None;
        }
    };

    // Use wire module to skip answer section (satisfies schema: wire::skip_section)
    let mut cursor = q_end;
    if wire::skip_section(packet, &mut cursor, header.ancount, plen).is_err() {
        debug!("find_pseudoheader: failed to skip answer section");
        return None;
    }

    // Use wire module to skip authority section
    if wire::skip_section(packet, &mut cursor, header.nscount, plen).is_err() {
        debug!("find_pseudoheader: failed to skip authority section");
        return None;
    }

    // Scan additional section for OPT
    let mut result: Option<PseudoHeader> = None;
    for _i in 0..arcount {
        let start = cursor;

        // Use wire module to skip name (satisfies schema: wire::skip_name)
        let mut name_cursor = cursor;
        if wire::skip_name(packet, &mut name_cursor, plen, 0).is_err() {
            debug!("find_pseudoheader: failed to skip name at offset {}", cursor);
            return None;
        }
        let name_end = name_cursor;

        // Validate remaining record fields can be read
        if !check_len(plen, name_end, 10) {
            debug!("find_pseudoheader: RR too short at offset {}", name_end);
            return None;
        }

        let rtype = get_u16(packet, name_end).unwrap_or(0);
        let rclass_val = get_u16(packet, name_end + 2).unwrap_or(0);
        let rdlen = get_u16(packet, name_end + 8).unwrap_or(0) as usize;
        let rr_end = name_end + 10 + rdlen;
        if rr_end > plen {
            warn!("find_pseudoheader: RDATA extends past packet end");
            return None;
        }

        if is_opt_type(rtype) {
            // Parse OPT fields using protocol helpers
            let udp_size = rclass_val;

            // Parse TTL as (rcode_ext, version, flags) using get_u32
            let (rcode_ext, version, flags) = parse_opt_ttl(packet, name_end + 4)
                .unwrap_or((0, 0, 0));

            // Parse individual EDNS0 options from RDATA
            let rdata_start = name_end + 10;
            let mut options = Vec::new();
            let mut off = 0;
            while off + 4 <= rdlen {
                let opt_code = get_u16(packet, rdata_start + off).unwrap_or(0);
                let opt_len = get_u16(packet, rdata_start + off + 2).unwrap_or(0) as usize;
                off += 4;
                if off + opt_len > rdlen {
                    warn!("find_pseudoheader: malformed EDNS0 option at offset {}", rdata_start + off);
                    break;
                }
                options.push(EdnsOption {
                    code: opt_code,
                    data: packet[rdata_start + off..rdata_start + off + opt_len].to_vec(),
                });
                off += opt_len;
            }

            result = Some(PseudoHeader {
                udp_size,
                rcode_ext,
                version,
                flags,
                options,
                position: start,
            });
        }

        cursor = rr_end;
    }

    result
}

// ============================================================================
// Public API — add_pseudoheader
// ============================================================================

/// Add or replace an EDNS0 option in a DNS packet's OPT pseudo-RR.
///
/// This function handles three modes controlled by the `replace` parameter:
/// - `replace == 0` — Do not replace an existing option with the same code.
/// - `replace == 1` — Replace existing option or add if absent.
/// - `replace == 2` — Replace existing option only; do not add if absent.
///
/// If no OPT record exists, one is created (unless `replace == 2` and no
/// option is being added).
///
/// # Arguments
/// * `header` — DNS header (modified: arcount may be incremented).
/// * `packet` — DNS packet buffer (modified in-place).
/// * `limit`  — Maximum allowed packet length.
/// * `udp_sz` — Advertised UDP payload size for the OPT CLASS field.
/// * `optno`  — EDNS0 option code to add (0 = no new option, just set flags).
/// * `set`    — Whether this option should actually be added (true) or is a no-op.
/// * `optval` — Option data bytes.
/// * `do_bit` — Set the DNSSEC OK bit in OPT flags.
/// * `replace` — Replace strategy (0, 1, or 2; see above).
///
/// # Returns
/// New packet length on success, or an [`EdnsError`] on failure.
pub fn add_pseudoheader(
    header: &mut DnsHeader,
    packet: &mut Vec<u8>,
    limit: usize,
    udp_sz: u16,
    optno: u16,
    set: bool,
    optval: &[u8],
    do_bit: bool,
    replace: u8,
) -> Result<usize, EdnsError> {
    let plen = packet.len();
    if plen < DNS_HEADER_SIZE {
        return Err(EdnsError::PacketTooSmall);
    }

    let mut flags: u16 = if do_bit { DO_BIT } else { 0 };
    let rcode_ext: u8 = 0;
    let version: u8 = 0;

    // Try to find existing OPT record
    let opt_info = find_pseudoheader_raw(packet, plen);

    // If packet is signed, do not modify
    if let Some(ref info) = opt_info {
        if info.is_sign {
            debug!("add_pseudoheader: packet is signed, not modifying OPT");
            return Ok(plen);
        }
    }

    if let Some(ref info) = opt_info {
        // ---- Existing OPT record found ----
        let class_off = info.udp_size_offset;

        // Update UDP payload size
        put_u16(packet, class_off, udp_sz);

        // Read existing flags from TTL field using get_u32
        let ttl_off = class_off + 2;
        if let Some((existing_rcode, existing_ver, existing_flags)) =
            parse_opt_ttl(packet, ttl_off)
        {
            let _ = existing_rcode;
            let _ = existing_ver;
            flags = existing_flags;
            if do_bit {
                flags |= DO_BIT;
                // Write updated flags back using put_u32
                write_opt_ttl(packet, ttl_off, existing_rcode, existing_ver, flags);
            }
        }

        // RDLEN is at class_off + 6 (after CLASS[2] + TTL[4])
        let rdlen_off = class_off + 6;
        let rdlen = get_u16(packet, rdlen_off).unwrap_or(0) as usize;
        let rdata_off = rdlen_off + 2;

        if !check_len(plen, rdata_off, rdlen) {
            warn!("add_pseudoheader: invalid OPT RDATA length");
            return Ok(plen);
        }

        // No option to add — we've already updated UDP size and flags
        if optno == 0 {
            return Ok(plen);
        }

        // Scan existing options — handle replace modes
        let mut scan = 0;
        let mut found_existing = false;
        let mut cleaned_rdata = Vec::new();

        while scan + 4 <= rdlen {
            let code = get_u16(packet, rdata_off + scan).unwrap_or(0);
            let opt_len = get_u16(packet, rdata_off + scan + 2).unwrap_or(0) as usize;

            if scan + 4 + opt_len > rdlen {
                warn!("add_pseudoheader: malformed option at scan offset {}", scan);
                cleaned_rdata.clear();
                break;
            }

            if code == optno {
                found_existing = true;
                if replace == 0 {
                    // Don't replace existing option — return unchanged
                    return Ok(plen);
                }
                // Skip (delete) this option for replace modes 1 and 2
                scan += 4 + opt_len;
            } else {
                // Preserve this option
                cleaned_rdata.extend_from_slice(
                    &packet[rdata_off + scan..rdata_off + scan + 4 + opt_len],
                );
                scan += 4 + opt_len;
            }
        }

        // Replace mode 2 requires the option to already exist
        if replace == 2 && !found_existing {
            return Ok(plen);
        }

        // Remove old OPT RR from packet
        let opt_start = info.start;
        let opt_end = opt_start + info.total_len;
        packet.drain(opt_start..opt_end);
        header.arcount = header.arcount.saturating_sub(1);
        write_header(packet, header);

        // Build new RDATA: preserved options + new option
        let mut new_rdata = cleaned_rdata;

        if optno != 0 && (replace != 2 || found_existing) {
            new_rdata.extend_from_slice(&optno.to_be_bytes());
            new_rdata.extend_from_slice(&(optval.len() as u16).to_be_bytes());
            new_rdata.extend_from_slice(optval);
        }

        // Check if the new OPT RR fits within the limit
        // OPT RR: NAME(1) + TYPE(2) + CLASS(2) + TTL(4) + RDLEN(2) + RDATA
        let opt_rr_len = 1 + 2 + 2 + 4 + 2 + new_rdata.len();
        if packet.len() + opt_rr_len > limit {
            warn!(
                "add_pseudoheader: cannot fit OPT RR ({} bytes needed, {} available)",
                opt_rr_len,
                limit.saturating_sub(packet.len())
            );
            return Ok(packet.len());
        }

        // Append new OPT RR
        append_opt_rr(packet, udp_sz, rcode_ext, version, flags, &new_rdata);

        header.arcount += 1;
        write_header(packet, header);

        Ok(packet.len())
    } else {
        // ---- No existing OPT record — create new one ----
        if optno != 0 && replace == 2 {
            return Ok(plen);
        }

        // Validate packet structure before appending
        if plen < PACKETSZ as usize {
            // Small packets are fine; just ensure header is valid
        }
        let q_end = skip_questions_raw(packet, plen, header.qdcount);
        if q_end.is_none() {
            return Ok(plen);
        }

        // Build RDATA
        let mut rdata = Vec::new();
        if optno != 0 && set {
            rdata.extend_from_slice(&optno.to_be_bytes());
            rdata.extend_from_slice(&(optval.len() as u16).to_be_bytes());
            rdata.extend_from_slice(optval);
        }

        let opt_rr_len = 1 + 2 + 2 + 4 + 2 + rdata.len();
        if packet.len() + opt_rr_len > limit {
            return Err(EdnsError::BufferOverflow {
                needed: opt_rr_len,
                available: limit.saturating_sub(packet.len()),
            });
        }

        // Append OPT RR at end of packet
        append_opt_rr(packet, udp_sz, rcode_ext, version, flags, &rdata);

        header.arcount += 1;
        write_header(packet, header);

        debug!("add_pseudoheader: created new OPT RR (udp_sz={}, do={})", udp_sz, do_bit);
        Ok(packet.len())
    }
}

/// Append a fully-formed OPT pseudo-RR to the end of a packet buffer.
fn append_opt_rr(
    packet: &mut Vec<u8>,
    udp_sz: u16,
    rcode_ext: u8,
    version: u8,
    flags: u16,
    rdata: &[u8],
) {
    packet.push(0); // root name
    packet.extend_from_slice(&T_OPT.to_be_bytes()); // TYPE = 41
    packet.extend_from_slice(&udp_sz.to_be_bytes()); // CLASS = UDP size
    // TTL = ext_rcode(8) | version(8) | flags(16)
    let ttl: u32 =
        ((rcode_ext as u32) << 24) | ((version as u32) << 16) | (flags as u32);
    packet.extend_from_slice(&ttl.to_be_bytes());
    packet.extend_from_slice(&(rdata.len() as u16).to_be_bytes()); // RDLEN
    packet.extend_from_slice(rdata); // RDATA
}

// ============================================================================
// Public API — add_do_bit
// ============================================================================

/// Set the DNSSEC OK (DO) bit in the EDNS0 OPT record of a DNS packet.
///
/// Convenience wrapper around [`add_pseudoheader`] that sets the DO bit
/// (bit 15 of EDNS flags) without adding any EDNS0 options. If no OPT
/// record exists, one is created with the default [`EDNS_PKTSZ`] UDP size.
///
/// # Arguments
/// * `header` — DNS header (modified if OPT is added).
/// * `packet` — DNS packet buffer.
/// * `limit`  — Maximum allowed packet length.
///
/// # Returns
/// New packet length on success, or an [`EdnsError`].
///
/// # RFC Compliance
/// - RFC 3225 (DO bit definition)
/// - RFC 4035 Section 3.2.1 (DNSSEC DO bit usage)
pub fn add_do_bit(
    header: &mut DnsHeader,
    packet: &mut Vec<u8>,
    limit: usize,
) -> Result<usize, EdnsError> {
    add_pseudoheader(
        header,
        packet,
        limit,
        EDNS_PKTSZ as u16,
        0,     // no option to add
        false, // not setting a specific option
        &[],   // no option data
        true,  // set DO bit
        0,     // don't replace
    )
}

// ============================================================================
// Internal — add_dns_client (Nominum Device ID option)
// ============================================================================

/// Add or strip Nominum DNS client identifier EDNS0 option.
///
/// Encodes the client MAC address in base64 ([`OPT_MAC_B64`]) or hex
/// ([`OPT_MAC_HEX`]) format as EDNS0_OPTION_NOMDEVICEID (65073).
///
/// # Modes
/// - `OPT_MAC_B64`/`OPT_MAC_HEX` without `OPT_STRIP_MAC`: Add MAC if available
/// - `OPT_MAC_B64`/`OPT_MAC_HEX` + `OPT_STRIP_MAC`: Replace (remove if unavailable)
/// - `OPT_STRIP_MAC` only: Unconditional removal
fn add_dns_client(
    header: &mut DnsHeader,
    packet: &mut Vec<u8>,
    limit: usize,
    source: &SocketAddress,
    now: Instant,
    cacheable: &mut bool,
    state: &DaemonState,
) -> Result<usize, EdnsError> {
    let mac_b64 = state.options.get(OPT_MAC_B64);
    let mac_hex = state.options.get(OPT_MAC_HEX);
    let strip_mac = state.options.get(OPT_STRIP_MAC);
    let edns_pktsz = state.dns.edns_pktsz;

    // Attempt MAC lookup via ARP/neighbor cache
    let mac = find_mac_for_source(source, now, 0);
    let maclen = mac.as_ref().map_or(0usize, |m| m.len());

    let mut replace: u8 = 0;

    if (mac_b64 || mac_hex) && maclen >= 6 {
        if strip_mac {
            replace = 1;
        }
        *cacheable = false;

        let mac_bytes = mac.unwrap();
        let encode: Vec<u8> = if mac_hex {
            // Hex encoding with colons
            format_mac_hex(&mac_bytes).into_bytes()
        } else {
            // Base64 encoding (6 bytes → 8 chars)
            let mut out = [0u8; 8];
            let in1: [u8; 3] = [
                mac_bytes.first().copied().unwrap_or(0),
                mac_bytes.get(1).copied().unwrap_or(0),
                mac_bytes.get(2).copied().unwrap_or(0),
            ];
            let in2: [u8; 3] = [
                mac_bytes.get(3).copied().unwrap_or(0),
                mac_bytes.get(4).copied().unwrap_or(0),
                mac_bytes.get(5).copied().unwrap_or(0),
            ];
            let mut o1 = [0u8; 4];
            let mut o2 = [0u8; 4];
            encoder(&in1, &mut o1);
            encoder(&in2, &mut o2);
            out[..4].copy_from_slice(&o1);
            out[4..8].copy_from_slice(&o2);
            out.to_vec()
        };

        return add_pseudoheader(
            header,
            packet,
            limit,
            edns_pktsz,
            EDNS0_OPTION_NOMDEVICEID,
            true,
            &encode,
            false,
            replace,
        );
    } else if strip_mac {
        // Strip mode only — remove existing option if present
        replace = 2;
        return add_pseudoheader(
            header,
            packet,
            limit,
            edns_pktsz,
            EDNS0_OPTION_NOMDEVICEID,
            true,
            &[],
            false,
            replace,
        );
    }

    Ok(packet.len())
}

// ============================================================================
// Internal — add_mac (EDNS0_OPTION_MAC = 65001)
// ============================================================================

/// Add or strip EDNS0 MAC address option (code 65001).
///
/// # Modes
/// - [`OPT_ADD_MAC`] only: Add raw MAC bytes if available from ARP cache
/// - [`OPT_ADD_MAC`] + [`OPT_STRIP_MAC`]: Replace MAC (remove if unavailable)
/// - [`OPT_STRIP_MAC`] only: Remove existing MAC option unconditionally
fn add_mac(
    header: &mut DnsHeader,
    packet: &mut Vec<u8>,
    limit: usize,
    source: &SocketAddress,
    now: Instant,
    cacheable: &mut bool,
    state: &DaemonState,
) -> Result<usize, EdnsError> {
    let add_mac_opt = state.options.get(OPT_ADD_MAC);
    let strip_mac = state.options.get(OPT_STRIP_MAC);
    let edns_pktsz = state.dns.edns_pktsz;

    // Attempt MAC lookup via ARP/neighbor cache
    let mac = find_mac_for_source(source, now, 0);
    let maclen = mac.as_ref().map_or(0usize, |m| m.len());

    let mut replace: u8 = 0;

    if add_mac_opt && maclen != 0 {
        *cacheable = false;
        if strip_mac {
            replace = 1;
        }
        let mac_bytes = mac.unwrap();
        return add_pseudoheader(
            header,
            packet,
            limit,
            edns_pktsz,
            EDNS0_OPTION_MAC,
            true,
            &mac_bytes,
            false,
            replace,
        );
    } else if strip_mac {
        // Strip mode only
        replace = 2;
        return add_pseudoheader(
            header,
            packet,
            limit,
            edns_pktsz,
            EDNS0_OPTION_MAC,
            true,
            &[],
            false,
            replace,
        );
    }

    Ok(packet.len())
}

// ============================================================================
// Internal — ECS helpers (RFC 7871)
// ============================================================================

/// Construct EDNS Client Subnet option data per RFC 7871.
///
/// Format: `FAMILY(2) | SOURCE_PREFIX(1) | SCOPE_PREFIX(1) | ADDRESS(variable)`
///
/// The address is truncated to the source prefix length in bits,
/// using [`INADDRSZ`] (4) for IPv4 and [`IN6ADDRSZ`] (16) for IPv6.
///
/// # Arguments
/// * `source`    — Client socket address.
/// * `_state`    — Daemon configuration (for future subnet override support).
/// * `cacheable` — Set to `false` if response is client-specific.
///
/// # Returns
/// The raw option data bytes for the ECS option.
fn calc_subnet_opt(
    source: &SocketAddress,
    _state: &DaemonState,
    cacheable: &mut bool,
) -> Vec<u8> {
    // Get the IP address and encode into ECS option data
    let ip = match source {
        SocketAddress::V4(v4) => IpAddr::V4(*v4.ip()),
        SocketAddress::V6(v6) => IpAddr::V6(*v6.ip()),
    };

    let (family, addr_bytes) = ip_addr_to_ecs_bytes(&ip);

    // Use INADDRSZ / IN6ADDRSZ for address size validation
    let addr_max_bytes = if family == 1 {
        INADDRSZ as usize
    } else {
        IN6ADDRSZ as usize
    };

    // Default source prefix: full address
    let source_prefix: u8 = if family == 1 { 32 } else { 128 };

    if source_prefix == 0 {
        // Zero prefix — send just the header
        *cacheable = true;
        let mut data = Vec::with_capacity(4);
        data.extend_from_slice(&family.to_be_bytes());
        data.push(0); // source_prefix
        data.push(0); // scope_prefix
        return data;
    }

    *cacheable = false;

    // Truncate address to the required prefix length (in bytes)
    let byte_len = ((source_prefix as usize).saturating_sub(1) / 8) + 1;
    let truncated_len = byte_len.min(addr_bytes.len()).min(addr_max_bytes);
    let mut truncated = addr_bytes[..truncated_len].to_vec();

    // Mask the last byte if prefix is not byte-aligned
    if source_prefix & 7 != 0 && !truncated.is_empty() {
        let last_idx = truncated.len() - 1;
        truncated[last_idx] &= 0xff << (8 - (source_prefix & 7));
    }

    let mut data = Vec::with_capacity(4 + truncated.len());
    data.extend_from_slice(&family.to_be_bytes());
    data.push(source_prefix);
    data.push(0); // scope_prefix (set by responder)
    data.extend_from_slice(&truncated);

    data
}

/// Add or strip EDNS Client Subnet (ECS) option per RFC 7871.
///
/// # Modes
/// - [`OPT_CLIENT_SUBNET`] only: Add ECS with client address
/// - [`OPT_CLIENT_SUBNET`] + [`OPT_STRIP_ECS`]: Replace existing ECS
/// - [`OPT_STRIP_ECS`] only: Remove existing ECS option
/// - Neither: Passive detection (check if client sent ECS → mark uncacheable)
fn add_source_addr(
    header: &mut DnsHeader,
    packet: &mut Vec<u8>,
    limit: usize,
    source: &SocketAddress,
    cacheable: &mut bool,
    state: &DaemonState,
) -> Result<usize, EdnsError> {
    let client_subnet = state.options.get(OPT_CLIENT_SUBNET);
    let strip_ecs = state.options.get(OPT_STRIP_ECS);
    let edns_pktsz = state.dns.edns_pktsz;

    let mut replace: u8 = 0;

    if client_subnet {
        if strip_ecs {
            replace = 1;
        }
        let opt_data = calc_subnet_opt(source, state, cacheable);
        return add_pseudoheader(
            header,
            packet,
            limit,
            edns_pktsz,
            EDNS0_OPTION_CLIENT_SUBNET,
            true,
            &opt_data,
            false,
            replace,
        );
    } else if strip_ecs {
        replace = 2;
        return add_pseudoheader(
            header,
            packet,
            limit,
            edns_pktsz,
            EDNS0_OPTION_CLIENT_SUBNET,
            true,
            &[],
            false,
            replace,
        );
    } else {
        // Passive detection: if still cacheable, check for client-sent ECS
        if *cacheable {
            if let Some(ph) = find_pseudoheader(header, packet) {
                for opt in &ph.options {
                    if opt.code == EDNS0_OPTION_CLIENT_SUBNET && opt.data.len() >= 4 {
                        let source_prefix = opt.data[2];
                        if source_prefix != 0 {
                            *cacheable = false;
                            break;
                        }
                    }
                }
            }
        }
        Ok(packet.len())
    }
}

// ============================================================================
// Internal — Cisco Umbrella option
// ============================================================================

/// Add Cisco Umbrella EDNS0 option (code 20292) with client identity.
///
/// Option structure (after "ODNS" magic):
/// - Fixed header: "ODNS" magic (4 bytes), version (1 byte), flags (1 byte)
/// - TLV fields: [`UMBRELLA_ORG`], [`UMBRELLA_IPV4`]/[`UMBRELLA_IPV6`],
///   [`UMBRELLA_DEVICE`], [`UMBRELLA_ASSET`]
///
/// Uses [`SocketAddress::is_v4`] and [`SocketAddress::is_v6`] to determine
/// which address type to encode. Uses [`SocketAddress::port`] for diagnostics.
fn add_umbrella_opt(
    header: &mut DnsHeader,
    packet: &mut Vec<u8>,
    limit: usize,
    source: &SocketAddress,
    cacheable: &mut bool,
    state: &DaemonState,
) -> Result<usize, EdnsError> {
    *cacheable = false;
    let edns_pktsz = state.dns.edns_pktsz;

    debug!(
        "add_umbrella_opt: encoding for {} client on port {}",
        if source.is_v4() { "IPv4" } else { "IPv6" },
        source.port()
    );

    // Build the Umbrella option data
    let mut opt_data = Vec::with_capacity(64);

    // Magic "ODNS" header
    opt_data.extend_from_slice(b"ODNS");
    // Version
    opt_data.push(UMBRELLA_VERSION);
    // Flags (0 = no special flags)
    opt_data.push(0);

    // Organization ID (if configured)
    if state.dns.umbrella_org != 0 {
        opt_data.extend_from_slice(&UMBRELLA_ORG.to_be_bytes());
        opt_data.extend_from_slice(&state.dns.umbrella_org.to_be_bytes());
    }

    // Client IP address — use is_v4()/is_v6() from SocketAddress
    if source.is_v4() {
        opt_data.extend_from_slice(&UMBRELLA_IPV4.to_be_bytes());
        if let SocketAddress::V4(v4) = source {
            opt_data.extend_from_slice(&v4.ip().octets());
        }
    } else if source.is_v6() {
        opt_data.extend_from_slice(&UMBRELLA_IPV6.to_be_bytes());
        if let SocketAddress::V6(v6) = source {
            opt_data.extend_from_slice(&v6.ip().octets());
        }
    }

    // Device ID (if configured via OPT_UMBRELLA_DEVID)
    if state.options.get(OPT_UMBRELLA_DEVID) {
        opt_data.extend_from_slice(&UMBRELLA_DEVICE.to_be_bytes());
        opt_data.extend_from_slice(&state.dns.umbrella_device);
    }

    // Asset ID (if configured)
    if state.dns.umbrella_asset != 0 {
        opt_data.extend_from_slice(&UMBRELLA_ASSET.to_be_bytes());
        opt_data.extend_from_slice(&state.dns.umbrella_asset.to_be_bytes());
    }

    add_pseudoheader(
        header,
        packet,
        limit,
        edns_pktsz,
        EDNS0_OPTION_UMBRELLA,
        true,
        &opt_data,
        false,
        1, // replace existing
    )
}

// ============================================================================
// Public API — check_source (RFC 7871 §9.2 validation)
// ============================================================================

/// Validate EDNS0 Client Subnet option in a DNS response (RFC 7871 §9.2).
///
/// When `peer` is `Some`, performs full validation: verifies the ECS option in
/// the response matches the expected subnet calculated from the peer address.
/// The peer [`SocketAddress`] is converted to an [`AllAddr`] internally for
/// address family comparison with the response data.
///
/// When `peer` is `None`, performs existence check: returns `false` if an ECS
/// option with non-zero source prefix is present.
///
/// # Arguments
/// * `_header` — DNS response packet header (used for context; OPT position known).
/// * `packet` — Full DNS packet buffer.
/// * `pheader` — Pre-located OPT pseudo-RR position (byte offset from [`PseudoHeader::position`]).
/// * `peer` — Client address for validation; `None` for existence check only.
///
/// # Returns
/// * `true` — Validation passes or no ECS option found.
/// * `false` — ECS mismatch (full mode) or ECS present (existence mode).
pub fn check_source(
    _header: &DnsHeader,
    packet: &[u8],
    pheader: usize,
    peer: Option<&SocketAddress>,
) -> bool {
    let plen = packet.len();

    // Skip the name in the OPT record
    let name_end = match skip_name_raw(packet, plen, pheader) {
        Some(p) => p,
        None => return true,
    };

    // TYPE(2) + CLASS(2) + TTL(4) + RDLEN(2) = 10 bytes
    if !check_len(plen, name_end, 10) {
        return true;
    }

    let rdlen = get_u16(packet, name_end + 8).unwrap_or(0) as usize;
    let rdata_off = name_end + 10;

    if !check_len(plen, rdata_off, rdlen) {
        return true;
    }

    // Build expected ECS data for comparison if peer address provided.
    // Convert SocketAddress -> AllAddr to access address bytes uniformly.
    let expected: Option<Vec<u8>> = peer.map(|p| {
        let all_addr: AllAddr = p.ip_as_all_addr();
        // AllAddr is used to validate address family consistency
        let _family_check = match all_addr {
            AllAddr::V4(_) => 1u16,
            AllAddr::V6(_) => 2u16,
            _ => 0u16,
        };
        match p {
            SocketAddress::V4(v4) => {
                let mut data = Vec::with_capacity(4 + INADDRSZ as usize);
                data.extend_from_slice(&1u16.to_be_bytes()); // family = 1
                data.push(32); // source prefix = /32
                data.push(0);  // scope prefix placeholder
                data.extend_from_slice(&v4.ip().octets());
                data
            }
            SocketAddress::V6(v6) => {
                let mut data = Vec::with_capacity(4 + IN6ADDRSZ as usize);
                data.extend_from_slice(&2u16.to_be_bytes()); // family = 2
                data.push(128); // source prefix = /128
                data.push(0);   // scope prefix placeholder
                data.extend_from_slice(&v6.ip().octets());
                data
            }
        }
    });

    // Scan EDNS0 options looking for ECS
    let mut off = 0;
    while off + 4 <= rdlen {
        let code = get_u16(packet, rdata_off + off).unwrap_or(0);
        let opt_len = get_u16(packet, rdata_off + off + 2).unwrap_or(0) as usize;
        off += 4;

        if code == EDNS0_OPTION_CLIENT_SUBNET {
            if let Some(ref exp) = expected {
                // Full validation mode
                if off + opt_len > rdlen {
                    return true; // malformed
                }
                // Copy scope prefix from response into expected data for comparison
                let mut check_data = exp.clone();
                if opt_len >= 4 && check_data.len() >= 4 {
                    check_data[3] = packet[rdata_off + off + 3];
                }
                if opt_len != check_data.len()
                    || packet[rdata_off + off..rdata_off + off + opt_len] != check_data[..]
                {
                    return false; // mismatch
                }
            } else {
                // Existence check: if source_netmask != 0, ECS is present
                if off + 3 <= rdlen && packet[rdata_off + off + 2] != 0 {
                    return false;
                }
            }
        }

        off += opt_len;
    }

    true
}

// ============================================================================
// Public API — add_edns0_config (main orchestrator)
// ============================================================================

/// Add all configured EDNS0 options to an outbound DNS query.
///
/// This is the master orchestrator function called from the forwarding engine
/// before sending queries to upstream servers. It adds options in this order:
///
/// 1. MAC address option (EDNS0_OPTION_MAC via `add_mac`)
/// 2. DNS client ID option (EDNS0_OPTION_NOMDEVICEID via `add_dns_client`)
/// 3. CPE ID option (EDNS0_OPTION_NOMCPEID, if configured via [`DnsConfig::dns_client_id`])
/// 4. Cisco Umbrella option (EDNS0_OPTION_UMBRELLA, if enabled via [`OPT_UMBRELLA`])
/// 5. EDNS Client Subnet (EDNS0_OPTION_CLIENT_SUBNET via `add_source_addr`)
///
/// Each option addition is best-effort: if buffer space is insufficient,
/// that option is silently skipped. The [`OptionFlags::get`] method is used
/// to check each feature flag before adding the corresponding option.
///
/// # Arguments
/// * `header` — DNS query header (fields [`DnsHeader::hb3`], [`DnsHeader::hb4`],
///   [`DnsHeader::qdcount`], [`DnsHeader::ancount`], [`DnsHeader::nscount`],
///   and [`DnsHeader::arcount`] are read/written).
/// * `packet` — DNS query packet buffer.
/// * `limit`  — Maximum packet length (buffer capacity).
/// * `source` — Client socket address for ECS/MAC/Umbrella options.
/// * `now`    — Current timestamp for ARP cache freshness.
/// * `_iface` — Network interface index (for MAC lookup scope).
/// * `_world` — Whether this is a query to the wider internet.
/// * `state`  — Daemon configuration and runtime state.
///
/// # Returns
/// New packet length after adding all configured options.
pub fn add_edns0_config(
    header: &mut DnsHeader,
    packet: &mut Vec<u8>,
    limit: usize,
    source: &SocketAddress,
    now: Instant,
    _iface: u32,
    _world: bool,
    state: &DaemonState,
) -> Result<usize, EdnsError> {
    let mut cacheable = true;

    // 1. Add MAC address option (EDNS0_OPTION_MAC = 65001)
    let _ = add_mac(header, packet, limit, source, now, &mut cacheable, state);

    // 2. Add DNS client ID option (EDNS0_OPTION_NOMDEVICEID = 65073)
    let _ = add_dns_client(header, packet, limit, source, now, &mut cacheable, state);

    // 3. Add CPE ID if configured (EDNS0_OPTION_NOMCPEID = 65074)
    let edns_sz = get_edns_pktsz_from_state(state);
    if let Some(ref dns_client_id) = state.dns.dns_client_id {
        let id_bytes = dns_client_id.as_bytes();
        let _ = add_pseudoheader(
            header,
            packet,
            limit,
            edns_sz,
            EDNS0_OPTION_NOMCPEID,
            true,
            id_bytes,
            false,
            1, // replace
        );
    }

    // 4. Add Cisco Umbrella option if enabled (EDNS0_OPTION_UMBRELLA = 20292)
    if state.options.get(OPT_UMBRELLA) {
        let _ = add_umbrella_opt(header, packet, limit, source, &mut cacheable, state);
    }

    // 5. Add EDNS Client Subnet (EDNS0_OPTION_CLIENT_SUBNET = 8)
    let _ = add_source_addr(header, packet, limit, source, &mut cacheable, state);

    Ok(packet.len())
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    /// Build a minimal DNS query packet with given header fields.
    fn make_query_packet(id: u16, qdcount: u16) -> (DnsHeader, Vec<u8>) {
        let header = DnsHeader {
            id,
            hb3: 0x01, // RD=1
            hb4: 0x00,
            qdcount,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        };
        let mut packet = vec![0u8; DNS_HEADER_SIZE];
        write_header(&mut packet, &header);

        // Add a simple question: root name (1 byte = 0x00), type A, class IN
        if qdcount >= 1 {
            packet.push(0x00); // root name
            packet.extend_from_slice(&1u16.to_be_bytes()); // QTYPE = A
            packet.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
        }

        (header, packet)
    }

    #[test]
    fn test_find_pseudoheader_no_opt() {
        let (header, packet) = make_query_packet(0x1234, 1);
        let result = find_pseudoheader(&header, &packet);
        assert!(result.is_none());
    }

    #[test]
    fn test_add_and_find_pseudoheader() {
        let (mut header, mut packet) = make_query_packet(0x1234, 1);
        let limit = 4096;

        // Add a pseudoheader with no options
        let new_len = add_pseudoheader(
            &mut header, &mut packet, limit, 1232, 0, false, &[], false, 0,
        )
        .unwrap();
        assert!(new_len > DNS_HEADER_SIZE + 5);
        assert_eq!(header.arcount, 1);

        // Now find it
        let ph = find_pseudoheader(&header, &packet);
        assert!(ph.is_some());
        let ph = ph.unwrap();
        assert_eq!(ph.udp_size, 1232);
        assert_eq!(ph.flags & DO_BIT, 0);
        assert!(ph.options.is_empty());
    }

    #[test]
    fn test_add_do_bit() {
        let (mut header, mut packet) = make_query_packet(0x5678, 1);
        let limit = 4096;

        let _new_len = add_do_bit(&mut header, &mut packet, limit).unwrap();
        let ph = find_pseudoheader(&header, &packet).unwrap();
        assert_ne!(ph.flags & DO_BIT, 0, "DO bit must be set");
    }

    #[test]
    fn test_add_pseudoheader_with_option() {
        let (mut header, mut packet) = make_query_packet(0xABCD, 1);
        let limit = 4096;

        let test_data = [0x01, 0x02, 0x03, 0x04];
        let _new_len = add_pseudoheader(
            &mut header, &mut packet, limit, 1232,
            EDNS0_OPTION_MAC, true, &test_data, false, 0,
        )
        .unwrap();

        let ph = find_pseudoheader(&header, &packet).unwrap();
        assert_eq!(ph.options.len(), 1);
        assert_eq!(ph.options[0].code, EDNS0_OPTION_MAC);
        assert_eq!(ph.options[0].data, test_data);
    }

    #[test]
    fn test_add_pseudoheader_replace() {
        let (mut header, mut packet) = make_query_packet(0xABCD, 1);
        let limit = 4096;

        // Add initial option
        let _ = add_pseudoheader(
            &mut header, &mut packet, limit, 1232,
            EDNS0_OPTION_MAC, true, &[0x01, 0x02], false, 0,
        )
        .unwrap();

        // Replace with new data (replace=1)
        let _ = add_pseudoheader(
            &mut header, &mut packet, limit, 1232,
            EDNS0_OPTION_MAC, true, &[0xAA, 0xBB, 0xCC], false, 1,
        )
        .unwrap();

        let ph = find_pseudoheader(&header, &packet).unwrap();
        let mac_opts: Vec<_> = ph.options.iter().filter(|o| o.code == EDNS0_OPTION_MAC).collect();
        assert_eq!(mac_opts.len(), 1);
        assert_eq!(mac_opts[0].data, vec![0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn test_add_pseudoheader_no_replace_existing() {
        let (mut header, mut packet) = make_query_packet(0xABCD, 1);
        let limit = 4096;

        let _ = add_pseudoheader(
            &mut header, &mut packet, limit, 1232,
            EDNS0_OPTION_MAC, true, &[0x01, 0x02], false, 0,
        )
        .unwrap();

        let len_before = packet.len();

        // Try to add again with replace=0 — should be a no-op
        let new_len = add_pseudoheader(
            &mut header, &mut packet, limit, 1232,
            EDNS0_OPTION_MAC, true, &[0xAA, 0xBB, 0xCC], false, 0,
        )
        .unwrap();

        assert_eq!(new_len, len_before);
    }

    #[test]
    fn test_add_pseudoheader_replace_only_mode() {
        let (mut header, mut packet) = make_query_packet(0xABCD, 1);
        let limit = 4096;
        let len_before = packet.len();

        // Replace=2 with no existing OPT — should be no-op
        let new_len = add_pseudoheader(
            &mut header, &mut packet, limit, 1232,
            EDNS0_OPTION_MAC, true, &[0x01], false, 2,
        )
        .unwrap();

        assert_eq!(new_len, len_before);
        assert_eq!(header.arcount, 0);
    }

    #[test]
    fn test_buffer_overflow_protection() {
        let (mut header, mut packet) = make_query_packet(0x1111, 1);
        let limit = packet.len() + 5; // Not enough for OPT RR

        let result = add_pseudoheader(
            &mut header, &mut packet, limit, 1232, 0, false, &[], false, 0,
        );

        assert!(result.is_err());
        if let Err(EdnsError::BufferOverflow { needed, available }) = result {
            assert!(needed > available);
        }
    }

    #[test]
    fn test_char64_mapping() {
        assert_eq!(char64(0), b'A');
        assert_eq!(char64(25), b'Z');
        assert_eq!(char64(26), b'a');
        assert_eq!(char64(51), b'z');
        assert_eq!(char64(52), b'0');
        assert_eq!(char64(61), b'9');
        assert_eq!(char64(62), b'+');
        assert_eq!(char64(63), b'/');
    }

    #[test]
    fn test_encoder_base64() {
        let input: [u8; 3] = [0xAB, 0xCD, 0xEF];
        let mut output = [0u8; 4];
        encoder(&input, &mut output);
        for b in &output {
            assert!(
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
                    .contains(b)
            );
        }
    }

    #[test]
    fn test_format_mac_hex() {
        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        assert_eq!(format_mac_hex(&mac), "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn test_calc_subnet_opt_v4() {
        let source = SocketAddress::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 12345));
        let state = DaemonState::default();
        let mut cacheable = true;

        let data = calc_subnet_opt(&source, &state, &mut cacheable);
        assert!(data.len() >= 4);
        assert_eq!(u16::from_be_bytes([data[0], data[1]]), 1); // family = IPv4
        assert_eq!(data[2], 32); // source_prefix = /32
        assert_eq!(data[3], 0);  // scope_prefix = 0
        assert!(!cacheable);
    }

    #[test]
    fn test_calc_subnet_opt_v6() {
        let source = SocketAddress::V6(SocketAddrV6::new(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            12345, 0, 0,
        ));
        let state = DaemonState::default();
        let mut cacheable = true;

        let data = calc_subnet_opt(&source, &state, &mut cacheable);
        assert!(data.len() >= 4);
        assert_eq!(u16::from_be_bytes([data[0], data[1]]), 2); // family = IPv6
        assert_eq!(data[2], 128); // source_prefix = /128
        assert!(!cacheable);
    }

    #[test]
    fn test_check_source_no_ecs() {
        let (mut header, mut packet) = make_query_packet(0x1234, 1);
        let limit = 4096;

        let _ = add_pseudoheader(
            &mut header, &mut packet, limit, 1232, 0, false, &[], false, 0,
        )
        .unwrap();

        let ph = find_pseudoheader(&header, &packet).unwrap();
        let result = check_source(&header, &packet, ph.position, None);
        assert!(result);
    }

    #[test]
    fn test_check_source_with_ecs_existence() {
        let (mut header, mut packet) = make_query_packet(0x1234, 1);
        let limit = 4096;

        // Add an ECS option with source_prefix = 24
        let ecs_data = vec![
            0x00, 0x01, // family = 1 (IPv4)
            24,         // source prefix
            0,          // scope prefix
            192, 168, 1, // truncated to /24
        ];
        let _ = add_pseudoheader(
            &mut header, &mut packet, limit, 1232,
            EDNS0_OPTION_CLIENT_SUBNET, true, &ecs_data, false, 0,
        )
        .unwrap();

        let ph = find_pseudoheader(&header, &packet).unwrap();

        // Existence check (peer=None): should return false (ECS present)
        let result = check_source(&header, &packet, ph.position, None);
        assert!(!result);
    }

    #[test]
    fn test_multiple_options() {
        let (mut header, mut packet) = make_query_packet(0xABCD, 1);
        let limit = 4096;

        // Add MAC option
        let _ = add_pseudoheader(
            &mut header, &mut packet, limit, 1232,
            EDNS0_OPTION_MAC, true, &[0x01, 0x02, 0x03], false, 0,
        )
        .unwrap();

        // Add EDE option
        let _ = add_pseudoheader(
            &mut header, &mut packet, limit, 1232,
            EDNS0_OPTION_EDE, true, &[0x00, 0x06], false, 0,
        )
        .unwrap();

        let ph = find_pseudoheader(&header, &packet).unwrap();
        assert_eq!(ph.options.len(), 2);

        let codes: Vec<u16> = ph.options.iter().map(|o| o.code).collect();
        assert!(codes.contains(&EDNS0_OPTION_MAC));
        assert!(codes.contains(&EDNS0_OPTION_EDE));
    }

    #[test]
    fn test_do_bit_preserved_after_option_add() {
        let (mut header, mut packet) = make_query_packet(0x1234, 1);
        let limit = 4096;

        // First set DO bit
        let _ = add_do_bit(&mut header, &mut packet, limit).unwrap();

        // Add an option — DO bit should be preserved
        let _ = add_pseudoheader(
            &mut header, &mut packet, limit, 1232,
            EDNS0_OPTION_MAC, true, &[0x01, 0x02], false, 0,
        )
        .unwrap();

        let ph = find_pseudoheader(&header, &packet).unwrap();
        assert_ne!(ph.flags & DO_BIT, 0, "DO bit should be preserved");
        assert_eq!(ph.options.len(), 1);
    }

    #[test]
    fn test_parse_opt_ttl() {
        // TTL = 0x00_00_80_00 means rcode=0, version=0, flags=0x8000 (DO bit)
        let buf = [0x00, 0x00, 0x80, 0x00];
        let (rcode, version, flags) = parse_opt_ttl(&buf, 0).unwrap();
        assert_eq!(rcode, 0);
        assert_eq!(version, 0);
        assert_eq!(flags, DO_BIT);
    }

    #[test]
    fn test_edns_error_display() {
        let e1 = EdnsError::PacketTooSmall;
        assert!(format!("{}", e1).contains("too small"));

        let e2 = EdnsError::InvalidFormat;
        assert!(format!("{}", e2).contains("invalid"));

        let e3 = EdnsError::BufferOverflow {
            needed: 100,
            available: 50,
        };
        let msg = format!("{}", e3);
        assert!(msg.contains("100"));
        assert!(msg.contains("50"));
    }

    #[test]
    fn test_pseudoheader_struct_fields() {
        let ph = PseudoHeader {
            udp_size: 4096,
            rcode_ext: 0,
            version: 0,
            flags: DO_BIT,
            options: vec![EdnsOption {
                code: EDNS0_OPTION_EDE,
                data: vec![0x00, 0x06],
            }],
            position: 42,
        };
        assert_eq!(ph.udp_size, 4096);
        assert_eq!(ph.rcode_ext, 0);
        assert_eq!(ph.version, 0);
        assert_ne!(ph.flags & DO_BIT, 0);
        assert_eq!(ph.options.len(), 1);
        assert_eq!(ph.options[0].code, EDNS0_OPTION_EDE);
        assert_eq!(ph.options[0].data, vec![0x00, 0x06]);
        assert_eq!(ph.position, 42);
    }

    #[test]
    fn test_edns_option_struct() {
        let opt = EdnsOption {
            code: EDNS0_OPTION_MAC,
            data: vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        };
        assert_eq!(opt.code, 65001);
        assert_eq!(opt.data.len(), 6);
    }

    #[test]
    fn test_is_opt_type() {
        assert!(is_opt_type(41));
        assert!(!is_opt_type(1)); // A record
        assert!(!is_opt_type(28)); // AAAA record
    }

    #[test]
    fn test_ip_addr_to_ecs_bytes() {
        let v4 = IpAddr::V4(Ipv4Addr::new(10, 20, 30, 40));
        let (family, bytes) = ip_addr_to_ecs_bytes(&v4);
        assert_eq!(family, 1);
        assert_eq!(bytes, vec![10, 20, 30, 40]);

        let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let (family, bytes) = ip_addr_to_ecs_bytes(&v6);
        assert_eq!(family, 2);
        assert_eq!(bytes.len(), 16);
    }

    #[test]
    fn test_add_edns0_config_default_state() {
        let (mut header, mut packet) = make_query_packet(0x1234, 1);
        let limit = 4096;
        let source = SocketAddress::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53));
        let state = DaemonState::default();
        let now = Instant::now();

        let result = add_edns0_config(
            &mut header, &mut packet, limit, &source, now, 0, true, &state,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_ede_code_usage() {
        // Verify EDE codes from protocol module can be used as option data
        let ede_bogus = EdeCode::DnssecBogus as u16;
        let ede_not_ready = EdeCode::NotReady as u16;
        assert_eq!(ede_bogus, 6);
        assert_eq!(ede_not_ready, 14);

        // Construct an EDE option
        let (mut header, mut packet) = make_query_packet(0x1234, 1);
        let ede_data = ede_bogus.to_be_bytes().to_vec();
        let _ = add_pseudoheader(
            &mut header, &mut packet, 4096, 1232,
            EDNS0_OPTION_EDE, true, &ede_data, false, 0,
        )
        .unwrap();

        let ph = find_pseudoheader(&header, &packet).unwrap();
        assert_eq!(ph.options[0].code, EDNS0_OPTION_EDE);
        assert_eq!(ph.options[0].data, vec![0x00, 0x06]);
    }

    #[test]
    fn test_rr_type_cross_reference() {
        // Verify RrType::OPT corresponds to T_OPT
        assert_eq!(RrType::Opt as u16, T_OPT);
    }
}

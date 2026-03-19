// dnsmasq is Copyright (c) 2000-2025 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

//! EDNS0 Extension Mechanism for DNS per RFC 6891.
//!
//! This module implements the Extension Mechanisms for DNS (EDNS0), providing
//! mechanisms to extend DNS beyond its original 512-byte UDP limit and to carry
//! additional metadata. Migrated from C `src/edns0.c` (1,340 lines).
//!
//! # Core Functionality
//!
//! - **OPT Pseudo-RR Management** — Locate, add, and replace EDNS0 OPT pseudo-RRs
//!   in the DNS message additional section per RFC 6891.
//! - **DNSSEC DO Bit** — Set the DNSSEC OK (DO) bit in the EDNS0 flags to request
//!   DNSSEC-signed responses from upstream servers.
//! - **Client Subnet (ECS)** — RFC 7871 EDNS Client Subnet option for geographic
//!   DNS optimization, supporting both IPv4 and IPv6 source prefixes.
//! - **MAC Address Options** — Vendor-specific EDNS0 options for device identification
//!   in enterprise networks (raw MAC bytes, base64-encoded, or hex-encoded).
//! - **Cisco Umbrella** — Vendor-specific "ODNS" options for Cisco Umbrella integration
//!   including organization ID, device ID, and asset ID.
//! - **Extended DNS Error (EDE)** — RFC 8914 extended error information codes for
//!   richer error diagnostics.
//!
//! # Memory Safety
//!
//! All C `memcpy`/`memmove`/`PUTSHORT`/`PUTLONG` patterns have been replaced with
//! safe buffer operations via the `bytes` crate. There are zero `unsafe` blocks.

use crate::core::types::{opt, DaemonState, DnsmasqError, DnsmasqResult, MySockAddr};
use crate::core::util::format_mac;
use crate::dns::protocol::{ede, edns0, get_u16, get_u32, DnsHeader, RRType, PACKETSZ, RRFIXEDSZ};
use crate::dns::rrfilter::{rrfilter, RRFilterMode};
use crate::network::arp::{ArpCache, DHCP_CHADDR_MAX};

use bytes::{BufMut, BytesMut};
use std::net::IpAddr;
use std::time::Instant;
use tracing::{debug, trace};

// ===========================================================================
// DNS Header Size Constant (matches protocol.rs internal HDRSIZE = 12)
// ===========================================================================

/// DNS header size in bytes (ID + flags + 4 section counts).
const HDRSIZE: usize = 12;

// ===========================================================================
// EDNS0 Option Codes per RFC 6891 and IANA Registry
// ===========================================================================

/// EDNS0 option codes per RFC 6891 and IANA registry.
///
/// From `src/dns-protocol.h` EDNS0_OPTION_* constants. These are re-exported
/// from the protocol module's `edns0` sub-module, plus additional codes that
/// were not present there (COOKIE, PADDING).
pub mod option_codes {
    /// MAC address (vendor-specific, dnsmasq extension).
    pub const EDNS0_OPTION_MAC: u16 = super::edns0::OPTION_MAC;
    /// Client Subnet per RFC 7871.
    pub const EDNS0_OPTION_CLIENT_SUBNET: u16 = super::edns0::OPTION_CLIENT_SUBNET;
    /// Nominum/Akamai device ID (vendor-specific).
    pub const EDNS0_OPTION_NOMDEVICEID: u16 = super::edns0::OPTION_NOMDEVICEID;
    /// Nominum/Akamai CPE ID (vendor-specific).
    pub const EDNS0_OPTION_NOMCPEID: u16 = super::edns0::OPTION_NOMCPEID;
    /// Extended DNS Error per RFC 8914.
    pub const EDNS0_OPTION_EDE: u16 = super::edns0::OPTION_EDE;
    /// DNS Cookie per RFC 7873.
    pub const EDNS0_OPTION_COOKIE: u16 = 10;
    /// Padding per RFC 7830.
    pub const EDNS0_OPTION_PADDING: u16 = 12;
    /// Cisco Umbrella (vendor-specific).
    pub const EDNS0_OPTION_UMBRELLA: u16 = super::edns0::OPTION_UMBRELLA;
}

// ===========================================================================
// Extended DNS Error (EDE) Codes per RFC 8914
// ===========================================================================

/// Extended DNS Error (EDE) info-codes per RFC 8914.
///
/// These codes provide more detailed error information than the 4-bit DNS
/// RCODE field allows. Each code can optionally carry descriptive text.
/// From `src/dns-protocol.h` EDE_* constants.
pub mod ede_codes {
    /// Sentinel value indicating no EDE code has been set.
    pub const EDE_UNSET: i16 = super::ede::UNSET;
    /// Other error (code 0).
    pub const EDE_OTHER: u16 = super::ede::OTHER;
    /// Unsupported DNSKEY Algorithm.
    pub const EDE_UNSUPPORTED_DNSKEY: u16 = super::ede::UNSUP_DNSKEY;
    /// Unsupported DS Digest Type.
    pub const EDE_UNSUPPORTED_DS: u16 = super::ede::UNSUP_DS;
    /// Stale Answer (RFC 8767).
    pub const EDE_STALE_ANSWER: u16 = super::ede::STALE;
    /// Forged Answer.
    pub const EDE_FORGED_ANSWER: u16 = super::ede::FORGED;
    /// DNSSEC Indeterminate.
    pub const EDE_DNSSEC_INDETERMINATE: u16 = super::ede::DNSSEC_INDETERMINATE;
    /// DNSSEC Bogus.
    pub const EDE_DNSSEC_BOGUS: u16 = super::ede::DNSSEC_BOGUS;
    /// Signature Expired.
    pub const EDE_SIG_EXPIRED: u16 = super::ede::SIG_EXPIRED;
    /// Signature Not Yet Valid.
    pub const EDE_SIG_NOT_YET_VALID: u16 = super::ede::SIG_NOT_YET_VALID;
    /// DNSKEY Missing.
    pub const EDE_DNSKEY_MISSING: u16 = super::ede::DNSKEY_MISSING;
    /// RRSIG Missing.
    pub const EDE_RRSIG_MISSING: u16 = super::ede::RRSIG_MISSING;
    /// No Zone Key Bit Set.
    pub const EDE_NO_ZONE_KEY_BIT: u16 = super::ede::NO_ZONE_KEY;
    /// NSEC Missing.
    pub const EDE_NSEC_MISSING: u16 = super::ede::NSEC_MISSING;
    /// Cached Error.
    pub const EDE_CACHED_ERROR: u16 = super::ede::CACHED_ERR;
    /// Not Ready.
    pub const EDE_NOT_READY: u16 = super::ede::NOT_READY;
    /// Blocked.
    pub const EDE_BLOCKED: u16 = super::ede::BLOCKED;
    /// Censored.
    pub const EDE_CENSORED: u16 = super::ede::CENSORED;
    /// Filtered.
    pub const EDE_FILTERED: u16 = super::ede::FILTERED;
    /// Prohibited.
    pub const EDE_PROHIBITED: u16 = super::ede::PROHIBITED;
    /// Stale NXDOMAIN Answer.
    pub const EDE_STALE_NXDOMAIN: u16 = super::ede::STALE_NXD;
    /// Not Authoritative.
    pub const EDE_NOT_AUTHORITATIVE: u16 = super::ede::NOT_AUTH;
    /// Not Supported.
    pub const EDE_NOT_SUPPORTED: u16 = super::ede::NOT_SUP;
    /// No Reachable Authority.
    pub const EDE_NO_AUTHORITY: u16 = super::ede::NO_AUTH;
    /// Network Error.
    pub const EDE_NETWORK_ERROR: u16 = super::ede::NETERR;
    /// Invalid Data.
    pub const EDE_INVALID_DATA: u16 = super::ede::INVALID_DATA;
    /// Signature Expired Before Valid.
    pub const EDE_SIG_EXPIRED_BEFORE_VALID: u16 = super::ede::SIG_E_B_V;
    /// Too Early.
    pub const EDE_TOO_EARLY: u16 = super::ede::TOO_EARLY;
    /// Unsupported NSEC3 Iterations Value.
    pub const EDE_UNSUPPORTED_NS3_ITERATIONS: u16 = super::ede::UNS_NS3_ITER;
    /// Unable to Conform to Policy.
    pub const EDE_UNABLE_POLICY: u16 = super::ede::UNABLE_POLICY;
    /// Synthesized.
    pub const EDE_SYNTHESIZED: u16 = super::ede::SYNTHESIZED;
}

// ===========================================================================
// EDNS0 Data Structures
// ===========================================================================

/// EDNS0 flags parsed from the OPT pseudo-RR TTL field.
///
/// Per RFC 6891 Section 6.1.3, the TTL field of the OPT pseudo-RR is
/// repurposed to carry EDNS0 flags and metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdnsFlags {
    /// DNSSEC OK bit (DO) — set when the client wants DNSSEC resource records.
    pub dnssec_ok: bool,
    /// Maximum UDP payload size the sender can reassemble.
    pub udp_size: u16,
    /// Extended RCODE (upper 8 bits extending the 4-bit header RCODE).
    pub extended_rcode: u8,
    /// EDNS version (must be 0 for RFC 6891 compliance).
    pub version: u8,
}

impl Default for EdnsFlags {
    fn default() -> Self {
        Self {
            dnssec_ok: false,
            udp_size: PACKETSZ as u16,
            extended_rcode: 0,
            version: 0,
        }
    }
}

/// Parsed EDNS0 option from an OPT pseudo-RR's RDATA.
///
/// Each option consists of a 16-bit code and variable-length data, per
/// RFC 6891 Section 6.1.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdnsOption {
    /// EDNS0 option code (IANA registered or vendor-specific).
    pub code: u16,
    /// Raw option data bytes.
    pub data: Vec<u8>,
}

/// Collection of EDNS0 options attached to a DNS message.
///
/// Represents the full content of an OPT pseudo-RR: both the flags encoded
/// in the fixed fields and the list of variable-length options in the RDATA.
#[derive(Debug, Clone)]
pub struct EdnsData {
    /// EDNS0 flags (UDP size, DO bit, extended RCODE, version).
    pub flags: EdnsFlags,
    /// Parsed EDNS0 options from the OPT RDATA.
    pub options: Vec<EdnsOption>,
}

// ===========================================================================
// Replace Mode for add_pseudoheader()
// ===========================================================================

/// Controls how `add_pseudoheader()` handles existing EDNS0 options.
///
/// Mirrors C's `replace` parameter (0, 1, 2) from `add_pseudoheader()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplaceMode {
    /// Mode 0: Do not replace — only add if the option doesn't already exist.
    NoReplace,
    /// Mode 1: Replace existing option or add if not present.
    ReplaceOrAdd,
    /// Mode 2: Replace existing option only; do nothing if not present.
    ReplaceOnly,
}

// ===========================================================================
// Cisco Umbrella Constants
// ===========================================================================

/// Cisco Umbrella protocol version.
const UMBRELLA_VERSION: u8 = 1;
/// TLV type code for asset ID (u32).
const UMBRELLA_ASSET: u16 = 0x0004;
/// TLV type code for organization ID (u32).
const UMBRELLA_ORG: u16 = 0x0008;
/// TLV type code for IPv4 address (4 bytes).
const UMBRELLA_IPV4: u16 = 0x0010;
/// TLV type code for IPv6 address (16 bytes).
const UMBRELLA_IPV6: u16 = 0x0020;
/// TLV type code for device ID (8 bytes).
const UMBRELLA_DEVICE: u16 = 0x0040;

/// Cisco Umbrella "ODNS" magic header.
const UMBRELLA_MAGIC: &[u8; 4] = b"ODNS";

// ===========================================================================
// RFC 7871 Client Subnet Structure
// ===========================================================================

/// RFC 7871 EDNS Client Subnet option data layout.
///
/// Replaces C `struct subnet_opt` from edns0.c lines 783-787.
#[derive(Debug, Clone)]
struct SubnetOpt {
    /// Address family: 1 = IPv4, 2 = IPv6.
    family: u16,
    /// Source prefix length (number of significant bits).
    source_netmask: u8,
    /// Scope prefix length (set by responder, 0 in queries).
    scope_netmask: u8,
    /// Truncated address bytes (only `ceil(source_netmask/8)` bytes used).
    addr: Vec<u8>,
}

impl SubnetOpt {
    /// Serialize this option into wire format bytes.
    fn to_bytes(&self) -> Vec<u8> {
        // 2 (family) + 1 (source mask) + 1 (scope mask) + address bytes
        let addr_bytes = (self.source_netmask as usize).div_ceil(8);
        let total = 4 + addr_bytes;
        let mut buf = Vec::with_capacity(total);
        buf.push((self.family >> 8) as u8);
        buf.push((self.family & 0xFF) as u8);
        buf.push(self.source_netmask);
        buf.push(self.scope_netmask);
        // Copy only the significant bytes, masking the trailing bits
        for i in 0..addr_bytes {
            if i < self.addr.len() {
                buf.push(self.addr[i]);
            } else {
                buf.push(0);
            }
        }
        buf
    }

    /// Parse a SubnetOpt from wire format bytes.
    fn from_bytes(data: &[u8]) -> DnsmasqResult<Self> {
        if data.len() < 4 {
            return Err(DnsmasqError::DnsProtocol("subnet option too short".into()));
        }
        let family = u16::from_be_bytes([data[0], data[1]]);
        let source_netmask = data[2];
        let scope_netmask = data[3];
        let addr_bytes = (source_netmask as usize).div_ceil(8);
        if data.len() < 4 + addr_bytes {
            return Err(DnsmasqError::DnsProtocol(
                "subnet option address truncated".into(),
            ));
        }
        let addr = data[4..4 + addr_bytes].to_vec();
        Ok(Self {
            family,
            source_netmask,
            scope_netmask,
            addr,
        })
    }
}

// ===========================================================================
// EdnsHandler — Core EDNS0 Processing
// ===========================================================================

/// EDNS0 handler providing all EDNS0 OPT pseudo-RR manipulation functions.
///
/// This is a stateless handler struct — all methods operate on packet buffers
/// and daemon state passed as parameters. The struct groups the related
/// functionality for organizational clarity.
///
/// Replaces the top-level functions from C `src/edns0.c`.
pub struct EdnsHandler;

impl EdnsHandler {
    // -----------------------------------------------------------------------
    // find_pseudoheader() — Locate existing OPT pseudo-RR
    // -----------------------------------------------------------------------

    /// Locate an existing EDNS0 OPT pseudo-RR in a DNS packet's additional section.
    ///
    /// Scans the additional section of the DNS message for a record with type OPT (41).
    /// Per RFC 6891, there MUST be at most one OPT pseudo-RR per message, and its
    /// owner name MUST be the root domain (".").
    ///
    /// Also detects TSIG (type 250) and TKEY (type 249) records in the additional
    /// section, setting the `is_sign` flag if found.
    ///
    /// # Arguments
    /// * `packet` — Raw DNS packet bytes
    /// * `packet_len` — Actual length of the DNS packet within the buffer
    ///
    /// # Returns
    /// * `Ok(Some((edns_data, opt_start, opt_len, is_sign)))` — OPT found at byte offset
    ///   `opt_start`, spanning `opt_len` bytes. `is_sign` is true if TSIG/TKEY was also found.
    /// * `Ok(None)` — No OPT pseudo-RR in the message.
    /// * `Err(...)` — Malformed packet.
    ///
    /// Maps to C `find_pseudoheader()` (edns0.c lines 129-206).
    pub fn find_pseudoheader(
        packet: &[u8],
        packet_len: usize,
    ) -> DnsmasqResult<Option<(EdnsData, usize, usize, bool)>> {
        if packet_len < HDRSIZE {
            return Err(DnsmasqError::DnsProtocol(
                "find_pseudoheader: packet too short for DNS header".into(),
            ));
        }

        let header = DnsHeader::parse(&packet[..packet_len])?;
        let qdcount = header.qdcount as usize;
        let ancount = header.ancount as usize;
        let nscount = header.nscount as usize;
        let arcount = header.arcount as usize;

        // Navigate past all sections to reach the additional section.
        let mut offset = HDRSIZE;

        // Skip question section(s)
        for _ in 0..qdcount {
            offset = skip_name_wire(packet, packet_len, offset)?;
            // skip qtype (2) + qclass (2)
            if offset + 4 > packet_len {
                return Err(DnsmasqError::DnsProtocol(
                    "find_pseudoheader: question section truncated".into(),
                ));
            }
            offset += 4;
        }

        // Skip answer and authority sections
        let skip_rrs = ancount + nscount;
        for _ in 0..skip_rrs {
            offset = skip_rr_wire(packet, packet_len, offset)?;
        }

        // Scan the additional section for OPT (and TSIG/TKEY)
        let mut is_sign = false;
        for _ in 0..arcount {
            let rr_start = offset;

            // Read name
            let name_end = skip_name_wire(packet, packet_len, offset)?;
            if name_end + RRFIXEDSZ > packet_len {
                return Err(DnsmasqError::DnsProtocol(
                    "find_pseudoheader: additional section RR truncated".into(),
                ));
            }

            let rr_type_raw = get_u16(packet, name_end)?;
            let rr_type = RRType::from_u16(rr_type_raw);
            let _rr_class = get_u16(packet, name_end + 2)?;
            let rr_ttl = get_u32(packet, name_end + 4)?;
            let rdlength = get_u16(packet, name_end + 8)? as usize;
            let rdata_start = name_end + RRFIXEDSZ;
            let rr_end = rdata_start + rdlength;

            if rr_end > packet_len {
                return Err(DnsmasqError::DnsProtocol(
                    "find_pseudoheader: additional section RR RDATA overflows packet".into(),
                ));
            }

            // Detect TSIG/TKEY signatures
            if rr_type == RRType::TSIG || rr_type == RRType::TKEY {
                is_sign = true;
            }

            // Check for OPT pseudo-RR (type 41)
            if rr_type == RRType::OPT {
                // Parse EDNS0 flags from the fixed fields:
                // - CLASS field = UDP payload size
                // - TTL field bits: extended RCODE (8), version (8), DO (1), Z (15)
                let udp_size = _rr_class;
                let extended_rcode = ((rr_ttl >> 24) & 0xFF) as u8;
                let version = ((rr_ttl >> 16) & 0xFF) as u8;
                let dnssec_ok = (rr_ttl & 0x8000) != 0;

                let flags = EdnsFlags {
                    dnssec_ok,
                    udp_size,
                    extended_rcode,
                    version,
                };

                // Parse individual options from RDATA
                let options = Self::parse_options(&packet[rdata_start..rr_end])?;

                let edns_data = EdnsData { flags, options };
                let opt_len = rr_end - rr_start;

                trace!(
                    udp_size = udp_size,
                    dnssec_ok = dnssec_ok,
                    version = version,
                    num_options = edns_data.options.len(),
                    "found EDNS0 OPT pseudo-RR"
                );

                return Ok(Some((edns_data, rr_start, opt_len, is_sign)));
            }

            offset = rr_end;
        }

        // No OPT pseudo-RR found
        Ok(None)
    }

    // -----------------------------------------------------------------------
    // add_pseudoheader() — Add or replace EDNS0 OPT pseudo-RR
    // -----------------------------------------------------------------------

    /// Add or replace an EDNS0 OPT pseudo-RR with a specific option in a DNS packet.
    ///
    /// This is the core EDNS0 manipulation function. It handles three replace modes:
    /// - `NoReplace` (0): Only add the option if it doesn't already exist.
    /// - `ReplaceOrAdd` (1): Replace an existing option of the same code, or add if absent.
    /// - `ReplaceOnly` (2): Replace an existing option of the same code; do nothing if absent.
    ///
    /// If no OPT pseudo-RR exists and the mode allows addition, one is created with
    /// the daemon's configured EDNS0 UDP payload size. The packet buffer may be
    /// reallocated to accommodate the new data.
    ///
    /// # Arguments
    /// * `packet` — Mutable DNS packet buffer
    /// * `packet_len` — Current actual length of the DNS message within the buffer
    /// * `limit` — Maximum allowable packet size (buffer capacity)
    /// * `opt_code` — EDNS0 option code to add/replace
    /// * `opt_data` — Option data bytes
    /// * `set_do` — If true, set the DNSSEC OK (DO) bit
    /// * `replace` — Replacement mode
    /// * `edns_pktsz` — EDNS0 UDP payload size to advertise
    ///
    /// # Returns
    /// * `Ok(new_len)` — The new packet length after modification.
    /// * `Err(...)` — Packet malformed or buffer insufficient.
    ///
    /// Maps to C `add_pseudoheader()` (edns0.c lines 273-418).
    pub fn add_pseudoheader(
        packet: &mut BytesMut,
        packet_len: usize,
        limit: usize,
        opt_code: u16,
        opt_data: &[u8],
        set_do: bool,
        replace: ReplaceMode,
        edns_pktsz: u16,
    ) -> DnsmasqResult<usize> {
        let mut current_len = packet_len;

        // ReplaceOrAdd mode: strip ALL existing OPT pseudo-RRs via rrfilter
        // before adding a fresh one. Matches C: rrfilter(header, *plen, RRFILTER_EDNS0)
        if replace == ReplaceMode::ReplaceOrAdd {
            current_len = rrfilter(packet, current_len, RRFilterMode::Edns0)?;
            trace!(
                old_len = packet_len,
                new_len = current_len,
                "EDNS0: stripped existing OPT via rrfilter for replacement"
            );
        }

        // Locate existing OPT pseudo-RR (will be None after rrfilter strip)
        let existing = Self::find_pseudoheader(&packet[..current_len], current_len)?;

        if let Some((edns_data, opt_start, opt_len, is_sign)) = existing {
            // There's an existing OPT pseudo-RR (only reachable for NoReplace / ReplaceOnly).
            // If signed (TSIG/TKEY), we cannot safely modify — return unchanged.
            if is_sign {
                trace!("EDNS0: signed packet, skipping modification");
                return Ok(current_len);
            }

            // Check if the option already exists
            let has_option = edns_data.options.iter().any(|o| o.code == opt_code);

            match replace {
                ReplaceMode::NoReplace => {
                    if has_option {
                        // Option already present, nothing to do
                        trace!(code = opt_code, "EDNS0: option already present, no replace");
                        return Ok(current_len);
                    }
                    // Fall through to add the option to existing OPT RR
                }
                ReplaceMode::ReplaceOnly => {
                    if !has_option {
                        // Option not found and mode is replace-only
                        trace!(
                            code = opt_code,
                            "EDNS0: option not found, replace-only mode"
                        );
                        return Ok(current_len);
                    }
                    // Need to rebuild OPT with filtered options
                }
                ReplaceMode::ReplaceOrAdd => {
                    // Should not reach here after rrfilter strip, but handle gracefully
                }
            }

            // Build the new option list:
            // - If replacing, filter out the old option of the same code
            // - Append the new option data
            let mut new_options: Vec<EdnsOption> = Vec::new();
            for opt_entry in &edns_data.options {
                if opt_entry.code != opt_code {
                    new_options.push(opt_entry.clone());
                }
            }

            // Add the new option (if we have data)
            if !opt_data.is_empty() || opt_code != 0 {
                new_options.push(EdnsOption {
                    code: opt_code,
                    data: opt_data.to_vec(),
                });
            }

            // Calculate new OPT RR RDATA
            let mut new_rdata = Vec::new();
            for opt_entry in &new_options {
                // option code (2) + option length (2) + option data
                new_rdata.extend_from_slice(&opt_entry.code.to_be_bytes());
                new_rdata.extend_from_slice(&(opt_entry.data.len() as u16).to_be_bytes());
                new_rdata.extend_from_slice(&opt_entry.data);
            }

            // Build new OPT RR:
            // name(1: root) + type(2) + class/udp_size(2) + ttl/flags(4) + rdlength(2) + rdata
            let new_opt_len = 1 + 2 + 2 + 4 + 2 + new_rdata.len();

            // Calculate new flags TTL
            let mut ttl_flags: u32 = (edns_data.flags.extended_rcode as u32) << 24
                | (edns_data.flags.version as u32) << 16;
            if set_do || edns_data.flags.dnssec_ok {
                ttl_flags |= 0x8000;
            }

            let new_packet_len = current_len - opt_len + new_opt_len;
            if new_packet_len > limit {
                trace!("EDNS0: new packet would exceed limit");
                return Ok(current_len);
            }

            // Remove old OPT RR from packet
            let opt_end = opt_start + opt_len;
            let after_opt = packet[opt_end..current_len].to_vec();

            // Rebuild packet at opt_start
            packet.truncate(opt_start);

            // Write new OPT pseudo-RR
            packet.put_u8(0); // root name
            packet.put_u16(RRType::OPT.to_u16()); // type OPT
            packet.put_u16(edns_data.flags.udp_size); // class = UDP size
            packet.put_u32(ttl_flags); // TTL = extended RCODE + flags
            packet.put_u16(new_rdata.len() as u16); // RDLENGTH
            packet.extend_from_slice(&new_rdata); // RDATA

            // Append remainder of packet after old OPT
            packet.extend_from_slice(&after_opt);

            Ok(new_packet_len)
        } else {
            // No existing OPT pseudo-RR (or OPT was just stripped by rrfilter)
            if replace == ReplaceMode::ReplaceOnly {
                trace!("EDNS0: no existing OPT, replace-only mode — skipping");
                return Ok(current_len);
            }

            // Build new RDATA
            let mut new_rdata = Vec::new();
            if !opt_data.is_empty() || opt_code != 0 {
                new_rdata.extend_from_slice(&opt_code.to_be_bytes());
                new_rdata.extend_from_slice(&(opt_data.len() as u16).to_be_bytes());
                new_rdata.extend_from_slice(opt_data);
            }

            // New OPT RR: name(1) + type(2) + class(2) + ttl(4) + rdlength(2) + rdata
            let new_opt_len = 1 + 2 + 2 + 4 + 2 + new_rdata.len();
            let new_packet_len = current_len + new_opt_len;

            if new_packet_len > limit {
                trace!("EDNS0: cannot add OPT, would exceed limit");
                return Ok(current_len);
            }

            // Ensure buffer is large enough
            if packet.len() < current_len {
                packet.resize(current_len, 0);
            }

            let mut ttl_flags: u32 = 0;
            if set_do {
                ttl_flags |= 0x8000;
            }

            // Append OPT pseudo-RR at end of packet
            packet.truncate(current_len);
            packet.put_u8(0); // root name
            packet.put_u16(RRType::OPT.to_u16()); // type
            packet.put_u16(edns_pktsz); // class = UDP payload size
            packet.put_u32(ttl_flags); // TTL = extended flags
            packet.put_u16(new_rdata.len() as u16); // RDLENGTH
            packet.extend_from_slice(&new_rdata); // RDATA

            // Increment ARCOUNT in the DNS header
            if packet.len() >= HDRSIZE {
                let old_arcount = u16::from_be_bytes([packet[10], packet[11]]);
                let new_arcount = old_arcount + 1;
                packet[10] = (new_arcount >> 8) as u8;
                packet[11] = (new_arcount & 0xFF) as u8;
            }

            trace!(
                new_len = new_packet_len,
                opt_code = opt_code,
                "EDNS0: added new OPT pseudo-RR"
            );

            Ok(new_packet_len)
        }
    }

    // -----------------------------------------------------------------------
    // add_do_bit() — Set DNSSEC OK (DO) bit
    // -----------------------------------------------------------------------

    /// Set the DNSSEC OK (DO) bit in the EDNS0 OPT pseudo-RR.
    ///
    /// If no OPT pseudo-RR exists, one is created with the DO bit set.
    /// This is a convenience wrapper around `add_pseudoheader()`.
    ///
    /// # Arguments
    /// * `packet` — Mutable DNS packet buffer
    /// * `packet_len` — Current packet length
    /// * `limit` — Maximum packet size
    /// * `edns_pktsz` — EDNS0 UDP payload size
    ///
    /// # Returns
    /// * `Ok(new_len)` — The new packet length.
    ///
    /// Maps to C `add_do_bit()` (edns0.c lines 482-485).
    pub fn add_do_bit(
        packet: &mut BytesMut,
        packet_len: usize,
        limit: usize,
        edns_pktsz: u16,
    ) -> DnsmasqResult<usize> {
        // add_do_bit in C calls add_pseudoheader with optno=0, no data, set_do=1, replace=0
        Self::add_pseudoheader(
            packet,
            packet_len,
            limit,
            0,
            &[],
            true,
            ReplaceMode::NoReplace,
            edns_pktsz,
        )
    }

    // -----------------------------------------------------------------------
    // add_source_addr() — Add EDNS Client Subnet option (RFC 7871)
    // -----------------------------------------------------------------------

    /// Add EDNS Client Subnet (ECS) option per RFC 7871.
    ///
    /// Adds the client's source IP prefix as an ECS option for geographic DNS
    /// optimization. Supports both IPv4 and IPv6 addresses. If the daemon is
    /// configured with a static subnet via `add_subnet4`/`add_subnet6`, uses
    /// that; otherwise uses the actual client source address.
    ///
    /// Respects daemon option flags:
    /// - `OPT_CLIENT_SUBNET`: Enable ECS option addition
    /// - `OPT_STRIP_ECS`: Strip existing ECS from upstream-bound queries
    ///
    /// # Arguments
    /// * `packet` — Mutable DNS packet buffer
    /// * `packet_len` — Current packet length
    /// * `limit` — Maximum packet size
    /// * `source` — Client source socket address
    /// * `state` — Daemon configuration state
    ///
    /// # Returns
    /// * `Ok(new_len)` — Updated packet length.
    ///
    /// Maps to C `add_source_addr()` (edns0.c lines 993-1024).
    pub fn add_source_addr(
        packet: &mut BytesMut,
        packet_len: usize,
        limit: usize,
        source: &MySockAddr,
        state: &DaemonState,
    ) -> DnsmasqResult<usize> {
        if !state.options.is_set(opt::CLIENT_SUBNET) {
            return Ok(packet_len);
        }

        let source_addr = source.to_socket_addr();
        let ip = source_addr.ip();

        // Determine if we should strip existing ECS (passive mode detection)
        if state.options.is_set(opt::STRIP_ECS) {
            // Check if the client already sent an ECS option
            if let Some((edns_data, _, _, _)) =
                Self::find_pseudoheader(&packet[..packet_len], packet_len)?
            {
                let has_ecs = edns_data
                    .options
                    .iter()
                    .any(|o| o.code == edns0::OPTION_CLIENT_SUBNET);
                if has_ecs {
                    // Passively detected: client already sent ECS. Strip it.
                    debug!("EDNS0: stripping existing ECS from client query");
                    return Self::add_pseudoheader(
                        packet,
                        packet_len,
                        limit,
                        edns0::OPTION_CLIENT_SUBNET,
                        &[],
                        false,
                        ReplaceMode::ReplaceOnly,
                        state.edns_pktsz,
                    );
                }
            }
        }

        // Calculate the subnet option
        let subnet = Self::calc_subnet_opt(&ip, state);
        let opt_data = subnet.to_bytes();

        debug!(
            family = subnet.family,
            source_mask = subnet.source_netmask,
            "EDNS0: adding ECS option"
        );

        Self::add_pseudoheader(
            packet,
            packet_len,
            limit,
            edns0::OPTION_CLIENT_SUBNET,
            &opt_data,
            false,
            ReplaceMode::NoReplace,
            state.edns_pktsz,
        )
    }

    // -----------------------------------------------------------------------
    // add_mac() — Add MAC address option
    // -----------------------------------------------------------------------

    /// Add MAC address as a vendor-specific EDNS0 option (raw bytes).
    ///
    /// Resolves the client's MAC address from the ARP cache and adds it as
    /// `EDNS0_OPTION_MAC` with raw binary MAC bytes.
    ///
    /// Respects daemon option flags:
    /// - `OPT_ADD_MAC`: Enable MAC option addition
    /// - `OPT_STRIP_MAC`: Strip existing MAC options from client queries
    ///
    /// # Arguments
    /// * `packet` — Mutable DNS packet buffer
    /// * `packet_len` — Current packet length
    /// * `limit` — Maximum packet size
    /// * `source` — Client source socket address
    /// * `now` — Current timestamp for ARP cache freshness
    /// * `arp_cache` — ARP cache for MAC address resolution
    /// * `arp_enumerator` — Platform-specific ARP enumerator
    /// * `state` — Daemon configuration state
    ///
    /// # Returns
    /// * `Ok(new_len)` — Updated packet length.
    ///
    /// Maps to C `add_mac()` (edns0.c lines 762-781).
    pub fn add_mac(
        packet: &mut BytesMut,
        packet_len: usize,
        limit: usize,
        source: &MySockAddr,
        now: Instant,
        arp_cache: &mut ArpCache,
        arp_enumerator: &dyn crate::network::arp::ArpEnumerator,
        state: &DaemonState,
    ) -> DnsmasqResult<usize> {
        if !state.options.is_set(opt::ADD_MAC) {
            return Ok(packet_len);
        }

        // Determine replace mode from option flags
        let replace = if state.options.is_set(opt::STRIP_MAC) {
            ReplaceMode::ReplaceOrAdd
        } else {
            ReplaceMode::NoReplace
        };

        // Resolve MAC from ARP cache
        let source_ip = source.to_socket_addr().ip();
        let mac_result = arp_cache.find_mac(Some(&source_ip), false, now, arp_enumerator);

        if let Some((mac_bytes, hwlen)) = mac_result {
            // Clamp to DHCP_CHADDR_MAX (16 bytes), matching C: unsigned char mac[DHCP_CHADDR_MAX]
            let effective_len = hwlen.min(DHCP_CHADDR_MAX);
            let mac_data = &mac_bytes[..effective_len];
            debug!(
                mac = %format_mac(mac_data),
                "EDNS0: adding raw MAC option"
            );
            Self::add_pseudoheader(
                packet,
                packet_len,
                limit,
                edns0::OPTION_MAC,
                mac_data,
                false,
                replace,
                state.edns_pktsz,
            )
        } else {
            // MAC not found — if stripping, still try to remove existing option
            if replace == ReplaceMode::ReplaceOrAdd {
                Self::add_pseudoheader(
                    packet,
                    packet_len,
                    limit,
                    edns0::OPTION_MAC,
                    &[],
                    false,
                    ReplaceMode::ReplaceOnly,
                    state.edns_pktsz,
                )
            } else {
                Ok(packet_len)
            }
        }
    }

    // -----------------------------------------------------------------------
    // add_dns_client() — Add DNS client identification
    // -----------------------------------------------------------------------

    /// Add DNS client identification as EDNS0 NOMDEVICEID option.
    ///
    /// Encodes the client's MAC address using base64 or hex format and adds
    /// it as a device identification option. The format depends on configured
    /// option flags.
    ///
    /// Respects daemon option flags:
    /// - `OPT_MAC_B64`: Use base64 encoding for MAC address
    /// - `OPT_MAC_HEX`: Use hex encoding for MAC address
    /// - `OPT_STRIP_MAC`: Strip/replace existing identification
    ///
    /// # Arguments
    /// * `packet` — Mutable DNS packet buffer
    /// * `packet_len` — Current packet length
    /// * `limit` — Maximum packet size
    /// * `source` — Client source socket address
    /// * `now` — Current timestamp for ARP cache freshness
    /// * `arp_cache` — ARP cache for MAC address resolution
    /// * `arp_enumerator` — Platform-specific ARP enumerator
    /// * `state` — Daemon configuration state
    ///
    /// # Returns
    /// * `Ok(new_len)` — Updated packet length.
    ///
    /// Maps to C `add_dns_client()` (edns0.c lines 677-706).
    pub fn add_dns_client(
        packet: &mut BytesMut,
        packet_len: usize,
        limit: usize,
        source: &MySockAddr,
        now: Instant,
        arp_cache: &mut ArpCache,
        arp_enumerator: &dyn crate::network::arp::ArpEnumerator,
        state: &DaemonState,
    ) -> DnsmasqResult<usize> {
        // Need either base64 or hex MAC encoding enabled
        let use_b64 = state.options.is_set(opt::MAC_B64);
        let use_hex = state.options.is_set(opt::MAC_HEX);

        if !use_b64 && !use_hex {
            return Ok(packet_len);
        }

        // Determine replace mode
        let replace = if state.options.is_set(opt::STRIP_MAC) {
            ReplaceMode::ReplaceOrAdd
        } else {
            ReplaceMode::NoReplace
        };

        // Resolve MAC from ARP cache
        let source_ip = source.to_socket_addr().ip();
        let mac_result = arp_cache.find_mac(Some(&source_ip), false, now, arp_enumerator);

        if let Some((mac_bytes, hwlen)) = mac_result {
            let mac_data = &mac_bytes[..hwlen];

            let encoded: Vec<u8> = if use_b64 {
                // Base64 encode: 6-byte MAC → 8 character base64 string
                let b64_str = Self::base64_encode_mac(mac_data);
                debug!(
                    encoded = %b64_str,
                    "EDNS0: adding base64 MAC as NOMDEVICEID"
                );
                b64_str.into_bytes()
            } else {
                // Hex encode: colon-separated hex
                let hex_str = format_mac(mac_data);
                debug!(
                    encoded = %hex_str,
                    "EDNS0: adding hex MAC as NOMDEVICEID"
                );
                hex_str.into_bytes()
            };

            Self::add_pseudoheader(
                packet,
                packet_len,
                limit,
                edns0::OPTION_NOMDEVICEID,
                &encoded,
                false,
                replace,
                state.edns_pktsz,
            )
        } else {
            // MAC not found — if stripping, try to remove existing option
            if replace == ReplaceMode::ReplaceOrAdd {
                Self::add_pseudoheader(
                    packet,
                    packet_len,
                    limit,
                    edns0::OPTION_NOMDEVICEID,
                    &[],
                    false,
                    ReplaceMode::ReplaceOnly,
                    state.edns_pktsz,
                )
            } else {
                Ok(packet_len)
            }
        }
    }

    // -----------------------------------------------------------------------
    // add_umbrella_opt() — Cisco Umbrella vendor-specific option
    // -----------------------------------------------------------------------

    /// Add Cisco Umbrella device identification options.
    ///
    /// Constructs the "ODNS" magic header followed by TLV fields for:
    /// - Organization ID (u32)
    /// - IPv4 or IPv6 source address
    /// - Device ID (8 bytes)
    /// - Asset ID (u32)
    ///
    /// # Arguments
    /// * `packet` — Mutable DNS packet buffer
    /// * `packet_len` — Current packet length
    /// * `limit` — Maximum packet size
    /// * `source` — Client source socket address (for IP embedding)
    /// * `state` — Daemon configuration state
    ///
    /// # Returns
    /// * `Ok(new_len)` — Updated packet length.
    ///
    /// Maps to C `add_umbrella_opt()` (edns0.c lines 1215-1248).
    pub fn add_umbrella_opt(
        packet: &mut BytesMut,
        packet_len: usize,
        limit: usize,
        source: &MySockAddr,
        state: &DaemonState,
    ) -> DnsmasqResult<usize> {
        if !state.options.is_set(opt::UMBRELLA) {
            return Ok(packet_len);
        }

        let source_addr = source.to_socket_addr();
        let ip = source_addr.ip();

        // Build Umbrella option data: "ODNS" header + TLV fields
        let mut opt_buf: Vec<u8> = Vec::with_capacity(64);

        // Magic header: "ODNS" (4 bytes)
        opt_buf.extend_from_slice(UMBRELLA_MAGIC);
        // Version (1 byte)
        opt_buf.push(UMBRELLA_VERSION);

        // Calculate flags byte — indicates which TLV fields follow
        let mut flags: u8 = 0;

        // Determine which fields to include based on configuration
        let has_org = state.umbrella_org != 0;
        let has_device =
            state.options.is_set(opt::UMBRELLA_DEVID) && state.umbrella_device != [0u8; 8];
        let has_asset = state.umbrella_asset != 0;

        if has_org {
            flags |= (UMBRELLA_ORG >> 8) as u8;
        }
        match ip {
            IpAddr::V4(_) => flags |= (UMBRELLA_IPV4 >> 8) as u8,
            IpAddr::V6(_) => flags |= (UMBRELLA_IPV6 >> 8) as u8,
        }
        if has_device {
            flags |= (UMBRELLA_DEVICE >> 8) as u8;
        }
        if has_asset {
            flags |= (UMBRELLA_ASSET >> 8) as u8;
        }

        opt_buf.push(flags);

        // TLV fields (type is implicit via flags — just write data in order)

        // Organization ID (4 bytes, big-endian)
        if has_org {
            opt_buf.extend_from_slice(&state.umbrella_org.to_be_bytes());
        }

        // IP address
        match ip {
            IpAddr::V4(v4) => {
                opt_buf.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                opt_buf.extend_from_slice(&v6.octets());
            }
        }

        // Device ID (8 bytes)
        if has_device {
            opt_buf.extend_from_slice(&state.umbrella_device);
        }

        // Asset ID (4 bytes, big-endian)
        if has_asset {
            opt_buf.extend_from_slice(&state.umbrella_asset.to_be_bytes());
        }

        debug!(
            org = state.umbrella_org,
            asset = state.umbrella_asset,
            "EDNS0: adding Umbrella option"
        );

        Self::add_pseudoheader(
            packet,
            packet_len,
            limit,
            edns0::OPTION_UMBRELLA,
            &opt_buf,
            false,
            ReplaceMode::ReplaceOrAdd,
            state.edns_pktsz,
        )
    }

    // -----------------------------------------------------------------------
    // add_edns0_config() — Master orchestrator
    // -----------------------------------------------------------------------

    /// Master EDNS0 configuration orchestrator.
    ///
    /// Called before sending a query to upstream servers to add all configured
    /// EDNS0 options. Coordinates the addition of:
    /// 1. MAC address option (raw bytes)
    /// 2. DNS client identification (base64/hex MAC)
    /// 3. NOMCPEID option (dns_client_id string)
    /// 4. Cisco Umbrella option
    /// 5. EDNS Client Subnet option
    ///
    /// # Arguments
    /// * `packet` — Mutable DNS packet buffer
    /// * `packet_len` — Current packet length
    /// * `limit` — Maximum packet size
    /// * `source` — Client source socket address
    /// * `now` — Current timestamp for ARP cache freshness
    /// * `arp_cache` — ARP cache for MAC address resolution
    /// * `arp_enumerator` — Platform-specific ARP enumerator
    /// * `state` — Daemon configuration state
    ///
    /// # Returns
    /// * `Ok(new_len)` — Final packet length after all options are added.
    ///
    /// Maps to C `add_edns0_config()` (edns0.c lines 1322-1340).
    pub fn add_edns0_config(
        packet: &mut BytesMut,
        packet_len: usize,
        limit: usize,
        source: &MySockAddr,
        now: Instant,
        arp_cache: &mut ArpCache,
        arp_enumerator: &dyn crate::network::arp::ArpEnumerator,
        state: &DaemonState,
    ) -> DnsmasqResult<usize> {
        let mut len = packet_len;

        // 1. Add raw MAC address option
        len = Self::add_mac(
            packet,
            len,
            limit,
            source,
            now,
            arp_cache,
            arp_enumerator,
            state,
        )?;

        // 2. Add DNS client identification (base64/hex MAC)
        len = Self::add_dns_client(
            packet,
            len,
            limit,
            source,
            now,
            arp_cache,
            arp_enumerator,
            state,
        )?;

        // 3. Add NOMCPEID option (dns_client_id string)
        if let Some(ref client_id) = state.dns_client_id {
            let id_bytes = client_id.as_bytes();
            debug!(
                client_id = %client_id,
                "EDNS0: adding NOMCPEID option"
            );
            len = Self::add_pseudoheader(
                packet,
                len,
                limit,
                edns0::OPTION_NOMCPEID,
                id_bytes,
                false,
                ReplaceMode::ReplaceOrAdd,
                state.edns_pktsz,
            )?;
        }

        // 4. Add Cisco Umbrella option
        len = Self::add_umbrella_opt(packet, len, limit, source, state)?;

        // 5. Add EDNS Client Subnet option
        len = Self::add_source_addr(packet, len, limit, source, state)?;

        Ok(len)
    }

    // -----------------------------------------------------------------------
    // check_source() — RFC 7871 response validation
    // -----------------------------------------------------------------------

    /// Validate EDNS Client Subnet (ECS) option in a DNS response per RFC 7871 Section 9.2.
    ///
    /// Two validation modes:
    /// - **Full validation** (`peer` is `Some`): Verifies the response ECS matches
    ///   what was sent to the upstream server (address family, source prefix length,
    ///   and address bytes must match).
    /// - **Existence check** (`peer` is `None`): Simply checks whether an ECS option
    ///   exists in the response (used for passive detection).
    ///
    /// # Arguments
    /// * `packet` — DNS response packet bytes
    /// * `packet_len` — Actual packet length
    /// * `peer` — Optional upstream server address for full validation
    /// * `source_addr` — Original client source address
    /// * `state` — Daemon configuration state
    ///
    /// # Returns
    /// * `Ok(true)` — ECS validation passed or ECS option found.
    /// * `Ok(false)` — ECS validation failed or ECS option not found.
    /// * `Err(...)` — Packet malformed.
    ///
    /// Maps to C `check_source()` (edns0.c lines 1080-1123).
    pub fn check_source(
        packet: &[u8],
        packet_len: usize,
        peer: Option<&MySockAddr>,
        source_addr: &MySockAddr,
        state: &DaemonState,
    ) -> DnsmasqResult<bool> {
        // Find OPT pseudo-RR
        let existing = Self::find_pseudoheader(packet, packet_len)?;

        let edns_data = match existing {
            Some((data, _, _, _)) => data,
            None => return Ok(false),
        };

        // Find ECS option
        let ecs_opt = edns_data
            .options
            .iter()
            .find(|o| o.code == edns0::OPTION_CLIENT_SUBNET);

        let ecs_opt = match ecs_opt {
            Some(opt) => opt,
            None => return Ok(false),
        };

        // Existence check mode — just confirm the option exists
        if peer.is_none() {
            return Ok(true);
        }

        // Full validation mode: parse and compare
        let response_subnet = SubnetOpt::from_bytes(&ecs_opt.data)?;

        // Calculate what we originally sent
        let source_ip = source_addr.to_socket_addr().ip();
        let expected = Self::calc_subnet_opt(&source_ip, state);

        // Validate: address family, source prefix length must match
        if response_subnet.family != expected.family {
            trace!(
                expected_family = expected.family,
                got_family = response_subnet.family,
                "ECS check: family mismatch"
            );
            return Ok(false);
        }

        if response_subnet.source_netmask != expected.source_netmask {
            trace!(
                expected_mask = expected.source_netmask,
                got_mask = response_subnet.source_netmask,
                "ECS check: source netmask mismatch"
            );
            return Ok(false);
        }

        // Compare address bytes (only significant bytes based on source_netmask)
        let addr_bytes = (expected.source_netmask as usize).div_ceil(8);
        let expected_addr = &expected.addr[..addr_bytes.min(expected.addr.len())];
        let got_addr = &response_subnet.addr[..addr_bytes.min(response_subnet.addr.len())];

        if expected_addr != got_addr {
            trace!("ECS check: address bytes mismatch");
            return Ok(false);
        }

        Ok(true)
    }

    // -----------------------------------------------------------------------
    // Private helper: parse EDNS0 options from RDATA
    // -----------------------------------------------------------------------

    /// Parse EDNS0 options from OPT pseudo-RR RDATA bytes.
    ///
    /// Each option is encoded as: code(2) + length(2) + data(length).
    fn parse_options(rdata: &[u8]) -> DnsmasqResult<Vec<EdnsOption>> {
        let mut options = Vec::new();
        let mut pos = 0;

        while pos + 4 <= rdata.len() {
            let code = u16::from_be_bytes([rdata[pos], rdata[pos + 1]]);
            let length = u16::from_be_bytes([rdata[pos + 2], rdata[pos + 3]]) as usize;
            pos += 4;

            if pos + length > rdata.len() {
                return Err(DnsmasqError::DnsProtocol(
                    "EDNS0 option data truncated".into(),
                ));
            }

            options.push(EdnsOption {
                code,
                data: rdata[pos..pos + length].to_vec(),
            });
            pos += length;
        }

        Ok(options)
    }

    // -----------------------------------------------------------------------
    // Private helper: calculate RFC 7871 Client Subnet option
    // -----------------------------------------------------------------------

    /// Calculate RFC 7871 EDNS Client Subnet option from an IP address.
    ///
    /// Uses the daemon's configured subnet masks (`add_subnet4`/`add_subnet6`) if
    /// available, otherwise derives from the actual source address. Applies netmask
    /// bit masking to the address bytes for privacy.
    ///
    /// Maps to C `calc_subnet_opt()` (edns0.c lines 878-935).
    fn calc_subnet_opt(ip: &IpAddr, state: &DaemonState) -> SubnetOpt {
        match ip {
            IpAddr::V4(v4) => {
                // Check for configured subnet override
                if let Some(ref subnet) = state.add_subnet4 {
                    if let IpAddr::V4(cfg_addr) = subnet.addr {
                        let mask = subnet.mask;
                        let mut addr_bytes = cfg_addr.octets().to_vec();
                        Self::mask_address_bytes(&mut addr_bytes, mask);
                        return SubnetOpt {
                            family: 1,
                            source_netmask: mask,
                            scope_netmask: 0,
                            addr: addr_bytes,
                        };
                    }
                    // configured subnet is v6 but client is v4 — use dynamic
                }

                // Use actual source address with full /32 mask
                // (dnsmasq default when --add-subnet is used without explicit prefix)
                let mask = 32u8;
                let mut addr_bytes = v4.octets().to_vec();
                Self::mask_address_bytes(&mut addr_bytes, mask);
                SubnetOpt {
                    family: 1,
                    source_netmask: mask,
                    scope_netmask: 0,
                    addr: addr_bytes,
                }
            }
            IpAddr::V6(v6) => {
                // Check for configured subnet override
                if let Some(ref subnet) = state.add_subnet6 {
                    if let IpAddr::V6(cfg_addr) = subnet.addr {
                        let mask = subnet.mask;
                        let mut addr_bytes = cfg_addr.octets().to_vec();
                        Self::mask_address_bytes(&mut addr_bytes, mask);
                        return SubnetOpt {
                            family: 2,
                            source_netmask: mask,
                            scope_netmask: 0,
                            addr: addr_bytes,
                        };
                    }
                    // configured subnet is v4 but client is v6 — use dynamic
                }

                // Use actual source address with full /128 mask
                let mask = 128u8;
                let mut addr_bytes = v6.octets().to_vec();
                Self::mask_address_bytes(&mut addr_bytes, mask);
                SubnetOpt {
                    family: 2,
                    source_netmask: mask,
                    scope_netmask: 0,
                    addr: addr_bytes,
                }
            }
        }
    }

    /// Mask address bytes to the specified prefix length.
    ///
    /// Clears all bits beyond the prefix length for privacy. The last partial
    /// byte gets its trailing bits zeroed. This matches C's bit masking logic
    /// in `calc_subnet_opt()`.
    fn mask_address_bytes(addr: &mut [u8], prefix_len: u8) {
        let full_bytes = (prefix_len as usize) / 8;
        let remaining_bits = (prefix_len as usize) % 8;

        // Zero out bytes beyond the prefix
        for byte in addr
            .iter_mut()
            .skip(full_bytes + if remaining_bits > 0 { 1 } else { 0 })
        {
            *byte = 0;
        }

        // Mask the partial byte
        if remaining_bits > 0 && full_bytes < addr.len() {
            let mask = 0xFF_u8 << (8 - remaining_bits);
            addr[full_bytes] &= mask;
        }
    }

    // -----------------------------------------------------------------------
    // Private helper: base64 encode MAC address
    // -----------------------------------------------------------------------

    /// Base64 encode a MAC address (typically 6 bytes → 8 chars).
    ///
    /// Uses the standard base64 alphabet (A-Z, a-z, 0-9, +, /) with '=' padding.
    /// Reimplements C's `char64()` and `encoder()` from edns0.c lines 549-619.
    fn base64_encode_mac(mac: &[u8]) -> String {
        const B64_CHARS: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        let mut result = String::with_capacity(mac.len().div_ceil(3) * 4);
        let chunks = mac.chunks(3);

        for chunk in chunks {
            let b0 = chunk[0] as u32;
            let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
            let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };

            let triple = (b0 << 16) | (b1 << 8) | b2;

            result.push(B64_CHARS[((triple >> 18) & 0x3F) as usize] as char);
            result.push(B64_CHARS[((triple >> 12) & 0x3F) as usize] as char);

            if chunk.len() > 1 {
                result.push(B64_CHARS[((triple >> 6) & 0x3F) as usize] as char);
            } else {
                result.push('=');
            }

            if chunk.len() > 2 {
                result.push(B64_CHARS[(triple & 0x3F) as usize] as char);
            } else {
                result.push('=');
            }
        }

        result
    }
}

// ===========================================================================
// Wire Format Helpers (packet navigation)
// ===========================================================================

/// Skip over a compressed DNS name in wire format.
///
/// Returns the byte offset immediately after the name. Handles compression
/// pointers, labels, and the root terminator.
fn skip_name_wire(packet: &[u8], packet_len: usize, offset: usize) -> DnsmasqResult<usize> {
    let mut pos = offset;
    let mut jumps = 0;
    let max_jumps = 256; // prevent infinite loops from malformed packets

    loop {
        if pos >= packet_len {
            return Err(DnsmasqError::DnsProtocol(
                "skip_name_wire: offset beyond packet".into(),
            ));
        }

        let label_len = packet[pos] as usize;

        if label_len == 0 {
            // Root terminator
            return Ok(pos + 1);
        }

        if (label_len & 0xC0) == 0xC0 {
            // Compression pointer — 2 bytes
            if pos + 1 >= packet_len {
                return Err(DnsmasqError::DnsProtocol(
                    "skip_name_wire: truncated compression pointer".into(),
                ));
            }
            // The name ends here (pointer is 2 bytes), rest of name is elsewhere
            return Ok(pos + 2);
        }

        if (label_len & 0xC0) != 0 {
            // Reserved label type
            return Err(DnsmasqError::DnsProtocol(
                "skip_name_wire: reserved label type".into(),
            ));
        }

        // Standard label
        pos += 1 + label_len;
        jumps += 1;
        if jumps > max_jumps {
            return Err(DnsmasqError::DnsProtocol(
                "skip_name_wire: too many labels".into(),
            ));
        }
    }
}

/// Skip over a complete resource record in wire format.
///
/// Skips the name, then the fixed fields (type, class, TTL, rdlength), and
/// then the RDATA of the specified length.
fn skip_rr_wire(packet: &[u8], packet_len: usize, offset: usize) -> DnsmasqResult<usize> {
    let name_end = skip_name_wire(packet, packet_len, offset)?;

    // Need at least RRFIXEDSZ (10) bytes after the name for type+class+ttl+rdlength
    if name_end + RRFIXEDSZ > packet_len {
        return Err(DnsmasqError::DnsProtocol(
            "skip_rr_wire: RR fixed fields truncated".into(),
        ));
    }

    let rdlength = get_u16(packet, name_end + 8)? as usize;
    let rr_end = name_end + RRFIXEDSZ + rdlength;

    if rr_end > packet_len {
        return Err(DnsmasqError::DnsProtocol(
            "skip_rr_wire: RR RDATA overflows packet".into(),
        ));
    }

    Ok(rr_end)
}

// ===========================================================================
// Unit Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// Build a minimal DNS query packet with a question section.
    fn build_test_query() -> (BytesMut, usize) {
        let mut packet = BytesMut::with_capacity(512);

        // DNS header: ID=0x1234, RD=1, QDCOUNT=1
        packet.put_u16(0x1234); // ID
        packet.put_u8(0x01); // hb3: RD=1
        packet.put_u8(0x00); // hb4
        packet.put_u16(1); // QDCOUNT
        packet.put_u16(0); // ANCOUNT
        packet.put_u16(0); // NSCOUNT
        packet.put_u16(0); // ARCOUNT

        // Question: example.com, A, IN
        // "example" label (7 chars)
        packet.put_u8(7);
        packet.extend_from_slice(b"example");
        // "com" label (3 chars)
        packet.put_u8(3);
        packet.extend_from_slice(b"com");
        // Root terminator
        packet.put_u8(0);
        // QTYPE = A (1)
        packet.put_u16(1);
        // QCLASS = IN (1)
        packet.put_u16(1);

        let len = packet.len();
        (packet, len)
    }

    /// Build a DNS query packet with an existing OPT pseudo-RR.
    fn build_query_with_opt(udp_size: u16, do_bit: bool) -> (BytesMut, usize) {
        let (mut packet, _base_len) = build_test_query();

        // Add OPT pseudo-RR manually
        packet.put_u8(0); // root name
        packet.put_u16(RRType::OPT.to_u16()); // type OPT (41)
        packet.put_u16(udp_size); // class = UDP payload size
        let mut ttl: u32 = 0;
        if do_bit {
            ttl |= 0x8000;
        }
        packet.put_u32(ttl); // TTL = flags
        packet.put_u16(0); // RDLENGTH = 0 (no options yet)

        // Increment ARCOUNT
        packet[10] = 0;
        packet[11] = 1;

        let final_len = packet.len();
        (packet, final_len)
    }

    #[test]
    fn test_option_codes_values() {
        assert_eq!(option_codes::EDNS0_OPTION_MAC, 65001);
        assert_eq!(option_codes::EDNS0_OPTION_CLIENT_SUBNET, 8);
        assert_eq!(option_codes::EDNS0_OPTION_NOMDEVICEID, 65073);
        assert_eq!(option_codes::EDNS0_OPTION_NOMCPEID, 65074);
        assert_eq!(option_codes::EDNS0_OPTION_EDE, 15);
        assert_eq!(option_codes::EDNS0_OPTION_COOKIE, 10);
        assert_eq!(option_codes::EDNS0_OPTION_PADDING, 12);
        assert_eq!(option_codes::EDNS0_OPTION_UMBRELLA, 20292);
    }

    #[test]
    fn test_ede_codes_values() {
        assert_eq!(ede_codes::EDE_UNSET, -1);
        assert_eq!(ede_codes::EDE_OTHER, 0);
        assert_eq!(ede_codes::EDE_UNSUPPORTED_DNSKEY, 1);
        assert_eq!(ede_codes::EDE_UNSUPPORTED_DS, 2);
        assert_eq!(ede_codes::EDE_STALE_ANSWER, 3);
        assert_eq!(ede_codes::EDE_FORGED_ANSWER, 4);
        assert_eq!(ede_codes::EDE_DNSSEC_INDETERMINATE, 5);
        assert_eq!(ede_codes::EDE_DNSSEC_BOGUS, 6);
        assert_eq!(ede_codes::EDE_SIG_EXPIRED, 7);
        assert_eq!(ede_codes::EDE_SIG_NOT_YET_VALID, 8);
        assert_eq!(ede_codes::EDE_DNSKEY_MISSING, 9);
        assert_eq!(ede_codes::EDE_RRSIG_MISSING, 10);
        assert_eq!(ede_codes::EDE_NO_ZONE_KEY_BIT, 11);
        assert_eq!(ede_codes::EDE_NSEC_MISSING, 12);
        assert_eq!(ede_codes::EDE_CACHED_ERROR, 13);
        assert_eq!(ede_codes::EDE_NOT_READY, 14);
        assert_eq!(ede_codes::EDE_BLOCKED, 15);
        assert_eq!(ede_codes::EDE_CENSORED, 16);
        assert_eq!(ede_codes::EDE_FILTERED, 17);
        assert_eq!(ede_codes::EDE_PROHIBITED, 18);
        assert_eq!(ede_codes::EDE_STALE_NXDOMAIN, 19);
        assert_eq!(ede_codes::EDE_NOT_AUTHORITATIVE, 20);
        assert_eq!(ede_codes::EDE_NOT_SUPPORTED, 21);
        assert_eq!(ede_codes::EDE_NO_AUTHORITY, 22);
        assert_eq!(ede_codes::EDE_NETWORK_ERROR, 23);
        assert_eq!(ede_codes::EDE_INVALID_DATA, 24);
        assert_eq!(ede_codes::EDE_SIG_EXPIRED_BEFORE_VALID, 25);
        assert_eq!(ede_codes::EDE_TOO_EARLY, 26);
        assert_eq!(ede_codes::EDE_UNSUPPORTED_NS3_ITERATIONS, 27);
        assert_eq!(ede_codes::EDE_UNABLE_POLICY, 28);
        assert_eq!(ede_codes::EDE_SYNTHESIZED, 29);
    }

    #[test]
    fn test_edns_flags_default() {
        let flags = EdnsFlags::default();
        assert!(!flags.dnssec_ok);
        assert_eq!(flags.udp_size, PACKETSZ as u16);
        assert_eq!(flags.extended_rcode, 0);
        assert_eq!(flags.version, 0);
    }

    #[test]
    fn test_find_pseudoheader_no_opt() {
        let (packet, len) = build_test_query();
        let result = EdnsHandler::find_pseudoheader(&packet[..len], len).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_find_pseudoheader_with_opt() {
        let (packet, len) = build_query_with_opt(4096, true);
        let result = EdnsHandler::find_pseudoheader(&packet[..len], len).unwrap();
        assert!(result.is_some());

        let (edns_data, opt_start, _opt_len, is_sign) = result.unwrap();
        assert_eq!(edns_data.flags.udp_size, 4096);
        assert!(edns_data.flags.dnssec_ok);
        assert_eq!(edns_data.options.len(), 0);
        assert!(!is_sign);
        // OPT should start after the question section
        assert!(opt_start > HDRSIZE);
    }

    #[test]
    fn test_find_pseudoheader_with_do_bit_false() {
        let (packet, len) = build_query_with_opt(1232, false);
        let result = EdnsHandler::find_pseudoheader(&packet[..len], len).unwrap();
        let (edns_data, _, _, _) = result.unwrap();
        assert!(!edns_data.flags.dnssec_ok);
        assert_eq!(edns_data.flags.udp_size, 1232);
    }

    #[test]
    fn test_add_pseudoheader_creates_opt() {
        let (mut packet, len) = build_test_query();
        let new_len = EdnsHandler::add_pseudoheader(
            &mut packet,
            len,
            512,
            0,
            &[],
            false,
            ReplaceMode::NoReplace,
            1232,
        )
        .unwrap();

        // Should be larger than before (OPT RR added)
        assert!(new_len > len);

        // ARCOUNT should be 1
        assert_eq!(u16::from_be_bytes([packet[10], packet[11]]), 1);

        // Should be findable now
        let result = EdnsHandler::find_pseudoheader(&packet[..new_len], new_len).unwrap();
        assert!(result.is_some());
        let (edns_data, _, _, _) = result.unwrap();
        assert_eq!(edns_data.flags.udp_size, 1232);
        assert!(!edns_data.flags.dnssec_ok);
    }

    #[test]
    fn test_add_do_bit() {
        let (mut packet, len) = build_test_query();
        let new_len = EdnsHandler::add_do_bit(&mut packet, len, 512, 1232).unwrap();

        let result = EdnsHandler::find_pseudoheader(&packet[..new_len], new_len).unwrap();
        assert!(result.is_some());
        let (edns_data, _, _, _) = result.unwrap();
        assert!(edns_data.flags.dnssec_ok);
    }

    #[test]
    fn test_add_pseudoheader_with_option_data() {
        let (mut packet, len) = build_test_query();
        let test_data = vec![0x01, 0x02, 0x03, 0x04];
        let new_len = EdnsHandler::add_pseudoheader(
            &mut packet,
            len,
            512,
            option_codes::EDNS0_OPTION_MAC,
            &test_data,
            false,
            ReplaceMode::NoReplace,
            1232,
        )
        .unwrap();

        let result = EdnsHandler::find_pseudoheader(&packet[..new_len], new_len).unwrap();
        assert!(result.is_some());
        let (edns_data, _, _, _) = result.unwrap();
        assert_eq!(edns_data.options.len(), 1);
        assert_eq!(edns_data.options[0].code, option_codes::EDNS0_OPTION_MAC);
        assert_eq!(edns_data.options[0].data, test_data);
    }

    #[test]
    fn test_add_pseudoheader_no_replace_existing() {
        let (mut packet, len) = build_test_query();
        let test_data = vec![0x01, 0x02, 0x03];

        // Add initial option
        let len1 = EdnsHandler::add_pseudoheader(
            &mut packet,
            len,
            512,
            option_codes::EDNS0_OPTION_MAC,
            &test_data,
            false,
            ReplaceMode::NoReplace,
            1232,
        )
        .unwrap();

        // Try to add same option again with NoReplace
        let new_data = vec![0xFF, 0xFE];
        let len2 = EdnsHandler::add_pseudoheader(
            &mut packet,
            len1,
            512,
            option_codes::EDNS0_OPTION_MAC,
            &new_data,
            false,
            ReplaceMode::NoReplace,
            1232,
        )
        .unwrap();

        // Length should be unchanged (option not replaced)
        assert_eq!(len1, len2);

        // Original data should still be present
        let result = EdnsHandler::find_pseudoheader(&packet[..len2], len2).unwrap();
        let (edns_data, _, _, _) = result.unwrap();
        assert_eq!(edns_data.options[0].data, test_data);
    }

    #[test]
    fn test_add_pseudoheader_replace_or_add() {
        let (mut packet, len) = build_test_query();
        let test_data = vec![0x01, 0x02, 0x03];

        // Add initial option
        let len1 = EdnsHandler::add_pseudoheader(
            &mut packet,
            len,
            512,
            option_codes::EDNS0_OPTION_MAC,
            &test_data,
            false,
            ReplaceMode::NoReplace,
            1232,
        )
        .unwrap();

        // Replace with new data
        let new_data = vec![0xFF, 0xFE, 0xFD];
        let len2 = EdnsHandler::add_pseudoheader(
            &mut packet,
            len1,
            512,
            option_codes::EDNS0_OPTION_MAC,
            &new_data,
            false,
            ReplaceMode::ReplaceOrAdd,
            1232,
        )
        .unwrap();

        // New data should be present
        let result = EdnsHandler::find_pseudoheader(&packet[..len2], len2).unwrap();
        let (edns_data, _, _, _) = result.unwrap();
        assert_eq!(edns_data.options.len(), 1);
        assert_eq!(edns_data.options[0].data, new_data);
    }

    #[test]
    fn test_add_pseudoheader_replace_only_missing() {
        let (mut packet, len) = build_test_query();
        let test_data = vec![0x01, 0x02, 0x03];

        // Create OPT with no options
        let len1 = EdnsHandler::add_pseudoheader(
            &mut packet,
            len,
            512,
            0,
            &[],
            false,
            ReplaceMode::NoReplace,
            1232,
        )
        .unwrap();

        // Try replace-only for option that doesn't exist
        let len2 = EdnsHandler::add_pseudoheader(
            &mut packet,
            len1,
            512,
            option_codes::EDNS0_OPTION_MAC,
            &test_data,
            false,
            ReplaceMode::ReplaceOnly,
            1232,
        )
        .unwrap();

        // Length should be unchanged (nothing to replace)
        assert_eq!(len1, len2);
    }

    #[test]
    fn test_base64_encode_mac() {
        // Standard 6-byte MAC address
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let encoded = EdnsHandler::base64_encode_mac(&mac);
        // 6 bytes → 8 base64 chars, no padding needed since 6 is divisible by 3
        assert_eq!(encoded.len(), 8);

        // Verify round-trip: manually decode and compare
        // 0x00=0, 0x11=17, 0x22=34 → triple = (0<<16)|(17<<8)|34 = 0x001122
        // 0x001122 = 4386
        // Index 0: (4386 >> 18) & 0x3F = 0 → 'A'
        // Index 1: (4386 >> 12) & 0x3F = 1 → 'B'
        // Index 2: (4386 >> 6) & 0x3F = 4 → 'E'
        // Index 3: 4386 & 0x3F = 34 → 'i'
        assert!(encoded.starts_with("ABEi"));
    }

    #[test]
    fn test_mask_address_bytes() {
        // Test /24 mask on IPv4
        let mut addr = vec![192, 168, 1, 100];
        EdnsHandler::mask_address_bytes(&mut addr, 24);
        assert_eq!(addr, vec![192, 168, 1, 0]);

        // Test /16 mask on IPv4
        let mut addr = vec![10, 20, 30, 40];
        EdnsHandler::mask_address_bytes(&mut addr, 16);
        assert_eq!(addr, vec![10, 20, 0, 0]);

        // Test /20 mask (partial byte)
        let mut addr = vec![172, 16, 255, 200];
        EdnsHandler::mask_address_bytes(&mut addr, 20);
        assert_eq!(addr, vec![172, 16, 0xF0, 0]);

        // Test /0 mask (all zeroed)
        let mut addr = vec![1, 2, 3, 4];
        EdnsHandler::mask_address_bytes(&mut addr, 0);
        assert_eq!(addr, vec![0, 0, 0, 0]);

        // Test /32 mask (no masking)
        let mut addr = vec![10, 20, 30, 40];
        EdnsHandler::mask_address_bytes(&mut addr, 32);
        assert_eq!(addr, vec![10, 20, 30, 40]);
    }

    #[test]
    fn test_subnet_opt_roundtrip() {
        let original = SubnetOpt {
            family: 1,
            source_netmask: 24,
            scope_netmask: 0,
            addr: vec![192, 168, 1],
        };
        let bytes = original.to_bytes();
        let parsed = SubnetOpt::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.family, 1);
        assert_eq!(parsed.source_netmask, 24);
        assert_eq!(parsed.scope_netmask, 0);
        assert_eq!(parsed.addr, vec![192, 168, 1]);
    }

    #[test]
    fn test_subnet_opt_ipv6_roundtrip() {
        let original = SubnetOpt {
            family: 2,
            source_netmask: 48,
            scope_netmask: 0,
            addr: vec![0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01],
        };
        let bytes = original.to_bytes();
        let parsed = SubnetOpt::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.family, 2);
        assert_eq!(parsed.source_netmask, 48);
        assert_eq!(parsed.addr, vec![0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01]);
    }

    #[test]
    fn test_skip_name_wire_simple() {
        // "example.com\0" = [7, 'e','x','a','m','p','l','e', 3, 'c','o','m', 0]
        let mut packet = Vec::new();
        // Header (12 bytes of zeros)
        packet.extend_from_slice(&[0u8; 12]);
        // Name
        packet.push(7);
        packet.extend_from_slice(b"example");
        packet.push(3);
        packet.extend_from_slice(b"com");
        packet.push(0);

        let result = skip_name_wire(&packet, packet.len(), 12).unwrap();
        assert_eq!(result, 12 + 13); // 7+1 + 3+1 + 1 = 13 bytes for name
    }

    #[test]
    fn test_skip_name_wire_compressed() {
        // Compression pointer: 0xC0 0x0C (points to offset 12)
        let mut packet = Vec::new();
        packet.extend_from_slice(&[0u8; 12]); // header
                                              // First name at offset 12
        packet.push(3);
        packet.extend_from_slice(b"com");
        packet.push(0);
        // Compression pointer at offset 17
        packet.push(0xC0);
        packet.push(0x0C);

        let result = skip_name_wire(&packet, packet.len(), 17).unwrap();
        assert_eq!(result, 19); // 2 bytes for compression pointer
    }

    #[test]
    fn test_find_pseudoheader_short_packet() {
        let packet = [0u8; 6]; // too short
        let result = EdnsHandler::find_pseudoheader(&packet, 6);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_options_empty() {
        let options = EdnsHandler::parse_options(&[]).unwrap();
        assert!(options.is_empty());
    }

    #[test]
    fn test_parse_options_single() {
        // code=8 (ECS), length=7, data=[0,1,24,0,192,168,1]
        let data: Vec<u8> = vec![
            0x00, 0x08, // code = 8
            0x00, 0x07, // length = 7
            0x00, 0x01, // family = 1 (IPv4)
            24,   // source mask
            0,    // scope mask
            192, 168, 1, // address bytes
        ];
        let options = EdnsHandler::parse_options(&data).unwrap();
        assert_eq!(options.len(), 1);
        assert_eq!(options[0].code, 8);
        assert_eq!(options[0].data.len(), 7);
    }

    #[test]
    fn test_parse_options_multiple() {
        let mut data = Vec::new();
        // Option 1: code=10 (cookie), length=8, data=8 bytes
        data.extend_from_slice(&[0x00, 0x0A, 0x00, 0x08]);
        data.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        // Option 2: code=12 (padding), length=4, data=4 zero bytes
        data.extend_from_slice(&[0x00, 0x0C, 0x00, 0x04]);
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        let options = EdnsHandler::parse_options(&data).unwrap();
        assert_eq!(options.len(), 2);
        assert_eq!(options[0].code, 10);
        assert_eq!(options[0].data.len(), 8);
        assert_eq!(options[1].code, 12);
        assert_eq!(options[1].data.len(), 4);
    }

    #[test]
    fn test_edns_data_structure() {
        let data = EdnsData {
            flags: EdnsFlags {
                dnssec_ok: true,
                udp_size: 4096,
                extended_rcode: 0,
                version: 0,
            },
            options: vec![EdnsOption {
                code: option_codes::EDNS0_OPTION_COOKIE,
                data: vec![1, 2, 3, 4, 5, 6, 7, 8],
            }],
        };
        assert!(data.flags.dnssec_ok);
        assert_eq!(data.flags.udp_size, 4096);
        assert_eq!(data.options.len(), 1);
        assert_eq!(data.options[0].code, option_codes::EDNS0_OPTION_COOKIE);
    }

    #[test]
    fn test_umbrella_constants() {
        assert_eq!(UMBRELLA_VERSION, 1);
        assert_eq!(UMBRELLA_ORG, 0x0008);
        assert_eq!(UMBRELLA_IPV4, 0x0010);
        assert_eq!(UMBRELLA_IPV6, 0x0020);
        assert_eq!(UMBRELLA_DEVICE, 0x0040);
        assert_eq!(UMBRELLA_ASSET, 0x0004);
        assert_eq!(UMBRELLA_MAGIC, b"ODNS");
    }

    #[test]
    fn test_calc_subnet_opt_ipv4_default() {
        let state = DaemonState::new();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let subnet = EdnsHandler::calc_subnet_opt(&ip, &state);
        assert_eq!(subnet.family, 1);
        assert_eq!(subnet.source_netmask, 32);
        assert_eq!(subnet.scope_netmask, 0);
        assert_eq!(subnet.addr, vec![192, 168, 1, 100]);
    }

    #[test]
    fn test_calc_subnet_opt_ipv6_default() {
        let state = DaemonState::new();
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let subnet = EdnsHandler::calc_subnet_opt(&ip, &state);
        assert_eq!(subnet.family, 2);
        assert_eq!(subnet.source_netmask, 128);
        assert_eq!(subnet.scope_netmask, 0);
        assert_eq!(subnet.addr.len(), 16);
    }
}

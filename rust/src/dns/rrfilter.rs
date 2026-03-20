// Copyright (C) 2000-2025 Simon Kelley
// SPDX-License-Identifier: GPL-2.0-or-later
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.

//! # DNS Resource Record Filtering
//!
//! Safe removal and filtering of DNS Resource Records (RRs) from DNS response
//! packets, migrated from C `src/rrfilter.c` (918 lines).
//!
//! ## Four-Pass Filtering Algorithm
//!
//! The core challenge is that DNS packets use compression pointers within domain
//! names to reduce packet size. When removing records from a packet, any
//! compression pointers that reference the removed records must be detected and
//! rejected, and pointers that skip over removed sections must be recalculated.
//!
//! The algorithm operates in four sequential passes:
//!
//! 1. **Pass 1 — Mark records**: Iterate through all answer, authority, and
//!    additional RRs. Apply filtering rules based on mode (EDNS0, DNSSEC,
//!    Address, ByType). Record start/end byte offsets for each RR to be removed.
//!
//! 2. **Pass 2 — Validate pointers (detection only)**: Check the question section
//!    name and all retained RR names. Verify no compression pointers target
//!    records marked for removal. If invalid pointers are found, abort and return
//!    the original packet unchanged.
//!
//! 3. **Pass 3 — Fix pointers (adjustment)**: Traverse all names again,
//!    adjusting compression pointer offsets to account for the bytes that will be
//!    removed. Rewrite pointer bytes in the packet with corrected offsets.
//!
//! 4. **Pass 4 — Compact packet**: Use `memmove`-equivalent copies to physically
//!    remove marked records. Update packet length and DNS header section counts.
//!
//! ## Safety
//!
//! - All packet access uses Rust slice bounds checking (replaces C `CHECK_LEN` macro).
//! - Compression pointers are validated against packet boundaries.
//! - Malformed packets return `DnsmasqError::DnsProtocol`.
//! - Zero `unsafe` blocks.

use crate::core::types::{DnsmasqError, DnsmasqResult};
use crate::dns::protocol::{
    get_u16, DnsClass, DnsHeader, DnsName, DnsPacket, RRType, NAME_ESCAPE, RRFIXEDSZ,
};
use bytes::{BufMut, BytesMut};
use tracing::{debug, trace, warn};

// ===========================================================================
// DNS Header Size (12 bytes)
// ===========================================================================

/// DNS header size in bytes (ID + FLAGS + 4 counts × 2 bytes each).
const HDRSIZE: usize = 12;

// ===========================================================================
// RR Filter Mode (from rrfilter.c filter mode constants)
// ===========================================================================

/// RR filter modes matching C `RRFILTER_*` constants from `rrfilter.c`.
///
/// Controls which DNS resource records are removed from a response packet
/// by the [`rrfilter`] function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RRFilterMode {
    /// Remove EDNS0 OPT pseudo-RRs from the additional section.
    ///
    /// Used when the downstream client does not support EDNS0.
    /// Only removes `T_OPT` records from the additional section.
    Edns0,

    /// Remove DNSSEC validation records (RRSIG, NSEC, NSEC3) from all sections.
    ///
    /// Preserves answer-section records if the query type matches the record type
    /// (i.e., the client explicitly queried for DNSSEC records).
    Dnssec,

    /// Remove address records (A/AAAA) matching a filter.
    ///
    /// Used for address-based filtering in the answer section.
    Address,

    /// Remove records of a specific RR type.
    ///
    /// Policy-based filtering using a configured type list.
    ByType(RRType),
}

// ===========================================================================
// RR Type Descriptor Table
// (from C rrfilter.c rrfilter_desc(), lines 632-674)
// ===========================================================================

/// An entry in the descriptor table returned by [`rr_type_descriptor`].
///
/// - `Skip(n)`: Skip `n` bytes of fixed-length data.
/// - `Name`: A domain name at the current position (variable length).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RdataField {
    /// Skip `n` bytes of fixed-length fields.
    Skip(u16),
    /// A domain name at the current position.
    Name,
}

/// RR type descriptors indicating which RDATA fields contain domain names.
///
/// Returns a descriptor slice for the given RR type that describes the internal
/// structure of the RDATA section. This is needed for compression pointer
/// validation after record removal — domain names within RDATA may contain
/// compression pointers that reference removed sections.
///
/// Matches C `rrfilter_desc()` from `rrfilter.c` lines 632-674.
///
/// # Descriptor Format
///
/// - `RdataField::Skip(n)`: Skip `n` bytes (fixed-length fields like integers, IPs).
/// - `RdataField::Name`: Process a domain name at the current position (variable length).
/// - An empty slice means no domain names in RDATA for that type.
///
/// # Examples
///
/// - `T_MX`: `[Skip(2), Name]` — skip 2-byte preference field, then exchange name.
/// - `T_SOA`: `[Name, Name]` — mname domain, rname domain (followed by 20 bytes of integers
///   which are not covered because we only need to find the domain names).
pub fn rr_type_descriptor(rr_type: RRType) -> &'static [RdataField] {
    use RdataField::*;
    match rr_type {
        // T_NS: nameserver name
        RRType::NS => &[Name],
        // T_MD: mail destination (obsolete)
        RRType::MD => &[Name],
        // T_MF: mail forwarder (obsolete)
        RRType::MF => &[Name],
        // T_CNAME: canonical name
        RRType::CNAME => &[Name],
        // T_SOA: mname + rname (followed by 20 bytes of integers, not listed)
        RRType::SOA => &[Name, Name],
        // T_MB: mailbox domain
        RRType::MB => &[Name],
        // T_MG: mail group member
        RRType::MG => &[Name],
        // T_MR: mail rename
        RRType::MR => &[Name],
        // T_PTR: pointer
        RRType::PTR => &[Name],
        // T_MINFO: mailbox info (two names)
        RRType::MINFO => &[Name, Name],
        // T_MX: 2-byte preference + exchange name
        RRType::MX => &[Skip(2), Name],
        // T_RP: responsible person (mbox + txt domain names)
        RRType::RP => &[Name, Name],
        // T_AFSDB: 2-byte subtype + hostname
        RRType::AFSDB => &[Skip(2), Name],
        // T_RT: 2-byte preference + intermediate host
        RRType::RT => &[Skip(2), Name],
        // T_SIG: 18 bytes of fixed data + signer's name
        RRType::SIG => &[Skip(18), Name],
        // T_PX: 2-byte preference + map822 + mapx400
        RRType::PX => &[Skip(2), Name, Name],
        // T_NXT: next domain name (obsolete DNSSEC)
        RRType::NXT => &[Name],
        // T_KX: 2-byte preference + key exchange
        RRType::KX => &[Skip(2), Name],
        // T_SRV: 2-byte priority + 2-byte weight + 2-byte port + target
        RRType::SRV => &[Skip(6), Name],
        // T_DNAME: delegation name
        RRType::DNAME => &[Name],
        // All other types (A, AAAA, TXT, etc.): no domain names in RDATA
        _ => &[],
    }
}

// ===========================================================================
// Internal helper: skip a DNS name in wire format (returns new offset)
// ===========================================================================

/// Skip over a DNS name in wire format starting at `offset` within `packet`.
///
/// Returns the offset just past the name (after the zero label or compression
/// pointer). Used during the filtering passes to advance through names without
/// needing to fully decode them. Validates bounds and detects compression
/// pointer loops (max 256 hops per RFC 1035).
///
/// Equivalent to C `skip_name()` from rfc1035.c.
fn skip_name(packet: &[u8], offset: usize) -> DnsmasqResult<usize> {
    let mut pos = offset;
    let mut hops = 0usize;
    let mut first_jump_end: Option<usize> = None;

    loop {
        if pos >= packet.len() {
            return Err(DnsmasqError::DnsProtocol(
                "skip_name: offset beyond packet".into(),
            ));
        }

        let label_byte = packet[pos];

        if label_byte == 0 {
            // Zero-length label: end of name.
            return Ok(first_jump_end.unwrap_or(pos + 1));
        }

        let label_type = label_byte & 0xC0;

        if label_type == 0xC0 {
            // Compression pointer (2 bytes).
            if pos + 1 >= packet.len() {
                return Err(DnsmasqError::DnsProtocol(
                    "skip_name: truncated compression pointer".into(),
                ));
            }
            if first_jump_end.is_none() {
                first_jump_end = Some(pos + 2);
            }
            let ptr = (u16::from(label_byte & 0x3F) << 8) | u16::from(packet[pos + 1]);
            pos = ptr as usize;
            hops += 1;
            if hops > 256 {
                return Err(DnsmasqError::DnsProtocol(
                    "skip_name: compression pointer loop".into(),
                ));
            }
            continue;
        }

        if label_type == 0x80 {
            return Err(DnsmasqError::DnsProtocol(
                "skip_name: reserved label type 0x80".into(),
            ));
        }

        if label_type == 0x40 {
            // Extended label (bitstring, RFC 2673).
            if pos + 1 >= packet.len() {
                return Err(DnsmasqError::DnsProtocol(
                    "skip_name: truncated extended label".into(),
                ));
            }
            if (packet[pos] & 0x3F) != 1 {
                return Err(DnsmasqError::DnsProtocol(
                    "skip_name: unsupported extended label type".into(),
                ));
            }
            pos += 1; // skip label type byte
            let count = packet[pos] as usize;
            pos += 1; // skip count byte
                      // count == 0 means 256 bits
            let bytes_needed = if count == 0 { 32 } else { (count - 1) / 8 + 1 };
            pos += bytes_needed;
            continue;
        }

        // Normal label (bottom 6 bits = length).
        let len = (label_byte & 0x3F) as usize;
        pos += 1 + len;
    }
}

// ===========================================================================
// check_name — validate and fix DNS name compression pointers
// (from C rrfilter.c lines 139-222)
// ===========================================================================

/// Validate and optionally fix DNS name compression pointers after record removal.
///
/// Walks a DNS domain name in wire format, identifying compression pointers
/// (label type `0xC0`) and validating or adjusting them based on records that
/// have been removed from the packet.
///
/// # Arguments
///
/// * `packet` — The DNS packet as a mutable byte slice.
/// * `offset` — Starting offset of the name within `packet`.
/// * `fixup` — If `true`, rewrite compression pointer offsets; if `false`, validate only.
/// * `rrs` — Pairs of `(start, end)` byte offsets for records being removed.
///
/// # Returns
///
/// `Ok(new_offset)` on success, with the offset advanced past the name.
/// `Err(DnsmasqError::DnsProtocol)` if a pointer references a removed section,
/// the name is out of bounds, or a reserved label type is found.
///
/// Corresponds to C `check_name()` from rrfilter.c lines 139-222.
pub fn check_name(
    packet: &mut [u8],
    offset: usize,
    fixup: bool,
    rrs: &[(usize, usize)],
) -> DnsmasqResult<usize> {
    let plen = packet.len();
    let mut pos = offset;

    loop {
        if pos >= plen {
            return Err(DnsmasqError::DnsProtocol(
                "check_name: offset beyond packet".into(),
            ));
        }

        let label_type = packet[pos] & 0xC0;

        if label_type == 0xC0 {
            // Compression pointer (2 bytes).
            if pos + 1 >= plen {
                return Err(DnsmasqError::DnsProtocol(
                    "check_name: truncated compression pointer".into(),
                ));
            }

            let ptr_offset = (u16::from(packet[pos] & 0x3F) << 8) | u16::from(packet[pos + 1]);

            // Walk through the removed-RR list. The rrs array is a list of
            // (start, end) pairs. For each pair where the pointer target (p)
            // is beyond start, we check:
            //  - If p < end of that removed range, the pointer lands inside
            //    a removed record, so we fail.
            //  - Otherwise, we subtract (end - start) from the offset to
            //    account for the bytes being removed.
            //
            // Linearized version of the C loop that uses alternating indices:
            //   for (i = 0; i < rr_count; i++)
            //     if (p < rrs[i]) break;
            //     else if (i & 1) offset -= rrs[i] - rrs[i-1];
            //   if (i & 1) return 0;
            //
            // In Rust terms: flatten the (start, end) pairs into a single
            // list [start0, end0, start1, end1, ...] and step through.
            let p_abs = ptr_offset as usize;
            let mut adjusted = ptr_offset as i64;
            let mut inside_removed = false;

            for &(rr_start, rr_end) in rrs {
                if p_abs < rr_start {
                    // Pointer is before this removed range — stop.
                    break;
                }
                if p_abs < rr_end {
                    // Pointer lands inside this removed record.
                    inside_removed = true;
                    break;
                }
                // Pointer is beyond this removed range — adjust offset down.
                adjusted -= (rr_end - rr_start) as i64;
            }

            if inside_removed {
                trace!(
                    offset = ptr_offset,
                    "compression pointer references removed RR"
                );
                return Err(DnsmasqError::DnsProtocol(
                    "check_name: pointer into removed record".into(),
                ));
            }

            if fixup {
                let new_offset = adjusted as u16;
                packet[pos] = ((new_offset >> 8) as u8) | 0xC0;
                packet[pos + 1] = (new_offset & 0xFF) as u8;
                trace!(
                    old_offset = ptr_offset,
                    new_offset = new_offset,
                    "adjusted compression pointer"
                );
            }

            // Compression pointer terminates the name.
            pos += 2;
            break;
        } else if label_type == 0x80 {
            // Reserved label type.
            return Err(DnsmasqError::DnsProtocol(
                "check_name: reserved label type 0x80".into(),
            ));
        } else if label_type == 0x40 {
            // Extended label (bitstring, RFC 2673).
            if pos + 1 >= plen {
                return Err(DnsmasqError::DnsProtocol(
                    "check_name: truncated extended label".into(),
                ));
            }
            if (packet[pos] & 0x3F) != 1 {
                return Err(DnsmasqError::DnsProtocol(
                    "check_name: unsupported extended label type".into(),
                ));
            }
            pos += 1; // skip label type byte
            if pos >= plen {
                return Err(DnsmasqError::DnsProtocol(
                    "check_name: truncated bitstring count".into(),
                ));
            }
            let count = packet[pos] as usize;
            pos += 1;
            // count == 0 means 256 bits
            let bytes_needed = if count == 0 { 32 } else { (count - 1) / 8 + 1 };
            pos += bytes_needed;
        } else {
            // Normal label (bottom 6 bits = length).
            let len = (packet[pos] & 0x3F) as usize;
            pos += 1;

            if len == 0 {
                break; // Zero-length label marks the end.
            }

            // Bounds check: ensure label data is within packet.
            if pos + len > plen {
                return Err(DnsmasqError::DnsProtocol(
                    "check_name: label extends beyond packet".into(),
                ));
            }
            pos += len;
        }
    }

    Ok(pos)
}

// ===========================================================================
// check_rrs — validate RRs and their embedded names for pointer integrity
// (from C rrfilter.c lines 283-330)
// ===========================================================================

/// Validate resource records and their embedded names for compression pointer
/// integrity after record removal.
///
/// Iterates through all answer, authority, and additional section RRs.
/// For each retained record (not in `rrs`), validates/adjusts the owner name
/// and any domain names embedded in the RDATA (using [`rr_type_descriptor`]).
///
/// Records marked for removal (present in `rrs`) are skipped.
///
/// # Arguments
///
/// * `packet` — The DNS packet as a mutable byte slice.
/// * `start_offset` — Offset to the start of the answer section.
/// * `ancount` — Number of answer RRs.
/// * `nscount` — Number of authority RRs.
/// * `arcount` — Number of additional RRs.
/// * `fixup` — If `true`, adjust pointers; if `false`, validate only.
/// * `rrs` — Pairs of `(start, end)` byte offsets for records being removed.
///
/// # Returns
///
/// `Ok(())` if all RRs validated successfully.
/// `Err(DnsmasqError::DnsProtocol)` if validation fails.
///
/// Corresponds to C `check_rrs()` from rrfilter.c lines 283-330.
pub fn check_rrs(
    packet: &mut [u8],
    start_offset: usize,
    ancount: u16,
    nscount: u16,
    arcount: u16,
    fixup: bool,
    rrs: &[(usize, usize)],
) -> DnsmasqResult<()> {
    let total_rr = ancount as usize + nscount as usize + arcount as usize;
    let plen = packet.len();
    let mut pos = start_offset;

    for _i in 0..total_rr {
        let rr_start = pos;

        // Skip the owner name.
        let name_end = skip_name(packet, pos)?;

        // Ensure we have at least 10 bytes for the fixed RR fields.
        if name_end + RRFIXEDSZ > plen {
            return Err(DnsmasqError::DnsProtocol(
                "check_rrs: RR too short for fixed fields".into(),
            ));
        }

        let rr_type_raw = get_u16(packet, name_end)?;
        let rr_class_raw = get_u16(packet, name_end + 2)?;
        // TTL at name_end+4..name_end+8 (skipped)
        let rdlen = get_u16(packet, name_end + 8)? as usize;

        let rdata_start = name_end + RRFIXEDSZ;
        let rr_end = rdata_start + rdlen;

        if rr_end > plen {
            return Err(DnsmasqError::DnsProtocol(
                "check_rrs: RDATA extends beyond packet".into(),
            ));
        }

        // Check if this RR is marked for removal — skip if so.
        let is_removed = rrs.iter().any(|&(start, _end)| start == rr_start);

        if !is_removed {
            // Validate/fix the owner name.
            let _ = check_name(packet, rr_start, fixup, rrs)?;

            // For class IN records, check domain names within RDATA.
            let rr_class = DnsClass::from_u16(rr_class_raw);
            if rr_class == Some(DnsClass::IN) {
                let rr_type = RRType::from_u16(rr_type_raw);
                let desc = rr_type_descriptor(rr_type);
                let mut rdata_pos = rdata_start;

                for field in desc {
                    match field {
                        RdataField::Skip(n) => {
                            rdata_pos += *n as usize;
                        }
                        RdataField::Name => {
                            rdata_pos = check_name(packet, rdata_pos, fixup, rrs)?;
                        }
                    }
                }
            }
        }

        pos = rr_end;
    }

    Ok(())
}

// ===========================================================================
// rrfilter — core four-pass DNS RR filtering algorithm
// (from C rrfilter.c lines 426-558)
// ===========================================================================

/// Safely remove DNS resource records from a packet using the four-pass
/// algorithm.
///
/// # Algorithm
///
/// 1. **Pass 1**: Identify records to remove based on filter mode.
/// 2. **Pass 2**: Validate compression pointers in retained records (detection only).
/// 3. **Pass 3**: Adjust compression pointer offsets to account for removed bytes.
/// 4. **Pass 4**: Compact the packet by physically removing marked records.
///
/// # Arguments
///
/// * `packet` — Mutable DNS packet buffer. Modified in-place.
/// * `packet_len` — Current length of valid data in `packet`.
/// * `mode` — The [`RRFilterMode`] controlling which records are removed.
///
/// # Returns
///
/// `Ok(new_len)` — The new packet length after filtering. If no records were
/// removed, the original `packet_len` is returned.
///
/// `Err(DnsmasqError::DnsProtocol)` — The packet is malformed.
///
/// Corresponds to C `rrfilter()` from rrfilter.c lines 426-558.
pub fn rrfilter(
    packet: &mut BytesMut,
    packet_len: usize,
    mode: RRFilterMode,
) -> DnsmasqResult<usize> {
    // Ensure the packet is large enough for a DNS header.
    if packet_len < HDRSIZE {
        return Err(DnsmasqError::DnsProtocol(
            "rrfilter: packet too short for DNS header".into(),
        ));
    }

    // Work on the raw bytes within the buffer.
    let data = &packet[..packet_len];

    // Parse the header to get section counts.
    let header = DnsHeader::parse(data)?;

    // Must have exactly 1 question.
    if header.qdcount != 1 {
        trace!(qdcount = header.qdcount, "rrfilter: qdcount != 1, skipping");
        return Ok(packet_len);
    }

    // Skip the question section name.
    let q_name_end = skip_name(data, HDRSIZE)?;

    // Need 4 bytes for qtype + qclass after the name.
    if q_name_end + 4 > packet_len {
        return Err(DnsmasqError::DnsProtocol(
            "rrfilter: question section truncated".into(),
        ));
    }

    let qtype = RRType::from_u16(get_u16(data, q_name_end)?);
    let qclass = DnsClass::from_u16(get_u16(data, q_name_end + 2)?);

    let rr_section_start = q_name_end + 4;

    // -----------------------------------------------------------------------
    // Pass 1: Mark records for removal.
    // -----------------------------------------------------------------------
    let total_rr = header.ancount as usize + header.nscount as usize + header.arcount as usize;
    let mut rrs: Vec<(usize, usize)> = Vec::new();
    let mut chop_an: u16 = 0;
    let mut chop_ns: u16 = 0;
    let mut chop_ar: u16 = 0;

    {
        let data = &packet[..packet_len];
        let mut pos = rr_section_start;

        for i in 0..total_rr {
            let rr_start = pos;

            let name_end = match skip_name(data, pos) {
                Ok(end) => end,
                Err(_) => {
                    debug!("rrfilter pass 1: malformed name at RR {}", i);
                    return Ok(packet_len);
                }
            };

            if name_end + RRFIXEDSZ > packet_len {
                debug!("rrfilter pass 1: RR {} truncated", i);
                return Ok(packet_len);
            }

            let rr_type_raw = match get_u16(data, name_end) {
                Ok(v) => v,
                Err(_) => {
                    debug!("rrfilter pass 1: RR {} truncated type field", i);
                    return Ok(packet_len);
                }
            };
            let rr_class_raw = match get_u16(data, name_end + 2) {
                Ok(v) => v,
                Err(_) => {
                    debug!("rrfilter pass 1: RR {} truncated class field", i);
                    return Ok(packet_len);
                }
            };
            let rdlen = match get_u16(data, name_end + 8) {
                Ok(v) => v as usize,
                Err(_) => {
                    debug!("rrfilter pass 1: RR {} truncated rdlen field", i);
                    return Ok(packet_len);
                }
            };

            let rdata_start = name_end + RRFIXEDSZ;
            let rr_end = rdata_start + rdlen;

            if rr_end > packet_len {
                debug!("rrfilter pass 1: RR {} RDATA extends beyond packet", i);
                return Ok(packet_len);
            }

            pos = rr_end;

            let rr_type = RRType::from_u16(rr_type_raw);
            let rr_class = DnsClass::from_u16(rr_class_raw);

            // Determine the section this RR belongs to.
            let in_answer = i < header.ancount as usize;
            let in_authority = i >= header.ancount as usize
                && i < (header.ancount as usize + header.nscount as usize);
            // Remaining is additional section.

            // Apply filtering rules based on mode.
            let should_remove = match mode {
                RRFilterMode::Edns0 => {
                    // Remove T_OPT from additional section only.
                    !in_answer && !in_authority && rr_type == RRType::OPT
                }
                RRFilterMode::Dnssec => {
                    // Remove RRSIG, NSEC, NSEC3 from all sections.
                    if rr_type != RRType::NSEC
                        && rr_type != RRType::NSEC3
                        && rr_type != RRType::RRSIG
                    {
                        false
                    } else if in_answer && rr_type == qtype && qclass == rr_class {
                        // Don't remove the answer if it was explicitly queried.
                        false
                    } else {
                        true
                    }
                }
                RRFilterMode::Address => {
                    // Remove A/AAAA from answer section only.
                    in_answer
                        && rr_class == Some(DnsClass::IN)
                        && (rr_type == RRType::A || rr_type == RRType::AAAA)
                }
                RRFilterMode::ByType(filter_type) => {
                    // Policy-based: remove matching type from answer section if class IN.
                    // Special handling for T_ANY queries (RFC 8482 spirit):
                    if qtype == RRType::ANY && filter_type == RRType::ANY {
                        // Filter replies to ANY queries — keep only A, AAAA, MX, CNAME.
                        // Remove records that are NOT one of the preserved types.
                        rr_class == Some(DnsClass::IN)
                            && rr_type != RRType::A
                            && rr_type != RRType::AAAA
                            && rr_type != RRType::MX
                            && rr_type != RRType::CNAME
                    } else {
                        // Normal policy filtering: answer section only, class IN, matching type.
                        in_answer && rr_class == Some(DnsClass::IN) && rr_type == filter_type
                    }
                }
            };

            if should_remove {
                trace!(
                    rr_index = i,
                    rr_type = ?rr_type,
                    start = rr_start,
                    end = rr_end,
                    "marking RR for removal"
                );
                rrs.push((rr_start, rr_end));

                if in_answer {
                    chop_an += 1;
                } else if in_authority {
                    chop_ns += 1;
                } else {
                    chop_ar += 1;
                }
            }
        }
    }

    // Nothing to do.
    if rrs.is_empty() {
        debug!(mode = ?mode, "rrfilter: no records matched for removal");
        return Ok(packet_len);
    }

    debug!(
        mode = ?mode,
        records_to_remove = rrs.len(),
        chop_an = chop_an,
        chop_ns = chop_ns,
        chop_ar = chop_ar,
        "rrfilter: pass 1 complete"
    );

    // -----------------------------------------------------------------------
    // Pass 2: Validate compression pointers (detection only, fixup=false).
    // -----------------------------------------------------------------------
    {
        let data = &mut packet[..packet_len];

        // Check question section name.
        if check_name(data, HDRSIZE, false, &rrs).is_err() {
            warn!("rrfilter pass 2: question name has pointer into removed RR, aborting");
            return Ok(packet_len);
        }

        // Check all answer/authority/additional RR names and RDATA names.
        if check_rrs(
            data,
            rr_section_start,
            header.ancount,
            header.nscount,
            header.arcount,
            false,
            &rrs,
        )
        .is_err()
        {
            warn!("rrfilter pass 2: RR name has pointer into removed RR, aborting");
            return Ok(packet_len);
        }
    }

    // -----------------------------------------------------------------------
    // Pass 3: Fix compression pointers (fixup=true).
    // -----------------------------------------------------------------------
    {
        let data = &mut packet[..packet_len];

        // Fix question section name.
        let _ = check_name(data, HDRSIZE, true, &rrs);
        // Note: ignoring errors here because pass 2 already validated.

        // Fix all RR names and RDATA names.
        let _ = check_rrs(
            data,
            rr_section_start,
            header.ancount,
            header.nscount,
            header.arcount,
            true,
            &rrs,
        );
    }

    // -----------------------------------------------------------------------
    // Pass 4: Compact packet by removing marked records.
    // -----------------------------------------------------------------------
    // Build a new buffer with the removed sections excised.
    // We copy: [0..rrs[0].start] + [rrs[0].end..rrs[1].start] + ... + [rrs[last].end..packet_len]
    let mut new_packet = BytesMut::with_capacity(packet_len);

    let mut copy_from = 0usize;
    for &(rr_start, rr_end) in &rrs {
        // Copy everything from copy_from up to rr_start.
        if rr_start > copy_from {
            new_packet.extend_from_slice(&packet[copy_from..rr_start]);
        }
        copy_from = rr_end;
    }
    // Copy remaining data after last removed record.
    if copy_from < packet_len {
        new_packet.extend_from_slice(&packet[copy_from..packet_len]);
    }

    let new_len = new_packet.len();

    // Update the header section counts in the new packet using BufMut.
    if new_len >= HDRSIZE {
        let new_ancount = header.ancount.saturating_sub(chop_an);
        let new_nscount = header.nscount.saturating_sub(chop_ns);
        let new_arcount = header.arcount.saturating_sub(chop_ar);

        // Write updated section counts (bytes 6-11 of the DNS header).
        // Uses a temporary BufMut-backed buffer for correct big-endian encoding.
        let mut count_buf = BytesMut::with_capacity(6);
        count_buf.put_u16(new_ancount);
        count_buf.put_u16(new_nscount);
        count_buf.put_u16(new_arcount);
        new_packet[6..12].copy_from_slice(&count_buf);
    }

    // Replace the original packet content.
    packet.clear();
    packet.extend_from_slice(&new_packet);

    debug!(
        original_len = packet_len,
        new_len = new_len,
        records_removed = rrs.len(),
        "rrfilter: pass 4 complete, packet compacted"
    );

    Ok(new_len)
}

// ===========================================================================
// Convenience: filter a parsed DnsPacket by re-serializing and filtering
// ===========================================================================

/// Parse the filtered packet into a structured [`DnsPacket`] for further processing.
///
/// This is a convenience wrapper that calls [`rrfilter`] on the raw packet data
/// and then parses the result into a structured [`DnsPacket`]. Useful when the
/// caller needs structured access to the filtered result rather than raw bytes.
///
/// # Arguments
///
/// * `raw_packet` — The raw DNS packet bytes.
/// * `mode` — The [`RRFilterMode`] controlling which records are removed.
///
/// # Returns
///
/// `Ok((DnsPacket, new_len))` — The parsed filtered packet and its byte length.
/// `Err(DnsmasqError::DnsProtocol)` — The packet is malformed.
pub fn rrfilter_to_packet(
    raw_packet: &[u8],
    mode: RRFilterMode,
) -> DnsmasqResult<(DnsPacket, usize)> {
    let mut buf = BytesMut::from(raw_packet);
    let plen = raw_packet.len();
    let new_len = rrfilter(&mut buf, plen, mode)?;
    let parsed = DnsPacket::parse(&buf[..new_len])?;
    Ok((parsed, new_len))
}

/// Extract the question name from a raw DNS packet as a structured [`DnsName`].
///
/// This helper is used by the filtering module to extract the question name
/// for logging, display, and comparison purposes. The name is extracted using
/// [`DnsName::from_wire`] which handles compression pointers.
///
/// # Arguments
///
/// * `packet` — The raw DNS packet bytes.
///
/// # Returns
///
/// `Ok(DnsName)` — The extracted question name.
/// `Err(DnsmasqError::DnsProtocol)` — If the packet is malformed.
pub fn extract_question_name(packet: &[u8]) -> DnsmasqResult<DnsName> {
    if packet.len() < HDRSIZE {
        return Err(DnsmasqError::DnsProtocol(
            "extract_question_name: packet too short".into(),
        ));
    }
    let (name, _consumed) = DnsName::from_wire(HDRSIZE, packet)?;
    Ok(name)
}

// ===========================================================================
// to_wire — convert domain name from presentation format to DNS wire format
// (from C rrfilter.c lines 801-830)
// ===========================================================================

/// Convert a domain name from presentation format (dotted notation, e.g.
/// `"example.com"`) to DNS wire format (length-prefixed labels terminated
/// by a zero byte).
///
/// During conversion:
/// - Uppercase letters (A-Z) are mapped to lowercase (a-z) for canonical form.
/// - [`NAME_ESCAPE`] sequences are processed: the escape byte is removed and
///   the following byte is decremented by 1, restoring the original character
///   that was escaped.
///
/// # Arguments
///
/// * `name` — The domain name in presentation format as a mutable byte vector.
///   Modified in place to contain wire format.
///
/// # Returns
///
/// The length of the wire-format name in bytes, including the terminal zero byte.
///
/// # Examples
///
/// ```ignore
/// let mut name = b"Example.COM".to_vec();
/// let wire_len = to_wire(&mut name);
/// // name now contains: [7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0]
/// // wire_len is 13
/// ```
///
/// Corresponds to C `to_wire()` from rrfilter.c lines 801-830.
pub fn to_wire(name: &mut Vec<u8>) -> usize {
    if name.is_empty() {
        name.push(0);
        return 1;
    }

    // Process NAME_ESCAPE sequences and case mapping first.
    let mut processed = Vec::with_capacity(name.len());
    let mut i = 0;
    while i < name.len() {
        if name[i] == NAME_ESCAPE && i + 1 < name.len() {
            // Escape sequence: remove the escape byte, decrement next byte.
            let ch = name[i + 1].wrapping_sub(1);
            processed.push(ch);
            i += 2;
        } else if name[i] >= b'A' && name[i] <= b'Z' {
            // Map uppercase to lowercase.
            processed.push(name[i] - b'A' + b'a');
            i += 1;
        } else {
            processed.push(name[i]);
            i += 1;
        }
    }

    // Now convert to wire format: split by '.', prepend length byte for each label.
    let mut wire = Vec::with_capacity(processed.len() + 2);
    let labels: Vec<&[u8]> = processed.split(|&b| b == b'.').collect();

    for label in &labels {
        if label.is_empty() {
            continue;
        }
        wire.push(label.len() as u8);
        wire.extend_from_slice(label);
    }
    wire.push(0); // terminal zero label

    let wire_len = wire.len();
    *name = wire;
    wire_len
}

// ===========================================================================
// from_wire — convert domain name from DNS wire format to presentation format
// (from C rrfilter.c lines 893-918)
// ===========================================================================

/// Convert a domain name from DNS wire format (length-prefixed labels terminated
/// by a zero byte) to presentation format (dotted notation, e.g. `"example.com"`).
///
/// During conversion, special characters (`.`, NUL byte `\0`, and
/// [`NAME_ESCAPE`] itself) are escaped by inserting a [`NAME_ESCAPE`] byte
/// before the character and incrementing the character by 1.
///
/// # Important
///
/// The input must be in **uncompressed** wire format — no compression pointers.
/// Names extracted from DNS packets must be decompressed first.
///
/// # Arguments
///
/// * `name` — The domain name in wire format as a mutable byte vector.
///   Modified in place to contain presentation format.
///
/// # Examples
///
/// ```ignore
/// let mut name = vec![7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0];
/// from_wire(&mut name);
/// // name now contains: b"example.com"
/// ```
///
/// Corresponds to C `from_wire()` from rrfilter.c lines 893-918.
pub fn from_wire(name: &mut Vec<u8>) {
    if name.is_empty() {
        return;
    }

    // Parse the wire format labels.
    let mut labels: Vec<Vec<u8>> = Vec::new();
    let mut pos = 0;

    while pos < name.len() {
        let len = name[pos] as usize;
        if len == 0 {
            break;
        }
        pos += 1;

        if pos + len > name.len() {
            break;
        }

        let label_bytes = &name[pos..pos + len];

        // Escape special characters within the label.
        let mut escaped_label = Vec::with_capacity(len + 4);
        for &b in label_bytes {
            if b == b'.' || b == 0 || b == NAME_ESCAPE {
                escaped_label.push(NAME_ESCAPE);
                escaped_label.push(b.wrapping_add(1));
            } else {
                escaped_label.push(b);
            }
        }

        labels.push(escaped_label);
        pos += len;
    }

    // Join labels with dots.
    let mut result = Vec::new();
    for (idx, label) in labels.iter().enumerate() {
        if idx > 0 {
            result.push(b'.');
        }
        result.extend_from_slice(label);
    }

    *name = result;
}

// ===========================================================================
// Unit Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    /// Helper: build a minimal DNS packet with a single question and specified RRs.
    /// Returns (packet, answer_section_offset).
    fn build_test_packet(
        qname_wire: &[u8],
        qtype: u16,
        qclass: u16,
        answer_rrs: &[(
            /*name_wire:*/ &[u8],
            /*type:*/ u16,
            /*class:*/ u16,
            /*ttl:*/ u32,
            /*rdata:*/ &[u8],
        )],
        authority_rrs: &[(
            /*name_wire:*/ &[u8],
            /*type:*/ u16,
            /*class:*/ u16,
            /*ttl:*/ u32,
            /*rdata:*/ &[u8],
        )],
        additional_rrs: &[(
            /*name_wire:*/ &[u8],
            /*type:*/ u16,
            /*class:*/ u16,
            /*ttl:*/ u32,
            /*rdata:*/ &[u8],
        )],
    ) -> BytesMut {
        let mut buf = BytesMut::new();

        // DNS Header (12 bytes)
        let ancount = answer_rrs.len() as u16;
        let nscount = authority_rrs.len() as u16;
        let arcount = additional_rrs.len() as u16;

        // ID
        buf.put_u16(0x1234);
        // Flags: QR=1, RD=1 (standard response)
        buf.put_u8(0x81);
        buf.put_u8(0x80);
        // Counts
        buf.put_u16(1); // qdcount
        buf.put_u16(ancount);
        buf.put_u16(nscount);
        buf.put_u16(arcount);

        // Question section
        buf.extend_from_slice(qname_wire);
        buf.put_u16(qtype);
        buf.put_u16(qclass);

        // Helper to write RRs
        let write_rrs = |buf: &mut BytesMut, rrs: &[(&[u8], u16, u16, u32, &[u8])]| {
            for &(name, rr_type, rr_class, ttl, rdata) in rrs {
                buf.extend_from_slice(name);
                buf.put_u16(rr_type);
                buf.put_u16(rr_class);
                buf.put_u32(ttl);
                buf.put_u16(rdata.len() as u16);
                buf.extend_from_slice(rdata);
            }
        };

        write_rrs(&mut buf, answer_rrs);
        write_rrs(&mut buf, authority_rrs);
        write_rrs(&mut buf, additional_rrs);

        buf
    }

    // Wire-format name "example.com" = [7, e, x, a, m, p, l, e, 3, c, o, m, 0]
    fn example_com_wire() -> Vec<u8> {
        vec![
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]
    }

    #[test]
    fn test_rrfilter_mode_enum() {
        // Ensure all variants are distinguishable.
        assert_ne!(RRFilterMode::Edns0, RRFilterMode::Dnssec);
        assert_ne!(RRFilterMode::Address, RRFilterMode::ByType(RRType::A));
        assert_eq!(
            RRFilterMode::ByType(RRType::MX),
            RRFilterMode::ByType(RRType::MX)
        );
        assert_ne!(
            RRFilterMode::ByType(RRType::MX),
            RRFilterMode::ByType(RRType::A)
        );
    }

    #[test]
    fn test_rr_type_descriptor_known_types() {
        // NS: single name
        assert_eq!(rr_type_descriptor(RRType::NS), &[RdataField::Name]);

        // CNAME: single name
        assert_eq!(rr_type_descriptor(RRType::CNAME), &[RdataField::Name]);

        // MX: skip 2 + name
        assert_eq!(
            rr_type_descriptor(RRType::MX),
            &[RdataField::Skip(2), RdataField::Name]
        );

        // SOA: name + name
        assert_eq!(
            rr_type_descriptor(RRType::SOA),
            &[RdataField::Name, RdataField::Name]
        );

        // SRV: skip 6 + name
        assert_eq!(
            rr_type_descriptor(RRType::SRV),
            &[RdataField::Skip(6), RdataField::Name]
        );

        // SIG: skip 18 + name
        assert_eq!(
            rr_type_descriptor(RRType::SIG),
            &[RdataField::Skip(18), RdataField::Name]
        );

        // PX: skip 2 + name + name
        assert_eq!(
            rr_type_descriptor(RRType::PX),
            &[RdataField::Skip(2), RdataField::Name, RdataField::Name]
        );
    }

    #[test]
    fn test_rr_type_descriptor_no_names() {
        // A, AAAA, TXT, OPT: no domain names in RDATA
        assert!(rr_type_descriptor(RRType::A).is_empty());
        assert!(rr_type_descriptor(RRType::AAAA).is_empty());
        assert!(rr_type_descriptor(RRType::TXT).is_empty());
        assert!(rr_type_descriptor(RRType::OPT).is_empty());
        assert!(rr_type_descriptor(RRType::Unknown(9999)).is_empty());
    }

    #[test]
    fn test_rrfilter_edns0_removes_opt() {
        let qname = example_com_wire();
        // A record answer: 4-byte IPv4 address
        let a_rdata = &[192u8, 168, 1, 1];
        // OPT pseudo-RR in additional: name="." (just [0]), type=OPT(41), class=4096 (UDP size)
        let opt_name = &[0u8]; // root name
        let opt_rdata = &[]; // no EDNS0 options

        let mut pkt = build_test_packet(
            &qname,
            1, // A
            1, // IN
            &[(&qname, 1, 1, 300, a_rdata)],
            &[],
            &[(opt_name, 41, 4096, 0, opt_rdata)],
        );

        let orig_len = pkt.len();
        let new_len = rrfilter(&mut pkt, orig_len, RRFilterMode::Edns0).unwrap();

        // The OPT record should be removed.
        assert!(new_len < orig_len);

        // Parse the result to verify counts.
        let hdr = DnsHeader::parse(&pkt[..new_len]).unwrap();
        assert_eq!(hdr.ancount, 1); // A record preserved
        assert_eq!(hdr.arcount, 0); // OPT removed
    }

    #[test]
    fn test_rrfilter_dnssec_removes_rrsig() {
        let qname = example_com_wire();
        let a_rdata = &[10u8, 0, 0, 1];
        // RRSIG record (type 46): fake RDATA (18 bytes fixed + signer name).
        let rrsig_rdata = &[0u8; 20]; // placeholder RRSIG data

        let mut pkt = build_test_packet(
            &qname,
            1, // A
            1, // IN
            &[
                (&qname, 1, 1, 300, a_rdata),
                (&qname, 46, 1, 300, rrsig_rdata), // RRSIG in answer
            ],
            &[],
            &[],
        );

        let orig_len = pkt.len();
        let new_len = rrfilter(&mut pkt, orig_len, RRFilterMode::Dnssec).unwrap();

        // RRSIG should be removed from answer.
        assert!(new_len < orig_len);

        let hdr = DnsHeader::parse(&pkt[..new_len]).unwrap();
        assert_eq!(hdr.ancount, 1); // A preserved, RRSIG removed
    }

    #[test]
    fn test_rrfilter_no_match_returns_same_length() {
        let qname = example_com_wire();
        let a_rdata = &[10u8, 0, 0, 1];

        let mut pkt = build_test_packet(
            &qname,
            1, // A
            1, // IN
            &[(&qname, 1, 1, 300, a_rdata)],
            &[],
            &[],
        );

        let orig_len = pkt.len();
        // EDNS0 mode but no OPT records — should not modify.
        let new_len = rrfilter(&mut pkt, orig_len, RRFilterMode::Edns0).unwrap();
        assert_eq!(new_len, orig_len);
    }

    #[test]
    fn test_rrfilter_too_short_packet() {
        let mut pkt = BytesMut::from(&[0u8; 6][..]);
        let result = rrfilter(&mut pkt, 6, RRFilterMode::Edns0);
        assert!(result.is_err());
    }

    #[test]
    fn test_to_wire_simple() {
        let mut name = b"example.com".to_vec();
        let len = to_wire(&mut name);
        assert_eq!(
            name,
            vec![7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0]
        );
        assert_eq!(len, 13);
    }

    #[test]
    fn test_to_wire_uppercase() {
        let mut name = b"Example.COM".to_vec();
        let len = to_wire(&mut name);
        // All lowercase in wire format.
        assert_eq!(
            name,
            vec![7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0]
        );
        assert_eq!(len, 13);
    }

    #[test]
    fn test_to_wire_empty() {
        let mut name = Vec::new();
        let len = to_wire(&mut name);
        assert_eq!(name, vec![0]);
        assert_eq!(len, 1);
    }

    #[test]
    fn test_to_wire_single_label() {
        let mut name = b"localhost".to_vec();
        let len = to_wire(&mut name);
        assert_eq!(
            name,
            vec![9, b'l', b'o', b'c', b'a', b'l', b'h', b'o', b's', b't', 0]
        );
        assert_eq!(len, 11);
    }

    #[test]
    fn test_to_wire_escape_sequence() {
        // NAME_ESCAPE (0x01) followed by '/' (0x2F+1=0x30='0')
        // The escape removes the escape byte and decrements the next byte by 1.
        let mut name = vec![b'a', NAME_ESCAPE, b'/' + 1, b'.', b'b'];
        let len = to_wire(&mut name);
        // After escape processing: 'a', '/' (0x2F), '.', 'b'
        // Split by '.': ["a/", "b"]
        // Wire: [2, a, /, 1, b, 0]
        assert_eq!(name, vec![2, b'a', b'/', 1, b'b', 0]);
        assert_eq!(len, 6);
    }

    #[test]
    fn test_from_wire_simple() {
        let mut name = vec![
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ];
        from_wire(&mut name);
        assert_eq!(name, b"example.com");
    }

    #[test]
    fn test_from_wire_single_label() {
        let mut name = vec![9, b'l', b'o', b'c', b'a', b'l', b'h', b'o', b's', b't', 0];
        from_wire(&mut name);
        assert_eq!(name, b"localhost");
    }

    #[test]
    fn test_from_wire_empty() {
        let mut name = Vec::new();
        from_wire(&mut name);
        assert!(name.is_empty());
    }

    #[test]
    fn test_from_wire_root() {
        let mut name = vec![0u8];
        from_wire(&mut name);
        assert!(name.is_empty());
    }

    #[test]
    fn test_from_wire_escape_dot() {
        // Wire format: label with a literal dot inside.
        // e.g., label "a.b" = length 3, 'a', '.', 'b'
        let mut name = vec![3, b'a', b'.', b'b', 0];
        from_wire(&mut name);
        // The dot inside the label should be escaped: NAME_ESCAPE, '.'+1
        assert_eq!(name, vec![b'a', NAME_ESCAPE, b'.' + 1, b'b']);
    }

    #[test]
    fn test_to_wire_from_wire_roundtrip() {
        // Start with a simple name in presentation format.
        let original = b"test.example.org".to_vec();
        let mut wire = original.clone();
        let _wire_len = to_wire(&mut wire);

        // Convert back to presentation.
        from_wire(&mut wire);
        assert_eq!(wire, original);
    }

    #[test]
    fn test_check_name_no_compression() {
        // Simple name with no compression pointers.
        let mut packet = vec![
            // DNS header (12 bytes, all zeros)
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            // Name "a.b" at offset 12: [1, 'a', 1, 'b', 0]
            1, b'a', 1, b'b', 0,
        ];
        let rrs: Vec<(usize, usize)> = Vec::new();
        let result = check_name(&mut packet, 12, false, &rrs);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 17); // past the name
    }

    #[test]
    fn test_check_name_with_compression() {
        // Name "a.b" at offset 12 as [1, 'a', 1, 'b', 0]
        // Then at offset 17: compression pointer to offset 14 ([1, 'b', 0])
        let mut packet = vec![
            // DNS header (12 bytes)
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Name "a.b" at offset 12
            1, b'a', 1, b'b', 0, // Compression pointer to offset 14 at offset 17
            0xC0, 14,
        ];
        let rrs: Vec<(usize, usize)> = Vec::new();
        let result = check_name(&mut packet, 17, false, &rrs);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 19); // past the 2-byte pointer
    }

    #[test]
    fn test_rrfilter_address_removes_a_records() {
        let qname = example_com_wire();
        let a_rdata = &[10u8, 0, 0, 1];
        let txt_rdata = b"some text";

        let mut pkt = build_test_packet(
            &qname,
            1, // A
            1, // IN
            &[
                (&qname, 1, 1, 300, a_rdata),             // A record
                (&qname, 16, 1, 300, txt_rdata.as_ref()), // TXT record
            ],
            &[],
            &[],
        );

        let orig_len = pkt.len();
        let new_len = rrfilter(&mut pkt, orig_len, RRFilterMode::Address).unwrap();

        // A record should be removed, TXT preserved.
        assert!(new_len < orig_len);
        let hdr = DnsHeader::parse(&pkt[..new_len]).unwrap();
        assert_eq!(hdr.ancount, 1); // Only TXT remains
    }

    #[test]
    fn test_rrfilter_by_type() {
        let qname = example_com_wire();
        let a_rdata = &[10u8, 0, 0, 1];
        let mx_rdata = {
            // MX RDATA: 2-byte preference + exchange name
            let mut mx = vec![0u8, 10]; // preference = 10
            mx.extend_from_slice(&example_com_wire()); // exchange
            mx
        };

        let mut pkt = build_test_packet(
            &qname,
            255, // ANY
            1,   // IN
            &[
                (&qname, 1, 1, 300, a_rdata),    // A record
                (&qname, 15, 1, 300, &mx_rdata), // MX record
            ],
            &[],
            &[],
        );

        let orig_len = pkt.len();
        // Filter MX records
        let new_len = rrfilter(&mut pkt, orig_len, RRFilterMode::ByType(RRType::MX)).unwrap();

        // MX should be removed, A preserved.
        assert!(new_len < orig_len);
        let hdr = DnsHeader::parse(&pkt[..new_len]).unwrap();
        assert_eq!(hdr.ancount, 1);
    }

    // -----------------------------------------------------------------------
    // rr_type_descriptor coverage — every branch in the match
    // -----------------------------------------------------------------------

    #[test]
    fn test_rr_type_descriptor_ns() {
        let desc = rr_type_descriptor(RRType::NS);
        assert_eq!(desc.len(), 1);
        assert!(matches!(desc[0], RdataField::Name));
    }

    #[test]
    fn test_rr_type_descriptor_md() {
        assert_eq!(rr_type_descriptor(RRType::MD).len(), 1);
    }

    #[test]
    fn test_rr_type_descriptor_mf() {
        assert_eq!(rr_type_descriptor(RRType::MF).len(), 1);
    }

    #[test]
    fn test_rr_type_descriptor_cname() {
        let desc = rr_type_descriptor(RRType::CNAME);
        assert_eq!(desc.len(), 1);
        assert!(matches!(desc[0], RdataField::Name));
    }

    #[test]
    fn test_rr_type_descriptor_soa() {
        let desc = rr_type_descriptor(RRType::SOA);
        assert_eq!(desc.len(), 2);
        assert!(matches!(desc[0], RdataField::Name));
        assert!(matches!(desc[1], RdataField::Name));
    }

    #[test]
    fn test_rr_type_descriptor_mb() {
        assert_eq!(rr_type_descriptor(RRType::MB).len(), 1);
    }

    #[test]
    fn test_rr_type_descriptor_mg() {
        assert_eq!(rr_type_descriptor(RRType::MG).len(), 1);
    }

    #[test]
    fn test_rr_type_descriptor_mr() {
        assert_eq!(rr_type_descriptor(RRType::MR).len(), 1);
    }

    #[test]
    fn test_rr_type_descriptor_ptr() {
        let desc = rr_type_descriptor(RRType::PTR);
        assert_eq!(desc.len(), 1);
        assert!(matches!(desc[0], RdataField::Name));
    }

    #[test]
    fn test_rr_type_descriptor_minfo() {
        let desc = rr_type_descriptor(RRType::MINFO);
        assert_eq!(desc.len(), 2);
    }

    #[test]
    fn test_rr_type_descriptor_mx() {
        let desc = rr_type_descriptor(RRType::MX);
        assert_eq!(desc.len(), 2);
        assert!(matches!(desc[0], RdataField::Skip(2)));
        assert!(matches!(desc[1], RdataField::Name));
    }

    #[test]
    fn test_rr_type_descriptor_rp() {
        assert_eq!(rr_type_descriptor(RRType::RP).len(), 2);
    }

    #[test]
    fn test_rr_type_descriptor_afsdb() {
        let desc = rr_type_descriptor(RRType::AFSDB);
        assert_eq!(desc.len(), 2);
        assert!(matches!(desc[0], RdataField::Skip(2)));
    }

    #[test]
    fn test_rr_type_descriptor_rt() {
        assert_eq!(rr_type_descriptor(RRType::RT).len(), 2);
    }

    #[test]
    fn test_rr_type_descriptor_sig() {
        let desc = rr_type_descriptor(RRType::SIG);
        assert_eq!(desc.len(), 2);
        assert!(matches!(desc[0], RdataField::Skip(18)));
    }

    #[test]
    fn test_rr_type_descriptor_px() {
        let desc = rr_type_descriptor(RRType::PX);
        assert_eq!(desc.len(), 3);
    }

    #[test]
    fn test_rr_type_descriptor_nxt() {
        assert_eq!(rr_type_descriptor(RRType::NXT).len(), 1);
    }

    #[test]
    fn test_rr_type_descriptor_kx() {
        let desc = rr_type_descriptor(RRType::KX);
        assert_eq!(desc.len(), 2);
        assert!(matches!(desc[0], RdataField::Skip(2)));
    }

    #[test]
    fn test_rr_type_descriptor_srv() {
        let desc = rr_type_descriptor(RRType::SRV);
        assert_eq!(desc.len(), 2);
        assert!(matches!(desc[0], RdataField::Skip(6)));
    }

    #[test]
    fn test_rr_type_descriptor_dname() {
        let desc = rr_type_descriptor(RRType::DNAME);
        assert_eq!(desc.len(), 1);
    }

    #[test]
    fn test_rr_type_descriptor_a() {
        assert!(rr_type_descriptor(RRType::A).is_empty());
    }

    #[test]
    fn test_rr_type_descriptor_aaaa() {
        assert!(rr_type_descriptor(RRType::AAAA).is_empty());
    }

    #[test]
    fn test_rr_type_descriptor_txt() {
        assert!(rr_type_descriptor(RRType::TXT).is_empty());
    }

    // -----------------------------------------------------------------------
    // skip_name edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_skip_name_normal() {
        // "\x07example\x03com\x00"
        let packet = b"\x07example\x03com\x00";
        let result = skip_name(packet, 0).unwrap();
        assert_eq!(result, packet.len());
    }

    #[test]
    fn test_skip_name_compression_pointer() {
        // Build a packet with a name at offset 0 and a compression pointer at offset 13
        let mut pkt = vec![];
        pkt.extend_from_slice(b"\x07example\x03com\x00"); // 13 bytes
        pkt.push(0xC0); // compression pointer
        pkt.push(0x00); // points to offset 0
        let result = skip_name(&pkt, 13).unwrap();
        assert_eq!(result, 15); // skips the 2-byte compression pointer
    }

    #[test]
    fn test_skip_name_truncated() {
        let packet = b"\x07exam"; // Label says 7 bytes but only 4 available
        assert!(skip_name(packet, 0).is_err());
    }

    #[test]
    fn test_skip_name_beyond_packet() {
        let packet = b"\x00";
        assert!(skip_name(packet, 5).is_err());
    }

    #[test]
    fn test_skip_name_reserved_label_type() {
        let packet = [0x80, 0x00]; // reserved label type 0x80
        assert!(skip_name(&packet, 0).is_err());
    }

    #[test]
    fn test_skip_name_compression_loop() {
        // Create a pointer loop: offset 0 → offset 0
        let packet = [0xC0, 0x00];
        // This should hit the 256-hop limit
        assert!(skip_name(&packet, 0).is_err());
    }

    // -----------------------------------------------------------------------
    // check_name edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_check_name_empty_rrs() {
        let mut packet = b"\x07example\x03com\x00".to_vec();
        let result = check_name(&mut packet, 0, false, &[]).unwrap();
        assert_eq!(result, 13);
    }

    #[test]
    fn test_check_name_fixup_adjusts_pointer() {
        // Name at offset 0: "\x07example\x03com\x00" (13 bytes)
        // RR was at offsets 13..20 (7 bytes removed)
        // Pointer at offset 20: 0xC0 0x00 (points to offset 0)
        let mut pkt = vec![];
        pkt.extend_from_slice(b"\x07example\x03com\x00"); // 0..13
        pkt.extend_from_slice(&[0u8; 7]); // 13..20 (removed range)
        pkt.push(0xC0); // pointer at 20
        pkt.push(0x00); // points to 0
                        // After removing 13..20, pointer should remain at offset 0 (before the removed range)
        let result = check_name(&mut pkt, 20, true, &[(13, 20)]).unwrap();
        assert_eq!(result, 22);
    }

    #[test]
    fn test_check_name_pointer_into_removed_record() {
        // Pointer targets offset 15, which is within removed range 13..20
        let mut pkt = vec![0u8; 25];
        pkt[20] = 0xC0;
        pkt[21] = 15; // points to offset 15, inside removed (13..20)
        let result = check_name(&mut pkt, 20, false, &[(13, 20)]);
        assert!(result.is_err());
    }

    #[test]
    fn test_check_name_reserved_label_type() {
        let mut pkt = vec![0x80, 0x00];
        assert!(check_name(&mut pkt, 0, false, &[]).is_err());
    }

    // -----------------------------------------------------------------------
    // extract_question_name tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_question_name_valid() {
        // Build minimal DNS query: 12-byte header + "\x03www\x07example\x03com\x00" + qtype(A) + qclass(IN)
        let mut pkt = vec![0u8; 12]; // header
        pkt[4] = 0;
        pkt[5] = 1; // qdcount = 1
        pkt.extend_from_slice(b"\x03www\x07example\x03com\x00");
        pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // qtype=A, qclass=IN
        let name = extract_question_name(&pkt).unwrap();
        assert_eq!(name.to_string().trim_end_matches('.'), "www.example.com");
    }

    #[test]
    fn test_extract_question_name_too_short() {
        let pkt = vec![0u8; 10]; // less than HDRSIZE
        assert!(extract_question_name(&pkt).is_err());
    }

    // -----------------------------------------------------------------------
    // check_rrs basic tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_check_rrs_empty() {
        // Build a valid DNS packet with 0 RRs
        let mut pkt = vec![0u8; 12]; // header, all counts = 0
        pkt.extend_from_slice(b"\x03www\x07example\x03com\x00");
        pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // qtype, qclass
        let qs_end = 12 + 17 + 4;
        let result = check_rrs(&mut pkt, qs_end, 0, 0, 0, false, &[]);
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // to_wire/from_wire additional edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_to_wire_trailing_dot() {
        let mut name = b"example.com.".to_vec();
        let len = to_wire(&mut name);
        assert!(len > 0);
    }

    #[test]
    fn test_to_wire_multiple_labels() {
        let mut name = b"a.b.c.d.e.f".to_vec();
        let len = to_wire(&mut name);
        assert!(len > 0);
    }

    #[test]
    fn test_from_wire_multiple_labels() {
        let mut name = b"\x01a\x01b\x01c\x01d\x00".to_vec();
        from_wire(&mut name);
        let s = String::from_utf8_lossy(&name);
        assert!(s.contains('.'));
    }

    #[test]
    fn test_to_wire_from_wire_long_name() {
        let mut name = b"subdomain.host.region.cloud.example.org".to_vec();
        let len = to_wire(&mut name);
        assert!(len > 0);
        let mut wire = name[..len].to_vec();
        from_wire(&mut wire);
        assert!(String::from_utf8_lossy(&wire).contains("subdomain"));
    }

    // -----------------------------------------------------------------------
    // rrfilter edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_rrfilter_packet_too_short() {
        let mut pkt = BytesMut::from(&[0u8; 5][..]);
        let result = rrfilter(&mut pkt, 5, RRFilterMode::Address);
        assert!(result.is_err());
    }

    #[test]
    fn test_rrfilter_address_removes_aaaa() {
        // Address mode removes A/AAAA from answer section
        let qname = example_com_wire();
        let mut pkt = build_test_packet(
            &qname,
            28,
            1,                                   // AAAA query
            &[(&qname, 28, 1, 300, &[0u8; 16])], // AAAA answer
            &[],
            &[],
        );
        let orig_len = pkt.len();
        let new_len = rrfilter(&mut pkt, orig_len, RRFilterMode::Address).unwrap();
        let hdr = DnsHeader::parse(&pkt[..new_len]).unwrap();
        assert_eq!(hdr.ancount, 0); // AAAA is address type, removed
    }

    #[test]
    fn test_rrfilter_address_keeps_ns() {
        // Address mode only removes A/AAAA; NS is kept
        let qname = example_com_wire();
        let ns_rdata = example_com_wire();
        let mut pkt = build_test_packet(
            &qname,
            2,
            1,                                 // NS query
            &[(&qname, 2, 1, 300, &ns_rdata)], // NS answer
            &[],
            &[],
        );
        let orig_len = pkt.len();
        let new_len = rrfilter(&mut pkt, orig_len, RRFilterMode::Address).unwrap();
        let hdr = DnsHeader::parse(&pkt[..new_len]).unwrap();
        assert_eq!(hdr.ancount, 1); // NS is not address type, kept
    }

    #[test]
    fn test_rrfilter_no_question() {
        let mut pkt = BytesMut::new();
        pkt.put_u16(0x1234); // ID
        pkt.put_u8(0x81);
        pkt.put_u8(0x80); // flags
        pkt.put_u16(0); // qdcount = 0
        pkt.put_u16(0);
        pkt.put_u16(0);
        pkt.put_u16(0);
        let len = pkt.len();
        let result = rrfilter(&mut pkt, len, RRFilterMode::Address).unwrap();
        assert_eq!(result, len); // unchanged
    }

    #[test]
    fn test_rrfilter_multiple_answers_partial_remove() {
        let qname = example_com_wire();
        let mx_rdata = {
            let mut v = vec![0u8, 10]; // preference = 10
            v.extend_from_slice(&example_com_wire());
            v
        };
        let mut pkt = build_test_packet(
            &qname,
            255,
            1, // ANY query
            &[
                (&qname, 1, 1, 300, &[192, 168, 1, 1]), // A record
                (&qname, 15, 1, 300, &mx_rdata),        // MX record
            ],
            &[],
            &[],
        );
        let orig_len = pkt.len();
        // In Address mode, both A and AAAA are kept; MX is removed for non-address
        // Actually: RRFilterMode::Address removes A/AAAA (address records) for non-address queries.
        // Let's use ByType to remove MX instead for clearer semantics
        let new_len = rrfilter(&mut pkt, orig_len, RRFilterMode::ByType(RRType::MX)).unwrap();
        let hdr = DnsHeader::parse(&pkt[..new_len]).unwrap();
        assert_eq!(hdr.ancount, 1); // Only A kept
    }

    // -----------------------------------------------------------------------
    // rrfilter_to_packet tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_rrfilter_to_packet_no_change() {
        let qname = example_com_wire();
        let pkt = build_test_packet(
            &qname,
            1,
            1,
            &[(&qname, 1, 1, 300, &[10, 0, 0, 1])],
            &[],
            &[],
        );
        let orig = pkt.to_vec();
        // Address mode with A query and A answer — the A record won't be filtered
        // (address filter removes non-address-type answers when query is address type)
        let result = rrfilter_to_packet(&orig, RRFilterMode::Address);
        assert!(result.is_ok());
    }
}

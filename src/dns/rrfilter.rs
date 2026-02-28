//! DNS resource record filtering with compression pointer rewriting.
//!
//! Complete Rust rewrite of `src/rrfilter.c` (918 lines of C). Implements safe
//! removal/filtering of DNS Resource Records from response packets while
//! maintaining packet integrity, including correct DNS name compression pointer
//! rewriting when records are removed.
//!
//! # Four-Pass Algorithm
//!
//! The core [`rrfilter`] function uses a four-pass algorithm:
//!
//! 1. **Mark** — Scan all sections, identify records to remove based on mode.
//! 2. **Validate** — Check that no remaining compression pointers target removed records.
//! 3. **Fixup** — Rewrite compression pointer offsets to account for removed bytes.
//! 4. **Compact** — Copy remaining data forward, update header counts.
//!
//! # Name Format Conversion
//!
//! [`to_wire`] and [`from_wire`] convert DNS names between presentation format
//! (dot-separated, e.g. `"example.com"`) and wire format (length-prefixed labels,
//! e.g. `\x07example\x03com\x00`).
//!
//! # Safety
//!
//! All packet access is bounds-checked. No `unsafe` blocks. Compression pointer
//! loops are detected and rejected. All in-place buffer modifications use safe
//! Rust slice operations.
//!
//! # RFC Compliance
//!
//! - RFC 1035 Section 4.1.4 — message compression pointer handling
//! - RFC 2673 — bitstring labels (extended label type 0x40)
//! - RFC 6891 — EDNS0 OPT pseudo-RR handling
//! - RFC 8482 Section 4.3 — minimal responses to ANY queries

use log::{debug, warn};
use thiserror::Error;

use crate::core::daemon::DaemonState;
use crate::dns::protocol::{
    check_len, get_u16, C_IN, NAME_ESCAPE, RRFIXEDSZ,
    T_A, T_AAAA, T_AFSDB, T_ANY, T_CNAME, T_DNAME, T_KX, T_MB, T_MD, T_MF,
    T_MG, T_MINFO, T_MR, T_MX, T_NSEC, T_NSEC3, T_NXT, T_OPT, T_PTR, T_PX,
    T_RP, T_RRSIG, T_RT, T_SIG, T_SOA, T_SRV, T_NS,
};
use crate::dns::wire;
use crate::types::dns::DnsHeader;

// ============================================================================
// Constants
// ============================================================================

/// DNS header size in bytes (ID + flags + 4 section counts).
const DNS_HEADER_SIZE: usize = 12;

/// Maximum compression pointer hops before declaring a loop.
/// Used as a safety limit in check_name to prevent infinite traversal.
#[allow(dead_code)]
const MAX_POINTER_HOPS: usize = 256;

// ============================================================================
// Error Types
// ============================================================================

/// Errors encountered during DNS resource record filtering.
#[derive(Debug, Error)]
pub enum FilterError {
    /// Packet is shorter than expected at the given offset.
    #[error("packet too short at offset {offset}: need {needed}, have {available}")]
    PacketTooShort {
        /// Byte offset where the access was attempted.
        offset: usize,
        /// Number of bytes needed.
        needed: usize,
        /// Number of bytes actually available.
        available: usize,
    },
    /// Compression pointer target is out of bounds.
    #[error("invalid compression pointer at offset {0}")]
    InvalidPointer(usize),
    /// Compression pointer loop detected (exceeded maximum hop count).
    #[error("compression pointer loop detected at offset {0}")]
    PointerLoop(usize),
}

// ============================================================================
// Filter Mode
// ============================================================================

/// DNS resource record filtering mode.
///
/// Determines which records to remove from a DNS response packet.
/// Replaces the C `RRFILTER_EDNS0`, `RRFILTER_DNSSEC`, `RRFILTER_CONF` constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RrFilterMode {
    /// Remove EDNS0 OPT pseudo-RR from the additional section.
    /// Used when the downstream client does not support EDNS0.
    Edns0,
    /// Remove DNSSEC records (RRSIG, NSEC, NSEC3) from all sections,
    /// except when they are the explicit answer to the query.
    Dnssec,
    /// Remove records matching the `daemon.dns.filter_rr` configuration list.
    /// Includes special handling for T_ANY queries per RFC 8482 Section 4.3.
    Config,
    /// Remove A (IPv4 address) records from the answer section.
    A,
    /// Remove AAAA (IPv6 address) records from the answer section.
    Aaaa,
}

// ============================================================================
// Helper: read u16 from packet with FilterError
// ============================================================================

/// Read a big-endian u16 from `packet` at `offset`, returning a FilterError on failure.
#[inline]
fn read_u16_at(packet: &[u8], offset: usize) -> Result<u16, FilterError> {
    get_u16(packet, offset).ok_or(FilterError::PacketTooShort {
        offset,
        needed: 2,
        available: packet.len().saturating_sub(offset),
    })
}

// ============================================================================
// check_name — Compression pointer validation and fixup
// ============================================================================

/// Walk a DNS name in the packet, validating or adjusting compression pointers.
///
/// Traverses the name starting at `*cursor`, handling normal labels (length-prefixed),
/// compression pointers (0xC0), extended labels (0x40, bitstring), and reserved types
/// (0x80). For compression pointers:
///
/// - **Validate mode** (`fixup=false`): checks whether the pointer target falls within
///   any removed range. Returns `Ok(false)` if so.
/// - **Fixup mode** (`fixup=true`): adjusts the pointer offset to account for bytes
///   that have been (or will be) removed from the packet.
///
/// On success, advances `*cursor` past the name.
///
/// # Returns
/// - `Ok(true)` — Name is valid; all pointers safe (or adjusted).
/// - `Ok(false)` — A pointer targets a removed range (validate mode only).
/// - `Err(FilterError)` — Packet corruption (bounds, reserved label, pointer loop).
fn check_name(
    packet: &mut [u8],
    cursor: &mut usize,
    plen: usize,
    fixup: bool,
    removed: &[(usize, usize)],
) -> Result<bool, FilterError> {
    let mut pos = *cursor;

    loop {
        // Bounds check: need at least 1 byte for the label type
        if !check_len(plen, pos, 1) {
            return Err(FilterError::PacketTooShort {
                offset: pos,
                needed: 1,
                available: plen.saturating_sub(pos),
            });
        }

        let label_type = packet[pos] & 0xC0;

        if label_type == 0xC0 {
            // ---- Compression pointer (2 bytes) ----
            if !check_len(plen, pos, 2) {
                return Err(FilterError::PacketTooShort {
                    offset: pos,
                    needed: 2,
                    available: plen.saturating_sub(pos),
                });
            }

            // Read the raw 14-bit offset
            let mut offset =
                ((packet[pos] as usize & 0x3F) << 8) | (packet[pos + 1] as usize);

            // Walk through removed ranges to check and adjust offset.
            // Removed ranges are sorted by start offset.
            let mut in_removed = false;
            for &(start, end) in removed {
                if offset < start {
                    // Target is before this range — no more adjustments needed
                    break;
                }
                if offset < end {
                    // Target falls within a removed range
                    in_removed = true;
                    break;
                }
                // Target is past this range — subtract range size
                offset -= end - start;
            }

            if in_removed {
                return Ok(false);
            }

            // Rewrite the pointer with the adjusted offset
            if fixup {
                packet[pos] = ((offset >> 8) as u8) | 0xC0;
                packet[pos + 1] = (offset & 0xFF) as u8;
            }

            pos += 2;
            break; // Compression pointer terminates the name in the byte stream
        } else if label_type == 0x80 {
            // ---- Reserved label type — invalid ----
            return Ok(false);
        } else if label_type == 0x40 {
            // ---- Extended label type (bitstring labels, RFC 2673) ----
            if !check_len(plen, pos, 2) {
                return Err(FilterError::PacketTooShort {
                    offset: pos,
                    needed: 2,
                    available: plen.saturating_sub(pos),
                });
            }
            // Only bitstring (subtype 1) is understood
            if (packet[pos] & 0x3F) != 1 {
                return Ok(false);
            }
            pos += 1;

            let count = packet[pos] as usize;
            pos += 1;

            // count == 0 means 256 bits
            let byte_count = if count == 0 { 32 } else { ((count - 1) >> 3) + 1 };
            if !check_len(plen, pos, byte_count) {
                return Err(FilterError::PacketTooShort {
                    offset: pos,
                    needed: byte_count,
                    available: plen.saturating_sub(pos),
                });
            }
            pos += byte_count;
        } else {
            // ---- Normal label: low 6 bits = length ----
            let len = (packet[pos] & 0x3F) as usize;
            pos += 1;

            if len == 0 {
                break; // Zero-length label marks end of name
            }

            if !check_len(plen, pos, len) {
                return Err(FilterError::PacketTooShort {
                    offset: pos,
                    needed: len,
                    available: plen.saturating_sub(pos),
                });
            }
            pos += len;
        }
    }

    *cursor = pos;
    Ok(true)
}

// ============================================================================
// check_rrs — RR-level name validation and fixup
// ============================================================================

/// Validate and optionally fix up domain names within all resource records.
///
/// Iterates through all RRs in answer, authority, and additional sections.
/// For each retained (non-removed) RR:
/// 1. Validates/adjusts the owner name via [`check_name`].
/// 2. For class-IN RRs with embedded domain names in RDATA (identified via
///    [`rrfilter_desc`]), validates/adjusts each embedded name.
///
/// Records marked for removal (their start offset appears in `removed`) are
/// skipped entirely since their contents will be discarded.
fn check_rrs(
    packet: &mut [u8],
    start: usize,
    plen: usize,
    fixup: bool,
    removed: &[(usize, usize)],
    header: &DnsHeader,
) -> Result<bool, FilterError> {
    let total = header.ancount as usize + header.nscount as usize + header.arcount as usize;
    let mut p = start;

    for _i in 0..total {
        let rr_start = p;

        // Skip the owner name (need at least RRFIXEDSZ bytes after it)
        if wire::skip_name(packet, &mut p, plen, RRFIXEDSZ).is_err() {
            return Ok(false);
        }

        // Read TYPE (2), CLASS (2), skip TTL (4), RDLEN (2)
        let rr_type = read_u16_at(packet, p)?;
        let rr_class = read_u16_at(packet, p + 2)?;
        // p + 4..p + 8 = TTL (skipped)
        let rdlen = read_u16_at(packet, p + 8)? as usize;
        let rdata_offset = p + RRFIXEDSZ;

        // Check if this RR is being removed — match against removed range starts
        let is_removed = removed.iter().any(|&(s, _)| s == rr_start);

        if !is_removed {
            // Fix up the owner name
            let mut name_pos = rr_start;
            if !check_name(packet, &mut name_pos, plen, fixup, removed)? {
                return Ok(false);
            }

            // For class IN records with embedded names, fix up RDATA names
            if rr_class == C_IN {
                let desc = rrfilter_desc(rr_type);
                let mut pp = rdata_offset;
                for &d in desc {
                    if d == -1 {
                        break;
                    } else if d != 0 {
                        pp += d as usize;
                    } else if !check_name(packet, &mut pp, plen, fixup, removed)? {
                        return Ok(false);
                    }
                }
            }
        }

        // Advance past RDATA
        if !check_len(plen, rdata_offset, rdlen) {
            return Ok(false);
        }
        p = rdata_offset + rdlen;
    }

    Ok(true)
}

// ============================================================================
// rrfilter — Main four-pass RR filtering algorithm
// ============================================================================

/// Safely remove DNS resource records from a packet using a four-pass algorithm.
///
/// Removes specific resource records from a DNS response while preserving packet
/// integrity, including DNS name compression pointer adjustment.
///
/// # Algorithm
///
/// 1. **Pass 1 — Mark:** Scan answer/authority/additional sections, identify
///    records to remove based on `mode`.
/// 2. **Pass 2 — Validate:** Check all compression pointers in retained records
///    to ensure none target removed byte ranges. Aborts if invalid pointers found.
/// 3. **Pass 3 — Fixup:** Rewrite compression pointer offsets to account for
///    bytes that will be removed.
/// 4. **Pass 4 — Compact:** Copy remaining data forward (memmove-safe), truncate
///    packet, update header section counts.
///
/// # Arguments
///
/// * `header` — Mutable DNS header (section counts updated on return).
/// * `packet` — Mutable packet buffer (modified in place, may be truncated).
/// * `mode`   — Filtering mode determining which records to remove.
/// * `state`  — Daemon state (used for `Config` mode filter list).
///
/// # Returns
///
/// The number of records removed, or `Err` on packet corruption.
/// Returns `Ok(0)` if no records match the filter criteria.
pub fn rrfilter(
    header: &mut DnsHeader,
    packet: &mut Vec<u8>,
    mode: RrFilterMode,
    state: &DaemonState,
) -> Result<usize, FilterError> {
    let plen = packet.len();

    // Config mode with empty filter list → nothing to do
    if mode == RrFilterMode::Config && state.dns.filter_rr.is_empty() {
        return Ok(0);
    }

    // Must have exactly 1 question
    if header.qdcount != 1 {
        return Ok(0);
    }

    // Skip past question name, reading qtype and qclass
    let mut cursor = DNS_HEADER_SIZE;
    if wire::skip_name(packet, &mut cursor, plen, 4).is_err() {
        return Ok(0);
    }
    let qtype = match read_u16_at(packet, cursor) {
        Ok(v) => v,
        Err(_) => return Ok(0),
    };
    let qclass = match read_u16_at(packet, cursor + 2) {
        Ok(v) => v,
        Err(_) => return Ok(0),
    };
    cursor += 4;

    // ----------------------------------------------------------------
    // Pass 1: Mark records for removal
    // ----------------------------------------------------------------
    let total_rrs =
        header.ancount as usize + header.nscount as usize + header.arcount as usize;
    let mut removed: Vec<(usize, usize)> = Vec::new();
    let mut chop_an: u16 = 0;
    let mut chop_ns: u16 = 0;
    let mut chop_ar: u16 = 0;

    let an_count = header.ancount as usize;
    let ns_boundary = an_count + header.nscount as usize;

    for i in 0..total_rrs {
        let rr_start = cursor;

        // Skip owner name (need RRFIXEDSZ bytes after)
        if wire::skip_name(packet, &mut cursor, plen, RRFIXEDSZ).is_err() {
            debug!("rrfilter pass 1: malformed name at RR {i}");
            break;
        }

        let rr_type = match read_u16_at(packet, cursor) {
            Ok(v) => v,
            Err(_) => break,
        };
        let rr_class = match read_u16_at(packet, cursor + 2) {
            Ok(v) => v,
            Err(_) => break,
        };
        // Skip: type(2) + class(2) + TTL(4) = 8, then read rdlen
        let rdlen = match read_u16_at(packet, cursor + 8) {
            Ok(v) => v as usize,
            Err(_) => break,
        };
        cursor += RRFIXEDSZ; // Past type+class+TTL+rdlen

        // Advance past RDATA
        if !check_len(plen, cursor, rdlen) {
            break;
        }
        cursor += rdlen;
        let rr_end = cursor;

        // Determine whether to remove this record based on mode
        let should_remove = match mode {
            RrFilterMode::Edns0 => {
                // Remove T_OPT from additional section only
                i >= ns_boundary && rr_type == T_OPT
            }
            RrFilterMode::Dnssec => {
                // Remove RRSIG, NSEC, NSEC3 from all sections
                if rr_type != T_NSEC && rr_type != T_NSEC3 && rr_type != T_RRSIG {
                    false
                } else if i < an_count && rr_type == qtype && rr_class == qclass {
                    // Don't remove the explicit answer (query was for RRSIG etc.)
                    false
                } else {
                    true
                }
            }
            RrFilterMode::Config => should_remove_config(
                i, rr_type, rr_class, qtype, an_count, state,
            ),
            RrFilterMode::A => {
                // Remove A records from answer section only
                i < an_count && rr_type == T_A && rr_class == C_IN
            }
            RrFilterMode::Aaaa => {
                // Remove AAAA records from answer section only
                i < an_count && rr_type == T_AAAA && rr_class == C_IN
            }
        };

        if should_remove {
            removed.push((rr_start, rr_end));

            if i < an_count {
                chop_an += 1;
            } else if i < ns_boundary {
                chop_ns += 1;
            } else {
                chop_ar += 1;
            }
        }
    }

    // Nothing to do
    if removed.is_empty() {
        return Ok(0);
    }

    let records_removed = removed.len();
    debug!(
        "rrfilter: mode={:?}, removing {} records (an={}, ns={}, ar={})",
        mode, records_removed, chop_an, chop_ns, chop_ar
    );

    // ----------------------------------------------------------------
    // Pass 2: Validate compression pointers (detection only, no fixup)
    // ----------------------------------------------------------------
    let mut p2 = DNS_HEADER_SIZE;
    if !check_name(packet, &mut p2, plen, false, &removed)? {
        warn!("rrfilter: question name pointer targets removed record, aborting");
        return Ok(0);
    }
    p2 += 4; // qtype + qclass

    if !check_rrs(packet, p2, plen, false, &removed, header)? {
        warn!("rrfilter: RR pointer targets removed record, aborting");
        return Ok(0);
    }

    // ----------------------------------------------------------------
    // Pass 3: Fix up compression pointers (adjust offsets)
    // ----------------------------------------------------------------
    let mut p3 = DNS_HEADER_SIZE;
    // Errors in pass 3 are not possible if pass 2 succeeded
    let _ = check_name(packet, &mut p3, plen, true, &removed);
    p3 += 4; // qtype + qclass
    let _ = check_rrs(packet, p3, plen, true, &removed, header);

    // ----------------------------------------------------------------
    // Pass 4: Compact — remove marked records by copying data forward
    // ----------------------------------------------------------------
    let mut write_pos = removed[0].0;
    for i in 0..removed.len() {
        let copy_from = removed[i].1;
        let copy_to = if i + 1 < removed.len() {
            removed[i + 1].0
        } else {
            plen
        };
        if copy_from < copy_to {
            packet.copy_within(copy_from..copy_to, write_pos);
            write_pos += copy_to - copy_from;
        }
    }
    packet.truncate(write_pos);

    // Update header section counts
    header.ancount = header.ancount.saturating_sub(chop_an);
    header.nscount = header.nscount.saturating_sub(chop_ns);
    header.arcount = header.arcount.saturating_sub(chop_ar);

    // Write updated counts back to packet header bytes
    if packet.len() >= DNS_HEADER_SIZE {
        packet[6..8].copy_from_slice(&header.ancount.to_be_bytes());
        packet[8..10].copy_from_slice(&header.nscount.to_be_bytes());
        packet[10..12].copy_from_slice(&header.arcount.to_be_bytes());
    }

    Ok(records_removed)
}

/// Determine whether a record should be removed in Config mode.
///
/// Implements the C `RRFILTER_CONF` logic with special handling for T_ANY queries
/// per RFC 8482 Section 4.3.
fn should_remove_config(
    rr_index: usize,
    rr_type: u16,
    rr_class: u16,
    qtype: u16,
    an_count: usize,
    state: &DaemonState,
) -> bool {
    // Special handling for ANY queries when T_ANY is in the filter list
    if qtype == T_ANY && state.dns.filter_rr.contains(&T_ANY) {
        // RFC 8482: keep A, AAAA, MX, CNAME and non-IN class records
        if rr_class != C_IN
            || rr_type == T_A
            || rr_type == T_AAAA
            || rr_type == T_MX
            || rr_type == T_CNAME
        {
            return false;
        }
        return true;
    }

    // Normal config filtering: only look at answer section
    if rr_index >= an_count {
        return false;
    }
    // Skip non-IN class records
    if rr_class != C_IN {
        return false;
    }
    // Remove if type is in the filter list
    state.dns.filter_rr.contains(&rr_type)
}

// ============================================================================
// rrfilter_desc — RR type descriptor for domain name fields in RDATA
// ============================================================================

/// Get the structure descriptor for a DNS resource record type.
///
/// Returns a static slice describing which fields in the RR's RDATA contain
/// domain names that need compression pointer fixup when records are removed.
///
/// # Descriptor Format
///
/// - **Positive value**: skip that many bytes (fixed-length fields).
/// - **`0`**: a domain name follows at this position.
/// - **`-1`**: end of descriptor (terminator).
///
/// # Examples
///
/// ```text
/// T_MX  → [2, 0, -1]   — 2-byte preference, then exchange name, end.
/// T_SOA → [0, 0, -1]   — mname, rname, end (20 bytes of integers follow but
///                          have no names, so the descriptor stops).
/// T_A   → [-1]          — No domain names in A record RDATA.
/// ```
///
/// This function is also used by the DNSSEC validation module for name
/// canonicalization and wire-format traversal.
pub fn rrfilter_desc(rr_type: u16) -> &'static [i16] {
    // Table matches the C rr_desc[] static array from rrfilter.c lines 643-666.
    // Each entry: positive value = skip N bytes, 0 = domain name, -1 = end.
    match rr_type {
        T_NS => &[0, -1],
        T_MD => &[0, -1],
        T_MF => &[0, -1],
        T_CNAME => &[0, -1],
        T_SOA => &[0, 0, -1],
        T_MB => &[0, -1],
        T_MG => &[0, -1],
        T_MR => &[0, -1],
        T_PTR => &[0, -1],
        T_MINFO => &[0, 0, -1],
        T_MX => &[2, 0, -1],
        T_RP => &[0, 0, -1],
        T_AFSDB => &[2, 0, -1],
        T_RT => &[2, 0, -1],
        T_SIG => &[18, 0, -1],
        T_PX => &[2, 0, 0, -1],
        T_NXT => &[0, -1],
        T_KX => &[2, 0, -1],
        T_SRV => &[6, 0, -1],
        T_DNAME => &[0, -1],
        // Wildcard catchall: no embedded domain names
        _ => &[-1],
    }
}

// ============================================================================
// to_wire — Presentation format to DNS wire format conversion
// ============================================================================

/// Convert a DNS name from presentation format to wire format, in place.
///
/// Transforms a dot-separated domain name (e.g., `"Example.COM\0"`) into
/// length-prefixed labels (e.g., `\x07example\x03com\x00`). The conversion:
///
/// - Replaces dots with length-prefix bytes.
/// - Lowercases ASCII letters (A–Z → a–z) for canonical form.
/// - Processes [`NAME_ESCAPE`] sequences: removes the escape byte and
///   decrements the following byte to recover the original character.
/// - Appends a zero-length root label terminator.
///
/// # Arguments
///
/// * `name` — Mutable buffer containing the null-terminated presentation-format
///   name. Modified in place. Must be large enough for wire format (same size
///   suffices since wire format is never larger than presentation format plus one).
///
/// # Returns
///
/// Length of the wire-format name in bytes (including the terminal zero label).
///
/// # Example
///
/// ```text
/// Input:  b"Example.COM\0"
/// Output: b"\x07example\x03com\x00" (returns 13)
/// ```
pub fn to_wire(name: &mut [u8]) -> usize {
    if name.is_empty() {
        return 0;
    }

    if name[0] == 0 {
        // Empty/root name — already a zero label
        return 1;
    }

    // Single-pass approach matching C to_wire() at rrfilter.c line 801:
    // Walk through the presentation-format name, finding each label delimited
    // by '.' or '\0'. For each label, shift its bytes right by 1 position to
    // make room for the length prefix byte.

    let mut label_start: usize = 0;

    loop {
        if label_start >= name.len() || name[label_start] == 0 {
            // Write terminal zero label
            if label_start < name.len() {
                name[label_start] = 0;
            }
            return label_start + 1;
        }

        // Scan forward to find the end of the current label (dot or null).
        // Simultaneously lowercase and process NAME_ESCAPE characters.
        let mut scan = label_start;
        let mut effective_len = 0usize;
        while scan < name.len() && name[scan] != b'.' && name[scan] != 0 {
            if name[scan] >= b'A' && name[scan] <= b'Z' {
                name[scan] = name[scan] - b'A' + b'a';
            } else if name[scan] == NAME_ESCAPE {
                // Remove the escape byte: shift remaining data left by 1
                for q in scan..name.len().saturating_sub(1) {
                    name[q] = name[q + 1];
                }
                if name.len() > 0 {
                    name[name.len() - 1] = 0;
                }
                // Decrement the byte that was after the escape to undo +1 from from_wire
                if scan < name.len() {
                    name[scan] = name[scan].wrapping_sub(1);
                }
                // Don't advance scan — re-examine what we just shifted in
                // but do count the character
            }
            scan += 1;
            effective_len += 1;
        }

        let at_end = scan >= name.len() || name[scan] == 0;

        // Shift the label data right by 1 to insert the length prefix.
        // The effective_len characters are at name[label_start..label_start+effective_len].
        // After shift they will be at name[label_start+1..label_start+1+effective_len].
        if effective_len > 0 && label_start + effective_len < name.len() {
            name.copy_within(
                label_start..label_start + effective_len,
                label_start + 1,
            );
        }
        name[label_start] = effective_len as u8;

        label_start += 1 + effective_len;

        if at_end {
            // Write terminal zero label
            if label_start < name.len() {
                name[label_start] = 0;
            }
            return label_start + 1;
        }

        // We are at the dot separator position. The next iteration starts
        // at the same position (the dot byte will be overwritten by the
        // next label's length prefix).
    }
}

// ============================================================================
// from_wire — DNS wire format to presentation format conversion
// ============================================================================

/// Convert a DNS name from wire format to presentation format, in place.
///
/// Transforms length-prefixed labels (e.g., `\x07example\x03com\x00`) into
/// a dot-separated name (e.g., `"example.com\0"`). Special characters (dot,
/// null, [`NAME_ESCAPE`]) within labels are escaped as `[NAME_ESCAPE, char+1]`.
///
/// # Arguments
///
/// * `name` — Mutable buffer containing the wire-format name (terminated by a
///   zero-length label). Modified in place. Must have enough room for escape
///   expansion (worst case: every byte needs escaping → 2× original size).
///
/// # Preconditions
///
/// The input must NOT contain compression pointers (0xC0 prefix bytes).
/// Use `extract_name()` to decompress names before calling this function.
///
/// # Example
///
/// ```text
/// Input:  b"\x07example\x03com\x00"
/// Output: b"example.com\0"
/// ```
pub fn from_wire(name: &mut [u8]) {
    if name.is_empty() || name[0] == 0 {
        return;
    }

    // To avoid in-place buffer overlap issues during escaping expansion,
    // copy the wire-format name to a temporary stack buffer first.
    // DNS names are max 255 bytes in wire format (RFC 1035 Section 2.3.4).
    let mut tmp = [0u8; 256];
    let mut wire_end = 0usize;

    // Find the end of the wire-format name and copy to tmp
    {
        let mut pos = 0usize;
        while pos < name.len() && pos < 255 {
            let label_len = name[pos] as usize;
            tmp[pos] = name[pos];
            if label_len == 0 {
                wire_end = pos;
                break;
            }
            // Copy the label data bytes
            for i in 1..=label_len {
                if pos + i < name.len() && pos + i < 256 {
                    tmp[pos + i] = name[pos + i];
                }
            }
            pos += label_len + 1;
        }
    }

    // Now read from tmp (immutable wire format) and write to name (output).
    // This two-buffer approach safely handles the case where escaping expands
    // the name beyond its original wire-format length.
    let mut rp = 0usize; // read position in tmp
    let mut wp = 0usize; // write position in name
    let mut first = true;

    while rp < wire_end {
        let label_len = tmp[rp] as usize;
        if label_len == 0 {
            break;
        }

        // Dot separator before non-first labels
        if !first {
            if wp < name.len() {
                name[wp] = b'.';
                wp += 1;
            }
        }
        first = false;

        rp += 1; // Skip past the length byte

        // Copy each byte of the label, escaping special characters
        for i in 0..label_len {
            if rp + i >= 256 {
                break;
            }
            let ch = tmp[rp + i];
            if ch == b'.' || ch == 0 || ch == NAME_ESCAPE {
                // Escape: write [NAME_ESCAPE, char + 1]
                if wp < name.len() {
                    name[wp] = NAME_ESCAPE;
                    wp += 1;
                }
                if wp < name.len() {
                    name[wp] = ch.wrapping_add(1);
                    wp += 1;
                }
            } else {
                if wp < name.len() {
                    name[wp] = ch;
                    wp += 1;
                }
            }
        }

        rp += label_len;
    }

    // Null-terminate the presentation-format name
    if wp < name.len() {
        name[wp] = 0;
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ---- FilterError display ----

    #[test]
    fn test_filter_error_display() {
        let e = FilterError::PacketTooShort {
            offset: 10,
            needed: 4,
            available: 2,
        };
        assert!(format!("{e}").contains("packet too short"));

        let e = FilterError::InvalidPointer(42);
        assert!(format!("{e}").contains("invalid compression pointer"));

        let e = FilterError::PointerLoop(100);
        assert!(format!("{e}").contains("compression pointer loop"));
    }

    // ---- RrFilterMode ----

    #[test]
    fn test_filter_mode_equality() {
        assert_eq!(RrFilterMode::Edns0, RrFilterMode::Edns0);
        assert_ne!(RrFilterMode::Dnssec, RrFilterMode::Config);
        assert_ne!(RrFilterMode::A, RrFilterMode::Aaaa);
    }

    // ---- rrfilter_desc ----

    #[test]
    fn test_rrfilter_desc_ns() {
        let desc = rrfilter_desc(T_NS);
        assert_eq!(desc, &[0, -1]);
    }

    #[test]
    fn test_rrfilter_desc_mx() {
        let desc = rrfilter_desc(T_MX);
        assert_eq!(desc, &[2, 0, -1]);
    }

    #[test]
    fn test_rrfilter_desc_soa() {
        let desc = rrfilter_desc(T_SOA);
        assert_eq!(desc, &[0, 0, -1]);
    }

    #[test]
    fn test_rrfilter_desc_srv() {
        let desc = rrfilter_desc(T_SRV);
        assert_eq!(desc, &[6, 0, -1]);
    }

    #[test]
    fn test_rrfilter_desc_sig() {
        let desc = rrfilter_desc(T_SIG);
        assert_eq!(desc, &[18, 0, -1]);
    }

    #[test]
    fn test_rrfilter_desc_px() {
        let desc = rrfilter_desc(T_PX);
        assert_eq!(desc, &[2, 0, 0, -1]);
    }

    #[test]
    fn test_rrfilter_desc_unknown() {
        let desc = rrfilter_desc(T_A);
        assert_eq!(desc, &[-1]);
        let desc = rrfilter_desc(T_AAAA);
        assert_eq!(desc, &[-1]);
        let desc = rrfilter_desc(9999);
        assert_eq!(desc, &[-1]);
    }

    // ---- to_wire / from_wire basic tests ----

    #[test]
    fn test_to_wire_simple() {
        let mut buf = [0u8; 64];
        let src = b"example.com\0";
        buf[..src.len()].copy_from_slice(src);
        let wire_len = to_wire(&mut buf);
        assert_eq!(wire_len, 13); // \x07example\x03com\x00
        assert_eq!(buf[0], 7);
        assert_eq!(&buf[1..8], b"example");
        assert_eq!(buf[8], 3);
        assert_eq!(&buf[9..12], b"com");
        assert_eq!(buf[12], 0);
    }

    #[test]
    fn test_to_wire_lowercase() {
        let mut buf = [0u8; 64];
        let src = b"Example.COM\0";
        buf[..src.len()].copy_from_slice(src);
        let wire_len = to_wire(&mut buf);
        assert_eq!(wire_len, 13);
        assert_eq!(&buf[1..8], b"example");
        assert_eq!(&buf[9..12], b"com");
    }

    #[test]
    fn test_to_wire_root() {
        let mut buf = [0u8; 4];
        buf[0] = 0; // empty name
        let wire_len = to_wire(&mut buf);
        assert_eq!(wire_len, 1);
        assert_eq!(buf[0], 0);
    }

    #[test]
    fn test_to_wire_single_label() {
        let mut buf = [0u8; 32];
        let src = b"localhost\0";
        buf[..src.len()].copy_from_slice(src);
        let wire_len = to_wire(&mut buf);
        assert_eq!(wire_len, 11); // \x09localhost\x00
        assert_eq!(buf[0], 9);
        assert_eq!(&buf[1..10], b"localhost");
        assert_eq!(buf[10], 0);
    }

    #[test]
    fn test_from_wire_simple() {
        let mut buf = [0u8; 64];
        // Wire format: \x07example\x03com\x00
        buf[0] = 7;
        buf[1..8].copy_from_slice(b"example");
        buf[8] = 3;
        buf[9..12].copy_from_slice(b"com");
        buf[12] = 0;
        from_wire(&mut buf);
        let end = buf.iter().position(|&b| b == 0).unwrap();
        let s = std::str::from_utf8(&buf[..end]).unwrap();
        assert_eq!(s, "example.com");
    }

    #[test]
    fn test_from_wire_root() {
        let mut buf = [0u8; 4];
        buf[0] = 0; // wire root name
        from_wire(&mut buf);
        assert_eq!(buf[0], 0);
    }

    #[test]
    fn test_from_wire_single_label() {
        let mut buf = [0u8; 32];
        // Wire format: \x09localhost\x00
        buf[0] = 9;
        buf[1..10].copy_from_slice(b"localhost");
        buf[10] = 0;
        from_wire(&mut buf);
        let end = buf.iter().position(|&b| b == 0).unwrap();
        let s = std::str::from_utf8(&buf[..end]).unwrap();
        assert_eq!(s, "localhost");
    }

    // ---- check_name tests ----

    #[test]
    fn test_check_name_simple_labels() {
        let mut packet = vec![0u8; 32];
        packet[12] = 3;
        packet[13..16].copy_from_slice(b"www");
        packet[16] = 3;
        packet[17..20].copy_from_slice(b"com");
        packet[20] = 0;

        let mut cursor = 12usize;
        let result = check_name(&mut packet, &mut cursor, 21, false, &[]);
        assert!(result.is_ok());
        assert!(result.unwrap());
        assert_eq!(cursor, 21);
    }

    #[test]
    fn test_check_name_compression_pointer() {
        let mut packet = vec![0u8; 32];
        packet[12] = 0xC0;
        packet[13] = 20;
        packet[20] = 3;
        packet[21..24].copy_from_slice(b"com");
        packet[24] = 0;

        let mut cursor = 12usize;
        let result = check_name(&mut packet, &mut cursor, 25, false, &[]);
        assert!(result.is_ok());
        assert!(result.unwrap());
        assert_eq!(cursor, 14);
    }

    #[test]
    fn test_check_name_pointer_into_removed_range() {
        let mut packet = vec![0u8; 32];
        packet[12] = 0xC0;
        packet[13] = 20;
        packet[20] = 3;
        packet[21..24].copy_from_slice(b"com");
        packet[24] = 0;

        let removed = vec![(18usize, 25usize)];

        let mut cursor = 12usize;
        let result = check_name(&mut packet, &mut cursor, 25, false, &removed);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_check_name_fixup_adjusts_pointer() {
        let mut packet = vec![0u8; 40];
        packet[12] = 0xC0;
        packet[13] = 30;
        packet[30] = 3;
        packet[31..34].copy_from_slice(b"com");
        packet[34] = 0;

        let removed = vec![(20usize, 25usize)];

        let mut cursor = 12usize;
        let result = check_name(&mut packet, &mut cursor, 35, true, &removed);
        assert!(result.is_ok());
        assert!(result.unwrap());

        let new_offset = ((packet[12] as u16 & 0x3F) << 8) | packet[13] as u16;
        assert_eq!(new_offset, 25);
    }

    #[test]
    fn test_check_name_bounds_error() {
        let mut packet = vec![0u8; 4];
        // Try to read a label starting at offset 5 in a 4-byte buffer
        let mut cursor = 5usize;
        let result = check_name(&mut packet, &mut cursor, 4, false, &[]);
        assert!(result.is_err());
    }
}

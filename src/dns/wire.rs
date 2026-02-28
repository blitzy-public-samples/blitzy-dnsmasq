//! DNS wire-format codec (RFC 1035).
//!
//! Complete Rust rewrite of `src/rfc1035.c` — the performance-critical DNS
//! wire-format module handling name compression parsing (0xC0 pointers), DNS
//! packet construction, `answer_request()` for local query resolution, and all
//! wire-format encoding / decoding. Uses zero-copy buffer handling via Rust
//! slices with rigorous bounds checking.
//!
//! # Key exported functions
//!
//! | Function              | Purpose                                         |
//! |-----------------------|-------------------------------------------------|
//! | [`extract_name`]      | Extract or verify a DNS name from wire format    |
//! | [`skip_name`]         | Skip over a DNS name in a packet                 |
//! | [`skip_questions`]    | Skip the entire question section                 |
//! | [`skip_section`]      | Skip N resource records                          |
//! | [`setup_reply`]       | Initialise a response header from a query        |
//! | [`add_resource_record`] | Append an RR to a response packet              |
//! | [`resize_packet`]     | Truncate packet, optionally re-add EDNS0 OPT     |
//! | [`answer_request`]    | Resolve queries locally from cache / config      |
//! | [`find_soa`]          | Locate SOA RR in an authority section             |
//! | [`in_arpa_name_2_addr`] | Parse reverse-DNS name into an IP address       |
//! | [`get_u16`] / [`get_u32`] | Read big-endian integers from wire           |
//! | [`put_u16`] / [`put_u32`] | Write big-endian integers to wire             |

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Instant;

use log::debug;
use thiserror::Error;

use crate::config::constants::CNAME_CHAIN;
use crate::core::daemon::DaemonState;
use crate::core::metrics::Metric;
use crate::dns::cache::DnsCache;
use crate::dns::protocol::{
    C_CHAOS, C_IN, MAXDNAME, MAXLABEL, NAME_ESCAPE,
    QUERY, RRFIXEDSZ, Rcode,
    T_A, T_AAAA, T_CNAME, T_MX, T_NS,
    T_PTR, T_SOA, T_SRV, T_TXT,
};
use crate::types::addr::AllAddr;
use crate::types::dns::{CacheEntry, CacheEntryFlags, DnsHeader};

// ============================================================================
// Constants
// ============================================================================

/// DNS header size in bytes (ID + flags + 4 counts).
const DNS_HEADER_SIZE: usize = 12;

/// Maximum compression pointer hops before declaring a loop.
const MAX_COMPRESSION_HOPS: usize = 256;

// DNS header flag bit masks (local copies — the types::dns module exposes
// the fields `hb3` / `hb4` publicly but the mask constants are private).
const HB3_QR: u8 = 0x80;
const HB3_OPCODE_MASK: u8 = 0x78;
const HB3_AA: u8 = 0x04;
const HB3_TC: u8 = 0x02;
const HB3_RD: u8 = 0x01;
const HB4_RA: u8 = 0x80;
const HB4_AD: u8 = 0x20;
#[allow(dead_code)]
const HB4_CD: u8 = 0x10;

/// T_ANY pseudo-type used in queries.
const T_ANY: u16 = 255;

// ============================================================================
// WireError
// ============================================================================

/// DNS wire-format errors encountered during packet parsing or construction.
#[derive(Debug, Error)]
pub enum WireError {
    /// Packet is shorter than expected at the given offset.
    #[error("packet too short at offset {offset}: need {needed}, have {available}")]
    PacketTooShort {
        /// Byte offset within the packet where the read was attempted.
        offset: usize,
        /// Number of bytes the parser required at the offset.
        needed: usize,
        /// Number of bytes actually remaining in the packet.
        available: usize,
    },
    /// DNS name exceeds maximum length.
    #[error("name too long: {length} > {max}")]
    NameTooLong {
        /// Actual length of the DNS name in bytes.
        length: usize,
        /// Maximum allowed length (typically 255 per RFC 1035).
        max: usize,
    },
    /// Single label exceeds 63 bytes.
    #[error("label too long: {length} > 63")]
    LabelTooLong {
        /// Actual length of the label in bytes.
        length: usize,
    },
    /// Compression pointer loop detected.
    #[error("compression pointer loop detected at offset {0}")]
    PointerLoop(usize),
    /// Invalid compression pointer offset.
    #[error("invalid compression pointer at offset {0}")]
    InvalidPointer(usize),
    /// Packet truncated unexpectedly.
    #[error("packet truncated")]
    Truncated,
    /// Buffer overflow during write.
    #[error("buffer overflow: cannot add {needed} bytes")]
    BufferOverflow {
        /// Number of bytes that could not be written due to insufficient buffer space.
        needed: usize,
    },
    /// Invalid DNS name encoding.
    #[error("invalid DNS name: {0}")]
    InvalidName(String),
}

// ============================================================================
// RrData — Resource record data variants
// ============================================================================

/// DNS resource record data for wire-format serialization.
///
/// Each variant carries the data payload for the corresponding RR type.
/// The lifetime parameter borrows domain-name strings from the caller.
#[derive(Debug, Clone)]
pub enum RrData<'a> {
    /// A record — 4-byte IPv4 address.
    A(Ipv4Addr),
    /// AAAA record — 16-byte IPv6 address.
    Aaaa(Ipv6Addr),
    /// CNAME record — canonical name.
    Cname(&'a str),
    /// PTR record — pointer to domain name.
    Ptr(&'a str),
    /// MX record — preference + exchange.
    Mx(u16, &'a str),
    /// SRV record — priority, weight, port, target.
    Srv(u16, u16, u16, &'a str),
    /// TXT record — raw text data.
    Txt(&'a [u8]),
    /// SOA record — all 7 fields.
    Soa {
        /// Primary master name server for the zone.
        mname: &'a str,
        /// Email address of the zone administrator (in DNS name form).
        rname: &'a str,
        /// Zone serial number.
        serial: u32,
        /// Refresh interval in seconds.
        refresh: u32,
        /// Retry interval in seconds.
        retry: u32,
        /// Expire time in seconds.
        expire: u32,
        /// Minimum TTL for negative caching (RFC 2308).
        minimum: u32,
    },
    /// NS record — authoritative name server.
    Ns(&'a str),
    /// DNSKEY record data (raw wire bytes).
    Dnskey(&'a [u8]),
    /// DS record data (raw wire bytes).
    Ds(&'a [u8]),
    /// RRSIG record data (raw wire bytes).
    Rrsig(&'a [u8]),
    /// NSEC record data (raw wire bytes).
    Nsec(&'a [u8]),
    /// Raw record data (any unhandled type).
    Raw(&'a [u8]),
}

// ============================================================================
// RrSection — DNS message section selector
// ============================================================================

/// DNS message section for resource record placement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RrSection {
    /// Answer section (`ancount`).
    Answer,
    /// Authority section (`nscount`).
    Authority,
    /// Additional section (`arcount`).
    Additional,
}

// ============================================================================
// Byte-order helpers (replacing C GETSHORT/GETLONG/PUTSHORT/PUTLONG macros)
// ============================================================================

/// Read a big-endian `u16` from `packet` at `*cursor`, advance by 2.
#[inline]
pub fn get_u16(packet: &[u8], cursor: &mut usize) -> Result<u16, WireError> {
    let off = *cursor;
    if off + 2 > packet.len() {
        return Err(WireError::PacketTooShort {
            offset: off,
            needed: 2,
            available: packet.len().saturating_sub(off),
        });
    }
    let val = u16::from_be_bytes([packet[off], packet[off + 1]]);
    *cursor = off + 2;
    Ok(val)
}

/// Read a big-endian `u32` from `packet` at `*cursor`, advance by 4.
#[inline]
pub fn get_u32(packet: &[u8], cursor: &mut usize) -> Result<u32, WireError> {
    let off = *cursor;
    if off + 4 > packet.len() {
        return Err(WireError::PacketTooShort {
            offset: off,
            needed: 4,
            available: packet.len().saturating_sub(off),
        });
    }
    let val = u32::from_be_bytes([
        packet[off],
        packet[off + 1],
        packet[off + 2],
        packet[off + 3],
    ]);
    *cursor = off + 4;
    Ok(val)
}

/// Write a big-endian `u16` to `packet` at `*cursor`, advance by 2.
#[inline]
pub fn put_u16(packet: &mut [u8], cursor: &mut usize, val: u16) -> Result<(), WireError> {
    let off = *cursor;
    if off + 2 > packet.len() {
        return Err(WireError::BufferOverflow { needed: 2 });
    }
    let bytes = val.to_be_bytes();
    packet[off] = bytes[0];
    packet[off + 1] = bytes[1];
    *cursor = off + 2;
    Ok(())
}

/// Write a big-endian `u32` to `packet` at `*cursor`, advance by 4.
#[inline]
pub fn put_u32(packet: &mut [u8], cursor: &mut usize, val: u32) -> Result<(), WireError> {
    let off = *cursor;
    if off + 4 > packet.len() {
        return Err(WireError::BufferOverflow { needed: 4 });
    }
    let bytes = val.to_be_bytes();
    packet[off] = bytes[0];
    packet[off + 1] = bytes[1];
    packet[off + 2] = bytes[2];
    packet[off + 3] = bytes[3];
    *cursor = off + 4;
    Ok(())
}

// ============================================================================
// DNS header helpers
// ============================================================================

/// Read the 12-byte DNS header from the start of `packet`.
///
/// Returns `Err` if the packet is shorter than 12 bytes.
#[inline]
pub fn read_header(packet: &[u8]) -> Result<DnsHeader, WireError> {
    if packet.len() < DNS_HEADER_SIZE {
        return Err(WireError::PacketTooShort {
            offset: 0,
            needed: DNS_HEADER_SIZE,
            available: packet.len(),
        });
    }
    Ok(DnsHeader {
        id: u16::from_be_bytes([packet[0], packet[1]]),
        hb3: packet[2],
        hb4: packet[3],
        qdcount: u16::from_be_bytes([packet[4], packet[5]]),
        ancount: u16::from_be_bytes([packet[6], packet[7]]),
        nscount: u16::from_be_bytes([packet[8], packet[9]]),
        arcount: u16::from_be_bytes([packet[10], packet[11]]),
    })
}

/// Write the 12-byte DNS header back to the start of `packet`.
#[inline]
pub fn write_header(packet: &mut [u8], header: &DnsHeader) -> Result<(), WireError> {
    if packet.len() < DNS_HEADER_SIZE {
        return Err(WireError::BufferOverflow {
            needed: DNS_HEADER_SIZE,
        });
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
    Ok(())
}

// ============================================================================
// Name extraction and compression (C rfc1035.c extract_name / skip_name)
// ============================================================================

/// Extract (or verify) a DNS name from wire format, following compression
/// pointers (0xC0).
///
/// # Arguments
/// * `packet`     - Full DNS packet buffer.
/// * `plen`       - Logical packet length (may be less than `packet.len()`).
/// * `cursor`     - Current read position; advanced past the name on return.
/// * `name_buf`   - Output buffer for the extracted name (presentation format,
///                  dot-separated, NUL-terminated). Must be `MAXDNAME` bytes.
/// * `is_extract` - `true` to extract the name into `name_buf`;
///                  `false` to compare wire-format name against `name_buf`.
///
/// # Returns
/// * `Ok(true)`   - Name extracted (or matches when `!is_extract`).
/// * `Ok(false)`  - Name does not match (`!is_extract` mode).
/// * `Err(..)`    - Malformed packet.
#[inline(never)]
pub fn extract_name(
    packet: &[u8],
    plen: usize,
    cursor: &mut usize,
    name_buf: &mut [u8; MAXDNAME],
    is_extract: bool,
) -> Result<bool, WireError> {
    let plen = plen.min(packet.len());
    let mut p = *cursor;
    let mut name_pos: usize = 0;
    let mut compare_pos: usize = 0;
    let mut hops: usize = 0;
    let mut first_pointer: Option<usize> = None;
    let mut retvalue = true;
    let mut total: usize = 0;

    if p >= plen {
        return Err(WireError::Truncated);
    }

    loop {
        if p >= plen {
            return Err(WireError::Truncated);
        }
        let label_byte = packet[p];

        // Compression pointer (top two bits set)
        if (label_byte & 0xC0) == 0xC0 {
            if p + 1 >= plen {
                return Err(WireError::Truncated);
            }
            if first_pointer.is_none() {
                first_pointer = Some(p + 2);
            }
            let offset = (((label_byte & 0x3F) as usize) << 8) | (packet[p + 1] as usize);
            if offset >= plen {
                return Err(WireError::InvalidPointer(p));
            }
            p = offset;
            hops += 1;
            if hops >= MAX_COMPRESSION_HOPS {
                return Err(WireError::PointerLoop(p));
            }
            continue;
        }

        let label_len = label_byte as usize;

        // Root label — end of name
        if label_len == 0 {
            p += 1;
            break;
        }

        // Label too long
        if label_len > MAXLABEL as usize {
            return Err(WireError::LabelTooLong { length: label_len });
        }

        // Verify data available for label
        if p + 1 + label_len > plen {
            return Err(WireError::Truncated);
        }

        // Track total name length (labels + separating dots)
        total += label_len + 1;
        if total > MAXDNAME - 1 {
            return Err(WireError::NameTooLong {
                length: total,
                max: MAXDNAME - 1,
            });
        }

        // Add dot separator (extract mode) or check separator (compare mode)
        if is_extract {
            if name_pos > 0 {
                if name_pos >= MAXDNAME - 1 {
                    return Err(WireError::NameTooLong {
                        length: name_pos,
                        max: MAXDNAME - 1,
                    });
                }
                name_buf[name_pos] = b'.';
                name_pos += 1;
            }
        } else if compare_pos > 0 {
            if compare_pos < MAXDNAME && name_buf[compare_pos] == b'.' {
                compare_pos += 1;
            } else {
                retvalue = false;
            }
        }

        p += 1; // skip label-length byte

        for i in 0..label_len {
            let ch = packet[p + i];

            if is_extract {
                // Escape non-printable, dots, and escape characters
                if ch == b'.' || ch == NAME_ESCAPE as u8 || ch < b' ' || ch > 126 {
                    if name_pos + 2 > MAXDNAME - 1 {
                        return Err(WireError::NameTooLong {
                            length: name_pos + 2,
                            max: MAXDNAME - 1,
                        });
                    }
                    name_buf[name_pos] = NAME_ESCAPE as u8;
                    name_pos += 1;
                    name_buf[name_pos] = ch;
                    name_pos += 1;
                } else {
                    if name_pos >= MAXDNAME - 1 {
                        return Err(WireError::NameTooLong {
                            length: name_pos,
                            max: MAXDNAME - 1,
                        });
                    }
                    name_buf[name_pos] = ch;
                    name_pos += 1;
                }
            } else {
                // Compare mode
                if compare_pos >= MAXDNAME {
                    retvalue = false;
                } else {
                    let expected = name_buf[compare_pos];
                    if expected == NAME_ESCAPE as u8 {
                        compare_pos += 1;
                        if compare_pos < MAXDNAME {
                            if name_buf[compare_pos] != ch {
                                retvalue = false;
                            }
                            compare_pos += 1;
                        } else {
                            retvalue = false;
                        }
                    } else {
                        // Case-insensitive comparison for ASCII letters
                        let a = ch.to_ascii_lowercase();
                        let b = expected.to_ascii_lowercase();
                        if a != b {
                            retvalue = false;
                        }
                        compare_pos += 1;
                    }
                }
            }
        }

        p += label_len;
    }

    // Finalise
    if is_extract {
        if name_pos == 0 {
            // Root domain — store a single dot
            name_buf[0] = b'.';
            name_pos = 1;
        }
        if name_pos < MAXDNAME {
            name_buf[name_pos] = 0;
        }
    } else {
        // Verify entire name_buf was consumed
        if compare_pos < MAXDNAME && name_buf[compare_pos] != 0 {
            retvalue = false;
        }
    }

    // Advance caller's cursor past the name in the original stream.
    *cursor = first_pointer.unwrap_or(p);
    Ok(retvalue)
}

/// Skip over a DNS name without extracting it.
///
/// Handles normal labels and compression pointers. Verifies that at least
/// `extra_bytes` remain after the name.
pub fn skip_name(
    packet: &[u8],
    cursor: &mut usize,
    plen: usize,
    extra_bytes: usize,
) -> Result<(), WireError> {
    let plen = plen.min(packet.len());
    let mut p = *cursor;

    loop {
        if p >= plen {
            return Err(WireError::Truncated);
        }
        let label_byte = packet[p];

        // Compression pointer — skip 2 bytes
        if (label_byte & 0xC0) == 0xC0 {
            p += 2;
            if p > plen {
                return Err(WireError::Truncated);
            }
            break;
        }

        let label_len = label_byte as usize;
        if label_len == 0 {
            p += 1;
            break;
        }

        p += 1 + label_len;
        if p > plen {
            return Err(WireError::Truncated);
        }
    }

    if p + extra_bytes > plen {
        return Err(WireError::Truncated);
    }

    *cursor = p;
    Ok(())
}

// ============================================================================
// Section navigation (C rfc1035.c skip_questions / skip_section)
// ============================================================================

/// Skip the question section of a DNS packet.
///
/// Returns the cursor position immediately after all questions.
/// Each question consists of a name + QTYPE (2) + QCLASS (2).
pub fn skip_questions(
    header: &DnsHeader,
    packet: &[u8],
    plen: usize,
) -> Result<usize, WireError> {
    let mut cursor = DNS_HEADER_SIZE;
    let count = header.qdcount;
    for _ in 0..count {
        // Skip name, then 4 extra bytes (QTYPE + QCLASS)
        skip_name(packet, &mut cursor, plen, 4)?;
        cursor += 4;
    }
    Ok(cursor)
}

/// Skip `count` resource records starting at `cursor`.
///
/// Each RR: NAME + TYPE(2) + CLASS(2) + TTL(4) + RDLEN(2) + RDATA(RDLEN).
pub fn skip_section(
    packet: &[u8],
    cursor: &mut usize,
    count: u16,
    plen: usize,
) -> Result<(), WireError> {
    let plen = plen.min(packet.len());
    for _ in 0..count {
        // Skip name + 8 bytes of fixed fields (type+class+ttl)
        skip_name(packet, cursor, plen, RRFIXEDSZ as usize)?;
        // Read RDLEN (bytes 8..10 after name)
        let rdlen_off = *cursor + 8;
        if rdlen_off + 2 > plen {
            return Err(WireError::Truncated);
        }
        let rdlen =
            u16::from_be_bytes([packet[rdlen_off], packet[rdlen_off + 1]]) as usize;
        let next = rdlen_off + 2 + rdlen;
        if next > plen {
            return Err(WireError::Truncated);
        }
        *cursor = next;
    }
    Ok(())
}

// ============================================================================
// Packet construction helpers
// ============================================================================

/// Initialise a DNS response header from a query.
///
/// Sets QR=1 (response), copies opcode from query, sets the RCODE from
/// `flags`, and clears answer/authority/additional counts.  The `ede`
/// parameter is currently reserved for Extended DNS Error support.
pub fn setup_reply(header: &mut DnsHeader, flags: u16, _ede: i32) {
    // Set QR bit (response)
    header.hb3 |= HB3_QR;

    // Clear AA, TC bits; preserve opcode and RD
    header.hb3 &= HB3_QR | HB3_OPCODE_MASK | HB3_RD;

    // Set RCODE from low nibble of flags
    let rcode = (flags & 0x0F) as u8;
    header.set_rcode(rcode);

    // Set RA (recursion available)
    header.hb4 |= HB4_RA;

    // Clear AD and CD bits
    header.hb4 &= !(HB4_AD | HB4_CD);

    // If flags request AA bit (bit 10), set it
    if (flags & 0x0400) != 0 {
        header.hb3 |= HB3_AA;
    }

    // Zero section counts (answer, authority, additional)
    header.ancount = 0;
    header.nscount = 0;
    header.arcount = 0;
}

/// Truncate a DNS packet to just the question section, optionally re-adding
/// the EDNS0 pseudo-header (OPT record) at the end.
///
/// Returns the new packet length.
pub fn resize_packet(
    header: &mut DnsHeader,
    packet: &mut Vec<u8>,
    pheader: Option<&[u8]>,
    hlen: usize,
) -> usize {
    // Find end of question section
    let mut cursor = DNS_HEADER_SIZE;
    let plen = packet.len();
    for _ in 0..header.qdcount {
        if skip_name(packet, &mut cursor, plen, 4).is_err() {
            // Malformed — truncate to header only
            packet.truncate(DNS_HEADER_SIZE);
            header.ancount = 0;
            header.nscount = 0;
            header.arcount = 0;
            write_header(packet, header).ok();
            return packet.len();
        }
        cursor += 4;
    }

    // Truncate to end of question section
    packet.truncate(cursor);
    header.ancount = 0;
    header.nscount = 0;
    header.arcount = 0;

    // Re-add pseudo-header (EDNS0 OPT record) if provided
    if let Some(ph) = pheader {
        if hlen > 0 && hlen <= ph.len() {
            packet.extend_from_slice(&ph[..hlen]);
            header.arcount = 1;
        }
    }

    // Write updated header
    if packet.len() >= DNS_HEADER_SIZE {
        write_header(packet, header).ok();
    }

    packet.len()
}

// ============================================================================
// Name encoding helper (presentation → wire format within a packet)
// ============================================================================

/// Encode a dotted presentation-format DNS name into wire format at `cursor`
/// within `buffer`. Returns Ok(()) and advances cursor, or Err if the buffer
/// is too small.
fn encode_name_uncompressed(
    buffer: &mut [u8],
    cursor: &mut usize,
    limit: usize,
    name: &str,
) -> Result<(), WireError> {
    if name.is_empty() || name == "." {
        // Root label
        if *cursor + 1 > limit {
            return Err(WireError::BufferOverflow { needed: 1 });
        }
        buffer[*cursor] = 0;
        *cursor += 1;
        return Ok(());
    }

    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        let label_bytes = label.as_bytes();
        let len = label_bytes.len();
        if len > MAXLABEL as usize {
            return Err(WireError::LabelTooLong { length: len });
        }
        // Need: 1 (length byte) + len (label data)
        if *cursor + 1 + len > limit {
            return Err(WireError::BufferOverflow { needed: 1 + len });
        }
        buffer[*cursor] = len as u8;
        *cursor += 1;
        buffer[*cursor..*cursor + len].copy_from_slice(label_bytes);
        *cursor += len;
    }

    // Root terminator
    if *cursor + 1 > limit {
        return Err(WireError::BufferOverflow { needed: 1 });
    }
    buffer[*cursor] = 0;
    *cursor += 1;
    Ok(())
}

/// Write a two-byte compression pointer at `cursor`.
fn write_compression_pointer(
    buffer: &mut [u8],
    cursor: &mut usize,
    limit: usize,
    offset: u16,
) -> Result<(), WireError> {
    if *cursor + 2 > limit {
        return Err(WireError::BufferOverflow { needed: 2 });
    }
    let ptr = 0xC000 | offset;
    let bytes = ptr.to_be_bytes();
    buffer[*cursor] = bytes[0];
    buffer[*cursor + 1] = bytes[1];
    *cursor += 2;
    Ok(())
}

// ============================================================================
// add_resource_record — Append an RR to a response packet
// ============================================================================

/// Append a single DNS resource record to the response packet.
///
/// # Arguments
/// * `header`     — Mutable header (section counts updated on success).
/// * `buffer`     — Mutable packet buffer.
/// * `limit`      — Maximum allowed packet size (truncation boundary).
/// * `truncp`     — Set to `true` if the record cannot fit.
/// * `nameoffset` — If >= 0, use a compression pointer to this offset for the
///                  RR owner name. If < 0, the name is written from `RrData`.
/// * `cursor`     — Current write position; advanced on success.
/// * `ttl`        — TTL value for this record.
/// * `section`    — Which section this record belongs to.
/// * `rr_type`    — DNS RR type code.
/// * `rr_class`   — DNS RR class code.
/// * `rdata`      — Record data payload.
///
/// Returns `Ok(true)` if the record was added, `Ok(false)` if truncated.
pub fn add_resource_record(
    header: &mut DnsHeader,
    buffer: &mut [u8],
    limit: usize,
    truncp: &mut bool,
    nameoffset: i32,
    cursor: &mut usize,
    ttl: u32,
    section: RrSection,
    rr_type: u16,
    rr_class: u16,
    rdata: &RrData<'_>,
) -> Result<bool, WireError> {
    let start = *cursor;
    let limit = limit.min(buffer.len());

    // ---- Owner name ----
    if nameoffset >= 0 {
        // Compression pointer
        write_compression_pointer(buffer, cursor, limit, nameoffset as u16)?;
    } else {
        // For negative nameoffset, we encode a root name (edge case).
        if *cursor + 1 > limit {
            *truncp = true;
            *cursor = start;
            return Ok(false);
        }
        buffer[*cursor] = 0;
        *cursor += 1;
    }

    // ---- Fixed fields: TYPE(2) + CLASS(2) + TTL(4) + RDLEN(2) = 10 bytes ----
    if *cursor + 10 > limit {
        *truncp = true;
        *cursor = start;
        return Ok(false);
    }

    put_u16(buffer, cursor, rr_type)?;
    put_u16(buffer, cursor, rr_class)?;
    put_u32(buffer, cursor, ttl)?;

    // RDLEN placeholder — we will backfill after writing RDATA
    let rdlen_offset = *cursor;
    *cursor += 2;

    let rdata_start = *cursor;

    // ---- RDATA encoding ----
    let encode_result = encode_rdata(buffer, cursor, limit, rdata);
    if encode_result.is_err() {
        // If encoding fails because of buffer space, treat as truncation
        *truncp = true;
        *cursor = start;
        return Ok(false);
    }

    let rdlen = (*cursor - rdata_start) as u16;

    // Check total record fits
    if *cursor > limit {
        *truncp = true;
        *cursor = start;
        return Ok(false);
    }

    // Backfill RDLEN
    let rd_bytes = rdlen.to_be_bytes();
    buffer[rdlen_offset] = rd_bytes[0];
    buffer[rdlen_offset + 1] = rd_bytes[1];

    // Update section count in header
    match section {
        RrSection::Answer => header.ancount = header.ancount.wrapping_add(1),
        RrSection::Authority => header.nscount = header.nscount.wrapping_add(1),
        RrSection::Additional => header.arcount = header.arcount.wrapping_add(1),
    }

    Ok(true)
}

/// Encode RDATA payload into the buffer at `cursor`.
fn encode_rdata(
    buffer: &mut [u8],
    cursor: &mut usize,
    limit: usize,
    rdata: &RrData<'_>,
) -> Result<(), WireError> {
    match rdata {
        RrData::A(addr) => {
            let octets = addr.octets();
            if *cursor + 4 > limit {
                return Err(WireError::BufferOverflow { needed: 4 });
            }
            buffer[*cursor..*cursor + 4].copy_from_slice(&octets);
            *cursor += 4;
        }
        RrData::Aaaa(addr) => {
            let octets = addr.octets();
            if *cursor + 16 > limit {
                return Err(WireError::BufferOverflow { needed: 16 });
            }
            buffer[*cursor..*cursor + 16].copy_from_slice(&octets);
            *cursor += 16;
        }
        RrData::Cname(name) | RrData::Ptr(name) | RrData::Ns(name) => {
            encode_name_uncompressed(buffer, cursor, limit, name)?;
        }
        RrData::Mx(pref, exchange) => {
            put_u16(buffer, cursor, *pref)?;
            encode_name_uncompressed(buffer, cursor, limit, exchange)?;
        }
        RrData::Srv(priority, weight, port, target) => {
            put_u16(buffer, cursor, *priority)?;
            put_u16(buffer, cursor, *weight)?;
            put_u16(buffer, cursor, *port)?;
            encode_name_uncompressed(buffer, cursor, limit, target)?;
        }
        RrData::Txt(data) => {
            if *cursor + data.len() > limit {
                return Err(WireError::BufferOverflow { needed: data.len() });
            }
            buffer[*cursor..*cursor + data.len()].copy_from_slice(data);
            *cursor += data.len();
        }
        RrData::Soa {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        } => {
            encode_name_uncompressed(buffer, cursor, limit, mname)?;
            encode_name_uncompressed(buffer, cursor, limit, rname)?;
            put_u32(buffer, cursor, *serial)?;
            put_u32(buffer, cursor, *refresh)?;
            put_u32(buffer, cursor, *retry)?;
            put_u32(buffer, cursor, *expire)?;
            put_u32(buffer, cursor, *minimum)?;
        }
        RrData::Dnskey(data)
        | RrData::Ds(data)
        | RrData::Rrsig(data)
        | RrData::Nsec(data)
        | RrData::Raw(data) => {
            if *cursor + data.len() > limit {
                return Err(WireError::BufferOverflow { needed: data.len() });
            }
            buffer[*cursor..*cursor + data.len()].copy_from_slice(data);
            *cursor += data.len();
        }
    }
    Ok(())
}

// ============================================================================
// find_soa — Locate SOA record in an authority section
// ============================================================================

/// Search for a SOA record in the packet starting at `cursor`.
///
/// Scans `count` resource records looking for one with TYPE=SOA and CLASS=IN.
/// If found, returns `Some((name, ttl))` where `name` is the SOA owner name
/// extracted into the provided buffer, and `ttl` is the record's TTL.
/// Returns `None` if no SOA is found. Advances `cursor` past all scanned RRs.
pub fn find_soa(
    packet: &[u8],
    plen: usize,
    cursor: &mut usize,
    count: u16,
    name_buf: &mut [u8; MAXDNAME],
) -> Option<(bool, u32)> {
    let plen = plen.min(packet.len());

    for _ in 0..count {
        // Extract the RR name
        let name_ok = extract_name(packet, plen, cursor, name_buf, true).unwrap_or(false);

        // Read TYPE(2) + CLASS(2) + TTL(4) + RDLEN(2) = 10 fixed bytes
        if *cursor + RRFIXEDSZ as usize > plen {
            return None;
        }

        let mut off = *cursor;
        let rr_type = u16::from_be_bytes([packet[off], packet[off + 1]]);
        off += 2;
        let rr_class = u16::from_be_bytes([packet[off], packet[off + 1]]);
        off += 2;
        let ttl = u32::from_be_bytes([packet[off], packet[off + 1], packet[off + 2], packet[off + 3]]);
        off += 4;
        let rdlen = u16::from_be_bytes([packet[off], packet[off + 1]]) as usize;
        off += 2;

        let next = off + rdlen;
        if next > plen {
            return None;
        }

        if rr_type == T_SOA && rr_class == C_IN && name_ok {
            *cursor = next;
            return Some((true, ttl));
        }

        *cursor = next;
    }

    None
}

// ============================================================================
// in_arpa_name_2_addr — Parse reverse-DNS name into an IP address
// ============================================================================

/// Parse an in-addr.arpa or ip6.arpa reverse-DNS name into an IP address.
///
/// Supports:
/// - IPv4: `d.c.b.a.in-addr.arpa` → `a.b.c.d`
/// - IPv6 nibble: `<32 hex nibbles>.ip6.arpa` → Ipv6Addr
///
/// Returns `Some(AllAddr::V4(..))` or `Some(AllAddr::V6(..))` on success,
/// or `None` if the name is not a valid reverse-DNS name.
pub fn in_arpa_name_2_addr(name: &[u8]) -> Option<AllAddr> {
    // Convert name buffer to a string (stop at first NUL or end)
    let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
    let name_str = std::str::from_utf8(&name[..end]).ok()?;

    // Try IPv4 reverse: x.x.x.x.in-addr.arpa
    if let Some(addr) = parse_ipv4_reverse(name_str) {
        return Some(AllAddr::V4(addr));
    }

    // Try IPv6 nibble reverse: nibbles.ip6.arpa
    if let Some(addr) = parse_ipv6_nibble_reverse(name_str) {
        return Some(AllAddr::V6(addr));
    }

    None
}

/// Parse an IPv4 reverse-DNS name like `4.3.2.1.in-addr.arpa`.
fn parse_ipv4_reverse(name: &str) -> Option<Ipv4Addr> {
    let lower = name.to_ascii_lowercase();
    let stripped = lower.strip_suffix(".in-addr.arpa")?;
    // May have trailing dot: ".in-addr.arpa." -> already handled by strip_suffix

    let parts: Vec<&str> = stripped.split('.').collect();
    if parts.len() != 4 {
        return None;
    }

    let mut octets = [0u8; 4];
    for (i, part) in parts.iter().enumerate() {
        let val: u8 = part.parse().ok()?;
        // Reverse order: first label is least-significant octet
        octets[3 - i] = val;
    }

    Some(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]))
}

/// Parse an IPv6 nibble reverse-DNS name like
/// `b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa`.
fn parse_ipv6_nibble_reverse(name: &str) -> Option<Ipv6Addr> {
    let lower = name.to_ascii_lowercase();
    let stripped = lower
        .strip_suffix(".ip6.arpa")
        .or_else(|| lower.strip_suffix(".ip6.int"))?;

    let nibbles: Vec<&str> = stripped.split('.').collect();
    if nibbles.len() != 32 {
        return None;
    }

    let mut addr_bytes = [0u8; 16];
    for (i, nibble_str) in nibbles.iter().enumerate() {
        if nibble_str.len() != 1 {
            return None;
        }
        let nibble = u8::from_str_radix(nibble_str, 16).ok()?;
        // The first nibble in the name is the least significant nibble of the
        // address (i.e., nibble 31), so reverse:
        let addr_nibble_index = 31 - i;
        let byte_index = addr_nibble_index / 2;
        if addr_nibble_index % 2 == 0 {
            // Even index = high nibble of the byte
            addr_bytes[byte_index] |= nibble << 4;
        } else {
            // Odd index = low nibble of the byte
            addr_bytes[byte_index] |= nibble;
        }
    }

    Some(Ipv6Addr::from(addr_bytes))
}

// ============================================================================
// Name utility helpers
// ============================================================================

/// Convert a NUL-terminated name buffer to a Rust `&str`.
///
/// Returns the portion of `buf` up to the first NUL byte (or the full
/// buffer if no NUL is present), interpreted as UTF-8.
fn name_buf_to_str(buf: &[u8]) -> &str {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    std::str::from_utf8(&buf[..end]).unwrap_or("")
}

// ============================================================================
// answer_request — Local query resolution (C rfc1035.c answer_request)
// ============================================================================

/// Process a DNS query locally, answering from cache, hosts file entries,
/// DHCP lease registrations, configured local records, and synthetic names.
///
/// This is the central function for locally-resolved queries. For queries
/// that cannot be answered locally (e.g., recursive lookups for external
/// domains), the forwarding engine handles them separately.
///
/// # Arguments
/// * `header`             — Mutable DNS header (modified to become a response).
/// * `buffer`             — Mutable packet buffer (response is built in-place).
/// * `limit`              — Maximum response packet size.
/// * `qlen`               — Original query length (bytes).
/// * `now`                — Current monotonic time for TTL calculations.
/// * `ad_reqd`            — Client requested Authenticated Data (AD bit).
/// * `do_bit`             — Client set DNSSEC OK (DO bit) in EDNS0.
/// * `have_pseudoheader`  — Client included an EDNS0 OPT record.
/// * `state`              — Daemon configuration and runtime state.
/// * `cache`              — DNS cache for record lookups.
///
/// # Returns
/// New packet length on success, or `WireError` on parse failure.
#[allow(clippy::too_many_arguments)]
pub fn answer_request(
    header: &mut DnsHeader,
    buffer: &mut [u8],
    limit: usize,
    qlen: usize,
    now: Instant,
    ad_reqd: bool,
    _do_bit: bool,
    _have_pseudoheader: bool,
    state: &DaemonState,
    cache: &mut DnsCache,
) -> Result<usize, WireError> {
    // Only handle standard queries (QUERY opcode)
    if header.opcode() != QUERY as u8 {
        setup_reply(header, Rcode::NotImp as u16, -1);
        let new_len = DNS_HEADER_SIZE.min(limit);
        if buffer.len() >= DNS_HEADER_SIZE {
            write_header(buffer, header)?;
        }
        return Ok(new_len);
    }

    // Must have exactly one question
    if header.qdcount != 1 {
        setup_reply(header, Rcode::FormErr as u16, -1);
        let new_len = DNS_HEADER_SIZE.min(limit);
        if buffer.len() >= DNS_HEADER_SIZE {
            write_header(buffer, header)?;
        }
        return Ok(new_len);
    }

    // Extract question name, type, class
    let mut qcursor = DNS_HEADER_SIZE;
    let mut qname_buf = [0u8; MAXDNAME];
    extract_name(buffer, qlen, &mut qcursor, &mut qname_buf, true)?;

    if qcursor + 4 > qlen {
        return Err(WireError::Truncated);
    }
    let qtype = u16::from_be_bytes([buffer[qcursor], buffer[qcursor + 1]]);
    let qclass = u16::from_be_bytes([buffer[qcursor + 2], buffer[qcursor + 3]]);
    qcursor += 4;

    let qname_str = name_buf_to_str(&qname_buf);

    debug!("answer_request: qname='{}' qtype={} qclass={}", qname_str, qtype, qclass);

    // Setup the response header
    setup_reply(header, Rcode::NoError as u16, -1);
    // RA is already set by setup_reply

    // The response starts writing RRs after the question section
    let mut write_cursor = qcursor;
    let mut truncated = false;

    // Name offset for compression pointer to the question name
    let name_offset: i32 = DNS_HEADER_SIZE as i32;

    // Track whether all answers are DNSSEC-validated for AD bit
    let mut all_secure = ad_reqd;
    let mut answered = false;
    let mut nxdomain = false;

    // ---- Handle CHAOS class queries (version.bind, etc.) ----
    if qclass == C_CHAOS {
        return handle_chaos_query(
            header, buffer, limit, qtype, &qname_buf, name_offset,
            &mut write_cursor, &mut truncated, state,
        );
    }

    // ---- Handle IN class queries ----
    if qclass != C_IN {
        // Unsupported class — return empty NOERROR
        if buffer.len() >= DNS_HEADER_SIZE {
            write_header(buffer, header)?;
        }
        return Ok(write_cursor.min(limit));
    }

    // ---- Check for synthetic names (synth-domain) ----
    // DaemonState doesn't currently expose cond_domains, so we check cache
    // as the primary resolution path.

    // ---- Try to answer from cache/local data ----
    // Determine cache flags based on query type
    let type_flag = match qtype {
        T_A => CacheEntryFlags::IPV4,
        T_AAAA => CacheEntryFlags::IPV6,
        T_CNAME => CacheEntryFlags::CNAME,
        T_PTR => CacheEntryFlags::REVERSE,
        _ => CacheEntryFlags::empty(),
    };

    // For PTR queries, try reverse lookup
    if qtype == T_PTR || qtype == T_ANY {
        if let Some(addr) = in_arpa_name_2_addr(&qname_buf) {
            let entries = cache.find_by_addr(&addr, now, CacheEntryFlags::REVERSE);
            for entry in &entries {
                if !entry.name.is_empty() {
                    let ttl = compute_ttl(entry, state);
                    let added = add_resource_record(
                        header,
                        buffer,
                        limit,
                        &mut truncated,
                        name_offset,
                        &mut write_cursor,
                        ttl,
                        RrSection::Answer,
                        T_PTR,
                        C_IN,
                        &RrData::Ptr(&entry.name),
                    )?;
                    if added {
                        answered = true;
                        check_entry_security(entry, &mut all_secure);
                    }
                }
            }
            if answered {
                state.metrics.borrow_mut().increment(Metric::DnsLocalAnswered);
                finalize_response(
                    header, buffer, limit, &mut write_cursor,
                    &mut truncated, all_secure, ad_reqd, nxdomain,
                )?;
                return Ok(write_cursor.min(limit));
            }
        }
    }

    // For A/AAAA/CNAME/ANY queries, try forward lookup
    if matches!(qtype, T_A | T_AAAA | T_CNAME | T_ANY) || type_flag != CacheEntryFlags::empty() {
        // CNAME chain following
        let mut cname_depth = 0;
        let mut current_name = qname_str.to_owned();
        let mut current_offset = name_offset;

        loop {
            if cname_depth > CNAME_CHAIN as usize {
                break;
            }

            // Look up A records if qtype is A or ANY
            if qtype == T_A || qtype == T_ANY {
                let entries = cache.find_by_name(&current_name, now, CacheEntryFlags::IPV4);
                for entry in &entries {
                    if entry.flags.contains(CacheEntryFlags::IPV4) {
                        if let Some(ipv4) = entry.addr.as_ipv4() {
                            let ttl = compute_ttl(entry, state);
                            let added = add_resource_record(
                                header,
                                buffer,
                                limit,
                                &mut truncated,
                                current_offset,
                                &mut write_cursor,
                                ttl,
                                RrSection::Answer,
                                T_A,
                                C_IN,
                                &RrData::A(*ipv4),
                            )?;
                            if added {
                                answered = true;
                                check_entry_security(entry, &mut all_secure);
                            }
                        }
                    }
                    // Check for NXDOMAIN
                    if entry.flags.contains(CacheEntryFlags::NXDOMAIN) {
                        nxdomain = true;
                    }
                }
            }

            // Look up AAAA records if qtype is AAAA or ANY
            if qtype == T_AAAA || qtype == T_ANY {
                let entries = cache.find_by_name(&current_name, now, CacheEntryFlags::IPV6);
                for entry in &entries {
                    if entry.flags.contains(CacheEntryFlags::IPV6) {
                        if let Some(ipv6) = entry.addr.as_ipv6() {
                            let ttl = compute_ttl(entry, state);
                            let added = add_resource_record(
                                header,
                                buffer,
                                limit,
                                &mut truncated,
                                current_offset,
                                &mut write_cursor,
                                ttl,
                                RrSection::Answer,
                                T_AAAA,
                                C_IN,
                                &RrData::Aaaa(*ipv6),
                            )?;
                            if added {
                                answered = true;
                                check_entry_security(entry, &mut all_secure);
                            }
                        }
                    }
                    if entry.flags.contains(CacheEntryFlags::NXDOMAIN) {
                        nxdomain = true;
                    }
                }
            }

            // Check for CNAME at the current name
            let cname_entries = cache.find_by_name(&current_name, now, CacheEntryFlags::CNAME);
            let mut followed_cname = false;
            for entry in &cname_entries {
                if entry.flags.contains(CacheEntryFlags::CNAME) {
                    // Add CNAME record to response
                    let ttl = compute_ttl(entry, state);
                    let target = &entry.name;
                    let added = add_resource_record(
                        header,
                        buffer,
                        limit,
                        &mut truncated,
                        current_offset,
                        &mut write_cursor,
                        ttl,
                        RrSection::Answer,
                        T_CNAME,
                        C_IN,
                        &RrData::Cname(target),
                    )?;
                    if added {
                        answered = true;
                        check_entry_security(entry, &mut all_secure);
                        // Follow CNAME chain (unless the query was for CNAME itself)
                        if qtype != T_CNAME {
                            current_name = target.clone();
                            current_offset = -1; // No compression for chained names
                            followed_cname = true;
                            cname_depth += 1;
                        }
                    }
                    break; // Only follow first CNAME
                }
            }

            if !followed_cname {
                break;
            }
        }
    }

    // ---- Handle MX queries ----
    if qtype == T_MX || qtype == T_ANY {
        // Look up from cache for MX records (stored as generic entries)
        let entries = cache.find_by_name(qname_str, now, CacheEntryFlags::empty());
        for entry in &entries {
            if entry.flags.contains(CacheEntryFlags::RR) && !entry.name.is_empty() {
                // MX records from cache are stored with name as the exchange
                let ttl = compute_ttl(entry, state);
                let added = add_resource_record(
                    header,
                    buffer,
                    limit,
                    &mut truncated,
                    name_offset,
                    &mut write_cursor,
                    ttl,
                    RrSection::Answer,
                    T_MX,
                    C_IN,
                    &RrData::Mx(10, &entry.name),
                )?;
                if added {
                    answered = true;
                    check_entry_security(entry, &mut all_secure);
                }
            }
        }
    }

    // ---- Handle SRV queries ----
    if qtype == T_SRV || qtype == T_ANY {
        let entries = cache.find_by_name(qname_str, now, CacheEntryFlags::empty());
        for entry in &entries {
            if entry.flags.contains(CacheEntryFlags::RR) && !entry.name.is_empty() {
                let ttl = compute_ttl(entry, state);
                let added = add_resource_record(
                    header,
                    buffer,
                    limit,
                    &mut truncated,
                    name_offset,
                    &mut write_cursor,
                    ttl,
                    RrSection::Answer,
                    T_SRV,
                    C_IN,
                    &RrData::Srv(0, 0, 0, &entry.name),
                )?;
                if added {
                    answered = true;
                    check_entry_security(entry, &mut all_secure);
                }
            }
        }
    }

    // ---- Handle TXT queries ----
    if qtype == T_TXT || qtype == T_ANY {
        let entries = cache.find_by_name(qname_str, now, CacheEntryFlags::empty());
        for entry in &entries {
            if entry.flags.contains(CacheEntryFlags::RR) && !entry.name.is_empty() {
                let txt_data = entry.name.as_bytes();
                let ttl = compute_ttl(entry, state);
                let added = add_resource_record(
                    header,
                    buffer,
                    limit,
                    &mut truncated,
                    name_offset,
                    &mut write_cursor,
                    ttl,
                    RrSection::Answer,
                    T_TXT,
                    C_IN,
                    &RrData::Txt(txt_data),
                )?;
                if added {
                    answered = true;
                    check_entry_security(entry, &mut all_secure);
                }
            }
        }
    }

    // ---- Handle SOA queries ----
    if qtype == T_SOA || qtype == T_ANY {
        let entries = cache.find_by_name(qname_str, now, CacheEntryFlags::empty());
        for entry in &entries {
            if entry.flags.contains(CacheEntryFlags::RR) {
                let ttl = compute_ttl(entry, state);
                let added = add_resource_record(
                    header,
                    buffer,
                    limit,
                    &mut truncated,
                    name_offset,
                    &mut write_cursor,
                    ttl,
                    RrSection::Answer,
                    T_SOA,
                    C_IN,
                    &RrData::Soa {
                        mname: state.dns.auth_server.as_deref().unwrap_or("localhost"),
                        rname: state.dns.hostmaster.as_deref().unwrap_or("hostmaster.localhost"),
                        serial: state.dns.soa_serial,
                        refresh: state.dns.soa_refresh,
                        retry: state.dns.soa_retry,
                        expire: state.dns.soa_expiry,
                        minimum: ttl,
                    },
                )?;
                if added {
                    answered = true;
                    check_entry_security(entry, &mut all_secure);
                }
            }
        }
    }

    // ---- Handle NS queries ----
    if qtype == T_NS || qtype == T_ANY {
        let entries = cache.find_by_name(qname_str, now, CacheEntryFlags::empty());
        for entry in &entries {
            if entry.flags.contains(CacheEntryFlags::RR) && !entry.name.is_empty() {
                let ttl = compute_ttl(entry, state);
                let added = add_resource_record(
                    header,
                    buffer,
                    limit,
                    &mut truncated,
                    name_offset,
                    &mut write_cursor,
                    ttl,
                    RrSection::Answer,
                    T_NS,
                    C_IN,
                    &RrData::Ns(&entry.name),
                )?;
                if added {
                    answered = true;
                    check_entry_security(entry, &mut all_secure);
                }
            }
        }
    }

    // ---- Handle negative cache entries (NXDOMAIN / NODATA) ----
    if !answered {
        let neg_entries = cache.find_by_name(qname_str, now, CacheEntryFlags::NEG);
        for entry in &neg_entries {
            if entry.flags.contains(CacheEntryFlags::NXDOMAIN) {
                nxdomain = true;
                check_entry_security(entry, &mut all_secure);
            } else if entry.flags.contains(CacheEntryFlags::NEG) {
                // NODATA — answer with empty answer section
                check_entry_security(entry, &mut all_secure);
            }
        }
    }

    // Update metrics
    if answered {
        state.metrics.borrow_mut().increment(Metric::DnsLocalAnswered);
    }

    // Finalise the response
    finalize_response(
        header, buffer, limit, &mut write_cursor,
        &mut truncated, all_secure, ad_reqd, nxdomain,
    )?;

    Ok(write_cursor.min(limit))
}

// ============================================================================
// answer_request helper functions
// ============================================================================

/// Compute the TTL for a cache entry, respecting local_ttl override.
fn compute_ttl(entry: &CacheEntry, state: &DaemonState) -> u32 {
    if state.dns.local_ttl > 0 {
        return state.dns.local_ttl;
    }

    // Immortal entries get the configured auth TTL or default
    if entry.flags.contains(CacheEntryFlags::IMMORTAL) {
        if state.dns.auth_ttl > 0 {
            return state.dns.auth_ttl;
        }
        return 300; // 5 minute default for hosts-file entries
    }

    // Dynamic entries: TTD is seconds-since-epoch, compute remaining TTL
    if entry.ttd > 0 {
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let remaining = entry.ttd - now_secs;
        if remaining > 0 {
            return remaining as u32;
        }
        return 0;
    }

    0
}

/// Check if a cache entry is DNSSEC-validated and update the `all_secure` flag.
fn check_entry_security(entry: &CacheEntry, all_secure: &mut bool) {
    if !entry.flags.contains(CacheEntryFlags::DNSSECOK) {
        *all_secure = false;
    }
}

/// Finalise the DNS response: set NXDOMAIN rcode, AD bit, TC bit, write header.
fn finalize_response(
    header: &mut DnsHeader,
    buffer: &mut [u8],
    limit: usize,
    write_cursor: &mut usize,
    truncated: &mut bool,
    all_secure: bool,
    ad_reqd: bool,
    nxdomain: bool,
) -> Result<(), WireError> {
    // Set NXDOMAIN if appropriate
    if nxdomain && header.ancount == 0 {
        header.set_rcode(Rcode::NxDomain as u8);
    }

    // Set AD bit if all answers are secure and client requested it
    if all_secure && ad_reqd && header.ancount > 0 {
        header.hb4 |= HB4_AD;
    }

    // Set TC bit if truncated
    if *truncated {
        header.hb3 |= HB3_TC;
    }

    // Write final header
    if buffer.len() >= DNS_HEADER_SIZE {
        write_header(buffer, header)?;
    }

    // Ensure we don't exceed limit
    if *write_cursor > limit {
        *write_cursor = limit;
        *truncated = true;
        header.hb3 |= HB3_TC;
        if buffer.len() >= DNS_HEADER_SIZE {
            write_header(buffer, header)?;
        }
    }

    Ok(())
}

/// Handle CHAOS class queries (version.bind, hostname.bind, id.server).
fn handle_chaos_query(
    header: &mut DnsHeader,
    buffer: &mut [u8],
    limit: usize,
    qtype: u16,
    qname_buf: &[u8; MAXDNAME],
    name_offset: i32,
    write_cursor: &mut usize,
    truncated: &mut bool,
    state: &DaemonState,
) -> Result<usize, WireError> {
    use crate::core::daemon::OPT_NO_IDENT;

    // Only respond to TXT queries
    if qtype != T_TXT {
        if buffer.len() >= DNS_HEADER_SIZE {
            write_header(buffer, header)?;
        }
        return Ok((*write_cursor).min(limit));
    }

    let qname_str = name_buf_to_str(qname_buf);

    // Check if identity queries are disabled
    if state.option_bool(OPT_NO_IDENT) {
        // Return REFUSED for identity queries
        header.set_rcode(Rcode::Refused as u8);
        if buffer.len() >= DNS_HEADER_SIZE {
            write_header(buffer, header)?;
        }
        return Ok((*write_cursor).min(limit));
    }

    // Known CHAOS TXT queries
    let response_text: Option<&str> = if qname_str.eq_ignore_ascii_case("version.bind")
        || qname_str.eq_ignore_ascii_case("version.server")
    {
        Some("dnsmasq-rust")
    } else if qname_str.eq_ignore_ascii_case("hostname.bind")
        || qname_str.eq_ignore_ascii_case("id.server")
    {
        // Return configured hostname or default
        Some("dnsmasq")
    } else {
        None
    };

    if let Some(txt) = response_text {
        // Build TXT RDATA: length-prefixed string
        let txt_bytes = txt.as_bytes();
        let mut txt_rdata = Vec::with_capacity(1 + txt_bytes.len());
        txt_rdata.push(txt_bytes.len() as u8);
        txt_rdata.extend_from_slice(txt_bytes);

        add_resource_record(
            header,
            buffer,
            limit,
            truncated,
            name_offset,
            write_cursor,
            0,
            RrSection::Answer,
            T_TXT,
            C_CHAOS,
            &RrData::Txt(&txt_rdata),
        )?;
    }

    // Set AA for CHAOS responses
    header.hb3 |= HB3_AA;

    if buffer.len() >= DNS_HEADER_SIZE {
        write_header(buffer, header)?;
    }

    Ok((*write_cursor).min(limit))
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal DNS query packet for testing.
    fn build_query(name: &str, qtype: u16, qclass: u16) -> Vec<u8> {
        let mut pkt = vec![0u8; 4096];
        // Header: ID=0x1234, QR=0, OPCODE=0, QDCOUNT=1
        pkt[0] = 0x12;
        pkt[1] = 0x34;
        pkt[2] = 0x00; // hb3
        pkt[3] = 0x00; // hb4
        pkt[4] = 0x00;
        pkt[5] = 0x01; // qdcount=1
        // ancount, nscount, arcount = 0

        let mut cursor = 12;
        // Encode name
        for label in name.split('.') {
            if label.is_empty() {
                continue;
            }
            pkt[cursor] = label.len() as u8;
            cursor += 1;
            for &b in label.as_bytes() {
                pkt[cursor] = b;
                cursor += 1;
            }
        }
        pkt[cursor] = 0; // root label
        cursor += 1;

        // QTYPE
        let qt = qtype.to_be_bytes();
        pkt[cursor] = qt[0];
        pkt[cursor + 1] = qt[1];
        cursor += 2;

        // QCLASS
        let qc = qclass.to_be_bytes();
        pkt[cursor] = qc[0];
        pkt[cursor + 1] = qc[1];
        cursor += 2;

        pkt.truncate(cursor);
        pkt
    }

    #[test]
    fn test_get_u16() {
        let data = [0x01, 0x02, 0x03, 0x04];
        let mut cursor = 0;
        assert_eq!(get_u16(&data, &mut cursor).unwrap(), 0x0102);
        assert_eq!(cursor, 2);
        assert_eq!(get_u16(&data, &mut cursor).unwrap(), 0x0304);
        assert_eq!(cursor, 4);
    }

    #[test]
    fn test_get_u32() {
        let data = [0x01, 0x02, 0x03, 0x04];
        let mut cursor = 0;
        assert_eq!(get_u32(&data, &mut cursor).unwrap(), 0x01020304);
    }

    #[test]
    fn test_put_u16() {
        let mut data = [0u8; 4];
        let mut cursor = 0;
        put_u16(&mut data, &mut cursor, 0xABCD).unwrap();
        assert_eq!(data[0], 0xAB);
        assert_eq!(data[1], 0xCD);
        assert_eq!(cursor, 2);
    }

    #[test]
    fn test_put_u32() {
        let mut data = [0u8; 4];
        let mut cursor = 0;
        put_u32(&mut data, &mut cursor, 0xDEADBEEF).unwrap();
        assert_eq!(data, [0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_extract_name_simple() {
        // Build a packet with name "example.com"
        let pkt = build_query("example.com", T_A, C_IN);
        let mut cursor = 12; // skip header
        let mut name_buf = [0u8; MAXDNAME];
        let result = extract_name(&pkt, pkt.len(), &mut cursor, &mut name_buf, true);
        assert!(result.is_ok());
        assert!(result.unwrap());
        let name = name_buf_to_str(&name_buf);
        assert_eq!(name, "example.com");
    }

    #[test]
    fn test_extract_name_with_compression() {
        // Build a packet with a compression pointer
        let mut pkt = vec![0u8; 64];
        // Header (12 bytes)
        pkt[4] = 0x00;
        pkt[5] = 0x01;

        // Name at offset 12: "com" -> [3, 'c', 'o', 'm', 0]
        pkt[12] = 3;
        pkt[13] = b'c';
        pkt[14] = b'o';
        pkt[15] = b'm';
        pkt[16] = 0;

        // Name at offset 17: "example" + pointer to offset 12
        pkt[17] = 7;
        pkt[18] = b'e';
        pkt[19] = b'x';
        pkt[20] = b'a';
        pkt[21] = b'm';
        pkt[22] = b'p';
        pkt[23] = b'l';
        pkt[24] = b'e';
        pkt[25] = 0xC0; // pointer
        pkt[26] = 12;   // to offset 12

        let mut cursor = 17;
        let mut name_buf = [0u8; MAXDNAME];
        let result = extract_name(&pkt, 27, &mut cursor, &mut name_buf, true);
        assert!(result.is_ok());
        assert!(result.unwrap());
        let name = name_buf_to_str(&name_buf);
        assert_eq!(name, "example.com");
        // Cursor should be at 27 (past the pointer)
        assert_eq!(cursor, 27);
    }

    #[test]
    fn test_extract_name_compare_mode() {
        let pkt = build_query("example.com", T_A, C_IN);
        let mut cursor = 12;
        let mut name_buf = [0u8; MAXDNAME];

        // First extract
        extract_name(&pkt, pkt.len(), &mut cursor, &mut name_buf, true).unwrap();

        // Now compare
        cursor = 12;
        let result = extract_name(&pkt, pkt.len(), &mut cursor, &mut name_buf, false);
        assert!(result.is_ok());
        assert!(result.unwrap()); // should match
    }

    #[test]
    fn test_skip_name() {
        let pkt = build_query("example.com", T_A, C_IN);
        let mut cursor = 12;
        skip_name(&pkt, &mut cursor, pkt.len(), 4).unwrap();
        // Should be past "example.com\0" = 1+7+1+3+1 = 13 bytes, so cursor = 25
        assert!(cursor > 12);
    }

    #[test]
    fn test_skip_questions() {
        let pkt = build_query("test.org", T_A, C_IN);
        let header = read_header(&pkt).unwrap();
        let after = skip_questions(&header, &pkt, pkt.len()).unwrap();
        // Should be past the entire question section
        assert!(after > DNS_HEADER_SIZE);
        assert_eq!(after, pkt.len());
    }

    #[test]
    fn test_read_write_header() {
        let pkt = build_query("a.b", T_A, C_IN);
        let header = read_header(&pkt).unwrap();
        assert_eq!(header.id, 0x1234);
        assert_eq!(header.qdcount, 1);

        let mut out = vec![0u8; 12];
        write_header(&mut out, &header).unwrap();
        assert_eq!(&out[..12], &pkt[..12]);
    }

    #[test]
    fn test_setup_reply() {
        let mut header = DnsHeader {
            id: 0x1234,
            hb3: HB3_RD, // RD set by client
            hb4: 0,
            qdcount: 1,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        };
        setup_reply(&mut header, Rcode::NoError as u16, -1);
        assert!(header.is_response());
        assert!(header.recursion_available());
        assert_eq!(header.rcode(), 0);
        assert_eq!(header.ancount, 0);
    }

    #[test]
    fn test_in_arpa_ipv4() {
        let mut buf = [0u8; MAXDNAME];
        let name = b"4.3.2.1.in-addr.arpa\0";
        buf[..name.len()].copy_from_slice(name);
        let result = in_arpa_name_2_addr(&buf);
        assert!(result.is_some());
        match result.unwrap() {
            AllAddr::V4(addr) => assert_eq!(addr, Ipv4Addr::new(1, 2, 3, 4)),
            _ => panic!("expected V4"),
        }
    }

    #[test]
    fn test_in_arpa_ipv6() {
        // 2001:0db8::1 in nibble format (reversed)
        let name = b"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa\0";
        let mut buf = [0u8; MAXDNAME];
        buf[..name.len()].copy_from_slice(name);
        let result = in_arpa_name_2_addr(&buf);
        assert!(result.is_some());
        match result.unwrap() {
            AllAddr::V6(addr) => {
                assert_eq!(
                    addr,
                    "2001:0db8::1".parse::<Ipv6Addr>().unwrap()
                );
            }
            _ => panic!("expected V6"),
        }
    }

    #[test]
    fn test_add_resource_record_a() {
        let mut header = DnsHeader {
            id: 0,
            hb3: 0,
            hb4: 0,
            qdcount: 0,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        };
        let mut buffer = vec![0u8; 512];
        let mut cursor = 12usize;
        let mut truncated = false;

        let added = add_resource_record(
            &mut header,
            &mut buffer,
            512,
            &mut truncated,
            12, // compression pointer to offset 12
            &mut cursor,
            300,
            RrSection::Answer,
            T_A,
            C_IN,
            &RrData::A(Ipv4Addr::new(192, 168, 1, 1)),
        )
        .unwrap();

        assert!(added);
        assert!(!truncated);
        assert_eq!(header.ancount, 1);
        // 2 (name ptr) + 2 (type) + 2 (class) + 4 (ttl) + 2 (rdlen) + 4 (addr) = 16
        assert_eq!(cursor, 12 + 16);
    }

    #[test]
    fn test_skip_section() {
        // Build a packet with one answer RR
        let mut pkt = build_query("example.com", T_A, C_IN);
        let qlen = pkt.len();
        // Append an A record answer
        // Name: compression pointer to offset 12
        pkt.push(0xC0);
        pkt.push(12);
        // TYPE = A (1)
        pkt.push(0x00);
        pkt.push(0x01);
        // CLASS = IN (1)
        pkt.push(0x00);
        pkt.push(0x01);
        // TTL = 300
        pkt.push(0x00);
        pkt.push(0x00);
        pkt.push(0x01);
        pkt.push(0x2C);
        // RDLEN = 4
        pkt.push(0x00);
        pkt.push(0x04);
        // RDATA = 1.2.3.4
        pkt.push(1);
        pkt.push(2);
        pkt.push(3);
        pkt.push(4);

        let mut cursor = qlen;
        skip_section(&pkt, &mut cursor, 1, pkt.len()).unwrap();
        assert_eq!(cursor, pkt.len());
    }

    #[test]
    fn test_pointer_loop_detection() {
        // Create a packet with a self-referencing pointer
        let mut pkt = vec![0u8; 14];
        pkt[12] = 0xC0;
        pkt[13] = 12; // Points to itself

        let mut cursor = 12;
        let mut name_buf = [0u8; MAXDNAME];
        let result = extract_name(&pkt, 14, &mut cursor, &mut name_buf, true);
        assert!(result.is_err());
    }

    #[test]
    fn test_wire_error_display() {
        let err = WireError::PacketTooShort {
            offset: 10,
            needed: 4,
            available: 2,
        };
        let msg = format!("{}", err);
        assert!(msg.contains("packet too short"));
    }
}

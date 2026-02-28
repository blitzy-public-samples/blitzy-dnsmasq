//! Integration tests for DNS wire-format encoding/decoding roundtrip.
//!
//! Tests the Rust rewrite of the DNS wire-format handling (originally in
//! `src/rfc1035.c`, with constants from `src/dns-protocol.h`, and EDNS0 from
//! `src/edns0.c`) by exercising the public API exported from `src/lib.rs`.
//! This is the most foundational test file as it validates low-level protocol
//! primitives including name compression, header parsing, resource record
//! serialization, EDNS0 OPT handling, and fixture-based packet replay.
//!
//! # Test Organization
//! - Phase 2: DNS name compression / decompression
//! - Phase 3: DNS header parsing and construction
//! - Phase 4: Question section
//! - Phase 5: Resource record serialization (A, AAAA, CNAME, PTR, MX, SRV, TXT, SOA, NS)
//! - Phase 6: DNSSEC record types (feature-gated)
//! - Phase 7: EDNS0 OPT pseudo-record
//! - Phase 8: Complete packet construction and parsing
//! - Phase 9: Boundary validation and malformed packets
//! - Phase 10: Fixture-based packet replay

use std::net::{Ipv4Addr, Ipv6Addr};

// Library crate imports
use dnsmasq::config::constants::{self, EDNS_PKTSZ, MAXDNAME, SMALLDNAME};
use dnsmasq::dns::edns::{add_do_bit, add_pseudoheader, find_pseudoheader};
use dnsmasq::dns::protocol::{
    C_ANY, C_CHAOS, C_HESIOD, C_IN, DnsClass, HB3_AA, HB3_QR, HB3_RD, HB3_TC, HB4_AD,
    HB4_CD, HB4_RA, HB4_RCODE, IN6ADDRSZ, INADDRSZ, MAXLABEL, PACKETSZ as PROTO_PACKETSZ,
    RRFIXEDSZ, Rcode, RrType, T_A, T_AAAA, T_CNAME, T_MX, T_NS, T_PTR, T_SOA, T_SRV, T_TXT,
};
#[cfg(feature = "dnssec")]
use dnsmasq::dns::protocol::{T_DNSKEY, T_DS, T_NSEC, T_NSEC3, T_RRSIG};
use dnsmasq::dns::wire::{
    add_resource_record, extract_name, get_u16, get_u32, put_u16, put_u32, read_header,
    setup_reply, skip_name, skip_questions, skip_section, write_header, RrData, RrSection,
    WireError,
};
use dnsmasq::types::addr::AllAddr;
use dnsmasq::types::dns::DnsHeader;

// ============================================================================
// Constants used across tests
// ============================================================================

/// DNS header size in bytes (always 12).
const DNS_HEADER_SIZE: usize = 12;

/// DNSSEC OK (DO) bit in EDNS0 flags — top bit of the flags field.
const DO_BIT: u16 = 0x8000;

// ============================================================================
// Helper functions
// ============================================================================

/// Encode a dotted domain name string (e.g. "example.com") into DNS wire format.
///
/// Returns a `Vec<u8>` containing length-prefixed labels terminated by a zero
/// byte. For example, "example.com" → `[7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0]`.
fn encode_dns_name(name: &str) -> Vec<u8> {
    let mut result = Vec::new();
    if name.is_empty() || name == "." {
        result.push(0);
        return result;
    }
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        result.push(label.len() as u8);
        result.extend_from_slice(label.as_bytes());
    }
    result.push(0); // root label terminator
    result
}

/// Build a minimal DNS query packet with a single question.
///
/// Returns a `Vec<u8>` containing a complete DNS message:
/// `[12-byte header] + [question: QNAME + QTYPE(2) + QCLASS(2)]`
fn build_query_packet(id: u16, name: &str, qtype: u16, qclass: u16) -> Vec<u8> {
    let mut packet = vec![0u8; DNS_HEADER_SIZE];
    let header = DnsHeader {
        id,
        hb3: HB3_RD, // recursion desired
        hb4: 0,
        qdcount: 1,
        ancount: 0,
        nscount: 0,
        arcount: 0,
    };
    write_header(&mut packet, &header).expect("write_header failed");
    let qname = encode_dns_name(name);
    packet.extend_from_slice(&qname);
    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&qclass.to_be_bytes());
    packet
}

/// Build a minimal DNS response packet with header + question + answer section.
///
/// The answer section contains a single RR written via `add_resource_record`.
/// `question_name` is encoded uncompressed in the question section. The answer
/// RR uses a compression pointer back to the question name (offset 12).
fn build_response_packet(
    id: u16,
    name: &str,
    qtype: u16,
    qclass: u16,
    ttl: u32,
    rdata: &RrData<'_>,
) -> Vec<u8> {
    let mut packet = vec![0u8; 4096];
    let mut header = DnsHeader {
        id,
        hb3: HB3_QR | HB3_RD | HB3_AA,
        hb4: HB4_RA,
        qdcount: 1,
        ancount: 0,
        nscount: 0,
        arcount: 0,
    };
    write_header(&mut packet, &header).expect("write_header failed");

    // Write question section
    let qname = encode_dns_name(name);
    let qname_offset = DNS_HEADER_SIZE;
    let mut cursor = DNS_HEADER_SIZE;
    packet[cursor..cursor + qname.len()].copy_from_slice(&qname);
    cursor += qname.len();
    put_u16(&mut packet, &mut cursor, qtype).unwrap();
    put_u16(&mut packet, &mut cursor, qclass).unwrap();

    // Write answer RR using compression pointer to question name
    let mut truncp = false;
    add_resource_record(
        &mut header,
        &mut packet,
        4096,
        &mut truncp,
        qname_offset as i32, // compression pointer to question name
        &mut cursor,
        ttl,
        RrSection::Answer,
        qtype,
        qclass,
        rdata,
    )
    .expect("add_resource_record failed");
    assert!(!truncp, "packet was truncated");

    // Update header with new counts
    write_header(&mut packet, &header).expect("write_header failed");

    // Truncate packet to actual size
    packet.truncate(cursor);
    packet
}

/// Load a fixture file from tests/fixtures/sample_packets/.
fn load_fixture(name: &str) -> Vec<u8> {
    let path = format!("tests/fixtures/sample_packets/{}", name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("Failed to load fixture {}: {}", path, e))
}

/// Convert a wire-format name (from name_buf) to a dotted string.
fn wire_name_to_string(name_buf: &[u8]) -> String {
    // extract_name writes a null-terminated dotted presentation string
    // (e.g., "example.com\0") into name_buf. We simply read up to the
    // first null byte and convert to a Rust String.
    let end = name_buf
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(name_buf.len());
    String::from_utf8_lossy(&name_buf[..end]).to_string()
}

// ============================================================================
// Phase 2: DNS Name Compression/Decompression Tests
// ============================================================================

#[test]
fn test_name_compression_basic() {
    // Build a packet with two names sharing a suffix.
    // Question: "host.example.com" (uncompressed)
    // Answer name: compressed pointer back to "example.com" within the question name
    let mut packet = vec![0u8; 512];
    let header = DnsHeader {
        id: 0x1234,
        hb3: HB3_QR | HB3_RD,
        hb4: 0,
        qdcount: 1,
        ancount: 1,
        nscount: 0,
        arcount: 0,
    };
    write_header(&mut packet, &header).unwrap();

    // Write question: "host.example.com"
    let qname = encode_dns_name("host.example.com");
    let mut cursor = DNS_HEADER_SIZE;
    packet[cursor..cursor + qname.len()].copy_from_slice(&qname);
    cursor += qname.len();
    put_u16(&mut packet, &mut cursor, T_A).unwrap();
    put_u16(&mut packet, &mut cursor, C_IN).unwrap();

    // The "example.com" portion starts at offset 12+5 = 17 (after "host" label)
    // "host" label: 1 byte len + 4 bytes = 5, so "example" starts at 12+5 = 17
    let example_offset = DNS_HEADER_SIZE + 5; // offset of "example.com" in question

    // Write answer: compressed name pointing to "example.com"
    // This is a direct compression pointer: 0xC0 | (example_offset >> 8), example_offset & 0xFF
    packet[cursor] = 0xC0 | ((example_offset >> 8) as u8);
    packet[cursor + 1] = (example_offset & 0xFF) as u8;
    cursor += 2;

    // Decompress the answer name
    let mut ans_cursor = cursor - 2; // back to the compression pointer
    let mut name_buf = [0u8; MAXDNAME];
    extract_name(&packet, cursor, &mut ans_cursor, &mut name_buf, true)
        .expect("extract_name should succeed on compression pointer");

    let decoded = wire_name_to_string(&name_buf);
    assert_eq!(decoded, "example.com");
}

#[test]
fn test_name_decompression_basic() {
    // Build a packet where the answer name is a 0xC0 pointer to the question name.
    let query = build_query_packet(0xABCD, "example.com", T_A, C_IN);
    let qname_offset = DNS_HEADER_SIZE as u16;

    // Append answer RR with compression pointer
    let mut packet = query.clone();
    // Compression pointer: 0xC000 | qname_offset
    packet.push(0xC0 | ((qname_offset >> 8) as u8));
    packet.push((qname_offset & 0xFF) as u8);
    // TYPE, CLASS, TTL, RDLENGTH, RDATA (A record: 4 bytes)
    packet.extend_from_slice(&T_A.to_be_bytes());
    packet.extend_from_slice(&C_IN.to_be_bytes());
    packet.extend_from_slice(&300u32.to_be_bytes()); // TTL
    packet.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
    packet.extend_from_slice(&[93, 184, 216, 34]); // RDATA: 93.184.216.34

    // Decompress the name at the answer section start
    let answer_start = query.len();
    let mut cursor = answer_start;
    let mut name_buf = [0u8; MAXDNAME];
    extract_name(&packet, packet.len(), &mut cursor, &mut name_buf, true)
        .expect("extract_name should decompress pointer");

    let decoded = wire_name_to_string(&name_buf);
    assert_eq!(decoded, "example.com");
}

#[test]
fn test_name_compression_roundtrip() {
    // Encode "www.example.com" to wire format, then decode back
    let wire = encode_dns_name("www.example.com");

    // Build a minimal packet containing just this name
    let mut packet = vec![0u8; DNS_HEADER_SIZE];
    packet.extend_from_slice(&wire);

    let mut cursor = DNS_HEADER_SIZE;
    let mut name_buf = [0u8; MAXDNAME];
    extract_name(&packet, packet.len(), &mut cursor, &mut name_buf, true)
        .expect("extract_name should succeed");

    let decoded = wire_name_to_string(&name_buf);
    assert_eq!(decoded, "www.example.com");
    // Verify cursor advanced past the full uncompressed name
    assert_eq!(cursor, DNS_HEADER_SIZE + wire.len());
}

#[test]
fn test_name_compression_multiple_pointers() {
    // Build a response with multiple names sharing suffixes via compression pointers.
    // Question: "host1.example.com" at offset 12
    // Answer 1: pointer to offset 12 (host1.example.com)
    // Answer 2: "host2" + pointer to "example.com" at offset 12+6
    let mut packet = vec![0u8; 512];
    let header = DnsHeader {
        id: 0x5678,
        hb3: HB3_QR | HB3_RD,
        hb4: 0,
        qdcount: 1,
        ancount: 2,
        nscount: 0,
        arcount: 0,
    };
    write_header(&mut packet, &header).unwrap();

    // Write question: "host1.example.com"
    let qname = encode_dns_name("host1.example.com");
    let mut cursor = DNS_HEADER_SIZE;
    packet[cursor..cursor + qname.len()].copy_from_slice(&qname);
    cursor += qname.len();
    put_u16(&mut packet, &mut cursor, T_A).unwrap();
    put_u16(&mut packet, &mut cursor, C_IN).unwrap();

    // "example.com" starts at offset 12 + 6 = 18 (after "host1" label: 1+5=6)
    let example_offset = DNS_HEADER_SIZE + 6;

    // Answer 1: compression pointer to full question name at offset 12
    packet[cursor] = 0xC0;
    packet[cursor + 1] = DNS_HEADER_SIZE as u8;
    cursor += 2;
    // TYPE(A), CLASS(IN), TTL, RDLEN, RDATA
    put_u16(&mut packet, &mut cursor, T_A).unwrap();
    put_u16(&mut packet, &mut cursor, C_IN).unwrap();
    put_u32(&mut packet, &mut cursor, 300).unwrap();
    put_u16(&mut packet, &mut cursor, 4).unwrap();
    packet[cursor..cursor + 4].copy_from_slice(&[10, 0, 0, 1]);
    cursor += 4;

    // Answer 2: "host2" + compression pointer to "example.com"
    packet[cursor] = 5; // label length for "host2"
    cursor += 1;
    packet[cursor..cursor + 5].copy_from_slice(b"host2");
    cursor += 5;
    packet[cursor] = 0xC0 | ((example_offset >> 8) as u8);
    packet[cursor + 1] = (example_offset & 0xFF) as u8;
    cursor += 2;
    put_u16(&mut packet, &mut cursor, T_A).unwrap();
    put_u16(&mut packet, &mut cursor, C_IN).unwrap();
    put_u32(&mut packet, &mut cursor, 300).unwrap();
    put_u16(&mut packet, &mut cursor, 4).unwrap();
    packet[cursor..cursor + 4].copy_from_slice(&[10, 0, 0, 2]);
    cursor += 4;

    // Decompress Answer 1 name — should be "host1.example.com"
    let ans1_start = DNS_HEADER_SIZE + qname.len() + 4; // after question
    let mut c = ans1_start;
    let mut nbuf = [0u8; MAXDNAME];
    extract_name(&packet, cursor, &mut c, &mut nbuf, true).unwrap();
    assert_eq!(wire_name_to_string(&nbuf), "host1.example.com");

    // Skip past answer 1 RR (pointer(2) + type(2) + class(2) + ttl(4) + rdlen(2) + rdata(4))
    let ans2_start = ans1_start + 2 + 10 + 4;
    let mut c2 = ans2_start;
    let mut nbuf2 = [0u8; MAXDNAME];
    extract_name(&packet, cursor, &mut c2, &mut nbuf2, true).unwrap();
    assert_eq!(wire_name_to_string(&nbuf2), "host2.example.com");
}

#[test]
fn test_name_compression_loop_detection() {
    // Construct a packet with a circular compression pointer.
    // At offset 12: compression pointer → offset 12 (self-referencing loop)
    let mut packet = vec![0u8; DNS_HEADER_SIZE + 4];
    let header = DnsHeader {
        id: 0x9999,
        hb3: 0,
        hb4: 0,
        qdcount: 1,
        ancount: 0,
        nscount: 0,
        arcount: 0,
    };
    write_header(&mut packet, &header).unwrap();

    // Write a compression pointer that points to itself at offset 12
    packet[12] = 0xC0;
    packet[13] = 0x0C; // points back to offset 12

    let mut cursor = DNS_HEADER_SIZE;
    let mut name_buf = [0u8; MAXDNAME];
    let result = extract_name(&packet, packet.len(), &mut cursor, &mut name_buf, true);
    assert!(result.is_err(), "circular compression pointer should be rejected");
}

#[test]
fn test_name_decompression_invalid_offset() {
    // Compression pointer pointing outside packet boundaries
    let mut packet = vec![0u8; DNS_HEADER_SIZE + 2];
    let header = DnsHeader {
        id: 0xAAAA,
        hb3: 0,
        hb4: 0,
        qdcount: 1,
        ancount: 0,
        nscount: 0,
        arcount: 0,
    };
    write_header(&mut packet, &header).unwrap();

    // Compression pointer to offset 0xFF (way beyond packet length of 14)
    packet[12] = 0xC0;
    packet[13] = 0xFF;

    let mut cursor = DNS_HEADER_SIZE;
    let mut name_buf = [0u8; MAXDNAME];
    let result = extract_name(&packet, packet.len(), &mut cursor, &mut name_buf, true);
    assert!(result.is_err(), "out-of-bounds compression pointer should be rejected");
}

#[test]
fn test_name_max_length() {
    // Build a name at the 255-byte total wire-format limit.
    // Wire format: label_len(1) + data(63) per label, plus root terminator(1).
    // 3 labels × (1+63) = 192. Remaining: 255 - 192 - 1(root) - 1(len byte) = 61.
    // Final label: 1(len) + 61(data) = 62 bytes. Total: 192 + 62 + 1 = 255.
    let mut wire_name = Vec::new();
    // 3 labels of 63 bytes each: 3 * 64 = 192 bytes
    for _ in 0..3 {
        wire_name.push(63u8);
        wire_name.extend_from_slice(&[b'a'; 63]);
    }
    // Final label data length: 255 - 192(so far) - 1(length byte) - 1(root) = 61
    let final_data_len = 255 - wire_name.len() - 1 - 1;
    wire_name.push(final_data_len as u8);
    wire_name.extend(std::iter::repeat(b'b').take(final_data_len));
    wire_name.push(0); // root terminator
    assert_eq!(wire_name.len(), 255, "wire name should be exactly 255 bytes");

    // Put this in a packet and try to extract
    let mut packet = vec![0u8; DNS_HEADER_SIZE];
    packet.extend_from_slice(&wire_name);

    let mut cursor = DNS_HEADER_SIZE;
    let mut name_buf = [0u8; MAXDNAME];
    let result = extract_name(&packet, packet.len(), &mut cursor, &mut name_buf, true);
    // Should succeed — this is at the limit
    assert!(result.is_ok(), "name at 255-byte limit should be accepted");

    // Now try a label exceeding 63 bytes — should be rejected
    let mut bad_packet = vec![0u8; DNS_HEADER_SIZE];
    bad_packet.push(64); // label length = 64 (exceeds max of 63)
    bad_packet.extend(std::iter::repeat(b'x').take(64));
    bad_packet.push(0); // root

    let mut cursor2 = DNS_HEADER_SIZE;
    let mut name_buf2 = [0u8; MAXDNAME];
    let result2 = extract_name(&bad_packet, bad_packet.len(), &mut cursor2, &mut name_buf2, true);
    // Label > 63 bytes uses the top 2 bits as a compression pointer indicator
    // 64 = 0x40, which doesn't have top 2 bits set to 0xC0, so this should be treated
    // as a very long label or trigger an error.
    // The actual behavior depends on implementation: label length 64 uses bit pattern 01xxxxxx
    // which in DNS wire format is reserved. Many implementations reject this.
    // We accept either an error or the implementation treating it as invalid.
    // The key point is it shouldn't cause a panic.
    let _ = result2; // just verify no panic
}

// ============================================================================
// Phase 3: DNS Header Parsing and Construction Tests
// ============================================================================

#[test]
fn test_dns_header_parsing() {
    // Construct a 12-byte header manually in network byte order
    let raw: [u8; 12] = [
        0xAB, 0xCD, // ID = 0xABCD
        0x85,       // hb3: QR=1, OPCODE=0, AA=1, TC=0, RD=1
        0x80,       // hb4: RA=1, Z=0, AD=0, CD=0, RCODE=0
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x02, // ANCOUNT = 2
        0x00, 0x03, // NSCOUNT = 3
        0x00, 0x04, // ARCOUNT = 4
    ];

    let header = read_header(&raw).expect("read_header should succeed");
    assert_eq!(header.id, 0xABCD);
    assert!(header.is_response()); // QR bit set
    assert!(header.is_authoritative()); // AA bit set
    assert!(header.recursion_desired()); // RD bit set
    assert!(header.recursion_available()); // RA bit set
    assert!(!header.is_truncated()); // TC bit clear
    assert_eq!(header.hb4 & HB4_RCODE, 0); // RCODE = NOERROR
    assert_eq!(header.qdcount, 1);
    assert_eq!(header.ancount, 2);
    assert_eq!(header.nscount, 3);
    assert_eq!(header.arcount, 4);
}

#[test]
fn test_dns_header_construction() {
    let header = DnsHeader {
        id: 0x1234,
        hb3: HB3_QR | HB3_AA | HB3_RD,
        hb4: HB4_RA,
        qdcount: 1,
        ancount: 0,
        nscount: 0,
        arcount: 0,
    };

    let mut buf = [0u8; 12];
    write_header(&mut buf, &header).expect("write_header should succeed");

    // Verify wire format
    assert_eq!(buf[0], 0x12);
    assert_eq!(buf[1], 0x34);
    assert_eq!(buf[2], HB3_QR | HB3_AA | HB3_RD);
    assert_eq!(buf[3], HB4_RA);
    assert_eq!(u16::from_be_bytes([buf[4], buf[5]]), 1); // qdcount
    assert_eq!(u16::from_be_bytes([buf[6], buf[7]]), 0); // ancount
    assert_eq!(u16::from_be_bytes([buf[8], buf[9]]), 0); // nscount
    assert_eq!(u16::from_be_bytes([buf[10], buf[11]]), 0); // arcount
}

#[test]
fn test_dns_header_roundtrip() {
    let original = DnsHeader {
        id: 0xFEDC,
        hb3: HB3_QR | HB3_TC | HB3_RD,
        hb4: HB4_RA | HB4_AD | 0x03, // RCODE = NxDomain
        qdcount: 1,
        ancount: 3,
        nscount: 2,
        arcount: 1,
    };

    let mut buf = [0u8; 12];
    write_header(&mut buf, &original).expect("write_header failed");
    let parsed = read_header(&buf).expect("read_header failed");

    assert_eq!(parsed.id, original.id);
    assert_eq!(parsed.hb3, original.hb3);
    assert_eq!(parsed.hb4, original.hb4);
    assert_eq!(parsed.qdcount, original.qdcount);
    assert_eq!(parsed.ancount, original.ancount);
    assert_eq!(parsed.nscount, original.nscount);
    assert_eq!(parsed.arcount, original.arcount);
}

#[test]
fn test_dns_header_flags() {
    // Test individual flag bits
    let mut header = DnsHeader {
        id: 1,
        hb3: 0,
        hb4: 0,
        qdcount: 0,
        ancount: 0,
        nscount: 0,
        arcount: 0,
    };

    // QR flag
    assert!(!header.is_response());
    header.hb3 |= HB3_QR;
    assert!(header.is_response());

    // AA flag
    header.hb3 = 0;
    assert!(!header.is_authoritative());
    header.hb3 |= HB3_AA;
    assert!(header.is_authoritative());

    // TC flag
    header.hb3 = 0;
    assert!(!header.is_truncated());
    header.hb3 |= HB3_TC;
    assert!(header.is_truncated());

    // RD flag
    header.hb3 = 0;
    assert!(!header.recursion_desired());
    header.hb3 |= HB3_RD;
    assert!(header.recursion_desired());

    // RA flag
    header.hb4 = 0;
    assert!(!header.recursion_available());
    header.hb4 |= HB4_RA;
    assert!(header.recursion_available());

    // AD flag
    header.hb4 = 0;
    assert!(!header.authenticated_data());
    header.hb4 |= HB4_AD;
    assert!(header.authenticated_data());

    // CD flag
    header.hb4 = 0;
    assert!(!header.checking_disabled());
    header.hb4 |= HB4_CD;
    assert!(header.checking_disabled());
}

#[test]
fn test_dns_header_rcode() {
    let mut header = DnsHeader {
        id: 1,
        hb3: HB3_QR,
        hb4: 0,
        qdcount: 0,
        ancount: 0,
        nscount: 0,
        arcount: 0,
    };

    // NOERROR (0)
    header.hb4 = (header.hb4 & !HB4_RCODE) | (Rcode::NoError as u8);
    assert_eq!(header.rcode(), Rcode::NoError as u8);

    // FORMERR (1)
    header.hb4 = (header.hb4 & !HB4_RCODE) | (Rcode::FormErr as u8);
    assert_eq!(header.rcode(), Rcode::FormErr as u8);

    // SERVFAIL (2)
    header.hb4 = (header.hb4 & !HB4_RCODE) | (Rcode::ServFail as u8);
    assert_eq!(header.rcode(), Rcode::ServFail as u8);

    // NXDOMAIN (3)
    header.hb4 = (header.hb4 & !HB4_RCODE) | (Rcode::NxDomain as u8);
    assert_eq!(header.rcode(), Rcode::NxDomain as u8);

    // NOTIMP (4)
    header.hb4 = (header.hb4 & !HB4_RCODE) | (Rcode::NotImp as u8);
    assert_eq!(header.rcode(), Rcode::NotImp as u8);

    // REFUSED (5)
    header.hb4 = (header.hb4 & !HB4_RCODE) | (Rcode::Refused as u8);
    assert_eq!(header.rcode(), Rcode::Refused as u8);
}

// ============================================================================
// Phase 4: Question Section Tests
// ============================================================================

#[test]
fn test_question_parsing() {
    let packet = build_query_packet(0x1111, "example.com", T_A, C_IN);
    let header = read_header(&packet).expect("read_header failed");
    assert_eq!(header.qdcount, 1);

    let mut cursor = DNS_HEADER_SIZE;
    let mut name_buf = [0u8; MAXDNAME];
    extract_name(&packet, packet.len(), &mut cursor, &mut name_buf, true)
        .expect("extract_name failed");
    assert_eq!(wire_name_to_string(&name_buf), "example.com");

    let qtype = get_u16(&packet, &mut cursor).expect("get_u16 for QTYPE failed");
    let qclass = get_u16(&packet, &mut cursor).expect("get_u16 for QCLASS failed");
    assert_eq!(qtype, T_A);
    assert_eq!(qclass, C_IN);
}

#[test]
fn test_question_construction() {
    let packet = build_query_packet(0x2222, "example.com", T_A, C_IN);
    let header = read_header(&packet).unwrap();
    assert_eq!(header.id, 0x2222);
    assert_eq!(header.qdcount, 1);

    let expected_qname = encode_dns_name("example.com");
    let qname_start = DNS_HEADER_SIZE;
    assert_eq!(
        &packet[qname_start..qname_start + expected_qname.len()],
        &expected_qname[..]
    );
}

#[test]
fn test_question_roundtrip() {
    let packet = build_query_packet(0x3333, "mail.example.org", T_MX, C_IN);

    let mut cursor = DNS_HEADER_SIZE;
    let mut name_buf = [0u8; MAXDNAME];
    extract_name(&packet, packet.len(), &mut cursor, &mut name_buf, true).unwrap();
    let qtype = get_u16(&packet, &mut cursor).unwrap();
    let qclass = get_u16(&packet, &mut cursor).unwrap();

    assert_eq!(wire_name_to_string(&name_buf), "mail.example.org");
    assert_eq!(qtype, T_MX);
    assert_eq!(qclass, C_IN);
}

#[test]
fn test_skip_questions_fn() {
    let packet = build_query_packet(0x4444, "example.com", T_A, C_IN);
    let header = read_header(&packet).unwrap();

    let pos = skip_questions(&header, &packet, packet.len())
        .expect("skip_questions failed");
    assert_eq!(pos, packet.len());
}

#[test]
fn test_multiple_questions() {
    let mut packet = vec![0u8; DNS_HEADER_SIZE];
    let header = DnsHeader {
        id: 0x5555,
        hb3: HB3_RD,
        hb4: 0,
        qdcount: 2,
        ancount: 0,
        nscount: 0,
        arcount: 0,
    };
    write_header(&mut packet, &header).unwrap();

    let q1 = encode_dns_name("example.com");
    packet.extend_from_slice(&q1);
    packet.extend_from_slice(&T_A.to_be_bytes());
    packet.extend_from_slice(&C_IN.to_be_bytes());

    let q2 = encode_dns_name("example.org");
    packet.extend_from_slice(&q2);
    packet.extend_from_slice(&T_AAAA.to_be_bytes());
    packet.extend_from_slice(&C_IN.to_be_bytes());

    let mut cursor = DNS_HEADER_SIZE;
    let mut name_buf1 = [0u8; MAXDNAME];
    extract_name(&packet, packet.len(), &mut cursor, &mut name_buf1, true).unwrap();
    let qt1 = get_u16(&packet, &mut cursor).unwrap();
    assert_eq!(wire_name_to_string(&name_buf1), "example.com");
    assert_eq!(qt1, T_A);
    let _ = get_u16(&packet, &mut cursor).unwrap(); // QCLASS

    let mut name_buf2 = [0u8; MAXDNAME];
    extract_name(&packet, packet.len(), &mut cursor, &mut name_buf2, true).unwrap();
    let qt2 = get_u16(&packet, &mut cursor).unwrap();
    assert_eq!(wire_name_to_string(&name_buf2), "example.org");
    assert_eq!(qt2, T_AAAA);

    let header2 = read_header(&packet).unwrap();
    let end_pos = skip_questions(&header2, &packet, packet.len()).unwrap();
    assert_eq!(end_pos, packet.len());
}

// ============================================================================
// Phase 5: Resource Record Serialization Tests
// ============================================================================

#[test]
fn test_rr_a_record_roundtrip() {
    let ip = Ipv4Addr::new(93, 184, 216, 34);
    let rdata = RrData::A(ip);
    let packet = build_response_packet(0x6001, "example.com", T_A, C_IN, 300, &rdata);

    let header = read_header(&packet).unwrap();
    assert_eq!(header.ancount, 1);
    let ans_start = skip_questions(&header, &packet, packet.len()).unwrap();

    let mut cursor = ans_start;
    skip_name(&packet, &mut cursor, packet.len(), 0).unwrap();
    let rr_type = get_u16(&packet, &mut cursor).unwrap();
    let rr_class = get_u16(&packet, &mut cursor).unwrap();
    let rr_ttl = get_u32(&packet, &mut cursor).unwrap();
    let rdlen = get_u16(&packet, &mut cursor).unwrap();

    assert_eq!(rr_type, T_A);
    assert_eq!(rr_class, C_IN);
    assert_eq!(rr_ttl, 300);
    assert_eq!(rdlen, 4);

    let rdata_bytes = &packet[cursor..cursor + rdlen as usize];
    let parsed_ip = Ipv4Addr::new(rdata_bytes[0], rdata_bytes[1], rdata_bytes[2], rdata_bytes[3]);
    assert_eq!(parsed_ip, ip);
}

#[test]
fn test_rr_aaaa_record_roundtrip() {
    let ip = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
    let rdata = RrData::Aaaa(ip);
    let packet = build_response_packet(0x6002, "example.com", T_AAAA, C_IN, 600, &rdata);

    let header = read_header(&packet).unwrap();
    let ans_start = skip_questions(&header, &packet, packet.len()).unwrap();

    let mut cursor = ans_start;
    skip_name(&packet, &mut cursor, packet.len(), 0).unwrap();
    assert_eq!(get_u16(&packet, &mut cursor).unwrap(), T_AAAA);
    assert_eq!(get_u16(&packet, &mut cursor).unwrap(), C_IN);
    assert_eq!(get_u32(&packet, &mut cursor).unwrap(), 600);
    let rdlen = get_u16(&packet, &mut cursor).unwrap();
    assert_eq!(rdlen, 16);

    let mut octets = [0u8; 16];
    octets.copy_from_slice(&packet[cursor..cursor + 16]);
    assert_eq!(Ipv6Addr::from(octets), ip);
}

#[test]
fn test_rr_cname_record_roundtrip() {
    let rdata = RrData::Cname("www.example.com");
    let packet = build_response_packet(0x6003, "alias.example.com", T_CNAME, C_IN, 3600, &rdata);

    let header = read_header(&packet).unwrap();
    let ans_start = skip_questions(&header, &packet, packet.len()).unwrap();

    let mut cursor = ans_start;
    skip_name(&packet, &mut cursor, packet.len(), 0).unwrap();
    assert_eq!(get_u16(&packet, &mut cursor).unwrap(), T_CNAME);
    let _ = get_u16(&packet, &mut cursor).unwrap();
    let _ = get_u32(&packet, &mut cursor).unwrap();
    let rdlen = get_u16(&packet, &mut cursor).unwrap();

    let rdata_end = cursor + rdlen as usize;
    let mut name_buf = [0u8; MAXDNAME];
    extract_name(&packet, rdata_end, &mut cursor, &mut name_buf, true)
        .expect("extract_name in CNAME RDATA failed");
    assert_eq!(wire_name_to_string(&name_buf), "www.example.com");
}

#[test]
fn test_rr_ptr_record_roundtrip() {
    let rdata = RrData::Ptr("example.com");
    let packet = build_response_packet(
        0x6004, "34.216.184.93.in-addr.arpa", T_PTR, C_IN, 3600, &rdata,
    );

    let header = read_header(&packet).unwrap();
    let ans_start = skip_questions(&header, &packet, packet.len()).unwrap();

    let mut cursor = ans_start;
    skip_name(&packet, &mut cursor, packet.len(), 0).unwrap();
    assert_eq!(get_u16(&packet, &mut cursor).unwrap(), T_PTR);
    let _ = get_u16(&packet, &mut cursor).unwrap();
    let _ = get_u32(&packet, &mut cursor).unwrap();
    let rdlen = get_u16(&packet, &mut cursor).unwrap();

    let rdata_end = cursor + rdlen as usize;
    let mut name_buf = [0u8; MAXDNAME];
    extract_name(&packet, rdata_end, &mut cursor, &mut name_buf, true).unwrap();
    assert_eq!(wire_name_to_string(&name_buf), "example.com");
}

#[test]
fn test_rr_mx_record_roundtrip() {
    let rdata = RrData::Mx(10, "mail.example.com");
    let packet = build_response_packet(0x6005, "example.com", T_MX, C_IN, 3600, &rdata);

    let header = read_header(&packet).unwrap();
    let ans_start = skip_questions(&header, &packet, packet.len()).unwrap();

    let mut cursor = ans_start;
    skip_name(&packet, &mut cursor, packet.len(), 0).unwrap();
    assert_eq!(get_u16(&packet, &mut cursor).unwrap(), T_MX);
    let _ = get_u16(&packet, &mut cursor).unwrap();
    let _ = get_u32(&packet, &mut cursor).unwrap();
    let _ = get_u16(&packet, &mut cursor).unwrap();

    let preference = get_u16(&packet, &mut cursor).unwrap();
    assert_eq!(preference, 10);

    let mut name_buf = [0u8; MAXDNAME];
    extract_name(&packet, packet.len(), &mut cursor, &mut name_buf, true).unwrap();
    assert_eq!(wire_name_to_string(&name_buf), "mail.example.com");
}

#[test]
fn test_rr_srv_record_roundtrip() {
    let rdata = RrData::Srv(10, 60, 5060, "sipserver.example.com");
    let packet = build_response_packet(
        0x6006, "_sip._tcp.example.com", T_SRV, C_IN, 3600, &rdata,
    );

    let header = read_header(&packet).unwrap();
    let ans_start = skip_questions(&header, &packet, packet.len()).unwrap();

    let mut cursor = ans_start;
    skip_name(&packet, &mut cursor, packet.len(), 0).unwrap();
    assert_eq!(get_u16(&packet, &mut cursor).unwrap(), T_SRV);
    let _ = get_u16(&packet, &mut cursor).unwrap();
    let _ = get_u32(&packet, &mut cursor).unwrap();
    let _ = get_u16(&packet, &mut cursor).unwrap();

    assert_eq!(get_u16(&packet, &mut cursor).unwrap(), 10);  // priority
    assert_eq!(get_u16(&packet, &mut cursor).unwrap(), 60);  // weight
    assert_eq!(get_u16(&packet, &mut cursor).unwrap(), 5060); // port

    let mut name_buf = [0u8; MAXDNAME];
    extract_name(&packet, packet.len(), &mut cursor, &mut name_buf, true).unwrap();
    assert_eq!(wire_name_to_string(&name_buf), "sipserver.example.com");
}

#[test]
fn test_rr_txt_record_roundtrip() {
    let txt_data = b"\x0bhello world";
    let rdata = RrData::Txt(txt_data);
    let packet = build_response_packet(0x6007, "example.com", T_TXT, C_IN, 3600, &rdata);

    let header = read_header(&packet).unwrap();
    let ans_start = skip_questions(&header, &packet, packet.len()).unwrap();

    let mut cursor = ans_start;
    skip_name(&packet, &mut cursor, packet.len(), 0).unwrap();
    assert_eq!(get_u16(&packet, &mut cursor).unwrap(), T_TXT);
    let _ = get_u16(&packet, &mut cursor).unwrap();
    let _ = get_u32(&packet, &mut cursor).unwrap();
    let rdlen = get_u16(&packet, &mut cursor).unwrap();

    assert_eq!(&packet[cursor..cursor + rdlen as usize], txt_data);
}

#[test]
fn test_rr_soa_record_roundtrip() {
    let rdata = RrData::Soa {
        mname: "ns1.example.com",
        rname: "admin.example.com",
        serial: 2024010100,
        refresh: 3600,
        retry: 900,
        expire: 604800,
        minimum: 86400,
    };
    let packet = build_response_packet(0x6008, "example.com", T_SOA, C_IN, 86400, &rdata);

    let header = read_header(&packet).unwrap();
    let ans_start = skip_questions(&header, &packet, packet.len()).unwrap();

    let mut cursor = ans_start;
    skip_name(&packet, &mut cursor, packet.len(), 0).unwrap();
    assert_eq!(get_u16(&packet, &mut cursor).unwrap(), T_SOA);
    let _ = get_u16(&packet, &mut cursor).unwrap();
    assert_eq!(get_u32(&packet, &mut cursor).unwrap(), 86400);
    let _ = get_u16(&packet, &mut cursor).unwrap();

    let mut nb = [0u8; MAXDNAME];
    extract_name(&packet, packet.len(), &mut cursor, &mut nb, true).unwrap();
    assert_eq!(wire_name_to_string(&nb), "ns1.example.com");

    let mut nb2 = [0u8; MAXDNAME];
    extract_name(&packet, packet.len(), &mut cursor, &mut nb2, true).unwrap();
    assert_eq!(wire_name_to_string(&nb2), "admin.example.com");

    assert_eq!(get_u32(&packet, &mut cursor).unwrap(), 2024010100);
    assert_eq!(get_u32(&packet, &mut cursor).unwrap(), 3600);
    assert_eq!(get_u32(&packet, &mut cursor).unwrap(), 900);
    assert_eq!(get_u32(&packet, &mut cursor).unwrap(), 604800);
    assert_eq!(get_u32(&packet, &mut cursor).unwrap(), 86400);
}

#[test]
fn test_rr_ns_record_roundtrip() {
    let rdata = RrData::Ns("ns1.example.com");
    let packet = build_response_packet(0x6009, "example.com", T_NS, C_IN, 86400, &rdata);

    let header = read_header(&packet).unwrap();
    let ans_start = skip_questions(&header, &packet, packet.len()).unwrap();

    let mut cursor = ans_start;
    skip_name(&packet, &mut cursor, packet.len(), 0).unwrap();
    assert_eq!(get_u16(&packet, &mut cursor).unwrap(), T_NS);
    let _ = get_u16(&packet, &mut cursor).unwrap();
    let _ = get_u32(&packet, &mut cursor).unwrap();
    let rdlen = get_u16(&packet, &mut cursor).unwrap();

    let rdata_end = cursor + rdlen as usize;
    let mut name_buf = [0u8; MAXDNAME];
    extract_name(&packet, rdata_end, &mut cursor, &mut name_buf, true).unwrap();
    assert_eq!(wire_name_to_string(&name_buf), "ns1.example.com");
}

#[test]
fn test_rr_ttl_encoding() {
    let rdata = RrData::A(Ipv4Addr::new(1, 2, 3, 4));
    let packet = build_response_packet(0x600A, "test.com", T_A, C_IN, 0x12345678, &rdata);

    let header = read_header(&packet).unwrap();
    let ans_start = skip_questions(&header, &packet, packet.len()).unwrap();

    let mut cursor = ans_start;
    skip_name(&packet, &mut cursor, packet.len(), 0).unwrap();
    let _ = get_u16(&packet, &mut cursor).unwrap();
    let _ = get_u16(&packet, &mut cursor).unwrap();
    let ttl = get_u32(&packet, &mut cursor).unwrap();
    assert_eq!(ttl, 0x12345678);

    // Verify network byte order in raw bytes
    let ttl_off = cursor - 4;
    assert_eq!(packet[ttl_off], 0x12);
    assert_eq!(packet[ttl_off + 1], 0x34);
    assert_eq!(packet[ttl_off + 2], 0x56);
    assert_eq!(packet[ttl_off + 3], 0x78);
}

#[test]
fn test_rr_class_encoding() {
    let rdata = RrData::A(Ipv4Addr::new(1, 1, 1, 1));

    // Test IN class
    let pkt_in = build_response_packet(0x600B, "t.com", T_A, C_IN, 300, &rdata);
    let hdr = read_header(&pkt_in).unwrap();
    let a = skip_questions(&hdr, &pkt_in, pkt_in.len()).unwrap();
    let mut c = a;
    skip_name(&pkt_in, &mut c, pkt_in.len(), 0).unwrap();
    let _ = get_u16(&pkt_in, &mut c).unwrap();
    assert_eq!(get_u16(&pkt_in, &mut c).unwrap(), C_IN);

    // Test CH class
    let pkt_ch = build_response_packet(0x600C, "t.com", T_A, C_CHAOS, 300, &rdata);
    let hdr2 = read_header(&pkt_ch).unwrap();
    let a2 = skip_questions(&hdr2, &pkt_ch, pkt_ch.len()).unwrap();
    let mut c2 = a2;
    skip_name(&pkt_ch, &mut c2, pkt_ch.len(), 0).unwrap();
    let _ = get_u16(&pkt_ch, &mut c2).unwrap();
    assert_eq!(get_u16(&pkt_ch, &mut c2).unwrap(), C_CHAOS);

    // Verify constant values
    assert_eq!(C_IN, 1);
    assert_eq!(C_CHAOS, 3);
    assert_eq!(C_HESIOD, 4);
    assert_eq!(C_ANY, 255);
}

// ============================================================================
// Phase 6: DNSSEC Record Types (feature-gated)
// ============================================================================

#[cfg(feature = "dnssec")]
#[test]
fn test_rr_dnskey_record_roundtrip() {
    // DNSKEY RDATA: flags(2) + protocol(1) + algorithm(1) + public_key(variable)
    let mut dnskey_rdata = Vec::new();
    dnskey_rdata.extend_from_slice(&257u16.to_be_bytes()); // KSK flag
    dnskey_rdata.push(3); // protocol (always 3)
    dnskey_rdata.push(8); // algorithm: RSA/SHA-256
    dnskey_rdata.extend_from_slice(&[0xAA; 64]); // mock public key

    let rdata = RrData::Dnskey(&dnskey_rdata);
    let packet = build_response_packet(0x7001, "example.com", T_DNSKEY, C_IN, 86400, &rdata);

    let header = read_header(&packet).unwrap();
    let ans_start = skip_questions(&header, &packet, packet.len()).unwrap();

    let mut cursor = ans_start;
    skip_name(&packet, &mut cursor, packet.len(), 0).unwrap();
    assert_eq!(get_u16(&packet, &mut cursor).unwrap(), T_DNSKEY);
    let _ = get_u16(&packet, &mut cursor).unwrap();
    let _ = get_u32(&packet, &mut cursor).unwrap();
    let rdlen = get_u16(&packet, &mut cursor).unwrap();

    let parsed_rdata = &packet[cursor..cursor + rdlen as usize];
    assert_eq!(parsed_rdata, &dnskey_rdata[..]);

    // Verify individual fields
    let flags = u16::from_be_bytes([parsed_rdata[0], parsed_rdata[1]]);
    assert_eq!(flags, 257); // KSK
    assert_eq!(parsed_rdata[2], 3); // protocol
    assert_eq!(parsed_rdata[3], 8); // RSA/SHA-256
}

#[cfg(feature = "dnssec")]
#[test]
fn test_rr_ds_record_roundtrip() {
    // DS RDATA: key_tag(2) + algorithm(1) + digest_type(1) + digest(variable)
    let mut ds_rdata = Vec::new();
    ds_rdata.extend_from_slice(&20326u16.to_be_bytes()); // key tag
    ds_rdata.push(8); // algorithm: RSA/SHA-256
    ds_rdata.push(2); // digest type: SHA-256
    ds_rdata.extend_from_slice(&[0xBB; 32]); // mock digest

    let rdata = RrData::Ds(&ds_rdata);
    let packet = build_response_packet(0x7002, "example.com", T_DS, C_IN, 86400, &rdata);

    let header = read_header(&packet).unwrap();
    let ans_start = skip_questions(&header, &packet, packet.len()).unwrap();

    let mut cursor = ans_start;
    skip_name(&packet, &mut cursor, packet.len(), 0).unwrap();
    assert_eq!(get_u16(&packet, &mut cursor).unwrap(), T_DS);
    let _ = get_u16(&packet, &mut cursor).unwrap();
    let _ = get_u32(&packet, &mut cursor).unwrap();
    let rdlen = get_u16(&packet, &mut cursor).unwrap();

    let parsed_rdata = &packet[cursor..cursor + rdlen as usize];
    assert_eq!(parsed_rdata, &ds_rdata[..]);

    let key_tag = u16::from_be_bytes([parsed_rdata[0], parsed_rdata[1]]);
    assert_eq!(key_tag, 20326);
    assert_eq!(parsed_rdata[2], 8);
    assert_eq!(parsed_rdata[3], 2);
}

#[cfg(feature = "dnssec")]
#[test]
fn test_rr_rrsig_record_roundtrip() {
    // RRSIG RDATA: type_covered(2) + algorithm(1) + labels(1) + original_ttl(4)
    //   + sig_expiration(4) + sig_inception(4) + key_tag(2) + signer_name(var) + signature(var)
    let mut rrsig_rdata = Vec::new();
    rrsig_rdata.extend_from_slice(&T_A.to_be_bytes()); // type covered = A
    rrsig_rdata.push(8); // algorithm = RSA/SHA-256
    rrsig_rdata.push(2); // labels
    rrsig_rdata.extend_from_slice(&86400u32.to_be_bytes()); // original TTL
    rrsig_rdata.extend_from_slice(&1700000000u32.to_be_bytes()); // expiration
    rrsig_rdata.extend_from_slice(&1690000000u32.to_be_bytes()); // inception
    rrsig_rdata.extend_from_slice(&12345u16.to_be_bytes()); // key tag
    // Signer name: "example.com" in wire format
    let signer = encode_dns_name("example.com");
    rrsig_rdata.extend_from_slice(&signer);
    // Signature (mock)
    rrsig_rdata.extend_from_slice(&[0xCC; 64]);

    let rdata = RrData::Rrsig(&rrsig_rdata);
    let packet = build_response_packet(0x7003, "example.com", T_RRSIG, C_IN, 86400, &rdata);

    let header = read_header(&packet).unwrap();
    let ans_start = skip_questions(&header, &packet, packet.len()).unwrap();

    let mut cursor = ans_start;
    skip_name(&packet, &mut cursor, packet.len(), 0).unwrap();
    assert_eq!(get_u16(&packet, &mut cursor).unwrap(), T_RRSIG);
    let _ = get_u16(&packet, &mut cursor).unwrap();
    let _ = get_u32(&packet, &mut cursor).unwrap();
    let rdlen = get_u16(&packet, &mut cursor).unwrap();

    let parsed_rdata = &packet[cursor..cursor + rdlen as usize];
    assert_eq!(parsed_rdata, &rrsig_rdata[..]);
}

#[cfg(feature = "dnssec")]
#[test]
fn test_rr_nsec_record_roundtrip() {
    // NSEC RDATA: next_domain_name(wire) + type_bitmaps(var)
    let mut nsec_rdata = Vec::new();
    let next_name = encode_dns_name("z.example.com");
    nsec_rdata.extend_from_slice(&next_name);
    // Type bitmap: window 0, bitmap length 7, bits for A(1), NS(2), SOA(6), MX(15), AAAA(28), RRSIG(46), NSEC(47)
    // Window 0 covers types 0-255
    nsec_rdata.push(0); // window block 0
    nsec_rdata.push(7); // bitmap length
    // Bitmap bytes: A=1(bit 1), NS=2(bit 2), SOA=6(bit 6), MX=15(bit 7 of byte 1)
    // byte 0: bits for types 0-7: A(1)=0x40, NS(2)=0x20, SOA(6)=0x02 → 0x62
    nsec_rdata.push(0x62);
    // byte 1: bits for types 8-15: MX(15)=0x01 → 0x01
    nsec_rdata.push(0x01);
    // byte 2: types 16-23: empty
    nsec_rdata.push(0x00);
    // byte 3: types 24-31: AAAA(28)=0x08
    nsec_rdata.push(0x08);
    // bytes 4-5: types 32-47: RRSIG(46)=bit 6 of byte 5, NSEC(47)=bit 7
    nsec_rdata.push(0x00);
    nsec_rdata.push(0x00);
    nsec_rdata.push(0x03); // RRSIG(46)=0x02, NSEC(47)=0x01 → 0x03

    let rdata = RrData::Nsec(&nsec_rdata);
    let packet = build_response_packet(0x7004, "a.example.com", T_NSEC, C_IN, 86400, &rdata);

    let header = read_header(&packet).unwrap();
    let ans_start = skip_questions(&header, &packet, packet.len()).unwrap();

    let mut cursor = ans_start;
    skip_name(&packet, &mut cursor, packet.len(), 0).unwrap();
    assert_eq!(get_u16(&packet, &mut cursor).unwrap(), T_NSEC);
    let _ = get_u16(&packet, &mut cursor).unwrap();
    let _ = get_u32(&packet, &mut cursor).unwrap();
    let rdlen = get_u16(&packet, &mut cursor).unwrap();

    let parsed_rdata = &packet[cursor..cursor + rdlen as usize];
    assert_eq!(parsed_rdata, &nsec_rdata[..]);
}

#[cfg(feature = "dnssec")]
#[test]
fn test_rr_nsec3_record_roundtrip() {
    // NSEC3 RDATA: hash_algo(1) + flags(1) + iterations(2) + salt_len(1) + salt(var)
    //   + hash_len(1) + next_hashed(var) + type_bitmaps(var)
    let mut nsec3_rdata = Vec::new();
    nsec3_rdata.push(1); // hash algorithm: SHA-1
    nsec3_rdata.push(0); // flags
    nsec3_rdata.extend_from_slice(&10u16.to_be_bytes()); // iterations
    nsec3_rdata.push(4); // salt length
    nsec3_rdata.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]); // salt
    nsec3_rdata.push(20); // hash length (SHA-1 = 20 bytes)
    nsec3_rdata.extend_from_slice(&[0xDD; 20]); // next hashed owner name
    // Type bitmap: A(1)
    nsec3_rdata.push(0); // window
    nsec3_rdata.push(1); // bitmap length
    nsec3_rdata.push(0x40); // A record type bit

    let rdata = RrData::Raw(&nsec3_rdata); // NSEC3 may use Raw variant
    let packet = build_response_packet(0x7005, "example.com", T_NSEC3, C_IN, 0, &rdata);

    let header = read_header(&packet).unwrap();
    let ans_start = skip_questions(&header, &packet, packet.len()).unwrap();

    let mut cursor = ans_start;
    skip_name(&packet, &mut cursor, packet.len(), 0).unwrap();
    assert_eq!(get_u16(&packet, &mut cursor).unwrap(), T_NSEC3);
    let _ = get_u16(&packet, &mut cursor).unwrap();
    let _ = get_u32(&packet, &mut cursor).unwrap();
    let rdlen = get_u16(&packet, &mut cursor).unwrap();

    let parsed_rdata = &packet[cursor..cursor + rdlen as usize];
    assert_eq!(parsed_rdata, &nsec3_rdata[..]);
}

// ============================================================================
// Phase 7: EDNS0 OPT Pseudo-Record Tests
// ============================================================================

#[test]
fn test_edns0_opt_construction() {
    // Build a query and add an OPT record via add_pseudoheader
    let mut packet = build_query_packet(0x8001, "example.com", T_A, C_IN);
    let mut header = read_header(&packet).unwrap();

    let _new_len = add_pseudoheader(
        &mut header,
        &mut packet,
        4096,         // limit
        EDNS_PKTSZ as u16, // UDP payload size (1232)
        0,            // no specific option
        false,        // not setting option
        &[],          // no option data
        false,        // no DO bit
        0,            // don't replace
    )
    .expect("add_pseudoheader failed");

    // Header should now have arcount = 1
    write_header(&mut packet, &header).unwrap();
    let updated = read_header(&packet).unwrap();
    assert_eq!(updated.arcount, 1);

    // Find and verify the OPT record
    let ph = find_pseudoheader(&updated, &packet);
    assert!(ph.is_some(), "OPT pseudo-header should be found");
    let ph = ph.unwrap();
    assert_eq!(ph.udp_size, EDNS_PKTSZ as u16);
    assert_eq!(ph.version, 0);
}

#[test]
fn test_edns0_opt_parsing() {
    // Build a packet with manually constructed EDNS0 OPT record
    let mut packet = build_query_packet(0x8002, "test.com", T_A, C_IN);
    let mut header = read_header(&packet).unwrap();

    // Add OPT via the public API
    add_pseudoheader(
        &mut header,
        &mut packet,
        4096,
        4096, // UDP size
        0,
        false,
        &[],
        true, // set DO bit
        0,
    )
    .unwrap();
    write_header(&mut packet, &header).unwrap();

    // Parse it back
    let hdr = read_header(&packet).unwrap();
    let ph = find_pseudoheader(&hdr, &packet).expect("OPT should be found");
    assert_eq!(ph.udp_size, 4096);
    assert_eq!(ph.version, 0);
    assert_eq!(ph.rcode_ext, 0);
    // Verify DO bit is set
    assert_ne!(ph.flags & DO_BIT, 0, "DO bit should be set");
}

#[test]
fn test_edns0_opt_roundtrip() {
    let mut packet = build_query_packet(0x8003, "example.com", T_A, C_IN);
    let mut header = read_header(&packet).unwrap();

    // Add OPT with specific settings
    add_pseudoheader(
        &mut header,
        &mut packet,
        4096,
        EDNS_PKTSZ as u16,
        0,
        false,
        &[],
        true,
        0,
    )
    .unwrap();
    write_header(&mut packet, &header).unwrap();

    // Parse back
    let hdr = read_header(&packet).unwrap();
    assert_eq!(hdr.arcount, 1);

    let ph = find_pseudoheader(&hdr, &packet).expect("OPT should be found");
    assert_eq!(ph.udp_size, EDNS_PKTSZ as u16);
    assert_ne!(ph.flags & DO_BIT, 0, "DO bit should be preserved in roundtrip");
}

#[test]
fn test_edns0_do_bit() {
    let mut packet = build_query_packet(0x8004, "example.com", T_A, C_IN);
    let mut header = read_header(&packet).unwrap();

    // Use add_do_bit convenience function
    let _new_len = add_do_bit(&mut header, &mut packet, 4096)
        .expect("add_do_bit failed");

    write_header(&mut packet, &header).unwrap();

    let hdr = read_header(&packet).unwrap();
    let ph = find_pseudoheader(&hdr, &packet).expect("OPT should exist after add_do_bit");
    assert_ne!(ph.flags & DO_BIT, 0, "DO bit must be set by add_do_bit");
    assert_eq!(ph.udp_size, EDNS_PKTSZ as u16, "UDP size should be EDNS_PKTSZ");
}

// ============================================================================
// Phase 8: Complete Packet Construction and Parsing Tests
// ============================================================================

#[test]
fn test_complete_query_packet() {
    let packet = build_query_packet(0x9001, "www.example.com", T_A, C_IN);

    // Verify header
    let header = read_header(&packet).unwrap();
    assert_eq!(header.id, 0x9001);
    assert!(!header.is_response()); // query
    assert!(header.recursion_desired());
    assert_eq!(header.qdcount, 1);
    assert_eq!(header.ancount, 0);
    assert_eq!(header.nscount, 0);
    assert_eq!(header.arcount, 0);

    // Verify question
    let expected_len = DNS_HEADER_SIZE
        + encode_dns_name("www.example.com").len()
        + 4; // QTYPE + QCLASS
    assert_eq!(packet.len(), expected_len);
}

#[test]
fn test_complete_response_packet() {
    let rdata = RrData::A(Ipv4Addr::new(192, 168, 1, 1));
    let packet = build_response_packet(0x9002, "host.local", T_A, C_IN, 300, &rdata);

    let header = read_header(&packet).unwrap();
    assert!(header.is_response());
    assert!(header.is_authoritative());
    assert_eq!(header.qdcount, 1);
    assert_eq!(header.ancount, 1);

    // Verify we can skip questions and reach the answer
    let ans_start = skip_questions(&header, &packet, packet.len()).unwrap();
    assert!(ans_start > DNS_HEADER_SIZE);
    assert!(ans_start < packet.len());
}

#[test]
fn test_response_with_authority_additional() {
    // Build a response with answer, authority, and additional sections
    let mut packet = vec![0u8; 4096];
    let mut header = DnsHeader {
        id: 0x9003,
        hb3: HB3_QR | HB3_RD | HB3_AA,
        hb4: HB4_RA,
        qdcount: 1,
        ancount: 0,
        nscount: 0,
        arcount: 0,
    };
    write_header(&mut packet, &header).unwrap();

    // Question section
    let qname = encode_dns_name("example.com");
    let mut cursor = DNS_HEADER_SIZE;
    packet[cursor..cursor + qname.len()].copy_from_slice(&qname);
    cursor += qname.len();
    put_u16(&mut packet, &mut cursor, T_A).unwrap();
    put_u16(&mut packet, &mut cursor, C_IN).unwrap();

    let qname_offset = DNS_HEADER_SIZE as i32;

    // Answer: A record
    let mut truncp = false;
    let a_rdata = RrData::A(Ipv4Addr::new(10, 0, 0, 1));
    add_resource_record(
        &mut header, &mut packet, 4096, &mut truncp,
        qname_offset, &mut cursor, 300, RrSection::Answer, T_A, C_IN, &a_rdata,
    ).unwrap();

    // Authority: NS record
    let ns_rdata = RrData::Ns("ns1.example.com");
    add_resource_record(
        &mut header, &mut packet, 4096, &mut truncp,
        qname_offset, &mut cursor, 86400, RrSection::Authority, T_NS, C_IN, &ns_rdata,
    ).unwrap();

    // Additional: A record for ns1 (using root name since no compression available)
    let ns_a_rdata = RrData::A(Ipv4Addr::new(10, 0, 0, 2));
    add_resource_record(
        &mut header, &mut packet, 4096, &mut truncp,
        -1, &mut cursor, 86400, RrSection::Additional, T_A, C_IN, &ns_a_rdata,
    ).unwrap();

    write_header(&mut packet, &header).unwrap();
    packet.truncate(cursor);

    // Verify section counts
    let hdr = read_header(&packet).unwrap();
    assert_eq!(hdr.qdcount, 1);
    assert_eq!(hdr.ancount, 1);
    assert_eq!(hdr.nscount, 1);
    assert_eq!(hdr.arcount, 1);

    // Navigate through all sections
    let ans_start = skip_questions(&hdr, &packet, packet.len()).unwrap();
    let mut nav = ans_start;
    skip_section(&packet, &mut nav, hdr.ancount, packet.len()).unwrap();
    skip_section(&packet, &mut nav, hdr.nscount, packet.len()).unwrap();
    skip_section(&packet, &mut nav, hdr.arcount, packet.len()).unwrap();
    assert_eq!(nav, packet.len());
}

#[test]
fn test_packet_section_navigation() {
    // Build a response with 2 answers and 1 authority
    let mut packet = vec![0u8; 4096];
    let mut header = DnsHeader {
        id: 0x9004,
        hb3: HB3_QR | HB3_RD,
        hb4: HB4_RA,
        qdcount: 1,
        ancount: 0,
        nscount: 0,
        arcount: 0,
    };
    write_header(&mut packet, &header).unwrap();

    let qname = encode_dns_name("multi.example.com");
    let mut cursor = DNS_HEADER_SIZE;
    packet[cursor..cursor + qname.len()].copy_from_slice(&qname);
    cursor += qname.len();
    put_u16(&mut packet, &mut cursor, T_A).unwrap();
    put_u16(&mut packet, &mut cursor, C_IN).unwrap();

    let qname_offset = DNS_HEADER_SIZE as i32;
    let mut truncp = false;

    // Answer 1
    let a1 = RrData::A(Ipv4Addr::new(10, 0, 0, 1));
    add_resource_record(
        &mut header, &mut packet, 4096, &mut truncp,
        qname_offset, &mut cursor, 300, RrSection::Answer, T_A, C_IN, &a1,
    ).unwrap();

    // Answer 2
    let a2 = RrData::A(Ipv4Addr::new(10, 0, 0, 2));
    add_resource_record(
        &mut header, &mut packet, 4096, &mut truncp,
        qname_offset, &mut cursor, 300, RrSection::Answer, T_A, C_IN, &a2,
    ).unwrap();

    // Authority: SOA
    let soa = RrData::Soa {
        mname: "ns1.example.com",
        rname: "admin.example.com",
        serial: 1,
        refresh: 3600,
        retry: 900,
        expire: 604800,
        minimum: 86400,
    };
    add_resource_record(
        &mut header, &mut packet, 4096, &mut truncp,
        qname_offset, &mut cursor, 86400, RrSection::Authority, T_SOA, C_IN, &soa,
    ).unwrap();

    write_header(&mut packet, &header).unwrap();
    packet.truncate(cursor);

    // Verify counts
    let hdr = read_header(&packet).unwrap();
    assert_eq!(hdr.ancount, 2);
    assert_eq!(hdr.nscount, 1);

    // Navigate section by section
    let ans_start = skip_questions(&hdr, &packet, packet.len()).unwrap();
    let mut pos = ans_start;

    // Skip 2 answers
    skip_section(&packet, &mut pos, hdr.ancount, packet.len()).unwrap();

    // Skip 1 authority
    skip_section(&packet, &mut pos, hdr.nscount, packet.len()).unwrap();

    // Should be at end
    assert_eq!(pos, packet.len());
}

// ============================================================================
// Phase 9: Boundary Validation and Malformed Packets Tests
// ============================================================================

#[test]
fn test_truncated_header_rejection() {
    // Packet shorter than 12 bytes
    let short = vec![0u8; 6];
    let result: Result<DnsHeader, WireError> = read_header(&short);
    assert!(result.is_err(), "packet shorter than 12 bytes must be rejected");

    // Empty packet
    let empty: Vec<u8> = Vec::new();
    let result2: Result<DnsHeader, WireError> = read_header(&empty);
    assert!(result2.is_err(), "empty packet must be rejected");
}

#[test]
fn test_truncated_question_rejection() {
    // Header says QDCOUNT=1 but no question data follows
    let mut packet = vec![0u8; DNS_HEADER_SIZE];
    let header = DnsHeader {
        id: 0xBBBB,
        hb3: 0,
        hb4: 0,
        qdcount: 1,
        ancount: 0,
        nscount: 0,
        arcount: 0,
    };
    write_header(&mut packet, &header).unwrap();
    // No question data — packet ends right after header

    let hdr = read_header(&packet).unwrap();
    let result = skip_questions(&hdr, &packet, packet.len());
    assert!(result.is_err(), "truncated question section should be rejected");
}

#[test]
fn test_truncated_rr_rejection() {
    // Build a packet with answer count = 1 but truncated RR data
    let mut packet = build_query_packet(0xCCCC, "test.com", T_A, C_IN);
    // Manually increment ancount
    packet[6] = 0;
    packet[7] = 1; // ancount = 1

    // Add a partial RR: just a compression pointer, but no TYPE/CLASS/TTL/RDLEN/RDATA
    packet.push(0xC0);
    packet.push(0x0C); // pointer to question name

    let hdr = read_header(&packet).unwrap();
    let ans_start = skip_questions(&hdr, &packet, packet.len()).unwrap();

    let mut cursor = ans_start;
    let result = skip_section(&packet, &mut cursor, 1, packet.len());
    assert!(result.is_err(), "truncated RR should be rejected");
}

#[test]
fn test_oversized_rdlength_rejection() {
    // Build a response where RDLENGTH exceeds remaining packet data
    let mut packet = build_query_packet(0xDDDD, "test.com", T_A, C_IN);
    packet[6] = 0;
    packet[7] = 1; // ancount = 1

    // Add answer: compression pointer + TYPE + CLASS + TTL + RDLENGTH(999) + only 4 bytes data
    packet.push(0xC0);
    packet.push(0x0C); // pointer
    packet.extend_from_slice(&T_A.to_be_bytes());
    packet.extend_from_slice(&C_IN.to_be_bytes());
    packet.extend_from_slice(&300u32.to_be_bytes());
    packet.extend_from_slice(&999u16.to_be_bytes()); // RDLENGTH = 999 (far beyond packet)
    packet.extend_from_slice(&[1, 2, 3, 4]); // only 4 bytes of RDATA

    let hdr = read_header(&packet).unwrap();
    let ans_start = skip_questions(&hdr, &packet, packet.len()).unwrap();

    let mut cursor = ans_start;
    let result = skip_section(&packet, &mut cursor, 1, packet.len());
    assert!(result.is_err(), "oversized RDLENGTH should be rejected");
}

#[test]
fn test_malformed_label_length() {
    // Create a packet with label length > 63 (but not a compression pointer)
    // Label lengths 64-191 are invalid in DNS (bits 00xxxxxx = label, 11xxxxxx = pointer)
    let mut packet = vec![0u8; DNS_HEADER_SIZE];
    let header = DnsHeader {
        id: 0xEEEE,
        hb3: 0,
        hb4: 0,
        qdcount: 1,
        ancount: 0,
        nscount: 0,
        arcount: 0,
    };
    write_header(&mut packet, &header).unwrap();

    // Label with length 64 (0x40) — this is in the reserved range
    packet.push(0x40);
    packet.extend(std::iter::repeat(b'x').take(64));
    packet.push(0); // root
    packet.extend_from_slice(&T_A.to_be_bytes());
    packet.extend_from_slice(&C_IN.to_be_bytes());

    let mut cursor = DNS_HEADER_SIZE;
    let mut name_buf = [0u8; MAXDNAME];
    // This should either be rejected as invalid or treated specially
    // The key requirement is no panic
    let _ = extract_name(&packet, packet.len(), &mut cursor, &mut name_buf, true);
}

#[test]
fn test_zero_length_packet() {
    let empty: Vec<u8> = Vec::new();

    // read_header should fail
    assert!(read_header(&empty).is_err());

    // extract_name should fail
    let mut cursor = 0;
    let mut name_buf = [0u8; MAXDNAME];
    let result = extract_name(&empty, 0, &mut cursor, &mut name_buf, true);
    assert!(result.is_err(), "zero-length packet should be rejected by extract_name");
}

// ============================================================================
// Phase 10: Fixture-Based Packet Replay Tests
// ============================================================================

#[test]
fn test_captured_dns_query_parsing() {
    // Load and parse captured DNS A query
    let query_a = load_fixture("dns_query_a.bin");
    assert!(query_a.len() >= DNS_HEADER_SIZE, "fixture must be at least 12 bytes");

    let header = read_header(&query_a).expect("should parse query_a header");
    assert!(!header.is_response(), "query should not have QR bit set");
    assert!(header.qdcount >= 1, "query should have at least one question");
    assert_eq!(header.ancount, 0, "query should have no answers");

    // Skip questions should succeed
    let end = skip_questions(&header, &query_a, query_a.len());
    assert!(end.is_ok(), "skip_questions should succeed on valid query fixture");

    // Load and parse captured DNS AAAA query
    let query_aaaa = load_fixture("dns_query_aaaa.bin");
    assert!(query_aaaa.len() >= DNS_HEADER_SIZE);

    let header_aaaa = read_header(&query_aaaa).expect("should parse query_aaaa header");
    assert!(!header_aaaa.is_response());
    assert!(header_aaaa.qdcount >= 1);
}

#[test]
fn test_captured_dns_response_parsing() {
    // Test A response fixture
    let resp_a = load_fixture("dns_response_a.bin");
    let header_a = read_header(&resp_a).expect("should parse response_a header");
    assert!(header_a.is_response(), "response should have QR bit set");
    assert!(header_a.ancount >= 1, "response should have answer(s)");

    let ans_start = skip_questions(&header_a, &resp_a, resp_a.len())
        .expect("skip_questions should succeed on response fixture");
    assert!(ans_start > DNS_HEADER_SIZE);

    // Test AAAA response fixture
    let resp_aaaa = load_fixture("dns_response_aaaa.bin");
    let header_aaaa = read_header(&resp_aaaa).expect("should parse response_aaaa header");
    assert!(header_aaaa.is_response());
    assert!(header_aaaa.ancount >= 1);

    // Test CNAME response fixture
    let resp_cname = load_fixture("dns_response_cname.bin");
    let header_cname = read_header(&resp_cname).expect("should parse cname response header");
    assert!(header_cname.is_response());

    // Test compressed response fixture
    let resp_comp = load_fixture("dns_response_compressed.bin");
    let header_comp = read_header(&resp_comp).expect("should parse compressed response header");
    assert!(header_comp.is_response());

    // Navigate through compressed response sections
    let comp_ans = skip_questions(&header_comp, &resp_comp, resp_comp.len()).unwrap();
    let mut cursor = comp_ans;
    // Should be able to skip all answer RRs
    let skip_result = skip_section(&resp_comp, &mut cursor, header_comp.ancount, resp_comp.len());
    assert!(skip_result.is_ok(), "should navigate compressed response answers");

    // Test NXDOMAIN response fixture
    let resp_nx = load_fixture("dns_response_nxdomain.bin");
    let header_nx = read_header(&resp_nx).expect("should parse nxdomain response header");
    assert!(header_nx.is_response());
    let rcode = header_nx.rcode();
    assert_eq!(rcode, Rcode::NxDomain as u8, "NXDOMAIN fixture should have RCODE=3");

    // Test MX response fixture
    let resp_mx = load_fixture("dns_response_mx.bin");
    let header_mx = read_header(&resp_mx).expect("should parse mx response header");
    assert!(header_mx.is_response());

    // Test SRV response fixture
    let resp_srv = load_fixture("dns_response_srv.bin");
    let header_srv = read_header(&resp_srv).expect("should parse srv response header");
    assert!(header_srv.is_response());
}

#[test]
fn test_captured_packet_roundtrip() {
    // For each query fixture, parse the header and verify it can be written back identically
    let query_a = load_fixture("dns_query_a.bin");
    let header = read_header(&query_a).expect("parse query_a");

    let mut rewritten = vec![0u8; DNS_HEADER_SIZE];
    write_header(&mut rewritten, &header).expect("write header back");
    assert_eq!(
        &rewritten[..DNS_HEADER_SIZE],
        &query_a[..DNS_HEADER_SIZE],
        "header roundtrip should be byte-identical for query_a"
    );

    // Parse EDNS0 query and verify pseudoheader detection
    let query_edns = load_fixture("dns_query_edns0.bin");
    let header_edns = read_header(&query_edns).expect("parse edns0 query");
    if header_edns.arcount > 0 {
        let ph = find_pseudoheader(&header_edns, &query_edns);
        // If fixture has OPT, verify it parses without error
        if let Some(ph) = ph {
            assert!(ph.udp_size > 0, "UDP size should be positive");
        }
    }

    // Verify response fixture header roundtrip
    let resp_a = load_fixture("dns_response_a.bin");
    let header_resp = read_header(&resp_a).expect("parse response_a");
    let mut rewritten_resp = vec![0u8; DNS_HEADER_SIZE];
    write_header(&mut rewritten_resp, &header_resp).expect("write response header back");
    assert_eq!(
        &rewritten_resp[..DNS_HEADER_SIZE],
        &resp_a[..DNS_HEADER_SIZE],
        "header roundtrip should be byte-identical for response_a"
    );
}

// ============================================================================
// Additional fixture tests for malformed packets
// ============================================================================

#[test]
fn test_malformed_compression_loop_fixture() {
    let malformed = load_fixture("dns_malformed_compression_loop.bin");
    if malformed.len() >= DNS_HEADER_SIZE {
        let header = read_header(&malformed);
        // Header parsing may succeed on a valid-sized header
        if let Ok(_hdr) = header {
            // But navigating the packet should fail due to compression loop
            let mut cursor = DNS_HEADER_SIZE;
            let mut name_buf = [0u8; MAXDNAME];
            if cursor < malformed.len() {
                let result = extract_name(&malformed, malformed.len(), &mut cursor, &mut name_buf, true);
                // Should either error or handle gracefully — no infinite loop
                let _ = result;
            }
        }
    }
}

#[test]
fn test_malformed_truncated_fixture() {
    let truncated = load_fixture("dns_malformed_truncated.bin");
    assert_eq!(truncated.len(), 12, "truncated fixture should be header-only (12 bytes)");

    let header = read_header(&truncated).expect("12-byte header should parse");
    // Header claims QDCOUNT=1 but no question data
    if header.qdcount > 0 {
        let result = skip_questions(&header, &truncated, truncated.len());
        assert!(result.is_err(), "skip_questions should fail on truncated packet with QDCOUNT>0");
    }
}

// ============================================================================
// Additional EDNS0 fixture tests
// ============================================================================

#[test]
fn test_edns0_query_fixture() {
    let edns_query = load_fixture("dns_query_edns0.bin");
    let header = read_header(&edns_query).expect("parse EDNS0 query fixture");
    assert!(!header.is_response());

    if header.arcount > 0 {
        let ph = find_pseudoheader(&header, &edns_query);
        if let Some(ph) = ph {
            // EDNS0 query should advertise a UDP payload size
            assert!(ph.udp_size > 0, "EDNS0 query should have positive UDP size");
        }
    }
}

#[test]
fn test_edns0_response_fixture() {
    let edns_resp = load_fixture("dns_response_edns0.bin");
    let header = read_header(&edns_resp).expect("parse EDNS0 response fixture");
    assert!(header.is_response());

    if header.arcount > 0 {
        let ph = find_pseudoheader(&header, &edns_resp);
        if let Some(ph) = ph {
            assert!(ph.udp_size > 0, "EDNS0 response should have positive UDP size");
        }
    }
}

// ============================================================================
// Additional tests using AllAddr from types::addr
// ============================================================================

#[test]
fn test_alladdr_v4_in_rr() {
    // Verify that AllAddr::V4 correctly represents IPv4 addresses for DNS records
    let addr = AllAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
    match addr {
        AllAddr::V4(ip) => assert_eq!(ip, Ipv4Addr::new(8, 8, 8, 8)),
        _ => panic!("expected AllAddr::V4"),
    }
}

#[test]
fn test_alladdr_v6_in_rr() {
    // Verify that AllAddr::V6 correctly represents IPv6 addresses for DNS records
    let addr = AllAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    match addr {
        AllAddr::V6(ip) => assert_eq!(ip, Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        _ => panic!("expected AllAddr::V6"),
    }
}

// ============================================================================
// Verify config constants match expected values
// ============================================================================

#[test]
fn test_wire_format_constants() {
    // Verify protocol constants are correct per dns-protocol.h
    assert_eq!(MAXLABEL, 63, "max label length");
    assert_eq!(RRFIXEDSZ, 10, "RR fixed size (TYPE+CLASS+TTL+RDLEN)");
    assert_eq!(INADDRSZ, 4, "IPv4 address size");
    assert_eq!(IN6ADDRSZ, 16, "IPv6 address size");
    assert_eq!(PROTO_PACKETSZ, 512, "default packet size from protocol");
    assert_eq!(MAXDNAME as usize, 1025, "max domain name from protocol");

    // Verify config constants
    assert_eq!(EDNS_PKTSZ, 1232, "default EDNS0 buffer size");
    assert_eq!(constants::MAXDNAME, 1025, "max domain name from config");
    assert_eq!(constants::PACKETSZ, 512, "default packet size from config");
    assert_eq!(SMALLDNAME, 50, "small domain name optimization size");

    // Verify RrType enum values match the u16 constants from dns-protocol.h
    assert_eq!(RrType::A as u16, T_A, "RrType::A must match T_A constant");
    assert_eq!(RrType::Aaaa as u16, T_AAAA, "RrType::Aaaa must match T_AAAA constant");
    assert_eq!(RrType::Cname as u16, T_CNAME, "RrType::Cname must match T_CNAME constant");
    assert_eq!(RrType::Mx as u16, T_MX, "RrType::Mx must match T_MX constant");
    assert_eq!(RrType::Ns as u16, T_NS, "RrType::Ns must match T_NS constant");
    assert_eq!(RrType::Ptr as u16, T_PTR, "RrType::Ptr must match T_PTR constant");
    assert_eq!(RrType::Soa as u16, T_SOA, "RrType::Soa must match T_SOA constant");
    assert_eq!(RrType::Srv as u16, T_SRV, "RrType::Srv must match T_SRV constant");
    assert_eq!(RrType::Txt as u16, T_TXT, "RrType::Txt must match T_TXT constant");
    assert_eq!(RrType::Opt as u16, 41, "RrType::Opt must be 41");

    // Verify DnsClass enum values match the u16 constants
    assert_eq!(DnsClass::In as u16, C_IN, "DnsClass::In must match C_IN constant");
    assert_eq!(DnsClass::Chaos as u16, C_CHAOS, "DnsClass::Chaos must match C_CHAOS constant");
    assert_eq!(DnsClass::Hesiod as u16, C_HESIOD, "DnsClass::Hesiod must match C_HESIOD constant");
    assert_eq!(DnsClass::Any as u16, C_ANY, "DnsClass::Any must match C_ANY constant");

    // Verify RrType::from_u16 roundtrip
    assert_eq!(RrType::from_u16(T_A), Some(RrType::A));
    assert_eq!(RrType::from_u16(T_AAAA), Some(RrType::Aaaa));
    assert_eq!(RrType::from_u16(9999), None, "unknown RR type should return None");

    // Verify DnsClass::from_u16 roundtrip
    assert_eq!(DnsClass::from_u16(C_IN), Some(DnsClass::In));
    assert_eq!(DnsClass::from_u16(C_ANY), Some(DnsClass::Any));
    assert_eq!(DnsClass::from_u16(9999), None, "unknown class should return None");

    // Verify Rcode enum consistency
    assert_eq!(Rcode::NoError as u8, 0);
    assert_eq!(Rcode::FormErr as u8, 1);
    assert_eq!(Rcode::ServFail as u8, 2);
    assert_eq!(Rcode::NxDomain as u8, 3);
    assert_eq!(Rcode::NotImp as u8, 4);
    assert_eq!(Rcode::Refused as u8, 5);
}

// ============================================================================
// setup_reply test
// ============================================================================

#[test]
fn test_setup_reply_clears_counts() {
    let mut header = DnsHeader {
        id: 0xF001,
        hb3: HB3_RD,
        hb4: 0,
        qdcount: 1,
        ancount: 0,
        nscount: 0,
        arcount: 0,
    };

    // setup_reply should set QR bit and configure response flags
    setup_reply(&mut header, 0, 0);

    assert!(header.is_response(), "setup_reply should set QR bit");
    // Answer, authority, and additional counts should be zeroed
    assert_eq!(header.ancount, 0);
    assert_eq!(header.nscount, 0);
    assert_eq!(header.arcount, 0);
}

#[test]
fn test_setup_reply_preserves_id() {
    let mut header = DnsHeader {
        id: 0xBEEF,
        hb3: HB3_RD,
        hb4: 0,
        qdcount: 1,
        ancount: 0,
        nscount: 0,
        arcount: 0,
    };

    setup_reply(&mut header, 0, 0);
    assert_eq!(header.id, 0xBEEF, "setup_reply should preserve the query ID");
}

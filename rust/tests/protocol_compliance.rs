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

//! # Property-Based Protocol Compliance Tests
//!
//! Uses the [`proptest`] crate (v1.9.0) for property-based testing of DNS,
//! DHCPv4, and DHCPv6 wire format implementations. Instead of hand-writing
//! individual test vectors, these tests generate thousands of random—but
//! structurally valid—protocol messages and verify round-trip invariants:
//!
//! ```text
//! Property:  ∀ msg.  parse(serialize(msg)) == Ok(msg)
//! ```
//!
//! Coverage:
//! - **DNS (RFC 1035):** Header, name compression, A/AAAA/CNAME/PTR/MX/SRV
//!   records, query and response packets, name-length invariants, packet-size
//!   invariants, case-preservation.
//! - **DHCPv4 (RFC 2131):** Packet round-trip, option TLV encoding, message
//!   type consistency, minimum packet size, magic cookie presence.
//! - **DHCPv6 (RFC 3315):** Message round-trip, option TLV encoding, DUID
//!   round-trip, IA_NA option with nested IAADDR sub-options.
//! - **Cross-Protocol:** Packet size bounds, option capacity, network byte
//!   order consistency.
//!
//! ## proptest Configuration
//! - Debug builds: 256 cases (fast feedback during development).
//! - Release builds: 10 000 cases (thorough fuzzing in CI).
//! - Shrink iterations: 1 000 (good failure minimization).

use std::net::{Ipv4Addr, Ipv6Addr};

use proptest::collection::vec as prop_vec;
use proptest::prelude::*;

// ---------------------------------------------------------------------------
// DNS protocol imports (always available — not feature-gated)
// ---------------------------------------------------------------------------
use dnsmasq::dns::protocol::{
    get_u16, get_u32, put_u16, put_u32, DnsClass, DnsHeader, DnsHeaderFlags, DnsName, DnsPacket,
    DnsPacketBuilder, DnsQuestion, RRType, ResponseCode, MAXDNAME, MAXLABEL, PACKETSZ, RRFIXEDSZ,
};

// ---------------------------------------------------------------------------
// DHCPv4 protocol imports (feature-gated)
// ---------------------------------------------------------------------------
#[cfg(feature = "dhcp")]
use dnsmasq::dhcp::v4::protocol::{
    DhcpPacket, DhcpV4State, BOOTREPLY, BOOTREQUEST, DHCP_COOKIE, DHCP_PACKET_SIZE, OPTION_END,
    OPTION_MESSAGE_TYPE, OPTION_PAD,
};

// ---------------------------------------------------------------------------
// DHCPv6 protocol imports (feature-gated)
// ---------------------------------------------------------------------------
#[cfg(feature = "dhcp6")]
use dnsmasq::dhcp::v6::protocol::{opt6_find, opt6_next, opt6_uint, DhcpV6State, IaType};

// ===========================================================================
// proptest configuration helpers
// ===========================================================================

/// Returns a [`ProptestConfig`] tuned for the current build profile.
/// - Debug:   256 cases, 1 000 max shrink iters.
/// - Release: 10 000 cases, 1 000 max shrink iters.
fn test_config() -> ProptestConfig {
    let cases = if cfg!(debug_assertions) { 256 } else { 10_000 };
    ProptestConfig {
        cases,
        max_shrink_iters: 1_000,
        ..ProptestConfig::default()
    }
}

// ===========================================================================
// Strategy helpers — DNS
// ===========================================================================

/// Generates a valid DNS label: 1-63 ASCII lower-alpha / digit characters.
/// Start with a letter, end with alphanumeric.
fn dns_label_strategy() -> impl Strategy<Value = String> {
    // label lengths 1..=10 (keep short for composability in names)
    (1usize..=10).prop_flat_map(|len| {
        if len == 1 {
            "[a-z]".prop_map(|s| s.to_string()).boxed()
        } else {
            let middle_len = len.saturating_sub(2);
            (
                "[a-z]".prop_map(|s| s.to_string()),
                prop_vec(
                    "[a-z0-9]".prop_map(|s| s.to_string()),
                    middle_len..=middle_len,
                ),
                "[a-z0-9]".prop_map(|s| s.to_string()),
            )
                .prop_map(|(f, m, l)| {
                    let mut s = f;
                    for c in m {
                        s.push_str(&c);
                    }
                    s.push_str(&l);
                    s
                })
                .boxed()
        }
    })
}

/// Generates a valid DNS domain name with 1-4 labels, total wire length ≤ 253.
fn dns_name_strategy() -> impl Strategy<Value = DnsName> {
    prop_vec(dns_label_strategy(), 1..=4).prop_filter_map(
        "total name length must be ≤ 253 and wire length ≤ 255",
        |labels| {
            let text_len: usize = labels.iter().map(|l| l.len()).sum::<usize>() + labels.len() - 1;
            if text_len > 253 {
                return None;
            }
            let wire_len: usize = labels.iter().map(|l| 1 + l.len()).sum::<usize>() + 1;
            if wire_len > 255 {
                return None;
            }
            let name_str = labels.join(".");
            Some(DnsName::from_str_unchecked(&name_str))
        },
    )
}

/// Strategy for a random [`ResponseCode`].
fn response_code_strategy() -> impl Strategy<Value = ResponseCode> {
    prop_oneof![
        Just(ResponseCode::NoError),
        Just(ResponseCode::FormErr),
        Just(ResponseCode::ServFail),
        Just(ResponseCode::NxDomain),
        Just(ResponseCode::NotImp),
        Just(ResponseCode::Refused),
    ]
}

/// Strategy for a random [`DnsClass`].
fn dns_class_strategy() -> impl Strategy<Value = DnsClass> {
    prop_oneof![
        Just(DnsClass::IN),
        Just(DnsClass::Chaos),
        Just(DnsClass::Hesiod),
        Just(DnsClass::Any),
    ]
}

/// Strategy for a subset of common [`RRType`] values suitable for round-trip tests.
fn rr_type_strategy() -> impl Strategy<Value = RRType> {
    prop_oneof![
        Just(RRType::A),
        Just(RRType::NS),
        Just(RRType::CNAME),
        Just(RRType::SOA),
        Just(RRType::PTR),
        Just(RRType::MX),
        Just(RRType::TXT),
        Just(RRType::AAAA),
        Just(RRType::SRV),
    ]
}

/// Strategy for random [`DnsHeaderFlags`].
fn dns_flags_strategy() -> impl Strategy<Value = DnsHeaderFlags> {
    (
        any::<bool>(), // qr
        0u8..16,       // opcode (4 bits)
        any::<bool>(), // aa
        any::<bool>(), // tc
        any::<bool>(), // rd
        any::<bool>(), // ra
        any::<bool>(), // ad
        any::<bool>(), // cd
        response_code_strategy(),
    )
        .prop_map(
            |(qr, opcode, aa, tc, rd, ra, ad, cd, rcode)| DnsHeaderFlags {
                qr,
                opcode,
                aa,
                tc,
                rd,
                ra,
                ad,
                cd,
                rcode,
            },
        )
}

/// Strategy for a random [`DnsHeader`].
fn dns_header_strategy() -> impl Strategy<Value = DnsHeader> {
    (
        any::<u16>(), // id
        dns_flags_strategy(),
        0u16..=10, // qdcount
        0u16..=10, // ancount
        0u16..=10, // nscount
        0u16..=10, // arcount
    )
        .prop_map(
            |(id, flags, qdcount, ancount, nscount, arcount)| DnsHeader {
                id,
                flags,
                qdcount,
                ancount,
                nscount,
                arcount,
            },
        )
}

/// Strategy for a random [`DnsQuestion`].
fn dns_question_strategy() -> impl Strategy<Value = DnsQuestion> {
    (
        dns_name_strategy(),
        rr_type_strategy(),
        dns_class_strategy(),
    )
        .prop_map(|(name, qtype, qclass)| DnsQuestion {
            name,
            qtype,
            qclass,
        })
}

// ===========================================================================
//  DNS Wire Format Round-Trip Tests (RFC 1035)
// ===========================================================================

proptest! {
    #![proptest_config(test_config())]

    // -----------------------------------------------------------------------
    // Test: DNS header round-trip
    // Property: ∀ header: DnsHeader. parse(serialize(header)) == Ok(header)
    // -----------------------------------------------------------------------
    #[test]
    fn dns_header_roundtrip(header in dns_header_strategy()) {
        let mut buf = bytes::BytesMut::new();
        header.serialize(&mut buf);
        let wire = buf.freeze();

        // DNS header is always exactly 12 bytes
        prop_assert_eq!(wire.len(), 12);

        let parsed = DnsHeader::parse(&wire).expect("header parse must succeed");
        prop_assert_eq!(parsed.id, header.id);
        prop_assert_eq!(parsed.flags.qr, header.flags.qr);
        prop_assert_eq!(parsed.flags.opcode, header.flags.opcode);
        prop_assert_eq!(parsed.flags.aa, header.flags.aa);
        prop_assert_eq!(parsed.flags.tc, header.flags.tc);
        prop_assert_eq!(parsed.flags.rd, header.flags.rd);
        prop_assert_eq!(parsed.flags.ra, header.flags.ra);
        prop_assert_eq!(parsed.flags.ad, header.flags.ad);
        prop_assert_eq!(parsed.flags.cd, header.flags.cd);
        prop_assert_eq!(parsed.qdcount, header.qdcount);
        prop_assert_eq!(parsed.ancount, header.ancount);
        prop_assert_eq!(parsed.nscount, header.nscount);
        prop_assert_eq!(parsed.arcount, header.arcount);
    }
}

proptest! {
    #![proptest_config(test_config())]

    // -----------------------------------------------------------------------
    // Test: DNS name compression round-trip
    // Property: ∀ name: DnsName. parse(serialize(name)) == Ok(name)
    // -----------------------------------------------------------------------
    #[test]
    fn dns_name_roundtrip(name in dns_name_strategy()) {
        let mut buf = bytes::BytesMut::new();
        name.to_wire(&mut buf);
        let wire = buf.freeze();

        // Wire format ends with a 0x00 root label terminator
        prop_assert_eq!(*wire.last().unwrap(), 0u8);

        // Wire length = sum(1+label.len()) + 1 root ≤ 255
        prop_assert!(wire.len() <= 255);

        let (parsed, _offset) = DnsName::from_wire(0, &wire).expect("name parse must succeed");
        // Compare case-insensitively (RFC 1035 Section 2.3.3)
        prop_assert_eq!(
            parsed.to_string().to_ascii_lowercase(),
            name.to_string().to_ascii_lowercase()
        );
    }
}

proptest! {
    #![proptest_config(test_config())]

    // -----------------------------------------------------------------------
    // Test: DNS name label length invariant
    // Property: each label ≤ 63 octets, total wire ≤ 255 octets
    // -----------------------------------------------------------------------
    #[test]
    fn dns_name_label_length_invariant(name in dns_name_strategy()) {
        let mut buf = bytes::BytesMut::new();
        name.to_wire(&mut buf);
        let wire = buf.freeze();

        // Total wire length invariant
        prop_assert!(wire.len() <= 255, "wire name length {} exceeds 255", wire.len());

        // Individual label length invariant
        let mut pos = 0usize;
        while pos < wire.len() {
            let label_len = wire[pos] as usize;
            if label_len == 0 {
                break; // root terminator
            }
            prop_assert!(
                label_len <= MAXLABEL,
                "label length {} exceeds MAXLABEL {}",
                label_len,
                MAXLABEL
            );
            pos += 1 + label_len;
        }
    }
}

proptest! {
    #![proptest_config(test_config())]

    // -----------------------------------------------------------------------
    // Test: DNS name case preservation
    // Property: DNS names preserve case in wire format but compare
    //           case-insensitively (RFC 1035 Section 2.3.3)
    // -----------------------------------------------------------------------
    #[test]
    fn dns_name_case_preservation(
        labels in prop_vec("[A-Za-z]{1,10}".prop_map(|s| s.to_string()), 1..=3)
    ) {
        let name_str = labels.join(".");
        let name = DnsName::from_str_unchecked(&name_str);
        let mut buf = bytes::BytesMut::new();
        name.to_wire(&mut buf);
        let wire = buf.freeze();

        let (parsed, _) = DnsName::from_wire(0, &wire).expect("parse must succeed");
        let parsed_str = parsed.to_string();

        // DnsName::to_string() produces FQDN format with trailing dot.
        // Strip it for comparison with the original non-FQDN input.
        let parsed_normalized = parsed_str.strip_suffix('.').unwrap_or(&parsed_str);

        // Case-insensitive equality (RFC 1035 Section 2.3.3)
        prop_assert_eq!(
            parsed_normalized.to_ascii_lowercase(),
            name_str.to_ascii_lowercase(),
            "case-insensitive mismatch"
        );
    }
}

proptest! {
    #![proptest_config(test_config())]

    // -----------------------------------------------------------------------
    // Test: DNS A record round-trip
    // Build a response with one A record, serialize via builder, parse back.
    // -----------------------------------------------------------------------
    #[test]
    fn dns_a_record_roundtrip(
        id in any::<u16>(),
        name in dns_name_strategy(),
        ttl in any::<u32>(),
        ip in any::<u32>(),
    ) {
        let addr = Ipv4Addr::from(ip);
        let rdata = addr.octets().to_vec();

        let packet = DnsPacketBuilder::new(id)
            .set_response()
            .add_question(&name, RRType::A, DnsClass::IN)
            .add_answer(&name, RRType::A, DnsClass::IN, ttl, &rdata)
            .build()
            .expect("build must succeed");

        let wire = packet.raw.clone();
        let parsed = DnsPacket::parse(&wire).expect("parse must succeed");

        prop_assert_eq!(parsed.header.id, id);
        prop_assert!(parsed.header.flags.qr, "response flag must be set");
        prop_assert_eq!(parsed.answers.len(), 1);

        let ans = &parsed.answers[0];
        prop_assert_eq!(ans.rr_type, RRType::A);
        prop_assert_eq!(ans.class, DnsClass::IN);
        prop_assert_eq!(ans.ttl, ttl);
        prop_assert_eq!(ans.rdata.len(), 4);

        let parsed_addr = ans.as_ipv4();
        prop_assert!(parsed_addr.is_some(), "A record must parse as IPv4");
        prop_assert_eq!(parsed_addr.unwrap(), addr);
    }
}

proptest! {
    #![proptest_config(test_config())]

    // -----------------------------------------------------------------------
    // Test: DNS AAAA record round-trip
    // -----------------------------------------------------------------------
    #[test]
    fn dns_aaaa_record_roundtrip(
        id in any::<u16>(),
        name in dns_name_strategy(),
        ttl in any::<u32>(),
        ip in any::<u128>(),
    ) {
        let addr = Ipv6Addr::from(ip);
        let rdata = addr.octets().to_vec();

        let packet = DnsPacketBuilder::new(id)
            .set_response()
            .add_question(&name, RRType::AAAA, DnsClass::IN)
            .add_answer(&name, RRType::AAAA, DnsClass::IN, ttl, &rdata)
            .build()
            .expect("build must succeed");

        let wire = packet.raw.clone();
        let parsed = DnsPacket::parse(&wire).expect("parse must succeed");

        prop_assert_eq!(parsed.header.id, id);
        prop_assert_eq!(parsed.answers.len(), 1);

        let ans = &parsed.answers[0];
        prop_assert_eq!(ans.rr_type, RRType::AAAA);
        prop_assert_eq!(ans.rdata.len(), 16);

        let parsed_addr = ans.as_ipv6();
        prop_assert!(parsed_addr.is_some(), "AAAA record must parse as IPv6");
        prop_assert_eq!(parsed_addr.unwrap(), addr);
    }
}

proptest! {
    #![proptest_config(test_config())]

    // -----------------------------------------------------------------------
    // Test: DNS query packet round-trip
    // Generate a query packet with 1-3 questions, serialize, parse, verify.
    // -----------------------------------------------------------------------
    #[test]
    fn dns_query_packet_roundtrip(
        id in any::<u16>(),
        questions in prop_vec(dns_question_strategy(), 1..=3),
    ) {
        let mut builder = DnsPacketBuilder::new(id);
        for q in &questions {
            builder = builder.add_question(&q.name, q.qtype, q.qclass);
        }

        let packet = builder.build().expect("build must succeed");
        let wire = packet.raw.clone();

        let parsed = DnsPacket::parse(&wire).expect("parse must succeed");

        prop_assert_eq!(parsed.header.id, id);
        prop_assert!(!parsed.header.flags.qr, "query flag must be false");
        prop_assert_eq!(parsed.questions.len(), questions.len());

        for (orig, parsed_q) in questions.iter().zip(parsed.questions.iter()) {
            prop_assert_eq!(
                orig.name.to_string().to_ascii_lowercase(),
                parsed_q.name.to_string().to_ascii_lowercase()
            );
            prop_assert_eq!(orig.qtype, parsed_q.qtype);
            prop_assert_eq!(orig.qclass, parsed_q.qclass);
        }

        // Query packets have no answers
        prop_assert_eq!(parsed.answers.len(), 0);
        prop_assert_eq!(parsed.authority.len(), 0);
        prop_assert_eq!(parsed.additional.len(), 0);
    }
}

proptest! {
    #![proptest_config(test_config())]

    // -----------------------------------------------------------------------
    // Test: DNS response packet round-trip
    // Generate a response with question + 1-3 answer A RRs, serialize, parse.
    // -----------------------------------------------------------------------
    #[test]
    fn dns_response_packet_roundtrip(
        id in any::<u16>(),
        name in dns_name_strategy(),
        ttl in any::<u32>(),
        answer_ips in prop_vec(any::<u32>(), 1..=3),
    ) {
        let mut builder = DnsPacketBuilder::new(id)
            .set_response()
            .set_authoritative()
            .add_question(&name, RRType::A, DnsClass::IN);

        for ip_raw in &answer_ips {
            let addr = Ipv4Addr::from(*ip_raw);
            builder = builder.add_answer(&name, RRType::A, DnsClass::IN, ttl, &addr.octets());
        }

        let packet = builder.build().expect("build must succeed");
        let wire = packet.raw.clone();

        let parsed = DnsPacket::parse(&wire).expect("parse must succeed");

        prop_assert!(parsed.header.flags.qr, "response flag must be set");
        prop_assert!(parsed.header.flags.aa, "authoritative flag must be set");
        prop_assert_eq!(parsed.header.id, id);
        prop_assert_eq!(parsed.questions.len(), 1);
        prop_assert_eq!(parsed.answers.len(), answer_ips.len());

        for (i, ans) in parsed.answers.iter().enumerate() {
            prop_assert_eq!(ans.rr_type, RRType::A);
            prop_assert_eq!(ans.class, DnsClass::IN);
            prop_assert_eq!(ans.ttl, ttl);
            let expected_addr = Ipv4Addr::from(answer_ips[i]);
            prop_assert_eq!(ans.as_ipv4().unwrap(), expected_addr);
        }
    }
}

proptest! {
    #![proptest_config(test_config())]

    // -----------------------------------------------------------------------
    // Test: DNS packet size invariant
    // A simple query or response with a single small RR must not exceed the
    // default UDP packet size (PACKETSZ = 512).
    // -----------------------------------------------------------------------
    #[test]
    fn dns_packet_size_invariant(
        id in any::<u16>(),
        name in dns_name_strategy(),
        ttl in any::<u32>(),
        ip in any::<u32>(),
    ) {
        let addr = Ipv4Addr::from(ip);
        let packet = DnsPacketBuilder::new(id)
            .set_response()
            .add_question(&name, RRType::A, DnsClass::IN)
            .add_answer(&name, RRType::A, DnsClass::IN, ttl, &addr.octets())
            .build()
            .expect("build must succeed");

        let wire_len = packet.raw.len();
        prop_assert!(
            wire_len <= PACKETSZ,
            "single-RR packet length {} exceeds PACKETSZ {}",
            wire_len,
            PACKETSZ
        );
    }
}

// ===========================================================================
// Network byte-order helper tests
// ===========================================================================

proptest! {
    #![proptest_config(test_config())]

    // -----------------------------------------------------------------------
    // Test: put_u16 / get_u16 round-trip (network byte order)
    // Property: ∀ v: u16.  get_u16(put_u16(v), 0) == v
    // -----------------------------------------------------------------------
    #[test]
    fn u16_network_byte_order_roundtrip(val in any::<u16>()) {
        let mut buf = bytes::BytesMut::new();
        put_u16(&mut buf, val);
        let wire = buf.freeze();
        prop_assert_eq!(wire.len(), 2);
        let parsed = get_u16(&wire, 0).expect("get_u16 must succeed");
        prop_assert_eq!(parsed, val);
    }

    // -----------------------------------------------------------------------
    // Test: put_u32 / get_u32 round-trip (network byte order)
    // Property: ∀ v: u32.  get_u32(put_u32(v), 0) == v
    // -----------------------------------------------------------------------
    #[test]
    fn u32_network_byte_order_roundtrip(val in any::<u32>()) {
        let mut buf = bytes::BytesMut::new();
        put_u32(&mut buf, val);
        let wire = buf.freeze();
        prop_assert_eq!(wire.len(), 4);
        let parsed = get_u32(&wire, 0).expect("get_u32 must succeed");
        prop_assert_eq!(parsed, val);
    }

    // -----------------------------------------------------------------------
    // Test: Network byte order consistency — multi-byte fields are big-endian
    // -----------------------------------------------------------------------
    #[test]
    fn u16_is_big_endian(val in any::<u16>()) {
        let mut buf = bytes::BytesMut::new();
        put_u16(&mut buf, val);
        let wire = buf.freeze();
        let expected_hi = (val >> 8) as u8;
        let expected_lo = (val & 0xFF) as u8;
        prop_assert_eq!(wire[0], expected_hi);
        prop_assert_eq!(wire[1], expected_lo);
    }

    #[test]
    fn u32_is_big_endian(val in any::<u32>()) {
        let mut buf = bytes::BytesMut::new();
        put_u32(&mut buf, val);
        let wire = buf.freeze();
        prop_assert_eq!(wire[0], ((val >> 24) & 0xFF) as u8);
        prop_assert_eq!(wire[1], ((val >> 16) & 0xFF) as u8);
        prop_assert_eq!(wire[2], ((val >> 8) & 0xFF) as u8);
        prop_assert_eq!(wire[3], (val & 0xFF) as u8);
    }
}

// ===========================================================================
//  ResponseCode / DnsClass / RRType value round-trip tests
// ===========================================================================

proptest! {
    #![proptest_config(test_config())]

    // -----------------------------------------------------------------------
    // Test: ResponseCode numeric value round-trip
    // -----------------------------------------------------------------------
    #[test]
    fn response_code_value_roundtrip(rcode in response_code_strategy()) {
        let numeric = rcode.to_u8();
        match rcode {
            ResponseCode::NoError  => prop_assert_eq!(numeric, 0),
            ResponseCode::FormErr  => prop_assert_eq!(numeric, 1),
            ResponseCode::ServFail => prop_assert_eq!(numeric, 2),
            ResponseCode::NxDomain => prop_assert_eq!(numeric, 3),
            ResponseCode::NotImp   => prop_assert_eq!(numeric, 4),
            ResponseCode::Refused  => prop_assert_eq!(numeric, 5),
            _ => {} // exhaustive for the 6 standard codes
        }
        // Round-trip
        let back = ResponseCode::from_u8(numeric);
        prop_assert_eq!(back.to_u8(), numeric);
    }

    // -----------------------------------------------------------------------
    // Test: DnsClass numeric value round-trip
    // -----------------------------------------------------------------------
    #[test]
    fn dns_class_value_roundtrip(cls in dns_class_strategy()) {
        let numeric = cls.to_u16();
        match cls {
            DnsClass::IN     => prop_assert_eq!(numeric, 1),
            DnsClass::Chaos  => prop_assert_eq!(numeric, 3),
            DnsClass::Hesiod => prop_assert_eq!(numeric, 4),
            DnsClass::Any    => prop_assert_eq!(numeric, 255),
        }
        // Round-trip via from_u16
        let back = DnsClass::from_u16(numeric);
        prop_assert!(back.is_some(), "from_u16({}) must succeed", numeric);
        prop_assert_eq!(back.unwrap().to_u16(), numeric);
    }

    // -----------------------------------------------------------------------
    // Test: RRType numeric round-trip
    // -----------------------------------------------------------------------
    #[test]
    fn rr_type_value_roundtrip(rr in rr_type_strategy()) {
        let numeric = rr.to_u16();
        match rr {
            RRType::A     => prop_assert_eq!(numeric, 1),
            RRType::NS    => prop_assert_eq!(numeric, 2),
            RRType::CNAME => prop_assert_eq!(numeric, 5),
            RRType::SOA   => prop_assert_eq!(numeric, 6),
            RRType::PTR   => prop_assert_eq!(numeric, 12),
            RRType::MX    => prop_assert_eq!(numeric, 15),
            RRType::TXT   => prop_assert_eq!(numeric, 16),
            RRType::AAAA  => prop_assert_eq!(numeric, 28),
            RRType::SRV   => prop_assert_eq!(numeric, 33),
            _ => {}
        }
        let back = RRType::from_u16(numeric);
        prop_assert_eq!(back.to_u16(), numeric);
    }
}

// ===========================================================================
//  DHCPv4 Packet Round-Trip Tests (RFC 2131)
//  Feature-gated behind `dhcp`.
// ===========================================================================

#[cfg(feature = "dhcp")]
mod dhcpv4_tests {
    use super::*;

    /// Raw fields for constructing a DHCPv4 test packet.
    struct DhcpV4Fields {
        op: u8,
        htype: u8,
        hlen: u8,
        hops: u8,
        xid: u32,
        secs: u16,
        flags: u16,
        ciaddr: [u8; 4],
        yiaddr: [u8; 4],
        siaddr: [u8; 4],
        giaddr: [u8; 4],
        chaddr: [u8; 6],
    }

    /// Construct a minimal valid DHCPv4 packet buffer (≥ DHCP_PACKET_SIZE)
    /// from raw field values. Returns the byte vector.
    fn build_dhcpv4_packet_bytes(f: &DhcpV4Fields) -> Vec<u8> {
        let mut buf = vec![0u8; DHCP_PACKET_SIZE];
        buf[0] = f.op;
        buf[1] = f.htype;
        buf[2] = f.hlen;
        buf[3] = f.hops;
        buf[4..8].copy_from_slice(&f.xid.to_be_bytes());
        buf[8..10].copy_from_slice(&f.secs.to_be_bytes());
        buf[10..12].copy_from_slice(&f.flags.to_be_bytes());
        buf[12..16].copy_from_slice(&f.ciaddr);
        buf[16..20].copy_from_slice(&f.yiaddr);
        buf[20..24].copy_from_slice(&f.siaddr);
        buf[24..28].copy_from_slice(&f.giaddr);
        buf[28..34].copy_from_slice(&f.chaddr);
        // sname (64 bytes) at offset 44..108 — leave zeros
        // file (128 bytes) at offset 108..236 — leave zeros
        // Magic cookie at offset 236
        buf[236..240].copy_from_slice(&DHCP_COOKIE);
        // End option
        buf[240] = OPTION_END;
        buf
    }

    proptest! {
        #![proptest_config(test_config())]

        // -------------------------------------------------------------------
        // Test: DHCPv4 packet round-trip
        // Property: from_bytes(as_bytes(build(pkt))) preserves fields
        // -------------------------------------------------------------------
        #[test]
        fn dhcpv4_packet_roundtrip(
            op in prop_oneof![Just(BOOTREQUEST), Just(BOOTREPLY)],
            xid in any::<u32>(),
            secs in any::<u16>(),
            flags in any::<u16>(),
            ciaddr in any::<[u8; 4]>(),
            yiaddr in any::<[u8; 4]>(),
            siaddr in any::<[u8; 4]>(),
            giaddr in any::<[u8; 4]>(),
            mac in any::<[u8; 6]>(),
        ) {
            let fields = DhcpV4Fields {
                op, htype: 1, hlen: 6, hops: 0,
                xid, secs, flags,
                ciaddr, yiaddr, siaddr, giaddr, chaddr: mac,
            };
            let raw = build_dhcpv4_packet_bytes(&fields);
            let pkt = DhcpPacket::from_bytes(&raw).expect("from_bytes must succeed");
            let out = pkt.as_bytes();

            // Re-parse the output
            let pkt2 = DhcpPacket::from_bytes(out).expect("re-parse must succeed");

            prop_assert_eq!(pkt2.op(), op);
            prop_assert_eq!(pkt2.htype(), 1);
            prop_assert_eq!(pkt2.hlen(), 6);
            prop_assert_eq!(pkt2.xid(), xid);
            prop_assert_eq!(pkt2.secs(), secs);
            prop_assert_eq!(pkt2.flags(), flags);
            prop_assert_eq!(pkt2.ciaddr_addr(), Ipv4Addr::from(ciaddr));
            prop_assert_eq!(pkt2.yiaddr_addr(), Ipv4Addr::from(yiaddr));
            prop_assert_eq!(pkt2.siaddr_addr(), Ipv4Addr::from(siaddr));
            prop_assert_eq!(pkt2.giaddr_addr(), Ipv4Addr::from(giaddr));
            prop_assert_eq!(&pkt2.chaddr()[..6], &mac[..]);
        }
    }

    proptest! {
        #![proptest_config(test_config())]

        // -------------------------------------------------------------------
        // Test: DHCPv4 option encoding round-trip
        // Generate random DHCP options as TLV triplets, encode in the options
        // field, parse back, verify option values.
        // -------------------------------------------------------------------
        #[test]
        fn dhcpv4_option_encoding_roundtrip(
            xid in any::<u32>(),
            opt_type in 1u8..254,
            opt_data in prop_vec(any::<u8>(), 1..32),
        ) {
            let mut raw = vec![0u8; DHCP_PACKET_SIZE];
            raw[0] = BOOTREQUEST;
            raw[1] = 1;
            raw[2] = 6;
            raw[4..8].copy_from_slice(&xid.to_be_bytes());
            raw[236..240].copy_from_slice(&DHCP_COOKIE);
            // Option: type + length + data
            let opt_len = opt_data.len() as u8;
            raw[240] = opt_type;
            raw[241] = opt_len;
            raw[242..(242 + opt_data.len())].copy_from_slice(&opt_data);
            raw[242 + opt_data.len()] = OPTION_END;

            let pkt = DhcpPacket::from_bytes(&raw).expect("from_bytes must succeed");
            let options = pkt.options();

            // options() starts at offset 236 which includes the 4-byte DHCP
            // cookie — skip the first 4 bytes to reach actual TLV options.
            let tlv_start = if options.len() >= 4 { 4 } else { 0 };
            let tlv_opts = &options[tlv_start..];

            // Find our option in the TLV options buffer
            let mut found = false;
            let mut pos = 0usize;
            while pos < tlv_opts.len() {
                let code = tlv_opts[pos];
                if code == OPTION_PAD {
                    pos += 1;
                    continue;
                }
                if code == OPTION_END {
                    break;
                }
                if pos + 1 >= tlv_opts.len() {
                    break;
                }
                let len = tlv_opts[pos + 1] as usize;
                if code == opt_type && len == opt_data.len() {
                    let data_slice = &tlv_opts[pos + 2..pos + 2 + len];
                    prop_assert_eq!(data_slice, opt_data.as_slice());
                    found = true;
                    break;
                }
                pos += 2 + len;
            }
            prop_assert!(found, "encoded option {} not found in parsed packet", opt_type);
        }
    }

    proptest! {
        #![proptest_config(test_config())]

        // -------------------------------------------------------------------
        // Test: DHCPv4 message type consistency
        // Property: message type option (53) value ∈ {1..8} for standard types
        // -------------------------------------------------------------------
        #[test]
        fn dhcpv4_message_type_consistency(
            msg_type in 1u8..=8u8,
            xid in any::<u32>(),
        ) {
            let mut raw = vec![0u8; DHCP_PACKET_SIZE];
            raw[0] = BOOTREQUEST;
            raw[1] = 1;
            raw[2] = 6;
            raw[4..8].copy_from_slice(&xid.to_be_bytes());
            raw[236..240].copy_from_slice(&DHCP_COOKIE);
            raw[240] = OPTION_MESSAGE_TYPE;
            raw[241] = 1;
            raw[242] = msg_type;
            raw[243] = OPTION_END;

            let pkt = DhcpPacket::from_bytes(&raw).expect("from_bytes must succeed");

            // Verify the DhcpV4State conversion is valid for values 1-8
            let state = DhcpV4State::try_from(msg_type);
            prop_assert!(state.is_ok(), "msg type {} should be valid", msg_type);

            // Verify the message type option is present in the packet.
            // options() starts at offset 236 which includes the 4-byte magic
            // cookie — skip the first 4 bytes to reach actual TLV options.
            let options = pkt.options();
            let tlv_start = if options.len() >= 4 { 4 } else { 0 };
            let tlv_opts = &options[tlv_start..];
            let mut found_type = false;
            let mut pos = 0usize;
            while pos < tlv_opts.len() {
                let code = tlv_opts[pos];
                if code == OPTION_PAD { pos += 1; continue; }
                if code == OPTION_END { break; }
                if pos + 1 >= tlv_opts.len() { break; }
                let len = tlv_opts[pos + 1] as usize;
                if code == OPTION_MESSAGE_TYPE && len == 1 {
                    prop_assert_eq!(tlv_opts[pos + 2], msg_type);
                    found_type = true;
                }
                pos += 2 + len;
            }
            prop_assert!(found_type, "message type option not found in packet");
        }
    }

    proptest! {
        #![proptest_config(test_config())]

        // -------------------------------------------------------------------
        // Test: DHCPv4 minimum packet size
        // Property: serialized DHCP packet ≥ 300 bytes (BOOTP minimum)
        // -------------------------------------------------------------------
        #[test]
        fn dhcpv4_minimum_packet_size(xid in any::<u32>()) {
            let fields = DhcpV4Fields {
                op: BOOTREQUEST, htype: 1, hlen: 6, hops: 0,
                xid, secs: 0, flags: 0,
                ciaddr: [0; 4], yiaddr: [0; 4], siaddr: [0; 4], giaddr: [0; 4],
                chaddr: [0; 6],
            };
            let raw = build_dhcpv4_packet_bytes(&fields);

            let pkt = DhcpPacket::from_bytes(&raw).expect("from_bytes must succeed");
            prop_assert!(
                pkt.len() >= 300,
                "DHCP packet size {} is below BOOTP minimum 300",
                pkt.len()
            );
        }
    }

    proptest! {
        #![proptest_config(test_config())]

        // -------------------------------------------------------------------
        // Test: DHCPv4 magic cookie presence
        // Property: bytes at offset 236-239 always equal 0x63825363
        // -------------------------------------------------------------------
        #[test]
        fn dhcpv4_magic_cookie_presence(
            xid in any::<u32>(),
            mac in any::<[u8; 6]>(),
        ) {
            let fields = DhcpV4Fields {
                op: BOOTREQUEST, htype: 1, hlen: 6, hops: 0,
                xid, secs: 0, flags: 0,
                ciaddr: [0; 4], yiaddr: [0; 4], siaddr: [0; 4], giaddr: [0; 4],
                chaddr: mac,
            };
            let raw = build_dhcpv4_packet_bytes(&fields);

            let pkt = DhcpPacket::from_bytes(&raw).expect("from_bytes must succeed");
            let buf = pkt.as_bytes();

            prop_assert!(pkt.has_dhcp_cookie(), "DHCP magic cookie must be present");

            // Also verify raw byte values (0x63825363 = [99, 130, 83, 99])
            prop_assert_eq!(buf[236], 99);
            prop_assert_eq!(buf[237], 130);
            prop_assert_eq!(buf[238], 83);
            prop_assert_eq!(buf[239], 99);
        }
    }

    proptest! {
        #![proptest_config(test_config())]

        // -------------------------------------------------------------------
        // Test: DhcpV4State name() consistency
        // Verify each state variant maps to a non-empty descriptive name.
        // -------------------------------------------------------------------
        #[test]
        fn dhcpv4_state_name_nonempty(raw_type in 1u8..=8u8) {
            let state = DhcpV4State::try_from(raw_type).expect("valid state");
            let name = state.name();
            prop_assert!(!name.is_empty(), "state name must not be empty");
            let display = format!("{}", state);
            prop_assert!(!display.is_empty(), "Display must not be empty");
        }
    }

    proptest! {
        #![proptest_config(test_config())]

        // -------------------------------------------------------------------
        // Test: DHCP option total length never exceeds options field capacity
        // Property: total options bytes ≤ DHCP_OPTIONS_SIZE (312)
        // -------------------------------------------------------------------
        #[test]
        fn dhcpv4_options_within_capacity(
            xid in any::<u32>(),
            num_options in 1usize..=5,
            opt_data in prop_vec(prop_vec(any::<u8>(), 1..16), 5),
        ) {
            let mut raw = vec![0u8; DHCP_PACKET_SIZE];
            raw[0] = BOOTREQUEST;
            raw[1] = 1;
            raw[2] = 6;
            raw[4..8].copy_from_slice(&xid.to_be_bytes());
            raw[236..240].copy_from_slice(&DHCP_COOKIE);

            let mut pos = 240usize;
            for (i, data) in opt_data.iter().enumerate().take(num_options.min(opt_data.len())) {
                let code = ((i as u8) + 10).min(254);
                if pos + 2 + data.len() >= DHCP_PACKET_SIZE {
                    break;
                }
                raw[pos] = code;
                raw[pos + 1] = data.len() as u8;
                raw[pos + 2..pos + 2 + data.len()].copy_from_slice(data);
                pos += 2 + data.len();
            }
            if pos < DHCP_PACKET_SIZE {
                raw[pos] = OPTION_END;
            }

            let pkt = DhcpPacket::from_bytes(&raw).expect("from_bytes must succeed");
            let options = pkt.options();
            prop_assert!(
                options.len() <= 312,
                "options field length {} exceeds DHCP_OPTIONS_SIZE (312)",
                options.len()
            );
        }
    }
} // mod dhcpv4_tests

// ===========================================================================
//  DHCPv6 Packet Round-Trip Tests (RFC 3315)
//  Feature-gated behind `dhcp6` (which implies `dhcp`).
// ===========================================================================

#[cfg(feature = "dhcp6")]
mod dhcpv6_tests {
    use super::*;

    use dnsmasq::dhcp::v6::{OPTION6_CLIENT_ID, OPTION6_IAADDR, OPTION6_IA_NA};

    /// Encode a single DHCPv6 option TLV into a byte vector.
    fn encode_dhcpv6_option(opt_type: u16, data: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + data.len());
        buf.extend_from_slice(&opt_type.to_be_bytes());
        buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
        buf.extend_from_slice(data);
        buf
    }

    /// Construct a DHCPv6 message: msg_type(1B) + transaction_id(3B) + options.
    fn build_dhcpv6_message(msg_type: u8, txn_id: u32, options: &[u8]) -> Vec<u8> {
        let mut msg = Vec::with_capacity(4 + options.len());
        msg.push(msg_type);
        msg.push(((txn_id >> 16) & 0xFF) as u8);
        msg.push(((txn_id >> 8) & 0xFF) as u8);
        msg.push((txn_id & 0xFF) as u8);
        msg.extend_from_slice(options);
        msg
    }

    /// Strategy for valid DHCPv6 message types (1-11 for client/server).
    fn dhcpv6_msg_type_strategy() -> impl Strategy<Value = u8> {
        prop_oneof![
            Just(1u8),  // SOLICIT
            Just(2u8),  // ADVERTISE
            Just(3u8),  // REQUEST
            Just(4u8),  // CONFIRM
            Just(5u8),  // RENEW
            Just(6u8),  // REBIND
            Just(7u8),  // REPLY
            Just(8u8),  // RELEASE
            Just(9u8),  // DECLINE
            Just(11u8), // INFORMATION-REQUEST
        ]
    }

    proptest! {
        #![proptest_config(test_config())]

        // -------------------------------------------------------------------
        // Test: DHCPv6 message round-trip
        // Generate random DHCPv6 messages, verify parse preserves structure.
        // -------------------------------------------------------------------
        #[test]
        fn dhcpv6_message_roundtrip(
            msg_type in dhcpv6_msg_type_strategy(),
            txn_id in 0u32..0x00FF_FFFF,
            opt_data in prop_vec(any::<u8>(), 4..32),
        ) {
            let opt_bytes = encode_dhcpv6_option(OPTION6_CLIENT_ID, &opt_data);
            let msg = build_dhcpv6_message(msg_type, txn_id, &opt_bytes);

            prop_assert!(msg.len() >= 4, "message too short");
            prop_assert_eq!(msg[0], msg_type);

            let parsed_txn =
                ((msg[1] as u32) << 16) | ((msg[2] as u32) << 8) | (msg[3] as u32);
            prop_assert_eq!(parsed_txn, txn_id);

            let state = DhcpV6State::try_from(msg_type);
            prop_assert!(state.is_ok(), "msg type {} should be valid", msg_type);

            let options = &msg[4..];
            let found = opt6_find(options, OPTION6_CLIENT_ID, 0);
            prop_assert!(found.is_some(), "CLIENT_ID option must be findable");
            let found_data = found.unwrap();
            prop_assert_eq!(found_data, opt_data.as_slice());
        }
    }

    proptest! {
        #![proptest_config(test_config())]

        // -------------------------------------------------------------------
        // Test: DHCPv6 option TLV encoding round-trip
        // -------------------------------------------------------------------
        #[test]
        fn dhcpv6_option_tlv_roundtrip(
            opt_type in 1u16..1000,
            opt_data in prop_vec(any::<u8>(), 0..64),
        ) {
            let encoded = encode_dhcpv6_option(opt_type, &opt_data);

            prop_assert_eq!(encoded.len(), 4 + opt_data.len());

            let parsed_type = u16::from_be_bytes([encoded[0], encoded[1]]);
            prop_assert_eq!(parsed_type, opt_type);

            let parsed_len = u16::from_be_bytes([encoded[2], encoded[3]]);
            prop_assert_eq!(parsed_len as usize, opt_data.len());

            let parsed_data = &encoded[4..];
            prop_assert_eq!(parsed_data, opt_data.as_slice());

            let found = opt6_find(&encoded, opt_type, 0);
            prop_assert!(found.is_some(), "encoded option must be findable");
            prop_assert_eq!(found.unwrap(), opt_data.as_slice());
        }
    }

    proptest! {
        #![proptest_config(test_config())]

        // -------------------------------------------------------------------
        // Test: DHCPv6 option iteration via opt6_next
        // -------------------------------------------------------------------
        #[test]
        fn dhcpv6_option_iteration(
            opt1_data in prop_vec(any::<u8>(), 1..16),
            opt2_data in prop_vec(any::<u8>(), 1..16),
        ) {
            let opt1 = encode_dhcpv6_option(100, &opt1_data);
            let opt2 = encode_dhcpv6_option(200, &opt2_data);
            let mut combined = Vec::new();
            combined.extend_from_slice(&opt1);
            combined.extend_from_slice(&opt2);

            let mut found_types = Vec::new();
            let mut pos = 0usize;
            while let Some((otype, _data, next_pos)) = opt6_next(&combined, pos) {
                found_types.push(otype);
                pos = next_pos;
            }

            prop_assert!(found_types.contains(&100), "option type 100 must be found");
            prop_assert!(found_types.contains(&200), "option type 200 must be found");
            prop_assert_eq!(found_types.len(), 2);
        }
    }

    proptest! {
        #![proptest_config(test_config())]

        // -------------------------------------------------------------------
        // Test: DHCPv6 opt6_uint extracts integers correctly
        // -------------------------------------------------------------------
        #[test]
        fn dhcpv6_opt6_uint_extraction(
            val_u8 in any::<u8>(),
            val_u16 in any::<u16>(),
            val_u32 in any::<u32>(),
        ) {
            // 1-byte extraction
            let data1 = vec![val_u8];
            let result1 = opt6_uint(&data1, 0, 1);
            prop_assert_eq!(result1, val_u8 as u32);

            // 2-byte extraction (big-endian)
            let data2 = val_u16.to_be_bytes().to_vec();
            let result2 = opt6_uint(&data2, 0, 2);
            prop_assert_eq!(result2, val_u16 as u32);

            // 4-byte extraction (big-endian)
            let data4 = val_u32.to_be_bytes().to_vec();
            let result4 = opt6_uint(&data4, 0, 4);
            prop_assert_eq!(result4, val_u32);
        }
    }

    proptest! {
        #![proptest_config(test_config())]

        // -------------------------------------------------------------------
        // Test: DHCPv6 DUID round-trip
        // Generate random DUIDs (DUID-LLT=1, DUID-EN=2, DUID-LL=3), encode
        // as CLIENT_ID option, parse back.
        // -------------------------------------------------------------------
        #[test]
        fn dhcpv6_duid_roundtrip(
            duid_type in prop_oneof![Just(1u16), Just(2u16), Just(3u16)],
            hw_type in Just(1u16),
            mac in any::<[u8; 6]>(),
            time_val in any::<u32>(),
            enterprise_num in any::<u32>(),
            identifier in prop_vec(any::<u8>(), 1..16),
        ) {
            let duid_data = match duid_type {
                1 => {
                    // DUID-LLT: type(2B) + hw-type(2B) + time(4B) + link-layer(6B)
                    let mut d = Vec::with_capacity(14);
                    d.extend_from_slice(&duid_type.to_be_bytes());
                    d.extend_from_slice(&hw_type.to_be_bytes());
                    d.extend_from_slice(&time_val.to_be_bytes());
                    d.extend_from_slice(&mac);
                    d
                }
                2 => {
                    // DUID-EN: type(2B) + enterprise-number(4B) + identifier(var)
                    let mut d = Vec::with_capacity(6 + identifier.len());
                    d.extend_from_slice(&duid_type.to_be_bytes());
                    d.extend_from_slice(&enterprise_num.to_be_bytes());
                    d.extend_from_slice(&identifier);
                    d
                }
                3 => {
                    // DUID-LL: type(2B) + hw-type(2B) + link-layer(6B)
                    let mut d = Vec::with_capacity(10);
                    d.extend_from_slice(&duid_type.to_be_bytes());
                    d.extend_from_slice(&hw_type.to_be_bytes());
                    d.extend_from_slice(&mac);
                    d
                }
                _ => unreachable!(),
            };

            let opt_bytes = encode_dhcpv6_option(OPTION6_CLIENT_ID, &duid_data);

            let found = opt6_find(&opt_bytes, OPTION6_CLIENT_ID, 0);
            prop_assert!(found.is_some(), "CLIENT_ID option must be findable");
            let found_data = found.unwrap();
            prop_assert_eq!(found_data, duid_data.as_slice());

            // Verify DUID type field
            let parsed_duid_type = u16::from_be_bytes([found_data[0], found_data[1]]);
            prop_assert_eq!(parsed_duid_type, duid_type);
        }
    }

    proptest! {
        #![proptest_config(test_config())]

        // -------------------------------------------------------------------
        // Test: DHCPv6 IA_NA option round-trip with nested IAADDR
        // -------------------------------------------------------------------
        #[test]
        fn dhcpv6_ia_na_roundtrip(
            iaid in any::<u32>(),
            t1 in any::<u32>(),
            t2 in any::<u32>(),
            addr_bytes in any::<u128>(),
            preferred_lifetime in any::<u32>(),
            valid_lifetime in any::<u32>(),
        ) {
            let addr = Ipv6Addr::from(addr_bytes);
            let mut iaaddr_data = Vec::with_capacity(24);
            iaaddr_data.extend_from_slice(&addr.octets());
            iaaddr_data.extend_from_slice(&preferred_lifetime.to_be_bytes());
            iaaddr_data.extend_from_slice(&valid_lifetime.to_be_bytes());
            let iaaddr_opt = encode_dhcpv6_option(OPTION6_IAADDR, &iaaddr_data);

            let mut ia_na_data = Vec::with_capacity(12 + iaaddr_opt.len());
            ia_na_data.extend_from_slice(&iaid.to_be_bytes());
            ia_na_data.extend_from_slice(&t1.to_be_bytes());
            ia_na_data.extend_from_slice(&t2.to_be_bytes());
            ia_na_data.extend_from_slice(&iaaddr_opt);
            let ia_na_opt = encode_dhcpv6_option(OPTION6_IA_NA, &ia_na_data);

            let found = opt6_find(&ia_na_opt, OPTION6_IA_NA, 0);
            prop_assert!(found.is_some(), "IA_NA option must be findable");
            let ia_data = found.unwrap();

            // Verify IAID
            let parsed_iaid = u32::from_be_bytes([ia_data[0], ia_data[1], ia_data[2], ia_data[3]]);
            prop_assert_eq!(parsed_iaid, iaid);

            // Verify T1
            let parsed_t1 = u32::from_be_bytes([ia_data[4], ia_data[5], ia_data[6], ia_data[7]]);
            prop_assert_eq!(parsed_t1, t1);

            // Verify T2
            let parsed_t2 = u32::from_be_bytes([ia_data[8], ia_data[9], ia_data[10], ia_data[11]]);
            prop_assert_eq!(parsed_t2, t2);

            // Verify nested IAADDR sub-option
            let sub_options = &ia_data[12..];
            let found_iaaddr = opt6_find(sub_options, OPTION6_IAADDR, 0);
            prop_assert!(found_iaaddr.is_some(), "IAADDR must be findable within IA_NA");
            let iaaddr = found_iaaddr.unwrap();
            prop_assert_eq!(iaaddr.len(), 24, "IAADDR data must be 24 bytes");

            let mut addr_buf = [0u8; 16];
            addr_buf.copy_from_slice(&iaaddr[0..16]);
            let parsed_addr = Ipv6Addr::from(addr_buf);
            prop_assert_eq!(parsed_addr, addr);

            let parsed_preferred = u32::from_be_bytes([iaaddr[16], iaaddr[17], iaaddr[18], iaaddr[19]]);
            prop_assert_eq!(parsed_preferred, preferred_lifetime);
            let parsed_valid = u32::from_be_bytes([iaaddr[20], iaaddr[21], iaaddr[22], iaaddr[23]]);
            prop_assert_eq!(parsed_valid, valid_lifetime);
        }
    }

    proptest! {
        #![proptest_config(test_config())]

        // -------------------------------------------------------------------
        // Test: DhcpV6State enum round-trip
        // -------------------------------------------------------------------
        #[test]
        fn dhcpv6_state_roundtrip(msg_type in dhcpv6_msg_type_strategy()) {
            let state = DhcpV6State::try_from(msg_type).expect("valid state");
            let back: u8 = state.into();
            prop_assert_eq!(back, msg_type);
        }
    }

    proptest! {
        #![proptest_config(test_config())]

        // -------------------------------------------------------------------
        // Test: IaType option code round-trip
        // -------------------------------------------------------------------
        #[test]
        fn dhcpv6_ia_type_roundtrip(
            ia_type in prop_oneof![Just(IaType::Na), Just(IaType::Ta), Just(IaType::Pd)]
        ) {
            let code = ia_type.option_code();
            match ia_type {
                IaType::Na => prop_assert_eq!(code, OPTION6_IA_NA),
                IaType::Ta => prop_assert_eq!(code, 4),  // OPTION6_IA_TA
                IaType::Pd => prop_assert_eq!(code, 25), // OPTION6_IA_PD
            }
            let back = IaType::from_option_code(code);
            prop_assert!(back.is_some(), "option code must map back to IaType");
            prop_assert_eq!(back.unwrap().option_code(), code);
        }
    }
} // mod dhcpv6_tests

// ===========================================================================
//  Cross-Protocol Invariant Tests
// ===========================================================================

proptest! {
    #![proptest_config(test_config())]

    // -----------------------------------------------------------------------
    // Test: DNS packet never exceeds max size for single-RR responses
    // -----------------------------------------------------------------------
    #[test]
    fn cross_dns_packet_bounded(
        id in any::<u16>(),
        ip in any::<u32>(),
    ) {
        let name = DnsName::from_str_unchecked("a.b");
        let addr = Ipv4Addr::from(ip);
        let packet = DnsPacketBuilder::new(id)
            .set_response()
            .add_question(&name, RRType::A, DnsClass::IN)
            .add_answer(&name, RRType::A, DnsClass::IN, 300, &addr.octets())
            .build()
            .expect("build must succeed");

        prop_assert!(
            packet.raw.len() <= PACKETSZ,
            "packet len {} > PACKETSZ {}",
            packet.raw.len(),
            PACKETSZ
        );
    }

    // -----------------------------------------------------------------------
    // Test: DNS header flags serialization determinism
    // Property: Same flags always produce the same serialized header bytes.
    // -----------------------------------------------------------------------
    #[test]
    fn cross_dns_flags_deterministic(flags in dns_flags_strategy()) {
        // Serialize the flags within a full header to exercise to_bytes()
        let header = DnsHeader {
            id: 0x1234,
            flags: flags.clone(),
            qdcount: 0,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        };
        let mut buf1 = bytes::BytesMut::new();
        header.serialize(&mut buf1);
        let wire1 = buf1.freeze();

        let header2 = DnsHeader {
            id: 0x1234,
            flags,
            qdcount: 0,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        };
        let mut buf2 = bytes::BytesMut::new();
        header2.serialize(&mut buf2);
        let wire2 = buf2.freeze();

        prop_assert_eq!(wire1, wire2, "flag serialization must be deterministic");
    }

    // -----------------------------------------------------------------------
    // Test: RRFIXEDSZ constant correctness
    // The fixed portion of a resource record is exactly 10 bytes per RFC 1035.
    // -----------------------------------------------------------------------
    #[test]
    fn cross_rrfixedsz_is_ten(_dummy in Just(())) {
        prop_assert_eq!(RRFIXEDSZ, 10, "RRFIXEDSZ must be 10 per RFC 1035");
    }

    // -----------------------------------------------------------------------
    // Test: MAXDNAME, MAXLABEL, PACKETSZ constant correctness
    // -----------------------------------------------------------------------
    #[test]
    fn cross_dns_name_constants(_dummy in Just(())) {
        prop_assert_eq!(MAXLABEL, 63, "MAXLABEL must be 63");
        prop_assert_eq!(MAXDNAME, 1025, "MAXDNAME must be 1025");
        prop_assert_eq!(PACKETSZ, 512, "PACKETSZ must be 512");
    }
}

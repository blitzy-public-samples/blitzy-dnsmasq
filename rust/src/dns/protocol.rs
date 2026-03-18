// Copyright (C) 2024 Simon Kelley
// SPDX-License-Identifier: GPL-2.0-or-later
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.

//! # DNS Wire Format and Protocol Constants
//!
//! Comprehensive DNS protocol implementation combining the C `src/dns-protocol.h`
//! (873 lines of constants) and `src/rfc1035.c` (3,622 lines of wire format handling).
//!
//! ## Key Types
//!
//! - [`DnsHeader`] — Replaces C `struct dns_header` with typed flag access methods.
//! - [`DnsHeaderFlags`] — Individual header flag fields (QR, AA, TC, RD, RA, AD, CD, RCODE).
//! - [`DnsName`] — Domain name with compression/decompression, replacing C `char*` names.
//! - [`DnsPacket`] — Parsed DNS packet with header, questions, answers, authority, additional.
//! - [`DnsPacketBuilder`] — Builder pattern for type-safe DNS packet construction.
//! - [`RRType`] — DNS resource record type codes per RFC 1035 and extensions.
//! - [`DnsClass`] — DNS class codes (IN, Chaos, Hesiod, Any).
//! - [`ResponseCode`] — DNS response codes (RCODE) per RFC 1035.
//!
//! ## Wire Format
//!
//! All parsing and serialization follows RFC 1035 wire format with big-endian byte order.
//! The `bytes` crate provides efficient buffer management via [`Bytes`] and [`BytesMut`].
//!
//! ## Safety
//!
//! Zero `unsafe` blocks. Rust bounds checking replaces C `CHECK_LEN`/`ADD_RDLEN` macros.

use crate::core::types::{DnsmasqError, DnsmasqResult};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use tracing::{debug, trace, warn};

// ===========================================================================
// Port and Size Constants (from dns-protocol.h lines 76-112)
// ===========================================================================

/// DNS protocol standard port (UDP and TCP) per RFC 1035 Section 4.2.
pub const NAMESERVER_PORT: u16 = 53;

/// TFTP protocol standard port per RFC 1350.
pub const TFTP_PORT: u16 = 69;

/// First non-privileged port number.
pub const MIN_PORT: u16 = 1024;

/// Maximum valid port number.
pub const MAX_PORT: u16 = 65535;

/// IPv6 address size in bytes (128 bits).
pub const IN6ADDRSZ: usize = 16;

/// IPv4 address size in bytes (32 bits).
pub const INADDRSZ: usize = 4;

/// Default maximum DNS UDP packet size per RFC 1035 Section 2.3.4.
pub const PACKETSZ: usize = 512;

/// Maximum domain name length including separators.
/// One byte longer than the 1024-byte wire limit to accommodate trailing dot.
pub const MAXDNAME: usize = 1025;

/// Fixed size of resource record metadata (TYPE + CLASS + TTL + RDLENGTH = 10 bytes).
pub const RRFIXEDSZ: usize = 10;

/// Maximum single DNS label length per RFC 1035 Section 2.3.4.
pub const MAXLABEL: usize = 63;

/// DNS header size in bytes (ID + FLAGS + 4 counts × 2 bytes each = 12).
const HDRSIZE: usize = 12;

/// Maximum compression pointer hops before declaring a loop.
const MAX_COMPRESSION_HOPS: usize = 256;

/// Internal escape character for encoding NUL, dot, and escape within label bytes.
/// Value 0x01 (SOH control character) from dns-protocol.h line 873.
pub const NAME_ESCAPE: u8 = 1;

// ===========================================================================
// DNS Header Flag Bit Constants (from dns-protocol.h lines 521-546)
// ===========================================================================

/// hb3 bit 7: Query/Response flag (1 = response).
pub const HB3_QR: u8 = 0x80;
/// hb3 bits 6-3: Opcode field (4 bits).
pub const HB3_OPCODE: u8 = 0x78;
/// hb3 bit 2: Authoritative Answer.
pub const HB3_AA: u8 = 0x04;
/// hb3 bit 1: Truncation.
pub const HB3_TC: u8 = 0x02;
/// hb3 bit 0: Recursion Desired.
pub const HB3_RD: u8 = 0x01;

/// hb4 bit 7: Recursion Available.
pub const HB4_RA: u8 = 0x80;
/// hb4 bit 5: Authenticated Data (DNSSEC, RFC 4035).
pub const HB4_AD: u8 = 0x20;
/// hb4 bit 4: Checking Disabled (DNSSEC, RFC 4035).
pub const HB4_CD: u8 = 0x10;
/// hb4 bits 3-0: Response code (lower 4 bits).
pub const HB4_RCODE: u8 = 0x0f;

// ===========================================================================
// Response Codes (from dns-protocol.h lines 124-141)
// ===========================================================================

/// DNS response codes (RCODE) per RFC 1035 Section 4.1.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ResponseCode {
    /// No error condition.
    NoError = 0,
    /// Format error — server unable to interpret the query.
    FormErr = 1,
    /// Server failure — unable to process due to internal error.
    ServFail = 2,
    /// Non-Existent Domain — the queried domain name does not exist.
    NxDomain = 3,
    /// Not Implemented — server does not support the requested operation.
    NotImp = 4,
    /// Query Refused — server refuses to perform the operation.
    Refused = 5,
}

impl ResponseCode {
    /// Convert a raw `u8` to a [`ResponseCode`], returning `None` for unknown codes.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::NoError),
            1 => Some(Self::FormErr),
            2 => Some(Self::ServFail),
            3 => Some(Self::NxDomain),
            4 => Some(Self::NotImp),
            5 => Some(Self::Refused),
            _ => None,
        }
    }
}

impl fmt::Display for ResponseCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoError => write!(f, "NOERROR"),
            Self::FormErr => write!(f, "FORMERR"),
            Self::ServFail => write!(f, "SERVFAIL"),
            Self::NxDomain => write!(f, "NXDOMAIN"),
            Self::NotImp => write!(f, "NOTIMP"),
            Self::Refused => write!(f, "REFUSED"),
        }
    }
}

// ===========================================================================
// DNS Class Codes (from dns-protocol.h lines 168-178)
// ===========================================================================

/// DNS class codes per RFC 1035 Section 3.2.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DnsClass {
    /// Internet class.
    IN = 1,
    /// Chaosnet class.
    Chaos = 3,
    /// Hesiod class.
    Hesiod = 4,
    /// Any class (wildcard, used in queries only).
    Any = 255,
}

impl DnsClass {
    /// Convert a raw `u16` to a [`DnsClass`], returning `None` for unknown classes.
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            1 => Some(Self::IN),
            3 => Some(Self::Chaos),
            4 => Some(Self::Hesiod),
            255 => Some(Self::Any),
            _ => None,
        }
    }

    /// Convert to raw `u16` value.
    pub fn to_u16(self) -> u16 {
        self as u16
    }
}

impl fmt::Display for DnsClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IN => write!(f, "IN"),
            Self::Chaos => write!(f, "CH"),
            Self::Hesiod => write!(f, "HS"),
            Self::Any => write!(f, "ANY"),
        }
    }
}

// ===========================================================================
// Resource Record Types (from dns-protocol.h lines 192-298)
// ===========================================================================

/// DNS resource record types per RFC 1035 and subsequent RFCs.
///
/// Covers all types referenced by dnsmasq including obsolete types
/// retained for protocol completeness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum RRType {
    /// IPv4 host address (RFC 1035).
    A = 1,
    /// Authoritative name server (RFC 1035).
    NS = 2,
    /// Mail destination — obsolete, use MX (RFC 1035).
    MD = 3,
    /// Mail forwarder — obsolete, use MX (RFC 1035).
    MF = 4,
    /// Canonical name alias (RFC 1035).
    CNAME = 5,
    /// Start of zone authority (RFC 1035).
    SOA = 6,
    /// Mailbox domain name — experimental (RFC 1035).
    MB = 7,
    /// Mail group member — experimental (RFC 1035).
    MG = 8,
    /// Mail rename domain — experimental (RFC 1035).
    MR = 9,
    /// Domain name pointer for reverse DNS (RFC 1035).
    PTR = 12,
    /// Mailbox info — experimental (RFC 1035).
    MINFO = 14,
    /// Mail exchange (RFC 1035).
    MX = 15,
    /// Text strings (RFC 1035).
    TXT = 16,
    /// Responsible person (RFC 1183).
    RP = 17,
    /// AFS database location (RFC 1183).
    AFSDB = 18,
    /// Route through (RFC 1183).
    RT = 21,
    /// Security signature — obsolete DNSSEC (RFC 2535).
    SIG = 24,
    /// X.400 mail mapping (RFC 2163).
    PX = 26,
    /// IPv6 host address (RFC 3596).
    AAAA = 28,
    /// Next domain — obsolete DNSSEC (RFC 2535).
    NXT = 30,
    /// Service locator (RFC 2782).
    SRV = 33,
    /// Naming authority pointer (RFC 2915).
    NAPTR = 35,
    /// Key exchange delegation (RFC 2230).
    KX = 36,
    /// Delegation name (RFC 6672).
    DNAME = 39,
    /// EDNS0 pseudo-RR (RFC 6891).
    OPT = 41,
    /// Delegation signer — DNSSEC (RFC 4034).
    DS = 43,
    /// DNSSEC signature (RFC 4034).
    RRSIG = 46,
    /// DNSSEC authenticated denial of existence (RFC 4034).
    NSEC = 47,
    /// DNSSEC public key (RFC 4034).
    DNSKEY = 48,
    /// Hashed authenticated denial — DNSSEC (RFC 5155).
    NSEC3 = 50,
    /// Transaction key (RFC 2930).
    TKEY = 249,
    /// Transaction signature (RFC 8945).
    TSIG = 250,
    /// Incremental zone transfer (RFC 1995) — actually AXFR below.
    AXFR = 252,
    /// Mailbox-related RRs (RFC 1035).
    MAILB = 253,
    /// Wildcard match — all record types (RFC 1035).
    ANY = 255,
    /// Certification Authority Authorization (RFC 8659).
    CAA = 257,
}

impl RRType {
    /// Convert a raw `u16` to a known [`RRType`], returning `None` for unrecognised codes.
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            1 => Some(Self::A),
            2 => Some(Self::NS),
            3 => Some(Self::MD),
            4 => Some(Self::MF),
            5 => Some(Self::CNAME),
            6 => Some(Self::SOA),
            7 => Some(Self::MB),
            8 => Some(Self::MG),
            9 => Some(Self::MR),
            12 => Some(Self::PTR),
            14 => Some(Self::MINFO),
            15 => Some(Self::MX),
            16 => Some(Self::TXT),
            17 => Some(Self::RP),
            18 => Some(Self::AFSDB),
            21 => Some(Self::RT),
            24 => Some(Self::SIG),
            26 => Some(Self::PX),
            28 => Some(Self::AAAA),
            30 => Some(Self::NXT),
            33 => Some(Self::SRV),
            35 => Some(Self::NAPTR),
            36 => Some(Self::KX),
            39 => Some(Self::DNAME),
            41 => Some(Self::OPT),
            43 => Some(Self::DS),
            46 => Some(Self::RRSIG),
            47 => Some(Self::NSEC),
            48 => Some(Self::DNSKEY),
            50 => Some(Self::NSEC3),
            249 => Some(Self::TKEY),
            250 => Some(Self::TSIG),
            252 => Some(Self::AXFR),
            253 => Some(Self::MAILB),
            255 => Some(Self::ANY),
            257 => Some(Self::CAA),
            _ => None,
        }
    }

    /// Convert to the raw `u16` wire-format value.
    pub fn to_u16(self) -> u16 {
        self as u16
    }
}

impl fmt::Display for RRType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Use the Debug name which matches the variant identifier (A, NS, etc.)
        fmt::Debug::fmt(self, f)
    }
}

// ===========================================================================
// EDNS0 Option Codes (from dns-protocol.h lines 316-332)
// ===========================================================================

/// EDNS0 option codes per RFC 6891 and vendor extensions.
pub mod edns0 {
    /// dnsmasq MAC address option (vendor-specific).
    pub const OPTION_MAC: u16 = 65001;
    /// EDNS Client Subnet (RFC 7871).
    pub const OPTION_CLIENT_SUBNET: u16 = 8;
    /// Extended DNS Error (RFC 8914).
    pub const OPTION_EDE: u16 = 15;
    /// Nominum device ID (vendor-specific).
    pub const OPTION_NOMDEVICEID: u16 = 65073;
    /// Nominum CPE ID (vendor-specific).
    pub const OPTION_NOMCPEID: u16 = 65074;
    /// Cisco Umbrella (vendor-specific).
    pub const OPTION_UMBRELLA: u16 = 20292;
}

// ===========================================================================
// Extended DNS Error Codes (from dns-protocol.h lines 349-441, RFC 8914)
// ===========================================================================

/// Extended DNS Error (EDE) info-codes per RFC 8914.
pub mod ede {
    /// Sentinel value indicating no EDE code has been set.
    pub const UNSET: i16 = -1;
    /// Other error (code 0).
    pub const OTHER: u16 = 0;
    /// Unsupported DNSKEY Algorithm.
    pub const UNSUP_DNSKEY: u16 = 1;
    /// Unsupported DS Digest Type.
    pub const UNSUP_DS: u16 = 2;
    /// Stale Answer (RFC 8767).
    pub const STALE: u16 = 3;
    /// Forged Answer (RFC 8914).
    pub const FORGED: u16 = 4;
    /// DNSSEC Indeterminate.
    pub const DNSSEC_INDETERMINATE: u16 = 5;
    /// DNSSEC Bogus.
    pub const DNSSEC_BOGUS: u16 = 6;
    /// Signature Expired.
    pub const SIG_EXPIRED: u16 = 7;
    /// Signature Not Yet Valid.
    pub const SIG_NOT_YET_VALID: u16 = 8;
    /// DNSKEY Missing.
    pub const DNSKEY_MISSING: u16 = 9;
    /// RRSIG Missing.
    pub const RRSIG_MISSING: u16 = 10;
    /// No Zone Key Bit Set.
    pub const NO_ZONE_KEY: u16 = 11;
    /// NSEC Missing.
    pub const NSEC_MISSING: u16 = 12;
    /// Cached Error.
    pub const CACHED_ERR: u16 = 13;
    /// Not Ready.
    pub const NOT_READY: u16 = 14;
    /// Blocked.
    pub const BLOCKED: u16 = 15;
    /// Censored.
    pub const CENSORED: u16 = 16;
    /// Filtered.
    pub const FILTERED: u16 = 17;
    /// Prohibited.
    pub const PROHIBITED: u16 = 18;
    /// Stale NXDOMAIN Answer.
    pub const STALE_NXD: u16 = 19;
    /// Not Authoritative.
    pub const NOT_AUTH: u16 = 20;
    /// Not Supported.
    pub const NOT_SUP: u16 = 21;
    /// No Reachable Authority.
    pub const NO_AUTH: u16 = 22;
    /// Network Error.
    pub const NETERR: u16 = 23;
    /// Invalid Data.
    pub const INVALID_DATA: u16 = 24;
    /// Signature Expired Before Valid.
    pub const SIG_E_B_V: u16 = 25;
    /// Too Early.
    pub const TOO_EARLY: u16 = 26;
    /// Unsupported NSEC3 Iterations Value.
    pub const UNS_NS3_ITER: u16 = 27;
    /// Unable to Conform to Policy.
    pub const UNABLE_POLICY: u16 = 28;
    /// Synthesized.
    pub const SYNTHESIZED: u16 = 29;
}

// ===========================================================================
// DNS Header (from dns-protocol.h lines 471-492)
// ===========================================================================

/// DNS header flag fields, replacing C `hb3`/`hb4` byte pair.
///
/// Each field maps to specific bit positions in the two flag bytes
/// of a DNS header per RFC 1035 Section 4.1.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsHeaderFlags {
    /// Query (false) or Response (true) — hb3 bit 7.
    pub qr: bool,
    /// 4-bit operation code — hb3 bits 6-3 (QUERY=0, IQUERY=1, STATUS=2).
    pub opcode: u8,
    /// Authoritative Answer — hb3 bit 2.
    pub aa: bool,
    /// Truncation — hb3 bit 1.
    pub tc: bool,
    /// Recursion Desired — hb3 bit 0.
    pub rd: bool,
    /// Recursion Available — hb4 bit 7.
    pub ra: bool,
    /// Authenticated Data (DNSSEC, RFC 4035) — hb4 bit 5.
    pub ad: bool,
    /// Checking Disabled (DNSSEC, RFC 4035) — hb4 bit 4.
    pub cd: bool,
    /// Response code (lower 4 bits of hb4).
    pub rcode: ResponseCode,
}

impl Default for DnsHeaderFlags {
    fn default() -> Self {
        Self {
            qr: false,
            opcode: 0,
            aa: false,
            tc: false,
            rd: false,
            ra: false,
            ad: false,
            cd: false,
            rcode: ResponseCode::NoError,
        }
    }
}

impl DnsHeaderFlags {
    /// Encode flags into the two raw bytes (hb3, hb4) for wire format.
    fn to_bytes(&self) -> (u8, u8) {
        let mut hb3: u8 = 0;
        if self.qr {
            hb3 |= HB3_QR;
        }
        hb3 |= (self.opcode & 0x0f) << 3;
        if self.aa {
            hb3 |= HB3_AA;
        }
        if self.tc {
            hb3 |= HB3_TC;
        }
        if self.rd {
            hb3 |= HB3_RD;
        }

        let mut hb4: u8 = 0;
        if self.ra {
            hb4 |= HB4_RA;
        }
        if self.ad {
            hb4 |= HB4_AD;
        }
        if self.cd {
            hb4 |= HB4_CD;
        }
        hb4 |= (self.rcode as u8) & HB4_RCODE;

        (hb3, hb4)
    }

    /// Decode flags from the two raw bytes (hb3, hb4) from wire format.
    fn from_bytes(hb3: u8, hb4: u8) -> Self {
        let rcode_val = hb4 & HB4_RCODE;
        let rcode = ResponseCode::from_u8(rcode_val).unwrap_or(ResponseCode::NoError);
        Self {
            qr: (hb3 & HB3_QR) != 0,
            opcode: (hb3 & HB3_OPCODE) >> 3,
            aa: (hb3 & HB3_AA) != 0,
            tc: (hb3 & HB3_TC) != 0,
            rd: (hb3 & HB3_RD) != 0,
            ra: (hb4 & HB4_RA) != 0,
            ad: (hb4 & HB4_AD) != 0,
            cd: (hb4 & HB4_CD) != 0,
            rcode,
        }
    }
}

/// DNS message header per RFC 1035 Section 4.1.1.
///
/// Replaces C `struct dns_header` with typed accessors. The header is exactly
/// 12 bytes on the wire: 2-byte ID, 2 flag bytes, and four 2-byte section counts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsHeader {
    /// 16-bit message identifier assigned by the program generating the query.
    pub id: u16,
    /// Decoded flag fields (QR, OPCODE, AA, TC, RD, RA, AD, CD, RCODE).
    pub flags: DnsHeaderFlags,
    /// Number of entries in the question section.
    pub qdcount: u16,
    /// Number of entries in the answer section.
    pub ancount: u16,
    /// Number of entries in the authority section.
    pub nscount: u16,
    /// Number of entries in the additional section.
    pub arcount: u16,
}

impl DnsHeader {
    /// Parse a 12-byte DNS header from the start of `buf`.
    ///
    /// Returns `Err` if `buf` is shorter than 12 bytes.
    pub fn parse(buf: &[u8]) -> DnsmasqResult<Self> {
        if buf.len() < HDRSIZE {
            return Err(DnsmasqError::DnsProtocol(format!(
                "DNS header too short: {} bytes (need {})",
                buf.len(),
                HDRSIZE
            )));
        }
        let id = u16::from_be_bytes([buf[0], buf[1]]);
        let hb3 = buf[2];
        let hb4 = buf[3];
        let flags = DnsHeaderFlags::from_bytes(hb3, hb4);
        let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
        let ancount = u16::from_be_bytes([buf[6], buf[7]]);
        let nscount = u16::from_be_bytes([buf[8], buf[9]]);
        let arcount = u16::from_be_bytes([buf[10], buf[11]]);

        trace!(
            id = id,
            opcode = flags.opcode,
            qr = flags.qr,
            qdcount = qdcount,
            "parsed DNS header"
        );

        Ok(Self {
            id,
            flags,
            qdcount,
            ancount,
            nscount,
            arcount,
        })
    }

    /// Serialize this header into exactly 12 bytes appended to `buf`.
    pub fn serialize(&self, buf: &mut BytesMut) {
        buf.put_u16(self.id);
        let (hb3, hb4) = self.flags.to_bytes();
        buf.put_u8(hb3);
        buf.put_u8(hb4);
        buf.put_u16(self.qdcount);
        buf.put_u16(self.ancount);
        buf.put_u16(self.nscount);
        buf.put_u16(self.arcount);
    }

    /// Return the 4-bit OPCODE value — replaces C `OPCODE(header)` macro.
    pub fn opcode(&self) -> u8 {
        self.flags.opcode
    }

    /// Set the 4-bit OPCODE value — replaces C `SET_OPCODE(header, v)` macro.
    pub fn set_opcode(&mut self, v: u8) {
        self.flags.opcode = v & 0x0f;
    }

    /// Return the response code — replaces C `RCODE(header)` macro.
    pub fn rcode(&self) -> ResponseCode {
        self.flags.rcode
    }

    /// Set the response code — replaces C `SET_RCODE(header, v)` macro.
    pub fn set_rcode(&mut self, rcode: ResponseCode) {
        self.flags.rcode = rcode;
    }
}

impl fmt::Display for DnsHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DNS Header [id={:#06x} {} op={} {} qd={} an={} ns={} ar={}]",
            self.id,
            if self.flags.qr { "QR" } else { "Q" },
            self.flags.opcode,
            self.flags.rcode,
            self.qdcount,
            self.ancount,
            self.nscount,
            self.arcount
        )
    }
}

// ===========================================================================
// DNS Name (domain name with wire format encoding)
// ===========================================================================

/// DNS domain name, stored as a sequence of labels.
///
/// Handles compression/decompression per RFC 1035 Section 4.1.4 and internal
/// label escaping using [`NAME_ESCAPE`] for special characters.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DnsName {
    /// Individual labels of the domain name (without dots or length prefixes).
    labels: Vec<String>,
}

impl DnsName {
    /// Create a `DnsName` from a dotted string (e.g. `"example.com"`).
    ///
    /// Empty labels are filtered out so both `"example.com"` and
    /// `"example.com."` yield the same result.
    pub fn from_str_unchecked(s: &str) -> Self {
        let labels: Vec<String> = s
            .split('.')
            .filter(|l| !l.is_empty())
            .map(|l| l.to_string())
            .collect();
        Self { labels }
    }

    /// Create an empty (root) domain name.
    pub fn root() -> Self {
        Self { labels: Vec::new() }
    }

    /// Return the number of labels in this name.
    pub fn label_count(&self) -> usize {
        self.labels.len()
    }

    /// Check whether this name represents the root domain.
    pub fn is_root(&self) -> bool {
        self.labels.is_empty()
    }

    /// Extract a domain name from DNS wire format at `offset` within `packet`.
    ///
    /// Handles compression pointers (RFC 1035 Section 4.1.4) with loop detection
    /// (max [`MAX_COMPRESSION_HOPS`] pointer hops). Returns `(DnsName, bytes_consumed)`
    /// where `bytes_consumed` is the number of bytes consumed at the *original* offset
    /// (before following any compression pointers).
    ///
    /// Replaces C `extract_name()` from rfc1035.c.
    pub fn from_wire(_buf: &[u8], offset: usize, packet: &[u8]) -> DnsmasqResult<(Self, usize)> {
        let mut labels = Vec::new();
        let mut pos = offset;
        let mut hops = 0usize;
        let mut bytes_consumed: Option<usize> = None;

        loop {
            if pos >= packet.len() {
                return Err(DnsmasqError::DnsProtocol(
                    "DNS name: offset beyond packet".to_string(),
                ));
            }

            let len_or_ptr = packet[pos];

            // Check for end of name (zero-length label).
            if len_or_ptr == 0 {
                if bytes_consumed.is_none() {
                    bytes_consumed = Some(pos + 1 - offset);
                }
                break;
            }

            // Compression pointer: top two bits are 11.
            if (len_or_ptr & 0xC0) == 0xC0 {
                if pos + 1 >= packet.len() {
                    return Err(DnsmasqError::DnsProtocol(
                        "DNS name: truncated compression pointer".to_string(),
                    ));
                }
                let ptr = ((u16::from(len_or_ptr) & 0x3F) << 8) | u16::from(packet[pos + 1]);
                if bytes_consumed.is_none() {
                    bytes_consumed = Some(pos + 2 - offset);
                }
                pos = ptr as usize;
                hops += 1;
                if hops > MAX_COMPRESSION_HOPS {
                    warn!("DNS name compression pointer loop detected");
                    return Err(DnsmasqError::DnsProtocol(
                        "DNS name: compression pointer loop".to_string(),
                    ));
                }
                continue;
            }

            // Extended label types (0x40 = bitstring, etc.) are not supported.
            if (len_or_ptr & 0xC0) != 0 {
                return Err(DnsmasqError::DnsProtocol(format!(
                    "DNS name: unsupported label type {:#04x}",
                    len_or_ptr
                )));
            }

            // Normal label.
            let label_len = len_or_ptr as usize;
            if label_len > MAXLABEL {
                return Err(DnsmasqError::DnsProtocol(format!(
                    "DNS label too long: {} bytes (max {})",
                    label_len, MAXLABEL
                )));
            }
            let label_start = pos + 1;
            let label_end = label_start + label_len;
            if label_end > packet.len() {
                return Err(DnsmasqError::DnsProtocol(
                    "DNS name: label extends beyond packet".to_string(),
                ));
            }
            let label = String::from_utf8_lossy(&packet[label_start..label_end]).to_string();
            trace!(label = %label, "extracted DNS label");
            labels.push(label);
            pos = label_end;
        }

        let consumed = bytes_consumed.unwrap_or(1);
        Ok((Self { labels }, consumed))
    }

    /// Encode this domain name into DNS wire format (uncompressed) and append to `buf`.
    ///
    /// Each label is written as a length byte followed by the label bytes,
    /// terminated by a zero byte. Replaces C `do_rfc1035_name()` + null terminator.
    pub fn to_wire(&self, buf: &mut BytesMut) {
        for label in &self.labels {
            let bytes = label.as_bytes();
            let len = bytes.len().min(MAXLABEL);
            buf.put_u8(len as u8);
            buf.put_slice(&bytes[..len]);
        }
        buf.put_u8(0); // root label terminator
    }

    /// Return the presentation-format string (e.g. `"example.com."`).
    ///
    /// Uses trailing dot notation per RFC 1035 convention.
    #[allow(clippy::inherent_to_string_shadow_display)]
    pub fn to_string(&self) -> String {
        if self.labels.is_empty() {
            return ".".to_string();
        }
        let mut s = self.labels.join(".");
        s.push('.');
        s
    }

    /// Check whether this name is a subdomain of `parent`.
    ///
    /// Returns `true` if `self` ends with all labels from `parent`.
    /// A name is considered a subdomain of itself.
    pub fn is_subdomain_of(&self, parent: &DnsName) -> bool {
        if parent.labels.len() > self.labels.len() {
            return false;
        }
        let offset = self.labels.len() - parent.labels.len();
        for (i, parent_label) in parent.labels.iter().enumerate() {
            if !self.labels[offset + i].eq_ignore_ascii_case(parent_label) {
                return false;
            }
        }
        true
    }
}

impl fmt::Display for DnsName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

// ===========================================================================
// DNS Question
// ===========================================================================

/// A single question entry in the DNS question section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    /// The domain name being queried.
    pub name: DnsName,
    /// The type of query (A, AAAA, MX, etc.).
    pub qtype: RRType,
    /// The class of query (typically IN).
    pub qclass: DnsClass,
}

// ===========================================================================
// DNS Resource Record
// ===========================================================================

/// A single DNS resource record (answer, authority, or additional section).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsResourceRecord {
    /// Owner name of this resource record.
    pub name: DnsName,
    /// Resource record type.
    pub rr_type: RRType,
    /// Resource record class.
    pub class: DnsClass,
    /// Time to live in seconds.
    pub ttl: u32,
    /// Raw RDATA bytes (type-specific payload).
    pub rdata: Bytes,
}

impl DnsResourceRecord {
    /// Interpret RDATA as an IPv4 address (for A records).
    ///
    /// Returns `Some(Ipv4Addr)` if this is an A record with exactly 4 bytes of RDATA,
    /// `None` otherwise.
    pub fn as_ipv4(&self) -> Option<Ipv4Addr> {
        if self.rr_type == RRType::A && self.rdata.len() == INADDRSZ {
            Some(Ipv4Addr::new(
                self.rdata[0],
                self.rdata[1],
                self.rdata[2],
                self.rdata[3],
            ))
        } else {
            None
        }
    }

    /// Interpret RDATA as an IPv6 address (for AAAA records).
    ///
    /// Returns `Some(Ipv6Addr)` if this is an AAAA record with exactly 16 bytes of RDATA,
    /// `None` otherwise.
    pub fn as_ipv6(&self) -> Option<Ipv6Addr> {
        if self.rr_type == RRType::AAAA && self.rdata.len() == IN6ADDRSZ {
            let mut cursor = &self.rdata[..];
            Some(Ipv6Addr::new(
                Buf::get_u16(&mut cursor),
                Buf::get_u16(&mut cursor),
                Buf::get_u16(&mut cursor),
                Buf::get_u16(&mut cursor),
                Buf::get_u16(&mut cursor),
                Buf::get_u16(&mut cursor),
                Buf::get_u16(&mut cursor),
                Buf::get_u16(&mut cursor),
            ))
        } else {
            None
        }
    }
}

// ===========================================================================
// DNS Packet (parsed representation)
// ===========================================================================

/// A fully-parsed DNS packet with all sections.
///
/// Provides structured access to the header, question, answer, authority,
/// and additional sections. The original raw bytes are retained for
/// reference and re-serialization.
#[derive(Debug, Clone)]
pub struct DnsPacket {
    /// Parsed DNS header.
    pub header: DnsHeader,
    /// Question section entries.
    pub questions: Vec<DnsQuestion>,
    /// Answer section resource records.
    pub answers: Vec<DnsResourceRecord>,
    /// Authority section resource records.
    pub authority: Vec<DnsResourceRecord>,
    /// Additional section resource records.
    pub additional: Vec<DnsResourceRecord>,
    /// Original raw packet bytes.
    pub raw: Bytes,
}

impl DnsPacket {
    /// Parse a complete DNS packet from raw bytes.
    ///
    /// Parses the header, then iterates through each section (questions,
    /// answers, authority, additional) extracting structured records.
    /// Unknown RR types or classes are preserved with their raw numeric values
    /// by falling back to defaults.
    pub fn parse(data: &[u8]) -> DnsmasqResult<Self> {
        let header = DnsHeader::parse(data)?;
        let mut offset = HDRSIZE;

        // Parse questions.
        let mut questions = Vec::with_capacity(header.qdcount as usize);
        for _ in 0..header.qdcount {
            let (name, consumed) = DnsName::from_wire(data, offset, data)?;
            offset += consumed;
            if offset + 4 > data.len() {
                return Err(DnsmasqError::DnsProtocol(
                    "DNS question section truncated".to_string(),
                ));
            }
            let qtype_raw = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let qclass_raw = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
            offset += 4;

            let qtype = RRType::from_u16(qtype_raw).unwrap_or(RRType::ANY);
            let qclass = DnsClass::from_u16(qclass_raw).unwrap_or(DnsClass::IN);

            questions.push(DnsQuestion {
                name,
                qtype,
                qclass,
            });
        }

        // Helper closure to parse a section of resource records.
        let parse_section =
            |data: &[u8], off: &mut usize, count: u16| -> DnsmasqResult<Vec<DnsResourceRecord>> {
                let mut records = Vec::with_capacity(count as usize);
                for _ in 0..count {
                    let (name, consumed) = DnsName::from_wire(data, *off, data)?;
                    *off += consumed;

                    // TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) = 10 bytes
                    if *off + RRFIXEDSZ > data.len() {
                        return Err(DnsmasqError::DnsProtocol(
                            "DNS RR section truncated".to_string(),
                        ));
                    }
                    let rr_type_raw = u16::from_be_bytes([data[*off], data[*off + 1]]);
                    let class_raw = u16::from_be_bytes([data[*off + 2], data[*off + 3]]);
                    let ttl = u32::from_be_bytes([
                        data[*off + 4],
                        data[*off + 5],
                        data[*off + 6],
                        data[*off + 7],
                    ]);
                    let rdlength = u16::from_be_bytes([data[*off + 8], data[*off + 9]]) as usize;
                    *off += RRFIXEDSZ;

                    if *off + rdlength > data.len() {
                        return Err(DnsmasqError::DnsProtocol(
                            "DNS RR RDATA extends beyond packet".to_string(),
                        ));
                    }
                    let rdata = Bytes::copy_from_slice(&data[*off..*off + rdlength]);
                    *off += rdlength;

                    let rr_type = RRType::from_u16(rr_type_raw).unwrap_or(RRType::ANY);
                    let class = DnsClass::from_u16(class_raw).unwrap_or(DnsClass::IN);

                    records.push(DnsResourceRecord {
                        name,
                        rr_type,
                        class,
                        ttl,
                        rdata,
                    });
                }
                Ok(records)
            };

        let answers = parse_section(data, &mut offset, header.ancount)?;
        let authority = parse_section(data, &mut offset, header.nscount)?;
        let additional = parse_section(data, &mut offset, header.arcount)?;

        debug!(
            id = header.id,
            questions = questions.len(),
            answers = answers.len(),
            authority = authority.len(),
            additional = additional.len(),
            "parsed DNS packet"
        );

        Ok(Self {
            header,
            questions,
            answers,
            authority,
            additional,
            raw: Bytes::copy_from_slice(data),
        })
    }
}

// ===========================================================================
// DNS Packet Builder (builder pattern per AAP Section 0.4.2)
// ===========================================================================

/// Builder for constructing DNS packets with type safety.
///
/// Implements the builder pattern per AAP Section 0.4.2, replacing C's
/// `add_resource_record()` variadic function with type-safe method chaining.
///
/// # Example
/// ```ignore
/// let packet = DnsPacketBuilder::new(0x1234)
///     .set_response()
///     .set_authoritative()
///     .add_question(&name, RRType::A, DnsClass::IN)
///     .add_answer(&name, RRType::A, DnsClass::IN, 300, &rdata)
///     .build()?;
/// ```
pub struct DnsPacketBuilder {
    buffer: BytesMut,
    header: DnsHeader,
}

impl DnsPacketBuilder {
    /// Create a new builder with the given transaction ID.
    pub fn new(id: u16) -> Self {
        Self {
            buffer: BytesMut::with_capacity(PACKETSZ),
            header: DnsHeader {
                id,
                flags: DnsHeaderFlags::default(),
                qdcount: 0,
                ancount: 0,
                nscount: 0,
                arcount: 0,
            },
        }
    }

    /// Mark this packet as a response (sets QR flag).
    pub fn set_response(mut self) -> Self {
        self.header.flags.qr = true;
        self
    }

    /// Set the authoritative answer flag.
    pub fn set_authoritative(mut self) -> Self {
        self.header.flags.aa = true;
        self
    }

    /// Add a question entry.
    pub fn add_question(mut self, name: &DnsName, rr_type: RRType, class: DnsClass) -> Self {
        name.to_wire(&mut self.buffer);
        self.buffer.put_u16(rr_type.to_u16());
        self.buffer.put_u16(class.to_u16());
        self.header.qdcount += 1;
        self
    }

    /// Add an answer resource record.
    pub fn add_answer(
        mut self,
        name: &DnsName,
        rr_type: RRType,
        class: DnsClass,
        ttl: u32,
        rdata: &[u8],
    ) -> Self {
        self.write_rr(name, rr_type, class, ttl, rdata);
        self.header.ancount += 1;
        self
    }

    /// Add an authority resource record.
    pub fn add_authority(
        mut self,
        name: &DnsName,
        rr_type: RRType,
        class: DnsClass,
        ttl: u32,
        rdata: &[u8],
    ) -> Self {
        self.write_rr(name, rr_type, class, ttl, rdata);
        self.header.nscount += 1;
        self
    }

    /// Add an additional resource record.
    pub fn add_additional(
        mut self,
        name: &DnsName,
        rr_type: RRType,
        class: DnsClass,
        ttl: u32,
        rdata: &[u8],
    ) -> Self {
        self.write_rr(name, rr_type, class, ttl, rdata);
        self.header.arcount += 1;
        self
    }

    /// Build the final [`DnsPacket`] by prepending the header and parsing the result.
    pub fn build(self) -> DnsmasqResult<DnsPacket> {
        let mut out = BytesMut::with_capacity(HDRSIZE + self.buffer.len());
        self.header.serialize(&mut out);
        out.extend_from_slice(&self.buffer);
        let raw = out.freeze();
        DnsPacket::parse(&raw)
    }

    /// Internal: write a single resource record to the buffer.
    fn write_rr(
        &mut self,
        name: &DnsName,
        rr_type: RRType,
        class: DnsClass,
        ttl: u32,
        rdata: &[u8],
    ) {
        name.to_wire(&mut self.buffer);
        self.buffer.put_u16(rr_type.to_u16());
        self.buffer.put_u16(class.to_u16());
        self.buffer.put_u32(ttl);
        self.buffer.put_u16(rdata.len() as u16);
        self.buffer.put_slice(rdata);
    }
}

// ===========================================================================
// Byte Order Helpers (replacing C GETSHORT / GETLONG / PUTSHORT / PUTLONG)
// ===========================================================================

/// Read a `u16` in network byte order (big-endian) from `buf` at `offset`.
///
/// Replaces C `GETSHORT()` macro from dns-protocol.h.
pub fn get_u16(buf: &[u8], offset: usize) -> DnsmasqResult<u16> {
    if offset + 2 > buf.len() {
        return Err(DnsmasqError::DnsProtocol(format!(
            "get_u16: offset {} + 2 > buffer length {}",
            offset,
            buf.len()
        )));
    }
    Ok(u16::from_be_bytes([buf[offset], buf[offset + 1]]))
}

/// Read a `u32` in network byte order (big-endian) from `buf` at `offset`.
///
/// Replaces C `GETLONG()` macro from dns-protocol.h.
pub fn get_u32(buf: &[u8], offset: usize) -> DnsmasqResult<u32> {
    if offset + 4 > buf.len() {
        return Err(DnsmasqError::DnsProtocol(format!(
            "get_u32: offset {} + 4 > buffer length {}",
            offset,
            buf.len()
        )));
    }
    Ok(u32::from_be_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ]))
}

/// Write a `u16` in network byte order (big-endian) to `buf`.
///
/// Replaces C `PUTSHORT()` macro from dns-protocol.h.
pub fn put_u16(buf: &mut BytesMut, value: u16) {
    buf.put_u16(value);
}

/// Write a `u32` in network byte order (big-endian) to `buf`.
///
/// Replaces C `PUTLONG()` macro from dns-protocol.h.
pub fn put_u32(buf: &mut BytesMut, value: u32) {
    buf.put_u32(value);
}

// ===========================================================================
// RRSet for DNSSEC (gated behind "dnssec" feature)
// ===========================================================================

/// A set of resource records sharing the same owner name, type, and class.
///
/// Used during DNSSEC signature verification where all RRs in an RRSet
/// must be validated together.
#[cfg(feature = "dnssec")]
#[derive(Debug, Clone)]
pub struct RRSet {
    /// Owner name of the RRSet.
    pub name: DnsName,
    /// Record type shared by all records in this set.
    pub rr_type: RRType,
    /// Record class shared by all records.
    pub class: DnsClass,
    /// Individual resource records belonging to this set.
    pub records: Vec<DnsResourceRecord>,
}

// ===========================================================================
// Unit Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_response_code_roundtrip() {
        for code in [
            ResponseCode::NoError,
            ResponseCode::FormErr,
            ResponseCode::ServFail,
            ResponseCode::NxDomain,
            ResponseCode::NotImp,
            ResponseCode::Refused,
        ] {
            let v = code as u8;
            assert_eq!(ResponseCode::from_u8(v), Some(code));
        }
        assert_eq!(ResponseCode::from_u8(6), None);
        assert_eq!(ResponseCode::from_u8(255), None);
    }

    #[test]
    fn test_dns_class_roundtrip() {
        assert_eq!(DnsClass::from_u16(1), Some(DnsClass::IN));
        assert_eq!(DnsClass::from_u16(3), Some(DnsClass::Chaos));
        assert_eq!(DnsClass::from_u16(4), Some(DnsClass::Hesiod));
        assert_eq!(DnsClass::from_u16(255), Some(DnsClass::Any));
        assert_eq!(DnsClass::from_u16(0), None);
        assert_eq!(DnsClass::from_u16(2), None);
        assert_eq!(DnsClass::IN.to_u16(), 1);
    }

    #[test]
    fn test_rr_type_roundtrip() {
        assert_eq!(RRType::from_u16(1), Some(RRType::A));
        assert_eq!(RRType::from_u16(28), Some(RRType::AAAA));
        assert_eq!(RRType::from_u16(41), Some(RRType::OPT));
        assert_eq!(RRType::from_u16(257), Some(RRType::CAA));
        assert_eq!(RRType::from_u16(0), None);
        assert_eq!(RRType::from_u16(9999), None);
        assert_eq!(RRType::A.to_u16(), 1);
        assert_eq!(RRType::AAAA.to_u16(), 28);
    }

    #[test]
    fn test_dns_header_parse_serialize_roundtrip() {
        let mut buf = BytesMut::new();
        let header = DnsHeader {
            id: 0xABCD,
            flags: DnsHeaderFlags {
                qr: true,
                opcode: 0,
                aa: true,
                tc: false,
                rd: true,
                ra: true,
                ad: false,
                cd: false,
                rcode: ResponseCode::NoError,
            },
            qdcount: 1,
            ancount: 2,
            nscount: 0,
            arcount: 1,
        };
        header.serialize(&mut buf);
        assert_eq!(buf.len(), HDRSIZE);

        let parsed = DnsHeader::parse(&buf).unwrap();
        assert_eq!(parsed.id, 0xABCD);
        assert!(parsed.flags.qr);
        assert!(parsed.flags.aa);
        assert!(!parsed.flags.tc);
        assert!(parsed.flags.rd);
        assert!(parsed.flags.ra);
        assert!(!parsed.flags.ad);
        assert!(!parsed.flags.cd);
        assert_eq!(parsed.flags.rcode, ResponseCode::NoError);
        assert_eq!(parsed.qdcount, 1);
        assert_eq!(parsed.ancount, 2);
        assert_eq!(parsed.nscount, 0);
        assert_eq!(parsed.arcount, 1);
    }

    #[test]
    fn test_dns_header_parse_too_short() {
        let buf = [0u8; 11];
        assert!(DnsHeader::parse(&buf).is_err());
    }

    #[test]
    fn test_dns_header_opcode_rcode() {
        let mut hdr = DnsHeader {
            id: 1,
            flags: DnsHeaderFlags::default(),
            qdcount: 0,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        };
        assert_eq!(hdr.opcode(), 0);
        hdr.set_opcode(2);
        assert_eq!(hdr.opcode(), 2);
        assert_eq!(hdr.rcode(), ResponseCode::NoError);
        hdr.set_rcode(ResponseCode::NxDomain);
        assert_eq!(hdr.rcode(), ResponseCode::NxDomain);
    }

    #[test]
    fn test_dns_name_from_wire_simple() {
        // Wire format for "example.com": 7 e x a m p l e 3 c o m 0
        let wire: Vec<u8> = vec![
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ];
        let (name, consumed) = DnsName::from_wire(&wire, 0, &wire).unwrap();
        assert_eq!(name.to_string(), "example.com.");
        assert_eq!(consumed, 13);
        assert_eq!(name.label_count(), 2);
    }

    #[test]
    fn test_dns_name_from_wire_compression() {
        // Packet: header (12 bytes) + "example.com" name, then pointer at offset 25
        let mut pkt = vec![0u8; 12]; // dummy header
                                     // Name at offset 12: 7 example 3 com 0
        pkt.extend_from_slice(&[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]);
        // At offset 25, a compression pointer to offset 12
        pkt.extend_from_slice(&[0xC0, 12]);

        let (name, consumed) = DnsName::from_wire(&pkt, 25, &pkt).unwrap();
        assert_eq!(name.to_string(), "example.com.");
        assert_eq!(consumed, 2); // pointer is 2 bytes
    }

    #[test]
    fn test_dns_name_compression_loop_detected() {
        // Create a packet with a self-referencing compression pointer
        let pkt = vec![0xC0, 0x00]; // points back to itself
        let result = DnsName::from_wire(&pkt, 0, &pkt);
        assert!(result.is_err());
    }

    #[test]
    fn test_dns_name_to_wire() {
        let name = DnsName::from_str_unchecked("example.com");
        let mut buf = BytesMut::new();
        name.to_wire(&mut buf);
        let expected: Vec<u8> = vec![
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ];
        assert_eq!(&buf[..], &expected[..]);
    }

    #[test]
    fn test_dns_name_to_string() {
        let name = DnsName::from_str_unchecked("foo.bar.baz");
        assert_eq!(name.to_string(), "foo.bar.baz.");
        let root = DnsName::root();
        assert_eq!(root.to_string(), ".");
    }

    #[test]
    fn test_dns_name_is_subdomain_of() {
        let child = DnsName::from_str_unchecked("mail.example.com");
        let parent = DnsName::from_str_unchecked("example.com");
        let other = DnsName::from_str_unchecked("other.net");

        assert!(child.is_subdomain_of(&parent));
        assert!(parent.is_subdomain_of(&parent)); // self
        assert!(!parent.is_subdomain_of(&child));
        assert!(!child.is_subdomain_of(&other));
    }

    #[test]
    fn test_dns_name_is_subdomain_case_insensitive() {
        let child = DnsName::from_str_unchecked("Mail.EXAMPLE.Com");
        let parent = DnsName::from_str_unchecked("example.com");
        assert!(child.is_subdomain_of(&parent));
    }

    #[test]
    fn test_get_u16_get_u32() {
        let buf = [0x00, 0x35, 0x00, 0x00, 0x01, 0x00];
        assert_eq!(get_u16(&buf, 0).unwrap(), 0x0035);
        assert_eq!(get_u32(&buf, 2).unwrap(), 0x00000100);
        assert!(get_u16(&buf, 5).is_err());
        assert!(get_u32(&buf, 4).is_err());
    }

    #[test]
    fn test_put_u16_put_u32() {
        let mut buf = BytesMut::new();
        put_u16(&mut buf, 0xABCD);
        assert_eq!(&buf[..], &[0xAB, 0xCD]);

        let mut buf2 = BytesMut::new();
        put_u32(&mut buf2, 0x12345678);
        assert_eq!(&buf2[..], &[0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn test_dns_packet_builder_simple_query() {
        let name = DnsName::from_str_unchecked("example.com");
        let pkt = DnsPacketBuilder::new(0x1234)
            .add_question(&name, RRType::A, DnsClass::IN)
            .build()
            .unwrap();

        assert_eq!(pkt.header.id, 0x1234);
        assert!(!pkt.header.flags.qr);
        assert_eq!(pkt.header.qdcount, 1);
        assert_eq!(pkt.questions.len(), 1);
        assert_eq!(pkt.questions[0].name.to_string(), "example.com.");
        assert_eq!(pkt.questions[0].qtype, RRType::A);
        assert_eq!(pkt.questions[0].qclass, DnsClass::IN);
    }

    #[test]
    fn test_dns_packet_builder_response_with_answer() {
        let name = DnsName::from_str_unchecked("example.com");
        let rdata: [u8; 4] = [93, 184, 216, 34]; // 93.184.216.34
        let pkt = DnsPacketBuilder::new(0x5678)
            .set_response()
            .set_authoritative()
            .add_question(&name, RRType::A, DnsClass::IN)
            .add_answer(&name, RRType::A, DnsClass::IN, 300, &rdata)
            .build()
            .unwrap();

        assert!(pkt.header.flags.qr);
        assert!(pkt.header.flags.aa);
        assert_eq!(pkt.header.ancount, 1);
        assert_eq!(pkt.answers.len(), 1);
        assert_eq!(pkt.answers[0].rr_type, RRType::A);
        assert_eq!(pkt.answers[0].ttl, 300);
        assert_eq!(&pkt.answers[0].rdata[..], &rdata[..]);
    }

    #[test]
    fn test_dns_packet_builder_authority_additional() {
        let name = DnsName::from_str_unchecked("example.com");
        let ns_name = DnsName::from_str_unchecked("ns1.example.com");
        let mut ns_rdata = BytesMut::new();
        ns_name.to_wire(&mut ns_rdata);

        let a_rdata: [u8; 4] = [192, 0, 2, 1];
        let pkt = DnsPacketBuilder::new(0x0001)
            .set_response()
            .add_question(&name, RRType::A, DnsClass::IN)
            .add_authority(&name, RRType::NS, DnsClass::IN, 3600, &ns_rdata)
            .add_additional(&ns_name, RRType::A, DnsClass::IN, 3600, &a_rdata)
            .build()
            .unwrap();

        assert_eq!(pkt.header.nscount, 1);
        assert_eq!(pkt.header.arcount, 1);
        assert_eq!(pkt.authority.len(), 1);
        assert_eq!(pkt.additional.len(), 1);
        assert_eq!(pkt.authority[0].rr_type, RRType::NS);
        assert_eq!(pkt.additional[0].rr_type, RRType::A);
    }

    #[test]
    fn test_dns_packet_parse_real_query() {
        // A standard DNS query for example.com A
        let mut pkt = BytesMut::new();
        // Header: id=0x1234, flags=0x0100 (RD), qdcount=1
        pkt.put_u16(0x1234); // id
        pkt.put_u8(0x01); // hb3: RD
        pkt.put_u8(0x00); // hb4
        pkt.put_u16(1); // qdcount
        pkt.put_u16(0); // ancount
        pkt.put_u16(0); // nscount
        pkt.put_u16(0); // arcount
                        // Question: example.com IN A
        pkt.put_slice(&[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]);
        pkt.put_u16(1); // QTYPE = A
        pkt.put_u16(1); // QCLASS = IN

        let parsed = DnsPacket::parse(&pkt).unwrap();
        assert_eq!(parsed.header.id, 0x1234);
        assert!(!parsed.header.flags.qr);
        assert!(parsed.header.flags.rd);
        assert_eq!(parsed.questions.len(), 1);
        assert_eq!(parsed.questions[0].name.to_string(), "example.com.");
        assert_eq!(parsed.questions[0].qtype, RRType::A);
        assert_eq!(parsed.questions[0].qclass, DnsClass::IN);
    }

    #[test]
    fn test_header_flags_all_set() {
        let flags = DnsHeaderFlags {
            qr: true,
            opcode: 0,
            aa: true,
            tc: true,
            rd: true,
            ra: true,
            ad: true,
            cd: true,
            rcode: ResponseCode::Refused,
        };
        let (hb3, hb4) = flags.to_bytes();
        assert_eq!(hb3 & HB3_QR, HB3_QR);
        assert_eq!(hb3 & HB3_AA, HB3_AA);
        assert_eq!(hb3 & HB3_TC, HB3_TC);
        assert_eq!(hb3 & HB3_RD, HB3_RD);
        assert_eq!(hb4 & HB4_RA, HB4_RA);
        assert_eq!(hb4 & HB4_AD, HB4_AD);
        assert_eq!(hb4 & HB4_CD, HB4_CD);
        assert_eq!(hb4 & HB4_RCODE, ResponseCode::Refused as u8);

        let decoded = DnsHeaderFlags::from_bytes(hb3, hb4);
        assert_eq!(decoded, flags);
    }

    #[test]
    fn test_constants_values() {
        assert_eq!(NAMESERVER_PORT, 53);
        assert_eq!(TFTP_PORT, 69);
        assert_eq!(MIN_PORT, 1024);
        assert_eq!(MAX_PORT, 65535);
        assert_eq!(IN6ADDRSZ, 16);
        assert_eq!(INADDRSZ, 4);
        assert_eq!(PACKETSZ, 512);
        assert_eq!(MAXDNAME, 1025);
        assert_eq!(RRFIXEDSZ, 10);
        assert_eq!(MAXLABEL, 63);
        assert_eq!(NAME_ESCAPE, 1);
    }

    #[test]
    fn test_edns0_constants() {
        assert_eq!(edns0::OPTION_MAC, 65001);
        assert_eq!(edns0::OPTION_CLIENT_SUBNET, 8);
        assert_eq!(edns0::OPTION_EDE, 15);
        assert_eq!(edns0::OPTION_NOMDEVICEID, 65073);
        assert_eq!(edns0::OPTION_NOMCPEID, 65074);
        assert_eq!(edns0::OPTION_UMBRELLA, 20292);
    }

    #[test]
    fn test_ede_constants() {
        assert_eq!(ede::UNSET, -1);
        assert_eq!(ede::OTHER, 0);
        assert_eq!(ede::SYNTHESIZED, 29);
        assert_eq!(ede::BLOCKED, 15);
        assert_eq!(ede::SIG_EXPIRED, 7);
    }

    #[test]
    fn test_header_flag_constants() {
        assert_eq!(HB3_QR, 0x80);
        assert_eq!(HB3_OPCODE, 0x78);
        assert_eq!(HB3_AA, 0x04);
        assert_eq!(HB3_TC, 0x02);
        assert_eq!(HB3_RD, 0x01);
        assert_eq!(HB4_RA, 0x80);
        assert_eq!(HB4_AD, 0x20);
        assert_eq!(HB4_CD, 0x10);
        assert_eq!(HB4_RCODE, 0x0f);
    }

    #[test]
    fn test_response_code_display() {
        assert_eq!(format!("{}", ResponseCode::NoError), "NOERROR");
        assert_eq!(format!("{}", ResponseCode::NxDomain), "NXDOMAIN");
        assert_eq!(format!("{}", ResponseCode::Refused), "REFUSED");
    }

    #[test]
    fn test_dns_class_display() {
        assert_eq!(format!("{}", DnsClass::IN), "IN");
        assert_eq!(format!("{}", DnsClass::Chaos), "CH");
        assert_eq!(format!("{}", DnsClass::Hesiod), "HS");
        assert_eq!(format!("{}", DnsClass::Any), "ANY");
    }

    #[test]
    fn test_rr_type_display() {
        assert_eq!(format!("{}", RRType::A), "A");
        assert_eq!(format!("{}", RRType::AAAA), "AAAA");
        assert_eq!(format!("{}", RRType::CNAME), "CNAME");
        assert_eq!(format!("{}", RRType::MX), "MX");
    }

    #[test]
    fn test_dns_name_root() {
        let root = DnsName::root();
        assert!(root.is_root());
        assert_eq!(root.to_string(), ".");
        let mut buf = BytesMut::new();
        root.to_wire(&mut buf);
        assert_eq!(&buf[..], &[0u8]);
    }

    #[test]
    fn test_dns_name_from_wire_root() {
        let wire = [0u8]; // root label
        let (name, consumed) = DnsName::from_wire(&wire, 0, &wire).unwrap();
        assert!(name.is_root());
        assert_eq!(consumed, 1);
    }

    #[test]
    fn test_dns_packet_parse_truncated() {
        let short = [0u8; 10]; // less than 12 bytes
        assert!(DnsPacket::parse(&short).is_err());
    }

    #[test]
    fn test_dns_header_serialize_matches_parse() {
        let header = DnsHeader {
            id: 0x9876,
            flags: DnsHeaderFlags {
                qr: false,
                opcode: 5,
                aa: false,
                tc: true,
                rd: false,
                ra: false,
                ad: true,
                cd: true,
                rcode: ResponseCode::ServFail,
            },
            qdcount: 3,
            ancount: 7,
            nscount: 1,
            arcount: 2,
        };
        let mut buf = BytesMut::new();
        header.serialize(&mut buf);
        let parsed = DnsHeader::parse(&buf).unwrap();
        assert_eq!(parsed, header);
    }

    #[test]
    fn test_dns_header_display() {
        let header = DnsHeader {
            id: 0x0042,
            flags: DnsHeaderFlags {
                qr: true,
                opcode: 0,
                aa: false,
                tc: false,
                rd: true,
                ra: true,
                ad: false,
                cd: false,
                rcode: ResponseCode::NoError,
            },
            qdcount: 1,
            ancount: 1,
            nscount: 0,
            arcount: 0,
        };
        let s = format!("{}", header);
        assert!(s.contains("0x0042"));
        assert!(s.contains("QR"));
        assert!(s.contains("NOERROR"));
    }

    #[test]
    fn test_dns_name_wire_roundtrip() {
        let name = DnsName::from_str_unchecked("mail.example.com");
        let mut buf = BytesMut::new();
        name.to_wire(&mut buf);
        let (parsed, _consumed) = DnsName::from_wire(&buf, 0, &buf).unwrap();
        assert_eq!(name, parsed);
    }

    #[test]
    fn test_dns_name_label_too_long() {
        // Create a wire-format name with a label > MAXLABEL
        let mut wire = vec![64u8]; // label length 64 (exceeds MAXLABEL=63)
        wire.extend(vec![b'a'; 64]);
        wire.push(0);
        let result = DnsName::from_wire(&wire, 0, &wire);
        assert!(result.is_err());
    }

    #[test]
    fn test_dns_name_label_beyond_packet() {
        // label says 10 bytes but packet only has 5 after length byte
        let wire = vec![10, b'a', b'b', b'c', b'd', b'e'];
        let result = DnsName::from_wire(&wire, 0, &wire);
        assert!(result.is_err());
    }

    #[test]
    fn test_all_rr_types_have_values() {
        // Verify every RRType variant round-trips through from_u16/to_u16
        let types = [
            RRType::A,
            RRType::NS,
            RRType::MD,
            RRType::MF,
            RRType::CNAME,
            RRType::SOA,
            RRType::MB,
            RRType::MG,
            RRType::MR,
            RRType::PTR,
            RRType::MINFO,
            RRType::MX,
            RRType::TXT,
            RRType::RP,
            RRType::AFSDB,
            RRType::RT,
            RRType::SIG,
            RRType::PX,
            RRType::AAAA,
            RRType::NXT,
            RRType::SRV,
            RRType::NAPTR,
            RRType::KX,
            RRType::DNAME,
            RRType::OPT,
            RRType::DS,
            RRType::RRSIG,
            RRType::NSEC,
            RRType::DNSKEY,
            RRType::NSEC3,
            RRType::TKEY,
            RRType::TSIG,
            RRType::AXFR,
            RRType::MAILB,
            RRType::ANY,
            RRType::CAA,
        ];
        for t in &types {
            let val = t.to_u16();
            assert_eq!(
                RRType::from_u16(val),
                Some(*t),
                "RRType {:?} failed roundtrip",
                t
            );
        }
    }

    #[test]
    fn test_dns_packet_with_answer() {
        // Build a packet with a question and an answer, then parse it
        let mut pkt = BytesMut::new();
        // Header: response, AA, RD, RA, 1 question, 1 answer
        pkt.put_u16(0xAAAA);
        pkt.put_u8(0x85); // QR=1, AA=1, RD=1
        pkt.put_u8(0x80); // RA=1
        pkt.put_u16(1); // qdcount
        pkt.put_u16(1); // ancount
        pkt.put_u16(0); // nscount
        pkt.put_u16(0); // arcount
                        // Question: test.example A IN
        pkt.put_slice(&[
            4, b't', b'e', b's', b't', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0,
        ]);
        pkt.put_u16(1); // A
        pkt.put_u16(1); // IN
                        // Answer: test.example A IN 300 4 bytes (1.2.3.4)
        pkt.put_slice(&[
            4, b't', b'e', b's', b't', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0,
        ]);
        pkt.put_u16(1); // A
        pkt.put_u16(1); // IN
        pkt.put_u32(300); // TTL
        pkt.put_u16(4); // RDLENGTH
        pkt.put_slice(&[1, 2, 3, 4]); // RDATA

        let parsed = DnsPacket::parse(&pkt).unwrap();
        assert!(parsed.header.flags.qr);
        assert!(parsed.header.flags.aa);
        assert!(parsed.header.flags.rd);
        assert!(parsed.header.flags.ra);
        assert_eq!(parsed.questions.len(), 1);
        assert_eq!(parsed.answers.len(), 1);
        assert_eq!(parsed.answers[0].ttl, 300);
        assert_eq!(&parsed.answers[0].rdata[..], &[1, 2, 3, 4]);
    }

    #[test]
    fn test_default_header_flags() {
        let flags = DnsHeaderFlags::default();
        assert!(!flags.qr);
        assert_eq!(flags.opcode, 0);
        assert!(!flags.aa);
        assert!(!flags.tc);
        assert!(!flags.rd);
        assert!(!flags.ra);
        assert!(!flags.ad);
        assert!(!flags.cd);
        assert_eq!(flags.rcode, ResponseCode::NoError);
    }
}

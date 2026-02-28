//! DNS wire-format constants, types, and helper functions per RFC 1035, RFC 6891, and RFC 8914.
//!
//! This module is the Rust equivalent of `src/dns-protocol.h` (873 lines of C). It serves as the
//! canonical source for all DNS protocol constants, wire-format enumerations, and serialization
//! helpers used throughout the dnsmasq DNS implementation.
//!
//! # Contents
//!
//! - **Port numbers** — Standard service ports for DNS and TFTP
//! - **Size constants** — Protocol-defined size limits (label, name, packet, address sizes)
//! - **Response codes** — [`Rcode`] enum and raw `NOERROR`..`REFUSED` constants
//! - **Operation codes** — `QUERY` standard query opcode
//! - **Class codes** — [`DnsClass`] enum and raw `C_IN`..`C_ANY` constants
//! - **Resource record types** — [`RrType`] enum (36 variants) and raw `T_A`..`T_CAA` constants
//! - **EDNS0 option codes** — `EDNS0_OPTION_*` constants per RFC 6891 / RFC 7871
//! - **Extended DNS Error codes** — [`EdeCode`] enum and raw `EDE_*` constants per RFC 8914
//! - **Header flag masks** — `HB3_*` / `HB4_*` bit masks for DNS header flag manipulation
//! - **Header accessors** — [`opcode`], [`set_opcode`], [`rcode`], [`set_rcode`] functions
//! - **Wire-format helpers** — [`get_u16`], [`get_u32`], [`put_u16`], [`put_u32`] for network
//!   byte order conversion with bounds checking
//! - **Buffer validation** — [`check_len`] safe bounds checking
//! - **Name encoding** — [`NAME_ESCAPE`] escape character for presentation format
//!
//! # Design Decisions
//!
//! All constants are provided as both typed enums (for idiomatic Rust code) and raw numeric
//! constants (for compatibility with C-style wire-format manipulation). This dual representation
//! allows callers to choose type safety or raw integer flexibility as appropriate.
//!
//! # No Feature Gates
//!
//! This module is always available — it has no conditional compilation. Every DNS module depends
//! on these foundational definitions.
//!
//! # RFC Compliance
//!
//! - RFC 1035: Domain Names — Implementation and Specification (base DNS protocol)
//! - RFC 2929: Domain Name System (DNS) IANA Considerations
//! - RFC 6891: Extension Mechanisms for DNS (EDNS0)
//! - RFC 7871: Client Subnet in DNS Queries (ECS)
//! - RFC 8914: Extended DNS Errors (EDE)

use core::fmt;

// ============================================================================
// Port Number Constants
// ============================================================================

/// DNS protocol standard port (UDP and TCP) per RFC 1035 Section 4.2.
pub const NAMESERVER_PORT: u16 = 53;

/// TFTP protocol standard port per RFC 1350.
pub const TFTP_PORT: u16 = 69;

/// First non-privileged port number (ports 1–1023 require root privileges).
pub const MIN_PORT: u16 = 1024;

/// Maximum valid port number (16-bit unsigned integer limit).
pub const MAX_PORT: u16 = 65535;

// ============================================================================
// DNS Protocol Size Constants
// ============================================================================

/// IPv6 address size in bytes (128 bits = 16 bytes).
pub const IN6ADDRSZ: usize = 16;

/// IPv4 address size in bytes (32 bits = 4 bytes).
pub const INADDRSZ: usize = 4;

/// Default maximum DNS UDP packet size per RFC 1035 (512 bytes without EDNS0).
pub const PACKETSZ: usize = 512;

/// Maximum domain name length in presentation format (RFC 1035: 255 octets wire + labels + null).
pub const MAXDNAME: usize = 1025;

/// Fixed size of RR metadata: name pointer (2) + type (2) + class (2) + TTL (4) = 10 bytes.
///
/// Note: this does not include the RDLENGTH field itself; the canonical RR fixed overhead
/// used in dnsmasq is 10 bytes encompassing the type/class/TTL/rdlength fields after the
/// compressed owner name pointer.
pub const RRFIXEDSZ: usize = 10;

/// Maximum length of a single DNS label per RFC 1035 Section 2.3.4 (63 octets).
pub const MAXLABEL: usize = 63;

// ============================================================================
// DNS Response Codes (RCODE) — RFC 1035 Section 4.1.1
// ============================================================================

/// DNS Response Codes per RFC 1035 Section 4.1.1.
///
/// These values occupy the low 4 bits of header byte 4 (hb4). Values above 5 are defined
/// by later RFCs but dnsmasq only uses the original set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Rcode {
    /// No error condition — query was successful.
    NoError = 0,
    /// Format error — server unable to interpret query due to format problem.
    FormErr = 1,
    /// Server failure — server unable to process query due to internal problem.
    ServFail = 2,
    /// Name Error (NXDOMAIN) — the queried domain name does not exist.
    NxDomain = 3,
    /// Not Implemented — server does not support the requested query type.
    NotImp = 4,
    /// Refused — server refuses to perform the operation for policy reasons.
    Refused = 5,
}

impl Rcode {
    /// Convert a raw u8 value to an `Rcode`, returning `None` for unknown codes.
    #[inline]
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
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

impl TryFrom<u8> for Rcode {
    type Error = u8;

    #[inline]
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::from_u8(value).ok_or(value)
    }
}

impl fmt::Display for Rcode {
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

// Raw RCODE constants for C-style compatibility.
/// No error condition (RCODE 0).
pub const NOERROR: u8 = 0;
/// Format error (RCODE 1).
pub const FORMERR: u8 = 1;
/// Server failure (RCODE 2).
pub const SERVFAIL: u8 = 2;
/// Non-existent domain (RCODE 3).
pub const NXDOMAIN: u8 = 3;
/// Not implemented (RCODE 4).
pub const NOTIMP: u8 = 4;
/// Query refused (RCODE 5).
pub const REFUSED: u8 = 5;

// ============================================================================
// DNS Operation Codes (OPCODE) — RFC 1035 Section 4.1.1
// ============================================================================

/// Standard query (QUERY) — the default and most common DNS operation (opcode 0).
pub const QUERY: u8 = 0;

// ============================================================================
// DNS Class Codes — RFC 1035 Section 3.2.4
// ============================================================================

/// DNS Class Codes per RFC 1035 Section 3.2.4.
///
/// Class codes identify the protocol family or namespace for DNS queries and resource records.
/// The Internet class (`In`) is used for nearly all modern DNS queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DnsClass {
    /// Internet class (IN) — the standard class for Internet IP addresses.
    In = 1,
    /// Chaos class — originally for MIT's Chaosnet, now rarely used.
    Chaos = 3,
    /// Hesiod class — used by MIT's Hesiod information service.
    Hesiod = 4,
    /// Wildcard class (ANY) — matches any class (used in queries only, not in RRs).
    Any = 255,
}

impl DnsClass {
    /// Convert a raw u16 value to a `DnsClass`, returning `None` for unknown classes.
    #[inline]
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::In),
            3 => Some(Self::Chaos),
            4 => Some(Self::Hesiod),
            255 => Some(Self::Any),
            _ => None,
        }
    }
}

impl TryFrom<u16> for DnsClass {
    type Error = u16;

    #[inline]
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Self::from_u16(value).ok_or(value)
    }
}

impl fmt::Display for DnsClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::In => write!(f, "IN"),
            Self::Chaos => write!(f, "CH"),
            Self::Hesiod => write!(f, "HS"),
            Self::Any => write!(f, "ANY"),
        }
    }
}

// Raw class constants for C-style compatibility.
/// Internet class (1).
pub const C_IN: u16 = 1;
/// Chaos class (3).
pub const C_CHAOS: u16 = 3;
/// Hesiod class (4).
pub const C_HESIOD: u16 = 4;
/// Wildcard class (255).
pub const C_ANY: u16 = 255;

// ============================================================================
// DNS Resource Record Types — RFC 1035 and subsequent RFCs
// ============================================================================

/// DNS Resource Record Types per RFC 1035 and subsequent RFCs.
///
/// This enum covers all RR types used by dnsmasq for DNS forwarding, caching, DNSSEC
/// validation, and authoritative serving. Each variant's discriminant matches the IANA-
/// assigned type code value exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum RrType {
    /// A record — IPv4 host address (RFC 1035).
    A = 1,
    /// NS record — authoritative name server (RFC 1035).
    Ns = 2,
    /// MD record — mail destination (obsolete, RFC 1035).
    Md = 3,
    /// MF record — mail forwarder (obsolete, RFC 1035).
    Mf = 4,
    /// CNAME record — canonical name for an alias (RFC 1035).
    Cname = 5,
    /// SOA record — start of authority zone record (RFC 1035).
    Soa = 6,
    /// MB record — mailbox domain name (experimental, RFC 1035).
    Mb = 7,
    /// MG record — mail group member (experimental, RFC 1035).
    Mg = 8,
    /// MR record — mail rename domain name (experimental, RFC 1035).
    Mr = 9,
    /// PTR record — pointer for reverse DNS lookups (RFC 1035).
    Ptr = 12,
    /// MINFO record — mailbox information (experimental, RFC 1035).
    Minfo = 14,
    /// MX record — mail exchange (RFC 1035).
    Mx = 15,
    /// TXT record — text strings (RFC 1035).
    Txt = 16,
    /// RP record — responsible person (RFC 1183).
    Rp = 17,
    /// AFSDB record — AFS database location (RFC 1183).
    Afsdb = 18,
    /// RT record — route through (RFC 1183).
    Rt = 21,
    /// SIG record — security signature (RFC 2535, obsoleted by RRSIG).
    Sig = 24,
    /// PX record — pointer to X.400/RFC 822 mapping (RFC 2163).
    Px = 26,
    /// AAAA record — IPv6 host address (RFC 3596).
    Aaaa = 28,
    /// NXT record — next domain (obsolete DNSSEC, RFC 2535).
    Nxt = 30,
    /// SRV record — service location (RFC 2782).
    Srv = 33,
    /// NAPTR record — naming authority pointer (RFC 2915).
    Naptr = 35,
    /// KX record — key exchange delegation (RFC 2230).
    Kx = 36,
    /// DNAME record — delegation name (RFC 6672).
    Dname = 39,
    /// OPT pseudo-record — EDNS0 option (RFC 6891, not a true RR type).
    Opt = 41,
    /// DS record — delegation signer for DNSSEC chain of trust (RFC 4034).
    Ds = 43,
    /// RRSIG record — DNSSEC signature (RFC 4034).
    Rrsig = 46,
    /// NSEC record — authenticated denial of existence (RFC 4034).
    Nsec = 47,
    /// DNSKEY record — DNS public key for DNSSEC (RFC 4034).
    Dnskey = 48,
    /// NSEC3 record — hashed authenticated denial (RFC 5155).
    Nsec3 = 50,
    /// TKEY record — transaction key (RFC 2930).
    Tkey = 249,
    /// TSIG record — transaction signature (RFC 2845).
    Tsig = 250,
    /// AXFR query type — zone transfer request (RFC 1035, query type only).
    Axfr = 252,
    /// MAILB query type — mailbox-related records (RFC 1035, query type only).
    Mailb = 253,
    /// ANY query type — request for all records (RFC 1035, query type only).
    Any = 255,
    /// CAA record — certification authority authorization (RFC 6844).
    Caa = 257,
}

impl RrType {
    /// Convert a raw u16 value to an `RrType`, returning `None` for unrecognized types.
    ///
    /// This is the primary method for parsing RR type codes from DNS wire format. Only types
    /// actually used by dnsmasq are recognized; unknown type codes return `None`.
    #[inline]
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::A),
            2 => Some(Self::Ns),
            3 => Some(Self::Md),
            4 => Some(Self::Mf),
            5 => Some(Self::Cname),
            6 => Some(Self::Soa),
            7 => Some(Self::Mb),
            8 => Some(Self::Mg),
            9 => Some(Self::Mr),
            12 => Some(Self::Ptr),
            14 => Some(Self::Minfo),
            15 => Some(Self::Mx),
            16 => Some(Self::Txt),
            17 => Some(Self::Rp),
            18 => Some(Self::Afsdb),
            21 => Some(Self::Rt),
            24 => Some(Self::Sig),
            26 => Some(Self::Px),
            28 => Some(Self::Aaaa),
            30 => Some(Self::Nxt),
            33 => Some(Self::Srv),
            35 => Some(Self::Naptr),
            36 => Some(Self::Kx),
            39 => Some(Self::Dname),
            41 => Some(Self::Opt),
            43 => Some(Self::Ds),
            46 => Some(Self::Rrsig),
            47 => Some(Self::Nsec),
            48 => Some(Self::Dnskey),
            50 => Some(Self::Nsec3),
            249 => Some(Self::Tkey),
            250 => Some(Self::Tsig),
            252 => Some(Self::Axfr),
            253 => Some(Self::Mailb),
            255 => Some(Self::Any),
            257 => Some(Self::Caa),
            _ => None,
        }
    }

    /// Return the IANA-assigned numeric type code.
    #[inline]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

impl TryFrom<u16> for RrType {
    type Error = u16;

    #[inline]
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Self::from_u16(value).ok_or(value)
    }
}

impl fmt::Display for RrType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::A => write!(f, "A"),
            Self::Ns => write!(f, "NS"),
            Self::Md => write!(f, "MD"),
            Self::Mf => write!(f, "MF"),
            Self::Cname => write!(f, "CNAME"),
            Self::Soa => write!(f, "SOA"),
            Self::Mb => write!(f, "MB"),
            Self::Mg => write!(f, "MG"),
            Self::Mr => write!(f, "MR"),
            Self::Ptr => write!(f, "PTR"),
            Self::Minfo => write!(f, "MINFO"),
            Self::Mx => write!(f, "MX"),
            Self::Txt => write!(f, "TXT"),
            Self::Rp => write!(f, "RP"),
            Self::Afsdb => write!(f, "AFSDB"),
            Self::Rt => write!(f, "RT"),
            Self::Sig => write!(f, "SIG"),
            Self::Px => write!(f, "PX"),
            Self::Aaaa => write!(f, "AAAA"),
            Self::Nxt => write!(f, "NXT"),
            Self::Srv => write!(f, "SRV"),
            Self::Naptr => write!(f, "NAPTR"),
            Self::Kx => write!(f, "KX"),
            Self::Dname => write!(f, "DNAME"),
            Self::Opt => write!(f, "OPT"),
            Self::Ds => write!(f, "DS"),
            Self::Rrsig => write!(f, "RRSIG"),
            Self::Nsec => write!(f, "NSEC"),
            Self::Dnskey => write!(f, "DNSKEY"),
            Self::Nsec3 => write!(f, "NSEC3"),
            Self::Tkey => write!(f, "TKEY"),
            Self::Tsig => write!(f, "TSIG"),
            Self::Axfr => write!(f, "AXFR"),
            Self::Mailb => write!(f, "MAILB"),
            Self::Any => write!(f, "ANY"),
            Self::Caa => write!(f, "CAA"),
        }
    }
}

// Raw T_* constants matching the C source exactly.
/// A record — IPv4 host address (type 1).
pub const T_A: u16 = 1;
/// NS record — authoritative name server (type 2).
pub const T_NS: u16 = 2;
/// MD record — mail destination (type 3, obsolete).
pub const T_MD: u16 = 3;
/// MF record — mail forwarder (type 4, obsolete).
pub const T_MF: u16 = 4;
/// CNAME record — canonical name (type 5).
pub const T_CNAME: u16 = 5;
/// SOA record — start of authority (type 6).
pub const T_SOA: u16 = 6;
/// MB record — mailbox domain (type 7, experimental).
pub const T_MB: u16 = 7;
/// MG record — mail group member (type 8, experimental).
pub const T_MG: u16 = 8;
/// MR record — mail rename domain (type 9, experimental).
pub const T_MR: u16 = 9;
/// PTR record — pointer for reverse DNS (type 12).
pub const T_PTR: u16 = 12;
/// MINFO record — mailbox information (type 14, experimental).
pub const T_MINFO: u16 = 14;
/// MX record — mail exchange (type 15).
pub const T_MX: u16 = 15;
/// TXT record — text strings (type 16).
pub const T_TXT: u16 = 16;
/// RP record — responsible person (type 17).
pub const T_RP: u16 = 17;
/// AFSDB record — AFS database location (type 18).
pub const T_AFSDB: u16 = 18;
/// RT record — route through (type 21).
pub const T_RT: u16 = 21;
/// SIG record — security signature (type 24, obsoleted by RRSIG).
pub const T_SIG: u16 = 24;
/// PX record — pointer to X.400 mapping (type 26).
pub const T_PX: u16 = 26;
/// AAAA record — IPv6 host address (type 28).
pub const T_AAAA: u16 = 28;
/// NXT record — next domain (type 30, obsolete DNSSEC).
pub const T_NXT: u16 = 30;
/// SRV record — service location (type 33).
pub const T_SRV: u16 = 33;
/// NAPTR record — naming authority pointer (type 35).
pub const T_NAPTR: u16 = 35;
/// KX record — key exchange delegation (type 36).
pub const T_KX: u16 = 36;
/// DNAME record — delegation name (type 39).
pub const T_DNAME: u16 = 39;
/// OPT pseudo-record — EDNS0 option (type 41).
pub const T_OPT: u16 = 41;
/// DS record — delegation signer for DNSSEC (type 43).
pub const T_DS: u16 = 43;
/// RRSIG record — DNSSEC signature (type 46).
pub const T_RRSIG: u16 = 46;
/// NSEC record — next secure record (type 47).
pub const T_NSEC: u16 = 47;
/// DNSKEY record — DNS public key for DNSSEC (type 48).
pub const T_DNSKEY: u16 = 48;
/// NSEC3 record — hashed authenticated denial (type 50).
pub const T_NSEC3: u16 = 50;
/// TKEY record — transaction key (type 249).
pub const T_TKEY: u16 = 249;
/// TSIG record — transaction signature (type 250).
pub const T_TSIG: u16 = 250;
/// AXFR query type — zone transfer request (type 252).
pub const T_AXFR: u16 = 252;
/// MAILB query type — mailbox-related records (type 253).
pub const T_MAILB: u16 = 253;
/// ANY query type — request for all records (type 255).
pub const T_ANY: u16 = 255;
/// CAA record — certification authority authorization (type 257).
pub const T_CAA: u16 = 257;

// ============================================================================
// EDNS0 Option Codes — RFC 6891 / RFC 7871 / RFC 8914
// ============================================================================

/// EDNS0 MAC address option — dyndns.org temporary assignment (private use range).
pub const EDNS0_OPTION_MAC: u16 = 65001;
/// EDNS0 Client Subnet option — provides client IP prefix for geo-aware responses (RFC 7871).
pub const EDNS0_OPTION_CLIENT_SUBNET: u16 = 8;
/// EDNS0 Extended DNS Error option — detailed error information (RFC 8914).
pub const EDNS0_OPTION_EDE: u16 = 15;
/// EDNS0 Nominum device ID option — device identification (Nominum private use).
pub const EDNS0_OPTION_NOMDEVICEID: u16 = 65073;
/// EDNS0 Nominum CPE ID option — customer premises equipment identification (Nominum private use).
pub const EDNS0_OPTION_NOMCPEID: u16 = 65074;
/// EDNS0 Cisco Umbrella option — Umbrella security platform integration (Cisco private use).
pub const EDNS0_OPTION_UMBRELLA: u16 = 20292;

// ============================================================================
// Extended DNS Error (EDE) Codes — RFC 8914
// ============================================================================

/// Extended DNS Error (EDE) Codes per RFC 8914.
///
/// EDE codes provide detailed diagnostic information about DNS resolution failures,
/// particularly for DNSSEC validation errors. They are carried in the EDNS0 EDE option
/// (option code 15). The `Unset` variant (-1) is a dnsmasq-internal sentinel not
/// transmitted on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i16)]
pub enum EdeCode {
    /// Internal: No extended DNS error available (dnsmasq-specific, not sent on wire).
    Unset = -1,
    /// Other error — general catch-all for unspecified errors (code 0).
    Other = 0,
    /// Unsupported DNSKEY algorithm — DNSSEC validation failed due to unknown algorithm (code 1).
    UnsupDnskey = 1,
    /// Unsupported DS digest type — DS record uses unsupported hash algorithm (code 2).
    UnsupDs = 2,
    /// Stale answer — resolver returning cached data past TTL expiration (code 3).
    Stale = 3,
    /// Forged answer — response appears to be fake or manipulated (code 4).
    Forged = 4,
    /// DNSSEC indeterminate — unable to determine DNSSEC validation status (code 5).
    DnssecInd = 5,
    /// DNSSEC bogus — DNSSEC validation conclusively failed (code 6).
    DnssecBogus = 6,
    /// Signature expired — RRSIG signature past expiration time (code 7).
    SigExp = 7,
    /// Signature not yet valid — RRSIG signature before inception time (code 8).
    SigNyv = 8,
    /// DNSKEY missing — no DNSKEY record found for validation (code 9).
    NoDnskey = 9,
    /// RRSIGs missing — expected RRSIG records not present (code 10).
    NoRrsig = 10,
    /// No zone key bit set — DNSKEY lacks zone signing key flag (code 11).
    NoZonekey = 11,
    /// NSEC missing — expected NSEC record not present (code 12).
    NoNsec = 12,
    /// Cached error — resolver returning cached error response (code 13).
    CachedErr = 13,
    /// Not ready — server not ready to answer query (code 14).
    NotReady = 14,
    /// Blocked — query blocked by policy (code 15).
    Blocked = 15,
    /// Censored — answer censored by policy (code 16).
    Censored = 16,
    /// Filtered — query filtered by policy (code 17).
    Filtered = 17,
    /// Prohibited — query prohibited by policy (code 18).
    Prohibited = 18,
    /// Stale NXDOMAIN — stale NXDOMAIN answer returned (code 19).
    StaleNxd = 19,
    /// Not authoritative — server is not authoritative for zone (code 20).
    NotAuth = 20,
    /// Not supported — query type not supported (code 21).
    NotSup = 21,
    /// No reachable authority — unable to reach authoritative servers (code 22).
    NoAuth = 22,
    /// Network error — network error prevented resolution (code 23).
    NetErr = 23,
    /// Invalid data — response data invalid or malformed (code 24).
    InvalidData = 24,
    /// Signature expired before valid — RRSIG expiration before inception (code 25).
    SigExpBeforeValid = 25,
    /// Too early — response generated before acceptable time (code 26).
    TooEarly = 26,
    /// Unsupported NSEC3 iterations — NSEC3 iterations exceed policy limit (code 27).
    UnsNs3Iter = 27,
    /// Unable to conform to policy — policy requirements cannot be satisfied (code 28).
    UnablePolicy = 28,
    /// Synthesized — answer was synthesized by resolver (code 29).
    Synthesized = 29,
}

impl EdeCode {
    /// Convert a raw i16 value to an `EdeCode`, returning `None` for unrecognized codes.
    #[inline]
    pub fn from_i16(value: i16) -> Option<Self> {
        match value {
            -1 => Some(Self::Unset),
            0 => Some(Self::Other),
            1 => Some(Self::UnsupDnskey),
            2 => Some(Self::UnsupDs),
            3 => Some(Self::Stale),
            4 => Some(Self::Forged),
            5 => Some(Self::DnssecInd),
            6 => Some(Self::DnssecBogus),
            7 => Some(Self::SigExp),
            8 => Some(Self::SigNyv),
            9 => Some(Self::NoDnskey),
            10 => Some(Self::NoRrsig),
            11 => Some(Self::NoZonekey),
            12 => Some(Self::NoNsec),
            13 => Some(Self::CachedErr),
            14 => Some(Self::NotReady),
            15 => Some(Self::Blocked),
            16 => Some(Self::Censored),
            17 => Some(Self::Filtered),
            18 => Some(Self::Prohibited),
            19 => Some(Self::StaleNxd),
            20 => Some(Self::NotAuth),
            21 => Some(Self::NotSup),
            22 => Some(Self::NoAuth),
            23 => Some(Self::NetErr),
            24 => Some(Self::InvalidData),
            25 => Some(Self::SigExpBeforeValid),
            26 => Some(Self::TooEarly),
            27 => Some(Self::UnsNs3Iter),
            28 => Some(Self::UnablePolicy),
            29 => Some(Self::Synthesized),
            _ => None,
        }
    }

    /// Return the numeric code for this EDE value.
    #[inline]
    pub const fn as_i16(self) -> i16 {
        self as i16
    }
}

impl TryFrom<i16> for EdeCode {
    type Error = i16;

    #[inline]
    fn try_from(value: i16) -> Result<Self, Self::Error> {
        Self::from_i16(value).ok_or(value)
    }
}

impl fmt::Display for EdeCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unset => write!(f, "UNSET"),
            Self::Other => write!(f, "Other"),
            Self::UnsupDnskey => write!(f, "Unsupported DNSKEY Algorithm"),
            Self::UnsupDs => write!(f, "Unsupported DS Digest Type"),
            Self::Stale => write!(f, "Stale Answer"),
            Self::Forged => write!(f, "Forged Answer"),
            Self::DnssecInd => write!(f, "DNSSEC Indeterminate"),
            Self::DnssecBogus => write!(f, "DNSSEC Bogus"),
            Self::SigExp => write!(f, "Signature Expired"),
            Self::SigNyv => write!(f, "Signature Not Yet Valid"),
            Self::NoDnskey => write!(f, "DNSKEY Missing"),
            Self::NoRrsig => write!(f, "RRSIGs Missing"),
            Self::NoZonekey => write!(f, "No Zone Key Bit Set"),
            Self::NoNsec => write!(f, "NSEC Missing"),
            Self::CachedErr => write!(f, "Cached Error"),
            Self::NotReady => write!(f, "Not Ready"),
            Self::Blocked => write!(f, "Blocked"),
            Self::Censored => write!(f, "Censored"),
            Self::Filtered => write!(f, "Filtered"),
            Self::Prohibited => write!(f, "Prohibited"),
            Self::StaleNxd => write!(f, "Stale NXDOMAIN"),
            Self::NotAuth => write!(f, "Not Authoritative"),
            Self::NotSup => write!(f, "Not Supported"),
            Self::NoAuth => write!(f, "No Reachable Authority"),
            Self::NetErr => write!(f, "Network Error"),
            Self::InvalidData => write!(f, "Invalid Data"),
            Self::SigExpBeforeValid => write!(f, "Signature Expired Before Valid"),
            Self::TooEarly => write!(f, "Too Early"),
            Self::UnsNs3Iter => write!(f, "Unsupported NSEC3 Iterations"),
            Self::UnablePolicy => write!(f, "Unable to Conform to Policy"),
            Self::Synthesized => write!(f, "Synthesized"),
        }
    }
}

// Raw EDE_* constants matching the C source exactly.
/// Internal: no EDE available (-1, dnsmasq-specific).
pub const EDE_UNSET: i16 = -1;
/// Other error (code 0).
pub const EDE_OTHER: i16 = 0;
/// Unsupported DNSKEY algorithm (code 1).
pub const EDE_USUPDNSKEY: i16 = 1;
/// Unsupported DS digest type (code 2).
pub const EDE_USUPDS: i16 = 2;
/// Stale answer (code 3).
pub const EDE_STALE: i16 = 3;
/// Forged answer (code 4).
pub const EDE_FORGED: i16 = 4;
/// DNSSEC indeterminate (code 5).
pub const EDE_DNSSEC_IND: i16 = 5;
/// DNSSEC bogus (code 6).
pub const EDE_DNSSEC_BOGUS: i16 = 6;
/// Signature expired (code 7).
pub const EDE_SIG_EXP: i16 = 7;
/// Signature not yet valid (code 8).
pub const EDE_SIG_NYV: i16 = 8;
/// DNSKEY missing (code 9).
pub const EDE_NO_DNSKEY: i16 = 9;
/// RRSIGs missing (code 10).
pub const EDE_NO_RRSIG: i16 = 10;
/// No zone key bit set (code 11).
pub const EDE_NO_ZONEKEY: i16 = 11;
/// NSEC missing (code 12).
pub const EDE_NO_NSEC: i16 = 12;
/// Cached error (code 13).
pub const EDE_CACHED_ERR: i16 = 13;
/// Not ready (code 14).
pub const EDE_NOT_READY: i16 = 14;
/// Blocked by policy (code 15).
pub const EDE_BLOCKED: i16 = 15;
/// Censored by policy (code 16).
pub const EDE_CENSORED: i16 = 16;
/// Filtered by policy (code 17).
pub const EDE_FILTERED: i16 = 17;
/// Prohibited by policy (code 18).
pub const EDE_PROHIBITED: i16 = 18;
/// Stale NXDOMAIN (code 19).
pub const EDE_STALE_NXD: i16 = 19;
/// Not authoritative (code 20).
pub const EDE_NOT_AUTH: i16 = 20;
/// Not supported (code 21).
pub const EDE_NOT_SUP: i16 = 21;
/// No reachable authority (code 22).
pub const EDE_NO_AUTH: i16 = 22;
/// Network error (code 23).
pub const EDE_NETERR: i16 = 23;
/// Invalid data (code 24).
pub const EDE_INVALID_DATA: i16 = 24;
/// Signature expired before valid (code 25).
pub const EDE_SIG_E_B_V: i16 = 25;
/// Too early (code 26).
pub const EDE_TOO_EARLY: i16 = 26;
/// Unsupported NSEC3 iterations (code 27).
pub const EDE_UNS_NS3_ITER: i16 = 27;
/// Unable to conform to policy (code 28).
pub const EDE_UNABLE_POLICY: i16 = 28;
/// Synthesized answer (code 29).
pub const EDE_SYNTHESIZED: i16 = 29;

// ============================================================================
// DNS Header Flag Constants — RFC 1035 Section 4.1.1 / RFC 4035 Section 3.1.6
// ============================================================================
//
// Header byte 3 (hb3) bit layout:
//   Bit 7:     QR       (0 = query, 1 = response)
//   Bits 6–3:  OPCODE   (0 = QUERY, 1 = IQUERY, 2 = STATUS)
//   Bit 2:     AA       (Authoritative Answer)
//   Bit 1:     TC       (TrunCation)
//   Bit 0:     RD       (Recursion Desired)
//
// Header byte 4 (hb4) bit layout:
//   Bit 7:     RA       (Recursion Available)
//   Bit 6:     Z        (Reserved, must be zero)
//   Bit 5:     AD       (Authenticated Data — DNSSEC)
//   Bit 4:     CD       (Checking Disabled — DNSSEC)
//   Bits 3–0:  RCODE    (Response Code)

/// QR flag — Query (0) or Response (1) indicator (hb3, bit 7).
pub const HB3_QR: u8 = 0x80;

/// OPCODE mask — operation code field (hb3, bits 6–3).
pub const HB3_OPCODE: u8 = 0x78;

/// AA flag — Authoritative Answer (hb3, bit 2).
pub const HB3_AA: u8 = 0x04;

/// TC flag — TrunCation, message was truncated (hb3, bit 1).
pub const HB3_TC: u8 = 0x02;

/// RD flag — Recursion Desired, set by query sender (hb3, bit 0).
pub const HB3_RD: u8 = 0x01;

/// RA flag — Recursion Available, set by name server (hb4, bit 7).
pub const HB4_RA: u8 = 0x80;

/// AD flag — Authenticated Data, DNSSEC validation succeeded (hb4, bit 5).
pub const HB4_AD: u8 = 0x20;

/// CD flag — Checking Disabled, client requests no DNSSEC validation (hb4, bit 4).
pub const HB4_CD: u8 = 0x10;

/// RCODE mask — Response Code field (hb4, bits 3–0).
pub const HB4_RCODE: u8 = 0x0f;

// ============================================================================
// DNS Header Accessor Functions (replacing C macros OPCODE/SET_OPCODE/RCODE/SET_RCODE)
// ============================================================================

/// Extract the OPCODE field from DNS header byte 3.
///
/// Replaces the C macro `OPCODE(header)` — masks with [`HB3_OPCODE`] (0x78) and
/// right-shifts by 3 to yield a value in range 0–15.
///
/// # Examples
///
/// ```
/// use dnsmasq::dns::protocol::{opcode, QUERY};
/// let hb3: u8 = 0x01; // RD set, OPCODE = 0 (standard query)
/// assert_eq!(opcode(hb3), QUERY);
/// ```
#[inline]
pub fn opcode(hb3: u8) -> u8 {
    (hb3 & HB3_OPCODE) >> 3
}

/// Set the OPCODE field in DNS header byte 3.
///
/// Replaces the C macro `SET_OPCODE(header, code)`. Clears the existing OPCODE bits,
/// then OR-s in `code` shifted left by 3. All other flags in hb3 (QR, AA, TC, RD) are
/// preserved.
///
/// # Arguments
///
/// * `hb3` — Mutable reference to header byte 3.
/// * `code` — OPCODE value (0–15). Typically [`QUERY`] (0).
///
/// # Examples
///
/// ```
/// use dnsmasq::dns::protocol::{set_opcode, opcode, QUERY};
/// let mut hb3: u8 = 0x81; // QR=1, RD=1
/// set_opcode(&mut hb3, QUERY);
/// assert_eq!(opcode(hb3), QUERY);
/// assert_eq!(hb3 & 0x81, 0x81); // QR and RD preserved
/// ```
#[inline]
pub fn set_opcode(hb3: &mut u8, code: u8) {
    *hb3 = (*hb3 & !HB3_OPCODE) | ((code & 0x0f) << 3);
}

/// Extract the RCODE (response code) field from DNS header byte 4.
///
/// Replaces the C macro `RCODE(header)` — masks with [`HB4_RCODE`] (0x0f) to yield a
/// value in range 0–15. The most common values are defined by [`Rcode`].
///
/// # Examples
///
/// ```
/// use dnsmasq::dns::protocol::{rcode, NOERROR};
/// let hb4: u8 = 0x80; // RA set, RCODE = 0
/// assert_eq!(rcode(hb4), NOERROR);
/// ```
#[inline]
pub fn rcode(hb4: u8) -> u8 {
    hb4 & HB4_RCODE
}

/// Set the RCODE (response code) field in DNS header byte 4.
///
/// Replaces the C macro `SET_RCODE(header, code)`. Clears the existing RCODE bits, then
/// OR-s in the new `code`. All other flags in hb4 (RA, AD, CD) are preserved.
///
/// # Arguments
///
/// * `hb4` — Mutable reference to header byte 4.
/// * `code` — RCODE value (0–15). See [`Rcode`] for named constants.
///
/// # Examples
///
/// ```
/// use dnsmasq::dns::protocol::{set_rcode, rcode, NXDOMAIN};
/// let mut hb4: u8 = 0x80; // RA set
/// set_rcode(&mut hb4, NXDOMAIN);
/// assert_eq!(rcode(hb4), NXDOMAIN);
/// assert_eq!(hb4 & 0x80, 0x80); // RA preserved
/// ```
#[inline]
pub fn set_rcode(hb4: &mut u8, code: u8) {
    *hb4 = (*hb4 & !HB4_RCODE) | (code & HB4_RCODE);
}

// ============================================================================
// Wire-Format Helper Functions (replacing C GETSHORT/GETLONG/PUTSHORT/PUTLONG)
// ============================================================================

/// Read a `u16` from a buffer in network byte order (big-endian) at the given offset.
///
/// Returns `None` if the buffer does not contain at least 2 bytes starting at `offset`.
/// This replaces the C `GETSHORT` macro with safe bounds checking.
///
/// # Examples
///
/// ```
/// use dnsmasq::dns::protocol::get_u16;
/// let buf = [0x00, 0x01, 0x00, 0x1c]; // type=1 (A), type=28 (AAAA)
/// assert_eq!(get_u16(&buf, 0), Some(1));
/// assert_eq!(get_u16(&buf, 2), Some(28));
/// assert_eq!(get_u16(&buf, 3), None); // insufficient space
/// ```
#[inline]
pub fn get_u16(buf: &[u8], offset: usize) -> Option<u16> {
    if offset.checked_add(2).is_none_or(|end| end > buf.len()) {
        return None;
    }
    Some(u16::from_be_bytes([buf[offset], buf[offset + 1]]))
}

/// Read a `u32` from a buffer in network byte order (big-endian) at the given offset.
///
/// Returns `None` if the buffer does not contain at least 4 bytes starting at `offset`.
/// This replaces the C `GETLONG` macro with safe bounds checking.
///
/// # Examples
///
/// ```
/// use dnsmasq::dns::protocol::get_u32;
/// let buf = [0x00, 0x00, 0x0E, 0x10]; // TTL = 3600
/// assert_eq!(get_u32(&buf, 0), Some(3600));
/// assert_eq!(get_u32(&buf, 1), None); // insufficient space
/// ```
#[inline]
pub fn get_u32(buf: &[u8], offset: usize) -> Option<u32> {
    if offset.checked_add(4).is_none_or(|end| end > buf.len()) {
        return None;
    }
    Some(u32::from_be_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ]))
}

/// Write a `u16` to a buffer in network byte order (big-endian) at the given offset.
///
/// Returns `true` if the write succeeded, `false` if the buffer does not have at least
/// 2 bytes starting at `offset`. This replaces the C `PUTSHORT` macro.
///
/// # Examples
///
/// ```
/// use dnsmasq::dns::protocol::put_u16;
/// let mut buf = [0u8; 4];
/// assert!(put_u16(&mut buf, 0, 1)); // Write type A
/// assert_eq!(&buf[0..2], &[0x00, 0x01]);
/// assert!(!put_u16(&mut buf, 3, 1)); // Not enough space
/// ```
#[inline]
pub fn put_u16(buf: &mut [u8], offset: usize, val: u16) -> bool {
    if offset.checked_add(2).is_none_or(|end| end > buf.len()) {
        return false;
    }
    buf[offset..offset + 2].copy_from_slice(&val.to_be_bytes());
    true
}

/// Write a `u32` to a buffer in network byte order (big-endian) at the given offset.
///
/// Returns `true` if the write succeeded, `false` if the buffer does not have at least
/// 4 bytes starting at `offset`. This replaces the C `PUTLONG` macro.
///
/// # Examples
///
/// ```
/// use dnsmasq::dns::protocol::put_u32;
/// let mut buf = [0u8; 8];
/// assert!(put_u32(&mut buf, 0, 3600)); // Write TTL
/// assert_eq!(&buf[0..4], &[0x00, 0x00, 0x0E, 0x10]);
/// assert!(!put_u32(&mut buf, 5, 0)); // Not enough space
/// ```
#[inline]
pub fn put_u32(buf: &mut [u8], offset: usize, val: u32) -> bool {
    if offset.checked_add(4).is_none_or(|end| end > buf.len()) {
        return false;
    }
    buf[offset..offset + 4].copy_from_slice(&val.to_be_bytes());
    true
}

// ============================================================================
// Buffer Validation (replacing C CHECK_LEN / ADD_RDLEN macros)
// ============================================================================

/// Check if a buffer has space for `len` bytes starting at `offset`.
///
/// Returns `true` if `offset + len <= buf_len`, guarding against integer overflow.
/// This replaces the C `CHECK_LEN` macro with safe Rust arithmetic.
///
/// # Examples
///
/// ```
/// use dnsmasq::dns::protocol::check_len;
/// assert!(check_len(512, 0, 12));      // 12-byte header fits in 512-byte packet
/// assert!(!check_len(512, 510, 4));     // 4 bytes at offset 510 exceeds 512
/// assert!(!check_len(10, usize::MAX, 1)); // overflow protection
/// ```
#[inline]
pub fn check_len(buf_len: usize, offset: usize, len: usize) -> bool {
    offset.checked_add(len).is_some_and(|end| end <= buf_len)
}

// ============================================================================
// Name Encoding Constants
// ============================================================================

/// Escape character for DNS name presentation format encoding.
///
/// Used in dnsmasq's internal representation of domain names to encode non-printable or
/// special characters as a two-byte sequence: `[NAME_ESCAPE, original_char + 1]`. Adding 1
/// to the original character prevents embedded null bytes in C-compatible strings while
/// preserving all possible byte values.
///
/// Value 1 (SOH control character) is chosen because it is non-printable, non-null, and
/// not the dot (`.`) label separator.
pub const NAME_ESCAPE: u8 = 1;

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Port and Size Constants ----

    #[test]
    fn test_port_constants() {
        assert_eq!(NAMESERVER_PORT, 53);
        assert_eq!(TFTP_PORT, 69);
        assert_eq!(MIN_PORT, 1024);
        assert_eq!(MAX_PORT, 65535);
    }

    #[test]
    fn test_size_constants() {
        assert_eq!(IN6ADDRSZ, 16);
        assert_eq!(INADDRSZ, 4);
        assert_eq!(PACKETSZ, 512);
        assert_eq!(MAXDNAME, 1025);
        assert_eq!(RRFIXEDSZ, 10);
        assert_eq!(MAXLABEL, 63);
    }

    // ---- Rcode Enum and Constants ----

    #[test]
    fn test_rcode_enum_values() {
        assert_eq!(Rcode::NoError as u8, 0);
        assert_eq!(Rcode::FormErr as u8, 1);
        assert_eq!(Rcode::ServFail as u8, 2);
        assert_eq!(Rcode::NxDomain as u8, 3);
        assert_eq!(Rcode::NotImp as u8, 4);
        assert_eq!(Rcode::Refused as u8, 5);
    }

    #[test]
    fn test_rcode_raw_constants_match_enum() {
        assert_eq!(NOERROR, Rcode::NoError as u8);
        assert_eq!(FORMERR, Rcode::FormErr as u8);
        assert_eq!(SERVFAIL, Rcode::ServFail as u8);
        assert_eq!(NXDOMAIN, Rcode::NxDomain as u8);
        assert_eq!(NOTIMP, Rcode::NotImp as u8);
        assert_eq!(REFUSED, Rcode::Refused as u8);
    }

    #[test]
    fn test_rcode_try_from() {
        assert_eq!(Rcode::try_from(0u8), Ok(Rcode::NoError));
        assert_eq!(Rcode::try_from(3u8), Ok(Rcode::NxDomain));
        assert_eq!(Rcode::try_from(5u8), Ok(Rcode::Refused));
        assert_eq!(Rcode::try_from(6u8), Err(6u8));
        assert_eq!(Rcode::try_from(255u8), Err(255u8));
    }

    #[test]
    fn test_rcode_display() {
        assert_eq!(format!("{}", Rcode::NoError), "NOERROR");
        assert_eq!(format!("{}", Rcode::NxDomain), "NXDOMAIN");
        assert_eq!(format!("{}", Rcode::ServFail), "SERVFAIL");
    }

    // ---- Opcode Constant ----

    #[test]
    fn test_query_opcode() {
        assert_eq!(QUERY, 0);
    }

    // ---- DnsClass Enum and Constants ----

    #[test]
    fn test_dns_class_enum_values() {
        assert_eq!(DnsClass::In as u16, 1);
        assert_eq!(DnsClass::Chaos as u16, 3);
        assert_eq!(DnsClass::Hesiod as u16, 4);
        assert_eq!(DnsClass::Any as u16, 255);
    }

    #[test]
    fn test_dns_class_raw_constants_match_enum() {
        assert_eq!(C_IN, DnsClass::In as u16);
        assert_eq!(C_CHAOS, DnsClass::Chaos as u16);
        assert_eq!(C_HESIOD, DnsClass::Hesiod as u16);
        assert_eq!(C_ANY, DnsClass::Any as u16);
    }

    #[test]
    fn test_dns_class_try_from() {
        assert_eq!(DnsClass::try_from(1u16), Ok(DnsClass::In));
        assert_eq!(DnsClass::try_from(3u16), Ok(DnsClass::Chaos));
        assert_eq!(DnsClass::try_from(4u16), Ok(DnsClass::Hesiod));
        assert_eq!(DnsClass::try_from(255u16), Ok(DnsClass::Any));
        assert_eq!(DnsClass::try_from(2u16), Err(2u16));
        assert_eq!(DnsClass::try_from(0u16), Err(0u16));
    }

    #[test]
    fn test_dns_class_display() {
        assert_eq!(format!("{}", DnsClass::In), "IN");
        assert_eq!(format!("{}", DnsClass::Chaos), "CH");
        assert_eq!(format!("{}", DnsClass::Hesiod), "HS");
        assert_eq!(format!("{}", DnsClass::Any), "ANY");
    }

    // ---- RrType Enum and Constants ----

    #[test]
    fn test_rrtype_enum_discriminants() {
        assert_eq!(RrType::A as u16, 1);
        assert_eq!(RrType::Ns as u16, 2);
        assert_eq!(RrType::Md as u16, 3);
        assert_eq!(RrType::Mf as u16, 4);
        assert_eq!(RrType::Cname as u16, 5);
        assert_eq!(RrType::Soa as u16, 6);
        assert_eq!(RrType::Mb as u16, 7);
        assert_eq!(RrType::Mg as u16, 8);
        assert_eq!(RrType::Mr as u16, 9);
        assert_eq!(RrType::Ptr as u16, 12);
        assert_eq!(RrType::Minfo as u16, 14);
        assert_eq!(RrType::Mx as u16, 15);
        assert_eq!(RrType::Txt as u16, 16);
        assert_eq!(RrType::Rp as u16, 17);
        assert_eq!(RrType::Afsdb as u16, 18);
        assert_eq!(RrType::Rt as u16, 21);
        assert_eq!(RrType::Sig as u16, 24);
        assert_eq!(RrType::Px as u16, 26);
        assert_eq!(RrType::Aaaa as u16, 28);
        assert_eq!(RrType::Nxt as u16, 30);
        assert_eq!(RrType::Srv as u16, 33);
        assert_eq!(RrType::Naptr as u16, 35);
        assert_eq!(RrType::Kx as u16, 36);
        assert_eq!(RrType::Dname as u16, 39);
        assert_eq!(RrType::Opt as u16, 41);
        assert_eq!(RrType::Ds as u16, 43);
        assert_eq!(RrType::Rrsig as u16, 46);
        assert_eq!(RrType::Nsec as u16, 47);
        assert_eq!(RrType::Dnskey as u16, 48);
        assert_eq!(RrType::Nsec3 as u16, 50);
        assert_eq!(RrType::Tkey as u16, 249);
        assert_eq!(RrType::Tsig as u16, 250);
        assert_eq!(RrType::Axfr as u16, 252);
        assert_eq!(RrType::Mailb as u16, 253);
        assert_eq!(RrType::Any as u16, 255);
        assert_eq!(RrType::Caa as u16, 257);
    }

    #[test]
    fn test_rrtype_raw_constants_match_enum() {
        assert_eq!(T_A, RrType::A as u16);
        assert_eq!(T_NS, RrType::Ns as u16);
        assert_eq!(T_MD, RrType::Md as u16);
        assert_eq!(T_MF, RrType::Mf as u16);
        assert_eq!(T_CNAME, RrType::Cname as u16);
        assert_eq!(T_SOA, RrType::Soa as u16);
        assert_eq!(T_MB, RrType::Mb as u16);
        assert_eq!(T_MG, RrType::Mg as u16);
        assert_eq!(T_MR, RrType::Mr as u16);
        assert_eq!(T_PTR, RrType::Ptr as u16);
        assert_eq!(T_MINFO, RrType::Minfo as u16);
        assert_eq!(T_MX, RrType::Mx as u16);
        assert_eq!(T_TXT, RrType::Txt as u16);
        assert_eq!(T_RP, RrType::Rp as u16);
        assert_eq!(T_AFSDB, RrType::Afsdb as u16);
        assert_eq!(T_RT, RrType::Rt as u16);
        assert_eq!(T_SIG, RrType::Sig as u16);
        assert_eq!(T_PX, RrType::Px as u16);
        assert_eq!(T_AAAA, RrType::Aaaa as u16);
        assert_eq!(T_NXT, RrType::Nxt as u16);
        assert_eq!(T_SRV, RrType::Srv as u16);
        assert_eq!(T_NAPTR, RrType::Naptr as u16);
        assert_eq!(T_KX, RrType::Kx as u16);
        assert_eq!(T_DNAME, RrType::Dname as u16);
        assert_eq!(T_OPT, RrType::Opt as u16);
        assert_eq!(T_DS, RrType::Ds as u16);
        assert_eq!(T_RRSIG, RrType::Rrsig as u16);
        assert_eq!(T_NSEC, RrType::Nsec as u16);
        assert_eq!(T_DNSKEY, RrType::Dnskey as u16);
        assert_eq!(T_NSEC3, RrType::Nsec3 as u16);
        assert_eq!(T_TKEY, RrType::Tkey as u16);
        assert_eq!(T_TSIG, RrType::Tsig as u16);
        assert_eq!(T_AXFR, RrType::Axfr as u16);
        assert_eq!(T_MAILB, RrType::Mailb as u16);
        assert_eq!(T_ANY, RrType::Any as u16);
        assert_eq!(T_CAA, RrType::Caa as u16);
    }

    #[test]
    fn test_rrtype_try_from_all_known() {
        // Exhaustively test all 36 known type codes
        let known: &[(u16, RrType)] = &[
            (1, RrType::A),
            (2, RrType::Ns),
            (3, RrType::Md),
            (4, RrType::Mf),
            (5, RrType::Cname),
            (6, RrType::Soa),
            (7, RrType::Mb),
            (8, RrType::Mg),
            (9, RrType::Mr),
            (12, RrType::Ptr),
            (14, RrType::Minfo),
            (15, RrType::Mx),
            (16, RrType::Txt),
            (17, RrType::Rp),
            (18, RrType::Afsdb),
            (21, RrType::Rt),
            (24, RrType::Sig),
            (26, RrType::Px),
            (28, RrType::Aaaa),
            (30, RrType::Nxt),
            (33, RrType::Srv),
            (35, RrType::Naptr),
            (36, RrType::Kx),
            (39, RrType::Dname),
            (41, RrType::Opt),
            (43, RrType::Ds),
            (46, RrType::Rrsig),
            (47, RrType::Nsec),
            (48, RrType::Dnskey),
            (50, RrType::Nsec3),
            (249, RrType::Tkey),
            (250, RrType::Tsig),
            (252, RrType::Axfr),
            (253, RrType::Mailb),
            (255, RrType::Any),
            (257, RrType::Caa),
        ];
        for &(code, expected) in known {
            assert_eq!(
                RrType::try_from(code),
                Ok(expected),
                "RrType::try_from({code}) should be Ok({expected:?})"
            );
        }
    }

    #[test]
    fn test_rrtype_try_from_unknown() {
        // Test some unknown type codes return Err
        for code in [0, 10, 11, 13, 19, 20, 22, 23, 25, 27, 29, 31, 32, 34, 37, 38, 40, 42, 100, 256, 500, 65535] {
            assert!(
                RrType::try_from(code).is_err(),
                "RrType::try_from({code}) should be Err"
            );
        }
    }

    #[test]
    fn test_rrtype_as_u16() {
        assert_eq!(RrType::A.as_u16(), 1);
        assert_eq!(RrType::Aaaa.as_u16(), 28);
        assert_eq!(RrType::Caa.as_u16(), 257);
    }

    #[test]
    fn test_rrtype_display() {
        assert_eq!(format!("{}", RrType::A), "A");
        assert_eq!(format!("{}", RrType::Ns), "NS");
        assert_eq!(format!("{}", RrType::Cname), "CNAME");
        assert_eq!(format!("{}", RrType::Soa), "SOA");
        assert_eq!(format!("{}", RrType::Ptr), "PTR");
        assert_eq!(format!("{}", RrType::Mx), "MX");
        assert_eq!(format!("{}", RrType::Txt), "TXT");
        assert_eq!(format!("{}", RrType::Aaaa), "AAAA");
        assert_eq!(format!("{}", RrType::Srv), "SRV");
        assert_eq!(format!("{}", RrType::Naptr), "NAPTR");
        assert_eq!(format!("{}", RrType::Dname), "DNAME");
        assert_eq!(format!("{}", RrType::Opt), "OPT");
        assert_eq!(format!("{}", RrType::Ds), "DS");
        assert_eq!(format!("{}", RrType::Rrsig), "RRSIG");
        assert_eq!(format!("{}", RrType::Nsec), "NSEC");
        assert_eq!(format!("{}", RrType::Dnskey), "DNSKEY");
        assert_eq!(format!("{}", RrType::Nsec3), "NSEC3");
        assert_eq!(format!("{}", RrType::Tkey), "TKEY");
        assert_eq!(format!("{}", RrType::Tsig), "TSIG");
        assert_eq!(format!("{}", RrType::Axfr), "AXFR");
        assert_eq!(format!("{}", RrType::Mailb), "MAILB");
        assert_eq!(format!("{}", RrType::Any), "ANY");
        assert_eq!(format!("{}", RrType::Caa), "CAA");
        // Obsolete / experimental types
        assert_eq!(format!("{}", RrType::Md), "MD");
        assert_eq!(format!("{}", RrType::Mf), "MF");
        assert_eq!(format!("{}", RrType::Mb), "MB");
        assert_eq!(format!("{}", RrType::Mg), "MG");
        assert_eq!(format!("{}", RrType::Mr), "MR");
        assert_eq!(format!("{}", RrType::Minfo), "MINFO");
        assert_eq!(format!("{}", RrType::Rp), "RP");
        assert_eq!(format!("{}", RrType::Afsdb), "AFSDB");
        assert_eq!(format!("{}", RrType::Rt), "RT");
        assert_eq!(format!("{}", RrType::Sig), "SIG");
        assert_eq!(format!("{}", RrType::Px), "PX");
        assert_eq!(format!("{}", RrType::Nxt), "NXT");
        assert_eq!(format!("{}", RrType::Kx), "KX");
    }

    // ---- EDNS0 Option Codes ----

    #[test]
    fn test_edns0_option_codes() {
        assert_eq!(EDNS0_OPTION_MAC, 65001);
        assert_eq!(EDNS0_OPTION_CLIENT_SUBNET, 8);
        assert_eq!(EDNS0_OPTION_EDE, 15);
        assert_eq!(EDNS0_OPTION_NOMDEVICEID, 65073);
        assert_eq!(EDNS0_OPTION_NOMCPEID, 65074);
        assert_eq!(EDNS0_OPTION_UMBRELLA, 20292);
    }

    // ---- EdeCode Enum and Constants ----

    #[test]
    fn test_ede_code_enum_values() {
        assert_eq!(EdeCode::Unset as i16, -1);
        assert_eq!(EdeCode::Other as i16, 0);
        assert_eq!(EdeCode::UnsupDnskey as i16, 1);
        assert_eq!(EdeCode::UnsupDs as i16, 2);
        assert_eq!(EdeCode::Stale as i16, 3);
        assert_eq!(EdeCode::Forged as i16, 4);
        assert_eq!(EdeCode::DnssecInd as i16, 5);
        assert_eq!(EdeCode::DnssecBogus as i16, 6);
        assert_eq!(EdeCode::SigExp as i16, 7);
        assert_eq!(EdeCode::SigNyv as i16, 8);
        assert_eq!(EdeCode::NoDnskey as i16, 9);
        assert_eq!(EdeCode::NoRrsig as i16, 10);
        assert_eq!(EdeCode::NoZonekey as i16, 11);
        assert_eq!(EdeCode::NoNsec as i16, 12);
        assert_eq!(EdeCode::CachedErr as i16, 13);
        assert_eq!(EdeCode::NotReady as i16, 14);
        assert_eq!(EdeCode::Blocked as i16, 15);
        assert_eq!(EdeCode::Censored as i16, 16);
        assert_eq!(EdeCode::Filtered as i16, 17);
        assert_eq!(EdeCode::Prohibited as i16, 18);
        assert_eq!(EdeCode::StaleNxd as i16, 19);
        assert_eq!(EdeCode::NotAuth as i16, 20);
        assert_eq!(EdeCode::NotSup as i16, 21);
        assert_eq!(EdeCode::NoAuth as i16, 22);
        assert_eq!(EdeCode::NetErr as i16, 23);
        assert_eq!(EdeCode::InvalidData as i16, 24);
        assert_eq!(EdeCode::SigExpBeforeValid as i16, 25);
        assert_eq!(EdeCode::TooEarly as i16, 26);
        assert_eq!(EdeCode::UnsNs3Iter as i16, 27);
        assert_eq!(EdeCode::UnablePolicy as i16, 28);
        assert_eq!(EdeCode::Synthesized as i16, 29);
    }

    #[test]
    fn test_ede_raw_constants_match_enum() {
        assert_eq!(EDE_UNSET, EdeCode::Unset as i16);
        assert_eq!(EDE_OTHER, EdeCode::Other as i16);
        assert_eq!(EDE_USUPDNSKEY, EdeCode::UnsupDnskey as i16);
        assert_eq!(EDE_USUPDS, EdeCode::UnsupDs as i16);
        assert_eq!(EDE_STALE, EdeCode::Stale as i16);
        assert_eq!(EDE_FORGED, EdeCode::Forged as i16);
        assert_eq!(EDE_DNSSEC_IND, EdeCode::DnssecInd as i16);
        assert_eq!(EDE_DNSSEC_BOGUS, EdeCode::DnssecBogus as i16);
        assert_eq!(EDE_SIG_EXP, EdeCode::SigExp as i16);
        assert_eq!(EDE_SIG_NYV, EdeCode::SigNyv as i16);
        assert_eq!(EDE_NO_DNSKEY, EdeCode::NoDnskey as i16);
        assert_eq!(EDE_NO_RRSIG, EdeCode::NoRrsig as i16);
        assert_eq!(EDE_NO_ZONEKEY, EdeCode::NoZonekey as i16);
        assert_eq!(EDE_NO_NSEC, EdeCode::NoNsec as i16);
        assert_eq!(EDE_CACHED_ERR, EdeCode::CachedErr as i16);
        assert_eq!(EDE_NOT_READY, EdeCode::NotReady as i16);
        assert_eq!(EDE_BLOCKED, EdeCode::Blocked as i16);
        assert_eq!(EDE_CENSORED, EdeCode::Censored as i16);
        assert_eq!(EDE_FILTERED, EdeCode::Filtered as i16);
        assert_eq!(EDE_PROHIBITED, EdeCode::Prohibited as i16);
        assert_eq!(EDE_STALE_NXD, EdeCode::StaleNxd as i16);
        assert_eq!(EDE_NOT_AUTH, EdeCode::NotAuth as i16);
        assert_eq!(EDE_NOT_SUP, EdeCode::NotSup as i16);
        assert_eq!(EDE_NO_AUTH, EdeCode::NoAuth as i16);
        assert_eq!(EDE_NETERR, EdeCode::NetErr as i16);
        assert_eq!(EDE_INVALID_DATA, EdeCode::InvalidData as i16);
        assert_eq!(EDE_SIG_E_B_V, EdeCode::SigExpBeforeValid as i16);
        assert_eq!(EDE_TOO_EARLY, EdeCode::TooEarly as i16);
        assert_eq!(EDE_UNS_NS3_ITER, EdeCode::UnsNs3Iter as i16);
        assert_eq!(EDE_UNABLE_POLICY, EdeCode::UnablePolicy as i16);
        assert_eq!(EDE_SYNTHESIZED, EdeCode::Synthesized as i16);
    }

    #[test]
    fn test_ede_code_try_from() {
        assert_eq!(EdeCode::try_from(-1i16), Ok(EdeCode::Unset));
        assert_eq!(EdeCode::try_from(0i16), Ok(EdeCode::Other));
        assert_eq!(EdeCode::try_from(6i16), Ok(EdeCode::DnssecBogus));
        assert_eq!(EdeCode::try_from(15i16), Ok(EdeCode::Blocked));
        assert_eq!(EdeCode::try_from(29i16), Ok(EdeCode::Synthesized));
        assert_eq!(EdeCode::try_from(-2i16), Err(-2i16));
        assert_eq!(EdeCode::try_from(30i16), Err(30i16));
        assert_eq!(EdeCode::try_from(100i16), Err(100i16));
    }

    #[test]
    fn test_ede_code_as_i16() {
        assert_eq!(EdeCode::Unset.as_i16(), -1);
        assert_eq!(EdeCode::DnssecBogus.as_i16(), 6);
        assert_eq!(EdeCode::Synthesized.as_i16(), 29);
    }

    // ---- Header Flag Constants ----

    #[test]
    fn test_hb3_flags() {
        assert_eq!(HB3_QR, 0x80);
        assert_eq!(HB3_OPCODE, 0x78);
        assert_eq!(HB3_AA, 0x04);
        assert_eq!(HB3_TC, 0x02);
        assert_eq!(HB3_RD, 0x01);
        // Verify non-overlapping bits (QR | OPCODE | AA | TC | RD should cover all 8 bits except unused)
        assert_eq!(HB3_QR | HB3_OPCODE | HB3_AA | HB3_TC | HB3_RD, 0xFF);
    }

    #[test]
    fn test_hb4_flags() {
        assert_eq!(HB4_RA, 0x80);
        assert_eq!(HB4_AD, 0x20);
        assert_eq!(HB4_CD, 0x10);
        assert_eq!(HB4_RCODE, 0x0f);
    }

    // ---- Header Accessor Functions ----

    #[test]
    fn test_opcode_extract() {
        // OPCODE is bits 6–3 of hb3: mask 0x78, shift right by 3
        assert_eq!(opcode(0x00), 0); // All zeros -> QUERY
        assert_eq!(opcode(0x78), 15); // Max OPCODE (all 4 bits set)
        assert_eq!(opcode(0x08), 1); // OPCODE=1 (IQUERY)
        assert_eq!(opcode(0x10), 2); // OPCODE=2 (STATUS)
        assert_eq!(opcode(0x81), 0); // QR=1, RD=1, OPCODE=0
    }

    #[test]
    fn test_set_opcode() {
        let mut hb3: u8 = 0x00;
        set_opcode(&mut hb3, 0);
        assert_eq!(opcode(hb3), 0);

        set_opcode(&mut hb3, 2); // STATUS
        assert_eq!(opcode(hb3), 2);
        assert_eq!(hb3, 0x10);

        // Verify other flags are preserved
        let mut hb3: u8 = 0x85; // QR=1, AA=1, RD=1
        set_opcode(&mut hb3, 3);
        assert_eq!(opcode(hb3), 3);
        assert_eq!(hb3 & HB3_QR, HB3_QR); // QR preserved
        assert_eq!(hb3 & HB3_AA, HB3_AA); // AA preserved
        assert_eq!(hb3 & HB3_RD, HB3_RD); // RD preserved
    }

    #[test]
    fn test_rcode_extract() {
        assert_eq!(rcode(0x00), 0); // NOERROR
        assert_eq!(rcode(0x03), 3); // NXDOMAIN
        assert_eq!(rcode(0x0f), 15); // Max RCODE
        assert_eq!(rcode(0x82), 2); // RA=1, RCODE=2 (SERVFAIL)
    }

    #[test]
    fn test_set_rcode_fn() {
        let mut hb4: u8 = 0x00;
        set_rcode(&mut hb4, NXDOMAIN);
        assert_eq!(rcode(hb4), NXDOMAIN);
        assert_eq!(hb4, 0x03);

        // Verify other flags are preserved
        let mut hb4: u8 = 0xB0; // RA=1, AD=1, CD=1
        set_rcode(&mut hb4, SERVFAIL);
        assert_eq!(rcode(hb4), SERVFAIL);
        assert_eq!(hb4 & HB4_RA, HB4_RA); // RA preserved
        assert_eq!(hb4 & HB4_AD, HB4_AD); // AD preserved
        assert_eq!(hb4 & HB4_CD, HB4_CD); // CD preserved
    }

    // ---- Wire-Format Helper Functions ----

    #[test]
    fn test_get_u16_normal() {
        let buf = [0x00, 0x35]; // 53 in big-endian
        assert_eq!(get_u16(&buf, 0), Some(53));
    }

    #[test]
    fn test_get_u16_offset() {
        let buf = [0xFF, 0x00, 0x01, 0x00, 0x1C]; // padding, type=1, type=28
        assert_eq!(get_u16(&buf, 1), Some(1));
        assert_eq!(get_u16(&buf, 3), Some(28));
    }

    #[test]
    fn test_get_u16_boundary() {
        let buf = [0x01, 0x02];
        assert_eq!(get_u16(&buf, 0), Some(0x0102));
        assert_eq!(get_u16(&buf, 1), None); // Only 1 byte left
    }

    #[test]
    fn test_get_u16_empty() {
        let buf: [u8; 0] = [];
        assert_eq!(get_u16(&buf, 0), None);
    }

    #[test]
    fn test_get_u16_overflow_offset() {
        let buf = [0x00, 0x01];
        assert_eq!(get_u16(&buf, usize::MAX), None);
    }

    #[test]
    fn test_get_u32_normal() {
        let buf = [0x00, 0x00, 0x0E, 0x10]; // 3600 TTL
        assert_eq!(get_u32(&buf, 0), Some(3600));
    }

    #[test]
    fn test_get_u32_max() {
        let buf = [0xFF, 0xFF, 0xFF, 0xFF];
        assert_eq!(get_u32(&buf, 0), Some(u32::MAX));
    }

    #[test]
    fn test_get_u32_boundary() {
        let buf = [0x00, 0x00, 0x00, 0x01];
        assert_eq!(get_u32(&buf, 0), Some(1));
        assert_eq!(get_u32(&buf, 1), None); // Only 3 bytes left
    }

    #[test]
    fn test_get_u32_overflow_offset() {
        let buf = [0x00; 10];
        assert_eq!(get_u32(&buf, usize::MAX), None);
    }

    #[test]
    fn test_put_u16_normal() {
        let mut buf = [0u8; 4];
        assert!(put_u16(&mut buf, 0, 53));
        assert_eq!(&buf[0..2], &[0x00, 0x35]);
    }

    #[test]
    fn test_put_u16_max() {
        let mut buf = [0u8; 2];
        assert!(put_u16(&mut buf, 0, 0xFFFF));
        assert_eq!(&buf, &[0xFF, 0xFF]);
    }

    #[test]
    fn test_put_u16_boundary() {
        let mut buf = [0u8; 3];
        assert!(put_u16(&mut buf, 1, 0x0100));
        assert_eq!(&buf, &[0x00, 0x01, 0x00]);
        assert!(!put_u16(&mut buf, 2, 1)); // Only 1 byte left
    }

    #[test]
    fn test_put_u16_overflow_offset() {
        let mut buf = [0u8; 4];
        assert!(!put_u16(&mut buf, usize::MAX, 0));
    }

    #[test]
    fn test_put_u32_normal() {
        let mut buf = [0u8; 8];
        assert!(put_u32(&mut buf, 0, 3600));
        assert_eq!(&buf[0..4], &[0x00, 0x00, 0x0E, 0x10]);
    }

    #[test]
    fn test_put_u32_max() {
        let mut buf = [0u8; 4];
        assert!(put_u32(&mut buf, 0, u32::MAX));
        assert_eq!(&buf, &[0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_put_u32_boundary() {
        let mut buf = [0u8; 5];
        assert!(put_u32(&mut buf, 1, 256));
        assert_eq!(&buf, &[0x00, 0x00, 0x00, 0x01, 0x00]);
        assert!(!put_u32(&mut buf, 2, 0)); // Only 3 bytes left
    }

    #[test]
    fn test_put_get_roundtrip_u16() {
        let mut buf = [0u8; 10];
        let values: &[u16] = &[0, 1, 53, 255, 1024, 12345, 65535];
        for (i, &v) in values.iter().enumerate() {
            if i * 2 + 2 <= buf.len() {
                assert!(put_u16(&mut buf, i * 2, v));
            }
        }
        for (i, &expected) in values.iter().enumerate() {
            if i * 2 + 2 <= buf.len() {
                assert_eq!(get_u16(&buf, i * 2), Some(expected));
            }
        }
    }

    #[test]
    fn test_put_get_roundtrip_u32() {
        let mut buf = [0u8; 16];
        let values: &[u32] = &[0, 1, 3600, 86400, u32::MAX];
        for (i, &v) in values.iter().enumerate() {
            if i * 4 + 4 <= buf.len() {
                assert!(put_u32(&mut buf, i * 4, v));
            }
        }
        for (i, &expected) in values.iter().enumerate() {
            if i * 4 + 4 <= buf.len() {
                assert_eq!(get_u32(&buf, i * 4), Some(expected));
            }
        }
    }

    // ---- Buffer Validation ----

    #[test]
    fn test_check_len_valid() {
        assert!(check_len(512, 0, 12)); // 12-byte header fits in 512
        assert!(check_len(512, 500, 12)); // Just fits
        assert!(check_len(10, 0, 10)); // Exact fit
        assert!(check_len(10, 10, 0)); // Zero length at end
        assert!(check_len(0, 0, 0)); // Empty buffer, zero length
    }

    #[test]
    fn test_check_len_invalid() {
        assert!(!check_len(512, 510, 4)); // 4 bytes at 510 exceeds 512
        assert!(!check_len(10, 0, 11)); // 11 bytes exceeds 10
        assert!(!check_len(0, 0, 1)); // 1 byte in empty buffer
        assert!(!check_len(10, 11, 0)); // Offset past buffer
    }

    #[test]
    fn test_check_len_overflow_protection() {
        assert!(!check_len(10, usize::MAX, 1)); // Would overflow
        assert!(!check_len(10, 1, usize::MAX)); // Would overflow
        assert!(!check_len(usize::MAX, usize::MAX, 1)); // Would overflow
    }

    // ---- NAME_ESCAPE ----

    #[test]
    fn test_name_escape() {
        assert_eq!(NAME_ESCAPE, 1);
        // Verify it's non-printable, non-null, and not '.'
        assert_ne!(NAME_ESCAPE, 0);
        assert_ne!(NAME_ESCAPE, b'.');
        assert!(NAME_ESCAPE < 0x20); // Non-printable ASCII control character
    }

    // ---- Integration: Header construction simulation ----

    #[test]
    fn test_dns_header_construction() {
        // Simulate building a DNS query header
        let mut packet = [0u8; 12];

        // Transaction ID = 0x1234
        assert!(put_u16(&mut packet, 0, 0x1234));

        // hb3: RD=1, OPCODE=QUERY, QR=0
        let mut hb3: u8 = 0;
        hb3 |= HB3_RD;
        set_opcode(&mut hb3, QUERY);
        packet[2] = hb3;

        // hb4: all zeros for query
        packet[3] = 0;

        // Question count = 1
        assert!(put_u16(&mut packet, 4, 1));

        // Answer, Authority, Additional counts = 0
        assert!(put_u16(&mut packet, 6, 0));
        assert!(put_u16(&mut packet, 8, 0));
        assert!(put_u16(&mut packet, 10, 0));

        // Verify the constructed header
        assert_eq!(get_u16(&packet, 0), Some(0x1234)); // ID
        assert_eq!(opcode(packet[2]), QUERY);
        assert_eq!(packet[2] & HB3_RD, HB3_RD);
        assert_eq!(packet[2] & HB3_QR, 0); // Query, not response
        assert_eq!(rcode(packet[3]), NOERROR);
        assert_eq!(get_u16(&packet, 4), Some(1)); // 1 question
        assert_eq!(get_u16(&packet, 6), Some(0)); // 0 answers

        // Now simulate setting the response
        packet[2] |= HB3_QR; // Mark as response
        packet[2] |= HB3_AA; // Authoritative
        set_rcode(&mut packet[3], NOERROR);
        assert!(put_u16(&mut packet, 6, 1)); // 1 answer

        assert_ne!(packet[2] & HB3_QR, 0); // Is response
        assert_ne!(packet[2] & HB3_AA, 0); // Is authoritative
        assert_eq!(opcode(packet[2]), QUERY); // OPCODE preserved
        assert_eq!(packet[2] & HB3_RD, HB3_RD); // RD preserved
    }

    // ---- Completeness checks ----

    #[test]
    fn test_all_t_constants_count() {
        // Verify we have exactly 36 T_* constants by testing each value
        let all_t: &[u16] = &[
            T_A, T_NS, T_MD, T_MF, T_CNAME, T_SOA, T_MB, T_MG, T_MR,
            T_PTR, T_MINFO, T_MX, T_TXT, T_RP, T_AFSDB, T_RT, T_SIG,
            T_PX, T_AAAA, T_NXT, T_SRV, T_NAPTR, T_KX, T_DNAME, T_OPT,
            T_DS, T_RRSIG, T_NSEC, T_DNSKEY, T_NSEC3, T_TKEY, T_TSIG,
            T_AXFR, T_MAILB, T_ANY, T_CAA,
        ];
        assert_eq!(all_t.len(), 36);
        // Each should successfully convert to RrType
        for &t in all_t {
            assert!(RrType::try_from(t).is_ok(), "T_* constant {t} should map to RrType");
        }
    }

    #[test]
    fn test_all_ede_constants_count() {
        // Verify we have exactly 31 EDE_* constants
        let all_ede: &[i16] = &[
            EDE_UNSET, EDE_OTHER, EDE_USUPDNSKEY, EDE_USUPDS, EDE_STALE,
            EDE_FORGED, EDE_DNSSEC_IND, EDE_DNSSEC_BOGUS, EDE_SIG_EXP,
            EDE_SIG_NYV, EDE_NO_DNSKEY, EDE_NO_RRSIG, EDE_NO_ZONEKEY,
            EDE_NO_NSEC, EDE_CACHED_ERR, EDE_NOT_READY, EDE_BLOCKED,
            EDE_CENSORED, EDE_FILTERED, EDE_PROHIBITED, EDE_STALE_NXD,
            EDE_NOT_AUTH, EDE_NOT_SUP, EDE_NO_AUTH, EDE_NETERR,
            EDE_INVALID_DATA, EDE_SIG_E_B_V, EDE_TOO_EARLY, EDE_UNS_NS3_ITER,
            EDE_UNABLE_POLICY, EDE_SYNTHESIZED,
        ];
        assert_eq!(all_ede.len(), 31);
        // Each should successfully convert to EdeCode
        for &e in all_ede {
            assert!(EdeCode::try_from(e).is_ok(), "EDE_* constant {e} should map to EdeCode");
        }
    }
}

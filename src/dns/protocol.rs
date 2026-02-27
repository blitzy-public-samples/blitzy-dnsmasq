//! DNS wire-format constants derived from `src/dns-protocol.h`.
//!
//! This is a minimal stub that will be replaced by the code generation agent
//! with the complete implementation. It defines the types re-exported by
//! `dns::mod.rs` to allow the module tree to compile.

/// DNS Resource Record Types per RFC 1035 and subsequent RFCs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum RrType {
    /// IPv4 host address (RFC 1035)
    A = 1,
    /// Authoritative name server (RFC 1035)
    NS = 2,
    /// Canonical name alias (RFC 1035)
    CNAME = 5,
    /// Start of authority (RFC 1035)
    SOA = 6,
    /// Pointer for reverse DNS (RFC 1035)
    PTR = 12,
    /// Mail exchange (RFC 1035)
    MX = 15,
    /// Text strings (RFC 1035)
    TXT = 16,
    /// IPv6 host address (RFC 3596)
    AAAA = 28,
    /// Service location (RFC 2782)
    SRV = 33,
    /// OPT pseudo-record for EDNS0 (RFC 6891)
    OPT = 41,
    /// Delegation signer for DNSSEC (RFC 4034)
    DS = 43,
    /// DNSSEC signature (RFC 4034)
    RRSIG = 46,
    /// Next secure record (RFC 4034)
    NSEC = 47,
    /// DNS public key for DNSSEC (RFC 4034)
    DNSKEY = 48,
    /// Hashed authenticated denial (RFC 5155)
    NSEC3 = 50,
    /// NSEC3 parameters (RFC 5155)
    NSEC3PARAM = 51,
    /// Request for all records (RFC 1035, query only)
    ANY = 255,
}

/// DNS Response Codes per RFC 1035 Section 4.1.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Rcode {
    /// No error condition
    NoError = 0,
    /// Format error — server unable to interpret query
    FormErr = 1,
    /// Server failure — unable to process due to server problem
    ServFail = 2,
    /// Non-Existent Domain — the domain name does not exist
    NxDomain = 3,
    /// Not Implemented — server does not support the query type
    NotImp = 4,
    /// Refused — server refuses to perform the operation
    Refused = 5,
}

/// DNS Class Codes per RFC 1035 Section 3.2.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DnsClass {
    /// Internet
    IN = 1,
    /// Chaosnet
    CH = 3,
    /// Hesiod
    HS = 4,
    /// Wildcard (query only)
    ANY = 255,
}

/// Extended DNS Error (EDE) Codes per RFC 8914.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i16)]
pub enum EdeCode {
    /// General catch-all
    Other = 0,
    /// Unsupported DNSKEY algorithm
    UnsupportedDnskeyAlgorithm = 1,
    /// Unsupported DS digest type
    UnsupportedDsDigestType = 2,
    /// Stale answer
    StaleAnswer = 3,
    /// Forged answer
    ForgedAnswer = 4,
    /// DNSSEC indeterminate
    DnssecIndeterminate = 5,
    /// DNSSEC bogus
    DnssecBogus = 6,
    /// Signature expired
    SignatureExpired = 7,
    /// Signature not yet valid
    SignatureNotYetValid = 8,
    /// DNSKEY missing
    DnskeyMissing = 9,
    /// RRSIGs missing
    RrsigsMissing = 10,
    /// No zone key bit set
    NoZoneKeyBitSet = 11,
    /// NSEC missing
    NsecMissing = 12,
    /// Cached error
    CachedError = 13,
    /// Not ready
    NotReady = 14,
    /// Blocked by policy
    Blocked = 15,
    /// Censored by policy
    Censored = 16,
    /// Filtered by policy
    Filtered = 17,
    /// Prohibited by policy
    Prohibited = 18,
}

// Raw T_* constants for C compatibility
pub const T_A: u16 = 1;
pub const T_NS: u16 = 2;
pub const T_CNAME: u16 = 5;
pub const T_SOA: u16 = 6;
pub const T_MX: u16 = 15;
pub const T_TXT: u16 = 16;
pub const T_AAAA: u16 = 28;
pub const T_SRV: u16 = 33;
pub const T_OPT: u16 = 41;
pub const T_DS: u16 = 43;
pub const T_RRSIG: u16 = 46;
pub const T_NSEC: u16 = 47;
pub const T_DNSKEY: u16 = 48;
pub const T_NSEC3: u16 = 50;
pub const C_IN: u16 = 1;
pub const RCODE_NOERROR: u8 = 0;
pub const RCODE_SERVFAIL: u8 = 2;
pub const RCODE_NXDOMAIN: u8 = 3;
pub const RCODE_REFUSED: u8 = 5;

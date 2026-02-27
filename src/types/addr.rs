//! Address type definitions for dnsmasq.
//!
//! This module defines the core address enums that replace the C `union all_addr`
//! and `union mysockaddr` types from the original dnsmasq C codebase.
//!
//! ## Key Transformations
//! - C `union all_addr` → [`AllAddr`] enum with exhaustive pattern matching
//! - C `union mysockaddr` → [`SocketAddress`] enum leveraging `std::net` types
//! - C discriminated union (cname.target + is_name_ptr) → Rust [`CnameTarget`] enum
//! - C raw `struct blockdata *` → Rust `Vec<u8>` for DNSSEC key/digest data
//!
//! ## Design Pattern
//! Uses the **Enum Dispatch** pattern (AAP Section 0.4.3) to replace unsafe C unions
//! with exhaustive Rust enums. Every variant is type-safe and requires exhaustive
//! pattern matching, eliminating undefined behavior from reading the wrong union member.
//!
//! ## Wire Protocol Compatibility
//! The [`RR_IMDATALEN`] constant is preserved for protocol compatibility when deciding
//! whether to inline RR data or use external block storage, even though Rust uses
//! `Vec<u8>` instead of inline data in the union.
//!
//! ## Source
//! - `src/dnsmasq.h` lines 492–533 (`union all_addr`)
//! - `src/dnsmasq.h` lines 732–739 (`union mysockaddr`)
//! - `src/dnsmasq.h` line 535 (`RR_IMDATALEN`)

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

// ---------------------------------------------------------------------------
// CnameTarget enum
// ---------------------------------------------------------------------------

/// Target of a CNAME record, replacing the C discriminated union
/// `cname.target` + `cname.is_name_ptr` from `union all_addr`.
///
/// In the C code, `is_name_ptr == 0` means `target.cache` (a pointer to
/// a cache entry) and `is_name_ptr != 0` means `target.name` (a DNS name string).
///
/// # Source
/// `src/dnsmasq.h` lines 495–502.
#[derive(Debug, Clone)]
pub enum CnameTarget {
    /// Reference to a cache entry by index.
    /// Replaces: `cname.target.cache` (struct crec pointer) when `is_name_ptr == 0`.
    /// The `usize` is an index into the cache, not a raw pointer.
    CacheIndex(usize),

    /// A DNS name string.
    /// Replaces: `cname.target.name` (char pointer) when `is_name_ptr != 0`.
    Name(String),
}

// ---------------------------------------------------------------------------
// AllAddr enum
// ---------------------------------------------------------------------------

/// Unified address type replacing C `union all_addr`.
///
/// In the C codebase, `union all_addr` is a 16-byte union (sized to hold
/// `struct in6_addr`) used throughout the DNS cache and forwarding engine
/// to store different types of address/record data in the same memory.
///
/// The Rust enum provides type safety through exhaustive pattern matching,
/// eliminating the possibility of reading the wrong variant.
///
/// # Source
/// `src/dnsmasq.h` lines 492–533.
#[derive(Debug, Clone)]
pub enum AllAddr {
    /// IPv4 address.
    /// Replaces: `all_addr.addr4` (`struct in_addr`).
    V4(Ipv4Addr),

    /// IPv6 address.
    /// Replaces: `all_addr.addr6` (`struct in6_addr`).
    V6(Ipv6Addr),

    /// CNAME record data with target and unique ID.
    /// Replaces: `all_addr.cname` (discriminated union with cache/name target,
    /// uid, is_name_ptr).
    Cname {
        /// The target of the CNAME — either a cache index or a DNS name.
        target: CnameTarget,
        /// Unique identifier for cache entry matching.
        uid: u32,
    },

    /// DNSSEC key record data (DNSKEY RR).
    /// Replaces: `all_addr.key` with keydata, keylen, flags, keytag, algo.
    /// Feature-gated to `dnssec` since DNSSEC types are only needed when
    /// DNSSEC validation is enabled.
    #[cfg(feature = "dnssec")]
    Key {
        /// The raw key data bytes. Replaces: `struct blockdata *keydata`.
        keydata: Vec<u8>,
        /// Key flags field from DNSKEY RR (RFC 4034 Section 2.1.1).
        flags: u16,
        /// Key tag for efficient RRSIG matching (RFC 4034 Appendix B).
        keytag: u16,
        /// DNSSEC algorithm number (RFC 8624).
        algo: u8,
    },

    /// DNSSEC DS (Delegation Signer) record data.
    /// Replaces: `all_addr.ds` with keydata, keylen, keytag, algo, digest.
    #[cfg(feature = "dnssec")]
    Ds {
        /// The digest data bytes. Replaces: `struct blockdata *keydata`.
        keydata: Vec<u8>,
        /// Key tag identifying the referenced DNSKEY.
        keytag: u16,
        /// DNSSEC algorithm number.
        algo: u8,
        /// Digest type (SHA-1 = 1, SHA-256 = 2, SHA-384 = 4).
        digest: u8,
    },

    /// Logging metadata for DNSSEC-related log entries.
    /// Replaces: `all_addr.log` used by `log_query()` for DNSSEC diagnostics.
    #[cfg(feature = "dnssec")]
    Log {
        /// Key tag of the relevant DNSKEY/DS record.
        keytag: u16,
        /// DNSSEC algorithm number.
        algo: u16,
        /// Digest type.
        digest: u16,
        /// DNS response code (RCODE).
        rcode: u16,
        /// Extended DNS Error code (RFC 8914), -1 if not present.
        ede: i32,
    },

    /// Arbitrary RR record stored in an external block (large records).
    /// Replaces: `all_addr.rrblock` (rrtype, datalen, `struct blockdata *rrdata`).
    ///
    /// NOTE: `RrBlock` and `RrData` are discriminated by the `F_KEYTAG` bit
    /// in cache entry flags (comment from `dnsmasq.h` line 526–527).
    RrBlock {
        /// DNS RR type code.
        rrtype: u16,
        /// Raw record data bytes. Replaces: `struct blockdata *rrdata` + datalen.
        data: Vec<u8>,
    },

    /// Arbitrary RR record small enough to fit inline (small records).
    /// Replaces: `all_addr.rrdata` (`struct datablock` with rrtype, datalen,
    /// `char data[1]`). In C, `data` is a flexible array member occupying the
    /// remaining space in the union.
    RrData {
        /// DNS RR type code.
        rrtype: u16,
        /// Raw record data bytes (also encodes SOA length in negative cache records).
        /// Maximum size in C was `RR_IMDATALEN` =
        /// `sizeof(union all_addr) - offsetof(struct datablock, data)`.
        data: Vec<u8>,
    },
}

impl AllAddr {
    /// Create an `AllAddr` from an IPv4 address.
    #[inline]
    pub fn from_ipv4(addr: Ipv4Addr) -> Self {
        AllAddr::V4(addr)
    }

    /// Create an `AllAddr` from an IPv6 address.
    #[inline]
    pub fn from_ipv6(addr: Ipv6Addr) -> Self {
        AllAddr::V6(addr)
    }

    /// Try to extract an IPv4 address.
    /// Returns `None` if this is not a `V4` variant.
    #[inline]
    pub fn as_ipv4(&self) -> Option<&Ipv4Addr> {
        match self {
            AllAddr::V4(addr) => Some(addr),
            _ => None,
        }
    }

    /// Try to extract an IPv6 address.
    /// Returns `None` if this is not a `V6` variant.
    #[inline]
    pub fn as_ipv6(&self) -> Option<&Ipv6Addr> {
        match self {
            AllAddr::V6(addr) => Some(addr),
            _ => None,
        }
    }

    /// Check if this is an IPv4 address variant.
    #[inline]
    pub fn is_v4(&self) -> bool {
        matches!(self, AllAddr::V4(_))
    }

    /// Check if this is an IPv6 address variant.
    #[inline]
    pub fn is_v6(&self) -> bool {
        matches!(self, AllAddr::V6(_))
    }
}

impl From<Ipv4Addr> for AllAddr {
    #[inline]
    fn from(addr: Ipv4Addr) -> Self {
        AllAddr::V4(addr)
    }
}

impl From<Ipv6Addr> for AllAddr {
    #[inline]
    fn from(addr: Ipv6Addr) -> Self {
        AllAddr::V6(addr)
    }
}

impl fmt::Display for AllAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AllAddr::V4(addr) => write!(f, "{}", addr),
            AllAddr::V6(addr) => write!(f, "{}", addr),
            AllAddr::Cname { uid, .. } => write!(f, "CNAME(uid={})", uid),
            #[cfg(feature = "dnssec")]
            AllAddr::Key { keytag, algo, .. } => {
                write!(f, "KEY(tag={}, algo={})", keytag, algo)
            }
            #[cfg(feature = "dnssec")]
            AllAddr::Ds {
                keytag,
                algo,
                digest,
                ..
            } => {
                write!(f, "DS(tag={}, algo={}, digest={})", keytag, algo, digest)
            }
            #[cfg(feature = "dnssec")]
            AllAddr::Log { rcode, ede, .. } => write!(f, "LOG(rcode={}, ede={})", rcode, ede),
            AllAddr::RrBlock { rrtype, data } => {
                write!(f, "RR(type={}, len={})", rrtype, data.len())
            }
            AllAddr::RrData { rrtype, data } => {
                write!(f, "RR(type={}, len={}, inline)", rrtype, data.len())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// RR_IMDATALEN constant
// ---------------------------------------------------------------------------

/// Maximum inline data length for [`AllAddr::RrData`].
///
/// In C: `#define RR_IMDATALEN (sizeof(union all_addr) - offsetof(struct datablock, data))`
///
/// The C `union all_addr` is 16 bytes (sized to hold `struct in6_addr`).
/// `struct datablock` has: `rrtype` (2 bytes) + `datalen` (1 byte) + `data[1]`.
/// So `offsetof(struct datablock, data) = 3`, giving `RR_IMDATALEN = 16 - 3 = 13` bytes.
///
/// In Rust, we don't need this for memory layout (we use `Vec<u8>`),
/// but it's preserved for protocol compatibility when deciding whether
/// to inline RR data or use external block storage.
pub const RR_IMDATALEN: usize = 13;

// ---------------------------------------------------------------------------
// SocketAddress enum
// ---------------------------------------------------------------------------

/// Socket address type replacing C `union mysockaddr`.
///
/// The C `union mysockaddr` wraps `struct sockaddr`, `struct sockaddr_in`,
/// and `struct sockaddr_in6` into a union large enough to hold any address type.
/// This was necessary in C because `struct sockaddr` alone is too small for IPv6.
///
/// In Rust, we use an enum with `std::net` socket address types, which provides
/// type safety and avoids the need for unsafe casts between address types.
///
/// # Source
/// `src/dnsmasq.h` lines 732–739.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SocketAddress {
    /// IPv4 socket address (address + port).
    /// Replaces: `mysockaddr.in` (`struct sockaddr_in`).
    V4(SocketAddrV4),

    /// IPv6 socket address (address + port + flow info + scope ID).
    /// Replaces: `mysockaddr.in6` (`struct sockaddr_in6`).
    V6(SocketAddrV6),
}

impl SocketAddress {
    /// Get the port number from either address family.
    #[inline]
    pub fn port(&self) -> u16 {
        match self {
            SocketAddress::V4(addr) => addr.port(),
            SocketAddress::V6(addr) => addr.port(),
        }
    }

    /// Set the port number for either address family.
    #[inline]
    pub fn set_port(&mut self, port: u16) {
        match self {
            SocketAddress::V4(addr) => addr.set_port(port),
            SocketAddress::V6(addr) => addr.set_port(port),
        }
    }

    /// Check if this is an IPv4 address.
    #[inline]
    pub fn is_v4(&self) -> bool {
        matches!(self, SocketAddress::V4(_))
    }

    /// Check if this is an IPv6 address.
    #[inline]
    pub fn is_v6(&self) -> bool {
        matches!(self, SocketAddress::V6(_))
    }

    /// Get the IP address (without port) as an [`AllAddr`].
    #[inline]
    pub fn ip_as_all_addr(&self) -> AllAddr {
        match self {
            SocketAddress::V4(addr) => AllAddr::V4(*addr.ip()),
            SocketAddress::V6(addr) => AllAddr::V6(*addr.ip()),
        }
    }

    /// Create an IPv4 socket address from address and port.
    #[inline]
    pub fn new_v4(addr: Ipv4Addr, port: u16) -> Self {
        SocketAddress::V4(SocketAddrV4::new(addr, port))
    }

    /// Create an IPv6 socket address from address, port, flow info, and scope ID.
    #[inline]
    pub fn new_v6(addr: Ipv6Addr, port: u16, flowinfo: u32, scope_id: u32) -> Self {
        SocketAddress::V6(SocketAddrV6::new(addr, port, flowinfo, scope_id))
    }
}

impl From<SocketAddrV4> for SocketAddress {
    #[inline]
    fn from(addr: SocketAddrV4) -> Self {
        SocketAddress::V4(addr)
    }
}

impl From<SocketAddrV6> for SocketAddress {
    #[inline]
    fn from(addr: SocketAddrV6) -> Self {
        SocketAddress::V6(addr)
    }
}

impl From<SocketAddr> for SocketAddress {
    #[inline]
    fn from(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(v4) => SocketAddress::V4(v4),
            SocketAddr::V6(v6) => SocketAddress::V6(v6),
        }
    }
}

impl From<SocketAddress> for SocketAddr {
    #[inline]
    fn from(addr: SocketAddress) -> Self {
        match addr {
            SocketAddress::V4(v4) => SocketAddr::V4(v4),
            SocketAddress::V6(v6) => SocketAddr::V6(v6),
        }
    }
}

impl fmt::Display for SocketAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SocketAddress::V4(addr) => write!(f, "{}", addr),
            SocketAddress::V6(addr) => write!(f, "{}", addr),
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

    // -- AllAddr tests --

    #[test]
    fn test_all_addr_v4() {
        let addr = AllAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert!(addr.is_v4());
        assert!(!addr.is_v6());
        assert_eq!(addr.as_ipv4(), Some(&Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(addr.as_ipv6(), None);
    }

    #[test]
    fn test_all_addr_v6() {
        let addr = AllAddr::V6(Ipv6Addr::LOCALHOST);
        assert!(!addr.is_v4());
        assert!(addr.is_v6());
        assert_eq!(addr.as_ipv6(), Some(&Ipv6Addr::LOCALHOST));
        assert_eq!(addr.as_ipv4(), None);
    }

    #[test]
    fn test_all_addr_cname_with_name() {
        let addr = AllAddr::Cname {
            target: CnameTarget::Name("example.com".to_string()),
            uid: 42,
        };
        assert!(!addr.is_v4());
        assert!(!addr.is_v6());
        assert_eq!(addr.as_ipv4(), None);
        assert_eq!(addr.as_ipv6(), None);
    }

    #[test]
    fn test_all_addr_cname_with_cache_index() {
        let addr = AllAddr::Cname {
            target: CnameTarget::CacheIndex(99),
            uid: 7,
        };
        assert!(!addr.is_v4());
        assert!(!addr.is_v6());
    }

    #[test]
    fn test_all_addr_from_ipv4() {
        let addr: AllAddr = Ipv4Addr::new(10, 0, 0, 1).into();
        assert!(addr.is_v4());
        assert_eq!(addr.as_ipv4(), Some(&Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn test_all_addr_from_ipv6() {
        let addr: AllAddr = Ipv6Addr::UNSPECIFIED.into();
        assert!(addr.is_v6());
        assert_eq!(addr.as_ipv6(), Some(&Ipv6Addr::UNSPECIFIED));
    }

    #[test]
    fn test_all_addr_from_ipv4_constructor() {
        let addr = AllAddr::from_ipv4(Ipv4Addr::new(127, 0, 0, 1));
        assert!(addr.is_v4());
        assert_eq!(addr.as_ipv4(), Some(&Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn test_all_addr_from_ipv6_constructor() {
        let addr = AllAddr::from_ipv6(Ipv6Addr::LOCALHOST);
        assert!(addr.is_v6());
        assert_eq!(addr.as_ipv6(), Some(&Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn test_all_addr_rr_block() {
        let addr = AllAddr::RrBlock {
            rrtype: 1,
            data: vec![1, 2, 3, 4],
        };
        assert!(!addr.is_v4());
        assert!(!addr.is_v6());
    }

    #[test]
    fn test_all_addr_rr_data_inline() {
        let addr = AllAddr::RrData {
            rrtype: 28,
            data: vec![0; RR_IMDATALEN], // max inline length
        };
        assert!(!addr.is_v4());
        assert!(!addr.is_v6());
    }

    #[test]
    fn test_all_addr_display_v4() {
        let addr = AllAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        assert_eq!(format!("{}", addr), "8.8.8.8");
    }

    #[test]
    fn test_all_addr_display_v6() {
        let addr = AllAddr::V6(Ipv6Addr::LOCALHOST);
        assert_eq!(format!("{}", addr), "::1");
    }

    #[test]
    fn test_all_addr_display_cname() {
        let addr = AllAddr::Cname {
            target: CnameTarget::Name("example.com".to_string()),
            uid: 42,
        };
        assert_eq!(format!("{}", addr), "CNAME(uid=42)");
    }

    #[test]
    fn test_all_addr_display_rr_block() {
        let addr = AllAddr::RrBlock {
            rrtype: 1,
            data: vec![1, 2, 3, 4],
        };
        assert_eq!(format!("{}", addr), "RR(type=1, len=4)");
    }

    #[test]
    fn test_all_addr_display_rr_data() {
        let addr = AllAddr::RrData {
            rrtype: 28,
            data: vec![0; 10],
        };
        assert_eq!(format!("{}", addr), "RR(type=28, len=10, inline)");
    }

    // -- RR_IMDATALEN test --

    #[test]
    fn test_rr_imdatalen() {
        // Verify the constant matches the C calculation:
        // sizeof(union all_addr) = 16, offsetof(struct datablock, data) = 3
        assert_eq!(RR_IMDATALEN, 13);
    }

    // -- CnameTarget tests --

    #[test]
    fn test_cname_target_cache_index() {
        let target = CnameTarget::CacheIndex(42);
        match target {
            CnameTarget::CacheIndex(idx) => assert_eq!(idx, 42),
            _ => panic!("Expected CacheIndex variant"),
        }
    }

    #[test]
    fn test_cname_target_name() {
        let target = CnameTarget::Name("www.example.com".to_string());
        match target {
            CnameTarget::Name(ref n) => assert_eq!(n, "www.example.com"),
            _ => panic!("Expected Name variant"),
        }
    }

    #[test]
    fn test_cname_target_clone() {
        let original = CnameTarget::Name("test.com".to_string());
        let cloned = original.clone();
        match cloned {
            CnameTarget::Name(ref n) => assert_eq!(n, "test.com"),
            _ => panic!("Expected Name variant"),
        }
    }

    // -- SocketAddress tests --

    #[test]
    fn test_socket_address_v4() {
        let sa = SocketAddress::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53));
        assert!(sa.is_v4());
        assert!(!sa.is_v6());
        assert_eq!(sa.port(), 53);
    }

    #[test]
    fn test_socket_address_v6() {
        let sa = SocketAddress::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 53, 0, 0));
        assert!(!sa.is_v4());
        assert!(sa.is_v6());
        assert_eq!(sa.port(), 53);
    }

    #[test]
    fn test_socket_address_new_v4() {
        let sa = SocketAddress::new_v4(Ipv4Addr::new(10, 0, 0, 1), 8080);
        assert!(sa.is_v4());
        assert_eq!(sa.port(), 8080);
    }

    #[test]
    fn test_socket_address_new_v6() {
        let sa = SocketAddress::new_v6(Ipv6Addr::LOCALHOST, 443, 0, 0);
        assert!(sa.is_v6());
        assert_eq!(sa.port(), 443);
    }

    #[test]
    fn test_socket_address_set_port() {
        let mut sa = SocketAddress::new_v4(Ipv4Addr::LOCALHOST, 53);
        assert_eq!(sa.port(), 53);
        sa.set_port(5353);
        assert_eq!(sa.port(), 5353);
    }

    #[test]
    fn test_socket_address_set_port_v6() {
        let mut sa = SocketAddress::new_v6(Ipv6Addr::LOCALHOST, 53, 0, 0);
        assert_eq!(sa.port(), 53);
        sa.set_port(5353);
        assert_eq!(sa.port(), 5353);
    }

    #[test]
    fn test_socket_address_ip_as_all_addr_v4() {
        let sa = SocketAddress::new_v4(Ipv4Addr::new(192, 168, 1, 1), 53);
        let addr = sa.ip_as_all_addr();
        assert!(addr.is_v4());
        assert_eq!(addr.as_ipv4(), Some(&Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn test_socket_address_ip_as_all_addr_v6() {
        let sa = SocketAddress::new_v6(Ipv6Addr::LOCALHOST, 53, 0, 0);
        let addr = sa.ip_as_all_addr();
        assert!(addr.is_v6());
        assert_eq!(addr.as_ipv6(), Some(&Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn test_socket_address_from_socket_addr_v4() {
        let std_addr = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 80);
        let sa: SocketAddress = std_addr.into();
        assert!(sa.is_v4());
        assert_eq!(sa.port(), 80);
    }

    #[test]
    fn test_socket_address_from_socket_addr_v6() {
        let std_addr = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 0, 0);
        let sa: SocketAddress = std_addr.into();
        assert!(sa.is_v6());
        assert_eq!(sa.port(), 443);
    }

    #[test]
    fn test_socket_address_from_std_socket_addr() {
        let std_addr = SocketAddr::from(([127, 0, 0, 1], 53));
        let sa: SocketAddress = std_addr.into();
        assert!(sa.is_v4());
        assert_eq!(sa.port(), 53);

        // Roundtrip conversion
        let roundtrip: SocketAddr = sa.into();
        assert_eq!(roundtrip, SocketAddr::from(([127, 0, 0, 1], 53)));
    }

    #[test]
    fn test_socket_address_roundtrip_v6() {
        let std_addr = SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 53));
        let sa: SocketAddress = std_addr.clone().into();
        let roundtrip: SocketAddr = sa.into();
        assert_eq!(roundtrip, std_addr);
    }

    #[test]
    fn test_socket_address_display_v4() {
        let sa = SocketAddress::new_v4(Ipv4Addr::LOCALHOST, 53);
        assert_eq!(format!("{}", sa), "127.0.0.1:53");
    }

    #[test]
    fn test_socket_address_display_v6() {
        let sa = SocketAddress::new_v6(Ipv6Addr::LOCALHOST, 53, 0, 0);
        let displayed = format!("{}", sa);
        // IPv6 socket addr displays as [::1]:53
        assert!(displayed.contains("53"));
        assert!(displayed.contains("::1"));
    }

    #[test]
    fn test_socket_address_equality() {
        let a = SocketAddress::new_v4(Ipv4Addr::LOCALHOST, 53);
        let b = SocketAddress::new_v4(Ipv4Addr::LOCALHOST, 53);
        let c = SocketAddress::new_v4(Ipv4Addr::LOCALHOST, 5353);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_socket_address_hash_equality() {
        use std::collections::HashMap;
        let mut map = HashMap::new();
        let key = SocketAddress::new_v4(Ipv4Addr::new(8, 8, 8, 8), 53);
        map.insert(key.clone(), "dns");
        assert_eq!(map.get(&key), Some(&"dns"));

        // Different port should be a different key
        let other = SocketAddress::new_v4(Ipv4Addr::new(8, 8, 8, 8), 5353);
        assert_eq!(map.get(&other), None);
    }

    #[test]
    fn test_socket_address_clone() {
        let original = SocketAddress::new_v6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 443, 0, 0);
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    // -- DNSSEC variant tests (feature-gated) --

    #[cfg(feature = "dnssec")]
    #[test]
    fn test_all_addr_key() {
        let addr = AllAddr::Key {
            keydata: vec![0x01, 0x02, 0x03],
            flags: 257,
            keytag: 12345,
            algo: 8,
        };
        assert!(!addr.is_v4());
        assert!(!addr.is_v6());
        assert_eq!(format!("{}", addr), "KEY(tag=12345, algo=8)");
    }

    #[cfg(feature = "dnssec")]
    #[test]
    fn test_all_addr_ds() {
        let addr = AllAddr::Ds {
            keydata: vec![0xAB, 0xCD],
            keytag: 54321,
            algo: 13,
            digest: 2,
        };
        assert!(!addr.is_v4());
        assert!(!addr.is_v6());
        assert_eq!(format!("{}", addr), "DS(tag=54321, algo=13, digest=2)");
    }

    #[cfg(feature = "dnssec")]
    #[test]
    fn test_all_addr_log() {
        let addr = AllAddr::Log {
            keytag: 100,
            algo: 8,
            digest: 2,
            rcode: 0,
            ede: -1,
        };
        assert!(!addr.is_v4());
        assert!(!addr.is_v6());
        assert_eq!(format!("{}", addr), "LOG(rcode=0, ede=-1)");
    }
}

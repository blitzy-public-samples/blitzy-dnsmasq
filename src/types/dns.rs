//! DNS-specific type definitions for the dnsmasq Rust implementation.
//!
//! This module defines all DNS-specific data types used across the dnsmasq codebase,
//! replacing the DNS-related struct definitions from the C `dnsmasq.h` header and the
//! `struct dns_header` from `dns-protocol.h`. These types are fundamental to the DNS
//! forwarding, caching, and DNSSEC subsystems.
//!
//! # Key Transformations from C
//! - **Intrusive linked lists removed:** All `next`, `prev`, `hash_next` pointers from C
//!   structs are eliminated. Collections manage relationships externally via `HashMap`,
//!   `Vec`, and `VecDeque`.
//! - **C unions → Rust enums:** `union all_addr` becomes [`AllAddr`](super::addr::AllAddr),
//!   defined in the `addr` module and imported here.
//! - **C fixed-size arrays → Rust `String`/`Vec<u8>`:** `char sname[SMALLDNAME]` → `String`,
//!   `unsigned char key[KEYBLOCK_LEN]` → `Vec<u8>`.
//! - **C pointer-to-struct → Rust `Option`/index:** `struct server *sentto` → `Option<usize>`.
//! - **C `time_t` → `i64`:** Timestamps use `i64` for seconds since epoch.
//! - **C `#define` flag groups → `bitflags!` macro:** Type-safe bitflag types for all flag sets.
//! - **C `#ifdef HAVE_*` → `#[cfg(feature = "...")]`:** Feature-gated compilation.
//!
//! # Source References
//! - `src/dnsmasq.h` lines 352–998, 1528–1534
//! - `src/dns-protocol.h` lines 471–633

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use bitflags::bitflags;

use crate::types::addr::{AllAddr, SocketAddress};

// ===========================================================================
// DnsName — Newtype for DNS wire-format names (AAP Section 0.4.3)
// ===========================================================================

/// DNS name in wire format (length-prefixed labels).
///
/// Newtype pattern prevents accidental mixing of wire-format and
/// presentation-format domain name strings. Wire format uses length-prefixed
/// labels (e.g., `[3]www[7]example[3]com[0]`) per RFC 1035 Section 3.1.
///
/// # Examples
/// ```
/// # use dnsmasq::types::dns::DnsName;
/// // Wire-format for "www.example.com"
/// let wire = vec![3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0];
/// let name = DnsName::new(wire);
/// assert_eq!(name.to_string_lossy(), "www.example.com");
/// ```
///
/// Replaces: C `char` arrays used as DNS names throughout `dnsmasq.h`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DnsName(pub Vec<u8>);

impl DnsName {
    /// Create a new `DnsName` from wire-format bytes.
    ///
    /// The caller is responsible for ensuring the bytes represent a valid
    /// wire-format DNS name (sequence of length-prefixed labels terminated
    /// by a zero-length label).
    #[inline]
    pub fn new(wire_format: Vec<u8>) -> Self {
        DnsName(wire_format)
    }

    /// Return a reference to the raw wire-format bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Return the total length of the wire-format representation in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check whether the wire-format representation is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Convert wire-format DNS name to a dotted presentation-format string.
    ///
    /// Parses the length-prefixed label sequence and joins labels with `.`.
    /// Non-UTF-8 bytes within labels are replaced with the Unicode replacement
    /// character (U+FFFD), hence "lossy".
    ///
    /// A root name (single zero byte) produces an empty string.
    /// An empty byte slice also produces an empty string.
    pub fn to_string_lossy(&self) -> String {
        if self.0.is_empty() {
            return String::new();
        }

        let mut result = String::new();
        let mut pos = 0;
        let data = &self.0;

        while pos < data.len() {
            let label_len = data[pos] as usize;
            // A zero-length label marks the root (end of name).
            if label_len == 0 {
                break;
            }
            pos += 1;

            // Guard against truncated data.
            let end = (pos + label_len).min(data.len());
            let label_bytes = &data[pos..end];

            if !result.is_empty() {
                result.push('.');
            }
            result.push_str(&String::from_utf8_lossy(label_bytes));

            pos = end;
        }

        result
    }
}

impl fmt::Display for DnsName {
    /// Display the DNS name in dotted presentation format.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string_lossy())
    }
}

// ===========================================================================
// DnsHeader — 12-byte DNS message header (RFC 1035 Section 4.1.1)
// ===========================================================================

// Header byte 3 (hb3) bit masks — from dns-protocol.h lines 521–533.
const HB3_QR: u8 = 0x80;
const HB3_OPCODE: u8 = 0x78;
const HB3_AA: u8 = 0x04;
const HB3_TC: u8 = 0x02;
const HB3_RD: u8 = 0x01;

// Header byte 4 (hb4) bit masks — from dns-protocol.h lines 536–545.
const HB4_RA: u8 = 0x80;
const HB4_AD: u8 = 0x20;
const HB4_CD: u8 = 0x10;
const HB4_RCODE: u8 = 0x0f;

/// DNS message header per RFC 1035 Section 4.1.1.
///
/// 12-byte fixed-format header at the start of all DNS messages.
/// All multi-byte fields (`id`, `qdcount`, `ancount`, `nscount`, `arcount`)
/// are stored in **network byte order** (big-endian) on the wire.
///
/// # Wire Format
/// ```text
/// Bytes  0– 1: id       (message identifier)
/// Byte      2: hb3      (QR, OPCODE, AA, TC, RD)
/// Byte      3: hb4      (RA, Z, AD, CD, RCODE)
/// Bytes  4– 5: qdcount  (question section count)
/// Bytes  6– 7: ancount  (answer section count)
/// Bytes  8– 9: nscount  (authority section count)
/// Bytes 10–11: arcount  (additional section count)
/// ```
///
/// Replaces: `struct dns_header` from `src/dns-protocol.h` (lines 471–492).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsHeader {
    /// Message identifier for matching queries with responses.
    pub id: u16,
    /// Header byte 3: QR (bit 7), OPCODE (bits 6–3), AA (bit 2), TC (bit 1), RD (bit 0).
    pub hb3: u8,
    /// Header byte 4: RA (bit 7), Z (bit 6), AD (bit 5), CD (bit 4), RCODE (bits 3–0).
    pub hb4: u8,
    /// Number of entries in the question section.
    pub qdcount: u16,
    /// Number of resource records in the answer section.
    pub ancount: u16,
    /// Number of name-server resource records in the authority section.
    pub nscount: u16,
    /// Number of resource records in the additional records section.
    pub arcount: u16,
}

impl DnsHeader {
    /// Check whether the QR bit is set (message is a response).
    ///
    /// Corresponds to the `HB3_QR` (0x80) bit in `hb3`.
    /// `false` = query, `true` = response.
    #[inline]
    pub fn is_response(&self) -> bool {
        self.hb3 & HB3_QR != 0
    }

    /// Extract the 4-bit OPCODE field (bits 6–3 of `hb3`).
    ///
    /// Returns a value 0–15. Standard query = 0.
    /// Corresponds to the C macro `OPCODE(header)`.
    #[inline]
    pub fn opcode(&self) -> u8 {
        (self.hb3 & HB3_OPCODE) >> 3
    }

    /// Set the 4-bit OPCODE field (bits 6–3 of `hb3`).
    ///
    /// `opcode` should be in the range 0–15. Only the low 4 bits are used.
    /// Corresponds to the C macro `SET_OPCODE(header, code)`.
    #[inline]
    pub fn set_opcode(&mut self, opcode: u8) {
        self.hb3 = (self.hb3 & !HB3_OPCODE) | ((opcode & 0x0f) << 3);
    }

    /// Check whether the AA (Authoritative Answer) flag is set.
    ///
    /// Corresponds to the `HB3_AA` (0x04) bit in `hb3`.
    #[inline]
    pub fn is_authoritative(&self) -> bool {
        self.hb3 & HB3_AA != 0
    }

    /// Check whether the TC (Truncation) flag is set.
    ///
    /// Corresponds to the `HB3_TC` (0x02) bit in `hb3`.
    #[inline]
    pub fn is_truncated(&self) -> bool {
        self.hb3 & HB3_TC != 0
    }

    /// Check whether the RD (Recursion Desired) flag is set.
    ///
    /// Corresponds to the `HB3_RD` (0x01) bit in `hb3`.
    #[inline]
    pub fn recursion_desired(&self) -> bool {
        self.hb3 & HB3_RD != 0
    }

    /// Check whether the RA (Recursion Available) flag is set.
    ///
    /// Corresponds to the `HB4_RA` (0x80) bit in `hb4`.
    #[inline]
    pub fn recursion_available(&self) -> bool {
        self.hb4 & HB4_RA != 0
    }

    /// Check whether the AD (Authenticated Data) flag is set (DNSSEC, RFC 4035).
    ///
    /// Corresponds to the `HB4_AD` (0x20) bit in `hb4`.
    #[inline]
    pub fn authenticated_data(&self) -> bool {
        self.hb4 & HB4_AD != 0
    }

    /// Check whether the CD (Checking Disabled) flag is set (DNSSEC, RFC 4035).
    ///
    /// Corresponds to the `HB4_CD` (0x10) bit in `hb4`.
    #[inline]
    pub fn checking_disabled(&self) -> bool {
        self.hb4 & HB4_CD != 0
    }

    /// Extract the 4-bit RCODE (response code) field (bits 3–0 of `hb4`).
    ///
    /// Returns a value 0–15 (e.g., 0 = NOERROR, 3 = NXDOMAIN).
    /// Corresponds to the C macro `RCODE(header)`.
    #[inline]
    pub fn rcode(&self) -> u8 {
        self.hb4 & HB4_RCODE
    }

    /// Set the 4-bit RCODE field (bits 3–0 of `hb4`).
    ///
    /// `rcode` should be in the range 0–15. Only the low 4 bits are used.
    /// Corresponds to the C macro `SET_RCODE(header, code)`.
    #[inline]
    pub fn set_rcode(&mut self, rcode: u8) {
        self.hb4 = (self.hb4 & !HB4_RCODE) | (rcode & 0x0f);
    }
}

// ===========================================================================
// CacheEntryFlags — Bitflags for DNS cache entries (dnsmasq.h lines 687–718)
// ===========================================================================

bitflags! {
    /// Cache entry flags controlling behavior and classification.
    ///
    /// These flags determine how a cache entry is treated during lookups,
    /// eviction, and response construction. Each flag corresponds to a C
    /// `F_*` constant from `dnsmasq.h` lines 687–718.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct CacheEntryFlags: u32 {
        /// Entry never expires (permanent hosts-file or config entries).
        const IMMORTAL   = 1 << 0;
        /// Name field is a pointer (used internally for name storage).
        const NAMEP      = 1 << 1;
        /// Reverse-lookup entry (PTR record).
        const REVERSE    = 1 << 2;
        /// Forward-lookup entry (A/AAAA record).
        const FORWARD    = 1 << 3;
        /// Entry originates from a DHCP lease.
        const DHCP       = 1 << 4;
        /// Negative cache entry (NXDOMAIN or NODATA).
        const NEG        = 1 << 5;
        /// Entry loaded from a hosts file.
        const HOSTS      = 1 << 6;
        /// Entry contains an IPv4 address.
        const IPV4       = 1 << 7;
        /// Entry contains an IPv6 address.
        const IPV6       = 1 << 8;
        /// Name stored in bigname allocation.
        const BIGNAME    = 1 << 9;
        /// NXDOMAIN response cached.
        const NXDOMAIN   = 1 << 10;
        /// CNAME record.
        const CNAME      = 1 << 11;
        /// DNSKEY record (DNSSEC).
        const DNSKEY     = 1 << 12;
        /// Entry from static configuration.
        const CONFIG     = 1 << 13;
        /// DS record (DNSSEC delegation signer).
        const DS         = 1 << 14;
        /// DNSSEC validation succeeded for this entry.
        const DNSSECOK   = 1 << 15;
        /// Entry obtained from an upstream server.
        const UPSTREAM   = 1 << 16;
        /// RR name record.
        const RRNAME     = 1 << 17;
        /// Server record.
        const SERVER     = 1 << 18;
        /// Query record.
        const QUERY      = 1 << 19;
        /// NOERROR response (successful but possibly empty).
        const NOERR      = 1 << 20;
        /// Authoritative answer.
        const AUTH       = 1 << 21;
        /// DNSSEC-related record.
        const DNSSEC     = 1 << 22;
        /// Entry has associated keytag data.
        const KEYTAG     = 1 << 23;
        /// Security status indicator.
        const SECSTAT    = 1 << 24;
        /// No resource record data present.
        const NO_RR      = 1 << 25;
        /// Entry used for ipset/nftset population.
        const IPSET      = 1 << 26;
        /// No extra data attached.
        const NOEXTRA    = 1 << 27;
        /// Domain-specific server entry.
        const DOMAINSRV  = 1 << 28;
        /// Entry carries an RCODE value.
        const RCODE      = 1 << 29;
        /// Generic RR record entry.
        const RR         = 1 << 30;
        /// Stale cache entry (past TTL but still served).
        const STALE      = 1 << 31;
    }
}

// UID source constants (dnsmasq.h lines 720–724)

/// UID value indicating no specific source.
pub const UID_NONE: u32 = 0;
/// UID value for entries sourced from static configuration.
pub const SRC_CONFIG: u32 = 1;
/// UID value for entries sourced from hosts files.
pub const SRC_HOSTS: u32 = 2;
/// UID value for entries sourced from additional hosts (addn-hosts).
pub const SRC_AH: u32 = 3;

// Pipe operation constants (dnsmasq.h lines 726–730)

/// Pipe operation: insert a cache entry (helper → parent).
pub const PIPE_OP_INSERT: u8 = 1;
/// Pipe operation: report validation result (helper → parent).
pub const PIPE_OP_RESULT: u8 = 2;
/// Pipe operation: update parent's statistics (helper → parent).
pub const PIPE_OP_STATS: u8 = 3;
/// Pipe operation: update ipset membership (helper → parent).
pub const PIPE_OP_IPSET: u8 = 4;
/// Pipe operation: update nftables set (helper → parent).
pub const PIPE_OP_NFTSET: u8 = 5;

// ===========================================================================
// CacheEntry — DNS cache record (dnsmasq.h struct crec, lines 670–682)
// ===========================================================================

/// DNS cache entry replacing C `struct crec` (`dnsmasq.h` lines 670–682).
///
/// The C intrusive linked-list pointers (`next`, `prev`, `hash_next`) are
/// removed. Cache entries are managed externally by `HashMap` + `VecDeque` for LRU.
/// The C name union is replaced by a `String` field.
#[derive(Debug, Clone)]
pub struct CacheEntry {
    /// Address data (IPv4, IPv6, CNAME target, DNSSEC key, etc.).
    pub addr: AllAddr,
    /// Time to die — expiration timestamp as seconds since epoch (0 = immortal).
    pub ttd: i64,
    /// DNS class for DNSKEY/DS entries, or source index for F_HOSTS entries.
    pub uid: u32,
    /// Cache entry flags.
    pub flags: CacheEntryFlags,
    /// Domain name associated with this cache entry.
    pub name: String,
}

// ===========================================================================
// ForwardRecordFlags — Bitflags for forward records (dnsmasq.h lines 962–971)
// ===========================================================================

bitflags! {
    /// Forward record flags controlling query forwarding behavior.
    ///
    /// Replaces: `FREC_*` constants from `dnsmasq.h` lines 962–971.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct ForwardRecordFlags: u32 {
        /// Do not apply rebind protection.
        const NOREBIND          = 1;
        /// DNSSEC checking disabled by client.
        const CHECKING_DISABLED = 2;
        /// Do not cache the response.
        const NO_CACHE          = 4;
        /// Internally-generated DNSKEY query.
        const DNSKEY_QUERY      = 8;
        /// Internally-generated DS query.
        const DS_QUERY          = 16;
        /// Client query had AD flag set.
        const AD_QUESTION       = 32;
        /// Client query had DO flag set.
        const DO_QUESTION       = 64;
        /// Query has an EDNS0 OPT pseudo-header.
        const HAS_PHEADER       = 128;
        /// Query was retried over TCP after truncation.
        const GONE_TO_TCP       = 256;
        /// Response answer received.
        const ANSWER            = 512;
    }
}

// ===========================================================================
// ForwardRecordSource — Source info (dnsmasq.h struct frec_src, lines 974–981)
// ===========================================================================

/// Source information for a forwarded DNS query.
///
/// Replaces C `struct frec_src`. The `next` pointer is removed —
/// multiple sources stored in a `Vec`.
#[derive(Debug, Clone)]
pub struct ForwardRecordSource {
    /// Client source socket address.
    pub source: SocketAddress,
    /// Destination address the query arrived on.
    pub dest: AllAddr,
    /// Interface index the query arrived on.
    pub iface: u32,
    /// Logging identifier for this query.
    pub log_id: u32,
    /// Bitmap for EDNS0 option encoding.
    pub encode_bitmap: u32,
    /// File descriptor for sending the reply.
    pub fd: i32,
    /// Original transaction ID from the client.
    pub orig_id: u16,
    /// Maximum UDP packet size advertised by the client.
    pub udp_pkt_size: u16,
}

// ===========================================================================
// ForwardRecordDnssec — DNSSEC-specific fields (feature-gated)
// ===========================================================================

/// DNSSEC-specific fields for a forward record.
///
/// Replaces the `#ifdef HAVE_DNSSEC` block in C `struct frec`.
/// Dependency chains use transaction IDs instead of raw pointers.
#[cfg(feature = "dnssec")]
#[derive(Debug, Clone)]
pub struct ForwardRecordDnssec {
    /// Unique identifier for DNSSEC chain tracking.
    pub uid: i32,
    /// DNS class for the DNSSEC query.
    pub class: i32,
    /// Counter limiting cryptographic work.
    pub work_counter: i32,
    /// Counter limiting validation recursion.
    pub validate_counter: i32,
    /// Transaction ID of the dependent query awaiting our result.
    pub dependent: Option<u16>,
    /// Transaction ID linking to the next dependent in a chain.
    pub next_dependent: Option<u16>,
    /// Transaction ID of the query blocking our progress.
    pub blocking_query: Option<u16>,
}

// ===========================================================================
// ForwardRecord — DNS query tracking (dnsmasq.h struct frec, lines 973–998)
// ===========================================================================

/// Forward record tracking a DNS query sent to an upstream server.
///
/// Replaces C `struct frec`. Managed in `HashMap<u16, ForwardRecord>` keyed
/// by `new_id`. The C `next` pointer is removed.
#[derive(Debug, Clone)]
pub struct ForwardRecord {
    /// Primary source information for this query.
    pub frec_src: ForwardRecordSource,
    /// Additional sources (merged queries).
    pub additional_sources: Vec<ForwardRecordSource>,
    /// Server index, `None` means free.
    pub sentto: Option<usize>,
    /// Rewritten transaction ID for the upstream query.
    pub new_id: u16,
    /// Non-zero to forward to all servers.
    pub forwardall: i32,
    /// Flags controlling forwarding behavior.
    pub flags: ForwardRecordFlags,
    /// Timestamp when the query was created (seconds since epoch).
    pub time: i64,
    /// High-resolution forward timestamp for latency calculation.
    pub forward_timestamp: u32,
    /// Delay before sending (query pacing).
    pub forward_delay: i32,
    /// Saved query/reply data during validation.
    pub stash: Option<Vec<u8>>,
    /// Length of the stashed data.
    pub stash_len: usize,
    /// DNSSEC-specific tracking fields.
    #[cfg(feature = "dnssec")]
    pub dnssec: Option<ForwardRecordDnssec>,
}

// ===========================================================================
// ServerFlags — Bitflags for server entries (dnsmasq.h lines 749–764)
// ===========================================================================

bitflags! {
    /// Server configuration flags controlling upstream DNS server behavior.
    ///
    /// The actual numeric values matter because servers are sorted by flag
    /// values to order: IPv6 addr, IPv4 addr, all-zero return, no-data return,
    /// resolv.conf servers, upstream server.
    ///
    /// Replaces: `SERV_*` constants from `dnsmasq.h` lines 749–764.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct ServerFlags: u16 {
        /// Forward this domain in the normal way (use resolv.conf servers).
        const USE_RESOLV       = 1;
        /// Address is the answer, or NoDATA depending on ADDR4/ADDR6.
        const LITERAL_ADDRESS  = 2;
        /// Return all zeros for A and AAAA queries.
        const ALL_ZEROS        = 4;
        /// Server address is IPv4.
        const ADDR4            = 8;
        /// Server address is IPv6.
        const ADDR6            = 16;
        /// A source address is defined for outgoing queries.
        const HAS_SOURCE       = 32;
        /// Server handles names with no domain part only.
        const FOR_NODOTS       = 64;
        /// Avoid repeated warnings about recursive-only servers.
        const WARNED_RECURSIVE = 128;
        /// Server was configured via D-Bus.
        const FROM_DBUS        = 256;
        /// Temporary mark for mark-and-delete operations.
        const MARK             = 512;
        /// Domain has a leading `*` (wildcard).
        const WILDCARD         = 1024;
        /// Server from resolv.conf (not command line).
        const FROM_RESOLV      = 2048;
        /// Server read from a `--servers-file`.
        const FROM_FILE        = 4096;
        /// Server causes a forwarding loop.
        const LOOP             = 8192;
        /// Validate DNSSEC when using this server.
        const DO_DNSSEC        = 16384;
        /// Got some data from the TCP connection.
        const GOT_TCP          = 32768;
    }
}

// ===========================================================================
// ServerEntry — Upstream DNS server (dnsmasq.h struct server, lines 786–804)
// ===========================================================================

/// Upstream DNS server configuration and runtime state.
///
/// Replaces C `struct server` (`dnsmasq.h` lines 786–804).
/// The `next` pointer is removed — servers are stored in a `Vec` or sorted array.
/// The `sfd` (server file descriptor) pointer is removed — socket management is
/// handled externally.
#[derive(Debug, Clone)]
pub struct ServerEntry {
    /// Server flags controlling behavior and routing.
    pub flags: ServerFlags,
    /// Length of the domain string (for efficient comparison).
    pub domain_len: u16,
    /// Domain this server handles (`None` for default server).
    pub domain: Option<String>,
    /// Serial number for configuration version tracking.
    pub serial: i32,
    /// Position in the sorted server array.
    pub arrayposn: i32,
    /// Index of the last server used in a round-robin group.
    pub last_server: i32,
    /// Server socket address (IP + port).
    pub addr: SocketAddress,
    /// Source address for outgoing queries to this server.
    pub source_addr: SocketAddress,
    /// Network interface name bound to this server.
    pub interface: String,
    /// Network interface index.
    pub ifindex: u32,
    /// TCP connection file descriptor (-1 if not connected).
    pub tcpfd: i32,
    /// Total number of queries sent to this server.
    pub queries: u32,
    /// Number of queries that failed (timeout, error).
    pub failed_queries: u32,
    /// Number of NXDOMAIN replies received.
    pub nxdomain_replies: u32,
    /// Number of retries attempted.
    pub retrys: u32,
    /// Measured query latency in milliseconds.
    pub query_latency: u32,
    /// Moving minimum average latency.
    pub mma_latency: u32,
    /// Timestamp of last forwarded query.
    pub forwardtime: i64,
    /// Count of queries forwarded in the current time window.
    pub forwardcount: i32,
    /// Unique ID for loop detection probes (only with loop_detect feature).
    #[cfg(feature = "loop_detect")]
    pub uid: u32,
}

// ===========================================================================
// DnssecStatus — DNSSEC validation status (dnsmasq.h lines 935–945)
// ===========================================================================

/// DNSSEC validation status codes.
///
/// These status values encode the result of DNSSEC validation for a DNS
/// response. The numeric values are chosen to be distinct from DNS RCODEs
/// (which fit in the low 16 bits).
///
/// Replaces: `STAT_*` constants from `dnsmasq.h` lines 936–945.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DnssecStatus {
    /// Response is cryptographically validated and secure.
    Secure         = 0x10000,
    /// Response is provably insecure (no trust chain).
    Insecure       = 0x20000,
    /// Response failed DNSSEC validation (bogus signatures).
    Bogus          = 0x30000,
    /// Need to fetch DS record to continue validation.
    NeedDs         = 0x40000,
    /// Need to fetch DNSKEY record to continue validation.
    NeedKey        = 0x50000,
    /// Response was truncated, need TCP retry.
    Truncated      = 0x60000,
    /// Secure response that matched via wildcard.
    SecureWildcard = 0x70000,
    /// Validation completed successfully (generic OK).
    Ok             = 0x80000,
    /// Validation abandoned (too much work / crypto).
    Abandoned      = 0x90000,
    /// Asynchronous validation in progress.
    Async          = 0xa0000,
}

// ===========================================================================
// DnssecFailFlags — DNSSEC failure reason flags (dnsmasq.h lines 947–958)
// ===========================================================================

bitflags! {
    /// DNSSEC failure reason flags indicating why validation failed.
    ///
    /// Multiple flags can be set simultaneously to indicate compound failures.
    ///
    /// Replaces: `DNSSEC_FAIL_*` constants from `dnsmasq.h` lines 947–958.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct DnssecFailFlags: u16 {
        /// Key not yet valid (inception time in the future).
        const NYV         = 0x0001;
        /// Key expired (expiration time in the past).
        const EXP         = 0x0002;
        /// Indeterminate validation state.
        const INDET       = 0x0004;
        /// No supported key algorithm available.
        const NOKEYSUP    = 0x0008;
        /// No RRSIGs present for validation.
        const NOSIG       = 0x0010;
        /// No zone bit set in DNSKEY flags.
        const NOZONE      = 0x0020;
        /// No NSEC/NSEC3 records for negative proof.
        const NONSEC      = 0x0040;
        /// No supported DS digest algorithm available.
        const NODSSUP     = 0x0080;
        /// No DNSKEY record found for verification.
        const NOKEY       = 0x0100;
        /// Too many NSEC3 hash iterations.
        const NSEC3_ITERS = 0x0200;
        /// Malformed or corrupt DNS packet.
        const BADPACKET   = 0x0400;
        /// Exceeded cryptographic work limit.
        const WORK        = 0x0800;
    }
}

// ===========================================================================
// AddrListFlags — Address list flags (dnsmasq.h lines 597–602)
// ===========================================================================

bitflags! {
    /// Flags controlling address list entry behavior.
    ///
    /// Replaces: `ADDRLIST_*` constants from `dnsmasq.h` lines 597–602.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct AddrListFlags: i32 {
        /// Address is a literal (not derived from interface).
        const LITERAL   = 1;
        /// Address is IPv6.
        const IPV6      = 2;
        /// Address used for reverse-lookup only.
        const REVONLY   = 4;
        /// Address includes a prefix length.
        const PREFIX    = 8;
        /// Wildcard address match.
        const WILDCARD  = 16;
        /// Address has been declined (DHCP).
        const DECLINED  = 32;
    }
}

// ===========================================================================
// AddrList — Address list entry (dnsmasq.h struct addrlist, lines 604–609)
// ===========================================================================

/// Address list entry for zone subnets, exclusions, and interface addresses.
///
/// Replaces C `struct addrlist` (`dnsmasq.h` lines 604–609).
/// The `next` pointer is removed — entries are stored in `Vec<AddrList>`.
#[derive(Debug, Clone)]
pub struct AddrList {
    /// The address (IPv4 or IPv6).
    pub addr: AllAddr,
    /// Flags controlling this entry's behavior.
    pub flags: AddrListFlags,
    /// Prefix length for subnet matching.
    pub prefixlen: i32,
    /// Time when a DHCP decline was received (seconds since epoch).
    pub decline_time: i64,
}

// ===========================================================================
// BogusAddr — Bogus address entry (dnsmasq.h struct bogus_addr, lines 537–541)
// ===========================================================================

/// An address configured as "bogus" — responses containing these addresses
/// are rejected as likely DNS rebinding attacks.
///
/// Replaces C `struct bogus_addr` (`dnsmasq.h` lines 537–541).
/// The `next` pointer is removed.
#[derive(Debug, Clone)]
pub struct BogusAddr {
    /// Whether this is an IPv6 address (true) or IPv4 (false).
    pub is6: bool,
    /// Prefix length for subnet matching.
    pub prefix: i32,
    /// The bogus address (IPv4 or IPv6).
    pub addr: AllAddr,
}

// ===========================================================================
// DnsDoctor — DNS address rewriting (dnsmasq.h struct doctor, lines 544–547)
// ===========================================================================

/// DNS doctor rule for rewriting addresses in DNS responses.
///
/// When a response contains an IPv4 address matching the range
/// `[addr_in, addr_end]`, it is rewritten using `addr_out` and `mask`.
///
/// Replaces C `struct doctor` (`dnsmasq.h` lines 544–547).
/// The `next` pointer is removed.
#[derive(Debug, Clone)]
pub struct DnsDoctor {
    /// Start of the address range to match.
    pub addr_in: Ipv4Addr,
    /// End of the address range to match.
    pub addr_end: Ipv4Addr,
    /// Output address (bitwise OR with original after masking).
    pub addr_out: Ipv4Addr,
    /// Mask applied during address rewriting.
    pub mask: Ipv4Addr,
}

// ===========================================================================
// MxSrvRecord — MX and SRV record config (dnsmasq.h lines 549–554)
// ===========================================================================

/// Configured MX or SRV record for local DNS responses.
///
/// Replaces C `struct mx_srv_record` (`dnsmasq.h` lines 549–554).
/// The `next` pointer is removed.
#[derive(Debug, Clone)]
pub struct MxSrvRecord {
    /// Domain name this record is associated with.
    pub name: String,
    /// Target hostname for MX or SRV.
    pub target: String,
    /// `true` if this is an SRV record, `false` for MX.
    pub is_srv: bool,
    /// SRV port number.
    pub srvport: i32,
    /// MX priority or SRV priority.
    pub priority: i32,
    /// SRV weight.
    pub weight: i32,
    /// Byte offset for DNS name compression.
    pub offset: u32,
}

// ===========================================================================
// TxtRecord — TXT record config (dnsmasq.h struct txt_record, lines 572–578)
// ===========================================================================

/// Configured TXT record for local DNS responses.
///
/// Replaces C `struct txt_record` (`dnsmasq.h` lines 572–578).
/// The `next` pointer is removed. The `len` field from C is implicit
/// in the `Vec<u8>` length.
#[derive(Debug, Clone)]
pub struct TxtRecord {
    /// Domain name this record is associated with.
    pub name: String,
    /// TXT record data (one or more character-strings).
    pub txt: Vec<u8>,
    /// DNS class (normally `C_IN = 1`, may be `C_CHAOS = 3` for version.bind).
    pub class: u16,
    /// Statistics category (non-zero for auto-generated server stats TXT).
    pub stat: i32,
}

// ===========================================================================
// PtrRecord — PTR record config (dnsmasq.h struct ptr_record, lines 580–583)
// ===========================================================================

/// Configured PTR record for reverse-DNS responses.
///
/// Replaces C `struct ptr_record` (`dnsmasq.h` lines 580–583).
/// The `next` pointer is removed.
#[derive(Debug, Clone)]
pub struct PtrRecord {
    /// The PTR query name (typically an in-addr.arpa or ip6.arpa name).
    pub name: String,
    /// The target hostname this PTR points to.
    pub ptr: String,
}

// ===========================================================================
// CnameRecord — CNAME alias config (dnsmasq.h struct cname, lines 585–589)
// ===========================================================================

/// Configured CNAME alias for local DNS responses.
///
/// Replaces C `struct cname` (`dnsmasq.h` lines 585–589).
/// The `next` and `targetp` pointers are removed.
#[derive(Debug, Clone)]
pub struct CnameRecord {
    /// TTL override (-1 to use default).
    pub ttl: i32,
    /// Configuration flags.
    pub flag: i32,
    /// The alias name (source of the CNAME).
    pub alias: String,
    /// The canonical target name.
    pub target: String,
}

// ===========================================================================
// DsConfig — DNSSEC DS trust anchor (dnsmasq.h struct ds_config, lines 591–595)
// ===========================================================================

/// Configured DNSSEC DS (Delegation Signer) trust anchor.
///
/// Used for configuring explicit trust anchors via `--trust-anchor`.
///
/// Replaces C `struct ds_config` (`dnsmasq.h` lines 591–595).
/// The `next` pointer is removed. The `digestlen` field from C is
/// implicit in the `Vec<u8>` length.
#[derive(Debug, Clone)]
pub struct DsConfig {
    /// Domain name the DS record applies to.
    pub name: String,
    /// DS digest data.
    pub digest: Vec<u8>,
    /// DNS class (normally `C_IN = 1`).
    pub class: i32,
    /// DNSSEC algorithm number (RFC 8624).
    pub algo: i32,
    /// Key tag identifying the DNSKEY record.
    pub keytag: i32,
    /// Digest type (1 = SHA-1, 2 = SHA-256, 4 = SHA-384).
    pub digest_type: i32,
}

// ===========================================================================
// AuthNameEntry + AuthZone — Authoritative DNS zones (dnsmasq.h lines 614–624)
// ===========================================================================

/// Interface name entry within an authoritative zone configuration.
///
/// Replaces C `struct auth_name_list` (`dnsmasq.h` lines 616–620).
/// The `next` pointer is removed.
#[derive(Debug, Clone)]
pub struct AuthNameEntry {
    /// Interface or domain name.
    pub name: String,
    /// Flags (AUTH6=1, AUTH4=2).
    pub flags: i32,
}

/// Authoritative DNS zone configuration.
///
/// Defines a zone for which dnsmasq acts as an authoritative name server,
/// serving records from hosts-file and DHCP lease data.
///
/// Replaces C `struct auth_zone` (`dnsmasq.h` lines 614–624).
/// The `next` pointer is removed.
#[derive(Debug, Clone)]
pub struct AuthZone {
    /// The domain served by this zone (e.g., "example.com").
    pub domain: String,
    /// Interface names that contribute addresses to this zone.
    pub interface_names: Vec<AuthNameEntry>,
    /// Subnet ranges included in this zone.
    pub subnet: Vec<AddrList>,
    /// Subnet ranges excluded from this zone.
    pub exclude: Vec<AddrList>,
}

// ===========================================================================
// HostRecord — Static host record (dnsmasq.h struct host_record, lines 629–638)
// ===========================================================================

/// Static host record defined via `--host-record` configuration.
///
/// Associates one or more hostnames with IPv4 and/or IPv6 addresses.
///
/// Replaces C `struct host_record` (`dnsmasq.h` lines 629–638).
/// The `next` pointer and inner `struct name_list` linked list are replaced
/// by `Vec<String>`.
#[derive(Debug, Clone)]
pub struct HostRecord {
    /// TTL override (-1 to use default).
    pub ttl: i32,
    /// Flags (HR_6=1 for IPv6, HR_4=2 for IPv4).
    pub flags: i32,
    /// Hostnames associated with this record.
    pub names: Vec<String>,
    /// IPv4 address for A records.
    pub addr: Ipv4Addr,
    /// IPv6 address for AAAA records.
    pub addr6: Ipv6Addr,
}

// ===========================================================================
// RrList — Resource record type list (dnsmasq.h struct rrlist, lines 872–875)
// ===========================================================================

/// Entry in a list of DNS resource record types.
///
/// Used for filtering or selecting specific RR types.
///
/// Replaces C `struct rrlist` (`dnsmasq.h` lines 872–875).
/// The `next` pointer is removed — stored in `Vec<RrList>`.
#[derive(Debug, Clone)]
pub struct RrList {
    /// DNS resource record type code (e.g., 1=A, 28=AAAA).
    pub rr: u16,
}

// ===========================================================================
// Subnet — EDNS0 client subnet (dnsmasq.h struct mysubnet, lines 878–882)
// ===========================================================================

/// EDNS0 client subnet configuration.
///
/// Used for the `--add-subnet` option that adds ECS (EDNS Client Subnet,
/// RFC 7871) data to upstream queries.
///
/// Replaces C `struct mysubnet` (`dnsmasq.h` lines 878–882).
#[derive(Debug, Clone)]
pub struct Subnet {
    /// Source address for the subnet.
    pub addr: SocketAddress,
    /// Whether the address has been populated (non-zero if valid).
    pub addr_used: i32,
    /// Prefix length (subnet mask) to include in ECS option.
    pub mask: i32,
}

// ===========================================================================
// ResolvConf — resolv.conf file tracking (dnsmasq.h struct resolvc, lines 885–895)
// ===========================================================================

/// Resolv.conf file tracker for monitoring upstream DNS server changes.
///
/// Tracks the modification time and inode of `resolv.conf` (or files specified
/// via `--resolv-file`) to detect when upstream DNS servers change.
///
/// Replaces C `struct resolvc` (`dnsmasq.h` lines 885–895).
/// The `next` pointer is removed.
#[derive(Debug, Clone)]
pub struct ResolvConf {
    /// Whether this is the default `/etc/resolv.conf` entry.
    pub is_default: bool,
    /// Whether this file has been logged (to avoid repeated messages).
    pub logged: bool,
    /// Last-seen modification time (seconds since epoch).
    pub mtime: i64,
    /// Inode number for change detection.
    pub ino: u64,
    /// Path to the resolv.conf file.
    pub name: String,
    /// Inotify watch descriptor (Linux-specific).
    #[cfg(feature = "inotify_monitor")]
    pub wd: i32,
    /// Pointer to the file component of the path (for inotify directory watches).
    #[cfg(feature = "inotify_monitor")]
    pub file: Option<String>,
}

// ===========================================================================
// HostsFileFlags — Hosts file flags (dnsmasq.h lines 898–903)
// ===========================================================================

bitflags! {
    /// Flags for hosts file and dynamic directory entries.
    ///
    /// Replaces: `AH_*` constants from `dnsmasq.h` lines 898–903.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct HostsFileFlags: i32 {
        /// Entry is a directory (not a single file).
        const DIR       = 1;
        /// Entry is currently inactive.
        const INACTIVE  = 2;
        /// Inotify watch descriptor has been set up.
        const WD_DONE   = 4;
        /// File contains host-address mappings (hosts format).
        const HOSTS     = 8;
        /// File contains DHCP host definitions.
        const DHCP_HST  = 16;
        /// File contains DHCP option definitions.
        const DHCP_OPT  = 32;
    }
}

// ===========================================================================
// HostsFile — Hosts file entry (dnsmasq.h struct hostsfile, lines 904–909)
// ===========================================================================

/// Hosts file or DHCP configuration file entry.
///
/// Tracks additional hosts files loaded via `--addn-hosts`, `--dhcp-hostsfile`,
/// or `--dhcp-optsfile`.
///
/// Replaces C `struct hostsfile` (`dnsmasq.h` lines 904–909).
/// The `next` pointer is removed.
#[derive(Debug, Clone)]
pub struct HostsFile {
    /// Flags indicating file type and status.
    pub flags: HostsFileFlags,
    /// Path to the file.
    pub fname: String,
    /// Index for matching cache entries back to their source file (logging).
    pub index: u32,
}

// ===========================================================================
// DynDir — Dynamic directory (dnsmasq.h struct dyndir, lines 911–919)
// ===========================================================================

/// Dynamic directory tracked by inotify for automatic reload.
///
/// Replaces C `struct dyndir` (`dnsmasq.h` lines 911–919).
/// The `next` pointer is removed. The inner `struct hostsfile *files`
/// linked list is replaced by `Vec<HostsFile>`.
#[derive(Debug, Clone)]
pub struct DynDir {
    /// Files discovered within this directory.
    pub files: Vec<HostsFile>,
    /// Flags (same domain as `HostsFileFlags` numeric values).
    pub flags: i32,
    /// Path to the watched directory.
    pub dname: String,
    /// Inotify watch descriptor (Linux-specific).
    #[cfg(feature = "inotify_monitor")]
    pub wd: i32,
}

// ===========================================================================
// ServerDetails — Server parsing details (dnsmasq.h lines 1528–1534)
// ===========================================================================

/// Temporary structure used during configuration parsing to collect
/// server address details before creating a [`ServerEntry`].
///
/// Replaces C `struct server_details` (`dnsmasq.h` lines 1528–1534).
/// Pointer-to-pointer fields from C become `Option` types.
#[derive(Debug, Clone)]
pub struct ServerDetails {
    /// Parsed server address (if valid).
    pub addr: Option<SocketAddress>,
    /// Parsed source address for outgoing queries.
    pub source_addr: Option<SocketAddress>,
    /// Interface name to bind to.
    pub interface: Option<String>,
    /// Source interface name.
    pub source: Option<String>,
    /// IPv6 scope ID string.
    pub scope_id: Option<String>,
    /// Interface option from command line.
    pub interface_opt: Option<String>,
    /// Server port number.
    pub serv_port: i32,
    /// Source port number.
    pub source_port: i32,
    /// Address type indicator.
    pub addr_type: i32,
    /// Numeric scope index for IPv6 link-local addresses.
    pub scope_index: i32,
    /// Whether this configuration entry is valid.
    pub valid: bool,
    /// Server flags being constructed.
    pub flags: ServerFlags,
}

// ===========================================================================
// DumpFlags — Packet dump flags (dnsmasq.h lines 921–933)
// ===========================================================================

bitflags! {
    /// Flags selecting which packet types to dump to the pcap file.
    ///
    /// Used with the `--dumpfile` / `--dumpmask` options to control
    /// packet capture for debugging.
    ///
    /// Replaces: `DUMP_*` constants from `dnsmasq.h` lines 922–933.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct DumpFlags: u16 {
        /// Dump incoming DNS queries from clients.
        const QUERY       = 0x0001;
        /// Dump outgoing DNS replies to clients.
        const REPLY       = 0x0002;
        /// Dump outgoing DNS queries to upstream servers.
        const UP_QUERY    = 0x0004;
        /// Dump incoming DNS replies from upstream servers.
        const UP_REPLY    = 0x0008;
        /// Dump DNSSEC validation queries.
        const SEC_QUERY   = 0x0010;
        /// Dump DNSSEC validation replies.
        const SEC_REPLY   = 0x0020;
        /// Dump packets flagged as bogus.
        const BOGUS       = 0x0040;
        /// Dump DNSSEC packets flagged as bogus.
        const SEC_BOGUS   = 0x0080;
        /// Dump DHCPv4 packets.
        const DHCP        = 0x1000;
        /// Dump DHCPv6 packets.
        const DHCPV6      = 0x2000;
        /// Dump Router Advertisement packets.
        const RA          = 0x4000;
        /// Dump TFTP packets.
        const TFTP        = 0x8000;
    }
}

// ===========================================================================
// Event — Async event types (dnsmasq.h lines 357–382)
// ===========================================================================

/// Asynchronous event types passed through the self-pipe signal mechanism.
///
/// Signals caught by the signal handler are translated into events written
/// to a pipe. The main event loop reads these events and dispatches them.
///
/// Replaces: `EVENT_*` constants from `dnsmasq.h` lines 357–382.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum Event {
    /// SIGHUP received: reload configuration files.
    Reload    = 1,
    /// SIGUSR2 received: dump server statistics.
    Dump      = 2,
    /// Alarm timer expired.
    Alarm     = 3,
    /// SIGTERM/SIGINT received: graceful shutdown.
    Term      = 4,
    /// SIGCHLD received: child process exited.
    Child     = 5,
    /// Reopen log file (after log rotation).
    Reopen    = 6,
    /// Helper process exited normally.
    Exited    = 7,
    /// Helper process was killed by a signal.
    Killed    = 8,
    /// Helper process exec() failed.
    ExecErr   = 9,
    /// Pipe communication error with helper.
    PipeErr   = 10,
    /// User lookup error during privilege drop.
    UserErr   = 11,
    /// Capability setting error during privilege drop.
    CapErr    = 12,
    /// PID file creation error.
    PidFile   = 13,
    /// Helper user lookup error.
    HuserErr  = 14,
    /// Group lookup error during privilege drop.
    GroupErr  = 15,
    /// Fatal error — daemon must exit.
    Die       = 16,
    /// Log subsystem error.
    LogErr    = 17,
    /// Fork error during daemonization.
    ForkErr   = 18,
    /// Lua script error.
    LuaErr    = 19,
    /// TFTP error.
    TftpErr   = 20,
    /// Initialization complete.
    Init      = 21,
    /// New network address detected (netlink).
    NewAddr   = 22,
    /// New network route detected (netlink).
    NewRoute  = 23,
    /// System time error.
    TimeErr   = 24,
    /// Script produced log output.
    ScriptLog = 25,
    /// Time-related event.
    Time      = 26,
}

// ===========================================================================
// EventDesc — Event descriptor (dnsmasq.h struct event_desc, lines 353–355)
// ===========================================================================

/// Descriptor for an asynchronous event read from the self-pipe.
///
/// Events are written atomically by signal handlers and read by the
/// main event loop for dispatch.
///
/// Replaces C `struct event_desc` (`dnsmasq.h` lines 353–355).
#[derive(Debug, Clone, Copy)]
pub struct EventDesc {
    /// Event type (corresponds to [`Event`] discriminant values).
    pub event: i32,
    /// Event-specific data payload (e.g., exit status, signal number).
    pub data: i32,
    /// Message size for variable-length event data (0 if none).
    pub msg_sz: i32,
}

// ===========================================================================
// Exit code constants (dnsmasq.h lines 384–391)
// ===========================================================================

/// Exit code: successful termination.
pub const EC_GOOD: i32 = 0;

/// Exit code: bad configuration (syntax error, invalid option).
pub const EC_BADCONF: i32 = 1;

/// Exit code: network error (bind failure, interface error).
pub const EC_BADNET: i32 = 2;

/// Exit code: file error (cannot open config/lease file).
pub const EC_FILE: i32 = 3;

/// Exit code: memory allocation failure.
pub const EC_NOMEM: i32 = 4;

/// Exit code: miscellaneous error.
pub const EC_MISC: i32 = 5;

/// Exit code offset for init-phase errors (added to base exit codes).
pub const EC_INIT_OFFSET: i32 = 10;

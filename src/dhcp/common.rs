//! Shared DHCP utilities for DHCPv4 and DHCPv6 implementations.
//!
//! This module replaces `src/dhcp-common.c` (2337 lines) as the shared DHCP
//! utilities module. It provides common functionality used by both DHCPv4
//! (`v4/server.rs`, `v4/rfc2131.rs`) and DHCPv6 (`v6/server.rs`, `v6/rfc3315.rs`)
//! implementations, including:
//!
//! - **DHCP option definition tables:** Complete `opttab[]` and `opttab6[]` with
//!   80+ DHCPv4 and 30+ DHCPv6 option definitions
//! - **Packet reception:** `recv_dhcp_packet()` with automatic buffer expansion
//! - **Tag-based configuration:** `match_netid()`, `match_netid_wild()`, `run_tag_if()`
//!   for client classification
//! - **Option filtering:** `option_filter()` with priority-based tag matching
//! - **Config lookup:** `find_config()` with two-pass tag matching strategy
//! - **Hostname sanitization:** `strip_hostname()` for RFC-compliant name processing
//! - **Transaction logging:** `log_tags()`, `log_context()`, `log_relay()`
//!
//! # Feature Gates
//! - Module-level: `#[cfg(any(feature = "dhcp", feature = "dhcp6"))]`
//! - DHCPv6-specific code gated by `#[cfg(feature = "dhcp6")]`
//!
//! # Source Reference
//! Primary: `src/dhcp-common.c` lines 107–2337

use std::fmt;
use std::io;
use std::io::IoSliceMut;
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::io::RawFd;

use log::{debug, info, warn};
use nix::sys::socket::{self, MsgFlags, SockaddrStorage};

use crate::core::util::{hostname_isequal, legal_hostname};
use crate::dhcp::protocol_v4::{DhcpPacket, DHCP_BUFF_SZ};
#[cfg(feature = "dhcp6")]
use crate::dhcp::protocol_v6;
use crate::types::addr::{AllAddr, SocketAddress};
use crate::types::dhcp::{
    DhcpConfig, DhcpConfigFlags, DhcpContext, DhcpContextFlags, DhcpNetId, DhcpOptExtra,
    DhcpOptFlags, DhcpOption, DhcpRelay, RelayAddr, TagIf,
};

// ===========================================================================
// Protocol Enum
// ===========================================================================

/// Identifies the DHCP protocol version for option table selection.
///
/// Used by `lookup_dhcp_opt()`, `lookup_dhcp_len()`, `option_string()`,
/// `display_opts()` / `display_opts6()` to select the appropriate option
/// definition table (DHCPv4 vs DHCPv6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    /// DHCPv4 (RFC 2131 / RFC 2132).
    V4,
    /// DHCPv6 (RFC 3315 and extensions).
    V6,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::V4 => write!(f, "DHCPv4"),
            Protocol::V6 => write!(f, "DHCPv6"),
        }
    }
}

// ===========================================================================
// Option Format Enum
// ===========================================================================

/// DHCP option format descriptor matching C `OT_*` constants.
///
/// Specifies how the value bytes of a DHCP option should be interpreted
/// for display and validation. Replaces the C bitmask flags:
/// `OT_ADDR_LIST`, `OT_NAME`, `OT_RFC1035_NAME`, `OT_INTERNAL`,
/// `OT_DEC`, `OT_TIME`, `OT_CSTRING`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptionFormat {
    /// Variable-length list of IP addresses (4 bytes each for v4, 16 for v6).
    AddrList,
    /// Fixed-size option with the given byte count.
    Fixed(u16),
    /// Human-readable name string.
    DnsName,
    /// DNS name in RFC 1035 compressed wire format.
    Rfc1035Name,
    /// Internal option — not user-configurable.
    Internal,
    /// Decimal number display format.
    Decimal,
    /// Time value display format (seconds, pretty-printed).
    Time,
    /// Counted string (DHCPv6 option with 2-byte length prefix per string).
    CountedString,
    /// Combined formats — fixed-size with additional flags packed.
    Combined(u16),
}

// ===========================================================================
// DhcpOptionDef — Option Definition Table Entry
// ===========================================================================

/// DHCP option definition with name, code, and format information.
///
/// Each entry in the static option tables (`DHCP_V4_OPTIONS`, `DHCP_V6_OPTIONS`)
/// maps an option code to its human-readable name and expected data format.
/// Used by `lookup_dhcp_opt()`, `lookup_dhcp_len()`, `display_opts()`,
/// and `option_string()` for option identification and formatting.
///
/// Replaces: C `struct opttab_t` from `dhcp-common.c` lines 1584–1667.
#[derive(Debug, Clone)]
pub struct DhcpOptionDef {
    /// Human-readable option name (e.g., "netmask", "router", "dns-server").
    pub name: &'static str,
    /// DHCP option code number (0–255 for v4, 0–65535 for v6).
    pub code: u16,
    /// Expected option data format for display and validation.
    pub format: OptionFormat,
}

impl fmt::Display for DhcpOptionDef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name, self.code)
    }
}

// ===========================================================================
// Raw format flags — match C OT_* bitmask values for lookup_dhcp_len
// ===========================================================================

/// C OT_ADDR_LIST bitmask value.
const OT_ADDR_LIST: u16 = 0x8000;
/// C OT_RFC1035_NAME bitmask value.
const OT_RFC1035_NAME: u16 = 0x4000;
/// C OT_INTERNAL bitmask value.
const OT_INTERNAL: u16 = 0x2000;
/// C OT_NAME bitmask value.
const OT_NAME: u16 = 0x1000;
/// C OT_CSTRING bitmask value.
const OT_CSTRING: u16 = 0x0800;
/// C OT_DEC bitmask value.
const OT_DEC: u16 = 0x0400;
/// C OT_TIME bitmask value.
const OT_TIME: u16 = 0x0200;

/// Raw DHCP option table entry matching C `struct opttab_t`.
///
/// The `size` field packs both the byte count (low bits) and format flags
/// (high bits: `OT_ADDR_LIST`, `OT_NAME`, `OT_INTERNAL`, etc.) into a u16.
pub struct RawOptEntry {
    name: &'static str,
    val: u16,
    size: u16,
}

/// Convert a raw size field to an `OptionFormat`.
fn raw_size_to_format(size: u16) -> OptionFormat {
    if size & OT_INTERNAL != 0 {
        // Internal options may also carry other flags (e.g., OT_NAME, OT_ADDR_LIST)
        // but are primarily "internal-only" for user display filtering.
        OptionFormat::Internal
    } else if size & OT_ADDR_LIST != 0 {
        OptionFormat::AddrList
    } else if size & OT_RFC1035_NAME != 0 {
        OptionFormat::Rfc1035Name
    } else if size & OT_NAME != 0 {
        OptionFormat::DnsName
    } else if size & OT_CSTRING != 0 {
        OptionFormat::CountedString
    } else if size & OT_TIME != 0 {
        let fixed = size & 0x00FF;
        if fixed > 0 {
            OptionFormat::Time
        } else {
            OptionFormat::Time
        }
    } else if size & OT_DEC != 0 {
        let fixed = size & 0x00FF;
        if fixed > 0 {
            OptionFormat::Fixed(fixed)
        } else {
            OptionFormat::Decimal
        }
    } else {
        let fixed = size & 0x00FF;
        if fixed > 0 {
            OptionFormat::Fixed(fixed)
        } else {
            OptionFormat::Fixed(0) // variable length
        }
    }
}

// ===========================================================================
// Raw Option Tables — exact transcription from C opttab[]/opttab6[]
// ===========================================================================

/// Raw DHCPv4 option table — exact transcription from C `opttab[]`
/// (dhcp-common.c lines 1584–1667). The `size` field packs both the
/// fixed byte count (low bits) and format flags (high bits).
static RAW_V4_OPTIONS: &[RawOptEntry] = &[
    RawOptEntry { name: "netmask", val: 1, size: OT_ADDR_LIST },
    RawOptEntry { name: "time-offset", val: 2, size: 4 },
    RawOptEntry { name: "router", val: 3, size: OT_ADDR_LIST },
    RawOptEntry { name: "dns-server", val: 6, size: OT_ADDR_LIST },
    RawOptEntry { name: "log-server", val: 7, size: OT_ADDR_LIST },
    RawOptEntry { name: "lpr-server", val: 9, size: OT_ADDR_LIST },
    RawOptEntry { name: "hostname", val: 12, size: OT_INTERNAL | OT_NAME },
    RawOptEntry { name: "boot-file-size", val: 13, size: 2 | OT_DEC },
    RawOptEntry { name: "domain-name", val: 15, size: OT_NAME },
    RawOptEntry { name: "swap-server", val: 16, size: OT_ADDR_LIST },
    RawOptEntry { name: "root-path", val: 17, size: OT_NAME },
    RawOptEntry { name: "extension-path", val: 18, size: OT_NAME },
    RawOptEntry { name: "ip-forward-enable", val: 19, size: 1 },
    RawOptEntry { name: "non-local-source-routing", val: 20, size: 1 },
    RawOptEntry { name: "policy-filter", val: 21, size: OT_ADDR_LIST },
    RawOptEntry { name: "max-datagram-reassembly", val: 22, size: 2 | OT_DEC },
    RawOptEntry { name: "default-ttl", val: 23, size: 1 | OT_DEC },
    RawOptEntry { name: "mtu", val: 26, size: 2 | OT_DEC },
    RawOptEntry { name: "all-subnets-local", val: 27, size: 1 },
    RawOptEntry { name: "broadcast", val: 28, size: OT_INTERNAL | OT_ADDR_LIST },
    RawOptEntry { name: "router-discovery", val: 31, size: 1 },
    RawOptEntry { name: "router-solicitation", val: 32, size: OT_ADDR_LIST },
    RawOptEntry { name: "static-route", val: 33, size: OT_ADDR_LIST },
    RawOptEntry { name: "trailer-encapsulation", val: 34, size: 1 },
    RawOptEntry { name: "arp-timeout", val: 35, size: 4 | OT_DEC },
    RawOptEntry { name: "ethernet-encap", val: 36, size: 1 },
    RawOptEntry { name: "tcp-ttl", val: 37, size: 1 },
    RawOptEntry { name: "tcp-keepalive", val: 38, size: 4 | OT_DEC },
    RawOptEntry { name: "nis-domain", val: 40, size: OT_NAME },
    RawOptEntry { name: "nis-server", val: 41, size: OT_ADDR_LIST },
    RawOptEntry { name: "ntp-server", val: 42, size: OT_ADDR_LIST },
    RawOptEntry { name: "vendor-encap", val: 43, size: OT_INTERNAL },
    RawOptEntry { name: "netbios-ns", val: 44, size: OT_ADDR_LIST },
    RawOptEntry { name: "netbios-dd", val: 45, size: OT_ADDR_LIST },
    RawOptEntry { name: "netbios-nodetype", val: 46, size: 1 },
    RawOptEntry { name: "netbios-scope", val: 47, size: 0 },
    RawOptEntry { name: "x-windows-fs", val: 48, size: OT_ADDR_LIST },
    RawOptEntry { name: "x-windows-dm", val: 49, size: OT_ADDR_LIST },
    RawOptEntry { name: "requested-address", val: 50, size: OT_INTERNAL | OT_ADDR_LIST },
    RawOptEntry { name: "lease-time", val: 51, size: OT_INTERNAL | OT_TIME },
    RawOptEntry { name: "option-overload", val: 52, size: OT_INTERNAL },
    RawOptEntry { name: "message-type", val: 53, size: OT_INTERNAL | OT_DEC },
    RawOptEntry { name: "server-identifier", val: 54, size: OT_INTERNAL | OT_ADDR_LIST },
    RawOptEntry { name: "parameter-request", val: 55, size: OT_INTERNAL },
    RawOptEntry { name: "message", val: 56, size: OT_INTERNAL },
    RawOptEntry { name: "max-message-size", val: 57, size: OT_INTERNAL },
    RawOptEntry { name: "T1", val: 58, size: OT_TIME },
    RawOptEntry { name: "T2", val: 59, size: OT_TIME },
    RawOptEntry { name: "vendor-class", val: 60, size: 0 },
    RawOptEntry { name: "client-id", val: 61, size: OT_INTERNAL },
    RawOptEntry { name: "nis+-domain", val: 64, size: OT_NAME },
    RawOptEntry { name: "nis+-server", val: 65, size: OT_ADDR_LIST },
    RawOptEntry { name: "tftp-server", val: 66, size: OT_NAME },
    RawOptEntry { name: "bootfile-name", val: 67, size: OT_NAME },
    RawOptEntry { name: "mobile-ip-home", val: 68, size: OT_ADDR_LIST },
    RawOptEntry { name: "smtp-server", val: 69, size: OT_ADDR_LIST },
    RawOptEntry { name: "pop3-server", val: 70, size: OT_ADDR_LIST },
    RawOptEntry { name: "nntp-server", val: 71, size: OT_ADDR_LIST },
    RawOptEntry { name: "irc-server", val: 74, size: OT_ADDR_LIST },
    RawOptEntry { name: "user-class", val: 77, size: 0 },
    RawOptEntry { name: "rapid-commit", val: 80, size: 0 },
    RawOptEntry { name: "FQDN", val: 81, size: OT_INTERNAL },
    RawOptEntry { name: "agent-info", val: 82, size: OT_INTERNAL },
    RawOptEntry { name: "last-transaction", val: 91, size: 4 | OT_TIME },
    RawOptEntry { name: "associated-ip", val: 92, size: OT_ADDR_LIST },
    RawOptEntry { name: "client-arch", val: 93, size: 2 | OT_DEC },
    RawOptEntry { name: "client-interface-id", val: 94, size: 0 },
    RawOptEntry { name: "client-machine-id", val: 97, size: 0 },
    RawOptEntry { name: "posix-timezone", val: 100, size: OT_NAME },
    RawOptEntry { name: "tzdb-timezone", val: 101, size: OT_NAME },
    RawOptEntry { name: "ipv6-only", val: 108, size: 4 | OT_DEC },
    RawOptEntry { name: "subnet-select", val: 118, size: OT_INTERNAL },
    RawOptEntry { name: "domain-search", val: 119, size: OT_RFC1035_NAME },
    RawOptEntry { name: "sip-server", val: 120, size: 0 },
    RawOptEntry { name: "classless-static-route", val: 121, size: 0 },
    RawOptEntry { name: "vendor-id-encap", val: 125, size: 0 },
    RawOptEntry { name: "tftp-server-address", val: 150, size: OT_ADDR_LIST },
    RawOptEntry { name: "server-ip-address", val: 255, size: OT_ADDR_LIST },
];

/// Raw DHCPv6 option table — exact transcription from C `opttab6[]`
/// (dhcp-common.c lines 1670–1701).
#[cfg(feature = "dhcp6")]
static RAW_V6_OPTIONS: &[RawOptEntry] = &[
    RawOptEntry { name: "client-id", val: 1, size: OT_INTERNAL },
    RawOptEntry { name: "server-id", val: 2, size: OT_INTERNAL },
    RawOptEntry { name: "ia-na", val: 3, size: OT_INTERNAL },
    RawOptEntry { name: "ia-ta", val: 4, size: OT_INTERNAL },
    RawOptEntry { name: "iaaddr", val: 5, size: OT_INTERNAL },
    RawOptEntry { name: "oro", val: 6, size: OT_INTERNAL },
    RawOptEntry { name: "preference", val: 7, size: OT_INTERNAL | OT_DEC },
    RawOptEntry { name: "unicast", val: 12, size: OT_INTERNAL },
    RawOptEntry { name: "status", val: 13, size: OT_INTERNAL },
    RawOptEntry { name: "rapid-commit", val: 14, size: OT_INTERNAL },
    RawOptEntry { name: "user-class", val: 15, size: OT_INTERNAL | OT_CSTRING },
    RawOptEntry { name: "vendor-class", val: 16, size: OT_INTERNAL | OT_CSTRING },
    RawOptEntry { name: "vendor-opts", val: 17, size: OT_INTERNAL },
    RawOptEntry { name: "sip-server-domain", val: 21, size: OT_RFC1035_NAME },
    RawOptEntry { name: "sip-server", val: 22, size: OT_ADDR_LIST },
    RawOptEntry { name: "dns-server", val: 23, size: OT_ADDR_LIST },
    RawOptEntry { name: "domain-search", val: 24, size: OT_RFC1035_NAME },
    RawOptEntry { name: "nis-server", val: 27, size: OT_ADDR_LIST },
    RawOptEntry { name: "nis+-server", val: 28, size: OT_ADDR_LIST },
    RawOptEntry { name: "nis-domain", val: 29, size: OT_RFC1035_NAME },
    RawOptEntry { name: "nis+-domain", val: 30, size: OT_RFC1035_NAME },
    RawOptEntry { name: "sntp-server", val: 31, size: OT_ADDR_LIST },
    RawOptEntry { name: "information-refresh-time", val: 32, size: OT_TIME },
    RawOptEntry { name: "FQDN", val: 39, size: OT_INTERNAL | OT_RFC1035_NAME },
    RawOptEntry { name: "posix-timezone", val: 41, size: OT_NAME },
    RawOptEntry { name: "tzdb-timezone", val: 42, size: OT_NAME },
    RawOptEntry { name: "ntp-server", val: 56, size: 0 },
    RawOptEntry { name: "bootfile-url", val: 59, size: OT_NAME },
    RawOptEntry { name: "bootfile-param", val: 60, size: OT_CSTRING },
];

// ===========================================================================
// Public Static Option Tables (built from raw entries)
// ===========================================================================

/// Build a `DhcpOptionDef` from a raw entry at compile time isn't possible
/// with complex logic, so we provide accessor functions instead.

/// DHCPv4 option definitions (80+ entries from C `opttab[]`).
///
/// Complete table of all DHCPv4 options recognized by dnsmasq, including
/// option name, code number, and expected data format. Used by
/// `lookup_dhcp_opt()`, `lookup_dhcp_len()`, `display_opts()`, and
/// `option_string()`.
pub fn dhcp_v4_options() -> Vec<DhcpOptionDef> {
    RAW_V4_OPTIONS
        .iter()
        .map(|e| DhcpOptionDef {
            name: e.name,
            code: e.val,
            format: raw_size_to_format(e.size),
        })
        .collect()
}

/// Provide a static reference-like accessor for DHCPv4 options.
/// Uses the raw table directly for lookups without allocation.
pub static DHCP_V4_OPTIONS: &[RawOptEntry] = RAW_V4_OPTIONS;

/// DHCPv6 option definitions (30+ entries from C `opttab6[]`).
#[cfg(feature = "dhcp6")]
pub static DHCP_V6_OPTIONS: &[RawOptEntry] = RAW_V6_OPTIONS;

// ===========================================================================
// DhcpBuffers — Shared DHCP Buffer Management
// ===========================================================================

/// Shared DHCP buffers used by both DHCPv4 and DHCPv6 packet processing.
///
/// Provides pre-allocated buffers for DHCP option data manipulation and
/// packet reception. Replaces the C global `daemon->dhcp_buff`,
/// `daemon->dhcp_buff2`, `daemon->dhcp_buff3`, `daemon->dhcp_packet`,
/// and `daemon->outpacket` buffers.
///
/// # Buffer Purposes
/// - `buff1`/`buff2`/`buff3`: General-purpose 256-byte option buffers for
///   temporary option data storage during packet construction/parsing.
/// - `dhcp_packet`: Expandable buffer for DHCPv4 packet reception.
/// - `outpacket`: Expandable buffer for DHCPv6 response construction
///   (feature-gated to `dhcp6`).
///
/// Replaces: C `dhcp_common_init()` (dhcp-common.c lines 107–123).
#[derive(Debug)]
pub struct DhcpBuffers {
    /// General-purpose DHCP option buffer 1 (DHCP_BUFF_SZ = 256 bytes).
    buff1: Vec<u8>,
    /// General-purpose DHCP option buffer 2.
    buff2: Vec<u8>,
    /// General-purpose DHCP option buffer 3.
    buff3: Vec<u8>,
    /// Expandable packet buffer for DHCPv4 packet reception.
    dhcp_packet: Vec<u8>,
    /// Expandable packet buffer for DHCPv6 response construction.
    #[cfg(feature = "dhcp6")]
    outpacket: Vec<u8>,
}

impl DhcpBuffers {
    /// Create new DHCP buffers with standard initial sizes.
    ///
    /// Allocates three 256-byte option buffers and packet buffers sized to
    /// hold at least one `DhcpPacket` structure. This mirrors the C
    /// `dhcp_common_init()` function behavior.
    pub fn new() -> Self {
        let packet_size = mem::size_of::<DhcpPacket>();
        DhcpBuffers {
            buff1: vec![0u8; DHCP_BUFF_SZ],
            buff2: vec![0u8; DHCP_BUFF_SZ],
            buff3: vec![0u8; DHCP_BUFF_SZ],
            dhcp_packet: vec![0u8; packet_size],
            #[cfg(feature = "dhcp6")]
            outpacket: vec![0u8; packet_size],
        }
    }

    /// Get a mutable reference to the packet buffer.
    ///
    /// The packet buffer automatically grows via Vec when larger packets
    /// are received, replacing the C `expand_buf()` mechanism.
    pub fn packet_buffer(&mut self) -> &mut Vec<u8> {
        &mut self.dhcp_packet
    }

    /// Get a mutable reference to option buffer 1.
    pub fn option_buffer(&mut self) -> &mut Vec<u8> {
        &mut self.buff1
    }

    /// Reset all buffers to their initial zeroed state.
    ///
    /// Clears buffer contents without deallocating. Useful between
    /// DHCP transactions to prevent data leakage.
    pub fn reset(&mut self) {
        self.buff1.iter_mut().for_each(|b| *b = 0);
        self.buff2.iter_mut().for_each(|b| *b = 0);
        self.buff3.iter_mut().for_each(|b| *b = 0);
        self.dhcp_packet.iter_mut().for_each(|b| *b = 0);
        #[cfg(feature = "dhcp6")]
        self.outpacket.iter_mut().for_each(|b| *b = 0);
    }
}

/// Initialize shared DHCP buffers.
///
/// Allocates and returns the shared buffer set used throughout DHCP
/// processing. Called once during daemon initialization.
///
/// Replaces: C `dhcp_common_init()` (dhcp-common.c lines 107–123).
pub fn init() -> DhcpBuffers {
    DhcpBuffers::new()
}

// ===========================================================================
// Network ID Tag Matching
// ===========================================================================

/// Check if all required tags in `check` are present in `pool`.
///
/// Core tag-matching function for DHCP client classification. Evaluates
/// whether a configuration item's required tags (check) are satisfied by
/// the client's current tag set (pool).
///
/// # Tag Matching Rules
/// - **Positive tags** (no prefix): ALL must be present in pool (AND logic).
/// - **Negative tags** (`!` or `#` prefix): NONE may be present in pool.
///   The `#` prefix is supported for backwards compatibility.
/// - **Empty check with `tag_not_needed=true`**: Matches (unconditional default).
/// - **Empty check with `tag_not_needed=false`**: Does not match.
///
/// # Arguments
/// - `check`: Required tag list for a configuration item.
/// - `pool`: Client's current tag list from classification.
/// - `tag_not_needed`: If `true`, empty `check` list matches unconditionally.
///
/// # Returns
/// `true` if all positive check tags are found in pool and no negative
/// check tags are found.
///
/// Replaces: C `match_netid()` (dhcp-common.c lines 605–629).
pub fn match_netid(check: &[DhcpNetId], pool: &[DhcpNetId], tag_not_needed: bool) -> bool {
    if check.is_empty() && !tag_not_needed {
        return false;
    }

    for tag in check {
        let net = &tag.net;
        // Check for negation prefix (! or # for backwards compat)
        if !net.starts_with('!') && !net.starts_with('#') {
            // Positive tag: must be present in pool
            let found = pool.iter().any(|p| p.net == *net);
            if !found {
                return false;
            }
        } else {
            // Negative tag: must NOT be present in pool
            let name = &net[1..]; // skip the ! or # prefix
            let found = pool.iter().any(|p| p.net == *name);
            if found {
                return false;
            }
        }
    }

    true
}

/// Match tag lists with wildcard support.
///
/// Extension of `match_netid()` that supports trailing `*` wildcard in
/// check tags for prefix matching. For example, `"vlan*"` matches any
/// pool tag starting with `"vlan"` (e.g., `"vlan1"`, `"vlan42"`).
///
/// # Tag Matching Rules
/// - **Positive wildcard** (`"tag*"`): Matches any pool tag with prefix `"tag"`.
/// - **Positive exact** (`"tag"`): Exact string match required.
/// - **Negative wildcard** (`"!tag*"`): Fails if any pool tag has prefix `"tag"`.
/// - **Negative exact** (`"!tag"`): Fails if `"tag"` is in pool.
///
/// # Returns
/// `true` if all positive tags matched and no negative tags matched.
///
/// Replaces: C `match_netid_wild()` (dhcp-common.c lines 269–295).
pub fn match_netid_wild(check: &[DhcpNetId], pool: &[DhcpNetId]) -> bool {
    for tag in check {
        let net = &tag.net;
        let is_negated = net.starts_with('!') || net.starts_with('#');
        let name = if is_negated { &net[1..] } else { net.as_str() };
        let is_wildcard = name.ends_with('*');
        let prefix = if is_wildcard {
            &name[..name.len() - 1]
        } else {
            name
        };

        if !is_negated {
            // Positive tag: must find a match in pool
            let found = pool.iter().any(|p| {
                if is_wildcard {
                    p.net.starts_with(prefix)
                } else {
                    p.net == *prefix
                }
            });
            if !found {
                return false;
            }
        } else {
            // Negative tag: must NOT find a match in pool
            let found = pool.iter().any(|p| {
                if is_wildcard {
                    p.net.starts_with(prefix)
                } else {
                    p.net == *prefix
                }
            });
            if found {
                return false;
            }
        }
    }

    true
}

/// Evaluate conditional tag-if rules to derive additional tags.
///
/// Iterates through `tag_if_rules`, and for each rule whose trigger
/// condition (rule.tag) matches the current tag set (using wildcard
/// matching), adds the rule's derived tags (rule.set) to the tag list.
///
/// This enables configuration like:
/// ```text
/// tag-if:set:server-pool-A,tag:vlan*
/// ```
/// Meaning: if any tag matching `"vlan*"` is present, also add
/// `"server-pool-A"` to the tag set.
///
/// # Arguments
/// - `tags`: Current tag list (modified in-place with derived tags appended).
/// - `tag_if_rules`: Conditional rules from daemon configuration.
///
/// Replaces: C `run_tag_if()` (dhcp-common.c lines 344–361).
pub fn run_tag_if(tags: &mut Vec<DhcpNetId>, tag_if_rules: &[TagIf]) {
    for expr in tag_if_rules {
        if match_netid_wild(&expr.tag, tags) {
            // Add all tag sets from the matched rule
            for tag_set in &expr.set {
                for derived_tag in tag_set {
                    // Avoid duplicates
                    if !tags.iter().any(|t| t.net == derived_tag.net) {
                        tags.push(derived_tag.clone());
                    }
                }
            }
        }
    }
}

// ===========================================================================
// Option Filtering
// ===========================================================================

/// Filter DHCP option based on PXE mode requirements.
///
/// Determines whether a DHCP option should be included in a response based
/// on PXE boot mode:
/// - Mode 0 (Normal DHCP): Exclude PXE-specific options.
/// - Mode 1 (PXE hybrid): Include all options.
/// - Mode 2 (PXE-only): Include ONLY PXE-specific options.
///
/// Replaces: C `pxe_ok()` (dhcp-common.c lines 411–425).
pub fn pxe_ok(opt: &DhcpOption, pxe_mode: i32) -> bool {
    if opt.flags.contains(DhcpOptFlags::PXE_OPT) {
        pxe_mode != 0
    } else {
        pxe_mode != 2
    }
}

/// Filter DHCP options based on tag matching and priority rules.
///
/// Determines which configured DHCP options should be included in the
/// response by evaluating tag matches, context tags, and priority rules.
///
/// # Filtering Passes
/// 1. Flag options matching current tags (without context tags).
/// 2. If `context_tags` provided, re-evaluate with context included.
/// 3. Flag untagged options not overridden by tagged ones.
/// 4. Eliminate duplicate options (keeping higher priority ones).
///
/// Options are marked with `DHOPT_TAGOK` flag if selected for inclusion.
///
/// # Arguments
/// - `tags`: Current tag set from client identification.
/// - `context_tags`: Additional tags from network context (may be empty).
/// - `opts`: All configured DHCP options to filter (modified in-place).
/// - `pxe_mode`: PXE boot mode (0=not PXE, 1=PXE mode 1, 2=PXE mode 2).
/// - `tag_if_rules`: Conditional tag rules for tag expansion.
///
/// Replaces: C `option_filter()` (dhcp-common.c lines 470–540).
pub fn option_filter(
    tags: &[DhcpNetId],
    context_tags: &[DhcpNetId],
    opts: &mut [DhcpOption],
    pxe_mode: i32,
    tag_if_rules: &[TagIf],
) -> Vec<DhcpNetId> {
    // Expand tags via tag-if rules
    let mut tagif = tags.to_vec();
    run_tag_if(&mut tagif, tag_if_rules);

    // Pass 1: Flag options matching current tags (sans context tags)
    for opt in opts.iter_mut() {
        opt.flags.remove(DhcpOptFlags::TAGOK);
        let dominated = opt.flags.intersects(
            DhcpOptFlags::ENCAPSULATE | DhcpOptFlags::VENDOR | DhcpOptFlags::RFC3925,
        );
        if !dominated && match_netid(&opt.netid, &tagif, false) && pxe_ok(opt, pxe_mode) {
            opt.flags.insert(DhcpOptFlags::TAGOK);
        }
    }

    // Pass 2: Re-evaluate with context tags included
    if !context_tags.is_empty() {
        let mut combined = context_tags.to_vec();
        combined.extend_from_slice(tags);
        let mut ctx_tagif = combined;
        run_tag_if(&mut ctx_tagif, tag_if_rules);

        // Reset options that no longer match with combined tags
        for opt in opts.iter_mut() {
            let dominated = opt.flags.intersects(
                DhcpOptFlags::ENCAPSULATE | DhcpOptFlags::VENDOR | DhcpOptFlags::RFC3925,
            );
            if !dominated
                && opt.flags.contains(DhcpOptFlags::TAGOK)
                && !match_netid(&opt.netid, &ctx_tagif, false)
            {
                opt.flags.remove(DhcpOptFlags::TAGOK);
            }
        }

        // Flag options matching context tags that aren't already overridden
        let opt_codes_tagged: Vec<i32> = opts
            .iter()
            .filter(|o| o.flags.contains(DhcpOptFlags::TAGOK))
            .map(|o| o.opt)
            .collect();

        for opt in opts.iter_mut() {
            let dominated = opt.flags.intersects(
                DhcpOptFlags::ENCAPSULATE
                    | DhcpOptFlags::VENDOR
                    | DhcpOptFlags::RFC3925
                    | DhcpOptFlags::TAGOK,
            );
            if !dominated
                && match_netid(&opt.netid, &ctx_tagif, false)
                && pxe_ok(opt, pxe_mode)
                && !opt.netid.is_empty()
            {
                // Only add if no higher-priority tagged option exists
                if !opt_codes_tagged.contains(&opt.opt) {
                    opt.flags.insert(DhcpOptFlags::TAGOK);
                }
            }
        }

        tagif = ctx_tagif;
    }

    // Pass 3: Flag untagged options not overridden by tagged ones
    let tagged_codes: Vec<i32> = opts
        .iter()
        .filter(|o| o.flags.contains(DhcpOptFlags::TAGOK))
        .map(|o| o.opt)
        .collect();

    // Collect duplicates for warning (before mutating)
    let mut dup_warn: Vec<i32> = Vec::new();
    for (i, opt) in opts.iter().enumerate() {
        let dominated = opt.flags.intersects(
            DhcpOptFlags::ENCAPSULATE
                | DhcpOptFlags::VENDOR
                | DhcpOptFlags::RFC3925
                | DhcpOptFlags::TAGOK,
        );
        if !dominated && opt.netid.is_empty() && pxe_ok(opt, pxe_mode)
            && tagged_codes.contains(&opt.opt)
        {
            // Check if there's another untagged option with same code that's already tagged
            let has_dup = opts.iter().enumerate().any(|(j, o)| {
                j != i && o.opt == opt.opt && o.flags.contains(DhcpOptFlags::TAGOK) && o.netid.is_empty()
            });
            if has_dup {
                dup_warn.push(opt.opt);
            }
        }
    }
    for code in &dup_warn {
        warn!("Ignoring duplicate dhcp-option {}", code);
    }

    for opt in opts.iter_mut() {
        let dominated = opt.flags.intersects(
            DhcpOptFlags::ENCAPSULATE
                | DhcpOptFlags::VENDOR
                | DhcpOptFlags::RFC3925
                | DhcpOptFlags::TAGOK,
        );
        if !dominated && opt.netid.is_empty() && pxe_ok(opt, pxe_mode)
            && !tagged_codes.contains(&opt.opt)
        {
            opt.flags.insert(DhcpOptFlags::TAGOK);
        }
    }

    // Pass 4: Eliminate duplicate options (keep first occurrence with TAGOK)
    let mut seen_codes: Vec<i32> = Vec::new();
    let len = opts.len();
    for i in 0..len {
        if opts[i].flags.contains(DhcpOptFlags::TAGOK) {
            if seen_codes.contains(&opts[i].opt) {
                opts[i].flags.remove(DhcpOptFlags::TAGOK);
            } else {
                seen_codes.push(opts[i].opt);
            }
        }
    }

    tagif
}

// ===========================================================================
// Byte Pattern Matching
// ===========================================================================

/// Match DHCP option bytes against a pattern.
///
/// Compares a byte buffer against a DHCP option pattern for client
/// classification. Supports three matching modes:
///
/// 1. **Hex matching** (`DHOPT_HEX`): Masked byte comparison using
///    `wildcard_mask` for flexible pattern matching.
/// 2. **String matching** (`DHOPT_STRING`): Substring search advancing
///    byte-by-byte through the buffer.
/// 3. **Default matching**: Exact match at option-length-aligned boundaries.
///
/// A zero-length pattern matches any buffer (wildcard).
///
/// # Arguments
/// - `opt`: DHCP option containing the match pattern.
/// - `data`: Buffer to search for the pattern.
///
/// # Returns
/// `true` if the pattern is found in the buffer.
///
/// Replaces: C `match_bytes()` (dhcp-common.c lines 797–825).
pub fn match_bytes(opt: &DhcpOption, data: &[u8]) -> bool {
    let pattern_len = opt.len as usize;

    if pattern_len > data.len() {
        return false;
    }
    if pattern_len == 0 {
        return true;
    }

    if opt.flags.contains(DhcpOptFlags::HEX) {
        // Hex mode: masked comparison
        let wildcard = match &opt.extra {
            DhcpOptExtra::WildcardMask(mask) => *mask,
            _ => 0,
        };
        return memcmp_masked(&opt.val[..pattern_len], &data[..pattern_len], wildcard);
    }

    // String or exact mode
    let step = if opt.flags.contains(DhcpOptFlags::STRING) {
        1
    } else {
        pattern_len
    };

    let mut i = 0;
    while i + pattern_len <= data.len() {
        if opt.val[..pattern_len] == data[i..i + pattern_len] {
            return true;
        }
        i += step;
    }

    false
}

/// Compare byte slices with a wildcard bitmask.
///
/// Compares `a` and `b` byte-by-byte, skipping positions where the
/// corresponding bit in `mask` is set (wildcard positions).
/// Returns `true` if all non-masked bytes are equal.
fn memcmp_masked(a: &[u8], b: &[u8], mask: u32) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for (i, (&ab, &bb)) in a.iter().zip(b.iter()).enumerate() {
        // If the bit at position (i % 32) is set in mask, skip this byte
        if mask & (1u32 << (i as u32 % 32)) != 0 {
            continue;
        }
        if ab != bb {
            return false;
        }
    }
    true
}

// ===========================================================================
// Configuration Lookup
// ===========================================================================

/// Check if a DHCP configuration matches a specific hardware (MAC) address.
///
/// Searches the configuration's hardware address list for an exact match
/// (no wildcard) against the given hardware address, length, and type.
///
/// # Arguments
/// - `config`: DHCP configuration entry to check.
/// - `hwaddr`: Client hardware address bytes (e.g., 6-byte MAC).
/// - `hw_type`: Hardware type code (e.g., 1 = Ethernet per RFC 826).
///
/// # Returns
/// `true` if the configuration has a non-wildcard hardware address that
/// matches exactly.
///
/// Replaces: C `config_has_mac()` (dhcp-common.c lines 919–931).
pub fn config_has_mac(config: &DhcpConfig, hwaddr: &[u8], hw_type: u16) -> bool {
    for conf_addr in &config.hwaddr {
        if conf_addr.wildcard_mask == 0
            && conf_addr.hwaddr_len as usize == hwaddr.len()
            && (conf_addr.hwaddr_type == hw_type as i32 || conf_addr.hwaddr_type == 0)
            && conf_addr.hwaddr[..hwaddr.len()] == *hwaddr
        {
            return true;
        }
    }
    false
}

/// Check if a DHCP configuration is valid for a specific network context.
///
/// Validates whether a DHCP client configuration (static lease, host options)
/// is appropriate for the given network segment. For IPv4, checks if the
/// config address falls within the context's subnet. Configurations without
/// a static address apply to all contexts.
///
/// # Arguments
/// - `context`: DHCP context (network segment). `None` means any context.
/// - `config`: DHCP configuration entry to validate.
///
/// # Returns
/// `true` if the configuration applies to the context.
///
/// Replaces: C `is_config_in_context()` (dhcp-common.c lines 1007–1040).
fn is_config_in_context(context: Option<&DhcpContext>, config: &DhcpConfig) -> bool {
    let ctx = match context {
        None => return true, // NULL context: always matches
        Some(c) => c,
    };

    // Configs without static addresses apply everywhere
    let has_v4_addr = config.flags.contains(DhcpConfigFlags::ADDR);
    #[cfg(feature = "dhcp6")]
    let has_v6_addr = config.flags.contains(DhcpConfigFlags::ADDR6);
    #[cfg(not(feature = "dhcp6"))]
    let has_v6_addr = false;

    if !has_v4_addr && !has_v6_addr {
        return true;
    }

    // Check IPv6 context
    #[cfg(feature = "dhcp6")]
    if ctx.flags.contains(DhcpContextFlags::V6) {
        if config.flags.contains(DhcpConfigFlags::ADDR6) && !config.addr6.is_empty() {
            // IPv6 address is present in config; check against context range.
            // For simplicity, accept any config with an IPv6 address for IPv6 contexts.
            // Full prefix matching (is_same_net6) is handled by the caller.
            return true;
        }
        return false;
    }

    // IPv4: check if config address is in context subnet
    if config.flags.contains(DhcpConfigFlags::ADDR) {
        let config_addr_bits = u32::from(config.addr);
        let start_bits = u32::from(ctx.start);
        let mask_bits = u32::from(ctx.netmask);

        if (config_addr_bits & mask_bits) == (start_bits & mask_bits) {
            return true;
        }
    }

    false
}

/// Internal config matching with specified tag matching mode.
///
/// Searches the DHCP configuration list for entries matching the client's
/// identity (client ID, MAC address, hostname) and network context.
///
/// # Matching Precedence
/// 1. Client ID match (if provided)
/// 2. Hardware address exact match
/// 3. Hostname match (if provided and context available)
/// 4. Hardware address wildcard match (best match by bit count)
///
/// Replaces: C `find_config_match()` (dhcp-common.c lines 1097–1164).
fn find_config_match<'a>(
    configs: &'a [DhcpConfig],
    context: Option<&DhcpContext>,
    clid: Option<&[u8]>,
    hwaddr: Option<&[u8]>,
    hw_type: u16,
    hostname: Option<&str>,
    tags: &[DhcpNetId],
    tag_not_needed: bool,
) -> Option<&'a DhcpConfig> {
    // Pass 1: Client ID match
    if let Some(client_id) = clid {
        for config in configs {
            if config.flags.contains(DhcpConfigFlags::CLID)
                && config.clid == client_id
                && is_config_in_context(context, config)
                && match_netid(&config.filter, tags, tag_not_needed)
            {
                return Some(config);
            }

            // Handle dhcpcd bug: ASCII client IDs prefixed by zero byte (IPv4 only)
            let is_v4 = context
                .map(|c| !c.flags.contains(DhcpContextFlags::V6))
                .unwrap_or(true);
            if is_v4
                && !client_id.is_empty()
                && client_id[0] == 0
                && config.clid.len() == client_id.len() - 1
                && config.clid == client_id[1..]
                && is_config_in_context(context, config)
                && match_netid(&config.filter, tags, tag_not_needed)
            {
                return Some(config);
            }
        }
    }

    // Pass 2: Hardware address exact match
    if let Some(hw) = hwaddr {
        for config in configs {
            if config_has_mac(config, hw, hw_type)
                && is_config_in_context(context, config)
                && match_netid(&config.filter, tags, tag_not_needed)
            {
                return Some(config);
            }
        }
    }

    // Pass 3: Hostname match
    if let (Some(name), Some(_ctx)) = (hostname, context) {
        for config in configs {
            if config.flags.contains(DhcpConfigFlags::NAME)
                && config
                    .hostname
                    .as_ref()
                    .is_some_and(|h| hostname_isequal(h, name))
                && is_config_in_context(context, config)
                && match_netid(&config.filter, tags, tag_not_needed)
            {
                return Some(config);
            }
        }
    }

    // Pass 4: Wildcard MAC match (find best match by bit count)
    if let Some(hw) = hwaddr {
        let mut best_count = 0i32;
        let mut candidate: Option<&DhcpConfig> = None;

        for config in configs {
            if !is_config_in_context(context, config)
                || !match_netid(&config.filter, tags, tag_not_needed)
            {
                continue;
            }

            for conf_addr in &config.hwaddr {
                if conf_addr.wildcard_mask != 0
                    && conf_addr.hwaddr_len as usize == hw.len()
                    && (conf_addr.hwaddr_type == hw_type as i32 || conf_addr.hwaddr_type == 0)
                {
                    let count = count_matching_bits(
                        &conf_addr.hwaddr[..hw.len()],
                        hw,
                        conf_addr.wildcard_mask,
                    );
                    if count > best_count {
                        best_count = count;
                        candidate = Some(config);
                    }
                }
            }
        }

        return candidate;
    }

    None
}

/// Count matching non-wildcard bits between two byte arrays.
fn count_matching_bits(a: &[u8], b: &[u8], mask: u32) -> i32 {
    let mut count = 0i32;
    for (i, (&ab, &bb)) in a.iter().zip(b.iter()).enumerate() {
        if mask & (1u32 << (i as u32 % 32)) != 0 {
            // Wildcard byte — still count matching bits for ranking
            count += (!(ab ^ bb)).count_ones() as i32;
        } else if ab == bb {
            count += 8;
        }
    }
    count
}

/// Find DHCP configuration for a client using two-pass tag matching.
///
/// First attempts exact tag matching (tagged configurations get priority),
/// then falls back to wildcard tag matching for less-specific configs.
///
/// # Configuration Precedence
/// - **Pass 1** (exact tags): Configurations with matching network ID tags.
/// - **Pass 2** (wildcard tags): Configurations with no tag requirements.
///
/// Within each pass, `find_config_match()` applies:
/// Client ID > exact MAC > wildcard MAC > hostname
///
/// # Arguments
/// - `configs`: List of DHCP configuration entries to search.
/// - `context`: Current network context (`None` for any context).
/// - `clid`: Client identifier bytes (optional).
/// - `hwaddr`: Hardware address bytes (optional).
/// - `hw_type`: Hardware type code.
/// - `hostname`: Client hostname (optional).
/// - `tags`: Network ID tags for classification.
///
/// # Returns
/// Best matching configuration, or `None` if no match found.
///
/// Replaces: C `find_config()` (dhcp-common.c lines 1228–1240).
pub fn find_config<'a>(
    configs: &'a [DhcpConfig],
    context: Option<&DhcpContext>,
    clid: Option<&[u8]>,
    hwaddr: Option<&[u8]>,
    hw_type: u16,
    hostname: Option<&str>,
    tags: &[DhcpNetId],
) -> Option<&'a DhcpConfig> {
    // Pass 1: exact tag matching
    let ret = find_config_match(configs, context, clid, hwaddr, hw_type, hostname, tags, false);
    if ret.is_some() {
        return ret;
    }
    // Pass 2: wildcard tag matching
    find_config_match(configs, context, clid, hwaddr, hw_type, hostname, tags, true)
}

/// Update DHCP config entries with DNS-resolved addresses from /etc/hosts.
///
/// Processes DHCP configurations that have hostnames but no static IP,
/// attempting to resolve addresses from the DNS cache (populated from
/// /etc/hosts). Maintains the invariant that each IP address appears
/// in at most one dhcp-host configuration.
///
/// This function is typically called during daemon initialization and on
/// SIGHUP configuration reload.
///
/// Replaces: C `dhcp_update_configs()` (dhcp-common.c lines 1288–1390).
pub fn dhcp_update_configs(configs: &mut [DhcpConfig]) {
    // Clear previously imported addresses (CONFIG_ADDR_HOSTS flag)
    for config in configs.iter_mut() {
        if config.flags.contains(DhcpConfigFlags::ADDR_HOSTS) {
            config.flags.remove(DhcpConfigFlags::ADDR | DhcpConfigFlags::ADDR_HOSTS);
        }
        #[cfg(feature = "dhcp6")]
        if config.flags.contains(DhcpConfigFlags::ADDR6_HOSTS) {
            config.flags.remove(DhcpConfigFlags::ADDR6 | DhcpConfigFlags::ADDR6_HOSTS);
        }
    }

    // In the full implementation, this would query the DNS cache for
    // hostnames in each config and import matching addresses.
    // For now, the structure is in place for integration with the DNS
    // cache module when it becomes available.
    //
    // The C implementation uses cache_find_by_name() to look up addresses
    // and config_find_by_address() to check for duplicates. These will be
    // wired up when the dns::cache module is integrated.
    debug!("dhcp_update_configs: processed {} config entries", configs.len());
}

// ===========================================================================
// Hostname Utilities
// ===========================================================================

/// Strip domain suffix from hostname, leaving only the short hostname.
///
/// Finds the first dot in the hostname and splits at that point. Returns
/// the domain suffix if present and non-empty, or `None` otherwise.
///
/// Unlike the C version which modifies the string in-place, this returns
/// an owned tuple `(short_hostname, Option<domain>)`.
///
/// # Examples
/// ```text
/// "myhost.example.com" -> Some(("myhost", Some("example.com")))
/// "myhost" -> Some(("myhost", None))
/// "" -> None
/// ```
///
/// Replaces: C `strip_hostname()` (dhcp-common.c lines 660–672).
pub fn strip_hostname(hostname: &str) -> Option<String> {
    if hostname.is_empty() {
        return None;
    }

    // Validate hostname characters
    if !legal_hostname(hostname) {
        return None;
    }

    // Find the first dot and split there
    if let Some(dot_pos) = hostname.find('.') {
        let short = &hostname[..dot_pos];
        if short.is_empty() {
            return None;
        }
        // Return just the short hostname (domain is stripped)
        Some(short.to_lowercase())
    } else {
        // No dot: return the full hostname lowercased
        Some(hostname.to_lowercase())
    }
}

// ===========================================================================
// Option Lookup Functions
// ===========================================================================

/// Look up a DHCP option code by its human-readable name.
///
/// Performs a case-insensitive search through the appropriate option table
/// (DHCPv4 or DHCPv6) and returns the option code if found.
///
/// # Arguments
/// - `protocol`: Which option table to search (`V4` or `V6`).
/// - `name`: Human-readable option name (case-insensitive).
///
/// # Returns
/// Option code if found, `None` if not recognized.
///
/// Replaces: C `lookup_dhcp_opt()` (dhcp-common.c lines 1850–1869).
pub fn lookup_dhcp_opt(protocol: Protocol, name: &str) -> Option<u16> {
    let table: &[RawOptEntry] = match protocol {
        Protocol::V4 => RAW_V4_OPTIONS,
        #[cfg(feature = "dhcp6")]
        Protocol::V6 => RAW_V6_OPTIONS,
        #[cfg(not(feature = "dhcp6"))]
        Protocol::V6 => return None,
    };

    for entry in table {
        if entry.name.eq_ignore_ascii_case(name) {
            return Some(entry.val);
        }
    }
    None
}

/// Look up expected length/size for a DHCP option code.
///
/// Returns the expected byte size for fixed-length options, or 0 for
/// variable-length options. The result masks out format flags to return
/// only the numeric size component.
///
/// # Arguments
/// - `protocol`: Which option table to search.
/// - `code`: DHCP option code to look up.
///
/// # Returns
/// Expected length in bytes, or 0 for variable-length/unknown options.
///
/// Replaces: C `lookup_dhcp_len()` (dhcp-common.c lines 1918–1937).
pub fn lookup_dhcp_len(protocol: Protocol, code: u16) -> Option<u16> {
    let table: &[RawOptEntry] = match protocol {
        Protocol::V4 => RAW_V4_OPTIONS,
        #[cfg(feature = "dhcp6")]
        Protocol::V6 => RAW_V6_OPTIONS,
        #[cfg(not(feature = "dhcp6"))]
        Protocol::V6 => return None,
    };

    for entry in table {
        if entry.val == code {
            // Mask out format flags, return only the numeric size component
            let size = entry.size & !(OT_DEC | OT_TIME | OT_ADDR_LIST | OT_NAME
                | OT_RFC1035_NAME | OT_INTERNAL | OT_CSTRING);
            return Some(size);
        }
    }
    None
}

/// Display all known DHCPv4 option names to stdout.
///
/// Prints a list of user-visible (non-internal) DHCPv4 option codes and
/// their names. Used by `--help-dhcp` CLI option.
///
/// Replaces: C `display_opts()` (dhcp-common.c lines 1742–1751).
pub fn display_opts() {
    println!("Known DHCP options:");
    for entry in RAW_V4_OPTIONS {
        if entry.size & OT_INTERNAL == 0 {
            println!("{:3} {}", entry.val, entry.name);
        }
    }
}

/// Display all known DHCPv6 option names to stdout.
///
/// Prints a list of user-visible (non-internal) DHCPv6 option codes and
/// their names. Used by `--help-dhcp6` CLI option.
///
/// Replaces: C `display_opts6()` (dhcp-common.c lines 1793–1801).
#[cfg(feature = "dhcp6")]
pub fn display_opts6() {
    println!("Known DHCPv6 options:");
    for entry in RAW_V6_OPTIONS {
        if entry.size & OT_INTERNAL == 0 {
            println!("{:3} {}", entry.val, entry.name);
        }
    }
}

/// Format DHCP option value as a human-readable string.
///
/// Converts raw DHCP option data into a human-readable representation
/// for logging and debugging. Formatting depends on the option type:
/// - Address lists: Comma-separated dotted-decimal (v4) or hex (v6)
/// - Names: Printable characters only
/// - Decimal numbers: Unsigned integer representation
/// - Time values: Pretty-printed duration
/// - Unknown/binary: Colon-separated hex bytes (truncated at 14 bytes)
///
/// # Arguments
/// - `protocol`: DHCPv4 or DHCPv6 for option table selection.
/// - `opt`: DHCP option code.
/// - `val`: Raw option data bytes.
/// - `buf`: Output buffer for the formatted string.
///
/// # Returns
/// The option name if known, or an empty string.
///
/// Replaces: C `option_string()` (dhcp-common.c lines 2005–2127).
pub fn option_string(protocol: Protocol, opt: u16, val: &[u8], buf: &mut String) -> &'static str {
    buf.clear();

    let table: &[RawOptEntry] = match protocol {
        Protocol::V4 => RAW_V4_OPTIONS,
        #[cfg(feature = "dhcp6")]
        Protocol::V6 => RAW_V6_OPTIONS,
        #[cfg(not(feature = "dhcp6"))]
        Protocol::V6 => {
            format_hex_bytes(val, buf);
            return "";
        }
    };

    // Find option in table
    let mut found_entry: Option<&RawOptEntry> = None;
    for entry in table {
        if entry.val == opt {
            found_entry = Some(entry);
            break;
        }
    }

    let entry = match found_entry {
        Some(e) => e,
        None => {
            // Unknown option: format as hex
            format_hex_bytes(val, buf);
            return "";
        }
    };

    if val.is_empty() {
        return entry.name;
    }

    let size = entry.size;

    if size & OT_ADDR_LIST != 0 {
        // Format as IP address list
        let addr_len = match protocol {
            Protocol::V4 => 4usize,
            Protocol::V6 => 16usize,
        };
        let mut first = true;
        let mut i = 0;
        while i + addr_len <= val.len() {
            if !first {
                buf.push_str(", ");
            }
            first = false;
            match protocol {
                Protocol::V4 => {
                    if i + 4 <= val.len() {
                        let addr = Ipv4Addr::new(val[i], val[i + 1], val[i + 2], val[i + 3]);
                        buf.push_str(&addr.to_string());
                    }
                }
                Protocol::V6 => {
                    if i + 16 <= val.len() {
                        let mut octets = [0u8; 16];
                        octets.copy_from_slice(&val[i..i + 16]);
                        let addr = Ipv6Addr::from(octets);
                        buf.push_str(&addr.to_string());
                    }
                }
            }
            i += addr_len;
        }
    } else if size & OT_NAME != 0 {
        // Format as printable string
        for &b in val {
            let c = b as char;
            if c.is_ascii_graphic() || c == ' ' {
                buf.push(c);
            }
        }
    } else if size & OT_RFC1035_NAME != 0 {
        // Decode RFC 1035 wire-format name
        #[cfg(feature = "dhcp6")]
        if matches!(protocol, Protocol::V6) {
            decode_rfc1035_name(val, buf);
        }
    } else if size & OT_CSTRING != 0 {
        // Counted string format (DHCPv6)
        #[cfg(feature = "dhcp6")]
        decode_counted_string(val, buf);
    } else if (size & (OT_DEC | OT_TIME)) != 0 && !val.is_empty() {
        // Decimal or time value
        let mut dec: u32 = 0;
        for &b in val {
            dec = (dec << 8) | b as u32;
        }
        if size & OT_TIME != 0 {
            prettyprint_time(buf, dec);
        } else {
            buf.push_str(&dec.to_string());
        }
    } else {
        // Default: hex dump
        format_hex_bytes(val, buf);
    }

    entry.name
}

/// Format bytes as colon-separated hex string, truncating at 14 bytes.
fn format_hex_bytes(val: &[u8], buf: &mut String) {
    let truncated = val.len() > 14;
    let display_len = if truncated { 14 } else { val.len() };
    for (i, &b) in val[..display_len].iter().enumerate() {
        if i > 0 {
            buf.push(':');
        }
        buf.push_str(&format!("{:02x}", b));
    }
    if truncated {
        buf.push_str("...");
    }
}

/// Pretty-print a time duration in seconds.
fn prettyprint_time(buf: &mut String, mut secs: u32) {
    if secs == 0 {
        buf.push_str("0s");
        return;
    }

    if secs >= 86400 {
        let days = secs / 86400;
        buf.push_str(&format!("{}d", days));
        secs %= 86400;
    }
    if secs >= 3600 {
        let hours = secs / 3600;
        buf.push_str(&format!("{}h", hours));
        secs %= 3600;
    }
    if secs >= 60 {
        let mins = secs / 60;
        buf.push_str(&format!("{}m", mins));
        secs %= 60;
    }
    if secs > 0 {
        buf.push_str(&format!("{}s", secs));
    }
}

/// Decode an RFC 1035 wire-format domain name sequence.
#[cfg(feature = "dhcp6")]
fn decode_rfc1035_name(val: &[u8], buf: &mut String) {
    let mut i = 0;
    while i < val.len() && val[i] != 0 {
        let label_len = val[i] as usize;
        i += 1;
        let end = (i + label_len).min(val.len());
        for &b in &val[i..end] {
            let c = b as char;
            if c.is_ascii_graphic() || c == '-' {
                buf.push(c);
            }
        }
        i = end;
        if i < val.len() && val[i] != 0 {
            buf.push('.');
        }
    }
}

/// Decode a counted-string format (DHCPv6 option with 2-byte length prefix).
#[cfg(feature = "dhcp6")]
fn decode_counted_string(val: &[u8], buf: &mut String) {
    let mut i = 0;
    let mut first = true;
    while i + 2 <= val.len() {
        let len = ((val[i] as usize) << 8) | val[i + 1] as usize;
        i += 2;
        if !first {
            buf.push(',');
        }
        first = false;
        let end = (i + len).min(val.len());
        for &b in &val[i..end] {
            let c = b as char;
            if c.is_ascii_graphic() || c == ' ' {
                buf.push(c);
            }
        }
        i = end;
    }
}

// ===========================================================================
// Packet Reception and Device Binding
// ===========================================================================

/// Ancillary (control) message data from DHCP packet reception.
///
/// Contains interface index and optional destination address extracted
/// from `recvmsg()` ancillary data via `IP_PKTINFO` or `IPV6_PKTINFO`.
#[derive(Debug, Clone)]
pub struct ControlMessages {
    /// Interface index where the packet was received.
    pub if_index: i32,
    /// Destination IP address of the received packet.
    pub dest_addr: Option<AllAddr>,
}

/// Receive a DHCP packet with automatic buffer expansion.
///
/// Uses `MSG_PEEK` | `MSG_TRUNC` to determine required buffer size before
/// actual receive. Automatically expands the buffer if the packet exceeds
/// current capacity. Handles `EINTR` by retrying and works around kernels
/// that ignore `MSG_PEEK`.
///
/// # Arguments
/// - `fd`: Socket file descriptor for DHCP packet reception.
/// - `buf`: Expandable receive buffer (will be resized if needed).
///
/// # Returns
/// On success: `(bytes_received, sender_address, control_messages)`.
/// On error: `Err` with I/O error details.
///
/// Replaces: C `recv_dhcp_packet()` (dhcp-common.c lines 175–216).
pub fn recv_dhcp_packet(
    fd: RawFd,
    buf: &mut Vec<u8>,
) -> Result<(usize, SocketAddress, ControlMessages), io::Error> {
    use nix::errno::Errno;

    // Allocate a cmsg buffer for ancillary data (IP_PKTINFO)
    let mut cmsg_buf = vec![0u8; 256];

    loop {
        // Peek to determine required buffer size
        let mut iov_peek = [IoSliceMut::new(buf.as_mut_slice())];

        let peek_result: Result<socket::RecvMsg<'_, '_, SockaddrStorage>, io::Error> = loop {
            match socket::recvmsg::<SockaddrStorage>(
                fd,
                &mut iov_peek,
                Some(&mut cmsg_buf),
                MsgFlags::MSG_PEEK | MsgFlags::MSG_TRUNC,
            ) {
                Ok(msg) => break Ok(msg),
                Err(Errno::EINTR) => continue,
                Err(e) => break Err(io::Error::from_raw_os_error(e as i32)),
            }
        };
        let peek_result = peek_result?;

        let sz = peek_result.bytes;

        if !peek_result.flags.contains(MsgFlags::MSG_TRUNC) {
            break; // Buffer is large enough
        }

        // Buffer too small — expand
        if sz == buf.len() {
            // Older kernel: doesn't report actual size, add headroom
            buf.resize(sz + 100, 0);
        } else {
            // Newer kernel: reported actual size
            buf.resize(sz, 0);
            break;
        }
    }

    // Actual receive (dequeue the packet)
    let mut iov = [IoSliceMut::new(buf.as_mut_slice())];

    let msg_result: Result<socket::RecvMsg<'_, '_, SockaddrStorage>, io::Error> = loop {
        match socket::recvmsg::<SockaddrStorage>(
            fd,
            &mut iov,
            Some(&mut cmsg_buf),
            MsgFlags::empty(),
        ) {
            Ok(m) => break Ok(m),
            Err(Errno::EINTR) => continue,
            Err(Errno::EAGAIN) => {
                // Some kernels dequeue on MSG_PEEK; packet already consumed.
                // Try one more non-blocking receive; if that fails, packet was already
                // received during the peek phase.
                match socket::recvmsg::<SockaddrStorage>(
                    fd,
                    &mut iov,
                    Some(&mut cmsg_buf),
                    MsgFlags::MSG_DONTWAIT,
                ) {
                    Ok(m) => break Ok(m),
                    Err(_) => {
                        break Err(io::Error::new(
                            io::ErrorKind::WouldBlock,
                            "DHCP packet lost due to kernel MSG_PEEK behavior",
                        ));
                    }
                }
            }
            Err(e) => break Err(io::Error::from_raw_os_error(e as i32)),
        }
    };
    let msg = msg_result?;

    if msg.flags.contains(MsgFlags::MSG_TRUNC) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DHCP packet truncated after buffer expansion",
        ));
    }

    // Extract sender address
    let sender: SocketAddress = msg
        .address
        .and_then(|addr: SockaddrStorage| {
            if let Some(v4) = addr.as_sockaddr_in() {
                // v4.ip() returns an Ipv4Addr in nix; convert via octets for byte order
                let ip = v4.ip();
                Some(SocketAddress::new_v4(ip, v4.port()))
            } else if let Some(v6) = addr.as_sockaddr_in6() {
                Some(SocketAddress::new_v6(v6.ip(), v6.port(), v6.flowinfo(), v6.scope_id()))
            } else {
                None
            }
        })
        .unwrap_or_else(|| SocketAddress::new_v4(Ipv4Addr::UNSPECIFIED, 0));

    // Extract control messages (interface index, destination address)
    let mut ctrl = ControlMessages {
        if_index: 0,
        dest_addr: None,
    };

    if let Ok(cmsgs) = msg.cmsgs() {
        for cmsg in cmsgs {
            match cmsg {
                socket::ControlMessageOwned::Ipv4PacketInfo(info) => {
                    ctrl.if_index = info.ipi_ifindex as i32;
                    ctrl.dest_addr = Some(AllAddr::V4(Ipv4Addr::from(
                        u32::from_be(info.ipi_addr.s_addr),
                    )));
                }
                #[cfg(target_os = "linux")]
                socket::ControlMessageOwned::Ipv6PacketInfo(info) => {
                    ctrl.if_index = info.ipi6_ifindex as i32;
                    ctrl.dest_addr = Some(AllAddr::V6(Ipv6Addr::from(info.ipi6_addr.s6_addr)));
                }
                _ => {}
            }
        }
    }

    Ok((msg.bytes, sender, ctrl))
}

/// Bind DHCP sockets to a specific network device using `SO_BINDTODEVICE`.
///
/// On Linux, restricts DHCP packet reception/transmission to the specified
/// network interface. This is essential for multi-VLAN environments (e.g.,
/// OpenStack) where each dnsmasq instance serves a single interface.
///
/// # Arguments
/// - `bound_device`: Interface name to bind to (e.g., `"eth0"`). If `None`,
///   no binding is performed.
/// - `dhcp_fd`: DHCP socket file descriptor to bind.
///
/// # Returns
/// `Ok(())` on success, `Err` if binding fails (EPERM is treated as non-fatal).
///
/// Replaces: C `bind_dhcp_devices()` / `bindtodevice()` (dhcp-common.c lines
/// 1509–1581).
pub fn bind_dhcp_devices(
    bound_device: Option<&str>,
    dhcp_fd: RawFd,
) -> Result<(), io::Error> {
    let device = match bound_device {
        Some(d) => d,
        None => return Ok(()),
    };

    // Truncate device name to IFNAMSIZ (typically 16 on Linux)
    const IFNAMSIZ: usize = 16;
    let name = if device.len() >= IFNAMSIZ {
        &device[..IFNAMSIZ - 1]
    } else {
        device
    };

    // Use nix to set SO_BINDTODEVICE
    // SAFETY: We trust the caller to provide a valid open file descriptor.
    let borrowed_fd = unsafe { std::os::fd::BorrowedFd::borrow_raw(dhcp_fd) };

    match socket::setsockopt(
        &borrowed_fd,
        socket::sockopt::BindToDevice,
        &std::ffi::OsString::from(name),
    ) {
        Ok(()) => Ok(()),
        Err(nix::errno::Errno::EPERM) => {
            // Insufficient privileges — graceful degradation
            debug!(
                "SO_BINDTODEVICE to {} failed (EPERM) — continuing without device binding",
                name
            );
            Ok(())
        }
        Err(e) => Err(io::Error::from_raw_os_error(e as i32)),
    }
}

// ===========================================================================
// Logging Helpers
// ===========================================================================

/// Log comma-separated list of DHCP tags for a transaction.
///
/// Builds a human-readable string of unique tag names from the tag list
/// and logs it at INFO level. Duplicate tags are automatically filtered.
///
/// # Arguments
/// - `netid`: Tag list to log.
/// - `xid`: Transaction ID for log correlation.
///
/// Replaces: C `log_tags()` (dhcp-common.c lines 705–728).
pub fn log_tags(netid: &[DhcpNetId], xid: u32) {
    if netid.is_empty() {
        return;
    }

    let mut seen: Vec<&str> = Vec::new();
    let mut parts: Vec<&str> = Vec::new();

    for tag in netid {
        if !seen.contains(&tag.net.as_str()) {
            seen.push(&tag.net);
            parts.push(&tag.net);
        }
    }

    let tag_str = parts.join(", ");
    info!("{} tags: {}", xid, tag_str);
}

/// Address family for logging context selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFamily {
    /// IPv4 (AF_INET).
    V4,
    /// IPv6 (AF_INET6).
    V6,
}

/// Log DHCP context configuration details.
///
/// Formats and logs address range, lease time, deprecation status, and
/// template/constructed status for a DHCP context. Handles both DHCPv4
/// and DHCPv6 contexts with appropriate formatting.
///
/// # Arguments
/// - `family`: Address family (V4 or V6).
/// - `context`: DHCP context to log.
///
/// Replaces: C `log_context()` (dhcp-common.c lines 2165–2257).
pub fn log_context(family: AddressFamily, context: &DhcpContext) {
    let protocol_name = match family {
        AddressFamily::V4 => "DHCP",
        AddressFamily::V6 => "DHCPv6",
    };

    let mut lease_info = String::new();
    if family == AddressFamily::V6
        && context.flags.contains(DhcpContextFlags::DEPRECATE)
    {
        lease_info.push_str(", prefix deprecated");
    } else {
        lease_info.push_str(", lease time ");
        prettyprint_time(&mut lease_info, context.lease_time);
    }

    let mut template_info = String::new();
    #[cfg(feature = "dhcp6")]
    {
        if context.flags.contains(DhcpContextFlags::CONSTRUCTED) {
            if let Some(ref tpl_iface) = context.template_interface {
                let kind = if context.flags.contains(DhcpContextFlags::OLD) {
                    "old prefix"
                } else {
                    "constructed"
                };
                template_info = format!(", {} for {}", kind, tpl_iface);
            }
        } else if context.flags.contains(DhcpContextFlags::TEMPLATE)
            && !context.flags.contains(DhcpContextFlags::RA_STATELESS)
        {
            if let Some(ref tpl_iface) = context.template_interface {
                template_info = format!(", template for {}", tpl_iface);
            }
        }
    }

    if !context.flags.contains(DhcpContextFlags::OLD)
        && (context.flags.contains(DhcpContextFlags::DHCP) || family == AddressFamily::V4)
    {
        if context.flags.contains(DhcpContextFlags::RA_STATELESS) {
            info!(
                "{} stateless on {}{}",
                protocol_name, context.start, template_info
            );
        } else if context.flags.contains(DhcpContextFlags::STATIC) {
            info!(
                "{}, static leases only on {}{}",
                protocol_name, context.start, lease_info
            );
        } else if context.flags.contains(DhcpContextFlags::PROXY) {
            info!(
                "{}, proxy on subnet {}{}",
                protocol_name, context.start, lease_info
            );
        } else {
            info!(
                "{}, IP range {} -- {}{}{}",
                protocol_name, context.start, context.end, lease_info, template_info
            );
        }
    }

    #[cfg(feature = "dhcp6")]
    {
        if context.flags.contains(DhcpContextFlags::RA_NAME)
            && !context.flags.contains(DhcpContextFlags::OLD)
        {
            info!("DHCPv4-derived IPv6 names on {}", context.start);
        }

        if context.flags.contains(DhcpContextFlags::RA) {
            info!("router advertisement on {}{}", context.start, template_info);
        }
    }
}

/// Log DHCP relay agent configuration.
///
/// Formats and logs relay local address, server address, interface name,
/// and non-default port numbers. Handles both broadcast/multicast relay
/// and standard relay modes.
///
/// # Arguments
/// - `family`: Address family (V4 or V6).
/// - `relay`: Relay configuration to log.
///
/// Replaces: C `log_relay()` (dhcp-common.c lines 2301–2335).
pub fn log_relay(family: AddressFamily, relay: &DhcpRelay) {
    let local_str = match &relay.local {
        RelayAddr::V4(addr) => addr.to_string(),
        RelayAddr::V6(addr) => addr.to_string(),
    };

    let mut server_str = match &relay.server {
        RelayAddr::V4(addr) => addr.to_string(),
        RelayAddr::V6(addr) => addr.to_string(),
    };

    // Detect broadcast/multicast relay mode
    let is_broadcast = match (&relay.server, family) {
        (RelayAddr::V4(addr), AddressFamily::V4) => addr.is_unspecified(),
        #[cfg(feature = "dhcp6")]
        (RelayAddr::V6(addr), AddressFamily::V6) => {
            // Check if server is the ALL_SERVERS multicast address
            *addr == protocol_v6::ALL_RELAY_AGENTS_AND_SERVERS
                || *addr == protocol_v6::ALL_SERVERS
        }
        _ => false,
    };

    // Append non-default port
    match family {
        AddressFamily::V4 => {
            if relay.port != 67 {
                server_str.push_str(&format!("#{}", relay.port));
            }
        }
        AddressFamily::V6 => {
            #[cfg(feature = "dhcp6")]
            if relay.port != 547 {
                server_str.push_str(&format!("#{}", relay.port));
            }
        }
    }

    if let Some(ref iface) = relay.interface {
        if is_broadcast {
            info!("DHCP relay from {} via {}", local_str, iface);
        } else if relay.split_mode != 0 {
            info!(
                "DHCP split-relay from {} to {} via {}",
                local_str, server_str, iface
            );
        } else {
            info!(
                "DHCP relay from {} to {} via {}",
                local_str, server_str, iface
            );
        }
    } else {
        info!("DHCP relay from {} to {}", local_str, server_str);
    }
}

// ===========================================================================
// Unit Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::dhcp::HwaddrConfig;

    #[test]
    fn test_protocol_display() {
        assert_eq!(format!("{}", Protocol::V4), "DHCPv4");
        assert_eq!(format!("{}", Protocol::V6), "DHCPv6");
    }

    #[test]
    fn test_dhcp_buffers_new() {
        let bufs = DhcpBuffers::new();
        assert_eq!(bufs.buff1.len(), DHCP_BUFF_SZ);
        assert_eq!(bufs.buff2.len(), DHCP_BUFF_SZ);
        assert_eq!(bufs.buff3.len(), DHCP_BUFF_SZ);
        assert!(bufs.dhcp_packet.len() >= mem::size_of::<DhcpPacket>());
    }

    #[test]
    fn test_dhcp_buffers_reset() {
        let mut bufs = DhcpBuffers::new();
        bufs.buff1[0] = 0xFF;
        bufs.reset();
        assert_eq!(bufs.buff1[0], 0);
    }

    #[test]
    fn test_match_netid_empty_check() {
        let pool = vec![DhcpNetId {
            net: "test".to_string(),
        }];
        // Empty check with tag_not_needed=true -> match
        assert!(match_netid(&[], &pool, true));
        // Empty check with tag_not_needed=false -> no match
        assert!(!match_netid(&[], &pool, false));
    }

    #[test]
    fn test_match_netid_positive() {
        let check = vec![DhcpNetId {
            net: "vlan1".to_string(),
        }];
        let pool = vec![
            DhcpNetId { net: "vlan1".to_string() },
            DhcpNetId { net: "vlan2".to_string() },
        ];
        assert!(match_netid(&check, &pool, false));
    }

    #[test]
    fn test_match_netid_positive_missing() {
        let check = vec![DhcpNetId {
            net: "vlan3".to_string(),
        }];
        let pool = vec![DhcpNetId { net: "vlan1".to_string() }];
        assert!(!match_netid(&check, &pool, false));
    }

    #[test]
    fn test_match_netid_negative() {
        let check = vec![DhcpNetId {
            net: "!server".to_string(),
        }];
        let pool = vec![DhcpNetId { net: "desktop".to_string() }];
        // "server" not in pool -> match
        assert!(match_netid(&check, &pool, false));
    }

    #[test]
    fn test_match_netid_negative_found() {
        let check = vec![DhcpNetId {
            net: "!server".to_string(),
        }];
        let pool = vec![DhcpNetId { net: "server".to_string() }];
        // "server" in pool -> no match
        assert!(!match_netid(&check, &pool, false));
    }

    #[test]
    fn test_match_netid_wild_prefix() {
        let check = vec![DhcpNetId {
            net: "vlan*".to_string(),
        }];
        let pool = vec![DhcpNetId { net: "vlan42".to_string() }];
        assert!(match_netid_wild(&check, &pool));
    }

    #[test]
    fn test_match_netid_wild_no_match() {
        let check = vec![DhcpNetId {
            net: "eth*".to_string(),
        }];
        let pool = vec![DhcpNetId { net: "vlan42".to_string() }];
        assert!(!match_netid_wild(&check, &pool));
    }

    #[test]
    fn test_match_netid_wild_negated() {
        let check = vec![DhcpNetId {
            net: "!vlan*".to_string(),
        }];
        let pool = vec![DhcpNetId { net: "vlan42".to_string() }];
        assert!(!match_netid_wild(&check, &pool));
    }

    #[test]
    fn test_pxe_ok() {
        let mut opt = DhcpOption {
            opt: 1,
            len: 0,
            flags: DhcpOptFlags::empty(),
            extra: DhcpOptExtra::None,
            val: vec![],
            netid: vec![],
        };
        // Non-PXE option
        assert!(pxe_ok(&opt, 0)); // normal mode: include
        assert!(pxe_ok(&opt, 1)); // hybrid: include
        assert!(!pxe_ok(&opt, 2)); // PXE-only: exclude

        // PXE option
        opt.flags = DhcpOptFlags::PXE_OPT;
        assert!(!pxe_ok(&opt, 0)); // normal: exclude
        assert!(pxe_ok(&opt, 1)); // hybrid: include
        assert!(pxe_ok(&opt, 2)); // PXE-only: include
    }

    #[test]
    fn test_match_bytes_empty_pattern() {
        let opt = DhcpOption {
            opt: 1,
            len: 0,
            flags: DhcpOptFlags::empty(),
            extra: DhcpOptExtra::None,
            val: vec![],
            netid: vec![],
        };
        assert!(match_bytes(&opt, &[1, 2, 3]));
    }

    #[test]
    fn test_match_bytes_exact() {
        let opt = DhcpOption {
            opt: 1,
            len: 3,
            flags: DhcpOptFlags::empty(),
            extra: DhcpOptExtra::None,
            val: vec![1, 2, 3],
            netid: vec![],
        };
        assert!(match_bytes(&opt, &[1, 2, 3, 4, 5, 6]));
        assert!(!match_bytes(&opt, &[4, 5, 6]));
    }

    #[test]
    fn test_match_bytes_string_mode() {
        let opt = DhcpOption {
            opt: 1,
            len: 2,
            flags: DhcpOptFlags::STRING,
            extra: DhcpOptExtra::None,
            val: vec![0x42, 0x43],
            netid: vec![],
        };
        assert!(match_bytes(&opt, &[0x41, 0x42, 0x43, 0x44]));
    }

    #[test]
    fn test_strip_hostname() {
        assert_eq!(strip_hostname("myhost"), Some("myhost".to_string()));
        assert_eq!(strip_hostname("MyHost"), Some("myhost".to_string()));
        assert_eq!(
            strip_hostname("myhost.example.com"),
            Some("myhost".to_string())
        );
        assert_eq!(strip_hostname(""), None);
    }

    #[test]
    fn test_lookup_dhcp_opt_v4() {
        assert_eq!(lookup_dhcp_opt(Protocol::V4, "netmask"), Some(1));
        assert_eq!(lookup_dhcp_opt(Protocol::V4, "router"), Some(3));
        assert_eq!(lookup_dhcp_opt(Protocol::V4, "dns-server"), Some(6));
        assert_eq!(lookup_dhcp_opt(Protocol::V4, "unknown-opt"), None);
        // Case insensitive
        assert_eq!(lookup_dhcp_opt(Protocol::V4, "NETMASK"), Some(1));
    }

    #[test]
    fn test_lookup_dhcp_len_v4() {
        // netmask is OT_ADDR_LIST -> size bits stripped, result is 0
        assert_eq!(lookup_dhcp_len(Protocol::V4, 1), Some(0));
        // time-offset is Fixed(4)
        assert_eq!(lookup_dhcp_len(Protocol::V4, 2), Some(4));
        // Unknown option
        assert_eq!(lookup_dhcp_len(Protocol::V4, 999), None);
    }

    #[test]
    fn test_option_string_addr() {
        let mut buf = String::new();
        let val = [192, 168, 1, 1];
        let name = option_string(Protocol::V4, 3, &val, &mut buf);
        assert_eq!(name, "router");
        assert_eq!(buf, "192.168.1.1");
    }

    #[test]
    fn test_option_string_name() {
        let mut buf = String::new();
        let val = b"example.com";
        let name = option_string(Protocol::V4, 15, val, &mut buf);
        assert_eq!(name, "domain-name");
        assert_eq!(buf, "example.com");
    }

    #[test]
    fn test_option_string_unknown() {
        let mut buf = String::new();
        let val = [0xAB, 0xCD, 0xEF];
        let name = option_string(Protocol::V4, 200, &val, &mut buf);
        assert_eq!(name, "");
        assert_eq!(buf, "ab:cd:ef");
    }

    #[test]
    fn test_prettyprint_time() {
        let mut buf = String::new();
        prettyprint_time(&mut buf, 3661);
        assert_eq!(buf, "1h1m1s");

        buf.clear();
        prettyprint_time(&mut buf, 86400);
        assert_eq!(buf, "1d");

        buf.clear();
        prettyprint_time(&mut buf, 0);
        assert_eq!(buf, "0s");
    }

    #[test]
    fn test_config_has_mac() {
        let config = DhcpConfig {
            flags: DhcpConfigFlags::empty(),
            clid: vec![],
            hostname: None,
            domain: None,
            netid: vec![],
            filter: vec![],
            #[cfg(feature = "dhcp6")]
            addr6: vec![],
            addr: Ipv4Addr::UNSPECIFIED,
            decline_time: 0,
            lease_time: 0,
            hwaddr: vec![HwaddrConfig {
                hwaddr_len: 6,
                hwaddr_type: 1,
                hwaddr: vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
                wildcard_mask: 0,
            }],
        };

        assert!(config_has_mac(
            &config,
            &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            1
        ));
        assert!(!config_has_mac(
            &config,
            &[0x00, 0x11, 0x22, 0x33, 0x44, 0x66],
            1
        ));
        // Type 0 in config acts as wildcard for type
        let config2 = DhcpConfig {
            hwaddr: vec![HwaddrConfig {
                hwaddr_len: 6,
                hwaddr_type: 0,
                hwaddr: vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
                wildcard_mask: 0,
            }],
            ..config
        };
        assert!(config_has_mac(
            &config2,
            &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            99
        ));
    }

    #[test]
    fn test_find_config_by_mac() {
        let configs = vec![DhcpConfig {
            flags: DhcpConfigFlags::empty(),
            clid: vec![],
            hostname: None,
            domain: None,
            netid: vec![],
            filter: vec![],
            #[cfg(feature = "dhcp6")]
            addr6: vec![],
            addr: Ipv4Addr::new(192, 168, 1, 50),
            decline_time: 0,
            lease_time: 3600,
            hwaddr: vec![HwaddrConfig {
                hwaddr_len: 6,
                hwaddr_type: 1,
                hwaddr: vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
                wildcard_mask: 0,
            }],
        }];

        let result = find_config(
            &configs,
            None,
            None,
            Some(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]),
            1,
            None,
            &[],
        );
        assert!(result.is_some());
        assert_eq!(result.unwrap().addr, Ipv4Addr::new(192, 168, 1, 50));
    }

    #[test]
    fn test_v4_option_table_completeness() {
        // Verify all expected entries are present with correct codes
        assert_eq!(
            lookup_dhcp_opt(Protocol::V4, "netmask"),
            Some(1)
        );
        assert_eq!(
            lookup_dhcp_opt(Protocol::V4, "router"),
            Some(3)
        );
        assert_eq!(
            lookup_dhcp_opt(Protocol::V4, "dns-server"),
            Some(6)
        );
        assert_eq!(
            lookup_dhcp_opt(Protocol::V4, "domain-name"),
            Some(15)
        );
        assert_eq!(
            lookup_dhcp_opt(Protocol::V4, "lease-time"),
            Some(51)
        );
        assert_eq!(
            lookup_dhcp_opt(Protocol::V4, "domain-search"),
            Some(119)
        );
        assert_eq!(
            lookup_dhcp_opt(Protocol::V4, "server-ip-address"),
            Some(255)
        );
        // Total entry count
        assert!(RAW_V4_OPTIONS.len() >= 77);
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn test_v6_option_table_completeness() {
        assert_eq!(
            lookup_dhcp_opt(Protocol::V6, "client-id"),
            Some(1)
        );
        assert_eq!(
            lookup_dhcp_opt(Protocol::V6, "server-id"),
            Some(2)
        );
        assert_eq!(
            lookup_dhcp_opt(Protocol::V6, "dns-server"),
            Some(23)
        );
        assert_eq!(
            lookup_dhcp_opt(Protocol::V6, "domain-search"),
            Some(24)
        );
        assert_eq!(
            lookup_dhcp_opt(Protocol::V6, "FQDN"),
            Some(39)
        );
        assert!(RAW_V6_OPTIONS.len() >= 28);
    }

    #[test]
    fn test_run_tag_if() {
        let mut tags = vec![DhcpNetId {
            net: "vlan1".to_string(),
        }];
        let rules = vec![TagIf {
            tag: vec![DhcpNetId {
                net: "vlan*".to_string(),
            }],
            set: vec![vec![DhcpNetId {
                net: "server-pool-A".to_string(),
            }]],
        }];
        run_tag_if(&mut tags, &rules);
        assert!(tags.iter().any(|t| t.net == "server-pool-A"));
    }

    #[test]
    fn test_log_tags() {
        // Should not panic with empty list
        log_tags(&[], 0x12345678);
        // Should not panic with tags
        log_tags(
            &[
                DhcpNetId { net: "vlan1".to_string() },
                DhcpNetId { net: "known".to_string() },
            ],
            0xABCD,
        );
    }
}

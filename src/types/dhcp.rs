//! DHCP-specific type definitions for the dnsmasq Rust implementation.
//!
//! This module defines all DHCP-specific data types (DHCPv4, DHCPv6, Router
//! Advertisement, TFTP, lease, relay) used across the dnsmasq codebase. It
//! replaces the DHCP-related struct definitions from the C `dnsmasq.h` header.
//!
//! # Key Transformations from C
//! - **Intrusive linked lists removed:** All `next` pointers from C structs are
//!   eliminated. Collections manage relationships externally via `HashMap`, `Vec`.
//! - **C unions → Rust enums:** `union { addr4; addr6; }` in `struct dhcp_relay`
//!   becomes [`RelayAddr`] enum; `union { encap; wildcard_mask; vendor_class; }`
//!   in `struct dhcp_opt` becomes [`DhcpOptExtra`] enum.
//! - **C `unsigned char *` + len → `Vec<u8>`:** Client IDs, hardware addresses,
//!   extra data all become self-describing `Vec<u8>`.
//! - **C `char *` → `Option<String>`:** Nullable string pointers become
//!   `Option<String>`.
//! - **C `time_t` → `i64`:** Timestamps stored as `i64` (seconds since epoch).
//! - **C `#define` flag groups → `bitflags!` macro:** Type-safe bitflag types.
//! - **C `#ifdef HAVE_*` → `#[cfg(feature = "...")]`:** Feature-gated compilation.
//!
//! # Feature Gates
//! - DHCPv6 fields are gated by `#[cfg(feature = "dhcp6")]`
//! - TFTP types are gated by `#[cfg(feature = "tftp")]`
//! - Script/helper types are gated by `#[cfg(feature = "script")]`
//!
//! # Source References
//! - `src/dnsmasq.h` lines 1000–1341

use std::net::{Ipv4Addr, Ipv6Addr};

use bitflags::bitflags;

// Internal imports from dependency files
use crate::types::addr::{AllAddr, SocketAddress};
use crate::types::dns::AddrList;

// ===========================================================================
// DHCP Option Table Flags (dnsmasq.h lines 1000–1007)
// ===========================================================================

bitflags! {
    /// Flags in the top of the length field for DHCP-option tables.
    ///
    /// These flags appear in the high bits of the option length field in
    /// the internal DHCP option type table (`opttab4[]` / `opttab6[]`),
    /// controlling how option values are parsed and presented.
    ///
    /// Replaces: `OT_*` constants from `dnsmasq.h` lines 1000–1007.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct DhcpOptTypeFlags: u16 {
        /// Option value is a list of IP addresses.
        const ADDR_LIST    = 0x8000;
        /// Option value is a DNS name in RFC 1035 wire format.
        const RFC1035_NAME = 0x4000;
        /// Option is for internal use only (not user-configurable).
        const INTERNAL     = 0x2000;
        /// Option value is a human-readable name string.
        const NAME         = 0x1000;
        /// Option value is a C-style null-terminated string.
        const CSTRING      = 0x0800;
        /// Option value is a decimal number.
        const DEC          = 0x0400;
        /// Option value is a time duration (seconds).
        const TIME         = 0x0200;
    }
}

// ===========================================================================
// Helper RPC Action Constants (dnsmasq.h lines 1009–1017)
// ===========================================================================

/// Helper action: delete a lease.
/// Replaces: `ACTION_DEL` from `dnsmasq.h` line 1010.
pub const ACTION_DEL: i32 = 1;

/// Helper action: notify of old hostname before lease move.
/// Replaces: `ACTION_OLD_HOSTNAME` from `dnsmasq.h` line 1011.
pub const ACTION_OLD_HOSTNAME: i32 = 2;

/// Helper action: notify of existing lease (daemon restart).
/// Replaces: `ACTION_OLD` from `dnsmasq.h` line 1012.
pub const ACTION_OLD: i32 = 3;

/// Helper action: add/renew a lease.
/// Replaces: `ACTION_ADD` from `dnsmasq.h` line 1013.
pub const ACTION_ADD: i32 = 4;

/// Helper action: TFTP transfer event.
/// Replaces: `ACTION_TFTP` from `dnsmasq.h` line 1014.
pub const ACTION_TFTP: i32 = 5;

/// Helper action: ARP cache event (new neighbor).
/// Replaces: `ACTION_ARP` from `dnsmasq.h` line 1015.
pub const ACTION_ARP: i32 = 6;

/// Helper action: ARP cache event (neighbor removed).
/// Replaces: `ACTION_ARP_DEL` from `dnsmasq.h` line 1016.
pub const ACTION_ARP_DEL: i32 = 7;

/// Helper action: DHCP relay snoop event.
/// Replaces: `ACTION_RELAY_SNOOP` from `dnsmasq.h` line 1017.
pub const ACTION_RELAY_SNOOP: i32 = 8;

// ===========================================================================
// Lease State Flags (dnsmasq.h lines 1019–1027)
// ===========================================================================

bitflags! {
    /// DHCP lease state flags tracking lifecycle and modification state.
    ///
    /// These flags are used by the lease management subsystem to track
    /// which leases need script notifications, DNS updates, or file
    /// persistence operations.
    ///
    /// Replaces: `LEASE_*` constants from `dnsmasq.h` lines 1019–1027.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct LeaseFlags: i32 {
        /// Lease was newly created this transaction.
        const NEW          = 1;
        /// Lease was modified (address, hostname, or other key field changed).
        const CHANGED      = 2;
        /// Auxiliary data changed (CLID or expiry time).
        const AUX_CHANGED  = 4;
        /// Hostname came from static configuration, not from client request.
        const AUTH_NAME    = 8;
        /// Lease was used/touched during this DHCPv6 transaction.
        const USED         = 16;
        /// DHCPv6 non-temporary address lease (IA_NA).
        const NA           = 32;
        /// DHCPv6 temporary address lease (IA_TA).
        const TA           = 64;
        /// Hardware address has been set on this lease.
        const HAVE_HWADDR  = 128;
        /// Lease expiry time was changed.
        const EXP_CHANGED  = 256;
    }
}

// ===========================================================================
// SlaacAddress — DHCPv6 SLAAC Tracking (dnsmasq.h lines 1058–1063)
// ===========================================================================

/// SLAAC address tracking entry for IPv6 Duplicate Address Detection probing.
///
/// Tracks an IPv6 address derived via SLAAC that needs DAD (Duplicate Address
/// Detection) probing via ICMPv6 echo. The `backoff` field controls the
/// probing interval: zero means the address is confirmed (DAD complete).
///
/// Replaces: C `struct slaac_address` (dnsmasq.h lines 1058–1063).
/// NOTE: The `next` pointer is removed — SLAAC addresses are stored in `Vec`.
#[cfg(feature = "dhcp6")]
#[derive(Debug, Clone)]
pub struct SlaacAddress {
    /// The IPv6 address being probed.
    pub addr: Ipv6Addr,
    /// Time of the next ping probe (seconds since epoch).
    pub ping_time: i64,
    /// Backoff counter for probing. Zero means confirmed (DAD complete).
    pub backoff: i32,
}

// ===========================================================================
// DhcpLease — Lease Database Entry (dnsmasq.h lines 1035–1067)
// ===========================================================================

/// DHCP lease database entry representing an active or expired address lease.
///
/// This is the persistent lease representation stored in the lease database.
/// The AAP calls for a Type-State Pattern for lease lifecycle
/// (DISCOVER→OFFER→REQUEST→ACK), but this base struct stores the persistent
/// data. State transitions can be encoded as wrapper types or enums in the
/// DHCP protocol modules.
///
/// # Critical Transformations
/// - C `struct dhcp_lease *next` pointer **removed** — leases managed in
///   `HashMap<IpAddr, DhcpLease>` keyed by IP address (AAP Section 0.4.1).
/// - C `unsigned char *clid` with `clid_len` → `Vec<u8>` (self-describing).
/// - C `unsigned char hwaddr[DHCP_CHADDR_MAX]` fixed array → `Vec<u8>`.
/// - C `unsigned char *extradata` with `extradata_len`/`extradata_size` → `Vec<u8>`.
/// - C `unsigned char *agent_id` with `agent_id_len` → `Vec<u8>`.
/// - C `unsigned char *vendorclass` with `vendorclass_len` → `Vec<u8>`.
///
/// Replaces: C `struct dhcp_lease` (dnsmasq.h lines 1035–1067).
#[derive(Debug, Clone)]
pub struct DhcpLease {
    /// Client identifier bytes (variable length).
    /// Replaces: C `unsigned char *clid` + `clid_len`.
    pub clid: Vec<u8>,

    /// Hostname from client-hostname option or static configuration.
    /// Replaces: C `char *hostname`.
    pub hostname: Option<String>,

    /// Fully qualified domain name.
    /// Replaces: C `char *fqdn`.
    pub fqdn: Option<String>,

    /// Previous hostname before the lease moved to another address.
    /// Replaces: C `char *old_hostname`.
    pub old_hostname: Option<String>,

    /// Lease state flags (NEW, CHANGED, AUTH_NAME, etc.).
    /// Replaces: C `int flags`.
    pub flags: LeaseFlags,

    /// Lease expiry timestamp (seconds since epoch, 0 = never expires).
    /// Replaces: C `time_t expires`.
    pub expires: i64,

    /// Hardware address length in bytes.
    /// Replaces: C `int hwaddr_len`.
    pub hwaddr_len: i32,

    /// Hardware address type (ARPHRD_ETHER = 1, etc.).
    /// Replaces: C `int hwaddr_type`.
    pub hwaddr_type: i32,

    /// Hardware address bytes (max DHCP_CHADDR_MAX = 16).
    /// Replaces: C `unsigned char hwaddr[DHCP_CHADDR_MAX]`.
    pub hwaddr: Vec<u8>,

    /// Assigned IPv4 address for this lease.
    /// Replaces: C `struct in_addr addr`.
    pub addr: Ipv4Addr,

    /// Override address (used for address override in certain configurations).
    /// Replaces: C `struct in_addr override`.
    pub override_addr: Ipv4Addr,

    /// Gateway/relay agent IP address (GIADDR from DHCP packet).
    /// Replaces: C `struct in_addr giaddr`.
    pub giaddr: Ipv4Addr,

    /// Extra data bytes for helper script communication.
    /// Replaces: C `unsigned char *extradata` + `extradata_len`/`extradata_size`.
    pub extradata: Vec<u8>,

    /// Interface index where this lease was last seen.
    /// Replaces: C `int last_interface`.
    pub last_interface: i32,

    /// New interface index (saves possible originated interface).
    /// Replaces: C `int new_interface`.
    pub new_interface: i32,

    /// New prefix length for the interface.
    /// Replaces: C `int new_prefixlen`.
    pub new_prefixlen: i32,

    /// DHCP relay agent ID bytes.
    /// Replaces: C `unsigned char *agent_id` + `agent_id_len`.
    pub agent_id: Vec<u8>,

    /// Vendor class data bytes.
    /// Replaces: C `unsigned char *vendorclass` + `vendorclass_len`.
    pub vendorclass: Vec<u8>,

    /// DHCPv6 assigned address.
    /// Replaces: C `struct in6_addr addr6`.
    #[cfg(feature = "dhcp6")]
    pub addr6: Ipv6Addr,

    /// DHCPv6 Identity Association Identifier.
    /// Replaces: C `unsigned int iaid`.
    #[cfg(feature = "dhcp6")]
    pub iaid: u32,

    /// SLAAC address list for DAD probing.
    /// Replaces: C `struct slaac_address *slaac_address` linked list.
    #[cfg(feature = "dhcp6")]
    pub slaac_addresses: Vec<SlaacAddress>,

    /// Number of vendor class entries (DHCPv6).
    /// Replaces: C `int vendorclass_count`.
    #[cfg(feature = "dhcp6")]
    pub vendorclass_count: i32,
}

// ===========================================================================
// DHCP Network ID / Tag System (dnsmasq.h lines 1069–1089)
// ===========================================================================

/// DHCP network tag identifier used for conditional option/config matching.
///
/// Tags are string identifiers that can be set on interfaces, DHCP ranges,
/// or matched against client attributes. They drive conditional configuration
/// (e.g., send different options to different client classes).
///
/// Replaces: C `struct dhcp_netid` (dnsmasq.h lines 1069–1072).
/// NOTE: The `next` pointer is removed — tag lists are stored in `Vec<DhcpNetId>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DhcpNetId {
    /// The tag name string (e.g., "known", "vlan100", "printers").
    pub net: String,
}

/// Tag-conditional configuration entry.
///
/// Enables configuration like "if tags X and Y are set, then also set tag Z".
/// The `set` field contains lists of tag sets (OR of ANDs), and `tag` contains
/// the tags to set when the condition is met.
///
/// Replaces: C `struct tag_if` (dnsmasq.h lines 1079–1083).
/// NOTE: The `next` pointer is removed — entries stored in `Vec<TagIf>`.
#[derive(Debug, Clone)]
pub struct TagIf {
    /// List of tag-set conditions (each inner Vec is AND-ed, outer Vec is OR-ed).
    /// Replaces: C `struct dhcp_netid_list *set` (linked list of netid lists).
    pub set: Vec<Vec<DhcpNetId>>,
    /// Tags to set when the condition matches.
    /// Replaces: C `struct dhcp_netid *tag`.
    pub tag: Vec<DhcpNetId>,
}

/// DHCP response delay configuration (anti-spoofing).
///
/// Configures a delay before responding to DHCP requests matching certain tags.
/// Used to give priority to a known DHCP server before responding.
///
/// Replaces: C `struct delay_config` (dnsmasq.h lines 1085–1089).
/// NOTE: The `next` pointer is removed.
#[derive(Debug, Clone)]
pub struct DelayConfig {
    /// Delay in seconds before responding.
    pub delay: i32,
    /// Tags that must match for the delay to apply.
    /// Replaces: C `struct dhcp_netid *netid` linked list.
    pub netid: Vec<DhcpNetId>,
}

// ===========================================================================
// DhcpConfig — Static Host Configuration (dnsmasq.h lines 1091–1128)
// ===========================================================================

/// Hardware address configuration for static DHCP host matching.
///
/// Allows matching clients by hardware (MAC) address with optional
/// wildcard masking. Multiple hardware addresses can be associated
/// with a single static host configuration.
///
/// Replaces: C `struct hwaddr_config` (dnsmasq.h lines 1091–1096).
/// NOTE: The `next` pointer is removed — stored in `Vec<HwaddrConfig>`.
#[derive(Debug, Clone)]
pub struct HwaddrConfig {
    /// Length of the hardware address in bytes.
    pub hwaddr_len: i32,
    /// Hardware address type (ARPHRD_ETHER = 1, etc.).
    pub hwaddr_type: i32,
    /// Hardware address bytes (max DHCP_CHADDR_MAX = 16).
    /// Replaces: C `unsigned char hwaddr[DHCP_CHADDR_MAX]`.
    pub hwaddr: Vec<u8>,
    /// Bitmask for wildcard matching (0 = exact match on all bytes).
    pub wildcard_mask: u32,
}

bitflags! {
    /// DHCP static host configuration flags.
    ///
    /// Control which fields of a `DhcpConfig` entry are active/valid.
    /// For example, `CONFIG_ADDR` means the IPv4 address field should be used.
    ///
    /// Replaces: `CONFIG_*` constants from `dnsmasq.h` lines 1117–1128.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct DhcpConfigFlags: u32 {
        /// Host is disabled (ignore this entry).
        const DISABLE        = 1;
        /// Client identifier is specified.
        const CLID           = 2;
        /// Lease time is specified.
        const TIME           = 8;
        /// Hostname is specified.
        const NAME           = 16;
        /// IPv4 address is specified.
        const ADDR           = 32;
        /// Ignore client identifier (match by hardware address only).
        const NOCLID         = 128;
        /// Entry created from /etc/ethers file.
        const FROM_ETHERS    = 256;
        /// Address added from /etc/hosts file.
        const ADDR_HOSTS     = 512;
        /// Address has been declined by a client.
        const DECLINED       = 1024;
        /// Entry loaded from dhcp-hostsfile.
        const BANK           = 2048;
        /// DHCPv6 address is specified.
        const ADDR6          = 4096;
        /// DHCPv6 address added from /etc/hosts file.
        const ADDR6_HOSTS    = 16384;
    }
}

/// Static DHCP host configuration entry.
///
/// Maps hardware addresses, client identifiers, or hostnames to fixed
/// IP addresses and per-host configuration parameters.
///
/// Replaces: C `struct dhcp_config` (dnsmasq.h lines 1098–1113).
/// NOTE: The `next` pointer is removed — entries stored in `Vec<DhcpConfig>`.
#[derive(Debug, Clone)]
pub struct DhcpConfig {
    /// Configuration flags indicating which fields are active.
    pub flags: DhcpConfigFlags,

    /// Client identifier bytes for matching.
    /// Replaces: C `unsigned char *clid` + `clid_len`.
    pub clid: Vec<u8>,

    /// Hostname to assign to this client.
    /// Replaces: C `char *hostname`.
    pub hostname: Option<String>,

    /// Domain name to assign to this client.
    /// Replaces: C `char *domain`.
    pub domain: Option<String>,

    /// Network tag lists for this host configuration.
    /// Replaces: C `struct dhcp_netid_list *netid` (linked list of netid lists).
    pub netid: Vec<Vec<DhcpNetId>>,

    /// Tags that must be present for this config to apply.
    /// Replaces: C `struct dhcp_netid *filter` linked list.
    pub filter: Vec<DhcpNetId>,

    /// DHCPv6 address list for this host.
    /// Replaces: C `struct addrlist *addr6`.
    #[cfg(feature = "dhcp6")]
    pub addr6: Vec<AddrList>,

    /// Fixed IPv4 address for this host.
    /// Replaces: C `struct in_addr addr`.
    pub addr: Ipv4Addr,

    /// Time when the address was declined (seconds since epoch).
    /// Replaces: C `time_t decline_time`.
    pub decline_time: i64,

    /// Lease time override for this host (seconds).
    /// Replaces: C `unsigned int lease_time`.
    pub lease_time: u32,

    /// Hardware address configurations for matching.
    /// Replaces: C `struct hwaddr_config *hwaddr` linked list.
    pub hwaddr: Vec<HwaddrConfig>,
}

// ===========================================================================
// DhcpOption — DHCP Option Encoding (dnsmasq.h lines 1130–1157)
// ===========================================================================

bitflags! {
    /// DHCP option encoding and behavior flags.
    ///
    /// Control how individual DHCP options are encoded, matched, and sent.
    /// These flags determine whether an option is forced, hex-encoded,
    /// vendor-specific, or part of an encapsulation chain.
    ///
    /// Replaces: `DHOPT_*` constants from `dnsmasq.h` lines 1142–1157.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct DhcpOptFlags: i32 {
        /// Option value is an IP address.
        const ADDR           = 1;
        /// Option value is a string.
        const STRING         = 2;
        /// Option is encapsulated within another option.
        const ENCAPSULATE    = 4;
        /// Encapsulation match found.
        const ENCAP_MATCH    = 8;
        /// Force sending this option even if not requested.
        const FORCE          = 16;
        /// Entry loaded from dhcp-optsfile.
        const BANK           = 32;
        /// Encapsulation processing complete.
        const ENCAP_DONE     = 64;
        /// Use this entry for matching (not sending).
        const MATCH          = 128;
        /// Vendor-specific option.
        const VENDOR         = 256;
        /// Option value is hex-encoded.
        const HEX            = 512;
        /// Vendor option match.
        const VENDOR_MATCH   = 1024;
        /// RFC 3925 vendor-identifying option.
        const RFC3925        = 2048;
        /// Tag check passed for this option.
        const TAGOK          = 4096;
        /// Option value is an IPv6 address.
        const ADDR6          = 8192;
        /// PXE vendor-specific option.
        const VENDOR_PXE     = 16384;
        /// PXE option (not vendor-encapsulated).
        const PXE_OPT        = 32768;
    }
}

/// Variant data for DHCP option union field.
///
/// Replaces the C union `u` inside `struct dhcp_opt`:
/// ```c
/// union {
///     int encap;                      // encapsulation option number
///     unsigned int wildcard_mask;     // MAC wildcard mask
///     unsigned char *vendor_class;    // vendor class data
/// } u;
/// ```
///
/// Using a Rust enum provides type-safe access to the variant data.
#[derive(Debug, Clone)]
pub enum DhcpOptExtra {
    /// Encapsulation option number (the outer option containing this one).
    Encap(i32),
    /// Wildcard mask for hardware address matching.
    WildcardMask(u32),
    /// Vendor class identifier data.
    VendorClass(Vec<u8>),
    /// No extra data associated with this option.
    None,
}

/// DHCP option encoding entry.
///
/// Represents a single DHCP option to be sent in responses or used for
/// matching incoming requests. Options can be tagged (conditional), forced,
/// encapsulated, or vendor-specific.
///
/// Replaces: C `struct dhcp_opt` (dnsmasq.h lines 1130–1140).
/// NOTE: The `next` pointer is removed — options stored in `Vec<DhcpOption>`.
#[derive(Debug, Clone)]
pub struct DhcpOption {
    /// DHCP option code number (e.g., 1 = subnet mask, 3 = router).
    pub opt: i32,
    /// Length of the option value in bytes.
    pub len: i32,
    /// Option behavior flags.
    pub flags: DhcpOptFlags,
    /// Extra variant data (encapsulation number, wildcard mask, or vendor class).
    pub extra: DhcpOptExtra,
    /// Option value bytes.
    /// Replaces: C `unsigned char *val`.
    pub val: Vec<u8>,
    /// Tags that must match for this option to be sent.
    /// Replaces: C `struct dhcp_netid *netid` linked list.
    pub netid: Vec<DhcpNetId>,
}

// ===========================================================================
// PXE and Boot Types (dnsmasq.h lines 1159–1209)
// ===========================================================================

/// DHCP boot server configuration (next-server, filename, server name).
///
/// Configures PXE/UEFI network boot parameters sent in DHCP responses.
/// Multiple boot configurations can be tagged for conditional assignment.
///
/// Replaces: C `struct dhcp_boot` (dnsmasq.h lines 1159–1164).
/// NOTE: The `next` pointer is removed.
#[derive(Debug, Clone)]
pub struct DhcpBoot {
    /// Boot filename (option 67).
    pub file: Option<String>,
    /// Server hostname (sname field in BOOTP header).
    pub sname: Option<String>,
    /// TFTP server name (for option 66 when sname is occupied).
    pub tftp_sname: Option<String>,
    /// Next-server IP address (siaddr in BOOTP header).
    pub next_server: Ipv4Addr,
    /// Tags that must match for this boot config to apply.
    /// Replaces: C `struct dhcp_netid *netid` linked list.
    pub netid: Vec<DhcpNetId>,
}

/// DHCP hostname matching rule for tag assignment.
///
/// Matches client hostnames (with optional wildcard) and sets tags
/// when a match is found. Used for conditional configuration based
/// on client-supplied hostnames.
///
/// Replaces: C `struct dhcp_match_name` (dnsmasq.h lines 1166–1171).
/// NOTE: The `next` pointer is removed.
#[derive(Debug, Clone)]
pub struct DhcpMatchName {
    /// Hostname pattern to match.
    pub name: String,
    /// Whether the pattern uses wildcard matching.
    /// Replaces: C `int wildcard` (non-zero = wildcard).
    pub wildcard: bool,
    /// Tags to set when the hostname matches.
    /// Replaces: C `struct dhcp_netid *netid` linked list.
    pub netid: Vec<DhcpNetId>,
}

/// PXE boot service entry for PXE boot menu.
///
/// Defines a network boot service that appears in the PXE boot menu
/// presented to PXE clients during the DHCP boot process.
///
/// Replaces: C `struct pxe_service` (dnsmasq.h lines 1173–1179).
/// NOTE: The `next` pointer is removed.
#[derive(Debug, Clone)]
pub struct PxeService {
    /// Client System Architecture (option 93) value.
    /// Replaces: C `unsigned short CSA`.
    pub csa: u16,
    /// PXE service type code.
    /// Replaces: C `unsigned short type`.
    pub service_type: u16,
    /// Menu description text shown to the user.
    pub menu: Option<String>,
    /// Base filename for the boot image.
    pub basename: Option<String>,
    /// Server name for the boot service.
    pub sname: Option<String>,
    /// IP address of the boot server.
    pub server: Ipv4Addr,
    /// Tags that must match for this service to be offered.
    /// Replaces: C `struct dhcp_netid *netid` linked list.
    pub netid: Vec<DhcpNetId>,
}

/// Default PXE vendor class string.
/// Replaces: C `DHCP_PXE_DEF_VENDOR` from `dnsmasq.h` line 1181.
pub const DHCP_PXE_DEF_VENDOR: &str = "PXEClient";

// ===========================================================================
// Match Type Constants (dnsmasq.h lines 1183–1187)
// ===========================================================================

/// Match against vendor class (option 60).
/// Replaces: C `MATCH_VENDOR` from `dnsmasq.h` line 1183.
pub const MATCH_VENDOR: i32 = 1;

/// Match against user class (option 77).
/// Replaces: C `MATCH_USER` from `dnsmasq.h` line 1184.
pub const MATCH_USER: i32 = 2;

/// Match against circuit ID (relay agent sub-option 1).
/// Replaces: C `MATCH_CIRCUIT` from `dnsmasq.h` line 1185.
pub const MATCH_CIRCUIT: i32 = 3;

/// Match against remote ID (relay agent sub-option 2).
/// Replaces: C `MATCH_REMOTE` from `dnsmasq.h` line 1186.
pub const MATCH_REMOTE: i32 = 4;

/// Match against subscriber ID (relay agent sub-option 6).
/// Replaces: C `MATCH_SUBSCRIBER` from `dnsmasq.h` line 1187.
pub const MATCH_SUBSCRIBER: i32 = 5;

// ===========================================================================
// Vendor/MAC Matching Types (dnsmasq.h lines 1190–1209)
// ===========================================================================

/// DHCP vendor/user/circuit/remote class matching rule.
///
/// Matches incoming DHCP requests against vendor class, user class,
/// circuit ID, remote ID, or subscriber ID values and sets tags
/// when a match is found.
///
/// Replaces: C `struct dhcp_vendor` (dnsmasq.h lines 1190–1196).
/// NOTE: The `next` pointer is removed.
#[derive(Debug, Clone)]
pub struct DhcpVendor {
    /// Length of the match data.
    pub len: i32,
    /// Type of match (MATCH_VENDOR, MATCH_USER, etc.).
    pub match_type: i32,
    /// Enterprise number for RFC 3925 vendor-identifying options.
    pub enterprise: u32,
    /// Match data string.
    /// Replaces: C `char *data`.
    pub data: String,
    /// Tag to set when match succeeds.
    /// Replaces: C `struct dhcp_netid netid` (embedded, not pointer).
    pub netid: DhcpNetId,
}

/// PXE vendor class data for vendor identification.
///
/// Replaces: C `struct dhcp_pxe_vendor` (dnsmasq.h lines 1198–1201).
/// NOTE: The `next` pointer is removed.
#[derive(Debug, Clone)]
pub struct DhcpPxeVendor {
    /// Vendor class string data.
    pub data: String,
}

/// DHCP hardware address matching rule for tag assignment.
///
/// Matches clients by hardware (MAC) address with optional wildcard
/// masking and sets tags when a match is found.
///
/// Replaces: C `struct dhcp_mac` (dnsmasq.h lines 1203–1209).
/// NOTE: The `next` pointer is removed.
#[derive(Debug, Clone)]
pub struct DhcpMac {
    /// Bitmask for wildcard matching (0 = exact match on all bytes).
    pub mask: u32,
    /// Length of the hardware address in bytes.
    pub hwaddr_len: i32,
    /// Hardware address type (ARPHRD_ETHER = 1, etc.).
    pub hwaddr_type: i32,
    /// Hardware address bytes (max DHCP_CHADDR_MAX = 16).
    /// Replaces: C `unsigned char hwaddr[DHCP_CHADDR_MAX]`.
    pub hwaddr: Vec<u8>,
    /// Tag to set when the hardware address matches.
    /// Replaces: C `struct dhcp_netid netid` (embedded, not pointer).
    pub netid: DhcpNetId,
}

// ===========================================================================
// DHCP Bridge / Conditional Domain (dnsmasq.h lines 1211–1224)
// ===========================================================================

/// DHCP bridge alias configuration for interface bridging.
///
/// Maps physical interfaces to bridge interfaces so that DHCP can
/// properly identify which subnet a client belongs to when operating
/// behind a bridge.
///
/// Replaces: C `struct dhcp_bridge` (dnsmasq.h lines 1211–1214).
/// NOTE: The `next` pointer is removed, `alias` linked list becomes `Vec`.
#[derive(Debug, Clone)]
pub struct DhcpBridge {
    /// Interface name (max IF_NAMESIZE characters).
    /// Replaces: C `char iface[IF_NAMESIZE]`.
    pub iface: String,
    /// Alias bridge interfaces.
    /// Replaces: C `struct dhcp_bridge *alias` linked list.
    pub aliases: Vec<DhcpBridge>,
}

/// Conditional domain configuration for split-horizon DNS.
///
/// Associates domain names with address ranges or interfaces, enabling
/// different domain suffixes for different subnets (split-horizon).
///
/// Replaces: C `struct cond_domain` (dnsmasq.h lines 1216–1224).
/// NOTE: The `next` pointer is removed.
#[derive(Debug, Clone)]
pub struct CondDomain {
    /// Domain name suffix for matching addresses.
    /// Replaces: C `char *domain`.
    pub domain: Option<String>,
    /// Text prefix prepended to generated hostnames.
    /// Replaces: C `char *prefix`.
    pub prefix: Option<String>,
    /// Interface name (set when domain comes from interface).
    /// Replaces: C `char *interface`.
    pub interface: Option<String>,
    /// Address list for this conditional domain.
    /// Replaces: C `struct addrlist *al`.
    pub al: Vec<AddrList>,
    /// Start of IPv4 address range.
    pub start: Ipv4Addr,
    /// End of IPv4 address range.
    pub end: Ipv4Addr,
    /// Start of IPv6 address range.
    pub start6: Ipv6Addr,
    /// End of IPv6 address range.
    pub end6: Ipv6Addr,
    /// Whether this is an IPv6 conditional domain.
    /// Replaces: C `int is6` (non-zero = IPv6).
    pub is6: bool,
    /// Interface index for indexed domains.
    pub indexed: i32,
    /// Prefix length for subnet matching.
    pub prefixlen: i32,
}

// ===========================================================================
// Router Advertisement Interface (dnsmasq.h lines 1226–1231)
// ===========================================================================

/// Router Advertisement interface configuration.
///
/// Configures per-interface Router Advertisement parameters including
/// advertisement interval, router lifetime, priority, and MTU.
///
/// Replaces: C `struct ra_interface` (dnsmasq.h lines 1226–1231).
/// NOTE: The `next` pointer is removed.
#[derive(Debug, Clone)]
pub struct RaInterface {
    /// Interface name for this RA configuration.
    pub name: String,
    /// Name of the interface to use for MTU option (if different).
    pub mtu_name: Option<String>,
    /// RA interval in seconds (MinRtrAdvInterval → MaxRtrAdvInterval).
    pub interval: i32,
    /// Router lifetime in seconds (0 = not default router).
    pub lifetime: i32,
    /// Router preference (0 = medium, 1 = high, -1 = low).
    pub prio: i32,
    /// MTU value to advertise (0 = omit MTU option).
    pub mtu: i32,
}

// ===========================================================================
// DhcpContext — Address Pool Configuration (dnsmasq.h lines 1233–1280)
// ===========================================================================

bitflags! {
    /// DHCP context/range flags controlling address pool behavior.
    ///
    /// These flags control how a DHCP address range is used, whether it
    /// provides Router Advertisements, is a template, or has been
    /// constructed from interface information.
    ///
    /// Replaces: `CONTEXT_*` constants from `dnsmasq.h` lines 1261–1280.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct DhcpContextFlags: u32 {
        /// Static address allocation only (no dynamic range).
        const STATIC       = 1 << 0;
        /// Netmask explicitly set.
        const NETMASK      = 1 << 1;
        /// Broadcast address explicitly set.
        const BRDCAST      = 1 << 2;
        /// Proxy DHCP mode (respond with options but don't allocate addresses).
        const PROXY        = 1 << 3;
        /// Include router address in RA PIOs.
        const RA_ROUTER    = 1 << 4;
        /// Router Advertisement has been sent for this context.
        const RA_DONE      = 1 << 5;
        /// Use DNS to find router name for RA.
        const RA_NAME      = 1 << 6;
        /// RA-only, stateless DHCPv6 (M=0, O=1 or O=0).
        const RA_STATELESS = 1 << 7;
        /// Context provides DHCP addresses.
        const DHCP         = 1 << 8;
        /// Prefix is deprecated (still valid but not preferred).
        const DEPRECATE    = 1 << 9;
        /// Template context (creates contexts from interface addresses).
        const TEMPLATE     = 1 << 10;
        /// Context was auto-constructed from interface address discovery.
        const CONSTRUCTED  = 1 << 11;
        /// Garbage collection mark (for removing stale constructed contexts).
        const GC           = 1 << 12;
        /// Context is used for Router Advertisements.
        const RA           = 1 << 13;
        /// Configuration has been matched/used.
        const CONF_USED    = 1 << 14;
        /// Context is currently in use (has matching interface address).
        const USED         = 1 << 15;
        /// Context marked as old (previous configuration).
        const OLD          = 1 << 16;
        /// IPv6 context.
        const V6           = 1 << 17;
        /// RA prefix is off-link (L=0 in PIO).
        const RA_OFF_LINK  = 1 << 18;
        /// Use lease time from context for RA valid lifetime.
        const SETLEASE     = 1 << 19;
    }
}

/// DHCP address pool context/range configuration.
///
/// Defines a range of IP addresses available for dynamic DHCP allocation,
/// along with associated parameters like lease time, netmask, broadcast
/// address, and router. Each context represents one `dhcp-range` directive.
///
/// Replaces: C `struct dhcp_context` (dnsmasq.h lines 1233–1249).
/// NOTE: The `next`/`current` pointers are removed — contexts stored in `Vec`.
#[derive(Debug, Clone)]
pub struct DhcpContext {
    /// Default lease time for this range (seconds).
    pub lease_time: u32,
    /// Address epoch counter for detecting range changes.
    pub addr_epoch: u32,
    /// Network mask for this range.
    pub netmask: Ipv4Addr,
    /// Broadcast address for this range.
    pub broadcast: Ipv4Addr,
    /// Local interface address for this range.
    pub local: Ipv4Addr,
    /// Default router address for this range.
    pub router: Ipv4Addr,
    /// Start of the available IPv4 address range.
    pub start: Ipv4Addr,
    /// End of the available IPv4 address range.
    pub end: Ipv4Addr,

    /// Start of the available IPv6 address range.
    #[cfg(feature = "dhcp6")]
    pub start6: Ipv6Addr,
    /// End of the available IPv6 address range.
    #[cfg(feature = "dhcp6")]
    pub end6: Ipv6Addr,
    /// Local IPv6 interface address.
    #[cfg(feature = "dhcp6")]
    pub local6: Ipv6Addr,
    /// IPv6 prefix length.
    #[cfg(feature = "dhcp6")]
    pub prefix: i32,
    /// Interface index for this context.
    #[cfg(feature = "dhcp6")]
    pub if_index: i32,
    /// Valid lifetime for IPv6 prefix (seconds).
    #[cfg(feature = "dhcp6")]
    pub valid: u32,
    /// Preferred lifetime for IPv6 prefix (seconds).
    #[cfg(feature = "dhcp6")]
    pub preferred: u32,
    /// Saved valid lifetime before deprecation.
    #[cfg(feature = "dhcp6")]
    pub saved_valid: u32,
    /// Time of next Router Advertisement for this context.
    #[cfg(feature = "dhcp6")]
    pub ra_time: i64,
    /// Start time of RA short period (rapid advertisements).
    #[cfg(feature = "dhcp6")]
    pub ra_short_period_start: i64,
    /// Time when the address/prefix was lost (for deprecation).
    #[cfg(feature = "dhcp6")]
    pub address_lost_time: i64,
    /// Interface name for template-constructed contexts.
    #[cfg(feature = "dhcp6")]
    pub template_interface: Option<String>,

    /// Context behavior flags.
    pub flags: DhcpContextFlags,
    /// Network tag for this context.
    /// Replaces: C `struct dhcp_netid netid` (embedded, not pointer).
    pub netid: DhcpNetId,
    /// Tags that must be present for this context to be used.
    /// Replaces: C `struct dhcp_netid *filter` linked list.
    pub filter: Vec<DhcpNetId>,
}

/// Shared network configuration linking interfaces to DHCP contexts.
///
/// Maps interface indices and addresses to shared DHCP address pools,
/// enabling multiple interfaces to share the same DHCP address range.
///
/// Replaces: C `struct shared_network` (dnsmasq.h lines 1251–1259).
/// NOTE: The `next` pointer is removed.
#[derive(Debug, Clone)]
pub struct SharedNetwork {
    /// Interface index for this shared network mapping.
    pub if_index: i32,
    /// IPv4 address to match on the interface.
    pub match_addr: Ipv4Addr,
    /// IPv4 address of the shared network.
    pub shared_addr: Ipv4Addr,
    /// IPv6 address to match on the interface.
    #[cfg(feature = "dhcp6")]
    pub match_addr6: Ipv6Addr,
    /// IPv6 address of the shared network.
    #[cfg(feature = "dhcp6")]
    pub shared_addr6: Ipv6Addr,
}

// ===========================================================================
// Ping Result (dnsmasq.h lines 1282–1287)
// ===========================================================================

/// Result of an ICMP ping probe for DHCP address conflict detection.
///
/// Before offering an address, dnsmasq can ping it to detect conflicts.
/// This struct records the result of such a probe.
///
/// Replaces: C `struct ping_result` (dnsmasq.h lines 1282–1287).
/// NOTE: The `next` pointer is removed.
#[derive(Debug, Clone)]
pub struct PingResult {
    /// The IPv4 address that was pinged.
    pub addr: Ipv4Addr,
    /// Time when the ping was sent (seconds since epoch).
    pub time: i64,
    /// Hash of the ping for correlation.
    pub hash: u32,
}

// ===========================================================================
// TFTP Types (dnsmasq.h lines 1289–1321) — feature-gated
// ===========================================================================

/// TFTP file handle with reference counting.
///
/// Represents an open file being served by the TFTP server. Multiple
/// transfers can share the same file handle (reference counted).
///
/// Replaces: C `struct tftp_file` (dnsmasq.h lines 1289–1295).
/// NOTE: The flexible array member `filename[]` becomes a `String`.
#[cfg(feature = "tftp")]
#[derive(Debug, Clone)]
pub struct TftpFile {
    /// Number of active transfers using this file.
    pub refcount: i32,
    /// File descriptor for the open file.
    pub fd: i32,
    /// Total file size in bytes.
    pub size: i64,
    /// Current read position in the file.
    pub posn: i64,
    /// Device ID (for identifying unique files across filesystems).
    pub dev: u64,
    /// Inode number (for identifying unique files on the same filesystem).
    pub inode: u64,
    /// Filename path.
    /// Replaces: C `char filename[]` (flexible array member).
    pub filename: String,
}

/// Active TFTP transfer state.
///
/// Tracks the complete state of an in-progress TFTP file transfer
/// including socket, block tracking, peer address, and transfer options.
///
/// Replaces: C `struct tftp_transfer` (dnsmasq.h lines 1297–1309).
/// NOTE: The `next` pointer is removed — transfers stored in `Vec`.
#[cfg(feature = "tftp")]
#[derive(Debug, Clone)]
pub struct TftpTransfer {
    /// Socket file descriptor for this transfer.
    pub sockfd: i32,
    /// High bits of block counter (for large file support).
    pub block_hi: u16,
    /// Previous ACK block number received.
    pub ackprev: u16,
    /// Time of last retransmission (seconds since epoch).
    pub retransmit: i64,
    /// Transfer start time (seconds since epoch).
    pub start: i64,
    /// Last acknowledged block number (full 32-bit).
    pub lastack: u32,
    /// Current block number being sent.
    pub block: u32,
    /// Negotiated block size in bytes (default 512).
    pub blocksize: u32,
    /// Negotiated window size (RFC 7440).
    pub windowsize: u32,
    /// Negotiated timeout in seconds.
    pub timeout: u32,
    /// Expansion factor for adaptive timeout.
    pub expansion: u32,
    /// Current file offset for reading.
    pub offset: i64,
    /// Peer (client) socket address.
    /// Replaces: C `union mysockaddr peer`.
    pub peer: SocketAddress,
    /// Source (local) address for sending.
    /// Replaces: C `union all_addr source`.
    pub source: AllAddr,
    /// Interface index for the transfer.
    pub if_index: i32,
    /// Whether blocksize option was negotiated.
    /// Replaces: C `unsigned char opt_blocksize` (treated as bool).
    pub opt_blocksize: bool,
    /// Whether transfer size option was negotiated.
    /// Replaces: C `unsigned char opt_transize` (treated as bool).
    pub opt_transize: bool,
    /// Whether window size option was negotiated.
    /// Replaces: C `unsigned char opt_windowsize` (treated as bool).
    pub opt_windowsize: bool,
    /// Whether timeout option was negotiated.
    /// Replaces: C `unsigned char opt_timeout` (treated as bool).
    pub opt_timeout: bool,
    /// Whether this is a netascii mode transfer.
    /// Replaces: C `unsigned char netascii` (treated as bool).
    pub netascii: bool,
    /// Carry LF state for netascii CR-LF conversion.
    /// Replaces: C `unsigned char carrylf` (treated as bool).
    pub carrylf: bool,
    /// Last carry LF state for netascii conversion.
    /// Replaces: C `unsigned char lastcarrylf` (treated as bool).
    pub lastcarrylf: bool,
    /// Retransmission backoff counter.
    /// Replaces: C `unsigned char backoff`.
    pub backoff: u8,
    /// File being transferred (shared reference).
    /// Replaces: C `struct tftp_file *file`.
    pub file: Option<TftpFile>,
}

/// TFTP prefix configuration for per-interface file path mapping.
///
/// Maps interface names to file path prefixes, allowing different
/// interfaces to serve files from different directories.
///
/// Replaces: C `struct tftp_prefix` (dnsmasq.h lines 1316–1321).
/// NOTE: The `next` pointer is removed.
#[cfg(feature = "tftp")]
#[derive(Debug, Clone)]
pub struct TftpPrefix {
    /// Interface name this prefix applies to.
    pub interface: String,
    /// File path prefix to prepend to requested filenames.
    pub prefix: String,
    /// Whether to allow access to missing files (404 vs reject).
    /// Replaces: C `int missing` (non-zero = allow missing).
    pub missing: bool,
}

// ===========================================================================
// DHCP Relay Types (dnsmasq.h lines 1323–1341)
// ===========================================================================

/// Relay address type replacing the C union of IPv4/IPv6 addresses.
///
/// In the C code, `struct dhcp_relay` uses `union { struct in_addr addr4;
/// struct in6_addr addr6; }` for `local`, `server`, and `uplink` fields.
/// This Rust enum provides type-safe address storage.
///
/// Replaces: C `union { struct in_addr addr4; struct in6_addr addr6; }`
/// inside `struct dhcp_relay` (dnsmasq.h lines 1324–1327).
#[derive(Debug, Clone)]
pub enum RelayAddr {
    /// IPv4 relay address.
    V4(Ipv4Addr),
    /// IPv6 relay address.
    V6(Ipv6Addr),
}

/// DHCP relay snoop record for prefix delegation tracking.
///
/// Records client IPv6 address and delegated prefix information
/// captured during DHCP relay snooping. Used by the script helper
/// for lease-change notification.
///
/// Replaces: C `struct snoop_record` (dnsmasq.h lines 1334–1338).
/// NOTE: The `next` pointer is removed.
#[cfg(feature = "script")]
#[derive(Debug, Clone)]
pub struct SnoopRecord {
    /// Client IPv6 address.
    pub client: Ipv6Addr,
    /// Delegated IPv6 prefix.
    pub prefix: Ipv6Addr,
    /// Length of the delegated prefix.
    pub prefix_len: i32,
}

/// DHCP relay agent configuration.
///
/// Configures a DHCP relay that forwards DHCP messages between clients
/// on one network segment and a DHCP server on another. Supports both
/// DHCPv4 and DHCPv6 relay modes.
///
/// Replaces: C `struct dhcp_relay` (dnsmasq.h lines 1323–1341).
/// NOTE: The `next` pointer is removed — relay configs stored in `Vec`.
#[derive(Debug, Clone)]
pub struct DhcpRelay {
    /// Local address to listen on for relay.
    pub local: RelayAddr,
    /// Server address to forward requests to.
    pub server: RelayAddr,
    /// Uplink address (for DHCPv6 relay chain).
    pub uplink: RelayAddr,
    /// Allowable interface for replies from server (also dest for IPv6 multicast).
    /// Replaces: C `char *interface`.
    pub interface: Option<String>,
    /// Working interface index where requests arrived (for return path).
    pub iface_index: i32,
    /// Port of the relay server to forward to.
    pub port: i32,
    /// Split address allocation and relay address mode.
    pub split_mode: i32,
    /// Warning flag (set when relay warnings have been issued).
    pub warned: i32,
    /// Count of matched relay hops.
    pub matchcount: i32,
    /// Snoop records for prefix delegation tracking (script feature).
    /// Replaces: C `struct snoop_record *snoop_records` linked list.
    #[cfg(feature = "script")]
    pub snoop_records: Vec<SnoopRecord>,
}

// ===========================================================================
// Unit Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lease_flags_values() {
        // Verify flag values match the C constants exactly
        assert_eq!(LeaseFlags::NEW.bits(), 1);
        assert_eq!(LeaseFlags::CHANGED.bits(), 2);
        assert_eq!(LeaseFlags::AUX_CHANGED.bits(), 4);
        assert_eq!(LeaseFlags::AUTH_NAME.bits(), 8);
        assert_eq!(LeaseFlags::USED.bits(), 16);
        assert_eq!(LeaseFlags::NA.bits(), 32);
        assert_eq!(LeaseFlags::TA.bits(), 64);
        assert_eq!(LeaseFlags::HAVE_HWADDR.bits(), 128);
        assert_eq!(LeaseFlags::EXP_CHANGED.bits(), 256);
    }

    #[test]
    fn test_lease_flags_combination() {
        let flags = LeaseFlags::NEW | LeaseFlags::CHANGED | LeaseFlags::NA;
        assert!(flags.contains(LeaseFlags::NEW));
        assert!(flags.contains(LeaseFlags::CHANGED));
        assert!(flags.contains(LeaseFlags::NA));
        assert!(!flags.contains(LeaseFlags::TA));
        assert_eq!(flags.bits(), 1 | 2 | 32);
    }

    #[test]
    fn test_dhcp_opt_type_flags_values() {
        assert_eq!(DhcpOptTypeFlags::ADDR_LIST.bits(), 0x8000);
        assert_eq!(DhcpOptTypeFlags::RFC1035_NAME.bits(), 0x4000);
        assert_eq!(DhcpOptTypeFlags::INTERNAL.bits(), 0x2000);
        assert_eq!(DhcpOptTypeFlags::NAME.bits(), 0x1000);
        assert_eq!(DhcpOptTypeFlags::CSTRING.bits(), 0x0800);
        assert_eq!(DhcpOptTypeFlags::DEC.bits(), 0x0400);
        assert_eq!(DhcpOptTypeFlags::TIME.bits(), 0x0200);
    }

    #[test]
    fn test_action_constants() {
        assert_eq!(ACTION_DEL, 1);
        assert_eq!(ACTION_OLD_HOSTNAME, 2);
        assert_eq!(ACTION_OLD, 3);
        assert_eq!(ACTION_ADD, 4);
        assert_eq!(ACTION_TFTP, 5);
        assert_eq!(ACTION_ARP, 6);
        assert_eq!(ACTION_ARP_DEL, 7);
        assert_eq!(ACTION_RELAY_SNOOP, 8);
    }

    #[test]
    fn test_match_constants() {
        assert_eq!(MATCH_VENDOR, 1);
        assert_eq!(MATCH_USER, 2);
        assert_eq!(MATCH_CIRCUIT, 3);
        assert_eq!(MATCH_REMOTE, 4);
        assert_eq!(MATCH_SUBSCRIBER, 5);
    }

    #[test]
    fn test_dhcp_pxe_def_vendor() {
        assert_eq!(DHCP_PXE_DEF_VENDOR, "PXEClient");
    }

    #[test]
    fn test_dhcp_config_flags_values() {
        assert_eq!(DhcpConfigFlags::DISABLE.bits(), 1);
        assert_eq!(DhcpConfigFlags::CLID.bits(), 2);
        assert_eq!(DhcpConfigFlags::TIME.bits(), 8);
        assert_eq!(DhcpConfigFlags::NAME.bits(), 16);
        assert_eq!(DhcpConfigFlags::ADDR.bits(), 32);
        assert_eq!(DhcpConfigFlags::NOCLID.bits(), 128);
        assert_eq!(DhcpConfigFlags::FROM_ETHERS.bits(), 256);
        assert_eq!(DhcpConfigFlags::ADDR_HOSTS.bits(), 512);
        assert_eq!(DhcpConfigFlags::DECLINED.bits(), 1024);
        assert_eq!(DhcpConfigFlags::BANK.bits(), 2048);
        assert_eq!(DhcpConfigFlags::ADDR6.bits(), 4096);
        assert_eq!(DhcpConfigFlags::ADDR6_HOSTS.bits(), 16384);
    }

    #[test]
    fn test_dhcp_opt_flags_values() {
        assert_eq!(DhcpOptFlags::ADDR.bits(), 1);
        assert_eq!(DhcpOptFlags::STRING.bits(), 2);
        assert_eq!(DhcpOptFlags::ENCAPSULATE.bits(), 4);
        assert_eq!(DhcpOptFlags::ENCAP_MATCH.bits(), 8);
        assert_eq!(DhcpOptFlags::FORCE.bits(), 16);
        assert_eq!(DhcpOptFlags::BANK.bits(), 32);
        assert_eq!(DhcpOptFlags::ENCAP_DONE.bits(), 64);
        assert_eq!(DhcpOptFlags::MATCH.bits(), 128);
        assert_eq!(DhcpOptFlags::VENDOR.bits(), 256);
        assert_eq!(DhcpOptFlags::HEX.bits(), 512);
        assert_eq!(DhcpOptFlags::VENDOR_MATCH.bits(), 1024);
        assert_eq!(DhcpOptFlags::RFC3925.bits(), 2048);
        assert_eq!(DhcpOptFlags::TAGOK.bits(), 4096);
        assert_eq!(DhcpOptFlags::ADDR6.bits(), 8192);
        assert_eq!(DhcpOptFlags::VENDOR_PXE.bits(), 16384);
        assert_eq!(DhcpOptFlags::PXE_OPT.bits(), 32768);
    }

    #[test]
    fn test_dhcp_context_flags_values() {
        assert_eq!(DhcpContextFlags::STATIC.bits(), 1 << 0);
        assert_eq!(DhcpContextFlags::NETMASK.bits(), 1 << 1);
        assert_eq!(DhcpContextFlags::BRDCAST.bits(), 1 << 2);
        assert_eq!(DhcpContextFlags::PROXY.bits(), 1 << 3);
        assert_eq!(DhcpContextFlags::RA_ROUTER.bits(), 1 << 4);
        assert_eq!(DhcpContextFlags::RA_DONE.bits(), 1 << 5);
        assert_eq!(DhcpContextFlags::RA_NAME.bits(), 1 << 6);
        assert_eq!(DhcpContextFlags::RA_STATELESS.bits(), 1 << 7);
        assert_eq!(DhcpContextFlags::DHCP.bits(), 1 << 8);
        assert_eq!(DhcpContextFlags::DEPRECATE.bits(), 1 << 9);
        assert_eq!(DhcpContextFlags::TEMPLATE.bits(), 1 << 10);
        assert_eq!(DhcpContextFlags::CONSTRUCTED.bits(), 1 << 11);
        assert_eq!(DhcpContextFlags::GC.bits(), 1 << 12);
        assert_eq!(DhcpContextFlags::RA.bits(), 1 << 13);
        assert_eq!(DhcpContextFlags::CONF_USED.bits(), 1 << 14);
        assert_eq!(DhcpContextFlags::USED.bits(), 1 << 15);
        assert_eq!(DhcpContextFlags::OLD.bits(), 1 << 16);
        assert_eq!(DhcpContextFlags::V6.bits(), 1 << 17);
        assert_eq!(DhcpContextFlags::RA_OFF_LINK.bits(), 1 << 18);
        assert_eq!(DhcpContextFlags::SETLEASE.bits(), 1 << 19);
    }

    #[test]
    fn test_dhcp_net_id_equality() {
        let id1 = DhcpNetId { net: "known".to_string() };
        let id2 = DhcpNetId { net: "known".to_string() };
        let id3 = DhcpNetId { net: "unknown".to_string() };
        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_relay_addr_variants() {
        let v4 = RelayAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let v6 = RelayAddr::V6(Ipv6Addr::LOCALHOST);
        match v4 {
            RelayAddr::V4(addr) => assert_eq!(addr, Ipv4Addr::new(192, 168, 1, 1)),
            RelayAddr::V6(_) => panic!("Expected V4"),
        }
        match v6 {
            RelayAddr::V6(addr) => assert_eq!(addr, Ipv6Addr::LOCALHOST),
            RelayAddr::V4(_) => panic!("Expected V6"),
        }
    }

    #[test]
    fn test_dhcp_opt_extra_variants() {
        let encap = DhcpOptExtra::Encap(43);
        let mask = DhcpOptExtra::WildcardMask(0xFF);
        let vendor = DhcpOptExtra::VendorClass(vec![0x50, 0x58, 0x45]);
        let none = DhcpOptExtra::None;

        match encap {
            DhcpOptExtra::Encap(v) => assert_eq!(v, 43),
            _ => panic!("Expected Encap"),
        }
        match mask {
            DhcpOptExtra::WildcardMask(v) => assert_eq!(v, 0xFF),
            _ => panic!("Expected WildcardMask"),
        }
        match vendor {
            DhcpOptExtra::VendorClass(ref v) => assert_eq!(v, &[0x50, 0x58, 0x45]),
            _ => panic!("Expected VendorClass"),
        }
        match none {
            DhcpOptExtra::None => {}
            _ => panic!("Expected None"),
        }
    }

    #[test]
    fn test_dhcp_lease_default_construction() {
        let lease = DhcpLease {
            clid: vec![0x01, 0x08, 0x00, 0x27],
            hostname: Some("testhost".to_string()),
            fqdn: Some("testhost.example.com".to_string()),
            old_hostname: None,
            flags: LeaseFlags::NEW,
            expires: 1700000000,
            hwaddr_len: 6,
            hwaddr_type: 1,
            hwaddr: vec![0x08, 0x00, 0x27, 0xAA, 0xBB, 0xCC],
            addr: Ipv4Addr::new(192, 168, 1, 100),
            override_addr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            extradata: Vec::new(),
            last_interface: 0,
            new_interface: 0,
            new_prefixlen: 0,
            agent_id: Vec::new(),
            vendorclass: Vec::new(),
            #[cfg(feature = "dhcp6")]
            addr6: Ipv6Addr::UNSPECIFIED,
            #[cfg(feature = "dhcp6")]
            iaid: 0,
            #[cfg(feature = "dhcp6")]
            slaac_addresses: Vec::new(),
            #[cfg(feature = "dhcp6")]
            vendorclass_count: 0,
        };

        assert_eq!(lease.hostname.as_deref(), Some("testhost"));
        assert!(lease.flags.contains(LeaseFlags::NEW));
        assert_eq!(lease.addr, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(lease.hwaddr.len(), 6);
    }

    #[test]
    fn test_dhcp_context_flags_combination() {
        let flags = DhcpContextFlags::DHCP | DhcpContextFlags::RA | DhcpContextFlags::V6;
        assert!(flags.contains(DhcpContextFlags::DHCP));
        assert!(flags.contains(DhcpContextFlags::RA));
        assert!(flags.contains(DhcpContextFlags::V6));
        assert!(!flags.contains(DhcpContextFlags::STATIC));
        assert!(!flags.contains(DhcpContextFlags::PROXY));
    }

    #[test]
    fn test_ping_result_construction() {
        let result = PingResult {
            addr: Ipv4Addr::new(10, 0, 0, 1),
            time: 1700000000,
            hash: 0xDEADBEEF,
        };
        assert_eq!(result.addr, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(result.hash, 0xDEADBEEF);
    }

    #[test]
    fn test_dhcp_boot_construction() {
        let boot = DhcpBoot {
            file: Some("pxelinux.0".to_string()),
            sname: Some("tftpserver".to_string()),
            tftp_sname: None,
            next_server: Ipv4Addr::new(192, 168, 1, 1),
            netid: vec![DhcpNetId { net: "pxe".to_string() }],
        };
        assert_eq!(boot.file.as_deref(), Some("pxelinux.0"));
        assert_eq!(boot.next_server, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(boot.netid.len(), 1);
    }

    #[test]
    fn test_dhcp_bridge_nested() {
        let bridge = DhcpBridge {
            iface: "br0".to_string(),
            aliases: vec![
                DhcpBridge {
                    iface: "eth0".to_string(),
                    aliases: Vec::new(),
                },
                DhcpBridge {
                    iface: "eth1".to_string(),
                    aliases: Vec::new(),
                },
            ],
        };
        assert_eq!(bridge.iface, "br0");
        assert_eq!(bridge.aliases.len(), 2);
        assert_eq!(bridge.aliases[0].iface, "eth0");
    }
}

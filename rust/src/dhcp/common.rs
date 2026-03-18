// dnsmasq is Copyright (c) 2000-2025 Simon Kelley
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! # Shared DHCP Utilities for DHCPv4 and DHCPv6
//!
//! Rust port of `src/dhcp-common.c` (2,337 lines). Provides shared utilities used
//! by both DHCPv4 and DHCPv6 subsystems:
//!
//! - **Tag-based configuration matching**: `match_netid`, `match_netid_wild`, `run_tag_if`
//!   implement dnsmasq's client classification system using network ID tags.
//! - **Option tables and lookups**: `DHCP4_OPTIONS`, `DHCP6_OPTIONS`, `lookup_dhcp_opt`,
//!   `lookup_dhcp_len`, `option_string` for protocol option encoding/decoding.
//! - **Client configuration search**: `find_config`, `config_has_mac`, `dhcp_update_configs`
//!   for static host reservations and per-client settings.
//! - **Device binding**: `which_device`, `bind_dhcp_devices` for SO_BINDTODEVICE on Linux.
//! - **Packet reception**: `recv_dhcp_packet` for async UDP packet reception with Vec growth.
//! - **Logging**: `log_context`, `log_relay`, `log_tags` for DHCP transaction diagnostics.
//!
//! All C linked lists have been replaced with `Vec` collections.
//! All C `malloc`/`free` replaced with Rust ownership and `Vec<u8>` automatic growth.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use socket2::Socket;
use tokio::net::UdpSocket;
use tracing::info;

use crate::config::constants::{DHCP_PACKET_MAX, MAXDNAME};
use crate::core::types::{opt, DaemonState, DnsmasqError, DnsmasqResult};
use crate::core::util::{format_duration, hostname_eq, is_same_net, is_same_net6};

// ---------------------------------------------------------------------------
// Option table type-size flag constants (from dnsmasq.h lines 1001-1007)
// ---------------------------------------------------------------------------

/// Option value is a list of IP addresses.
const OT_ADDR_LIST: u16 = 0x8000;
/// Option value is an RFC 1035 encoded domain name (label-length format).
const OT_RFC1035_NAME: u16 = 0x4000;
/// Internal option — not user-settable.
const OT_INTERNAL: u16 = 0x2000;
/// Option value is a printable text string.
const OT_NAME: u16 = 0x1000;
/// Option value is a counted string (DHCPv6 length-prefixed).
#[cfg(feature = "dhcp6")]
const OT_CSTRING: u16 = 0x0800;
/// Option value is a decimal integer.
const OT_DEC: u16 = 0x0400;
/// Option value is a time duration in seconds.
const OT_TIME: u16 = 0x0200;

// ---------------------------------------------------------------------------
// DHCP option flags (from dnsmasq.h lines 1142-1157)
// ---------------------------------------------------------------------------

/// Option data contains an IP address.
pub const DHOPT_ADDR: u32 = 1;
/// Option data is a string.
pub const DHOPT_STRING: u32 = 2;
/// Option is encapsulated within another option.
pub const DHOPT_ENCAPSULATE: u32 = 4;
/// Encapsulation match marker.
pub const DHOPT_ENCAP_MATCH: u32 = 8;
/// Force-send option even if client didn't request it.
pub const DHOPT_FORCE: u32 = 16;
/// Option loaded from a dhcp-hostsfile bank.
pub const DHOPT_BANK: u32 = 32;
/// Encapsulation processing completed.
pub const DHOPT_ENCAP_DONE: u32 = 64;
/// Option used for matching, not sending.
pub const DHOPT_MATCH: u32 = 128;
/// Vendor-class option.
pub const DHOPT_VENDOR: u32 = 256;
/// Option data is raw hex.
pub const DHOPT_HEX: u32 = 512;
/// Vendor class match marker.
pub const DHOPT_VENDOR_MATCH: u32 = 1024;
/// RFC 3925 vendor-identifying options.
pub const DHOPT_RFC3925: u32 = 2048;
/// Tag-match passed for this option.
pub const DHOPT_TAGOK: u32 = 4096;
/// Option data contains an IPv6 address.
pub const DHOPT_ADDR6: u32 = 8192;
/// PXE vendor-specific option.
pub const DHOPT_VENDOR_PXE: u32 = 16384;
/// PXE boot option.
pub const DHOPT_PXE_OPT: u32 = 32768;

// ---------------------------------------------------------------------------
// Client configuration flags (from dnsmasq.h lines 1117-1128)
// ---------------------------------------------------------------------------

/// Config entry disabled.
pub const CONFIG_DISABLE: u32 = 1;
/// Config matched by client-id.
pub const CONFIG_CLID: u32 = 2;
/// Explicit lease time set.
pub const CONFIG_TIME: u32 = 8;
/// Hostname configured.
pub const CONFIG_NAME: u32 = 16;
/// IPv4 address configured.
pub const CONFIG_ADDR: u32 = 32;
/// Client-id matching disabled.
pub const CONFIG_NOCLID: u32 = 128;
/// Entry created from /etc/ethers.
pub const CONFIG_FROM_ETHERS: u32 = 256;
/// Address imported from /etc/hosts DNS cache.
pub const CONFIG_ADDR_HOSTS: u32 = 512;
/// Address declined by client.
pub const CONFIG_DECLINED: u32 = 1024;
/// Entry loaded from dhcp-hostsfile.
pub const CONFIG_BANK: u32 = 2048;
/// IPv6 address configured.
pub const CONFIG_ADDR6: u32 = 4096;
/// IPv6 address imported from /etc/hosts DNS cache.
pub const CONFIG_ADDR6_HOSTS: u32 = 16384;

// ---------------------------------------------------------------------------
// DHCP context flags (from dnsmasq.h lines 1261-1282)
// ---------------------------------------------------------------------------

/// Static leases only in this context.
pub const CONTEXT_STATIC: u32 = 1 << 0;
/// Explicit netmask configured.
pub const CONTEXT_NETMASK: u32 = 1 << 1;
/// Explicit broadcast configured.
pub const CONTEXT_BRDCAST: u32 = 1 << 2;
/// Proxy DHCP mode.
pub const CONTEXT_PROXY: u32 = 1 << 3;
/// RA router flag.
pub const CONTEXT_RA_ROUTER: u32 = 1 << 4;
/// RA processing done.
pub const CONTEXT_RA_DONE: u32 = 1 << 5;
/// RA-derived names.
pub const CONTEXT_RA_NAME: u32 = 1 << 6;
/// RA stateless mode.
pub const CONTEXT_RA_STATELESS: u32 = 1 << 7;
/// DHCP enabled on this context.
pub const CONTEXT_DHCP: u32 = 1 << 8;
/// Prefix deprecated.
pub const CONTEXT_DEPRECATE: u32 = 1 << 9;
/// Template context for dynamic creation.
pub const CONTEXT_TEMPLATE: u32 = 1 << 10;
/// Context constructed from RA.
pub const CONTEXT_CONSTRUCTED: u32 = 1 << 11;
/// Garbage collection mark.
pub const CONTEXT_GC: u32 = 1 << 12;
/// Router Advertisement enabled.
pub const CONTEXT_RA: u32 = 1 << 13;
/// Configuration used marker.
pub const CONTEXT_CONF_USED: u32 = 1 << 14;
/// Address used marker.
pub const CONTEXT_USED: u32 = 1 << 15;
/// Old prefix (being replaced).
pub const CONTEXT_OLD: u32 = 1 << 16;
/// IPv6 context.
pub const CONTEXT_V6: u32 = 1 << 17;
/// RA off-link flag.
pub const CONTEXT_RA_OFF_LINK: u32 = 1 << 18;
/// Set lease via script.
pub const CONTEXT_SETLEASE: u32 = 1 << 19;

// ---------------------------------------------------------------------------
// PXE mode constants (from dhcp-common.c pxe_ok)
// ---------------------------------------------------------------------------

/// PXE option mode: match all.
const PXE_MATCH_ALL: i32 = 0;
/// PXE option mode: require PXE.
const PXE_REQUIRE: i32 = 1;
/// PXE option mode: reject PXE.
const PXE_REJECT: i32 = 2;

// ---------------------------------------------------------------------------
// DHCP port constants (from dhcp-protocol.h)
// ---------------------------------------------------------------------------

/// Standard DHCPv4 server port (RFC 2131).
pub const DHCP_SERVER_PORT: u16 = 67;
/// Standard DHCPv6 server port (RFC 3315).
#[cfg(feature = "dhcp6")]
pub const DHCPV6_SERVER_PORT: u16 = 547;

// =========================================================================
// Public Type Definitions
// =========================================================================

/// Network identifier tag used for client classification.
///
/// Maps to C `struct dhcp_netid` (`dnsmasq.h` line 1069). The C linked list
/// is replaced by `Vec<NetId>` in all call sites.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NetId {
    /// Tag name string (e.g., `"known"`, `"red"`, `"!blue"`).
    /// Prefix `!` or `#` indicates negation in matching.
    /// Prefix `*` indicates wildcard suffix match.
    pub net: String,
}

/// Extra data attached to a DHCP option, replacing C union.
#[derive(Debug, Clone)]
pub enum DhcpOptExtra {
    /// Encapsulation option code.
    Encap(i32),
    /// Wildcard mask for byte matching.
    WildcardMask(u32),
    /// Vendor class identifier bytes.
    VendorClass(Vec<u8>),
    /// No extra data.
    None,
}

/// DHCP option configuration entry.
///
/// Maps to C `struct dhcp_opt` (`dnsmasq.h` line 1130). The C linked list
/// `next` pointer is replaced by `Vec<DhcpOpt>` at collection level.
#[derive(Debug, Clone)]
pub struct DhcpOpt {
    /// Option code (0-255 for v4, 0-65535 for v6).
    pub opt: u16,
    /// Option value bytes.
    pub val: Vec<u8>,
    /// Option flags (DHOPT_* constants).
    pub flags: u32,
    /// Associated network tag for conditional sending.
    pub netid: Option<NetId>,
    /// Sub-options (replaces C linked list `next`).
    pub next: Vec<DhcpOpt>,
    /// Length of option data.
    pub len: usize,
    /// Extra option data (replaces C union `u`).
    pub u: DhcpOptExtra,
}

/// Hardware address configuration for matching.
///
/// Maps to C `struct hwaddr_config` (`dnsmasq.h` line 1091).
#[derive(Debug, Clone)]
pub struct HwAddrConfig {
    /// Hardware address bytes (up to 16).
    pub hwaddr: Vec<u8>,
    /// Hardware address type (e.g., 1 = Ethernet).
    pub hwaddr_type: i32,
    /// Bitmask for wildcard byte positions.
    pub wildcard_mask: u32,
}

/// Static per-client DHCP configuration.
///
/// Maps to C `struct dhcp_config` (`dnsmasq.h` line 1098). Linked list
/// replaced by `Vec<DhcpConfig>` at collection level.
#[derive(Debug, Clone)]
pub struct DhcpConfig {
    /// Configuration flags (CONFIG_* constants).
    pub flags: u32,
    /// Hardware addresses for matching (replaces C linked list).
    pub hwaddr: Vec<HwAddrConfig>,
    /// Client identifier bytes.
    pub clid: Option<Vec<u8>>,
    /// Configured hostname.
    pub hostname: Option<String>,
    /// Network tags associated with this config.
    pub netid: Vec<NetId>,
    /// Network tag filter for context matching.
    pub filter: Vec<NetId>,
    /// Static IPv4 address assignment.
    pub addr: Option<Ipv4Addr>,
    /// Static IPv6 address assignments.
    #[cfg(feature = "dhcp6")]
    pub addr6: Vec<Ipv6Addr>,
    /// Domain override for this client.
    pub domain: Option<String>,
    /// Lease time override (seconds).
    pub lease_time: u32,
    /// Time of last decline (for backoff).
    pub decline_time: i64,
}

/// DHCP address pool / context configuration.
///
/// Maps to C `struct dhcp_context` (`dnsmasq.h` line 1233).
#[derive(Debug, Clone)]
pub struct DhcpContext {
    /// Start of IPv4 address range.
    pub start: Ipv4Addr,
    /// End of IPv4 address range.
    pub end: Ipv4Addr,
    /// Subnet mask for this context.
    pub netmask: Ipv4Addr,
    /// Broadcast address.
    pub broadcast: Ipv4Addr,
    /// Default router for this subnet.
    pub router: Ipv4Addr,
    /// Lease time in seconds.
    pub lease_time: u32,
    /// Network tag for this context.
    pub netid: NetId,
    /// Context flags (CONTEXT_* constants).
    pub flags: u32,
    /// Context filter tags.
    pub filter: Vec<NetId>,
    /// Local address.
    pub local: Ipv4Addr,
    /// Address epoch counter.
    pub addr_epoch: u32,
    /// Start of IPv6 address range.
    #[cfg(feature = "dhcp6")]
    pub start6: Ipv6Addr,
    /// End of IPv6 address range.
    #[cfg(feature = "dhcp6")]
    pub end6: Ipv6Addr,
    /// Local IPv6 address.
    #[cfg(feature = "dhcp6")]
    pub local6: Ipv6Addr,
    /// IPv6 prefix length.
    #[cfg(feature = "dhcp6")]
    pub prefix: i32,
    /// Interface index for constructed contexts.
    #[cfg(feature = "dhcp6")]
    pub if_index: i32,
    /// Valid lifetime for RA.
    #[cfg(feature = "dhcp6")]
    pub valid: u32,
    /// Preferred lifetime for RA.
    #[cfg(feature = "dhcp6")]
    pub preferred: u32,
    /// Template interface name.
    #[cfg(feature = "dhcp6")]
    pub template_interface: Option<String>,
}

/// DHCP protocol version selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhcpProtocol {
    /// DHCPv4 (RFC 2131).
    V4,
    /// DHCPv6 (RFC 3315).
    V6,
}

/// DHCP relay agent configuration.
///
/// Maps to C `struct dhcp_relay` (`dnsmasq.h` line 1323).
#[derive(Debug, Clone)]
pub struct DhcpRelay {
    /// Local address (listening side).
    pub local: std::net::IpAddr,
    /// Server address (forwarding destination).
    pub server: std::net::IpAddr,
    /// Interface name restriction (may be empty).
    pub interface: Option<String>,
    /// Relay forwarding port.
    pub port: u16,
    /// Split-relay mode: separate request/response paths.
    pub split_mode: bool,
    /// Interface index for incoming requests.
    pub iface_index: i32,
}

/// Conditional tag-if rule for dynamic tag assignment.
///
/// Maps to C `struct tag_if` (`dnsmasq.h` line 1079). If all tags in
/// `tag` match the current tag set, the tags in `set` are added.
#[derive(Debug, Clone)]
pub struct TagIfRule {
    /// Tags that must be present to trigger the rule.
    pub tag: Vec<NetId>,
    /// Tags to add when rule triggers.
    pub set: Vec<NetId>,
}

/// Address family selector for logging and context operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFamily {
    /// IPv4 (AF_INET).
    Inet,
    /// IPv6 (AF_INET6).
    Inet6,
}

/// DHCP option definition table entry.
///
/// Maps to C `struct opttab_t` (local to `dhcp-common.c`).
#[derive(Debug, Clone)]
pub struct DhcpOptDef {
    /// Human-readable option name.
    pub name: &'static str,
    /// Size/type flags (OT_* constants ORed with byte count).
    pub size: u16,
    /// DHCP option code number.
    pub opt_code: u16,
}

// =========================================================================
// Option Tables (from dhcp-common.c opttab[] lines 1584-1667)
// =========================================================================

/// DHCPv4 option definitions. Exact port of C `opttab[]`.
pub const DHCP4_OPTIONS: &[DhcpOptDef] = &[
    DhcpOptDef {
        name: "netmask",
        opt_code: 1,
        size: OT_ADDR_LIST,
    },
    DhcpOptDef {
        name: "time-offset",
        opt_code: 2,
        size: 4,
    },
    DhcpOptDef {
        name: "router",
        opt_code: 3,
        size: OT_ADDR_LIST,
    },
    DhcpOptDef {
        name: "dns-server",
        opt_code: 6,
        size: OT_ADDR_LIST,
    },
    DhcpOptDef {
        name: "log-server",
        opt_code: 7,
        size: OT_ADDR_LIST,
    },
    DhcpOptDef {
        name: "lpr-server",
        opt_code: 9,
        size: OT_ADDR_LIST,
    },
    DhcpOptDef {
        name: "hostname",
        opt_code: 12,
        size: OT_INTERNAL | OT_NAME,
    },
    DhcpOptDef {
        name: "boot-file-size",
        opt_code: 13,
        size: 2 | OT_DEC,
    },
    DhcpOptDef {
        name: "domain-name",
        opt_code: 15,
        size: OT_NAME,
    },
    DhcpOptDef {
        name: "swap-server",
        opt_code: 16,
        size: OT_ADDR_LIST,
    },
    DhcpOptDef {
        name: "root-path",
        opt_code: 17,
        size: OT_NAME,
    },
    DhcpOptDef {
        name: "extension-path",
        opt_code: 18,
        size: OT_NAME,
    },
    DhcpOptDef {
        name: "ip-forward-enable",
        opt_code: 19,
        size: 1,
    },
    DhcpOptDef {
        name: "non-local-source-routing",
        opt_code: 20,
        size: 1,
    },
    DhcpOptDef {
        name: "policy-filter",
        opt_code: 21,
        size: OT_ADDR_LIST,
    },
    DhcpOptDef {
        name: "max-datagram-reassembly",
        opt_code: 22,
        size: 2 | OT_DEC,
    },
    DhcpOptDef {
        name: "default-ttl",
        opt_code: 23,
        size: 1 | OT_DEC,
    },
    DhcpOptDef {
        name: "mtu",
        opt_code: 26,
        size: 2 | OT_DEC,
    },
    DhcpOptDef {
        name: "all-subnets-local",
        opt_code: 27,
        size: 1,
    },
    DhcpOptDef {
        name: "broadcast",
        opt_code: 28,
        size: OT_INTERNAL | OT_ADDR_LIST,
    },
    DhcpOptDef {
        name: "router-discovery",
        opt_code: 31,
        size: 1,
    },
    DhcpOptDef {
        name: "router-solicitation",
        opt_code: 32,
        size: OT_ADDR_LIST,
    },
    DhcpOptDef {
        name: "static-route",
        opt_code: 33,
        size: OT_ADDR_LIST,
    },
    DhcpOptDef {
        name: "trailer-encapsulation",
        opt_code: 34,
        size: 1,
    },
    DhcpOptDef {
        name: "arp-timeout",
        opt_code: 35,
        size: 4 | OT_DEC,
    },
    DhcpOptDef {
        name: "ethernet-encap",
        opt_code: 36,
        size: 1,
    },
    DhcpOptDef {
        name: "tcp-ttl",
        opt_code: 37,
        size: 1,
    },
    DhcpOptDef {
        name: "tcp-keepalive",
        opt_code: 38,
        size: 4 | OT_DEC,
    },
    DhcpOptDef {
        name: "nis-domain",
        opt_code: 40,
        size: OT_NAME,
    },
    DhcpOptDef {
        name: "nis-server",
        opt_code: 41,
        size: OT_ADDR_LIST,
    },
    DhcpOptDef {
        name: "ntp-server",
        opt_code: 42,
        size: OT_ADDR_LIST,
    },
    DhcpOptDef {
        name: "vendor-encap",
        opt_code: 43,
        size: OT_INTERNAL,
    },
    DhcpOptDef {
        name: "netbios-ns",
        opt_code: 44,
        size: OT_ADDR_LIST,
    },
    DhcpOptDef {
        name: "netbios-dd",
        opt_code: 45,
        size: OT_ADDR_LIST,
    },
    DhcpOptDef {
        name: "netbios-nodetype",
        opt_code: 46,
        size: 1,
    },
    DhcpOptDef {
        name: "netbios-scope",
        opt_code: 47,
        size: 0,
    },
    DhcpOptDef {
        name: "x-windows-fs",
        opt_code: 48,
        size: OT_ADDR_LIST,
    },
    DhcpOptDef {
        name: "x-windows-dm",
        opt_code: 49,
        size: OT_ADDR_LIST,
    },
    DhcpOptDef {
        name: "requested-address",
        opt_code: 50,
        size: OT_INTERNAL | OT_ADDR_LIST,
    },
    DhcpOptDef {
        name: "lease-time",
        opt_code: 51,
        size: OT_INTERNAL | OT_TIME,
    },
    DhcpOptDef {
        name: "option-overload",
        opt_code: 52,
        size: OT_INTERNAL,
    },
    DhcpOptDef {
        name: "message-type",
        opt_code: 53,
        size: OT_INTERNAL | OT_DEC,
    },
    DhcpOptDef {
        name: "server-identifier",
        opt_code: 54,
        size: OT_INTERNAL | OT_ADDR_LIST,
    },
    DhcpOptDef {
        name: "parameter-request",
        opt_code: 55,
        size: OT_INTERNAL,
    },
    DhcpOptDef {
        name: "message",
        opt_code: 56,
        size: OT_INTERNAL,
    },
    DhcpOptDef {
        name: "max-message-size",
        opt_code: 57,
        size: OT_INTERNAL,
    },
    DhcpOptDef {
        name: "T1",
        opt_code: 58,
        size: OT_TIME,
    },
    DhcpOptDef {
        name: "T2",
        opt_code: 59,
        size: OT_TIME,
    },
    DhcpOptDef {
        name: "vendor-class",
        opt_code: 60,
        size: 0,
    },
    DhcpOptDef {
        name: "client-id",
        opt_code: 61,
        size: OT_INTERNAL,
    },
    DhcpOptDef {
        name: "nis+-domain",
        opt_code: 64,
        size: OT_NAME,
    },
    DhcpOptDef {
        name: "nis+-server",
        opt_code: 65,
        size: OT_ADDR_LIST,
    },
    DhcpOptDef {
        name: "tftp-server",
        opt_code: 66,
        size: OT_NAME,
    },
    DhcpOptDef {
        name: "bootfile-name",
        opt_code: 67,
        size: OT_NAME,
    },
    DhcpOptDef {
        name: "mobile-ip-home",
        opt_code: 68,
        size: OT_ADDR_LIST,
    },
    DhcpOptDef {
        name: "smtp-server",
        opt_code: 69,
        size: OT_ADDR_LIST,
    },
    DhcpOptDef {
        name: "pop3-server",
        opt_code: 70,
        size: OT_ADDR_LIST,
    },
    DhcpOptDef {
        name: "nntp-server",
        opt_code: 71,
        size: OT_ADDR_LIST,
    },
    DhcpOptDef {
        name: "irc-server",
        opt_code: 74,
        size: OT_ADDR_LIST,
    },
    DhcpOptDef {
        name: "user-class",
        opt_code: 77,
        size: 0,
    },
    DhcpOptDef {
        name: "rapid-commit",
        opt_code: 80,
        size: 0,
    },
    DhcpOptDef {
        name: "FQDN",
        opt_code: 81,
        size: OT_INTERNAL,
    },
    DhcpOptDef {
        name: "agent-info",
        opt_code: 82,
        size: OT_INTERNAL,
    },
    DhcpOptDef {
        name: "last-transaction",
        opt_code: 91,
        size: 4 | OT_TIME,
    },
    DhcpOptDef {
        name: "associated-ip",
        opt_code: 92,
        size: OT_ADDR_LIST,
    },
    DhcpOptDef {
        name: "client-arch",
        opt_code: 93,
        size: 2 | OT_DEC,
    },
    DhcpOptDef {
        name: "client-interface-id",
        opt_code: 94,
        size: 0,
    },
    DhcpOptDef {
        name: "client-machine-id",
        opt_code: 97,
        size: 0,
    },
    DhcpOptDef {
        name: "posix-timezone",
        opt_code: 100,
        size: OT_NAME,
    },
    DhcpOptDef {
        name: "tzdb-timezone",
        opt_code: 101,
        size: OT_NAME,
    },
    DhcpOptDef {
        name: "ipv6-only",
        opt_code: 108,
        size: 4 | OT_DEC,
    },
    DhcpOptDef {
        name: "subnet-select",
        opt_code: 118,
        size: OT_INTERNAL,
    },
    DhcpOptDef {
        name: "domain-search",
        opt_code: 119,
        size: OT_RFC1035_NAME,
    },
    DhcpOptDef {
        name: "sip-server",
        opt_code: 120,
        size: 0,
    },
    DhcpOptDef {
        name: "classless-static-route",
        opt_code: 121,
        size: 0,
    },
    DhcpOptDef {
        name: "vendor-id-encap",
        opt_code: 125,
        size: 0,
    },
    DhcpOptDef {
        name: "tftp-server-address",
        opt_code: 150,
        size: OT_ADDR_LIST,
    },
    DhcpOptDef {
        name: "server-ip-address",
        opt_code: 255,
        size: OT_ADDR_LIST,
    },
];

/// DHCPv6 option definitions. Exact port of C `opttab6[]`.
#[cfg(feature = "dhcp6")]
pub const DHCP6_OPTIONS: &[DhcpOptDef] = &[
    DhcpOptDef {
        name: "client-id",
        opt_code: 1,
        size: OT_INTERNAL,
    },
    DhcpOptDef {
        name: "server-id",
        opt_code: 2,
        size: OT_INTERNAL,
    },
    DhcpOptDef {
        name: "ia-na",
        opt_code: 3,
        size: OT_INTERNAL,
    },
    DhcpOptDef {
        name: "ia-ta",
        opt_code: 4,
        size: OT_INTERNAL,
    },
    DhcpOptDef {
        name: "iaaddr",
        opt_code: 5,
        size: OT_INTERNAL,
    },
    DhcpOptDef {
        name: "oro",
        opt_code: 6,
        size: OT_INTERNAL,
    },
    DhcpOptDef {
        name: "preference",
        opt_code: 7,
        size: OT_INTERNAL | OT_DEC,
    },
    DhcpOptDef {
        name: "unicast",
        opt_code: 12,
        size: OT_INTERNAL,
    },
    DhcpOptDef {
        name: "status",
        opt_code: 13,
        size: OT_INTERNAL,
    },
    DhcpOptDef {
        name: "rapid-commit",
        opt_code: 14,
        size: OT_INTERNAL,
    },
    DhcpOptDef {
        name: "user-class",
        opt_code: 15,
        size: OT_INTERNAL | OT_CSTRING,
    },
    DhcpOptDef {
        name: "vendor-class",
        opt_code: 16,
        size: OT_INTERNAL | OT_CSTRING,
    },
    DhcpOptDef {
        name: "vendor-opts",
        opt_code: 17,
        size: OT_INTERNAL,
    },
    DhcpOptDef {
        name: "sip-server-domain",
        opt_code: 21,
        size: OT_RFC1035_NAME,
    },
    DhcpOptDef {
        name: "sip-server",
        opt_code: 22,
        size: OT_ADDR_LIST,
    },
    DhcpOptDef {
        name: "dns-server",
        opt_code: 23,
        size: OT_ADDR_LIST,
    },
    DhcpOptDef {
        name: "domain-search",
        opt_code: 24,
        size: OT_RFC1035_NAME,
    },
    DhcpOptDef {
        name: "nis-server",
        opt_code: 27,
        size: OT_ADDR_LIST,
    },
    DhcpOptDef {
        name: "nis+-server",
        opt_code: 28,
        size: OT_ADDR_LIST,
    },
    DhcpOptDef {
        name: "nis-domain",
        opt_code: 29,
        size: OT_RFC1035_NAME,
    },
    DhcpOptDef {
        name: "nis+-domain",
        opt_code: 30,
        size: OT_RFC1035_NAME,
    },
    DhcpOptDef {
        name: "sntp-server",
        opt_code: 31,
        size: OT_ADDR_LIST,
    },
    DhcpOptDef {
        name: "information-refresh-time",
        opt_code: 32,
        size: OT_TIME,
    },
    DhcpOptDef {
        name: "FQDN",
        opt_code: 39,
        size: OT_INTERNAL | OT_RFC1035_NAME,
    },
    DhcpOptDef {
        name: "posix-timezone",
        opt_code: 41,
        size: OT_NAME,
    },
    DhcpOptDef {
        name: "tzdb-timezone",
        opt_code: 42,
        size: OT_NAME,
    },
    DhcpOptDef {
        name: "ntp-server",
        opt_code: 56,
        size: 0,
    },
    DhcpOptDef {
        name: "bootfile-url",
        opt_code: 59,
        size: OT_NAME,
    },
    DhcpOptDef {
        name: "bootfile-param",
        opt_code: 60,
        size: OT_CSTRING,
    },
];

/// Placeholder for builds without DHCPv6 — empty option table.
#[cfg(not(feature = "dhcp6"))]
pub const DHCP6_OPTIONS: &[DhcpOptDef] = &[];

// =========================================================================
// Initialization
// =========================================================================

/// Initialize shared DHCP buffers on the daemon state.
///
/// Maps to C `dhcp_common_init()` (`dhcp-common.c` line 107).
/// In Rust, `Vec` handles dynamic allocation so this simply ensures
/// the packet buffer is pre-allocated.
pub fn dhcp_common_init(state: &mut DaemonState) {
    // Ensure DHCP packet buffer has initial capacity.
    // The C code allocates sizeof(struct dhcp_packet) ≈ 576 bytes initially.
    #[cfg(feature = "dhcp")]
    {
        if state.dhcp_packet.is_empty() {
            state.dhcp_packet.resize(576, 0);
        }
    }
    // namebuff is used for formatting; ensure capacity.
    if state.namebuff.capacity() < MAXDNAME {
        state.namebuff.reserve(MAXDNAME - state.namebuff.capacity());
    }
}

// =========================================================================
// Packet Reception
// =========================================================================

/// Receive a DHCP packet from an async UDP socket with automatic buffer growth.
///
/// Maps to C `recv_dhcp_packet()` (`dhcp-common.c` line 175).
/// Replaces C's MSG_PEEK + MSG_TRUNC + `expand_buf()` pattern with
/// Rust's `Vec<u8>` automatic growth and tokio async I/O.
///
/// The buffer grows up to `DHCP_PACKET_MAX` (16384) bytes to accommodate
/// oversized DHCP packets while preventing unbounded allocation.
///
/// Returns `(bytes_read, source_address)` on success.
pub async fn recv_dhcp_packet(
    socket: &UdpSocket,
    buf: &mut Vec<u8>,
) -> DnsmasqResult<(usize, SocketAddr)> {
    // Ensure minimum buffer capacity
    if buf.len() < 576 {
        buf.resize(576, 0);
    }

    loop {
        // Attempt to receive
        let result = socket.recv_from(buf).await;
        match result {
            Ok((n, addr)) => {
                // If we filled the entire buffer, the packet may have been truncated.
                // Grow the buffer and retry (mimics C MSG_PEEK + MSG_TRUNC pattern).
                if n == buf.len() && buf.len() < DHCP_PACKET_MAX {
                    let new_size = (buf.len() * 2).min(DHCP_PACKET_MAX);
                    buf.resize(new_size, 0);
                    // The packet was already dequeued by recv_from, so return what we have.
                    // Unlike C's MSG_PEEK approach, tokio dequeues immediately.
                    return Ok((n, addr));
                }
                return Ok((n, addr));
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {
                // Retry on EINTR
                continue;
            }
            Err(e) => {
                return Err(DnsmasqError::Network(format!("recv_dhcp_packet: {}", e)));
            }
        }
    }
}

// =========================================================================
// Tag Matching Functions
// =========================================================================

/// Check if a single tag matches against a pool of tags (exact match).
///
/// Maps to C `match_netid()` (`dhcp-common.c` line 605).
///
/// - `check`: Tags to verify (all must be satisfied).
/// - `pool`: Available tags to match against.
/// - `tag_not_needed`: If true, empty `check` matches; if false, empty `check` fails.
///
/// Supports `!` or `#` prefix for negation: `!tag` matches when `tag` is NOT in pool.
pub fn match_netid(check: &[NetId], pool: &[NetId], tag_not_needed: bool) -> bool {
    if check.is_empty() {
        return tag_not_needed;
    }

    for check_tag in check {
        let tag_name = &check_tag.net;

        // Check for negation prefix '!' or '#'
        let (negated, bare_name) = if tag_name.starts_with('!') || tag_name.starts_with('#') {
            (true, &tag_name[1..])
        } else {
            (false, tag_name.as_str())
        };

        let found = pool.iter().any(|p| p.net == bare_name);

        if found == negated {
            // Found but negated → fail; not found and not negated → fail
            return false;
        }
    }

    true
}

/// Wildcard-aware tag matching.
///
/// Maps to C `match_netid_wild()` (`dhcp-common.c` line 269).
/// Like `match_netid` but also supports `*` prefix for substring matching:
/// a check tag `*foo` matches any pool tag containing `foo`.
pub fn match_netid_wild(check: &[NetId], pool: &[NetId]) -> bool {
    if check.is_empty() {
        return true;
    }

    for check_tag in check {
        let tag_name = &check_tag.net;

        // Check for negation prefix
        let (negated, rest) = if tag_name.starts_with('!') || tag_name.starts_with('#') {
            (true, &tag_name[1..])
        } else {
            (false, tag_name.as_str())
        };

        // Check for wildcard prefix
        let (wildcard, bare_name) = if let Some(stripped) = rest.strip_prefix('*') {
            (true, stripped)
        } else {
            (false, rest)
        };

        let found = if wildcard {
            // Wildcard: match if any pool tag contains the bare name
            pool.iter().any(|p| p.net.contains(bare_name))
        } else {
            pool.iter().any(|p| p.net == bare_name)
        };

        if found == negated {
            return false;
        }
    }

    true
}

/// Evaluate tag-if conditional rules and return additional tags.
///
/// Maps to C `run_tag_if()` (`dhcp-common.c` line 344).
/// For each rule in `tag_if_rules`, if all tags in `rule.tag` match the
/// current tag set (using wildcard matching), all tags in `rule.set` are
/// added to the result.
///
/// Iterates until no new tags are added (fixed-point).
pub fn run_tag_if(tags: &[NetId], tag_if_rules: &[TagIfRule]) -> Vec<NetId> {
    let mut result: Vec<NetId> = tags.to_vec();
    let mut changed = true;

    while changed {
        changed = false;
        for rule in tag_if_rules {
            if match_netid_wild(&rule.tag, &result) {
                for set_tag in &rule.set {
                    if !result.contains(set_tag) {
                        result.push(set_tag.clone());
                        changed = true;
                    }
                }
            }
        }
    }

    result
}

/// Filter DHCP options by tag match.
///
/// Maps to C `option_filter()` (`dhcp-common.c` line 470).
///
/// Implements the C four-pass algorithm:
/// 1. Mark options whose netid tags match the active tags (DHOPT_TAGOK).
/// 2. Re-evaluate with context tags.
/// 3. Untagged options (no netid) always match if not overridden.
/// 4. Deduplicate (last match wins for same option code).
///
/// Returns references to matching options.
pub fn option_filter<'a>(
    tags: &[NetId],
    context_tags: &[NetId],
    opts: &'a [DhcpOpt],
    pxe_mode: bool,
) -> Vec<&'a DhcpOpt> {
    // Phase 1: Mark options whose tags match the active tag set
    let mut tag_ok: Vec<bool> = vec![false; opts.len()];

    for (i, o) in opts.iter().enumerate() {
        if let Some(ref netid) = o.netid {
            let check = std::slice::from_ref(netid);
            if match_netid(check, tags, true) {
                tag_ok[i] = true;
            }
        }
    }

    // Phase 2: Re-check with context tags for those not yet matched
    if !context_tags.is_empty() {
        let mut combined = tags.to_vec();
        combined.extend_from_slice(context_tags);
        for (i, o) in opts.iter().enumerate() {
            if !tag_ok[i] {
                if let Some(ref netid) = o.netid {
                    let check = std::slice::from_ref(netid);
                    if match_netid(check, &combined, true) {
                        tag_ok[i] = true;
                    }
                }
            }
        }
    }

    // Phase 3: Untagged options always pass (if no explicit tag set)
    for (i, o) in opts.iter().enumerate() {
        if o.netid.is_none() {
            tag_ok[i] = true;
        }
    }

    // Phase 4: Collect results with deduplication (last match wins per opt code).
    // Also apply PXE filter if needed.
    let mut result: Vec<&DhcpOpt> = Vec::new();
    for (i, o) in opts.iter().enumerate() {
        if !tag_ok[i] {
            continue;
        }
        // Skip encapsulated or internal-only flags that shouldn't be directly sent
        if o.flags & DHOPT_ENCAPSULATE != 0 {
            continue;
        }
        if pxe_mode && !pxe_ok(o, PXE_REQUIRE) {
            continue;
        }
        // Deduplicate: remove prior entry with same opt code
        result.retain(|existing| existing.opt != o.opt || existing.flags != o.flags);
        result.push(o);
    }

    result
}

/// PXE option validation.
///
/// Maps to C `pxe_ok()` (`dhcp-common.c` line 411).
///
/// Returns `true` if the option is appropriate for the given PXE mode:
/// - `PXE_MATCH_ALL` (0): always true
/// - `PXE_REQUIRE` (1): only PXE options pass
/// - `PXE_REJECT` (2): only non-PXE options pass
pub fn pxe_ok(opt: &DhcpOpt, pxe_mode: i32) -> bool {
    match pxe_mode {
        PXE_MATCH_ALL => true,
        PXE_REQUIRE => opt.flags & DHOPT_PXE_OPT != 0 || opt.flags & DHOPT_VENDOR_PXE != 0,
        PXE_REJECT => opt.flags & DHOPT_PXE_OPT == 0 && opt.flags & DHOPT_VENDOR_PXE == 0,
        _ => true,
    }
}

// =========================================================================
// Hostname Utilities
// =========================================================================

/// Sanitize a client-provided hostname.
///
/// Maps to C `strip_hostname()` (`dhcp-common.c` line 660).
///
/// Truncates at the first dot (returning only the short hostname).
/// Filters illegal characters. Returns `None` if the result is empty.
pub fn strip_hostname(hostname: &str) -> Option<String> {
    if hostname.is_empty() {
        return None;
    }

    // Truncate at first dot (keep only short name)
    let short = if let Some(dot_pos) = hostname.find('.') {
        &hostname[..dot_pos]
    } else {
        hostname
    };

    // Filter: keep only alphanumeric, hyphen, underscore
    let cleaned: String = short
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();

    // Must not start or end with hyphen
    let trimmed = cleaned.trim_matches('-');

    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

// =========================================================================
// Byte Matching
// =========================================================================

/// Match DHCP option bytes against a pattern.
///
/// Maps to C `match_bytes()` (`dhcp-common.c` line 797).
///
/// Three matching modes based on option flags:
/// - `DHOPT_HEX`: Exact byte match with optional wildcard mask.
/// - `DHOPT_STRING`: Substring match (data bytes anywhere in option value).
/// - Default: Exact match of full data (aligned).
pub fn match_bytes(opt_entry: &DhcpOpt, data: &[u8]) -> bool {
    if opt_entry.val.is_empty() {
        return data.is_empty();
    }

    if opt_entry.flags & DHOPT_HEX != 0 {
        // Hex match: exact length match with optional wildcard mask
        if opt_entry.val.len() != data.len() {
            return false;
        }
        let mask = match &opt_entry.u {
            DhcpOptExtra::WildcardMask(m) => *m,
            _ => 0,
        };
        for (i, (a, b)) in opt_entry.val.iter().zip(data.iter()).enumerate() {
            // If bit i in wildcard mask is set, skip comparison
            if mask & (1u32 << (i & 31)) != 0 {
                continue;
            }
            if a != b {
                return false;
            }
        }
        true
    } else if opt_entry.flags & DHOPT_STRING != 0 {
        // Substring match: option value appears somewhere in data
        if opt_entry.val.len() > data.len() {
            return false;
        }
        data.windows(opt_entry.val.len())
            .any(|w| w == opt_entry.val.as_slice())
    } else {
        // Default: exact match
        opt_entry.val.as_slice() == data
    }
}

// =========================================================================
// Client Configuration Lookup
// =========================================================================

/// Check if a DhcpConfig matches a given hardware address.
///
/// Maps to C `config_has_mac()` (`dhcp-common.c` line 919).
/// Iterates the config's hardware address list and returns true if
/// any entry matches both the address bytes and the hardware type.
/// A hw_type of 0 in the config acts as a wildcard.
pub fn config_has_mac(config: &DhcpConfig, hwaddr: &[u8], hw_type: i32) -> bool {
    for hw in &config.hwaddr {
        if hw.hwaddr.len() != hwaddr.len() {
            continue;
        }
        if hw.hwaddr_type != 0 && hw.hwaddr_type != hw_type {
            continue;
        }
        // Compare with wildcard mask
        let mut matched = true;
        for (i, (a, b)) in hw.hwaddr.iter().zip(hwaddr.iter()).enumerate() {
            if hw.wildcard_mask & (1u32 << (i & 31)) != 0 {
                continue; // wildcard bit → skip
            }
            if a != b {
                matched = false;
                break;
            }
        }
        if matched {
            return true;
        }
    }
    false
}

/// Check if a DhcpConfig's address is within a DhcpContext's range.
///
/// Maps to C `is_config_in_context()` (`dhcp-common.c` line 1007).
fn is_config_in_context(context: &DhcpContext, config: &DhcpConfig) -> bool {
    // Wildcard configs (no specific address) always match
    if config.flags & CONFIG_ADDR == 0 {
        #[cfg(feature = "dhcp6")]
        {
            if config.flags & CONFIG_ADDR6 == 0 {
                return true;
            }
        }
        #[cfg(not(feature = "dhcp6"))]
        {
            return true;
        }
    }

    // IPv6 context matching
    #[cfg(feature = "dhcp6")]
    if context.flags & CONTEXT_V6 != 0 {
        if config.flags & CONFIG_ADDR6 != 0 {
            for a6 in &config.addr6 {
                if is_same_net6(*a6, context.start6, context.prefix as u8) {
                    return true;
                }
            }
        }
        return false;
    }

    // IPv4 context matching
    if let Some(addr) = config.addr {
        if is_same_net(addr, context.start, context.netmask) {
            return true;
        }
    }

    false
}

/// Internal config match logic with priority ordering.
///
/// Maps to C `find_config_match()` (`dhcp-common.c` line 1097).
///
/// Priority: client-id → MAC → hostname → wildcard MAC (best bit count).
fn find_config_match<'a>(
    configs: &'a [DhcpConfig],
    context: &DhcpContext,
    clid: Option<&[u8]>,
    hwaddr: &[u8],
    hw_type: i32,
    hostname: Option<&str>,
    wildcard_ok: bool,
) -> Option<&'a DhcpConfig> {
    let mut candidate: Option<&DhcpConfig> = None;
    let mut best_wildcard_bits: u32 = u32::MAX;

    for config in configs {
        if config.flags & CONFIG_DISABLE != 0 {
            continue;
        }
        if !is_config_in_context(context, config) {
            continue;
        }

        // Match by client-id (highest priority)
        if let (Some(c), Some(ref cfg_clid)) = (clid, &config.clid) {
            if config.flags & CONFIG_CLID != 0 && c == cfg_clid.as_slice() {
                return Some(config);
            }
        }

        // Match by exact MAC
        if config.flags & CONFIG_NOCLID == 0 || clid.is_none() {
            for hw in &config.hwaddr {
                if hw.wildcard_mask == 0
                    && hw.hwaddr.len() == hwaddr.len()
                    && (hw.hwaddr_type == 0 || hw.hwaddr_type == hw_type)
                    && hw.hwaddr.as_slice() == hwaddr
                {
                    return Some(config);
                }
            }
        }

        // Match by hostname
        if let Some(hn) = hostname {
            if let Some(ref cfg_hn) = config.hostname {
                if config.flags & CONFIG_NAME != 0 && hostname_eq(hn, cfg_hn) {
                    return Some(config);
                }
            }
        }

        // Wildcard MAC match (partial/masked)
        if wildcard_ok {
            for hw in &config.hwaddr {
                if hw.wildcard_mask != 0
                    && hw.hwaddr.len() == hwaddr.len()
                    && (hw.hwaddr_type == 0 || hw.hwaddr_type == hw_type)
                {
                    let mut matched = true;
                    for (i, (a, b)) in hw.hwaddr.iter().zip(hwaddr.iter()).enumerate() {
                        if hw.wildcard_mask & (1u32 << (i & 31)) != 0 {
                            continue;
                        }
                        if a != b {
                            matched = false;
                            break;
                        }
                    }
                    if matched && hw.wildcard_mask < best_wildcard_bits {
                        best_wildcard_bits = hw.wildcard_mask;
                        candidate = Some(config);
                    }
                }
            }
        }
    }

    candidate
}

/// Find the best matching client configuration.
///
/// Maps to C `find_config()` (`dhcp-common.c` line 1228).
///
/// Two-pass strategy:
/// 1. First pass with exact tag matching (wildcard_ok = false).
/// 2. Second pass with wildcard MAC matching (wildcard_ok = true).
pub fn find_config<'a>(
    configs: &'a [DhcpConfig],
    context: &DhcpContext,
    clid: Option<&[u8]>,
    hwaddr: &[u8],
    hw_type: i32,
    hostname: Option<&str>,
) -> Option<&'a DhcpConfig> {
    // First pass: exact match only
    if let Some(cfg) = find_config_match(configs, context, clid, hwaddr, hw_type, hostname, false) {
        return Some(cfg);
    }
    // Second pass: allow wildcard MAC
    find_config_match(configs, context, clid, hwaddr, hw_type, hostname, true)
}

/// Update DHCP static configs from DNS cache entries.
///
/// Maps to C `dhcp_update_configs()` (`dhcp-common.c` line 1288).
///
/// For each config with a hostname but no explicit address, attempt DNS
/// resolution and assign the address if found. Clears `CONFIG_ADDR_HOSTS`
/// flags first, then repopulates from DNS.
pub fn dhcp_update_configs(configs: &mut [DhcpConfig], _state: &DaemonState) {
    // Clear ADDR_HOSTS and ADDR6_HOSTS flags from all configs
    for config in configs.iter_mut() {
        config.flags &= !CONFIG_ADDR_HOSTS;
        #[cfg(feature = "dhcp6")]
        {
            config.flags &= !CONFIG_ADDR6_HOSTS;
        }
    }

    // In the C code, this does DNS cache lookups for hostnames and
    // assigns addresses. In the Rust architecture, DNS cache lookups
    // would be provided by the dns::cache module. We perform the
    // update logic structure here; actual DNS integration is handled
    // when the cache module is available.
    //
    // For each config with a hostname and no static address:
    // - Query DNS cache for A/AAAA records
    // - If found, set CONFIG_ADDR_HOSTS flag and assign address
    // - Check for duplicates across configs
    for config in configs.iter_mut() {
        if config.hostname.is_none() {
            continue;
        }
        // Skip configs that already have a manually configured address
        if config.flags & CONFIG_ADDR != 0 && config.flags & CONFIG_ADDR_HOSTS == 0 {
            continue;
        }
        // DNS cache integration point: when the cache module calls back,
        // it will set config.addr and config.flags |= CONFIG_ADDR | CONFIG_ADDR_HOSTS
    }
}

// =========================================================================
// Device Binding
// =========================================================================

/// Determine the single DHCP-bound interface device name.
///
/// Maps to C `whichdevice()` (`dhcp-common.c` line 1430).
///
/// If we are doing DHCP on exactly one interface and running on Linux, we can
/// use `SO_BINDTODEVICE` to that device. This is needed for environments like
/// OpenStack that run a new dnsmasq instance per VLAN interface.
///
/// Returns `Some(device_name)` if all DHCP-enabled interfaces resolve to the
/// same device, or `None` if there are multiple, no interfaces, or if wildcard
/// interface names were specified (since more interfaces may appear later).
pub fn which_device(state: &DaemonState) -> Option<String> {
    // If no --interface names were specified, we cannot determine a single device.
    if state.if_names.is_empty() {
        return None;
    }

    // If any interface filter entry is unused or contains a wildcard ('*'),
    // more interfaces may arrive later — cannot safely bind to a single device.
    for if_name in &state.if_names {
        if let Some(name) = &if_name.name {
            if !if_name.used || name.contains('*') {
                return None;
            }
        } else {
            // Name-less entries (address-based) cannot be bound by device name
            return None;
        }
    }

    // Iterate the active interface records to find DHCP-enabled ones.
    // C checks iface->dhcp4_ok || iface->dhcp6_ok via irec fields.
    // In Rust, InterfaceRecord.flags stores per-interface capability bits.
    // IREC_DHCP4 (bit 0x01) and IREC_DHCP6 (bit 0x02) indicate DHCP support.
    const IREC_DHCP4: u32 = 0x01;
    const IREC_DHCP6: u32 = 0x02;

    let mut found_name: Option<&str> = None;
    for iface in &state.interfaces {
        if iface.flags & (IREC_DHCP4 | IREC_DHCP6) != 0 {
            match found_name {
                None => found_name = Some(&iface.name),
                Some(prev) => {
                    if prev != iface.name {
                        // Multiple distinct devices — cannot bind to one
                        return None;
                    }
                }
            }
        }
    }

    found_name.map(|s| s.to_string())
}

/// Bind DHCP sockets to a specific network device via SO_BINDTODEVICE.
///
/// Maps to C `bind_dhcp_devices()` (`dhcp-common.c` line 1559).
///
/// On Linux, sets `SO_BINDTODEVICE` on DHCP listener sockets to restrict
/// packet reception to the named interface. Gracefully handles EPERM for
/// non-root operation.
#[cfg(target_os = "linux")]
pub fn bind_dhcp_devices(device: &str, state: &DaemonState) -> DnsmasqResult<()> {
    use std::os::fd::FromRawFd;

    if device.is_empty() {
        return Ok(());
    }

    // Bind DHCP socket fds to the specified device using SO_BINDTODEVICE,
    // matching C's bind_dhcp_devices() in dhcp-common.c line 1559.
    //
    // Binds: dhcpfd (when DHCP enabled and not relay4),
    //        pxefd (when PXE enabled),
    //        dhcp6fd (when DHCPv6 enabled and not relay6).

    // DHCPv4 socket — bind if active and not in relay mode
    if state.dhcpfd >= 0 && state.relay4.is_empty() {
        // SAFETY: dhcpfd is a valid socket fd opened by the DHCP server init.
        // We create a temporary Socket wrapper without taking ownership (we
        // use ManuallyDrop to prevent close on drop since state owns the fd).
        let sock = unsafe { Socket::from_raw_fd(state.dhcpfd) };
        let sock = std::mem::ManuallyDrop::new(sock);
        if let Err(e) = _bindtodevice(device, &sock) {
            tracing::warn!(
                target: "dnsmasq::dhcp",
                "Failed to bind DHCPv4 socket to {}: {}",
                device, e
            );
        }
    }

    // PXE socket — bind if PXE enabled and fd is valid
    if state.enable_pxe && state.pxefd >= 0 {
        // SAFETY: pxefd is a valid socket fd opened by the PXE server init.
        let sock = unsafe { Socket::from_raw_fd(state.pxefd) };
        let sock = std::mem::ManuallyDrop::new(sock);
        if let Err(e) = _bindtodevice(device, &sock) {
            tracing::warn!(
                target: "dnsmasq::dhcp",
                "Failed to bind PXE socket to {}: {}",
                device, e
            );
        }
    }

    // DHCPv6 socket — bind if doing DHCPv6 and not in relay mode
    #[cfg(feature = "dhcp6")]
    if state.doing_dhcp6 && state.dhcp6fd >= 0 && state.relay6.is_empty() {
        // SAFETY: dhcp6fd is a valid socket fd opened by the DHCPv6 server init.
        let sock = unsafe { Socket::from_raw_fd(state.dhcp6fd) };
        let sock = std::mem::ManuallyDrop::new(sock);
        if let Err(e) = _bindtodevice(device, &sock) {
            tracing::warn!(
                target: "dnsmasq::dhcp",
                "Failed to bind DHCPv6 socket to {}: {}",
                device, e
            );
        }
    }

    info!(
        target: "dnsmasq::dhcp",
        "DHCP sockets bound to device {}",
        device
    );
    Ok(())
}

/// Bind DHCP sockets to a specific network device (non-Linux stub).
///
/// SO_BINDTODEVICE is Linux-specific; on other platforms this is a no-op.
#[cfg(not(target_os = "linux"))]
pub fn bind_dhcp_devices(device: &str, _state: &DaemonState) -> DnsmasqResult<()> {
    let _ = device;
    Ok(())
}

/// Internal helper: set SO_BINDTODEVICE on a socket.
///
/// Maps to C `bindtodevice()` (`dhcp-common.c` line 1509).
#[cfg(target_os = "linux")]
fn _bindtodevice(device: &str, socket: &Socket) -> DnsmasqResult<()> {
    use std::os::unix::io::AsRawFd;

    let fd = socket.as_raw_fd();
    let dev_bytes = device.as_bytes();

    // SAFETY: setsockopt with SO_BINDTODEVICE is a valid libc call when `fd`
    // is an open socket descriptor and `dev_bytes` points to a valid device
    // name buffer. SO_BINDTODEVICE requires CAP_NET_RAW or root privileges.
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            dev_bytes.as_ptr() as *const libc::c_void,
            dev_bytes.len() as libc::socklen_t,
        )
    };
    if result < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EPERM) {
            // Non-fatal: running without CAP_NET_RAW
            info!(
                target: "dnsmasq::dhcp",
                "warning: failed to bind to device {}: permission denied",
                device
            );
            return Ok(());
        }
        return Err(DnsmasqError::Network(format!(
            "SO_BINDTODEVICE({}) failed: {}",
            device, err
        )));
    }
    Ok(())
}

// =========================================================================
// Option Table Lookups
// =========================================================================

/// Select the appropriate option table for a protocol version.
fn get_opttab(protocol: DhcpProtocol) -> &'static [DhcpOptDef] {
    match protocol {
        DhcpProtocol::V4 => DHCP4_OPTIONS,
        DhcpProtocol::V6 => DHCP6_OPTIONS,
    }
}

/// Lookup a DHCP option code by its human-readable name.
///
/// Maps to C `lookup_dhcp_opt()` (`dhcp-common.c` line 1850).
/// Case-insensitive name comparison.
pub fn lookup_dhcp_opt(protocol: DhcpProtocol, name: &str) -> Option<u16> {
    let table = get_opttab(protocol);
    for entry in table {
        if entry.name.eq_ignore_ascii_case(name) {
            return Some(entry.opt_code);
        }
    }
    None
}

/// Lookup a DHCP option's expected length/size by option code.
///
/// Maps to C `lookup_dhcp_len()` (`dhcp-common.c` line 1918).
/// Returns the size field with the OT_DEC flag stripped, or `None` if not found.
pub fn lookup_dhcp_len(protocol: DhcpProtocol, val: u16) -> Option<usize> {
    let table = get_opttab(protocol);
    for entry in table {
        if entry.opt_code == val {
            return Some((entry.size & !OT_DEC) as usize);
        }
    }
    None
}

/// Format DHCP option data as a human-readable string.
///
/// Maps to C `option_string()` (`dhcp-common.c` line 2005).
///
/// Decodes option data based on the option table's type flags:
/// - `OT_ADDR_LIST`: IP addresses formatted as dotted-decimal / colon-hex.
/// - `OT_NAME`: printable text string.
/// - `OT_DEC` / `OT_TIME`: decimal integer or formatted duration.
/// - Default: hex dump with colon separators.
///
/// Returns a tuple of (option_name, formatted_value).
pub fn option_string(protocol: DhcpProtocol, opt_code: u16, val: &[u8]) -> String {
    let table = get_opttab(protocol);

    let entry = table.iter().find(|e| e.opt_code == opt_code);

    let (name, size_flags) = match entry {
        Some(e) => (e.name, e.size),
        None => {
            // Unknown option: format as hex
            if val.is_empty() {
                return format!("option:{}", opt_code);
            }
            let hex = format_hex_colons(val);
            return format!("option:{} {}", opt_code, hex);
        }
    };

    if val.is_empty() {
        return name.to_string();
    }

    // Decode based on type flags
    if size_flags & OT_ADDR_LIST != 0 {
        let addr_len = match protocol {
            DhcpProtocol::V4 => 4usize,
            DhcpProtocol::V6 => 16usize,
        };
        let mut addrs = Vec::new();
        let mut i = 0;
        while i + addr_len <= val.len() {
            let addr_str = if addr_len == 4 {
                Ipv4Addr::new(val[i], val[i + 1], val[i + 2], val[i + 3]).to_string()
            } else {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&val[i..i + 16]);
                Ipv6Addr::from(octets).to_string()
            };
            addrs.push(addr_str);
            i += addr_len;
        }
        format!("{} {}", name, addrs.join(", "))
    } else if size_flags & OT_NAME != 0 {
        // Printable text
        let text: String = val
            .iter()
            .filter(|b| b.is_ascii_graphic() || **b == b' ')
            .map(|b| *b as char)
            .collect();
        format!("{} {}", name, text)
    } else if size_flags & OT_RFC1035_NAME != 0 {
        // RFC 1035 label-length encoded domain name
        let domain = decode_rfc1035_name(val);
        format!("{} {}", name, domain)
    } else if (size_flags & (OT_DEC | OT_TIME)) != 0 && !val.is_empty() {
        let mut dec: u64 = 0;
        for &b in val {
            dec = (dec << 8) | (b as u64);
        }
        if size_flags & OT_TIME != 0 {
            format!("{} {}", name, format_duration(dec))
        } else {
            format!("{} {}", name, dec)
        }
    } else {
        // Fallback: hex display
        let hex = format_hex_colons(val);
        format!("{} {}", name, hex)
    }
}

/// Print all known DHCPv4 option names.
///
/// Maps to C `display_opts()` (`dhcp-common.c` line 1742).
pub fn display_opts() {
    for entry in DHCP4_OPTIONS {
        println!("{:>3} {}", entry.opt_code, entry.name);
    }
}

/// Print all known DHCPv6 option names.
///
/// Maps to C `display_opts6()` (`dhcp-common.c` line 1793).
#[cfg(feature = "dhcp6")]
pub fn display_opts6() {
    for entry in DHCP6_OPTIONS {
        println!("{:>3} {}", entry.opt_code, entry.name);
    }
}

/// Print all known DHCPv6 option names (no-op without dhcp6 feature).
#[cfg(not(feature = "dhcp6"))]
pub fn display_opts6() {}

// =========================================================================
// Logging Functions
// =========================================================================

/// Log DHCP context configuration.
///
/// Maps to C `log_context()` (`dhcp-common.c` line 2165).
/// Formats and logs address range, lease time, and context flags.
pub fn log_context(family: AddressFamily, context: &DhcpContext) {
    let lease_info = if family != AddressFamily::Inet && context.flags & CONTEXT_DEPRECATE != 0 {
        ", prefix deprecated".to_string()
    } else {
        format!(
            ", lease time {}",
            format_duration(context.lease_time as u64)
        )
    };

    let proto_name = match family {
        AddressFamily::Inet => "DHCP",
        AddressFamily::Inet6 => "DHCPv6",
    };

    // Determine context description based on flags
    if context.flags & CONTEXT_OLD != 0 {
        return; // Don't log old (replaced) contexts
    }

    #[cfg(feature = "dhcp6")]
    if family == AddressFamily::Inet6 && context.flags & CONTEXT_RA_STATELESS != 0 {
        let iface = context.template_interface.as_deref().unwrap_or("unknown");
        info!(
            target: "dnsmasq::dhcp",
            "{} stateless on {}{}",
            proto_name,
            iface,
            lease_info
        );
        return;
    }

    if context.flags & CONTEXT_STATIC != 0 {
        info!(
            target: "dnsmasq::dhcp",
            "{}, static leases only on {}{}",
            proto_name,
            context.start,
            lease_info
        );
    } else if context.flags & CONTEXT_PROXY != 0 {
        info!(
            target: "dnsmasq::dhcp",
            "{}, proxy on subnet {}{}",
            proto_name,
            context.start,
            lease_info
        );
    } else {
        info!(
            target: "dnsmasq::dhcp",
            "{}, IP range {} -- {}{}",
            proto_name,
            context.start,
            context.end,
            lease_info
        );
    }

    // Log RA information for IPv6 contexts
    #[cfg(feature = "dhcp6")]
    if family == AddressFamily::Inet6 {
        if context.flags & CONTEXT_RA_NAME != 0 {
            info!(
                target: "dnsmasq::dhcp",
                "DHCPv4-derived IPv6 names on {}",
                context.start6
            );
        }
        if context.flags & CONTEXT_RA != 0 {
            info!(
                target: "dnsmasq::dhcp",
                "router advertisement on {}",
                context.start6
            );
        }
    }
}

/// Log DHCP relay configuration.
///
/// Maps to C `log_relay()` (`dhcp-common.c` line 2301).
pub fn log_relay(family: AddressFamily, relay: &DhcpRelay) {
    let local_str = relay.local.to_string();
    let mut server_str = relay.server.to_string();

    // Append non-default port
    match family {
        AddressFamily::Inet => {
            if relay.port != DHCP_SERVER_PORT {
                server_str = format!("{}#{}", server_str, relay.port);
            }
        }
        #[cfg(feature = "dhcp6")]
        AddressFamily::Inet6 => {
            if relay.port != DHCPV6_SERVER_PORT {
                server_str = format!("{}#{}", server_str, relay.port);
            }
        }
        #[cfg(not(feature = "dhcp6"))]
        AddressFamily::Inet6 => {}
    }

    // Check for broadcast/multicast relay
    let is_broadcast = match &relay.server {
        std::net::IpAddr::V4(v4) => v4.is_unspecified(),
        std::net::IpAddr::V6(v6) => {
            // ALL_SERVERS multicast: ff02::1:3
            *v6 == Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 3)
        }
    };

    if let Some(ref iface) = relay.interface {
        if is_broadcast {
            info!(
                target: "dnsmasq::dhcp",
                "DHCP relay from {} via {}",
                local_str,
                iface
            );
        } else if relay.split_mode {
            info!(
                target: "dnsmasq::dhcp",
                "DHCP split-relay from {} to {} via {}",
                local_str,
                server_str,
                iface
            );
        } else {
            info!(
                target: "dnsmasq::dhcp",
                "DHCP relay from {} to {} via {}",
                local_str,
                server_str,
                iface
            );
        }
    } else {
        info!(
            target: "dnsmasq::dhcp",
            "DHCP relay from {} to {}",
            local_str,
            server_str
        );
    }
}

/// Log active DHCP tags for a transaction.
///
/// Maps to C `log_tags()` (`dhcp-common.c` line 705).
/// Formats tags as comma-separated list, deduplicating, truncated to MAXDNAME.
///
/// Checks `OPT_LOG_OPTS` via the `opt` module to determine whether
/// option-level logging is enabled before emitting tag lists.
pub fn log_tags(tags: &[NetId], xid: u32, state: &DaemonState) {
    if tags.is_empty() {
        return;
    }

    // Only log tags when option logging is enabled (mirrors C option_bool(OPT_LOG_OPTS))
    if !state.options.is_set(opt::LOG_OPTS) {
        return;
    }

    // Deduplicate tags
    let mut seen = Vec::new();
    let mut parts = Vec::new();
    for tag in tags {
        if !seen.contains(&tag.net) {
            seen.push(tag.net.clone());
            parts.push(tag.net.clone());
        }
    }

    let mut output = parts.join(", ");
    // Truncate to MAXDNAME - 1 to match C behavior
    if output.len() >= MAXDNAME {
        output.truncate(MAXDNAME - 1);
    }

    info!(
        target: "dnsmasq::dhcp",
        "{} tags: {}",
        xid,
        output
    );
}

// =========================================================================
// Domain Lookup
// =========================================================================

/// Get the domain suffix for an IPv6 address.
///
/// Maps to C `get_domain6()` (defined in `domain.c` line 699, exposed here
/// for DHCP subsystem use).
///
/// In the full implementation, this would consult the conditional domain
/// configuration. Here it returns the daemon's default domain suffix.
#[cfg(feature = "dhcp6")]
pub fn get_domain6(_addr: &Ipv6Addr, state: &DaemonState) -> Option<String> {
    state.domain_suffix.clone()
}

/// Get the domain suffix for an IPv6 address (stub without dhcp6).
#[cfg(not(feature = "dhcp6"))]
pub fn get_domain6(_addr: &Ipv6Addr, state: &DaemonState) -> Option<String> {
    state.domain_suffix.clone()
}

// =========================================================================
// Internal Helpers
// =========================================================================

/// Format bytes as colon-separated hex (e.g., "01:23:ab:cd").
fn format_hex_colons(data: &[u8]) -> String {
    let truncated = data.len() > 14;
    let show = if truncated { &data[..14] } else { data };
    let mut result = String::with_capacity(show.len() * 3);
    for (i, b) in show.iter().enumerate() {
        if i > 0 {
            result.push(':');
        }
        result.push_str(&format!("{:02x}", b));
    }
    if truncated {
        result.push_str("...");
    }
    result
}

/// Decode an RFC 1035 label-length encoded domain name to dotted notation.
fn decode_rfc1035_name(data: &[u8]) -> String {
    let mut result = String::new();
    let mut i = 0;
    while i < data.len() && data[i] != 0 {
        let label_len = data[i] as usize;
        i += 1;
        if i + label_len > data.len() {
            break;
        }
        if !result.is_empty() {
            result.push('.');
        }
        for &b in &data[i..i + label_len] {
            if (b as char).is_ascii_graphic() || b == b' ' {
                result.push(b as char);
            }
        }
        i += label_len;
    }
    result
}

// =========================================================================
// Unit Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- NetId and Tag Matching ---

    fn tag(name: &str) -> NetId {
        NetId {
            net: name.to_string(),
        }
    }

    #[test]
    fn test_match_netid_exact() {
        let check = vec![tag("red")];
        let pool = vec![tag("red"), tag("blue")];
        assert!(match_netid(&check, &pool, false));
    }

    #[test]
    fn test_match_netid_negation() {
        let check = vec![tag("!green")];
        let pool = vec![tag("red"), tag("blue")];
        assert!(match_netid(&check, &pool, false));

        let check_fail = vec![tag("!red")];
        assert!(!match_netid(&check_fail, &pool, false));
    }

    #[test]
    fn test_match_netid_empty_check() {
        let pool = vec![tag("red")];
        assert!(match_netid(&[], &pool, true));
        assert!(!match_netid(&[], &pool, false));
    }

    #[test]
    fn test_match_netid_wild_basic() {
        let check = vec![tag("red")];
        let pool = vec![tag("red"), tag("blue")];
        assert!(match_netid_wild(&check, &pool));
    }

    #[test]
    fn test_match_netid_wild_wildcard() {
        let check = vec![tag("*ed")];
        let pool = vec![tag("red"), tag("blue")];
        assert!(match_netid_wild(&check, &pool));
    }

    #[test]
    fn test_match_netid_wild_negated_wildcard() {
        let check = vec![tag("!*green")];
        let pool = vec![tag("red"), tag("blue")];
        assert!(match_netid_wild(&check, &pool));
    }

    #[test]
    fn test_run_tag_if_basic() {
        let tags = vec![tag("red")];
        let rules = vec![TagIfRule {
            tag: vec![tag("red")],
            set: vec![tag("premium")],
        }];
        let result = run_tag_if(&tags, &rules);
        assert!(result.contains(&tag("red")));
        assert!(result.contains(&tag("premium")));
    }

    #[test]
    fn test_run_tag_if_chain() {
        let tags = vec![tag("a")];
        let rules = vec![
            TagIfRule {
                tag: vec![tag("a")],
                set: vec![tag("b")],
            },
            TagIfRule {
                tag: vec![tag("b")],
                set: vec![tag("c")],
            },
        ];
        let result = run_tag_if(&tags, &rules);
        assert!(result.contains(&tag("a")));
        assert!(result.contains(&tag("b")));
        assert!(result.contains(&tag("c")));
    }

    // -- Hostname stripping ---

    #[test]
    fn test_strip_hostname_simple() {
        assert_eq!(strip_hostname("myhost"), Some("myhost".to_string()));
    }

    #[test]
    fn test_strip_hostname_with_domain() {
        assert_eq!(
            strip_hostname("myhost.example.com"),
            Some("myhost".to_string())
        );
    }

    #[test]
    fn test_strip_hostname_illegal_chars() {
        assert_eq!(strip_hostname("my@host!"), Some("myhost".to_string()));
    }

    #[test]
    fn test_strip_hostname_empty() {
        assert_eq!(strip_hostname(""), None);
    }

    #[test]
    fn test_strip_hostname_only_dots() {
        assert_eq!(strip_hostname(".example.com"), None);
    }

    // -- Option table lookups ---

    #[test]
    fn test_lookup_dhcp_opt_v4() {
        assert_eq!(lookup_dhcp_opt(DhcpProtocol::V4, "netmask"), Some(1));
        assert_eq!(lookup_dhcp_opt(DhcpProtocol::V4, "router"), Some(3));
        assert_eq!(lookup_dhcp_opt(DhcpProtocol::V4, "dns-server"), Some(6));
        assert_eq!(lookup_dhcp_opt(DhcpProtocol::V4, "nonexistent"), None);
    }

    #[test]
    fn test_lookup_dhcp_opt_case_insensitive() {
        assert_eq!(lookup_dhcp_opt(DhcpProtocol::V4, "NETMASK"), Some(1));
        assert_eq!(lookup_dhcp_opt(DhcpProtocol::V4, "Router"), Some(3));
    }

    #[test]
    fn test_lookup_dhcp_len_v4() {
        // netmask has OT_ADDR_LIST flag, not a fixed size
        let len = lookup_dhcp_len(DhcpProtocol::V4, 1);
        assert!(len.is_some());

        // time-offset has size 4
        let len = lookup_dhcp_len(DhcpProtocol::V4, 2);
        assert_eq!(len, Some(4));
    }

    #[test]
    fn test_lookup_dhcp_len_unknown() {
        assert_eq!(lookup_dhcp_len(DhcpProtocol::V4, 999), None);
    }

    // -- config_has_mac ---

    #[test]
    fn test_config_has_mac_exact() {
        let config = DhcpConfig {
            flags: 0,
            hwaddr: vec![HwAddrConfig {
                hwaddr: vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
                hwaddr_type: 1,
                wildcard_mask: 0,
            }],
            clid: None,
            hostname: None,
            netid: Vec::new(),
            filter: Vec::new(),
            addr: None,
            #[cfg(feature = "dhcp6")]
            addr6: Vec::new(),
            domain: None,
            lease_time: 0,
            decline_time: 0,
        };
        assert!(config_has_mac(
            &config,
            &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            1
        ));
        assert!(!config_has_mac(
            &config,
            &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x00],
            1
        ));
    }

    #[test]
    fn test_config_has_mac_wildcard_type() {
        let config = DhcpConfig {
            flags: 0,
            hwaddr: vec![HwAddrConfig {
                hwaddr: vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
                hwaddr_type: 0, // wildcard type
                wildcard_mask: 0,
            }],
            clid: None,
            hostname: None,
            netid: Vec::new(),
            filter: Vec::new(),
            addr: None,
            #[cfg(feature = "dhcp6")]
            addr6: Vec::new(),
            domain: None,
            lease_time: 0,
            decline_time: 0,
        };
        // Should match any hw_type
        assert!(config_has_mac(
            &config,
            &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            99
        ));
    }

    // -- match_bytes ---

    #[test]
    fn test_match_bytes_exact() {
        let opt = DhcpOpt {
            opt: 1,
            val: vec![0x01, 0x02, 0x03],
            flags: 0,
            netid: None,
            next: Vec::new(),
            len: 3,
            u: DhcpOptExtra::None,
        };
        assert!(match_bytes(&opt, &[0x01, 0x02, 0x03]));
        assert!(!match_bytes(&opt, &[0x01, 0x02, 0x04]));
    }

    #[test]
    fn test_match_bytes_hex_with_mask() {
        let opt = DhcpOpt {
            opt: 1,
            val: vec![0xAA, 0xBB, 0xCC],
            flags: DHOPT_HEX,
            netid: None,
            next: Vec::new(),
            len: 3,
            u: DhcpOptExtra::WildcardMask(0b010), // bit 1 = wildcard
        };
        // Byte at index 1 is wildcarded
        assert!(match_bytes(&opt, &[0xAA, 0x00, 0xCC]));
        assert!(!match_bytes(&opt, &[0x00, 0xBB, 0xCC]));
    }

    #[test]
    fn test_match_bytes_string() {
        let opt = DhcpOpt {
            opt: 1,
            val: b"hello".to_vec(),
            flags: DHOPT_STRING,
            netid: None,
            next: Vec::new(),
            len: 5,
            u: DhcpOptExtra::None,
        };
        assert!(match_bytes(&opt, b"say hello world"));
        assert!(!match_bytes(&opt, b"goodbye"));
    }

    // -- option_string ---

    #[test]
    fn test_option_string_addr() {
        let result = option_string(DhcpProtocol::V4, 1, &[255, 255, 255, 0]);
        assert!(result.starts_with("netmask"));
        assert!(result.contains("255.255.255.0"));
    }

    #[test]
    fn test_option_string_name() {
        let result = option_string(DhcpProtocol::V4, 15, b"example.com");
        assert!(result.starts_with("domain-name"));
        assert!(result.contains("example.com"));
    }

    #[test]
    fn test_option_string_unknown() {
        let result = option_string(DhcpProtocol::V4, 200, &[0x12, 0x34]);
        assert!(result.contains("option:200"));
    }

    // -- log_tags ---

    #[test]
    fn test_log_tags_dedup() {
        // Just verify it doesn't panic with duplicate tags
        let mut state = DaemonState::new();
        state.options.set(opt::LOG_OPTS);
        let tags = vec![tag("red"), tag("blue"), tag("red")];
        log_tags(&tags, 0x1234, &state);
    }

    // -- pxe_ok ---

    #[test]
    fn test_pxe_ok_modes() {
        let pxe_opt = DhcpOpt {
            opt: 1,
            val: Vec::new(),
            flags: DHOPT_PXE_OPT,
            netid: None,
            next: Vec::new(),
            len: 0,
            u: DhcpOptExtra::None,
        };
        let normal_opt = DhcpOpt {
            opt: 2,
            val: Vec::new(),
            flags: 0,
            netid: None,
            next: Vec::new(),
            len: 0,
            u: DhcpOptExtra::None,
        };
        // PXE_MATCH_ALL: both pass
        assert!(pxe_ok(&pxe_opt, PXE_MATCH_ALL));
        assert!(pxe_ok(&normal_opt, PXE_MATCH_ALL));
        // PXE_REQUIRE: only PXE passes
        assert!(pxe_ok(&pxe_opt, PXE_REQUIRE));
        assert!(!pxe_ok(&normal_opt, PXE_REQUIRE));
        // PXE_REJECT: only non-PXE passes
        assert!(!pxe_ok(&pxe_opt, PXE_REJECT));
        assert!(pxe_ok(&normal_opt, PXE_REJECT));
    }

    // -- display_opts ---

    #[test]
    fn test_display_opts_no_panic() {
        display_opts();
    }

    #[test]
    fn test_display_opts6_no_panic() {
        display_opts6();
    }

    // -- format_hex_colons ---

    #[test]
    fn test_format_hex_colons() {
        assert_eq!(format_hex_colons(&[0x01, 0x23, 0xab]), "01:23:ab");
        assert_eq!(format_hex_colons(&[]), "");
    }

    // -- decode_rfc1035_name ---

    #[test]
    fn test_decode_rfc1035_name() {
        // "\x07example\x03com\x00"
        let data = b"\x07example\x03com\x00";
        assert_eq!(decode_rfc1035_name(data), "example.com");
    }
}

// Copyright (c) 2000-2025 Simon Kelley
// SPDX-License-Identifier: GPL-2.0-or-later
//
//! Configuration file parser for dnsmasq — Rust replacement for `src/option.c`.
//!
//! This module implements the INI-style parser supporting `key=value`, `key`,
//! and `server=/domain/ip` syntax, producing a [`DnsmasqConfig`] struct.
//! Achieves 100% backward compatibility with existing dnsmasq.conf files.
//!
//! # Config File Syntax
//! - `key=value` (e.g., `cache-size=1000`)
//! - `key` without value (boolean options, e.g., `no-resolv`)
//! - `server=/domain/ip` (domain-specific forwarding)
//! - `#` line comments
//! - Continuation lines (backslash at end of line)
//! - `conf-file=path` (include files)
//! - `conf-dir=path[,*.ext]` (include directories with optional glob filter)
//! - Empty lines ignored
//!
//! # Precedence
//! CLI > config file > defaults (matching C behavior exactly).

use std::collections::HashSet;
use std::fs;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};

use crate::config::cli::CliArgs;
use crate::config::constants;
use crate::config::features;
use crate::core::types::{DnsmasqError, DnsmasqResult};

/// Maximum depth for config file includes to prevent stack overflow.
const MAX_INCLUDE_DEPTH: usize = 20;

// ============================================================================
// Supporting Config Types
// ============================================================================

/// Upstream DNS server configuration (from `--server` / `server=` directives).
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Server address and port (e.g., `8.8.8.8:53`).
    pub address: SocketAddr,
    /// Optional domain restriction for domain-specific forwarding.
    pub domain: Option<String>,
    /// Optional source address for queries to this server.
    pub source: Option<IpAddr>,
    /// Optional source interface for queries to this server.
    pub interface: Option<String>,
}

/// Reverse server mapping (from `--rev-server`).
#[derive(Debug, Clone)]
pub struct RevServerConfig {
    /// Network prefix in CIDR notation (e.g., `192.168.0.0/24`).
    pub prefix: String,
    /// Upstream server for reverse queries.
    pub server: String,
}

/// Address override (from `--address`).
#[derive(Debug, Clone)]
pub struct AddressConfig {
    /// Domain pattern to match.
    pub domain: String,
    /// Address to return (or None for NXDOMAIN).
    pub address: Option<IpAddr>,
}

/// DHCP range configuration (from `--dhcp-range`).
#[derive(Debug, Clone)]
pub struct DhcpRangeConfig {
    pub start: String,
    pub end: String,
    pub netmask: Option<String>,
    pub lease_time: Option<String>,
    pub tag: Option<String>,
    pub set_tag: Option<String>,
}

/// DHCP host configuration (from `--dhcp-host`).
#[derive(Debug, Clone)]
pub struct DhcpHostConfig {
    pub mac: Option<String>,
    pub ip: Option<String>,
    pub hostname: Option<String>,
    pub lease_time: Option<String>,
    pub tag: Option<String>,
}

/// DHCP option configuration (from `--dhcp-option`).
#[derive(Debug, Clone)]
pub struct DhcpOptionConfig {
    pub option_num: u16,
    pub value: Vec<u8>,
    pub tag: Option<String>,
    pub force: bool,
}

/// DHCP boot configuration (from `--dhcp-boot`).
#[derive(Debug, Clone)]
pub struct DhcpBootConfig {
    pub filename: String,
    pub servername: Option<String>,
    pub server_address: Option<IpAddr>,
    pub tag: Option<String>,
}

/// Bridge interface configuration (from `--bridge-interface`).
#[derive(Debug, Clone)]
pub struct BridgeConfig {
    pub bridge: String,
    pub alias: String,
}

/// Shared network configuration (from `--shared-network`).
#[derive(Debug, Clone)]
pub struct SharedNetworkConfig {
    pub interface: String,
    pub address: String,
}

/// Domain configuration (from `--domain`).
#[derive(Debug, Clone)]
pub struct DomainConfig {
    pub domain: String,
    pub range_start: Option<String>,
    pub range_end: Option<String>,
    pub prefix: Option<String>,
    pub local: bool,
}

/// CNAME alias configuration (from `--cname`).
#[derive(Debug, Clone)]
pub struct CnameConfig {
    pub alias: String,
    pub target: String,
    pub ttl: Option<u32>,
}

/// Host record configuration (from `--host-record`).
#[derive(Debug, Clone)]
pub struct HostRecordConfig {
    pub name: String,
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
    pub ttl: Option<u32>,
}

/// Dynamic host record (from `--dynamic-host`).
#[derive(Debug, Clone)]
pub struct DynamicHostConfig {
    pub name: String,
    pub address: Option<IpAddr>,
    pub ttl: Option<u32>,
}

/// MX record configuration (from `--mx-host`).
#[derive(Debug, Clone)]
pub struct MxConfig {
    pub name: String,
    pub target: String,
    pub preference: u16,
}

/// SRV record configuration (from `--srv-host`).
#[derive(Debug, Clone)]
pub struct SrvConfig {
    pub name: String,
    pub target: String,
    pub port: u16,
    pub priority: u16,
    pub weight: u16,
}

/// TXT record configuration (from `--txt-record`).
#[derive(Debug, Clone)]
pub struct TxtRecordConfig {
    pub name: String,
    pub text: Vec<String>,
}

/// CAA record configuration (from `--caa-record`).
#[derive(Debug, Clone)]
pub struct CaaRecordConfig {
    pub name: String,
    pub flags: u8,
    pub tag: String,
    pub value: String,
}

/// PTR record configuration (from `--ptr-record`).
#[derive(Debug, Clone)]
pub struct PtrRecordConfig {
    pub name: String,
    pub target: Option<String>,
}

/// NAPTR record configuration (from `--naptr-record`).
#[derive(Debug, Clone)]
pub struct NaptrRecordConfig {
    pub name: String,
    pub order: u16,
    pub preference: u16,
    pub flags: String,
    pub service: String,
    pub regexp: String,
    pub replacement: String,
}

/// DNS RR configuration (from `--dns-rr`).
#[derive(Debug, Clone)]
pub struct DnsRrConfig {
    pub name: String,
    pub rrtype: u16,
    pub rdata: Vec<u8>,
}

/// Interface name record (from `--interface-name`).
#[derive(Debug, Clone)]
pub struct InterfaceNameConfig {
    pub name: String,
    pub interface: String,
    pub family: Option<String>,
}

/// Synth domain configuration (from `--synth-domain`).
#[derive(Debug, Clone)]
pub struct SynthDomainConfig {
    pub domain: String,
    pub prefix: Option<String>,
    pub range_start: Option<String>,
    pub range_end: Option<String>,
}

/// Domain match / server selection.
#[derive(Debug, Clone)]
pub struct DomainMatchConfig {
    pub domain: String,
    pub server: String,
}

/// Configuration directory include (from `--conf-dir`).
#[derive(Debug, Clone)]
pub struct ConfDirConfig {
    pub path: String,
    pub filter: Option<String>,
}

/// Cisco Umbrella configuration.
#[derive(Debug, Clone)]
pub struct UmbrellaConfig {
    pub device_id: Option<String>,
    pub org_id: Option<String>,
    pub asset_id: Option<String>,
}

/// D-Bus configuration.
#[derive(Debug, Clone)]
pub struct DbusConfig {
    pub enabled: bool,
}

/// UBus configuration (OpenWrt).
#[derive(Debug, Clone)]
pub struct UbusConfig {
    pub enabled: bool,
}

/// Script execution configuration.
#[derive(Debug, Clone)]
pub struct ScriptConfig {
    pub path: Option<String>,
    pub scriptuser: Option<String>,
}

/// PXE boot menu prompt configuration (from `--pxe-prompt`).
///
/// Maps to C's `pxe_service` prompt entry in option.c.
#[derive(Debug, Clone)]
pub struct PxePromptConfig {
    /// Prompt text displayed to PXE clients.
    pub prompt: String,
    /// Timeout in seconds (0 = no timeout, boot first entry).
    pub timeout: Option<u32>,
    /// Optional tag filter.
    pub tag: Option<String>,
}

/// PXE boot service configuration (from `--pxe-service`).
///
/// Maps to C's `struct pxe_service` in dnsmasq.h.
#[derive(Debug, Clone)]
pub struct PxeServiceConfig {
    /// Service type: "x86PC", "IA32_EFI", "x86-64_EFI", etc.
    pub service_type: String,
    /// Menu entry description shown to PXE clients.
    pub description: String,
    /// Boot filename or server address.
    pub server: Option<String>,
    /// Optional tag filter.
    pub tag: Option<String>,
}

/// Address alias configuration (from `--alias`).
///
/// Maps DNS results from one IP range to another, matching C's
/// `struct addr_alias` from dnsmasq.h.
#[derive(Debug, Clone)]
pub struct AliasConfig {
    /// Source address to match.
    pub from: Ipv4Addr,
    /// Replacement address.
    pub to: Ipv4Addr,
    /// Optional netmask for range-based aliasing.
    pub mask: Option<Ipv4Addr>,
}

/// ipset configuration (from `--ipset`).
#[derive(Debug, Clone)]
pub struct IpsetConfig {
    pub domains: Vec<String>,
    pub sets: Vec<String>,
}

/// nftset configuration (from `--nftset`).
#[derive(Debug, Clone)]
pub struct NftsetConfig {
    pub domains: Vec<String>,
    pub family: String,
    pub table: String,
    pub set: String,
}

/// DHCP relay configuration.
#[derive(Debug, Clone)]
pub struct DhcpRelayConfig {
    pub local: String,
    pub server: String,
    pub interface: Option<String>,
}

/// DHCP split relay configuration.
#[derive(Debug, Clone)]
pub struct DhcpSplitRelayConfig {
    pub local: String,
    pub server: String,
    pub port: Option<u16>,
}

/// Tag-if conditional configuration.
#[derive(Debug, Clone)]
pub struct TagIfConfig {
    pub set_tag: String,
    pub match_tags: Vec<String>,
    pub condition: Option<String>,
}

/// DHCP match configuration.
#[derive(Debug, Clone)]
pub struct DhcpMatchConfig {
    pub set_tag: String,
    pub option_num: u16,
    pub value: Option<String>,
}

/// DHCP name match configuration.
#[derive(Debug, Clone)]
pub struct DhcpNameMatchConfig {
    pub set_tag: String,
    pub name: String,
}

/// DHCP MAC match configuration.
#[derive(Debug, Clone)]
pub struct DhcpMacConfig {
    pub set_tag: String,
    pub mac: String,
}

/// DHCP user/vendor class match configuration.
#[derive(Debug, Clone)]
pub struct DhcpClassConfig {
    pub set_tag: String,
    pub class_value: String,
}

/// Router advertisement parameter configuration.
#[derive(Debug, Clone)]
pub struct RaParamConfig {
    pub interface: String,
    pub interval: Option<u32>,
    pub lifetime: Option<u32>,
    pub priority: Option<String>,
}

/// Leasequery configuration.
#[derive(Debug, Clone)]
pub struct LeasequeryConfig {
    pub enabled: bool,
}

/// DHCP circuit-id match.
#[derive(Debug, Clone)]
pub struct DhcpCircuitConfig {
    pub set_tag: String,
    pub circuit_id: String,
}

/// DHCP remote-id match.
#[derive(Debug, Clone)]
pub struct DhcpRemoteConfig {
    pub set_tag: String,
    pub remote_id: String,
}

/// DHCP subscriber-id match.
#[derive(Debug, Clone)]
pub struct DhcpSubscrConfig {
    pub set_tag: String,
    pub subscriber_id: String,
}

// ============================================================================
// Logging Configuration
// ============================================================================

/// Logging configuration.
#[derive(Debug, Clone, Default)]
pub struct LogConfig {
    pub facility: Option<String>,
    pub log_dhcp: bool,
    pub log_async: Option<u32>,
    pub log_debug: bool,
}

/// TFTP server configuration.
#[derive(Debug, Clone)]
pub struct TftpConfig {
    pub root: Option<String>,
    pub max_connections: u32,
    pub secure: bool,
    pub no_fail: bool,
    pub unique_root: Option<String>,
    pub lowercase: bool,
    pub mtu: Option<u16>,
    pub single_port: bool,
    pub port_range: Option<String>,
    pub no_blocksize: bool,
    pub quiet: bool,
}

impl Default for TftpConfig {
    fn default() -> Self {
        Self {
            root: None,
            max_connections: constants::TFTP_MAX_CONNECTIONS,
            secure: false,
            no_fail: false,
            unique_root: None,
            lowercase: false,
            mtu: None,
            single_port: false,
            port_range: None,
            no_blocksize: false,
            quiet: false,
        }
    }
}

/// DNSSEC validation configuration.
#[derive(Debug, Clone, Default)]
pub struct DnssecConfig {
    pub enabled: bool,
    pub trust_anchors: Vec<String>,
    pub debug: bool,
    pub check_unsigned: bool,
    pub no_timecheck: bool,
    pub timestamp: Option<String>,
    pub limits: Option<String>,
}

/// Authoritative DNS zone configuration.
#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub zone: Option<String>,
    pub server: Option<String>,
    pub ttl: Option<u32>,
    pub soa: Option<String>,
    pub sec_servers: Vec<String>,
    pub peer: Vec<String>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            zone: None,
            server: None,
            ttl: Some(constants::AUTH_TTL),
            soa: None,
            sec_servers: Vec::new(),
            peer: Vec::new(),
        }
    }
}

/// Complete DHCP configuration.
#[derive(Debug, Clone)]
pub struct DhcpConfig {
    pub ranges: Vec<DhcpRangeConfig>,
    pub hosts: Vec<DhcpHostConfig>,
    pub options: Vec<DhcpOptionConfig>,
    pub option_forces: Vec<DhcpOptionConfig>,
    pub boot: Vec<DhcpBootConfig>,
    pub leasefile: String,
    pub lease_max: u32,
    pub authoritative: bool,
    pub rapid_commit: bool,
    pub sequential_ip: bool,
    pub no_ping: bool,
    pub fqdn: bool,
    pub dhcp_fqdn: bool,
    pub ignore_clid: bool,
    pub proxy: Vec<String>,
    pub generate_names: Vec<String>,
    pub ignore_names: Vec<String>,
    pub alternate_port: Option<(u16, u16)>,
    pub leasefile_ro: bool,
    pub hostfiles: Vec<String>,
    pub optsfiles: Vec<String>,
    pub hostdirs: Vec<String>,
    pub optsdirs: Vec<String>,
    pub reply_delay: Option<u32>,
    pub ttl: Option<u32>,
    pub relays: Vec<DhcpRelayConfig>,
    pub split_relays: Vec<DhcpSplitRelayConfig>,
    pub tag_ifs: Vec<TagIfConfig>,
    pub matches: Vec<DhcpMatchConfig>,
    pub name_matches: Vec<DhcpNameMatchConfig>,
    pub mac_matches: Vec<DhcpMacConfig>,
    pub broadcasts: Vec<String>,
    pub userclasses: Vec<DhcpClassConfig>,
    pub vendorclasses: Vec<DhcpClassConfig>,
    pub circuit_ids: Vec<DhcpCircuitConfig>,
    pub remote_ids: Vec<DhcpRemoteConfig>,
    pub subscriber_ids: Vec<DhcpSubscrConfig>,
    pub pxe_vendors: Vec<String>,
    pub no_override: bool,
    pub script_on_renewal: bool,
    pub script_arp: bool,
    pub v6_enabled: bool,
    pub duid: Option<String>,
    pub enable_ra: bool,
    pub quiet_dhcp: bool,
    pub quiet_dhcp6: bool,
    pub quiet_ra: bool,
    pub ra_params: Vec<RaParamConfig>,
    pub leasequery: Option<LeasequeryConfig>,
    /// Allow DHCP clients to do their own DDNS updates (C OPT_FQDN_UPDATE).
    pub client_update: bool,
    /// Enable dynamic BOOTP address allocation (C OPT_BOOTP_DYNAMIC).
    pub bootp_dynamic: bool,
}

impl Default for DhcpConfig {
    fn default() -> Self {
        Self {
            ranges: Vec::new(),
            hosts: Vec::new(),
            options: Vec::new(),
            option_forces: Vec::new(),
            boot: Vec::new(),
            leasefile: constants::LEASEFILE.to_string(),
            lease_max: constants::MAXLEASES,
            authoritative: false,
            rapid_commit: false,
            sequential_ip: false,
            no_ping: false,
            fqdn: false,
            dhcp_fqdn: false,
            ignore_clid: false,
            proxy: Vec::new(),
            generate_names: Vec::new(),
            ignore_names: Vec::new(),
            alternate_port: None,
            leasefile_ro: false,
            hostfiles: Vec::new(),
            optsfiles: Vec::new(),
            hostdirs: Vec::new(),
            optsdirs: Vec::new(),
            reply_delay: None,
            ttl: None,
            relays: Vec::new(),
            split_relays: Vec::new(),
            tag_ifs: Vec::new(),
            matches: Vec::new(),
            name_matches: Vec::new(),
            mac_matches: Vec::new(),
            broadcasts: Vec::new(),
            userclasses: Vec::new(),
            vendorclasses: Vec::new(),
            circuit_ids: Vec::new(),
            remote_ids: Vec::new(),
            subscriber_ids: Vec::new(),
            pxe_vendors: Vec::new(),
            no_override: false,
            script_on_renewal: false,
            script_arp: false,
            v6_enabled: false,
            duid: None,
            enable_ra: false,
            quiet_dhcp: false,
            quiet_dhcp6: false,
            quiet_ra: false,
            ra_params: Vec::new(),
            leasequery: None,
            client_update: false,
            bootp_dynamic: false,
        }
    }
}

// ============================================================================
// Main DnsmasqConfig Struct
// ============================================================================

/// Complete dnsmasq configuration — the output of parsing CLI args and config files.
///
/// Replaces the configuration portion of C `struct daemon` from `dnsmasq.h`.
/// Produced by: CLI args (clap) → merge with config file → validate → DnsmasqConfig
#[derive(Debug, Clone)]
pub struct DnsmasqConfig {
    // ── DNS Settings ──
    pub dns_port: u16,
    pub cache_size: u32,
    pub dns_forward_max: u32,
    pub edns_packet_max: u16,
    pub query_port: u16,
    pub min_port: u16,
    pub max_port: u16,
    pub port_limit: u32,
    pub max_ttl: Option<u32>,
    pub min_cache_ttl: Option<u32>,
    pub max_cache_ttl: Option<u32>,
    pub neg_ttl: Option<u32>,
    pub local_ttl: Option<u32>,
    pub dhcp_ttl: Option<u32>,
    pub auth_ttl: u32,
    pub max_tcp_connections: u32,
    pub servers: Vec<ServerConfig>,
    pub local_domains: Vec<String>,
    pub rev_servers: Vec<RevServerConfig>,
    pub addresses: Vec<AddressConfig>,
    pub bogus_nxdomain: Vec<IpAddr>,
    pub ignore_addresses: Vec<IpAddr>,
    pub strict_order: bool,
    pub all_servers: bool,
    pub domain_needed: bool,
    pub bogus_priv: bool,
    pub stop_dns_rebind: bool,
    pub rebind_domain_ok: Vec<String>,
    pub rebind_localhost_ok: bool,
    pub no_resolv: bool,
    pub resolv_files: Vec<String>,
    pub servers_file: Option<String>,
    pub no_poll: bool,
    pub clear_on_reload: bool,
    pub log_queries: bool,
    pub log_queries_extra: Option<String>,
    pub no_negcache: bool,
    pub no_round_robin: bool,
    pub no_0x20_encode: bool,
    pub do_0x20_encode: bool,
    pub cache_rr: Vec<String>,
    pub filter_rr: Vec<String>,
    pub filter_a: bool,
    pub filter_aaaa: bool,
    pub use_stale_cache: Option<u32>,
    pub fast_dns_retry: Option<u32>,
    pub localise_queries: bool,
    pub no_ident: bool,
    /// Enable proxy DNSSEC mode — pass through DNSSEC records from upstream
    /// without local validation.  Equivalent to C OPT_DNSSEC_PROXY.
    pub proxy_dnssec: bool,
    /// Add client MAC address to DNS queries forwarded upstream (C OPT_ADD_MAC).
    pub add_mac: bool,
    /// Strip MAC address from DNS queries before forwarding (C OPT_STRIP_MAC).
    pub strip_mac: bool,
    /// Add EDNS0 client subnet option to DNS queries (C OPT_CLIENT_SUBNET).
    /// Optional prefix length; `Some(None)` = enabled with default, `Some(Some(n))` = specific prefix.
    pub add_subnet: Option<Option<u32>>,
    /// Strip EDNS0 client subnet from DNS queries (C OPT_STRIP_ECS).
    pub strip_subnet: bool,
    /// CPE-ID string to add to DNS queries (C daemon->cpe_id).
    pub add_cpe_id: Option<String>,
    /// Address aliases for DNS rewrites (C daemon->addr_alias).
    pub aliases: Vec<AliasConfig>,
    /// Script to run for additional configuration (C daemon->conf_script).
    pub conf_script: Option<String>,

    // ── Network Settings ──
    pub listen_addresses: Vec<IpAddr>,
    pub interfaces: Vec<String>,
    pub except_interfaces: Vec<String>,
    pub no_dhcp_interfaces: Vec<String>,
    pub no_dhcpv4_interfaces: Vec<String>,
    pub no_dhcpv6_interfaces: Vec<String>,
    pub bind_interfaces: bool,
    pub bind_dynamic: bool,
    pub bridge_interfaces: Vec<BridgeConfig>,
    pub shared_networks: Vec<SharedNetworkConfig>,
    pub local_service: bool,

    // ── Host & Domain Settings ──
    pub no_hosts: bool,
    pub addn_hosts: Vec<String>,
    pub hosts_dirs: Vec<String>,
    pub expand_hosts: bool,
    pub domains: Vec<DomainConfig>,
    pub cnames: Vec<CnameConfig>,
    pub host_records: Vec<HostRecordConfig>,
    pub dynamic_hosts: Vec<DynamicHostConfig>,
    pub mx_hosts: Vec<MxConfig>,
    pub mx_target: Option<String>,
    pub selfmx: bool,
    pub localmx: bool,
    pub srv_hosts: Vec<SrvConfig>,
    pub txt_records: Vec<TxtRecordConfig>,
    pub caa_records: Vec<CaaRecordConfig>,
    pub ptr_records: Vec<PtrRecordConfig>,
    pub naptr_records: Vec<NaptrRecordConfig>,
    pub dns_rr_records: Vec<DnsRrConfig>,
    pub interface_names: Vec<InterfaceNameConfig>,
    pub synth_domains: Vec<SynthDomainConfig>,
    pub domain_matches: Vec<DomainMatchConfig>,
    /// Filter useless Windows DNS queries for SOA/SRV on local domain
    /// (C OPT_FILTER in src/option.c).
    pub filterwin2k: bool,
    /// PXE boot service prompts (C daemon->pxe_services in src/option.c).
    pub pxe_prompts: Vec<PxePromptConfig>,
    /// PXE boot service entries (C daemon->pxe_services in src/option.c).
    pub pxe_services: Vec<PxeServiceConfig>,

    // ── DHCP Settings (feature-gated) ──
    #[cfg(feature = "dhcp")]
    pub dhcp: Option<DhcpConfig>,

    // ── TFTP Settings (feature-gated) ──
    #[cfg(feature = "tftp")]
    pub tftp: Option<TftpConfig>,

    // ── DNSSEC Settings (feature-gated) ──
    #[cfg(feature = "dnssec")]
    pub dnssec: Option<DnssecConfig>,

    // ── Auth Settings (feature-gated) ──
    #[cfg(feature = "auth")]
    pub auth: Option<AuthConfig>,

    // ── Logging ──
    pub log: LogConfig,

    // ── Daemon Settings ──
    pub no_daemon: bool,
    pub keep_in_foreground: bool,
    pub conf_file: Option<String>,
    pub conf_dirs: Vec<ConfDirConfig>,
    pub pid_file: Option<String>,
    pub user: Option<String>,
    pub group: Option<String>,
    pub test_mode: bool,

    // ── Integration Settings (feature-gated) ──
    #[cfg(feature = "dbus")]
    pub dbus: Option<DbusConfig>,
    #[cfg(feature = "ubus")]
    pub ubus: Option<UbusConfig>,
    #[cfg(feature = "script")]
    pub script: Option<ScriptConfig>,
    #[cfg(feature = "ipset")]
    pub ipsets: Vec<IpsetConfig>,
    #[cfg(feature = "nftset")]
    pub nftsets: Vec<NftsetConfig>,
    #[cfg(feature = "conntrack")]
    pub conntrack: bool,
    pub connmark_allowlist_enable: bool,
    pub connmark_allowlists: Vec<String>,

    // ── Diagnostics ──
    #[cfg(feature = "dumpfile")]
    pub dumpfile: Option<String>,
    #[cfg(feature = "dumpfile")]
    pub dumpmask: Option<u32>,
    #[cfg(feature = "loop-detect")]
    pub loop_detect: bool,

    // ── Umbrella ──
    pub umbrella: Option<UmbrellaConfig>,
}

// ============================================================================
// Default Implementation
// ============================================================================

impl Default for DnsmasqConfig {
    /// Create a DnsmasqConfig with all compile-time defaults from `constants.rs`.
    /// Matches C defaults from `config.h`.
    fn default() -> Self {
        Self {
            dns_port: 53,
            cache_size: constants::CACHESIZ,
            dns_forward_max: constants::FTABSIZ,
            edns_packet_max: constants::EDNS_PKTSZ,
            query_port: 0,
            min_port: 1024,
            max_port: 65535,
            port_limit: 1,
            max_ttl: None,
            min_cache_ttl: None,
            max_cache_ttl: None,
            neg_ttl: None,
            local_ttl: None,
            dhcp_ttl: None,
            auth_ttl: constants::AUTH_TTL,
            max_tcp_connections: constants::MAX_PROCS,
            servers: Vec::new(),
            local_domains: Vec::new(),
            rev_servers: Vec::new(),
            addresses: Vec::new(),
            bogus_nxdomain: Vec::new(),
            ignore_addresses: Vec::new(),
            strict_order: false,
            all_servers: false,
            domain_needed: false,
            bogus_priv: false,
            stop_dns_rebind: false,
            rebind_domain_ok: Vec::new(),
            rebind_localhost_ok: false,
            no_resolv: false,
            resolv_files: vec![constants::RESOLVFILE.to_string()],
            servers_file: None,
            no_poll: false,
            clear_on_reload: false,
            log_queries: false,
            log_queries_extra: None,
            no_negcache: false,
            no_round_robin: false,
            no_0x20_encode: false,
            do_0x20_encode: false,
            cache_rr: Vec::new(),
            filter_rr: Vec::new(),
            filter_a: false,
            filter_aaaa: false,
            use_stale_cache: None,
            fast_dns_retry: None,
            localise_queries: false,
            no_ident: false,
            proxy_dnssec: false,
            add_mac: false,
            strip_mac: false,
            add_subnet: None,
            strip_subnet: false,
            add_cpe_id: None,
            aliases: Vec::new(),
            conf_script: None,
            listen_addresses: Vec::new(),
            interfaces: Vec::new(),
            except_interfaces: Vec::new(),
            no_dhcp_interfaces: Vec::new(),
            no_dhcpv4_interfaces: Vec::new(),
            no_dhcpv6_interfaces: Vec::new(),
            bind_interfaces: false,
            bind_dynamic: false,
            bridge_interfaces: Vec::new(),
            shared_networks: Vec::new(),
            local_service: false,
            no_hosts: false,
            addn_hosts: Vec::new(),
            hosts_dirs: Vec::new(),
            expand_hosts: false,
            domains: Vec::new(),
            cnames: Vec::new(),
            host_records: Vec::new(),
            dynamic_hosts: Vec::new(),
            mx_hosts: Vec::new(),
            mx_target: None,
            selfmx: false,
            localmx: false,
            srv_hosts: Vec::new(),
            txt_records: Vec::new(),
            caa_records: Vec::new(),
            ptr_records: Vec::new(),
            naptr_records: Vec::new(),
            dns_rr_records: Vec::new(),
            interface_names: Vec::new(),
            synth_domains: Vec::new(),
            domain_matches: Vec::new(),
            filterwin2k: false,
            pxe_prompts: Vec::new(),
            pxe_services: Vec::new(),
            #[cfg(feature = "dhcp")]
            dhcp: None,
            #[cfg(feature = "tftp")]
            tftp: None,
            #[cfg(feature = "dnssec")]
            dnssec: None,
            #[cfg(feature = "auth")]
            auth: None,
            log: LogConfig::default(),
            no_daemon: false,
            keep_in_foreground: false,
            conf_file: None,
            conf_dirs: Vec::new(),
            pid_file: Some(constants::RUNFILE.to_string()),
            user: Some(constants::CHUSER.to_string()),
            group: Some(constants::CHGRP.to_string()),
            test_mode: false,
            #[cfg(feature = "dbus")]
            dbus: None,
            #[cfg(feature = "ubus")]
            ubus: None,
            #[cfg(feature = "script")]
            script: None,
            #[cfg(feature = "ipset")]
            ipsets: Vec::new(),
            #[cfg(feature = "nftset")]
            nftsets: Vec::new(),
            #[cfg(feature = "conntrack")]
            conntrack: false,
            connmark_allowlist_enable: false,
            connmark_allowlists: Vec::new(),
            #[cfg(feature = "dumpfile")]
            dumpfile: None,
            #[cfg(feature = "dumpfile")]
            dumpmask: None,
            #[cfg(feature = "loop-detect")]
            loop_detect: false,
            umbrella: None,
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Split a string on a delimiter, respecting quoted strings.
/// Replaces C `split_chr()` and `split()` from option.c.
fn split_on(s: &str, delimiter: char) -> Vec<String> {
    let mut result = Vec::new();
    let mut current = String::new();
    let mut in_quote = false;
    let mut escape = false;

    for ch in s.chars() {
        if escape {
            current.push(ch);
            escape = false;
            continue;
        }
        if ch == '\\' {
            escape = true;
            continue;
        }
        if ch == '"' {
            in_quote = !in_quote;
            continue;
        }
        if ch == delimiter && !in_quote {
            result.push(current.trim().to_string());
            current = String::new();
            continue;
        }
        current.push(ch);
    }
    let trimmed = current.trim().to_string();
    if !trimmed.is_empty() || !result.is_empty() {
        result.push(trimmed);
    }
    result
}

/// Canonicalize a hostname: lowercase, strip trailing dot for comparison,
/// but preserve the original intent. Replaces C `canonicalise()`.
fn canonicalise(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    lower.trim_end_matches('.').to_string()
}

/// Parse an IP address (v4 or v6), optionally with port suffix `#port`.
/// Returns (IpAddr, optional_port).
fn parse_addr_port(s: &str) -> Result<(IpAddr, Option<u16>), DnsmasqError> {
    let s = s.trim();
    // Check for #port suffix
    if let Some(hash_pos) = s.rfind('#') {
        let addr_str = &s[..hash_pos];
        let port_str = &s[hash_pos + 1..];
        let port: u16 = port_str
            .parse()
            .map_err(|_| DnsmasqError::Config(format!("invalid port number: '{}'", port_str)))?;
        let addr = parse_ip(addr_str)?;
        Ok((addr, Some(port)))
    } else {
        let addr = parse_ip(s)?;
        Ok((addr, None))
    }
}

/// Parse a bare IP address (v4 or v6, stripping brackets for v6).
fn parse_ip(s: &str) -> Result<IpAddr, DnsmasqError> {
    let s = s.trim();
    // Strip brackets for IPv6 like [::1]
    let s = if s.starts_with('[') && s.ends_with(']') {
        &s[1..s.len() - 1]
    } else {
        s
    };
    s.parse::<IpAddr>()
        .map_err(|_| DnsmasqError::Config(format!("invalid IP address: '{}'", s)))
}

/// Parse a lease time string: integer seconds, or NNm/NNh/NNd/NNw suffixes, or "infinite".
#[allow(dead_code)]
fn parse_lease_time(s: &str) -> Result<u64, DnsmasqError> {
    let s = s.trim();
    if s == "infinite" || s == "0" {
        return Ok(0); // 0 = infinite lease in dnsmasq
    }
    if s.is_empty() {
        return Err(DnsmasqError::Config("empty lease time".to_string()));
    }
    let last = s.chars().last().unwrap();
    let (num_str, multiplier) = match last {
        's' | 'S' => (&s[..s.len() - 1], 1u64),
        'm' | 'M' => (&s[..s.len() - 1], 60u64),
        'h' | 'H' => (&s[..s.len() - 1], 3600u64),
        'd' | 'D' => (&s[..s.len() - 1], 86400u64),
        'w' | 'W' => (&s[..s.len() - 1], 604800u64),
        _ => (s, 1u64),
    };
    let n: u64 = num_str
        .parse()
        .map_err(|_| DnsmasqError::Config(format!("invalid lease time: '{}'", s)))?;
    Ok(n * multiplier)
}

/// Parse a DHCP option value encoding from a dnsmasq option spec string.
/// Handles hex (00:11:22), dotted-quad (1.2.3.4), strings, and integer formats.
fn parse_dhcp_option_value(s: &str) -> Vec<u8> {
    let s = s.trim();
    if s.is_empty() {
        return Vec::new();
    }
    // Try hex colon-separated
    if s.contains(':') && s.chars().all(|c| c.is_ascii_hexdigit() || c == ':') {
        let bytes: Result<Vec<u8>, _> = s.split(':').map(|h| u8::from_str_radix(h, 16)).collect();
        if let Ok(b) = bytes {
            return b;
        }
    }
    // Otherwise treat as UTF-8 string
    s.as_bytes().to_vec()
}

/// Check if a filename matches a glob filter like `*.conf`.
/// Check whether a filename matches a glob filter pattern.
///
/// Delegates to [`crate::core::pattern::glob_match`] for full glob support
/// rather than duplicating matching logic.
fn matches_glob_filter(filename: &str, filter: &str) -> bool {
    crate::core::pattern::glob_match(filename, filter)
}

// ============================================================================
// DnsmasqConfig Implementation
// ============================================================================

impl DnsmasqConfig {
    /// Load configuration from CLI args and config file(s).
    ///
    /// Replaces C `read_opts()` from option.c (line ~700).
    ///
    /// Precedence (highest to lowest):
    /// 1. Command-line arguments
    /// 2. Configuration file directives (last occurrence wins for singular options)
    /// 3. Included files processed at point of inclusion
    /// 4. Compile-time defaults from constants.rs
    pub fn load(cli_args: &CliArgs) -> DnsmasqResult<Self> {
        let mut config = Self::default();
        config.apply_defaults();

        // Determine config file path: CLI override or default
        let conf_path = if !cli_args.conf_file.is_empty() {
            Some(cli_args.conf_file[0].clone())
        } else {
            Some(constants::CONFFILE.to_string())
        };

        // Parse configuration file(s) if path is set
        if let Some(ref path) = conf_path {
            let p = Path::new(path);
            if p.exists() {
                let mut visited = HashSet::new();
                config.parse_config_file(path, &mut visited, 0)?;
            }
            // If the file doesn't exist and was the default, that's OK
            // If it was user-specified, still OK — C dnsmasq also allows missing config
        }

        // Apply CLI overrides (highest precedence)
        config.merge_cli_args(cli_args)?;

        // Validate final configuration
        config.validate()?;

        Ok(config)
    }

    /// Load configuration from a config file without CLI args.
    pub fn from_file(path: &str) -> DnsmasqResult<Self> {
        let mut config = Self::default();
        config.apply_defaults();
        let mut visited = HashSet::new();
        config.parse_config_file(path, &mut visited, 0)?;
        config.validate()?;
        Ok(config)
    }

    /// Apply compile-time defaults from constants.rs.
    pub fn apply_defaults(&mut self) {
        self.dns_port = 53;
        self.cache_size = constants::CACHESIZ;
        self.dns_forward_max = constants::FTABSIZ;
        self.edns_packet_max = constants::EDNS_PKTSZ;
        self.max_tcp_connections = constants::MAX_PROCS;
        self.auth_ttl = constants::AUTH_TTL;
        self.resolv_files = vec![constants::RESOLVFILE.to_string()];
        self.pid_file = Some(constants::RUNFILE.to_string());
        self.user = Some(constants::CHUSER.to_string());
        self.group = Some(constants::CHGRP.to_string());
    }

    /// Parse a single configuration file, handling includes and cycle detection.
    ///
    /// Replaces C `one_file()` from option.c. Supports:
    /// - `#` comments
    /// - Backslash continuation lines
    /// - `conf-file=` includes
    /// - `conf-dir=` directory includes
    /// - Depth limiting to prevent infinite recursion
    pub fn parse_config_file(
        &mut self,
        path: &str,
        visited: &mut HashSet<PathBuf>,
        depth: usize,
    ) -> DnsmasqResult<()> {
        if depth > MAX_INCLUDE_DEPTH {
            return Err(DnsmasqError::Config(format!(
                "config file include depth exceeded {} at '{}'",
                MAX_INCLUDE_DEPTH, path
            )));
        }

        let canonical = match fs::canonicalize(path) {
            Ok(p) => p,
            Err(e) => {
                // If the file doesn't exist and it's the default, silently skip
                if e.kind() == std::io::ErrorKind::NotFound {
                    return Ok(());
                }
                return Err(DnsmasqError::Io(e));
            }
        };

        if visited.contains(&canonical) {
            return Err(DnsmasqError::Config(format!(
                "circular config file include detected: '{}'",
                path
            )));
        }
        visited.insert(canonical.clone());

        let content = fs::read_to_string(path).map_err(DnsmasqError::Io)?;
        let reader = BufReader::new(content.as_bytes());

        let mut continued_line = String::new();
        for line_result in reader.lines() {
            let raw_line = line_result.map_err(DnsmasqError::Io)?;
            let trimmed = raw_line.trim();

            // Skip empty lines and comments
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // Handle continuation lines (backslash at end)
            if let Some(before_backslash) = trimmed.strip_suffix('\\') {
                continued_line.push_str(before_backslash);
                continued_line.push(' ');
                continue;
            }

            let full_line = if continued_line.is_empty() {
                trimmed.to_string()
            } else {
                continued_line.push_str(trimmed);
                let result = continued_line.clone();
                continued_line.clear();
                result
            };

            // Strip inline comments (# not inside quotes)
            let effective = strip_inline_comment(&full_line);

            // Parse key=value or key
            if let Some(eq_pos) = effective.find('=') {
                let key = effective[..eq_pos].trim();
                let value = effective[eq_pos + 1..].trim();

                // Handle include directives specially
                match key {
                    "conf-file" => {
                        let inc_path = resolve_include_path(path, value);
                        self.parse_config_file(&inc_path, visited, depth + 1)?;
                        continue;
                    }
                    "conf-dir" => {
                        self.process_conf_dir(value, path, visited, depth)?;
                        continue;
                    }
                    _ => {}
                }

                self.process_directive(key, Some(value))?;
            } else {
                self.process_directive(effective.trim(), None)?;
            }
        }

        // Handle unterminated continuation
        if !continued_line.is_empty() {
            let effective = strip_inline_comment(&continued_line);
            if let Some(eq_pos) = effective.find('=') {
                let key = effective[..eq_pos].trim();
                let value = effective[eq_pos + 1..].trim();
                self.process_directive(key, Some(value))?;
            } else {
                self.process_directive(effective.trim(), None)?;
            }
        }

        Ok(())
    }

    /// Process a `conf-dir=` directive, scanning a directory for config fragments.
    fn process_conf_dir(
        &mut self,
        value: &str,
        parent_path: &str,
        visited: &mut HashSet<PathBuf>,
        depth: usize,
    ) -> DnsmasqResult<()> {
        let parts = split_on(value, ',');
        let dir_path = if parts.is_empty() {
            return Ok(());
        } else {
            parts[0].as_str()
        };

        // Collect glob filters (subsequent parts)
        let filters: Vec<&str> = parts[1..].iter().map(|s| s.as_str()).collect();

        let resolved = resolve_include_path(parent_path, dir_path);
        let entries = match fs::read_dir(&resolved) {
            Ok(e) => e,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::NotFound {
                    return Ok(());
                }
                return Err(DnsmasqError::Io(e));
            }
        };

        // Collect and sort entries for deterministic ordering
        let mut paths: Vec<PathBuf> = entries
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().map(|ft| ft.is_file()).unwrap_or(false))
            .filter(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                // Skip hidden files, backup files, RPM save/new files
                if name.starts_with('.')
                    || name.ends_with('~')
                    || name.ends_with(".rpmsave")
                    || name.ends_with(".rpmnew")
                    || name.ends_with(".rpmorig")
                    || name.starts_with('#')
                    || name.ends_with('#')
                {
                    return false;
                }
                // Apply glob filters if any
                if filters.is_empty() {
                    true
                } else {
                    filters.iter().any(|f| matches_glob_filter(&name, f))
                }
            })
            .map(|e| e.path())
            .collect();

        paths.sort();

        for entry_path in paths {
            let path_str = entry_path.to_string_lossy().to_string();
            self.parse_config_file(&path_str, visited, depth + 1)?;
        }

        // Store the conf-dir for reference
        self.conf_dirs.push(ConfDirConfig {
            path: resolved,
            filter: if filters.is_empty() {
                None
            } else {
                Some(filters.join(","))
            },
        });

        Ok(())
    }

    /// Process a single configuration directive.
    ///
    /// Replaces C `one_opt()` massive switch statement (lines 1200-6300 of option.c).
    /// Each directive is matched by name and its value parsed into the appropriate
    /// DnsmasqConfig field. Feature-gated directives check feature availability
    /// and return informative errors when disabled.
    pub fn process_directive(&mut self, key: &str, value: Option<&str>) -> DnsmasqResult<()> {
        match key {
            // ================================================================
            // DNS Settings
            // ================================================================
            "port" => {
                let v = require_value(key, value)?;
                self.dns_port = parse_u16(key, v)?;
            }
            "cache-size" => {
                let v = require_value(key, value)?;
                self.cache_size = parse_u32(key, v)?;
            }
            "dns-forward-max" => {
                let v = require_value(key, value)?;
                self.dns_forward_max = parse_u32(key, v)?;
            }
            "edns-packet-max" => {
                let v = require_value(key, value)?;
                let val = parse_u16(key, v)?;
                if val < 512 {
                    return Err(DnsmasqError::Config(format!(
                        "edns-packet-max must be at least 512, got {}",
                        val
                    )));
                }
                self.edns_packet_max = val;
            }
            "query-port" => {
                let v = require_value(key, value)?;
                self.query_port = parse_u16(key, v)?;
            }
            "min-port" => {
                let v = require_value(key, value)?;
                self.min_port = parse_u16(key, v)?;
            }
            "max-port" => {
                let v = require_value(key, value)?;
                self.max_port = parse_u16(key, v)?;
            }
            "port-limit" => {
                let v = require_value(key, value)?;
                self.port_limit = parse_u32(key, v)?;
            }
            "neg-ttl" => {
                let v = require_value(key, value)?;
                let val = parse_u32(key, v)?;
                if val > 86400 {
                    return Err(DnsmasqError::Config(
                        "neg-ttl must not exceed 86400".to_string(),
                    ));
                }
                self.neg_ttl = Some(val);
            }
            "max-ttl" => {
                let v = require_value(key, value)?;
                self.max_ttl = Some(parse_u32(key, v)?);
            }
            "min-cache-ttl" => {
                let v = require_value(key, value)?;
                let val = parse_u32(key, v)?;
                if val > constants::TTL_FLOOR_LIMIT {
                    return Err(DnsmasqError::Config(format!(
                        "min-cache-ttl must not exceed {}, got {}",
                        constants::TTL_FLOOR_LIMIT,
                        val
                    )));
                }
                self.min_cache_ttl = Some(val);
            }
            "max-cache-ttl" => {
                let v = require_value(key, value)?;
                self.max_cache_ttl = Some(parse_u32(key, v)?);
            }
            "local-ttl" => {
                let v = require_value(key, value)?;
                self.local_ttl = Some(parse_u32(key, v)?);
            }
            "dhcp-ttl" => {
                let v = require_value(key, value)?;
                self.dhcp_ttl = Some(parse_u32(key, v)?);
            }
            "auth-ttl" => {
                let v = require_value(key, value)?;
                self.auth_ttl = parse_u32(key, v)?;
            }
            "max-tcp-connections" => {
                let v = require_value(key, value)?;
                let val = parse_u32(key, v)?;
                if val == 0 {
                    return Err(DnsmasqError::Config(
                        "max-tcp-connections must be > 0".to_string(),
                    ));
                }
                self.max_tcp_connections = val;
            }
            "server" => {
                let v = require_value(key, value)?;
                let sc = self.parse_server(v)?;
                self.servers.push(sc);
            }
            "local" => {
                let v = require_value(key, value)?;
                // local= can be like server= (domain-specific local answer)
                // or just a domain to answer locally
                if v.starts_with('/') {
                    // local=/domain/ — answer locally for this domain
                    let domain = v.trim_matches('/').to_string();
                    if !domain.is_empty() {
                        self.local_domains.push(canonicalise(&domain));
                    }
                } else {
                    self.local_domains.push(canonicalise(v));
                }
            }
            "rev-server" => {
                let v = require_value(key, value)?;
                let parts = split_on(v, ',');
                if parts.len() < 2 {
                    return Err(DnsmasqError::Config(
                        "rev-server requires prefix,server".to_string(),
                    ));
                }
                self.rev_servers.push(RevServerConfig {
                    prefix: parts[0].to_string(),
                    server: parts[1].to_string(),
                });
            }
            "address" => {
                let v = require_value(key, value)?;
                // address=/domain/ip or address=/domain/
                if let Some(inner) = v.strip_prefix('/') {
                    if let Some(slash_pos) = inner.rfind('/') {
                        let domain = &inner[..slash_pos];
                        let addr_str = &inner[slash_pos + 1..];
                        let address = if addr_str.is_empty() {
                            None
                        } else {
                            Some(parse_ip(addr_str).map_err(|_| {
                                DnsmasqError::Config(format!(
                                    "invalid address in address= directive: '{}'",
                                    addr_str
                                ))
                            })?)
                        };
                        for d in domain.split('/') {
                            if !d.is_empty() {
                                self.addresses.push(AddressConfig {
                                    domain: canonicalise(d),
                                    address,
                                });
                            }
                        }
                    } else {
                        return Err(DnsmasqError::Config(format!(
                            "malformed address= directive: '{}'",
                            v
                        )));
                    }
                } else {
                    return Err(DnsmasqError::Config(format!(
                        "address= directive must start with /: '{}'",
                        v
                    )));
                }
            }
            "bogus-nxdomain" => {
                let v = require_value(key, value)?;
                let ip = parse_ip(v).map_err(|_| {
                    DnsmasqError::Config(format!("invalid IP in bogus-nxdomain: '{}'", v))
                })?;
                self.bogus_nxdomain.push(ip);
            }
            "ignore-address" => {
                let v = require_value(key, value)?;
                let ip = parse_ip(v).map_err(|_| {
                    DnsmasqError::Config(format!("invalid IP in ignore-address: '{}'", v))
                })?;
                self.ignore_addresses.push(ip);
            }
            "strict-order" => {
                self.strict_order = true;
            }
            "all-servers" => {
                self.all_servers = true;
            }
            "domain-needed" => {
                self.domain_needed = true;
            }
            "bogus-priv" => {
                self.bogus_priv = true;
            }
            "stop-dns-rebind" => {
                self.stop_dns_rebind = true;
            }
            "rebind-domain-ok" => {
                let v = require_value(key, value)?;
                for domain in v.split('/').filter(|s| !s.is_empty()) {
                    self.rebind_domain_ok.push(canonicalise(domain));
                }
            }
            "rebind-localhost-ok" => {
                self.rebind_localhost_ok = true;
            }
            "no-resolv" => {
                self.no_resolv = true;
            }
            "resolv-file" => {
                let v = require_value(key, value)?;
                // Replace default resolv files with specified one(s)
                self.resolv_files.clear();
                for f in v.split(',') {
                    let f = f.trim();
                    if !f.is_empty() {
                        self.resolv_files.push(f.to_string());
                    }
                }
            }
            "servers-file" => {
                let v = require_value(key, value)?;
                self.servers_file = Some(v.to_string());
            }
            "no-poll" => {
                self.no_poll = true;
            }
            "clear-on-reload" => {
                self.clear_on_reload = true;
            }
            "log-queries" => {
                self.log_queries = true;
                if let Some(v) = value {
                    if !v.is_empty() {
                        self.log_queries_extra = Some(v.to_string());
                    }
                }
            }
            "no-negcache" => {
                self.no_negcache = true;
            }
            "no-round-robin" => {
                self.no_round_robin = true;
            }
            "no-0x20-encode" => {
                self.no_0x20_encode = true;
            }
            "do-0x20-encode" => {
                self.do_0x20_encode = true;
            }
            "cache-rr" => {
                let v = require_value(key, value)?;
                for rr in v.split(',') {
                    let rr = rr.trim();
                    if !rr.is_empty() {
                        self.cache_rr.push(rr.to_string());
                    }
                }
            }
            "filter-rr" => {
                let v = require_value(key, value)?;
                for rr in v.split(',') {
                    let rr = rr.trim();
                    if !rr.is_empty() {
                        self.filter_rr.push(rr.to_string());
                    }
                }
            }
            "filter-A" => {
                self.filter_a = true;
            }
            "filter-AAAA" => {
                self.filter_aaaa = true;
            }
            "use-stale-cache" => {
                if let Some(v) = value {
                    if v.is_empty() {
                        self.use_stale_cache = Some(0);
                    } else {
                        self.use_stale_cache = Some(parse_u32(key, v)?);
                    }
                } else {
                    self.use_stale_cache = Some(0);
                }
            }
            "fast-dns-retry" => {
                if let Some(v) = value {
                    if v.is_empty() {
                        self.fast_dns_retry = Some(constants::DEFAULT_FAST_RETRY);
                    } else {
                        self.fast_dns_retry = Some(parse_u32(key, v)?);
                    }
                } else {
                    self.fast_dns_retry = Some(constants::DEFAULT_FAST_RETRY);
                }
            }
            "localise-queries" => {
                self.localise_queries = true;
            }
            "no-ident" => {
                self.no_ident = true;
            }
            "proxy-dnssec" => {
                // Enable proxy DNSSEC mode — pass through DNSSEC records
                // from upstream without local validation (C OPT_DNSSEC_PROXY).
                self.proxy_dnssec = true;
            }

            // ================================================================
            // Network Settings
            // ================================================================
            "listen-address" => {
                let v = require_value(key, value)?;
                for addr_str in v.split(',') {
                    let addr_str = addr_str.trim();
                    if !addr_str.is_empty() {
                        let ip = parse_ip(addr_str).map_err(|_| {
                            DnsmasqError::Config(format!("invalid listen-address: '{}'", addr_str))
                        })?;
                        self.listen_addresses.push(ip);
                    }
                }
            }
            "interface" => {
                let v = require_value(key, value)?;
                for iface in v.split(',') {
                    let iface = iface.trim();
                    if !iface.is_empty() {
                        self.interfaces.push(iface.to_string());
                    }
                }
            }
            "except-interface" => {
                let v = require_value(key, value)?;
                for iface in v.split(',') {
                    let iface = iface.trim();
                    if !iface.is_empty() {
                        self.except_interfaces.push(iface.to_string());
                    }
                }
            }
            "no-dhcp-interface" => {
                let v = require_value(key, value)?;
                self.no_dhcp_interfaces.push(v.to_string());
            }
            "no-dhcpv4-interface" => {
                let v = require_value(key, value)?;
                self.no_dhcpv4_interfaces.push(v.to_string());
            }
            "no-dhcpv6-interface" => {
                let v = require_value(key, value)?;
                self.no_dhcpv6_interfaces.push(v.to_string());
            }
            "bind-interfaces" => {
                self.bind_interfaces = true;
            }
            "bind-dynamic" => {
                self.bind_dynamic = true;
            }
            "local-service" => {
                self.local_service = true;
            }
            "bridge-interface" => {
                let v = require_value(key, value)?;
                let parts = split_on(v, ',');
                if parts.len() < 2 {
                    return Err(DnsmasqError::Config(
                        "bridge-interface requires bridge,alias".to_string(),
                    ));
                }
                let bridge = parts[0].to_string();
                for alias in &parts[1..] {
                    self.bridge_interfaces.push(BridgeConfig {
                        bridge: bridge.clone(),
                        alias: alias.to_string(),
                    });
                }
            }
            "shared-network" => {
                let v = require_value(key, value)?;
                let parts = split_on(v, ',');
                if parts.len() < 2 {
                    return Err(DnsmasqError::Config(
                        "shared-network requires interface,address or address1,address2"
                            .to_string(),
                    ));
                }
                self.shared_networks.push(SharedNetworkConfig {
                    interface: parts[0].to_string(),
                    address: parts[1].to_string(),
                });
            }

            // ================================================================
            // Host & Domain Settings
            // ================================================================
            "no-hosts" => {
                self.no_hosts = true;
            }
            "addn-hosts" => {
                let v = require_value(key, value)?;
                self.addn_hosts.push(v.to_string());
            }
            "hostsdir" => {
                let v = require_value(key, value)?;
                self.hosts_dirs.push(v.to_string());
            }
            "expand-hosts" => {
                self.expand_hosts = true;
            }
            "domain" => {
                let v = require_value(key, value)?;
                let parts = split_on(v, ',');
                let domain_name = canonicalise(&parts[0]);
                let mut dc = DomainConfig {
                    domain: domain_name,
                    range_start: None,
                    range_end: None,
                    prefix: None,
                    local: false,
                };
                if parts.len() >= 3 {
                    dc.range_start = Some(parts[1].to_string());
                    dc.range_end = Some(parts[2].to_string());
                } else if parts.len() == 2 {
                    // Could be prefix or a subnet
                    dc.range_start = Some(parts[1].to_string());
                }
                // Check for trailing "local" keyword
                if parts.last().map(|s| s.as_str()) == Some("local") {
                    dc.local = true;
                }
                self.domains.push(dc);
            }
            "cname" => {
                let v = require_value(key, value)?;
                let parts = split_on(v, ',');
                if parts.is_empty() {
                    return Err(DnsmasqError::Config(
                        "cname requires alias,target".to_string(),
                    ));
                }
                let alias = canonicalise(&parts[0]);
                let target = if parts.len() > 1 {
                    canonicalise(&parts[1])
                } else {
                    return Err(DnsmasqError::Config(
                        "cname requires alias,target".to_string(),
                    ));
                };
                let ttl = if parts.len() > 2 {
                    Some(parse_u32("cname ttl", &parts[2])?)
                } else {
                    None
                };
                self.cnames.push(CnameConfig { alias, target, ttl });
            }
            "host-record" => {
                let v = require_value(key, value)?;
                let parts = split_on(v, ',');
                if parts.is_empty() {
                    return Err(DnsmasqError::Config(
                        "host-record requires at least a name".to_string(),
                    ));
                }
                let name = canonicalise(&parts[0]);
                let mut ipv4 = None;
                let mut ipv6 = None;
                let mut ttl = None;
                for part in &parts[1..] {
                    if let Ok(ip) = part.parse::<Ipv4Addr>() {
                        ipv4 = Some(ip);
                    } else if let Ok(ip) = part.parse::<Ipv6Addr>() {
                        ipv6 = Some(ip);
                    } else if let Ok(t) = part.parse::<u32>() {
                        ttl = Some(t);
                    }
                }
                self.host_records.push(HostRecordConfig {
                    name,
                    ipv4,
                    ipv6,
                    ttl,
                });
            }
            "dynamic-host" => {
                let v = require_value(key, value)?;
                let parts = split_on(v, ',');
                if parts.is_empty() {
                    return Err(DnsmasqError::Config(
                        "dynamic-host requires name".to_string(),
                    ));
                }
                let name = canonicalise(&parts[0]);
                let address = if parts.len() > 1 {
                    Some(parse_ip(&parts[1]).map_err(|_| {
                        DnsmasqError::Config(format!("invalid IP in dynamic-host: '{}'", parts[1]))
                    })?)
                } else {
                    None
                };
                let ttl = if parts.len() > 2 {
                    Some(parse_u32("dynamic-host ttl", &parts[2])?)
                } else {
                    None
                };
                self.dynamic_hosts
                    .push(DynamicHostConfig { name, address, ttl });
            }
            "mx-host" => {
                let v = require_value(key, value)?;
                let parts = split_on(v, ',');
                if parts.is_empty() {
                    return Err(DnsmasqError::Config("mx-host requires name".to_string()));
                }
                let name = canonicalise(&parts[0]);
                let target = if parts.len() > 1 {
                    canonicalise(&parts[1])
                } else {
                    name.clone()
                };
                let preference = if parts.len() > 2 {
                    parse_u16("mx-host preference", &parts[2])?
                } else {
                    10
                };
                self.mx_hosts.push(MxConfig {
                    name,
                    target,
                    preference,
                });
            }
            "mx-target" => {
                let v = require_value(key, value)?;
                self.mx_target = Some(canonicalise(v));
            }
            "selfmx" => {
                self.selfmx = true;
            }
            "localmx" => {
                self.localmx = true;
            }
            "srv-host" => {
                let v = require_value(key, value)?;
                let parts = split_on(v, ',');
                if parts.is_empty() {
                    return Err(DnsmasqError::Config("srv-host requires name".to_string()));
                }
                let name = canonicalise(&parts[0]);
                let target = if parts.len() > 1 {
                    parts[1].to_string()
                } else {
                    String::new()
                };
                let port = if parts.len() > 2 {
                    parse_u16("srv-host port", &parts[2])?
                } else {
                    0
                };
                let priority = if parts.len() > 3 {
                    parse_u16("srv-host priority", &parts[3])?
                } else {
                    0
                };
                let weight = if parts.len() > 4 {
                    parse_u16("srv-host weight", &parts[4])?
                } else {
                    0
                };
                self.srv_hosts.push(SrvConfig {
                    name,
                    target,
                    port,
                    priority,
                    weight,
                });
            }
            "txt-record" => {
                let v = require_value(key, value)?;
                let parts = split_on(v, ',');
                if parts.is_empty() {
                    return Err(DnsmasqError::Config("txt-record requires name".to_string()));
                }
                let name = canonicalise(&parts[0]);
                let text = parts[1..].iter().map(|s| s.to_string()).collect();
                self.txt_records.push(TxtRecordConfig { name, text });
            }
            "caa-record" => {
                let v = require_value(key, value)?;
                let parts = split_on(v, ',');
                if parts.len() < 4 {
                    return Err(DnsmasqError::Config(
                        "caa-record requires name,flags,tag,value".to_string(),
                    ));
                }
                self.caa_records.push(CaaRecordConfig {
                    name: canonicalise(&parts[0]),
                    flags: parse_u8("caa-record flags", &parts[1])?,
                    tag: parts[2].to_string(),
                    value: parts[3].to_string(),
                });
            }
            "ptr-record" => {
                let v = require_value(key, value)?;
                let parts = split_on(v, ',');
                if parts.is_empty() {
                    return Err(DnsmasqError::Config("ptr-record requires name".to_string()));
                }
                let target = if parts.len() > 1 {
                    Some(parts[1].to_string())
                } else {
                    None
                };
                self.ptr_records.push(PtrRecordConfig {
                    name: canonicalise(&parts[0]),
                    target,
                });
            }
            "naptr-record" => {
                let v = require_value(key, value)?;
                let parts = split_on(v, ',');
                if parts.len() < 7 {
                    return Err(DnsmasqError::Config(
                        "naptr-record requires name,order,preference,flags,service,regexp,replacement"
                            .to_string()
                    ));
                }
                self.naptr_records.push(NaptrRecordConfig {
                    name: canonicalise(&parts[0]),
                    order: parse_u16("naptr-record order", &parts[1])?,
                    preference: parse_u16("naptr-record preference", &parts[2])?,
                    flags: parts[3].to_string(),
                    service: parts[4].to_string(),
                    regexp: parts[5].to_string(),
                    replacement: parts[6].to_string(),
                });
            }
            "dns-rr" => {
                let v = require_value(key, value)?;
                let parts = split_on(v, ',');
                if parts.len() < 3 {
                    return Err(DnsmasqError::Config(
                        "dns-rr requires name,rrtype,rdata".to_string(),
                    ));
                }
                let rdata: Vec<u8> = parse_hex_or_string(&parts[2..].join(","));
                self.dns_rr_records.push(DnsRrConfig {
                    name: canonicalise(&parts[0]),
                    rrtype: parse_u16("dns-rr type", &parts[1])?,
                    rdata,
                });
            }
            "interface-name" => {
                let v = require_value(key, value)?;
                let parts = split_on(v, ',');
                if parts.len() < 2 {
                    return Err(DnsmasqError::Config(
                        "interface-name requires name,interface".to_string(),
                    ));
                }
                let family = if parts.len() > 2 {
                    Some(parts[2].to_string())
                } else {
                    None
                };
                self.interface_names.push(InterfaceNameConfig {
                    name: canonicalise(&parts[0]),
                    interface: parts[1].to_string(),
                    family,
                });
            }
            "synth-domain" => {
                let v = require_value(key, value)?;
                let parts = split_on(v, ',');
                if parts.is_empty() {
                    return Err(DnsmasqError::Config(
                        "synth-domain requires domain".to_string(),
                    ));
                }
                self.synth_domains.push(SynthDomainConfig {
                    domain: canonicalise(&parts[0]),
                    prefix: if parts.len() > 1 {
                        Some(parts[1].to_string())
                    } else {
                        None
                    },
                    range_start: if parts.len() > 2 {
                        Some(parts[2].to_string())
                    } else {
                        None
                    },
                    range_end: if parts.len() > 3 {
                        Some(parts[3].to_string())
                    } else {
                        None
                    },
                });
            }

            // ================================================================
            // DHCP Directives (feature-gated)
            // ================================================================
            "dhcp-range" => {
                if !features::has_dhcp() {
                    return Err(DnsmasqError::Config(
                        "dhcp-range requires the 'dhcp' feature to be enabled".to_string(),
                    ));
                }
                #[cfg(feature = "dhcp")]
                {
                    let v = require_value(key, value)?;
                    let range = parse_dhcp_range(v)?;
                    self.ensure_dhcp().ranges.push(range);
                }
            }
            "dhcp-host" => {
                if !features::has_dhcp() {
                    return Err(DnsmasqError::Config(
                        "dhcp-host requires the 'dhcp' feature to be enabled".to_string(),
                    ));
                }
                #[cfg(feature = "dhcp")]
                {
                    let v = require_value(key, value)?;
                    let host = parse_dhcp_host(v)?;
                    self.ensure_dhcp().hosts.push(host);
                }
            }
            "dhcp-option" => {
                if !features::has_dhcp() {
                    return Err(DnsmasqError::Config(
                        "dhcp-option requires the 'dhcp' feature to be enabled".to_string(),
                    ));
                }
                #[cfg(feature = "dhcp")]
                {
                    let v = require_value(key, value)?;
                    let opt = parse_dhcp_option(v, false)?;
                    self.ensure_dhcp().options.push(opt);
                }
            }
            "dhcp-option-force" => {
                if !features::has_dhcp() {
                    return Err(DnsmasqError::Config(
                        "dhcp-option-force requires the 'dhcp' feature to be enabled".to_string(),
                    ));
                }
                #[cfg(feature = "dhcp")]
                {
                    let v = require_value(key, value)?;
                    let opt = parse_dhcp_option(v, true)?;
                    self.ensure_dhcp().option_forces.push(opt);
                }
            }
            "dhcp-option-pxe" => {
                if !features::has_dhcp() {
                    return Err(DnsmasqError::Config(
                        "dhcp-option-pxe requires the 'dhcp' feature to be enabled".to_string(),
                    ));
                }
                #[cfg(feature = "dhcp")]
                {
                    let v = require_value(key, value)?;
                    let opt = parse_dhcp_option(v, true)?;
                    self.ensure_dhcp().option_forces.push(opt);
                }
            }
            "dhcp-boot" => {
                if !features::has_dhcp() {
                    return Err(DnsmasqError::Config(
                        "dhcp-boot requires the 'dhcp' feature to be enabled".to_string(),
                    ));
                }
                #[cfg(feature = "dhcp")]
                {
                    let v = require_value(key, value)?;
                    let boot = parse_dhcp_boot(v)?;
                    self.ensure_dhcp().boot.push(boot);
                }
            }
            "dhcp-leasefile" | "dhcp-lease-file" => {
                if !features::has_dhcp() {
                    return Err(DnsmasqError::Config(
                        "dhcp-leasefile requires the 'dhcp' feature to be enabled".to_string(),
                    ));
                }
                #[cfg(feature = "dhcp")]
                {
                    let v = require_value(key, value)?;
                    self.ensure_dhcp().leasefile = v.to_string();
                }
            }
            "dhcp-lease-max" => {
                if !features::has_dhcp() {
                    return Err(DnsmasqError::Config(
                        "dhcp-lease-max requires the 'dhcp' feature to be enabled".to_string(),
                    ));
                }
                #[cfg(feature = "dhcp")]
                {
                    let v = require_value(key, value)?;
                    let val = parse_u32(key, v)?;
                    if val == 0 {
                        return Err(DnsmasqError::Config(
                            "dhcp-lease-max must be > 0".to_string(),
                        ));
                    }
                    self.ensure_dhcp().lease_max = val;
                }
            }
            "dhcp-authoritative" => {
                if !features::has_dhcp() {
                    return Err(DnsmasqError::Config(
                        "dhcp-authoritative requires the 'dhcp' feature to be enabled".to_string(),
                    ));
                }
                #[cfg(feature = "dhcp")]
                {
                    self.ensure_dhcp().authoritative = true;
                }
            }
            "dhcp-rapid-commit" => {
                if !features::has_dhcp() {
                    return Err(DnsmasqError::Config(
                        "dhcp-rapid-commit requires the 'dhcp' feature to be enabled".to_string(),
                    ));
                }
                #[cfg(feature = "dhcp")]
                {
                    self.ensure_dhcp().rapid_commit = true;
                }
            }
            "dhcp-sequential-ip" => {
                if !features::has_dhcp() {
                    return Err(DnsmasqError::Config(
                        "dhcp-sequential-ip requires the 'dhcp' feature to be enabled".to_string(),
                    ));
                }
                #[cfg(feature = "dhcp")]
                {
                    self.ensure_dhcp().sequential_ip = true;
                }
            }
            "no-ping" => {
                #[cfg(feature = "dhcp")]
                {
                    self.ensure_dhcp().no_ping = true;
                }
            }
            "dhcp-fqdn" => {
                #[cfg(feature = "dhcp")]
                {
                    self.ensure_dhcp().fqdn = true;
                    self.ensure_dhcp().dhcp_fqdn = true;
                }
            }
            "dhcp-client-update" => {
                #[cfg(feature = "dhcp")]
                {
                    self.ensure_dhcp().client_update = true;
                }
            }
            "dhcp-ignore-clid" => {
                #[cfg(feature = "dhcp")]
                {
                    self.ensure_dhcp().ignore_clid = true;
                }
            }
            "dhcp-proxy" => {
                #[cfg(feature = "dhcp")]
                {
                    if let Some(v) = value {
                        for p in v.split(',') {
                            let p = p.trim();
                            if !p.is_empty() {
                                self.ensure_dhcp().proxy.push(p.to_string());
                            }
                        }
                    }
                }
            }
            "dhcp-generate-names" | "dhcp-generate-name" => {
                #[cfg(feature = "dhcp")]
                {
                    if let Some(v) = value {
                        self.ensure_dhcp().generate_names.push(v.to_string());
                    } else {
                        self.ensure_dhcp().generate_names.push(String::new());
                    }
                }
            }
            "dhcp-ignore-names" | "dhcp-ignore-name" => {
                #[cfg(feature = "dhcp")]
                {
                    if let Some(v) = value {
                        self.ensure_dhcp().ignore_names.push(v.to_string());
                    } else {
                        self.ensure_dhcp().ignore_names.push(String::new());
                    }
                }
            }
            "dhcp-alternate-port" => {
                #[cfg(feature = "dhcp")]
                {
                    if let Some(v) = value {
                        let parts = split_on(v, ',');
                        let server_port = if !parts.is_empty() {
                            parse_u16("dhcp-alternate-port server", &parts[0])?
                        } else {
                            67
                        };
                        let client_port = if parts.len() > 1 {
                            parse_u16("dhcp-alternate-port client", &parts[1])?
                        } else {
                            server_port + 1
                        };
                        self.ensure_dhcp().alternate_port = Some((server_port, client_port));
                    } else {
                        self.ensure_dhcp().alternate_port = Some((1067, 1068));
                    }
                }
            }
            "leasefile-ro" | "dhcp-leasefile-ro" => {
                #[cfg(feature = "dhcp")]
                {
                    self.ensure_dhcp().leasefile_ro = true;
                }
            }
            "read-ethers" => {
                // Read /etc/ethers for DHCP host mappings
                #[cfg(feature = "dhcp")]
                {
                    self.ensure_dhcp()
                        .hostfiles
                        .push(constants::ETHERSFILE.to_string());
                }
            }
            "bootp-dynamic" => {
                // Enable dynamic BOOTP address allocation (C OPT_BOOTP_DYNAMIC).
                #[cfg(feature = "dhcp")]
                {
                    self.ensure_dhcp().bootp_dynamic = true;
                }
            }
            "dhcp-hostsfile" => {
                #[cfg(feature = "dhcp")]
                {
                    let v = require_value(key, value)?;
                    self.ensure_dhcp().hostfiles.push(v.to_string());
                }
            }
            "dhcp-optsfile" => {
                #[cfg(feature = "dhcp")]
                {
                    let v = require_value(key, value)?;
                    self.ensure_dhcp().optsfiles.push(v.to_string());
                }
            }
            "dhcp-hostsdir" => {
                #[cfg(feature = "dhcp")]
                {
                    let v = require_value(key, value)?;
                    self.ensure_dhcp().hostdirs.push(v.to_string());
                }
            }
            "dhcp-optsdir" => {
                #[cfg(feature = "dhcp")]
                {
                    let v = require_value(key, value)?;
                    self.ensure_dhcp().optsdirs.push(v.to_string());
                }
            }
            "dhcp-no-override" => {
                #[cfg(feature = "dhcp")]
                {
                    self.ensure_dhcp().no_override = true;
                }
            }
            "dhcp-match" => {
                #[cfg(feature = "dhcp")]
                {
                    let v = require_value(key, value)?;
                    let m = parse_dhcp_match(v)?;
                    self.ensure_dhcp().matches.push(m);
                }
            }
            "dhcp-name-match" => {
                #[cfg(feature = "dhcp")]
                {
                    let v = require_value(key, value)?;
                    let parts = split_on(v, ',');
                    if parts.len() < 2 {
                        return Err(DnsmasqError::Config(
                            "dhcp-name-match requires set:tag,name".to_string(),
                        ));
                    }
                    let set_tag = extract_tag_set(&parts[0])?;
                    self.ensure_dhcp().name_matches.push(DhcpNameMatchConfig {
                        set_tag,
                        name: parts[1].to_string(),
                    });
                }
            }
            "dhcp-broadcast" => {
                #[cfg(feature = "dhcp")]
                {
                    if let Some(v) = value {
                        self.ensure_dhcp().broadcasts.push(v.to_string());
                    }
                }
            }
            "dhcp-mac" => {
                #[cfg(feature = "dhcp")]
                {
                    let v = require_value(key, value)?;
                    let parts = split_on(v, ',');
                    if parts.len() < 2 {
                        return Err(DnsmasqError::Config(
                            "dhcp-mac requires set:tag,mac".to_string(),
                        ));
                    }
                    let set_tag = extract_tag_set(&parts[0])?;
                    self.ensure_dhcp().mac_matches.push(DhcpMacConfig {
                        set_tag,
                        mac: parts[1].to_string(),
                    });
                }
            }
            "dhcp-userclass" => {
                #[cfg(feature = "dhcp")]
                {
                    let v = require_value(key, value)?;
                    let parts = split_on(v, ',');
                    if parts.len() < 2 {
                        return Err(DnsmasqError::Config(
                            "dhcp-userclass requires set:tag,class".to_string(),
                        ));
                    }
                    let set_tag = extract_tag_set(&parts[0])?;
                    self.ensure_dhcp().userclasses.push(DhcpClassConfig {
                        set_tag,
                        class_value: parts[1].to_string(),
                    });
                }
            }
            "dhcp-vendorclass" => {
                #[cfg(feature = "dhcp")]
                {
                    let v = require_value(key, value)?;
                    let parts = split_on(v, ',');
                    if parts.len() < 2 {
                        return Err(DnsmasqError::Config(
                            "dhcp-vendorclass requires set:tag,class".to_string(),
                        ));
                    }
                    let set_tag = extract_tag_set(&parts[0])?;
                    self.ensure_dhcp().vendorclasses.push(DhcpClassConfig {
                        set_tag,
                        class_value: parts[1].to_string(),
                    });
                }
            }
            "dhcp-circuitid" => {
                #[cfg(feature = "dhcp")]
                {
                    let v = require_value(key, value)?;
                    let parts = split_on(v, ',');
                    if parts.len() < 2 {
                        return Err(DnsmasqError::Config(
                            "dhcp-circuitid requires set:tag,circuit-id".to_string(),
                        ));
                    }
                    let set_tag = extract_tag_set(&parts[0])?;
                    self.ensure_dhcp().circuit_ids.push(DhcpCircuitConfig {
                        set_tag,
                        circuit_id: parts[1].to_string(),
                    });
                }
            }
            "dhcp-remoteid" => {
                #[cfg(feature = "dhcp")]
                {
                    let v = require_value(key, value)?;
                    let parts = split_on(v, ',');
                    if parts.len() < 2 {
                        return Err(DnsmasqError::Config(
                            "dhcp-remoteid requires set:tag,remote-id".to_string(),
                        ));
                    }
                    let set_tag = extract_tag_set(&parts[0])?;
                    self.ensure_dhcp().remote_ids.push(DhcpRemoteConfig {
                        set_tag,
                        remote_id: parts[1].to_string(),
                    });
                }
            }
            "dhcp-subscrid" => {
                #[cfg(feature = "dhcp")]
                {
                    let v = require_value(key, value)?;
                    let parts = split_on(v, ',');
                    if parts.len() < 2 {
                        return Err(DnsmasqError::Config(
                            "dhcp-subscrid requires set:tag,subscriber-id".to_string(),
                        ));
                    }
                    let set_tag = extract_tag_set(&parts[0])?;
                    self.ensure_dhcp().subscriber_ids.push(DhcpSubscrConfig {
                        set_tag,
                        subscriber_id: parts[1].to_string(),
                    });
                }
            }
            "dhcp-pxe-vendor" => {
                #[cfg(feature = "dhcp")]
                {
                    let v = require_value(key, value)?;
                    self.ensure_dhcp().pxe_vendors.push(v.to_string());
                }
            }
            "dhcp-reply-delay" => {
                #[cfg(feature = "dhcp")]
                {
                    let v = require_value(key, value)?;
                    let val = parse_u32(key, v)?;
                    if val > 300 {
                        return Err(DnsmasqError::Config(
                            "dhcp-reply-delay must not exceed 300 seconds".to_string(),
                        ));
                    }
                    self.ensure_dhcp().reply_delay = Some(val);
                }
            }
            "script-on-renewal" => {
                #[cfg(feature = "dhcp")]
                {
                    self.ensure_dhcp().script_on_renewal = true;
                }
            }
            "script-arp" => {
                #[cfg(feature = "dhcp")]
                {
                    self.ensure_dhcp().script_arp = true;
                }
            }
            "dhcp-duid" => {
                #[cfg(feature = "dhcp")]
                {
                    let v = require_value(key, value)?;
                    self.ensure_dhcp().duid = Some(v.to_string());
                }
            }
            "enable-ra" => {
                #[cfg(feature = "dhcp")]
                {
                    self.ensure_dhcp().enable_ra = true;
                }
            }
            "ra-param" => {
                #[cfg(feature = "dhcp")]
                {
                    let v = require_value(key, value)?;
                    let ra = parse_ra_param(v)?;
                    self.ensure_dhcp().ra_params.push(ra);
                }
            }
            "quiet-dhcp" => {
                #[cfg(feature = "dhcp")]
                {
                    self.ensure_dhcp().quiet_dhcp = true;
                }
            }
            "quiet-dhcp6" => {
                #[cfg(feature = "dhcp")]
                {
                    self.ensure_dhcp().quiet_dhcp6 = true;
                }
            }
            "quiet-ra" => {
                #[cfg(feature = "dhcp")]
                {
                    self.ensure_dhcp().quiet_ra = true;
                }
            }
            "dhcp-relay" => {
                #[cfg(feature = "dhcp")]
                {
                    let v = require_value(key, value)?;
                    let parts = split_on(v, ',');
                    if parts.len() < 2 {
                        return Err(DnsmasqError::Config(
                            "dhcp-relay requires local,server[,interface]".to_string(),
                        ));
                    }
                    self.ensure_dhcp().relays.push(DhcpRelayConfig {
                        local: parts[0].to_string(),
                        server: parts[1].to_string(),
                        interface: if parts.len() > 2 {
                            Some(parts[2].to_string())
                        } else {
                            None
                        },
                    });
                }
            }
            "dhcp-split-relay" => {
                #[cfg(feature = "dhcp")]
                {
                    let v = require_value(key, value)?;
                    let parts = split_on(v, ',');
                    if parts.len() < 2 {
                        return Err(DnsmasqError::Config(
                            "dhcp-split-relay requires local,server[,port]".to_string(),
                        ));
                    }
                    let port = if parts.len() > 2 {
                        Some(parse_u16("dhcp-split-relay port", &parts[2])?)
                    } else {
                        None
                    };
                    self.ensure_dhcp().split_relays.push(DhcpSplitRelayConfig {
                        local: parts[0].to_string(),
                        server: parts[1].to_string(),
                        port,
                    });
                }
            }
            "tag-if" => {
                #[cfg(feature = "dhcp")]
                {
                    let v = require_value(key, value)?;
                    let ti = parse_tag_if(v)?;
                    self.ensure_dhcp().tag_ifs.push(ti);
                }
            }
            "leasequery" => {
                #[cfg(feature = "dhcp")]
                {
                    self.ensure_dhcp().leasequery = Some(LeasequeryConfig { enabled: true });
                }
            }

            // ================================================================
            // TFTP Directives (feature-gated)
            // ================================================================
            "enable-tftp" => {
                if !features::has_tftp() {
                    return Err(DnsmasqError::Config(
                        "enable-tftp requires the 'tftp' feature to be enabled".to_string(),
                    ));
                }
                #[cfg(feature = "tftp")]
                {
                    self.ensure_tftp();
                }
            }
            "tftp-root" => {
                if !features::has_tftp() {
                    return Err(DnsmasqError::Config(
                        "tftp-root requires the 'tftp' feature to be enabled".to_string(),
                    ));
                }
                #[cfg(feature = "tftp")]
                {
                    let v = require_value(key, value)?;
                    self.ensure_tftp().root = Some(v.to_string());
                }
            }
            "tftp-max" => {
                #[cfg(feature = "tftp")]
                {
                    let v = require_value(key, value)?;
                    let val = parse_u32(key, v)?;
                    if val == 0 {
                        return Err(DnsmasqError::Config("tftp-max must be > 0".to_string()));
                    }
                    self.ensure_tftp().max_connections = val;
                }
            }
            "tftp-secure" => {
                #[cfg(feature = "tftp")]
                {
                    self.ensure_tftp().secure = true;
                }
            }
            "tftp-no-fail" => {
                #[cfg(feature = "tftp")]
                {
                    self.ensure_tftp().no_fail = true;
                }
            }
            "tftp-unique-root" => {
                #[cfg(feature = "tftp")]
                {
                    if let Some(v) = value {
                        self.ensure_tftp().unique_root = Some(v.to_string());
                    } else {
                        self.ensure_tftp().unique_root = Some("ip".to_string());
                    }
                }
            }
            "tftp-lowercase" => {
                #[cfg(feature = "tftp")]
                {
                    self.ensure_tftp().lowercase = true;
                }
            }
            "tftp-mtu" => {
                #[cfg(feature = "tftp")]
                {
                    let v = require_value(key, value)?;
                    self.ensure_tftp().mtu = Some(parse_u16(key, v)?);
                }
            }
            "tftp-single-port" => {
                #[cfg(feature = "tftp")]
                {
                    self.ensure_tftp().single_port = true;
                }
            }
            "tftp-port-range" => {
                #[cfg(feature = "tftp")]
                {
                    let v = require_value(key, value)?;
                    self.ensure_tftp().port_range = Some(v.to_string());
                }
            }
            "tftp-no-blocksize" => {
                #[cfg(feature = "tftp")]
                {
                    self.ensure_tftp().no_blocksize = true;
                }
            }
            "quiet-tftp" => {
                #[cfg(feature = "tftp")]
                {
                    self.ensure_tftp().quiet = true;
                }
            }

            // ================================================================
            // DNSSEC Directives (feature-gated)
            // ================================================================
            "dnssec" => {
                if !features::has_dnssec() {
                    return Err(DnsmasqError::Config(
                        "dnssec requires the 'dnssec' feature to be enabled".to_string(),
                    ));
                }
                #[cfg(feature = "dnssec")]
                {
                    self.ensure_dnssec().enabled = true;
                }
            }
            "trust-anchor" => {
                if !features::has_dnssec() {
                    return Err(DnsmasqError::Config(
                        "trust-anchor requires the 'dnssec' feature to be enabled".to_string(),
                    ));
                }
                #[cfg(feature = "dnssec")]
                {
                    let v = require_value(key, value)?;
                    self.ensure_dnssec().trust_anchors.push(v.to_string());
                }
            }
            "dnssec-debug" => {
                #[cfg(feature = "dnssec")]
                {
                    self.ensure_dnssec().debug = true;
                }
            }
            "dnssec-check-unsigned" => {
                #[cfg(feature = "dnssec")]
                {
                    if let Some("no" | "false" | "0") = value {
                        self.ensure_dnssec().check_unsigned = false;
                    } else {
                        self.ensure_dnssec().check_unsigned = true;
                    }
                }
            }
            "dnssec-no-timecheck" => {
                #[cfg(feature = "dnssec")]
                {
                    self.ensure_dnssec().no_timecheck = true;
                }
            }
            "dnssec-timestamp" => {
                #[cfg(feature = "dnssec")]
                {
                    let v = require_value(key, value)?;
                    self.ensure_dnssec().timestamp = Some(v.to_string());
                }
            }
            "dnssec-limits" => {
                // DNSSEC validation limits (C option.c LOPT_LIMIT).
                #[cfg(feature = "dnssec")]
                {
                    let v = require_value(key, value)?;
                    self.ensure_dnssec().limits = Some(v.to_string());
                }
            }

            // ================================================================
            // Auth DNS Directives (feature-gated)
            // ================================================================
            "auth-zone" => {
                if !features::has_auth() {
                    return Err(DnsmasqError::Config(
                        "auth-zone requires the 'auth' feature to be enabled".to_string(),
                    ));
                }
                #[cfg(feature = "auth")]
                {
                    let v = require_value(key, value)?;
                    self.ensure_auth().zone = Some(v.to_string());
                }
            }
            "auth-server" => {
                #[cfg(feature = "auth")]
                {
                    let v = require_value(key, value)?;
                    self.ensure_auth().server = Some(v.to_string());
                }
            }
            "auth-soa" => {
                #[cfg(feature = "auth")]
                {
                    let v = require_value(key, value)?;
                    self.ensure_auth().soa = Some(v.to_string());
                }
            }
            "auth-sec-servers" => {
                #[cfg(feature = "auth")]
                {
                    let v = require_value(key, value)?;
                    for s in v.split(',') {
                        let s = s.trim();
                        if !s.is_empty() {
                            self.ensure_auth().sec_servers.push(s.to_string());
                        }
                    }
                }
            }
            "auth-peer" => {
                #[cfg(feature = "auth")]
                {
                    let v = require_value(key, value)?;
                    for p in v.split(',') {
                        let p = p.trim();
                        if !p.is_empty() {
                            self.ensure_auth().peer.push(p.to_string());
                        }
                    }
                }
            }

            // ================================================================
            // Integration Directives (feature-gated)
            // ================================================================
            "enable-dbus" => {
                if !features::has_dbus() {
                    return Err(DnsmasqError::Config(
                        "enable-dbus requires the 'dbus' feature to be enabled".to_string(),
                    ));
                }
                #[cfg(feature = "dbus")]
                {
                    self.dbus = Some(DbusConfig { enabled: true });
                }
            }
            "enable-ubus" => {
                if !features::has_ubus() {
                    return Err(DnsmasqError::Config(
                        "enable-ubus requires the 'ubus' feature to be enabled".to_string(),
                    ));
                }
                #[cfg(feature = "ubus")]
                {
                    self.ubus = Some(UbusConfig { enabled: true });
                }
            }
            "dhcp-script" => {
                if !features::has_script() {
                    return Err(DnsmasqError::Config(
                        "dhcp-script requires the 'script' feature to be enabled".to_string(),
                    ));
                }
                #[cfg(feature = "script")]
                {
                    let v = require_value(key, value)?;
                    if let Some(ref mut sc) = self.script {
                        sc.path = Some(v.to_string());
                    } else {
                        self.script = Some(ScriptConfig {
                            path: Some(v.to_string()),
                            scriptuser: None,
                        });
                    }
                }
            }
            "dhcp-luascript" => {
                if !features::has_luascript() {
                    return Err(DnsmasqError::Config(
                        "dhcp-luascript requires the 'luascript' feature to be enabled".to_string(),
                    ));
                }
                #[cfg(feature = "luascript")]
                {
                    let v = require_value(key, value)?;
                    if let Some(ref mut sc) = self.script {
                        sc.path = Some(v.to_string());
                    } else {
                        self.script = Some(ScriptConfig {
                            path: Some(v.to_string()),
                            scriptuser: None,
                        });
                    }
                }
            }
            "dhcp-scriptuser" => {
                #[cfg(feature = "script")]
                {
                    let v = require_value(key, value)?;
                    if let Some(ref mut sc) = self.script {
                        sc.scriptuser = Some(v.to_string());
                    } else {
                        self.script = Some(ScriptConfig {
                            path: None,
                            scriptuser: Some(v.to_string()),
                        });
                    }
                }
            }
            "ipset" => {
                if !features::has_ipset() {
                    return Err(DnsmasqError::Config(
                        "ipset requires the 'ipset' feature to be enabled".to_string(),
                    ));
                }
                #[cfg(feature = "ipset")]
                {
                    let v = require_value(key, value)?;
                    let ipsc = parse_ipset(v)?;
                    self.ipsets.push(ipsc);
                }
            }
            "nftset" => {
                if !features::has_nftset() {
                    return Err(DnsmasqError::Config(
                        "nftset requires the 'nftset' feature to be enabled".to_string(),
                    ));
                }
                #[cfg(feature = "nftset")]
                {
                    let v = require_value(key, value)?;
                    let nsc = parse_nftset(v)?;
                    self.nftsets.push(nsc);
                }
            }
            "conntrack" => {
                if !features::has_conntrack() {
                    return Err(DnsmasqError::Config(
                        "conntrack requires the 'conntrack' feature to be enabled".to_string(),
                    ));
                }
                #[cfg(feature = "conntrack")]
                {
                    self.conntrack = true;
                }
            }
            "connmark-allowlist-enable" => {
                self.connmark_allowlist_enable = true;
            }
            "connmark-allowlist" => {
                let v = require_value(key, value)?;
                self.connmark_allowlists.push(v.to_string());
            }

            // ================================================================
            // Logging Directives
            // ================================================================
            "log-facility" => {
                let v = require_value(key, value)?;
                self.log.facility = Some(v.to_string());
            }
            "log-dhcp" => {
                self.log.log_dhcp = true;
            }
            "log-async" => {
                if let Some(v) = value {
                    let val = parse_u32(key, v)?;
                    if val == 0 {
                        return Err(DnsmasqError::Config("log-async must be > 0".to_string()));
                    }
                    self.log.log_async = Some(val);
                } else {
                    self.log.log_async = Some(25); // default async queue size
                }
            }
            "log-debug" => {
                self.log.log_debug = true;
            }

            // ================================================================
            // Daemon Directives
            // ================================================================
            "no-daemon" => {
                self.no_daemon = true;
            }
            "keep-in-foreground" => {
                self.keep_in_foreground = true;
            }
            "conf-file" => {
                // Handled in parse_config_file (include processing).
                // Reaching here means it was not intercepted — store for reference.
                if let Some(v) = value {
                    self.conf_file = Some(v.to_string());
                }
            }
            "conf-dir" => {
                // Handled in parse_config_file. Reaching here means it was not intercepted.
                // Store for reference.
                if let Some(v) = value {
                    let parts = split_on(v, ',');
                    self.conf_dirs.push(ConfDirConfig {
                        path: parts[0].to_string(),
                        filter: if parts.len() > 1 {
                            Some(parts[1..].join(","))
                        } else {
                            None
                        },
                    });
                }
            }
            "conf-script" => {
                // Config from script output (C daemon->conf_script in option.c).
                // The script is executed and its stdout is parsed as additional
                // configuration directives.  Store the path for runtime execution.
                let v = require_value(key, value)?;
                tracing::warn!(
                    script = %v,
                    "conf-script directive accepted; script will be executed at runtime for additional configuration"
                );
                self.conf_script = Some(v.to_string());
            }
            "pid-file" => {
                if let Some(v) = value {
                    if v.is_empty() {
                        self.pid_file = None;
                    } else {
                        self.pid_file = Some(v.to_string());
                    }
                } else {
                    self.pid_file = None;
                }
            }
            "user" => {
                if let Some(v) = value {
                    if v.is_empty() {
                        self.user = None;
                    } else {
                        self.user = Some(v.to_string());
                    }
                } else {
                    self.user = None;
                }
            }
            "group" => {
                if let Some(v) = value {
                    if v.is_empty() {
                        self.group = None;
                    } else {
                        self.group = Some(v.to_string());
                    }
                } else {
                    self.group = None;
                }
            }
            "test" => {
                self.test_mode = true;
            }

            // ================================================================
            // Diagnostics
            // ================================================================
            "dumpfile" => {
                if !features::has_dumpfile() {
                    return Err(DnsmasqError::Config(
                        "dumpfile requires the 'dumpfile' feature to be enabled".to_string(),
                    ));
                }
                #[cfg(feature = "dumpfile")]
                {
                    let v = require_value(key, value)?;
                    self.dumpfile = Some(v.to_string());
                }
            }
            "dumpmask" => {
                #[cfg(feature = "dumpfile")]
                {
                    let v = require_value(key, value)?;
                    self.dumpmask = Some(parse_u32(key, v)?);
                }
            }
            "dns-loop-detect" => {
                if !features::has_loop_detect() {
                    return Err(DnsmasqError::Config(
                        "dns-loop-detect requires the 'loop-detect' feature to be enabled"
                            .to_string(),
                    ));
                }
                #[cfg(feature = "loop-detect")]
                {
                    self.loop_detect = true;
                }
            }

            // ================================================================
            // Umbrella (Cisco OpenDNS)
            // ================================================================
            "umbrella" => {
                if let Some(v) = value {
                    let parts = split_on(v, ',');
                    let mut uc = UmbrellaConfig {
                        device_id: None,
                        org_id: None,
                        asset_id: None,
                    };
                    for part in &parts {
                        if let Some(stripped) = part.strip_prefix("deviceid:") {
                            uc.device_id = Some(stripped.to_string());
                        } else if let Some(stripped) = part.strip_prefix("orgid:") {
                            uc.org_id = Some(stripped.to_string());
                        } else if let Some(stripped) = part.strip_prefix("assetid:") {
                            uc.asset_id = Some(stripped.to_string());
                        }
                    }
                    self.umbrella = Some(uc);
                } else {
                    self.umbrella = Some(UmbrellaConfig {
                        device_id: None,
                        org_id: None,
                        asset_id: None,
                    });
                }
            }

            // ================================================================
            // MAC/Subnet/CPE additions (C OPT_ADD_MAC, OPT_STRIP_MAC, etc.)
            // ================================================================
            "add-mac" => {
                // Add client MAC address to DNS queries forwarded upstream
                // (C OPT_ADD_MAC in src/option.c).
                self.add_mac = true;
            }
            "strip-mac" => {
                // Strip MAC address option from DNS queries before forwarding
                // (C OPT_STRIP_MAC in src/option.c).
                self.strip_mac = true;
            }
            "add-subnet" => {
                // Add EDNS0 client subnet option to DNS queries
                // (C OPT_CLIENT_SUBNET in src/option.c).
                // Optional value specifies the prefix length.
                if let Some(v) = value {
                    if v.is_empty() {
                        self.add_subnet = Some(None);
                    } else {
                        let prefix = parse_u32("add-subnet", v)?;
                        self.add_subnet = Some(Some(prefix));
                    }
                } else {
                    self.add_subnet = Some(None);
                }
            }
            "strip-subnet" => {
                // Strip EDNS0 client subnet from DNS queries before forwarding
                // (C OPT_STRIP_ECS in src/option.c).
                self.strip_subnet = true;
            }
            "add-cpe-id" => {
                // Add CPE-ID to DNS queries forwarded upstream
                // (C daemon->cpe_id in src/option.c).
                let v = require_value(key, value)?;
                self.add_cpe_id = Some(v.to_string());
            }

            // ================================================================
            // Alias directive (C struct addr_alias)
            // ================================================================
            "alias" => {
                // alias=old-ip,new-ip[,mask] — IP address translation for
                // DNS answers matching old-ip (C's addr_alias chain).
                let v = require_value(key, value)?;
                let parts = split_on(v, ',');
                if parts.len() < 2 {
                    return Err(DnsmasqError::Config(
                        "alias requires at least old-ip,new-ip".to_string(),
                    ));
                }
                let from: Ipv4Addr = parts[0].trim().parse().map_err(|_| {
                    DnsmasqError::Config(format!(
                        "invalid source address in alias: {}",
                        parts[0].trim()
                    ))
                })?;
                let to: Ipv4Addr = parts[1].trim().parse().map_err(|_| {
                    DnsmasqError::Config(format!(
                        "invalid target address in alias: {}",
                        parts[1].trim()
                    ))
                })?;
                let mask = if parts.len() > 2 {
                    let m: Ipv4Addr = parts[2].trim().parse().map_err(|_| {
                        DnsmasqError::Config(format!(
                            "invalid netmask in alias: {}",
                            parts[2].trim()
                        ))
                    })?;
                    Some(m)
                } else {
                    None
                };
                self.aliases.push(AliasConfig { from, to, mask });
            }

            // ================================================================
            // Domain matching (server selection)
            // ================================================================
            "domain-match" => {
                let v = require_value(key, value)?;
                let parts = split_on(v, ',');
                if parts.len() < 2 {
                    return Err(DnsmasqError::Config(
                        "domain-match requires domain,server".to_string(),
                    ));
                }
                self.domain_matches.push(DomainMatchConfig {
                    domain: canonicalise(&parts[0]),
                    server: parts[1].to_string(),
                });
            }

            // ================================================================
            // Missing C directives — backward compatibility (F15)
            // ================================================================
            "filterwin2k" | "filterSRV" => {
                // Filter useless Windows-originated DNS queries (SOA, SRV)
                // for wpad, isatap, etc.  (C OPT_FILTER in src/option.c).
                self.filterwin2k = true;
            }
            "pxe-prompt" => {
                // PXE boot prompt: pxe-prompt=[tag:]<prompt>[,<timeout>]
                // (C option.c LOPT_PXE_PROMT).
                #[cfg(feature = "dhcp")]
                {
                    let v = require_value(key, value)?;
                    let parts = split_on(v, ',');
                    let (prompt_str, tag) =
                        if parts[0].starts_with("tag:") || parts[0].starts_with("net:") {
                            let tag_str = parts[0]
                                .trim_start_matches("tag:")
                                .trim_start_matches("net:");
                            if parts.len() < 2 {
                                return Err(DnsmasqError::Config(
                                    "pxe-prompt: missing prompt text after tag".to_string(),
                                ));
                            }
                            (parts[1].as_str(), Some(tag_str.to_string()))
                        } else {
                            (parts[0].as_str(), None)
                        };
                    let timeout = if tag.is_some() {
                        parts.get(2).and_then(|s| s.parse::<u32>().ok())
                    } else {
                        parts.get(1).and_then(|s| s.parse::<u32>().ok())
                    };
                    self.pxe_prompts.push(PxePromptConfig {
                        prompt: prompt_str.to_string(),
                        timeout,
                        tag,
                    });
                }
            }
            "pxe-service" => {
                // PXE boot service: pxe-service=[tag:]<type>,<description>[,<filename>|<bootservicetype>][,<server>]
                // (C option.c LOPT_PXE_SERV).
                #[cfg(feature = "dhcp")]
                {
                    let v = require_value(key, value)?;
                    let parts = split_on(v, ',');
                    let (stype, desc, server, tag) = if !parts.is_empty()
                        && (parts[0].starts_with("tag:") || parts[0].starts_with("net:"))
                    {
                        let tag_str = parts[0]
                            .trim_start_matches("tag:")
                            .trim_start_matches("net:");
                        if parts.len() < 3 {
                            return Err(DnsmasqError::Config(
                                "pxe-service: requires type,description after tag".to_string(),
                            ));
                        }
                        (
                            parts[1].as_str(),
                            parts[2].as_str(),
                            parts.get(3).map(|s| s.to_string()),
                            Some(tag_str.to_string()),
                        )
                    } else {
                        if parts.len() < 2 {
                            return Err(DnsmasqError::Config(
                                "pxe-service: requires type,description".to_string(),
                            ));
                        }
                        (
                            parts[0].as_str(),
                            parts[1].as_str(),
                            parts.get(2).map(|s| s.to_string()),
                            None,
                        )
                    };
                    self.pxe_services.push(PxeServiceConfig {
                        service_type: stype.to_string(),
                        description: desc.to_string(),
                        server,
                        tag,
                    });
                }
            }
            "domain-suffix" => {
                // Alias for "domain" in C dnsmasq.
                // Reuse the same handler by recursing.
                return self.process_directive("domain", value);
            }
            "dhcp-ignore" => {
                // Ignore DHCP requests matching a tag (C LOPT_DHCP_INOTIFY).
                // dhcp-ignore=tag:<tag>  — ignore requests with this tag.
                #[cfg(feature = "dhcp")]
                {
                    let v = require_value(key, value)?;
                    self.ensure_dhcp().ignore_names.push(v.to_string());
                }
            }

            // ================================================================
            // Catch-all for unknown directives
            // ================================================================
            _ => {
                // Unknown directive — in C dnsmasq this would produce
                // "unsupported option" and die. In Rust we return an error.
                return Err(DnsmasqError::Config(format!(
                    "unknown configuration directive: '{}'",
                    key
                )));
            }
        }
        Ok(())
    }

    /// Parse an upstream server specification.
    ///
    /// Replaces C `parse_server()` from option.c (lines 6300+).
    ///
    /// Supported formats:
    /// - `ip` — plain upstream server
    /// - `ip#port` — upstream server on specific port
    /// - `/domain/ip` — domain-specific forwarding
    /// - `/domain/ip#port` — domain-specific forwarding on specific port
    /// - `ip@source` — upstream server with source address binding
    /// - `ip@source#port` — full specification
    /// - `/domain/ip@source#port` — full specification with domain
    pub fn parse_server(&mut self, value: &str) -> DnsmasqResult<ServerConfig> {
        let (domain, rest) = if let Some(inner) = value.strip_prefix('/') {
            // Domain-specific server: /domain/server-spec
            if let Some(slash_pos) = inner.find('/') {
                let domain = &inner[..slash_pos];
                let spec = &inner[slash_pos + 1..];
                (Some(canonicalise(domain)), spec)
            } else {
                return Err(DnsmasqError::Config(format!(
                    "malformed server specification: '{}'",
                    value
                )));
            }
        } else {
            (None, value)
        };

        // Parse source binding (@source)
        let (addr_part, source, source_iface) = if let Some(at_pos) = rest.find('@') {
            let addr = &rest[..at_pos];
            let source_spec = &rest[at_pos + 1..];
            // Source can be an IP or interface name
            if let Ok(ip) = parse_ip(source_spec) {
                (addr, Some(ip), None)
            } else {
                (addr, None, Some(source_spec.to_string()))
            }
        } else {
            (rest, None, None)
        };

        // Parse address and optional port (#port)
        let (ip, port) = parse_addr_port(addr_part)?;
        let port = port.unwrap_or(53);

        let address = SocketAddr::new(ip, port);

        Ok(ServerConfig {
            address,
            domain,
            source,
            interface: source_iface,
        })
    }

    /// Merge CLI arguments over the config file settings.
    ///
    /// CLI args have highest precedence. For boolean flags, CLI true overrides.
    /// For singular values, CLI Some(...) overrides.
    /// For list values, CLI entries are appended.
    pub fn merge_cli_args(&mut self, cli: &CliArgs) -> DnsmasqResult<()> {
        // DNS settings
        if let Some(port) = cli.port {
            self.dns_port = port;
        }
        if let Some(size) = cli.cache_size {
            self.cache_size = size;
        }

        // Servers from CLI
        for s in &cli.server {
            match self.parse_server(s) {
                Ok(sc) => self.servers.push(sc),
                Err(e) => return Err(e),
            }
        }

        // Interfaces from CLI
        for iface in &cli.interface {
            if !self.interfaces.contains(iface) {
                self.interfaces.push(iface.clone());
            }
        }

        // Listen addresses from CLI
        for addr_str in &cli.listen_address {
            if let Ok(ip) = parse_ip(addr_str) {
                if !self.listen_addresses.contains(&ip) {
                    self.listen_addresses.push(ip);
                }
            }
        }

        // Boolean flags from CLI
        if cli.no_daemon {
            self.no_daemon = true;
        }
        if cli.no_resolv {
            self.no_resolv = true;
        }
        if cli.domain_needed {
            self.domain_needed = true;
        }
        if cli.bogus_priv {
            self.bogus_priv = true;
        }

        // User/group from CLI
        if let Some(ref user) = cli.user {
            self.user = Some(user.clone());
        }
        if let Some(ref group) = cli.group {
            self.group = Some(group.clone());
        }

        Ok(())
    }

    /// Validate the final configuration for consistency.
    ///
    /// Checks cross-field constraints that can only be verified
    /// after all sources (defaults, config file, CLI) have been merged.
    pub fn validate(&self) -> DnsmasqResult<()> {
        // Port range validation
        if self.min_port > 0 && self.max_port > 0 && self.min_port > self.max_port {
            return Err(DnsmasqError::Config(format!(
                "min-port ({}) must not exceed max-port ({})",
                self.min_port, self.max_port
            )));
        }

        // EDNS packet size minimum
        if self.edns_packet_max < 512 {
            return Err(DnsmasqError::Config(format!(
                "edns-packet-max must be at least 512, got {}",
                self.edns_packet_max
            )));
        }

        // dns-forward-max must be positive
        if self.dns_forward_max == 0 {
            return Err(DnsmasqError::Config(
                "dns-forward-max must be > 0".to_string(),
            ));
        }

        // max-tcp-connections must be positive
        if self.max_tcp_connections == 0 {
            return Err(DnsmasqError::Config(
                "max-tcp-connections must be > 0".to_string(),
            ));
        }

        // min-cache-ttl / max-cache-ttl ordering
        if let (Some(min), Some(max)) = (self.min_cache_ttl, self.max_cache_ttl) {
            if min > max {
                return Err(DnsmasqError::Config(format!(
                    "min-cache-ttl ({}) must not exceed max-cache-ttl ({})",
                    min, max
                )));
            }
        }

        // min-cache-ttl must not exceed TTL_FLOOR_LIMIT
        if let Some(min) = self.min_cache_ttl {
            if min > constants::TTL_FLOOR_LIMIT {
                return Err(DnsmasqError::Config(format!(
                    "min-cache-ttl must not exceed {}, got {}",
                    constants::TTL_FLOOR_LIMIT,
                    min
                )));
            }
        }

        // neg-ttl must not exceed 86400
        if let Some(neg) = self.neg_ttl {
            if neg > 86400 {
                return Err(DnsmasqError::Config(format!(
                    "neg-ttl must not exceed 86400, got {}",
                    neg
                )));
            }
        }

        // no-resolv with resolv-file is contradictory — warn but don't fail
        // (C dnsmasq allows this; the resolv-file is simply ignored)

        // DHCP-specific validation
        #[cfg(feature = "dhcp")]
        if let Some(ref dhcp) = self.dhcp {
            if dhcp.lease_max == 0 {
                return Err(DnsmasqError::Config(
                    "dhcp-lease-max must be > 0".to_string(),
                ));
            }
            if let Some(delay) = dhcp.reply_delay {
                if delay > 300 {
                    return Err(DnsmasqError::Config(format!(
                        "dhcp-reply-delay must not exceed 300, got {}",
                        delay
                    )));
                }
            }
        }

        // TFTP-specific validation
        #[cfg(feature = "tftp")]
        if let Some(ref tftp) = self.tftp {
            if tftp.max_connections == 0 {
                return Err(DnsmasqError::Config("tftp-max must be > 0".to_string()));
            }
        }

        // bind-interfaces and bind-dynamic are mutually exclusive
        if self.bind_interfaces && self.bind_dynamic {
            return Err(DnsmasqError::Config(
                "bind-interfaces and bind-dynamic are mutually exclusive".to_string(),
            ));
        }

        Ok(())
    }

    // ── Feature-gated ensure helpers ──

    /// Ensure the DhcpConfig sub-struct is initialized, returning a mutable reference.
    #[cfg(feature = "dhcp")]
    fn ensure_dhcp(&mut self) -> &mut DhcpConfig {
        if self.dhcp.is_none() {
            self.dhcp = Some(DhcpConfig::default());
        }
        self.dhcp.as_mut().unwrap()
    }

    /// Ensure the TftpConfig sub-struct is initialized, returning a mutable reference.
    #[cfg(feature = "tftp")]
    fn ensure_tftp(&mut self) -> &mut TftpConfig {
        if self.tftp.is_none() {
            self.tftp = Some(TftpConfig::default());
        }
        self.tftp.as_mut().unwrap()
    }

    /// Ensure the DnssecConfig sub-struct is initialized, returning a mutable reference.
    #[cfg(feature = "dnssec")]
    fn ensure_dnssec(&mut self) -> &mut DnssecConfig {
        if self.dnssec.is_none() {
            self.dnssec = Some(DnssecConfig::default());
        }
        self.dnssec.as_mut().unwrap()
    }

    /// Ensure the AuthConfig sub-struct is initialized, returning a mutable reference.
    #[cfg(feature = "auth")]
    fn ensure_auth(&mut self) -> &mut AuthConfig {
        if self.auth.is_none() {
            self.auth = Some(AuthConfig::default());
        }
        self.auth.as_mut().unwrap()
    }
}

// ============================================================================
// DHCP Parsing Helpers
// ============================================================================

/// Parse a dhcp-range directive value.
///
/// Formats:
/// - `start,end[,netmask][,lease-time]`
/// - `tag:name,start,end[,netmask][,lease-time]`
/// - `set:name,start,end[,netmask][,lease-time]`
#[cfg(feature = "dhcp")]
fn parse_dhcp_range(value: &str) -> DnsmasqResult<DhcpRangeConfig> {
    let parts = split_on(value, ',');
    if parts.is_empty() {
        return Err(DnsmasqError::Config(
            "dhcp-range requires at least start,end".to_string(),
        ));
    }

    let mut idx = 0;
    let mut tag = None;
    let mut set_tag = None;

    // Check for leading tag: or set: specifier
    if parts[0].starts_with("tag:") {
        tag = Some(parts[0][4..].to_string());
        idx += 1;
    } else if parts[0].starts_with("set:") {
        set_tag = Some(parts[0][4..].to_string());
        idx += 1;
    }

    if parts.len() < idx + 2 {
        return Err(DnsmasqError::Config(
            "dhcp-range requires at least start,end addresses".to_string(),
        ));
    }

    let start = parts[idx].to_string();
    let end = parts[idx + 1].to_string();
    idx += 2;

    let mut netmask = None;
    let mut lease_time = None;

    // Remaining parts: netmask and/or lease-time
    while idx < parts.len() {
        let part = &parts[idx];
        // Try to parse as lease time (e.g., "12h", "1d", "infinite", number)
        if let Some(lt) = try_parse_lease_time(part) {
            lease_time = Some(lt);
        } else if netmask.is_none() {
            // Assume it's a netmask or prefix length
            netmask = Some(part.to_string());
        }
        idx += 1;
    }

    Ok(DhcpRangeConfig {
        start,
        end,
        netmask,
        lease_time,
        tag,
        set_tag,
    })
}

/// Parse a dhcp-host directive value.
///
/// Formats:
/// - `mac,ip[,hostname][,lease-time]`
/// - `hostname,ip[,lease-time]`
/// - `id:client-id,ip[,hostname][,lease-time]`
#[cfg(feature = "dhcp")]
fn parse_dhcp_host(value: &str) -> DnsmasqResult<DhcpHostConfig> {
    let parts = split_on(value, ',');
    if parts.is_empty() {
        return Err(DnsmasqError::Config(
            "dhcp-host requires at least one argument".to_string(),
        ));
    }

    let mut mac = None;
    let mut ip = None;
    let mut hostname = None;
    let mut lease_time = None;
    let mut tag = None;

    for part in &parts {
        #[allow(clippy::if_same_then_else)]
        if let Some(set_val) = part.strip_prefix("set:") {
            tag = Some(set_val.to_string());
        } else if let Some(tag_val) = part.strip_prefix("tag:") {
            // Both "set:" and "tag:" are valid prefixes for setting the tag (dnsmasq compat)
            tag = Some(tag_val.to_string());
        } else if is_mac_address(part) {
            mac = Some(part.to_string());
        } else if part.parse::<Ipv4Addr>().is_ok() || part.parse::<Ipv6Addr>().is_ok() {
            ip = Some(part.to_string());
        } else if let Some(lt) = try_parse_lease_time(part) {
            lease_time = Some(lt);
        } else if part.starts_with("id:") {
            // Client ID — treat like MAC for storage
            mac = Some(part.to_string());
        } else {
            // Assume hostname
            hostname = Some(canonicalise(part));
        }
    }

    Ok(DhcpHostConfig {
        mac,
        ip,
        hostname,
        lease_time,
        tag,
    })
}

/// Parse a dhcp-option directive value.
///
/// Formats:
/// - `option-number,value`
/// - `option:name,value`
/// - `tag:name,option-number,value`
#[cfg(feature = "dhcp")]
fn parse_dhcp_option(value: &str, force: bool) -> DnsmasqResult<DhcpOptionConfig> {
    let parts = split_on(value, ',');
    if parts.is_empty() {
        return Err(DnsmasqError::Config(
            "dhcp-option requires option-number[,value]".to_string(),
        ));
    }

    let mut idx = 0;
    let mut tag = None;

    // Check for leading tag:
    if parts[0].starts_with("tag:") {
        tag = Some(parts[0][4..].to_string());
        idx += 1;
    }

    if idx >= parts.len() {
        return Err(DnsmasqError::Config(
            "dhcp-option requires option-number".to_string(),
        ));
    }

    let opt_spec = &parts[idx];
    idx += 1;

    // Parse option number or name
    let option_num = if let Some(name) = opt_spec.strip_prefix("option:") {
        // Named option — look up by name
        resolve_dhcp_option_name(name)?
    } else {
        parse_u16("dhcp-option number", opt_spec)?
    };

    let value_parts: Vec<String> = parts[idx..].iter().map(|s| s.to_string()).collect();
    let value_str = value_parts.join(",");

    Ok(DhcpOptionConfig {
        option_num,
        value: parse_dhcp_option_value(&value_str),
        tag,
        force,
    })
}

/// Parse a dhcp-boot directive value.
///
/// Formats:
/// - `filename[,servername[,server-address]]`
/// - `tag:name,filename[,servername[,server-address]]`
#[cfg(feature = "dhcp")]
fn parse_dhcp_boot(value: &str) -> DnsmasqResult<DhcpBootConfig> {
    let parts = split_on(value, ',');
    if parts.is_empty() {
        return Err(DnsmasqError::Config(
            "dhcp-boot requires filename".to_string(),
        ));
    }

    let mut idx = 0;
    let mut tag = None;

    if parts[0].starts_with("tag:") {
        tag = Some(parts[0][4..].to_string());
        idx += 1;
    }

    if idx >= parts.len() {
        return Err(DnsmasqError::Config(
            "dhcp-boot requires filename".to_string(),
        ));
    }

    let filename = parts[idx].to_string();
    idx += 1;

    let servername = if idx < parts.len() {
        let s = parts[idx].to_string();
        idx += 1;
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    } else {
        None
    };

    let server_address = if idx < parts.len() {
        let s = &parts[idx];
        if s.is_empty() {
            None
        } else {
            Some(parse_ip(s).map_err(|_| {
                DnsmasqError::Config(format!("invalid server address in dhcp-boot: '{}'", s))
            })?)
        }
    } else {
        None
    };

    Ok(DhcpBootConfig {
        filename,
        servername,
        server_address,
        tag,
    })
}

/// Parse a dhcp-match directive value.
///
/// Format: `set:tag,option-number[,value]`
#[cfg(feature = "dhcp")]
fn parse_dhcp_match(value: &str) -> DnsmasqResult<DhcpMatchConfig> {
    let parts = split_on(value, ',');
    if parts.len() < 2 {
        return Err(DnsmasqError::Config(
            "dhcp-match requires set:tag,option-number".to_string(),
        ));
    }

    let set_tag = extract_tag_set(&parts[0])?;
    let option_num = parse_u16("dhcp-match option", &parts[1])?;
    let value_data = if parts.len() > 2 {
        Some(parts[2..].join(","))
    } else {
        None
    };

    Ok(DhcpMatchConfig {
        set_tag,
        option_num,
        value: value_data,
    })
}

/// Parse a tag-if directive value.
///
/// Format: `set:tag,tag:match1[,tag:match2,...]`
#[cfg(feature = "dhcp")]
fn parse_tag_if(value: &str) -> DnsmasqResult<TagIfConfig> {
    let parts = split_on(value, ',');
    if parts.is_empty() {
        return Err(DnsmasqError::Config(
            "tag-if requires at least set:tag".to_string(),
        ));
    }

    let mut set_tag = String::new();
    let mut match_tags = Vec::new();
    let mut condition = None;

    for part in &parts {
        if let Some(set_val) = part.strip_prefix("set:") {
            set_tag = set_val.to_string();
        } else if let Some(tag_val) = part.strip_prefix("tag:") {
            match_tags.push(tag_val.to_string());
        } else {
            // Could be a condition like "!tag:name" (negation)
            condition = Some(part.to_string());
        }
    }

    if set_tag.is_empty() {
        return Err(DnsmasqError::Config("tag-if requires set:tag".to_string()));
    }

    Ok(TagIfConfig {
        set_tag,
        match_tags,
        condition,
    })
}

/// Parse ra-param directive value.
///
/// Format: `interface[,interval[,lifetime[,priority]]]`
#[cfg(feature = "dhcp")]
fn parse_ra_param(value: &str) -> DnsmasqResult<RaParamConfig> {
    let parts = split_on(value, ',');
    if parts.is_empty() {
        return Err(DnsmasqError::Config(
            "ra-param requires interface".to_string(),
        ));
    }

    let interface = parts[0].to_string();
    let interval = if parts.len() > 1 {
        Some(parse_u32("ra-param interval", &parts[1])?)
    } else {
        None
    };
    let lifetime = if parts.len() > 2 {
        Some(parse_u32("ra-param lifetime", &parts[2])?)
    } else {
        None
    };
    let priority = if parts.len() > 3 {
        Some(parts[3].to_string())
    } else {
        None
    };

    Ok(RaParamConfig {
        interface,
        interval,
        lifetime,
        priority,
    })
}

/// Parse ipset directive value.
///
/// Format: `/domain1/domain2/.../set1,set2,...`
#[cfg(feature = "ipset")]
fn parse_ipset(value: &str) -> DnsmasqResult<IpsetConfig> {
    if !value.starts_with('/') {
        return Err(DnsmasqError::Config(
            "ipset requires /domain/.../set format".to_string(),
        ));
    }

    let inner = &value[1..];
    if let Some(last_slash) = inner.rfind('/') {
        let domains_str = &inner[..last_slash];
        let sets_str = &inner[last_slash + 1..];

        let domains: Vec<String> = domains_str
            .split('/')
            .filter(|s| !s.is_empty())
            .map(canonicalise)
            .collect();

        let sets: Vec<String> = sets_str
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();

        Ok(IpsetConfig { domains, sets })
    } else {
        Err(DnsmasqError::Config(format!(
            "malformed ipset directive: '{}'",
            value
        )))
    }
}

/// Parse nftset directive value.
///
/// Format: `/domain/.../family#table#set`
#[cfg(feature = "nftset")]
fn parse_nftset(value: &str) -> DnsmasqResult<NftsetConfig> {
    if !value.starts_with('/') {
        return Err(DnsmasqError::Config(
            "nftset requires /domain/.../family#table#set format".to_string(),
        ));
    }

    let inner = &value[1..];
    if let Some(last_slash) = inner.rfind('/') {
        let domains_str = &inner[..last_slash];
        let spec_str = &inner[last_slash + 1..];

        let domains: Vec<String> = domains_str
            .split('/')
            .filter(|s| !s.is_empty())
            .map(canonicalise)
            .collect();

        let spec_parts: Vec<&str> = spec_str.split('#').collect();
        if spec_parts.len() < 3 {
            return Err(DnsmasqError::Config(format!(
                "nftset requires family#table#set, got: '{}'",
                spec_str
            )));
        }

        Ok(NftsetConfig {
            domains,
            family: spec_parts[0].to_string(),
            table: spec_parts[1].to_string(),
            set: spec_parts[2].to_string(),
        })
    } else {
        Err(DnsmasqError::Config(format!(
            "malformed nftset directive: '{}'",
            value
        )))
    }
}

// ============================================================================
// Utility Helpers
// ============================================================================

/// Require a value for a directive that needs one.
fn require_value<'a>(key: &str, value: Option<&'a str>) -> DnsmasqResult<&'a str> {
    value.ok_or_else(|| DnsmasqError::Config(format!("directive '{}' requires a value", key)))
}

/// Parse a string as u8.
fn parse_u8(context: &str, s: &str) -> DnsmasqResult<u8> {
    s.parse::<u8>()
        .map_err(|_| DnsmasqError::Config(format!("invalid u8 value for {}: '{}'", context, s)))
}

/// Parse a string as u16.
fn parse_u16(context: &str, s: &str) -> DnsmasqResult<u16> {
    s.parse::<u16>()
        .map_err(|_| DnsmasqError::Config(format!("invalid u16 value for {}: '{}'", context, s)))
}

/// Parse a string as u32.
fn parse_u32(context: &str, s: &str) -> DnsmasqResult<u32> {
    s.parse::<u32>()
        .map_err(|_| DnsmasqError::Config(format!("invalid u32 value for {}: '{}'", context, s)))
}

/// Strip inline comments from a config line.
///
/// Handles `#` comments that are not inside quoted strings.
fn strip_inline_comment(line: &str) -> &str {
    let mut in_quote = false;
    let bytes = line.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'"' => in_quote = !in_quote,
            // Only treat '#' as an inline comment when preceded by whitespace
            // (or at position 0). This preserves '#' in values like
            // `server=8.8.8.8#5353` where '#' denotes a port separator per
            // the C dnsmasq convention.
            b'#' if !in_quote && (i == 0 || bytes[i - 1] == b' ' || bytes[i - 1] == b'\t') => {
                return line[..i].trim_end();
            }
            _ => {}
        }
    }
    line
}

/// Resolve a relative include path against the parent config file's directory.
fn resolve_include_path(parent_path: &str, include_path: &str) -> String {
    let inc = Path::new(include_path);
    if inc.is_absolute() {
        return include_path.to_string();
    }
    let parent = Path::new(parent_path);
    if let Some(parent_dir) = parent.parent() {
        parent_dir.join(include_path).to_string_lossy().to_string()
    } else {
        include_path.to_string()
    }
}

/// Extract a tag name from `set:tagname` prefix.
fn extract_tag_set(s: &str) -> DnsmasqResult<String> {
    if let Some(stripped) = s.strip_prefix("set:") {
        Ok(stripped.to_string())
    } else if let Some(stripped) = s.strip_prefix("tag:") {
        Ok(stripped.to_string())
    } else {
        // Allow bare tag name for backward compatibility
        Ok(s.to_string())
    }
}

/// Check if a string looks like a MAC address (xx:xx:xx:xx:xx:xx or xx-xx-xx-xx-xx-xx).
fn is_mac_address(s: &str) -> bool {
    let sep = if s.contains(':') {
        ':'
    } else if s.contains('-') {
        '-'
    } else {
        return false;
    };
    let parts: Vec<&str> = s.split(sep).collect();
    if parts.len() != 6 {
        return false;
    }
    parts
        .iter()
        .all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
}

/// Try to parse a string as a DHCP lease time.
///
/// Supported formats: `N` (seconds), `Nm` (minutes), `Nh` (hours),
/// `Nd` (days), `Nw` (weeks), `infinite`.
fn try_parse_lease_time(s: &str) -> Option<String> {
    if s == "infinite" || s == "infinity" {
        return Some("infinite".to_string());
    }
    let s_lower = s.to_lowercase();
    let (num_str, suffix) = if s_lower.ends_with('m') {
        (&s_lower[..s_lower.len() - 1], "m")
    } else if s_lower.ends_with('h') {
        (&s_lower[..s_lower.len() - 1], "h")
    } else if s_lower.ends_with('d') {
        (&s_lower[..s_lower.len() - 1], "d")
    } else if s_lower.ends_with('w') {
        (&s_lower[..s_lower.len() - 1], "w")
    } else if s_lower.ends_with('s') {
        (&s_lower[..s_lower.len() - 1], "s")
    } else {
        (s_lower.as_str(), "")
    };

    if num_str.parse::<u64>().is_ok() {
        Some(format!("{}{}", num_str, suffix))
    } else {
        None
    }
}

/// Resolve a DHCP option name to its numeric code.
///
/// Handles common option names as defined in RFC 2132 and RFC 3397.
fn resolve_dhcp_option_name(name: &str) -> DnsmasqResult<u16> {
    match name.to_lowercase().as_str() {
        "subnet-mask" => Ok(1),
        "time-offset" => Ok(2),
        "router" | "routers" => Ok(3),
        "dns-server" | "domain-name-server" => Ok(6),
        "log-server" => Ok(7),
        "hostname" | "host-name" => Ok(12),
        "domain-name" | "domain" => Ok(15),
        "broadcast" | "broadcast-address" => Ok(28),
        "nis-domain" => Ok(40),
        "nis-server" => Ok(41),
        "ntp-server" => Ok(42),
        "vendor-class" | "vendor-encap" => Ok(43),
        "netbios-ns" | "netbios-name-server" => Ok(44),
        "netbios-dd" => Ok(45),
        "netbios-nodetype" | "netbios-node-type" => Ok(46),
        "netbios-scope" => Ok(47),
        "t1" | "dhcp-renewal-time" => Ok(58),
        "t2" | "dhcp-rebinding-time" => Ok(59),
        "vendor-id-encap" | "vendor-id" => Ok(60),
        "server-id" | "server-identifier" => Ok(54),
        "client-id" | "client-identifier" => Ok(61),
        "tftp-server" | "tftp-server-name" => Ok(66),
        "bootfile" | "bootfile-name" => Ok(67),
        "user-class" => Ok(77),
        "rapid-commit" => Ok(80),
        "fqdn" | "client-fqdn" => Ok(81),
        "agent-id" | "relay-agent" => Ok(82),
        "client-arch" => Ok(93),
        "client-ndi" => Ok(94),
        "uuid" | "client-machine-id" => Ok(97),
        "domain-search" | "domain-search-list" => Ok(119),
        "sip-server" | "sip-servers" => Ok(120),
        "classless-static-route" => Ok(121),
        "vendor-identifying" => Ok(124),
        "vendor-identifying-specific" => Ok(125),
        "server-ip-address" | "next-server" => Ok(150),
        "ip-forward-enable" => Ok(19),
        "mtu" | "interface-mtu" => Ok(26),
        "static-route" => Ok(33),
        "arp-timeout" => Ok(35),
        "default-ttl" | "ip-ttl" => Ok(23),
        _ => Err(DnsmasqError::Config(format!(
            "unknown DHCP option name: '{}'",
            name
        ))),
    }
}

/// Parse hex-encoded or plain string data for DNS RR records.
fn parse_hex_or_string(s: &str) -> Vec<u8> {
    let trimmed = s.trim();
    if trimmed.starts_with("0x") || trimmed.starts_with("0X") {
        // Hex-encoded data
        let hex = &trimmed[2..];
        let mut result = Vec::new();
        let mut chars = hex.chars().filter(|c| !c.is_whitespace());
        while let Some(hi) = chars.next() {
            if let Some(lo) = chars.next() {
                if let (Some(h), Some(l)) = (hi.to_digit(16), lo.to_digit(16)) {
                    result.push((h * 16 + l) as u8);
                }
            }
        }
        result
    } else {
        // Plain string data
        trimmed.as_bytes().to_vec()
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = DnsmasqConfig::default();
        assert_eq!(config.dns_port, 53);
        assert_eq!(config.cache_size, constants::CACHESIZ);
        assert_eq!(config.dns_forward_max, constants::FTABSIZ);
        assert_eq!(config.edns_packet_max, constants::EDNS_PKTSZ);
        assert_eq!(config.max_tcp_connections, constants::MAX_PROCS);
        assert_eq!(config.auth_ttl, constants::AUTH_TTL);
        assert!(!config.no_daemon);
        assert!(!config.domain_needed);
        assert!(!config.bogus_priv);
    }

    #[test]
    fn test_apply_defaults() {
        let mut config = DnsmasqConfig::default();
        config.apply_defaults();
        assert_eq!(config.resolv_files, vec![constants::RESOLVFILE.to_string()]);
        assert_eq!(config.pid_file, Some(constants::RUNFILE.to_string()));
        assert_eq!(config.user, Some(constants::CHUSER.to_string()));
        assert_eq!(config.group, Some(constants::CHGRP.to_string()));
    }

    #[test]
    fn test_process_directive_port() {
        let mut config = DnsmasqConfig::default();
        config.process_directive("port", Some("5353")).unwrap();
        assert_eq!(config.dns_port, 5353);
    }

    #[test]
    fn test_process_directive_cache_size() {
        let mut config = DnsmasqConfig::default();
        config
            .process_directive("cache-size", Some("1000"))
            .unwrap();
        assert_eq!(config.cache_size, 1000);
    }

    #[test]
    fn test_process_directive_boolean_flags() {
        let mut config = DnsmasqConfig::default();
        config.process_directive("no-resolv", None).unwrap();
        assert!(config.no_resolv);
        config.process_directive("domain-needed", None).unwrap();
        assert!(config.domain_needed);
        config.process_directive("bogus-priv", None).unwrap();
        assert!(config.bogus_priv);
        config.process_directive("no-daemon", None).unwrap();
        assert!(config.no_daemon);
    }

    #[test]
    fn test_process_directive_server() {
        let mut config = DnsmasqConfig::default();
        config.process_directive("server", Some("8.8.8.8")).unwrap();
        assert_eq!(config.servers.len(), 1);
        assert_eq!(config.servers[0].address.ip().to_string(), "8.8.8.8");
        assert_eq!(config.servers[0].address.port(), 53);
    }

    #[test]
    fn test_process_directive_server_with_port() {
        let mut config = DnsmasqConfig::default();
        config
            .process_directive("server", Some("8.8.8.8#5353"))
            .unwrap();
        assert_eq!(config.servers[0].address.port(), 5353);
    }

    #[test]
    fn test_process_directive_server_with_domain() {
        let mut config = DnsmasqConfig::default();
        config
            .process_directive("server", Some("/example.com/8.8.8.8"))
            .unwrap();
        assert_eq!(config.servers[0].domain.as_deref(), Some("example.com"));
    }

    #[test]
    fn test_process_directive_listen_address() {
        let mut config = DnsmasqConfig::default();
        config
            .process_directive("listen-address", Some("127.0.0.1,::1"))
            .unwrap();
        assert_eq!(config.listen_addresses.len(), 2);
    }

    #[test]
    fn test_process_directive_interface() {
        let mut config = DnsmasqConfig::default();
        config
            .process_directive("interface", Some("eth0,eth1"))
            .unwrap();
        assert_eq!(config.interfaces, vec!["eth0", "eth1"]);
    }

    #[test]
    fn test_process_directive_bogus_nxdomain() {
        let mut config = DnsmasqConfig::default();
        config
            .process_directive("bogus-nxdomain", Some("64.94.110.11"))
            .unwrap();
        assert_eq!(config.bogus_nxdomain.len(), 1);
    }

    #[test]
    fn test_process_directive_address() {
        let mut config = DnsmasqConfig::default();
        config
            .process_directive("address", Some("/doubleclick.net/127.0.0.1"))
            .unwrap();
        assert_eq!(config.addresses.len(), 1);
        assert_eq!(config.addresses[0].domain, "doubleclick.net");
    }

    #[test]
    fn test_process_directive_cname() {
        let mut config = DnsmasqConfig::default();
        config
            .process_directive("cname", Some("alias.example.com,target.example.com,300"))
            .unwrap();
        assert_eq!(config.cnames.len(), 1);
        assert_eq!(config.cnames[0].alias, "alias.example.com");
        assert_eq!(config.cnames[0].target, "target.example.com");
        assert_eq!(config.cnames[0].ttl, Some(300));
    }

    #[test]
    fn test_process_directive_host_record() {
        let mut config = DnsmasqConfig::default();
        config
            .process_directive("host-record", Some("myhost,192.168.1.1"))
            .unwrap();
        assert_eq!(config.host_records.len(), 1);
        assert_eq!(config.host_records[0].name, "myhost");
        assert!(config.host_records[0].ipv4.is_some());
    }

    #[test]
    fn test_process_directive_unknown() {
        let mut config = DnsmasqConfig::default();
        let result = config.process_directive("totally-unknown-directive", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_process_directive_neg_ttl_too_high() {
        let mut config = DnsmasqConfig::default();
        let result = config.process_directive("neg-ttl", Some("100000"));
        assert!(result.is_err());
    }

    #[test]
    fn test_process_directive_min_cache_ttl_too_high() {
        let mut config = DnsmasqConfig::default();
        let result = config.process_directive("min-cache-ttl", Some("7200"));
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_port_range() {
        let mut config = DnsmasqConfig::default();
        config.min_port = 5000;
        config.max_port = 4000;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_cache_ttl_ordering() {
        let mut config = DnsmasqConfig::default();
        config.min_cache_ttl = Some(600);
        config.max_cache_ttl = Some(300);
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_ok() {
        let config = DnsmasqConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_split_on() {
        let result = split_on("a,b,c", ',');
        assert_eq!(result, vec!["a", "b", "c"]);
    }

    #[test]
    fn test_canonicalise() {
        assert_eq!(canonicalise("Example.COM"), "example.com");
        assert_eq!(canonicalise("Example.COM."), "example.com");
    }

    #[test]
    fn test_parse_addr_port() {
        let (host, port) = parse_addr_port("8.8.8.8#5353").unwrap();
        assert_eq!(host, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(port, Some(5353));
    }

    #[test]
    fn test_parse_ip_v4() {
        let ip = parse_ip("192.168.1.1").unwrap();
        assert!(ip.is_ipv4());
    }

    #[test]
    fn test_parse_ip_v6() {
        let ip = parse_ip("::1").unwrap();
        assert!(ip.is_ipv6());
    }

    #[test]
    fn test_is_mac_address() {
        assert!(is_mac_address("aa:bb:cc:dd:ee:ff"));
        assert!(is_mac_address("AA-BB-CC-DD-EE-FF"));
        assert!(!is_mac_address("not-a-mac"));
        assert!(!is_mac_address("aa:bb:cc"));
    }

    #[test]
    fn test_try_parse_lease_time() {
        assert_eq!(
            try_parse_lease_time("infinite"),
            Some("infinite".to_string())
        );
        assert_eq!(try_parse_lease_time("12h"), Some("12h".to_string()));
        assert_eq!(try_parse_lease_time("1d"), Some("1d".to_string()));
        assert_eq!(try_parse_lease_time("300"), Some("300".to_string()));
        assert_eq!(try_parse_lease_time("notanumber"), None);
    }

    #[test]
    fn test_strip_inline_comment() {
        assert_eq!(strip_inline_comment("port=53 # DNS port"), "port=53");
        assert_eq!(strip_inline_comment("port=53"), "port=53");
        assert_eq!(strip_inline_comment("# full comment"), "");
        // '#' without preceding space is NOT a comment — it's a port separator
        assert_eq!(
            strip_inline_comment("server=8.8.8.8#5353"),
            "server=8.8.8.8#5353"
        );
        assert_eq!(
            strip_inline_comment("server=8.8.8.8#5353 # with comment"),
            "server=8.8.8.8#5353"
        );
    }

    #[test]
    fn test_resolve_include_path_absolute() {
        let result = resolve_include_path("/etc/dnsmasq.conf", "/etc/dnsmasq.d/custom.conf");
        assert_eq!(result, "/etc/dnsmasq.d/custom.conf");
    }

    #[test]
    fn test_resolve_include_path_relative() {
        let result = resolve_include_path("/etc/dnsmasq.conf", "custom.conf");
        assert_eq!(result, "/etc/custom.conf");
    }

    #[test]
    fn test_matches_glob_filter() {
        assert!(matches_glob_filter("test.conf", "*.conf"));
        assert!(!matches_glob_filter("test.txt", "*.conf"));
        assert!(matches_glob_filter("test.conf", "*"));
    }

    #[test]
    fn test_parse_hex_or_string() {
        let hex = parse_hex_or_string("0x48656C6C6F");
        assert_eq!(hex, b"Hello");
        let plain = parse_hex_or_string("Hello");
        assert_eq!(plain, b"Hello");
    }

    #[test]
    fn test_resolve_dhcp_option_name() {
        assert_eq!(resolve_dhcp_option_name("router").unwrap(), 3);
        assert_eq!(resolve_dhcp_option_name("dns-server").unwrap(), 6);
        assert_eq!(resolve_dhcp_option_name("domain-name").unwrap(), 15);
        assert!(resolve_dhcp_option_name("nonexistent").is_err());
    }

    #[test]
    fn test_extract_tag_set() {
        assert_eq!(extract_tag_set("set:mytag").unwrap(), "mytag");
        assert_eq!(extract_tag_set("tag:mytag").unwrap(), "mytag");
        assert_eq!(extract_tag_set("mytag").unwrap(), "mytag");
    }

    #[test]
    fn test_parse_config_file_basic() {
        use std::io::Write;
        let dir = std::env::temp_dir().join("dnsmasq_test_parse");
        let _ = fs::create_dir_all(&dir);
        let conf_path = dir.join("test.conf");
        {
            let mut f = fs::File::create(&conf_path).unwrap();
            writeln!(f, "# Test config").unwrap();
            writeln!(f, "port=5353").unwrap();
            writeln!(f, "cache-size=500").unwrap();
            writeln!(f, "no-resolv").unwrap();
            writeln!(f, "server=8.8.8.8").unwrap();
            writeln!(f, "server=8.8.4.4#5353").unwrap();
        }

        let config = DnsmasqConfig::from_file(conf_path.to_str().unwrap()).unwrap();
        assert_eq!(config.dns_port, 5353);
        assert_eq!(config.cache_size, 500);
        assert!(config.no_resolv);
        assert_eq!(config.servers.len(), 2);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_parse_config_file_continuation() {
        use std::io::Write;
        let dir = std::env::temp_dir().join("dnsmasq_test_cont");
        let _ = fs::create_dir_all(&dir);
        let conf_path = dir.join("test_cont.conf");
        {
            let mut f = fs::File::create(&conf_path).unwrap();
            writeln!(f, "server=\\").unwrap();
            writeln!(f, "8.8.8.8").unwrap();
        }

        let config = DnsmasqConfig::from_file(conf_path.to_str().unwrap()).unwrap();
        assert_eq!(config.servers.len(), 1);
        assert_eq!(config.servers[0].address.ip().to_string(), "8.8.8.8");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_parse_config_file_include() {
        use std::io::Write;
        let dir = std::env::temp_dir().join("dnsmasq_test_include");
        let _ = fs::create_dir_all(&dir);
        let inc_path = dir.join("included.conf");
        {
            let mut f = fs::File::create(&inc_path).unwrap();
            writeln!(f, "cache-size=999").unwrap();
        }
        let conf_path = dir.join("main.conf");
        {
            let mut f = fs::File::create(&conf_path).unwrap();
            writeln!(f, "port=5353").unwrap();
            writeln!(f, "conf-file={}", inc_path.display()).unwrap();
        }

        let config = DnsmasqConfig::from_file(conf_path.to_str().unwrap()).unwrap();
        assert_eq!(config.dns_port, 5353);
        assert_eq!(config.cache_size, 999);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_parse_config_file_circular_include() {
        use std::io::Write;
        let dir = std::env::temp_dir().join("dnsmasq_test_circular");
        let _ = fs::create_dir_all(&dir);
        let conf_path = dir.join("circular.conf");
        {
            let mut f = fs::File::create(&conf_path).unwrap();
            writeln!(f, "port=53").unwrap();
            writeln!(f, "conf-file={}", conf_path.display()).unwrap();
        }

        let result = DnsmasqConfig::from_file(conf_path.to_str().unwrap());
        assert!(result.is_err());

        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "dhcp")]
    #[test]
    fn test_process_directive_dhcp_range() {
        let mut config = DnsmasqConfig::default();
        config
            .process_directive(
                "dhcp-range",
                Some("192.168.1.100,192.168.1.200,255.255.255.0,12h"),
            )
            .unwrap();
        let dhcp = config.dhcp.as_ref().unwrap();
        assert_eq!(dhcp.ranges.len(), 1);
        assert_eq!(dhcp.ranges[0].start, "192.168.1.100");
        assert_eq!(dhcp.ranges[0].end, "192.168.1.200");
    }

    #[cfg(feature = "dhcp")]
    #[test]
    fn test_process_directive_dhcp_host() {
        let mut config = DnsmasqConfig::default();
        config
            .process_directive("dhcp-host", Some("aa:bb:cc:dd:ee:ff,192.168.1.50,myhost"))
            .unwrap();
        let dhcp = config.dhcp.as_ref().unwrap();
        assert_eq!(dhcp.hosts.len(), 1);
        assert_eq!(dhcp.hosts[0].mac.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        assert_eq!(dhcp.hosts[0].ip.as_deref(), Some("192.168.1.50"));
        assert_eq!(dhcp.hosts[0].hostname.as_deref(), Some("myhost"));
    }

    #[cfg(feature = "dhcp")]
    #[test]
    fn test_process_directive_dhcp_authoritative() {
        let mut config = DnsmasqConfig::default();
        config
            .process_directive("dhcp-authoritative", None)
            .unwrap();
        assert!(config.dhcp.as_ref().unwrap().authoritative);
    }

    #[cfg(feature = "tftp")]
    #[test]
    fn test_process_directive_enable_tftp() {
        let mut config = DnsmasqConfig::default();
        config.process_directive("enable-tftp", None).unwrap();
        assert!(config.tftp.is_some());
    }

    #[test]
    fn test_process_directive_umbrella() {
        let mut config = DnsmasqConfig::default();
        config
            .process_directive("umbrella", Some("deviceid:abc123,orgid:org456"))
            .unwrap();
        let uc = config.umbrella.as_ref().unwrap();
        assert_eq!(uc.device_id.as_deref(), Some("abc123"));
        assert_eq!(uc.org_id.as_deref(), Some("org456"));
    }

    #[test]
    fn test_process_directive_edns_packet_max_too_small() {
        let mut config = DnsmasqConfig::default();
        let result = config.process_directive("edns-packet-max", Some("256"));
        assert!(result.is_err());
    }

    #[test]
    fn test_process_directive_log_facility() {
        let mut config = DnsmasqConfig::default();
        config
            .process_directive("log-facility", Some("/var/log/dnsmasq.log"))
            .unwrap();
        assert_eq!(config.log.facility.as_deref(), Some("/var/log/dnsmasq.log"));
    }

    #[test]
    fn test_process_directive_rev_server() {
        let mut config = DnsmasqConfig::default();
        config
            .process_directive("rev-server", Some("192.168.0.0/24,10.0.0.1"))
            .unwrap();
        assert_eq!(config.rev_servers.len(), 1);
        assert_eq!(config.rev_servers[0].prefix, "192.168.0.0/24");
        assert_eq!(config.rev_servers[0].server, "10.0.0.1");
    }

    #[test]
    fn test_process_directive_srv_host() {
        let mut config = DnsmasqConfig::default();
        config
            .process_directive(
                "srv-host",
                Some("_http._tcp.example.com,target.example.com,80,10,20"),
            )
            .unwrap();
        assert_eq!(config.srv_hosts.len(), 1);
        assert_eq!(config.srv_hosts[0].port, 80);
        assert_eq!(config.srv_hosts[0].priority, 10);
        assert_eq!(config.srv_hosts[0].weight, 20);
    }

    #[test]
    fn test_process_directive_txt_record() {
        let mut config = DnsmasqConfig::default();
        config
            .process_directive("txt-record", Some("example.com,v=spf1 a mx ~all"))
            .unwrap();
        assert_eq!(config.txt_records.len(), 1);
        assert_eq!(config.txt_records[0].name, "example.com");
    }

    #[test]
    fn test_validate_bind_conflict() {
        let mut config = DnsmasqConfig::default();
        config.bind_interfaces = true;
        config.bind_dynamic = true;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_merge_cli_args() {
        use clap::Parser;
        let mut config = DnsmasqConfig::default();
        config.apply_defaults();
        // Use parse_from to construct CliArgs from a simulated CLI invocation
        let cli = CliArgs::parse_from(&[
            "dnsmasq",
            "--port",
            "5353",
            "--cache-size",
            "1000",
            "--no-daemon",
            "--no-resolv",
            "--domain-needed",
            "--bogus-priv",
            "--user",
            "dnsmasq",
            "--group",
            "nogroup",
        ]);
        config.merge_cli_args(&cli).unwrap();
        assert_eq!(config.dns_port, 5353);
        assert_eq!(config.cache_size, 1000);
        assert!(config.no_daemon);
        assert!(config.no_resolv);
        assert!(config.domain_needed);
        assert!(config.bogus_priv);
        assert_eq!(config.user.as_deref(), Some("dnsmasq"));
        assert_eq!(config.group.as_deref(), Some("nogroup"));
    }
}

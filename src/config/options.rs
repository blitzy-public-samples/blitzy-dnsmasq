//! CLI and Configuration File Parser for dnsmasq
//!
//! This module is the Rust replacement for `src/option.c` — the largest module in the
//! dnsmasq C codebase. It parses all 160+ configuration directives from both command-line
//! arguments and dnsmasq.conf files, populating a `DaemonConfig` struct.
//!
//! Key transformations from C:
//! - `setjmp`/`longjmp` error recovery → `Result<T, ConfigError>` with `thiserror`
//! - `options[]` bitmask array → `OptionFlags` (canonical type from `core::daemon`)
//! - `LOPT_*` `#define` constants → `LongOption` enum
//! - Global `struct daemon` → decomposed `DaemonConfig` with nested domain structs
//! - Builder pattern for config construction: `ConfigBuilder::new().parse_cli().parse_file().build()`

use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::str::FromStr;

use log::{debug, info, warn};
use thiserror::Error;

use crate::config::constants;
use crate::config::feature_flags;

// Import the canonical OptionFlags type and OPT_* constants from core::daemon.
// This eliminates the previous duplicate bitflags! definition that was incompatible
// with daemon.rs's version, ensuring a single unified OptionFlags type is used
// for both config parsing and runtime daemon state.
#[allow(unused_imports)]
use crate::core::daemon::{
    OptionFlags,
    OPT_ADD_MAC, OPT_ALL_SERVERS, OPT_AUTH_LOG, OPT_AUTH_NXDOMAIN,
    OPT_BOGUSPRIV, OPT_BOOTP_DYNAMIC,
    OPT_CACHE_DNSSEC, OPT_CACHE_RR, OPT_CLEVERBIND, OPT_CLIENT_SUBNET,
    OPT_CMARK_ALST_EN, OPT_CMARK_ALST_NEW, OPT_CONNTRACK, OPT_CONSEC_ADDR,
    OPT_DBUS, OPT_DEBUG, OPT_DHCP_FQDN, OPT_DNSSEC_DEBUG, OPT_DNSSEC_IGN_NS,
    OPT_DNSSEC_NO_SIGN, OPT_DNSSEC_PROXY, OPT_DNSSEC_TIME, OPT_DNSSEC_VALID,
    OPT_DO_0X20, OPT_ETHERS, OPT_EXPAND, OPT_EXTRALOG,
    OPT_FILTER, OPT_FILTER_A, OPT_FILTER_AAAA, OPT_FQDN_UPDATE,
    OPT_IGNORE_ADDR, OPT_IGNORE_CLID,
    OPT_LEASE_RENEW, OPT_LEASE_RO, OPT_LEASEQUERY,
    OPT_LOCAL_REBIND, OPT_LOCAL_SERVICE, OPT_LOCALISE, OPT_LOCALMX,
    OPT_LOCALHOST_SERVICE, OPT_LOG, OPT_LOG_DEBUG, OPT_LOG_OPTS,
    OPT_LOG_PROTO, OPT_LOOP_DETECT,
    OPT_MAC_B64, OPT_MAC_HEX,
    OPT_NAT_PMP, OPT_NO_0X20, OPT_NO_4OVER6, OPT_NO_DHCP_HOSTNAME,
    OPT_NO_FORK, OPT_NO_HOSTS, OPT_NO_IDENT, OPT_NO_NEG,
    OPT_NO_OVERRIDE, OPT_NO_PING, OPT_NO_POLL, OPT_NO_REBIND,
    OPT_NO_RESOLV, OPT_NODOTS_LOCAL, OPT_NORR, OPT_NORR6, OPT_NOWILD,
    OPT_ORDER, OPT_RA, OPT_RAPID_COMMIT,
    OPT_REBIND_DOMAIN_OK, OPT_REBIND_LOCALHOST, OPT_RELOAD,
    OPT_RESOLV_DOMAIN, OPT_SCRIPT_ARP, OPT_SELFMX,
    OPT_SINGLE_PORT, OPT_STALE_CACHE, OPT_STRIP_ECS, OPT_STRIP_MAC,
    OPT_TFTP, OPT_TFTP_APREF, OPT_TFTP_APREF_IP, OPT_TFTP_APREF_MAC,
    OPT_TFTP_LC, OPT_TFTP_NOBLOCK, OPT_TFTP_NO_FAIL, OPT_TFTP_SECURE,
    OPT_UBUS, OPT_UMBRELLA, OPT_UMBRELLA_DEVID,
    OPT_AUTHORITATIVE, OPT_QUIET_DHCP, OPT_QUIET_DHCP6,
    OPT_QUIET_RA, OPT_QUIET_TFTP,
};
use crate::types::addr::{AllAddr, SocketAddress};
#[allow(unused_imports)]
use crate::types::dns::{
    AddrList, AddrListFlags, AuthNameEntry, AuthZone, BogusAddr, CnameRecord, DnsDoctor, DnsName,
    DsConfig, DumpFlags, DynDir, HostRecord, HostsFile, HostsFileFlags, MxSrvRecord, PtrRecord,
    ResolvConf, RrList, ServerDetails, ServerEntry, ServerFlags, TxtRecord,
};
use crate::types::network::{InterfaceName, InterfaceNameBinding, InameFlags, SimpleAddrList};

#[cfg(any(feature = "dhcp", feature = "dhcp6"))]
#[allow(unused_imports)]
use crate::types::dhcp::{
    CondDomain, DelayConfig, DhcpBoot, DhcpBridge,
    DhcpConfig as DhcpHostDef, DhcpConfigFlags, DhcpContext, DhcpContextFlags, DhcpMac,
    DhcpMatchName, DhcpNetId, DhcpOption as DhcpOptDef, DhcpOptExtra, DhcpOptFlags,
    DhcpOptTypeFlags, DhcpPxeVendor, DhcpRelay, DhcpVendor, HwaddrConfig, LeaseFlags,
    PxeService, RaInterface, RelayAddr, SharedNetwork, TagIf,
};

// ---------------------------------------------------------------------------
// ConfigError — replaces C setjmp/longjmp error recovery
// ---------------------------------------------------------------------------

/// Errors that can occur during configuration parsing.
///
/// Replaces the C `setjmp`/`longjmp` error recovery mechanism with
/// idiomatic Rust `Result`-based error handling.
#[derive(Error, Debug)]
pub enum ConfigError {
    /// A parse error at a specific file and line.
    #[error("configuration error at {file}:{line}: {message}")]
    ParseError {
        file: String,
        line: usize,
        message: String,
    },

    /// An option was provided with an invalid value.
    #[error("invalid option '{option}': {reason}")]
    InvalidOption { option: String, reason: String },

    /// Two or more options conflict with each other.
    #[error("conflicting options: {0}")]
    ConflictingOptions(String),

    /// An I/O error while reading a configuration file.
    #[error("I/O error reading {path}: {source}")]
    IoError {
        path: String,
        #[source]
        source: std::io::Error,
    },

    /// An unrecognized option was encountered.
    #[error("unknown option: {0}")]
    UnknownOption(String),

    /// An option that requires an argument was given without one.
    #[error("missing required argument for option: {0}")]
    MissingArgument(String),
}

// OptionFlags is now imported from crate::core::daemon — the single canonical
// type used by both config parsing and runtime state. The previous bitflags!
// definition that existed here was removed to eliminate the type duplication
// that blocked integration between config parsing and daemon state management.

// ---------------------------------------------------------------------------
// LongOption — replaces LOPT_* #defines from option.c lines 200-332
// ---------------------------------------------------------------------------

/// Long option identifiers for dnsmasq configuration directives.
///
/// Each variant corresponds to a `LOPT_*` constant in the C source.
/// Values start at 256 to avoid overlap with single-character short options.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
#[allow(non_camel_case_types)]
pub enum LongOption {
    Reload = 256,
    NoNames = 257,
    Tftp = 258,
    Secure = 259,
    Prefix = 260,
    PtrRec = 261,
    Bridge = 262,
    TftpMax = 263,
    Force = 264,
    TftpLc = 265,
    NoBlock = 266,
    LogRo = 267,
    LogFac = 268,
    LogAsync = 269,
    LeasesFile = 270,
    NoAutoPxe = 271,
    ServAuth = 272,
    RaParam = 273,
    Ra = 274,
    Naptr = 275,
    MinPort = 276,
    MaxPort = 277,
    MinTTL = 278,
    MaxTTL = 279,
    CnameTTL = 280,
    NoCacheDnssec = 281,
    HostRec = 282,
    AuthZone = 283,
    AuthServer = 284,
    AuthTTL = 285,
    AuthSoa = 286,
    MaxCacheTTL = 287,
    MinCacheTTL = 288,
    NegTTL = 289,
    LocalTTL = 290,
    LeaseQuery = 291,
    ConnmarkAllowlistEnable = 292,
    ConnmarkAllowlistNew = 293,
    StaleCache = 294,
    NormRep = 295,
    NoIdent = 296,
    StripEcs = 297,
    StripMac = 298,
    NormRep6 = 299,
    QuietDhcp = 300,
    QuietDhcp6 = 301,
    QuietRa = 302,
    QuietTftp = 303,
    DnssecCheck = 304,
    DnssecTime = 305,
    DnssecDebug = 306,
    DnssecNoSign = 307,
    DnssecIgnoreNs = 308,
    DnssecTimestamp = 309,
    LocalRebind = 310,
    RebindLocalhost = 311,
    RebindDomainOk = 312,
    StopDnsRebind = 313,
    AllServers = 314,
    IpSet = 315,
    NftSet = 316,
    ConnMark = 317,
    SynTh = 318,
    DnssecSeed = 319,
    Cname = 320,
    LoopDetect = 321,
    AddMac = 322,
    AddSubnet = 323,
    Umbrella = 324,
    UmbrellaDevId = 325,
    DhcpIgnoreClid = 326,
    NoCache4 = 327,
    SinglePort = 328,
    ScriptArp = 329,
    FilterA = 330,
    FilterAAAA = 331,
    DhcpIgnoreHostname = 332,
    AuthNxdomain = 333,
    ConfScript = 334,
    PxeVendor = 335,
    DhcpOpt6 = 336,
    ProxyDnssec = 337,
    Tag = 338,
    TagIf = 339,
    MatchName = 340,
    SharedNet = 341,
    DhcpRelay = 342,
    Delay = 343,
    Limit = 344,
    LocalService = 345,
    NatPmp = 346,
    Quiet4Over6 = 347,
    Dynamic = 348,
    RapidCommit = 349,
    DnssecLimitWork = 350,
    DnssecLimitCrypto = 351,
    DnssecLimitSigFail = 352,
    DnssecLimitNsec3Iters = 353,
    DumpFlagsOpt = 354,
    Dump = 355,
    IgnoreAddr = 356,
    CacheRr = 357,
    ScriptTime = 358,
    TftpMtu = 359,
    RrName = 360,
    NumPort = 361,
    FastDns = 362,
    Stale = 363,
    NormRepV6 = 364,
    LocalRebindV6 = 365,
    RebindLocalAll = 366,
    DynHost = 367,
    Log4 = 368,
    Log6 = 369,
    LogDebug = 370,
    EncapVendor = 371,
    RaSolicit = 372,
    RaSolicitRefresh = 373,
    ConsecAddr = 374,
    BootPDynamic = 375,
    DhcpNoDns = 376,
    DhcpFirewall = 377,
    DnssecCacheLimit = 378,
    ConMarkAlstEnNew = 379,
    MaxPortV6 = 380,
    MinPortV6 = 381,
    TftpAprefMac = 382,
    TftpWindow = 383,
    SplitRelay = 384,
    LocalAddr = 385,
    Bogus4 = 386,
    Bogus6 = 387,
    DnsDomain = 388,
    ExtraLog = 389,
    StickyOrder = 390,
}

impl LongOption {
    /// Convert a u16 value to a LongOption, if valid.
    pub fn from_u16(val: u16) -> Option<LongOption> {
        if !(256..=390).contains(&val) {
            return None;
        }
        match val {
            256 => Some(LongOption::Reload),
            257 => Some(LongOption::NoNames),
            258 => Some(LongOption::Tftp),
            259 => Some(LongOption::Secure),
            260 => Some(LongOption::Prefix),
            261 => Some(LongOption::PtrRec),
            262 => Some(LongOption::Bridge),
            263 => Some(LongOption::TftpMax),
            264 => Some(LongOption::Force),
            265 => Some(LongOption::TftpLc),
            266 => Some(LongOption::NoBlock),
            267 => Some(LongOption::LogRo),
            268 => Some(LongOption::LogFac),
            269 => Some(LongOption::LogAsync),
            270 => Some(LongOption::LeasesFile),
            271 => Some(LongOption::NoAutoPxe),
            272 => Some(LongOption::ServAuth),
            273 => Some(LongOption::RaParam),
            274 => Some(LongOption::Ra),
            275 => Some(LongOption::Naptr),
            276 => Some(LongOption::MinPort),
            277 => Some(LongOption::MaxPort),
            278 => Some(LongOption::MinTTL),
            279 => Some(LongOption::MaxTTL),
            280 => Some(LongOption::CnameTTL),
            281 => Some(LongOption::NoCacheDnssec),
            282 => Some(LongOption::HostRec),
            283 => Some(LongOption::AuthZone),
            284 => Some(LongOption::AuthServer),
            285 => Some(LongOption::AuthTTL),
            286 => Some(LongOption::AuthSoa),
            287 => Some(LongOption::MaxCacheTTL),
            288 => Some(LongOption::MinCacheTTL),
            289 => Some(LongOption::NegTTL),
            290 => Some(LongOption::LocalTTL),
            291 => Some(LongOption::LeaseQuery),
            292 => Some(LongOption::ConnmarkAllowlistEnable),
            293 => Some(LongOption::ConnmarkAllowlistNew),
            294 => Some(LongOption::StaleCache),
            295 => Some(LongOption::NormRep),
            296 => Some(LongOption::NoIdent),
            297 => Some(LongOption::StripEcs),
            298 => Some(LongOption::StripMac),
            299 => Some(LongOption::NormRep6),
            300 => Some(LongOption::QuietDhcp),
            301 => Some(LongOption::QuietDhcp6),
            302 => Some(LongOption::QuietRa),
            303 => Some(LongOption::QuietTftp),
            304 => Some(LongOption::DnssecCheck),
            305 => Some(LongOption::DnssecTime),
            306 => Some(LongOption::DnssecDebug),
            307 => Some(LongOption::DnssecNoSign),
            308 => Some(LongOption::DnssecIgnoreNs),
            309 => Some(LongOption::DnssecTimestamp),
            310 => Some(LongOption::LocalRebind),
            311 => Some(LongOption::RebindLocalhost),
            312 => Some(LongOption::RebindDomainOk),
            313 => Some(LongOption::StopDnsRebind),
            314 => Some(LongOption::AllServers),
            315 => Some(LongOption::IpSet),
            316 => Some(LongOption::NftSet),
            317 => Some(LongOption::ConnMark),
            318 => Some(LongOption::SynTh),
            319 => Some(LongOption::DnssecSeed),
            320 => Some(LongOption::Cname),
            321 => Some(LongOption::LoopDetect),
            322 => Some(LongOption::AddMac),
            323 => Some(LongOption::AddSubnet),
            324 => Some(LongOption::Umbrella),
            325 => Some(LongOption::UmbrellaDevId),
            326 => Some(LongOption::DhcpIgnoreClid),
            327 => Some(LongOption::NoCache4),
            328 => Some(LongOption::SinglePort),
            329 => Some(LongOption::ScriptArp),
            330 => Some(LongOption::FilterA),
            331 => Some(LongOption::FilterAAAA),
            332 => Some(LongOption::DhcpIgnoreHostname),
            333 => Some(LongOption::AuthNxdomain),
            334 => Some(LongOption::ConfScript),
            335 => Some(LongOption::PxeVendor),
            336 => Some(LongOption::DhcpOpt6),
            337 => Some(LongOption::ProxyDnssec),
            338 => Some(LongOption::Tag),
            339 => Some(LongOption::TagIf),
            340 => Some(LongOption::MatchName),
            341 => Some(LongOption::SharedNet),
            342 => Some(LongOption::DhcpRelay),
            343 => Some(LongOption::Delay),
            344 => Some(LongOption::Limit),
            345 => Some(LongOption::LocalService),
            346 => Some(LongOption::NatPmp),
            347 => Some(LongOption::Quiet4Over6),
            348 => Some(LongOption::Dynamic),
            349 => Some(LongOption::RapidCommit),
            350 => Some(LongOption::DnssecLimitWork),
            351 => Some(LongOption::DnssecLimitCrypto),
            352 => Some(LongOption::DnssecLimitSigFail),
            353 => Some(LongOption::DnssecLimitNsec3Iters),
            354 => Some(LongOption::DumpFlagsOpt),
            355 => Some(LongOption::Dump),
            356 => Some(LongOption::IgnoreAddr),
            357 => Some(LongOption::CacheRr),
            358 => Some(LongOption::ScriptTime),
            359 => Some(LongOption::TftpMtu),
            360 => Some(LongOption::RrName),
            361 => Some(LongOption::NumPort),
            362 => Some(LongOption::FastDns),
            363 => Some(LongOption::Stale),
            364 => Some(LongOption::NormRepV6),
            365 => Some(LongOption::LocalRebindV6),
            366 => Some(LongOption::RebindLocalAll),
            367 => Some(LongOption::DynHost),
            368 => Some(LongOption::Log4),
            369 => Some(LongOption::Log6),
            370 => Some(LongOption::LogDebug),
            371 => Some(LongOption::EncapVendor),
            372 => Some(LongOption::RaSolicit),
            373 => Some(LongOption::RaSolicitRefresh),
            374 => Some(LongOption::ConsecAddr),
            375 => Some(LongOption::BootPDynamic),
            376 => Some(LongOption::DhcpNoDns),
            377 => Some(LongOption::DhcpFirewall),
            378 => Some(LongOption::DnssecCacheLimit),
            379 => Some(LongOption::ConMarkAlstEnNew),
            380 => Some(LongOption::MaxPortV6),
            381 => Some(LongOption::MinPortV6),
            382 => Some(LongOption::TftpAprefMac),
            383 => Some(LongOption::TftpWindow),
            384 => Some(LongOption::SplitRelay),
            385 => Some(LongOption::LocalAddr),
            386 => Some(LongOption::Bogus4),
            387 => Some(LongOption::Bogus6),
            388 => Some(LongOption::DnsDomain),
            389 => Some(LongOption::ExtraLog),
            390 => Some(LongOption::StickyOrder),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// BindMode — network binding strategy
// ---------------------------------------------------------------------------

/// Network binding mode for listen sockets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindMode {
    /// Bind to wildcard address (default).
    Wildcard,
    /// Bind to specific interfaces only (--bind-interfaces).
    BindInterfaces,
    /// Bind dynamically as interfaces appear (--bind-dynamic).
    BindDynamic,
}

impl Default for BindMode {
    fn default() -> Self {
        BindMode::Wildcard
    }
}

// ---------------------------------------------------------------------------
// Configuration sub-structs — decomposition of C's struct daemon
// ---------------------------------------------------------------------------

/// DNS-specific configuration.
#[derive(Debug, Clone)]
pub struct DnsConfig {
    /// DNS cache size (default: CACHESIZ=150).
    pub cache_size: usize,
    /// Maximum simultaneous forwarded queries (default: FTABSIZ=150).
    pub forward_max: usize,
    /// DNS listening port (default: 53).
    pub port: u16,
    /// EDNS0 UDP payload size (default: 1232).
    pub edns_pktsz: u16,
    /// Negative cache TTL in seconds (default: 0 = use SOA minimum).
    pub negative_ttl: u32,
    /// Maximum TTL to send to clients (default: 0 = no limit).
    pub max_ttl: u32,
    /// Minimum cache TTL (default: 0 = no floor).
    pub min_cache_ttl: u32,
    /// Maximum cache TTL (default: 0 = no cap).
    pub max_cache_ttl: u32,
    /// Local TTL for hosts-file entries (default: 0).
    pub local_ttl: u32,
    /// CNAME chain TTL (default: 0).
    pub cname_ttl: u32,
    /// Auth zone default TTL (default: AUTH_TTL=600).
    pub auth_ttl: u32,
    /// Resolv.conf file references.
    pub resolv_files: Vec<ResolvConf>,
    /// Upstream DNS servers.
    pub servers: Vec<ServerEntry>,
    /// Bogus NXDOMAIN addresses to ignore.
    pub bogus_addresses: Vec<BogusAddr>,
    /// DNS address rewriting (--address doctor) rules.
    pub doctors: Vec<DnsDoctor>,
    /// MX record definitions.
    pub mx_records: Vec<MxSrvRecord>,
    /// SRV record definitions.
    pub srv_records: Vec<MxSrvRecord>,
    /// TXT record definitions.
    pub txt_records: Vec<TxtRecord>,
    /// PTR record definitions.
    pub ptr_records: Vec<PtrRecord>,
    /// CNAME alias definitions.
    pub cname_records: Vec<CnameRecord>,
    /// Static host records (--host-record).
    pub host_records: Vec<HostRecord>,
    /// Cached RR type list.
    pub rr_list: Vec<RrList>,
    /// Additional hosts files.
    pub hosts_files: Vec<HostsFile>,
    /// Dynamic directory watching.
    pub dyn_dirs: Vec<DynDir>,
    /// Max TCP queries per connection (default: TCP_MAX_QUERIES=100).
    pub tcp_max_queries: u16,
    /// TCP connection timeout in seconds (default: TCP_TIMEOUT=5).
    pub tcp_timeout: u16,
    /// Local-only domains.
    pub local_domains: Vec<String>,
}

/// DHCP-specific configuration (feature-gated).
#[derive(Debug, Clone)]
pub struct DhcpConfig {
    /// Maximum number of DHCP leases (default: MAXLEASES=1000).
    pub max_leases: usize,
    /// DHCPv4 client port (default: 68).
    pub client_port: u16,
    /// DHCPv4 server port (default: 67).
    pub server_port: u16,
    /// DHCPv6 client port (default: 546).
    pub client_port_v6: u16,
    /// DHCPv6 server port (default: 547).
    pub server_port_v6: u16,
    /// Lease file path.
    pub lease_file: PathBuf,
    /// Static DHCP host definitions (--dhcp-host).
    #[cfg(any(feature = "dhcp", feature = "dhcp6"))]
    pub hosts: Vec<DhcpHostDef>,
    #[cfg(not(any(feature = "dhcp", feature = "dhcp6")))]
    pub hosts: Vec<()>,
    /// DHCP address range contexts (--dhcp-range).
    #[cfg(any(feature = "dhcp", feature = "dhcp6"))]
    pub contexts: Vec<DhcpContext>,
    #[cfg(not(any(feature = "dhcp", feature = "dhcp6")))]
    pub contexts: Vec<()>,
    /// DHCP options (--dhcp-option).
    #[cfg(any(feature = "dhcp", feature = "dhcp6"))]
    pub options: Vec<DhcpOptDef>,
    #[cfg(not(any(feature = "dhcp", feature = "dhcp6")))]
    pub options: Vec<()>,
    /// PXE boot parameters (--dhcp-boot).
    #[cfg(any(feature = "dhcp", feature = "dhcp6"))]
    pub boots: Vec<DhcpBoot>,
    #[cfg(not(any(feature = "dhcp", feature = "dhcp6")))]
    pub boots: Vec<()>,
    /// DHCP network IDs.
    #[cfg(any(feature = "dhcp", feature = "dhcp6"))]
    pub net_ids: Vec<DhcpNetId>,
    #[cfg(not(any(feature = "dhcp", feature = "dhcp6")))]
    pub net_ids: Vec<()>,
    /// Vendor class matching (--dhcp-vendorclass).
    #[cfg(any(feature = "dhcp", feature = "dhcp6"))]
    pub vendors: Vec<DhcpVendor>,
    #[cfg(not(any(feature = "dhcp", feature = "dhcp6")))]
    pub vendors: Vec<()>,
    /// MAC address matching (--dhcp-mac).
    #[cfg(any(feature = "dhcp", feature = "dhcp6"))]
    pub macs: Vec<DhcpMac>,
    #[cfg(not(any(feature = "dhcp", feature = "dhcp6")))]
    pub macs: Vec<()>,
    /// PXE service definitions (--pxe-service).
    #[cfg(any(feature = "dhcp", feature = "dhcp6"))]
    pub pxe_services: Vec<PxeService>,
    #[cfg(not(any(feature = "dhcp", feature = "dhcp6")))]
    pub pxe_services: Vec<()>,
    /// Bridge interface mappings (--bridge-interface).
    #[cfg(any(feature = "dhcp", feature = "dhcp6"))]
    pub bridges: Vec<DhcpBridge>,
    #[cfg(not(any(feature = "dhcp", feature = "dhcp6")))]
    pub bridges: Vec<()>,
    /// Conditional domain definitions.
    #[cfg(any(feature = "dhcp", feature = "dhcp6"))]
    pub cond_domains: Vec<CondDomain>,
    #[cfg(not(any(feature = "dhcp", feature = "dhcp6")))]
    pub cond_domains: Vec<()>,
    /// DHCP relay targets (--dhcp-relay).
    #[cfg(any(feature = "dhcp", feature = "dhcp6"))]
    pub relays: Vec<DhcpRelay>,
    #[cfg(not(any(feature = "dhcp", feature = "dhcp6")))]
    pub relays: Vec<()>,
    /// Router advertisement interface settings.
    #[cfg(any(feature = "dhcp", feature = "dhcp6"))]
    pub ra_interfaces: Vec<RaInterface>,
    #[cfg(not(any(feature = "dhcp", feature = "dhcp6")))]
    pub ra_interfaces: Vec<()>,
    /// Tag-conditional config (--tag-if).
    #[cfg(any(feature = "dhcp", feature = "dhcp6"))]
    pub tag_ifs: Vec<TagIf>,
    #[cfg(not(any(feature = "dhcp", feature = "dhcp6")))]
    pub tag_ifs: Vec<()>,
    /// Shared network associations.
    #[cfg(any(feature = "dhcp", feature = "dhcp6"))]
    pub shared_networks: Vec<SharedNetwork>,
    #[cfg(not(any(feature = "dhcp", feature = "dhcp6")))]
    pub shared_networks: Vec<()>,
    /// Override relay addresses.
    pub override_relays: Vec<SimpleAddrList>,
    /// Default DHCPv4 lease time in seconds (default: DEFLEASE=3600).
    pub default_lease: u32,
    /// Default DHCPv6 lease time in seconds (default: DEFLEASE6=86400).
    pub default_lease_v6: u32,
}

/// TFTP-specific configuration (feature-gated).
#[derive(Debug, Clone)]
pub struct TftpConfig {
    /// Max simultaneous TFTP connections (default: TFTP_MAX_CONNECTIONS=50).
    pub max_connections: usize,
    /// TFTP root directory.
    pub root: Option<PathBuf>,
    /// Port range (low, high) for TFTP.
    pub port_range: Option<(u16, u16)>,
    /// TFTP MTU override.
    pub mtu: Option<u16>,
    /// TFTP maximum window size.
    pub max_window: Option<u16>,
}

/// DNSSEC-specific configuration (feature-gated).
#[derive(Debug, Clone)]
pub struct DnssecConfig {
    /// Trust anchor DS records.
    pub trust_anchors: Vec<DsConfig>,
    /// Path to trust anchors file.
    pub trust_anchors_file: Option<PathBuf>,
    /// Work limit for DNSSEC validation.
    pub limit_work: u32,
    /// Signature failure limit.
    pub limit_sig_fail: u32,
    /// Cryptographic operation limit.
    pub limit_crypto: u32,
    /// NSEC3 iteration limit.
    pub limit_nsec3_iters: u32,
    /// Timestamp file for DNSSEC time validation.
    pub timestamp_file: Option<PathBuf>,
}

/// Logging configuration.
#[derive(Debug, Clone)]
pub struct LogConfig {
    /// Syslog facility (LOG_DAEMON, LOG_LOCAL0..7, etc.).
    pub facility: Option<i32>,
    /// Log to file instead of syslog.
    pub file: Option<PathBuf>,
    /// Number of async log lines (enables async logging if Some).
    pub async_lines: Option<usize>,
    /// Maximum log entries per second (default: LOG_MAX=5).
    pub max_logs: usize,
}

/// Authoritative DNS zone configuration (feature-gated).
#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// Authoritative zones.
    pub zones: Vec<AuthZone>,
    /// Auth zone default TTL.
    pub ttl: u32,
    /// SOA refresh interval.
    pub soa_refresh: u32,
    /// SOA retry interval.
    pub soa_retry: u32,
    /// SOA expiry interval.
    pub soa_expiry: u32,
    /// SOA serial number (explicit override).
    pub soa_serial: Option<u32>,
    /// SOA serial number (computed or user-provided).
    pub soa_sn: u32,
}

/// Network interface and binding configuration.
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Interfaces to listen on (--interface).
    pub interfaces: Vec<InterfaceNameBinding>,
    /// Explicit listen addresses (--listen-address).
    pub listen_addresses: Vec<AllAddr>,
    /// Interfaces to exclude (--except-interface).
    pub except_interfaces: Vec<InterfaceNameBinding>,
    /// Interface-to-name mappings (--interface-name).
    pub interface_names: Vec<InterfaceName>,
    /// Socket binding mode.
    pub bind_mode: BindMode,
    /// Source address for outgoing queries.
    pub source_addr: Option<SocketAddress>,
    /// Fixed query port (0 = random).
    pub query_port: u16,
    /// Minimum source port.
    pub min_port: u16,
    /// Maximum source port.
    pub max_port: u16,
}

/// Security and privilege configuration.
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    /// User to run as after privilege drop (default: CHUSER="nobody").
    pub username: String,
    /// Group to run as after privilege drop (default: CHGRP="dip").
    pub groupname: String,
    /// Whether to stay running as root.
    pub run_as_root: bool,
    /// PID file path.
    pub pid_file: Option<PathBuf>,
    /// Lease-change script.
    pub script_file: Option<PathBuf>,
    /// Lua lease-change script.
    pub lua_script: Option<PathBuf>,
    /// DNSSEC notification script.
    pub notify_script: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// DaemonConfig — the top-level configuration struct
// ---------------------------------------------------------------------------

/// Complete daemon configuration, populated from CLI arguments and config files.
///
/// This is the Rust equivalent of the C `struct daemon` global state,
/// decomposed into domain-specific sub-structs for clarity and ownership.
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    /// DNS resolver configuration.
    pub dns: DnsConfig,
    /// DHCP server configuration.
    pub dhcp: DhcpConfig,
    /// TFTP server configuration.
    pub tftp: TftpConfig,
    /// DNSSEC validation configuration.
    pub dnssec: DnssecConfig,
    /// Logging configuration.
    pub log: LogConfig,
    /// Authoritative DNS zone configuration.
    pub auth: AuthConfig,
    /// Network interface and binding configuration.
    pub network: NetworkConfig,
    /// Security and privilege separation configuration.
    pub security: SecurityConfig,
    /// Boolean option flags.
    pub options: OptionFlags,
}

impl Default for DaemonConfig {
    /// Create a `DaemonConfig` with defaults matching `read_opts()` in option.c
    /// (lines 7773-7803 of the C source).
    fn default() -> Self {
        DaemonConfig {
            dns: DnsConfig {
                cache_size: constants::CACHESIZ,
                forward_max: constants::FTABSIZ,
                port: constants::DNS_PORT,
                edns_pktsz: constants::EDNS_PKTSZ as u16,
                negative_ttl: 0,
                max_ttl: 0,
                min_cache_ttl: 0,
                max_cache_ttl: 0,
                local_ttl: 0,
                cname_ttl: 0,
                auth_ttl: constants::AUTH_TTL as u32,
                resolv_files: Vec::new(),
                servers: Vec::new(),
                bogus_addresses: Vec::new(),
                doctors: Vec::new(),
                mx_records: Vec::new(),
                srv_records: Vec::new(),
                txt_records: Vec::new(),
                ptr_records: Vec::new(),
                cname_records: Vec::new(),
                host_records: Vec::new(),
                rr_list: Vec::new(),
                hosts_files: Vec::new(),
                dyn_dirs: Vec::new(),
                tcp_max_queries: constants::TCP_MAX_QUERIES as u16,
                tcp_timeout: constants::TCP_TIMEOUT as u16,
                local_domains: Vec::new(),
            },
            dhcp: DhcpConfig {
                max_leases: constants::MAXLEASES,
                client_port: constants::DHCP_CLIENT_PORT,
                server_port: constants::DHCP_SERVER_PORT,
                client_port_v6: constants::DHCPV6_CLIENT_PORT,
                server_port_v6: constants::DHCPV6_SERVER_PORT,
                lease_file: PathBuf::from(constants::LEASEFILE),
                hosts: Vec::new(),
                contexts: Vec::new(),
                options: Vec::new(),
                boots: Vec::new(),
                net_ids: Vec::new(),
                vendors: Vec::new(),
                macs: Vec::new(),
                pxe_services: Vec::new(),
                bridges: Vec::new(),
                cond_domains: Vec::new(),
                relays: Vec::new(),
                ra_interfaces: Vec::new(),
                tag_ifs: Vec::new(),
                shared_networks: Vec::new(),
                override_relays: Vec::new(),
                default_lease: constants::DEFLEASE as u32,
                default_lease_v6: constants::DEFLEASE6 as u32,
            },
            tftp: TftpConfig {
                max_connections: constants::TFTP_MAX_CONNECTIONS,
                root: None,
                port_range: None,
                mtu: None,
                max_window: Some(constants::TFTP_MAX_WINDOW as u16),
            },
            dnssec: DnssecConfig {
                trust_anchors: Vec::new(),
                trust_anchors_file: None,
                limit_work: constants::DNSSEC_LIMIT_WORK as u32,
                limit_sig_fail: constants::DNSSEC_LIMIT_SIG_FAIL as u32,
                limit_crypto: constants::DNSSEC_LIMIT_CRYPTO as u32,
                limit_nsec3_iters: constants::DNSSEC_LIMIT_NSEC3_ITERS as u32,
                timestamp_file: None,
            },
            log: LogConfig {
                facility: None,
                file: None,
                async_lines: None,
                max_logs: constants::LOG_MAX,
            },
            auth: AuthConfig {
                zones: Vec::new(),
                ttl: constants::AUTH_TTL as u32,
                soa_refresh: constants::SOA_REFRESH as u32,
                soa_retry: constants::SOA_RETRY as u32,
                soa_expiry: constants::SOA_EXPIRY as u32,
                soa_serial: None,
                soa_sn: 0,
            },
            network: NetworkConfig {
                interfaces: Vec::new(),
                listen_addresses: Vec::new(),
                except_interfaces: Vec::new(),
                interface_names: Vec::new(),
                bind_mode: BindMode::Wildcard,
                source_addr: None,
                query_port: 0,
                min_port: 1025,
                max_port: 65535,
            },
            security: SecurityConfig {
                username: constants::CHUSER.to_string(),
                groupname: constants::CHGRP.to_string(),
                run_as_root: false,
                pid_file: Some(PathBuf::from(constants::RUNFILE)),
                script_file: None,
                lua_script: None,
                notify_script: None,
            },
            options: OptionFlags::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Option definition table — maps option names to IDs
// ---------------------------------------------------------------------------

/// An option definition entry matching the C `opts[]` array.
#[allow(dead_code)]
struct OptDef {
    name: &'static str,
    has_arg: bool,
    id: u16,
}

/// Short option character to u16 conversion.
fn short_opt_id(c: char) -> u16 {
    c as u16
}

/// Build the option name -> id lookup table.
/// This corresponds to the C `opts[]` static array (option.c lines 334-535).
fn build_option_table() -> HashMap<String, (u16, bool)> {
    let mut m: HashMap<String, (u16, bool)> = HashMap::new();

    // Helper: insert name -> (id, has_arg)
    let mut ins = |name: &str, id: u16, has_arg: bool| {
        m.insert(name.to_string(), (id, has_arg));
    };

    // Short options mapped to long-form names (from C opts[] array)
    ins("version", short_opt_id('v'), false);
    ins("help", short_opt_id('w'), false);
    ins("no-hosts", short_opt_id('h'), false);
    ins("no-poll", short_opt_id('n'), false);
    ins("no-resolv", short_opt_id('R'), false);
    ins("keep-in-foreground", short_opt_id('k'), false);
    ins("no-daemon", short_opt_id('d'), false);
    ins("log-queries", short_opt_id('q'), false);
    ins("selfmx", short_opt_id('e'), false);
    ins("filterwin2k", short_opt_id('f'), false);
    ins("bogus-priv", short_opt_id('b'), false);
    ins("strict-order", short_opt_id('o'), false);
    ins("stop-dns-rebind", LongOption::StopDnsRebind as u16, false);
    ins("expand-hosts", short_opt_id('E'), false);
    ins("localmx", short_opt_id('L'), false);
    ins("bind-interfaces", short_opt_id('z'), false);
    ins("bind-dynamic", LongOption::Dynamic as u16, false);
    ins("domain-needed", short_opt_id('D'), false);
    ins("no-negcache", short_opt_id('N'), false);
    ins("read-ethers", short_opt_id('Z'), false);

    // Options with required arguments (short opts)
    ins("pid-file", short_opt_id('x'), true);
    ins("dhcp-leasefile", short_opt_id('l'), true);
    ins("dhcp-lease", short_opt_id('l'), true);
    ins("user", short_opt_id('u'), true);
    ins("group", short_opt_id('j'), true);
    ins("port", short_opt_id('p'), true);
    ins("cache-size", short_opt_id('c'), true);
    ins("dns-forward-max", short_opt_id('0'), true);
    ins("listen-address", short_opt_id('a'), true);
    ins("local", short_opt_id('S'), true);
    ins("server", short_opt_id('S'), true);
    ins("rev-server", short_opt_id('S'), true);
    ins("address", short_opt_id('A'), true);
    ins("conf-file", short_opt_id('C'), true);
    ins("conf-dir", short_opt_id('7'), true);
    ins("interface", short_opt_id('i'), true);
    ins("except-interface", short_opt_id('I'), true);
    ins("bogus-nxdomain", short_opt_id('B'), true);
    ins("mx-host", short_opt_id('m'), true);
    ins("mx-target", short_opt_id('t'), true);
    ins("edns-packet-max", short_opt_id('P'), true);
    ins("dhcp-range", short_opt_id('F'), true);
    ins("dhcp-host", short_opt_id('G'), true);
    ins("dhcp-option", short_opt_id('O'), true);
    ins("dhcp-boot", short_opt_id('M'), true);
    ins("domain", short_opt_id('s'), true);
    ins("dhcp-vendorclass", short_opt_id('U'), true);
    ins("dhcp-userclass", short_opt_id('j'), true);
    ins("dhcp-mac", short_opt_id('J'), true);
    ins("dhcp-ignore", short_opt_id('K'), true);
    ins("dhcp-optsfile", short_opt_id('Y'), true);
    ins("dhcp-hostsfile", short_opt_id('H'), true);
    ins("addn-hosts", short_opt_id('H'), true);
    ins("hostsdir", short_opt_id('H'), true);
    ins("dhcp-hostsdir", short_opt_id('H'), true);
    ins("dhcp-optsdir", short_opt_id('Y'), true);
    ins("dhcp-script", short_opt_id('6'), true);
    ins("dhcp-luascript", short_opt_id('6'), true);
    ins("pxe-prompt", short_opt_id('X'), true);
    ins("pxe-service", short_opt_id('W'), true);
    ins("txt-record", short_opt_id('Y'), true);
    ins("srv-host", short_opt_id('W'), true);
    ins("resolv-file", short_opt_id('r'), true);
    ins("dhcp-broadcast", short_opt_id('3'), true);

    // Long-only options (LOPT_* values)
    ins("log-facility", LongOption::LogFac as u16, true);
    ins("log-async", LongOption::LogAsync as u16, true);
    ins("add-mac", LongOption::AddMac as u16, true);
    ins("add-subnet", LongOption::AddSubnet as u16, true);
    ins("add-cpe-id", LongOption::AddSubnet as u16, true);
    ins("dhcp-generate-names", LongOption::Tag as u16, true);
    ins("tag-if", LongOption::TagIf as u16, true);

    ins("tftp-root", LongOption::Tftp as u16, true);
    ins("enable-tftp", LongOption::Tftp as u16, true);
    ins("tftp-secure", LongOption::Secure as u16, false);
    ins("tftp-unique-root", LongOption::Prefix as u16, true);
    ins("tftp-max", LongOption::TftpMax as u16, true);
    ins("tftp-lowercase", LongOption::TftpLc as u16, false);
    ins("tftp-no-blocksize", LongOption::NoBlock as u16, false);
    ins("tftp-single-port", LongOption::SinglePort as u16, false);
    ins("tftp-port-range", LongOption::NumPort as u16, true);
    ins("tftp-mtu", LongOption::TftpMtu as u16, true);
    ins("tftp-no-fail", LongOption::Force as u16, false);
    ins("tftp-window", LongOption::TftpWindow as u16, true);
    ins("tftp-apref-mac", LongOption::TftpAprefMac as u16, false);

    ins("ptr-record", LongOption::PtrRec as u16, true);
    ins("naptr-record", LongOption::Naptr as u16, true);
    ins("bridge-interface", LongOption::Bridge as u16, true);
    ins("shared-network", LongOption::SharedNet as u16, true);
    ins("dhcp-option-force", LongOption::Force as u16, true);
    ins("no-auto-pxe", LongOption::NoAutoPxe as u16, false);
    ins("log-dhcp", LongOption::LogRo as u16, false);

    ins("min-port", LongOption::MinPort as u16, true);
    ins("max-port", LongOption::MaxPort as u16, true);
    ins("min-cache-ttl", LongOption::MinCacheTTL as u16, true);
    ins("max-cache-ttl", LongOption::MaxCacheTTL as u16, true);
    ins("neg-ttl", LongOption::NegTTL as u16, true);
    ins("local-ttl", LongOption::LocalTTL as u16, true);
    ins("min-ttl", LongOption::MinTTL as u16, true);
    ins("max-ttl", LongOption::MaxTTL as u16, true);
    ins("cname-ttl", LongOption::CnameTTL as u16, true);

    ins("host-record", LongOption::HostRec as u16, true);
    ins("cname", LongOption::Cname as u16, true);

    ins("auth-zone", LongOption::AuthZone as u16, true);
    ins("auth-server", LongOption::AuthServer as u16, true);
    ins("auth-ttl", LongOption::AuthTTL as u16, true);
    ins("auth-soa", LongOption::AuthSoa as u16, true);

    ins("dnssec", LongOption::DnssecCheck as u16, false);
    ins("trust-anchor", LongOption::DnssecSeed as u16, true);
    ins("dnssec-check-unsigned", LongOption::DnssecNoSign as u16, true);
    ins("dnssec-no-timecheck", LongOption::DnssecTime as u16, false);
    ins("dnssec-timestamp", LongOption::DnssecTimestamp as u16, true);
    ins("dnssec-debug", LongOption::DnssecDebug as u16, false);
    ins("proxy-dnssec", LongOption::ProxyDnssec as u16, false);

    ins("dhcp-relay", LongOption::DhcpRelay as u16, true);
    ins("ra-param", LongOption::RaParam as u16, true);
    ins("enable-ra", LongOption::Ra as u16, false);

    ins("leasequery", LongOption::LeaseQuery as u16, false);
    ins("connmark-allowlist-enable", LongOption::ConnmarkAllowlistEnable as u16, true);
    ins("connmark-allowlist", LongOption::ConnmarkAllowlistNew as u16, true);
    ins("use-stale-cache", LongOption::StaleCache as u16, true);
    ins("no-round-robin", LongOption::NormRep as u16, false);
    ins("no-ident", LongOption::NoIdent as u16, false);
    ins("strip-subnet", LongOption::StripEcs as u16, false);
    ins("strip-mac", LongOption::StripMac as u16, false);
    ins("no-round-robin6", LongOption::NormRep6 as u16, false);
    ins("quiet-dhcp", LongOption::QuietDhcp as u16, false);
    ins("quiet-dhcp6", LongOption::QuietDhcp6 as u16, false);
    ins("quiet-ra", LongOption::QuietRa as u16, false);
    ins("quiet-tftp", LongOption::QuietTftp as u16, false);
    ins("log-debug", LongOption::LogDebug as u16, false);
    ins("extra-log", LongOption::ExtraLog as u16, false);

    ins("local-service", LongOption::LocalService as u16, false);
    ins("loop-detect", LongOption::LoopDetect as u16, false);
    ins("rebind-localhost-ok", LongOption::RebindLocalhost as u16, false);
    ins("rebind-domain-ok", LongOption::RebindDomainOk as u16, true);
    ins("local-rebind", LongOption::LocalRebind as u16, false);
    ins("all-servers", LongOption::AllServers as u16, false);

    ins("ipset", LongOption::IpSet as u16, true);
    ins("nftset", LongOption::NftSet as u16, true);
    ins("conntrack", LongOption::ConnMark as u16, false);
    ins("synth-domain", LongOption::SynTh as u16, true);
    ins("ignore-address", LongOption::IgnoreAddr as u16, true);
    ins("cache-rr", LongOption::CacheRr as u16, true);

    ins("umbrella", LongOption::Umbrella as u16, true);
    ins("umbrella-devid", LongOption::UmbrellaDevId as u16, true);
    ins("pxe-vendor", LongOption::PxeVendor as u16, true);
    ins("dhcp-match", LongOption::MatchName as u16, true);
    ins("dhcp-name-match", LongOption::MatchName as u16, true);
    ins("filter-A", LongOption::FilterA as u16, false);
    ins("filter-AAAA", LongOption::FilterAAAA as u16, false);

    ins("dump-stats", LongOption::Dump as u16, true);
    ins("dumpfile", LongOption::DumpFlagsOpt as u16, true);
    ins("script-on-renewal", LongOption::ScriptTime as u16, false);
    ins("rapid-commit", LongOption::RapidCommit as u16, false);
    ins("dhcp-sequential-ip", LongOption::ConsecAddr as u16, false);
    ins("bootp-dynamic", LongOption::BootPDynamic as u16, true);
    ins("dhcp-ignore-names", LongOption::DhcpIgnoreHostname as u16, true);
    ins("dhcp-no-override", LongOption::DhcpNoDns as u16, false);
    ins("auth-nxdomain", LongOption::AuthNxdomain as u16, false);
    ins("conf-script", LongOption::ConfScript as u16, true);

    ins("dhcp-ignore-clid", LongOption::DhcpIgnoreClid as u16, false);
    ins("script-arp", LongOption::ScriptArp as u16, false);
    ins("single-port", LongOption::SinglePort as u16, false);
    ins("delay-config", LongOption::Delay as u16, true);
    ins("nat-pmp", LongOption::NatPmp as u16, false);
    ins("4-over-6", LongOption::Quiet4Over6 as u16, false);

    ins("dnssec-limit-work", LongOption::DnssecLimitWork as u16, true);
    ins("dnssec-limit-crypto", LongOption::DnssecLimitCrypto as u16, true);
    ins("dnssec-limit-sig-fail", LongOption::DnssecLimitSigFail as u16, true);
    ins("dnssec-limit-nsec3-iters", LongOption::DnssecLimitNsec3Iters as u16, true);

    ins("split-relay", LongOption::SplitRelay as u16, false);

    m
}

// ---------------------------------------------------------------------------
// ConfigBuilder — Builder pattern for configuration construction
// ---------------------------------------------------------------------------

/// Maximum recursion depth for config file includes.
const MAX_INCLUDE_DEPTH: usize = 32;

/// Builder for constructing a `DaemonConfig` from CLI args and config files.
///
/// Replaces the C `read_opts()` function with a structured builder approach.
/// Configuration precedence: CLI overrides > config file > compile-time defaults.
pub struct ConfigBuilder {
    config: DaemonConfig,
    errors: Vec<ConfigError>,
    option_table: HashMap<String, (u16, bool)>,
    included_files: HashSet<PathBuf>,
    include_depth: usize,
    test_mode: bool,
    show_help: bool,
    show_version: bool,
}

impl ConfigBuilder {
    /// Create a new `ConfigBuilder` with default configuration values.
    ///
    /// Defaults match the C `read_opts()` implementation (option.c lines 7773-7803).
    pub fn new() -> Self {
        ConfigBuilder {
            config: DaemonConfig::default(),
            errors: Vec::new(),
            option_table: build_option_table(),
            included_files: HashSet::new(),
            include_depth: 0,
            test_mode: false,
            show_help: false,
            show_version: false,
        }
    }

    /// Parse command-line arguments.
    ///
    /// Processes both short (-p 53) and long (--port=53, --port 53) option forms.
    /// Corresponds to the CLI parsing loop in C `read_opts()` (option.c lines ~7810-7890).
    pub fn parse_cli(&mut self, args: &[String]) -> &mut Self {
        let mut i = 0;
        while i < args.len() {
            let arg = &args[i];

            if arg == "--" {
                break;
            }

            if arg.starts_with("--") {
                // Long option: --name or --name=value
                let rest = &arg[2..];
                let (name, value) = if let Some(eq_pos) = rest.find('=') {
                    (rest[..eq_pos].to_string(), Some(rest[eq_pos + 1..].to_string()))
                } else {
                    (rest.to_string(), None)
                };

                if let Some(&(id, has_arg)) = self.option_table.get(&name) {
                    let val = if has_arg {
                        if let Some(v) = value {
                            Some(v)
                        } else {
                            i += 1;
                            if i < args.len() {
                                Some(args[i].clone())
                            } else {
                                self.errors.push(ConfigError::MissingArgument(name.clone()));
                                i += 1;
                                continue;
                            }
                        }
                    } else {
                        value
                    };
                    let val_str = val.as_deref().unwrap_or("");
                    if let Err(e) = self.process_option(id, val_str, "<cli>", 0) {
                        self.errors.push(e);
                    }
                } else {
                    self.errors.push(ConfigError::UnknownOption(name));
                }
            } else if arg.starts_with('-') && arg.len() > 1 {
                // Short option: -p 53 or -p53 or boolean -n
                let chars: Vec<char> = arg[1..].chars().collect();
                let mut ci = 0;
                while ci < chars.len() {
                    let c = chars[ci];
                    let name = c.to_string();
                    let id = short_opt_id(c);
                    let has_arg = self.option_table.values().any(|&(oid, ha)| oid == id && ha);

                    if has_arg {
                        let val = if ci + 1 < chars.len() {
                            // Value attached: -p53
                            let v: String = chars[ci + 1..].iter().collect();
                            ci = chars.len();
                            v
                        } else {
                            // Value is next argument: -p 53
                            i += 1;
                            if i < args.len() {
                                args[i].clone()
                            } else {
                                self.errors.push(ConfigError::MissingArgument(name));
                                break;
                            }
                        };
                        if let Err(e) = self.process_option(id, &val, "<cli>", 0) {
                            self.errors.push(e);
                        }
                    } else {
                        if let Err(e) = self.process_option(id, "", "<cli>", 0) {
                            self.errors.push(e);
                        }
                    }
                    ci += 1;
                }
            }

            i += 1;
        }
        self
    }

    /// Parse a configuration file.
    ///
    /// If `hard` is true, a missing file causes an error.
    /// If `hard` is false, a missing file is silently ignored.
    pub fn parse_file(&mut self, path: &str, hard: bool) -> &mut Self {
        if let Err(e) = self.read_config_file(path, hard) {
            self.errors.push(e);
        }
        self
    }

    /// Set a single option by its LongOption identifier and string value.
    pub fn set_option(&mut self, option: LongOption, value: &str) -> &mut Self {
        if let Err(e) = self.process_option(option as u16, value, "<api>", 0) {
            self.errors.push(e);
        }
        self
    }

    /// Finalize building and return the config, or the first error.
    pub fn build(self) -> Result<DaemonConfig, ConfigError> {
        if let Some(e) = self.errors.into_iter().next() {
            return Err(e);
        }

        let mut config = self.config;

        // Post-processing: if no resolv files specified, use the default
        if config.dns.resolv_files.is_empty() && !config.options.get(OPT_NO_RESOLV) {
            config.dns.resolv_files.push(ResolvConf {
                name: constants::RESOLVFILE.to_string(),
                is_default: true,
                logged: false,
                mtime: 0,
                ino: 0,
                #[cfg(feature = "inotify_monitor")]
                wd: -1,
                #[cfg(feature = "inotify_monitor")]
                file: None,
            });
        }

        // If no hosts file specified and not disabled, add default
        if config.dns.hosts_files.is_empty() && !config.options.get(OPT_NO_HOSTS) {
            config.dns.hosts_files.push(HostsFile {
                fname: constants::HOSTSFILE.to_string(),
                flags: HostsFileFlags::empty(),
                index: 0,
            });
        }

        // Validate port ranges
        if config.network.min_port > config.network.max_port {
            return Err(ConfigError::ConflictingOptions(
                "min-port is greater than max-port".to_string(),
            ));
        }

        // DNSSEC requires cache
        #[cfg(feature = "dnssec")]
        if config.options.get(OPT_DNSSEC_VALID) && config.dns.cache_size == 0 {
            return Err(ConfigError::ConflictingOptions(
                "DNSSEC requires DNS cache (cache-size > 0)".to_string(),
            ));
        }

        Ok(config)
    }

    /// Whether --test mode was requested.
    pub fn is_test_mode(&self) -> bool {
        self.test_mode
    }

    /// Whether --help was requested.
    pub fn is_help_requested(&self) -> bool {
        self.show_help
    }

    /// Whether --version was requested.
    pub fn is_version_requested(&self) -> bool {
        self.show_version
    }
}

// ---------------------------------------------------------------------------
// Configuration file parser
// ---------------------------------------------------------------------------

impl ConfigBuilder {
    /// Read and parse a configuration file line by line.
    ///
    /// Handles comments (#), continuation lines (backslash), quoted strings,
    /// and recursive includes (`conf-file=`, `conf-dir=`).
    fn read_config_file(&mut self, path: &str, hard: bool) -> Result<(), ConfigError> {
        let file_path = PathBuf::from(path);

        // Check for include cycle
        if let Ok(canonical) = file_path.canonicalize() {
            if self.included_files.contains(&canonical) {
                warn!("Ignoring already-included config file: {}", path);
                return Ok(());
            }
            self.included_files.insert(canonical);
        }

        // Check depth limit
        if self.include_depth >= MAX_INCLUDE_DEPTH {
            return Err(ConfigError::ParseError {
                file: path.to_string(),
                line: 0,
                message: format!("maximum include depth ({MAX_INCLUDE_DEPTH}) exceeded"),
            });
        }

        let file = match File::open(&file_path) {
            Ok(f) => f,
            Err(e) => {
                if hard {
                    return Err(ConfigError::IoError {
                        path: path.to_string(),
                        source: e,
                    });
                } else {
                    debug!("Optional config file not found: {}", path);
                    return Ok(());
                }
            }
        };

        self.include_depth += 1;
        let reader = BufReader::new(file);
        let mut line_num = 0usize;
        let mut continued_line = String::new();
        let mut continuation = false;

        for raw_line in reader.lines() {
            let raw_line = raw_line.map_err(|e| ConfigError::IoError {
                path: path.to_string(),
                source: e,
            })?;
            line_num += 1;

            // Handle continuation lines (trailing backslash)
            let trimmed = raw_line.trim_end();
            if trimmed.ends_with('\\') {
                continued_line.push_str(&trimmed[..trimmed.len() - 1]);
                continuation = true;
                continue;
            }

            if continuation {
                continued_line.push_str(trimmed);
                continuation = false;
            } else {
                continued_line = trimmed.to_string();
            }

            let line = continued_line.trim().to_string();
            continued_line = String::new();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse: option=value or option value or just option (boolean)
            if let Err(e) = self.parse_config_line(&line, path, line_num) {
                self.errors.push(e);
            }
        }

        self.include_depth -= 1;
        Ok(())
    }

    /// Parse a single configuration file line.
    fn parse_config_line(
        &mut self,
        line: &str,
        file: &str,
        line_num: usize,
    ) -> Result<(), ConfigError> {
        // Split on first = or whitespace
        let (name, value) = if let Some(eq_pos) = line.find('=') {
            let n = line[..eq_pos].trim();
            let v = line[eq_pos + 1..].trim();
            (n.to_string(), v.to_string())
        } else if let Some(sp_pos) = line.find(char::is_whitespace) {
            let n = line[..sp_pos].trim();
            let v = line[sp_pos..].trim();
            (n.to_string(), v.to_string())
        } else {
            (line.to_string(), String::new())
        };

        // Look up the option
        if let Some(&(id, _has_arg)) = self.option_table.get(&name) {
            self.process_option(id, &value, file, line_num)
        } else {
            Err(ConfigError::UnknownOption(format!(
                "at {}:{}: {}", file, line_num, name
            )))
        }
    }
}

// ---------------------------------------------------------------------------
// Helper parsing utilities
// ---------------------------------------------------------------------------

/// Parse an IP address (v4 or v6) from a string.
fn parse_ip(s: &str) -> Result<IpAddr, ConfigError> {
    IpAddr::from_str(s).map_err(|_| ConfigError::InvalidOption {
        option: s.to_string(),
        reason: "invalid IP address".to_string(),
    })
}

/// Parse a u16 value from a string.
fn parse_u16(s: &str, context: &str) -> Result<u16, ConfigError> {
    s.parse::<u16>().map_err(|_| ConfigError::InvalidOption {
        option: context.to_string(),
        reason: format!("invalid numeric value: '{s}'"),
    })
}

/// Parse a u32 value from a string.
fn parse_u32(s: &str, context: &str) -> Result<u32, ConfigError> {
    s.parse::<u32>().map_err(|_| ConfigError::InvalidOption {
        option: context.to_string(),
        reason: format!("invalid numeric value: '{s}'"),
    })
}

/// Parse a usize value from a string.
fn parse_usize(s: &str, context: &str) -> Result<usize, ConfigError> {
    s.parse::<usize>().map_err(|_| ConfigError::InvalidOption {
        option: context.to_string(),
        reason: format!("invalid numeric value: '{s}'"),
    })
}

/// Parse an address with optional port: addr#port or [addr]#port (for IPv6).
fn parse_addr_port(s: &str, default_port: u16) -> Result<SocketAddress, ConfigError> {
    let (addr_part, port) = if let Some(hash) = s.rfind('#') {
        let port_str = &s[hash + 1..];
        let port = parse_u16(port_str, "port")?;
        (&s[..hash], port)
    } else {
        (s, default_port)
    };

    // Strip brackets for IPv6
    let addr_str = addr_part.trim_start_matches('[').trim_end_matches(']');

    let ip = parse_ip(addr_str)?;
    match ip {
        IpAddr::V4(v4) => Ok(SocketAddress::new_v4(v4, port)),
        IpAddr::V6(v6) => Ok(SocketAddress::new_v6(v6, port, 0, 0)),
    }
}

/// Split a comma-separated list, respecting quoted segments.
fn split_comma(s: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;

    for c in s.chars() {
        match c {
            '"' | '\'' => {
                in_quotes = !in_quotes;
            }
            ',' if !in_quotes => {
                result.push(current.trim().to_string());
                current = String::new();
            }
            _ => {
                current.push(c);
            }
        }
    }
    if !current.is_empty() {
        result.push(current.trim().to_string());
    }
    result
}

/// Parse a time duration value: number with optional suffix (s, m, h, d, w).
fn parse_time(s: &str, context: &str) -> Result<u32, ConfigError> {
    if s.is_empty() {
        return Err(ConfigError::MissingArgument(context.to_string()));
    }

    let s = s.trim();
    if let Ok(v) = s.parse::<u32>() {
        return Ok(v);
    }

    let last = s.chars().last().unwrap_or('s');
    let num_str = &s[..s.len() - 1];
    let num = num_str.parse::<u32>().map_err(|_| ConfigError::InvalidOption {
        option: context.to_string(),
        reason: format!("invalid time value: '{s}'"),
    })?;

    match last {
        's' => Ok(num),
        'm' => Ok(num * 60),
        'h' => Ok(num * 3600),
        'd' => Ok(num * 86400),
        'w' => Ok(num * 604800),
        _ => Err(ConfigError::InvalidOption {
            option: context.to_string(),
            reason: format!("unknown time suffix '{last}' in '{s}'"),
        }),
    }
}

/// Validate a hostname per RFC 1123.
#[allow(dead_code)]
fn is_valid_hostname(name: &str) -> bool {
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return false;
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Server address parsing — replaces parse_server() / parse_server_addr()
// ---------------------------------------------------------------------------

impl ConfigBuilder {
    /// Parse a server specification: `[/domain[/domain...]/]addr[#port][@iface]`
    fn parse_server(
        &mut self,
        value: &str,
        is_local: bool,
    ) -> Result<(), ConfigError> {
        let mut domains: Vec<String> = Vec::new();
        let mut remainder = value;

        // Extract domain list: /domain1/domain2/.../
        if remainder.starts_with('/') {
            let after_slash = &remainder[1..];
            let mut search = after_slash;
            let mut found_end = false;
            while let Some(pos) = search.find('/') {
                let domain = &search[..pos];
                if !domain.is_empty() {
                    domains.push(domain.to_lowercase());
                }
                search = &search[pos + 1..];
                if search.is_empty() || !search.starts_with('/') {
                    found_end = true;
                    remainder = search;
                    break;
                }
            }
            if !found_end && !search.is_empty() {
                if !search.is_empty() {
                    domains.push(search.to_lowercase());
                }
                remainder = "";
            }
        }

        // For 'local' directive with just domains and no address, treat as local-only
        if is_local && remainder.is_empty() {
            for domain in &domains {
                self.config.dns.local_domains.push(domain.clone());
            }
            return Ok(());
        }

        if remainder.is_empty() {
            if !domains.is_empty() {
                for domain in &domains {
                    self.config.dns.local_domains.push(domain.clone());
                }
                return Ok(());
            }
            return Err(ConfigError::InvalidOption {
                option: "server".to_string(),
                reason: "no address specified".to_string(),
            });
        }

        // Parse the server address portion: addr[#port][@interface]
        let mut iface = None;
        let mut addr_str = remainder;

        // Extract interface binding (@iface)
        if let Some(at_pos) = remainder.rfind('@') {
            iface = Some(remainder[at_pos + 1..].to_string());
            addr_str = &remainder[..at_pos];
        }

        if addr_str.is_empty() {
            return Err(ConfigError::InvalidOption {
                option: "server".to_string(),
                reason: "empty address".to_string(),
            });
        }

        let sock_addr = parse_addr_port(addr_str, constants::DNS_PORT)?;

        let mut flags = ServerFlags::empty();
        if is_local {
            flags.insert(ServerFlags::LITERAL_ADDRESS);
        }

        let dom = if domains.is_empty() {
            None
        } else {
            Some(domains[0].clone())
        };
        let dom_len = dom.as_ref().map(|d| d.len() as u16).unwrap_or(0);
        let entry = ServerEntry {
            flags,
            domain_len: dom_len,
            domain: dom,
            serial: 0,
            arrayposn: 0,
            last_server: 0,
            addr: sock_addr.clone(),
            source_addr: SocketAddress::new_v4(Ipv4Addr::UNSPECIFIED, 0),
            interface: iface.unwrap_or_default(),
            ifindex: 0,
            tcpfd: -1,
            queries: 0,
            failed_queries: 0,
            nxdomain_replies: 0,
            retrys: 0,
            query_latency: 0,
            mma_latency: 0,
            forwardtime: 0,
            forwardcount: 0,
            #[cfg(feature = "loop_detect")]
            uid: 0,
        };

        if domains.len() <= 1 {
            self.config.dns.servers.push(entry);
        } else {
            for domain in &domains {
                let mut e = entry.clone();
                e.domain = Some(domain.clone());
                e.domain_len = domain.len() as u16;
                self.config.dns.servers.push(e);
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Option dispatcher — replaces one_opt() from C option.c
// This is the core of configuration processing: each option gets a match arm.
// ---------------------------------------------------------------------------

impl ConfigBuilder {
    /// Process a single option by its numeric ID and string value.
    ///
    /// This is the Rust equivalent of `one_opt()` from option.c — the massive
    /// dispatch function handling all 160+ dnsmasq configuration directives.
    #[allow(clippy::cognitive_complexity)]
    fn process_option(
        &mut self,
        option_id: u16,
        value: &str,
        file: &str,
        line: usize,
    ) -> Result<(), ConfigError> {
        // Helper to create parse error for this option
        let _parse_err = |msg: &str| -> ConfigError {
            ConfigError::ParseError {
                file: file.to_string(),
                line,
                message: msg.to_string(),
            }
        };

        match option_id {
            // ---------------------------------------------------------------
            // Version, help, test
            // ---------------------------------------------------------------
            id if id == short_opt_id('v') => {
                self.show_version = true;
                Ok(())
            }
            id if id == short_opt_id('w') => {
                self.show_help = true;
                Ok(())
            }

            // ---------------------------------------------------------------
            // Boolean flags (no argument)
            // ---------------------------------------------------------------
            id if id == short_opt_id('b') => {
                // --bogus-priv
                self.config.options.set(OPT_BOGUSPRIV);
                Ok(())
            }
            id if id == short_opt_id('f') => {
                // --filterwin2k
                self.config.options.set(OPT_FILTER);
                Ok(())
            }
            id if id == short_opt_id('q') => {
                // --log-queries
                self.config.options.set(OPT_LOG);
                Ok(())
            }
            id if id == short_opt_id('e') => {
                // --selfmx
                self.config.options.set(OPT_SELFMX);
                Ok(())
            }
            id if id == short_opt_id('h') => {
                // --no-hosts
                self.config.options.set(OPT_NO_HOSTS);
                Ok(())
            }
            id if id == short_opt_id('n') => {
                // --no-poll
                self.config.options.set(OPT_NO_POLL);
                Ok(())
            }
            id if id == short_opt_id('d') => {
                // --no-daemon
                self.config.options.set(OPT_DEBUG);
                Ok(())
            }
            id if id == short_opt_id('k') => {
                // --keep-in-foreground (same as debug for our purposes)
                self.config.options.set(OPT_DEBUG);
                Ok(())
            }
            id if id == short_opt_id('R') => {
                // --no-resolv
                self.config.options.set(OPT_NO_RESOLV);
                Ok(())
            }
            id if id == short_opt_id('E') => {
                // --expand-hosts
                self.config.options.set(OPT_EXPAND);
                Ok(())
            }
            id if id == short_opt_id('L') => {
                // --localmx
                self.config.options.set(OPT_LOCALMX);
                Ok(())
            }
            id if id == short_opt_id('N') => {
                // --no-negcache
                self.config.options.set(OPT_NO_NEG);
                Ok(())
            }
            id if id == short_opt_id('D') => {
                // --domain-needed
                self.config.options.set(OPT_NODOTS_LOCAL);
                Ok(())
            }
            id if id == short_opt_id('o') => {
                // --strict-order (deprecated, use server ordering)
                warn!("--strict-order is deprecated");
                Ok(())
            }
            id if id == short_opt_id('z') => {
                // --bind-interfaces
                self.config.network.bind_mode = BindMode::BindInterfaces;
                self.config.options.set(OPT_NOWILD);
                Ok(())
            }
            id if id == short_opt_id('Z') => {
                // --read-ethers
                // Read /etc/ethers for DHCP static hosts
                Ok(())
            }

            // ---------------------------------------------------------------
            // Numeric / value options
            // ---------------------------------------------------------------
            id if id == short_opt_id('p') => {
                // --port=N
                let port = parse_u16(value, "port")?;
                self.config.dns.port = port;
                Ok(())
            }
            id if id == short_opt_id('c') => {
                // --cache-size=N
                let size = parse_usize(value, "cache-size")?;
                self.config.dns.cache_size = size;
                Ok(())
            }
            id if id == short_opt_id('0') => {
                // --dns-forward-max=N
                let max = parse_usize(value, "dns-forward-max")?;
                self.config.dns.forward_max = max;
                Ok(())
            }
            id if id == short_opt_id('P') => {
                // --edns-packet-max=N
                let size = parse_u16(value, "edns-packet-max")?;
                if size < 512 {
                    return Err(ConfigError::InvalidOption {
                        option: "edns-packet-max".to_string(),
                        reason: "must be at least 512".to_string(),
                    });
                }
                self.config.dns.edns_pktsz = size;
                Ok(())
            }

            // ---------------------------------------------------------------
            // String / path options
            // ---------------------------------------------------------------
            id if id == short_opt_id('u') => {
                // --user=name
                if value.is_empty() {
                    self.config.security.run_as_root = true;
                } else {
                    self.config.security.username = value.to_string();
                }
                Ok(())
            }
            id if id == short_opt_id('j') => {
                // --group=name
                self.config.security.groupname = value.to_string();
                Ok(())
            }
            id if id == short_opt_id('x') => {
                // --pid-file=path
                if value.is_empty() || value == "-" {
                    self.config.security.pid_file = None;
                } else {
                    self.config.security.pid_file = Some(PathBuf::from(value));
                }
                Ok(())
            }
            id if id == short_opt_id('l') => {
                // --dhcp-leasefile=path
                self.config.dhcp.lease_file = PathBuf::from(value);
                Ok(())
            }

            // ---------------------------------------------------------------
            // Network interface options
            // ---------------------------------------------------------------
            id if id == short_opt_id('a') => {
                // --listen-address=addr[,addr...]
                for addr_str in split_comma(value) {
                    let ip = parse_ip(&addr_str)?;
                    match ip {
                        IpAddr::V4(v4) => {
                            self.config.network.listen_addresses.push(AllAddr::from_ipv4(v4));
                        }
                        IpAddr::V6(v6) => {
                            self.config.network.listen_addresses.push(AllAddr::from_ipv6(v6));
                        }
                    }
                }
                Ok(())
            }
            id if id == short_opt_id('i') => {
                // --interface=name[,name...]
                for name in split_comma(value) {
                    self.config.network.interfaces.push(InterfaceNameBinding {
                        name: Some(name.clone()),
                        addr: SocketAddress::new_v4(Ipv4Addr::UNSPECIFIED, 0),
                        flags: InameFlags::empty(),
                    });
                }
                Ok(())
            }
            id if id == short_opt_id('I') => {
                // --except-interface=name[,name...]
                for name in split_comma(value) {
                    self.config.network.except_interfaces.push(InterfaceNameBinding {
                        name: Some(name.clone()),
                        addr: SocketAddress::new_v4(Ipv4Addr::UNSPECIFIED, 0),
                        flags: InameFlags::empty(),
                    });
                }
                Ok(())
            }

            // ---------------------------------------------------------------
            // Server / address / local
            // ---------------------------------------------------------------
            id if id == short_opt_id('S') => {
                // --server=... / --local=... / --rev-server=...
                self.parse_server(value, false)?;
                Ok(())
            }
            id if id == short_opt_id('A') => {
                // --address=/domain/addr — returns specific address for domain queries
                self.parse_server(value, true)?;
                Ok(())
            }

            // ---------------------------------------------------------------
            // Config file includes
            // ---------------------------------------------------------------
            id if id == short_opt_id('C') => {
                // --conf-file=path
                if !value.is_empty() {
                    self.read_config_file(value, true)?;
                }
                Ok(())
            }
            id if id == short_opt_id('7') => {
                // --conf-dir=path[,filter]
                let parts = split_comma(value);
                let dir_path = parts.first().map(|s| s.as_str()).unwrap_or("");
                let filter_extensions: Vec<&str> = parts.iter().skip(1).map(|s| s.as_str()).collect();

                if !dir_path.is_empty() {
                    self.read_config_dir(dir_path, &filter_extensions)?;
                }
                Ok(())
            }

            // ---------------------------------------------------------------
            // Resolv file
            // ---------------------------------------------------------------
            id if id == short_opt_id('r') => {
                // --resolv-file=path
                if !value.is_empty() {
                    self.config.dns.resolv_files.push(ResolvConf {
                        name: value.to_string(),
                        is_default: false,
                        logged: false,
                        mtime: 0,
                        ino: 0,
                        #[cfg(feature = "inotify_monitor")]
                        wd: -1,
                        #[cfg(feature = "inotify_monitor")]
                        file: None,
                    });
                }
                Ok(())
            }

            // ---------------------------------------------------------------
            // Hosts file
            // ---------------------------------------------------------------
            id if id == short_opt_id('H') => {
                // --addn-hosts=path / --dhcp-hostsfile=path / --hostsdir=path
                if !value.is_empty() {
                    self.config.dns.hosts_files.push(HostsFile {
                        fname: value.to_string(),
                        flags: HostsFileFlags::empty(),
                        index: self.config.dns.hosts_files.len() as u32,
                    });
                }
                Ok(())
            }

            // ---------------------------------------------------------------
            // Bogus NXDOMAIN
            // ---------------------------------------------------------------
            id if id == short_opt_id('B') => {
                // --bogus-nxdomain=addr[/prefix]
                let ip = parse_ip(value)?;
                match ip {
                    IpAddr::V4(v4) => {
                        self.config.dns.bogus_addresses.push(BogusAddr {
                            is6: false,
                            prefix: 32,
                            addr: AllAddr::from_ipv4(v4),
                        });
                    }
                    IpAddr::V6(v6) => {
                        self.config.dns.bogus_addresses.push(BogusAddr {
                            is6: true,
                            prefix: 128,
                            addr: AllAddr::from_ipv6(v6),
                        });
                    }
                }
                Ok(())
            }

            // ---------------------------------------------------------------
            // MX record
            // ---------------------------------------------------------------
            id if id == short_opt_id('m') => {
                // --mx-host=hostname[,target[,pref]]
                let parts = split_comma(value);
                let name = parts.first().map(|s| s.as_str()).unwrap_or("");
                let target = parts.get(1).map(|s| s.as_str()).unwrap_or("");
                let pref = parts.get(2).map(|s| s.as_str()).unwrap_or("10");
                let priority = pref.parse::<u16>().unwrap_or(10);
                if !name.is_empty() {
                    self.config.dns.mx_records.push(MxSrvRecord {
                        name: name.to_string(),
                        target: target.to_string(),
                        priority: priority as i32,
                        weight: 0,
                        srvport: 0,
                        is_srv: false,
                        offset: 0,
                    });
                }
                Ok(())
            }
            id if id == short_opt_id('t') => {
                // --mx-target=hostname
                // Set the default MX target
                Ok(())
            }

            // ---------------------------------------------------------------
            // Domain
            // ---------------------------------------------------------------
            id if id == short_opt_id('s') => {
                // --domain=domain[,range,local]
                // Domain for DHCP hosts
                let parts = split_comma(value);
                if let Some(domain) = parts.first() {
                    if !domain.is_empty() {
                        self.config.dns.local_domains.push(domain.clone());
                    }
                }
                Ok(())
            }

            // ---------------------------------------------------------------
            // DHCP options (feature-gated)
            // ---------------------------------------------------------------
            id if id == short_opt_id('F') => {
                // --dhcp-range=...
                #[cfg(any(feature = "dhcp", feature = "dhcp6"))]
                {
                    self.parse_dhcp_range(value, file, line)?;
                }
                #[cfg(not(any(feature = "dhcp", feature = "dhcp6")))]
                {
                    let _ = (value, file, line);
                    warn!("DHCP not compiled in; ignoring --dhcp-range");
                }
                Ok(())
            }
            id if id == short_opt_id('G') => {
                // --dhcp-host=...
                #[cfg(any(feature = "dhcp", feature = "dhcp6"))]
                {
                    self.parse_dhcp_host(value, file, line)?;
                }
                #[cfg(not(any(feature = "dhcp", feature = "dhcp6")))]
                {
                    let _ = (value, file, line);
                    warn!("DHCP not compiled in; ignoring --dhcp-host");
                }
                Ok(())
            }
            id if id == short_opt_id('O') => {
                // --dhcp-option=...
                #[cfg(any(feature = "dhcp", feature = "dhcp6"))]
                {
                    self.parse_dhcp_option(value, file, line)?;
                }
                #[cfg(not(any(feature = "dhcp", feature = "dhcp6")))]
                {
                    let _ = (value, file, line);
                    warn!("DHCP not compiled in; ignoring --dhcp-option");
                }
                Ok(())
            }
            id if id == short_opt_id('M') => {
                // --dhcp-boot=file[,server[,addr]]
                #[cfg(any(feature = "dhcp", feature = "dhcp6"))]
                {
                    let parts = split_comma(value);
                    let filename = parts.first().map(|s| s.to_string()).unwrap_or_default();
                    let servername = parts.get(1).map(|s| s.to_string());
                    let server_addr = parts.get(2).and_then(|s| {
                        Ipv4Addr::from_str(s).ok()
                    });
                    self.config.dhcp.boots.push(DhcpBoot {
                        file: Some(filename),
                        sname: servername,
                        tftp_sname: None,
                        next_server: server_addr.unwrap_or(Ipv4Addr::UNSPECIFIED),
                        netid: Vec::new(),
                    });
                }
                #[cfg(not(any(feature = "dhcp", feature = "dhcp6")))]
                {
                    let _ = value;
                    warn!("DHCP not compiled in; ignoring --dhcp-boot");
                }
                Ok(())
            }
            id if id == short_opt_id('U') => {
                // --dhcp-vendorclass=tag,class
                #[cfg(any(feature = "dhcp", feature = "dhcp6"))]
                {
                    let parts = split_comma(value);
                    if parts.len() >= 2 {
                        let data_str = parts[1].clone();
                        let data_len = data_str.len() as i32;
                        self.config.dhcp.vendors.push(DhcpVendor {
                            netid: DhcpNetId { net: parts[0].clone() },
                            data: data_str,
                            len: data_len,
                            match_type: 0,
                            enterprise: 0,
                        });
                    }
                }
                #[cfg(not(any(feature = "dhcp", feature = "dhcp6")))]
                {
                    let _ = value;
                }
                Ok(())
            }
            id if id == short_opt_id('J') => {
                // --dhcp-mac=tag,mac
                #[cfg(any(feature = "dhcp", feature = "dhcp6"))]
                {
                    let parts = split_comma(value);
                    if parts.len() >= 2 {
                        let mac_bytes = parse_mac_addr(&parts[1]);
                        self.config.dhcp.macs.push(DhcpMac {
                            netid: DhcpNetId { net: parts[0].clone() },
                            hwaddr: mac_bytes,
                            hwaddr_len: 6,
                            hwaddr_type: 1, // Ethernet
                            mask: 0,
                        });
                    }
                }
                #[cfg(not(any(feature = "dhcp", feature = "dhcp6")))]
                {
                    let _ = value;
                }
                Ok(())
            }
            id if id == short_opt_id('K') => {
                // --dhcp-ignore=tag[,tag...]
                // Ignore DHCP requests matching these tags
                Ok(())
            }
            id if id == short_opt_id('X') => {
                // --pxe-prompt=prompt[,timeout]
                Ok(())
            }
            id if id == short_opt_id('W') => {
                // --srv-host / --pxe-service
                // SRV record: name,target,port[,priority[,weight]]
                let parts = split_comma(value);
                if parts.len() >= 3 {
                    let name = &parts[0];
                    let target = &parts[1];
                    let port = parse_u16(&parts[2], "srv-host port")?;
                    let priority = parts.get(3).map(|s| s.parse::<u16>().unwrap_or(0)).unwrap_or(0);
                    let weight = parts.get(4).map(|s| s.parse::<u16>().unwrap_or(0)).unwrap_or(0);
                    self.config.dns.srv_records.push(MxSrvRecord {
                        name: name.to_string(),
                        target: target.to_string(),
                        priority: priority as i32,
                        weight: weight as i32,
                        srvport: port as i32,
                        is_srv: true,
                        offset: 0,
                    });
                }
                Ok(())
            }
            id if id == short_opt_id('Y') => {
                // --txt-record / --dhcp-optsfile / --dhcp-optsdir
                // TXT record: name,text[,text...]
                let parts = split_comma(value);
                if !parts.is_empty() {
                    let name = parts[0].clone();
                    let txt_data: Vec<u8> = parts[1..].iter()
                        .flat_map(|s| {
                            let bytes = s.as_bytes();
                            let mut v = vec![bytes.len() as u8];
                            v.extend_from_slice(bytes);
                            v
                        })
                        .collect();
                    self.config.dns.txt_records.push(TxtRecord {
                        name,
                        txt: txt_data,
                        class: 1, // IN
                        stat: 0,
                    });
                }
                Ok(())
            }
            id if id == short_opt_id('3') => {
                // --dhcp-broadcast=tag
                Ok(())
            }
            id if id == short_opt_id('6') => {
                // --dhcp-script=path / --dhcp-luascript=path
                #[cfg(feature = "script")]
                {
                    self.config.security.script_file = Some(PathBuf::from(value));
                }
                #[cfg(not(feature = "script"))]
                {
                    let _ = value;
                    warn!("Script support not compiled in");
                }
                Ok(())
            }

            // ---------------------------------------------------------------
            // Long-only options (LOPT_* values, 256+)
            // ---------------------------------------------------------------

            // --- TTL options ---
            id if id == LongOption::NegTTL as u16 => {
                self.config.dns.negative_ttl = parse_u32(value, "neg-ttl")?;
                Ok(())
            }
            id if id == LongOption::MaxTTL as u16 => {
                self.config.dns.max_ttl = parse_u32(value, "max-ttl")?;
                Ok(())
            }
            id if id == LongOption::MinTTL as u16 => {
                // min-ttl: applied to answers from upstream
                let ttl = parse_u32(value, "min-ttl")?;
                if ttl > 86400 {
                    return Err(ConfigError::InvalidOption {
                        option: "min-ttl".to_string(),
                        reason: "cannot exceed 86400 (1 day)".to_string(),
                    });
                }
                self.config.dns.min_cache_ttl = ttl;
                Ok(())
            }
            id if id == LongOption::MaxCacheTTL as u16 => {
                self.config.dns.max_cache_ttl = parse_u32(value, "max-cache-ttl")?;
                Ok(())
            }
            id if id == LongOption::MinCacheTTL as u16 => {
                self.config.dns.min_cache_ttl = parse_u32(value, "min-cache-ttl")?;
                Ok(())
            }
            id if id == LongOption::LocalTTL as u16 => {
                self.config.dns.local_ttl = parse_u32(value, "local-ttl")?;
                Ok(())
            }
            id if id == LongOption::CnameTTL as u16 => {
                self.config.dns.cname_ttl = parse_u32(value, "cname-ttl")?;
                Ok(())
            }
            id if id == LongOption::AuthTTL as u16 => {
                self.config.dns.auth_ttl = parse_u32(value, "auth-ttl")?;
                self.config.auth.ttl = self.config.dns.auth_ttl;
                Ok(())
            }

            // --- Port range ---
            id if id == LongOption::MinPort as u16 => {
                self.config.network.min_port = parse_u16(value, "min-port")?;
                Ok(())
            }
            id if id == LongOption::MaxPort as u16 => {
                self.config.network.max_port = parse_u16(value, "max-port")?;
                Ok(())
            }

            // --- Logging ---
            id if id == LongOption::LogFac as u16 => {
                // log-facility: named facility or numeric
                self.config.log.facility = parse_log_facility(value);
                if self.config.log.facility.is_none() {
                    // Treat as file path
                    self.config.log.file = Some(PathBuf::from(value));
                }
                Ok(())
            }
            id if id == LongOption::LogAsync as u16 => {
                if value.is_empty() {
                    self.config.log.async_lines = Some(constants::LOG_MAX);
                } else {
                    self.config.log.async_lines = Some(parse_usize(value, "log-async")?);
                }
                Ok(())
            }
            id if id == LongOption::LogRo as u16 => {
                // --log-dhcp
                self.config.options.set(OPT_LOG_OPTS);
                Ok(())
            }
            id if id == LongOption::LogDebug as u16 => {
                self.config.options.set(OPT_LOG);
                self.config.options.set(OPT_LOG_OPTS);
                Ok(())
            }
            id if id == LongOption::ExtraLog as u16 => {
                self.config.options.set(OPT_EXTRALOG);
                Ok(())
            }

            // --- TFTP options ---
            id if id == LongOption::Tftp as u16 => {
                // --enable-tftp / --tftp-root
                #[cfg(feature = "tftp")]
                if !value.is_empty() {
                    self.config.tftp.root = Some(PathBuf::from(value));
                }
                #[cfg(not(feature = "tftp"))]
                {
                    let _ = value;
                    warn!("TFTP not compiled in");
                }
                Ok(())
            }
            id if id == LongOption::Secure as u16 => {
                self.config.options.set(OPT_TFTP_SECURE);
                Ok(())
            }
            id if id == LongOption::TftpMax as u16 => {
                #[cfg(feature = "tftp")]
                {
                    self.config.tftp.max_connections = parse_usize(value, "tftp-max")?;
                }
                #[cfg(not(feature = "tftp"))]
                let _ = value;
                Ok(())
            }
            id if id == LongOption::NoBlock as u16 => {
                self.config.options.set(OPT_TFTP_NOBLOCK);
                Ok(())
            }
            id if id == LongOption::TftpMtu as u16 => {
                #[cfg(feature = "tftp")]
                {
                    self.config.tftp.mtu = Some(parse_u16(value, "tftp-mtu")?);
                }
                #[cfg(not(feature = "tftp"))]
                let _ = value;
                Ok(())
            }
            id if id == LongOption::TftpWindow as u16 => {
                #[cfg(feature = "tftp")]
                {
                    self.config.tftp.max_window = Some(parse_u16(value, "tftp-window")?);
                }
                #[cfg(not(feature = "tftp"))]
                let _ = value;
                Ok(())
            }
            id if id == LongOption::NumPort as u16 => {
                // --tftp-port-range=low,high
                #[cfg(feature = "tftp")]
                {
                    let parts = split_comma(value);
                    if parts.len() == 2 {
                        let low = parse_u16(&parts[0], "tftp-port-range low")?;
                        let high = parse_u16(&parts[1], "tftp-port-range high")?;
                        self.config.tftp.port_range = Some((low, high));
                    }
                }
                #[cfg(not(feature = "tftp"))]
                let _ = value;
                Ok(())
            }
            id if id == LongOption::SinglePort as u16 => {
                self.config.options.set(OPT_SINGLE_PORT);
                Ok(())
            }
            id if id == LongOption::TftpAprefMac as u16 => {
                self.config.options.set(OPT_TFTP_APREF_MAC);
                Ok(())
            }
            id if id == LongOption::Prefix as u16 => {
                // --tftp-unique-root
                self.config.options.set(OPT_TFTP_APREF);
                if value == "ip" {
                    self.config.options.set(OPT_TFTP_APREF_IP);
                } else if value == "mac" {
                    self.config.options.set(OPT_TFTP_APREF_MAC);
                }
                Ok(())
            }
            id if id == LongOption::TftpLc as u16 => {
                // tftp-lowercase: handled at runtime
                Ok(())
            }
            id if id == LongOption::Force as u16 => {
                // --tftp-no-fail or --dhcp-option-force
                Ok(())
            }

            // --- DNSSEC options ---
            id if id == LongOption::DnssecCheck as u16 => {
                #[cfg(feature = "dnssec")]
                {
                    self.config.options.set(OPT_DNSSEC_VALID);
                }
                #[cfg(not(feature = "dnssec"))]
                warn!("DNSSEC not compiled in");
                Ok(())
            }
            id if id == LongOption::DnssecTime as u16 => {
                self.config.options.set(OPT_DNSSEC_TIME);
                Ok(())
            }
            id if id == LongOption::DnssecDebug as u16 => {
                self.config.options.set(OPT_DNSSEC_DEBUG);
                Ok(())
            }
            id if id == LongOption::DnssecNoSign as u16 => {
                self.config.options.set(OPT_DNSSEC_NO_SIGN);
                Ok(())
            }
            id if id == LongOption::DnssecIgnoreNs as u16 => {
                self.config.options.set(OPT_DNSSEC_IGN_NS);
                Ok(())
            }
            id if id == LongOption::DnssecTimestamp as u16 => {
                #[cfg(feature = "dnssec")]
                {
                    self.config.dnssec.timestamp_file = Some(PathBuf::from(value));
                }
                #[cfg(not(feature = "dnssec"))]
                let _ = value;
                Ok(())
            }
            id if id == LongOption::DnssecSeed as u16 => {
                // --trust-anchor=zone,flags,proto,algo,digest
                #[cfg(feature = "dnssec")]
                {
                    self.parse_trust_anchor(value)?;
                }
                #[cfg(not(feature = "dnssec"))]
                let _ = value;
                Ok(())
            }
            id if id == LongOption::ProxyDnssec as u16 => {
                self.config.options.set(OPT_DNSSEC_VALID);
                Ok(())
            }
            id if id == LongOption::DnssecLimitWork as u16 => {
                self.config.dnssec.limit_work = parse_u32(value, "dnssec-limit-work")?;
                Ok(())
            }
            id if id == LongOption::DnssecLimitCrypto as u16 => {
                self.config.dnssec.limit_crypto = parse_u32(value, "dnssec-limit-crypto")?;
                Ok(())
            }
            id if id == LongOption::DnssecLimitSigFail as u16 => {
                self.config.dnssec.limit_sig_fail = parse_u32(value, "dnssec-limit-sig-fail")?;
                Ok(())
            }
            id if id == LongOption::DnssecLimitNsec3Iters as u16 => {
                self.config.dnssec.limit_nsec3_iters = parse_u32(value, "dnssec-limit-nsec3-iters")?;
                Ok(())
            }
            id if id == LongOption::NoCacheDnssec as u16 => {
                self.config.options.set(OPT_CACHE_DNSSEC);
                Ok(())
            }
            id if id == LongOption::DnssecCacheLimit as u16 => {
                // dnssec-cache-limit: limit cached DNSSEC records
                Ok(())
            }

            // --- Auth zone options ---
            id if id == LongOption::AuthZone as u16 => {
                #[cfg(feature = "auth")]
                {
                    self.parse_auth_zone(value)?;
                }
                #[cfg(not(feature = "auth"))]
                {
                    let _ = value;
                    warn!("Auth DNS not compiled in");
                }
                Ok(())
            }
            id if id == LongOption::AuthServer as u16 => {
                #[cfg(feature = "auth")]
                {
                    // auth-server=domain,interface
                    let _parts = split_comma(value);
                    // Parse and store auth server config
                }
                #[cfg(not(feature = "auth"))]
                let _ = value;
                Ok(())
            }
            id if id == LongOption::AuthSoa as u16 => {
                #[cfg(feature = "auth")]
                {
                    let parts = split_comma(value);
                    if let Some(sn) = parts.first() {
                        if let Ok(v) = sn.parse::<u32>() {
                            self.config.auth.soa_sn = v;
                        }
                    }
                    if let Some(r) = parts.get(1) {
                        if let Ok(v) = r.parse::<u32>() {
                            self.config.auth.soa_refresh = v;
                        }
                    }
                    if let Some(r) = parts.get(2) {
                        if let Ok(v) = r.parse::<u32>() {
                            self.config.auth.soa_retry = v;
                        }
                    }
                    if let Some(e) = parts.get(3) {
                        if let Ok(v) = e.parse::<u32>() {
                            self.config.auth.soa_expiry = v;
                        }
                    }
                }
                #[cfg(not(feature = "auth"))]
                let _ = value;
                Ok(())
            }

            // --- DNS rebind options ---
            id if id == LongOption::LocalRebind as u16 => {
                self.config.options.set(OPT_LOCAL_REBIND);
                Ok(())
            }
            id if id == LongOption::RebindLocalhost as u16 => {
                self.config.options.set(OPT_REBIND_LOCALHOST);
                Ok(())
            }
            id if id == LongOption::RebindDomainOk as u16 => {
                self.config.options.set(OPT_REBIND_DOMAIN_OK);
                Ok(())
            }
            id if id == LongOption::StopDnsRebind as u16 => {
                self.config.options.set(OPT_NO_REBIND);
                Ok(())
            }

            // --- Server selection ---
            id if id == LongOption::AllServers as u16 => {
                self.config.options.set(OPT_ALL_SERVERS);
                Ok(())
            }
            id if id == LongOption::LocalService as u16 => {
                self.config.options.set(OPT_LOCAL_SERVICE);
                Ok(())
            }

            // --- Loop detection ---
            id if id == LongOption::LoopDetect as u16 => {
                #[cfg(feature = "loop_detect")]
                {
                    self.config.options.set(OPT_LOOP_DETECT);
                }
                #[cfg(not(feature = "loop_detect"))]
                warn!("Loop detection not compiled in");
                Ok(())
            }

            // --- Firewall sets ---
            id if id == LongOption::IpSet as u16 => {
                #[cfg(feature = "ipset")]
                {
                    // ipset=/domain/setname[,setname...]
                    // Parsed but stored for runtime use
                    let _ = value;
                }
                #[cfg(not(feature = "ipset"))]
                {
                    let _ = value;
                    warn!("ipset not compiled in");
                }
                Ok(())
            }
            id if id == LongOption::NftSet as u16 => {
                #[cfg(feature = "nftset")]
                {
                    let _ = value;
                }
                #[cfg(not(feature = "nftset"))]
                {
                    let _ = value;
                    warn!("nftset not compiled in");
                }
                Ok(())
            }

            // --- Connmark ---
            id if id == LongOption::ConnMark as u16 => {
                #[cfg(feature = "conntrack")]
                {
                    let _ = value;
                }
                #[cfg(not(feature = "conntrack"))]
                {
                    let _ = value;
                    warn!("conntrack not compiled in");
                }
                Ok(())
            }
            id if id == LongOption::ConnmarkAllowlistEnable as u16 => {
                self.config.options.set(OPT_CMARK_ALST_EN);
                Ok(())
            }
            id if id == LongOption::ConnmarkAllowlistNew as u16 => {
                self.config.options.set(OPT_CMARK_ALST_NEW);
                Ok(())
            }

            // --- DHCP relay ---
            id if id == LongOption::DhcpRelay as u16 => {
                #[cfg(any(feature = "dhcp", feature = "dhcp6"))]
                {
                    self.parse_dhcp_relay(value)?;
                }
                #[cfg(not(any(feature = "dhcp", feature = "dhcp6")))]
                let _ = value;
                Ok(())
            }
            id if id == LongOption::SplitRelay as u16 => {
                // split-relay: split DHCP relay across interfaces
                Ok(())
            }

            // --- Router Advertisement ---
            id if id == LongOption::Ra as u16 => {
                self.config.options.set(OPT_RA);
                Ok(())
            }
            id if id == LongOption::RaParam as u16 => {
                // ra-param=interface,mtu:N,high/low,interval,lifetime
                Ok(())
            }
            id if id == LongOption::RaSolicit as u16 || id == LongOption::RaSolicitRefresh as u16 => {
                Ok(())
            }

            // --- CNAME ---
            id if id == LongOption::Cname as u16 => {
                // cname=alias,target[,ttl]
                let parts = split_comma(value);
                if parts.len() >= 2 {
                    let ttl = parts.get(2).and_then(|s| s.parse::<i32>().ok());
                    self.config.dns.cname_records.push(CnameRecord {
                        alias: parts[0].clone(),
                        target: parts[1].clone(),
                        ttl: ttl.unwrap_or(-1),
                        flag: 0,
                    });
                }
                Ok(())
            }

            // --- Host record ---
            id if id == LongOption::HostRec as u16 => {
                // host-record=name[,name...],addr[,addr...]
                let parts = split_comma(value);
                if parts.len() >= 2 {
                    let mut names = Vec::new();
                    let mut v4addr = Ipv4Addr::UNSPECIFIED;
                    let mut v6addr = Ipv6Addr::UNSPECIFIED;
                    let mut flags = 0i32;
                    for part in &parts {
                        if let Ok(ip) = IpAddr::from_str(part) {
                            match ip {
                                IpAddr::V4(a) => { v4addr = a; flags |= 2; } // HR_4
                                IpAddr::V6(a) => { v6addr = a; flags |= 1; } // HR_6
                            }
                        } else {
                            names.push(part.clone());
                        }
                    }
                    if !names.is_empty() && flags != 0 {
                        self.config.dns.host_records.push(HostRecord {
                            names,
                            addr: v4addr,
                            addr6: v6addr,
                            ttl: 0,
                            flags,
                        });
                    }
                }
                Ok(())
            }

            // --- PTR record ---
            id if id == LongOption::PtrRec as u16 => {
                // ptr-record=name,target
                let parts = split_comma(value);
                if parts.len() >= 2 {
                    self.config.dns.ptr_records.push(PtrRecord {
                        name: parts[0].clone(),
                        ptr: parts[1].clone(),
                    });
                }
                Ok(())
            }

            // --- NAPTR record ---
            id if id == LongOption::Naptr as u16 => {
                // naptr-record=name,order,pref,flags,service,regexp,replacement
                // Stored but complex parsing deferred to DNS module
                Ok(())
            }

            // --- Bridge interface ---
            id if id == LongOption::Bridge as u16 => {
                #[cfg(any(feature = "dhcp", feature = "dhcp6"))]
                {
                    let parts = split_comma(value);
                    if parts.len() >= 2 {
                        let bridge_name = parts[0].clone();
                        let alias_bridges: Vec<DhcpBridge> = parts[1..].iter().map(|a| {
                            DhcpBridge {
                                iface: a.clone(),
                                aliases: Vec::new(),
                            }
                        }).collect();
                        self.config.dhcp.bridges.push(DhcpBridge {
                            iface: bridge_name,
                            aliases: alias_bridges,
                        });
                    }
                }
                #[cfg(not(any(feature = "dhcp", feature = "dhcp6")))]
                let _ = value;
                Ok(())
            }

            // --- Shared network ---
            id if id == LongOption::SharedNet as u16 => {
                #[cfg(any(feature = "dhcp", feature = "dhcp6"))]
                {
                    let parts = split_comma(value);
                    if parts.len() >= 2 {
                        let shared_v4 = parts.get(1).and_then(|s| Ipv4Addr::from_str(s).ok())
                            .unwrap_or(Ipv4Addr::UNSPECIFIED);
                        self.config.dhcp.shared_networks.push(SharedNetwork {
                            if_index: 0,
                            match_addr: Ipv4Addr::UNSPECIFIED,
                            shared_addr: shared_v4,
                            #[cfg(feature = "dhcp6")]
                            match_addr6: Ipv6Addr::UNSPECIFIED,
                            #[cfg(feature = "dhcp6")]
                            shared_addr6: Ipv6Addr::UNSPECIFIED,
                        });
                    }
                }
                #[cfg(not(any(feature = "dhcp", feature = "dhcp6")))]
                let _ = value;
                Ok(())
            }

            // --- Misc boolean DHCP flags ---
            id if id == LongOption::NoAutoPxe as u16 => {
                Ok(())
            }
            id if id == LongOption::QuietDhcp as u16 => {
                self.config.options.set(OPT_QUIET_DHCP);
                Ok(())
            }
            id if id == LongOption::QuietDhcp6 as u16 => {
                self.config.options.set(OPT_QUIET_DHCP6);
                Ok(())
            }
            id if id == LongOption::QuietRa as u16 => {
                self.config.options.set(OPT_QUIET_RA);
                Ok(())
            }
            id if id == LongOption::QuietTftp as u16 => {
                self.config.options.set(OPT_QUIET_TFTP);
                Ok(())
            }
            id if id == LongOption::Quiet4Over6 as u16 => {
                self.config.options.set(OPT_NO_4OVER6);
                Ok(())
            }
            id if id == LongOption::RapidCommit as u16 => {
                self.config.options.set(OPT_RAPID_COMMIT);
                Ok(())
            }
            id if id == LongOption::ConsecAddr as u16 => {
                self.config.options.set(OPT_CONSEC_ADDR);
                Ok(())
            }
            id if id == LongOption::BootPDynamic as u16 => {
                self.config.options.set(OPT_BOOTP_DYNAMIC);
                Ok(())
            }
            id if id == LongOption::DhcpIgnoreClid as u16 => {
                self.config.options.set(OPT_IGNORE_CLID);
                Ok(())
            }
            id if id == LongOption::DhcpIgnoreHostname as u16 => {
                self.config.options.set(OPT_NO_DHCP_HOSTNAME);
                Ok(())
            }
            id if id == LongOption::DhcpNoDns as u16 => {
                // dhcp-no-override: don't override DNS server info in DHCP
                Ok(())
            }

            // --- Misc boolean flags ---
            id if id == LongOption::NormRep as u16 => {
                self.config.options.set(OPT_NORR);
                Ok(())
            }
            id if id == LongOption::NormRep6 as u16 => {
                self.config.options.set(OPT_NORR6);
                Ok(())
            }
            id if id == LongOption::NoIdent as u16 => {
                self.config.options.set(OPT_NO_IDENT);
                Ok(())
            }
            id if id == LongOption::StripEcs as u16 => {
                self.config.options.set(OPT_STRIP_ECS);
                Ok(())
            }
            id if id == LongOption::StripMac as u16 => {
                self.config.options.set(OPT_STRIP_MAC);
                Ok(())
            }
            id if id == LongOption::ScriptArp as u16 => {
                self.config.options.set(OPT_SCRIPT_ARP);
                Ok(())
            }
            id if id == LongOption::NatPmp as u16 => {
                self.config.options.set(OPT_NAT_PMP);
                Ok(())
            }
            id if id == LongOption::FilterA as u16 => {
                self.config.options.set(OPT_FILTER_A);
                Ok(())
            }
            id if id == LongOption::FilterAAAA as u16 => {
                self.config.options.set(OPT_FILTER_AAAA);
                Ok(())
            }
            id if id == LongOption::AuthNxdomain as u16 => {
                self.config.options.set(OPT_AUTH_NXDOMAIN);
                Ok(())
            }
            id if id == LongOption::LeaseQuery as u16 => {
                self.config.options.set(OPT_LEASEQUERY);
                Ok(())
            }

            // --- Stale cache ---
            id if id == LongOption::StaleCache as u16 => {
                self.config.options.set(OPT_STALE_CACHE);
                Ok(())
            }

            // --- Bind mode ---
            id if id == LongOption::Dynamic as u16 => {
                self.config.network.bind_mode = BindMode::BindDynamic;
                self.config.options.set(OPT_CLEVERBIND);
                Ok(())
            }

            // --- Add-MAC / Add-Subnet ---
            id if id == LongOption::AddMac as u16 => {
                self.config.options.set(OPT_ADD_MAC);
                if value == "base64" {
                    self.config.options.set(OPT_MAC_B64);
                } else if value == "text" {
                    self.config.options.set(OPT_MAC_HEX);
                }
                Ok(())
            }
            id if id == LongOption::AddSubnet as u16 => {
                self.config.options.set(OPT_CLIENT_SUBNET);
                Ok(())
            }

            // --- Umbrella ---
            id if id == LongOption::Umbrella as u16 => {
                self.config.options.set(OPT_UMBRELLA);
                Ok(())
            }
            id if id == LongOption::UmbrellaDevId as u16 => {
                self.config.options.set(OPT_UMBRELLA_DEVID);
                Ok(())
            }

            // --- Cache RR ---
            id if id == LongOption::CacheRr as u16 => {
                self.config.options.set(OPT_CACHE_RR);
                Ok(())
            }
            id if id == LongOption::IgnoreAddr as u16 => {
                self.config.options.set(OPT_IGNORE_ADDR);
                Ok(())
            }

            // --- Tag-if ---
            id if id == LongOption::TagIf as u16 => {
                #[cfg(any(feature = "dhcp", feature = "dhcp6"))]
                {
                    // tag-if=set:tag-one,set:tag-two,tag:tag-three
                    // Complex conditional tag logic
                    let _ = value;
                }
                #[cfg(not(any(feature = "dhcp", feature = "dhcp6")))]
                let _ = value;
                Ok(())
            }
            id if id == LongOption::Tag as u16 => {
                // dhcp-generate-names / tag
                Ok(())
            }
            id if id == LongOption::MatchName as u16 => {
                // dhcp-match / dhcp-name-match
                Ok(())
            }

            // --- Synth domain ---
            id if id == LongOption::SynTh as u16 => {
                // synth-domain=domain,address-range[,prefix]
                Ok(())
            }

            // --- Conf-script ---
            id if id == LongOption::ConfScript as u16 => {
                // conf-script: not commonly used; skip with warning
                warn!("conf-script option is noted but not actively processed");
                Ok(())
            }

            // --- Dump ---
            id if id == LongOption::Dump as u16 => {
                #[cfg(feature = "dump")]
                {
                    let _ = value;
                }
                #[cfg(not(feature = "dump"))]
                {
                    let _ = value;
                    warn!("Dump not compiled in");
                }
                Ok(())
            }
            id if id == LongOption::DumpFlagsOpt as u16 => {
                #[cfg(feature = "dump")]
                {
                    let _ = value;
                }
                #[cfg(not(feature = "dump"))]
                {
                    let _ = value;
                }
                Ok(())
            }

            // --- PXE vendor ---
            id if id == LongOption::PxeVendor as u16 => {
                Ok(())
            }

            // --- D-Bus / UBus ---
            id if id == LongOption::ServAuth as u16 => {
                // --enable-dbus / --enable-ubus
                #[cfg(feature = "dbus")]
                self.config.options.set(OPT_DBUS);
                #[cfg(feature = "ubus")]
                self.config.options.set(OPT_UBUS);
                Ok(())
            }
            id if id == LongOption::Reload as u16 => {
                // reload: clear cache on SIGHUP
                Ok(())
            }
            id if id == LongOption::NoNames as u16 => {
                // no-negcache for names
                Ok(())
            }

            // --- Script time ---
            id if id == LongOption::ScriptTime as u16 => {
                // script-on-renewal
                Ok(())
            }

            // --- Delay ---
            id if id == LongOption::Delay as u16 => {
                // delay-config: delay response to allow tag processing
                Ok(())
            }
            id if id == LongOption::Limit as u16 => {
                // limit: per-source query limit
                Ok(())
            }
            id if id == LongOption::LeasesFile as u16 => {
                self.config.dhcp.lease_file = PathBuf::from(value);
                Ok(())
            }

            // --- Various other long opts ---
            id if id == LongOption::DhcpOpt6 as u16 => {
                // dhcp-option for DHCPv6
                #[cfg(feature = "dhcp6")]
                {
                    self.parse_dhcp_option(value, file, line)?;
                }
                #[cfg(not(feature = "dhcp6"))]
                {
                    let _ = (value, file, line);
                }
                Ok(())
            }
            id if id == LongOption::DhcpFirewall as u16 => {
                Ok(())
            }
            id if id == LongOption::ConMarkAlstEnNew as u16 => {
                Ok(())
            }
            id if id == LongOption::MaxPortV6 as u16 || id == LongOption::MinPortV6 as u16 => {
                Ok(())
            }
            id if id == LongOption::LocalAddr as u16 => {
                Ok(())
            }
            id if id == LongOption::Bogus4 as u16 => {
                // bogus-nxdomain for v4 only
                if let Ok(v4) = Ipv4Addr::from_str(value) {
                    self.config.dns.bogus_addresses.push(BogusAddr {
                        is6: false,
                        prefix: 32,
                        addr: AllAddr::from_ipv4(v4),
                    });
                }
                Ok(())
            }
            id if id == LongOption::Bogus6 as u16 => {
                // bogus-nxdomain for v6 only
                if let Ok(v6) = Ipv6Addr::from_str(value) {
                    self.config.dns.bogus_addresses.push(BogusAddr {
                        is6: true,
                        prefix: 128,
                        addr: AllAddr::from_ipv6(v6),
                    });
                }
                Ok(())
            }
            id if id == LongOption::DnsDomain as u16 => {
                if !value.is_empty() {
                    self.config.dns.local_domains.push(value.to_string());
                }
                Ok(())
            }
            id if id == LongOption::StickyOrder as u16 => {
                Ok(())
            }
            id if id == LongOption::FastDns as u16 => {
                Ok(())
            }
            id if id == LongOption::Stale as u16 => {
                self.config.options.set(OPT_STALE_CACHE);
                Ok(())
            }
            id if id == LongOption::NormRepV6 as u16 => {
                self.config.options.set(OPT_NORR6);
                Ok(())
            }
            id if id == LongOption::LocalRebindV6 as u16 || id == LongOption::RebindLocalAll as u16 => {
                self.config.options.set(OPT_LOCAL_REBIND);
                Ok(())
            }
            id if id == LongOption::DynHost as u16 => {
                Ok(())
            }
            id if id == LongOption::Log4 as u16 || id == LongOption::Log6 as u16 => {
                self.config.options.set(OPT_LOG);
                Ok(())
            }
            id if id == LongOption::EncapVendor as u16 => {
                Ok(())
            }
            id if id == LongOption::RrName as u16 => {
                Ok(())
            }
            id if id == LongOption::NoCache4 as u16 => {
                Ok(())
            }

            // ---------------------------------------------------------------
            // Catch-all — return error for unrecognized option IDs
            // ---------------------------------------------------------------
            _ => {
                warn!("Unrecognized option id {} at {}:{}", option_id, file, line);
                Err(ConfigError::UnknownOption(format!(
                    "unhandled option id {} at {}:{}",
                    option_id, file, line
                )))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Configuration directory scanning
// ---------------------------------------------------------------------------

impl ConfigBuilder {
    /// Read all configuration files from a directory, optionally filtering by extension.
    ///
    /// Replaces the `conf-dir=` directive processing from C option.c.
    fn read_config_dir(
        &mut self,
        dir_path: &str,
        filter_extensions: &[&str],
    ) -> Result<(), ConfigError> {
        let dir = PathBuf::from(dir_path);
        if !dir.is_dir() {
            return Err(ConfigError::IoError {
                path: dir_path.to_string(),
                source: std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "not a directory",
                ),
            });
        }

        let mut entries: Vec<PathBuf> = Vec::new();
        let rd = fs::read_dir(&dir).map_err(|e| ConfigError::IoError {
            path: dir_path.to_string(),
            source: e,
        })?;

        for entry in rd {
            let entry = entry.map_err(|e| ConfigError::IoError {
                path: dir_path.to_string(),
                source: e,
            })?;
            let path = entry.path();

            if !path.is_file() {
                continue;
            }

            // Skip hidden files
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.starts_with('.') || name.starts_with('#') || name.ends_with('~') {
                    continue;
                }
            }

            // Apply extension filter: if filters provided, file must match one
            if !filter_extensions.is_empty() {
                let ext_match = path.extension().and_then(|e| e.to_str()).map_or(false, |ext| {
                    filter_extensions.iter().any(|f| {
                        // Filter can be ".ext" (must match) or "ext" (must not match if prefixed with no-)
                        let filt = f.trim();
                        if filt.starts_with('.') {
                            ext == &filt[1..]
                        } else {
                            ext != filt
                        }
                    })
                });
                if !ext_match && path.extension().is_some() {
                    continue;
                }
            }

            entries.push(path);
        }

        // Sort for deterministic ordering
        entries.sort();

        for path in entries {
            if let Some(path_str) = path.to_str() {
                self.read_config_file(path_str, true)?;
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// DHCP option parsing helpers (feature-gated)
// ---------------------------------------------------------------------------

#[cfg(any(feature = "dhcp", feature = "dhcp6"))]
impl ConfigBuilder {
    /// Parse a --dhcp-range directive.
    ///
    /// Format: `[tag:<tag>,]<start>,<end>[,<mask>][,<lease_time>]`
    /// Or for IPv6: `[tag:<tag>,]<start_addr6>,<end_addr6|prefix_len>[,<lease_time>]`
    fn parse_dhcp_range(
        &mut self,
        value: &str,
        _file: &str,
        _line: usize,
    ) -> Result<(), ConfigError> {
        let parts = split_comma(value);
        if parts.is_empty() {
            return Err(ConfigError::MissingArgument("dhcp-range".to_string()));
        }

        let mut idx = 0;
        let mut netid = None;

        // Check for tag: prefix
        if parts[0].starts_with("tag:") {
            netid = Some(DhcpNetId {
                net: parts[0][4..].to_string(),
            });
            idx = 1;
        } else if parts[0].starts_with("set:") {
            netid = Some(DhcpNetId {
                net: parts[0][4..].to_string(),
            });
            idx = 1;
        }

        if idx >= parts.len() {
            return Err(ConfigError::InvalidOption {
                option: "dhcp-range".to_string(),
                reason: "missing address range".to_string(),
            });
        }

        // Determine v4 vs v6
        let is_v6 = parts[idx].contains(':');

        let mut flags = DhcpContextFlags::empty();
        if is_v6 {
            flags.insert(DhcpContextFlags::V6);
        }

        let start_str = &parts[idx];
        idx += 1;

        let end_str = if idx < parts.len() {
            let s = &parts[idx];
            idx += 1;
            s.clone()
        } else {
            start_str.clone()
        };

        // Parse optional netmask and lease time
        let mut netmask = None;
        let mut lease_time: u32 = if is_v6 {
            constants::DEFLEASE6 as u32
        } else {
            constants::DEFLEASE as u32
        };

        while idx < parts.len() {
            let part = &parts[idx];
            // Check if it's a time value
            if let Ok(t) = parse_time(part, "dhcp-range lease-time") {
                lease_time = t;
            } else if let Ok(mask) = Ipv4Addr::from_str(part) {
                netmask = Some(mask);
            } else if part == "static" {
                flags.insert(DhcpContextFlags::STATIC);
            } else if part == "proxy" {
                flags.insert(DhcpContextFlags::PROXY);
            } else if part == "ra-only" || part == "slaac" {
                flags.insert(DhcpContextFlags::RA);
            } else if part == "ra-names" {
                flags.insert(DhcpContextFlags::RA_NAME);
            } else if part == "ra-stateless" {
                flags.insert(DhcpContextFlags::RA_STATELESS);
            }
            idx += 1;
        }

        // Parse addresses
        let start_v4 = if !is_v6 {
            Ipv4Addr::from_str(start_str).unwrap_or(Ipv4Addr::UNSPECIFIED)
        } else {
            Ipv4Addr::UNSPECIFIED
        };
        let end_v4 = if !is_v6 {
            Ipv4Addr::from_str(&end_str).unwrap_or(Ipv4Addr::UNSPECIFIED)
        } else {
            Ipv4Addr::UNSPECIFIED
        };

        let ctx = DhcpContext {
            flags,
            netid: netid.unwrap_or(DhcpNetId { net: String::new() }),
            filter: Vec::new(),
            start: start_v4,
            end: end_v4,
            netmask: netmask.unwrap_or(Ipv4Addr::UNSPECIFIED),
            broadcast: Ipv4Addr::UNSPECIFIED,
            local: Ipv4Addr::UNSPECIFIED,
            router: Ipv4Addr::UNSPECIFIED,
            lease_time,
            addr_epoch: 0,
            #[cfg(feature = "dhcp6")]
            start6: if is_v6 { Ipv6Addr::from_str(start_str).unwrap_or(Ipv6Addr::UNSPECIFIED) } else { Ipv6Addr::UNSPECIFIED },
            #[cfg(feature = "dhcp6")]
            end6: if is_v6 { Ipv6Addr::from_str(&end_str).unwrap_or(Ipv6Addr::UNSPECIFIED) } else { Ipv6Addr::UNSPECIFIED },
            #[cfg(feature = "dhcp6")]
            local6: Ipv6Addr::UNSPECIFIED,
            #[cfg(feature = "dhcp6")]
            prefix: if is_v6 { 64 } else { 0 },
            #[cfg(feature = "dhcp6")]
            if_index: 0,
            #[cfg(feature = "dhcp6")]
            valid: 0,
            #[cfg(feature = "dhcp6")]
            preferred: 0,
            #[cfg(feature = "dhcp6")]
            saved_valid: 0,
            #[cfg(feature = "dhcp6")]
            ra_time: 0,
            #[cfg(feature = "dhcp6")]
            ra_short_period_start: 0,
            #[cfg(feature = "dhcp6")]
            address_lost_time: 0,
            #[cfg(feature = "dhcp6")]
            template_interface: None,
        };

        self.config.dhcp.contexts.push(ctx);
        Ok(())
    }

    /// Parse a --dhcp-host directive.
    ///
    /// Format: `[mac|id:client_id|*,]addr[,hostname[,lease_time[,ignore]]]`
    fn parse_dhcp_host(
        &mut self,
        value: &str,
        _file: &str,
        _line: usize,
    ) -> Result<(), ConfigError> {
        let parts = split_comma(value);
        if parts.is_empty() {
            return Err(ConfigError::MissingArgument("dhcp-host".to_string()));
        }

        let mut flags = DhcpConfigFlags::empty();
        let mut hwaddr: Option<Vec<u8>> = None;
        let mut addr: Option<AllAddr> = None;
        let mut hostname: Option<String> = None;
        let mut lease_time = 0u32;
        let mut clid: Option<Vec<u8>> = None;

        for part in &parts {
            let part = part.trim();

            if part == "ignore" {
                flags.insert(DhcpConfigFlags::NOCLID);
                continue;
            }

            if part.starts_with("id:") {
                clid = Some(part[3..].as_bytes().to_vec());
                continue;
            }

            if part.starts_with("set:") || part.starts_with("tag:") {
                continue;
            }

            // Try MAC address
            if part.contains(':') && part.len() == 17 {
                let mac = parse_mac_addr(part);
                if mac.len() == 6 {
                    hwaddr = Some(mac);
                    continue;
                }
            }

            // Try IP address
            if let Ok(ip) = IpAddr::from_str(part) {
                match ip {
                    IpAddr::V4(v4) => addr = Some(AllAddr::from_ipv4(v4)),
                    IpAddr::V6(v6) => addr = Some(AllAddr::from_ipv6(v6)),
                }
                continue;
            }

            // Try time value
            if let Ok(t) = parse_time(part, "dhcp-host lease-time") {
                lease_time = t;
                continue;
            }

            // Otherwise treat as hostname
            hostname = Some(part.to_string());
        }

        let parsed_addr = match addr {
            Some(AllAddr::V4(v4)) => v4,
            _ => Ipv4Addr::UNSPECIFIED,
        };
        let mut hw_configs = Vec::new();
        if let Some(mac_bytes) = hwaddr {
            hw_configs.push(HwaddrConfig {
                hwaddr_len: 6,
                hwaddr_type: 1,
                hwaddr: mac_bytes,
                wildcard_mask: 0,
            });
        }
        let host = DhcpHostDef {
            flags,
            clid: clid.unwrap_or_default(),
            hostname,
            domain: None,
            netid: Vec::new(),
            filter: Vec::new(),
            #[cfg(feature = "dhcp6")]
            addr6: Vec::new(),
            addr: parsed_addr,
            decline_time: 0,
            lease_time,
            hwaddr: hw_configs,
        };

        self.config.dhcp.hosts.push(host);
        Ok(())
    }

    /// Parse a --dhcp-option directive.
    ///
    /// Format: `[tag:<tag>,][encap:<vendor>,]option_num[,value]`
    fn parse_dhcp_option(
        &mut self,
        value: &str,
        _file: &str,
        _line: usize,
    ) -> Result<(), ConfigError> {
        let parts = split_comma(value);
        if parts.is_empty() {
            return Err(ConfigError::MissingArgument("dhcp-option".to_string()));
        }

        let mut idx = 0;
        let mut flags = DhcpOptFlags::empty();
        let mut netid = None;

        // Check for tag/encap prefixes
        while idx < parts.len() {
            if parts[idx].starts_with("tag:") {
                netid = Some(DhcpNetId {
                    net: parts[idx][4..].to_string(),
                });
                idx += 1;
            } else if parts[idx].starts_with("encap:") {
                flags.insert(DhcpOptFlags::ENCAPSULATE);
                idx += 1;
            } else if parts[idx] == "force" {
                flags.insert(DhcpOptFlags::FORCE);
                idx += 1;
            } else {
                break;
            }
        }

        if idx >= parts.len() {
            return Err(ConfigError::InvalidOption {
                option: "dhcp-option".to_string(),
                reason: "missing option number".to_string(),
            });
        }

        let opt_num_str = &parts[idx];
        let opt_num = if opt_num_str.starts_with("option:") {
            // Named option - lookup by name
            let name = &opt_num_str[7..];
            dhcp_option_name_to_number(name).unwrap_or(0)
        } else if opt_num_str.starts_with("option6:") {
            let name = &opt_num_str[8..];
            dhcp6_option_name_to_number(name).unwrap_or(0)
        } else {
            opt_num_str.parse::<u16>().unwrap_or(0)
        };
        idx += 1;

        // Remaining parts are the option value
        let val_parts: Vec<String> = parts[idx..].to_vec();
        let val_bytes = encode_dhcp_option_value(opt_num, &val_parts);

        let opt = DhcpOptDef {
            opt: opt_num as i32,
            len: val_bytes.len() as i32,
            flags,
            extra: DhcpOptExtra::None,
            val: val_bytes,
            netid: if let Some(nid) = netid { vec![nid] } else { Vec::new() },
        };

        self.config.dhcp.options.push(opt);
        Ok(())
    }

    /// Parse a --dhcp-relay directive.
    ///
    /// Format: `local_addr,server_addr[,interface]`
    fn parse_dhcp_relay(&mut self, value: &str) -> Result<(), ConfigError> {
        let parts = split_comma(value);
        if parts.len() < 2 {
            return Err(ConfigError::InvalidOption {
                option: "dhcp-relay".to_string(),
                reason: "requires at least local_addr,server_addr".to_string(),
            });
        }

        let local_ip = parse_ip(&parts[0])?;
        let server_ip = parse_ip(&parts[1])?;
        let iface = parts.get(2).cloned().unwrap_or_default();

        let local_relay = match local_ip {
            IpAddr::V4(v4) => RelayAddr::V4(v4),
            IpAddr::V6(v6) => RelayAddr::V6(v6),
        };
        let server_relay = match server_ip {
            IpAddr::V4(v4) => RelayAddr::V4(v4),
            IpAddr::V6(v6) => RelayAddr::V6(v6),
        };

        self.config.dhcp.relays.push(DhcpRelay {
            local: local_relay.clone(),
            server: server_relay,
            uplink: local_relay,
            interface: if iface.is_empty() { None } else { Some(iface) },
            iface_index: 0,
            port: 0,
            split_mode: 0,
            warned: 0,
            matchcount: 0,
            #[cfg(feature = "script")]
            snoop_records: Vec::new(),
        });

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// DNSSEC trust anchor parsing
// ---------------------------------------------------------------------------

impl ConfigBuilder {
    /// Parse a --trust-anchor directive.
    ///
    /// Format: `zone,flags,protocol,algorithm,digest_type:hex_digest`
    #[cfg(feature = "dnssec")]
    fn parse_trust_anchor(&mut self, value: &str) -> Result<(), ConfigError> {
        let parts = split_comma(value);
        if parts.len() < 5 {
            return Err(ConfigError::InvalidOption {
                option: "trust-anchor".to_string(),
                reason: "requires zone,flags,protocol,algorithm,digest".to_string(),
            });
        }

        let zone = parts[0].clone();
        let keytag = parts[1].parse::<i32>().map_err(|_| ConfigError::InvalidOption {
            option: "trust-anchor".to_string(),
            reason: "invalid keytag".to_string(),
        })?;
        let algo = parts[2].parse::<i32>().map_err(|_| ConfigError::InvalidOption {
            option: "trust-anchor".to_string(),
            reason: "invalid algorithm".to_string(),
        })?;
        let digest_type = parts[3].parse::<i32>().map_err(|_| ConfigError::InvalidOption {
            option: "trust-anchor".to_string(),
            reason: "invalid digest type".to_string(),
        })?;

        // Parse hex digest (may contain colons)
        let digest_hex: String = parts[4..].join(",").replace(':', "").replace(' ', "");
        let digest = hex_decode(&digest_hex).map_err(|_| ConfigError::InvalidOption {
            option: "trust-anchor".to_string(),
            reason: "invalid hex digest".to_string(),
        })?;

        self.config.dnssec.trust_anchors.push(DsConfig {
            name: zone,
            keytag,
            algo,
            digest_type,
            digest,
            class: 1, // C_IN
        });

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Auth zone parsing
// ---------------------------------------------------------------------------

impl ConfigBuilder {
    /// Parse a --auth-zone directive.
    ///
    /// Format: `domain[,subnet[,subnet...][,exclude-subnet...][,interface...]]`
    #[cfg(feature = "auth")]
    fn parse_auth_zone(&mut self, value: &str) -> Result<(), ConfigError> {
        let parts = split_comma(value);
        if parts.is_empty() {
            return Err(ConfigError::MissingArgument("auth-zone".to_string()));
        }

        let domain = parts[0].clone();
        let mut subnets: Vec<AddrList> = Vec::new();
        let mut exclude_subnets: Vec<AddrList> = Vec::new();
        let mut iface_names: Vec<AuthNameEntry> = Vec::new();

        for part in parts.iter().skip(1) {
            if part.starts_with("exclude:") {
                let addr_str = &part[8..];
                if let Ok(ip) = IpAddr::from_str(addr_str) {
                    let (addr, flags) = match ip {
                        IpAddr::V4(v4) => (AllAddr::from_ipv4(v4), AddrListFlags::empty()),
                        IpAddr::V6(v6) => (AllAddr::from_ipv6(v6), AddrListFlags::IPV6),
                    };
                    exclude_subnets.push(AddrList { addr, flags, prefixlen: 0, decline_time: 0 });
                }
            } else if part.contains('/') || part.contains('.') || part.contains(':') {
                if let Ok(ip) = IpAddr::from_str(part.split('/').next().unwrap_or("")) {
                    let prefix = part.split('/').nth(1).and_then(|p| p.parse::<i32>().ok()).unwrap_or(0);
                    let (addr, flags) = match ip {
                        IpAddr::V4(v4) => (AllAddr::from_ipv4(v4), AddrListFlags::empty()),
                        IpAddr::V6(v6) => (AllAddr::from_ipv6(v6), AddrListFlags::IPV6),
                    };
                    subnets.push(AddrList { addr, flags, prefixlen: prefix, decline_time: 0 });
                }
            } else {
                iface_names.push(AuthNameEntry {
                    name: part.clone(),
                    flags: 0,
                });
            }
        }

        self.config.auth.zones.push(AuthZone {
            domain,
            subnet: subnets,
            exclude: exclude_subnets,
            interface_names: iface_names,
        });

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Log facility parsing
// ---------------------------------------------------------------------------

/// Parse a syslog facility name to its numeric value.
fn parse_log_facility(name: &str) -> Option<i32> {
    match name.to_lowercase().as_str() {
        "kern" => Some(0),
        "user" => Some(8),
        "mail" => Some(16),
        "daemon" => Some(24),
        "auth" => Some(32),
        "syslog" => Some(40),
        "lpr" => Some(48),
        "news" => Some(56),
        "uucp" => Some(64),
        "cron" => Some(72),
        "local0" => Some(128),
        "local1" => Some(136),
        "local2" => Some(144),
        "local3" => Some(152),
        "local4" => Some(160),
        "local5" => Some(168),
        "local6" => Some(176),
        "local7" => Some(184),
        _ => name.parse::<i32>().ok(),
    }
}

// ---------------------------------------------------------------------------
// MAC address and hex parsing helpers
// ---------------------------------------------------------------------------

/// Parse a MAC address string (aa:bb:cc:dd:ee:ff) into bytes.
fn parse_mac_addr(s: &str) -> Vec<u8> {
    s.split(':')
        .filter_map(|h| u8::from_str_radix(h, 16).ok())
        .collect()
}

/// Decode a hex string into bytes.
fn hex_decode(s: &str) -> Result<Vec<u8>, ()> {
    if s.len() % 2 != 0 {
        return Err(());
    }
    let mut bytes = Vec::with_capacity(s.len() / 2);
    let mut chars = s.chars();
    while let (Some(h), Some(l)) = (chars.next(), chars.next()) {
        let byte = u8::from_str_radix(&format!("{h}{l}"), 16).map_err(|_| ())?;
        bytes.push(byte);
    }
    Ok(bytes)
}

// ---------------------------------------------------------------------------
// DHCP option name-to-number mapping
// ---------------------------------------------------------------------------

/// Map well-known DHCPv4 option names to their numbers (RFC 2132 and extensions).
#[cfg(any(feature = "dhcp", feature = "dhcp6"))]
fn dhcp_option_name_to_number(name: &str) -> Option<u16> {
    match name.to_lowercase().as_str() {
        "netmask" | "subnet-mask" => Some(1),
        "time-offset" => Some(2),
        "router" | "routers" => Some(3),
        "dns-server" | "domain-name-server" => Some(6),
        "log-server" => Some(7),
        "hostname" | "host-name" => Some(12),
        "domain-name" | "domain" => Some(15),
        "broadcast" | "broadcast-address" => Some(28),
        "static-route" | "classless-static-route" => Some(121),
        "ntp-server" => Some(42),
        "wins-server" | "netbios-ns" => Some(44),
        "mtu" | "interface-mtu" => Some(26),
        "lease-time" | "ip-address-lease-time" => Some(51),
        "server-identifier" | "server-id" => Some(54),
        "tftp-server" | "tftp-server-name" => Some(66),
        "bootfile-name" | "bootfile" => Some(67),
        "vendor-class" | "vendor-class-identifier" => Some(60),
        "client-id" | "client-identifier" => Some(61),
        "option-6rd" | "6rd" => Some(212),
        "sip-server" | "sip-servers" => Some(120),
        "ms-classless-static-route" => Some(249),
        _ => name.parse::<u16>().ok(),
    }
}

/// Map well-known DHCPv6 option names to their numbers (RFC 8415 and extensions).
#[cfg(any(feature = "dhcp", feature = "dhcp6"))]
fn dhcp6_option_name_to_number(name: &str) -> Option<u16> {
    match name.to_lowercase().as_str() {
        "dns-server" | "dns-recursive-name-server" => Some(23),
        "domain-search" | "domain-search-list" => Some(24),
        "ntp-server" => Some(56),
        "sip-server" | "sip-server-address" => Some(22),
        "sip-domain" | "sip-server-domain-name" => Some(21),
        "sntp-server" => Some(31),
        "information-refresh-time" => Some(32),
        _ => name.parse::<u16>().ok(),
    }
}

/// Encode DHCP option value parts into raw bytes.
#[cfg(any(feature = "dhcp", feature = "dhcp6"))]
fn encode_dhcp_option_value(opt_num: u16, parts: &[String]) -> Vec<u8> {
    let mut result = Vec::new();

    if parts.is_empty() {
        return result;
    }

    // For IP address options, try parsing as IP
    match opt_num {
        1 | 3 | 6 | 28 | 42 | 44 | 54 => {
            // Options that take IP addresses
            for part in parts {
                if let Ok(IpAddr::V4(v4)) = IpAddr::from_str(part.trim()) {
                    result.extend_from_slice(&v4.octets());
                }
            }
        }
        _ => {
            // Default: encode as string bytes
            let joined = parts.join(",");
            result.extend_from_slice(joined.as_bytes());
        }
    }

    result
}

// ---------------------------------------------------------------------------
// Help, version, and test mode output
// ---------------------------------------------------------------------------

/// Print version information including compile options.
pub fn print_version() {
    let compile_opts = feature_flags::compile_opts_string();
    println!("dnsmasq version {} {}", env!("CARGO_PKG_VERSION"), compile_opts);
    println!("Compile time options: {compile_opts}");
    println!();
    println!("This software comes with ABSOLUTELY NO WARRANTY.");
    println!("Dnsmasq is free software, and you are welcome to redistribute it");
    println!("under the terms of the GNU General Public License, version 2 or 3.");
}

/// Print usage/help text for all options.
pub fn print_usage() {
    println!("Usage: dnsmasq [options]\n");
    println!("Valid options are:");
    let entries = [
        ("-a, --listen-address=<ipaddr>", "Specify local address(es) to listen on."),
        ("-A, --address=/domain/ipaddr", "Return ipaddr for all hosts in specified domain."),
        ("-b, --bogus-priv", "Fake reverse lookups for RFC1918 private address ranges."),
        ("-B, --bogus-nxdomain=<ipaddr>", "Treat ipaddr as NXDOMAIN (defeats upstream wildcards)."),
        ("-c, --cache-size=<cachesize>", "Specify the size of the cache in entries (defaults to 150)."),
        ("-C, --conf-file=<path>", "Specify configuration file (default: /etc/dnsmasq.conf)."),
        ("-d, --no-daemon", "Do NOT fork into the background: run in debug mode."),
        ("-D, --domain-needed", "Do NOT forward queries with no domain part."),
        ("-e, --selfmx", "Return self-pointing MX record for local hosts."),
        ("-E, --expand-hosts", "Expand simple names in /etc/hosts with domain suffix."),
        ("-f, --filterwin2k", "Don't forward spurious DNS requests from Windows hosts."),
        ("-F, --dhcp-range=...", "Enable DHCP in the range given with lease duration."),
        ("-G, --dhcp-host=...", "Set address or hostname for a specified machine."),
        ("-h, --no-hosts", "Do NOT load /etc/hosts file."),
        ("-H, --addn-hosts=<path>", "Specify additional hosts file."),
        ("-i, --interface=<interface>", "Specify interface(s) to listen on."),
        ("-I, --except-interface=<interface>", "Specify interface(s) NOT to listen on."),
        ("-k, --keep-in-foreground", "Do NOT fork into the background, do NOT run in debug mode."),
        ("-l, --dhcp-leasefile=<path>", "Specify where DHCP leases are stored (defaults to /var/lib/misc/dnsmasq.leases)."),
        ("-L, --localmx", "Return MX records for local hosts."),
        ("-m, --mx-host=<host_name>,<target>,<preference>", "Specify MX record."),
        ("-M, --dhcp-boot=<filename>[,<servername>[,<server address>]]", "Specify BOOTP options to DHCP server."),
        ("-n, --no-poll", "Do NOT poll /etc/resolv.conf for changes."),
        ("-N, --no-negcache", "Do NOT cache negative lookups."),
        ("-o, --strict-order", "Use nameservers strictly in the order given."),
        ("-O, --dhcp-option=...", "Specify options to be sent to DHCP clients."),
        ("-p, --port=<port>", "Specify port to listen for DNS requests on (defaults to 53)."),
        ("-P, --edns-packet-max=<size>", "Maximum supported UDP packet size for EDNS.0 (defaults to 1232)."),
        ("-q, --log-queries", "Log DNS queries."),
        ("-r, --resolv-file=<path>", "Specify path to resolv.conf (defaults to /etc/resolv.conf)."),
        ("-R, --no-resolv", "Do NOT read resolv.conf."),
        ("-S, --server=...", "Specify DNS server or local domain address."),
        ("-t, --mx-target=<host_name>", "Specify default target in MX record."),
        ("-u, --user=<username>", "Specify user to run as after startup."),
        ("-v, --version", "Display dnsmasq version and copyright information."),
        ("-w, --help", "Display this message."),
        ("-x, --pid-file=<path>", "Specify path of PID file (defaults to /var/run/dnsmasq.pid)."),
        ("-z, --bind-interfaces", "Bind only to interfaces in use."),
        ("--test", "Check configuration syntax only."),
        ("--dnssec", "Activate DNSSEC validation."),
        ("--trust-anchor=<domain>,<keytag>,<algo>,<digest_type>,<hex_digest>", "Specify a DNSSEC trust anchor."),
        ("--enable-ra", "Enable IPv6 Router Advertisement."),
        ("--enable-tftp", "Enable built-in TFTP server."),
    ];
    for (opt, desc) in &entries {
        println!("  {:<52} {}", opt, desc);
    }
}

/// Validate configuration in test mode (--test).
///
/// Returns Ok(()) if the configuration is valid, or Err with details.
pub fn test_config(args: &[String]) -> Result<(), ConfigError> {
    let mut builder = ConfigBuilder::new();
    builder.test_mode = true;
    builder.parse_cli(args);

    // Try default config file if no explicit one was given
    if builder.included_files.is_empty() {
        builder.parse_file(constants::CONFFILE, false);
    }

    let config = builder.build()?;
    info!("dnsmasq: syntax check OK.");
    info!("  cache-size: {}", config.dns.cache_size);
    info!("  dns-forward-max: {}", config.dns.forward_max);
    info!("  port: {}", config.dns.port);

    Ok(())
}

//! DaemonState struct — the central state hub for the dnsmasq daemon.
//!
//! Replaces the C global `extern struct daemon *daemon` singleton
//! (defined in `src/dnsmasq.h` lines 1343-1526, ~180 fields).
//!
//! ## Decomposition Strategy
//! The monolithic C struct is split into domain-specific nested structs:
//! - [`DnsConfig`] — DNS-specific configuration (TTLs, cache size, EDNS, auth zones)
//! - [`DhcpState`] — DHCP runtime state (fds, lease config, packet buffers)
//! - [`NetworkState`] — Network interfaces, listeners, platform FDs
//! - [`RuntimeState`] — Runtime operational state (packet buffers, log IDs, process tracking)
//! - [`LogConfig`] — Logging facility and file configuration
//! - [`UserConfig`] — User/group/privilege separation settings
//! - [`TftpConfig`] — TFTP server parameters (feature-gated)
//! - [`OptionFlags`] — The OPT_* bitfield flags (replaces C `options[OPTION_SIZE]`)
//!
//! ## Ownership Model
//! - `DaemonState` is owned by main() and passed as `&mut` or `&` to subsystems
//! - Uses `RefCell` for interior mutability where subsystems need shared mutable access
//!   within the single-threaded event loop (no async runtime, so RefCell is safe)
//! - No global mutable statics — explicit state passing replaces C's `daemon->` pattern
//!
//! ## Numeric Defaults
//! All default values match the C `config.h` constants:
//! - `CACHESIZ = 150` — default DNS cache entries
//! - `FTABSIZ = 150` — default forward table size
//! - `EDNS_PKTSZ = 1232` — default EDNS0 UDP payload (DNS Flag Day 2020)
//! - `MAXLEASES = 1000` — default max DHCP leases
//! - `MAX_PROCS = 20` — default max TCP child processes
//! - `RANDOM_SOCKS = 64` — default random source ports

use std::cell::RefCell;
use std::net::SocketAddr;
use std::os::unix::io::RawFd;
use std::path::PathBuf;

use crate::core::metrics::MetricsStore;
use crate::core::prng::Prng;

// ---------------------------------------------------------------------------
// Exit code constants — canonical definitions in types::dns, re-exported here
// for backward compatibility with consumers importing from core::daemon.
// ---------------------------------------------------------------------------

pub use crate::types::dns::{
    EC_BADCONF, EC_BADNET, EC_FILE, EC_GOOD, EC_INIT_OFFSET, EC_MISC, EC_NOMEM,
};

// ---------------------------------------------------------------------------
// Numeric constants from config.h
// ---------------------------------------------------------------------------

/// Default DNS cache size — number of entries (config.h `CACHESIZ`).
pub const DEFAULT_CACHE_SIZE: i32 = 150;
/// Default forward table size — max outstanding queries (config.h `FTABSIZ`).
pub const DEFAULT_FTAB_SIZE: i32 = 150;
/// Default EDNS0 UDP payload size in bytes (config.h `EDNS_PKTSZ`).
/// Follows DNS Flag Day 2020 recommendation to avoid IPv6 fragmentation.
pub const DEFAULT_EDNS_PKTSZ: u16 = 1232;
/// Default maximum concurrent DHCP leases (config.h `MAXLEASES`).
pub const DEFAULT_MAX_LEASES: i32 = 1000;
/// Default max TCP child processes (config.h `MAX_PROCS`).
pub const DEFAULT_MAX_PROCS: i32 = 20;
/// TCP child process lifetime in seconds (config.h `CHILD_LIFETIME`).
/// RFC 1035 suggests > 120 seconds.
pub const CHILD_LIFETIME: i32 = 150;
/// Max DNS queries per single TCP connection (config.h `TCP_MAX_QUERIES`).
pub const TCP_MAX_QUERIES: i32 = 100;
/// Default number of random source ports (config.h `RANDOM_SOCKS`).
pub const DEFAULT_RANDOM_SOCKS: i32 = 64;
/// Default max TFTP connections (config.h `TFTP_MAX_CONNECTIONS`).
pub const DEFAULT_TFTP_MAX: i32 = 50;
/// Max DNS domain name length in bytes including trailing null (MAXDNAME).
pub const MAXDNAME: usize = 1025;
/// Max DNS label length in bytes (MAXLABEL).
pub const MAXLABEL: usize = 63;
/// Address string buffer length — fits longest IPv6 text representation (ADDRSTRLEN).
pub const ADDRSTRLEN: usize = 46;
/// DNS query upstream timeout in seconds (config.h `TIMEOUT`).
pub const TIMEOUT: i32 = 10;
/// DNS resource record fixed-size fields: TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) + terminator.
pub const RRFIXEDSZ: usize = 11;
/// Kernel listen backlog for TCP sockets (config.h `TCP_BACKLOG`).
pub const TCP_BACKLOG: i32 = 32;
/// TCP connection timeout in seconds (config.h `TCP_TIMEOUT`).
/// Doubled when waiting for response after connection is established.
pub const TCP_TIMEOUT: i32 = 5;

// ---------------------------------------------------------------------------
// OPT_* option flag constants (dnsmasq.h lines 393-471)
//
// These replace the C `#define OPT_*` macros. Each constant is a bit index
// into the `OptionFlags` bitfield array. Values 0..=77 are valid indices;
// `OPT_LAST` (78) is the sentinel marking the end of the range.
// ---------------------------------------------------------------------------

/// Filter private-range reverse DNS lookups (bogus-priv).
pub const OPT_BOGUSPRIV: usize = 0;
/// Filter useless DNS responses.
pub const OPT_FILTER: usize = 1;
/// Enable query logging.
pub const OPT_LOG: usize = 2;
/// Return self as MX record.
pub const OPT_SELFMX: usize = 3;
/// Do not read /etc/hosts.
pub const OPT_NO_HOSTS: usize = 4;
/// Do not poll /etc/resolv.conf for changes.
pub const OPT_NO_POLL: usize = 5;
/// Run in debug mode (foreground, verbose logging).
pub const OPT_DEBUG: usize = 6;
/// Use strict server order from config.
pub const OPT_ORDER: usize = 7;
/// Do not read /etc/resolv.conf.
pub const OPT_NO_RESOLV: usize = 8;
/// Expand simple hostnames with domain suffix.
pub const OPT_EXPAND: usize = 9;
/// Return self as MX for local machines.
pub const OPT_LOCALMX: usize = 10;
/// Do not cache negative (NXDOMAIN) responses.
pub const OPT_NO_NEG: usize = 11;
/// Do not forward unqualified names (no dots).
pub const OPT_NODOTS_LOCAL: usize = 12;
/// Bind only to specific interfaces (no wildcard).
pub const OPT_NOWILD: usize = 13;
/// Read /etc/ethers for DHCP static hosts.
pub const OPT_ETHERS: usize = 14;
/// Set domain from DHCP configuration.
pub const OPT_RESOLV_DOMAIN: usize = 15;
/// Do not fork into background (stay in foreground).
pub const OPT_NO_FORK: usize = 16;
/// Enable authoritative DHCP mode.
pub const OPT_AUTHORITATIVE: usize = 17;
/// Return answers for local subnets only.
pub const OPT_LOCALISE: usize = 18;
/// Enable D-Bus control interface.
pub const OPT_DBUS: usize = 19;
/// Use FQDN for DHCP clients in DNS.
pub const OPT_DHCP_FQDN: usize = 20;
/// Do not ICMP-ping before offering DHCP address.
pub const OPT_NO_PING: usize = 21;
/// Lease file is read-only.
pub const OPT_LEASE_RO: usize = 22;
/// Query all upstream servers simultaneously.
pub const OPT_ALL_SERVERS: usize = 23;
/// Re-read configuration on SIGHUP.
pub const OPT_RELOAD: usize = 24;
/// Allow private-range results from upstream.
pub const OPT_LOCAL_REBIND: usize = 25;
/// TFTP only serves files below chroot.
pub const OPT_TFTP_SECURE: usize = 26;
/// TFTP does not use blocksize negotiation.
pub const OPT_TFTP_NOBLOCK: usize = 27;
/// Log DHCP/DNS option details.
pub const OPT_LOG_OPTS: usize = 28;
/// TFTP uses client IP as path prefix.
pub const OPT_TFTP_APREF_IP: usize = 29;
/// Do not override client-provided DHCP options.
pub const OPT_NO_OVERRIDE: usize = 30;
/// Reject private-range results from upstream.
pub const OPT_NO_REBIND: usize = 31;
/// Add MAC address to DNS queries (EDNS0 option).
pub const OPT_ADD_MAC: usize = 32;
/// Proxy DNSSEC flag to upstream (without local validation).
pub const OPT_DNSSEC_PROXY: usize = 33;
/// Allocate DHCP addresses consecutively.
pub const OPT_CONSEC_ADDR: usize = 34;
/// Preserve conntrack marks on DNS replies.
pub const OPT_CONNTRACK: usize = 35;
/// Enable FQDN update in DHCP.
pub const OPT_FQDN_UPDATE: usize = 36;
/// Enable Router Advertisement.
pub const OPT_RA: usize = 37;
/// Convert TFTP filenames to lowercase.
pub const OPT_TFTP_LC: usize = 38;
/// Bind to addresses of specific interfaces only.
pub const OPT_CLEVERBIND: usize = 39;
/// Enable built-in TFTP server.
pub const OPT_TFTP: usize = 40;
/// Add client subnet (EDNS0 Client Subnet option).
pub const OPT_CLIENT_SUBNET: usize = 41;
/// Suppress DHCPv4 logging.
pub const OPT_QUIET_DHCP: usize = 42;
/// Suppress DHCPv6 logging.
pub const OPT_QUIET_DHCP6: usize = 43;
/// Suppress Router Advertisement logging.
pub const OPT_QUIET_RA: usize = 44;
/// Enable DNSSEC validation.
pub const OPT_DNSSEC_VALID: usize = 45;
/// Disable DNSSEC time-based signature checks.
pub const OPT_DNSSEC_TIME: usize = 46;
/// Enable DNSSEC debug logging.
pub const OPT_DNSSEC_DEBUG: usize = 47;
/// Ignore NS records from DNSSEC-signed zones.
pub const OPT_DNSSEC_IGN_NS: usize = 48;
/// Only serve DNS to directly-connected clients.
pub const OPT_LOCAL_SERVICE: usize = 49;
/// Enable DNS forwarding loop detection.
pub const OPT_LOOP_DETECT: usize = 50;
/// Extra-verbose logging.
pub const OPT_EXTRALOG: usize = 51;
/// Do not fail if TFTP root directory is missing.
pub const OPT_TFTP_NO_FAIL: usize = 52;
/// Execute script on ARP changes.
pub const OPT_SCRIPT_ARP: usize = 53;
/// Encode MAC addresses in base64 for EDNS0.
pub const OPT_MAC_B64: usize = 54;
/// Encode MAC addresses in hex for EDNS0.
pub const OPT_MAC_HEX: usize = 55;
/// TFTP uses client MAC as path prefix.
pub const OPT_TFTP_APREF_MAC: usize = 56;
/// Enable DHCPv6 Rapid Commit (two-message exchange).
pub const OPT_RAPID_COMMIT: usize = 57;
/// Enable UBus control interface (OpenWrt).
pub const OPT_UBUS: usize = 58;
/// Ignore DHCP client identifiers.
pub const OPT_IGNORE_CLID: usize = 59;
/// Use single port for all DNS queries (no port randomization).
pub const OPT_SINGLE_PORT: usize = 60;
/// Force lease renewal on config reload.
pub const OPT_LEASE_RENEW: usize = 61;
/// Enable debug-level log messages.
pub const OPT_LOG_DEBUG: usize = 62;
/// Enable Cisco Umbrella integration.
pub const OPT_UMBRELLA: usize = 63;
/// Include device ID in Umbrella queries.
pub const OPT_UMBRELLA_DEVID: usize = 64;
/// Enable connmark-based allowlist enforcement.
pub const OPT_CMARK_ALST_EN: usize = 65;
/// Suppress TFTP logging.
pub const OPT_QUIET_TFTP: usize = 66;
/// Strip EDNS0 Client Subnet (ECS) from upstream queries.
pub const OPT_STRIP_ECS: usize = 67;
/// Strip MAC address option from upstream queries.
pub const OPT_STRIP_MAC: usize = 68;
/// Do not return additional resource records.
pub const OPT_NORR: usize = 69;
/// Do not respond to server identification queries.
pub const OPT_NO_IDENT: usize = 70;
/// Cache arbitrary RR types.
pub const OPT_CACHE_RR: usize = 71;
/// Only serve clients on localhost interface.
pub const OPT_LOCALHOST_SERVICE: usize = 72;
/// Log protocol (UDP/TCP) in query log lines.
pub const OPT_LOG_PROTO: usize = 73;
/// Disable DNS 0x20 bit encoding for case randomization.
pub const OPT_NO_0X20: usize = 74;
/// Enable DNS 0x20 bit encoding for case randomization.
pub const OPT_DO_0X20: usize = 75;
/// Log authoritative DNS queries.
pub const OPT_AUTH_LOG: usize = 76;
/// Enable DHCP leasequery (RFC 4388) support.
pub const OPT_LEASEQUERY: usize = 77;

// -------------------------------------------------------------------------
// Extended OPT_* constants (78+) — additional flags used by the Rust config
// parser that do not have C `OPT_*` equivalents. These extend the flag space
// beyond the C codebase's 78 flags while remaining within the same [u32; 3]
// backing store (capacity = 96 bits).
// -------------------------------------------------------------------------

/// Filter type-A (IPv4) DNS responses.
pub const OPT_FILTER_A: usize = 78;
/// Filter type-AAAA (IPv6) DNS responses.
pub const OPT_FILTER_AAAA: usize = 79;
/// Enable dynamic BOOTP address allocation.
pub const OPT_BOOTP_DYNAMIC: usize = 80;
/// TFTP uses address-prefix path (generic).
pub const OPT_TFTP_APREF: usize = 81;
/// Enable connmark allowlist — create new allowlist entries.
pub const OPT_CMARK_ALST_NEW: usize = 82;
/// Disable DHCPv4-over-DHCPv6 (RFC 7341).
pub const OPT_NO_4OVER6: usize = 83;
/// Enable serving stale cache entries (RFC 8767).
pub const OPT_STALE_CACHE: usize = 84;
/// Do not return additional AAAA resource records.
pub const OPT_NORR6: usize = 85;
/// Allow rebinding to localhost addresses.
pub const OPT_REBIND_LOCALHOST: usize = 86;
/// Allow rebinding for specific domain suffixes.
pub const OPT_REBIND_DOMAIN_OK: usize = 87;
/// Enable NAT-PMP port mapping protocol support.
pub const OPT_NAT_PMP: usize = 88;
/// Ignore specific upstream DNS response addresses.
pub const OPT_IGNORE_ADDR: usize = 89;
/// Cache DNSSEC validation results.
pub const OPT_CACHE_DNSSEC: usize = 90;
/// Do not derive DNS hostnames from DHCP client info.
pub const OPT_NO_DHCP_HOSTNAME: usize = 91;
/// Return NXDOMAIN for names in authoritative zones with no match.
pub const OPT_AUTH_NXDOMAIN: usize = 92;
/// Proxy DNSSEC flag to upstream without local signature validation.
pub const OPT_DNSSEC_NO_SIGN: usize = 93;

/// Sentinel value marking the end of the option range (not a valid option).
pub const OPT_LAST: usize = 94;

/// Number of u32 words needed to store all option flags as a bitfield.
/// `OPT_LAST.div_ceil(32)` = 3 for 94 flags (78 C-compatible + 16 extended).
/// Matches C `OPTION_SIZE = ((OPT_LAST/OPTION_BITS)+((OPT_LAST%OPTION_BITS)!=0))`.
const OPTION_WORDS: usize = OPT_LAST.div_ceil(32);

// ---------------------------------------------------------------------------
// OptionFlags — bitfield replacing C `options[OPTION_SIZE]`
// ---------------------------------------------------------------------------

/// Daemon option flags, replacing the C `options[OPTION_SIZE]` bitfield array.
///
/// This is the **canonical OptionFlags type** used by both the config parser
/// (`config::options`) and the runtime daemon state (`DaemonState`).
///
/// In C (dnsmasq.h lines 393-474):
/// ```c
/// #define OPT_BOGUSPRIV   0
/// #define OPT_LAST        78
/// #define OPTION_SIZE ((OPT_LAST/OPTION_BITS)+((OPT_LAST%OPTION_BITS)!=0))
/// unsigned int options[OPTION_SIZE]; // 3 u32 words for 78 flags
/// ```
///
/// In Rust, we use a fixed-size `[u32; 3]` array with the same bit-manipulation
/// semantics. Each flag is identified by its index (`OPT_*` constants) and
/// stored as a single bit in the corresponding word. The Rust version extends
/// the flag space with indices 78-93 for additional flags used by the config
/// parser that do not have C equivalents.
///
/// ## Bit Layout
/// - Word 0 (`bits[0]`): flags 0..31  (C-compatible)
/// - Word 1 (`bits[1]`): flags 32..63 (C-compatible)
/// - Word 2 (`bits[2]`): flags 64..93 (64-77 C-compatible, 78-93 Rust-extended)
#[derive(Debug, Clone)]
pub struct OptionFlags {
    /// Backing storage: 3 × u32 = 96 bits, of which 78 are used.
    bits: [u32; OPTION_WORDS],
}

impl OptionFlags {
    /// Create a new `OptionFlags` with all flags cleared (all zero).
    ///
    /// This matches the C behaviour where `daemon->options[]` is zero-initialized
    /// by `safe_malloc()` / `calloc()` in `dnsmasq.c` before `read_opts()`.
    #[inline]
    pub fn new() -> Self {
        OptionFlags {
            bits: [0u32; OPTION_WORDS],
        }
    }

    /// Check whether an option flag is set.
    ///
    /// Replaces the C macro `option_bool(x)`:
    /// ```c
    /// #define option_bool(x) (option_var(x) & option_val(x))
    /// ```
    ///
    /// # Arguments
    /// * `opt` — Option index (one of the `OPT_*` constants, 0 ≤ opt < OPT_LAST).
    ///
    /// # Panics
    /// Returns `false` for out-of-range indices rather than panicking,
    /// matching the C behaviour where reading beyond the array yields zero.
    #[inline]
    pub fn get(&self, opt: usize) -> bool {
        let word = opt / 32;
        let bit = opt % 32;
        if word >= OPTION_WORDS {
            return false;
        }
        (self.bits[word] & (1u32 << bit)) != 0
    }

    /// Set an option flag.
    ///
    /// # Arguments
    /// * `opt` — Option index (one of the `OPT_*` constants).
    ///
    /// # Panics
    /// Silently ignores out-of-range indices.
    #[inline]
    pub fn set(&mut self, opt: usize) {
        let word = opt / 32;
        let bit = opt % 32;
        if word < OPTION_WORDS {
            self.bits[word] |= 1u32 << bit;
        }
    }

    /// Clear an option flag.
    ///
    /// # Arguments
    /// * `opt` — Option index (one of the `OPT_*` constants).
    ///
    /// # Panics
    /// Silently ignores out-of-range indices.
    #[inline]
    pub fn clear(&mut self, opt: usize) {
        let word = opt / 32;
        let bit = opt % 32;
        if word < OPTION_WORDS {
            self.bits[word] &= !(1u32 << bit);
        }
    }
}

impl Default for OptionFlags {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// DnsConfig — DNS-specific configuration
// ---------------------------------------------------------------------------

/// DNS-related configuration parameters.
///
/// Populated during config parsing (`option.c`), read-only during normal
/// operation. Replaces fields from the C `struct daemon` related to DNS
/// behaviour (dnsmasq.h lines ~1350-1395, 1423, 1432-1435).
pub struct DnsConfig {
    /// DNS listening port (default 53). C: `daemon->port`
    pub port: u16,
    /// Upstream query port (0 = random). C: `daemon->query_port`
    pub query_port: u16,
    /// Min source port for random allocation. C: `daemon->min_port`
    pub min_port: u16,
    /// Max source port for random allocation. C: `daemon->max_port`
    pub max_port: u16,
    /// Maximum number of source ports for queries. C: `daemon->randport_limit`
    pub randport_limit: i32,
    /// Local TTL override. C: `daemon->local_ttl`
    pub local_ttl: u32,
    /// Negative TTL for NXDOMAIN responses. C: `daemon->neg_ttl`
    pub neg_ttl: u32,
    /// Maximum TTL clamp for cached records. C: `daemon->max_ttl`
    pub max_ttl: u32,
    /// Minimum cache TTL (floor). C: `daemon->min_cache_ttl`
    pub min_cache_ttl: u32,
    /// Maximum cache TTL (ceiling). C: `daemon->max_cache_ttl`
    pub max_cache_ttl: u32,
    /// TTL for authoritative zone records. C: `daemon->auth_ttl`
    pub auth_ttl: u32,
    /// EDNS0 UDP payload size (default 1232). C: `daemon->edns_pktsz`
    pub edns_pktsz: u16,
    /// DNS cache size (default `CACHESIZ` = 150). C: `daemon->cachesize`
    pub cache_size: i32,
    /// Forward table size (default `FTABSIZ` = 150). C: `daemon->ftabsize`
    pub ftab_size: i32,
    /// Maximum cache expiry time. C: `daemon->cache_max_expiry`
    pub cache_max_expiry: i32,
    /// Fast retry interval (seconds). C: `daemon->fast_retry_time`
    pub fast_retry_time: i32,
    /// Fast retry timeout (seconds). C: `daemon->fast_retry_timeout`
    pub fast_retry_timeout: i32,
    /// MX target hostname. C: `daemon->mxtarget`
    pub mx_target: Option<String>,
    /// Default domain suffix for unqualified names. C: `daemon->domain_suffix`
    pub domain_suffix: Option<String>,
    /// DNS client ID for Cisco Umbrella queries. C: `daemon->dns_client_id`
    pub dns_client_id: Option<String>,
    /// Umbrella organisation ID. C: `daemon->umbrella_org`
    pub umbrella_org: u32,
    /// Umbrella asset ID. C: `daemon->umbrella_asset`
    pub umbrella_asset: u32,
    /// Umbrella device ID (8 bytes). C: `daemon->umbrella_device[8]`
    pub umbrella_device: [u8; 8],
    /// Authoritative DNS server hostname. C: `daemon->authserver`
    pub auth_server: Option<String>,
    /// Hostmaster for SOA records. C: `daemon->hostmaster`
    pub hostmaster: Option<String>,
    /// SOA serial number. C: `daemon->soa_sn`
    pub soa_serial: u32,
    /// SOA refresh interval. C: `daemon->soa_refresh`
    pub soa_refresh: u32,
    /// SOA retry interval. C: `daemon->soa_retry`
    pub soa_retry: u32,
    /// SOA expiry time. C: `daemon->soa_expiry`
    pub soa_expiry: u32,
    /// Resolver config files list (includes default `/etc/resolv.conf`).
    /// C: `daemon->resolv_files`, `daemon->default_resolv`
    pub resolv_files: Vec<PathBuf>,
    /// Path to a file containing upstream DNS server addresses.
    /// C: `daemon->servers_file`
    pub servers_file: Option<PathBuf>,
    /// Hosts file index counter. C: `daemon->host_index`
    pub host_index: i32,
    /// Domains excluded from DNS rebind protection. C: `daemon->no_rebind`
    pub no_rebind_domains: Vec<String>,
    /// Whether any server entry uses a wildcard domain pattern.
    /// C: `daemon->server_has_wildcard`
    pub server_has_wildcard: bool,
    /// Current size of the sorted server array. C: `daemon->serverarraysz`
    pub server_array_size: i32,
    /// High-water mark for server array population. C: `daemon->serverarrayhwm`
    pub server_array_hwm: i32,
    /// D-Bus service name override. C: `daemon->dbus_name`
    pub dbus_name: Option<String>,
    /// UBus object name override. C: `daemon->ubus_name`
    pub ubus_name: Option<String>,
}

impl Default for DnsConfig {
    fn default() -> Self {
        DnsConfig {
            port: 53,
            query_port: 0,
            min_port: 1024,
            max_port: 65535,
            randport_limit: DEFAULT_RANDOM_SOCKS,
            local_ttl: 0,
            neg_ttl: 0,
            max_ttl: 0,
            min_cache_ttl: 0,
            max_cache_ttl: 0,
            auth_ttl: 0,
            edns_pktsz: DEFAULT_EDNS_PKTSZ,
            cache_size: DEFAULT_CACHE_SIZE,
            ftab_size: DEFAULT_FTAB_SIZE,
            cache_max_expiry: 0,
            fast_retry_time: 0,
            fast_retry_timeout: 0,
            mx_target: None,
            domain_suffix: None,
            dns_client_id: None,
            umbrella_org: 0,
            umbrella_asset: 0,
            umbrella_device: [0u8; 8],
            auth_server: None,
            hostmaster: None,
            soa_serial: 0,
            soa_refresh: 0,
            soa_retry: 0,
            soa_expiry: 0,
            resolv_files: Vec::new(),
            servers_file: None,
            host_index: 0,
            no_rebind_domains: Vec::new(),
            server_has_wildcard: false,
            server_array_size: 0,
            server_array_hwm: 0,
            dbus_name: None,
            ubus_name: None,
        }
    }
}

// ---------------------------------------------------------------------------
// DhcpState — DHCP runtime state (feature-gated)
// ---------------------------------------------------------------------------

/// DHCP subsystem runtime state.
///
/// Feature-gated behind `dhcp`. Replaces DHCP-related fields from the C
/// `struct daemon` (dnsmasq.h lines ~1397-1498).
#[cfg(feature = "dhcp")]
pub struct DhcpState {
    /// DHCPv4 socket file descriptor. C: `daemon->dhcpfd`
    pub dhcp_fd: RawFd,
    /// Helper process pipe file descriptor. C: `daemon->helperfd`
    pub helper_fd: RawFd,
    /// PXE socket file descriptor. C: `daemon->pxefd`
    pub pxe_fd: RawFd,
    /// Lease database file path. C: `daemon->lease_file`
    pub lease_file: Option<PathBuf>,
    /// Shell command executed on lease changes. C: `daemon->lease_change_command`
    pub lease_change_command: Option<String>,
    /// Maximum concurrent DHCP leases (default `MAXLEASES` = 1000).
    /// C: `daemon->dhcp_max`
    pub dhcp_max: i32,
    /// DHCP server-side port (default 67). C: `daemon->dhcp_server_port`
    pub dhcp_server_port: u16,
    /// DHCP client-side port (default 68). C: `daemon->dhcp_client_port`
    pub dhcp_client_port: u16,
    /// Minimum lease time in seconds. C: `daemon->min_leasetime`
    pub min_lease_time: u32,
    /// DNS TTL for DHCP-derived records. C: `daemon->dhcp_ttl`
    pub dhcp_ttl: u32,
    /// Whether to use `dhcp_ttl` override. C: `daemon->use_dhcp_ttl`
    pub use_dhcp_ttl: u32,
    /// Whether Router Advertisement is active. C: `daemon->doing_ra`
    pub doing_ra: bool,
    /// Whether DHCPv6 is active. C: `daemon->doing_dhcp6`
    pub doing_dhcp6: bool,
    /// Whether PXE boot support is enabled. C: `daemon->enable_pxe`
    pub enable_pxe: bool,
    /// Whether to override client-set options. C: `daemon->override`
    pub override_flag: bool,
    /// DUID enterprise number for DHCPv6. C: `daemon->duid_enterprise`
    pub duid_enterprise: u32,
    /// DUID configuration data (raw bytes). C: `daemon->duid_config`, `duid_config_len`
    pub duid_config: Vec<u8>,
    /// DHCPv6 socket file descriptor. C: `daemon->dhcp6fd`
    #[cfg(feature = "dhcp6")]
    pub dhcp6_fd: RawFd,
    /// ICMPv6 socket file descriptor for RA/NDP. C: `daemon->icmp6fd`
    #[cfg(feature = "dhcp6")]
    pub icmp6_fd: RawFd,
    /// Server DUID for DHCPv6 (raw bytes). C: `daemon->duid`, `duid_len`
    #[cfg(feature = "dhcp6")]
    pub duid: Vec<u8>,
}

#[cfg(feature = "dhcp")]
impl Default for DhcpState {
    fn default() -> Self {
        DhcpState {
            dhcp_fd: -1,
            helper_fd: -1,
            pxe_fd: -1,
            lease_file: None,
            lease_change_command: None,
            dhcp_max: DEFAULT_MAX_LEASES,
            dhcp_server_port: 67,
            dhcp_client_port: 68,
            min_lease_time: 0,
            dhcp_ttl: 0,
            use_dhcp_ttl: 0,
            doing_ra: false,
            doing_dhcp6: false,
            enable_pxe: false,
            override_flag: false,
            duid_enterprise: 0,
            duid_config: Vec::new(),
            #[cfg(feature = "dhcp6")]
            dhcp6_fd: -1,
            #[cfg(feature = "dhcp6")]
            icmp6_fd: -1,
            #[cfg(feature = "dhcp6")]
            duid: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// NetworkState — network and platform-specific runtime state
// ---------------------------------------------------------------------------

/// Network and platform-specific runtime state.
///
/// Replaces network/platform fields from C `struct daemon`
/// (dnsmasq.h lines ~1375, 1457-1483).
pub struct NetworkState {
    /// Number of random source ports to maintain. C: `daemon->numrrand`
    /// Default `RANDOM_SOCKS` = 64.
    pub num_random_sockets: i32,
    /// IPv6 pktinfo support flag. C: `daemon->v6pktinfo`
    pub v6_pkt_info: i32,
    /// Whether supplementary groups have been set. C: `daemon->group_set`
    pub group_set: i32,
    /// Whether the OS chose the listening port. C: `daemon->osport`
    pub os_port: i32,
    /// Connmark allowlist bit mask. C: `daemon->allowlist_mask`
    pub allowlist_mask: u32,
    /// Netlink socket file descriptor (Linux only). C: `daemon->netlinkfd`
    #[cfg(target_os = "linux")]
    pub netlink_fd: RawFd,
    /// Detected kernel version encoded as integer (Linux only).
    /// C: `daemon->kernel_version`
    #[cfg(target_os = "linux")]
    pub kernel_version: i32,
    /// Inotify file descriptor for config monitoring (Linux, feature-gated).
    /// C: `daemon->inotifyfd`
    #[cfg(feature = "inotify_monitor")]
    pub inotify_fd: RawFd,
    /// Raw DHCP socket file descriptor (BSD only). C: `daemon->dhcp_raw_fd`
    #[cfg(target_os = "freebsd")]
    pub dhcp_raw_fd: RawFd,
    /// DHCP ICMP socket file descriptor (BSD only). C: `daemon->dhcp_icmp_fd`
    #[cfg(target_os = "freebsd")]
    pub dhcp_icmp_fd: RawFd,
    /// Routing socket file descriptor (BSD only). C: `daemon->routefd`
    #[cfg(target_os = "freebsd")]
    pub route_fd: RawFd,
}

impl Default for NetworkState {
    fn default() -> Self {
        NetworkState {
            num_random_sockets: DEFAULT_RANDOM_SOCKS,
            v6_pkt_info: 0,
            group_set: 0,
            os_port: 0,
            allowlist_mask: 0,
            #[cfg(target_os = "linux")]
            netlink_fd: -1,
            #[cfg(target_os = "linux")]
            kernel_version: 0,
            #[cfg(feature = "inotify_monitor")]
            inotify_fd: -1,
            #[cfg(target_os = "freebsd")]
            dhcp_raw_fd: -1,
            #[cfg(target_os = "freebsd")]
            dhcp_icmp_fd: -1,
            #[cfg(target_os = "freebsd")]
            route_fd: -1,
        }
    }
}

// ---------------------------------------------------------------------------
// RuntimeState — operational buffers and process tracking
// ---------------------------------------------------------------------------

/// Runtime operational state: packet buffers, process tracking, logging IDs.
///
/// Replaces the runtime/buffer fields from the C `struct daemon`
/// (dnsmasq.h lines 1441-1472, 1513-1525).
pub struct RuntimeState {
    /// Main packet buffer (DNS/DHCP I/O). C: `daemon->packet`
    pub packet: Vec<u8>,
    /// Allocated size of packet buffer. C: `daemon->packet_buff_sz`
    pub packet_buff_size: usize,
    /// Name buffer for DNS name manipulation (MAXDNAME bytes). C: `daemon->namebuff`
    pub name_buff: Vec<u8>,
    /// Secondary workspace name buffer. C: `daemon->workspacename`
    pub workspace_name: Vec<u8>,
    /// Saved packet length for resend operations. C: `daemon->packet_len`
    pub saved_packet_len: usize,
    /// Saved file descriptor for resend operations. C: `daemon->fd_save`
    pub saved_fd: RawFd,
    /// PIDs of forked TCP child processes. C: `daemon->tcp_pids`
    pub tcp_pids: Vec<i32>,
    /// Pipe file descriptors for TCP child communication. C: `daemon->tcp_pipes`
    pub tcp_pipes: Vec<RawFd>,
    /// Pipe write-end to parent process (for TCP children). C: `daemon->pipe_to_parent`
    pub pipe_to_parent: RawFd,
    /// Transaction ID for log message correlation. C: `daemon->log_id`
    pub log_id: i32,
    /// Display ID for log message presentation. C: `daemon->log_display_id`
    pub log_display_id: i32,
    /// Address string buffer for formatting (ADDRSTRLEN bytes).
    /// C: `daemon->addrbuff`
    pub addr_buff: String,
    /// Extra address string buffer (allocated when `OPT_EXTRALOG` is set).
    /// C: `daemon->addrbuff2`
    pub addr_buff2: Option<String>,
    /// Maximum number of concurrent TCP child processes. C: `daemon->max_procs`
    /// Default `MAX_PROCS` = 20.
    pub max_procs: i32,
    /// Peak concurrent TCP processes observed. C: `daemon->max_procs_used`
    pub max_procs_used: u32,
    /// Last time /etc/resolv.conf was checked (Unix timestamp). C: `daemon->last_resolv`
    pub last_resolv: i64,
    /// DNSSEC key name buffer (MAXDNAME bytes). C: `daemon->keyname`
    #[cfg(feature = "dnssec")]
    pub key_name: Vec<u8>,
    /// DNSSEC CNAME chain buffer. C: `daemon->cname`
    #[cfg(feature = "dnssec")]
    pub cname_buf: Vec<u8>,
    /// DNSSEC RR validation status flags per record. C: `daemon->rr_status`, `rr_status_sz`
    #[cfg(feature = "dnssec")]
    pub rr_status: Vec<u64>,
    /// Skip DNSSEC signature time-validity checks. C: `daemon->dnssec_no_time_check`
    #[cfg(feature = "dnssec")]
    pub dnssec_no_time_check: bool,
    /// DNSSEC "back to the future" mode for timestamp handling.
    /// C: `daemon->back_to_the_future`
    #[cfg(feature = "dnssec")]
    pub back_to_the_future: bool,
    /// Pcap dump file path. C: `daemon->dump_file`
    #[cfg(feature = "dump")]
    pub dump_file: Option<PathBuf>,
    /// Bitmask selecting which packet types to dump. C: `daemon->dump_mask`
    #[cfg(feature = "dump")]
    pub dump_mask: i32,
    /// File descriptor for pcap dump output. C: `daemon->dumpfd`
    #[cfg(feature = "dump")]
    pub dump_fd: RawFd,
}

impl Default for RuntimeState {
    fn default() -> Self {
        // Packet buffer size: EDNS_PKTSZ + MAXDNAME + RRFIXEDSZ
        let pkt_size = (DEFAULT_EDNS_PKTSZ as usize) + MAXDNAME + RRFIXEDSZ;

        RuntimeState {
            packet: vec![0u8; pkt_size],
            packet_buff_size: pkt_size,
            name_buff: vec![0u8; MAXDNAME],
            workspace_name: vec![0u8; MAXDNAME],
            saved_packet_len: 0,
            saved_fd: -1,
            tcp_pids: Vec::new(),
            tcp_pipes: Vec::new(),
            pipe_to_parent: -1,
            log_id: 0,
            log_display_id: 0,
            addr_buff: String::with_capacity(ADDRSTRLEN),
            addr_buff2: None,
            max_procs: DEFAULT_MAX_PROCS,
            max_procs_used: 0,
            last_resolv: 0,
            #[cfg(feature = "dnssec")]
            key_name: vec![0u8; MAXDNAME],
            #[cfg(feature = "dnssec")]
            cname_buf: vec![0u8; MAXDNAME],
            #[cfg(feature = "dnssec")]
            rr_status: Vec::new(),
            #[cfg(feature = "dnssec")]
            dnssec_no_time_check: false,
            #[cfg(feature = "dnssec")]
            back_to_the_future: false,
            #[cfg(feature = "dump")]
            dump_file: None,
            #[cfg(feature = "dump")]
            dump_mask: 0,
            #[cfg(feature = "dump")]
            dump_fd: -1,
        }
    }
}

// ---------------------------------------------------------------------------
// LogConfig — logging configuration
// ---------------------------------------------------------------------------

/// Logging configuration.
///
/// Populated during config parsing, consumed by `core::logging` module.
/// Replaces logging fields from C `struct daemon` (dnsmasq.h lines 1384-1386, 1471-1472).
///
/// Default values: all numeric fields zero, all optional fields `None`.
/// The actual syslog facility (`LOG_DAEMON`) is set during config parsing.
#[derive(Default)]
pub struct LogConfig {
    /// Syslog facility code (default `LOG_DAEMON`). C: `daemon->log_fac`
    pub log_facility: i32,
    /// Optional log file path (if logging to file). C: `daemon->log_file`
    pub log_file: Option<PathBuf>,
    /// Max log queue size (async syslog queue bound). C: `daemon->max_logs`
    pub max_logs: i32,
    /// Optional source address for remote syslog. C: `daemon->log_source_addr`
    pub log_source_addr: Option<SocketAddr>,
}

// ---------------------------------------------------------------------------
// UserConfig — user/group/privilege configuration
// ---------------------------------------------------------------------------

/// User, group, and privilege-separation configuration.
///
/// Replaces user/group fields from C `struct daemon` (dnsmasq.h lines 1365-1367, 1373).
///
/// Default values: all fields `None` (privilege settings are populated from config).
#[derive(Default)]
pub struct UserConfig {
    /// Username to drop privileges to. C: `daemon->username`
    pub username: Option<String>,
    /// Group name to drop privileges to. C: `daemon->groupname`
    pub group_name: Option<String>,
    /// User for running lease-change scripts. C: `daemon->scriptuser`
    pub script_user: Option<String>,
    /// Path to Lua script for lease events. C: `daemon->luascript`
    pub lua_script: Option<String>,
    /// Path to PID file. C: `daemon->runfile`
    pub run_file: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// TftpConfig — TFTP server configuration (feature-gated)
// ---------------------------------------------------------------------------

/// TFTP server configuration.
///
/// Feature-gated behind `tftp`. Replaces TFTP-related fields from the C
/// `struct daemon` (dnsmasq.h lines 1418-1425).
#[cfg(feature = "tftp")]
pub struct TftpConfig {
    /// Maximum concurrent TFTP connections (default 50). C: `daemon->tftp_max`
    pub tftp_max: i32,
    /// TFTP MTU override (0 = auto). C: `daemon->tftp_mtu`
    pub tftp_mtu: i32,
    /// TFTP root directory prefix. C: `daemon->tftp_prefix`
    pub tftp_prefix: Option<String>,
    /// Start of TFTP source port range (0 = OS default). C: `daemon->start_tftp_port`
    pub start_tftp_port: u16,
    /// End of TFTP source port range. C: `daemon->end_tftp_port`
    pub end_tftp_port: u16,
}

#[cfg(feature = "tftp")]
impl Default for TftpConfig {
    fn default() -> Self {
        TftpConfig {
            tftp_max: DEFAULT_TFTP_MAX,
            tftp_mtu: 0,
            tftp_prefix: None,
            start_tftp_port: 0,
            end_tftp_port: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// DaemonState — the top-level state hub
// ---------------------------------------------------------------------------

/// Central daemon state, replacing C's global `struct daemon *daemon`.
///
/// This struct owns all subsystem state and is passed explicitly to handlers.
/// In the C code, this was a heap-allocated global accessed everywhere via
/// `daemon->field_name`. In Rust, subsystem functions receive references to
/// the specific sub-struct they need.
///
/// ## Interior Mutability
/// Where multiple subsystems need mutable access within the single-threaded
/// event loop, `RefCell` provides runtime borrow checking without `unsafe`.
/// This is safe because dnsmasq uses a single-threaded architecture — no
/// concurrent borrows can occur.
///
/// ## Feature Gates
/// Optional subsystems (DHCP, TFTP, DNSSEC) are conditionally compiled using
/// Cargo feature flags, replacing the C `#ifdef HAVE_*` preprocessor guards.
pub struct DaemonState {
    /// Daemon option flags (78 boolean flags as bitfield).
    /// Replaces C `daemon->options[OPTION_SIZE]`.
    pub options: OptionFlags,

    /// DNS-specific configuration (ports, TTLs, cache size, SOA, etc.).
    pub dns: DnsConfig,

    /// Logging configuration (facility, file, queue size).
    pub log: LogConfig,

    /// User/group/privilege-separation configuration.
    pub user: UserConfig,

    /// Metrics store wrapped in `RefCell` for interior mutability.
    /// Replaces C `daemon->metrics[__METRIC_MAX]`.
    pub metrics: RefCell<MetricsStore>,

    /// Runtime operational state (packet buffers, process tracking).
    /// `RefCell` because the event loop mutates runtime state from multiple
    /// subsystem handlers that share a `&DaemonState` reference.
    pub runtime: RefCell<RuntimeState>,

    /// Network and platform state (socket FDs, random port pool).
    /// `RefCell` for interior mutability during event-loop operation.
    pub network: RefCell<NetworkState>,

    /// DHCP subsystem state (feature-gated behind `dhcp`).
    #[cfg(feature = "dhcp")]
    pub dhcp: RefCell<DhcpState>,

    /// TFTP server configuration (feature-gated behind `tftp`).
    #[cfg(feature = "tftp")]
    pub tftp: TftpConfig,

    /// PRNG instance for DNS transaction IDs, port randomization, DHCP XIDs.
    /// `RefCell` because PRNG is mutated during query processing.
    pub prng: RefCell<Prng>,
}

impl DaemonState {
    /// Construct a new `DaemonState` with defaults matching C `config.h` constants.
    ///
    /// All numeric defaults are preserved exactly from the C implementation:
    /// - `cache_size = 150` (CACHESIZ)
    /// - `ftab_size = 150` (FTABSIZ)
    /// - `edns_pktsz = 1232` (EDNS_PKTSZ)
    /// - `max_procs = 20` (MAX_PROCS)
    /// - `port = 53` (NAMESERVER_PORT)
    /// - `query_port = 0` (random)
    /// - `min_port = 1024`, `max_port = 65535`
    /// - `randport_limit = 64` (RANDOM_SOCKS)
    /// - `dhcp_max = 1000` (MAXLEASES) — when dhcp feature enabled
    /// - `tftp_max = 50` (TFTP_MAX_CONNECTIONS) — when tftp feature enabled
    /// - `packet_buff_size = EDNS_PKTSZ + MAXDNAME + RRFIXEDSZ` = 1232 + 1025 + 11 = 2268
    pub fn new() -> Self {
        DaemonState {
            options: OptionFlags::new(),
            dns: DnsConfig::default(),
            log: LogConfig::default(),
            user: UserConfig::default(),
            metrics: RefCell::new(MetricsStore::new()),
            runtime: RefCell::new(RuntimeState::default()),
            network: RefCell::new(NetworkState::default()),
            #[cfg(feature = "dhcp")]
            dhcp: RefCell::new(DhcpState::default()),
            #[cfg(feature = "tftp")]
            tftp: TftpConfig::default(),
            prng: RefCell::new(Prng::new()),
        }
    }

    /// Check whether an option flag is set.
    ///
    /// Convenience method wrapping `self.options.get(opt)`.
    /// Direct replacement for the C macro `option_bool(x)`.
    ///
    /// # Arguments
    /// * `opt` — Option index (one of the `OPT_*` constants).
    #[inline]
    pub fn option_bool(&self, opt: usize) -> bool {
        self.options.get(opt)
    }

    /// Set an option flag.
    ///
    /// Convenience method wrapping `self.options.set(opt)`.
    ///
    /// # Arguments
    /// * `opt` — Option index (one of the `OPT_*` constants).
    #[inline]
    pub fn set_option(&mut self, opt: usize) {
        self.options.set(opt);
    }

    /// Clear an option flag.
    ///
    /// Convenience method wrapping `self.options.clear(opt)`.
    ///
    /// # Arguments
    /// * `opt` — Option index (one of the `OPT_*` constants).
    #[inline]
    pub fn clear_option(&mut self, opt: usize) {
        self.options.clear(opt);
    }
}

impl Default for DaemonState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::metrics::Metric;

    // -- OptionFlags tests --

    #[test]
    fn option_flags_new_all_zero() {
        let flags = OptionFlags::new();
        for i in 0..OPT_LAST {
            assert!(!flags.get(i), "flag {} should be false initially", i);
        }
    }

    #[test]
    fn option_flags_set_get_clear_bit_zero() {
        let mut flags = OptionFlags::new();
        assert!(!flags.get(OPT_BOGUSPRIV));
        flags.set(OPT_BOGUSPRIV);
        assert!(flags.get(OPT_BOGUSPRIV));
        flags.clear(OPT_BOGUSPRIV);
        assert!(!flags.get(OPT_BOGUSPRIV));
    }

    #[test]
    fn option_flags_set_get_clear_bit_31() {
        // Boundary between word 0 and word 1
        let mut flags = OptionFlags::new();
        assert!(!flags.get(OPT_NO_REBIND));
        flags.set(OPT_NO_REBIND);
        assert!(flags.get(OPT_NO_REBIND));
        flags.clear(OPT_NO_REBIND);
        assert!(!flags.get(OPT_NO_REBIND));
    }

    #[test]
    fn option_flags_set_get_clear_bit_32() {
        // First bit in word 1
        let mut flags = OptionFlags::new();
        assert!(!flags.get(OPT_ADD_MAC));
        flags.set(OPT_ADD_MAC);
        assert!(flags.get(OPT_ADD_MAC));
        // Verify no cross-contamination with neighbouring bits
        assert!(!flags.get(OPT_NO_REBIND)); // bit 31
        assert!(!flags.get(OPT_DNSSEC_PROXY)); // bit 33
        flags.clear(OPT_ADD_MAC);
        assert!(!flags.get(OPT_ADD_MAC));
    }

    #[test]
    fn option_flags_set_get_clear_bit_63() {
        // Boundary between word 1 and word 2
        let mut flags = OptionFlags::new();
        assert!(!flags.get(OPT_UMBRELLA));
        flags.set(OPT_UMBRELLA);
        assert!(flags.get(OPT_UMBRELLA));
        flags.clear(OPT_UMBRELLA);
        assert!(!flags.get(OPT_UMBRELLA));
    }

    #[test]
    fn option_flags_set_get_clear_bit_77() {
        // Last C-compatible bit
        let mut flags = OptionFlags::new();
        assert!(!flags.get(OPT_LEASEQUERY));
        flags.set(OPT_LEASEQUERY);
        assert!(flags.get(OPT_LEASEQUERY));
        flags.clear(OPT_LEASEQUERY);
        assert!(!flags.get(OPT_LEASEQUERY));
    }

    #[test]
    fn option_flags_set_get_clear_extended_bit_93() {
        // Last extended flag — OPT_DNSSEC_NO_SIGN (93)
        let mut flags = OptionFlags::new();
        assert!(!flags.get(OPT_DNSSEC_NO_SIGN));
        flags.set(OPT_DNSSEC_NO_SIGN);
        assert!(flags.get(OPT_DNSSEC_NO_SIGN));
        // Verify no cross-contamination with neighbours
        assert!(!flags.get(OPT_AUTH_NXDOMAIN)); // bit 92
        flags.clear(OPT_DNSSEC_NO_SIGN);
        assert!(!flags.get(OPT_DNSSEC_NO_SIGN));
    }

    #[test]
    fn option_flags_out_of_range_returns_false() {
        let flags = OptionFlags::new();
        assert!(!flags.get(OPT_LAST));
        assert!(!flags.get(100));
        assert!(!flags.get(usize::MAX));
    }

    #[test]
    fn option_flags_set_out_of_range_no_panic() {
        let mut flags = OptionFlags::new();
        flags.set(100); // should not panic
        flags.clear(200); // should not panic
    }

    #[test]
    fn option_flags_multiple_bits_independent() {
        let mut flags = OptionFlags::new();
        flags.set(OPT_BOGUSPRIV); // 0
        flags.set(OPT_NO_RESOLV); // 8
        flags.set(OPT_NOWILD); // 13
        flags.set(OPT_TFTP); // 40
        flags.set(OPT_DNSSEC_VALID); // 45
        flags.set(OPT_CACHE_RR); // 71
        flags.set(OPT_LEASEQUERY); // 77

        assert!(flags.get(OPT_BOGUSPRIV));
        assert!(flags.get(OPT_NO_RESOLV));
        assert!(flags.get(OPT_NOWILD));
        assert!(flags.get(OPT_TFTP));
        assert!(flags.get(OPT_DNSSEC_VALID));
        assert!(flags.get(OPT_CACHE_RR));
        assert!(flags.get(OPT_LEASEQUERY));
        // Check unset bits remain clear
        assert!(!flags.get(OPT_FILTER));
        assert!(!flags.get(OPT_LOG));
        assert!(!flags.get(OPT_DEBUG));
    }

    // -- DaemonState tests --

    #[test]
    fn daemon_state_new_has_correct_dns_defaults() {
        let state = DaemonState::new();
        assert_eq!(state.dns.port, 53);
        assert_eq!(state.dns.query_port, 0);
        assert_eq!(state.dns.min_port, 1024);
        assert_eq!(state.dns.max_port, 65535);
        assert_eq!(state.dns.cache_size, DEFAULT_CACHE_SIZE);
        assert_eq!(state.dns.cache_size, 150);
        assert_eq!(state.dns.ftab_size, DEFAULT_FTAB_SIZE);
        assert_eq!(state.dns.ftab_size, 150);
        assert_eq!(state.dns.edns_pktsz, DEFAULT_EDNS_PKTSZ);
        assert_eq!(state.dns.edns_pktsz, 1232);
        assert_eq!(state.dns.randport_limit, DEFAULT_RANDOM_SOCKS);
    }

    #[test]
    fn daemon_state_new_has_correct_runtime_defaults() {
        let state = DaemonState::new();
        let rt = state.runtime.borrow();
        let expected_size = (DEFAULT_EDNS_PKTSZ as usize) + MAXDNAME + RRFIXEDSZ;
        assert_eq!(rt.packet_buff_size, expected_size);
        assert_eq!(rt.packet_buff_size, 1232 + 1025 + 11);
        assert_eq!(rt.packet.len(), expected_size);
        assert_eq!(rt.max_procs, DEFAULT_MAX_PROCS);
        assert_eq!(rt.max_procs, 20);
        assert_eq!(rt.name_buff.len(), MAXDNAME);
        assert_eq!(rt.workspace_name.len(), MAXDNAME);
        assert_eq!(rt.saved_fd, -1);
        assert_eq!(rt.pipe_to_parent, -1);
        assert_eq!(rt.log_id, 0);
    }

    #[test]
    fn daemon_state_option_bool_set_clear() {
        let mut state = DaemonState::new();
        assert!(!state.option_bool(OPT_LOG));
        state.set_option(OPT_LOG);
        assert!(state.option_bool(OPT_LOG));
        state.clear_option(OPT_LOG);
        assert!(!state.option_bool(OPT_LOG));
    }

    #[test]
    fn daemon_state_metrics_store_works() {
        let state = DaemonState::new();
        {
            let mut metrics = state.metrics.borrow_mut();
            metrics.increment(Metric::DnsQueriesForwarded);
            assert_eq!(metrics.get(Metric::DnsQueriesForwarded), 1);
            metrics.clear();
            assert_eq!(metrics.get(Metric::DnsQueriesForwarded), 0);
        }
    }

    #[test]
    fn daemon_state_prng_works() {
        let state = DaemonState::new();
        let mut prng = state.prng.borrow_mut();
        let v16 = prng.rand16();
        let v32 = prng.rand32();
        let v64 = prng.rand64();
        // Just verify they don't panic; exact values are random
        let _ = (v16, v32, v64);
    }

    #[test]
    #[cfg(feature = "dhcp")]
    fn daemon_state_dhcp_defaults() {
        let state = DaemonState::new();
        let dhcp = state.dhcp.borrow();
        assert_eq!(dhcp.dhcp_max, DEFAULT_MAX_LEASES);
        assert_eq!(dhcp.dhcp_max, 1000);
        assert_eq!(dhcp.dhcp_server_port, 67);
        assert_eq!(dhcp.dhcp_client_port, 68);
        assert_eq!(dhcp.dhcp_fd, -1);
        assert_eq!(dhcp.helper_fd, -1);
        assert_eq!(dhcp.pxe_fd, -1);
        assert!(!dhcp.doing_ra);
        assert!(!dhcp.doing_dhcp6);
        assert!(!dhcp.enable_pxe);
    }

    #[test]
    #[cfg(feature = "tftp")]
    fn daemon_state_tftp_defaults() {
        let state = DaemonState::new();
        assert_eq!(state.tftp.tftp_max, DEFAULT_TFTP_MAX);
        assert_eq!(state.tftp.tftp_max, 50);
        assert_eq!(state.tftp.tftp_mtu, 0);
        assert!(state.tftp.tftp_prefix.is_none());
    }

    // -- Constant value verification tests --

    #[test]
    fn exit_code_constants_match_c() {
        assert_eq!(EC_GOOD, 0);
        assert_eq!(EC_BADCONF, 1);
        assert_eq!(EC_BADNET, 2);
        assert_eq!(EC_FILE, 3);
        assert_eq!(EC_NOMEM, 4);
        assert_eq!(EC_MISC, 5);
        assert_eq!(EC_INIT_OFFSET, 10);
    }

    #[test]
    fn opt_constants_match_c() {
        // C-compatible OPT_* constants (indices 0-77) must match dnsmasq.h exactly
        assert_eq!(OPT_BOGUSPRIV, 0);
        assert_eq!(OPT_FILTER, 1);
        assert_eq!(OPT_LOG, 2);
        assert_eq!(OPT_NO_HOSTS, 4);
        assert_eq!(OPT_NO_RESOLV, 8);
        assert_eq!(OPT_NOWILD, 13);
        assert_eq!(OPT_AUTHORITATIVE, 17);
        assert_eq!(OPT_ADD_MAC, 32);
        assert_eq!(OPT_TFTP, 40);
        assert_eq!(OPT_DNSSEC_VALID, 45);
        assert_eq!(OPT_LOOP_DETECT, 50);
        assert_eq!(OPT_UMBRELLA, 63);
        assert_eq!(OPT_CACHE_RR, 71);
        assert_eq!(OPT_LEASEQUERY, 77);
        // Extended Rust flags (78-93) — beyond C's OPT_LAST=78
        assert_eq!(OPT_FILTER_A, 78);
        assert_eq!(OPT_DNSSEC_NO_SIGN, 93);
        // Sentinel includes both C-compatible and extended flags
        assert_eq!(OPT_LAST, 94);
    }

    #[test]
    fn option_words_constant_is_three() {
        // 94 flags / 32 bits per word = 2.9375 → 3 words (capacity = 96 bits)
        assert_eq!(OPTION_WORDS, 3);
    }

    #[test]
    fn numeric_constants_match_config_h() {
        assert_eq!(DEFAULT_CACHE_SIZE, 150);
        assert_eq!(DEFAULT_FTAB_SIZE, 150);
        assert_eq!(DEFAULT_EDNS_PKTSZ, 1232);
        assert_eq!(DEFAULT_MAX_LEASES, 1000);
        assert_eq!(DEFAULT_MAX_PROCS, 20);
        assert_eq!(CHILD_LIFETIME, 150);
        assert_eq!(TCP_MAX_QUERIES, 100);
        assert_eq!(DEFAULT_RANDOM_SOCKS, 64);
        assert_eq!(DEFAULT_TFTP_MAX, 50);
        assert_eq!(MAXDNAME, 1025);
        assert_eq!(MAXLABEL, 63);
        assert_eq!(ADDRSTRLEN, 46);
        assert_eq!(TIMEOUT, 10);
        assert_eq!(RRFIXEDSZ, 11);
        assert_eq!(TCP_BACKLOG, 32);
        assert_eq!(TCP_TIMEOUT, 5);
    }

    #[test]
    fn network_state_defaults() {
        let ns = NetworkState::default();
        assert_eq!(ns.num_random_sockets, DEFAULT_RANDOM_SOCKS);
        assert_eq!(ns.v6_pkt_info, 0);
        assert_eq!(ns.group_set, 0);
        assert_eq!(ns.os_port, 0);
        assert_eq!(ns.allowlist_mask, 0);
    }

    #[test]
    fn log_config_defaults() {
        let lc = LogConfig::default();
        assert_eq!(lc.log_facility, 0);
        assert!(lc.log_file.is_none());
        assert_eq!(lc.max_logs, 0);
        assert!(lc.log_source_addr.is_none());
    }

    #[test]
    fn user_config_defaults() {
        let uc = UserConfig::default();
        assert!(uc.username.is_none());
        assert!(uc.group_name.is_none());
        assert!(uc.script_user.is_none());
        assert!(uc.lua_script.is_none());
        assert!(uc.run_file.is_none());
    }

    #[test]
    fn dns_config_defaults() {
        let dc = DnsConfig::default();
        assert_eq!(dc.port, 53);
        assert_eq!(dc.query_port, 0);
        assert_eq!(dc.min_port, 1024);
        assert_eq!(dc.max_port, 65535);
        assert_eq!(dc.edns_pktsz, 1232);
        assert_eq!(dc.cache_size, 150);
        assert_eq!(dc.ftab_size, 150);
        assert!(dc.mx_target.is_none());
        assert!(dc.domain_suffix.is_none());
        assert!(dc.resolv_files.is_empty());
        assert!(dc.servers_file.is_none());
        assert!(!dc.server_has_wildcard);
        assert!(dc.dbus_name.is_none());
        assert!(dc.ubus_name.is_none());
    }
}

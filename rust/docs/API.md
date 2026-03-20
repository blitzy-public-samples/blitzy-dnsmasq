# Internal API Reference

> **dnsmasq v2.92 — Memory-Safe Rust Implementation**

This document provides comprehensive internal API documentation for the dnsmasq Rust
implementation. It covers the public Rust API surface of every module, with function
signatures, type definitions, and purpose descriptions derived from the original C source
code inline comments across all 50 source files (42 `.c` + 8 `.h`).

For the module hierarchy and dependency graph, see [ARCHITECTURE.md](ARCHITECTURE.md).
For the C-to-Rust pattern mapping, see [MIGRATION.md](MIGRATION.md). For full
auto-generated Rustdoc, run `cargo doc --open` from the `rust/` directory.

---

## Table of Contents

- [1. Core Module (`crate::core`)](#1-core-module-cratecore)
- [2. Config Module (`crate::config`)](#2-config-module-crateconfig)
- [3. DNS Module (`crate::dns`)](#3-dns-module-cratedns)
- [4. DHCP Module (`crate::dhcp`)](#4-dhcp-module-cratedhcp)
- [5. Network Module (`crate::network`)](#5-network-module-cratenetwork)
- [6. Integration Module (`crate::integration`)](#6-integration-module-crateintegration)
- [7. Services Module (`crate::services`)](#7-services-module-crateservices)
- [8. Diagnostics Module (`crate::diagnostics`)](#8-diagnostics-module-cratediagnostics)
- [9. Error Types](#9-error-types)
- [10. Trait Definitions](#10-trait-definitions)
- [11. Cross-References](#11-cross-references)

---

## 1. Core Module (`crate::core`)

The core module provides the daemon runtime, global type definitions, logging, event
handling, and shared utility functions. All other modules depend on `core` for
foundational types and services.

### 1.1 `core::daemon`

**Source:** `src/dnsmasq.c` (3,827 lines) — main entry point, event loop, signal handling,
initialization and teardown.

#### Public Types

```rust
/// Top-level daemon runner managing the async event loop and all subsystem lifecycles.
/// Replaces C's main() orchestration in src/dnsmasq.c.
pub struct DaemonRunner { /* ... */ }
```

#### Public Functions

```rust
impl DaemonRunner {
    /// Construct a new `DaemonRunner` from the fully-parsed daemon state.
    /// Initialises all subsystems — DNS cache, DHCP context, listeners, etc.
    pub fn new(state: DaemonState) -> DnsmasqResult<Self>;

    /// Main async entry point — binds sockets, drops privileges, and enters
    /// the tokio::select! event loop. Replaces C main() in src/dnsmasq.c.
    pub async fn run(&mut self) -> DnsmasqResult<()>;
}
```

---

### 1.2 `core::types`

**Source:** `src/dnsmasq.h` (2,233 lines) — global struct definitions, type aliases,
event codes, option flags, and exit codes.

#### Public Types

```rust
/// Central daemon state hub holding all subsystem references.
/// Replaces C `struct daemon` — the global singleton accessed by every module.
/// In Rust, passed via `Arc<RwLock<DaemonState>>` rather than global mutable state.
pub struct DaemonState {
    pub options: OptionFlags,
    pub dns_cache: DnsCache,
    pub lease_db: LeaseDatabase,
    pub listeners: Vec<Listener>,
    pub servers: Vec<ServerEntry>,
    pub metrics: MetricsStore,
    // ... additional fields corresponding to struct daemon members
}

/// Address variant enum replacing C `union all_addr`.
/// Discriminated union providing type-safe access to address data.
pub enum AllAddr {
    Addr4(Ipv4Addr),
    Addr6(Ipv6Addr),
    Cname { target: CnameTarget, uid: u32, is_name_ptr: bool },
    Key { keydata: Vec<u8>, keylen: u16, flags: u16, keytag: u16, algo: u8 },
    Ds { keydata: Vec<u8>, keylen: u16, keytag: u16, algo: u8, digest: u8 },
    Log { keytag: u16, algo: u16, digest: u16, rcode: u16, ede: i32 },
    RrBlock { rrtype: u16, datalen: u16, rrdata: Vec<u8> },
    RrData { rrtype: u16, data: Vec<u8> },
}

/// Socket address wrapper replacing C `union mysockaddr`.
/// Provides safe access to IPv4 and IPv6 socket addresses.
pub enum MySockAddr {
    V4(SocketAddrV4),
    V6(SocketAddrV6),
}

/// Upstream DNS server descriptor.
/// Replaces C `struct server` from src/dnsmasq.h.
pub struct ServerEntry {
    pub addr: MySockAddr,
    pub source_addr: MySockAddr,
    pub interface: Option<String>,
    pub flags: u32,
    pub queries: u32,
    pub failed_queries: u32,
    pub nxdomain_replies: u32,
    pub retrys: u32,
    // ... additional fields
}

/// Network interface record.
/// Replaces C `struct irec` from src/dnsmasq.h.
pub struct InterfaceRecord {
    pub addr: MySockAddr,
    pub netmask: Ipv4Addr,
    pub tftp_ok: bool,
    pub dhcp4_ok: bool,
    pub dhcp6_ok: bool,
    pub mtu: u32,
    pub done: bool,
    pub warned: bool,
    pub dad: bool,
    pub dns_auth: bool,
    pub index: i32,
    pub multicast_done: bool,
    pub found: bool,
    pub name: String,
}
```

#### Event Codes

```rust
/// Async event queue event types.
/// Replaces C EVENT_* defines from src/dnsmasq.h.
pub const EVENT_RELOAD: i32 = 1;
pub const EVENT_DUMP: i32 = 2;
pub const EVENT_ALARM: i32 = 3;
pub const EVENT_TERM: i32 = 4;
pub const EVENT_CHILD: i32 = 5;
pub const EVENT_REOPEN: i32 = 6;
pub const EVENT_EXITED: i32 = 7;
pub const EVENT_KILLED: i32 = 8;
pub const EVENT_EXEC_ERR: i32 = 9;
pub const EVENT_PIPE_ERR: i32 = 10;
pub const EVENT_USER_ERR: i32 = 11;
pub const EVENT_CAP_ERR: i32 = 12;
pub const EVENT_PIDFILE: i32 = 13;
pub const EVENT_HUSER_ERR: i32 = 14;
pub const EVENT_GROUP_ERR: i32 = 15;
pub const EVENT_DIE: i32 = 16;
pub const EVENT_LOG_ERR: i32 = 17;
pub const EVENT_FORK_ERR: i32 = 18;
pub const EVENT_LUA_ERR: i32 = 19;
pub const EVENT_TFTP_ERR: i32 = 20;
pub const EVENT_INIT: i32 = 21;
pub const EVENT_NEWADDR: i32 = 22;
pub const EVENT_NEWROUTE: i32 = 23;
pub const EVENT_TIME_ERR: i32 = 24;
pub const EVENT_SCRIPT_LOG: i32 = 25;
pub const EVENT_TIME: i32 = 26;
```

#### Exit Codes

```rust
pub const EC_GOOD: i32 = 0;
pub const EC_BADCONF: i32 = 1;
pub const EC_BADNET: i32 = 2;
pub const EC_FILE: i32 = 3;
pub const EC_NOMEM: i32 = 4;
pub const EC_MISC: i32 = 5;
pub const EC_INIT_OFFSET: i32 = 10;
```

---

### 1.3 `core::poll`

**Source:** `src/poll.c` (484 lines) — poll-based I/O multiplexing abstraction, replaced
by `tokio::select!` in the Rust implementation.

#### Public Functions

```rust
/// Timer event types for the event loop scheduler.
/// Replaces C's ad-hoc timer tracking in the poll loop.
pub enum TimerEvent { /* DhcpLease, RouterAdvert, DnsCacheEvict, etc. */ }

/// Async event loop abstraction built on tokio::select!.
/// Replaces C's poll_reset()/poll_listen()/poll_check()/do_poll() from src/poll.c.
pub struct EventLoop { /* ... */ }

impl EventLoop {
    /// Create a new event loop with default timer set.
    pub fn new() -> Self;

    /// Schedule (or reschedule) a timer for the given event type.
    pub fn schedule_timer(&mut self, event: TimerEvent, when: Instant);

    /// Return the next timeout duration until the earliest pending timer fires.
    pub fn next_timeout(&self) -> Option<Duration>;

    /// Fire all timers whose deadline has passed and return their event types.
    pub fn fire_expired_timers(&mut self) -> Vec<TimerEvent>;

    /// Take ownership of the timer receiver channel for integration with
    /// tokio::select! in the main daemon loop.
    pub fn take_timer_receiver(&mut self) -> Option<tokio::sync::mpsc::Receiver<TimerEvent>>;
}

/// Bind a UDP socket to the specified address with SO_REUSEADDR.
/// Replaces C's socket + bind pattern in src/poll.c / src/network.c.
pub fn bind_udp(addr: SocketAddr) -> DnsmasqResult<tokio::net::UdpSocket>;

/// Bind a TCP listener to the specified address with SO_REUSEADDR.
pub fn bind_tcp(addr: SocketAddr) -> DnsmasqResult<tokio::net::TcpListener>;
```

---

### 1.4 `core::log`

**Source:** `src/log.c` (1,120 lines) — syslog integration, connection-based logging,
async-safe logging subsystem.

#### Public Functions

```rust
/// Log facility/subsystem identifiers for categorised logging.
pub enum LogFacility { /* DnsMasq, Dhcp, Tftp, Script, Debug, ... */ }

/// Configuration for the logging subsystem.
pub struct LogConfig { /* ... */ }

/// Initialise the logging subsystem, opening the syslog connection and
/// configuring structured output. Replaces C log_start() from src/log.c.
pub fn init_logging(config: &LogConfig) -> DnsmasqResult<()>;

/// Flush all pending log messages to the output destination.
/// Replaces C flush_log() from src/log.c.
pub fn flush_logging();

/// Reopen the log file (for log rotation). Replaces C log_reopen().
pub fn reopen_log(state: &mut DaemonState) -> DnsmasqResult<()>;

/// Log a DNS query with structured fields (name, type, source).
/// Replaces C log_query() from src/log.c with structured logging.
pub fn log_dns_query(flags: u32, name: &str, source: &str, qtype: &str);

/// Log a DHCP event (lease grant, release, NAK, etc.) with structured fields.
pub fn log_dhcp_event(event_type: &str, mac: &str, ip: &str, hostname: Option<&str>);

/// Log a privilege-drop event for the security audit trail.
pub fn log_privilege_drop(user: &str, group: &str);

/// Log a configuration reload event (SIGHUP handling).
pub fn log_config_reload();

/// Log a DNSSEC validation failure with chain-of-trust details.
pub fn log_dnssec_failure(domain: &str, reason: &str);

/// Log a DNS cache poisoning attempt detection.
pub fn log_cache_poisoning_attempt(domain: &str, source: &str);

/// Log a TFTP transfer event (start, complete, error).
pub fn log_tftp_event(event_type: &str, file: &str, client: &str);

/// Log a script execution event (lease-change callback).
pub fn log_script_event(action: &str, script: &str, result: i32);

/// Log a debug-level message (only when debug logging enabled).
pub fn log_debug_message(message: &str);

/// Open the system syslog connection (low-level wrapper).
pub fn open_system_syslog(ident: &str, facility: i32);

/// Write a message to the system syslog (low-level wrapper).
pub fn write_system_syslog(priority: i32, message: &str);

/// Close the system syslog connection.
pub fn close_system_syslog();

/// Convert a tracing log level to a syslog priority constant.
pub fn tracing_level_to_syslog_priority(level: &tracing::Level) -> i32;
```

---

### 1.5 `core::util`

**Source:** `src/util.c` (2,730 lines) — string utilities, helper functions. All manual
memory allocation wrappers (`safe_malloc`, `whine_malloc`) are eliminated in Rust — RAII
and standard collections replace explicit heap management.

#### Public Functions

```rust
/// Canonicalise a domain name: lowercase, validate label lengths, remove trailing dot.
/// Replaces C canonicalise() from src/util.c.
pub fn canonicalise(input: &str) -> Result<String, DnsmasqError>;

/// Validate a DNS name for correctness (label length, total length, characters).
/// Replaces C check_dns_name() from src/util.c.
pub fn check_dns_name(name: &str) -> bool;

/// Case-insensitive domain name equality comparison (RFC 1035 §2.3.3).
/// Replaces C hostname_isequal() from src/util.c.
pub fn hostname_eq(a: &str, b: &str) -> bool;

/// Case-insensitive domain name comparison returning Ordering.
pub fn hostname_cmp(a: &str, b: &str) -> std::cmp::Ordering;

/// Check whether `sub` is a subdomain of `parent`.
pub fn is_subdomain(sub: &str, parent: &str) -> bool;

/// Validate that a hostname conforms to RFC 952/1123 rules.
/// Replaces C legal_hostname() from src/util.c.
pub fn legal_hostname(name: &str) -> bool;

/// Format a duration in seconds into a human-readable string (e.g., "2h30m").
/// Replaces C prettyprint_time() from src/util.c.
pub fn format_duration(seconds: u64) -> String;

/// Parse a hexadecimal string into a byte vector.
/// Replaces C parse_hex() from src/util.c.
pub fn parse_hex(hex: &str) -> Result<Vec<u8>, DnsmasqError>;

/// Format a MAC address as a colon-separated hex string.
pub fn format_mac(mac: &[u8]) -> String;

/// Format an IP address (v4 or v6) for display.
pub fn format_addr(addr: &AllAddr) -> String;

/// Compare two socket addresses for equality.
pub fn sockaddr_eq(a: &MySockAddr, b: &MySockAddr) -> bool;

/// Compute the prefix length from a network mask.
pub fn netmask_length(mask: Ipv4Addr) -> u32;

/// Check whether two IPv4 addresses are on the same network.
pub fn is_same_net(a: Ipv4Addr, b: Ipv4Addr, mask: Ipv4Addr) -> bool;

/// Check whether two IPv6 addresses are on the same /prefix network.
pub fn is_same_net6(a: &Ipv6Addr, b: &Ipv6Addr, prefix_len: u32) -> bool;

/// Return the current time as seconds since epoch (monotonic for relative durations).
pub fn dnsmasq_time() -> i64;

/// Return the current time in milliseconds (for timeout calculations).
pub fn dnsmasq_millis() -> u64;

/// Create a non-blocking pipe pair. Replaces C safe_pipe() from src/util.c.
pub fn safe_pipe() -> DnsmasqResult<(RawFd, RawFd)>;

/// Close all file descriptors above a given threshold (for privilege separation).
pub fn close_fds(max_fd: i32);

/// Encode a domain name to IDNA/punycode form (if `idn` feature enabled).
#[cfg(feature = "idn")]
pub fn idn_encode(name: &str) -> DnsmasqResult<String>;

/// Check whether a Linux kernel version meets the minimum requirement.
/// Replaces C kernel_version() from src/util.c.
#[cfg(target_os = "linux")]
pub fn kernel_version() -> i32;
```

> **Note:** The C functions `safe_malloc()`, `whine_malloc()`, and `safe_pipe()` from
> `src/util.c` are **not ported** to Rust. Rust's ownership model and RAII provide
> automatic, compile-time-verified memory management via `Vec`, `Box`, `String`, and
> other standard types. See [SAFETY.md](SAFETY.md) for details.

---

### 1.6 `core::pattern`

**Source:** `src/pattern.c` (648 lines) — wildcard and glob pattern matching for domain
names and hostnames.

#### Public Functions

```rust
/// Match a string against a wildcard/glob pattern (supports `*` and `?`).
/// Replaces C wildcard_match() from src/pattern.c.
pub fn glob_match(pattern: &str, candidate: &str) -> bool;

/// Validate whether a value is a well-formed DNS name.
/// Replaces C is_valid_dns_name() from src/pattern.c.
pub fn is_valid_dns_name(value: &str) -> bool;

/// Validate whether a value is a valid DNS name pattern (with wildcards).
/// Replaces C is_valid_dns_name_pattern() from src/pattern.c.
pub fn is_valid_dns_name_pattern(value: &str) -> bool;

/// Check whether a DNS name matches a pattern (including wildcards).
/// Replaces C dns_name_matches_pattern() from src/pattern.c.
pub fn dns_name_matches_pattern(name: &str, pattern: &str) -> bool;
```

---

## 2. Config Module (`crate::config`)

The config module handles compile-time constants, feature flag logic, configuration file
parsing (350+ directives), and command-line argument processing.

### 2.1 `config::constants`

**Source:** `src/config.h` (3,020 lines) — compile-time configuration defaults, resource
limits, and numeric constants.

#### Key Constants

```rust
// --- DNS Forward Table ---
/// Maximum concurrent outstanding DNS queries (forward table size).
/// Tunable via: --dns-forward-max
pub const FTABSIZ: usize = 150;

/// Maximum TCP child processes for DNS-over-TCP connections.
pub const MAX_PROCS: usize = 20;

/// TCP child process lifetime limit in seconds.
pub const CHILD_LIFETIME: u64 = 150;

/// Maximum queries per TCP connection before forced close.
pub const TCP_MAX_QUERIES: usize = 100;

/// TCP connection establishment timeout (seconds); response timeout is double.
pub const TCP_TIMEOUT: u64 = 5;

/// Kernel listen backlog for TCP accept queue.
pub const TCP_BACKLOG: i32 = 32;

// --- DNS Cache ---
/// Default DNS cache entry count. Tunable via: --cache-size
pub const CACHESIZ: usize = 150;

/// Maximum min-cache-ttl ceiling (seconds). Prevents stale data persistence.
pub const TTL_FLOOR_LIMIT: u64 = 3600;

// --- DHCP ---
/// Maximum concurrent DHCP leases.
pub const MAXLEASES: usize = 1000;

/// Lease file write retry interval (seconds) after I/O failure.
pub const LEASE_RETRY: u64 = 60;

// --- DNS Protocol ---
/// Maximum domain name length including null terminator (RFC 1035).
pub const MAXDNAME: usize = 1025;

/// Maximum single DNS label length (RFC 1035 §2.3.4).
pub const MAXLABEL: usize = 63;

/// Default EDNS0 UDP payload size (DNS Flag Day 2020).
pub const EDNS_PKTSZ: usize = 1232;

/// Default RFC 1035 UDP packet size (without EDNS0).
pub const PACKETSZ: usize = 512;

/// DNS query timeout in seconds (UDP).
pub const TIMEOUT: u64 = 10;

// --- DNSSEC Limits ---
/// Max queries during DNSSEC validation chain (DoS prevention).
pub const DNSSEC_LIMIT_WORK: usize = 40;

/// Max signature validation failures per response.
pub const DNSSEC_LIMIT_SIG_FAIL: usize = 20;

/// Max cryptographic operations per validation query.
pub const DNSSEC_LIMIT_CRYPTO: usize = 200;

/// Max NSEC3 hash iterations (RFC 5155 recommendation).
pub const DNSSEC_LIMIT_NSEC3_ITERS: usize = 150;

/// Block size for DNSSEC key material storage (bytes).
pub const KEYBLOCK_LEN: usize = 40;

// --- Network Ports ---
/// DNS standard port (UDP and TCP), per RFC 1035 §4.2.
pub const NAMESERVER_PORT: u16 = 53;

/// DHCP server listening port (RFC 2131 §4.1).
pub const DHCP_SERVER_PORT: u16 = 67;

/// DHCP client listening port (RFC 2131 §4.1).
pub const DHCP_CLIENT_PORT: u16 = 68;

/// Alternate DHCP server port for non-privileged deployments.
pub const DHCP_SERVER_ALTPORT: u16 = 1067;

/// Alternate DHCP client port for non-privileged deployments.
pub const DHCP_CLIENT_ALTPORT: u16 = 1068;

/// TFTP standard port (RFC 1350).
pub const TFTP_PORT: u16 = 69;

/// PXE proxy DHCP port (Intel PXE Specification 2.1).
pub const PXE_PORT: u16 = 4011;

/// Maximum TFTP concurrent connections.
pub const TFTP_MAX_CONNECTIONS: usize = 50;

// --- Upstream Server Health ---
/// Query count interval for upstream server health testing.
pub const FORWARD_TEST: usize = 50;

/// Time interval (seconds) for upstream server health testing.
pub const FORWARD_TIME: u64 = 20;
```

---

### 2.2 `config::features`

**Source:** `src/config.h` — feature flag compilation logic. In Rust, `HAVE_*` C
preprocessor macros are replaced by Cargo feature flags and `#[cfg(feature = "...")]`
attributes.

#### Feature Flag Mapping

| Cargo Feature | C Macro | Default | Description |
|---|---|---|---|
| `dhcp` | `HAVE_DHCP` | Enabled | DHCPv4 server |
| `dhcp6` | `HAVE_DHCP6` | Enabled | DHCPv6 server (implies `dhcp`) |
| `tftp` | `HAVE_TFTP` | Enabled | TFTP server and PXE boot |
| `script` | `HAVE_SCRIPT` | Enabled | Lease-change script execution |
| `auth` | `HAVE_AUTH` | Enabled | Authoritative DNS zones |
| `ipset` | `HAVE_IPSET` | Enabled | Linux ipset integration |
| `loop-detect` | `HAVE_LOOP` | Enabled | DNS forwarding loop detection |
| `dumpfile` | `HAVE_DUMPFILE` | Enabled | Packet dump for debugging |
| `inotify` | `HAVE_INOTIFY` | Enabled | File change monitoring (Linux) |
| `dnssec` | `HAVE_DNSSEC` | Disabled | DNSSEC validation (requires nettle) |
| `dbus` | `HAVE_DBUS` | Disabled | D-Bus/NetworkManager integration |
| `ubus` | `HAVE_UBUS` | Disabled | OpenWrt ubus integration |
| `idn` | `HAVE_IDN` / `HAVE_LIBIDN2` | Disabled | Internationalized domain names |
| `conntrack` | `HAVE_CONNTRACK` | Disabled | Linux conntrack mark support |
| `nftset` | `HAVE_NFTSET` | Disabled | nftables set integration |
| `luascript` | `HAVE_LUASCRIPT` | Disabled | Lua scripting support |
| `broken-rtc` | `HAVE_BROKEN_RTC` | Disabled | Embedded systems without a hardware real-time clock |

Platform-specific features are auto-detected via `#[cfg(target_os = "...")]`:
- `#[cfg(target_os = "linux")]` replaces `HAVE_LINUX_NETWORK`
- `#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "macos"))]` replaces `HAVE_BSD_NETWORK`

#### Public Functions

```rust
/// Return a human-readable string listing all enabled compile-time features.
/// Replaces C compile_opts logic from src/option.c.
pub fn compile_options_string() -> String;

/// Validate that feature flag dependencies are satisfied (e.g., dhcp6 implies dhcp).
pub fn validate_feature_dependencies() -> DnsmasqResult<()>;
```

---

### 2.3 `config::options`

**Source:** `src/option.c` (8,128 lines) — configuration file parser and 350+ directive
processor.

#### Public Functions

```rust
/// Top-level config loading entry point — parse CLI args, then load and merge
/// the config file(s). Replaces C read_opts() from src/option.c.
pub fn load(cli: &CliArgs) -> DnsmasqResult<DaemonState>;

/// Parse a single config file at the given path.
/// Processes all directives, expanding conf-dir and conf-file includes.
pub fn from_file(path: &Path) -> DnsmasqResult<Vec<ConfigDirective>>;

/// Apply default values to any unset configuration fields.
pub fn apply_defaults(state: &mut DaemonState);

/// Parse a configuration file, processing each directive line.
/// Replaces C read_opts() file-reading loop.
pub fn parse_config_file(path: &Path, state: &mut DaemonState) -> DnsmasqResult<()>;

/// Process a single configuration directive (name=value pair).
/// Handles all 350+ dnsmasq.conf directives via pattern matching.
/// Replaces C one_opt() from src/option.c.
pub fn process_directive(key: &str, value: &str, state: &mut DaemonState) -> DnsmasqResult<()>;

/// Parse a server= directive argument into server configuration.
/// Replaces C parse_server() from src/option.c.
pub fn parse_server(arg: &str) -> DnsmasqResult<ServerConfig>;

/// Merge CLI-specified overrides into the loaded configuration state.
pub fn merge_cli_args(cli: &CliArgs, state: &mut DaemonState);

/// Validate the fully-merged configuration for consistency.
pub fn validate(state: &DaemonState) -> DnsmasqResult<()>;
```

---

### 2.4 `config::cli`

**Source:** `src/option.c` (CLI portion) — command-line argument processing via `clap`
derive API, providing identical interface to the C `getopt_long` behavior.

#### Public Types

```rust
/// CLI argument structure generated via clap derive.
/// Maps to every dnsmasq command-line flag exactly.
#[derive(Parser)]
pub struct CliArgs {
    /// Read configuration from this file (default: /etc/dnsmasq.conf)
    #[arg(short = 'C', long = "conf-file")]
    pub conf_file: Option<PathBuf>,

    /// Read configuration from all files in directory
    #[arg(long = "conf-dir")]
    pub conf_dir: Option<PathBuf>,

    /// Do not daemonize; run in foreground
    #[arg(short = 'd', long = "no-daemon")]
    pub no_daemon: bool,

    /// Test configuration and exit
    #[arg(long = "test")]
    pub test_config: bool,

    /// Set DNS cache size (0 disables caching)
    #[arg(short = 'c', long = "cache-size")]
    pub cache_size: Option<usize>,

    /// Listen on this specific port (default: 53)
    #[arg(short = 'p', long = "port")]
    pub port: Option<u16>,

    // ... additional flags matching every dnsmasq CLI option
}

impl CliArgs {
    /// Validate CLI arguments for consistency and conflicts.
    pub fn validate(&self) -> DnsmasqResult<()>;

    /// Resolve cache-size with default fallback.
    pub fn effective_cache_size(&self) -> usize;

    /// Resolve dns-forward-max with default fallback.
    pub fn effective_dns_forward_max(&self) -> usize;

    /// Resolve EDNS packet max size with default fallback.
    pub fn effective_edns_packet_max(&self) -> usize;

    /// Resolve the effective unprivileged user name.
    pub fn effective_user(&self) -> String;

    /// Resolve the effective unprivileged group name.
    pub fn effective_group(&self) -> String;

    /// Resolve the effective DNS listening port.
    pub fn effective_port(&self) -> u16;

    /// Resolve the effective DHCP lease max.
    pub fn effective_dhcp_lease_max(&self) -> usize;

    /// Resolve the effective maximum TCP connections.
    pub fn effective_max_tcp_connections(&self) -> usize;

    /// Resolve the effective TFTP connection max.
    pub fn effective_tftp_max(&self) -> usize;
}
```

---

## 3. DNS Module (`crate::dns`)

The DNS module implements DNS query forwarding, caching, wire format handling, DNSSEC
validation, EDNS0 extensions, authoritative zone serving, and supporting utilities.

### 3.1 `dns::forward`

**Source:** `src/forward.c` (6,068 lines) — DNS query forwarding engine with upstream
server selection, retry/timeout logic, and TCP fallback.

#### Public Functions

```rust
/// Flags controlling forwarding behaviour.
pub struct ForwardFlags { /* ... */ }

/// Flags describing server properties.
pub struct ServerFlags { /* ... */ }

/// Upstream DNS server configuration and status.
pub struct UpstreamServer { /* ... */ }

/// Tracking record for an outstanding forwarded DNS query.
pub struct ForwardRecord { /* ... */ }

/// Table of outstanding forwarded queries (bounded by FTABSIZ).
pub struct ForwardTable { /* ... */ }

/// Random file descriptor entry for source port randomisation.
pub struct RfdEntry { /* ... */ }

/// Pool of random file descriptors for upstream queries.
pub struct RfdPool { /* ... */ }

/// Receive and dispatch an incoming DNS query from a client.
/// Initiates cache lookup and, on cache miss, forwards to upstream servers.
/// Replaces C receive_query() from src/forward.c.
pub async fn receive_query(listener: &Listener, state: &mut DaemonState, now: Instant) -> DnsmasqResult<()>;

/// Forward a DNS query to the selected upstream server(s).
/// Handles server selection, retry logic, and source port randomisation.
/// Replaces C forward_query() from src/forward.c.
pub async fn forward_query(state: &mut DaemonState, header: &DnsHeader, plen: usize, now: Instant) -> DnsmasqResult<()>;

/// Process a reply from an upstream DNS server and deliver to the waiting client.
/// Replaces C reply_query() from src/forward.c.
pub async fn reply_query(fd: RawFd, state: &mut DaemonState, now: Instant) -> DnsmasqResult<()>;

/// Return a processed reply to the originating client.
/// Replaces C return_reply() from src/forward.c.
pub fn return_reply(now: Instant, forward: &mut ForwardRecord, header: &DnsHeader, n: usize, status: i32);

/// Build a DNS response using the `DnsPacketBuilder` and return it.
pub fn build_response_with_builder(header: &DnsHeader, name: &str, qtype: u16) -> Vec<u8>;

/// Perform fast retry of queries to servers that have not yet responded.
/// Returns true if any retries were sent.
/// Replaces C fast_retry() from src/forward.c.
pub fn fast_retry(now: Instant) -> bool;

/// Send a DNS packet from the specified source address to a destination.
/// Handles interface binding and source address selection.
/// Replaces C send_from() from src/forward.c.
pub fn send_from(
    fd: RawFd, nowild: bool, packet: &[u8],
    to: &MySockAddr, source: &AllAddr, iface: u32,
) -> DnsmasqResult<()>;

/// Allocate a random file descriptor for upstream query source port.
/// Replaces C allocate_rfd() from src/forward.c.
pub fn allocate_rfd(server: &UpstreamServer) -> DnsmasqResult<RawFd>;

/// Free all random file descriptors in the given pool.
pub fn free_rfds(pool: &mut RfdPool);

/// Clean up state when an upstream server is removed from configuration.
/// Replaces C server_gone() from src/forward.c.
pub fn server_gone(server: &ServerEntry);

/// Resend all pending queries (after upstream server list change).
/// Replaces C resend_query() from src/forward.c.
pub fn resend_query();

/// Mark query servers with connection status flags.
pub fn mark_query_servers(forward: &mut ForwardRecord, flags: u32);

/// Handle a TCP DNS request on an accepted connection.
/// Replaces C tcp_request() from src/forward.c.
pub async fn tcp_request(
    conn_fd: RawFd, now: Instant,
    local_addr: &MySockAddr, netmask: Ipv4Addr, auth_dns: bool,
) -> DnsmasqResult<()>;

/// Promote a UDP query to TCP when the response is truncated.
/// Replaces C tcp_from_udp() from src/forward.c.
pub async fn tcp_from_udp(forward: &ForwardRecord, state: &mut DaemonState) -> DnsmasqResult<()>;
```

---

### 3.2 `dns::cache`

**Source:** `src/cache.c` (4,119 lines) — DNS cache using hash table with TTL-based
expiry and LRU eviction. Rust implementation replaces the manual hash table with
`HashMap`/`BTreeMap` collections.

#### Public Types

```rust
/// Flags associated with cache entries.
pub struct CacheFlags { /* ... */ }

/// Statistics counters for cache operations.
pub struct CacheStats { /* ... */ }

/// Union-like enum for cache record data (address, CNAME target, DNSSEC key, etc.).
pub enum CacheData { /* ... */ }

/// DNS cache record. Replaces C `struct crec` from src/dnsmasq.h.
pub struct CacheEntry {
    pub addr: AllAddr,
    pub ttd: Instant,        // Time-to-die (expiry)
    pub uid: u32,            // Source identifier (SRC_CONFIG, SRC_HOSTS, SRC_AH)
    pub flags: CacheFlags,   // Cache flags (F_IMMORTAL, F_IPV4, F_IPV6, F_CNAME, ...)
    pub name: String,        // Domain name
}

/// DNS cache container with hash-based lookup and LRU eviction.
pub struct DnsCache { /* ... */ }
```

#### Public Functions

```rust
/// Initialise the DNS cache with the configured size.
/// Replaces C cache_init() from src/cache.c.
pub fn cache_init(size: usize) -> DnsCache;

/// Look up a cache record by domain name and record type.
/// Returns None if not found or expired.
/// Replaces C cache_find_by_name() from src/cache.c.
pub fn cache_find_by_name(cache: &DnsCache, name: &str, now: Instant, flags: u32) -> Option<&CacheEntry>;

/// Look up a cache record by address (for reverse DNS / PTR queries).
/// Replaces C cache_find_by_addr() from src/cache.c.
pub fn cache_find_by_addr(cache: &DnsCache, addr: &AllAddr, now: Instant, flags: u32) -> Option<&CacheEntry>;

/// Insert a record into the cache, evicting expired or LRU entries as needed.
/// Replaces C cache_insert() from src/cache.c.
pub fn cache_insert(cache: &mut DnsCache, name: &str, addr: &AllAddr, class: u16, now: Instant, ttl: u64, flags: u32) -> Option<&mut CacheEntry>;

/// Evict all expired entries from the cache.
/// Replaces C cache_scan_free() from src/cache.c.
pub fn cache_evict_expired(cache: &mut DnsCache, now: Instant);

/// Read a hosts-format file and add all entries to the cache.
/// Replaces C read_hostsfile() from src/cache.c.
pub fn read_hostsfile(path: &str, cache: &mut DnsCache, state: &mut DaemonState) -> DnsmasqResult<()>;

/// Add (or update) a DHCP-derived entry in the DNS cache.
/// Replaces C cache_add_dhcp_entry() from src/cache.c.
#[cfg(feature = "dhcp")]
pub fn cache_add_dhcp_entry(cache: &mut DnsCache, hostname: &str, addr: &AllAddr, flags: u32);

/// Reload all hosts files and clear non-static entries.
/// Replaces C cache_reload() triggered by SIGHUP.
pub fn cache_reload(cache: &mut DnsCache, state: &mut DaemonState);

/// Dump all cache entries to the log (triggered by SIGUSR1).
/// Replaces C dump_cache() from src/cache.c.
pub fn dump_cache(cache: &DnsCache, state: &DaemonState);

/// Log a DNS query with its flags and source information.
/// Replaces C log_query() from src/cache.c.
pub fn log_query(flags: u32, name: &str, source: &str, qtype: &str);

/// Generate a cache statistics summary for SIGUSR1 output.
/// Replaces C cache_make_stat() from src/cache.c.
pub fn cache_make_stat(cache: &DnsCache) -> CacheStats;
```

---

### 3.3 `dns::protocol`

**Source:** `src/rfc1035.c` (3,622 lines) + `src/dns-protocol.h` (873 lines) — DNS wire
format parsing and construction per RFC 1035, plus protocol constant definitions.

#### Protocol Constants

```rust
// --- DNS Resource Record Types ---
pub const T_A: u16 = 1;        // IPv4 host address (RFC 1035)
pub const T_NS: u16 = 2;       // Authoritative name server (RFC 1035)
pub const T_CNAME: u16 = 5;    // Canonical name alias (RFC 1035)
pub const T_SOA: u16 = 6;      // Start of authority (RFC 1035)
pub const T_PTR: u16 = 12;     // Pointer for reverse DNS (RFC 1035)
pub const T_MX: u16 = 15;      // Mail exchange (RFC 1035)
pub const T_TXT: u16 = 16;     // Text string (RFC 1035)
pub const T_AAAA: u16 = 28;    // IPv6 host address (RFC 3596)
pub const T_SRV: u16 = 33;     // Service locator (RFC 2782)
pub const T_OPT: u16 = 41;     // EDNS0 pseudo-RR (RFC 6891)
pub const T_DS: u16 = 43;      // Delegation signer (RFC 4034)
pub const T_RRSIG: u16 = 46;   // DNSSEC signature (RFC 4034)
pub const T_NSEC: u16 = 47;    // Next secure record (RFC 4034)
pub const T_DNSKEY: u16 = 48;  // DNS public key (RFC 4034)
pub const T_NSEC3: u16 = 50;   // NSEC3 hashed denial (RFC 5155)
pub const T_CAA: u16 = 257;    // Certification Authority Authorization (RFC 8659)
pub const T_HTTPS: u16 = 65;   // HTTPS service binding (RFC 9460)
pub const T_SVCB: u16 = 64;    // Service binding (RFC 9460)

// --- DNS Response Codes ---
pub const NOERROR: u8 = 0;     // Success
pub const FORMERR: u8 = 1;     // Format error
pub const SERVFAIL: u8 = 2;    // Server failure
pub const NXDOMAIN: u8 = 3;    // Non-existent domain
pub const NOTIMP: u8 = 4;      // Not implemented
pub const REFUSED: u8 = 5;     // Query refused

// --- DNS Class Codes ---
pub const C_IN: u16 = 1;       // Internet
pub const C_CHAOS: u16 = 3;    // Chaos
pub const C_HESIOD: u16 = 4;   // Hesiod
pub const C_ANY: u16 = 255;    // Wildcard (query only)
```

#### Public Types

```rust
/// DNS response code enum. Replaces C RCODE constants.
pub enum ResponseCode { NoError, FormErr, ServFail, NxDomain, NotImp, Refused, /* ... */ }

/// DNS class codes.
pub enum DnsClass { IN, Chaos, Hesiod, Any }

/// DNS resource record type enum (comprehensive, maps all T_* constants).
pub enum RRType { A, NS, CNAME, SOA, PTR, MX, TXT, AAAA, SRV, OPT, DS, RRSIG, NSEC, DNSKEY, /* ... */ }

/// DNS header flags (QR, opcode, AA, TC, RD, RA, AD, CD, rcode).
pub struct DnsHeaderFlags { /* ... */ }

/// DNS message header (12 bytes, wire format per RFC 1035 §4.1.1).
/// Replaces C `struct dns_header` from src/dns-protocol.h.
pub struct DnsHeader {
    pub id: u16,
    pub flags: DnsHeaderFlags,
    pub qdcount: u16,   // Question count
    pub ancount: u16,   // Answer count
    pub nscount: u16,   // Authority count
    pub arcount: u16,   // Additional count
}

/// A parsed DNS domain name with encoding/decoding and compression support.
pub struct DnsName { /* ... */ }

/// A DNS question entry (QNAME + QTYPE + QCLASS).
pub struct DnsQuestion { /* ... */ }

/// A DNS resource record (name, type, class, TTL, rdata).
pub struct DnsResourceRecord { /* ... */ }

/// A fully parsed DNS packet containing header, questions, and RR sections.
pub struct DnsPacket { /* ... */ }

/// Builder for constructing DNS response packets with type-safe API.
/// Replaces C's manual packet buffer manipulation in rfc1035.c.
pub struct DnsPacketBuilder { /* ... */ }

/// A set of resource records sharing the same name/type/class.
pub struct RRSet { /* ... */ }
```

#### Public Functions

DNS protocol operations use builder/struct methods rather than C-style free functions:

```rust
impl DnsName {
    /// Parse a compressed DNS name from a packet at the given offset.
    /// Replaces C extract_name() from src/rfc1035.c.
    pub fn from_wire(packet: &[u8], offset: &mut usize) -> DnsmasqResult<Self>;

    /// Encode the name to wire format (with label length prefixes).
    pub fn to_wire(&self) -> Vec<u8>;
}

impl DnsPacket {
    /// Parse a complete DNS packet from raw bytes.
    pub fn from_bytes(data: &[u8]) -> DnsmasqResult<Self>;

    /// Serialise the packet to wire format.
    pub fn to_bytes(&self) -> Vec<u8>;
}

impl DnsPacketBuilder {
    /// Create a new builder for a DNS response.
    pub fn new_response(request: &DnsHeader) -> Self;

    /// Add an answer resource record.
    pub fn add_answer(&mut self, rr: DnsResourceRecord) -> &mut Self;

    /// Add an authority (NS) resource record.
    pub fn add_authority(&mut self, rr: DnsResourceRecord) -> &mut Self;

    /// Add an additional resource record.
    pub fn add_additional(&mut self, rr: DnsResourceRecord) -> &mut Self;

    /// Build the final wire-format packet.
    pub fn build(self) -> Vec<u8>;
}

/// Read a big-endian u16 from a byte slice at the given offset.
pub fn get_u16(data: &[u8], offset: usize) -> u16;

/// Read a big-endian u32 from a byte slice at the given offset.
pub fn get_u32(data: &[u8], offset: usize) -> u32;

/// Write a big-endian u16 into a byte slice at the given offset.
pub fn put_u16(data: &mut [u8], offset: usize, val: u16);

/// Write a big-endian u32 into a byte slice at the given offset.
pub fn put_u32(data: &mut [u8], offset: usize, val: u32);
```

---

### 3.4 `dns::dnssec`

**Source:** `src/dnssec.c` (4,009 lines) — DNSSEC validation engine implementing chain
of trust verification, signature validation, and denial-of-existence proofs.

**Feature gate:** `#[cfg(feature = "dnssec")]`

#### Public Functions

```rust
/// DNSSEC validation result status.
pub enum DnssecStatus { Secure, Insecure, Bogus, Indeterminate, NxDomain, /* ... */ }

/// Flags indicating DNSSEC failure reasons (bitfield).
pub struct DnssecFailFlags { /* ... */ }

/// DNSSEC trust anchor configuration.
pub struct TrustAnchor { /* ... */ }

/// Limits for DNSSEC validation recursion and work factor.
pub struct DnssecLimits { /* ... */ }

/// Stateful DNSSEC validator managing trust anchors and validation chains.
/// Replaces C's dnssec_* function family from src/dnssec.c.
pub struct DnssecValidator { /* ... */ }

#[cfg(feature = "dnssec")]
impl DnssecValidator {
    /// Validate a DNS reply for DNSSEC authenticity.
    /// Walks the chain of trust from the response back to a configured trust anchor.
    /// Replaces C dnssec_validate_reply() from src/dnssec.c.
    pub fn dnssec_validate_reply(
        &self, header: &DnsHeader, packet: &[u8], name: &str, keyname: &str,
        class: u16, now: Instant,
    ) -> DnsmasqResult<DnssecStatus>;

    /// Validate using a DS record chain (delegation signer).
    /// Replaces C dnssec_validate_by_ds() from src/dnssec.c.
    pub fn dnssec_validate_by_ds(
        &self, header: &DnsHeader, packet: &[u8], name: &str, class: u16, now: Instant,
    ) -> DnsmasqResult<DnssecStatus>;

    /// Validate an individual resource record set (RRset) against its RRSIG.
    /// Replaces C validate_rrset() from src/dnssec.c.
    pub fn validate_rrset(
        &self, now: Instant, header: &DnsHeader, packet: &[u8],
        class: u16, rrtype: u16, name: &str,
    ) -> DnsmasqResult<DnssecStatus>;

    /// Prove non-existence of a domain name or RR type using NSEC/NSEC3 records.
    /// Replaces C prove_non_existence() from src/dnssec.c.
    pub fn prove_non_existence(
        &self, header: &DnsHeader, packet: &[u8], name: &str, qtype: u16,
    ) -> DnsmasqResult<DnssecStatus>;
}

/// Compute the key tag for a DNSKEY record (RFC 4034 Appendix B).
#[cfg(feature = "dnssec")]
pub fn dnskey_keytag(key_data: &[u8], algo: u8) -> u16;

/// Convert DNSSEC failure flags to an Extended DNS Error (EDE) code.
#[cfg(feature = "dnssec")]
pub fn errflags_to_ede(flags: &DnssecFailFlags) -> u16;
```

Supported DNSSEC algorithms: RSA/SHA-1, RSA/SHA-256, RSA/SHA-512, ECDSA P-256,
ECDSA P-384, Ed25519, Ed448.

---

### 3.5 `dns::crypto`

**Source:** `src/crypto.c` (1,295 lines) — cryptographic operations for DNSSEC signature
verification and digest computation.

**Feature gate:** `#[cfg(feature = "dnssec")]`

#### Public Functions

```rust
/// Supported DNSSEC cryptographic algorithms.
pub enum DnssecAlgorithm { RsaSha1, RsaSha256, RsaSha512, EcdsaP256, EcdsaP384, Ed25519, Ed448, /* ... */ }

/// Hash/digest algorithms for DS and NSEC3 records.
pub enum DigestAlgorithm { Sha1, Sha256, Sha384, /* ... */ }

/// NSEC3 hash algorithm identifiers.
pub enum Nsec3HashAlgorithm { Sha1 }

/// Trait for pluggable hash function implementations.
pub trait HashFunction: Send + Sync { /* ... */ }

/// Unified DNSSEC cryptographic verifier.
/// Replaces C dnsmasq_rsa_verify(), dnsmasq_ecdsa_verify(), dnsmasq_eddsa_verify().
#[cfg(feature = "dnssec")]
pub struct CryptoVerifier { /* ... */ }

#[cfg(feature = "dnssec")]
impl CryptoVerifier {
    /// Verify a DNSSEC signature against the provided key data and digest.
    /// Dispatches to the appropriate algorithm (RSA, ECDSA, EdDSA).
    pub fn verify(&self, algo: DnssecAlgorithm, key: &[u8], sig: &[u8], data: &[u8]) -> DnsmasqResult<bool>;

    /// Return the digest algorithm name for a given DNSSEC algorithm.
    pub fn algo_digest_name(algo: DnssecAlgorithm) -> &'static str;

    /// Return the DS digest algorithm name.
    pub fn ds_digest_name(algo: DigestAlgorithm) -> &'static str;

    /// Return the NSEC3 hash algorithm name.
    pub fn nsec3_digest_name(algo: Nsec3HashAlgorithm) -> &'static str;

    /// Look up a hash function implementation by algorithm.
    pub fn hash_find(name: &str) -> Option<Box<dyn HashFunction>>;
}
```

---

### 3.6 `dns::edns`

**Source:** `src/edns0.c` (1,340 lines) — EDNS0 (Extension Mechanisms for DNS, RFC 6891)
option processing, including client subnet and DNS cookie support.

#### Public Functions

```rust
/// EDNS0 flags for tracking OPT record state.
pub struct EdnsFlags { /* ... */ }

/// A single EDNS0 option (code + data).
pub struct EdnsOption { /* ... */ }

/// Parsed EDNS0 data from a DNS packet's OPT pseudo-header.
pub struct EdnsData { /* ... */ }

/// EDNS0 option replacement mode.
pub enum ReplaceMode { Add, Replace }

/// Stateful EDNS0 handler for manipulating OPT pseudo-headers.
pub struct EdnsHandler { /* ... */ }

impl EdnsHandler {
    /// Locate the EDNS0 OPT pseudo-header in a DNS packet.
    /// Replaces C find_pseudoheader() from src/edns0.c.
    pub fn find_pseudoheader(&self, header: &DnsHeader, packet: &[u8]) -> Option<EdnsData>;

    /// Add or replace an EDNS0 OPT pseudo-header in a DNS packet.
    /// Replaces C add_pseudoheader() from src/edns0.c.
    pub fn add_pseudoheader(
        &self, header: &mut DnsHeader, packet: &mut Vec<u8>,
        optno: u16, opt_data: &[u8], set_do: bool, replace: bool,
    ) -> usize;

    /// Set the DNSSEC OK (DO) bit in the EDNS0 OPT record.
    /// Replaces C add_do_bit() from src/edns0.c.
    pub fn add_do_bit(&self, header: &mut DnsHeader, packet: &mut Vec<u8>) -> usize;

    /// Add EDNS0 client subnet option to an outgoing query.
    pub fn add_source_addr(&self, header: &mut DnsHeader, packet: &mut Vec<u8>, source: &MySockAddr) -> usize;

    /// Add MAC address EDNS0 option (for DHCP-linked DNS queries).
    pub fn add_mac(&self, header: &mut DnsHeader, packet: &mut Vec<u8>, mac: &[u8]) -> usize;

    /// Add the DNS client identifier option.
    pub fn add_dns_client(&self, header: &mut DnsHeader, packet: &mut Vec<u8>) -> usize;

    /// Add Cisco Umbrella EDNS0 option.
    pub fn add_umbrella_opt(&self, header: &mut DnsHeader, packet: &mut Vec<u8>) -> usize;

    /// Add EDNS0 client subnet and other configured options to a query.
    /// Replaces C add_edns0_config() from src/edns0.c.
    pub fn add_edns0_config(
        &self, header: &mut DnsHeader, packet: &mut Vec<u8>,
        source: &MySockAddr, now: Instant,
    ) -> (usize, bool);

    /// Check whether the source address in an EDNS0 client subnet option matches.
    /// Replaces C check_source() from src/edns0.c.
    pub fn check_source(&self, header: &DnsHeader, packet: &[u8], pseudoheader: &[u8], peer: &MySockAddr) -> bool;
}
```

---

### 3.7 `dns::rrfilter`

**Source:** `src/rrfilter.c` (918 lines) — DNS resource record type filtering for
response manipulation.

#### Public Functions

```rust
/// Filter mode for resource record filtering.
pub enum RRFilterMode { Edns0, Dnssec, Conf }

/// Descriptor for RR type rdata field layout.
pub enum RdataField { /* ... */ }

/// Get the field descriptor for a specific RR type (for filtering decisions).
/// Replaces C rrfilter_desc() / rr_type_descriptor() from src/rrfilter.c.
pub fn rr_type_descriptor(rr_type: u16) -> Option<Vec<RdataField>>;

/// Validate a domain name in a DNS packet for correctness.
/// Replaces C check_name() from src/rrfilter.c.
pub fn check_name(packet: &[u8], offset: usize) -> bool;

/// Validate all resource records in a DNS response for well-formedness.
/// Replaces C check_rrs() from src/rrfilter.c.
pub fn check_rrs(header: &DnsHeader, packet: &[u8]) -> bool;

/// Filter resource records from a DNS response based on mode.
/// Replaces C rrfilter() from src/rrfilter.c.
pub fn rrfilter(header: &mut DnsHeader, packet: &mut Vec<u8>, mode: RRFilterMode) -> usize;

/// Filter and write resource records directly to an output packet.
/// Replaces C rrfilter_to_packet() from src/rrfilter.c.
pub fn rrfilter_to_packet(header: &DnsHeader, packet: &[u8], output: &mut Vec<u8>, mode: RRFilterMode) -> usize;

/// Extract the question name from a DNS packet.
pub fn extract_question_name(header: &DnsHeader, packet: &[u8]) -> Option<String>;

/// Convert a domain name to wire format (length-prefixed labels).
/// Replaces C to_wire() from src/rrfilter.c.
pub fn to_wire(name: &str) -> Vec<u8>;

/// Convert a wire-format domain name back to presentation format.
/// Replaces C from_wire() from src/rrfilter.c.
pub fn from_wire(wire: &[u8]) -> String;
```

---

### 3.8 `dns::auth`

**Source:** `src/auth.c` (1,284 lines) — authoritative DNS zone serving, SOA and NS
record generation.

**Feature gate:** `#[cfg(feature = "auth")]`

#### Public Functions

```rust
/// Subnet record for authoritative zone access control.
pub struct AuthSubnet { /* ... */ }

/// Types of authoritative DNS records.
pub enum AuthRecord { /* ... */ }

/// Name entry within an authoritative zone.
pub struct AuthNameEntry { /* ... */ }

/// Authoritative DNS zone configuration.
pub struct AuthZone { /* ... */ }

/// Result of an authoritative query lookup.
pub enum AuthResult { /* ... */ }

/// Check whether a query name falls within a configured authoritative zone.
/// Replaces part of C answer_auth() zone matching from src/auth.c.
#[cfg(feature = "auth")]
pub fn in_zone(zone: &AuthZone, name: &str) -> bool;

/// Answer a DNS query from a locally configured authoritative zone.
/// Generates SOA, NS, A, AAAA, and other records from zone configuration.
/// Replaces C answer_auth() from src/auth.c.
#[cfg(feature = "auth")]
pub fn answer_auth(
    header: &mut DnsHeader, packet: &mut Vec<u8>,
    now: Instant, peer: &MySockAddr, local: bool,
) -> Result<usize, DnsmasqError>;

/// Convert an authoritative record to a DNS resource record for response construction.
#[cfg(feature = "auth")]
pub fn record_to_rr(record: &AuthRecord, packet: &mut Vec<u8>) -> DnsmasqResult<usize>;
```

---

### 3.9 `dns::domain_match`

**Source:** `src/domain-match.c` (1,591 lines) — domain matching algorithms for upstream
server selection and local answer generation.

#### Public Functions

```rust
/// Flags controlling server match behaviour.
pub struct ServerMatchFlags { /* bitflags */ }

/// Server configuration entry for upstream DNS server selection.
pub struct ServerConfig { /* ... */ }

/// Domain matcher for upstream server selection and local answer generation.
/// Maintains a sorted server array for efficient domain-based lookup.
pub struct DomainMatcher { /* ... */ }

impl DomainMatcher {
    /// Create a new domain matcher.
    pub fn new() -> Self;

    /// Build the sorted server array for efficient domain-based lookup.
    /// Replaces C build_server_array() from src/domain-match.c.
    pub fn build_server_array(&mut self, state: &mut DaemonState);

    /// Look up which upstream servers should handle a query for the given domain.
    /// Returns index range into the server array.
    /// Replaces C lookup_domain() from src/domain-match.c.
    pub fn lookup_domain(&self, domain: &str, flags: ServerMatchFlags) -> Option<(usize, usize)>;

    /// Filter the server list based on flags and domain match.
    /// Replaces C filter_servers() from src/domain-match.c.
    pub fn filter_servers(&self, seed: usize, flags: ServerMatchFlags) -> Option<(usize, usize)>;

    /// Check if two servers belong to the same group (for round-robin selection).
    /// Replaces C server_samegroup() from src/domain-match.c.
    pub fn server_samegroup(&self, a: &ServerEntry, b: &ServerEntry) -> bool;

    /// Mark servers with the specified flag.
    /// Replaces C mark_servers() from src/domain-match.c.
    pub fn mark_servers(&mut self, flag: ServerMatchFlags);

    /// Remove servers marked for deletion.
    /// Replaces C cleanup_servers() from src/domain-match.c.
    pub fn cleanup_servers(&mut self);

    /// Check if a query can be answered locally (from /etc/hosts, config, etc.).
    /// Replaces C is_local_answer() from src/domain-match.c.
    pub fn is_local_answer(&self, now: Instant, first: i32, name: &str) -> bool;

    /// Generate a local answer response packet.
    /// Replaces C make_local_answer() from src/domain-match.c.
    pub fn make_local_answer(
        &self, flags: ServerMatchFlags, got_name: bool,
        header: &mut DnsHeader, name: &str, first: i32, last: i32, ede: i32,
    ) -> usize;

    /// Add or update a server entry in the server list.
    /// Replaces C add_update_server() from src/domain-match.c.
    pub fn add_update_server(
        &mut self, flags: ServerMatchFlags, addr: &MySockAddr,
        source_addr: &MySockAddr, interface: Option<&str>,
        domain: Option<&str>, local_addr: Option<&AllAddr>,
    ) -> Result<(), DnsmasqError>;

    /// Check if a server supports DNSSEC for a given domain.
    /// Replaces C dnssec_server() from src/domain-match.c.
    pub fn dnssec_server(&self, domain: &str) -> bool;
}
```

---

### 3.10 `dns::domain`

**Source:** `src/domain.c` (707 lines) — reverse DNS domain synthesis for PTR record
generation from address ranges.

#### Public Functions

```rust
/// Conditional domain configuration entry.
pub struct ConditionalDomain { /* ... */ }

/// Check if a domain name is a synthetic reverse DNS name.
/// Replaces C is_name_synthetic() from src/domain.c.
pub fn is_name_synthetic(flags: i32, name: &str, addr: &AllAddr) -> bool;

/// Check if a reverse PTR name is synthetic and extract the forward address.
/// Replaces C is_rev_synth() from src/domain.c.
pub fn is_rev_synth(flags: i32, addr: &AllAddr, name: &mut String) -> bool;

/// Synthesise a reverse DNS domain name from an IPv4 address and configured ranges.
/// Replaces C get_domain() from src/domain.c.
pub fn get_domain(addr: &AllAddr) -> Option<String>;

/// Synthesise a reverse DNS domain name from an IPv6 address and configured ranges.
/// Replaces C get_domain6() from src/domain.c.
pub fn get_domain6(addr: &Ipv6Addr) -> Option<String>;
```

---

### 3.11 `dns::blockdata`

**Source:** `src/blockdata.c` (810 lines) — block-allocated storage for variable-length
DNSSEC record data. In Rust, `Vec<u8>` and `Box<[u8]>` replace the linked-block
allocator.

#### Public Functions

```rust
/// Block-allocated storage for variable-length DNSSEC record data.
/// In Rust, uses Vec<u8>/Box<[u8]> instead of the C linked-block allocator.
pub struct BlockData { /* ... */ }

/// Pool manager for block-allocated data storage.
pub struct BlockDataPool { /* ... */ }

impl BlockData {
    /// Allocate and store variable-length data (DNSSEC keys, signatures).
    /// Replaces C blockdata_alloc() from src/blockdata.c.
    pub fn new(data: &[u8]) -> Self;

    /// Retrieve the stored data as a contiguous byte slice.
    /// Replaces C blockdata_retrieve() from src/blockdata.c.
    pub fn retrieve(&self) -> &[u8];
}

impl BlockDataPool {
    /// Create a new block data pool for managing DNSSEC record storage.
    pub fn new() -> Self;

    /// Free all allocated blocks, resetting the pool.
    pub fn free_all(&mut self);
}
```

---

### 3.12 `dns::loop_detect`

**Source:** `src/loop.c` (539 lines) — DNS forwarding loop detection to prevent infinite
query cycles.

**Feature gate:** `#[cfg(feature = "loop-detect")]`

#### Public Functions

```rust
/// DNS forwarding loop detector.
/// Maintains daemon UID and probe state for detecting query cycles.
pub struct LoopDetector { /* ... */ }

impl LoopDetector {
    /// Create a new loop detector instance.
    #[cfg(feature = "loop-detect")]
    pub fn new() -> Self;

    /// Get the daemon's unique identifier used in loop detection probes.
    #[cfg(feature = "loop-detect")]
    pub fn daemon_uid(&self) -> u32;

    /// Send loop detection probe queries to all configured upstream servers.
    /// Replaces C loop_send_probes() from src/loop.c.
    #[cfg(feature = "loop-detect")]
    pub fn loop_send_probes(&self);

    /// Construct a loop detection probe query packet.
    /// Replaces C loop_make_probe() from src/loop.c.
    #[cfg(feature = "loop-detect")]
    pub fn loop_make_probe(&self, server_index: usize) -> Vec<u8>;

    /// Check if an incoming query matches a loop detection probe (indicating a loop).
    /// Returns true if a forwarding loop is detected.
    /// Replaces C detect_loop() from src/loop.c.
    #[cfg(feature = "loop-detect")]
    pub fn detect_loop(&self, query: &str, qtype: u16) -> bool;
}
```

---

## 4. DHCP Module (`crate::dhcp`)

The DHCP module implements DHCPv4 and DHCPv6 server functionality, lease management,
Router Advertisement, SLAAC tracking, and shared protocol utilities.

### 4.1 `dhcp::v4::server`

**Source:** `src/dhcp.c` (2,344 lines) — DHCPv4 server initialisation, raw socket I/O,
and packet dispatch.

**Feature gate:** `#[cfg(feature = "dhcp")]`

#### Public Functions

```rust
/// Parameters for interface matching during DHCP context narrowing.
pub struct IfaceParam { /* ... */ }

/// Parameters for client matching during DHCP configuration lookup.
pub struct MatchParam { /* ... */ }

/// Initialise the DHCPv4 server: create raw sockets, set BPF filters.
/// Replaces C dhcp_init() from src/dhcp.c.
#[cfg(feature = "dhcp")]
pub async fn dhcp_init() -> Result<(), DnsmasqError>;

/// Process an incoming DHCPv4 packet from the raw socket.
/// Dispatches to the protocol state machine (rfc2131 handler).
/// Replaces C dhcp_packet() from src/dhcp.c.
#[cfg(feature = "dhcp")]
pub async fn dhcp_packet(state: &mut DaemonState, now: Instant, pxe_fd: Option<RawFd>) -> Result<(), DnsmasqError>;

/// Allocate an IP address from the DHCP pool.
/// Replaces C address_allocate() from src/dhcp.c.
#[cfg(feature = "dhcp")]
pub fn address_allocate(
    context: &DhcpContext, hwaddr: &[u8], netids: &[DhcpNetId], now: Instant, loopback: bool,
) -> Result<Ipv4Addr, DnsmasqError>;

/// Look up a client lease by address, hardware address, or client ID.
/// Replaces C lookup_client_lease() from src/dhcp.c.
#[cfg(feature = "dhcp")]
pub fn lookup_client_lease(hwaddr: &[u8], clid: Option<&[u8]>, addr: Ipv4Addr) -> Option<&DhcpLease>;

/// Look up a client configuration by MAC address or client identity.
/// Replaces C lookup_client_config() from src/dhcp.c.
#[cfg(feature = "dhcp")]
pub fn lookup_client_config(configs: &[DhcpConfig], hwaddr: &[u8], clid: Option<&[u8]>) -> Option<&DhcpConfig>;

/// Check if bind-interfaces mode is active (affects socket binding strategy).
/// Replaces C is_bind_interfaces_mode() from src/dhcp.c.
#[cfg(feature = "dhcp")]
pub fn is_bind_interfaces_mode() -> bool;

/// Complete DHCP context narrowing by populating interface-specific fields.
/// Replaces C complete_context() from src/dhcp.c.
#[cfg(feature = "dhcp")]
pub fn complete_context(contexts: &mut [DhcpContext], iface: &IfaceParam);

/// Guess the netmask for a DHCP range from the interface configuration.
/// Replaces C guess_range_netmask() from src/dhcp.c.
#[cfg(feature = "dhcp")]
pub fn guess_range_netmask(addr: Ipv4Addr, netmask: Ipv4Addr) -> Ipv4Addr;

/// Narrow DHCP contexts to those matching the arrival interface.
/// Replaces C narrow_context() / narrow_context3() from src/dhcp.c.
#[cfg(feature = "dhcp")]
pub fn narrow_context(contexts: &[DhcpContext], iface_addr: Ipv4Addr) -> Vec<&DhcpContext>;

/// Check if the given address is accepted by local listen configuration.
/// Replaces C check_listen_addrs() from src/dhcp.c.
#[cfg(feature = "dhcp")]
pub fn check_listen_addrs(addr: Ipv4Addr, iface_index: i32) -> bool;

/// Send an ICMP ping to check if an address is already in use before offering.
/// Replaces C do_icmp_ping() from src/dhcp.c.
#[cfg(feature = "dhcp")]
pub async fn do_icmp_ping(addr: Ipv4Addr) -> bool;

/// Find a DHCP static configuration by IP address.
/// Replaces C config_find_by_address() from src/dhcp.c.
#[cfg(feature = "dhcp")]
pub fn config_find_by_address(configs: &[DhcpConfig], addr: Ipv4Addr) -> Option<&DhcpConfig>;

/// Resolve a hostname via DNS for DHCP client identification.
/// Replaces C host_from_dns() from src/dhcp.c.
#[cfg(feature = "dhcp")]
pub fn host_from_dns(addr: Ipv4Addr) -> Option<String>;

/// Read static DHCP assignments from /etc/ethers file.
/// Replaces C dhcp_read_ethers() from src/dhcp.c.
#[cfg(feature = "dhcp")]
pub fn dhcp_read_ethers() -> DnsmasqResult<()>;

/// Process a relayed DHCPv4 reply message.
/// Replaces C relay_reply4() from src/dhcp.c.
#[cfg(feature = "dhcp")]
pub fn relay_reply4(mess: &DhcpPacket, sz: usize, arrival_interface: &str) -> u32;
```

---

### 4.2 `dhcp::v4::protocol`

**Source:** `src/rfc2131.c` (5,209 lines) + `src/dhcp-protocol.h` (936 lines) — DHCPv4
protocol state machine implementing the full DISCOVER → OFFER → REQUEST → ACK exchange
per RFC 2131.

**Feature gate:** `#[cfg(feature = "dhcp")]`

#### Protocol Constants

```rust
// --- DHCP Message Types (RFC 2131 §3) ---
pub const DHCPDISCOVER: u8 = 1;
pub const DHCPOFFER: u8 = 2;
pub const DHCPREQUEST: u8 = 3;
pub const DHCPDECLINE: u8 = 4;
pub const DHCPACK: u8 = 5;
pub const DHCPNAK: u8 = 6;
pub const DHCPRELEASE: u8 = 7;
pub const DHCPINFORM: u8 = 8;

// --- DHCP Options (RFC 2132) ---
pub const OPTION_PAD: u8 = 0;
pub const OPTION_NETMASK: u8 = 1;
pub const OPTION_ROUTER: u8 = 3;
pub const OPTION_DNSSERVER: u8 = 6;
pub const OPTION_HOSTNAME: u8 = 12;
pub const OPTION_DOMAINNAME: u8 = 15;
pub const OPTION_BROADCAST: u8 = 28;
pub const OPTION_REQUESTED_IP: u8 = 50;
pub const OPTION_LEASE_TIME: u8 = 51;
pub const OPTION_OVERLOAD: u8 = 52;
pub const OPTION_MESSAGE_TYPE: u8 = 53;
pub const OPTION_SERVER_IDENTIFIER: u8 = 54;
pub const OPTION_PARAMETERLIST: u8 = 55;
pub const OPTION_MAXMESSAGE: u8 = 57;
pub const OPTION_VENDOR_ID: u8 = 60;
pub const OPTION_CLIENT_ID: u8 = 61;
pub const OPTION_END: u8 = 255;

// --- DHCP Packet Structure ---
pub const DHCP_COOKIE: u32 = 0x63825363;
pub const BOOTREQUEST: u8 = 1;
pub const BOOTREPLY: u8 = 2;
```

#### Public Types

```rust
/// DHCPv4 protocol state machine states.
pub enum DhcpV4State {
    Discover,
    Offer,
    Request,
    Decline,
    Ack,
    Nak,
    Release,
    Inform,
}

/// Parsed DHCPv4 packet with accessor methods for all fields.
/// Replaces C's raw `struct dhcp_packet` buffer manipulation.
pub struct DhcpPacket { /* ... */ }

impl DhcpPacket {
    /// Parse a DHCPv4 packet from raw bytes.
    pub fn from_bytes(data: &[u8]) -> DnsmasqResult<Self>;
    /// Create a reply packet from a request.
    pub fn new_reply(request: &DhcpPacket) -> Self;
    /// Serialize the packet to wire format.
    pub fn as_bytes(&self) -> &[u8];
    pub fn as_bytes_mut(&mut self) -> &mut [u8];
    pub fn len(&self) -> usize;
    pub fn is_empty(&self) -> bool;
    /// Field accessors (op, htype, hlen, hops, xid, secs, flags, chaddr, sname, file, options)
    pub fn op(&self) -> u8;
    pub fn htype(&self) -> u8;
    pub fn hlen(&self) -> u8;
    pub fn hops(&self) -> u8;
    pub fn xid(&self) -> u32;
    pub fn secs(&self) -> u16;
    pub fn flags(&self) -> u16;
    pub fn chaddr(&self) -> &[u8];
    pub fn sname(&self) -> &[u8];
    pub fn file(&self) -> &[u8];
    pub fn options(&self) -> &[u8];
    /// Address field accessors
    pub fn ciaddr_addr(&self) -> Ipv4Addr;
    pub fn yiaddr_addr(&self) -> Ipv4Addr;
    pub fn siaddr_addr(&self) -> Ipv4Addr;
    pub fn giaddr_addr(&self) -> Ipv4Addr;
    /// Address field setters
    pub fn set_op(&mut self, op: u8);
    pub fn set_hops(&mut self, hops: u8);
    pub fn set_ciaddr(&mut self, addr: Ipv4Addr);
    pub fn set_yiaddr(&mut self, addr: Ipv4Addr);
    pub fn set_siaddr(&mut self, addr: Ipv4Addr);
    pub fn set_giaddr(&mut self, addr: Ipv4Addr);
}
```

#### Public Functions

```rust
/// Process a DHCPv4 message and generate the appropriate response.
/// Implements the full state machine: DISCOVER→OFFER, REQUEST→ACK/NAK, etc.
/// Replaces C dhcp_reply() from src/rfc2131.c.
#[cfg(feature = "dhcp")]
pub fn dhcp_reply(
    context: &DhcpContext, iface_name: &str, iface_index: i32,
    packet: &mut [u8], sz: usize, now: Instant,
    unicast_dest: bool, loopback: bool,
) -> Result<(usize, bool), DnsmasqError>;

/// Relay an upstream DHCPv4 message (relay agent support).
/// Replaces C relay_upstream4() from src/rfc2131.c.
#[cfg(feature = "dhcp")]
pub fn relay_upstream4(
    iface_addr: Ipv4Addr, iface_index: i32,
    mess: &DhcpPacket, sz: usize, unicast: bool,
);

/// Process a relayed DHCPv4 reply message.
/// Replaces C relay_reply4() from src/rfc2131.c.
#[cfg(feature = "dhcp")]
pub fn relay_reply4(mess: &DhcpPacket, sz: usize, arrival_interface: &str) -> u32;
```

---

### 4.3 `dhcp::v4::options`

**Source:** `src/dhcp-common.c` (2,337 lines, DHCPv4 option portion) — DHCPv4 option
encoding and decoding utilities.

**Feature gate:** `#[cfg(feature = "dhcp")]`

#### Public Functions

```rust
/// Return the length of a DHCP option payload.
/// Replaces C option_len() from src/dhcp-common.c.
#[cfg(feature = "dhcp")]
pub fn option_len(opt: &[u8]) -> usize;

/// Return the data portion of a DHCP option.
/// Replaces C option_data() from src/dhcp-common.c.
#[cfg(feature = "dhcp")]
pub fn option_data(opt: &[u8]) -> &[u8];

/// Find the first occurrence of an option code in the primary option area.
/// Replaces C option_find1() from src/dhcp-common.c.
#[cfg(feature = "dhcp")]
pub fn option_find1(options: &[u8], code: u8) -> Option<&[u8]>;

/// Find an option with overload handling (sname/file field overload).
/// Replaces C option_find() from src/dhcp-common.c.
#[cfg(feature = "dhcp")]
pub fn option_find(packet: &DhcpPacket, code: u8) -> Option<&[u8]>;

/// Extract an IPv4 address from a DHCP option.
/// Replaces C option_addr() from src/dhcp-common.c.
#[cfg(feature = "dhcp")]
pub fn option_addr(opt: &[u8]) -> Option<Ipv4Addr>;

/// Extract an unsigned integer (1/2/4 bytes) from a DHCP option.
/// Replaces C option_uint() from src/dhcp-common.c.
#[cfg(feature = "dhcp")]
pub fn option_uint(opt: &[u8], size: usize) -> u32;

/// Sanitise a hostname extracted from DHCP options.
/// Replaces C sanitise() from src/dhcp-common.c.
#[cfg(feature = "dhcp")]
pub fn sanitise(name: &[u8]) -> Option<String>;

/// Check whether a DHCP option code is in a request list.
/// Replaces C in_list() from src/dhcp-common.c.
#[cfg(feature = "dhcp")]
pub fn in_list(list: &[u8], code: u8) -> bool;

/// Find free space in the option buffer for inserting a new option.
/// Replaces C free_space() from src/dhcp-common.c.
#[cfg(feature = "dhcp")]
pub fn free_space(options: &mut [u8], end: usize, code: u8, len: usize) -> Option<usize>;

/// Put a DHCP option (code + length + data) into the option buffer.
/// Replaces C option_put() from src/dhcp-common.c.
#[cfg(feature = "dhcp")]
pub fn option_put(options: &mut [u8], end: usize, code: u8, len: usize, val: u32) -> usize;

/// Put a string-valued DHCP option into the option buffer.
/// Replaces C option_put_string() from src/dhcp-common.c.
#[cfg(feature = "dhcp")]
pub fn option_put_string(options: &mut [u8], end: usize, code: u8, val: &str) -> usize;

/// Clear all options from the option buffer.
/// Replaces C clear_options() from src/dhcp-common.c.
#[cfg(feature = "dhcp")]
pub fn clear_options(options: &mut [u8], end: usize);

/// Calculate the maximum DHCP packet size the client can accept.
/// Replaces C dhcp_packet_size() from src/dhcp-common.c.
#[cfg(feature = "dhcp")]
pub fn dhcp_packet_size(packet: &DhcpPacket, netmask: Ipv4Addr) -> usize;
```

---

### 4.4 `dhcp::v6::server`

**Source:** `src/dhcp6.c` (1,487 lines) — DHCPv6 server, relay agent support, and prefix
delegation initialisation.

**Feature gate:** `#[cfg(feature = "dhcp6")]`

#### Public Functions

```rust
/// Initialise the DHCPv6 server: create sockets, join multicast groups.
/// Replaces C dhcp6_init() from src/dhcp6.c.
#[cfg(feature = "dhcp6")]
pub async fn dhcp6_init() -> Result<(), DnsmasqError>;

/// Process an incoming DHCPv6 packet.
/// Replaces C dhcp6_packet() from src/dhcp6.c.
#[cfg(feature = "dhcp6")]
pub async fn dhcp6_packet(state: &mut DaemonState, now: Instant) -> Result<(), DnsmasqError>;

/// Retrieve the MAC address from a DHCPv6 client request.
/// Replaces C get_client_mac() from src/dhcp6.c.
#[cfg(feature = "dhcp6")]
pub async fn get_client_mac(
    client: &Ipv6Addr, iface_index: i32,
) -> Option<[u8; 6]>;

/// Find a DHCPv6 static configuration by IPv6 address.
/// Replaces C config_find_by_address6() from src/dhcp6.c.
#[cfg(feature = "dhcp6")]
pub fn config_find_by_address6(
    configs: &[DhcpConfig], addr: &Ipv6Addr, prefix: u8, plain_range: bool,
) -> Option<&DhcpConfig>;

/// Allocate a DHCPv6 address from the configured context pools.
/// Replaces C address6_allocate() from src/dhcp6.c.
#[cfg(feature = "dhcp6")]
pub fn address6_allocate(
    context: &DhcpContext, clid: &[u8], iaid: u32, serial: i32,
    netids: &[DhcpNetId], plain_range: bool,
) -> Result<Ipv6Addr, DnsmasqError>;

/// Check whether an IPv6 address is available in the pool (not leased).
/// Replaces C address6_available() from src/dhcp6.c.
#[cfg(feature = "dhcp6")]
pub fn address6_available(
    context: &DhcpContext, addr: &Ipv6Addr, netids: &[DhcpNetId],
) -> bool;

/// Validate that an existing DHCPv6 address is still valid in the current context.
/// Replaces C address6_valid() from src/dhcp6.c.
#[cfg(feature = "dhcp6")]
pub fn address6_valid(
    context: &DhcpContext, addr: &Ipv6Addr, netids: &[DhcpNetId],
    plain_range: bool,
) -> bool;

/// Generate a DUID (DHCP Unique Identifier) for this server instance.
/// Replaces C make_duid() from src/dhcp6.c.
#[cfg(feature = "dhcp6")]
pub fn make_duid(now: Instant);

/// Construct DHCP contexts from the current network interface configuration.
/// Replaces C dhcp_construct_contexts() from src/dhcp6.c.
#[cfg(feature = "dhcp6")]
pub fn dhcp_construct_contexts(now: Instant);
```

---

### 4.5 `dhcp::v6::protocol`

**Source:** `src/rfc3315.c` (4,216 lines) + `src/dhcp6-protocol.h` (685 lines) — DHCPv6
protocol state machine implementing SOLICIT → ADVERTISE → REQUEST → REPLY per RFC 3315.

**Feature gate:** `#[cfg(feature = "dhcp6")]`

#### Public Types

```rust
/// DHCPv6 protocol state machine states.
pub enum DhcpV6State {
    Solicit,
    Advertise,
    Request,
    Confirm,
    Renew,
    Rebind,
    Reply,
    Release,
    Decline,
    Reconfigure,
    InformationRequest,
    RelayForw,
    RelayRepl,
}

/// Identity Association type (address vs prefix delegation).
pub enum IaType {
    Na,  // Non-temporary addresses (IA_NA)
    Ta,  // Temporary addresses (IA_TA)
    Pd,  // Prefix delegation (IA_PD)
}

/// State accumulated during DHCPv6 request processing.
pub struct Dhcp6RequestState { /* ... */ }
```

#### Public Functions

```rust
/// Find a DHCPv6 option by code within an option buffer.
/// Replaces C opt6_find() from src/rfc3315.c.
#[cfg(feature = "dhcp6")]
pub fn opt6_find(opts: &[u8], code: u16) -> Option<&[u8]>;

/// Iterate to the next DHCPv6 option in a buffer.
/// Replaces C opt6_next() from src/rfc3315.c.
#[cfg(feature = "dhcp6")]
pub fn opt6_next(current: &[u8], remaining: &[u8]) -> Option<&[u8]>;

/// Extract an unsigned integer value from a DHCPv6 option.
/// Replaces C opt6_uint() from src/rfc3315.c.
#[cfg(feature = "dhcp6")]
pub fn opt6_uint(opt: &[u8], offset: usize, size: usize) -> u32;

/// Process a DHCPv6 message and generate the appropriate response.
/// Implements the full state machine: SOLICIT→ADVERTISE, REQUEST→REPLY, etc.
/// Replaces C dhcp6_reply() from src/rfc3315.c.
#[cfg(feature = "dhcp6")]
pub fn dhcp6_reply(
    context: &DhcpContext, multicast_dest: bool, iface_index: i32,
    iface_name: &str, fallback: &Ipv6Addr, ll_addr: &Ipv6Addr,
    ula_addr: &Ipv6Addr, packet: &mut [u8], sz: usize,
    client_addr: &Ipv6Addr, now: Instant,
) -> Result<u16, DnsmasqError>;

/// Relay an upstream DHCPv6 message.
/// Replaces C relay_upstream6() from src/rfc3315.c.
#[cfg(feature = "dhcp6")]
pub fn relay_upstream6(
    iface_index: i32, sz: usize, peer: &Ipv6Addr,
    scope_id: u32, now: Instant,
) -> Result<bool, DnsmasqError>;

/// Process a relayed DHCPv6 reply message.
/// Replaces C relay_reply6() from src/rfc3315.c.
#[cfg(feature = "dhcp6")]
pub fn relay_reply6(peer: &SocketAddrV6, sz: usize, arrival_interface: &str) -> Result<bool, DnsmasqError>;
```

---

### 4.6 `dhcp::v6::outpacket`

**Source:** `src/outpacket.c` (702 lines) — DHCPv6 outgoing packet construction buffer
management. In Rust, `Vec<u8>` replaces the manual buffer allocator.

**Feature gate:** `#[cfg(feature = "dhcp6")]`

#### Public Types

```rust
/// DHCPv6 outgoing packet construction buffer.
/// In Rust, wraps a `Vec<u8>` with helper methods for building
/// nested DHCPv6 options in wire format.
/// Replaces C's manual buffer management in src/outpacket.c.
pub struct OutPacket { /* ... */ }

impl OutPacket {
    /// Create a new empty output packet.
    pub fn new() -> Self;
    /// Create with pre-allocated capacity.
    pub fn with_capacity(capacity: usize) -> Self;
    /// Reset the buffer and write counter.
    pub fn reset(&mut self);
    /// Save the current write position for later backpatching.
    pub fn save_counter(&mut self) -> usize;
    /// Current packet length.
    pub fn len(&self) -> usize;
    /// Whether the packet buffer is empty.
    pub fn is_empty(&self) -> bool;
    /// Start a new DHCPv6 option container; returns a handle for end_opt6().
    pub fn new_opt6(&mut self, opt: u16) -> i32;
    /// Write raw data into the packet.
    pub fn put_opt6(&mut self, data: &[u8]);
    /// Write raw bytes into an option.
    pub fn put_opt6_raw(&mut self, data: &[u8]);
    /// Write a 32-bit value (network byte order).
    pub fn put_opt6_long(&mut self, val: u32);
    /// Write a 16-bit value (network byte order).
    pub fn put_opt6_short(&mut self, val: u16);
    /// Write a single byte.
    pub fn put_opt6_char(&mut self, val: u8);
    /// Write a string.
    pub fn put_opt6_string(&mut self, s: &str);
    /// Close an open option container, writing the final length.
    pub fn end_opt6(&mut self, container: i32);
    /// Get a read-only reference to the packet bytes.
    pub fn as_bytes(&self) -> &[u8];
    /// Get a mutable reference to the packet bytes.
    pub fn as_mut_bytes(&mut self) -> &mut [u8];
}
```

---

### 4.7 `dhcp::common`

**Source:** `src/dhcp-common.c` (2,337 lines, shared portion) — shared DHCP utilities
used by both DHCPv4 and DHCPv6, including vendor class matching and option display.

**Feature gate:** `#[cfg(feature = "dhcp")]`

#### Public Types

```rust
/// Network identity tag for DHCP option matching.
pub struct NetId { /* ... */ }

/// DHCP option definition (code + value + flags).
pub struct DhcpOpt { /* ... */ }

/// Hardware address configuration for a DHCP host record.
pub struct HwAddrConfig { /* ... */ }

/// DHCP static host configuration record.
pub struct DhcpConfig { /* ... */ }

/// DHCP address pool context (network range, options, timing).
pub struct DhcpContext { /* ... */ }

/// DHCP relay configuration.
pub struct DhcpRelay { /* ... */ }

/// Tag-if conditional rule for DHCP option matching.
pub struct TagIfRule { /* ... */ }

/// Known DHCP option code definition with name, length, and type.
pub struct DhcpOptDef { /* ... */ }

/// Extra data variants for DHCP option encoding.
pub enum DhcpOptExtra { /* ... */ }

/// Protocol discriminator (DHCPv4 vs DHCPv6).
pub enum DhcpProtocol {
    V4,
    V6,
}

/// Address family discriminator.
pub enum AddressFamily {
    Inet,
    Inet6,
}
```

#### Public Functions

```rust
/// Initialise shared DHCP data structures.
/// Replaces C dhcp_common_init() from src/dhcp-common.c.
#[cfg(feature = "dhcp")]
pub fn dhcp_common_init();

/// Receive a DHCP packet from a raw or UDP socket with ancillary data.
/// Replaces C recv_dhcp_packet() from src/dhcp-common.c.
#[cfg(feature = "dhcp")]
pub async fn recv_dhcp_packet(fd: RawFd) -> Result<(Vec<u8>, MsgHdr), DnsmasqError>;

/// Match network tags against a tag pool.
/// Replaces C match_netid() from src/dhcp-common.c.
#[cfg(feature = "dhcp")]
pub fn match_netid(check: &[NetId], pool: &[NetId], tag_not_needed: bool) -> bool;

/// Match network tags with wildcard support.
/// Replaces C match_netid_wild() from src/dhcp-common.c.
#[cfg(feature = "dhcp")]
pub fn match_netid_wild(check: &[NetId], pool: &[NetId]) -> bool;

/// Process tag-if matching rules for DHCP network tags.
/// Replaces C run_tag_if() from src/dhcp-common.c.
#[cfg(feature = "dhcp")]
pub fn run_tag_if(tags: &[NetId]) -> Vec<NetId>;

/// Filter DHCP options based on tag matching.
/// Replaces C option_filter() from src/dhcp-common.c.
#[cfg(feature = "dhcp")]
pub fn option_filter(tags: &[NetId], opts: &[DhcpOpt]) -> Vec<&DhcpOpt>;

/// Check if PXE options are valid for the current client.
/// Replaces C pxe_ok() from src/dhcp-common.c.
#[cfg(feature = "dhcp")]
pub fn pxe_ok(tags: &[NetId], options: &[DhcpOpt]) -> bool;

/// Strip invalid characters from a hostname received from a DHCP client.
/// Replaces C strip_hostname() from src/dhcp-common.c.
#[cfg(feature = "dhcp")]
pub fn strip_hostname(hostname: &str) -> String;

/// Match raw bytes against a configuration pattern.
/// Replaces C match_bytes() from src/dhcp-common.c.
#[cfg(feature = "dhcp")]
pub fn match_bytes(opt: &DhcpOpt, data: &[u8]) -> bool;

/// Check whether a DHCP config entry matches by MAC address.
/// Replaces C config_has_mac() from src/dhcp-common.c.
#[cfg(feature = "dhcp")]
pub fn config_has_mac(config: &DhcpConfig, hwaddr: &[u8], hw_type: i32) -> bool;

/// Find a DHCP configuration record by client identity.
/// Replaces C find_config() from src/dhcp-common.c.
#[cfg(feature = "dhcp")]
pub fn find_config(
    configs: &[DhcpConfig], context: &DhcpContext,
    clid: Option<&[u8]>, hwaddr: &[u8], hostname: Option<&str>,
    filter: &[NetId],
) -> Option<&DhcpConfig>;

/// Update DHCP static host configurations from external sources.
/// Replaces C dhcp_update_configs() from src/dhcp-common.c.
#[cfg(feature = "dhcp")]
pub fn dhcp_update_configs(configs: &mut Vec<DhcpConfig>);

/// Determine which network interface a DHCP packet arrived on.
/// Replaces C which_device() from src/dhcp-common.c.
#[cfg(feature = "dhcp")]
pub fn which_device(dest: &std::net::SocketAddr) -> Option<String>;

/// Bind DHCP sockets to specific interfaces.
/// Replaces C bind_dhcp_devices() from src/dhcp-common.c.
#[cfg(feature = "dhcp")]
pub fn bind_dhcp_devices(interfaces: &[String]) -> DnsmasqResult<()>;

/// Look up a DHCP option code by name.
/// Replaces C lookup_dhcp_opt() from src/dhcp-common.c.
#[cfg(feature = "dhcp")]
pub fn lookup_dhcp_opt(protocol: i32, name: &str) -> Option<u32>;

/// Look up the expected length for a DHCP option code.
/// Replaces C lookup_dhcp_len() from src/dhcp-common.c.
#[cfg(feature = "dhcp")]
pub fn lookup_dhcp_len(protocol: i32, code: u32) -> Option<usize>;

/// Format a DHCP option value as a human-readable string.
/// Replaces C option_string() from src/dhcp-common.c.
#[cfg(feature = "dhcp")]
pub fn option_string(protocol: i32, code: u32, data: &[u8]) -> String;
```

---

### 4.8 `dhcp::lease`

**Source:** `src/lease.c` (3,364 lines) — DHCP lease management including persistence to
the lease file, lease lookup, allocation, pruning, and DNS update integration.

**Feature gate:** `#[cfg(feature = "dhcp")]`

#### Public Types

```rust
/// Discriminator for DHCPv4 vs DHCPv6 lease types.
pub enum LeaseType {
    V4,
    Na,  // DHCPv6 non-temporary address
    Ta,  // DHCPv6 temporary address
    Pd,  // DHCPv6 prefix delegation
}

/// Flags on a lease entry (state tracking).
pub struct LeaseFlags { /* ... */ }

/// A DHCP lease entry.
pub struct DhcpLease { /* ... */ }

/// Lease database container with lookup indexes.
pub struct LeaseDatabase { /* ... */ }

impl LeaseDatabase {
    /// Create a new empty lease database.
    pub fn new() -> Self;
}
```

#### Public Functions

```rust
/// Write current lease database state to the lease file.
/// Replaces C lease_update_file() from src/lease.c.
#[cfg(feature = "dhcp")]
pub fn lease_update_file(now: Instant) -> Result<(), DnsmasqError>;

/// Initialise the lease database, reading persisted leases from the lease file.
/// Replaces C lease_init() from src/lease.c.
#[cfg(feature = "dhcp")]
pub fn lease_init(now: Instant) -> Result<(), DnsmasqError>;

/// Allocate a new DHCPv4 lease for the given IP address.
/// Replaces C lease4_allocate() from src/lease.c.
#[cfg(feature = "dhcp")]
pub fn lease4_allocate(addr: Ipv4Addr) -> Result<DhcpLease, DnsmasqError>;

/// Allocate a new DHCPv6 lease for the given IPv6 address.
/// Replaces C lease6_allocate() from src/lease.c.
#[cfg(feature = "dhcp6")]
pub fn lease6_allocate(addr: &Ipv6Addr, lease_type: LeaseType) -> Result<DhcpLease, DnsmasqError>;

/// Add a lease to the database.
/// Replaces C lease_db_add() from src/lease.c.
#[cfg(feature = "dhcp")]
pub fn lease_db_add(db: &mut LeaseDatabase, lease: DhcpLease);

/// Find a DHCPv4 lease by IPv4 address.
/// Replaces C lease_find_by_addr() from src/lease.c.
#[cfg(feature = "dhcp")]
pub fn lease_find_by_addr(addr: Ipv4Addr) -> Option<&DhcpLease>;

/// Find a DHCPv4 lease by IPv4 address (mutable).
/// Replaces C lease_find_by_addr() from src/lease.c.
#[cfg(feature = "dhcp")]
pub fn lease_find_by_addr_mut(addr: Ipv4Addr) -> Option<&mut DhcpLease>;

/// Find a lease by client hardware address or client identifier.
/// Replaces C lease_find_by_client() from src/lease.c.
#[cfg(feature = "dhcp")]
pub fn lease_find_by_client(hwaddr: &[u8], hw_type: i32, clid: Option<&[u8]>) -> Option<&DhcpLease>;

/// Find a DHCPv6 lease by type and IAID.
/// Replaces C lease6_find() from src/lease.c.
#[cfg(feature = "dhcp6")]
pub fn lease6_find(lease_type: LeaseType, iaid: u32) -> Option<&DhcpLease>;

/// Find a DHCPv6 lease by client DUID.
/// Replaces C lease6_find_by_client() from src/lease.c.
#[cfg(feature = "dhcp6")]
pub fn lease6_find_by_client(clid: &[u8], iaid: u32) -> Option<&DhcpLease>;

/// Find a DHCPv6 lease by IPv6 address.
/// Replaces C lease6_find_by_addr() from src/lease.c.
#[cfg(feature = "dhcp6")]
pub fn lease6_find_by_addr(addr: &Ipv6Addr, prefix: u8) -> Option<&DhcpLease>;

/// Find a DHCPv6 lease by plain IPv6 address (no prefix consideration).
/// Replaces C lease6_find_by_plain_addr() from src/lease.c.
#[cfg(feature = "dhcp6")]
pub fn lease6_find_by_plain_addr(addr: &Ipv6Addr) -> Option<&DhcpLease>;

/// Reset DHCPv6 lease state for re-enumeration.
/// Replaces C lease6_reset() from src/lease.c.
#[cfg(feature = "dhcp6")]
pub fn lease6_reset();

/// Set the lease expiry time.
/// Replaces C lease_set_expires() from src/lease.c.
#[cfg(feature = "dhcp")]
pub fn lease_set_expires(lease: &mut DhcpLease, duration: u32, now: Instant);

/// Set the lease expiry time from the database context.
/// Replaces C lease_set_expires() (database variant) from src/lease.c.
#[cfg(feature = "dhcp")]
pub fn lease_set_expires_db(lease: &mut DhcpLease, expires: u64);

/// Set the IAID on a DHCPv6 lease.
/// Replaces C lease_set_iaid() from src/lease.c.
#[cfg(feature = "dhcp6")]
pub fn lease_set_iaid(lease: &mut DhcpLease, iaid: u32);

/// Set the hardware address and client identifier on a lease.
/// Replaces C lease_set_hwaddr() from src/lease.c.
#[cfg(feature = "dhcp")]
pub fn lease_set_hwaddr(lease: &mut DhcpLease, hwaddr: &[u8], clid: Option<&[u8]>, hw_type: i32, now: Instant, force: bool);

/// Set the hostname on a lease (with domain qualification).
/// Replaces C lease_set_hostname() from src/lease.c.
#[cfg(feature = "dhcp")]
pub fn lease_set_hostname(lease: &mut DhcpLease, name: &str, auth: bool, domain: Option<&str>, config_domain: Option<&str>);

/// Set the interface name on a lease.
/// Replaces C lease_set_interface() from src/lease.c.
#[cfg(feature = "dhcp")]
pub fn lease_set_interface(lease: &mut DhcpLease, iface: &str, now: Instant);

/// Set the relay agent information (option 82) on a lease.
/// Replaces C lease_set_agent_id() from src/lease.c.
#[cfg(feature = "dhcp")]
pub fn lease_set_agent_id(lease: &mut DhcpLease, agent_id: &[u8]);

/// Set the vendor class identifier on a lease.
/// Replaces C lease_set_vendorclass() from src/lease.c.
#[cfg(feature = "dhcp")]
pub fn lease_set_vendorclass(lease: &mut DhcpLease, vendorclass: &str);
```

---

### 4.9 `dhcp::radv`

**Source:** `src/radv.c` (2,175 lines) + `src/radv-protocol.h` (869 lines) — IPv6 Router
Advertisement construction and dispatch per RFC 4861.

**Feature gate:** `#[cfg(feature = "dhcp6")]`

#### Public Types

```rust
/// ICMPv6 Router Advertisement packet structure.
pub struct RaPacket { /* ... */ }

/// ICMPv6 Prefix Information Option (RFC 4861 §4.6.2).
pub struct PrefixOpt { /* ... */ }

/// ICMPv6 Echo Request/Reply for neighbor probing.
pub struct PingPacket { /* ... */ }

/// ICMPv6 Neighbor Solicitation/Advertisement.
pub struct NeighPacket { /* ... */ }

/// Per-interface Router Advertisement configuration.
pub struct RaInterface { /* ... */ }

/// Parameters accumulated during RA construction.
pub struct RaParam { /* ... */ }
```

#### Public Functions

```rust
/// Initialise the Router Advertisement subsystem.
/// Replaces C ra_init() from src/radv.c.
#[cfg(feature = "dhcp6")]
pub fn ra_init(now: Instant) -> Result<(), DnsmasqError>;

/// Process an incoming ICMPv6 Router Solicitation packet.
/// Replaces C icmp6_packet() from src/radv.c.
#[cfg(feature = "dhcp6")]
pub async fn icmp6_packet(state: &mut DaemonState, now: Instant) -> Result<(), DnsmasqError>;

/// Construct and send a Router Advertisement on the specified interface.
/// Replaces C send_ra() from src/radv.c.
#[cfg(feature = "dhcp6")]
pub fn send_ra(now: Instant, iface_index: i32, iface_name: &str, dest: &Ipv6Addr) -> DnsmasqResult<()>;

/// Send periodic unsolicited Router Advertisements.
/// Returns the next scheduled RA time.
/// Replaces C periodic_ra() from src/radv.c.
#[cfg(feature = "dhcp6")]
pub fn periodic_ra(now: Instant) -> Instant;

/// Start sending unsolicited RAs for a newly configured context.
/// Replaces C ra_start_unsolicited() from src/radv.c.
#[cfg(feature = "dhcp6")]
pub fn ra_start_unsolicited(now: Instant, context: &DhcpContext);
```

---

### 4.10 `dhcp::slaac`

**Source:** `src/slaac.c` (537 lines) — SLAAC (Stateless Address Autoconfiguration)
address tracking and ping checks.

**Feature gate:** `#[cfg(feature = "dhcp6")]`

#### Public Types

```rust
/// A SLAAC-derived IPv6 address record associated with a lease.
pub struct SlaacAddress { /* ... */ }

/// SLAAC lease information for tracking purposes.
pub struct SlaacLeaseInfo { /* ... */ }

/// A pending SLAAC ping (DAD probe) record.
pub struct PendingPing { /* ... */ }

/// Result of periodic SLAAC maintenance.
pub struct PeriodicSlaacResult { /* ... */ }
```

#### Public Functions

```rust
/// Convert a MAC address to an EUI-64 identifier for SLAAC.
/// Replaces C mac_to_eui64() from src/slaac.c.
#[cfg(feature = "dhcp6")]
pub fn mac_to_eui64(mac: &[u8]) -> [u8; 8];

/// Add SLAAC-derived addresses to a DHCP lease for tracking.
/// Replaces C slaac_add_addrs() from src/slaac.c.
#[cfg(feature = "dhcp6")]
pub fn slaac_add_addrs(lease: &mut DhcpLease, now: Instant, force: bool);

/// Periodic SLAAC maintenance: prune expired SLAAC entries.
/// Returns the next scheduled check time.
/// Replaces C periodic_slaac() from src/slaac.c.
#[cfg(feature = "dhcp6")]
pub fn periodic_slaac(now: Instant, leases: &mut [DhcpLease]) -> Instant;

/// Handle an error from a SLAAC ping send attempt.
/// Replaces C handle_ping_send_error() from src/slaac.c.
#[cfg(feature = "dhcp6")]
pub fn handle_ping_send_error(addr: &Ipv6Addr, err: std::io::Error);

/// Handle a SLAAC ping reply confirming address reachability.
/// Replaces C slaac_ping_reply() from src/slaac.c.
#[cfg(feature = "dhcp6")]
pub fn slaac_ping_reply(sender: &Ipv6Addr, packet: &[u8], interface: &str, leases: &mut [DhcpLease]);
```

---

### 4.11 `dhcp::ip6addr`

**Source:** `src/ip6addr.h` (183 lines) — IPv6 address utility macros, converted to Rust
functions.

#### Public Functions

```rust
/// Check whether an IPv6 address is a Unique Local Address (ULA, fc00::/7).
/// Replaces C is_ula() macro from src/ip6addr.h.
pub fn is_ula(addr: &Ipv6Addr) -> bool;

/// Check whether an IPv6 address is a ULA with a zero interface ID.
/// Replaces C is_ula_zero() macro from src/ip6addr.h.
pub fn is_ula_zero(addr: &Ipv6Addr) -> bool;

/// Check whether an IPv6 address is a link-local address with a zero interface ID.
/// Replaces C is_link_local_zero() macro from src/ip6addr.h.
pub fn is_link_local_zero(addr: &Ipv6Addr) -> bool;
```

---

## 5. Network Module (`crate::network`)

The network module provides platform-abstracted network interface enumeration, socket
binding, and low-level network monitoring.

### 5.1 `network::interface`

**Source:** `src/network.c` (6,331 lines) — interface enumeration, socket creation, bind
operations, and listener management.

#### Public Types

```rust
/// Platform-abstracted socket address (IPv4 or IPv6 with scope).
/// Replaces C `union mysockaddr` from src/dnsmasq.h.
pub struct MySockAddr { /* ... */ }

impl MySockAddr {
    /// Construct from an IPv4 address and port.
    pub fn v4(addr: Ipv4Addr, port: u16) -> Self;
    /// Construct from an IPv6 address, port, and scope ID.
    pub fn v6(addr: Ipv6Addr, port: u16, scope_id: u32) -> Self;
    /// Get the port number.
    pub fn port(&self) -> u16;
    /// Set the port number.
    pub fn set_port(&mut self, port: u16);
    /// Get the IP address.
    pub fn ip(&self) -> std::net::IpAddr;
}

/// Extract the IP address from a MySockAddr.
pub fn mysockaddr_ip(addr: &MySockAddr) -> std::net::IpAddr;
```

#### Public Functions

```rust
/// Translate a network interface index to its name.
/// Replaces C indextoname() from src/network.c.
pub fn index_to_name(fd: RawFd, index: i32) -> Result<String, DnsmasqError>;

/// Check whether an address on a named interface should be used.
/// Replaces C iface_check() from src/network.c.
pub fn iface_check(family: i32, addr: &AllAddr, name: &str) -> (bool, bool);

/// Check for loopback exceptions in interface binding.
/// Replaces C loopback_exception() from src/network.c.
pub fn loopback_exception(fd: RawFd, family: i32, addr: &AllAddr, name: &str) -> bool;

/// Check for label exceptions in interface binding.
/// Replaces C label_exception() from src/network.c.
pub fn label_exception(index: i32, family: i32, addr: &AllAddr) -> bool;

/// Enumerate all network interfaces and their addresses.
/// Replaces C enumerate_interfaces() from src/network.c.
pub fn enumerate_interfaces(reset: bool) -> Result<bool, DnsmasqError>;

/// Set FD_CLOEXEC and O_NONBLOCK on a file descriptor.
/// Replaces C fix_fd() from src/network.c.
pub fn fix_fd(fd: RawFd) -> Result<(), DnsmasqError>;

/// Set IPV6_RECVPKTINFO on a socket for destination address retrieval.
/// Replaces C set_ipv6pktinfo() from src/network.c.
pub fn set_ipv6pktinfo(fd: RawFd) -> Result<(), DnsmasqError>;

/// Determine the TCP interface for a connected socket.
/// Replaces C tcp_interface() from src/network.c.
pub fn tcp_interface(fd: RawFd, af: i32) -> Result<i32, DnsmasqError>;

/// Create wildcard listeners (bind to INADDR_ANY/in6addr_any).
/// Replaces C create_wildcard_listeners() from src/network.c.
pub fn create_wildcard_listeners() -> Result<(), DnsmasqError>;

/// Create per-interface bound listeners for each configured address.
/// Replaces C create_bound_listeners() from src/network.c.
pub fn create_bound_listeners(die_now: bool) -> Result<(), DnsmasqError>;

/// Log warnings about interfaces that could not bind.
/// Replaces C warn_bound_listeners() from src/network.c.
pub fn warn_bound_listeners();

/// Log warnings about wildcard-mode interface labels.
/// Replaces C warn_wild_labels() from src/network.c.
pub fn warn_wild_labels();

/// Log warnings about --interface-name entries.
/// Replaces C warn_int_names() from src/network.c.
pub fn warn_int_names();

/// Check if Duplicate Address Detection listeners are needed.
/// Replaces C is_dad_listeners() from src/network.c.
pub fn is_dad_listeners() -> bool;

/// Join DHCPv6 multicast groups on all interfaces.
/// Replaces C join_multicast() from src/network.c.
#[cfg(feature = "dhcp6")]
pub fn join_multicast(die_now: bool);

/// Bind a socket to a local address, optionally to a specific interface.
/// Replaces C local_bind() from src/network.c.
pub fn local_bind(fd: RawFd, addr: &MySockAddr, intname: Option<&str>, ifindex: u32, is_tcp: bool) -> Result<(), DnsmasqError>;

/// Pre-allocate shared file descriptors for server connections.
/// Replaces C pre_allocate_sfds() from src/network.c.
pub fn pre_allocate_sfds();

/// Validate configured upstream servers, removing unreachable ones.
/// Replaces C check_servers() from src/network.c.
pub fn check_servers(no_loop_call: bool);

/// Reload upstream server list from resolv.conf or equivalent.
/// Replaces C reload_servers() from src/network.c.
pub fn reload_servers(fname: &str) -> Result<bool, DnsmasqError>;

/// Handle a new address event (interface address added or removed).
/// Replaces C newaddress() from src/network.c.
pub fn newaddress(now: Instant);
```

---

### 5.2 `network::netlink`

**Source:** `src/netlink.c` (740 lines) — Linux netlink socket interface for network
address and route change monitoring.

**Platform gate:** `#[cfg(target_os = "linux")]`

#### Public Types

```rust
/// Callback discriminator for netlink interface enumeration results.
pub enum IfaceCallback { /* ... */ }

/// Netlink-based network interface enumerator.
/// Wraps a NETLINK_ROUTE socket for address/route monitoring.
pub struct NetlinkNetwork { /* ... */ }

impl NetlinkNetwork {
    /// Create a new netlink network interface.
    pub fn new() -> DnsmasqResult<Self>;
    /// Enumerate all interfaces and their addresses.
    pub fn enumerate_interfaces(&self) -> DnsmasqResult<Vec<IfaceCallback>>;
    /// Enumerate IPv4 addresses only.
    pub fn enumerate_interfaces_v4(&self) -> DnsmasqResult<Vec<IfaceCallback>>;
    /// Enumerate IPv6 addresses only.
    pub fn enumerate_interfaces_v6(&self) -> DnsmasqResult<Vec<IfaceCallback>>;
    /// Process pending multicast netlink messages.
    pub fn process_multicast(&self) -> DnsmasqResult<bool>;
    /// Initialise monitoring for address/route changes.
    pub fn init_monitoring(&self) -> DnsmasqResult<()>;
}
```

#### Free Functions

```rust
/// Initialise the netlink socket for monitoring address/route changes.
/// Replaces C netlink_init() from src/netlink.c.
#[cfg(target_os = "linux")]
pub fn netlink_init() -> Result<(), DnsmasqError>;

/// Process pending netlink multicast messages (address/route changes).
/// Replaces C netlink_multicast() from src/netlink.c.
#[cfg(target_os = "linux")]
pub fn netlink_multicast();

/// Async netlink event processing.
/// Replaces C nl_async() from src/netlink.c.
#[cfg(target_os = "linux")]
pub fn nl_async() -> DnsmasqResult<bool>;
```

---

### 5.3 `network::bpf`

**Source:** `src/bpf.c` (805 lines) — BSD BPF (Berkeley Packet Filter) device access for
raw DHCP packet capture on BSD and macOS systems.

**Platform gate:** `#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "macos"))]`

#### Public Types

```rust
/// BPF-based network interface enumerator for BSD systems.
pub struct BpfNetwork { /* ... */ }

impl BpfNetwork {
    /// Create a new BPF network interface.
    pub fn new() -> DnsmasqResult<Self>;
    /// Enumerate IPv4 addresses via getifaddrs.
    pub fn enumerate_interfaces_v4(&self) -> DnsmasqResult<Vec<IfaceCallback>>;
    /// Enumerate IPv6 addresses via getifaddrs.
    pub fn enumerate_interfaces_v6(&self) -> DnsmasqResult<Vec<IfaceCallback>>;
    /// Initialise routing socket monitoring.
    pub fn init_monitoring(&self) -> DnsmasqResult<()>;
}
```

#### Free Functions

```rust
/// Enumerate ARP entries on BSD (via sysctl/route socket).
/// Replaces C arp_enumerate_bsd() from src/bpf.c.
#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "macos"))]
pub fn arp_enumerate_bsd() -> DnsmasqResult<Vec<ArpRecord>>;

/// Initialise BPF device for raw DHCP packet capture.
/// Replaces C init_bpf() from src/bpf.c.
#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "macos"))]
pub fn init_bpf() -> Result<(), DnsmasqError>;

/// Send a DHCP packet via BPF (bypassing IP stack for broadcast).
/// Replaces C send_via_bpf() from src/bpf.c.
#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "macos"))]
pub fn send_via_bpf(packet: &DhcpPacket, len: usize, iface_addr: Ipv4Addr, ifr: &str) -> Result<(), DnsmasqError>;

/// Initialise routing socket for route change monitoring.
/// Replaces C route_init() from src/bpf.c.
#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "macos"))]
pub fn route_init() -> Result<(), DnsmasqError>;

/// Process routing socket events.
/// Replaces C route_sock() from src/bpf.c.
#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "macos"))]
pub fn route_sock();
```

---

### 5.4 `network::arp`

**Source:** `src/arp.c` (475 lines) — ARP (Address Resolution Protocol) cache reading for
DHCP address conflict detection.

#### Public Types

```rust
/// ARP lookup result status.
pub enum ArpStatus {
    Found,
    NotFound,
    Pending,
}

/// ARP cache entry record.
pub struct ArpRecord {
    pub ip: std::net::IpAddr,
    pub mac: [u8; 6],
    pub iface: String,
}

/// Trait for ARP enumeration (platform-specific implementations).
pub trait ArpEnumerator {
    fn enumerate(&self) -> DnsmasqResult<Vec<ArpRecord>>;
}

/// Null ARP enumerator (no-op for unsupported platforms).
pub struct NullArpEnumerator;

/// ARP cache with lookup and event tracking.
pub struct ArpCache { /* ... */ }

impl ArpCache {
    /// Create a new ARP cache.
    pub fn new() -> Self;
    /// Look up a MAC address by IP from the ARP cache.
    pub fn find_mac(&self, addr: &MySockAddr, lazy: bool, now: Instant) -> Option<Vec<u8>>;
    /// Execute ARP event scripts (for lease-change notifications).
    pub fn do_arp_script_run(&mut self) -> bool;
}
```

#### Free Functions

```rust
/// Look up a MAC address in the system ARP cache for a given IP address.
/// Replaces C find_mac() from src/arp.c.
pub fn find_mac(addr: &MySockAddr, lazy: bool, now: Instant) -> Option<Vec<u8>>;

/// Execute ARP event scripts (for lease-change notifications).
/// Replaces C do_arp_script_run() from src/arp.c.
pub fn do_arp_script_run() -> bool;
```

---

## 6. Integration Module (`crate::integration`)

The integration module provides external system integrations, each gated by a Cargo
feature flag. These modules are independently optional.

### 6.1 `integration::dbus`

**Source:** `src/dbus.c` (2,175 lines) — D-Bus interface for NetworkManager integration
and remote management.

**Feature gate:** `#[cfg(feature = "dbus")]`

#### Public Types

```rust
/// D-Bus integration error type.
pub enum DbusError { /* ... */ }

/// D-Bus controller managing the dnsmasq service bus connection.
pub struct DbusController { /* ... */ }

impl DbusController {
    /// Create a new D-Bus controller and register the service on the system bus.
    pub fn new() -> Result<Self, DbusError>;
    /// Get file descriptors for D-Bus watches (for I/O reactor integration).
    pub fn get_fds(&self) -> Vec<RawFd>;
    /// Check for incoming D-Bus method calls and signals.
    pub fn check_listeners(&self);
    /// Emit a D-Bus signal (e.g., DHCP lease change).
    pub fn emit_signal(&self, action: i32, lease: &DhcpLease, hostname: Option<&str>);
}
```

---

### 6.2 `integration::ubus`

**Source:** `src/ubus.c` (968 lines) — OpenWrt ubus message bus integration.

**Feature gate:** `#[cfg(feature = "ubus")]`

#### Public Types

```rust
/// OpenWrt ubus controller managing the bus connection.
pub struct UbusController { /* ... */ }

impl UbusController {
    /// Create a new ubus controller and connect to the system bus.
    pub fn new() -> Result<Self, DnsmasqError>;
    /// Get the ubus file descriptor for I/O reactor integration.
    pub fn get_fd(&self) -> RawFd;
    /// Check for incoming ubus messages and dispatch handlers.
    pub fn check_listeners(&self);
    /// Broadcast a ubus event for DHCP lease changes.
    pub fn event_bcast(&self, event_type: &str, mac: &str, ip: &str, name: &str, interface: &str);
    /// Broadcast a connmark allowlist refused event.
    pub fn event_bcast_connmark_allowlist_refused(&self, addr: &str, mac: &str);
    /// Broadcast a connmark allowlist resolved event.
    pub fn event_bcast_connmark_allowlist_resolved(&self, addr: &str, name: &str);
}
```

---

### 6.3 `integration::helper`

**Source:** `src/helper.c` (1,528 lines) — script execution helper for lease-change
callbacks using `tokio::process::Command`.

**Feature gate:** `#[cfg(feature = "script")]`

#### Public Types

```rust
/// Script event action type.
pub enum EventAction {
    Add,
    Del,
    Old,
    Arp,
    ArpDel,
    Tftp,
    RelaySnoopV4,
    RelaySnoopV6,
}

/// A queued script execution event.
pub struct ScriptEvent { /* ... */ }

/// Script helper managing the event queue and subprocess execution.
pub struct ScriptHelper { /* ... */ }

impl ScriptHelper {
    /// Create a new script helper.
    pub fn new() -> Self;
    /// Create from DaemonState credentials.
    pub fn from_daemon_state(uid: u32, gid: u32) -> Self;
    /// Resolve default credentials (uid/gid) for the helper process.
    pub fn resolve_default_credentials(&mut self);
    /// Queue a lease-change script execution.
    pub fn queue_script(&mut self, action: EventAction, lease: &DhcpLease, hostname: Option<&str>, now: Instant);
    /// Queue a TFTP event for script notification.
    pub fn queue_tftp(&mut self, file_len: u64, filename: &str, peer: &MySockAddr);
    /// Queue an ARP event for script notification.
    pub fn queue_arp(&mut self, action: EventAction, mac: &[u8], family: i32, addr: &AllAddr);
    /// Queue a relay snoop event.
    pub fn queue_relay_snoop(&mut self, action: EventAction, lease: &DhcpLease);
    /// Check if the event queue is empty.
    pub fn is_empty(&self) -> bool;
    /// Process all pending events by executing scripts.
    pub fn process_events(&mut self) -> DnsmasqResult<()>;
}
```

#### Free Functions

```rust
/// Queue a lease-change script execution (convenience wrapper).
/// Replaces C queue_script() from src/helper.c.
#[cfg(feature = "script")]
pub fn queue_script(action: i32, lease: &DhcpLease, hostname: Option<&str>, now: Instant);

/// Queue an ARP event for script notification (convenience wrapper).
/// Replaces C queue_arp() from src/helper.c.
#[cfg(feature = "script")]
pub fn queue_arp(action: i32, mac: &[u8], family: i32, addr: &AllAddr);
```

---

### 6.4 `integration::conntrack`

**Source:** `src/conntrack.c` (324 lines) — Linux conntrack mark preservation for
firewall integration.

**Feature gate:** `#[cfg(all(target_os = "linux", feature = "conntrack"))]`

#### Public Types

```rust
/// Errors from conntrack mark operations.
pub enum ConntrackError {
    SocketCreate(io::Error),
    Query(io::Error),
    NotFound,
}
```

#### Public Functions

```rust
/// Retrieve the conntrack mark for an incoming connection.
/// Used to preserve firewall marks across DNS forwarding.
/// Replaces C get_incoming_mark() from src/conntrack.c.
#[cfg(all(target_os = "linux", feature = "conntrack"))]
pub fn get_incoming_mark(peer: &MySockAddr, local: &AllAddr, is_tcp: bool) -> Result<u32, DnsmasqError>;
```

---

### 6.5 `integration::ipset`

**Source:** `src/ipset.c` (532 lines) — Linux ipset integration for adding resolved
addresses to firewall sets.

**Feature gate:** `#[cfg(all(target_os = "linux", feature = "ipset"))]`

#### Public Types

```rust
/// Controller for ipset netlink operations.
pub struct IpsetController { /* ... */ }

impl IpsetController {
    /// Create a new ipset controller and initialise the netlink socket.
    pub fn new() -> Result<Self, DnsmasqError>;
    /// Add or remove an IP address from a named ipset.
    pub fn add_to_ipset(&self, setname: &str, addr: &AllAddr, flags: i32, remove: bool) -> Result<(), DnsmasqError>;
}
```

---

### 6.6 `integration::nftset`

**Source:** `src/nftset.c` (392 lines) — nftables set integration for adding resolved
addresses to nftables firewall sets.

**Feature gate:** `#[cfg(all(target_os = "linux", feature = "nftset"))]`

#### Public Types

```rust
/// Errors from nftables set operations.
pub enum NftsetError {
    InitFailed(String),
    AddFailed(String),
}

/// Controller for nftables set operations.
pub struct NftsetController { /* ... */ }

impl NftsetController {
    /// Create a new nftset controller and initialise the interface.
    pub fn new() -> Result<Self, DnsmasqError>;
    /// Add or remove an IP address from a named nftables set.
    pub fn add_to_nftset(&self, setpath: &str, addr: &AllAddr, flags: i32, remove: bool) -> Result<(), DnsmasqError>;
}
```

---

### 6.7 `integration::tables`

**Source:** `src/tables.c` (386 lines) — routing table interaction for BSD platforms.

**Platform gate:** `#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]`

#### Public Types

```rust
/// Controller for PF table operations on BSD platforms.
pub struct PfTableController { /* ... */ }

impl PfTableController {
    /// Create a new PF table controller.
    pub fn new() -> Result<Self, DnsmasqError>;
    /// Add an address to a PF table.
    pub fn add_to_table(&self, table: &str, addr: &AllAddr) -> Result<(), DnsmasqError>;
}
```

---

## 7. Services Module (`crate::services`)

### 7.1 `services::tftp`

**Source:** `src/tftp.c` (1,647 lines) — TFTP (Trivial File Transfer Protocol) server
with PXE (Preboot Execution Environment) network boot support.

**Feature gate:** `#[cfg(feature = "tftp")]`

#### Public Types

```rust
/// TFTP error codes (RFC 1350).
pub enum TftpError {
    FileNotFound,
    AccessViolation,
    DiskFull,
    IllegalOperation,
    UnknownTransferId,
    FileAlreadyExists,
    PermissionDenied,
    OptionNegotiation,
}

/// TFTP transfer modes.
pub enum TransferMode {
    Octet,
    Netascii,
}

/// Represents an open file for a TFTP transfer.
pub struct TftpFile { /* ... */ }

/// Active TFTP transfer state machine.
pub struct TftpTransfer { /* ... */ }

/// TFTP directory prefix configuration.
pub struct TftpPrefix { /* ... */ }

/// TFTP server managing all active transfers and listener sockets.
pub struct TftpServer { /* ... */ }

impl TftpServer {
    /// Create a new TFTP server instance.
    pub fn new() -> Self;
    /// Handle an incoming TFTP request (RRQ/WRQ).
    pub async fn handle_request(&mut self, listener: &TokioUdpSocket, now: Instant) -> Result<(), DnsmasqError>;
    /// Process pending TFTP data transfers (send DATA/receive ACK).
    pub async fn process_transfers(&mut self, now: Instant) -> Result<(), DnsmasqError>;
    /// Check TFTP listener sockets for incoming requests.
    pub async fn check_listeners(&mut self, state: &mut DaemonState, now: Instant) -> Result<(), DnsmasqError>;
    /// Clean up completed transfers and run notification scripts.
    pub fn process_done_transfers(&mut self) -> bool;
    /// Collect file descriptors for active transfers (for poll integration).
    pub fn get_transfer_fds(&self) -> Vec<RawFd>;
}
```

---

## 8. Diagnostics Module (`crate::diagnostics`)

The diagnostics module provides packet dumping, file change monitoring, and runtime
metrics counters for operational visibility.

### 8.1 `diagnostics::dump`

**Source:** `src/dump.c` (815 lines) — pcap-format packet dump for debugging and
analysis.

**Feature gate:** `#[cfg(feature = "dumpfile")]`

#### Public Types

```rust
/// Packet dumper managing the pcap output file.
pub struct PacketDumper { /* ... */ }

impl PacketDumper {
    /// Create and initialise a new packet dumper with the given file path.
    /// Replaces C dump_init() from src/dump.c.
    pub fn new(path: &str) -> Result<Self, DnsmasqError>;
    /// Dump a UDP packet to the pcap file.
    /// Replaces C dump_packet_udp() from src/dump.c.
    pub fn dump_packet_udp(&mut self, mask: i32, packet: &[u8], src: &MySockAddr, dst: &MySockAddr, fd: RawFd);
    /// Dump an ICMPv6 packet to the pcap file.
    /// Replaces C dump_packet_icmp() from src/dump.c.
    pub fn dump_packet_icmp(&mut self, mask: i32, packet: &[u8], src: &MySockAddr, dst: &MySockAddr);
}
```

---

### 8.2 `diagnostics::inotify`

**Source:** `src/inotify.c` (687 lines) — asynchronous file change monitoring using Linux
inotify for `/etc/hosts` and `/etc/resolv.conf` changes.

**Feature gate:** `#[cfg(feature = "inotify")]`

#### Public Types

```rust
/// Callback trait for inotify file change events.
pub trait InotifyCallbacks {
    /// Called when a watched file is modified.
    fn on_file_changed(&mut self, path: &str);
}

/// Asynchronous file change watcher using inotify.
pub struct InotifyWatcher { /* ... */ }

impl InotifyWatcher {
    /// Create a new inotify watcher and initialise watches.
    /// Replaces C inotify_dnsmasq_init() from src/inotify.c.
    pub fn new() -> Result<Self, DnsmasqError>;
    /// Set up dynamic inotify watches for runtime-added hosts directories.
    /// Replaces C set_dynamic_inotify() from src/inotify.c.
    pub fn setup_dynamic_dirs(&mut self, dirs: &[&str]) -> Result<(), DnsmasqError>;
    /// Check for inotify events and process file changes.
    /// Returns true if files were modified and configuration needs reloading.
    /// Replaces C inotify_check() from src/inotify.c.
    pub fn check_events(&mut self, now: Instant) -> Result<bool, DnsmasqError>;
}
```

---

### 8.3 `diagnostics::metrics`

**Source:** `src/metrics.c` (315 lines) + `src/metrics.h` (365 lines) — runtime
performance counters using `AtomicU64` for lock-free increment operations.

#### Metric Identifiers

```rust
/// Metric counter identifiers. In Rust, stored using AtomicU64 for safe concurrent access.
pub enum MetricType {
    DnsCacheInserted,       // Cache record successfully inserted
    DnsCacheLiveFreed,      // Cache record evicted while still valid (LRU pressure)
    DnsQueriesForwarded,    // Queries forwarded to upstream servers (cache miss)
    DnsAuthAnswered,        // Queries answered from authoritative zones
    DnsLocalAnswered,       // Queries answered from /etc/hosts or static config
    DnsStaleAnswered,       // Queries answered with stale cache entries (beyond TTL)
    DnsUnansweredQuery,     // Queries that could not be answered
    CryptoHwm,             // DNSSEC crypto operations high-water mark
    SigFailHwm,            // DNSSEC signature failure high-water mark
    WorkHwm,               // DNSSEC validation work high-water mark
    Bootp,                 // Legacy BOOTP requests processed
    Pxe,                   // PXE boot requests processed
    DhcpAck,               // DHCPv4 ACK messages sent
    DhcpDecline,           // DHCPv4 DECLINE messages received
    DhcpDiscover,          // DHCPv4 DISCOVER messages received
    DhcpInform,            // DHCPv4 INFORM messages received
    DhcpNak,               // DHCPv4 NAK messages sent
    DhcpOffer,             // DHCPv4 OFFER messages sent
    DhcpRelease,           // DHCPv4 RELEASE messages received
    DhcpRequest,           // DHCPv4 REQUEST messages received
    NoAnswer,              // Queries with no answer available
    LeasesAllocated4,      // DHCPv4 leases allocated from dynamic pools
    LeasesPruned4,         // DHCPv4 leases expired and pruned
    LeasesAllocated6,      // DHCPv6 leases allocated
    LeasesPruned6,         // DHCPv6 leases expired and pruned
    TcpConnections,        // TCP connections for DNS-over-TCP
    DhcpLeaseQuery,        // DHCPv4 LEASEQUERY requests (RFC 4388)
    DhcpLeaseUnassigned,   // LEASEQUERY: IP not in pool
    DhcpLeaseActive,       // LEASEQUERY: active lease returned
    DhcpLeaseUnknown,      // LEASEQUERY: no matching lease found
}
```

#### Public Types

```rust
/// Runtime metrics store backed by AtomicU64 counters.
pub struct MetricsStore { /* ... */ }

impl MetricsStore {
    /// Create a new metrics store with all counters at zero.
    pub fn new() -> Self;
    /// Increment a metric counter by one.
    pub fn increment(&self, metric: MetricType);
    /// Set a metric to the maximum of its current value and the given value.
    pub fn set_max(&self, metric: MetricType, value: u64);
    /// Read the current value of a metric counter.
    pub fn get(&self, metric: MetricType) -> u64;
    /// Retrieve the human-readable name for a metric identifier.
    pub fn get_name(metric: MetricType) -> &'static str;
    /// Reset all metric counters to zero.
    pub fn clear(&self);
    /// Iterate over all metrics (identifier, value) pairs.
    pub fn iter(&self) -> impl Iterator<Item = (MetricType, u64)>;
}

/// Per-server query statistics.
pub struct ServerStats { /* ... */ }
```

---

## 9. Error Types

The Rust implementation replaces C errno-checking and `goto` cleanup patterns with a
unified error type hierarchy using `Result<T, DnsmasqError>` and the `?` operator.

### `DnsmasqError` Enum

```rust
/// Central error type for all dnsmasq operations.
/// Derived using thiserror for ergonomic error handling.
/// Defined in `core/types.rs`.
#[derive(Debug, thiserror::Error)]
pub enum DnsmasqError {
    /// Configuration file parse error.
    #[error("configuration error: {0}")]
    Config(String),

    /// Network-level error (socket bind failure, send/receive error, etc.).
    #[error("network error: {0}")]
    Network(String),

    /// Standard I/O error (file operations, pipe I/O, etc.).
    /// Automatically converted from `std::io::Error` via `#[from]`.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// DNS protocol error (malformed packet, invalid name, compression error, etc.).
    #[error("DNS protocol error: {0}")]
    DnsProtocol(String),

    /// DHCP protocol error (invalid option, state machine violation, etc.).
    #[error("DHCP error: {0}")]
    Dhcp(String),

    /// Privilege/permission error (failed to drop privileges, bind to port <1024, etc.).
    #[error("privilege error: {0}")]
    Privilege(String),

    /// DNSSEC validation failure (bad signature, missing key, chain broken, etc.).
    #[error("DNSSEC validation failed: {0}")]
    Dnssec(String),

    /// Lease database error (file I/O, corrupt lease, allocation failure, etc.).
    #[error("lease error: {0}")]
    Lease(String),

    /// Miscellaneous error that does not fit other categories.
    #[error("error: {0}")]
    Misc(String),

    /// Fatal error requiring immediate daemon termination.
    #[error("fatal error (code {code}): {message}")]
    Fatal {
        /// Exit code to return to the operating system.
        code: i32,
        /// Human-readable description of the fatal condition.
        message: String,
    },
}
```

### Error Handling Pattern

The C `goto` cleanup pattern:

```c
/* C pattern (src/forward.c, src/rfc2131.c, etc.) */
if (func() == -1) {
    goto cleanup;
}
/* ... */
cleanup:
    free(buffer);
    close(fd);
    return -1;
```

Is replaced by Rust's `?` operator with RAII:

```rust
// Rust equivalent — no goto, no manual cleanup
fn process() -> Result<(), DnsmasqError> {
    let buffer = Vec::new();  // Automatically freed on drop
    let fd = open_socket()?;  // Propagates error, fd closed on drop
    func()?;                  // Propagates error; buffer and fd cleaned up automatically
    Ok(())
}
```

---

## 10. Trait Definitions

### `ServerSelector` — Upstream Server Selection Strategy

Defined in `dns/forward.rs`. Used to implement pluggable upstream DNS server
selection algorithms.

```rust
/// Strategy trait for selecting upstream DNS servers.
/// Enables pluggable selection algorithms (round-robin, weighted, failover).
/// Used by dns::forward for server selection.
pub trait ServerSelector: Send + Sync {
    /// Select the best upstream server for the given query and domain context.
    fn select_server(
        &self,
        servers: &[Arc<UpstreamServer>],
        query: &DnsPacket,
        domain_matcher: &DomainMatcher,
    ) -> Option<Arc<UpstreamServer>>;
}
```

#### Built-in Implementations

```rust
/// Round-robin server selector — cycles through available upstream servers.
pub struct RoundRobinSelector { /* ... */ }

impl ServerSelector for RoundRobinSelector { /* ... */ }
```

### `InotifyCallbacks` — File Change Event Callback

Defined in `diagnostics/inotify.rs`. Used by the inotify watcher to notify
the daemon of file changes.

```rust
/// Callback trait for inotify file change events.
pub trait InotifyCallbacks {
    /// Called when a watched file is modified.
    fn on_file_changed(&mut self, path: &str);
}
```

### `ArpEnumerator` — ARP Cache Iteration Callback

Defined in `network/arp.rs`. Used for platform-specific ARP table enumeration.

```rust
/// Callback trait for ARP cache enumeration.
pub trait ArpEnumerator {
    /// Called for each ARP entry discovered.
    fn on_arp_entry(&mut self, addr: &std::net::IpAddr, mac: &[u8; 6], iface: &str);
}
```

---

## 11. Cross-References

| Document | Purpose |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Module hierarchy, dependency graph, design patterns |
| [MIGRATION.md](MIGRATION.md) | C→Rust pattern mapping, file-by-file transformation guide |
| [SAFETY.md](SAFETY.md) | Unsafe block inventory and safety justifications |
| [README.md](README.md) | Build instructions, feature flags, deployment guide |

### Auto-Generated Documentation

For complete, type-level API documentation with cross-linked source code:

```bash
cd rust/
cargo doc --all-features --open
```

This generates full Rustdoc from the `///` doc comments embedded in every Rust source
file, providing navigable API documentation with type signatures, trait implementations,
and cross-references.

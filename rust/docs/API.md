# Internal API Reference

> **dnsmasq v2.92 — Memory-Safe Rust Implementation**

This document provides comprehensive internal API documentation for the dnsmasq Rust
implementation. It covers the public Rust API surface of every module, with function
signatures, type definitions, and purpose descriptions derived from the original C source
code inline comments across all 50 source files (44 `.c` + 6 `.h`).

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
pub struct Daemon { /* ... */ }
```

#### Public Functions

```rust
/// Main async entry point — initialises all subsystems, binds sockets, drops
/// privileges, and enters the tokio::select! event loop.
/// Replaces C main() in src/dnsmasq.c.
pub async fn run(config: DaemonConfig) -> Result<(), DnsmasqError>;

/// Process a queued asynchronous event (signal, child exit, timer).
/// Replaces C async_event() from src/dnsmasq.c.
pub async fn async_event(state: &mut DaemonState, event: Event) -> Result<(), DnsmasqError>;

/// Flush the DNS cache and reload configuration files (/etc/hosts, /etc/resolv.conf).
/// Triggered by SIGHUP. Replaces C clear_cache_and_reload().
pub fn clear_cache_and_reload(state: &mut DaemonState, now: Instant) -> Result<(), DnsmasqError>;

/// Queue an event for processing in the next event loop iteration.
/// Replaces C queue_event() from src/dnsmasq.c.
pub fn queue_event(event: Event);

/// Send a time-based alarm event. Schedules a timer for the given instant.
/// Replaces C send_alarm() from src/dnsmasq.c.
pub fn send_alarm(event_time: Instant, now: Instant);

/// Send an event with associated data and optional message.
/// Replaces C send_event() from src/dnsmasq.c.
pub fn send_event(fd: RawFd, event: i32, data: i32, msg: Option<&str>);

/// Check DNS listener sockets for incoming queries and dispatch processing.
/// Replaces C check_dns_listeners() from src/dnsmasq.c.
pub async fn check_dns_listeners(state: &mut DaemonState, now: Instant) -> Result<(), DnsmasqError>;

/// Register DNS listener file descriptors with the async I/O reactor.
/// Replaces C set_dns_listeners() from src/dnsmasq.c.
pub fn set_dns_listeners(state: &DaemonState);

/// Create an ICMP socket for DHCP ping-before-offer functionality.
/// Replaces C make_icmp_sock() from src/dnsmasq.c.
#[cfg(feature = "dhcp")]
pub fn make_icmp_sock() -> Result<RawFd, DnsmasqError>;

/// Perform an ICMP ping to check address availability before DHCP offer.
/// Replaces C icmp_ping() from src/dnsmasq.c.
#[cfg(feature = "dhcp")]
pub fn icmp_ping(addr: Ipv4Addr) -> Result<bool, DnsmasqError>;
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
    pub servers: Vec<ServerStruct>,
    pub metrics: MetricsCounters,
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
pub struct ServerStruct {
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
pub struct Irec {
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
/// Reset the poll state, clearing all registered file descriptors.
/// Replaces C poll_reset() from src/poll.c.
pub fn poll_reset();

/// Check whether a file descriptor has a pending event of the given type.
/// Replaces C poll_check() from src/poll.c.
pub fn poll_check(fd: RawFd, event: PollEvent) -> bool;

/// Register a file descriptor for monitoring with the specified event type.
/// Replaces C poll_listen() from src/poll.c.
pub fn poll_listen(fd: RawFd, event: PollEvent);

/// Execute the poll wait, blocking until at least one event fires or timeout expires.
/// In the Rust implementation, this is replaced by tokio::select! in the main event loop.
/// Replaces C do_poll() from src/poll.c.
pub fn do_poll(timeout_ms: i32) -> Result<i32, DnsmasqError>;
```

---

### 1.4 `core::log`

**Source:** `src/log.c` (1,120 lines) — syslog integration, connection-based logging,
async-safe logging subsystem.

#### Public Functions

```rust
/// Terminate the daemon with a fatal error message and exit code.
/// Replaces C die() from src/log.c.
pub fn die(message: &str, arg: Option<&str>, exit_code: i32) -> !;

/// Initialise the logging subsystem, opening the syslog connection.
/// Returns Ok on success. Replaces C log_start() from src/log.c.
pub fn log_start(ent_pw: Option<&Passwd>, errfd: RawFd) -> Result<i32, DnsmasqError>;

/// Reopen the log file (for log rotation). Returns Ok on success.
/// Replaces C log_reopen() from src/log.c.
pub fn log_reopen(log_file: &str) -> Result<i32, DnsmasqError>;

/// Log a message via syslog with the given priority level.
/// Supports MS_TFTP, MS_DHCP, MS_SCRIPT, MS_DEBUG facility flags.
/// Replaces C my_syslog() from src/log.c.
pub fn my_syslog(priority: i32, message: &str);

/// Register the log writer file descriptor with the I/O reactor.
/// Replaces C set_log_writer() from src/log.c.
pub fn set_log_writer();

/// Check and flush pending log messages. If `force` is true, flush unconditionally.
/// Replaces C check_log_writer() from src/log.c.
pub fn check_log_writer(force: bool);

/// Flush all pending log messages to the output destination.
/// Replaces C flush_log() from src/log.c.
pub fn flush_log();
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

/// Case-insensitive domain name equality comparison (RFC 1035 §2.3.3).
/// Replaces C hostname_isequal() from src/util.c.
pub fn hostname_isequal(a: &str, b: &str) -> bool;

/// Validate that a hostname conforms to RFC 952/1123 rules.
/// Replaces C legal_hostname() from src/util.c.
pub fn legal_hostname(name: &str) -> bool;

/// Format a duration in seconds into a human-readable string (e.g., "2h30m").
/// Replaces C prettyprint_time() from src/util.c.
pub fn prettyprint_time(seconds: u64) -> String;

/// Parse a hexadecimal string into a byte vector.
/// Replaces C parse_hex() from src/util.c.
pub fn parse_hex(hex: &str) -> Result<Vec<u8>, DnsmasqError>;

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
/// Match a string against a wildcard pattern (supports `*` and `?` globs).
/// Replaces C wildcard_match() from src/pattern.c.
pub fn wildcard_match(wildcard: &str, candidate: &str) -> bool;

/// Match with a maximum character count limit.
/// Replaces C wildcard_matchn() from src/pattern.c.
pub fn wildcard_matchn(wildcard: &str, candidate: &str, max_chars: usize) -> bool;

/// Check whether a hostname is a subdomain of a given domain.
/// Replaces C hostname_issubdomain() from src/pattern.c.
pub fn hostname_issubdomain(name: &str, domain: &str) -> bool;

/// Validate whether a value is a well-formed DNS name.
/// Replaces C is_valid_dns_name() from src/pattern.c.
#[cfg(feature = "conntrack")]
pub fn is_valid_dns_name(value: &str) -> bool;

/// Validate whether a value is a valid DNS name pattern (with wildcards).
/// Replaces C is_valid_dns_name_pattern() from src/pattern.c.
#[cfg(feature = "conntrack")]
pub fn is_valid_dns_name_pattern(value: &str) -> bool;

/// Check whether a DNS name matches a pattern (including wildcards).
/// Replaces C is_dns_name_matching_pattern() from src/pattern.c.
#[cfg(feature = "conntrack")]
pub fn is_dns_name_matching_pattern(name: &str, pattern: &str) -> bool;
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

Platform-specific features are auto-detected via `#[cfg(target_os = "...")]`:
- `#[cfg(target_os = "linux")]` replaces `HAVE_LINUX_NETWORK`
- `#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "macos"))]` replaces `HAVE_BSD_NETWORK`

---

### 2.3 `config::options`

**Source:** `src/option.c` (8,128 lines) — configuration file parser and 350+ directive
processor.

#### Public Functions

```rust
/// Parse configuration from command-line arguments and config files.
/// Processes /etc/dnsmasq.conf (or --conf-file path) and all --conf-dir includes.
/// Replaces C read_opts() from src/option.c.
pub fn read_opts(args: &[String], compile_opts: &str) -> Result<DaemonConfig, DnsmasqError>;

/// Process a single configuration directive (name=value pair).
/// Handles all 350+ dnsmasq.conf directives via pattern matching.
/// Replaces C one_opt() from src/option.c.
pub fn one_opt(option: u32, arg: &str, config: &mut DaemonConfig) -> Result<(), DnsmasqError>;

/// Parse a DHCP option directive (--dhcp-option).
/// Handles vendor classes, option numbers, and typed value encoding.
/// Replaces C parse_dhcp_opt() from src/option.c.
#[cfg(feature = "dhcp")]
pub fn parse_dhcp_opt(arg: &str, config: &mut DaemonConfig) -> Result<(), DnsmasqError>;

/// Render a DHCP option value as a human-readable string.
/// Replaces C option_string() from src/option.c.
pub fn option_string(protocol: i32, opt: u32, val: &[u8], buf: &mut String) -> Result<(), DnsmasqError>;

/// Reread DHCP configuration (hosts file, ethers file).
/// Replaces C reread_dhcp() from src/option.c.
#[cfg(feature = "dhcp")]
pub fn reread_dhcp();

/// Reload the upstream servers configuration file.
/// Replaces C read_servers_file() from src/option.c.
pub fn read_servers_file();

/// Parse a server= directive argument into server details.
/// Replaces C parse_server() from src/option.c.
pub fn parse_server(arg: &str, details: &mut ServerDetails) -> Result<(), DnsmasqError>;
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
/// Receive and dispatch an incoming DNS query from a client.
/// Initiates cache lookup and, on cache miss, forwards to upstream servers.
/// Replaces C receive_query() from src/forward.c.
pub async fn receive_query(listener: &Listener, state: &mut DaemonState, now: Instant) -> Result<(), DnsmasqError>;

/// Forward a DNS query to the selected upstream server(s).
/// Handles server selection, retry logic, and source port randomisation.
/// Replaces C forward_query() from src/forward.c.
pub async fn forward_query(state: &mut DaemonState, header: &DnsHeader, plen: usize, now: Instant) -> Result<(), DnsmasqError>;

/// Process a reply from an upstream DNS server and deliver to the waiting client.
/// Replaces C reply_query() from src/forward.c.
pub async fn reply_query(fd: RawFd, state: &mut DaemonState, now: Instant) -> Result<(), DnsmasqError>;

/// Return a processed reply to the originating client.
/// Replaces C return_reply() from src/forward.c.
pub fn return_reply(now: Instant, forward: &mut ForwardRecord, header: &DnsHeader, n: usize, status: i32);

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
) -> Result<(), DnsmasqError>;

/// Allocate a new forward record for tracking an outstanding DNS query.
/// Replaces C get_new_frec() from src/forward.c.
pub fn get_new_frec(now: Instant) -> Result<&mut ForwardRecord, DnsmasqError>;

/// Find an existing forward record by query ID and sender address.
/// Replaces C lookup_frec() from src/forward.c.
pub fn lookup_frec(id: u16, source: &MySockAddr) -> Option<&mut ForwardRecord>;

/// Release a forward record back to the free pool.
/// Replaces C free_frec() from src/forward.c.
pub fn free_frec(forward: &mut ForwardRecord);

/// Handle a TCP DNS request on an accepted connection.
/// Replaces C tcp_request() from src/forward.c.
pub async fn tcp_request(
    conn_fd: RawFd, now: Instant,
    local_addr: &MySockAddr, netmask: Ipv4Addr, auth_dns: bool,
) -> Result<(), DnsmasqError>;

/// Clean up state when an upstream server is removed from configuration.
/// Replaces C server_gone() from src/forward.c.
pub fn server_gone(server: &ServerStruct);

/// Allocate a random file descriptor for upstream query source port.
/// Replaces C allocate_rfd() from src/forward.c.
pub fn allocate_rfd(server: &ServerStruct) -> Result<RawFd, DnsmasqError>;

/// Resend all pending queries (after upstream server list change).
/// Replaces C resend_query() from src/forward.c.
pub fn resend_query();

/// Initiate DNSSEC TCP key recursion for validation chain.
/// Replaces C tcp_key_recurse() / swap_to_tcp() from src/forward.c.
#[cfg(feature = "dnssec")]
pub async fn tcp_key_recurse(
    state: &mut DaemonState, now: Instant, status: i32,
    header: &mut DnsHeader, name: &str, server: &ServerStruct,
) -> Result<(), DnsmasqError>;
```

---

### 3.2 `dns::cache`

**Source:** `src/cache.c` (4,119 lines) — DNS cache using hash table with TTL-based
expiry and LRU eviction. Rust implementation replaces the manual hash table with
`HashMap`/`BTreeMap` collections.

#### Public Types

```rust
/// DNS cache record. Replaces C `struct crec` from src/dnsmasq.h.
pub struct CacheRecord {
    pub addr: AllAddr,
    pub ttd: Instant,        // Time-to-die (expiry)
    pub uid: u32,            // Source identifier (SRC_CONFIG, SRC_HOSTS, SRC_AH)
    pub flags: u32,          // Cache flags (F_IMMORTAL, F_IPV4, F_IPV6, F_CNAME, ...)
    pub name: CacheName,     // Domain name (small inline or heap-allocated)
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
pub fn cache_find_by_name(cache: &DnsCache, name: &str, now: Instant, flags: u32) -> Option<&CacheRecord>;

/// Look up a cache record by address (for reverse DNS / PTR queries).
/// Replaces C cache_find_by_addr() from src/cache.c.
pub fn cache_find_by_addr(cache: &DnsCache, addr: &AllAddr, now: Instant, flags: u32) -> Option<&CacheRecord>;

/// Begin an insert transaction (for batching multiple record insertions).
/// Replaces C cache_start_insert() from src/cache.c.
pub fn cache_start_insert(cache: &mut DnsCache);

/// Insert a record into the cache. Must be called between start_insert/end_insert.
/// Replaces C cache_insert() from src/cache.c.
pub fn cache_insert(cache: &mut DnsCache, name: &str, addr: &AllAddr, class: u16, now: Instant, ttl: u64, flags: u32) -> Option<&mut CacheRecord>;

/// Commit the current insert transaction.
/// Replaces C cache_end_insert() from src/cache.c.
pub fn cache_end_insert(cache: &mut DnsCache);

/// Prune expired entries and rebuild the hash table if load factor exceeded.
/// Replaces C cache_scan_free() / rehash() from src/cache.c.
pub fn rehash(cache: &mut DnsCache, size: usize);

/// Generate a new unique identifier for cache records.
/// Replaces C next_uid() from src/cache.c.
pub fn next_uid() -> u32;

/// Return the string name for a DNS resource record type code.
/// Replaces C rrtype() from src/cache.c.
pub fn rrtype(rr_type: u16) -> &'static str;
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
/// DNS message header (12 bytes, wire format per RFC 1035 §4.1.1).
/// Replaces C `struct dns_header` from src/dns-protocol.h.
pub struct DnsHeader {
    pub id: u16,
    pub flags: DnsFlags,
    pub qdcount: u16,   // Question count
    pub ancount: u16,   // Answer count
    pub nscount: u16,   // Authority count
    pub arcount: u16,   // Additional count
}
```

#### Public Functions

```rust
/// Extract a domain name from a DNS packet at the given offset, handling
/// name compression pointers (RFC 1035 §4.1.4).
/// Replaces C extract_name() from src/rfc1035.c.
pub fn extract_name(header: &DnsHeader, packet: &[u8], offset: &mut usize) -> Result<String, DnsmasqError>;

/// Skip over a compressed domain name in a DNS packet.
/// Replaces C skip_name() from src/rfc1035.c.
pub fn skip_name(packet: &[u8], offset: &mut usize) -> Result<(), DnsmasqError>;

/// Skip the question section of a DNS message.
/// Replaces C skip_questions() from src/rfc1035.c.
pub fn skip_questions(header: &DnsHeader, packet: &[u8], offset: &mut usize) -> Result<(), DnsmasqError>;

/// Skip a resource record section (answer, authority, or additional).
/// Replaces C skip_section() from src/rfc1035.c.
pub fn skip_section(packet: &[u8], offset: &mut usize, count: u16) -> Result<(), DnsmasqError>;

/// Resize a DNS packet buffer, adjusting internal pointers.
/// Replaces C resize_packet() from src/rfc1035.c.
pub fn resize_packet(header: &mut DnsHeader, packet: &mut Vec<u8>, new_size: usize);

/// Parse an in-addr.arpa or ip6.arpa name into an IP address (reverse DNS).
/// Replaces C in_arpa_name_2_addr() from src/rfc1035.c.
pub fn in_arpa_name_2_addr(name: &str) -> Result<AllAddr, DnsmasqError>;

/// Apply DNS doctor rules to rewrite addresses in responses.
/// Replaces C do_doctor() from src/rfc1035.c.
pub fn do_doctor(header: &mut DnsHeader, packet: &mut [u8], now: Instant) -> bool;

/// Find the SOA record for a name in the DNS packet.
/// Replaces C find_soa() from src/rfc1035.c.
pub fn find_soa(header: &DnsHeader, packet: &[u8]) -> Option<SoaData>;

/// Check whether an IPv4 address is in a private (RFC 1918) range.
/// Replaces C private_net() from src/rfc1035.c.
pub fn private_net(addr: Ipv4Addr, ban_localhost: bool) -> bool;

/// Check whether an IPv6 address is in a private/link-local range.
/// Replaces C private_net6() from src/rfc1035.c.
pub fn private_net6(addr: &Ipv6Addr) -> bool;
```

---

### 3.4 `dns::dnssec`

**Source:** `src/dnssec.c` (4,009 lines) — DNSSEC validation engine implementing chain
of trust verification, signature validation, and denial-of-existence proofs.

**Feature gate:** `#[cfg(feature = "dnssec")]`

#### Public Functions

```rust
/// Validate a DNS reply for DNSSEC authenticity.
/// Walks the chain of trust from the response back to a configured trust anchor.
/// Replaces C dnssec_validate_reply() from src/dnssec.c.
#[cfg(feature = "dnssec")]
pub fn dnssec_validate_reply(
    header: &DnsHeader, packet: &[u8], name: &str, keyname: &str,
    class: u16, now: Instant,
) -> Result<DnssecStatus, DnsmasqError>;

/// Validate an individual resource record set (RRset) against its RRSIG signature.
/// Replaces C validate_rrset() from src/dnssec.c.
#[cfg(feature = "dnssec")]
pub fn validate_rrset(
    now: Instant, header: &DnsHeader, packet: &[u8],
    class: u16, rrtype: u16, name: &str,
) -> Result<DnssecStatus, DnsmasqError>;

/// Prove non-existence of a domain name or RR type using NSEC/NSEC3 records.
/// Replaces C prove_non_existence() from src/dnssec.c.
#[cfg(feature = "dnssec")]
pub fn prove_non_existence(
    header: &DnsHeader, packet: &[u8], name: &str, qtype: u16,
) -> Result<DnssecStatus, DnsmasqError>;
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
/// Verify an RSA signature against a DNSKEY public key.
/// Replaces C dnsmasq_rsa_verify() from src/crypto.c.
#[cfg(feature = "dnssec")]
pub fn rsa_verify(key: &[u8], sig: &[u8], digest: &[u8], algo: u8) -> Result<bool, DnsmasqError>;

/// Verify an ECDSA (P-256 or P-384) signature.
/// Replaces C dnsmasq_ecdsa_verify() from src/crypto.c.
#[cfg(feature = "dnssec")]
pub fn ecdsa_verify(key: &[u8], sig: &[u8], digest: &[u8], algo: u8) -> Result<bool, DnsmasqError>;

/// Verify an EdDSA (Ed25519 or Ed448) signature.
/// Replaces C dnsmasq_eddsa_verify() from src/crypto.c.
#[cfg(feature = "dnssec")]
pub fn eddsa_verify(key: &[u8], sig: &[u8], digest: &[u8], algo: u8) -> Result<bool, DnsmasqError>;
```

---

### 3.6 `dns::edns`

**Source:** `src/edns0.c` (1,340 lines) — EDNS0 (Extension Mechanisms for DNS, RFC 6891)
option processing, including client subnet and DNS cookie support.

#### Public Functions

```rust
/// Locate the EDNS0 OPT pseudo-header in a DNS packet.
/// Replaces C find_pseudoheader() from src/edns0.c.
pub fn find_pseudoheader(header: &DnsHeader, packet: &[u8]) -> Option<EdnsInfo>;

/// Add or replace an EDNS0 OPT pseudo-header in a DNS packet.
/// Replaces C add_pseudoheader() from src/edns0.c.
pub fn add_pseudoheader(
    header: &mut DnsHeader, packet: &mut Vec<u8>,
    optno: u16, opt_data: &[u8], set_do: bool, replace: bool,
) -> usize;

/// Set the DNSSEC OK (DO) bit in the EDNS0 OPT record.
/// Replaces C add_do_bit() from src/edns0.c.
pub fn add_do_bit(header: &mut DnsHeader, packet: &mut Vec<u8>) -> usize;

/// Add EDNS0 client subnet and other configured options to a query.
/// Replaces C add_edns0_config() from src/edns0.c.
pub fn add_edns0_config(
    header: &mut DnsHeader, packet: &mut Vec<u8>,
    source: &MySockAddr, now: Instant,
) -> (usize, bool);

/// Check whether the source address in an EDNS0 client subnet option matches.
/// Replaces C check_source() from src/edns0.c.
pub fn check_source(header: &DnsHeader, packet: &[u8], pseudoheader: &[u8], peer: &MySockAddr) -> bool;
```

---

### 3.7 `dns::rrfilter`

**Source:** `src/rrfilter.c` (918 lines) — DNS resource record type filtering for
response manipulation.

#### Public Functions

```rust
/// Filter resource records from a DNS response based on mode.
/// Modes: RRFILTER_EDNS0 (0), RRFILTER_DNSSEC (1), RRFILTER_CONF (2).
/// Replaces C rrfilter() from src/rrfilter.c.
pub fn rrfilter(header: &mut DnsHeader, packet: &mut Vec<u8>, mode: i32) -> usize;

/// Get the descriptor for a specific RR type (for filtering decisions).
/// Replaces C rrfilter_desc() from src/rrfilter.c.
pub fn rrfilter_desc(rr_type: u16) -> Option<Vec<i16>>;

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
/// Answer a DNS query from a locally configured authoritative zone.
/// Generates SOA, NS, A, AAAA, and other records from zone configuration.
/// Replaces C answer_auth() from src/auth.c.
#[cfg(feature = "auth")]
pub fn answer_auth(
    header: &mut DnsHeader, packet: &mut Vec<u8>,
    now: Instant, peer: &MySockAddr, local: bool,
) -> Result<usize, DnsmasqError>;
```

---

### 3.9 `dns::domain_match`

**Source:** `src/domain-match.c` (1,591 lines) — domain matching algorithms for upstream
server selection and local answer generation.

#### Public Functions

```rust
/// Build the sorted server array for efficient domain-based lookup.
/// Replaces C build_server_array() from src/domain-match.c.
pub fn build_server_array(state: &mut DaemonState);

/// Look up which upstream servers should handle a query for the given domain.
/// Returns index range into the server array.
/// Replaces C lookup_domain() from src/domain-match.c.
pub fn lookup_domain(domain: &str, flags: i32) -> Option<(usize, usize)>;

/// Filter the server list based on flags and domain match.
/// Replaces C filter_servers() from src/domain-match.c.
pub fn filter_servers(seed: usize, flags: i32) -> Option<(usize, usize)>;

/// Check if a query can be answered locally (from /etc/hosts, config, etc.).
/// Replaces C is_local_answer() from src/domain-match.c.
pub fn is_local_answer(now: Instant, first: i32, name: &str) -> bool;

/// Generate a local answer response packet.
/// Replaces C make_local_answer() from src/domain-match.c.
pub fn make_local_answer(
    flags: i32, got_name: bool, header: &mut DnsHeader,
    name: &str, first: i32, last: i32, ede: i32,
) -> usize;

/// Check if two servers belong to the same group (for round-robin selection).
/// Replaces C server_samegroup() from src/domain-match.c.
pub fn server_samegroup(a: &ServerStruct, b: &ServerStruct) -> bool;

/// Mark servers with the specified flag.
/// Replaces C mark_servers() from src/domain-match.c.
pub fn mark_servers(flag: i32);

/// Remove servers marked for deletion.
/// Replaces C cleanup_servers() from src/domain-match.c.
pub fn cleanup_servers();

/// Add or update a server entry in the server list.
/// Replaces C add_update_server() from src/domain-match.c.
pub fn add_update_server(
    flags: i32, addr: &MySockAddr, source_addr: &MySockAddr,
    interface: Option<&str>, domain: Option<&str>, local_addr: Option<&AllAddr>,
) -> Result<(), DnsmasqError>;
```

---

### 3.10 `dns::domain`

**Source:** `src/domain.c` (707 lines) — reverse DNS domain synthesis for PTR record
generation from address ranges.

#### Public Functions

```rust
/// Synthesise a reverse DNS domain name from an IP address and configured ranges.
/// Replaces the domain synthesis logic from src/domain.c.
pub fn get_domain(addr: &AllAddr) -> Option<String>;
```

---

### 3.11 `dns::blockdata`

**Source:** `src/blockdata.c` (810 lines) — block-allocated storage for variable-length
DNSSEC record data. In Rust, `Vec<u8>` and `Box<[u8]>` replace the linked-block
allocator.

#### Public Functions

```rust
/// Store variable-length data (DNSSEC keys, signatures) in block storage.
/// In Rust, uses Vec<u8> instead of the C linked-block allocator.
/// Replaces C blockdata_alloc() from src/blockdata.c.
pub fn blockdata_alloc(data: &[u8]) -> Vec<u8>;

/// Retrieve data from block storage into a contiguous buffer.
/// Replaces C blockdata_retrieve() from src/blockdata.c.
pub fn blockdata_retrieve(blocks: &[u8], len: usize) -> Vec<u8>;
```

---

### 3.12 `dns::loop_detect`

**Source:** `src/loop.c` (539 lines) — DNS forwarding loop detection to prevent infinite
query cycles.

**Feature gate:** `#[cfg(feature = "loop-detect")]`

#### Public Functions

```rust
/// Send loop detection probe queries to all configured upstream servers.
/// Replaces C loop_send_probes() from src/loop.c.
#[cfg(feature = "loop-detect")]
pub fn loop_send_probes();

/// Check if an incoming query matches a loop detection probe (indicating a loop).
/// Returns true if a forwarding loop is detected.
/// Replaces C detect_loop() from src/loop.c.
#[cfg(feature = "loop-detect")]
pub fn detect_loop(query: &str, qtype: u16) -> bool;
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
/// Initialise the DHCPv4 server: create raw sockets, set BPF filters.
/// Replaces C dhcp_init() from src/dhcp.c.
#[cfg(feature = "dhcp")]
pub fn dhcp_init() -> Result<(), DnsmasqError>;

/// Process an incoming DHCPv4 packet from the raw socket.
/// Dispatches to the protocol state machine (rfc2131 handler).
/// Replaces C dhcp_packet() from src/dhcp.c.
#[cfg(feature = "dhcp")]
pub async fn dhcp_packet(state: &mut DaemonState, now: Instant, pxe_fd: Option<RawFd>) -> Result<(), DnsmasqError>;

/// Check whether a DHCP context contains available addresses for allocation.
/// Replaces C address_available() from src/dhcp.c.
#[cfg(feature = "dhcp")]
pub fn address_available(context: &DhcpContext, addr: Ipv4Addr, netids: &[DhcpNetId]) -> Option<&DhcpContext>;

/// Allocate an IP address from the DHCP pool.
/// Replaces C address_allocate() from src/dhcp.c.
#[cfg(feature = "dhcp")]
pub fn address_allocate(
    context: &DhcpContext, hwaddr: &[u8], netids: &[DhcpNetId], now: Instant, loopback: bool,
) -> Result<Ipv4Addr, DnsmasqError>;

/// Find a DHCP static configuration by IP address.
/// Replaces C config_find_by_address() from src/dhcp.c.
#[cfg(feature = "dhcp")]
pub fn config_find_by_address(configs: &[DhcpConfig], addr: Ipv4Addr) -> Option<&DhcpConfig>;
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
/// Receive a DHCP packet from a raw or UDP socket with ancillary data.
/// Replaces C recv_dhcp_packet() from src/dhcp-common.c.
#[cfg(feature = "dhcp")]
pub fn recv_dhcp_packet(fd: RawFd) -> Result<(Vec<u8>, MsgHdr), DnsmasqError>;

/// Process tag-if matching rules for DHCP network tags.
/// Replaces C run_tag_if() from src/dhcp-common.c.
#[cfg(feature = "dhcp")]
pub fn run_tag_if(tags: &[DhcpNetId]) -> Vec<DhcpNetId>;

/// Match network tags against a tag pool.
/// Replaces C match_netid() from src/dhcp-common.c.
#[cfg(feature = "dhcp")]
pub fn match_netid(check: &[DhcpNetId], pool: &[DhcpNetId], tag_not_needed: bool) -> bool;

/// Find a DHCP configuration record by client identity (MAC, client-id, hostname).
/// Replaces C find_config() from src/dhcp-common.c.
#[cfg(feature = "dhcp")]
pub fn find_config(
    configs: &[DhcpConfig], context: &DhcpContext,
    clid: Option<&[u8]>, hwaddr: &[u8], hostname: Option<&str>,
    filter: &[DhcpNetId],
) -> Option<&DhcpConfig>;
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
pub fn dhcp6_init() -> Result<(), DnsmasqError>;

/// Process an incoming DHCPv6 packet.
/// Replaces C dhcp6_packet() from src/dhcp6.c.
#[cfg(feature = "dhcp6")]
pub async fn dhcp6_packet(state: &mut DaemonState, now: Instant) -> Result<(), DnsmasqError>;

/// Allocate a DHCPv6 address from the configured context pools.
/// Replaces C address6_allocate() from src/dhcp6.c.
#[cfg(feature = "dhcp6")]
pub fn address6_allocate(
    context: &DhcpContext, clid: &[u8], iaid: u32, serial: i32,
    netids: &[DhcpNetId], plain_range: bool,
) -> Result<Ipv6Addr, DnsmasqError>;

/// Construct DHCP contexts from the current network interface configuration.
/// Replaces C dhcp_construct_contexts() from src/dhcp6.c.
#[cfg(feature = "dhcp6")]
pub fn dhcp_construct_contexts(now: Instant);

/// Generate a DUID (DHCP Unique Identifier) for this server instance.
/// Replaces C make_duid() from src/dhcp6.c.
#[cfg(feature = "dhcp6")]
pub fn make_duid(now: Instant);
```

---

### 4.5 `dhcp::v6::protocol`

**Source:** `src/rfc3315.c` (4,216 lines) + `src/dhcp6-protocol.h` (685 lines) — DHCPv6
protocol state machine implementing SOLICIT → ADVERTISE → REQUEST → REPLY per RFC 3315.

**Feature gate:** `#[cfg(feature = "dhcp6")]`

#### Public Functions

```rust
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

#### Public Functions

```rust
/// Start a new DHCPv6 option in the output packet.
/// Replaces C new_opt6() from src/outpacket.c.
#[cfg(feature = "dhcp6")]
pub fn new_opt6(opt: u16) -> i32;

/// Close an open DHCPv6 option container, writing the final length.
/// Replaces C end_opt6() from src/outpacket.c.
#[cfg(feature = "dhcp6")]
pub fn end_opt6(container: i32);

/// Write raw data into the DHCPv6 output packet.
/// Replaces C put_opt6() from src/outpacket.c.
#[cfg(feature = "dhcp6")]
pub fn put_opt6(data: &[u8]);

/// Write a 32-bit value into the DHCPv6 output packet (network byte order).
/// Replaces C put_opt6_long() from src/outpacket.c.
#[cfg(feature = "dhcp6")]
pub fn put_opt6_long(val: u32);

/// Write a 16-bit value into the DHCPv6 output packet (network byte order).
/// Replaces C put_opt6_short() from src/outpacket.c.
#[cfg(feature = "dhcp6")]
pub fn put_opt6_short(val: u16);

/// Write a single byte into the DHCPv6 output packet.
/// Replaces C put_opt6_char() from src/outpacket.c.
#[cfg(feature = "dhcp6")]
pub fn put_opt6_char(val: u8);

/// Write a null-terminated string into the DHCPv6 output packet.
/// Replaces C put_opt6_string() from src/outpacket.c.
#[cfg(feature = "dhcp6")]
pub fn put_opt6_string(s: &str);

/// Reset the output buffer write counter.
/// Replaces C reset_counter() from src/outpacket.c.
#[cfg(feature = "dhcp6")]
pub fn reset_counter();
```

---

### 4.7 `dhcp::common`

**Source:** `src/dhcp-common.c` (2,337 lines, shared portion) — shared DHCP utilities
used by both DHCPv4 and DHCPv6, including vendor class matching and option display.

**Feature gate:** `#[cfg(feature = "dhcp")]`

#### Public Functions

```rust
/// Initialise shared DHCP data structures.
/// Replaces C dhcp_common_init() from src/dhcp-common.c.
#[cfg(feature = "dhcp")]
pub fn dhcp_common_init();

/// Strip invalid characters from a hostname received from a DHCP client.
/// Replaces C strip_hostname() from src/dhcp-common.c.
#[cfg(feature = "dhcp")]
pub fn strip_hostname(hostname: &str) -> String;

/// Display all configured DHCP options (for debugging/logging).
/// Replaces C display_opts() from src/dhcp-common.c.
#[cfg(feature = "dhcp")]
pub fn display_opts();

/// Look up a DHCP option code by name.
/// Replaces C lookup_dhcp_opt() from src/dhcp-common.c.
#[cfg(feature = "dhcp")]
pub fn lookup_dhcp_opt(protocol: i32, name: &str) -> Option<u32>;

/// Update DHCP static host configurations from external sources.
/// Replaces C dhcp_update_configs() from src/dhcp-common.c.
#[cfg(feature = "dhcp")]
pub fn dhcp_update_configs(configs: &mut Vec<DhcpConfig>);

/// Log DHCP context details for a given address family.
/// Replaces C log_context() from src/dhcp-common.c.
#[cfg(feature = "dhcp")]
pub fn log_context(family: i32, context: &DhcpContext);
```

---

### 4.8 `dhcp::lease`

**Source:** `src/lease.c` (3,364 lines) — DHCP lease management including persistence to
the lease file, lease lookup, allocation, pruning, and DNS update integration.

**Feature gate:** `#[cfg(feature = "dhcp")]`

#### Public Functions

```rust
/// Initialise the lease database, reading persisted leases from the lease file.
/// Replaces C lease_init() from src/lease.c.
#[cfg(feature = "dhcp")]
pub fn lease_init(now: Instant) -> Result<(), DnsmasqError>;

/// Write current lease database state to the lease file.
/// Replaces C lease_update_file() from src/lease.c.
#[cfg(feature = "dhcp")]
pub fn lease_update_file(now: Instant) -> Result<(), DnsmasqError>;

/// Update DNS records based on current lease database state.
/// Replaces C lease_update_dns() from src/lease.c.
#[cfg(feature = "dhcp")]
pub fn lease_update_dns(force: bool);

/// Allocate a new DHCPv4 lease for the given IP address.
/// Replaces C lease4_allocate() from src/lease.c.
#[cfg(feature = "dhcp")]
pub fn lease4_allocate(addr: Ipv4Addr) -> Result<DhcpLease, DnsmasqError>;

/// Allocate a new DHCPv6 lease for the given IPv6 address.
/// Replaces C lease6_allocate() from src/lease.c.
#[cfg(feature = "dhcp6")]
pub fn lease6_allocate(addr: &Ipv6Addr, lease_type: i32) -> Result<DhcpLease, DnsmasqError>;

/// Find a lease by client hardware address or client identifier.
/// Replaces C lease_find_by_client() from src/lease.c.
#[cfg(feature = "dhcp")]
pub fn lease_find_by_client(hwaddr: &[u8], hw_type: i32, clid: Option<&[u8]>) -> Option<&DhcpLease>;

/// Find a lease by IPv4 address.
/// Replaces C lease_find_by_addr() from src/lease.c.
#[cfg(feature = "dhcp")]
pub fn lease_find_by_addr(addr: Ipv4Addr) -> Option<&DhcpLease>;

/// Prune expired leases from the database.
/// Replaces C lease_prune() from src/lease.c.
#[cfg(feature = "dhcp")]
pub fn lease_prune(target: Option<&DhcpLease>, now: Instant);

/// Set the hardware address and client identifier on a lease.
/// Replaces C lease_set_hwaddr() from src/lease.c.
#[cfg(feature = "dhcp")]
pub fn lease_set_hwaddr(lease: &mut DhcpLease, hwaddr: &[u8], clid: Option<&[u8]>, hw_type: i32, now: Instant, force: bool);

/// Set the hostname on a lease (with domain qualification).
/// Replaces C lease_set_hostname() from src/lease.c.
#[cfg(feature = "dhcp")]
pub fn lease_set_hostname(lease: &mut DhcpLease, name: &str, auth: bool, domain: Option<&str>, config_domain: Option<&str>);

/// Set the lease expiry time.
/// Replaces C lease_set_expires() from src/lease.c.
#[cfg(feature = "dhcp")]
pub fn lease_set_expires(lease: &mut DhcpLease, duration: u32, now: Instant);
```

---

### 4.9 `dhcp::radv`

**Source:** `src/radv.c` (2,175 lines) + `src/radv-protocol.h` (869 lines) — IPv6 Router
Advertisement construction and dispatch per RFC 4861.

**Feature gate:** `#[cfg(feature = "dhcp6")]`

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

#### Public Functions

```rust
/// Add SLAAC-derived addresses to a DHCP lease for tracking.
/// Replaces C slaac_add_addrs() from src/slaac.c.
#[cfg(feature = "dhcp6")]
pub fn slaac_add_addrs(lease: &mut DhcpLease, now: Instant, force: bool);

/// Periodic SLAAC maintenance: prune expired SLAAC entries.
/// Returns the next scheduled check time.
/// Replaces C periodic_slaac() from src/slaac.c.
#[cfg(feature = "dhcp6")]
pub fn periodic_slaac(now: Instant, leases: &mut [DhcpLease]) -> Instant;

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
/// Check whether an IPv6 address falls within a given prefix.
/// Replaces C is_same_net6() macro from src/ip6addr.h.
pub fn is_same_net6(addr: &Ipv6Addr, net: &Ipv6Addr, prefix_len: u32) -> bool;

/// Set the host portion of an IPv6 address from a u64 value.
/// Replaces C addr6part() / setaddr6part() macros from src/ip6addr.h.
pub fn set_addr6_part(addr: &mut Ipv6Addr, host: u64);

/// Extract the host portion (lower 64 bits) of an IPv6 address.
/// Replaces C addr6part() macro from src/ip6addr.h.
pub fn addr6_part(addr: &Ipv6Addr) -> u64;
```

---

## 5. Network Module (`crate::network`)

The network module provides platform-abstracted network interface enumeration, socket
binding, and low-level network monitoring.

### 5.1 `network::interface`

**Source:** `src/network.c` (6,331 lines) — interface enumeration, socket creation, bind
operations, and listener management.

#### Public Functions

```rust
/// Enumerate all network interfaces and their addresses.
/// Replaces C enumerate_interfaces() from src/network.c.
pub fn enumerate_interfaces(reset: bool) -> Result<bool, DnsmasqError>;

/// Create wildcard listeners (bind to INADDR_ANY/in6addr_any).
/// Replaces C create_wildcard_listeners() from src/network.c.
pub fn create_wildcard_listeners() -> Result<(), DnsmasqError>;

/// Create per-interface bound listeners for each configured address.
/// Replaces C create_bound_listeners() from src/network.c.
pub fn create_bound_listeners(die_now: bool) -> Result<(), DnsmasqError>;

/// Bind a socket to a local address, optionally to a specific interface.
/// Replaces C local_bind() from src/network.c.
pub fn local_bind(fd: RawFd, addr: &MySockAddr, intname: Option<&str>, ifindex: u32, is_tcp: bool) -> Result<(), DnsmasqError>;

/// Pre-allocate shared file descriptors for server connections.
/// Replaces C pre_allocate_sfds() from src/network.c.
pub fn pre_allocate_sfds();

/// Reload upstream server list from resolv.conf or equivalent.
/// Replaces C reload_servers() from src/network.c.
pub fn reload_servers(fname: &str) -> Result<bool, DnsmasqError>;

/// Validate configured upstream servers, removing unreachable ones.
/// Replaces C check_servers() from src/network.c.
pub fn check_servers(no_loop_call: bool);

/// Check whether an address on a named interface should be used.
/// Replaces C iface_check() from src/network.c.
pub fn iface_check(family: i32, addr: &AllAddr, name: &str) -> (bool, bool);

/// Translate a network interface index to its name.
/// Replaces C indextoname() from src/network.c.
pub fn indextoname(fd: RawFd, index: i32) -> Result<String, DnsmasqError>;

/// Set IPV6_RECVPKTINFO on a socket for destination address retrieval.
/// Replaces C set_ipv6pktinfo() from src/network.c.
pub fn set_ipv6pktinfo(fd: RawFd) -> Result<(), DnsmasqError>;

/// Join DHCPv6 multicast groups on all interfaces.
/// Replaces C join_multicast() from src/network.c.
#[cfg(feature = "dhcp6")]
pub fn join_multicast(die_now: bool);
```

---

### 5.2 `network::netlink`

**Source:** `src/netlink.c` (740 lines) — Linux netlink socket interface for network
address and route change monitoring.

**Platform gate:** `#[cfg(target_os = "linux")]`

#### Public Functions

```rust
/// Initialise the netlink socket for monitoring address/route changes.
/// Replaces C netlink_init() from src/netlink.c.
#[cfg(target_os = "linux")]
pub fn netlink_init() -> Result<(), DnsmasqError>;

/// Process pending netlink multicast messages (address/route changes).
/// Replaces C netlink_multicast() from src/netlink.c.
#[cfg(target_os = "linux")]
pub fn netlink_multicast();
```

---

### 5.3 `network::bpf`

**Source:** `src/bpf.c` (805 lines) — BSD BPF (Berkeley Packet Filter) device access for
raw DHCP packet capture on BSD and macOS systems.

**Platform gate:** `#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "macos"))]`

#### Public Functions

```rust
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

#### Public Functions

```rust
/// Look up a MAC address in the system ARP cache for a given IP address.
/// Returns true if a MAC address was found and written to the output buffer.
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

#### Public Functions

```rust
/// Initialise the D-Bus connection and register the dnsmasq service.
/// Replaces C dbus_init() from src/dbus.c.
#[cfg(feature = "dbus")]
pub fn dbus_init() -> Result<(), DnsmasqError>;

/// Check D-Bus listener for incoming method calls and signals.
/// Replaces C check_dbus_listeners() from src/dbus.c.
#[cfg(feature = "dbus")]
pub fn check_dbus_listeners();

/// Register D-Bus file descriptors with the I/O reactor.
/// Replaces C set_dbus_listeners() from src/dbus.c.
#[cfg(feature = "dbus")]
pub fn set_dbus_listeners();

/// Emit a D-Bus signal when a DHCP lease changes.
/// Replaces C emit_dbus_signal() from src/dbus.c.
#[cfg(all(feature = "dbus", feature = "dhcp"))]
pub fn emit_dbus_signal(action: i32, lease: &DhcpLease, hostname: Option<&str>);
```

---

### 6.2 `integration::ubus`

**Source:** `src/ubus.c` (968 lines) — OpenWrt ubus message bus integration.

**Feature gate:** `#[cfg(feature = "ubus")]`

#### Public Functions

```rust
/// Initialise the ubus connection.
/// Replaces C ubus_init() from src/ubus.c.
#[cfg(feature = "ubus")]
pub fn ubus_init() -> Result<(), DnsmasqError>;

/// Register ubus file descriptors with the I/O reactor.
/// Replaces C set_ubus_listeners() from src/ubus.c.
#[cfg(feature = "ubus")]
pub fn set_ubus_listeners();

/// Check ubus for incoming messages.
/// Replaces C check_ubus_listeners() from src/ubus.c.
#[cfg(feature = "ubus")]
pub fn check_ubus_listeners();

/// Broadcast a ubus event for DHCP lease changes.
/// Replaces C ubus_event_bcast() from src/ubus.c.
#[cfg(feature = "ubus")]
pub fn ubus_event_bcast(event_type: &str, mac: &str, ip: &str, name: &str, interface: &str);
```

---

### 6.3 `integration::helper`

**Source:** `src/helper.c` (1,528 lines) — script execution helper for lease-change
callbacks using `tokio::process::Command`.

**Feature gate:** `#[cfg(feature = "script")]`

#### Public Functions

```rust
/// Create the script helper process and communication pipe.
/// Replaces C create_helper() from src/helper.c.
#[cfg(feature = "script")]
pub fn create_helper(event_fd: RawFd, err_fd: RawFd, uid: u32, gid: u32, max_fd: i64) -> Result<i32, DnsmasqError>;

/// Flush pending script execution data to the helper process.
/// Replaces C helper_write() from src/helper.c.
#[cfg(feature = "script")]
pub fn helper_write();

/// Queue a lease-change script execution.
/// Replaces C queue_script() from src/helper.c.
#[cfg(feature = "script")]
pub fn queue_script(action: i32, lease: &DhcpLease, hostname: Option<&str>, now: Instant);

/// Queue a TFTP event for script notification.
/// Replaces C queue_tftp() from src/helper.c.
#[cfg(all(feature = "script", feature = "tftp"))]
pub fn queue_tftp(file_len: u64, filename: &str, peer: &MySockAddr);

/// Queue an ARP event for script notification.
/// Replaces C queue_arp() from src/helper.c.
#[cfg(feature = "script")]
pub fn queue_arp(action: i32, mac: &[u8], family: i32, addr: &AllAddr);

/// Check if the helper output buffer is empty (all events flushed).
/// Replaces C helper_buf_empty() from src/helper.c.
#[cfg(feature = "script")]
pub fn helper_buf_empty() -> bool;
```

---

### 6.4 `integration::conntrack`

**Source:** `src/conntrack.c` (324 lines) — Linux conntrack mark preservation for
firewall integration.

**Feature gate:** `#[cfg(feature = "conntrack")]`

#### Public Functions

```rust
/// Retrieve the conntrack mark for an incoming connection.
/// Used to preserve firewall marks across DNS forwarding.
/// Replaces C get_incoming_mark() from src/conntrack.c.
#[cfg(feature = "conntrack")]
pub fn get_incoming_mark(peer: &MySockAddr, local: &AllAddr, is_tcp: bool) -> Result<u32, DnsmasqError>;
```

---

### 6.5 `integration::ipset`

**Source:** `src/ipset.c` (532 lines) — Linux ipset integration for adding resolved
addresses to firewall sets.

**Feature gate:** `#[cfg(feature = "ipset")]`

#### Public Functions

```rust
/// Initialise the ipset netlink socket.
/// Replaces C ipset_init() from src/ipset.c.
#[cfg(feature = "ipset")]
pub fn ipset_init() -> Result<(), DnsmasqError>;

/// Add or remove an IP address from a named ipset.
/// Replaces C add_to_ipset() from src/ipset.c.
#[cfg(feature = "ipset")]
pub fn add_to_ipset(setname: &str, addr: &AllAddr, flags: i32, remove: bool) -> Result<(), DnsmasqError>;
```

---

### 6.6 `integration::nftset`

**Source:** `src/nftset.c` (392 lines) — nftables set integration for adding resolved
addresses to nftables firewall sets.

**Feature gate:** `#[cfg(feature = "nftset")]`

#### Public Functions

```rust
/// Initialise the nftables set interface.
/// Replaces C nftset_init() from src/nftset.c.
#[cfg(feature = "nftset")]
pub fn nftset_init() -> Result<(), DnsmasqError>;

/// Add or remove an IP address from a named nftables set.
/// Replaces C add_to_nftset() from src/nftset.c.
#[cfg(feature = "nftset")]
pub fn add_to_nftset(setpath: &str, addr: &AllAddr, flags: i32, remove: bool) -> Result<(), DnsmasqError>;
```

---

### 6.7 `integration::tables`

**Source:** `src/tables.c` (386 lines) — routing table interaction for FreeBSD.

**Platform gate:** `#[cfg(target_os = "freebsd")]`

#### Public Functions

```rust
/// Platform-specific routing table interaction for FreeBSD.
/// Replaces the routing table functions from src/tables.c.
#[cfg(target_os = "freebsd")]
pub fn tables_init() -> Result<(), DnsmasqError>;
```

---

## 7. Services Module (`crate::services`)

### 7.1 `services::tftp`

**Source:** `src/tftp.c` (1,647 lines) — TFTP (Trivial File Transfer Protocol) server
with PXE (Preboot Execution Environment) network boot support.

**Feature gate:** `#[cfg(feature = "tftp")]`

#### Public Functions

```rust
/// Check TFTP listener sockets for incoming requests and handle file transfers.
/// Replaces C check_tftp_listeners() from src/tftp.c.
#[cfg(feature = "tftp")]
pub async fn check_tftp_listeners(state: &mut DaemonState, now: Instant) -> Result<(), DnsmasqError>;

/// Execute pending TFTP event scripts.
/// Replaces C do_tftp_script_run() from src/tftp.c.
#[cfg(feature = "tftp")]
pub fn do_tftp_script_run() -> bool;
```

---

## 8. Diagnostics Module (`crate::diagnostics`)

The diagnostics module provides packet dumping, file change monitoring, and runtime
metrics counters for operational visibility.

### 8.1 `diagnostics::dump`

**Source:** `src/dump.c` (815 lines) — pcap-format packet dump for debugging and
analysis.

**Feature gate:** `#[cfg(feature = "dumpfile")]`

#### Public Functions

```rust
/// Initialise the packet dump file.
/// Replaces C dump_init() from src/dump.c.
#[cfg(feature = "dumpfile")]
pub fn dump_init() -> Result<(), DnsmasqError>;

/// Dump a UDP packet to the pcap file.
/// Replaces C dump_packet_udp() from src/dump.c.
#[cfg(feature = "dumpfile")]
pub fn dump_packet_udp(mask: i32, packet: &[u8], src: &MySockAddr, dst: &MySockAddr, fd: RawFd);

/// Dump an ICMPv6 packet to the pcap file.
/// Replaces C dump_packet_icmp() from src/dump.c.
#[cfg(feature = "dumpfile")]
pub fn dump_packet_icmp(mask: i32, packet: &[u8], src: &MySockAddr, dst: &MySockAddr);
```

---

### 8.2 `diagnostics::inotify`

**Source:** `src/inotify.c` (687 lines) — asynchronous file change monitoring using Linux
inotify for `/etc/hosts` and `/etc/resolv.conf` changes.

**Feature gate:** `#[cfg(feature = "inotify")]`

#### Public Functions

```rust
/// Initialise inotify watches for configuration files.
/// Replaces C inotify_dnsmasq_init() from src/inotify.c.
#[cfg(feature = "inotify")]
pub fn inotify_dnsmasq_init() -> Result<(), DnsmasqError>;

/// Check for inotify events and process file changes.
/// Returns true if files were modified and configuration needs reloading.
/// Replaces C inotify_check() from src/inotify.c.
#[cfg(feature = "inotify")]
pub fn inotify_check(now: Instant) -> Result<bool, DnsmasqError>;

/// Set up dynamic inotify watches for runtime-added hosts directories.
/// Replaces C set_dynamic_inotify() from src/inotify.c.
#[cfg(feature = "inotify")]
pub fn set_dynamic_inotify(flag: i32, total_size: i32);
```

---

### 8.3 `diagnostics::metrics`

**Source:** `src/metrics.c` (315 lines) + `src/metrics.h` (365 lines) — runtime
performance counters using `AtomicU64` for lock-free increment operations.

#### Metric Identifiers

```rust
/// Metric counter identifiers. In Rust, stored using AtomicU64 for safe concurrent access.
pub enum Metric {
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

#### Public Functions

```rust
/// Retrieve the human-readable name for a metric identifier.
/// Replaces C get_metric_name() from src/metrics.c.
pub fn get_metric_name(metric: Metric) -> &'static str;

/// Reset all metric counters to zero.
/// Typically called on daemon startup or SIGHUP configuration reload.
/// Replaces C clear_metrics() from src/metrics.c.
pub fn clear_metrics();
```

---

## 9. Error Types

The Rust implementation replaces C errno-checking and `goto` cleanup patterns with a
unified error type hierarchy using `Result<T, DnsmasqError>` and the `?` operator.

### `DnsmasqError` Enum

```rust
/// Central error type for all dnsmasq operations.
/// Derived using thiserror for ergonomic error handling.
#[derive(Debug, thiserror::Error)]
pub enum DnsmasqError {
    /// Configuration file parse error.
    #[error("configuration error: {0}")]
    Config(String),

    /// Network socket or I/O error.
    #[error("network error: {0}")]
    Network(#[from] std::io::Error),

    /// DNS protocol error (malformed packet, invalid name, etc.).
    #[error("DNS protocol error: {0}")]
    Dns(String),

    /// DHCP protocol error.
    #[error("DHCP error: {0}")]
    Dhcp(String),

    /// DNSSEC validation failure.
    #[error("DNSSEC validation failed: {0}")]
    Dnssec(String),

    /// Platform-specific system call failure.
    #[error("platform error: {0}")]
    Platform(String),

    /// Insufficient permissions for the requested operation.
    #[error("permission denied: {0}")]
    Permission(String),

    /// Resource exhaustion (too many connections, cache full, etc.).
    #[error("resource limit reached: {0}")]
    ResourceLimit(String),
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

```rust
/// Strategy trait for selecting upstream DNS servers.
/// Enables pluggable selection algorithms (round-robin, weighted, failover).
/// Used by dns::forward for server selection.
pub trait ServerSelector {
    /// Select the next upstream server to use for a query.
    fn select(&mut self, servers: &[ServerStruct], domain: &str) -> Option<usize>;

    /// Notify the selector that a server has failed.
    fn report_failure(&mut self, server_index: usize);

    /// Notify the selector that a server has responded successfully.
    fn report_success(&mut self, server_index: usize);
}
```

### `InterfaceEnumerator` — Platform Callback Abstraction

```rust
/// Callback trait for platform-specific network interface enumeration.
/// Replaces C `callback_t` union from src/dnsmasq.h.
pub trait InterfaceEnumerator {
    /// Called for each IPv4 address discovered on an interface.
    fn on_ipv4(&mut self, local: Ipv4Addr, if_index: i32, label: &str, netmask: Ipv4Addr, broadcast: Ipv4Addr);

    /// Called for each IPv6 address discovered on an interface.
    fn on_ipv6(&mut self, local: &Ipv6Addr, prefix: i32, scope: i32, if_index: i32, flags: i32, preferred: u32, valid: u32);

    /// Called for each link-layer interface discovered.
    fn on_link(&mut self, index: i32, hw_type: u32, mac: &[u8]);
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

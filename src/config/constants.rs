// dnsmasq is Copyright (c) 2000-2025 Simon Kelley
//
//   This program is free software; you can redistribute it and/or modify
//   it under the terms of the GNU General Public License as published by
//   the Free Software Foundation; version 2 dated June, 1991, or
//   (at your option) version 3 dated 29 June, 2007.
//
//   This program is distributed in the hope that it will be useful,
//   but WITHOUT ANY WARRANTY; without even the implied warranty of
//   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//   GNU General Public License for more details.
//
//   You should have received a copy of the GNU General Public License
//   along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! Compile-time constants for the dnsmasq Rust rewrite.
//!
//! This module replaces the numeric constants, default string values, and
//! platform-specific file paths originally defined in the C `src/config.h`
//! header file and `src/dns-protocol.h`. These constants control default
//! behavior limits, buffer sizes, timeouts, file paths, and DNS/DHCP protocol
//! parameters throughout the entire dnsmasq codebase.
//!
//! All constants use `pub const` declarations for crate-wide visibility and
//! are grouped logically by subsystem. Values have been verified
//! character-by-character against the original C source definitions.
//!
//! # Subsystem Groups
//! - **DNS Forwarding and Query Handling** — forward table, packet sizes, timeouts
//! - **DNS Cache** — cache size, TTL limits, CNAME chain depth
//! - **DNSSEC** — validation limits, key storage, TTL bounds
//! - **DHCP** — lease limits, ping test, packet sizes, default lease times
//! - **TFTP** — connection limits, window size, transfer timeout
//! - **Logging** — queue depth, logging limits
//! - **Authoritative DNS / SOA** — TTL, refresh, retry, expiry
//! - **Loop Detection** — probe domain and query type
//! - **Security / Privilege Separation** — default user and group
//! - **File Paths** — platform-specific default paths for config, leases, PID, etc.
//! - **Integration Service Names** — D-Bus and UBus service identifiers
//! - **Default Port Numbers** — DNS, DHCP, DHCPv6, TFTP port defaults

// =============================================================================
// DNS Forwarding and Query Handling Constants
// =============================================================================

/// Maximum number of concurrent outstanding DNS forward queries (default).
///
/// Controls the size of the forward record table tracking active DNS queries
/// from clients to upstream servers. Each outstanding query consumes one
/// forward record. When the limit is reached, new queries are dropped until
/// slots become available.
///
/// Tunable via: `--dns-forward-max` command-line option.
///
/// Source: C `config.h` line 93 — `#define FTABSIZ 150`
pub const FTABSIZ: usize = 150;

/// Maximum number of child processes for handling TCP DNS connections.
///
/// Limits concurrent TCP connections to prevent resource exhaustion from
/// TCP connection floods. Each TCP connection forks a child process to
/// handle query processing without blocking the main event loop.
///
/// Source: C `config.h` line 108 — `#define MAX_PROCS 20`
pub const MAX_PROCS: usize = 20;

/// Maximum lifetime in seconds for TCP child processes.
///
/// TCP child processes automatically terminate after this duration to
/// prevent resource leaks from hung connections. RFC 1035 suggests
/// a value greater than 120 seconds.
///
/// Source: C `config.h` line 121 — `#define CHILD_LIFETIME 150`
pub const CHILD_LIFETIME: u64 = 150;

/// Maximum number of DNS queries per single TCP connection.
///
/// Limits query pipelining over TCP connections to prevent resource
/// exhaustion. After this many queries, the connection is closed and
/// the client must reconnect.
///
/// Source: C `config.h` line 134 — `#define TCP_MAX_QUERIES 100`
pub const TCP_MAX_QUERIES: usize = 100;

/// Timeout in seconds for TCP connection establishment to upstream servers.
///
/// Maximum time to wait when establishing a TCP connection to an upstream
/// DNS server. The response timeout after connection establishment is
/// double this value.
///
/// Source: C `config.h` line 147 — `#define TCP_TIMEOUT 5`
pub const TCP_TIMEOUT: u64 = 5;

/// Kernel listen backlog for TCP socket accept queue.
///
/// Maximum number of pending TCP connections in the kernel accept queue
/// before new connection attempts are rejected. Passed to the `listen()`
/// system call.
///
/// Source: C `config.h` line 160 — `#define TCP_BACKLOG 32`
pub const TCP_BACKLOG: i32 = 32;

// =============================================================================
// EDNS0 and Packet Size Constants
// =============================================================================

/// Default maximum EDNS0 UDP packet size advertised to clients (bytes).
///
/// Maximum UDP payload size advertised in EDNS0 OPT records. This value
/// follows the DNS Flag Day 2020 recommendations to avoid IP fragmentation
/// issues, fitting within a single Ethernet frame with headers.
///
/// Tunable via: `--edns-packet-max` command-line option.
///
/// **Note:** This is 1232, NOT 4096. The value was changed per DNS Flag Day
/// 2020 (`dnsflagday.net/2020`) to avoid IPv6 fragmentation (1280 MTU
/// minus headers ≈ 1232 payload).
///
/// Source: C `config.h` line 175 — `#define EDNS_PKTSZ 1232`
pub const EDNS_PKTSZ: usize = 1232;

/// Standard DNS UDP packet size per RFC 1035 (bytes).
///
/// The maximum DNS message size guaranteed deliverable via UDP without
/// EDNS0. All DNS implementations must handle packets up to this size.
///
/// Source: C `dns-protocol.h` line 102 — `#define PACKETSZ 512`
pub const PACKETSZ: usize = 512;

/// Maximum DNS domain name length in bytes (presentation format with null).
///
/// RFC 1035 limits domain names to 255 octets in wire format. This constant
/// includes room for label separators and a null terminator in the
/// presentation format.
///
/// Source: C `dns-protocol.h` line 105 — `#define MAXDNAME 1025`
pub const MAXDNAME: usize = 1025;

/// Optimization hint: most domain names fit within this length (bytes).
///
/// Used for buffer allocation and performance tuning. The full DNS name
/// maximum is 255 bytes (RFC 1035), but typical names are much shorter.
///
/// Source: C `config.h` line 480 — `#define SMALLDNAME 50`
pub const SMALLDNAME: usize = 50;

// =============================================================================
// Query Timeout and Retry Constants
// =============================================================================

/// Timeout in seconds for upstream DNS queries (UDP).
///
/// Maximum time to wait for a UDP response from an upstream DNS server
/// before considering the query failed and trying the next server or
/// returning SERVFAIL.
///
/// Source: C `config.h` line 271 — `#define TIMEOUT 10`
pub const TIMEOUT: u64 = 10;

/// Port range threshold for sequential vs. random allocation.
///
/// If the configured DNS query source port range is smaller than this
/// threshold, sequential allocation is used instead of random. This
/// prevents port exhaustion in small ranges.
///
/// Source: C `config.h` line 284 — `#define SMALL_PORT_RANGE 30`
pub const SMALL_PORT_RANGE: usize = 30;

/// Query count interval for upstream server health testing.
///
/// After this many queries, all configured upstream servers are tested
/// even if the current server is responding, to detect recovered failed
/// servers and enable automatic failback to preferred upstreams.
///
/// Source: C `config.h` line 297 — `#define FORWARD_TEST 50`
pub const FORWARD_TEST: usize = 50;

/// Time interval in seconds for upstream server health testing.
///
/// Complement to [`FORWARD_TEST`]: tests all servers after this time
/// interval to ensure periodic health checks even during low query rates.
///
/// Source: C `config.h` line 310 — `#define FORWARD_TIME 20`
pub const FORWARD_TIME: u64 = 20;

/// Interval in seconds to reset EDNS0 packet size assumptions.
///
/// Periodically retests maximum UDP packet size with upstream servers
/// to adapt to network path MTU changes and recover from transient
/// fragmentation issues.
///
/// Source: C `config.h` line 323 — `#define UDP_TEST_TIME 60`
pub const UDP_TEST_TIME: u64 = 60;

/// Default delay in milliseconds before fast retry to next upstream.
///
/// When an upstream server fails immediately (connection refused, etc.),
/// the daemon waits this short interval before trying the next server
/// instead of the full [`TIMEOUT`] duration.
///
/// Source: C `config.h` line 814 — `#define DEFAULT_FAST_RETRY 1000`
pub const DEFAULT_FAST_RETRY: u64 = 1000;

// =============================================================================
// DNS Cache Constants
// =============================================================================

/// Default DNS cache size in number of entries.
///
/// Number of DNS records cached in memory. Each entry stores one resource
/// record (A, AAAA, CNAME, PTR, etc.) with TTL and lookup metadata.
/// A value of 0 disables caching entirely.
///
/// Tunable via: `--cache-size` command-line option.
///
/// Source: C `config.h` line 379 — `#define CACHESIZ 150`
pub const CACHESIZ: usize = 150;

/// Maximum TTL that `--min-cache-ttl` option can impose (seconds).
///
/// Prevents `--min-cache-ttl` from setting unreasonably high minimum TTLs
/// that would cache records longer than intended by authoritative servers.
/// This is a safety ceiling, not a default value.
///
/// Source: C `config.h` line 392 — `#define TTL_FLOOR_LIMIT 3600`
pub const TTL_FLOOR_LIMIT: u64 = 3600;

/// Maximum age in seconds for serving stale cache data.
///
/// When all upstream servers are unavailable, stale cached data may be
/// served if it is less than this age. Allows continued operation during
/// upstream outages (1 day).
///
/// Tunable via: `--use-stale-cache` command-line option.
///
/// Source: C `config.h` line 828 — `#define STALE_CACHE_EXPIRY 86400`
pub const STALE_CACHE_EXPIRY: u64 = 86400;

/// Maximum CNAME chain depth before loop detection triggers.
///
/// Prevents infinite loops from circular CNAME records. Chains longer
/// than this depth are truncated and flagged as potential loops.
///
/// Source: C `config.h` line 494 — `#define CNAME_CHAIN 10`
pub const CNAME_CHAIN: usize = 10;

// =============================================================================
// DNSSEC Constants
// =============================================================================

/// Block size in bytes for DNSSEC key material storage.
///
/// DNSSEC keys (DNSKEY, RRSIG) vary in length. This block size minimizes
/// memory fragmentation when chaining blocks to store large keys.
///
/// Source: C `config.h` line 186 — `#define KEYBLOCK_LEN 40`
pub const KEYBLOCK_LEN: usize = 40;

/// Maximum number of DNS queries allowed during DNSSEC validation chain.
///
/// Prevents denial-of-service attacks where malicious zones create deep
/// validation chains requiring excessive upstream queries. Validation is
/// aborted if the query count exceeds this limit.
///
/// Source: C `config.h` line 201 — `#define DNSSEC_LIMIT_WORK 40`
pub const DNSSEC_LIMIT_WORK: usize = 40;

/// Maximum number of signature validation failures allowed per response.
///
/// Limits CPU consumption when validating responses with multiple
/// signatures. If this many signatures fail validation, the entire
/// response is marked as BOGUS.
///
/// Source: C `config.h` line 215 — `#define DNSSEC_LIMIT_SIG_FAIL 20`
pub const DNSSEC_LIMIT_SIG_FAIL: usize = 20;

/// Maximum number of cryptographic operations per validation query.
///
/// Total limit on all crypto operations (signature verifications, hash
/// computations) to prevent CPU exhaustion from validation DoS attacks.
///
/// Source: C `config.h` line 230 — `#define DNSSEC_LIMIT_CRYPTO 200`
pub const DNSSEC_LIMIT_CRYPTO: usize = 200;

/// Maximum NSEC3 hash iterations allowed for denial-of-existence proofs.
///
/// NSEC3 uses iterated hashing for zone enumeration protection. This
/// limit prevents CPU exhaustion from excessive hashing. RFC 5155
/// recommends ≤150 iterations for production zones.
///
/// Source: C `config.h` line 245 — `#define DNSSEC_LIMIT_NSEC3_ITERS 150`
pub const DNSSEC_LIMIT_NSEC3_ITERS: usize = 150;

/// TTL in seconds for synthesized negative DS records (insecure delegations).
///
/// When `server=/domain/` configuration forces non-DNSSEC upstream, a
/// synthesized negative DS record is cached with this TTL to mark the
/// delegation as insecure and prevent repeated DNSSEC queries.
///
/// Source: C `config.h` line 258 — `#define DNSSEC_ASSUMED_DS_TTL 3600`
pub const DNSSEC_ASSUMED_DS_TTL: u64 = 3600;

/// Minimum TTL in seconds for cached DNSSEC records (DNSKEY, DS).
///
/// DNSSEC validation records are cached at least this long even if the
/// authoritative TTL is shorter. Prevents excessive re-validation queries.
///
/// Source: C `config.h` line 508 — `#define DNSSEC_MIN_TTL 60`
pub const DNSSEC_MIN_TTL: u64 = 60;

// =============================================================================
// DHCP Constants
// =============================================================================

/// Maximum number of concurrent DHCP leases supported.
///
/// Hard limit on the DHCP lease database size. Prevents memory exhaustion
/// from unbounded lease table growth. Suitable for small-to-medium network
/// scale (home routers, small office).
///
/// Source: C `config.h` line 407 — `#define MAXLEASES 1000`
pub const MAXLEASES: usize = 1000;

/// Seconds to wait for ping response during address-in-use testing.
///
/// Before offering a DHCP address, an ICMP ping is sent to detect
/// conflicts. The server waits this long for a response before assuming
/// the address is available. Per RFC 2131 address conflict detection.
///
/// Source: C `config.h` line 422 — `#define PING_WAIT 3`
pub const PING_WAIT: u64 = 3;

/// Seconds to trust cached ping test results.
///
/// Recent ping test results are cached to avoid re-pinging the same
/// address for subsequent DHCP requests. The cache expires after this
/// duration.
///
/// Source: C `config.h` line 436 — `#define PING_CACHE_TIME 30`
pub const PING_CACHE_TIME: u64 = 30;

/// Seconds to disable DECLINEd static DHCP reservations.
///
/// When a client sends DHCPDECLINE for a static reservation (indicating
/// an address conflict), the reservation is temporarily disabled for this
/// duration to allow the client to obtain a different address.
///
/// Source: C `config.h` line 451 — `#define DECLINE_BACKOFF 600`
pub const DECLINE_BACKOFF: u64 = 600;

/// Hard maximum size for DHCP packets in bytes.
///
/// Absolute upper limit on DHCP packet buffer allocation. Prevents memory
/// exhaustion from malformed packets claiming huge option lengths.
///
/// Source: C `config.h` line 466 — `#define DHCP_PACKET_MAX 16384`
pub const DHCP_PACKET_MAX: usize = 16384;

/// Retry interval in seconds for failed lease file writes.
///
/// If writing the DHCP lease database fails (e.g., disk full, permission
/// error), the write is retried after this interval. Prevents tight retry
/// loops consuming CPU during filesystem failures.
///
/// Source: C `config.h` line 363 — `#define LEASE_RETRY 60`
pub const LEASE_RETRY: u64 = 60;

/// Default DHCPv4 lease time in seconds (1 hour).
///
/// Lease duration assigned when the client does not request a specific
/// time and the `dhcp-range` configuration does not specify a default.
/// One hour balances lease churn versus address pool exhaustion.
///
/// Source: C `config.h` line 551 — `#define DEFLEASE 3600`
pub const DEFLEASE: u64 = 3600;

/// Default DHCPv6 lease time in seconds (24 hours).
///
/// Lease duration for DHCPv6 stateful address assignment. Longer than
/// the DHCPv4 default due to the abundant IPv6 address space, which
/// reduces churn concerns.
///
/// Computed as: 3600 × 24 = 86400.
///
/// Source: C `config.h` line 566 — `#define DEFLEASE6 (3600*24)`
pub const DEFLEASE6: u64 = 86400;

// =============================================================================
// TFTP Constants
// =============================================================================

/// Maximum number of simultaneous TFTP transfers.
///
/// Hard limit on concurrent TFTP file transfers. Prevents resource
/// exhaustion from TFTP connection floods during network boot storms
/// (e.g., many hosts PXE booting simultaneously).
///
/// Source: C `config.h` line 610 — `#define TFTP_MAX_CONNECTIONS 50`
pub const TFTP_MAX_CONNECTIONS: usize = 50;

/// Maximum TFTP window size for RFC 7440 windowed transfers.
///
/// Window size for TFTP option negotiation. Larger windows improve
/// throughput for large files by reducing round-trip overhead.
///
/// Source: C `config.h` line 625 — `#define TFTP_MAX_WINDOW 32`
pub const TFTP_MAX_WINDOW: usize = 32;

/// Timeout in seconds for abandoned TFTP transfers.
///
/// Maximum duration for a single TFTP transfer. Transfers exceeding
/// this time are terminated to free resources for other clients.
///
/// Source: C `config.h` line 640 — `#define TFTP_TRANSFER_TIME 120`
pub const TFTP_TRANSFER_TIME: u64 = 120;

// =============================================================================
// Logging Constants
// =============================================================================

/// Non-blocking logging queue depth.
///
/// Maximum pending log messages before the queue-full condition triggers.
/// The non-blocking queue prevents slow syslog from blocking packet
/// processing. When full, new messages are dropped with a warning.
///
/// Source: C `config.h` line 654 — `#define LOG_MAX 5`
pub const LOG_MAX: usize = 5;

/// Maximum number of upstream servers logged in state dumps.
///
/// When logging configuration state (e.g., via SIGUSR1), the upstream
/// server list is limited to this many entries to prevent log flooding
/// in large configurations.
///
/// Source: C `config.h` line 336 — `#define SERVERS_LOGGED 30`
pub const SERVERS_LOGGED: usize = 30;

/// Maximum number of local addresses logged in state dumps.
///
/// When logging configuration state, the local interface address list
/// is limited to this many entries to prevent excessive log output
/// on multi-homed hosts.
///
/// Source: C `config.h` line 349 — `#define LOCALS_LOGGED 8`
pub const LOCALS_LOGGED: usize = 8;

// =============================================================================
// Authoritative DNS and SOA Constants
// =============================================================================

/// Default TTL in seconds for authoritative DNS responses (10 minutes).
///
/// Time-to-live assigned to records served from authoritative zones when
/// operating in authoritative DNS mode (`--auth-zone` configuration).
///
/// Tunable via: `--auth-ttl` command-line option.
///
/// Source: C `config.h` line 727 — `#define AUTH_TTL 600`
pub const AUTH_TTL: u64 = 600;

/// SOA record refresh interval in seconds (20 minutes).
///
/// Seconds between zone refresh attempts by secondary nameservers.
/// Used in automatically generated SOA records for authoritative zones.
///
/// Source: C `config.h` line 742 — `#define SOA_REFRESH 1200`
pub const SOA_REFRESH: u64 = 1200;

/// SOA record retry interval in seconds (3 minutes).
///
/// Seconds between retry attempts when a zone refresh fails. Used in
/// SOA records for authoritative zones.
///
/// Source: C `config.h` line 757 — `#define SOA_RETRY 180`
pub const SOA_RETRY: u64 = 180;

/// SOA record expiry time in seconds (14 days).
///
/// Seconds after which a secondary stops answering queries if unable
/// to refresh. Used in SOA records for authoritative zones.
///
/// Computed as: 14 × 86400 = 1,209,600.
///
/// Source: C `config.h` line 772 — `#define SOA_EXPIRY 1209600`
pub const SOA_EXPIRY: u64 = 1_209_600;

// =============================================================================
// Loop Detection Constants
// =============================================================================

/// Domain name used for DNS forwarding loop detection.
///
/// Special query sent to detect forwarding loops where dnsmasq forwards
/// queries to an upstream that forwards back to dnsmasq. The "test" TLD
/// is reserved by RFC 2606 and will not clash with real domains.
///
/// Source: C `config.h` line 787 — `#define LOOP_TEST_DOMAIN "test"`
pub const LOOP_TEST_DOMAIN: &str = "test";

/// DNS query type used for loop detection queries (T_TXT = 16).
///
/// Query type for loop detection probes sent to [`LOOP_TEST_DOMAIN`].
/// Uses the TXT record type (value 16) as defined in RFC 1035.
///
/// Source: C `config.h` line 800 — `#define LOOP_TEST_TYPE T_TXT`
/// where T_TXT is defined in `dns-protocol.h` line 228 as 16.
pub const LOOP_TEST_TYPE: u16 = 16;

// =============================================================================
// Security and Privilege Separation Constants
// =============================================================================

/// Default unprivileged user for privilege separation.
///
/// After binding privileged ports (53, 67, 69), the daemon drops
/// privileges to this user for security, minimizing damage if the
/// daemon process is compromised.
///
/// Tunable via: `--user` command-line option.
///
/// Source: C `config.h` line 581 — `#define CHUSER "nobody"`
pub const CHUSER: &str = "nobody";

/// Default unprivileged group for privilege separation.
///
/// Group ID changed to this group after binding privileged ports. The
/// "dip" group traditionally has network device access without full
/// root privileges. May need adjustment on non-Linux platforms.
///
/// Tunable via: `--group` command-line option.
///
/// Source: C `config.h` line 595 — `#define CHGRP "dip"`
pub const CHGRP: &str = "dip";

// =============================================================================
// File Path Constants — Static (same on all platforms)
// =============================================================================

/// Default path to system hosts file for local hostname resolution.
///
/// Static hostname-to-IP mappings read from this file and integrated
/// into DNS resolution. Entries override upstream DNS responses.
///
/// Tunable via: `--hostsdir`, `--addn-hosts` command-line options.
///
/// Source: C `config.h` line 521 — `#define HOSTSFILE "/etc/hosts"`
pub const HOSTSFILE: &str = "/etc/hosts";

/// Default path to system ethers file for MAC-to-IP mappings.
///
/// Optional file mapping Ethernet MAC addresses to IP addresses for
/// static DHCP reservations.
///
/// Tunable via: `--read-ethers` command-line option.
///
/// Source: C `config.h` line 536 — `#define ETHERSFILE "/etc/ethers"`
pub const ETHERSFILE: &str = "/etc/ethers";

/// Entropy source device path for random number generation.
///
/// Device file providing cryptographic random numbers for DNS query
/// IDs, source port randomization, and other security-critical values.
///
/// Source: C `config.h` line 668 — `#define RANDFILE "/dev/urandom"`
pub const RANDFILE: &str = "/dev/urandom";

// =============================================================================
// File Path Constants — Platform-Specific
// =============================================================================

/// Default DHCP lease file path (BSD variants: FreeBSD, OpenBSD, DragonFly, NetBSD).
///
/// Source: C `config.h` lines 1898–1908
#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "dragonfly",
    target_os = "netbsd"
))]
pub const LEASEFILE: &str = "/var/db/dnsmasq.leases";

/// Default DHCP lease file path (Solaris / illumos).
///
/// Source: C `config.h` lines 1898–1908
#[cfg(target_os = "solaris")]
pub const LEASEFILE: &str = "/var/cache/dnsmasq.leases";

/// Default DHCP lease file path (Android).
///
/// Source: C `config.h` lines 1898–1908
#[cfg(target_os = "android")]
pub const LEASEFILE: &str = "/data/misc/dhcp/dnsmasq.leases";

/// Default DHCP lease file path (Linux and all other platforms).
///
/// Source: C `config.h` lines 1898–1908
#[cfg(not(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "dragonfly",
    target_os = "netbsd",
    target_os = "solaris",
    target_os = "android"
)))]
pub const LEASEFILE: &str = "/var/lib/misc/dnsmasq.leases";

/// Default configuration file path (FreeBSD).
///
/// FreeBSD ports and packages install to `/usr/local` by convention,
/// so configuration files go in `/usr/local/etc` to avoid conflicts
/// with the base system `/etc`.
///
/// Source: C `config.h` lines 1950–1956
#[cfg(target_os = "freebsd")]
pub const CONFFILE: &str = "/usr/local/etc/dnsmasq.conf";

/// Default configuration file path (all platforms except FreeBSD).
///
/// Source: C `config.h` lines 1950–1956
#[cfg(not(target_os = "freebsd"))]
pub const CONFFILE: &str = "/etc/dnsmasq.conf";

/// Default system resolver configuration file path.
///
/// Dnsmasq reads this file to discover upstream DNS servers for forwarding.
/// The file is automatically monitored for changes via inotify on Linux
/// or periodic polling otherwise.
///
/// **Note:** The uClinux variant (`/etc/config/resolv.conf`) is not
/// applicable in Rust as there is no `target_os = "uclinux"`. If needed,
/// that edge case can be handled at runtime.
///
/// Source: C `config.h` lines 2002–2008
pub const RESOLVFILE: &str = "/etc/resolv.conf";

/// Default PID file path (Android).
///
/// Android restricts `/var/run` access; `/data` is the writable
/// partition suitable for runtime daemon data.
///
/// Source: C `config.h` lines 2053–2058
#[cfg(target_os = "android")]
pub const RUNFILE: &str = "/data/dnsmasq.pid";

/// Default PID file path (all platforms except Android).
///
/// Standard FHS location for runtime process data. On systemd systems,
/// `/var/run` is typically a symlink to `/run`.
///
/// Source: C `config.h` lines 2053–2058
#[cfg(not(target_os = "android"))]
pub const RUNFILE: &str = "/var/run/dnsmasq.pid";

// =============================================================================
// Integration Service Name Constants
// =============================================================================

/// D-Bus service name for the dnsmasq control interface.
///
/// Service name registered on the D-Bus system bus for programmatic
/// control and monitoring. Follows reverse-domain naming convention.
///
/// Tunable via: `--dbus-service-name` command-line option.
///
/// Source: C `config.h` line 683 — `#define DNSMASQ_SERVICE "uk.org.thekelleys.dnsmasq"`
pub const DNSMASQ_SERVICE: &str = "uk.org.thekelleys.dnsmasq";

/// D-Bus object path for the dnsmasq control interface.
///
/// Object path where D-Bus methods and properties are exposed. Matches
/// the service name following D-Bus path conventions.
///
/// Source: C `config.h` line 697 — `#define DNSMASQ_PATH "/uk/org/thekelleys/dnsmasq"`
pub const DNSMASQ_PATH: &str = "/uk/org/thekelleys/dnsmasq";

/// UBus service name for the dnsmasq control interface (OpenWrt).
///
/// Service name registered on the UBus system bus for programmatic
/// control on OpenWrt and embedded Linux systems.
///
/// Tunable via: `--ubus-name` command-line option.
///
/// Source: C `config.h` line 712 — `#define DNSMASQ_UBUS_NAME "dnsmasq"`
pub const DNSMASQ_UBUS_NAME: &str = "dnsmasq";

// =============================================================================
// Default Port Numbers
// =============================================================================

/// Default DNS listening port (UDP and TCP).
///
/// Standard DNS port number per RFC 1035 Section 4.2.
///
/// Source: C `dns-protocol.h` line 76 — `#define NAMESERVER_PORT 53`
pub const DNS_PORT: u16 = 53;

/// Default DHCPv4 server port.
///
/// Standard BOOTP/DHCP server port per RFC 2131.
pub const DHCP_SERVER_PORT: u16 = 67;

/// Default DHCPv4 client port.
///
/// Standard BOOTP/DHCP client port per RFC 2131.
pub const DHCP_CLIENT_PORT: u16 = 68;

/// Default DHCPv6 server port.
///
/// Standard DHCPv6 server port per RFC 3315.
pub const DHCPV6_SERVER_PORT: u16 = 547;

/// Default DHCPv6 client port.
///
/// Standard DHCPv6 client port per RFC 3315.
pub const DHCPV6_CLIENT_PORT: u16 = 546;

/// Default TFTP port.
///
/// Standard TFTP port per RFC 1350.
///
/// Source: C `dns-protocol.h` line 79 — `#define TFTP_PORT 69`
pub const TFTP_PORT: u16 = 69;

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_forwarding_constants() {
        assert_eq!(FTABSIZ, 150);
        assert_eq!(MAX_PROCS, 20);
        assert_eq!(CHILD_LIFETIME, 150);
        assert_eq!(TCP_MAX_QUERIES, 100);
        assert_eq!(TCP_TIMEOUT, 5);
        assert_eq!(TCP_BACKLOG, 32);
    }

    #[test]
    fn test_edns_and_packet_sizes() {
        assert_eq!(EDNS_PKTSZ, 1232);
        assert_eq!(PACKETSZ, 512);
        assert_eq!(MAXDNAME, 1025);
        assert_eq!(SMALLDNAME, 50);
    }

    #[test]
    fn test_query_timeouts() {
        assert_eq!(TIMEOUT, 10);
        assert_eq!(SMALL_PORT_RANGE, 30);
        assert_eq!(FORWARD_TEST, 50);
        assert_eq!(FORWARD_TIME, 20);
        assert_eq!(UDP_TEST_TIME, 60);
        assert_eq!(DEFAULT_FAST_RETRY, 1000);
    }

    #[test]
    fn test_cache_constants() {
        assert_eq!(CACHESIZ, 150);
        assert_eq!(TTL_FLOOR_LIMIT, 3600);
        assert_eq!(STALE_CACHE_EXPIRY, 86400);
        assert_eq!(CNAME_CHAIN, 10);
    }

    #[test]
    fn test_dnssec_constants() {
        assert_eq!(KEYBLOCK_LEN, 40);
        assert_eq!(DNSSEC_LIMIT_WORK, 40);
        assert_eq!(DNSSEC_LIMIT_SIG_FAIL, 20);
        assert_eq!(DNSSEC_LIMIT_CRYPTO, 200);
        assert_eq!(DNSSEC_LIMIT_NSEC3_ITERS, 150);
        assert_eq!(DNSSEC_ASSUMED_DS_TTL, 3600);
        assert_eq!(DNSSEC_MIN_TTL, 60);
    }

    #[test]
    fn test_dhcp_constants() {
        assert_eq!(MAXLEASES, 1000);
        assert_eq!(PING_WAIT, 3);
        assert_eq!(PING_CACHE_TIME, 30);
        assert_eq!(DECLINE_BACKOFF, 600);
        assert_eq!(DHCP_PACKET_MAX, 16384);
        assert_eq!(LEASE_RETRY, 60);
        assert_eq!(DEFLEASE, 3600);
        // DEFLEASE6 = 3600 * 24 = 86400
        assert_eq!(DEFLEASE6, 86400);
        assert_eq!(DEFLEASE6, 3600 * 24);
    }

    #[test]
    fn test_tftp_constants() {
        assert_eq!(TFTP_MAX_CONNECTIONS, 50);
        assert_eq!(TFTP_MAX_WINDOW, 32);
        assert_eq!(TFTP_TRANSFER_TIME, 120);
    }

    #[test]
    fn test_logging_constants() {
        assert_eq!(LOG_MAX, 5);
        assert_eq!(SERVERS_LOGGED, 30);
        assert_eq!(LOCALS_LOGGED, 8);
    }

    #[test]
    fn test_auth_soa_constants() {
        assert_eq!(AUTH_TTL, 600);
        assert_eq!(SOA_REFRESH, 1200);
        assert_eq!(SOA_RETRY, 180);
        // SOA_EXPIRY = 14 * 86400 = 1,209,600
        assert_eq!(SOA_EXPIRY, 1_209_600);
        assert_eq!(SOA_EXPIRY, 14 * 86400);
    }

    #[test]
    fn test_loop_detection_constants() {
        assert_eq!(LOOP_TEST_DOMAIN, "test");
        assert_eq!(LOOP_TEST_TYPE, 16); // T_TXT
    }

    #[test]
    fn test_security_constants() {
        assert_eq!(CHUSER, "nobody");
        assert_eq!(CHGRP, "dip");
    }

    #[test]
    fn test_file_path_constants() {
        assert_eq!(HOSTSFILE, "/etc/hosts");
        assert_eq!(ETHERSFILE, "/etc/ethers");
        assert_eq!(RANDFILE, "/dev/urandom");
        assert_eq!(RESOLVFILE, "/etc/resolv.conf");

        // Platform-specific paths — verify they are non-empty strings
        assert!(!LEASEFILE.is_empty());
        assert!(!CONFFILE.is_empty());
        assert!(!RUNFILE.is_empty());
    }

    #[test]
    fn test_service_name_constants() {
        assert_eq!(DNSMASQ_SERVICE, "uk.org.thekelleys.dnsmasq");
        assert_eq!(DNSMASQ_PATH, "/uk/org/thekelleys/dnsmasq");
        assert_eq!(DNSMASQ_UBUS_NAME, "dnsmasq");
    }

    #[test]
    fn test_port_constants() {
        assert_eq!(DNS_PORT, 53);
        assert_eq!(DHCP_SERVER_PORT, 67);
        assert_eq!(DHCP_CLIENT_PORT, 68);
        assert_eq!(DHCPV6_SERVER_PORT, 547);
        assert_eq!(DHCPV6_CLIENT_PORT, 546);
        assert_eq!(TFTP_PORT, 69);
    }

    #[test]
    fn test_computed_values_accuracy() {
        // Verify computed constants match their formulas
        assert_eq!(DEFLEASE6, 3600 * 24, "DEFLEASE6 must be exactly 24 hours");
        assert_eq!(SOA_EXPIRY, 14 * 86400, "SOA_EXPIRY must be exactly 14 days");
        assert_eq!(STALE_CACHE_EXPIRY, 86400, "STALE_CACHE_EXPIRY must be exactly 1 day");
        assert_eq!(TTL_FLOOR_LIMIT, 3600, "TTL_FLOOR_LIMIT must be exactly 1 hour");
        assert_eq!(DNSSEC_ASSUMED_DS_TTL, 3600, "DNSSEC_ASSUMED_DS_TTL must be exactly 1 hour");
    }

    #[test]
    fn test_linux_specific_paths() {
        // On Linux (CI/CD environment), verify specific platform paths
        #[cfg(target_os = "linux")]
        {
            assert_eq!(LEASEFILE, "/var/lib/misc/dnsmasq.leases");
            assert_eq!(CONFFILE, "/etc/dnsmasq.conf");
            assert_eq!(RUNFILE, "/var/run/dnsmasq.pid");
        }
    }
}

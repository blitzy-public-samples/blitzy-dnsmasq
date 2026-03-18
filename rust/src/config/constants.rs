// Copyright (c) 2000-2025 Simon Kelley
// SPDX-License-Identifier: GPL-2.0-or-later
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.

//! # Compile-Time Constants
//!
//! All numeric constants, resource limits, timeout values, default file paths,
//! and hardware type identifiers from the C `src/config.h` header and
//! `src/dns-protocol.h`. These values are identical to the C implementation
//! to ensure drop-in replacement compatibility.
//!
//! ## Organization
//!
//! Constants are grouped by functional domain:
//! - **DNS Forward Table & TCP Limits** — Connection management defaults
//! - **EDNS & DNS Limits** — Packet sizes and name length maximums
//! - **DNSSEC DoS Protection** — Validation resource limits
//! - **Timeout & Health Check** — Upstream server monitoring intervals
//! - **DHCP & Lease** — Lease management defaults and limits
//! - **DNS Name & Cache** — Cache sizing and chain limits
//! - **File Paths** — Default configuration, lease, PID, and hosts file locations
//! - **Service Names** — D-Bus and ubus identifiers
//! - **SOA & Auth DNS** — Authoritative DNS zone timing parameters
//! - **Platform-Specific Paths** — OS-dependent file locations via `cfg(target_os)`
//! - **ARP Hardware Types** — Hardware address type constants from `if_arp.h`
//!
//! ## Source Reference
//!
//! - `src/config.h` lines 93–828: All numeric constants
//! - `src/config.h` lines 1898–2059: Platform-specific file paths
//! - `src/dns-protocol.h` lines 102–105: `PACKETSZ` and `MAXDNAME`
//! - System header `linux/if_arp.h`: `ARPHRD_*` hardware type codes

// =============================================================================
// DNS Forward Table & TCP Limits
// From config.h lines 93–160
// =============================================================================

/// Maximum number of concurrent outstanding DNS queries (forward table size).
///
/// Controls the size of the forward query table which tracks DNS queries
/// awaiting upstream responses. When this limit is reached, new queries are
/// dropped until existing queries complete or time out.
///
/// Default for `--dns-forward-max` option.
///
/// Source: `config.h` line 93: `#define FTABSIZ 150`
pub const FTABSIZ: u32 = 150;

/// Maximum number of child processes for TCP DNS connections.
///
/// Each TCP DNS connection is handled by a separate child process (in the C
/// implementation) or async task (in the Rust implementation). This limits
/// the total number of concurrent TCP DNS sessions.
///
/// Default for `--max-tcp-connections` option.
///
/// Source: `config.h` line 108: `#define MAX_PROCS 20`
pub const MAX_PROCS: u32 = 20;

/// Maximum lifetime (seconds) for TCP child processes.
///
/// TCP DNS handler processes that exceed this age are forcibly terminated
/// to prevent resource leaks from stuck connections.
///
/// Source: `config.h` line 121: `#define CHILD_LIFETIME 150`
pub const CHILD_LIFETIME: u32 = 150;

/// Maximum queries per TCP connection.
///
/// After this many queries on a single TCP connection, the connection is
/// closed. Prevents a single client from monopolizing a TCP slot indefinitely.
///
/// Source: `config.h` line 134: `#define TCP_MAX_QUERIES 100`
pub const TCP_MAX_QUERIES: u32 = 100;

/// TCP connection timeout (seconds).
///
/// Time to wait for data on a TCP connection before closing it. The actual
/// timeout for waiting for a response is doubled (2 × `TCP_TIMEOUT`).
///
/// Source: `config.h` line 147: `#define TCP_TIMEOUT 5`
pub const TCP_TIMEOUT: u32 = 5;

/// Kernel listen backlog for TCP socket accept queue.
///
/// Passed to `listen(2)` as the backlog parameter. Controls how many pending
/// TCP connections the kernel will queue before refusing new ones.
///
/// Source: `config.h` line 160: `#define TCP_BACKLOG 32`
pub const TCP_BACKLOG: i32 = 32;

// =============================================================================
// EDNS & DNS Limits
// From config.h lines 162–186 and dns-protocol.h lines 102–105
// =============================================================================

/// Default maximum EDNS0 UDP packet size (bytes).
///
/// Follows DNS Flag Day 2020 recommendations to use 1232 bytes as the
/// default EDNS0 UDP payload size, avoiding fragmentation on most networks
/// (IPv6 minimum MTU 1280 minus headers).
///
/// Default for `--edns-packet-max` option.
///
/// Source: `config.h` line 175: `#define EDNS_PKTSZ 1232`
pub const EDNS_PKTSZ: u16 = 1232;

/// Standard DNS UDP packet size without EDNS (bytes).
///
/// The original DNS specification (RFC 1035) limits UDP DNS messages to
/// 512 bytes. EDNS0 (RFC 6891) extends this via the OPT pseudo-RR.
///
/// Source: `dns-protocol.h` line 102: `#define PACKETSZ 512`
pub const PACKETSZ: u16 = 512;

/// Maximum DNS domain name length (bytes) including trailing null.
///
/// RFC 1035 Section 3.1 specifies a maximum domain name length of 255 octets
/// in wire format. The value 1025 accounts for the text representation
/// (each label up to 63 chars, separated by dots, plus trailing null).
///
/// Source: `dns-protocol.h` line 105: `#define MAXDNAME 1025`
pub const MAXDNAME: usize = 1025;

/// Block size for DNSSEC key material storage (bytes).
///
/// DNSSEC key data and signatures are stored in fixed-size blocks
/// for efficient memory allocation and management.
///
/// Source: `config.h` line 186: `#define KEYBLOCK_LEN 40`
pub const KEYBLOCK_LEN: usize = 40;

// =============================================================================
// DNSSEC DoS Protection Limits
// From config.h lines 188–258, 508
// =============================================================================

/// Maximum DNS queries during DNSSEC validation chain.
///
/// Limits the total number of sub-queries generated while following a DNSSEC
/// chain of trust. Prevents excessive resource consumption from deeply nested
/// or maliciously constructed delegation chains.
///
/// Source: `config.h` line 201: `#define DNSSEC_LIMIT_WORK 40`
pub const DNSSEC_LIMIT_WORK: u32 = 40;

/// Maximum signature validation failures per response.
///
/// If more than this many signatures fail validation for a single response,
/// the entire validation is aborted. Prevents CPU exhaustion from responses
/// containing many invalid signatures.
///
/// Source: `config.h` line 215: `#define DNSSEC_LIMIT_SIG_FAIL 20`
pub const DNSSEC_LIMIT_SIG_FAIL: u32 = 20;

/// Maximum cryptographic operations per validation query.
///
/// Caps the total number of cryptographic signature verifications and hash
/// computations performed for a single DNSSEC validation. This is the primary
/// defense against algorithmic complexity attacks.
///
/// Source: `config.h` line 230: `#define DNSSEC_LIMIT_CRYPTO 200`
pub const DNSSEC_LIMIT_CRYPTO: u32 = 200;

/// Maximum NSEC3 hash iterations for denial-of-existence proofs.
///
/// NSEC3 (RFC 5155) allows variable hash iteration counts. High iteration
/// counts can be used as a DoS vector. This limit caps the accepted iterations.
///
/// Source: `config.h` line 245: `#define DNSSEC_LIMIT_NSEC3_ITERS 150`
pub const DNSSEC_LIMIT_NSEC3_ITERS: u32 = 150;

/// TTL for synthesized negative DS records (seconds).
///
/// When a zone is unsigned (no DS record at delegation), dnsmasq synthesizes
/// a negative cache entry with this TTL to avoid repeated upstream queries.
///
/// Source: `config.h` line 258: `#define DNSSEC_ASSUMED_DS_TTL 3600`
pub const DNSSEC_ASSUMED_DS_TTL: u32 = 3600;

/// Minimum TTL for cached DNSSEC records (seconds).
///
/// Ensures DNSSEC-related cache entries persist for at least this long,
/// even if the upstream TTL is shorter. Prevents excessive re-validation
/// traffic for frequently queried signed zones.
///
/// Source: `config.h` line 508: `#define DNSSEC_MIN_TTL 60`
pub const DNSSEC_MIN_TTL: u32 = 60;

// =============================================================================
// Timeout & Health Check Values
// From config.h lines 259–349
// =============================================================================

/// UDP query timeout (seconds).
///
/// Default timeout for upstream DNS queries sent via UDP. If no response
/// is received within this period, the query is retried or fails.
///
/// Source: `config.h` line 271: `#define TIMEOUT 10`
pub const TIMEOUT: u32 = 10;

/// Threshold for random vs sequential port allocation.
///
/// When the available port range has fewer than this many ports, dnsmasq
/// switches from random selection to sequential allocation to ensure all
/// ports are used before recycling.
///
/// Source: `config.h` line 284: `#define SMALL_PORT_RANGE 30`
pub const SMALL_PORT_RANGE: u16 = 30;

/// Query count interval for upstream server health testing.
///
/// Every `FORWARD_TEST` queries, dnsmasq re-evaluates upstream server
/// health by testing all configured servers, not just the currently
/// preferred one.
///
/// Source: `config.h` line 297: `#define FORWARD_TEST 50`
pub const FORWARD_TEST: u32 = 50;

/// Time interval (seconds) for upstream server health testing.
///
/// In addition to the query-count trigger (`FORWARD_TEST`), upstream
/// servers are tested if this many seconds have elapsed since the last test.
///
/// Source: `config.h` line 310: `#define FORWARD_TIME 20`
pub const FORWARD_TIME: u32 = 20;

/// Interval (seconds) to reset EDNS packet size assumptions.
///
/// If EDNS0 queries fail (likely due to middlebox interference), dnsmasq
/// falls back to smaller packets. After this interval, it retries with
/// the full EDNS0 size to check if the path has been fixed.
///
/// Source: `config.h` line 323: `#define UDP_TEST_TIME 60`
pub const UDP_TEST_TIME: u32 = 60;

/// Maximum servers logged in state dumps.
///
/// When dumping server statistics (via SIGUSR1), only the first
/// `SERVERS_LOGGED` servers are included to keep output manageable.
///
/// Source: `config.h` line 336: `#define SERVERS_LOGGED 30`
pub const SERVERS_LOGGED: u32 = 30;

/// Maximum local addresses logged in state dumps.
///
/// When dumping local address bindings, only the first `LOCALS_LOGGED`
/// addresses are included in the log output.
///
/// Source: `config.h` line 349: `#define LOCALS_LOGGED 8`
pub const LOCALS_LOGGED: u32 = 8;

// =============================================================================
// DHCP & Lease Constants
// From config.h lines 351–466
// =============================================================================

/// Retry interval (seconds) for failed lease file writes.
///
/// If writing the DHCP lease file fails (e.g., disk full), dnsmasq retries
/// after this interval. Lease data is held in memory and persisted when
/// the write succeeds.
///
/// Source: `config.h` line 363: `#define LEASE_RETRY 60`
pub const LEASE_RETRY: u32 = 60;

/// Default DNS cache size in entries.
///
/// Controls the maximum number of DNS resource records cached in memory.
/// Setting to 0 disables the cache entirely.
///
/// Default for `--cache-size` option.
///
/// Source: `config.h` line 379: `#define CACHESIZ 150`
pub const CACHESIZ: u32 = 150;

/// Maximum TTL for `--min-cache-ttl` option (seconds).
///
/// Caps the `--min-cache-ttl` directive to prevent excessively stale data.
/// Users cannot set a minimum cache TTL higher than this value.
///
/// Source: `config.h` line 392: `#define TTL_FLOOR_LIMIT 3600`
pub const TTL_FLOOR_LIMIT: u32 = 3600;

/// Maximum concurrent DHCP leases.
///
/// Limits the total number of active DHCP address leases. When this limit
/// is reached, new DHCP requests are silently dropped until existing
/// leases expire.
///
/// Default for `--dhcp-lease-max` option.
///
/// Source: `config.h` line 407: `#define MAXLEASES 1000`
pub const MAXLEASES: u32 = 1000;

/// Seconds to wait for ping response in address-in-use testing.
///
/// Before offering a DHCP address, dnsmasq pings it to check for conflicts.
/// This is the timeout for waiting for the ping (ICMP echo) reply.
///
/// Source: `config.h` line 422: `#define PING_WAIT 3`
pub const PING_WAIT: u32 = 3;

/// Seconds to trust cached ping results.
///
/// After a successful (no-reply) ping check, the result is cached for
/// this duration. Subsequent DHCP requests for the same address skip
/// the ping check within this window.
///
/// Source: `config.h` line 436: `#define PING_CACHE_TIME 30`
pub const PING_CACHE_TIME: u32 = 30;

/// Seconds to disable DECLINEd static reservations.
///
/// When a client sends a DHCPDECLINE for a statically reserved address,
/// the reservation is disabled for this duration to allow the conflicting
/// device to be identified and resolved.
///
/// Source: `config.h` line 451: `#define DECLINE_BACKOFF 600`
pub const DECLINE_BACKOFF: u32 = 600;

/// Hard maximum DHCP packet size (bytes).
///
/// The absolute maximum size for DHCP packets, including all options.
/// This caps the `--dhcp-packet-max` directive. RFC 2131 specifies a
/// minimum of 576 bytes; this allows much larger packets for environments
/// with many DHCP options.
///
/// Source: `config.h` line 466: `#define DHCP_PACKET_MAX 16384`
pub const DHCP_PACKET_MAX: usize = 16384;

// =============================================================================
// DNS Name & Cache Constants
// From config.h lines 468–508
// =============================================================================

/// Typical maximum domain name length for buffer optimization.
///
/// Used for stack-allocated buffers in hot paths where a full `MAXDNAME`
/// buffer would be wasteful. Most real-world domain names fit within this
/// limit. Longer names fall back to heap allocation.
///
/// Source: `config.h` line 480: `#define SMALLDNAME 50`
pub const SMALLDNAME: usize = 50;

/// Maximum CNAME chain length before loop detection.
///
/// When resolving CNAME chains, dnsmasq follows at most this many links.
/// Exceeding this limit is treated as a CNAME loop and the query fails
/// with SERVFAIL.
///
/// Source: `config.h` line 494: `#define CNAME_CHAIN 10`
pub const CNAME_CHAIN: u32 = 10;

// =============================================================================
// File Paths & String Constants
// From config.h lines 521–668
// =============================================================================

/// Default hosts file path.
///
/// The standard system hosts file, read at startup and monitored for
/// changes (via inotify on Linux). Entries are served as local DNS records.
///
/// Source: `config.h` line 521: `#define HOSTSFILE "/etc/hosts"`
pub const HOSTSFILE: &str = "/etc/hosts";

/// Default ethers file path.
///
/// The standard system ethers file mapping MAC addresses to hostnames.
/// Used by `--read-ethers` to create static DHCP reservations.
///
/// Source: `config.h` line 536: `#define ETHERSFILE "/etc/ethers"`
pub const ETHERSFILE: &str = "/etc/ethers";

/// Default DHCP lease time (seconds) for DHCPv4.
///
/// When no explicit lease time is configured in a `--dhcp-range` directive,
/// this default of one hour is used.
///
/// Source: `config.h` line 551: `#define DEFLEASE 3600`
pub const DEFLEASE: u32 = 3600;

/// Default DHCP lease time (seconds) for DHCPv6 (24 hours).
///
/// DHCPv6 uses a longer default lease time than DHCPv4 because IPv6
/// address assignment is typically more stable.
///
/// Source: `config.h` line 566: `#define DEFLEASE6 (3600*24)`
pub const DEFLEASE6: u32 = 3600 * 24;

/// Default user for privilege separation.
///
/// After binding privileged ports (< 1024), dnsmasq drops privileges to
/// this user. On most systems, "nobody" is an unprivileged account with
/// minimal permissions.
///
/// Source: `config.h` line 581: `#define CHUSER "nobody"`
pub const CHUSER: &str = "nobody";

/// Default group for privilege separation.
///
/// After binding privileged ports, dnsmasq drops to this group. The "dip"
/// group typically has permissions for network device access on Debian-based
/// systems.
///
/// Source: `config.h` line 595: `#define CHGRP "dip"`
pub const CHGRP: &str = "dip";

/// Maximum concurrent TFTP transfers.
///
/// Limits the total number of simultaneous TFTP file transfers. Each active
/// transfer consumes a file descriptor and a memory buffer.
///
/// Default for `--tftp-max` option.
///
/// Source: `config.h` line 610: `#define TFTP_MAX_CONNECTIONS 50`
pub const TFTP_MAX_CONNECTIONS: u32 = 50;

/// Maximum TFTP window size for RFC 7440.
///
/// Controls the maximum number of data blocks sent before requiring an
/// acknowledgment, as defined in the TFTP Windowsize Option (RFC 7440).
///
/// Source: `config.h` line 625: `#define TFTP_MAX_WINDOW 32`
pub const TFTP_MAX_WINDOW: u32 = 32;

/// Timeout (seconds) for abandoned TFTP transfers.
///
/// If no packets are received for an active TFTP transfer within this
/// period, the transfer is considered abandoned and its resources are freed.
///
/// Source: `config.h` line 640: `#define TFTP_TRANSFER_TIME 120`
pub const TFTP_TRANSFER_TIME: u32 = 120;

/// Non-blocking log queue depth.
///
/// Maximum number of log messages queued for asynchronous delivery when
/// `--log-async` is enabled. When the queue is full, additional messages
/// are dropped rather than blocking the event loop.
///
/// Source: `config.h` line 654: `#define LOG_MAX 5`
pub const LOG_MAX: u32 = 5;

/// Entropy source device path.
///
/// Used for seeding the random number generator for DNS query ID
/// generation and port randomization. `/dev/urandom` provides
/// non-blocking cryptographically secure random bytes.
///
/// Source: `config.h` line 668: `#define RANDFILE "/dev/urandom"`
pub const RANDFILE: &str = "/dev/urandom";

// =============================================================================
// Service Names
// From config.h lines 683–712
// =============================================================================

/// D-Bus service name.
///
/// The well-known D-Bus service name used for registering dnsmasq on the
/// system bus. NetworkManager and other D-Bus clients use this name to
/// communicate with dnsmasq for dynamic DNS server configuration.
///
/// Source: `config.h` line 683: `#define DNSMASQ_SERVICE "uk.org.thekelleys.dnsmasq"`
pub const DNSMASQ_SERVICE: &str = "uk.org.thekelleys.dnsmasq";

/// D-Bus object path.
///
/// The D-Bus object path at which dnsmasq exposes its interface. D-Bus
/// method calls and signals are routed through this path.
///
/// Source: `config.h` line 697: `#define DNSMASQ_PATH "/uk/org/thekelleys/dnsmasq"`
pub const DNSMASQ_PATH: &str = "/uk/org/thekelleys/dnsmasq";

/// UBus service name (OpenWrt).
///
/// The service name used for registering dnsmasq on OpenWrt's ubus
/// message bus. Used for integration with OpenWrt's network management.
///
/// Source: `config.h` line 712: `#define DNSMASQ_UBUS_NAME "dnsmasq"`
pub const DNSMASQ_UBUS_NAME: &str = "dnsmasq";

// =============================================================================
// SOA & Authoritative DNS Constants
// From config.h lines 727–772
// =============================================================================

/// Default authoritative DNS TTL (seconds).
///
/// Time-to-live for records served from authoritative zones configured
/// via `--auth-zone`. Controls how long downstream resolvers cache
/// authoritative answers.
///
/// Default for `--auth-ttl` option.
///
/// Source: `config.h` line 727: `#define AUTH_TTL 600`
pub const AUTH_TTL: u32 = 600;

/// SOA refresh interval (seconds).
///
/// The refresh field in SOA records for authoritative zones. Controls how
/// often secondary servers check for zone updates.
///
/// Source: `config.h` line 742: `#define SOA_REFRESH 1200`
pub const SOA_REFRESH: u32 = 1200;

/// SOA retry interval (seconds).
///
/// The retry field in SOA records. If a refresh attempt fails, the
/// secondary server retries after this interval.
///
/// Source: `config.h` line 757: `#define SOA_RETRY 180`
pub const SOA_RETRY: u32 = 180;

/// SOA expiry time (seconds, 14 days).
///
/// The expire field in SOA records. If a secondary server cannot reach
/// the primary for this duration, it stops serving the zone.
///
/// Source: `config.h` line 772: `#define SOA_EXPIRY 1209600`
pub const SOA_EXPIRY: u32 = 1_209_600;

// =============================================================================
// Miscellaneous Constants
// From config.h lines 787–828
// =============================================================================

/// Domain for DNS forwarding loop detection.
///
/// When `--dns-loop-detect` is enabled, dnsmasq periodically queries this
/// domain with a unique identifier. If the query is received back, a
/// forwarding loop is detected and the offending server is disabled.
///
/// Source: `config.h` line 787: `#define LOOP_TEST_DOMAIN "test"`
pub const LOOP_TEST_DOMAIN: &str = "test";

/// Default fast retry delay (milliseconds).
///
/// When `--fast-dns-retry` is enabled (or by default), this is the initial
/// delay before retrying a DNS query to an alternative upstream server
/// if the first server is slow to respond.
///
/// Source: `config.h` line 814: `#define DEFAULT_FAST_RETRY 1000`
pub const DEFAULT_FAST_RETRY: u32 = 1000;

/// Maximum stale cache data age (seconds, 1 day).
///
/// When `--use-stale-cache` is enabled, expired cache entries can be served
/// if the upstream server is unreachable. This constant limits how old a
/// stale entry can be before it is discarded entirely.
///
/// Source: `config.h` line 828: `#define STALE_CACHE_EXPIRY 86400`
pub const STALE_CACHE_EXPIRY: u32 = 86400;

// =============================================================================
// Platform-Specific Paths
// From config.h lines 1898–2059
// =============================================================================

/// Default DHCP lease file path (BSD variants).
///
/// FreeBSD, OpenBSD, DragonFlyBSD, and NetBSD store lease files in `/var/db/`.
///
/// Source: `config.h` lines 1898–1908
#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "dragonfly",
    target_os = "netbsd"
))]
pub const LEASEFILE: &str = "/var/db/dnsmasq.leases";

/// Default DHCP lease file path (Solaris).
///
/// Solaris stores lease files in `/var/cache/`.
///
/// Source: `config.h` lines 1898–1908
#[cfg(target_os = "solaris")]
pub const LEASEFILE: &str = "/var/cache/dnsmasq.leases";

/// Default DHCP lease file path (Android).
///
/// Android stores lease files in the DHCP data directory.
///
/// Source: `config.h` lines 1898–1908
#[cfg(target_os = "android")]
pub const LEASEFILE: &str = "/data/misc/dhcp/dnsmasq.leases";

/// Default DHCP lease file path (Linux and other platforms).
///
/// The standard Linux FHS location for dnsmasq lease persistence.
///
/// Source: `config.h` lines 1898–1908
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
/// FreeBSD installs dnsmasq via ports/packages to `/usr/local/etc/`.
///
/// Source: `config.h` lines 1950–1956
#[cfg(target_os = "freebsd")]
pub const CONFFILE: &str = "/usr/local/etc/dnsmasq.conf";

/// Default configuration file path (non-FreeBSD).
///
/// Standard FHS location for the dnsmasq configuration file.
///
/// Source: `config.h` lines 1950–1956
#[cfg(not(target_os = "freebsd"))]
pub const CONFFILE: &str = "/etc/dnsmasq.conf";

/// Default resolv.conf path.
///
/// The standard system resolver configuration file, read to discover
/// upstream DNS servers when `--no-resolv` is not set.
///
/// Source: `config.h` lines 2002–2008
pub const RESOLVFILE: &str = "/etc/resolv.conf";

/// Default PID file path (Android).
///
/// Android stores PID files in the data partition.
///
/// Source: `config.h` lines 2053–2059
#[cfg(target_os = "android")]
pub const RUNFILE: &str = "/data/dnsmasq.pid";

/// Default PID file path (non-Android).
///
/// Standard FHS location for the dnsmasq PID file.
///
/// Source: `config.h` lines 2053–2059
#[cfg(not(target_os = "android"))]
pub const RUNFILE: &str = "/var/run/dnsmasq.pid";

// =============================================================================
// ARP Hardware Type Constants
// From system header linux/if_arp.h (used throughout dnsmasq DHCP subsystem)
// =============================================================================

/// ARP hardware type: Ethernet (10 Mbps).
///
/// IEEE 802.3 Ethernet hardware address type. Used in DHCP `htype` fields,
/// lease management, and hardware address comparison throughout the DHCP
/// subsystem.
///
/// Source: `linux/if_arp.h`: `#define ARPHRD_ETHER 1`
pub const ARPHRD_ETHER: u16 = 1;

/// ARP hardware type: IEEE 802.2 Token Ring.
///
/// Token Ring hardware address type. Supported for DHCP clients on legacy
/// Token Ring networks.
///
/// Source: `linux/if_arp.h`: `#define ARPHRD_IEEE802 6`
pub const ARPHRD_IEEE802: u16 = 6;

/// ARP hardware type: EUI-64 (64-bit Extended Unique Identifier).
///
/// Used for hardware addresses that use the 64-bit EUI format, such as
/// some IEEE 1394 (FireWire) and InfiniBand interfaces.
///
/// Source: `linux/if_arp.h`: `#define ARPHRD_EUI64 27`
pub const ARPHRD_EUI64: u16 = 27;

/// ARP hardware type: IEEE 1394 (FireWire).
///
/// FireWire network interface hardware address type. FireWire supports
/// IP networking via RFC 2734.
///
/// Source: `linux/if_arp.h`: `#define ARPHRD_IEEE1394 24`
pub const ARPHRD_IEEE1394: u16 = 24;

// =============================================================================
// Module-Level Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_forward_table_and_tcp_limits() {
        assert_eq!(FTABSIZ, 150);
        assert_eq!(MAX_PROCS, 20);
        assert_eq!(CHILD_LIFETIME, 150);
        assert_eq!(TCP_MAX_QUERIES, 100);
        assert_eq!(TCP_TIMEOUT, 5);
        assert_eq!(TCP_BACKLOG, 32);
    }

    #[test]
    fn test_edns_and_dns_limits() {
        assert_eq!(EDNS_PKTSZ, 1232);
        assert_eq!(PACKETSZ, 512);
        assert_eq!(MAXDNAME, 1025);
        assert_eq!(KEYBLOCK_LEN, 40);
    }

    #[test]
    fn test_dnssec_dos_protection_limits() {
        assert_eq!(DNSSEC_LIMIT_WORK, 40);
        assert_eq!(DNSSEC_LIMIT_SIG_FAIL, 20);
        assert_eq!(DNSSEC_LIMIT_CRYPTO, 200);
        assert_eq!(DNSSEC_LIMIT_NSEC3_ITERS, 150);
        assert_eq!(DNSSEC_ASSUMED_DS_TTL, 3600);
        assert_eq!(DNSSEC_MIN_TTL, 60);
    }

    #[test]
    fn test_timeout_and_health_check_values() {
        assert_eq!(TIMEOUT, 10);
        assert_eq!(SMALL_PORT_RANGE, 30);
        assert_eq!(FORWARD_TEST, 50);
        assert_eq!(FORWARD_TIME, 20);
        assert_eq!(UDP_TEST_TIME, 60);
        assert_eq!(SERVERS_LOGGED, 30);
        assert_eq!(LOCALS_LOGGED, 8);
    }

    #[test]
    fn test_dhcp_and_lease_constants() {
        assert_eq!(LEASE_RETRY, 60);
        assert_eq!(CACHESIZ, 150);
        assert_eq!(TTL_FLOOR_LIMIT, 3600);
        assert_eq!(MAXLEASES, 1000);
        assert_eq!(PING_WAIT, 3);
        assert_eq!(PING_CACHE_TIME, 30);
        assert_eq!(DECLINE_BACKOFF, 600);
        assert_eq!(DHCP_PACKET_MAX, 16384);
    }

    #[test]
    fn test_dns_name_and_cache_constants() {
        assert_eq!(SMALLDNAME, 50);
        assert_eq!(CNAME_CHAIN, 10);
    }

    #[test]
    fn test_file_paths() {
        assert_eq!(HOSTSFILE, "/etc/hosts");
        assert_eq!(ETHERSFILE, "/etc/ethers");
        assert_eq!(RANDFILE, "/dev/urandom");
        assert_eq!(RESOLVFILE, "/etc/resolv.conf");
    }

    #[test]
    fn test_lease_defaults() {
        assert_eq!(DEFLEASE, 3600);
        assert_eq!(DEFLEASE6, 86400); // 3600 * 24
    }

    #[test]
    fn test_privilege_separation_defaults() {
        assert_eq!(CHUSER, "nobody");
        assert_eq!(CHGRP, "dip");
    }

    #[test]
    fn test_tftp_constants() {
        assert_eq!(TFTP_MAX_CONNECTIONS, 50);
        assert_eq!(TFTP_MAX_WINDOW, 32);
        assert_eq!(TFTP_TRANSFER_TIME, 120);
    }

    #[test]
    fn test_log_constant() {
        assert_eq!(LOG_MAX, 5);
    }

    #[test]
    fn test_service_names() {
        assert_eq!(DNSMASQ_SERVICE, "uk.org.thekelleys.dnsmasq");
        assert_eq!(DNSMASQ_PATH, "/uk/org/thekelleys/dnsmasq");
        assert_eq!(DNSMASQ_UBUS_NAME, "dnsmasq");
    }

    #[test]
    fn test_soa_and_auth_constants() {
        assert_eq!(AUTH_TTL, 600);
        assert_eq!(SOA_REFRESH, 1200);
        assert_eq!(SOA_RETRY, 180);
        assert_eq!(SOA_EXPIRY, 1_209_600);
    }

    #[test]
    fn test_miscellaneous_constants() {
        assert_eq!(LOOP_TEST_DOMAIN, "test");
        assert_eq!(DEFAULT_FAST_RETRY, 1000);
        assert_eq!(STALE_CACHE_EXPIRY, 86400);
    }

    #[test]
    fn test_platform_specific_leasefile() {
        // The value of LEASEFILE depends on the target OS.
        // On Linux (the most common build target), it should be:
        #[cfg(target_os = "linux")]
        assert_eq!(LEASEFILE, "/var/lib/misc/dnsmasq.leases");

        // On FreeBSD:
        #[cfg(target_os = "freebsd")]
        assert_eq!(LEASEFILE, "/var/db/dnsmasq.leases");

        // On Android:
        #[cfg(target_os = "android")]
        assert_eq!(LEASEFILE, "/data/misc/dhcp/dnsmasq.leases");

        // Regardless of platform, LEASEFILE should be a non-empty string
        assert!(!LEASEFILE.is_empty());
    }

    #[test]
    fn test_platform_specific_conffile() {
        #[cfg(target_os = "freebsd")]
        assert_eq!(CONFFILE, "/usr/local/etc/dnsmasq.conf");

        #[cfg(not(target_os = "freebsd"))]
        assert_eq!(CONFFILE, "/etc/dnsmasq.conf");

        assert!(!CONFFILE.is_empty());
    }

    #[test]
    fn test_platform_specific_runfile() {
        #[cfg(target_os = "android")]
        assert_eq!(RUNFILE, "/data/dnsmasq.pid");

        #[cfg(not(target_os = "android"))]
        assert_eq!(RUNFILE, "/var/run/dnsmasq.pid");

        assert!(!RUNFILE.is_empty());
    }

    #[test]
    fn test_arphrd_constants() {
        assert_eq!(ARPHRD_ETHER, 1);
        assert_eq!(ARPHRD_IEEE802, 6);
        assert_eq!(ARPHRD_EUI64, 27);
        assert_eq!(ARPHRD_IEEE1394, 24);
    }

    #[test]
    fn test_edns_pktsz_within_ipv6_mtu() {
        // EDNS_PKTSZ (1232) should fit within IPv6 minimum MTU (1280)
        // minus IPv6 header (40) and UDP header (8) = 1232
        assert!(EDNS_PKTSZ <= 1232);
        assert!(EDNS_PKTSZ > PACKETSZ);
    }

    #[test]
    fn test_deflease6_is_24_hours() {
        assert_eq!(DEFLEASE6, 24 * DEFLEASE);
    }

    #[test]
    fn test_soa_timing_relationships() {
        // Refresh > Retry (standard SOA timing convention)
        assert!(SOA_REFRESH > SOA_RETRY);
        // Expiry >> Refresh (zone should survive many missed refreshes)
        assert!(SOA_EXPIRY > SOA_REFRESH * 10);
    }

    #[test]
    fn test_constant_count() {
        // Verify we have all 62 exported constants by referencing each one.
        // This test ensures no constant was accidentally removed.
        let _constants: [&dyn std::fmt::Debug; 62] = [
            &FTABSIZ,
            &CACHESIZ,
            &MAXLEASES,
            &EDNS_PKTSZ,
            &CONFFILE,
            &LEASEFILE,
            &MAX_PROCS,
            &MAXDNAME,
            &RANDFILE,
            &TIMEOUT,
            &CHILD_LIFETIME,
            &RESOLVFILE,
            &CHUSER,
            &CHGRP,
            &TCP_MAX_QUERIES,
            &TCP_TIMEOUT,
            &TCP_BACKLOG,
            &PACKETSZ,
            &KEYBLOCK_LEN,
            &DNSSEC_LIMIT_WORK,
            &DNSSEC_LIMIT_SIG_FAIL,
            &DNSSEC_LIMIT_CRYPTO,
            &DNSSEC_LIMIT_NSEC3_ITERS,
            &DNSSEC_ASSUMED_DS_TTL,
            &DNSSEC_MIN_TTL,
            &SMALL_PORT_RANGE,
            &FORWARD_TEST,
            &FORWARD_TIME,
            &UDP_TEST_TIME,
            &SERVERS_LOGGED,
            &LOCALS_LOGGED,
            &LEASE_RETRY,
            &TTL_FLOOR_LIMIT,
            &PING_WAIT,
            &PING_CACHE_TIME,
            &DECLINE_BACKOFF,
            &DHCP_PACKET_MAX,
            &SMALLDNAME,
            &CNAME_CHAIN,
            &HOSTSFILE,
            &ETHERSFILE,
            &DEFLEASE,
            &DEFLEASE6,
            &TFTP_MAX_CONNECTIONS,
            &TFTP_MAX_WINDOW,
            &TFTP_TRANSFER_TIME,
            &LOG_MAX,
            &DNSMASQ_SERVICE,
            &DNSMASQ_PATH,
            &DNSMASQ_UBUS_NAME,
            &AUTH_TTL,
            &SOA_REFRESH,
            &SOA_RETRY,
            &SOA_EXPIRY,
            &LOOP_TEST_DOMAIN,
            &DEFAULT_FAST_RETRY,
            &STALE_CACHE_EXPIRY,
            &RUNFILE,
            &ARPHRD_ETHER,
            &ARPHRD_IEEE802,
            &ARPHRD_EUI64,
            &ARPHRD_IEEE1394,
        ];
        assert_eq!(_constants.len(), 62);
    }
}

// dnsmasq is Copyright (c) 2000-2025 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! # Runtime Metrics Counters
//!
//! Rust implementation of runtime performance counters for DNS, DHCP, DNSSEC,
//! and network operations. Replaces `src/metrics.c` (315 lines) and
//! `src/metrics.h` (365 lines) from the C dnsmasq implementation.
//!
//! ## Thread Safety
//! Uses [`AtomicU64`] for thread-safe atomic counters, replacing the C
//! single-threaded `u32` counter array (`daemon->metrics[__METRIC_MAX]`).
//! All atomic operations use [`Ordering::Relaxed`] because:
//! 1. Metrics are informational only — strict ordering is not required
//! 2. Individual counter consistency matters, cross-counter consistency does not
//! 3. Matches C behavior where counters were incremented without memory barriers
//! 4. Relaxed provides the best performance for high-frequency counter updates
//!
//! ## Compilation
//! This module is **always compiled** — no feature gate. Metrics are
//! unconditionally available, matching C behavior where `metrics.c` and
//! `metrics.h` have no conditional compilation guards.
//!
//! ## Upgrade from C
//! - Counter type upgraded from C `u32` to Rust `AtomicU64` for:
//!   - Thread safety (Rust async runtime may use multiple threads)
//!   - Larger counter range (avoids `u32` overflow for high-traffic deployments)
//!   - Lock-free concurrent access via atomic operations
//!
//! ## Backward Compatibility
//! All metric name strings exactly match the C `metric_names[]` array
//! (including the intentional typo `"dhcp_lease_actve"` at index 28)
//! for D-Bus/UBus export and monitoring integration compatibility.
//!
//! ## C Source Origin
//! - `src/metrics.h` lines 102–268: Metric type enum (30 metrics + `__METRIC_MAX` sentinel)
//! - `src/metrics.c` lines 123–154: Metric name string array
//! - `src/metrics.c` lines 208–210: `get_metric_name()` function
//! - `src/metrics.c` lines 297–314: `clear_metrics()` function

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Total number of defined metric types.
/// Matches C `__METRIC_MAX` sentinel value (metrics.h line 267).
///
/// Used to size the [`MetricsStore`] counter array and validate metric IDs.
/// This must always equal the number of variants in [`MetricType`].
pub const METRIC_MAX: usize = 30;

/// Human-readable metric names indexed by [`MetricType`] discriminant.
///
/// Order and content **must** match C `metric_names[]` in `metrics.c`
/// lines 123–154. Used for D-Bus/UBus export, logging, and monitoring
/// system integration.
///
/// # String Format Convention
/// - Lowercase with underscores separating words
/// - Prefixed by category: `dns_`, `dhcp_`, `dnssec_`, `leases_`, `tcp_`
/// - Describes the event being counted (e.g., `"forwarded"`, `"inserted"`, `"pruned"`)
///
/// # Backward Compatibility
/// **CRITICAL**: Index 28 (`"dhcp_lease_actve"`) preserves the C typo for
/// backward compatibility with existing monitoring integrations that depend
/// on this exact string. Do **not** correct it.
pub const METRIC_NAMES: [&str; METRIC_MAX] = [
    "dns_cache_inserted",    // 0:  DnsCacheInserted
    "dns_cache_live_freed",  // 1:  DnsCacheLiveFreed
    "dns_queries_forwarded", // 2:  DnsQueriesForwarded
    "dns_auth_answered",     // 3:  DnsAuthAnswered
    "dns_local_answered",    // 4:  DnsLocalAnswered
    "dns_stale_answered",    // 5:  DnsStaleAnswered
    "dns_unanswered",        // 6:  DnsUnansweredQuery
    "dnssec_max_crypto_use", // 7:  CryptoHwm
    "dnssec_max_sig_fail",   // 8:  SigFailHwm
    "dnssec_max_work",       // 9:  WorkHwm
    "bootp",                 // 10: Bootp
    "pxe",                   // 11: Pxe
    "dhcp_ack",              // 12: DhcpAck
    "dhcp_decline",          // 13: DhcpDecline
    "dhcp_discover",         // 14: DhcpDiscover
    "dhcp_inform",           // 15: DhcpInform
    "dhcp_nak",              // 16: DhcpNak
    "dhcp_offer",            // 17: DhcpOffer
    "dhcp_release",          // 18: DhcpRelease
    "dhcp_request",          // 19: DhcpRequest
    "noanswer",              // 20: NoAnswer
    "leases_allocated_4",    // 21: LeasesAllocated4
    "leases_pruned_4",       // 22: LeasesPruned4
    "leases_allocated_6",    // 23: LeasesAllocated6
    "leases_pruned_6",       // 24: LeasesPruned6
    "tcp_connections",       // 25: TcpConnections
    "dhcp_leasequery",       // 26: DhcpLeaseQuery
    "dhcp_lease_unassigned", // 27: DhcpLeaseUnassigned
    "dhcp_lease_actve",      // 28: DhcpLeaseActive — preserves C typo for backward compat
    "dhcp_lease_unknown",    // 29: DhcpLeaseUnknown
];

// ---------------------------------------------------------------------------
// MetricType enum
// ---------------------------------------------------------------------------

/// Metric type identifiers for all collectible performance metrics.
///
/// Replaces the C anonymous enum in `metrics.h` (lines 102–268).
/// Each variant maps to a counter in the [`MetricsStore`].
///
/// # Ordering
/// Enum ordering **must** match C ordering for compatibility. The explicit
/// `#[repr(u32)]` discriminant values correspond to array indices in
/// [`METRIC_NAMES`] and the [`MetricsStore`] counter array.
///
/// # Examples
/// ```
/// use dnsmasq::diagnostics::metrics::MetricType;
///
/// assert_eq!(MetricType::DnsQueriesForwarded.name(), "dns_queries_forwarded");
/// assert_eq!(MetricType::DhcpLeaseActive.name(), "dhcp_lease_actve"); // preserves C typo
/// assert_eq!(MetricType::DhcpLeaseUnknown as u32, 29);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum MetricType {
    /// DNS cache record successfully inserted into cache hash table.
    /// Tracks cache population rate and cache insertion throughput.
    /// Source: `cache.c` — `cache_insert()` operations.
    DnsCacheInserted = 0,

    /// DNS cache record evicted from cache while still within TTL (live eviction).
    /// Indicates cache pressure when LRU eviction removes valid entries.
    /// High values suggest cache size too small for query patterns.
    /// Source: `cache.c` — `cache_scan_free()`.
    DnsCacheLiveFreed = 1,

    /// DNS queries forwarded to upstream recursive DNS servers.
    /// Counts cache miss queries requiring upstream resolution.
    /// Ratio to total queries indicates cache effectiveness.
    /// Source: `forward.c` — `forward_query()` upstream forwarding.
    DnsQueriesForwarded = 2,

    /// DNS queries answered authoritatively from configured zones.
    /// Tracks authoritative DNS mode usage (`HAVE_AUTH`).
    /// Source: `auth.c` — authoritative zone query responses.
    DnsAuthAnswered = 3,

    /// DNS queries answered from local sources (`/etc/hosts`, static configuration).
    /// Includes responses from hosts file entries and manual address records.
    /// Source: `cache.c` and `forward.c` — local hostname resolution.
    DnsLocalAnswered = 4,

    /// DNS queries answered with stale cache entries beyond original TTL.
    /// Indicates serve-stale functionality providing expired cached responses.
    /// Source: `cache.c` — stale cache serving logic.
    DnsStaleAnswered = 5,

    /// DNS queries that could not be answered (NXDOMAIN or timeout).
    /// Tracks failed resolution attempts including upstream timeouts.
    /// High values may indicate upstream DNS problems or invalid query patterns.
    /// Source: `forward.c` — query timeout and NXDOMAIN handling.
    DnsUnansweredQuery = 6,

    /// DNSSEC cryptographic operations high-water mark (maximum observed).
    /// Tracks peak crypto operations during DNSSEC validation chains.
    /// Monitors resource limits: `DNSSEC_LIMIT_CRYPTO` (default 200).
    /// Source: `dnssec.c` — DNSSEC validation chain processing.
    CryptoHwm = 7,

    /// DNSSEC signature verification failures high-water mark.
    /// Maximum signature failures observed in single validation chain.
    /// Monitors resource limits: `DNSSEC_LIMIT_SIG_FAIL` (default 20).
    /// Source: `dnssec.c` — RRSIG signature verification.
    SigFailHwm = 8,

    /// DNSSEC validation work operations high-water mark.
    /// Maximum queries required for single DNSSEC validation chain.
    /// Monitors resource limits: `DNSSEC_LIMIT_WORK` (default 40).
    /// Source: `dnssec.c` — validation query tracking.
    WorkHwm = 9,

    /// BOOTP protocol requests processed.
    /// Counts legacy BOOTP (pre-DHCP) network boot requests.
    /// Source: `dhcp.c` — BOOTP message processing.
    Bootp = 10,

    /// PXE (Preboot Execution Environment) boot requests processed.
    /// Tracks network boot via PXE protocol (PXE proxy mode or integrated DHCP).
    /// Source: `dhcp.c` — PXE vendor class identifier detection.
    Pxe = 11,

    /// DHCPv4 ACK messages sent (address assignment confirmation).
    /// Successful DHCP lease grants: DISCOVER→OFFER→REQUEST→ACK sequence completion.
    /// Primary indicator of successful DHCP transactions.
    /// Source: `rfc2131.c` — DHCPACK message transmission.
    DhcpAck = 12,

    /// DHCPv4 DECLINE messages received from clients.
    /// Client detected IP address conflict via ARP and declined offered address.
    /// Indicates address pool conflicts requiring investigation.
    /// Source: `dhcp.c` — DHCPDECLINE message processing.
    DhcpDecline = 13,

    /// DHCPv4 DISCOVER messages received (initial address request).
    /// First phase of DHCP four-way handshake: client broadcasts discovery.
    /// Source: `rfc2131.c` — DHCPDISCOVER message processing.
    DhcpDiscover = 14,

    /// DHCPv4 INFORM messages received (configuration without address).
    /// Client has static IP but requests DHCP configuration options only.
    /// Source: `dhcp.c` — DHCPINFORM message processing.
    DhcpInform = 15,

    /// DHCPv4 NAK messages sent (address assignment rejection).
    /// Server rejects client REQUEST (wrong network, expired lease, etc.).
    /// Source: `rfc2131.c` — DHCPNAK message transmission.
    DhcpNak = 16,

    /// DHCPv4 OFFER messages sent (address offer to client).
    /// Second phase of DHCP handshake: server offers available address.
    /// Source: `rfc2131.c` — DHCPOFFER message transmission.
    DhcpOffer = 17,

    /// DHCPv4 RELEASE messages received (client relinquishes lease).
    /// Client explicitly releases IP address before lease expiration.
    /// Source: `dhcp.c` — DHCPRELEASE message processing.
    DhcpRelease = 18,

    /// DHCPv4 REQUEST messages received (address request/renewal).
    /// Third phase of DHCP handshake or lease renewal request.
    /// Source: `rfc2131.c` — DHCPREQUEST message processing.
    DhcpRequest = 19,

    /// Queries with no answer available (distinct from NXDOMAIN).
    /// Tracks queries that daemon cannot answer due to configuration or policy.
    /// Source: `forward.c` — query rejection paths.
    NoAnswer = 20,

    /// DHCPv4 leases allocated from dynamic address pools.
    /// Counts successful IPv4 address assignments (dynamic leases only).
    /// Tracks address pool utilization and capacity planning.
    /// Source: `dhcp.c` — `address_allocate()` for IPv4.
    LeasesAllocated4 = 21,

    /// DHCPv4 leases expired and pruned from lease database.
    /// Lease expiration cleanup and memory reclamation for IPv4.
    /// Source: `lease.c` — lease expiration processing.
    LeasesPruned4 = 22,

    /// DHCPv6 leases allocated from IPv6 address pools.
    /// Counts successful IPv6 address assignments (stateful DHCPv6).
    /// Source: `dhcp6.c` — IPv6 address allocation.
    LeasesAllocated6 = 23,

    /// DHCPv6 leases expired and pruned from lease database.
    /// Lease expiration cleanup and memory reclamation for IPv6.
    /// Source: `lease.c` — IPv6 lease expiration processing.
    LeasesPruned6 = 24,

    /// TCP connections established for DNS-over-TCP queries.
    /// Tracks TCP query volume (large responses, zone transfers, DNSSEC).
    /// High values may indicate need for larger UDP packet sizes.
    /// Source: `forward.c` — TCP connection establishment.
    TcpConnections = 25,

    /// DHCPv4 LEASEQUERY requests received (RFC 4388).
    /// External systems querying lease information by IP or MAC address.
    /// Source: `dhcp.c` — DHCPLEASEQUERY message processing.
    DhcpLeaseQuery = 26,

    /// DHCPv4 LEASEQUERY responses: lease unassigned (IP not in pool).
    /// LEASEQUERY query for IP address not within configured DHCP ranges.
    /// Source: `dhcp.c` — DHCPLEASEUNASSIGNED response generation.
    DhcpLeaseUnassigned = 27,

    /// DHCPv4 LEASEQUERY responses: lease active (IP currently leased).
    /// LEASEQUERY query returned active lease information.
    /// Source: `dhcp.c` — DHCPLEASEACTIVE response with lease details.
    DhcpLeaseActive = 28,

    /// DHCPv4 LEASEQUERY responses: lease unknown (no record found).
    /// LEASEQUERY query for IP/MAC with no matching lease database entry.
    /// Source: `dhcp.c` — DHCPLEASEUNKNOWN response generation.
    DhcpLeaseUnknown = 29,
}

/// Complete list of all [`MetricType`] variants in discriminant order.
///
/// Used by [`MetricType::all()`] to provide an iterator over all metric types.
/// Ordering matches C enum for compatibility.
const ALL_METRICS: [MetricType; METRIC_MAX] = [
    MetricType::DnsCacheInserted,
    MetricType::DnsCacheLiveFreed,
    MetricType::DnsQueriesForwarded,
    MetricType::DnsAuthAnswered,
    MetricType::DnsLocalAnswered,
    MetricType::DnsStaleAnswered,
    MetricType::DnsUnansweredQuery,
    MetricType::CryptoHwm,
    MetricType::SigFailHwm,
    MetricType::WorkHwm,
    MetricType::Bootp,
    MetricType::Pxe,
    MetricType::DhcpAck,
    MetricType::DhcpDecline,
    MetricType::DhcpDiscover,
    MetricType::DhcpInform,
    MetricType::DhcpNak,
    MetricType::DhcpOffer,
    MetricType::DhcpRelease,
    MetricType::DhcpRequest,
    MetricType::NoAnswer,
    MetricType::LeasesAllocated4,
    MetricType::LeasesPruned4,
    MetricType::LeasesAllocated6,
    MetricType::LeasesPruned6,
    MetricType::TcpConnections,
    MetricType::DhcpLeaseQuery,
    MetricType::DhcpLeaseUnassigned,
    MetricType::DhcpLeaseActive,
    MetricType::DhcpLeaseUnknown,
];

impl MetricType {
    /// Get the human-readable name string for this metric type.
    ///
    /// Replaces C `get_metric_name(int i)` (`metrics.c` lines 208–210).
    ///
    /// # Examples
    /// ```
    /// use dnsmasq::diagnostics::metrics::MetricType;
    ///
    /// assert_eq!(MetricType::DnsQueriesForwarded.name(), "dns_queries_forwarded");
    /// assert_eq!(MetricType::DhcpLeaseActive.name(), "dhcp_lease_actve"); // preserves C typo
    /// ```
    #[inline]
    pub fn name(&self) -> &'static str {
        METRIC_NAMES[*self as usize]
    }

    /// Convert a raw `u32` index to a [`MetricType`] variant.
    ///
    /// Returns `Some(MetricType)` if `value` is a valid discriminant
    /// (0 through [`METRIC_MAX`] − 1), or `None` for out-of-range values.
    ///
    /// # Examples
    /// ```
    /// use dnsmasq::diagnostics::metrics::MetricType;
    ///
    /// assert_eq!(MetricType::from_u32(0), Some(MetricType::DnsCacheInserted));
    /// assert_eq!(MetricType::from_u32(29), Some(MetricType::DhcpLeaseUnknown));
    /// assert_eq!(MetricType::from_u32(30), None);
    /// assert_eq!(MetricType::from_u32(u32::MAX), None);
    /// ```
    #[inline]
    pub fn from_u32(value: u32) -> Option<Self> {
        if (value as usize) < METRIC_MAX {
            Some(ALL_METRICS[value as usize])
        } else {
            None
        }
    }

    /// Return an iterator over all [`MetricType`] variants in discriminant order.
    ///
    /// Yields all 30 metric types from `DnsCacheInserted` (0) through
    /// `DhcpLeaseUnknown` (29), matching C enum ordering.
    ///
    /// # Examples
    /// ```
    /// use dnsmasq::diagnostics::metrics::MetricType;
    ///
    /// let all: Vec<MetricType> = MetricType::all().collect();
    /// assert_eq!(all.len(), 30);
    /// assert_eq!(all[0], MetricType::DnsCacheInserted);
    /// assert_eq!(all[29], MetricType::DhcpLeaseUnknown);
    /// ```
    #[inline]
    pub fn all() -> impl Iterator<Item = MetricType> {
        ALL_METRICS.iter().copied()
    }
}

impl fmt::Display for MetricType {
    /// Display the human-readable metric name.
    ///
    /// Delegates to [`MetricType::name()`] for the string representation.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// ---------------------------------------------------------------------------
// MetricsStore
// ---------------------------------------------------------------------------

/// Thread-safe runtime metrics store using atomic counters.
///
/// Replaces C `daemon->metrics[__METRIC_MAX]` (`u32` array, `dnsmasq.h`
/// line 1254).
///
/// # Thread Safety
/// Uses [`AtomicU64`] instead of C's `u32` for:
/// 1. **Thread safety** — Rust async runtime may use multiple threads
/// 2. **Larger counter range** — avoids `u32` overflow for high-traffic deployments
/// 3. **Lock-free concurrent access** — via atomic operations with [`Ordering::Relaxed`]
///
/// # Usage
/// ```
/// use dnsmasq::diagnostics::metrics::{MetricType, MetricsStore};
///
/// let store = MetricsStore::new();
///
/// // Increment a counter (replaces C: daemon->metrics[METRIC_DNS_QUERIES_FORWARDED]++)
/// store.increment(MetricType::DnsQueriesForwarded);
/// store.increment(MetricType::DnsQueriesForwarded);
/// assert_eq!(store.get(MetricType::DnsQueriesForwarded), 2);
///
/// // Set high-water mark (DNSSEC metrics)
/// store.set_max(MetricType::CryptoHwm, 42);
/// assert_eq!(store.get(MetricType::CryptoHwm), 42);
///
/// // Clear all counters
/// store.clear();
/// assert_eq!(store.get(MetricType::DnsQueriesForwarded), 0);
/// ```
pub struct MetricsStore {
    /// Atomic counter array indexed by [`MetricType`] discriminant.
    counters: [AtomicU64; METRIC_MAX],
}

impl MetricsStore {
    /// Create a new metrics store with all counters initialized to zero.
    ///
    /// # Examples
    /// ```
    /// use dnsmasq::diagnostics::metrics::{MetricType, MetricsStore};
    ///
    /// let store = MetricsStore::new();
    /// assert_eq!(store.get(MetricType::DnsCacheInserted), 0);
    /// ```
    pub fn new() -> Self {
        // Initialize all counters to zero. We use a const initializer to avoid
        // requiring a loop with AtomicU64 (which is not Copy).
        Self {
            counters: [
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
            ],
        }
    }

    /// Increment a metric counter by 1.
    ///
    /// Replaces the C pattern: `daemon->metrics[METRIC_X]++`
    ///
    /// Uses [`Ordering::Relaxed`] because metrics are informational only and
    /// do not participate in any synchronization protocol.
    ///
    /// # Examples
    /// ```
    /// use dnsmasq::diagnostics::metrics::{MetricType, MetricsStore};
    ///
    /// let store = MetricsStore::new();
    /// store.increment(MetricType::DhcpDiscover);
    /// assert_eq!(store.get(MetricType::DhcpDiscover), 1);
    /// ```
    #[inline]
    pub fn increment(&self, metric: MetricType) {
        self.counters[metric as usize].fetch_add(1, Ordering::Relaxed);
    }

    /// Set a metric to the maximum of its current value and the given value.
    ///
    /// Used by DNSSEC high-water mark metrics ([`MetricType::CryptoHwm`],
    /// [`MetricType::SigFailHwm`], [`MetricType::WorkHwm`]) that track the
    /// maximum values observed during operation.
    ///
    /// Uses [`AtomicU64::fetch_max`] with [`Ordering::Relaxed`] for lock-free
    /// atomic maximum computation.
    ///
    /// # Examples
    /// ```
    /// use dnsmasq::diagnostics::metrics::{MetricType, MetricsStore};
    ///
    /// let store = MetricsStore::new();
    /// store.set_max(MetricType::CryptoHwm, 100);
    /// assert_eq!(store.get(MetricType::CryptoHwm), 100);
    ///
    /// // Only increases: lower value is ignored
    /// store.set_max(MetricType::CryptoHwm, 50);
    /// assert_eq!(store.get(MetricType::CryptoHwm), 100);
    ///
    /// // Higher value replaces current
    /// store.set_max(MetricType::CryptoHwm, 200);
    /// assert_eq!(store.get(MetricType::CryptoHwm), 200);
    /// ```
    #[inline]
    pub fn set_max(&self, metric: MetricType, value: u64) {
        self.counters[metric as usize].fetch_max(value, Ordering::Relaxed);
    }

    /// Get current value of a metric counter.
    ///
    /// Uses [`Ordering::Relaxed`] because metrics are informational and
    /// do not participate in synchronization.
    ///
    /// # Examples
    /// ```
    /// use dnsmasq::diagnostics::metrics::{MetricType, MetricsStore};
    ///
    /// let store = MetricsStore::new();
    /// store.increment(MetricType::TcpConnections);
    /// assert_eq!(store.get(MetricType::TcpConnections), 1);
    /// ```
    #[inline]
    pub fn get(&self, metric: MetricType) -> u64 {
        self.counters[metric as usize].load(Ordering::Relaxed)
    }

    /// Get human-readable name for a metric type.
    ///
    /// Replaces C `get_metric_name(int i)` (`metrics.c` lines 208–210).
    /// This is a convenience associated function that delegates to
    /// [`MetricType::name()`].
    ///
    /// # Examples
    /// ```
    /// use dnsmasq::diagnostics::metrics::{MetricType, MetricsStore};
    ///
    /// assert_eq!(MetricsStore::get_name(MetricType::Bootp), "bootp");
    /// ```
    #[inline]
    pub fn get_name(metric: MetricType) -> &'static str {
        metric.name()
    }

    /// Reset all metric counters to zero.
    ///
    /// Replaces C `clear_metrics()` (`metrics.c` lines 297–314).
    ///
    /// **Note:** The C version also resets per-server statistics (queries,
    /// failed_queries, retrys, nxdomain_replies, query_latency). In Rust,
    /// per-server stats live in [`ServerStats`] instances owned by the
    /// server state structs and should be cleared separately via
    /// [`ServerStats::clear()`].
    ///
    /// # Examples
    /// ```
    /// use dnsmasq::diagnostics::metrics::{MetricType, MetricsStore};
    ///
    /// let store = MetricsStore::new();
    /// store.increment(MetricType::DhcpAck);
    /// store.increment(MetricType::DhcpOffer);
    /// store.set_max(MetricType::CryptoHwm, 99);
    ///
    /// store.clear();
    ///
    /// assert_eq!(store.get(MetricType::DhcpAck), 0);
    /// assert_eq!(store.get(MetricType::DhcpOffer), 0);
    /// assert_eq!(store.get(MetricType::CryptoHwm), 0);
    /// ```
    pub fn clear(&self) {
        for counter in &self.counters {
            counter.store(0, Ordering::Relaxed);
        }
    }

    /// Iterate over all metrics as `(name, value)` pairs.
    ///
    /// Yields each metric's human-readable name alongside its current counter
    /// value. Useful for D-Bus/UBus metric export, structured logging output,
    /// and monitoring system integration.
    ///
    /// The iteration order matches the C enum order (discriminant 0 through 29).
    ///
    /// # Examples
    /// ```
    /// use dnsmasq::diagnostics::metrics::{MetricType, MetricsStore};
    ///
    /// let store = MetricsStore::new();
    /// store.increment(MetricType::Pxe);
    ///
    /// let metrics: Vec<(&str, u64)> = store.iter().collect();
    /// assert_eq!(metrics.len(), 30);
    /// assert_eq!(metrics[11], ("pxe", 1)); // Pxe is at index 11
    /// ```
    pub fn iter(&self) -> impl Iterator<Item = (&'static str, u64)> + '_ {
        METRIC_NAMES
            .iter()
            .zip(self.counters.iter())
            .map(|(name, counter)| (*name, counter.load(Ordering::Relaxed)))
    }
}

impl Default for MetricsStore {
    /// Create a new [`MetricsStore`] with all counters initialized to zero.
    ///
    /// Equivalent to [`MetricsStore::new()`].
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for MetricsStore {
    /// Display all metrics in `name: value` format for logging.
    ///
    /// Outputs one line per metric, each formatted as `"metric_name: value"`.
    /// Useful for statistics dumps triggered by SIGUSR1/SIGUSR2 or
    /// administrative logging.
    ///
    /// # Examples
    /// ```
    /// use dnsmasq::diagnostics::metrics::{MetricType, MetricsStore};
    ///
    /// let store = MetricsStore::new();
    /// store.increment(MetricType::DnsQueriesForwarded);
    /// let output = format!("{}", store);
    /// assert!(output.contains("dns_queries_forwarded: 1"));
    /// ```
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for (name, value) in self.iter() {
            if !first {
                writeln!(f)?;
            }
            write!(f, "{name}: {value}")?;
            first = false;
        }
        Ok(())
    }
}

// MetricsStore is safe to share across threads because all its fields
// (AtomicU64) are themselves Sync + Send.
// SAFETY: AtomicU64 already implements Sync + Send. The compiler auto-derives
// these for MetricsStore since all fields are Sync + Send. We include the
// assertion here as documentation.
#[allow(dead_code)]
const _: () = {
    const fn assert_sync_send<T: Sync + Send>() {}
    assert_sync_send::<MetricsStore>();
};

// ---------------------------------------------------------------------------
// ServerStats
// ---------------------------------------------------------------------------

/// Per-upstream-server performance statistics.
///
/// Replaces C `struct server` fields: `queries`, `failed_queries`, `retrys`,
/// `nxdomain_replies`, `query_latency` (`metrics.c` lines 305–313).
///
/// These statistics are stored per upstream DNS server and are reset by
/// [`ServerStats::clear()`] (corresponding to the per-server reset loop in
/// C's `clear_metrics()`).
///
/// # Thread Safety
/// Uses [`AtomicU64`] with [`Ordering::Relaxed`] for all operations, matching
/// the lock-free increment pattern used in [`MetricsStore`].
///
/// # Examples
/// ```
/// use dnsmasq::diagnostics::metrics::ServerStats;
///
/// let stats = ServerStats::default();
/// stats.queries.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
/// stats.failed_queries.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
/// assert_eq!(stats.queries.load(std::sync::atomic::Ordering::Relaxed), 1);
///
/// stats.clear();
/// assert_eq!(stats.queries.load(std::sync::atomic::Ordering::Relaxed), 0);
/// assert_eq!(stats.failed_queries.load(std::sync::atomic::Ordering::Relaxed), 0);
/// ```
#[derive(Debug)]
pub struct ServerStats {
    /// Total queries sent to this upstream server.
    /// Replaces C `struct server::queries`.
    pub queries: AtomicU64,

    /// Queries that failed (timeout, connection refused, etc.).
    /// Replaces C `struct server::failed_queries`.
    pub failed_queries: AtomicU64,

    /// Query retry attempts after initial failure.
    /// Replaces C `struct server::retrys` (note: C field name preserves
    /// non-standard spelling; Rust uses `retries` for clarity).
    pub retries: AtomicU64,

    /// NXDOMAIN responses received from this server.
    /// Replaces C `struct server::nxdomain_replies`.
    pub nxdomain_replies: AtomicU64,

    /// Accumulated query response latency in microseconds.
    /// Used for average latency calculation: `query_latency / queries`.
    /// Replaces C `struct server::query_latency`.
    pub query_latency: AtomicU64,
}

impl ServerStats {
    /// Reset all server statistics to zero.
    ///
    /// Replaces the per-server reset loop in C `clear_metrics()`
    /// (`metrics.c` lines 305–313).
    ///
    /// # Examples
    /// ```
    /// use dnsmasq::diagnostics::metrics::ServerStats;
    /// use std::sync::atomic::Ordering;
    ///
    /// let stats = ServerStats::default();
    /// stats.queries.store(100, Ordering::Relaxed);
    /// stats.failed_queries.store(5, Ordering::Relaxed);
    /// stats.retries.store(3, Ordering::Relaxed);
    /// stats.nxdomain_replies.store(10, Ordering::Relaxed);
    /// stats.query_latency.store(50000, Ordering::Relaxed);
    ///
    /// stats.clear();
    ///
    /// assert_eq!(stats.queries.load(Ordering::Relaxed), 0);
    /// assert_eq!(stats.failed_queries.load(Ordering::Relaxed), 0);
    /// assert_eq!(stats.retries.load(Ordering::Relaxed), 0);
    /// assert_eq!(stats.nxdomain_replies.load(Ordering::Relaxed), 0);
    /// assert_eq!(stats.query_latency.load(Ordering::Relaxed), 0);
    /// ```
    pub fn clear(&self) {
        self.queries.store(0, Ordering::Relaxed);
        self.failed_queries.store(0, Ordering::Relaxed);
        self.retries.store(0, Ordering::Relaxed);
        self.nxdomain_replies.store(0, Ordering::Relaxed);
        self.query_latency.store(0, Ordering::Relaxed);
    }
}

impl Default for ServerStats {
    /// Create a new [`ServerStats`] with all counters initialized to zero.
    fn default() -> Self {
        Self {
            queries: AtomicU64::new(0),
            failed_queries: AtomicU64::new(0),
            retries: AtomicU64::new(0),
            nxdomain_replies: AtomicU64::new(0),
            query_latency: AtomicU64::new(0),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metric_max_matches_enum_count() {
        assert_eq!(METRIC_MAX, 30);
        assert_eq!(ALL_METRICS.len(), METRIC_MAX);
        assert_eq!(METRIC_NAMES.len(), METRIC_MAX);
    }

    #[test]
    fn test_metric_type_discriminants() {
        assert_eq!(MetricType::DnsCacheInserted as u32, 0);
        assert_eq!(MetricType::DnsCacheLiveFreed as u32, 1);
        assert_eq!(MetricType::DnsQueriesForwarded as u32, 2);
        assert_eq!(MetricType::DnsAuthAnswered as u32, 3);
        assert_eq!(MetricType::DnsLocalAnswered as u32, 4);
        assert_eq!(MetricType::DnsStaleAnswered as u32, 5);
        assert_eq!(MetricType::DnsUnansweredQuery as u32, 6);
        assert_eq!(MetricType::CryptoHwm as u32, 7);
        assert_eq!(MetricType::SigFailHwm as u32, 8);
        assert_eq!(MetricType::WorkHwm as u32, 9);
        assert_eq!(MetricType::Bootp as u32, 10);
        assert_eq!(MetricType::Pxe as u32, 11);
        assert_eq!(MetricType::DhcpAck as u32, 12);
        assert_eq!(MetricType::DhcpDecline as u32, 13);
        assert_eq!(MetricType::DhcpDiscover as u32, 14);
        assert_eq!(MetricType::DhcpInform as u32, 15);
        assert_eq!(MetricType::DhcpNak as u32, 16);
        assert_eq!(MetricType::DhcpOffer as u32, 17);
        assert_eq!(MetricType::DhcpRelease as u32, 18);
        assert_eq!(MetricType::DhcpRequest as u32, 19);
        assert_eq!(MetricType::NoAnswer as u32, 20);
        assert_eq!(MetricType::LeasesAllocated4 as u32, 21);
        assert_eq!(MetricType::LeasesPruned4 as u32, 22);
        assert_eq!(MetricType::LeasesAllocated6 as u32, 23);
        assert_eq!(MetricType::LeasesPruned6 as u32, 24);
        assert_eq!(MetricType::TcpConnections as u32, 25);
        assert_eq!(MetricType::DhcpLeaseQuery as u32, 26);
        assert_eq!(MetricType::DhcpLeaseUnassigned as u32, 27);
        assert_eq!(MetricType::DhcpLeaseActive as u32, 28);
        assert_eq!(MetricType::DhcpLeaseUnknown as u32, 29);
    }

    #[test]
    fn test_metric_names_match_c() {
        // Verify exact string values from C metric_names[] (metrics.c lines 123-154)
        assert_eq!(METRIC_NAMES[0], "dns_cache_inserted");
        assert_eq!(METRIC_NAMES[1], "dns_cache_live_freed");
        assert_eq!(METRIC_NAMES[2], "dns_queries_forwarded");
        assert_eq!(METRIC_NAMES[3], "dns_auth_answered");
        assert_eq!(METRIC_NAMES[4], "dns_local_answered");
        assert_eq!(METRIC_NAMES[5], "dns_stale_answered");
        assert_eq!(METRIC_NAMES[6], "dns_unanswered");
        assert_eq!(METRIC_NAMES[7], "dnssec_max_crypto_use");
        assert_eq!(METRIC_NAMES[8], "dnssec_max_sig_fail");
        assert_eq!(METRIC_NAMES[9], "dnssec_max_work");
        assert_eq!(METRIC_NAMES[10], "bootp");
        assert_eq!(METRIC_NAMES[11], "pxe");
        assert_eq!(METRIC_NAMES[12], "dhcp_ack");
        assert_eq!(METRIC_NAMES[13], "dhcp_decline");
        assert_eq!(METRIC_NAMES[14], "dhcp_discover");
        assert_eq!(METRIC_NAMES[15], "dhcp_inform");
        assert_eq!(METRIC_NAMES[16], "dhcp_nak");
        assert_eq!(METRIC_NAMES[17], "dhcp_offer");
        assert_eq!(METRIC_NAMES[18], "dhcp_release");
        assert_eq!(METRIC_NAMES[19], "dhcp_request");
        assert_eq!(METRIC_NAMES[20], "noanswer");
        assert_eq!(METRIC_NAMES[21], "leases_allocated_4");
        assert_eq!(METRIC_NAMES[22], "leases_pruned_4");
        assert_eq!(METRIC_NAMES[23], "leases_allocated_6");
        assert_eq!(METRIC_NAMES[24], "leases_pruned_6");
        assert_eq!(METRIC_NAMES[25], "tcp_connections");
        assert_eq!(METRIC_NAMES[26], "dhcp_leasequery");
        assert_eq!(METRIC_NAMES[27], "dhcp_lease_unassigned");
        // CRITICAL: preserves C typo "actve" for backward compatibility
        assert_eq!(METRIC_NAMES[28], "dhcp_lease_actve");
        assert_eq!(METRIC_NAMES[29], "dhcp_lease_unknown");
    }

    #[test]
    fn test_metric_type_name() {
        assert_eq!(MetricType::DnsCacheInserted.name(), "dns_cache_inserted");
        assert_eq!(
            MetricType::DnsQueriesForwarded.name(),
            "dns_queries_forwarded"
        );
        assert_eq!(MetricType::DhcpLeaseActive.name(), "dhcp_lease_actve");
        assert_eq!(MetricType::DhcpLeaseUnknown.name(), "dhcp_lease_unknown");
    }

    #[test]
    fn test_metric_type_from_u32() {
        assert_eq!(MetricType::from_u32(0), Some(MetricType::DnsCacheInserted));
        assert_eq!(MetricType::from_u32(12), Some(MetricType::DhcpAck));
        assert_eq!(MetricType::from_u32(29), Some(MetricType::DhcpLeaseUnknown));
        assert_eq!(MetricType::from_u32(30), None);
        assert_eq!(MetricType::from_u32(u32::MAX), None);
    }

    #[test]
    fn test_metric_type_all() {
        let all: Vec<MetricType> = MetricType::all().collect();
        assert_eq!(all.len(), METRIC_MAX);
        assert_eq!(all[0], MetricType::DnsCacheInserted);
        assert_eq!(all[29], MetricType::DhcpLeaseUnknown);

        // Verify each variant's discriminant matches its position
        for (i, metric) in all.iter().enumerate() {
            assert_eq!(*metric as usize, i);
        }
    }

    #[test]
    fn test_metric_type_display() {
        assert_eq!(format!("{}", MetricType::Bootp), "bootp");
        assert_eq!(format!("{}", MetricType::Pxe), "pxe");
        assert_eq!(format!("{}", MetricType::DhcpAck), "dhcp_ack");
    }

    #[test]
    fn test_metrics_store_new() {
        let store = MetricsStore::new();
        for metric in MetricType::all() {
            assert_eq!(
                store.get(metric),
                0,
                "Metric {:?} should be 0 on init",
                metric
            );
        }
    }

    #[test]
    fn test_metrics_store_increment() {
        let store = MetricsStore::new();
        store.increment(MetricType::DnsQueriesForwarded);
        store.increment(MetricType::DnsQueriesForwarded);
        store.increment(MetricType::DnsQueriesForwarded);
        assert_eq!(store.get(MetricType::DnsQueriesForwarded), 3);

        // Other counters unaffected
        assert_eq!(store.get(MetricType::DnsCacheInserted), 0);
    }

    #[test]
    fn test_metrics_store_set_max() {
        let store = MetricsStore::new();

        store.set_max(MetricType::CryptoHwm, 100);
        assert_eq!(store.get(MetricType::CryptoHwm), 100);

        // Lower value should not decrease
        store.set_max(MetricType::CryptoHwm, 50);
        assert_eq!(store.get(MetricType::CryptoHwm), 100);

        // Higher value should increase
        store.set_max(MetricType::CryptoHwm, 200);
        assert_eq!(store.get(MetricType::CryptoHwm), 200);
    }

    #[test]
    fn test_metrics_store_clear() {
        let store = MetricsStore::new();
        store.increment(MetricType::DhcpAck);
        store.increment(MetricType::DhcpOffer);
        store.set_max(MetricType::CryptoHwm, 99);

        store.clear();

        for metric in MetricType::all() {
            assert_eq!(
                store.get(metric),
                0,
                "Metric {:?} should be 0 after clear",
                metric
            );
        }
    }

    #[test]
    fn test_metrics_store_get_name() {
        assert_eq!(MetricsStore::get_name(MetricType::Bootp), "bootp");
        assert_eq!(
            MetricsStore::get_name(MetricType::DhcpLeaseActive),
            "dhcp_lease_actve"
        );
    }

    #[test]
    fn test_metrics_store_iter() {
        let store = MetricsStore::new();
        store.increment(MetricType::Pxe);
        store.increment(MetricType::TcpConnections);
        store.increment(MetricType::TcpConnections);

        let metrics: Vec<(&str, u64)> = store.iter().collect();
        assert_eq!(metrics.len(), METRIC_MAX);

        // Check specific values
        assert_eq!(metrics[11], ("pxe", 1));
        assert_eq!(metrics[25], ("tcp_connections", 2));

        // All others should be 0
        assert_eq!(metrics[0], ("dns_cache_inserted", 0));
    }

    #[test]
    fn test_metrics_store_default() {
        let store = MetricsStore::default();
        for metric in MetricType::all() {
            assert_eq!(store.get(metric), 0);
        }
    }

    #[test]
    fn test_metrics_store_display() {
        let store = MetricsStore::new();
        store.increment(MetricType::DnsQueriesForwarded);
        let output = format!("{}", store);

        // Should contain all 30 metric lines
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), METRIC_MAX);

        // First line should be dns_cache_inserted: 0
        assert_eq!(lines[0], "dns_cache_inserted: 0");

        // dns_queries_forwarded should show 1
        assert_eq!(lines[2], "dns_queries_forwarded: 1");
    }

    #[test]
    fn test_server_stats_default() {
        let stats = ServerStats::default();
        assert_eq!(stats.queries.load(Ordering::Relaxed), 0);
        assert_eq!(stats.failed_queries.load(Ordering::Relaxed), 0);
        assert_eq!(stats.retries.load(Ordering::Relaxed), 0);
        assert_eq!(stats.nxdomain_replies.load(Ordering::Relaxed), 0);
        assert_eq!(stats.query_latency.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_server_stats_clear() {
        let stats = ServerStats::default();
        stats.queries.store(100, Ordering::Relaxed);
        stats.failed_queries.store(5, Ordering::Relaxed);
        stats.retries.store(3, Ordering::Relaxed);
        stats.nxdomain_replies.store(10, Ordering::Relaxed);
        stats.query_latency.store(50_000, Ordering::Relaxed);

        stats.clear();

        assert_eq!(stats.queries.load(Ordering::Relaxed), 0);
        assert_eq!(stats.failed_queries.load(Ordering::Relaxed), 0);
        assert_eq!(stats.retries.load(Ordering::Relaxed), 0);
        assert_eq!(stats.nxdomain_replies.load(Ordering::Relaxed), 0);
        assert_eq!(stats.query_latency.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_metric_type_roundtrip() {
        // Verify from_u32 roundtrip for all variants
        for metric in MetricType::all() {
            let value = metric as u32;
            let recovered = MetricType::from_u32(value);
            assert_eq!(recovered, Some(metric));
        }
    }

    #[test]
    fn test_metric_name_consistency() {
        // Verify name() matches METRIC_NAMES for all variants
        for metric in MetricType::all() {
            let idx = metric as usize;
            assert_eq!(metric.name(), METRIC_NAMES[idx]);
        }
    }

    // =========================================================================
    // Additional coverage tests
    // =========================================================================

    #[test]
    fn test_increment_all_metrics() {
        let store = MetricsStore::new();
        for metric in MetricType::all() {
            store.increment(metric);
            assert_eq!(store.get(metric), 1, "Metric {:?} should be 1", metric);
        }
        // Verify all are at 1
        for metric in MetricType::all() {
            assert_eq!(store.get(metric), 1);
        }
    }

    #[test]
    fn test_increment_overflow_behavior() {
        let store = MetricsStore::new();
        // Increment many times, verify count
        for _ in 0..1000 {
            store.increment(MetricType::DnsQueriesForwarded);
        }
        assert_eq!(store.get(MetricType::DnsQueriesForwarded), 1000);
    }

    #[test]
    fn test_set_max_from_zero() {
        let store = MetricsStore::new();
        store.set_max(MetricType::SigFailHwm, 0);
        assert_eq!(store.get(MetricType::SigFailHwm), 0);
        store.set_max(MetricType::SigFailHwm, 1);
        assert_eq!(store.get(MetricType::SigFailHwm), 1);
    }

    #[test]
    fn test_set_max_all_hwm_metrics() {
        let store = MetricsStore::new();
        let hwm_metrics = [
            MetricType::CryptoHwm,
            MetricType::SigFailHwm,
            MetricType::WorkHwm,
        ];
        for metric in hwm_metrics {
            store.set_max(metric, 50);
            assert_eq!(store.get(metric), 50);
            store.set_max(metric, 10);
            assert_eq!(store.get(metric), 50); // Doesn't decrease
            store.set_max(metric, 100);
            assert_eq!(store.get(metric), 100);
        }
    }

    #[test]
    fn test_set_max_u64_max() {
        let store = MetricsStore::new();
        store.set_max(MetricType::WorkHwm, u64::MAX);
        assert_eq!(store.get(MetricType::WorkHwm), u64::MAX);
        // Still can't increase past u64::MAX
        store.set_max(MetricType::WorkHwm, 1);
        assert_eq!(store.get(MetricType::WorkHwm), u64::MAX);
    }

    #[test]
    fn test_clear_then_increment() {
        let store = MetricsStore::new();
        store.increment(MetricType::DhcpDiscover);
        store.increment(MetricType::DhcpDiscover);
        store.clear();
        assert_eq!(store.get(MetricType::DhcpDiscover), 0);
        store.increment(MetricType::DhcpDiscover);
        assert_eq!(store.get(MetricType::DhcpDiscover), 1);
    }

    #[test]
    fn test_multiple_clear() {
        let store = MetricsStore::new();
        store.increment(MetricType::Bootp);
        store.clear();
        store.clear(); // Double-clear should be safe
        assert_eq!(store.get(MetricType::Bootp), 0);
    }

    #[test]
    fn test_iter_count_always_30() {
        let store = MetricsStore::new();
        assert_eq!(store.iter().count(), 30);
        store.increment(MetricType::DhcpAck);
        assert_eq!(store.iter().count(), 30);
        store.clear();
        assert_eq!(store.iter().count(), 30);
    }

    #[test]
    fn test_iter_names_order() {
        let store = MetricsStore::new();
        let names: Vec<&str> = store.iter().map(|(name, _)| name).collect();
        assert_eq!(names[0], "dns_cache_inserted");
        assert_eq!(names[29], "dhcp_lease_unknown");
        // Verify order matches ALL_METRICS
        for (i, metric) in MetricType::all().enumerate() {
            assert_eq!(names[i], metric.name());
        }
    }

    #[test]
    fn test_display_all_zeros() {
        let store = MetricsStore::new();
        let output = format!("{}", store);
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 30);
        for line in &lines {
            assert!(line.ends_with(": 0"), "Expected all zeros, got: {}", line);
        }
    }

    #[test]
    fn test_display_with_mixed_values() {
        let store = MetricsStore::new();
        store.increment(MetricType::DhcpDiscover);
        store.increment(MetricType::DhcpDiscover);
        store.increment(MetricType::DhcpOffer);
        store.increment(MetricType::DhcpRequest);
        store.increment(MetricType::DhcpAck);
        store.set_max(MetricType::CryptoHwm, 42);

        let output = format!("{}", store);
        assert!(output.contains("dhcp_discover: 2"));
        assert!(output.contains("dhcp_offer: 1"));
        assert!(output.contains("dhcp_request: 1"));
        assert!(output.contains("dhcp_ack: 1"));
        assert!(output.contains("dnssec_max_crypto_use: 42"));
    }

    #[test]
    fn test_metric_type_display_all() {
        for metric in MetricType::all() {
            let display = format!("{}", metric);
            let name = metric.name();
            assert_eq!(display, name, "Display mismatch for {:?}", metric);
        }
    }

    #[test]
    fn test_from_u32_boundary() {
        assert!(MetricType::from_u32(0).is_some());
        assert!(MetricType::from_u32(29).is_some());
        assert!(MetricType::from_u32(30).is_none());
        assert!(MetricType::from_u32(100).is_none());
        assert!(MetricType::from_u32(u32::MAX).is_none());
    }

    #[test]
    fn test_server_stats_increment_and_read() {
        let stats = ServerStats::default();
        stats.queries.fetch_add(10, Ordering::Relaxed);
        stats.failed_queries.fetch_add(2, Ordering::Relaxed);
        stats.retries.fetch_add(3, Ordering::Relaxed);
        stats.nxdomain_replies.fetch_add(4, Ordering::Relaxed);
        stats.query_latency.fetch_add(5000, Ordering::Relaxed);

        assert_eq!(stats.queries.load(Ordering::Relaxed), 10);
        assert_eq!(stats.failed_queries.load(Ordering::Relaxed), 2);
        assert_eq!(stats.retries.load(Ordering::Relaxed), 3);
        assert_eq!(stats.nxdomain_replies.load(Ordering::Relaxed), 4);
        assert_eq!(stats.query_latency.load(Ordering::Relaxed), 5000);
    }

    #[test]
    fn test_server_stats_debug() {
        let stats = ServerStats::default();
        stats.queries.store(42, Ordering::Relaxed);
        let debug_str = format!("{:?}", stats);
        assert!(debug_str.contains("42"));
    }

    #[test]
    fn test_server_stats_latency_accumulation() {
        let stats = ServerStats::default();
        stats.query_latency.fetch_add(100, Ordering::Relaxed);
        stats.query_latency.fetch_add(200, Ordering::Relaxed);
        stats.query_latency.fetch_add(300, Ordering::Relaxed);
        assert_eq!(stats.query_latency.load(Ordering::Relaxed), 600);
    }

    #[test]
    fn test_server_stats_clear_after_accumulation() {
        let stats = ServerStats::default();
        for _ in 0..100 {
            stats.queries.fetch_add(1, Ordering::Relaxed);
        }
        assert_eq!(stats.queries.load(Ordering::Relaxed), 100);
        stats.clear();
        assert_eq!(stats.queries.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_metric_type_dhcp_lifecycle() {
        // Verify all DHCP-related metrics exist and are properly named
        let dhcp_metrics = [
            (MetricType::DhcpDiscover, "dhcp_discover"),
            (MetricType::DhcpOffer, "dhcp_offer"),
            (MetricType::DhcpRequest, "dhcp_request"),
            (MetricType::DhcpAck, "dhcp_ack"),
            (MetricType::DhcpNak, "dhcp_nak"),
            (MetricType::DhcpDecline, "dhcp_decline"),
            (MetricType::DhcpRelease, "dhcp_release"),
            (MetricType::DhcpInform, "dhcp_inform"),
        ];
        for (metric, expected_name) in dhcp_metrics {
            assert_eq!(metric.name(), expected_name);
        }
    }

    #[test]
    fn test_metric_type_dns_metrics() {
        let dns_metrics = [
            (MetricType::DnsCacheInserted, "dns_cache_inserted"),
            (MetricType::DnsCacheLiveFreed, "dns_cache_live_freed"),
            (MetricType::DnsQueriesForwarded, "dns_queries_forwarded"),
            (MetricType::DnsAuthAnswered, "dns_auth_answered"),
            (MetricType::DnsLocalAnswered, "dns_local_answered"),
            (MetricType::DnsStaleAnswered, "dns_stale_answered"),
            (MetricType::DnsUnansweredQuery, "dns_unanswered"),
        ];
        for (metric, expected_name) in dns_metrics {
            assert_eq!(metric.name(), expected_name);
        }
    }

    #[test]
    fn test_metric_type_lease_metrics() {
        let lease_metrics = [
            (MetricType::LeasesAllocated4, "leases_allocated_4"),
            (MetricType::LeasesPruned4, "leases_pruned_4"),
            (MetricType::LeasesAllocated6, "leases_allocated_6"),
            (MetricType::LeasesPruned6, "leases_pruned_6"),
            (MetricType::DhcpLeaseQuery, "dhcp_leasequery"),
            (MetricType::DhcpLeaseUnassigned, "dhcp_lease_unassigned"),
            (MetricType::DhcpLeaseActive, "dhcp_lease_actve"),
            (MetricType::DhcpLeaseUnknown, "dhcp_lease_unknown"),
        ];
        for (metric, expected_name) in lease_metrics {
            assert_eq!(metric.name(), expected_name);
        }
    }

    #[test]
    fn test_metrics_store_get_name_all() {
        for metric in MetricType::all() {
            let name = MetricsStore::get_name(metric);
            assert!(
                !name.is_empty(),
                "Name should not be empty for {:?}",
                metric
            );
            assert_eq!(name, metric.name());
        }
    }

    #[test]
    fn test_metrics_store_independence() {
        // Verify incrementing one metric doesn't affect others
        let store = MetricsStore::new();
        store.increment(MetricType::TcpConnections);
        for metric in MetricType::all() {
            if metric == MetricType::TcpConnections {
                assert_eq!(store.get(metric), 1);
            } else {
                assert_eq!(store.get(metric), 0, "Metric {:?} should be 0", metric);
            }
        }
    }

    #[test]
    fn test_all_metrics_constant_matches_all_iter() {
        let from_const: Vec<MetricType> = ALL_METRICS.to_vec();
        let from_iter: Vec<MetricType> = MetricType::all().collect();
        assert_eq!(from_const, from_iter);
    }

    #[test]
    fn test_metric_names_no_empty_strings() {
        for name in METRIC_NAMES {
            assert!(!name.is_empty(), "Found empty metric name");
            assert!(
                !name.contains(' '),
                "Metric name '{}' contains spaces",
                name
            );
        }
    }

    #[test]
    fn test_store_iter_after_mixed_operations() {
        let store = MetricsStore::new();
        store.increment(MetricType::Pxe);
        store.increment(MetricType::Pxe);
        store.set_max(MetricType::CryptoHwm, 77);
        store.increment(MetricType::NoAnswer);

        let collected: Vec<(_, _)> = store.iter().collect();
        assert_eq!(collected[MetricType::Pxe as usize].1, 2);
        assert_eq!(collected[MetricType::CryptoHwm as usize].1, 77);
        assert_eq!(collected[MetricType::NoAnswer as usize].1, 1);
    }
}

//! Metric definitions, naming, and management for dnsmasq.
//!
//! This module defines all 29 metric types tracked by the daemon, their human-readable
//! names for D-Bus/UBus export, and reset functionality. It replaces the C
//! `metrics.c` (metric_names[] array + clear_metrics()) and `metrics.h` (enum definition).
//!
//! ## Architecture
//! - C integer enum → Rust `Metric` enum with `#[repr(u32)]`
//! - C `metric_names[]` string array → Rust `Metric::name()` method
//! - C `daemon->metrics[__METRIC_MAX]` → Rust `MetricsStore` with fixed-size array
//! - C `clear_metrics()` zeroing daemon->metrics + per-server stats → `MetricsStore::clear()`
//!
//! ## Usage
//! ```ignore
//! use crate::core::metrics::{Metric, MetricsStore};
//!
//! let mut store = MetricsStore::new();
//! store.increment(Metric::DnsQueriesForwarded);
//! assert_eq!(store.get(Metric::DnsQueriesForwarded), 1);
//! store.clear();
//! assert_eq!(store.get(Metric::DnsQueriesForwarded), 0);
//! ```
//!
//! ## Thread Safety
//! Single-threaded architecture: No locking required for metric counter increments.
//! All metric operations are lock-free integer operations in the main event loop.
//! The `MetricsStore` is wrapped in a `RefCell` in `DaemonState` for interior mutability.

/// All metric types tracked by the dnsmasq daemon.
///
/// This enum provides type-safe metric identifiers replacing the C integer enum
/// from `src/metrics.h`. Each variant corresponds to a specific operational event
/// counter used for monitoring, diagnostics, and export via D-Bus/UBus interfaces.
///
/// The `#[repr(u32)]` attribute preserves index compatibility with the C implementation,
/// enabling efficient array-based storage in [`MetricsStore`].
///
/// ## Metric Categories
/// - **DNS Cache:** `DnsCacheInserted`, `DnsCacheLiveFreed`
/// - **DNS Queries:** `DnsQueriesForwarded`, `DnsAuthAnswered`, `DnsLocalAnswered`,
///   `DnsStaleAnswered`, `DnsUnanswered`
/// - **Network Boot:** `Bootp`, `Pxe`
/// - **DHCPv4 Messages:** `DhcpAck`, `DhcpDecline`, `DhcpDiscover`, `DhcpInform`,
///   `DhcpNak`, `DhcpOffer`, `DhcpRelease`, `DhcpRequest`
/// - **General:** `NoAnswer`
/// - **DHCP Leases:** `LeasesAllocated4`, `LeasesPruned4`, `LeasesAllocated6`, `LeasesPruned6`
/// - **TCP:** `TcpConnections`
/// - **DNSSEC HWM:** `DnssecMaxCryptoUse`, `DnssecMaxSigFail`, `DnssecMaxWork`
/// - **Leasequery:** `DnsQueriesLeasequery`, `DnsQueriesLeasequeryAnswered`,
///   `DnsQueriesLeasequeryRefused`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum Metric {
    /// DNS cache record successfully inserted into cache hash table.
    /// Tracks cache population rate and insertion throughput.
    /// Source: cache.c cache_insert() operations.
    DnsCacheInserted = 0,

    /// DNS cache record evicted while still within TTL (live eviction).
    /// Indicates cache pressure when LRU eviction removes valid entries.
    /// High values suggest cache size too small for query patterns.
    DnsCacheLiveFreed = 1,

    /// DNS queries forwarded to upstream recursive DNS servers.
    /// Counts cache miss queries requiring upstream resolution.
    /// Ratio to total queries indicates cache effectiveness.
    DnsQueriesForwarded = 2,

    /// DNS queries answered authoritatively from configured zones.
    /// Tracks authoritative DNS mode usage (auth feature).
    DnsAuthAnswered = 3,

    /// DNS queries answered from local sources (/etc/hosts, static configuration).
    /// Includes responses from hosts file entries and manual address records.
    DnsLocalAnswered = 4,

    /// DNS queries answered with stale cache entries beyond original TTL.
    /// Indicates serve-stale functionality providing expired cached responses.
    DnsStaleAnswered = 5,

    /// DNS queries that could not be answered (NXDOMAIN or timeout).
    /// Tracks failed resolution attempts including upstream timeouts.
    /// High values may indicate upstream DNS problems or invalid query patterns.
    DnsUnanswered = 6,

    /// BOOTP protocol requests processed.
    /// Counts legacy BOOTP (pre-DHCP) network boot requests.
    Bootp = 7,

    /// PXE (Preboot Execution Environment) boot requests processed.
    /// Tracks network boot via PXE protocol.
    Pxe = 8,

    /// DHCPv4 ACK messages sent (address assignment confirmation).
    /// Primary indicator of successful DHCP transactions.
    DhcpAck = 9,

    /// DHCPv4 DECLINE messages received from clients.
    /// Client detected IP address conflict via ARP and declined offered address.
    DhcpDecline = 10,

    /// DHCPv4 DISCOVER messages received (initial address request).
    /// First phase of DHCP four-way handshake.
    DhcpDiscover = 11,

    /// DHCPv4 INFORM messages received (configuration without address).
    /// Client has static IP but requests DHCP configuration options only.
    DhcpInform = 12,

    /// DHCPv4 NAK messages sent (address assignment rejection).
    /// Server rejects client REQUEST (wrong network, expired lease, etc.).
    DhcpNak = 13,

    /// DHCPv4 OFFER messages sent (address offer to client).
    /// Second phase of DHCP handshake.
    DhcpOffer = 14,

    /// DHCPv4 RELEASE messages received (client relinquishes lease).
    /// Client explicitly releases IP address before lease expiration.
    DhcpRelease = 15,

    /// DHCPv4 REQUEST messages received (address request/renewal).
    /// Third phase of DHCP handshake or lease renewal request.
    DhcpRequest = 16,

    /// Queries with no answer available (distinct from NXDOMAIN).
    /// Tracks queries that daemon cannot answer due to configuration or policy.
    NoAnswer = 17,

    /// DHCPv4 leases allocated from dynamic address pools.
    /// Counts successful IPv4 address assignments (dynamic leases only).
    LeasesAllocated4 = 18,

    /// DHCPv4 leases expired and pruned from lease database.
    /// Lease expiration cleanup and memory reclamation for IPv4.
    LeasesPruned4 = 19,

    /// DHCPv6 leases allocated from IPv6 address pools.
    /// Counts successful IPv6 address assignments (stateful DHCPv6).
    LeasesAllocated6 = 20,

    /// DHCPv6 leases expired and pruned from lease database.
    /// Lease expiration cleanup and memory reclamation for IPv6.
    LeasesPruned6 = 21,

    /// TCP connections established for DNS-over-TCP queries.
    /// Tracks TCP query volume (large responses, zone transfers, DNSSEC).
    TcpConnections = 22,

    /// DNSSEC cryptographic operations high-water mark (maximum observed).
    /// Tracks peak crypto operations during DNSSEC validation chains.
    /// Monitors resource limits: DNSSEC_LIMIT_CRYPTO (default 200).
    DnssecMaxCryptoUse = 23,

    /// DNSSEC signature verification failures high-water mark.
    /// Maximum signature failures observed in single validation chain.
    /// Monitors resource limits: DNSSEC_LIMIT_SIG_FAIL (default 20).
    DnssecMaxSigFail = 24,

    /// DNSSEC validation work operations high-water mark.
    /// Maximum queries required for single DNSSEC validation chain.
    /// Monitors resource limits: DNSSEC_LIMIT_WORK (default 40).
    DnssecMaxWork = 25,

    /// DHCPv4 LEASEQUERY requests received (RFC 4388).
    /// External systems querying lease information by IP or MAC address.
    DnsQueriesLeasequery = 26,

    /// DHCPv4 LEASEQUERY responses: lease query answered.
    /// LEASEQUERY query returned information about queried lease.
    DnsQueriesLeasequeryAnswered = 27,

    /// DHCPv4 LEASEQUERY responses: lease query refused.
    /// LEASEQUERY query could not be fulfilled (unknown, unauthorized, etc.).
    DnsQueriesLeasequeryRefused = 28,
}

/// Total number of defined metrics, replacing C `__METRIC_MAX` sentinel.
/// Used to size the `MetricsStore::counters` array and validate metric IDs.
impl Metric {
    /// Total number of metric variants (replacing C `__METRIC_MAX`).
    ///
    /// This constant is used to size arrays and validate index bounds.
    /// It equals the number of variants in the `Metric` enum.
    pub const COUNT: usize = 29;

    /// Returns the human-readable name string for this metric.
    ///
    /// These names are used by D-Bus/UBus control interfaces for metric export,
    /// syslog message formatting, and administrative display. They follow the
    /// convention of lowercase with underscores separating words.
    ///
    /// # Examples
    /// ```ignore
    /// assert_eq!(Metric::DnsCacheInserted.name(), "dns_cache_inserted");
    /// assert_eq!(Metric::DhcpAck.name(), "dhcpack");
    /// ```
    pub fn name(&self) -> &'static str {
        match self {
            Metric::DnsCacheInserted => "dns_cache_inserted",
            Metric::DnsCacheLiveFreed => "dns_cache_live_freed",
            Metric::DnsQueriesForwarded => "dns_queries_forwarded",
            Metric::DnsAuthAnswered => "dns_auth_answered",
            Metric::DnsLocalAnswered => "dns_local_answered",
            Metric::DnsStaleAnswered => "dns_stale_answered",
            Metric::DnsUnanswered => "dns_unanswered",
            Metric::Bootp => "bootp",
            Metric::Pxe => "pxe",
            Metric::DhcpAck => "dhcpack",
            Metric::DhcpDecline => "dhcpdecline",
            Metric::DhcpDiscover => "dhcpdiscover",
            Metric::DhcpInform => "dhcpinform",
            Metric::DhcpNak => "dhcpnak",
            Metric::DhcpOffer => "dhcpoffer",
            Metric::DhcpRelease => "dhcprelease",
            Metric::DhcpRequest => "dhcprequest",
            Metric::NoAnswer => "noanswer",
            Metric::LeasesAllocated4 => "leases_allocated_4",
            Metric::LeasesPruned4 => "leases_pruned_4",
            Metric::LeasesAllocated6 => "leases_allocated_6",
            Metric::LeasesPruned6 => "leases_pruned_6",
            Metric::TcpConnections => "tcp_connections",
            Metric::DnssecMaxCryptoUse => "dnssec_max_crypto_use",
            Metric::DnssecMaxSigFail => "dnssec_max_sig_fail",
            Metric::DnssecMaxWork => "dnssec_max_work",
            Metric::DnsQueriesLeasequery => "dns_queries_leasequery",
            Metric::DnsQueriesLeasequeryAnswered => "dns_queries_leasequery_answered",
            Metric::DnsQueriesLeasequeryRefused => "dns_queries_leasequery_refused",
        }
    }

    /// Returns a static slice containing all metric variants in index order.
    ///
    /// Useful for iterating over all metrics during export, reset, or reporting.
    ///
    /// # Examples
    /// ```ignore
    /// for metric in Metric::all() {
    ///     println!("{}: {}", metric.name(), store.get(*metric));
    /// }
    /// ```
    pub fn all() -> &'static [Metric] {
        static ALL_METRICS: [Metric; Metric::COUNT] = [
            Metric::DnsCacheInserted,
            Metric::DnsCacheLiveFreed,
            Metric::DnsQueriesForwarded,
            Metric::DnsAuthAnswered,
            Metric::DnsLocalAnswered,
            Metric::DnsStaleAnswered,
            Metric::DnsUnanswered,
            Metric::Bootp,
            Metric::Pxe,
            Metric::DhcpAck,
            Metric::DhcpDecline,
            Metric::DhcpDiscover,
            Metric::DhcpInform,
            Metric::DhcpNak,
            Metric::DhcpOffer,
            Metric::DhcpRelease,
            Metric::DhcpRequest,
            Metric::NoAnswer,
            Metric::LeasesAllocated4,
            Metric::LeasesPruned4,
            Metric::LeasesAllocated6,
            Metric::LeasesPruned6,
            Metric::TcpConnections,
            Metric::DnssecMaxCryptoUse,
            Metric::DnssecMaxSigFail,
            Metric::DnssecMaxWork,
            Metric::DnsQueriesLeasequery,
            Metric::DnsQueriesLeasequeryAnswered,
            Metric::DnsQueriesLeasequeryRefused,
        ];
        &ALL_METRICS
    }
}

/// Converts a `u32` index to a `Metric` variant.
///
/// Returns `Ok(Metric)` for valid indices (0 to `Metric::COUNT - 1`),
/// or `Err(())` for out-of-range values.
///
/// # Examples
/// ```ignore
/// use std::convert::TryFrom;
/// assert_eq!(Metric::try_from(0u32), Ok(Metric::DnsCacheInserted));
/// assert!(Metric::try_from(29u32).is_err());
/// ```
impl TryFrom<u32> for Metric {
    type Error = MetricConversionError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Metric::DnsCacheInserted),
            1 => Ok(Metric::DnsCacheLiveFreed),
            2 => Ok(Metric::DnsQueriesForwarded),
            3 => Ok(Metric::DnsAuthAnswered),
            4 => Ok(Metric::DnsLocalAnswered),
            5 => Ok(Metric::DnsStaleAnswered),
            6 => Ok(Metric::DnsUnanswered),
            7 => Ok(Metric::Bootp),
            8 => Ok(Metric::Pxe),
            9 => Ok(Metric::DhcpAck),
            10 => Ok(Metric::DhcpDecline),
            11 => Ok(Metric::DhcpDiscover),
            12 => Ok(Metric::DhcpInform),
            13 => Ok(Metric::DhcpNak),
            14 => Ok(Metric::DhcpOffer),
            15 => Ok(Metric::DhcpRelease),
            16 => Ok(Metric::DhcpRequest),
            17 => Ok(Metric::NoAnswer),
            18 => Ok(Metric::LeasesAllocated4),
            19 => Ok(Metric::LeasesPruned4),
            20 => Ok(Metric::LeasesAllocated6),
            21 => Ok(Metric::LeasesPruned6),
            22 => Ok(Metric::TcpConnections),
            23 => Ok(Metric::DnssecMaxCryptoUse),
            24 => Ok(Metric::DnssecMaxSigFail),
            25 => Ok(Metric::DnssecMaxWork),
            26 => Ok(Metric::DnsQueriesLeasequery),
            27 => Ok(Metric::DnsQueriesLeasequeryAnswered),
            28 => Ok(Metric::DnsQueriesLeasequeryRefused),
            _ => Err(MetricConversionError { value }),
        }
    }
}

/// Error type returned when converting an invalid `u32` index to a [`Metric`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetricConversionError {
    /// The invalid index value that was attempted.
    pub value: u32,
}

impl core::fmt::Display for MetricConversionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "invalid metric index {}: valid range is 0..{}",
            self.value,
            Metric::COUNT
        )
    }
}

impl std::error::Error for MetricConversionError {}

/// Counter storage for all daemon-wide metrics.
///
/// Stores all [`Metric::COUNT`] counters in a fixed-size array, replacing the
/// C `daemon->metrics[__METRIC_MAX]` global array. Provides type-safe access
/// via [`Metric`] enum variants instead of raw integer indices.
///
/// ## Performance
/// All operations are O(1) array index operations with no heap allocation.
/// The single-threaded event loop architecture ensures no locking is needed.
///
/// ## Usage
/// ```ignore
/// let mut store = MetricsStore::new();
///
/// // Increment on query forwarding
/// store.increment(Metric::DnsQueriesForwarded);
///
/// // Track DNSSEC high-water mark
/// store.set_max(Metric::DnssecMaxCryptoUse, current_crypto_ops);
///
/// // Export all metrics
/// for metric in Metric::all() {
///     export_metric(metric.name(), store.get(*metric));
/// }
///
/// // Reset all counters (e.g., on config reload or D-Bus ClearMetrics)
/// store.clear();
/// ```
pub struct MetricsStore {
    /// Counter array indexed by `Metric` variant discriminant values.
    counters: [u32; Metric::COUNT],
}

impl MetricsStore {
    /// Creates a new `MetricsStore` with all counters initialized to zero.
    ///
    /// This replaces the zero-initialization of `daemon->metrics[]` in the C
    /// daemon startup code.
    pub fn new() -> Self {
        MetricsStore {
            counters: [0u32; Metric::COUNT],
        }
    }

    /// Returns the current value of the specified metric counter.
    ///
    /// # Arguments
    /// * `metric` - The metric to query.
    ///
    /// # Examples
    /// ```ignore
    /// let store = MetricsStore::new();
    /// assert_eq!(store.get(Metric::DnsCacheInserted), 0);
    /// ```
    #[inline]
    pub fn get(&self, metric: Metric) -> u32 {
        self.counters[metric as usize]
    }

    /// Increments the specified metric counter by one.
    ///
    /// This is the most common operation, used throughout the codebase at
    /// key operational events (e.g., `daemon->metrics[METRIC_DNS_QUERIES_FORWARDED]++`
    /// in the C code).
    ///
    /// Uses saturating arithmetic to prevent overflow panics in production.
    ///
    /// # Arguments
    /// * `metric` - The metric to increment.
    #[inline]
    pub fn increment(&mut self, metric: Metric) {
        self.counters[metric as usize] = self.counters[metric as usize].saturating_add(1);
    }

    /// Adds the specified value to the metric counter.
    ///
    /// Uses saturating arithmetic to prevent overflow panics in production.
    ///
    /// # Arguments
    /// * `metric` - The metric to update.
    /// * `value` - The value to add to the current counter.
    #[inline]
    pub fn add(&mut self, metric: Metric, value: u32) {
        self.counters[metric as usize] = self.counters[metric as usize].saturating_add(value);
    }

    /// Sets the metric counter to the specified value.
    ///
    /// # Arguments
    /// * `metric` - The metric to set.
    /// * `value` - The new counter value.
    #[inline]
    pub fn set(&mut self, metric: Metric, value: u32) {
        self.counters[metric as usize] = value;
    }

    /// Sets the metric counter to the maximum of its current value and the
    /// specified value (high-water mark semantics).
    ///
    /// Used for DNSSEC resource tracking metrics (`DnssecMaxCryptoUse`,
    /// `DnssecMaxSigFail`, `DnssecMaxWork`) which track peak resource
    /// consumption rather than cumulative counts.
    ///
    /// # Arguments
    /// * `metric` - The metric to update.
    /// * `value` - The candidate high-water mark value.
    #[inline]
    pub fn set_max(&mut self, metric: Metric, value: u32) {
        let idx = metric as usize;
        if value > self.counters[idx] {
            self.counters[idx] = value;
        }
    }

    /// Resets all metric counters to zero.
    ///
    /// Replaces the C `clear_metrics()` function's global metrics reset
    /// (`for (i = 0; i < __METRIC_MAX; i++) daemon->metrics[i] = 0;`).
    ///
    /// **Note:** The C `clear_metrics()` also zeroes per-server statistics by
    /// iterating `daemon->servers`. In the Rust design, the server list is owned
    /// elsewhere; callers must separately invoke [`ServerMetrics::clear()`] on
    /// each server's metrics to achieve full parity with the C behavior.
    ///
    /// **Bug fix:** The C code (metrics.c line 309) contains a duplicate
    /// `serv->failed_queries = 0;` assignment. The Rust version does not
    /// replicate this bug.
    pub fn clear(&mut self) {
        self.counters = [0u32; Metric::COUNT];
    }
}

impl Default for MetricsStore {
    fn default() -> Self {
        MetricsStore::new()
    }
}

/// Per-upstream-server performance statistics.
///
/// Tracks query volume, failure rates, retry behavior, and latency for each
/// upstream DNS server. These counters are zeroed alongside global metrics when
/// `clear_metrics()` is invoked via D-Bus/UBus or during configuration reload.
///
/// Replaces the per-server fields from the C `struct server` definition in
/// `dnsmasq.h` that are cleared by `clear_metrics()` in `metrics.c`:
/// - `serv->queries`
/// - `serv->failed_queries`
/// - `serv->retrys`
/// - `serv->nxdomain_replies`
/// - `serv->query_latency`
///
/// **Bug fix:** The C `clear_metrics()` (metrics.c line 309) contains a
/// duplicate `serv->failed_queries = 0;` assignment (the line immediately
/// after the first `serv->failed_queries = 0;`). This Rust implementation
/// correctly assigns each field exactly once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerMetrics {
    /// Total queries sent to this upstream server.
    pub queries: u32,

    /// Queries that failed (timeout, connection refused, SERVFAIL, etc.).
    pub failed_queries: u32,

    /// NXDOMAIN responses received from this server.
    pub nxdomain_replies: u32,

    /// Query retry attempts after initial failure or timeout.
    pub retrys: u32,

    /// Accumulated query response latency (milliseconds) for average calculation.
    pub query_latency: u32,

    /// Modified moving average of query latency for smoothed performance tracking.
    pub mma_latency: u32,
}

impl ServerMetrics {
    /// Creates a new `ServerMetrics` with all counters initialized to zero.
    pub fn new() -> Self {
        ServerMetrics {
            queries: 0,
            failed_queries: 0,
            nxdomain_replies: 0,
            retrys: 0,
            query_latency: 0,
            mma_latency: 0,
        }
    }

    /// Resets all per-server counters to zero.
    ///
    /// Called during `clear_metrics()` processing for each upstream server
    /// in the server linked list. In Rust, the server list is owned by the
    /// network module; this method clears a single server's metrics.
    ///
    /// **Bug fix:** The C code assigns `serv->failed_queries = 0` twice
    /// (metrics.c lines 308-309). This method correctly zeros each field once.
    pub fn clear(&mut self) {
        self.queries = 0;
        self.failed_queries = 0;
        self.nxdomain_replies = 0;
        self.retrys = 0;
        self.query_latency = 0;
        self.mma_latency = 0;
    }
}

impl Default for ServerMetrics {
    fn default() -> Self {
        ServerMetrics::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =====================================================================
    // Metric enum tests
    // =====================================================================

    #[test]
    fn test_metric_count_equals_29() {
        assert_eq!(Metric::COUNT, 29);
    }

    #[test]
    fn test_metric_all_returns_correct_count() {
        let all = Metric::all();
        assert_eq!(all.len(), Metric::COUNT);
        assert_eq!(all.len(), 29);
    }

    #[test]
    fn test_metric_all_variants_are_unique() {
        let all = Metric::all();
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "Duplicate metric at indices {} and {}", i, j);
                }
            }
        }
    }

    #[test]
    fn test_metric_all_matches_index_order() {
        let all = Metric::all();
        for (i, metric) in all.iter().enumerate() {
            assert_eq!(
                *metric as u32, i as u32,
                "Metric {:?} has discriminant {} but expected {}",
                metric, *metric as u32, i
            );
        }
    }

    #[test]
    fn test_metric_names_match_expected_strings() {
        let expected_names = [
            "dns_cache_inserted",
            "dns_cache_live_freed",
            "dns_queries_forwarded",
            "dns_auth_answered",
            "dns_local_answered",
            "dns_stale_answered",
            "dns_unanswered",
            "bootp",
            "pxe",
            "dhcpack",
            "dhcpdecline",
            "dhcpdiscover",
            "dhcpinform",
            "dhcpnak",
            "dhcpoffer",
            "dhcprelease",
            "dhcprequest",
            "noanswer",
            "leases_allocated_4",
            "leases_pruned_4",
            "leases_allocated_6",
            "leases_pruned_6",
            "tcp_connections",
            "dnssec_max_crypto_use",
            "dnssec_max_sig_fail",
            "dnssec_max_work",
            "dns_queries_leasequery",
            "dns_queries_leasequery_answered",
            "dns_queries_leasequery_refused",
        ];

        let all = Metric::all();
        assert_eq!(all.len(), expected_names.len());
        for (metric, expected) in all.iter().zip(expected_names.iter()) {
            assert_eq!(
                metric.name(),
                *expected,
                "Metric {:?} has name '{}' but expected '{}'",
                metric,
                metric.name(),
                expected
            );
        }
    }

    #[test]
    fn test_metric_individual_names() {
        assert_eq!(Metric::DnsCacheInserted.name(), "dns_cache_inserted");
        assert_eq!(Metric::DnsCacheLiveFreed.name(), "dns_cache_live_freed");
        assert_eq!(Metric::DnsQueriesForwarded.name(), "dns_queries_forwarded");
        assert_eq!(Metric::DnsAuthAnswered.name(), "dns_auth_answered");
        assert_eq!(Metric::DnsLocalAnswered.name(), "dns_local_answered");
        assert_eq!(Metric::DnsStaleAnswered.name(), "dns_stale_answered");
        assert_eq!(Metric::DnsUnanswered.name(), "dns_unanswered");
        assert_eq!(Metric::Bootp.name(), "bootp");
        assert_eq!(Metric::Pxe.name(), "pxe");
        assert_eq!(Metric::DhcpAck.name(), "dhcpack");
        assert_eq!(Metric::DhcpDecline.name(), "dhcpdecline");
        assert_eq!(Metric::DhcpDiscover.name(), "dhcpdiscover");
        assert_eq!(Metric::DhcpInform.name(), "dhcpinform");
        assert_eq!(Metric::DhcpNak.name(), "dhcpnak");
        assert_eq!(Metric::DhcpOffer.name(), "dhcpoffer");
        assert_eq!(Metric::DhcpRelease.name(), "dhcprelease");
        assert_eq!(Metric::DhcpRequest.name(), "dhcprequest");
        assert_eq!(Metric::NoAnswer.name(), "noanswer");
        assert_eq!(Metric::LeasesAllocated4.name(), "leases_allocated_4");
        assert_eq!(Metric::LeasesPruned4.name(), "leases_pruned_4");
        assert_eq!(Metric::LeasesAllocated6.name(), "leases_allocated_6");
        assert_eq!(Metric::LeasesPruned6.name(), "leases_pruned_6");
        assert_eq!(Metric::TcpConnections.name(), "tcp_connections");
        assert_eq!(Metric::DnssecMaxCryptoUse.name(), "dnssec_max_crypto_use");
        assert_eq!(Metric::DnssecMaxSigFail.name(), "dnssec_max_sig_fail");
        assert_eq!(Metric::DnssecMaxWork.name(), "dnssec_max_work");
        assert_eq!(Metric::DnsQueriesLeasequery.name(), "dns_queries_leasequery");
        assert_eq!(
            Metric::DnsQueriesLeasequeryAnswered.name(),
            "dns_queries_leasequery_answered"
        );
        assert_eq!(
            Metric::DnsQueriesLeasequeryRefused.name(),
            "dns_queries_leasequery_refused"
        );
    }

    #[test]
    fn test_try_from_valid_indices() {
        for i in 0..Metric::COUNT as u32 {
            let result = Metric::try_from(i);
            assert!(
                result.is_ok(),
                "Metric::try_from({}) should succeed but returned {:?}",
                i,
                result
            );
            let metric = result.unwrap();
            assert_eq!(metric as u32, i);
        }
    }

    #[test]
    fn test_try_from_invalid_indices() {
        assert!(Metric::try_from(29u32).is_err());
        assert!(Metric::try_from(30u32).is_err());
        assert!(Metric::try_from(100u32).is_err());
        assert!(Metric::try_from(u32::MAX).is_err());
    }

    #[test]
    fn test_try_from_boundary_values() {
        // Last valid index
        assert_eq!(
            Metric::try_from(28u32),
            Ok(Metric::DnsQueriesLeasequeryRefused)
        );
        // First invalid index
        let err = Metric::try_from(29u32).unwrap_err();
        assert_eq!(err.value, 29);
    }

    #[test]
    fn test_metric_conversion_error_display() {
        let err = MetricConversionError { value: 42 };
        let msg = format!("{}", err);
        assert!(msg.contains("42"));
        assert!(msg.contains("29"));
    }

    #[test]
    fn test_metric_debug_format() {
        let metric = Metric::DnsCacheInserted;
        let debug_str = format!("{:?}", metric);
        assert_eq!(debug_str, "DnsCacheInserted");
    }

    #[test]
    fn test_metric_clone_and_copy() {
        let metric = Metric::DnsQueriesForwarded;
        let cloned = metric.clone();
        let copied = metric;
        assert_eq!(metric, cloned);
        assert_eq!(metric, copied);
    }

    #[test]
    fn test_metric_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        for metric in Metric::all() {
            assert!(set.insert(*metric), "Duplicate hash for {:?}", metric);
        }
        assert_eq!(set.len(), Metric::COUNT);
    }

    // =====================================================================
    // MetricsStore tests
    // =====================================================================

    #[test]
    fn test_metrics_store_new_initializes_all_zeros() {
        let store = MetricsStore::new();
        for metric in Metric::all() {
            assert_eq!(
                store.get(*metric),
                0,
                "Metric {:?} should be 0 after new()",
                metric
            );
        }
    }

    #[test]
    fn test_metrics_store_default_equals_new() {
        let store_new = MetricsStore::new();
        let store_default = MetricsStore::default();
        for metric in Metric::all() {
            assert_eq!(store_new.get(*metric), store_default.get(*metric));
        }
    }

    #[test]
    fn test_metrics_store_increment() {
        let mut store = MetricsStore::new();

        store.increment(Metric::DnsQueriesForwarded);
        assert_eq!(store.get(Metric::DnsQueriesForwarded), 1);

        store.increment(Metric::DnsQueriesForwarded);
        assert_eq!(store.get(Metric::DnsQueriesForwarded), 2);

        // Other metrics should remain zero
        assert_eq!(store.get(Metric::DnsCacheInserted), 0);
        assert_eq!(store.get(Metric::DhcpAck), 0);
    }

    #[test]
    fn test_metrics_store_add() {
        let mut store = MetricsStore::new();

        store.add(Metric::TcpConnections, 5);
        assert_eq!(store.get(Metric::TcpConnections), 5);

        store.add(Metric::TcpConnections, 10);
        assert_eq!(store.get(Metric::TcpConnections), 15);
    }

    #[test]
    fn test_metrics_store_set() {
        let mut store = MetricsStore::new();

        store.set(Metric::DnsCacheInserted, 42);
        assert_eq!(store.get(Metric::DnsCacheInserted), 42);

        store.set(Metric::DnsCacheInserted, 100);
        assert_eq!(store.get(Metric::DnsCacheInserted), 100);

        // Set to zero
        store.set(Metric::DnsCacheInserted, 0);
        assert_eq!(store.get(Metric::DnsCacheInserted), 0);
    }

    #[test]
    fn test_metrics_store_set_max() {
        let mut store = MetricsStore::new();

        // Initial set_max should set the value
        store.set_max(Metric::DnssecMaxCryptoUse, 50);
        assert_eq!(store.get(Metric::DnssecMaxCryptoUse), 50);

        // Higher value should update
        store.set_max(Metric::DnssecMaxCryptoUse, 100);
        assert_eq!(store.get(Metric::DnssecMaxCryptoUse), 100);

        // Lower value should NOT update (high-water mark semantics)
        store.set_max(Metric::DnssecMaxCryptoUse, 75);
        assert_eq!(store.get(Metric::DnssecMaxCryptoUse), 100);

        // Equal value should NOT update
        store.set_max(Metric::DnssecMaxCryptoUse, 100);
        assert_eq!(store.get(Metric::DnssecMaxCryptoUse), 100);

        // Zero should NOT update
        store.set_max(Metric::DnssecMaxCryptoUse, 0);
        assert_eq!(store.get(Metric::DnssecMaxCryptoUse), 100);
    }

    #[test]
    fn test_metrics_store_set_max_all_hwm_metrics() {
        let mut store = MetricsStore::new();

        // Test all three DNSSEC HWM metrics
        store.set_max(Metric::DnssecMaxCryptoUse, 200);
        store.set_max(Metric::DnssecMaxSigFail, 20);
        store.set_max(Metric::DnssecMaxWork, 40);

        assert_eq!(store.get(Metric::DnssecMaxCryptoUse), 200);
        assert_eq!(store.get(Metric::DnssecMaxSigFail), 20);
        assert_eq!(store.get(Metric::DnssecMaxWork), 40);
    }

    #[test]
    fn test_metrics_store_clear() {
        let mut store = MetricsStore::new();

        // Set various metrics to non-zero values
        store.increment(Metric::DnsCacheInserted);
        store.add(Metric::DnsQueriesForwarded, 100);
        store.set(Metric::DhcpAck, 50);
        store.set_max(Metric::DnssecMaxCryptoUse, 200);

        // Verify they are non-zero
        assert_ne!(store.get(Metric::DnsCacheInserted), 0);
        assert_ne!(store.get(Metric::DnsQueriesForwarded), 0);
        assert_ne!(store.get(Metric::DhcpAck), 0);
        assert_ne!(store.get(Metric::DnssecMaxCryptoUse), 0);

        // Clear all
        store.clear();

        // Verify all are zero
        for metric in Metric::all() {
            assert_eq!(
                store.get(*metric),
                0,
                "Metric {:?} should be 0 after clear()",
                metric
            );
        }
    }

    #[test]
    fn test_metrics_store_increment_saturating() {
        let mut store = MetricsStore::new();

        // Set to max u32 value
        store.set(Metric::DnsCacheInserted, u32::MAX);
        assert_eq!(store.get(Metric::DnsCacheInserted), u32::MAX);

        // Increment should saturate, not panic or wrap
        store.increment(Metric::DnsCacheInserted);
        assert_eq!(store.get(Metric::DnsCacheInserted), u32::MAX);
    }

    #[test]
    fn test_metrics_store_add_saturating() {
        let mut store = MetricsStore::new();

        // Set near max
        store.set(Metric::DnsCacheInserted, u32::MAX - 5);

        // Add more than remaining headroom
        store.add(Metric::DnsCacheInserted, 100);
        assert_eq!(store.get(Metric::DnsCacheInserted), u32::MAX);
    }

    #[test]
    fn test_metrics_store_independence() {
        let mut store = MetricsStore::new();

        // Modifying one metric should not affect others
        store.set(Metric::DhcpDiscover, 999);
        for metric in Metric::all() {
            if *metric == Metric::DhcpDiscover {
                assert_eq!(store.get(*metric), 999);
            } else {
                assert_eq!(
                    store.get(*metric),
                    0,
                    "Metric {:?} should be 0 but got {}",
                    metric,
                    store.get(*metric)
                );
            }
        }
    }

    // =====================================================================
    // ServerMetrics tests
    // =====================================================================

    #[test]
    fn test_server_metrics_new_all_zeros() {
        let sm = ServerMetrics::new();
        assert_eq!(sm.queries, 0);
        assert_eq!(sm.failed_queries, 0);
        assert_eq!(sm.nxdomain_replies, 0);
        assert_eq!(sm.retrys, 0);
        assert_eq!(sm.query_latency, 0);
        assert_eq!(sm.mma_latency, 0);
    }

    #[test]
    fn test_server_metrics_default_equals_new() {
        let sm_new = ServerMetrics::new();
        let sm_default = ServerMetrics::default();
        assert_eq!(sm_new, sm_default);
    }

    #[test]
    fn test_server_metrics_clear() {
        let mut sm = ServerMetrics {
            queries: 100,
            failed_queries: 10,
            nxdomain_replies: 5,
            retrys: 3,
            query_latency: 250,
            mma_latency: 120,
        };

        sm.clear();

        assert_eq!(sm.queries, 0);
        assert_eq!(sm.failed_queries, 0);
        assert_eq!(sm.nxdomain_replies, 0);
        assert_eq!(sm.retrys, 0);
        assert_eq!(sm.query_latency, 0);
        assert_eq!(sm.mma_latency, 0);
    }

    #[test]
    fn test_server_metrics_fields_are_public() {
        let mut sm = ServerMetrics::new();

        // Verify all fields are publicly accessible for direct modification
        sm.queries = 42;
        sm.failed_queries = 7;
        sm.nxdomain_replies = 3;
        sm.retrys = 2;
        sm.query_latency = 150;
        sm.mma_latency = 100;

        assert_eq!(sm.queries, 42);
        assert_eq!(sm.failed_queries, 7);
        assert_eq!(sm.nxdomain_replies, 3);
        assert_eq!(sm.retrys, 2);
        assert_eq!(sm.query_latency, 150);
        assert_eq!(sm.mma_latency, 100);
    }

    #[test]
    fn test_server_metrics_clone() {
        let sm = ServerMetrics {
            queries: 100,
            failed_queries: 10,
            nxdomain_replies: 5,
            retrys: 3,
            query_latency: 250,
            mma_latency: 120,
        };

        let cloned = sm.clone();
        assert_eq!(sm, cloned);
    }

    #[test]
    fn test_server_metrics_debug_format() {
        let sm = ServerMetrics::new();
        let debug_str = format!("{:?}", sm);
        assert!(debug_str.contains("ServerMetrics"));
        assert!(debug_str.contains("queries: 0"));
    }
}

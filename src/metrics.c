/* dnsmasq is Copyright (c) 2000-2025 Simon Kelley

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 dated June, 1991, or
   (at your option) version 3 dated 29 June, 2007.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * @file metrics.c
 * @brief Performance metrics collection and reporting for dnsmasq operations
 * 
 * DETAILED PURPOSE:
 * This module implements basic performance metrics collection including cache hit/miss
 * counters, query rate tracking, DHCP transaction statistics, and upstream server
 * performance monitoring. Metrics are stored as simple counters in the global daemon
 * structure and can be exported via control interfaces (D-Bus, UBus) or reset on demand.
 * 
 * The metrics system provides operational visibility into:
 * - DNS cache operations (insertions, evictions, queries served)
 * - DNS query routing (forwarded, locally answered, stale answers, unanswered)
 * - DNSSEC validation resource limits (max crypto operations, signature failures, work)
 * - DHCP protocol message counters (DISCOVER, OFFER, REQUEST, ACK, NAK, DECLINE, RELEASE, INFORM)
 * - DHCP lease allocation and pruning statistics (IPv4 and IPv6)
 * - BOOTP and PXE request counters for network boot scenarios
 * - TCP connection tracking for DNS-over-TCP
 * - DHCPv4 leasequery protocol counters
 * - Upstream server query statistics (queries sent, failures, retries, latency)
 * 
 * KEY RESPONSIBILITIES:
 * - Provide string names for all metric types via get_metric_name() for display and export
 * - Reset all metric counters to zero via clear_metrics() for statistics collection periods
 * - Maintain metric_names array mapping enum values to human-readable metric names
 * - Reset per-server statistics (queries, failures, retries, NXDOMAIN, latency) alongside global metrics
 * 
 * DEPENDENCIES:
 * Includes: dnsmasq.h (for daemon structure and type definitions)
 * Called by: Control interfaces (dbus.c, ubus.c) for metric export; various modules for counter increments
 * Calls: None - this is a leaf module providing utility functions
 * 
 * DATA STRUCTURES:
 * - metric_names[]: Constant string array providing human-readable names for each metric type
 *   (defined at lines 19-50, array size __METRIC_MAX from metrics.h)
 * - daemon->metrics[]: Global counter array in struct daemon holding metric values
 *   (defined in dnsmasq.h line 1254 as u32 metrics[__METRIC_MAX])
 * - struct server: Contains per-upstream-server counters (queries, failed_queries, retrys,
 *   nxdomain_replies, query_latency) that are reset by clear_metrics()
 * 
 * COMPILE-TIME OPTIONS:
 * - No conditional compilation - metrics are always available
 * - Metric collection overhead is minimal (single counter increment per event)
 * 
 * THREADING/CONCURRENCY:
 * Single-threaded architecture ensures atomic counter updates without locking.
 * Metrics are incremented inline during packet processing in the main event loop.
 * Counter updates are simple increments (daemon->metrics[METRIC_X]++) with no race conditions.
 * 
 * INTEGRATION POINTS:
 * - cache.c: Increments METRIC_DNS_CACHE_INSERTED, METRIC_DNS_CACHE_LIVE_FREED
 * - forward.c: Increments METRIC_DNS_QUERIES_FORWARDED, METRIC_NOANSWER, METRIC_TCP_CONNECTIONS
 * - auth.c: Increments METRIC_DNS_AUTH_ANSWERED
 * - cache.c: Increments METRIC_DNS_LOCAL_ANSWERED, METRIC_DNS_STALE_ANSWERED
 * - dhcp.c, rfc2131.c: Increment DHCP message counters (DISCOVER, OFFER, REQUEST, ACK, etc.)
 * - lease.c: Increments METRIC_LEASES_ALLOCATED_4/6, METRIC_LEASES_PRUNED_4/6
 * - dnssec.c: Updates METRIC_DNSSEC_MAX_CRYPTO_USE, METRIC_DNSSEC_MAX_SIG_FAIL, METRIC_DNSSEC_MAX_WORK
 * - dbus.c: Exports metrics via D-Bus GetMetrics method
 * - ubus.c: Exports metrics via UBus metrics object
 * 
 * @copyright Copyright (c) 2000-2025 Simon Kelley
 * @license GPL-2.0-or-later
 */

#include "dnsmasq.h"

/**
 * @brief Human-readable names for all metric types
 * 
 * This constant string array provides display names for each metric type defined
 * in the metric_name enum (src/metrics.h). The array is indexed by enum values
 * (METRIC_DNS_CACHE_INSERTED = 0, METRIC_DNS_CACHE_LIVE_FREED = 1, etc.) and
 * contains corresponding human-readable identifiers suitable for logging,
 * export via control interfaces (D-Bus, UBus), and administrative display.
 * 
 * Array Elements:
 * - DNS cache metrics: cache insertions, live entry evictions
 * - DNS query routing: forwarded queries, authoritative answers, local answers,
 *   stale answers, unanswered queries
 * - DNSSEC resource tracking: maximum crypto operations, signature failures, work units
 * - Network boot: BOOTP requests, PXE requests
 * - DHCPv4 messages: ACK, DECLINE, DISCOVER, INFORM, NAK, OFFER, RELEASE, REQUEST
 * - DHCP leases: allocations and pruning for IPv4 and IPv6
 * - TCP connections: DNS-over-TCP connection count
 * - DHCPv4 leasequery: query counts and response types (unassigned, active, unknown)
 * - General: noanswer counter for queries without any response
 * 
 * Array Size: __METRIC_MAX (defined in metrics.h as final enum value)
 * 
 * Usage Pattern:
 * - get_metric_name(METRIC_DNS_CACHE_INSERTED) returns "dns_cache_inserted"
 * - D-Bus/UBus interfaces iterate over array to export all metrics with names
 * - Logging and statistics dumps use names for human-readable output
 * 
 * String Format Convention:
 * - Lowercase with underscores separating words
 * - Prefixed by category: dns_, dhcp_, dnssec_, leases_, tcp_
 * - Describes the event being counted (e.g., "forwarded", "inserted", "pruned")
 * 
 * IMPORTANT: Array order must exactly match the metric_name enum definition
 * in src/metrics.h. Adding, removing, or reordering metrics requires updating
 * both the enum and this array in parallel to maintain correct index mapping.
 * 
 * @see get_metric_name() for safe accessor function
 * @see metrics.h for metric_name enum definition
 */
const char * metric_names[] = {
    "dns_cache_inserted",
    "dns_cache_live_freed",
    "dns_queries_forwarded",
    "dns_auth_answered",
    "dns_local_answered",
    "dns_stale_answered",
    "dns_unanswered",
    "dnssec_max_crypto_use",
    "dnssec_max_sig_fail",
    "dnssec_max_work",
    "bootp",
    "pxe",
    "dhcp_ack",
    "dhcp_decline",
    "dhcp_discover",
    "dhcp_inform",
    "dhcp_nak",
    "dhcp_offer",
    "dhcp_release",
    "dhcp_request",
    "noanswer",
    "leases_allocated_4",
    "leases_pruned_4",
    "leases_allocated_6",
    "leases_pruned_6",
    "tcp_connections",
    "dhcp_leasequery",
    "dhcp_lease_unassigned",
    "dhcp_lease_actve",
    "dhcp_lease_unknown"
};

/**
 * @brief Retrieve human-readable name for a specific metric type
 * 
 * Returns the display name string for the metric identified by the provided
 * index. This function provides safe access to the metric_names array, enabling
 * control interfaces (D-Bus, UBus) and logging systems to obtain human-readable
 * metric identifiers for export and display.
 * 
 * The function performs direct array indexing without bounds checking, relying
 * on the caller to provide valid enum values from the metric_name enum defined
 * in metrics.h. Invalid indices will cause undefined behavior (array overrun).
 * 
 * Typical usage pattern in control interfaces:
 * - Iterate over metric enum values from 0 to __METRIC_MAX - 1
 * - For each index, call get_metric_name(i) to obtain display name
 * - Pair name with corresponding counter value from daemon->metrics[i]
 * - Export as key-value pairs via D-Bus, UBus, or logging output
 * 
 * @param i Metric type index from metric_name enum (0 to __METRIC_MAX - 1)
 *          Valid values: METRIC_DNS_CACHE_INSERTED, METRIC_DNS_CACHE_LIVE_FREED,
 *          METRIC_DNS_QUERIES_FORWARDED, etc. (all enum values from metrics.h)
 * 
 * @return Pointer to constant string containing metric display name
 *         Example return values: "dns_cache_inserted", "dhcp_discover",
 *         "leases_allocated_4", "dnssec_max_crypto_use"
 *         The returned pointer references static data and must not be freed.
 * 
 * @warning No bounds checking is performed. Passing an index >= __METRIC_MAX
 *          will cause array overrun and undefined behavior. Caller must ensure
 *          index is valid enum value from metrics.h.
 * 
 * @note This function is called frequently during metric export operations but
 *       has negligible overhead (single array index and pointer return).
 * 
 * EXAMPLE USAGE:
 * @code
 * // Export all metrics with names
 * for (int i = 0; i < __METRIC_MAX; i++) {
 *     const char *name = get_metric_name(i);
 *     u32 value = daemon->metrics[i];
 *     printf("%s: %u\n", name, value);
 * }
 * @endcode
 * 
 * INTEGRATION POINTS:
 * - dbus.c: D-Bus GetMetrics method iterates metrics and calls this function
 * - ubus.c: UBus metrics object export uses this for metric name retrieval
 * - Logging: Statistics dumps use metric names for human-readable output
 * 
 * @see metric_names array for the underlying string storage
 * @see metrics.h for metric_name enum definition with all valid indices
 */
const char* get_metric_name(int i) {
    return metric_names[i];
}

/**
 * @brief Reset all performance metrics to zero
 * 
 * Resets all global metric counters and per-upstream-server statistics to zero,
 * typically invoked at the start of a monitoring period or when requested via
 * control interfaces (D-Bus, UBus). This function provides a clean slate for
 * statistics collection over a defined time window.
 * 
 * The function performs two categories of reset operations:
 * 
 * 1. Global Metrics Reset:
 *    Iterates through the daemon->metrics array (size __METRIC_MAX) and sets
 *    all counters to zero. This resets DNS cache statistics, query routing
 *    counters, DHCP message counts, DNSSEC resource tracking, lease allocation
 *    statistics, and all other system-wide metrics.
 * 
 * 2. Per-Server Statistics Reset:
 *    Iterates through the linked list of upstream DNS servers (daemon->servers)
 *    and resets per-server performance counters including:
 *    - queries: Total queries sent to this upstream server
 *    - failed_queries: Queries that failed (timeout, connection refused, etc.)
 *    - retrys: Query retry attempts after initial failure
 *    - nxdomain_replies: NXDOMAIN responses from this server
 *    - query_latency: Accumulated query response latency (for average calculation)
 * 
 * Implementation Note:
 * Line 68 contains duplicate assignment "serv->failed_queries = 0;" which is
 * harmless but redundant. This is preserved exactly as-is per documentation
 * policy (no code modification).
 * 
 * Invocation Context:
 * - Administrator request via D-Bus/UBus control interface to reset statistics
 * - Monitoring system starting new collection period (e.g., hourly/daily reset)
 * - Testing scenarios requiring clean metric state
 * 
 * Thread Safety:
 * Single-threaded architecture ensures atomic reset operation. No concurrent
 * metric updates occur during this function's execution as it runs in the
 * main event loop thread.
 * 
 * Performance Considerations:
 * - Global metrics reset: O(n) where n = __METRIC_MAX (typically 30 metrics)
 * - Server statistics reset: O(m) where m = number of upstream servers (typically 1-10)
 * - Total overhead negligible: completes in microseconds even with many servers
 * 
 * @note This function is a void function with no parameters - it operates
 *       exclusively on global daemon state (daemon->metrics and daemon->servers).
 * 
 * @warning Calling this function loses all accumulated statistics. There is no
 *          undo or backup mechanism. Ensure metrics are exported/logged before
 *          clearing if historical data retention is required.
 * 
 * EXAMPLE USAGE:
 * @code
 * // Reset metrics at start of monitoring period
 * clear_metrics();
 * // ... dnsmasq operates normally, incrementing counters ...
 * // After 1 hour, export metrics then reset
 * export_metrics_to_monitoring_system();
 * clear_metrics();
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (internal monitoring function, no protocol specification)
 * 
 * SIDE EFFECTS:
 * - Zeroes all entries in daemon->metrics[0...__METRIC_MAX-1]
 * - Zeroes queries, failed_queries, retrys, nxdomain_replies, query_latency
 *   for every server in daemon->servers linked list
 * - No filesystem I/O, network operations, or external state modifications
 * 
 * THREAD SAFETY:
 * Safe in single-threaded dnsmasq architecture. Called from main event loop
 * thread with no concurrent access to daemon structure. Multi-threaded
 * environments would require mutex protection around daemon->metrics and
 * daemon->servers access.
 * 
 * INTEGRATION POINTS:
 * - dbus.c: D-Bus ClearMetrics method invokes this function
 * - ubus.c: UBus clear_metrics command invokes this function
 * - Signal handlers: Could be invoked on SIGUSR2 or similar for administrative reset
 * 
 * @see get_metric_name() for metric name retrieval
 * @see daemon->metrics[] for global counter storage (dnsmasq.h line 1254)
 * @see struct server for upstream server statistics structure (dnsmasq.h)
 */
void clear_metrics(void)
{
  int i;
  struct server *serv;
  
  for (i = 0; i < __METRIC_MAX; i++)
    daemon->metrics[i] = 0;

  for (serv = daemon->servers; serv; serv = serv->next)
    {
      serv->queries = 0;
      serv->failed_queries = 0;
      serv->failed_queries = 0;
      serv->retrys = 0;
      serv->nxdomain_replies = 0;
      serv->query_latency = 0;
    }
}
	

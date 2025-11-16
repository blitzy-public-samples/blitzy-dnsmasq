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
 * @file metrics.h
 * @brief Metrics collection interface for performance monitoring and operational visibility
 * 
 * DETAILED PURPOSE:
 * This header defines the metrics collection infrastructure for dnsmasq, providing
 * operational visibility into DNS query processing, DHCP transactions, cache behavior,
 * and DNSSEC validation operations. The metrics system enables monitoring of system
 * performance, capacity planning, and troubleshooting through quantitative measurement
 * of key operational events.
 * 
 * The metrics collection is designed for minimal performance impact, using simple counter
 * increments without locking (single-threaded architecture) or complex data structures.
 * Metrics can be exported via D-Bus/UBus control interfaces or logged on demand, providing
 * integration points for monitoring systems and network management tools.
 * 
 * KEY RESPONSIBILITIES:
 * - Define enumeration of all collectible metric types covering DNS, DHCP, and DNSSEC operations
 * - Provide metric counter management API for initialization, reset, and retrieval
 * - Enable integration with external monitoring systems through D-Bus/UBus metric export
 * - Support operational troubleshooting through query rates, cache effectiveness, and transaction counts
 * 
 * METRIC CATEGORIES:
 * - DNS Cache Metrics: Cache insertions, evictions, and memory management (METRIC_DNS_CACHE_*)
 * - DNS Query Metrics: Forwarded queries, authoritative answers, local answers, stale responses (METRIC_DNS_*)
 * - DNSSEC Validation Metrics: Cryptographic operation high-water marks, signature failures (METRIC_CRYPTO_HWM, METRIC_SIG_FAIL_HWM)
 * - DHCPv4 Transaction Metrics: DISCOVER, OFFER, REQUEST, ACK, NAK, DECLINE, RELEASE, INFORM message counts (METRIC_DHCP*)
 * - DHCPv6 Metrics: Lease allocations and pruning for IPv6 (METRIC_LEASES_ALLOCATED_6, METRIC_LEASES_PRUNED_6)
 * - DHCP Lease Metrics: IPv4 and IPv6 lease allocations and pruning (METRIC_LEASES_*)
 * - Network Boot Metrics: BOOTP and PXE transaction counts (METRIC_BOOTP, METRIC_PXE)
 * - Connection Metrics: TCP connection establishment count (METRIC_TCP_CONNECTIONS)
 * 
 * DEPENDENCIES:
 * Includes: None (standalone header defining interface only)
 * Implementation: metrics.c provides actual counter storage and metric name labels
 * Integration: Used by forward.c, cache.c, dhcp.c, dhcp6.c, dnssec.c for event counting
 * Export Interfaces: D-Bus (dbus.c) and UBus (ubus.c) may export metrics for monitoring tools
 * 
 * USAGE PATTERNS:
 * Metric counters are incremented at key operational events throughout the codebase:
 * - DNS query forwarded: daemon->metrics[METRIC_DNS_QUERIES_FORWARDED]++
 * - DHCP ACK sent: daemon->metrics[METRIC_DHCPACK]++
 * - Cache entry inserted: daemon->metrics[METRIC_DNS_CACHE_INSERTED]++
 * 
 * Metrics can be queried via:
 * - get_metric_name(metric_id) to retrieve human-readable metric name
 * - Direct access to daemon->metrics[] array for counter values
 * - clear_metrics() to reset all counters (typically on configuration reload)
 * 
 * THREAD SAFETY:
 * Single-threaded architecture: No locking required for metric counter increments.
 * All metric operations are lock-free integer increments in the main event loop.
 * 
 * @copyright Copyright (c) 2000-2025 Simon Kelley
 * @license GPL-2.0-or-later
 */

/**
 * @brief Metric type enumeration defining all collectible performance and operational metrics
 * 
 * This enumeration defines unique identifiers for each metric counter tracked by dnsmasq.
 * The metric counters are stored in the daemon->metrics[] array, indexed by these enum values.
 * 
 * SYNCHRONIZATION REQUIREMENT:
 * If you modify this list, you MUST keep the metric name labels in metrics.c in sync.
 * The get_metric_name() function in metrics.c returns string labels corresponding to
 * these enum values, and the array indices must match exactly.
 * 
 * METRIC NAMING CONVENTIONS:
 * - DNS metrics: METRIC_DNS_* prefix for DNS-related operations
 * - DHCP metrics: METRIC_DHCP* prefix for DHCPv4 protocol messages
 * - Lease metrics: METRIC_LEASES_* prefix for lease lifecycle events
 * - DNSSEC metrics: METRIC_CRYPTO_*, METRIC_SIG_FAIL_*, METRIC_WORK_* for validation operations
 * - High-water mark (HWM) metrics: Track maximum values observed during operation
 * 
 * USAGE EXAMPLE:
 * @code
 * // Increment metric when forwarding DNS query to upstream server
 * daemon->metrics[METRIC_DNS_QUERIES_FORWARDED]++;
 * 
 * // Retrieve human-readable name for logging
 * const char *name = get_metric_name(METRIC_DNS_QUERIES_FORWARDED);
 * // name = "dns_queries_forwarded"
 * @endcode
 */
enum {
  /** DNS cache record successfully inserted into cache hash table.
   *  Tracks cache population rate and cache insertion throughput.
   *  Source: cache.c cache_insert() operations */
  METRIC_DNS_CACHE_INSERTED,
  
  /** DNS cache record evicted from cache while still within TTL (live eviction).
   *  Indicates cache pressure when LRU eviction removes valid entries.
   *  High values suggest cache size too small for query patterns.
   *  Source: cache.c cache eviction in cache_scan_free() */
  METRIC_DNS_CACHE_LIVE_FREED,
  
  /** DNS queries forwarded to upstream recursive DNS servers.
   *  Counts cache miss queries requiring upstream resolution.
   *  Ratio to total queries indicates cache effectiveness.
   *  Source: forward.c forward_query() upstream forwarding */
  METRIC_DNS_QUERIES_FORWARDED,
  
  /** DNS queries answered authoritatively from configured zones.
   *  Tracks authoritative DNS mode usage (HAVE_AUTH).
   *  Source: auth.c authoritative zone query responses */
  METRIC_DNS_AUTH_ANSWERED,
  
  /** DNS queries answered from local sources (/etc/hosts, static configuration).
   *  Includes responses from hosts file entries and manual address records.
   *  Source: cache.c and forward.c local hostname resolution */
  METRIC_DNS_LOCAL_ANSWERED,
  
  /** DNS queries answered with stale cache entries beyond original TTL.
   *  Indicates serve-stale functionality providing expired cached responses.
   *  Source: cache.c stale cache serving logic */
  METRIC_DNS_STALE_ANSWERED,
  
  /** DNS queries that could not be answered (NXDOMAIN or timeout).
   *  Tracks failed resolution attempts including upstream timeouts.
   *  High values may indicate upstream DNS problems or invalid query patterns.
   *  Source: forward.c query timeout and NXDOMAIN handling */
  METRIC_DNS_UNANSWERED_QUERY,
  
  /** DNSSEC cryptographic operations high-water mark (maximum observed).
   *  Tracks peak crypto operations during DNSSEC validation chains.
   *  Monitors resource limits: DNSSEC_LIMIT_CRYPTO (default 200).
   *  Source: dnssec.c DNSSEC validation chain processing */
  METRIC_CRYPTO_HWM,
  
  /** DNSSEC signature verification failures high-water mark.
   *  Maximum signature failures observed in single validation chain.
   *  Monitors resource limits: DNSSEC_LIMIT_SIG_FAIL (default 20).
   *  Source: dnssec.c RRSIG signature verification */
  METRIC_SIG_FAIL_HWM,
  
  /** DNSSEC validation work operations high-water mark.
   *  Maximum queries required for single DNSSEC validation chain.
   *  Monitors resource limits: DNSSEC_LIMIT_WORK (default 40).
   *  Source: dnssec.c validation query tracking */
  METRIC_WORK_HWM,
  
  /** BOOTP protocol requests processed.
   *  Counts legacy BOOTP (pre-DHCP) network boot requests.
   *  Source: dhcp.c BOOTP message processing */
  METRIC_BOOTP,
  
  /** PXE (Preboot Execution Environment) boot requests processed.
   *  Tracks network boot via PXE protocol (PXE proxy mode or integrated DHCP).
   *  Source: dhcp.c PXE vendor class identifier detection */
  METRIC_PXE,
  
  /** DHCPv4 ACK messages sent (address assignment confirmation).
   *  Successful DHCP lease grants: DISCOVER→OFFER→REQUEST→ACK sequence completion.
   *  Primary indicator of successful DHCP transactions.
   *  Source: rfc2131.c DHCPACK message transmission */
  METRIC_DHCPACK,
  
  /** DHCPv4 DECLINE messages received from clients.
   *  Client detected IP address conflict via ARP and declined offered address.
   *  Indicates address pool conflicts requiring investigation.
   *  Source: dhcp.c DHCPDECLINE message processing */
  METRIC_DHCPDECLINE,
  
  /** DHCPv4 DISCOVER messages received (initial address request).
   *  First phase of DHCP four-way handshake: client broadcasts discovery.
   *  Source: rfc2131.c DHCPDISCOVER message processing */
  METRIC_DHCPDISCOVER,
  
  /** DHCPv4 INFORM messages received (configuration without address).
   *  Client has static IP but requests DHCP configuration options only.
   *  Source: dhcp.c DHCPINFORM message processing */
  METRIC_DHCPINFORM,
  
  /** DHCPv4 NAK messages sent (address assignment rejection).
   *  Server rejects client REQUEST (wrong network, expired lease, etc.).
   *  Source: rfc2131.c DHCPNAK message transmission */
  METRIC_DHCPNAK,
  
  /** DHCPv4 OFFER messages sent (address offer to client).
   *  Second phase of DHCP handshake: server offers available address.
   *  Source: rfc2131.c DHCPOFFER message transmission */
  METRIC_DHCPOFFER,
  
  /** DHCPv4 RELEASE messages received (client relinquishes lease).
   *  Client explicitly releases IP address before lease expiration.
   *  Source: dhcp.c DHCPRELEASE message processing */
  METRIC_DHCPRELEASE,
  
  /** DHCPv4 REQUEST messages received (address request/renewal).
   *  Third phase of DHCP handshake or lease renewal request.
   *  Source: rfc2131.c DHCPREQUEST message processing */
  METRIC_DHCPREQUEST,
  
  /** Queries with no answer available (distinct from NXDOMAIN).
   *  Tracks queries that daemon cannot answer due to configuration or policy.
   *  Source: forward.c query rejection paths */
  METRIC_NOANSWER,
  
  /** DHCPv4 leases allocated from dynamic address pools.
   *  Counts successful IPv4 address assignments (dynamic leases only).
   *  Tracks address pool utilization and capacity planning.
   *  Source: dhcp.c address_allocate() for IPv4 */
  METRIC_LEASES_ALLOCATED_4,
  
  /** DHCPv4 leases expired and pruned from lease database.
   *  Lease expiration cleanup and memory reclamation for IPv4.
   *  Source: lease.c lease expiration processing */
  METRIC_LEASES_PRUNED_4,
  
  /** DHCPv6 leases allocated from IPv6 address pools.
   *  Counts successful IPv6 address assignments (stateful DHCPv6).
   *  Source: dhcp6.c IPv6 address allocation */
  METRIC_LEASES_ALLOCATED_6,
  
  /** DHCPv6 leases expired and pruned from lease database.
   *  Lease expiration cleanup and memory reclamation for IPv6.
   *  Source: lease.c IPv6 lease expiration processing */
  METRIC_LEASES_PRUNED_6,
  
  /** TCP connections established for DNS-over-TCP queries.
   *  Tracks TCP query volume (large responses, zone transfers, DNSSEC).
   *  High values may indicate need for larger UDP packet sizes.
   *  Source: forward.c TCP connection establishment */
  METRIC_TCP_CONNECTIONS,
  
  /** DHCPv4 LEASEQUERY requests received (RFC 4388).
   *  External systems querying lease information by IP or MAC address.
   *  Added in dnsmasq v2.92 for lease database integration.
   *  Source: dhcp.c DHCPLEASEQUERY message processing */
  METRIC_DHCPLEASEQUERY,
  
  /** DHCPv4 LEASEQUERY responses: lease unassigned (IP not in pool).
   *  LEASEQUERY query for IP address not within configured DHCP ranges.
   *  Source: dhcp.c DHCPLEASEUNASSIGNED response generation */
  METRIC_DHCPLEASEUNASSIGNED,
  
  /** DHCPv4 LEASEQUERY responses: lease active (IP currently leased).
   *  LEASEQUERY query returned active lease information.
   *  Source: dhcp.c DHCPLEASEACTIVE response with lease details */
  METRIC_DHCPLEASEACTIVE,
  
  /** DHCPv4 LEASEQUERY responses: lease unknown (no record found).
   *  LEASEQUERY query for IP/MAC with no matching lease database entry.
   *  Source: dhcp.c DHCPLEASEUNKNOWN response generation */
  METRIC_DHCPLEASEUNKNOWN,
  
  /** Sentinel value: total number of defined metrics.
   *  Used to size daemon->metrics[] array and validate metric IDs.
   *  Always keep as last enum member for automatic count. */
  __METRIC_MAX,
};

/**
 * @brief Retrieve human-readable metric name string for given metric identifier
 * 
 * @detailed
 * This function maps metric enum values to human-readable string labels for logging,
 * monitoring system export, and diagnostic output. The metric name labels are defined
 * in metrics.c and must be kept synchronized with the enum definition in this header.
 * 
 * The returned string is a static constant and does not require memory deallocation.
 * The pointer remains valid for the lifetime of the process.
 * 
 * USAGE CONTEXTS:
 * - Logging: Include metric names in syslog messages for troubleshooting
 * - D-Bus/UBus export: Provide metric names to monitoring system queries
 * - Statistics dumps: Generate human-readable metric reports on SIGUSR1 signal
 * - Administrative tools: Display metrics in contrib utilities (dnslist.pl, etc.)
 * 
 * @param metric_id Metric identifier from the metrics enum (0 to __METRIC_MAX-1)
 * 
 * @return Pointer to static string containing metric name (e.g., "dns_queries_forwarded")
 * @retval "unknown" If metric_id is invalid (>= __METRIC_MAX or negative)
 * @retval static_string Valid metric name string for recognized metric_id values
 * 
 * @note Thread-safe: Returns pointer to read-only static string
 * @warning Metric ID validation: Passing invalid metric_id returns "unknown" string
 * 
 * @see metrics.c:metric_names[] - String label array implementation
 * @see clear_metrics() - Reset all metric counters to zero
 * 
 * EXAMPLE USAGE:
 * @code
 * // Log metric value with human-readable name
 * int metric_id = METRIC_DNS_QUERIES_FORWARDED;
 * unsigned int count = daemon->metrics[metric_id];
 * const char *name = get_metric_name(metric_id);
 * my_syslog(LOG_INFO, "Metric %s: %u", name, count);
 * // Output: "Metric dns_queries_forwarded: 12345"
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (internal monitoring interface)
 * SIDE EFFECTS: None (read-only operation)
 * THREAD SAFETY: Thread-safe (returns pointer to static read-only data)
 */
const char* get_metric_name(int);

/**
 * @brief Reset all metric counters to zero
 * 
 * @detailed
 * This function resets all metric counters in the daemon->metrics[] array to zero,
 * effectively clearing all accumulated statistics. This operation is typically performed
 * during daemon initialization or configuration reload to establish a fresh baseline
 * for metric collection.
 * 
 * The function iterates through all __METRIC_MAX metrics and sets each counter to zero.
 * This is a destructive operation with no undo capability—metric history is permanently lost.
 * 
 * INVOCATION CONTEXTS:
 * - Daemon startup: Initialize metrics to zero on first daemon startup
 * - Configuration reload: Reset metrics on SIGHUP configuration reload
 * - Administrative reset: Manual metric reset via D-Bus/UBus control interface
 * - Periodic reset: Automated metric reset for time-windowed statistics collection
 * 
 * OPERATIONAL IMPACT:
 * - All accumulated metric counters immediately become zero
 * - Cache hit/miss ratios calculations reset to baseline
 * - DHCP transaction counts cleared (administrative view only, actual leases unaffected)
 * - DNSSEC high-water marks reset (will rebuild based on subsequent operations)
 * 
 * @note Single-threaded: No locking required due to event-driven architecture
 * @warning Data loss: All accumulated metric history permanently discarded
 * @warning High-water marks: DNSSEC HWM metrics reset and will re-accumulate from zero
 * 
 * @see get_metric_name() - Retrieve metric names for identification
 * @see daemon->metrics[] - Actual metric counter storage array
 * 
 * EXAMPLE USAGE:
 * @code
 * // Reset metrics during configuration reload
 * if (config_reload_requested) {
 *   clear_metrics();
 *   my_syslog(LOG_INFO, "Metrics reset to zero on configuration reload");
 * }
 * 
 * // Administrative reset via D-Bus method
 * if (dbus_reset_metrics_requested) {
 *   clear_metrics();
 *   return dbus_success_response();
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (internal monitoring operation)
 * SIDE EFFECTS: All daemon->metrics[] array elements set to zero
 * THREAD SAFETY: Single-threaded architecture—no locking required
 */
void clear_metrics(void);

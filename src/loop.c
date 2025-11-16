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
 * @file loop.c
 * @brief Upstream DNS forwarding loop detection and prevention
 * 
 * DETAILED PURPOSE:
 * This module implements DNS forwarding loop detection to prevent circular query paths
 * in complex network topologies where multiple dnsmasq instances or DNS forwarders
 * might create forwarding loops. Without loop detection, a misconfigured network
 * where dnsmasq instance A forwards to instance B, which forwards back to A, would
 * result in infinite query recursion, resource exhaustion, and denial of service.
 * 
 * The implementation uses a probe-based detection mechanism: periodically sending
 * specially crafted DNS queries with unique identifiers to each upstream server.
 * If dnsmasq receives its own probe query back (detecting the embedded UID), it
 * identifies a forwarding loop and marks the upstream server to prevent future
 * forwarding to that server, breaking the loop.
 * 
 * KEY RESPONSIBILITIES:
 * - loop_send_probes(): Periodically transmit unique probe queries to all general-purpose
 *   upstream servers to detect forwarding loops before they cause operational issues
 * - loop_make_probe(): Construct probe DNS packets with embedded unique identifiers
 *   formatted as 8-character hex UID plus reserved test domain
 * - detect_loop(): Analyze incoming DNS queries to identify loop detection probes,
 *   extract the UID, match against known server UIDs, and mark looping servers
 * 
 * DEPENDENCIES:
 * Includes: dnsmasq.h for core data structures (struct server, struct daemon, struct dns_header)
 * Called by: Main event loop (dnsmasq.c) invokes loop_send_probes() periodically;
 *            DNS query processing (forward.c) invokes detect_loop() for incoming queries
 * Calls: Network functions (allocate_rfd, free_rfds, sendto) for probe transmission;
 *        Server management (check_servers) when loops detected
 * 
 * DATA STRUCTURES:
 * - struct server: Upstream DNS server definition with uid field (line ~620 in dnsmasq.h)
 *   containing unique identifier for loop detection; flags field includes SERV_LOOP bit
 * - struct daemon: Global daemon state providing packet buffer and server list
 * - struct dns_header: DNS packet header structure for probe query construction
 * 
 * COMPILE-TIME OPTIONS:
 * - HAVE_LOOP: Entire module conditionally compiled with this flag; when disabled,
 *   loop detection functionality is completely excluded from binary, saving ~2KB code size
 * - LOOP_TEST_DOMAIN: Domain name for probe queries (default "test", RFC 2606 reserved)
 *   defined in src/config.h line 66
 * - LOOP_TEST_TYPE: DNS query type for probes (default T_TXT) defined in src/config.h line 67
 * - OPT_LOOP_DETECT: Runtime configuration option to enable/disable loop detection
 *   defined in src/dnsmasq.h
 * 
 * LOOP DETECTION MECHANISM:
 * 1. Each upstream server struct contains a unique 32-bit identifier (uid field)
 * 2. Probe queries are constructed with domain name: "<8-hex-uid>.test" (e.g., "a1b2c3d4.test")
 * 3. Probes sent periodically to all general-purpose upstream servers (not domain-specific servers)
 * 4. If dnsmasq receives a query matching probe format, detect_loop() extracts the UID
 * 5. UID compared against all configured upstream servers; match indicates loop
 * 6. Matching server marked with SERV_LOOP flag, preventing future query forwarding to it
 * 7. check_servers() logs the loop detection event and updates server selection logic
 * 
 * INTEGRATION WITH FORWARD.C:
 * Loop detection is tightly integrated with the DNS query forwarding engine in forward.c.
 * Before forwarding a query to an upstream server, forward.c checks the SERV_LOOP flag.
 * Servers marked with SERV_LOOP are excluded from the forwarding rotation, preventing
 * queries from being sent into detected loops. This integration ensures that loop
 * detection directly protects the forwarding path without requiring architectural changes.
 * 
 * RELIABILITY AND CRITICAL IMPORTANCE:
 * Loop detection is critical for operational reliability in multi-level DNS forwarding
 * scenarios including:
 * - Multiple dnsmasq instances in network hierarchy (edge routers forwarding to core routers)
 * - Split-horizon DNS with potential misconfiguration creating circular forwarding
 * - VPN environments where tunnel DNS forwarding might loop back to origin
 * - Recursive resolver chains where upstream server is itself a forwarder
 * 
 * Without loop detection, forwarding loops cause:
 * - Query amplification: Single client query becomes hundreds or thousands of recursive queries
 * - Resource exhaustion: File descriptor, memory, and CPU exhaustion from query storms
 * - Network congestion: UDP packet floods between looping servers
 * - Service failure: Daemon becomes unresponsive, legitimate queries time out
 * 
 * THREADING/CONCURRENCY:
 * Single-threaded architecture with event-driven execution. Probe transmission occurs
 * during periodic maintenance cycles in main event loop. Loop detection occurs inline
 * during query reception processing. No thread synchronization required.
 * 
 * @copyright Copyright (c) 2000-2025 Simon Kelley
 * @license GPL-2.0-or-later
 */

#include "dnsmasq.h"

#ifdef HAVE_LOOP
static ssize_t loop_make_probe(u32 uid);

/**
 * @brief Transmit loop detection probe queries to all general-purpose upstream DNS servers
 * 
 * @detailed This function implements the proactive component of loop detection by periodically
 * sending specially crafted probe DNS queries to each configured upstream server. Each probe
 * contains a unique identifier (UID) specific to the target server, enabling later detection
 * if the probe query returns to this dnsmasq instance (indicating a forwarding loop).
 * 
 * The function iterates through the daemon's server list (daemon->servers linked list), 
 * identifying general-purpose upstream servers (those without domain-specific forwarding rules).
 * For each eligible server, it constructs a probe query with loop_make_probe(), allocates
 * a random file descriptor via allocate_rfd() to send the probe, and transmits the probe
 * packet using sendto(). Any existing SERV_LOOP flag is cleared before transmission to allow
 * re-detection if loop conditions change (server configuration changes, network topology changes).
 * 
 * Servers are filtered to exclude:
 * - Domain-specific servers (strlen(serv->domain) > 0): These forward only specific domains,
 *   so loops are contained to those domains and less critical
 * - SERV_FOR_NODOTS servers: Special-purpose servers for unqualified names
 * 
 * The function uses the retry_send() wrapper around sendto() to handle EINTR and transient
 * network errors, ensuring probe transmission succeeds despite signal interruptions.
 * 
 * @note This function is called periodically from the main event loop in dnsmasq.c, typically
 * every few minutes, to continuously monitor for newly introduced forwarding loops.
 * 
 * @note Probe transmission is low-overhead: single small UDP packet per upstream server.
 * Even with dozens of upstream servers, total bandwidth is negligible (<1KB/probe cycle).
 * 
 * @warning If OPT_LOOP_DETECT runtime option is disabled (--loop-detect=no), this function
 * returns immediately without sending probes, allowing loop detection to be disabled for
 * networks known to be loop-free (performance optimization for high-query-rate scenarios).
 * 
 * @see loop_make_probe() for probe packet construction details
 * @see detect_loop() for probe reception and loop identification logic
 * @see check_servers() in dnsmasq.c for server state logging when loops detected
 * @see allocate_rfd() in network.c for random file descriptor allocation preventing
 *      upstream servers from tracking dnsmasq via source port fingerprinting
 * 
 * EXAMPLE USAGE:
 * @code
 * // Called from main event loop's periodic maintenance cycle
 * // Example scenario: Two dnsmasq instances misconfigured
 * // Instance A (192.168.1.1) forwards to Instance B (192.168.2.1)
 * // Instance B forwards back to Instance A
 * loop_send_probes();  // Instance A sends probes with UIDs to B
 * // Instance B receives probes, forwards them back to A
 * // Instance A's detect_loop() identifies returning probe, sets SERV_LOOP on B
 * // Future queries from A will skip B, breaking the loop
 * @endcode
 * 
 * LOOP DETECTION SCENARIOS:
 * Scenario 1: Direct loop
 *   - dnsmasq A forwards to dnsmasq B
 *   - dnsmasq B forwards to dnsmasq A
 *   - A's probe reaches B, B forwards to A, A detects its own probe
 * 
 * Scenario 2: Multi-hop loop
 *   - dnsmasq A forwards to B, B forwards to C, C forwards to A
 *   - A's probe travels A→B→C→A, detected when arriving back at A
 * 
 * Scenario 3: Conditional loop (split-horizon DNS)
 *   - Certain domains loop while others don't
 *   - General probes detect loop; domain-specific servers excluded from detection
 * 
 * RFC COMPLIANCE: Loop detection uses reserved "test" domain per RFC 2606 Section 2,
 * ensuring probes don't interfere with legitimate DNS queries.
 * 
 * SIDE EFFECTS:
 * - Clears SERV_LOOP flag on all targeted servers before sending probes (line 39)
 * - Allocates temporary random file descriptors for probe transmission
 * - Sends UDP packets to each upstream server (network I/O)
 * - Modifies daemon->packet buffer contents for probe construction
 * - Sets daemon->srv_save = NULL in loop_make_probe() (packet buffer overwrite)
 * 
 * THREAD SAFETY: Single-threaded architecture; no synchronization required.
 * Function called from main event loop only.
 */
void loop_send_probes(void)
{
   struct server *serv;
   struct randfd_list *rfds = NULL;
   
   if (!option_bool(OPT_LOOP_DETECT))
     return;

   /* Loop through all upstream servers not for particular domains, and send a query to that server which is
      identifiable, via the uid. If we see that query back again, then the server is looping, and we should not use it. */
   for (serv = daemon->servers; serv; serv = serv->next)
     if (strlen(serv->domain) == 0 &&
	 !(serv->flags & (SERV_FOR_NODOTS)))
       {
	 ssize_t len = loop_make_probe(serv->uid);
	 int fd;
	 
	 serv->flags &= ~SERV_LOOP;

	 if ((fd = allocate_rfd(&rfds, serv)) == -1)
	   continue;
	 
	 while (retry_send(sendto(fd, daemon->packet, len, 0, 
				  &serv->addr.sa, sa_len(&serv->addr))));
       }

   free_rfds(&rfds);
}

/**
 * @brief Construct a DNS probe query packet with embedded unique identifier
 * 
 * @detailed This static helper function builds a specially formatted DNS query packet
 * used for forwarding loop detection. The probe packet contains a unique 32-bit identifier
 * (UID) encoded as an 8-character hexadecimal string in the query domain name, followed
 * by the reserved test domain (LOOP_TEST_DOMAIN, default "test"). The complete query
 * name format is: "<8-hex-uid>.test" (e.g., "a1b2c3d4.test").
 * 
 * The probe packet is constructed directly in daemon->packet buffer, which is shared
 * across DNS processing operations. The function sets daemon->srv_save = NULL to indicate
 * that any previously stored server state is invalidated by packet buffer overwrite.
 * 
 * DNS packet structure created:
 * - DNS header: Random transaction ID, standard query opcode, recursion desired (RD) flag set
 * - Question section: Single query for "<uid>.test" domain with LOOP_TEST_TYPE (default T_TXT)
 * - Answer/Authority/Additional sections: All empty (counts set to 0)
 * 
 * Domain name encoding follows DNS wire format (RFC 1035 Section 4.1.2):
 * - First label: Length byte (8) followed by 8 hex characters of UID
 * - Second label: Length byte (strlen(LOOP_TEST_DOMAIN)) followed by domain name
 * - Name terminator: Zero byte
 * 
 * @param uid Unique 32-bit identifier for the target upstream server (from serv->uid).
 *            Each server in daemon->servers list has a unique UID assigned at configuration
 *            time. The UID enables identification of the probe's origin when received.
 * 
 * @return Packet length in bytes from start of DNS header to end of constructed query.
 *         Typical return value: 30-35 bytes (header 12 + question section 18-23).
 *         Return value used as length parameter for sendto() system call.
 * 
 * @note Function is static (file-local scope), only called by loop_send_probes() within
 *       this module. Not exposed in dnsmasq.h header or accessible externally.
 * 
 * @note UID encoding as hex string ensures all characters are valid DNS label characters
 *       (alphanumeric only), avoiding need for special encoding or escaping.
 * 
 * @note Random transaction ID (header->id = rand16()) prevents cache pollution if probe
 *       query is processed by caching resolvers along the path, and enables correlation
 *       if responses are received (though responses are not expected for probe queries).
 * 
 * @warning daemon->packet buffer is shared across all DNS processing operations. Caller
 *          (loop_send_probes) must use packet immediately after construction, as subsequent
 *          DNS operations will overwrite the buffer contents.
 * 
 * @warning Function modifies daemon->srv_save global variable, invalidating any saved
 *          server state. This is safe during probe transmission as no query forwarding
 *          context needs preservation.
 * 
 * @see loop_send_probes() for probe transmission logic
 * @see detect_loop() for probe parsing and UID extraction on reception
 * @see struct dns_header in dnsmasq.h for DNS header structure definition (line ~260)
 * @see LOOP_TEST_DOMAIN in src/config.h line 66 (default "test", RFC 2606 reserved)
 * @see LOOP_TEST_TYPE in src/config.h line 67 (default T_TXT)
 * 
 * EXAMPLE USAGE:
 * @code
 * // Example: Construct probe for server with UID 0xa1b2c3d4
 * struct server *serv = ...; // Upstream server with serv->uid = 0xa1b2c3d4
 * ssize_t len = loop_make_probe(serv->uid);
 * // Result: daemon->packet contains DNS query for "a1b2c3d4.test"
 * // len = 33 bytes (header 12 + question 21)
 * // Ready for sendto(fd, daemon->packet, len, ...)
 * @endcode
 * 
 * PROBE PACKET WIRE FORMAT (hex dump example):
 * @code
 * // Query for "a1b2c3d4.test" with TXT record type
 * // Transaction ID: Random 16-bit value (e.g., 0x1234)
 * 12 34    // ID: 0x1234
 * 01 00    // Flags: Standard query, RD=1
 * 00 01    // QDCOUNT: 1 question
 * 00 00    // ANCOUNT: 0 answers
 * 00 00    // NSCOUNT: 0 authority records
 * 00 00    // ARCOUNT: 0 additional records
 * 08       // Label length: 8 bytes
 * 61 31 62 32 63 33 64 34  // "a1b2c3d4" (hex digits)
 * 04       // Label length: 4 bytes
 * 74 65 73 74  // "test"
 * 00       // Name terminator
 * 00 10    // QTYPE: T_TXT (16)
 * 00 01    // QCLASS: C_IN (1)
 * @endcode
 * 
 * RFC COMPLIANCE: 
 * - DNS packet format per RFC 1035 Section 4
 * - Reserved "test" domain per RFC 2606 Section 2 (reserved for testing/documentation)
 * - TXT record type per RFC 1035 Section 3.3.14
 * 
 * SIDE EFFECTS:
 * - Overwrites daemon->packet buffer (global packet buffer)
 * - Sets daemon->srv_save = NULL (invalidates saved server state)
 * - Calls rand16() for transaction ID generation (advances RNG state)
 * 
 * THREAD SAFETY: Single-threaded architecture; function accesses global daemon structure.
 * Safe as only called from main event loop context.
 */
  
static ssize_t loop_make_probe(u32 uid)
{
  struct dns_header *header = (struct dns_header *)daemon->packet;
  unsigned char *p = (unsigned char *)(header+1);
  
  /* packet buffer overwritten */
  daemon->srv_save = NULL;
  
  header->id = rand16();
  header->ancount = header->nscount = header->arcount = htons(0);
  header->qdcount = htons(1);
  header->hb3 = HB3_RD;
  header->hb4 = 0;
  SET_OPCODE(header, QUERY);

  *p++ = 8;
  sprintf((char *)p, "%.8x", uid);
  p += 8;
  *p++ = strlen(LOOP_TEST_DOMAIN);
  strcpy((char *)p, LOOP_TEST_DOMAIN); /* Add terminating zero */
  p += strlen(LOOP_TEST_DOMAIN) + 1;

  PUTSHORT(LOOP_TEST_TYPE, p);
  PUTSHORT(C_IN, p);

  return p - (unsigned char *)header;
}

/**
 * @brief Detect forwarding loops by identifying returning probe queries
 * 
 * @detailed This function implements the reactive component of loop detection by analyzing
 * incoming DNS queries to determine if they match the probe query format sent by
 * loop_send_probes(). When a probe query returns to its origin dnsmasq instance, it
 * indicates that a forwarding loop exists in the upstream server chain.
 * 
 * The detection algorithm performs several validation steps:
 * 1. Runtime option check: Return immediately if OPT_LOOP_DETECT is disabled
 * 2. Query type validation: Verify type matches LOOP_TEST_TYPE (default T_TXT)
 * 3. Query name length validation: Ensure length is exactly 8 + 1 + strlen(LOOP_TEST_DOMAIN)
 *    (8 hex chars + dot + domain name, e.g., "a1b2c3d4.test" = 8 + 1 + 4 = 13 chars)
 * 4. Domain suffix validation: Verify query ends with LOOP_TEST_DOMAIN at correct position
 * 5. Hexadecimal validation: Confirm first 8 characters are valid hex digits (0-9, a-f, A-F)
 * 6. UID extraction: Parse first 8 characters as hexadecimal integer (base 16)
 * 7. Server matching: Search daemon->servers linked list for server with matching UID
 * 
 * When a match is found (indicating the probe has looped back), the function:
 * - Sets SERV_LOOP flag on the matching server (serv->flags |= SERV_LOOP)
 * - Calls check_servers(1) to log the loop detection event and update server state
 * - Returns 1 to indicate loop detected
 * 
 * The SERV_LOOP flag prevents future query forwarding to the looping server in forward.c,
 * effectively breaking the loop by removing the problematic server from the forwarding
 * rotation. The server remains in the configuration but is bypassed for query forwarding.
 * 
 * Only general-purpose upstream servers (strlen(serv->domain) == 0) are checked, matching
 * the filtering logic in loop_send_probes(). Domain-specific servers are excluded from
 * loop detection as their forwarding scope is limited and loops are less critical.
 * 
 * @param query Domain name from incoming DNS query as null-terminated string in DNS
 *              wire format (length-prefixed labels converted to dotted notation).
 *              Expected format for probe: "<8-hex-uid>.<domain>" (e.g., "a1b2c3d4.test").
 *              The query string is provided by the DNS packet parsing code in rfc1035.c
 *              which extracts the QNAME from the question section of incoming packets.
 * 
 * @param type DNS query type (QTYPE) from the question section of the incoming DNS packet.
 *             Must match LOOP_TEST_TYPE (default T_TXT = 16) for probe query identification.
 *             Non-matching types are immediately rejected (return 0) as normal queries.
 * 
 * @return 1 if forwarding loop detected (probe query matched a known server UID and
 *         SERV_LOOP flag was set), 0 otherwise (not a probe, probe doesn't match any
 *         server, loop detection disabled, or validation failed at any step).
 * @retval 1 Loop detected: Probe query matched an upstream server UID; SERV_LOOP flag
 *           set on the matching server; check_servers() called to log event
 * @retval 0 No loop detected: Query is not a probe, probe format invalid, no UID match,
 *           or OPT_LOOP_DETECT runtime option disabled
 * 
 * @note Function is called from DNS query reception path in forward.c (receive_query())
 *       for EVERY incoming DNS query. Performance is critical; early return checks
 *       (option disabled, type mismatch) minimize overhead for non-probe queries.
 * 
 * @note The SERV_LOOP flag is persistent across probe cycles. Once set, it remains until
 *       the next loop_send_probes() cycle clears it (line 39 in loop_send_probes()),
 *       allowing re-detection if loop conditions change.
 * 
 * @note UID extraction uses strtol() with base 16 (hexadecimal parsing). Invalid hex
 *       strings are rejected by the isxdigit() validation loop before strtol() is called,
 *       preventing potential parsing errors or unexpected behavior.
 * 
 * @warning Function modifies server state (sets SERV_LOOP flag) when loop is detected.
 *          This state change affects query forwarding behavior in forward.c immediately.
 * 
 * @warning check_servers(1) call (line 368) performs logging and may trigger additional
 *          server state updates. The argument '1' signals "don't send more probes" to
 *          prevent recursive probe transmission during loop handling.
 * 
 * @see loop_send_probes() for probe transmission that generates detectable queries
 * @see loop_make_probe() for probe packet construction format
 * @see check_servers() in dnsmasq.c for server state logging and management
 * @see forward.c:receive_query() for integration point (calls detect_loop early in processing)
 * @see forward.c:forward_query() for SERV_LOOP flag checking before forwarding
 * @see struct server in dnsmasq.h line ~620 for server structure with flags and uid fields
 * 
 * EXAMPLE USAGE:
 * @code
 * // Example: Two dnsmasq instances creating a loop
 * // Instance A (192.168.1.1, UID 0xa1b2c3d4) forwards to Instance B (192.168.2.1)
 * // Instance B forwards back to Instance A
 * 
 * // Instance A sends probe: "a1b2c3d4.test" TXT query to Instance B
 * // Instance B receives probe, forwards to Instance A (not recognizing it as probe)
 * // Instance A receives query from B:
 * 
 * char *query = "a1b2c3d4.test";  // Extracted from DNS packet QNAME
 * int type = T_TXT;                 // Query type from DNS packet QTYPE
 * 
 * int loop_detected = detect_loop(query, type);
 * // Returns: 1 (loop detected)
 * // Side effect: Server B marked with SERV_LOOP flag
 * // Side effect: check_servers() logs: "possible DNS loop detected for server 192.168.2.1"
 * // Result: Future queries from A will skip server B, breaking the loop
 * @endcode
 * 
 * DETECTION VALIDATION FLOW:
 * @code
 * // Step-by-step validation for query "a1b2c3d4.test" TXT:
 * // 1. option_bool(OPT_LOOP_DETECT) == true? → Continue
 * // 2. type (16) == LOOP_TEST_TYPE (16)? → Continue
 * // 3. strlen("a1b2c3d4.test") == strlen("test") + 9? → 13 == 4 + 9 → Continue
 * // 4. strstr("a1b2c3d4.test", "test") == "a1b2c3d4.test" + 9? → "test" at position 9 → Continue
 * // 5. isxdigit('a') && isxdigit('1') && ... && isxdigit('4')? → All valid hex → Continue
 * // 6. uid = strtol("a1b2c3d4", NULL, 16) → 0xa1b2c3d4
 * // 7. Search servers: find server with uid == 0xa1b2c3d4 → Match found
 * // 8. Set SERV_LOOP flag, call check_servers(1), return 1
 * @endcode
 * 
 * FALSE POSITIVE PREVENTION:
 * The multiple validation steps prevent false positives from legitimate queries:
 * - Random domain "a1b2c3d4.example.com" → Fails domain suffix check (not ".test")
 * - Query "12345678.test" A record → Fails type check (A != T_TXT)
 * - Query "toolong01.test" TXT → Fails length check (10 chars != 8 chars)
 * - Query "invalid!.test" TXT → Fails hex validation ('!' not hexadecimal)
 * 
 * INTEGRATION WITH FORWARD.C QUERY FORWARDING:
 * Loop detection integrates at two critical points in forward.c:
 * 
 * 1. Query Reception (forward.c:receive_query()):
 *    - detect_loop() called early in query processing
 *    - If loop detected (return 1), query is NOT forwarded further
 *    - Prevents loop amplification by stopping circulation immediately
 * 
 * 2. Upstream Server Selection (forward.c:forward_query()):
 *    - Before forwarding to an upstream server, check: !(serv->flags & SERV_LOOP)
 *    - Servers with SERV_LOOP flag are excluded from forwarding rotation
 *    - Ensures queries never enter detected loop paths
 * 
 * This two-point integration provides defense-in-depth:
 * - Incoming loop probes are identified and stop circulation
 * - Outgoing queries avoid servers known to create loops
 * 
 * OPERATIONAL BEHAVIOR OVER TIME:
 * T=0: Initial configuration, no loops detected
 *      → All upstream servers available for forwarding
 * 
 * T=5min: First probe cycle (loop_send_probes())
 *         → Probes sent to all servers, server B returns probe
 *         → detect_loop() identifies loop, sets SERV_LOOP on server B
 *         → Server B excluded from forwarding rotation
 * 
 * T=10min: Second probe cycle
 *          → loop_send_probes() clears SERV_LOOP flags (line 39)
 *          → Probes sent again to test if loop resolved
 *          → If loop persists, detect_loop() sets SERV_LOOP again
 *          → If loop resolved (B no longer forwards to A), flag stays clear
 * 
 * This periodic re-testing allows automatic recovery when loop conditions change
 * (network reconfiguration, server configuration updates, etc.).
 * 
 * RFC COMPLIANCE:
 * - Uses reserved "test" domain per RFC 2606 Section 2 (reserved for testing)
 * - TXT record type per RFC 1035 Section 3.3.14
 * - Query processing follows DNS wire format per RFC 1035 Section 4
 * 
 * SIDE EFFECTS:
 * - Sets SERV_LOOP flag on matching server (permanent until next probe cycle)
 * - Calls check_servers(1) which logs loop detection event to syslog
 * - Modifies query forwarding behavior in forward.c (excludes flagged server)
 * 
 * THREAD SAFETY: Single-threaded architecture; function called from main event loop
 * during query reception processing. No synchronization required.
 */
  

int detect_loop(char *query, int type)
{
  int i;
  u32 uid;
  struct server *serv;
  
  if (!option_bool(OPT_LOOP_DETECT))
    return 0;

  if (type != LOOP_TEST_TYPE ||
      strlen(LOOP_TEST_DOMAIN) + 9 != strlen(query) ||
      strstr(query, LOOP_TEST_DOMAIN) != query + 9)
    return 0;

  for (i = 0; i < 8; i++)
    if (!isxdigit((unsigned char)query[i]))
      return 0;

  uid = strtol(query, NULL, 16);

  for (serv = daemon->servers; serv; serv = serv->next)
    if (strlen(serv->domain) == 0 &&
	!(serv->flags & SERV_LOOP) &&
	uid == serv->uid)
      {
	serv->flags |= SERV_LOOP;
	check_servers(1); /* log new state - don't send more probes. */
	return 1;
      }
  
  return 0;
}

#endif

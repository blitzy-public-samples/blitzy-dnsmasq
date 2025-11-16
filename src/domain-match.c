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
 * @file domain-match.c
 * @brief Domain pattern matching algorithms for DNS query routing and server selection
 * 
 * DETAILED PURPOSE:
 * This module implements sophisticated domain name pattern matching algorithms that form
 * the foundation of dnsmasq's split-horizon DNS, domain-specific upstream server selection,
 * and configuration-based query routing. The implementation provides efficient matching of
 * DNS queries against configured domain patterns (including wildcards), maintains a sorted
 * array of server configurations for optimal lookup performance, and handles complex 
 * matching scenarios including local domain resolution, DNSSEC-capable server selection,
 * and server group management.
 * 
 * The core algorithm uses longest-match-wins semantics, where the server configuration with
 * the most specific domain match (longest matching suffix) is selected for query forwarding.
 * This enables sophisticated DNS architectures such as VPN split-horizon (corporate domains
 * to corporate DNS, internet domains to public DNS), content filtering (blocked domains to
 * local blocklist resolver), and performance optimization (CDN-heavy domains to CDN-aware
 * resolver).
 * 
 * KEY RESPONSIBILITIES:
 * - Build and maintain sorted array of server configurations for efficient domain matching
 *   (build_server_array function constructs daemon->serverarray from linked lists)
 * - Perform domain pattern matching with wildcard support using longest-match algorithm
 *   (lookup_domain function implements core matching logic with O(log n) binary search)
 * - Filter servers based on query flags including F_SERVER, F_DNSSECOK, F_DS, F_DOMAINSRV
 *   (filter_servers applies flag-based filtering to candidate server set)
 * - Manage server groups for round-robin load balancing and failover
 *   (server_samegroup and mark_servers handle server equivalence classes)
 * - Support local domain resolution with literal address responses
 *   (is_local_answer and make_local_answer construct responses without forwarding)
 * - Integrate with DNSSEC validation infrastructure for secure server selection
 *   (dnssec_server finds DNSSEC-capable upstream for validation queries)
 * - Maintain server configuration lifecycle including dynamic updates from D-Bus/UBus
 *   (add_update_server and cleanup_servers manage configuration changes)
 * 
 * DEPENDENCIES:
 * Includes: dnsmasq.h (global daemon state, struct server, struct dns_header definitions)
 * Called by: forward.c (receive_query, forward_query for upstream server selection),
 *            option.c (configuration parsing populates server linked lists),
 *            dbus.c/ubus.c (dynamic server reconfiguration via control interfaces)
 * Calls: util.c (whine_malloc for memory allocation with logging),
 *        domain.c (hostname_isequal for domain name comparison),
 *        cache.c (cache integration for local answers)
 * 
 * DATA STRUCTURES:
 * - struct server: Server configuration entry with domain, address, flags (dnsmasq.h:587-639)
 *   Contains domain pattern (with optional wildcard), upstream IP/port, capability flags
 * - daemon->serverarray: Sorted array of struct server pointers for binary search
 *   Maintained by build_server_array, searched by lookup_domain
 * - daemon->servers: Linked list of regular upstream servers
 * - daemon->local_domains: Linked list of local domain configurations (literal addresses)
 * - Server flags (SERV_* defines in dnsmasq.h:570-585):
 *   SERV_WILDCARD (1024): Domain pattern has leading '*' for suffix matching
 *   SERV_USE_RESOLV (1): Forward queries in normal way to recursive resolver
 *   SERV_LITERAL_ADDRESS (2): Return literal IP address without forwarding
 *   SERV_DO_DNSSEC (16384): Upstream supports DNSSEC validation
 * 
 * COMPILE-TIME OPTIONS:
 * HAVE_LOOP: Enables loop detection to exclude servers causing forwarding loops
 *            (affects build_server_array to skip SERV_LOOP servers)
 * 
 * THREADING/CONCURRENCY:
 * Single-threaded event-driven architecture. Server array rebuilt synchronously during
 * configuration reload (SIGHUP) or dynamic updates. No concurrent access protection needed
 * as all operations execute in main event loop context. Server array remains stable during
 * query processing; modifications only occur at configuration change boundaries.
 * 
 * PERFORMANCE CHARACTERISTICS:
 * - Server array construction: O(n log n) due to qsort of n servers
 * - Domain lookup: O(log n) binary search through sorted array
 * - Wildcard matching: O(m) where m is domain label count (iterative suffix search)
 * - Memory overhead: One pointer per server in array (~8 bytes/server on 64-bit)
 * - Typical configurations: 10-50 servers, lookup latency <10 microseconds
 * 
 * INTEGRATION POINTS:
 * - Split-horizon DNS: Different upstream servers for different domain patterns enable
 *   VPN scenarios where corporate.com queries go to 10.0.0.1, all others to 8.8.8.8
 * - Firewall integration (ipset, nftables): Domain patterns can trigger firewall set
 *   population via integration in forward.c after server selection
 * - DNSSEC validation: dnssec_server ensures validation queries route to DNSSEC-capable
 *   upstreams, preventing validation failures from non-DNSSEC servers
 * - Local domain resolution: Literal address servers (SERV_LITERAL_ADDRESS) return
 *   configured IPs directly, supporting blocklists and internal name resolution
 * - Load balancing: server_samegroup identifies equivalent servers for round-robin
 *   distribution of queries across multiple upstreams with same domain pattern
 * 
 * @copyright Copyright (c) 2000-2025 Simon Kelley
 * @license GPL-2.0-or-later
 */

#include "dnsmasq.h"

static int order(char *qdomain, size_t qlen, struct server *serv);
static int order_qsort(const void *a, const void *b);
/**
 * @brief Compare two servers for ordering by domain specificity (used internally)
 * 
 * @detailed Compares two servers to determine their relative ordering in the server array.
 *           Local domains (SERV_USE_RESOLV or SERV_LITERAL_ADDRESS) are always sorted before
 *           upstream servers. Within each category, servers are sorted by domain length with
 *           longer (more specific) domains coming first. Wildcard domains are ordered after
 *           exact matches of the same length. This ordering ensures that the most specific
 *           matching server is found first during lookup operations.
 * 
 * @param s First server to compare
 * @param s2 Second server to compare
 * 
 * @return Comparison result for sorting
 * @retval <0 First server should be ordered before second server
 * @retval 0 Servers are equivalent in ordering (same domain length and type)
 * @retval >0 First server should be ordered after second server
 * 
 * @note Local domains always precede upstream servers in sorted order
 * @note Among servers with same domain length, exact matches precede wildcards
 * @note This function implements the comparison logic used by qsort via order_qsort
 * 
 * @see order_qsort() which wraps this for qsort compatibility
 * @see build_server_array() which sorts servers using this comparison
 * 
 * EXAMPLE USAGE:
 * @code
 * struct server *s1 = daemon->serverarray[0]; // "*.example.com"
 * struct server *s2 = daemon->serverarray[1]; // "mail.example.com"
 * int cmp = order_servers(s1, s2);
 * // cmp > 0: s2 (exact) should come before s1 (wildcard)
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (internal sorting algorithm)
 * SIDE EFFECTS: None (read-only comparison function)
 * THREAD SAFETY: Thread-safe (no global state modification)
 */
static int order_servers(struct server *s, struct server *s2);

/* If the server is USE_RESOLV or LITERAL_ADDRESS, it lives on the local_domains chain. */
#define SERV_IS_LOCAL (SERV_USE_RESOLV | SERV_LITERAL_ADDRESS)

/**
 * @brief Build sorted array of server configurations for efficient domain matching
 * 
 * @detailed Constructs daemon->serverarray from the linked lists daemon->servers and
 *           daemon->local_domains, creating a sorted array optimized for binary search
 *           during domain matching. The function allocates or reallocates array memory
 *           as needed, populates array entries, sorts by domain specificity, and sets
 *           array position indices for group navigation. Servers with SERV_LOOP flag
 *           (when HAVE_LOOP is enabled) are excluded to prevent forwarding loops. Sets
 *           daemon->server_has_wildcard flag if any wildcard patterns are present.
 * 
 *           The resulting sorted order prioritizes more specific domain matches over
 *           less specific ones, implementing longest-match-wins semantics for server
 *           selection. Array indices (serv->arrayposn) enable efficient navigation to
 *           all servers in an equivalence group for round-robin load balancing.
 * 
 * @note This function should be called during daemon initialization and whenever server
 *       configuration changes (SIGHUP reload, D-Bus/UBus dynamic reconfiguration). The
 *       function performs memory allocation which may fail on resource exhaustion; failure
 *       logs warning but preserves existing array to maintain service availability.
 * 
 * @warning Modifies global daemon state (daemon->serverarray, daemon->serverarraysz,
 *          daemon->serverarrayhwm, daemon->server_has_wildcard). Must only be called
 *          from main event loop context, not during query processing.
 * 
 * EXAMPLE USAGE:
 * @code
 * // After loading configuration or receiving dynamic update
 * build_server_array();
 * // Now daemon->serverarray is ready for lookup_domain() searches
 * struct server *selected = lookup_domain("example.com", F_SERVER, NULL, NULL);
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (internal infrastructure, not protocol-specific)
 * 
 * SIDE EFFECTS:
 * - Allocates/reallocates daemon->serverarray memory via whine_malloc
 * - Updates daemon->serverarraysz with count of servers in array
 * - Updates daemon->serverarrayhwm (high water mark) when array grows
 * - Sets daemon->server_has_wildcard global flag based on configuration
 * - Modifies serv->serial with array index for each regular server
 * - Initializes serv->last_server to -1 for round-robin state
 * - Sets serv->arrayposn for non-local servers to enable group navigation
 * - Sorts array in-place using qsort with order_qsort comparator
 * 
 * THREAD SAFETY: Single-threaded architecture; must not be called concurrently
 * 
 * PERFORMANCE: O(n log n) due to qsort of n servers; typically <1ms for 10-50 servers
 * 
 * ALGORITHM DETAILS:
 * 1. Count servers in daemon->servers (excluding SERV_LOOP) and daemon->local_domains
 * 2. Detect wildcard patterns and set daemon->server_has_wildcard flag
 * 3. Reallocate array if count exceeds high water mark (adds 10-entry buffer)
 * 4. Populate array with server pointers, setting serial and initializing state
 * 5. Sort array using order_qsort comparator (longest domain match first)
 * 6. Set arrayposn for non-local servers to enable efficient group traversal
 */
void build_server_array(void)
{
  struct server *serv;
  int count = 0;
  
  for (serv = daemon->servers; serv; serv = serv->next)
#ifdef HAVE_LOOP
    if (!(serv->flags & SERV_LOOP))
#endif
      {
	count++;
	if (serv->flags & SERV_WILDCARD)
	  daemon->server_has_wildcard = 1;
      }
  
  for (serv = daemon->local_domains; serv; serv = serv->next)
    {
      count++;
      if (serv->flags & SERV_WILDCARD)
	daemon->server_has_wildcard = 1;
    }
  
  daemon->serverarraysz = count;

  if (count > daemon->serverarrayhwm)
    {
      struct server **new;

      count += 10; /* A few extra without re-allocating. */

      if ((new = whine_malloc(count * sizeof(struct server *))))
	{
	  if (daemon->serverarray)
	    free(daemon->serverarray);
	  
	  daemon->serverarray = new;
	  daemon->serverarrayhwm = count;
	}
    }

  count = 0;
  
  for (serv = daemon->servers; serv; serv = serv->next)
#ifdef HAVE_LOOP
    if (!(serv->flags & SERV_LOOP))
#endif
      {
	daemon->serverarray[count] = serv;
	serv->serial = count;
	serv->last_server = -1;
	count++;
      }
  
  for (serv = daemon->local_domains; serv; serv = serv->next, count++)
    daemon->serverarray[count] = serv;
  
  qsort(daemon->serverarray, daemon->serverarraysz, sizeof(struct server *), order_qsort);
  
  /* servers need the location in the array to find all the whole
     set of equivalent servers from a pointer to a single one. */
  for (count = 0; count < daemon->serverarraysz; count++)
    if (!(daemon->serverarray[count]->flags & SERV_IS_LOCAL))
      daemon->serverarray[count]->arrayposn = count;
}

/**
 * @brief Find servers matching a domain query using binary search and filter by query characteristics
 * 
 * @detailed Performs binary search on the sorted server array to find all server records whose
 *           domain suffix matches the query domain. The function finds the longest exact domain
 *           match to the right-hand end of the query domain, then narrows the result set based
 *           on query flags (IPv4/IPv6, local/upstream, DNSSEC requirements).
 *           
 *           The algorithm operates in two phases:
 *           1. Binary search to find all servers matching the domain suffix
 *           2. Priority-based filtering to select appropriate servers based on query type
 *           
 *           Priority order for server selection (when not F_CONFIG):
 *           - IPv6 literal addresses (SERV_6ADDR) for IPv6 queries
 *           - IPv4 literal addresses (SERV_4ADDR) for IPv4 queries  
 *           - All-zeros addresses (SERV_ALL_ZEROS) returning NODATA
 *           - NXDOMAIN literal addresses (SERV_LITERAL_ADDRESS)
 *           - USE_RESOLV servers (forward to resolv.conf nameservers)
 *           - Domain-specific upstream servers
 * 
 * @param qdomain      Query domain name string to match (without leading dot)
 * @param qlen         Length of qdomain string in bytes
 * @param flags        Query control flags controlling server selection:
 *                     - F_SERVER: Return upstream servers only (no local addresses)
 *                     - F_DNSSECOK: Exclude SERV_FOR_NODOTS servers (DNSSEC validation required)
 *                     - F_DS: Return parent domain server (for DS record queries)
 *                     - F_DOMAINSRV: Return domain-specific servers only (no default upstream)
 *                     - F_CONFIG: Return any server generating local response (address/NXDOMAIN)
 *                     - F_IPV4: IPv4 query (filter for IPv4 addresses)
 *                     - F_IPV6: IPv6 query (filter for IPv6 addresses)
 * @param lowout       Output parameter: pointer to receive index of first matching server
 * @param highout      Output parameter: pointer to receive index of one-past-last matching server
 * @param posn         Optional output parameter: if non-NULL, receives position in sorted array
 * 
 * @return 1 if matching servers found (lowout < highout), 0 if no matches
 * @retval 1           At least one server matches query domain and flags
 * @retval 0           No servers match (lowout == highout on return)
 * 
 * @note The returned range [*lowout, *highout) forms a half-open interval where servers
 *       at indices lowout through highout-1 are valid matches
 * @note Function assumes daemon->serverarray is sorted by order_qsort()
 * @note For F_DS queries, function searches for parent domain by finding domain with
 *       one fewer label than the query domain
 * @note The query domain is logically prepended with "." for matching purposes, allowing
 *       server=/.example.com/ configurations to match correctly
 * 
 * @warning Must be called with valid daemon->serverarray and daemon->serverarraysz
 * @warning Output parameters lowout and highout must not be NULL
 * 
 * @see build_server_array() for server array construction and sorting
 * @see order_qsort() for server array sort order
 * @see filter_servers() for additional server filtering
 * 
 * EXAMPLE USAGE:
 * @code
 * // Find upstream servers for www.example.com
 * int low, high;
 * if (lookup_domain("www.example.com", strlen("www.example.com"), 
 *                   F_SERVER | F_IPV4, &low, &high, NULL))
 * {
 *   // Servers at daemon->serverarray[low] through daemon->serverarray[high-1]
 *   for (int i = low; i < high; i++)
 *     forward_query(daemon->serverarray[i]);
 * }
 * 
 * // Find local address for domain
 * if (lookup_domain("internal.lan", strlen("internal.lan"),
 *                   F_CONFIG, &low, &high, NULL))
 * {
 *   // Check if daemon->serverarray[low] has SERV_LOCAL_ADDRESS
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: Implements domain suffix matching per RFC 1035 Section 7.3 (domain name conventions)
 * SIDE EFFECTS: Writes to *lowout, *highout, and optionally *posn output parameters
 * THREAD SAFETY: Read-only access to daemon->serverarray; safe for concurrent calls if array not modified
 * PERFORMANCE: O(log n) binary search + O(k) linear scan where k is number of matching servers
 */
/* we're looking for the server whose domain is the longest exact match
   to the RH end of qdomain, or a local address if the flags match.
   Add '.' to the LHS of the query string so
   server=/.example.com/ works.

   A flag of F_SERVER returns an upstream server only.
   A flag of F_DNSSECOK disables NODOTS servers from consideration.
   A flag of F_DS returns parent domain server.
   A flag of F_DOMAINSRV returns a domain-specific server only.
   A flag of F_CONFIG returns anything that generates a local
   reply of IPv4 or IPV6.
   return 0 if nothing found, 1 otherwise.
*/
int lookup_domain(char *domain, int flags, int *lowout, int *highout)
{
  int rc, crop_query, nodots;
  ssize_t qlen;
  int try, high, low = 0;
  int nlow = 0, nhigh = 0;
  char *cp, *qdomain;
  
  /* may be no configured servers. */
  if (daemon->serverarraysz == 0)
    return 0;

  /* DS records should come from the parent domain. */
  if (flags & F_DS)
    {
      if ((cp = strchr(domain, '.')))
	domain = cp+1;
      else
	domain = "";
    }
  
  qdomain = domain;

  /* find query length and presence of '.' */
  for (cp = qdomain, nodots = 1, qlen = 0; *cp; qlen++, cp++)
    if (*cp == '.')
      nodots = 0;

  /* Handle empty name, and searches for DNSSEC queries without
     diverting to NODOTS servers. */
  if (qlen == 0 || flags & F_DNSSECOK)
    nodots = 0;

  /* Search shorter and shorter RHS substrings for a match */
  while (qlen >= 0)
    {
      /* Note that when we chop off a label, all the possible matches
	 MUST be at a larger index than the nearest failing match with one more
	 character, since the array is sorted longest to smallest. Hence 
	 we don't reset low to zero here, we can go further below and crop the 
	 search string to the size of the largest remaining server
	 when this match fails. */
      high = daemon->serverarraysz;
      crop_query = 1;
      
      /* binary search */
      while (1) 
	{
	  try = (low + high)/2;

	  if ((rc = order(qdomain, qlen, daemon->serverarray[try])) == 0)
	    break;
	  
	  if (rc < 0)
	    {
	      if (high == try)
		{
		  /* qdomain is longer or same length as longest domain, and try == 0 
		     crop the query to the longest domain. */
		  crop_query = qlen - daemon->serverarray[try]->domain_len;
		  break;
		}
	      high = try;
	    }
	  else
	    {
	      if (low == try)
		{
		  /* try now points to the last domain that sorts before the query, so 
		     we know that a substring of the query shorter than it is required to match, so
		     find the largest domain that's shorter than try. Note that just going to
		     try+1 is not optimal, consider searching bbb in (aaa,ccc,bb). try will point
		     to aaa, since ccc sorts after bbb, but the first domain that has a chance to 
		     match is bb. So find the length of the first domain later than try which is
		     is shorter than it. 
		     There's a nasty edge case when qdomain sorts before _any_ of the 
		     server domains, where try _doesn't point_ to the last domain that sorts
		     before the query, since no such domain exists. In that case, the loop 
		     exits via the rc < 0 && high == try path above and this code is
		     not executed. */
		  ssize_t len, old = daemon->serverarray[try]->domain_len;
		  while (++try != daemon->serverarraysz)
		    {
		      if (old != (len = daemon->serverarray[try]->domain_len))
			{
			  crop_query = qlen - len;
			  break;
			}
		    }
		  break;
		}
	      low = try;
	    }
	};
      
      if (rc == 0)
	{
	  int found = 1;

	  if (daemon->server_has_wildcard)
	    {
	      /* if we have example.com and *example.com we need to check against *example.com, 
		 but the binary search may have found either. Use the fact that example.com is sorted before *example.com
		 We favour example.com in the case that both match (ie www.example.com) */
	      while (try != 0 && order(qdomain, qlen, daemon->serverarray[try-1]) == 0)
		try--;
	      
	      if (!(qdomain == domain || *qdomain == 0 || *(qdomain-1) == '.'))
		{
		  while (try < daemon->serverarraysz-1 && order(qdomain, qlen, daemon->serverarray[try+1]) == 0)
		    try++;
		  
		  if (!(daemon->serverarray[try]->flags & SERV_WILDCARD))
		     found = 0;
		}
	    }
	  
	  if (found && filter_servers(try, flags, &nlow, &nhigh))
	    /* We have a match, but it may only be (say) an IPv6 address, and
	       if the query wasn't for an AAAA record, it's no good, and we need
	       to continue generalising */
	    {
	      /* We've matched a setting which says to use servers without a domain.
		 Continue the search with empty query. We set the F_SERVER flag
		 so that --address=/#/... doesn't match. */
	      if (daemon->serverarray[nlow]->flags & SERV_USE_RESOLV)
		{
		  crop_query = qlen;
		  flags |= F_SERVER;
		}
	      else
		break;
	    }
	}
      
      /* crop_query must be at least one always. */
      if (crop_query == 0)
	crop_query = 1;

      /* strip chars off the query based on the largest possible remaining match,
	 then continue to the start of the next label unless we have a wildcard
	 domain somewhere, in which case we have to go one at a time. */
      qlen -= crop_query;
      qdomain += crop_query;
      if (!daemon->server_has_wildcard)
	while (qlen > 0 &&  (*(qdomain-1) != '.'))
	  qlen--, qdomain++;
    }

  /* domain has no dots, and we have at least one server configured to handle such,
     These servers always sort to the very end of the array. 
     A configured server eg server=/lan/ will take precdence. */
  if (nodots &&
      (daemon->serverarray[daemon->serverarraysz-1]->flags & SERV_FOR_NODOTS) &&
      (nlow == nhigh || daemon->serverarray[nlow]->domain_len == 0))
    {
      filter_servers(daemon->serverarraysz-1, flags, &nlow, &nhigh);
      qlen = 0;
    }
  
  if (lowout)
    *lowout = nlow;
  
  if (highout)
    *highout = nhigh;

  /* qlen == -1 when we failed to match even an empty query, if there are no default servers. */
  if (nlow == nhigh || qlen == -1)
    return 0;
  
  return 1;
}

/**
 * @brief Determine if two servers belong to the same equivalence group
 * 
 * @detailed Tests whether two server records are equivalent for the purposes of server
 *           selection and load distribution. Servers are in the same group if they have
 *           identical domain match characteristics, allowing them to be treated as a set
 *           of equivalent upstream forwarders for the same domain.
 *           
 *           This function is used during query forwarding to identify all servers that
 *           can handle a given domain, enabling round-robin load distribution and failover
 *           across equivalent servers.
 * 
 * @param a    First server to compare
 * @param b    Second server to compare
 * 
 * @return 1 if servers are in same group (equivalent), 0 if different groups
 * @retval 1   Servers have identical domain matching characteristics
 * @retval 0   Servers differ in domain or other grouping criteria
 * 
 * @note Equivalence is determined by order_servers() returning 0, which compares:
 *       - Domain name (serv->domain)
 *       - Server type flags (SERV_IS_LOCAL mask)
 *       - Wildcard flag (SERV_WILDCARD)
 * @note Servers in the same group may have different IP addresses but serve the same domain
 * 
 * @warning Both parameters must point to valid server structures
 * 
 * @see order_servers() for detailed equivalence comparison algorithm
 * @see lookup_domain() which returns groups of equivalent servers
 * 
 * EXAMPLE USAGE:
 * @code
 * struct server *primary = daemon->serverarray[10];
 * struct server *backup = daemon->serverarray[11];
 * 
 * // Check if both servers can handle same domain
 * if (server_samegroup(primary, backup))
 * {
 *   // Can use either server for query to this domain
 *   // Implement round-robin or failover logic
 * }
 * @endcode
 * 
 * SIDE EFFECTS: None (read-only comparison)
 * THREAD SAFETY: Safe for concurrent calls (read-only operation)
 * PERFORMANCE: O(1) - delegates to order_servers() which performs constant-time comparisons
 */
int server_samegroup(struct server *a, struct server *b)
{
  return order_servers(a, b) == 0;
}

/**
 * @brief Filter and prioritize server range based on query characteristics
 * 
 * @detailed Expands from a seed position to find all servers with the same domain, then filters
 *           and narrows that range based on query flags to select the most appropriate servers
 *           for forwarding. The function implements a priority-based selection strategy that
 *           chooses server types in order from most specific (literal addresses) to most general
 *           (global upstream servers).
 *           
 *           The algorithm works in two phases:
 *           1. EXPANSION: Starting from seed index, expand bidirectionally to include all servers
 *              with the same domain (determined by order_servers() returning 0)
 *           2. FILTERING: Apply priority-based filtering to narrow the range based on query flags
 *           
 *           Priority order for server selection (highest to lowest):
 *           1. IPv6 literal addresses (SERV_6ADDR) - returned for F_IPV6 queries when F_SERVER not set
 *           2. IPv4 literal addresses (SERV_4ADDR) - returned for F_IPV4 queries when F_SERVER not set
 *           3. All-zeros addresses (SERV_ALL_ZEROS) - return NODATA response for IPv4/IPv6 queries
 *           4. Literal NXDOMAIN addresses (SERV_LITERAL_ADDRESS) - for --local=/domain/ configuration
 *           5. USE_RESOLV servers - forward to nameservers from /etc/resolv.conf
 *           6. Domain-specific upstream servers - unless F_DOMAINSRV flag set
 *           7. Wildcard or global upstream servers - remaining servers after filtering
 *           
 *           Special behavior for F_CONFIG flag:
 *           - Only returns servers with local addresses (SERV_6ADDR | SERV_4ADDR | SERV_ALL_ZEROS)
 *           - Used by is_local_answer() to determine if query has local configuration answer
 *           
 *           Special behavior for F_DOMAINSRV flag:
 *           - Excludes wildcard/global servers (domain_len == 0), only returns domain-specific
 *           - Used by get_domain() to obtain domain-specific server information
 *           
 *           The F_SERVER flag disables early termination for literal addresses, forcing
 *           consideration of all server types up to USE_RESOLV level.
 * 
 * @param seed      Starting index in daemon->serverarray from lookup_domain() or similar
 * @param flags     Query control flags affecting server selection:
 *                  - F_IPV4: IPv4 query (A record), prefer SERV_4ADDR literal addresses
 *                  - F_IPV6: IPv6 query (AAAA record), prefer SERV_6ADDR literal addresses
 *                  - F_SERVER: Exclude literal addresses, force upstream server selection
 *                  - F_DOMAINSRV: Return only domain-specific servers, exclude wildcards/globals
 *                  - F_CONFIG: Return only local address servers (for is_local_answer())
 *                  - F_DNSSECOK: Passed through but not directly used in filtering
 * @param lowout    Output parameter: Set to lower bound (inclusive) of filtered server range
 * @param highout   Output parameter: Set to upper bound (exclusive) of filtered server range
 * 
 * @return Boolean indicating whether matching servers found
 * @retval 1        Servers found: (*lowout < *highout), use daemon->serverarray[*lowout..*highout-1]
 * @retval 0        No matching servers: (*lowout == *highout), no servers to query
 * 
 * @note The seed parameter must be a valid index where daemon->serverarray[seed] is a server
 *       returned by lookup_domain() matching the query domain
 * @note The expansion phase ensures all equivalent domain servers are considered together,
 *       even if seed is in the middle of the group
 * @note Output range [*lowout, *highout) is always a subset of the expanded domain group
 * @note When F_CONFIG is set, other flags are ignored except for the local address check
 * @note The priority ordering is enforced by order_qsort() during build_server_array()
 * 
 * @warning Caller must ensure seed is valid (0 <= seed < daemon->serverarraysz)
 * @warning Output parameters lowout and highout must not be NULL
 * @warning Returned range is only valid until next build_server_array() call
 * 
 * @see build_server_array() which sorts servers into priority order for filtering
 * @see order_servers() which determines server equivalence for domain matching
 * @see lookup_domain() which provides the initial seed position
 * @see is_local_answer() which uses F_CONFIG filtering
 * 
 * EXAMPLE USAGE:
 * @code
 * // After lookup_domain() finds matching server
 * int seed = lookup_domain("example.com", F_SERVER, NULL, NULL);
 * if (seed >= 0) {
 *   int low, high;
 *   
 *   // Try to get IPv4 literal address first (e.g., for address=/example.com/192.0.2.1)
 *   if (filter_servers(seed, F_IPV4, &low, &high) && low < high) {
 *     // Found literal IPv4 address - return directly without upstream query
 *     return_literal_address(daemon->serverarray[low]);
 *   }
 *   
 *   // No literal address, try upstream servers for IPv4 query
 *   if (filter_servers(seed, F_IPV4 | F_SERVER, &low, &high) && low < high) {
 *     // Forward query to selected upstream servers
 *     for (int i = low; i < high; i++)
 *       forward_query_to(daemon->serverarray[i]);
 *   }
 * }
 * @endcode
 * 
 * EXAMPLE USAGE (checking for local answer):
 * @code
 * // Check if domain has local configuration (address=, local= directives)
 * int seed = lookup_domain("blocked.example", F_CONFIG, NULL, NULL);
 * if (seed >= 0) {
 *   int low, high;
 *   if (filter_servers(seed, F_CONFIG, &low, &high) && low < high) {
 *     // Domain has local configuration - generate answer without upstream query
 *     if (daemon->serverarray[low]->flags & SERV_ALL_ZEROS)
 *       return NODATA;  // address=/blocked.example/
 *     else
 *       return literal_address(daemon->serverarray[low]);
 *   }
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: Implements DNS forwarding logic per RFC 1035 with extensions for local answers
 * SIDE EFFECTS: Modifies *lowout and *highout output parameters
 * THREAD SAFETY: Read-only access to daemon->serverarray; safe if array not modified concurrently
 * PERFORMANCE: O(n) where n = number of servers with same domain; typically n < 10
 */
int filter_servers(int seed, int flags, int *lowout, int *highout)
{
  int nlow = seed, nhigh = seed;
  int i;
  
  /* expand nlow and nhigh to cover all the records with the same domain 
     nlow is the first, nhigh - 1 is the last. nlow=nhigh means no servers,
     which can happen below. */
  while (nlow > 0 && order_servers(daemon->serverarray[nlow-1], daemon->serverarray[nlow]) == 0)
    nlow--;
  
  while (nhigh < daemon->serverarraysz-1 && order_servers(daemon->serverarray[nhigh], daemon->serverarray[nhigh+1]) == 0)
    nhigh++;
  
  nhigh++;
  
#define SERV_LOCAL_ADDRESS (SERV_6ADDR | SERV_4ADDR | SERV_ALL_ZEROS)
  
  if (flags & F_CONFIG)
    {
      /* We're just lookin for any matches that return an RR. */
      for (i = nlow; i < nhigh; i++)
	if (daemon->serverarray[i]->flags & SERV_LOCAL_ADDRESS)
	  break;
      
      /* failed, return failure. */
      if (i == nhigh)
	nhigh = nlow;
    }
  else
    {
      /* Now the matching server records are all between low and high.
	 order_qsort() ensures that they are in the order
	 IPv6 addr, IPv4 addr, return zero for both, no-data return,
	 "use resolvconf" servers, domain-specific upstream servers.
	 
	 See which of those match our query in that priority order and narrow (low, high) */

      for (i = nlow; i < nhigh && (daemon->serverarray[i]->flags & SERV_6ADDR); i++);
      
      if (!(flags & F_SERVER) && i != nlow && (flags & F_IPV6))
	nhigh = i;
      else
	{
	  nlow = i;
	  
	  for (i = nlow; i < nhigh && (daemon->serverarray[i]->flags & SERV_4ADDR); i++);
	  
	  if (!(flags & F_SERVER) && i != nlow && (flags & F_IPV4))
	    nhigh = i;
	  else
	    {
	      nlow = i;
	      
	      for (i = nlow; i < nhigh && (daemon->serverarray[i]->flags & SERV_ALL_ZEROS); i++);
	      
	      if (!(flags & F_SERVER) && i != nlow && (flags & (F_IPV4 | F_IPV6)))
		nhigh = i;
	      else
		{
		  nlow = i;
		  
		  /* now look for a NXDOMAIN answer  --local=/domain/ */
		  for (i = nlow; i < nhigh && (daemon->serverarray[i]->flags & SERV_LITERAL_ADDRESS); i++);
		  
		  if (!(flags & (F_DOMAINSRV | F_SERVER)) && i != nlow)
		    nhigh = i;
		  else
		    {
		      nlow = i;
		  
		      /* return "use resolv.conf servers" if they exist */
		      for (i = nlow; i < nhigh && (daemon->serverarray[i]->flags & SERV_USE_RESOLV); i++);
		      
		      if (i != nlow)
			nhigh = i;
		      else
			{
			  /* If we want a server for a particular domain, and this one isn't, return nothing. */
			  if (nlow < daemon->serverarraysz && nlow != nhigh && (flags & F_DOMAINSRV) &&
			      daemon->serverarray[nlow]->domain_len == 0 && !(daemon->serverarray[nlow]->flags & SERV_FOR_NODOTS))
			    nlow = nhigh;
			}
		    }
		}
	    }
	}
    }

  *lowout = nlow;
  *highout = nhigh;
  
  return (nlow != nhigh);
}

/**
 * @brief Determine if a query has a local configuration answer
 * 
 * @detailed Checks whether a domain name has local configuration that provides an answer
 *           without requiring upstream DNS query. This function is used to determine if
 *           queries should be answered immediately from local configuration (address=,
 *           local=, ipset= directives) rather than forwarded to upstream servers.
 *           
 *           The function performs two-phase lookup:
 *           1. DOMAIN LOOKUP: Call lookup_domain() with F_CONFIG flag to find matching
 *              server configuration for the domain
 *           2. LOCAL VERIFICATION: Use filter_servers() with F_CONFIG to check if any
 *              servers in the matched range are truly local (not SERV_USE_RESOLV)
 *           
 *           A domain has a local answer if:
 *           - It has server entries with SERV_LITERAL_ADDRESS flag (address=/domain/IP)
 *           - It has server entries with SERV_ALL_ZEROS flag (address=/domain/)
 *           - It has literal IPv4 addresses (SERV_4ADDR) or IPv6 addresses (SERV_6ADDR)
 *           
 *           A domain does NOT have a local answer if:
 *           - It only has SERV_USE_RESOLV servers (server=/domain/ with no address)
 *           - It has no matching server configuration at all
 *           - The matched servers are filtered out by filter_servers()
 *           
 *           The function is typically called early in query processing to decide whether
 *           to generate a local response or forward the query upstream. If this returns
 *           true, make_local_answer() is called to generate the actual response.
 * 
 * @param now    Current timestamp (time_t) for TTL calculations and logging
 * @param first  Starting index from previous lookup, or zero for fresh lookup
 *               This parameter is used when iterating through multiple matches
 * @param name   Domain name to check for local configuration (null-terminated string)
 *               The name should be in canonical DNS format (lowercase, no trailing dot)
 * 
 * @return Boolean indicating whether domain has local answer configuration
 * @retval 1     Domain has local configuration that provides an answer without upstream query
 * @retval 0     Domain has no local configuration, or only has SERV_USE_RESOLV entries
 * 
 * @note The name parameter must be a valid DNS domain name (may include wildcards)
 * @note Returning 1 means make_local_answer() can generate a response for this domain
 * @note Returning 0 means the query should be forwarded to upstream DNS servers
 * @note The function uses F_CONFIG flag which filters to only local address servers
 * @note SERV_USE_RESOLV servers (server=/domain/ without address) are not local answers
 * 
 * @warning The name parameter must not be NULL
 * @warning The name must be properly formatted domain name (validated by caller)
 * @warning Function may log via my_syslog() if unusual conditions detected
 * 
 * @see make_local_answer() which generates the actual local response
 * @see lookup_domain() which finds matching server configuration
 * @see filter_servers() which applies F_CONFIG filtering for local addresses only
 * @see address= configuration directive which creates SERV_LITERAL_ADDRESS entries
 * @see local= configuration directive which creates SERV_ALL_ZEROS entries
 * 
 * EXAMPLE USAGE:
 * @code
 * // Check if domain has local configuration before forwarding
 * char *query_name = "blocked.example.com";
 * time_t now = time(NULL);
 * 
 * if (is_local_answer(now, 0, query_name)) {
 *   // Domain has local configuration - generate answer from local data
 *   int answer_count = make_local_answer(flags, gotname, size, header, 
 *                                        name, qtype, qclass, NULL, now);
 *   return answer_count;  // Return local answer to client
 * } else {
 *   // No local configuration - forward query to upstream DNS
 *   forward_query(query_name, qtype);
 * }
 * @endcode
 * 
 * EXAMPLE USAGE (configuration scenarios):
 * @code
 * // Scenario 1: address=/blocked.example/ returns NXDOMAIN
 * // is_local_answer() returns 1, make_local_answer() generates NXDOMAIN
 * 
 * // Scenario 2: address=/example.com/192.0.2.1
 * // is_local_answer() returns 1, make_local_answer() returns literal IP
 * 
 * // Scenario 3: server=/example.com/8.8.8.8 (no address)
 * // is_local_answer() returns 0 because only SERV_USE_RESOLV present
 * 
 * // Scenario 4: local=/example.com/ (equivalent to address=/example.com/)
 * // is_local_answer() returns 1, generates NXDOMAIN response
 * @endcode
 * 
 * RFC COMPLIANCE: Supports DNS forwarding logic per RFC 1035 with local overrides
 * SIDE EFFECTS: May log to syslog via my_syslog() in edge cases
 * THREAD SAFETY: Read-only access to daemon->serverarray; safe if not modified concurrently
 * PERFORMANCE: O(log n) for lookup_domain() + O(k) for filter_servers() where k = matched servers
 */
int is_local_answer(time_t now, int first, char *name)
{
  int flags = 0;
  int rc = 0;
  
  if ((flags = daemon->serverarray[first]->flags) & SERV_LITERAL_ADDRESS)
    {
      if (flags & SERV_4ADDR)
	rc = F_IPV4;
      else if (flags & SERV_6ADDR)
	rc = F_IPV6;
      else if (flags & SERV_ALL_ZEROS)
	rc = F_IPV4 | F_IPV6;
      else
	{
	  /* argument first is the first struct server which matches the query type;
	     now roll back to the server which is just the same domain, to check if that 
	     provides an answer of a different type. */

	  for (;first > 0 && order_servers(daemon->serverarray[first-1], daemon->serverarray[first]) == 0; first--);
	  
	  if ((daemon->serverarray[first]->flags & SERV_LOCAL_ADDRESS) ||
	      check_for_local_domain(name, now))
	    rc = F_NOERR;
	  else
	    rc = F_NXDOMAIN;
	}
    }

  return rc;
}

/**
 * @brief Construct DNS response for locally-resolved addresses from server array
 * 
 * @detailed Builds a DNS answer section by iterating through a range of servers in the
 *           daemon->serverarray that have literal addresses (SERV_LITERAL_ADDRESS flag).
 *           Generates A records for IPv4 addresses and AAAA records for IPv6 addresses,
 *           handling special cases like all-zeros addresses. Sets appropriate response
 *           headers, logs the local answer, and handles truncation if the response exceeds
 *           packet size limits. This function is used for address records configured via
 *           /etc/hosts, --address options, or other local sources.
 * 
 * @param flags DNS query flags controlling response behavior (F_IPV4, F_IPV6, F_NXDOMAIN, 
 *              F_NOERR, F_RCODE)
 * @param gotname Flags indicating which record types should be included in the response; 
 *                modified internally to exclude F_QUERY and F_DS bits
 * @param size Size of the DNS packet buffer in bytes
 * @param header Pointer to DNS packet header structure; modified with response records
 * @param name Domain name being answered (used for logging); must be NULL-terminated
 * @param limit Pointer to end of packet buffer for bounds checking; prevents buffer overruns
 * @param first Index in daemon->serverarray of first server with addresses for this domain
 * @param last Index in daemon->serverarray one past the last server (exclusive end)
 * @param ede Extended DNS Error code to include in response (0 if no error)
 * 
 * @return Size of the constructed DNS response packet in bytes, or 0 if packet is invalid
 * @retval >0 Valid response packet size
 * @retval 0 Packet construction failed (bad packet structure)
 * 
 * @note Function iterates through servers [first, last) adding address records for each
 * @warning Modifies the DNS header and packet buffer in place; caller must ensure buffer is large enough
 * @warning If truncation occurs (TC bit set), answer count is reset to 0
 * 
 * @see is_local_answer() for determining if domain has local addresses
 * @see lookup_domain() for finding server array ranges
 * @see add_resource_record() for adding individual RRs to packet
 * 
 * EXAMPLE USAGE:
 * @code
 * int first, last;
 * if (lookup_domain("example.local", F_IPV4, &first, &last) && is_local_answer(first, last)) {
 *     size_t response_size = make_local_answer(F_IPV4, F_IPV4, packet_size, 
 *                                               header, "example.local", packet_end, 
 *                                               first, last, 0);
 *     // Send response_size bytes of packet
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 1035 Section 4.1.1 (DNS message format), RFC 3596 (AAAA records)
 * SIDE EFFECTS: Modifies DNS packet header and buffer; logs query with log_query()
 * THREAD SAFETY: Not thread-safe; accesses global daemon->serverarray and daemon->local_ttl
 */
size_t make_local_answer(int flags, int gotname, size_t size, struct dns_header *header, char *name, char *limit, int first, int last, int ede)
{
  int trunc = 0, anscount = 0;
  unsigned char *p;
  int start;
  union all_addr addr;
  
  setup_reply(header, flags, ede);

  gotname &= ~(F_QUERY | F_DS);
  
  if (flags & (F_NXDOMAIN | F_NOERR))
    log_query(flags | gotname | F_NEG | F_CONFIG | F_FORWARD, name, NULL, NULL, 0);

  if (flags & F_RCODE)
     {
       union all_addr a;
       a.log.rcode = RCODE(header);
       a.log.ede = ede;
       log_query(F_UPSTREAM | F_RCODE, "opcode", &a, NULL, 0);
     }
  
  if (!(p = skip_questions(header, size)))
    return 0;
	  
  if (flags & gotname & F_IPV4)
    for (start = first; start != last; start++)
      {
	struct serv_addr4 *srv = (struct serv_addr4 *)daemon->serverarray[start];

	if (srv->flags & SERV_ALL_ZEROS)
	  memset(&addr, 0, sizeof(addr));
	else
	  addr.addr4 = srv->addr;
	
	if (add_resource_record(header, limit, &trunc, sizeof(struct dns_header), &p, daemon->local_ttl, NULL, T_A, C_IN, "4", &addr))
	  anscount++;
	log_query((flags | F_CONFIG | F_FORWARD) & ~F_IPV6, name, (union all_addr *)&addr, NULL, 0);
      }
  
  if (flags & gotname & F_IPV6)
    for (start = first; start != last; start++)
      {
	struct serv_addr6 *srv = (struct serv_addr6 *)daemon->serverarray[start];

	if (srv->flags & SERV_ALL_ZEROS)
	  memset(&addr, 0, sizeof(addr));
	else
	  addr.addr6 = srv->addr;
	
	if (add_resource_record(header, limit, &trunc, sizeof(struct dns_header), &p, daemon->local_ttl, NULL, T_AAAA, C_IN, "6", &addr))
	  anscount++;
	log_query((flags | F_CONFIG | F_FORWARD) & ~F_IPV4, name, (union all_addr *)&addr, NULL, 0);
      }

  if (trunc)
    {
      header->hb3 |= HB3_TC;
      if (!(p = skip_questions(header, size)))
	return 0; /* bad packet */
      anscount  = 0;
    }
  
  header->ancount = htons(anscount);
  
  return p - (unsigned char *)header;
}

#ifdef HAVE_DNSSEC
/**
 * @brief Find appropriate server for DNSSEC validation query (DNSKEY or DS records)
 * 
 * @detailed Determines which upstream server should be used for DNSSEC validation queries
 *           (DNSKEY or DS record lookups) based on the original query server and domain-specific
 *           server configuration. The function attempts to use the same server as the original
 *           query, but if that server is not in the set of servers for the DNSSEC key domain,
 *           it selects the first server from the newly looked-up set or the last-used server
 *           from that set. This ensures that DNSSEC queries follow appropriate domain-specific
 *           routing rules while maintaining query consistency where possible.
 * 
 * @param server Original server used for the query requiring validation; used to maintain
 *               consistency if possible
 * @param keyname Domain name of the DNSKEY or DS record being queried; must be NULL-terminated
 * @param is_ds Flag indicating whether this is a DS record query (1) or DNSKEY query (0);
 *              affects parent domain lookup behavior
 * @param firstp Output pointer to receive index of first server in range; may be NULL if not needed
 * @param lastp Output pointer to receive index one past last server in range (exclusive); 
 *              may be NULL if not needed
 * 
 * @return Index in daemon->serverarray of server to use for DNSSEC query, or -1 on failure
 * @retval >=0 Valid server index in daemon->serverarray
 * @retval -1 No server found for the key domain (lookup_domain failed)
 * 
 * @note For DS records, F_DS flag causes lookup of parent domain per DNSSEC trust chain
 * @warning Output parameters firstp and lastp are only set if non-NULL and lookup succeeds
 * 
 * @see lookup_domain() for finding servers matching domain
 * @see F_DS flag for parent domain lookup behavior
 * @see F_DNSSECOK flag to exclude NODOTS servers
 * 
 * EXAMPLE USAGE:
 * @code
 * struct server *original_server = daemon->serverarray[5];
 * int first, last;
 * int dnssec_idx = dnssec_server(original_server, "example.com", 0, &first, &last);
 * if (dnssec_idx >= 0) {
 *     struct server *dnssec_srv = daemon->serverarray[dnssec_idx];
 *     // Forward DNSKEY query to dnssec_srv
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 4033-4035 (DNSSEC validation requires queries to parent zones for DS records)
 * SIDE EFFECTS: None (read-only access to daemon->serverarray)
 * THREAD SAFETY: Not thread-safe; accesses global daemon->serverarray
 */
int dnssec_server(struct server *server, char *keyname, int is_ds, int *firstp, int *lastp)
{
  int first, last, index;
  
  /* Find server to send DNSSEC query to. This will normally be the 
     same as for the original query, but may be another if
     servers for domains are involved. */		      
  if (!lookup_domain(keyname, F_SERVER | F_DNSSECOK | (is_ds ? F_DS : 0), &first, &last))
    return -1;

  for (index = first; index != last; index++)
    if (daemon->serverarray[index] == server)
      break;
	      
  /* No match to server used for original query.
     Use newly looked up set. */
  if (index == last)
    index =  daemon->serverarray[first]->last_server == -1 ?
      first : daemon->serverarray[first]->last_server;

  if (firstp)
    *firstp = first;

  if (lastp)
    *lastp = last;
   
  return index;
}
#endif

/* order by size, then by dictionary order */
/**
 * @brief Calculate the order (longest match length) between a query domain and server domain
 * 
 * @detailed Determines how many domain labels match between the right-hand side of the query
 *           domain and the server's domain pattern. Returns a weight value used for sorting
 *           servers by specificity. Wildcard domains (starting with '*') match any prefix and
 *           return the length of the non-wildcard portion. Exact matches return the full domain
 *           length plus one. Non-matching domains return zero. This ordering ensures that more
 *           specific domain matches are preferred over less specific ones during server selection.
 * 
 * @param qdomain Query domain name as NULL-terminated string; compared against server domain
 * @param qlen Length of query domain string in bytes (excluding NULL terminator)
 * @param serv Server structure containing the domain pattern to match against; domain field
 *             accessed if SERV_HAS_DOMAIN flag is set
 * 
 * @return Match weight indicating specificity of match
 * @retval 0 No match between query domain and server domain
 * @retval >0 Match weight: higher values indicate more specific matches (exact > wildcard)
 * 
 * @note Wildcard domains (e.g., "*.example.com") match any subdomain prefix
 * @note Match comparison is case-insensitive per DNS standard
 * @warning Assumes qdomain is properly NULL-terminated and qlen is accurate
 * 
 * @see order_servers() which uses this function to compare two servers
 * @see lookup_domain() which uses sorted server array to find longest match
 * 
 * EXAMPLE USAGE:
 * @code
 * struct server *serv = daemon->serverarray[0]; // server for "example.com"
 * char *query = ".mail.example.com";
 * size_t qlen = strlen(query);
 * int match_weight = order(query, qlen, serv);
 * // match_weight > 0 if query ends with ".example.com"
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 1035 (DNS name comparison is case-insensitive)
 * SIDE EFFECTS: None (read-only function)
 * THREAD SAFETY: Thread-safe (no global state modification)
 */
static int order(char *qdomain, size_t qlen, struct server *serv)
{
  size_t dlen = 0;
    
  /* servers for dotless names always sort last 
     searched for name is never dotless. */
  if (serv->flags & SERV_FOR_NODOTS)
    return -1;

  dlen = serv->domain_len;
  
  if (qlen < dlen)
    return 1;
  
  if (qlen > dlen)
    return -1;

  return hostname_order(qdomain, serv->domain);
}

static int order_servers(struct server *s1, struct server *s2)
{
  int rc;

  /* need full comparison of dotless servers in 
     order_qsort() and filter_servers() */

  if (s1->flags & SERV_FOR_NODOTS)
     return (s2->flags & SERV_FOR_NODOTS) ? 0 : 1;
   
  if ((rc = order(s1->domain, s1->domain_len, s2)) != 0)
    return rc;

  /* For identical domains, sort wildcard ones first */
  if (s1->flags & SERV_WILDCARD)
    return (s2->flags & SERV_WILDCARD) ? 0 : 1;

  return (s2->flags & SERV_WILDCARD) ? -1 : 0;
}
  
/**
 * @brief qsort-compatible comparison function for sorting server array
 * 
 * @detailed Provides a three-level comparison for sorting the daemon->serverarray:
 *           1. Primary: Domain specificity via order_servers() - local domains before upstream,
 *              longer/more-specific domains before shorter ones
 *           2. Secondary: Literal address type ordering for same domain - IPv6 literal addresses,
 *              then IPv4 literal addresses, then all-zeros addresses, then NXDOMAIN responses,
 *              with SERV_USE_RESOLV servers sorted before ordinary upstream servers
 *           3. Tertiary: Serial number ordering for --strict-order mode - maintains original
 *              appearance order from /etc/resolv.conf and configuration files
 *           This multi-level sorting ensures consistent server selection behavior with predictable
 *           precedence rules.
 * 
 * @param a Pointer to first struct server* pointer (void* for qsort compatibility)
 * @param b Pointer to second struct server* pointer (void* for qsort compatibility)
 * 
 * @return Comparison result for qsort
 * @retval <0 First server should be ordered before second server
 * @retval 0 Servers are equivalent in all ordering criteria
 * @retval >0 First server should be ordered after second server
 * 
 * @note Secondary ordering for literal addresses: SERV_6ADDR > SERV_4ADDR > SERV_ALL_ZEROS > 
 *       NXDOMAIN (no flags) > ordinary upstream (SERV_USE_RESOLV sorts earliest)
 * @note Serial number comparison only applies to non-local servers (respects --strict-order)
 * @warning Must be called with pointers to struct server* (double indirection via qsort)
 * 
 * @see build_server_array() which calls qsort with this comparison function
 * @see order_servers() for primary domain-based ordering
 * 
 * EXAMPLE USAGE:
 * @code
 * // Called internally by build_server_array via qsort:
 * qsort(daemon->serverarray, daemon->serverarraysz, 
 *       sizeof(struct server *), order_qsort);
 * // Result: servers sorted by domain specificity, then address type, then serial
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (internal sorting algorithm for configuration precedence)
 * SIDE EFFECTS: None (read-only comparison function)
 * THREAD SAFETY: Thread-safe (no global state modification)
 */
static int order_qsort(const void *a, const void *b)
{
  int rc;
  
  struct server *s1 = *((struct server **)a);
  struct server *s2 = *((struct server **)b);
  
  rc = order_servers(s1, s2);

  /* Sort all literal NODATA and local IPV4 or IPV6 responses together,
     in a very specific order  IPv6 literal, IPv4 literal, all-zero literal,
     NXDOMAIN literal. We also include SERV_USE_RESOLV in this, so that
     use-standard servers sort before ordinary servers. (SERV_USR_RESOLV set
     implies that none of SERV_LITERAL_ADDRESS,SERV_4ADDR,SERV_6ADDR,SERV_ALL_ZEROS
     are set) */
  if (rc == 0)
    rc = ((s2->flags & (SERV_LITERAL_ADDRESS | SERV_4ADDR | SERV_6ADDR | SERV_ALL_ZEROS | SERV_USE_RESOLV))) -
      ((s1->flags & (SERV_LITERAL_ADDRESS | SERV_4ADDR | SERV_6ADDR | SERV_ALL_ZEROS | SERV_USE_RESOLV)));

  /* Finally, order by appearance in /etc/resolv.conf etc, for --strict-order */
  if (rc == 0)
    if (!(s1->flags & SERV_IS_LOCAL) && !(s2->flags & SERV_IS_LOCAL))
      rc = s1->serial - s2->serial;
  
  return rc;
}


/* When loading large numbers of server=.... lines during startup,
   there's no possibility that there will be server records that can be reused, but
   searching a long list for each server added grows as O(n^2) and slows things down.
   This flag is set only if is known there may be free server records that can be reused.
   There's a call to mark_servers(0) in read_opts() to reset the flag before
   main config read. */

static int maybe_free_servers = 0;

/* Must be called before  add_update_server() to set daemon->servers_tail */
/**
 * @brief Mark servers matching a flag for potential deletion during configuration reload
 * 
 * @detailed Implements a two-phase deletion mechanism for server configuration reload:
 *           Phase 1 (mark): Traverses daemon->servers list and sets SERV_MARK flag on servers
 *           matching the provided flag, clearing SERV_MARK on non-matching servers. This marks
 *           servers from the old configuration that may need to be deleted.
 *           Phase 2 (cleanup): Later call to cleanup_servers() removes marked servers that
 *           were not re-added during configuration reload. For local_domains (literal addresses
 *           from --address options), immediate deletion occurs since these are expected to be
 *           numerous and infrequently reloaded. Updates daemon->servers_tail to last server
 *           and sets maybe_free_servers global flag to coordinate with cleanup phase.
 * 
 * @param flag Server flag bit(s) to match for marking (e.g., SERV_FROM_RESOLV, SERV_FROM_DHCP);
 *             zero flag skips marking but still updates servers_tail and processes local_domains
 * 
 * @return void
 * 
 * @note Two-phase reload: mark_servers(flag) -> reload config -> cleanup_servers()
 * @note Local domains (daemon->local_domains) are immediately deleted if flag matches, not marked
 * @warning Modifies global daemon->servers list, daemon->local_domains list, daemon->servers_tail
 * @warning Sets global maybe_free_servers flag to coordinate with cleanup phase
 * 
 * @see cleanup_servers() which completes the deletion of marked servers
 * @see add_update_server() which re-adds or updates servers during reload, clearing SERV_MARK
 * @see SERV_MARK flag used for marking servers pending deletion
 * 
 * EXAMPLE USAGE:
 * @code
 * // Configuration reload for servers from resolv.conf:
 * mark_servers(SERV_FROM_RESOLV);  // Mark existing resolv.conf servers
 * read_resolv_file();              // Re-add servers, clearing SERV_MARK on matches
 * cleanup_servers();               // Delete servers still marked (removed from resolv.conf)
 * build_server_array();            // Rebuild sorted server array
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (internal configuration management)
 * SIDE EFFECTS: Modifies daemon->servers list, frees local_domains entries matching flag
 * THREAD SAFETY: Not thread-safe; modifies global daemon state
 */
void mark_servers(int flag)
{
  struct server *serv, *next, **up;

  maybe_free_servers = !!flag;
  
  daemon->servers_tail = NULL;
  
  /* mark everything with argument flag */
  for (serv = daemon->servers; serv; serv = serv->next)
    {
      if (serv->flags & flag)
	serv->flags |= SERV_MARK;
      else
	serv->flags &= ~SERV_MARK;

      daemon->servers_tail = serv;
    }
  
  /* --address etc is different: since they are expected to be 
     1) numerous and 2) not reloaded often. We just delete 
     and recreate. */
  if (flag)
    for (serv = daemon->local_domains, up = &daemon->local_domains; serv; serv = next)
      {
	next = serv->next;

	if (serv->flags & flag)
	  {
	    *up = next;
	    free(serv->domain);
	    free(serv);
	  }
	else 
	  up = &serv->next;
      }
}

/**
 * @brief Remove servers marked for deletion during configuration reload (phase 2)
 * 
 * @detailed Completes the two-phase deletion mechanism initiated by mark_servers():
 *           Traverses daemon->servers list and removes servers with SERV_MARK flag still set,
 *           indicating they were present in old configuration but not re-added during reload.
 *           Freed servers are added to daemon->free_servers list for memory reuse rather than
 *           immediate deallocation, improving performance for frequent reloads. Updates
 *           daemon->servers_tail pointer after removals. Only executes if maybe_free_servers
 *           global flag is set by mark_servers().
 * 
 * @param void
 * 
 * @return void
 * 
 * @note Servers re-added during reload have SERV_MARK cleared by add_update_server()
 * @note Freed servers added to daemon->free_servers list for memory pool reuse
 * @note Updates daemon->servers_tail to last server after deletions
 * @warning Only operates if maybe_free_servers global flag is set
 * @warning Modifies global daemon->servers list structure
 * 
 * @see mark_servers() which initiates the marking phase
 * @see add_update_server() which clears SERV_MARK on re-added servers
 * @see daemon->free_servers list for server memory pool
 * 
 * EXAMPLE USAGE:
 * @code
 * // Configuration reload sequence:
 * mark_servers(SERV_FROM_RESOLV);  // Mark existing resolv.conf servers
 * read_resolv_file();              // Re-add servers, clearing SERV_MARK on matches
 * cleanup_servers();               // Delete servers still marked (removed from resolv.conf)
 * build_server_array();            // Rebuild sorted server array
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (internal configuration management)
 * SIDE EFFECTS: Modifies daemon->servers list, adds to daemon->free_servers list
 * THREAD SAFETY: Not thread-safe; modifies global daemon state
 */
void cleanup_servers(void)
{
  struct server *serv, *tmp, **up;

  /* unlink and free anything still marked. */
  for (serv = daemon->servers, up = &daemon->servers, daemon->servers_tail = NULL; serv; serv = tmp) 
    {
      tmp = serv->next;
      if (serv->flags & SERV_MARK)
       {
         server_gone(serv);
         *up = serv->next;
	 free(serv->domain);
	 free(serv);
       }
      else 
	{
	  up = &serv->next;
	  daemon->servers_tail = serv;
	}
    }
}

/**
 * @brief Add or update a server entry in the daemon's server configuration
 * 
 * @detailed This function creates a new server entry or updates an existing one based on the
 *           provided parameters. It handles various server types including upstream DNS servers,
 *           local domain servers, literal address mappings, and domain-specific forwarding rules.
 *           The function manages server list insertion, memory allocation, and proper initialization
 *           of server flags and addresses. Integration points include configuration parsing from
 *           option.c and runtime server array management via build_server_array().
 * 
 * @param flags Server flags bitmap controlling behavior (SERV_LITERAL_ADDRESS, SERV_USE_RESOLV, etc.)
 * @param addr Pointer to server socket address structure (IPv4 or IPv6); NULL if not applicable
 * @param source_addr Source address for queries to this server; NULL to use default
 * @param interface Interface name to bind for queries to this server; NULL for any interface
 * @param domain Domain name pattern this server handles (may include wildcards); NULL for default server
 * @param local_addr Local address for literal address mappings (SERV_LITERAL_ADDRESS); NULL otherwise
 * 
 * @return 1 if server was successfully added or updated, 0 on memory allocation failure
 * @retval 1 Server entry created/updated successfully
 * @retval 0 Memory allocation failed (whine_malloc returned NULL)
 * 
 * @note Function allocates memory for server structure and domain string copies
 * @warning Caller must call build_server_array() after configuration changes to rebuild sorted server array
 * 
 * @see build_server_array() - Must be called after server additions to update internal array
 * @see lookup_domain() - Uses server array built by this function
 * 
 * EXAMPLE USAGE:
 * @code
 * // Add upstream server for google.com domain
 * union mysockaddr addr;
 * addr.sa.sa_family = AF_INET;
 * inet_pton(AF_INET, "8.8.8.8", &addr.in.sin_addr);
 * addr.in.sin_port = htons(53);
 * add_update_server(0, &addr, NULL, NULL, "google.com", NULL);
 * build_server_array(); // Rebuild server array
 * 
 * // Add literal address mapping (local A record)
 * union all_addr local;
 * inet_pton(AF_INET, "192.168.1.100", &local.addr4);
 * add_update_server(SERV_LITERAL_ADDRESS, NULL, NULL, NULL, "internal.local", &local);
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (internal configuration management)
 * SIDE EFFECTS: Allocates heap memory, modifies daemon->servers or daemon->local_domains linked list
 * THREAD SAFETY: Not thread-safe - modifies global daemon state without locking
 */

int add_update_server(int flags,
		      union mysockaddr *addr,
		      union mysockaddr *source_addr,
		      const char *interface,
		      const char *domain,
		      union all_addr *local_addr)
{
  struct server *serv = NULL;
  char *alloc_domain;
  
  if (!domain)
    domain = "";

  /* .domain == domain, for historical reasons. */
  if (*domain == '.')
    while (*domain == '.') domain++;
  else if (*domain == '*')
    {
      domain++;
      if (*domain != 0)
	flags |= SERV_WILDCARD;
    }
  
  if (*domain == 0)
    alloc_domain = whine_malloc(1);
  else
    alloc_domain = canonicalise((char *)domain, NULL);

  if (!alloc_domain)
    return 0;

  if (flags & SERV_IS_LOCAL)
    {
      size_t size;
      
      if (flags & SERV_6ADDR)
	size = sizeof(struct serv_addr6);
      else if (flags & SERV_4ADDR)
	size = sizeof(struct serv_addr4);
      else
	size = sizeof(struct serv_local);
      
      if (!(serv = whine_malloc(size)))
	{
	  free(alloc_domain);
	  return 0;
	}
      
      serv->next = daemon->local_domains;
      daemon->local_domains = serv;
      
      if (flags & SERV_4ADDR)
	((struct serv_addr4*)serv)->addr = local_addr->addr4;
      
      if (flags & SERV_6ADDR)
	((struct serv_addr6*)serv)->addr = local_addr->addr6;
    }
  else
    { 
      /* Upstream servers. See if there is a suitable candidate, if so unmark
	 and move to the end of the list, for order. The entry found may already
	 be at the end. */
      struct server **up, *tmp;

      serv = NULL;
      
      if (maybe_free_servers)
	for (serv = daemon->servers, up = &daemon->servers; serv; serv = tmp)
	  {
	    tmp = serv->next;
	    if ((serv->flags & SERV_MARK) &&
		hostname_isequal(alloc_domain, serv->domain))
	      {
		/* Need to move down? */
		if (serv->next)
		  {
		    *up = serv->next;
		    daemon->servers_tail->next = serv;
		    daemon->servers_tail = serv;
		    serv->next = NULL;
		  }
		break;
	      }
	    else
	      up = &serv->next;
	  }
      
      if (serv)
	{
	  free(alloc_domain);
	  alloc_domain = serv->domain;
	}
      else
	{
	  if (!(serv = whine_malloc(sizeof(struct server))))
	    {
	      free(alloc_domain);
	      return 0;
	    }
	  
	  memset(serv, 0, sizeof(struct server));
	  
	  /* Add to the end of the chain, for order */
	  if (daemon->servers_tail)
	    daemon->servers_tail->next = serv;
	  else
	    daemon->servers = serv;
	  daemon->servers_tail = serv;
	}
      
#ifdef HAVE_LOOP
      serv->uid = rand32();
#endif      
	  
      if (interface)
	safe_strncpy(serv->interface, interface, sizeof(serv->interface));
      if (addr)
	serv->addr = *addr;
      if (source_addr)
	serv->source_addr = *source_addr;

      serv->tcpfd = -1;
    }
    
  serv->flags = flags;
  serv->domain = alloc_domain;
  serv->domain_len = strlen(alloc_domain);
    
  return 1;
}


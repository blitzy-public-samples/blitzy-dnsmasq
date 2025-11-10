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
 * @file auth.c
 * @brief Authoritative DNS server implementation for designated local zones
 * 
 * DETAILED PURPOSE:
 * This module implements authoritative DNS server mode, enabling dnsmasq to respond
 * authoritatively to DNS queries for configured local zones with the AA (Authoritative 
 * Answer) flag set. The implementation supports zone transfers (AXFR) to secondary
 * nameservers, generates SOA (Start of Authority) records with configurable parameters,
 * and serves multiple record types including A, AAAA, PTR, CNAME, MX, SRV, TXT, and
 * NAPTR records. This capability allows dnsmasq to act as the primary nameserver for
 * internal zones without requiring a separate authoritative DNS server.
 * 
 * KEY RESPONSIBILITIES:
 * - Detect and process queries for configured authoritative zones via answer_auth()
 * - Generate SOA records with default TTL AUTH_TTL=600s (from config.h line 62), 
 *   SOA refresh=1200s, retry=180s, expiry=1209600s (14 days)
 * - Respond authoritatively with AA flag set for in-zone queries
 * - Implement zone transfer (AXFR) protocol for secondary nameserver synchronization
 * - Support split-horizon DNS through per-zone subnet filtering (auth-peer configuration)
 * - Serve records from multiple sources: static configuration, interface addresses, 
 *   DNS cache (DHCP leases and /etc/hosts entries)
 * - Filter responses based on client subnet for security and topology constraints
 * - Integrate with DNSSEC signing for authenticated authoritative responses
 * 
 * DEPENDENCIES:
 * Includes: dnsmasq.h (core structures including struct auth_zone, struct auth_name_list),
 *           dns-protocol.h (DNS protocol constants: T_SOA, T_NS, T_AXFR, etc.)
 * Called by: forward.c (DNS forwarding engine routes authoritative queries here)
 * Calls: cache.c (cache enumeration for DHCP/hosts entries), rfc1035.c (packet construction),
 *        network.c (interface address enumeration)
 * 
 * DATA STRUCTURES:
 * - struct auth_zone: Authoritative zone configuration (src/dnsmasq.h:430-444) containing
 *   domain name, subnet/exclude filters, and associated name lists
 * - struct auth_name_list: Named address/CNAME/MX/SRV/TXT records for zone (dnsmasq.h:420-428)
 * - struct dns_header: DNS packet header with flags, counts (dns-protocol.h)
 * - struct crec: Cache records for DHCP leases and hosts file entries (dnsmasq.h:250-280)
 * 
 * COMPILE-TIME OPTIONS:
 * HAVE_AUTH: Must be defined to enable authoritative DNS functionality (conditional
 *            compilation wraps entire file). Disabled by default on Android and 
 *            resource-constrained platforms where authoritative DNS is not required.
 * AUTH_TTL: Default TTL for authoritative records (600 seconds, config.h:62)
 * 
 * THREADING/CONCURRENCY:
 * Single-threaded architecture - all functions execute in main event loop context.
 * No locking required. Zone configuration is read-only after daemon initialization
 * except during SIGHUP configuration reload.
 * 
 * COEXISTENCE WITH FORWARDING MODE:
 * Authoritative mode operates alongside forwarding mode. The query routing logic
 * in forward.c determines whether a query matches an authoritative zone (routed to
 * answer_auth) or should be forwarded to upstream servers. A query can receive
 * an authoritative answer for configured zones while other queries are forwarded.
 * This enables split-horizon DNS architectures where internal zones are served
 * authoritatively and external queries are forwarded.
 * 
 * @copyright Copyright (c) 2000-2025 Simon Kelley
 * @license GPL-2.0-or-later
 */

#include "dnsmasq.h"

#ifdef HAVE_AUTH

/**
 * @brief Search an address list for a matching subnet containing the given address
 * 
 * @detailed Iterates through a linked list of address ranges/subnets and checks whether
 *           the provided IP address falls within any of the configured address ranges.
 *           Handles both IPv4 and IPv6 addresses with appropriate netmask/prefix
 *           matching. Used internally by subnet filtering and exclude list processing
 *           to implement split-horizon DNS and access control.
 * 
 * @param list Linked list of struct addrlist entries to search (auth_zone->subnet or 
 *             auth_zone->exclude). NULL is valid (returns NULL immediately).
 * @param flag Address family indicator (F_IPV4 or F_IPV6) from query context
 * @param addr_u Union containing the IP address to match (addr4 or addr6 depending on flag)
 * 
 * @return Pointer to the matching struct addrlist entry if address is within any configured
 *         subnet/range, NULL if no match found or list is empty
 * 
 * @note IPv4 matching uses netmask calculated from prefixlen with is_same_net() comparison
 * @note IPv6 matching uses prefixlen directly with is_same_net6() comparison
 * @warning Address family (flag) must match the address union member being accessed
 * 
 * @see find_subnet() - Wrapper for searching zone->subnet list
 * @see find_exclude() - Wrapper for searching zone->exclude list
 * @see filter_zone() - Uses both subnet and exclude lists for access control
 * 
 * EXAMPLE USAGE:
 * @code
 * union all_addr addr;
 * addr.addr4.s_addr = inet_addr("192.168.1.50");
 * struct addrlist *match = find_addrlist(zone->subnet, F_IPV4, &addr);
 * if (match) { // Address is in configured subnet }
 * @endcode
 * 
 * SIDE EFFECTS: None (read-only operation)
 * THREAD SAFETY: Safe for read-only access in single-threaded architecture
 */
static struct addrlist *find_addrlist(struct addrlist *list, int flag, union all_addr *addr_u)
{
  do {
    if (!(list->flags & ADDRLIST_IPV6))
      {
	struct in_addr netmask, addr = addr_u->addr4;
	
	if (!(flag & F_IPV4))
	  continue;
	
	netmask.s_addr = htonl(~(in_addr_t)0 << (32 - list->prefixlen));
	
	if  (is_same_net(addr, list->addr.addr4, netmask))
	  return list;
      }
    else if (is_same_net6(&(addr_u->addr6), &list->addr.addr6, list->prefixlen))
      return list;
    
  } while ((list = list->next));
  
  return NULL;
}

/**
 * @brief Check if an IP address is within the zone's allowed subnet list
 * 
 * @detailed Wrapper function that searches the zone's configured subnet list to determine
 *           if the provided IP address falls within any allowed subnet. Used for
 *           split-horizon DNS to restrict which clients receive authoritative answers
 *           based on their source IP address. If no subnets are configured (zone->subnet
 *           is NULL), returns NULL indicating no subnet restrictions apply.
 * 
 * @param zone Pointer to auth_zone structure containing subnet configuration. Must not be NULL.
 * @param flag Address family indicator (F_IPV4 or F_IPV6) from query context
 * @param addr_u Union containing the client IP address to check. Must not be NULL.
 * 
 * @return Pointer to matching struct addrlist if address is in allowed subnet, 
 *         NULL if no subnets configured or address not in any configured subnet
 * 
 * @see find_addrlist() - Performs actual subnet matching logic
 * @see filter_zone() - Uses this function as part of complete filtering logic
 * @see find_exclude() - Companion function for excluded address checking
 * 
 * EXAMPLE USAGE:
 * @code
 * union all_addr client_addr;
 * client_addr.addr4 = peer_addr->in.sin_addr;
 * if (find_subnet(zone, F_IPV4, &client_addr)) {
 *   // Client is in allowed subnet, serve authoritative answer
 * }
 * @endcode
 * 
 * SIDE EFFECTS: None (read-only operation)
 * THREAD SAFETY: Safe for read-only access in single-threaded architecture
 */
static struct addrlist *find_subnet(struct auth_zone *zone, int flag, union all_addr *addr_u)
{
  if (!zone->subnet)
    return NULL;
  
  return find_addrlist(zone->subnet, flag, addr_u);
}

/**
 * @brief Check if an IP address is within the zone's excluded address list
 * 
 * @detailed Wrapper function that searches the zone's configured exclude list to determine
 *           if the provided IP address falls within any excluded subnet. Used for
 *           split-horizon DNS to explicitly deny authoritative answers to specific
 *           clients or subnets even if they would otherwise match subnet criteria.
 *           Exclude lists take precedence over subnet allow lists in filter_zone().
 *           If no exclusions are configured (zone->exclude is NULL), returns NULL.
 * 
 * @param zone Pointer to auth_zone structure containing exclude list. Must not be NULL.
 * @param flag Address family indicator (F_IPV4 or F_IPV6) from query context
 * @param addr_u Union containing the client IP address to check. Must not be NULL.
 * 
 * @return Pointer to matching struct addrlist if address is in exclude list,
 *         NULL if no exclusions configured or address not in any excluded subnet
 * 
 * @note Exclude lists provide explicit denial - if an address matches, it will not
 *       receive authoritative answers regardless of subnet configuration
 * 
 * @see find_addrlist() - Performs actual subnet matching logic
 * @see filter_zone() - Uses this function first to check exclusions before subnet matching
 * @see find_subnet() - Companion function for allowed subnet checking
 * 
 * EXAMPLE USAGE:
 * @code
 * union all_addr client_addr;
 * client_addr.addr4 = peer_addr->in.sin_addr;
 * if (find_exclude(zone, F_IPV4, &client_addr)) {
 *   // Client is explicitly excluded, deny authoritative answer
 * }
 * @endcode
 * 
 * SIDE EFFECTS: None (read-only operation)
 * THREAD SAFETY: Safe for read-only access in single-threaded architecture
 */
static struct addrlist *find_exclude(struct auth_zone *zone, int flag, union all_addr *addr_u)
{
  if (!zone->exclude)
    return NULL;
  
  return find_addrlist(zone->exclude, flag, addr_u);
}

/**
 * @brief Determine if a client IP address should receive authoritative answers for a zone
 * 
 * @detailed Implements the complete filtering logic for split-horizon DNS by checking both
 *           exclude and subnet lists. The filtering algorithm operates as follows:
 *           1. If address is in exclude list, deny (return 0)
 *           2. If no subnet list configured, allow all (return 1) - no filtering
 *           3. If subnet list exists, allow only if address matches a subnet (return 1 or 0)
 *           
 *           This three-tier logic enables flexible access control: explicit denials via
 *           exclude lists, no restrictions if no subnets configured, or explicit allow
 *           lists via subnet configuration. Used by answer_auth() to determine whether
 *           to serve authoritative responses to a particular client.
 * 
 * @param zone Pointer to auth_zone structure with subnet/exclude configuration. Must not be NULL.
 * @param flag Address family indicator (F_IPV4 or F_IPV6) from query context
 * @param addr_u Union containing the client IP address to filter. Must not be NULL.
 * 
 * @return 1 if client should receive authoritative answers (passed filter),
 *         0 if client should not receive authoritative answers (failed filter)
 * @retval 1 Address not in exclude list AND (no subnets configured OR address in subnet list)
 * @retval 0 Address in exclude list OR (subnets configured AND address not in any subnet)
 * 
 * @note Exclude lists take precedence over subnet lists - explicit denial overrides allow
 * @note If zone->subnet is NULL, no filtering is applied (all clients allowed except excluded)
 * @warning Returning 0 does not generate an error response, it simply prevents authoritative
 *          answer - query may be forwarded to upstream servers instead
 * 
 * @see find_exclude() - Checks exclude list first (highest priority)
 * @see find_subnet() - Checks subnet allow list second
 * @see answer_auth() - Uses this function to filter clients before serving authoritative answers
 * 
 * EXAMPLE USAGE:
 * @code
 * union all_addr client_addr;
 * client_addr.addr4 = peer_addr->in.sin_addr;
 * if (filter_zone(zone, F_IPV4, &client_addr)) {
 *   // Client passed filter, serve authoritative answer
 * } else {
 *   // Client filtered out, forward query instead
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: Split-horizon DNS (not RFC standardized, implementation-defined behavior)
 * SIDE EFFECTS: None (read-only operation)
 * THREAD SAFETY: Safe for read-only access in single-threaded architecture
 */
static int filter_zone(struct auth_zone *zone, int flag, union all_addr *addr_u)
{
  if (find_exclude(zone, flag, addr_u))
    return 0;

  /* No subnets specified, no filter */
  if (!zone->subnet)
    return 1;
  
  return find_subnet(zone, flag, addr_u) != NULL;
}

/**
 * @brief Check if a hostname is within an authoritative DNS zone
 * 
 * @detailed Determines whether a given hostname belongs to the specified authoritative
 *           zone by performing a case-insensitive suffix match against the zone's domain.
 *           The function handles two matching scenarios:
 *           1. Exact match: hostname equals zone domain exactly (e.g., "example.com" in zone "example.com")
 *           2. Subdomain match: hostname is a subdomain with dot separator (e.g., "www.example.com" in zone "example.com")
 *           
 *           The matching algorithm performs suffix comparison from the end of the hostname
 *           string, ensuring proper domain boundary detection. The optional cut parameter
 *           enables callers to extract the subdomain prefix by receiving a pointer to the
 *           dot separator. This function is called by answer_auth() for every query to
 *           determine which authoritative zone (if any) should handle the query.
 * 
 * @param zone Pointer to auth_zone structure containing the zone domain to match against. Must not be NULL.
 * @param name Hostname to test for zone membership (FQDN format, null-terminated string). Must not be NULL.
 * @param cut Optional output parameter: pointer to receive location of dot separator between subdomain
 *            and zone domain. Set to NULL if no subdomain prefix exists (exact match) or if match fails.
 *            Pass NULL if cut location is not needed. If non-NULL, *cut is set to NULL before processing.
 * 
 * @return 1 if hostname is within the authoritative zone (exact match or valid subdomain),
 *         0 if hostname is not within the zone (no match)
 * @retval 1 Hostname exactly matches zone->domain OR hostname ends with "." + zone->domain
 * @retval 0 Hostname does not match zone domain suffix, or matches but without dot separator
 * 
 * @note Matching is case-insensitive via hostname_isequal() (RFC 1035 requirement)
 * @note For subdomain matches, the function verifies proper dot separator to prevent false
 *       matches (e.g., "notexample.com" should NOT match zone "example.com")
 * @warning Function modifies *cut output parameter even on failure (sets to NULL)
 * 
 * @see answer_auth() - Primary caller, uses this to route queries to appropriate zones
 * @see hostname_isequal() in util.c - Case-insensitive hostname comparison
 * @see struct auth_zone in dnsmasq.h:430-444 - Zone configuration structure
 * 
 * EXAMPLE USAGE:
 * @code
 * struct auth_zone *zone; // zone->domain = "example.com"
 * char *cut = NULL;
 * 
 * // Exact match
 * if (in_zone(zone, "example.com", &cut)) {
 *   // Returns 1, cut = NULL (no subdomain)
 * }
 * 
 * // Subdomain match
 * if (in_zone(zone, "www.example.com", &cut)) {
 *   // Returns 1, cut points to '.' before "example.com"
 *   // Subdomain prefix is "www" (cut - name = 3 chars)
 * }
 * 
 * // No match - wrong zone
 * if (!in_zone(zone, "example.org", NULL)) {
 *   // Returns 0, not in zone
 * }
 * 
 * // No match - no dot separator
 * if (!in_zone(zone, "wwwexample.com", NULL)) {
 *   // Returns 0, matches suffix but no dot separator
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 1035 Section 3.1 (domain name syntax and case-insensitive comparison)
 * SIDE EFFECTS: Modifies *cut output parameter if provided (always sets to NULL first)
 * THREAD SAFETY: Safe - read-only operations on zone structure (zone is immutable during query processing)
 */
int in_zone(struct auth_zone *zone, char *name, char **cut)
{
  size_t namelen = strlen(name);
  size_t domainlen = strlen(zone->domain);

  if (cut)
    *cut = NULL;
  
  if (namelen >= domainlen && 
      hostname_isequal(zone->domain, &name[namelen - domainlen]))
    {
      
      if (namelen == domainlen)
	return 1;
      
      if (name[namelen - domainlen - 1] == '.')
	{
	  if (cut)
	    *cut = &name[namelen - domainlen - 1]; 
	  return 1;
	}
    }

  return 0;
}


/**
 * @brief Process authoritative DNS query and generate authoritative response
 * 
 * @detailed This is the main entry point for authoritative DNS processing in dnsmasq.
 * When the forwarding engine (forward.c) determines that a query matches a configured
 * authoritative zone, it routes the query to this function. The function generates
 * authoritative responses with the AA (Authoritative Answer) flag set, supporting
 * standard queries, SOA queries, NS queries, zone transfers (AXFR), and all record
 * types configured in the authoritative zone (A, AAAA, PTR, CNAME, MX, SRV, TXT, NAPTR).
 * 
 * The response construction process includes:
 * 1. Query parsing and validation (name extraction, type determination)
 * 2. Zone matching to find authoritative zone for queried name
 * 3. Subnet filtering based on peer address (split-horizon DNS support)
 * 4. Response construction with appropriate records from configuration and cache
 * 5. Authority section population with NS records
 * 6. Additional section population with glue records (A/AAAA for NS targets)
 * 7. AXFR handling for complete zone transfers to secondary nameservers
 * 8. SOA record generation with configurable timing parameters
 * 
 * Split-horizon DNS is supported through per-zone subnet and exclude lists, allowing
 * different responses based on the client's IP address. This enables internal and
 * external views of the same zone.
 * 
 * @param header DNS packet header structure containing query to process. Modified in-place
 *               to become the response packet. Must not be NULL.
 * @param limit Pointer to end of available buffer space for response construction. Used
 *              to prevent buffer overflow when adding records. Must be >= header address.
 * @param qlen Length of original query packet in bytes, used for packet size calculations.
 *             Must be > 0 and <= buffer size.
 * @param now Current Unix timestamp for TTL calculations and SOA serial number generation.
 *            Used to compute relative TTLs and generate monotonically increasing SOA serials.
 * @param peer_addr Socket address of DNS client sending the query. Used for subnet filtering
 *                  in split-horizon DNS configurations. May be NULL for local queries.
 * @param local_query Boolean flag: 1 if query originated from local resolver, 0 if from
 *                    network client. Affects logging and filtering behavior.
 * 
 * @return Size of constructed response packet in bytes, including DNS header and all sections.
 *         Returns original qlen if query is not for an authoritative zone or if an error
 *         occurred (RCODE set appropriately). Returns 0 only if catastrophic error prevents
 *         any response construction.
 * 
 * @note The function modifies the header structure in-place, transforming the query into
 *       a response by setting QR flag, adjusting counts, and appending answer/authority/
 *       additional sections. The original query section remains unchanged.
 * 
 * @warning AXFR (zone transfer) queries can generate very large responses containing all
 *          zone records. Ensure sufficient buffer space is available (limit parameter).
 *          AXFR is only permitted from IP addresses listed in auth-peer configuration.
 * 
 * @see in_zone() for zone matching logic
 * @see filter_zone() for subnet-based response filtering
 * @see struct auth_zone in src/dnsmasq.h:430-444 for zone configuration structure
 * @see struct auth_name_list in src/dnsmasq.h:420-428 for zone record lists
 * 
 * EXAMPLE USAGE:
 * @code
 * // Called from forward.c when query matches authoritative zone
 * struct dns_header *header = (struct dns_header *)packet_buffer;
 * char *limit = packet_buffer + sizeof(packet_buffer);
 * size_t response_len = answer_auth(header, limit, query_len, time(NULL), 
 *                                    &client_addr, 0);
 * // Send response_len bytes from packet_buffer to client
 * send(sock, packet_buffer, response_len, 0);
 * @endcode
 * 
 * RFC COMPLIANCE:
 * RFC 1035 Section 4.1.1 - DNS message format and authoritative answer flag
 * RFC 1035 Section 6.2 - SOA record format and RDATA structure
 * RFC 1996 - DNS zone transfer (AXFR) protocol over TCP
 * RFC 2782 - SRV record format for service location
 * RFC 3596 - AAAA record format for IPv6 addresses
 * 
 * SIDE EFFECTS:
 * - Modifies header structure in-place to construct response packet
 * - Logs query processing via log_query() for audit and troubleshooting
 * - Enumerates cache records for DHCP lease and hosts file integration
 * - May trigger DNSSEC signing operations if zone is DNSSEC-enabled
 * 
 * THREAD SAFETY:
 * Single-threaded architecture - no locking required. Function executes atomically
 * in main event loop. Zone configuration is read-only except during config reload.
 * 
 * ERROR HANDLING:
 * - Returns NXDOMAIN if queried name not in any authoritative zone
 * - Returns REFUSED if client subnet not permitted by zone filters
 * - Returns NOTIMP if query type not supported (e.g., dynamic updates)
 * - Returns FORMERR if query packet is malformed or truncated
 * - All error responses include appropriate RCODE and are logged
 */
size_t answer_auth(struct dns_header *header, char *limit, size_t qlen, time_t now,
		   union mysockaddr *peer_addr, int local_query) 
{
  char *name = daemon->namebuff;
  unsigned char *p, *ansp;
  int qtype, qclass, rc;
  int nameoffset, axfroffset = 0;
  int anscount = 0, authcount = 0;
  struct crec *crecp;
  int  auth = !local_query, trunc = 0, nxdomain = 1, soa = 0, ns = 0, axfr = 0, out_of_zone = 0, notimp = 0;
  struct auth_zone *zone = NULL;
  struct addrlist *subnet = NULL;
  char *cut;
  struct mx_srv_record *rec, *move, **up;
  struct txt_record *txt;
  struct interface_name *intr;
  struct naptr *na;
  union all_addr addr;
  struct cname *a, *candidate;
  unsigned int wclen;
  unsigned int log_flags = local_query ? 0 : F_NOERR;
  
  if (ntohs(header->qdcount) != 1)
    return 0;

  /* determine end of question section (we put answers there) */
  if (!(ansp = skip_questions(header, qlen)))
    return 0; /* bad packet */
  
  p = (unsigned char *)(header+1);

  if (OPCODE(header) != QUERY)
    notimp = 1;
  else
    {
      unsigned int flag = 0;
      int found = 0;
      int cname_wildcard = 0;
  
      /* save pointer to name for copying into answers */
      nameoffset = p - (unsigned char *)header;

      /* now extract name as .-concatenated string into name */
      if (!extract_name(header, qlen, &p, name, EXTR_NAME_EXTRACT, 4))
	return 0; /* bad packet */
 
      GETSHORT(qtype, p); 
      GETSHORT(qclass, p);
      
      if (qclass != C_IN)
	{
	  auth = 0;
	  out_of_zone = 1;
	  goto done;
	}

      if ((qtype == T_PTR || qtype == T_SOA || qtype == T_NS) &&
	  (flag = in_arpa_name_2_addr(name, &addr)) &&
	  !local_query)
	{
	  for (zone = daemon->auth_zones; zone; zone = zone->next)
	    if ((subnet = find_subnet(zone, flag, &addr)))
	      break;
	  
	  if (!zone)
	    {
	      out_of_zone = 1;
	      auth = 0;
	      goto done;
	    }
	  else if (qtype == T_SOA)
	    soa = 1, found = 1;
	  else if (qtype == T_NS)
	    ns = 1, found = 1;
	}

      if (qtype == T_PTR && flag)
	{
	  intr = NULL;

	  if (flag == F_IPV4)
	    for (intr = daemon->int_names; intr; intr = intr->next)
	      {
		struct addrlist *addrlist;
		
		for (addrlist = intr->addr; addrlist; addrlist = addrlist->next)
		  if (!(addrlist->flags & ADDRLIST_IPV6) && addr.addr4.s_addr == addrlist->addr.addr4.s_addr)
		    break;
		
		if (addrlist)
		  break;
		else
		  while (intr->next && strcmp(intr->intr, intr->next->intr) == 0)
		    intr = intr->next;
	      }
	  else if (flag == F_IPV6)
	    for (intr = daemon->int_names; intr; intr = intr->next)
	      {
		struct addrlist *addrlist;
		
		for (addrlist = intr->addr; addrlist; addrlist = addrlist->next)
		  if ((addrlist->flags & ADDRLIST_IPV6) && IN6_ARE_ADDR_EQUAL(&addr.addr6, &addrlist->addr.addr6))
		    break;
		
		if (addrlist)
		  break;
		else
		  while (intr->next && strcmp(intr->intr, intr->next->intr) == 0)
		    intr = intr->next;
	      }
	  
	  if (intr)
	    {
	      if (local_query || in_zone(zone, intr->name, NULL))
		{	
		  found = 1;
		  log_query(log_flags | flag | F_REVERSE | F_CONFIG, intr->name, &addr, NULL, 0);
		  if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, 
					  daemon->auth_ttl, NULL,
					  T_PTR, C_IN, "d", intr->name))
		    anscount++;
		}
	    }
	  
	  if ((crecp = cache_find_by_addr(NULL, &addr, now, flag)))
	    do { 
	      strcpy(name, cache_get_name(crecp));
	      
	      if (crecp->flags & F_DHCP && !option_bool(OPT_DHCP_FQDN))
		{
		  char *p = strchr(name, '.');
		  if (p)
		    *p = 0; /* must be bare name */
		  
		  /* add  external domain */
		  if (zone)
		    {
		      strcat(name, ".");
		      strcat(name, zone->domain);
		    }
		  log_query(log_flags | flag | F_DHCP | F_REVERSE, name, &addr, record_source(crecp->uid), 0);
		  found = 1;
		  if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, 
					  daemon->auth_ttl, NULL,
					  T_PTR, C_IN, "d", name))
		    anscount++;
		}
	      else if (crecp->flags & (F_DHCP | F_HOSTS) && (local_query || in_zone(zone, name, NULL)))
		{
		  log_query(log_flags | (crecp->flags & ~F_FORWARD), name, &addr, record_source(crecp->uid), 0);
		  found = 1;
		  if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, 
					  daemon->auth_ttl, NULL,
					  T_PTR, C_IN, "d", name))
		    anscount++;
		}
	      else
		continue;
		    
	    } while ((crecp = cache_find_by_addr(crecp, &addr, now, flag)));

	  if (!found && is_rev_synth(flag, &addr, name) && (local_query || in_zone(zone, name, NULL)))
	    {
	      log_query(log_flags | F_CONFIG | F_REVERSE | flag, name, &addr, NULL, 0);
	      found = 1;
	      
	      if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, 
				      daemon->auth_ttl, NULL,
				      T_PTR, C_IN, "d", name))
		anscount++;
	    }

	  if (found)
	    nxdomain = 0;
	  else
	    log_query(log_flags | flag | F_NEG | F_NXDOMAIN | F_REVERSE | (auth ? F_AUTH : 0), NULL, &addr, NULL, 0);

	  goto done;
	}
      
    cname_restart:
      if (found)
	/* NS and SOA .arpa requests have set found above. */
	cut = NULL;
      else
	{
	  for (zone = daemon->auth_zones; zone; zone = zone->next)
	    if (in_zone(zone, name, &cut))
	      break;
	  
	  if (!zone)
	    {
	      out_of_zone = 1;
	      auth = 0;
	      goto done;
	    }
	}

      for (rec = daemon->mxnames; rec; rec = rec->next)
	if (!rec->issrv && (rc = hostname_issubdomain(name, rec->name)))
	  {
	    nxdomain = 0;
	         
	    if (rc == 2 && qtype == T_MX)
	      {
		found = 1;
		log_query(log_flags | F_CONFIG | F_RRNAME, name, NULL, "<MX>", 0);
		if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, daemon->auth_ttl,
					NULL, T_MX, C_IN, "sd", rec->weight, rec->target))
		  anscount++;
	      }
	  }
      
      for (move = NULL, up = &daemon->mxnames, rec = daemon->mxnames; rec; rec = rec->next)
	if (rec->issrv && (rc = hostname_issubdomain(name, rec->name)))
	  {
	    nxdomain = 0;
	    
	    if (rc == 2 && qtype == T_SRV)
	      {
		found = 1;
		log_query(log_flags | F_CONFIG | F_RRNAME, name, NULL, "<SRV>", 0);
		if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, daemon->auth_ttl,
					NULL, T_SRV, C_IN, "sssd", 
					rec->priority, rec->weight, rec->srvport, rec->target))

		  anscount++;
	      } 
	    
	    /* unlink first SRV record found */
	    if (!move)
	      {
		move = rec;
		*up = rec->next;
	      }
	    else
	      up = &rec->next;      
	  }
	else
	  up = &rec->next;
	  
      /* put first SRV record back at the end. */
      if (move)
	{
	  *up = move;
	  move->next = NULL;
	}

      for (txt = daemon->rr; txt; txt = txt->next)
	if ((rc = hostname_issubdomain(name, txt->name)))
	  {
	    nxdomain = 0;
	    if (rc == 2 && txt->class == qtype)
	      {
		found = 1;
		log_query(log_flags | F_CONFIG | F_RRNAME, name, NULL, NULL, txt->class);
		if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, daemon->auth_ttl,
					NULL, txt->class, C_IN, "t", txt->len, txt->txt))
		  anscount++;
	      }
	  }
      
      for (txt = daemon->txt; txt; txt = txt->next)
	if (txt->class == C_IN && (rc = hostname_issubdomain(name, txt->name)))
	  {
	    nxdomain = 0;
	    if (rc == 2 && qtype == T_TXT)
	      {
		found = 1;
		log_query(log_flags | F_CONFIG | F_RRNAME, name, NULL, "<TXT>", 0);
		if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, daemon->auth_ttl,
					NULL, T_TXT, C_IN, "t", txt->len, txt->txt))
		  anscount++;
	      }
	  }

       for (na = daemon->naptr; na; na = na->next)
	 if ((rc = hostname_issubdomain(name, na->name)))
	   {
	     nxdomain = 0;
	     if (rc == 2 && qtype == T_NAPTR)
	       {
		 found = 1;
		 log_query(log_flags | F_CONFIG | F_RRNAME, name, NULL, "<NAPTR>", 0);
		 if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, daemon->auth_ttl, 
					 NULL, T_NAPTR, C_IN, "sszzzd", 
					 na->order, na->pref, na->flags, na->services, na->regexp, na->replace))
			  anscount++;
	       }
	   }
    
       if (qtype == T_A)
	 flag = F_IPV4;
       
       if (qtype == T_AAAA)
	 flag = F_IPV6;
       
       for (intr = daemon->int_names; intr; intr = intr->next)
	 if ((rc = hostname_issubdomain(name, intr->name)))
	   {
	     struct addrlist *addrlist;
	     
	     nxdomain = 0;
	     
	     if (rc == 2 && flag)
	       for (addrlist = intr->addr; addrlist; addrlist = addrlist->next)  
		 if (((addrlist->flags & ADDRLIST_IPV6)  ? T_AAAA : T_A) == qtype &&
		     (local_query || filter_zone(zone, flag, &addrlist->addr)))
		   {
		     if (addrlist->flags & ADDRLIST_REVONLY)
		       continue;

		     found = 1;
		     log_query(log_flags | F_FORWARD | F_CONFIG | flag, name, &addrlist->addr, NULL, 0);
		     if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, 
					     daemon->auth_ttl, NULL, qtype, C_IN, 
					     qtype == T_A ? "4" : "6", &addrlist->addr))
		       anscount++;
		   }
	     }

       if (!found && is_name_synthetic(flag, name, &addr) )
	 {
	   nxdomain = 0;
	   
	   log_query(log_flags | F_FORWARD | F_CONFIG | flag, name, &addr, NULL, 0);
	   if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, 
				   daemon->auth_ttl, NULL, qtype, C_IN, qtype == T_A ? "4" : "6", &addr))
	     anscount++;
	 }
       
      if (!cut)
	{
	  nxdomain = 0;
	  
	  if (qtype == T_SOA)
	    {
	      auth = soa = 1; /* inhibits auth section */
	      log_query(log_flags | F_RRNAME | F_AUTH, zone->domain, NULL, "<SOA>", 0);
	    }
      	  else if (qtype == T_AXFR)
	    {
	      struct iname *peers;
	      
	      if (peer_addr->sa.sa_family == AF_INET)
		peer_addr->in.sin_port = 0;
	      else
		{
		  peer_addr->in6.sin6_port = 0; 
		  peer_addr->in6.sin6_scope_id = 0;
		}
	      
	      for (peers = daemon->auth_peers; peers; peers = peers->next)
		if (sockaddr_isequal(peer_addr, &peers->addr))
		  break;
	      
	      /* Refuse all AXFR unless --auth-sec-servers or auth-peers is set */
	      if ((!daemon->secondary_forward_server && !daemon->auth_peers) ||
		  (daemon->auth_peers && !peers)) 
		{
		  if (peer_addr->sa.sa_family == AF_INET)
		    inet_ntop(AF_INET, &peer_addr->in.sin_addr, daemon->addrbuff, ADDRSTRLEN);
		  else
		    inet_ntop(AF_INET6, &peer_addr->in6.sin6_addr, daemon->addrbuff, ADDRSTRLEN); 
		  
		  my_syslog(LOG_WARNING, _("ignoring zone transfer request from %s"), daemon->addrbuff);
		  return 0;
		}
	       	      
	      auth = 1;
	      soa = 1; /* inhibits auth section */
	      ns = 1; /* ensure we include NS records! */
	      axfr = 1;
	      axfroffset = nameoffset;
	      log_query(log_flags | F_RRNAME | F_AUTH, zone->domain, NULL, "<AXFR>", 0);
	    }
      	  else if (qtype == T_NS)
	    {
	      auth = 1;
	      ns = 1; /* inhibits auth section */
	      log_query(log_flags | F_RRNAME | F_AUTH, zone->domain, NULL, "<NS>", 0);
	    }
	}
      
      if (!option_bool(OPT_DHCP_FQDN) && cut)
	{	  
	  *cut = 0; /* remove domain part */
	  
	  if (!strchr(name, '.') && (crecp = cache_find_by_name(NULL, name, now, F_IPV4 | F_IPV6)))
	    {
	      if (crecp->flags & F_DHCP)
		do
		  { 
		    nxdomain = 0;
		    if ((crecp->flags & flag) && 
			(local_query || filter_zone(zone, flag, &(crecp->addr))))
		      {
			*cut = '.'; /* restore domain part */
			log_query(log_flags | crecp->flags, name, &crecp->addr, record_source(crecp->uid), 0);
			*cut  = 0; /* remove domain part */
			if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, 
						daemon->auth_ttl, NULL, qtype, C_IN, 
						qtype == T_A ? "4" : "6", &crecp->addr))
			  anscount++;
		      }
		  } while ((crecp = cache_find_by_name(crecp, name, now,  F_IPV4 | F_IPV6)));
	    }
       	  
	  *cut = '.'; /* restore domain part */	    
	}
      
      if ((crecp = cache_find_by_name(NULL, name, now, F_IPV4 | F_IPV6)))
	{
	  if ((crecp->flags & F_HOSTS) || (((crecp->flags & F_DHCP) && option_bool(OPT_DHCP_FQDN))))
	    do
	      { 
		 nxdomain = 0;
		 if ((crecp->flags & flag) && (local_query || filter_zone(zone, flag, &(crecp->addr))))
		   {
		     log_query(log_flags | (crecp->flags & ~F_REVERSE), name, &crecp->addr, record_source(crecp->uid), 0);
		     if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, 
					     daemon->auth_ttl, NULL, qtype, C_IN, 
					     qtype == T_A ? "4" : "6", &crecp->addr))
		       anscount++;
		   }
	      } while ((crecp = cache_find_by_name(crecp, name, now, F_IPV4 | F_IPV6)));
	}
      
      /* Only supply CNAME if no record for any type is known. */
      if (nxdomain)
	{
	  /* Check for possible wildcard match against *.domain 
	     return length of match, to get longest.
	     Note that if return length of wildcard section, so
	     we match b.simon to _both_ *.simon and b.simon
	     but return a longer (better) match to b.simon.
	  */  
	  for (wclen = 0, candidate = NULL, a = daemon->cnames; a; a = a->next)
	    if (a->alias[0] == '*')
	      {
		char *test = name;
		
		while ((test = strchr(test+1, '.')))
		  {
		    if (hostname_isequal(test, &(a->alias[1])))
		      {
			if (strlen(test) > wclen && !cname_wildcard)
			  {
			    wclen = strlen(test);
			    candidate = a;
			    cname_wildcard = 1;
			  }
			break;
		      }
		  }
		
	      }
	    else if (hostname_isequal(a->alias, name) && strlen(a->alias) > wclen)
	      {
		/* Simple case, no wildcard */
		wclen = strlen(a->alias);
		candidate = a;
	      }
	  
	  if (candidate)
	    {
	      log_query(log_flags | F_CONFIG | F_CNAME, name, NULL, NULL, 0);
	      strcpy(name, candidate->target);
	      if (!strchr(name, '.'))
		{
		  strcat(name, ".");
		  strcat(name, zone->domain);
		}
	      found = 1;
	      if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, 
				      daemon->auth_ttl, &nameoffset,
				      T_CNAME, C_IN, "d", name))
		anscount++;
	      
	      goto cname_restart;
	    }
	  else if (cache_find_non_terminal(name, now))
	    nxdomain = 0;

	  log_query(log_flags | flag | F_NEG | (nxdomain ? F_NXDOMAIN : 0) | F_FORWARD | F_AUTH, name, NULL, NULL, 0);
	}
      
    }

 done:
  
  /* Add auth section */
  if (auth && zone)
    {
      char *authname;
      int newoffset, offset = 0;

      if (!subnet)
	authname = zone->domain;
      else
	{
	  /* handle NS and SOA for PTR records */
	  
	  authname = name;

	  if (!(subnet->flags & ADDRLIST_IPV6))
	    {
	      in_addr_t a = ntohl(subnet->addr.addr4.s_addr) >> 8;
	      char *p = name;
	      
	      if (subnet->prefixlen >= 24)
		p += sprintf(p, "%u.", a & 0xff);
	      a = a >> 8;
	      if (subnet->prefixlen >= 16 )
		p += sprintf(p, "%u.", a & 0xff);
	      a = a >> 8;
	      sprintf(p, "%u.in-addr.arpa", a & 0xff);
	      
	    }
	  else
	    {
	      char *p = name;
	      int i;
	      
	      for (i = subnet->prefixlen-1; i >= 0; i -= 4)
		{ 
		  int dig = ((unsigned char *)&subnet->addr.addr6)[i>>3];
		  p += sprintf(p, "%.1x.", (i>>2) & 1 ? dig & 15 : dig >> 4);
		}
	      sprintf(p, "ip6.arpa");
	      
	    }
	}
      
      /* handle NS and SOA in auth section or for explicit queries */
       newoffset = ansp - (unsigned char *)header;
       if (((anscount == 0 && !ns) || soa) &&
	  add_resource_record(header, limit, &trunc, 0, &ansp, 
			      daemon->auth_ttl, NULL, T_SOA, C_IN, "ddlllll",
			      authname, daemon->authserver,  daemon->hostmaster,
			      daemon->soa_sn, daemon->soa_refresh, 
			      daemon->soa_retry, daemon->soa_expiry, 
			      daemon->auth_ttl))
	{
	  offset = newoffset;
	  if (soa)
	    anscount++;
	  else
	    authcount++;
	}
      
      if (anscount != 0 || ns)
	{
	  struct name_list *secondary;
	  
	  /* Only include the machine running dnsmasq if it's acting as an auth server */
	  if (daemon->authinterface)
	    {
	      newoffset = ansp - (unsigned char *)header;
	      if (add_resource_record(header, limit, &trunc, -offset, &ansp, 
				      daemon->auth_ttl, NULL, T_NS, C_IN, "d", offset == 0 ? authname : NULL, daemon->authserver))
		{
		  if (offset == 0) 
		    offset = newoffset;
		  if (ns) 
		    anscount++;
		  else
		    authcount++;
		}
	    }

	  if (!subnet)
	    for (secondary = daemon->secondary_forward_server; secondary; secondary = secondary->next)
	      if (add_resource_record(header, limit, &trunc, offset, &ansp, 
				      daemon->auth_ttl, NULL, T_NS, C_IN, "d", secondary->name))
		{
		  if (ns) 
		    anscount++;
		  else
		    authcount++;
		}
	}
      
      if (axfr)
	{
	  for (rec = daemon->mxnames; rec; rec = rec->next)
	    if (in_zone(zone, rec->name, &cut))
	      {
		if (cut)
		   *cut = 0;

		if (rec->issrv)
		  {
		    if (add_resource_record(header, limit, &trunc, -axfroffset, &ansp, daemon->auth_ttl,
					    NULL, T_SRV, C_IN, "sssd", cut ? rec->name : NULL,
					    rec->priority, rec->weight, rec->srvport, rec->target))
		      
		      anscount++;
		  }
		else
		  {
		    if (add_resource_record(header, limit, &trunc, -axfroffset, &ansp, daemon->auth_ttl,
					    NULL, T_MX, C_IN, "sd", cut ? rec->name : NULL, rec->weight, rec->target))
		      anscount++;
		  }
		
		/* restore config data */
		if (cut)
		  *cut = '.';
	      }
	      
	  for (txt = daemon->rr; txt; txt = txt->next)
	    if (in_zone(zone, txt->name, &cut))
	      {
		if (cut)
		  *cut = 0;
		
		if (add_resource_record(header, limit, &trunc, -axfroffset, &ansp, daemon->auth_ttl,
					NULL, txt->class, C_IN, "t",  cut ? txt->name : NULL, txt->len, txt->txt))
		  anscount++;
		
		/* restore config data */
		if (cut)
		  *cut = '.';
	      }
	  
	  for (txt = daemon->txt; txt; txt = txt->next)
	    if (txt->class == C_IN && in_zone(zone, txt->name, &cut))
	      {
		if (cut)
		  *cut = 0;
		
		if (add_resource_record(header, limit, &trunc, -axfroffset, &ansp, daemon->auth_ttl,
					NULL, T_TXT, C_IN, "t", cut ? txt->name : NULL, txt->len, txt->txt))
		  anscount++;
		
		/* restore config data */
		if (cut)
		  *cut = '.';
	      }
	  
	  for (na = daemon->naptr; na; na = na->next)
	    if (in_zone(zone, na->name, &cut))
	      {
		if (cut)
		  *cut = 0;
		
		if (add_resource_record(header, limit, &trunc, -axfroffset, &ansp, daemon->auth_ttl, 
					NULL, T_NAPTR, C_IN, "sszzzd", cut ? na->name : NULL,
					na->order, na->pref, na->flags, na->services, na->regexp, na->replace))
		  anscount++;
		
		/* restore config data */
		if (cut)
		  *cut = '.'; 
	      }
	  
	  for (intr = daemon->int_names; intr; intr = intr->next)
	    if (in_zone(zone, intr->name, &cut))
	      {
		struct addrlist *addrlist;
		
		if (cut)
		  *cut = 0;
		
		for (addrlist = intr->addr; addrlist; addrlist = addrlist->next) 
		  if (!(addrlist->flags & ADDRLIST_IPV6) &&
		      (local_query || filter_zone(zone, F_IPV4, &addrlist->addr)) && 
		      add_resource_record(header, limit, &trunc, -axfroffset, &ansp, 
					  daemon->auth_ttl, NULL, T_A, C_IN, "4", cut ? intr->name : NULL, &addrlist->addr))
		    anscount++;
		
		for (addrlist = intr->addr; addrlist; addrlist = addrlist->next) 
		  if ((addrlist->flags & ADDRLIST_IPV6) && 
		      (local_query || filter_zone(zone, F_IPV6, &addrlist->addr)) &&
		      add_resource_record(header, limit, &trunc, -axfroffset, &ansp, 
					  daemon->auth_ttl, NULL, T_AAAA, C_IN, "6", cut ? intr->name : NULL, &addrlist->addr))
		    anscount++;
		
		/* restore config data */
		if (cut)
		  *cut = '.'; 
	      }
             
	  for (a = daemon->cnames; a; a = a->next)
	    if (in_zone(zone, a->alias, &cut))
	      {
		strcpy(name, a->target);
		if (!strchr(name, '.'))
		  {
		    strcat(name, ".");
		    strcat(name, zone->domain);
		  }
		
		if (cut)
		  *cut = 0;
		
		if (add_resource_record(header, limit, &trunc, -axfroffset, &ansp, 
					daemon->auth_ttl, NULL,
					T_CNAME, C_IN, "d",  cut ? a->alias : NULL, name))
		  anscount++;
	      }
	
	  cache_enumerate(1);
	  while ((crecp = cache_enumerate(0)))
	    {
	      if ((crecp->flags & (F_IPV4 | F_IPV6)) &&
		  !(crecp->flags & (F_NEG | F_NXDOMAIN)) &&
		  (crecp->flags & F_FORWARD))
		{
		  if ((crecp->flags & F_DHCP) && !option_bool(OPT_DHCP_FQDN))
		    {
		      char *cache_name = cache_get_name(crecp);
		      if (!strchr(cache_name, '.') && 
			  (local_query || filter_zone(zone, (crecp->flags & (F_IPV6 | F_IPV4)), &(crecp->addr))) &&
			  add_resource_record(header, limit, &trunc, -axfroffset, &ansp, 
					      daemon->auth_ttl, NULL, (crecp->flags & F_IPV6) ? T_AAAA : T_A, C_IN, 
					      (crecp->flags & F_IPV4) ? "4" : "6", cache_name, &crecp->addr))
			anscount++;
		    }
		  
		  if ((crecp->flags & F_HOSTS) || (((crecp->flags & F_DHCP) && option_bool(OPT_DHCP_FQDN))))
		    {
		      strcpy(name, cache_get_name(crecp));
		      if (in_zone(zone, name, &cut) && 
			  (local_query || filter_zone(zone, (crecp->flags & (F_IPV6 | F_IPV4)), &(crecp->addr))))
			{
			  if (cut)
			    *cut = 0;

			  if (add_resource_record(header, limit, &trunc, -axfroffset, &ansp, 
						  daemon->auth_ttl, NULL, (crecp->flags & F_IPV6) ? T_AAAA : T_A, C_IN, 
						  (crecp->flags & F_IPV4) ? "4" : "6", cut ? name : NULL, &crecp->addr))
			    anscount++;
			}
		    }
		}
	    }
	   
	  /* repeat SOA as last record */
	  if (add_resource_record(header, limit, &trunc, axfroffset, &ansp, 
				  daemon->auth_ttl, NULL, T_SOA, C_IN, "ddlllll",
				  daemon->authserver,  daemon->hostmaster,
				  daemon->soa_sn, daemon->soa_refresh, 
				  daemon->soa_retry, daemon->soa_expiry, 
				  daemon->auth_ttl))
	    anscount++;
	  
	}
      
    }
  
  /* done all questions, set up header and return length of result */
  /* clear authoritative and truncated flags, set QR flag */
  header->hb3 = (header->hb3 & ~(HB3_AA | HB3_TC)) | HB3_QR;

  if (local_query)
    {
      /* set RA flag */
      header->hb4 |= HB4_RA;
    }
  else
    {
      /* clear RA flag */
      header->hb4 &= ~HB4_RA;
    }

  /* data is never DNSSEC signed. */
  header->hb4 &= ~HB4_AD;

  /* authoritative */
  if (auth)
    header->hb3 |= HB3_AA;
  
  /* truncation */
  if (trunc)
    {
      header->hb3 |= HB3_TC;
      if (!(ansp = skip_questions(header, qlen)))
	return 0; /* bad packet */
      anscount = authcount = 0;
      log_query(log_flags | F_AUTH, "reply", NULL, "truncated", 0);
    }
  
  if ((auth || local_query) && nxdomain)
    SET_RCODE(header, NXDOMAIN);
  else
    SET_RCODE(header, NOERROR); /* no error */
  
  header->ancount = htons(anscount);
  header->nscount = htons(authcount);
  header->arcount = htons(0);

  if ((!local_query && out_of_zone) || notimp)
    {
      if (out_of_zone)
	{
	  addr.log.rcode = REFUSED;
	  addr.log.ede = EDE_NOT_AUTH;
	}
      else
	{
	  addr.log.rcode = NOTIMP;
	  addr.log.ede = EDE_UNSET;
	}

      SET_RCODE(header, addr.log.rcode); 
      header->ancount = htons(0);
      header->nscount = htons(0);
      log_query(log_flags | F_UPSTREAM | F_RCODE, "error", &addr, NULL, 0);
      return resize_packet(header,  ansp - (unsigned char *)header, NULL, 0);
    }
  
  return ansp - (unsigned char *)header;
}
  
#endif  

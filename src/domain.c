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
 * @file domain.c
 * @brief Domain name handling utilities for DNS query processing and synthetic name generation
 * 
 * DETAILED PURPOSE:
 * This module provides core domain name manipulation and validation functionality for dnsmasq's
 * DNS and DHCP services. It implements synthetic domain name generation and matching, conditional
 * domain selection based on client IP addresses, and domain name parsing with RFC 1035 compliance.
 * The module supports both IPv4 and IPv6 address spaces with parallel implementations for each
 * protocol family.
 * 
 * KEY RESPONSIBILITIES:
 * - Synthetic name matching: is_name_synthetic() validates domain names against configured synthetic
 *   domain patterns with prefix matching and indexed address generation
 * - Reverse synthesis: is_rev_synth() generates synthetic domain names from IP addresses for reverse
 *   DNS queries, enabling automatic PTR record creation
 * - Conditional domain lookup: get_domain() and get_domain6() select appropriate domain configurations
 *   based on client source IP addresses for split-horizon DNS scenarios
 * - Domain name validation: Ensures domain names comply with RFC 1035 syntax requirements including
 *   label length limits (63 characters) and total name length restrictions (255 characters)
 * - Case-insensitive comparison: Implements hostname comparison following DNS case-insensitivity rules
 *   per RFC 1035 Section 3.1
 * 
 * DEPENDENCIES:
 * Includes:
 *   - dnsmasq.h: Core data structures including struct cond_domain, union all_addr, daemon global state
 *   - Standard C libraries: For string manipulation (atoi, atoll) and network byte order (htonl, ntohl)
 * 
 * Called by:
 *   - forward.c: DNS query forwarding logic uses synthetic name matching and conditional domain selection
 *   - cache.c: DNS cache operations use domain matching for cache key generation and lookup
 *   - option.c: Configuration parsing validates domain names during startup
 *   - dhcp.c, dhcp6.c: DHCP lease assignment uses conditional domains for client classification
 * 
 * Calls:
 *   - hostname_isequal() in util.c: Case-insensitive hostname comparison
 *   - inet_ntop(), inet_pton(): IP address string conversion (standard library)
 *   - addr6part(), setaddr6part(): IPv6 address manipulation utilities from dnsmasq.h
 * 
 * DATA STRUCTURES:
 * - struct cond_domain (defined dnsmasq.h:1037): Represents conditional domain configuration with
 *   address ranges (IPv4/IPv6), domain suffix, prefix string, and linked list structure. Used for
 *   matching client addresses to appropriate domain configurations in split-horizon scenarios.
 * - union all_addr (defined dnsmasq.h): Union of struct in_addr (addr4) and struct in6_addr (addr6)
 *   for protocol-independent address storage
 * 
 * COMPILE-TIME OPTIONS:
 * - HAVE_IDN: Enables Internationalized Domain Name support via libidn (IDN 2003 standard) for
 *   domain names containing non-ASCII characters. When enabled, domain comparison handles Unicode
 *   normalization and Punycode encoding.
 * - HAVE_LIBIDN2: Enables IDN support via libidn2 (IDN 2008/IDNA2008 standard), mutually exclusive
 *   with HAVE_IDN. Provides updated Unicode handling and better international character support.
 * - Note: IDN libraries handle conversion between Unicode domain names and ASCII-Compatible Encoding
 *   (ACE) used in DNS wire protocol, but this module primarily operates on already-encoded names.
 * 
 * THREADING/CONCURRENCY:
 * Single-threaded event-driven architecture. All functions operate on shared daemon state
 * (daemon->synth_domains, daemon->cond_domain) accessed from main event loop without locking.
 * Functions are reentrant but not thread-safe due to shared global state access.
 * 
 * @copyright Copyright (c) 2000-2025 Simon Kelley
 * @license GPL-2.0-or-later
 */

#include "dnsmasq.h"

/* Static helper function forward declarations */
static struct cond_domain *search_domain(struct in_addr addr, struct cond_domain *c);
static int match_domain(struct in_addr addr, struct cond_domain *c);
static struct cond_domain *search_domain6(struct in6_addr *addr, struct cond_domain *c);
static int match_domain6(struct in6_addr *addr, struct cond_domain *c);

/**
 * @brief Check if domain name matches synthetic domain configuration and generate corresponding IP address
 * 
 * @detailed Validates whether a given domain name matches any configured synthetic domain patterns
 * (from daemon->synth_domains list) and generates the corresponding IP address if a match is found.
 * Synthetic domains enable automatic DNS responses for ranges of hostnames without explicit configuration,
 * commonly used for reverse DNS zones or automatic hostname generation in DHCP environments.
 * 
 * The function performs case-insensitive prefix matching followed by either indexed matching (numeric
 * component extraction) or direct subnet-based matching. For indexed domains, extracts numeric index
 * from hostname, validates it falls within configured address range, and computes corresponding IP.
 * For non-indexed domains, performs hexadecimal parsing of address components from hostname.
 * 
 * @param flags Query flags indicating protocol family (F_IPV6 for IPv6, otherwise IPv4)
 * @param name Domain name to check (null-terminated string). Modified in-place during processing
 *             (dots replaced with nulls for parsing), restored on failure. Must not be NULL.
 * @param addrp Output parameter receiving generated IP address on successful match. Must not be NULL.
 *              For IPv4: addrp->addr4 set to struct in_addr. For IPv6: addrp->addr6 set to struct in6_addr.
 * 
 * @return 1 if name matches synthetic domain configuration and address generated successfully,
 *         0 if no match found or name does not conform to synthetic pattern
 * @retval 1 Name matches synthetic domain, addrp contains generated address, name may be modified
 * @retval 0 No synthetic match, addrp unchanged, name restored to original state
 * 
 * @note Modifies input 'name' string during processing by replacing dots with null terminators for
 *       domain component parsing. Restores original dots if function returns 0 (no match).
 * @warning Input 'name' buffer must be writable. Caller must preserve original name separately if
 *          needed after failed match, as restoration may not be complete in all code paths.
 * 
 * @see is_rev_synth() for reverse operation (IP address to synthetic name generation)
 * @see struct cond_domain in dnsmasq.h:1037 for synthetic domain configuration structure
 * 
 * EXAMPLE USAGE:
 * @code
 * union all_addr addr;
 * char hostname[] = "host10.example.com";
 * if (is_name_synthetic(F_IPV4, hostname, &addr)) {
 *   // addr.addr4 now contains IPv4 address for host10
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: Domain name syntax per RFC 1035 Section 3.1 (case-insensitive comparison)
 * SIDE EFFECTS: Modifies daemon->synth_domains list traversal; modifies input name string temporarily
 * THREAD SAFETY: Not thread-safe, accesses shared daemon->synth_domains without locking
 */
int is_name_synthetic(int flags, char *name, union all_addr *addrp)
{
  char *p;
  struct cond_domain *c = NULL;
  int prot = (flags & F_IPV6) ? AF_INET6 : AF_INET;
  union all_addr addr;
  
  for (c = daemon->synth_domains; c; c = c->next)
    {
      int found = 0;
      char *tail, *pref;
      
      for (tail = name, pref = c->prefix; *tail != 0 && pref && *pref != 0; tail++, pref++)
	{
	  unsigned int c1 = (unsigned char) *pref;
	  unsigned int c2 = (unsigned char) *tail;
	  
	  if (c1 >= 'A' && c1 <= 'Z')
	    c1 += 'a' - 'A';
	  if (c2 >= 'A' && c2 <= 'Z')
	    c2 += 'a' - 'A';
	  
	  if (c1 != c2)
	    break;
	}
      
      if (pref && *pref != 0)
	continue; /* prefix match fail */

      if (c->indexed)
	{
	  for (p = tail; *p; p++)
	    {
	      char c = *p;
	      
	      if (c < '0' || c > '9')
		break;
	    }
	  
	  if (*p != '.')
	    continue;
	  
	  *p = 0;
	  
	  if (hostname_isequal(c->domain, p+1))
	    {
	      if (prot == AF_INET)
		{
		  unsigned int index = atoi(tail);

		   if (!c->is6 &&
		      index <= ntohl(c->end.s_addr) - ntohl(c->start.s_addr))
		    {
		      addr.addr4.s_addr = htonl(ntohl(c->start.s_addr) + index);
		      found = 1;
		    }
		} 
	      else
		{
		  u64 index = atoll(tail);
		  
		  if (c->is6 &&
		      index <= addr6part(&c->end6) - addr6part(&c->start6))
		    {
		      u64 start = addr6part(&c->start6);
		      addr.addr6 = c->start6;
		      setaddr6part(&addr.addr6, start + index);
		      found = 1;
		    }
		}
	    }
	}
      else
	{
	  /* NB, must not alter name if we return zero */
	  for (p = tail; *p; p++)
	    {
	      char c = *p;
	      
	      if ((c >='0' && c <= '9') || c == '-')
		continue;
	      
	      if (prot == AF_INET6 && ((c >='A' && c <= 'F') || (c >='a' && c <= 'f'))) 
		continue;
	      
	      break;
	    }
	  
	  if (*p != '.')
	    continue;
	  
	  *p = 0;	
	  
	  /* swap . or : for - */
	  for (p = tail; *p; p++)
	    if (*p == '-')
	      {
		if (prot == AF_INET)
		  *p = '.';
		else
		  *p = ':';
	      }
	  
	  if (hostname_isequal(c->domain, p+1) && inet_pton(prot, tail, &addr))
	    found = (prot == AF_INET) ? match_domain(addr.addr4, c) : match_domain6(&addr.addr6, c);
	}
      
      /* restore name */
      for (p = tail; *p; p++)
	if (*p == '.' || *p == ':')
	  *p = '-';
      
      *p = '.';
      
      
      if (found)
	{
	  if (addrp)
	    *addrp = addr;
	  
	  return 1;
	}
    }
  
  return 0;
}

/**
 * @brief Generate synthetic domain name from IP address for reverse DNS queries
 * 
 * @detailed Performs reverse synthetic name generation by searching the configured synthetic
 *           domain list for a domain that includes the specified IP address, then constructing
 *           the corresponding synthetic domain name. This function supports both indexed
 *           (numeric suffix) and address-based synthetic name generation for IPv4 and IPv6.
 *           Used primarily for automatic PTR record generation enabling reverse DNS resolution
 *           of synthetic forward records without manual configuration.
 * 
 * @param flag Protocol flags indicating address family (F_IPV4 or F_IPV6 from dnsmasq.h)
 * @param addr Pointer to address for which to generate synthetic name (must not be NULL)
 * @param name Output buffer for generated synthetic domain name (must be at least MAXDNAME bytes)
 * 
 * @return 1 if synthetic name generated successfully, 0 if no matching synthetic domain found
 * @retval 1 Address matched configured synthetic domain, name buffer populated with synthetic hostname
 * @retval 0 No synthetic domain configuration matched the address, name buffer unchanged
 * 
 * @note Modifies name buffer only on successful match (return value 1)
 * @note For indexed mode, generates name as "<prefix><index>.<domain>" where index is offset from range start
 * @note For non-indexed mode, generates name as "<prefix><addr-with-dashes>.<domain>"
 * @warning Caller must ensure name buffer is at least MAXDNAME bytes to prevent overflow
 * @warning addr parameter must not be NULL
 * 
 * @see is_name_synthetic() for forward synthetic name validation
 * @see search_domain() for IPv4 address-to-domain matching logic
 * @see search_domain6() for IPv6 address-to-domain matching logic
 * 
 * EXAMPLE USAGE:
 * @code
 * union all_addr addr;
 * char hostname[MAXDNAME];
 * addr.addr4.s_addr = inet_addr("192.168.1.100");
 * if (is_rev_synth(F_IPV4, &addr, hostname)) {
 *   // hostname now contains synthetic name like "prefix100.synth.example.com"
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: Generates domain names conforming to RFC 1035 Section 2.3.1 (domain name syntax)
 * SIDE EFFECTS: Writes to name buffer on successful match; reads daemon->synth_domains global state
 * THREAD SAFETY: Not thread-safe due to daemon global state access and lack of locking
 */
int is_rev_synth(int flag, union all_addr *addr, char *name)
{
   struct cond_domain *c;

   if (flag & F_IPV4 && (c = search_domain(addr->addr4, daemon->synth_domains))) 
     {
       char *p;
       
       *name = 0;
       if (c->indexed)
	 {
	   unsigned int index = ntohl(addr->addr4.s_addr) - ntohl(c->start.s_addr);
	   snprintf(name, MAXDNAME, "%s%u", c->prefix ? c->prefix : "", index);
	 }
       else
	 {
	   if (c->prefix)
	     strncpy(name, c->prefix, MAXDNAME - ADDRSTRLEN);
       
       	   inet_ntop(AF_INET, &addr->addr4, name + strlen(name), ADDRSTRLEN);
	   for (p = name; *p; p++)
	     if (*p == '.')
	       *p = '-';
	 }
       
       strncat(name, ".", MAXDNAME);
       strncat(name, c->domain, MAXDNAME);

       return 1;
     }

   if ((flag & F_IPV6) && (c = search_domain6(&addr->addr6, daemon->synth_domains))) 
     {
       *name = 0;

       if (c->indexed)
	 {
	   u64 index = addr6part(&addr->addr6) - addr6part(&c->start6);
	   snprintf(name, MAXDNAME, "%s%llu", c->prefix ? c->prefix : "", index);
	 }
       else
	 {
	   int i;
	   char frag[6];

	   if (c->prefix)
	     strncpy(name, c->prefix, MAXDNAME);
	   
	   for (i = 0; i < 16; i += 2)
	     {
	       sprintf(frag, "%s%02x%02x",  i == 0 ? "" : "-", addr->addr6.s6_addr[i], addr->addr6.s6_addr[i+1]);
	       strncat(name, frag, MAXDNAME);
	     }
	 }

       strncat(name, ".", MAXDNAME);
       strncat(name, c->domain, MAXDNAME);
       
       return 1;
     }
   
   return 0;
}


/**
 * @brief Test if IPv4 address matches conditional domain configuration
 * 
 * @detailed Determines whether the specified IPv4 address falls within the address range or
 *           network prefix configured for a conditional domain entry. This function supports
 *           two matching modes: interface-based matching where addresses are tested against
 *           all IPv4 prefixes associated with a named interface, and range-based matching
 *           where the address is tested against an explicit start-end address range. This
 *           flexibility enables conditional domains to be configured either by interface name
 *           (automatically tracking interface address changes) or by static address ranges.
 *           The function is used internally by search_domain() to implement conditional
 *           domain selection logic.
 * 
 * @param addr IPv4 address to test against conditional domain configuration
 * @param c Pointer to conditional domain configuration entry containing match criteria
 * 
 * @return Integer boolean indicating match success
 * @retval 1 Address matches: either falls within configured range or matches interface prefix
 * @retval 0 Address does not match: outside range, wrong address family, or no match found
 * 
 * @note Static internal helper function - not part of public module API
 * @note Interface-based matching iterates through all IPv4 addresses on the interface
 * @note Range-based matching uses host byte order comparison via ntohl() for correct ordering
 * @note Returns 0 immediately if conditional domain is configured for IPv6 (!c->is6 check)
 * @warning Assumes c is non-NULL; NULL c will cause segmentation fault
 * 
 * @see search_domain() which uses this function to find matching conditional domains
 * @see is_same_net_prefix() for subnet prefix matching logic (network.c)
 * @see struct cond_domain in dnsmasq.h for conditional domain configuration structure
 * @see struct addrlist in dnsmasq.h for interface address list structure
 * 
 * EXAMPLE USAGE:
 * @code
 * struct cond_domain *c = ...; // conditional domain config for 192.168.1.0/24
 * struct in_addr test_addr;
 * test_addr.s_addr = inet_addr("192.168.1.100");
 * if (match_domain(test_addr, c))
 *   printf("Address matches conditional domain: %s\n", c->domain);
 * @endcode
 * 
 * RFC COMPLIANCE: N/A - internal helper for dnsmasq-specific conditional domain feature
 * SIDE EFFECTS: None - pure read-only comparison of address against configuration
 * THREAD SAFETY: Not thread-safe if conditional domain configuration modified concurrently
 */
static int match_domain(struct in_addr addr, struct cond_domain *c)
{
  if (c->interface)
    {
      struct addrlist *al;
      for (al = c->al; al; al = al->next)
	if (!(al->flags & ADDRLIST_IPV6) &&
	    is_same_net_prefix(addr, al->addr.addr4, al->prefixlen))
	  return 1;
    }
  else if (!c->is6 &&
	   ntohl(addr.s_addr) >= ntohl(c->start.s_addr) &&
	   ntohl(addr.s_addr) <= ntohl(c->end.s_addr))
    return 1;

  return 0;
}

/**
 * @brief Search conditional domain list for IPv4 address match
 * 
 * @detailed Iterates through the linked list of conditional domain configurations starting
 *           from the provided node, testing each entry to find a conditional domain whose
 *           configured address range includes the specified IPv4 address. This is an internal
 *           helper function used by get_domain() to implement conditional domain selection.
 *           The function performs linear search through the list, returning the first matching
 *           conditional domain entry or NULL if no match is found in the entire list.
 * 
 * @param addr IPv4 address to test against conditional domain address ranges
 * @param c Starting node of conditional domain linked list to search; NULL allowed (returns NULL)
 * 
 * @return Pointer to matching cond_domain structure or NULL if no match found
 * @retval non-NULL Pointer to first cond_domain entry whose address range includes addr
 * @retval NULL If c is NULL, or if no entry in the list matches addr
 * 
 * @note Static internal helper function - not part of public module API
 * @note Linear search may iterate through all configured conditional domains (typically <10 entries)
 * @warning Assumes conditional domain list structure is well-formed (no circular references)
 * 
 * @see match_domain() for address range matching logic
 * @see get_domain() for public API using this function
 * @see struct cond_domain in dnsmasq.h for conditional domain configuration structure
 * 
 * EXAMPLE USAGE:
 * @code
 * struct in_addr test_addr;
 * test_addr.s_addr = inet_addr("192.168.1.100");
 * struct cond_domain *match = search_domain(test_addr, daemon->cond_domain);
 * if (match)
 *   printf("Matched conditional domain: %s\n", match->domain);
 * @endcode
 * 
 * RFC COMPLIANCE: N/A - internal helper for conditional domain configuration feature
 * SIDE EFFECTS: None - pure read-only list traversal
 * THREAD SAFETY: Not thread-safe if conditional domain list is modified concurrently
 */
static struct cond_domain *search_domain(struct in_addr addr, struct cond_domain *c)
{
  for (; c; c = c->next)
    if (match_domain(addr, c))
      return c;
  
  return NULL;
}

/**
 * @brief Retrieve conditional domain name for IPv4 address
 * 
 * @detailed Searches the list of conditional domain configurations to find a domain matching
 *           the specified IPv4 address. Conditional domains enable split-horizon DNS where
 *           different client networks receive different domain suffixes for local name resolution.
 *           If no conditional domain matches the address, returns the global default domain suffix.
 *           This function is used during DNS query processing and DHCP lease assignment to determine
 *           the appropriate domain for a client based on its IP address.
 * 
 * @param addr IPv4 address to match against conditional domain configurations
 * 
 * @return Pointer to domain string (null-terminated), either from matching conditional domain or global default
 * @retval non-NULL Domain string from daemon->cond_domain entry if address matched a configured range
 * @retval non-NULL Global domain suffix from daemon->domain_suffix if no conditional domain matched
 * @retval NULL Only if both conditional domain search and global default are unconfigured (rare edge case)
 * 
 * @note Return value points to persistent configuration memory, valid for daemon lifetime
 * @note Does not allocate memory; returns pointer to existing configuration string
 * @warning Returned pointer must not be freed by caller
 * 
 * @see get_domain6() for IPv6 equivalent functionality
 * @see search_domain() for IPv4 address matching logic
 * @see struct cond_domain in dnsmasq.h for conditional domain configuration structure
 * 
 * EXAMPLE USAGE:
 * @code
 * struct in_addr client_addr;
 * client_addr.s_addr = inet_addr("192.168.1.100");
 * char *domain = get_domain(client_addr);
 * // domain now contains appropriate domain suffix for this client's network
 * snprintf(fqdn, sizeof(fqdn), "client-hostname.%s", domain);
 * @endcode
 * 
 * RFC COMPLIANCE: Domain selection supports RFC 1035 domain name syntax
 * SIDE EFFECTS: None - pure read-only lookup of daemon configuration state
 * THREAD SAFETY: Not thread-safe due to daemon global state access without locking
 */
char *get_domain(struct in_addr addr)
{
  struct cond_domain *c;

  if ((c = search_domain(addr, daemon->cond_domain)))
    return c->domain;

  return daemon->domain_suffix;
} 

/**
 * @brief Test if IPv6 address matches conditional domain configuration
 * 
 * @detailed Determines whether the specified IPv6 address falls within the IPv6 address range,
 *           network prefix, or interface subnet configured for a conditional domain entry.
 *           This function is the IPv6 equivalent of match_domain() for IPv4, providing support
 *           for two matching modes: interface-based matching where addresses are tested against
 *           all IPv6 prefixes associated with a named interface, and range-based matching where
 *           the address is tested against configured IPv6 start-end ranges with prefix length.
 *           For ranges with prefix length >= 64 bits, the function uses optimized matching that
 *           checks the /64 network portion separately from the interface identifier portion,
 *           enabling efficient range checking within a single /64 subnet. For ranges with
 *           prefix length < 64, simpler network prefix matching is used. This flexibility
 *           enables conditional domains to be configured either by interface name (automatically
 *           tracking interface address changes) or by static IPv6 address ranges.
 * 
 * @param addr Pointer to IPv6 address to test against conditional domain configuration;
 *             must not be NULL (NULL will cause segmentation fault)
 * @param c Pointer to conditional domain configuration entry containing IPv6 match criteria;
 *          must not be NULL (NULL will cause segmentation fault)
 * 
 * @return Integer boolean indicating match success
 * @retval 1 Address matches: falls within configured range, matches interface prefix, or within /64 subnet range
 * @retval 0 Address does not match: outside range, wrong address family (IPv4 config), or no match found
 * 
 * @note Static internal helper function - not part of public module API
 * @note Interface-based matching iterates through all IPv6 addresses on the interface
 * @note Range-based matching with prefixlen >= 64 uses addr6part() to extract lower 64 bits for efficient range checking
 * @note Range-based matching with prefixlen < 64 uses network prefix comparison only
 * @note Returns 0 immediately if conditional domain is configured for IPv4 only (c->is6 check)
 * @warning Assumes both addr and c are non-NULL; NULL parameters will cause segmentation fault
 * @warning Assumes addr points to valid in6_addr structure with properly initialized address data
 * 
 * @see search_domain6() which uses this function to find matching conditional domains
 * @see match_domain() for IPv4 equivalent functionality with similar logic
 * @see is_same_net6() for IPv6 subnet prefix matching logic (network.c)
 * @see addr6part() for extracting lower 64 bits of IPv6 address (dnsmasq.h)
 * @see struct cond_domain in dnsmasq.h for conditional domain configuration structure
 * @see struct addrlist in dnsmasq.h for interface address list structure
 * 
 * EXAMPLE USAGE:
 * @code
 * struct cond_domain *c = ...; // conditional domain config for 2001:db8::/64 range
 * struct in6_addr test_addr6;
 * inet_pton(AF_INET6, "2001:db8::1234", &test_addr6);
 * if (match_domain6(&test_addr6, c))
 *   printf("IPv6 address matches conditional domain: %s\n", c->domain);
 * @endcode
 * 
 * RFC COMPLIANCE: N/A - internal helper for dnsmasq-specific conditional domain feature
 * SIDE EFFECTS: None - pure read-only comparison of address against configuration
 * THREAD SAFETY: Not thread-safe if conditional domain configuration modified concurrently
 */
static int match_domain6(struct in6_addr *addr, struct cond_domain *c)
{
    
  /* subnet from interface address. */
  if (c->interface)
    {
      struct addrlist *al;
      for (al = c->al; al; al = al->next)
	if (al->flags & ADDRLIST_IPV6 &&
	    is_same_net6(addr, &al->addr.addr6, al->prefixlen))
	  return 1;
    }
  else if (c->is6)
    {
      if (c->prefixlen >= 64)
	{
	  u64 addrpart = addr6part(addr);
	  if (is_same_net6(addr, &c->start6, 64) &&
	      addrpart >= addr6part(&c->start6) &&
	      addrpart <= addr6part(&c->end6))
	    return 1;
	}
      else if (is_same_net6(addr, &c->start6, c->prefixlen))
	return 1;
    }
    
  return 0;
}

/**
 * @brief Search conditional domain list for IPv6 address match
 * 
 * @detailed Iterates through the linked list of conditional domain configurations starting
 *           from the provided node, testing each entry to find a conditional domain whose
 *           configured IPv6 address range or prefix includes the specified IPv6 address.
 *           This is the IPv6-equivalent internal helper function to search_domain() for IPv4.
 *           Used by get_domain6() to implement conditional domain selection for IPv6 clients.
 *           The function performs linear search through the list, returning the first matching
 *           conditional domain entry or NULL if no match is found in the entire list.
 * 
 * @param addr Pointer to IPv6 address to test against conditional domain address ranges;
 *             NULL allowed (will not match any entry, returns NULL)
 * @param c Starting node of conditional domain linked list to search; NULL allowed (returns NULL)
 * 
 * @return Pointer to matching cond_domain structure or NULL if no match found
 * @retval non-NULL Pointer to first cond_domain entry whose IPv6 address range includes addr
 * @retval NULL If c is NULL, addr is NULL, or if no entry in the list matches addr
 * 
 * @note Static internal helper function - not part of public module API
 * @note Linear search may iterate through all configured conditional domains (typically <10 entries)
 * @note NULL addr parameter is explicitly allowed and will result in NULL return (no match possible)
 * @warning Assumes conditional domain list structure is well-formed (no circular references)
 * 
 * @see match_domain6() for IPv6 address range matching logic
 * @see get_domain6() for public API using this function
 * @see search_domain() for IPv4 equivalent functionality
 * @see struct cond_domain in dnsmasq.h for conditional domain configuration structure
 * 
 * EXAMPLE USAGE:
 * @code
 * struct in6_addr test_addr6;
 * inet_pton(AF_INET6, "2001:db8::1", &test_addr6);
 * struct cond_domain *match = search_domain6(&test_addr6, daemon->cond_domain);
 * if (match)
 *   printf("Matched conditional domain: %s\n", match->domain);
 * @endcode
 * 
 * RFC COMPLIANCE: N/A - internal helper for conditional domain configuration feature
 * SIDE EFFECTS: None - pure read-only list traversal
 * THREAD SAFETY: Not thread-safe if conditional domain list is modified concurrently
 */
static struct cond_domain *search_domain6(struct in6_addr *addr, struct cond_domain *c)
{
  for (; c; c = c->next)
    if (match_domain6(addr, c))
      return c;
  
  return NULL;
}

/**
 * @brief Retrieve conditional domain name for IPv6 address
 * 
 * @detailed Searches the list of conditional domain configurations to find a domain matching
 *           the specified IPv6 address. This function provides IPv6-equivalent functionality
 *           to get_domain() for IPv4. Conditional domains enable split-horizon DNS where
 *           different client networks receive different domain suffixes for local name resolution.
 *           If no conditional domain matches the address, or if addr is NULL, returns the global
 *           default domain suffix. Used during DHCPv6 lease assignment and IPv6 DNS query
 *           processing to determine the appropriate domain suffix for a client.
 * 
 * @param addr Pointer to IPv6 address to match against conditional domain configurations;
 *             NULL results in returning global default domain
 * 
 * @return Pointer to domain string (null-terminated), either from matching conditional domain or global default
 * @retval non-NULL Domain string from daemon->cond_domain entry if address matched a configured IPv6 range
 * @retval non-NULL Global domain suffix from daemon->domain_suffix if no conditional domain matched or addr NULL
 * @retval NULL Only if both conditional domain search and global default are unconfigured (rare edge case)
 * 
 * @note Return value points to persistent configuration memory, valid for daemon lifetime
 * @note Does not allocate memory; returns pointer to existing configuration string
 * @note NULL addr parameter is explicitly allowed and treated as "no specific address" case
 * @warning Returned pointer must not be freed by caller
 * 
 * @see get_domain() for IPv4 equivalent functionality
 * @see search_domain6() for IPv6 address matching logic
 * @see struct cond_domain in dnsmasq.h for conditional domain configuration structure
 * 
 * EXAMPLE USAGE:
 * @code
 * struct in6_addr client_addr6;
 * inet_pton(AF_INET6, "2001:db8::1", &client_addr6);
 * char *domain = get_domain6(&client_addr6);
 * // domain now contains appropriate domain suffix for this IPv6 client's network
 * snprintf(fqdn, sizeof(fqdn), "client-hostname.%s", domain);
 * @endcode
 * 
 * RFC COMPLIANCE: Domain selection supports RFC 1035 domain name syntax for IPv6 contexts
 * SIDE EFFECTS: None - pure read-only lookup of daemon configuration state
 * THREAD SAFETY: Not thread-safe due to daemon global state access without locking
 */
char *get_domain6(struct in6_addr *addr)
{
  struct cond_domain *c;

  if (addr && (c = search_domain6(addr, daemon->cond_domain)))
    return c->domain;

  return daemon->domain_suffix;
} 

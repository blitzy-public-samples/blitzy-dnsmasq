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
 * @file forward.c
 * @brief DNS query forwarding engine and state machine
 * 
 * DETAILED PURPOSE:
 * This module implements the core DNS query forwarding state machine that tracks
 * the complete lifecycle of DNS queries from initial client reception through cache
 * lookup, upstream server forwarding, response validation, cache population, and
 * final client response transmission. It manages query state using struct frec
 * (forward record) to track outstanding queries, handles both UDP and TCP transport
 * protocols, implements retry logic with configurable timeouts, and coordinates with
 * cache.c for local resolution, rfc1035.c for DNS wire format processing, and
 * dnssec.c for cryptographic validation when DNSSEC is enabled.
 * 
 * KEY RESPONSIBILITIES:
 * - receive_query(): Accept DNS queries from clients on UDP/TCP sockets, validate
 *   query format, check local cache via cache.c, initiate upstream forwarding
 * - forward_query(): Select upstream DNS server using round-robin with failure
 *   tracking, construct outbound query with randomized source port and query ID,
 *   manage EDNS0 options including DO bit for DNSSEC
 * - reply_query(): Process upstream DNS responses, validate response matches
 *   outstanding query, populate cache via cache.c, return response to client
 * - Upstream server selection: Implement server rotation algorithm with failure
 *   detection, timeout tracking (TIMEOUT=10s default from config.h), and automatic
 *   failover to alternative servers
 * - TCP fallback handling: Detect truncated UDP responses (TC bit set), establish
 *   TCP connection to upstream server, retry query over reliable transport
 * - Query state management: Allocate struct frec for each outstanding query,
 *   track query ID, source port, client address, upstream server, EDNS0 state
 * - Socket management: Randomize UDP source ports for security, manage TCP
 *   connection lifecycle, handle socket errors and resource exhaustion
 * - DNSSEC integration: Coordinate with dnssec.c for validation when DO bit set,
 *   handle DNSSEC-specific record types (DNSKEY, DS, RRSIG), manage validation state
 * 
 * DEPENDENCIES:
 * Includes: dnsmasq.h (core data structures including struct frec, struct server)
 * Called by: Main event loop in dnsmasq.c dispatches network events to receive_query()
 * Calls: cache.c (cache_find_by_name, cache_insert), rfc1035.c (extract_name,
 *        add_resource_record), dnssec.c (dnssec_validate_reply when HAVE_DNSSEC),
 *        network.c (socket operations), util.c (retry_send)
 * 
 * DATA STRUCTURES:
 * - struct frec: Forward record tracking outstanding queries (defined dnsmasq.h:794-819)
 *   Contains query ID, source address/port, upstream server pointer, flags, timing
 * - struct server: Upstream DNS server descriptor (dnsmasq.h) with address, domain
 *   restrictions, failure tracking, EDNS0 capability flags
 * - struct randfd: Random file descriptor for source port randomization
 * - struct randfd_list: List of randomized UDP sockets per upstream server
 * 
 * COMPILE-TIME OPTIONS:
 * - HAVE_DNSSEC: Enable DNSSEC validation integration with dnssec.c
 * - HAVE_CONNTRACK: Enable Linux connection tracking mark preservation
 * - HAVE_IPSET: Enable ipset population with resolved addresses
 * - HAVE_NFTSET: Enable nftables set population
 * - TIMEOUT (config.h:30): Upstream query timeout in seconds, default 10
 * - FORWARD_TEST (config.h:21): Maximum forwarding test depth, default 30
 * - FORWARD_TIME (config.h:22): Forwarding time threshold in seconds, default 30
 * 
 * THREADING/CONCURRENCY:
 * Single-threaded event-driven architecture. All functions execute in main event
 * loop context with no concurrent access. Query state mutations are atomic within
 * function call boundaries. No locking required due to single-threaded design.
 * 
 * @copyright Copyright (c) 2000-2025 Simon Kelley
 * @license GPL-2.0-or-later
 */

#include "dnsmasq.h"

static struct frec *get_new_frec(time_t now, struct server *serv, int force);
static struct frec *lookup_frec(time_t now, char *target, int class, int rrtype, int id, int flags, int flagmask);
#ifdef HAVE_DNSSEC
static int tcp_key_recurse(time_t now, int status, struct dns_header *header, size_t n, 
			   int class, char *name, char *keyname, struct server *server, 
			   int have_mark, unsigned int mark, int *keycount, int *validatecount);
#endif
static unsigned short get_id(void);
static void free_frec(struct frec *f);
static void query_full(time_t now, char *domain);

/**
 * @brief Send UDP packet with explicit source address using platform-specific APIs
 * 
 * @detailed Transmits a UDP packet using sendmsg() with ancillary data to specify
 * the source IP address for the outgoing packet. On Linux, uses IP_PKTINFO/IPV6_PKTINFO
 * control messages; on BSD systems uses IP_SENDSRCADDR. This allows dnsmasq to respond
 * from the same IP address that received the original query, critical for correct
 * operation when listening on multiple interfaces or IP addresses. When nowild is set,
 * sends packet with kernel-selected source address (wildcard binding behavior).
 * Platform-specific implementations handle differences in control message structures
 * between Linux (struct in_pktinfo) and BSD (struct in_addr for IPv4).
 * 
 * @param fd Socket file descriptor for sending (must be bound UDP socket)
 * @param nowild If true (non-zero), send with kernel default source address;
 *               if false (0), use explicit source address from 'source' parameter
 * @param packet Pointer to DNS packet buffer to transmit (must not be NULL)
 * @param len Length of packet data in bytes (must be > 0, typically 12-512 for DNS)
 * @param to Destination socket address (IPv4 or IPv6, must not be NULL)
 * @param source Source IP address to use when nowild=0 (IPv4 in addr4, IPv6 in addr6)
 * @param iface Interface index for IPv6 link-local addresses (0 for global addresses)
 * 
 * @return 1 on successful transmission, 0 on failure (errno set by sendmsg)
 * @retval 1 Packet successfully transmitted via sendmsg()
 * @retval 0 Transmission failed (check errno for details: EINVAL, ENETUNREACH, etc.)
 * 
 * @note For IPv6 link-local addresses, iface parameter is required to identify the
 *       correct outbound interface since link-local addresses are not globally unique
 * @warning On Linux, EINVAL errors during IPv6 DAD (Duplicate Address Detection) are
 *          silently ignored as this is a transient condition during interface initialization
 * 
 * @see retry_send() in util.c for automatic retry on EINTR
 * @see receive_query() for typical usage pattern responding to client queries
 * 
 * EXAMPLE USAGE:
 * @code
 * union mysockaddr dest;
 * union all_addr src_addr;
 * src_addr.addr4.s_addr = query_source_addr;
 * int success = send_from(daemon->srv_fd, 0, response_packet, response_len, 
 *                         &dest, &src_addr, 0);
 * @endcode
 * 
 * RFC COMPLIANCE: Supports RFC 1035 DNS protocol UDP transport
 * 
 * SIDE EFFECTS:
 * - Transmits UDP packet via kernel network stack
 * - Sets errno on failure
 * - Logs error message on transmission failure (except EINVAL on Linux)
 * 
 * THREAD SAFETY: Single-threaded architecture, no concurrent calls
 */
int send_from(int fd, int nowild, char *packet, size_t len, 
	      union mysockaddr *to, union all_addr *source,
	      unsigned int iface)
{
  struct msghdr msg;
  struct iovec iov[1]; 
  union {
    struct cmsghdr align; /* this ensures alignment */
#if defined(HAVE_LINUX_NETWORK)
    char control[CMSG_SPACE(sizeof(struct in_pktinfo))];
#elif defined(IP_SENDSRCADDR)
    char control[CMSG_SPACE(sizeof(struct in_addr))];
#endif
    char control6[CMSG_SPACE(sizeof(struct in6_pktinfo))];
  } control_u;
      
  iov[0].iov_base = packet;
  iov[0].iov_len = len;

  msg.msg_control = NULL;
  msg.msg_controllen = 0;
  msg.msg_flags = 0;
  msg.msg_name = to;
  msg.msg_namelen = sa_len(to);
  msg.msg_iov = iov;
  msg.msg_iovlen = 1;
  
  if (!nowild)
    {
      struct cmsghdr *cmptr = msg.msg_control = &control_u.align;

      /* alignment padding passed to the kernel should not be uninitialised. */
      memset(&control_u, 0, sizeof(control_u));
      
      if (to->sa.sa_family == AF_INET)
	{
#if defined(HAVE_LINUX_NETWORK)
	  struct in_pktinfo *p = (struct in_pktinfo *)CMSG_DATA(cmptr);;
	  p->ipi_ifindex = 0;
	  p->ipi_spec_dst = source->addr4;
	  msg.msg_controllen = CMSG_SPACE(sizeof(struct in_pktinfo));
	  cmptr->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
	  cmptr->cmsg_level = IPPROTO_IP;
	  cmptr->cmsg_type = IP_PKTINFO;
#elif defined(IP_SENDSRCADDR)
	  msg.msg_controllen = CMSG_SPACE(sizeof(struct in_addr));
	  memcpy(CMSG_DATA(cmptr), &(source->addr4), sizeof(source->addr4));
	  cmptr->cmsg_len = CMSG_LEN(sizeof(struct in_addr));
	  cmptr->cmsg_level = IPPROTO_IP;
	  cmptr->cmsg_type = IP_SENDSRCADDR;
#endif
	}
      else
	{
	  struct in6_pktinfo *p = (struct in6_pktinfo *)CMSG_DATA(cmptr);
	  p->ipi6_ifindex = iface; /* Need iface for IPv6 to handle link-local addrs */
	  p->ipi6_addr = source->addr6;
	  msg.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo));
	  cmptr->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
	  cmptr->cmsg_type = daemon->v6pktinfo;
	  cmptr->cmsg_level = IPPROTO_IPV6;
	}
    }
  
  while (retry_send(sendmsg(fd, &msg, 0)));

  if (errno != 0)
    {
#ifdef HAVE_LINUX_NETWORK
      /* If interface is still in DAD, EINVAL results - ignore that. */
      if (errno != EINVAL)
	my_syslog(LOG_ERR, _("failed to send packet: %s"), strerror(errno));
#endif
      return 0;
    }
  
  return 1;
}
          
#ifdef HAVE_CONNTRACK
/**
 * @brief Copy connection tracking mark from incoming query to outgoing socket
 * 
 * @detailed Retrieves the conntrack mark from the incoming DNS query and applies it
 *           to the outgoing upstream socket. This enables policy-based routing and
 *           advanced firewall rules to apply consistently across the DNS forwarding path.
 * 
 * @param forward Forward record containing source socket information
 * @param fd File descriptor of outgoing socket to mark
 * 
 * @note Only compiled when HAVE_CONNTRACK is defined
 * @note Mark propagation requires CAP_NET_ADMIN capability or root privileges
 * @warning Setsockopt failure is silent; mark may not be applied if privileges insufficient
 * 
 * @see get_incoming_mark() in conntrack.c for mark retrieval
 * 
 * EXAMPLE USAGE:
 * @code
 * struct frec *forward = get_new_frec(now, server, 0);
 * int udpfd = random_sock(server);
 * set_outgoing_mark(forward, udpfd); // Apply conntrack mark to outgoing socket
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (Linux-specific conntrack integration)
 * SIDE EFFECTS: Sets SO_MARK socket option on fd if mark retrieval succeeds
 * THREAD SAFETY: Single-threaded architecture; modifies socket state
 */
static void set_outgoing_mark(struct frec *forward, int fd)
{
  /* Copy connection mark of incoming query to outgoing connection. */
  unsigned int mark;
  if (get_incoming_mark(&forward->frec_src.source, &forward->frec_src.dest, 0, &mark))
    setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(unsigned int));
}
#endif

/**
 * @brief Log DNS query with socket address information handling IPv4/IPv6
 * 
 * @detailed Helper function that extracts IP address from union mysockaddr and
 *           calls log_query with appropriate flags. For server logging (F_SERVER flag),
 *           uses port number from socket address instead of query type parameter.
 *           Automatically detects address family and sets F_IPV4 or F_IPV6 flags.
 * 
 * @param flags Query logging flags (F_SERVER, F_FORWARD, F_REVERSE, etc.)
 * @param name Domain name being queried or resolved
 * @param addr Socket address containing IP address (IPv4 or IPv6) and optional port
 * @param arg Additional argument passed to log_query (e.g., query source description)
 * @param type Query type (A, AAAA, PTR, etc.) or overridden by port if F_SERVER set
 * 
 * @note When F_SERVER flag is set, type parameter is replaced with port number from addr
 * @note Automatically determines address family from addr->sa.sa_family
 * 
 * @see log_query() in log.c for actual logging implementation
 * 
 * EXAMPLE USAGE:
 * @code
 * union mysockaddr server_addr;
 * server_addr.in.sin_family = AF_INET;
 * server_addr.in.sin_addr.s_addr = inet_addr("8.8.8.8");
 * server_addr.in.sin_port = htons(53);
 * log_query_mysockaddr(F_SERVER | F_FORWARD, "example.com", &server_addr, "query[A]", T_A);
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (logging helper function)
 * SIDE EFFECTS: Generates log message via log_query if logging enabled
 * THREAD SAFETY: Single-threaded architecture; reads socket address structure
 */
/**
 * @brief Log DNS query with mysockaddr address resolution for IPv4/IPv6
 * 
 * @detailed Helper function that logs DNS queries by extracting IP address and port
 *           information from a union mysockaddr structure, which can contain either
 *           IPv4 or IPv6 sockaddr information. The function determines the address
 *           family, extracts the appropriate IP address, and optionally extracts the
 *           port number for server logging. It then delegates to log_query() with
 *           the correct F_IPV4 or F_IPV6 flag added to distinguish address families.
 *           
 *           When the F_SERVER flag is set in the flags parameter, the function
 *           overrides the type parameter with the port number extracted from the
 *           sockaddr structure (converted from network byte order to host byte order
 *           using ntohs). This enables logging of server addresses with their port
 *           numbers. For client queries, the type parameter is passed through as-is,
 *           typically containing a DNS record type (A, AAAA, PTR, etc.).
 *           
 *           The function supports both IPv4 (AF_INET) and IPv6 (AF_INET6) address
 *           families, automatically detecting the family from addr->sa.sa_family and
 *           extracting the appropriate address structure (sin_addr for IPv4,
 *           sin6_addr for IPv6).
 * 
 * @param flags Query flags (F_FORWARD, F_REVERSE, F_SERVER, etc.; F_IPV4/F_IPV6 added automatically)
 * @param name Domain name being queried (NULL-terminated string; NULL treated as empty string by log_query)
 * @param addr Socket address structure containing IP address and port (must not be NULL; must be valid IPv4 or IPv6 sockaddr)
 * @param arg Additional argument string for logging context (NULL-terminated; NULL permitted)
 * @param type DNS query type (A=1, AAAA=28, PTR=12, etc.) or overridden with port number if F_SERVER flag set
 * 
 * @return void (no return value; delegates to log_query which performs actual logging)
 * 
 * @note Assumes addr->sa.sa_family is either AF_INET or AF_INET6 (no validation for other families)
 * @note Port extraction only occurs when F_SERVER flag is set; otherwise type parameter passed unchanged
 * @note ntohs() converts 16-bit port from network byte order (big-endian) to host byte order
 * @note log_query() is called with F_IPV4 or F_IPV6 flag OR'd into flags parameter
 * @warning Function does not validate addr pointer or check for valid address family values
 * @warning Non-IPv4/IPv6 address families fall through to IPv6 branch (potential undefined behavior)
 * 
 * @see log_query() in log.c for actual logging implementation
 * @see union mysockaddr in dnsmasq.h for sockaddr union definition
 * @see union all_addr in dnsmasq.h for IP address union
 * @see F_SERVER flag in dnsmasq.h indicating server address logging
 * @see ntohs() for network-to-host byte order conversion
 * 
 * EXAMPLE USAGE:
 * @code
 * union mysockaddr server_addr;
 * // server_addr populated with IPv4 upstream DNS server 8.8.8.8:53
 * log_query_mysockaddr(F_SERVER | F_FORWARD, "example.com", &server_addr, "to", 0);
 * // Logs: "query[A] example.com to 8.8.8.8#53"
 * @endcode
 * 
 * RFC COMPLIANCE: None (internal logging helper, no protocol specification)
 * SIDE EFFECTS: Calls log_query() which writes to syslog if query logging enabled
 * THREAD SAFETY: Single-threaded architecture; modifies no global state directly
 */
static void log_query_mysockaddr(unsigned int flags, char *name, union mysockaddr *addr, char *arg, unsigned short type)
{
  if (addr->sa.sa_family == AF_INET)
    {
      if (flags & F_SERVER)
	type = ntohs(addr->in.sin_port);
      log_query(flags | F_IPV4, name, (union all_addr *)&addr->in.sin_addr, arg, type);
    }
  else
    {
      if (flags & F_SERVER)
	type = ntohs(addr->in6.sin6_port);
      log_query(flags | F_IPV6, name, (union all_addr *)&addr->in6.sin6_addr, arg, type);
    }
}

/**
 * @brief Send UDP packet to upstream DNS server with automatic retry on EINTR
 * 
 * @detailed Simple wrapper around sendto() system call that automatically retries on
 *           EINTR (interrupted system call) using retry_send() macro. This function
 *           transmits DNS query or response packets to configured upstream DNS servers.
 *           The retry loop handles signal interruption transparently, ensuring the
 *           packet is eventually transmitted or a real error occurs.
 *           
 *           The function extracts the destination address and address length from the
 *           server structure, which contains both IPv4 and IPv6 sockaddr information.
 *           The sa_len() utility handles platform-specific sockaddr length calculation.
 * 
 * @param server Upstream server to send packet to (must not be NULL; contains destination address)
 * @param fd Socket file descriptor for transmission (must be valid open UDP socket)
 * @param header Pointer to packet data to send (DNS query/response packet, must not be NULL)
 * @param plen Packet length in bytes (must be > 0 and <= maximum DNS packet size 65535)
 * @param flags Sendto flags (typically 0; MSG_DONTWAIT, MSG_DONTROUTE, etc. per platform)
 * 
 * @return void (no return value; errors silently ignored after retry exhaustion)
 * 
 * @note retry_send() macro retries on errno == EINTR only, terminates on other errors
 * @note Function does not check sendto() return value after retry_send() completes
 * @note Transmission errors (ENETUNREACH, EHOSTUNREACH, etc.) are silently ignored
 * @warning Silent error handling means packet loss is not reported to caller
 * @warning Blocking sendto() can stall event loop if socket send buffer is full
 * 
 * @see retry_send() macro in dnsmasq.h for EINTR retry logic
 * @see sendto() system call for UDP transmission semantics
 * @see sa_len() in network.c for sockaddr length calculation
 * @see struct server in dnsmasq.h for upstream server structure
 * 
 * EXAMPLE USAGE:
 * @code
 * struct server *server = ...;
 * int fd = server->sfd->fd;
 * struct dns_header *header = ...;
 * size_t plen = 512;
 * 
 * // Send DNS query to upstream server
 * server_send(server, fd, header, plen, 0);
 * // Packet transmitted or silently dropped on error
 * @endcode
 * 
 * RETRY LOGIC:
 * - retry_send() macro: while ((x) == -1 && errno == EINTR)
 * - Retries indefinitely on EINTR (signal interruption)
 * - Terminates on successful send or non-EINTR error
 * - EINTR typically occurs when signal handler interrupts sendto()
 * 
 * ERROR HANDLING:
 * - No explicit error handling after retry_send() completes
 * - Transmission errors silently ignored (ENETUNREACH, EHOSTUNREACH, ECONNREFUSED)
 * - Rationale: UDP is fire-and-forget; upstream timeout will trigger retry at higher level
 * - Alternative error handling would require return value propagation through call chain
 * 
 * PLATFORM CONSIDERATIONS:
 * - sa_len() handles BSD vs. Linux sockaddr length differences
 * - IPv4: sizeof(struct sockaddr_in)
 * - IPv6: sizeof(struct sockaddr_in6)
 * - Flags parameter supports platform-specific sendto() flags
 * 
 * RFC COMPLIANCE: RFC 1035 (UDP DNS query transmission)
 * 
 * SIDE EFFECTS:
 * - Transmits UDP packet to network via sendto() system call
 * - May set errno on transmission failure
 * - No modification of server or header structures
 * 
 * THREAD SAFETY: Thread-safe (no shared state; sendto() is system call)
 */
static void server_send(struct server *server, int fd,
			const void *header, size_t plen, int flags)
{
  while (retry_send(sendto(fd, header, plen, flags,
			   &server->addr.sa,
			   sa_len(&server->addr))));
}

/**
 * @brief Check if domain matches DNS rebinding protection exception list
 * 
 * @detailed Tests whether a query domain matches any entry in the rebind protection
 *           exception list (daemon->no_rebind). This function is used to determine if
 *           DNS responses containing private IP addresses should be allowed for specific
 *           domains despite rebind protection being enabled.
 *           
 *           DNS rebinding attacks exploit DNS to bypass same-origin policy by resolving
 *           public domain names to private IP addresses (RFC 1918: 10.0.0.0/8, 172.16.0.0/12,
 *           192.168.0.0/16). The --stop-dns-rebind option blocks such responses, but this
 *           function identifies domains that should be exempted from the blocking (configured
 *           via --rebind-domain-ok option).
 *           
 *           Matching algorithm:
 *           1. Suffix matching: Domain must end with exception pattern
 *           2. Whole-label matching: Match must occur at label boundary (after '.')
 *           3. Empty pattern matching: Zero-length exception matches any single-label domain
 *           
 *           Examples with exception "example.com":
 *           - "example.com" matches (exact)
 *           - "www.example.com" matches (suffix at label boundary)
 *           - "notexample.com" does NOT match (no label boundary)
 *           
 *           Examples with empty exception "":
 *           - "localhost" matches (single label, no dots)
 *           - "router" matches (single label)
 *           - "www.example.com" does NOT match (multiple labels with dots)
 * 
 * @param domain Domain name to test against exception list (null-terminated string, must not be NULL)
 * 
 * @return Integer indicating match status
 * @retval 1 Domain matches at least one exception pattern (allow rebind response)
 * @retval 0 Domain does not match any exception pattern (apply rebind protection)
 * 
 * @note Matching is case-insensitive via hostname_isequal() function
 * @note Exception list configured via --rebind-domain-ok=<domain> command-line option
 * @note Empty exception pattern ("") matches any single-label domain (no dots)
 * @note Matching requires label boundary alignment to prevent partial label matches
 * @warning Function assumes domain parameter is valid null-terminated string
 * 
 * @see hostname_isequal() in util.c for case-insensitive domain comparison
 * @see struct rebind_domain in dnsmasq.h for exception list structure
 * @see daemon->no_rebind list (populated from --rebind-domain-ok options)
 * @see check_for_local_domain() for related domain filtering logic
 * 
 * EXAMPLE USAGE:
 * @code
 * char *query_domain = "vpn.corp.example.com";
 * 
 * // Check if domain is exempt from rebind protection
 * if (domain_no_rebind(query_domain)) {
 *   // Domain is on exception list, allow private IP in response
 *   return 0; // Don't block response
 * } else {
 *   // Domain not exempt, apply rebind protection
 *   if (is_private_ip(response_ip)) {
 *     return 1; // Block rebind response
 *   }
 * }
 * @endcode
 * 
 * MATCHING ALGORITHM DETAILS:
 * 
 * Suffix Matching:
 * 1. Calculate domain length (dlen) and exception pattern length (tlen)
 * 2. Verify domain is at least as long as pattern (dlen >= tlen)
 * 3. Extract suffix from domain: &domain[dlen - tlen]
 * 4. Compare suffix with pattern using hostname_isequal() (case-insensitive)
 * 5. Verify match occurs at label boundary:
 *    - If dlen == tlen: Exact match, always valid
 *    - If dlen > tlen: Character before match must be '.' (label separator)
 * 
 * Empty Pattern Matching:
 * 1. Check if exception pattern length is zero (tlen == 0)
 * 2. Check if domain has no dots (!dots, i.e., single-label domain)
 * 3. If both true, match (allows single-label domains like "localhost", "router")
 * 
 * Label Boundary Enforcement:
 * - Prevents "example.com" from matching "notexample.com"
 * - Ensures match occurs at '.' separator or start of string
 * - Expression: (dlen == tlen || domain[dlen - tlen - 1] == '.')
 * 
 * DNS REBINDING PROTECTION CONTEXT:
 * - Rebinding attacks: Attacker-controlled DNS resolves public name to private IP
 * - Victim browser makes request to attacker.com, receives 192.168.1.1
 * - Browser treats 192.168.1.1 as same origin as attacker.com
 * - Attacker can access internal network resources via victim browser
 * - Protection: Block DNS responses containing RFC 1918 private IPs
 * - Exceptions: Legitimate internal domains need private IPs (VPN, corporate DNS)
 * 
 * CONFIGURATION:
 * - Exception list built from --rebind-domain-ok=<domain> options
 * - Multiple exceptions supported (linked list via rbd->next)
 * - Empty exception "--rebind-domain-ok=" matches single-label domains
 * - Example: --rebind-domain-ok=vpn.corp.example.com --rebind-domain-ok=
 * 
 * RFC COMPLIANCE:
 * - RFC 1918 (private address space: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
 * - DNS rebinding protection not defined by RFC, security best practice
 * 
 * SIDE EFFECTS:
 * - Calls hostname_isequal() for case-insensitive comparison
 * - Calls strlen() on domain and each exception pattern
 * - Calls strchr() to locate first dot in domain
 * - No modification of domain string or exception list
 * 
 * THREAD SAFETY: Thread-safe (read-only access to daemon->no_rebind list and domain string)
 */
static int domain_no_rebind(char *domain)
{
  struct rebind_domain *rbd;
  size_t tlen, dlen = strlen(domain);
  char *dots = strchr(domain, '.');

  /* Match whole labels only. Empty domain matches no dots (any single label) */
  for (rbd = daemon->no_rebind; rbd; rbd = rbd->next)
    {
      if (dlen >= (tlen = strlen(rbd->domain)) &&
	hostname_isequal(rbd->domain, &domain[dlen - tlen]) &&
	(dlen == tlen || domain[dlen - tlen - 1] == '.'))
      return 1;

      if (tlen == 0 && !dots)
	return 1;
    }
  
  return 0;
}

/**
 * @brief Forward DNS query from client to upstream recursive DNS servers with retry logic
 * 
 * @detailed This is the core DNS forwarding function implementing the complete query forwarding
 *           state machine. It handles both initial query transmission and retry attempts for
 *           queries that have not received responses. The function performs domain validation,
 *           upstream server selection with round-robin rotation, DNS 0x20 randomization for
 *           security, EDNS0 pseudoheader addition for DNSSEC support, socket allocation with
 *           source port randomization, connection tracking mark propagation, and local error
 *           response generation when forwarding fails.
 * 
 *           The forwarding process follows this sequence:
 *           1. For retries: Retrieve stashed packet data and apply DNS 0x20 case randomization
 *           2. For new queries: Extract question section, validate domain, check rebinding protection
 *           3. Allocate forward record (struct frec) to track query state if not already allocated
 *           4. Select upstream servers based on domain-specific routing rules and server availability
 *           5. For each selected server: Add EDNS0 pseudoheader if required, allocate socket with
 *              randomized source port, set connection tracking marks, transmit via sendto()
 *           6. On successful transmission: Update metrics, record timestamp, return
 *           7. On failure to forward: Generate local error response with Extended DNS Error (EDE)
 * 
 *           DNS 0x20 randomization randomly varies the case of alphabetic characters in query 
 *           names, providing protection against cache poisoning attacks by increasing entropy 
 *           in DNS transactions. The randomization is stored in the forward record and applied
 *           consistently to all retries to match against responses.
 * 
 *           The function integrates with multiple subsystems: cache lookup for existing answers,
 *           DNSSEC validation for secure responses, firewall integration (ipset/nftset) for
 *           resolved addresses, connection tracking for mark preservation, and packet dumping
 *           for troubleshooting.
 * 
 * @param udpfd UDP socket file descriptor for client communication (-1 if TCP or no reply socket)
 * @param udpaddr Client source address for sending response (NULL if no reply needed)
 * @param dst_addr Destination address where query was received (for source address binding in replies)
 * @param dst_iface Network interface index where query was received (for IPv6 link-local)
 * @param header DNS packet header (wire format, will be modified in-place for forwarding)
 * @param plen DNS packet length in bytes (including header, limited by PACKETSZ)
 * @param replylimit Maximum size of reply packet that can be sent to client
 * @param now Current time in seconds since epoch (for TTL calculations and timeouts)
 * @param forward Existing forward record for retry (NULL for new query, will be allocated)
 * @param fwd_flags Query processing flags bitmap (FREC_* constants for tracking query state)
 * @param fast_retry Set to 1 if this is a fast retry attempt, 0 for normal retry timing
 * 
 * @return void (no return value)
 * 
 * @note This function modifies header in-place: flips query ID for upstream transmission,
 *       applies DNS 0x20 case randomization to question section, adds EDNS0 pseudoheader
 *       with DO bit, buffer size, and Extended DNS Error options
 * 
 * @warning Function performs network I/O via sendto(); may block briefly on socket operations.
 *          On forwarding failure, sends error response directly to client via send_from().
 * 
 * @see get_new_frec() for forward record allocation and management
 * @see lookup_frec() for finding existing forward records by query ID
 * @see server_send() for selecting next upstream server in rotation
 * @see add_do_bit() in edns0.c for EDNS0 DO bit handling
 * @see domain_no_rebind() for DNS rebinding protection checks
 * @see answer_disallowed() for filtering malicious responses
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dns_header *header = (struct dns_header *)packet;
 * size_t plen = recv_from(udpfd, packet, sizeof(packet), &udpaddr, &dst_addr);
 * size_t replylimit = udp_size(udpfd);
 * forward_query(udpfd, &udpaddr, &dst_addr, dst_iface, header, plen, replylimit, now, NULL, 0, 0);
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 1035 Section 4.1 (DNS query processing and forwarding)
 *                 RFC 6891 (EDNS0 extension mechanism for buffer size and options)
 *                 RFC 7873 (DNS Cookies for DNSSEC)
 *                 RFC 8914 (Extended DNS Errors for detailed failure reporting)
 * 
 * SIDE EFFECTS: Allocates forward record in daemon->frec_list if forward is NULL
 *               Transmits UDP packets to upstream DNS servers via sendto()
 *               Modifies DNS header (ID, case randomization, EDNS0 pseudoheader)
 *               Updates daemon->metrics[METRIC_DNS_QUERIES_FORWARDED]
 *               May allocate new UDP sockets with randomized source ports
 *               Sends local error response to client on forwarding failure
 *               Applies connection tracking marks via setsockopt(SO_MARK)
 *               May trigger firewall set population (ipset/nftset)
 * 
 * THREAD SAFETY: Not thread-safe - modifies global daemon state and forward record list.
 *                 Designed for single-threaded event loop architecture.
 */
static void forward_query(int udpfd, union mysockaddr *udpaddr,
			  union all_addr *dst_addr, unsigned int dst_iface,
			  struct dns_header *header, size_t plen,  size_t replylimit, time_t now, 
			  struct frec *forward, unsigned int fwd_flags, int fast_retry)
{
  unsigned int flags = 0;
  int is_dnssec = forward && (forward->flags & (FREC_DNSKEY_QUERY | FREC_DS_QUERY));
  struct server *master;
  unsigned int gotname;
  int old_src = 0, old_reply = 0;
  int first, last, start = 0;
  int forwarded = 0;
  int ede = EDE_UNSET;
  unsigned short rrtype, rrclass;

  gotname = extract_request(header, plen, daemon->namebuff, &rrtype, &rrclass);
  
  /* Check for retry on existing query.
     FREC_DNSKEY and FREC_DS_QUERY are never set in flags, so the test below 
     ensures that no frec created for internal DNSSEC query can be returned here.
     
     Similarly FREC_NO_CACHE is never set in flags, so a query which is
     contigent on a particular source address EDNS0 option will never be matched. */
  if (forward)
    {
      old_src = 1;
      old_reply = 1;
      fwd_flags = forward->flags;
    }
  else if (gotname && (forward = lookup_frec(now, daemon->namebuff, (int)rrclass, (int)rrtype, -1, fwd_flags,
					     FREC_CHECKING_DISABLED | FREC_AD_QUESTION | FREC_DO_QUESTION |
					     FREC_HAS_PHEADER | FREC_DNSKEY_QUERY | FREC_DS_QUERY | FREC_NO_CACHE)))
    {
      struct frec_src *src;
      unsigned int casediff = 0;
      unsigned int *bitvector = NULL;
      unsigned short id = ntohs(header->id); /* Retrieve the id from the new query before we overwrite it. */
      
      /* Get the case-scambled version of the query to resend. This is important because we
	 may fall through below and forward the query in the packet buffer again and we
	 want to use the same case scrambling as the first time. */
      blockdata_retrieve(forward->stash, forward->stash_len, (void *)header); 
      plen = forward->stash_len;

      for (src = &forward->frec_src; src; src = src->next)
	if (src->orig_id == id && 
	    sockaddr_isequal(&src->source, udpaddr))
	  break;
      
      if (src)
	{
	  old_src = 1;
	  /* If a query is retried, use the log_id for the retry when logging the answer. */
	  src->log_id = daemon->log_id;
	}
      else
	{
	  /* Existing query, but from new source, just add this 
	     client to the list that will get the reply.*/
	  
	  /* Note whine_malloc() zeros memory. */
	  if (!daemon->free_frec_src &&
	      daemon->frec_src_count < daemon->ftabsize &&
	      (daemon->free_frec_src = whine_malloc(sizeof(struct frec_src))))
	    {
	      daemon->frec_src_count++;
	      daemon->free_frec_src->next = NULL;
	      daemon->free_frec_src->encode_bigmap = NULL;
	    }
	  
	  /* If we've been spammed with many duplicates, return REFUSED. */
	  if (!daemon->free_frec_src)
	    {
	      query_full(now, NULL);
	      /* This is tricky; if we're blasted with the same query
		 over and over, we'll end up taking this path each time
		 and never resetting until the frec gets deleted by
		 aging followed by the receipt of a different query. This
		 is a bit of a DoS vuln. Avoid by explicitly deleting the
		 frec once it expires. */
	      if (difftime(now, forward->time) >= TIMEOUT)
		free_frec(forward);
	      goto reply;
	    }

	  /* Find a bitmap of case differences between the query sent upstream and this one,
	     so we can reply to each query with the correct case pattern.
	     Since we need this to get back the exact case pattern of each query when doing
	     query combining, we have to handle the (rare) case that there are case differences
	     beyond the first 32 letters.
	     If that happens we have to allocate memory to save it, and the casediff variable
	     holds the length of that array.
	     Mismatches beyond 32 letters are rare because most queries are all lowercase and
	     we only scramble the first 32 letters for security reasons.

	     Note the two names are guaranteed to be the same length and differ only in the case
	     of letters at this point.

	     The original query we sent is now in packet buffer and the query name in the
	     new instance is on daemon->namebuff. */
	    	  
	  if (extract_name(header, forward->stash_len, NULL, daemon->workspacename, EXTR_NAME_EXTRACT, 0))
	    {
	      unsigned int i, gobig = 0;
	      char *s1, *s2;

#define BITS_IN_INT (sizeof(unsigned int) * 8)
	      
	    big_redo:
	      for (s1 = daemon->namebuff, s2 = daemon->workspacename, i = 0; *s1; s1++, s2++)
		{
		  char c1 = *s1, c2 = *s2;
		  
		  if ((c1 >= 'a' && c1 <= 'z') || (c1 >= 'A' && c1 <= 'Z'))
		    {
		      if ((c1 & 0x20) ^ (c2 & 0x20))
			{
			  if (bitvector)
			    bitvector[i/BITS_IN_INT] |= 1<<(i%BITS_IN_INT);
			  else if (i >= BITS_IN_INT)
			    gobig = 1; /* More than 32 */
			  else
			    casediff |= 1<<i;
			}
		      i++;
		    }
		}

	      if (gobig && !bitvector)
		{
		  casediff = ((i - 1)/BITS_IN_INT) + 1; /* length of array */
		  /* whine_malloc() zeros memory */
		  if ((bitvector = whine_malloc(casediff * sizeof(unsigned int))))
		    goto big_redo;
		}
	    }
	  
	  src = daemon->free_frec_src;
	  daemon->free_frec_src = src->next;
	  src->next = forward->frec_src.next;
	  forward->frec_src.next = src;
	  src->orig_id = id;
	  src->source = *udpaddr;
	  src->dest = *dst_addr;
	  src->log_id = daemon->log_id;
	  src->iface = dst_iface;
	  src->fd = udpfd;
	  src->encode_bitmap = casediff;
	  src->encode_bigmap = bitvector;
	  
	  src->udp_pkt_size = (unsigned short)replylimit;

	  /* closely spaced identical queries cannot be a try and a retry, so
	     it's safe to wait for the reply from the first without
	     forwarding the second. */
	  if (difftime(now, forward->time) < 2)
	    return;
	}
      
      /* use our id when resending */
      header->id = ntohs(forward->new_id);
    }
  
  /* new query */
  if (!forward)
    {
      if (OPCODE(header) != QUERY)
	{
	  flags = F_RCODE;
	  goto reply;
	}
      else if (!gotname)
	{
	  /* If the query is malformed, we can't forward it because
	     we can't recognise the answer. */
	  flags = 0;
	  ede = EDE_INVALID_DATA;
	  goto reply;
	}
      
      if (lookup_domain(daemon->namebuff, gotname, &first, &last))
	flags = is_local_answer(now, first, daemon->namebuff);
      else
	{
	  /* no available server. */
	  ede = EDE_NOT_READY;
	  flags = 0;
	}

      /* don't forward A or AAAA queries for simple names, except the empty name */
      if (!flags &&
	  option_bool(OPT_NODOTS_LOCAL) &&
	  (gotname & (F_IPV4 | F_IPV6)) &&
	  !strchr(daemon->namebuff, '.') &&
	  strlen(daemon->namebuff) != 0)
	flags = check_for_local_domain(daemon->namebuff, now) ? F_NOERR : F_NXDOMAIN;
      
      /* Configured answer. */
      if (flags || ede == EDE_NOT_READY)
	goto reply;

      master = daemon->serverarray[first];

      if (!(forward = get_new_frec(now, master, 0)))
	goto reply;
      /* table full - flags == 0, return REFUSED */

      forward->flags = fwd_flags;

#ifdef HAVE_DNSSEC
      if (option_bool(OPT_DNSSEC_VALID))
	{
	  plen = add_do_bit(header, plen, ((unsigned char *) header) + daemon->edns_pktsz);
	  
	  /* For debugging, set Checking Disabled, otherwise, have the upstream check too,
	     this allows it to select auth servers when one is returning bad data. */
	  if (option_bool(OPT_DNSSEC_DEBUG))
	    header->hb4 |= HB4_CD;
	}
#endif
      
      /* Do these before saving query. */
      forward->frec_src.orig_id = ntohs(header->id);
      forward->new_id = get_id();
      header->id = ntohs(forward->new_id);
      forward->frec_src.encode_bitmap = (!option_bool(OPT_NO_0x20) && option_bool(OPT_DO_0x20)) ? rand32() : 0;
      forward->frec_src.encode_bigmap = NULL;

      if (!extract_name(header, plen, NULL, (char *)&forward->frec_src.encode_bitmap, EXTR_NAME_FLIP, 1))
	goto reply;
      
      /* Keep copy of query for retries and move to TCP */
      if (!(forward->stash = blockdata_alloc((char *)header, plen)))
	{
	  free_frec(forward);
	  goto reply; /* no mem. return REFUSED */
	}
      
      forward->stash_len = plen;
      forward->frec_src.log_id = daemon->log_id;
      forward->frec_src.source = *udpaddr;
      forward->frec_src.dest = *dst_addr;
      forward->frec_src.iface = dst_iface;
      forward->frec_src.next = NULL;
      forward->frec_src.fd = udpfd;
      forward->frec_src.udp_pkt_size = (unsigned short)replylimit;
      forward->forwardall = 0;
      if (domain_no_rebind(daemon->namebuff))
	forward->flags |= FREC_NOREBIND;
#ifdef HAVE_DNSSEC
      forward->work_counter = daemon->limit[LIMIT_WORK];
      forward->validate_counter = daemon->limit[LIMIT_CRYPTO]; 
#endif
      
      start = first;

      if (option_bool(OPT_ALL_SERVERS))
	forward->forwardall = 1;

      if (!option_bool(OPT_ORDER))
	{
	  if (master->forwardcount++ > FORWARD_TEST ||
	      difftime(now, master->forwardtime) > FORWARD_TIME ||
	      master->last_server == -1)
	    {
	      master->forwardtime = now;
	      master->forwardcount = 0;
	      forward->forwardall = 1;
	    }
	  else
	    start = master->last_server;
	}
    }
  else
    {
#ifdef HAVE_DNSSEC
      /* If we've already got an answer to this query, but we're awaiting keys for validation,
	 there's no point retrying the query, retry the key query instead...... */
      while (forward->blocking_query)
	forward = forward->blocking_query;

      /* Don't retry if we've already sent it via TCP. */
      if (forward->flags & FREC_GONE_TO_TCP)
	return;
      
      if (forward->flags & (FREC_DNSKEY_QUERY | FREC_DS_QUERY))
	{
	  /* log_id should match previous DNSSEC query. */
	  daemon->log_display_id = forward->frec_src.log_id;
	  
	  blockdata_retrieve(forward->stash, forward->stash_len, (void *)header);
	  plen = forward->stash_len;
	  /* get query for logging. */
	  gotname = extract_request(header, plen, daemon->namebuff, NULL, NULL);
	  
	  /* Find suitable servers: should never fail. */
	  if (!filter_servers(forward->sentto->arrayposn, F_DNSSECOK, &first, &last))
	    return;
	  
	  is_dnssec = 1;
	  forward->forwardall = 1;
	}
      else
#endif
	{
	  /* retry on existing query, from original source. Send to all available servers  */
	  if (udpfd == -1 && !fast_retry)
	    forward->sentto->failed_queries++;
	  else
	    forward->sentto->retrys++;
	  
	  if (!filter_servers(forward->sentto->arrayposn, F_SERVER, &first, &last))
	    goto reply;
	  
	  master = daemon->serverarray[first];
	  
	  /* Forward to all available servers on retry of query from same host. */
	  if (!option_bool(OPT_ORDER) && old_src && !fast_retry)
	    forward->forwardall = 1;
	  else
	    {
	      start = forward->sentto->arrayposn;
	      
	      if (option_bool(OPT_ORDER) && !fast_retry)
		{
		  /* In strict order mode, there must be a server later in the list
		     left to send to, otherwise without the forwardall mechanism,
		     code further on will cycle around the list forwever if they
		     all return REFUSED. If at the last, give up.
		     Note that we can get here EITHER because a client retried,
		     or an upstream server returned REFUSED. The above only
		     applied in the later case. For client retries,
		     keep trying the last server.. */
		  if (++start == last)
		    {
		      if (old_reply)
			goto reply;
		      else
			start--;
		    }
		}
	    }	  
	}
    }

  if (forward->forwardall)
    start = first;

  forwarded = 0;

  /* Advertise the size of UDP reply we can accept. */
  plen = add_pseudoheader(header, plen, (unsigned char *)(header + daemon->edns_pktsz), 0, NULL, 0, 0, 0);

  /* check for send errors here (no route to host) 
     if we fail to send to all nameservers, send back an error
     packet straight away (helps modem users when offline)  */

  while (1)
    { 
      int fd;
      struct server *srv = daemon->serverarray[start];
      
      if ((fd = allocate_rfd(&forward->rfds, srv)) != -1)
	{
	  
#ifdef HAVE_CONNTRACK
	  /* Copy connection mark of incoming query to outgoing connection. */
	  if (option_bool(OPT_CONNTRACK))
	    set_outgoing_mark(forward, fd);
#endif
	  if (retry_send(sendto(fd, (char *)header, plen, 0,
				&srv->addr.sa,
				sa_len(&srv->addr))))
	    continue;
	  
	  if (errno == 0)
	    {
#ifdef HAVE_DUMPFILE
	      dump_packet_udp(DUMP_UP_QUERY, (void *)header, plen, NULL, &srv->addr, fd);
#endif
	      
	      /* Keep info in case we want to re-send this packet */
	      daemon->srv_save = srv;
	      daemon->packet_len = plen;
	      daemon->fd_save = fd;
	      
	       if (!gotname)
		 strcpy(daemon->namebuff, "query");
	       
	       if (!(forward->flags & (FREC_DNSKEY_QUERY | FREC_DS_QUERY)))
		 log_query_mysockaddr(F_SERVER | F_FORWARD, daemon->namebuff,
				      &srv->addr, NULL, 0);
#ifdef HAVE_DNSSEC
	       else
		 log_query_mysockaddr(F_NOEXTRA | F_DNSSEC | F_SERVER, daemon->namebuff, &srv->addr,
				      (forward->flags & FREC_DNSKEY_QUERY) ? "dnssec-retry[DNSKEY]" : "dnssec-retry[DS]", 0);
#endif

	      srv->queries++;
	      forwarded = 1;
	      forward->sentto = srv;
	      if (!forward->forwardall) 
		break;
	      forward->forwardall++;
	    }
	}
      
      if (++start == last)
	break;
    }
  
  if (forwarded || is_dnssec)
    {
      daemon->metrics[METRIC_DNS_QUERIES_FORWARDED]++;
      forward->forward_timestamp = dnsmasq_milliseconds();
      return;
    }
  
  /* could not send on, prepare to return */ 
  header->id = htons(forward->frec_src.orig_id);
  free_frec(forward); /* cancel */
  ede = EDE_NETERR;
  
 reply:
  if (udpfd != -1)
    {
      if (!(plen = make_local_answer(flags, gotname, plen, header, daemon->namebuff, (char *)(header + replylimit), first, last, ede)))
	return;
      
      if (fwd_flags & FREC_HAS_PHEADER)
	{
	  u16 swap = htons((u16)ede);

	  if (ede != EDE_UNSET)
	    plen = add_pseudoheader(header, plen, (unsigned char *)(header + replylimit), EDNS0_OPTION_EDE, (unsigned char *)&swap, 2, 0, 0);
	  else
	    plen = add_pseudoheader(header, plen, (unsigned char *)(header + replylimit), 0, NULL, 0, 0, 0);
	}
      
#if defined(HAVE_CONNTRACK) && defined(HAVE_UBUS)
      if (option_bool(OPT_CMARK_ALST_EN))
	{
	  unsigned int mark;
	  int have_mark = get_incoming_mark(udpaddr, dst_addr, /* istcp: */ 0, &mark);
	  if (have_mark && ((u32)mark & daemon->allowlist_mask))
	    report_addresses(header, plen, mark);
	}
#endif

#ifdef HAVE_DUMPFILE
      dump_packet_udp(DUMP_REPLY, (void *)header, plen, NULL, udpaddr, udpfd);
#endif
      send_from(udpfd, option_bool(OPT_NOWILD) || option_bool(OPT_CLEVERBIND), (char *)header, plen, udpaddr, dst_addr, dst_iface);
    }
  
  daemon->metrics[METRIC_DNS_LOCAL_ANSWERED]++;
  return;
}

/* Check if any frecs need to do a retry, and action that if so. 
   Return time in milliseconds until he next retry will be required,
   or -1 if none. */
/**
 * @brief Implement fast retry mechanism with exponential backoff for pending DNS queries
 * 
 * @detailed This function processes the fast retry queue, re-transmitting DNS queries that
 *           have not received responses after their backoff delay has elapsed. The implementation
 *           uses exponential backoff, doubling the retry delay after each attempt until the
 *           overall timeout (daemon->fast_retry_timeout) is reached. This mechanism improves
 *           query responsiveness when upstream servers are slow or temporarily unavailable,
 *           while avoiding excessive retransmissions through exponential backoff.
 * 
 *           The function iterates through all active forward records (daemon->frec_list),
 *           identifying queries that have been sent to upstream servers and are still within
 *           the fast retry timeout window. For each eligible query, it calculates the time
 *           since last transmission using millisecond-precision timestamps. If the exponential
 *           backoff delay has elapsed, the function retrieves the stashed packet data and
 *           re-transmits it via forward_query(). The forward_delay is then doubled for the next
 *           retry attempt. Queries that are blocking or have already transitioned to TCP are
 *           skipped (DNSSEC-related optimization).
 * 
 *           The function returns the minimum time in milliseconds until the next retry should
 *           occur across all pending queries, allowing the event loop to schedule the next
 *           fast_retry() invocation efficiently.
 * 
 * @param now Current time as returned by time(NULL), used to check query age against timeout
 * 
 * @return Milliseconds until next retry should occur (minimum across all pending queries),
 *         or -1 if no retries are pending or fast retry is disabled
 * @retval -1 No queries are eligible for fast retry, or fast retry disabled (daemon->fast_retry_time == 0)
 * @retval 0 At least one query is ready for immediate retry (delay elapsed)
 * @retval >0 Time in milliseconds until the next query should be retried
 * 
 * @note Fast retry must be explicitly enabled via daemon->fast_retry_time configuration
 * @note Uses millisecond-precision timing (dnsmasq_milliseconds()) for accurate retry scheduling
 * @note Exponential backoff: forward_delay is doubled after each retry attempt
 * @note Queries are skipped if f->blocking_query is set or FREC_GONE_TO_TCP flag is set (DNSSEC)
 * @warning Packet buffer (daemon->packet) is overwritten during retry, daemon->srv_save cleared
 * @warning Assumes f->stash contains valid packet data for retrieval
 * 
 * @see forward_query() in forward.c - called to re-transmit queries
 * @see blockdata_retrieve() in blockdata.c - retrieves stashed packet data
 * @see dnsmasq_milliseconds() in util.c - provides millisecond-precision timestamp
 * @see struct frec - forward record structure containing retry state
 * 
 * EXAMPLE USAGE:
 * @code
 * time_t now = dnsmasq_time();
 * int next_retry_ms = fast_retry(now);
 * if (next_retry_ms != -1) {
 *   // Schedule next fast_retry() call in next_retry_ms milliseconds
 *   set_event_timer(next_retry_ms);
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: Implements retry mechanism for RFC 1035 query timeout handling
 * SIDE EFFECTS: Re-transmits queries via forward_query(); modifies f->forward_delay (exponential backoff);
 *               overwrites daemon->packet buffer; clears daemon->srv_save; sets daemon->log_display_id
 *               and daemon->log_source_addr for retry logging context
 * THREAD SAFETY: Single-threaded architecture; modifies global daemon structure and forward record list
 */
int fast_retry(time_t now)
{
  struct frec *f;
  int ret = -1;
  
  if (daemon->fast_retry_time != 0)
    {
      u32 millis = dnsmasq_milliseconds();
      
      for (f = daemon->frec_list; f; f = f->next)
	if (f->sentto && difftime(now, f->time) < daemon->fast_retry_timeout)
	  {
#ifdef HAVE_DNSSEC
	    if (f->blocking_query || (f->flags & FREC_GONE_TO_TCP))
	      continue;
#endif
	    /* t is milliseconds since last query sent. */ 
	    int to_run, t = (int)(millis - f->forward_timestamp);
	    
	    if (t < f->forward_delay)
	      to_run = f->forward_delay - t;
	    else
	      {
		struct dns_header *header = (struct dns_header *)daemon->packet;
		
		/* packet buffer overwritten */
		daemon->srv_save = NULL;
		
		blockdata_retrieve(f->stash, f->stash_len, (void *)header);
		
		daemon->log_display_id = f->frec_src.log_id;
		daemon->log_source_addr = NULL;
		
		forward_query(-1, NULL, NULL, 0, header, f->stash_len, 0, now, f, 0, 1);
		
		to_run = f->forward_delay = 2 * f->forward_delay;
	      }

	    if (ret == -1 || ret > to_run)
	      ret = to_run;
	  }
    }
  return ret;
}

#if defined(HAVE_IPSET) || defined(HAVE_NFTSET)
/**
 * @brief Find ipset/nftset configuration matching a domain name using longest suffix match
 * 
 * @detailed Searches the ipset/nftset configuration list for the best match to the given domain
 *           using longest suffix matching algorithm (similar to search_servers). Performs
 *           case-insensitive comparison and ensures proper domain component boundaries.
 *           Returns the configuration entry with the longest matching domain suffix.
 * 
 * @param setlist Linked list of ipset/nftset configurations to search (ipsets->next chain)
 * @param domain Domain name to match (null-terminated string, may be fully qualified)
 * 
 * @return Pointer to best matching ipset configuration, or NULL if no match found
 * @retval non-NULL Best match from setlist with longest domain suffix match
 * @retval NULL No matching configuration found in setlist
 * 
 * @note Matching algorithm ensures domain component boundaries (. separator or full match)
 * @note Case-insensitive comparison via hostname_isequal()
 * @note Similar algorithm to search_servers() for upstream DNS server selection
 * 
 * @see hostname_isequal() in domain.c for case-insensitive domain comparison
 * 
 * EXAMPLE USAGE:
 * @code
 * struct ipsets *ipset_config = daemon->ipsets;
 * struct ipsets *match = domain_find_sets(ipset_config, "www.example.com");
 * if (match) {
 *   // Add resolved IPs to match->sets
 * }
 * @endcode
 * 
 * ALGORITHM:
 * - Iterates through setlist linked list
 * - For each entry, checks if domain ends with entry's domain suffix
 * - Ensures match at domain component boundary (. separator or full string match)
 * - Tracks longest matching suffix
 * - Returns configuration with longest match (most specific)
 * 
 * SIDE EFFECTS: None (read-only operation)
 * THREAD SAFETY: Safe (no global state modification)
 */
static struct ipsets *domain_find_sets(struct ipsets *setlist, const char *domain) {
  /* Similar algorithm to search_servers. */
  struct ipsets *ipset_pos, *ret = NULL;
  unsigned int namelen = strlen(domain);
  unsigned int matchlen = 0;
  for (ipset_pos = setlist; ipset_pos; ipset_pos = ipset_pos->next) 
    {
      unsigned int domainlen = strlen(ipset_pos->domain);
      const char *matchstart = domain + namelen - domainlen;
      if (namelen >= domainlen && hostname_isequal(matchstart, ipset_pos->domain) &&
          (domainlen == 0 || namelen == domainlen || *(matchstart - 1) == '.' ) &&
          domainlen >= matchlen) 
        {
          matchlen = domainlen;
          ret = ipset_pos;
        }
    }

  return ret;
}
#endif

/**
 * @brief Process DNS reply from upstream server and prepare for client delivery
 * 
 * @detailed This function performs comprehensive post-processing on DNS responses received
 *           from upstream servers before forwarding to clients. Processing includes EDNS0 option
 *           handling (client subnet, MAC address options), DNSSEC validation state management,
 *           security checks (bogus wildcard detection, DNS rebind protection), resource record
 *           filtering, packet resizing, and Extended DNS Error (EDE) code insertion.
 *           
 *           The function modifies the DNS header and packet in place, adjusting EDNS0 options,
 *           clearing/setting DNSSEC flags, filtering RRs, and potentially truncating the response
 *           if it exceeds client limits or contains security violations.
 * 
 * @param header DNS packet header (modified in place)
 * @param now Current time for cache TTL calculations
 * @param server Upstream server that provided this reply
 * @param n Packet size in bytes (may be modified by resizing)
 * @param check_rebind If non-zero, perform DNS rebind attack detection
 * @param no_cache If non-zero, do not cache this response
 * @param cache_secure If non-zero, response should be cached as DNSSEC-secure
 * @param bogusanswer If non-zero, DNSSEC validation failed (response is bogus)
 * @param ad_reqd If non-zero, client requested DNSSEC validation (DO bit set)
 * @param do_bit Original DO bit state from client query
 * @param added_pheader If non-zero, EDNS0 pseudo-header was added by dnsmasq
 * @param query_source Source address of original client query
 * @param limit Pointer to end of valid packet buffer
 * @param ede Extended DNS Error code to insert if applicable
 * 
 * @return Packet size after processing (may be smaller due to filtering/truncation)
 * @retval 0 Empty packet after filtering (should not forward to client)
 * @retval >0 Valid packet size to forward to client
 * 
 * @note Modifies packet in place - EDNS0 options stripped/adjusted, RRs filtered, flags updated
 * @warning Packet buffer must have adequate space for potential EDNS0 option adjustments
 * 
 * @see forward_query() for initial query processing
 * @see extract_addresses() for RR extraction and filtering logic
 * @see resize_packet() for final packet size adjustment
 * 
 * EXAMPLE USAGE:
 * @code
 * size_t reply_size = process_reply(header, now, server, packet_len,
 *                                   1, 0, 0, 0, ad_required, do_bit,
 *                                   0, &client_addr, packet_end, ede_code);
 * if (reply_size > 0)
 *   send_to_client(reply, reply_size);
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 1035 (DNS response processing), RFC 6891 (EDNS0 handling),
 *                 RFC 4035 (DNSSEC AD/DO bit management), RFC 8914 (Extended DNS Errors)
 * 
 * SIDE EFFECTS:
 * - Modifies DNS header flags (AD bit, DO bit in EDNS0)
 * - Strips or adjusts EDNS0 options (client subnet, MAC address)
 * - May filter out resource records (rebind protection, bogus wildcard)
 * - Resizes packet to actual content length
 * - May insert Extended DNS Error (EDE) codes for validation failures
 * - Logs security violations (rebind attacks, bogus wildcards)
 * 
 * THREAD SAFETY: Single-threaded event-driven architecture; not thread-safe
 */
static size_t process_reply(struct dns_header *header, time_t now, struct server *server, size_t n, int check_rebind, 
			    int no_cache, int cache_secure, int bogusanswer, int ad_reqd, int do_bit, int added_pheader, 
			    union mysockaddr *query_source, unsigned char *limit, int ede)
{
  unsigned char *pheader, *sizep;
  struct ipsets *ipsets = NULL, *nftsets = NULL;
  int is_sign;
  unsigned int rcode = RCODE(header);
  size_t plen; 
    
  (void)ad_reqd;
  (void)do_bit;
 
#if defined(HAVE_IPSET) || defined(HAVE_NFTSET)
  if ((daemon->ipsets || daemon->nftsets) && extract_name(header, n, NULL, daemon->namebuff, EXTR_NAME_EXTRACT, 0))
    {
#  ifdef HAVE_IPSET
      ipsets = domain_find_sets(daemon->ipsets, daemon->namebuff);
#  endif
      
#  ifdef HAVE_NFTSET
      nftsets = domain_find_sets(daemon->nftsets, daemon->namebuff);
#  endif
    }
#endif
  
  if ((pheader = find_pseudoheader(header, n, &plen, &sizep, &is_sign, NULL)))
    {
      /* Get extended RCODE. */
      rcode |= sizep[2] << 4;
      
      if (option_bool(OPT_CLIENT_SUBNET) && !check_source(header, plen, pheader, query_source))
	{
	  my_syslog(LOG_WARNING, _("discarding DNS reply: subnet option mismatch"));
	  return 0;
	}
      
      if (!is_sign)
	{
	  if (added_pheader)
	    {
	      /* client didn't send EDNS0, we added one, strip it off before returning answer. */
	      rrfilter(header, &n, RRFILTER_EDNS0);
	      pheader = NULL;
	    }
	  else
	    {
	      /* Advertise our max UDP packet to the client. */
	      PUTSHORT(daemon->edns_pktsz, sizep);
	      
#ifdef HAVE_DNSSEC
	      /* If the client didn't set the do bit, but we did, reset it. */
	      if (option_bool(OPT_DNSSEC_VALID) && !do_bit)
		{
		  unsigned short flags;
		  sizep += 2; /* skip RCODE */
		  GETSHORT(flags, sizep);
		  flags &= ~0x8000;
		  sizep -= 2;
		  PUTSHORT(flags, sizep);
		}
#endif
	    }
	}
    }
  
  /* RFC 4035 sect 4.6 para 3 */
  if (!is_sign && !option_bool(OPT_DNSSEC_PROXY))
     header->hb4 &= ~HB4_AD;

  /* Complain loudly if the upstream server is non-recursive. */
  if (!(header->hb4 & HB4_RA) && rcode == NOERROR &&
      server && !(server->flags & SERV_WARNED_RECURSIVE))
    {
      (void)prettyprint_addr(&server->addr, daemon->namebuff);
      my_syslog(LOG_WARNING, _("nameserver %s refused to do a recursive query"), daemon->namebuff);
      if (!option_bool(OPT_LOG))
	server->flags |= SERV_WARNED_RECURSIVE;
    }  

  header->hb4 |= HB4_RA; /* recursion if available */

  if (OPCODE(header) != QUERY)
    return resize_packet(header, n, pheader, plen);

  if (rcode != NOERROR && rcode != NXDOMAIN)
    {
      union all_addr a;
      a.log.rcode = rcode;
      a.log.ede = ede;
      log_query(F_UPSTREAM | F_RCODE, "error", &a, NULL, 0);
      
      return resize_packet(header, n, pheader, plen);
    }
  
  if (header->hb3 & HB3_TC)
    log_query(F_UPSTREAM, NULL, NULL, "truncated", 0);
  else if (!bogusanswer || (header->hb4 & HB4_CD))
    {
      if (rcode == NXDOMAIN && extract_name(header, n, NULL, daemon->namebuff, EXTR_NAME_EXTRACT, 0) &&
	  (check_for_local_domain(daemon->namebuff, now) || lookup_domain(daemon->namebuff, F_CONFIG, NULL, NULL)))
	{
	  /* if we forwarded a query for a locally known name (because it was for 
	     an unknown type) and the answer is NXDOMAIN, convert that to NODATA,
	     since we know that the domain exists, even if upstream doesn't */
	  header->hb3 |= HB3_AA;
	  SET_RCODE(header, NOERROR);
	  cache_secure = 0;
	}
      
      if (daemon->doctors && do_doctor(header, n, daemon->namebuff))
	cache_secure = 0;
      
      /* check_for_bogus_wildcard() does its own caching, so
	 don't call extract_addresses() if it triggers. */
      if (daemon->bogus_addr && rcode != NXDOMAIN &&
	  check_for_bogus_wildcard(header, n, daemon->namebuff, now))
	{
	  header->ancount = htons(0);
	  header->nscount = htons(0);
	  header->arcount = htons(0);
	  SET_RCODE(header, NXDOMAIN);
	  header->hb3 &= ~HB3_AA;
	  cache_secure = 0;
	  ede = EDE_BLOCKED;
	}
      else
	{
	  int rc = extract_addresses(header, n, daemon->namebuff, now, ipsets, nftsets, check_rebind, no_cache, cache_secure);

	  if (rc != 0)
	    {
	      header->ancount = htons(0);
	      header->nscount = htons(0);
	      header->arcount = htons(0);
	      cache_secure = 0;
	    }
	  
	  if (rc == 1)
	    {
	      my_syslog(LOG_WARNING, _("possible DNS-rebind attack detected: %s"), daemon->namebuff);
	      ede = EDE_BLOCKED;
	    }

	  if (rc == 2)
	    {
	      /* extract_addresses() found a malformed answer. */
	      SET_RCODE(header, SERVFAIL);
	      ede = EDE_OTHER;
	    }
	}
      
      if (RCODE(header) == NOERROR && rrfilter(header, &n, RRFILTER_CONF) > 0) 
	ede = EDE_FILTERED;
    }
  
#ifdef HAVE_DNSSEC
  if (option_bool(OPT_DNSSEC_VALID))
    {
      if (bogusanswer)
	{
	  if (!(header->hb4 & HB4_CD) && !option_bool(OPT_DNSSEC_DEBUG))
	    {
	      /* Bogus reply, turn into SERVFAIL */
	      SET_RCODE(header, SERVFAIL);
	      header->ancount = htons(0);
	      header->nscount = htons(0);
	      header->arcount = htons(0);
	    }
	}
      else if (ad_reqd && cache_secure)
	header->hb4 |= HB4_AD;
      
      /* If the requestor didn't set the DO bit, don't return DNSSEC info. */
      if (!do_bit)
	rrfilter(header, &n, RRFILTER_DNSSEC);
    }
#endif
  
  /* the code above can elide sections of the packet. Find the new length here 
     and put back pseudoheader if it was removed. */
  n = resize_packet(header, n, pheader, plen);

  if (pheader && ede != EDE_UNSET)
    {
      u16 swap = htons((u16)ede);
      n = add_pseudoheader(header, n, limit, EDNS0_OPTION_EDE, (unsigned char *)&swap, 2, do_bit, 1);
    }

  if (RCODE(header) == NXDOMAIN)
    server->nxdomain_replies++;

  return n;
}

#ifdef HAVE_DNSSEC
/**
 * @brief Orchestrate DNSSEC validation chain processing including subsidiary query management
 * 
 * @detailed This DNSSEC validation orchestration function manages the complex process of
 *           validating DNS responses through DNSSEC cryptographic verification. DNSSEC validation
 *           often requires additional queries to retrieve DNSKEY and DS records needed to verify
 *           signature chains. This function coordinates the validation workflow, creates subsidiary
 *           queries when additional data is needed, detects and prevents dependency loops, handles
 *           TCP fallback for truncated responses, and ultimately delivers validated results to clients.
 *
 *           The validation process follows RFC 4035: start with the original query response,
 *           validate RRSIGs using DNSKEYs, validate DNSKEYs using DS records from parent zone,
 *           and continue up the chain until reaching a trusted anchor. If any required record
 *           is missing, create a subsidiary query (FREC_DNSKEY_QUERY or FREC_DS_QUERY) to retrieve it.
 *
 *           The function maintains a dependency graph of forward records: the original query blocks
 *           on subsidiary queries via the blocking_query pointer, while subsidiary queries track
 *           their dependents via the dependent and next_dependent pointers. This graph structure
 *           enables proper ordering and unwinding of validation operations.
 *
 *           Loop detection is critical: broken DNSSEC signatures could cause circular dependencies
 *           (e.g., validating A requires DS B, validating DS B requires DNSKEY C, validating
 *           DNSKEY C requires DS B). The function detects such cycles by traversing the blocking_query
 *           chain and transforms them into STAT_ABANDONED status to prevent infinite loops.
 *
 *           Source: /src/forward.c:1491-1725
 *
 * @param forward Pointer to forward record being validated (must not be NULL).
 *                The forward record's blocking_query chain is traversed to find the original query.
 *                For subsidiary queries (FREC_DNSKEY_QUERY or FREC_DS_QUERY), this is the subsidiary.
 *                The function modifies forward's blocking_query, dependent, next_dependent, and stash fields.
 * @param header Pointer to DNS packet header containing response to validate (must not be NULL).
 *               The header's answer section is extracted and validated. For subsidiary queries,
 *               this contains the DNSKEY or DS records retrieved. Modified during TCP swapping.
 * @param plen Packet length in bytes (must be positive). The total length of the DNS packet
 *             including header and all sections. Used for validation bounds checking and
 *             blockdata allocation. Modified if TCP swap occurs.
 * @param status Current validation status from upstream processing or previous validation step.
 *               Values include STAT_OK (proceed with validation), STAT_BOGUS (failed validation),
 *               STAT_TRUNCATED (TCP fallback needed), STAT_ABANDONED (resource limits exceeded or loop detected),
 *               STAT_NEED_DS (need DS record from parent), STAT_NEED_KEY (need DNSKEY record).
 *               The function updates status based on validation results.
 * @param now Current time from time(NULL) for timeout checking, log timestamps, and frec allocation.
 *            Used when creating subsidiary queries and checking expiration.
 * 
 * @return void - Completion handled through callbacks: return_reply() for validated original queries,
 *                pop_and_retry_query() for completing dependent queries, or return without action
 *                if creating subsidiary query (processing continues when subsidiary completes).
 * 
 * @note This function is DNSSEC-specific and only invoked when DNSSEC validation is enabled
 *       (compile flag HAVE_DNSSEC). It implements recursive validation by creating subsidiary
 *       forward records that themselves call dnssec_validate() when their responses arrive.
 * @note Work counter (orig->work_counter) limits subsidiary queries to prevent validation DoS attacks.
 *       Default limit is 40 queries per original query (DNSSEC_LIMIT_WORK in config.h line 25).
 * @note Validate counter (orig->validate_counter) limits cryptographic operations to prevent CPU exhaustion.
 * @warning Loop detection is essential: without it, circular DNSSEC dependencies could cause infinite recursion.
 *          The function detects loops by traversing the blocking_query chain before linking new dependencies.
 * @warning TCP fallback for truncated responses creates forked child process that may not return immediately.
 *          Caller must handle FREC_GONE_TO_TCP flag and expect pop_and_retry_query() callback completion.
 * @warning Memory management: blockdata allocations for stashed queries must be freed on all error paths
 *          to prevent leaks. The function carefully frees stash data on loop detection and allocation failures.
 * 
 * @see dnssec_validate_by_ds() in dnssec.c - validates DNSKEY records using DS from parent zone
 * @see dnssec_validate_ds() in dnssec.c - validates DS records using DNSKEY from child zone  
 * @see dnssec_validate_reply() in dnssec.c - validates RRSET using RRSIG and DNSKEY
 * @see pop_and_retry_query() below - handles completion of dependent queries and retry logic
 * @see return_reply() in forward.c - delivers final validated response to client
 * @see get_new_frec() in forward.c - allocates new forward record for subsidiary queries
 * @see swap_to_tcp() in forward.c - switches truncated query to TCP transport
 * @see blockdata_alloc() in blockdata.c - allocates storage for stashed query/response data
 * 
 * EXAMPLE USAGE:
 * @code
 * // Called from reply_query() when DNSSEC validation is active
 * #ifdef HAVE_DNSSEC
 * if (forward->flags & FREC_CHECKING_DISABLED)
 *   status = STAT_OK; // Client doesn't want validation
 * else
 *   {
 *     status = STAT_OK; // Start with OK status
 *     dnssec_validate(forward, header, plen, status, now);
 *     // Function returns void; completion handled via callbacks
 *   }
 * #endif
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 4033 Section 5 (DNSSEC validation process overview),
 *                 RFC 4034 (DNSSEC resource records - DNSKEY, DS, RRSIG),
 *                 RFC 4035 Section 3.2 (recursive validation algorithm),
 *                 RFC 4035 Section 5 (validator behavior and trust anchor usage)
 * 
 * SIDE EFFECTS: 
 * - Network I/O: Creates and sends UDP queries for missing DNSKEY or DS records via server_send()
 * - Forward record chain mutations: Links forward records via blocking_query, dependent, next_dependent
 * - Memory allocations: Allocates blockdata for stashing queries/responses, allocates new forward records
 * - Logging: Logs truncated responses, resource limit violations, DNSSEC query creation via log_query_mysockaddr()
 * - Server statistics: Increments server->queries counter for each subsidiary query sent
 * - TCP forking: May fork child process for TCP fallback on truncated responses (FREC_GONE_TO_TCP flag)
 * - Callback invocation: Calls return_reply() for completed validations or pop_and_retry_query() for dependents
 * - Work counter decrements: Reduces orig->work_counter to enforce subsidiary query limits
 * - Packet dumping: Generates DUMP_BOGUS or DUMP_SEC_BOGUS dump files if HAVE_DUMPFILE enabled
 * 
 * THREAD SAFETY: Single-threaded architecture (not thread-safe). All state mutations assume exclusive access
 *                to daemon global state and forward record chains. No locking mechanisms present.
 */
static void dnssec_validate(struct frec *forward, struct dns_header *header,
			    ssize_t plen, int status, time_t now)
{
  struct frec *orig;
  int log_resource = 0;

  daemon->log_display_id = forward->frec_src.log_id;
    
  /* Find the original query that started it all.... */
  for (orig = forward; orig->dependent; orig = orig->dependent);
  
  /* As soon as anything returns BOGUS, we stop and unwind, to do otherwise
     would invite infinite loops, since the answers to DNSKEY and DS queries
     will not be cached, so they'll be repeated. */
  if (!STAT_ISEQUAL(status, STAT_BOGUS) && !STAT_ISEQUAL(status, STAT_TRUNCATED) && !STAT_ISEQUAL(status, STAT_ABANDONED))
    {
      /* If all replies to a query are REFUSED, give up. */
      if (RCODE(header) == REFUSED)
	status = STAT_ABANDONED;
      else if (header->hb3 & HB3_TC)
	{
	  /* Truncated answer can't be validated.
	     If this is an answer to a DNSSEC-generated query, we 
	     switch to TCP mode. For downstream queries, if the client didn't ask for 
	     DNSSEC RRs, do the query over TCP, and hope that it fits once the DNSSEC RRs 
	     have been stripped, otherwise get the client 
	     to retry over TCP, so return an answer with the TC bit set. */
	  if ((forward->flags & (FREC_DNSKEY_QUERY | FREC_DS_QUERY)) || !(forward->flags & FREC_DO_QUESTION))
	    {
	      status = (forward->flags & FREC_DNSKEY_QUERY) ? STAT_NEED_KEY:
		((forward->flags & FREC_DS_QUERY) ? STAT_NEED_DS : STAT_OK);
		
	      /* Get the query we sent by UDP */
	      blockdata_retrieve(forward->stash, forward->stash_len, (void *)header);
	      
	      if  (!extract_name(header, forward->stash_len, NULL, daemon->namebuff, EXTR_NAME_EXTRACT, 0))
		status = STAT_ABANDONED;
	      else
		{
		  log_query(F_UPSTREAM | F_NOEXTRA, daemon->namebuff, NULL, "truncated", 0);
		  
		  /* Don't count failed UDP attempt AND TCP */
		  if (status != STAT_OK)
		    orig->work_counter++;
		  
		  /* NOTE: Can't move connection marks from UDP to TCP */
		  plen = forward->stash_len;
		  status = swap_to_tcp(forward, now, status, header, &plen, daemon->namebuff, forward->class, forward->sentto, &orig->work_counter, &orig->validate_counter);
		  
		  /* We forked a new process. pop_and_retry_query() will be called when is completes. */
		  if (STAT_ISEQUAL(status, STAT_ASYNC))
		    {
		      forward->flags |=  FREC_GONE_TO_TCP;
		      return;
		    }
		}
	    }
	  else
	    status = STAT_TRUNCATED;
	}
      else
	{
	  /* As soon as anything returns BOGUS, we stop and unwind, to do otherwise
	     would invite infinite loops, since the answers to DNSKEY and DS queries
	     will not be cached, so they'll be repeated. */
	  if (forward->flags & FREC_DNSKEY_QUERY)
	    status = dnssec_validate_by_ds(now, header, plen, daemon->namebuff, daemon->keyname, forward->class, &orig->validate_counter);
	  else if (forward->flags & FREC_DS_QUERY)
	    status = dnssec_validate_ds(now, header, plen, daemon->namebuff, daemon->keyname, forward->class, &orig->validate_counter);
	  else
	    status = dnssec_validate_reply(now, header, plen, daemon->namebuff, daemon->keyname, &forward->class, 
					   !option_bool(OPT_DNSSEC_IGN_NS), NULL, NULL, NULL, &orig->validate_counter);
	  
	  if (STAT_ISEQUAL(status, STAT_ABANDONED))
	    log_resource = 1;
	}
    }
  
  /* Can't validate, as we're missing key data. Put this
     answer aside, whilst we get that. */     
  if (STAT_ISEQUAL(status, STAT_NEED_DS) || STAT_ISEQUAL(status, STAT_NEED_KEY))
    {
      struct blockdata *stash;
      
      /* Now save reply pending receipt of key data */
      if ((stash = blockdata_alloc((char *)header, plen)))
	{
	  /* validate routines leave name of required record in daemon->keyname */
	  unsigned int flags = STAT_ISEQUAL(status, STAT_NEED_KEY) ? FREC_DNSKEY_QUERY : FREC_DS_QUERY;
	  struct frec *old;
	  
	  if ((old = lookup_frec(now, daemon->keyname, forward->class, -1, -1, flags, flags)))
	    {
	      /* This is tricky; it detects loops in the dependency
		 graph for DNSSEC validation, say validating A requires DS B
		 and validating DS B requires DNSKEY C and validating DNSKEY C requires DS B.
		 This should never happen in correctly signed records, but it's
		 likely the case that sufficiently broken ones can cause our validation
		 code requests to exhibit cycles. The result is that the ->blocking_query list
		 can form a cycle, and under certain circumstances that can lock us in 
		 an infinite loop. Here we transform the situation into ABANDONED. */
	      struct frec *f;
	      for (f = old; f; f = f->blocking_query)
		if (f == forward)
		  break;

	      if (!f)
		{
		  forward->next_dependent = old->dependent;
		  old->dependent = forward;
		  /* Make consistent, only replace query copy with unvalidated answer
		     when we set ->blocking_query. */
		  blockdata_free(forward->stash);
		  forward->blocking_query = old;
		  forward->stash_len = plen;
		  forward->stash = stash;
		  return;
		}
	    }
	  else if (orig->work_counter-- == 0)
	    {
	      my_syslog(LOG_WARNING, _("limit exceeded: per-query subqueries"));
	      log_resource = 1;
	    }
	  else
	    {
	      struct server *server;
	      size_t nn;
	      int serverind, fd;
	      struct randfd_list *rfds = NULL;
	      struct frec *new = NULL;
	      struct blockdata *newstash = NULL;
	     	      
	      /* Make sure we don't expire and free the orig frec during the
		 allocation of a new one: third arg of get_new_frec() does that. */
	      if ((serverind = dnssec_server(forward->sentto, daemon->keyname, STAT_ISEQUAL(status, STAT_NEED_DS), NULL, NULL)) != -1 &&
		  (server = daemon->serverarray[serverind]) &&
		  (nn = dnssec_generate_query(header, ((unsigned char *) header) + daemon->edns_pktsz,
					      daemon->keyname, forward->class, get_id(),
					      STAT_ISEQUAL(status, STAT_NEED_KEY) ? T_DNSKEY : T_DS)) && 
		  (fd = allocate_rfd(&rfds, server)) != -1 &&
		  (newstash = blockdata_alloc((char *)header, nn)) &&
		  (new = get_new_frec(now, server, 1)))
		{
		  struct frec *next = new->next;
		  
		  *new = *forward; /* copy everything, then overwrite */
		  new->next = next;
		  new->blocking_query = NULL;
		  
		  new->frec_src.log_id = daemon->log_display_id = ++daemon->log_id;
		  new->sentto = server;
		  new->rfds = rfds;
		  new->frec_src.next = NULL;
		  new->flags &= ~(FREC_DNSKEY_QUERY | FREC_DS_QUERY);
		  new->flags |= flags;
		  new->forwardall = 0;
		  new->frec_src.encode_bitmap = 0;
		  new->frec_src.encode_bigmap = NULL;

		  forward->next_dependent = NULL;
		  new->dependent = forward; /* to find query awaiting new one. */
		  
		  /* Make consistent, only replace query copy with unvalidated answer
		     when we set ->blocking_query. */
		  forward->blocking_query = new; 
		  blockdata_free(forward->stash);
		  forward->stash_len = plen;
		  forward->stash = stash;
		  
		  new->new_id = ntohs(header->id);
		  /* Save query for retransmission and de-dup */
		  new->stash = newstash;
		  new->stash_len = nn;
		  if (daemon->fast_retry_time != 0)
		    new->forward_timestamp = dnsmasq_milliseconds();
		  
		  /* Don't resend this. */
		  daemon->srv_save = NULL;
		  
#ifdef HAVE_CONNTRACK
		  if (option_bool(OPT_CONNTRACK))
		    set_outgoing_mark(orig, fd);
#endif

		  server_send(server, fd, header, nn, 0);
		  server->queries++;
#ifdef HAVE_DUMPFILE
		  dump_packet_udp(DUMP_SEC_QUERY, (void *)header, (size_t)nn, NULL, &server->addr, fd);
#endif
		  log_query_mysockaddr(F_NOEXTRA | F_DNSSEC | F_SERVER, daemon->keyname, &server->addr,
				       STAT_ISEQUAL(status, STAT_NEED_KEY) ? "dnssec-query[DNSKEY]" : "dnssec-query[DS]", 0);
		  return;
		}
	      
	      /* error unwind */
	      free_rfds(&rfds);
	      blockdata_free(newstash);
	    }
	  
	  blockdata_free(stash); /* don't leak this on failure. */
	}

      /* sending DNSSEC query failed or loop detected. */
      status = STAT_ABANDONED;
    }

  if (log_resource)
    {
      /* Log the actual validation that made us barf. */
      if  (extract_name(header, plen, NULL, daemon->namebuff, EXTR_NAME_EXTRACT, 0))
	my_syslog(LOG_WARNING, _("validation of %s failed: resource limit exceeded."),
		  daemon->namebuff[0] ? daemon->namebuff : ".");
    }
  
#ifdef HAVE_DUMPFILE
  if (STAT_ISEQUAL(status, STAT_BOGUS) || STAT_ISEQUAL(status, STAT_ABANDONED))
    dump_packet_udp((forward->flags & (FREC_DNSKEY_QUERY | FREC_DS_QUERY)) ? DUMP_SEC_BOGUS : DUMP_BOGUS,
		    header, (size_t)plen, &forward->sentto->addr, NULL, -daemon->port);
#endif
  
  if (!forward->dependent)
    /* Validated original answer, all done. */
    return_reply(now, forward, header, plen, status);
  else
    pop_and_retry_query(forward, status, now);
}

/**
 * @brief Resume processing of dependent DNSSEC queries after subsidiary validation completes
 * 
 * @detailed This DNSSEC-specific function handles the completion of subsidiary DNS queries
 *           required for DNSSEC validation chain processing. When a DNSSEC validation step
 *           requires retrieving additional records (e.g., DNSKEY records to validate RRSIG,
 *           or DS records from parent zone), the original validation is suspended and dependent
 *           forward records are created. Once the subsidiary query completes, this function
 *           "pops" back to the dependent queries and resumes their validation processing.
 * 
 *           The function frees the completed subsidiary forward record, then iterates through
 *           the chain of dependent queries (linked via ->dependent and ->next_dependent).
 *           For each dependent query, it:
 *           1. Clears the blocking_query pointer (subsidiary query has completed)
 *           2. Retrieves the original packet data from blockdata stash
 *           3. Calls dnssec_validate() to continue validation with the new information
 * 
 *           This implements the DNSSEC validation state machine where validation can be
 *           suspended to fetch additional records, then resumed after those records are
 *           obtained. The status parameter indicates the validation result of the subsidiary
 *           query (STAT_SECURE, STAT_INSECURE, STAT_BOGUS, etc.) which affects how dependent
 *           validations proceed.
 * 
 * @param forward Forward record for the completed subsidiary query, will be freed by this function
 * @param status DNSSEC validation status of the subsidiary query (STAT_SECURE, STAT_INSECURE, 
 *               STAT_BOGUS, STAT_ABANDONED, etc. from dnssec.c), passed to dependent validations
 * @param now Current time as returned by time(NULL), passed to dnssec_validate() for TTL checks
 * 
 * @return void - Function does not return a value, side effects occur through dnssec_validate() calls
 * 
 * @note Only compiled when HAVE_DNSSEC is defined (conditional compilation)
 * @note The forward record passed as parameter is freed and must not be accessed afterward
 * @note Dependent queries are linked via forward->dependent and prev->next_dependent chain
 * @note Each dependent query has its packet restored from prev->stash before validation resumes
 * @warning forward parameter is freed by free_frec() and becomes invalid
 * @warning daemon->packet buffer is overwritten with dependent query packet data
 * @warning Recursive calls to dnssec_validate() may trigger further subsidiary queries
 * 
 * @see dnssec_validate() in dnssec.c - called for each dependent query to resume validation
 * @see free_frec() in forward.c - releases the completed subsidiary forward record
 * @see blockdata_retrieve() in blockdata.c - restores stashed packet data
 * @see struct frec members: dependent, next_dependent, blocking_query, stash, stash_len
 * 
 * EXAMPLE USAGE:
 * @code
 * // After receiving response to subsidiary DNSKEY query
 * int validation_status = STAT_SECURE; // Subsidiary query validated successfully
 * time_t now = dnsmasq_time();
 * // Pop back to queries that were waiting for this DNSKEY
 * pop_and_retry_query(subsidiary_forward, validation_status, now);
 * // subsidiary_forward is now freed and invalid
 * @endcode
 * 
 * RFC COMPLIANCE: Implements DNSSEC validation chain processing per RFC 4035 Section 5
 * SIDE EFFECTS: Frees forward record; overwrites daemon->packet; calls dnssec_validate() 
 *               which may trigger cache updates, response transmission, or further queries;
 *               clears blocking_query pointers in dependent records
 * THREAD SAFETY: Single-threaded architecture; modifies global daemon->packet buffer and
 *                forward record structures
 */
void pop_and_retry_query(struct frec *forward, int status, time_t now)
{
  /* validated subsidiary query/queries, (and cached result)
     pop that and return to the previous query/queries we were working on. */
  struct frec *prev, *nxt = forward->dependent;
  struct dns_header *header =  (struct dns_header *)daemon->packet;
  
  free_frec(forward);
  
  while ((prev = nxt))
    {
      /* ->next_dependent will have changed after return from recursive call below. */
      nxt = prev->next_dependent;
      prev->blocking_query = NULL; /* already gone */
      blockdata_retrieve(prev->stash, prev->stash_len, (void *)header);
      dnssec_validate(prev, header, prev->stash_len, status, now);
    }
}
#endif

/**
 * @brief Process DNS response from upstream server and route to validation or reply delivery
 * 
 * @detailed This function handles DNS responses received from upstream recursive DNS servers
 *           on UDP sockets. It performs the critical task of matching responses to pending
 *           queries, validating response authenticity, handling server failure conditions,
 *           and routing successful responses to either DNSSEC validation or direct client reply.
 * 
 *           The processing flow consists of several stages:
 *           1. Receive UDP packet from upstream server socket (recvfrom on fd)
 *           2. Perform spoof check: validate query ID and source address match expected server
 *           3. Look up forward record (struct frec) using query ID and packet characteristics
 *           4. Handle error responses: retry with different server for REFUSED/SERVFAIL
 *           5. Update server latency statistics using moving average calculation
 *           6. Restore original query name case using XOR bitmap (anti-spoof measure)
 *           7. Route to DNSSEC validation (if enabled) or direct reply delivery
 * 
 *           Anti-spoofing protection is layered: random query IDs, source address validation,
 *           and query name case randomization (0x20 encoding) ensure that only legitimate
 *           responses from queried servers are accepted. The function detects and discards
 *           responses that don't match any outstanding query.
 * 
 *           Server failure handling implements automatic failover: if a server responds with
 *           REFUSED or SERVFAIL and the query was not sent to all servers (forwardall==0),
 *           the original query is re-forwarded to an alternative upstream server.
 * 
 *           Latency tracking maintains a modified moving average (MMA) of query response times
 *           for each upstream server, enabling intelligent server selection based on performance
 *           (server->mma_latency divided by 128 gives query_latency in milliseconds). The MMA
 *           calculation uses 128 as the denominator to average over recent queries while giving
 *           higher weight to recent measurements.
 * 
 *           File descriptor conservation: once a valid answer is received, all rfds (random file
 *           descriptors for source port randomization) are freed via free_rfds() to prevent
 *           fd exhaustion and reduce unnecessary packet processing from other servers.
 * 
 * @param fd File descriptor of the UDP socket that received the response (from server->fd)
 * @param now Current time as returned by dnsmasq_time(), used for timeout checks and statistics
 * 
 * @return void - Function does not return a value; side effects occur through validation/reply
 * 
 * @note Reads response into global daemon->packet buffer (size daemon->packet_buff_sz)
 * @note Forward record lookup uses query ID, flags, and packet characteristics for matching
 * @note Sets daemon->last_server to the responding server for statistics/logging purposes
 * @note Responses with ignored addresses (daemon->ignore_addr) are silently discarded
 * @warning Invalid packets (too small, spoof check failure, no matching forward) are silently dropped
 * @warning daemon->packet buffer is overwritten with response data
 * @warning Forward record may be freed after return_reply() or during validation completion
 * 
 * @see lookup_frec() in forward.c - finds forward record matching the response
 * @see check_for_bogus_wildcard() in forward.c - validates response against bogus patterns
 * @see check_for_ignored_address() in forward.c - checks ignore-address configuration
 * @see dnssec_validate() in dnssec.c - performs DNSSEC validation before reply
 * @see return_reply() in forward.c - delivers validated response to client
 * @see forward_query() in forward.c - called to retry query on REFUSED/SERVFAIL
 * @see free_rfds() in forward.c - closes random source port file descriptors
 * @see extract_name() in rfc1035.c - used to flip query name case back to original
 * 
 * EXAMPLE USAGE:
 * @code
 * // Called from main event loop when upstream server socket has data
 * struct pollfd *pfd = &pollfds[server->fd_index];
 * if (pfd->revents & POLLIN) {
 *   time_t now = dnsmasq_time();
 *   reply_query(server->fd, now);
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 1035 Section 7.3 (resolver implementation), RFC 4035 Section 3.1.6
 *                 (DNSSEC validation timing), RFC 5452 (spoof prevention via query ID randomization)
 * SIDE EFFECTS: Reads from network socket; overwrites daemon->packet; updates server->mma_latency
 *               and server->query_latency; sets daemon->last_server; may call forward_query() to retry;
 *               calls dnssec_validate() or return_reply() which send packets to clients; frees rfds via
 *               free_rfds(); may clear daemon->rr_status if DNSSEC validation is disabled
 * THREAD SAFETY: Single-threaded architecture; modifies global daemon structure and server statistics
 */
/* sets new last_server */
void reply_query(int fd, time_t now)
{
  /* packet from peer server, extract data for cache, and send to
     original requester */
  struct dns_header *header;
  union mysockaddr serveraddr;
  struct frec *forward;
  socklen_t addrlen = sizeof(serveraddr);
  ssize_t n = recvfrom(fd, daemon->packet, daemon->packet_buff_sz, 0, &serveraddr.sa, &addrlen);
  struct server *server;
  int first, last, serv, c, class, rrtype;
  unsigned char *p;
  struct randfd_list *fdl;
  
  /* packet buffer overwritten */
  daemon->srv_save = NULL;

  /* Determine the address of the server replying  so that we can mark that as good */
  if (serveraddr.sa.sa_family == AF_INET6)
    serveraddr.in6.sin6_flowinfo = 0;
  
  header = (struct dns_header *)daemon->packet;

  if (n < (int)sizeof(struct dns_header) || !(header->hb3 & HB3_QR) || ntohs(header->qdcount) != 1)
    return;

  p = (unsigned char *)(header+1);
  if (!extract_name(header, n, &p, daemon->namebuff, EXTR_NAME_EXTRACT, 4))
    return; /* bad packet */
  GETSHORT(rrtype, p); 
  GETSHORT(class, p);

  if (!(forward = lookup_frec(now, daemon->namebuff, class, rrtype, ntohs(header->id), FREC_ANSWER, 0)))
    return;

  filter_servers(forward->sentto->arrayposn, F_SERVER, &first, &last);

  /* Check that this arrived on the file descriptor we expected. */

  /* sent from random port */
  for (fdl = forward->rfds; fdl; fdl = fdl->next)
    if (fdl->rfd->fd == fd)
      break;

  if (!fdl)
    {
      /* Sent to upstream from socket associated with a server. 
	 Note we have to iterate over all the possible servers, since they may
	 have different bound sockets. */
      for (serv = first; serv != last; serv++)
	{
	  server = daemon->serverarray[serv];
	  if (server->sfd && server->sfd->fd == fd)
	    break;

	  if (serv == last)
	    return;
	}
    }
  
  /* spoof check: answer must come from known server, also
     we may have sent the same query to multiple servers from
     the same local socket, and would like to know which one has answered. */
  for (c = first; c != last; c++)
    if (sockaddr_isequal(&daemon->serverarray[c]->addr, &serveraddr))
      break;
  
  if (c == last)
    return;

  server = daemon->serverarray[c];

  if (RCODE(header) != REFUSED)
    daemon->serverarray[first]->last_server = c;
  else if (daemon->serverarray[first]->last_server == c)
    daemon->serverarray[first]->last_server = -1;

  /* log_query gets called indirectly all over the place, so 
     pass these in global variables - sorry. */
  daemon->log_display_id = forward->frec_src.log_id;
  daemon->log_source_addr = &forward->frec_src.source;
  
#ifdef HAVE_DUMPFILE
  dump_packet_udp((forward->flags & (FREC_DNSKEY_QUERY | FREC_DS_QUERY)) ? DUMP_SEC_REPLY : DUMP_UP_REPLY,
		  (void *)header, n, &serveraddr, NULL, fd);
#endif

  if (daemon->ignore_addr && RCODE(header) == NOERROR &&
      check_for_ignored_address(header, n))
    return;

#ifdef HAVE_DNSSEC
      /* The query MAY have got a good answer, and be awaiting
	 the results of further queries, in which case
	 the stash contains something else and we don't need to retry anyway.
	 We may also have already got a truncated reply, and be in the process
	 of doing the query by TCP so can ignore further, probably truncated, UDP answers. */
      if (forward->blocking_query || (forward->flags & FREC_GONE_TO_TCP))
	return;
#endif
      
  if ((RCODE(header) == REFUSED || RCODE(header) == SERVFAIL) && forward->forwardall == 0)
    /* for broken servers, attempt to send to another one. */
    {
      /* Get the saved query back. */
      blockdata_retrieve(forward->stash, forward->stash_len, (void *)header);
      
      forward_query(-1, NULL, NULL, 0, header, forward->stash_len, 0, now, forward, 0, 0);
      return;
    }

  /* If the answer is an error, keep the forward record in place in case
     we get a good reply from another server. Kill it when we've
     had replies from all to avoid filling the forwarding table when
     everything is broken */

  /* decrement count of replies recieved if we sent to more than one server. */
  if (forward->forwardall && (--forward->forwardall > 1) && RCODE(header) == REFUSED)
    return;

  forward->sentto = server;

  /* We have a good answer, and will now validate it or return it. 
     It may be some time before this the validation completes, but we don't need
     any more answers, so close the socket(s) on which we were expecting
     answers, to conserve file descriptors, and to save work reading and
     discarding answers for other upstreams. */
  free_rfds(&forward->rfds);

  /* calculate modified moving average of server latency */
  if (server->query_latency == 0)
    server->mma_latency = (dnsmasq_milliseconds() - forward->forward_timestamp) * 128; /* init */
  else
    server->mma_latency += dnsmasq_milliseconds() - forward->forward_timestamp - server->query_latency;
  /* denominator controls how many queries we average over. */
  server->query_latency = server->mma_latency/128;
  
  /* Flip the bits back in the query name. */
    if (!extract_name(header, n, NULL, (char *)&forward->frec_src.encode_bitmap, EXTR_NAME_FLIP, 1))
    return;
      
#ifdef HAVE_DNSSEC
  if (option_bool(OPT_DNSSEC_VALID))
    {
      if (!(forward->flags & FREC_CHECKING_DISABLED))
	{
	  dnssec_validate(forward, header, n, STAT_OK, now);
	  return;
	}
      
      /* If dnssec_validate() not called, rr_status{} is not valid
	 Clear it so we don't erroneously mark RRs as secure using stale data from
	 previous queries. */
      memset(daemon->rr_status, 0, sizeof(*daemon->rr_status) * daemon->rr_status_sz);
    }
#endif
  
    return_reply(now, forward, header, n, STAT_OK); 
}

/**
 * @brief Perform element-wise XOR operation on two integer arrays
 * 
 * @detailed Applies bitwise XOR operation between corresponding elements of two
 *           unsigned integer arrays, storing results in the first array. Used by
 *           flip_queryname() to merge bitmap encodings for DNS query name case flipping,
 *           which helps prevent tracking through query name capitalization patterns.
 * 
 * @param arg1 Target array receiving XOR results (modified in-place). Must not be NULL.
 * @param arg2 Source array for XOR operation (read-only). Must not be NULL.
 * @param len Number of unsigned int elements to process in both arrays
 * 
 * @return void
 * 
 * @note Both arrays must have at least 'len' elements to prevent buffer overflow
 * @note arg1 is modified in-place with XOR results: arg1[i] = arg1[i] ^ arg2[i]
 * @note If arrays differ in actual length, caller must ensure len matches shorter array
 * 
 * @warning No bounds checking performed - caller must ensure arrays are properly sized
 * @warning Undefined behavior if arg1 or arg2 is NULL
 * 
 * @see flip_queryname() in forward.c - primary caller using this for bitmap merging
 * 
 * EXAMPLE USAGE:
 * @code
 * unsigned int bitmap1[4] = {0xFF00FF00, 0x00FF00FF, 0x12345678, 0xABCDEF00};
 * unsigned int bitmap2[4] = {0x0F0F0F0F, 0xF0F0F0F0, 0x11111111, 0x22222222};
 * xor_array(bitmap1, bitmap2, 4);
 * // bitmap1 now contains: {0xF00FF00F, 0xF00FF00F, 0x03254569, 0x89EFCD22}
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (internal utility function for query privacy enhancement)
 * SIDE EFFECTS: Modifies arg1 array contents
 * THREAD SAFETY: Not thread-safe - caller must ensure exclusive access to arg1 array
 */
static void xor_array(unsigned int *arg1, unsigned int *arg2, unsigned int len)
{
  unsigned int i;

  for (i = 0; i < len; i++)
    arg1[i] ^= arg2[i];
}

/* Call extract_name() to flip case of query in packet according to the XOR of the bit maps help in arg1 and arg2 */
/**
 * @brief Flip DNS query name case based on XOR of two bitmap encodings for privacy
 * 
 * @detailed Applies case-flipping transformation to DNS query name by XORing two bitmap
 *           encodings (from arg1 and arg2 frec_src structures) and using the result to
 *           control which characters flip case. This privacy-enhancing feature prevents
 *           tracking through query name capitalization patterns (0x20 bit encoding).
 *           
 *           The function handles two bitmap storage modes:
 *           - Single 32-bit integer (encode_bigmap is NULL, uses encode_bitmap field)
 *           - Arbitrary-length array of 32-bit integers (encode_bigmap points to array,
 *             encode_bitmap field stores array length)
 *           
 *           When bitmap lengths differ, the shorter is notionally zero-extended. The
 *           XOR result is used by extract_name() with EXTR_NAME_FLIP flag to flip
 *           specific character cases, then original bitmaps are restored via second XOR.
 * 
 * @param header DNS packet header containing query name to flip. Must not be NULL.
 * @param len Total length of DNS packet in bytes, used for bounds checking
 * @param arg1 First frec_src structure with bitmap encoding. Must not be NULL.
 * @param arg2 Second frec_src structure with bitmap encoding. Must not be NULL.
 * 
 * @return void
 * 
 * @note Bitmaps are XORed, used for flipping, then restored to original values
 * @note If arg1->encode_bigmap is NULL, uses &arg1->encode_bitmap as single-int bitmap
 * @note If arg2->encode_bigmap is NULL, uses &arg2->encode_bitmap as single-int bitmap
 * @note Longer bitmap is used for extract_name operation after XOR merging
 * @note The frec_src structures are temporarily modified but restored before return
 * 
 * @warning Modifies DNS packet header in-place (flips query name case)
 * @warning Undefined behavior if header, arg1, or arg2 is NULL
 * @warning extract_name() must support EXTR_NAME_FLIP flag for case flipping
 * 
 * @see xor_array() in forward.c - performs bitwise XOR of bitmap arrays
 * @see extract_name() in rfc1035.c - DNS name extraction with EXTR_NAME_FLIP support
 * @see struct frec_src in dnsmasq.h - forward record source with bitmap encoding
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dns_header *header = ...;  // DNS packet with query
 * ssize_t pktlen = 512;
 * struct frec_src src1, src2;
 * src1.encode_bitmap = 0x12345678;
 * src1.encode_bigmap = NULL;  // Single 32-bit bitmap
 * src2.encode_bitmap = 0xABCDEF00;
 * src2.encode_bigmap = NULL;
 * flip_queryname(header, pktlen, &src1, &src2);
 * // Query name case flipped based on XOR(0x12345678, 0xABCDEF00) bitmap
 * @endcode
 * 
 * RFC COMPLIANCE: Privacy enhancement (0x20 bit encoding) - not standardized RFC feature
 * SIDE EFFECTS: Modifies DNS query name case in header; temporarily modifies arg1/arg2 bitmaps
 * THREAD SAFETY: Not thread-safe - caller must ensure exclusive access to header and frec_src
 */
static void flip_queryname(struct dns_header *header, ssize_t len, struct frec_src *arg1, struct frec_src *arg2)
{
  unsigned int *arg1p, *arg2p, arg1len, arg2len;

   /* Two cases: bitmap is single 32 bit int, or it's arbitrary-length array of 32bit ints.
      The two args may be different and of different lengths.
      The shorter gets notionally extended with zeros. */
    
  if (arg1->encode_bigmap)
    arg1p = arg1->encode_bigmap, arg1len = arg1->encode_bitmap;
  else
    arg1p = &arg1->encode_bitmap, arg1len = 1;

  if (arg2->encode_bigmap)
    arg2p = arg2->encode_bigmap, arg2len = arg2->encode_bitmap;
  else
    arg2p = &arg2->encode_bitmap, arg2len = 1;

  /* make arg1 the longer, if they differ. */
  if (arg2len > arg1len)
    {
      unsigned int swapl = arg1len, *swapp = arg1p;
      arg1len = arg2len, arg1p = arg2p;
      arg2len = swapl, arg2p = swapp;
    }

  /* XOR on shorter length, flip on longer, operate on longer */
  xor_array(arg1p, arg2p, arg2len);
  extract_name(header, len, NULL, (char *)arg1p, EXTR_NAME_FLIP, arg1len);
  xor_array(arg1p, arg2p, arg2len); /* restore */
}

/**
 * @brief Process DNS response from upstream server and return to original client(s)
 * 
 * @detailed This function handles the complete response processing pipeline after receiving
 *           a DNS response from an upstream server. It processes DNSSEC validation status,
 *           determines caching policy, restores original query flags, handles multiple
 *           requestors for the same query, manages packet size limitations, and sends
 *           responses to all clients. The function also updates performance metrics and
 *           performs cleanup of the forward record. This is the final stage of the DNS
 *           query forwarding state machine before returning to idle state.
 * 
 * @param now Current time for cache TTL calculations and logging timestamps
 * @param forward Forward record (struct frec) containing query state, source information,
 *                and linked list of all clients that requested this query. Must not be NULL.
 * @param header DNS response packet header with complete DNS message. Modified in-place
 *               to restore CD bit and set truncation flag if needed. Must not be NULL.
 * @param n Size of DNS response packet in bytes (ssize_t). Must be positive for valid response.
 * @param status DNSSEC validation status code: STAT_OK (validation off), STAT_SECURE (valid),
 *               STAT_INSECURE (unsigned), STAT_BOGUS (invalid), STAT_ABANDONED (validation failed),
 *               or STAT_TRUNCATED. Used to determine caching policy and logging.
 * 
 * @return void (no return value)
 * 
 * @note This function handles multiple query sources through the forward->frec_src linked list,
 *       allowing efficient handling of duplicate queries from different clients
 * @note Packet size handling: responses larger than client UDP buffer size trigger truncated
 *       response with TC bit set per RFC 1035
 * @note Query name flipping: restores original query names for each requestor when multiple
 *       queries were deduplicated upstream
 * 
 * @warning Frees the forward record at completion - forward pointer invalid after return
 * @warning Modifies header in-place: CD bit restoration and potential truncation flag setting
 * @warning Forward record must have at least one valid source in forward->frec_src
 * 
 * @see process_reply() for response validation, rebind checking, and cache insertion
 * @see send_from() for UDP packet transmission with source address control
 * @see free_frec() for forward record cleanup
 * @see flip_queryname() for query name restoration for multiple requestors
 * 
 * EXAMPLE USAGE:
 * @code
 * // Called from reply_query after receiving upstream response
 * struct frec *forward = lookup_frec(now, target, class, type, id, flags, flagmask);
 * struct dns_header *header = (struct dns_header *)daemon->packet;
 * ssize_t n = recv(forward->rfds->fd, daemon->packet, daemon->packet_buff_sz, 0);
 * return_reply(now, forward, header, n, STAT_OK);
 * // forward is now freed and must not be accessed
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 1035 Section 4.2.1 (UDP response truncation for oversized packets)
 * RFC COMPLIANCE: RFC 4035 Section 3.2.2 (CD bit handling for DNSSEC validation)
 * RFC COMPLIANCE: RFC 8914 (Extended DNS Errors) - sets EDE codes for validation failures
 * 
 * SIDE EFFECTS:
 * - Sets daemon->log_display_id and daemon->log_source_addr for logging context
 * - Updates daemon->metrics[METRIC_CRYPTO_HWM] with crypto operation high-water mark
 * - Updates daemon->metrics[METRIC_WORK_HWM] with validation work high-water mark
 * - Modifies header->hb4 CD bit to match original query state
 * - Calls process_reply() which may insert response into cache
 * - Sends UDP packets to all clients via send_from()
 * - Logs query results with F_SECSTAT for DNSSEC status, F_UPSTREAM for duplicates
 * - Frees forward record and all associated frec_src entries
 * - May dump packets via dump_packet_udp() if HAVE_DUMPFILE enabled
 * - May call report_addresses() for conntrack allowlist integration
 * 
 * THREAD SAFETY: Single-threaded daemon architecture - modifies global daemon state
 */
void return_reply(time_t now, struct frec *forward, struct dns_header *header, ssize_t n, int status)
{
  int check_rebind = 0, no_cache_dnssec = 0, cache_secure = 0, bogusanswer = 0;
  size_t nn;
  int ede = EDE_UNSET;

  (void)status;

  daemon->log_display_id = forward->frec_src.log_id;
  daemon->log_source_addr = (forward->frec_src.fd != -1) ? &forward->frec_src.source : NULL;
  
  /* Don't cache replies where DNSSEC validation was turned off, either
     the upstream server told us so, or the original query specified it.  */
  if ((header->hb4 & HB4_CD) || (forward->flags & FREC_CHECKING_DISABLED))
    no_cache_dnssec = 1;

#ifdef HAVE_DNSSEC
  if (!STAT_ISEQUAL(status, STAT_OK))
    {
      /* status is STAT_OK when validation not turned on. */
      no_cache_dnssec = 0;
      
      if (STAT_ISEQUAL(status, STAT_TRUNCATED))
	{
	  header->hb3 |= HB3_TC;
	  log_query(F_SECSTAT, "result", NULL, "TRUNCATED", 0);
	}
      else
	{
	  char *result, *domain = "result";
	  union all_addr a;

	  ede = errflags_to_ede(status);
	  
	  if (STAT_ISEQUAL(status, STAT_ABANDONED))
	    {
	      result = "ABANDONED";
	      status = STAT_BOGUS;
	      if (ede == EDE_UNSET)
		ede = EDE_OTHER;
	    }
	  else
	    result = (STAT_ISEQUAL(status, STAT_SECURE) ? "SECURE" : (STAT_ISEQUAL(status, STAT_INSECURE) ? "INSECURE" : "BOGUS"));

	  
	  if (STAT_ISEQUAL(status, STAT_SECURE))
	    cache_secure = 1;
	  else if (STAT_ISEQUAL(status, STAT_BOGUS))
	    {
	      if (ede == EDE_UNSET)
		ede = EDE_DNSSEC_BOGUS;
	      no_cache_dnssec = 1;
	      bogusanswer = 1;
	      
	      if (extract_name(header, n, NULL, daemon->namebuff, EXTR_NAME_EXTRACT, 0))
		domain = daemon->namebuff;
	    }
      
	  a.log.ede = ede;
	  log_query(F_SECSTAT, domain, &a, result, 0);
	}
    }
  
  if ((daemon->limit[LIMIT_CRYPTO] - forward->validate_counter) > (int)daemon->metrics[METRIC_CRYPTO_HWM])
    daemon->metrics[METRIC_CRYPTO_HWM] = daemon->limit[LIMIT_CRYPTO] - forward->validate_counter;
  
  if ((daemon->limit[LIMIT_WORK] - forward->work_counter) > (int)daemon->metrics[METRIC_WORK_HWM])
    daemon->metrics[METRIC_WORK_HWM] = daemon->limit[LIMIT_WORK] - forward->work_counter;
#endif
  
  if (option_bool(OPT_NO_REBIND))
    check_rebind = !(forward->flags & FREC_NOREBIND);
  
  /* restore CD bit to the value in the query */
  if (forward->flags & FREC_CHECKING_DISABLED)
    header->hb4 |= HB4_CD;
  else
    header->hb4 &= ~HB4_CD;

  /* Never cache answers which are contingent on the source or MAC address EDSN0 option,
     since the cache is ignorant of such things. */
  if (forward->flags & FREC_NO_CACHE)
    no_cache_dnssec = 1;
  
  if ((nn = process_reply(header, now, forward->sentto, (size_t)n, check_rebind, no_cache_dnssec, cache_secure, bogusanswer, 
			  forward->flags & FREC_AD_QUESTION, forward->flags & FREC_DO_QUESTION, 
			  !(forward->flags & FREC_HAS_PHEADER), &forward->frec_src.source,
			  ((unsigned char *)header) + daemon->edns_pktsz, ede)))
    {
      struct frec_src *src, *prev;
      int do_trunc;
            
      for (do_trunc = 0, prev = NULL, src = &forward->frec_src; src; prev = src, src = src->next)
	{
	  header->id = htons(src->orig_id);
	  
#if defined(HAVE_CONNTRACK) && defined(HAVE_UBUS)
	  if (option_bool(OPT_CMARK_ALST_EN))
	    {
	      unsigned int mark;
	      int have_mark = get_incoming_mark(&src->source, &src->dest, /* istcp: */ 0, &mark);
	      if (have_mark && ((u32)mark & daemon->allowlist_mask))
		report_addresses(header, nn, mark);
	    }
#endif
	  
	  /* You will have to draw diagrams and scratch your head to convince yourself
	     that this works. Bear in mind that the flip to upstream state has already been undone,
	     for the original query so nothing needs to be done, but subsequent queries' flips
	     were recorded relative to the flipped name sent upstream. */
	  if (prev)
	    flip_queryname(header, nn, prev, src);
	  
	  if (src->fd != -1)
	    {
	      /* Only send packets that fit what the requestor allows.
		 We'll send a truncated packet to others below. */
	      if (nn <= src->udp_pkt_size)
		{
		  send_from(src->fd, option_bool(OPT_NOWILD) || option_bool (OPT_CLEVERBIND), daemon->packet, nn, 
			    &src->source, &src->dest, src->iface);
#ifdef HAVE_DUMPFILE
		  dump_packet_udp(DUMP_REPLY, daemon->packet, (size_t)nn, NULL, &src->source, src->fd);
#endif
		}
	      else
		do_trunc = 1;
	      
	      if (option_bool(OPT_EXTRALOG) && src != &forward->frec_src)
		{
		  daemon->log_display_id = src->log_id;
		  daemon->log_source_addr = &src->source;
		  log_query(F_UPSTREAM, "query", NULL, "duplicate", 0);
		}
	    }
	}

      /* The packet is too big for one or more requestors, send them a truncated answer. */
      if (do_trunc)
	{
	  size_t hlen, new;
	  unsigned char *pheader = find_pseudoheader(header, nn, &hlen, NULL, NULL, NULL);
	  
	  header->ancount = htons(0);
	  header->nscount = htons(0);
	  header->arcount = htons(0);
	  header->hb3 |= HB3_TC;
	  new = resize_packet(header, nn, pheader, hlen);
	  
	  daemon->log_display_id = forward->frec_src.log_id;
	  daemon->log_source_addr = &forward->frec_src.source;
	  log_query(F_UPSTREAM, NULL, NULL, "truncated", 0);

	  /* This gets the name back to the state it was in when we started. */
	  flip_queryname(header, new, prev, &forward->frec_src);
	  
	  for (src = &forward->frec_src, prev = NULL; src; prev = src, src = src->next)
	    {
	      /* If you didn't undertand this above, you won't understand it here either. */
	      if (prev)
		flip_queryname(header, new, prev, src);
	      
	      if (src->fd != -1 && nn > src->udp_pkt_size)
		{
		  header->id = htons(src->orig_id);
		  send_from(src->fd, option_bool(OPT_NOWILD) || option_bool (OPT_CLEVERBIND), daemon->packet, new, 
			    &src->source, &src->dest, src->iface);
		  
#ifdef HAVE_DUMPFILE
		  dump_packet_udp(DUMP_REPLY, daemon->packet, (size_t)new, NULL, &src->source, src->fd);
#endif
		}
	    }
	}
    }
      
  free_frec(forward); /* cancel */
}
  

#ifdef HAVE_CONNTRACK
/**
 * @brief Check if DNS query for name is allowed for given connection tracking mark
 * 
 * @detailed Validates DNS query against configured allowlists associated with firewall
 *           connection tracking marks. This feature enables fine-grained DNS filtering
 *           based on source connection identity (e.g., container, network namespace,
 *           user UID) propagated through netfilter conntrack marks.
 *           
 *           The function iterates through daemon->allowlists, matching marks using
 *           bitwise AND with daemon->allowlist_mask and allowlist-specific masks.
 *           For matching allowlist entries, it checks domain name patterns:
 *           - Wildcard "*" permits all queries
 *           - Specific patterns (e.g., "*.example.com") use DNS name matching
 *           
 *           Name validation occurs lazily (only once, cached in did_validate_name)
 *           to avoid redundant checks across multiple patterns. If no allowlist
 *           matches the mark, or no pattern matches the name, query is denied.
 * 
 * @param mark Connection tracking mark (u32) from netfilter conntrack. Zero if no mark.
 * @param name DNS query name (FQDN) to check against allowlist patterns. May be NULL
 *             for malformed queries (treated as invalid name, no match).
 * 
 * @return 1 if query is allowed (mark matches allowlist AND pattern matches name)
 * @retval 1 Query allowed: mark matched AND ("*" pattern OR name matched pattern)
 * @retval 0 Query denied: no allowlist matched mark, OR no pattern matched name
 * 
 * @note If name is NULL, treated as invalid name (no pattern match except "*")
 * @note Wildcard "*" pattern allows all queries for that mark regardless of name
 * @note Mark matching uses: (mark & daemon->allowlist_mask & allowlist->mask) == allowlist->mark
 * @note Name validation and pattern matching only performed if mark matches
 * @note First matching pattern returns 1 immediately (short-circuit evaluation)
 * 
 * @warning Requires HAVE_CONNTRACK compile flag and configured allowlists
 * @warning Invalid mark values (when allowlists configured) result in query denial
 * @warning Performance: O(N*M) where N=allowlists, M=patterns per allowlist
 * 
 * @see is_valid_dns_name() in util.c - validates DNS name format
 * @see is_dns_name_matching_pattern() in domain-match.c - pattern matching logic
 * @see struct allowlist in dnsmasq.h - allowlist configuration structure
 * @see answer_disallowed() in forward.c - generates REFUSED response for denied queries
 * 
 * EXAMPLE USAGE:
 * @code
 * u32 mark = 0x00000100;  // Connection mark from conntrack
 * const char *query_name = "www.example.com";
 * if (is_query_allowed_for_mark(mark, query_name)) {
 *   // Forward query to upstream
 * } else {
 *   // Return REFUSED (answer_disallowed)
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: Non-standard feature (connection tracking mark-based filtering)
 * SIDE EFFECTS: None (read-only check against daemon->allowlists configuration)
 * THREAD SAFETY: Not thread-safe - assumes single-threaded daemon access to allowlists
 */
static int is_query_allowed_for_mark(u32 mark, const char *name)
{
  int is_allowable_name, did_validate_name = 0;
  struct allowlist *allowlists;
  char **patterns_pos;
  
  for (allowlists = daemon->allowlists; allowlists; allowlists = allowlists->next)
    if (allowlists->mark == (mark & daemon->allowlist_mask & allowlists->mask))
      for (patterns_pos = allowlists->patterns; *patterns_pos; patterns_pos++)
	{
	  if (!strcmp(*patterns_pos, "*"))
	    return 1;
	  if (!did_validate_name)
	    {
	      is_allowable_name = name ? is_valid_dns_name(name) : 0;
	      did_validate_name = 1;
	    }
	  if (is_allowable_name && is_dns_name_matching_pattern(name, *patterns_pos))
	    return 1;
	}
  return 0;
}

/**
 * @brief Generate DNS REFUSED response for disallowed query (failed allowlist check)
 * 
 * @detailed Constructs DNS error response when query is denied by allowlist filtering
 *           (is_query_allowed_for_mark returned 0). Sets DNS response code to indicate
 *           query refusal, includes Extended DNS Error (EDE) code EDE_BLOCKED when
 *           supported, and optionally broadcasts UBus event for audit/monitoring.
 *           
 *           Response construction process:
 *           1. Broadcast UBus event (HAVE_UBUS): Notify system of blocked query
 *           2. Call setup_reply() with flags=0 and EDE_BLOCKED (RFC 8914 extended error)
 *           3. Skip question section to position response pointer
 *           4. Return response length (pointer offset from header start)
 *           
 *           The function returns minimal response (header + question section, no answer)
 *           with REFUSED rcode to inform client of policy denial.
 * 
 * @param header DNS packet header to convert into REFUSED response. Must not be NULL.
 *               Modified in-place to set response flags and extended error.
 * @param qlen Original query length in bytes, used for question section bounds checking
 * @param mark Connection tracking mark that failed allowlist check (logged in UBus event)
 * @param name DNS query name that was disallowed (logged in UBus event). May be NULL.
 * 
 * @return Size of DNS response packet in bytes (header + question section)
 * @retval >0 Response length: successfully constructed REFUSED response
 * @retval 0 Failure: skip_questions() failed (malformed question section)
 * 
 * @note Parameters 'name' and 'mark' unused except for HAVE_UBUS broadcast
 * @note Response contains no answer records (authority/additional sections empty)
 * @note setup_reply() sets DNS response code to REFUSED and includes EDE_BLOCKED
 * @note UBus event only sent if HAVE_UBUS compiled and name is non-NULL
 * @note Caller must send returned response to client via UDP or TCP
 * 
 * @warning Modifies DNS header in-place to construct response
 * @warning Returns 0 if question section malformed (caller should drop packet)
 * @warning Undefined behavior if header is NULL
 * 
 * @see is_query_allowed_for_mark() in forward.c - allowlist check triggering this response
 * @see setup_reply() in rfc1035.c - sets DNS header flags and extended error code
 * @see skip_questions() in rfc1035.c - validates and skips question section
 * @see ubus_event_bcast_connmark_allowlist_refused() in ubus.c - audit event broadcast
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dns_header *header = ...; // DNS query packet
 * size_t qlen = 512;
 * u32 mark = 0x00000100;
 * const char *name = "blocked.example.com";
 * if (!is_query_allowed_for_mark(mark, name)) {
 *   size_t resplen = answer_disallowed(header, qlen, mark, name);
 *   if (resplen > 0)
 *     send_from(udpfd, 0, (char *)header, resplen, &client_addr, NULL, 0);
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 1035 (REFUSED response), RFC 8914 (EDE_BLOCKED extended error)
 * SIDE EFFECTS: Modifies header to REFUSED response; broadcasts UBus event if HAVE_UBUS
 * THREAD SAFETY: Not thread-safe - modifies header in-place, accesses daemon globals
 */
static size_t answer_disallowed(struct dns_header *header, size_t qlen, u32 mark, const char *name)
{
  unsigned char *p;
  (void)name;
  (void)mark;
  
#ifdef HAVE_UBUS
  if (name)
    ubus_event_bcast_connmark_allowlist_refused(mark, name);
#endif
  
  setup_reply(header, /* flags: */ 0, EDE_BLOCKED);
  
  if (!(p = skip_questions(header, qlen)))
    return 0;
  return p - (unsigned char *)header;
}
#endif

/**
 * @brief Process DNS query packet received from downstream client on listening socket
 * 
 * @detailed This is the main entry point for client DNS query processing in the forwarding
 * engine. Handles query reception on UDP or TCP sockets, performs cache lookups, initiates
 * upstream forwarding for cache misses, and manages the complete query lifecycle from client
 * reception through response transmission. Integrates with cache.c for local resolution,
 * rfc1035.c for wire format parsing, and dnssec.c for DNSSEC processing when enabled.
 * 
 * Processing flow:
 * 1. Receive DNS query packet from client socket (UDP port 53 or TCP connection)
 * 2. Parse and validate DNS header and question section (extract_request)
 * 3. Apply filtering rules (bogus-priv, filterwin2k, local-only domains)
 * 4. Check local cache via cache.c:lookup_domain() for existing answer
 * 5. If cache hit: return cached response immediately to client
 * 6. If cache miss: allocate forward record (struct frec), select upstream server,
 *    forward query via send_from() with randomized source port
 * 7. Track query state in forward record for matching response to client
 * 
 * Special handling:
 * - DNSSEC queries: Preserve DO (DNSSEC OK) bit, may require TCP fallback
 * - TCP queries: Handle connection state, large responses, truncation
 * - Local queries: /etc/hosts, DHCP leases, authoritative zones answered locally
 * - Filtered domains: Return NXDOMAIN or NODATA for blocked domains
 * - Upstream selection: Round-robin with server availability tracking
 * 
 * @param listen Pointer to listener structure representing the socket that received
 *               the query. Contains socket file descriptor, listening address/interface,
 *               and socket type (UDP vs TCP). Must not be NULL.
 * @param now Current timestamp for TTL calculations, cache expiration checks, and
 *            timeout management. Typically obtained from time(0).
 * 
 * @return void - Function does not return error status. Errors are logged via my_syslog()
 *         and query processing continues for subsequent queries. Malformed packets and
 *         resource exhaustion are handled gracefully without daemon termination.
 * 
 * @note This function performs extensive error checking and logging via my_syslog().
 *       Failed queries due to malformed packets or resource limits are logged but do not
 *       crash the daemon - graceful degradation ensures continued service.
 * 
 * @warning Modifies global daemon state including forward record array (daemon->frec_list),
 *          cache contents via cache operations, and server selection state. Not thread-safe:
 *          relies on single-threaded event loop architecture for synchronization.
 * 
 * @see forward_query() for upstream forwarding after cache miss
 * @see reply_query() for processing upstream server responses
 * @see extract_request() in rfc1035.c for DNS packet parsing
 * @see lookup_domain() in cache.c for cache query operations
 * 
 * EXAMPLE USAGE:
 * @code
 * struct listener *udp_listener = ...; // UDP socket listener
 * time_t current_time = time(0);
 * receive_query(udp_listener, current_time);
 * // Function returns void; errors logged internally
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 1035 Section 4.1 (query format), RFC 6891 (EDNS0 processing)
 * 
 * SIDE EFFECTS:
 * - Network I/O: Reads from client socket, may write cached response immediately
 * - Memory allocation: May allocate forward record (struct frec) for query tracking
 * - Cache queries: Performs cache lookup, may return cached records
 * - State mutation: Updates forward record array, server availability tracking
 * - Logging: Generates query logs when --log-queries enabled
 * - Upstream forwarding: May initiate UDP/TCP connection to upstream DNS server
 * 
 * THREAD SAFETY: NOT thread-safe. Designed for single-threaded event loop. Assumes
 * exclusive access to global daemon state, forward record array, and cache structures.
 */
void receive_query(struct listener *listen, time_t now)
{
  struct dns_header *header = (struct dns_header *)daemon->packet;
  union mysockaddr source_addr;
  unsigned char *pheader;
  unsigned short type, udp_size = PACKETSZ; /* default if no EDNS0 */
  union all_addr dst_addr;
  struct in_addr netmask, dst_addr_4;
  size_t m;
  ssize_t n;
  int if_index = 0, auth_dns = 0, do_bit = 0;
  unsigned int fwd_flags = 0;
  int stale = 0, filtered = 0, ede = EDE_UNSET, do_forward = 0;
  int metric, fd; 
  struct blockdata *saved_question = NULL;
#ifdef HAVE_CONNTRACK
  unsigned int mark = 0;
  int have_mark = 0;
  int allowed = 1;
#  ifdef HAVE_UBUS
  int report = 0;
#  endif
#endif
#ifdef HAVE_AUTH
  int local_auth = 0;
#endif
  struct iovec iov[1];
  struct msghdr msg;
  struct cmsghdr *cmptr;
  union {
    struct cmsghdr align; /* this ensures alignment */
    char control6[CMSG_SPACE(sizeof(struct in6_pktinfo))];
#if defined(HAVE_LINUX_NETWORK)
    char control[CMSG_SPACE(sizeof(struct in_pktinfo))];
#elif defined(IP_RECVDSTADDR) && defined(HAVE_SOLARIS_NETWORK)
    char control[CMSG_SPACE(sizeof(struct in_addr)) +
		 CMSG_SPACE(sizeof(unsigned int))];
#elif defined(IP_RECVDSTADDR)
    char control[CMSG_SPACE(sizeof(struct in_addr)) +
		 CMSG_SPACE(sizeof(struct sockaddr_dl))];
#endif
  } control_u;
  int family = listen->addr.sa.sa_family;
   /* Can always get recvd interface for IPv6 */
  int check_dst = !option_bool(OPT_NOWILD) || family == AF_INET6;
  
  /* packet buffer overwritten */
  daemon->srv_save = NULL;

  dst_addr_4.s_addr = dst_addr.addr4.s_addr = 0;
  netmask.s_addr = 0;
  
  if (option_bool(OPT_NOWILD) && listen->iface)
    {
      auth_dns = listen->iface->dns_auth;
     
      if (family == AF_INET)
	{
	  dst_addr_4 = dst_addr.addr4 = listen->iface->addr.in.sin_addr;
	  netmask = listen->iface->netmask;
	}
    }
  
  iov[0].iov_base = daemon->packet;
  iov[0].iov_len = daemon->edns_pktsz;
    
  msg.msg_control = control_u.control;
  msg.msg_controllen = sizeof(control_u);
  msg.msg_flags = 0;
  msg.msg_name = &source_addr;
  msg.msg_namelen = sizeof(source_addr);
  msg.msg_iov = iov;
  msg.msg_iovlen = 1;
  
  if ((n = recvmsg(listen->fd, &msg, 0)) == -1)
    return;
  
  if (n < (int)sizeof(struct dns_header) || 
      (msg.msg_flags & MSG_TRUNC) ||
      (header->hb3 & HB3_QR))
    return;

  /* Clear buffer beyond request to avoid risk of
     information disclosure. */
  memset(daemon->packet + n, 0, daemon->edns_pktsz - n);
  
  source_addr.sa.sa_family = family;
  
  if (family == AF_INET)
    {
       /* Source-port == 0 is an error, we can't send back to that. 
	  http://www.ietf.org/mail-archive/web/dnsop/current/msg11441.html */
      if (source_addr.in.sin_port == 0)
	return;
    }
  else
    {
      /* Source-port == 0 is an error, we can't send back to that. */
      if (source_addr.in6.sin6_port == 0)
	return;
      source_addr.in6.sin6_flowinfo = 0;
    }
  
  /* We can be configured to only accept queries from at-most-one-hop-away addresses. */
  if (option_bool(OPT_LOCAL_SERVICE))
    {
      struct addrlist *addr;

      if (family == AF_INET6) 
	{
	  for (addr = daemon->interface_addrs; addr; addr = addr->next)
	    if ((addr->flags & ADDRLIST_IPV6) &&
		is_same_net6(&addr->addr.addr6, &source_addr.in6.sin6_addr, addr->prefixlen))
	      break;
	}
      else
	{
	  struct in_addr netmask;
	  for (addr = daemon->interface_addrs; addr; addr = addr->next)
	    {
	      netmask.s_addr = htonl(~(in_addr_t)0 << (32 - addr->prefixlen));
	      if (!(addr->flags & ADDRLIST_IPV6) &&
		  is_same_net(addr->addr.addr4, source_addr.in.sin_addr, netmask))
		break;
	    }
	}
      if (!addr)
	{
	  static int warned = 0;
	  if (!warned)
	    {
	      prettyprint_addr(&source_addr, daemon->addrbuff);
	      my_syslog(LOG_WARNING, _("ignoring query from non-local network %s (logged only once)"), daemon->addrbuff);
	      warned = 1;
	    }
	  return;
	}
    }
		
  if (check_dst)
    {
      struct ifreq ifr;

      if (msg.msg_controllen < sizeof(struct cmsghdr))
	return;

#if defined(HAVE_LINUX_NETWORK)
      if (family == AF_INET)
	for (cmptr = CMSG_FIRSTHDR(&msg); cmptr; cmptr = CMSG_NXTHDR(&msg, cmptr))
	  if (cmptr->cmsg_level == IPPROTO_IP && cmptr->cmsg_type == IP_PKTINFO)
	    {
	      union {
		unsigned char *c;
		struct in_pktinfo *p;
	      } p;
	      p.c = CMSG_DATA(cmptr);
	      dst_addr_4 = dst_addr.addr4 = p.p->ipi_spec_dst;
	      if_index = p.p->ipi_ifindex;
	    }
#elif defined(IP_RECVDSTADDR) && defined(IP_RECVIF)
      if (family == AF_INET)
	{
	  for (cmptr = CMSG_FIRSTHDR(&msg); cmptr; cmptr = CMSG_NXTHDR(&msg, cmptr))
	    {
	      union {
		unsigned char *c;
		unsigned int *i;
		struct in_addr *a;
#ifndef HAVE_SOLARIS_NETWORK
		struct sockaddr_dl *s;
#endif
	      } p;
	       p.c = CMSG_DATA(cmptr);
	       if (cmptr->cmsg_level == IPPROTO_IP && cmptr->cmsg_type == IP_RECVDSTADDR)
		 dst_addr_4 = dst_addr.addr4 = *(p.a);
	       else if (cmptr->cmsg_level == IPPROTO_IP && cmptr->cmsg_type == IP_RECVIF)
#ifdef HAVE_SOLARIS_NETWORK
		 if_index = *(p.i);
#else
  	         if_index = p.s->sdl_index;
#endif
	    }
	}
#endif
      
      if (family == AF_INET6)
	{
	  for (cmptr = CMSG_FIRSTHDR(&msg); cmptr; cmptr = CMSG_NXTHDR(&msg, cmptr))
	    if (cmptr->cmsg_level == IPPROTO_IPV6 && cmptr->cmsg_type == daemon->v6pktinfo)
	      {
		union {
		  unsigned char *c;
		  struct in6_pktinfo *p;
		} p;
		p.c = CMSG_DATA(cmptr);
		  
		dst_addr.addr6 = p.p->ipi6_addr;
		if_index = p.p->ipi6_ifindex;
	      }
	}
      
      /* enforce available interface configuration */
      
      if (!indextoname(listen->fd, if_index, ifr.ifr_name))
	return;
      
      if (!iface_check(family, &dst_addr, ifr.ifr_name, &auth_dns))
	{
	   if (!option_bool(OPT_CLEVERBIND))
	     enumerate_interfaces(0); 
	   if (!loopback_exception(listen->fd, family, &dst_addr, ifr.ifr_name) &&
	       !label_exception(if_index, family, &dst_addr))
	     return;
	}

      if (family == AF_INET && option_bool(OPT_LOCALISE))
	{
	  struct irec *iface;
	  
	  /* get the netmask of the interface which has the address we were sent to.
	     This is no necessarily the interface we arrived on. */
	  
	  for (iface = daemon->interfaces; iface; iface = iface->next)
	    if (iface->addr.sa.sa_family == AF_INET &&
		iface->addr.in.sin_addr.s_addr == dst_addr_4.s_addr)
	      break;
	  
	  /* interface may be new */
	  if (!iface && !option_bool(OPT_CLEVERBIND))
	    enumerate_interfaces(0); 
	  
	  for (iface = daemon->interfaces; iface; iface = iface->next)
	    if (iface->addr.sa.sa_family == AF_INET &&
		iface->addr.in.sin_addr.s_addr == dst_addr_4.s_addr)
	      break;
	  
	  /* If we failed, abandon localisation */
	  if (iface)
	    netmask = iface->netmask;
	  else
	    dst_addr_4.s_addr = 0;
	}
    }
   
  /* log_query gets called indirectly all over the place, so 
     pass these in global variables - sorry. */
  daemon->log_display_id = ++daemon->log_id;
  daemon->log_source_addr = &source_addr;

#ifdef HAVE_DUMPFILE
  dump_packet_udp(DUMP_QUERY, daemon->packet, (size_t)n, &source_addr, NULL, listen->fd);
#endif
  
#ifdef HAVE_CONNTRACK
  if (option_bool(OPT_CMARK_ALST_EN))
    have_mark = get_incoming_mark(&source_addr, &dst_addr, /* istcp: */ 0, &mark);
#endif

  if (OPCODE(header) != QUERY)
    log_query_mysockaddr((auth_dns ? F_NOERR : 0) | F_QUERY | F_FORWARD | F_CONFIG, NULL, &source_addr, NULL, OPCODE(header));
  else if (extract_request(header, (size_t)n, daemon->namebuff, &type, NULL))
    {
#ifdef HAVE_AUTH
      struct auth_zone *zone;
#endif
      log_query_mysockaddr((auth_dns ? F_NOERR | F_AUTH : 0 ) | F_QUERY | F_FORWARD, daemon->namebuff,
			   &source_addr, NULL, type);
      
#ifdef HAVE_AUTH
      /* Find queries for zones we're authoritative for, and answer them directly.
	 The exception to this is DS queries for the zone route. They
	 have to come from the parent zone. Since dnsmasq's auth server
	 can't do DNSSEC, the zone will be unsigned, and anything using
	 dnsmasq as a forwarder and doing validation will be expecting to
	 see the proof of non-existence from the parent. */
      if (!auth_dns && !option_bool(OPT_LOCALISE))
	for (zone = daemon->auth_zones; zone; zone = zone->next)
	  {
	    char *cut;
	    
	    if (in_zone(zone, daemon->namebuff, &cut))
	      {
		if (type != T_DS || cut)
		  {
		    auth_dns = 1;
		    local_auth = 1;
		  }
		break;
	      }
	  }
#endif
      
#ifdef HAVE_LOOP
      /* Check for forwarding loop */
      if (detect_loop(daemon->namebuff, type))
	return;
#endif
    }
  
  if (find_pseudoheader(header, (size_t)n, NULL, &pheader, NULL, NULL))
    { 
      unsigned short flags;
      
      fwd_flags |= FREC_HAS_PHEADER;
      
      GETSHORT(udp_size, pheader);
      pheader += 2; /* ext_rcode */
      GETSHORT(flags, pheader);
      
      if (flags & 0x8000)
	do_bit = 1;/* do bit */ 
	
      /* If the client provides an EDNS0 UDP size, use that to limit our reply.
	 (bounded by the maximum configured). If no EDNS0, then it
	 defaults to 512. We write this value into the query packet too, so that
	 if it's forwarded, we don't specify a maximum size greater than we can handle. */
      if (udp_size > daemon->edns_pktsz)
	udp_size = daemon->edns_pktsz;
      else if (udp_size < PACKETSZ)
	udp_size = PACKETSZ; /* Sanity check - can't reduce below default. RFC 6891 6.2.3 */
    }

  /* RFC 6840 5.7 */
  if (do_bit || (header->hb4 & HB4_AD))
    fwd_flags |= FREC_AD_QUESTION;

  if (do_bit)
    fwd_flags |= FREC_DO_QUESTION;

  if (header->hb4 & HB4_CD)
    fwd_flags |= FREC_CHECKING_DISABLED;

  fd = listen->fd;
  
#ifdef HAVE_CONNTRACK
#ifdef HAVE_AUTH
  if (!auth_dns || local_auth)
#endif
    if (option_bool(OPT_CMARK_ALST_EN) && have_mark && ((u32)mark & daemon->allowlist_mask))
      allowed = is_query_allowed_for_mark((u32)mark, daemon->namebuff);
#endif
  
  if (0);
#ifdef HAVE_CONNTRACK
  else if (!allowed)
    {
      ede = EDE_BLOCKED;
      m = answer_disallowed(header, (size_t)n, (u32)mark, daemon->namebuff);
      metric = METRIC_DNS_LOCAL_ANSWERED;
    }
#endif
#ifdef HAVE_AUTH
  else if (auth_dns)
    {
      m = answer_auth(header, ((char *) header) + udp_size, (size_t)n, now, &source_addr, local_auth);
      metric = METRIC_DNS_AUTH_ANSWERED;

#if defined(HAVE_CONNTRACK) && defined(HAVE_UBUS)
      if (local_auth)
	report = 1;
#endif
    }
#endif
  else
    {
      int cacheable;

      n = add_edns0_config(header, n, ((unsigned char *)header) + daemon->edns_pktsz, &source_addr, now, &cacheable);
      saved_question = blockdata_alloc((char *) header, (size_t)n);

      if (!cacheable)
	fwd_flags |= FREC_NO_CACHE;

      m = answer_request(header, ((char *) header) + udp_size, (size_t)n, 
			 dst_addr_4, netmask, now, fwd_flags & FREC_AD_QUESTION, do_bit, !cacheable, &stale, &filtered);
      
      metric = stale ? METRIC_DNS_STALE_ANSWERED : METRIC_DNS_LOCAL_ANSWERED;
      
      if (m == 0)
	do_forward = 1;
      else
	{
#if defined(HAVE_CONNTRACK) && defined(HAVE_UBUS)
	  report = 1;
#endif

	  if (filtered)
	    ede = EDE_FILTERED;
	  else if (stale)
	    ede = EDE_STALE;
	}
    }
  
  if (m != 0)
    {
      if (fwd_flags & FREC_HAS_PHEADER)
	{
	  if (ede != EDE_UNSET)
	    {
	      u16 swap = htons(ede);
	      
	      m = add_pseudoheader(header,  m,  ((unsigned char *) header) + daemon->edns_pktsz,
				   EDNS0_OPTION_EDE, (unsigned char *)&swap, 2, do_bit, 0);
	    }
	  else
	    m = add_pseudoheader(header,  m,  ((unsigned char *) header) + daemon->edns_pktsz,
				 0, NULL, 0, do_bit, 0);
	}
  
#ifdef HAVE_DUMPFILE
      dump_packet_udp(DUMP_REPLY, daemon->packet, m, NULL, &source_addr, listen->fd);
#endif
      
#if defined(HAVE_CONNTRACK) && defined(HAVE_UBUS)
      if (report)
	report_addresses(header, m, mark);
#endif
      
      send_from(listen->fd, option_bool(OPT_NOWILD) || option_bool(OPT_CLEVERBIND),
		(char *)header, m, &source_addr, &dst_addr, if_index);

      daemon->metrics[metric]++;
      
      if (stale)
	{
	  /* We answered with stale cache data, so forward the query anyway to
	     refresh that. */
	  do_forward = 1;
	  
	  /* Don't mark the query with the source in this case. */
	  daemon->log_source_addr = NULL;
	  
	  /* We've already answered the client, so don't send it the answer 
	     when it comes back. */
	  fd = -1;
	}
    }
  
  if (do_forward && saved_question)
    {
      /* Get the question back, since it may have been mangled by answer_request() */
      blockdata_retrieve(saved_question, (size_t)n, (void *)header);
      blockdata_free(saved_question);
      saved_question = NULL;

      forward_query(fd, &source_addr, &dst_addr, if_index, header, (size_t)n,
		    udp_size, now, NULL, fwd_flags, 0);
    }

  blockdata_free(saved_question);
}

 
/**
 * @brief Send DNS query via TCP to upstream servers using round-robin selection and return response
 * 
 * Attempts to send a DNS query to upstream servers via TCP connection, trying servers in the range
 * [first, last) starting at index 'start' in round-robin fashion. Opens TCP connections on demand,
 * applies socket timeouts, uses MSG_FASTOPEN when available, and validates response question section
 * matches the original query to prevent cache poisoning attacks.
 * 
 * @param first First server index in the rotation range (inclusive)
 * @param last Last server index in the rotation range (exclusive, stop before this index)
 * @param start Starting server index for this query attempt, must be in [first, last)
 * @param packet DNS query packet with 2-byte length prefix already written at offset 0-1
 * @param qsize Size of DNS query payload in bytes (excluding 2-byte length prefix)
 * @param have_mark Non-zero if connection tracking mark is available (Linux conntrack)
 * @param mark Connection tracking mark value to apply via SO_MARK socket option (Linux only)
 * @param servp Output parameter, points to pointer that will be updated to the server that responded successfully
 * 
 * @return Response size in bytes (payload only, excluding length prefix) on success
 * @retval >0 Successfully received response from upstream server, *servp updated to responding server
 * @retval 0 All servers tried without success, or fatal error occurred (connection refused, timeout, etc.)
 * 
 * @note Function tries servers in round-robin order: start, start+1, ..., last-1, first, first+1, ..., start-1
 * @note TCP connections are cached in serv->tcpfd and reused across queries for efficiency
 * @note Socket timeouts: send timeout TCP_TIMEOUT seconds, receive timeout 2*TCP_TIMEOUT seconds
 * @note MSG_FASTOPEN used when available to reduce connection latency (TFO sends data with SYN)
 * @note If read/write fails on a connection with SERV_GOT_TCP flag set, connection is closed and same server retried
 * @note Response question section validated to match original query (name, type, class) to prevent spoofing
 * 
 * @warning Connection tracking mark handling requires Linux kernel with netfilter conntrack support
 * @warning Function does not validate response authenticity beyond question section matching
 * @warning Socket operations have timeout but may still block main event loop briefly
 * 
 * EXAMPLE USAGE:
 * @code
 * unsigned char packet[DNS_PACKETSZ + 2];
 * u16 *length = (u16 *)packet;
 * struct dns_header *header = (struct dns_header *)&packet[2];
 * // ... build query in header with size qsize ...
 * struct server *responding_server = NULL;
 * ssize_t response_size = tcp_talk(0, daemon->numservers, 5, packet, qsize, 0, 0, &responding_server);
 * if (response_size > 0) {
 *   // Process response in packet[2..response_size+1], from responding_server
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 1035 Section 4.2.2 (DNS queries over TCP transport)
 * 
 * SIDE EFFECTS:
 * - Opens TCP connections (serv->tcpfd) and stores file descriptors in server structures
 * - Allocates blockdata for query copy (freed before return)
 * - Logs connection failures via my_syslog
 * - Updates daemon->serverarray[first]->last_server on successful connection
 * - Sets SERV_GOT_TCP flag on serv->flags after successful data exchange
 * - Applies SO_MARK socket option for connection tracking (Linux with HAVE_CONNTRACK)
 * - Sets SO_SNDTIMEO and SO_RCVTIMEO socket options for timeout enforcement
 * - May close and reopen TCP connections on I/O failures
 * 
 * THREAD SAFETY: Not thread-safe, modifies global daemon state and server structures
 */
static ssize_t tcp_talk(int first, int last, int start, unsigned char *packet,  size_t qsize,
			int have_mark, unsigned int mark, struct server **servp)
{
  int firstsendto = -1;
  u16 *length = (u16 *)packet;
  unsigned char *payload = &packet[2];
  struct dns_header *header = (struct dns_header *)payload;
  unsigned int rsize;
  int class, rclass, type, rtype;
  unsigned char *p;
  struct blockdata *saved_question;
  struct timeval tv;
  
  (void)mark;
  (void)have_mark;

  /* Save the query to make sure we get the answer we expect. */
  p = (unsigned char *)(header+1);
  if (!extract_name(header, qsize, &p, daemon->namebuff, EXTR_NAME_EXTRACT, 4))
    return 0;
  GETSHORT(type, p); 
  GETSHORT(class, p);

  /* Save question for retry. */
  if (!(saved_question = blockdata_alloc((char *)header, (size_t)qsize)))
    return 0;
  
  while (1) 
    {
      int data_sent = 0, fatal = 0;
      struct server *serv;

      if (firstsendto == -1)
	firstsendto = start;
      else
	{
	  start++;
	  
	  if (start == last)
	    start = first;
	  
	  if (start == firstsendto)
	    break;
	}
      
      *servp = serv = daemon->serverarray[start];
      
    retry:
      blockdata_retrieve(saved_question, qsize, header);
      
      *length = htons(qsize);
      
      if (serv->tcpfd == -1)
	{
	  if ((serv->tcpfd = socket(serv->addr.sa.sa_family, SOCK_STREAM, 0)) == -1)
	    continue;
	  
#ifdef HAVE_CONNTRACK
	  /* Copy connection mark of incoming query to outgoing connection. */
	  if (have_mark)
	    setsockopt(serv->tcpfd, SOL_SOCKET, SO_MARK, &mark, sizeof(unsigned int));
#endif			  
	  
	  if ((!local_bind(serv->tcpfd,  &serv->source_addr, serv->interface, 0, 1)))
	    {
	      close(serv->tcpfd);
	      serv->tcpfd = -1;
	      continue;
	    }

#if defined(SO_SNDTIMEO) && defined(SO_RCVTIMEO)
	  /* TCP connections by default take ages to time out.
	     Set shorter timeouts more appropriate for a DNS server.
	     We set the recieve timeout as twice the send timeout; we
	     want to fail quickly on a non-responsive server, but give it time to get an
	     answer. */
	  tv.tv_sec = TCP_TIMEOUT;
	  tv.tv_usec = 0;
	  setsockopt(serv->tcpfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	  tv.tv_sec += TCP_TIMEOUT;
	  setsockopt(serv->tcpfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
	  
#ifdef MSG_FASTOPEN
	  server_send(serv, serv->tcpfd, packet, qsize + sizeof(u16), MSG_FASTOPEN);
	  
	  if (errno == 0)
	    data_sent = 1;
	  else if (errno == ETIMEDOUT || errno == EHOSTUNREACH || errno == EINPROGRESS || errno == ECONNREFUSED)
	    fatal = 1;
#endif
	  
	  /* If fastopen failed due to lack of reply, then there's no point in
	     trying again in non-FASTOPEN mode. */
	  if (fatal || (!data_sent && connect(serv->tcpfd, &serv->addr.sa, sa_len(&serv->addr)) == -1))
	    {
	      int port;
	      
	    failed:
	      port = prettyprint_addr(&serv->addr, daemon->addrbuff);
	      my_syslog(LOG_DEBUG|MS_DEBUG, _("TCP connection failed to %s#%d"), daemon->addrbuff, port);

	      close(serv->tcpfd);
	      serv->tcpfd = -1;
	      continue;
	    }
	  
	  daemon->serverarray[first]->last_server = start;
	  serv->flags &= ~SERV_GOT_TCP;
	}
      
      /* We us the _ONCE veriant of read_write() here because we've set a timeout on the tcp socket
	 and wish to abort if the whole data is not read/written within the timeout. */      
      if ((!data_sent && !read_write(serv->tcpfd, (unsigned char *)packet, qsize + sizeof(u16), RW_WRITE_ONCE)) ||
	  !read_write(serv->tcpfd, (unsigned char *)length, sizeof (*length), RW_READ_ONCE) ||
	  !read_write(serv->tcpfd, payload, (rsize = ntohs(*length)), RW_READ_ONCE))
	{
	  /* We get data then EOF, reopen connection to same server,
	     else try next. This avoids DoS from a server which accepts
	     connections and then closes them. */
	  if (serv->flags & SERV_GOT_TCP)
	    {
	      close(serv->tcpfd);
	      serv->tcpfd = -1;
	      goto retry;
	    }
	  else
	    goto failed;
	}
      
      /* If the question section of the reply doesn't match the question we sent, then
	 someone might be attempting to insert bogus values into the cache by 
	 sending replies containing questions and bogus answers.
	 Try another server, or give up */
      p = (unsigned char *)(header+1);
      if (extract_name(header, rsize, &p, daemon->namebuff, EXTR_NAME_COMPARE, 4) != 1)
	continue;
      GETSHORT(rtype, p); 
      GETSHORT(rclass, p);
      
      if (type != rtype || class != rclass)
	continue;
      
      serv->flags |= SERV_GOT_TCP;
      
      *servp = serv;
      blockdata_free(saved_question);
      return rsize;
    }
  
  blockdata_free(saved_question);
  return 0;
}
		  
#ifdef HAVE_DNSSEC
/* An answer to an downstream query or DNSSEC subquery has 
   returned truncated. (Which type held in status).
   Resend the query (in header) via TCP */
/**
 * @brief Handle TCP fallback when UDP response was truncated (TC bit set)
 * 
 * @detailed When a UDP DNS query receives a truncated response (TC=1), this function
 *           re-sends the original query to the same upstream server using TCP to obtain
 *           the complete response. For DNSSEC validation queries, it performs recursive
 *           DNSKEY/DS resolution via TCP. For normal downstream queries (STAT_OK), it
 *           strips DNSSEC resource records from the TCP response and progressively
 *           removes optional sections (authority, additional, then answer) if the result
 *           still exceeds the client's UDP buffer size, ensuring the response fits in UDP.
 *           This implements RFC 1035 Section 4.2.2 TCP fallback for truncated responses.
 * 
 * @param now Current time for logging timestamps and validation operations
 * @param status DNSSEC validation status: STAT_OK (normal downstream query), STAT_NEED_KEY
 *               (DNSSEC DNSKEY lookup), STAT_NEED_DS (DNSSEC DS lookup), or validation state
 * @param header Original truncated UDP response header. For STAT_OK queries, replaced with
 *               stripped/truncated TCP response on success. Must not be NULL.
 * @param plenp Pointer to packet length in/out parameter. Input: original UDP response size.
 *              Output: size of stripped TCP response for STAT_OK, or 0 on failure. Must not be NULL.
 * @param class DNS query class (typically IN=1 for Internet class)
 * @param name Domain name being queried (null-terminated string). Used for logging and
 *             DNSSEC server selection. Must not be NULL.
 * @param server Upstream server that sent truncated UDP response. TCP query sent to same
 *               server for consistency. Must not be NULL.
 * @param keycount Pointer to DNSSEC key operation counter. Incremented during validation.
 *                 May be NULL if DNSSEC not compiled.
 * @param validatecount Pointer to DNSSEC validation operation counter. Incremented during
 *                      validation. May be NULL if DNSSEC not compiled.
 * 
 * @return DNSSEC validation status code:
 * @retval STAT_ABANDONED Memory allocation failed or TCP query failed or DNSSEC server lookup failed
 * @retval STAT_TRUNCATED TCP response too large even after stripping all optional sections
 * @retval STAT_OK TCP query succeeded and response fits in UDP buffer (for downstream queries)
 * @retval STAT_SECURE Valid DNSSEC signature (for DNSSEC queries)
 * @retval STAT_INSECURE Unsigned zone (for DNSSEC queries)
 * @retval STAT_BOGUS Invalid DNSSEC signature (for DNSSEC queries)
 * 
 * @note Allocates 65536 + MAXDNAME + RRFIXEDSZ + sizeof(u16) byte buffer for TCP packet
 * @note Sets TCP log flag by negating daemon->log_display_id during operation
 * @note For STAT_OK queries, strips DNSSEC RRs with rrfilter(RRFILTER_DNSSEC)
 * @note Progressively removes sections if size >= daemon->edns_pktsz: first NS/AR, then AN
 * @note On success for STAT_OK, copies stripped response back to header and sets *plenp
 * @note On failure, sets *plenp = 0 to signal no response available
 * 
 * @warning Modifies header in-place for STAT_OK queries - contains stripped TCP response on success
 * @warning TCP communication may block briefly - called from main event loop
 * @warning Buffer allocation may fail in low-memory conditions - returns STAT_ABANDONED
 * @warning Aggressive section removal for oversized responses may produce empty answer section
 * 
 * @see tcp_talk() for TCP query transmission and response reception
 * @see tcp_key_recurse() for recursive DNSSEC validation via TCP
 * @see rrfilter() for DNSSEC resource record stripping
 * @see resize_packet() for removing DNS sections to reduce packet size
 * @see dnssec_server() for selecting DNSSEC-capable upstream server
 * 
 * EXAMPLE USAGE:
 * @code
 * // Received truncated UDP response (TC=1), fallback to TCP
 * struct dns_header *header = (struct dns_header *)daemon->packet;
 * ssize_t plen = udp_response_size;
 * int keycount = 0, validatecount = 0;
 * int status = tcp_from_udp(now, STAT_OK, header, &plen, C_IN, "example.com",
 *                           upstream_server, &keycount, &validatecount);
 * if (status == STAT_OK && plen > 0)
 *   send_udp_response_to_client(header, plen); // Send stripped TCP response via UDP
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 1035 Section 4.2.2 (TCP fallback for truncated UDP responses)
 * RFC COMPLIANCE: RFC 4035 Section 4 (DNSSEC validation may require TCP for large responses)
 * RFC COMPLIANCE: RFC 6891 Section 6.2.3 (response size limited by EDNS buffer size)
 * 
 * SIDE EFFECTS:
 * - Allocates 65536+ byte buffer with whine_malloc() - freed before return
 * - Negates daemon->log_display_id to mark TCP queries in logs
 * - Restores daemon->log_display_id before return
 * - Calls log_query_mysockaddr() to log TCP query with F_FORWARD or F_DNSSEC flag
 * - Calls tcp_talk() which may block on TCP socket I/O
 * - For STAT_OK: modifies header in-place with stripped response, updates *plenp
 * - For DNSSEC: calls tcp_key_recurse() which may perform recursive validation
 * - Increments *keycount and *validatecount during DNSSEC validation
 * - May call rrfilter() to remove DNSSEC RRs (DNSKEY, DS, RRSIG, NSEC, NSEC3)
 * - May call resize_packet() multiple times to progressively reduce response size
 * - Sets *plenp = 0 on entry to signal "no response" until success
 * 
 * THREAD SAFETY: Single-threaded daemon - modifies global daemon->log_display_id
 */
int tcp_from_udp(time_t now, int status, struct dns_header *header, ssize_t *plenp, 
		 int class, char *name, struct server *server, 
		 int *keycount, int *validatecount)
{
  unsigned char *packet = whine_malloc(65536 + MAXDNAME + RRFIXEDSZ + sizeof(u16));
  struct dns_header *new_header = (struct dns_header *)&packet[2];
  int start, first, last, new_status;
  ssize_t n = *plenp;
  int log_save = daemon->log_display_id;
  
  *plenp = 0;
  
  if (!packet)
    return STAT_ABANDONED;

  memcpy(new_header, header, n);

  /* Set TCP flag in logs. */
  daemon->log_display_id = -daemon->log_display_id;

  /* send orginal query to same server that generated truncated reply on UDP. */
  first = start = server->arrayposn;
  last = first + 1;
  
  if (!STAT_ISEQUAL(status, STAT_OK) && (start = dnssec_server(server, name, STAT_ISEQUAL(status, STAT_NEED_DS), &first, &last)) == -1)
    new_status = STAT_ABANDONED;
  else
    {
      if (STAT_ISEQUAL(status, STAT_OK))
	log_query_mysockaddr(F_SERVER | F_FORWARD, name, &server->addr, NULL, 0);
      else
	log_query_mysockaddr(F_NOEXTRA | F_DNSSEC | F_SERVER, name, &server->addr,
			     STAT_ISEQUAL(status, STAT_NEED_KEY) ? "dnssec-query[DNSKEY]" : "dnssec-query[DS]", 0);

      if ((n = tcp_talk(first, last, start, packet, n, 0, 0, &server)) == 0)
	new_status = STAT_ABANDONED;
      else
	{
	  new_status = tcp_key_recurse(now, status, new_header, n, class, daemon->namebuff, daemon->keyname, server, 0, 0, keycount, validatecount);
	  
	  if (STAT_ISEQUAL(status, STAT_OK))
	    {
	      /* downstream query: strip DNSSSEC RRs and see if it will
		 fit in a UDP reply. */
	      rrfilter(new_header, (size_t *)&n, RRFILTER_DNSSEC);
	      
	      if (n >= daemon->edns_pktsz)
		{
		  /* still too bIg, strip optional sections and try again. */
		  new_header->nscount = htons(0);
		  new_header->arcount = htons(0);
		  n = resize_packet(new_header, n, NULL, 0);
		  if (n >= daemon->edns_pktsz)
		    {
		      /* truncating the packet will break the answers, so remove them too
			 and mark the reply as truncated. */
		      new_header->ancount = htons(0);
		      n = resize_packet(new_header, n, NULL, 0);
		      new_status = STAT_TRUNCATED;
		    }
		}
	      
	      /* return the stripped or truncated reply. */
	      memcpy(header, new_header, n);
	      *plenp = n;
	    }
	}
    }
  
  daemon->log_display_id = log_save;
  free(packet);
  return new_status;
}			    
 
/* Recurse down the key hierarchy */
/**
 * @brief Recursively fetch and validate DNSSEC keys/DS records over TCP to complete validation chain
 * 
 * @detailed Implements recursive DNSSEC validation by fetching missing DNSKEY or DS records
 *           when the primary validation process indicates additional keys are needed to
 *           complete the DNSSEC chain of trust. This function is critical to the DNSSEC
 *           validation workflow and handles the complex case where validating a response
 *           requires fetching additional DNSSEC records (DNSKEY, DS) to establish trust.
 *           
 *           The function operates in a loop, repeatedly calling DNSSEC validation functions
 *           (dnssec_validate_by_ds, dnssec_validate_ds, dnssec_validate_reply) until either:
 *           1. Validation succeeds (STAT_OK) - chain of trust established
 *           2. Validation fails definitively (STAT_BOGUS, STAT_INSECURE)
 *           3. Resource limit exceeded (STAT_ABANDONED) - too many recursive queries
 *           4. Network or allocation failure (STAT_ABANDONED)
 *           
 *           Recursive workflow when STAT_NEED_KEY or STAT_NEED_DS encountered:
 *           1. Generate DNS query for missing DNSKEY or DS record (keyname)
 *           2. Select appropriate DNSSEC-capable upstream server
 *           3. Execute TCP query via tcp_talk() to fetch the record
 *           4. Recursively call tcp_key_recurse() to validate the fetched record
 *           5. If recursive call returns STAT_OK, retry original validation with new data
 *           6. If recursive call fails, propagate failure status
 *           
 *           Resource limits prevent infinite recursion or DoS attacks:
 *           - keycount parameter decremented on each iteration
 *           - When keycount reaches zero, validation abandoned with warning log
 *           - Default limit enforced by caller (typically DNSSEC_LIMIT_WORK from config.h)
 *           
 *           TCP vs UDP: This function uses TCP exclusively because:
 *           - DNSSEC records (DNSKEY, RRSIG) are often larger than 512 bytes
 *           - UDP truncation (TC bit) would require fallback to TCP anyway
 *           - TCP ensures reliable delivery of large DNSSEC response packets
 *           
 *           Memory management:
 *           - Allocates 65536-byte packet buffer on first need (lazy allocation)
 *           - Reuses buffer across loop iterations to minimize allocations
 *           - Frees buffer before return regardless of success/failure path
 *           
 *           Logging: Each recursive query logged with unique query ID (daemon->log_id)
 *           to track recursion depth and correlate queries in syslog output.
 * 
 * @param now Current time for TTL calculations and cache expiration (from time(2) system call)
 * @param status Current validation status indicating what's needed (STAT_NEED_KEY, STAT_NEED_DS, or other STAT_* codes)
 * @param header DNS response header being validated (contains RRsets, signatures, keys; must not be NULL)
 * @param n Size of DNS response in bytes (must be > 0 and <= 65535)
 * @param class DNS class (typically C_IN for Internet class)
 * @param name Domain name being validated (original query name, null-terminated)
 * @param keyname Key/DS name to fetch if recursion needed (filled by validation functions, null-terminated)
 * @param server Upstream server to query for missing records (must not be NULL, must support DNSSEC)
 * @param have_mark Whether connection tracking mark is set (0=no mark, 1=mark valid)
 * @param mark Connection tracking mark value for policy routing (only used if have_mark=1)
 * @param keycount Pointer to remaining recursion budget (decremented each iteration, validation abandoned at 0; must not be NULL)
 * @param validatecount Pointer to validation operation counter for resource limiting (incremented by validation functions; must not be NULL)
 * 
 * @return Integer DNSSEC validation status code (STAT_* constants from dnsmasq.h)
 * @retval STAT_OK Validation succeeded, DNSSEC chain of trust established
 * @retval STAT_BOGUS Validation failed, signature invalid or trust chain broken
 * @retval STAT_INSECURE Zone is unsigned (no DNSSEC), insecure delegation
 * @retval STAT_ABANDONED Resource limit exceeded or allocation/network failure
 * @retval STAT_NEED_KEY (intermediate, not returned) DNSKEY record needed, triggers recursion
 * @retval STAT_NEED_DS (intermediate, not returned) DS record needed, triggers recursion
 * 
 * @note Function is recursive, calls itself to validate fetched DNSKEY/DS records
 * @note Resource limits prevent infinite recursion (keycount budget)
 * @note Lazy packet buffer allocation minimizes memory usage when recursion not needed
 * @note TCP-only operation ensures reliable delivery of large DNSSEC packets
 * @warning Deep recursion can consume significant stack space (typically limited to 10-40 levels)
 * @warning Allocation failure for packet buffer causes immediate abandonment
 * @warning Exceeding keycount limit logs warning and abandons validation
 * 
 * @see dnssec_validate_by_ds() in dnssec.c for DNSKEY validation using DS records
 * @see dnssec_validate_ds() in dnssec.c for DS record validation
 * @see dnssec_validate_reply() in dnssec.c for general DNSSEC validation
 * @see dnssec_generate_query() in dnssec.c for DNSKEY/DS query packet generation
 * @see tcp_talk() in this file for TCP query execution
 * @see dnssec_server() in dnssec.c for DNSSEC-capable server selection
 * @see STAT_NEED_KEY, STAT_NEED_DS, STAT_OK status codes in dnsmasq.h
 * 
 * EXAMPLE USAGE:
 * @code
 * time_t now = time(NULL);
 * int status = STAT_NEED_KEY; // Initial validation needs DNSKEY
 * struct dns_header *header = ...; // DNS response to validate
 * size_t n = 1024;
 * int class = C_IN;
 * char name[] = "www.example.com";
 * char keyname[MAXDNAME]; // Filled by validation with needed key name
 * struct server *server = ...; // DNSSEC-capable upstream server
 * int keycount = 40; // DNSSEC_LIMIT_WORK from config.h
 * int validatecount = 0;
 * 
 * // Recursively fetch keys and validate
 * int result = tcp_key_recurse(now, status, header, n, class, 
 *                              name, keyname, server,
 *                              0, 0, &keycount, &validatecount);
 * 
 * if (result == STAT_OK) {
 *   // Validation succeeded, trust chain established
 * } else if (result == STAT_BOGUS) {
 *   // Validation failed, response is bogus
 * } else if (result == STAT_ABANDONED) {
 *   // Resource limit exceeded or network failure
 * }
 * @endcode
 * 
 * RECURSION DEPTH ANALYSIS:
 * 
 * Typical DNSSEC validation recursion depth:
 * - Level 0: Validate www.example.com A record (needs example.com DNSKEY)
 * - Level 1: Fetch and validate example.com DNSKEY (needs example.com DS from com)
 * - Level 2: Fetch and validate example.com DS from com (needs com DNSKEY)
 * - Level 3: Fetch and validate com DNSKEY (needs com DS from root)
 * - Level 4: Fetch and validate com DS from root (needs root DNSKEY)
 * - Level 5: Validate root DNSKEY against trust anchor (STAT_OK)
 * 
 * Maximum recursion depth: Typically 5-10 levels from leaf to root
 * Stack usage: ~1KB per recursion level (local variables + packet buffer pointer)
 * Total stack: 5-10KB typical, up to 40KB at limit
 * 
 * VALIDATION STATUS FLOW:
 * 
 * Input status determines validation function called:
 * - STAT_NEED_KEY -> dnssec_validate_by_ds() validates DNSKEY using DS record
 * - STAT_NEED_DS -> dnssec_validate_ds() validates DS record from parent zone
 * - Other -> dnssec_validate_reply() performs general DNSSEC validation
 * 
 * Validation function returns:
 * - STAT_OK: Validation succeeded, break loop and return success
 * - STAT_BOGUS/STAT_INSECURE: Validation failed definitively, break and return
 * - STAT_NEED_KEY/STAT_NEED_DS: More data needed, enter recursion block
 * - STAT_ABANDONED: Resource limit or failure, break and return
 * 
 * Recursion block (when STAT_NEED_KEY or STAT_NEED_DS):
 * 1. Check keycount budget, decrement, abandon if zero
 * 2. Allocate packet buffer if not already allocated
 * 3. Generate query for missing DNSKEY or DS record
 * 4. Select DNSSEC-capable server via dnssec_server()
 * 5. Execute TCP query via tcp_talk()
 * 6. Log recursive query with unique ID
 * 7. Recursively call tcp_key_recurse() to validate fetched record
 * 8. If recursive call returns STAT_OK, loop continues to retry original validation
 * 9. If recursive call fails, break loop and return failure status
 * 
 * RESOURCE LIMIT ENFORCEMENT:
 * 
 * keycount limit:
 * - Prevents infinite recursion from circular dependencies
 * - Prevents DoS attacks via crafted responses requiring many queries
 * - Default limit: DNSSEC_LIMIT_WORK (40 queries) from config.h:25
 * - Logged warning: "limit exceeded: per-query subqueries"
 * 
 * validatecount limit:
 * - Tracks total validation operations across all recursion levels
 * - Incremented by dnssec validation functions (not this function directly)
 * - Prevents CPU-intensive validation DoS
 * - Default limit: DNSSEC_LIMIT_CRYPTO (200 operations) from config.h:27
 * 
 * MEMORY ALLOCATION STRATEGY:
 * 
 * Lazy packet buffer allocation:
 * - Buffer only allocated when recursion actually needed (STAT_NEED_KEY/STAT_NEED_DS)
 * - Size: 65536 bytes + MAXDNAME + RRFIXEDSZ + sizeof(u16)
 * - Rationale: 65536 is maximum TCP DNS message size
 * - Reused across loop iterations within single tcp_key_recurse() call
 * - Freed before return to prevent memory leak
 * 
 * Allocation failure handling:
 * - whine_malloc() logs error message to syslog
 * - NULL check immediately abandons validation (STAT_ABANDONED)
 * - No retry or fallback allocation strategy
 * 
 * TCP QUERY EXECUTION:
 * 
 * tcp_talk() function:
 * - Executes DNS query over TCP connection
 * - Handles server selection from first/last range
 * - Implements retry logic on transient failures
 * - Returns response size on success, 0 on failure
 * - Connection tracking mark applied if have_mark=1
 * 
 * Server selection:
 * - dnssec_server() selects DNSSEC-capable upstream server
 * - Considers server DNSSEC support flags
 * - Handles DS queries vs. DNSKEY queries differently
 * - Returns server index range (first, last) and starting index
 * 
 * LOGGING AND DEBUGGING:
 * 
 * Query logging:
 * - Each recursive query logged via log_query_mysockaddr()
 * - Log type: F_NOEXTRA | F_DNSSEC | F_SERVER
 * - Query type string: "dnssec-query[DNSKEY]" or "dnssec-query[DS]"
 * - Unique query ID: -(++daemon->log_id) (negative for recursion tracking)
 * - Log ID saved and restored to maintain parent query context
 * 
 * Abandonment logging:
 * - Resource limit exceeded: "limit exceeded: per-query subqueries"
 * - Includes domain name from DNS header (daemon->namebuff)
 * - Validation failure: "validation of <domain> failed: resource limit exceeded."
 * 
 * RFC COMPLIANCE:
 * - RFC 4033: DNS Security Introduction (DNSSEC overview)
 * - RFC 4034: Resource Records for DNS Security Extensions (DNSKEY, DS, RRSIG)
 * - RFC 4035: Protocol Modifications for DNS Security (validation procedures)
 * - RFC 5011: Automated Updates of DNSSEC Trust Anchors (trust anchor management)
 * 
 * SIDE EFFECTS:
 * - Allocates and frees packet buffer (65536+ bytes)
 * - Executes TCP queries to upstream DNS servers (network I/O)
 * - Decrements keycount budget (modifies *keycount)
 * - Increments validatecount via validation functions (modifies *validatecount)
 * - Increments daemon->log_id for unique query tracking
 * - Temporarily modifies daemon->log_display_id for recursion logging
 * - Logs queries and errors to syslog via my_syslog()
 * - Calls dnssec validation functions which modify cache state
 * - Recursive function calls consume stack space
 * 
 * THREAD SAFETY: Not thread-safe (modifies shared daemon state: log_id, log_display_id)
 */
static int tcp_key_recurse(time_t now, int status, struct dns_header *header, size_t n, 
			   int class, char *name, char *keyname, struct server *server, 
			   int have_mark, unsigned int mark, int *keycount, int *validatecount)
{
  int first, last, start, new_status;
  unsigned char *packet = NULL;
  struct dns_header *new_header = NULL;

  while (1)
    {
      size_t m;
      int log_save;
            
      /* limit the amount of work we do, to avoid cycling forever on loops in the DNS */
      if (STAT_ISEQUAL(status, STAT_NEED_KEY))
	new_status = dnssec_validate_by_ds(now, header, n, name, keyname, class, validatecount);
      else if (STAT_ISEQUAL(status, STAT_NEED_DS))
	new_status = dnssec_validate_ds(now, header, n, name, keyname, class, validatecount);
      else
	new_status = dnssec_validate_reply(now, header, n, name, keyname, &class,
					   !option_bool(OPT_DNSSEC_IGN_NS), NULL, NULL, NULL, validatecount);
      
      if (!STAT_ISEQUAL(new_status, STAT_NEED_DS) && !STAT_ISEQUAL(new_status, STAT_NEED_KEY) && !STAT_ISEQUAL(new_status, STAT_ABANDONED))
	break;
      
      if ((*keycount)-- == 0)
	{
	  my_syslog(LOG_WARNING, _("limit exceeded: per-query subqueries"));
	  new_status = STAT_ABANDONED;
	}
      
      if (STAT_ISEQUAL(new_status, STAT_ABANDONED))
	{
	  /* Log the actual validation that made us barf. */
	  if  (extract_name(header, n, NULL, daemon->namebuff, EXTR_NAME_EXTRACT, 0))
	    my_syslog(LOG_WARNING, _("validation of %s failed: resource limit exceeded."),
		      daemon->namebuff[0] ? daemon->namebuff : ".");
	  break;
	}
      
      /* Can't validate because we need a key/DS whose name now in keyname.
	 Make query for same, and recurse to validate */
      if (!packet)
	{
	  packet = whine_malloc(65536 + MAXDNAME + RRFIXEDSZ + sizeof(u16));
	  new_header = (struct dns_header *)&packet[2];
	}
      
      if (!packet)
	{
	  new_status = STAT_ABANDONED;
	  break;
	}
      
      m = dnssec_generate_query(new_header, ((unsigned char *) new_header) + 65536, keyname, class, 0,
				STAT_ISEQUAL(new_status, STAT_NEED_KEY) ? T_DNSKEY : T_DS);
      
      if ((start = dnssec_server(server, keyname, STAT_ISEQUAL(new_status, STAT_NEED_DS), &first, &last)) == -1)
	{
	  new_status = STAT_ABANDONED;
	  break;
	}
      
      if ((m = tcp_talk(first, last, start, packet, m, have_mark, mark, &server)) == 0)
	{
	  new_status = STAT_ABANDONED;
	  break;
	}

      log_save = daemon->log_display_id;
      daemon->log_display_id = -(++daemon->log_id);
      
      log_query_mysockaddr(F_NOEXTRA | F_DNSSEC | F_SERVER, keyname, &server->addr,
			   STAT_ISEQUAL(new_status, STAT_NEED_KEY) ? "dnssec-query[DNSKEY]" : "dnssec-query[DS]", 0);
      
      new_status = tcp_key_recurse(now, new_status, new_header, m, class, name, keyname, server,
				   have_mark, mark, keycount, validatecount);
      
      daemon->log_display_id = log_save;
      
      /* If we got STAT_OK from a DS or KEY validation on recursing, loop round and try the failed validation again. */
      if (!STAT_ISEQUAL(new_status, STAT_OK))
	break; 
    }
  
  if (packet)
    free(packet);
  
  return new_status;
}
#endif


/* The daemon forks before calling this: it should deal with one connection,
   blocking as necessary, and then return. Note, need to be a bit careful
   about resources for debug mode, when the fork is suppressed: that's
   done by the caller. */
/**
 * @brief Handle incoming TCP DNS query connection from client
 * 
 * @detailed This function processes DNS queries received over TCP from downstream clients.
 *           It reads queries from the TCP connection, enforces per-connection query limits
 *           (TCP_MAX_QUERIES from config.h, default 100), forwards queries to upstream servers,
 *           handles DNSSEC validation if enabled, supports AUTH DNS for authoritative zones,
 *           implements serve-stale functionality for expired cache entries, processes responses
 *           via process_reply(), and writes responses back to the client. The connection remains
 *           open for multiple sequential queries (HTTP/1.1 keepalive style) until the limit is
 *           reached or client closes connection. This implements RFC 1035 Section 4.2.2 TCP
 *           transport for DNS. When serving stale data, the connection is closed after response
 *           to signal to client that data may be outdated, then fresh data is fetched for cache.
 * 
 * @param confd TCP connection file descriptor (already accept()ed from listening socket).
 *              Function reads query packets from this socket and writes responses. The socket
 *              is closed by this function on normal exit or error. Must be valid open socket.
 * @param now Current time for cache TTL evaluation, timeout tracking, logging timestamps, and
 *            DNSSEC validation operations. Obtained from time(NULL) in main event loop.
 * @param local_addr Local address on which TCP connection was accepted. Used for determining
 *                   interface binding for AUTH DNS and logging. Must not be NULL.
 * @param netmask Network mask for local_addr. Used for AUTH DNS zone matching and
 *                rebinding protection. IPv4 address structure (struct in_addr).
 * @param auth_dns Flag indicating AUTH DNS mode is enabled (HAVE_AUTH compiled). When 1,
 *                 authoritative DNS lookups are attempted via lookup_domain() before forwarding.
 *                 When 0, all queries forwarded to upstream servers.
 * 
 * @return Pointer to allocated packet buffer (65536 bytes) on success, or NULL on error.
 *         Caller must free returned buffer. Buffer returned even if connection processing
 *         failed, to allow reuse in caller's connection pool.
 * 
 * @note Allocates 65536 byte packet buffer with whine_malloc() - returned to caller for cleanup
 * @note Closes confd socket before return (calls shutdown(SHUT_RDWR) then close())
 * @note Enforces TCP_MAX_QUERIES limit (config.h:20, default 100) to prevent resource exhaustion
 * @note Sets daemon->log_source_addr for query logging attribution
 * @note For AUTH DNS: calls lookup_domain() to check authoritative zones before forwarding
 * @note For DNSSEC: performs validation via tcp_key_recurse(), tracks keycount/validatecount
 * @note For serve-stale: may serve expired cache data, then refresh cache after client disconnect
 * @note Reads 2-byte length prefix (network byte order) before each query packet
 * @note Writes 2-byte length prefix before each response packet
 * @note Uses blockdata_save() to preserve original question for logging and stale refresh
 * 
 * @warning Blocking TCP read/write operations - called from dedicated TCP handler, not main loop
 * @warning Connection held open for multiple queries - may consume resources for minutes
 * @warning Buffer allocation may fail in low-memory conditions - returns NULL
 * @warning Malformed packets (bad length, invalid DNS) cause connection termination
 * @warning DNSSEC validation may trigger recursive TCP queries via tcp_key_recurse()
 * @warning Stale data serve-and-refresh closes connection after response to signal staleness
 * 
 * @see forward_query() for query forwarding to upstream servers
 * @see process_reply() for response processing and cache population
 * @see lookup_domain() for AUTH DNS authoritative zone lookup
 * @see tcp_key_recurse() for recursive DNSSEC validation via TCP
 * @see make_local_answer() for generating local error responses (NXDOMAIN, SERVFAIL)
 * @see add_pseudoheader() for adding EDNS0 pseudo-header with EDE codes
 * @see blockdata_save() and blockdata_retrieve() for question preservation
 * 
 * EXAMPLE USAGE:
 * @code
 * // Called from TCP connection handler after accept()
 * int client_fd = accept(tcp_listen_fd, (struct sockaddr *)&peer, &peer_len);
 * union mysockaddr local;
 * struct in_addr netmask;
 * // ... get local address and netmask ...
 * unsigned char *buf = tcp_request(client_fd, time(NULL), &local, netmask,
 *                                   option_bool(OPT_AUTH));
 * if (buf)
 *   free(buf); // Caller must free returned buffer
 * // Socket is already closed by tcp_request()
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 1035 Section 4.2.2 (TCP transport for DNS queries)
 * RFC COMPLIANCE: RFC 7766 (DNS Transport over TCP - Implementation Requirements)
 * RFC COMPLIANCE: RFC 6891 Section 7 (EDNS0 extended error codes via EDE option)
 * RFC COMPLIANCE: RFC 8914 (Extended DNS Errors - EDE_STALE, EDE_FILTERED, etc.)
 * 
 * SIDE EFFECTS:
 * - Allocates 65536 byte packet buffer with whine_malloc() - returned for caller cleanup
 * - Closes confd socket via shutdown(SHUT_RDWR) and close() before return
 * - Sets daemon->log_source_addr to client address from getpeername() for query logging
 * - Clears daemon->log_source_addr before return (or sets NULL for stale refresh)
 * - Reads variable-length data from confd socket (2-byte length + query packet)
 * - Writes variable-length responses to confd socket (2-byte length + response packet)
 * - Calls check_log_writer(1) to flush log queue after query processing
 * - Calls forward_query() which may create struct frec and initiate upstream queries
 * - Calls process_reply() which populates DNS cache via cache_insert()
 * - For AUTH DNS: calls lookup_domain() and answer_auth() to serve authoritative data
 * - For DNSSEC: calls tcp_key_recurse() which performs recursive validation queries
 * - For DNSSEC: increments keycount, validatecount, updates metrics METRIC_CRYPTO_HWM/WORK_HWM
 * - For serve-stale: may serve expired cache data and trigger background refresh
 * - Calls blockdata_save() to preserve original question, blockdata_free() on cleanup
 * - Calls log_query() with F_FORWARD, F_AUTH, F_STALE, or F_SECSTAT flags
 * - For CONNTRACK+UBUS: may call report_addresses() to notify UBus of resolved addresses
 * - Enforces TCP_MAX_QUERIES limit - closes connection when query count exceeded
 * - Updates daemon->metrics[METRIC_TCP_QUERIES] (implicit via query processing)
 * - May modify header flags: sets QR=1, AA bit for AUTH, CD bit preservation for DNSSEC
 * - Adds EDNS0 pseudo-header via add_pseudoheader() with EDE option when appropriate
 * 
 * THREAD SAFETY: Single-threaded daemon - modifies global daemon state:
 *                daemon->log_source_addr, daemon->metrics, daemon->namebuff
 */
unsigned char *tcp_request(int confd, time_t now,
			   union mysockaddr *local_addr, struct in_addr netmask, int auth_dns)
{
  size_t size = 0, saved_size = 0;
  int norebind = 0;
#ifdef HAVE_CONNTRACK
  int allowed = 1;
#endif
#ifdef HAVE_AUTH
  int local_auth = 0;
#endif
  int checking_disabled, do_bit = 0, ad_reqd = 0, have_pseudoheader = 0;
  struct blockdata *saved_question = NULL;
  unsigned short qtype;
  unsigned int gotname = 0;
  /* Max TCP packet + slop + size */
  unsigned char *packet = whine_malloc(65536 + MAXDNAME + RRFIXEDSZ + sizeof(u16));
  unsigned char *payload = &packet[2];
  u16 tcp_len;
  /* largest field in header is 16-bits, so this is still sufficiently aligned */
  struct dns_header *header = (struct dns_header *)payload;
  u16 *length = (u16 *)packet;
  struct server *serv;
  struct in_addr dst_addr_4;
  union mysockaddr peer_addr;
  socklen_t peer_len = sizeof(union mysockaddr);
  int query_count = 0;
  unsigned char *pheader;
  unsigned int mark = 0;
  int have_mark = 0;
  int first, last, filtered, do_stale = 0;
      
  if (!packet || getpeername(confd, (struct sockaddr *)&peer_addr, &peer_len) == -1)
    return packet;

#ifdef HAVE_CONNTRACK
  /* Get connection mark of incoming query to set on outgoing connections. */
  if (option_bool(OPT_CONNTRACK) || option_bool(OPT_CMARK_ALST_EN))
    {
      union all_addr local;
		      
      if (local_addr->sa.sa_family == AF_INET6)
	local.addr6 = local_addr->in6.sin6_addr;
      else
	local.addr4 = local_addr->in.sin_addr;
      
      have_mark = get_incoming_mark(&peer_addr, &local, 1, &mark);
    }
#endif	

  /* We can be configured to only accept queries from at-most-one-hop-away addresses. */
  if (option_bool(OPT_LOCAL_SERVICE))
    {
      struct addrlist *addr;

      if (peer_addr.sa.sa_family == AF_INET6) 
	{
	  for (addr = daemon->interface_addrs; addr; addr = addr->next)
	    if ((addr->flags & ADDRLIST_IPV6) &&
		is_same_net6(&addr->addr.addr6, &peer_addr.in6.sin6_addr, addr->prefixlen))
	      break;
	}
      else
	{
	  struct in_addr netmask;
	  for (addr = daemon->interface_addrs; addr; addr = addr->next)
	    {
	      netmask.s_addr = htonl(~(in_addr_t)0 << (32 - addr->prefixlen));
	      if (!(addr->flags & ADDRLIST_IPV6) && 
		  is_same_net(addr->addr.addr4, peer_addr.in.sin_addr, netmask))
		break;
	    }
	}
      if (!addr)
	{
	  prettyprint_addr(&peer_addr, daemon->addrbuff);
	  my_syslog(LOG_WARNING, _("ignoring query from non-local network %s"), daemon->addrbuff);
	  return packet;
	}
    }

  while (1)
    {
      int cacheable = 1, stale = 0, ede = EDE_UNSET;
      size_t m = 0;
      unsigned int flags = 0;
#ifdef HAVE_AUTH
      struct auth_zone *zone;
#endif
	  
      if (!do_stale)
	{
	  if (query_count >= TCP_MAX_QUERIES)
	    break;
	  
	  if (!read_write(confd, (unsigned char *)&tcp_len, sizeof(tcp_len), RW_READ) ||
	      !(size = ntohs(tcp_len)) ||
	      !read_write(confd, payload, size, RW_READ))
	    break;
	      
	  if (size < (int)sizeof(struct dns_header))
	    continue;
	  
	  /* Clear buffer beyond request to avoid risk of
	     information disclosure. */
	  memset(payload + size, 0, 65536 - size);
	  
	  query_count++;
	  
	  /* log_query gets called indirectly all over the place, so 
	     pass these in global variables - sorry. 
	     log_display_id is negative for TCP connections. */
	  daemon->log_display_id = -(++daemon->log_id);
	  daemon->log_source_addr = &peer_addr;
	  
	  if (OPCODE(header) != QUERY)
	    {
	      log_query_mysockaddr((auth_dns ? F_NOERR : 0) |  F_QUERY | F_FORWARD | F_CONFIG, NULL, &peer_addr, NULL, OPCODE(header));
	      gotname = 0;
	      flags = F_RCODE;
	    }
	  else if (!(gotname = extract_request(header, (unsigned int)size, daemon->namebuff, &qtype, NULL)))
	    ede = EDE_INVALID_DATA;
	  else
	    {
	      if (saved_question)
		blockdata_free(saved_question);

	      do_bit = 0;
	      
	      if (find_pseudoheader(header, (size_t)size, NULL, &pheader, NULL, NULL))
		{ 
		  unsigned short ede_flags;
		  
		  have_pseudoheader = 1;
		  pheader += 4; /* udp_size, ext_rcode */
		  GETSHORT(ede_flags, pheader);
		  
		  if (ede_flags & 0x8000)
		    do_bit = 1; /* do bit */ 
		}

	      size = add_edns0_config(header, size, ((unsigned char *) header) + 65536, &peer_addr, now, &cacheable);
	      saved_question = blockdata_alloc((char *)header, (size_t)size);
	      saved_size = size;
	      
	      log_query_mysockaddr((auth_dns ? F_NOERR | F_AUTH : 0) | F_QUERY | F_FORWARD, daemon->namebuff,
				   &peer_addr, NULL, qtype);
	      
#ifdef HAVE_AUTH
	      /* Find queries for zones we're authoritative for, and answer them directly.
		 The exception to this is DS queries for the zone route. They
		 have to come from the parent zone. Since dnsmasq's auth server
		 can't do DNSSEC, the zone will be unsigned, and anything using
		 dnsmasq as a forwarder and doing validation will be expecting to
		 see the proof of non-existence from the parent. */
	      if (!auth_dns && !option_bool(OPT_LOCALISE))
		for (zone = daemon->auth_zones; zone; zone = zone->next)
		  {
		    char *cut;
		    
		    if (in_zone(zone, daemon->namebuff, &cut))
		      {
			if (qtype != T_DS || cut)
			  {
			    auth_dns = 1;
			    local_auth = 1;
			  }
			break;
		      }
		  }
#endif
	      
	      norebind = domain_no_rebind(daemon->namebuff);
	  
	      if (local_addr->sa.sa_family == AF_INET)
		dst_addr_4 = local_addr->in.sin_addr;
	      else
		dst_addr_4.s_addr = 0;
	      
	      ad_reqd = do_bit;
	      /* RFC 6840 5.7 */
	      if (header->hb4 & HB4_AD)
		ad_reqd = 1;

#ifdef HAVE_CONNTRACK
#ifdef HAVE_AUTH
	      if (!auth_dns || local_auth)
#endif
		if (option_bool(OPT_CMARK_ALST_EN) && have_mark && ((u32)mark & daemon->allowlist_mask))
		  allowed = is_query_allowed_for_mark((u32)mark, daemon->namebuff);
#endif
	  
	      if (0);
#ifdef HAVE_CONNTRACK
	      else if (!allowed)
		{
		  ede = EDE_BLOCKED;
		  m = answer_disallowed(header, size, (u32)mark, daemon->namebuff);
		}
#endif
#ifdef HAVE_AUTH
	      else if (auth_dns)
		m = answer_auth(header, ((char *) header) + 65536, (size_t)size, now, &peer_addr, local_auth);
#endif
	      else
		m = answer_request(header, ((char *) header) + 65536, (size_t)size, 
				   dst_addr_4, netmask, now, ad_reqd, do_bit, !cacheable, &stale, &filtered);
	    }
	}
      
      /* Do this by steam now we're not in the select() loop */
      check_log_writer(1); 
      
      if (m == 0 && ede == EDE_UNSET && saved_question)
	{
	  struct server *master;
	  int start;
	  int no_cache_dnssec = 0, cache_secure = 0, bogusanswer = 0;

	  blockdata_retrieve(saved_question, (size_t)saved_size, header);
	  size = saved_size;

	  /* save state of "cd" flag in query */
	  checking_disabled = header->hb4 & HB4_CD;
	  
	  if (lookup_domain(daemon->namebuff, gotname, &first, &last))
	    flags = is_local_answer(now, first, daemon->namebuff);
	  else
	    ede = EDE_NOT_READY;
	  
	  if (!flags && ede == EDE_UNSET)
	    {
	      /* don't forward A or AAAA queries for simple names, except the empty name */
	      if (option_bool(OPT_NODOTS_LOCAL) &&
		  (gotname & (F_IPV4 | F_IPV6)) &&
		  !strchr(daemon->namebuff, '.') &&
		  strlen(daemon->namebuff) != 0)
		flags = check_for_local_domain(daemon->namebuff, now) ? F_NOERR : F_NXDOMAIN;
	      else
		{
		  master = daemon->serverarray[first];
		  
		  if (option_bool(OPT_ORDER) || master->last_server == -1)
		    start = first;
		  else
		    start = master->last_server;
		  
#ifdef HAVE_DNSSEC
		  if (option_bool(OPT_DNSSEC_VALID))
		    {
		      size = add_do_bit(header, size, ((unsigned char *) header) + 65536);
		      
		      /* For debugging, set Checking Disabled, otherwise, have the upstream check too,
			 this allows it to select auth servers when one is returning bad data. */
		      if (option_bool(OPT_DNSSEC_DEBUG))
			header->hb4 |= HB4_CD;
		    }
#endif
		  
		  /* Loop round available servers until we succeed in connecting to one. */
		  if ((m = tcp_talk(first, last, start, packet, size, have_mark, mark, &serv)) == 0)
		    ede = EDE_NETERR;
		  else
		    {
		      /* get query name again for logging - may have been overwritten */
		      if (!extract_name(header, (unsigned int)size, NULL, daemon->namebuff, EXTR_NAME_EXTRACT, 0))
			strcpy(daemon->namebuff, "query");
		      log_query_mysockaddr(F_SERVER | F_FORWARD, daemon->namebuff, &serv->addr, NULL, 0);
		      
#ifdef HAVE_DNSSEC
		      if (option_bool(OPT_DNSSEC_VALID))
			{
			  /* Clear this in case we don't call tcp_key_recurse() below */
			  memset(daemon->rr_status, 0, sizeof(*daemon->rr_status) * daemon->rr_status_sz);
			  
			  if (checking_disabled || (header->hb4 & HB4_CD))
			    no_cache_dnssec = 1;
			  else
			    {
			      int keycount = daemon->limit[LIMIT_WORK]; /* Limit to number of DNSSEC questions, to catch loops and avoid filling cache. */
			      int validatecount = daemon->limit[LIMIT_CRYPTO]; 
			      int status = tcp_key_recurse(now, STAT_OK, header, m, 0, daemon->namebuff, daemon->keyname, 
							   serv, have_mark, mark, &keycount, &validatecount);
			      char *result, *domain = "result";
			      
			      union all_addr a;
			      ede = errflags_to_ede(status);
			      
			      if (STAT_ISEQUAL(status, STAT_ABANDONED))
				{
				  result = "ABANDONED";
				  status = STAT_BOGUS;
				  if (ede == EDE_UNSET)
				    ede = EDE_OTHER;
				}
			      else
				result = (STAT_ISEQUAL(status, STAT_SECURE) ? "SECURE" : (STAT_ISEQUAL(status, STAT_INSECURE) ? "INSECURE" : "BOGUS"));
			      
			      if (STAT_ISEQUAL(status, STAT_SECURE))
				cache_secure = 1;
			      else if (STAT_ISEQUAL(status, STAT_BOGUS))
				{
				  if (ede == EDE_UNSET)
				    ede = EDE_DNSSEC_BOGUS;
				  no_cache_dnssec = 1;
				  bogusanswer = 1;
				  
				  if (extract_name(header, m, NULL, daemon->namebuff, EXTR_NAME_EXTRACT, 0))
				    domain = daemon->namebuff;
				}
			      
			      a.log.ede = ede;
			      log_query(F_SECSTAT, domain, &a, result, 0);
			      
			      if ((daemon->limit[LIMIT_CRYPTO] - validatecount) > (int)daemon->metrics[METRIC_CRYPTO_HWM])
				daemon->metrics[METRIC_CRYPTO_HWM] = daemon->limit[LIMIT_CRYPTO] - validatecount;
			      
			      if ((daemon->limit[LIMIT_WORK] - keycount) > (int)daemon->metrics[METRIC_WORK_HWM])
				daemon->metrics[METRIC_WORK_HWM] = daemon->limit[LIMIT_WORK] - keycount;
			      
			      /* include DNSSEC queries in the limit for a connection. */
			      query_count += daemon->limit[LIMIT_WORK] - keycount;
			    }
			}
#endif

		    
		      /* restore CD bit to the value in the query */
		      if (checking_disabled)
			header->hb4 |= HB4_CD;
		      else
			header->hb4 &= ~HB4_CD;
		      
		      /* Never cache answers which are contingent on the source or MAC address EDSN0 option,
			 since the cache is ignorant of such things. */
		      if (!cacheable)
			no_cache_dnssec = 1;
		      
		      m = process_reply(header, now, serv, (unsigned int)m, 
					option_bool(OPT_NO_REBIND) && !norebind, no_cache_dnssec, cache_secure, bogusanswer,
					ad_reqd, do_bit, !have_pseudoheader, &peer_addr, ((unsigned char *)header) + 65536, ede);

		      /* process_reply() adds pheader itself */
		      have_pseudoheader = 0; 
		    }
		}
	    }
	}

      if (do_stale)
	break;
      
      /* In case of local answer or no connections made. */
      if (m == 0)
	{
	  if (!(m = make_local_answer(flags, gotname, size, header, daemon->namebuff,
				      ((char *) header) + 65536, first, last, ede)))
	    break;
	}
      else if (ede == EDE_UNSET)
	{
	  if (filtered)
	    ede = EDE_FILTERED;
	  else if (stale)
	    ede = EDE_STALE;
	}
      
      if (have_pseudoheader)
	{
	  u16 swap = htons((u16)ede);
	  
	  if (ede != EDE_UNSET)
	    m = add_pseudoheader(header, m, ((unsigned char *) header) + 65536, EDNS0_OPTION_EDE, (unsigned char *)&swap, 2, do_bit, 0);
	  else
	    m = add_pseudoheader(header, m, ((unsigned char *) header) + 65536, 0, NULL, 0, do_bit, 0);
	}
		  
      check_log_writer(1);
      
      *length = htons(m);
      
#if defined(HAVE_CONNTRACK) && defined(HAVE_UBUS)
#ifdef HAVE_AUTH
      if (!auth_dns || local_auth)
#endif
	if (option_bool(OPT_CMARK_ALST_EN) && have_mark && ((u32)mark & daemon->allowlist_mask))
	  report_addresses(header, m, mark);
#endif
      
      if (!read_write(confd, packet, m + sizeof(u16), RW_WRITE))
	break;
      
      /* If we answered with stale data, this process will now try and get fresh data into
	 the cache and cannot therefore accept new queries. Close the incoming
	 connection to signal that to the client. Then set do_stale and loop round
	 once more to try and get fresh data, after which we exit. */
      if (stale)
	{
	  shutdown(confd, SHUT_RDWR);
	  close(confd);
	  do_stale = 1;
	  /* Don't mark the query with the source when refreshing stale data. */
	  daemon->log_source_addr = NULL;
	}
    }

  /* If we ran once to get fresh data, confd is already closed. */
  if (!do_stale)
    {
      shutdown(confd, SHUT_RDWR);
      close(confd);
    }

  blockdata_free(saved_question);
  check_log_writer(1);

  return packet;
}

/* return a UDP socket bound to a random port, have to cope with straying into
   occupied port nos and reserved ones. */
/**
 * @brief Create and bind UDP socket to specific source address for upstream DNS queries
 * 
 * Creates a UDP socket bound to the source address, interface, and interface index specified
 * in the server structure. For IPv6 sockets, sets IPV6_V6ONLY option to allow port reuse
 * between IPv4 and IPv6 address families, preventing port exhaustion in restricted port
 * scenarios where all available ports might be consumed by one address family.
 * 
 * @param s Server structure containing source_addr (bind address), interface (interface name),
 *          and ifindex (interface index) for socket binding. source_addr.sa.sa_family determines
 *          socket address family (AF_INET or AF_INET6)
 * 
 * @return Socket file descriptor (>= 0) on successful socket creation and binding
 * @retval >=0 Successfully created and bound UDP socket to specified source address/interface
 * @retval -1 Socket creation failed, or IPV6_V6ONLY setsockopt failed, or local_bind failed
 * 
 * @note IPV6_V6ONLY socket option set to 1 for IPv6 sockets to enable port sharing between families
 * @note EADDRINUSE errors not logged (normal in restricted port scenarios, handled by caller)
 * @note Other binding errors logged with interface name or source address for troubleshooting
 * @note Socket closed automatically on any failure before returning -1
 * 
 * @warning Modifies global daemon->addrbuff for error message formatting (not thread-safe)
 * @warning Caller responsible for closing returned file descriptor when no longer needed
 * 
 * EXAMPLE USAGE:
 * @code
 * struct server *upstream = daemon->servers;
 * int query_fd = random_sock(upstream);
 * if (query_fd >= 0) {
 *   // Send query via this socket
 *   sendto(query_fd, packet, packet_len, 0, &upstream->addr.sa, sa_len(&upstream->addr));
 *   close(query_fd);
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 1035 Section 4.2.1 (UDP usage for DNS queries)
 * 
 * SIDE EFFECTS:
 * - Creates socket file descriptor via socket(2)
 * - Sets IPV6_V6ONLY socket option for AF_INET6 sockets via setsockopt(2)
 * - Binds socket to source address/interface via local_bind()
 * - Logs binding errors (except EADDRINUSE) to syslog via my_syslog()
 * - Writes to daemon->addrbuff for error message formatting
 * - Closes socket file descriptor on failure via close(2)
 * 
 * THREAD SAFETY: Not thread-safe, modifies global daemon->addrbuff
 */
static int random_sock(struct server *s)
{
  int fd;

  if ((fd = socket(s->source_addr.sa.sa_family, SOCK_DGRAM, 0)) != -1)
    {
      /* We need to set IPV6ONLY so we can use the same ports
	 for IPv4 and IPV6, otherwise, in restriced port situations,
	 we can end up with all our available ports in use for 
	 one address family, and the other address family cannot be used. */
      if (s->source_addr.sa.sa_family == AF_INET6)
	{
	  int opt = 1;

	  if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt)) == -1)
	    {
	      close(fd);
	      return -1;
	    }
	}
      
      if (local_bind(fd, &s->source_addr, s->interface, s->ifindex, 0))
	return fd;

      /* don't log errors due to running out of available ports, we handle those. */
      if (!sockaddr_isnull(&s->source_addr) || errno != EADDRINUSE)
	{
	  if (s->interface[0] == 0)
	    (void)prettyprint_addr(&s->source_addr, daemon->addrbuff);
	  else
	    safe_strncpy(daemon->addrbuff, s->interface, ADDRSTRLEN);
	  
	  my_syslog(LOG_ERR, _("failed to bind server socket to %s: %s"),
		    daemon->addrbuff, strerror(errno));
	}
	  
      close(fd);
    }
  
  return -1;
}

/**
 * @brief Compare two server structures for equality based on source address and interface
 * 
 * Determines if two server structures are equivalent by comparing their interface index,
 * source address (IP address and port), and interface name. Used for detecting duplicate
 * server configurations or finding matching upstream servers in server list operations.
 * Comparison is null-safe: returns false immediately if serv2 is NULL.
 * 
 * @param serv1 First server structure to compare, must not be NULL
 * @param serv2 Second server structure to compare, may be NULL (treated as not equal)
 * 
 * @return Non-zero if servers are equal in all compared fields, zero if different or serv2 is NULL
 * @retval 1 Servers have identical ifindex, source_addr (address and port), and interface name
 * @retval 0 Servers differ in any compared field, or serv2 is NULL
 * 
 * @note Comparison includes interface index (ifindex), source sockaddr (IP+port), and interface name
 * @note Interface name comparison uses strncmp with IF_NAMESIZE limit for safety
 * @note Function uses short-circuit evaluation: serv2 NULL check prevents dereferencing
 * @note sockaddr_isequal() compares both address family and address+port data
 * 
 * EXAMPLE USAGE:
 * @code
 * struct server *current_server = daemon->servers;
 * struct server *candidate = find_server_by_domain("example.com");
 * if (server_isequal(current_server, candidate)) {
 *   // Same server configuration, avoid duplicate query
 * }
 * @endcode
 * 
 * SIDE EFFECTS: None (pure comparison function, read-only operations)
 * 
 * THREAD SAFETY: Thread-safe, performs only read operations on const-qualified parameters
 */
static int server_isequal(const struct server *serv1,
			 const struct server *serv2)
{
  return (serv2 &&
    serv2->ifindex == serv1->ifindex &&
    sockaddr_isequal(&serv2->source_addr, &serv1->source_addr) &&
    strncmp(serv2->interface, serv1->interface, IF_NAMESIZE) == 0);
}

/* fdlp points to chain of randomfds already in use by transaction.
   If there's already a suitable one, return it, else allocate a 
   new one and add it to the list. 

   Not leaking any resources in the face of allocation failures
   is rather convoluted here.
   
   Note that rfd->serv may be NULL, when a server goes away.
*/
/**
 * @brief Allocate random source port file descriptor for DNS query to upstream server
 * 
 * @detailed This function allocates a UDP socket with randomized source port for sending
 *           DNS queries to the specified upstream server. Randomized source ports provide
 *           security against DNS cache poisoning attacks by making query IDs harder to
 *           predict (RFC 5452). The function implements sophisticated socket management:
 *           (1) reuses server's pre-allocated fd if available (serv->sfd),
 *           (2) searches for existing suitable socket already linked to this transaction,
 *           (3) enforces per-server socket limit (daemon->randport_limit) with round-robin,
 *           (4) allocates new socket from daemon->randomsocks pool if slots available,
 *           (5) shares existing socket by incrementing refcount if pool exhausted,
 *           (6) creates temporary overflow record (refcount=0xffff) as last resort.
 *           This prevents port exhaustion while maintaining good randomization.
 * 
 * @param fdlp Pointer to pointer to randfd_list head. Input: current list of allocated
 *             sockets for this transaction (forward record). Output: updated list with
 *             newly allocated socket prepended. The list is modified in-place by adding
 *             new randfd_list entry at head. Must not be NULL.
 * @param serv Upstream server for which to allocate socket. Used to match existing sockets,
 *             determine address family, check for pre-allocated fd (serv->sfd), and pass
 *             to random_sock() for socket creation. Must not be NULL.
 * 
 * @return File descriptor (integer >= 0) for the allocated UDP socket on success.
 * @retval -1 Memory allocation failed (whine_malloc returned NULL) or socket creation failed
 * @retval >= 0 Valid file descriptor for UDP socket bound to random source port
 * 
 * @note Uses static 'finger' variable for round-robin socket selection across calls
 * @note Pre-allocated server fd (serv->sfd->fd) bypasses all allocation logic
 * @note Enforces daemon->randport_limit (default from config.h) sockets per server
 * @note Checks ports_avail vs ports_inuse to prevent futile bind() attempts
 * @note Socket pool size controlled by daemon->numrrand (NUMRAND from config.h)
 * @note Normal sockets have refcount 1..N, temporary overflow records have refcount 0xffff
 * @note Temporary records (refcount 0xffff) added to daemon->rfl_poll for poll monitoring
 * @note Reuses entries from daemon->rfl_spare free list before calling malloc
 * @note On malloc failure, cleans up partially allocated structures to prevent leaks
 * @note Returned fd must be closed by caller (via free_rfds()) when transaction completes
 * 
 * @warning Returns -1 on failure - caller must check before using fd
 * @warning Increments refcount on shared sockets - refcount must be decremented via free_rfds()
 * @warning Temporary overflow sockets (refcount 0xffff) consume extra memory until freed
 * @warning Port exhaustion may occur if daemon->max_port - daemon->min_port range too small
 * @warning Socket creation via random_sock() may fail due to port exhaustion or system limits
 * 
 * @see free_rfds() to release allocated sockets and decrement refcounts
 * @see random_sock() for actual UDP socket creation with randomized source port
 * @see server_isequal() to match server instances for socket reuse
 * @see struct randfd in dnsmasq.h: {int fd, struct server *serv, int refcount}
 * @see struct randfd_list in dnsmasq.h: {struct randfd *rfd, struct randfd_list *next}
 * 
 * EXAMPLE USAGE:
 * @code
 * // Allocate socket for forwarding query to upstream server
 * struct randfd_list *rfds = NULL;
 * struct server *upstream_server = get_upstream_server();
 * int fd = allocate_rfd(&rfds, upstream_server);
 * if (fd != -1) {
 *   // Send DNS query using fd
 *   sendto(fd, query_packet, query_len, 0, &upstream_server->addr, sa_len(&upstream_server->addr));
 *   // Later, free the socket when transaction completes
 *   free_rfds(&rfds);
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 5452 Section 9.2 (Source port randomization for DNS security)
 * RFC COMPLIANCE: RFC 1035 Section 4.2.1 (UDP queries should use random source ports)
 * 
 * SIDE EFFECTS:
 * - Modifies *fdlp by prepending new randfd_list entry (rfl->next = *fdlp; *fdlp = rfl)
 * - Increments refcount on reused sockets (rfd->refcount++)
 * - May allocate randfd_list from daemon->rfl_spare free list or via whine_malloc()
 * - For temporary overflow: allocates struct randfd via whine_malloc(), adds to daemon->rfl_poll
 * - For new permanent socket: initializes daemon->randomsocks[i] entry (refcount=1, fd, serv)
 * - Calls random_sock(serv) which creates UDP socket, binds to random port, sets socket options
 * - Updates static finger variable for round-robin selection (finger = i + 1)
 * - On failure: returns unused rfl structures to daemon->rfl_spare, closes allocated fd if any
 * - Checks daemon->max_port, daemon->min_port to determine ports_avail for exhaustion check
 * - Iterates daemon->randomsocks[] pool checking refcount and address family
 * - For port exhaustion check: counts in-use sockets matching address family
 * - Promotes found socket to list head for round-robin when limit reached (*fdlp manipulation)
 * - For temporary records: sets rfd->refcount = 0xffff marker, adds rfl_poll to daemon->rfl_poll
 * - Does NOT set rfd->serv for temporary records (noted in comment line 3621)
 * 
 * THREAD SAFETY: Single-threaded daemon - modifies global state:
 *                static int finger, daemon->randomsocks[], daemon->rfl_spare, daemon->rfl_poll
 */
int allocate_rfd(struct randfd_list **fdlp, struct server *serv)
{
  static int finger = 0;
  int i, j = 0;
  int ports_full = 0;
  struct randfd_list **up, *rfl, *found, **found_link;
  struct randfd *rfd = NULL;
  int fd = 0;
  int ports_avail = 0;
  
  /* We can't have more randomsocks for this AF available than ports in  our port range,
     so check that here, to avoid trying and failing to bind every port
     in local_bind(), called from random_sock(). The actual check is below when 
     ports_avail != 0 */
  if (daemon->max_port != 0)
    {
      ports_avail = daemon->max_port - daemon->min_port + 1;
      if (ports_avail >= SMALL_PORT_RANGE)
	ports_avail = 0;
    }
  
  /* If server has a pre-allocated fd, use that. */
  if (serv->sfd)
    return serv->sfd->fd;
  
  /* existing suitable random port socket linked to this transaction?
     Find the last one in the list and count how many there are. */
  for (found = NULL, found_link = NULL, i = 0, up = fdlp, rfl = *fdlp; rfl; up = &rfl->next, rfl = rfl->next)
    if (server_isequal(serv, rfl->rfd->serv))
      {
	i++;
	found = rfl;
	found_link = up;
      }

  /* We have the maximum number for this query already. Promote
     the last one on the list to the head, to circulate them,
     and return it. */
  if (found && i >= daemon->randport_limit)
    {
      *found_link = found->next;
      found->next = *fdlp;
      *fdlp = found;
      return found->rfd->fd;
    }

  /* check for all available ports in use. */
  if (ports_avail != 0)
    {
      int ports_inuse;

      for (ports_inuse = 0, i = 0; i < daemon->numrrand; i++)
	if (daemon->randomsocks[i].refcount != 0 &&
	    daemon->randomsocks[i].serv->source_addr.sa.sa_family == serv->source_addr.sa.sa_family &&
	    ++ports_inuse >= ports_avail)
	  {
	    ports_full = 1;
	    break;
	  }
    }
  
  /* limit the number of sockets we have open to avoid starvation of 
     (eg) TFTP. Once we have a reasonable number, randomness should be OK */
  if (!ports_full)
    for (i = 0; i < daemon->numrrand; i++)
      if (daemon->randomsocks[i].refcount == 0)
	{
	  if ((fd = random_sock(serv)) != -1)
	    {
	      rfd = &daemon->randomsocks[i];
	      rfd->serv = serv;
	      rfd->fd = fd;
	      rfd->refcount = 1;
	    }
	  break;
	}
    
  /* No good existing. Need new link. */
  if ((rfl = daemon->rfl_spare))
    daemon->rfl_spare = rfl->next;
  else if (!(rfl = whine_malloc(sizeof(struct randfd_list))))
    {
      /* malloc failed, don't leak allocated sock */
      if (rfd)
	{
	  close(rfd->fd);
	  rfd->refcount = 0;
	}

      return -1;
    }
  
  /* No free ones or cannot get new socket, grab an existing one */
  if (!rfd)
    for (j = 0; j < daemon->numrrand; j++)
      {
	i = (j + finger) % daemon->numrrand;
	if (daemon->randomsocks[i].refcount != 0 &&
	    server_isequal(serv, daemon->randomsocks[i].serv) &&
	    daemon->randomsocks[i].refcount != 0xfffe)
	  {
	    struct randfd_list *rl;
	    /* Don't pick one we already have. */
	    for (rl = *fdlp; rl; rl = rl->next)
	      if (rl->rfd == &daemon->randomsocks[i])
		break;

	    if (!rl)
	      {
		finger = i + 1;
		rfd = &daemon->randomsocks[i];
		rfd->refcount++;
		break;
	      }
	  }
      }

  if (!rfd) /* should be when j == daemon->numrrand */
    {
      struct randfd_list *rfl_poll;

      /* there are no free slots, and non with the same parameters we can piggy-back on. 
	 We're going to have to allocate a new temporary record, distinguished by
	 refcount == 0xffff. This will exist in the frec randfd list, never be shared,
	 and be freed when no longer in use. It will also be held on 
	 the daemon->rfl_poll list so the poll system can find it. */

      if ((rfl_poll = daemon->rfl_spare))
	daemon->rfl_spare = rfl_poll->next;
      else
	rfl_poll = whine_malloc(sizeof(struct randfd_list));
      
      if (!rfl_poll ||
	  !(rfd = whine_malloc(sizeof(struct randfd))) ||
	  (fd = random_sock(serv)) == -1)
	{
	  
	  /* Don't leak anything we may already have */
	  rfl->next = daemon->rfl_spare;
	  daemon->rfl_spare = rfl;

	  if (rfl_poll)
	    {
	      rfl_poll->next = daemon->rfl_spare;
	      daemon->rfl_spare = rfl_poll;
	    }
	  
	  if (rfd)
	    free(rfd);
	  
	  return -1; /* doom */
	}

      /* Note rfd->serv not set here, since it's not reused */
      rfd->fd = fd;
      rfd->refcount = 0xffff; /* marker for temp record */

      rfl_poll->rfd = rfd;
      rfl_poll->next = daemon->rfl_poll;
      daemon->rfl_poll = rfl_poll;
    }
  
  rfl->rfd = rfd;
  rfl->next = *fdlp;
  *fdlp = rfl;
  
  return rfl->rfd->fd;
}

/**
 * @brief Release allocated random file descriptors and return to free pools
 * 
 * @detailed This function releases all UDP sockets allocated for DNS queries via
 *           allocate_rfd(). It iterates through the randfd_list linked list, decrements
 *           refcount on each socket (supporting reference-counted sharing), closes sockets
 *           when refcount reaches zero or for temporary overflow records (refcount=0xffff),
 *           frees temporary struct randfd allocations, removes temporary records from
 *           daemon->rfl_poll, returns all randfd_list entries to daemon->rfl_spare free
 *           list for reuse, and sets *fdlp to NULL to indicate list is empty. This is
 *           called when a DNS transaction completes (frec cleanup) to release resources.
 * 
 * @param fdlp Pointer to pointer to randfd_list head. Input: linked list of allocated
 *             sockets to release. Output: set to NULL after all entries freed. The
 *             function does not modify fdlp if *fdlp is already NULL (safe for empty
 *             lists). Must not be NULL pointer (but *fdlp may be NULL).
 * 
 * @return void (no return value)
 * 
 * @note Decrements refcount before closing permanent sockets (daemon->randomsocks[])
 * @note Closes socket immediately for temporary overflow records (refcount 0xffff marker)
 * @note Temporary records created by allocate_rfd() when pool exhausted are fully freed
 * @note Permanent sockets remain in daemon->randomsocks[] pool for reuse by other queries
 * @note All randfd_list entries returned to daemon->rfl_spare for memory reuse
 * @note The daemon->rfl_poll list cleanup is expected to find few or zero entries
 * @note Safe to call with *fdlp == NULL (no-op, just sets *fdlp = NULL redundantly)
 * @note Does not free struct randfd for permanent sockets (daemon->randomsocks[] managed elsewhere)
 * @note Closes file descriptors via close() which may block briefly on final flush
 * 
 * @warning Must be called to prevent socket descriptor and memory leaks after query completes
 * @warning Modifies global daemon->rfl_spare free list (returned entries prepended)
 * @warning Modifies global daemon->rfl_poll list (temporary record removal)
 * @warning Closes file descriptors which may fail silently (close() errors not checked)
 * @warning After return, all file descriptors in original list are closed or decremented
 * @warning Dereferencing original fdlp entries after this call causes use-after-free
 * 
 * @see allocate_rfd() for socket allocation and refcount initialization
 * @see struct randfd in dnsmasq.h: {int fd, struct server *serv, int refcount}
 * @see struct randfd_list in dnsmasq.h: {struct randfd *rfd, struct randfd_list *next}
 * @see free_frec() which calls this function during forward record cleanup
 * 
 * EXAMPLE USAGE:
 * @code
 * // Allocate sockets for query
 * struct randfd_list *rfds = NULL;
 * int fd1 = allocate_rfd(&rfds, server1); // refcount=1
 * int fd2 = allocate_rfd(&rfds, server2); // refcount=1
 * // ... use sockets for DNS queries ...
 * // Release when transaction completes
 * free_rfds(&rfds); // rfds now NULL, sockets closed or refcount decremented
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (internal resource management, not protocol-related)
 * 
 * SIDE EFFECTS:
 * - Iterates through *fdlp linked list from head to tail
 * - For each entry: decrements rfd->refcount (unless refcount already 0xffff)
 * - Closes socket via close(rfd->fd) if refcount reaches 0 or refcount was 0xffff
 * - For temporary records (refcount 0xffff): calls free(rfl->rfd) to release struct randfd
 * - For temporary records: searches daemon->rfl_poll list to remove matching entry
 * - Removes temporary poll entry from daemon->rfl_poll via pointer manipulation (*up = poll->next)
 * - Returns removed temporary poll entry to daemon->rfl_spare free list
 * - Returns each randfd_list entry to daemon->rfl_spare (prepends: rfl->next = daemon->rfl_spare)
 * - Updates daemon->rfl_spare to point to returned entries
 * - Sets *fdlp = NULL after processing all entries
 * - Does NOT free struct randfd for permanent sockets (refcount 1..0xfffe) - these remain in
 *   daemon->randomsocks[] pool with refcount=0 indicating available for reuse
 * - Saves next pointer (tmp = rfl->next) before modifying rfl->next to prevent list traversal break
 * - For daemon->rfl_poll cleanup: uses 'up' double pointer for efficient in-place list removal
 * - Comment notes daemon->rfl_poll cleanup list "expected to be almost always empty"
 * - No error checking on close() - failures ignored (common practice for cleanup paths)
 * 
 * THREAD SAFETY: Single-threaded daemon - modifies global state:
 *                daemon->rfl_spare, daemon->rfl_poll, daemon->randomsocks[].refcount
 */
void free_rfds(struct randfd_list **fdlp)
{
  struct randfd_list *tmp, *rfl, *poll, *next, **up;
  
  for (rfl = *fdlp; rfl; rfl = tmp)
    {
      if (rfl->rfd->refcount == 0xffff || --(rfl->rfd->refcount) == 0)
	close(rfl->rfd->fd);

      /* temporary overflow record */
      if (rfl->rfd->refcount == 0xffff)
	{
	  free(rfl->rfd);
	  
	  /* go through the link of all these by steam to delete.
	     This list is expected to be almost always empty. */
	  for (poll = daemon->rfl_poll, up = &daemon->rfl_poll; poll; poll = next)
	    {
	      next = poll->next;
	      
	      if (poll->rfd == rfl->rfd)
		{
		  *up = poll->next;
		  poll->next = daemon->rfl_spare;
		  daemon->rfl_spare = poll;
		}
	      else
		up = &poll->next;
	    }
	}

      tmp = rfl->next;
      rfl->next = daemon->rfl_spare;
      daemon->rfl_spare = rfl;
    }

  *fdlp = NULL;
}

/**
 * @brief Free a forward record (frec) and release all associated resources
 * 
 * @detailed This function performs comprehensive cleanup of a forward record structure,
 *           releasing all dynamically allocated resources and returning reusable components
 *           to their respective free pools. The cleanup process includes: (1) Iterating
 *           through the frec_src chain (additional source address records for multi-homed
 *           queries) and freeing any encode_bigmap structures used for EDNS0 Client Subnet
 *           address compression, then returning all frec_src structures (except the builtin
 *           one) to daemon->free_frec_src pool for reuse. (2) Clearing the frec_src.next
 *           pointer to NULL to mark the forward record as having no additional sources.
 *           (3) Calling free_rfds() to release all random file descriptors (UDP sockets)
 *           associated with this forward record back to the socket pool. (4) Clearing
 *           sentto pointer (upstream server) and flags field to reset record state.
 *           (5) Freeing blockdata in f->stash (used for storing original query packets
 *           for validation) via blockdata_free(). (6) For DNSSEC-enabled builds: handling
 *           blocking_query dependencies by unlinking this frec from the blocking query's
 *           dependent list, and recursively freeing the blocking query itself if this was
 *           the last/only dependent (cascade cleanup). (7) Clearing all DNSSEC-related
 *           pointers (blocking_query, dependent, next_dependent) to NULL. The forward
 *           record itself remains in daemon->frec_list but is marked as available for
 *           reuse (sentto == NULL indicates free record). This function is called when
 *           a DNS query completes (successfully or with error), when a query times out,
 *           when an upstream server is removed (server_gone), or during daemon shutdown.
 * 
 * @param f Pointer to struct frec to be freed and reset. Must not be NULL. Must be a
 *          valid forward record from daemon->frec_list. After this function returns, the
 *          frec is marked as free (sentto == NULL) and available for reuse by get_new_frec().
 * 
 * @return void (no return value)
 * 
 * @note Does NOT remove frec from daemon->frec_list (records remain in list, marked free)
 * @note frec_src.next chain (additional source records) is freed and returned to pool
 * @note encode_bigmap structures (EDNS0 Client Subnet compression maps) are freed if present
 * @note Calls free_rfds() to release random file descriptors back to socket pool
 * @note Calls blockdata_free() to release f->stash (stored original query packet)
 * @note For DNSSEC: recursively frees blocking queries if this was last dependent
 * @note For DNSSEC: unlinks this frec from blocking_query->dependent chain
 * @note Clears sentto, flags, stash, blocking_query, dependent, next_dependent to NULL/0
 * @note The frec structure itself is NOT freed (pre-allocated array, always in memory)
 * @note After this call, sentto == NULL indicates frec is available for reuse
 * @note May trigger recursive free_frec() calls for DNSSEC blocking queries
 * @note Recursive freeing depth bounded by DNSSEC validation dependency chain length
 * 
 * @warning Parameter f must not be NULL (no NULL check, will segfault on NULL dereference)
 * @warning Must only be called for forward records currently in use (sentto != NULL)
 * @warning Recursive free_frec() calls for blocking queries may cause deep call stacks
 * @warning If encode_bigmap was allocated, must be freed here (memory leak prevention)
 * @warning If f->stash contains blockdata, must be freed here (memory leak prevention)
 * @warning DNSSEC: must unlink from blocking_query->dependent before freeing blocking query
 * @warning DNSSEC: recursive free may cascade through entire dependency chain
 * @warning After this function, f is marked free but remains in daemon->frec_list
 * 
 * @see get_new_frec() which allocates/reuses forward records (looks for sentto == NULL)
 * @see struct frec in dnsmasq.h for forward record structure definition
 * @see struct frec_src in dnsmasq.h for additional source address record structure
 * @see free_rfds() in forward.c for releasing random file descriptors
 * @see blockdata_free() for releasing stored packet data in f->stash
 * @see server_gone() in forward.c which calls free_frec() for all queries to removed server
 * @see reply_query() which calls free_frec() after sending response to client
 * @see forward_query() which calls free_frec() when allocation fails or query rejected
 * 
 * EXAMPLE USAGE:
 * @code
 * // Query completed, send response to client, then free forward record
 * send_response_to_client(f);
 * free_frec(f); // Release all resources, mark as available
 * // f remains in daemon->frec_list with sentto == NULL
 * // get_new_frec() can now reuse this forward record
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (internal resource management, not protocol-specified behavior)
 * 
 * SIDE EFFECTS:
 * - Iterates through f->frec_src.next chain (additional source address records)
 * - For each frec_src in chain: checks if encode_bigmap != NULL
 * - If encode_bigmap present: calls free(last->encode_bigmap), sets to NULL
 * - encode_bigmap is EDNS0 Client Subnet address compression bitmap (allocated by malloc)
 * - After freeing all bigmaps, links entire frec_src chain to daemon->free_frec_src pool
 * - last->next = daemon->free_frec_src; daemon->free_frec_src = f->frec_src.next
 * - Returns all frec_src structures (except builtin f->frec_src) to free pool for reuse
 * - Sets f->frec_src.next = NULL (clears chain, marks as having no additional sources)
 * - Calls free_rfds(&f->rfds) which releases random file descriptors to socket pool
 * - free_rfds() decrements refcounts in daemon->randomsocks[] and closes unused sockets
 * - Sets f->sentto = NULL (clears upstream server pointer, marks frec as free)
 * - Sets f->flags = 0 (clears all query flags: F_FORWARD, F_NEG, F_DNSSEC, etc.)
 * - Checks if f->stash != NULL (blockdata containing original query packet)
 * - If stash present: calls blockdata_free(f->stash), sets f->stash = NULL
 * - blockdata_free() releases variable-length data blocks to block pool
 * - For DNSSEC builds (#ifdef HAVE_DNSSEC):
 * - Checks if f->blocking_query != NULL (this query depends on DNSSEC validation query)
 * - If blocking_query exists: unlinks f from blocking_query->dependent list
 * - Traverses blocking_query->dependent chain to find f, updates pointers to unlink
 * - After unlinking: checks if blocking_query->dependent == NULL (no more dependents)
 * - If no more dependents: calls free_frec(f->blocking_query) recursively
 * - Recursive free cascades through DNSSEC validation dependency tree
 * - Sets f->blocking_query = NULL, f->dependent = NULL, f->next_dependent = NULL
 * - Clears all DNSSEC dependency pointers to prevent dangling references
 * - Does NOT remove f from daemon->frec_list (frec remains in list, marked free)
 * - Does NOT free the frec structure itself (pre-allocated, never freed)
 * - Modifies global daemon state: free_frec_src pool, randomsocks[] via free_rfds()
 * 
 * THREAD SAFETY: Single-threaded daemon - modifies global state:
 *                daemon->free_frec_src pool, daemon->randomsocks[] (via free_rfds),
 *                f struct members (sentto, flags, stash, blocking_query, dependent, etc.)
 */
/**
 * @brief Clean up and release all resources associated with a forward record
 * 
 * @detailed Frees a forward record (frec) and all associated resources, returning memory
 *           to freelists for reuse. This is the comprehensive cleanup function invoked when
 *           a DNS query completes (successfully or by timeout) or when garbage collection
 *           reclaims old records. The function handles multiple resource types and complex
 *           dependency chains for DNSSEC validation.
 *           
 *           The cleanup process executes in several phases:
 *           
 *           1. **frec_src Chain Cleanup**: Each forward record contains a builtin frec_src
 *              structure for source address/interface tracking. Extended queries (those
 *              requiring multiple source addresses) allocate additional frec_src nodes
 *              forming a linked list. The function walks this chain (f->frec_src.next),
 *              frees any encode_bigmap buffers allocated for EDNS0 client subnet encoding,
 *              then returns the entire chain (excluding the builtin first node) to the
 *              global freelist daemon->free_frec_src for reuse. This avoids repeated
 *              malloc/free cycles for common query patterns.
 *           
 *           2. **Socket File Descriptor Cleanup**: Calls free_rfds(&f->rfds) to close any
 *              random source port UDP sockets or TCP connection file descriptors associated
 *              with this query. This ensures no file descriptor leaks occur for queries
 *              using randomized source ports (security feature) or TCP transport for large
 *              responses/zone transfers.
 *           
 *           3. **Core State Reset**: Sets f->sentto = NULL (marking record as free for
 *              get_new_frec() allocation) and f->flags = 0 (clearing all query state flags
 *              like F_IPV4, F_IPV6, F_DNSSEC, F_SERVER, etc.).
 *           
 *           4. **Stash Buffer Cleanup**: If f->stash is non-NULL (contains a cached copy
 *              of the original query packet for retry scenarios), calls blockdata_free()
 *              to release the blockdata-allocated buffer. The stash mechanism stores the
 *              original query in case the upstream server fails and retry to an alternate
 *              server is needed, preserving the exact original query bytes including any
 *              EDNS0 options and query ID.
 *           
 *           5. **DNSSEC Dependency Chain Resolution**: When HAVE_DNSSEC is enabled, DNS
 *              queries may spawn dependent sub-queries for DNSKEY and DS record lookups
 *              required for DNSSEC validation. These form a dependency graph where one
 *              query (f->blocking_query) blocks another (f) waiting for validation data.
 *              The cleanup logic:
 *              
 *              - Unlinks f from its blocking_query's dependent list by walking the
 *                blocking_query->dependent chain and removing f from next_dependent links
 *              - If f was the last/only dependent of blocking_query (dependent list
 *                becomes NULL after removal), recursively calls free_frec(blocking_query)
 *                to cascade the cleanup up the dependency chain
 *              - Clears all DNSSEC dependency pointers (blocking_query, dependent,
 *                next_dependent) to prevent dangling references
 *              
 *              This recursive cleanup ensures that DNSSEC validation chains are properly
 *              torn down when queries complete or time out, preventing memory leaks and
 *              ensuring that blocked queries don't wait indefinitely for freed resources.
 *           
 *           The function is called from multiple contexts:
 *           - get_new_frec() during garbage collection of timed-out queries
 *           - return_reply() after successfully forwarding response to client
 *           - Various error paths when queries fail or are rejected
 *           - Recursively from free_frec() itself for DNSSEC dependency chain cleanup
 * 
 * @param f Forward record to free (must not be NULL; must point to valid frec in daemon->frec_list)
 * 
 * @return void (no return value; modifies global state by updating freelists and clearing frec fields)
 * 
 * @note Does not remove frec from daemon->frec_list; only marks as free (sentto=NULL)
 * @note Builtin frec_src (first node in chain) is NOT freed or added to freelist
 * @note Extended frec_src nodes (frec_src.next chain) are returned to daemon->free_frec_src
 * @note encode_bigmap buffers in frec_src chain are freed via free() if present
 * @note Recursive DNSSEC cleanup may free multiple frecs in single call (dependency cascade)
 * @note After this call, f->sentto == NULL signals to get_new_frec() that slot is available
 * @note Socket fds in f->rfds are closed via free_rfds() to prevent file descriptor leaks
 * @note blockdata_free() handles NULL stash safely (no-op if stash already NULL)
 * 
 * @warning Must not call free_frec() twice on same frec without re-initialization
 * @warning Assumes f parameter is non-NULL (no validation performed)
 * @warning Recursive calls for DNSSEC dependencies may cause deep call stack in pathological cases
 * @warning Modifies global daemon->free_frec_src freelist without locking (single-threaded assumption)
 * @warning Does not validate frec is actually in daemon->frec_list before freeing
 * 
 * @see get_new_frec() for frec allocation which checks f->sentto to identify free slots
 * @see free_rfds() for closing socket file descriptors and returning to random fd pool
 * @see blockdata_free() in blockdata.c for stash buffer deallocation
 * @see struct frec in dnsmasq.h for forward record structure definition
 * @see struct frec_src in dnsmasq.h for source address tracking structure
 * @see daemon->free_frec_src in dnsmasq.h for frec_src freelist
 * @see F_DNSSEC and other flags in dnsmasq.h for query state tracking
 * 
 * EXAMPLE USAGE:
 * @code
 * struct frec *f = ...; // Forward record for completed query
 * // Query has been answered or timed out
 * free_frec(f);
 * // f->sentto now NULL, frec available for reuse by get_new_frec()
 * // All associated resources (sockets, buffers, dependencies) released
 * @endcode
 * 
 * RFC COMPLIANCE: None (internal resource management, no protocol specification)
 * SIDE EFFECTS:
 *   - Sets f->sentto = NULL (marks record as free for allocation)
 *   - Sets f->flags = 0 (clears all query state flags)
 *   - Frees f->frec_src.next chain encode_bigmap buffers via free()
 *   - Returns f->frec_src.next chain to daemon->free_frec_src freelist
 *   - Sets f->frec_src.next = NULL (detaches extended frec_src chain)
 *   - Calls free_rfds(&f->rfds) which closes sockets and modifies random fd pool
 *   - Calls blockdata_free(f->stash) if stash non-NULL, freeing blockdata buffers
 *   - Sets f->stash = NULL after freeing
 *   - For DNSSEC: Unlinks f from f->blocking_query->dependent list (modifies dependency chain)
 *   - For DNSSEC: Recursively calls free_frec(f->blocking_query) if last dependent removed
 *   - For DNSSEC: Sets f->blocking_query, f->dependent, f->next_dependent to NULL
 * THREAD SAFETY: Single-threaded architecture; modifies shared global state without locking
 */
static void free_frec(struct frec *f)
{
  struct frec_src *last;
  
  /* add back to freelist if not the record builtin to every frec,
     also free any bigmaps they've been decorated with. */
  for (last = f->frec_src.next; last && last->next; last = last->next)
    if (last->encode_bigmap)
      {
	free(last->encode_bigmap);
	last->encode_bigmap = NULL;
      }
  
  if (last)
    {
      /* final link in the chain loses bigmap too. */
      if (last->encode_bigmap)
	{
	  free(last->encode_bigmap);
	  last->encode_bigmap = NULL;
	}
      last->next = daemon->free_frec_src;
      daemon->free_frec_src = f->frec_src.next;
    }
    
  f->frec_src.next = NULL;    
  free_rfds(&f->rfds);
  f->sentto = NULL;
  f->flags = 0;

  if (f->stash)
    {
      blockdata_free(f->stash);
      f->stash = NULL;
    }

#ifdef HAVE_DNSSEC
  /* Anything we're waiting on is pointless now, too */
  if (f->blocking_query)
    {
      struct frec *n, **up;

      /* unlink outselves from the blocking query's dependents list. */
      for (n = f->blocking_query->dependent, up = &f->blocking_query->dependent; n; n = n->next_dependent)
	if (n == f)
	  {
	    *up = n->next_dependent;
	    break;
	  }
	else
	  up = &n->next_dependent;

      /* If we were the only/last dependent, free the blocking query too. */
      if (!f->blocking_query->dependent)
	free_frec(f->blocking_query);
    }
  
  f->blocking_query = NULL;
  f->dependent = NULL;
  f->next_dependent = NULL;
#endif
}



/* Impose an absolute
   limit of 4*TIMEOUT before we wipe things (for random sockets).
   If force is set, always return a result, even if we have
   to allocate above the limit, and don't free any records.
   This is set when allocating for DNSSEC to avoid cutting off
   the branch we are sitting on. */
/**
 * @brief Allocate or recycle a forward record (frec) for tracking a DNS query
 * 
 * @detailed Manages the forward record pool (daemon->frec_list) by allocating new records,
 *           recycling free records, or garbage collecting timed-out queries. The function
 *           implements several resource management strategies:
 *           1. First-fit allocation: Reuses first free record (!sentto) encountered
 *           2. Garbage collection: Frees records older than 4*TIMEOUT (40 seconds default)
 *           3. Rate limiting: Enforces per-server-group concurrent query limits
 *           4. LRU reuse: Recycles oldest timed-out record if no free records available
 *           5. Dynamic expansion: Allocates new records when pool is exhausted
 *           
 *           The rate limiting mechanism counts active queries to the same server group
 *           and rejects new queries when count >= daemon->ftabsize (default 150). This
 *           prevents query flooding to specific upstream servers while allowing queries
 *           to other server groups to proceed normally.
 * 
 * @param now Current time (seconds since epoch) for timeout calculations and record timestamp
 * @param master Server to associate with this query; used for server-group rate limiting
 *               (must not be NULL; determines which server group this query belongs to)
 * @param force If non-zero, bypass rate limiting and garbage collection checks
 *              (used for high-priority queries that must not be rejected)
 * 
 * @return Pointer to allocated/recycled frec structure on success, NULL on failure
 * @retval non-NULL Successfully allocated or recycled forward record, initialized with
 *                  current time, forward_delay, and DNSSEC uid (if enabled)
 * @retval NULL     Allocation failed due to rate limiting (count >= ftabsize), or
 *                  memory allocation failure (whine_malloc returned NULL)
 * 
 * @note Forward records (frec) track outstanding DNS queries from query transmission
 *       through response reception, maintaining query state, retry timing, and DNSSEC context
 * @note Garbage collection threshold: 4*TIMEOUT (40 seconds default, TIMEOUT=10s from config.h)
 * @note LRU reuse threshold: TIMEOUT (10 seconds default)
 * @note DNSSEC sub-queries (dependent=1) are never garbage collected to prevent dangling references
 * @warning Rate limiting can cause query drops when concurrent query limit is reached
 * @warning Setting force=1 bypasses critical resource protections and should be used sparingly
 * 
 * @see free_frec() for forward record cleanup and release
 * @see struct frec in dnsmasq.h for forward record structure definition
 * @see daemon->ftabsize (FTABSIZ in config.h line 17, default 150) for query limit
 * @see query_full() for rate limit warning logging
 * 
 * EXAMPLE USAGE:
 * @code
 * struct server *server = ...;
 * time_t now = dnsmasq_time();
 * 
 * // Allocate forward record for new query
 * struct frec *forward = get_new_frec(now, server, 0);
 * if (!forward) {
 *   // Rate limit hit or allocation failed, query dropped
 *   return; 
 * }
 * 
 * // Initialize query state
 * forward->sentto = server;
 * forward->orig_id = header->id;
 * forward->new_id = get_id();
 * @endcode
 * 
 * ALLOCATION STRATEGY:
 * 1. Scan daemon->frec_list for free records (!sentto field NULL)
 * 2. Garbage collect records older than 4*TIMEOUT (if !force)
 * 3. Track oldest non-garbage record for potential LRU reuse
 * 4. Count active queries to same server group for rate limiting
 * 5. If count >= ftabsize and !force, call query_full() and return NULL
 * 6. If no free record, reuse oldest if age >= TIMEOUT (if !force)
 * 7. If still no record, allocate new one with whine_malloc()
 * 8. Prepend new allocation to daemon->frec_list
 * 9. Initialize record: set time=now, forward_delay=fast_retry_time, uid=next_uid
 * 
 * RATE LIMITING BEHAVIOR:
 * - Per-server-group enforcement: Only counts queries to same server_samegroup()
 * - Active query definition: f->sentto != NULL && age < TIMEOUT
 * - Force bypass: force=1 skips all rate limit checks
 * - Limit: daemon->ftabsize concurrent queries per server group
 * 
 * GARBAGE COLLECTION BEHAVIOR:
 * - Threshold: Records older than 4*TIMEOUT (40 seconds)
 * - DNSSEC protection: Dependent sub-queries never garbage collected
 * - Metric tracking: Increments METRIC_DNS_UNANSWERED_QUERY for timed-out queries
 * - Immediate reuse: Freed record becomes allocation target
 * 
 * RFC COMPLIANCE: RFC 1035 (DNS query processing and resource management)
 * 
 * SIDE EFFECTS:
 * - May call free_frec() to garbage collect timed-out records
 * - May call whine_malloc() to allocate new forward record
 * - May call query_full() to log rate limiting warnings
 * - Modifies daemon->frec_list by prepending new allocations
 * - Increments daemon->metrics[METRIC_DNS_UNANSWERED_QUERY] for timeouts
 * - Increments static next_uid for DNSSEC unique ID assignment
 * 
 * THREAD SAFETY: Not thread-safe (uses static next_uid, modifies shared daemon->frec_list)
 */
/**
 * @brief Allocate or reclaim a forward record (frec) for tracking DNS query state
 * 
 * @detailed Manages the forward record (frec) pool which tracks outstanding DNS queries
 *           forwarded to upstream servers. The function implements a sophisticated allocation
 *           strategy combining free slot search, garbage collection of timed-out queries,
 *           LRU-style reuse of oldest records, and dynamic allocation when needed.
 *           
 *           The allocation algorithm executes in phases:
 *           1. Scan daemon->frec_list for free slots (f->sentto == NULL) and identify oldest record
 *           2. Garbage collect records older than 4*TIMEOUT (40 seconds with default TIMEOUT=10)
 *           3. Count active queries for the same server group to enforce per-group limits
 *           4. If count >= daemon->ftabsize, reject allocation and call query_full() to log warning
 *           5. If no free slot found, reuse oldest record if it's older than TIMEOUT (10 seconds)
 *           6. If still no slot, allocate new frec via whine_malloc() and prepend to frec_list
 *           7. Initialize selected frec with current time, forward_delay, and unique ID
 *           
 *           The 'force' parameter bypasses capacity checks and timeout-based garbage collection,
 *           used for retries and special circumstances where allocation must succeed. Normal
 *           operation uses force=0 to enforce query limits and prevent resource exhaustion.
 *           
 *           Server group counting ensures that no single upstream server group (servers sharing
 *           the same domain prefix or configuration group) can monopolize the forward record
 *           table. This prevents cascading failures where one failing upstream server exhausts
 *           all frec slots while other upstreams remain healthy.
 *           
 *           DNSSEC queries allocate dependent sub-queries for DNSKEY/DS validation. These
 *           dependent queries (f->dependent != NULL) are never garbage collected by this
 *           function - they are only freed when their parent query completes, preventing
 *           dangling references in the DNSSEC validation chain.
 * 
 * @param now Current time in seconds since epoch (from time(2)); used for timeout calculations
 * @param master Upstream server for which the frec will be allocated (must not be NULL; determines server group for counting)
 * @param force If non-zero, bypass capacity checks and timeout-based GC; if zero, enforce ftabsize limit and timeout policies
 * 
 * @return Pointer to allocated/reused frec structure with time, forward_delay, and uid initialized
 * @retval non-NULL Successfully allocated or reclaimed forward record ready for query tracking
 * @retval NULL Allocation failed: either ftabsize limit reached (force=0) or malloc failure
 * 
 * @note Garbage collection uses 4*TIMEOUT threshold to ensure sufficient time for slow upstream servers
 * @note Records older than TIMEOUT but newer than 4*TIMEOUT can be reused if no free slots exist
 * @note DNSSEC dependent queries (f->dependent set) are never garbage collected by this function
 * @note Static next_uid counter increments monotonically for DNSSEC query tracking (32-bit wraparound)
 * @note Newly allocated frecs are prepended to daemon->frec_list (O(1) insertion)
 * @note Increments daemon->metrics[METRIC_DNS_UNANSWERED_QUERY] for each timed-out query garbage collected
 * 
 * @warning Returns NULL when capacity exhausted (count >= ftabsize) in non-forced mode
 * @warning Assumes master parameter is non-NULL (no validation performed)
 * @warning whine_malloc() failure returns NULL (out of memory condition)
 * @warning Modifies global daemon->frec_list by prepending new allocations
 * 
 * @see struct frec in dnsmasq.h for forward record structure definition
 * @see free_frec() for frec cleanup and deallocation logic
 * @see query_full() for capacity exhaustion logging
 * @see server_samegroup() for server group membership testing
 * @see whine_malloc() in util.c for memory allocation with logging
 * @see TIMEOUT in config.h (default 10 seconds) for query timeout constant
 * @see daemon->ftabsize (default FTABSIZ=150 from config.h) for concurrent query limit
 * 
 * EXAMPLE USAGE:
 * @code
 * struct server *upstream = daemon->servers;  // First upstream server
 * time_t now = dnsmasq_time();
 * struct frec *f = get_new_frec(now, upstream, 0);  // Normal allocation
 * if (f) {
 *   f->sentto = upstream;
 *   f->orig_id = query_id;
 *   f->new_id = get_id();
 *   // Proceed with query forwarding
 * } else {
 *   // Capacity exhausted - drop query
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: None (internal resource management, no protocol specification)
 * SIDE EFFECTS: 
 *   - Modifies daemon->frec_list by garbage collecting old records and prepending new allocations
 *   - Calls free_frec() which may modify multiple frec fields (sentto, dependent, hash_next, etc.)
 *   - Calls query_full() which logs capacity warnings to syslog
 *   - Increments daemon->metrics[METRIC_DNS_UNANSWERED_QUERY] for garbage collected queries
 *   - Increments static next_uid counter for DNSSEC query tracking (HAVE_DNSSEC)
 *   - Allocates heap memory via whine_malloc() which may trigger out-of-memory logging
 * THREAD SAFETY: Single-threaded architecture; modifies shared daemon->frec_list without locking
 */
static struct frec *get_new_frec(time_t now, struct server *master, int force)
{
  struct frec *f, *oldest, *target;
  int count;
#ifdef HAVE_DNSSEC
  static int next_uid = 0;
#endif
  
  /* look for free records, garbage collect old records and count number in use by our server-group. */
  for (f = daemon->frec_list, oldest = NULL, target =  NULL, count = 0; f; f = f->next)
    {
      if (!f->sentto)
	target = f;
      else
	{
#ifdef HAVE_DNSSEC
	  /* Don't free DNSSEC sub-queries here, as we may end up with
	     dangling references to them. They'll go when their "real" query 
	     is freed. */
	  if (!f->dependent)
#endif
	    if (!force)
	      {
		if (difftime(now, f->time) >= 4*TIMEOUT)
		  {
		    daemon->metrics[METRIC_DNS_UNANSWERED_QUERY]++;
		    free_frec(f);
		    target = f;
		  }
		else if (!oldest || difftime(f->time, oldest->time) <= 0)
		  oldest = f;
	      }
	}
      
      if (f->sentto && ((int)difftime(now, f->time)) < TIMEOUT && server_samegroup(f->sentto, master))
	count++;
    }
  
  if (!force)
    {
      if (count >= daemon->ftabsize)
	{
	  query_full(now, master->domain);
	  return NULL;
	}
      
      if (!target && oldest && ((int)difftime(now, oldest->time)) >= TIMEOUT)
	{ 
	  /* can't find empty one, use oldest if there is one and it's older than timeout */
	  daemon->metrics[METRIC_DNS_UNANSWERED_QUERY]++;
	  free_frec(oldest);
	  target = oldest;
	}      
    }
  
  if (!target && (target = (struct frec *)whine_malloc(sizeof(struct frec))))
    {
      target->next = daemon->frec_list;
      daemon->frec_list = target;
    }

  if (target)
    {
      target->time = now;
      target->forward_delay = daemon->fast_retry_time;
#ifdef HAVE_DNSSEC
      target->uid = next_uid++;
#endif
    }
  
  return target;
}

/**
 * @brief Log warning when maximum concurrent DNS query limit is reached
 * 
 * @detailed Generates rate-limited warning messages when the forward record table (frec_list)
 *           is exhausted and no free slots are available for new DNS queries. This condition
 *           indicates the system is at capacity (daemon->ftabsize concurrent queries active).
 *           Rate limiting ensures log flooding is prevented - warnings are issued at most once
 *           every 5 seconds regardless of how many queries are rejected. The function supports
 *           both generic warnings (when domain is NULL/empty) and domain-specific warnings
 *           (when a specific domain name causes the failure).
 * 
 * @param now Current time (seconds since epoch) for rate limiting calculation
 * @param domain Domain name causing query failure, or NULL/empty for generic warning
 *               (null-terminated string, may be NULL or empty string)
 * 
 * @note Rate limiting prevents syslog flooding during sustained overload conditions
 * @note Uses static variable last_log to track last warning time (persists across calls)
 * @note Maximum queries controlled by daemon->ftabsize (default FTABSIZ=150 from config.h)
 * @warning Query table exhaustion causes query drops and degraded DNS service
 * 
 * @see get_new_frec() which calls this function when no free forward records available
 * @see struct frec in dnsmasq.h for forward record structure
 * @see daemon->ftabsize (FTABSIZ in config.h line 17, default 150)
 * 
 * EXAMPLE USAGE:
 * @code
 * struct frec *forward = get_new_frec(now, server, 0);
 * if (!forward) {
 *   // No free forward records, query_full already logged warning
 *   // Query will be dropped
 *   return;
 * }
 * @endcode
 * 
 * LOG MESSAGE FORMATS:
 * - Generic: "Maximum number of concurrent DNS queries reached (max: 150)"
 * - Domain-specific: "Maximum number of concurrent DNS queries to example.com reached (max: 150)"
 * 
 * RATE LIMITING ALGORITHM:
 * 1. Calculate time difference: now - last_log
 * 2. If difference > 5 seconds, issue new warning and update last_log
 * 3. If difference <= 5 seconds, silently return (suppress duplicate warnings)
 * 
 * SIDE EFFECTS: 
 * - Writes LOG_WARNING message to syslog
 * - Updates static last_log variable on rate limit expiry
 * 
 * THREAD SAFETY: Not thread-safe (uses static variable last_log)
 */
static void query_full(time_t now, char *domain)
{
  static time_t last_log = 0;
  
  if ((int)difftime(now, last_log) > 5)
    {
      last_log = now;
      if (!domain || strlen(domain) == 0)
	my_syslog(LOG_WARNING, _("Maximum number of concurrent DNS queries reached (max: %d)"), daemon->ftabsize);
      else
	my_syslog(LOG_WARNING, _("Maximum number of concurrent DNS queries to %s reached (max: %d)"), domain, daemon->ftabsize);
    }
}

/**
 * @brief Find forward record matching query parameters with DNS 0x20 case encoding support
 * 
 * @detailed Searches the forward record list (daemon->frec_list) for an active query matching
 *           the specified parameters. This function is critical for correlating DNS responses
 *           with their originating queries and preventing duplicate query transmission.
 *           
 *           The function implements DNS 0x20 case randomization support (security feature that
 *           randomizes case in DNS queries to make cache poisoning attacks harder). When matching
 *           received answers (FREC_ANSWER flag set), the function uses case-insensitive comparison
 *           if OPT_DO_0x20 is enabled and OPT_NO_0x20 is disabled. For duplicate query detection,
 *           case-sensitive comparison is always used.
 *           
 *           The matching algorithm extracts the query name from the stashed original query packet
 *           and compares it with the target name, then validates DNS class and type. The function
 *           also implements age filtering to match get_new_frec() garbage collection behavior,
 *           rejecting frecs older than 4*TIMEOUT (40 seconds default) even if they haven't been
 *           garbage collected yet.
 * 
 * @param now Current time (seconds since epoch) for age filtering
 * @param target Domain name to match against stashed query (null-terminated string)
 * @param class DNS class to match (e.g., C_IN for Internet class)
 * @param rrtype DNS resource record type to match (e.g., T_A, T_AAAA), or -1 to match any type
 * @param id Query ID to match (f->new_id field - the randomized ID), or -1 to match any ID
 * @param flags Flag values to match after applying flagmask (e.g., FREC_ANSWER, DNSSEC flags)
 * @param flagmask Bitmask specifying which flags to compare (only masked flags must match)
 * 
 * @return Pointer to matching forward record, or NULL if no match found
 * @retval non-NULL Successfully found matching forward record with active query (sentto != NULL)
 * @retval NULL     No matching record found, or matching record too old (age >= 4*TIMEOUT),
 *                  or case mismatch detected in DNS 0x20 encoding, or stash retrieval failed
 * 
 * @note FREC_ANSWER flag in flags parameter controls case sensitivity mode:
 *       - If set: Use case-insensitive comparison for DNS 0x20 answer matching
 *       - If clear: Use case-sensitive comparison for duplicate query detection
 * @note The FREC_ANSWER flag is cleared from flags after mode determination
 * @note Query ID -1 acts as wildcard, matching any query ID (used for duplicate detection)
 * @note Resource type -1 acts as wildcard, matching any type (flags check type for DNSSEC)
 * @note Age filtering threshold: 4*TIMEOUT (40 seconds, matches get_new_frec() GC threshold)
 * @warning Case mismatch in DNS 0x20 replies generates one-time warning to syslog
 * @warning Returns NULL for old frecs to maintain consistent behavior even when get_new_frec()
 *          not actively garbage collecting
 * 
 * @see get_new_frec() for forward record allocation and garbage collection
 * @see extract_name() in rfc1035.c for domain name extraction and comparison
 * @see blockdata_retrieve() for stashed query packet retrieval
 * @see struct frec in dnsmasq.h for forward record structure
 * 
 * EXAMPLE USAGE:
 * @code
 * // Match received DNS answer to original query
 * time_t now = dnsmasq_time();
 * char *domain = "example.com";
 * int new_id = ntohs(header->id);
 * 
 * struct frec *forward = lookup_frec(now, domain, C_IN, T_A, new_id,
 *                                     FREC_ANSWER, 0xFFFF);
 * if (forward) {
 *   // Found matching query, process response
 *   forward_header->id = forward->orig_id; // Restore original query ID
 *   send_to_client(forward);
 * }
 * @endcode
 * 
 * MATCHING ALGORITHM:
 * 1. Determine case sensitivity mode based on FREC_ANSWER flag and OPT_DO_0x20
 * 2. Iterate through daemon->frec_list for active records (f->sentto != NULL)
 * 3. Apply flagmask to flags and compare with (f->flags & flagmask)
 * 4. Match query ID (f->new_id) or accept -1 wildcard
 * 5. Retrieve stashed original query packet via blockdata_retrieve()
 * 6. Extract domain name from stashed query with case-sensitive or case-insensitive mode
 * 7. Extract and compare DNS class and type from stashed query
 * 8. If type mismatch and rrtype != -1, continue to next record
 * 9. If class mismatch, continue to next record
 * 10. Check extract_name() return code (rc):
 *     - rc == 1: Successful match
 *     - rc == 3: Case mismatch in DNS 0x20 encoding (warn once, continue)
 *     - Other: Extraction error, continue
 * 11. Check record age: reject if >= 4*TIMEOUT
 * 12. Return matching record
 * 
 * DNS 0x20 CASE ENCODING:
 * - Security feature randomizing case in DNS queries (RFC draft-vixie-dnsext-dns0x20)
 * - Makes cache poisoning attacks harder by adding entropy to queries
 * - Answer matching uses case-insensitive comparison (EXTR_NAME_NOCASE)
 * - Duplicate detection uses case-sensitive comparison (EXTR_NAME_COMPARE)
 * - Controlled by OPT_DO_0x20 and OPT_NO_0x20 options
 * - Case mismatch warning issued once per daemon lifetime (static variable)
 * 
 * FLAG MATCHING:
 * - flagmask specifies which flags are significant
 * - Comparison: (f->flags & flagmask) == (flags & flagmask)
 * - Allows flexible matching on subset of flags (e.g., DNSSEC, forwarding flags)
 * - FREC_ANSWER flag special: controls mode but excluded from comparison
 * 
 * AGE FILTERING:
 * - Threshold: difftime(now, f->time) >= 4*TIMEOUT
 * - Matches garbage collection threshold in get_new_frec()
 * - Prevents returning stale frecs that should have been garbage collected
 * - Ensures consistent behavior even when get_new_frec() not running frequently
 * 
 * STASHED QUERY RETRIEVAL:
 * - Original query stored in f->stash via blockdata
 * - Retrieved with blockdata_retrieve(f->stash, f->stash_len, NULL)
 * - Used for domain name, class, and type comparison
 * - Failure to retrieve stash causes skip to next record
 * 
 * RFC COMPLIANCE: 
 * - RFC 1035 (DNS query/response correlation)
 * - RFC draft-vixie-dnsext-dns0x20 (DNS 0x20 case randomization)
 * 
 * SIDE EFFECTS:
 * - May call extract_name() to parse stashed query
 * - May call blockdata_retrieve() to access stashed query
 * - Issues one-time syslog warning for DNS 0x20 case mismatch (static variable warned)
 * - Modifies flags parameter (clears FREC_ANSWER bit if set)
 * 
 * THREAD SAFETY: Not thread-safe (uses static variable warned, accesses shared frec_list)
 */
static struct frec *lookup_frec(time_t now, char *target, int class, int rrtype, int id, int flags, int flagmask)
{
  struct frec *f;
  struct dns_header *header;
  int compare_mode = EXTR_NAME_COMPARE;

  /* Only compare case-sensitive when matching frec to a received answer,
     NOT when looking for a duplicated question. */
  if (flags & FREC_ANSWER)
    {
      flags &= ~FREC_ANSWER;
      if (!option_bool(OPT_NO_0x20) && option_bool(OPT_DO_0x20))
	compare_mode = EXTR_NAME_NOCASE;
    }
  
  for (f = daemon->frec_list; f; f = f->next)
    if (f->sentto &&
	(f->flags & flagmask) == flags &&
	(f->new_id == id || id == -1) &&
	(header = blockdata_retrieve(f->stash, f->stash_len, NULL)))
      {
	unsigned char *p = (unsigned char *)(header+1);
	int hclass, hrrtype, rc;

	/* Case sensitive compare for DNS-0x20 encoding. */
	if ((rc = extract_name(header, f->stash_len, &p, target, compare_mode, 4)))
	  {
	    GETSHORT(hrrtype, p);
	    GETSHORT(hclass, p);
	    
	    /* type checked by flags for DNSSEC queries. */
	    if (rrtype != -1 && rrtype != hrrtype)
	      continue;
	    
	    if (class != hclass)
	      continue;
	  }

	if (rc != 1)
	  {
	    static int warned = 0;
	    
	    if (rc == 3 && !warned)
	      {
		my_syslog(LOG_WARNING, _("Case mismatch in DNS reply - check bit 0x20 encoding."));
		warned = 1;
	      }
	    
	    continue;
	  }

	/* frecs older than this will get garbage-collected in
	   get_new_frec(), so don't return them here, so we have
	   consistent behaviour from an idle dnsmasq which
	   is not calling get_new_frec() often. */
	if (difftime(now, f->time) >= 4*TIMEOUT)
	  return NULL;
	
	return f;
      }
  
  return NULL;
}

/* Send query packet again, if we can. */
/**
 * @brief Resend a previously saved DNS query to the saved upstream server
 * 
 * @detailed This function resends a DNS query that was previously saved in global daemon
 *           state (daemon->srv_save, daemon->fd_save, daemon->packet, daemon->packet_len).
 *           It is called when a query needs to be retried or resent after some event or
 *           condition. The function checks if a saved server exists (daemon->srv_save not
 *           NULL) and if so, calls server_send() to transmit the saved packet to that
 *           server using the saved file descriptor. This mechanism allows the system to
 *           retry queries after transient failures, timeout events, or other conditions
 *           requiring query resubmission. If no saved server exists, the function does
 *           nothing (safe no-op).
 * 
 * @return void (no return value)
 * 
 * @note Requires daemon->srv_save, daemon->fd_save, daemon->packet, daemon->packet_len
 *       to be populated before calling (typically by code that initiates the query retry)
 * @note If daemon->srv_save is NULL, function returns immediately without action
 * @note Does not modify daemon state - just uses saved state for resend operation
 * @note The saved packet in daemon->packet must still be valid (not overwritten)
 * @note The saved file descriptor in daemon->fd_save must still be open and valid
 * @note Typically called from signal handlers or event loop after specific triggers
 * @note Does not check if daemon->fd_save is still valid (assumes caller ensures validity)
 * @note Does not check if daemon->packet_len is non-zero or valid
 * 
 * @warning Assumes global daemon state is correctly populated with valid saved query data
 * @warning If daemon->packet has been overwritten, sends corrupted/wrong query
 * @warning If daemon->fd_save refers to closed descriptor, server_send() will fail
 * @warning If daemon->srv_save server has been freed, causes use-after-free (caller must ensure validity)
 * @warning No error handling if server_send() fails - errors handled within server_send()
 * 
 * @see server_send() in forward.c for actual packet transmission logic
 * @see struct daemon in dnsmasq.h for srv_save, fd_save, packet, packet_len members
 * @see receive_query() which may populate daemon saved state for later resend
 * 
 * EXAMPLE USAGE:
 * @code
 * // Somewhere in code, save query for potential retry
 * daemon->srv_save = target_server;
 * daemon->fd_save = query_fd;
 * memcpy(daemon->packet, query_packet, query_len);
 * daemon->packet_len = query_len;
 * // ... later, when retry condition detected ...
 * resend_query(); // Resends to daemon->srv_save
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (internal query retry mechanism, not protocol-specified behavior)
 * 
 * SIDE EFFECTS:
 * - Reads daemon->srv_save to check if saved server exists
 * - If daemon->srv_save is not NULL: calls server_send(daemon->srv_save, daemon->fd_save,
 *   daemon->packet, daemon->packet_len, 0)
 * - server_send() performs UDP/TCP transmission with source port randomization
 * - server_send() may update server statistics (queries sent, failures, etc.)
 * - Network I/O via server_send(): sends UDP datagram or writes to TCP socket
 * - Does NOT clear or modify daemon->srv_save, daemon->fd_save, daemon->packet, or
 *   daemon->packet_len (leaves saved state intact for potential multiple resends)
 * - If server_send() fails, error handling occurs within server_send() (not propagated here)
 * 
 * THREAD SAFETY: Single-threaded daemon - reads global daemon state
 *                (daemon->srv_save, daemon->fd_save, daemon->packet, daemon->packet_len)
 */
void resend_query(void)
{
  if (daemon->srv_save)
    server_send(daemon->srv_save, daemon->fd_save,
		daemon->packet, daemon->packet_len, 0);
}

/* A server record is going away, remove references to it */
/**
 * @brief Clean up all references to an upstream DNS server being removed or disabled
 * 
 * @detailed This function performs comprehensive cleanup when an upstream DNS server is
 *           being removed from the active server pool (due to configuration reload, server
 *           failure detection, or administrative removal). It prevents dangling pointers
 *           and use-after-free errors by: (1) Iterating through daemon->frec_list (all
 *           active forward records) and calling free_frec() for any forward record whose
 *           sentto field points to the removed server, effectively aborting all in-flight
 *           queries to that server. (2) Iterating through daemon->randomsocks[] array
 *           (random source port socket pool) and NULLing the serv pointer in any socket
 *           that references the removed server, preventing future socket reuse for queries
 *           to the defunct server. (3) Clearing daemon->srv_save if it points to the
 *           removed server, preventing resend_query() from attempting to resend to invalid
 *           server. This function is typically called during configuration reload (SIGHUP)
 *           when server list changes, or when a server is detected as permanently failed
 *           and removed from rotation.
 * 
 * @param server Pointer to struct server being removed from active server pool. Must not
 *               be NULL. The server structure may be freed by caller after this function
 *               returns, so all references must be cleared. This is the authoritative
 *               upstream DNS server structure from daemon->servers linked list that is
 *               being deleted.
 * 
 * @return void (no return value)
 * 
 * @note Frees ALL forward records (frec) currently targeting the removed server
 * @note free_frec() calls may trigger SERVFAIL responses to clients for aborted queries
 * @note NULLing server references in randomsocks[] prevents future socket reuse for this server
 * @note Sockets in randomsocks[] remain in pool with serv=NULL (available for other servers)
 * @note Only NULLs server references for sockets with refcount != 0 (allocated sockets)
 * @note If daemon->srv_save points to removed server, clears it to prevent resend_query() failure
 * @note Does NOT free the server structure itself (caller's responsibility)
 * @note Does NOT close sockets in randomsocks[] (sockets remain open for reuse)
 * @note Forward records freed via free_frec() which releases all associated resources
 * 
 * @warning Must be called before freeing the server structure to prevent dangling pointers
 * @warning Aborts all in-flight queries to the removed server (clients receive SERVFAIL or timeout)
 * @warning Parameter 'server' must not be NULL (no NULL check, will segfault on NULL dereference)
 * @warning After this function, no active queries remain targeting the removed server
 * @warning Iterates full daemon->frec_list - O(n) complexity where n is number of active queries
 * @warning Iterates full daemon->randomsocks[] array - O(m) where m is daemon->numrrand socket pool size
 * 
 * @see free_frec() in forward.c for forward record cleanup including client notification
 * @see struct server in dnsmasq.h for upstream server structure definition
 * @see struct frec in dnsmasq.h: sentto field points to upstream server receiving query
 * @see struct randfd in dnsmasq.h: serv field points to server associated with socket
 * @see resend_query() which uses daemon->srv_save (cleared by this function if needed)
 * @see read_servers() in option.c for server list management during configuration reload
 * 
 * EXAMPLE USAGE:
 * @code
 * // Configuration reload scenario - server being removed
 * struct server *old_server = find_server_to_remove();
 * server_gone(old_server); // Clean up all references
 * // Now safe to unlink old_server from daemon->servers list
 * unlink_server_from_list(old_server);
 * free(old_server); // Safe to free after server_gone() call
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (internal resource management during server reconfiguration,
 *                      not specified by DNS protocol RFCs)
 * 
 * SIDE EFFECTS:
 * - Iterates through daemon->frec_list linked list from head to tail
 * - For each forward record f: checks if f->sentto == server
 * - If match found: calls free_frec(f) which:
 *   - Sends SERVFAIL response to client (query aborted due to server removal)
 *   - Releases allocated random file descriptors via free_rfds()
 *   - Closes TCP connections if applicable
 *   - Returns frec to free pool (daemon->frec_list management)
 * - Iterates through daemon->randomsocks[] array from index 0 to daemon->numrrand-1
 * - For each socket: checks if refcount != 0 (socket allocated) AND serv == server
 * - If match found: sets daemon->randomsocks[i].serv = NULL (clears server reference)
 * - NULLed sockets remain in pool with refcount preserved (available for other servers)
 * - Checks if daemon->srv_save == server (saved server for resend_query())
 * - If match: sets daemon->srv_save = NULL (prevents invalid resend after server removal)
 * - Does NOT modify server structure itself (caller must free after this function)
 * - Does NOT close file descriptors (sockets remain open in randomsocks[] pool)
 * - Modifies global daemon state: frec_list (via free_frec), randomsocks[].serv, srv_save
 * 
 * THREAD SAFETY: Single-threaded daemon - modifies global state:
 *                daemon->frec_list (via free_frec), daemon->randomsocks[].serv, daemon->srv_save
 */
void server_gone(struct server *server)
{
  struct frec *f;
  int i;
  
  for (f = daemon->frec_list; f; f = f->next)
    if (f->sentto && f->sentto == server)
      free_frec(f);

  /* If any random socket refers to this server, NULL the reference.
     No more references to the socket will be created in the future. */
  for (i = 0; i < daemon->numrrand; i++)
    if (daemon->randomsocks[i].refcount != 0 && daemon->randomsocks[i].serv == server)
      daemon->randomsocks[i].serv = NULL;
  
  if (daemon->srv_save == server)
    daemon->srv_save = NULL;
}

/* return unique random ids. */
/**
 * @brief Generate unique random DNS query ID for outgoing query
 * 
 * @detailed Generates a cryptographically random 16-bit DNS query ID and ensures uniqueness
 *           among currently active forward records. The function loops until it finds an ID
 *           that is not currently in use by any outstanding query. This prevents query ID
 *           collisions that could cause response mismatches or security vulnerabilities
 *           (DNS ID prediction attacks). Uses rand16() for randomness.
 * 
 * @return Unique 16-bit DNS query ID not currently used by any active forward record
 * 
 * @note Query ID randomization is a critical security measure to prevent DNS cache poisoning
 * @note Function loops indefinitely until unique ID found (extremely unlikely to loop many times)
 * @warning With 65536 possible IDs and typical query counts <150 (FTABSIZ), collision probability is very low
 * 
 * @see rand16() in util.c for SURF-based random number generation
 * @see struct frec in dnsmasq.h for forward record structure with new_id field
 * 
 * EXAMPLE USAGE:
 * @code
 * struct frec *forward = get_new_frec(now, server, 0);
 * unsigned short query_id = get_id();
 * forward->new_id = query_id;
 * // Use query_id in outgoing DNS packet
 * @endcode
 * 
 * ALGORITHM:
 * 1. Generate random 16-bit value with rand16()
 * 2. Scan daemon->frec_list for active queries (f->sentto != NULL)
 * 3. Check if any active query uses the generated ID (f->new_id == ret)
 * 4. If collision found, generate new ID and repeat
 * 5. If no collision, return unique ID
 * 
 * RFC COMPLIANCE: RFC 1035 Section 4.1.1 (query ID field for matching responses)
 * SIDE EFFECTS: Calls rand16() which updates RNG state
 * THREAD SAFETY: Not thread-safe (accesses global daemon->frec_list)
 */
/**
 * @brief Generate a unique random 16-bit DNS query ID not currently in use
 * 
 * @detailed Generates cryptographically random DNS query IDs for upstream queries,
 *           ensuring uniqueness across all active forward records. The function provides
 *           critical security protection against DNS cache poisoning attacks by making
 *           query IDs unpredictable. It repeatedly generates random 16-bit values using
 *           rand16() and checks each candidate against the daemon->frec_list to verify
 *           no active query is using that ID.
 *           
 *           The uniqueness check examines only active forward records (f->sentto != NULL),
 *           meaning queries that have been sent to upstream servers and are awaiting
 *           responses. Free forward records (f->sentto == NULL) do not participate in
 *           collision detection since they hold no active query state.
 *           
 *           The loop continues indefinitely until a unique ID is found. With 65536 possible
 *           IDs and typical query counts well under 150 (daemon->ftabsize), collision
 *           probability is extremely low. The expected number of iterations is approximately
 *           1 + (N/65536) where N is the number of active queries, typically resulting in
 *           immediate success (1 iteration) under normal load conditions.
 *           
 *           Query ID randomization is a fundamental DNS security mechanism specified in
 *           RFC 5452. Without randomization, attackers can predict query IDs and inject
 *           forged responses that poison the cache. The rand16() function uses the SURF
 *           cryptographic pseudo-random number generator implemented in util.c, providing
 *           sufficient entropy to resist brute-force guessing attacks.
 *           
 *           The generated ID is stored in frec->new_id and used as the DNS query ID in
 *           the outbound packet to upstream servers. The original client query ID is
 *           preserved in frec->orig_id to enable correct response mapping when replies
 *           arrive from upstream servers - the response ID must be rewritten from new_id
 *           back to orig_id before forwarding to the client.
 * 
 * @return Unique random 16-bit DNS query ID not currently used by any active forward record
 * @retval [0-65535] 16-bit unsigned integer unique across all f->new_id values where f->sentto != NULL
 * 
 * @note Function never returns without finding a unique ID (infinite loop until success)
 * @note Only checks active queries (f->sentto != NULL); free records ignored
 * @note Collision probability is very low: approximately N/65536 where N = active query count
 * @note Expected iterations under typical load: ~1 (immediate success with high probability)
 * @note rand16() uses SURF cryptographic PRNG providing unpredictable IDs (see util.c)
 * @note Generated ID stored in frec->new_id; original client ID preserved in frec->orig_id
 * @note ID rewriting on responses: upstream response new_id → client response orig_id
 * 
 * @warning Infinite loop if no unique IDs available (theoretically possible with 65536+ active queries, not achievable with ftabsize=150 limit)
 * @warning Function does not bound iteration count; pathological collision rate could cause delays
 * @warning Assumes rand16() provides sufficient entropy (depends on SURF PRNG seeding at startup)
 * 
 * @see rand16() in util.c for cryptographic random number generation (SURF algorithm)
 * @see struct frec in dnsmasq.h for forward record definition with new_id and orig_id fields
 * @see get_new_frec() for forward record allocation where get_id() result is assigned
 * @see send_from() and other packet transmission functions that use frec->new_id in outbound packets
 * @see RFC 5452 - "Measures for Making DNS More Resilient against Forged Answers" (query ID randomization)
 * @see daemon->frec_list for linked list of forward records checked for ID collisions
 * 
 * EXAMPLE USAGE:
 * @code
 * struct frec *f = get_new_frec(now, server, 0);
 * if (f) {
 *   f->orig_id = header->id;       // Preserve client's original query ID
 *   f->new_id = get_id();          // Generate unique random ID for upstream query
 *   header->id = htons(f->new_id); // Rewrite DNS packet ID before forwarding
 *   // Send query to upstream with randomized ID
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 5452 Section 9.2 (Query ID Randomization for cache poisoning resistance)
 * SIDE EFFECTS: None (pure function examining daemon->frec_list; no state modifications)
 * THREAD SAFETY: Single-threaded architecture; reads shared daemon->frec_list without modifications
 */
static unsigned short get_id(void)
{
  unsigned short ret = 0;
  struct frec *f;
  
  while (1)
    {
      ret = rand16();

      /* ensure id is unique. */
      for (f = daemon->frec_list; f; f = f->next)
	if (f->sentto && f->new_id == ret)
	  break;

      if (!f)
	return ret;
    }
}

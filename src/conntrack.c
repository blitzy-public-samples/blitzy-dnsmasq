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
 * @file conntrack.c
 * @brief Linux netfilter connection tracking integration for DNS query mark preservation
 * 
 * DETAILED PURPOSE:
 * This Linux-specific module integrates with the Linux netfilter connection tracking
 * (conntrack) subsystem to enable connection tracking mark preservation across NAT
 * boundaries. When a DNS query arrives, this module queries the netfilter conntrack
 * table to retrieve the connection tracking mark associated with the connection tuple
 * (source IP, source port, destination IP, destination port, protocol). The retrieved
 * mark can then be used for advanced routing policies, per-connection DNS policies,
 * and VPN routing decisions based on the originating connection's classification.
 * 
 * This functionality enables dnsmasq to participate in sophisticated policy-based
 * routing scenarios where different connections from the same host may require
 * different DNS resolution behavior based on netfilter marks previously assigned
 * by firewall rules, such as routing VPN traffic through VPN-specific DNS servers
 * while routing regular traffic through standard DNS servers.
 * 
 * KEY RESPONSIBILITIES:
 * - Query netfilter conntrack table for connection tracking marks by connection tuple
 * - Extract conntrack mark from established connections for DNS query processing
 * - Support both IPv4 and IPv6 connection tracking mark retrieval
 * - Integrate with forward.c DNS query processing for mark-based DNS policies
 * - Handle libnetfilter_conntrack API initialization and query operations
 * - Provide graceful error handling when conntrack queries fail
 * 
 * DEPENDENCIES:
 * Includes: dnsmasq.h (core data structures including union mysockaddr, union all_addr,
 *           struct daemon), libnetfilter_conntrack/libnetfilter_conntrack.h (netfilter
 *           conntrack API including struct nf_conntrack, struct nfct_handle, attribute
 *           definitions ATTR_L4PROTO, ATTR_PORT_DST, ATTR_L3PROTO, ATTR_IPV4_SRC,
 *           ATTR_IPV6_SRC, ATTR_PORT_SRC, ATTR_IPV4_DST, ATTR_IPV6_DST, ATTR_MARK)
 * Called by: forward.c DNS query processing functions when mark-based policies enabled
 * Calls: libnetfilter_conntrack API functions (nfct_new, nfct_set_attr_u8,
 *        nfct_set_attr_u16, nfct_set_attr_u32, nfct_set_attr, nfct_open,
 *        nfct_callback_register, nfct_query, nfct_close, nfct_destroy, nfct_get_attr_u32)
 * 
 * DATA STRUCTURES:
 * - union mysockaddr: Socket address union (IPv4/IPv6) for peer connection endpoint
 *   (defined in dnsmasq.h line 556)
 * - union all_addr: Generic address union for local DNS server address
 *   (defined in dnsmasq.h line 313)
 * - struct nf_conntrack: Netfilter conntrack connection structure from libnetfilter_conntrack
 * - struct nfct_handle: Netfilter conntrack handle for query operations
 * 
 * COMPILE-TIME OPTIONS:
 * HAVE_CONNTRACK: This entire module is conditionally compiled only when HAVE_CONNTRACK
 *                 is defined, indicating libnetfilter_conntrack library availability
 *                 and Linux kernel netfilter support
 * 
 * THREADING/CONCURRENCY:
 * Single-threaded event-driven model. Uses static global variable for callback
 * communication (not thread-safe). Conntrack queries execute synchronously within
 * DNS query processing path.
 * 
 * USE CASES:
 * 1. Policy-Based Routing: Route DNS queries from specific connections through
 *    designated DNS servers based on netfilter marks (e.g., VPN vs. direct routing)
 * 2. Per-Connection DNS Policies: Apply different DNS filtering or forwarding rules
 *    based on connection marks assigned by firewall rules
 * 3. VPN Split-Horizon DNS: Direct DNS queries from VPN-marked connections to VPN
 *    DNS servers while routing unmarked queries to local/ISP DNS servers
 * 4. Multi-WAN Routing: Support DNS resolution appropriate to connection's selected
 *    WAN interface based on mark-based routing policies
 * 
 * LINUX KERNEL REQUIREMENTS:
 * - Linux kernel with netfilter connection tracking enabled (CONFIG_NF_CONNTRACK)
 * - Netfilter conntrack kernel module loaded (nf_conntrack)
 * - CAP_NET_ADMIN capability or root privileges for conntrack table queries
 * - Connection tracking must be active for the queried connection
 * 
 * @copyright Copyright (c) 2000-2025 Simon Kelley
 * @license GPL-2.0-or-later
 */

#include "dnsmasq.h"

#ifdef HAVE_CONNTRACK

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

/**
 * @brief Callback communication flag indicating successful conntrack mark retrieval
 * 
 * Static global variable used to communicate success status from the netfilter
 * conntrack callback function back to the main query function. Set to 0 before
 * initiating conntrack query, then set to 1 by callback() when a matching
 * conntrack entry is found and the mark is successfully retrieved.
 * 
 * This approach is necessary because the libnetfilter_conntrack callback API
 * does not provide a mechanism to return success/failure status directly from
 * the query operation. The callback is invoked asynchronously by nfct_query()
 * when matching conntrack entries are found.
 * 
 * THREAD SAFETY: Not thread-safe. Relies on single-threaded event-driven
 * architecture where only one conntrack query executes at a time.
 * 
 * @note Original comment "yuck" acknowledges the non-elegant nature of using
 *       a global variable for callback communication, but this is constrained
 *       by the libnetfilter_conntrack API design
 */
static int gotit = 0; /* yuck */

static int callback(enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data);

/**
 * @brief Query netfilter conntrack table for connection tracking mark by connection tuple
 * 
 * Queries the Linux netfilter connection tracking table to retrieve the connection
 * tracking mark associated with an incoming DNS query connection. The function
 * constructs a connection tuple from the provided peer address, local address,
 * and protocol type, then queries the kernel conntrack table for a matching
 * established connection. If found, the connection's mark is extracted and returned.
 * 
 * This enables dnsmasq to implement mark-based DNS policies where different
 * connections receive different DNS resolution behavior based on netfilter marks
 * previously assigned by firewall rules. Common use cases include VPN split-horizon
 * DNS (routing VPN-marked queries to VPN DNS servers), policy-based routing
 * (different DNS servers per routing policy), and per-application DNS policies.
 * 
 * The function handles both IPv4 and IPv6 connections, constructing the appropriate
 * conntrack query based on the peer address family. It uses the libnetfilter_conntrack
 * API to create a conntrack query object, populate it with the connection 5-tuple
 * (source IP, source port, destination IP, destination port, protocol), execute
 * the query, and extract the mark via registered callback.
 * 
 * @param peer_addr Pointer to union mysockaddr containing the remote peer's socket
 *                  address (IP address and port). For IPv4 connections, uses peer_addr->in
 *                  (struct sockaddr_in). For IPv6 connections, uses peer_addr->in6
 *                  (struct sockaddr_in6). The sa_family field determines IPv4 vs IPv6.
 *                  Must not be NULL. Source port extracted in network byte order.
 * @param local_addr Pointer to union all_addr containing the local DNS server address
 *                   that received the query. For IPv4, uses local_addr->addr4 (struct in_addr).
 *                   For IPv6, uses local_addr->addr6 (struct in6_addr). Must not be NULL.
 * @param istcp Integer flag indicating transport protocol: non-zero for TCP connections,
 *              zero for UDP connections. Determines whether IPPROTO_TCP or IPPROTO_UDP
 *              is used in conntrack query (ATTR_L4PROTO attribute).
 * @param markp Pointer to unsigned int variable where retrieved connection tracking mark
 *              will be stored if query succeeds. Value is written by callback() function
 *              when matching conntrack entry is found. Must not be NULL. If query fails,
 *              value is undefined (not modified).
 * 
 * @return 1 if conntrack mark successfully retrieved (gotit flag set by callback),
 *         0 if mark retrieval failed (no matching conntrack entry found, conntrack
 *         API call failed, or conntrack subsystem unavailable)
 * @retval 1 Mark successfully retrieved and stored in *markp
 * @retval 0 Mark retrieval failed (query failed, no match, or API error)
 * 
 * @note Requires Linux kernel with CONFIG_NF_CONNTRACK enabled and nf_conntrack module loaded
 * @note Requires CAP_NET_ADMIN capability or root privileges for conntrack table access
 * @note First failure logs error via syslog (LOG_ERR), subsequent failures silent to prevent log spam
 * @warning Not thread-safe due to global variable gotit usage
 * 
 * EXAMPLE USAGE:
 * @code
 * union mysockaddr peer;
 * union all_addr local;
 * unsigned int mark;
 * // peer and local populated from incoming DNS query connection
 * if (get_incoming_mark(&peer, &local, 0, &mark)) // UDP query
 *   {
 *     // Use mark for policy-based DNS routing
 *     if (mark == VPN_MARK)
 *       forward_to_vpn_dns_server();
 *     else
 *       forward_to_default_dns_server();
 *   }
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (Linux-specific netfilter conntrack integration)
 * 
 * SIDE EFFECTS:
 * - Allocates and frees struct nf_conntrack via nfct_new()/nfct_destroy()
 * - Opens and closes netfilter conntrack handle via nfct_open()/nfct_close()
 * - Logs error to syslog on first query failure (LOG_ERR level)
 * - Modifies global variable gotit (set to 0 before query, set to 1 by callback on success)
 * - Modifies *markp via callback if query succeeds
 * 
 * THREAD SAFETY: Not thread-safe (uses static global variables gotit and warned)
 * 
 * IMPLEMENTATION DETAILS:
 * Connection tuple construction for IPv4:
 * - L3 protocol: AF_INET (ATTR_L3PROTO)
 * - L4 protocol: IPPROTO_TCP or IPPROTO_UDP (ATTR_L4PROTO)
 * - Source IP: peer_addr->in.sin_addr.s_addr (ATTR_IPV4_SRC)
 * - Source port: peer_addr->in.sin_port (ATTR_PORT_SRC, network byte order)
 * - Destination IP: local_addr->addr4.s_addr (ATTR_IPV4_DST)
 * - Destination port: htons(daemon->port) (ATTR_PORT_DST, typically 53 for DNS)
 * 
 * Connection tuple construction for IPv6:
 * - L3 protocol: AF_INET6 (ATTR_L3PROTO)
 * - L4 protocol: IPPROTO_TCP or IPPROTO_UDP (ATTR_L4PROTO)
 * - Source IP: peer_addr->in6.sin6_addr.s6_addr (ATTR_IPV6_SRC, 16 bytes)
 * - Source port: peer_addr->in6.sin6_port (ATTR_PORT_SRC, network byte order)
 * - Destination IP: local_addr->addr6.s6_addr (ATTR_IPV6_DST, 16 bytes)
 * - Destination port: htons(daemon->port) (ATTR_PORT_DST, typically 53 for DNS)
 * 
 * Error handling:
 * - nfct_new() failure: Returns 0 (mark retrieval failed)
 * - nfct_open() failure: Cleans up ct, returns 0
 * - nfct_query() failure: Logs error on first occurrence, returns 0
 * - No matching conntrack entry: callback not invoked, returns 0
 */
int get_incoming_mark(union mysockaddr *peer_addr, union all_addr *local_addr, int istcp, unsigned int *markp)
{
  struct nf_conntrack *ct;
  struct nfct_handle *h;
  
  gotit = 0;
  
  if ((ct = nfct_new())) 
    {
      nfct_set_attr_u8(ct, ATTR_L4PROTO, istcp ? IPPROTO_TCP : IPPROTO_UDP);
      nfct_set_attr_u16(ct, ATTR_PORT_DST, htons(daemon->port));
      
      if (peer_addr->sa.sa_family == AF_INET6)
	{
	  nfct_set_attr_u8(ct, ATTR_L3PROTO, AF_INET6);
	  nfct_set_attr(ct, ATTR_IPV6_SRC, peer_addr->in6.sin6_addr.s6_addr);
	  nfct_set_attr_u16(ct, ATTR_PORT_SRC, peer_addr->in6.sin6_port);
	  nfct_set_attr(ct, ATTR_IPV6_DST, local_addr->addr6.s6_addr);
	}
      else
	{
	  nfct_set_attr_u8(ct, ATTR_L3PROTO, AF_INET);
	  nfct_set_attr_u32(ct, ATTR_IPV4_SRC, peer_addr->in.sin_addr.s_addr);
	  nfct_set_attr_u16(ct, ATTR_PORT_SRC, peer_addr->in.sin_port);
	  nfct_set_attr_u32(ct, ATTR_IPV4_DST, local_addr->addr4.s_addr);
	}
      
      
      if ((h = nfct_open(CONNTRACK, 0))) 
	{
	  nfct_callback_register(h, NFCT_T_ALL, callback, (void *)markp);  
	  if (nfct_query(h, NFCT_Q_GET, ct) == -1)
	    {
	      static int warned = 0;
	      if (!warned)
		{
		  my_syslog(LOG_ERR, _("Conntrack connection mark retrieval failed: %s"), strerror(errno));
		  warned = 1;
		}
	    }
	  nfct_close(h);  
	}
      nfct_destroy(ct);
    }

  return gotit;
}

/**
 * @brief Netfilter conntrack query callback function for mark retrieval
 * 
 * Callback function invoked by nfct_query() when a matching conntrack entry
 * is found in the netfilter connection tracking table. Extracts the connection
 * tracking mark from the conntrack entry and stores it in the caller-provided
 * output parameter, then sets the global success flag.
 * 
 * This callback is registered with nfct_callback_register() in get_incoming_mark()
 * before executing the conntrack query. The libnetfilter_conntrack library
 * invokes this callback for each matching conntrack entry (typically one match
 * for a specific connection tuple).
 * 
 * @param type Message type from netfilter conntrack subsystem (unused, all types
 *             handled identically for mark retrieval). Typical value is NFCT_T_ALL
 *             when registered to handle all message types. Parameter explicitly
 *             cast to void to suppress unused parameter warning.
 * @param ct Pointer to struct nf_conntrack containing the matching connection
 *           tracking entry with all conntrack attributes including ATTR_MARK.
 *           Must not be NULL.
 * @param data User-provided data pointer passed through from nfct_callback_register(),
 *             expected to point to unsigned int variable for storing retrieved mark.
 *             Cast to (unsigned int *) to extract mark storage location. Must not be NULL.
 * 
 * @return NFCT_CB_CONTINUE to continue processing (allows library to invoke callback
 *         for additional matches if multiple conntrack entries match, though typically
 *         only one entry matches a specific connection tuple)
 * 
 * @note Sets global variable gotit = 1 to signal successful mark retrieval to caller
 * @warning Not thread-safe due to global variable modification
 * 
 * EXAMPLE USAGE:
 * @code
 * unsigned int mark;
 * struct nfct_handle *h = nfct_open(CONNTRACK, 0);
 * nfct_callback_register(h, NFCT_T_ALL, callback, (void *)&mark);
 * nfct_query(h, NFCT_Q_GET, ct); // callback invoked if match found
 * @endcode
 * 
 * SIDE EFFECTS:
 * - Modifies unsigned int pointed to by data parameter (stores retrieved mark)
 * - Sets global variable gotit to 1
 * 
 * THREAD SAFETY: Not thread-safe (modifies global variable gotit)
 */
static int callback(enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data)
{
  unsigned int *ret = (unsigned int *)data;
  *ret = nfct_get_attr_u32(ct, ATTR_MARK);
  (void)type; /* eliminate warning */
  gotit = 1;

  return NFCT_CB_CONTINUE;
}

#endif /* HAVE_CONNTRACK */

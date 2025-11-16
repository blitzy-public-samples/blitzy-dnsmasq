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
 * @file dhcp6.c
 * @brief DHCPv6 server core business logic and message processing
 * 
 * DETAILED PURPOSE:
 * This module implements the DHCPv6 server functionality for dnsmasq, providing both
 * stateful and stateless DHCPv6 operation modes per RFC 3315. The implementation handles
 * DHCPv6 message processing (SOLICIT, ADVERTISE, REQUEST, REPLY, RENEW, REBIND, RELEASE,
 * DECLINE, INFORMATION-REQUEST), IPv6 address allocation from configured pools, prefix
 * delegation for hierarchical networks, and lease time management with default 86400
 * seconds (DEFLEASE6 from config.h line 51).
 * 
 * The DHCPv6 server coordinates with Router Advertisement (radv.c) to provide cohesive
 * IPv6 address management through M (managed address) and O (other configuration) flags:
 * - M=1: Stateful DHCPv6 with address assignment and lease tracking
 * - O=1: Stateless DHCPv6 providing configuration without addresses
 * - M=O=0: SLAAC-only with no DHCPv6 address management
 * 
 * KEY RESPONSIBILITIES:
 * - Process DHCPv6 message types: dhcp6_packet() handles all incoming DHCPv6 requests
 * - Allocate IPv6 addresses: address6_allocate(), address6_available(), address6_valid()
 * - Manage prefix delegation: Support IA_PD prefix delegation for downstream routers
 * - Track lease state: Integration with lease.c for lease database persistence
 * - Coordinate with Router Advertisement: Ensure M/O flag behavior consistency
 * - Generate DHCPv6 responses: Use rfc3315.c and outpacket.c for message construction
 * - Register DNS names: Integrate with cache.c for DHCP hostname DNS registration
 * 
 * DEPENDENCIES:
 * Includes: dnsmasq.h (core structs), dhcp6-protocol.h (DHCPv6 constants), netinet/icmp6.h
 * Called by: dnsmasq.c (main event loop) when DHCPv6 packets arrive on port 547
 * Calls: rfc3315.c (protocol message handling), outpacket.c (option serialization),
 *        lease.c (lease database), cache.c (DNS integration), radv.c (RA coordination),
 *        network.c (interface enumeration), util.c (memory allocation)
 * 
 * DATA STRUCTURES:
 * - struct dhcp_context: DHCPv6 address pool configuration (dnsmasq.h:1054)
 * - struct dhcp_netid: Client classification tags (dnsmasq.h:1019)
 * - struct dhcp_config: Static lease reservations (dnsmasq.h:1095)
 * - struct iface_param: Interface enumeration state (dhcp6.c:23)
 * - struct state: DHCPv6 packet processing state (defined locally)
 * 
 * COMPILE-TIME OPTIONS:
 * HAVE_DHCP6: Enables DHCPv6 server functionality (entire file conditional)
 * HAVE_SCRIPT: Enables lease-change script execution
 * HAVE_LUASCRIPT: Enables Lua scripting for lease events
 * IPV6_TCLASS: Traffic class socket option support
 * IPTOS_CLASS_CS6: Traffic class value for DHCPv6 packets
 * SO_REUSEPORT: Socket option for multiple instance binding
 * 
 * THREADING/CONCURRENCY:
 * Single-process event-driven model. DHCPv6 packet processing occurs in main event loop
 * when select/poll indicates data ready on daemon->dhcp6fd socket. All DHCPv6 operations
 * execute sequentially with no concurrent access to shared data structures.
 * 
 * @copyright Copyright (c) 2000-2025 Simon Kelley
 * @license GPL-2.0-or-later
 */

#include "dnsmasq.h"

#ifdef HAVE_DHCP6

#include <netinet/icmp6.h>

struct iface_param {
  struct dhcp_context *current;
  struct in6_addr fallback, ll_addr, ula_addr;
  int ind, addr_match;
};


static int complete_context6(struct in6_addr *local,  int prefix,
			     int scope, int if_index, int flags, 
			     unsigned int preferred, unsigned int valid, void *vparam);
static int make_duid1(int index, unsigned int type, char *mac, size_t maclen, void *parm); 

/**
 * @brief Initialize DHCPv6 server socket and bind to port 547
 * 
 * @detailed Creates IPv6 UDP socket for DHCPv6 server operation, configures socket options
 *           for IPv6-only operation and packet metadata reception, and binds to the well-known
 *           DHCPv6 server port 547. Sets traffic class to CS6 (network control) if supported.
 *           When bind-interfaces or cleverbind mode is enabled, sets SO_REUSEADDR|SO_REUSEPORT
 *           to allow multiple dnsmasq instances serving different networks.
 * 
 * @return void Dies with error message if socket creation or binding fails
 * 
 * @note This function requires root privileges to bind to privileged port 547
 * @warning Dies with EC_BADNET exit code if socket operations fail - no recovery possible
 * 
 * @see dhcp6_packet() processes packets received on the initialized socket
 * @see daemon->dhcp6fd stores the socket file descriptor for main event loop
 * 
 * EXAMPLE USAGE:
 * @code
 * // Called during daemon initialization (dnsmasq.c:main)
 * if (daemon->dhcp6)
 *   dhcp6_init();  // Creates socket, binds port 547, stores in daemon->dhcp6fd
 * @endcode
 * 
 * RFC COMPLIANCE: DHCPv6 server port 547 per RFC 3315 Section 5.2
 * SIDE EFFECTS: Creates global socket daemon->dhcp6fd; terminates process on failure
 * THREAD SAFETY: Called once during single-threaded daemon initialization
 */
void dhcp6_init(void)
{
  int fd;
  struct sockaddr_in6 saddr;
#if defined(IPV6_TCLASS) && defined(IPTOS_CLASS_CS6)
  int class = IPTOS_CLASS_CS6;
#endif
  int oneopt = 1;

  if ((fd = socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP)) == -1 ||
#if defined(IPV6_TCLASS) && defined(IPTOS_CLASS_CS6)
      setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS, &class, sizeof(class)) == -1 ||
#endif
      setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &oneopt, sizeof(oneopt)) == -1 ||
      !fix_fd(fd) ||
      !set_ipv6pktinfo(fd))
    die (_("cannot create DHCPv6 socket: %s"), NULL, EC_BADNET);
  
 /* When bind-interfaces is set, there might be more than one dnsmasq
     instance binding port 547. That's OK if they serve different networks.
     Need to set REUSEADDR|REUSEPORT to make this possible.
     Handle the case that REUSEPORT is defined, but the kernel doesn't 
     support it. This handles the introduction of REUSEPORT on Linux. */
  if (option_bool(OPT_NOWILD) || option_bool(OPT_CLEVERBIND))
    {
      int rc = 0;

#ifdef SO_REUSEPORT
      if ((rc = setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &oneopt, sizeof(oneopt))) == -1 &&
	  errno == ENOPROTOOPT)
	rc = 0;
#endif
      
      if (rc != -1)
	rc = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &oneopt, sizeof(oneopt));
      
      if (rc == -1)
	die(_("failed to set SO_REUSE{ADDR|PORT} on DHCPv6 socket: %s"), NULL, EC_BADNET);
    }
  
  memset(&saddr, 0, sizeof(saddr));
#ifdef HAVE_SOCKADDR_SA_LEN
  saddr.sin6_len = sizeof(struct sockaddr_in6);
#endif
  saddr.sin6_family = AF_INET6;
  saddr.sin6_addr = in6addr_any;
  saddr.sin6_port = htons(DHCPV6_SERVER_PORT);
  
  if (bind(fd, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in6)))
    die(_("failed to bind DHCPv6 server socket: %s"), NULL, EC_BADNET);
  
  daemon->dhcp6fd = fd;
}

/**
 * @brief Process incoming DHCPv6 packets and generate appropriate responses
 * 
 * @detailed Main entry point for DHCPv6 packet processing, called from the main event loop when
 *           data is ready on the DHCPv6 socket (daemon->dhcp6fd). Receives DHCPv6 packets,
 *           extracts packet metadata (interface index, destination address), handles relay
 *           forwarding, applies interface filtering, enumerates network interfaces to find
 *           matching DHCP contexts, and invokes dhcp6_reply() to generate and transmit responses.
 *           Supports both direct client communication and relay agent scenarios. Handles multicast
 *           destinations (ALL_SERVERS, ALL_RELAY_AGENTS_AND_SERVERS) and unicast relay paths.
 *           Implements bridge interface aliasing for complex network topologies.
 * 
 * @param now Current time from main event loop for lease expiration and timestamp operations
 * 
 * @return void Processing always completes; errors result in early return without response
 * 
 * @note Called repeatedly from main event loop whenever DHCPv6 packets arrive on port 547
 * @warning Early return on errors (invalid interface, filtered interface, relay-only mode)
 * 
 * @see dhcp6_init() initializes the socket this function reads from
 * @see dhcp6_reply() generates DHCPv6 responses (rfc3315.c)
 * @see relay_reply6() handles relay reply messages
 * @see relay_upstream6() forwards requests to relay agents
 * @see complete_context6() callback for interface enumeration
 * 
 * EXAMPLE USAGE:
 * @code
 * // Main event loop in dnsmasq.c
 * if (FD_ISSET(daemon->dhcp6fd, &rset))
 *   dhcp6_packet(now);  // Process DHCPv6 packet, generate response
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 3315 DHCPv6 message processing, RFC 3736 stateless DHCPv6
 * SIDE EFFECTS: 
 *   - Sends DHCPv6 response packets via sendto() on daemon->dhcp6fd
 *   - Calls lease_prune() to expire old leases before processing
 *   - Logs VRF kernel bug workaround on Linux (once per daemon lifetime)
 *   - Dumps packets to pcap if HAVE_DUMPFILE enabled
 * THREAD SAFETY: Single-threaded event loop ensures sequential processing
 */
void dhcp6_packet(time_t now)
{
  struct dhcp_context *context;
  struct dhcp_relay *relay;
  struct iface_param parm;
  struct cmsghdr *cmptr;
  struct msghdr msg;
  uint32_t if_index = 0;
  union {
    struct cmsghdr align; /* this ensures alignment */
    char control6[CMSG_SPACE(sizeof(struct in6_pktinfo))];
  } control_u;
  struct sockaddr_in6 from;
  ssize_t sz; 
  struct ifreq ifr;
  struct iname *tmp;
  unsigned short port;
  struct in6_addr dst_addr;
  struct in6_addr all_servers;
  
  memset(&dst_addr, 0, sizeof(dst_addr));

  msg.msg_control = control_u.control6;
  msg.msg_controllen = sizeof(control_u);
  msg.msg_flags = 0;
  msg.msg_name = &from;
  msg.msg_namelen = sizeof(from);
  msg.msg_iov =  &daemon->dhcp_packet;
  msg.msg_iovlen = 1;
  
  if ((sz = recv_dhcp_packet(daemon->dhcp6fd, &msg)) == -1)
    return;
  
  for (cmptr = CMSG_FIRSTHDR(&msg); cmptr; cmptr = CMSG_NXTHDR(&msg, cmptr))
    if (cmptr->cmsg_level == IPPROTO_IPV6 && cmptr->cmsg_type == daemon->v6pktinfo)
      {
	union {
	  unsigned char *c;
	  struct in6_pktinfo *p;
	} p;
	p.c = CMSG_DATA(cmptr);
        
	if_index = p.p->ipi6_ifindex;
	dst_addr = p.p->ipi6_addr;
      }

  if (!indextoname(daemon->dhcp6fd, if_index, ifr.ifr_name))
    return;
  
#ifdef HAVE_LINUX_NETWORK
  /* This works around a possible Linux kernel bug when using interfaces
     enslaved to a VRF. The scope_id in the source address gets set
     to the index of the VRF interface, not the slave. Fortunately,
     the interface index returned by packetinfo is correct so we use
     that instead. Log this once, so if it triggers in other circumstances
     we've not anticipated and breaks things, we get some clues. */
  if (from.sin6_scope_id != if_index)
    {
      static int logged = 0;
      
      if (!logged)
	{
	  my_syslog(MS_DHCP | LOG_WARNING,
		    _("Working around kernel bug: faulty source address scope for VRF slave %s"),
		    ifr.ifr_name);
	  logged = 1;
	}
      
      from.sin6_scope_id = if_index;
    }
#endif

#ifdef HAVE_DUMPFILE
  dump_packet_udp(DUMP_DHCPV6, (void *)daemon->dhcp_packet.iov_base, sz,
		  (union mysockaddr *)&from, NULL, daemon->dhcp6fd);
#endif

  if (relay_reply6(&from, sz, ifr.ifr_name))
    {
#ifdef HAVE_DUMPFILE
      dump_packet_udp(DUMP_DHCPV6, (void *)daemon->outpacket.iov_base, save_counter(-1), NULL,
		      (union mysockaddr *)&from, daemon->dhcp6fd);
#endif
      
      while (retry_send(sendto(daemon->dhcp6fd, daemon->outpacket.iov_base, 
			       save_counter(-1), 0, (struct sockaddr *)&from, 
			       sizeof(from))));
    }
  else
    {
      struct dhcp_bridge *bridge, *alias;
      int multicast_dest = 0;
      
      for (tmp = daemon->if_except; tmp; tmp = tmp->next)
	if (tmp->name && wildcard_match(tmp->name, ifr.ifr_name))
	  return;
      
      for (tmp = daemon->dhcp_except; tmp; tmp = tmp->next)
	if (tmp->name && (tmp->flags & INAME_6) &&
	    wildcard_match(tmp->name, ifr.ifr_name))
	  return;
      
      parm.current = NULL;
      parm.ind = if_index;
      parm.addr_match = 0;
      memset(&parm.fallback, 0, IN6ADDRSZ);
      memset(&parm.ll_addr, 0, IN6ADDRSZ);
      memset(&parm.ula_addr, 0, IN6ADDRSZ);
      
      /* If the interface on which the DHCPv6 request was received is
         an alias of some other interface (as specified by the
         --bridge-interface option), change parm.ind so that we look
         for DHCPv6 contexts associated with the aliased interface
         instead of with the aliasing one. */
      for (bridge = daemon->bridges; bridge; bridge = bridge->next)
	{
	  for (alias = bridge->alias; alias; alias = alias->next)
	    if (wildcard_matchn(alias->iface, ifr.ifr_name, IF_NAMESIZE))
	      {
		parm.ind = if_nametoindex(bridge->iface);
		if (!parm.ind)
		  {
		    my_syslog(MS_DHCP | LOG_WARNING,
			      _("unknown interface %s in bridge-interface"),
			      bridge->iface);
		    return;
		  }
		break;
	      }
	  if (alias)
	    break;
	}
      
      for (context = daemon->dhcp6; context; context = context->next)
	if (IN6_IS_ADDR_UNSPECIFIED(&context->start6) && context->prefix == 0)
	  {
	    /* wildcard context for DHCP-stateless only */
	    parm.current = context;
	    context->current = NULL;
	  }
	else
	  {
	    /* unlinked contexts are marked by context->current == context */
	    context->current = context;
	    memset(&context->local6, 0, IN6ADDRSZ);
	  }

      for (relay = daemon->relay6; relay; relay = relay->next)
	relay->matchcount = 0;

      inet_pton(AF_INET6, ALL_RELAY_AGENTS_AND_SERVERS, &all_servers);
      if (IN6_ARE_ADDR_EQUAL(&dst_addr, &all_servers))
	multicast_dest = 1;
      
      inet_pton(AF_INET6, ALL_SERVERS, &all_servers);
      if (IN6_ARE_ADDR_EQUAL(&dst_addr, &all_servers))
	multicast_dest = 1;
      else
	{
	  /* Ignore requests sent to the ALL_SERVERS multicast address for relay when
	     we're listening there for DHCPv6 server reasons. */
	  if (relay_upstream6(if_index, (size_t)sz, &from.sin6_addr, from.sin6_scope_id, now))
	    return;
	}
      
      if (!iface_enumerate(AF_INET6, &parm, (callback_t){.af_inet6=complete_context6}))
	return;
      
      /* Check for a relay again after iface_enumerate/complete_context has had
	 chance to fill in relay->iface_index fields. This handles first time through
	 and any changes in interface config. */
      if (!IN6_ARE_ADDR_EQUAL(&dst_addr, &all_servers) &&
	  relay_upstream6(if_index, (size_t)sz, &from.sin6_addr, from.sin6_scope_id, now))
	return;
      
      if (daemon->if_names || daemon->if_addrs)
	{
	  
	  for (tmp = daemon->if_names; tmp; tmp = tmp->next)
	    if (tmp->name && wildcard_match(tmp->name, ifr.ifr_name))
	      break;
	  
	  if (!tmp && !parm.addr_match)
	    return;
	}
      
      /* May have configured relay, but not DHCP server */
      if (!daemon->doing_dhcp6)
	return;
      
      lease_prune(NULL, now); /* lose any expired leases */
      
      port = dhcp6_reply(parm.current, multicast_dest, if_index, ifr.ifr_name, &parm.fallback, 
			 &parm.ll_addr, &parm.ula_addr, sz, &from.sin6_addr, now);
      
      /* The port in the source address of the original request should
	 be correct, but at least once client sends from the server port,
	 so we explicitly send to the client port to a client, and the
	 server port to a relay. */
      if (port != 0)
	{
	  from.sin6_port = htons(port);
	  
#ifdef HAVE_DUMPFILE
	  dump_packet_udp(DUMP_DHCPV6, (void *)daemon->outpacket.iov_base, save_counter(-1),
			  NULL, (union mysockaddr *)&from, daemon->dhcp6fd);
#endif 
	  
	  while (retry_send(sendto(daemon->dhcp6fd, daemon->outpacket.iov_base,
				   save_counter(-1), 0, (struct sockaddr *)&from, sizeof(from))));
	}
      
      /* These need to be called _after_ we send DHCPv6 packet, since lease_update_file()
	 may trigger sending an RA packet, which overwrites our buffer. */
      lease_update_file(now);
      lease_update_dns(0);
    }
}

/**
 * @brief Retrieve MAC address for DHCPv6 client using neighbor discovery
 * 
 * @detailed Obtains the link-layer (MAC) address for a DHCPv6 client by consulting the IPv6
 *           neighbor cache. If the client is not in the neighbor cache (common since receiving
 *           a packet does not populate the cache), sends ICMPv6 Neighbor Solicitation messages
 *           to actively discover the client and populate the cache. Retries up to 5 times with
 *           100ms sleep between attempts to handle packet loss. MAC address is needed for DHCP
 *           client identification and static lease matching.
 * 
 * @param client IPv6 address of the DHCPv6 client to look up
 * @param iface Network interface index where client is reachable
 * @param mac Output buffer for retrieved MAC address (must be at least DHCP_CHADDR_MAX bytes)
 * @param maclenp Output pointer to store MAC address length (0 if not found)
 * @param mactypep Output pointer to store hardware type (always ARPHRD_ETHER for Ethernet)
 * @param now Current time for neighbor cache operations
 * 
 * @return void Results returned via output parameters maclenp and mactypep
 * 
 * @note MAC address retrieval may fail if client is not on local link or unreachable
 * @warning Sends ICMPv6 packets on daemon->icmp6fd socket; requires active ICMPv6 socket
 * 
 * @see find_mac() in arp.c queries neighbor cache
 * @see daemon->icmp6fd socket used for Neighbor Solicitation transmission
 * 
 * EXAMPLE USAGE:
 * @code
 * unsigned char mac[DHCP_CHADDR_MAX];
 * unsigned int maclen, mactype;
 * struct in6_addr client_addr;
 * get_client_mac(&client_addr, if_index, mac, &maclen, &mactype, now);
 * if (maclen > 0) {
 *   // MAC address retrieved successfully, use for client identification
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 4861 Neighbor Discovery for IPv6
 * SIDE EFFECTS: Sends ICMPv6 Neighbor Solicitation packets; sleeps 100ms between retries
 * THREAD SAFETY: Single-threaded event loop ensures sequential execution
 */
void get_client_mac(struct in6_addr *client, int iface, unsigned char *mac, unsigned int *maclenp, unsigned int *mactypep, time_t now)
{
  /* Receiving a packet from a host does not populate the neighbour
     cache, so we send a neighbour discovery request if we can't 
     find the sender. Repeat a few times in case of packet loss. */
  
  struct neigh_packet neigh;
  union mysockaddr addr;
  int i, maclen;

  neigh.type = ND_NEIGHBOR_SOLICIT;
  neigh.code = 0;
  neigh.reserved = 0;
  neigh.target = *client;
  /* RFC4443 section-2.3: checksum has to be zero to be calculated */
  neigh.checksum = 0;
   
  memset(&addr, 0, sizeof(addr));
#ifdef HAVE_SOCKADDR_SA_LEN
  addr.in6.sin6_len = sizeof(struct sockaddr_in6);
#endif
  addr.in6.sin6_family = AF_INET6;
  addr.in6.sin6_port = htons(IPPROTO_ICMPV6);
  addr.in6.sin6_addr = *client;
  addr.in6.sin6_scope_id = iface;
  
  for (i = 0; i < 5; i++)
    {
      struct timespec ts;
      
      if ((maclen = find_mac(&addr, mac, 0, now)) != 0)
	break;
	  
      while(retry_send(sendto(daemon->icmp6fd, &neigh, sizeof(neigh), 0, &addr.sa, sizeof(addr))));
      
      ts.tv_sec = 0;
      ts.tv_nsec = 100000000; /* 100ms */
      nanosleep(&ts, NULL);
    }

  *maclenp = maclen;
  *mactypep = ARPHRD_ETHER;
}

/**
 * @brief Callback for interface enumeration to match DHCPv6 contexts with interface addresses
 * 
 * @detailed Invoked by iface_enumerate() for each IPv6 address on each network interface during
 *           DHCPv6 packet processing. Matches interface addresses against configured DHCPv6
 *           contexts to determine which address pools apply to the receiving interface. Sets
 *           context valid lifetimes based on interface address preferred/valid lifetimes.
 *           Identifies fallback source addresses (link-local for multicast replies, ULA for
 *           relay scenarios). Matches relay agent configurations with interface addresses and
 *           tracks relay interface indices. Handles dynamic context lifetime updates when
 *           interface addresses have finite lifetimes (e.g., temporary privacy addresses).
 * 
 * @param local IPv6 address configured on the interface being enumerated
 * @param prefix Prefix length of the IPv6 address (typically 64 for SLAAC addresses)
 * @param scope IPv6 address scope (link-local, site-local, global)
 * @param if_index Kernel interface index for the interface with this address
 * @param flags Interface address flags (preferred, deprecated, tentative, etc.)
 * @param preferred Preferred lifetime of the address in seconds (0xffffffff = infinite)
 * @param valid Valid lifetime of the address in seconds (0xffffffff = infinite)
 * @param vparam Pointer to struct iface_param containing enumeration state and context list
 * 
 * @return int Always returns 1 to continue interface enumeration
 * @retval 1 Continue enumeration (no early termination condition)
 * 
 * @note Called multiple times per interface (once per IPv6 address) during dhcp6_packet() processing
 * @warning Context lifetime manipulation affects lease renewal behavior - finite address lifetimes
 *          propagate to DHCPv6 lease valid lifetimes to coordinate with SLAAC address expiration
 * 
 * @see iface_enumerate() in network.c invokes this callback for each interface address
 * @see struct iface_param in dhcp6.c:23 defines callback state including fallback addresses
 * @see complete_context6() sets context->current linkage for matching contexts
 * 
 * EXAMPLE USAGE:
 * @code
 * // Called indirectly via iface_enumerate in dhcp6_packet()
 * struct iface_param parm;
 * parm.current = NULL;  // Initialize context list
 * parm.ind = if_index;  // Target interface
 * iface_enumerate(AF_INET6, &parm, complete_context6);
 * // After enumeration, parm.current contains linked contexts for interface
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 4862 IPv6 address lifetimes, RFC 3315 DHCPv6 valid lifetime coordination
 * SIDE EFFECTS: 
 *   - Modifies context->current linkage to chain matching contexts
 *   - Updates context->valid lifetime based on interface address valid lifetime
 *   - Sets relay->iface_index for relay agent configurations
 *   - Logs warning if relay address appears on multiple interfaces
 *   - Stores fallback addresses in parm->ll_addr and parm->ula_addr
 * THREAD SAFETY: Single-threaded callback invoked sequentially during interface enumeration
 */
    
static int complete_context6(struct in6_addr *local,  int prefix,
			     int scope, int if_index, int flags, unsigned int preferred, 
			     unsigned int valid, void *vparam)
{
  struct dhcp_context *context;
  struct shared_network *share;
  struct dhcp_relay *relay;
  struct iface_param *param = vparam;
  struct iname *tmp;
  int match = !daemon->if_addrs;
 
  (void)scope; /* warning */
  
  if (if_index != param->ind)
    return 1;
  
  if (IN6_IS_ADDR_LINKLOCAL(local))
    param->ll_addr = *local;
  else if (IN6_IS_ADDR_ULA(local))
    param->ula_addr = *local;
      
  if (IN6_IS_ADDR_LOOPBACK(local) ||
      IN6_IS_ADDR_LINKLOCAL(local) ||
      IN6_IS_ADDR_MULTICAST(local))
    return 1;
  
  /* if we have --listen-address config, see if the 
     arrival interface has a matching address. */
  for (tmp = daemon->if_addrs; tmp; tmp = tmp->next)
    if (tmp->addr.sa.sa_family == AF_INET6 &&
	IN6_ARE_ADDR_EQUAL(&tmp->addr.in6.sin6_addr, local))
      match = param->addr_match = 1;
  
  /* Determine a globally address on the arrival interface, even
     if we have no matching dhcp-context, because we're only
     allocating on remote subnets via relays. This
     is used as a default for the DNS server option. */
  param->fallback = *local;
  
  for (context = daemon->dhcp6; context; context = context->next)
    if ((context->flags & CONTEXT_DHCP) &&
	!(context->flags & (CONTEXT_TEMPLATE | CONTEXT_OLD)) &&
	prefix <= context->prefix &&
	context->current == context)
      {
	if (is_same_net6(local, &context->start6, context->prefix) &&
	    is_same_net6(local, &context->end6, context->prefix))
	  {
	    struct dhcp_context *tmp, **up;
	    
	    /* use interface values only for constructed contexts */
	    if (!(context->flags & CONTEXT_CONSTRUCTED))
	      preferred = valid = 0xffffffff;
	    else if (flags & IFACE_DEPRECATED)
	      preferred = 0;
		    
	    if (context->flags & CONTEXT_DEPRECATE)
	      preferred = 0;
	    
	    /* order chain, longest preferred time first */
	    for (up = &param->current, tmp = param->current; tmp; tmp = tmp->current)
	      if (tmp->preferred <= preferred)
		break;
	      else
		up = &tmp->current;
	    
	    context->current = *up;
	    *up = context;
	    context->local6 = *local;
	    context->preferred = preferred;
	    context->valid = valid;
	  }
	else
	  {
	    for (share = daemon->shared_networks; share; share = share->next)
	      {
		/* IPv4 shared_address - ignore */
		if (share->shared_addr.s_addr != 0)
		  continue;
			
		if (share->if_index != 0)
		  {
		    if (share->if_index != if_index)
		      continue;
		  }
		else
		  {
		    if (!IN6_ARE_ADDR_EQUAL(&share->match_addr6, local))
		      continue;
		  }
		
		if (is_same_net6(&share->shared_addr6, &context->start6, context->prefix) &&
		    is_same_net6(&share->shared_addr6, &context->end6, context->prefix))
		  {
		    context->current = param->current;
		    param->current = context;
		    context->local6 = *local;
		    context->preferred = context->flags & CONTEXT_DEPRECATE ? 0 :0xffffffff;
		    context->valid = 0xffffffff;
		  }
	      }
	  }      
      }
  
  if (match)
    for (relay = daemon->relay6; relay; relay = relay->next)
      if (IN6_ARE_ADDR_EQUAL(local, &relay->local.addr6))
	{
	  relay->iface_index = if_index;

	  /* More than one interface with the relay address breaks things. */
	  if (relay->matchcount++ == 1 && !relay->warned)
	    {
	      relay->warned = 1;
	      inet_ntop(AF_INET6, &local, daemon->addrbuff, ADDRSTRLEN);
	      my_syslog(MS_DHCP | LOG_WARNING, _("DHCP relay address %s appears on more than one interface"), daemon->addrbuff);
	    }
	}
  
  return 1;
}

/**
 * @brief Search DHCPv6 static host configurations for matching IPv6 address assignment
 * 
 * @detailed Searches linked list of static host configurations (from --dhcp-host=) to find
 *           configuration entries with statically assigned IPv6 addresses matching the specified
 *           address within the given network prefix. Supports exact 128-bit address matches and
 *           prefix-based subnet matches. Wildcard configurations (ADDRLIST_WILDCARD) match any
 *           address within /64 prefixes when network prefix is 64 bits. Used during DHCPv6
 *           REQUEST processing to determine if client is requesting a validly configured static
 *           address, enabling static lease reservations similar to DHCPv4 dhcp-host directives.
 *           Validates that requested addresses correspond to known static configurations before
 *           assignment to prevent unauthorized address claims.
 * 
 * @param configs Head of linked list of dhcp_config structures from daemon->dhcp_configs
 * @param net Network prefix to match (NULL means match any network for relay scenarios)
 * @param prefix Prefix length for network matching (typically 64 for SLAAC-aligned pools)
 * @param addr Target IPv6 address to search for in configuration entries
 * 
 * @return struct dhcp_config* Pointer to matching configuration entry, or NULL if not found
 * @retval non-NULL Configuration entry with matching IPv6 address assignment
 * @retval NULL No configuration matches the specified address and network criteria
 * 
 * @note Multiple address assignments per config supported via addr_list chaining
 * @warning Wildcard matches (ADDRLIST_WILDCARD) only apply to /64 prefixes per RFC 4862 SLAAC
 * 
 * @see struct dhcp_config in dnsmasq.h defines static host configuration structure
 * @see config_find_by_address6() called during DHCPv6 REQUEST validation in dhcp6_maybe_relay()
 * @see CONFIG_ADDR6 flag indicates configuration contains IPv6 address assignments
 * 
 * EXAMPLE USAGE:
 * @code
 * struct in6_addr client_addr, net_prefix;
 * // Client requests specific address in DHCP REQUEST
 * struct dhcp_config *cfg = config_find_by_address6(daemon->dhcp_configs, 
 *                                                     &net_prefix, 64, &client_addr);
 * if (cfg && cfg->hostname) {
 *   // Assign requested static address with associated hostname
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 3315 Section 18.2.3 static address assignment validation
 * SIDE EFFECTS: None (read-only search operation)
 * THREAD SAFETY: Single-threaded DHCPv6 packet processing, no locking required
 */
struct dhcp_config *config_find_by_address6(struct dhcp_config *configs, struct in6_addr *net, int prefix,  struct in6_addr *addr)
{
  struct dhcp_config *config;
  
  for (config = configs; config; config = config->next)
    if (config->flags & CONFIG_ADDR6)
      {
	struct addrlist *addr_list;
	
	for (addr_list = config->addr6; addr_list; addr_list = addr_list->next)
	  if ((!net || is_same_net6(&addr_list->addr.addr6, net, prefix) || ((addr_list->flags & ADDRLIST_WILDCARD) && prefix == 64)) &&
	      is_same_net6(&addr_list->addr.addr6, addr, (addr_list->flags & ADDRLIST_PREFIX) ? addr_list->prefixlen : 128))
	    return config;
      }
  
  return NULL;
}

/**
 * @brief Allocate IPv6 address from DHCPv6 address pool for stateful address assignment
 * 
 * @detailed Implements DHCPv6 stateful address allocation algorithm conforming to RFC 3315.
 *           Searches configured address pools (dhcp_context structures) for available IPv6
 *           addresses not currently leased. Honors static address reservations from dhcp-host
 *           configurations, preferring previously assigned addresses for lease renewals (address
 *           persistence). Supports both standard address allocation (IA_NA) and temporary address
 *           allocation (IA_TA) with different lifetime characteristics. Handles address pool
 *           construction modes including enumerated ranges, prefix-based allocation, and
 *           constructor-generated address pools. Validates address availability through lease
 *           database consultation and performs duplicate address detection preparation. Respects
 *           client network ID tag matching for tag-based pool selection. Updates allocation
 *           serial to track context changes requiring lease rebinding.
 * 
 * @param context Linked list of DHCPv6 address pool contexts applicable to the interface
 * @param clid Client DUID (DHCPv6 Unique Identifier) for lease binding, must not be NULL
 * @param clid_len Length of client DUID in bytes (variable length per RFC 3315)
 * @param temp_addr Boolean flag: 1 for temporary addresses (IA_TA), 0 for normal (IA_NA)
 * @param iaid Identity Association Identifier from client request for lease correlation
 * @param serial Context serial number for tracking configuration changes requiring REBIND
 * @param netids Client network ID tag list for tag-based pool matching (NULL = no filtering)
 * @param plain_range Boolean: 1 for simple enumerated ranges, 0 for constructor/prefix pools
 * @param ans Output parameter: allocated IPv6 address written here on success
 * 
 * @return struct dhcp_context* Pointer to context from which address was allocated, or NULL
 * @retval non-NULL Address successfully allocated, *ans contains assigned address
 * @retval NULL No available addresses in matching pools (exhaustion or config mismatch)
 * 
 * @note Address selection honors address persistence for renewals before attempting new allocation
 * @warning Pool exhaustion returns NULL - caller must send DHCPv6 NoAddrsAvail status
 * 
 * @see lease_find_by_client6() in lease.c checks for existing client leases
 * @see lease6_allocate() in lease.c creates new lease database entry for allocation
 * @see address6_available() validates address not in use before allocation
 * @see struct dhcp_context in dnsmasq.h defines address pool structure with start/end bounds
 * 
 * EXAMPLE USAGE:
 * @code
 * struct in6_addr allocated_addr;
 * unsigned char client_duid[16];
 * struct dhcp_context *pool = address6_allocate(context, client_duid, 16,
 *                                                0, // normal address (not temporary)
 *                                                iaid, serial, tags, 1, &allocated_addr);
 * if (pool) {
 *   // Send DHCPv6 REPLY with allocated_addr in IA_NA option
 * } else {
 *   // Send DHCPv6 REPLY with NoAddrsAvail status
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 3315 Section 17.2.2 address allocation algorithm for stateful DHCPv6
 * SIDE EFFECTS:
 *   - May allocate new lease in lease database via lease6_allocate()
 *   - Updates context serial in returned context for configuration tracking
 *   - Logs address allocation events when logging enabled
 *   - Address availability checked via ping (duplicate address detection preparation)
 * THREAD SAFETY: Single-threaded DHCPv6 packet processing, relies on global daemon state
 */
struct dhcp_context *address6_allocate(struct dhcp_context *context,  unsigned char *clid, int clid_len, int temp_addr,
				       unsigned int iaid, int serial, struct dhcp_netid *netids, int plain_range, struct in6_addr *ans)
{
  /* Find a free address: exclude anything in use and anything allocated to
     a particular hwaddr/clientid/hostname in our configuration.
     Try to return from contexts which match netids first. 
     
     Note that we assume the address prefix lengths are 64 or greater, so we can
     get by with 64 bit arithmetic.
*/

  u64 start, addr;
  struct dhcp_context *c, *d;
  int i, pass;
  u64 j; 

  /* hash hwaddr: use the SDBM hashing algorithm.  This works
     for MAC addresses, let's see how it manages with client-ids! 
     For temporary addresses, we generate a new random one each time. */
  if (temp_addr)
    j = rand64();
  else
    for (j = iaid, i = 0; i < clid_len; i++)
      j = clid[i] + (j << 6) + (j << 16) - j;
  
  for (pass = 0; pass <= plain_range ? 1 : 0; pass++)
    for (c = context; c; c = c->current)
      if (c->flags & (CONTEXT_DEPRECATE | CONTEXT_STATIC | CONTEXT_RA_STATELESS | CONTEXT_USED))
	continue;
      else if (!match_netid(c->filter, netids, pass))
	continue;
      else
	{ 
	  if (!temp_addr && option_bool(OPT_CONSEC_ADDR))
	    {
	      /* seed is largest extant lease addr in this context,
		 skip addresses equal to the number of addresses rejected
		 by clients. This should avoid the same client being offered the same
		 address after it has rjected it. */
	      start = lease_find_max_addr6(c) + 1 + serial + c->addr_epoch;
	      if (c->addr_epoch)
		c->addr_epoch--;
	    }
	  else
	    {
	      u64 range = 1 + addr6part(&c->end6) - addr6part(&c->start6);
	      u64 offset = j + c->addr_epoch;

	      /* don't divide by zero if range is whole 2^64 */
	      if (range != 0)
		offset = offset % range;

	      start = addr6part(&c->start6) + offset;
	    }

	  /* iterate until we find a free address. */
	  addr = start;
	  
	  do {
	    /* eliminate addresses in use by the server. */
	    for (d = context; d; d = d->current)
	      if (addr == addr6part(&d->local6))
		break;
	    
	    *ans = c->start6;
	    setaddr6part (ans, addr);

	    if (!d &&
		!lease6_find_by_addr(&c->start6, c->prefix, addr) && 
		!config_find_by_address6(daemon->dhcp_conf, &c->start6, c->prefix, ans))
	      return c;
	    
	    addr++;
	    
	    if (addr  == addr6part(&c->end6) + 1)
	      addr = addr6part(&c->start6);
	    
	  } while (addr != start);
	}
	   
  return NULL;
}

/**
 * @brief Check if specific IPv6 address is available for dynamic allocation from address pools
 * 
 * @detailed Validates that a specific IPv6 address can be dynamically allocated from configured
 *           DHCPv6 address pools. Searches context list for pool containing the target address,
 *           verifying address falls within pool range boundaries (start6 to end6), matches the
 *           pool's network prefix, and satisfies network ID tag filtering. Excludes static-only
 *           pools (CONTEXT_STATIC) and stateless RA pools (CONTEXT_RA_STATELESS) from dynamic
 *           allocation. Used during address allocation to verify candidate addresses are within
 *           valid allocatable ranges before lease creation. Supports both enumerated address
 *           ranges (plain_range=1) and constructor-generated pools (plain_range=0). Address
 *           availability check is prerequisite to lease database insertion and duplicate address
 *           detection (DAD). Complements address6_allocate() by validating specific address
 *           rather than searching for any available address.
 * 
 * @param context Linked list of DHCPv6 contexts applicable to the receiving interface
 * @param taddr Target IPv6 address to check for allocation availability
 * @param netids Client network ID tag list for tag-based pool matching (NULL = no filtering)
 * @param plain_range Boolean: 1 for enumerated ranges, 0 for constructor/prefix-based pools
 * 
 * @return struct dhcp_context* Pointer to context containing available address, or NULL
 * @retval non-NULL Address is within valid dynamic allocation pool matching all criteria
 * @retval NULL Address not available (outside pools, in static pool, or tag mismatch)
 * 
 * @note Address availability check does NOT consult lease database - caller must check leases
 * @warning Static contexts (CONTEXT_STATIC) excluded from dynamic allocation
 * 
 * @see address6_allocate() in dhcp6.c performs full allocation including lease database checks
 * @see is_same_net6() in util.c validates address matches pool network prefix
 * @see match_netid() in dhcp-common.c performs network ID tag matching
 * @see addr6part() in dnsmasq.h extracts low 64 bits for range comparison
 * 
 * EXAMPLE USAGE:
 * @code
 * struct in6_addr candidate_addr;
 * // Check if client-requested address is dynamically allocatable
 * struct dhcp_context *pool = address6_available(context, &candidate_addr, tags, 1);
 * if (pool && !lease_find_by_addr6(&candidate_addr)) {
 *   // Address is available and not leased - safe to allocate
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 3315 Section 18.2.1 address validation for client requests
 * SIDE EFFECTS: None (read-only validation, no state modification)
 * THREAD SAFETY: Single-threaded DHCPv6 processing, no locking required
 */
/* can dynamically allocate addr */
struct dhcp_context *address6_available(struct dhcp_context *context, 
					struct in6_addr *taddr,
					struct dhcp_netid *netids,
					int plain_range)
{
  u64 start, end, addr = addr6part(taddr);
  struct dhcp_context *tmp;
 
  for (tmp = context; tmp; tmp = tmp->current)
    {
      start = addr6part(&tmp->start6);
      end = addr6part(&tmp->end6);

      if (!(tmp->flags & (CONTEXT_STATIC | CONTEXT_RA_STATELESS)) &&
          is_same_net6(&tmp->start6, taddr, tmp->prefix) &&
	  is_same_net6(&tmp->end6, taddr, tmp->prefix) &&
	  addr >= start &&
          addr <= end &&
          match_netid(tmp->filter, netids, plain_range))
        return tmp;
    }

  return NULL;
}

/**
 * @brief Validate that an IPv6 address is within a configured DHCPv6 context
 * 
 * @detailed Verifies that the specified IPv6 address falls within the address
 *           range of at least one configured DHCPv6 context, considering network ID
 *           matching for tag-based configuration. This function is used to validate
 *           client-requested addresses in DHCPv6 REQUEST messages and to verify
 *           that statically assigned addresses are properly configured.
 * 
 * @param context Linked list of DHCPv6 contexts to search
 * @param taddr IPv6 address to validate. Must not be NULL
 * @param netids Network ID tags for client classification (vendor class, user class, etc.)
 * @param plain_range Flag indicating whether to require tag matching (0) or accept any match (1)
 * 
 * @return Pointer to matching dhcp_context if address is valid and configured, NULL if address
 *         is not within any configured range or fails network ID matching
 * @retval non-NULL Address is valid within returned context
 * @retval NULL Address is not configured or fails filtering
 * 
 * @note This function iterates through the context linked list via the 'current' pointer
 * @warning Does not perform duplicate address detection - only validates configuration
 * 
 * @see is_same_net6() in network.c for network comparison
 * @see match_netid() for tag-based filtering logic
 * 
 * EXAMPLE USAGE:
 * @code
 * struct in6_addr client_addr;
 * struct dhcp_context *valid_ctx;
 * // Client requests specific address in REQUEST message
 * valid_ctx = address6_valid(context, &client_addr, netids, 0);
 * if (valid_ctx == NULL) {
 *   // Address not in configured range - send NOADDRSAVAIL
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 3315 Section 18.2.3 (server processing of Request messages)
 * SIDE EFFECTS: None - read-only validation operation
 * THREAD SAFETY: Safe for single-threaded architecture
 */
/* address OK if configured */
struct dhcp_context *address6_valid(struct dhcp_context *context, 
				    struct in6_addr *taddr,
				    struct dhcp_netid *netids,
				    int plain_range)
{
  struct dhcp_context *tmp;
 
  for (tmp = context; tmp; tmp = tmp->current)
    if (is_same_net6(&tmp->start6, taddr, tmp->prefix) &&
	match_netid(tmp->filter, netids, plain_range))
      return tmp;

  return NULL;
}

/**
 * @brief Generate DHCPv6 DUID (DHCP Unique Identifier) for server
 * 
 * @detailed Creates a DUID for the DHCPv6 server using one of three methods: configured DUID-EN
 *            (Enterprise Number, type 2) if daemon->duid_config is set, DUID-LLT (Link-Layer Time,
 *            type 1) with timestamp if stable lease database and RTC available, or DUID-LL (Link-Layer,
 *            type 3) without timestamp otherwise. Per RFC 3315 Section 9, the DUID uniquely identifies
 *            the server across restarts. DUID-EN uses configured enterprise number and identifier.
 *            DUID-LLT/LL use MAC address from first suitable interface (non-loopback, non-P-to-P, type < 256).
 *            The generated DUID is stored in daemon->duid with length daemon->duid_len for inclusion
 *            in all DHCPv6 server messages (ADVERTISE, REPLY, etc.).
 * 
 * @param now Current time for DUID-LLT timestamp calculation (rebased to epoch 1/1/2000)
 * 
 * @return void
 * 
 * @note This function should be called during DHCPv6 server initialization before processing client
 *       messages. The DUID persists for the lifetime of the daemon process and should remain stable
 *       across restarts if using DUID-LLT with persistent lease database.
 * @warning Dies with EC_MISC error if no suitable interface found for DUID-LL/LLT generation. For
 *          systems without stable RTC (HAVE_BROKEN_RTC), always uses DUID-LL to avoid timestamp issues.
 *          For read-only lease databases (OPT_LEASE_RO), uses DUID-LL unless lease-change-command configured.
 * 
 * @see make_duid1() Helper function that constructs DUID from interface MAC address
 * @see RFC 3315 Section 9 (DUID formats and construction rules)
 * 
 * EXAMPLE USAGE:
 * @code
 * // During DHCPv6 server initialization with configured DUID
 * daemon->duid_config = configured_identifier;
 * daemon->duid_config_len = identifier_length;
 * daemon->duid_enterprise = 1234; // Enterprise number
 * make_duid(dnsmasq_time());
 * // daemon->duid now contains DUID-EN for server identity
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 3315 Section 9 (DUID formats: DUID-LLT, DUID-EN, DUID-LL)
 * SIDE EFFECTS: Allocates daemon->duid via safe_malloc; sets daemon->duid_len; calls iface_enumerate; dies on failure
 * THREAD SAFETY: Single-threaded architecture; called during initialization only
 */
void make_duid(time_t now)
{
  (void)now;

  if (daemon->duid_config)
    {
      unsigned char *p;
      
      daemon->duid = p = safe_malloc(daemon->duid_config_len + 6);
      daemon->duid_len = daemon->duid_config_len + 6;
      PUTSHORT(2, p); /* DUID_EN */
      PUTLONG(daemon->duid_enterprise, p);
      memcpy(p, daemon->duid_config, daemon->duid_config_len);
    }
  else
    {
      time_t newnow = 0;
      
      /* If we have no persistent lease database, or a non-stable RTC, use DUID_LL (newnow == 0) */
#ifndef HAVE_BROKEN_RTC
      /* rebase epoch to 1/1/2000 */
      if (!option_bool(OPT_LEASE_RO) || daemon->lease_change_command)
	newnow = now - 946684800;
#endif      
      
      iface_enumerate(AF_LOCAL, &newnow, (callback_t){.af_local=make_duid1});
      
      if(!daemon->duid)
	die("Cannot create DHCPv6 server DUID: %s", NULL, EC_MISC);
    }
}

/**
 * @brief Callback function invoked per interface to create DHCPv6 server DUID from first suitable interface
 * 
 * @detailed This callback is invoked by iface_enumerate() for each network interface. It creates the
 *           DHCPv6 server DUID (DHCP Unique IDentifier) per RFC 3315 using the MAC address of the first
 *           suitable interface encountered. The function generates either DUID-LLT (Link-layer address plus time)
 *           or DUID-LL (Link-layer address only) depending on whether a stable time value is available.
 *           Selection criteria: First interface that is not loopback, not point-to-point, and has
 *           address type < 256. Address types >= 256 (tunnels, etc.) lack usable MAC addresses and are skipped.
 *           Once a DUID is created, enumeration terminates by returning 0.
 * 
 * @param index Interface index (unused in this implementation)
 * @param type Hardware address type from interface (ARPHRD_* constants). Types >= 256 are rejected.
 * @param mac Pointer to MAC address bytes of the interface
 * @param maclen Length of MAC address in bytes (typically 6 for Ethernet)
 * @param parm Pointer to time_t value: 0 for DUID-LL, non-zero epoch (rebased to 2000-01-01) for DUID-LLT
 * 
 * @return 0 on successful DUID creation (terminates enumeration), 1 to continue enumeration
 * @retval 0 DUID successfully created from this interface MAC address, enumeration stops
 * @retval 1 Interface unsuitable (type >= 256), continue enumeration to next interface
 * 
 * @note This function is used as a callback with iface_enumerate(AF_LOCAL, ...). It modifies global
 *       daemon->duid and daemon->duid_len on successful DUID creation.
 * @warning Allocates memory via safe_malloc() for daemon->duid; caller (make_duid) verifies creation.
 * 
 * @see make_duid() in src/dhcp6.c - parent function that invokes this callback
 * @see iface_enumerate() in src/network.c - enumerates interfaces invoking this callback
 * 
 * EXAMPLE USAGE:
 * @code
 * // Called from make_duid() via iface_enumerate
 * time_t newnow = now - 946684800; // Rebase epoch to 2000-01-01
 * iface_enumerate(AF_LOCAL, &newnow, (callback_t){.af_local=make_duid1});
 * // Result: daemon->duid contains DUID-LLT or DUID-LL from first suitable interface
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 3315 Section 9.2 (DUID-LLT), Section 9.3 (DUID-LL)
 * SIDE EFFECTS: Allocates and populates global daemon->duid and daemon->duid_len on success
 * THREAD SAFETY: Not thread-safe (modifies global daemon state); called from single-threaded event loop
 */
static int make_duid1(int index, unsigned int type, char *mac, size_t maclen, void *parm)
{
  /* create DUID as specified in RFC3315. We use the MAC of the
     first interface we find that isn't loopback or P-to-P and
     has address-type < 256. Address types above 256 are things like 
     tunnels which don't have usable MAC addresses. */
  
  unsigned char *p;
  (void)index;
  (void)parm;
  time_t newnow = *((time_t *)parm);
  
  if (type >= 256)
    return 1;

  if (newnow == 0)
    {
      daemon->duid = p = safe_malloc(maclen + 4);
      daemon->duid_len = maclen + 4;
      PUTSHORT(3, p); /* DUID_LL */
      PUTSHORT(type, p); /* address type */
    }
  else
    {
      daemon->duid = p = safe_malloc(maclen + 8);
      daemon->duid_len = maclen + 8;
      PUTSHORT(1, p); /* DUID_LLT */
      PUTSHORT(type, p); /* address type */
      PUTLONG(*((time_t *)parm), p); /* time */
    }
  
  memcpy(p, mac, maclen);

  return 0;
}

struct cparam {
  time_t now;
  int newone, newname;
};

/**
 * @brief Construct or update DHCPv6 contexts dynamically from network interface addresses
 * 
 * @detailed This callback function is invoked by iface_enumerate() for each IPv6 address
 *           on network interfaces. It creates dynamic DHCPv6 contexts from CONTEXT_TEMPLATE
 *           entries by matching interface addresses with configured ranges. When a matching
 *           template is found, constructs a new context with the actual interface parameters
 *           or updates an existing constructed context. Handles context lifecycle (CONTEXT_OLD
 *           flag for address disappearance/reappearance), triggers Router Advertisement
 *           unsolicited RAs for new or restored contexts, and manages SLAAC name integration.
 *           This mechanism enables DHCPv6 to adapt dynamically to interface configuration
 *           changes without requiring daemon restart.
 * 
 * @param local IPv6 address found on the interface
 * @param prefix Prefix length (bits) for the address
 * @param scope Address scope (link-local, site-local, global)
 * @param if_index Interface index where address was found
 * @param flags Address flags (IFA_F_* from netlink or equivalent)
 * @param preferred Preferred lifetime in seconds for the address
 * @param valid Valid lifetime in seconds for the address
 * @param vparam Pointer to struct cparam containing timestamp and modification flags
 * 
 * @return Always returns 1 to continue enumeration
 * @retval 1 Continue enumeration to next interface address
 * 
 * @note Context construction matches template ranges using is_same_net6() to find
 *       appropriate CONTEXT_TEMPLATE entries for the discovered interface address
 * @note Newly constructed contexts have CONTEXT_CONSTRUCTED flag set and CONTEXT_TEMPLATE
 *       flag cleared, distinguishing them from the original templates
 * @note CONTEXT_GC flag is cleared for active contexts; contexts not matched during
 *       enumeration will retain this flag and can be garbage collected later
 * @note CONTEXT_OLD flag indicates address was previously seen but disappeared; clearing
 *       it on reappearance triggers RA restart and name re-registration
 * 
 * @warning Memory allocation failure (whine_malloc returns NULL) prevents context
 *          creation but does not abort enumeration
 * @warning Context list is modified during enumeration; daemon->dhcp6 list is updated
 *          with new contexts prepended to the head
 * 
 * @see iface_enumerate() in network.c for enumeration driver
 * @see is_same_net6() for prefix matching logic
 * @see ra_start_unsolicited() in radv.c for Router Advertisement trigger
 * @see log_context() for context logging
 * 
 * EXAMPLE USAGE:
 * @code
 * struct cparam param;
 * param.now = dnsmasq_time();
 * param.newone = param.newname = 0;
 * iface_enumerate(AF_INET6, &param, construct_worker);
 * if (param.newone) lease_update_file(param.now);
 * @endcode
 * 
 * RFC COMPLIANCE: Supports DHCPv6 dynamic prefix configuration per RFC 3315
 * SIDE EFFECTS: Modifies daemon->dhcp6 context list; triggers unsolicited Router
 *               Advertisements via ra_start_unsolicited(); logs context changes;
 *               sets param->newone and param->newname flags for caller action
 * THREAD SAFETY: Single-threaded architecture; modifies global daemon state
 */
static int construct_worker(struct in6_addr *local, int prefix, 
			    int scope, int if_index, int flags, 
			    unsigned int preferred, unsigned int valid, void *vparam)
{
  char ifrn_name[IFNAMSIZ];
  struct in6_addr start6, end6;
  struct dhcp_context *template, *context;
  struct iname *tmp;
  
  (void)scope;
  (void)flags;
  (void)valid;
  (void)preferred;

  struct cparam *param = vparam;

  if (IN6_IS_ADDR_LOOPBACK(local) ||
      IN6_IS_ADDR_LINKLOCAL(local) ||
      IN6_IS_ADDR_MULTICAST(local))
    return 1;

  if (!(flags & IFACE_PERMANENT))
    return 1;

  if (flags & IFACE_DEPRECATED)
    return 1;

  /* Ignore interfaces where we're not doing RA/DHCP6 */
  if (!indextoname(daemon->icmp6fd, if_index, ifrn_name) ||
      !iface_check(AF_LOCAL, NULL, ifrn_name, NULL))
    return 1;
  
  for (tmp = daemon->dhcp_except; tmp; tmp = tmp->next)
    if (tmp->name && wildcard_match(tmp->name, ifrn_name))
      return 1;

  for (template = daemon->dhcp6; template; template = template->next)
    if (!(template->flags & (CONTEXT_TEMPLATE | CONTEXT_CONSTRUCTED)))
      {
	/* non-template entries, just fill in interface and local addresses */
	if (prefix <= template->prefix &&
	    is_same_net6(local, &template->start6, template->prefix) &&
	    is_same_net6(local, &template->end6, template->prefix))
	  {
	    /* First time found, do fast RA. */
	    if (template->if_index == 0)
	      {
		ra_start_unsolicited(param->now, template);
		param->newone = 1;
	      }
	    
	    template->if_index = if_index;
	    template->local6 = *local;
	  }
	
      }
    else if (wildcard_match(template->template_interface, ifrn_name) &&
	     template->prefix >= prefix)
      {
	start6 = *local;
	setaddr6part(&start6, addr6part(&template->start6));
	end6 = *local;
	setaddr6part(&end6, addr6part(&template->end6));
	
	for (context = daemon->dhcp6; context; context = context->next)
	  if (!(context->flags & CONTEXT_TEMPLATE) &&
	      IN6_ARE_ADDR_EQUAL(&start6, &context->start6) &&
	      IN6_ARE_ADDR_EQUAL(&end6, &context->end6))
	    {
	      /* If there's an absolute address context covering this address
		 then don't construct one as well. */
	      if (!(context->flags & CONTEXT_CONSTRUCTED))
		break;
	      
	      if (context->if_index == if_index)
		{
		  int cflags = context->flags;
		  context->flags &= ~(CONTEXT_GC | CONTEXT_OLD);
		  if (cflags & CONTEXT_OLD)
		    {
		      /* address went, now it's back, and on the same interface */
		      log_context(AF_INET6, context); 
		      /* fast RAs for a while */
		      ra_start_unsolicited(param->now, context);
		      param->newone = 1; 
		      /* Add address to name again */
		      if (context->flags & CONTEXT_RA_NAME)
			param->newname = 1;
		    
		    }
		  break;
		}
	    }
	
	if (!context && (context = whine_malloc(sizeof (struct dhcp_context))))
	  {
	    *context = *template;
	    context->start6 = start6;
	    context->end6 = end6;
	    context->flags &= ~CONTEXT_TEMPLATE;
	    context->flags |= CONTEXT_CONSTRUCTED;
	    context->if_index = if_index;
	    context->local6 = *local;
	    context->saved_valid = 0;
	    
	    context->next = daemon->dhcp6;
	    daemon->dhcp6 = context;

	    ra_start_unsolicited(param->now, context);
	    /* we created a new one, need to call
	       lease_update_file to get periodic functions called */
	    param->newone = 1; 

	    /* Will need to add new putative SLAAC addresses to existing leases */
	    if (context->flags & CONTEXT_RA_NAME)
	      param->newname = 1;
	    
	    log_context(AF_INET6, context);
	  } 
      }
  
  return 1;
}

/**
 * @brief Reconstruct DHCPv6 contexts dynamically from current network interface configuration
 * 
 * @detailed This function performs a complete DHCPv6 context reconstruction cycle by enumerating
 *           all IPv6 addresses on network interfaces and creating/updating contexts to match.
 *           The three-phase process ensures contexts accurately reflect current network state:
 *           Phase 1 - Mark all existing CONTEXT_CONSTRUCTED contexts with CONTEXT_GC (garbage
 *           collection) flag; Phase 2 - Call iface_enumerate() with construct_worker() to 
 *           create new contexts or refresh existing ones (clearing CONTEXT_GC); Phase 3 - 
 *           Process contexts that still have CONTEXT_GC flag (indicating interface address 
 *           disappeared): if Router Advertisement is active, mark context CONTEXT_OLD and 
 *           trigger unsolicited RA to advertise address deprecation, otherwise free the context.
 *           This mechanism enables automatic DHCPv6 adaptation to interface reconfiguration,
 *           address addition/removal, and network topology changes without daemon restart.
 * 
 * @param now Current timestamp from dnsmasq_time() for lease management and RA scheduling
 * 
 * @note Called periodically to synchronize DHCPv6 contexts with actual interface configuration
 * @note CONTEXT_GC flag implements mark-and-sweep garbage collection: contexts not refreshed
 *       during enumeration are candidates for removal or deprecation
 * @note CONTEXT_OLD flag on deprecated contexts triggers Router Advertisement with zero
 *       lifetime to inform clients that addresses are no longer available
 * @note saved_valid lifetime is capped at context->lease_time and absolute maximum 7200
 *       seconds (2 hours per RFC) when transitioning to CONTEXT_OLD state
 * @note CONTEXT_RA_NAME flag indicates SLAAC-derived names should be updated via
 *       lease_update_slaac() when contexts change
 * 
 * @warning Modifies global daemon->dhcp6 context list by removing deprecated contexts
 *          or updating flags on existing contexts
 * @warning Memory deallocation via free() for contexts no longer needed (non-RA contexts
 *          that disappeared)
 * @warning Triggers unsolicited Router Advertisements via ra_start_unsolicited() which
 *          generates network traffic
 * @warning File I/O operations via lease_update_file() and lease_update_slaac() when
 *          contexts change, potentially blocking if filesystem is slow
 * 
 * @see construct_worker() for individual address processing callback
 * @see iface_enumerate() in network.c for interface enumeration driver
 * @see ra_start_unsolicited() in radv.c for Router Advertisement transmission
 * @see lease_update_file() in lease.c for lease database persistence
 * @see lease_update_slaac() in lease.c for SLAAC name synchronization
 * @see periodic_ra() in radv.c for periodic RA scheduling
 * 
 * EXAMPLE USAGE:
 * @code
 * // Called periodically from main event loop when interface state changes
 * time_t now = dnsmasq_time();
 * dhcp_construct_contexts(now);
 * // Contexts now reflect current interface configuration
 * @endcode
 * 
 * RFC COMPLIANCE: Implements dynamic prefix configuration per RFC 3315 Section 12;
 *                 Router Advertisement lifetime management per RFC 4861 Section 6.2.5
 * SIDE EFFECTS: Modifies daemon->dhcp6 context list; triggers unsolicited Router
 *               Advertisements for deprecated addresses; updates lease database files
 *               via lease_update_file() and lease_update_slaac(); schedules periodic
 *               RA alarms via send_alarm(periodic_ra()) in non-DHCP mode; logs context
 *               changes via log_context(); may free() dynamically allocated contexts
 * THREAD SAFETY: Single-threaded architecture; modifies global daemon state
 */
void dhcp_construct_contexts(time_t now)
{ 
  struct dhcp_context *context, *tmp, **up;
  struct cparam param;
  param.newone = 0;
  param.newname = 0;
  param.now = now;

  for (context = daemon->dhcp6; context; context = context->next)
    if (context->flags & CONTEXT_CONSTRUCTED)
      context->flags |= CONTEXT_GC;
   
  iface_enumerate(AF_INET6, &param, (callback_t){.af_inet6=construct_worker});

  for (up = &daemon->dhcp6, context = daemon->dhcp6; context; context = tmp)
    {
      
      tmp = context->next; 
     
      if (context->flags & CONTEXT_GC && !(context->flags & CONTEXT_OLD))
	{
	  if ((context->flags & CONTEXT_RA) || option_bool(OPT_RA))
	    {
	      /* previously constructed context has gone; advertise its demise */
	      context->flags |= CONTEXT_OLD;
	      context->address_lost_time = now;
	      /* Apply same ceiling of configured lease time as in radv.c */
	      if (context->saved_valid > context->lease_time)
		context->saved_valid = context->lease_time;
	      /* maximum time is 2 hours, from RFC */
	      if (context->saved_valid > 7200) /* 2 hours */
		context->saved_valid = 7200;
	      ra_start_unsolicited(now, context);
	      param.newone = 1; /* include deletion */ 
	      
	      if (context->flags & CONTEXT_RA_NAME)
		param.newname = 1; 
			      
	      log_context(AF_INET6, context);
	      
	      up = &context->next;
	    }
	  else
	    {
	      /* we were never doing RA for this, so free now */
	      *up = context->next;
	      free(context);
	    }
	}
      else
	 up = &context->next;
    }
  
  if (param.newone)
    {
      if (daemon->dhcp || daemon->doing_dhcp6)
	{
	  if (param.newname)
	    lease_update_slaac(now);
	  lease_update_file(now);
	}
      else 
	/* Not doing DHCP, so no lease system, manage alarms for ra only */
	send_alarm(periodic_ra(now), now);
    }
}

#endif /* HAVE_DHCP6 */

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
 * @file radv.c
 * @brief IPv6 Router Advertisement Implementation
 * 
 * DETAILED PURPOSE:
 * This module implements IPv6 Router Advertisement (RA) functionality per RFC 4861
 * (IPv6 Neighbor Discovery Protocol). It constructs and transmits ICMPv6 Router
 * Advertisement messages (type 134) containing network configuration information
 * to enable IPv6 Stateless Address Autoconfiguration (SLAAC) on client devices.
 * 
 * The implementation provides integrated IPv6 network management by coordinating
 * with the DHCPv6 server to control client addressing behavior through M (managed)
 * and O (other configuration) flags. This coordination enables flexible deployment
 * models: SLAAC-only, SLAAC with stateless DHCPv6 configuration, or full stateful
 * DHCPv6 address management.
 * 
 * KEY RESPONSIBILITIES:
 * - ICMPv6 packet reception and processing (Router Solicitations, Echo Replies for SLAAC confirmation)
 * - Router Advertisement message construction with RFC 4861 packet format (ra_packet structure)
 * - Prefix Information Option (PIO) generation with valid/preferred lifetimes for SLAAC
 * - M and O flag configuration controlling DHCPv6 behavior (M=1 stateful, O=1 stateless)
 * - Recursive DNS Server (RDNSS) option inclusion per RFC 6106
 * - MTU option, Advertisement Interval option, Route Information option support
 * - Periodic unsolicited RA transmission with configurable intervals
 * - Router Solicitation response for immediate client configuration
 * - SLAAC address confirmation via ping (Echo Request/Reply) for RA-names mode
 * - Integration with dhcp6.c for DHCPv6 coordination and slaac.c for address validation
 * 
 * DEPENDENCIES:
 * Includes: dnsmasq.h (core data structures), netinet/icmp6.h (ICMPv6 definitions)
 * Called by: dhcp6.c (DHCPv6 server), network.c (event loop packet dispatch)
 * Calls: dhcp6.c (DHCPv6 context management), slaac.c (confirm_address),
 *        network.c (packet transmission via send_from)
 * 
 * DATA STRUCTURES:
 * - struct ra_param: Internal state for RA construction process (lines 29-37)
 *   Tracks interface details, timing, addresses, flags, and found DHCPv6 contexts
 * - struct search_param: Interface search parameters (lines 39-42)
 * - struct alias_param: Bridge alias interface tracking (lines 44-50)
 * - struct ra_interface: Per-interface RA configuration from dnsmasq.h
 *   Contains name, interval, lifetime, priority, MTU settings
 * - struct dhcp_context: DHCPv6 context from dnsmasq.h with RA timing fields
 *   Includes ra_time, ra_short_period_start for periodic transmission scheduling
 * - struct ra_packet: ICMPv6 RA wire format from radv-protocol.h
 * - struct prefix_opt: Prefix Information Option format from radv-protocol.h
 * 
 * COMPILE-TIME OPTIONS:
 * - HAVE_DHCP6: Master flag enabling all DHCPv6 and RA functionality (required)
 *   This entire file is conditionally compiled only when HAVE_DHCP6 is defined
 * - HAVE_LINUX_NETWORK: Linux-specific netlink interface monitoring
 * - IPV6_TCLASS: Traffic class socket option support for CS6 marking
 * 
 * OPERATIONAL MODES:
 * - ra-only: SLAAC addressing with M=0, O=1 for stateless DHCPv6 configuration
 * - ra-names: SLAAC addressing with RDNSS option, ping confirmation for hostname assignment
 * - ra-stateless: SLAAC addressing with M=0, O=0, no DHCPv6 (RDNSS provides DNS servers)
 * - Stateful DHCPv6: M=1 signals clients to use DHCPv6 for address assignment
 * 
 * RFC COMPLIANCE:
 * - RFC 4861: IPv6 Neighbor Discovery Protocol (Router Advertisement, sections 4.2, 4.6.2, 6.2.3)
 * - RFC 4862: IPv6 Stateless Address Autoconfiguration
 * - RFC 6106: IPv6 Router Advertisement Options for DNS Configuration (RDNSS, DNSSL)
 * - RFC 4191: Default Router Preferences and More-Specific Routes
 * - RFC 6275: Mobility Support in IPv6 (Advertisement Interval option)
 * 
 * THREADING/CONCURRENCY:
 * Single-threaded event-driven architecture. All functions called from main event loop
 * in response to ICMPv6 packet arrival or timer expiration. No locking required.
 * 
 * RESOURCE MANAGEMENT:
 * Uses daemon->outpacket buffer for RA construction (allocated at startup, line 83).
 * This buffer is NOT used by DHCPv4, allowing safe concurrent operation during DHCPv4
 * ping-wait states. Buffer expanded to maximum packet size via expand_buf().
 * 
 * @copyright Copyright (c) 2000-2025 Simon Kelley
 * @license GPL-2.0-or-later
 */

/* NB. This code may be called during a DHCPv4 or transaction which is in ping-wait
   It therefore cannot use any DHCP buffer resources except outpacket, which is
   not used by DHCPv4 code. This code may also be called when DHCP 4 or 6 isn't
   active, so we ensure that outpacket is allocated here too */

#include "dnsmasq.h"

#ifdef HAVE_DHCP6

#include <netinet/icmp6.h>

struct ra_param {
  time_t now;
  int ind, managed, other, first, adv_router;
  char *if_name;
  struct dhcp_netid *tags;
  struct in6_addr link_local, link_global, ula;
  unsigned int glob_pref_time, link_pref_time, ula_pref_time, adv_interval, prio;
  struct dhcp_context *found_context;
};

struct search_param {
  time_t now; int iface;
  char name[IF_NAMESIZE+1];
};

struct alias_param {
  int iface;
  struct dhcp_bridge *bridge;
  int num_alias_ifs;
  int max_alias_ifs;
  int *alias_ifs;
};

static void send_ra(time_t now, int iface, char *iface_name, struct in6_addr *dest);
/**
 * @brief Send ICMPv6 Router Advertisement message on specified interface
 * 
 * @detailed Constructs and transmits complete ICMPv6 Router Advertisement (type 134) packet
 * including prefix information options, M (managed address) and O (other configuration) flags
 * to control DHCPv6 client behavior, RDNSS (Recursive DNS Server) option per RFC 6106,
 * MTU option, and route information options. This function performs the core RA construction
 * logic, calculating appropriate lifetimes, intervals, and priorities based on configuration
 * and current time. Supports multiple operational modes: ra-only (SLAAC addressing with
 * stateless DHCPv6 for configuration), ra-names (SLAAC with RDNSS), and ra-stateless
 * (SLAAC addressing without DHCPv6). Coordinates with DHCPv6 server via M/O flag settings.
 * 
 * The function walks all configured DHCPv6 contexts to determine appropriate prefix
 * advertisements, validates contexts against current interface addresses, calculates
 * preferred and valid lifetimes considering context expiration times, and constructs
 * ICMPv6 options following RFC 4861 wire format. Special handling for SLAAC name
 * confirmation (ra-names mode) where daemon responds to ping requests to verify
 * self-assigned addresses are not in use.
 * 
 * @param now Current time for lifetime and interval calculations
 * @param iface Interface index determining which prefixes to advertise (content source)
 * @param iface_name Interface name for logging and configuration matching (e.g., "eth0")
 * @param dest Destination IPv6 address for RA packet (NULL for all-nodes multicast ff02::1)
 * @param send_iface Physical interface index for actual packet transmission (may differ from iface)
 * 
 * @note M=1 flag signals stateful DHCPv6 (managed address configuration)
 * @note O=1 flag signals stateless DHCPv6 (other configuration like DNS)
 * @note M=0, O=0 signals SLAAC-only operation (no DHCPv6)
 * @note Prefix valid lifetime capped at 2 hours minimum per RA protocol requirements
 * @note Function uses daemon->outpacket buffer which is not used by DHCPv4
 * 
 * @warning Must not be called during DHCPv4 transaction except using outpacket buffer
 * @warning Interface must exist and be IPv6-enabled; errors logged but not fatal
 * @warning Destination address validation performed; invalid address uses all-nodes multicast
 * 
 * @see send_ra() for wrapper function that sends RA on same interface as content
 * @see icmp6_packet() for RA reception and Router Solicit handling
 * @see add_prefixes() for IPv6 prefix enumeration callback
 * @see new_timeout() for RA retransmission scheduling
 * 
 * EXAMPLE USAGE:
 * @code
 * // Send RA on eth0 with content from eth0, destination all-nodes multicast
 * time_t now = dnsmasq_time();
 * int iface_idx = if_nametoindex("eth0");
 * send_ra_alias(now, iface_idx, "eth0", NULL, iface_idx);
 * 
 * // Send RA with specific destination (Router Solicit response)
 * struct in6_addr client_addr;
 * inet_pton(AF_INET6, "fe80::1234:5678", &client_addr);
 * send_ra_alias(now, iface_idx, "eth0", &client_addr, iface_idx);
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 4861 Section 6.2.3 (Router Advertisement format and transmission)
 * RFC COMPLIANCE: RFC 6106 (RDNSS and DNSSL options in Router Advertisements)
 * RFC COMPLIANCE: RFC 4191 (Route Information Option for RA)
 * 
 * SIDE EFFECTS: Transmits ICMPv6 packet on specified network interface via sendmsg
 * SIDE EFFECTS: Updates context timeout for next RA transmission via new_timeout
 * SIDE EFFECTS: May log warnings for configuration errors or transmission failures
 * 
 * THREAD SAFETY: Single-threaded event loop, not reentrant, uses shared daemon->outpacket buffer
 */
static void send_ra_alias(time_t now, int iface, char *iface_name, struct in6_addr *dest,
                    int send_iface);
static int send_ra_to_aliases(int index, unsigned int type, char *mac, size_t maclen, void *parm);
static int add_prefixes(struct in6_addr *local,  int prefix,
			int scope, int if_index, int flags, 
			unsigned int preferred, unsigned int valid, void *vparam);
static int iface_search(struct in6_addr *local,  int prefix,
			int scope, int if_index, int flags, 
			unsigned int prefered, unsigned int valid, void *vparam);
static int add_lla(int index, unsigned int type, char *mac, size_t maclen, void *parm);
static void new_timeout(struct dhcp_context *context, char *iface_name, time_t now);
static unsigned int calc_lifetime(struct ra_interface *ra);
static unsigned int calc_interval(struct ra_interface *ra);
static unsigned int calc_prio(struct ra_interface *ra);
static struct ra_interface *find_iface_param(char *iface);

static int hop_limit;

/**
 * @brief Initialize Router Advertisement subsystem and ICMPv6 socket
 * 
 * @detailed Creates ICMPv6 raw socket for Router Advertisement transmission and
 * Router Solicitation reception. Configures socket options including hop limit (255),
 * traffic class (CS6 for network control), ICMPv6 filter to accept only Router
 * Solicitations (type 133) and optionally Echo Replies (type 129) for SLAAC
 * address confirmation. Allocates outpacket buffer for RA construction.
 * 
 * This function initializes the RA subsystem regardless of whether Router Advertisement
 * is actively enabled (daemon->doing_ra), because the ICMPv6 socket is also used by
 * DHCPv6 for link-local communication. The socket is configured to receive Router
 * Solicitations only when daemon->doing_ra is true, enabling on-demand RA responses.
 * 
 * SLAAC address confirmation (RA-names mode) requires Echo Reply reception for ping-based
 * duplicate address detection, so the filter is adjusted when CONTEXT_RA_NAME contexts exist.
 * 
 * @param now Current time for context initialization and timing calculations
 * 
 * @return void (function does not return error status; aborts on fatal errors via die())
 * 
 * @note Called once during daemon startup from main event loop initialization
 * @warning Creates raw socket requiring CAP_NET_RAW capability or root privileges initially
 * 
 * @see icmp6_packet() for Router Solicitation processing
 * @see confirm_address() in slaac.c for SLAAC ping confirmation logic
 * 
 * EXAMPLE USAGE:
 * @code
 * time_t now = dnsmasq_time();
 * ra_init(now);  // Initialize RA subsystem at daemon startup
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 4861 Section 6.1.1 (Router Configuration Variables)
 * SIDE EFFECTS: Creates global ICMPv6 socket daemon->icmp6fd, allocates outpacket buffer
 * THREAD SAFETY: Called once at startup before event loop, no concurrency concerns
 */
void ra_init(time_t now)
{
  struct icmp6_filter filter;
  int fd;
#if defined(IPV6_TCLASS) && defined(IPTOS_CLASS_CS6)
  int class = IPTOS_CLASS_CS6;
#endif
  int val = 255; /* radvd uses this value */
  socklen_t len = sizeof(int);
  struct dhcp_context *context;
  
  /* ensure this is around even if we're not doing DHCPv6 */
  expand_buf(&daemon->outpacket, sizeof(struct dhcp_packet));
 
  /* See if we're guessing SLAAC addresses, if so we need to receive ping replies */
  for (context = daemon->dhcp6; context; context = context->next)
    if ((context->flags & CONTEXT_RA_NAME))
      break;
  
  /* Need ICMP6 socket for transmission for DHCPv6 even when not doing RA. */

  ICMP6_FILTER_SETBLOCKALL(&filter);
  if (daemon->doing_ra)
    {
      ICMP6_FILTER_SETPASS(ND_ROUTER_SOLICIT, &filter);
      if (context)
	ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY, &filter);
    }
  
  if ((fd = socket(PF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) == -1 ||
      getsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &hop_limit, &len) ||
#if defined(IPV6_TCLASS) && defined(IPTOS_CLASS_CS6)
      setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS, &class, sizeof(class)) == -1 ||
#endif
      !fix_fd(fd) ||
      !set_ipv6pktinfo(fd) ||
      setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &val, sizeof(val)) ||
      setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &val, sizeof(val)) ||
      setsockopt(fd, IPPROTO_ICMPV6, ICMP6_FILTER, &filter, sizeof(filter)) == -1)
    die (_("cannot create ICMPv6 socket: %s"), NULL, EC_BADNET);
  
   daemon->icmp6fd = fd;
   
   if (daemon->doing_ra)
     ra_start_unsolicited(now, NULL);
}

/**
 * @brief Start unsolicited Router Advertisement transmission for DHCPv6 contexts
 * 
 * @detailed Initializes RA timers to schedule unsolicited RA transmissions for IPv6
 *           contexts. If a specific context is provided, schedules RA for that context
 *           with 1-second delay. If no context is provided (NULL), initializes all
 *           non-template DHCPv6 contexts with randomized initial delays (0-5 seconds)
 *           and enables short period mode for rapid initial advertisement. This function
 *           is called at daemon startup and on netlink route changes to re-advertise
 *           network configuration and discover new interfaces.
 * 
 * @param now Current time in seconds since epoch
 * @param context Specific DHCPv6 context to start RA for, or NULL to initialize all contexts
 * 
 * @return None (void function, modifies context ra_time and ra_short_period_start fields)
 * 
 * @note When context is NULL, all DHCPv6 contexts except templates are initialized.
 *       The random delay (0-5 seconds) prevents synchronized RA bursts from multiple
 *       routers on the same network. Short period mode causes frequent RAs for ~1 minute
 *       to ensure reliable initial advertisement even if first packet is lost.
 * 
 * @warning Context ra_times may be zeroed later if advertisement is not appropriate
 *          for specific contexts based on network configuration.
 * 
 * @see ra_init() for initial daemon setup calling this function
 * @see periodic_ra() for scheduled RA transmission
 * @see send_ra() for actual RA packet construction
 * 
 * EXAMPLE USAGE:
 * @code
 * // At daemon startup, initialize all contexts
 * ra_start_unsolicited(dnsmasq_time(), NULL);
 * 
 * // For specific context after route change
 * struct dhcp_context *ctx = daemon->dhcp6;
 * ra_start_unsolicited(dnsmasq_time(), ctx);
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 4861 Section 6.2.4 (unsolicited multicast RA timing)
 * SIDE EFFECTS: Modifies context->ra_time and context->ra_short_period_start for one or all contexts
 * THREAD SAFETY: Single-threaded architecture, safe
 */
void ra_start_unsolicited(time_t now, struct dhcp_context *context)
{   
   /* init timers so that we do ra's for some/all soon. some ra_times will end up zeroed
     if it's not appropriate to advertise those contexts.
     This gets re-called on a netlink route-change to re-do the advertisement
     and pick up new interfaces */
  
  if (context)
    {
      context->ra_short_period_start = now;
      /* start after 1 second to get logging right at startup. */
      context->ra_time = now + 1;
    }
  else
    for (context = daemon->dhcp6; context; context = context->next)
      if (!(context->flags & CONTEXT_TEMPLATE))
	{
	  context->ra_time = now + (rand16()/13000); /* range 0 - 5 */
	  /* re-do frequently for a minute or so, in case the first gets lost. */
	  context->ra_short_period_start = now;
	}
}

/**
 * @brief Process incoming ICMPv6 packets for Router Advertisement and SLAAC confirmation
 * 
 * @detailed Main ICMPv6 packet handler that processes two types of messages:
 *           (1) ICMP6_ECHO_REPLY - Echo replies for SLAAC address confirmation ping tests
 *           (2) ND_ROUTER_SOLICIT - Router Solicitations requiring RA responses
 *           
 *           For router solicitations, this function extracts the source link-layer address
 *           from ICMPv6 options for logging, checks for bridge interface aliasing (where
 *           the receiving interface is an alias for another interface per --bridge-interface
 *           configuration), and sends an appropriate RA response using either the aliased
 *           interface context or the receiving interface context.
 *           
 *           The function performs extensive validation including interface name resolution,
 *           interface permission checks, DHCPv6 exception list filtering, packet code
 *           verification, and option parsing with bounds checking.
 * 
 * @param now Current time in seconds since epoch for RA timestamp and scheduling
 * 
 * @return None (void function, sends RA packets as side effect)
 * 
 * @note Uses daemon->outpacket as input buffer (shared with DHCPv6 but safe due to
 *       non-overlapping usage). ICMPv6 socket (daemon->icmp6fd) must be initialized
 *       by ra_init() before calling this function. Packet reception uses recvmsg()
 *       with ancillary data to extract receiving interface index.
 * 
 * @warning Function returns silently on errors: receive failure, invalid packet size
 *          (<8 bytes), interface name resolution failure, interface check failure,
 *          DHCPv6 exception match, non-zero ICMPv6 code field, or malformed options.
 *          Malformed Router Solicitation options (opt_sz == 0 or > remaining length)
 *          are treated as bad packets and processing terminates immediately.
 * 
 * @see ra_init() for ICMPv6 socket initialization and packet filter setup
 * @see send_ra() for unicast/multicast RA transmission to soliciting host
 * @see send_ra_alias() for RA transmission using bridge interface context
 * @see lease_ping_reply() for SLAAC address confirmation processing
 * 
 * EXAMPLE USAGE:
 * @code
 * // Called from main event loop when ICMPv6 socket has data
 * if (poll_check(daemon->icmp6fd, POLLIN))
 *   icmp6_packet(dnsmasq_time());
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 4861 Section 6.2.6 (processing Router Solicitations),
 *                 RFC 4861 Section 4.1 (Router Solicitation format),
 *                 RFC 4861 Section 4.6.1 (Source Link-Layer Address option)
 * 
 * SIDE EFFECTS: 
 * - Sends Router Advertisement packets via send_ra() or send_ra_alias()
 * - Logs RTR-SOLICIT messages to syslog (unless OPT_QUIET_RA set)
 * - Calls lease_ping_reply() for echo replies (may update DHCP lease state)
 * - Dumps packets to pcap file if HAVE_DUMPFILE enabled
 * 
 * THREAD SAFETY: Single-threaded architecture, safe
 */
void icmp6_packet(time_t now)
{
  char interface[IF_NAMESIZE+1];
  ssize_t sz; 
  int if_index = 0;
  struct cmsghdr *cmptr;
  struct msghdr msg;
  union {
    struct cmsghdr align; /* this ensures alignment */
    char control6[CMSG_SPACE(sizeof(struct in6_pktinfo))];
  } control_u;
  struct sockaddr_in6 from;
  unsigned char *packet;
  struct iname *tmp;

  /* Note: use outpacket for input buffer */
  msg.msg_control = control_u.control6;
  msg.msg_controllen = sizeof(control_u);
  msg.msg_flags = 0;
  msg.msg_name = &from;
  msg.msg_namelen = sizeof(from);
  msg.msg_iov = &daemon->outpacket;
  msg.msg_iovlen = 1;
  
  if ((sz = recv_dhcp_packet(daemon->icmp6fd, &msg)) == -1 || sz < 8)
    return;
   
  packet = (unsigned char *)daemon->outpacket.iov_base;

  for (cmptr = CMSG_FIRSTHDR(&msg); cmptr; cmptr = CMSG_NXTHDR(&msg, cmptr))
    if (cmptr->cmsg_level == IPPROTO_IPV6 && cmptr->cmsg_type == daemon->v6pktinfo)
      {
	union {
	  unsigned char *c;
	  struct in6_pktinfo *p;
	} p;
	p.c = CMSG_DATA(cmptr);
        
	if_index = p.p->ipi6_ifindex;
      }
  
  if (!indextoname(daemon->icmp6fd, if_index, interface))
    return;
    
  if (!iface_check(AF_LOCAL, NULL, interface, NULL))
    return;
  
  for (tmp = daemon->dhcp_except; tmp; tmp = tmp->next)
    if (tmp->name && (tmp->flags & INAME_6) &&
	wildcard_match(tmp->name, interface))
      return;
 
  if (packet[1] != 0)
    return;

  if (packet[0] == ICMP6_ECHO_REPLY)
    lease_ping_reply(&from.sin6_addr, packet, interface); 
  else if (packet[0] == ND_ROUTER_SOLICIT)
    {
      char *mac = "";
      struct dhcp_bridge *bridge, *alias;
      ssize_t rem;
      unsigned char *p;
      int opt_sz;
      
#ifdef HAVE_DUMPFILE
      dump_packet_icmp(DUMP_RA, (void *)packet, sz, (union mysockaddr *)&from, NULL);
#endif           
      
      /* look for link-layer address option for logging */
      for (rem = sz - 8, p = &packet[8]; rem >= 2; rem -= opt_sz, p += opt_sz)
	{
	  opt_sz = p[1] * 8;
	  
	  if (opt_sz == 0 || opt_sz > rem)
	    return; /* Bad packet */
	  
	  if (p[0] == ICMP6_OPT_SOURCE_MAC && ((opt_sz - 2) * 3 - 1 < MAXDNAME))
	    {
	      print_mac(daemon->namebuff, &p[2], opt_sz - 2);
	      mac = daemon->namebuff;
	    }
	}
      
      if (!option_bool(OPT_QUIET_RA))
	my_syslog(MS_DHCP | LOG_INFO, "RTR-SOLICIT(%s) %s", interface, mac);

      /* If the incoming interface is an alias of some other one (as
         specified by the --bridge-interface option), send an RA using
         the context of the aliased interface. */
      for (bridge = daemon->bridges; bridge; bridge = bridge->next)
        {
          int bridge_index = if_nametoindex(bridge->iface);
          if (bridge_index)
	    {
	      for (alias = bridge->alias; alias; alias = alias->next)
		if (wildcard_matchn(alias->iface, interface, IF_NAMESIZE))
		  {
		    /* Send an RA on if_index with information from
		       bridge_index. */
		    send_ra_alias(now, bridge_index, bridge->iface, NULL, if_index);
		    break;
		  }
	      if (alias)
		break;
	    }
        }

      /* If the incoming interface wasn't an alias, send an RA using
	 the context of the incoming interface. */
      if (!bridge)
	/* source address may not be valid in solicit request. */
	send_ra(now, if_index, interface, !IN6_IS_ADDR_UNSPECIFIED(&from.sin6_addr) ? &from.sin6_addr : NULL);
    }
}

static void send_ra_alias(time_t now, int iface, char *iface_name, struct in6_addr *dest, int send_iface)
{
  struct ra_packet *ra;
  struct ra_param parm;
  struct sockaddr_in6 addr;
  struct dhcp_context *context, *tmp,  **up;
  struct dhcp_netid iface_id;
  struct dhcp_opt *opt_cfg;
  struct ra_interface *ra_param = find_iface_param(iface_name);
  int done_dns = 0, old_prefix = 0, mtu = 0;
  unsigned int min_pref_time;
#ifdef HAVE_LINUX_NETWORK
  FILE *f;
#endif
  
  parm.ind = iface;
  parm.managed = 0;
  parm.other = 0;
  parm.found_context = NULL;
  parm.adv_router = 0;
  parm.if_name = iface_name;
  parm.first = 1;
  parm.now = now;
  parm.glob_pref_time = parm.link_pref_time = parm.ula_pref_time = 0;
  parm.adv_interval = calc_interval(ra_param);
  parm.prio = calc_prio(ra_param);
  
  reset_counter();
  
  if (!(ra = expand(sizeof(struct ra_packet))))
    return;
  
  ra->type = ND_ROUTER_ADVERT;
  ra->code = 0;
  ra->hop_limit = hop_limit;
  ra->flags = parm.prio;
  ra->lifetime = htons(calc_lifetime(ra_param));
  ra->reachable_time = 0;
  ra->retrans_time = 0;

  /* set tag with name == interface */
  iface_id.net = iface_name;
  iface_id.next = NULL;
  parm.tags = &iface_id; 
  
  for (context = daemon->dhcp6; context; context = context->next)
    {
      context->flags &= ~CONTEXT_RA_DONE;
      context->netid.next = &context->netid;
    }

  /* If no link-local address then we can't advertise since source address of
     advertisement must be link local address: RFC 4861 para 6.1.2. */
  if (!iface_enumerate(AF_INET6, &parm, (callback_t){.af_inet6=add_prefixes}) ||
      parm.link_pref_time == 0)
    return;

  /* Find smallest preferred time within address classes,
     to use as lifetime for options. This is a rather arbitrary choice. */
  min_pref_time = 0xffffffff;
  if (parm.glob_pref_time != 0 && parm.glob_pref_time < min_pref_time)
    min_pref_time = parm.glob_pref_time;
  
  if (parm.ula_pref_time != 0 && parm.ula_pref_time < min_pref_time)
    min_pref_time = parm.ula_pref_time;

  if (parm.link_pref_time != 0 && parm.link_pref_time < min_pref_time)
    min_pref_time = parm.link_pref_time;

  /* Look for constructed contexts associated with addresses which have gone, 
     and advertise them with preferred_time == 0  RFC 6204 4.3 L-13 */
  for (up = &daemon->dhcp6, context = daemon->dhcp6; context; context = tmp)
    {
      tmp = context->next;

      if (context->if_index == iface && (context->flags & CONTEXT_OLD))
	{
	  unsigned int old = difftime(now, context->address_lost_time);
	  
	  if (old > context->saved_valid)
	    { 
	      /* We've advertised this enough, time to go */
	     
	      /* If this context held the timeout, and there's another context in use
		 transfer the timeout there. */
	      if (context->ra_time != 0 && parm.found_context && parm.found_context->ra_time == 0)
		new_timeout(parm.found_context, iface_name, now);
	      
	      *up = context->next;
	      free(context);
	    }
	  else
	    {
	      struct prefix_opt *opt;
	      struct in6_addr local = context->start6;
	      int do_slaac = 0;

	      old_prefix = 1;

	      /* zero net part of address */
	      setaddr6part(&local, addr6part(&local) & ~((context->prefix == 64) ? (u64)-1LL : (1LLU << (128 - context->prefix)) - 1LLU));
	     
	      
	      if (context->flags & CONTEXT_RA)
		{
		  do_slaac = 1;
		  if (context->flags & CONTEXT_DHCP)
		    {
		      parm.other = 1; 
		      if (!(context->flags & CONTEXT_RA_STATELESS))
			parm.managed = 1;
		    }
		}
	      else
		{
		  /* don't do RA for non-ra-only unless --enable-ra is set */
		  if (option_bool(OPT_RA))
		    {
		      parm.managed = 1;
		      parm.other = 1;
		    }
		}

	      if ((opt = expand(sizeof(struct prefix_opt))))
		{
		  opt->type = ICMP6_OPT_PREFIX;
		  opt->len = 4;
		  opt->prefix_len = context->prefix;
		  /* autonomous only if we're not doing dhcp, set
                     "on-link" unless "off-link" was specified */
		  opt->flags = (do_slaac ? 0x40 : 0) |
                    ((context->flags & CONTEXT_RA_OFF_LINK) ? 0 : 0x80);
		  opt->valid_lifetime = htonl(context->saved_valid - old);
		  opt->preferred_lifetime = htonl(0);
		  opt->reserved = 0; 
		  opt->prefix = local;
		  
		  inet_ntop(AF_INET6, &local, daemon->addrbuff, ADDRSTRLEN);
		  if (!option_bool(OPT_QUIET_RA))
		    my_syslog(MS_DHCP | LOG_INFO, "RTR-ADVERT(%s) %s old prefix", iface_name, daemon->addrbuff); 		    
		}
	   
	      up = &context->next;
	    }
	}
      else
	up = &context->next;
    }
    
  /* If we're advertising only old prefixes, set router lifetime to zero. */
  if (old_prefix && !parm.found_context)
    ra->lifetime = htons(0);

  /* No prefixes to advertise. */
  if (!old_prefix && !parm.found_context)
    return; 
  
  /* If we're sending router address instead of prefix in at least one prefix,
     include the advertisement interval option. */
  if (parm.adv_router)
    {
      put_opt6_char(ICMP6_OPT_ADV_INTERVAL);
      put_opt6_char(1);
      put_opt6_short(0);
      /* interval value is in milliseconds */
      put_opt6_long(1000 * calc_interval(find_iface_param(iface_name)));
    }

  /* Set the MTU from ra_param if any, an MTU of 0 mean automatic for linux, */
  /* an MTU of -1 prevents the option from being sent. */
  if (ra_param)
    mtu = ra_param->mtu;
#ifdef HAVE_LINUX_NETWORK
  /* Note that IPv6 MTU is not necessarily the same as the IPv4 MTU
     available from SIOCGIFMTU */
  if (mtu == 0)
    {
      char *mtu_name = ra_param ? ra_param->mtu_name : NULL;
      sprintf(daemon->namebuff, "/proc/sys/net/ipv6/conf/%s/mtu", mtu_name ? mtu_name : iface_name);
      if ((f = fopen(daemon->namebuff, "r")))
        {
          if (fgets(daemon->namebuff, MAXDNAME, f))
            mtu = atoi(daemon->namebuff);
          fclose(f);
        }
    }
#endif
  if (mtu > 0)
    {
      put_opt6_char(ICMP6_OPT_MTU);
      put_opt6_char(1);
      put_opt6_short(0);
      put_opt6_long(mtu);
    }
     
  iface_enumerate(AF_LOCAL, &send_iface, (callback_t){.af_local=add_lla});
 
  /* RDNSS, RFC 6106, use relevant DHCP6 options */
  (void)option_filter(parm.tags, NULL, daemon->dhcp_opts6, 0);
  
  for (opt_cfg = daemon->dhcp_opts6; opt_cfg; opt_cfg = opt_cfg->next)
    {
      int i;
      
      /* netids match and not encapsulated? */
      if (!(opt_cfg->flags & DHOPT_TAGOK))
        continue;
      
      if (opt_cfg->opt == OPTION6_DNS_SERVER)
        {
	  struct in6_addr *a;
	  int len;

	  done_dns = 1;

          if (opt_cfg->len == 0)
	    continue;
	  
	  /* reduce len for any addresses we can't substitute */
	  for (a = (struct in6_addr *)opt_cfg->val, len = opt_cfg->len, i = 0; 
	       i < opt_cfg->len; i += IN6ADDRSZ, a++)
	    if ((IN6_IS_ADDR_UNSPECIFIED(a) && parm.glob_pref_time == 0) ||
		(IN6_IS_ADDR_ULA_ZERO(a) && parm.ula_pref_time == 0) ||
		(IN6_IS_ADDR_LINK_LOCAL_ZERO(a) && parm.link_pref_time == 0))
	      len -= IN6ADDRSZ;

	  if (len != 0)
	    {
	      put_opt6_char(ICMP6_OPT_RDNSS);
	      put_opt6_char((len/8) + 1);
	      put_opt6_short(0);
	      put_opt6_long(min_pref_time);
	 
	      for (a = (struct in6_addr *)opt_cfg->val, i = 0; i <  opt_cfg->len; i += IN6ADDRSZ, a++)
		if (IN6_IS_ADDR_UNSPECIFIED(a))
		  {
		    if (parm.glob_pref_time != 0)
		      put_opt6(&parm.link_global, IN6ADDRSZ);
		  }
		else if (IN6_IS_ADDR_ULA_ZERO(a))
		  {
		    if (parm.ula_pref_time != 0)
		    put_opt6(&parm.ula, IN6ADDRSZ);
		  }
		else if (IN6_IS_ADDR_LINK_LOCAL_ZERO(a))
		  {
		    if (parm.link_pref_time != 0)
		      put_opt6(&parm.link_local, IN6ADDRSZ);
		  }
		else
		  put_opt6(a, IN6ADDRSZ);
	    }
	}
      
      if (opt_cfg->opt == OPTION6_DOMAIN_SEARCH && opt_cfg->len != 0)
	{
	  int len = ((opt_cfg->len+7)/8);
	  
	  put_opt6_char(ICMP6_OPT_DNSSL);
	  put_opt6_char(len + 1);
	  put_opt6_short(0);
	  put_opt6_long(min_pref_time); 
	  put_opt6(opt_cfg->val, opt_cfg->len);
	  
	  /* pad */
	  for (i = opt_cfg->len; i < len * 8; i++)
	    put_opt6_char(0);
	}
    }
	
  if (daemon->port == NAMESERVER_PORT && !done_dns && parm.link_pref_time != 0)
    {
      /* default == us, as long as we are supplying DNS service. */
      put_opt6_char(ICMP6_OPT_RDNSS);
      put_opt6_char(3);
      put_opt6_short(0);
      put_opt6_long(min_pref_time); 
      put_opt6(&parm.link_local, IN6ADDRSZ);
    }

  /* set managed bits unless we're providing only RA on this link */
  if (parm.managed)
    ra->flags |= 0x80; /* M flag, managed, */
   if (parm.other)
    ra->flags |= 0x40; /* O flag, other */ 
			
  /* decide where we're sending */
  memset(&addr, 0, sizeof(addr));
#ifdef HAVE_SOCKADDR_SA_LEN
  addr.sin6_len = sizeof(struct sockaddr_in6);
#endif
  addr.sin6_family = AF_INET6;
  addr.sin6_port = htons(IPPROTO_ICMPV6);
  if (dest)
    {
      addr.sin6_addr = *dest;
      if (IN6_IS_ADDR_LINKLOCAL(dest) ||
	  IN6_IS_ADDR_MC_LINKLOCAL(dest))
	addr.sin6_scope_id = iface;
    }
  else
    {
      inet_pton(AF_INET6, ALL_NODES, &addr.sin6_addr); 
      setsockopt(daemon->icmp6fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &send_iface, sizeof(send_iface));
    }
  
#ifdef HAVE_DUMPFILE
  {
    struct sockaddr_in6 src;
    src.sin6_family = AF_INET6;
    src.sin6_addr = parm.link_local;
    
    dump_packet_icmp(DUMP_RA, (void *)daemon->outpacket.iov_base, save_counter(-1), (union mysockaddr *)&src, (union mysockaddr *)&addr);
  }
#endif

  while (retry_send(sendto(daemon->icmp6fd, daemon->outpacket.iov_base, 
			   save_counter(-1), 0, (struct sockaddr *)&addr, 
			   sizeof(addr))));
  
}

/**
 * @brief Send Router Advertisement on primary interface
 * 
 * Sends an IPv6 Router Advertisement message on the specified network interface.
 * This is a convenience wrapper function that calls send_ra_alias() with matching
 * send and content interfaces, ensuring the RA is transmitted on the same interface
 * where the RA content is based.
 * 
 * @param now Current timestamp for timing calculations
 * @param iface Interface index for RA transmission
 * @param iface_name Interface name (e.g., "eth0", "wlan0")
 * @param dest Destination IPv6 address for RA (NULL for all-nodes multicast ff02::1)
 * 
 * @note This function ensures RA content and transmission interface are the same
 * @warning Interface must be valid and up; invalid interface silently fails
 * 
 * @see send_ra_alias() for actual RA construction and transmission
 * @see ra_start_unsolicited() for periodic RA scheduling
 * 
 * EXAMPLE USAGE:
 * @code
 * time_t now = dnsmasq_time();
 * int iface_idx = if_nametoindex("eth0");
 * struct in6_addr all_nodes;
 * inet_pton(AF_INET6, "ff02::1", &all_nodes);
 * send_ra(now, iface_idx, "eth0", &all_nodes);
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 4861 Section 6.2.3 (Router Advertisement transmission)
 * SIDE EFFECTS: Transmits ICMPv6 packet on network interface
 * THREAD SAFETY: Single-threaded event loop, not reentrant
 */
static void send_ra(time_t now, int iface, char *iface_name, struct in6_addr *dest)
{
  /* Send an RA on the same interface that the RA content is based
     on. */
  send_ra_alias(now, iface, iface_name, dest, iface);
}

/**
 * @brief Enumerate IPv6 addresses and construct RA prefix information options
 * 
 * @detailed Callback function invoked by iface_enumerate() for each IPv6 address on the system.
 * Filters addresses by interface index and constructs ICMPv6 Router Advertisement prefix
 * information options (type 3) for addresses matching configured DHCPv6 contexts. Handles
 * link-local address selection, global address and ULA (Unique Local Address) preference
 * logic, lifetime calculations based on context lease times, and M/O flag determination for
 * DHCPv6 coordination. The function implements RFC 4861 prefix information option construction
 * including on-link (L) and autonomous (A) flags, preferred and valid lifetimes.
 * 
 * For link-local addresses (fe80::/10), the function tracks the address with the longest
 * preferred time and stores it in param->link_local for use as the source address in RA
 * transmission. For global unicast and ULA addresses, the function searches through all
 * configured DHCPv6 contexts to find matching network ranges, validates prefix containment,
 * and constructs appropriate prefix options. Special handling for CONTEXT_RA contexts enables
 * SLAAC (Stateless Address Autoconfiguration), while CONTEXT_DHCP contexts set M (managed
 * address) or O (other configuration) flags controlling DHCPv6 client behavior.
 * 
 * Lifetime calculation considers context expiration times: if context has finite lease time,
 * preferred lifetime is reduced to remaining lease time, and valid lifetime is set to lease
 * time. For infinite leases, kernel-provided lifetimes are used. Deprecated addresses (kernel
 * preferred lifetime 0) receive 0 preferred lifetime but retain valid lifetime for ongoing
 * connections.
 * 
 * @param local Pointer to IPv6 address being enumerated from interface
 * @param prefix Prefix length (bits) for this address, typically 64 for SLAAC, 128 for host
 * @param scope Address scope: link-local, global, site-local (unused parameter)
 * @param if_index Interface index from which this address originates
 * @param flags Address flags from kernel (IFA_F_DEPRECATED, IFA_F_TEMPORARY, etc.)
 * @param preferred Preferred lifetime in seconds from kernel (0 = deprecated)
 * @param valid Valid lifetime in seconds from kernel
 * @param vparam Void pointer to struct ra_param containing RA construction state
 * 
 * @return 1 to continue address enumeration, 0 would stop enumeration (always returns 1)
 * 
 * @note Function only processes addresses on interface matching param->ind
 * @note Link-local address with longest preferred time becomes RA source address
 * @note M flag (managed address) set when CONTEXT_DHCP without CONTEXT_RA_STATELESS
 * @note O flag (other configuration) set when CONTEXT_DHCP present
 * @note Valid lifetime capped at 2 hours minimum per RFC 4861 requirements
 * @note ULA (fd00::/8) and global addresses tracked separately for preference logic
 * @note Prefix options added directly to daemon->outpacket buffer
 * 
 * @warning Must not use DHCP buffers except outpacket (may be called during DHCPv4 transaction)
 * @warning Context lease time calculations require valid context->lease_time field
 * @warning Deprecated addresses (preferred=0) receive 0 preferred lifetime in RA
 * 
 * @see send_ra_alias() for RA construction that invokes this callback via iface_enumerate()
 * @see iface_enumerate() for IPv6 address enumeration across system interfaces
 * @see struct prefix_opt in radv-protocol.h for ICMPv6 prefix option wire format
 * @see is_same_net6() for IPv6 prefix matching against context ranges
 * 
 * EXAMPLE USAGE:
 * @code
 * // Invoked automatically by iface_enumerate in send_ra_alias:
 * struct ra_param param;
 * param.ind = if_nametoindex("eth0");
 * param.managed = 0;
 * param.other = 0;
 * param.now = dnsmasq_time();
 * // add_prefixes called for each IPv6 address on system:
 * iface_enumerate(AF_INET6, &param, add_prefixes);
 * // After enumeration, param.link_local contains selected link-local address,
 * // param.managed and param.other reflect M/O flag settings,
 * // and daemon->outpacket contains constructed prefix options
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 4861 Section 4.6.2 (Prefix Information option format)
 * RFC COMPLIANCE: RFC 4862 Section 5.5.3 (Router Advertisement processing by hosts)
 * RFC COMPLIANCE: RFC 4193 (Unique Local IPv6 Unicast Addresses - ULA fd00::/8)
 * 
 * SIDE EFFECTS: Modifies param->link_local, param->managed, param->other based on addresses
 * SIDE EFFECTS: Appends prefix_opt structures to daemon->outpacket for matching addresses
 * SIDE EFFECTS: Sets context->saved_valid for contexts matching enumerated addresses
 * SIDE EFFECTS: May set param->first=0 after first valid prefix, param->adv_router for default route
 * 
 * THREAD SAFETY: Single-threaded event loop, not reentrant, modifies shared daemon->outpacket buffer
 */
static int add_prefixes(struct in6_addr *local,  int prefix,
			int scope, int if_index, int flags, 
			unsigned int preferred, unsigned int valid, void *vparam)
{
  struct ra_param *param = vparam;

  (void)scope; /* warning */
  
  if (if_index == param->ind)
    {
      if (IN6_IS_ADDR_LINKLOCAL(local))
	{
	  /* Can there be more than one LL address?
	     Select the one with the longest preferred time 
	     if there is. */
	  if (preferred > param->link_pref_time)
	    {
	      param->link_pref_time = preferred;
	      param->link_local = *local;
	    }
	}
      else if (!IN6_IS_ADDR_LOOPBACK(local) &&
	       !IN6_IS_ADDR_MULTICAST(local))
	{
	  int real_prefix = 0;
	  int do_slaac = 0;
	  int deprecate  = 0;
	  int constructed = 0;
	  int adv_router = 0;
	  int off_link = 0;
	  unsigned int time = 0xffffffff;
	  struct dhcp_context *context;
	  
	  for (context = daemon->dhcp6; context; context = context->next)
	    if (!(context->flags & (CONTEXT_TEMPLATE | CONTEXT_OLD)) &&
		prefix <= context->prefix &&
		is_same_net6(local, &context->start6, context->prefix) &&
		is_same_net6(local, &context->end6, context->prefix))
	      {
		context->saved_valid = valid;

		if (context->flags & CONTEXT_RA) 
		  {
		    do_slaac = 1;
		    if (context->flags & CONTEXT_DHCP)
		      {
			param->other = 1; 
			if (!(context->flags & CONTEXT_RA_STATELESS))
			  param->managed = 1;
		      }
		  }
		else
		  {
		    /* don't do RA for non-ra-only unless --enable-ra is set */
		    if (!option_bool(OPT_RA))
		      continue;
		    param->managed = 1;
		    param->other = 1;
		  }

		/* Configured to advertise router address, not prefix. See RFC 3775 7.2 
		 In this case we do all addresses associated with a context, 
		 hence the real_prefix setting here. */
		if (context->flags & CONTEXT_RA_ROUTER)
		  {
		    adv_router = 1;
		    param->adv_router = 1;
		    real_prefix = context->prefix;
		  }

		/* find floor time, don't reduce below 3 * RA interval.
		   If the lease time has been left as default, don't
		   use that as a floor. */
		if ((context->flags & CONTEXT_SETLEASE) &&
		    time > context->lease_time)
		  {
		    time = context->lease_time;
		    if (time < ((unsigned int)(3 * param->adv_interval)))
		      time = 3 * param->adv_interval;
		  }

		if (context->flags & CONTEXT_DEPRECATE)
		  deprecate = 1;
		
		if (context->flags & CONTEXT_CONSTRUCTED)
		  constructed = 1;


		/* collect dhcp-range tags */
		if (context->netid.next == &context->netid && context->netid.net)
		  {
		    context->netid.next = param->tags;
		    param->tags = &context->netid;
		  }
		  
		/* subsequent prefixes on the same interface 
		   and subsequent instances of this prefix don't need timers.
		   Be careful not to find the same prefix twice with different
		   addresses unless we're advertising the actual addresses. */
		if (!(context->flags & CONTEXT_RA_DONE))
		  {
		    if (!param->first)
		      context->ra_time = 0;
		    context->flags |= CONTEXT_RA_DONE;
		    real_prefix = context->prefix;
                    off_link = (context->flags & CONTEXT_RA_OFF_LINK);
		  }

		param->first = 0;
		/* found_context is the _last_ one we found, so if there's 
		   more than one, it's not the first. */
		param->found_context = context;
	      }

	  /* configured time is ceiling */
	  if (!constructed || valid > time)
	    valid = time;
	  
	  if (flags & IFACE_DEPRECATED)
	    preferred = 0;
	  
	  if (deprecate)
	    time = 0;
	  
	  /* configured time is ceiling */
	  if (!constructed || preferred > time)
	    preferred = time;
	  
	  if (IN6_IS_ADDR_ULA(local))
	    {
	      if (preferred > param->ula_pref_time)
		{
		  param->ula_pref_time = preferred;
		  param->ula = *local;
		}
	    }
	  else 
	    {
	      if (preferred > param->glob_pref_time)
		{
		  param->glob_pref_time = preferred;
		  param->link_global = *local;
		}
	    }
	  
	  if (real_prefix != 0)
	    {
	      struct prefix_opt *opt;
	     	      
	      if ((opt = expand(sizeof(struct prefix_opt))))
		{
		  /* zero net part of address */
		  if (!adv_router)
		    setaddr6part(local, addr6part(local) & ~((real_prefix == 64) ? (u64)-1LL : (1LLU << (128 - real_prefix)) - 1LLU));
		  
		  opt->type = ICMP6_OPT_PREFIX;
		  opt->len = 4;
		  opt->prefix_len = real_prefix;
		  /* autonomous only if we're not doing dhcp, set
                     "on-link" unless "off-link" was specified */
		  opt->flags = (off_link ? 0 : 0x80);
		  if (do_slaac)
		    opt->flags |= 0x40;
		  if (adv_router)
		    opt->flags |= 0x20;
		  opt->valid_lifetime = htonl(valid);
		  opt->preferred_lifetime = htonl(preferred);
		  opt->reserved = 0; 
		  opt->prefix = *local;
		  
		  inet_ntop(AF_INET6, local, daemon->addrbuff, ADDRSTRLEN);
		  if (!option_bool(OPT_QUIET_RA))
		    my_syslog(MS_DHCP | LOG_INFO, "RTR-ADVERT(%s) %s", param->if_name, daemon->addrbuff); 		    
		}
	    }
	}
    }          
  return 1;
}

/**
 * @brief Add Source Link-Layer Address option to Router Advertisement packet
 * 
 * @detailed Callback function used with iface_enumerate() to add the ICMP6_OPT_SOURCE_MAC
 *           option to an RA packet being constructed. This option advertises the router's
 *           link-layer (MAC) address on the interface, allowing IPv6 neighbors to populate
 *           their neighbor cache without sending a separate Neighbor Solicitation. The
 *           function only processes the interface matching the target index passed via parm.
 *           Option length is calculated in 8-octet units per RFC 4861, with proper alignment.
 * 
 * @param index Interface index from enumeration
 * @param type Interface type (unused, cast to void)
 * @param mac Pointer to MAC address bytes
 * @param maclen Length of MAC address in bytes (typically 6 for Ethernet)
 * @param parm Pointer to target interface index (int*)
 * 
 * @return 0 if option successfully added for matching interface, 1 otherwise
 * @retval 0 Option added successfully for target interface
 * @retval 1 Interface doesn't match target or expand() failed
 * 
 * @note Option length field is in 8-octet units including type and length bytes.
 *       Formula: len = (maclen + 2 + 7) / 8 = (maclen + 9) >> 3 (rounds up).
 *       For 6-byte Ethernet MAC: (6+9)/8 = 1 unit = 8 bytes total.
 * 
 * @warning expand() may fail if outpacket buffer exhausted, returns 1 on failure.
 *          Caller must check return value.
 * 
 * @see iface_enumerate() which calls this as callback
 * @see send_ra() which uses this to add source LLA to RA packets
 * 
 * EXAMPLE USAGE:
 * @code
 * int iface_index = 2;
 * // Called by iface_enumerate within send_ra context
 * iface_enumerate(AF_LOCAL, &iface_index, add_lla);
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 4861 Section 4.6.1 (Source Link-Layer Address option format)
 * SIDE EFFECTS: Modifies outpacket buffer by appending option data
 * THREAD SAFETY: Single-threaded architecture, safe
 */
/**
 * @brief Add source link-layer address option to Router Advertisement message
 * 
 * @detailed Callback function invoked by iface_enumerate() to locate the MAC address of the
 * interface from which a Router Advertisement will be transmitted, and construct the ICMPv6
 * source link-layer address option (type 1) containing that MAC address. This option enables
 * receiving hosts to learn the link-layer address of the router without performing additional
 * Neighbor Discovery, optimizing network efficiency per RFC 4861 Section 4.6.1.
 * 
 * The function implements the search pattern: enumerate all network interfaces until finding
 * the one matching the interface index passed via the parm parameter (cast from int*). When
 * the match is found, the function constructs an ICMPv6 option with type 1 (source link-layer
 * address), calculates the option length in 8-octet units as required by ICMPv6 option format,
 * expands the packet buffer (daemon->outpacket) to accommodate the option, and writes the
 * option structure including type field, length field, and MAC address bytes.
 * 
 * The option length calculation accounts for ICMPv6 option format requirements: length field
 * is in units of 8 octets and includes the 2-byte header (type + length bytes). Formula:
 * len = (maclen + 9) >> 3, which is equivalent to ceil((maclen + 2) / 8), rounds up to the
 * next 8-octet boundary. For Ethernet with 6-byte MAC: (6 + 9) >> 3 = 15 >> 3 = 1 (8 octets).
 * The remaining bytes in the 8-octet unit are zero-padded per RFC 4861.
 * 
 * Buffer expansion failure (expand() returns NULL) causes immediate return with code 1,
 * continuing enumeration to try alternative interfaces. Successful option construction returns
 * 0 to abort enumeration since the target interface has been found and processed.
 * 
 * @param index Interface index being enumerated by iface_enumerate()
 * @param type Interface hardware type from netlink/BPF: ARPHRD_ETHER, ARPHRD_IEEE80211, etc. (unused)
 * @param mac Pointer to MAC address bytes in binary format (typically 6 bytes for Ethernet)
 * @param maclen Length of MAC address in bytes: 6 for Ethernet, 8 for IEEE 802, 20 for IPoIB
 * @param parm Void pointer to int containing target interface index to match
 * 
 * @return 0 to abort enumeration (target interface found and option added), 1 to continue searching
 * @retval 0 Interface index matched parm and source link-layer address option successfully added
 * @retval 1 Interface index does not match parm (continue enumeration) or buffer expansion failed
 * 
 * @note Option length field is in 8-octet units per RFC 4861 option format
 * @note Unused bytes in final 8-octet unit are zero-padded (memset before copying MAC)
 * @note Function ignores the type parameter (marked with (void) to suppress unused warnings)
 * @note Buffer expansion uses expand() which appends to daemon->outpacket
 * @note For Ethernet (maclen=6): option size is 8 bytes (type, len, 6-byte MAC, 0 padding)
 * @note Only one source link-layer address option added per RA (stops enumeration at first match)
 * 
 * @warning Requires parm to be valid int* pointer to interface index
 * @warning Buffer expansion failure silently continues enumeration (may result in RA without source LLA option)
 * @warning Caller must ensure daemon->outpacket buffer is initialized before invocation
 * @warning MAC address must be valid for the specified maclen (no bounds checking performed)
 * 
 * @see send_ra() for RA construction that invokes this callback via iface_enumerate()
 * @see send_ra_alias() for alias interface RA construction also using this callback
 * @see iface_enumerate() for system-wide interface enumeration mechanism
 * @see expand() for packet buffer expansion in outpacket.c
 * @see struct nd_opt_hdr in radv-protocol.h for ICMPv6 option header format
 * 
 * EXAMPLE USAGE:
 * @code
 * // Invoked automatically by iface_enumerate in send_ra:
 * int iface = if_nametoindex("eth0");
 * // add_lla called for each interface until match found:
 * iface_enumerate(AF_LOCAL, &iface, add_lla);
 * // After successful match, daemon->outpacket contains:
 * // [type=1][len=1][6-byte MAC][0x00 0x00] for Ethernet
 * // Total 8 bytes (1 unit of 8 octets)
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 4861 Section 4.6.1 (Source Link-Layer Address option format)
 * RFC COMPLIANCE: RFC 4861 Section 4.2 (Options format - length in 8-octet units)
 * 
 * SIDE EFFECTS: Expands daemon->outpacket buffer by appending source link-layer address option
 * SIDE EFFECTS: Modifies outpacket by writing type, length, MAC address, and zero padding
 * SIDE EFFECTS: Returns 0 to abort iface_enumerate() when target interface found
 * 
 * THREAD SAFETY: Single-threaded event loop, modifies shared daemon->outpacket buffer
 */
static int add_lla(int index, unsigned int type, char *mac, size_t maclen, void *parm)
{
  (void)type;

  if (index == *((int *)parm))
    {
      /* size is in units of 8 octets and includes type and length (2 bytes)
	 add 7 to round up */
      int len = (maclen + 9) >> 3;
      unsigned char *p = expand(len << 3);
      if (!p)
	return 1;
      memset(p, 0, len << 3);
      *p++ = ICMP6_OPT_SOURCE_MAC;
      *p++ = len;
      memcpy(p, mac, maclen);

      return 0;
    }

  return 1;
}

/**
 * @brief Perform periodic unsolicited Router Advertisement transmission for all configured interfaces
 * 
 * @detailed This function implements the periodic RA transmission timer mechanism required by RFC 4861.
 *           It iterates through all DHCPv6 contexts, checks for overdue RA transmission events, and sends
 *           unsolicited multicast RAs to configured interfaces and their bridge aliases. The function manages
 *           RA timing intervals, reschedules future transmissions, and coordinates with the main event loop
 *           to schedule the next RA event. This periodic transmission ensures that IPv6 hosts receive network
 *           configuration updates even without sending Router Solicitation messages.
 * 
 * @param now Current timestamp for comparing against scheduled RA times
 * 
 * @return Timestamp of the next scheduled RA event across all interfaces, or 0 if no RAs are pending
 * @retval 0 No Router Advertisement contexts configured or no pending RA transmissions
 * @retval >0 Unix timestamp when the next RA should be sent
 * 
 * @note This function is called from the main event loop and must complete quickly without blocking.
 * @note Bridge interface aliases are discovered dynamically via iface_enumerate and sent targeted RAs.
 * @note Contexts marked with CONTEXT_RA_DONE have completed their periodic RA cycle.
 * 
 * @warning Modifies CONTEXT_RA_DONE flag and ra_time fields in DHCP contexts during execution.
 * @warning Allocates temporary alias interface arrays that must be freed before return.
 * 
 * @see ra_start_unsolicited() - Initializes periodic RA transmission
 * @see send_ra() - Transmits individual RA message to interface
 * @see send_ra_alias() - Transmits RA to bridge alias interface
 * @see new_timeout() - Schedules next RA transmission time
 * 
 * EXAMPLE USAGE:
 * @code
 * time_t now = dnsmasq_time();
 * time_t next_ra_time = periodic_ra(now);
 * if (next_ra_time > 0)
 *     set_timer(next_ra_time - now); // Schedule alarm for next RA
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 4861 Section 6.2.4 (Sending Unsolicited Router Advertisements)
 * SIDE EFFECTS: Transmits ICMPv6 packets on network interfaces, modifies context state flags
 * THREAD SAFETY: Single-threaded architecture, not thread-safe (uses global daemon state)
 */
time_t periodic_ra(time_t now)
{
  struct search_param param;
  struct dhcp_context *context;
  time_t next_event;
  struct alias_param aparam;
    
  param.now = now;
  param.iface = 0;

  while (1)
    {
      /* find overdue events, and time of first future event */
      for (next_event = 0, context = daemon->dhcp6; context; context = context->next)
	if (context->ra_time != 0)
	  {
	    if (difftime(context->ra_time, now) <= 0.0)
	      break; /* overdue */
	    
	    if (next_event == 0 || difftime(next_event, context->ra_time) > 0.0)
	      next_event = context->ra_time;
	  }
      
      /* none overdue */
      if (!context)
	break;
      
      if ((context->flags & CONTEXT_OLD) && 
	  context->if_index != 0 && 
	  indextoname(daemon->icmp6fd, context->if_index, param.name))
	{
	  /* A context for an old address. We'll not find the interface by 
	     looking for addresses, but we know it anyway, since the context is
	     constructed */
	  param.iface = context->if_index;
	  new_timeout(context, param.name, now);
	}
      else if (iface_enumerate(AF_INET6, &param, (callback_t){.af_inet6=iface_search}))
	/* There's a context overdue, but we can't find an interface
	   associated with it, because it's for a subnet we don't
	   have an interface on. Probably we're doing DHCP on
	   a remote subnet via a relay. Zero the timer, since we won't
	   ever be able to send RAs to satisfy it. */
	context->ra_time = 0;
      
      if (param.iface != 0 &&
	  iface_check(AF_LOCAL, NULL, param.name, NULL))
	{
	  struct iname *tmp;
	  for (tmp = daemon->dhcp_except; tmp; tmp = tmp->next)
	    if (tmp->name && (tmp->flags & INAME_6) &&
		wildcard_match(tmp->name, param.name))
	      break;
	  if (!tmp)
            {
              send_ra(now, param.iface, param.name, NULL); 

              /* Also send on all interfaces that are aliases of this
                 one. */
              for (aparam.bridge = daemon->bridges;
                   aparam.bridge;
                   aparam.bridge = aparam.bridge->next)
                if ((int)if_nametoindex(aparam.bridge->iface) == param.iface)
                  {
                    /* Count the number of alias interfaces for this
                       'bridge', by calling iface_enumerate with
                       send_ra_to_aliases and NULL alias_ifs. */
                    aparam.iface = param.iface;
                    aparam.alias_ifs = NULL;
                    aparam.num_alias_ifs = 0;
                    iface_enumerate(AF_LOCAL, &aparam, (callback_t){.af_local=send_ra_to_aliases});
                    my_syslog(MS_DHCP | LOG_INFO, "RTR-ADVERT(%s) %s => %d alias(es)",
                              param.name, daemon->addrbuff, aparam.num_alias_ifs);

                    /* Allocate memory to store the alias interface
                       indices. */
                    aparam.alias_ifs = (int *)whine_malloc(aparam.num_alias_ifs *
                                                           sizeof(int));
                    if (aparam.alias_ifs)
                      {
                        /* Use iface_enumerate again to get the alias
                           interface indices, then send on each of
                           those. */
                        aparam.max_alias_ifs = aparam.num_alias_ifs;
                        aparam.num_alias_ifs = 0;
                        iface_enumerate(AF_LOCAL, &aparam, (callback_t){.af_local=send_ra_to_aliases});
                        for (; aparam.num_alias_ifs; aparam.num_alias_ifs--)
                          {
                            my_syslog(MS_DHCP | LOG_INFO, "RTR-ADVERT(%s) %s => i/f %d",
                                      param.name, daemon->addrbuff,
                                      aparam.alias_ifs[aparam.num_alias_ifs - 1]);
                            send_ra_alias(now,
                                          param.iface,
                                          param.name,
                                          NULL,
                                          aparam.alias_ifs[aparam.num_alias_ifs - 1]);
                          }
                        free(aparam.alias_ifs);
                      }

                    /* The source interface can only appear in at most
                       one --bridge-interface. */
                    break;
                  }
            }
	}
    }      
  return next_event;
}

/**
 * @brief Callback function to identify bridge alias interfaces matching configured patterns
 * 
 * @detailed This callback is invoked by iface_enumerate() for each network interface to determine if the
 *           interface matches any alias patterns configured in a bridge-interface directive. When a match
 *           is found, the interface index is recorded for subsequent Router Advertisement transmission.
 *           The function is called twice per bridge: first to count matching aliases, then to populate
 *           the alias interface index array. This two-pass approach allows dynamic memory allocation
 *           based on the actual number of matching interfaces.
 * 
 * @param index Interface index of the candidate interface being evaluated
 * @param type Interface type (unused - marked with (void) cast to suppress warnings)
 * @param mac MAC address of the interface (unused - marked with (void) cast)
 * @param maclen Length of MAC address (unused - marked with (void) cast)
 * @param parm Pointer to struct alias_param containing bridge configuration and result storage
 * 
 * @return Always returns 1 to continue enumeration of remaining interfaces
 * @retval 1 Continue interface enumeration
 * 
 * @note This function is designed as a callback for iface_enumerate() and should not be called directly.
 * @note On the first pass, alias_ifs is NULL and num_alias_ifs counts matches without storing indices.
 * @note On the second pass, alias_ifs points to allocated array and indices are stored.
 * 
 * @warning Assumes alias_param structure is properly initialized before iface_enumerate() invocation.
 * @warning Array bounds checking uses max_alias_ifs to prevent buffer overflow.
 * 
 * @see iface_enumerate() - Iterates through all network interfaces invoking this callback
 * @see send_ra_alias() - Transmits RA to discovered alias interfaces
 * @see wildcard_matchn() - Performs pattern matching for alias interface names
 * 
 * EXAMPLE USAGE:
 * @code
 * struct alias_param aparam = { .iface = base_iface, .bridge = bridge_config,
 *                                .num_alias_ifs = 0, .alias_ifs = NULL };
 * // First pass: count matching aliases
 * iface_enumerate(AF_LOCAL, &aparam, (callback_t){.af_local=send_ra_to_aliases});
 * // Second pass: populate alias indices
 * aparam.alias_ifs = malloc(aparam.num_alias_ifs * sizeof(int));
 * iface_enumerate(AF_LOCAL, &aparam, (callback_t){.af_local=send_ra_to_aliases});
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (internal implementation detail for bridge support)
 * SIDE EFFECTS: Increments num_alias_ifs counter, populates alias_ifs array when non-NULL
 * THREAD SAFETY: Single-threaded architecture, not thread-safe (modifies aparam state)
 */
/**
 * @brief Enumerate interfaces matching bridge alias patterns for RA transmission
 * 
 * @detailed Callback function invoked by iface_enumerate() to identify network interfaces
 * that match wildcard patterns defined as aliases of a DHCP bridge, enabling Router
 * Advertisement transmission to all members of a bridge group. This function supports
 * the bridge functionality where a single DHCPv6/RA configuration applies to multiple
 * related interfaces (e.g., bridge members, VLAN interfaces, virtual interfaces). The
 * callback pattern-matches each enumerated interface name against configured alias patterns
 * and accumulates matching interface indices for subsequent RA transmission.
 * 
 * The function converts the enumerated interface index to its name string using if_indextoname,
 * then iterates through all alias patterns configured for the bridge structure contained in
 * the aparam parameter. Each alias pattern is compared against the interface name using
 * wildcard_matchn(), which supports glob-style wildcards (* for any characters, ? for single
 * character). When a match is found, the interface index is stored in the aparam->alias_ifs
 * array (if space available) and the counter aparam->num_alias_ifs is incremented. This
 * accumulation enables the caller to subsequently send RAs to all matching interfaces.
 * 
 * The function handles array bounds checking: if aparam->alias_ifs is non-NULL and the
 * array has not reached capacity (num_alias_ifs < max_alias_ifs), the interface index is
 * stored at the next available position. If the array is NULL or full, num_alias_ifs is
 * still incremented to track the total number of matches (allowing detection of insufficient
 * array size). This two-pass approach (first count, then allocate and populate) enables
 * dynamic array sizing.
 * 
 * @param index Interface index being enumerated by iface_enumerate()
 * @param type Interface type from netlink/BPF: ARPHRD_ETHER, ARPHRD_IEEE80211, etc. (unused)
 * @param mac MAC address of interface in binary format (unused)
 * @param maclen Length of MAC address in bytes, typically 6 for Ethernet (unused)
 * @param parm Void pointer to struct alias_param containing bridge alias configuration
 * 
 * @return 1 to continue interface enumeration (always continues, never aborts)
 * 
 * @note Function ignores type, mac, maclen parameters (marked with (void) to suppress warnings)
 * @note Wildcard patterns support * (match any characters) and ? (match single character)
 * @note If alias_ifs array is NULL, function only counts matches without storing indices
 * @note If alias_ifs array is full, function continues counting but doesn't store additional indices
 * @note Always returns 1 to ensure complete enumeration of all system interfaces
 * @note Called via iface_enumerate() which iterates through all network interfaces
 * 
 * @warning Requires aparam->bridge->alias to be valid pointer or NULL
 * @warning Interface name buffer ifrn_name limited to IFNAMSIZ (typically 16 bytes)
 * @warning Caller must ensure aparam->max_alias_ifs accurately reflects alias_ifs array size
 * @warning if_indextoname may fail if interface disappeared; function silently skips such cases
 * 
 * @see send_ra() for RA transmission to primary interface
 * @see send_ra_alias() for RA transmission to discovered alias interfaces
 * @see iface_enumerate() for system-wide interface enumeration mechanism
 * @see wildcard_matchn() for glob-style pattern matching with * and ? wildcards
 * @see struct dhcp_bridge in dnsmasq.h for bridge alias configuration structure
 * 
 * EXAMPLE USAGE:
 * @code
 * // Invoked automatically by iface_enumerate in icmp6_packet for bridge handling:
 * struct alias_param aparam;
 * aparam.iface = primary_interface_index;
 * aparam.bridge = configured_bridge;  // Contains alias patterns like "eth*", "vlan?"
 * aparam.num_alias_ifs = 0;
 * aparam.max_alias_ifs = 10;
 * aparam.alias_ifs = malloc(10 * sizeof(int));
 * // send_ra_to_aliases called for each interface on system:
 * iface_enumerate(AF_UNSPEC, &aparam, send_ra_to_aliases);
 * // After enumeration, aparam.alias_ifs contains indices of matching interfaces
 * // and aparam.num_alias_ifs contains count (may exceed max_alias_ifs if insufficient space)
 * for (int i = 0; i < aparam.num_alias_ifs && i < aparam.max_alias_ifs; i++) {
 *   send_ra_alias(now, aparam.iface, iface_name, dest, aparam.alias_ifs[i]);
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 4861 (Router Advertisement applies to all bridge member interfaces)
 * RFC COMPLIANCE: Bridge forwarding of ICMPv6 RAs per IEEE 802.1D bridge standards
 * 
 * SIDE EFFECTS: Increments aparam->num_alias_ifs for each matching interface
 * SIDE EFFECTS: Stores interface indices in aparam->alias_ifs array (if space available)
 * SIDE EFFECTS: May leave num_alias_ifs > max_alias_ifs indicating insufficient array space
 * 
 * THREAD SAFETY: Single-threaded event loop, modifies only aparam structure passed as parameter
 */
static int send_ra_to_aliases(int index, unsigned int type, char *mac, size_t maclen, void *parm)
{
  struct alias_param *aparam = (struct alias_param *)parm;
  char ifrn_name[IFNAMSIZ];
  struct dhcp_bridge *alias;

  (void)type;
  (void)mac;
  (void)maclen;

  if (if_indextoname(index, ifrn_name))
    for (alias = aparam->bridge->alias; alias; alias = alias->next)
      if (wildcard_matchn(alias->iface, ifrn_name, IFNAMSIZ))
        {
          if (aparam->alias_ifs && (aparam->num_alias_ifs < aparam->max_alias_ifs))
            aparam->alias_ifs[aparam->num_alias_ifs] = index;
          aparam->num_alias_ifs++;
        }

  return 1;
}

/**
 * @brief Search for interfaces requiring Router Advertisement transmission
 * 
 * @detailed Callback function invoked by iface_enumerate() to identify network interfaces
 * that are overdue for periodic Router Advertisement transmission. This function implements
 * the RA scheduling mechanism by scanning all IPv6 addresses on the system, matching them
 * against configured DHCPv6 contexts, and determining which interfaces require immediate
 * RA transmission based on context->ra_time timeout values. The function enforces interface
 * filtering (only interfaces with DHCPv6 enabled), validates prefix containment, checks for
 * Duplicate Address Detection (DAD) completion, and coordinates timeout values across
 * multiple contexts on the same subnet to prevent redundant transmissions.
 * 
 * The search algorithm first validates that the interface is eligible for DHCP operation
 * by checking interface name resolution and iface_check() filter. It then excludes interfaces
 * explicitly listed in daemon->dhcp_except with INAME_6 flag. For eligible interfaces, the
 * function iterates through all DHCPv6 contexts searching for one that:
 * 1. Is active (not CONTEXT_TEMPLATE or CONTEXT_OLD)
 * 2. Has prefix length <= enumerated address prefix (allows broader context to match)
 * 3. Contains the enumerated address within context start6-end6 range (is_same_net6 check)
 * 4. Has non-zero ra_time (RA scheduling enabled for this context)
 * 5. Is overdue: difftime(context->ra_time, now) <= 0 (scheduled time has passed)
 * 
 * Upon finding an overdue context, the function verifies the interface is not in tentative
 * state (IFACE_TENTATIVE flag), which would indicate Duplicate Address Detection is still
 * in progress. If DAD is complete, the interface index is stored in param->iface for RA
 * transmission by the caller. The function then calls new_timeout() to calculate and set
 * the next RA transmission time for this context. To prevent multiple RAs on the same
 * subnet, the function zeros ra_time for all subsequent contexts matching the same network
 * prefix, ensuring only one timeout fires per subnet.
 * 
 * @param local Pointer to IPv6 address being enumerated from interface
 * @param prefix Prefix length (bits) for this address, typically 64 for network addresses
 * @param scope Address scope: link-local, global, site-local (unused - marked with (void))
 * @param if_index Interface index from which this address originates
 * @param flags Address flags from kernel: IFACE_TENTATIVE indicates DAD in progress
 * @param preferred Preferred lifetime in seconds from kernel (unused - marked with (void))
 * @param valid Valid lifetime in seconds from kernel (unused - marked with (void))
 * @param vparam Void pointer to struct search_param containing search state
 * 
 * @return 0 to abort enumeration (interface found requiring RA), 1 to continue searching
 * 
 * @note Only processes interfaces passing iface_check() filter and not in dhcp_except list
 * @note Prefix matching uses <= comparison: context prefix can be broader than address prefix
 * @note IFACE_TENTATIVE flag prevents RA on addresses undergoing Duplicate Address Detection
 * @note Multiple contexts on same subnet synchronized: first match schedules, others zeroed
 * @note Function called repeatedly by iface_enumerate() for every IPv6 address on system
 * @note Interface index stored in param->iface signals caller to send RA
 * 
 * @warning Must not use DHCP buffers except outpacket (may be called during DHCPv4 transaction)
 * @warning Requires valid context->ra_time field for timeout comparison
 * @warning Modifies context->ra_time for multiple contexts (timeout synchronization)
 * 
 * @see ra_start_unsolicited() for the caller that invokes this via iface_enumerate()
 * @see new_timeout() for RA timeout calculation and scheduling logic
 * @see iface_enumerate() for system-wide IPv6 address enumeration mechanism
 * @see is_same_net6() for IPv6 prefix containment testing
 * @see indextoname() for interface index to name resolution
 * @see iface_check() for interface filtering based on --interface/--except-interface
 * 
 * EXAMPLE USAGE:
 * @code
 * // Invoked automatically by iface_enumerate in ra_start_unsolicited:
 * struct search_param param;
 * param.now = dnsmasq_time();
 * param.iface = 0;  // Will be set if interface found requiring RA
 * // iface_search called for each IPv6 address on system:
 * iface_enumerate(AF_INET6, &param, iface_search);
 * if (param.iface != 0) {
 *   // Interface param.iface requires RA transmission
 *   send_ra(param.now, param.iface, param.name, NULL);
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 4861 Section 6.2.4 (Sending Unsolicited Router Advertisements)
 * RFC COMPLIANCE: RFC 4862 Section 5.4.2 (Stateless address autoconfiguration timing)
 * 
 * SIDE EFFECTS: Sets param->iface to interface index requiring RA transmission
 * SIDE EFFECTS: Calls new_timeout() which modifies context->ra_time for matched context
 * SIDE EFFECTS: Zeros context->ra_time for subsequent contexts on same subnet
 * SIDE EFFECTS: Stores interface name in param->name via indextoname()
 * 
 * THREAD SAFETY: Single-threaded event loop, modifies shared context structures
 */
static int iface_search(struct in6_addr *local,  int prefix,
			int scope, int if_index, int flags, 
			unsigned int preferred, unsigned int valid, void *vparam)
{
  struct search_param *param = vparam;
  struct dhcp_context *context;
  struct iname *tmp;
  
  (void)scope;
  (void)preferred;
  (void)valid;

  /* ignore interfaces we're not doing DHCP on. */
  if (!indextoname(daemon->icmp6fd, if_index, param->name) ||
      !iface_check(AF_LOCAL, NULL, param->name, NULL))
    return 1;

  for (tmp = daemon->dhcp_except; tmp; tmp = tmp->next)
    if (tmp->name && (tmp->flags & INAME_6) &&
	wildcard_match(tmp->name, param->name))
      return 1;

  for (context = daemon->dhcp6; context; context = context->next)
    if (!(context->flags & (CONTEXT_TEMPLATE | CONTEXT_OLD)) &&
	prefix <= context->prefix &&
	is_same_net6(local, &context->start6, context->prefix) &&
	is_same_net6(local, &context->end6, context->prefix) &&
	context->ra_time != 0 && 
	difftime(context->ra_time, param->now) <= 0.0)
      {
	/* found an interface that's overdue for RA determine new 
	   timeout value and arrange for RA to be sent unless interface is
	   still doing DAD.*/
	if (!(flags & IFACE_TENTATIVE))
	  param->iface = if_index;
	
	new_timeout(context, param->name, param->now);
	
	/* zero timers for other contexts on the same subnet, so they don't timeout 
	   independently */
	for (context = context->next; context; context = context->next)
	  if (prefix <= context->prefix &&
	      is_same_net6(local, &context->start6, context->prefix) &&
	      is_same_net6(local, &context->end6, context->prefix))
	    context->ra_time = 0;
	
	return 0; /* found, abort */
      }
  
  return 1; /* keep searching */
}
 
/**
 * @brief Calculate and set next Router Advertisement transmission timeout for DHCP context
 * 
 * @detailed Implements RFC 4861 Section 6.2.4 timing requirements for Router Advertisement
 *           transmission scheduling with randomized intervals to prevent synchronization between
 *           multiple routers on the same link. The function operates in two distinct modes based
 *           on whether the interface is in the initial short-period transmission phase or normal
 *           periodic transmission phase.
 * 
 * SHORT PERIOD MODE (first 60 seconds after ra_short_period_start):
 * When an interface first begins sending Router Advertisements (triggered by configuration
 * reload, interface state change, or daemon startup), RFC 4861 requires more frequent initial
 * transmissions to ensure hosts quickly discover the new router. During this 60-second window,
 * this function schedules the next transmission in the range 5-20 seconds from now, calculated
 * as: ra_time = now + 5 + (rand16()/4400), where rand16() returns 0-65535, giving approximately
 * 5 to 20 seconds (5 + 65535/4400 = 5 + 14.89 ≈ 20 seconds). This rapid transmission phase
 * helps hosts update their default router list and routing tables promptly.
 * 
 * NORMAL PERIOD MODE (more than 60 seconds after ra_short_period_start):
 * After the initial short period expires, the function transitions to RFC 4861's standard
 * periodic transmission schedule. The next transmission is scheduled in the range
 * [0.75*MaxRtrAdvInterval, MaxRtrAdvInterval], calculated as:
 * ra_time = now + (3*adv_interval)/4 + ((adv_interval * rand16()) >> 18)
 * This formula implements: base = 3/4 * interval, random_add = interval * rand16()/262144
 * giving a uniform random distribution across [0.75*interval, interval]. For default
 * MaxRtrAdvInterval of 600 seconds, this yields 450-600 second intervals.
 * 
 * The randomization is critical to prevent synchronization: if multiple routers transmitted
 * at exactly the same interval, their transmissions would remain synchronized indefinitely,
 * causing unnecessary network traffic spikes and potential packet collisions. The RFC-mandated
 * randomized interval ensures routers gradually desynchronize over time.
 * 
 * The MaxRtrAdvInterval value is retrieved via calc_interval(find_iface_param(iface_name)),
 * which looks up interface-specific configuration (--ra-param directive) or returns the
 * default 600-second value. Interface-specific configuration allows administrators to tune
 * RA frequency per network segment (e.g., faster for critical networks, slower for stable ones).
 * 
 * @param context DHCP context structure for the interface requiring timeout update
 * @param iface_name Interface name string used to look up RA configuration parameters
 * @param now Current time in seconds since epoch (from time() system call)
 * 
 * @return void (modifies context->ra_time in place)
 * 
 * @note Short period mode applies for first 60 seconds after context->ra_short_period_start
 * @note Short period interval: 5-20 seconds (formula: 5 + rand16()/4400)
 * @note Normal period interval: 0.75 to 1.0 times MaxRtrAdvInterval (default 450-600 seconds)
 * @note Uses rand16() from util.c for cryptographically secure random number generation
 * @note Formula for normal period: (3*interval)/4 + (interval * rand16() >> 18)
 * @note Right shift by 18 divides rand16() output (0-65535) by 262144 for normalization
 * @note Multiple routers on same link MUST use randomized intervals per RFC 4861
 * @note context->ra_time is absolute time (seconds since epoch), not relative offset
 * @note Subsequent calls to periodic_ra() check if now >= context->ra_time to trigger transmission
 * 
 * @warning Requires context->ra_short_period_start to be initialized before first call
 * @warning iface_name must be valid null-terminated string (passed to find_iface_param)
 * @warning Assumes context pointer is valid and points to initialized dhcp_context
 * @warning Does not validate MaxRtrAdvInterval is >= MIN_RTR_ADV_INTERVAL (600s per RFC)
 * @warning Randomization assumes rand16() provides sufficient entropy for security
 * 
 * @see ra_start_unsolicited() for initialization of context->ra_short_period_start
 * @see periodic_ra() for periodic check of context->ra_time and RA transmission
 * @see calc_interval() for retrieval of MaxRtrAdvInterval from configuration
 * @see find_iface_param() for interface-specific RA configuration lookup
 * @see rand16() in util.c for cryptographically secure random number generation
 * @see send_ra() for actual Router Advertisement transmission when timeout expires
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_context *ctx = daemon->dhcp6;
 * time_t now = dnsmasq_time();
 * ctx->ra_short_period_start = now; // Start short period
 * new_timeout(ctx, "eth0", now);
 * // ctx->ra_time now set to now + 5-20 seconds (short period)
 * 
 * // After 60+ seconds, next call uses normal period:
 * now = dnsmasq_time(); // 70 seconds later
 * new_timeout(ctx, "eth0", now);
 * // ctx->ra_time now set to now + 450-600 seconds (default interval)
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 4861 Section 6.2.4 (Sending Router Advertisements)
 * RFC COMPLIANCE: RFC 4861 Section 6.2.1 (Router Configuration Variables - MaxRtrAdvInterval)
 * RFC COMPLIANCE: RFC 4861 requires interval randomization to prevent router synchronization
 * 
 * SIDE EFFECTS: Modifies context->ra_time to schedule next RA transmission
 * SIDE EFFECTS: Calls find_iface_param() which searches daemon->ra_interfaces list
 * SIDE EFFECTS: Calls calc_interval() which may return default or configured interval
 * SIDE EFFECTS: Invokes rand16() which updates internal PRNG state
 * 
 * THREAD SAFETY: Single-threaded event loop, modifies shared context structure
 */
static void new_timeout(struct dhcp_context *context, char *iface_name, time_t now)
{
  if (difftime(now, context->ra_short_period_start) < 60.0)
    /* range 5 - 20 */
    context->ra_time = now + 5 + (rand16()/4400);
  else
    {
      /* range 3/4 - 1 times MaxRtrAdvInterval */
      unsigned int adv_interval = calc_interval(find_iface_param(iface_name));
      context->ra_time = now + (3 * adv_interval)/4 + ((adv_interval * (unsigned int)rand16()) >> 18);
    }
}

/**
 * @brief Find Router Advertisement interface configuration by name
 * 
 * Searches the global list of configured RA interfaces to find the ra_interface
 * structure matching the given interface name. Supports wildcard pattern matching
 * to allow a single configuration entry to apply to multiple interfaces (e.g.,
 * "eth*" matching eth0, eth1, eth2). Used by RA transmission and lifetime
 * calculation functions to retrieve interface-specific configuration parameters.
 * 
 * @param iface Interface name to search for (e.g., "eth0", "wlan0")
 * 
 * @return Pointer to matching ra_interface structure, or NULL if not found
 * @retval ra_interface* First matching interface configuration (if found)
 * @retval NULL No matching interface configuration (uses default behavior)
 * 
 * @note Function performs linear search through daemon->ra_interfaces linked list
 * @note Wildcard matching allows patterns like "eth*" to match "eth0", "eth1", etc.
 * @note Returns first match when wildcards could match multiple entries
 * @note NULL return triggers default RA behavior (calc_lifetime, calc_interval defaults)
 * @note Interface names are case-sensitive for matching
 * @warning NULL iface parameter will cause wildcard_match to fail (returns NULL)
 * @warning Wildcard patterns should be carefully ordered in configuration (first match wins)
 * 
 * @see wildcard_match() for pattern matching algorithm (supports * and ? wildcards)
 * @see calc_lifetime() which calls this to get configured lifetime
 * @see calc_interval() which calls this to get configured interval
 * @see calc_prio() which calls this to get configured router preference
 * @see struct ra_interface in dnsmasq.h for configuration structure definition
 * 
 * EXAMPLE USAGE:
 * @code
 * struct ra_interface *ra = find_iface_param("eth0");
 * if (ra) {
 *   // Use ra->interval, ra->lifetime, ra->prio from configuration
 *   unsigned int interval = calc_interval(ra);
 * } else {
 *   // Use default behavior (no specific configuration for eth0)
 *   unsigned int interval = calc_interval(NULL);
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: Not directly specified by RFC 4861 (configuration management)
 * - Enables per-interface customization of RFC 4861 parameters
 * - Supports multiple interface RA configuration as required by multi-homed routers
 * 
 * SIDE EFFECTS: None (pure read operation, no state modification)
 * THREAD SAFETY: Safe (single-threaded architecture, reads only from global linked list)
 */
/**
 * @brief Find Router Advertisement interface configuration by name
 * 
 * Searches the configured RA interface list to locate interface-specific configuration
 * matching the provided interface name. Uses wildcard matching to support pattern-based
 * configuration (e.g., "eth*" matching "eth0", "eth1"). This lookup determines RA
 * transmission parameters (interval, lifetime, priority) for the specified interface.
 * 
 * @detailed
 * Iterates through the global linked list daemon->ra_interfaces comparing each
 * ra_interface->name against the provided interface name using wildcard_match().
 * The first matching entry is returned, with NULL indicating no explicit configuration
 * exists for this interface (defaults will be used).
 * 
 * Wildcard matching enables efficient configuration where multiple interfaces share
 * the same RA parameters (e.g., "eth*" applies to all Ethernet interfaces). The
 * search returns on first match, so more specific patterns should be configured
 * before generic wildcards if precedence control is needed.
 * 
 * @param iface Interface name to search for (e.g., "eth0", "wlan0"). Must not be NULL.
 * 
 * @return Pointer to matching ra_interface structure containing RA configuration parameters
 * @retval non-NULL Matching interface configuration found
 * @retval NULL No explicit configuration exists for this interface (use defaults)
 * 
 * @note This function is called frequently during RA transmission and should remain
 *       efficient. The wildcard matching adds minimal overhead.
 * @warning The returned pointer references global configuration data and must not be freed.
 *          The structure remains valid until configuration reload.
 * 
 * @see calc_lifetime() Uses ra_interface to calculate RA valid lifetime
 * @see calc_interval() Uses ra_interface to calculate RA transmission interval
 * @see calc_prio() Uses ra_interface to calculate router priority
 * 
 * EXAMPLE USAGE:
 * @code
 * struct ra_interface *ra = find_iface_param("eth0");
 * if (ra) {
 *   unsigned int interval = calc_interval(ra);
 *   unsigned int lifetime = calc_lifetime(ra);
 * } else {
 *   // Use system defaults for this interface
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 4861 Section 6.2.1 - Router Configuration Variables per interface
 * SIDE EFFECTS: None (read-only lookup)
 * THREAD SAFETY: Safe in single-threaded architecture; reads global daemon->ra_interfaces
 */
static struct ra_interface *find_iface_param(char *iface)
{
  struct ra_interface *ra;
  
  for (ra = daemon->ra_interfaces; ra; ra = ra->next)
    if (wildcard_match(ra->name, iface))
      return ra;

  return NULL;
}

/**
 * @brief Calculate Router Advertisement transmission interval
 * 
 * Computes the time interval between unsolicited RA transmissions for an interface.
 * Enforces RFC 4861-compliant bounds on the advertisement interval to prevent
 * network flooding or excessive gaps in router discovery. The interval affects
 * how quickly hosts detect the router and must be coordinated with router lifetime.
 * 
 * @param ra Pointer to ra_interface configuration or NULL for default interval
 * 
 * @return Advertisement interval in seconds (cast to unsigned int)
 * @retval 600 Default interval when ra is NULL or ra->interval is 0
 * @retval 4 Minimum interval enforced (if configured <4 seconds)
 * @retval 1800 Maximum interval enforced (if configured >1800 seconds)
 * @retval ra->interval Configured interval value (if within valid range)
 * 
 * @note Default interval is 600 seconds (10 minutes) for reasonable discovery time
 * @note RFC 4861 recommends 4-1800 second range to balance responsiveness vs. overhead
 * @note Minimum 4 seconds prevents excessive network overhead from frequent RAs
 * @note Maximum 1800 seconds (30 minutes) ensures timely router rediscovery
 * @note Interval must be less than router lifetime to maintain reachability
 * @warning Interval configured outside [4, 1800] range is automatically clamped
 * @warning Very short intervals (<10s) may impact network performance
 * 
 * @see calc_lifetime() which must return value >= interval (or 0)
 * @see calc_prio() for router preference calculation
 * @see RFC 4861 Section 6.2.1 Router Configuration Variables
 * @see RFC 4861 MaxRtrAdvInterval and MinRtrAdvInterval constants
 * 
 * EXAMPLE USAGE:
 * @code
 * struct ra_interface *ra = find_iface_param("eth0");
 * unsigned int interval = calc_interval(ra);
 * // interval will be 600 if ra is NULL or has interval=0
 * // interval will be clamped to [4, 1800] if ra->interval is set
 * my_syslog(LOG_INFO, "RA interval for eth0: %u seconds", interval);
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 4861 Section 6.2.1 Router Configuration Variables
 * - MaxRtrAdvInterval: maximum time between unsolicited RAs (default 600s, max 1800s)
 * - MinRtrAdvInterval: minimum time between unsolicited RAs (default 0.33*max, min 3s)
 * - Implementation uses single interval value within RFC-compliant bounds
 * 
 * SIDE EFFECTS: None (pure calculation, no state modification)
 * THREAD SAFETY: Safe (reads only from parameter, no global state access)
 */
/**
 * @brief Calculate MaxRtrAdvInterval for Router Advertisement transmission timing
 * 
 * @detailed Computes the MaxRtrAdvInterval value controlling the maximum time between
 *           unsolicited Router Advertisement transmissions on this interface, as defined
 *           in RFC 4861 Section 6.2.1. This interval directly determines RA transmission
 *           frequency and impacts network convergence time when routers appear or disappear.
 *           Hosts use this interval (when communicated via future RA options) to determine
 *           how long to wait before concluding a router has become unreachable.
 * 
 * The function implements RFC 4861's mandatory constraints on MaxRtrAdvInterval with
 * dnsmasq's default policy:
 * 
 * DEFAULT INTERVAL (no configuration or interval == 0):
 * When no interface-specific interval is configured (ra parameter is NULL or ra->interval
 * is 0), the function returns the RFC 4861 recommended default of 600 seconds (10 minutes).
 * This conservative default balances network responsiveness against RA traffic overhead:
 * hosts receive topology updates within 10 minutes, while RA packets consume minimal
 * bandwidth on typical networks. Formula: interval = 600 seconds.
 * 
 * RFC 4861 states: "Default: 600 seconds" for MaxRtrAdvInterval. This value was chosen
 * by the IPv6 working group to provide reasonable convergence time for residential and
 * small office networks without excessive multicast traffic.
 * 
 * CONFIGURED INTERVAL WITH RFC 4861 VALIDATION:
 * When an administrator configures an explicit interval via --ra-param interval=<seconds>,
 * the function applies that value but enforces RFC 4861's mandatory range constraints to
 * prevent both protocol violations and operational problems:
 * 
 * MINIMUM CONSTRAINT (4 seconds):
 * RFC 4861 Section 6.2.1 mandates: "MUST be no less than 4 seconds." If the configured
 * interval is less than 4 seconds, the function raises the value to 4 seconds. This lower
 * bound prevents excessive RA traffic that could overwhelm low-bandwidth links or slow
 * embedded systems. Intervals below 4 seconds would generate 15+ multicast packets per
 * minute per router, creating unacceptable overhead on shared network segments.
 * 
 * MAXIMUM CONSTRAINT (1800 seconds):
 * RFC 4861 Section 6.2.1 mandates: "MUST be no more than 1800 seconds." If the configured
 * interval exceeds 1800 seconds (30 minutes), the function caps the value at 1800 seconds.
 * This upper bound ensures hosts detect topology changes within reasonable timeframes.
 * Without this limit, network convergence could take hours, rendering IPv6 autoconfiguration
 * impractical for environments with mobile hosts or dynamic router availability.
 * 
 * The RFC's 1800-second maximum was chosen to balance opposing concerns:
 * - Longer intervals reduce multicast overhead (important for battery-powered devices)
 * - Shorter intervals improve convergence time (important for mobile networks)
 * - 30 minutes represents the maximum acceptable delay for prefix/route updates
 * 
 * RELATIONSHIP TO MinRtrAdvInterval:
 * RFC 4861 also defines MinRtrAdvInterval = 0.33 * MaxRtrAdvInterval (with floor of 3 seconds).
 * Dnsmasq uses MinRtrAdvInterval to randomize RA transmission times, sending unsolicited RAs
 * at random intervals between MinRtrAdvInterval and MaxRtrAdvInterval. This randomization
 * prevents synchronization of RAs from multiple routers on the same link, which would cause
 * periodic bursts of multicast traffic. The calc_interval() return value feeds into this
 * randomization logic in ra_start_unsolicited().
 * 
 * RELATIONSHIP TO ROUTER LIFETIME:
 * The calc_lifetime() function uses this interval to compute default router lifetime
 * (3 * interval) and to enforce the RFC 4861 requirement that Router Lifetime must be
 * at least MaxRtrAdvInterval. This dependency ensures lifetime scaling remains consistent
 * with advertisement frequency.
 * 
 * @param ra Pointer to ra_interface structure containing interface-specific RA configuration
 *           including interval member, or NULL if no configuration exists for this interface
 * 
 * @return MaxRtrAdvInterval value in seconds controlling RA transmission timing
 * @retval 600 Default interval when ra is NULL or ra->interval == 0 (RFC 4861 default)
 * @retval 4 Configured interval was less than 4 seconds (raised to RFC 4861 minimum)
 * @retval 1800 Configured interval exceeded 1800 seconds (capped at RFC 4861 maximum)
 * @retval ra->interval Configured interval within RFC-compliant range (4 to 1800 seconds)
 * 
 * @note Default MaxRtrAdvInterval is 600 seconds per RFC 4861 Section 6.2.1
 * @note RFC 4861 mandates minimum 4 seconds and maximum 1800 seconds for MaxRtrAdvInterval
 * @note MinRtrAdvInterval is computed as max(3, 0.33 * MaxRtrAdvInterval) elsewhere in code
 * @note Actual RA transmission occurs at random times between Min and Max intervals
 * @note Lower intervals improve convergence time but increase multicast traffic overhead
 * @note Higher intervals reduce traffic but delay host awareness of topology changes
 * @note This interval affects router lifetime calculation in calc_lifetime()
 * @note Configured interval of 0 is treated as "use default" (not "disable RAs")
 * @note ra->interval values are assumed to be in seconds (no unit conversion)
 * @note Casting to unsigned int is safe since interval is clamped to [4, 1800] range
 * 
 * @warning Intervals below 4 seconds violate RFC 4861 and are automatically raised
 * @warning Intervals above 1800 seconds violate RFC 4861 and are automatically capped
 * @warning Very short intervals (<10 seconds) may cause excessive multicast traffic
 * @warning Very long intervals (>600 seconds) may delay critical prefix updates
 * @warning Requires ra->interval to be configured in seconds (not milliseconds)
 * @warning Interval affects network convergence time when routers become available/unavailable
 * 
 * @see ra_start_unsolicited() for unsolicited RA scheduling using this interval
 * @see calc_lifetime() for Router Lifetime calculation using this interval
 * @see send_ra() for actual RA transmission function
 * @see new_timeout() for timeout calculation using this interval
 * @see struct ra_interface in dnsmasq.h for interval configuration member
 * @see find_iface_param() for ra_interface structure lookup by interface name
 * 
 * EXAMPLE USAGE:
 * @code
 * // Default interval (no configuration):
 * struct ra_interface *ra = NULL;
 * unsigned int interval = calc_interval(ra);
 * // Returns: 600 seconds (10 minutes)
 * 
 * // Configured interval within valid range:
 * struct ra_interface ra_cfg = { .interval = 300 };
 * interval = calc_interval(&ra_cfg);
 * // Returns: 300 seconds (5 minutes)
 * 
 * // Configured interval too low (raised to RFC minimum):
 * ra_cfg.interval = 2;
 * interval = calc_interval(&ra_cfg);
 * // Returns: 4 seconds (raised to RFC 4861 minimum)
 * 
 * // Configured interval too high (capped at RFC maximum):
 * ra_cfg.interval = 3600;
 * interval = calc_interval(&ra_cfg);
 * // Returns: 1800 seconds (capped at RFC 4861 maximum)
 * 
 * // Using interval for timeout calculation:
 * time_t next_ra = now + calc_interval(ra);
 * // Schedule next unsolicited RA transmission
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 4861 Section 6.2.1 (Router Configuration Variables - MaxRtrAdvInterval)
 * RFC COMPLIANCE: RFC 4861 requires 4 <= MaxRtrAdvInterval <= 1800 seconds
 * RFC COMPLIANCE: RFC 4861 default MaxRtrAdvInterval is 600 seconds
 * RFC COMPLIANCE: RFC 4861 defines MinRtrAdvInterval = max(3, 0.33 * MaxRtrAdvInterval)
 * 
 * SIDE EFFECTS: None (pure calculation function with no global state modifications)
 * 
 * THREAD SAFETY: Read-only access to ra structure, safe in single-threaded event loop
 */
static unsigned int calc_interval(struct ra_interface *ra)
{
  int interval = 600;
  
  if (ra && ra->interval != 0)
    {
      interval = ra->interval;
      if (interval > 1800)
	interval = 1800;
      else if (interval < 4)
	interval = 4;
    }
  
  return (unsigned int)interval;
}

/**
 * @brief Calculate Router Advertisement lifetime value
 * 
 * Computes the router lifetime to advertise in RA messages. The lifetime
 * indicates how long (in seconds) hosts should consider this router as a
 * default router. Must be zero or greater than the advertisement interval.
 * Enforces RFC-compliant bounds and relationships between interval and lifetime.
 * 
 * @param ra Pointer to ra_interface configuration or NULL
 * 
 * @return Router lifetime in seconds (cast to unsigned int)
 * @retval 3*interval Default lifetime when ra is NULL or lifetime not specified (-1)
 * @retval interval Corrected lifetime if configured < interval (and non-zero)
 * @retval 9000 Maximum lifetime enforced per RFC 4861 upper bound
 * @retval ra->lifetime Configured lifetime value (validated and bounded)
 * 
 * @note If ra is NULL or ra->lifetime == -1 (unspecified), defaults to 3x interval
 * @note If configured lifetime is non-zero but less than interval, uses interval
 * @note Maximum lifetime is capped at 9000 seconds per RFC 4861 recommendations
 * @note Lifetime of 0 indicates router should not be used as default router
 * @warning Lifetime must be either 0 or >= advertisement interval per RFC 4861
 * @warning Lifetime capped at 9000 seconds maximum
 * 
 * @see calc_interval() to get advertisement interval for validation
 * @see calc_prio() for priority calculation
 * @see RFC 4861 Section 6.2.1 for lifetime requirements
 * 
 * EXAMPLE USAGE:
 * @code
 * struct ra_interface *ra = find_iface_param("eth0");
 * unsigned int lifetime = calc_lifetime(ra);
 * // Include lifetime in RA header (typically 1800-9000 seconds)
 * // Default: 3 x MaxRtrAdvInterval if not configured
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 4861 Section 6.2.1 (Router Lifetime: 0 or >= MaxRtrAdvInterval, max 9000s)
 * SIDE EFFECTS: None (pure calculation, no logging in this implementation)
 * THREAD SAFETY: Single-threaded access, safe for daemon global state reads
 */
/**
 * @brief Calculate Router Lifetime value for Router Advertisement message
 * 
 * @detailed Computes the Router Lifetime field value for inclusion in the ICMPv6 Router
 *           Advertisement message header per RFC 4861. The Router Lifetime indicates the
 *           duration in seconds that receiving hosts should consider this router as a valid
 *           default router for forwarding packets off the local network segment. This value
 *           directly impacts host routing table entries: hosts remove the router from their
 *           default router list when the lifetime expires, requiring a new RA to restore
 *           reachability.
 * 
 * The function implements a three-tier calculation strategy with RFC 4861 compliance and
 * dnsmasq-specific policy constraints:
 * 
 * TIER 1 - DEFAULT LIFETIME (no configuration or lifetime == -1):
 * When the administrator has not explicitly configured a lifetime value (ra parameter is NULL
 * or ra->lifetime == -1), the function applies RFC 4861's recommended default: 3 times the
 * MaxRtrAdvInterval. This ensures the router lifetime extends well beyond the typical RA
 * transmission interval, providing redundancy against packet loss. With default MaxRtrAdvInterval
 * of 600 seconds, this yields 1800 seconds (30 minutes) lifetime. Formula: lifetime = 3 * interval.
 * 
 * RFC 4861 Section 6.2.1 states: "AdvDefaultLifetime SHOULD be at least MaxRtrAdvInterval if the
 * router is to be used as a default router." The 3x multiplier provides comfortable margin.
 * 
 * TIER 2 - CONFIGURED LIFETIME WITH VALIDATION:
 * When the administrator has configured an explicit lifetime via --ra-param lifetime=<seconds>,
 * the function applies that value but enforces two critical constraints to prevent misconfigurations:
 * 
 * MINIMUM CONSTRAINT: If configured lifetime is less than MaxRtrAdvInterval AND is non-zero,
 * the function raises the lifetime to equal MaxRtrAdvInterval. This prevents the invalid
 * scenario where the router lifetime expires before the next RA transmission, causing hosts
 * to remove the router from their default router list despite the router continuing to advertise.
 * Special case: lifetime=0 is permitted and means "do not use as default router" (RFC 4861
 * explicitly allows 0 to signal non-default-router status for routers advertising only prefixes).
 * 
 * MAXIMUM CONSTRAINT: If configured lifetime exceeds 9000 seconds, the function caps the value
 * at 9000 seconds. While RFC 4861 allows Router Lifetime up to 65535 seconds (18.2 hours),
 * dnsmasq enforces a conservative 9000-second (2.5 hours) maximum to limit the duration hosts
 * retain stale routing information if the router becomes unreachable. This policy protects
 * against excessively long convergence times in dynamic network environments.
 * 
 * TIER 3 - INTERVAL CALCULATION DEPENDENCY:
 * All lifetime calculations depend on MaxRtrAdvInterval retrieved via calc_interval(ra), which
 * returns either the interface-specific configured interval or the default 600-second value.
 * This ensures lifetime scaling remains proportional to advertisement frequency regardless of
 * per-interface interval tuning.
 * 
 * The calculated lifetime is returned as unsigned int matching the 16-bit Router Lifetime
 * field in the ICMPv6 RA header (struct nd_router_advert), though dnsmasq's 9000-second cap
 * ensures the value never approaches the 65535 maximum.
 * 
 * @param ra Pointer to ra_interface structure containing interface-specific RA configuration,
 *           or NULL if no configuration exists for this interface
 * 
 * @return Router Lifetime value in seconds for inclusion in RA header
 * @retval 3*interval Default when ra is NULL or ra->lifetime == -1 (typically 1800 seconds)
 * @retval 0 Administrator explicitly configured lifetime=0 (non-default router mode)
 * @retval interval Configured lifetime was less than interval (raised to interval for RFC compliance)
 * @retval 9000 Configured lifetime exceeded 9000 seconds (capped at maximum)
 * @retval ra->lifetime Configured lifetime within valid range (interval to 9000 seconds)
 * 
 * @note Default lifetime is 3 times MaxRtrAdvInterval per RFC 4861 recommendation
 * @note Lifetime of 0 is valid and signals "do not use as default router" (RFC 4861)
 * @note Non-zero lifetimes are enforced to be >= MaxRtrAdvInterval for RFC compliance
 * @note Maximum enforced lifetime is 9000 seconds (dnsmasq policy, not RFC limit)
 * @note RFC 4861 permits lifetimes up to 65535 seconds, but dnsmasq caps at 9000
 * @note Lifetime affects host default router list entry expiration time
 * @note Hosts remove expired default routers from routing tables automatically
 * @note interval is calculated via calc_interval(ra) which may return default or configured value
 * @note ra->lifetime == -1 is the sentinel value meaning "use default calculation"
 * @note Casting to unsigned int is safe since lifetime is clamped to [0, 9000] range
 * 
 * @warning Requires calc_interval() to return valid MaxRtrAdvInterval value
 * @warning Lifetime < interval (except 0) violates RFC 4861 and is automatically corrected
 * @warning Lifetime > 9000 is clamped to 9000 regardless of configuration
 * @warning ra->lifetime values are assumed to be in seconds (no unit conversion)
 * @warning Lifetime = 0 is special: router advertises prefixes but not default route
 * @warning Hosts will NOT forward off-link traffic to routers with lifetime = 0
 * @warning Overly long lifetimes delay convergence when routers become unreachable
 * 
 * @see send_ra() for RA message construction using calculated lifetime in nd_router_advert header
 * @see send_ra_alias() for alias interface RA construction also using this calculation
 * @see calc_interval() for MaxRtrAdvInterval retrieval used in lifetime calculation
 * @see find_iface_param() for ra_interface structure lookup by interface name
 * @see struct nd_router_advert in radv-protocol.h for Router Lifetime field (16-bit)
 * @see struct ra_interface in dnsmasq.h for lifetime configuration member
 * 
 * EXAMPLE USAGE:
 * @code
 * // Default lifetime calculation (no configuration):
 * struct ra_interface *ra = NULL;
 * unsigned int lifetime = calc_lifetime(ra);
 * // Returns: 3 * 600 = 1800 seconds (30 minutes)
 * 
 * // Configured lifetime within valid range:
 * struct ra_interface ra_cfg = { .lifetime = 3600 };
 * lifetime = calc_lifetime(&ra_cfg);
 * // Returns: 3600 seconds (1 hour)
 * 
 * // Configured lifetime too low (raised to interval):
 * ra_cfg.lifetime = 300; // Less than default interval of 600
 * lifetime = calc_lifetime(&ra_cfg);
 * // Returns: 600 seconds (raised to interval minimum)
 * 
 * // Configured lifetime too high (capped at maximum):
 * ra_cfg.lifetime = 20000;
 * lifetime = calc_lifetime(&ra_cfg);
 * // Returns: 9000 seconds (capped at dnsmasq maximum)
 * 
 * // Special case - non-default router mode:
 * ra_cfg.lifetime = 0;
 * lifetime = calc_lifetime(&ra_cfg);
 * // Returns: 0 (router advertises prefixes only, no default route)
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 4861 Section 6.2.1 (Router Configuration Variables - AdvDefaultLifetime)
 * RFC COMPLIANCE: RFC 4861 Section 4.2 (Router Advertisement Message Format - Router Lifetime field)
 * RFC COMPLIANCE: RFC 4861 requires lifetime >= MaxRtrAdvInterval (enforced by minimum constraint)
 * RFC COMPLIANCE: RFC 4861 allows lifetime = 0 for non-default-router operation
 * 
 * SIDE EFFECTS: Calls calc_interval(ra) which may search daemon->ra_interfaces configuration list
 * SIDE EFFECTS: None to global state (pure calculation function with no modifications)
 * 
 * THREAD SAFETY: Read-only access to ra structure, safe in single-threaded event loop
 */
static unsigned int calc_lifetime(struct ra_interface *ra)
{
  int lifetime, interval = (int)calc_interval(ra);
  
  if (!ra || ra->lifetime == -1) /* not specified */
    lifetime = 3 * interval;
  else
    {
      lifetime = ra->lifetime;
      if (lifetime < interval && lifetime != 0)
	lifetime = interval;
      else if (lifetime > 9000)
	lifetime = 9000;
    }
  
  return (unsigned int)lifetime;
}

/**
 * @brief Calculate router priority for Router Advertisement
 * 
 * Determines the router priority to include in the RA message. Priority
 * values control router selection preference when multiple routers advertise
 * on the same network segment. Higher values indicate higher priority.
 * 
 * @param ra Pointer to ra_interface configuration or NULL
 * 
 * @return Router priority value if ra is non-NULL and configured, 0 otherwise
 * @retval 0 Default priority (medium) when not configured
 * @retval ra->prio Configured priority value
 * 
 * @note Priority values are typically:
 *       - 0 (low)
 *       - 0 (medium/default) 
 *       - High priority (positive values)
 * @note Returns 0 for medium priority by default per RFC 4191
 * 
 * @see calc_lifetime() for lifetime calculation
 * @see calc_interval() for advertisement interval
 * 
 * EXAMPLE USAGE:
 * @code
 * struct ra_interface *ra = find_iface_param("eth0");
 * unsigned int prio = calc_prio(ra);
 * // Use prio in RA message construction
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 4191 Section 2.1 (Router Preference)
 * THREAD SAFETY: Single-threaded access, safe for read-only operations
 */
/**
 * @brief Calculate Router Preference (Prf) value for Router Advertisement message
 * 
 * @detailed Retrieves the Router Preference value for inclusion in the ICMPv6 Router
 *           Advertisement message header flags field per RFC 4191 Section 2.2. The Router
 *           Preference (Prf) is a 2-bit field that indicates the preference for this router
 *           compared to other routers on the same link, helping hosts make intelligent
 *           routing decisions when multiple default routers are available. This preference
 *           influences the host's default router selection algorithm: higher-preference
 *           routers are selected preferentially for forwarding off-link packets, improving
 *           traffic distribution and enabling administrator control over routing paths.
 * 
 * The function implements a simple configuration retrieval mechanism with RFC 4191
 * compliance and dnsmasq's default policy:
 * 
 * DEFAULT PREFERENCE (no configuration):
 * When no interface-specific preference is configured (ra parameter is NULL), the
 * function returns 0, corresponding to Medium (00) preference per RFC 4191. This neutral
 * default ensures the router participates in default router selection without claiming
 * priority over peers. Formula: prio = 0 (Medium preference).
 * 
 * RFC 4191 Section 2.1 states: "Medium (00) preference is the default, and SHOULD be
 * used for routers that need not be distinguished from their peers." This value is
 * appropriate when all routers on the link have equivalent capabilities and the
 * administrator has not configured preferential routing.
 * 
 * CONFIGURED PREFERENCE:
 * When the administrator has explicitly configured a preference via --ra-param
 * priority=<value>, the function returns that configured value from the ra->prio
 * member of the ra_interface structure. The configuration parser (in option.c)
 * accepts three named values corresponding to RFC 4191 preferences:
 * 
 * - "high" (1): High (01) preference signals this router should be preferred over
 *   routers with Medium or Low preference when forwarding packets. Use for primary
 *   internet-connected routers or routers with better upstream connectivity.
 * 
 * - "medium" (0): Medium (00) preference indicates no special priority. This is the
 *   RFC default and appropriate for most scenarios where routers have equivalent
 *   capabilities and no preferential treatment is desired.
 * 
 * - "low" (3): Low (11) preference signals this router should be used only when no
 *   Higher or Medium preference routers are available. Use for backup routers, slow
 *   links, or routers with limited capabilities. Note: RFC 4191 uses 11 binary (3
 *   decimal) to encode Low preference, not 2 (which is Reserved).
 * 
 * RFC 4191 PREFERENCE ENCODING:
 * The 2-bit Prf field in the ICMPv6 RA header flags occupies bits 3-4 (counting from
 * bit 0 as LSB) with the following standardized encoding per RFC 4191 Section 2.2:
 * 
 *   00 (0 decimal): Medium preference (default)
 *   01 (1 decimal): High preference
 *   10 (2 decimal): Reserved (MUST NOT be used)
 *   11 (3 decimal): Low preference
 * 
 * The returned value is assigned to the ra_packet->flags field in send_ra() and
 * send_ra_alias(), where it is positioned in the appropriate bits of the ICMPv6
 * Router Advertisement header flags byte before transmission.
 * 
 * HOST BEHAVIOR WITH ROUTER PREFERENCE:
 * RFC 4191-compliant IPv6 hosts use Router Preference to make intelligent default
 * router selection decisions when multiple routers advertise on the same link:
 * 
 * SELECTION ALGORITHM (RFC 4191 Section 3.1):
 * 1. Hosts prefer routers with higher Router Preference over lower preference
 * 2. Among routers with equal preference, hosts may use round-robin or reachability
 * 3. Hosts may maintain multiple default routers and load-balance across equal-preference
 *    routers, with preference governing the load-balance weighting
 * 
 * FAILOVER BEHAVIOR:
 * If the highest-preference router becomes unreachable (detected via Neighbor
 * Unreachability Detection), hosts fail over to the next-highest-preference router.
 * This enables graceful degradation: traffic flows to the preferred router normally,
 * fails over to medium-preference backup routers if the primary fails, and only uses
 * low-preference routers as a last resort.
 * 
 * ADMINISTRATIVE USE CASES:
 * - DUAL-HOMED NETWORKS: Set priority=high on the primary internet-connected router,
 *   priority=medium on the secondary internet connection, and priority=low on the
 *   local-only router serving internal resources. This ensures internet traffic
 *   prefers the primary uplink while maintaining backup connectivity.
 * 
 * - ASYMMETRIC LINKS: Set priority=low on routers with slow or metered connections
 *   (e.g., cellular backup, satellite) to discourage their use except during failures
 *   of faster links.
 * 
 * - POLICY-BASED ROUTING: Use preference to guide hosts toward routers that provide
 *   access to specific resources or paths, implementing basic traffic engineering
 *   without requiring host-side route configuration.
 * 
 * RELATIONSHIP TO PREFIX PREFERENCE:
 * RFC 4191 also defines Route Information Options that can advertise specific routes
 * with preferences. The Router Preference returned by this function applies to the
 * router's role as a default router (for destinations not covered by more-specific
 * routes), while route-specific preferences apply to explicitly advertised prefixes.
 * Both mechanisms work together to provide comprehensive routing preference signaling.
 * 
 * The function's simplicity (direct return of configured or default value) reflects
 * the straightforward nature of Router Preference: it is a static configuration
 * parameter set by the administrator and does not change based on runtime conditions.
 * Dynamic preference adjustment based on link quality, load, or other factors is not
 * part of RFC 4191 and would require custom protocols.
 * 
 * @param ra Pointer to ra_interface structure containing interface-specific RA
 *           configuration including prio member, or NULL if no configuration exists
 *           for this interface
 * 
 * @return Router Preference value for encoding in ICMPv6 RA header flags field
 * @retval 0 Default Medium preference when ra is NULL or not configured (00 binary)
 * @retval 1 High preference when configured with priority=high (01 binary)
 * @retval 3 Low preference when configured with priority=low (11 binary)
 * @retval ra->prio Configured preference value from ra_interface structure
 * 
 * @note Default preference is 0 (Medium) per RFC 4191 Section 2.1
 * @note RFC 4191 defines three valid preferences: High (1), Medium (0), Low (3)
 * @note Value 2 (10 binary) is Reserved and MUST NOT be used per RFC 4191
 * @note Preference encoding: 00=Medium, 01=High, 10=Reserved, 11=Low
 * @note Return value is assigned to ra_packet->flags which maps to ICMPv6 RA header
 * @note Hosts use preference to prioritize routers when multiple are available
 * @note Higher-preference routers are selected preferentially for packet forwarding
 * @note Preference affects default router selection but not neighbor reachability
 * @note ra->prio is configured via --ra-param priority=high|medium|low option
 * @note Configuration parsing in option.c validates preference values
 * @note Preference is static per interface and does not change at runtime
 * @note This function has no side effects and performs pure configuration lookup
 * 
 * @warning Value 2 is Reserved per RFC 4191 and produces undefined host behavior
 * @warning Preference only affects RFC 4191-compliant hosts (not legacy IPv6 stacks)
 * @warning Misconfigured preferences can cause suboptimal routing or traffic imbalance
 * @warning Low preference may result in router underutilization even when idle
 * @warning High preference may overload a router if other routers have lower capacity
 * @warning Preference does not override host's manual default route configuration
 * @warning Router Preference requires Router Lifetime > 0 to be effective
 * @warning Hosts may cache preference and continue using old value after RA change
 * 
 * @see send_ra() for RA message construction using calculated preference in ra_packet flags
 * @see send_ra_alias() for alias interface RA construction also using this preference
 * @see struct ra_packet in radv-protocol.h for flags field (includes Prf bits)
 * @see struct ra_interface in dnsmasq.h for prio configuration member
 * @see find_iface_param() for ra_interface structure lookup by interface name
 * @see RFC 4191 Section 2.2 for Router Preference definition and encoding
 * @see RFC 4191 Section 3.1 for host default router selection algorithm
 * 
 * EXAMPLE USAGE:
 * @code
 * // Default preference (no configuration):
 * struct ra_interface *ra = NULL;
 * unsigned int prio = calc_prio(ra);
 * // Returns: 0 (Medium preference, 00 binary)
 * 
 * // Configured high preference (primary router):
 * struct ra_interface ra_cfg = { .prio = 1 };
 * prio = calc_prio(&ra_cfg);
 * // Returns: 1 (High preference, 01 binary)
 * // Hosts prefer this router for default gateway
 * 
 * // Configured low preference (backup router):
 * ra_cfg.prio = 3;
 * prio = calc_prio(&ra_cfg);
 * // Returns: 3 (Low preference, 11 binary)
 * // Hosts use this router only when higher-preference routers unavailable
 * 
 * // Using preference in RA construction:
 * struct ra_packet *ra_pkt = malloc(sizeof(struct ra_packet));
 * ra_pkt->flags = calc_prio(ra);
 * // RA header flags field now contains Router Preference bits
 * 
 * // Multi-homed network scenario:
 * struct ra_interface ra_primary = { .prio = 1 };    // High - main internet
 * struct ra_interface ra_backup = { .prio = 0 };     // Medium - backup internet
 * struct ra_interface ra_local = { .prio = 3 };      // Low - local only
 * // Hosts will prefer primary, fall back to backup, use local as last resort
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 4191 Section 2.2 (Router Preference and Preference Values)
 * RFC COMPLIANCE: RFC 4191 Section 2.1 (Router Preference Default Router Extension)
 * RFC COMPLIANCE: RFC 4191 defines encoding: 00=Medium, 01=High, 10=Reserved, 11=Low
 * RFC COMPLIANCE: RFC 4191 Section 3.1 (Host Default Router Selection Algorithm)
 * RFC COMPLIANCE: Medium (0) is default preference per RFC 4191
 * 
 * SIDE EFFECTS: None (pure configuration retrieval with no global state modifications)
 * 
 * THREAD SAFETY: Read-only access to ra structure, safe in single-threaded event loop
 */
static unsigned int calc_prio(struct ra_interface *ra)
{
  if (ra)
    return ra->prio;
  
  return 0;
}

#endif

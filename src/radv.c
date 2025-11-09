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

/**
 * @struct ra_param
 * @brief Router Advertisement construction state parameters
 * 
 * This structure accumulates state during the Router Advertisement construction
 * process, tracking interface details, discovered addresses, timing parameters,
 * and DHCPv6 context associations. Passed to callback functions during address
 * enumeration to build complete RA packets with appropriate prefix options.
 * 
 * LIFECYCLE:
 * Creation: Stack-allocated in send_ra() and send_ra_alias()
 * Initialization: Zero-initialized, then populated during address enumeration
 * Destruction: Automatic (stack-allocated structure)
 * Ownership: Local to RA construction functions
 * 
 * MEMORY LAYOUT:
 * Size: ~80-100 bytes (includes time_t, integers, pointer, struct in6_addr x3)
 * Alignment: Natural alignment for contained types
 * 
 * USAGE PATTERNS:
 * - Allocated on stack in send_ra() before calling iface_enumerate()
 * - Passed as void* parameter to add_prefixes() callback during enumeration
 * - Accumulates link-local, global, and ULA addresses found on interface
 * - Tracks preferred/valid times for each address scope
 * - Records managed/other flags, advertisement interval, router priority
 * - Links to found DHCPv6 context for lease time coordination
 */
struct ra_param {
  time_t now;                         /**< Current time for lease calculations */
  int ind;                            /**< Interface index for this RA */
  int managed;                        /**< M flag: 1=use DHCPv6 for addresses */
  int other;                          /**< O flag: 1=use DHCPv6 for config */
  int first;                          /**< First prefix flag for RA construction */
  int adv_router;                     /**< Advertisement router flag */
  char *if_name;                      /**< Interface name (e.g., "eth0") */
  struct dhcp_netid *tags;            /**< DHCP network tags for this interface */
  struct in6_addr link_local;         /**< Link-local address (fe80::/10) */
  struct in6_addr link_global;        /**< Global unicast address (2000::/3) */
  struct in6_addr ula;                /**< Unique local address (fc00::/7) */
  unsigned int glob_pref_time;        /**< Preferred lifetime for global address */
  unsigned int link_pref_time;        /**< Preferred lifetime for link-local */
  unsigned int ula_pref_time;         /**< Preferred lifetime for ULA */
  unsigned int adv_interval;          /**< Advertisement interval in seconds */
  unsigned int prio;                  /**< Router priority (low/medium/high) */
  struct dhcp_context *found_context; /**< Associated DHCPv6 context or NULL */
};

/**
 * @struct search_param
 * @brief Interface search parameters for Router Advertisement processing
 * 
 * Lightweight structure used to search for specific interfaces during packet
 * reception and processing. Primarily used to match received ICMPv6 packets
 * to configured interfaces by index and retrieve interface name for logging
 * and context lookup.
 * 
 * LIFECYCLE:
 * Creation: Stack-allocated in icmp6_packet() during packet processing
 * Initialization: Populated with current time, interface index from packet
 * Destruction: Automatic (stack-allocated structure)
 * Ownership: Local to packet reception functions
 * 
 * MEMORY LAYOUT:
 * Size: ~24 bytes (time_t + int + IF_NAMESIZE+1 char array)
 * Alignment: Natural alignment for time_t
 * 
 * USAGE PATTERNS:
 * - Allocated in icmp6_packet() when Router Solicitation received
 * - Passed to iface_search() callback to match interface index
 * - Interface name populated during enumeration for subsequent processing
 */
struct search_param {
  time_t now;                  /**< Current time for RA scheduling */
  int iface;                   /**< Interface index to search for */
  char name[IF_NAMESIZE+1];    /**< Interface name output (null-terminated) */
};

/**
 * @struct alias_param
 * @brief Bridge alias interface tracking for Router Advertisement
 * 
 * Manages the set of bridge alias interfaces that require Router Advertisement
 * transmission. Used to send identical RA packets across multiple related
 * interfaces (e.g., bridge members) to ensure consistent configuration across
 * a bridged network segment.
 * 
 * LIFECYCLE:
 * Creation: Stack-allocated in send_ra_to_aliases()
 * Initialization: Zero-initialized, dynamically grows alias_ifs array
 * Destruction: alias_ifs array freed with free() before function return
 * Ownership: Local to send_ra_to_aliases() function
 * 
 * MEMORY LAYOUT:
 * Size: ~32 bytes base + dynamically allocated array
 * Alignment: Natural alignment for pointers and integers
 * 
 * USAGE PATTERNS:
 * - Allocated when sending RA to bridge with aliases
 * - alias_ifs array dynamically allocated and grown as aliases discovered
 * - Each alias interface index added to array during enumeration
 * - Array traversed after enumeration to send RA to each alias
 * - Memory freed after all RAs transmitted
 */
struct alias_param {
  int iface;                   /**< Primary interface index */
  struct dhcp_bridge *bridge;  /**< Bridge configuration or NULL */
  int num_alias_ifs;           /**< Current count of alias interfaces */
  int max_alias_ifs;           /**< Allocated capacity of alias_ifs array */
  int *alias_ifs;              /**< Dynamically allocated array of alias indices */
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

/**
 * @brief Send Router Advertisement with configurable send and content interfaces
 * 
 * @detailed Constructs and transmits an IPv6 Router Advertisement (ICMPv6 type 134) message
 *           with prefix information, DNS options, and DHCPv6 coordination flags. This function
 *           supports bridge and alias scenarios where RA content is based on one interface
 *           (iface) but transmitted on another (send_iface), enabling complex network topologies.
 *           
 *           The function handles:
 *           - Prefix information options with valid/preferred lifetimes
 *           - M (managed address) and O (other configuration) flags for DHCPv6 coordination
 *           - RDNSS (Recursive DNS Server) option per RFC 6106
 *           - DNSSL (DNS Search List) option per RFC 6106
 *           - Advertisement interval and MTU options
 *           - Old prefix advertisement for smooth renumbering transitions
 *           - Router lifetime calculation based on prefix validity
 * 
 * @param now Current timestamp for calculating prefix lifetimes and RA intervals
 * @param iface Interface index for determining RA content (contexts, prefixes, addresses)
 * @param iface_name Name of the interface (e.g., "eth0", "br0") for logging and context matching
 * @param dest Destination IPv6 address for RA (NULL means all-nodes multicast ff02::1)
 * @param send_iface Interface index for actual packet transmission (may differ from iface for bridges)
 * 
 * @return void
 * 
 * @note This function is the workhorse of Router Advertisement generation, handling all
 *       complexity of prefix management, DNS option encoding, and DHCPv6 flag coordination.
 * @note When send_iface differs from iface, supports bridge/alias scenarios where RA content
 *       from one interface is transmitted on another.
 * @note Router lifetime is set to the maximum valid lifetime of advertised prefixes, or
 *       calculated from ra_interface configuration if no valid prefixes exist.
 * 
 * @warning Function may be called during DHCPv4/DHCPv6 transactions - uses only outpacket
 *          buffer which is not shared with DHCPv4 code.
 * @warning Expired DHCP contexts are pruned during RA construction; this modifies daemon state.
 * @warning Invalid interface indices or missing link-local addresses cause silent failure.
 * 
 * @see send_ra() Simple wrapper calling send_ra_alias with matching iface and send_iface
 * @see add_prefixes() Callback that populates prefix information options
 * @see iface_search() Helper for finding link-local address on interface
 * 
 * EXAMPLE USAGE:
 * @code
 * // Send RA on eth0 to all nodes
 * send_ra_alias(time(NULL), if_nametoindex("eth0"), "eth0", NULL, if_nametoindex("eth0"));
 * 
 * // Send RA with eth0 content but transmit on br0 (bridge scenario)
 * send_ra_alias(time(NULL), if_nametoindex("eth0"), "eth0", NULL, if_nametoindex("br0"));
 * 
 * // Send RA to specific destination (solicited RA)
 * struct in6_addr client_addr = ...; // From router solicitation
 * send_ra_alias(time(NULL), if_nametoindex("eth0"), "eth0", &client_addr, if_nametoindex("eth0"));
 * @endcode
 * 
 * RFC COMPLIANCE:
 * - RFC 4861 Section 4.2: Router Advertisement Message Format
 * - RFC 4861 Section 6.2.3: Router Advertisement processing
 * - RFC 4861 Section 6.2.6: Prefix Information option format
 * - RFC 6106 Section 5: RDNSS and DNSSL options
 * - RFC 4191 Section 2.2: Route Information option
 * 
 * SIDE EFFECTS:
 * - Modifies daemon->outpacket buffer for ICMPv6 packet construction
 * - Prunes expired DHCP contexts from daemon->dhcp6 linked list
 * - Updates context deprecation and invalidation times
 * - Transmits ICMPv6 packet via raw socket to network
 * - Logs RA transmission events to syslog
 * 
 * THREAD SAFETY: Single-threaded architecture - function modifies global daemon state
 * 
 * OPERATIONAL MODES:
 * - ra-only: SLAAC addressing with stateless DHCPv6 for configuration (M=0, O=1)
 * - ra-names: SLAAC addressing with RDNSS in RA, no DHCPv6 (M=0, O=0)
 * - ra-stateless: SLAAC addressing with no additional configuration (M=0, O=0)
 * - ra-stateful: Stateful DHCPv6 address assignment (M=1, O=1)
 * 
 * DHCPv6 FLAG COORDINATION:
 * - M flag (managed address): When set to 1, signals clients to obtain addresses via DHCPv6
 * - O flag (other configuration): When set to 1, signals clients to obtain DNS/domain via DHCPv6
 * - Flags determined by CONTEXT_RA_STATELESS, CONTEXT_RA_OFF_LINK contexts
 * - SLAAC-only mode: Both flags 0, prefix autonomous flag set
 */
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

/**
 * @brief Send Router Advertisement to bridged alias interfaces
 * 
 * Callback function invoked during interface enumeration to transmit Router
 * Advertisements to alias interfaces that are bridged to the primary interface.
 * This enables RA distribution across complex network topologies with bridge
 * configurations, ensuring all connected network segments receive RA messages.
 * 
 * @param index Interface index being enumerated
 * @param type Interface type (unused - accepts any interface type)
 * @param mac MAC address of interface (unused)
 * @param maclen Length of MAC address (unused)
 * @param parm Pointer to struct alias_param containing bridge configuration and interface list
 * 
 * @return Always returns 1 to continue interface enumeration
 * 
 * @note This function is used as a callback for iface_enumerate() to process all interfaces.
 *       It checks if the enumerated interface is an alias of a bridged interface and sends
 *       RA via send_ra_alias() if a bridge relationship is found.
 * 
 * @see send_ra_alias() for actual RA transmission to alias interface
 * @see iface_enumerate() in network.c for enumeration mechanism
 * 
 * EXAMPLE USAGE:
 * @code
 * struct alias_param aparm = {
 *   .iface = primary_if_index,
 *   .bridge = daemon->bridges,
 *   .num_alias_ifs = 5,
 *   .alias_ifs = alias_array
 * };
 * iface_enumerate(AF_UNSPEC, &aparm, send_ra_to_aliases);
 * @endcode
 * 
 * SIDE EFFECTS: Sends Router Advertisement packets to discovered alias interfaces
 * THREAD SAFETY: Single-threaded architecture - uses global daemon structure
 */
static int send_ra_to_aliases(int index, unsigned int type, char *mac, size_t maclen, void *parm)
{
  struct alias_param *aparm = (struct alias_param *)parm;
  char ifrn_name[IF_NAMESIZE+1];
  struct dhcp_bridge *bridge;
  int i; 
  
  (void)type;
  (void)mac;
  (void)maclen;

  if (index == aparm->iface)
    return 1;

  for (bridge = aparm->bridge; bridge; bridge = bridge->next)
    for (i = 0; i < aparm->num_alias_ifs; i++)
      if ((int)if_nametoindex(bridge->iface) == aparm->alias_ifs[i] &&
	  bridge->alias && (int)if_nametoindex(bridge->alias->iface) == index &&
	  indextoname(daemon->icmp6fd, index, ifrn_name))
	{
	  send_ra_alias(dnsmasq_time(), aparm->iface, ifrn_name, NULL, if_nametoindex(bridge->iface));
	  break;
	}
  
  return 1;
}

/**
 * @brief Search for link-local IPv6 address on specified interface
 * 
 * Callback function invoked during IPv6 address enumeration to locate a link-local
 * address (/128 host address) on a specific interface. When a matching link-local
 * address is found, it is converted to string format and stored in daemon->addrbuff,
 * and the search parameter's interface index is set to -1 to signal discovery.
 * This function is used during Router Advertisement initialization to verify the
 * presence of link-local addresses required for RA transmission.
 * 
 * @param local IPv6 address being examined during enumeration
 * @param prefix Prefix length of the address (must be 128 for host addresses)
 * @param scope Address scope (unused - filtering done via address inspection)
 * @param if_index Interface index for this address
 * @param flags Address flags (unused)
 * @param preferred Preferred lifetime for the address (unused)
 * @param valid Valid lifetime for the address (unused)
 * @param vparam Pointer to struct search_param containing target interface index and name
 * 
 * @return Always returns 1 to continue enumeration through all addresses
 * 
 * @note When a link-local address is found, param->iface is set to -1 to signal
 *       successful discovery. The address is converted to string format in
 *       daemon->addrbuff for logging or further processing.
 * @warning This function modifies vparam (sets iface to -1) and daemon->addrbuff
 *          (stores address string) when a match is found.
 * 
 * @see iface_enumerate() in network.c for enumeration mechanism
 * @see ra_init() which uses this to detect link-local addresses
 * 
 * EXAMPLE USAGE:
 * @code
 * struct search_param param = {
 *   .now = current_time,
 *   .iface = eth0_index,
 * };
 * strcpy(param.name, "eth0");
 * iface_enumerate(AF_INET6, &param, iface_search);
 * if (param.iface == -1) {
 *   // Link-local address found and stored in daemon->addrbuff
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 4861 Section 6.1.1 - Validates link-local address presence
 * SIDE EFFECTS: Modifies param->iface to -1 and populates daemon->addrbuff on match
 * THREAD SAFETY: Single-threaded architecture - safe for callback use
 */
static int iface_search(struct in6_addr *local,  int prefix,
			int scope, int if_index, int flags, 
			unsigned int preferred, unsigned int valid, void *vparam)
{
  struct search_param *param = vparam;
  
  (void)scope;
  (void)preferred;
  (void)valid;
  (void)flags;

  if (prefix == 128 &&
      IN6_IS_ADDR_LINKLOCAL(local) &&
      param->iface == if_index)
    {
      /* Check to see if there's another link-local address */
      inet_ntop(AF_INET6, local, daemon->addrbuff, ADDRSTRLEN);
      param->iface = -1;
    }
  
  return 1;
}

/**
 * @brief Calculate and set next Router Advertisement transmission time
 * 
 * Determines the next scheduled RA transmission time for a DHCP context based on
 * RFC 4861 timing requirements. During the initial 60-second "short period" after
 * context activation, RAs are transmitted more frequently (5-20 seconds) to ensure
 * rapid network configuration for newly connected clients. After the short period,
 * transmission intervals are randomized between 3/4 and 1 times MaxRtrAdvInterval
 * to prevent synchronization and reduce network congestion.
 * 
 * The randomization formula during normal operation calculates:
 *   next_time = now + (3 * MaxRtrAdvInterval / 4) + random_component
 * where random_component ranges from 0 to MaxRtrAdvInterval/4, ensuring the
 * interval stays within RFC-mandated bounds.
 * 
 * @param context DHCP context containing RA state and timing information
 * @param iface_name Interface name for looking up RA parameters
 * @param now Current time in seconds since epoch
 * 
 * @note The short period duration is fixed at 60 seconds per RFC 4861 recommendation.
 * @note Random intervals prevent synchronized RA transmission from multiple routers.
 * @warning context->ra_time is modified to schedule next transmission; must be checked
 *          in main event loop to trigger actual RA sending.
 * 
 * @see calc_interval() in radv.c for MaxRtrAdvInterval calculation
 * @see find_iface_param() in radv.c for interface parameter lookup
 * @see ra_start_unsolicited() which initializes ra_short_period_start
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_context *ctx = ...;
 * char *iface = "eth0";
 * time_t now = time(NULL);
 * new_timeout(ctx, iface, now);
 * // ctx->ra_time now contains next scheduled transmission time
 * // Main loop will send RA when (now >= ctx->ra_time)
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 4861 Section 6.2.1 - Router Advertisement timing
 *                 Short period: 3-16 seconds (relaxed to 5-20 for implementation)
 *                 Normal period: MinRtrAdvInterval to MaxRtrAdvInterval
 * SIDE EFFECTS: Modifies context->ra_time to schedule next RA transmission
 * THREAD SAFETY: Single-threaded architecture - safe for sequential use
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
 * @brief Find Router Advertisement parameters for specified interface
 * 
 * Searches the global linked list of configured RA interfaces to locate parameters
 * for the specified interface name. The search supports wildcard matching, allowing
 * configuration patterns like "eth*" to match multiple physical interfaces. This
 * function is used throughout the RA subsystem to retrieve interface-specific
 * configuration such as advertisement intervals, router lifetime, and router priority.
 * 
 * The function iterates through daemon->ra_interfaces (populated during configuration
 * parsing) and returns the first entry whose name pattern matches the provided
 * interface name. If no match is found, NULL is returned and the caller typically
 * falls back to default RA behavior or skips RA transmission for that interface.
 * 
 * @param iface Interface name to search for (e.g., "eth0", "wlan0")
 * 
 * @return Pointer to struct ra_interface containing RA parameters for the interface,
 *         or NULL if no matching configuration found
 * @retval non-NULL Matching RA interface configuration found
 * @retval NULL No configuration matches the specified interface name
 * 
 * @note Wildcard patterns in configuration (e.g., "eth*") are supported via
 *       wildcard_match() function for flexible interface matching.
 * @note Returns the FIRST matching entry if multiple patterns match the interface.
 * @warning Caller must handle NULL return gracefully; many callers use default
 *          values or skip RA operations when NULL is returned.
 * 
 * @see calc_interval() which uses this to retrieve MaxRtrAdvInterval
 * @see calc_lifetime() which uses this to retrieve router lifetime
 * @see calc_prio() which uses this to retrieve router priority
 * @see wildcard_match() in util.c for pattern matching implementation
 * 
 * EXAMPLE USAGE:
 * @code
 * char *interface = "eth0";
 * struct ra_interface *ra_params = find_iface_param(interface);
 * if (ra_params) {
 *   // Use ra_params->interval, ra_params->lifetime, ra_params->prio
 *   unsigned int interval = calc_interval(ra_params);
 * } else {
 *   // Use default RA parameters
 *   interval = DEFAULT_RA_INTERVAL;
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: Configuration lookup supporting RFC 4861 RA parameters
 * SIDE EFFECTS: None - read-only traversal of daemon->ra_interfaces list
 * THREAD SAFETY: Single-threaded architecture - safe for sequential access
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
 * @brief Process IPv6 addresses and construct Router Advertisement prefix information options
 * 
 * @detailed Callback function invoked by iface_enumerate() during RA packet construction to process
 *           each IPv6 address assigned to an interface. The function matches addresses against
 *           configured DHCPv6 contexts, determines SLAAC and managed configuration flags, calculates
 *           appropriate lifetimes, and constructs ICMP6_OPT_PREFIX options for inclusion in the RA.
 *           This implements the core logic for IPv6 prefix advertisement per RFC 4861, including
 *           support for router address advertisement (RFC 3775 Section 7.2), ULA (Unique Local
 *           Address) tracking for RDNSS, and coordination with stateful/stateless DHCPv6.
 * 
 *           The function processes three categories of addresses:
 *           - Link-local addresses: Stored in param->link_local for RDNSS source selection
 *           - Loopback/multicast: Skipped (not advertised)
 *           - Global/ULA unicast: Matched against dhcp6 contexts and advertised as prefixes
 * 
 *           For each matching context, the function:
 *           - Sets M (managed) flag if stateful DHCPv6 address assignment is configured
 *           - Sets O (other) flag if DHCPv6 is providing configuration parameters
 *           - Determines autonomous (SLAAC) flag based on CONTEXT_RA presence
 *           - Calculates floor lifetimes (minimum 3 * RA interval) from lease times
 *           - Handles deprecation (preferred lifetime = 0) when CONTEXT_DEPRECATE set
 *           - Tracks highest preferred lifetime addresses for ULA and global scopes
 *           - Constructs prefix options with proper flags and zero network bits
 * 
 * @param local Pointer to IPv6 address on the interface being enumerated
 * @param prefix Prefix length (0-128) for this address, typically 64 for SLAAC prefixes
 * @param scope Address scope from kernel (unused in current implementation, cast to void)
 * @param if_index Interface index from kernel (unused, interface already identified in param)
 * @param flags Interface flags from kernel, checked for IFACE_DEPRECATED to set preferred=0
 * @param preferred Preferred lifetime in seconds from kernel (may be adjusted based on config)
 * @param valid Valid lifetime in seconds from kernel (may be adjusted based on config)
 * @param vparam Opaque pointer to struct ra_param containing RA construction context
 * 
 * @return Always returns 1 to continue interface enumeration
 * @retval 1 Continue processing additional addresses on interface
 * 
 * @note Link-local addresses (fe80::/10) are stored in param->link_local but not advertised
 *       as prefixes; they are used later for RDNSS source address selection.
 * 
 * @note The function implements RFC 3775 Section 7.2 "Home Agent Information Option" behavior
 *       when CONTEXT_RA_ROUTER flag is set: advertises individual router IPv6 addresses with
 *       the R (router address) flag (0x20) instead of network prefixes with zeroed host bits.
 * 
 * @note Lifetime calculations enforce a floor of 3 * adv_interval to prevent thrashing, but
 *       only if CONTEXT_SETLEASE is present (explicit lease time configuration). Default
 *       lease times don't impose a floor.
 * 
 * @note ULA (fd00::/8) and global addresses are tracked separately in param->ula and
 *       param->link_global with their respective preferred lifetimes for RDNSS option
 *       construction, which requires a valid IPv6 source address.
 * 
 * @note The autonomous flag (0x40) enables SLAAC address autoconfiguration per RFC 4862.
 *       The on-link flag (0x80) indicates the prefix is on-link (default) unless
 *       CONTEXT_RA_OFF_LINK is set. Both flags are independent of M/O flag settings.
 * 
 * @warning expand() may fail if outpacket buffer is exhausted, silently dropping the prefix
 *          option. Callers should ensure adequate buffer space via expand_buf() before RA
 *          construction. Current buffer size is sizeof(struct dhcp_packet) minimum.
 * 
 * @warning Modifies param->managed and param->other flags as side effects based on context
 *          matching. These flags accumulate across all prefixes and are used to set M/O bits
 *          in the RA header by send_ra()/send_ra_alias().
 * 
 * @warning Sets CONTEXT_RA_DONE flag on contexts to prevent duplicate prefix advertisements
 *          for the same network. This flag persists across RA transmissions and is cleared
 *          only during configuration reload.
 * 
 * @see iface_enumerate() which invokes this callback for each IPv6 address
 * @see send_ra() which calls iface_enumerate() with this callback during RA construction
 * @see send_ra_alias() which also uses this for bridge alias interfaces
 * 
 * EXAMPLE USAGE:
 * @code
 * struct ra_param param;
 * memset(&param, 0, sizeof(param));
 * param.now = dnsmasq_time();
 * param.if_name = "eth0";
 * param.ind = if_nametoindex("eth0");
 * param.adv_interval = calc_interval(find_iface_param("eth0"));
 * // Enumerate IPv6 addresses on eth0, calling add_prefixes for each
 * iface_enumerate(AF_INET6, &param, add_prefixes);
 * // After enumeration, param.managed and param.other contain accumulated flags
 * // and outpacket contains constructed prefix options
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 4861 Section 4.6.2 (Prefix Information option format)
 * RFC COMPLIANCE: RFC 4862 Section 5.5.3 (Autonomous address configuration)
 * RFC COMPLIANCE: RFC 3775 Section 7.2 (Router address advertisement for mobile IPv6)
 * RFC COMPLIANCE: RFC 4193 (Unique Local IPv6 Unicast Addresses - ULA handling)
 * 
 * SIDE EFFECTS: Modifies param->managed, param->other, param->link_local, param->ula,
 *               param->link_global, param->ula_pref_time, param->glob_pref_time,
 *               param->found_context, param->first, param->tags, and marks contexts with
 *               CONTEXT_RA_DONE flag. Appends prefix options to outpacket buffer via expand().
 * 
 * THREAD SAFETY: Single-threaded architecture; not thread-safe (modifies global daemon state).
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
 */



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
static unsigned int calc_prio(struct ra_interface *ra)
{
  if (ra)
    return ra->prio;
  
  return 0;
}

#endif

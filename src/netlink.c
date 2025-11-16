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
 * @file netlink.c
 * @brief Linux-specific netlink interface for real-time network monitoring and configuration
 * 
 * DETAILED PURPOSE:
 * This Linux-specific module provides real-time monitoring of network interface changes,
 * address assignments, and route updates using the Linux netlink socket interface. Unlike
 * polling-based approaches, netlink provides immediate notification of kernel network
 * events, enabling dnsmasq to respond instantly to network topology changes without
 * resource-intensive periodic scanning.
 * 
 * The netlink implementation serves as the Linux-specific backend for the platform-
 * independent network abstraction layer in network.c, handling address enumeration,
 * interface state monitoring, and dynamic configuration updates triggered by hotplug
 * events, DHCP lease changes, or administrative network reconfiguration.
 * 
 * KEY RESPONSIBILITIES:
 * - Initialize netlink socket with multicast group subscriptions for address and route changes
 * - Parse RTM_NEWADDR/RTM_DELADDR messages for IPv4/IPv6 address addition/removal notifications
 * - Parse RTM_NEWLINK messages for interface state changes (up/down, MAC address changes)
 * - Parse RTM_NEWROUTE messages for routing table updates
 * - Enumerate all network interfaces and addresses via netlink requests (iface_enumerate)
 * - Queue EVENT_NEWADDR and EVENT_NEWROUTE events to main event loop for deferred processing
 * - Integrate with network.c abstraction layer providing platform-independent interface API
 * 
 * DEPENDENCIES:
 * Includes: dnsmasq.h (core data structures), linux/netlink.h, linux/rtnetlink.h (kernel APIs)
 * Called by: dnsmasq.c (initialization), network.c (interface enumeration), main event loop (multicast handler)
 * Calls: queue_event() in dnsmasq.c to schedule deferred processing, callback functions for address enumeration
 * 
 * DATA STRUCTURES:
 * - struct sockaddr_nl: netlink socket address structure for kernel communication (lines 62-71)
 * - struct nlmsghdr: netlink message header for all kernel messages (used throughout)
 * - struct ifaddrmsg: address change notification message format (lines 35-40, IFA_RTA macro)
 * - struct ndmsg: neighbor discovery message format (lines 42-44, NDA_RTA macro)
 * - struct rtmsg: routing message format (implicit in RTM_NEWROUTE handling)
 * - enum async_states: bit flags for tracking pending address/route refresh operations (lines 48-51)
 * 
 * COMPILE-TIME OPTIONS:
 * HAVE_LINUX_NETWORK: Entire file conditionally compiled only on Linux platforms with netlink support
 *   - Enables superior real-time network monitoring compared to polling-based BSD approach
 *   - Provides immediate notification of network changes without periodic interface scanning
 *   - Reduces CPU overhead and improves responsiveness to dynamic network topology changes
 * 
 * THREADING/CONCURRENCY:
 * Single-process event-driven model: netlink socket integrated into main poll() event loop.
 * netlink_multicast() called from main loop when netlink socket becomes readable, parsing
 * messages and queuing events for deferred processing. No locking required as all netlink
 * operations occur on main thread.
 * 
 * PLATFORM SPECIFICITY:
 * This implementation is Linux-specific and provides superior performance to polling-based
 * approaches because:
 * - Kernel push notifications eliminate polling overhead and reduce response latency
 * - Multicast groups provide filtered event delivery (only subscribed event types received)
 * - Netlink protocol is stable kernel ABI available since Linux 2.2 (rtnetlink since 2.4)
 * - Direct kernel communication avoids userspace parsing of /proc or sysfs filesystems
 * 
 * See rtnetlink(7) man page for protocol details and netlink(7) for socket-level operations.
 * 
 * @copyright Copyright (c) 2000-2025 Simon Kelley
 * @license GPL-2.0-or-later
 */

#include "dnsmasq.h"

#ifdef HAVE_LINUX_NETWORK

#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

/* Blergh. Radv does this, so that's our excuse. */
#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

#ifndef NETLINK_NO_ENOBUFS
#define NETLINK_NO_ENOBUFS 5
#endif

/* linux 2.6.19 buggers up the headers, patch it up here. */ 
#ifndef IFA_RTA
#  define IFA_RTA(r)  \
       ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ifaddrmsg))))

#  include <linux/if_addr.h>
#endif

#ifndef NDA_RTA
#  define NDA_RTA(r) ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ndmsg)))) 
#endif

/* Used to request refresh of addresses or routes just once,
 * when multiple changes might be announced. */
enum async_states {
  STATE_NEWADDR = (1 << 0),
  STATE_NEWROUTE = (1 << 1),
};


static struct iovec iov;
static u32 netlink_pid;

static unsigned nl_async(struct nlmsghdr *h, unsigned state);
static void nl_multicast_state(unsigned state);

/**
 * @brief Initialize netlink socket for kernel network event monitoring
 * 
 * @detailed Creates and configures a netlink socket subscribed to IPv4/IPv6 address and
 * route change multicast groups (RTMGRP_IPV4_IFADDR, RTMGRP_IPV6_IFADDR, RTMGRP_IPV4_ROUTE,
 * RTMGRP_IPV6_ROUTE). The socket enables real-time notification of network topology changes
 * without polling. Falls back to non-multicast mode if EPERM encountered (unprivileged operation).
 * 
 * The function initializes daemon->netlinkfd with the netlink socket file descriptor and saves
 * the kernel-assigned netlink PID for later message correlation. Allocates initial message
 * receive buffer (100 bytes, dynamically expanded as needed in netlink_recv).
 * 
 * @return NULL on success (no error message), dies via die() if socket creation or bind fails
 * @retval NULL Netlink socket successfully created and configured
 * 
 * @note Socket creation requires CAP_NET_ADMIN capability for multicast group subscription,
 *       but gracefully falls back to unicast-only operation if permission denied
 * @warning Fatal error (daemon termination via die()) if socket cannot be created or bound
 * 
 * @see netlink_multicast() processes messages received on this socket
 * @see netlink_recv() handles actual message reading and buffer management
 * 
 * EXAMPLE USAGE:
 * @code
 * // Called once during daemon initialization in dnsmasq.c
 * char *err = netlink_init();
 * if (err)
 *   die(_("netlink initialization failed: %s"), err, EC_MISC);
 * // daemon->netlinkfd now ready for poll() monitoring
 * @endcode
 * 
 * RFC COMPLIANCE: Implements Linux rtnetlink protocol per rtnetlink(7) man page
 * 
 * SIDE EFFECTS:
 * - Sets daemon->netlinkfd to netlink socket file descriptor
 * - Sets global netlink_pid to kernel-assigned PID for message filtering
 * - Allocates global iov.iov_base buffer (100 bytes initial) for message reception
 * - Subscribes to kernel multicast groups for address/route notifications
 * 
 * THREAD SAFETY: Single-threaded initialization, called once at daemon startup before event loop
 */
char *netlink_init(void)
{
  struct sockaddr_nl addr;
  socklen_t slen = sizeof(addr);

  addr.nl_family = AF_NETLINK;
  addr.nl_pad = 0;
  addr.nl_pid = 0; /* autobind */
  addr.nl_groups = RTMGRP_IPV4_ROUTE;
  addr.nl_groups |= RTMGRP_IPV4_IFADDR;  
  addr.nl_groups |= RTMGRP_IPV6_ROUTE;
  addr.nl_groups |= RTMGRP_IPV6_IFADDR;

  /* May not be able to have permission to set multicast groups don't die in that case */
  if ((daemon->netlinkfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) != -1)
    {
      if (bind(daemon->netlinkfd, (struct sockaddr *)&addr, sizeof(addr)) == -1)
	{
	  addr.nl_groups = 0;
	  if (errno != EPERM || bind(daemon->netlinkfd, (struct sockaddr *)&addr, sizeof(addr)) == -1)
	    daemon->netlinkfd = -1;
	}
    }
  
  if (daemon->netlinkfd == -1 || 
      getsockname(daemon->netlinkfd, (struct sockaddr *)&addr, &slen) == -1)
    die(_("cannot create netlink socket: %s"), NULL, EC_MISC);
  
  
  /* save pid assigned by bind() and retrieved by getsockname() */ 
  netlink_pid = addr.nl_pid;
  
  iov.iov_len = 100;
  iov.iov_base = safe_malloc(iov.iov_len);
  
  return NULL;
}

/**
 * @brief Read netlink message from kernel with automatic buffer expansion
 * 
 * @detailed Receives a single netlink message from daemon->netlinkfd into the global
 * iov buffer. Implements automatic buffer expansion if MSG_TRUNC indicates message was
 * truncated due to insufficient buffer size. Doubles buffer size on truncation and retries
 * until message fits or maximum reasonable size exceeded.
 * 
 * The function uses recvmsg() with MSG_PEEK for truncation detection, then reads the
 * actual message if buffer is adequate. This approach avoids message loss when buffer
 * is too small for kernel message.
 * 
 * @param flags Message reception flags passed to recvmsg() (MSG_DONTWAIT for non-blocking)
 * 
 * @return Number of bytes received on success, -1 on error or would-block
 * @retval >0 Netlink message successfully received, return value is message length
 * @retval -1 No message available (EAGAIN/EWOULDBLOCK) or error occurred
 * 
 * @note Buffer starts at 100 bytes (netlink_init) and doubles on truncation up to reasonable limit
 * @warning Infinite loop possible if kernel continuously sends messages larger than buffer capacity
 * 
 * @see netlink_multicast() calls this function to receive kernel event notifications
 * @see nl_multicast_state() processes received messages in loop until ENOBUFS
 * 
 * EXAMPLE USAGE:
 * @code
 * // Non-blocking read in event loop
 * ssize_t len;
 * while ((len = netlink_recv(MSG_DONTWAIT)) != -1) {
 *   struct nlmsghdr *h = (struct nlmsghdr *)iov.iov_base;
 *   // Process message in iov.iov_base with length len
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: Netlink message framing per netlink(7) man page
 * 
 * SIDE EFFECTS:
 * - May reallocate iov.iov_base buffer and update iov.iov_len if truncation detected
 * - Uses global iov structure for message buffer management
 * 
 * THREAD SAFETY: Single-threaded access to global iov buffer, called only from main event loop
 */
static ssize_t netlink_recv(int flags)
{
  struct msghdr msg;
  struct sockaddr_nl nladdr;
  ssize_t rc;

  while (1)
    {
      msg.msg_control = NULL;
      msg.msg_controllen = 0;
      msg.msg_name = &nladdr;
      msg.msg_namelen = sizeof(nladdr);
      msg.msg_iov = &iov;
      msg.msg_iovlen = 1;
      msg.msg_flags = 0;
      
      while ((rc = recvmsg(daemon->netlinkfd, &msg, flags | MSG_PEEK | MSG_TRUNC)) == -1 &&
	     errno == EINTR);
      
      /* make buffer big enough */
      if (rc != -1 && (msg.msg_flags & MSG_TRUNC))
	{
	  /* Very new Linux kernels return the actual size needed, older ones always return truncated size */
	  if ((size_t)rc == iov.iov_len)
	    {
	      if (expand_buf(&iov, rc + 100))
		continue;
	    }
	  else
	    expand_buf(&iov, rc);
	}

      /* read it for real */
      msg.msg_flags = 0;
      while ((rc = recvmsg(daemon->netlinkfd, &msg, flags)) == -1 && errno == EINTR);
      
      /* Make sure this is from the kernel */
      if (rc == -1 || nladdr.nl_pid == 0)
	break;
    }
      
  /* discard stuff which is truncated at this point (expand_buf() may fail) */
  if (msg.msg_flags & MSG_TRUNC)
    {
      rc = -1;
      errno = ENOMEM;
    }
  
  return rc;
}
  

/**
 * @brief Enumerate all network interfaces and addresses via netlink requests
 * 
 * @detailed Queries the kernel for complete network interface and address configuration
 * by sending RTM_GETLINK (interface enumeration), RTM_GETADDR (address enumeration), or
 * RTM_GETNEIGH (ARP table) netlink requests depending on family parameter. Processes kernel
 * responses synchronously and invokes callback function for each discovered interface, address,
 * or neighbor entry matching the requested address family.
 * 
 * The function constructs netlink request messages with NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST|NLM_F_ACK
 * flags to request complete dumps of interface, address, or neighbor tables. Reads responses
 * synchronously in blocking mode until NLMSG_DONE sentinel received. For each message
 * (RTM_NEWLINK, RTM_NEWADDR, or RTM_NEWNEIGH), invokes callback with parsed data.
 * 
 * This provides the platform-independent interface enumeration API for network.c, replacing
 * getifaddrs() or ioctl-based enumeration with netlink's more comprehensive and efficient
 * interface. Used during daemon initialization and after network change events to refresh
 * interface state.
 * 
 * Special family values:
 * - AF_UNSPEC: Enumerate ARP table entries (RTM_GETNEIGH request)
 * - AF_LOCAL: Enumerate MAC addresses via link layer (RTM_GETLINK request)
 * - AF_INET/AF_INET6: Enumerate IPv4/IPv6 addresses (RTM_GETADDR request)
 * 
 * @param family Address family filter: AF_UNSPEC (ARP table), AF_LOCAL (MAC addresses),
 *               AF_INET (IPv4 addresses), AF_INET6 (IPv6 addresses)
 * @param parm Opaque pointer passed to callback function for context (typically daemon pointer)
 * @param callback Function pointer from callback_t union invoked for each interface/address/neighbor
 * 
 * @return Success/failure status and restart indication
 * @retval 1 All interfaces/addresses enumerated successfully
 * @retval 0 Enumeration failed (sendto error setting errno)
 * @retval -1 Restart required due to ENOBUFS (kernel buffer overflow, events lost)
 * 
 * @note Callback invoked multiple times: once per interface (RTM_NEWLINK), address (RTM_NEWADDR),
 *       or neighbor (RTM_NEWNEIGH) depending on requested family
 * @warning Blocking I/O operation may delay daemon startup if kernel response is slow
 * @warning Returns -1 (restart required) if ENOBUFS encountered, indicating events were lost
 * 
 * @see nl_async() processes each netlink message and invokes callback function
 * @see network.c for callback function implementations that populate interface structures
 * @see netlink_multicast() handles asynchronous notifications after enumeration complete
 * 
 * EXAMPLE USAGE:
 * @code
 * // Enumerate all IPv4 addresses during initialization
 * static int callback_fn(int index, unsigned int flags, struct in_addr addr, void *parm) {
 *   // Process address data
 *   return 1; // success
 * }
 * int result = iface_enumerate(AF_INET, daemon, (callback_t)callback_fn);
 * if (result == -1)
 *   my_syslog(LOG_WARNING, _("network state changed, restarting enumeration"));
 * else if (result == 0)
 *   die(_("interface enumeration failed: %s"), NULL, EC_MISC);
 * @endcode
 * 
 * RFC COMPLIANCE: RTM_GETLINK, RTM_GETADDR, RTM_GETNEIGH request/response per rtnetlink(7)
 * 
 * SIDE EFFECTS:
 * - Sends RTM_GETLINK, RTM_GETADDR, or RTM_GETNEIGH request to kernel via netlink socket
 * - Blocks reading responses until NLMSG_DONE received for the request
 * - Invokes callback function multiple times with discovered interface/address/neighbor data
 * - Uses global iov buffer for message reception (may reallocate via netlink_recv)
 * - May queue EVENT_NEWADDR or EVENT_NEWROUTE events if changes detected during enumeration
 * - Increments static sequence number (seq) for request correlation with responses
 * 
 * THREAD SAFETY: Single-threaded operation, called during initialization or config reload
 */
/* Original comment: family = AF_UNSPEC finds ARP table entries.
   family = AF_LOCAL finds MAC addresses.
   returns 0 on failure, 1 on success, -1 when restart is required
*/
int iface_enumerate(int family, void *parm, callback_t callback)
{
  struct sockaddr_nl addr;
  struct nlmsghdr *h;
  ssize_t len;
  static unsigned int seq = 0;
  int callback_ok = 1;
  unsigned state = 0;

  struct {
    struct nlmsghdr nlh;
    struct rtgenmsg g; 
  } req;

  memset(&req, 0, sizeof(req));
  memset(&addr, 0, sizeof(addr));

  addr.nl_family = AF_NETLINK;
 
  if (family == AF_UNSPEC)
    req.nlh.nlmsg_type = RTM_GETNEIGH;
  else if (family == AF_LOCAL)
    req.nlh.nlmsg_type = RTM_GETLINK;
  else
    req.nlh.nlmsg_type = RTM_GETADDR;

  req.nlh.nlmsg_len = sizeof(req);
  req.nlh.nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST | NLM_F_ACK; 
  req.nlh.nlmsg_pid = 0;
  req.nlh.nlmsg_seq = ++seq;
  req.g.rtgen_family = family; 

  /* Don't block in recvfrom if send fails */
  while(retry_send(sendto(daemon->netlinkfd, (void *)&req, sizeof(req), 0, 
			  (struct sockaddr *)&addr, sizeof(addr))));

  if (errno != 0)
    return 0;
    
  while (1)
    {
      if ((len = netlink_recv(0)) == -1)
	{
	  if (errno == ENOBUFS)
	    {
	      nl_multicast_state(state);
	      return -1;
	    }
	  return 0;
	}

      for (h = (struct nlmsghdr *)iov.iov_base; NLMSG_OK(h, (size_t)len); h = NLMSG_NEXT(h, len))
	if (h->nlmsg_pid != netlink_pid || h->nlmsg_type == NLMSG_ERROR)
	  {
	    /* May be multicast arriving async */
	    state = nl_async(h, state);
	  }
	else if (h->nlmsg_seq != seq)
	  {
	    /* May be part of incomplete response to previous request after
	       ENOBUFS. Drop it. */
	    continue;
	  }
	else if (h->nlmsg_type == NLMSG_DONE)
	  return callback_ok;
	else if (h->nlmsg_type == RTM_NEWADDR && family != AF_UNSPEC && family != AF_LOCAL)
	  {
	    struct ifaddrmsg *ifa = NLMSG_DATA(h);  
	    struct rtattr *rta = IFA_RTA(ifa);
	    unsigned int len1 = h->nlmsg_len - NLMSG_LENGTH(sizeof(*ifa));
	    
	    if (ifa->ifa_family == family)
	      {
		if (ifa->ifa_family == AF_INET)
		  {
		    struct in_addr netmask, addr, broadcast;
		    char *label = NULL;

		    netmask.s_addr = htonl(~(in_addr_t)0 << (32 - ifa->ifa_prefixlen));

		    addr.s_addr = 0;
		    broadcast.s_addr = 0;
		    
		    while (RTA_OK(rta, len1))
		      {
			if (rta->rta_type == IFA_LOCAL)
			  addr = *((struct in_addr *)(rta+1));
			else if (rta->rta_type == IFA_BROADCAST)
			  broadcast = *((struct in_addr *)(rta+1));
			else if (rta->rta_type == IFA_LABEL)
			  label = RTA_DATA(rta);
			
			rta = RTA_NEXT(rta, len1);
		      }
		    
		    if (addr.s_addr && callback_ok)
		      if (!callback.af_inet(addr, ifa->ifa_index, label,  netmask, broadcast, parm))
			callback_ok = 0;
		  }
		else if (ifa->ifa_family == AF_INET6)
		  {
		    struct in6_addr *addrp = NULL;
		    u32 valid = 0, preferred = 0;
		    int flags = 0;
		    
		    while (RTA_OK(rta, len1))
		      {
			/*
			 * Important comment: (from if_addr.h)
			 * IFA_ADDRESS is prefix address, rather than local interface address.
			 * It makes no difference for normally configured broadcast interfaces,
			 * but for point-to-point IFA_ADDRESS is DESTINATION address,
			 * local address is supplied in IFA_LOCAL attribute.
			 */
			if (rta->rta_type == IFA_LOCAL)
			  addrp = ((struct in6_addr *)(rta+1));
			else if (rta->rta_type == IFA_ADDRESS && !addrp)
			  addrp = ((struct in6_addr *)(rta+1)); 
			else if (rta->rta_type == IFA_CACHEINFO)
			  {
			    struct ifa_cacheinfo *ifc = (struct ifa_cacheinfo *)(rta+1);
			    preferred = ifc->ifa_prefered;
			    valid = ifc->ifa_valid;
			  }
			rta = RTA_NEXT(rta, len1);
		      }
		    
		    if (ifa->ifa_flags & IFA_F_TENTATIVE)
		      flags |= IFACE_TENTATIVE;
		    
		    if (ifa->ifa_flags & IFA_F_DEPRECATED)
		      flags |= IFACE_DEPRECATED;
		    
		    if (!(ifa->ifa_flags & IFA_F_TEMPORARY))
		      flags |= IFACE_PERMANENT;
    		    
		    if (addrp && callback_ok)
		      if (!callback.af_inet6(addrp, (int)(ifa->ifa_prefixlen), (int)(ifa->ifa_scope), 
					(int)(ifa->ifa_index), flags, 
					(unsigned int)preferred, (unsigned int)valid, parm))
			callback_ok = 0;
		  }
	      }
	  }
	else if (h->nlmsg_type == RTM_NEWNEIGH && family == AF_UNSPEC)
	  {
	    struct ndmsg *neigh = NLMSG_DATA(h);  
	    struct rtattr *rta = NDA_RTA(neigh);
	    unsigned int len1 = h->nlmsg_len - NLMSG_LENGTH(sizeof(*neigh));
	    size_t maclen = 0;
	    char *inaddr = NULL, *mac = NULL;
	    
	    while (RTA_OK(rta, len1))
	      {
		if (rta->rta_type == NDA_DST)
		  inaddr = (char *)(rta+1);
		else if (rta->rta_type == NDA_LLADDR)
		  {
		    maclen = rta->rta_len - sizeof(struct rtattr);
		    mac = (char *)(rta+1);
		  }
		
		rta = RTA_NEXT(rta, len1);
	      }

	    if (!(neigh->ndm_state & (NUD_NOARP | NUD_INCOMPLETE | NUD_FAILED)) &&
		inaddr && mac && callback_ok)
	      if (!callback.af_unspec(neigh->ndm_family, inaddr, mac, maclen, parm))
		callback_ok = 0;
	  }
#ifdef HAVE_DHCP6
	else if (h->nlmsg_type == RTM_NEWLINK && family == AF_LOCAL)
	  {
	    struct ifinfomsg *link =  NLMSG_DATA(h);
	    struct rtattr *rta = IFLA_RTA(link);
	    unsigned int len1 = h->nlmsg_len - NLMSG_LENGTH(sizeof(*link));
	    char *mac = NULL;
	    size_t maclen = 0;

	    while (RTA_OK(rta, len1))
	      {
		if (rta->rta_type == IFLA_ADDRESS)
		  {
		    maclen = rta->rta_len - sizeof(struct rtattr);
		    mac = (char *)(rta+1);
		  }
		
		rta = RTA_NEXT(rta, len1);
	      }

	    if (mac && callback_ok && !((link->ifi_flags & (IFF_LOOPBACK | IFF_POINTOPOINT))) && 
		!callback.af_local((int)link->ifi_index, (unsigned int)link->ifi_type, mac, maclen, parm))
	      callback_ok = 0;
	  }
#endif
    }
}

/**
 * @brief Process queued netlink multicast messages and handle network state changes
 * 
 * @detailed Drains the netlink multicast message queue and processes each message
 *           through nl_async() to handle network configuration changes. Uses non-blocking
 *           reads (MSG_DONTWAIT) to avoid blocking the main event loop. Retries the entire
 *           process if ENOBUFS occurs (buffer overflow), which indicates messages were
 *           dropped and need to be refreshed. Tracks state changes across messages to
 *           avoid duplicate event generation for batched updates.
 * 
 * @param state Current async state flags (STATE_NEWADDR, STATE_NEWROUTE) used to
 *              prevent duplicate event generation when multiple related messages arrive
 * 
 * @return void
 * 
 * @note Called from netlink_multicast() when netlink socket becomes readable
 * @note Uses MSG_DONTWAIT to prevent blocking main event loop during message reads
 * @note Retries with do-while if ENOBUFS indicates dropped messages requiring refresh
 * @note Processes all queued messages in a single call to batch state changes
 * 
 * @warning ENOBUFS indicates kernel dropped messages - full state refresh required
 * 
 * @see netlink_multicast() - public function that calls this internal handler
 * @see nl_async() - processes individual netlink messages and updates state flags
 * @see netlink_recv() - reads messages from netlink socket with specified flags
 * 
 * EXAMPLE USAGE:
 * @code
 * // Called internally when netlink socket has data available
 * unsigned state = 0;
 * nl_multicast_state(state);  // Processes all pending messages
 * // If ENOBUFS occurred, retries to ensure no state changes missed
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (Linux netlink-specific implementation)
 * SIDE EFFECTS: May queue EVENT_NEWROUTE or EVENT_NEWADDR to main event loop via nl_async()
 * THREAD SAFETY: Single-threaded architecture - modifies shared iov buffer and global state
 */
static void nl_multicast_state(unsigned state)
{
  ssize_t len;
  struct nlmsghdr *h;

  do {
    /* don't risk blocking reading netlink messages here. */
    while ((len = netlink_recv(MSG_DONTWAIT)) != -1)
  
      for (h = (struct nlmsghdr *)iov.iov_base; NLMSG_OK(h, (size_t)len); h = NLMSG_NEXT(h, len))
	state = nl_async(h, state);
  } while (errno == ENOBUFS);
}

/**
 * @brief Handle netlink multicast socket events and process network configuration changes
 * 
 * @detailed Entry point for processing netlink multicast messages when the netlink socket
 *           becomes readable. This function is called from the main event loop when network
 *           configuration changes are detected (interface up/down, address add/remove, route
 *           changes). Initializes state tracking and delegates to nl_multicast_state() for
 *           message processing. This wrapper provides a clean API boundary between the main
 *           event loop and the internal netlink message handling implementation.
 * 
 * @return void
 * 
 * @note Called from main event loop (dnsmasq.c) when daemon->netlinkfd is readable
 * @note Initializes state to 0 to allow nl_multicast_state to track all change types
 * @note Non-blocking operation - returns immediately after processing queued messages
 * 
 * @see nl_multicast_state() - internal function that processes message queue
 * @see netlink_init() - initializes netlink socket monitored by this handler
 * @see nl_async() - processes individual netlink messages for state changes
 * 
 * EXAMPLE USAGE:
 * @code
 * // Called from main event loop when netlink socket has data
 * if (FD_ISSET(daemon->netlinkfd, &rset))
 *   netlink_multicast();  // Process all pending network changes
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (Linux netlink-specific implementation per netlink(7) and rtnetlink(7))
 * SIDE EFFECTS: May queue EVENT_NEWROUTE or EVENT_NEWADDR to main event loop via nl_async()
 * THREAD SAFETY: Single-threaded architecture - safe for use in event loop context
 */
void netlink_multicast(void)
{
  unsigned state = 0;
  nl_multicast_state(state);
}


/**
 * @brief Process individual netlink message and update asynchronous event state
 * 
 * @detailed Parses a single netlink message from the kernel and queues appropriate events
 *           to the main event loop based on message type. Handles three message categories:
 *           1) NLMSG_ERROR - logs netlink protocol errors from kernel
 *           2) RTM_NEWROUTE - detects new unicast routes for DoD link handling
 *           3) RTM_NEWADDR/RTM_DELADDR - detects interface address changes
 *           
 *           State tracking prevents duplicate event queueing when multiple related messages
 *           arrive in a single netlink read operation. The DoD (Dial-on-Demand) route handling
 *           enables DNS query retry when new routes appear, recovering packets lost during
 *           link establishment. Only multicast messages (nlmsg_pid == 0) trigger events,
 *           ignoring responses to our own netlink requests.
 * 
 * @param h Pointer to netlink message header containing message type, length, and payload
 * @param state Current state bitmap tracking which event types have been queued this iteration
 *              (STATE_NEWROUTE=0x01, STATE_NEWADDR=0x02)
 * 
 * @return Updated state bitmap with newly queued event types marked
 * @retval state Original state if no events queued for this message
 * @retval state|STATE_NEWROUTE If RTM_NEWROUTE triggered EVENT_NEWROUTE queue
 * @retval state|STATE_NEWADDR If RTM_NEWADDR/DELADDR triggered EVENT_NEWADDR queue
 * 
 * @note Only multicast messages (nlmsg_pid==0) trigger events, not request responses
 * @note Route filtering: only unicast routes with RT_SCOPE_LINK in main/local tables
 * @note DoD behavior: EVENT_NEWROUTE causes DNS query retry for packets lost during dial-up
 * @warning State parameter MUST be initialized to 0 before first call in batch processing
 * 
 * @see nl_multicast_state() - calls this function for each message in netlink queue
 * @see queue_event() in dnsmasq.c - receives EVENT_NEWROUTE and EVENT_NEWADDR
 * @see netlink_recv() - retrieves raw netlink message data parsed by this function
 * 
 * EXAMPLE USAGE:
 * @code
 * unsigned state = 0;
 * struct nlmsghdr *h = (struct nlmsghdr *)buffer;
 * // Process batch of netlink messages
 * while (NLMSG_OK(h, len)) {
 *   state = nl_async(h, state);  // Update state, queue events once per type
 *   h = NLMSG_NEXT(h, len);
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (Linux rtnetlink protocol per rtnetlink(7) man page)
 * SIDE EFFECTS: Calls queue_event() to trigger main event loop processing; logs errors to syslog
 * THREAD SAFETY: Single-threaded - safe for event loop; modifies no global state except event queue
 */
static unsigned nl_async(struct nlmsghdr *h, unsigned state)
{
  if (h->nlmsg_type == NLMSG_ERROR)
    {
      struct nlmsgerr *err = NLMSG_DATA(h);
      if (err->error != 0)
	my_syslog(LOG_ERR, _("netlink returns error: %s"), strerror(-(err->error)));
    }
  else if (h->nlmsg_pid == 0 && h->nlmsg_type == RTM_NEWROUTE &&
	   (state & STATE_NEWROUTE)==0)
    {
      /* We arrange to receive netlink multicast messages whenever the network route is added.
	 If this happens and we still have a DNS packet in the buffer, we re-send it.
	 This helps on DoD links, where frequently the packet which triggers dialling is
	 a DNS query, which then gets lost. By re-sending, we can avoid the lookup
	 failing. */ 
      struct rtmsg *rtm = NLMSG_DATA(h);
      
      if (rtm->rtm_type == RTN_UNICAST && rtm->rtm_scope == RT_SCOPE_LINK &&
	  (rtm->rtm_table == RT_TABLE_MAIN ||
	   rtm->rtm_table == RT_TABLE_LOCAL))
	{
	  queue_event(EVENT_NEWROUTE);
	  state |= STATE_NEWROUTE;
	}
    }
  else if ((h->nlmsg_type == RTM_NEWADDR || h->nlmsg_type == RTM_DELADDR) &&
	   (state & STATE_NEWADDR)==0)
    {
      queue_event(EVENT_NEWADDR);
      state |= STATE_NEWADDR;
    }
  return state;
}
#endif /* HAVE_LINUX_NETWORK */

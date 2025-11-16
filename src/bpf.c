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
 * @file bpf.c
 * @brief BSD/Solaris Berkeley Packet Filter (BPF) interface for raw packet access and routing socket monitoring
 * 
 * DETAILED PURPOSE:
 * This module provides BSD and Solaris-specific network interface implementations using the
 * Berkeley Packet Filter (BPF) for raw packet transmission and PF_ROUTE sockets for network
 * interface change detection. This is the BSD/Solaris counterpart to the Linux netlink
 * implementation in netlink.c.
 * 
 * The BPF interface allows dnsmasq to bypass the kernel's IP stack for DHCP packet transmission,
 * which is essential for sending DHCP replies before a client has a valid IP address. The routing
 * socket (PF_ROUTE) provides real-time notification of network interface state changes including
 * address additions and deletions.
 * 
 * KEY RESPONSIBILITIES:
 * - ARP table enumeration via sysctl (arp_enumerate) on BSD systems excluding macOS
 * - Network interface enumeration (iface_enumerate) supporting IPv4, IPv6, and link-layer addresses
 * - BPF device initialization and configuration (init_bpf)
 * - Raw DHCP packet transmission via BPF (send_via_bpf) bypassing kernel IP stack
 * - Routing socket initialization (route_init) for monitoring interface changes
 * - Routing message processing (route_sock) for address addition/deletion events
 * 
 * DEPENDENCIES:
 * Includes: dnsmasq.h (core structures), ifaddrs.h (interface enumeration), sys/param.h,
 *           sys/sysctl.h (BSD), net/if.h, net/route.h (routing socket), net/if_dl.h (datalink),
 *           netinet/if_ether.h, netinet/in_var.h, netinet6/in6_var.h
 * Called by: network.c (for interface operations), dhcp.c (for packet transmission)
 * Calls: System calls (sysctl, socket, ioctl, open, read, write), utility functions in util.c
 * 
 * DATA STRUCTURES:
 * - struct rt_msghdr: Routing message header (lines 91, 414)
 * - struct sockaddr_inarp: ARP socket address (line 92)
 * - struct sockaddr_dl: Datalink socket address (lines 93, 178, etc.)
 * - struct ifreq: Interface request structure (lines 254-256)
 * - struct bpf_insn: BPF instruction (line 285)
 * - struct bpf_program: BPF program (line 286)
 * - struct ifa_msghdr: Interface address message (lines 406, 426)
 * 
 * COMPILE-TIME OPTIONS:
 * - HAVE_BSD_NETWORK: Enables BSD-specific BPF and routing socket implementation
 * - HAVE_SOLARIS_NETWORK: Enables Solaris-specific variant of BSD networking
 * - HAVE_DHCP: Required for send_via_bpf functionality
 * - __APPLE__: Excludes certain BSD features (e.g., sysctl-based ARP enumeration)
 * - __FreeBSD__: Includes FreeBSD-specific headers (net/if_var.h)
 * - RTF_LLINFO: Legacy routing flag for ARP entries (pre-BSD modernization)
 * 
 * THREADING/CONCURRENCY:
 * Single-threaded event-driven model. The route_sock function is called from the main event
 * loop when the routing socket becomes readable. BPF operations are synchronous and blocking
 * within the single-threaded context.
 * 
 * PLATFORM DIFFERENCES FROM LINUX:
 * Linux uses netlink sockets (NETLINK_ROUTE) for interface monitoring and raw sockets for
 * packet injection. BSD uses PF_ROUTE sockets for interface monitoring and BPF character
 * devices (/dev/bpf) for raw packet access. The routing message formats (struct rt_msghdr,
 * struct ifa_msghdr) are BSD-specific and differ significantly from netlink messages.
 * 
 * @copyright Copyright (c) 2000-2025 Simon Kelley
 * @license GPL-2.0-or-later
 * 
 * @see bpf(4) BSD manual page for Berkeley Packet Filter device interface
 * @see route(4) BSD manual page for routing socket protocol
 * @see netlink.c Linux netlink implementation providing equivalent functionality
 */

#include "dnsmasq.h"

#if defined(HAVE_BSD_NETWORK) || defined(HAVE_SOLARIS_NETWORK)
#include <ifaddrs.h>

#include <sys/param.h>
#if defined(HAVE_BSD_NETWORK) && !defined(__APPLE__)
#include <sys/sysctl.h>
#endif
#include <net/if.h>
#include <net/route.h>
#include <net/if_dl.h>
#include <netinet/if_ether.h>
#if defined(__FreeBSD__)
#  include <net/if_var.h> 
#endif
#include <netinet/in_var.h>
#include <netinet6/in6_var.h>

#ifndef SA_SIZE
#define SA_SIZE(sa)                                             \
    (  (!(sa) || ((struct sockaddr *)(sa))->sa_len == 0) ?      \
        sizeof(long)            :                               \
        1 + ( (((struct sockaddr *)(sa))->sa_len - 1) | (sizeof(long) - 1) ) )
#endif

#ifdef HAVE_BSD_NETWORK
static int del_family = 0;
static union all_addr del_addr;
#endif

#if defined(HAVE_BSD_NETWORK) && !defined(__APPLE__)

/**
 * @brief Enumerate ARP table entries via sysctl on BSD systems
 * 
 * @detailed Retrieves the kernel ARP cache table using the BSD sysctl interface and invokes
 * a callback function for each ARP entry. This function queries the routing table with
 * NET_RT_FLAGS filter to obtain link-layer information (MAC addresses) associated with
 * IPv4 addresses. The implementation uses a dynamic buffer that expands as needed to
 * accommodate the ARP table size.
 * 
 * This function is BSD-specific and excluded on macOS (__APPLE__) where different APIs
 * are used for ARP table access. The sysctl MIB path CTL_NET.PF_ROUTE.0.AF_INET.NET_RT_FLAGS
 * with RTF_LLINFO flag retrieves ARP entries.
 * 
 * @param parm User-defined parameter passed through to callback function (typically context pointer)
 * @param callback Callback function of type callback_t that receives address family (AF_INET),
 *                 IP address (struct in_addr*), MAC address (unsigned char*), MAC length, and parm
 * 
 * @return 1 on success (all entries enumerated), 0 on failure (sysctl error, memory allocation failure,
 *         or callback returned 0 indicating enumeration should stop)
 * 
 * @note macOS/Darwin systems do not support this sysctl-based ARP enumeration and use alternative APIs
 * @warning The RTF_LLINFO flag is deprecated on modern BSD systems; newer systems may require
 *          alternative approaches for ARP table enumeration
 * 
 * @see arp(8) BSD manual for ARP table management
 * @see sysctl(3) BSD manual for kernel state query interface
 * @see route(4) BSD manual for routing socket message formats
 * 
 * EXAMPLE USAGE:
 * @code
 * int arp_callback(int af, union all_addr *addr, unsigned char *hwaddr, size_t len, void *ctx) {
 *   // Process ARP entry: addr contains IPv4 address, hwaddr contains MAC address
 *   return 1; // Continue enumeration
 * }
 * struct context *ctx = ...;
 * if (!arp_enumerate(ctx, arp_callback)) {
 *   // Handle enumeration failure
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (platform-specific system interface)
 * SIDE EFFECTS: Allocates dynamic memory via expand_buf(), memory freed by caller's buffer management
 * THREAD SAFETY: Not thread-safe (uses static sysctl interface and modifies iovec buffer)
 */
int arp_enumerate(void *parm, callback_t callback)
{
  int mib[6];
  size_t needed;
  char *next;
  struct rt_msghdr *rtm;
  struct sockaddr_inarp *sin2;
  struct sockaddr_dl *sdl;
  struct iovec buff;
  int rc;

  buff.iov_base = NULL;
  buff.iov_len = 0;

  mib[0] = CTL_NET;
  mib[1] = PF_ROUTE;
  mib[2] = 0;
  mib[3] = AF_INET;
  mib[4] = NET_RT_FLAGS;
#ifdef RTF_LLINFO
  mib[5] = RTF_LLINFO;
#else
  mib[5] = 0;
#endif	
  if (sysctl(mib, 6, NULL, &needed, NULL, 0) == -1 || needed == 0)
    return 0;

  while (1) 
    {
      if (!expand_buf(&buff, needed))
	return 0;
      if ((rc = sysctl(mib, 6, buff.iov_base, &needed, NULL, 0)) == 0 ||
	  errno != ENOMEM)
	break;
      needed += needed / 8;
    }
  if (rc == -1)
    return 0;
  
  for (next = buff.iov_base ; next < (char *)buff.iov_base + needed; next += rtm->rtm_msglen)
    {
      rtm = (struct rt_msghdr *)next;
      sin2 = (struct sockaddr_inarp *)(rtm + 1);
      sdl = (struct sockaddr_dl *)((char *)sin2 + SA_SIZE(sin2));
      if (!callback.af_unspec(AF_INET, &sin2->sin_addr, LLADDR(sdl), sdl->sdl_alen, parm))
	return 0;
    }

  return 1;
}
#endif /* defined(HAVE_BSD_NETWORK) && !defined(__APPLE__) */


/**
 * @brief Enumerate network interface addresses for specified address family
 * 
 * @detailed Enumerates all network interface addresses matching the specified address family
 * and invokes a callback function for each address. This function provides a unified interface
 * enumeration API across IPv4, IPv6, and link-layer (MAC) addresses using the BSD getifaddrs(3)
 * system call.
 * 
 * For AF_UNSPEC (hardware/ARP addresses), the function delegates to arp_enumerate on BSD systems
 * excluding macOS. For AF_LOCAL (mapped to AF_LINK internally), the function enumerates link-layer
 * addresses (MAC addresses). For AF_INET and AF_INET6, the function enumerates network-layer
 * addresses with associated netmasks and metrics.
 * 
 * On BSD systems excluding macOS, IPv6 addresses receive extended metadata including tentative,
 * deprecated, and permanent flags via SIOCGIFAFLAG_IN6 ioctl, plus valid and preferred lifetimes
 * via SIOCGIFALIFETIME_IN6 ioctl. Link-local IPv6 addresses have interface identifiers cleared
 * when not in wild mode.
 * 
 * The function maintains a deletion filter (del_family, del_addr) on BSD to skip addresses that
 * were recently deleted but may still appear in getifaddrs results due to timing issues.
 * 
 * @param family Address family to enumerate: AF_UNSPEC (ARP/hardware), AF_LOCAL (link-layer),
 *               AF_INET (IPv4), or AF_INET6 (IPv6). AF_LOCAL is internally converted to AF_LINK.
 * @param parm User-defined parameter passed through to callback function (typically context pointer)
 * @param callback Callback function union of type callback_t with family-specific function pointers:
 *                 - callback.af_unspec for AF_UNSPEC (AF, address, MAC, MAC length, parm)
 *                 - callback.af_inet for AF_INET (address, iface_index, NULL, netmask, broadcast, parm)
 *                 - callback.af_inet6 for AF_INET6 (address, prefix, scope_id, iface_index, flags, preferred, valid, parm)
 *                 - callback.af_local for AF_LINK (iface_index, ARPHRD_ETHER, MAC, MAC length, parm)
 * 
 * @return 1 on success (all interfaces enumerated), 0 on failure (getifaddrs error, socket error,
 *         or callback returned 0 indicating enumeration should stop)
 * 
 * @note AF_LOCAL is a Linux compatibility alias; internally converted to BSD AF_LINK
 * @note macOS does not support sysctl-based ARP enumeration (AF_UNSPEC returns 0)
 * @note Solaris support for AF_UNSPEC is not implemented (returns 0)
 * @warning Link-local IPv6 addresses have interface identifiers zeroed unless OPT_NOWILD is set
 * @warning The del_family/del_addr filter may cause recently deleted addresses to be skipped
 * 
 * @see getifaddrs(3) BSD manual for interface address enumeration
 * @see if_nametoindex(3) BSD manual for interface name to index conversion
 * @see ioctl(2) with SIOCGIFAFLAG_IN6 and SIOCGIFALIFETIME_IN6 for IPv6 metadata
 * @see netlink.c Linux equivalent using netlink sockets
 * 
 * EXAMPLE USAGE:
 * @code
 * int inet_callback(struct in_addr addr, int index, struct in_addr *a2, 
 *                   struct in_addr netmask, struct in_addr broadcast, void *ctx) {
 *   // Process IPv4 address: addr, netmask, broadcast
 *   return 1; // Continue enumeration
 * }
 * callback_t cb = { .af_inet = inet_callback };
 * if (!iface_enumerate(AF_INET, context, cb)) {
 *   // Handle enumeration failure
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (platform-specific system interface)
 * SIDE EFFECTS: Opens and closes IPv6 socket for metadata retrieval on BSD (non-Apple);
 *               allocates and frees interface address list via getifaddrs/freeifaddrs
 * THREAD SAFETY: Not thread-safe (uses static del_family/del_addr variables on BSD)
 */
int iface_enumerate(int family, void *parm, callback_t callback)
{
  struct ifaddrs *head, *addrs;
  int errsave, fd = -1, ret = 0;

  if (family == AF_UNSPEC)
#if defined(HAVE_BSD_NETWORK) && !defined(__APPLE__)
    return  arp_enumerate(parm, callback);
#else
  return 0; /* need code for Solaris and MacOS*/
#endif

  /* AF_LINK doesn't exist in Linux, so we can't use it in our API */
  if (family == AF_LOCAL)
    family = AF_LINK;

  if (getifaddrs(&head) == -1)
    return 0;

#if defined(HAVE_BSD_NETWORK)
  if (family == AF_INET6)
    fd = socket(PF_INET6, SOCK_DGRAM, 0);
#endif
  
  for (addrs = head; addrs; addrs = addrs->ifa_next)
    {
      int iface_index = if_nametoindex(addrs->ifa_name);
      
      if (iface_index == 0 || !addrs->ifa_addr || 
	  addrs->ifa_addr->sa_family != family ||
	  (!addrs->ifa_netmask && family != AF_LINK))
	continue;
      
      if (family == AF_INET)
	{
	  struct in_addr addr, netmask, broadcast;
	  addr = ((struct sockaddr_in *) addrs->ifa_addr)->sin_addr;
#ifdef HAVE_BSD_NETWORK
	  if (del_family == AF_INET && del_addr.addr4.s_addr == addr.s_addr)
	    continue;
#endif
	  netmask = ((struct sockaddr_in *) addrs->ifa_netmask)->sin_addr;
	  if (addrs->ifa_broadaddr)
	    broadcast = ((struct sockaddr_in *) addrs->ifa_broadaddr)->sin_addr; 
	  else 
	    broadcast.s_addr = 0;	      
	  if (!callback.af_inet(addr, iface_index, NULL, netmask, broadcast, parm))
	    goto err;
	}
      else if (family == AF_INET6)
	{
	  struct in6_addr *addr = &((struct sockaddr_in6 *) addrs->ifa_addr)->sin6_addr;
	  unsigned char *netmask = (unsigned char *) &((struct sockaddr_in6 *) addrs->ifa_netmask)->sin6_addr;
	  int scope_id = ((struct sockaddr_in6 *) addrs->ifa_addr)->sin6_scope_id;
	  int i, j, prefix = 0;
	  u32 valid = 0xffffffff, preferred = 0xffffffff;
	  int flags = 0;
#ifdef HAVE_BSD_NETWORK
	  if (del_family == AF_INET6 && IN6_ARE_ADDR_EQUAL(&del_addr.addr6, addr))
	    continue;
#endif
#if defined(HAVE_BSD_NETWORK) && !defined(__APPLE__)
	  struct in6_ifreq ifr6;
	  
	  memset(&ifr6, 0, sizeof(ifr6));
	  safe_strncpy(ifr6.ifr_name, addrs->ifa_name, sizeof(ifr6.ifr_name));
	  
	  ifr6.ifr_addr = *((struct sockaddr_in6 *) addrs->ifa_addr);
	  if (fd != -1 && ioctl(fd, SIOCGIFAFLAG_IN6, &ifr6) != -1)
	    {
	      if (ifr6.ifr_ifru.ifru_flags6 & IN6_IFF_TENTATIVE)
		flags |= IFACE_TENTATIVE;
	      
	      if (ifr6.ifr_ifru.ifru_flags6 & IN6_IFF_DEPRECATED)
		flags |= IFACE_DEPRECATED;
	      
#ifdef IN6_IFF_TEMPORARY
	      if (!(ifr6.ifr_ifru.ifru_flags6 & (IN6_IFF_AUTOCONF | IN6_IFF_TEMPORARY)))
		flags |= IFACE_PERMANENT;
#endif
	      
#ifdef IN6_IFF_PRIVACY
	      if (!(ifr6.ifr_ifru.ifru_flags6 & (IN6_IFF_AUTOCONF | IN6_IFF_PRIVACY)))
		flags |= IFACE_PERMANENT;
#endif
	    }
	  
	  ifr6.ifr_addr = *((struct sockaddr_in6 *) addrs->ifa_addr);
	  if (fd != -1 && ioctl(fd, SIOCGIFALIFETIME_IN6, &ifr6) != -1)
	    {
	      valid = ifr6.ifr_ifru.ifru_lifetime.ia6t_vltime;
	      preferred = ifr6.ifr_ifru.ifru_lifetime.ia6t_pltime;
	    }
#endif
	  
	  for (i = 0; i < IN6ADDRSZ; i++, prefix += 8) 
	    if (netmask[i] != 0xff)
	      break;
	  
	  if (i != IN6ADDRSZ && netmask[i]) 
	    for (j = 7; j > 0; j--, prefix++) 
	      if ((netmask[i] & (1 << j)) == 0)
		break;
	  
	  /* voodoo to clear interface field in address */
	  if (!option_bool(OPT_NOWILD) && IN6_IS_ADDR_LINKLOCAL(addr))
	    {
	      addr->s6_addr[2] = 0;
	      addr->s6_addr[3] = 0;
	    } 
	  
	  if (!callback.af_inet6(addr, prefix, scope_id, iface_index, flags,
				 (unsigned int) preferred, (unsigned int)valid, parm))
	    goto err;	      
	}
      
#ifdef HAVE_DHCP6      
      else if (family == AF_LINK)
	{ 
	  /* Assume ethernet again here */
	  struct sockaddr_dl *sdl = (struct sockaddr_dl *) addrs->ifa_addr;
	  if (sdl->sdl_alen != 0 && 
	      !callback.af_local(iface_index, ARPHRD_ETHER, LLADDR(sdl), sdl->sdl_alen, parm))
	    goto err;
	}
#endif 
    }
  
  ret = 1;
  
 err:
  errsave = errno;
  freeifaddrs(head); 
  if (fd != -1)
    close(fd);
  errno = errsave;

  return ret;
}
#endif /* defined(HAVE_BSD_NETWORK) || defined(HAVE_SOLARIS_NETWORK) */


#if defined(HAVE_BSD_NETWORK) && defined(HAVE_DHCP)
#include <net/bpf.h>

/**
 * @brief Initialize Berkeley Packet Filter (BPF) device for DHCP raw packet transmission
 * 
 * @detailed Opens a BPF character device (/dev/bpf0, /dev/bpf1, ...) for raw packet I/O
 * required for DHCP server operations. BSD systems provide BPF as a cloning device where
 * each open of any /dev/bpfN creates a new instance. This function iterates through BPF
 * device nodes until it finds an available one.
 * 
 * BPF is required for DHCP because DHCP servers must send replies to clients that do not
 * yet have valid IP addresses. This requires constructing complete Ethernet frames with
 * manually built IP and UDP headers, bypassing the kernel's network stack. The opened
 * BPF descriptor is stored in daemon->dhcp_raw_fd for subsequent use by send_via_bpf().
 * 
 * The function tries /dev/bpf0, /dev/bpf1, /dev/bpf2, etc. in sequence until it successfully
 * opens a device. On failure (all devices busy or permission denied), the daemon terminates
 * with EC_BADNET error code.
 * 
 * @param None (uses global daemon structure)
 * 
 * @return None (void function; terminates process on fatal error via die())
 * @retval void On success, daemon->dhcp_raw_fd contains the BPF file descriptor
 * @retval <never> On failure, calls die() with EC_BADNET error code
 * 
 * @note This function must be called after privilege separation but before dropping root
 *       privileges, as /dev/bpf devices typically require root access
 * @warning Uses daemon->dhcp_buff as temporary buffer for constructing device paths
 * @warning Calling this function multiple times leaks the previous BPF file descriptor
 * 
 * @see send_via_bpf() Function that uses the opened BPF descriptor to transmit packets
 * @see bpf(4) BSD manual page for Berkeley Packet Filter device interface
 * @see dhcp.c DHCP server implementation that calls init_bpf() during initialization
 * 
 * EXAMPLE USAGE:
 * @code
 * // Called from daemon initialization (dnsmasq.c)
 * if (daemon->dhcp) {
 *   init_bpf();  // Opens /dev/bpf* for DHCP raw packet transmission
 *   // daemon->dhcp_raw_fd now contains valid BPF descriptor
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (platform-specific system interface for RFC 2131 DHCP implementation)
 * SIDE EFFECTS: Opens BPF character device file descriptor stored in daemon->dhcp_raw_fd;
 *               may terminate process via die() on fatal error (no available BPF devices)
 * THREAD SAFETY: Not thread-safe (modifies global daemon structure, uses daemon->dhcp_buff)
 */
void init_bpf(void)
{
  int i = 0;

  while (1) 
    {
      sprintf(daemon->dhcp_buff, "/dev/bpf%d", i++);
      if ((daemon->dhcp_raw_fd = open(daemon->dhcp_buff, O_RDWR, 0)) != -1)
	return;

      if (errno != EBUSY)
	die(_("cannot create DHCP BPF socket: %s"), NULL, EC_BADNET);
    }	     
}

/**
 * @brief Send DHCP packet via Berkeley Packet Filter bypassing kernel IP stack
 * 
 * @detailed Constructs and transmits a complete Ethernet frame containing IP and UDP headers
 * plus the DHCP payload, using the BPF raw packet interface. This low-level transmission is
 * required for DHCP server operations because DHCP clients often do not yet have configured
 * IP addresses and cannot respond to ARP requests, making normal socket-based transmission
 * impossible.
 * 
 * The function manually builds three protocol layers:
 * 1. Ethernet header: Sets source MAC (from interface), destination MAC (from DHCP chaddr or
 *    broadcast FF:FF:FF:FF:FF:FF), and EtherType (0x0800 for IPv4)
 * 2. IP header: Constructs IPv4 header with source address (server interface), destination
 *    (client yiaddr or broadcast), protocol UDP (17), TTL (64), and manually calculated
 *    IP header checksum
 * 3. UDP header: Sets source port (67), destination port (68), length, and manually calculated
 *    UDP checksum covering pseudo-header, UDP header, and DHCP payload
 * 
 * The DHCP packet broadcast flag (0x8000 in mess->flags) determines destination: if set,
 * packet is broadcast to Ethernet FF:FF:FF:FF:FF:FF and IP 255.255.255.255; if clear,
 * packet is unicast to client hardware address (mess->chaddr) and IP address (mess->yiaddr).
 * 
 * Checksum calculations follow RFC 1071 (Internet checksum) with 16-bit one's complement
 * arithmetic. UDP checksum includes IP pseudo-header (source IP, dest IP, protocol, UDP length)
 * as required by RFC 768.
 * 
 * @param mess Pointer to DHCP packet structure containing payload to transmit; must have
 *             valid htype (ARPHRD_ETHER=1), hlen (6 bytes), chaddr (client MAC), yiaddr
 *             (assigned IP), and flags (broadcast bit). Must not be NULL.
 * @param len Size of DHCP packet payload in bytes; must be >0 and ≤ MTU-42 (MTU minus
 *            Ethernet(14) + IP(20) + UDP(8) headers)
 * @param iface_addr Source IP address for IP header; typically the DHCP server's address
 *                   on the interface specified by ifr parameter
 * @param ifr Pointer to ifreq structure identifying the network interface for transmission;
 *            ifr_name must be valid interface name. Used both to retrieve source MAC address
 *            via SIOCGIFADDR ioctl and to bind BPF descriptor via BIOCSETIF ioctl. Must not
 *            be NULL.
 * 
 * @return None (void function)
 * @retval void On success, packet transmitted via BPF; on error, silently returns
 * 
 * @note Only supports Ethernet hardware type (ARPHRD_ETHER); other types logged as warning
 * @note Silently returns on SIOCGIFADDR ioctl failure (cannot retrieve source MAC address)
 * @note Pads DHCP payload to even length for checksum calculation if necessary
 * @warning Modifies mess buffer (last byte) if len is odd for checksum calculation
 * @warning Assumes daemon->dhcp_raw_fd was initialized by init_bpf() and is valid
 * @warning No error checking on BIOCSETIF ioctl or writev system call
 * 
 * @see init_bpf() Initializes BPF descriptor stored in daemon->dhcp_raw_fd
 * @see dhcp.c DHCP server functions that call send_via_bpf() for packet transmission
 * @see bpf(4) BSD manual page for Berkeley Packet Filter interface
 * @see RFC 2131 DHCP protocol specification (broadcast flag handling)
 * @see RFC 768 UDP protocol specification (checksum calculation)
 * @see RFC 1071 Internet checksum computation algorithm
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_packet *packet = ...;  // DHCP OFFER or ACK packet
 * size_t packet_len = sizeof(struct dhcp_packet);
 * struct in_addr server_addr;
 * struct ifreq ifr;
 * 
 * server_addr.s_addr = inet_addr("192.168.1.1");
 * strncpy(ifr.ifr_name, "eth0", IFNAMSIZ);
 * 
 * // Send DHCP reply bypassing kernel IP stack (client has no IP yet)
 * send_via_bpf(packet, packet_len, server_addr, &ifr);
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 2131 Section 4.1 (DHCP broadcast flag handling), RFC 768 (UDP),
 *                 RFC 791 (IPv4), RFC 826 (Ethernet), RFC 1071 (checksums)
 * SIDE EFFECTS: Transmits raw Ethernet frame to network via BPF; modifies ifr structure
 *               (sets sa_family to AF_LINK); may modify last byte of mess if len is odd;
 *               performs multiple ioctl calls on daemon->dhcpfd and daemon->dhcp_raw_fd
 * THREAD SAFETY: Not thread-safe (uses global daemon structure, modifies ifr parameter)
 */
void send_via_bpf(struct dhcp_packet *mess, size_t len,
		  struct in_addr iface_addr, struct ifreq *ifr)
{
   /* Hairy stuff, packet either has to go to the
      net broadcast or the destination can't reply to ARP yet,
      but we do know the physical address. 
      Build the packet by steam, and send directly, bypassing
      the kernel IP stack */
  
  struct ether_header ether; 
  struct ip ip;
  struct udphdr {
    u16 uh_sport;               /* source port */
    u16 uh_dport;               /* destination port */
    u16 uh_ulen;                /* udp length */
    u16 uh_sum;                 /* udp checksum */
  } udp;
  
  u32 i, sum;
  struct iovec iov[4];

  /* Only know how to do ethernet on *BSD */
  if (mess->htype != ARPHRD_ETHER || mess->hlen != ETHER_ADDR_LEN)
    {
      my_syslog(MS_DHCP | LOG_WARNING, _("DHCP request for unsupported hardware type (%d) received on %s"), 
		mess->htype, ifr->ifr_name);
      return;
    }
   
  ifr->ifr_addr.sa_family = AF_LINK;
  if (ioctl(daemon->dhcpfd, SIOCGIFADDR, ifr) < 0)
    return;
  
  memcpy(ether.ether_shost, LLADDR((struct sockaddr_dl *)&ifr->ifr_addr), ETHER_ADDR_LEN);
  ether.ether_type = htons(ETHERTYPE_IP);
  
  if (ntohs(mess->flags) & 0x8000)
    {
      memset(ether.ether_dhost, 255,  ETHER_ADDR_LEN);
      ip.ip_dst.s_addr = INADDR_BROADCAST;
    }
  else
    {
      memcpy(ether.ether_dhost, mess->chaddr, ETHER_ADDR_LEN); 
      ip.ip_dst.s_addr = mess->yiaddr.s_addr;
    }
  
  ip.ip_p = IPPROTO_UDP;
  ip.ip_src.s_addr = iface_addr.s_addr;
  ip.ip_len = htons(sizeof(struct ip) + 
		    sizeof(struct udphdr) +
		    len) ;
  ip.ip_hl = sizeof(struct ip) / 4;
  ip.ip_v = IPVERSION;
  ip.ip_tos = 0;
  ip.ip_id = htons(0);
  ip.ip_off = htons(0x4000); /* don't fragment */
  ip.ip_ttl = IPDEFTTL;
  ip.ip_sum = 0;
  for (sum = 0, i = 0; i < sizeof(struct ip) / 2; i++)
    sum += ((u16 *)&ip)[i];
  while (sum>>16)
    sum = (sum & 0xffff) + (sum >> 16);  
  ip.ip_sum = (sum == 0xffff) ? sum : ~sum;
  
  udp.uh_sport = htons(daemon->dhcp_server_port);
  udp.uh_dport = htons(daemon->dhcp_client_port);
  if (len & 1)
    ((char *)mess)[len] = 0; /* for checksum, in case length is odd. */
  udp.uh_sum = 0;
  udp.uh_ulen = sum = htons(sizeof(struct udphdr) + len);
  sum += htons(IPPROTO_UDP);
  sum += ip.ip_src.s_addr & 0xffff;
  sum += (ip.ip_src.s_addr >> 16) & 0xffff;
  sum += ip.ip_dst.s_addr & 0xffff;
  sum += (ip.ip_dst.s_addr >> 16) & 0xffff;
  for (i = 0; i < sizeof(struct udphdr)/2; i++)
    sum += ((u16 *)&udp)[i];
  for (i = 0; i < (len + 1) / 2; i++)
    sum += ((u16 *)mess)[i];
  while (sum>>16)
    sum = (sum & 0xffff) + (sum >> 16);
  udp.uh_sum = (sum == 0xffff) ? sum : ~sum;
  
  ioctl(daemon->dhcp_raw_fd, BIOCSETIF, ifr);
  
  iov[0].iov_base = &ether;
  iov[0].iov_len = sizeof(ether);
  iov[1].iov_base = &ip;
  iov[1].iov_len = sizeof(ip);
  iov[2].iov_base = &udp;
  iov[2].iov_len = sizeof(udp);
  iov[3].iov_base = mess;
  iov[3].iov_len = len;

  while (retry_send(writev(daemon->dhcp_raw_fd, iov, 4)));
}

#endif /* defined(HAVE_BSD_NETWORK) && defined(HAVE_DHCP) */
 

#ifdef HAVE_BSD_NETWORK

/**
 * @brief Initialize PF_ROUTE socket for monitoring network interface changes
 * 
 * @detailed Creates a raw routing socket (PF_ROUTE) to receive asynchronous
 *           notifications of network interface changes including address additions,
 *           address deletions, and interface state changes. The socket is configured
 *           with AF_UNSPEC to receive messages for all address families (IPv4 and IPv6).
 *           This BSD-specific mechanism replaces Linux netlink for interface monitoring.
 * 
 * @note This function is only compiled on BSD platforms (HAVE_BSD_NETWORK defined)
 * @warning Terminates the daemon process if socket creation fails, as interface
 *          monitoring is essential for proper network configuration tracking
 * 
 * @see route_sock() for processing messages received on this socket
 * @see route(4) BSD manual page for PF_ROUTE socket interface details
 * 
 * EXAMPLE USAGE:
 * @code
 * // Called during daemon initialization
 * route_init();  // Creates daemon->routefd for monitoring
 * // Later polled in main event loop via route_sock()
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (BSD-specific system interface)
 * SIDE EFFECTS: 
 * - Creates daemon->routefd socket descriptor
 * - Calls fix_fd() to set FD_CLOEXEC and non-blocking flags
 * - Terminates process via die() if socket creation fails
 * THREAD SAFETY: Single-threaded daemon architecture, called during initialization only
 */
void route_init(void)
{
  /* AF_UNSPEC: all addr families */
  daemon->routefd = socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC);
  
  if (daemon->routefd == -1 || !fix_fd(daemon->routefd))
    die(_("cannot create PF_ROUTE socket: %s"), NULL, EC_BADNET);
}

/**
 * @brief Process routing socket messages for network interface address changes
 * 
 * @detailed Receives and processes messages from the PF_ROUTE socket (daemon->routefd)
 *           to detect network interface address changes. Handles RTM_NEWADDR (address
 *           addition) and RTM_DELADDR (address deletion) messages, queuing EVENT_NEWADDR
 *           to trigger interface re-enumeration in the main event loop. For RTM_DELADDR
 *           messages, extracts and stores the deleted address in static variables
 *           (del_family, del_addr) to work around a kernel race condition where the
 *           deleted address may still appear during immediate interface enumeration.
 * 
 * @note This function is only compiled on BSD platforms (HAVE_BSD_NETWORK defined)
 * @note RTM_DELADDR handling: A race condition exists in the BSD kernel where a
 *       deleted address still appears in interface enumeration immediately after
 *       the DELADDR event. To work around this, the deleted address is stored in
 *       del_family and del_addr static variables, which iface_enumerate() checks
 *       to filter out the stale address from enumeration results
 * @warning Requires daemon->routefd to be initialized by route_init()
 * @warning Protocol version mismatches are logged once via static warned flag
 * 
 * @see route_init() for routing socket creation and initialization
 * @see iface_enumerate() which uses del_family/del_addr to filter deleted addresses
 * @see route(4) BSD manual page for routing socket message format details
 * 
 * EXAMPLE USAGE:
 * @code
 * // Called from main event loop when routefd has pending data
 * // (detected by poll() on daemon->routefd)
 * route_sock();  // Processes routing message and queues event
 * // Main loop will later process EVENT_NEWADDR and call iface_enumerate()
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (BSD-specific system interface)
 * SIDE EFFECTS:
 * - Reads from daemon->routefd routing socket using daemon->packet buffer
 * - Updates del_family and del_addr static variables for RTM_DELADDR messages
 * - Queues EVENT_NEWADDR via queue_event() for main loop processing
 * - Logs warning via my_syslog() if routing message version mismatch detected (once only)
 * - Clears del_family (sets to 0) for RTM_NEWADDR messages
 * THREAD SAFETY: Single-threaded daemon architecture, called from main event loop only
 */
void route_sock(void)
{
  struct if_msghdr *msg;
  int rc = recv(daemon->routefd, daemon->packet, daemon->packet_buff_sz, 0);

  if (rc < 4)
    return;

  msg = (struct if_msghdr *)daemon->packet;
  
  if (rc < msg->ifm_msglen)
    return;

   if (msg->ifm_version != RTM_VERSION)
     {
       static int warned = 0;
       if (!warned)
	 {
	   my_syslog(LOG_WARNING, _("Unknown protocol version from route socket"));
	   warned = 1;
	 }
     }
   else if (msg->ifm_type == RTM_NEWADDR)
     {
       del_family = 0;
       queue_event(EVENT_NEWADDR);
     }
   else if (msg->ifm_type == RTM_DELADDR)
     {
       /* There's a race in the kernel, such that if we run iface_enumerate() immediately
	  we get a DELADDR event, the deleted address still appears. Here we store the deleted address
	  in a static variable, and omit it from the set returned by iface_enumerate() */
       int mask = ((struct ifa_msghdr *)msg)->ifam_addrs;
       int maskvec[] = { RTA_DST, RTA_GATEWAY, RTA_NETMASK, RTA_GENMASK,
			 RTA_IFP, RTA_IFA, RTA_AUTHOR, RTA_BRD };
       int of;
       unsigned int i;
       
       for (i = 0,  of = sizeof(struct ifa_msghdr); of < rc && i < sizeof(maskvec)/sizeof(maskvec[0]); i++) 
	 if (mask & maskvec[i]) 
	   {
	     struct sockaddr *sa = (struct sockaddr *)((char *)msg + of);
	     size_t diff = (sa->sa_len != 0) ? sa->sa_len : sizeof(long);
	     
	     if (maskvec[i] == RTA_IFA)
	       {
		 del_family = sa->sa_family;
		 if (del_family == AF_INET)
		   del_addr.addr4 = ((struct sockaddr_in *)sa)->sin_addr;
		 else if (del_family == AF_INET6)
		   del_addr.addr6 = ((struct sockaddr_in6 *)sa)->sin6_addr;
		 else
		   del_family = 0;
	       }
	     
	     of += diff;
	     /* round up as needed */
	     if (diff & (sizeof(long) - 1)) 
	       of += sizeof(long) - (diff & (sizeof(long) - 1));
	   }
       
       queue_event(EVENT_NEWADDR);
     }
}

#endif /* HAVE_BSD_NETWORK */

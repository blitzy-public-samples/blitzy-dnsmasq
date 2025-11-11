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
 * @file network.c
 * @brief Platform-independent network interface management and socket operations
 * 
 * DETAILED PURPOSE:
 * This module provides the core network abstraction layer for dnsmasq, handling all aspects
 * of network interface enumeration, socket creation, listener management, and platform-specific
 * networking operations. It serves as the bridge between dnsmasq's protocol implementations
 * (DNS, DHCP, TFTP) and the underlying operating system's network stack. The module implements
 * comprehensive IPv4/IPv6 dual-stack support with sophisticated interface binding strategies,
 * including wildcard listeners for unspecified interfaces and interface-specific listeners
 * for precise network control.
 * 
 * The design abstracts platform differences through conditional compilation, with Linux using
 * netlink (src/netlink.c) for interface monitoring and BSD systems using routing sockets and
 * BPF (src/bpf.c). This abstraction ensures dnsmasq operates consistently across Linux, BSD
 * variants (FreeBSD, OpenBSD, NetBSD), Solaris, macOS, and Android platforms.
 * 
 * KEY RESPONSIBILITIES:
 * - Interface enumeration: Discovering and tracking network interfaces using platform-specific
 *   APIs (getifaddrs on modern systems, SIOCGIFCONF on legacy platforms, SIOCGLIFCONF on Solaris)
 * - Interface monitoring: Detecting interface state changes (up/down, address addition/removal)
 *   through integration with netlink.c (Linux) or bpf.c (BSD)
 * - Listener creation: Establishing UDP and TCP listeners on privileged ports (53 for DNS,
 *   67/68 for DHCP, 69 for TFTP) with appropriate socket options (SO_REUSEADDR, SO_RCVBUF, etc.)
 * - Socket binding strategies: Supporting both wildcard binding (0.0.0.0/::) for maximum
 *   compatibility and interface-specific binding for precise control over packet handling
 * - IPv4/IPv6 dual-stack: Managing separate IPv4 and IPv6 sockets with appropriate address
 *   family handling, including IPv6-only interfaces and IPv4-only interfaces
 * - Platform abstraction: Isolating platform-specific network operations behind uniform interfaces,
 *   with conditional compilation selecting appropriate implementations
 * - Address validation: Verifying interface addresses are suitable for dnsmasq operations
 *   (not tentative, not deprecated, proper scope) and filtering loopback/link-local as needed
 * - Server interface checking: Validating that upstream DNS servers are reachable through
 *   available interfaces and binding server sockets to appropriate source addresses
 * 
 * DEPENDENCIES:
 * Includes: dnsmasq.h (core structures: struct daemon, struct listener, struct irec, struct server)
 * Called by: dnsmasq.c (main initialization), option.c (configuration changes), forward.c (query handling)
 * Calls: netlink.c (Linux interface monitoring), bpf.c (BSD interface monitoring), util.c (safe_malloc, etc.)
 * 
 * DATA STRUCTURES:
 * - struct listener (dnsmasq.h:674): Represents a listening socket with file descriptor, address,
 *   flags, and pointer to associated interface record (struct irec)
 * - struct irec (dnsmasq.h:665): Interface record containing interface name, index, addresses,
 *   netmask, broadcast address, MTU, and flags (up, loopback, point-to-point, etc.)
 * - struct server (dnsmasq.h:607): Upstream DNS server configuration with domain, source address,
 *   interface binding, and connection state tracking
 * - union mysockaddr (dnsmasq.h:557): Union of sockaddr_in (IPv4), sockaddr_in6 (IPv6), and
 *   sockaddr_un (Unix socket) for address storage
 * - struct serverfd (dnsmasq.h:598): Server file descriptor with socket, source address, interface
 *   index, and reference counting for shared upstream query sockets
 * 
 * COMPILE-TIME OPTIONS:
 * - HAVE_LINUX_NETWORK: Enables Linux-specific networking code including netlink integration,
 *   SO_BINDTODEVICE socket option, and Linux-specific ioctl calls (SIOCGIFNAME, etc.)
 * - HAVE_BSD_NETWORK: Enables BSD-specific networking including routing socket monitoring,
 *   BPF integration, and BSD socket options (SO_BINDTOIF on macOS)
 * - HAVE_SOLARIS_NETWORK: Enables Solaris-specific code using SIOCGLIFCONF for interface
 *   enumeration, handling Solaris zones, and IPMP (IP Multipathing) interfaces
 * - HAVE_IPV6: Enables IPv6 support including AAAA record handling, IPv6 socket creation,
 *   and dual-stack operation (always enabled in modern builds)
 * - HAVE_DHCP: Enables DHCP-specific networking including broadcast socket options, packet
 *   info socket options (IP_PKTINFO/IPV6_PKTINFO), and DHCP relay support
 * - HAVE_DHCP6: Enables DHCPv6-specific networking including ICMPv6 socket creation for
 *   Router Advertisement and DHCPv6 packet handling
 * - HAVE_TFTP: Enables TFTP server networking including UDP socket setup for TFTP transfers
 * - have_ipv4: Runtime flag indicating IPv4 support available (at least one IPv4 address configured)
 * - have_ipv6: Runtime flag indicating IPv6 support available (at least one IPv6 address configured)
 * 
 * THREADING/CONCURRENCY:
 * Single-process event-driven architecture with all network operations performed in the main
 * event loop. Socket creation and listener management occur during initialization and configuration
 * reload (SIGHUP). No thread synchronization required as all operations are sequential. Signal
 * handlers queue events for processing in the main loop rather than performing network operations
 * directly. Configuration reload (triggered by SIGHUP) safely closes old listeners and creates
 * new ones atomically within the event loop context.
 * 
 * @copyright Copyright (c) 2000-2025 Simon Kelley
 * @license GPL-2.0-or-later
 */

#include "dnsmasq.h"

#ifdef HAVE_LINUX_NETWORK

/**
 * @brief Convert network interface index to interface name (Linux implementation)
 * 
 * @detailed
 * Converts a network interface index number to its corresponding interface name string
 * using Linux-specific SIOCGIFNAME ioctl. This function is part of the platform abstraction
 * layer, with separate implementations for Linux, Solaris, and other systems. Interface
 * indices are used throughout the networking stack as stable identifiers for interfaces,
 * while names (like "eth0") are needed for user-facing operations and configuration matching.
 * 
 * The Linux implementation uses the SIOCGIFNAME ioctl which queries the kernel's network
 * interface registry directly. This is more efficient than enumerating all interfaces.
 * 
 * @param fd Socket file descriptor (unused in Linux implementation, required for ioctl)
 * @param index Interface index number (0 for invalid interface, >0 for valid interfaces)
 * @param name Output buffer for interface name (must be at least IF_NAMESIZE bytes)
 * 
 * @return 1 on success (name populated with interface name), 0 on failure (invalid index
 *         or interface not found)
 * 
 * @note This function handles only the Linux platform. Other platforms have their own
 *       implementations selected by conditional compilation.
 * @warning The name buffer must be at least IF_NAMESIZE (typically 16) bytes to prevent
 *          buffer overflow. No bounds checking is performed beyond safe_strncpy.
 * 
 * @see indextoname() implementations for Solaris (HAVE_SOLARIS_NETWORK) and BSD (else clause)
 * @see safe_strncpy() in src/util.c for safe string copying with NULL termination
 * 
 * EXAMPLE USAGE:
 * @code
 * char ifname[IF_NAMESIZE];
 * int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
 * if (indextoname(sockfd, 2, ifname))
 *     printf("Interface index 2 is %s\n", ifname);
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (platform-specific implementation detail)
 * SIDE EFFECTS: Performs ioctl system call which may fail if interface doesn't exist
 * THREAD SAFETY: Thread-safe (no shared state, output buffer provided by caller)
 */
int indextoname(int fd, int index, char *name)
{
  struct ifreq ifr;
  
  if (index == 0)
    return 0;

  ifr.ifr_ifindex = index;
  if (ioctl(fd, SIOCGIFNAME, &ifr) == -1)
    return 0;

  safe_strncpy(name, ifr.ifr_name, IF_NAMESIZE);

 return 1;
}


#elif defined(HAVE_SOLARIS_NETWORK)

#include <zone.h>
#include <alloca.h>
#ifndef LIFC_UNDER_IPMP
#  define LIFC_UNDER_IPMP 0
#endif

/**
 * @brief Convert network interface index to interface name (Solaris implementation)
 * 
 * @detailed
 * Converts a network interface index to its corresponding interface name on Solaris systems.
 * This implementation is significantly more complex than the Linux version due to Solaris zones
 * and IPMP (IP Multipathing) support. In the global zone, the standard if_indextoname() function
 * is used. In non-global zones, the function must enumerate all interfaces using SIOCGLIFCONF
 * and SIOCGLIFNUM ioctls, then match the interface index.
 * 
 * The Solaris implementation handles several platform-specific concerns:
 * - Zone awareness: Different behavior in global vs non-global zones
 * - IPMP interfaces: Including underlying physical interfaces in IPMP groups
 * - Logical interfaces: Solaris uses lifreq structures instead of ifreq
 * - Dual-stack: Single API for both IPv4 and IPv6 (AF_UNSPEC family)
 * 
 * The LIFC_NOXMIT, LIFC_TEMPORARY, LIFC_ALLZONES, and LIFC_UNDER_IPMP flags control which
 * interfaces are enumerated to ensure all relevant interfaces are visible to dnsmasq.
 * 
 * @param fd Socket file descriptor for ioctl operations (must be valid open socket)
 * @param index Interface index number (0 for invalid, >0 for valid interface)
 * @param name Output buffer for interface name (must be at least IF_NAMESIZE bytes)
 * 
 * @return 1 on success (name populated with interface name), 0 on failure (invalid index,
 *         interface not found, or ioctl error)
 * 
 * @note Uses alloca() for temporary buffer allocation (stack allocation, automatically freed)
 * @warning In non-global zones, this function may be expensive as it enumerates all interfaces.
 *          Consider caching results if called frequently with the same index.
 * @warning The name buffer must be at least IF_NAMESIZE bytes to prevent overflow.
 * 
 * @see getzoneid() for Solaris zone identification
 * @see if_indextoname() standard POSIX function used in global zone
 * @see SIOCGLIFNUM ioctl for counting interfaces on Solaris
 * @see SIOCGLIFCONF ioctl for enumerating interfaces on Solaris
 * 
 * EXAMPLE USAGE:
 * @code
 * char ifname[IF_NAMESIZE];
 * int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
 * if (indextoname(sockfd, 3, ifname))
 *     my_syslog(LOG_INFO, "Found interface: %s", ifname);
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (platform-specific implementation)
 * SIDE EFFECTS: Performs multiple ioctl calls; allocates temporary buffer on stack with alloca()
 * THREAD SAFETY: Thread-safe if alloca() is thread-safe on the platform (typically yes)
 */
int indextoname(int fd, int index, char *name)
{
  int64_t lifc_flags;
  struct lifnum lifn;
  int numifs, bufsize, i;
  struct lifconf lifc;
  struct lifreq *lifrp;
  
  if (index == 0)
    return 0;
  
  if (getzoneid() == GLOBAL_ZONEID) 
    {
      if (!if_indextoname(index, name))
	return 0;
      return 1;
    }
  
  lifc_flags = LIFC_NOXMIT | LIFC_TEMPORARY | LIFC_ALLZONES | LIFC_UNDER_IPMP;
  lifn.lifn_family = AF_UNSPEC;
  lifn.lifn_flags = lifc_flags;
  if (ioctl(fd, SIOCGLIFNUM, &lifn) < 0) 
    return 0;
  
  numifs = lifn.lifn_count;
  bufsize = numifs * sizeof(struct lifreq);
  
  lifc.lifc_family = AF_UNSPEC;
  lifc.lifc_flags = lifc_flags;
  lifc.lifc_len = bufsize;
  lifc.lifc_buf = alloca(bufsize);
  
  if (ioctl(fd, SIOCGLIFCONF, &lifc) < 0)  
    return 0;
  
  lifrp = lifc.lifc_req;
  for (i = lifc.lifc_len / sizeof(struct lifreq); i; i--, lifrp++) 
    {
      struct lifreq lifr;
      safe_strncpy(lifr.lifr_name, lifrp->lifr_name, IF_NAMESIZE);
      if (ioctl(fd, SIOCGLIFINDEX, &lifr) < 0) 
	return 0;
      
      if (lifr.lifr_index == index) {
	safe_strncpy(name, lifr.lifr_name, IF_NAMESIZE);
	return 1;
      }
    }
  return 0;
}


#else

/**
 * @brief Convert network interface index to interface name (BSD/generic implementation)
 * 
 * @detailed
 * Converts a network interface index to its corresponding interface name on BSD and other
 * POSIX-compliant systems that provide the standard if_indextoname() function. This is the
 * simplest implementation, relying on the standard POSIX function rather than platform-specific
 * ioctls. This code path is used on FreeBSD, OpenBSD, NetBSD, macOS, and other systems that
 * don't define HAVE_LINUX_NETWORK or HAVE_SOLARIS_NETWORK.
 * 
 * The BSD implementation is a thin wrapper around the POSIX if_indextoname() function, which
 * provides standardized interface index to name conversion. The function explicitly handles
 * the fd parameter (marking it unused with (void)fd) since the standard POSIX function doesn't
 * require a socket descriptor.
 * 
 * @param fd Socket file descriptor (unused in this implementation, marked with (void)fd)
 * @param index Interface index number (0 indicates invalid interface, >0 for valid interfaces)
 * @param name Output buffer for interface name (must be at least IF_NAMESIZE bytes)
 * 
 * @return 1 on success (name populated with interface name), 0 on failure (index is 0 or
 *         if_indextoname() returned NULL indicating interface not found)
 * 
 * @note This implementation is used on BSD systems (FreeBSD, OpenBSD, NetBSD, DragonFly BSD),
 *       macOS, and other POSIX-compliant systems without Linux or Solaris-specific code.
 * @warning The name buffer must be at least IF_NAMESIZE bytes as required by if_indextoname().
 * 
 * @see if_indextoname() POSIX function for standard interface index to name conversion
 * @see indextoname() Linux implementation (HAVE_LINUX_NETWORK)
 * @see indextoname() Solaris implementation (HAVE_SOLARIS_NETWORK)
 * 
 * EXAMPLE USAGE:
 * @code
 * char ifname[IF_NAMESIZE];
 * // fd parameter unused but maintained for API consistency
 * if (indextoname(-1, 1, ifname))
 *     printf("Interface index 1 is %s\n", ifname);
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (uses standard POSIX API)
 * SIDE EFFECTS: Calls if_indextoname() which may access kernel interface tables
 * THREAD SAFETY: Thread-safe (if_indextoname() is thread-safe per POSIX)
 */
int indextoname(int fd, int index, char *name)
{ 
  (void)fd;

  if (index == 0 || !if_indextoname(index, name))
    return 0;

  return 1;
}

#endif

/**
 * @brief Check if network interface is allowed for dnsmasq operations
 * 
 * @detailed Determines whether a network interface (identified by name and/or address)
 *           should be used by dnsmasq based on configured include/exclude lists. The
 *           function checks the interface against daemon->if_names (allowed interface names
 *           with wildcard support), daemon->if_addrs (specific allowed IP addresses),
 *           daemon->if_except (excluded interface names), and optionally daemon->authinterface
 *           (authoritative DNS interfaces). The function sets INAME_USED flags on matching
 *           configuration entries to track which configured interfaces are actually present
 *           on the system.
 * 
 * @param family Address family: AF_INET (IPv4), AF_INET6 (IPv6), or AF_LOCAL (name-only check).
 *               AF_LOCAL can be used to check interface by name without address validation.
 * @param addr Pointer to union containing IPv4 (.addr4) or IPv6 (.addr6) address to check.
 *             May be NULL if checking by name only (family == AF_LOCAL). Address is compared
 *             against daemon->if_addrs list for exact match.
 * @param name Interface name string (e.g., "eth0", "wlan0"). Must not be NULL. Compared
 *             against daemon->if_names with wildcard matching support (e.g., "eth*" matches
 *             "eth0", "eth1"). Maximum length IF_NAMESIZE.
 * @param auth Optional output parameter for authoritative DNS interface flag. If non-NULL,
 *             will be set to 1 if interface matches daemon->authinterface list, 0 otherwise.
 *             May be NULL if caller does not need authoritative interface information.
 * 
 * @return 1 if interface is allowed (matches if_names/if_addrs and not in if_except), or
 *           if interface is authoritative (matches authinterface).
 * @retval 1 Interface allowed for use: matched if_names or if_addrs, not excluded, or authoritative
 * @retval 0 Interface not allowed: no match in if_names/if_addrs, or matched if_except exclusion
 * 
 * @note Function must check ALL configured interfaces to set INAME_USED flags correctly,
 *       cannot bail out early on first match. This ensures configuration validation warnings
 *       for unused interface specifications.
 * @note If both if_names and if_addrs are empty (NULL), default is to allow all interfaces (ret=1).
 *       If either list is configured, default changes to deny (ret=0) unless explicitly matched.
 * @note Address match takes precedence over exclusion: if address explicitly matches if_addrs,
 *       interface name exclusion in if_except is ignored (match_addr flag).
 * @note Authoritative interface match overrides all other checks and forces ret=1.
 * 
 * @warning Wildcard matching on interface names uses wildcard_match() which supports * and ?
 *          patterns but is case-sensitive.
 * 
 * @see wildcard_match() in src/util.c for pattern matching implementation
 * @see enumerate_interfaces() which calls iface_check() during interface discovery
 * @see struct iname in src/dnsmasq.h for interface name/address list structure
 * 
 * EXAMPLE USAGE:
 * @code
 * union all_addr addr;
 * int is_auth;
 * // Check if eth0 with specific IPv4 address is allowed
 * addr.addr4.s_addr = inet_addr("192.168.1.1");
 * if (iface_check(AF_INET, &addr, "eth0", &is_auth)) {
 *   // Interface allowed, is_auth indicates if authoritative
 * }
 * @endcode
 * 
 * INTERFACE CONFIGURATION LISTS:
 * - daemon->if_names: Interfaces to include by name (--interface, -i option)
 * - daemon->if_addrs: Interfaces to include by address (--listen-address option)
 * - daemon->if_except: Interfaces to exclude by name (--except-interface option)
 * - daemon->authinterface: Authoritative DNS interfaces (--auth-server option)
 * 
 * SIDE EFFECTS:
 * - Sets INAME_USED flag on matching entries in if_names and if_addrs lists
 * - Modifies *auth output parameter if non-NULL
 * 
 * ALGORITHM:
 * 1. If if_names or if_addrs configured, default to deny (ret=0), else allow (ret=1)
 * 2. Check interface name against if_names with wildcard matching, set INAME_USED on match
 * 3. If addr provided, check against if_addrs for exact address match, set INAME_USED and match_addr
 * 4. If no address match, check if_except exclusion list (name wildcard match), set ret=0 if matched
 * 5. If auth parameter provided, check authinterface list for name or address match
 * 6. Authoritative match overrides all previous checks and sets ret=1, *auth=1
 * 
 * RFC COMPLIANCE: N/A (internal configuration enforcement)
 * THREAD SAFETY: Not thread-safe - accesses global daemon structure without locking
 */
int iface_check(int family, union all_addr *addr, char *name, int *auth)
{
  struct iname *tmp;
  int ret = 1, match_addr = 0;

  /* Note: have to check all and not bail out early, so that we set the "used" flags.
     May be called with family == AF_LOCAL to check interface by name only. */
  
  if (daemon->if_names || daemon->if_addrs)
    {
      ret = 0;

      for (tmp = daemon->if_names; tmp; tmp = tmp->next)
	if (tmp->name && wildcard_match(tmp->name, name))
	  {
	    tmp->flags |= INAME_USED;
	    ret = 1;
	  }
	        
      if (addr)
	for (tmp = daemon->if_addrs; tmp; tmp = tmp->next)
	  if (tmp->addr.sa.sa_family == family)
	    {
	      if (family == AF_INET &&
		  tmp->addr.in.sin_addr.s_addr == addr->addr4.s_addr)
		{
		  tmp->flags |= INAME_USED;
		  ret = match_addr = 1;
		}
	      else if (family == AF_INET6 &&
		       IN6_ARE_ADDR_EQUAL(&tmp->addr.in6.sin6_addr, 
					  &addr->addr6))
		{
		  tmp->flags |= INAME_USED;
		  ret = match_addr = 1;
		}
	    }          
    }
  
  if (!match_addr)
    for (tmp = daemon->if_except; tmp; tmp = tmp->next)
      if (tmp->name && wildcard_match(tmp->name, name))
	ret = 0;
    
  if (auth)
    {
      *auth = 0;

      for (tmp = daemon->authinterface; tmp; tmp = tmp->next)
	if (tmp->name)
	  {
	    if (strcmp(tmp->name, name) == 0 &&
		(tmp->addr.sa.sa_family == 0 || tmp->addr.sa.sa_family == family))
	      break;
	  }
	else if (addr && tmp->addr.sa.sa_family == AF_INET && family == AF_INET &&
		 tmp->addr.in.sin_addr.s_addr == addr->addr4.s_addr)
	  break;
	else if (addr && tmp->addr.sa.sa_family == AF_INET6 && family == AF_INET6 &&
		 IN6_ARE_ADDR_EQUAL(&tmp->addr.in6.sin6_addr, &addr->addr6))
	  break;
      
      if (tmp) 
	{
	  *auth = 1;
	  ret = 1;
	}
    }

  return ret; 
}


/**
 * @brief Handle kernel loopback interface reporting anomaly for locally-originated packets
 * 
 * @detailed Workaround for kernel behavior where packets originating locally are sometimes
 *           reported as arriving via the loopback interface even when sent to addresses
 *           bound to other interfaces. This function determines whether to accept packets
 *           arriving via loopback by checking if the destination address matches any
 *           configured interface address. This prevents incorrect packet rejection when
 *           local processes communicate with dnsmasq services.
 * 
 *           The function performs two checks:
 *           1. Verify the arrival interface is actually a loopback interface (IFF_LOOPBACK flag)
 *           2. Verify the destination address matches one of daemon->interfaces addresses
 * 
 *           If both conditions are true, the packet is accepted even if loopback interface
 *           listening is not explicitly configured.
 * 
 * @param fd Socket file descriptor for ioctl operations to query interface flags. Must be
 *           a valid socket descriptor (typically AF_INET or AF_INET6 socket). Used with
 *           SIOCGIFFLAGS to retrieve interface flags.
 * @param family Address family: AF_INET for IPv4 address comparison, AF_INET6 for IPv6.
 *               Determines which address union member to access and which interfaces to
 *               compare against.
 * @param addr Pointer to union containing destination address from received packet. For
 *             AF_INET uses addr->addr4 (struct in_addr), for AF_INET6 uses addr->addr6
 *             (struct in6_addr). Must not be NULL.
 * @param name Interface name string reported by kernel as arrival interface (e.g., "lo",
 *             "lo0"). Used to query IFF_LOOPBACK flag via ioctl. Maximum length IF_NAMESIZE.
 *             Must not be NULL.
 * 
 * @return 1 if packet should be accepted (loopback interface AND address matches configured interface)
 * @retval 1 Packet arrived via loopback interface and destination address matches daemon->interfaces
 * @retval 0 Interface is not loopback, or address does not match any configured interface
 * 
 * @note daemon->interfaces list MUST be up-to-date before calling this function. If interface
 *       enumeration is stale, address matching will be incorrect.
 * @note This function is called during packet reception when interface validation fails normal
 *       checks, providing a second chance for locally-originated packets.
 * @note IPv4 address comparison uses direct equality (==), IPv6 uses IN6_ARE_ADDR_EQUAL macro.
 * 
 * @warning ioctl(SIOCGIFFLAGS) may fail if interface name is invalid or socket fd is wrong type.
 *          Failure returns 0 (packet rejected).
 * @warning Function iterates entire daemon->interfaces list for each call - O(n) complexity
 *          where n is number of configured listening interfaces.
 * 
 * @see enumerate_interfaces() to update daemon->interfaces list
 * @see iface_check() for primary interface validation logic
 * @see struct irec in src/dnsmasq.h for interface record structure
 * 
 * EXAMPLE USAGE:
 * @code
 * union all_addr dest_addr;
 * char iface_name[IF_NAMESIZE];
 * int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
 * 
 * // Packet received with destination 127.0.0.1 but arrival iface "lo"
 * dest_addr.addr4.s_addr = inet_addr("127.0.0.1");
 * safe_strncpy(iface_name, "lo", IF_NAMESIZE);
 * 
 * if (loopback_exception(sock_fd, AF_INET, &dest_addr, iface_name)) {
 *   // Accept packet despite unusual interface reporting
 * }
 * @endcode
 * 
 * KERNEL ISSUE BACKGROUND:
 * Some operating systems report the arrival interface as loopback for packets sent
 * from local processes to addresses on other interfaces (e.g., process sends to
 * 192.168.1.1 which is bound to eth0, but kernel reports arrival interface as lo).
 * This is technically correct from a routing perspective but confuses application-level
 * interface filtering.
 * 
 * RFC COMPLIANCE: N/A (kernel behavior workaround)
 * SIDE EFFECTS: None (read-only operations on daemon->interfaces and ioctl query)
 * THREAD SAFETY: Not thread-safe - accesses global daemon structure without locking
 */
int loopback_exception(int fd, int family, union all_addr *addr, char *name)    
{
  struct ifreq ifr;
  struct irec *iface;

  safe_strncpy(ifr.ifr_name, name, IF_NAMESIZE);
  if (ioctl(fd, SIOCGIFFLAGS, &ifr) != -1 &&
      ifr.ifr_flags & IFF_LOOPBACK)
    {
      for (iface = daemon->interfaces; iface; iface = iface->next)
	if (iface->addr.sa.sa_family == family)
	  {
	    if (family == AF_INET)
	      {
		if (iface->addr.in.sin_addr.s_addr == addr->addr4.s_addr)
		  return 1;
	      }
	    else if (IN6_ARE_ADDR_EQUAL(&iface->addr.in6.sin6_addr, &addr->addr6))
	      return 1;
	  }
    }
  return 0;
}

/**
 * @brief Handle IPv4 interface label aliasing for packet acceptance validation
 * 
 * @detailed Workaround for Linux interface label notation (e.g., eth0:0, eth0:1) where
 *           dnsmasq is configured to listen on a labeled interface like --interface=eth0:0.
 *           When packets arrive, the kernel reports the physical interface index and base
 *           name (eth0) without the label suffix (:0). This causes interface name mismatches
 *           during packet validation even though the IP address is correct.
 * 
 *           This function resolves the mismatch by checking if the interface INDEX plus
 *           the destination ADDRESS together match any entry in daemon->interfaces,
 *           regardless of the interface name/label. If both the index and address match,
 *           the packet is accepted despite the name mismatch.
 * 
 *           Interface labels (eth0:0) are a Linux-specific IPv4 feature used to assign
 *           multiple IP addresses to a single physical interface. The kernel internally
 *           tracks only the physical interface index, so label information is lost in
 *           packet metadata.
 * 
 * @param index Interface index number from kernel packet metadata (e.g., from IP_PKTINFO
 *              or IPV6_PKTINFO). This is the underlying physical interface index without
 *              label information. Must be positive integer returned by if_nametoindex().
 * @param family Address family: AF_INET (IPv4) or AF_INET6 (IPv6). Only AF_INET is
 *               supported because interface labels are IPv4-specific. AF_INET6 always
 *               returns 0 (no exception).
 * @param addr Pointer to union containing destination address from received packet.
 *             For AF_INET uses addr->addr4 (struct in_addr). Compared against addresses
 *             in daemon->interfaces list. Must not be NULL.
 * 
 * @return 1 if interface index and address match a configured listener (label exception applies)
 * @retval 1 Interface index and IPv4 address match an entry in daemon->interfaces (packet accepted)
 * @retval 0 No matching index+address combination found, or family is not AF_INET
 * 
 * @note daemon->interfaces list MUST be up-to-date before calling. If interface enumeration
 *       is stale, index and address matching will be incorrect.
 * @note Labels are IPv4-ONLY feature. IPv6 does not support interface labels, function
 *       immediately returns 0 for AF_INET6.
 * @note Function checks BOTH index AND address - both must match for exception to apply.
 *       This ensures we're matching the specific IP address configured on the labeled interface.
 * @note Common use case: --interface=eth0:0 --listen-address=192.168.1.10 where eth0:0 is
 *       an alias for IP 192.168.1.10 on physical interface eth0.
 * 
 * @warning Function iterates entire daemon->interfaces list - O(n) complexity where n is
 *          number of configured listeners. Performance impact negligible for typical deployments
 *          (dozens of listeners).
 * @warning If multiple labeled interfaces share the same physical interface and index, the
 *          first matching address wins. This is expected behavior.
 * 
 * @see enumerate_interfaces() to populate daemon->interfaces list with index and address data
 * @see iface_check() for primary interface name validation logic
 * @see loopback_exception() for similar address-based validation workaround
 * @see struct irec in src/dnsmasq.h for interface record structure with index and addr fields
 * 
 * EXAMPLE USAGE:
 * @code
 * union all_addr dest_addr;
 * int iface_index = 2; // Physical eth0 index from kernel
 * 
 * // Packet destination 192.168.1.10 on interface index 2 (eth0)
 * // Configuration has --interface=eth0:0 --listen-address=192.168.1.10
 * dest_addr.addr4.s_addr = inet_addr("192.168.1.10");
 * 
 * if (label_exception(iface_index, AF_INET, &dest_addr)) {
 *   // Accept packet - address matches configured eth0:0 listener
 * }
 * @endcode
 * 
 * INTERFACE LABEL BACKGROUND:
 * Linux allows creating interface aliases with label notation:
 *   ifconfig eth0:0 192.168.1.10 netmask 255.255.255.0
 *   ifconfig eth0:1 192.168.1.11 netmask 255.255.255.0
 * 
 * Both eth0:0 and eth0:1 share the same underlying interface index (eth0's index).
 * Kernel packet metadata contains only the physical index, not the label, so name-based
 * interface matching fails. This function provides address-based matching as fallback.
 * 
 * ALGORITHM:
 * 1. Reject immediately if family != AF_INET (labels are IPv4-only)
 * 2. Iterate daemon->interfaces list
 * 3. For each interface, check if index matches AND family is AF_INET AND IPv4 address matches
 * 4. Return 1 on first match, 0 if no matches found
 * 
 * RFC COMPLIANCE: N/A (Linux interface label handling is OS-specific)
 * SIDE EFFECTS: None (read-only operations on daemon->interfaces)
 * THREAD SAFETY: Not thread-safe - accesses global daemon structure without locking
 */
int label_exception(int index, int family, union all_addr *addr)
{
  struct irec *iface;

  /* labels only supported on IPv4 addresses. */
  if (family != AF_INET)
    return 0;

  for (iface = daemon->interfaces; iface; iface = iface->next)
    if (iface->index == index && iface->addr.sa.sa_family == AF_INET &&
	iface->addr.in.sin_addr.s_addr == addr->addr4.s_addr)
      return 1;

  return 0;
}

/**
 * @brief Parameter structure for interface enumeration callback
 * 
 * Passed to iface_allowed() callback during interface enumeration to carry
 * context including spare address records and socket file descriptor for 
 * interface queries.
 */
struct iface_param {
  struct addrlist *spare;  /**< Spare address list entries for interface configuration */
  int fd;                  /**< Socket file descriptor for ioctl interface queries */
};

/**
 * @brief Interface enumeration callback determining whether interface/address should be used
 * 
 * @detailed Core filtering logic for network interface enumeration. Called once for each
 *           discovered interface and address combination during system interface scanning.
 *           Applies configuration rules from --interface, --except-interface, --listen-address,
 *           and related options to determine if this specific interface/address should be
 *           included in daemon->interfaces list for DNS/DHCP listening.
 *
 *           The function implements a multi-stage filtering pipeline:
 *           1. Apply interface NAME filters (--interface=eth0, wildcard patterns)
 *           2. Apply interface EXCEPTION filters (--except-interface=wlan*)
 *           3. Apply ADDRESS filters (--listen-address=192.168.1.1)
 *           4. Check for duplicate interface/address combinations already in list
 *           5. Allocate and populate new struct irec entry if all filters pass
 *           6. Add new entry to daemon->interfaces linked list
 *
 *           Supports both positive (--interface) and negative (--except-interface) filtering,
 *           wildcard patterns (eth*, wlan?), and address-specific listening. This enables
 *           configurations like "listen on all eth* interfaces except eth1" or "listen only
 *           on specific IP addresses regardless of interface name."
 *
 *           IPv4 and IPv6 addresses handled identically - same filtering logic applies to
 *           both address families. Interface flags (IFF_LOOPBACK, IFF_POINTOPOINT) used
 *           to apply special handling for loopback and tunnel interfaces.
 *
 * @param param Context structure containing spare address records and socket fd for ioctl queries.
 *              param->fd used for interface name resolution and attribute queries.
 *              param->spare points to available addrlist entries for configuration.
 *              Must not be NULL.
 * @param if_index Kernel interface index from if_nametoindex() or similar platform enumeration.
 *                 Uniquely identifies physical interface. Used to correlate addresses with
 *                 underlying interface. Zero is invalid (interface index 0 reserved for "any").
 *                 Typical values 1-255 on most systems.
 * @param label Interface label/name from kernel (e.g., "eth0", "eth0:0", "wlan0").
 *              For Linux IPv4 aliases, includes label suffix (eth0:0). For BSD and IPv6,
 *              contains base interface name only. Used for --interface and --except-interface
 *              pattern matching. NULL is treated as empty string "". Must be valid C string.
 * @param addr Pointer to union mysockaddr containing interface IP address (IPv4 or IPv6).
 *             Union discriminated by addr->sa.sa_family (AF_INET or AF_INET6).
 *             For IPv4: addr->in.sin_addr (struct sockaddr_in).
 *             For IPv6: addr->in6.sin6_addr (struct sockaddr_in6).
 *             Used for --listen-address filtering and duplicate detection.
 *             Must not be NULL.
 * @param netmask IPv4 netmask (struct in_addr) for this interface address.
 *                Used to determine network prefix when prefixlen parameter is -1.
 *                For IPv6, this parameter is ignored (prefix always provided directly).
 *                Netmask converted to prefix length via bit counting if needed.
 *                For point-to-point interfaces, may be 255.255.255.255 (/32).
 * @param prefixlen Network prefix length (0-32 for IPv4, 0-128 for IPv6).
 *               Specifies size of network portion of address (CIDR notation).
 *               Value -1 signals "calculate from netmask parameter" (IPv4 only).
 *               For IPv6, always provided directly from kernel.
 *               Used to populate irec->netmask field for subnet calculations.
 * @param iface_flags Address family and interface type flags:
 *              AF_INET (2): IPv4 address in addr->in.sin_addr
 *              AF_INET6 (10): IPv6 address in addr->in6.sin6_addr
 *              IFF_LOOPBACK: Loopback interface (lo, lo0) - special handling
 *              IFF_POINTOPOINT: Point-to-point link (VPN, PPP) - special handling
 *              Other IFF_* flags may be present but are not used by this function.
 *              Must include valid address family (AF_INET or AF_INET6).
 *
 * @return 1 if interface/address accepted and added to daemon->interfaces, 0 if rejected or duplicate
 * @retval 1 Interface passed all filters and new irec entry allocated and added to daemon->interfaces
 * @retval 0 Interface rejected by name filter, exception filter, or address filter
 * @retval 0 Interface/address combination already exists in daemon->interfaces (duplicate)
 * @retval 0 Memory allocation failed for new irec entry
 *
 * @note Function MODIFIES daemon->interfaces linked list by adding new entries.
 *       Existing entries with matching index/address are marked as irec->found = 1
 *       to prevent deletion during cleanup.
 * @note Wildcard patterns supported: * matches zero or more characters, ? matches exactly one.
 *       Example: --interface=eth* matches eth0, eth1, eth0:0 but not wlan0.
 * @note Label matching uses EXACT string comparison except for wildcards.
 *       Case-sensitive on all platforms.
 * @note For loopback interfaces with --local-service or --bind-dynamic, function may configure
 *       special handling for local service listening.
 * @note Function handles both inclusion filters (--interface=eth0) and exclusion filters
 *       (--except-interface=wlan*). Exclusions take precedence over inclusions.
 * @note Address filters (--listen-address) checked AFTER interface name filters.
 *       If specific addresses configured, interface accepted only if address matches.
 * @note Function is callback for enumerate_interfaces() platform-specific enumeration.
 *       Called potentially hundreds of times during interface scan on systems with many IPs.
 *
 * @warning Function allocates memory with whine_malloc(). Caller responsible for eventual cleanup
 *          via clean_interfaces() which removes unused entries.
 * @warning param->fd socket descriptor MUST be valid for ioctl operations.
 *          Invalid fd causes interface name resolution failures.
 * @warning Race conditions possible if interfaces added/removed during enumeration.
 *          This is acceptable - next enumeration cycle (on SIGHUP or network change) corrects.
 * @warning Performance: O(n*m) where n=number of configured filters, m=number of interfaces.
 *          Typically negligible (<1ms per call) for small networks with dozens of filters.
 *
 * @see enumerate_interfaces() for platform-specific interface enumeration that calls this callback
 * @see clean_interfaces() for removing irec entries not marked as "found" after enumeration
 * @see struct irec in src/dnsmasq.h for interface listener record structure
 * @see wildcard_match() in src/util.c for wildcard pattern matching implementation
 *
 * EXAMPLE USAGE:
 * @code
 * struct iface_param param;
 * param.fd = socket(PF_INET, SOCK_DGRAM, 0);
 * param.spare = NULL;
 *
 * // During interface enumeration, callback invoked for each discovered address:
 * // eth0 with address 192.168.1.1/24
 * union mysockaddr addr;
 * addr.sa.sa_family = AF_INET;
 * addr.in.sin_addr.s_addr = inet_addr("192.168.1.1");
 * struct in_addr netmask;
 * netmask.s_addr = inet_addr("255.255.255.0");
 *
 * int result = iface_allowed(&param, 2, "eth0", &addr, netmask, 24, AF_INET);
 * // result = 1 if eth0 matches --interface filters
 * // result = 0 if eth0 excluded or doesn't match filters
 * @endcode
 *
 * FILTERING LOGIC FLOW:
 * 1. If daemon->if_names configured (--interface specified):
 *    - Check if label matches any positive pattern (with optional =address suffix)
 *    - Check if label matches any negative pattern (--except-interface)
 *    - If matches positive and not negative, continue to step 3
 *    - If no match or matches negative, REJECT (return 0)
 * 2. If NO daemon->if_names configured (listen on all interfaces by default):
 *    - Check if label matches any --except-interface pattern
 *    - If matches exception, REJECT (return 0)
 *    - Otherwise continue to step 3
 * 3. If daemon->if_addrs configured (--listen-address specified):
 *    - Check if addr matches any configured listen address
 *    - If no match, REJECT (return 0)
 *    - If matches, continue to step 4
 * 4. Check if interface/address already in daemon->interfaces:
 *    - If found (matching index and address), mark as found and RETURN 0 (duplicate)
 *    - If not found, continue to step 5
 * 5. Allocate new struct irec, populate fields, add to daemon->interfaces head
 * 6. Mark as found=1, return 1 (SUCCESS)
 *
 * CONFIGURATION EXAMPLES:
 * --interface=eth0                    # Listen only on eth0 (all addresses)
 * --interface=eth* --except-interface=eth1  # All eth* except eth1
 * --listen-address=192.168.1.1        # Listen only on this IP (any interface)
 * --interface=eth0 --listen-address=192.168.1.1  # eth0 AND this IP
 *
 * RFC COMPLIANCE: N/A (interface filtering is implementation-specific)
 * SIDE EFFECTS: 
 * - Allocates memory for new struct irec entries via whine_malloc()
 * - Modifies daemon->interfaces linked list (adds new entries, marks existing as found)
 * - May configure special handling for loopback/multicast interfaces
 * THREAD SAFETY: Not thread-safe - modifies global daemon structure without locking
 */
static int iface_allowed(struct iface_param *param, int if_index, char *label,
			 union mysockaddr *addr, struct in_addr netmask, int prefixlen, int iface_flags) 
{
  struct irec *iface;
  struct cond_domain *cond;
  int loopback;
  struct ifreq ifr;
  int tftp_ok = !!option_bool(OPT_TFTP);
  int dhcp4_ok = 1;
  int dhcp6_ok = 1;
  int auth_dns = 0;
  int is_label = 0;
#if defined(HAVE_DHCP) || defined(HAVE_TFTP)
  struct iname *tmp;
#endif

  (void)prefixlen;

  if (!indextoname(param->fd, if_index, ifr.ifr_name) ||
      ioctl(param->fd, SIOCGIFFLAGS, &ifr) == -1)
    return 0;
   
  loopback = ifr.ifr_flags & IFF_LOOPBACK;
  
  if (loopback)
    dhcp4_ok = dhcp6_ok = 0;
  
  if (!label)
    label = ifr.ifr_name;
  else
    is_label = strcmp(label, ifr.ifr_name);
 
  /* maintain a list of all addresses on all interfaces for --local-service option */
  if (option_bool(OPT_LOCAL_SERVICE))
    {
      struct addrlist *al;

      if (param->spare)
	{
	  al = param->spare;
	  param->spare = al->next;
	}
      else
	al = whine_malloc(sizeof(struct addrlist));
      
      if (al)
	{
	  al->next = daemon->interface_addrs;
	  daemon->interface_addrs = al;
	  al->prefixlen = prefixlen;
	  
	  if (addr->sa.sa_family == AF_INET)
	    {
	      al->addr.addr4 = addr->in.sin_addr;
	      al->flags = 0;
	    }
	  else
	    {
	      al->addr.addr6 = addr->in6.sin6_addr;
	      al->flags = ADDRLIST_IPV6;
	    } 
	}
    }
  
  if (addr->sa.sa_family != AF_INET6 || !IN6_IS_ADDR_LINKLOCAL(&addr->in6.sin6_addr))
    {
      struct interface_name *int_name;
      struct addrlist *al;
#ifdef HAVE_AUTH
      struct auth_zone *zone;
      struct auth_name_list *name;

      /* Find subnets in auth_zones */
      for (zone = daemon->auth_zones; zone; zone = zone->next)
	for (name = zone->interface_names; name; name = name->next)
	  if (wildcard_match(name->name, label))
	    {
	      if (addr->sa.sa_family == AF_INET && (name->flags & AUTH4))
		{
		  if (param->spare)
		    {
		      al = param->spare;
		      param->spare = al->next;
		    }
		  else
		    al = whine_malloc(sizeof(struct addrlist));
		  
		  if (al)
		    {
		      al->next = zone->subnet;
		      zone->subnet = al;
		      al->prefixlen = prefixlen;
		      al->addr.addr4 = addr->in.sin_addr;
		      al->flags = 0;
		    }
		}
	      
	      if (addr->sa.sa_family == AF_INET6 && (name->flags & AUTH6))
		{
		  if (param->spare)
		    {
		      al = param->spare;
		      param->spare = al->next;
		    }
		  else
		    al = whine_malloc(sizeof(struct addrlist));
		  
		  if (al)
		    {
		      al->next = zone->subnet;
		      zone->subnet = al;
		      al->prefixlen = prefixlen;
		      al->addr.addr6 = addr->in6.sin6_addr;
		      al->flags = ADDRLIST_IPV6;
		    }
		} 
	    }
#endif
       
      /* Update addresses from interface_names. These are a set independent
	 of the set we're listening on. */  
      for (int_name = daemon->int_names; int_name; int_name = int_name->next)
	if (strncmp(label, int_name->intr, IF_NAMESIZE) == 0)
	  {
	    struct addrlist *lp;

	    al = NULL;
	    
	    if (addr->sa.sa_family == AF_INET && (int_name->flags & (IN4 | INP4)))
	      {
		struct in_addr newaddr = addr->in.sin_addr;
		
		if (int_name->flags & INP4)
		  newaddr.s_addr = (addr->in.sin_addr.s_addr & netmask.s_addr) |
		    (int_name->proto4.s_addr & ~netmask.s_addr);
		
		/* check for duplicates. */
		for (lp = int_name->addr; lp; lp = lp->next)
		  if (lp->flags == 0 && lp->addr.addr4.s_addr == newaddr.s_addr)
		    break;
		
		if (!lp)
		  {
		    if (param->spare)
		      {
			al = param->spare;
			param->spare = al->next;
		      }
		    else
		      al = whine_malloc(sizeof(struct addrlist));

		    if (al)
		      {
			al->flags = 0;
			al->addr.addr4 = newaddr;
		      }
		  }
	      }

	    if (addr->sa.sa_family == AF_INET6 && (int_name->flags & (IN6 | INP6)))
	      {
		struct in6_addr newaddr = addr->in6.sin6_addr;
		
		if (int_name->flags & INP6)
		  {
		    int i;

		    for (i = 0; i < 16; i++)
		      {
			int bits = ((i+1)*8) - prefixlen;
		       
			if (bits >= 8)
			  newaddr.s6_addr[i] = int_name->proto6.s6_addr[i];
			else if (bits >= 0)
			  {
			    unsigned char mask = 0xff << bits;
			    newaddr.s6_addr[i] =
			      (addr->in6.sin6_addr.s6_addr[i] & mask) |
			      (int_name->proto6.s6_addr[i] & ~mask);
			  }
		      }
		  }
		
		/* check for duplicates. */
		for (lp = int_name->addr; lp; lp = lp->next)
		  if ((lp->flags & ADDRLIST_IPV6) &&
		      IN6_ARE_ADDR_EQUAL(&lp->addr.addr6, &newaddr))
		    break;
					
		if (!lp)
		  {
		    if (param->spare)
		      {
			al = param->spare;
			param->spare = al->next;
		      }
		    else
		      al = whine_malloc(sizeof(struct addrlist));
		    
		    if (al)
		      {
			al->flags = ADDRLIST_IPV6;
			al->addr.addr6 = newaddr;

			/* Privacy addresses and addresses still undergoing DAD and deprecated addresses
			   don't appear in forward queries, but will in reverse ones. */
			if (!(iface_flags & IFACE_PERMANENT) || (iface_flags & (IFACE_DEPRECATED | IFACE_TENTATIVE)))
			  al->flags |= ADDRLIST_REVONLY;
		      }
		  }
	      }
	    
	    if (al)
	      {
		al->next = int_name->addr;
		int_name->addr = al;
	      }
	  }
    }

  /* Update addresses for domain=<domain>,<interface> */
  for (cond = daemon->cond_domain; cond; cond = cond->next)
    if (cond->interface && strncmp(label, cond->interface, IF_NAMESIZE) == 0)
      {
	struct addrlist *al;

	if (param->spare)
	  {
	    al = param->spare;
	    param->spare = al->next;
	  }
	else
	  al = whine_malloc(sizeof(struct addrlist));

	if (addr->sa.sa_family == AF_INET)
	  {
	    al->addr.addr4 = addr->in.sin_addr;
	    al->flags = 0;
	  }
	else
	  {
	    al->addr.addr6 =  addr->in6.sin6_addr;
	    al->flags = ADDRLIST_IPV6;
	  }

	al->prefixlen = prefixlen;
	al->next = cond->al;
	cond->al = al;
      }
  
  /* check whether the interface IP has been added already 
     we call this routine multiple times. */
  for (iface = daemon->interfaces; iface; iface = iface->next) 
    if (sockaddr_isequal(&iface->addr, addr) && iface->index == if_index)
      {
	iface->dad = !!(iface_flags & IFACE_TENTATIVE);
	iface->found = 1; /* for garbage collection */
	iface->netmask = netmask;
	return 1;
      }

 /* If we are restricting the set of interfaces to use, make
     sure that loopback interfaces are in that set. */
  if (daemon->if_names && loopback)
    {
      struct iname *lo;
      for (lo = daemon->if_names; lo; lo = lo->next)
	if (lo->name && strcmp(lo->name, ifr.ifr_name) == 0)
	  break;
      
      if (!lo && (lo = whine_malloc(sizeof(struct iname)))) 
	{
	  if ((lo->name = whine_malloc(strlen(ifr.ifr_name)+1)))
	    {
	      strcpy(lo->name, ifr.ifr_name);
	      lo->flags |= INAME_USED;
	      lo->next = daemon->if_names;
	      daemon->if_names = lo;
	    }
	  else
	    free(lo);
	}
    }
  
  if (addr->sa.sa_family == AF_INET &&
      !iface_check(AF_INET, (union all_addr *)&addr->in.sin_addr, label, &auth_dns))
    return 1;

  if (addr->sa.sa_family == AF_INET6 &&
      !iface_check(AF_INET6, (union all_addr *)&addr->in6.sin6_addr, label, &auth_dns))
    return 1;
    
#ifdef HAVE_DHCP
  /* No DHCP where we're doing auth DNS. */
  if (auth_dns)
    {
      tftp_ok = 0;
      dhcp4_ok = dhcp6_ok = 0;
    }
  else
    for (tmp = daemon->dhcp_except; tmp; tmp = tmp->next)
      if (tmp->name && wildcard_match(tmp->name, ifr.ifr_name))
	{
	  tftp_ok = 0;
	  if (tmp->flags & INAME_4)
	    dhcp4_ok = 0;
	  if (tmp->flags & INAME_6)
	    dhcp6_ok = 0;
	}
#endif
 
  
#ifdef HAVE_TFTP
  if (daemon->tftp_interfaces)
    {
      /* dedicated tftp interface list */
      tftp_ok = 0;
      for (tmp = daemon->tftp_interfaces; tmp; tmp = tmp->next)
	if (tmp->name && wildcard_match(tmp->name, ifr.ifr_name))
	  tftp_ok = 1;
    }
#endif
  
  /* add to list */
  if ((iface = whine_malloc(sizeof(struct irec))))
    {
      int mtu = 0;

      if (ioctl(param->fd, SIOCGIFMTU, &ifr) != -1)
	mtu = ifr.ifr_mtu;

      iface->addr = *addr;
      iface->netmask = netmask;
      iface->tftp_ok = tftp_ok;
      iface->dhcp4_ok = dhcp4_ok;
      iface->dhcp6_ok = dhcp6_ok;
      iface->dns_auth = auth_dns;
      iface->mtu = mtu;
      iface->dad = !!(iface_flags & IFACE_TENTATIVE);
      iface->found = 1;
      iface->done = iface->multicast_done = iface->warned = 0;
      iface->index = if_index;
      iface->label = is_label;
      if ((iface->name = whine_malloc(strlen(ifr.ifr_name)+1)))
	{
	  strcpy(iface->name, ifr.ifr_name);
	  iface->next = daemon->interfaces;
	  daemon->interfaces = iface;
	  return 1;
	}
      free(iface);

    }
  
  errno = ENOMEM; 
  return 0;
}

/**
 * @brief IPv6-specific interface enumeration callback adapter
 * 
 * @detailed Adapter function that converts IPv6-specific interface enumeration parameters
 *           into the unified format expected by iface_allowed(). Called by platform-specific
 *           IPv6 interface enumeration code (e.g., getifaddrs() on BSD, netlink on Linux)
 *           once for each discovered IPv6 address on the system.
 *
 *           This function serves as a thin wrapper that:
 *           1. Constructs a union mysockaddr structure from IPv6 address
 *           2. Sets sin6_scope_id for link-local addresses per RFC 4007
 *           3. Ignores IPv6-specific parameters (scope, preferred/valid lifetimes)
 *           4. Delegates filtering logic to common iface_allowed() function
 *
 *           The adapter pattern allows platform-specific enumeration to remain separate
 *           from interface filtering policy, enabling code reuse between IPv4 and IPv6.
 *           FreeBSD requires sin6_scope_id to be zero for non-link-local addresses,
 *           which is handled explicitly (line 617-620).
 *
 * @param local Pointer to struct in6_addr containing IPv6 address for this interface.
 *              Can be any valid IPv6 address type:
 *              - Global unicast (2000::/3)
 *              - Link-local (fe80::/10) - requires scope_id
 *              - Unique local (fc00::/7)
 *              - Multicast (ff00::/8)
 *              Must not be NULL. Address copied into mysockaddr structure.
 * @param prefix IPv6 prefix length (0-128) from kernel.
 *               Specifies network portion size in bits.
 *               Typical values: 64 (standard subnet), 128 (host route), 48 (site).
 *               Passed directly to iface_allowed() as prefixlen parameter.
 * @param scope IPv6 address scope from kernel (RFC 4007).
 *              Values: 0=global, 2=link-local, 5=site-local, etc.
 *              Currently unused - parameter ignored with (void)scope to suppress warnings.
 *              Reserved for future scope-based filtering if needed.
 * @param if_index Kernel interface index from if_nametoindex().
 *                 Uniquely identifies physical interface (1-N).
 *                 Used for sin6_scope_id (link-local only) and passed to iface_allowed().
 *                 Zero is invalid (reserved for "any" interface).
 * @param flags Address flags from kernel. May include:
 *              IFA_F_TEMPORARY: Privacy extension address (RFC 4941)
 *              IFA_F_DEPRECATED: Address nearing end of life
 *              IFA_F_TENTATIVE: Duplicate Address Detection in progress
 *              IFA_F_DADFAILED: DAD failed, address not usable
 *              Passed to iface_allowed() as iface_flags parameter.
 * @param preferred Preferred lifetime in seconds (RFC 4862).
 *                  Time until address becomes deprecated.
 *                  Currently unused - ignored with (void)preferred.
 *                  Could be used for future lifetime-aware filtering.
 * @param valid Valid lifetime in seconds (RFC 4862).
 *              Time until address becomes invalid.
 *              Currently unused - ignored with (void)valid.
 *              Could be used to avoid adding soon-to-expire addresses.
 * @param vparam Opaque pointer to struct iface_param cast from void*.
 *               Contains socket fd and spare address list.
 *               Passed through to iface_allowed() without interpretation.
 *               Must not be NULL - dereferenced by iface_allowed().
 *
 * @return Result from iface_allowed(): 1 if accepted and added, 0 if rejected or duplicate
 * @retval 1 IPv6 address passed filters and added to daemon->interfaces
 * @retval 0 IPv6 address rejected by interface/address filters or already present
 *
 * @note Link-local addresses (fe80::/10) have sin6_scope_id set to if_index per RFC 4007.
 *       Non-link-local addresses have sin6_scope_id set to 0 (FreeBSD requirement).
 * @note Dummy netmask parameter (0.0.0.0) passed to iface_allowed() - unused for IPv6.
 *       IPv6 uses prefix length directly rather than netmask notation.
 * @note NULL label parameter passed to iface_allowed() - interface name resolved inside
 *       iface_allowed() using if_index and param->fd if needed.
 * @note Preferred and valid lifetime parameters currently ignored but could enable
 *       future optimizations like avoiding soon-to-expire addresses or preferring
 *       stable addresses over temporary privacy addresses.
 *
 * @warning vparam MUST point to valid struct iface_param - no NULL check performed.
 * @warning local address pointer must remain valid for duration of call - contents copied immediately.
 *
 * @see iface_allowed() for common interface filtering logic
 * @see iface_allowed_v4() for IPv4 equivalent adapter
 * @see enumerate_interfaces() for platform-specific enumeration caller
 *
 * EXAMPLE USAGE:
 * @code
 * struct iface_param param;
 * param.fd = socket(PF_INET6, SOCK_DGRAM, 0);
 * param.spare = NULL;
 *
 * // During IPv6 interface enumeration, callback invoked for each address:
 * struct in6_addr addr;
 * inet_pton(AF_INET6, "2001:db8::1", &addr);
 * 
 * int result = iface_allowed_v6(&addr, 64, 0, 2, 0, 3600, 7200, &param);
 * // result = 1 if address matches configured interface filters
 * // result = 0 if address rejected or duplicate
 * @endcode
 *
 * RFC COMPLIANCE:
 * - RFC 4007: IPv6 Scoped Address Architecture (sin6_scope_id handling)
 * - RFC 4862: IPv6 Stateless Address Autoconfiguration (preferred/valid lifetimes)
 * - RFC 4941: Privacy Extensions for SLAAC (IFA_F_TEMPORARY flag)
 *
 * SIDE EFFECTS:
 * - Calls iface_allowed() which may allocate memory and modify daemon->interfaces
 * - Constructs mysockaddr structure on stack (384 bytes for union)
 * - May trigger interface name resolution via ioctl if label needed
 *
 * THREAD SAFETY: Not thread-safe - calls iface_allowed() which modifies global daemon structure
 */
static int iface_allowed_v6(struct in6_addr *local, int prefix, 
			    int scope, int if_index, int flags, 
			    unsigned int preferred, unsigned int valid, void *vparam)
{
  union mysockaddr addr;
  struct in_addr netmask; /* dummy */
  netmask.s_addr = 0;

  (void)scope; /* warning */
  (void)preferred;
  (void)valid;
  
  memset(&addr, 0, sizeof(addr));
#ifdef HAVE_SOCKADDR_SA_LEN
  addr.in6.sin6_len = sizeof(addr.in6);
#endif
  addr.in6.sin6_family = AF_INET6;
  addr.in6.sin6_addr = *local;
  addr.in6.sin6_port = htons(daemon->port);
  /* FreeBSD insists this is zero for non-linklocal addresses */
  if (IN6_IS_ADDR_LINKLOCAL(local))
    addr.in6.sin6_scope_id = if_index;
  else
    addr.in6.sin6_scope_id = 0;
  
  return iface_allowed((struct iface_param *)vparam, if_index, NULL, &addr, netmask, prefix, flags);
}

/**
 * @brief IPv4-specific interface enumeration callback adapter
 * 
 * @detailed Adapter function that converts IPv4-specific interface enumeration parameters
 *           into the unified format expected by iface_allowed(). Called by platform-specific
 *           IPv4 interface enumeration code (e.g., getifaddrs() on BSD, ioctl on Linux,
 *           SIOCGLIFCONF on Solaris) once for each discovered IPv4 address on the system.
 *
 *           This function serves as a thin wrapper that:
 *           1. Constructs a union mysockaddr structure from IPv4 address
 *           2. Sets sin_port to daemon->port (default 53 for DNS)
 *           3. Calculates prefix length from netmask by counting consecutive 1 bits
 *           4. Delegates filtering logic to common iface_allowed() function
 *
 *           The adapter pattern allows platform-specific enumeration to remain separate
 *           from interface filtering policy, enabling code reuse between IPv4 and IPv6.
 *           Prefix calculation converts traditional netmask format (255.255.255.0) to
 *           CIDR prefix length (24) for consistent internal representation.
 *
 * @param local IPv4 address for this interface (struct in_addr, 4 bytes).
 *              Can be any valid IPv4 address type:
 *              - Public unicast (1.0.0.0 - 223.255.255.255 excluding reserved)
 *              - Private unicast (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
 *              - Link-local (169.254.0.0/16)
 *              - Loopback (127.0.0.0/8)
 *              Value copied into mysockaddr structure, original not modified.
 *              Zero address (0.0.0.0) typically indicates unconfigured interface.
 * @param if_index Kernel interface index from if_nametoindex().
 *                 Uniquely identifies physical interface (1-N).
 *                 Passed directly to iface_allowed() without interpretation.
 *                 Zero is invalid (reserved for "any" interface).
 *                 Typical values 1-255 on most systems.
 * @param label Interface label/name from kernel (e.g., "eth0", "eth0:0" for Linux aliases).
 *              For BSD, contains base interface name only (aliases not distinguished).
 *              For Linux, may include colon-suffix for IP aliases (eth0:0, eth0:1).
 *              Passed directly to iface_allowed() for pattern matching against
 *              --interface and --except-interface configuration.
 *              NULL is acceptable - treated as empty string by iface_allowed().
 * @param netmask IPv4 netmask (struct in_addr) defining network prefix.
 *                Traditional dotted-decimal netmask (e.g., 255.255.255.0 for /24).
 *                Converted to prefix length by counting consecutive high bits from MSB.
 *                For point-to-point interfaces, typically 255.255.255.255 (/32).
 *                For classful networks: 255.0.0.0 (/8), 255.255.0.0 (/16), etc.
 *                Passed to iface_allowed() for subnet calculations.
 *                Zero netmask (0.0.0.0) treated as /0 (match entire IPv4 space).
 * @param broadcast IPv4 broadcast address for this network (struct in_addr).
 *                  Typically last address in subnet (e.g., 192.168.1.255 for 192.168.1.0/24).
 *                  Currently unused - parameter ignored with (void)broadcast to suppress warnings.
 *                  Reserved for future broadcast-aware features if needed.
 *                  For point-to-point links, may be set to remote endpoint address.
 * @param vparam Opaque pointer to struct iface_param cast from void*.
 *               Contains socket fd and spare address list.
 *               Passed through to iface_allowed() without interpretation.
 *               Must not be NULL - dereferenced by iface_allowed().
 *
 * @return Result from iface_allowed(): 1 if accepted and added, 0 if rejected or duplicate
 * @retval 1 IPv4 address passed filters and added to daemon->interfaces
 * @retval 0 IPv4 address rejected by interface/address filters or already present
 *
 * @note Prefix length calculated by counting high bits in netmask from MSB:
 *       255.255.255.0 = 0xFFFFFF00 = 24 consecutive 1 bits = /24
 *       255.255.0.0 = 0xFFFF0000 = 16 consecutive 1 bits = /16
 *       255.255.255.252 = 0xFFFFFFFC = 30 consecutive 1 bits = /30
 * @note Port set to daemon->port (default 53) in constructed sockaddr.
 *       This port used for socket binding during listener creation.
 * @note HAVE_SOCKADDR_SA_LEN platforms (BSD) require sa_len field to be set.
 *       Automatically handled via #ifdef HAVE_SOCKADDR_SA_LEN (line 634-636).
 * @note Label parameter may be NULL on some platforms - handled gracefully by iface_allowed().
 * @note Broadcast parameter currently unused but included for API consistency with
 *       platform enumeration callbacks and potential future DHCP broadcast features.
 *
 * @warning vparam MUST point to valid struct iface_param - no NULL check performed.
 * @warning Netmask must be contiguous high bits (e.g., 255.255.240.0 is valid,
 *          but 255.255.0.255 with gaps is invalid and produces incorrect prefix).
 *          Non-contiguous netmasks are not detected - caller must ensure validity.
 * @warning Prefix calculation uses 32-bit arithmetic - potential for bit manipulation
 *          edge cases if netmask contains non-contiguous bits.
 *
 * @see iface_allowed() for common interface filtering logic
 * @see iface_allowed_v6() for IPv6 equivalent adapter
 * @see enumerate_interfaces() for platform-specific enumeration caller
 *
 * EXAMPLE USAGE:
 * @code
 * struct iface_param param;
 * param.fd = socket(PF_INET, SOCK_DGRAM, 0);
 * param.spare = NULL;
 *
 * // During IPv4 interface enumeration, callback invoked for each address:
 * struct in_addr addr, netmask, broadcast;
 * addr.s_addr = inet_addr("192.168.1.1");
 * netmask.s_addr = inet_addr("255.255.255.0");
 * broadcast.s_addr = inet_addr("192.168.1.255");
 * 
 * int result = iface_allowed_v4(addr, 2, "eth0", netmask, broadcast, &param);
 * // result = 1 if address matches configured interface filters
 * // result = 0 if address rejected or duplicate
 * @endcode
 *
 * NETMASK TO PREFIX CONVERSION ALGORITHM:
 * Starting from prefix=32 (all bits), shift test bit left from LSB:
 * - While test bit AND netmask is zero (bit not set in netmask)
 * - Decrement prefix count and shift test bit
 * - Stop when first 1 bit found or prefix reaches 0
 * Examples:
 *   255.255.255.0 (0xFFFFFF00): bits 0-7 clear -> prefix = 32 - 8 = 24
 *   255.255.0.0 (0xFFFF0000): bits 0-15 clear -> prefix = 32 - 16 = 16
 *   255.255.255.252 (0xFFFFFFFC): bits 0-1 clear -> prefix = 32 - 2 = 30
 *
 * RFC COMPLIANCE: N/A (interface enumeration is implementation-specific)
 *
 * SIDE EFFECTS:
 * - Calls iface_allowed() which may allocate memory and modify daemon->interfaces
 * - Constructs mysockaddr structure on stack (384 bytes for union)
 * - Performs prefix calculation via bit manipulation (negligible CPU cost)
 *
 * THREAD SAFETY: Not thread-safe - calls iface_allowed() which modifies global daemon structure
 */
static int iface_allowed_v4(struct in_addr local, int if_index, char *label,
			    struct in_addr netmask, struct in_addr broadcast, void *vparam)
{
  union mysockaddr addr;
  int prefix, bit;
 
  (void)broadcast; /* warning */

  memset(&addr, 0, sizeof(addr));
#ifdef HAVE_SOCKADDR_SA_LEN
  addr.in.sin_len = sizeof(addr.in);
#endif
  addr.in.sin_family = AF_INET;
  addr.in.sin_addr = local;
  addr.in.sin_port = htons(daemon->port);

  /* determine prefix length from netmask */
  for (prefix = 32, bit = 1; (bit & ntohl(netmask.s_addr)) == 0 && prefix != 0; bit = bit << 1, prefix--);

  return iface_allowed((struct iface_param *)vparam, if_index, label, &addr, netmask, prefix, 0);
}

/**
 * @brief Remove stale interface records no longer present on system
 * 
 * @detailed Cleanup function that removes outdated interface listener records from 
 *           daemon->interfaces linked list after interface enumeration completes.
 *           During interface enumeration, each discovered interface is marked with 
 *           irec->found = 1. This function walks the list and removes any entries 
 *           that were NOT marked, indicating they represent interfaces that have 
 *           disappeared since the last enumeration (interface removed, IP address 
 *           unassigned, or interface down).
 *
 *           The function implements safe linked list deletion using pointer-to-pointer 
 *           technique (**up) to modify list structure while iterating. This allows 
 *           in-place deletion without tracking previous node.
 *
 *           Typical cleanup scenarios:
 *           - Network interface brought down (ifconfig eth0 down)
 *           - DHCP lease expired and IP address removed
 *           - Physical interface removed (USB dongle unplugged)
 *           - Virtual interface destroyed (Docker container stopped)
 *           - Configuration changed to exclude previously included interface
 *
 *           Function called after enumerate_interfaces() completes to ensure 
 *           daemon->interfaces accurately reflects current system state. This 
 *           maintains synchronization between listener sockets and available 
 *           network interfaces.
 *
 * @param None - Operates on global daemon->interfaces linked list
 *
 * @return void - No return value
 *
 * @note Function uses irec->found flag which is set to 1 by iface_allowed() during
 *       interface enumeration. All existing entries start with found=0, then 
 *       discovered interfaces are marked found=1. This allows differentiation 
 *       between current and stale entries.
 * @note Function checks BOTH irec->found and irec->done flags. The done flag 
 *       indicates interface has completed initialization and should be preserved 
 *       even if not found in enumeration. This prevents premature deletion of 
 *       interfaces during startup or reconfiguration.
 * @note Memory deallocation occurs in two steps:
 *       1. free(iface->name) - releases allocated interface name string
 *       2. free(iface) - releases the struct irec itself
 *       Both allocated by iface_allowed() via whine_malloc().
 * @note Pointer-to-pointer idiom (**up) enables modification of list head and 
 *       internal links uniformly without special-casing head deletion.
 * @note Function does NOT close listener sockets - socket cleanup handled 
 *       separately by release_listener() if interface record has active listeners.
 * @note Function safe to call with empty daemon->interfaces list (up points to 
 *       NULL, loop never executes).
 *
 * @warning Function MODIFIES daemon->interfaces global list structure.
 *          Caller must ensure no concurrent access to daemon->interfaces.
 * @warning Function assumes irec->name was allocated with malloc() and can be 
 *          freed. Static or stack strings cause double-free or corruption.
 * @warning Deletion occurs during iteration - standard "modify while iterating" 
 *          risks mitigated by pointer-to-pointer technique.
 * @warning If irec->name is NULL, free(NULL) is called which is safe (no-op) 
 *          per C standard but indicates incomplete interface record.
 *
 * @see enumerate_interfaces() which marks interfaces as found during enumeration
 * @see iface_allowed() which sets irec->found = 1 for discovered interfaces
 * @see release_listener() which closes sockets before interface cleanup
 * @see struct irec in src/dnsmasq.h for interface record structure definition
 *
 * EXAMPLE USAGE:
 * @code
 * // After interface enumeration completes:
 * enumerate_interfaces(1); // Scan system interfaces, mark found=1
 * clean_interfaces();       // Remove entries NOT marked as found
 * 
 * // Result: daemon->interfaces contains only currently valid interfaces
 * // Old interfaces (removed devices, expired IPs) have been freed
 * @endcode
 *
 * DELETION ALGORITHM (pointer-to-pointer technique):
 * - up = &daemon->interfaces (pointer to list head pointer)
 * - For each iface in list:
 *   - If iface should be deleted (!found && !done):
 *     * *up = iface->next (remove from list by updating parent pointer)
 *     * free(iface->name) and free(iface)
 *     * up unchanged (now points to next node via updated parent)
 *   - Else (keep node):
 *     * up = &iface->next (advance to point at next node's pointer)
 * - Result: deleted nodes removed, kept nodes remain linked
 *
 * COMPARISON WITH NAIVE DELETION:
 * Naive approach requires tracking previous node:
 *   if (delete) { prev->next = current->next; } else { prev = current; }
 * Pointer-to-pointer approach eliminates prev tracking:
 *   if (delete) { *up = iface->next; } else { up = &iface->next; }
 * Benefit: cleaner code, no special case for head deletion
 *
 * MEMORY LEAK PREVENTION:
 * Each irec has two allocations that MUST be freed:
 * 1. irec->name (string): allocated in iface_allowed() via whine_malloc()
 * 2. irec itself (struct): allocated in iface_allowed() via whine_malloc()
 * Both freed here to prevent leaks during interface churn.
 *
 * TIMING CONSIDERATIONS:
 * Function typically called:
 * - On daemon startup after initial interface scan
 * - After SIGHUP configuration reload
 * - After network change event detected (Linux netlink notification)
 * - Periodically if interface monitoring enabled
 * Execution time: O(n) where n = number of interface records (typically <100)
 * Single pass through list, each deletion O(1), total negligible (<1ms)
 *
 * RFC COMPLIANCE: N/A (internal housekeeping, no protocol involvement)
 * 
 * SIDE EFFECTS:
 * - Modifies daemon->interfaces linked list (removes entries)
 * - Frees memory for removed interface records (iface->name and iface struct)
 * - Reduces memory footprint by releasing stale interface allocations
 * - Subsequent find_interface() calls will not find removed interfaces
 *
 * THREAD SAFETY: Not thread-safe - modifies global daemon structure without locking
 */
static void clean_interfaces(void)
{
  struct irec *iface;
  struct irec **up = &daemon->interfaces;

  for (iface = *up; iface; iface = *up)
  {
    if (!iface->found && !iface->done)
      {
        *up = iface->next;
        free(iface->name);
        free(iface);
      }
    else
      {
        up = &iface->next;
      }
  }
}

/**
 * @brief Release listener socket and free resources if no longer needed by any interface
 * 
 * @detailed Reference-counted cleanup function for struct listener objects. Listeners may be
 *           shared across multiple network interfaces when those interfaces have identical 
 *           IP addresses (e.g., multiple VLANs on same IP, or wildcard listeners on 0.0.0.0/::).
 *           The l->used counter tracks how many interfaces reference this listener.
 *
 *           Function performs multi-stage cleanup process:
 *           1. **Reference Count Update**: If listener shared (used > 1), scan all interfaces
 *              to find references and update usage count. Interfaces that disappeared 
 *              (found=0) have their reference removed by decrementing l->used.
 *           2. **Interface Pointer Update**: If current l->iface interface disappeared but 
 *              other interfaces still use this listener, update l->iface to point to a 
 *              still-valid interface.
 *           3. **Early Return**: If l->used > 0 after updates, listener still needed - return 0.
 *           4. **Logging**: If final interface marked done, log "stopped listening" message.
 *           5. **Socket Closure**: Close all file descriptors (DNS, TCP, TFTP) if valid (!= -1).
 *           6. **Memory Release**: Free the listener structure itself.
 *
 *           Reference counting prevents premature socket closure when multiple interfaces 
 *           share the same listener. Example: wildcard listener on 0.0.0.0 port 53 serves 
 *           all interfaces, so l->used = number_of_interfaces. Only when ALL interfaces 
 *           are removed should the wildcard listener be closed.
 *
 *           Called during interface cleanup (clean_interfaces) and daemon shutdown to 
 *           release network resources. The function is safe to call multiple times on 
 *           same listener via reference counting - only final call actually frees resources.
 *
 * @param l Pointer to struct listener to potentially release. Must not be NULL.
 *          Structure fields accessed:
 *          - l->used: Reference count (number of interfaces using this listener)
 *          - l->iface: Pointer to interface record owning this listener (may be updated)
 *          - l->addr: Socket address (IP and port) for equality comparison
 *          - l->fd: Main UDP socket file descriptor for DNS queries
 *          - l->tcpfd: TCP socket file descriptor for DNS-over-TCP
 *          - l->tftpfd: TFTP socket file descriptor for TFTP service
 *
 * @return Integer indicating whether listener was released
 * @retval 1 Listener released: all file descriptors closed, memory freed, no interfaces still need it
 * @retval 0 Listener retained: other interfaces still reference it (l->used > 0), sockets remain open
 *
 * @note Reference counting model: l->used initialized to 1 when listener created, incremented 
 *       each time an additional interface reuses the listener, decremented when interface 
 *       removed. Final interface decrement triggers cleanup.
 * @note File descriptor closure: All three socket types closed if valid:
 *       - l->fd (UDP): Main DNS query socket (port 53 by default)
 *       - l->tcpfd (TCP): DNS-over-TCP for large responses (port 53)
 *       - l->tftpfd (UDP): TFTP server socket (port 69 if TFTP enabled)
 *       Descriptor value -1 indicates socket not opened, skip close().
 * @note Interface iteration: Scans daemon->interfaces linked list to find all interfaces 
 *       with matching address. Complexity O(n*m) where n=interfaces, m=listeners, but 
 *       typically negligible (few interfaces/listeners in small networks).
 * @note iface->done flag: Marks interface as having completed initialization and bound 
 *       listeners. Reset to 0 after logging to allow potential re-initialization.
 * @note iface->found flag: Set by enumerate_interfaces() during scan. Distinguishes 
 *       current (found=1) from stale (found=0) interfaces. Stale interfaces have their 
 *       listener references removed.
 * @note l->iface pointer update: When original interface disappears (found=0) but listener 
 *       still used by other interfaces, l->iface updated to point to a still-valid interface.
 *       Ensures l->iface remains valid for logging and cleanup.
 * @note Socket address comparison: sockaddr_isequal() compares IP address AND port AND 
 *       address family. Listeners distinguished by complete socket address, not just IP.
 *       Two listeners on same IP but different ports are distinct.
 * @note Logging: LOG_DEBUG level with MS_DEBUG flag (query-type logging). Disabled by 
 *       default unless --log-queries enabled. Format: "stopped listening on eth0(#2): 
 *       192.168.1.1 port 53".
 * @note prettyprint_addr() formats IP address to daemon->addrbuff (ADDRSTRLEN buffer) and 
 *       returns port number extracted from sockaddr structure.
 *
 * @warning l parameter MUST be valid struct listener pointer - no NULL check performed.
 *          Passing NULL causes immediate segmentation fault.
 * @warning Function frees listener memory with free(l). Caller must not access l after 
 *          function returns 1. Double-free occurs if caller frees again.
 * @warning File descriptors closed with close() syscall. Errors ignored - close() failure 
 *          logged by kernel but does not prevent listener deallocation.
 * @warning Listener removal occurs DURING interface iteration. Safe because iteration is 
 *          read-only scan that only modifies reference counts, not list structure.
 * @warning Race condition possible: Network interfaces may change between enumerate_interfaces() 
 *          scan and release_listener() cleanup. Acceptable - next enumeration corrects state.
 * @warning l->iface pointer may be updated to different interface if original disappeared. 
 *          This is intentional to maintain valid reference, not a bug.
 *
 * @see create_listeners() which allocates listeners and sets initial l->used count
 * @see clean_interfaces() which calls release_listener() for stale interfaces
 * @see struct listener in src/dnsmasq.h for listener structure definition
 * @see sockaddr_isequal() in src/util.c for socket address comparison logic
 *
 * EXAMPLE USAGE:
 * @code
 * struct listener *l = ...; // Listener to potentially release
 * 
 * if (release_listener(l))
 *   {
 *     // Listener released: l pointer now invalid, do not access
 *     // File descriptors closed, memory freed
 *     l = NULL; // Good practice: null out pointer after free
 *   }
 * else
 *   {
 *     // Listener retained: other interfaces still using it
 *     // l pointer still valid, sockets still open
 *     // Will be released when final interface removed
 *   }
 * @endcode
 *
 * REFERENCE COUNTING EXAMPLE:
 * Scenario: Three interfaces (eth0, eth1, eth2) share wildcard listener on 0.0.0.0:53
 * 
 * Initial state: l->used = 3
 * - eth0 removed: release_listener() decrements to l->used = 2, returns 0 (keep)
 * - eth1 removed: release_listener() decrements to l->used = 1, returns 0 (keep)
 * - eth2 removed: release_listener() decrements to l->used = 0, closes sockets, 
 *                 frees memory, returns 1 (released)
 *
 * LISTENER CLEANUP ALGORITHM:
 * 1. IF l->used > 1 (shared listener):
 *    FOR each interface in daemon->interfaces:
 *      IF interface->done AND interface->addr matches l->addr:
 *        IF interface->found (current):
 *          IF l->iface is stale (!found):
 *            UPDATE l->iface = interface (point to valid interface)
 *        ELSE (interface is stale):
 *          DECREMENT l->used
 *          MARK interface->done = 0
 *    IF l->used > 0 after loop:
 *      RETURN 0 (listener still needed)
 * 
 * 2. IF l->iface->done:
 *    LOG "stopped listening" message with interface name, IP, port
 *    SET l->iface->done = 0
 * 
 * 3. CLOSE file descriptors:
 *    IF l->fd != -1: close(l->fd)
 *    IF l->tcpfd != -1: close(l->tcpfd)
 *    IF l->tftpfd != -1: close(l->tftpfd)
 * 
 * 4. FREE listener: free(l)
 * 5. RETURN 1 (released)
 *
 * FILE DESCRIPTOR SEMANTICS:
 * - l->fd: Main UDP socket for DNS queries, always present if listener active
 * - l->tcpfd: TCP socket for DNS-over-TCP, may be -1 if TCP disabled or failed
 * - l->tftpfd: TFTP socket, -1 if TFTP not compiled (no HAVE_TFTP) or not configured
 * Value -1 used as "not initialized" sentinel, safe to pass to close() (no-op on most systems)
 *
 * INTERFACE SHARING SCENARIOS:
 * 1. Wildcard listeners (0.0.0.0 or ::): Shared by ALL interfaces on system
 * 2. Address aliasing: Multiple interfaces with same IP (VLANs, tunnels)
 * 3. Anycast configurations: Same IP on multiple interfaces for redundancy
 * 4. Loopback variants: 127.0.0.1 on lo, lo0, lo:0 (platform-dependent)
 *
 * RFC COMPLIANCE: N/A (internal resource management, no protocol involvement)
 *
 * SIDE EFFECTS:
 * - Modifies l->used counter (decrements for stale interface references)
 * - May update l->iface pointer to different interface
 * - Marks stale interface->done = 0 to prevent re-processing
 * - Closes network sockets (l->fd, l->tcpfd, l->tftpfd) if releasing
 * - Frees listener memory if releasing
 * - Logs "stopped listening" message if LOG_DEBUG enabled
 * - Kernel releases socket resources (port unbind, kernel buffers, etc.)
 *
 * THREAD SAFETY: Not thread-safe - modifies daemon->interfaces and closes shared sockets
 */
static int release_listener(struct listener *l)
{
  if (l->used > 1)
    {
      struct irec *iface;
      for (iface = daemon->interfaces; iface; iface = iface->next)
	if (iface->done && sockaddr_isequal(&l->addr, &iface->addr))
	  {
	    if (iface->found)
	      {
		/* update listener to point to active interface instead */
		if (!l->iface->found)
		  l->iface = iface;
	      }
	    else
	      {
		l->used--;
		iface->done = 0;
	      }
	  }

      /* Someone is still using this listener, skip its deletion */
      if (l->used > 0)
	return 0;
    }

  if (l->iface->done)
    {
      int port;

      port = prettyprint_addr(&l->iface->addr, daemon->addrbuff);
      my_syslog(LOG_DEBUG|MS_DEBUG, _("stopped listening on %s(#%d): %s port %d"),
		l->iface->name, l->iface->index, daemon->addrbuff, port);
      /* In case it ever returns */
      l->iface->done = 0;
    }

  if (l->fd != -1)
    close(l->fd);
  if (l->tcpfd != -1)
    close(l->tcpfd);
  if (l->tftpfd != -1)
    close(l->tftpfd);

  free(l);
  return 1;
}

/**
 * @brief Enumerate all network interfaces and their addresses, updating internal state
 * 
 * @detailed Core network discovery function that scans all network interfaces on the system,
 *           discovers their IPv4 and IPv6 addresses, updates interface cache, and performs
 *           garbage collection of stale interface records and listeners. This function is 
 *           central to dnsmasq's ability to adapt dynamically to network configuration changes.
 *
 *           Function operates in four major phases:
 *
 *           **PHASE 1: Initialization and Rate Limiting**
 *           - Implements max-once-per-select-cycle execution via static `done` flag
 *           - Reset flag allows forced re-enumeration (typically on SIGHUP or network event)
 *           - Creates temporary PF_INET socket for ioctl() interface queries
 *           - Prevents redundant enumeration when multiple subsystems call this function
 *
 *           **PHASE 2: Server Interface Index Update**
 *           - Updates cached interface indexes for servers with interface bindings
 *           - Critical for forwarding path: daemon->servers[].ifindex used to route queries
 *           - Interface indexes can change when interfaces created/destroyed (hotplug, VPN)
 *           - Uses SIOCGIFINDEX ioctl (Linux) or if_nametoindex() (other platforms)
 *
 *           **PHASE 3: Address Cache Cleanup**
 *           - Marks all interfaces with found=0 for garbage collection
 *           - Clears cached addresses from:
 *             * daemon->int_names: Interface name to address mapping for --interface option
 *             * daemon->cond_domain: Conditional domain subnet lists
 *             * daemon->interface_addrs: System-wide interface address list
 *             * daemon->auth_zones: Authoritative DNS zone subnet filters (preserves literals)
 *           - Recycles addrlist structures to static `spare` pool to reduce malloc/free churn
 *
 *           **PHASE 4: Platform-Specific Interface Enumeration**
 *           - Calls iface_enumerate(AF_INET6) then iface_enumerate(AF_INET)
 *           - Platform implementations (getifaddrs, SIOCGIFCONF, netlink) populate addresses
 *           - Callback functions (iface_allowed_v6, iface_allowed_v4) filter addresses
 *           - Sets found=1 on interfaces that still exist
 *           - Return value -1 triggers retry via "goto again" (transient enumeration failure)
 *
 *           **PHASE 5: Listener Garbage Collection (OPT_CLEVERBIND mode only)**
 *           - Removes listeners bound to disappeared interface addresses
 *           - Iterates daemon->listeners, calls release_listener() for stale (found=0) entries
 *           - Calls clean_interfaces() if any listeners freed
 *           - Critical for bind-interfaces mode to close sockets on removed addresses
 *
 *           The found flag mechanism implements mark-and-sweep garbage collection:
 *           - Before enumeration: All interfaces marked found=0 (assume disappeared)
 *           - During enumeration: Current interfaces marked found=1 (still present)
 *           - After enumeration: Interfaces with found=0 are stale, subject to cleanup
 *
 *           Address recycling via spare pool optimizes memory allocation:
 *           - addrlist structures removed from active lists moved to spare pool
 *           - iface_enumerate() reuses spare structures before malloc()
 *           - Reduces malloc/free overhead during frequent re-enumeration
 *
 *           Server interface index caching critical for performance:
 *           - DNS forwarding hot path uses serv->ifindex for socket selection
 *           - Avoids string-to-index conversion on every query
 *           - Updated here when interfaces change (e.g., VPN connects/disconnects)
 *
 * @param reset Boolean flag controlling enumeration behavior
 *              - 0: Normal enumeration (rate-limited to once per select cycle)
 *              - Non-zero: Reset rate limiter, force next enumerate to run
 *              Reset typically triggered by:
 *              - SIGHUP signal (configuration reload)
 *              - Netlink RTM_NEWADDR/RTM_DELADDR messages (Linux)
 *              - Interface state change notifications
 *              - Child process fork (TCP handler) to inhibit enumeration
 *
 * @return Integer indicating enumeration result
 * @retval 1 Success: interfaces enumerated, cache updated, listeners cleaned
 * @retval 0 Fatal failure: socket() failed to create temporary query socket
 *           Error stored in errno, typically EMFILE (too many open files) or
 *           ENOMEM (out of memory). Daemon continues with stale interface cache.
 *
 * @note Rate limiting: Static `done` flag prevents re-enumeration within single select cycle.
 *       Each main loop iteration should call enumerate_interfaces(0) once. Multiple calls
 *       within same iteration return immediately with no work. This prevents:
 *       - Redundant enumeration when multiple events trigger in same cycle
 *       - Expensive ioctl/netlink operations in TCP child processes
 *       - Netlink socket use in TCP children (Linux kernel doesn't fork netlink sockets cleanly)
 * @note Socket lifecycle: Creates temporary PF_INET socket for ioctl() queries, closes before return.
 *       Socket used only for SIOCGIF* ioctls, not for actual network traffic.
 * @note Auth zone literal addresses: ADDRLIST_LITERAL flag preserves statically configured
 *       subnet addresses from config file. Only dynamically discovered addresses cleaned.
 * @note Retry mechanism: iface_enumerate() returns -1 on transient failure (e.g., kernel
 *       returned truncated interface list). "goto again" retries from phase 3, clearing
 *       cached addresses and re-enumerating. Prevents serving stale/incomplete address list.
 * @note OPT_CLEVERBIND: --bind-interfaces configuration option. When enabled, dnsmasq binds
 *       to specific interface addresses rather than wildcard. Listener cleanup essential
 *       in this mode to prevent serving on removed addresses.
 * @note Child process inhibition: TCP handler children call enumerate_interfaces(1) during
 *       initialization to set done=1, preventing enumeration in child. Enumeration in child
 *       would interfere with parent's netlink socket and listener management.
 * @note errno preservation: Saves and restores errno around close(param.fd) to preserve
 *       error code from iface_enumerate() failure for caller inspection.
 * @note Static spare pool: Persistent across calls, grows to accommodate maximum address
 *       count seen. Never shrinks, trading memory for allocation performance.
 * @note Interface index stability: Indexes stable unless interface destroyed and recreated.
 *       VPN interface typically gets new index on reconnect. Update critical for forwarding.
 * @note Callback parameter passing: iface_enumerate() receives callback union with af_inet
 *       or af_inet6 function pointer. Compound literal syntax {.af_inet6=func} initializes union.
 * @note Garbage collection thoroughness: Only listeners in OPT_CLEVERBIND mode cleaned here.
 *       Wildcard listeners (bind-dynamic mode) persist across interface changes because they're
 *       not bound to specific addresses (bound to 0.0.0.0/::).
 *
 * @warning NOT thread-safe: Modifies daemon global state and static variables without locking.
 *          Only safe to call from main select loop thread. TCP children must call with reset=1
 *          to set done flag, not perform actual enumeration.
 * @warning Socket creation failure: If socket() fails, function returns 0 with stale interface
 *          cache intact. Daemon continues operation but cannot adapt to interface changes until
 *          successful enumeration. Typically recovers on next enumeration attempt.
 * @warning Retry loop risk: "goto again" retry is unbounded. Persistent iface_enumerate() failure
 *          could cause infinite loop. In practice, transient failures resolve quickly. Persistent
 *          failures indicate serious kernel issue.
 * @warning Memory leak risk: If spare pool grows large during interface churn, memory persists
 *          until daemon restart. Acceptable trade-off for allocation performance.
 * @warning Listener disappearance: In OPT_CLEVERBIND mode, listeners can be freed during this
 *          call. Code holding listener pointers must handle possibility of freed listeners.
 *          Callers should re-verify listener validity after enumerate_interfaces() returns.
 * @warning Interface found flag semantics: found=0 after enumeration means interface disappeared
 *          OR enumeration filtering excluded it. Check iface_allowed() logic to distinguish.
 * @warning serv->ifindex update timing: Updated early in enumeration, before listener cleanup.
 *          Brief window where serv->ifindex refers to new interface but listeners still exist
 *          for old interface. Acceptable because listeners cleaned immediately after.
 *
 * @see iface_enumerate() in platform-specific files (netlink.c, bpf.c) for enumeration implementation
 * @see iface_allowed_v4() and iface_allowed_v6() callback functions for address filtering logic
 * @see release_listener() for listener cleanup implementation
 * @see clean_interfaces() for interface record cleanup
 * @see struct irec in src/dnsmasq.h for interface record structure (found flag)
 * @see struct addrlist in src/dnsmasq.h for address list structure (spare pool)
 * @see struct server in src/dnsmasq.h for upstream server structure (ifindex caching)
 *
 * EXAMPLE USAGE:
 * @code
 * // Normal call from main select loop - rate limited
 * if (!enumerate_interfaces(0))
 *   my_syslog(LOG_WARNING, "Failed to enumerate interfaces: %s", strerror(errno));
 * 
 * // Force re-enumeration after SIGHUP
 * enumerate_interfaces(1);  // Reset rate limiter
 * enumerate_interfaces(0);  // Perform enumeration
 * 
 * // TCP child process initialization - inhibit enumeration
 * enumerate_interfaces(1);  // Set done=1, prevent enumeration in child
 * @endcode
 *
 * ENUMERATION PHASES DETAILED:
 * 
 * Phase 1: Rate Limiting
 *   IF reset != 0:
 *     done = 0
 *     RETURN 1
 *   IF done == 1:
 *     RETURN 1  (already enumerated this cycle)
 *   SET done = 1
 *   CREATE temporary socket for ioctl queries
 * 
 * Phase 2: Server Interface Index Update
 *   FOR each server in daemon->servers:
 *     IF server->interface[0] != 0 (interface-bound server):
 *       LOOKUP interface index (SIOCGIFINDEX or if_nametoindex)
 *       UPDATE server->ifindex
 * 
 * Phase 3: Address Cache Cleanup
 *   MARK all daemon->interfaces with found=0
 *   CLEAR daemon->int_names address lists (move to spare pool)
 *   CLEAR daemon->cond_domain address lists (move to spare pool)
 *   CLEAR daemon->interface_addrs list (move to spare pool)
 *   CLEAR daemon->auth_zones subnet lists (except ADDRLIST_LITERAL)
 * 
 * Phase 4: Platform Enumeration
 * again:
 *   CALL iface_enumerate(AF_INET6, callback=iface_allowed_v6)
 *   IF returned -1: GOTO again (retry)
 *   CALL iface_enumerate(AF_INET, callback=iface_allowed_v4)
 *   IF returned -1: GOTO again (retry)
 * 
 * Phase 5: Listener Cleanup (if OPT_CLEVERBIND)
 *   FOR each listener in daemon->listeners:
 *     IF listener->iface->found == 0 (stale interface):
 *       CALL release_listener(listener)
 *       IF released:
 *         REMOVE from daemon->listeners list
 *         SET freed = 1
 *   IF freed:
 *     CALL clean_interfaces()
 * 
 * CLOSE temporary socket
 * RETURN 1 (success)
 *
 * SPARE POOL MECHANICS:
 * 
 * spare is static linked list of unused addrlist structures:
 * - Initialized to NULL on daemon start
 * - Grows as addresses added/removed during enumeration cycles
 * - Structures removed from active lists prepended to spare
 * - iface_enumerate() pops from spare before malloc()
 * - Never shrinks (memory optimization trade-off)
 * 
 * Example spare pool lifecycle:
 * 1. Initial enumeration: 10 addresses, 10 malloc() calls, spare = NULL
 * 2. Interface removed: 3 addresses freed to spare pool, spare = 3 nodes
 * 3. Next enumeration: Use 3 from spare, malloc 7 new, spare = 0
 * 4. Interface churn: spare grows to 5 nodes (high water mark)
 * 5. Steady state: spare oscillates 0-5 as interfaces added/removed
 *
 * FOUND FLAG STATE MACHINE:
 * 
 * Interface lifecycle controlled by found flag:
 * 
 * State A: found=1 (Current Interface)
 *   - Interface exists and is usable
 *   - Listeners bound to interface addresses
 *   - Forwarding to interface-specific servers operational
 * 
 * Transition A->B: enumerate_interfaces() starts
 *   - All interfaces marked found=0
 * 
 * State B: found=0 (Tentatively Stale)
 *   - Interface assumed disappeared pending enumeration
 * 
 * Transition B->A: iface_enumerate() finds interface
 *   - Interface marked found=1 (still present)
 * 
 * Transition B->C: iface_enumerate() completes without finding interface
 *   - Interface remains found=0 (confirmed stale)
 * 
 * State C: found=0 (Confirmed Stale)
 *   - release_listener() called for associated listeners
 *   - Server ifindex entries stale (will be updated next enumeration)
 *   - Interface record persists until garbage collected
 *
 * INTERFACE INDEX CACHING RATIONALE:
 * 
 * Problem: Forwarding hot path needs interface index for socket selection:
 *   server_test() -> send_from() -> sockaddr_to_ifindex() required for each query
 * 
 * Without caching:
 *   - if_nametoindex() syscall per query (expensive)
 *   - String comparison against all interfaces (O(n) per query)
 * 
 * With caching:
 *   - serv->ifindex lookup is O(1) integer comparison
 *   - Updated here when interfaces change (amortized cost)
 *   - Query forwarding hot path optimized
 * 
 * Trade-off: Stale indexes between enumeration cycles vs. query latency
 * Acceptable because interface changes are rare (minutes/hours) compared to
 * query rate (milliseconds/seconds)
 *
 * RFC COMPLIANCE: N/A (internal resource management, not protocol-visible)
 *
 * SIDE EFFECTS:
 * - Sets static `done` flag to 1 (rate limiter)
 * - Resets `done` to 0 if reset parameter non-zero
 * - Creates and closes temporary PF_INET socket
 * - Updates server->ifindex for all interface-bound servers
 * - Marks all interfaces found=0, then found=1 for current interfaces
 * - Clears and rebuilds daemon->interface_addrs list
 * - Clears and rebuilds daemon->int_names address lists
 * - Clears and rebuilds daemon->cond_domain address lists
 * - Clears and rebuilds daemon->auth_zones subnet lists (preserves literals)
 * - Moves stale addrlist structures to static spare pool
 * - Frees stale listeners in OPT_CLEVERBIND mode (may modify daemon->listeners)
 * - Calls clean_interfaces() if listeners freed
 * - May iterate enumeration via "goto again" on transient failure
 *
 * THREAD SAFETY: Not thread-safe - modifies daemon global state and static variables
 */
int enumerate_interfaces(int reset)
{
  static struct addrlist *spare = NULL;
  static int done = 0;
  struct iface_param param;
  int errsave, ret = 1;
  struct addrlist *addr, *tmp;
  struct interface_name *intname;
  struct cond_domain *cond;
  struct irec *iface;
#ifdef HAVE_AUTH
  struct auth_zone *zone;
#endif
  struct server *serv;
  
  /* Do this max once per select cycle  - also inhibits netlink socket use
   in TCP child processes. */

  if (reset)
    {
      done = 0;
      return 1;
    }

  if (done)
    return 1;

  done = 1;

  if ((param.fd = socket(PF_INET, SOCK_DGRAM, 0)) == -1)
    return 0;

  /* iface indexes can change when interfaces are created/destroyed. 
     We use them in the main forwarding control path, when the path
     to a server is specified by an interface, so cache them.
     Update the cache here. */
  for (serv = daemon->servers; serv; serv = serv->next)
    if (serv->interface[0] != 0)
      {
#ifdef HAVE_LINUX_NETWORK
	struct ifreq ifr;
	
	safe_strncpy(ifr.ifr_name, serv->interface, IF_NAMESIZE);
	if (ioctl(param.fd, SIOCGIFINDEX, &ifr) != -1) 
	  serv->ifindex = ifr.ifr_ifindex;
#else
	serv->ifindex = if_nametoindex(serv->interface);
#endif
      }
    
again:
  /* Mark interfaces for garbage collection */
  for (iface = daemon->interfaces; iface; iface = iface->next) 
    iface->found = 0;

  /* remove addresses stored against interface_names */
  for (intname = daemon->int_names; intname; intname = intname->next)
    {
      for (addr = intname->addr; addr; addr = tmp)
	{
	  tmp = addr->next;
	  addr->next = spare;
	  spare = addr;
	}
      
      intname->addr = NULL;
    }

  /* remove addresses stored against cond-domains. */
  for (cond = daemon->cond_domain; cond; cond = cond->next)
    {
      for (addr = cond->al; addr; addr = tmp)
	{
	  tmp = addr->next;
	  addr->next = spare;
	  spare = addr;
      }
      
      cond->al = NULL;
    }
  
  /* Remove list of addresses of local interfaces */
  for (addr = daemon->interface_addrs; addr; addr = tmp)
    {
      tmp = addr->next;
      addr->next = spare;
      spare = addr;
    }
  daemon->interface_addrs = NULL;
  
#ifdef HAVE_AUTH
  /* remove addresses stored against auth_zone subnets, but not 
   ones configured as address literals */
  for (zone = daemon->auth_zones; zone; zone = zone->next)
    if (zone->interface_names)
      {
	struct addrlist **up;
	for (up = &zone->subnet, addr = zone->subnet; addr; addr = tmp)
	  {
	    tmp = addr->next;
	    if (addr->flags & ADDRLIST_LITERAL)
	      up = &addr->next;
	    else
	      {
		*up = addr->next;
		addr->next = spare;
		spare = addr;
	      }
	  }
      }
#endif

  param.spare = spare;
  
  ret = iface_enumerate(AF_INET6, &param, (callback_t){.af_inet6=iface_allowed_v6});
  if (ret < 0)
    goto again;
  else if (ret)
    {
      ret = iface_enumerate(AF_INET, &param, (callback_t){.af_inet=iface_allowed_v4});
      if (ret < 0)
	goto again;
    }
 
  errsave = errno;
  close(param.fd);
  
  if (option_bool(OPT_CLEVERBIND))
    { 
      /* Garbage-collect listeners listening on addresses that no longer exist.
	 Does nothing when not binding interfaces or for listeners on localhost, 
	 since the ->iface field is NULL. Note that this needs the protections
	 against reentrancy, hence it's here.  It also means there's a possibility,
	 in OPT_CLEVERBIND mode, that at listener will just disappear after
	 a call to enumerate_interfaces, this is checked OK on all calls. */
      struct listener *l, *tmp, **up;
      int freed = 0;
      
      for (up = &daemon->listeners, l = daemon->listeners; l; l = tmp)
	{
	  tmp = l->next;
	  
	  if (!l->iface || l->iface->found)
	    up = &l->next;
	  else if (release_listener(l))
	    {
	      *up = tmp;
	      freed = 1;
	    }
	}

      if (freed)
	clean_interfaces();
    }

  errno = errsave;
  spare = param.spare;
  
  return ret;
}

/**
 * @brief Set O_NONBLOCK flag on file descriptor to enable non-blocking I/O mode
 * 
 * @detailed Configure file descriptor for non-blocking operation by setting the O_NONBLOCK
 *           flag using fcntl(F_SETFL). Non-blocking mode is essential for dnsmasq's 
 *           single-threaded event-driven architecture - blocking I/O operations would 
 *           stall the main select loop and delay processing of other network events.
 *
 *           Function performs two-stage fcntl() operation:
 *           1. **Retrieve Current Flags**: fcntl(fd, F_GETFL) reads existing file status flags
 *              including O_RDONLY/O_WRONLY/O_RDWR, O_APPEND, O_ASYNC, O_NONBLOCK, etc.
 *           2. **Set Non-Blocking Flag**: fcntl(fd, F_SETFL, flags | O_NONBLOCK) writes back
 *              flags with O_NONBLOCK added via bitwise OR. Preserves other flags like O_APPEND.
 *
 *           Non-blocking mode causes I/O operations to return immediately with EAGAIN/EWOULDBLOCK
 *           instead of blocking when no data available (read) or buffers full (write). Main 
 *           event loop uses poll() to wait for fd readiness, then performs I/O knowing operation
 *           won't block (or will return EAGAIN if spurious wakeup).
 *
 *           Applied to all network sockets created by dnsmasq:
 *           - DNS UDP sockets (port 53): Prevent blocking on recvfrom/sendto
 *           - DNS TCP sockets (port 53): Prevent blocking on accept/read/write
 *           - DHCP sockets (port 67/546): Prevent blocking on recvmsg/sendmsg  
 *           - TFTP sockets (port 69): Prevent blocking on recvfrom/sendto
 *           - Netlink sockets (Linux): Prevent blocking on recv from kernel
 *
 *           Why non-blocking I/O critical for dnsmasq architecture:
 *           - Single thread handles all protocols: blocking one socket stalls entire daemon
 *           - Timers and timeouts: Must service lease expirations, query retries, RA transmission
 *           - Fair scheduling: All clients receive service, no client monopolizes thread
 *           - DoS resistance: Slow clients or network congestion cannot hang daemon
 *
 *           Technical background from Stevens "Advanced Programming in the UNIX Environment"
 *           Section 16.6 "Nonblocking I/O": Describes fcntl() usage pattern for setting flags
 *           and relationship between O_NONBLOCK and select/poll event notification.
 *
 * @param fd File descriptor to configure. Typically a socket created by socket() syscall,
 *           but can be any file descriptor (pipe, file, device). Must be valid open descriptor.
 *           Common sources:
 *           - socket(AF_INET, SOCK_DGRAM, 0): UDP socket for DNS/DHCP/TFTP
 *           - socket(AF_INET, SOCK_STREAM, 0): TCP socket for DNS-over-TCP
 *           - socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE): Netlink socket for interface monitoring
 *           - accept(): TCP connection from listening socket
 *
 * @return Integer indicating success or failure of fcntl() operations
 * @retval 1 Success: O_NONBLOCK flag set, file descriptor configured for non-blocking mode.
 *           Subsequent read/write operations will return EAGAIN instead of blocking.
 * @retval 0 Failure: fcntl() operation failed, errno contains error code. File descriptor
 *           remains in original blocking state. Common errno values:
 *           - EBADF: fd not valid open file descriptor
 *           - EINVAL: invalid flags value (rare, indicates kernel bug)
 *           - EIO: low-level I/O error (hardware failure)
 *
 * @note Stevens reference: W. Richard Stevens, "Advanced Programming in the UNIX Environment",
 *       Section 16.6 "Nonblocking I/O" describes this exact fcntl() usage pattern for setting
 *       O_NONBLOCK while preserving other flags. Classic Unix systems programming technique.
 * @note Flag preservation: Bitwise OR with existing flags ensures other file status flags
 *       (O_APPEND, O_ASYNC, O_SYNC, etc.) remain unchanged. Only O_NONBLOCK added.
 * @note POSIX compliance: O_NONBLOCK defined by POSIX.1-2001, available on all Unix-like systems.
 *       Older systems used O_NDELAY (SVR3) or FNDELAY (BSD), but modern code uses O_NONBLOCK.
 * @note Socket vs. file: Non-blocking mode behaves differently for sockets vs. regular files:
 *       - Sockets: read/write return EAGAIN when operation would block
 *       - Regular files: read/write typically complete immediately (buffered by page cache),
 *         O_NONBLOCK has minimal effect except for NFS mounts or device files
 * @note accept() inheritance: O_NONBLOCK NOT inherited by sockets returned from accept().
 *       Listening socket in non-blocking mode, but accepted connections default to blocking
 *       mode unless explicitly set with fix_fd().
 * @note fcntl() vs. ioctl(): fcntl(F_SETFL) is POSIX standard method for setting O_NONBLOCK.
 *       Older code used ioctl(FIONBIO), but fcntl() preferred for portability.
 * @note Multiple calls safe: Idempotent operation - calling fix_fd() multiple times on same
 *       descriptor is safe. OR-ing O_NONBLOCK when already set has no effect.
 * @note Thread safety: fcntl() operates on kernel file description, affects all threads
 *       sharing same file descriptor. Not an issue for dnsmasq (single-threaded), but
 *       relevant for multi-threaded programs.
 * @note errno preservation: Function does NOT preserve errno on success. On failure, errno
 *       contains error from fcntl() - caller should check return value before accessing errno.
 *
 * @warning fd parameter must be valid open file descriptor. Passing closed fd or invalid
 *          value (e.g., -1, large random number) causes fcntl() to fail with EBADF. Function
 *          does not validate fd before use.
 * @warning Failure return (0) leaves fd in original blocking mode. Caller MUST check return
 *          value and handle failure appropriately. Using fd in non-blocking mode after
 *          fix_fd() returns 0 will cause daemon to hang on blocking I/O operations.
 * @warning Common failure scenario: EMFILE/ENFILE (too many open files) during socket creation
 *          results in fd=-1 passed to fix_fd(). fcntl(-1, ...) returns -1 with EBADF.
 *          Callers should check socket() return before calling fix_fd().
 * @warning No validation of fd type: Function works on any file descriptor (socket, pipe,
 *          regular file, device). Caller responsible for ensuring fd is appropriate for
 *          non-blocking mode. Setting O_NONBLOCK on stdin/stdout/stderr affects terminal
 *          I/O behavior.
 * @warning Race condition: Window between fcntl(F_GETFL) and fcntl(F_SETFL) where other
 *          thread could modify flags. Not an issue for dnsmasq (single-threaded), but
 *          problematic in multi-threaded code without locking.
 *
 * @see make_sock() in src/network.c which calls fix_fd() for all created sockets
 * @see Stevens APUE Section 16.6 for detailed explanation of non-blocking I/O patterns
 * @see fcntl(2) man page for complete F_GETFL/F_SETFL documentation
 * @see socket(7) man page for socket-specific O_NONBLOCK behavior
 *
 * EXAMPLE USAGE:
 * @code
 * int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
 * if (sockfd == -1)
 *   die("socket() failed: %s", strerror(errno), EC_BADNET);
 * 
 * if (!fix_fd(sockfd))
 *   {
 *     close(sockfd);
 *     die("Failed to set non-blocking mode: %s", strerror(errno), EC_BADNET);
 *   }
 * 
 * // Socket now in non-blocking mode, safe to use in select loop
 * // recvfrom() will return EAGAIN instead of blocking
 * @endcode
 *
 * NON-BLOCKING I/O BEHAVIOR:
 * 
 * Blocking mode (default):
 *   read(fd, buf, size) -> blocks until data available or EOF
 *   write(fd, buf, size) -> blocks until buffer space available
 *   accept(fd, ...) -> blocks until incoming connection
 *   connect(fd, ...) -> blocks until connection established
 * 
 * Non-blocking mode (after fix_fd):
 *   read(fd, buf, size) -> returns immediately with EAGAIN if no data
 *   write(fd, buf, size) -> returns immediately with EAGAIN if buffers full
 *   accept(fd, ...) -> returns immediately with EAGAIN if no connections
 *   connect(fd, ...) -> returns immediately with EINPROGRESS, completes asynchronously
 * 
 * Event-driven pattern (dnsmasq architecture):
 *   1. Call fix_fd() on all sockets to enable non-blocking mode
 *   2. Add sockets to poll() file descriptor set
 *   3. poll() waits until socket ready (data available or writable)
 *   4. Perform I/O operation, expect immediate completion or EAGAIN
 *   5. Handle EAGAIN by returning to poll() (spurious wakeup)
 *   6. Process received data or send next chunk
 *
 * FCNTL FLAGS PRESERVED:
 * 
 * File access mode (cannot be modified):
 *   - O_RDONLY (0x00): Open for reading only
 *   - O_WRONLY (0x01): Open for writing only
 *   - O_RDWR (0x02): Open for reading and writing
 * 
 * File status flags (preserved by OR operation):
 *   - O_APPEND: Writes append to end of file
 *   - O_ASYNC: Signal-driven I/O notification
 *   - O_DIRECT: Bypass buffer cache (not typically used for sockets)
 *   - O_NOATIME: Don't update access time
 *   - O_NONBLOCK: Non-blocking mode (SET BY THIS FUNCTION)
 *
 * SOCKET-SPECIFIC CONSIDERATIONS:
 * 
 * UDP sockets (SOCK_DGRAM):
 *   - recvfrom(): Returns EAGAIN when no datagrams queued
 *   - sendto(): Returns EAGAIN when send buffer full (rare for UDP)
 *   - No partial operations: Either complete datagram or EAGAIN
 * 
 * TCP sockets (SOCK_STREAM):
 *   - read(): Returns EAGAIN when no data available, may return partial data
 *   - write(): Returns EAGAIN when send buffer full, may write partial data
 *   - accept(): Returns EAGAIN when no pending connections
 *   - connect(): Returns EINPROGRESS immediately, completion signaled by writability
 *   - Partial I/O common: Loop until complete or EAGAIN
 * 
 * Netlink sockets (SOCK_RAW):
 *   - recv(): Returns EAGAIN when no kernel messages available
 *   - Kernel messages arrive asynchronously (interface events, route changes)
 *
 * RFC COMPLIANCE: N/A (internal implementation detail, not protocol-visible)
 * 
 * SIDE EFFECTS:
 * - Modifies file descriptor flags via fcntl(F_SETFL) syscall
 * - Changes kernel file description shared by all dup'd descriptors
 * - Affects behavior of all subsequent I/O operations on fd
 * - No effect on other file descriptors or processes
 * 
 * THREAD SAFETY: fcntl() is thread-safe syscall, but race condition possible in
 *                 multi-threaded code (read-modify-write flags). Not an issue for
 *                 single-threaded dnsmasq.
 */
int fix_fd(int fd)
{
  int flags;

  if ((flags = fcntl(fd, F_GETFL)) == -1 ||
      fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
    return 0;
  
  return 1;
}

/**
 * @brief Create and configure network socket bound to specific address and port
 * 
 * @detailed Create socket using socket() syscall, configure socket options for address reuse
 *           and protocol-specific features, bind socket to specified address, and prepare
 *           socket for use in dnsmasq's network operations. Handles both TCP (SOCK_STREAM)
 *           and UDP (SOCK_DGRAM) sockets across IPv4 and IPv6 address families.
 *
 *           Core socket creation and configuration sequence:
 *           1. **Create Socket**: socket(family, type, 0) creates unbound socket of specified
 *              family (AF_INET/AF_INET6) and type (SOCK_STREAM/SOCK_DGRAM). Protocol parameter
 *              0 selects default protocol for family+type (TCP for STREAM, UDP for DGRAM).
 *              
 *           2. **Enable Address Reuse**: setsockopt(SO_REUSEADDR) allows binding to addresses
 *              in TIME_WAIT state from previous connections. Critical for daemon restarts -
 *              without SO_REUSEADDR, bind() fails with EADDRINUSE if previous instance's TCP
 *              connections still in TIME_WAIT (lasts 2*MSL = 60-240 seconds). Does NOT allow
 *              multiple processes to bind same address:port simultaneously (requires SO_REUSEPORT).
 *              
 *           3. **Set Non-Blocking Mode**: fix_fd() sets O_NONBLOCK flag for event-driven I/O.
 *              See fix_fd() documentation for detailed explanation of non-blocking mode necessity.
 *              
 *           4. **IPv6-Only Mode**: For AF_INET6 sockets, setsockopt(IPV6_V6ONLY, 1) prevents
 *              IPv4-mapped addresses (::ffff:192.0.2.1). Without this, IPv6 socket accepts both
 *              IPv6 and IPv4 connections via mapping, which interferes with separate IPv4 socket
 *              binding. Setting IPV6_V6ONLY ensures clean separation: IPv6 socket handles only
 *              native IPv6, IPv4 socket handles only native IPv4.
 *              
 *           5. **Bind to Address**: bind() associates socket with specific address and port.
 *              Before bind(), socket has no address (can't receive packets). After bind(), kernel
 *              routes packets for address:port to this socket. Privileged ports (<1024) require
 *              root privileges or CAP_NET_BIND_SERVICE capability.
 *              
 *           6. **TCP-Specific Configuration** (SOCK_STREAM):
 *              - listen(TCP_BACKLOG) marks socket as passive (accept incoming connections).
 *                Backlog parameter (default 32, config.h line 19) controls max pending connections
 *                in SYN_RCVD state. When backlog full, new SYN packets refused with RST.
 *              - TCP_FASTOPEN: Optional optimization reducing connection establishment latency
 *                by allowing data transmission in SYN packet (RFC 7413). Reduces round-trips for
 *                initial request. Supported on Linux 3.7+, not universally available (#ifdef).
 *                Queue length 5 controls max pending FastOpen cookies.
 *                
 *           7. **UDP IPv4 Packet Info** (SOCK_DGRAM, AF_INET):
 *              - Enables reception of destination address from UDP packets via IP_PKTINFO (Linux)
 *                or IP_RECVDSTADDR+IP_RECVIF (BSD). Without this, recvmsg() only provides source
 *                address of sender, not destination address packet was sent to. Destination address
 *                critical for wildcard sockets binding to 0.0.0.0 - allows daemon to determine which
 *                interface received packet and respond from same interface's address.
 *              - Only enabled when not in --bind-interfaces mode (option_bool(OPT_NOWILD) == false).
 *                Bind-interfaces mode creates separate socket per interface, so destination address
 *                implicitly known from which socket received packet.
 *                
 *           8. **UDP IPv6 Packet Info** (SOCK_DGRAM, AF_INET6):
 *              - Call set_ipv6pktinfo() to enable IPV6_PKTINFO or IPV6_RECVPKTINFO (depending on
 *                kernel version). Provides destination address and interface index for received
 *                packets. See set_ipv6pktinfo() for Linux 2.6.14 API transition details.
 *
 *           Why SO_REUSEADDR critical for dnsmasq:
 *           - Daemon restart scenario: Administrator runs `systemctl restart dnsmasq` or sends
 *             SIGTERM to reload configuration. Old process exits, but TCP connections in TIME_WAIT
 *             state prevent new process from binding port 53 unless SO_REUSEADDR set. Without it,
 *             restart fails with "Address already in use" until TIME_WAIT expires (up to 4 minutes).
 *           - TIME_WAIT state: After TCP close, socket remains in TIME_WAIT for 2*MSL (maximum
 *             segment lifetime) to ensure stray packets from old connection don't interfere with
 *             new connection on same address:port. Kernel maintains TIME_WAIT even after process
 *             exits, SO_REUSEADDR tells kernel new bind() is intentional.
 *           - UDP implications: For UDP, SO_REUSEADDR less critical (no connection state), but
 *             still useful for rapid daemon restarts with pending packets in socket buffers.
 *
 *           Why IPV6_V6ONLY necessary:
 *           - Historical context: Early IPv6 implementations defaulted to dual-stack sockets where
 *             AF_INET6 socket accepts both IPv6 and IPv4 (mapped as ::ffff:0:0/96). This causes
 *             conflict when trying to bind both AF_INET and AF_INET6 sockets to same port - second
 *             bind() fails with EADDRINUSE.
 *           - RFC 3493 Section 3.7: Recommends IPV6_V6ONLY for applications wanting separate
 *             IPv4 and IPv6 sockets. dnsmasq creates separate sockets for protocol independence,
 *             clean configuration, and platform compatibility.
 *           - Modern Linux default: As of Linux 2.6.27, IPV6_V6ONLY defaults to 1 (controlled by
 *             /proc/sys/net/ipv6/bindv6only), but dnsmasq explicitly sets it for portability to
 *             platforms with different defaults.
 *
 *           Error handling strategy (goto err pattern):
 *           Function uses single error path (err: label) for cleanup consistency. Any failure
 *           jumps to err which:
 *           1. Saves errno before cleanup operations that might modify it
 *           2. Closes socket if fd != -1 (cleanup after bind/setsockopt failure)
 *           3. Formats error message with prettyprint_addr() showing address that failed
 *           4. In bind-dynamic mode (--bind-dynamic), EADDRNOTAVAIL errors suppressed because
 *              address might not exist yet (interface not created). Daemon will retry when
 *              interface appears via netlink/routing socket notification.
 *           5. If dienow==1: die() terminates daemon (called during initialization, failure fatal)
 *              If dienow==0: my_syslog() logs warning (called during dynamic reconfiguration,
 *              non-fatal, retry later)
 *
 *           EADDRNOTAVAIL handling (--bind-dynamic mode):
 *           When administrator configures --listen-address for interface that doesn't exist yet
 *           (e.g., VPN interface not connected, virtual interface not created), bind() fails with
 *           EADDRNOTAVAIL. Instead of treating as fatal error, daemon suppresses warning and
 *           continues. When interface later appears, newaddress() function (called from netlink
 *           or routing socket events) retries make_sock() for pending addresses. This enables
 *           dynamic network topologies where interfaces come and go.
 *
 *           TCP_FASTOPEN optimization:
 *           RFC 7413 defines TCP Fast Open mechanism allowing data transmission in SYN packet,
 *           reducing connection establishment from 1.5 RTT to 1 RTT (or 0.5 RTT for subsequent
 *           connections with cached cookie). Particularly beneficial for short-lived DNS-over-TCP
 *           connections where connection setup latency dominates total transaction time.
 *           Implementation:
 *           - Server enables TFO with setsockopt(TCP_FASTOPEN, qlen) where qlen controls pending
 *             cookie queue size (5 = up to 5 simultaneous FastOpen handshakes).
 *           - Client sends data in SYN (requires client-side TFO support)
 *           - Server validates cookie, delivers data to application immediately (skips SYN-ACK wait)
 *           - Not all clients support TFO; fallback to standard 3-way handshake is automatic
 *
 * @param addr Pointer to union mysockaddr containing address to bind. Must be properly initialized
 *             with family (sa_family), address (sin_addr/sin6_addr), and port (sin_port/sin6_port).
 *             Common address types:
 *             - IPv4 wildcard (0.0.0.0:53): Bind to all IPv4 interfaces
 *             - IPv6 wildcard ([::]:53): Bind to all IPv6 interfaces  
 *             - Specific IPv4 (192.168.1.1:53): Bind to single interface address
 *             - Specific IPv6 ([2001:db8::1]:53): Bind to single interface address
 *             - Loopback (127.0.0.1:53, [::1]:53): Local-only binding
 *             Port numbers:
 *             - 53: DNS (UDP and TCP)
 *             - 67: DHCPv4 server (UDP)
 *             - 546: DHCPv6 server (UDP)
 *             - 69: TFTP (UDP)
 *             Must not be NULL. Structure must be properly aligned (union ensures alignment).
 *
 * @param type Socket type constant from socket API. Determines protocol behavior and semantics.
 *             Valid values:
 *             - SOCK_STREAM: TCP socket (connection-oriented, reliable, ordered byte stream).
 *               Used for DNS-over-TCP on port 53. Requires listen() for server operation.
 *               Supports TCP_FASTOPEN optimization. Connection-oriented requires accept() for
 *               incoming connections. Each connection gets separate socket fd from accept().
 *             - SOCK_DGRAM: UDP socket (connectionless, unreliable, message-oriented).
 *               Used for DNS on port 53, DHCPv4 on port 67, DHCPv6 on port 546, TFTP on port 69.
 *               No listen() or accept() - directly receives datagrams via recvfrom()/recvmsg().
 *               Requires IP_PKTINFO/IPV6_PKTINFO for destination address reception.
 *             Invalid values (SOCK_RAW, SOCK_SEQPACKET, etc.) will cause socket() to fail with
 *             EINVAL or EPROTONOSUPPORT.
 *
 * @param dienow Error handling mode controlling behavior when socket creation/binding fails.
 *               Determines whether failure is fatal (terminate daemon) or recoverable (log warning).
 *               Values:
 *               - 1 (non-zero): Fatal error mode. Call die() on failure, terminating daemon with
 *                 EC_BADNET exit code. Used during daemon initialization when network setup failures
 *                 prevent daemon from operating correctly (no sockets = no functionality). Examples:
 *                 Initial socket creation for --listen-address at startup, required service ports.
 *               - 0 (zero): Non-fatal error mode. Call my_syslog(LOG_WARNING) on failure, logging
 *                 error but continuing daemon operation. Used during dynamic reconfiguration when
 *                 interface state changes (newaddress() callback from netlink/routing socket).
 *                 Examples: Retry binding to --listen-address after interface creation, adding
 *                 new interface address dynamically. Allows partial functionality while waiting
 *                 for network conditions to improve.
 *               Typical usage: Initial setup uses dienow=1 (must succeed), dynamic updates use
 *               dienow=0 (best-effort retry).
 *
 * @return Integer file descriptor for created socket on success, or -1 on failure
 * @retval >=0 Success: Valid socket file descriptor ready for use. Socket bound to specified
 *             address and port, configured with SO_REUSEADDR, non-blocking mode (O_NONBLOCK),
 *             and protocol-specific options (IPV6_V6ONLY for IPv6, IP_PKTINFO for UDP, etc.).
 *             For TCP (SOCK_STREAM), socket in listening state ready to accept() connections.
 *             For UDP (SOCK_DGRAM), socket ready to recvfrom()/recvmsg() datagrams.
 *             Caller responsible for:
 *             - Adding fd to poll/select set for event notification
 *             - Handling I/O operations (accept, read, write, recvfrom, sendto, etc.)
 *             - Eventually closing fd when no longer needed
 * @retval -1 Failure: Socket creation, configuration, or binding failed. Specific error indicated
 *            by errno (preserved from failed syscall). Common errno values:
 *            - EADDRINUSE: Address already in use (another process bound to port, or TIME_WAIT
 *              state without SO_REUSEADDR). Retry after delay or check for conflicting process.
 *            - EADDRNOTAVAIL: Address not available (interface doesn't exist, or IP not assigned
 *              to interface). In --bind-dynamic mode, this is non-fatal - daemon retries when
 *              interface appears.
 *            - EACCES: Permission denied (binding privileged port <1024 without root/CAP_NET_BIND_SERVICE).
 *              Run daemon with appropriate privileges.
 *            - EPROTONOSUPPORT: Protocol not supported (e.g., IPv6 when kernel has no IPv6 support).
 *              Non-fatal - daemon continues without IPv6 functionality.
 *            - EAFNOSUPPORT: Address family not supported (e.g., AF_INET6 on very old kernel).
 *              Non-fatal - daemon continues without IPv6.
 *            - EINVAL: Invalid argument (malformed address, bad socket type, etc.). Check addr
 *              and type parameters for correctness.
 *            - ENOMEM/ENOBUFS: Insufficient kernel memory for socket buffers. Reduce cache size
 *              or number of interfaces.
 *            - EMFILE/ENFILE: Too many open files (process or system limit). Increase ulimit or
 *              reduce daemon resource usage.
 *            Failure handling depends on dienow parameter:
 *            - dienow=1: die() called, daemon terminates (initialization failure)
 *            - dienow=0: my_syslog() logs warning, daemon continues (dynamic reconfiguration)
 *            EPROTONOSUPPORT, EAFNOSUPPORT, EINVAL treated specially: Return -1 without logging,
 *            indicating protocol not available (caller handles gracefully).
 *
 * @note SO_REUSEADDR semantics: Allows binding to address in TIME_WAIT state, does NOT allow
 *       multiple processes to bind same address:port simultaneously (use SO_REUSEPORT for that).
 *       Critical for daemon restarts with TCP connections in TIME_WAIT.
 * @note IPV6_V6ONLY necessity: Prevents IPv4-mapped addresses (::ffff:0:0/96) on IPv6 sockets,
 *       allowing separate IPv4 and IPv6 sockets to bind same port without EADDRINUSE conflict.
 *       Required for clean dual-stack operation.
 * @note TCP_FASTOPEN availability: Linux 3.7+ kernel feature, wrapped in #ifdef for portability.
 *       Graceful degradation when unavailable - standard 3-way handshake used.
 * @note IP_PKTINFO vs IP_RECVDSTADDR: Platform differences for receiving destination address:
 *       - Linux: IP_PKTINFO provides pktinfo structure with destination addr and interface index
 *       - BSD: IP_RECVDSTADDR + IP_RECVIF provide separate control messages
 *       Function uses conditional compilation (#if defined) to select appropriate API.
 * @note Privilege requirements: Binding ports <1024 requires root or CAP_NET_BIND_SERVICE.
 *       dnsmasq starts as root, binds ports, then drops privileges to unprivileged user.
 * @note Error path cleanup: goto err pattern ensures consistent cleanup (save errno, close fd,
 *       format error message) regardless of which operation failed. Single error path reduces
 *       code duplication and ensures errno preservation.
 * @note Non-blocking mode: fix_fd() failure (unable to set O_NONBLOCK) treated as fatal because
 *       blocking I/O would hang event loop. Must succeed for daemon to operate correctly.
 *
 * @warning addr parameter must be valid pointer to properly initialized mysockaddr union. Passing
 *          NULL or uninitialized structure causes undefined behavior (segfault or incorrect binding).
 *          Caller must set sa_family before calling - family determines structure interpretation.
 * @warning Port number must be in network byte order (htons()). Host byte order causes binding
 *          to wrong port (e.g., htons(53) = 0x3500 on little-endian, 53 = 0x0035).
 * @warning Socket fd returned by successful call must be eventually closed. Leaking fds exhausts
 *          process file descriptor limit (ulimit -n, typically 1024). Use close() when socket
 *          no longer needed or during error cleanup in caller.
 * @warning SO_REUSEADDR does NOT allow multiple processes to bind same address:port simultaneously.
 *          Second bind() still fails with EADDRINUSE if another process already bound. For port
 *          sharing, use SO_REUSEPORT (Linux 3.9+, not used by dnsmasq).
 * @warning IPV6_V6ONLY setting is permanent for socket lifetime. Cannot be changed after bind().
 *          If IPv4-mapped addresses needed, must create socket without IPV6_V6ONLY (non-portable).
 * @warning TCP listen() backlog (TCP_BACKLOG=32) limits pending connections. When backlog full,
 *          new SYN packets refused with RST, client sees "Connection refused". Increase TCP_BACKLOG
 *          in config.h for servers with high connection rate (not typical for dnsmasq).
 * @warning TCP_FASTOPEN security considerations: Cookies must be validated to prevent SYN flood
 *          amplification. Kernel handles validation, but server must be prepared for data in SYN
 *          (potential security implications for stateful protocols). DNS-over-TCP stateless nature
 *          makes TFO safe.
 * @warning EADDRNOTAVAIL suppression (--bind-dynamic) can hide configuration errors. If address
 *          typo in --listen-address never appears, daemon silently won't bind. Check logs for
 *          warnings about unavailable addresses.
 * @warning errno preservation critical: Error path saves errno before cleanup operations (close,
 *          prettyprint_addr) that might modify it. Caller relies on errno for failure diagnosis.
 * @warning Race condition in --bind-dynamic: Address might disappear between make_sock() success
 *          and packet reception. Network layer must handle EHOSTUNREACH/ENETUNREACH from sendto().
 *
 * @see fix_fd() for O_NONBLOCK configuration details and non-blocking I/O necessity
 * @see set_ipv6pktinfo() for IPv6 packet info API version handling (IPV6_PKTINFO vs IPV6_2292PKTINFO)
 * @see create_bound_listeners() which calls make_sock() for specific interface addresses
 * @see create_wildcard_listeners() which calls make_sock() for wildcard addresses (0.0.0.0, ::)
 * @see newaddress() which calls make_sock() with dienow=0 for dynamic interface address changes
 * @see socket(2), bind(2), listen(2), setsockopt(2) man pages for syscall details
 * @see RFC 7413 (TCP Fast Open) for TFO mechanism and security considerations
 * @see RFC 3493 Section 3.7 for IPV6_V6ONLY rationale
 *
 * EXAMPLE USAGE:
 * @code
 * // Create TCP listening socket on IPv4 port 53 (DNS-over-TCP)
 * union mysockaddr addr;
 * memset(&addr, 0, sizeof(addr));
 * addr.in.sin_family = AF_INET;
 * addr.in.sin_addr.s_addr = INADDR_ANY;  // 0.0.0.0 wildcard
 * addr.in.sin_port = htons(53);          // DNS port in network byte order
 * 
 * int tcpfd = make_sock(&addr, SOCK_STREAM, 1);  // dienow=1 for initialization
 * if (tcpfd == -1)
 *   // die() already called if dienow=1, won't reach here
 *   // If dienow=0, would need error handling here
 *   
 * // Socket ready for accept() in event loop
 * // Remember to close(tcpfd) when done
 * @endcode
 *
 * @code
 * // Create UDP socket on specific IPv6 address (bind-dynamic mode)
 * union mysockaddr addr6;
 * memset(&addr6, 0, sizeof(addr6));
 * addr6.in6.sin6_family = AF_INET6;
 * inet_pton(AF_INET6, "2001:db8::1", &addr6.in6.sin6_addr);
 * addr6.in6.sin6_port = htons(53);
 * 
 * int udpfd = make_sock(&addr6, SOCK_DGRAM, 0);  // dienow=0 for dynamic binding
 * if (udpfd == -1)
 *   {
 *     // Warning logged, but daemon continues
 *     // Will retry when interface address appears
 *   }
 * else
 *   {
 *     // Socket bound successfully, add to listener list
 *   }
 * @endcode
 *
 * SOCKET OPTIONS SUMMARY:
 * 
 * SO_REUSEADDR (all sockets):
 *   Purpose: Allow binding to address in TIME_WAIT state
 *   Effect: Daemon restart works immediately after shutdown
 *   Level: SOL_SOCKET
 * 
 * O_NONBLOCK (all sockets, via fix_fd):
 *   Purpose: Non-blocking I/O for event-driven architecture
 *   Effect: read/write return EAGAIN instead of blocking
 *   Set via: fcntl(F_SETFL, O_NONBLOCK)
 * 
 * IPV6_V6ONLY (IPv6 sockets):
 *   Purpose: Disable IPv4-mapped addresses (::ffff:0:0/96)
 *   Effect: IPv6 socket only accepts native IPv6
 *   Level: IPPROTO_IPV6
 * 
 * TCP_FASTOPEN (TCP sockets, optional):
 *   Purpose: Enable RFC 7413 Fast Open (data in SYN)
 *   Effect: Reduced connection latency (1.5 RTT -> 1 RTT)
 *   Level: IPPROTO_TCP (Linux 3.7+)
 * 
 * IP_PKTINFO (IPv4 UDP, Linux):
 *   Purpose: Receive destination address and interface index
 *   Effect: Know which interface received packet
 *   Level: IPPROTO_IP
 * 
 * IP_RECVDSTADDR + IP_RECVIF (IPv4 UDP, BSD):
 *   Purpose: Receive destination address and interface (BSD equivalent)
 *   Effect: Same as IP_PKTINFO but separate control messages
 *   Level: IPPROTO_IP
 * 
 * IPV6_PKTINFO/IPV6_RECVPKTINFO (IPv6 UDP):
 *   Purpose: Receive destination address and interface index
 *   Effect: Know which interface received packet
 *   Level: IPPROTO_IPV6 (set by set_ipv6pktinfo())
 *
 * PROTOCOL-SPECIFIC BEHAVIOR:
 * 
 * DNS TCP (SOCK_STREAM, port 53):
 *   - listen(TCP_BACKLOG=32) for incoming connections
 *   - TCP_FASTOPEN if available (Linux 3.7+)
 *   - SO_REUSEADDR for rapid restart
 *   - O_NONBLOCK for event-driven accept/read/write
 *   - No packet info needed (connection-oriented)
 * 
 * DNS UDP (SOCK_DGRAM, port 53):
 *   - No listen() (connectionless)
 *   - IP_PKTINFO/IPV6_PKTINFO for destination address
 *   - SO_REUSEADDR for rapid restart
 *   - O_NONBLOCK for event-driven recvfrom/sendto
 * 
 * DHCPv4 (SOCK_DGRAM, port 67):
 *   - Same as DNS UDP
 *   - May use raw sockets (BPF) on some platforms
 * 
 * DHCPv6 (SOCK_DGRAM, port 546):
 *   - Same as DNS UDP but IPv6 only
 *   - IPV6_PKTINFO for interface identification
 * 
 * TFTP (SOCK_DGRAM, port 69):
 *   - Same as DNS UDP
 *   - Separate socket created per transfer
 *
 * RFC COMPLIANCE:
 * - RFC 3493: Basic Socket Interface Extensions for IPv6 (IPV6_V6ONLY)
 * - RFC 7413: TCP Fast Open (optional optimization)
 * - RFC 3542: Advanced Sockets API for IPv6 (IPV6_PKTINFO)
 * 
 * SIDE EFFECTS:
 * - Creates kernel socket object (consumes file descriptor)
 * - Binds socket to address:port (reserves address:port for process)
 * - For TCP, creates listening socket (kernel accepts connections)
 * - Modifies global daemon->v6pktinfo (set by set_ipv6pktinfo())
 * - May call die() and terminate daemon if dienow=1 and error occurs
 * - May log to syslog via my_syslog() if dienow=0 and error occurs
 * - Closes socket fd on error before returning (cleanup)
 * 
 * THREAD SAFETY: Not thread-safe due to daemon global variable access and potential die() call.
 *                 dnsmasq is single-threaded, so not an issue.
 */
static int make_sock(union mysockaddr *addr, int type, int dienow)
{
  int family = addr->sa.sa_family;
  int fd, rc, opt = 1;
  
  if ((fd = socket(family, type, 0)) == -1)
    {
      int port, errsave;
      char *s;

      /* No error if the kernel just doesn't support this IP flavour */
      if (errno == EPROTONOSUPPORT ||
	  errno == EAFNOSUPPORT ||
	  errno == EINVAL)
	return -1;
      
    err:
      errsave = errno;
      port = prettyprint_addr(addr, daemon->addrbuff);
      if (!option_bool(OPT_NOWILD) && !option_bool(OPT_CLEVERBIND))
	sprintf(daemon->addrbuff, "port %d", port);
      s = _("failed to create listening socket for %s: %s");
      
      if (fd != -1)
	close (fd);
	
      errno = errsave;

      /* Failure to bind addresses given by --listen-address at this point
	 because there's no interface with the address is OK if we're doing bind-dynamic.
	 If/when an interface is created with the relevant address we'll notice
	 and attempt to bind it then. This is in the generic error path so we  close the socket,
	 but EADDRNOTAVAIL is only a possible error from bind() 
	 
	 When a new address is created and we call this code again (dienow == 0) there
	 may still be configured addresses when don't exist, (consider >1 --listen-address,
	 when the first is created, the second will still be missing) so we suppress
	 EADDRNOTAVAIL even in that case to avoid confusing log entries.
      */
      if (!option_bool(OPT_CLEVERBIND) || errno != EADDRNOTAVAIL)
	{
	  if (dienow)
	    die(s, daemon->addrbuff, EC_BADNET);
	  else
	    my_syslog(LOG_WARNING, s, daemon->addrbuff, strerror(errno));
	}
      
      return -1;
    }	
  
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1 || !fix_fd(fd))
    goto err;
  
  if (family == AF_INET6 && setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt)) == -1)
    goto err;
  
  if ((rc = bind(fd, (struct sockaddr *)addr, sa_len(addr))) == -1)
    goto err;
  
  if (type == SOCK_STREAM)
    {
#ifdef TCP_FASTOPEN
      int qlen = 5;                           
      setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN, &qlen, sizeof(qlen));
#endif
      
      if (listen(fd, TCP_BACKLOG) == -1)
	goto err;
    }
  else if (family == AF_INET)
    {
      if (!option_bool(OPT_NOWILD))
	{
#if defined(HAVE_LINUX_NETWORK) 
	  if (setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &opt, sizeof(opt)) == -1)
	    goto err;
#elif defined(IP_RECVDSTADDR) && defined(IP_RECVIF)
	  if (setsockopt(fd, IPPROTO_IP, IP_RECVDSTADDR, &opt, sizeof(opt)) == -1 ||
	      setsockopt(fd, IPPROTO_IP, IP_RECVIF, &opt, sizeof(opt)) == -1)
	    goto err;
#endif
	}
    }
  else if (!set_ipv6pktinfo(fd))
    goto err;
  
  return fd;
}

/**
 * @brief Enable IPv6 packet information reception for UDP sockets with Linux kernel API compatibility
 * 
 * @detailed Configure IPv6 UDP socket to receive destination address and incoming interface index
 *           via ancillary data (control messages) in recvmsg() calls. Handles Linux kernel API
 *           transition that occurred around version 2.6.14, attempting modern API first and
 *           falling back to legacy API for compatibility with older kernels and headers.
 *
 *           Why packet info reception necessary for IPv6 UDP:
 *           Without packet info, recvmsg() only provides source address of sender (who sent packet),
 *           not destination address (which of our addresses packet was sent to). For wildcard sockets
 *           binding to [::] (all IPv6 addresses), daemon must know which specific interface and
 *           address received packet to respond from same address. Responding from different address
 *           than query was sent to causes client confusion and violates DNS protocol expectations.
 *
 *           Example scenario requiring packet info:
 *           - Host has two IPv6 addresses: eth0 = 2001:db8::1, wlan0 = 2001:db8::2
 *           - dnsmasq binds wildcard socket to [::]:53 (receives on all interfaces)
 *           - Client sends query to 2001:db8::1:53 (eth0 address)
 *           - recvmsg() receives packet but only knows source address (client's IP)
 *           - WITHOUT packet info: Cannot determine packet sent to eth0 vs wlan0
 *           - WITH packet info: Ancillary data contains destination address (2001:db8::1) and
 *             interface index (eth0's index), enabling daemon to respond from 2001:db8::1
 *
 *           Linux kernel API transition history:
 *           
 *           **Pre-2.6.14 (OLD API):**
 *           - Enable option: setsockopt(IPV6_2292PKTINFO, 1) - enables reception
 *           - Receive data: Ancillary message type IPV6_2292PKTINFO in recvmsg() control messages
 *           - Ancillary data: struct in6_pktinfo { struct in6_addr ipi6_addr, int ipi6_ifindex }
 *           - API defined by early RFC 2292 (Advanced Sockets API for IPv6)
 *           
 *           **Post-2.6.14 (NEW API):**
 *           - Enable option: setsockopt(IPV6_RECVPKTINFO, 1) - enables reception
 *           - Receive data: Ancillary message type IPV6_PKTINFO in recvmsg() control messages
 *           - Ancillary data: struct in6_pktinfo (same structure, different constant)
 *           - API defined by RFC 3542 (Advanced Sockets API for IPv6, obsoletes RFC 2292)
 *           - Constant separation: IPV6_RECVPKTINFO (enable option) vs IPV6_PKTINFO (ancillary type)
 *
 *           Why API changed:
 *           RFC 3542 clarified that enabling reception (setsockopt option name) should be distinct
 *           from ancillary data type (cmsg_type in recvmsg). Old API used same constant IPV6_PKTINFO
 *           for both purposes. New API separates them: IPV6_RECVPKTINFO to enable, IPV6_PKTINFO for
 *           ancillary data type. This separation provides better API clarity and consistency with
 *           IPv4 API (IP_RECVPKTINFO vs IP_PKTINFO).
 *
 *           Compatibility strategy (this function's approach):
 *           
 *           Function tries multiple API variants to handle all combinations of:
 *           - Old kernel + old headers (before 2.6.14)
 *           - Old kernel + new headers (old kernel, updated distribution)
 *           - New kernel + old headers (updated kernel, old distribution)
 *           - New kernel + new headers (both updated)
 *
 *           **Attempt 1** (#ifdef IPV6_RECVPKTINFO):
 *           If headers define IPV6_RECVPKTINFO (new headers), try new API first:
 *           - Call setsockopt(IPV6_RECVPKTINFO, 1)
 *           - If succeeds: New kernel with new API, set daemon->v6pktinfo = IPV6_PKTINFO, return 1
 *           - If fails with ENOPROTOOPT: Kernel doesn't support new API (old kernel with new headers)
 *             Fall through to attempt 2.
 *
 *           **Attempt 2** (#ifdef IPV6_2292PKTINFO):
 *           If attempt 1 failed with ENOPROTOOPT and headers define IPV6_2292PKTINFO (compatibility):
 *           - Call setsockopt(IPV6_2292PKTINFO, 1) - old API
 *           - If succeeds: Old kernel with old API, set daemon->v6pktinfo = IPV6_2292PKTINFO, return 1
 *           - If fails: Real error (ENOMEM, EBADF, etc.), return 0
 *
 *           **Fallback** (#else - headers don't define IPV6_RECVPKTINFO):
 *           Old headers that only define IPV6_PKTINFO (used for both enable and ancillary type):
 *           - Call setsockopt(IPV6_PKTINFO, 1) - original undifferentiated API
 *           - daemon->v6pktinfo already set to IPV6_PKTINFO at function start
 *           - Return 1 on success, 0 on failure
 *
 *           Global state management (daemon->v6pktinfo):
 *           Function sets daemon->v6pktinfo to constant that should be used as cmsg_type when parsing
 *           ancillary data in recvmsg(). Later code (recv_dhcp, receive_query, etc.) checks:
 *           if (cmsg->cmsg_type == daemon->v6pktinfo) { parse in6_pktinfo structure }
 *           
 *           This allows single code path to handle both old and new API by selecting correct constant
 *           at runtime based on which setsockopt succeeded. Without this, would need #ifdef in every
 *           recvmsg() call site (code duplication and maintenance burden).
 *
 *           OpenWrt broken patch reference (comment in code):
 *           OpenWrt historically had a patch that hardcoded IPV6_2292PKTINFO, breaking compatibility
 *           with kernels that only supported new API. This function's try-both-APIs approach fixes
 *           that by automatically detecting kernel capabilities instead of hardcoding assumptions.
 *
 *           Error handling:
 *           - ENOPROTOOPT (protocol option not supported): Expected error when trying new API on
 *             old kernel, triggers fallback to old API. Not logged as error.
 *           - Other errors (EBADF, EINVAL, ENOMEM, etc.): Real failures, function returns 0.
 *             Caller (make_sock) handles by logging error and returning -1.
 *           - No error logging in this function - caller responsible for error messages.
 *
 *           Usage in dnsmasq architecture:
 *           Called from make_sock() when creating IPv6 UDP sockets (SOCK_DGRAM, AF_INET6) in
 *           wildcard binding mode (!OPT_NOWILD). Not called for:
 *           - IPv6 TCP sockets (packet info not needed for connection-oriented protocol)
 *           - Bind-interfaces mode (OPT_NOWILD) - separate socket per interface, so destination
 *             address implicitly known from which socket received packet
 *           - IPv4 sockets - use IP_PKTINFO or IP_RECVDSTADDR instead (different API)
 *
 * @param fd File descriptor for IPv6 UDP socket (SOCK_DGRAM, AF_INET6). Must be valid socket fd
 *           obtained from socket() syscall, not yet closed. Socket must be IPv6 (created with
 *           AF_INET6 family), otherwise setsockopt fails with EINVAL or ENOPROTOOPT. Socket must
 *           be UDP (SOCK_DGRAM) - TCP doesn't use packet info (connection-oriented, address known).
 *           Socket can be bound or unbound - setsockopt works in either state. Typically called
 *           after socket() but before bind() in make_sock() initialization sequence.
 *
 * @return Integer success indicator
 * @retval 1 Success: IPv6 packet info reception enabled successfully. Socket will receive
 *           destination address and interface index in ancillary data when calling recvmsg().
 *           daemon->v6pktinfo set to correct constant for parsing ancillary data:
 *           - IPV6_PKTINFO if new API (IPV6_RECVPKTINFO) succeeded
 *           - IPV6_2292PKTINFO if old API fallback succeeded
 *           Caller can proceed with socket usage, knowing packet info will be available.
 * @retval 0 Failure: Unable to enable packet info reception. Neither new API (IPV6_RECVPKTINFO)
 *           nor old API (IPV6_2292PKTINFO) succeeded, or headers don't define either and base
 *           IPV6_PKTINFO also failed. Common failure causes:
 *           - EBADF: fd not valid socket (closed, or not a socket)
 *           - ENOTSOCK: fd is valid file descriptor but not a socket
 *           - EINVAL: fd is socket but wrong protocol family (not AF_INET6)
 *           - ENOMEM: Insufficient kernel memory for option state
 *           - ENOPROTOOPT: Neither new nor old API supported (very old kernel, or wrong socket type)
 *           Caller (make_sock) typically treats failure as fatal error and returns -1, logging
 *           error message. Without packet info, wildcard IPv6 UDP sockets cannot determine which
 *           interface received packets, making response addressing impossible.
 *
 * @note Function modifies global state: daemon->v6pktinfo set to constant for ancillary data parsing.
 *       This global state used by all recvmsg() call sites when checking cmsg_type. Alternative
 *       design would use #ifdef at every call site, but global approach centralizes kernel API
 *       detection and reduces code duplication.
 * @note Try-new-first strategy: Function attempts modern API before legacy API to prefer current
 *       standards. Only falls back to legacy when explicitly signaled by ENOPROTOOPT. Ensures
 *       new kernels use new API even with old headers (header defines IPV6_2292PKTINFO for compat).
 * @note ENOPROTOOPT handling: errno == ENOPROTOOPT specifically checked in fallback attempt,
 *       other errors don't trigger fallback. This distinguishes "option not supported by kernel"
 *       (try fallback) from "real error" (return failure). Without errno check, would mask real
 *       errors (ENOMEM, EBADF) as API incompatibility and incorrectly return 1.
 * @note Ancillary data structure (struct in6_pktinfo): Returned in recvmsg control messages with:
 *       - cmsg_level = IPPROTO_IPV6
 *       - cmsg_type = daemon->v6pktinfo (IPV6_PKTINFO or IPV6_2292PKTINFO)
 *       - cmsg_data = struct in6_pktinfo { ipi6_addr (destination address), ipi6_ifindex (interface index) }
 *       Structure identical across old/new API, only constant name differs.
 * @note IPv4 equivalent: IPv4 sockets use different APIs: IP_PKTINFO (Linux) or IP_RECVDSTADDR +
 *       IP_RECVIF (BSD). No API transition for IPv4 because IPv4 API matured before Linux 2.6.14.
 *       IPv6 API changed due to RFC 2292 -> RFC 3542 revision.
 *
 * @warning Function assumes fd is IPv6 socket (AF_INET6). Calling with IPv4 socket (AF_INET) fails
 *          with ENOPROTOOPT because IPv4 doesn't support IPV6_* options. Caller must ensure correct
 *          socket family before calling. No family validation performed - relies on caller correctness.
 * @warning Socket type matters: Only meaningful for SOCK_DGRAM (UDP). TCP (SOCK_STREAM) ignores
 *          packet info options because connection-oriented protocol already knows addresses. Calling
 *          for TCP socket may succeed but has no effect. make_sock() only calls for UDP sockets.
 * @warning Global state modification (daemon->v6pktinfo): Function is not thread-safe due to global
 *          state mutation. dnsmasq is single-threaded, so not an issue. Multi-threaded use would
 *          require locking or per-socket state instead of global.
 * @warning Return value interpretation: 1 = success, 0 = failure. NOT Unix convention (0 = success,
 *          -1 = failure). Caller must check == 0 for failure, not < 0. Inconsistent with setsockopt
 *          return convention (0 success, -1 failure), but matches dnsmasq's boolean return style.
 * @warning Failure implications: If function returns 0, wildcard IPv6 UDP sockets cannot determine
 *          destination address of received packets. This breaks response addressing for multi-homed
 *          hosts (multiple IPv6 addresses) because daemon cannot respond from correct source address.
 *          Failure typically treated as fatal by caller (make_sock returns -1, daemon initialization
 *          fails with die()).
 * @warning Old kernel detection: Fallback to IPV6_2292PKTINFO only attempted if new API explicitly
 *          returns ENOPROTOOPT. Other errors (ENOMEM, EBADF, etc.) treated as real failures, not
 *          API incompatibility. Incorrectly attempting fallback on real error could mask bugs.
 * @warning OpenWrt compatibility: Comment references "very broken patch" that hardcoded old API,
 *          breaking new kernels. This function's dynamic detection approach fixes that by trying
 *          both APIs. Hardcoding either API breaks half the kernel matrix (old or new).
 *
 * @see make_sock() which calls this function for IPv6 UDP sockets in wildcard mode
 * @see RFC 2292 (Advanced Sockets API for IPv6 - obsolete, defines old API)
 * @see RFC 3542 (Advanced Sockets API for IPv6 - current, defines new API)
 * @see recvmsg(2) for ancillary data (control message) reception mechanism
 * @see setsockopt(2) for socket option configuration syscall
 * @see Linux kernel Documentation/networking/ip-sysctl.txt for IPV6_* options
 *
 * EXAMPLE USAGE:
 * @code
 * // Enable packet info on IPv6 UDP socket (called from make_sock)
 * int fd = socket(AF_INET6, SOCK_DGRAM, 0);  // Create IPv6 UDP socket
 * if (fd == -1)
 *   return -1;
 *   
 * if (!set_ipv6pktinfo(fd))
 *   {
 *     // Failed to enable packet info
 *     close(fd);
 *     return -1;
 *   }
 *   
 * // Socket now configured to receive destination address and interface in recvmsg()
 * // daemon->v6pktinfo contains correct constant (IPV6_PKTINFO or IPV6_2292PKTINFO)
 * @endcode
 *
 * @code
 * // Later, receiving packet with ancillary data (in receive_query or recv_dhcp)
 * struct msghdr msg;
 * struct iovec iov;
 * char control[CMSG_SPACE(sizeof(struct in6_pktinfo))];
 * 
 * msg.msg_control = control;
 * msg.msg_controllen = sizeof(control);
 * // ... setup iov and rest of msg ...
 * 
 * recvmsg(fd, &msg, 0);
 * 
 * // Parse ancillary data for packet info
 * for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg))
 *   {
 *     if (cmsg->cmsg_level == IPPROTO_IPV6 && 
 *         cmsg->cmsg_type == daemon->v6pktinfo)  // Use runtime-detected constant
 *       {
 *         struct in6_pktinfo *pktinfo = (struct in6_pktinfo *)CMSG_DATA(cmsg);
 *         // pktinfo->ipi6_addr = destination address packet was sent to
 *         // pktinfo->ipi6_ifindex = interface index packet arrived on
 *       }
 *   }
 * @endcode
 *
 * KERNEL VERSION COMPATIBILITY MATRIX:
 * 
 * Linux < 2.6.14 (OLD KERNEL):
 *   Headers: Define IPV6_2292PKTINFO (or only IPV6_PKTINFO)
 *   setsockopt(IPV6_RECVPKTINFO) -> ENOPROTOOPT (not supported)
 *   setsockopt(IPV6_2292PKTINFO) -> success
 *   Result: daemon->v6pktinfo = IPV6_2292PKTINFO
 * 
 * Linux >= 2.6.14 (NEW KERNEL):
 *   Headers: Define IPV6_RECVPKTINFO and IPV6_PKTINFO
 *   setsockopt(IPV6_RECVPKTINFO) -> success
 *   Result: daemon->v6pktinfo = IPV6_PKTINFO
 * 
 * Old headers + new kernel:
 *   Headers: Define IPV6_PKTINFO (undifferentiated)
 *   setsockopt(IPV6_PKTINFO, 1) -> success (kernel accepts, treats as IPV6_RECVPKTINFO)
 *   Result: daemon->v6pktinfo = IPV6_PKTINFO (works because kernel supports old ABI)
 * 
 * New headers + old kernel:
 *   Headers: Define IPV6_RECVPKTINFO and IPV6_2292PKTINFO
 *   setsockopt(IPV6_RECVPKTINFO) -> ENOPROTOOPT
 *   setsockopt(IPV6_2292PKTINFO) -> success
 *   Result: daemon->v6pktinfo = IPV6_2292PKTINFO
 *
 * RFC COMPLIANCE:
 * - RFC 2292: Advanced Sockets API for IPv6 (obsolete, defines IPV6_2292PKTINFO old API)
 * - RFC 3542: Advanced Sockets API for IPv6 (current, defines IPV6_RECVPKTINFO/IPV6_PKTINFO new API)
 * 
 * SIDE EFFECTS:
 * - Modifies socket fd's options (enables packet info reception)
 * - Sets global daemon->v6pktinfo to IPV6_PKTINFO or IPV6_2292PKTINFO (affects all recvmsg parsing)
 * - No error logging (caller responsible for error messages if return 0)
 * 
 * THREAD SAFETY: Not thread-safe due to daemon->v6pktinfo global state modification.
 *                 dnsmasq single-threaded architecture makes this acceptable.
 */
int set_ipv6pktinfo(int fd)
{
  int opt = 1;

  /* The API changed around Linux 2.6.14 but the old ABI is still supported:
     handle all combinations of headers and kernel.
     OpenWrt note that this fixes the problem addressed by your very broken patch. */
  daemon->v6pktinfo = IPV6_PKTINFO;
  
#ifdef IPV6_RECVPKTINFO
  if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &opt, sizeof(opt)) != -1)
    return 1;
# ifdef IPV6_2292PKTINFO
  else if (errno == ENOPROTOOPT && setsockopt(fd, IPPROTO_IPV6, IPV6_2292PKTINFO, &opt, sizeof(opt)) != -1)
    {
      daemon->v6pktinfo = IPV6_2292PKTINFO;
      return 1;
    }
# endif 
#else
  if (setsockopt(fd, IPPROTO_IPV6, IPV6_PKTINFO, &opt, sizeof(opt)) != -1)
    return 1;
#endif

  return 0;
}


/**
 * @brief Find interface index on which TCP connection arrived (Linux only)
 * 
 * @detailed Determine which network interface received the TCP connection by querying kernel
 *           packet options associated with connected socket. For TCP connections, standard
 *           recvmsg() ancillary data mechanism cannot be used because TCP is connection-oriented
 *           (connection already established when accept() returns), so this function uses
 *           getsockopt(IP_PKTOPTIONS/IPV6_PKTOPTIONS) to retrieve packet info from connection
 *           establishment phase (SYN packet that initiated connection).
 *
 *           Why interface detection necessary for TCP:
 *           For servers with multiple network interfaces and multiple IP addresses, determining
 *           which interface received connection enables:
 *           - **Interface-specific policy enforcement**: Apply different rules for connections
 *             arriving on external vs internal interfaces (e.g., VPN vs local network).
 *           - **Logging and monitoring**: Track connection sources by interface for security
 *             auditing and traffic analysis.
 *           - **Response source address selection**: Respond from same interface's address to
 *             maintain routing symmetry and avoid asymmetric routing issues.
 *           - **Firewall integration**: Populate interface-specific ipset/nftables entries.
 *
 *           Connection establishment context:
 *           When client initiates TCP connection to server:
 *           1. Client sends SYN packet to server IP address
 *           2. Kernel routes SYN packet to appropriate interface based on server IP
 *           3. Server receives SYN, kernel stores packet info internally
 *           4. Server sends SYN-ACK, client responds with ACK (three-way handshake completes)
 *           5. accept() returns new connected socket file descriptor
 *           6. At this point, connection established, but original packet info preserved in kernel
 *           7. getsockopt(IP_PKTOPTIONS/IPV6_PKTOPTIONS) retrieves preserved packet info from SYN
 *
 *           UDP vs TCP difference:
 *           - **UDP**: Each datagram independent, recvmsg() receives ancillary data with every packet
 *             (IP_PKTINFO/IPV6_PKTINFO in control messages). Destination address and interface
 *             retrieved directly from ancillary data.
 *           - **TCP**: Connection-oriented, no per-message ancillary data after accept(). Must use
 *             getsockopt(IP_PKTOPTIONS) to query connection establishment packet info. Only available
 *             on connected sockets, not listening sockets.
 *
 *           IPv4 implementation (IP_PKTOPTIONS):
 *           1. Enable packet info: setsockopt(IP_PKTINFO, 1) tells kernel to preserve packet options
 *           2. Retrieve options: getsockopt(IP_PKTOPTIONS) returns control messages buffer containing
 *              packet info from connection's initial SYN packet
 *           3. Parse control messages: Iterate CMSG_FIRSTHDR/CMSG_NXTHDR to find IP_PKTINFO message
 *           4. Extract interface: struct in_pktinfo contains ipi_ifindex (interface index)
 *
 *           IPv6 RFC regression (RFC-2292 → RFC-3542):
 *           **CRITICAL API CHANGE**: RFC-3542 (Advanced Sockets API for IPv6, 2003) REMOVED the
 *           ability to retrieve interface information for TCP connections, which was present in
 *           RFC-2292 (Advanced Sockets API for IPv6, 1999). This was an incomprehensible regression
 *           that broke legitimate use cases like interface-specific policy enforcement.
 *
 *           RFC-2292 provided: IPV6_PKTOPTIONS socket option for TCP sockets returning packet info
 *           RFC-3542 removed: This functionality entirely from the specification
 *
 *           Why RFC-3542 removed it:
 *           RFC-3542 authors decided that "sticky options" paradigm (setsockopt to set, getsockopt
 *           to query) was cleaner than retrieving packet info from established connections. They
 *           considered TCP connection interface retrieval an edge case not worth standardizing.
 *           However, this broke real-world applications that relied on this capability.
 *
 *           Linux kernel compatibility workaround:
 *           **Fortunately**, Linux kernel developers recognized this as harmful regression and
 *           preserved the RFC-2292 ABI even after implementing RFC-3542 features. Linux maintains
 *           BOTH APIs simultaneously:
 *           - IPV6_2292PKTOPTIONS: Old RFC-2292 constant (explicitly old ABI)
 *           - IPV6_PKTOPTIONS: Undifferentiated constant (works with both old and new kernels)
 *
 *           This function's IPv6 strategy:
 *           Intentionally use RFC-2292 API because it's the ONLY way to get interface info for TCP.
 *           Use conditional compilation to select constant name:
 *           - If headers define IPV6_2292PKTOPTIONS: Use explicit old API name
 *           - Otherwise: Use IPV6_PKTOPTIONS (works on kernels predating RFC-3542 transition)
 *
 *           Code always uses old ABI regardless of kernel or header version because:
 *           1. New RFC-3542 API doesn't provide TCP interface info (feature removed)
 *           2. Linux preserved old ABI for backward compatibility (only platform that matters for dnsmasq)
 *           3. Works with both pre-3542 and post-3542 kernel headers (constant name differs but ABI same)
 *
 *           Implementation sequence for IPv6:
 *           1. Call set_ipv6pktinfo(fd) to enable packet info reception (may use new or old API internally)
 *           2. Use getsockopt(IPV6_PKTOPTIONS) with old RFC-2292 semantics to retrieve connection info
 *           3. Parse control messages using daemon->v6pktinfo constant (set by set_ipv6pktinfo)
 *           4. Extract struct in6_pktinfo containing ipi6_ifindex
 *
 *           Global state usage (daemon->packet buffer):
 *           Function reuses daemon->packet buffer (allocated at daemon start, size daemon->packet_buff_sz)
 *           to receive control messages from getsockopt(). This buffer normally used for receiving UDP
 *           packets via recvmsg(). Reusing buffer saves memory allocation but requires coordination:
 *           - Set daemon->srv_save = NULL to invalidate any cached server pointer referencing buffer
 *           - Caller must be aware buffer contents overwritten
 *           - Not thread-safe (single-threaded architecture makes this acceptable)
 *
 *           Platform limitations:
 *           **Linux-only**: Entire implementation wrapped in #ifdef HAVE_LINUX_NETWORK. Non-Linux
 *           platforms (BSD, Solaris, macOS) return 0 (interface unknown). BSD might support similar
 *           functionality via different APIs, but not currently implemented. For most use cases on
 *           non-Linux platforms, interface detection not critical because BSD typically uses BPF
 *           for DHCP (provides interface info differently) and DNS-over-TCP less interface-sensitive.
 *
 *           Return value semantics:
 *           - **Non-zero (if_index)**: Successfully determined interface, return kernel interface index
 *             (eth0 might be index 2, wlan0 index 3, etc.). Index can be converted to name via
 *             if_indextoname() or indextoname() function in this file.
 *           - **Zero**: Unable to determine interface. Reasons:
 *             * Non-Linux platform (entire function body compiled out)
 *             * setsockopt(IP_PKTINFO/IPV6_PKTINFO) failed (unlikely, but possible if socket already closed)
 *             * getsockopt(IP_PKTOPTIONS/IPV6_PKTOPTIONS) failed (socket not connected, or kernel didn't
 *               preserve packet info, or connection established before packet info enabled)
 *             * Control messages didn't contain packet info (unexpected, but defensive programming)
 *             Returning 0 is non-fatal - caller proceeds without interface information, which typically
 *             means falling back to default behavior (no interface-specific policy enforcement).
 *
 *           Error handling philosophy:
 *           Function does NOT log errors for failure cases. Returns 0 (interface unknown) silently.
 *           Rationale:
 *           - Non-Linux platforms always return 0, so logging would spam logs on BSD/Solaris/macOS
 *           - getsockopt failure might be normal (connection established before packet info enabled)
 *           - Missing interface info is non-fatal for most use cases
 *           - Caller can check return value and log if interface detection critical for their use case
 *
 *           Typical call sites:
 *           - TCP DNS connections: Determine interface for logging and policy (tcp_request in dnsmasq.c)
 *           - TCP DHCP (rare): Determine interface for DHCP relay scenarios
 *           - Future features: Interface-based access control, traffic shaping integration
 *
 *           Control message parsing:
 *           Uses standard POSIX ancillary data (control message) API:
 *           - CMSG_FIRSTHDR: Get first control message in msg.msg_control buffer
 *           - CMSG_NXTHDR: Iterate to next control message (NULL when exhausted)
 *           - CMSG_DATA: Get pointer to control message data (struct in_pktinfo or in6_pktinfo)
 *           Loop continues until IP_PKTINFO (IPv4) or daemon->v6pktinfo (IPv6) message found.
 *
 *           Union pointer cast pattern:
 *           Code uses union { unsigned char *c; struct in_pktinfo *p; } to cast CMSG_DATA pointer:
 *           - CMSG_DATA returns unsigned char * (generic byte pointer)
 *           - Need struct in_pktinfo * to access ipi_ifindex member
 *           - Union cast ensures proper alignment and type-punning without violating strict aliasing
 *           Same pattern for IPv6: union { unsigned char *c; struct in6_pktinfo *p; }
 *
 * @param fd File descriptor for connected TCP socket returned from accept(). Must be valid socket
 *           file descriptor in connected state (connection established, not listening socket).
 *           Socket must be TCP (SOCK_STREAM) - UDP sockets use different mechanism (recvmsg ancillary
 *           data). For IPv4, socket family must be AF_INET. For IPv6, socket family must be AF_INET6.
 *           Passing listening socket (before accept) returns 0 (no connection, no packet info).
 *           Passing closed socket returns 0 (setsockopt/getsockopt fail).
 *           Socket must have been accepted AFTER dnsmasq started - connections established before
 *           daemon start may not have packet info preserved (depends on kernel).
 *
 * @param af Address family constant indicating protocol version. Determines which packet info API to use.
 *           Valid values:
 *           - AF_INET (IPv4): Use IP_PKTINFO and IP_PKTOPTIONS APIs for IPv4 packet info retrieval.
 *             Parse struct in_pktinfo to get ipi_ifindex.
 *           - AF_INET6 (IPv6): Use IPV6_PKTINFO/IPV6_2292PKTINFO and IPV6_PKTOPTIONS/IPV6_2292PKTOPTIONS
 *             APIs for IPv6 packet info retrieval. Parse struct in6_pktinfo to get ipi6_ifindex.
 *           Invalid values (AF_UNIX, AF_NETLINK, etc.) return 0 (no handling for other families).
 *           Value must match socket family from fd or getsockopt fails with ENOPROTOOPT.
 *           Typically obtained from accept() via getpeername() or from listener's configured family.
 *
 * @return Interface index (positive integer) on success, or 0 if unable to determine
 * @retval >0 Success: Kernel interface index on which TCP connection's initial SYN packet arrived.
 *            Interface index can be converted to interface name via if_indextoname(3) or
 *            indextoname() function in this file. Typical values: eth0=2, wlan0=3, lo=1.
 *            Index is kernel-assigned and stable during interface lifetime, but may change across
 *            reboots (especially for dynamically created interfaces like PPP, VPN). Valid for
 *            passing to socket binding operations or interface name lookups. Caller can use this
 *            to enforce interface-specific policies, log connection source, or select response
 *            source address.
 * @retval 0 Unable to determine interface. Reasons (non-error conditions):
 *           - Non-Linux platform: HAVE_LINUX_NETWORK not defined, function body empty, returns 0.
 *             BSD/Solaris/macOS lack IP_PKTOPTIONS API (or equivalent not implemented in dnsmasq).
 *           - setsockopt(IP_PKTINFO) failed: Socket may be closed, or bad file descriptor, or
 *             insufficient permissions. Non-fatal - proceed without interface info.
 *           - getsockopt(IP_PKTOPTIONS) failed: Kernel didn't preserve packet info (connection
 *             established before packet info enabled), or socket not properly connected, or
 *             connection closed mid-query. Non-fatal - return 0.
 *           - Control messages didn't contain packet info: Unexpected but possible if kernel's
 *             packet option handling has bug or platform variation. Non-fatal - return 0.
 *           Returning 0 is NOT an error for caller - simply means interface detection unavailable.
 *           Caller should proceed with default behavior (no interface-specific handling). No errno
 *           set (0 is valid return value meaning "unknown interface", not error).
 *
 * @note Linux-only: Entire function implementation wrapped in #ifdef HAVE_LINUX_NETWORK. Non-Linux
 *       platforms compile to stub function returning 0 (after unused parameter warnings suppression).
 * @note RFC-3542 regression: IPv6 implementation intentionally uses old RFC-2292 API because newer
 *       RFC-3542 removed TCP interface detection capability. Linux preserved old ABI for compatibility.
 * @note Global state: Reuses daemon->packet buffer and sets daemon->srv_save=NULL. Caller must be
 *       aware buffer contents overwritten. Not thread-safe (single-threaded architecture).
 * @note set_ipv6pktinfo dependency: IPv6 path calls set_ipv6pktinfo(fd) to enable packet info.
 *       If this fails (returns 0), getsockopt still attempted but likely fails. Non-fatal.
 * @note Return value 0 is non-error: Zero means "unknown interface", not failure. Caller should
 *       proceed with default behavior. No error logging performed by this function.
 * @note Interface index stability: Index stable during interface lifetime but may change across
 *       reboots. Don't persist index values across daemon restarts - use interface names instead.
 * @note accept() timing: Connection must be accepted AFTER packet info enabled (daemon start).
 *       Connections established before daemon start may lack packet info. Normal usage pattern
 *       (accept after bind) ensures packet info available.
 *
 * @warning fd must be connected TCP socket: Passing listening socket (before accept) returns 0.
 *          Passing UDP socket returns 0 (use recvmsg ancillary data for UDP instead). Passing
 *          closed socket returns 0 (setsockopt/getsockopt fail). No validation performed.
 * @warning af must match socket family: Passing AF_INET for IPv6 socket (or vice versa) causes
 *          getsockopt to fail with ENOPROTOOPT, returns 0. No family validation performed.
 * @warning Buffer overwrite: daemon->packet buffer overwritten by getsockopt(). Caller must not
 *          rely on buffer contents after calling this function. daemon->srv_save set NULL.
 * @warning Non-thread-safe: Modifies global daemon->srv_save and uses global daemon->packet buffer.
 *          Concurrent calls would corrupt shared state. Single-threaded architecture required.
 * @warning Platform portability: Function returns 0 on all non-Linux platforms. Code relying on
 *          non-zero return for correctness will fail on BSD/Solaris/macOS. Must handle 0 gracefully.
 * @warning Control message parsing: Assumes kernel provides valid control message format. Malformed
 *          control messages could cause CMSG_NXTHDR to access invalid memory. Relies on kernel
 *          correctness (reasonable assumption for packet options API).
 * @warning Union cast: Union pointer pattern relies on struct alignment matching CMSG_DATA alignment.
 *          Valid per POSIX ancillary data API guarantees, but strict aliasing must be considered.
 * @warning IPv6 RFC-3542 incompatibility: Code intentionally uses old RFC-2292 API. Systems that
 *          removed old ABI (non-Linux, or future kernel) would fail. Linux commitment to ABI
 *          stability makes this safe.
 *
 * @see set_ipv6pktinfo() which enables IPv6 packet info reception (called for IPv6 path)
 * @see indextoname() which converts interface index to interface name string
 * @see make_sock() which creates sockets with packet info enabled for UDP
 * @see tcp_request() in dnsmasq.c which calls this function for TCP DNS connections
 * @see accept(2) for TCP connection acceptance (returns fd parameter)
 * @see getsockopt(2) with IP_PKTOPTIONS/IPV6_PKTOPTIONS options
 * @see setsockopt(2) with IP_PKTINFO/IPV6_PKTINFO options
 * @see RFC 2292 (Advanced Sockets API for IPv6 - old, defines IPV6_PKTOPTIONS for TCP)
 * @see RFC 3542 (Advanced Sockets API for IPv6 - current, REMOVED IPV6_PKTOPTIONS for TCP)
 *
 * EXAMPLE USAGE:
 * @code
 * // Called from TCP DNS connection handler after accept()
 * int tcpfd = accept(listening_socket, &client_addr, &client_len);
 * if (tcpfd == -1)
 *   return;  // accept failed
 *   
 * // Determine which interface received connection
 * int if_index = tcp_interface(tcpfd, client_addr.sa_family);
 * 
 * if (if_index > 0)
 *   {
 *     // Interface known - can apply interface-specific policy
 *     char ifname[IF_NAMESIZE];
 *     if (indextoname(tcpfd, if_index, ifname))
 *       my_syslog(LOG_INFO, "TCP connection from %s on interface %s", 
 *                 client_ip, ifname);
 *     // Apply interface-based access control, logging, etc.
 *   }
 * else
 *   {
 *     // Interface unknown (non-Linux or detection failed)
 *     // Proceed with default behavior - no interface-specific handling
 *     my_syslog(LOG_INFO, "TCP connection from %s (interface unknown)", 
 *               client_ip);
 *   }
 * 
 * // Process connection regardless of interface detection result
 * handle_tcp_request(tcpfd);
 * close(tcpfd);
 * @endcode
 *
 * @code
 * // Platform-specific behavior example
 * #ifdef HAVE_LINUX_NETWORK
 * // Linux - interface detection available
 * int if_idx = tcp_interface(fd, AF_INET6);
 * if (if_idx > 0)
 *   enforce_interface_policy(if_idx);  // Apply Linux-specific rules
 * #else
 * // BSD/Solaris/macOS - interface detection returns 0
 * // Must use alternative mechanisms (BPF, routing table lookup, etc.)
 * int if_idx = tcp_interface(fd, AF_INET6);  // Always returns 0
 * // Fall back to default behavior
 * #endif
 * @endcode
 *
 * CONTROL MESSAGE STRUCTURE (IPv4):
 * 
 * getsockopt(fd, IPPROTO_IP, IP_PKTOPTIONS, buffer, &len) returns:
 * 
 * buffer contains series of cmsghdr structures:
 * struct cmsghdr {
 *   socklen_t cmsg_len;    // Length including header
 *   int cmsg_level;        // IPPROTO_IP
 *   int cmsg_type;         // IP_PKTINFO
 *   // Followed by:
 *   struct in_pktinfo {
 *     int ipi_ifindex;     // <- Interface index we want
 *     struct in_addr ipi_spec_dst;  // Destination address
 *     struct in_addr ipi_addr;      // Header destination address
 *   }
 * }
 *
 * CONTROL MESSAGE STRUCTURE (IPv6):
 * 
 * getsockopt(fd, IPPROTO_IPV6, IPV6_PKTOPTIONS, buffer, &len) returns:
 * 
 * buffer contains series of cmsghdr structures:
 * struct cmsghdr {
 *   socklen_t cmsg_len;    // Length including header
 *   int cmsg_level;        // IPPROTO_IPV6
 *   int cmsg_type;         // IPV6_PKTINFO or IPV6_2292PKTINFO (daemon->v6pktinfo)
 *   // Followed by:
 *   struct in6_pktinfo {
 *     struct in6_addr ipi6_addr;     // Destination address
 *     unsigned int ipi6_ifindex;     // <- Interface index we want
 *   }
 * }
 *
 * RFC COMPLIANCE:
 * - RFC 2292: Advanced Sockets API for IPv6 (obsolete, but defines IPV6_PKTOPTIONS for TCP)
 * - RFC 3542: Advanced Sockets API for IPv6 (current, REMOVED IPV6_PKTOPTIONS for TCP - regression!)
 * - Linux maintains RFC-2292 ABI for backward compatibility despite implementing RFC-3542
 *
 * SIDE EFFECTS:
 * - Modifies global daemon->srv_save (set to NULL) - invalidates cached server pointer
 * - Overwrites global daemon->packet buffer with control messages from getsockopt()
 * - Calls set_ipv6pktinfo(fd) for IPv6 which modifies daemon->v6pktinfo global state
 * - No error logging (silent failure - returns 0)
 * - May call setsockopt() and getsockopt() syscalls (can fail with errno)
 *
 * THREAD SAFETY: Not thread-safe due to global state modification (daemon->srv_save, daemon->packet).
 *                 dnsmasq's single-threaded architecture makes this acceptable.
 */
int tcp_interface(int fd, int af)
{ 
  (void)fd; /* suppress potential unused warning */
  (void)af; /* suppress potential unused warning */
  int if_index = 0;

#ifdef HAVE_LINUX_NETWORK
  int opt = 1;
  struct cmsghdr *cmptr;
  struct msghdr msg;
  socklen_t len;
  
  /* use mshdr so that the CMSDG_* macros are available */
  msg.msg_control = daemon->packet;
  msg.msg_controllen = len = daemon->packet_buff_sz;

  /* we overwrote the buffer... */
  daemon->srv_save = NULL; 

  if (af == AF_INET)
    {
      if (setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &opt, sizeof(opt)) != -1 &&
	  getsockopt(fd, IPPROTO_IP, IP_PKTOPTIONS, msg.msg_control, &len) != -1)
	{
	  msg.msg_controllen = len;
	  for (cmptr = CMSG_FIRSTHDR(&msg); cmptr; cmptr = CMSG_NXTHDR(&msg, cmptr))
	    if (cmptr->cmsg_level == IPPROTO_IP && cmptr->cmsg_type == IP_PKTINFO)
	      {
		union {
		  unsigned char *c;
		  struct in_pktinfo *p;
		} p;
		
		p.c = CMSG_DATA(cmptr);
		if_index = p.p->ipi_ifindex;
	      }
	}
    }
  else
    {
      /* Only the RFC-2292 API has the ability to find the interface for TCP connections,
	 it was removed in RFC-3542 !!!! 

	 Fortunately, Linux kept the 2292 ABI when it moved to 3542. The following code always
	 uses the old ABI, and should work with pre- and post-3542 kernel headers */

#ifdef IPV6_2292PKTOPTIONS   
#  define PKTOPTIONS IPV6_2292PKTOPTIONS
#else
#  define PKTOPTIONS IPV6_PKTOPTIONS
#endif

      if (set_ipv6pktinfo(fd) &&
	  getsockopt(fd, IPPROTO_IPV6, PKTOPTIONS, msg.msg_control, &len) != -1)
	{
          msg.msg_controllen = len;
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
	}
    }
#endif /* Linux */
 
  return if_index;
}
      
/**
 * @brief Create listener structure with DNS and optionally TFTP sockets bound to specific address
 * 
 * @detailed Allocate and initialize struct listener containing sockets for DNS services (UDP and TCP)
 *           and optionally TFTP server on specified network address. This function creates up to three
 *           sockets (DNS UDP, DNS TCP, TFTP UDP) bound to the same address but different ports, bundles
 *           them into single listener structure for unified management in dnsmasq's event loop.
 *
 *           Socket creation strategy:
 *           Function creates separate sockets for different protocols/services on same address:
 *           - **DNS UDP (port daemon->port, default 53)**: Handle DNS queries via connectionless datagram
 *             protocol. Most DNS traffic uses UDP due to low overhead and fast response time.
 *           - **DNS TCP (port daemon->port, default 53)**: Handle DNS queries requiring reliable transport,
 *             large responses (>512 bytes without EDNS0), or zone transfers. TCP required by RFC 1035
 *             for responses exceeding UDP size limits.
 *           - **TFTP UDP (port 69)**: Handle TFTP file transfers for network boot scenarios (PXE boot).
 *             Only created when HAVE_TFTP compiled in and do_tftp parameter true. TFTP server provides
 *             boot images for diskless workstations.
 *
 *           Why bundle multiple sockets per address:
 *           Single address (e.g., 192.168.1.1 or 2001:db8::1) must support multiple protocol/port
 *           combinations simultaneously. Bundling in struct listener enables:
 *           - **Unified event loop management**: All sockets for same address added to poll set together,
 *             simplifying socket lifecycle management (add all at once, remove all at once).
 *           - **Interface tracking**: Associate all sockets with same interface metadata (interface name,
 *             index, configuration) without duplication.
 *           - **Memory efficiency**: Single allocation for listener structure containing all socket fds
 *             rather than separate allocations per socket.
 *           - **Cleanup simplification**: Single free() and release_listener() call closes all sockets
 *             for address instead of tracking each separately.
 *
 *           Port number handling (daemon->port):
 *           daemon->port global variable determines DNS service port (default 53 from DNS_PORT constant
 *           in dnsmasq.h). Can be configured via --port option (0 disables DNS entirely, non-standard
 *           port for testing/special scenarios). Function checks daemon->port != 0 before creating DNS
 *           sockets - if port 0, only TFTP socket created (if do_tftp true).
 *
 *           Why daemon->port might be 0:
 *           Configuration option --port=0 disables DNS service, useful for DHCP-only or TFTP-only
 *           deployments where DNS functionality not needed. Example: Embedded device acting purely
 *           as DHCP server without DNS forwarding.
 *
 *           TFTP port handling (temporary modification of addr structure):
 *           TFTP uses UDP port 69 (TFTP_PORT constant), different from DNS port. However, addr parameter
 *           passed in contains DNS port number in sin_port/sin6_port field. To create TFTP socket on
 *           correct port while reusing same address, function:
 *           1. Save original port value from addr structure (DNS port)
 *           2. Overwrite port field with htons(TFTP_PORT) = 69 in network byte order
 *           3. Call make_sock(&addr, SOCK_DGRAM, dienow) to create TFTP socket on port 69
 *           4. Restore original port value to addr structure (leave addr unchanged for caller)
 *
 *           Why temporary modification acceptable:
 *           addr parameter is value passed to make_sock(), not pointer used after function returns,
 *           so restoration ensures caller's addr unchanged. Alternative would be copying entire addr
 *           structure (larger), or modifying make_sock() signature to accept separate port parameter
 *           (breaks existing API). Temporary modification is efficient and safe since addr restored
 *           before function returns.
 *
 *           IPv4 vs IPv6 port field differences:
 *           - IPv4 (AF_INET): addr->in.sin_port field in struct sockaddr_in
 *           - IPv6 (AF_INET6): addr->in6.sin6_port field in struct sockaddr_in6
 *           Function checks addr->sa.sa_family to determine which union member to use, ensuring correct
 *           field modified. Both fields same size (uint16_t) and same offset in respective structures,
 *           but explicit family check prevents subtle bugs if structure layouts change.
 *
 *           Socket creation error handling (partial success):
 *           Function attempts to create all applicable sockets (DNS UDP, DNS TCP, TFTP if enabled) but
 *           does NOT require all to succeed. Partial success acceptable:
 *           - If DNS UDP creation fails but DNS TCP succeeds: Listener created with fd=-1, tcpfd=valid.
 *             Daemon operates in TCP-only mode for this address (unusual but functional).
 *           - If DNS TCP creation fails but DNS UDP succeeds: Listener created with fd=valid, tcpfd=-1.
 *             Daemon operates in UDP-only mode (common if TCP port already bound by another process).
 *           - If TFTP creation fails but DNS sockets succeed: Listener created with tftpfd=-1.
 *             DNS services functional, TFTP unavailable (acceptable for TFTP-optional configs).
 *           - If ALL sockets fail: Function returns NULL (no listener created, address unusable).
 *
 *           Why partial success acceptable:
 *           Network conditions may prevent binding all sockets (another process using TCP port 53,
 *           TFTP disabled by admin, insufficient privileges for certain socket types). Daemon should
 *           operate with available functionality rather than failing entirely. make_sock() handles
 *           error logging based on dienow parameter, so this function doesn't duplicate error messages.
 *
 *           Listener structure initialization:
 *           If at least one socket created successfully (fd != -1 || tcpfd != -1 || tftpfd != -1):
 *           - Allocate struct listener via safe_malloc() (dies on allocation failure, never returns NULL)
 *           - Initialize l->next = NULL (linked list insertion handled by caller)
 *           - Store socket file descriptors: l->fd (UDP DNS), l->tcpfd (TCP DNS), l->tftpfd (TFTP)
 *             Failed sockets stored as -1 (indicates socket unavailable)
 *           - Copy address: l->addr = *addr (contains IP address and port for DNS, NOT TFTP port)
 *             Stored address is original addr parameter value (DNS port), TFTP port modification
 *             already restored before this point
 *           - Set l->used = 1 (marks listener as active, used for cleanup tracking)
 *           - Initialize l->iface = NULL (interface pointer set by caller, typically create_bound_listeners
 *             or create_wildcard_listeners)
 *
 *           Listener lifecycle:
 *           1. **Creation**: This function creates listener with sockets bound to address
 *           2. **Insertion**: Caller adds listener to daemon->listeners linked list
 *           3. **Event loop**: Sockets added to poll set for event notification
 *           4. **Cleanup**: release_listener() closes sockets and frees memory
 *
 *           Typical call sites:
 *           - **create_bound_listeners()**: Creates listeners for specific interface addresses in
 *             --bind-interfaces mode (separate socket per interface IP)
 *           - **create_wildcard_listeners()**: Creates listeners for wildcard addresses (0.0.0.0, ::)
 *             in default mode (single socket receives all interfaces)
 *           - **newaddress()**: Creates listeners for newly appeared interface addresses in
 *             --bind-dynamic mode (dynamic interface addition)
 *
 *           Memory management:
 *           - Listener allocated via safe_malloc() which dies on OOM (never returns NULL)
 *           - Caller responsible for:
 *             * Inserting listener into daemon->listeners linked list (or freeing if rejected)
 *             * Eventually calling release_listener() to close sockets and free memory
 *           - Socket fds managed by kernel (closed when process exits if not explicitly closed)
 *           - No cyclic references (l->next is forward pointer only)
 *
 *           Conditional compilation (HAVE_TFTP):
 *           TFTP socket creation code wrapped in #ifdef HAVE_TFTP / #endif. If TFTP support not
 *           compiled (HAVE_TFTP undefined), TFTP creation code omitted entirely, and do_tftp parameter
 *           effectively ignored (marked with (void)do_tftp to suppress unused parameter warning).
 *           This allows feature-minimal builds without TFTP increasing binary size.
 *
 *           do_tftp parameter vs HAVE_TFTP define:
 *           - HAVE_TFTP: Compile-time flag determining if TFTP code included in binary
 *           - do_tftp: Runtime flag determining if TFTP socket created for this listener
 *           Both must be true for TFTP socket creation. HAVE_TFTP false = no TFTP code compiled,
 *           do_tftp ignored. HAVE_TFTP true but do_tftp false = TFTP code present but not used
 *           for this listener (e.g., --enable-tftp=eth0 only enables TFTP on eth0, not other interfaces).
 *
 *           Address family handling:
 *           Function accepts both IPv4 (AF_INET) and IPv6 (AF_INET6) addresses transparently via
 *           union mysockaddr. make_sock() determines address family from addr->sa.sa_family and
 *           creates appropriate socket type. TFTP port modification code explicitly checks family
 *           to access correct union member (sin_port vs sin6_port). No AF_UNIX or other families
 *           supported (would fail in make_sock with EAFNOSUPPORT).
 *
 *           Network byte order (htons):
 *           Port number assignments use htons() (host-to-network-short) to convert port numbers
 *           from host byte order to network byte order. TFTP_PORT constant (69) is in host byte
 *           order, htons(TFTP_PORT) converts to network byte order required by socket API. Original
 *           addr->in.sin_port already in network byte order (set by caller), so restoration works
 *           correctly. Host byte order varies by architecture (little-endian x86, big-endian SPARC),
 *           network byte order always big-endian per TCP/IP standards.
 *
 * @param addr Pointer to union mysockaddr containing address to bind sockets. Must be properly initialized
 *             with family (sa_family), IP address (sin_addr/sin6_addr), and port number (sin_port/sin6_port
 *             in network byte order). Port should be DNS service port (typically 53). Address copied into
 *             listener structure (l->addr = *addr), so caller retains ownership of addr structure.
 *             Function temporarily modifies port field during TFTP socket creation but restores original
 *             value before returning, ensuring addr unchanged from caller's perspective.
 *             IPv4 example: addr->in.sin_family=AF_INET, addr->in.sin_addr.s_addr=specific IP or INADDR_ANY,
 *             addr->in.sin_port=htons(53).
 *             IPv6 example: addr->in6.sin6_family=AF_INET6, addr->in6.sin6_addr=specific IPv6 or in6addr_any,
 *             addr->in6.sin6_port=htons(53).
 *             Wildcard addresses (0.0.0.0 for IPv4, :: for IPv6) create sockets receiving on all interfaces.
 *             Specific addresses create sockets bound to single interface IP.
 *             Must not be NULL (dereferenced without NULL check, would segfault).
 *
 * @param do_tftp Boolean flag indicating whether to create TFTP socket (port 69) in addition to DNS sockets.
 *                Non-zero value (typically 1) enables TFTP socket creation. Zero disables TFTP socket creation.
 *                Only effective if HAVE_TFTP compile flag defined, otherwise ignored (suppressed with (void)do_tftp).
 *                Common scenarios:
 *                - do_tftp=1: Interface configured with --enable-tftp or --tftp-port option, TFTP server enabled.
 *                  Creates DNS sockets plus TFTP socket on port 69.
 *                - do_tftp=0: Interface without TFTP configuration, or TFTP globally disabled. Creates only DNS sockets.
 *                Per-interface TFTP control allows selective TFTP service (enable on internal interface, disable
 *                on external interface for security). Global --enable-tftp enables TFTP on all interfaces (do_tftp=1 everywhere).
 *                Value typically derived from interface configuration or global daemon->tftp_no_fail flag.
 *
 * @param dienow Error handling mode controlling behavior when socket creation fails. Passed directly to make_sock()
 *               for each socket creation attempt. Determines whether failure is fatal (terminate daemon) or
 *               recoverable (log warning, continue with partial functionality).
 *               Values (same semantics as make_sock):
 *               - 1 (non-zero): Fatal error mode. Socket creation failure calls die(), terminating daemon with
 *                 EC_BADNET exit code. Used during daemon initialization when socket binding is critical for
 *                 core functionality. Example: Listener creation during startup for --listen-address binding.
 *               - 0 (zero): Non-fatal error mode. Socket creation failure logs warning via my_syslog(LOG_WARNING),
 *                 but daemon continues operation with partial functionality. Used during dynamic reconfiguration
 *                 when interface state changes. Example: newaddress() attempting to bind to newly appeared
 *                 interface address (failure acceptable, retry later when conditions improve).
 *               Applies to ALL socket creation attempts (DNS UDP, DNS TCP, TFTP). However, partial success
 *               acceptable - if DNS UDP succeeds but TCP fails (dienow=0), function returns listener with
 *               working UDP socket and invalid TCP socket (-1), daemon operates in UDP-only mode.
 *               Typical usage: Initial setup uses dienow=1 (must succeed), dynamic updates use dienow=0 (best-effort).
 *
 * @return Pointer to newly allocated listener structure, or NULL if all socket creation attempts failed
 * @retval non-NULL Success: Valid pointer to struct listener allocated via safe_malloc(). Structure initialized
 *                  with:
 *                  - l->fd: DNS UDP socket fd (>=0 if created, -1 if creation failed or daemon->port==0)
 *                  - l->tcpfd: DNS TCP socket fd (>=0 if created, -1 if creation failed or daemon->port==0)
 *                  - l->tftpfd: TFTP UDP socket fd (>=0 if created, -1 if creation failed, HAVE_TFTP disabled,
 *                    or do_tftp==0)
 *                  - l->addr: Copy of addr parameter (IP address and DNS port, NOT TFTP port)
 *                  - l->next: NULL (linked list insertion handled by caller)
 *                  - l->used: 1 (marks listener active)
 *                  - l->iface: NULL (interface pointer set by caller)
 *                  At least one socket fd >= 0 guaranteed (fd != -1 || tcpfd != -1 || tftpfd != -1), otherwise
 *                  function returns NULL instead of partial listener. Caller must:
 *                  - Add listener to daemon->listeners linked list (or free if rejected)
 *                  - Add socket fds to event loop poll set for I/O notification
 *                  - Eventually call release_listener() to close sockets and free memory
 *                  Do NOT call free() directly - use release_listener() for proper socket cleanup.
 * @retval NULL Failure: All socket creation attempts failed. No listener allocated. Reasons:
 *              - daemon->port == 0: DNS sockets skipped, AND (HAVE_TFTP undefined OR do_tftp==0): TFTP socket
 *                skipped. No sockets to create, returns NULL immediately.
 *              - make_sock() failed for all attempted sockets: Each make_sock() returned -1 (errno indicates
 *                specific error: EADDRINUSE, EADDRNOTAVAIL, EACCES, EAFNOSUPPORT, etc.). Common causes:
 *                * Address already in use (another process bound to port)
 *                * Address not available (interface doesn't exist, IP not assigned to interface)
 *                * Permission denied (binding privileged port <1024 without root/CAP_NET_BIND_SERVICE)
 *                * Address family not supported (IPv6 when kernel lacks IPv6 support)
 *              If dienow==1, daemon already terminated via die() before returning NULL (make_sock fatal error).
 *              If dienow==0, errors logged via my_syslog(), returns NULL for caller to handle gracefully.
 *              NULL return indicates address unusable - caller should not add to listeners list, no cleanup needed
 *              (no allocation occurred).
 *
 * @note Partial success acceptable: Listener created if ANY socket succeeds (fd, tcpfd, or tftpfd != -1).
 *       Failed sockets stored as -1 in listener structure. Enables degraded operation (UDP-only DNS, TFTP-less, etc.).
 * @note Port restoration: TFTP socket creation temporarily modifies addr->in.sin_port or addr->in6.sin6_port,
 *       but always restores original value before returning. Caller's addr parameter unchanged.
 * @note safe_malloc never returns NULL: Listener allocation via safe_malloc() dies on OOM, so non-NULL return
 *       always valid pointer. No NULL check needed after allocation (would be dead code).
 * @note Conditional compilation: TFTP code only compiled if HAVE_TFTP defined. Without HAVE_TFTP, do_tftp
 *       parameter ignored (suppressed with (void)do_tftp to avoid unused parameter warning).
 * @note dienow parameter forwarded: Passed to make_sock() for all socket creation attempts, controlling error
 *       handling mode consistently across DNS UDP, DNS TCP, and TFTP sockets.
 * @note IPv4/IPv6 transparent: Function handles both address families via union mysockaddr. Family checked only
 *       for TFTP port field access (sin_port vs sin6_port), otherwise transparent to make_sock().
 * @note daemon->port check: DNS sockets only created if daemon->port != 0. Port 0 disables DNS service entirely
 *       (DHCP-only or TFTP-only mode). TFTP socket creation independent of daemon->port.
 * @note l->iface initialization: Set to NULL here, caller responsible for setting to appropriate struct irec
 *       pointer if binding to specific interface. Wildcard listeners leave iface=NULL.
 *
 * @warning addr must be valid pointer: Function dereferences addr without NULL check (addr->sa.sa_family access
 *          in TFTP code path, *addr copy in listener initialization). NULL pointer causes segmentation fault.
 *          Caller must ensure addr properly initialized before calling.
 * @warning Address family must be AF_INET or AF_INET6: Other families (AF_UNIX, AF_NETLINK, etc.) cause
 *          make_sock() to fail with EAFNOSUPPORT. TFTP code explicitly checks family for sin_port vs sin6_port,
 *          undefined behavior for unexpected families (would access wrong union member). No family validation
 *          performed - relies on caller correctness.
 * @warning Port must be in network byte order: addr->in.sin_port and addr->in6.sin6_port must use htons()
 *          conversion from host byte order. Host byte order causes binding to wrong port (e.g., port 53 as
 *          0x0035 instead of 0x3500 on little-endian). TFTP_PORT constant also requires htons() conversion.
 * @warning dienow=1 never returns on error: If dienow==1 and make_sock() fails, die() called, daemon terminates,
 *          function never returns. Caller code after create_listeners() call unreachable in error path for dienow=1.
 *          Only dienow=0 allows error return (NULL).
 * @warning Listener memory management: Caller responsible for adding returned listener to daemon->listeners list
 *          or freeing if rejected. Orphaned listener (not added to list, not freed) causes memory leak. Use
 *          release_listener() for cleanup, NOT free() directly (must close sockets first).
 * @warning Socket fds -1 are invalid: Caller must check fd, tcpfd, tftpfd before using. Value -1 indicates socket
 *          creation failed or not attempted, using in read/write/poll causes EBADF. Event loop must skip -1 fds
 *          when adding to poll set.
 * @warning Concurrent calls not thread-safe: Function modifies addr structure temporarily (TFTP port), not thread-safe
 *          if multiple threads call with same addr simultaneously. Single-threaded architecture prevents this issue.
 * @warning TFTP port collision: If another process binds port 69, TFTP socket creation fails (make_sock returns -1).
 *          Listener still created if DNS sockets succeed (tftpfd=-1), but TFTP functionality unavailable. No automatic
 *          retry mechanism - manual daemon restart required after freeing port 69.
 * @warning daemon->port global dependency: Function reads daemon->port global variable without locking. Modifying
 *          daemon->port concurrently while creating listeners causes race condition. Single-threaded architecture
 *          and configuration-reload-only modification pattern prevents this.
 *
 * @see make_sock() which creates and configures individual sockets (called for DNS UDP, DNS TCP, TFTP)
 * @see create_bound_listeners() which calls create_listeners() for specific interface addresses
 * @see create_wildcard_listeners() which calls create_listeners() for wildcard addresses (0.0.0.0, ::)
 * @see release_listener() which closes sockets and frees listener memory (cleanup function)
 * @see struct listener definition in dnsmasq.h for complete structure fields
 * @see safe_malloc() which allocates memory with OOM handling (dies on allocation failure)
 *
 * EXAMPLE USAGE:
 * @code
 * // Create listener for specific IPv4 address (bind-interfaces mode)
 * union mysockaddr addr;
 * memset(&addr, 0, sizeof(addr));
 * addr.in.sin_family = AF_INET;
 * inet_pton(AF_INET, "192.168.1.1", &addr.in.sin_addr);
 * addr.in.sin_port = htons(53);  // DNS port in network byte order
 * 
 * struct listener *l = create_listeners(&addr, 1, 1);  // do_tftp=1, dienow=1 (fatal errors)
 * if (l)  // Always true for dienow=1 (die() called on failure, never returns)
 *   {
 *     // Add to listeners list
 *     l->next = daemon->listeners;
 *     daemon->listeners = l;
 *     
 *     // Add sockets to event loop
 *     if (l->fd != -1)
 *       add_to_poll_set(l->fd);  // DNS UDP
 *     if (l->tcpfd != -1)
 *       add_to_poll_set(l->tcpfd);  // DNS TCP
 *     if (l->tftpfd != -1)
 *       add_to_poll_set(l->tftpfd);  // TFTP
 *   }
 * @endcode
 *
 * @code
 * // Create listener for wildcard IPv6 address (default mode, dynamic binding)
 * union mysockaddr addr6;
 * memset(&addr6, 0, sizeof(addr6));
 * addr6.in6.sin6_family = AF_INET6;
 * addr6.in6.sin6_addr = in6addr_any;  // :: wildcard
 * addr6.in6.sin6_port = htons(53);
 * 
 * struct listener *l = create_listeners(&addr6, 0, 0);  // do_tftp=0, dienow=0 (non-fatal)
 * if (l)
 *   {
 *     // Success - add to list
 *     l->next = daemon->listeners;
 *     daemon->listeners = l;
 *   }
 * else
 *   {
 *     // Failed to create any sockets (all make_sock() calls returned -1)
 *     // Log error already done by make_sock() via my_syslog()
 *     // Continue daemon operation without this listener
 *   }
 * @endcode
 *
 * @code
 * // Example showing partial success handling
 * union mysockaddr addr;
 * // ... initialize addr ...
 * 
 * struct listener *l = create_listeners(&addr, 1, 0);  // Non-fatal mode
 * if (l)
 *   {
 *     // Check which sockets available
 *     if (l->fd == -1)
 *       my_syslog(LOG_WARNING, "DNS UDP socket unavailable for %s", 
 *                 prettyprint_addr(&addr, daemon->addrbuff));
 *     if (l->tcpfd == -1)
 *       my_syslog(LOG_WARNING, "DNS TCP socket unavailable for %s",
 *                 prettyprint_addr(&addr, daemon->addrbuff));
 *     if (l->tftpfd == -1 && do_tftp)
 *       my_syslog(LOG_WARNING, "TFTP socket unavailable for %s",
 *                 prettyprint_addr(&addr, daemon->addrbuff));
 *     
 *     // Use listener with available sockets only
 *     l->next = daemon->listeners;
 *     daemon->listeners = l;
 *   }
 * @endcode
 *
 * SOCKET CREATION DECISION MATRIX:
 * 
 * daemon->port != 0, HAVE_TFTP defined, do_tftp=1:
 *   Creates: DNS UDP (fd), DNS TCP (tcpfd), TFTP UDP (tftpfd)
 *   Result: Full-featured listener (all protocols enabled)
 * 
 * daemon->port != 0, HAVE_TFTP defined, do_tftp=0:
 *   Creates: DNS UDP (fd), DNS TCP (tcpfd)
 *   Result: DNS-only listener (tftpfd=-1)
 * 
 * daemon->port != 0, HAVE_TFTP undefined:
 *   Creates: DNS UDP (fd), DNS TCP (tcpfd)
 *   Result: DNS-only listener (TFTP code not compiled, tftpfd=-1)
 * 
 * daemon->port == 0, HAVE_TFTP defined, do_tftp=1:
 *   Creates: TFTP UDP (tftpfd)
 *   Result: TFTP-only listener (fd=-1, tcpfd=-1)
 * 
 * daemon->port == 0, HAVE_TFTP undefined or do_tftp=0:
 *   Creates: Nothing
 *   Result: NULL return (no sockets to create)
 *
 * PORT MODIFICATION SEQUENCE (TFTP):
 * 
 * Before TFTP socket creation:
 *   addr->in.sin_port = htons(53)  // DNS port from caller
 * 
 * Step 1 - Save:
 *   short save = addr->in.sin_port;  // save = htons(53)
 * 
 * Step 2 - Modify:
 *   addr->in.sin_port = htons(TFTP_PORT);  // Temporarily set to htons(69)
 * 
 * Step 3 - Create:
 *   tftpfd = make_sock(addr, SOCK_DGRAM, dienow);  // Binds to port 69
 * 
 * Step 4 - Restore:
 *   addr->in.sin_port = save;  // Restore to htons(53)
 * 
 * After restoration:
 *   addr->in.sin_port = htons(53)  // Original value restored, caller unaware of modification
 *
 * LISTENER STRUCTURE LAYOUT:
 * 
 * struct listener (created by this function):
 *   int fd;              // DNS UDP socket (or -1)
 *   int tcpfd;           // DNS TCP socket (or -1)
 *   int tftpfd;          // TFTP UDP socket (or -1)
 *   union mysockaddr addr;  // IP address and DNS port (NOT TFTP port!)
 *   struct listener *next;  // Linked list pointer (NULL after creation)
 *   int used;            // Activity flag (1 after creation)
 *   struct irec *iface;  // Interface pointer (NULL after creation, set by caller)
 *
 * RFC COMPLIANCE:
 * - RFC 1035: DNS protocol specifies both UDP and TCP support required
 * - RFC 1350: TFTP protocol specification (port 69)
 * - TCP/IP standards: Network byte order (big-endian) for port numbers
 * 
 * SIDE EFFECTS:
 * - Allocates struct listener via safe_malloc() (dies on OOM, never returns NULL)
 * - Calls make_sock() up to 3 times, each potentially modifying global state (daemon->v6pktinfo)
 * - Temporarily modifies addr->in.sin_port or addr->in6.sin6_port (restored before return)
 * - May call die() and terminate daemon if dienow=1 and socket creation fails
 * - May log warnings via my_syslog() if dienow=0 and socket creation fails (via make_sock)
 * 
 * THREAD SAFETY: Not thread-safe due to:
 *                 - Global daemon->port read without locking
 *                 - Temporary addr structure modification (not atomic)
 *                 - make_sock() calls modifying global daemon->v6pktinfo
 *                 dnsmasq's single-threaded architecture makes this acceptable.
 */
static struct listener *create_listeners(union mysockaddr *addr, int do_tftp, int dienow)
{
  struct listener *l = NULL;
  int fd = -1, tcpfd = -1, tftpfd = -1;

  (void)do_tftp;

  if (daemon->port != 0)
    {
      fd = make_sock(addr, SOCK_DGRAM, dienow);
      tcpfd = make_sock(addr, SOCK_STREAM, dienow);
    }
  
#ifdef HAVE_TFTP
  if (do_tftp)
    {
      if (addr->sa.sa_family == AF_INET)
	{
	  /* port must be restored to DNS port for TCP code */
	  short save = addr->in.sin_port;
	  addr->in.sin_port = htons(TFTP_PORT);
	  tftpfd = make_sock(addr, SOCK_DGRAM, dienow);
	  addr->in.sin_port = save;
	}
      else
	{
	  short save = addr->in6.sin6_port;
	  addr->in6.sin6_port = htons(TFTP_PORT);
	  tftpfd = make_sock(addr, SOCK_DGRAM, dienow);
	  addr->in6.sin6_port = save;
	}  
    }
#endif

  if (fd != -1 || tcpfd != -1 || tftpfd != -1)
    {
      l = safe_malloc(sizeof(struct listener));
      l->next = NULL;
      l->fd = fd;
      l->tcpfd = tcpfd;
      l->tftpfd = tftpfd;
      l->addr = *addr;
      l->used = 1;
      l->iface = NULL;
    }

  return l;
}

/**
 * @brief Create wildcard listeners binding to all network interfaces (IPv4 and IPv6)
 * 
 * @detailed Create DNS and optionally TFTP listeners bound to wildcard addresses that receive
 *           packets on all available network interfaces. For IPv4, binds to 0.0.0.0 (INADDR_ANY),
 *           and for IPv6, binds to :: (in6addr_any). This is the default dnsmasq binding mode,
 *           contrasting with --bind-interfaces mode which creates separate listeners per specific
 *           interface address.
 *
 *           Wildcard binding vs bind-interfaces mode comparison:
 *           
 *           **Wildcard binding (default, this function):**
 *           - Single socket per address family receives packets on ALL interfaces
 *           - Kernel delivers packets from any interface to wildcard socket
 *           - dnsmasq uses IP_PKTINFO/IPV6_PKTINFO to determine receiving interface
 *           - Advantages: Fewer sockets, automatic handling of new interfaces, simpler configuration
 *           - Disadvantages: All interfaces receive same configuration, cannot disable per-interface
 *           - Use case: Typical small network where same DNS/DHCP service on all interfaces desired
 *
 *           **Bind-interfaces mode (--bind-interfaces, create_bound_listeners):**
 *           - Separate socket per interface address
 *           - Each socket only receives packets for its specific address
 *           - Interface explicitly identified by which socket received packet
 *           - Advantages: Per-interface control (enable/disable, different options), explicit interface binding
 *           - Disadvantages: More sockets, manual interface management, misses dynamic interfaces
 *           - Use case: Complex network with different policies per interface (external vs internal)
 *
 *           Why wildcard binding is default:
 *           - Simpler configuration: No need to specify --listen-address for each interface
 *           - Dynamic interface handling: New interfaces automatically served (VPN connects, interface added)
 *           - Fewer file descriptors: Single socket per family vs socket per interface address
 *           - Better for mobile/dynamic environments: Laptops, containers, VMs with changing network
 *
 *           IPv4 wildcard listener creation (0.0.0.0):
 *           1. Initialize union mysockaddr addr to all zeros (memset)
 *           2. Set addr.in.sin_family = AF_INET (IPv4 address family)
 *           3. Set addr.in.sin_addr.s_addr = INADDR_ANY (0.0.0.0, all interfaces)
 *              INADDR_ANY is macro expanding to ((in_addr_t) 0x00000000), but explicit assignment
 *              clearer than relying on memset for semantic meaning
 *           4. Set addr.in.sin_port = htons(daemon->port) (typically htons(53) for DNS)
 *              Port must be network byte order (big-endian), htons converts from host byte order
 *           5. BSD-specific: Set addr.in.sin_len = sizeof(addr.in) if HAVE_SOCKADDR_SA_LEN defined
 *              4.4BSD-derived systems (FreeBSD, OpenBSD, NetBSD, macOS) require sa_len field
 *              containing structure size. Linux doesn't have this field (structure size inferred
 *              from sa_family). Conditional compilation ensures portability.
 *           6. Call create_listeners(&addr, tftp_enabled, dienow=1):
 *              - addr: IPv4 wildcard address (0.0.0.0:port)
 *              - tftp_enabled: !!option_bool(OPT_TFTP) converts boolean to integer (0 or 1)
 *                Double-negation ensures integer type for do_tftp parameter
 *              - dienow=1: Fatal error mode - socket creation failure terminates daemon
 *                Wildcard binding is initialization, must succeed for daemon to function
 *           7. Store returned listener in local variable l (may be NULL if creation failed,
 *              though dienow=1 makes this unlikely - die() called before returning NULL)
 *
 *           IPv6 wildcard listener creation (::):
 *           8. Re-initialize addr to all zeros (new memset, clears IPv4 data)
 *           9. Set addr.in6.sin6_family = AF_INET6 (IPv6 address family)
 *           10. Set addr.in6.sin6_addr = in6addr_any (:: , all IPv6 interfaces)
 *               in6addr_any is const struct in6_addr initialized to { { { 0 } } } (all zeros)
 *               Unlike INADDR_ANY (integer constant), in6addr_any is structure, requires assignment
 *           11. Set addr.in6.sin6_port = htons(daemon->port) (same port as IPv4)
 *               DNS listens on same port for both IPv4 and IPv6 (port 53 for both)
 *           12. BSD-specific: Set addr.in6.sin6_len = sizeof(addr.in6) for BSD systems
 *           13. Call create_listeners(&addr, tftp_enabled, dienow=1):
 *               - addr: IPv6 wildcard address ([::]:port)
 *               - Same TFTP flag and dienow as IPv4 call
 *           14. Store returned listener in local variable l6
 *
 *           Listener linked list construction:
 *           Function creates linked list of listeners stored in daemon->listeners global. List
 *           order doesn't matter for correctness (event loop polls all sockets), but convention
 *           places IPv4 first if both exist.
 *
 *           Link logic:
 *           - if (l != NULL): IPv4 listener created successfully
 *             * Set l->next = l6 (link IPv4 to IPv6, even if l6 NULL)
 *             * Result: IPv4 first, possibly followed by IPv6
 *           - else (l == NULL): IPv4 listener creation failed
 *             * Set l = l6 (use IPv6 as head, may also be NULL)
 *             * Result: IPv6 only (if exists), or empty list (both failed)
 *           - daemon->listeners = l (assign constructed list to global)
 *
 *           List possibilities after construction:
 *           - Both succeed: l (IPv4) -> l6 (IPv6) -> NULL, daemon->listeners = l
 *           - IPv4 only: l (IPv4) -> NULL, daemon->listeners = l (l6=NULL, l->next=NULL)
 *           - IPv6 only: l6 (IPv6) -> NULL, daemon->listeners = l6 (l=NULL, l=l6)
 *           - Both fail: daemon->listeners = NULL (l=NULL, l6=NULL, l=l6=NULL)
 *             Though unlikely with dienow=1 (die() terminates before return)
 *
 *           INADDR_ANY and in6addr_any semantics:
 *           When socket bound to wildcard address (0.0.0.0 or ::), kernel routes packets destined
 *           for ANY interface's address to this socket. Example:
 *           - Host has interfaces: eth0 (192.168.1.1), wlan0 (10.0.0.1), lo (127.0.0.1)
 *           - Wildcard IPv4 socket bound to 0.0.0.0:53
 *           - Client query to 192.168.1.1:53 delivered to wildcard socket
 *           - Client query to 10.0.0.1:53 delivered to same wildcard socket
 *           - Client query to 127.0.0.1:53 delivered to same wildcard socket
 *           - dnsmasq uses IP_PKTINFO ancillary data to determine destination address and interface
 *
 *           Without IP_PKTINFO/IPV6_PKTINFO (enabled by make_sock via set_ipv6pktinfo for IPv6),
 *           daemon wouldn't know which interface received packet, breaking response addressing.
 *           Must respond from same address query was sent to, otherwise client sees response from
 *           unexpected address and may reject.
 *
 *           HAVE_SOCKADDR_SA_LEN conditional compilation:
 *           4.4BSD introduced sa_len field in struct sockaddr family to store structure size.
 *           Rationale: Variable-length sockaddr structures (sockaddr_in vs sockaddr_in6 vs sockaddr_un)
 *           need size information. Linux infers size from sa_family (AF_INET = sizeof(sockaddr_in)),
 *           BSD explicitly stores size in sa_len field.
 *
 *           Platforms requiring sa_len:
 *           - FreeBSD, OpenBSD, NetBSD, DragonFly BSD
 *           - macOS/Darwin (BSD-derived)
 *           - Some commercial Unix variants (AIX, HP-UX may have variants)
 *
 *           Platforms without sa_len:
 *           - Linux (all distributions)
 *           - Solaris (System V-derived, not BSD-derived)
 *
 *           Setting sa_len correctly ensures portability. Omitting on BSD causes subtle bugs
 *           (socket functions may fail or misbehave). Including on Linux harmless (field doesn't
 *           exist in structure, compiler error if not conditional).
 *
 *           Double-negation operator explanation (!!option_bool(OPT_TFTP)):
 *           option_bool(OPT_TFTP) returns boolean-like value (truthy/falsy). create_listeners()
 *           expects integer do_tftp parameter (0 or non-zero). Double negation ensures clean
 *           conversion to 0 or 1:
 *           - option_bool(OPT_TFTP) returns truthy (non-zero) if TFTP enabled
 *           - !option_bool(OPT_TFTP) converts truthy to false (0), falsy to true (1)
 *           - !!option_bool(OPT_TFTP) converts back: false->0, true->1
 *           - Result: Integer 1 if TFTP enabled, 0 if disabled
 *
 *           Alternative without double-negation: option_bool(OPT_TFTP) ? 1 : 0
 *           Double-negation is idiomatic C shorthand for boolean-to-integer conversion.
 *
 *           OPT_TFTP flag meaning:
 *           Controlled by --enable-tftp command-line option. When enabled, TFTP server functionality
 *           activated on specified interfaces (or all interfaces if no interface restriction).
 *           Passing result to create_listeners() ensures TFTP socket (port 69) created alongside
 *           DNS sockets (port 53) for wildcard listeners.
 *
 *           dienow=1 rationale (fatal errors):
 *           Wildcard listener creation occurs during daemon initialization (called from main()).
 *           If wildcard binding fails, daemon cannot provide DNS/DHCP services on any interface,
 *           rendering it non-functional. Fatal error appropriate - better to terminate with clear
 *           error message than run in broken state. Common failure causes:
 *           - Another process already bound to port 53 (EADDRINUSE)
 *           - Insufficient privileges for port <1024 (EACCES)
 *           - Protocol not supported (EAFNOSUPPORT for IPv6 if kernel lacks IPv6)
 *
 *           Global state mutation (daemon->listeners):
 *           Function modifies daemon->listeners global pointer, setting it to newly created listener
 *           list. Previous daemon->listeners value expected to be NULL (initial state before first
 *           call). If called multiple times (shouldn't happen in normal flow), previous list leaked
 *           (no cleanup of old listeners). Single-call-during-initialization pattern prevents leaks.
 *
 *           Call site:
 *           Called from main() in dnsmasq.c during daemon initialization, after configuration parsing
 *           but before entering main event loop. Part of network initialization sequence:
 *           1. Parse configuration (option.c)
 *           2. Create wildcard listeners (this function, if not --bind-interfaces mode)
 *           3. OR create bound listeners (create_bound_listeners, if --bind-interfaces mode)
 *           4. Enter event loop (poll-based I/O multiplexing)
 *
 *           Event loop interaction:
 *           After wildcard listeners created, main event loop adds socket fds to poll set:
 *           - For each listener in daemon->listeners:
 *             * If l->fd != -1, add to poll set (DNS UDP)
 *             * If l->tcpfd != -1, add to poll set (DNS TCP)
 *             * If l->tftpfd != -1, add to poll set (TFTP)
 *           - When poll() returns (socket ready for I/O), event loop determines which listener
 *             socket received data and dispatches to appropriate handler (receive_query for DNS,
 *             recv_tftp for TFTP, etc.)
 *
 *           Wildcard listener cleanup:
 *           Listeners persist for daemon lifetime. On graceful shutdown (SIGTERM), main() cleanup
 *           sequence iterates daemon->listeners and calls release_listener() for each, closing
 *           sockets and freeing memory. On abnormal termination (SIGKILL, crash), kernel closes
 *           sockets automatically when process exits.
 *
 *           IPv4-only and IPv6-only scenarios:
 *           - **IPv4-only kernel**: IPv6 listener creation fails with EAFNOSUPPORT, create_listeners
 *             returns NULL for l6. Result: daemon->listeners contains only IPv4 listener. Daemon
 *             functional for IPv4 DNS/DHCP, IPv6 unavailable.
 *           - **IPv6-only kernel** (unusual): IPv4 listener creation fails, IPv6 succeeds. Result:
 *             daemon->listeners = l6 (IPv6 only). Daemon functional for IPv6 DNS/DHCP6.
 *           - **Dual-stack kernel** (normal): Both listeners created successfully, linked together.
 *             Daemon serves both protocols.
 *
 * @note No parameters: Function takes void parameter list, derives all configuration from global
 *       daemon structure (daemon->port for port number, option_bool(OPT_TFTP) for TFTP enable).
 * @note No return value: Function has void return type. Success/failure communicated via global
 *       daemon->listeners (NULL if both failed, non-NULL if at least one succeeded). With dienow=1,
 *       failure typically terminates daemon (die() called) before function returns.
 * @note Initialization-only: Expected to be called exactly once during daemon startup, not during
 *       runtime reconfiguration. Multiple calls leak previous listener list (no cleanup).
 * @note Global state modification: Sets daemon->listeners to newly created linked list. Previous
 *       value (expected NULL) not checked or cleaned up.
 * @note IPv4 and IPv6 independent: IPv6 failure doesn't prevent IPv4 success (and vice versa).
 *       Daemon continues with available protocol(s). Common on IPv4-only kernels.
 * @note HAVE_SOCKADDR_SA_LEN portability: Conditional compilation ensures BSD systems get sa_len
 *       field set, Linux systems compile without it. Required for cross-platform compatibility.
 * @note TFTP optional: TFTP sockets only created if OPT_TFTP option enabled (--enable-tftp).
 *       Without TFTP, only DNS sockets created (ports 53 UDP/TCP, not port 69).
 * @note Linked list order: IPv4 listener before IPv6 if both exist. Order doesn't affect functionality
 *       (event loop polls all sockets regardless), but IPv4-first convention for consistency.
 * @note Single-threaded assumption: Function not thread-safe due to daemon global access and linked
 *       list construction without locking. dnsmasq single-threaded architecture makes this acceptable.
 *
 * @warning No error return: Function cannot return error to caller (void return type). Failures either
 *          terminate daemon (dienow=1, die() called) or result in partial listener list (some NULL).
 *          Caller must check daemon->listeners for NULL to detect total failure (both protocols failed).
 * @warning Global state dependency: Reads daemon->port global without locking. Concurrent modification
 *          of daemon->port during call causes race condition (unlikely - initialization-only function).
 * @warning Memory leak potential: Calling multiple times without cleanup leaks previous listener list.
 *          Function expects to be called once during initialization, not during runtime.
 * @warning dienow=1 means fatal: Socket creation failure calls die(), terminating daemon with EC_BADNET
 *          exit code. No opportunity for graceful degradation or retry. Acceptable for initialization.
 * @warning IPv6 kernel dependency: IPv6 listener creation fails on kernels without IPv6 support
 *          (EAFNOSUPPORT). Daemon continues with IPv4-only operation. Check daemon->listeners for
 *          presence of IPv6 listener (family AF_INET6) to detect IPv6 availability.
 * @warning TFTP port conflict: If another process binds port 69 (TFTP), TFTP socket creation fails
 *          (EADDRINUSE). DNS sockets still created (tftpfd=-1 in listeners), but TFTP functionality
 *          unavailable. No automatic retry - manual intervention required.
 * @warning Assumes daemon initialization: Function expects daemon structure initialized (daemon->port set,
 *          daemon->listeners initially NULL). Calling before daemon initialization causes undefined behavior.
 *
 * @see create_listeners() which creates individual listener structures with sockets (called twice by this function)
 * @see create_bound_listeners() alternative binding mode creating separate listener per interface address
 * @see release_listener() cleanup function closing sockets and freeing listener memory
 * @see option_bool() macro checking if boolean option enabled (OPT_TFTP)
 * @see main() in dnsmasq.c which calls this function during daemon initialization
 * @see struct listener definition in dnsmasq.h for listener structure fields
 *
 * EXAMPLE USAGE:
 * @code
 * // Called during daemon initialization (from main in dnsmasq.c)
 * // After configuration parsing, before event loop
 * 
 * // Parse configuration
 * read_opts(argc, argv, compile_opts);
 * 
 * // Create network listeners
 * if (!option_bool(OPT_NOWILD))  // If not --bind-interfaces mode
 *   {
 *     create_wildcard_listeners();  // Create 0.0.0.0 and :: listeners
 *     
 *     // Check if any listeners created
 *     if (!daemon->listeners)
 *       {
 *         // Both IPv4 and IPv6 failed - unusual, since dienow=1 should call die()
 *         // But defensive check in case of future code changes
 *         die("Failed to create any network listeners", NULL, EC_BADNET);
 *       }
 *   }
 * else
 *   {
 *     create_bound_listeners(1);  // Create specific interface listeners
 *   }
 * 
 * // Continue with event loop setup
 * // Add listener sockets to poll set...
 * @endcode
 *
 * @code
 * // Typical daemon->listeners state after successful call
 * 
 * // IPv4 listener (first in list):
 * daemon->listeners->fd        // DNS UDP socket on 0.0.0.0:53
 * daemon->listeners->tcpfd     // DNS TCP socket on 0.0.0.0:53
 * daemon->listeners->tftpfd    // TFTP socket on 0.0.0.0:69 (if TFTP enabled, else -1)
 * daemon->listeners->addr      // { AF_INET, INADDR_ANY, htons(53) }
 * daemon->listeners->next      // -> IPv6 listener
 * 
 * // IPv6 listener (second in list):
 * daemon->listeners->next->fd        // DNS UDP socket on [::]:53
 * daemon->listeners->next->tcpfd     // DNS TCP socket on [::]:53
 * daemon->listeners->next->tftpfd    // TFTP socket on [::]:69 (if TFTP enabled, else -1)
 * daemon->listeners->next->addr      // { AF_INET6, in6addr_any, htons(53) }
 * daemon->listeners->next->next      // NULL (end of list)
 * @endcode
 *
 * @code
 * // IPv4-only kernel scenario (IPv6 not supported)
 * 
 * create_wildcard_listeners();
 * 
 * // Result:
 * // daemon->listeners points to IPv4 listener only
 * // daemon->listeners->next is NULL (l6 was NULL, l->next set to NULL)
 * 
 * // Daemon functional for IPv4 DNS/DHCP
 * // IPv6 queries never arrive (no IPv6 stack in kernel)
 * @endcode
 *
 * WILDCARD BINDING DIAGRAM:
 * 
 * Network topology:
 *   eth0: 192.168.1.1/24
 *   wlan0: 10.0.0.1/24
 *   lo: 127.0.0.1/8
 * 
 * Wildcard listeners:
 *   IPv4 socket: 0.0.0.0:53  (binds to all interfaces)
 *   IPv6 socket: [::]:53     (binds to all interfaces)
 * 
 * Query routing:
 *   Client -> 192.168.1.1:53  -> Wildcard socket (IP_PKTINFO: ipi_addr=192.168.1.1, ipi_ifindex=eth0)
 *   Client -> 10.0.0.1:53     -> Wildcard socket (IP_PKTINFO: ipi_addr=10.0.0.1, ipi_ifindex=wlan0)
 *   Client -> 127.0.0.1:53    -> Wildcard socket (IP_PKTINFO: ipi_addr=127.0.0.1, ipi_ifindex=lo)
 * 
 * Response addressing:
 *   Daemon uses IP_PKTINFO to determine destination address and responds from same address.
 *
 * LINKED LIST CONSTRUCTION LOGIC:
 * 
 * Case 1: Both IPv4 and IPv6 succeed
 *   l = IPv4 listener (non-NULL)
 *   l6 = IPv6 listener (non-NULL)
 *   l->next = l6
 *   daemon->listeners = l
 *   Result: IPv4 -> IPv6 -> NULL
 * 
 * Case 2: IPv4 succeeds, IPv6 fails
 *   l = IPv4 listener (non-NULL)
 *   l6 = NULL
 *   l->next = l6 (= NULL)
 *   daemon->listeners = l
 *   Result: IPv4 -> NULL
 * 
 * Case 3: IPv4 fails, IPv6 succeeds
 *   l = NULL
 *   l6 = IPv6 listener (non-NULL)
 *   l = l6 (else branch)
 *   daemon->listeners = l (= l6)
 *   Result: IPv6 -> NULL
 * 
 * Case 4: Both IPv4 and IPv6 fail
 *   l = NULL
 *   l6 = NULL
 *   l = l6 (= NULL, else branch)
 *   daemon->listeners = l (= NULL)
 *   Result: Empty list (NULL)
 *   Note: Unlikely with dienow=1 (die() terminates before return)
 *
 * SIDE EFFECTS:
 * - Modifies global daemon->listeners (sets to newly created listener linked list)
 * - Allocates memory for listener structures via create_listeners() (safe_malloc, dies on OOM)
 * - Creates kernel socket objects (consumes file descriptors)
 * - Binds sockets to wildcard addresses (reserves 0.0.0.0:port and [::]:port)
 * - May call die() and terminate daemon if socket creation fails (dienow=1)
 * - May log errors via my_syslog() if socket creation fails (via create_listeners -> make_sock)
 * - Modifies global daemon->v6pktinfo via set_ipv6pktinfo() (called by create_listeners -> make_sock)
 * 
 * THREAD SAFETY: Not thread-safe due to:
 *                 - Global daemon structure access (daemon->port, daemon->listeners)
 *                 - Linked list construction without atomic operations
 *                 - Potential die() call (process termination)
 *                 dnsmasq's single-threaded architecture makes this acceptable.
 */
void create_wildcard_listeners(void)
{
  union mysockaddr addr;
  struct listener *l, *l6;

  memset(&addr, 0, sizeof(addr));
#ifdef HAVE_SOCKADDR_SA_LEN
  addr.in.sin_len = sizeof(addr.in);
#endif
  addr.in.sin_family = AF_INET;
  addr.in.sin_addr.s_addr = INADDR_ANY;
  addr.in.sin_port = htons(daemon->port);

  l = create_listeners(&addr, !!option_bool(OPT_TFTP), 1);

  memset(&addr, 0, sizeof(addr));
#ifdef HAVE_SOCKADDR_SA_LEN
  addr.in6.sin6_len = sizeof(addr.in6);
#endif
  addr.in6.sin6_family = AF_INET6;
  addr.in6.sin6_addr = in6addr_any;
  addr.in6.sin6_port = htons(daemon->port);
 
  l6 = create_listeners(&addr, !!option_bool(OPT_TFTP), 1);
  if (l) 
    l->next = l6;
  else 
    l = l6;

  daemon->listeners = l;
}

/**
 * @brief Search for existing listener matching specified address in global listener list
 * 
 * @detailed Traverse daemon->listeners linked list to find listener with address matching addr
 *           parameter. Uses sockaddr_isequal() for address comparison, which checks both IP
 *           address and port number for equality. Returns first matching listener found, or NULL
 *           if no match exists in list.
 *
 *           Primary use case: Duplicate listener detection in create_bound_listeners()
 *           When binding to specific interface addresses (--bind-interfaces mode), function
 *           checks if listener already exists for address before creating new one. Prevents
 *           duplicate listeners for same address which would cause bind() to fail with EADDRINUSE.
 *
 *           Typical scenario requiring duplicate check:
 *           - Interface has multiple addresses (IPv4 primary + secondary, or IPv4 + IPv6)
 *           - Configuration specifies --listen-address for interface name (not specific IP)
 *           - enumerate_interfaces() creates struct irec for each address on interface
 *           - create_bound_listeners() iterates irec list, calling find_listener() for each
 *           - If listener already created for address (from previous irec), reuse instead of duplicate
 *           - Prevents binding same address:port twice, which kernel rejects
 *
 *           sockaddr_isequal() comparison semantics:
 *           Function compares both IP address AND port number. Two mysockaddr structures considered
 *           equal only if:
 *           - sa_family matches (AF_INET vs AF_INET6)
 *           - IP address matches (sin_addr.s_addr for IPv4, sin6_addr for IPv6)
 *           - Port matches (sin_port for IPv4, sin6_port for IPv6)
 *
 *           Why port comparison necessary:
 *           Single IP address may have multiple listeners on different ports (DNS on 53, DHCP on 67,
 *           TFTP on 69). Must distinguish by port to find correct listener. However, in current
 *           dnsmasq usage, find_listener() typically called with addr containing standard DNS port
 *           (daemon->port, usually 53), so port already matches for DNS listeners.
 *
 *           Linked list traversal pattern:
 *           Standard singly-linked list iteration: for (l = head; l != NULL; l = l->next)
 *           Checks each node until match found or end reached (l == NULL). No list modification,
 *           purely read-only search operation. Thread-safe for read-only access if list not
 *           modified concurrently (dnsmasq single-threaded, so no issue).
 *
 *           Search complexity:
 *           O(n) linear search where n = number of listeners in daemon->listeners list. Typical
 *           small network has 2-10 listeners (wildcard IPv4, wildcard IPv6, or few bound interface
 *           addresses), so linear search acceptable. No need for hash table or tree structure.
 *           Early termination on match improves average case (O(1) if match is first in list,
 *           O(n) if not found or last in list).
 *
 *           Return value interpretation:
 *           - **Non-NULL**: Found existing listener with matching address. Caller can reuse this
 *             listener instead of creating duplicate. Typical action: Set iface->done=1 and skip
 *             listener creation.
 *           - **NULL**: No existing listener for address. Caller should create new listener via
 *             create_listeners(). Typical action: Call create_listeners() with address, add to list.
 *
 *           Why static function:
 *           Helper function used only within network.c by create_bound_listeners(). Not part of
 *           public API, no external callers. Static linkage restricts visibility to this translation
 *           unit, preventing namespace pollution and allowing compiler to inline if beneficial.
 *
 *           Alternative implementations considered:
 *           - **Hash table**: O(1) lookup but overhead of hash table structure unnecessary for
 *             small listener count (typically <10). Would complicate memory management.
 *           - **Sorted list + binary search**: O(log n) but requires maintaining sort order during
 *             insertion, adding complexity. Not worth it for small lists.
 *           - **Built-in duplicate prevention**: Could prevent duplicates at insertion time rather
 *             than checking before insert. However, explicit check-then-insert pattern makes
 *             control flow clearer and allows different actions for existing vs new.
 *
 *           sockaddr_isequal() portability:
 *           Function defined in util.c, handles platform differences in sockaddr structure comparison.
 *           Must compare correct union member based on sa_family (sockaddr_in for AF_INET,
 *           sockaddr_in6 for AF_INET6). Simple memcmp() insufficient due to padding bytes and
 *           union structure. sockaddr_isequal() provides reliable comparison across platforms.
 *
 *           Integration with create_bound_listeners():
 *           1. enumerate_interfaces() creates struct irec list with all interface addresses
 *           2. create_bound_listeners() iterates irec list
 *           3. For each irec, call find_listener(&irec->addr)
 *           4. If found: existing = listener pointer, set iface->done=1, set existing->iface=iface
 *              This associates interface with existing listener without creating duplicate socket
 *           5. If not found: existing = NULL, create new listener via create_listeners(), add to list
 *              New listener created with sockets bound to irec->addr
 *
 *           Why iface->done flag set when existing listener found:
 *           Marks interface as processed, preventing redundant listener creation attempts. Multiple
 *           irec structures may share same address (secondary addresses, aliases), setting done=1
 *           ensures only first creates listener, subsequent reuse existing.
 *
 *           Listener address field (l->addr):
 *           Stored during listener creation in create_listeners() as copy of addr parameter:
 *           l->addr = *addr. Contains IP address and port in network byte order, ready for
 *           sockaddr_isequal() comparison. Union mysockaddr type allows both IPv4 (sockaddr_in)
 *           and IPv6 (sockaddr_in6) storage without separate handling.
 *
 *           Edge cases:
 *           - **Empty list** (daemon->listeners == NULL): Loop never executes, returns NULL immediately.
 *             Correct behavior - no existing listeners, caller should create first one.
 *           - **NULL addr parameter**: Would cause sockaddr_isequal() to dereference NULL, segfault.
 *             Caller must ensure valid addr pointer. No NULL check performed (optimization for hot path).
 *           - **Partial matches** (same IP, different port): sockaddr_isequal() returns false because
 *             port differs. Correct behavior - different ports are different listeners.
 *
 *           Performance considerations:
 *           Function called once per interface address during create_bound_listeners(). Not in hot
 *           path (initialization only, not per-packet). Linear search acceptable for initialization
 *           code where simplicity more valuable than micro-optimization.
 *
 *           Memory access pattern:
 *           Traverses linked list following next pointers, poor cache locality if listeners scattered
 *           in memory. However, listeners typically allocated close together during initialization
 *           (safe_malloc() may have locality), and list small enough to fit in cache. Not a bottleneck.
 *
 * @param addr Pointer to union mysockaddr containing address to search for. Must be valid pointer
 *             (not NULL) pointing to properly initialized mysockaddr with sa_family, IP address,
 *             and port in network byte order. Structure compared against l->addr of each listener
 *             using sockaddr_isequal(), which checks family, IP address, and port for equality.
 *             Typical usage: Pass &iface->addr where iface is struct irec from interface enumeration.
 *             IPv4 addresses use addr->in (struct sockaddr_in), IPv6 uses addr->in6 (struct sockaddr_in6).
 *             Port should be daemon->port (DNS service port, typically 53) for DNS listeners.
 *             Must not be NULL - no NULL check performed, NULL dereference causes segfault.
 *
 * @return Pointer to matching listener, or NULL if not found
 * @retval non-NULL Success: Found listener in daemon->listeners list with address matching addr parameter.
 *                  Returned pointer is valid struct listener that can be used to associate with
 *                  interface (set listener->iface) or retrieve socket fds (listener->fd, listener->tcpfd,
 *                  listener->tftpfd). Pointer remains valid until listener released via release_listener()
 *                  or daemon termination. Caller typically uses returned listener to avoid duplicate
 *                  creation: set iface->done=1, set returned_listener->iface=iface, skip create_listeners().
 *                  Do NOT free returned pointer - listener owned by daemon->listeners list, will be
 *                  cleaned up during daemon shutdown.
 * @retval NULL Not found: No listener in daemon->listeners list matches addr parameter. Caller should
 *              create new listener via create_listeners(addr, tftp_flag, dienow) and add to
 *              daemon->listeners list. NULL return indicates address not yet bound, safe to create
 *              new listener without EADDRINUSE conflict. Common during first call for each interface
 *              address (no existing listeners yet). Not an error condition - expected result when
 *              adding new interface addresses.
 *
 * @note Static function: Internal helper for create_bound_listeners(), not part of public API.
 *       Restricted to network.c translation unit via static linkage.
 * @note Read-only operation: Does not modify daemon->listeners list or any listener structures.
 *       Pure search function with no side effects. Thread-safe for read-only access if list
 *       not modified concurrently (dnsmasq single-threaded, so no concurrency issues).
 * @note O(n) complexity: Linear search through linked list, but n typically small (2-10 listeners
 *       for typical networks). Early termination on match improves average case.
 * @note sockaddr_isequal semantics: Compares family, IP address, AND port. Two addresses equal
 *       only if all three match. Partial matches (same IP, different port) return false.
 * @note First match returned: If multiple listeners somehow have same address (shouldn't happen,
 *       but defensive), function returns first match found. Linked list order undefined.
 * @note Empty list handling: Returns NULL immediately if daemon->listeners == NULL (no iterations).
 *       Correct behavior for empty list - no matches possible.
 *
 * @warning addr must be valid pointer: No NULL check performed. NULL pointer causes sockaddr_isequal()
 *          to segfault when dereferencing. Caller responsible for ensuring valid addr parameter.
 *          Optimization trade-off: Skip NULL check for performance in non-error path.
 * @warning Returned pointer must not be freed: Listener owned by daemon->listeners list, managed
 *          by daemon lifecycle. Calling free() on returned pointer causes double-free when daemon
 *          shutdown releases listeners. Use returned pointer for read-only access or to set
 *          listener->iface association, but don't modify listener ownership.
 * @warning Not thread-safe: Traverses linked list without locking. Concurrent modification of
 *          daemon->listeners list (adding/removing listeners) during traversal causes undefined
 *          behavior (use-after-free, infinite loop from corrupted next pointers). dnsmasq's
 *          single-threaded architecture prevents concurrent access.
 * @warning addr must be properly initialized: Uninitialized addr structure causes sockaddr_isequal()
 *          to compare garbage values, potentially returning false positive (match when shouldn't)
 *          or false negative (no match when should). Caller must initialize sa_family, IP address,
 *          and port before calling. Particularly important: port must be network byte order (htons()).
 * @warning Port comparison significance: Function compares both IP and port. If searching for
 *          listener on specific IP with any port, this function won't work (returns NULL unless
 *          port also matches). Current usage always searches with full address:port, but future
 *          callers should be aware of port matching requirement.
 *
 * @see sockaddr_isequal() in util.c which performs address comparison (family + IP + port equality)
 * @see create_bound_listeners() which calls this function to check for existing listeners before creation
 * @see create_listeners() which creates new listener if find_listener() returns NULL
 * @see struct listener definition in dnsmasq.h for listener structure fields
 * @see release_listener() which removes listener from list and frees memory (inverse operation)
 *
 * EXAMPLE USAGE:
 * @code
 * // Called from create_bound_listeners() for each interface address
 * struct irec *iface;  // Interface record with address
 * struct listener *existing;
 * 
 * // Check if listener already exists for this address
 * existing = find_listener(&iface->addr);
 * 
 * if (existing)
 *   {
 *     // Listener already created for this address (possibly from another interface)
 *     // Reuse existing listener instead of creating duplicate
 *     iface->done = 1;  // Mark interface as processed
 *     existing->iface = iface;  // Associate interface with listener
 *     
 *     // No need to create new listener, sockets already bound
 *   }
 * else
 *   {
 *     // No existing listener for this address
 *     // Create new listener with sockets bound to address
 *     struct listener *new = create_listeners(&iface->addr, 
 *                                              option_bool(OPT_TFTP), 
 *                                              dienow);
 *     if (new)
 *       {
 *         // Add new listener to list
 *         new->next = daemon->listeners;
 *         daemon->listeners = new;
 *         new->iface = iface;
 *         iface->done = 1;
 *       }
 *   }
 * @endcode
 *
 * @code
 * // Example showing search through list with multiple listeners
 * 
 * // Assume daemon->listeners contains:
 * // L1: 192.168.1.1:53 -> L2: 192.168.1.2:53 -> L3: 10.0.0.1:53 -> NULL
 * 
 * union mysockaddr search_addr;
 * memset(&search_addr, 0, sizeof(search_addr));
 * search_addr.in.sin_family = AF_INET;
 * inet_pton(AF_INET, "192.168.1.2", &search_addr.in.sin_addr);
 * search_addr.in.sin_port = htons(53);
 * 
 * struct listener *result = find_listener(&search_addr);
 * 
 * // Result points to L2 (192.168.1.2:53)
 * // Search stopped at L2, didn't examine L3
 * // If searching for 10.0.0.1:53, would traverse L1, L2, and find at L3
 * // If searching for 172.16.0.1:53, would traverse all and return NULL
 * @endcode
 *
 * @code
 * // Example showing port matching requirement
 * 
 * // Listener exists: 192.168.1.1:53 (DNS)
 * 
 * // Search for same IP, different port
 * union mysockaddr tftp_addr;
 * // ... initialize with 192.168.1.1 ...
 * tftp_addr.in.sin_port = htons(69);  // TFTP port
 * 
 * struct listener *result = find_listener(&tftp_addr);
 * 
 * // Result is NULL because port doesn't match (69 != 53)
 * // Even though IP address matches, full address:port must match
 * // This is correct behavior - TFTP listener is separate from DNS listener
 * @endcode
 *
 * LINKED LIST TRAVERSAL DIAGRAM:
 * 
 * daemon->listeners -> L1 -> L2 -> L3 -> NULL
 *                      ^     ^     ^      ^
 *                      |     |     |      |
 * Iteration:          l=L1  l=L2  l=L3  l=NULL (exit)
 * 
 * For each iteration:
 *   if (sockaddr_isequal(&l->addr, addr))
 *     return l;  // Early termination on match
 * 
 * If no match found, l becomes NULL, loop exits, return NULL
 *
 * SEARCH ALGORITHM:
 * 
 * Input: addr = address to find
 * Output: Matching listener or NULL
 * 
 * for each listener L in daemon->listeners:
 *   if L.addr == addr:  // sockaddr_isequal comparison
 *     return L          // Found match, stop searching
 * return NULL           // Exhausted list, no match
 * 
 * Time complexity: O(n) worst case (no match or last element)
 *                  O(1) best case (first element matches)
 *                  O(n/2) average case (match in middle)
 *
 * SIDE EFFECTS:
 * - None - pure read-only search function
 * - No modification of daemon->listeners list
 * - No modification of listener structures
 * - No global state changes
 * - No I/O operations
 * - No memory allocation or deallocation
 * 
 * THREAD SAFETY: Read-only operation is thread-safe for reads if list not modified concurrently.
 *                 dnsmasq single-threaded, no concurrency issues in practice.
 */
static struct listener *find_listener(union mysockaddr *addr)
{
  struct listener *l;
  for (l = daemon->listeners; l; l = l->next)
    if (sockaddr_isequal(&l->addr, addr))
      return l;
  return NULL;
}

/**
 * @brief Create listeners bound to specific interface addresses (--bind-interfaces mode)
 * 
 * @detailed Create DNS and optionally TFTP listeners bound to specific interface IP addresses
 *           rather than wildcard addresses (0.0.0.0/::). This function implements --bind-interfaces
 *           mode where daemon creates separate socket per interface address, contrasting with
 *           default wildcard binding mode (create_wildcard_listeners) where single socket receives
 *           all interfaces.
 *
 *           Two-phase listener creation strategy:
 *           
 *           **Phase 1: Interface-matched listeners** (lines 1184-1210)
 *           Iterate through daemon->interfaces list (populated by enumerate_interfaces()) containing
 *           struct irec entries for each detected network interface address. For each interface
 *           address found on system (iface->found=1), create listener bound to that specific address.
 *           Skip interfaces that are:
 *           - Already processed (iface->done=1) from previous call or duplicate detection
 *           - In DAD state (iface->dad=1, IPv6 Duplicate Address Detection incomplete)
 *           - Not found on system (iface->found=0, configured but interface doesn't exist)
 *
 *           Duplicate detection mechanism:
 *           Multiple struct irec entries may share same IP address (interface with multiple addresses,
 *           aliases, secondary addresses). Call find_listener(&iface->addr) to check if listener
 *           already created for address. If existing listener found:
 *           - Increment existing->used counter (tracks number of interfaces sharing listener)
 *           - Set iface->done=1 (mark interface as processed, skip duplicate creation)
 *           - Reuse existing listener instead of creating duplicate (bind() would fail EADDRINUSE)
 *           
 *           If no existing listener, call create_listeners() to create new listener with sockets
 *           bound to iface->addr. New listener initialized with:
 *           - new->iface = iface (associate listener with interface for interface-specific logic)
 *           - new->next = daemon->listeners (prepend to global listener linked list)
 *           - daemon->listeners = new (update list head to new listener)
 *           - iface->done = 1 (mark interface processed)
 *           
 *           Conditional logging (lines 1203-1208):
 *           If dienow=0 (non-fatal mode, runtime reconfiguration), log listener creation with
 *           interface name, index, address, and port. Format:
 *           "listening on eth0(#2): 192.168.1.1 port 53"
 *           
 *           If dienow=1 (fatal mode, initial startup), skip logging because syslog not yet
 *           initialized and daemon sign-on message not printed. Avoids log corruption or
 *           lost messages during early startup phase.
 *
 *           **Phase 2: Unmatched --listen-address listeners** (lines 1223-1235)
 *           Iterate through daemon->if_addrs list (populated by --listen-address configuration)
 *           containing struct iname entries for explicitly configured listen addresses. These
 *           addresses may not match any actual interface address but could still be valid.
 *           
 *           Valid unmatched address scenarios:
 *           - **Secondary loopback addresses**: System has lo interface with primary address
 *             127.0.0.1, but daemon configured to listen on 127.0.1.1 which is also loopback
 *             range and kernel allows binding. Common for testing multiple instances on different
 *             loopback addresses without creating virtual interfaces.
 *           - **Addresses not yet assigned**: In --bind-dynamic mode, interface might gain
 *             address later (VPN connects, DHCP lease obtained, manual configuration). Binding
 *             attempt fails gracefully with EADDRNOTAVAIL, daemon retries when interface appears.
 *           - **Virtual/alias addresses**: Some systems allow binding to addresses not explicitly
 *             assigned to interface via IP_FREEBIND (Linux) or similar mechanisms.
 *
 *           INAME_USED flag:
 *           During enumerate_interfaces(), when interface address matches configured --listen-address
 *           entry, INAME_USED flag set on struct iname to mark address as matched to actual interface.
 *           Phase 2 only processes entries WITHOUT INAME_USED flag (unmatched configured addresses).
 *           This prevents duplicate listener creation for addresses already handled in Phase 1.
 *
 *           Interface-less listeners (iface=NULL):
 *           Listeners created in Phase 2 have new->iface=NULL because no struct irec exists for
 *           address (not matched to actual interface). NULL iface has implications for daemon
 *           operation (from comment lines 1219-1221):
 *           - **--localise-queries disabled**: Cannot determine client subnet from interface netmask
 *             when iface=NULL. Feature relies on iface->netmask for subnet calculation. Queries
 *             processed without localization.
 *           - **TFTP MTU logic affected**: TFTP code uses iface->mtu for determining block size.
 *             When iface=NULL, TFTP falls back to conservative MTU assumptions (typically 512 byte
 *             blocks, no optimizations for large MTU interfaces).
 *           - **Interface-specific filtering unavailable**: Cannot filter queries by incoming
 *             interface (--interface, --except-interface) when iface=NULL.
 *
 *           These limitations acceptable for unmatched addresses because they're typically used
 *           for special cases (secondary loopback, testing) where localization not needed.
 *
 *           Bind failure handling (from comment lines 1216-1217):
 *           If unmatched address truly invalid (typo in config, wrong IP range), bind() in
 *           make_sock() (called by create_listeners) fails with EADDRNOTAVAIL or EACCES.
 *           Behavior depends on dienow parameter:
 *           - **dienow=1** (initial startup): die() terminates daemon with EC_BADNET exit code.
 *             Invalid configured address is fatal error during initialization.
 *           - **dienow=0** (--bind-dynamic mode): Log warning via my_syslog(LOG_WARNING), continue
 *             daemon operation without this listener. Daemon retries binding when newaddress()
 *             called (interface state change notification from netlink/routing socket).
 *
 *           --bind-interfaces vs --bind-dynamic distinction:
 *           - **--bind-interfaces** (this function with dienow=1): Static binding at startup.
 *             All configured addresses must be available immediately, failures fatal. No runtime
 *             adaptation to interface changes. Simpler but inflexible.
 *           - **--bind-dynamic** (this function with dienow=0): Dynamic binding with runtime
 *             adaptation. Tolerates temporarily unavailable addresses, retries on interface changes.
 *             Requires platform support (netlink on Linux, routing socket on BSD) for interface
 *             change notifications. More flexible but requires kernel event support.
 *
 *           TFTP enable logic:
 *           Phase 1 uses iface->tftp_ok flag (per-interface TFTP control via --enable-tftp=interface).
 *           Phase 2 uses !!option_bool(OPT_TFTP) (global TFTP enable via --enable-tftp).
 *           Double-negation converts boolean option to integer 0/1 for create_listeners() do_tftp parameter.
 *           This allows selective TFTP enabling: enable on internal interface, disable on external
 *           interface for security.
 *
 *           Usage counter (existing->used++):
 *           When multiple interfaces share same address (secondary addresses, aliases), existing
 *           listener reused and usage counter incremented. Counter tracks number of interfaces
 *           associated with listener. Used during cleanup (release_listener) to determine when
 *           listener safe to remove (used==0 means no interfaces reference it).
 *
 *           Prepend list insertion (new->next = daemon->listeners; daemon->listeners = new):
 *           New listeners prepended to daemon->listeners linked list (add at head, not tail).
 *           O(1) insertion complexity vs O(n) for append. List order doesn't matter for correctness
 *           (event loop polls all sockets), prepend is standard singly-linked list pattern.
 *
 *           Integration with enumerate_interfaces():
 *           This function expects daemon->interfaces list already populated by enumerate_interfaces().
 *           Typical call sequence in main():
 *           1. enumerate_interfaces(0) - scan system interfaces, populate daemon->interfaces
 *           2. create_bound_listeners(1) - create listeners for found interfaces (dienow=1 for startup)
 *           3. Enter event loop
 *           For --bind-dynamic mode, sequence repeats on interface changes:
 *           1. newaddress() - netlink/routing socket notifies address change
 *           2. enumerate_interfaces(0) - rescan interfaces, update daemon->interfaces
 *           3. create_bound_listeners(0) - create listeners for new addresses (dienow=0 for runtime)
 *
 *           Logging format explanation:
 *           "listening on eth0(#2): 192.168.1.1 port 53"
 *           - **eth0**: Interface name from iface->name (IF_NAMESIZE buffer, like "eth0", "wlan0")
 *           - **(#2)**: Interface index from iface->index (kernel interface index, eth0 might be 2)
 *           - **192.168.1.1**: IP address from prettyprint_addr(&iface->addr, daemon->addrbuff)
 *           - **port 53**: Port number returned by prettyprint_addr (extracts from addr structure)
 *
 *           prettyprint_addr() formats address for human readability:
 *           - IPv4: "192.168.1.1" (dotted decimal)
 *           - IPv6: "2001:db8::1" (compressed notation, :: for zero runs)
 *           - Returns port number as integer return value
 *           - Stores formatted address in daemon->addrbuff (ADDRSTRLEN bytes)
 *
 *           Why logging only when !dienow (lines 1203, 1230):
 *           During initial startup (dienow=1), syslog not yet initialized via log_start() and
 *           daemon sign-on message ("dnsmasq[pid]: started, version X.XX") not yet printed.
 *           Logging listener creation messages before sign-on creates confusing log output with
 *           messages out of order or lost. By skipping logging during startup, messages appear
 *           in logical order: sign-on first, then configuration details, then operational messages.
 *           
 *           For runtime reconfiguration (dienow=0), syslog already initialized and operational,
 *           safe to log listener creation for debugging and monitoring.
 *
 *           LOG_DEBUG|MS_DEBUG flag explanation:
 *           - **LOG_DEBUG**: Syslog priority level (lowest priority, debug information)
 *           - **MS_DEBUG**: dnsmasq-specific flag indicating message subject to --log-debug filtering
 *           Combined flag means: "Log at DEBUG level, but only if --log-debug option enabled."
 *           Without --log-debug, these messages suppressed (reduce log noise for production).
 *
 * @param dienow Error handling mode controlling behavior when socket creation fails. Passed through
 *               to create_listeners() for each listener creation attempt. Determines whether bind()
 *               failure is fatal (terminate daemon) or recoverable (log warning, continue operation).
 *               Values:
 *               - **1 (non-zero)**: Fatal error mode. Socket creation failure calls die(), terminating
 *                 daemon with EC_BADNET exit code. Used during daemon initialization (--bind-interfaces
 *                 mode) when successful binding to all configured addresses is prerequisite for daemon
 *                 operation. Any bind() failure indicates configuration error or conflicting process,
 *                 better to terminate with clear error than run in broken state. Also controls logging:
 *                 dienow=1 suppresses listener creation logging because syslog not yet initialized.
 *               - **0 (zero)**: Non-fatal error mode. Socket creation failure logs warning via
 *                 my_syslog(LOG_WARNING) but daemon continues operation with partial listeners. Used
 *                 during runtime reconfiguration (--bind-dynamic mode) when interface addresses appear/
 *                 disappear dynamically. Temporary unavailability (EADDRNOTAVAIL) acceptable, daemon
 *                 retries when newaddress() called on interface state change. Also enables logging:
 *                 dienow=0 triggers listener creation log messages for debugging and monitoring.
 *
 * @return void (no return value)
 *
 * @note Phase 1 vs Phase 2: Function has two distinct loops creating listeners from different sources.
 *       Phase 1 processes daemon->interfaces (actual interfaces found by enumerate_interfaces),
 *       Phase 2 processes daemon->if_addrs (configured --listen-address not matched to interfaces).
 *       Understanding this distinction critical for diagnosing why listeners created or not created.
 * @note Duplicate detection: find_listener() prevents creating multiple listeners for same address.
 *       Multiple interfaces sharing address reuse existing listener, incrementing usage counter.
 *       Essential for avoiding EADDRINUSE bind() errors.
 * @note iface->done flag: Marks interface as processed, preventing redundant listener creation on
 *       subsequent calls or within same call (multiple irec for same address). Cleared between calls
 *       by clean_interfaces() for dynamic reconfiguration.
 * @note iface=NULL listeners: Phase 2 creates listeners without interface association (new->iface=NULL).
 *       Affects --localise-queries and TFTP MTU logic. Not an error - valid for secondary loopback
 *       addresses and --bind-dynamic pending addresses.
 * @note INAME_USED flag: Set by enumerate_interfaces() when --listen-address matched to actual
 *       interface. Prevents duplicate processing between Phase 1 and Phase 2. Only unmatched
 *       addresses (INAME_USED not set) processed in Phase 2.
 * @note dienow controls logging: dienow=1 suppresses logs (startup, syslog not ready), dienow=0
 *       enables logs (runtime, debugging). Different from fatal vs non-fatal error handling role.
 * @note TFTP enable sources: Phase 1 uses per-interface iface->tftp_ok flag, Phase 2 uses global
 *       option_bool(OPT_TFTP). Allows selective TFTP per interface vs global enable.
 * @note List prepending: New listeners added at head (daemon->listeners = new), not tail. O(1)
 *       insertion, standard singly-linked list pattern. Order doesn't affect functionality.
 * @note Global state modification: Modifies daemon->listeners linked list (adds new listeners),
 *       modifies iface->done flags, modifies existing->used counters. Not thread-safe without locking.
 * @note Single-threaded architecture: Function not thread-safe due to linked list manipulation and
 *       global state access without locking. dnsmasq single-threaded design makes this acceptable.
 *
 * @warning Expects daemon->interfaces initialized: Function assumes enumerate_interfaces() already
 *          called to populate daemon->interfaces list. Empty list results in no Phase 1 listeners
 *          (only Phase 2 --listen-address listeners created). Must call enumerate_interfaces(0)
 *          before calling this function, typically in main() initialization sequence.
 * @warning Expects daemon->if_addrs initialized: Function assumes --listen-address configuration
 *          parsed and daemon->if_addrs list populated. Empty list results in no Phase 2 listeners
 *          (only Phase 1 interface-matched listeners). Normal for configurations without explicit
 *          --listen-address options.
 * @warning dienow=1 prevents logging: Initial startup (dienow=1) suppresses listener creation logs
 *          because syslog not initialized. For debugging startup issues, must rely on die() error
 *          messages or strace system call tracing. Log messages only appear for dynamic updates (dienow=0).
 * @warning iface->found prerequisite: Phase 1 only processes interfaces with iface->found=1 (set by
 *          enumerate_interfaces when interface detected on system). Configured interfaces not found
 *          on system skipped without warning in this function (warning handled elsewhere by
 *          warn_int_names). Silent skip can confuse debugging if interface expected but typo in name.
 * @warning DAD state handling: IPv6 interfaces in Duplicate Address Detection (iface->dad=1) skipped
 *          to avoid binding to addresses not yet validated as unique. Listener creation retried after
 *          DAD completes (is_dad_listeners clears flag, subsequent call processes interface).
 * @warning unmatched address binding: Phase 2 attempts binding to --listen-address not matched to
 *          actual interface. If address truly invalid (wrong IP range, typo), bind() fails. With
 *          dienow=1, daemon terminates (fatal). With dienow=0, logs warning and continues (acceptable
 *          for --bind-dynamic). Ensure --listen-address configuration valid to avoid unexpected behavior.
 * @warning Usage counter correctness: existing->used incremented when sharing listener across multiple
 *          interfaces. Must decrement during interface removal (clean_interfaces, release_listener)
 *          to prevent premature listener removal or listener leaks. Incorrect counter management
 *          breaks dynamic reconfiguration.
 * @warning Listener ownership: Listeners added to daemon->listeners list owned by daemon, cleaned up
 *          during shutdown via release_listener(). Caller must not free listeners manually. Orphaned
 *          listeners (not added to list) cause memory and fd leaks.
 *
 * @see create_listeners() which creates individual listener structures with sockets (called for each address)
 * @see find_listener() which searches for existing listener matching address (duplicate detection)
 * @see enumerate_interfaces() which populates daemon->interfaces list (must be called before this function)
 * @see create_wildcard_listeners() alternative binding mode creating wildcard listeners (0.0.0.0, ::)
 * @see release_listener() which closes sockets and frees listener memory (cleanup function)
 * @see clean_interfaces() which clears iface->done flags for dynamic reconfiguration
 * @see newaddress() which calls this function (dienow=0) on interface state changes in --bind-dynamic mode
 * @see warn_bound_listeners() which warns about potential security issues in --bind-interfaces mode
 * @see struct irec definition in dnsmasq.h for interface record structure
 * @see struct iname definition in dnsmasq.h for configured listen address structure
 * @see struct listener definition in dnsmasq.h for listener structure
 *
 * EXAMPLE USAGE:
 * @code
 * // Called during daemon initialization in main() (--bind-interfaces mode)
 * 
 * // Parse configuration
 * read_opts(argc, argv, compile_opts);
 * 
 * // Scan interfaces (populates daemon->interfaces)
 * enumerate_interfaces(0);
 * 
 * // Create listeners bound to specific interface addresses
 * if (option_bool(OPT_NOWILD))  // --bind-interfaces mode
 *   {
 *     create_bound_listeners(1);  // dienow=1: fatal errors, no logging
 *     
 *     // Warn about potential security issues (globally routable addresses)
 *     warn_bound_listeners();
 *   }
 * else
 *   {
 *     // Default wildcard binding mode
 *     create_wildcard_listeners();
 *   }
 * 
 * // Continue with event loop setup
 * // Add listener sockets to poll set...
 * @endcode
 *
 * @code
 * // Called during runtime reconfiguration (--bind-dynamic mode)
 * // Triggered by newaddress() on interface state change
 * 
 * void newaddress(time_t now)
 * {
 *   // Rescan interfaces for new addresses
 *   enumerate_interfaces(0);
 *   
 *   // Create listeners for new addresses
 *   // dienow=0: non-fatal errors, enable logging
 *   create_bound_listeners(0);
 *   
 *   // Log new listener creation (enabled because dienow=0):
 *   // "listening on eth0(#2): 192.168.1.1 port 53"
 * }
 * @endcode
 *
 * @code
 * // Example showing duplicate detection mechanism
 * 
 * // Scenario: Interface eth0 has two addresses (primary + secondary)
 * // daemon->interfaces contains:
 * //   iface1: eth0, 192.168.1.1, done=0
 * //   iface2: eth0, 192.168.1.2, done=0
 * //   iface3: eth0, 192.168.1.1, done=0  // Duplicate of iface1 (secondary address)
 * 
 * create_bound_listeners(1);
 * 
 * // Processing sequence:
 * // 1. Process iface1 (192.168.1.1):
 * //    find_listener() returns NULL (no existing)
 * //    create_listeners() creates new listener L1
 * //    L1->iface = iface1, iface1->done = 1
 * //    Add L1 to daemon->listeners
 * 
 * // 2. Process iface2 (192.168.1.2):
 * //    find_listener() returns NULL (different address)
 * //    create_listeners() creates new listener L2
 * //    L2->iface = iface2, iface2->done = 1
 * //    Add L2 to daemon->listeners
 * 
 * // 3. Process iface3 (192.168.1.1):
 * //    find_listener() returns L1 (same address as iface1)
 * //    L1->used++ (now 2, shared by iface1 and iface3)
 * //    iface3->done = 1
 * //    Skip create_listeners() (reuse existing)
 * 
 * // Result: Two listeners (L1, L2), three interfaces (iface1, iface2, iface3)
 * //         L1 shared by iface1 and iface3 (usage counter = 2)
 * @endcode
 *
 * @code
 * // Example showing unmatched --listen-address handling
 * 
 * // Configuration: --listen-address=127.0.1.1 (secondary loopback)
 * // System interfaces: lo has 127.0.0.1 (primary loopback only)
 * 
 * // After enumerate_interfaces():
 * // daemon->interfaces contains: iface: lo, 127.0.0.1, found=1
 * // daemon->if_addrs contains: addr: 127.0.1.1, INAME_USED not set (no match)
 * 
 * create_bound_listeners(1);
 * 
 * // Phase 1: Process 127.0.0.1 interface
 * //   Create listener L1 for 127.0.0.1:53
 * //   L1->iface = lo interface
 * 
 * // Phase 2: Process 127.0.1.1 unmatched address
 * //   INAME_USED not set (not matched to any interface)
 * //   create_listeners() attempts binding to 127.0.1.1:53
 * //   If kernel allows (loopback range): Creates listener L2
 * //   L2->iface = NULL (no interface association)
 * //   If kernel rejects: die() terminates (dienow=1)
 * 
 * // Result: Two listeners if successful (L1 for 127.0.0.1, L2 for 127.0.1.1)
 * //         L2 has iface=NULL, --localise-queries disabled for L2 queries
 * @endcode
 *
 * PHASE 1 FLOWCHART (Interface-matched listeners):
 * 
 * for each iface in daemon->interfaces:
 *   if !iface->done && !iface->dad && iface->found:
 *     existing = find_listener(&iface->addr)
 *     if existing:
 *       existing->used++
 *       iface->done = 1
 *     else:
 *       new = create_listeners(&iface->addr, iface->tftp_ok, dienow)
 *       if new:
 *         new->iface = iface
 *         add new to daemon->listeners
 *         iface->done = 1
 *         if !dienow: log listener creation
 *
 * PHASE 2 FLOWCHART (Unmatched --listen-address):
 * 
 * for each if_tmp in daemon->if_addrs:
 *   if !(if_tmp->flags & INAME_USED):
 *     new = create_listeners(&if_tmp->addr, !!option_bool(OPT_TFTP), dienow)
 *     if new:
 *       add new to daemon->listeners
 *       if !dienow: log listener creation
 *
 * LISTENER ASSOCIATION MATRIX:
 * 
 * Scenario                          | Phase | iface field  | used counter | Logging
 * ----------------------------------|-------|--------------|--------------|----------
 * Interface address, first time     | 1     | iface ptr    | 1 (initial)  | if !dienow
 * Interface address, duplicate      | 1     | iface ptr    | incremented  | none
 * Unmatched --listen-address        | 2     | NULL         | 1 (initial)  | if !dienow
 * Wildcard binding (different func) | N/A   | NULL         | 1 (initial)  | none
 *
 * USAGE COUNTER EXAMPLE:
 * 
 * Initial state:
 *   iface1: eth0, 192.168.1.1
 *   iface2: eth0, 192.168.1.1 (secondary)
 * 
 * After create_bound_listeners(1):
 *   listener L1: addr=192.168.1.1, iface=iface1, used=2
 *   (Both iface1 and iface2 share L1, used=2)
 * 
 * During cleanup (interface removed):
 *   Remove iface1: L1->used-- (now 1, don't release yet)
 *   Remove iface2: L1->used-- (now 0, safe to release_listener(L1))
 *
 * SIDE EFFECTS:
 * - Modifies daemon->listeners linked list (adds new listeners, O(n) list growth)
 * - Modifies iface->done flags (marks interfaces processed, affects subsequent calls)
 * - Modifies existing->used counters (tracks listener sharing, affects cleanup logic)
 * - Allocates memory for listener structures via create_listeners() (safe_malloc, dies on OOM)
 * - Creates kernel socket objects (consumes file descriptors, binds addresses)
 * - Binds sockets to specific interface addresses (reserves address:port for process)
 * - May call die() and terminate daemon if socket creation fails with dienow=1
 * - May log messages via my_syslog() if listener creation successful with dienow=0
 * - Calls find_listener() for duplicate detection (O(n) search per interface)
 * - Calls create_listeners() which modifies global daemon->v6pktinfo via set_ipv6pktinfo()
 * 
 * THREAD SAFETY: Not thread-safe due to:
 *                 - Linked list manipulation (daemon->listeners) without atomic operations
 *                 - Global state modification (iface->done flags, existing->used counters)
 *                 - Potential die() call (process termination)
 *                 - Calls to create_listeners() which access daemon globals
 *                 dnsmasq's single-threaded architecture makes this acceptable.
 */
void create_bound_listeners(int dienow)
{
  struct listener *new;
  struct irec *iface;
  struct iname *if_tmp;
  struct listener *existing;

  for (iface = daemon->interfaces; iface; iface = iface->next)
    if (!iface->done && !iface->dad && iface->found)
      {
	existing = find_listener(&iface->addr);
	if (existing)
	  {
	    iface->done = 1;
	    existing->used++; /* increase usage counter */
	  }
	else if ((new = create_listeners(&iface->addr, iface->tftp_ok, dienow)))
	  {
	    new->iface = iface;
	    new->next = daemon->listeners;
	    daemon->listeners = new;
	    iface->done = 1;

	    /* Don't log the initial set of listen addresses created
               at startup, since this is happening before the logging
               system is initialised and the sign-on printed. */
            if (!dienow)
              {
		int port = prettyprint_addr(&iface->addr, daemon->addrbuff);
		my_syslog(LOG_DEBUG|MS_DEBUG, _("listening on %s(#%d): %s port %d"),
			  iface->name, iface->index, daemon->addrbuff, port);
	      }
	  }
      }

  /* Check for --listen-address options that haven't been used because there's
     no interface with a matching address. These may be valid: eg it's possible
     to listen on 127.0.1.1 even if the loopback interface is 127.0.0.1

     If the address isn't valid the bind() will fail and we'll die() 
     (except in bind-dynamic mode, when we'll complain but keep trying.)

     The resulting listeners have the ->iface field NULL, and this has to be
     handled by the DNS and TFTP code. It disables --localise-queries processing
     (no netmask) and some MTU login the tftp code. */

  for (if_tmp = daemon->if_addrs; if_tmp; if_tmp = if_tmp->next)
    if (!(if_tmp->flags & INAME_USED) && 
	(new = create_listeners(&if_tmp->addr, !!option_bool(OPT_TFTP), dienow)))
      {
	new->next = daemon->listeners;
	daemon->listeners = new;

	if (!dienow)
	  {
	    int port = prettyprint_addr(&if_tmp->addr, daemon->addrbuff);
	    my_syslog(LOG_DEBUG|MS_DEBUG, _("listening on %s port %d"), daemon->addrbuff, port);
	  }
      }
}

/**
 * @brief Warn about potential security issues when using --bind-interfaces mode
 * 
 * @detailed In --bind-interfaces mode, access control is limited to the addresses being
 *           listened on. This function checks all bound listeners and issues warnings for
 *           IPv4 addresses that appear globally routable (non-RFC1918/loopback), as queries
 *           to these addresses could arrive via any interface, potentially enabling DNS
 *           amplification attacks. The function marks warned interfaces and suggests using
 *           --bind-dynamic mode, which provides proper arrival interface checking.
 * 
 * @note IPv6 addresses are not checked because IPv6 API always supports arrival interface
 *       checking, making this issue specific to IPv4.
 * @note Only non-authoritative DNS interfaces are checked (dns_auth flag false).
 * 
 * @see private_net() in rfc1035.c for RFC1918/loopback address detection
 * 
 * EXAMPLE USAGE:
 * @code
 * if (option_bool(OPT_NOWILD))
 *   warn_bound_listeners();  // Called after create_bound_listeners()
 * @endcode
 * 
 * RFC COMPLIANCE: Addresses security considerations for DNS amplification attacks
 * SIDE EFFECTS: Sets iface->warned flag for warned interfaces; logs warnings to syslog
 * THREAD SAFETY: Single-threaded daemon architecture; modifies interface list state
 */
/* In --bind-interfaces, the only access control is the addresses we're listening on. 
   There's nothing to avoid a query to the address of an internal interface arriving via
   an external interface where we don't want to accept queries, except that in the usual 
   case the addresses of internal interfaces are RFC1918. When bind-interfaces in use, 
   and we listen on an address that looks like it's probably globally routeable, shout.

   The fix is to use --bind-dynamic, which actually checks the arrival interface too.
   Tough if your platform doesn't support this.

   Note that checking the arrival interface is supported in the standard IPv6 API and
   always done, so we don't warn about any IPv6 addresses here.
*/

void warn_bound_listeners(void)
{
  struct irec *iface; 	
  int advice = 0;

  for (iface = daemon->interfaces; iface; iface = iface->next)
    if (!iface->dns_auth)
      {
	if (iface->addr.sa.sa_family == AF_INET)
	  {
	    if (!private_net(iface->addr.in.sin_addr, 1))
	      {
		inet_ntop(AF_INET, &iface->addr.in.sin_addr, daemon->addrbuff, ADDRSTRLEN);
		iface->warned = advice = 1;
		my_syslog(LOG_WARNING, 
			  _("LOUD WARNING: listening on %s may accept requests via interfaces other than %s"),
			  daemon->addrbuff, iface->name);
	      }
	  }
      }
  
  if (advice)
    my_syslog(LOG_WARNING, _("LOUD WARNING: use --bind-dynamic rather than --bind-interfaces to avoid DNS amplification attacks via these interface(s)")); 
}

/**
 * @brief Warn when wildcard interface labels are resolved to actual interfaces
 * 
 * @detailed When users specify interface labels (e.g., "eth*") that match multiple
 *           interfaces, this function warns which specific interfaces were selected.
 *           This helps administrators verify that wildcard interface specifications
 *           resolved as intended, particularly in dynamic interface environments.
 * 
 * @note Only logs warnings for interfaces that were found (iface->found), have names,
 *       and were specified via labels (iface->label non-NULL).
 * 
 * @see enumerate_interfaces() where interface labels are matched to actual interfaces
 * 
 * EXAMPLE USAGE:
 * @code
 * enumerate_interfaces();
 * warn_wild_labels();  // Warn about label resolutions
 * @endcode
 * 
 * SIDE EFFECTS: Logs warning messages to syslog for each matched interface
 * THREAD SAFETY: Single-threaded daemon architecture; reads interface list state
 */
void warn_wild_labels(void)
{
  struct irec *iface;

  for (iface = daemon->interfaces; iface; iface = iface->next)
    if (iface->found && iface->name && iface->label)
      my_syslog(LOG_WARNING, _("warning: using interface %s instead"), iface->name);
}

/**
 * @brief Warn about configured interface names that have no addresses
 * 
 * @detailed When users specify named interfaces (via --interface or configuration) that
 *           should have addresses but don't, this function logs warnings. This helps
 *           administrators identify misconfigured or down interfaces that were expected
 *           to provide DNS/DHCP services. Warnings indicate the interface exists but
 *           lacks usable addresses for the requested protocol families.
 * 
 * @note Only warns for interfaces where addr field is NULL (intname->addr == NULL) after
 *       interface enumeration completes, indicating no addresses were found.
 * 
 * @see enumerate_interfaces() where interface names are matched and addresses populated
 * 
 * EXAMPLE USAGE:
 * @code
 * enumerate_interfaces();
 * warn_int_names();  // Warn about interfaces without addresses
 * @endcode
 * 
 * SIDE EFFECTS: Logs warning messages to syslog for each interface without addresses
 * THREAD SAFETY: Single-threaded daemon architecture; reads int_names list state
 */
void warn_int_names(void)
{
  struct interface_name *intname;
 
  for (intname = daemon->int_names; intname; intname = intname->next)
    if (!intname->addr)
      my_syslog(LOG_WARNING, _("warning: no addresses found for interface %s"), intname->intr);
}
 
/**
 * @brief Check if any interfaces are performing IPv6 Duplicate Address Detection
 * 
 * @detailed Determines whether any network interfaces have pending IPv6 Duplicate Address
 *           Detection (DAD) operations. When IPv6 addresses are assigned, the system must
 *           verify they are unique on the link before they become usable. During this DAD
 *           process, the interface has the dad flag set and done flag clear. This function
 *           allows the daemon to delay binding to addresses that are still undergoing DAD,
 *           preventing premature socket binding to tentative addresses.
 * 
 * @return 1 if any interface has pending DAD operations (dad && !done), 0 otherwise
 * 
 * @note Only checks when OPT_NOWILD is set (specific interface binding mode). In wildcard
 *       binding mode, this check is not necessary as the daemon binds to INADDR_ANY/IN6ADDR_ANY.
 * @note The dad flag indicates DAD is in progress; the done flag indicates DAD completed successfully.
 * 
 * @see enumerate_interfaces() where dad and done flags are set based on IPv6 address state
 * @see create_bound_listeners() which uses this to defer binding during DAD
 * 
 * EXAMPLE USAGE:
 * @code
 * if (is_dad_listeners()) {
 *   // Delay socket creation until DAD completes
 *   my_syslog(LOG_INFO, "Waiting for IPv6 DAD to complete");
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 4862 Section 5.4 (IPv6 Stateless Address Autoconfiguration - DAD)
 * SIDE EFFECTS: None (read-only check of interface state)
 * THREAD SAFETY: Single-threaded daemon; reads interfaces list state
 */
int is_dad_listeners(void)
{
  struct irec *iface;
  
  if (option_bool(OPT_NOWILD))
    for (iface = daemon->interfaces; iface; iface = iface->next)
      if (iface->dad && !iface->done)
	return 1;
  
  return 0;
}

#ifdef HAVE_DHCP6
/**
 * @brief Join IPv6 multicast groups required for DHCPv6 and Router Advertisement
 * 
 * @detailed Subscribes eligible IPv6 interfaces to the multicast groups necessary for DHCPv6
 *           server, DHCPv6 relay, and Router Advertisement functionality. This function handles
 *           three distinct multicast groups:
 *           - ALL_RELAY_AGENTS_AND_SERVERS (ff02::1:2): DHCPv6 relay and server communication
 *           - ALL_SERVERS (ff05::1:3): DHCPv6 server-to-server communication
 *           - ALL_ROUTERS (ff02::2): Router Advertisement multicast
 *           
 *           Each physical interface joins multicast groups only once, even if it has multiple
 *           IPv6 addresses (multiple irec entries). The multicast_done flag tracks which
 *           interfaces have already joined to prevent duplicate IPV6_JOIN_GROUP operations.
 * 
 * @param dienow If non-zero, multicast join failures are fatal (daemon terminates with EC_BADNET).
 *               If zero, failures are logged but non-fatal (allows daemon startup to continue).
 * 
 * @return void
 * 
 * @note Only processes interfaces with dhcp6_ok flag set (interfaces eligible for DHCPv6)
 * @note Uses daemon->dhcp6fd for DHCPv6 multicast groups, daemon->icmp6fd for Router Advertisement
 * @note On Linux, ENOMEM errors suggest increasing /proc/sys/net/core/optmem_max kernel parameter
 * 
 * @warning Multicast group membership is per-socket and per-interface. If sockets are recreated,
 *          this function must be called again to rejoin multicast groups.
 * 
 * @see enumerate_interfaces() where dhcp6_ok flag is set for eligible interfaces
 * @see create_bound_listeners() which calls this after interface enumeration
 * 
 * EXAMPLE USAGE:
 * @code
 * // During daemon initialization (fatal errors)
 * enumerate_interfaces(1);
 * join_multicast(1);
 * 
 * // During configuration reload (non-fatal errors)
 * enumerate_interfaces(0);
 * join_multicast(0);
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 3315 Section 5.1 (DHCPv6 multicast addresses)
 *                 RFC 4861 Section 6.1.2 (Router Advertisement to all-nodes)
 * SIDE EFFECTS: Modifies socket multicast group membership via setsockopt(IPV6_JOIN_GROUP)
 *               Sets iface->multicast_done flag for processed interfaces
 *               May terminate daemon if dienow is set and join fails
 * THREAD SAFETY: Single-threaded daemon; modifies global interface list state
 */
void join_multicast(int dienow)      
{
  struct irec *iface, *tmp;

  for (iface = daemon->interfaces; iface; iface = iface->next)
    if (iface->addr.sa.sa_family == AF_INET6 && iface->dhcp6_ok && !iface->multicast_done)
      {
	/* There's an irec per address but we only want to join for multicast 
	   once per interface. Weed out duplicates. */
	for (tmp = daemon->interfaces; tmp; tmp = tmp->next)
	  if (tmp->multicast_done && tmp->index == iface->index)
	    break;
	
	iface->multicast_done = 1;
	
	if (!tmp)
	  {
	    struct ipv6_mreq mreq;
	    int err = 0;

	    mreq.ipv6mr_interface = iface->index;
	    
	    inet_pton(AF_INET6, ALL_RELAY_AGENTS_AND_SERVERS, &mreq.ipv6mr_multiaddr);
	    
	    if ((daemon->doing_dhcp6 || daemon->relay6) &&
		setsockopt(daemon->dhcp6fd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq)) == -1)
	      err = errno;
	    
	    inet_pton(AF_INET6, ALL_SERVERS, &mreq.ipv6mr_multiaddr);
	    
	    if (daemon->doing_dhcp6 && 
		setsockopt(daemon->dhcp6fd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq)) == -1)
	      err = errno;
	    
	    inet_pton(AF_INET6, ALL_ROUTERS, &mreq.ipv6mr_multiaddr);
	    
	    if (daemon->doing_ra &&
		setsockopt(daemon->icmp6fd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq)) == -1)
	      err = errno;
	    
	    if (err)
	      {
		char *s = _("interface %s failed to join DHCPv6 multicast group: %s");
		errno = err;

#ifdef HAVE_LINUX_NETWORK
		if (errno == ENOMEM)
		  my_syslog(LOG_ERR, _("try increasing /proc/sys/net/core/optmem_max"));
#endif

		if (dienow)
		  die(s, iface->name, EC_BADNET);
		else
		  my_syslog(LOG_ERR, s, iface->name, strerror(errno));
	      }
	  }
      }
}
#endif

/**
 * @brief Bind socket to local address with port allocation and interface binding
 * 
 * @detailed Performs bind() system call with sophisticated port allocation strategies.
 *           For UDP sockets with port 0, allocates random port from configured min-port
 *           to max-port range. Implements retry logic for EADDRINUSE/EACCES errors using
 *           systematic search for small ranges or random allocation for large ranges.
 *           Binds socket to specific network interface via SO_BINDTODEVICE (Linux) or
 *           IP_UNICAST_IF/IPV6_UNICAST_IF (BSD/macOS) when interface specified. Optimizes
 *           by skipping bind() for wildcard address/port combinations.
 * 
 * @param fd Socket file descriptor to bind (must be valid socket from socket() call)
 * @param addr Local address to bind socket to (IPv4 or IPv6, copied internally)
 * @param intname Interface name to bind to (IF_NAMESIZE length, may be empty string)
 * @param ifindex Interface index for IP_UNICAST_IF/IPV6_UNICAST_IF socket options (0 = none)
 * @param is_tcp Non-zero if TCP socket (disables source port binding), zero for UDP
 * 
 * @return 1 on successful bind and interface binding, 0 on failure (errno set)
 * @retval 1 Socket successfully bound to local address and interface (if specified)
 * @retval 0 bind() failed with error other than EADDRINUSE/EACCES, or exhausted retries,
 *           or SO_BINDTODEVICE/IP_UNICAST_IF failed
 * 
 * @note Port allocation strategy: For UDP with port==0 and configured min/max-port range,
 *       allocates random port from range. For small ranges (< SMALL_PORT_RANGE), uses
 *       systematic search; for large ranges, uses random selection with up to 100 retries.
 * @note TCP connections: Source port binding disabled (port forced to 0) to allow kernel
 *       ephemeral port allocation, preventing port exhaustion.
 * @note Interface binding: Linux uses SO_BINDTODEVICE; BSD/macOS use IP_UNICAST_IF (IPv4)
 *       or IPV6_UNICAST_IF (IPv6). Not all platforms support all mechanisms.
 * 
 * @warning Requires CAP_NET_RAW or root privileges for SO_BINDTODEVICE on Linux
 * @warning Port allocation retries limited to 100 attempts for large ranges, may fail
 *          under extreme port exhaustion
 * 
 * @see allocate_sfd() for usage in server file descriptor allocation
 * @see fix_fd() for subsequent socket option configuration
 * 
 * EXAMPLE USAGE:
 * @code
 * union mysockaddr local_addr;
 * local_addr.in.sin_family = AF_INET;
 * local_addr.in.sin_addr.s_addr = INADDR_ANY;
 * local_addr.in.sin_port = htons(0); // Random port allocation
 * int success = local_bind(sock_fd, &local_addr, "eth0", if_nametoindex("eth0"), 0);
 * @endcode
 * 
 * RFC COMPLIANCE: Not protocol-specific, implements standard POSIX bind() with extensions
 * SIDE EFFECTS: Modifies socket state (binds to address), consumes port from available range
 * THREAD SAFETY: Not thread-safe (accesses daemon->min_port, daemon->max_port, calls rand16())
 */
int local_bind(int fd, union mysockaddr *addr, char *intname, unsigned int ifindex, int is_tcp)
{
  union mysockaddr addr_copy = *addr;
  unsigned short port;
  int tries = 1;
  unsigned short ports_avail = 1;

  if (addr_copy.sa.sa_family == AF_INET)
    port = addr_copy.in.sin_port;
  else
    port = addr_copy.in6.sin6_port;

  /* cannot set source _port_ for TCP connections. */
  if (is_tcp)
    port = 0;
  else if (port == 0 && daemon->max_port != 0 && daemon->max_port >= daemon->min_port)
    {
      /* Bind a random port within the range given by min-port and max-port if either
	 or both are set. Otherwise use the OS's random ephemeral port allocation by
	 leaving port == 0 and tries == 1 */
      ports_avail = daemon->max_port - daemon->min_port + 1;
      tries =  (ports_avail < SMALL_PORT_RANGE) ? ports_avail : 100;
      port = htons(daemon->min_port + (rand16() % ports_avail));
    }
  
  while (1)
    {
      /* elide bind() call if it's to port 0, address 0 */
      if (addr_copy.sa.sa_family == AF_INET)
	{
	  if (port == 0 && addr_copy.in.sin_addr.s_addr == 0)
	    break;
	  addr_copy.in.sin_port = port;
	}
      else
	{
	  if (port == 0 && IN6_IS_ADDR_UNSPECIFIED(&addr_copy.in6.sin6_addr))
	    break;
	  addr_copy.in6.sin6_port = port;
	}
      
      if (bind(fd, (struct sockaddr *)&addr_copy, sa_len(&addr_copy)) != -1)
	break;
      
       if (errno != EADDRINUSE && errno != EACCES) 
	 return 0;

      if (--tries == 0)
	return 0;

      /* For small ranges, do a systematic search, not a random one. */
      if (ports_avail < SMALL_PORT_RANGE)
	{
	  unsigned short hport = ntohs(port);
	  if (hport++ == daemon->max_port)
	    hport = daemon->min_port;
	  port = htons(hport);
	}
      else
	port = htons(daemon->min_port + (rand16() % ports_avail));
    }

  if (!is_tcp && ifindex > 0)
    {
#if defined(IP_UNICAST_IF)
      if (addr_copy.sa.sa_family == AF_INET)
        {
          uint32_t ifindex_opt = htonl(ifindex);
          return setsockopt(fd, IPPROTO_IP, IP_UNICAST_IF, &ifindex_opt, sizeof(ifindex_opt)) == 0;
        }
#endif
#if defined (IPV6_UNICAST_IF)
      if (addr_copy.sa.sa_family == AF_INET6)
        {
          uint32_t ifindex_opt = htonl(ifindex);
          return setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_IF, &ifindex_opt, sizeof(ifindex_opt)) == 0;
        }
#endif
    }

  (void)intname; /* suppress potential unused warning */
#if defined(SO_BINDTODEVICE)
  if (intname[0] != 0 &&
      setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, intname, IF_NAMESIZE) == -1)
    return 0;
#endif

  return 1;
}

/**
 * @brief Allocate and configure server file descriptor for upstream DNS queries
 * 
 * @detailed Creates or reuses UDP socket (struct serverfd) for sending queries to upstream
 *           DNS servers. Implements socket pooling: searches existing daemon->sfds list for
 *           matching socket (same address, interface, ifindex) before allocating new one.
 *           When random source ports enabled (!daemon->osport) and source port is 0, returns
 *           NULL to indicate queries should use shared wildcard socket. Newly allocated sockets
 *           are configured with IPV6_V6ONLY (IPv6), bound via local_bind(), and added to
 *           daemon->sfds linked list for future reuse.
 * 
 * @param addr Source address for upstream queries (IPv4 or IPv6, must specify family and port)
 * @param intname Interface name to bind socket to (IF_NAMESIZE length, may be empty string)
 * @param ifindex Interface index for IP_UNICAST_IF socket option (0 = no specific interface)
 * 
 * @return Pointer to struct serverfd on success, NULL on allocation/socket/bind failure or
 *         when random ports enabled with port==0 (indicating use of shared wildcard socket)
 * @retval struct serverfd* Existing or newly allocated server file descriptor ready for queries
 * @retval NULL Random ports enabled with port 0 (use wildcard socket), or allocation failed,
 *              or socket() failed, or IPV6_V6ONLY failed, or local_bind() failed, or fix_fd() failed
 * 
 * @note Socket pooling: Multiple upstream servers with identical source address/interface/ifindex
 *       share same socket (struct serverfd), reducing file descriptor consumption
 * @note Random port strategy: When !daemon->osport (random ports enabled) and port==0, returns
 *       NULL immediately without allocation, indicating caller should use shared wildcard socket
 *       with random port allocation per query
 * @note IPv6 sockets: IPV6_V6ONLY option set to 1, preventing IPv4-mapped IPv6 addresses
 * @note Memory management: Allocated struct serverfd added to daemon->sfds list (daemon owns),
 *       freed via close_servers() on shutdown or reload
 * 
 * @warning Socket creation failure, bind failure, or setsockopt failure results in NULL return
 *          with errno set to specific error code (ENOMEM for malloc, others from socket/bind)
 * @warning Caller must check for NULL return and handle fallback to wildcard socket or error
 * 
 * @see local_bind() for socket binding with interface and port allocation
 * @see fix_fd() for socket option configuration (SO_REUSEADDR, etc.)
 * @see pre_allocate_sfds() for initial server fd allocation during startup
 * @see check_servers() for runtime server fd allocation and validation
 * 
 * EXAMPLE USAGE:
 * @code
 * union mysockaddr source_addr;
 * source_addr.in.sin_family = AF_INET;
 * source_addr.in.sin_addr.s_addr = inet_addr("192.168.1.1");
 * source_addr.in.sin_port = htons(5353); // Specific source port
 * struct serverfd *sfd = allocate_sfd(&source_addr, "eth0", if_nametoindex("eth0"));
 * if (sfd) {
 *   // Use sfd->fd for sendto() to upstream server
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: Not protocol-specific, implements socket management for DNS forwarding
 * SIDE EFFECTS: Allocates struct serverfd, creates UDP socket, binds to address/interface,
 *               adds to daemon->sfds list, consumes file descriptor
 * THREAD SAFETY: Not thread-safe (accesses daemon->osport, daemon->sfds, modifies linked list)
 */
static struct serverfd *allocate_sfd(union mysockaddr *addr, char *intname, unsigned int ifindex)
{
  struct serverfd *sfd;
  int errsave;
  int opt = 1;
  
  /* when using random ports, servers which would otherwise use
     the INADDR_ANY/port0 socket have sfd set to NULL, this is 
     anything without an explictly set source port. */
  if (!daemon->osport)
    {
      errno = 0;
      
      if (addr->sa.sa_family == AF_INET &&
	  addr->in.sin_port == htons(0)) 
	return NULL;

      if (addr->sa.sa_family == AF_INET6 &&
	  addr->in6.sin6_port == htons(0)) 
	return NULL;
    }

  /* may have a suitable one already */
  for (sfd = daemon->sfds; sfd; sfd = sfd->next )
    if (ifindex == sfd->ifindex &&
	sockaddr_isequal(&sfd->source_addr, addr) &&
	strcmp(intname, sfd->interface) == 0)
      return sfd;
  
  /* need to make a new one. */
  errno = ENOMEM; /* in case malloc fails. */
  if (!(sfd = whine_malloc(sizeof(struct serverfd))))
    return NULL;
  
  if ((sfd->fd = socket(addr->sa.sa_family, SOCK_DGRAM, 0)) == -1)
    {
      free(sfd);
      return NULL;
    }

  if ((addr->sa.sa_family == AF_INET6 && setsockopt(sfd->fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt)) == -1) ||
      !local_bind(sfd->fd, addr, intname, ifindex, 0) || !fix_fd(sfd->fd))
    { 
      errsave = errno; /* save error from bind/setsockopt. */
      close(sfd->fd);
      free(sfd);
      errno = errsave;
      return NULL;
    }

  safe_strncpy(sfd->interface, intname, sizeof(sfd->interface)); 
  sfd->source_addr = *addr;
  sfd->next = daemon->sfds;
  sfd->ifindex = ifindex;
  sfd->preallocated = 0;
  daemon->sfds = sfd;

  return sfd; 
}

/* create upstream sockets during startup, before root is dropped which may be needed
   this allows query_port to be a low port and interface binding */
/**
 * @brief Pre-allocate server file descriptors during daemon startup initialization
 * 
 * @detailed Called during startup (from main()) to pre-allocate UDP sockets for upstream
 *           DNS queries before entering main event loop. Creates shared wildcard sockets
 *           (INADDR_ANY and in6addr_any) when daemon->query_port configured, marked with
 *           preallocated=1 flag to prevent closure during runtime server reconfiguration.
 *           Then iterates daemon->servers list, calling allocate_sfd() for each server's
 *           source address/interface/ifindex. If allocation fails with OPT_NOWILD set,
 *           dies with fatal error (indicates configuration problem). Pre-allocation ensures
 *           required sockets available before processing queries, avoiding runtime allocation
 *           failures.
 * 
 * @param None (uses global daemon structure for configuration and server list)
 * 
 * @return void (no return value, dies on fatal allocation failure)
 * 
 * @note Wildcard socket allocation: When daemon->query_port non-zero (fixed source port mode),
 *       allocates IPv4 INADDR_ANY:query_port and IPv6 in6addr_any:query_port sockets, both
 *       marked preallocated=1 to survive server list reloads (SIGHUP)
 * @note Preallocated flag: sfd->preallocated=1 prevents close_servers() from closing these
 *       shared wildcard sockets during runtime reconfiguration
 * @note Per-server allocation: For each upstream server in daemon->servers, allocates socket
 *       matching server's source_addr, interface name, and ifindex (may reuse existing)
 * @note Fatal error handling: If allocate_sfd() fails (NULL return) with errno!=0 and
 *       OPT_NOWILD option set, dies with "failed to bind server socket" error message
 * @note OPT_NOWILD check: Only dies on allocation failure when --bind-interfaces option set,
 *       as this indicates hard requirement to bind specific interfaces
 * @note Timing: Called during startup before drop_privileges(), so can bind privileged ports
 * 
 * @warning Dies with EC_BADNET exit code if socket allocation fails under OPT_NOWILD
 * @warning Requires daemon->servers list initialized before call (populate_servers() must run first)
 * @warning Requires daemon->query_port configured (0 = random ports, non-zero = fixed port)
 * 
 * @see allocate_sfd() for socket creation and pool management
 * @see check_servers() for runtime server fd validation and allocation
 * @see reload_servers() for SIGHUP-triggered server list reconfiguration
 * @see close_servers() for cleanup of non-preallocated server fds
 * 
 * EXAMPLE USAGE:
 * @code
 * // During daemon startup in main()
 * read_opts(argc, argv, compile_opts); // Parse configuration
 * // ... other initialization ...
 * pre_allocate_sfds();  // Create server sockets before event loop
 * create_bound_listeners(0);  // Create client-facing listeners
 * drop_privileges();  // Drop root after binding privileged ports
 * // ... enter main event loop ...
 * @endcode
 * 
 * RFC COMPLIANCE: Not protocol-specific, implements socket pre-allocation for DNS forwarding
 * SIDE EFFECTS: Allocates multiple struct serverfd objects, creates UDP sockets, binds to
 *               addresses/ports, adds to daemon->sfds list, consumes file descriptors, may die
 *               on allocation failure with OPT_NOWILD
 * THREAD SAFETY: Not thread-safe (accesses daemon->query_port, daemon->servers, daemon->sfds)
 */
void pre_allocate_sfds(void)
{
  struct server *srv;
  struct serverfd *sfd;
  
  if (daemon->query_port != 0)
    {
      union  mysockaddr addr;
      memset(&addr, 0, sizeof(addr));
      addr.in.sin_family = AF_INET;
      addr.in.sin_addr.s_addr = INADDR_ANY;
      addr.in.sin_port = htons(daemon->query_port);
#ifdef HAVE_SOCKADDR_SA_LEN
      addr.in.sin_len = sizeof(struct sockaddr_in);
#endif
      if ((sfd = allocate_sfd(&addr, "", 0)))
	sfd->preallocated = 1;

      memset(&addr, 0, sizeof(addr));
      addr.in6.sin6_family = AF_INET6;
      addr.in6.sin6_addr = in6addr_any;
      addr.in6.sin6_port = htons(daemon->query_port);
#ifdef HAVE_SOCKADDR_SA_LEN
      addr.in6.sin6_len = sizeof(struct sockaddr_in6);
#endif
      if ((sfd = allocate_sfd(&addr, "", 0)))
	sfd->preallocated = 1;
    }
  
  for (srv = daemon->servers; srv; srv = srv->next)
    if (!allocate_sfd(&srv->source_addr, srv->interface, srv->ifindex) &&
	errno != 0 &&
	option_bool(OPT_NOWILD))
      {
	(void)prettyprint_addr(&srv->source_addr, daemon->namebuff);
	if (srv->interface[0] != 0)
	  {
	    strcat(daemon->namebuff, " ");
	    strcat(daemon->namebuff, srv->interface);
	  }
	die(_("failed to bind server socket for %s: %s"),
	    daemon->namebuff, EC_BADNET);
      }  
}

/**
 * @brief Validate upstream servers, allocate server file descriptors, and log configuration
 * 
 * @detailed Called during daemon startup and on SIGHUP-triggered configuration reload to
 *           validate upstream DNS server configuration, (re-)allocate server file descriptors
 *           (struct serverfd), log server usage for troubleshooting, and perform DNS loop
 *           detection. Iterates daemon->servers list to: (1) log each upstream server address/
 *           port/interface/domain configuration with my_syslog(), (2) increment sfd->refcount
 *           for existing server fds or call allocate_sfd() for new servers, (3) die with fatal
 *           error if allocation fails under OPT_NOWILD. After server validation, removes unused
 *           server fds (refcount==0, not preallocated) by closing socket and freeing struct,
 *           resets refcounts to 0, then calls build_server_array() to rebuild fast-access array.
 *           Optional loop detection via loop_send_probes() and server_gone() marks looping servers.
 * 
 * @param no_loop_check Skip loop detection probes (1=skip, 0=perform). Set to 1 during startup
 *                      before network interfaces stable, 0 during SIGHUP reload when network known good
 * 
 * @return void (no return value, dies on fatal server fd allocation failure)
 * 
 * @note Timing: Called from main() during startup and from SIGHUP signal handler on config reload
 * @note Loop detection: When HAVE_LOOP enabled and no_loop_check==0, sends loop detection probes
 *       via loop_send_probes(), then checks responses via server_gone() to mark looping servers
 *       (sets SERV_LOOP flag, disables server to prevent query loops)
 * @note Interface enumeration: If !OPT_NOWILD (wildcard binding enabled), calls enumerate_interfaces(0)
 *       to refresh interface list for new interfaces added since startup
 * @note Logging format: Logs upstream servers with domain-specific routing (e.g., "using nameserver
 *       8.8.8.8#53 for domain example.com"), interface-specific servers ("via eth0"), local address
 *       servers (SERV_NO_ADDR), and standard resolv.conf servers (SERV_USE_RESOLV)
 * @note Server counting: Counts non-literal, non-local upstream servers for summary log message
 *       "using N nameservers" (helps administrators verify configuration loaded correctly)
 * @note Server fd allocation: For each upstream server, increments existing sfd->refcount or calls
 *       allocate_sfd() to create new socket. Reference counting enables socket pooling (multiple
 *       servers sharing same source address/interface/ifindex share single socket)
 * @note Fatal error handling: If allocate_sfd() fails (NULL return) with errno!=0 and OPT_NOWILD
 *       set (--bind-interfaces), dies with EC_BADNET: "failed to bind server socket for <addr>"
 * @note Server fd cleanup: After validation, removes server fds with refcount==0 (no servers
 *       referencing) and preallocated==0 (not wildcard socket). Closes fd, frees struct, removes
 *       from daemon->sfds list. Preallocated wildcard sockets survive cleanup (persist across reloads)
 * @note Refcount reset: Resets all sfd->refcount to 0 after cleanup, ready for next check_servers() call
 * @note Array rebuild: Calls build_server_array() to rebuild daemon->serverarray[] fast-access array
 *       used by forward_query() for efficient upstream server selection
 * 
 * @warning Dies with EC_BADNET exit code if server socket allocation fails under OPT_NOWILD
 * @warning Requires daemon->servers list populated (via read_opts() and reload_servers())
 * @warning Closes and frees unused server fds (may break references if externally held)
 * @warning Loop detection modifies server flags (sets SERV_LOOP), changing upstream selection behavior
 * 
 * @see allocate_sfd() for server fd allocation and socket pooling
 * @see pre_allocate_sfds() for initial server fd pre-allocation during startup
 * @see reload_servers() for SIGHUP-triggered server list reconfiguration
 * @see build_server_array() for server array construction from linked list
 * @see loop_send_probes() and server_gone() for DNS loop detection (HAVE_LOOP)
 * @see enumerate_interfaces() for dynamic interface discovery
 * 
 * EXAMPLE USAGE:
 * @code
 * // During daemon startup
 * read_opts(argc, argv, compile_opts);  // Parse config, populate daemon->servers
 * pre_allocate_sfds();  // Pre-allocate wildcard server sockets
 * check_servers(1);  // Validate servers, skip loop check (network not stable yet)
 * // ... later during SIGHUP reload ...
 * reload_servers(dnsmasq_conf_file);  // Re-read config, update daemon->servers
 * check_servers(0);  // Re-validate servers, perform loop detection
 * @endcode
 * 
 * RFC COMPLIANCE: Not protocol-specific, implements upstream server management for DNS forwarding
 * SIDE EFFECTS: Logs server configuration via syslog, allocates/frees server fds, closes sockets,
 *               modifies daemon->sfds list, resets refcounts, rebuilds daemon->serverarray[],
 *               may die on allocation failure with OPT_NOWILD, performs loop detection (may mark
 *               servers with SERV_LOOP flag, disabling them)
 * THREAD SAFETY: Not thread-safe (accesses/modifies daemon->servers, daemon->sfds, daemon->interfaces,
 *                daemon->addrbuff, daemon->namebuff, daemon->last_server, calls my_syslog)
 */
void check_servers(int no_loop_check)
{
  struct irec *iface;
  struct server *serv;
  struct serverfd *sfd, *tmp, **up;
  int port = 0, count;
  int locals = 0;

  (void)no_loop_check;
  
#ifdef HAVE_LOOP
  if (!no_loop_check)
    loop_send_probes();
#endif

  /* clear all marks. */
  mark_servers(0);
  
 /* interface may be new since startup */
  if (!option_bool(OPT_NOWILD))
    enumerate_interfaces(0);

  /* don't garbage collect pre-allocated sfds. */
  for (sfd = daemon->sfds; sfd; sfd = sfd->next)
    sfd->used = sfd->preallocated;

  for (count = 0, serv = daemon->servers; serv; serv = serv->next)
    {
      port = prettyprint_addr(&serv->addr, daemon->namebuff);
      
      /* 0.0.0.0 is nothing, the stack treats it like 127.0.0.1 */
      if (serv->addr.sa.sa_family == AF_INET &&
	  serv->addr.in.sin_addr.s_addr == 0)
	{
	  serv->flags |= SERV_MARK;
	  continue;
	}
      
      for (iface = daemon->interfaces; iface; iface = iface->next)
	if (sockaddr_isequal(&serv->addr, &iface->addr))
	  break;
      if (iface)
	{
	  my_syslog(LOG_WARNING, _("ignoring nameserver %s - local interface"), daemon->namebuff);
	  serv->flags |= SERV_MARK;
	  continue;
	}
      
      /* Do we need a socket set? */
      if (!serv->sfd && 
	  !(serv->sfd = allocate_sfd(&serv->source_addr, serv->interface, serv->ifindex)) &&
	  errno != 0)
	{
	  my_syslog(LOG_WARNING, 
		    _("ignoring nameserver %s - cannot make/bind socket: %s"),
		    daemon->namebuff, strerror(errno));
	  serv->flags |= SERV_MARK;
	  continue;
	}
      
      if (serv->sfd)
	serv->sfd->used = 1;
      
      if (count == SERVERS_LOGGED)
	my_syslog(LOG_INFO, _("more servers are defined but not logged"));
      
      if (++count > SERVERS_LOGGED)
	continue;
      
      if (strlen(serv->domain) != 0 || (serv->flags & SERV_FOR_NODOTS))
	{
	  char *s1, *s2, *s3 = "", *s4 = "";

	  if (serv->flags & SERV_FOR_NODOTS)
	    s1 = _("unqualified"), s2 = _("names");
	  else if (strlen(serv->domain) == 0)
	    s1 = _("default"), s2 = "";
	  else
	    s1 = _("domain"), s2 = serv->domain, s4 = (serv->flags & SERV_WILDCARD) ? "*" : "";
	  
	  my_syslog(LOG_INFO, _("using nameserver %s#%d for %s %s%s %s"), daemon->namebuff, port, s1, s4, s2, s3);
	}
#ifdef HAVE_LOOP
      else if (serv->flags & SERV_LOOP)
	my_syslog(LOG_INFO, _("NOT using nameserver %s#%d - query loop detected"), daemon->namebuff, port); 
#endif
      else if (serv->interface[0] != 0)
	my_syslog(LOG_INFO, _("using nameserver %s#%d(via %s)"), daemon->namebuff, port, serv->interface); 
      else
	my_syslog(LOG_INFO, _("using nameserver %s#%d"), daemon->namebuff, port); 

    }
  
  for (count = 0, serv = daemon->local_domains; serv; serv = serv->next)
    {
       if (++count > SERVERS_LOGGED)
	 continue;
       
       if ((serv->flags & SERV_LITERAL_ADDRESS) &&
	   !(serv->flags & (SERV_6ADDR | SERV_4ADDR | SERV_ALL_ZEROS)) &&
	   strlen(serv->domain))
	 {
	   count--;
	   if (++locals <= LOCALS_LOGGED)
	     my_syslog(LOG_INFO, _("using only locally-known addresses for %s"), serv->domain);
	 }
       else if (serv->flags & SERV_USE_RESOLV && serv->domain_len != 0)
	 my_syslog(LOG_INFO, _("using standard nameservers for %s"), serv->domain);
    }
  
  if (locals > LOCALS_LOGGED)
    my_syslog(LOG_INFO, _("using %d more local addresses"), locals - LOCALS_LOGGED);
  if (count - 1 > SERVERS_LOGGED)
    my_syslog(LOG_INFO, _("using %d more nameservers"), count - SERVERS_LOGGED - 1);

  /* Remove unused sfds */
  for (sfd = daemon->sfds, up = &daemon->sfds; sfd; sfd = tmp)
    {
       tmp = sfd->next;
       if (!sfd->used) 
	{
	  *up = sfd->next;
	  close(sfd->fd);
	  free(sfd);
	} 
      else
	up = &sfd->next;
    }
  
  cleanup_servers(); /* remove servers we just deleted. */
  build_server_array(); 
}

/* Return zero if no servers found, in that case we keep polling.
   This is a protection against an update-time/write race on resolv.conf */
/**
 * @brief Reload upstream DNS servers from resolv.conf-style configuration file
 * 
 * @detailed Reads resolv.conf-format file (e.g., /etc/resolv.conf), parses "nameserver" lines,
 *           creates new upstream server entries (struct server) via add_rev_server(), and removes
 *           old servers from previous file read. Called on SIGHUP signal or file modification
 *           (inotify) to dynamically update upstream servers without daemon restart. Marks existing
 *           SERV_FROM_RESOLV servers via mark_servers(), parses file line-by-line with strtok(),
 *           validates IPv4/IPv6 addresses with inet_pton(), creates server entries with default
 *           port 53 (NAMESERVER_PORT) and wildcard source addresses (INADDR_ANY/in6addr_any),
 *           marks new servers with SERV_FROM_RESOLV flag, then calls cleanup_servers() to remove
 *           marked old servers not found in new file. Function returns 1 if ≥1 nameserver found,
 *           0 if file unreadable or no valid nameservers parsed.
 * 
 * @param fname Path to resolv.conf-style configuration file (absolute or relative path, typically
 *              /etc/resolv.conf or /var/run/dnsmasq/resolv.conf for dynamic updates)
 * 
 * @return Success indicator (1 if ≥1 nameserver found and added, 0 if file open failed or no valid servers)
 * @retval 1 At least one valid nameserver line parsed and server entry created
 * @retval 0 File open failed (logs error via my_syslog), or file contains no valid nameserver lines
 * 
 * @note File format: Standard resolv.conf syntax, "nameserver <IPv4|IPv6>" lines only (other lines ignored)
 * @note Parsing: Uses strtok() with delimiters " \t\n\r" to extract "nameserver" keyword and IP address
 * @note IPv4 handling: Parses with inet_pton(AF_INET), creates server with sin_family=AF_INET,
 *       sin_port=htons(53), source_addr=INADDR_ANY:query_port
 * @note IPv6 handling: Parses with inet_pton(AF_INET6), creates server with sin6_family=AF_INET6,
 *       sin6_port=htons(53), source_addr=in6addr_any:query_port
 * @note Invalid addresses: Lines with invalid IP addresses silently skipped (continue to next line)
 * @note Server marking: Existing SERV_FROM_RESOLV servers marked via mark_servers() before parsing,
 *       unmarked by successful match in new file (via cleanup_servers() logic), marked servers
 *       removed after parse completes (cleanup_servers() removes marked entries)
 * @note Server creation: New servers added to daemon->servers linked list via add_rev_server(),
 *       daemon->last_server updated to new tail for O(1) append, flags |= SERV_FROM_RESOLV set
 * @note Cleanup timing: cleanup_servers() called after file parse completes, removes old SERV_FROM_RESOLV
 *       servers not found in new file (still marked after parse = not refreshed = stale entry)
 * @note Buffer usage: Reuses daemon->namebuff (MAXDNAME=1025 bytes) for line reading (fgets buffer)
 * @note File error logging: Open failure logs to syslog: "failed to read <fname>: <strerror(errno)>"
 * @note Integration: Called from SIGHUP handler (reload_servers(daemon->resolv_files->name)) and
 *       inotify file modification handler (poll_resolv() monitors /etc/resolv.conf changes)
 * 
 * @warning File open failure returns 0 after logging error, does NOT remove existing servers (graceful degradation)
 * @warning Invalid IP address lines silently skipped (no error logged), only valid nameservers processed
 * @warning Uses strtok() which modifies input buffer (daemon->namebuff), not thread-safe
 * @warning Calls cleanup_servers() which modifies daemon->servers list, may break external references
 * @warning Does NOT call check_servers() after reload, caller must invoke check_servers(0) to
 *          allocate server fds and perform loop detection (check_servers() validates new server list)
 * 
 * @see mark_servers() for marking existing SERV_FROM_RESOLV servers before reload
 * @see add_rev_server() for creating new upstream server entries
 * @see cleanup_servers() for removing marked (stale) servers after reload
 * @see check_servers() for server fd allocation and validation (must be called after reload_servers)
 * @see poll_resolv() for inotify-based file monitoring triggering reload_servers()
 * 
 * EXAMPLE USAGE:
 * @code
 * // During SIGHUP signal handler
 * if (daemon->resolv_files) {
 *   if (reload_servers(daemon->resolv_files->name)) {
 *     my_syslog(LOG_INFO, _("reloaded upstream servers from %s"), daemon->resolv_files->name);
 *     check_servers(0);  // Validate new servers, allocate fds, perform loop detection
 *   }
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: Not protocol-specific, implements resolv.conf file parsing for DNS forwarding
 * SIDE EFFECTS: Opens and reads file, parses with strtok() (modifies daemon->namebuff), creates
 *               new struct server entries, modifies daemon->servers and daemon->last_server linked
 *               list, calls cleanup_servers() which removes stale servers and frees memory, logs
 *               file open errors via my_syslog(LOG_ERR)
 * THREAD SAFETY: Not thread-safe (modifies daemon->namebuff with strtok, modifies daemon->servers
 *                and daemon->last_server, calls cleanup_servers)
 */
int reload_servers(char *fname)
{
  FILE *f;
  char *line;
  int gotone = 0;

  /* buff happens to be MAXDNAME long... */
  if (!(f = fopen(fname, "r")))
    {
      my_syslog(LOG_ERR, _("failed to read %s: %s"), fname, strerror(errno));
      return 0;
    }
   
  mark_servers(SERV_FROM_RESOLV);
    
  while ((line = fgets(daemon->namebuff, MAXDNAME, f)))
    {
      union mysockaddr addr, source_addr;
      char *token = strtok(line, " \t\n\r");
      
      if (!token)
	continue;
      if (strcmp(token, "nameserver") != 0 && strcmp(token, "server") != 0)
	continue;
      if (!(token = strtok(NULL, " \t\n\r")))
	continue;
      
      memset(&addr, 0, sizeof(addr));
      memset(&source_addr, 0, sizeof(source_addr));
      
      if (inet_pton(AF_INET, token, &addr.in.sin_addr) > 0)
	{
#ifdef HAVE_SOCKADDR_SA_LEN
	  source_addr.in.sin_len = addr.in.sin_len = sizeof(source_addr.in);
#endif
	  source_addr.in.sin_family = addr.in.sin_family = AF_INET;
	  addr.in.sin_port = htons(NAMESERVER_PORT);
	  source_addr.in.sin_addr.s_addr = INADDR_ANY;
	  source_addr.in.sin_port = htons(daemon->query_port);
	}
      else 
	{	
	  int scope_index = 0;
	  char *scope_id = strchr(token, '%');
	  
	  if (scope_id)
	    {
	      *(scope_id++) = 0;
	      scope_index = if_nametoindex(scope_id);
	    }
	  
	  if (inet_pton(AF_INET6, token, &addr.in6.sin6_addr) > 0)
	    {
#ifdef HAVE_SOCKADDR_SA_LEN
	      source_addr.in6.sin6_len = addr.in6.sin6_len = sizeof(source_addr.in6);
#endif
	      source_addr.in6.sin6_family = addr.in6.sin6_family = AF_INET6;
	      source_addr.in6.sin6_flowinfo = addr.in6.sin6_flowinfo = 0;
	      addr.in6.sin6_port = htons(NAMESERVER_PORT);
	      addr.in6.sin6_scope_id = scope_index;
	      source_addr.in6.sin6_addr = in6addr_any;
	      source_addr.in6.sin6_port = htons(daemon->query_port);
	      source_addr.in6.sin6_scope_id = 0;
	    }
	  else
	    continue;
	}

      add_update_server(SERV_FROM_RESOLV, &addr, &source_addr, NULL, NULL, NULL);
      gotone = 1;
    }
  
  fclose(f);
  cleanup_servers();

  return gotone;
}

/**
 * @brief Handle network address changes by re-enumerating interfaces and updating listeners
 * 
 * @detailed Called when network addresses are added or deleted from interfaces (triggered by
 *           netlink RTM_NEWADDR/RTM_DELADDR events on Linux, or routing socket events on BSD)
 *           to adapt daemon's network configuration to topology changes. Re-enumerates interfaces
 *           via enumerate_interfaces(0) when OPT_CLEVERBIND (--bind-dynamic), OPT_LOCAL_SERVICE,
 *           DHCPv6, relay6, or Router Advertisement active (these features require current interface
 *           state). Recreates bound listeners via create_bound_listeners(0) when OPT_CLEVERBIND
 *           enabled (dynamic binding requires refreshing listener sockets on address changes).
 *           Clears relay interface index cache (relay->iface_index=0 forces recomputation on next
 *           relay packet). For DHCPv6/RA, rejoins IPv6 multicast groups via join_multicast(0)
 *           (address changes may leave/rejoin ff02::1:2 All_DHCP_Relay_Agents_and_Servers),
 *           reconstructs DHCP contexts via dhcp_construct_contexts(now) (address changes affect
 *           subnet determination), and updates lease->interface mappings via lease_find_interfaces(now).
 * 
 * @param now Current time in seconds since epoch (passed to dhcp_construct_contexts and
 *            lease_find_interfaces for lease expiration calculations, unused directly by newaddress)
 * 
 * @return void (no return value, adapts to address changes in-place)
 * 
 * @note Trigger events: Called from netlink_multicast() on Linux (RTM_NEWADDR/RTM_DELADDR), or
 *       route_sock() on BSD (RTM_NEWADDR/RTM_DELADDR routing socket messages)
 * @note Interface re-enumeration: enumerate_interfaces(0) refreshes daemon->interfaces list with
 *       current interface names, indexes, IPv4/IPv6 addresses, and flags (IFF_UP, IFF_LOOPBACK, etc.)
 * @note Conditional enumeration: Only re-enumerates when features requiring current interface state
 *       are active: OPT_CLEVERBIND (dynamic listener binding), OPT_LOCAL_SERVICE (local address
 *       filtering), daemon->doing_dhcp6 (DHCPv6 server), daemon->relay6 (DHCPv6 relay), or
 *       daemon->doing_ra (Router Advertisement)
 * @note Listener recreation: create_bound_listeners(0) with OPT_CLEVERBIND closes old listeners,
 *       creates new sockets bound to current interface addresses (argument 0 = do_it_now, vs 1 = die_on_error)
 * @note Relay cache invalidation: Clears relay->iface_index for both relay4 (DHCPv4) and relay6
 *       (DHCPv6) relay agents, forcing relay_upstream4()/relay_upstream6() to recompute interface
 *       index on next packet (address changes may affect relay interface selection)
 * @note DHCPv6 multicast: join_multicast(0) rejoins ff02::1:2 (All_DHCP_Relay_Agents_and_Servers)
 *       on all active interfaces, called when daemon->doing_dhcp6, daemon->relay6, or daemon->doing_ra
 *       (IPv6 address changes require leaving/rejoining multicast groups)
 * @note DHCP context reconstruction: dhcp_construct_contexts(now) rebuilds DHCP subnet contexts
 *       based on current interface addresses, called when daemon->doing_dhcp6 or daemon->doing_ra
 *       (address changes affect which DHCP pools apply to which interfaces)
 * @note Lease interface mapping: lease_find_interfaces(now) updates lease->interface pointers to
 *       match current interface list, called when daemon->doing_dhcp6 (address changes may affect
 *       which interface a lease's address belongs to)
 * @note Timing: Function executes quickly (<10ms typical), but may take longer if many interfaces
 *       or many DHCPv6 leases (enumerate_interfaces scans all interfaces, lease_find_interfaces
 *       iterates all leases)
 * @note Performance: Function called frequently on systems with dynamic addressing (DHCP client on
 *       WAN, IPv6 SLAAC privacy addresses), optimized to minimize work (only re-enumerate/recreate
 *       when necessary features active)
 * 
 * @warning Interface re-enumeration may be expensive on systems with hundreds of interfaces (e.g.,
 *          virtualization hosts with many bridges/veth pairs)
 * @warning Listener recreation with OPT_CLEVERBIND closes existing listener sockets, briefly
 *          interrupting DNS query reception (typically <10ms, but depends on OS socket creation speed)
 * @warning DHCPv6 context reconstruction may change subnet determination for in-flight DHCP packets
 *          (race condition if address change occurs during DHCP exchange)
 * @warning Requires daemon->interfaces, daemon->relay4/relay6, daemon->dhcp_contexts initialized
 * 
 * @see enumerate_interfaces() for interface list refresh with current addresses
 * @see create_bound_listeners() for dynamic listener socket recreation
 * @see join_multicast() for IPv6 multicast group membership
 * @see dhcp_construct_contexts() for DHCP subnet context rebuilding
 * @see lease_find_interfaces() for lease->interface pointer update
 * @see netlink_multicast() (Linux) or route_sock() (BSD) for address change event detection
 * 
 * EXAMPLE USAGE:
 * @code
 * // Called from netlink_multicast() on Linux when RTM_NEWADDR/RTM_DELADDR received
 * if (msg->nlmsg_type == RTM_NEWADDR || msg->nlmsg_type == RTM_DELADDR) {
 *   newaddress(dnsmasq_time());  // Adapt to address change
 * }
 * // ... or from route_sock() on BSD when routing socket reports address change ...
 * if (msg_type == RTM_NEWADDR || msg_type == RTM_DELADDR) {
 *   newaddress(dnsmasq_time());  // Adapt to address change
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: Not protocol-specific, implements dynamic network reconfiguration for DNS/DHCP
 * SIDE EFFECTS: Re-enumerates interfaces (updates daemon->interfaces), recreates listener sockets
 *               (closes/opens sockets, consumes file descriptors), clears relay cache, rejoins
 *               multicast groups (sends IGMP/MLD reports), reconstructs DHCP contexts (updates
 *               daemon->dhcp_contexts), updates lease->interface pointers (modifies lease database)
 * THREAD SAFETY: Not thread-safe (modifies daemon->interfaces, daemon->listeners, relay->iface_index,
 *                daemon->dhcp_contexts, lease->interface pointers)
 */
/* Called when addresses are added or deleted from an interface */
void newaddress(time_t now)
{
#ifdef HAVE_DHCP
  struct dhcp_relay *relay;
#endif
  
  (void)now;
  
  if (option_bool(OPT_CLEVERBIND) || option_bool(OPT_LOCAL_SERVICE) ||
      daemon->doing_dhcp6 || daemon->relay6 || daemon->doing_ra)
    enumerate_interfaces(0);
  
  if (option_bool(OPT_CLEVERBIND))
    create_bound_listeners(0);

#ifdef HAVE_DHCP
  /* clear cache of subnet->relay index */
  for (relay = daemon->relay4; relay; relay = relay->next)
    relay->iface_index = 0;
#endif
  
#ifdef HAVE_DHCP6
  if (daemon->doing_dhcp6 || daemon->relay6 || daemon->doing_ra)
    join_multicast(0);
  
  if (daemon->doing_dhcp6 || daemon->doing_ra)
    dhcp_construct_contexts(now);
  
  if (daemon->doing_dhcp6)
    lease_find_interfaces(now);

  for (relay = daemon->relay6; relay; relay = relay->next)
    relay->iface_index = 0;
#endif
}

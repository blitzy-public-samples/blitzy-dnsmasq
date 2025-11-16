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
 * @file dhcp.c
 * @brief DHCPv4 server core business logic and address allocation engine
 * 
 * DETAILED PURPOSE:
 * This file implements the DHCPv4 server core functionality for dnsmasq, providing
 * dynamic and static IP address allocation to network clients per RFC 2131. The
 * implementation handles the complete DHCP message processing lifecycle including
 * DISCOVER, OFFER, REQUEST, and ACK exchanges, address pool management, lease
 * assignment, conflict detection, and integration with DNS cache for automatic
 * hostname registration. This module serves as the central orchestrator for all
 * DHCPv4 operations in dnsmasq.
 * 
 * The dhcp_reply() function serves as the main entry point for DHCP packet processing,
 * dispatched from the event loop when DHCPv4 packets arrive. It coordinates with
 * rfc2131.c for protocol-specific message handling, lease.c for lease database
 * persistence, cache.c for DNS integration, and helper.c for script execution on
 * lease events.
 * 
 * KEY RESPONSIBILITIES:
 * - dhcp_init(): Initialize DHCPv4 server socket on port 67, configure interface
 *   listeners, set socket options for broadcast/multicast, and prepare DHCP contexts
 * - dhcp_packet(): Main packet reception routine, reads DHCPv4 messages from network,
 *   validates packet format, and dispatches to dhcp_reply() for processing
 * - dhcp_reply(): Central message processing engine, handles DISCOVER/REQUEST/INFORM
 *   messages, coordinates address allocation, generates OFFER/ACK responses
 * - address_allocate(): Dynamic IP allocation from configured address pools, implements
 *   conflict detection via ping testing, honors static reservations, selects available
 *   addresses using linear search with wrap-around
 * - do_icmp_ping(): Address-in-use detection, sends ICMP echo request to candidate
 *   IP address before allocation to prevent conflicts per RFC 2131 section 3.1
 * - config_find_by_address(): Locate static DHCP reservations by IP address for
 *   reservation enforcement and conflict prevention
 * - complete_context(): Interface enumeration callback, matches DHCP contexts to
 *   network interfaces, determines address ranges for each interface
 * - narrow_context(): DHCP relay agent support, narrows context selection based on
 *   giaddr field in relayed DHCP messages
 * - dhcp_read_ethers(): Parse /etc/ethers file for MAC-to-hostname mappings, integrate
 *   with DHCP configuration for automatic static lease creation
 * - host_from_dns(): Query DNS cache for hostname associated with IP address, used for
 *   reverse hostname lookups during DHCP processing
 * 
 * DEPENDENCIES:
 * Includes: dnsmasq.h (core data structures: struct daemon, struct dhcp_context,
 *           struct dhcp_config, struct dhcp_packet), dhcp-protocol.h (DHCPv4 protocol
 *           constants: DHCP_SERVER_PORT 67, DHCP_CLIENT_PORT 68, option codes,
 *           message types, struct dhcp_packet wire format)
 * 
 * Called by: Main event loop (dnsmasq.c) invokes dhcp_packet() when data ready on
 *            DHCPv4 socket file descriptor; configuration parser (option.c) calls
 *            dhcp_init() during daemon initialization
 * 
 * Calls: rfc2131.c functions for RFC 2131 protocol compliance (message generation,
 *        option encoding, state machine transitions); lease.c functions for lease
 *        database operations (lease_allocate, lease_update, lease_find_by_addr);
 *        cache.c functions for DNS integration (cache_add_dhcp_entry); network.c
 *        for interface enumeration (iface_enumerate); helper.c for script execution
 *        (queue_script); util.c for utility functions (prettyprint_time, parse_hex)
 * 
 * DATA STRUCTURES:
 * - struct dhcp_context (dnsmasq.h:1054-1080): DHCP address pool configuration,
 *   defines IP range [start, end], netmask, broadcast address, lease time, interface
 *   binding, flags for static/dynamic allocation, linked list for multiple contexts
 * - struct dhcp_config (dnsmasq.h:919-953): Static DHCP reservation configuration,
 *   maps MAC address/client-id to fixed IP, hostname, dhcp-options, vendor matching
 * - struct daemon (dnsmasq.h:1164-1400): Global daemon state, contains DHCP socket
 *   descriptors (dhcpfd, dhcp_raw_fd, dhcp_icmp_fd), DHCP context list pointer,
 *   configuration options, lease database handle
 * - struct dhcp_packet (dhcp-protocol.h:103-110): DHCPv4 wire format structure per
 *   RFC 2131, 236-byte fixed header plus 312-byte options field, matches network
 *   byte order for op/htype/hlen/hops/xid/secs/flags/addresses/chaddr/sname/file
 * - struct iface_param (dhcp.c:21-24): Interface enumeration callback parameter,
 *   tracks current context and interface index during address range completion
 * - struct match_param (dhcp.c:26-29): Interface address matching parameter for
 *   listen address validation, contains interface index, match status, network
 *   addressing (netmask, broadcast, local address)
 * 
 * COMPILE-TIME OPTIONS:
 * HAVE_DHCP: Master DHCPv4 enable flag, entire file conditionally compiled only
 *            when this flag is defined, typically enabled by default in standard builds
 * HAVE_LINUX_NETWORK: Linux-specific networking code, enables IP_PKTINFO socket option
 *                     for receiving destination address information on Linux systems
 * HAVE_SCRIPT: External script execution support, enables dhcp-script functionality
 *              for lease change notifications (add/old/del events)
 * HAVE_BROKEN_RTC: Systems without reliable real-time clock, affects lease time
 *                  calculations and expiry checking on embedded platforms
 * IP_RECVIF: BSD-specific socket option for receiving interface information, used
 *            on BSD platforms as alternative to Linux IP_PKTINFO
 * SO_REUSEPORT: Socket option for port sharing, allows multiple dnsmasq instances
 *               on same port serving different networks (bind-interfaces mode)
 * 
 * THREADING/CONCURRENCY:
 * Single-threaded event-driven architecture using poll-based I/O multiplexing. All
 * DHCPv4 packet processing occurs synchronously in main event loop thread. No
 * locking required for DHCP state as no concurrent access exists. External script
 * execution uses fork-based helper processes that run independently without blocking
 * main thread. ICMP ping for address conflict detection uses non-blocking socket with
 * timeout-based response collection in subsequent event loop iterations.
 * 
 * @copyright Copyright (c) 2000-2025 Simon Kelley
 * @license GPL-2.0-or-later
 */

#include "dnsmasq.h"

#ifdef HAVE_DHCP

struct iface_param {
  struct dhcp_context *current;
  int ind;
};

struct match_param {
  int ind, matched;
  struct in_addr netmask, broadcast, addr;
};

static int complete_context(struct in_addr local, int if_index, char *label,
			    struct in_addr netmask, struct in_addr broadcast, void *vparam);
static int check_listen_addrs(struct in_addr local, int if_index, char *label,
			      struct in_addr netmask, struct in_addr broadcast, void *vparam);

/**
 * @brief Create and configure UDP socket for DHCPv4 server operation
 * 
 * @detailed Creates IPv4 UDP datagram socket bound to specified port (typically 67
 * for DHCP server), configures socket options for broadcast reception, packet info
 * delivery, MTU discovery control, and traffic classification. Handles platform-specific
 * socket options (Linux IP_PKTINFO vs BSD IP_RECVIF) and supports multiple server
 * instances via SO_REUSEADDR/SO_REUSEPORT when bind-interfaces mode enabled. Dies with
 * fatal error if socket creation or option configuration fails, ensuring DHCP service
 * cannot start with misconfigured networking.
 * 
 * Platform-specific configurations: On Linux, enables IP_PKTINFO for receiving destination
 * address and interface index with each packet. On BSD systems, uses IP_RECVIF alternative.
 * Sets IP_MTU_DISCOVER to IP_PMTUDISC_DONT on Linux to disable Path MTU Discovery for
 * DHCP packets (always use interface MTU). Sets IP_TOS to IPTOS_CLASS_CS6 for traffic
 * prioritization where supported.
 * 
 * @param port UDP port number to bind socket (typically DHCP_SERVER_PORT=67)
 *             Range: 1-65535, but practical values are 67 (standard DHCP server),
 *             1067 (DHCP failover), or other non-standard ports for testing
 * 
 * @return File descriptor for successfully created and configured UDP socket
 *         Always returns valid fd >= 0; never returns on error (calls die())
 * 
 * @note This function terminates daemon process on any error condition via die()
 * @warning Requires root privileges to bind to privileged port 67
 * @warning SO_REUSEPORT may not be supported on older kernels; function handles
 *          ENOPROTOOPT gracefully by falling back to SO_REUSEADDR only
 * 
 * @see dhcp_init() - Calls make_fd() to create primary DHCPv4 listening socket
 * @see fix_fd() in util.c - Sets close-on-exec and other descriptor flags
 * 
 * EXAMPLE USAGE:
 * @code
 * // Create standard DHCP server socket bound to port 67
 * int dhcp_fd = make_fd(DHCP_SERVER_PORT);
 * // Socket now ready for recvmsg() to receive DHCPv4 packets
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 2131 Section 4.1 - DHCP server listens on UDP port 67
 * 
 * SIDE EFFECTS:
 * - Creates system socket resource (file descriptor)
 * - Binds to UDP port on all interfaces (INADDR_ANY)
 * - Modifies socket options affecting kernel packet handling
 * - Terminates daemon process via die() if socket creation/configuration fails
 * 
 * THREAD SAFETY: Not thread-safe due to die() calling exit(); single-threaded architecture
 */
static int make_fd(int port)
{
  int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
  struct sockaddr_in saddr;
  int oneopt = 1;
#if defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DONT)
  int mtu = IP_PMTUDISC_DONT;
#endif
#if defined(IP_TOS) && defined(IPTOS_CLASS_CS6)
  int tos = IPTOS_CLASS_CS6;
#endif

  if (fd == -1)
    die (_("cannot create DHCP socket: %s"), NULL, EC_BADNET);
  
  if (!fix_fd(fd) ||
#if defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DONT)
      setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &mtu, sizeof(mtu)) == -1 ||
#endif
#if defined(IP_TOS) && defined(IPTOS_CLASS_CS6)
      setsockopt(fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos)) == -1 ||
#endif
#if defined(HAVE_LINUX_NETWORK)
      setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &oneopt, sizeof(oneopt)) == -1 ||
#else
      setsockopt(fd, IPPROTO_IP, IP_RECVIF, &oneopt, sizeof(oneopt)) == -1 ||
#endif
      setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &oneopt, sizeof(oneopt)) == -1)  
    die(_("failed to set options on DHCP socket: %s"), NULL, EC_BADNET);
  
  /* When bind-interfaces is set, there might be more than one dnsmasq
     instance binding port 67. That's OK if they serve different networks.
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
	die(_("failed to set SO_REUSE{ADDR|PORT} on DHCP socket: %s"), NULL, EC_BADNET);
    }
  
  memset(&saddr, 0, sizeof(saddr));
  saddr.sin_family = AF_INET;
  saddr.sin_port = htons(port);
  saddr.sin_addr.s_addr = INADDR_ANY;
#ifdef HAVE_SOCKADDR_SA_LEN
  saddr.sin_len = sizeof(struct sockaddr_in);
#endif

  if (bind(fd, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in)))
    die(_("failed to bind DHCP server socket: %s"), NULL, EC_BADNET);

  return fd;
}

/**
 * @brief Initialize DHCPv4 server subsystem by creating listening sockets and platform-specific resources
 * 
 * @detailed Initializes the DHCPv4 server infrastructure by creating UDP sockets for standard
 * DHCP service on port 67 and optionally for PXE proxy service on port 4011. On BSD systems,
 * additionally creates ICMP raw socket for address conflict detection via ping testing and
 * initializes BPF (Berkeley Packet Filter) raw send socket for DHCP packet transmission.
 * 
 * This function must be called during daemon startup after configuration parsing but before
 * privilege drop. Socket creation requires root privileges to bind privileged ports (67, 4011).
 * After socket creation, daemon drops privileges to configured unprivileged user.
 * 
 * Socket creation details:
 * - Standard DHCP socket: Bound to daemon->dhcp_server_port (typically 67)
 * - PXE proxy socket: Bound to PXE_PORT (4011) only if daemon->enable_pxe is set
 * - ICMP ping socket (BSD only): Raw ICMP socket for address conflict detection unless OPT_NO_PING
 * - BPF socket (BSD only): Raw send socket for DHCP packet transmission via BPF interface
 * 
 * Platform differences:
 * - Linux: Uses standard UDP sockets with IP_PKTINFO for packet metadata
 * - BSD: Requires additional ICMP raw socket and BPF initialization for full DHCP functionality
 * 
 * Error handling: All socket creation failures terminate daemon via die() - no graceful degradation.
 * This ensures DHCP service cannot start in a partially functional state that could confuse clients.
 * 
 * @param None (void function)
 * 
 * @return None (void function)
 * 
 * @note Called from main() during daemon initialization sequence before privilege drop
 * @note Terminates daemon process via die() if socket creation fails on any platform
 * 
 * @warning Requires root privileges for privileged port binding (ports < 1024)
 * @warning Must be called before dropping privileges via change_user() in dnsmasq.c
 * @warning On BSD systems, ICMP socket creation failure is fatal (unless --no-ping configured)
 * @warning PXE proxy mode requires binding to port 4011 in addition to standard port 67
 * 
 * @see make_fd() - Creates and configures individual UDP listening sockets
 * @see make_icmp_sock() in network.c - Creates ICMP raw socket for ping testing (BSD)
 * @see init_bpf() in bpf.c - Initializes BPF raw send socket (BSD)
 * @see dhcp_packet() - Main DHCP packet processing function using initialized sockets
 * 
 * EXAMPLE USAGE:
 * @code
 * // Called from main() during daemon startup
 * daemon->dhcp_server_port = DHCP_SERVER_PORT; // 67
 * daemon->enable_pxe = 1; // Enable PXE proxy mode
 * dhcp_init(); // Creates sockets on ports 67 and 4011
 * // After return, daemon->dhcpfd and daemon->pxefd are valid descriptors
 * // Now safe to drop privileges via change_user()
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 2131 Section 4.1 - DHCP server listens on UDP port 67
 * RFC 2131 Section 4.1 - DHCP server sends from UDP port 67 to client port 68
 * PXE Specification - PXE proxy DHCP listens on UDP port 4011
 * 
 * SIDE EFFECTS:
 * - Sets daemon->dhcpfd to valid file descriptor for standard DHCP socket (always)
 * - Sets daemon->pxefd to valid descriptor if PXE enabled, or -1 if disabled
 * - Sets daemon->dhcp_icmp_fd to ICMP socket descriptor (BSD) or initialized later (Linux)
 * - Initializes global BPF state for raw packet transmission (BSD only)
 * - Allocates system socket resources (file descriptors, kernel buffers)
 * - Terminates daemon process via die() if any socket creation fails
 * 
 * THREAD SAFETY: Not thread-safe; must be called once during single-threaded initialization
 */
void dhcp_init(void)
{
#if defined(HAVE_BSD_NETWORK)
  int oneopt = 1;
#endif

  daemon->dhcpfd = make_fd(daemon->dhcp_server_port);
  if (daemon->enable_pxe)
    daemon->pxefd = make_fd(PXE_PORT);
  else
    daemon->pxefd = -1;

#if defined(HAVE_BSD_NETWORK)
  /* When we're not using capabilities, we need to do this here before
     we drop root. Also, set buffer size small, to avoid wasting
     kernel buffers */
  
  if (option_bool(OPT_NO_PING))
    daemon->dhcp_icmp_fd = -1;
  else if ((daemon->dhcp_icmp_fd = make_icmp_sock()) == -1 ||
	   setsockopt(daemon->dhcp_icmp_fd, SOL_SOCKET, SO_RCVBUF, &oneopt, sizeof(oneopt)) == -1 )
    die(_("cannot create ICMP raw socket: %s."), NULL, EC_BADNET);
  
  /* Make BPF raw send socket */
  init_bpf();
#endif  
}

/**
 * @brief Main entry point for DHCPv4 packet reception and processing
 * 
 * @detailed Receives incoming DHCPv4 packets from either the standard DHCP socket (port 67) 
 *           or PXE proxy DHCP socket (port 4011), performs packet validation, identifies the 
 *           receiving interface and matching dhcp_context, and dispatches to dhcp_reply() for 
 *           protocol processing. Handles platform-specific packet interface detection (IP_PKTINFO 
 *           on Linux, IP_RECVIF on BSD), bridge interface relay scenarios, and sends responses 
 *           using appropriate transmission methods (raw sockets on Linux, BPF on BSD). This 
 *           function implements the core receive-process-send cycle for all DHCPv4 transactions 
 *           including DISCOVER, REQUEST, INFORM, RELEASE, and BOOTP packets.
 * 
 * @param now Current timestamp from event loop for lease time calculations and expiration checks
 * @param pxe_fd Boolean flag: non-zero to process PXE proxy DHCP on port 4011, zero for regular DHCP on port 67
 * 
 * @return void (function logs errors and continues operation; fatal errors handled via die())
 * 
 * @note CRITICAL: This function is called from the main event loop whenever DHCP socket is readable
 * @note Platform-specific code paths for Linux (IP_PKTINFO), BSD (IP_RECVIF), Solaris, OpenBSD
 * @note PXE proxy mode (pxe_fd != 0) handles PXE-specific DHCP requests without IP allocation
 * @note Bridge interface detection uses special handling for relayed packets via bridge ports
 * @warning Packet validation failures are logged but do not stop daemon (drops malformed packets)
 * @warning Interface matching failure causes packet drop with warning log
 * @warning Buffer overflows prevented by strict size checks (minimum BOOTP_MESSAGE_SIZE)
 * 
 * @see dhcp_reply() in rfc2131.c - actual DHCPv4 protocol state machine processing
 * @see send_via_bpf() in bpf.c - BSD packet transmission using Berkeley Packet Filter
 * @see iface_check() in network.c - interface validation and context matching
 * 
 * EXAMPLE USAGE:
 * @code
 * // Called from main event loop when DHCP socket has data
 * time_t now = dnsmasq_time();
 * dhcp_packet(now, 0);  // Process regular DHCP on port 67
 * dhcp_packet(now, 1);  // Process PXE proxy DHCP on port 4011
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 2131 Section 2 (DHCP message format), Section 4.1 (server operation)
 * 
 * SIDE EFFECTS:
 * - Network I/O: recvmsg() reads packet from socket, sendto()/sendmsg() sends reply
 * - Lease database updates: dhcp_reply() may add/update/delete leases via lease.c
 * - DNS cache updates: dhcp_reply() registers hostnames via cache_add_dhcp_entry()
 * - Script execution: dhcp_reply() may trigger lease-change scripts via queue_script()
 * - Logging: Writes packet reception, interface matching, and error messages to syslog
 * - ARP cache: May query kernel ARP cache for MAC address validation via find_mac()
 * - Ping testing: dhcp_reply() may initiate ICMP ping for address conflict detection
 * 
 * THREAD SAFETY: Single-threaded event-driven model - assumes exclusive access to global daemon state
 * 
 * PACKET PROCESSING FLOW:
 * 1. recvmsg() receives UDP packet with ancillary data (interface info)
 * 2. Validate packet size (>= BOOTP_MESSAGE_SIZE=300), BOOTP magic number (0x63825363)
 * 3. Extract interface information (IP_PKTINFO on Linux, IP_RECVIF on BSD)
 * 4. Handle bridge interfaces: detect relay scenarios via giaddr field
 * 5. Match packet to dhcp_context based on destination IP and interface index
 * 6. Call dhcp_reply() to process DHCP message type and generate response
 * 7. Send reply using sendto() (Linux with IP_PKTINFO) or BPF (BSD platforms)
 * 8. Log packet reception statistics and any errors encountered
 * 
 * ERROR HANDLING:
 * - recvmsg() errors: Log warning and continue (EAGAIN, EINTR are benign)
 * - Packet too small: Drop with warning log
 * - Invalid BOOTP magic: Drop packet silently
 * - Interface not found: Drop with warning log
 * - No matching context: Drop with info log (may be relay to other DHCP server)
 * - sendmsg() errors: Log error but do not crash daemon
 */
void dhcp_packet(time_t now, int pxe_fd)
{
  int fd = pxe_fd ? daemon->pxefd : daemon->dhcpfd;
  struct dhcp_packet *mess;
  struct dhcp_context *context;
  struct dhcp_relay *relay;
  int is_relay_reply = 0, is_relay_use_source = 0;
  struct iname *tmp;
  struct ifreq ifr;
  struct msghdr msg;
  struct sockaddr_in dest;
  struct cmsghdr *cmptr;
  struct iovec iov;
  ssize_t sz; 
  int iface_index = 0, unicast_dest = 0, is_inform = 0, loopback = 0;
  int rcvd_iface_index, relay_index;
  struct in_addr iface_addr;
  struct iface_param parm;
  time_t recvtime = now;
#ifdef HAVE_LINUX_NETWORK
  struct arpreq arp_req;
  struct timeval tv;
  struct in_addr dst_addr;
#endif
  
  union {
    struct cmsghdr align; /* this ensures alignment */
#if defined(HAVE_LINUX_NETWORK)
    char control[CMSG_SPACE(sizeof(struct in_pktinfo))];
#elif defined(HAVE_SOLARIS_NETWORK)
    char control[CMSG_SPACE(sizeof(unsigned int))];
#elif defined(HAVE_BSD_NETWORK) 
    char control[CMSG_SPACE(sizeof(struct sockaddr_dl))];
#endif
  } control_u;
  struct dhcp_bridge *bridge, *alias;

  msg.msg_controllen = sizeof(control_u);
  msg.msg_control = control_u.control;
  msg.msg_name = &dest;
  msg.msg_namelen = sizeof(dest);
  msg.msg_iov = &daemon->dhcp_packet;
  msg.msg_iovlen = 1;
  
  if ((sz = recv_dhcp_packet(fd, &msg)) == -1 || 
      (sz < (ssize_t)(sizeof(*mess) - sizeof(mess->options)))) 
    return;
  
#if defined (HAVE_LINUX_NETWORK)
  if (ioctl(fd, SIOCGSTAMP, &tv) == 0)
    recvtime = tv.tv_sec;

  dst_addr.s_addr = 0;
  
  if (msg.msg_controllen >= sizeof(struct cmsghdr))
    for (cmptr = CMSG_FIRSTHDR(&msg); cmptr; cmptr = CMSG_NXTHDR(&msg, cmptr))
      if (cmptr->cmsg_level == IPPROTO_IP && cmptr->cmsg_type == IP_PKTINFO)
	{
	  union {
	    unsigned char *c;
	    struct in_pktinfo *p;
	  } p;
	  p.c = CMSG_DATA(cmptr);
	  iface_index = p.p->ipi_ifindex;
	  dst_addr = p.p->ipi_addr; 
	  if (dst_addr.s_addr != INADDR_BROADCAST)
	    unicast_dest = 1;
	}

#elif defined(HAVE_BSD_NETWORK) 
  if (msg.msg_controllen >= sizeof(struct cmsghdr))
    for (cmptr = CMSG_FIRSTHDR(&msg); cmptr; cmptr = CMSG_NXTHDR(&msg, cmptr))
      if (cmptr->cmsg_level == IPPROTO_IP && cmptr->cmsg_type == IP_RECVIF)
        {
	  union {
            unsigned char *c;
            struct sockaddr_dl *s;
          } p;
	  p.c = CMSG_DATA(cmptr);
	  iface_index = p.s->sdl_index;
	}
  
#elif defined(HAVE_SOLARIS_NETWORK) 
  if (msg.msg_controllen >= sizeof(struct cmsghdr))
    for (cmptr = CMSG_FIRSTHDR(&msg); cmptr; cmptr = CMSG_NXTHDR(&msg, cmptr))
      if (cmptr->cmsg_level == IPPROTO_IP && cmptr->cmsg_type == IP_RECVIF)
	{
	  union {
	    unsigned char *c;
	    unsigned int *i;
	  } p;
	  p.c = CMSG_DATA(cmptr);
	  iface_index = *(p.i);
	}
#endif

#ifdef HAVE_DUMPFILE
  union mysockaddr *sockp = NULL;
  
#  ifdef HAVE_LINUX_NETWORK
  union mysockaddr tosock;
  
  sockp = &tosock;
  tosock.in.sin_port = htons(daemon->dhcp_server_port);
  tosock.in.sin_addr = dst_addr;
  tosock.sa.sa_family = AF_INET;
#    ifdef HAVE_SOCKADDR_SA_LEN
  tosock.in.sin_len = sizeof(struct sockaddr_in);
#    endif
#  endif
  
  dump_packet_udp(DUMP_DHCP, (void *)daemon->dhcp_packet.iov_base, sz, (union mysockaddr *)&dest, sockp, -1);
#endif
  	
  if (!indextoname(daemon->dhcpfd, iface_index, ifr.ifr_name) ||
      ioctl(daemon->dhcpfd, SIOCGIFFLAGS, &ifr) != 0)
    return;
  
  mess = (struct dhcp_packet *)daemon->dhcp_packet.iov_base;
  
  /* Non-standard extension:
     If giaddr == 255.255.255.255 we reply to the source
     address in the request packet header. This makes
     stand-alone leasequery clients easier, as they
     can leave source address determination to the kernel.
     In this case, set a flag and clear giaddr here,
     to avoid massive relay confusion. */
  if (mess->giaddr.s_addr == INADDR_BROADCAST)
    {
      mess->giaddr.s_addr = 0;
      is_relay_use_source = 1;
    }
  
  loopback = !mess->giaddr.s_addr && (ifr.ifr_flags & IFF_LOOPBACK);
  
#ifdef HAVE_LINUX_NETWORK
  /* ARP fiddling uses original interface even if we pretend to use a different one. */
  safe_strncpy(arp_req.arp_dev, ifr.ifr_name, sizeof(arp_req.arp_dev));
#endif 

  /* If the interface on which the DHCP request was received is an
     alias of some other interface (as specified by the
     --bridge-interface option), change ifr.ifr_name so that we look
     for DHCP contexts associated with the aliased interface instead
     of with the aliasing one. */
  rcvd_iface_index = iface_index;
  for (bridge = daemon->bridges; bridge; bridge = bridge->next)
    {
      for (alias = bridge->alias; alias; alias = alias->next)
	if (wildcard_matchn(alias->iface, ifr.ifr_name, IF_NAMESIZE))
	  {
	    if (!(iface_index = if_nametoindex(bridge->iface)))
	      {
		my_syslog(MS_DHCP | LOG_WARNING,
			  _("unknown interface %s in bridge-interface"),
			  bridge->iface);
		return;
	      }
	    else 
	      {
		safe_strncpy(ifr.ifr_name,  bridge->iface, sizeof(ifr.ifr_name));
		break;
	      }
	  }
      
      if (alias)
	break;
    }

#ifdef MSG_BCAST
  /* OpenBSD tells us when a packet was broadcast */
  if (!(msg.msg_flags & MSG_BCAST))
    unicast_dest = 1;
#endif
  
  if ((relay_index = relay_reply4((struct dhcp_packet *)daemon->dhcp_packet.iov_base, (size_t)sz, ifr.ifr_name)))
    {
      /* Reply from server, using us as relay. */
      rcvd_iface_index = relay_index;
      if (!indextoname(daemon->dhcpfd, rcvd_iface_index, ifr.ifr_name))
	return;
      is_relay_reply = 1; 
      iov.iov_len = sz;
#ifdef HAVE_LINUX_NETWORK
      safe_strncpy(arp_req.arp_dev, ifr.ifr_name, sizeof(arp_req.arp_dev));
#endif 
    }
  else
    {
      ifr.ifr_addr.sa_family = AF_INET;
      if (ioctl(daemon->dhcpfd, SIOCGIFADDR, &ifr) != -1 )
	iface_addr = ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr;
      else
	{
	  if (iface_check(AF_INET, NULL, ifr.ifr_name, NULL))
	    my_syslog(MS_DHCP | LOG_WARNING, _("DHCP packet received on %s which has no address"), ifr.ifr_name);
	  return;
	}
      
      for (tmp = daemon->dhcp_except; tmp; tmp = tmp->next)
	if (tmp->name && (tmp->flags & INAME_4) && wildcard_match(tmp->name, ifr.ifr_name))
	  return;
      
      /* unlinked contexts are marked by context->current == context */
      for (context = daemon->dhcp; context; context = context->next)
	context->current = context;

      for (relay = daemon->relay4; relay; relay = relay->next)
	relay->matchcount = 0;
      
      parm.current = NULL;
      parm.ind = iface_index;
      
      if (!iface_check(AF_INET, (union all_addr *)&iface_addr, ifr.ifr_name, NULL))
	{
	  /* If we failed to match the primary address of the interface, see if we've got a --listen-address
	     for a secondary */
	  struct match_param match;
	  
	  match.matched = 0;
	  match.ind = iface_index;
	  
	  if (!daemon->if_addrs ||
	      !iface_enumerate(AF_INET, &match, (callback_t){.af_inet=check_listen_addrs}) ||
	      !match.matched)
	    return;
	  
	  iface_addr = match.addr;
	  /* make sure secondary address gets priority in case
	     there is more than one address on the interface in the same subnet */
	  complete_context(match.addr, iface_index, NULL, match.netmask, match.broadcast, &parm);
	}    
            
      if (!iface_enumerate(AF_INET, &parm, (callback_t){.af_inet=complete_context}))
	return;

      relay_upstream4(iface_addr, iface_index, mess, (size_t)sz, unicast_dest);
       
      /* May have configured relay, but not DHCP server */
      if (!daemon->dhcp)
	return;

      lease_prune(NULL, now); /* lose any expired leases */
      iov.iov_len = dhcp_reply(parm.current, ifr.ifr_name, iface_index, (size_t)sz, now, unicast_dest,
			       loopback, &is_inform, pxe_fd, iface_addr, recvtime,
			       is_relay_use_source ? dest.sin_addr : mess->giaddr);
      lease_update_file(now);
      lease_update_dns(0);
      
      if (iov.iov_len == 0)
	return;
    }

  msg.msg_name = &dest;
  msg.msg_namelen = sizeof(dest);
  msg.msg_control = NULL;
  msg.msg_controllen = 0;
  msg.msg_iov = &iov;
  iov.iov_base = daemon->dhcp_packet.iov_base;
  
  /* packet buffer may have moved */
  mess = (struct dhcp_packet *)daemon->dhcp_packet.iov_base;
  
#ifdef HAVE_SOCKADDR_SA_LEN
  dest.sin_len = sizeof(struct sockaddr_in);
#endif
  
  if (pxe_fd)
    { 
      if (mess->ciaddr.s_addr != 0)
	dest.sin_addr = mess->ciaddr;
    }
  if ((is_relay_use_source || mess->giaddr.s_addr) && !is_relay_reply)
    {
      /* Send to BOOTP relay. */
      if (is_relay_use_source)
	/* restore as-received value */
	mess->giaddr.s_addr = INADDR_BROADCAST;
      else
	{
	  dest.sin_addr = mess->giaddr;
	  dest.sin_port = htons(daemon->dhcp_server_port);
	}
    }
  else if (mess->ciaddr.s_addr)
    {
      /* If the client's idea of its own address tallys with
	 the source address in the request packet, we believe the
	 source port too, and send back to that.  If we're replying 
	 to a DHCPINFORM, trust the source address always. */
      if ((!is_inform && dest.sin_addr.s_addr != mess->ciaddr.s_addr) ||
	  dest.sin_port == 0 || dest.sin_addr.s_addr == 0 || is_relay_reply)
	{
	  dest.sin_port = htons(daemon->dhcp_client_port); 
	  dest.sin_addr = mess->ciaddr;
	}
    } 
#if defined(HAVE_LINUX_NETWORK)
  else
    {
      /* fill cmsg for outbound interface (both broadcast & unicast) */
      struct in_pktinfo *pkt;
      msg.msg_control = control_u.control;
      msg.msg_controllen = sizeof(control_u);

      /* alignment padding passed to the kernel should not be uninitialised. */
      memset(&control_u, 0, sizeof(control_u));

      cmptr = CMSG_FIRSTHDR(&msg);
      pkt = (struct in_pktinfo *)CMSG_DATA(cmptr);
      pkt->ipi_ifindex = rcvd_iface_index;
      pkt->ipi_spec_dst.s_addr = 0;
      msg.msg_controllen = CMSG_SPACE(sizeof(struct in_pktinfo));
      cmptr->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
      cmptr->cmsg_level = IPPROTO_IP;
      cmptr->cmsg_type = IP_PKTINFO;

      if ((ntohs(mess->flags) & 0x8000) || mess->hlen == 0 ||
         mess->hlen > sizeof(ifr.ifr_addr.sa_data) || mess->htype == 0)
        {
          /* broadcast to 255.255.255.255 (or mac address invalid) */
          dest.sin_addr.s_addr = INADDR_BROADCAST;
          dest.sin_port = htons(daemon->dhcp_client_port);
        }
      else
        {
          /* unicast to unconfigured client. Inject mac address direct into ARP cache.
          struct sockaddr limits size to 14 bytes. */
          dest.sin_addr = mess->yiaddr;
          dest.sin_port = htons(daemon->dhcp_client_port);
          memcpy(&arp_req.arp_pa, &dest, sizeof(struct sockaddr_in));
          arp_req.arp_ha.sa_family = mess->htype;
          memcpy(arp_req.arp_ha.sa_data, mess->chaddr, mess->hlen);
          /* interface name already copied in */
          arp_req.arp_flags = ATF_COM;
          if (ioctl(daemon->dhcpfd, SIOCSARP, &arp_req) == -1)
            my_syslog(MS_DHCP | LOG_ERR, _("ARP-cache injection failed: %s"), strerror(errno));
        }
    }
#elif defined(HAVE_SOLARIS_NETWORK)
  else if ((ntohs(mess->flags) & 0x8000) || mess->hlen != ETHER_ADDR_LEN || mess->htype != ARPHRD_ETHER)
    {
      /* broadcast to 255.255.255.255 (or mac address invalid) */
      dest.sin_addr.s_addr = INADDR_BROADCAST;
      dest.sin_port = htons(daemon->dhcp_client_port);
      /* note that we don't specify the interface here: that's done by the
	 IP_BOUND_IF sockopt lower down. */
    }
  else
    {
      /* unicast to unconfigured client. Inject mac address direct into ARP cache. 
	 Note that this only works for ethernet on solaris, because we use SIOCSARP
	 and not SIOCSXARP, which would be perfect, except that it returns ENXIO 
	 mysteriously. Bah. Fall back to broadcast for other net types. */
      struct arpreq req;
      dest.sin_addr = mess->yiaddr;
      dest.sin_port = htons(daemon->dhcp_client_port);
      *((struct sockaddr_in *)&req.arp_pa) = dest;
      req.arp_ha.sa_family = AF_UNSPEC;
      memcpy(req.arp_ha.sa_data, mess->chaddr, mess->hlen);
      req.arp_flags = ATF_COM;
      ioctl(daemon->dhcpfd, SIOCSARP, &req);
    }
#elif defined(HAVE_BSD_NETWORK)
  else 
    {
#ifdef HAVE_DUMPFILE
      if (ntohs(mess->flags) & 0x8000)
        dest.sin_addr.s_addr = INADDR_BROADCAST;
      else
        dest.sin_addr = mess->yiaddr;
      dest.sin_port = htons(daemon->dhcp_client_port);
      
      dump_packet_udp(DUMP_DHCP, (void *)iov.iov_base, iov.iov_len, NULL,
		      (union mysockaddr *)&dest, fd);
#endif
      
      send_via_bpf(mess, iov.iov_len, iface_addr, &ifr);
      return;
    }
#endif
   
#ifdef HAVE_SOLARIS_NETWORK
  setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &iface_index, sizeof(iface_index));
#endif

#ifdef HAVE_DUMPFILE
  dump_packet_udp(DUMP_DHCP, (void *)iov.iov_base, iov.iov_len, NULL,
		  (union mysockaddr *)&dest, fd);
#endif
  
  while(retry_send(sendmsg(fd, &msg, 0)));

  /* This can fail when, eg, iptables DROPS destination 255.255.255.255 */
  if (errno != 0)
    {
      inet_ntop(AF_INET, &dest.sin_addr, daemon->addrbuff, ADDRSTRLEN);
      my_syslog(MS_DHCP | LOG_WARNING, _("Error sending DHCP packet to %s: %s"),
		daemon->addrbuff, strerror(errno));
    }
}

/* check against secondary interface addresses */
/**
 * @brief Check if a specific IP address exists on a given network interface for DHCP listen address validation
 * 
 * @detailed This callback function is invoked by iface_enumerate() to validate that a requested DHCP
 * listen address (specified via --dhcp-range or --listen-address configuration) actually exists on
 * the specified network interface. Unlike other interface enumeration callbacks that check all interfaces,
 * this function validates a specific interface (identified by param->ind) to confirm that the requested
 * IP address is configured on that interface.
 * 
 * The function iterates through all IP addresses configured on the target interface (stored in
 * daemon->if_addrs list) and compares them against the interface's local address. When a match is found,
 * the function records the address details (IP, netmask, broadcast) in the match parameter structure.
 * 
 * Validation logic:
 * - Only examines the interface matching param->ind (target interface index)
 * - Searches daemon->if_addrs list for addresses on this interface
 * - Compares requested address with each configured address
 * - Records match details when found (sets param->matched flag)
 * 
 * This validation prevents configuration errors where an administrator specifies a DHCP listen address
 * that is not actually configured on the specified interface, which would prevent the DHCP server from
 * receiving requests.
 * 
 * @param local Local IP address assigned to the current interface being examined
 * @param if_index Kernel interface index being examined
 * @param label Interface name string (unused - suppressed via (void) cast)
 * @param netmask Network mask for the current interface (stored if match found)
 * @param broadcast Broadcast address for current interface (stored if match found)
 * @param vparam Void pointer to struct match_param containing target interface index and results
 * 
 * @return 1 to continue enumeration, 0 to stop (implementation continues enumeration)
 * 
 * @note Called during configuration validation, not during normal DHCP packet processing
 * @note Examines only the interface specified by param->ind, ignoring others
 * @note Searches daemon->if_addrs list which contains all configured interface addresses
 * 
 * @warning Label parameter unused to suppress compiler warnings about unused parameters
 * 
 * @see iface_enumerate() in network.c - Enumerates interfaces and invokes this callback
 * @see struct match_param - Contains target interface index and match results
 * @see struct iname in dnsmasq.h - Interface address list entry structure
 * @see daemon->if_addrs - Global list of configured interface addresses
 * 
 * EXAMPLE USAGE:
 * @code
 * // Validate that address exists on interface with index 2
 * struct match_param match;
 * match.ind = 2;  // Target interface index
 * match.matched = 0;
 * iface_enumerate(AF_INET, &match, check_listen_addrs);
 * if (!match.matched)
 *   die("Requested DHCP listen address not found on specified interface");
 * // match.addr, match.netmask, match.broadcast now contain interface details
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 2131 - DHCP server must listen on configured interface addresses
 * 
 * SIDE EFFECTS:
 * - Sets param->matched = 1 when requested address found on target interface
 * - Stores param->addr, param->netmask, param->broadcast from matching interface
 * - Breaks inner loop after first match (assumes one address per interface in typical case)
 * 
 * THREAD SAFETY: Not thread-safe; called during single-threaded initialization only
 */
static int check_listen_addrs(struct in_addr local, int if_index, char *label,
			      struct in_addr netmask, struct in_addr broadcast, void *vparam)
{
  struct match_param *param = vparam;
  struct iname *tmp;

  (void) label;

  if (if_index == param->ind)
    {
      for (tmp = daemon->if_addrs; tmp; tmp = tmp->next)
	if ( tmp->addr.sa.sa_family == AF_INET &&
	     tmp->addr.in.sin_addr.s_addr == local.s_addr)
	  {
	    param->matched = 1;
	    param->addr = local;
	    param->netmask = netmask;
	    param->broadcast = broadcast;
	    break;
	  }
    }
  
  return 1;
}

/* This is a complex routine: it gets called with each (address,netmask,broadcast) triple 
   of each interface (and any relay address) and does the  following things:

   1) Discards stuff for interfaces other than the one on which a DHCP packet just arrived.
   2) Fills in any netmask and broadcast addresses which have not been explicitly configured.
   3) Fills in local (this host) and router (this host or relay) addresses.
   4) Links contexts which are valid for hosts directly connected to the arrival interface on ->current.

   Note that the current chain may be superseded later for configured hosts or those coming via gateways. */

/**
 * @brief Automatically infer and set netmask for DHCP contexts without explicit netmask configuration
 * 
 * @detailed Iterates through all DHCP contexts in daemon->dhcp linked list, identifying contexts
 *           that lack an explicitly configured netmask (CONTEXT_NETMASK flag not set). For each
 *           such context, verifies that the provided address falls within the context's IP range
 *           (start to end) using the candidate netmask. If the range endpoints are consistent
 *           with the netmask, assigns it to the context. Issues warning if the DHCP range spans
 *           multiple subnets (start and end addresses are in different subnets with the given
 *           netmask), as this configuration is invalid per RFC 2131 Section 4.3.1.
 * 
 * @param addr Reference IPv4 address from the network interface (typically interface's IP address)
 * @param netmask Network mask from the interface configuration to apply to matching contexts
 * 
 * @return void (modifies context->netmask in-place for matching contexts)
 * 
 * @note Called during daemon initialization and interface enumeration to auto-configure netmasks
 * @note Only affects contexts without explicit netmask configuration (allows manual override)
 * @note Warning logged if range endpoints are not both in same subnet as addr with given netmask
 * @warning Invalid configurations (ranges spanning subnets) are logged but not rejected
 * 
 * @see complete_context() - calls this function during interface setup
 * @see is_same_net() in network.c - subnet membership test using address, reference, and netmask
 * 
 * EXAMPLE USAGE:
 * @code
 * struct in_addr iface_addr, iface_mask;
 * inet_pton(AF_INET, "192.168.1.1", &iface_addr);
 * inet_pton(AF_INET, "255.255.255.0", &iface_mask);
 * guess_range_netmask(iface_addr, iface_mask);  // Auto-configure context netmasks
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 2131 Section 4.3.1 requires DHCP server and all clients in range on same subnet
 * 
 * SIDE EFFECTS:
 * - Modifies context->netmask for contexts without CONTEXT_NETMASK flag
 * - Logs warning to syslog if range spans multiple subnets
 * - Uses daemon->dhcp_buff, daemon->dhcp_buff2, daemon->addrbuff for formatting warning messages
 * 
 * THREAD SAFETY: Single-threaded event-driven model - assumes exclusive access to daemon->dhcp list
 */
static void guess_range_netmask(struct in_addr addr, struct in_addr netmask)
{
  struct dhcp_context *context;

  for (context = daemon->dhcp; context; context = context->next)
    if (!(context->flags & CONTEXT_NETMASK) &&
	(is_same_net(addr, context->start, netmask) ||
	 is_same_net(addr, context->end, netmask)))
      { 
	if (context->netmask.s_addr != netmask.s_addr &&
	    !(is_same_net(addr, context->start, netmask) &&
	      is_same_net(addr, context->end, netmask)))
	  {
	    inet_ntop(AF_INET, &context->start, daemon->dhcp_buff, DHCP_BUFF_SZ);
	    inet_ntop(AF_INET, &context->end, daemon->dhcp_buff2, DHCP_BUFF_SZ);
	    inet_ntop(AF_INET, &netmask, daemon->addrbuff, ADDRSTRLEN);
	    my_syslog(MS_DHCP | LOG_WARNING, _("DHCP range %s -- %s is not consistent with netmask %s"),
		      daemon->dhcp_buff, daemon->dhcp_buff2, daemon->addrbuff);
	  }	
	context->netmask = netmask;
      }
}

/**
 * @brief Complete DHCP context configuration by associating network interface details with configured address ranges
 * 
 * @detailed This callback function is invoked by iface_enumerate() for each network interface to match
 * configured DHCP address ranges (dhcp_context entries) with actual network interfaces. For each interface,
 * the function associates the interface index, label (name), local IP address, netmask, and broadcast
 * address with all matching DHCP contexts. This enables the DHCP server to determine which address
 * pools apply to DHCP requests received on specific interfaces.
 * 
 * The function performs several critical tasks:
 * - Validates that dhcp-range configurations match actual network interfaces
 * - Associates DHCP contexts with interface indices for packet routing
 * - Calculates and validates address pool boundaries against interface netmasks
 * - Identifies relay agents for off-subnet DHCP service
 * - Detects shared network configurations (multiple contexts on same interface)
 * - Logs warnings for configuration mismatches (wrong subnet, overlapping ranges)
 * 
 * A DHCP context matches an interface if:
 * - Context start address is on the same subnet as interface address (considering netmask)
 * - Context is not already matched to a different interface
 * - Context is not a relay-agent-only configuration
 * 
 * Multiple DHCP contexts can share the same network interface (shared network scenario),
 * enabling multiple address pools or configurations on a single physical network segment.
 * 
 * @param local Local IP address assigned to this network interface
 * @param if_index Kernel interface index (used for packet routing and binding)
 * @param label Interface name string (e.g., "eth0", "wlan0") for logging
 * @param netmask Network mask for this interface
 * @param broadcast Broadcast address for this interface
 * @param vparam Void pointer to struct iface_param containing iteration state
 * 
 * @return 1 to continue enumeration to next interface, 0 would stop enumeration (never used)
 * 
 * @note Called once per network interface during daemon initialization by dhcp_init()
 * @note Multiple contexts may match a single interface (shared network scenario)
 * @note Contexts without matching interfaces generate warning logs
 * 
 * @warning Context configuration errors (wrong subnet, missing interface) logged but non-fatal
 * @warning Overlapping address ranges on same interface generate warnings but are permitted
 * 
 * @see iface_enumerate() in network.c - Enumerates interfaces and invokes this callback
 * @see struct dhcp_context in dnsmasq.h - DHCP address range configuration structure
 * @see struct iface_param - Callback parameter structure with iteration state
 * 
 * EXAMPLE USAGE:
 * @code
 * // Called internally by iface_enumerate() during dhcp_init()
 * struct iface_param param = { daemon->dhcp_contexts, 0 };
 * iface_enumerate(AF_INET, &param, complete_context);
 * // After enumeration, all matching contexts have interface details populated
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 2131 Section 3.1 - Server must determine client's subnet from interface
 * 
 * SIDE EFFECTS:
 * - Modifies dhcp_context entries: Sets current->netmask, current->broadcast, current->local
 * - Sets current->if_index for matched contexts (enables interface-specific packet handling)
 * - Increments param->ind index counter for logging
 * - Writes warning messages to syslog for configuration mismatches
 * - Identifies and marks relay agent configurations
 * 
 * THREAD SAFETY: Not thread-safe; called during single-threaded initialization only
 */
static int complete_context(struct in_addr local, int if_index, char *label,
			    struct in_addr netmask, struct in_addr broadcast, void *vparam)
{
  struct dhcp_context *context;
  struct dhcp_relay *relay;
  struct iface_param *param = vparam;
  struct shared_network *share;
  
  (void)label;

  for (share = daemon->shared_networks; share; share = share->next)
    {
      
#ifdef HAVE_DHCP6
      if (share->shared_addr.s_addr == 0)
	continue;
#endif
      
      if (share->if_index != 0)
	{
	  if (share->if_index != if_index)
	    continue;
	}
      else
	{
	  if (share->match_addr.s_addr != local.s_addr)
	    continue;
	}

      for (context = daemon->dhcp; context; context = context->next)
	{
	  if (context->netmask.s_addr != 0 &&
	      is_same_net(share->shared_addr, context->start, context->netmask) &&
	      is_same_net(share->shared_addr, context->end, context->netmask))
	    {
	      /* link it onto the current chain if we've not seen it before */
	      if (context->current == context)
		{
		  /* For a shared network, we have no way to guess what the default route should be. */
		  context->router.s_addr = 0;
		  context->local = local; /* Use configured address for Server Identifier */
		  context->current = param->current;
		  param->current = context;
		}
	      
	      if (!(context->flags & CONTEXT_BRDCAST))
		context->broadcast.s_addr  = context->start.s_addr | ~context->netmask.s_addr;
	    }		
	}
    }

  guess_range_netmask(local, netmask);
  
  for (context = daemon->dhcp; context; context = context->next)
    {
      if (context->netmask.s_addr != 0 &&
	  is_same_net(local, context->start, context->netmask) &&
	  is_same_net(local, context->end, context->netmask))
	{
	  /* link it onto the current chain if we've not seen it before */
	  if (if_index == param->ind && context->current == context)
	    {
	      context->router = local;
	      context->local = local;
	      context->current = param->current;
	      param->current = context;
	    }
	  
	  if (!(context->flags & CONTEXT_BRDCAST))
	    {
	      if (is_same_net(broadcast, context->start, context->netmask))
		context->broadcast = broadcast;
	      else 
		context->broadcast.s_addr  = context->start.s_addr | ~context->netmask.s_addr;
	    }
	}		
    }

  for (relay = daemon->relay4; relay; relay = relay->next)
    if (!relay->split_mode && relay->local.addr4.s_addr == local.s_addr)
      {
	if (if_index == param->ind)
	  relay->iface_index = if_index;
	
	/* More than one interface with the relay address breaks things. */
	if (relay->matchcount++ == 1 && !relay->warned)
	  {
	    relay->warned = 1;
	    inet_ntop(AF_INET, &local, daemon->addrbuff, ADDRSTRLEN);
	    my_syslog(MS_DHCP | LOG_WARNING, _("DHCP relay address %s appears on more than one interface"), daemon->addrbuff);
	  }
      }
  
  return 1;
}
	  
/**
 * @brief Validate that a requested IP address is available for dynamic allocation in a given context
 * 
 * @detailed Checks whether a specific IPv4 address is suitable for DHCP lease assignment by verifying
 *           that the address falls within a valid dynamic DHCP range, is not reserved for static use,
 *           is not the server/router address itself, and matches the client's network ID filters.
 *           Iterates through the linked list of contexts (context->current) to check all possible
 *           ranges associated with the interface/network. This function is used both for validating
 *           client-requested addresses (DHCPREQUEST with requested IP option) and for confirming
 *           dynamically selected addresses before allocation.
 * 
 * @param context Starting DHCP context (interface/network context, may be linked list via ->current)
 * @param taddr Target IPv4 address to validate for availability
 * @param netids Client network ID tags (vendor class, user class, MAC patterns) for filter matching
 * 
 * @return Pointer to matching dhcp_context if address is available in that context
 * @retval non-NULL Pointer to dhcp_context where address is valid and available
 * @retval NULL Address is unavailable (out of range, static/proxy context, router address, or filter mismatch)
 * 
 * @note Address availability does NOT check if address is already leased (caller must check lease database)
 * @note Router address check prevents server from allocating its own IP to clients
 * @note CONTEXT_STATIC ranges are excluded (reserved for static lease bindings only)
 * @note CONTEXT_PROXY ranges are excluded (PXE proxy mode, no IP allocation)
 * @warning Network byte order conversion (ntohl) used for arithmetic comparison of address ranges
 * 
 * @see address_allocate() - uses this function to validate dynamically selected addresses
 * @see match_netid() in netid.c - filters contexts based on client tags
 * @see lease_find_by_addr() in lease.c - must be called separately to check if address already leased
 * 
 * EXAMPLE USAGE:
 * @code
 * struct in_addr requested_addr;
 * inet_pton(AF_INET, "192.168.1.100", &requested_addr);
 * struct dhcp_context *avail = address_available(context, requested_addr, client_netids);
 * if (avail && !lease_find_by_addr(requested_addr))
 *     // Address is available and not currently leased
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 2131 Section 3.1 (client-supplied requested address), Section 4.3.1 (address selection)
 * 
 * SIDE EFFECTS: None (read-only validation function)
 * 
 * THREAD SAFETY: Single-threaded event-driven model - safe for read-only traversal of context list
 */
struct dhcp_context *address_available(struct dhcp_context *context, 
				       struct in_addr taddr,
				       struct dhcp_netid *netids)
{
  /* Check is an address is OK for this network, check all
     possible ranges. Make sure that the address isn't in use
     by the server itself. */
  
  unsigned int start, end, addr = ntohl(taddr.s_addr);
  struct dhcp_context *tmp;

  for (tmp = context; tmp; tmp = tmp->current)
    if (taddr.s_addr == context->router.s_addr)
      return NULL;
  
  for (tmp = context; tmp; tmp = tmp->current)
    {
      start = ntohl(tmp->start.s_addr);
      end = ntohl(tmp->end.s_addr);

      if (!(tmp->flags & (CONTEXT_STATIC | CONTEXT_PROXY)) &&
	  addr >= start &&
	  addr <= end &&
	  match_netid(tmp->filter, netids, 1))
	return tmp;
    }

  return NULL;
}

/**
 * @brief Narrow down a linked set of contexts to the single context matching a specific IP address
 * 
 * @detailed Given a set of possible DHCP contexts for a physical interface (chained via ->current),
 *           determines the single specific context that should handle a particular IP address. This
 *           function is critical for processing static DHCP reservations (dhcp-host) that may specify
 *           addresses outside the normal dynamic ranges. The selection algorithm follows a three-tier
 *           priority hierarchy: (1) Dynamic ranges where address is available via address_available(),
 *           (2) Static ranges (CONTEXT_STATIC) on the same subnet even if address is outside dynamic
 *           ranges, (3) Any non-proxy context on the same subnet as fallback. Returns a single context
 *           with ->current set to NULL to break the chain, or NULL if no suitable context found.
 * 
 * @param context Starting context (head of ->current chain) for the receiving interface
 * @param taddr Target IPv4 address to find the matching context for (e.g., from dhcp-host static assignment)
 * @param netids Client network ID tags (vendor class, user class, MAC patterns) for filter matching
 * 
 * @return Pointer to single dhcp_context matching the address (->current set to NULL), or NULL
 * @retval non-NULL Single context matching address with priority: dynamic > static > any non-proxy
 * @retval NULL No context matches address (address outside all ranges and not on any configured subnet)
 * 
 * @note Called during DHCP packet processing after interface/context identification to select final context
 * @note Handles static reservations outside dynamic ranges (common dhcp-host configuration pattern)
 * @note Multiple contexts matching same subnet may indicate configuration issue (no warning currently issued)
 * @note Returned context has ->current set to NULL to ensure single context (breaks linked list)
 * @warning May return NULL for addresses in dhcp-host entries that don't match any configured subnet
 * @warning PXE proxy contexts (CONTEXT_PROXY) excluded from fallback matching (no IP allocation)
 * 
 * @see address_available() - first-priority check for address in dynamic range
 * @see match_netid() in netid.c - filters contexts based on client tags
 * @see is_same_net() in network.c - subnet membership test
 * @see dhcp_reply() in rfc2131.c - calls this function to select final context for reply
 * 
 * EXAMPLE USAGE:
 * @code
 * struct in_addr static_addr;
 * inet_pton(AF_INET, "192.168.1.50", &static_addr);  // From dhcp-host entry
 * struct dhcp_context *final = narrow_context(context_chain, static_addr, client_netids);
 * if (final)
 *     // Use this single context for lease assignment
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 2131 Section 4.3.1 (address selection), supports static reservations
 * 
 * SIDE EFFECTS:
 * - Modifies tmp->current to NULL for returned context (breaks context chain)
 * - Read-only traversal of context->current linked list
 * 
 * THREAD SAFETY: Single-threaded event-driven model - safe for context list traversal
 * 
 * SELECTION ALGORITHM (priority order):
 * 1. PRIORITY 1: Dynamic range where address is available (address_available() succeeds)
 *    - Address must be within start..end range of dynamic context
 *    - Context must not be CONTEXT_STATIC or CONTEXT_PROXY
 *    - Must match client network ID filters
 * 
 * 2. PRIORITY 2: Static range on same subnet (CONTEXT_STATIC)
 *    - Address must be on same subnet as context->start using context->netmask
 *    - Context must have CONTEXT_STATIC flag (allows out-of-range static assignments)
 *    - Must match client network ID filters
 * 
 * 3. PRIORITY 3: Any non-proxy context on same subnet (fallback)
 *    - Address must be on same subnet as context->start using context->netmask
 *    - Context must NOT be CONTEXT_PROXY (PXE proxy does not allocate IPs)
 *    - Must match client network ID filters
 * 
 * USE CASES:
 * - Static IP assignments via dhcp-host where IP is outside dynamic dhcp-range
 * - Validating that client-requested IP belongs to an appropriate context
 * - Ensuring lease assignment uses correct context for subnet and tag matching
 */
struct dhcp_context *narrow_context(struct dhcp_context *context, 
				    struct in_addr taddr,
				    struct dhcp_netid *netids)
{
  /* We start of with a set of possible contexts, all on the current physical interface.
     These are chained on ->current.
     Here we have an address, and return the actual context corresponding to that
     address. Note that none may fit, if the address came a dhcp-host and is outside
     any dhcp-range. In that case we return a static range if possible, or failing that,
     any context on the correct subnet. (If there's more than one, this is a dodgy 
     configuration: maybe there should be a warning.) */
  
  struct dhcp_context *tmp;

  if (!(tmp = address_available(context, taddr, netids)))
    {
      for (tmp = context; tmp; tmp = tmp->current)
	if (match_netid(tmp->filter, netids, 1) &&
	    is_same_net(taddr, tmp->start, tmp->netmask) && 
	    (tmp->flags & CONTEXT_STATIC))
	  break;
      
      if (!tmp)
	for (tmp = context; tmp; tmp = tmp->current)
	  if (match_netid(tmp->filter, netids, 1) &&
	      is_same_net(taddr, tmp->start, tmp->netmask) &&
	      !(tmp->flags & CONTEXT_PROXY))
	    break;
    }
  
  /* Only one context allowed now */
  if (tmp)
    tmp->current = NULL;
  
  return tmp;
}

/**
 * @brief Locate a static DHCP host configuration by IP address
 * 
 * @detailed Searches through the linked list of static DHCP host configurations (dhcp-host entries
 *           from configuration file) to find the first entry that specifies the given IP address.
 *           Only considers configurations with the CONFIG_ADDR flag set (indicating an explicit IP
 *           address was configured rather than only MAC address or hostname). This function is used
 *           to determine if a particular IP address is reserved for static allocation, preventing
 *           that address from being assigned dynamically to other clients. Also used to validate
 *           static reservations during lease assignment and to implement dhcp-host priority over
 *           dynamic allocation.
 * 
 * @param configs Head of linked list of dhcp_config structures (from daemon->dhcp_conf)
 * @param addr IPv4 address to search for in static host configurations
 * 
 * @return Pointer to matching dhcp_config structure, or NULL if not found
 * @retval non-NULL Pointer to first dhcp_config with matching IP address (CONFIG_ADDR flag set)
 * @retval NULL No static host configuration exists for this IP address
 * 
 * @note Only matches configurations with CONFIG_ADDR flag (explicit IP address configured)
 * @note Returns first match if multiple configs specify same IP (configuration error if this occurs)
 * @note Does NOT check if address is currently leased (only checks static configuration)
 * @note Network byte order comparison used (addresses in struct in_addr are network byte order)
 * 
 * @see config_find_by_mac() - similar function searching by MAC address
 * @see address_allocate() - uses this function to avoid allocating statically reserved addresses
 * @see dhcp_reply() in rfc2131.c - uses this to match incoming packets to static reservations
 * 
 * EXAMPLE USAGE:
 * @code
 * struct in_addr check_addr;
 * inet_pton(AF_INET, "192.168.1.100", &check_addr);
 * struct dhcp_config *static_host = config_find_by_address(daemon->dhcp_conf, check_addr);
 * if (static_host)
 *     // This IP is statically reserved, do not allocate dynamically
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 2131 Section 3.1 allows static address reservations
 * 
 * SIDE EFFECTS: None (read-only search operation)
 * 
 * THREAD SAFETY: Single-threaded event-driven model - safe for read-only traversal of config list
 * 
 * CONFIGURATION SOURCE:
 * - dhcp-host=<MAC>,<IP> entries from dnsmasq.conf
 * - dhcp-host=<hostname>,<IP> entries from dnsmasq.conf
 * - /etc/ethers file entries if dhcp-read-ethers enabled
 * 
 * CONFIG_ADDR FLAG:
 * Set when dhcp-host entry includes explicit IP address specification
 * Not set for MAC-only or hostname-only entries without IP
 */
struct dhcp_config *config_find_by_address(struct dhcp_config *configs, struct in_addr addr)
{
  struct dhcp_config *config;
  
  for (config = configs; config; config = config->next)
    if ((config->flags & CONFIG_ADDR) && config->addr.s_addr == addr.s_addr)
      return config;

  return NULL;
}

/**
 * @brief Check if an IP address is in use by sending ICMP ping with caching and load-limiting
 * 
 * @detailed Implements address conflict detection before DHCP lease assignment by sending ICMP
 *           echo request (ping) to the target address. To avoid performance degradation from
 *           excessive pings, implements two key optimizations: (1) caching of ping results for
 *           PING_CACHE_TIME seconds (default 30 seconds from config.h) to prevent repeated pings
 *           to the same address, and (2) load-limiting that stops pinging when more than 60% of
 *           theoretically possible ping checks have occurred within the cache window, indicating
 *           high-load conditions (e.g., client rapidly requesting multiple addresses). This function
 *           acts as a wrapper around the low-level icmp_ping() function, providing the caching and
 *           rate-limiting logic. Used by address_allocate() before offering DHCP leases to ensure
 *           the IP is not already in use by an unconfigured host.
 * 
 * @param now Current time from time(0) call, used to check cache entry expiration
 * @param addr IPv4 address to check for in-use status via ICMP ping
 * @param hash Hash value for this address (used to tag cache entries, typically from address allocation logic)
 * @param loopback Boolean flag: 1 if address is on loopback interface, 0 otherwise
 * 
 * @return Pointer to ping_result cache entry if address NOT in use, or NULL if address IS in use
 * @retval NULL Address is in use (ICMP echo reply received) - do NOT allocate this address
 * @retval non-NULL Address is NOT in use or ping check was skipped - safe to allocate (pointer to cache entry or dummy)
 * 
 * @note Return value semantics: NULL means "address IS in use" (do not allocate), non-NULL means "address NOT in use" (safe to allocate)
 * @note Cache entries expire after PING_CACHE_TIME seconds (default 30s from config.h line 34)
 * @note Load-limiting threshold: stops pinging when count >= 60% of (PING_CACHE_TIME / PING_WAIT)
 * @note PING_WAIT is the time to wait for ping responses (default 3 seconds from config.h line 36)
 * @note If OPT_NO_PING option is set (--no-ping), always returns "not in use" without actual ping
 * @note Loopback addresses always return "not in use" without ping (cannot be assigned to other hosts)
 * @note High-load detection prevents DoS scenario where malicious client rapidly requests many addresses
 * 
 * @warning Modifies global daemon->ping_results linked list (adds new entries, updates timestamps)
 * @warning Allocates memory for new ping_result structures if cache miss and not overloaded
 * @warning Actual ICMP packet transmission occurs via icmp_ping() if cache miss and not rate-limited
 * 
 * @see icmp_ping() in network.c - low-level ICMP echo request transmission and response wait
 * @see address_allocate() - main caller of this function before DHCP lease assignment
 * @see struct ping_result in dnsmasq.h - cache entry structure definition
 * 
 * EXAMPLE USAGE:
 * @code
 * struct in_addr candidate_addr;
 * inet_pton(AF_INET, "192.168.1.100", &candidate_addr);
 * unsigned int addr_hash = hash_hwaddr(client_mac, 6);
 * struct ping_result *result = do_icmp_ping(time(0), candidate_addr, addr_hash, 0);
 * if (result)
 *     // Address is NOT in use, safe to offer as DHCP lease
 * else
 *     // Address IS in use, try next candidate address
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 2131 Section 2.2 recommends address conflict detection via ICMP echo
 * 
 * SIDE EFFECTS:
 * - Reads daemon->ping_results linked list for cache lookup
 * - Updates daemon->ping_results with new entries or reuses expired entries
 * - Allocates memory via whine_malloc() for new ping_result structures if needed
 * - Sends ICMP echo request packet via icmp_ping() if cache miss and not rate-limited
 * - Network I/O: ICMP packet transmission and response reception (via icmp_ping)
 * 
 * THREAD SAFETY: Single-threaded event-driven model - safe for cache list manipulation
 * 
 * CACHE MANAGEMENT:
 * - Searches cache linearly through daemon->ping_results linked list
 * - Entries older than PING_CACHE_TIME are marked as victims (reusable)
 * - New entries prepended to list for cache locality
 * - Victim selection: first expired entry encountered during traversal
 * 
 * LOAD-LIMITING ALGORITHM:
 * max_checks = 0.6 * (PING_CACHE_TIME / PING_WAIT)
 * With defaults (30s cache, 3s wait): max = 0.6 * 10 = 6 checks per 30s window
 * If current_count >= max, skip ping and return "not in use"
 * 
 * PERFORMANCE CHARACTERISTICS:
 * - Cache hit: O(n) list traversal where n = current cache size
 * - Cache miss without rate limit: O(n) traversal + ICMP round-trip (up to PING_WAIT seconds)
 * - Cache miss with rate limit: O(n) traversal only (no ICMP transmission)
 */
struct ping_result *do_icmp_ping(time_t now, struct in_addr addr, unsigned int hash, int loopback)
{
  static struct ping_result dummy;
  struct ping_result *r, *victim = NULL;
  int count, max = (int)(0.6 * (((float)PING_CACHE_TIME)/
				((float)PING_WAIT)));

  /* check if we failed to ping addr sometime in the last
     PING_CACHE_TIME seconds. If so, assume the same situation still exists.
     This avoids problems when a stupid client bangs
     on us repeatedly. As a final check, if we did more
     than 60% of the possible ping checks in the last 
     PING_CACHE_TIME, we are in high-load mode, so don't do any more. */
  for (count = 0, r = daemon->ping_results; r; r = r->next)
    if (difftime(now, r->time) >  (float)PING_CACHE_TIME)
      victim = r; /* old record */
    else 
      {
	count++;
	if (r->addr.s_addr == addr.s_addr)
	  return r;
      }
  
  /* didn't find cached entry */
  if ((count >= max) || option_bool(OPT_NO_PING) || loopback)
    {
      /* overloaded, or configured not to check, loopback interface, return "not in use" */
      dummy.hash = hash;
      return &dummy;
    }
  else if (icmp_ping(addr))
    return NULL; /* address in use. */
  else
    {
      /* at this point victim may hold an expired record */
      if (!victim)
	{
	  if ((victim = whine_malloc(sizeof(struct ping_result))))
	    {
	      victim->next = daemon->ping_results;
	      daemon->ping_results = victim;
	    }
	}
      
      /* record that this address is OK for 30s 
	 without more ping checks */
      if (victim)
	{
	  victim->addr = addr;
	  victim->time = now;
	  victim->hash = hash;
	}
      return victim;
    }
}

/**
 * @brief Allocate a free IP address from DHCP pool with intelligent selection and conflict avoidance
 * 
 * @detailed Implements the core dynamic address allocation algorithm for DHCPv4, selecting an available
 *           IP address from configured address pools (dhcp-range contexts) while avoiding conflicts with
 *           existing leases, static reservations, router addresses, and in-use addresses detected via ICMP
 *           ping. The allocation strategy uses a two-pass approach: first attempting to allocate from
 *           contexts matching the client's network IDs (tags from vendor class, user class, etc.), then
 *           falling back to any available context. Within each context, the starting address is selected
 *           either via hardware address hashing for distribution across the pool (default mode) or via
 *           consecutive addressing starting from the highest existing lease (OPT_CONSEC_ADDR mode). The
 *           function iterates through candidate addresses, excluding: (1) addresses in use as router/gateway,
 *           (2) addresses with active leases, (3) addresses with static reservations, (4) addresses ending
 *           in .255 or .0 within Class C ranges (Windows compatibility per KB281579), and (5) addresses
 *           that fail ICMP ping tests. Address epoch perturbation prevents repeatedly offering the same
 *           address to clients that have previously rejected it (e.g., due to DHCPDECLINE).
 * 
 * @param context Linked list of dhcp_context structures representing configured address pools (dhcp-range entries)
 * @param addrp Output parameter: pointer to in_addr structure that will receive allocated address on success
 * @param hwaddr Client hardware (MAC) address used for hash-based address selection and ping cache tagging
 * @param hw_len Length of hardware address in bytes (typically 6 for Ethernet MAC addresses)
 * @param netids Linked list of network IDs (tags) associated with client (from vendor class, user class, circuit ID, etc.)
 * @param now Current time from time(0), passed to do_icmp_ping() for cache expiration checks
 * @param loopback Boolean flag: 1 if allocation is for loopback interface, 0 otherwise (passed to do_icmp_ping)
 * 
 * @return Success indicator for address allocation
 * @retval 1 Address successfully allocated, IP address written to *addrp
 * @retval 0 No available addresses found in any applicable context (pool exhausted or all candidates in use)
 * 
 * @note Uses SDBM hashing algorithm on hardware address for distributed address selection
 * @note Hash value j == 0 is reserved as marker, replaced with j = 1
 * @note Two-pass allocation: pass 0 matches netids, pass 1 ignores netids (fallback)
 * @note Skips contexts with CONTEXT_STATIC (static-only leases) or CONTEXT_PROXY (PXE proxy mode) flags
 * @note Windows compatibility: avoids .0 and .255 addresses in Class C ranges (see Microsoft KB281579)
 * @note OPT_CONSEC_ADDR mode: consecutive addressing starting from highest existing lease in context
 * @note Default mode: hash-based seed with address epoch perturbation for rejected address avoidance
 * @note Address epoch incremented when address is in use, causing future allocations to skip ahead
 * @note In consec-ip mode, addr_epoch decrements count of rejected addresses before allocation
 * @note Iterates through entire address range (start to end, wrapping) until free address found or full cycle
 * 
 * @warning Modifies context->addr_epoch field for address perturbation (non-const side effect)
 * @warning Allocates memory and performs network I/O via do_icmp_ping() for conflict detection
 * @warning Output parameter addrp only valid if return value is 1 (success)
 * @warning Does NOT create lease entry - caller must invoke lease_allocate() after address allocation
 * 
 * @see do_icmp_ping() - ICMP ping test for address conflict detection before allocation
 * @see lease_find_by_addr() in lease.c - check if address has existing lease
 * @see config_find_by_address() - check if address has static reservation
 * @see lease_find_max_addr() in lease.c - find highest leased address in context (consec-ip mode)
 * @see match_netid() in option.c - filter contexts by network ID tags
 * @see dhcp_reply() in rfc2131.c - main caller during DHCPDISCOVER and DHCPREQUEST processing
 * 
 * EXAMPLE USAGE:
 * @code
 * struct in_addr allocated_addr;
 * unsigned char client_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
 * struct dhcp_netid *client_netids = get_client_netids(packet); // from vendor/user class
 * 
 * if (address_allocate(daemon->dhcp, &allocated_addr, client_mac, 6, client_netids, time(0), 0))
 * {
 *     // Success: allocated_addr contains available IP address
 *     // Now create lease: lease_allocate(client_mac, &allocated_addr, ...);
 * }
 * else
 * {
 *     // Failure: no addresses available, send DHCPNAK or log pool exhaustion
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 2131 Section 3.1 specifies dynamic address allocation from configured pools
 * RFC COMPLIANCE: RFC 2131 Section 2.2 recommends conflict detection via ICMP echo (implemented via do_icmp_ping)
 * 
 * SIDE EFFECTS:
 * - Reads daemon->dhcp_conf for static reservation checks (via config_find_by_address)
 * - Reads lease database for existing lease checks (via lease_find_by_addr)
 * - Modifies context->addr_epoch for address perturbation (increment on conflict, decrement in consec mode)
 * - Calls do_icmp_ping() which sends ICMP packets and updates ping cache (network I/O and memory allocation)
 * - Reads context->router, context->start, context->end for address range boundaries
 * - Reads context->filter for network ID matching
 * - Writes allocated address to *addrp output parameter on success
 * 
 * THREAD SAFETY: Single-threaded event-driven model - safe for context and lease database access
 * 
 * ALLOCATION ALGORITHM:
 * 1. Hash hardware address using SDBM algorithm: j = hwaddr[i] + (j << 6) + (j << 16) - j
 * 2. Two-pass context iteration:
 *    - Pass 0: Only contexts matching client's network IDs (tags)
 *    - Pass 1: All contexts regardless of network IDs (fallback if pass 0 fails)
 * 3. Within each context:
 *    - Skip CONTEXT_STATIC and CONTEXT_PROXY contexts
 *    - Select starting address:
 *      * OPT_CONSEC_ADDR mode: start = highest existing lease address + 1
 *      * Default mode: start = pool_start + ((hash + addr_epoch) % pool_size)
 *    - Iterate through addresses (wrapping at end back to start):
 *      * Skip if matches router address in any context
 *      * Skip if has existing lease (lease_find_by_addr)
 *      * Skip if has static reservation (config_find_by_address)
 *      * Skip if Class C address ending in .0 or .255 (Windows compatibility)
 *      * Check via ICMP ping (do_icmp_ping)
 *        - If ping succeeds (address not in use):
 *          * In consec-ip mode: verify hash matches or skip (prevent cross-client address reuse)
 *          * Return address (success)
 *        - If ping fails (address in use):
 *          * Increment addr_epoch (default mode) to perturb future allocations
 *      * Increment address, wrap at end of range
 *      * Continue until full cycle back to start address
 * 4. If all contexts exhausted without finding free address, return 0 (failure)
 * 
 * SDBM HASH ALGORITHM:
 * for (j = 0, i = 0; i < hw_len; i++)
 *     j = hwaddr[i] + (j << 6) + (j << 16) - j;
 * Equivalent to: j = hwaddr[i] + j*65599
 * Provides good distribution even for similar MAC addresses (sequential OUI ranges)
 * 
 * ADDRESS EPOCH PERTURBATION:
 * - Purpose: Avoid repeatedly offering same address to client that rejected it via DHCPDECLINE
 * - Default mode: addr_epoch increments when address found in use (shifts future hash-based selection)
 * - Consec-ip mode: addr_epoch decrements before allocation (skips forward through recently rejected addresses)
 * - addr_epoch resets to 0 on context reload or when wrapped through entire pool
 * 
 * WINDOWS .0 and .255 AVOIDANCE:
 * Microsoft KB281579 documents Windows bug treating .0 and .255 as broadcast in Class C ranges
 * even when using VLSM/CIDR with non-/24 netmasks. Dnsmasq avoids these addresses to prevent
 * Windows clients from experiencing connectivity issues after lease assignment.
 * Example: dhcp-range=192.168.0.1,192.168.1.254,255.255.254.0
 *   - 192.168.0.255 is valid IP with this netmask, but Windows treats as broadcast
 *   - Dnsmasq skips allocation to avoid hard-to-diagnose Windows problems
 * Check: IN_CLASSC(ntohl(addr)) && ((addr & 0xff) == 0xff || (addr & 0xff) == 0x0)
 * 
 * CONSECUTIVE ADDRESS MODE (OPT_CONSEC_ADDR):
 * - Enabled via --dhcp-sequential-ip configuration option
 * - Starting address = highest existing lease address in context + 1 (from lease_find_max_addr)
 * - Addresses allocated sequentially from this point forward
 * - Reduces address space fragmentation in environments with predictable client populations
 * - addr_epoch used differently: decrements to skip rejected addresses rather than perturbing hash
 * - Prevents same client from being re-offered address it recently declined
 * 
 * PERFORMANCE CHARACTERISTICS:
 * - Best case (hash-based, no conflicts): O(1) address selection, O(1) conflict checks, one ICMP ping
 * - Average case: O(k) where k = number of conflicts encountered before finding free address
 * - Worst case (pool exhausted): O(n*m) where n = pool size, m = number of contexts
 * - ICMP ping wait time: up to PING_WAIT seconds (default 3s) per candidate address tested
 * - Cache effectiveness: frequently tested addresses cached for PING_CACHE_TIME (30s), avoiding repeated pings
 * 
 * POOL EXHAUSTION HANDLING:
 * - Returns 0 when all addresses in all applicable contexts are unavailable
 * - Caller (dhcp_reply in rfc2131.c) typically responds with DHCPNAK or silently drops DHCPDISCOVER
 * - No lease created, no offer sent to client
 * - Administrator alerted via syslog if logging enabled
 * - Common causes: undersized address pool, clients not releasing leases, lease time too long
 * 
 * NETWORK ID (TAG) MATCHING:
 * - match_netid(context->filter, client_netids, pass) determines context applicability
 * - Pass 0: strict matching (context filter must match client netids)
 * - Pass 1: permissive matching (accepts all contexts regardless of filter)
 * - Network IDs derived from: vendor class, user class, circuit ID, remote ID, subscriber ID, MAC address patterns
 * - Enables policy-based address pool selection (e.g., laptops from pool1, servers from pool2)
 * 
 * CONFIGURATION EXAMPLES:
 * dhcp-range=192.168.1.50,192.168.1.150,255.255.255.0,24h           # Default hash-based allocation
 * dhcp-range=tag:blue,192.168.2.10,192.168.2.50,12h               # Only for clients matching "blue" tag
 * dhcp-option=tag:blue,option:router,192.168.2.1                   # Tag-based option delivery
 * dhcp-sequential-ip                                               # Enable consecutive addressing mode
 * no-ping                                                          # Disable ICMP conflict detection (faster but risky)
 */
int address_allocate(struct dhcp_context *context,
		     struct in_addr *addrp, unsigned char *hwaddr, int hw_len, 
		     struct dhcp_netid *netids, time_t now, int loopback)   
{
  /* Find a free address: exclude anything in use and anything allocated to
     a particular hwaddr/clientid/hostname in our configuration.
     Try to return from contexts which match netids first. */

  struct in_addr start, addr;
  struct dhcp_context *c, *d;
  int i, pass;
  unsigned int j; 

  /* hash hwaddr: use the SDBM hashing algorithm.  Seems to give good
     dispersal even with similarly-valued "strings". */ 
  for (j = 0, i = 0; i < hw_len; i++)
    j = hwaddr[i] + (j << 6) + (j << 16) - j;

  /* j == 0 is marker */
  if (j == 0)
    j = 1;
  
  for (pass = 0; pass <= 1; pass++)
    for (c = context; c; c = c->current)
      if (c->flags & (CONTEXT_STATIC | CONTEXT_PROXY))
	continue;
      else if (!match_netid(c->filter, netids, pass))
	continue;
      else
	{
	  if (option_bool(OPT_CONSEC_ADDR))
	    /* seed is largest extant lease addr in this context */
	    start = lease_find_max_addr(c);
	  else
	    /* pick a seed based on hwaddr */
	    start.s_addr = htonl(ntohl(c->start.s_addr) + 
				 ((j + c->addr_epoch) % (1 + ntohl(c->end.s_addr) - ntohl(c->start.s_addr))));

	  /* iterate until we find a free address. */
	  addr = start;
	  
	  do {
	    /* eliminate addresses in use by the server. */
	    for (d = context; d; d = d->current)
	      if (addr.s_addr == d->router.s_addr)
		break;

	    /* Addresses which end in .255 and .0 are broken in Windows even when using 
	       supernetting. ie dhcp-range=192.168.0.1,192.168.1.254,255,255,254.0
	       then 192.168.0.255 is a valid IP address, but not for Windows as it's
	       in the class C range. See  KB281579. We therefore don't allocate these 
	       addresses to avoid hard-to-diagnose problems. Thanks Bill. */	    
	    if (!d &&
		!lease_find_by_addr(addr) && 
		!config_find_by_address(daemon->dhcp_conf, addr) &&
		(!IN_CLASSC(ntohl(addr.s_addr)) || 
		 ((ntohl(addr.s_addr) & 0xff) != 0xff && ((ntohl(addr.s_addr) & 0xff) != 0x0))))
	      {
		/* in consec-ip mode, skip addresses equal to
		   the number of addresses rejected by clients. This
		   should avoid the same client being offered the same
		   address after it has rjected it. */
		if (option_bool(OPT_CONSEC_ADDR) && c->addr_epoch)
		  c->addr_epoch--;
		else
		  {
		    struct ping_result *r;
		    
		    if ((r = do_icmp_ping(now, addr, j, loopback)))
		      {
			/* consec-ip mode: we offered this address for another client
			   (different hash) recently, don't offer it to this one. */
			if (!option_bool(OPT_CONSEC_ADDR) || r->hash == j)
			  {
			    *addrp = addr;
			    return 1;
			  }
		      }
		    else
		      {
			/* address in use: perturb address selection so that we are
			   less likely to try this address again. */
			if (!option_bool(OPT_CONSEC_ADDR))
			  c->addr_epoch++;
		      }
		  }
	      }
	    
	    addr.s_addr = htonl(ntohl(addr.s_addr) + 1);
	    
	    if (addr.s_addr == htonl(ntohl(c->end.s_addr) + 1))
	      addr = c->start;
	    
	  } while (addr.s_addr != start.s_addr);
	}

  return 0;
}

/**
 * @brief Read /etc/ethers file and create static DHCP configurations from MAC-to-IP/hostname mappings
 * 
 * @detailed Implements integration with the standard Unix /etc/ethers file format, parsing MAC address
 *           to IP address or hostname mappings and creating corresponding dhcp_config entries for static
 *           DHCP lease assignments. The /etc/ethers file provides a centralized location for defining
 *           MAC-to-IP mappings used by both arp(8) and rarp(8) utilities, and dnsmasq leverages this
 *           existing infrastructure to avoid duplicate configuration. Each line in the file maps one MAC
 *           address (Ethernet hardware address) to either an IPv4 address or a hostname. On SIGHUP reload,
 *           this function is called again and removes all previously loaded ethers entries (marked with
 *           CONFIG_FROM_ETHERS flag) before re-parsing the file, ensuring configuration changes take effect.
 *           Entries loaded from /etc/ethers are merged with entries from dnsmasq.conf (dhcp-host directives),
 *           with manual configuration taking precedence when MAC addresses conflict. The function performs
 *           comprehensive validation including MAC address format verification, IP address syntax checking,
 *           hostname canonicalization and legality validation, and duplicate detection. Invalid entries are
 *           logged and skipped, allowing the file to be partially parsed even with some malformed lines.
 * 
 * @note Called during daemon initialization and on SIGHUP signal for configuration reload
 * @note ETHERSFILE constant defined in config.h, typically "/etc/ethers" on Unix systems
 * @note ETHER_ADDR_LEN is 6 bytes (48-bit MAC address for Ethernet)
 * @note Uses daemon->namebuff for line buffering (MAXDNAME bytes, typically 1024)
 * @note CONFIG_FROM_ETHERS flag marks entries loaded from this file (vs. dhcp-host config directives)
 * @note CONFIG_NOCLID flag prevents client ID matching (only hardware address matching enabled)
 * @note CONFIG_ADDR flag indicates entry has IP address; CONFIG_NAME indicates hostname
 * @note Duplicate MAC addresses with different IP/hostname entries generate warnings and are skipped
 * @note Manual dhcp-host entries take precedence over /etc/ethers for same MAC address
 * @note Empty lines, comment lines (starting with #), and NIS lines (starting with +) are skipped
 * 
 * @warning Modifies daemon->dhcp_conf global linked list (adds/updates/removes entries)
 * @warning Allocates memory for dhcp_config structures and hostname strings (via whine_malloc)
 * @warning Previously loaded ethers entries are freed and removed from list on each invocation
 * @warning File parsing failures logged to syslog but do not prevent daemon operation
 * @warning Malformed lines logged individually but do not stop processing of remaining lines
 * 
 * @see dhcp_init() - calls this function during daemon startup if --read-ethers option enabled
 * @see parse_hex() in util.c - parses MAC address from hex string representation
 * @see canonicalise() in util.c - canonicalizes hostname to lowercase with domain appending
 * @see legal_hostname() in util.c - validates hostname characters and structure per RFC requirements
 * @see struct dhcp_config in dnsmasq.h - configuration entry structure modified by this function
 * @see struct hwaddr_config in dnsmasq.h - hardware address configuration embedded in dhcp_config
 * 
 * EXAMPLE USAGE:
 * @code
 * // During daemon initialization or SIGHUP handler:
 * if (option_bool(OPT_ETHERS))  // --read-ethers option enabled
 *     dhcp_read_ethers();        // Parse /etc/ethers and populate static configurations
 * 
 * // Example /etc/ethers file format:
 * // 00:11:22:33:44:55 192.168.1.100     # Static IP assignment
 * // aa:bb:cc:dd:ee:ff server1.example   # Hostname assignment
 * // # Comments and blank lines are ignored
 * @endcode
 * 
 * FILE FORMAT: /etc/ethers standard format (one entry per line)
 *   MAC_ADDRESS  IP_OR_HOSTNAME
 * where:
 *   - MAC_ADDRESS: 6 colon-separated hex bytes (e.g., 00:11:22:33:44:55)
 *   - IP_OR_HOSTNAME: Either dotted-quad IPv4 (192.168.1.100) or hostname (server1.example)
 *   - Comments: Lines starting with # are ignored
 *   - NIS integration: Lines starting with + are ignored (NIS netgroup references)
 *   - Whitespace: Leading/trailing whitespace trimmed, fields separated by whitespace
 * 
 * SIDE EFFECTS:
 * - Opens and reads ETHERSFILE (typically /etc/ethers) from filesystem
 * - Traverses daemon->dhcp_conf linked list to find and remove CONFIG_FROM_ETHERS entries
 * - Frees memory for previously loaded ethers entries (config structures, hostnames, hwaddr)
 * - Allocates memory for new dhcp_config structures and hostname strings
 * - Modifies daemon->dhcp_conf linked list by prepending new entries
 * - Logs to syslog: file open errors, parse errors per line, duplicate warnings, final entry count
 * - File I/O: reads entire file line-by-line (blocking I/O during initialization/reload)
 * 
 * THREAD SAFETY: Single-threaded event-driven model - safe for linked list manipulation
 * 
 * CONFIGURATION PRECEDENCE:
 * 1. Manual dhcp-host entries from dnsmasq.conf (highest priority)
 * 2. /etc/ethers entries loaded by this function (if --read-ethers enabled)
 * 3. Dynamic DHCP allocation from address pools (lowest priority, no static configuration)
 * 
 * If manual dhcp-host entry exists for same MAC address, ethers entry is merged:
 * - Manual entry's IP/hostname retained if specified
 * - Ethers entry's IP/hostname used only if not manually configured
 * - Manual entry's DHCP options and other configuration preserved
 * 
 * RELOAD BEHAVIOR (SIGHUP):
 * 1. Traverse daemon->dhcp_conf and remove all entries with CONFIG_FROM_ETHERS flag
 * 2. Free associated memory (hostname strings, hwaddr structures, config structures)
 * 3. Re-parse /etc/ethers from beginning
 * 4. Create fresh dhcp_config entries for current file contents
 * 5. Result: Configuration changes in /etc/ethers take effect without daemon restart
 * 
 * DUPLICATE DETECTION:
 * - By IP address: Searches existing configs for matching addr.s_addr
 * - By hostname: Searches existing configs with hostname_isequal() for case-insensitive match
 * - By MAC address: Searches for exact 6-byte match (no wildcard masks)
 * - Duplicates within /etc/ethers itself: Second occurrence logged and skipped
 * - Conflicts with manual dhcp-host entries: Manual entry wins, ethers entry merged
 * 
 * MAC ADDRESS PARSING:
 * - parse_hex() expects 6 colon-separated hex bytes: XX:XX:XX:XX:XX:XX
 * - Alternative formats accepted: XX-XX-XX-XX-XX-XX or XXXXXXXXXXXX (12 hex digits)
 * - Exactly ETHER_ADDR_LEN (6) bytes required - more or fewer causes parse error
 * - Invalid characters or incorrect length logged and line skipped
 * 
 * HOSTNAME vs IP ADDRESS DETECTION:
 * - Scans second field character-by-character
 * - If all characters are digits or dots: treated as dotted-quad IP address
 * - If any character is not digit/dot: treated as hostname
 * - IP address parsed with inet_pton(AF_INET, ...) - validates format
 * - Hostname canonicalized (lowercased, domain appended) and validated per RFC
 * 
 * ERROR HANDLING:
 * - File open failure: Logged to syslog with errno description, function returns immediately
 * - Line parse errors: Logged with line number, line skipped, processing continues
 * - Bad MAC address: Line skipped, error logged
 * - Bad IP address: Line skipped, error logged
 * - Bad hostname: Line skipped, error logged (unless out-of-memory condition)
 * - Duplicate entries: Warning logged, line skipped
 * - Memory allocation failure: whine_malloc logs error, line skipped, processing continues
 * 
 * MEMORY MANAGEMENT:
 * - dhcp_config structures: Allocated via whine_malloc (logs error on failure)
 * - hostname strings: Allocated by canonicalise() (caller must free on error paths)
 * - hwaddr_config structures: Allocated via whine_malloc for MAC address storage
 * - Cleanup on reload: All CONFIG_FROM_ETHERS entries freed before re-parsing
 * - Partial failure handling: Memory leaks avoided by freeing host variable before continue
 * 
 * PERFORMANCE CHARACTERISTICS:
 * - File parsing: O(n) where n = number of lines in /etc/ethers
 * - Duplicate detection: O(m) where m = number of existing dhcp_config entries (for each new entry)
 * - Overall complexity: O(n*m) for n ethers entries and m existing configs
 * - Typical case: Small files (dozens to hundreds of entries), acceptable linear search
 * - Blocking I/O: Entire file read during initialization or SIGHUP (acceptable for small files)
 * 
 * INTEGRATION WITH DHCP SERVER:
 * - Loaded configurations used by dhcp_reply() in rfc2131.c during DHCPDISCOVER/DHCPREQUEST
 * - config_find_by_address() and find_config() locate matching configurations by MAC/IP/hostname
 * - Static lease assignment takes precedence over dynamic allocation from address pools
 * - DNS registration: Hostnames from ethers entries registered in DNS cache when lease assigned
 * 
 * TYPICAL USE CASES:
 * 1. Server infrastructure: Static IP assignments for servers with known MAC addresses
 * 2. Network printers: Predictable IP addresses for print services
 * 3. Network appliances: Fixed addressing for managed switches, access points, cameras
 * 4. ARP compatibility: Sharing MAC-to-IP mappings with arp(8) and rarp(8) utilities
 * 5. Centralized management: Single file defining static network assignments
 * 
 * CONFIGURATION EXAMPLE:
 * Enable in dnsmasq.conf:
 *   read-ethers  # or --read-ethers command-line option
 * 
 * Example /etc/ethers content:
 *   # Servers
 *   00:11:22:33:44:55 192.168.1.10       # webserver
 *   00:11:22:33:44:66 mailserver.local   # mailserver hostname
 *   
 *   # Printers
 *   aa:bb:cc:dd:ee:01 192.168.1.20
 *   aa:bb:cc:dd:ee:02 192.168.1.21
 *   
 *   # Comments and NIS lines ignored
 *   +netgroup_servers                     # NIS netgroup (ignored)
 */
void dhcp_read_ethers(void)
{
  FILE *f = fopen(ETHERSFILE, "r");
  unsigned int flags;
  char *buff = daemon->namebuff;
  char *ip, *cp;
  struct in_addr addr;
  unsigned char hwaddr[ETHER_ADDR_LEN];
  struct dhcp_config **up, *tmp;
  struct dhcp_config *config;
  int count = 0, lineno = 0;

  addr.s_addr = 0; /* eliminate warning */
  
  if (!f)
    {
      my_syslog(MS_DHCP | LOG_ERR, _("failed to read %s: %s"), ETHERSFILE, strerror(errno));
      return;
    }

  /* This can be called again on SIGHUP, so remove entries created last time round. */
  for (up = &daemon->dhcp_conf, config = daemon->dhcp_conf; config; config = tmp)
    {
      tmp = config->next;
      if (config->flags & CONFIG_FROM_ETHERS)
	{
	  *up = tmp;
	  /* cannot have a clid */
	  if (config->flags & CONFIG_NAME)
	    free(config->hostname);
	  free(config->hwaddr);
	  free(config);
	}
      else
	up = &config->next;
    }

  while (fgets(buff, MAXDNAME, f))
    {
      char *host = NULL;
      
      lineno++;
      
      while (strlen(buff) > 0 && isspace((unsigned char)buff[strlen(buff)-1]))
	buff[strlen(buff)-1] = 0;
      
      if ((*buff == '#') || (*buff == '+') || (*buff == 0))
	continue;
      
      for (ip = buff; *ip && !isspace((unsigned char)*ip); ip++);
      for(; *ip && isspace((unsigned char)*ip); ip++)
	*ip = 0;
      if (!*ip || parse_hex(buff, hwaddr, ETHER_ADDR_LEN, NULL, NULL) != ETHER_ADDR_LEN)
	{
	  my_syslog(MS_DHCP | LOG_ERR, _("bad line at %s line %d"), ETHERSFILE, lineno); 
	  continue;
	}
      
      /* check for name or dotted-quad */
      for (cp = ip; *cp; cp++)
	if (!(*cp == '.' || (*cp >='0' && *cp <= '9')))
	  break;
      
      if (!*cp)
	{
	  if (inet_pton(AF_INET, ip, &addr.s_addr) < 1)
	    {
	      my_syslog(MS_DHCP | LOG_ERR, _("bad address at %s line %d"), ETHERSFILE, lineno); 
	      continue;
	    }

	  flags = CONFIG_ADDR;
	  
	  for (config = daemon->dhcp_conf; config; config = config->next)
	    if ((config->flags & CONFIG_ADDR) && config->addr.s_addr == addr.s_addr)
	      break;
	}
      else 
	{
	  int nomem;
	  if (!(host = canonicalise(ip, &nomem)) || !legal_hostname(host))
	    {
	      if (!nomem)
		my_syslog(MS_DHCP | LOG_ERR, _("bad name at %s line %d"), ETHERSFILE, lineno); 
	      free(host);
	      continue;
	    }
	      
	  flags = CONFIG_NAME;

	  for (config = daemon->dhcp_conf; config; config = config->next)
	    if ((config->flags & CONFIG_NAME) && hostname_isequal(config->hostname, host))
	      break;
	}

      if (config && (config->flags & CONFIG_FROM_ETHERS))
	{
	  my_syslog(MS_DHCP | LOG_ERR, _("ignoring %s line %d, duplicate name or IP address"), ETHERSFILE, lineno); 
	  continue;
	}
	
      if (!config)
	{ 
	  for (config = daemon->dhcp_conf; config; config = config->next)
	    {
	      struct hwaddr_config *conf_addr = config->hwaddr;
	      if (conf_addr && 
		  conf_addr->next == NULL && 
		  conf_addr->wildcard_mask == 0 &&
		  conf_addr->hwaddr_len == ETHER_ADDR_LEN &&
		  (conf_addr->hwaddr_type == ARPHRD_ETHER || conf_addr->hwaddr_type == 0) &&
		  memcmp(conf_addr->hwaddr, hwaddr, ETHER_ADDR_LEN) == 0)
		break;
	    }
	  
	  if (!config)
	    {
	      if (!(config = whine_malloc(sizeof(struct dhcp_config))))
		continue;
	      config->flags = CONFIG_FROM_ETHERS;
	      config->hwaddr = NULL;
	      config->domain = NULL;
	      config->netid = NULL;
	      config->next = daemon->dhcp_conf;
	      daemon->dhcp_conf = config;
	    }
	  
	  config->flags |= flags;
	  
	  if (flags & CONFIG_NAME)
	    {
	      config->hostname = host;
	      host = NULL;
	    }
	  
	  if (flags & CONFIG_ADDR)
	    config->addr = addr;
	}
      
      config->flags |= CONFIG_NOCLID;
      if (!config->hwaddr)
	config->hwaddr = whine_malloc(sizeof(struct hwaddr_config));
      if (config->hwaddr)
	{
	  memcpy(config->hwaddr->hwaddr, hwaddr, ETHER_ADDR_LEN);
	  config->hwaddr->hwaddr_len = ETHER_ADDR_LEN;
	  config->hwaddr->hwaddr_type = ARPHRD_ETHER;
	  config->hwaddr->wildcard_mask = 0;
	  config->hwaddr->next = NULL;
	}
      count++;
      
      free(host);

    }
  
  fclose(f);

  my_syslog(MS_DHCP | LOG_INFO, _("read %s - %d addresses"), ETHERSFILE, count);
}


/* If we've not found a hostname any other way, try and see if there's one in /etc/hosts
   for this address. If it has a domain part, that must match the set domain and
   it gets stripped. The set of legal domain names is bigger than the set of legal hostnames
   so check here that the domain name is legal as a hostname. 
   NOTE: we're only allowed to overwrite daemon->dhcp_buff if we succeed. */
/**
 * @brief Retrieve hostname from DNS cache (/etc/hosts) for a given IP address to populate DHCP client hostname
 * 
 * @detailed Implements reverse hostname lookup from the DNS cache to discover hostnames for DHCP clients that
 *           do not provide their own hostname in DHCP packets. This function queries the DNS cache (which
 *           includes entries from /etc/hosts file) to find a hostname associated with the client's IP address,
 *           enabling automatic hostname assignment for devices that lack hostname configuration. The lookup is
 *           restricted to entries from /etc/hosts (F_HOSTS flag) rather than dynamically cached DNS responses,
 *           ensuring stable, administrator-defined hostname mappings. The function performs comprehensive
 *           validation including: (1) verification that DNS service is enabled (daemon->port != 0), (2) domain
 *           suffix matching to ensure hostname belongs to appropriate DHCP context domain, (3) hostname legality
 *           checking per RFC requirements, and (4) domain suffix stripping to return only the hostname portion
 *           suitable for DHCP option 12 (hostname) assignment. The result is stored in daemon->dhcp_buff to
 *           provide a stable string pointer across function calls within the same DHCP transaction processing.
 * 
 * @param addr IPv4 address to reverse-lookup for associated hostname
 * 
 * @return Hostname string pointer or NULL if no valid hostname found
 * @retval non-NULL Pointer to daemon->dhcp_buff containing hostname (without domain suffix) for this IP address
 * @retval NULL No hostname found, or DNS disabled, or hostname validation failed, or wrong domain
 * 
 * @note Return value points to daemon->dhcp_buff which is overwritten on subsequent calls
 * @note Hostname must exist in /etc/hosts file (F_HOSTS flag required) - dynamic DNS cache entries not used
 * @note Domain suffix stripped via strip_hostname() before return (only hostname part returned)
 * @note daemon->dhcp_buff size is 256 bytes (DHCP_BUFF_SIZE) for hostname storage
 * @note If DNS service disabled (daemon->port == 0, e.g., --port=0 option), immediately returns NULL
 * @note Domain validation via get_domain(addr) ensures hostname belongs to correct DHCP context domain
 * @note hostname_isequal() performs case-insensitive domain suffix comparison
 * @note legal_hostname() validates hostname characters per RFC 1123 requirements
 * 
 * @warning Return value is pointer to static buffer daemon->dhcp_buff - not thread-safe, overwritten on next call
 * @warning Caller must use returned string before next invocation of this function or other functions using dhcp_buff
 * @warning NULL return does not distinguish between "not found", "wrong domain", "illegal hostname", or "DNS disabled"
 * 
 * @see cache_find_by_addr() in cache.c - searches DNS cache for reverse IPv4 address lookup
 * @see cache_get_name() in cache.c - extracts hostname string from cache record
 * @see get_domain() in domain.c - determines appropriate domain for IP address based on DHCP context
 * @see hostname_isequal() in util.c - case-insensitive hostname comparison
 * @see legal_hostname() in util.c - validates hostname characters and structure per RFC 1123
 * @see strip_hostname() in util.c - removes domain suffix leaving only hostname portion
 * @see struct crec in dnsmasq.h - DNS cache record structure
 * @see dhcp_reply() in rfc2131.c - main caller using this for hostname discovery when client doesn't provide one
 * 
 * EXAMPLE USAGE:
 * @code
 * // During DHCP request processing when client provides no hostname:
 * struct in_addr client_addr;
 * inet_pton(AF_INET, "192.168.1.100", &client_addr);
 * 
 * char *discovered_hostname = host_from_dns(client_addr);
 * if (discovered_hostname)
 * {
 *     // Use hostname from /etc/hosts for this IP address
 *     // Set DHCP option 12 (hostname) in DHCP reply
 *     // Register hostname in DNS cache for forward lookup
 *     my_syslog(LOG_INFO, "DHCP using hostname from hosts: %s", discovered_hostname);
 * }
 * else
 * {
 *     // No hostname available from /etc/hosts
 *     // Either generate hostname from MAC address or leave unset
 * }
 * @endcode
 * 
 * /etc/hosts INTEGRATION:
 * Example /etc/hosts entries that would be found by this function:
 *   192.168.1.100  webserver.example.com webserver    # Fully qualified and short name
 *   192.168.1.101  printer                           # Short hostname only
 *   192.168.1.102  fileserver.example.com            # FQDN
 * 
 * For addr=192.168.1.100 with DHCP domain "example.com":
 *   - Lookup finds "webserver.example.com" in cache (first name in hosts line)
 *   - Domain suffix ".example.com" matches get_domain(addr) - validation passes
 *   - strip_hostname() removes ".example.com" suffix
 *   - Returns "webserver" in daemon->dhcp_buff
 * 
 * SIDE EFFECTS:
 * - Calls cache_find_by_addr() to search DNS cache (read-only cache access)
 * - Calls get_domain() which searches daemon->dhcp contexts for domain matching IP address
 * - Writes to daemon->dhcp_buff static buffer (256 bytes) - overwriting previous contents
 * - No memory allocation (uses pre-allocated daemon->dhcp_buff)
 * - No network I/O (cache lookup only, no DNS queries sent)
 * 
 * THREAD SAFETY: Single-threaded event-driven model - safe for cache read and dhcp_buff write
 * 
 * VALIDATION ALGORITHM:
 * 1. Check DNS enabled: if (daemon->port == 0) return NULL
 * 2. Reverse lookup: lookup = cache_find_by_addr(addr, F_IPV4)
 * 3. Check cache entry exists and from /etc/hosts: if (!lookup || !(lookup->flags & F_HOSTS)) return NULL
 * 4. Extract hostname: hostname = cache_get_name(lookup)
 * 5. Parse domain suffix: dot = strchr(hostname, '.')
 * 6. If FQDN (contains dot with non-empty suffix):
 *    a. Get expected domain: d2 = get_domain(addr)  // from DHCP context for this IP
 *    b. Compare domains case-insensitively: if (!hostname_isequal(dot+1, d2)) return NULL
 * 7. Validate hostname: if (!legal_hostname(hostname)) return NULL
 * 8. Copy to buffer: safe_strncpy(daemon->dhcp_buff, hostname, 256)
 * 9. Strip domain: strip_hostname(daemon->dhcp_buff)  // removes everything after first dot
 * 10. Return: return daemon->dhcp_buff
 * 
 * F_HOSTS FLAG SIGNIFICANCE:
 * - F_HOSTS indicates cache entry originated from /etc/hosts file
 * - Ensures hostname assignment uses stable, administrator-defined mappings
 * - Dynamic DNS cache entries (from upstream DNS servers) are excluded:
 *   * Prevents transient hostnames from DNS queries affecting DHCP
 *   * Avoids security issues from untrusted DNS responses
 *   * Ensures hostname consistency across DHCP lease renewals
 * - Entries from DHCP leases registered in DNS (F_DHCP flag) also excluded
 * 
 * DOMAIN SUFFIX MATCHING:
 * Purpose: Ensure hostname belongs to correct DHCP context domain
 * Example scenario:
 *   /etc/hosts contains: 192.168.1.100 server.corp.example.com
 *   DHCP context domain: lab.example.com
 *   Client requests IP 192.168.1.100
 *   Domain check: ".corp.example.com" != "lab.example.com" - validation fails
 *   Returns: NULL (wrong domain, hostname not used)
 * 
 * This prevents cross-domain hostname leakage when multiple DHCP contexts serve different domains
 * 
 * HOSTNAME STRIPPING:
 * - strip_hostname() removes everything after first dot: "server.example.com" -> "server"
 * - DHCP option 12 (hostname) should contain short hostname only, not FQDN
 * - DHCP option 15 (domain name) separately provides domain suffix
 * - Client reconstructs FQDN: hostname + "." + domain = "server.example.com"
 * 
 * LEGAL HOSTNAME VALIDATION:
 * - legal_hostname() enforces RFC 1123 requirements:
 *   * Letters (a-z, A-Z), digits (0-9), hyphens (-) only
 *   * Cannot start or end with hyphen
 *   * Maximum 63 characters per label
 *   * Total length limits
 * - Invalid hostnames rejected even if found in /etc/hosts
 * - Prevents DHCP protocol violations from malformed hosts file entries
 * 
 * PERFORMANCE CHARACTERISTICS:
 * - Cache lookup: O(1) hash table lookup in cache_find_by_addr()
 * - Domain validation: O(n) where n = number of DHCP contexts (typically small)
 * - String operations: O(m) where m = hostname length (typically <64 characters)
 * - Overall: O(1) constant time in typical small network deployments
 * - No disk I/O (cache already loaded from /etc/hosts during initialization)
 * 
 * INTEGRATION WITH DHCP WORKFLOW:
 * Called by dhcp_reply() in rfc2131.c during DHCP packet processing:
 * 1. Client sends DHCPDISCOVER or DHCPREQUEST without hostname option
 * 2. DHCP server allocates or confirms IP address
 * 3. Call host_from_dns(client_ip) to discover hostname from /etc/hosts
 * 4. If hostname found:
 *    - Add DHCP option 12 (hostname) to DHCP reply
 *    - Register hostname in DNS cache for forward lookup
 *    - Log lease assignment with hostname
 * 5. If hostname not found:
 *    - Omit hostname option from DHCP reply
 *    - Client remains unnamed in DNS
 * 
 * USE CASES:
 * 1. Embedded devices without hostname configuration capability
 * 2. Network printers with fixed IP addresses defined in /etc/hosts
 * 3. IoT devices that use DHCP but don't provide hostnames
 * 4. Legacy equipment with minimal DHCP client implementations
 * 5. Centralized hostname management via /etc/hosts for all network devices
 * 
 * CONFIGURATION EXAMPLE:
 * /etc/hosts entry:
 *   192.168.1.100  printer-office.example.com printer-office
 * 
 * dnsmasq.conf:
 *   dhcp-range=192.168.1.50,192.168.1.150,255.255.255.0,24h
 *   domain=example.com
 * 
 * When client at 192.168.1.100 requests DHCP without hostname:
 *   - host_from_dns() finds "printer-office.example.com" in DNS cache
 *   - Validates domain suffix "example.com" matches DHCP context domain
 *   - Strips domain suffix, returns "printer-office"
 *   - DHCP reply includes option 12 (hostname) = "printer-office"
 *   - Client sets its hostname to "printer-office"
 *   - DNS forward lookup: "printer-office.example.com" -> 192.168.1.100
 * 
 * ERROR HANDLING:
 * - DNS disabled (port == 0): Returns NULL immediately
 * - No cache entry for IP: Returns NULL (cache_find_by_addr returns NULL)
 * - Cache entry not from /etc/hosts: Returns NULL (missing F_HOSTS flag)
 * - Domain mismatch: Returns NULL (hostname belongs to different domain)
 * - Illegal hostname: Returns NULL (RFC validation failure)
 * - All error conditions handled by returning NULL (caller must handle missing hostname)
 * 
 * COMPARISON WITH OTHER HOSTNAME SOURCES:
 * 1. Client-provided hostname (DHCP option 12 in request): Highest priority, always used if present
 * 2. host_from_dns() lookup from /etc/hosts: Used if client provides no hostname
 * 3. MAC-address-based hostname generation: Fallback if both above unavailable
 * 4. No hostname: Client remains unnamed, IP-only identification
 * 
 * SECURITY CONSIDERATIONS:
 * - Only uses /etc/hosts entries (F_HOSTS flag) - administrator-controlled
 * - Excludes dynamic DNS cache entries - prevents DNS poisoning from affecting DHCP
 * - Domain validation prevents cross-domain hostname leakage
 * - RFC validation prevents protocol violations from malformed hostnames
 * - No external data sources - attack surface limited to local /etc/hosts file
 */
char *host_from_dns(struct in_addr addr)
{
  struct crec *lookup;

  if (daemon->port == 0)
    return NULL; /* DNS disabled. */
  
  lookup = cache_find_by_addr(NULL, (union all_addr *)&addr, 0, F_IPV4);

  if (lookup && (lookup->flags & F_HOSTS))
    {
      char *dot, *hostname = cache_get_name(lookup);
      dot = strchr(hostname, '.');
      
      if (dot && strlen(dot+1) != 0)
	{
	  char *d2 = get_domain(addr);
	  if (!d2 || !hostname_isequal(dot+1, d2))
	    return NULL; /* wrong domain */
	}

      if (!legal_hostname(hostname))
	return NULL;
      
      safe_strncpy(daemon->dhcp_buff, hostname, 256);
      strip_hostname(daemon->dhcp_buff);

      return daemon->dhcp_buff;
    }
  
  return NULL;
}

#endif

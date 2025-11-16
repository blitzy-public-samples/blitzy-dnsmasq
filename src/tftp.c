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
 * @file tftp.c
 * @brief Read-only TFTP server implementation for network boot support
 * 
 * DETAILED PURPOSE:
 * This module implements a read-only TFTP (Trivial File Transfer Protocol) server
 * conforming to RFC 1350 with option negotiation extensions from RFC 2349 (blksize,
 * tsize, timeout) and RFC 7440 (windowsize). The TFTP server is designed primarily
 * to support PXE (Preboot Execution Environment) network boot scenarios for diskless
 * workstations, thin clients, and automated OS deployment systems.
 * 
 * The implementation provides secure file serving with configurable root directories,
 * file ownership verification, concurrent connection management, and integration with
 * the DHCP subsystem for complete network boot infrastructure.
 * 
 * KEY RESPONSIBILITIES:
 * - tftp_request(): Initial TFTP request handling (RRQ) with option negotiation
 * - check_tftp_listeners(): Main TFTP event loop processing active transfers
 * - handle_tftp(): Packet processing for ACK and error handling
 * - get_block(): Data block preparation and transmission with netascii conversion
 * - check_tftp_fileperm(): File access security validation and path construction
 * - do_tftp_script_run(): Post-transfer script execution integration
 * 
 * DEPENDENCIES:
 * Includes: dnsmasq.h (core structures: struct tftp_transfer, struct tftp_file, 
 *           struct listener, daemon global state)
 * Called by: check_dns_listeners() in dnsmasq.c (main event loop)
 * Calls: queue_tftp() in helper.c (script execution when HAVE_SCRIPT enabled)
 * 
 * DATA STRUCTURES:
 * - struct tftp_transfer: Tracks active transfer state (block numbers, file handle,
 *   socket, peer address, options) - defined in dnsmasq.h line 1118
 * - struct tftp_file: File handle with offset and read buffer - dnsmasq.h line 1110
 * - struct tftp_prefix: Per-interface TFTP root directories - dnsmasq.h line 1135
 * - daemon->tftp_trans: Linked list of active transfers (max TFTP_MAX_CONNECTIONS)
 * 
 * COMPILE-TIME OPTIONS:
 * - HAVE_TFTP: Master enable flag for TFTP server compilation
 * - TFTP_MAX_CONNECTIONS: Maximum concurrent transfers (default 50, config.h line 54)
 * - TFTP_MAX_WINDOW: Maximum windowsize option value (default 32, config.h line 55)
 * - TFTP_TIMEOUT: Transfer inactivity timeout in seconds (120s)
 * - HAVE_SCRIPT: Enables post-transfer script execution via do_tftp_script_run()
 * - HAVE_DUMPFILE: Enables packet capture for debugging
 * 
 * THREADING/CONCURRENCY:
 * Single-process event-driven model using poll-based I/O multiplexing. All TFTP
 * processing occurs in main event loop without blocking. Concurrent transfers are
 * managed through linked list of struct tftp_transfer, with each transfer using
 * a separate UDP socket to enable parallel data transmission.
 * 
 * @copyright Copyright (c) 2000-2025 Simon Kelley
 * @license GPL-2.0-or-later
 */

#include "dnsmasq.h"

#ifdef HAVE_TFTP

static void handle_tftp(char *packet, time_t now, struct tftp_transfer *transfer, ssize_t len);
static struct tftp_file *check_tftp_fileperm(char *packet, ssize_t *len, char *prefix, char *client);
static void free_transfer(struct tftp_transfer *transfer);
static ssize_t tftp_err(int err, char *packet, char *message, char *file, char *arg2);
static ssize_t tftp_err_oops(char *packet, const char *file);
static ssize_t get_block(struct tftp_transfer *transfer);
static char *next(char **p, char *end);
static void sanitise(char *buf);

#define OP_RRQ  1
#define OP_WRQ  2
#define OP_DATA 3
#define OP_ACK  4
#define OP_ERR  5
#define OP_OACK 6

#define ERR_NOTDEF 0
#define ERR_FNF    1
#define ERR_PERM   2
#define ERR_FULL   3
#define ERR_ILL    4
#define ERR_TID    5

/**
 * @brief Process incoming TFTP read request (RRQ) and initiate file transfer
 * 
 * @detailed Handles initial TFTP RRQ packets by parsing requested filename and transfer
 * mode (netascii/octet), negotiating options (blksize, tsize, timeout, windowsize),
 * validating file permissions and path security, allocating transfer state, creating
 * dedicated transfer socket, and sending initial OACK or DATA block. Implements
 * per-interface TFTP root directories, secure mode file ownership verification,
 * MTU discovery, and interface-specific binding for multi-homed systems.
 * 
 * @param packet DNS name workspace buffer containing TFTP RRQ packet (reused from DNS)
 * @param plen Length of receive buffer available for packet
 * @param listen Listener structure containing TFTP socket (listen->tftpfd) and bind address
 * @param now Current timestamp for transfer timeout tracking
 * 
 * @return void (sends TFTP response packet or error to client)
 * 
 * @note This function is called from check_dns_listeners() main event loop when
 *       TFTP socket (listen->tftpfd) has data ready to read
 * @warning Refuses write requests (WRQ) with ERR_PERM - server is read-only
 * @warning Enforces connection limit TFTP_MAX_CONNECTIONS (50) - rejects with ERR_NOTDEF
 * @warning Secure mode (--tftp-secure) requires file owner match daemon user
 * 
 * @see check_tftp_fileperm() for file access validation
 * @see check_tftp_listeners() for active transfer processing
 * @see handle_tftp() for ACK and subsequent packet handling
 * 
 * EXAMPLE USAGE:
 * @code
 * // Called from main event loop in dnsmasq.c
 * if (poll_check(listen->tftpfd, POLLIN))
 *   tftp_request(daemon->namebuff, MAXDNAME, listen, now);
 * @endcode
 * 
 * RFC COMPLIANCE:
 * - RFC 1350: Basic TFTP protocol (RRQ/DATA/ACK/ERROR opcodes)
 * - RFC 2349: Option extension (blksize 512-65464, tsize, timeout)
 * - RFC 7440: Windowsize option (1-32 blocks, TFTP_MAX_WINDOW)
 * 
 * SIDE EFFECTS:
 * - Allocates struct tftp_transfer and adds to daemon->tftp_trans linked list
 * - Creates new UDP socket for dedicated transfer communication
 * - Opens file via check_tftp_fileperm() - file remains open for transfer duration
 * - Sends UDP response packet (OACK or DATA[1]) to client
 * - Logs transfer initiation when --log-dhcp enabled
 * 
 * THREAD SAFETY: Single-threaded event loop - modifies global daemon->tftp_trans list
 */
static void tftp_request(char *packet, ssize_t plen, struct listener *listen, time_t now)
{
  ssize_t len;
  char *filename, *mode, *p, *end;
  union mysockaddr addr, peer;
  struct msghdr msg;
  struct iovec iov;
  struct ifreq ifr;
  int is_err = 1, if_index = 0, mtu = 0;
  struct iname *tmp;
  struct tftp_transfer *transfer = NULL, **up;
  int port = daemon->start_tftp_port; /* may be zero to use ephemeral port */
#if defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DONT)
  int mtuflag = IP_PMTUDISC_DONT;
#endif
  char namebuff[IF_NAMESIZE];
  char *name = NULL;
  char *prefix = daemon->tftp_prefix;
  struct tftp_prefix *pref;
  union all_addr addra;
  int family = listen->addr.sa.sa_family;
  /* Can always get recvd interface for IPv6 */
  int check_dest = !option_bool(OPT_NOWILD) || family == AF_INET6;
  union {
    struct cmsghdr align; /* this ensures alignment */
    char control6[CMSG_SPACE(sizeof(struct in6_pktinfo))];
#if defined(HAVE_LINUX_NETWORK)
    char control[CMSG_SPACE(sizeof(struct in_pktinfo))];
#elif defined(HAVE_SOLARIS_NETWORK)
    char control[CMSG_SPACE(sizeof(struct in_addr)) +
		 CMSG_SPACE(sizeof(unsigned int))];
#elif defined(IP_RECVDSTADDR) && defined(IP_RECVIF)
    char control[CMSG_SPACE(sizeof(struct in_addr)) +
		 CMSG_SPACE(sizeof(struct sockaddr_dl))];
#endif
  } control_u; 

  msg.msg_controllen = sizeof(control_u);
  msg.msg_control = control_u.control;
  msg.msg_flags = 0;
  msg.msg_name = &peer;
  msg.msg_namelen = sizeof(peer);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  /* packet buff is DNS name workspace. */
  iov.iov_base = packet;
  iov.iov_len = plen;
  
  if ((len = recvmsg(listen->tftpfd, &msg, 0)) < 2)
    return;

#ifdef HAVE_DUMPFILE
  dump_packet_udp(DUMP_TFTP, (void *)packet, len, (union mysockaddr *)&peer, NULL, listen->tftpfd);
#endif
  
  /* Can always get recvd interface for IPv6 */
  if (!check_dest)
    {
      if (listen->iface)
	{
	  addr = listen->iface->addr;
	  name = listen->iface->name;
	  mtu = listen->iface->mtu;
	  if (daemon->tftp_mtu != 0 && daemon->tftp_mtu < mtu)
	    mtu = daemon->tftp_mtu;
	}
      else
	{
	  /* we're listening on an address that doesn't appear on an interface,
	     ask the kernel what the socket is bound to */
	  socklen_t tcp_len = sizeof(union mysockaddr);
	  if (getsockname(listen->tftpfd, (struct sockaddr *)&addr, &tcp_len) == -1)
	    return;
	}
    }
  else
    {
      struct cmsghdr *cmptr;

      if (msg.msg_controllen < sizeof(struct cmsghdr))
        return;
      
      addr.sa.sa_family = family;
      
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
	      addr.in.sin_addr = p.p->ipi_spec_dst;
	      if_index = p.p->ipi_ifindex;
	    }
      
#elif defined(HAVE_SOLARIS_NETWORK)
      if (family == AF_INET)
	for (cmptr = CMSG_FIRSTHDR(&msg); cmptr; cmptr = CMSG_NXTHDR(&msg, cmptr))
	  {
	    union {
	      unsigned char *c;
	      struct in_addr *a;
	      unsigned int *i;
	    } p;
	    p.c = CMSG_DATA(cmptr);
	    if (cmptr->cmsg_level == IPPROTO_IP && cmptr->cmsg_type == IP_RECVDSTADDR)
	    addr.in.sin_addr = *(p.a);
	    else if (cmptr->cmsg_level == IPPROTO_IP && cmptr->cmsg_type == IP_RECVIF)
	    if_index = *(p.i);
	  }
      
#elif defined(IP_RECVDSTADDR) && defined(IP_RECVIF)
      if (family == AF_INET)
	for (cmptr = CMSG_FIRSTHDR(&msg); cmptr; cmptr = CMSG_NXTHDR(&msg, cmptr))
	  {
	    union {
	      unsigned char *c;
	      struct in_addr *a;
	      struct sockaddr_dl *s;
	    } p;
	    p.c = CMSG_DATA(cmptr);
	    if (cmptr->cmsg_level == IPPROTO_IP && cmptr->cmsg_type == IP_RECVDSTADDR)
	      addr.in.sin_addr = *(p.a);
	    else if (cmptr->cmsg_level == IPPROTO_IP && cmptr->cmsg_type == IP_RECVIF)
	      if_index = p.s->sdl_index;
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
                  
                addr.in6.sin6_addr = p.p->ipi6_addr;
                if_index = p.p->ipi6_ifindex;
              }
        }
      
      if (!indextoname(listen->tftpfd, if_index, namebuff))
	return;

      name = namebuff;
      
      if (family == AF_INET6)
	addra.addr6 = addr.in6.sin6_addr;
      else
	addra.addr4 = addr.in.sin_addr;
      
      if (daemon->tftp_interfaces)
	{
	  /* dedicated tftp interface list */
	  for (tmp = daemon->tftp_interfaces; tmp; tmp = tmp->next)
	    if (tmp->name && wildcard_match(tmp->name, name))
	      break;

	  if (!tmp)
	    return;
	}
      else
	{
	  /* Do the same as DHCP */
	  if (!iface_check(family, &addra, name, NULL))
	    {
	      if (!option_bool(OPT_CLEVERBIND))
		enumerate_interfaces(0); 
	      if (!loopback_exception(listen->tftpfd, family, &addra, name) &&
		  !label_exception(if_index, family, &addra))
		return;
	    }
	  
#ifdef HAVE_DHCP      
	  /* allowed interfaces are the same as for DHCP */
	  for (tmp = daemon->dhcp_except; tmp; tmp = tmp->next)
	    if (tmp->name && (tmp->flags & INAME_4) && (tmp->flags & INAME_6) &&
		wildcard_match(tmp->name, name))
	      return;
#endif
	}

      safe_strncpy(ifr.ifr_name, name, IF_NAMESIZE);
      if (ioctl(listen->tftpfd, SIOCGIFMTU, &ifr) != -1)
	{
	  mtu = ifr.ifr_mtu;  
	  if (daemon->tftp_mtu != 0 && daemon->tftp_mtu < mtu)
	    mtu = daemon->tftp_mtu;    
	}
    }

  /* Failed to get interface mtu - can use configured value. */
  if (mtu == 0)
    mtu = daemon->tftp_mtu;

  /* data transfer via server listening socket */
  if (option_bool(OPT_SINGLE_PORT))
    {
      int tftp_cnt;

      for (tftp_cnt = 0, transfer = daemon->tftp_trans, up = &daemon->tftp_trans; transfer; up = &transfer->next, transfer = transfer->next)
	{
	  tftp_cnt++;

	  if (sockaddr_isequal(&peer, &transfer->peer))
	    {
	      if (ntohs(*((unsigned short *)packet)) == OP_RRQ)
		{
		  /* Handle repeated RRQ or abandoned transfer from same host and port 
		     by unlinking and reusing the struct transfer. */
		  *up = transfer->next;
		  break;
		}
	      else
		{
		  handle_tftp(packet, now, transfer, len);
		  return;
		}
	    }
	}
      
      /* Enforce simultaneous transfer limit. In non-single-port mode
	 this is done by not listening on the server socket when
	 too many transfers are in progress. */
      if (!transfer && tftp_cnt >= daemon->tftp_max)
	return;
    }
  
  if (name)
    {
      /* check for per-interface prefix */ 
      for (pref = daemon->if_prefix; pref; pref = pref->next)
	if (strcmp(pref->interface, name) == 0)
	  prefix = pref->prefix;  
    }

  if (family == AF_INET)
    {
      addr.in.sin_port = htons(port);
#ifdef HAVE_SOCKADDR_SA_LEN
      addr.in.sin_len = sizeof(addr.in);
#endif
    }
  else
    {
      addr.in6.sin6_port = htons(port);
      addr.in6.sin6_flowinfo = 0;
      addr.in6.sin6_scope_id = 0;
#ifdef HAVE_SOCKADDR_SA_LEN
      addr.in6.sin6_len = sizeof(addr.in6);
#endif
    }

  /* May reuse struct transfer from abandoned transfer in single port mode. */
  if (!transfer && !(transfer = whine_malloc(sizeof(struct tftp_transfer))))
    return;

  memset(transfer, 0, sizeof(struct tftp_transfer));
	 
  if (option_bool(OPT_SINGLE_PORT))
    transfer->sockfd = listen->tftpfd;
  else if ((transfer->sockfd = socket(family, SOCK_DGRAM, 0)) == -1)
    {
      free(transfer);
      return;
    }
  
  transfer->peer = peer;
  transfer->source = addra;
  transfer->if_index = if_index;
  transfer->timeout = 2;
  transfer->start = now;
  transfer->backoff = 1;
  transfer->block = 1;
  transfer->ackprev = 0;
  transfer->block_hi = 0;
  transfer->blocksize = 512;
  transfer->windowsize = 1;
  
  (void)prettyprint_addr(&peer, daemon->addrbuff);
  
  /* if we have a nailed-down range, iterate until we find a free one. */
  while (!option_bool(OPT_SINGLE_PORT))
    {
      if (bind(transfer->sockfd, &addr.sa, sa_len(&addr)) == -1 ||
#if defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DONT)
	  setsockopt(transfer->sockfd, IPPROTO_IP, IP_MTU_DISCOVER, &mtuflag, sizeof(mtuflag)) == -1 ||
#endif
	  !fix_fd(transfer->sockfd))
	{
	  if (errno == EADDRINUSE && daemon->start_tftp_port != 0)
	    {
	      if (++port <= daemon->end_tftp_port)
		{ 
		  if (family == AF_INET)
		    addr.in.sin_port = htons(port);
		  else
		    addr.in6.sin6_port = htons(port);
		  
		  continue;
		}
	      my_syslog(MS_TFTP | LOG_ERR, _("unable to get free port for TFTP"));
	    }
	  free_transfer(transfer);
	  return;
	}
      break;
    }
  
  p = packet + 2;
  end = packet + len;

  len = 0;
  
  if (ntohs(*((unsigned short *)packet)) == OP_WRQ)
    len = tftp_err(ERR_ILL, packet, _("unsupported write request from %s"),daemon->addrbuff, NULL);
  else if (ntohs(*((unsigned short *)packet)) == OP_RRQ)
    {
      if (!(filename = next(&p, end)))
	len = tftp_err(ERR_ILL, packet, _("empty filename in request from %s"), daemon->addrbuff, NULL);
      else if (!(mode = next(&p, end)) || (strcasecmp(mode, "octet") != 0 && strcasecmp(mode, "netascii") != 0))
	len = tftp_err(ERR_ILL, packet, _("unsupported request from %s"),daemon->addrbuff, NULL);
      else
	{
	  char *opt, *arg;
	  
	  if (strcasecmp(mode, "netascii") == 0)
	    transfer->netascii = 1;
	  
	  while ((opt = next(&p, end)) && (arg = next(&p, end)))
	    {
	      unsigned int val = atoi(arg);
	      
	      if (strcasecmp(opt, "blksize") == 0 && !option_bool(OPT_TFTP_NOBLOCK))
		{
		  /* 32 bytes for IP, UDP and TFTP headers, 52 bytes for IPv6 */
		  int overhead = (family == AF_INET) ? 32 : 52;
		  if (val < 1)
		    val  = 1;
		  if (val > (unsigned)daemon->packet_buff_sz - 4)
		    val  = (unsigned)daemon->packet_buff_sz - 4;
		  if (mtu != 0 && val > (unsigned)mtu - overhead)
		    val  = (unsigned)mtu - overhead;
		  transfer->blocksize = val;
		  transfer->opt_blocksize = 1;
		  transfer->block = 0;
		}
	      else if (strcasecmp(opt, "tsize") == 0 && !transfer->netascii)
		{
		  transfer->opt_transize = 1;
		  transfer->block = 0;
		}
	      else if (strcasecmp(opt, "timeout") == 0)
		{
		  if (val > 255)
		    val = 255;
		  transfer->timeout = val;
		  transfer->opt_timeout = 1;
		  transfer->block = 0;
		}
	      else if (strcasecmp(opt, "windowsize") == 0 && !transfer->netascii)
		{
		  /* windowsize option only supported for binary transfers. */
		  if (val < 1)
		    val = 1;
		  if (val > TFTP_MAX_WINDOW)
		    val = TFTP_MAX_WINDOW;
		  transfer->windowsize = val;
		  transfer->opt_windowsize = 1;
		  transfer->block = 0;
		}
	    }
	  
	  /* cope with backslashes from windows boxen. */
	  for (p = filename; *p; p++)
	    if (*p == '\\')
	      *p = '/';
	    else if (option_bool(OPT_TFTP_LC))
	      *p = tolower((unsigned char)*p);
	  
	  strcpy(daemon->namebuff, "/");
	  if (prefix)
	    {
	      if (prefix[0] == '/')
		daemon->namebuff[0] = 0;
	      strncat(daemon->namebuff, prefix, (MAXDNAME-1) - strlen(daemon->namebuff));
	      if (prefix[strlen(prefix)-1] != '/')
		strncat(daemon->namebuff, "/", (MAXDNAME-1) - strlen(daemon->namebuff));
	      
	      if (option_bool(OPT_TFTP_APREF_IP))
		{
		  size_t oldlen = strlen(daemon->namebuff);
		  struct stat statbuf;
		  
		  strncat(daemon->namebuff, daemon->addrbuff, (MAXDNAME-1) - strlen(daemon->namebuff));
		  strncat(daemon->namebuff, "/", (MAXDNAME-1) - strlen(daemon->namebuff));
		  
		  /* remove unique-directory if it doesn't exist */
		  if (stat(daemon->namebuff, &statbuf) == -1 || !S_ISDIR(statbuf.st_mode))
		    daemon->namebuff[oldlen] = 0;
		}
	      
	      if (option_bool(OPT_TFTP_APREF_MAC))
		{
		  unsigned char *macaddr = NULL;
		  unsigned char macbuf[DHCP_CHADDR_MAX];
		  
#ifdef HAVE_DHCP
		  if (daemon->dhcp && peer.sa.sa_family == AF_INET)
		    {
		      /* Check if the client IP is in our lease database */
		      struct dhcp_lease *lease = lease_find_by_addr(peer.in.sin_addr);
		      if (lease && lease->hwaddr_type == ARPHRD_ETHER && lease->hwaddr_len == ETHER_ADDR_LEN)
			macaddr = lease->hwaddr;
		    }
#endif
		  
		  /* If no luck, try to find in ARP table. This only works if client is in same (V)LAN */
		  if (!macaddr && find_mac(&peer, macbuf, 1, now) > 0)
		    macaddr = macbuf;
		  
		  if (macaddr)
		    {
		      size_t oldlen = strlen(daemon->namebuff);
		      struct stat statbuf;
		      
		      snprintf(daemon->namebuff + oldlen, (MAXDNAME-1) - oldlen, "%.2x-%.2x-%.2x-%.2x-%.2x-%.2x/",
			       macaddr[0], macaddr[1], macaddr[2], macaddr[3], macaddr[4], macaddr[5]);
		      
		      /* remove unique-directory if it doesn't exist */
		      if (stat(daemon->namebuff, &statbuf) == -1 || !S_ISDIR(statbuf.st_mode))
			daemon->namebuff[oldlen] = 0;
		    }
		}
	      
	      /* Absolute pathnames OK if they match prefix */
	      if (filename[0] == '/')
		{
		  if (strstr(filename, daemon->namebuff) == filename)
		    daemon->namebuff[0] = 0;
		  else
		    filename++;
		}
	    }
	  else if (filename[0] == '/')
	    daemon->namebuff[0] = 0;
	  strncat(daemon->namebuff, filename, (MAXDNAME-1) - strlen(daemon->namebuff));
	  
	  /* check permissions and open file */
	  if ((transfer->file = check_tftp_fileperm(packet, &len, prefix, daemon->addrbuff)))
	    {
	      transfer->lastack = transfer->block;
	      transfer->retransmit = now + transfer->timeout;
	      /* This packet is may be the first data packet, but only if windowsize == 1
		 To get windowsize greater then one requires an option negotiation,
		 in which case this packet is the OACK. */
	      if ((len = get_block(transfer)) == -1)
		len = tftp_err_oops(packet, daemon->namebuff);
	      else
		{
		  is_err = 0;
		  /* get_block put the packet to send in a different buffer. */
		  packet = daemon->packet;
		}
	    }
	}
    }
  
  if (len)
    {
      send_from(transfer->sockfd, !option_bool(OPT_SINGLE_PORT), packet, len, &peer, &addra, if_index);
      
#ifdef HAVE_DUMPFILE
      dump_packet_udp(DUMP_TFTP, (void *)packet, len, NULL, (union mysockaddr *)&peer, transfer->sockfd);
#endif
    }
  
  if (is_err)
    free_transfer(transfer);
  else
    {
      transfer->next = daemon->tftp_trans;
      daemon->tftp_trans = transfer;
    }
}
 
/**
 * @brief Check TFTP file permissions and open file for transfer
 * 
 * @detailed Validates requested file path against security policies, checks file
 *           permissions based on running user privileges, and opens file for reading.
 *           Implements path traversal prevention, ownership verification in secure mode,
 *           and world-readable requirement when running as root. Reuses file descriptors
 *           across multiple transfers to same file (inode matching) to conserve resources
 *           during mass network boot scenarios.
 * 
 * @param packet Buffer to populate with error message if permission check fails
 * @param len Pointer to size variable; updated with error message length on failure
 * @param prefix TFTP root directory prefix for path validation (NULL means no prefix restriction)
 * @param client Client identifier string for error messages
 * 
 * @return Pointer to allocated struct tftp_file on success (with refcount=1 for new allocation
 *         or incremented for shared file descriptor), NULL on failure (with error message in packet)
 * 
 * @note File descriptor sharing: Multiple concurrent transfers to same file (matched by dev/inode/filename)
 *       share single file descriptor with reference counting to prevent fd exhaustion
 * @warning Path traversal attacks prevented by rejecting paths containing "/../" patterns
 * 
 * @see struct tftp_file in dnsmasq.h for file descriptor tracking structure
 * @see tftp_err() for error message formatting
 * 
 * EXAMPLE USAGE:
 * @code
 * ssize_t len;
 * struct tftp_file *file = check_tftp_fileperm(packet, &len, daemon->tftp_prefix, "192.168.1.10");
 * if (!file) {
 *   // Send error in packet with length len
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: Security enforcement for RFC 1350 TFTP read-only operation
 * SIDE EFFECTS: Opens file descriptor (may be shared), allocates struct tftp_file if new file
 * THREAD SAFETY: Single-threaded architecture - references global daemon state
 */
static struct tftp_file *check_tftp_fileperm(char *packet, ssize_t *len, char *prefix, char *client)
{
  char *namebuff = daemon->namebuff;
  struct tftp_file *file;
  struct tftp_transfer *t;
  uid_t uid = geteuid();
  struct stat statbuf;
  int fd = -1;

  /* trick to ban moving out of the subtree */
  if (prefix && strstr(namebuff, "/../"))
    goto perm;
  
  if ((fd = open(namebuff, O_RDONLY)) == -1)
    {
      if (errno == ENOENT)
	{
	  *len = tftp_err(ERR_FNF, packet, _("file %s not found for %s"), namebuff, client);
	  return NULL;
	}
      else if (errno == EACCES)
	goto perm;
      else
	goto oops;
    }
  
  /* stat the file descriptor to avoid stat->open races */
  if (fstat(fd, &statbuf) == -1)
    goto oops;
  
  /* running as root, must be world-readable */
  if (uid == 0)
    {
      if (!(statbuf.st_mode & S_IROTH))
	goto perm;
    }
  /* in secure mode, must be owned by user running dnsmasq */
  else if (option_bool(OPT_TFTP_SECURE) && uid != statbuf.st_uid)
    goto perm;
      
  /* If we're doing many transfers from the same file, only 
     open it once this saves lots of file descriptors 
     when mass-booting a big cluster, for instance. 
     Be conservative and only share when inode and name match
     this keeps error messages sane. */
  for (t = daemon->tftp_trans; t; t = t->next)
    if (t->file->dev == statbuf.st_dev && 
	t->file->inode == statbuf.st_ino &&
	strcmp(t->file->filename, namebuff) == 0)
      {
	close(fd);
	t->file->refcount++;
	return t->file;
      }
  
  if (!(file = whine_malloc(sizeof(struct tftp_file) + strlen(namebuff) + 1)))
    {
      errno = ENOMEM;
      goto oops;
    }

  file->fd = fd;
  file->size = statbuf.st_size;
  file->dev = statbuf.st_dev;
  file->inode = statbuf.st_ino;
  file->posn = 0;
  file->refcount = 1;
  strcpy(file->filename, namebuff);
  return file;
  
 perm:
  *len =  tftp_err(ERR_PERM, packet, _("cannot access %s: %s"), namebuff, strerror(EACCES));
  if (fd != -1)
    close(fd);
  return NULL;

 oops:
  *len =  tftp_err_oops(packet, namebuff);
  if (fd != -1)
    close(fd);
  return NULL;
}

/**
 * @brief Main TFTP event loop processing active file transfers
 * 
 * @detailed Iterates through all active TFTP transfers in daemon->tftp_trans linked list,
 * checking for timeout expiration, processing incoming ACK packets, handling retransmissions,
 * managing windowed transfer flow control, detecting transfer completion, and cleaning up
 * finished transfers. This function is called from the main event loop (check_dns_listeners()
 * in dnsmasq.c) on each poll cycle to advance the state of all concurrent TFTP sessions.
 * 
 * For each active transfer:
 * - Checks if transfer timeout (TFTP_TIMEOUT=120s) expired - closes stale transfers
 * - Polls transfer socket for incoming ACK packets using recvfrom()
 * - Validates ACK block numbers match expected sequence
 * - Advances window state for windowed transfers (windowsize option)
 * - Transmits next block(s) via get_block() when ACKs received
 * - Detects EOF condition when file exhausted
 * - Invokes do_tftp_script_run() for post-transfer script execution (HAVE_SCRIPT)
 * - Removes completed transfers from daemon->tftp_trans list via free_transfer()
 * 
 * @param now Current timestamp (seconds since epoch) for timeout checking
 * 
 * @return void (modifies daemon->tftp_trans list, sends TFTP packets to clients)
 * 
 * @note Called every poll cycle from main event loop - must not block
 * @note Handles multiple concurrent transfers through linked list iteration
 * @warning Transfer sockets are non-blocking - recvfrom() returns immediately
 * @warning Timeout enforcement prevents resource leaks from abandoned transfers
 * 
 * @see tftp_request() for transfer initialization
 * @see handle_tftp() for ACK and error packet processing
 * @see get_block() for data block transmission
 * @see free_transfer() for transfer cleanup
 * @see do_tftp_script_run() for post-transfer script execution
 * 
 * EXAMPLE USAGE:
 * @code
 * // Called from main event loop in dnsmasq.c
 * while (1) {
 *   poll(pollfds, ...);
 *   if (daemon->tftp_trans)
 *     check_tftp_listeners(time(NULL));
 * }
 * @endcode
 * 
 * RFC COMPLIANCE:
 * - RFC 1350 Section 4: Implements timeout and retransmission (120s timeout)
 * - RFC 7440: Windowed transfer with multiple outstanding blocks
 * 
 * SIDE EFFECTS:
 * - Modifies daemon->tftp_trans linked list (removes completed transfers)
 * - Closes transfer sockets and file descriptors for finished transfers
 * - Sends DATA packets to clients via sendto() on transfer sockets
 * - Executes external scripts via do_tftp_script_run() (HAVE_SCRIPT)
 * - Logs transfer completion when --log-dhcp enabled
 * 
 * THREAD SAFETY: Single-threaded event loop - modifies global daemon state
 */
void check_tftp_listeners(time_t now)
{
  /* Use workspace to receive (small) request/ACK, to avoid overwriting precomputed reply */
  char *packet = daemon->workspacename;
  ssize_t plen = MAXDNAME * 2;
  struct listener *listener;
  struct tftp_transfer *transfer, *tmp, **up;
  
  for (listener = daemon->listeners; listener; listener = listener->next)
    if (listener->tftpfd != -1 && poll_check(listener->tftpfd, POLLIN))
      tftp_request(packet, plen, listener, now);
    
  /* In single port mode, all packets come via port 69 and tftp_request() */
  if (!option_bool(OPT_SINGLE_PORT))
    for (transfer = daemon->tftp_trans; transfer; transfer = transfer->next)
      if (poll_check(transfer->sockfd, POLLIN))
	{
	  union mysockaddr peer;
	  socklen_t addr_len = sizeof(union mysockaddr);
	  ssize_t len;
	  
	  if ((len = recvfrom(transfer->sockfd, packet, plen, 0, &peer.sa, &addr_len)) > 0)
	    {
#ifdef HAVE_DUMPFILE
	      dump_packet_udp(DUMP_TFTP, (void *)packet, len, (union mysockaddr *)&peer, NULL, transfer->sockfd);
#endif	      

	      if (sockaddr_isequal(&peer, &transfer->peer)) 
		handle_tftp(packet, now, transfer, len);
	      else
		{
		  /* Wrong source address. See rfc1350 para 4. */
		  prettyprint_addr(&peer, daemon->addrbuff);
		  len = tftp_err(ERR_TID, packet, _("ignoring packet from %s (TID mismatch)"), daemon->addrbuff, NULL);
		  while(retry_send(sendto(transfer->sockfd, packet, len, 0, &peer.sa, sa_len(&peer))));

#ifdef HAVE_DUMPFILE
		  dump_packet_udp(DUMP_TFTP, (void *)packet, len, NULL, (union mysockaddr *)&peer, transfer->sockfd);
#endif
		}
	    }
	}
	  
  for (transfer = daemon->tftp_trans, up = &daemon->tftp_trans; transfer; transfer = tmp)
    {
      int endcon = 0, error = 0, timeout = 0;
      
      tmp = transfer->next;
            
      /* ->start set to zero in handle_tftp() when we recv an error packet. */
      if (transfer->start == 0)
	endcon = error = 1;
      else if (difftime(now, transfer->start) > TFTP_TRANSFER_TIME)  
	{
	  endcon = 1;
	  /* don't complain about timeout when we're awaiting the last
	     ACK, some clients never send it */
	  if (get_block(transfer) > 0)
	    error = timeout = 1;
	}
      else if (difftime(now, transfer->retransmit) >= 0.0)
	{
	  /* Do transmission or re-transmission. When we get an ACK, the call to handle_tftp()
	     bumps transfer->lastack and trips the retransmit timer so that we send the next block(s)
	     here. */
	  ssize_t len;
	  unsigned int i, winsize;
	  
	  transfer->retransmit += transfer->timeout + (1<<(transfer->backoff/2));
	  transfer->backoff++;
	  transfer->block = transfer->lastack;
	  
	  /* send a window'a worth of blocks unless we're retransmitting OACK */
	  winsize = transfer->block ? transfer->windowsize : 1;
	  
	  for (i = 0; i < winsize; i++, transfer->block++)
	    {
	      if ((len = get_block(transfer)) == 0)
		{
		  if (i == 0)
		    endcon = 1; /* got last ACK */

		  break;
		}
	      
	      if (len == -1)
		{
		  len = tftp_err_oops(daemon->packet, transfer->file->filename);
		  endcon = error = 1;
		}
	      
	      send_from(transfer->sockfd, !option_bool(OPT_SINGLE_PORT), daemon->packet, len,
			&transfer->peer, &transfer->source, transfer->if_index);
#ifdef HAVE_DUMPFILE
	      dump_packet_udp(DUMP_TFTP, (void *)daemon->packet, len, NULL, (union mysockaddr *)&transfer->peer, transfer->sockfd);
#endif
	    }
	  
	  /* prefetch the block we'll probably need when we get an ACK. */
	  if (!endcon)
	    get_block(transfer);
	}
		      
      if (endcon)
	{
	  strcpy(daemon->namebuff, transfer->file->filename);
	  sanitise(daemon->namebuff);
	  (void)prettyprint_addr(&transfer->peer, daemon->addrbuff);
	  if (timeout)
	    my_syslog(MS_TFTP | LOG_ERR, _("timeout sending %s to %s"), daemon->namebuff, daemon->addrbuff);
	  else if (error)
	    my_syslog(MS_TFTP | LOG_ERR, _("failed sending %s to %s"), daemon->namebuff, daemon->addrbuff);
	  else
	    my_syslog(MS_TFTP | LOG_INFO, _("sent %s to %s"), daemon->namebuff, daemon->addrbuff);
	  
	  /* unlink */
	  *up = tmp;
	  if (error)
	    free_transfer(transfer);
	  else
	    {
	      /* put on queue to be sent to script and deleted */
	      transfer->next = daemon->tftp_done_trans;
	      daemon->tftp_done_trans = transfer;
	    }
	}
      else
	up = &transfer->next;
    }
}

/**
 * @brief Process TFTP ACK and ERROR packets for active transfer
 * 
 * @detailed Handles incoming ACK packets by advancing transfer window state, managing
 * 16-bit block number wrap-around for large files (>32MB with 512-byte blocks), updating
 * file offset for netascii mode line break expansion tracking, and resetting retransmit
 * timers. Also processes ERROR packets from client by logging error details and marking
 * transfer for abort. Implements duplicate ACK detection and out-of-order ACK handling
 * for UDP packet reordering scenarios.
 * 
 * For ACK packets:
 * - Converts 16-bit block number to 32-bit with wrap-around detection (block_hi tracking)
 * - Ignores duplicate ACKs (block < lastack) and premature ACKs (block > sent blocks)
 * - Updates transfer->lastack to advance send window
 * - Resets retransmit timer (transfer->retransmit = now, backoff = 0)
 * - Updates file offset for netascii mode transfers accounting for CR-LF expansion
 * 
 * For ERROR packets:
 * - Extracts error code and message string from packet
 * - Sanitizes error message to prevent log injection
 * - Logs error with client address to syslog (MS_TFTP | LOG_ERR)
 * - Sets transfer->start = 0 to trigger abort in check_tftp_listeners()
 * 
 * @param packet Buffer containing received TFTP packet (ACK or ERROR)
 * @param now Current timestamp for retransmit timer reset
 * @param transfer Active transfer state to update
 * @param len Length of received packet in bytes
 * 
 * @return void (modifies transfer state in-place)
 * 
 * @note Called from check_tftp_listeners() when transfer socket has data ready
 * @note Minimum packet length (sizeof(struct ack) = 4 bytes) enforced
 * @warning Ignores packets <4 bytes to prevent buffer underflow
 * @warning 16-bit wrap-around assumes sequential ACKs (non-adversarial client)
 * 
 * @see check_tftp_listeners() for main transfer event loop
 * @see get_block() for data transmission after ACK processing
 * @see next() for null-terminated string extraction from error messages
 * @see sanitise() for error message sanitization
 * 
 * EXAMPLE USAGE:
 * @code
 * char packet[TFTP_MTU];
 * ssize_t len = recvfrom(transfer->sockfd, packet, sizeof(packet), 0, NULL, NULL);
 * if (len > 0)
 *   handle_tftp(packet, time(NULL), transfer, len);
 * @endcode
 * 
 * RFC COMPLIANCE:
 * - RFC 1350 Section 5: ACK packet format (opcode=4, block number)
 * - RFC 1350 Section 5: ERROR packet format (opcode=5, error code, message)
 * 
 * SIDE EFFECTS:
 * - Modifies transfer->lastack, transfer->retransmit, transfer->backoff
 * - Updates transfer->offset and transfer->expansion for netascii mode
 * - Increments/decrements transfer->block_hi for 16-bit wrap-around tracking
 * - Sets transfer->start = 0 on ERROR to trigger abort
 * - Logs ERROR packets to syslog with MS_TFTP facility
 * 
 * THREAD SAFETY: Single-threaded event loop - modifies transfer state
 */
static void handle_tftp(char *packet, time_t now, struct tftp_transfer *transfer, ssize_t len)
{
  struct ack {
    unsigned short op, block;
  } *mess = (struct ack *)packet;
  
  if (len >= (ssize_t)sizeof(struct ack))
    {
      if (ntohs(mess->op) == OP_ACK)
	{
	  /* Handle 16-bit block number wrap-around. */
	  u16 new = ntohs(mess->block);
	  u32 block;

	  /* If the last ack received was in the top quarter of a 64k block
	     and this one is in the bottom quarter, assume it has wrapped.
	     
	     Since this is UDP and an old packet can in theory wander in we may also
	     need to drop back to a previous segment. Such an ACK is ignored below;
	     here we're just getting the most likely 32 bit value from the
	     16 bits that we have. */
	  if (new <= 0x4000 && transfer->ackprev >= 0xc000)
	    transfer->block_hi++;
	  else if (new >= 0xc000 && transfer->ackprev <= 0x4000 && transfer->block_hi != 0)
	    transfer->block_hi--;

	  transfer->ackprev = new;
	  block = (((u32)transfer->block_hi) << 16) + (u32)new;

	  /* Ignore duplicate ACKs and ACKs for blocks we've not yet sent. */
	  if (block >= transfer->lastack &&
	      block <= transfer->block) 
	    {
	      /* Got ack, move forward and ensure we take the (re)transmit path */
	      transfer->retransmit = transfer->start = now;
	      transfer->backoff = 0;
	      transfer->lastack = block + 1;

	      /* We have no easy function from block no. to file offset when
		 expanding line breaks in netascii mode, so we update the offset here
		 as each block is acknowledged. This explains why the window size must be
		 one for a netascii transfer; to avoid  the block no. doing anything
		 other than incrementing by one. */
	      if (transfer->netascii && block != 0)
		{
		  transfer->offset +=  (off_t)transfer->blocksize - (off_t)transfer->expansion;
		  transfer->lastcarrylf = transfer->carrylf;
		}
	    }
	}
      else if (ntohs(mess->op) == OP_ERR)
	{
	  char *p = packet + sizeof(struct ack);
	  char *end = packet + len;
	  char *err = next(&p, end);
	  
	  (void)prettyprint_addr(&transfer->peer, daemon->addrbuff);
	  
	  /* Sanitise error message */
	  if (!err)
	    err = "";
	  else
	    sanitise(err);
	  
	  my_syslog(MS_TFTP | LOG_ERR, _("error %d %s received from %s"),
		    (int)ntohs(mess->block), err, 
		    daemon->addrbuff);	
	  
	  /* Got err, ensure we take abort */
	  transfer->start = 0;
	}
    }
}

/**
 * @brief Free TFTP transfer structure and associated resources
 * 
 * @detailed Deallocates transfer structure and optionally closes file descriptor and socket.
 *           Implements reference counting for file descriptors: only closes the file
 *           when refcount reaches zero, as multiple concurrent transfers may share
 *           the same file descriptor (see check_tftp_fileperm for fd sharing logic).
 *           In multi-port mode (OPT_SINGLE_PORT disabled), also closes the transfer's
 *           dedicated socket; in single-port mode, socket is shared and not closed here.
 * 
 * @param transfer Pointer to struct tftp_transfer to deallocate (must not be NULL)
 * 
 * @return void
 * 
 * @note File descriptor sharing: Multiple transfers to same file share fd with refcount;
 *       fd closed only when last transfer completes
 * @note Socket management: Multi-port mode uses dedicated socket per transfer (closed here);
 *       single-port mode shares one socket across all transfers (not closed here)
 * @warning Called during transfer completion, timeout, or error cleanup; must not be
 *          called twice on same transfer (double-free vulnerability)
 * 
 * @see check_tftp_fileperm() for file descriptor allocation and refcount initialization
 * @see struct tftp_transfer in dnsmasq.h for transfer state structure
 * 
 * EXAMPLE USAGE:
 * @code
 * struct tftp_transfer *transfer = daemon->tftp_done_trans;
 * daemon->tftp_done_trans = transfer->next;
 * free_transfer(transfer); // Cleans up transfer and decrements file refcount
 * @endcode
 * 
 * RFC COMPLIANCE: Resource cleanup for RFC 1350 TFTP connection termination
 * SIDE EFFECTS: Closes file descriptor if refcount reaches zero, closes socket in multi-port mode, deallocates memory
 * THREAD SAFETY: Single-threaded architecture - no locking required
 */
static void free_transfer(struct tftp_transfer *transfer)
{
  if (!option_bool(OPT_SINGLE_PORT))
    close(transfer->sockfd);

  if (transfer->file && (--transfer->file->refcount) == 0)
    {
      close(transfer->file->fd);
      free(transfer->file);
    }
  
  free(transfer);
}

/**
 * @brief Extract next null-terminated string from TFTP packet buffer
 * 
 * @detailed Parses null-terminated strings from TFTP request packets (RRQ/WRQ) where
 *           multiple fields (filename, mode, option names, option values) are stored
 *           as consecutive null-terminated strings per RFC 1350 format. Advances the
 *           parse pointer *p to the position after the extracted string. Returns NULL
 *           if buffer boundary is reached before finding null terminator (malformed packet)
 *           or if string has zero length (empty field is invalid per TFTP protocol).
 * 
 * @param p Pointer to parse position pointer (modified to advance past extracted string)
 * @param end Pointer to end of packet buffer (boundary for bounds checking)
 * 
 * @return Pointer to start of extracted null-terminated string, or NULL if:
 * @retval NULL Packet boundary reached before null terminator (buffer overrun)
 * @retval NULL Zero-length string encountered (p == ret, invalid empty field)
 * @retval char* Valid null-terminated string from packet buffer
 * 
 * @note String extraction: Returns pointer to original buffer location, does not copy
 * @note Parse pointer advance: *p updated to point past null terminator (n+1)
 * @warning Malformed packet detection: NULL return indicates protocol violation; caller
 *          must abort request processing and send ERR_ILL (illegal TFTP operation)
 * 
 * @see tftp_request() uses this to parse filename, mode, and option fields from RRQ packets
 * @see handle_tftp() uses this to parse OACK option responses
 * 
 * EXAMPLE USAGE:
 * @code
 * char *p = packet + 2; // Skip opcode
 * char *end = packet + len;
 * char *filename = next(&p, end); // Extract filename
 * char *mode = next(&p, end);     // Extract transfer mode
 * if (!filename || !mode) {
 *   len = tftp_err(ERR_ILL, packet, "Malformed packet", filename, NULL);
 *   return;
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 1350 Section 5 - RRQ/WRQ packet format with null-terminated strings
 * SIDE EFFECTS: Modifies *p to advance parse position past extracted string
 * THREAD SAFETY: Single-threaded architecture - operates on caller's local buffer
 */
static char *next(char **p, char *end)
{
  char *n, *ret = *p;
  
  /* Look for end of string, without running off the end of the packet. */
  for (n = *p; n < end && *n != 0; n++);

  /* ran off the end or zero length string - failed */
  if (n == end || n == ret)
    return NULL;
  
  *p = n + 1;
  return ret;
}

/**
 * @brief Remove non-printable characters from string to prevent log injection attacks
 * 
 * @detailed Filters out non-printable characters from null-terminated strings by copying
 *           only printable characters (isprint() test) to form sanitized output. Used
 *           primarily for sanitizing filenames before logging or inclusion in error messages,
 *           preventing log injection attacks where malicious filenames containing control
 *           characters (newlines, escape sequences) could corrupt log files or terminals.
 *           Implements in-place filtering: if no sanitization needed, buffer unchanged
 *           (allows passing read-only string constants safely); if sanitization required,
 *           modifies buffer with printable-only content. Uses two-pointer technique:
 *           read pointer (r) scans input, write pointer (q) builds sanitized output.
 * 
 * @param buf Pointer to null-terminated string to sanitize (may be read-only if no changes needed)
 * 
 * @return void (modifies buf in-place only if non-printable characters found)
 * 
 * @note Read-only safety: If string contains only printable characters, buffer not modified
 *       (allows passing string literals safely)
 * @note In-place operation: Sanitized output overwrites input buffer when filtering needed
 * @note Character test: Uses isprint() to identify printable ASCII/locale characters
 * @warning Security critical: Must be called on all user-controlled strings before logging
 *          or error message construction to prevent log injection attacks
 * 
 * @see tftp_err() calls this on filename parameter before including in error messages
 * @see tftp_err_oops() calls this on filename before logging errors
 * 
 * EXAMPLE USAGE:
 * @code
 * char filename[] = "boot.img\n\033[1;31mFAKE LOG ENTRY\033[0m";
 * sanitise(filename); // Removes newline and ANSI escape sequences
 * // Result: "boot.imgFAKE LOG ENTRY" (control chars stripped)
 * my_syslog(LOG_ERR, "TFTP error accessing %s", filename); // Safe logging
 * @endcode
 * 
 * RFC COMPLIANCE: Security best practice for TFTP filename handling (not in RFC 1350)
 * SIDE EFFECTS: Modifies buf in-place if non-printable characters present; no-op if all printable
 * THREAD SAFETY: Single-threaded architecture - operates on caller's buffer
 */
/* If we don't do anything, don't write the the input/ouptut
   buffer. This allows us to pass in safe read-only strings constants. */
static void sanitise(char *buf)
{
  unsigned char *q, *r;

  for (q = r = (unsigned char *)buf; *r; r++)
    if (isprint((int)*r))
      {
	if (q != r)
	  *q = *r;
	q++;
      }
  
  if (q != r)
    *q = 0;
}

/**
 * @brief Construct TFTP ERROR packet and log error message
 * 
 * @detailed Builds TFTP ERROR packet (opcode 5, OP_ERR) per RFC 1350 Section 5 with error code
 *           and human-readable error message. Formats error message with printf-style substitution
 *           of file and arg2 parameters into message template. Sanitizes filename parameter to
 *           prevent log injection attacks before including in message. Logs error to syslog unless
 *           error is ERR_FNF (file not found) and OPT_QUIET_TFTP is enabled. ERROR packet format:
 *           2 bytes opcode (5), 2 bytes error code, variable-length null-terminated message string.
 *           Message limited to MAXMESSAGE (500 bytes) ensuring total packet size <512 bytes
 *           (standard TFTP packet size limit).
 * 
 * @param err TFTP error code: ERR_NOTDEF (0, undefined), ERR_FNF (1, file not found),
 *            ERR_PERM (2, access violation), ERR_FULL (3, disk full), ERR_ILL (4, illegal operation),
 *            ERR_TID (5, unknown transfer ID)
 * @param packet Pointer to packet buffer to fill with ERROR packet (minimum 512 bytes)
 * @param message Printf-style format string for error message (may contain %s placeholders)
 * @param file Filename to substitute into message format (sanitized before use; may be NULL)
 * @param arg2 Second argument to substitute into message format (typically strerror or NULL)
 * 
 * @return Size in bytes of constructed ERROR packet (including opcode, error code, message, null terminator)
 * @retval ssize_t Packet size: 4 bytes (op+err) + message length + 1 (null terminator), max 504 bytes
 * 
 * @note Message truncation: If formatted message exceeds MAXMESSAGE, truncated to fit packet size
 * @note Logging suppression: File-not-found errors not logged when OPT_QUIET_TFTP enabled (reduces log noise)
 * @note Filename sanitization: Calls sanitise(file) to strip non-printable characters before inclusion
 * @warning Packet buffer: Caller must provide buffer ≥512 bytes to accommodate ERROR packet
 * 
 * @see sanitise() for filename sanitization preventing log injection
 * @see tftp_err_oops() convenience wrapper for errno-based error messages
 * @see check_tftp_fileperm() for typical usage sending permission/access errors
 * 
 * EXAMPLE USAGE:
 * @code
 * // Send "file not found" error
 * ssize_t len = tftp_err(ERR_FNF, packet, _("file %s not found"), filename, NULL);
 * sendto(sockfd, packet, len, 0, &peer, sa_len(&peer));
 * 
 * // Send permission error with errno details
 * len = tftp_err(ERR_PERM, packet, _("cannot read %s: %s"), file, strerror(errno));
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 1350 Section 5 - ERROR packet format with opcode 5, error code, message
 * SIDE EFFECTS: Modifies packet buffer with ERROR packet; sanitizes file parameter in-place; logs to syslog
 * THREAD SAFETY: Single-threaded architecture - operates on caller's packet buffer
 */
#define MAXMESSAGE 500 /* limit to make packet < 512 bytes and definitely smaller than buffer */ 
static ssize_t tftp_err(int err, char *packet, char *message, char *file, char *arg2)
{
  struct errmess {
    unsigned short op, err;
    char message[];
  } *mess = (struct errmess *)packet;
  ssize_t len, ret = 4;

  if (file)
    sanitise(file);
  
  mess->op = htons(OP_ERR);
  mess->err = htons(err);
  len = snprintf(mess->message, MAXMESSAGE,  message, file, arg2);
  ret += (len < MAXMESSAGE) ? len + 1 : MAXMESSAGE; /* include terminating zero */
  
  if (err != ERR_FNF || !option_bool(OPT_QUIET_TFTP))
    my_syslog(MS_TFTP | LOG_ERR, "%s", mess->message);
  
  return  ret;
}

/**
 * @brief Convenience wrapper to send TFTP ERROR for file read failures with errno
 * 
 * @detailed Constructs TFTP ERROR packet for file read failures (open, read, stat errors) by
 *           calling tftp_err() with ERR_NOTDEF error code and errno-based error message.
 *           Uses strerror(errno) to convert current errno value to human-readable message
 *           explaining underlying system error (e.g., "Permission denied", "No such file").
 *           Safely copies filename to daemon->namebuff to avoid mangling the original string
 *           when multiple references to the same filename exist. If file already points to
 *           daemon->namebuff, avoids unnecessary copy. ERR_NOTDEF (error code 0) used for
 *           generic "undefined error" category per RFC 1350, with error message providing
 *           specifics.
 * 
 * @param packet Pointer to packet buffer for ERROR packet construction (minimum 512 bytes)
 * @param file Filename that caused error (const, will be copied to daemon->namebuff before use)
 * 
 * @return Size in bytes of constructed ERROR packet
 * @retval ssize_t Packet size returned from tftp_err() (typically 4 + message length + 1)
 * 
 * @note errno dependency: Uses global errno variable set by failed system call (open, read, stat)
 * @note ERR_NOTDEF usage: Generic error code 0 for "Not defined, see error message" per RFC 1350
 * @note daemon->namebuff usage: Copies filename to global buffer to safely pass mutable string
 *       to tftp_err sanitization without affecting original filename references
 * @warning Must be called immediately after system call failure while errno still valid
 * 
 * @see tftp_err() for ERROR packet construction and logging
 * @see check_tftp_fileperm() typical caller after open() failures
 * @see get_block() calls this after read() failures
 * 
 * EXAMPLE USAGE:
 * @code
 * int fd = open(filename, O_RDONLY);
 * if (fd == -1) {
 *   ssize_t len = tftp_err_oops(packet, filename); // Uses errno from open failure
 *   sendto(sockfd, packet, len, 0, &peer, sa_len(&peer));
 *   return;
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 1350 Section 5 - ERROR packet with code 0 (Not defined) and message
 * SIDE EFFECTS: Reads errno, modifies daemon->namebuff, constructs ERROR packet, logs error
 * THREAD SAFETY: Single-threaded architecture - errno and daemon->namebuff are safe
 */
static ssize_t tftp_err_oops(char *packet, const char *file)
{
  /* May have >1 refs to file, so potentially mangle a copy of the name */
  if (file != daemon->namebuff)
    strcpy(daemon->namebuff, file);
  return tftp_err(ERR_NOTDEF, packet, _("cannot read %s: %s"), daemon->namebuff, strerror(errno));
}

/* return -1 for error, zero for done. */
/**
 * @brief Construct TFTP packet (OACK or DATA) for current block number in transfer
 * 
 * @detailed Generates appropriate TFTP packet based on transfer->block value: for block 0,
 *           constructs OACK (Option Acknowledgment) packet with negotiated options (blksize,
 *           tsize, timeout, windowsize per RFC 2349/7440); for block >= 1, constructs DATA
 *           packet with file contents. Implements critical optimizations: prefetch cache
 *           reuses packet buffer if already containing requested block (avoids redundant
 *           disk I/O), netascii mode performs Unix-to-TFTP line ending conversion (LF to CR-LF
 *           per RFC 1350), and file positioning uses lseek for random access to support
 *           block retransmissions. Returns positive packet size for normal operation, 0 when
 *           transfer complete (offset exceeds file size), -1 on file read errors.
 * 
 * @param transfer Pointer to struct tftp_transfer containing state (block number, options,
 *                 file descriptor, offset, blocksize, mode flags); must not be NULL
 * 
 * @return Packet size in bytes, 0 for completion, or -1 for errors
 * @retval >0 Size of constructed packet in daemon->packet buffer (OACK: variable, DATA: 4+data)
 * @retval 0 Transfer complete - offset exceeds file size, final block already sent
 * @retval -1 File read error - lseek failed or read_write failed (errno set by system call)
 * 
 * @note Block 0 handling: OACK construction encodes option names and values as null-terminated
 *       strings per RFC 2347, including only options negotiated during RRQ (flags opt_blocksize,
 *       opt_transize, opt_timeout, opt_windowsize control inclusion). Packet buffer cleared
 *       with memset before OACK construction for clean option encoding.
 * @note Block >= 1 handling: DATA packet contains 2-byte opcode OP_DATA (3), 2-byte block number,
 *       followed by up to blocksize bytes of file data; last block identified by size < blocksize
 * @note Netascii offset calculation: In netascii mode, transfer->offset not recalculated from
 *       block number due to variable-length CR-LF expansion; offset tracked incrementally instead
 * @note Binary offset calculation: In binary mode, offset = (block - 1) * blocksize for random
 *       access support (allows block retransmissions without sequential reads)
 * @note Prefetch cache: Static variables saved_offset and saved_len track last constructed packet;
 *       if requested block already in buffer (daemon->srv_save == transfer && saved_offset matches),
 *       returns saved_len immediately (ACK retransmission optimization avoids redundant disk reads)
 * @note Netascii CR-LF conversion: Scans data for LF bytes ('\\n'), inserts CR before each LF
 *       using memmove to shift remaining data; transfer->expansion counts inserted CRs,
 *       transfer->carrylf tracks LF at block boundary requiring CR in next block
 * @warning Overwrites daemon->packet buffer; caller must send packet before next get_block call
 * @warning File descriptor shared via refcount - multiple transfers may reference same fd
 * @warning Netascii expansion may cause block size to exceed transfer->blocksize temporarily
 *          when final LF in full block requires CR insertion (carrylf flag defers to next block)
 * 
 * @see handle_tftp() calls get_block for initial packet and retransmissions
 * @see struct tftp_transfer in dnsmasq.h for state fields (block, offset, blocksize, opt_* flags)
 * @see read_write() in util.c for reliable file reading with interrupt handling
 * 
 * EXAMPLE USAGE:
 * @code
 * struct tftp_transfer *transfer = ...;
 * transfer->block = 1; // Request first data block
 * ssize_t len = get_block(transfer);
 * if (len > 0) {
 *   sendto(transfer->sockfd, daemon->packet, len, 0, &transfer->peer, sa_len(&transfer->peer));
 * } else if (len == 0) {
 *   my_syslog(LOG_INFO, "TFTP transfer complete");
 * } else {
 *   my_syslog(LOG_ERR, "TFTP read error: %s", strerror(errno));
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 1350 Section 5 (DATA packet format, netascii mode CR-LF conversion),
 *                 RFC 2347 Section 2 (OACK packet format with option strings),
 *                 RFC 2349 (blksize, tsize, timeout options),
 *                 RFC 7440 (windowsize option)
 * SIDE EFFECTS: Constructs packet in daemon->packet global buffer, updates transfer->offset
 *               (binary mode only), updates transfer->expansion/carrylf/lastcarrylf (netascii),
 *               updates transfer->file->posn for sequential read optimization, updates
 *               daemon->srv_save for prefetch cache and static saved_offset/saved_len, performs
 *               file I/O (lseek, read via read_write), clears packet buffer with memset for OACK
 * THREAD SAFETY: Single-threaded architecture - daemon->packet and srv_save globals, plus static
 *                saved_offset/saved_len variables are safe in single-threaded event loop
 */
static ssize_t get_block(struct tftp_transfer *transfer)
{
  static off_t saved_offset = 0;
  static ssize_t saved_len = 0;

  if (transfer->block == 0)
    {
      /* send OACK */
      char *p;
      struct oackmess {
	unsigned short op;
	char data[];
      } *mess = (struct oackmess *)daemon->packet;

      /* we overwrote the buffer... */
      daemon->srv_save = NULL;
      memset(daemon->packet, 0, daemon->packet_buff_sz);
            
      p = mess->data;
      mess->op = htons(OP_OACK);
      if (transfer->opt_blocksize)
	{
	  p += (sprintf(p, "blksize") + 1);
	  p += (sprintf(p, "%u", transfer->blocksize) + 1);
	}
      if (transfer->opt_transize)
	{
	  p += (sprintf(p,"tsize") + 1);
	  p += (sprintf(p, "%u", (unsigned int)transfer->file->size) + 1);
	}
      if (transfer->opt_timeout)
	{
	  p += (sprintf(p,"timeout") + 1);
	  p += (sprintf(p, "%u", transfer->timeout) + 1);
	}
      if (transfer->opt_windowsize)
	{
	  p += (sprintf(p,"windowsize") + 1);
	  p += (sprintf(p, "%u", (unsigned int)transfer->windowsize) + 1);
	}
 
      return p - daemon->packet;
    }
  else
    {
      /* send data packet */
      struct datamess {
	unsigned short op, block;
	unsigned char data[];
      } *mess = (struct datamess *)daemon->packet;
      
      size_t size;
      
      if (!transfer->netascii)
	transfer->offset = (off_t)(transfer->block - 1) * (off_t)transfer->blocksize;
      
      if (transfer->offset > transfer->file->size)
	return 0; /* finished */

      /* We may have a prefetched block already in the buffer. */
      if (daemon->srv_save == transfer && saved_offset == transfer->offset)
	return saved_len;
	
      /* we overwrote the buffer... */
      daemon->srv_save = NULL;

      if ((size = transfer->file->size - transfer->offset) > (size_t)transfer->blocksize)
	size = (size_t)transfer->blocksize;
      
      mess->op = htons(OP_DATA);
      mess->block = htons((unsigned short)(transfer->block));

      if (size != 0)
	{
	  if (transfer->file->posn != transfer->offset &&
	      lseek(transfer->file->fd, transfer->offset, SEEK_SET) == (off_t)-1)
	    return -1;

	  if (!read_write(transfer->file->fd, mess->data, size, RW_READ))
	    return -1;

	  transfer->file->posn = transfer->offset + size;
	}

      /* Map '\n' to CR-LF in netascii mode */
      if (transfer->netascii)
	{
	  size_t i;
	  	  
	  /* Map '\n' to CR-LF in netascii mode */
	  transfer->expansion = transfer->carrylf = 0;
	  
	  for (i = 0; i < size; i++)
	    if (mess->data[i] == '\n' && (i != 0 || !transfer->lastcarrylf))
	      {
		transfer->expansion++;

		if (size != transfer->blocksize)
		  size++; /* room in this block */
		else  if (i == size - 1)
		  transfer->carrylf = 1; /* don't expand LF again if it moves to the next block */
		  
		/* make space and insert CR */
		memmove(&mess->data[i+1], &mess->data[i], size - (i + 1));
		mess->data[i] = '\r';
		
		i++;
	      }
	}

      daemon->srv_save = transfer;
      saved_offset = transfer->offset;
      saved_len = size + 4;

      return saved_len;
    }
}


/**
 * @brief Process one completed TFTP transfer and invoke script notification if configured
 * 
 * @detailed Processes completed TFTP transfers from daemon->tftp_done_trans linked list,
 *           invoking external script notification (via queue_tftp in helper.c) when HAVE_SCRIPT
 *           compile flag enabled, and freeing transfer resources. Called iteratively from main
 *           event loop (dnsmasq.c) to drain completed transfer queue without blocking packet
 *           processing. Each invocation processes single transfer, returning 1 if transfer
 *           processed or 0 if queue empty, allowing event loop to interleave script notifications
 *           with other daemon activities. Transfer marked complete by handle_tftp when final
 *           ACK received (all blocks acknowledged) or transfer timeout/error occurs, moving
 *           transfer from active list to daemon->tftp_done_trans queue. Script notification
 *           passes transfer metadata (file size, filename, client peer address) to configured
 *           script (dhcp-script option) with "tftp" action keyword, enabling administrators
 *           to implement custom logging, auditing, or integration workflows for TFTP transfers.
 * 
 * @return 1 if transfer processed, 0 if no transfers pending
 * @retval 1 Transfer dequeued from daemon->tftp_done_trans, script queued (if HAVE_SCRIPT),
 *           resources freed via free_transfer - caller should invoke again to process next
 * @retval 0 No completed transfers in queue - daemon->tftp_done_trans is NULL, caller should
 *           return to event loop and wait for next TFTP activity
 * 
 * @note Called iteratively from main event loop: while (do_tftp_script_run()) allows processing
 *       all completed transfers without blocking, as each call processes single transfer
 * @note Transfer completion sources: (1) successful transfer - all blocks sent and ACKed,
 *       (2) client timeout - no response to DATA/OACK within transfer->timeout * retries,
 *       (3) error conditions - file read error, network error, or client-sent ERROR packet
 * @note Script execution conditional: queue_tftp call enclosed in #ifdef HAVE_SCRIPT, so
 *       script notification only occurs when daemon compiled with --enable-script or COPTS=-DHAVE_SCRIPT
 * @note Script receives: transfer->file->size (bytes transferred), transfer->file->filename
 *       (requested filename from RRQ packet, sanitized), transfer->peer (client sockaddr)
 * @note Transfer removal: daemon->tftp_done_trans = transfer->next unlinks transfer from queue
 *       head before script queuing and free, preventing duplicate processing if script blocks
 * @warning Queue operations not thread-safe - relies on single-threaded event loop architecture
 * @warning Script queuing may fail if helper process queue full - queue_tftp logs warning but
 *          does not affect transfer cleanup (transfer freed regardless of queue success)
 * @warning Transfer freed after script queuing - script must not retain transfer pointer, only
 *          copies metadata passed as queue_tftp arguments
 * 
 * @see handle_tftp() marks transfers complete and appends to daemon->tftp_done_trans
 * @see queue_tftp() in helper.c queues script execution with transfer metadata
 * @see free_transfer() releases all transfer resources including file descriptor and memory
 * @see struct tftp_transfer in dnsmasq.h for transfer state (file, peer, next pointer)
 * @see daemon->tftp_done_trans in dnsmasq.h for completed transfer queue head
 * 
 * EXAMPLE USAGE:
 * @code
 * // Main event loop in dnsmasq.c
 * while (1) {
 *   // ... process network events (DNS, DHCP, TFTP) ...
 *   
 *   // Process completed TFTP transfers and invoke scripts
 *   while (do_tftp_script_run())
 *     ; // Drain queue until empty
 *   
 *   // ... continue event loop ...
 * }
 * 
 * // Alternatively, process one transfer per event loop iteration:
 * if (do_tftp_script_run()) {
 *   // One transfer processed, more may be pending
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (script notification is dnsmasq-specific extension, not TFTP protocol)
 * SIDE EFFECTS: Modifies daemon->tftp_done_trans (removes head element), invokes queue_tftp
 *               which may fork helper process and execute external script (HAVE_SCRIPT), calls
 *               free_transfer which closes file descriptor and deallocates transfer memory
 * THREAD SAFETY: Single-threaded architecture - daemon->tftp_done_trans global queue safe in
 *                event loop; queue_tftp may fork helper process which executes concurrently
 *                but with separate memory space (no shared state)
 */
int do_tftp_script_run(void)
{
  struct tftp_transfer *transfer;

  if ((transfer = daemon->tftp_done_trans))
    {
      daemon->tftp_done_trans = transfer->next;
#ifdef HAVE_SCRIPT
      queue_tftp(transfer->file->size, transfer->file->filename, &transfer->peer);
#endif
      free_transfer(transfer);
      return 1;
    }

  return 0;
}
#endif

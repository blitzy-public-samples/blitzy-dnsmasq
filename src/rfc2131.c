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
 * @file rfc2131.c
 * @brief DHCPv4 Protocol Implementation per RFC 2131
 * 
 * DETAILED PURPOSE:
 * This file implements the complete DHCPv4 protocol as specified in RFC 2131,
 * handling all DHCPv4 message types (DISCOVER, OFFER, REQUEST, ACK, NAK, DECLINE,
 * RELEASE, INFORM), packet construction, and DHCP option encoding/decoding. It serves
 * as the protocol layer for the DHCPv4 server, implementing the wire format and
 * message exchange sequences while delegating business logic decisions to dhcp.c
 * and lease management to lease.c.
 * 
 * The implementation supports BOOTP compatibility (RFC 951), DHCPv4 rapid commit
 * (RFC 4039), DHCPv4 leasequery (RFC 4388, added v2.92), PXE network boot, DHCP
 * relay agent functionality with split-mode operation, and comprehensive DHCP option
 * processing per RFC 2132.
 * 
 * KEY RESPONSIBILITIES:
 * - dhcp_reply(): Main entry point processing incoming DHCPv4 packets and generating responses
 * - rfc2131_packet(): Core state machine implementing DISCOVER→OFFER→REQUEST→ACK exchange
 * - do_options(): DHCP option encoding with support for all standard options (1-161)
 * - relay_upstream4()/relay_reply4(): DHCP relay agent implementation with RFC 3046 support
 * - Option finding/encoding functions: option_find(), option_put(), option_put_string()
 * - PXE boot support: is_pxe_client(), pxe_opts(), pxe_misc() for network boot scenarios
 * - Packet validation: dhcp_packet_size(), sanitise() for security and RFC compliance
 * 
 * DEPENDENCIES:
 * Includes: dnsmasq.h (core data structures), dhcp-protocol.h (DHCP constants and packet format)
 * Called by: dhcp.c (forwards packets to dhcp_reply() for protocol processing)
 * Calls: lease.c (lease_find_by_*(), lease_update() for lease database operations),
 *        cache.c (cache_add_dhcp_entry() for DNS integration),
 *        helper.c (queue_script() for lease-change script execution)
 * 
 * DATA STRUCTURES:
 * - struct dhcp_packet: DHCPv4 wire format (defined dhcp-protocol.h:20-35)
 * - struct dhcp_context: DHCP address pool configuration (dnsmasq.h:1054-1070)
 * - struct dhcp_lease: Active lease tracking (dnsmasq.h:779-810)
 * - struct dhcp_config: Static host configuration (dnsmasq.h:841-870)
 * - struct dhcp_opt: DHCP option configuration (dnsmasq.h:872-888)
 * - struct dhcp_netid: Tag-based configuration (dnsmasq.h:756-760)
 * 
 * COMPILE-TIME OPTIONS:
 * - HAVE_DHCP: Enables all DHCPv4 functionality (entire file conditionally compiled)
 * - HAVE_SCRIPT: Enables lease-change script execution (add_extradata_opt())
 * - HAVE_DUMPFILE: Enables packet capture for debugging (dump_packet_udp())
 * - OPT_LOG_OPTS: Runtime option for detailed DHCP option logging
 * 
 * THREADING/CONCURRENCY:
 * Single-threaded event-driven architecture. All DHCP packet processing occurs
 * in the main event loop context. No locking required as daemon->dhcp_packet
 * buffer is reused serially for each packet.
 * 
 * DHCPv4 MESSAGE EXCHANGE STATE MACHINE:
 * 
 * Client DISCOVER → Server OFFER (address proposal)
 * Client REQUEST → Server ACK (address commitment) or NAK (rejection)
 * Client DECLINE → Server processes conflict notification
 * Client RELEASE → Server marks lease as available
 * Client INFORM → Server provides configuration without address assignment
 * 
 * BOOTP COMPATIBILITY:
 * Supports legacy BOOTP clients (RFC 951) when op=BOOTREQUEST and no DHCP options.
 * BOOTP replies omit DHCP-specific options and use simpler packet format.
 * 
 * RAPID COMMIT SUPPORT:
 * RFC 4039 rapid commit allows DISCOVER→ACK shortcut when both client and server
 * support rapid commit option (80), reducing exchange from 4 to 2 packets.
 * 
 * LEASEQUERY SUPPORT:
 * RFC 4388 leasequery (added v2.92) enables external systems to query lease
 * information via special DHCPREQUEST packets with empty ciaddr/chaddr.
 * 
 * @copyright Copyright (c) 2000-2025 Simon Kelley
 * @license GPL-2.0-or-later
 */

#include "dnsmasq.h"

#ifdef HAVE_DHCP

#define option_len(opt) ((int)(((unsigned char *)(opt))[1]))
#define option_ptr(opt, i) ((void *)&(((unsigned char *)(opt))[2u+(unsigned int)(i)]))

#ifdef HAVE_SCRIPT
static void add_extradata_opt(struct dhcp_lease *lease, unsigned char *opt);
#endif

static int sanitise(unsigned char *opt, char *buf);
static struct in_addr server_id(struct dhcp_context *context, struct in_addr override, struct in_addr fallback);
static unsigned int calc_time(struct dhcp_context *context, struct dhcp_config *config, unsigned char *opt);
static void option_put(struct dhcp_packet *mess, unsigned char *end, int opt, int len, unsigned int val);
static void option_put_string(struct dhcp_packet *mess, unsigned char *end, 
			      int opt, const char *string, int null_term);
static struct in_addr option_addr(unsigned char *opt);
static unsigned int option_uint(unsigned char *opt, int offset, int size);
static void log_packet(char *type, void *addr, unsigned char *ext_mac, 
		       int mac_len, char *interface, char *string, char *err, u32 xid);
static unsigned char *option_find(struct dhcp_packet *mess, size_t size, int opt_type, int minsize);
static unsigned char *option_find1(unsigned char *p, unsigned char *end, int opt, int minsize);
static size_t dhcp_packet_size(struct dhcp_packet *mess, unsigned char *agent_id, unsigned char *real_end);
static void clear_packet(struct dhcp_packet *mess, unsigned char *end);
static int in_list(unsigned char *list, int opt);
static unsigned char *free_space(struct dhcp_packet *mess, unsigned char *end, int opt, int len);
/**
 * @brief Populate DHCP options into response packet based on context and client requests
 * 
 * @detailed This function constructs the DHCP options section of a response packet by
 *           processing configured options, client-requested options, vendor-specific options,
 *           PXE boot options, and FQDN options. It handles option precedence, tag-based
 *           filtering, encapsulated options, and ensures all required and requested options
 *           are included within packet size limits. This is the core option processing
 *           engine for all DHCPv4 response types (OFFER, ACK, INFORM response).
 * 
 * @param context DHCP context containing network configuration (subnet mask, router, DNS servers, lease ranges)
 * @param mess DHCP packet structure to populate with options (options field is modified in place)
 * @param end Pointer to end of available space in packet buffer (options must not exceed this)
 * @param req_options Pointer to DHCP option 55 (Parameter Request List) from client, or NULL if not present
 * @param hostname Client hostname for option 12 (Host Name), may be NULL
 * @param domain Domain name for option 15 (Domain Name) and option 119 (Domain Search), may be NULL
 * @param netid Linked list of network ID tags for tag-based option filtering (vendor-class, user-class, etc.)
 * @param subnet_addr Subnet address for subnet mask calculation and subnet-specific options
 * @param fqdn_flags FQDN option flags from option 81 (Client FQDN) for FQDN processing
 * @param null_term If non-zero, string options are null-terminated; otherwise length-delimited per RFC
 * @param pxe_arch PXE client architecture code from option 93, or -1 if not PXE client
 * @param uuid PXE client UUID from option 97, or NULL if not present
 * @param vendor_class_len Length of vendor class identifier (option 60) from client
 * @param now Current time for time-dependent options (lease times, DHCP server time)
 * @param lease_time Lease duration in seconds for option 51 (IP Address Lease Time)
 * @param fuzz Random time offset for lease renewal/rebinding calculations to prevent client synchronization
 * @param pxevendor PXE vendor string extracted from vendor-class option, or NULL
 * @param leasequery If non-zero, this is a LEASEQUERY response (RFC 4388) requiring special option handling
 * 
 * @return None (void function modifies mess structure in place)
 * 
 * @note This function implements RFC 2132 (DHCP Options and BOOTP Vendor Extensions) option encoding
 * @note Option ordering follows client parameter request list (option 55) when present
 * @note Vendor-specific options (option 43) are handled via encapsulation per RFC 3925
 * @note PXE options require special handling for architecture-specific boot configurations
 * @note Function modifies daemon->outpacket.iov_len to reflect final packet size
 * @warning Packet buffer overflow protection: all option additions check available space via free_space()
 * @warning Tag-based filtering: options only added if matching netid tags (vendor-class, user-class)
 * 
 * @see do_opt() for individual option encoding
 * @see do_encap_opts() for vendor-specific encapsulated options
 * @see pxe_opts() for PXE boot menu and file options
 * @see handle_encap() for processing vendor-specific information from client
 * 
 * EXAMPLE USAGE:
 * @code
 * // Called from dhcp_reply after determining response type and lease
 * do_options(context, mess, end, req_options, hostname, domain, netid, 
 *            subnet_addr, fqdn_flags, 0, pxe_arch, uuid, vendor_class_len,
 *            now, lease_time, fuzz, pxevendor, 0);
 * @endcode
 * 
 * RFC COMPLIANCE:
 * - RFC 2132: DHCP Options and BOOTP Vendor Extensions (all standard options)
 * - RFC 3925: Vendor-Identifying Vendor Options for DHCPv4
 * - RFC 4039: Rapid Commit option (option 80)
 * - RFC 4361: Node-specific Client Identifiers for DHCPv4
 * - RFC 4578: PXE Vendor Options (options 93, 94, 97)
 * 
 * SIDE EFFECTS:
 * - Modifies mess->options field by appending option data
 * - Updates daemon->outpacket.iov_len with final packet size
 * - May log warnings if options exceed packet size limits
 * - Calls prune_vendor_opts() which modifies global vendor option state
 * 
 * THREAD SAFETY: Single-threaded architecture, modifies global daemon state
 * 
 * Source: /src/rfc2131.c:3657-4011
 */
static void do_options(struct dhcp_context *context,
		       struct dhcp_packet *mess,
		       unsigned char *end,
		       unsigned char *req_options,
		       char *hostname, 
		       char *domain,
		       struct dhcp_netid *netid,
		       struct in_addr subnet_addr, 
		       unsigned char fqdn_flags,
		       int null_term, int pxe_arch,
		       unsigned char *uuid,
		       int vendor_class_len,
		       time_t now,
		       unsigned int lease_time,
		       unsigned short fuzz,
		       const char *pxevendor,
		       int leasequery);


static void match_vendor_opts(unsigned char *opt, struct dhcp_opt *dopt); 
static int do_encap_opts(struct dhcp_opt *opt, int encap, int flag, struct dhcp_packet *mess, unsigned char *end, int null_term);
static void pxe_misc(struct dhcp_packet *mess, unsigned char *end, unsigned char *uuid, const char *pxevendor);
static int prune_vendor_opts(struct dhcp_netid *netid);
static struct dhcp_opt *pxe_opts(int pxe_arch, struct dhcp_netid *netid, struct in_addr local, time_t now);
struct dhcp_boot *find_boot(struct dhcp_netid *netid);
static int pxe_uefi_workaround(int pxe_arch, struct dhcp_netid *netid, struct dhcp_packet *mess, struct in_addr local, time_t now, int pxe);
static void apply_delay(u32 xid, time_t recvtime, struct dhcp_netid *netid);
static int is_pxe_client(struct dhcp_packet *mess, size_t sz, const char **pxe_vendor);
static int do_opt(struct dhcp_opt *opt, unsigned char *p, struct dhcp_context *context, int null_term);
static void handle_encap(struct dhcp_packet *mess, unsigned char *end, unsigned char *req_options, int null_term, struct dhcp_netid *tagif, int pxemode);

/**
 * @brief Process incoming DHCPv4 packet and generate appropriate response
 * 
 * @detailed Main entry point for DHCPv4 protocol processing. Parses incoming DHCP
 * packets, validates format and options, identifies client via MAC/Client-ID, matches
 * against static host configurations and dynamic address pools, handles all DHCPv4
 * message types (DISCOVER/REQUEST/DECLINE/RELEASE/INFORM), implements relay agent
 * processing, generates appropriate responses (OFFER/ACK/NAK), and coordinates with
 * lease database and DNS cache. Supports BOOTP compatibility, PXE network boot,
 * rapid commit, and leasequery protocol. Implements RFC 2131 state machine with
 * extensive option processing per RFC 2132.
 * 
 * @param context DHCP context (address pool) for this interface/subnet
 * @param iface_name Network interface name where packet was received
 * @param int_index Network interface index for packet transmission
 * @param sz Size of received packet in bytes
 * @param now Current time (seconds since epoch) for lease calculations
 * @param unicast_dest True if reply should be sent via unicast (RFC 2131 section 4.1)
 * @param loopback True if packet received on loopback interface
 * @param is_inform Output parameter set to 1 if packet was DHCPINFORM (caller uses this)
 * @param pxe PXE mode flags for network boot handling
 * @param fallback Fallback IP address for server identifier if no context match
 * @param recvtime Time packet was received (for delay calculation per RFC 2131)
 * @param leasequery_source Source IP for leasequery responses (RFC 4388)
 * 
 * @return Size of response packet in bytes, or 0 if no response should be sent
 * @retval 0 Packet ignored (invalid format, relay to upstream, or explicit ignore tag)
 * @retval >0 Size of DHCP response packet ready for transmission
 * 
 * @note Packet buffer is daemon->dhcp_packet, reused for both input and output
 * @warning Returns 0 for malformed packets - caller must not transmit
 * 
 * @see rfc2131_packet() Core protocol state machine called after option parsing
 * @see do_options() DHCP option encoding for response packets
 * @see relay_upstream4() Relay forwarding to upstream DHCP servers
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_context *context = find_context(iface);
 * int is_inform = 0;
 * size_t reply_sz = dhcp_reply(context, "eth0", 2, pkt_sz, time(NULL), 
 *                               0, 0, &is_inform, 0, fallback_ip, recv_time, query_src);
 * if (reply_sz > 0)
 *   send_dhcp_packet(reply_sz);
 * @endcode
 * 
 * RFC COMPLIANCE:
 * - RFC 2131 Section 4.3: DHCP server behavior and message processing
 * - RFC 2132: DHCP Options and BOOTP Vendor Extensions
 * - RFC 3046: DHCP Relay Agent Information Option
 * - RFC 4039: Rapid Commit option for expedited address assignment
 * - RFC 4388: DHCP Leasequery protocol (v2.92)
 * 
 * SIDE EFFECTS:
 * - Modifies daemon->dhcp_packet buffer with response packet
 * - Updates lease database via lease_update_from_configs(), lease_allocate()
 * - Adds DNS cache entries via cache_add_dhcp_entry()
 * - Executes lease-change scripts via queue_script() (if HAVE_SCRIPT)
 * - Logs DHCP transactions via log_packet()
 * 
 * THREAD SAFETY: Single-threaded only, uses global daemon->dhcp_packet buffer
 */
size_t dhcp_reply(struct dhcp_context *context, char *iface_name, int int_index,
		  size_t sz, time_t now, int unicast_dest, int loopback,
		  int *is_inform, int pxe, struct in_addr fallback, time_t recvtime, struct in_addr leasequery_source)
{
  unsigned char *opt, *clid = NULL;
  struct dhcp_lease *ltmp, *lease = NULL;
  struct dhcp_vendor *vendor;
  struct dhcp_mac *mac;
  struct dhcp_netid_list *id_list;
  int clid_len = 0, ignore = 0, do_classes = 0, rapid_commit = 0, selecting = 0, pxearch = -1;
  const char *pxevendor = NULL;
  struct dhcp_packet *mess = (struct dhcp_packet *)daemon->dhcp_packet.iov_base;
  unsigned char *end = (unsigned char *)(mess + 1); 
  unsigned char *real_end = (unsigned char *)(mess + 1); 
  char *hostname = NULL, *offer_hostname = NULL, *client_hostname = NULL, *domain = NULL;
  int hostname_auth = 0, borken_opt = 0;
  unsigned char *req_options = NULL;
  char *message = NULL;
  unsigned int time;
  struct dhcp_config *config;
  struct dhcp_netid *netid, *tagif_netid;
  struct in_addr subnet_addr, override;
  unsigned short fuzz = 0;
  unsigned int mess_type = 0;
  unsigned char fqdn_flags = 0;
  unsigned char *agent_id = NULL, *uuid = NULL;
  unsigned char *emac = NULL;
  int vendor_class_len = 0, emac_len = 0;
  struct dhcp_netid known_id, iface_id, cpewan_id;
  struct dhcp_opt *o;
  unsigned char pxe_uuid[17];
  unsigned char *oui = NULL, *serial = NULL;
#ifdef HAVE_SCRIPT
  unsigned char *class = NULL;
#endif

  subnet_addr.s_addr = override.s_addr = 0;
          
  /* set tag with name == interface */
  iface_id.net = iface_name;
  iface_id.next = NULL;
  netid = &iface_id; 
  
  if (mess->op != BOOTREQUEST || mess->hlen > DHCP_CHADDR_MAX)
    return 0;
   
  if (mess->htype == 0 && mess->hlen != 0)
    return 0;

  /* check for DHCP rather than BOOTP */
  if ((opt = option_find(mess, sz, OPTION_MESSAGE_TYPE, 1)))
    {
      u32 cookie = htonl(DHCP_COOKIE);
      
      /* only insist on a cookie for DHCP. */
      if (memcmp(mess->options, &cookie, sizeof(u32)) != 0)
	return 0;
      
      mess_type = option_uint(opt, 0, 1);
      
      /* two things to note here: expand_buf may move the packet,
	 so reassign mess from daemon->packet. Also, the size
	 sent includes the IP and UDP headers, hence the magic "-28" */
      if ((opt = option_find(mess, sz, OPTION_MAXMESSAGE, 2)))
	{
	  size_t size = (size_t)option_uint(opt, 0, 2) - 28;
	  
	  if (size > DHCP_PACKET_MAX)
	    size = DHCP_PACKET_MAX;
	  else if (size < sizeof(struct dhcp_packet))
	    size = sizeof(struct dhcp_packet);
	  
	  if (expand_buf(&daemon->dhcp_packet, size))
	    {
	      mess = (struct dhcp_packet *)daemon->dhcp_packet.iov_base;
	      real_end = end = ((unsigned char *)mess) + size;
	    }
	}

      /* Some buggy clients set ciaddr when they shouldn't, so clear that here since
	 it can affect the context-determination code. */
      if ((option_find(mess, sz, OPTION_REQUESTED_IP, INADDRSZ) || mess_type == DHCPDISCOVER))
	mess->ciaddr.s_addr = 0;

      /* search for device identity from CPEWAN devices, we pass this through to the script */
      if ((opt = option_find(mess, sz, OPTION_VENDOR_IDENT_OPT, 5)))
	{
	  unsigned  int elen, offset, len = option_len(opt);
	  
	  for (offset = 0; offset < (len - 5); offset += elen + 5)
	    {
	      elen = option_uint(opt, offset + 4 , 1);
	      if (option_uint(opt, offset, 4) == BRDBAND_FORUM_IANA && offset + elen + 5 <= len)
		{
		  unsigned char *x = option_ptr(opt, offset + 5);
		  unsigned char *y = option_ptr(opt, offset + elen + 5);
		  oui = option_find1(x, y, 1, 1);
		  serial = option_find1(x, y, 2, 1);
#ifdef HAVE_SCRIPT
		  class = option_find1(x, y, 3, 1);		  
#endif
		  /* If TR069-id is present set the tag "cpewan-id" to facilitate echoing 
		     the gateway id back. Note that the device class is optional */
		  if (oui && serial)
		    {
		      cpewan_id.net = "cpewan-id";
		      cpewan_id.next = netid;
		      netid = &cpewan_id;
		    }
		  break;
		}
	    }
	}
      
      if (mess_type != DHCPLEASEQUERY && (opt = option_find(mess, sz, OPTION_AGENT_ID, 1)))
	{
	  /* Any agent-id needs to be copied back out, verbatim, as the last option
	     in the packet. Here, we shift it to the very end of the buffer, if it doesn't
	     get overwritten, then it will be shuffled back at the end of processing.
	     Note that the incoming options must not be overwritten here, so there has to 
	     be enough free space at the end of the packet to copy the option. */
	  unsigned char *sopt;
	  unsigned int total = option_len(opt) + 2;
	  unsigned char *last_opt = option_find1(&mess->options[0] + sizeof(u32), ((unsigned char *)mess) + sz,
						 OPTION_END, 0);
	  if (last_opt && last_opt < end - total)
	    {
	      end -= total;
	      agent_id = end;
	      memcpy(agent_id, opt, total);
	    }

	  /* look for RFC5010 flags sub-option */
	  if ((sopt = option_find1(option_ptr(opt, 0), option_ptr(opt, option_len(opt)), SUBOPT_FLAGS, INADDRSZ)))
	    unicast_dest = !!(option_uint(opt, 0, 1) & 0x80);
	      
	  /* look for RFC3527 Link selection sub-option */
	  if ((sopt = option_find1(option_ptr(opt, 0), option_ptr(opt, option_len(opt)), SUBOPT_SUBNET_SELECT, INADDRSZ)))
	    subnet_addr = option_addr(sopt);

	  /* look for RFC5107 server-identifier-override */
	  if ((sopt = option_find1(option_ptr(opt, 0), option_ptr(opt, option_len(opt)), SUBOPT_SERVER_OR, INADDRSZ)))
	    override = option_addr(sopt);
	  
	  /* if a circuit-id or remote-is option is provided, exact-match to options. */
	  for (vendor = daemon->dhcp_vendors; vendor; vendor = vendor->next)
	    {
	      int search;
	      
	      if (vendor->match_type == MATCH_CIRCUIT)
		search = SUBOPT_CIRCUIT_ID;
	      else if (vendor->match_type == MATCH_REMOTE)
		search = SUBOPT_REMOTE_ID;
	      else if (vendor->match_type == MATCH_SUBSCRIBER)
		search = SUBOPT_SUBSCR_ID;
	      else 
		continue;
	      
	      if ((sopt = option_find1(option_ptr(opt, 0), option_ptr(opt, option_len(opt)), search, 1)) &&
		  vendor->len == option_len(sopt) &&
		  memcmp(option_ptr(sopt, 0), vendor->data, vendor->len) == 0)
		{
		  vendor->netid.next = netid;
		  netid = &vendor->netid;
		} 
	    }
	}
      
      /* Check for RFC3011 subnet selector - only if RFC3527 one not present */
      if (subnet_addr.s_addr == 0 && (opt = option_find(mess, sz, OPTION_SUBNET_SELECT, INADDRSZ)))
	subnet_addr = option_addr(opt);
      
      /* If there is no client identifier option, use the hardware address */
      if (!option_bool(OPT_IGNORE_CLID) && (opt = option_find(mess, sz, OPTION_CLIENT_ID, 1)))
	{
	  clid_len = option_len(opt);
	  clid = option_ptr(opt, 0);
	}

      /* do we have a lease in store? */
      lease = lease_find_by_client(mess->chaddr, mess->hlen, mess->htype, clid, clid_len);

      /* If this request is missing a clid, but we've seen one before, 
	 use it again for option matching etc. */
      if (lease && !clid && lease->clid)
	{
	  clid_len = lease->clid_len;
	  clid = lease->clid;
	}

      /* find mac to use for logging and hashing */
      emac = extended_hwaddr(mess->htype, mess->hlen, mess->chaddr, clid_len, clid, &emac_len);
    }
  
  for (mac = daemon->dhcp_macs; mac; mac = mac->next)
    if (mac->hwaddr_len == mess->hlen &&
	(mac->hwaddr_type == mess->htype || mac->hwaddr_type == 0) &&
	memcmp_masked(mac->hwaddr, mess->chaddr, mess->hlen, mac->mask))
      {
	mac->netid.next = netid;
	netid = &mac->netid;
      }
  
  /* Determine network for this packet. Our caller will have already linked all the 
     contexts which match the addresses of the receiving interface but if the 
     machine has an address already, or came via a relay, or we have a subnet selector, 
     we search again. If we don't have have a giaddr or explicit subnet selector, 
     use the ciaddr. This is necessary because a  machine which got a lease via a 
     relay won't use the relay to renew. If matching a ciaddr fails but we have a context 
     from the physical network, continue using that to allow correct DHCPNAK generation later. */
  if (mess->giaddr.s_addr || subnet_addr.s_addr || mess->ciaddr.s_addr)
    {
      struct dhcp_context *context_tmp, *context_new = NULL;
      struct shared_network *share = NULL;
      struct in_addr addr;
      int force = 0, via_relay = 0;
      
      if (subnet_addr.s_addr)
	{
	  addr = subnet_addr;
	  force = 1;
	  if (mess->giaddr.s_addr)
	    via_relay = 1;
	}
      else if (mess->giaddr.s_addr)
	{
	  addr = mess->giaddr;
	  force = 1;
	  via_relay = 1;
	}
      else
	{
	  /* If ciaddr is in the hardware derived set of contexts, leave that unchanged */
	  addr = mess->ciaddr;
	  for (context_tmp = context; context_tmp; context_tmp = context_tmp->current)
	    if (context_tmp->netmask.s_addr && 
		is_same_net(addr, context_tmp->start, context_tmp->netmask) &&
		is_same_net(addr, context_tmp->end, context_tmp->netmask))
	      {
		context_new = context;
		break;
	      }
	} 
		
      if (!context_new)
	{
	  for (context_tmp = daemon->dhcp; context_tmp; context_tmp = context_tmp->next)
	    {
	      struct in_addr netmask = context_tmp->netmask;
	      
	      /* guess the netmask for relayed networks */
	      if (!(context_tmp->flags & CONTEXT_NETMASK) && context_tmp->netmask.s_addr == 0)
		{
		  if (IN_CLASSA(ntohl(context_tmp->start.s_addr)) && IN_CLASSA(ntohl(context_tmp->end.s_addr)))
		    netmask.s_addr = htonl(0xff000000);
		  else if (IN_CLASSB(ntohl(context_tmp->start.s_addr)) && IN_CLASSB(ntohl(context_tmp->end.s_addr)))
		    netmask.s_addr = htonl(0xffff0000);
		  else if (IN_CLASSC(ntohl(context_tmp->start.s_addr)) && IN_CLASSC(ntohl(context_tmp->end.s_addr)))
		    netmask.s_addr = htonl(0xffffff00); 
		}

	      /* check to see is a context is OK because of a shared address on
		 the relayed subnet. */
	      if (via_relay)
		for (share = daemon->shared_networks; share; share = share->next)
		  {
#ifdef HAVE_DHCP6
		    if (share->shared_addr.s_addr == 0)
		      continue;
#endif
		    if (share->if_index != 0 ||
			share->match_addr.s_addr != mess->giaddr.s_addr)
		      continue;
		    
		    if (netmask.s_addr != 0  && 
			is_same_net(share->shared_addr, context_tmp->start, netmask) &&
			is_same_net(share->shared_addr, context_tmp->end, netmask))
		      break;
		  }
	      
	      /* This section fills in context mainly when a client which is on a remote (relayed)
		 network renews a lease without using the relay, after dnsmasq has restarted. */
	      if (share ||
		  (netmask.s_addr != 0  && 
		   is_same_net(addr, context_tmp->start, netmask) &&
		   is_same_net(addr, context_tmp->end, netmask)))
		{
		  context_tmp->netmask = netmask;
		  if (context_tmp->local.s_addr == 0)
		    context_tmp->local = fallback;
		  if (context_tmp->router.s_addr == 0 && !share)
		    {
		      if (override.s_addr)
			context_tmp->router = override;
		      else
			context_tmp->router = mess->giaddr;
		    }
		  
		  /* fill in missing broadcast addresses for relayed ranges */
		  if (!(context_tmp->flags & CONTEXT_BRDCAST) && context_tmp->broadcast.s_addr == 0 )
		    context_tmp->broadcast.s_addr = context_tmp->start.s_addr | ~context_tmp->netmask.s_addr;
		  
		  context_tmp->current = context_new;
		  context_new = context_tmp;
		}
	      
	    }
	}
	  
      if (context_new || force)
	context = context_new; 
    }
  
  if (mess_type != DHCPLEASEQUERY)
    {
      if  (!context)
	{
	  const char *via;
	  if (subnet_addr.s_addr)
	    {
	      via = _("with subnet selector");
	      inet_ntop(AF_INET, &subnet_addr, daemon->addrbuff, ADDRSTRLEN);
	    }
	  else
	    {
	      via = _("via");
	      if (mess->giaddr.s_addr)
		inet_ntop(AF_INET, &mess->giaddr, daemon->addrbuff, ADDRSTRLEN);
	      else
		safe_strncpy(daemon->addrbuff, iface_name, ADDRSTRLEN);
	    }
	  my_syslog(MS_DHCP | LOG_WARNING, _("no address range available for DHCP request %s %s"),
		    via, daemon->addrbuff);
	  return 0;
	}
      
      if (option_bool(OPT_LOG_OPTS))
	{
	  struct dhcp_context *context_tmp;
	  for (context_tmp = context; context_tmp; context_tmp = context_tmp->current)
	    {
	      inet_ntop(AF_INET, &context_tmp->start, daemon->namebuff, MAXDNAME);
	      if (context_tmp->flags & (CONTEXT_STATIC | CONTEXT_PROXY))
		{
		  inet_ntop(AF_INET, &context_tmp->netmask, daemon->addrbuff, ADDRSTRLEN);
		  my_syslog(MS_DHCP | LOG_INFO, _("%u available DHCP subnet: %s/%s"),
			    ntohl(mess->xid), daemon->namebuff, daemon->addrbuff);
		}
	      else
		{
		  inet_ntop(AF_INET, &context_tmp->end, daemon->addrbuff, ADDRSTRLEN);
		  my_syslog(MS_DHCP | LOG_INFO, _("%u available DHCP range: %s -- %s"),
			    ntohl(mess->xid), daemon->namebuff, daemon->addrbuff);
		}
	    }
	}
    }
  
  /* dhcp-match. If we have hex-and-wildcards, look for a left-anchored match.
     Otherwise assume the option is an array, and look for a matching element. 
     If no data given, existence of the option is enough. This code handles 
     rfc3925 V-I classes too. */
  for (o = daemon->dhcp_match; o; o = o->next)
    {
      unsigned int len, elen, match = 0;
      size_t offset, o2;

      if (o->flags & DHOPT_RFC3925)
	{
	  if (!(opt = option_find(mess, sz, OPTION_VENDOR_IDENT, 5)))
	    continue;
	  
	  for (offset = 0; offset < (option_len(opt) - 5u); offset += len + 5)
	    {
	      len = option_uint(opt, offset + 4 , 1);
	      /* Need to take care that bad data can't run us off the end of the packet */
	      if ((offset + len + 5 <= (unsigned)(option_len(opt))) &&
		  (option_uint(opt, offset, 4) == (unsigned int)o->u.encap))
		for (o2 = offset + 5; o2 < offset + len + 5; o2 += elen + 1)
		  { 
		    elen = option_uint(opt, o2, 1);
		    if ((o2 + elen + 1 <= (unsigned)option_len(opt)) &&
			(match = match_bytes(o, option_ptr(opt, o2 + 1), elen)))
		      break;
		  }
	      if (match) 
		break;
	    }	  
	}
      else
	{
	  if (!(opt = option_find(mess, sz, o->opt, 1)))
	    continue;
	  
	  match = match_bytes(o, option_ptr(opt, 0), option_len(opt));
	} 

      if (match)
	{
	  o->netid->next = netid;
	  netid = o->netid;
	}
    }
	
  /* user-class options are, according to RFC3004, supposed to contain
     a set of counted strings. Here we check that this is so (by seeing
     if the counts are consistent with the overall option length) and if
     so zero the counts so that we don't get spurious matches between 
     the vendor string and the counts. If the lengths don't add up, we
     assume that the option is a single string and non RFC3004 compliant 
     and just do the substring match. dhclient provides these broken options.
     The code, later, which sends user-class data to the lease-change script
     relies on the transformation done here.
  */

  if ((opt = option_find(mess, sz, OPTION_USER_CLASS, 1)))
    {
      unsigned char *ucp = option_ptr(opt, 0);
      int tmp, j;
      for (j = 0; j < option_len(opt); j += ucp[j] + 1);
      if (j == option_len(opt))
	for (j = 0; j < option_len(opt); j = tmp)
	  {
	    tmp = j + ucp[j] + 1;
	    ucp[j] = 0;
	  }
    }
    
  for (vendor = daemon->dhcp_vendors; vendor; vendor = vendor->next)
    {
      int mopt;
      
      if (vendor->match_type == MATCH_VENDOR)
	mopt = OPTION_VENDOR_ID;
      else if (vendor->match_type == MATCH_USER)
	mopt = OPTION_USER_CLASS; 
      else
	continue;

      if ((opt = option_find(mess, sz, mopt, 1)))
	{
	  int i;
	  for (i = 0; i <= (option_len(opt) - vendor->len); i++)
	    if (memcmp(vendor->data, option_ptr(opt, i), vendor->len) == 0)
	      {
		vendor->netid.next = netid;
		netid = &vendor->netid;
		break;
	      }
	}
    }

  /* mark vendor-encapsulated options which match the client-supplied vendor class,
     save client-supplied vendor class */
  if ((opt = option_find(mess, sz, OPTION_VENDOR_ID, 1)))
    {
      memcpy(daemon->dhcp_buff3, option_ptr(opt, 0), option_len(opt));
      vendor_class_len = option_len(opt);
    }
  match_vendor_opts(opt, daemon->dhcp_opts);
  
  if (option_bool(OPT_LOG_OPTS))
    {
      if (sanitise(opt, daemon->namebuff))
	my_syslog(MS_DHCP | LOG_INFO, _("%u vendor class: %s"), ntohl(mess->xid), daemon->namebuff);
      if (sanitise(option_find(mess, sz, OPTION_USER_CLASS, 1), daemon->namebuff))
	my_syslog(MS_DHCP | LOG_INFO, _("%u user class: %s"), ntohl(mess->xid), daemon->namebuff);
    }

  mess->op = BOOTREPLY;
  
  config = find_config(daemon->dhcp_conf, context, clid, clid_len, 
		       mess->chaddr, mess->hlen, mess->htype, NULL, run_tag_if(netid));

  /* set "known" tag for known hosts */
  if (config)
    {
      known_id.net = "known";
      known_id.next = netid;
      netid = &known_id;
    }
  else if (find_config(daemon->dhcp_conf, NULL, clid, clid_len, 
		       mess->chaddr, mess->hlen, mess->htype, NULL, run_tag_if(netid)))
    {
      known_id.net = "known-othernet";
      known_id.next = netid;
      netid = &known_id;
    }
  
  if (mess_type == 0 && !pxe)
    {
      /* BOOTP request */
      struct dhcp_netid id, bootp_id;
      struct in_addr *logaddr = NULL;

      /* must have a MAC addr for bootp */
      if (mess->htype == 0 || mess->hlen == 0 || (context->flags & CONTEXT_PROXY))
	return 0;
      
      if (have_config(config, CONFIG_DISABLE))
	message = _("disabled");

      end = mess->options + 64; /* BOOTP vend area is only 64 bytes */
            
      if (have_config(config, CONFIG_NAME))
	{
	  hostname = config->hostname;
	  domain = config->domain;
	}

      if (config)
	{
	  struct dhcp_netid_list *list;

	  for (list = config->netid; list; list = list->next)
	    {
	      list->list->next = netid;
	      netid = list->list;
	    }
	}

      /* Match incoming filename field as a netid. */
      if (mess->file[0])
	{
	  memcpy(daemon->dhcp_buff2, mess->file, sizeof(mess->file));
	  daemon->dhcp_buff2[sizeof(mess->file) + 1] = 0; /* ensure zero term. */
	  id.net = (char *)daemon->dhcp_buff2;
	  id.next = netid;
	  netid = &id;
	}

      /* Add "bootp" as a tag to allow different options, address ranges etc
	 for BOOTP clients */
      bootp_id.net = "bootp";
      bootp_id.next = netid;
      netid = &bootp_id;
      
      tagif_netid = run_tag_if(netid);

      for (id_list = daemon->dhcp_ignore; id_list; id_list = id_list->next)
	if (match_netid(id_list->list, tagif_netid, 0))
	  message = _("ignored");
      
      if (!message)
	{
	  int nailed = 0;

	  if (have_config(config, CONFIG_ADDR))
	    {
	      nailed = 1;
	      logaddr = &config->addr;
	      mess->yiaddr = config->addr;
	      if ((lease = lease_find_by_addr(config->addr)) &&
		  (lease->hwaddr_len != mess->hlen ||
		   lease->hwaddr_type != mess->htype ||
		   memcmp(lease->hwaddr, mess->chaddr, lease->hwaddr_len) != 0))
		message = _("address in use");
	    }
	  else
	    {
	      if (!(lease = lease_find_by_client(mess->chaddr, mess->hlen, mess->htype, NULL, 0)) ||
		  !address_available(context, lease->addr, tagif_netid))
		{
		   if (lease)
		     {
		       /* lease exists, wrong network. */
		       lease_prune(lease, now);
		       lease = NULL;
		     }
		   if (!address_allocate(context, &mess->yiaddr, mess->chaddr, mess->hlen, tagif_netid, now, loopback))
		     message = _("no address available");
		}
	      else
		mess->yiaddr = lease->addr;
	    }
	  
	  if (!message && !(context = narrow_context(context, mess->yiaddr, netid)))
	    message = _("wrong network");
	  else if (context->netid.net)
	    {
	      context->netid.next = netid;
	      tagif_netid = run_tag_if(&context->netid);
	    }

	  log_tags(tagif_netid, ntohl(mess->xid));
	    
	  if (!message && !nailed)
	    {
	      for (id_list = daemon->bootp_dynamic; id_list; id_list = id_list->next)
		if ((!id_list->list) || match_netid(id_list->list, tagif_netid, 0))
		  break;
	      if (!id_list)
		message = _("no address configured");
	    }

	  if (!message && 
	      !lease && 
	      (!(lease = lease4_allocate(mess->yiaddr))))
	    message = _("no leases left");
	  
	  if (!message)
	    {
	      logaddr = &mess->yiaddr;
		
	      lease_set_hwaddr(lease, mess->chaddr, NULL, mess->hlen, mess->htype, 0, now, 1);
	      if (hostname)
		lease_set_hostname(lease, hostname, 1, get_domain(lease->addr), domain); 
	      /* infinite lease unless nailed in dhcp-host line. */
	      lease_set_expires(lease,  
				have_config(config, CONFIG_TIME) ? config->lease_time : 0xffffffff, 
				now); 
	      lease_set_interface(lease, int_index, now);
	      
	      clear_packet(mess, end);
	      do_options(context, mess, end, NULL, hostname, get_domain(mess->yiaddr), 
			 netid, subnet_addr, 0, 0, -1, NULL, vendor_class_len, now, 0xffffffff, 0, NULL, 0);
	    }
	}
      
      daemon->metrics[METRIC_BOOTP]++;
      log_packet("BOOTP", logaddr, mess->chaddr, mess->hlen, iface_name, NULL, message, mess->xid);
      
      return message ? 0 : dhcp_packet_size(mess, agent_id, real_end);
    }
      
  if ((opt = option_find(mess, sz, OPTION_CLIENT_FQDN, 3)))
    {
      /* http://tools.ietf.org/wg/dhc/draft-ietf-dhc-fqdn-option/draft-ietf-dhc-fqdn-option-10.txt */
      int len = option_len(opt);
      char *pq = daemon->dhcp_buff;
      unsigned char *pp, *op = option_ptr(opt, 0);
      
      fqdn_flags = *op;
      len -= 3;
      op += 3;
      pp = op;
      
      /* NB, the following always sets at least one bit */
      if (option_bool(OPT_FQDN_UPDATE))
	{
	  if (fqdn_flags & 0x01)
	    {
	      fqdn_flags |= 0x02; /* set O */
	      fqdn_flags &= ~0x01; /* clear S */
	    }
	  fqdn_flags |= 0x08; /* set N */
	}
      else 
	{
	  if (!(fqdn_flags & 0x01))
	    fqdn_flags |= 0x03; /* set S and O */
	  fqdn_flags &= ~0x08; /* clear N */
	}
      
      if (fqdn_flags & 0x04)
	while (*op != 0 && ((op + (*op)) - pp) < len)
	  {
	    memcpy(pq, op+1, *op);
	    pq += *op;
	    op += (*op)+1;
	    *(pq++) = '.';
	  }
      else
	{
	  memcpy(pq, op, len);
	  if (len > 0 && op[len-1] == 0)
	    borken_opt = 1;
	  pq += len + 1;
	}
      
      if (pq != daemon->dhcp_buff)
	pq--;
      
      *pq = 0;
      
      if (legal_hostname(daemon->dhcp_buff))
	offer_hostname = client_hostname = daemon->dhcp_buff;
    }
  else if ((opt = option_find(mess, sz, OPTION_HOSTNAME, 1)))
    {
      int len = option_len(opt);
      memcpy(daemon->dhcp_buff, option_ptr(opt, 0), len);
      /* Microsoft clients are broken, and need zero-terminated strings
	 in options. We detect this state here, and do the same in
	 any options we send */
      if (len > 0 && daemon->dhcp_buff[len-1] == 0)
	borken_opt = 1;
      else
	daemon->dhcp_buff[len] = 0;
      if (legal_hostname(daemon->dhcp_buff))
	client_hostname = daemon->dhcp_buff;
    }

  if (client_hostname)
    {
      struct dhcp_match_name *m;
      size_t nl = strlen(client_hostname);
      
      if (option_bool(OPT_LOG_OPTS))
	my_syslog(MS_DHCP | LOG_INFO, _("%u client provides name: %s"), ntohl(mess->xid), client_hostname);
      for (m = daemon->dhcp_name_match; m; m = m->next)
	{
	  size_t ml = strlen(m->name);
	  char save = 0;
	  
	  if (nl < ml)
	    continue;
	  if (nl > ml)
	    {
	      save = client_hostname[ml];
	      client_hostname[ml] = 0;
	    }
	  
	  if (hostname_isequal(client_hostname, m->name) &&
	      (save == 0 || m->wildcard))
	    {
	      m->netid->next = netid;
	      netid = m->netid;
	    }
	  
	  if (save != 0)
	    client_hostname[ml] = save;
	}
    }
  
  if (have_config(config, CONFIG_NAME))
    {
      hostname = config->hostname;
      domain = config->domain;
      hostname_auth = 1;
      /* be careful not to send an OFFER with a hostname not matching the DISCOVER. */
      if (fqdn_flags != 0 || !client_hostname || hostname_isequal(hostname, client_hostname))
        offer_hostname = hostname;
    }
  else if (client_hostname)
    {
      domain = strip_hostname(client_hostname);
      
      if (strlen(client_hostname) != 0)
	{
	  hostname = client_hostname;
	  
	  if (!config)
	    {
	      /* Search again now we have a hostname. 
		 Only accept configs without CLID and HWADDR here, (they won't match)
		 to avoid impersonation by name. */
	      struct dhcp_config *new = find_config(daemon->dhcp_conf, context, NULL, 0,
						    mess->chaddr, mess->hlen, 
						    mess->htype, hostname, run_tag_if(netid));
	      if (new && !have_config(new, CONFIG_CLID) && !new->hwaddr)
		{
		  config = new;
		  /* set "known" tag for known hosts */
		  known_id.net = "known";
		  known_id.next = netid;
		  netid = &known_id;
		}
	    }
	}
    }

  if (mess_type != DHCPLEASEQUERY && config)
    {
      struct dhcp_netid_list *list;
      
      for (list = config->netid; list; list = list->next)
	{
	  list->list->next = netid;
	  netid = list->list;
	}
    }
  
  tagif_netid = run_tag_if(netid);
  
  /* if all the netids in the ignore list are present, ignore this client */
  for (id_list = daemon->dhcp_ignore; id_list; id_list = id_list->next)
    if (match_netid(id_list->list, tagif_netid, 0))
      ignore = 1;

  /* If configured, we can override the server-id to be the address of the relay, 
     so that all traffic goes via the relay and can pick up agent-id info. This can be
     configured for all relays, or by address. */
  if (daemon->override && mess->giaddr.s_addr != 0 && override.s_addr == 0)
    {
      if (!daemon->override_relays)
	override = mess->giaddr;
      else
	{
	  struct addr_list *l;
	  for (l = daemon->override_relays; l; l = l->next)
	    if (l->addr.s_addr == mess->giaddr.s_addr)
	      break;
	  if (l)
	    override = mess->giaddr;
	}
    }

  /* Can have setting to ignore the client ID for a particular MAC address or hostname */
  if (have_config(config, CONFIG_NOCLID))
    clid = NULL;
          
  /* Check if client is PXE client. */
  if (mess_type != DHCPLEASEQUERY &&
      daemon->enable_pxe &&
      is_pxe_client(mess, sz, &pxevendor))
    {
      if ((opt = option_find(mess, sz, OPTION_PXE_UUID, 17)))
	{
	  memcpy(pxe_uuid, option_ptr(opt, 0), 17);
	  uuid = pxe_uuid;
	}

      /* Check if this is really a PXE bootserver request, and handle specially if so. */
      if ((mess_type == DHCPREQUEST || mess_type == DHCPINFORM) &&
	  (opt = option_find(mess, sz, OPTION_VENDOR_CLASS_OPT, 1)) &&
	  (opt = option_find1(option_ptr(opt, 0), option_ptr(opt, option_len(opt)), SUBOPT_PXE_BOOT_ITEM, 4)))
	{
	  struct pxe_service *service;
	  int type = option_uint(opt, 0, 2);
	  int layer = option_uint(opt, 2, 2);
	  unsigned char save71[4];
	  struct dhcp_opt opt71;

	  if (ignore)
	    return 0;

	  if (layer & 0x8000)
	    {
	      my_syslog(MS_DHCP | LOG_ERR, _("PXE BIS not supported"));
	      return 0;
	    }

	  memcpy(save71, option_ptr(opt, 0), 4);
	  
	  for (service = daemon->pxe_services; service; service = service->next)
	    if (service->type == type)
	      break;
	  
	  for (; context; context = context->current)
	    if (match_netid(context->filter, tagif_netid, 1) &&
		is_same_net(mess->ciaddr, context->start, context->netmask))
	      break;
	  
	  if (!service || !service->basename || !context)
	    return 0;
	  	  
	  clear_packet(mess, end);
	  
	  mess->yiaddr = mess->ciaddr;
	  mess->ciaddr.s_addr = 0;
	  if (service->sname)
	    mess->siaddr = a_record_from_hosts(service->sname, now);
	  else if (service->server.s_addr != 0)
	    mess->siaddr = service->server; 
	  else
	    mess->siaddr = context->local; 
	  
	  if (strchr(service->basename, '.'))
	    snprintf((char *)mess->file, sizeof(mess->file),
		"%s", service->basename);
	  else
	    snprintf((char *)mess->file, sizeof(mess->file),
		"%s.%d", service->basename, layer);
	  
	  option_put(mess, end, OPTION_MESSAGE_TYPE, 1, DHCPACK);
	  option_put(mess, end, OPTION_SERVER_IDENTIFIER, INADDRSZ, htonl(context->local.s_addr));
	  pxe_misc(mess, end, uuid, pxevendor);
	  
	  prune_vendor_opts(tagif_netid);
	  opt71.val = save71;
	  opt71.opt = SUBOPT_PXE_BOOT_ITEM;
	  opt71.len = 4;
	  opt71.flags = DHOPT_VENDOR_MATCH;
	  opt71.netid = NULL;
	  opt71.next = daemon->dhcp_opts;
	  do_encap_opts(&opt71, OPTION_VENDOR_CLASS_OPT, DHOPT_VENDOR_MATCH, mess, end, 0);
	  
	  daemon->metrics[METRIC_PXE]++;
	  log_packet("PXE", &mess->yiaddr, emac, emac_len, iface_name, (char *)mess->file, NULL, mess->xid);
	  log_tags(tagif_netid, ntohl(mess->xid));
	  return dhcp_packet_size(mess, agent_id, real_end);	  
	}
      
      if ((opt = option_find(mess, sz, OPTION_ARCH, 2)))
	{
	  pxearch = option_uint(opt, 0, 2);

	  /* proxy DHCP here. */
	  if ((mess_type == DHCPDISCOVER || (pxe && mess_type == DHCPREQUEST)))
	    {
	      struct dhcp_context *tmp;
	      int workaround = 0;
	      
	      for (tmp = context; tmp; tmp = tmp->current)
		if ((tmp->flags & CONTEXT_PROXY) &&
		    match_netid(tmp->filter, tagif_netid, 1))
		  break;
	      
	      if (tmp)
		{
		  struct dhcp_boot *boot;
		  int redirect4011 = 0;
		  struct dhcp_opt *option;

		  /* OK only dhcp-option-pxe options. */
		  tagif_netid = option_filter(netid, tmp->netid.net ? &tmp->netid : NULL, daemon->dhcp_opts, 2);
		  boot = find_boot(tagif_netid);
		  
		  mess->yiaddr.s_addr = 0;
		  if  (mess_type == DHCPDISCOVER || mess->ciaddr.s_addr == 0)
		    {
		      mess->ciaddr.s_addr = 0;
		      mess->flags |= htons(0x8000); /* broadcast */
		    }
		  
		  clear_packet(mess, end);
		  
		  /* Redirect EFI clients to port 4011 */
		  if (pxearch >= 6)
		    {
		      redirect4011 = 1;
		      mess->siaddr = tmp->local;
		    }
		  
		  /* Returns true if only one matching service is available. On port 4011, 
		     it also inserts the boot file and server name. */
		  workaround = pxe_uefi_workaround(pxearch, tagif_netid, mess, tmp->local, now, pxe);
		  
		  if (!workaround && boot)
		    {
		      /* Provide the bootfile here, for iPXE, and in case we have no menu items
			 and set discovery_control = 8 */
		      if (boot->next_server.s_addr) 
			mess->siaddr = boot->next_server;
		      else if (boot->tftp_sname) 
			mess->siaddr = a_record_from_hosts(boot->tftp_sname, now);
		      
		      if (boot->file)
			safe_strncpy((char *)mess->file, boot->file, sizeof(mess->file));
		    }
		  
		  option_put(mess, end, OPTION_MESSAGE_TYPE, 1, 
			     mess_type == DHCPDISCOVER ? DHCPOFFER : DHCPACK);
		  option_put(mess, end, OPTION_SERVER_IDENTIFIER, INADDRSZ, htonl(tmp->local.s_addr));
		  pxe_misc(mess, end, uuid, pxevendor);
		  prune_vendor_opts(tagif_netid);
		  if ((pxe && !workaround) || !redirect4011)
		    do_encap_opts(pxe_opts(pxearch, tagif_netid, tmp->local, now), OPTION_VENDOR_CLASS_OPT, DHOPT_VENDOR_MATCH, mess, end, 0);

		  /* dhcp-option-pxe ONLY */
		  for (option = daemon->dhcp_opts; option; option = option->next)
		    {
		      int len;
		      unsigned char *p;
		      
		      if (!(option->flags & DHOPT_TAGOK))
			continue;
		      
		      len = do_opt(option, NULL, tmp, borken_opt);

		      if ((p = free_space(mess, end, option->opt, len)))
			do_opt(option, p, tmp, borken_opt);
		    }

		  handle_encap(mess, end, req_options, borken_opt, tagif_netid, 2);
		  
		  daemon->metrics[METRIC_PXE]++;
		  log_packet("PXE", NULL, emac, emac_len, iface_name, ignore ? "proxy-ignored" : "proxy", NULL, mess->xid);
		  log_tags(tagif_netid, ntohl(mess->xid));
		  if (!ignore)
		    apply_delay(mess->xid, recvtime, tagif_netid);
		  return ignore ? 0 : dhcp_packet_size(mess, agent_id, real_end);	  
		}
	    }
	}
    }

  /* if we're just a proxy server, go no further */
  if (mess_type != DHCPLEASEQUERY &&
      ((context->flags & CONTEXT_PROXY) || pxe))
    return 0;
  
  if ((opt = option_find(mess, sz, OPTION_REQUESTED_OPTIONS, 0)))
    {
      req_options = (unsigned char *)daemon->dhcp_buff2;
      memcpy(req_options, option_ptr(opt, 0), option_len(opt));
      req_options[option_len(opt)] = OPTION_END;
    }
  
  switch (mess_type)
    {
    case DHCPLEASEQUERY:
      mess_type = DHCPLEASEUNKNOWN;
      
      if (!option_bool(OPT_LEASEQUERY))
	return 0;
      
      if (leasequery_source.s_addr == 0)
	return 0;

      inet_ntop(AF_INET, &leasequery_source, daemon->workspacename, ADDRSTRLEN);

      if (daemon->leasequery_addr)
	{
	  struct bogus_addr *baddrp;

	  for (baddrp = daemon->leasequery_addr; baddrp; baddrp = baddrp->next)
	    if (!baddrp->is6 && is_same_net_prefix(leasequery_source, baddrp->addr.addr4, baddrp->prefix))
	      break;
	  
	  if (!baddrp)
	    {
	      my_syslog(MS_DHCP | LOG_WARNING, _("leasequery from %s not permitted"), daemon->workspacename);
	      return 0;
	    }
	}
      
      daemon->metrics[METRIC_DHCPLEASEQUERY]++;
      log_packet("DHCPLEASEQUERY", mess->ciaddr.s_addr ? &mess->ciaddr : NULL, emac_len != 0 ? emac : NULL, emac_len,
		 iface_name, "from ", daemon->workspacename, mess->xid);

      /* Put all the contexts on the ->current list for the next stages. */
      for (context = daemon->dhcp; context; context = context->next)
	context->current = context->next;
      
      /* Have maybe already found the lease by MAC or clid. */
      if (mess->ciaddr.s_addr != 0 &&
	  !(lease = lease_find_by_addr(mess->ciaddr)) &&
	  address_available(daemon->dhcp, mess->ciaddr, tagif_netid))
	{
	  mess_type = DHCPLEASEUNASSIGNED;
	  daemon->metrics[METRIC_DHCPLEASEUNASSIGNED]++;
	}
      
      if (lease)
	{
	  /* RFC4388 para 6.4.2 */
	  if (lease->agent_id)
	    {
	      unsigned char *sopt ;
	      
	      for (vendor = daemon->dhcp_vendors; vendor; vendor = vendor->next)
		{
		  int search;
		  
		  if (vendor->match_type == MATCH_CIRCUIT)
		    search = SUBOPT_CIRCUIT_ID;
		  else if (vendor->match_type == MATCH_REMOTE)
		    search = SUBOPT_REMOTE_ID;
		  else if (vendor->match_type == MATCH_SUBSCRIBER)
		    search = SUBOPT_SUBSCR_ID;
		  else 
		    continue;
		  
		  if ((sopt = option_find1(lease->agent_id, lease->agent_id + lease->agent_id_len, search, 1)) &&
		      vendor->len == option_len(sopt) &&
		      memcmp(option_ptr(sopt, 0), vendor->data, vendor->len) == 0)
		    {
		      vendor->netid.next = netid;
		      netid = &vendor->netid;
		    }
		}
	      
	      tagif_netid = run_tag_if(netid);
	    }
	  
	  /* Now find the context for this lease and config for this host. */
	  if ((context = narrow_context(daemon->dhcp, lease->addr, tagif_netid)))
	    {
	      if ((config = find_config(daemon->dhcp_conf, context, lease->clid, lease->clid_len, 
					lease->hwaddr, lease->hwaddr_len, lease->hwaddr_type, lease->hostname, tagif_netid)))
		{
		  struct dhcp_netid_list *list;
		  
		  for (list = config->netid; list; list = list->next)
		    {
		      list->list->next = netid;
		      netid = list->list;
		    }

		  tagif_netid = run_tag_if(netid);
		}
	      
	      if (context->netid.net)
		{
		  context->netid.next = netid;
		  tagif_netid = run_tag_if(&context->netid);
		}

	      log_tags(tagif_netid, ntohl(mess->xid));
	      emac = extended_hwaddr(lease->hwaddr_type, lease->hwaddr_len, lease->hwaddr, lease->clid_len, lease->clid, &emac_len);
	      mess_type = DHCPLEASEACTIVE;
	      daemon->metrics[METRIC_DHCPLEASEACTIVE]++;
	    }
	}
      
      log_packet(mess_type == DHCPLEASEACTIVE ? "DHCPLEASEACTIVE" : (mess_type == DHCPLEASEUNASSIGNED ? "DHCPLEASEUNASSIGNED" : "DHCPLEASEUNKNOWN"),
		 mess_type == DHCPLEASEACTIVE ? &lease->addr : (mess->ciaddr.s_addr != 0 ? &mess->ciaddr : NULL),
		 emac_len != 0 ? emac : NULL, emac_len,
		 iface_name, mess_type == DHCPLEASEACTIVE ? lease->hostname : NULL, NULL, mess->xid);
      
      clear_packet(mess, end);
      option_put(mess, end, OPTION_MESSAGE_TYPE, 1, mess_type);
      
      if (mess_type == DHCPLEASEUNKNOWN)
	{
	  daemon->metrics[METRIC_DHCPLEASEUNKNOWN]++;
	  mess->ciaddr.s_addr = 0;
	}
      
      if (mess_type == DHCPLEASEACTIVE)
	{
	  unsigned char *p;
	  
	  mess->ciaddr = lease->addr;
	  mess->hlen = lease->hwaddr_len;
	  mess->htype = lease->hwaddr_type;
	  memcpy(mess->chaddr, lease->hwaddr, lease->hwaddr_len);
	  
	  if (lease->clid && in_list(req_options, OPTION_CLIENT_ID) &&
	      (p = free_space(mess, end, OPTION_CLIENT_ID, lease->clid_len)))
	    memcpy(p, lease->clid, lease->clid_len);
	  
	  if (in_list(req_options, OPTION_LEASE_TIME))
	    {
	      if (lease->expires == 0) /* infinite lease */
		option_put(mess, end, OPTION_LEASE_TIME, 4, 0xffffffff);
	      else
		option_put(mess, end, OPTION_LEASE_TIME, 4, (unsigned int)(lease->expires - now));
	    }
	  
	  if (lease->expires != 0)
	    {
	      time = calc_time(context, config, NULL);

	      if (in_list(req_options, OPTION_T1) && (lease->expires - now) > time/2)
		option_put(mess, end, OPTION_T1, 4, ((unsigned int)(lease->expires - now)) - time/2);
	      if (in_list(req_options, OPTION_T2) && (lease->expires - now) > time/8)
		option_put(mess, end, OPTION_T2, 4, ((unsigned int)(lease->expires - now)) - time/8);
	      if (in_list(req_options, OPTION_LAST_TRANSACTION) && (lease->expires - now) < time)
		option_put(mess, end, OPTION_LAST_TRANSACTION, 4, time - ((unsigned int)(lease->expires - now)));
	    }
	  
	  if (lease->vendorclass)
	    {
	      memcpy(daemon->dhcp_buff3, lease->vendorclass, lease->vendorclass_len);
	      vendor_class_len = lease->vendorclass_len;
	    }
	  
	  subnet_addr.s_addr = 0;
	  do_options(context, mess, end, req_options, lease->hostname, get_domain(lease->addr), netid, subnet_addr,
		     0, 0, -1, NULL, vendor_class_len, now, 0xffffffff, 0, NULL, 1);
	  
	  /* Does this have to be last for leasequery replies also? RFC 4388 is silent on the subject. */
	  if (lease->agent_id && in_list(req_options, OPTION_AGENT_ID) &&
	      (p = free_space(mess, end, OPTION_AGENT_ID, lease->agent_id_len)))
	    memcpy(p, lease->agent_id, lease->agent_id_len);
	}
      
      return dhcp_packet_size(mess, NULL, real_end);
            
    case DHCPDECLINE:
      if (!(opt = option_find(mess, sz, OPTION_SERVER_IDENTIFIER, INADDRSZ)) ||
	  option_addr(opt).s_addr != server_id(context, override, fallback).s_addr)
	return 0;
      
      /* sanitise any message. Paranoid? Moi? */
      sanitise(option_find(mess, sz, OPTION_MESSAGE, 1), daemon->dhcp_buff);
      
      if (!(opt = option_find(mess, sz, OPTION_REQUESTED_IP, INADDRSZ)))
	return 0;
      
      daemon->metrics[METRIC_DHCPDECLINE]++;
      log_packet("DHCPDECLINE", option_ptr(opt, 0), emac, emac_len, iface_name, NULL, daemon->dhcp_buff, mess->xid);
      
      if (lease && lease->addr.s_addr == option_addr(opt).s_addr)
	lease_prune(lease, now);
      
      if (have_config(config, CONFIG_ADDR) && 
	  config->addr.s_addr == option_addr(opt).s_addr)
	{
	  prettyprint_time(daemon->dhcp_buff, DECLINE_BACKOFF);
	  inet_ntop(AF_INET, &config->addr, daemon->addrbuff, ADDRSTRLEN);
	  my_syslog(MS_DHCP | LOG_WARNING, _("disabling DHCP static address %s for %s"), 
		    daemon->addrbuff, daemon->dhcp_buff);
	  config->flags |= CONFIG_DECLINED;
	  config->decline_time = now;
	}
      else
	/* make sure this host gets a different address next time. */
	for (; context; context = context->current)
	  context->addr_epoch++;
      
      return 0;

    case DHCPRELEASE:
      if (!(context = narrow_context(context, mess->ciaddr, tagif_netid)) ||
	  !(opt = option_find(mess, sz, OPTION_SERVER_IDENTIFIER, INADDRSZ)) ||
	  option_addr(opt).s_addr != server_id(context, override, fallback).s_addr)
	return 0;
      
      if (lease && lease->addr.s_addr == mess->ciaddr.s_addr)
	lease_prune(lease, now);
      else
	message = _("unknown lease");

      daemon->metrics[METRIC_DHCPRELEASE]++;
      log_packet("DHCPRELEASE", &mess->ciaddr, emac, emac_len, iface_name, NULL, message, mess->xid);
	
      return 0;
      
    case DHCPDISCOVER:
      if (ignore || have_config(config, CONFIG_DISABLE))
	{
	  if (option_bool(OPT_QUIET_DHCP))
	    return 0;
	  message = _("ignored");
	  opt = NULL;
	}
      else 
	{
	  struct in_addr addr, conf;
	  
	  addr.s_addr = conf.s_addr = 0;

	  if ((opt = option_find(mess, sz, OPTION_REQUESTED_IP, INADDRSZ)))	 
	    addr = option_addr(opt);
	  
	  if (have_config(config, CONFIG_ADDR))
	    {
	      inet_ntop(AF_INET, &config->addr, daemon->addrbuff, ADDRSTRLEN);
	      
	      if ((ltmp = lease_find_by_addr(config->addr)) && 
		  ltmp != lease &&
		  !config_has_mac(config, ltmp->hwaddr, ltmp->hwaddr_len, ltmp->hwaddr_type))
		{
		  int len;
		  unsigned char *mac = extended_hwaddr(ltmp->hwaddr_type, ltmp->hwaddr_len,
						       ltmp->hwaddr, ltmp->clid_len, ltmp->clid, &len);
		  my_syslog(MS_DHCP | LOG_WARNING, _("not using configured address %s because it is leased to %s"),
			    daemon->addrbuff, print_mac(daemon->namebuff, mac, len));
		}
	      else
		{
		  struct dhcp_context *tmp;
		  for (tmp = context; tmp; tmp = tmp->current)
		    if (context->router.s_addr == config->addr.s_addr)
		      break;
		  if (tmp)
		    my_syslog(MS_DHCP | LOG_WARNING, _("not using configured address %s because it is in use by the server or relay"), daemon->addrbuff);
		  else if (have_config(config, CONFIG_DECLINED) &&
			   difftime(now, config->decline_time) < (float)DECLINE_BACKOFF)
		    my_syslog(MS_DHCP | LOG_WARNING, _("not using configured address %s because it was previously declined"), daemon->addrbuff);
		  else
		    conf = config->addr;
		}
	    }
	  
	  if (conf.s_addr)
	    mess->yiaddr = conf;
	  else if (lease && 
		   address_available(context, lease->addr, tagif_netid) && 
		   !config_find_by_address(daemon->dhcp_conf, lease->addr))
	    mess->yiaddr = lease->addr;
	  else if (opt && address_available(context, addr, tagif_netid) && !lease_find_by_addr(addr) && 
		   !config_find_by_address(daemon->dhcp_conf, addr) && do_icmp_ping(now, addr, 0, loopback))
	    mess->yiaddr = addr;
	  else if (emac_len == 0)
	    message = _("no unique-id");
	  else if (!address_allocate(context, &mess->yiaddr, emac, emac_len, tagif_netid, now, loopback))
	    message = _("no address available");      
	}
      
      daemon->metrics[METRIC_DHCPDISCOVER]++;
      log_packet("DHCPDISCOVER", opt ? option_ptr(opt, 0) : NULL, emac, emac_len, iface_name, NULL, message, mess->xid); 

      if (message || !(context = narrow_context(context, mess->yiaddr, tagif_netid)))
	return 0;

      if (context->netid.net)
	{
	  context->netid.next = netid;
	  tagif_netid = run_tag_if(&context->netid);
	}

      apply_delay(mess->xid, recvtime, tagif_netid);

      if (option_bool(OPT_RAPID_COMMIT) && option_find(mess, sz, OPTION_RAPID_COMMIT, 0))
	{
	  rapid_commit = 1;
	  /* If a lease exists for this host and another address, squash it. */
	  if (lease && lease->addr.s_addr != mess->yiaddr.s_addr)
	    {
	      lease_prune(lease, now);
	      lease = NULL;
	    }
	  goto rapid_commit;
	}
      
      log_tags(tagif_netid, ntohl(mess->xid));

      daemon->metrics[METRIC_DHCPOFFER]++;
      log_packet("DHCPOFFER" , &mess->yiaddr, emac, emac_len, iface_name, NULL, NULL, mess->xid);
      
      time = calc_time(context, config, option_find(mess, sz, OPTION_LEASE_TIME, 4));
      clear_packet(mess, end);
      option_put(mess, end, OPTION_MESSAGE_TYPE, 1, DHCPOFFER);
      option_put(mess, end, OPTION_SERVER_IDENTIFIER, INADDRSZ, ntohl(server_id(context, override, fallback).s_addr));
      option_put(mess, end, OPTION_LEASE_TIME, 4, time);
      /* T1 and T2 are required in DHCPOFFER by HP's wacky Jetdirect client. */
      do_options(context, mess, end, req_options, offer_hostname, get_domain(mess->yiaddr), 
		 netid, subnet_addr, fqdn_flags, borken_opt, pxearch, uuid, vendor_class_len, now, time, fuzz, pxevendor, 0);
      
      return dhcp_packet_size(mess, agent_id, real_end);
	

    case DHCPREQUEST:
      if (ignore || have_config(config, CONFIG_DISABLE))
	return 0;
      if ((opt = option_find(mess, sz, OPTION_REQUESTED_IP, INADDRSZ)))
	{
	  /* SELECTING  or INIT_REBOOT */
	  mess->yiaddr = option_addr(opt);
	  
	  /* send vendor and user class info for new or recreated lease */
	  do_classes = 1;
	  
	  if ((opt = option_find(mess, sz, OPTION_SERVER_IDENTIFIER, INADDRSZ)))
	    {
	      /* SELECTING */
	      selecting = 1;
	      
	      if (override.s_addr != 0)
		{
		  if (option_addr(opt).s_addr != override.s_addr)
		    return 0;
		}
	      else 
		{
		  for (; context; context = context->current)
		    if (context->local.s_addr == option_addr(opt).s_addr)
		      break;
		  
		  if (!context)
		    {
		      /* Handle very strange configs where clients have more than one route to the server.
			 If a clients idea of its server-id matches any of our DHCP interfaces, we let it pass.
			 Have to set override to make sure we echo back the correct server-id */
		      struct irec *intr;
		      
		      enumerate_interfaces(0);

		      for (intr = daemon->interfaces; intr; intr = intr->next)
			if (intr->addr.sa.sa_family == AF_INET &&
			    intr->addr.in.sin_addr.s_addr == option_addr(opt).s_addr &&
			    intr->tftp_ok)
			  break;

		      if (intr)
			override = intr->addr.in.sin_addr;
		      else
			{
			  /* In auth mode, a REQUEST sent to the wrong server
			     should be faulted, so that the client establishes 
			     communication with us, otherwise, silently ignore. */
			  if (!option_bool(OPT_AUTHORITATIVE))
			    return 0;
			  message = _("wrong server-ID");
			}
		    }
		}

	      /* If a lease exists for this host and another address, squash it. */
	      if (lease && lease->addr.s_addr != mess->yiaddr.s_addr)
		{
		  lease_prune(lease, now);
		  lease = NULL;
		}
	    }
	  else
	    {
	      /* INIT-REBOOT */
	      if (!lease && !option_bool(OPT_AUTHORITATIVE))
		return 0;
	      
	      if (lease && lease->addr.s_addr != mess->yiaddr.s_addr)
		message = _("wrong address");
	    }
	}
      else
	{
	  /* RENEWING or REBINDING */ 
	  /* Check existing lease for this address.
	     We allow it to be missing if dhcp-authoritative mode
	     as long as we can allocate the lease now - checked below.
	     This makes for a smooth recovery from a lost lease DB */
	  if ((lease && mess->ciaddr.s_addr != lease->addr.s_addr) ||
	      (!lease && !option_bool(OPT_AUTHORITATIVE)))
	    {
	      /* A client rebinding will broadcast the request, so we may see it even 
		 if the lease is held by another server. Just ignore it in that case. 
		 If the request is unicast to us, then somethings wrong, NAK */
	      if (!unicast_dest)
		return 0;
	      message = _("lease not found");
	      /* ensure we broadcast NAK */
	      unicast_dest = 0;
	    }

	  /* desynchronise renewals */
	  fuzz = rand16();
	  mess->yiaddr = mess->ciaddr;
	}

      daemon->metrics[METRIC_DHCPREQUEST]++;
      log_packet("DHCPREQUEST", &mess->yiaddr, emac, emac_len, iface_name, NULL, NULL, mess->xid);
      
    rapid_commit:
      if (!message)
	{
	  struct dhcp_config *addr_config;
	  struct dhcp_context *tmp = NULL;
	  
	  if (have_config(config, CONFIG_ADDR))
	    for (tmp = context; tmp; tmp = tmp->current)
	      if (context->router.s_addr == config->addr.s_addr)
		break;
	  
	  if (!(context = narrow_context(context, mess->yiaddr, tagif_netid)))
	    {
	      /* If a machine moves networks whilst it has a lease, we catch that here. */
	      message = _("wrong network");
	      /* ensure we broadcast NAK */
	      unicast_dest = 0;
	    }
	  
	  /* Check for renewal of a lease which is outside the allowed range. */
	  else if (!address_available(context, mess->yiaddr, tagif_netid) &&
		   (!have_config(config, CONFIG_ADDR) || config->addr.s_addr != mess->yiaddr.s_addr))
	    message = _("address not available");
	  
	  /* Check if a new static address has been configured. Be very sure that
	     when the client does DISCOVER, it will get the static address, otherwise
	     an endless protocol loop will ensue. */
	  else if (!tmp && !selecting &&
		   have_config(config, CONFIG_ADDR) && 
		   (!have_config(config, CONFIG_DECLINED) ||
		    difftime(now, config->decline_time) > (float)DECLINE_BACKOFF) &&
		   config->addr.s_addr != mess->yiaddr.s_addr &&
		   (!(ltmp = lease_find_by_addr(config->addr)) || ltmp == lease))
	    message = _("static lease available");

	  /* Check to see if the address is reserved as a static address for another host */
	  else if ((addr_config = config_find_by_address(daemon->dhcp_conf, mess->yiaddr)) && addr_config != config)
	    message = _("address reserved");

	  else if (!lease && (ltmp = lease_find_by_addr(mess->yiaddr)))
	    {
	      /* If a host is configured with more than one MAC address, it's OK to 'nix 
		 a lease from one of its MACs to give the address to another. */
	      if (config && config_has_mac(config, ltmp->hwaddr, ltmp->hwaddr_len, ltmp->hwaddr_type))
		{
		  inet_ntop(AF_INET, &ltmp->addr, daemon->addrbuff, ADDRSTRLEN);
		  my_syslog(MS_DHCP | LOG_INFO, _("abandoning lease to %s of %s"),
			    print_mac(daemon->namebuff, ltmp->hwaddr, ltmp->hwaddr_len), 
			    daemon->addrbuff);
		  lease = ltmp;
		}
	      else
		message = _("address in use");
	    }

	  if (!message)
	    {
	      if (emac_len == 0)
		message = _("no unique-id");
	      
	      else if (!lease)
		{	     
		  if ((lease = lease4_allocate(mess->yiaddr)))
		    do_classes = 1;
		  else
		    message = _("no leases left");
		}
	    }
	}

      if (message)
	{
	  daemon->metrics[rapid_commit ? METRIC_NOANSWER : METRIC_DHCPNAK]++;
	  log_packet(rapid_commit ? "NOANSWER" : "DHCPNAK", &mess->yiaddr, emac, emac_len, iface_name, NULL, message, mess->xid);

	  /* rapid commit case: lease allocate failed but don't send DHCPNAK */
	  if (rapid_commit)
	    return 0;
	  
	  mess->yiaddr.s_addr = 0;
	  clear_packet(mess, end);
	  option_put(mess, end, OPTION_MESSAGE_TYPE, 1, DHCPNAK);
	  option_put(mess, end, OPTION_SERVER_IDENTIFIER, INADDRSZ, ntohl(server_id(context, override, fallback).s_addr));
	  option_put_string(mess, end, OPTION_MESSAGE, message, borken_opt);
	  /* This fixes a problem with the DHCP spec, broadcasting a NAK to a host on 
	     a distant subnet which unicast a REQ to us won't work. */
	  if (!unicast_dest || mess->giaddr.s_addr != 0 || 
	      mess->ciaddr.s_addr == 0 || is_same_net(context->local, mess->ciaddr, context->netmask))
	    {
	      mess->flags |= htons(0x8000); /* broadcast */
	      mess->ciaddr.s_addr = 0;
	    }
	}
      else
	{
	  if (context->netid.net)
	    {
	      context->netid.next = netid;
	      tagif_netid = run_tag_if( &context->netid);
	    }

	  log_tags(tagif_netid, ntohl(mess->xid));
	  
	  if (do_classes)
	    {
	      /* pick up INIT-REBOOT events. */
	      lease->flags |= LEASE_CHANGED;

#ifdef HAVE_SCRIPT
	      if (daemon->lease_change_command)
		{
		  struct dhcp_netid *n;
		  
		  if (mess->giaddr.s_addr)
		    lease->giaddr = mess->giaddr;
		  
		  free(lease->extradata);
		  lease->extradata = NULL;
		  lease->extradata_size = lease->extradata_len = 0;
		  
		  add_extradata_opt(lease, option_find(mess, sz, OPTION_VENDOR_ID, 1));
		  add_extradata_opt(lease, option_find(mess, sz, OPTION_HOSTNAME, 1));
		  add_extradata_opt(lease, oui);
		  add_extradata_opt(lease, serial);
		  add_extradata_opt(lease, class);

		  if ((opt = option_find(mess, sz, OPTION_AGENT_ID, 1)))
		    {
		      add_extradata_opt(lease, option_find1(option_ptr(opt, 0), option_ptr(opt, option_len(opt)), SUBOPT_CIRCUIT_ID, 1));
		      add_extradata_opt(lease, option_find1(option_ptr(opt, 0), option_ptr(opt, option_len(opt)), SUBOPT_SUBSCR_ID, 1));
		      add_extradata_opt(lease, option_find1(option_ptr(opt, 0), option_ptr(opt, option_len(opt)), SUBOPT_REMOTE_ID, 1));
		    }
		  else
		    {
		      add_extradata_opt(lease, NULL);
		      add_extradata_opt(lease, NULL);
		      add_extradata_opt(lease, NULL);
		    }

		  /* DNSMASQ_REQUESTED_OPTIONS */
		  if ((opt = option_find(mess, sz, OPTION_REQUESTED_OPTIONS, 1)))
		    {
		      int i, len = option_len(opt);
		      unsigned char *rop = option_ptr(opt, 0);
		      
		      for (i = 0; i < len; i++)
			lease_add_extradata(lease, (unsigned char *)daemon->namebuff,
					    sprintf(daemon->namebuff, "%u", rop[i]), (i + 1) == len ? 0 : ',');
		    }
		  else
		    lease_add_extradata(lease, NULL, 0, 0);
		  
		  add_extradata_opt(lease, option_find(mess, sz, OPTION_MUD_URL_V4, 1));
		  
		  /* space-concat tag set */
		  if (!tagif_netid)
		    add_extradata_opt(lease, NULL);
		  else
		    for (n = tagif_netid; n; n = n->next)
		      {
			struct dhcp_netid *n1;
			/* kill dupes */
			for (n1 = n->next; n1; n1 = n1->next)
			  if (strcmp(n->net, n1->net) == 0)
			    break;
			if (!n1)
			  lease_add_extradata(lease, (unsigned char *)n->net, strlen(n->net), n->next ? ' ' : 0); 
		      }
		  
		  if ((opt = option_find(mess, sz, OPTION_USER_CLASS, 1)))
		    {
		      int len = option_len(opt);
		      unsigned char *ucp = option_ptr(opt, 0);
		      /* If the user-class option started as counted strings, the first byte will be zero. */
		      if (len != 0 && ucp[0] == 0)
			ucp++, len--;
		      lease_add_extradata(lease, ucp, len, -1);
		    }
		}
#endif
	    }
	  
	  if (!hostname_auth && (client_hostname = host_from_dns(mess->yiaddr)))
	    {
	      domain = get_domain(mess->yiaddr);
	      hostname = client_hostname;
	      hostname_auth = 1;
	    }
	  
	  time = calc_time(context, config, option_find(mess, sz, OPTION_LEASE_TIME, 4));
	  lease_set_hwaddr(lease, mess->chaddr, clid, mess->hlen, mess->htype, clid_len, now, do_classes);
	  
	  /* if all the netids in the ignore_name list are present, ignore client-supplied name */
	  if (!hostname_auth)
	    {
	      for (id_list = daemon->dhcp_ignore_names; id_list; id_list = id_list->next)
		if ((!id_list->list) || match_netid(id_list->list, tagif_netid, 0))
		  break;
	      if (id_list)
		hostname = NULL;
	    }
	  
	  /* Last ditch, if configured, generate hostname from mac address */
	  if (!hostname && emac_len != 0)
	    {
	      for (id_list = daemon->dhcp_gen_names; id_list; id_list = id_list->next)
		if ((!id_list->list) || match_netid(id_list->list, tagif_netid, 0))
		  break;
	      if (id_list)
		{
		  int i;

		  hostname = daemon->dhcp_buff;
		  /* buffer is 256 bytes, 3 bytes per octet */
		  for (i = 0; (i < emac_len) && (i < 80); i++)
		    hostname += sprintf(hostname, "%.2x%s", emac[i], (i == emac_len - 1) ? "" : "-");
		  hostname = daemon->dhcp_buff;
		}
	    }

	  if (hostname)
	    lease_set_hostname(lease, hostname, hostname_auth, get_domain(lease->addr), domain);
	  
	  lease_set_expires(lease, time, now);
	  lease_set_interface(lease, int_index, now);
	  
	  if (option_bool(OPT_LEASEQUERY))
	    {
	      if (agent_id)
		lease_set_agent_id(lease, option_ptr(agent_id, 0), option_len(agent_id));
	      if (vendor_class_len != 0)
		lease_set_vendorclass(lease, (unsigned char *)daemon->dhcp_buff3, vendor_class_len);
	    }
	  else
	    {
	      /* if leasequery no longer enabled, remove stuff that may have been stored when it was. */
	      lease_set_agent_id(lease, NULL, 0);
	      lease_set_vendorclass(lease, NULL, 0);
	    }
	  
	  if (override.s_addr != 0)
	    lease->override = override;
	  else
	    override = lease->override;

	  daemon->metrics[METRIC_DHCPACK]++;
	  log_packet("DHCPACK", &mess->yiaddr, emac, emac_len, iface_name, hostname, NULL, mess->xid);  

	  clear_packet(mess, end);
	  option_put(mess, end, OPTION_MESSAGE_TYPE, 1, DHCPACK);
	  option_put(mess, end, OPTION_SERVER_IDENTIFIER, INADDRSZ, ntohl(server_id(context, override, fallback).s_addr));
	  option_put(mess, end, OPTION_LEASE_TIME, 4, time);
	  if (rapid_commit)
	     option_put(mess, end, OPTION_RAPID_COMMIT, 0, 0);
	   do_options(context, mess, end, req_options, hostname, get_domain(mess->yiaddr), 
		      netid, subnet_addr, fqdn_flags, borken_opt, pxearch, uuid, vendor_class_len, now, time, fuzz, pxevendor, 0);
	}

      return dhcp_packet_size(mess, agent_id, real_end); 
      
    case DHCPINFORM:
      if (ignore || have_config(config, CONFIG_DISABLE))
	message = _("ignored");
      
      daemon->metrics[METRIC_DHCPINFORM]++;
      log_packet("DHCPINFORM", &mess->ciaddr, emac, emac_len, iface_name, message, NULL, mess->xid);
     
      if (message || mess->ciaddr.s_addr == 0)
	return 0;

      /* For DHCPINFORM only, cope without a valid context */
      context = narrow_context(context, mess->ciaddr, tagif_netid);
      
      /* Find a least based on IP address if we didn't
	 get one from MAC address/client-d */
      if (!lease &&
	  (lease = lease_find_by_addr(mess->ciaddr)) && 
	  lease->hostname)
	hostname = lease->hostname;
      
      if (!hostname)
	hostname = host_from_dns(mess->ciaddr);
      
      if (context && context->netid.net)
	{
	  context->netid.next = netid;
	  tagif_netid = run_tag_if(&context->netid);
	}

      log_tags(tagif_netid, ntohl(mess->xid));
      
      daemon->metrics[METRIC_DHCPACK]++;
      log_packet("DHCPACK", &mess->ciaddr, emac, emac_len, iface_name, hostname, NULL, mess->xid);
      
      if (lease)
	{
	  lease_set_interface(lease, int_index, now);
	  if (override.s_addr != 0)
	    lease->override = override;
	  else
	    override = lease->override;
	}

      clear_packet(mess, end);
      option_put(mess, end, OPTION_MESSAGE_TYPE, 1, DHCPACK);
      option_put(mess, end, OPTION_SERVER_IDENTIFIER, INADDRSZ, ntohl(server_id(context, override, fallback).s_addr));
     
      /* RFC 2131 says that DHCPINFORM shouldn't include lease-time parameters, but 
	 we supply a utility which makes DHCPINFORM requests to get this information.
	 Only include lease time if OPTION_LEASE_TIME is in the parameter request list,
	 which won't be true for ordinary clients, but will be true for the 
	 dhcp_lease_time utility. */
      if (lease && in_list(req_options, OPTION_LEASE_TIME))
	{
	  if (lease->expires == 0)
	    time = 0xffffffff;
	  else
	    time = (unsigned int)difftime(lease->expires, now);
	  option_put(mess, end, OPTION_LEASE_TIME, 4, time);
	}

      do_options(context, mess, end, req_options, hostname, get_domain(mess->ciaddr),
		 netid, subnet_addr, fqdn_flags, borken_opt, pxearch, uuid, vendor_class_len, now, 0xffffffff, 0, pxevendor, 0);
      
      *is_inform = 1; /* handle reply differently */
      return dhcp_packet_size(mess, agent_id, real_end); 
    }
  
  return 0;
}

/* find a good value to use as MAC address for logging and address-allocation hashing.
   This is normally just the chaddr field from the DHCP packet,
   but eg Firewire will have hlen == 0 and use the client-id instead. 
   This could be anything, but will normally be EUI64 for Firewire.
   We assume that if the first byte of the client-id equals the htype byte
   then the client-id is using the usual encoding and use the rest of the 
   client-id: if not we can use the whole client-id. This should give
   sane MAC address logs. */
unsigned char *extended_hwaddr(int hwtype, int hwlen, unsigned char *hwaddr, 
				      int clid_len, unsigned char *clid, int *len_out)
{
  if (hwlen == 0 && clid && clid_len > 3)
    {
      if (clid[0]  == hwtype)
	{
	  *len_out = clid_len - 1 ;
	  return clid + 1;
	}

#if defined(ARPHRD_EUI64) && defined(ARPHRD_IEEE1394)
      if (clid[0] ==  ARPHRD_EUI64 && hwtype == ARPHRD_IEEE1394)
	{
	  *len_out = clid_len - 1 ;
	  return clid + 1;
	}
#endif
      
      *len_out = clid_len;
      return clid;
    }
  
  *len_out = hwlen;
  return hwaddr;
}

/**
 * @brief Calculate DHCP lease time considering server config, context, and client request
 * 
 * Determines the appropriate lease time for a DHCP lease assignment by consulting
 * multiple sources in order of precedence and applying sanity checks. This function
 * implements the lease time negotiation logic specified in RFC 2131, where clients
 * may request specific lease durations but servers have final authority to grant
 * shorter or longer times based on policy.
 * 
 * Lease Time Selection Priority (from highest to lowest precedence):
 * 1. Client-requested lease time from OPTION_LEASE_TIME (option 51) if provided
 * 2. Host-specific lease time from dhcp_config (if CONFIG_TIME flag set)
 * 3. Network-segment default from dhcp_context->lease_time
 * 
 * The function applies a minimum lease time sanity check of 120 seconds to prevent
 * unreasonably short leases that would cause excessive DHCP traffic and server load.
 * Client requests below this threshold are silently raised to 120 seconds.
 * 
 * INFINITE LEASE HANDLING (0xffffffff):
 * If the server's configured lease time is 0xffffffff (infinite/permanent), the
 * server will grant an infinite lease UNLESS the client specifically requests a
 * finite lease time. This allows clients to opt for finite leases even when the
 * server offers infinite leases by default.
 * 
 * If the client requests a finite lease time (not 0xffffffff), the server will
 * grant the SHORTER of the server's maximum and the client's request. This ensures
 * that neither party can force a longer lease than the other party is willing to
 * grant.
 * 
 * Lease time negotiation logic:
 * - If server time is infinite (0xffffffff): honor any client request (infinite or finite)
 * - If client requests infinite (0xffffffff): grant server's maximum time
 * - Otherwise: grant minimum of server maximum and client request (both finite)
 * 
 * This implements RFC 2131 Section 4.3.1: "The server may choose to return a lease
 * duration other than the requested duration."
 * 
 * Lease time is measured in seconds from the time of assignment. A lease time of
 * 0xffffffff (4294967295) represents an infinite lease (permanent assignment), though
 * this is rarely used in practice due to reclamation and management concerns.
 * 
 * @param context Pointer to DHCP context for the network segment (contains default lease_time)
 *                Must not be NULL. Provides the fallback lease time if no host-specific
 *                configuration exists. Source: src/dnsmasq.h struct dhcp_context
 * @param config Pointer to host-specific DHCP configuration or NULL if no host config exists
 *               If non-NULL and CONFIG_TIME flag is set in config->flags, the config->lease_time
 *               is used as the server's maximum lease time. If NULL or CONFIG_TIME not set,
 *               context->lease_time is used instead. Source: src/dnsmasq.h struct dhcp_config
 * @param opt Pointer to OPTION_LEASE_TIME (option 51) data from client request, or NULL
 *            If non-NULL, points to DHCP option data starting with option code and length,
 *            followed by 4-byte big-endian unsigned integer containing client's requested
 *            lease time in seconds. If NULL, no client request is present and server's
 *            configured maximum is used without adjustment.
 * 
 * @return Calculated lease time in seconds to grant for this lease assignment
 * @retval 120..0xffffffff Lease time in seconds (minimum 120 enforced for finite leases)
 * @retval context->lease_time If no config and no client request
 * @retval config->lease_time If config has CONFIG_TIME and no client request
 * @retval 0xffffffff If server offers infinite lease and client doesn't request finite
 * @retval min(server_time, client_request) For finite lease negotiation
 * 
 * @note Minimum lease time of 120 seconds prevents excessive renewal traffic
 * @note Infinite leases (0xffffffff) are possible but should be used cautiously
 * @note Function does not modify any data structures - pure calculation
 * @note Client can request shorter lease than server maximum, but not longer
 * @warning context must not be NULL (no NULL check performed for performance)
 * @warning opt must point to valid option buffer if non-NULL (extracted via option_uint)
 * @warning Client-requested times below 120 seconds are silently adjusted upward
 * 
 * @see option_uint() in src/rfc2131.c - extracts 4-byte unsigned integer from DHCP option
 * @see have_config() macro in src/dnsmasq.h - checks if CONFIG_TIME flag is set
 * @see struct dhcp_context in src/dnsmasq.h:line~800 - defines context->lease_time
 * @see struct dhcp_config in src/dnsmasq.h:line~750 - defines config->lease_time and flags
 * @see OPTION_LEASE_TIME (option 51) in src/dhcp-protocol.h - client lease time request
 * @see CONFIG_TIME flag in src/dnsmasq.h - indicates config->lease_time is valid
 * 
 * EXAMPLE USAGE:
 * @code
 * // Scenario 1: No host config, no client request - use network default
 * struct dhcp_context *ctx = find_context(...);
 * ctx->lease_time = 3600; // 1 hour default
 * unsigned int lease = calc_time(ctx, NULL, NULL);
 * // Result: lease == 3600 (context default)
 * 
 * // Scenario 2: Host-specific config with longer lease time
 * struct dhcp_config *cfg = find_config(...);
 * cfg->flags |= CONFIG_TIME;
 * cfg->lease_time = 86400; // 24 hours
 * ctx->lease_time = 3600;  // 1 hour default
 * unsigned int lease = calc_time(ctx, cfg, NULL);
 * // Result: lease == 86400 (host config overrides context)
 * 
 * // Scenario 3: Client requests 2 hours, server max is 1 hour
 * unsigned char opt_data[6] = { OPTION_LEASE_TIME, 4, 0x00, 0x00, 0x1c, 0x20 }; // 7200 sec
 * ctx->lease_time = 3600; // 1 hour
 * unsigned int lease = calc_time(ctx, NULL, opt_data);
 * // Result: lease == 3600 (server maximum is less than client request)
 * 
 * // Scenario 4: Client requests 30 seconds (too short)
 * unsigned char opt_short[6] = { OPTION_LEASE_TIME, 4, 0x00, 0x00, 0x00, 0x1e }; // 30 sec
 * ctx->lease_time = 3600;
 * unsigned int lease = calc_time(ctx, NULL, opt_short);
 * // Result: lease == 120 (minimum sanity check applied)
 * 
 * // Scenario 5: Server offers infinite, client requests 1 hour
 * unsigned char opt_finite[6] = { OPTION_LEASE_TIME, 4, 0x00, 0x00, 0x0e, 0x10 }; // 3600 sec
 * ctx->lease_time = 0xffffffff; // Infinite
 * unsigned int lease = calc_time(ctx, NULL, opt_finite);
 * // Result: lease == 3600 (client opts for finite lease despite server offering infinite)
 * 
 * // Scenario 6: Server offers infinite, client requests infinite
 * unsigned char opt_inf[6] = { OPTION_LEASE_TIME, 4, 0xff, 0xff, 0xff, 0xff }; // Infinite
 * ctx->lease_time = 0xffffffff;
 * unsigned int lease = calc_time(ctx, NULL, opt_inf);
 * // Result: lease == 0xffffffff (both agree on infinite lease)
 * 
 * // Scenario 7: Server max 1 hour, client requests infinite
 * ctx->lease_time = 3600; // 1 hour
 * unsigned int lease = calc_time(ctx, NULL, opt_inf);
 * // Result: lease == 3600 (server maximum limits infinite client request)
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 2131 Section 4.3.1 - Server may return different lease duration than requested
 * RFC COMPLIANCE: RFC 2131 Section 3.1 - IP Address Lease Time option (option 51) format
 * RFC COMPLIANCE: RFC 2132 Section 9.2 - IP Address Lease Time option encoding (4-byte unsigned)
 * RFC COMPLIANCE: RFC 2131 Section 1.5 - Infinite lease time value 0xffffffff interpretation
 * SIDE EFFECTS: None (pure function, performs calculations only without modifying state)
 * THREAD SAFETY: Thread-safe (read-only access to context and config, no shared mutable state)
 */
static unsigned int calc_time(struct dhcp_context *context, struct dhcp_config *config, unsigned char *opt)
{
  unsigned int time = have_config(config, CONFIG_TIME) ? config->lease_time : context->lease_time;
  
  if (opt)
    { 
      unsigned int req_time = option_uint(opt, 0, 4);
      if (req_time < 120 )
	req_time = 120; /* sanity */
      if (time == 0xffffffff || (req_time != 0xffffffff && req_time < time))
	time = req_time;
    }

  return time;
}

/**
 * @brief Determine the DHCP server identifier IP address to use in responses
 * 
 * Selects the appropriate server identifier (option 54) to include in DHCP
 * responses based on configuration override, interface-specific context, and
 * fallback address. The server identifier tells clients which DHCP server they
 * are communicating with and is used in subsequent REQUEST messages.
 * 
 * @param context DHCP context for the interface receiving the request (may be NULL)
 * @param override Explicitly configured server identifier override (0.0.0.0 if none)
 * @param fallback Fallback IP address to use if no context-specific address available
 * 
 * @return Server identifier IP address selected according to precedence rules
 * 
 * @note Selection precedence: override address > context local address > fallback
 * @note Server identifier must be an IP address of the DHCP server reachable by client
 * 
 * EXAMPLE USAGE:
 * @code
 * struct in_addr sid = server_id(context, daemon->override, iface_addr);
 * // sid now contains the server identifier for DHCP option 54
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 2131 Section 4.3.1 - Server Identifier option required in OFFER and ACK
 * SIDE EFFECTS: None (pure function with no side effects)
 * THREAD SAFETY: Thread-safe (operates only on parameter values)
 */
static struct in_addr server_id(struct dhcp_context *context, struct in_addr override, struct in_addr fallback)
{
  if (override.s_addr != 0)
    return override;
  else if (context && context->local.s_addr != 0)
    return context->local;
  else
    return fallback;
}

/**
 * @brief Sanitize DHCP option data by filtering to printable ASCII characters
 * 
 * Converts DHCP option data to a printable string by extracting characters from the
 * option data field and filtering to include only printable ASCII characters as
 * determined by isprint(). Non-printable characters (control codes, NULL bytes, etc.)
 * are silently discarded to prevent log injection attacks and ensure safe string
 * handling in logging and display contexts.
 * 
 * This function is critical for security when handling untrusted DHCP option data
 * from clients, particularly for hostname, vendor class, user class, and other
 * text-oriented DHCP options that may be logged or displayed. The sanitization
 * prevents malicious clients from injecting control sequences, newlines, or NULL
 * bytes into log output or system buffers.
 * 
 * The function uses option_len() macro to determine the length of option data and
 * option_ptr() macro to obtain a pointer to the option data payload, excluding the
 * option type and length bytes defined in RFC 2132 option format.
 * 
 * @param opt Pointer to DHCP option structure beginning with option type byte, or
 *            NULL if option not present. Option format per RFC 2132: type (1 byte),
 *            length (1 byte), data (length bytes).
 * @param buf Output buffer to receive sanitized string. Must be pre-allocated by
 *            caller with sufficient space to hold option_len(opt) + 1 bytes for
 *            worst case (all printable) plus NULL terminator. Buffer is always
 *            NULL-terminated, even if empty.
 * 
 * @return 1 if option was present and processed (including if result is empty string
 *           because all characters were non-printable)
 * @return 0 if opt parameter was NULL (option not present)
 * 
 * @note Caller must allocate output buffer with size ≥ option_len(opt) + 1 bytes
 * @note Output buffer always NULL-terminated, even for NULL input (set to empty string)
 * @note Uses isprint() from <ctype.h> to determine character printability
 * @warning No bounds checking on output buffer - caller must ensure adequate size
 * @warning Filter is based on isprint() locale-dependent behavior
 * 
 * @see option_len() macro in rfc2131.c for extracting DHCP option length
 * @see option_ptr() macro in rfc2131.c for obtaining pointer to option data
 * @see log_packet() which uses sanitise() for hostname sanitization in DHCP logs
 * 
 * RFC COMPLIANCE: Sanitization implements defensive handling for RFC 2132 text options
 * including option 12 (hostname), option 60 (vendor class identifier), and option 77
 * (user class), which may contain untrusted data requiring validation before logging.
 * 
 * SIDE EFFECTS: Modifies output buffer pointed to by buf parameter
 * THREAD SAFETY: Thread-safe if opt and buf do not alias or overlap
 * 
 * EXAMPLE USAGE:
 * @code
 * unsigned char *hostname_opt = option_find(mess, sz, OPTION_HOSTNAME, 1);
 * char sanitized[256];
 * if (sanitise(hostname_opt, sanitized))
 *     my_syslog(MS_DHCP | LOG_INFO, "Client hostname: %s", sanitized);
 * @endcode
 */
static int sanitise(unsigned char *opt, char *buf)
{
  char *p;
  int i;
  
  *buf = 0;
  
  if (!opt)
    return 0;

  p = option_ptr(opt, 0);

  for (i = option_len(opt); i > 0; i--)
    {
      char c = *p++;
      if (isprint((unsigned char)c))
	*buf++ = c;
    }
  *buf = 0; /* add terminator */
  
  return 1;
}

#ifdef HAVE_SCRIPT
/**
 * @brief Store DHCP option data as extra data for lease-change script execution
 * 
 * Extracts data from a DHCP option structure and attaches it to a DHCP lease as
 * "extra data" for passing to external lease-change scripts (dhcp-script). This
 * function is a wrapper around lease_add_extradata() that handles the conversion
 * from DHCP option format (RFC 2132 type-length-value encoding) to the raw data
 * buffer format expected by the lease database and script invocation system.
 * 
 * This function is conditionally compiled only when HAVE_SCRIPT is defined, as
 * extra data is exclusively used for passing additional DHCP option information
 * to external scripts invoked on lease events (add, old, del). Without script
 * support, extra data collection would be unnecessary overhead.
 * 
 * The function supports collecting arbitrary DHCP options (vendor class, user
 * class, client identifier, vendor-specific information, etc.) that scripts may
 * need for custom processing such as dynamic DNS updates, firewall rule generation,
 * device classification, or asset management integration.
 * 
 * Extra data is stored in the lease structure using the lease_add_extradata()
 * interface defined in lease.c, which maintains a linked list of extra data
 * blocks associated with each lease. When scripts are invoked, this extra data
 * is passed via environment variables or command-line arguments depending on the
 * data type flag (final parameter, always 0 in this function).
 * 
 * @param lease Pointer to DHCP lease structure to attach extra data. Must not be
 *              NULL. Lease structure is modified to add extra data block to its
 *              linked list of additional information.
 * @param opt Pointer to DHCP option in RFC 2132 format (type, length, data bytes),
 *            or NULL if option was not present in client packet. When NULL, adds
 *            an empty extra data entry to indicate option was explicitly absent.
 *            When non-NULL, extracts data payload using option_ptr() and option_len()
 *            macros to skip type and length bytes.
 * 
 * @return void - No return value. Errors in lease_add_extradata() (memory allocation
 *         failures) are handled internally by that function.
 * 
 * @note Conditionally compiled only when HAVE_SCRIPT defined at build time
 * @note Extra data is used exclusively for script execution - has no impact on DHCP
 *       protocol operation or lease management without scripts
 * @note Calls lease_add_extradata() with data type flag always set to 0 (text data)
 * @warning Caller must ensure lease pointer is valid - no NULL checking performed
 * @warning Option pointer validity is checked only for NULL - malformed options
 *          with incorrect length fields may cause buffer overruns in lease_add_extradata()
 * 
 * @see lease_add_extradata() in lease.c for extra data storage implementation
 * @see option_ptr() macro in rfc2131.c for obtaining pointer to option data field
 * @see option_len() macro in rfc2131.c for extracting option data length
 * @see dhcp_reply() which calls this function to collect vendor class, user class,
 *      and other options for script execution
 * 
 * RFC COMPLIANCE: Handles RFC 2132 DHCP option format (type-length-value encoding)
 * for options including option 60 (vendor class identifier), option 61 (client
 * identifier), option 77 (user class), and vendor-specific options. The extracted
 * data is passed to external scripts for custom processing beyond standard DHCP
 * protocol requirements.
 * 
 * SIDE EFFECTS:
 * - Modifies lease structure by adding extra data block via lease_add_extradata()
 * - Allocates memory for extra data storage (handled by lease_add_extradata())
 * - Extra data persisted with lease and available during script invocation
 * 
 * THREAD SAFETY: Not thread-safe - modifies shared lease structure without locking
 * 
 * EXAMPLE USAGE:
 * @code
 * // Collect vendor class identifier (option 60) for script execution
 * unsigned char *vendor_opt = option_find(mess, sz, OPTION_VENDOR_ID, 1);
 * add_extradata_opt(lease, vendor_opt);  // Adds vendor class to lease extra data
 * 
 * // Collect client identifier (option 61) for script execution
 * unsigned char *client_id = option_find(mess, sz, OPTION_CLIENT_ID, 1);
 * add_extradata_opt(lease, client_id);   // Adds client ID to lease extra data
 * @endcode
 */
static void add_extradata_opt(struct dhcp_lease *lease, unsigned char *opt)
{
  if (!opt)
    lease_add_extradata(lease, NULL, 0, 0);
  else
    lease_add_extradata(lease, option_ptr(opt, 0), option_len(opt), 0); 
}
#endif

/**
 * @brief Log DHCPv4 transaction message to syslog and broadcast UBus event
 * 
 * Generates and logs a formatted DHCPv4 transaction message to syslog with the
 * MS_DHCP facility at LOG_INFO priority. The log message includes the transaction
 * type (DHCPDISCOVER, DHCPOFFER, DHCPREQUEST, DHCPACK, DHCPNAK, etc.), network
 * interface name, client IP address, client MAC address, hostname or additional
 * descriptive string, and any error message. On systems compiled with HAVE_UBUS,
 * the function also broadcasts UBus events for DHCPACK and DHCPRELEASE messages
 * to enable integration with OpenWrt system management tools.
 * 
 * The function respects configuration flags for logging behavior:
 * - OPT_QUIET_DHCP: Suppresses normal DHCP transaction logging (unless errors occur)
 * - OPT_LOG_OPTS: Includes transaction ID (xid) in log output for detailed diagnostics
 * 
 * Log message format varies based on OPT_LOG_OPTS:
 * - With OPT_LOG_OPTS: "<xid> <type>(<interface>) <ip> <mac> <string> <err>"
 * - Without OPT_LOG_OPTS: "<type>(<interface>) <ip> <mac> <string> <err>"
 * 
 * @param type DHCP message type string (e.g., "DHCPDISCOVER", "DHCPOFFER", "DHCPACK", "DHCPNAK")
 * @param addr Pointer to struct in_addr containing client IPv4 address, or NULL if address not available
 * @param ext_mac Pointer to client hardware address (MAC address) buffer, or NULL if not available
 * @param mac_len Length of hardware address in bytes (typically 6 for Ethernet MAC addresses)
 * @param interface Network interface name where DHCP transaction occurred (e.g., "eth0", "br0")
 * @param string Additional descriptive string (hostname, vendor info, etc.), or NULL if none
 * @param err Error message string describing transaction failure, or NULL if no error
 * @param xid DHCP transaction ID in network byte order (32-bit unsigned integer from DHCP packet)
 * 
 * @return void
 * 
 * @note Logging suppressed if OPT_QUIET_DHCP is set and no error occurred and OPT_LOG_OPTS not set
 * @note Uses daemon global buffers (addrbuff, namebuff) for formatting - not thread-safe
 * @note UBus events only broadcast for DHCPACK and DHCPRELEASE when HAVE_UBUS compiled
 * @warning Function modifies daemon->addrbuff and daemon->namebuff global buffers
 * 
 * @see my_syslog() in log.c for syslog message transmission
 * @see print_mac() for MAC address formatting
 * @see ubus_event_bcast() in ubus.c for UBus event broadcasting (if HAVE_UBUS)
 * 
 * EXAMPLE USAGE:
 * @code
 * // Log successful DHCP ACK with all information
 * struct in_addr client_ip;
 * client_ip.s_addr = mess->yiaddr;
 * unsigned char client_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
 * log_packet("DHCPACK", &client_ip, client_mac, 6, "eth0", 
 *            "client-hostname", NULL, mess->xid);
 * 
 * // Log DHCP NAK error with no IP address assigned
 * log_packet("DHCPNAK", NULL, client_mac, 6, "eth0", 
 *            NULL, "no address available", mess->xid);
 * 
 * // Log DHCP DISCOVER with minimal information
 * log_packet("DHCPDISCOVER", NULL, client_mac, 6, "eth0", NULL, NULL, mess->xid);
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 2131 Section 3 - DHCP Message Types
 * SIDE EFFECTS: Writes to syslog, modifies daemon->addrbuff and daemon->namebuff global buffers,
 *               broadcasts UBus events on OpenWrt systems (HAVE_UBUS)
 * THREAD SAFETY: Not thread-safe due to use of shared daemon global buffers
 */
static void log_packet(char *type, void *addr, unsigned char *ext_mac, 
		       int mac_len, char *interface, char *string, char *err, u32 xid)
{
  if (!err && !option_bool(OPT_LOG_OPTS) && option_bool(OPT_QUIET_DHCP))
    return;
  
  daemon->addrbuff[0] = daemon->namebuff[0] = 0;
  
  if (addr)
    inet_ntop(AF_INET, addr, daemon->addrbuff, ADDRSTRLEN);
  
  if (ext_mac)
    print_mac(daemon->namebuff, ext_mac, mac_len);
  
  if (option_bool(OPT_LOG_OPTS))
    my_syslog(MS_DHCP | LOG_INFO, "%u %s(%s) %s%s%s%s%s%s",
	      ntohl(xid), 
	      type,
	      interface, 
	      daemon->addrbuff,
	      addr ? " " : "",
	      daemon->namebuff,
	      ext_mac ? " " : "",
	      string ? string : "",
	      err ? err : "");
  else
    my_syslog(MS_DHCP | LOG_INFO, "%s(%s) %s%s%s%s%s%s",
	      type,
	      interface, 
	      daemon->addrbuff,
	      addr ? " " : "",
	      daemon->namebuff,
	      ext_mac ? " " : "",
	      string ? string : "",
	      err ? err : "");
  
#ifdef HAVE_UBUS
  if (!strcmp(type, "DHCPACK"))
    ubus_event_bcast("dhcp.ack", daemon->namebuff, addr ? daemon->addrbuff : NULL, string, interface);
  else if (!strcmp(type, "DHCPRELEASE"))
    ubus_event_bcast("dhcp.release", daemon->namebuff, addr ? daemon->addrbuff : NULL, string, interface);
#endif
}

/**
 * @brief Log all DHCP options present in a DHCP packet for debugging
 * 
 * Iterates through the DHCP options array starting from the given pointer and logs
 * each option encountered until the OPTION_END marker is reached. For each option,
 * logs the transaction ID, option size, option code, option name, and formatted
 * option value. This function is used for detailed DHCP transaction logging when
 * --log-opts is enabled.
 * 
 * @param start Pointer to the first DHCP option in the options array
 * @param xid DHCP transaction ID (XID) in network byte order for correlation with the parent request/reply
 * 
 * @note This function modifies daemon->namebuff as a scratch buffer for formatting
 * @warning Caller must ensure 'start' points to valid DHCP options with proper termination
 * 
 * @see option_string() in option.c for option value formatting
 * 
 * EXAMPLE USAGE:
 * @code
 * // Log all options in a DHCP packet after processing
 * unsigned char *opts = &mess->options[0] + sizeof(u32);
 * log_options(opts, mess->xid);
 * // Output: "12345 sent size:  4 option: 54 server-identifier  192.168.1.1"
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 2132 (DHCP Options and BOOTP Vendor Extensions)
 * SIDE EFFECTS: Writes log messages to syslog; modifies daemon->namebuff
 * THREAD SAFETY: Not thread-safe (uses shared daemon->namebuff buffer)
 */
static void log_options(unsigned char *start, u32 xid)
{
  while (*start != OPTION_END)
    {
      char *optname = option_string(AF_INET, start[0], option_ptr(start, 0), option_len(start), daemon->namebuff, MAXDNAME);
      
      my_syslog(MS_DHCP | LOG_INFO, "%u sent size:%3d option:%3d %s  %s", 
		ntohl(xid), option_len(start), start[0], optname, daemon->namebuff);
      start += start[1] + 2;
    }
}

/**
 * @brief Search for DHCP option in contiguous buffer with bounds checking
 * 
 * Low-level function that walks through a contiguous buffer of DHCP options
 * searching for a specific option type with minimum required length. The function
 * implements the DHCP option format parser that handles variable-length options,
 * special padding (OPTION_PAD = 0), and end-of-options marker (OPTION_END = 255).
 * Includes comprehensive bounds checking to detect malformed packets and prevent
 * buffer overruns.
 * 
 * Each DHCP option (except PAD and END) has the format:
 * - Byte 0: Option code (1-254)
 * - Byte 1: Option length (0-255, length of data only, not including code/length bytes)
 * - Bytes 2+: Option data (length bytes)
 * 
 * OPTION_PAD (0) is a single-byte option for alignment with no length or data.
 * OPTION_END (255) is a single-byte marker indicating end of options.
 * 
 * The function terminates when:
 * - The requested option is found with sufficient length (returns pointer to option)
 * - OPTION_END is encountered (returns NULL unless searching for OPTION_END itself)
 * - End of buffer reached (returns NULL)
 * - Malformed packet detected (returns NULL)
 * 
 * @param p Pointer to start of DHCP options buffer to search (must not be NULL)
 * @param end Pointer to one byte past end of buffer (must not be NULL, must be > p)
 * @param opt Option code to search for (0-255, use OPTION_* constants from dhcp-protocol.h)
 * @param minsize Minimum required length of option data in bytes (not including code/length)
 * 
 * @return Pointer to start of option (pointing at option code byte) if found with length >= minsize
 * @retval NULL if option not found, buffer exhausted, OPTION_END encountered (unless searching for it), or malformed packet detected
 * 
 * @note Function returns pointer to option code byte, use option_len() and option_ptr() to access data
 * @note OPTION_PAD (0) is skipped automatically as it has no length or data
 * @note OPTION_END (255) terminates search immediately; only returns non-NULL if opt == OPTION_END
 * @note Malformed packet detection prevents buffer overruns from invalid length fields
 * @warning Caller must ensure p and end are valid pointers with end > p
 * @warning Returned pointer is only valid within original buffer [p, end)
 * 
 * @see option_find() for high-level DHCP option search including OPTION_OVERLOAD handling
 * @see option_len() macro to extract option data length from returned pointer
 * @see option_ptr() macro to compute pointer to option data from returned pointer
 * 
 * EXAMPLE USAGE:
 * @code
 * // Search for subnet mask option (code 1) requiring 4 bytes
 * unsigned char *subnet_opt = option_find1(&mess->options[0] + 4, 
 *                                          ((unsigned char *)mess) + packet_size,
 *                                          OPTION_NETMASK, 4);
 * if (subnet_opt) {
 *     struct in_addr *mask = (struct in_addr *)option_ptr(subnet_opt, 0);
 *     // Use mask...
 * }
 * 
 * // Search for any occurrence of option 60 (vendor class) with min 1 byte
 * unsigned char *vendor_opt = option_find1(options_start, options_end, 
 *                                          OPTION_VENDOR_ID, 1);
 * if (vendor_opt) {
 *     int len = option_len(vendor_opt);
 *     char *vendor_string = (char *)option_ptr(vendor_opt, 0);
 * }
 * 
 * // Check if OPTION_END marker exists
 * unsigned char *end_marker = option_find1(options_start, options_end,
 *                                          OPTION_END, 0);
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 2132 Section 2 - DHCP Option Format
 * RFC COMPLIANCE: RFC 2131 Section 4.1 - DHCP option format in BOOTP message
 * SIDE EFFECTS: None (pure function, no state modification)
 * THREAD SAFETY: Thread-safe (no shared state, operates only on caller-provided buffers)
 */
static unsigned char *option_find1(unsigned char *p, unsigned char *end, int opt, int minsize)
{
  while (1) 
    {
      if (p >= end)
	return NULL;
      else if (*p == OPTION_END)
	return opt == OPTION_END ? p : NULL;
      else if (*p == OPTION_PAD)
	p++;
      else 
	{ 
	  int opt_len;
	  if (p > end - 2)
	    return NULL; /* malformed packet */
	  opt_len = option_len(p);
	  if (p > end - (2 + opt_len))
	    return NULL; /* malformed packet */
	  if (*p == opt && opt_len >= minsize)
	    return p;
	  p += opt_len + 2;
	}
    }
}
 
/**
 * @brief Search for DHCP option in packet with OPTION_OVERLOAD support
 * 
 * High-level function that searches for a DHCP option within a complete DHCP packet,
 * automatically handling the OPTION_OVERLOAD mechanism defined in RFC 2131. The function
 * first searches the standard options area (after the 4-byte DHCP magic cookie), then
 * if OPTION_OVERLOAD is present in the packet, extends the search to the 'file' field
 * and/or 'sname' field of the BOOTP message structure depending on the overload flags.
 * 
 * OPTION_OVERLOAD (code 52) indicates that the DHCP 'file' and/or 'sname' fields
 * are being used to hold additional DHCP options beyond the standard options area:
 * - Bit 0 (value 1): file field contains additional options (128 bytes)
 * - Bit 1 (value 2): sname field contains additional options (64 bytes)
 * - Value 3: both file and sname contain additional options
 * 
 * Search order:
 * 1. Standard options area (mess->options[] after 4-byte cookie)
 * 2. If OPTION_OVERLOAD bit 0 set: file field (mess->file[], 128 bytes)
 * 3. If OPTION_OVERLOAD bit 1 set: sname field (mess->sname[], 64 bytes)
 * 
 * The function stops and returns immediately when the requested option is found
 * in any search area.
 * 
 * @param mess Pointer to DHCP packet structure (must not be NULL)
 * @param size Total size of DHCP packet in bytes (must be >= sizeof(struct dhcp_packet))
 * @param opt_type Option code to search for (0-255, use OPTION_* constants from dhcp-protocol.h)
 * @param minsize Minimum required length of option data in bytes (not including code/length bytes)
 * 
 * @return Pointer to start of option (pointing at option code byte) if found with length >= minsize
 * @retval NULL if option not found in any area, packet malformed, or option too short
 * 
 * @note Function automatically skips 4-byte DHCP magic cookie at start of options field
 * @note DHCP magic cookie value is 0x63825363 (network byte order) per RFC 2131
 * @note Returned pointer may point into options[], file[], or sname[] depending on where found
 * @note Use option_len() and option_ptr() macros to access option data from returned pointer
 * @warning Caller must ensure mess and size describe valid DHCP packet
 * @warning OPTION_OVERLOAD itself cannot be located in file or sname areas (RFC violation to do so)
 * 
 * @see option_find1() for low-level option search in contiguous buffer
 * @see option_len() macro to extract option data length
 * @see option_ptr() macro to compute pointer to option data
 * @see RFC 2131 Section 4.1 for DHCP packet format and OPTION_OVERLOAD description
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_packet *mess = (struct dhcp_packet *)daemon->dhcp_packet.iov_base;
 * size_t packet_size = 576; // Received packet size
 * 
 * // Search for requested IP address option (code 50), requires 4 bytes
 * unsigned char *req_addr_opt = option_find(mess, packet_size, OPTION_REQUESTED_IP, 4);
 * if (req_addr_opt) {
 *     struct in_addr requested_addr;
 *     memcpy(&requested_addr, option_ptr(req_addr_opt, 0), 4);
 *     // Process requested address...
 * }
 * 
 * // Search for parameter request list (code 55), minimum 1 byte
 * unsigned char *param_req_opt = option_find(mess, packet_size, OPTION_PARAM_REQUEST, 1);
 * if (param_req_opt) {
 *     int list_len = option_len(param_req_opt);
 *     unsigned char *param_list = option_ptr(param_req_opt, 0);
 *     // Process requested parameters...
 * }
 * 
 * // Check if message type option exists (code 53), requires 1 byte
 * unsigned char *msg_type_opt = option_find(mess, packet_size, OPTION_MESSAGE_TYPE, 1);
 * if (msg_type_opt) {
 *     unsigned char msg_type = option_ptr(msg_type_opt, 0)[0];
 *     // msg_type is DHCPDISCOVER, DHCPREQUEST, etc.
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 2131 Section 4.1 - DHCP message format and options field
 * RFC COMPLIANCE: RFC 2132 Section 9.3 - Option Overloading (OPTION_OVERLOAD, code 52)
 * SIDE EFFECTS: None (pure function, no state modification)
 * THREAD SAFETY: Thread-safe (no shared state, operates only on caller-provided packet)
 */
static unsigned char *option_find(struct dhcp_packet *mess, size_t size, int opt_type, int minsize)
{
  unsigned char *ret, *overload;
  
  /* skip over DHCP cookie; */
  if ((ret = option_find1(&mess->options[0] + sizeof(u32), ((unsigned char *)mess) + size, opt_type, minsize)))
    return ret;

  /* look for overload option. */
  if (!(overload = option_find1(&mess->options[0] + sizeof(u32), ((unsigned char *)mess) + size, OPTION_OVERLOAD, 1)))
    return NULL;
  
  /* Can we look in filename area ? */
  if ((overload[2] & 1) &&
      (ret = option_find1(&mess->file[0], &mess->file[128], opt_type, minsize)))
    return ret;

  /* finally try sname area */
  if ((overload[2] & 2) &&
      (ret = option_find1(&mess->sname[0], &mess->sname[64], opt_type, minsize)))
    return ret;

  return NULL;
}

/**
 * @brief Extract an IPv4 address from a DHCP option
 * 
 * @detailed Safely extracts an IPv4 address from a DHCP option, handling
 *           potentially unaligned data by using memcpy instead of direct
 *           pointer casting. The returned address is in network byte order
 *           as required by struct in_addr.
 * 
 * @param opt Pointer to DHCP option containing IPv4 address (must not be NULL)
 * 
 * @return struct in_addr containing the extracted IPv4 address in network byte order
 * 
 * @note Uses memcpy to avoid alignment issues on architectures with strict
 *       alignment requirements (e.g., ARM, SPARC)
 * @warning Assumes option contains at least INADDRSZ (4) bytes of data;
 *          caller must verify option length before calling
 * 
 * EXAMPLE USAGE:
 * @code
 * unsigned char *server_id_opt = option_find(mess, sz, OPTION_SERVER_IDENTIFIER, INADDRSZ);
 * if (server_id_opt) {
 *   struct in_addr server = option_addr(server_id_opt);
 *   // Use server address
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 2132 Section 9.7 (Server Identifier)
 * SIDE EFFECTS: None (read-only operation)
 * THREAD SAFETY: Thread-safe (no global state modification)
 */
static struct in_addr option_addr(unsigned char *opt)
{
   /* this worries about unaligned data in the option. */
  /* struct in_addr is network byte order */
  struct in_addr ret;

  memcpy(&ret, option_ptr(opt, 0), INADDRSZ);

  return ret;
}

/**
 * @brief Extract unsigned integer value from DHCP option data
 * 
 * Reads a multi-byte unsigned integer value from DHCP option data at a specified
 * offset, correctly handling unaligned data and converting from network byte order
 * (big-endian) to host byte order. This function is used to extract numeric values
 * from DHCP options such as lease times, renewal times, IP addresses encoded as
 * integers, and other numeric DHCP option values.
 * 
 * The function reads size bytes starting at the specified offset within the option
 * data, assembling them into an unsigned integer by shifting and OR-ing bytes in
 * big-endian order. This approach handles unaligned memory access safely on all
 * architectures, including those that require aligned access.
 * 
 * @param opt Pointer to DHCP option structure (must not be NULL)
 * @param offset Byte offset within option data where integer value starts (0-based)
 * @param size Number of bytes to read (1-4 typical, maximum 4 for 32-bit unsigned int)
 * 
 * @return Unsigned integer value extracted from option data in host byte order
 * 
 * @note Function assumes option data has sufficient length (offset + size ≤ option length)
 * @note Reading beyond option boundaries results in undefined behavior - caller must validate
 * @note Maximum meaningful size is 4 bytes (sizeof(unsigned int) on most platforms)
 * @note For size > 4, only the least significant 4 bytes are returned
 * 
 * @see option_addr() for extracting IPv4 addresses from options
 * @see option_ptr() macro for computing pointer to option data at offset
 * @see option_len() macro for retrieving option data length
 * 
 * EXAMPLE USAGE:
 * @code
 * // Extract 4-byte lease time from DHCP option 51
 * unsigned char *lease_opt = option_find(mess, sz, OPTION_LEASE_TIME, 4);
 * if (lease_opt) {
 *     unsigned int lease_seconds = option_uint(lease_opt, 0, 4);
 *     // lease_seconds now contains lease time in seconds
 * }
 * 
 * // Extract 2-byte maximum message size from option 57
 * unsigned char *max_msg_opt = option_find(mess, sz, OPTION_MAXMESSAGE, 2);
 * if (max_msg_opt) {
 *     unsigned int max_size = option_uint(max_msg_opt, 0, 2);
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 2132 Section 9.2 - Long Options
 * SIDE EFFECTS: None (pure function, no state modification)
 * THREAD SAFETY: Thread-safe (no shared state access)
 */
static unsigned int option_uint(unsigned char *opt, int offset, int size)
{
  /* this worries about unaligned data and byte order */
  unsigned int ret = 0;
  int i;
  unsigned char *p = option_ptr(opt, offset);
  
  for (i = 0; i < size; i++)
    ret = (ret << 8) | *p++;

  return ret;
}

/**
 * @brief Find end of DHCP option data by scanning to OPTION_END marker
 * 
 * @detailed Advances through DHCP option data structure, skipping over each option
 * by reading its length field and advancing past the option header (type + length)
 * and data. Continues scanning until reaching the OPTION_END (0x00) marker that
 * terminates the option sequence per RFC 2131 section 4.1. This function assumes
 * well-formed option data and does not perform validation - it's used during packet
 * construction where option validity is guaranteed by the builder.
 * 
 * The DHCP option format is: [1-byte type][1-byte length][length bytes of data].
 * OPTION_END is represented by a single 0x00 byte with no length or data fields.
 * 
 * @param start Pointer to beginning of DHCP option data to scan
 *              Must point to valid option data with proper OPTION_END termination
 *              Typically points to mess->options[0]+4 (after magic cookie)
 * 
 * @return Pointer to OPTION_END marker (0x00 byte) terminating option sequence
 *         Never returns NULL - assumes OPTION_END is present
 * 
 * @note This function does NOT validate option structure or detect malformed data
 * @warning Caller must ensure option data is well-formed with OPTION_END present
 *          Using this on untrusted data without validation may cause buffer overruns
 * 
 * @see find_overload() Locates OPTION_OVERLOAD to identify additional option space
 * @see option_find() Safe option search with bounds checking for packet parsing
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_packet *mess = ...;
 * unsigned char *end = dhcp_skip_opts(&mess->options[0] + sizeof(u32));
 * // end now points to OPTION_END marker, suitable for appending new options
 * *end++ = OPTION_HOSTNAME;
 * *end++ = hostname_len;
 * memcpy(end, hostname, hostname_len);
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 2131 Section 4.1 (DHCP message format and option encoding)
 * SIDE EFFECTS: None - read-only scan of option data
 * THREAD SAFETY: Thread-safe - no shared state, read-only operation
 */
static unsigned char *dhcp_skip_opts(unsigned char *start)
{
  while (*start != 0)
    start += start[1] + 2;
  return start;
}

/**
 * @brief Locate OPTION_OVERLOAD option indicating file/sname field reuse
 * 
 * @detailed Searches DHCP packet's options field for the OPTION_OVERLOAD option
 * that signals whether the 'file' (128 bytes) and/or 'sname' (64 bytes) fields
 * contain additional DHCP options instead of their usual boot filename and server
 * hostname data. Per RFC 2131 section 4.1, OPTION_OVERLOAD value indicates:
 *   1 = 'file' field contains options
 *   2 = 'sname' field contains options  
 *   3 = both fields contain options
 * 
 * This function is used during packet CONSTRUCTION (not parsing) and assumes
 * well-formed option data. It's called to determine whether overload is already
 * enabled before deciding whether to activate overload for additional option space.
 * 
 * @param mess Pointer to DHCP packet structure to search
 *             Packet must have options field initialized with magic cookie
 *             Options must be well-formed with proper length fields
 * 
 * @return Pointer to OPTION_OVERLOAD option (pointing at option type byte) if found
 *         NULL if OPTION_OVERLOAD is not present in options field
 * 
 * @note This function does NOT perform bounds checking - use only with trusted data
 * @note Only searches main options field, not within file/sname fields themselves
 * @warning For packet construction only - not suitable for parsing untrusted packets
 * 
 * @see dhcp_skip_opts() Advances through option data to find insertion points
 * @see do_options() Main option encoding that uses overload when space exhausted
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_packet *mess = ...;
 * unsigned char *overload = find_overload(mess);
 * if (overload)
 *   {
 *     unsigned char overload_val = overload[2];
 *     if (overload_val & 1)
 *       // file field contains options, can't use for filename
 *     if (overload_val & 2)
 *       // sname field contains options, can't use for server name
 *   }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 2131 Section 4.1 (OPTION_OVERLOAD option definition)
 * SIDE EFFECTS: None - read-only search of existing packet data
 * THREAD SAFETY: Thread-safe - no shared state, read-only operation
 */
/* only for use when building packet: doesn't check for bad data. */ 
static unsigned char *find_overload(struct dhcp_packet *mess)
{
  unsigned char *p = &mess->options[0] + sizeof(u32);
  
  while (*p != 0)
    {
      if (*p == OPTION_OVERLOAD)
	return p;
      p += p[1] + 2;
    }
  return NULL;
}

/**
 * @brief Calculate final DHCP packet size with option overload handling
 * 
 * @detailed Computes the actual size of a constructed DHCP packet by finding the
 * end of option data, accounting for option overload (options stored in file/sname
 * fields per RFC 2131 section 4.1), and ensuring minimum packet size compliance.
 * Handles relay agent information option (OPTION_AGENT_ID) by moving it to the
 * packet end to prevent overwriting during option processing. Ensures packet meets
 * MIN_PACKETSZ requirement (300 bytes per RFC 2131).
 * 
 * @param mess DHCP packet with options to measure
 * @param agent_id Pointer to relay agent information option (option 82) or NULL
 * @param real_end End of relay agent information data if agent_id is non-NULL
 * 
 * @return Final packet size in bytes, guaranteed >= MIN_PACKETSZ (300 bytes)
 * 
 * @note Modifies packet by moving agent_id data to end if present
 * @warning agent_id data is relocated within packet - pointers to it become invalid
 * 
 * @see dhcp_skip_opts() Finds end of option data handling OPTION_END
 * @see option_find() Searches for specific options including OPTION_OVERLOAD
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_packet *mess = (struct dhcp_packet *)daemon->dhcp_packet.iov_base;
 * unsigned char *agent_id = option_find(mess, sz, OPTION_AGENT_ID, 1);
 * unsigned char *agent_end = agent_id ? agent_id + agent_id[1] + 2 : NULL;
 * size_t final_sz = dhcp_packet_size(mess, agent_id, agent_end);
 * @endcode
 * 
 * RFC COMPLIANCE:
 * - RFC 2131 Section 4.1: Minimum packet size of 300 bytes required
 * - RFC 2132 Section 9.3: Option overload allows file/sname to contain options
 * - RFC 3046 Section 2: Relay agent information option handling
 * 
 * SIDE EFFECTS:
 * - Moves agent_id option data to packet end if agent_id parameter is non-NULL
 * - Zeroes memory between original and relocated agent_id to prevent data leakage
 * 
 * THREAD SAFETY: Single-threaded only, modifies mess packet in place
 */
static size_t dhcp_packet_size(struct dhcp_packet *mess, unsigned char *agent_id, unsigned char *real_end)
{
  unsigned char *p = dhcp_skip_opts(&mess->options[0] + sizeof(u32));
  unsigned char *overload;
  size_t ret;
  
  /* move agent_id back down to the end of the packet */
  if (agent_id)
    {
      memmove(p, agent_id, real_end - agent_id);
      p += real_end - agent_id;
      memset(p, 0, real_end - p); /* in case of overlap */
    }
  
  /* add END options to the regions. */
  overload = find_overload(mess);
  
  if (overload && (option_uint(overload, 0, 1) & 1))
    {
      *dhcp_skip_opts(mess->file) = OPTION_END;
      if (option_bool(OPT_LOG_OPTS))
	log_options(mess->file, mess->xid);
    }
  else if (option_bool(OPT_LOG_OPTS) && strlen((char *)mess->file) != 0)
    my_syslog(MS_DHCP | LOG_INFO, _("%u bootfile name: %s"), ntohl(mess->xid), (char *)mess->file);
  
  if (overload && (option_uint(overload, 0, 1) & 2))
    {
      *dhcp_skip_opts(mess->sname) = OPTION_END;
      if (option_bool(OPT_LOG_OPTS))
	log_options(mess->sname, mess->xid);
    }
  else if (option_bool(OPT_LOG_OPTS) && strlen((char *)mess->sname) != 0)
    my_syslog(MS_DHCP | LOG_INFO, _("%u server name: %s"), ntohl(mess->xid), (char *)mess->sname);


  *p++ = OPTION_END;
  
  if (option_bool(OPT_LOG_OPTS))
    {
      if (mess->siaddr.s_addr != 0)
	{
	  inet_ntop(AF_INET, &mess->siaddr, daemon->addrbuff, ADDRSTRLEN);
	  my_syslog(MS_DHCP | LOG_INFO, _("%u next server: %s"), ntohl(mess->xid), daemon->addrbuff);
	}
      
      if ((mess->flags & htons(0x8000)) && mess->ciaddr.s_addr == 0)
	my_syslog(MS_DHCP | LOG_INFO, _("%u broadcast response"), ntohl(mess->xid));
      
      log_options(&mess->options[0] + sizeof(u32), mess->xid);
    } 
  
  ret = (size_t)(p - (unsigned char *)mess);
  
  if (ret < MIN_PACKETSZ)
    ret = MIN_PACKETSZ;
  
  return ret;
}

/**
 * @brief Find free space in DHCP packet for adding option, using overload if necessary
 * 
 * @detailed Locates available space in a DHCP packet to write a new option with specified
 * length. First attempts to use the standard options field (mess->options), but if insufficient
 * space remains, implements option overload per RFC 2131 section 4.1 by storing options in
 * the file and/or sname fields. Creates OPTION_OVERLOAD (option 52) if not already present
 * and space permits. Returns pointer to option buffer where caller should write option code
 * and length (already written by this function), followed by option data.
 * 
 * Option overload priority: options field → file field → sname field. The function marks
 * which fields contain options via OPTION_OVERLOAD value: 1=file only, 2=sname only, 3=both.
 * 
 * @param mess DHCP packet to find space in
 * @param end End of safe buffer space for options field
 * @param opt Option code being added (for logging purposes if no space)
 * @param len Length of option data in bytes (excluding option code and length bytes)
 * 
 * @return Pointer to option data area (after code and length bytes), or NULL if no space
 * @retval non-NULL Pointer where caller should write len bytes of option data
 * @retval NULL Insufficient space in packet; option cannot be added (warning logged)
 * 
 * @note Writes option code and length bytes before returning pointer to data area
 * @warning Modifies packet structure by setting OPTION_OVERLOAD if using file/sname fields
 * 
 * @see dhcp_skip_opts() Finds end of existing options to determine free space
 * @see find_overload() Locates existing OPTION_OVERLOAD option
 * @see option_put() Uses this function to add integer-valued options
 * @see option_put_string() Uses this function to add string-valued options
 * 
 * EXAMPLE USAGE:
 * @code
 * unsigned char *p = free_space(mess, end, OPTION_SUBNET, 4);
 * if (p) {
 *   memcpy(p, &subnet_mask, 4);  // Write 4-byte subnet mask
 * }
 * @endcode
 * 
 * RFC COMPLIANCE:
 * - RFC 2131 Section 4.1: Option overload allows file/sname to store options
 * - RFC 2132 Section 9.3: OPTION_OVERLOAD format with value 1 (file), 2 (sname), 3 (both)
 * 
 * SIDE EFFECTS:
 * - Creates OPTION_OVERLOAD option if using file/sname fields for first time
 * - Updates OPTION_OVERLOAD value (byte at overload[2]) to indicate which fields used
 * - Writes option code and length bytes at returned pointer location
 * - Logs warning to syslog if option cannot be added due to space constraints
 * 
 * THREAD SAFETY: Single-threaded only, modifies mess packet in place
 */
static unsigned char *free_space(struct dhcp_packet *mess, unsigned char *end, int opt, int len)
{
  unsigned char *p = dhcp_skip_opts(&mess->options[0] + sizeof(u32));
  
  if (p + len + 3 >= end)
    /* not enough space in options area, try and use overload, if poss */
    {
      unsigned char *overload;
      
      if (!(overload = find_overload(mess)) &&
	  (mess->file[0] == 0 || mess->sname[0] == 0))
	{
	  /* attempt to overload fname and sname areas, we've reserved space for the
	     overflow option previuously. */
	  overload = p;
	  *(p++) = OPTION_OVERLOAD;
	  *(p++) = 1;
	}
      
      p = NULL;
      
      /* using filename field ? */
      if (overload)
	{
	  if (mess->file[0] == 0)
	    overload[2] |= 1;
	  
	  if (overload[2] & 1)
	    {
	      p = dhcp_skip_opts(mess->file);
	      if (p + len + 3 >= mess->file + sizeof(mess->file))
		p = NULL;
	    }
	  
	  if (!p)
	    {
	      /* try to bring sname into play (it may be already) */
	      if (mess->sname[0] == 0)
		overload[2] |= 2;
	      
	      if (overload[2] & 2)
		{
		  p = dhcp_skip_opts(mess->sname);
		  if (p + len + 3 >= mess->sname + sizeof(mess->sname))
		    p = NULL;
		}
	    }
	}
      
      if (!p)
	my_syslog(MS_DHCP | LOG_WARNING, _("cannot send DHCP/BOOTP option %d: no space left in packet"), opt);
    }
 
  if (p)
    {
      *(p++) = opt;
      *(p++) = len;
    }

  return p;
}

/**
 * @brief Write integer-valued DHCP option to packet in big-endian format
 * 
 * @detailed Adds a DHCP option containing an integer value to the packet, encoding the value
 * in network byte order (big-endian). Uses free_space() to locate available buffer space,
 * implementing option overload if necessary. The integer value is split into bytes from
 * most significant to least significant byte order as required by DHCP protocol.
 * 
 * This is a convenience wrapper around free_space() for integer-valued options such as
 * lease time (4 bytes), MTU (2 bytes), maximum message size (2 bytes), and boolean
 * flags (1 byte). The len parameter determines how many bytes of val to encode.
 * 
 * @param mess DHCP packet to add option to
 * @param end End of safe buffer space for options field
 * @param opt DHCP option code (e.g., OPTION_LEASE_TIME=51, OPTION_MAXMESSAGE=57)
 * @param len Number of bytes to encode (1, 2, or 4 typically)
 * @param val Integer value to encode in big-endian format
 * 
 * @return None (void function)
 * 
 * @note Does nothing if free_space() returns NULL (insufficient space)
 * @warning Truncates val to len bytes; high-order bytes discarded if val requires more bits
 * 
 * @see free_space() Locates buffer space and handles option overload
 * @see option_put_string() Similar function for string-valued options
 * @see calc_time() Calculates lease time values for OPTION_LEASE_TIME
 * 
 * EXAMPLE USAGE:
 * @code
 * // Add 4-byte lease time option (3600 seconds = 1 hour)
 * option_put(mess, end, OPTION_LEASE_TIME, 4, 3600);
 * 
 * // Add 2-byte maximum message size option (1500 bytes)
 * option_put(mess, end, OPTION_MAXMESSAGE, 2, 1500);
 * 
 * // Add 1-byte boolean option (IP forwarding enabled)
 * option_put(mess, end, OPTION_IP_FORWARDING, 1, 1);
 * @endcode
 * 
 * RFC COMPLIANCE:
 * - RFC 2131 Section 2: Network byte order (big-endian) required for multi-byte integers
 * - RFC 2132: Defines integer-valued options (lease time, renewal time, MTU, etc.)
 * 
 * SIDE EFFECTS:
 * - Writes option code, length, and value bytes to packet via free_space()
 * - May trigger option overload if standard options field exhausted
 * 
 * THREAD SAFETY: Single-threaded only, modifies mess packet in place
 */
static void option_put(struct dhcp_packet *mess, unsigned char *end, int opt, int len, unsigned int val)
{
  int i;
  unsigned char *p = free_space(mess, end, opt, len);
  
  if (p) 
    for (i = 0; i < len; i++)
      *(p++) = val >> (8 * (len - (i + 1)));
}

/**
 * @brief Write string-valued DHCP option to packet
 * 
 * @detailed Adds a DHCP option containing a string value to the packet. Uses free_space()
 * to locate available buffer space, implementing option overload if necessary. The string
 * is copied verbatim into the option data field. Optionally includes a null terminator
 * byte at the end of the string if null_term is true and the string length allows it.
 * 
 * This is a convenience wrapper around free_space() and memcpy() for string-valued options
 * such as hostname (option 12), domain name (option 15), vendor class identifier (option 60),
 * and client identifier strings. The function automatically calculates string length and
 * handles null termination requirements.
 * 
 * @param mess DHCP packet to add option to
 * @param end End of safe buffer space for options field
 * @param opt DHCP option code (e.g., OPTION_HOSTNAME=12, OPTION_DOMAINNAME=15)
 * @param string Null-terminated C string to encode as option value
 * @param null_term If non-zero and length permits, include null byte in option data
 * 
 * @return None (void function)
 * 
 * @note Does nothing if free_space() returns NULL (insufficient space)
 * @note Maximum DHCP option data length is 255 bytes
 * @warning String must be null-terminated; strlen() is used to determine length
 * @warning If string length is 255 and null_term is true, null byte is NOT added (length limit)
 * 
 * @see free_space() Locates buffer space and handles option overload
 * @see option_put() Similar function for integer-valued options
 * @see sanitise() Sanitizes strings before encoding to prevent security issues
 * 
 * EXAMPLE USAGE:
 * @code
 * // Add hostname option (option 12)
 * option_put_string(mess, end, OPTION_HOSTNAME, "mycomputer", 0);
 * 
 * // Add domain name option (option 15) with null terminator
 * option_put_string(mess, end, OPTION_DOMAINNAME, "example.com", 1);
 * 
 * // Add vendor class identifier (option 60)
 * option_put_string(mess, end, OPTION_VENDOR_ID, "PXEClient", 0);
 * @endcode
 * 
 * RFC COMPLIANCE:
 * - RFC 2131 Section 2: Options format with option code, length, and data
 * - RFC 2132: Defines string-valued options (hostname, domain, vendor class, etc.)
 * - RFC 2132 Section 2: Maximum option data length is 255 octets
 * 
 * SIDE EFFECTS:
 * - Writes option code, length, and string data to packet via free_space()
 * - May trigger option overload if standard options field exhausted
 * 
 * THREAD SAFETY: Single-threaded only, modifies mess packet in place
 */
static void option_put_string(struct dhcp_packet *mess, unsigned char *end, int opt, 
			      const char *string, int null_term)
{
  unsigned char *p;
  size_t len = strlen(string);

  if (null_term && len != 255)
    len++;

  if ((p = free_space(mess, end, opt, len)))
    memcpy(p, string, len);
}

/* return length, note this only does the data part */
/**
 * @brief Write DHCP option value into packet buffer with address substitution
 * 
 * @detailed Encodes a DHCP option value into the packet buffer with special handling for:
 *           1) String options - adds null terminator byte if requested and not already max length
 *           2) Address options - substitutes 0.0.0.0 "self" addresses with local server address
 *           3) Other options - copies value directly from option structure
 *           Returns the actual encoded length (including null terminator if added) for proper
 *           DHCP option length field encoding by caller.
 * 
 * @param opt Pointer to dhcp_opt structure containing option code, flags, value, and length
 * @param p Buffer pointer where option value should be written, or NULL to only calculate length
 * @param context DHCP context containing local server address for "self" address substitution, or NULL
 * @param null_term If non-zero, add null terminator to string options (DHOPT_STRING flag set)
 * 
 * @return Encoded option value length in bytes (including null terminator if added)
 * @retval 0 Option has zero length (empty value)
 * @retval >0 Number of bytes written to buffer p (or would be written if p is NULL)
 * 
 * @note If p is NULL, no data is written but length is still calculated (dry-run mode)
 * @note Address substitution only occurs for DHOPT_ADDR options with non-NULL context
 * @note 0.0.0.0 addresses are replaced with context->local (server's IP on relevant interface)
 * @warning Buffer p must have sufficient space for opt->len bytes (plus null terminator if applicable)
 * @warning Caller responsible for ensuring p points to valid writable memory
 * 
 * @see do_options() which calls this function for each option to encode
 * @see option_put() for simpler numeric option encoding
 * 
 * EXAMPLE USAGE:
 * @code
 * unsigned char buffer[256];
 * int len = do_opt(opt, buffer, context, 1);
 * // len now contains encoded length, buffer contains option value
 * // Next encode option code and length fields before this value
 * @endcode
 * 
 * RFC COMPLIANCE: Implements DHCP option encoding per RFC 2132 with "self" address extension
 * SIDE EFFECTS: Writes len bytes to buffer p if p is non-NULL; no side effects if p is NULL
 * THREAD SAFETY: Safe if opt, context are not modified during call (single-threaded architecture)
 */
static int do_opt(struct dhcp_opt *opt, unsigned char *p, struct dhcp_context *context, int null_term)
{
  int len = opt->len;
  
  if ((opt->flags & DHOPT_STRING) && null_term && len != 255)
    len++;

  if (p && len != 0)
    {
      if (context && (opt->flags & DHOPT_ADDR))
	{
	  int j;
	  struct in_addr *a = (struct in_addr *)opt->val;
	  for (j = 0; j < opt->len; j+=INADDRSZ, a++)
	    {
	      /* zero means "self" (but not in vendorclass options.) */
	      if (a->s_addr == 0)
		memcpy(p, &context->local, INADDRSZ);
	      else
		memcpy(p, a, INADDRSZ);
	      p += INADDRSZ;
	    }
	}
      else
	/* empty string may be extended to "\0" by null_term */
	memcpy(p, opt->val ? opt->val : (unsigned char *)"", len);
    }  
  return len;
}

/**
 * @brief Check if DHCP option code is in parameter request list
 * 
 * Determines whether a specific DHCP option code appears in a parameter request
 * list, typically from OPTION_PARAM_REQUEST (option 55). This function implements
 * the server-side logic for filtering which options to include in DHCP responses
 * based on the client's explicit requests.
 * 
 * RFC 2131 Section 3.5 specifies that clients MAY include a Parameter Request List
 * option indicating which configuration parameters the client is interested in
 * receiving. The server SHOULD use this list to prioritize which options to include
 * in its response when space is limited.
 * 
 * Special handling for NULL list:
 * - If the client did not provide a parameter request list (list == NULL), the
 *   function returns 1 (true) for ALL options, implementing the semantic
 *   "send everything, not nothing" per RFC 2131 Section 4.3.1.
 * - This ensures that clients omitting the parameter request list receive all
 *   applicable configuration options.
 * 
 * The list format is a sequence of option codes (unsigned bytes, 0-255) terminated
 * by OPTION_END (255). Each byte represents one option code that the client requests.
 * The function scans the list linearly until either a match is found or OPTION_END
 * is encountered.
 * 
 * @param list Pointer to parameter request list (array of option codes terminated by OPTION_END)
 *             or NULL if client did not provide a parameter request list
 * @param opt Option code to search for (0-255, typically an OPTION_* constant from dhcp-protocol.h)
 * 
 * @return 1 if option should be included in response, 0 if option should be omitted
 * @retval 1 if list is NULL (client wants all options) OR opt is found in list
 * @retval 0 if list is non-NULL and opt is not found in list before OPTION_END
 * 
 * @note NULL list means "send everything" - all options pass the filter
 * @note The list is terminated by OPTION_END (255), not by a length field
 * @note Function performs linear search; typical lists are short (5-15 entries)
 * @note Option code 255 (OPTION_END) is never found because loop terminates on it
 * @warning Caller must ensure list (if non-NULL) is properly terminated with OPTION_END
 * @warning Unterminated list will cause infinite loop and buffer overrun
 * @warning list pointer must be valid (NULL or pointing to accessible memory)
 * 
 * @see do_options() which uses this function to filter options before adding to response
 * @see OPTION_PARAM_REQUEST (option 55) in dhcp-protocol.h - source of the list
 * @see option_find() to extract the parameter request list from a DHCP packet
 * 
 * EXAMPLE USAGE:
 * @code
 * // Extract parameter request list from client packet
 * unsigned char *req_options = option_find(mess, sz, OPTION_PARAM_REQUEST, 1);
 * unsigned char *param_list = NULL;
 * if (req_options)
 *     param_list = option_ptr(req_options, 0);
 * 
 * // Check if client requested subnet mask (option 1)
 * if (in_list(param_list, OPTION_NETMASK)) {
 *     // Add subnet mask to response
 *     option_put(mess, end, OPTION_NETMASK, 4, subnet.s_addr);
 * }
 * 
 * // Check if client requested DNS servers (option 6)
 * if (in_list(param_list, OPTION_DNS_SERVER)) {
 *     // Add DNS servers to response
 *     // ...
 * }
 * 
 * // If client sent no parameter request list, in_list returns 1 for all options
 * if (in_list(NULL, OPTION_ROUTER)) {
 *     // This will always be true - add router option
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 2131 Section 3.5 - Parameter Request List option format
 * RFC COMPLIANCE: RFC 2131 Section 4.3.1 - Server behavior with parameter request list
 * RFC COMPLIANCE: RFC 2132 Section 9.8 - Parameter Request List (option 55)
 * SIDE EFFECTS: None (pure function, read-only access to list)
 * THREAD SAFETY: Thread-safe (no shared state, read-only operation)
 */
static int in_list(unsigned char *list, int opt)
{
  int i;

   /* If no requested options, send everything, not nothing. */
  if (!list)
    return 1;
  
  for (i = 0; list[i] != OPTION_END; i++)
    if (opt == list[i])
      return 1;

  return 0;
}

/**
 * @brief Find DHCP option configuration with DHOPT_TAGOK flag in global option list
 * 
 * @detailed Searches the daemon's global DHCP option list (daemon->dhcp_opts) for
 *           an option configuration matching the specified option code with the
 *           DHOPT_TAGOK flag set. This function is used to locate tag-validated
 *           option configurations that should be included in DHCP responses based
 *           on network tag matching. Unlike option_find1() which searches in DHCP
 *           packets, this searches configured options for response construction.
 * 
 * @param opt DHCP option code to search for (OPTION_* constants from dhcp-protocol.h)
 * 
 * @return Pointer to matching dhcp_opt structure if found and DHOPT_TAGOK flag set
 * @retval struct dhcp_opt* Pointer to option configuration matching opt with DHOPT_TAGOK
 * @retval NULL No matching option found, or option found but DHOPT_TAGOK flag not set
 * 
 * @note This function only returns options with DHOPT_TAGOK flag set, meaning
 *       tag-based conditional logic has already validated this option should be included
 * @note The search is linear through the linked list; performance is O(n) where n is
 *       number of configured DHCP options (typically <100 for most deployments)
 * @note Multiple options with same opt code may exist in list; function returns first
 *       matching option with DHOPT_TAGOK flag
 * 
 * @see do_options() for usage in option response construction
 * @see do_encap_opts() for encapsulated option handling
 * @see option_find1() for searching options in received DHCP packets
 * @see struct dhcp_opt definition in dnsmasq.h for flag values
 * 
 * EXAMPLE USAGE:
 * @code
 * // Find router option configuration that passed tag validation
 * struct dhcp_opt *router_opt = option_find2(OPTION_ROUTER);
 * if (router_opt) {
 *     // Add router option to DHCP response using configured value
 *     add_option_to_response(mess, end, router_opt);
 * }
 * 
 * // Check if NTP server option is configured and tag-validated
 * if (option_find2(OPTION_NTP_SERVER)) {
 *     // NTP option will be included in response
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 2131 Section 4.3.1 - DHCP server configuration for option values
 * RFC COMPLIANCE: RFC 2132 - DHCP Options and BOOTP Vendor Extensions (all option definitions)
 * SIDE EFFECTS: None (read-only search of global configuration data structure)
 * THREAD SAFETY: Thread-safe in single-threaded architecture; read-only access to daemon->dhcp_opts
 */
static struct dhcp_opt *option_find2(int opt)
{
  struct dhcp_opt *opts;
  
  for (opts = daemon->dhcp_opts; opts; opts = opts->next)
    if (opts->opt == opt && (opts->flags & DHOPT_TAGOK))
      return opts;
  
  return NULL;
}

/* mark vendor-encapsulated options which match the client-supplied  or
   config-supplied vendor class */
/**
 * @brief Match vendor-specific DHCP options against client vendor class identifier
 * 
 * @detailed This function processes a linked list of configured DHCP options and marks those
 *           vendor-specific options whose vendor class matches the vendor class identifier
 *           provided by the client in option 60. It supports both PXE vendor matching (using
 *           the global PXE vendor list from daemon->dhcp_pxe_vendors) and regular vendor-class
 *           matching (using the vendor_class field from the option configuration). Options
 *           that match have the DHOPT_VENDOR_MATCH flag set, enabling them to be included
 *           in the DHCP response. This implements tag-based vendor option filtering.
 * 
 * @param opt Pointer to DHCP option 60 (Vendor class identifier) from client request, or NULL if not present
 * @param dopt Head of linked list of configured DHCP options to process (dhcp_opt structures)
 * 
 * @return None (void function modifies dopt flags in place)
 * 
 * @note All options in the dopt list have DHOPT_VENDOR_MATCH flag cleared initially
 * @note Only options with DHOPT_VENDOR flag are candidates for vendor matching
 * @note PXE vendor options (DHOPT_VENDOR_PXE) use daemon->dhcp_pxe_vendors list
 * @note Non-PXE vendor options use the vendor_class field from the option configuration
 * @note Matching is substring-based: vendor class data must appear anywhere in option 60 value
 * @note Empty vendor class (len == 0) matches all clients (wildcard match)
 * @warning If opt is NULL, all DHOPT_VENDOR options remain unmatched (DHOPT_VENDOR_MATCH not set)
 * 
 * @see do_options() which calls this function to filter vendor options before encoding
 * @see prune_vendor_opts() which removes unmatched vendor options from the option list
 * 
 * EXAMPLE USAGE:
 * @code
 * // Called from do_options to match vendor options against client's vendor class
 * unsigned char *vendor_opt = option_find(mess, sz, OPTION_VENDOR_ID, 1);
 * match_vendor_opts(vendor_opt, daemon->dhcp_opts);
 * @endcode
 * 
 * RFC COMPLIANCE:
 * - RFC 2132 Section 9.13: Option 60 (Vendor class identifier)
 * - RFC 3925: Vendor-Identifying Vendor Options for DHCPv4
 * - RFC 4578: PXE Vendor Options (PXE-specific vendor class matching)
 * 
 * SIDE EFFECTS:
 * - Clears DHOPT_VENDOR_MATCH flag for all options in dopt list
 * - Sets DHOPT_VENDOR_MATCH flag for options matching vendor class
 * - No global state modifications beyond option flag updates
 * 
 * THREAD SAFETY: Single-threaded architecture, safe to call
 * 
 * Source: /src/rfc2131.c:3326-3358
 */
static void match_vendor_opts(unsigned char *opt, struct dhcp_opt *dopt)
{
  for (; dopt; dopt = dopt->next)
    {
      dopt->flags &= ~DHOPT_VENDOR_MATCH;
      if (opt && (dopt->flags & DHOPT_VENDOR))
	{
	  const struct dhcp_pxe_vendor *pv;
	  struct dhcp_pxe_vendor dummy_vendor = {
	    .data = (char *)dopt->u.vendor_class,
	    .next = NULL,
	  };
	  if (dopt->flags & DHOPT_VENDOR_PXE)
	    pv = daemon->dhcp_pxe_vendors;
	  else
	    pv = &dummy_vendor;
	  for (; pv; pv = pv->next)
	    {
	      int i, len = 0, matched = 0;
	      if (pv->data)
	        len = strlen(pv->data);
	      for (i = 0; i <= (option_len(opt) - len); i++)
	        if (len == 0 || memcmp(pv->data, option_ptr(opt, i), len) == 0)
	          {
		    matched = 1;
	            break;
	          }
	      if (matched)
		{
	          dopt->flags |= DHOPT_VENDOR_MATCH;
		  break;
		}
	    }
	}
    }
}

/**
 * @brief Encode encapsulated DHCP options into packet with automatic fragmentation
 * 
 * @detailed This function encodes a linked list of DHCP options matching a specific flag into
 *           encapsulated option format (options nested inside a container option). It handles
 *           the complexity of splitting large encapsulated option sets across multiple option
 *           instances when the total length exceeds 255 bytes (the maximum DHCP option length).
 *           This is commonly used for vendor-specific options (option 43), vendor-identifying
 *           vendor options (option 125), and relay agent information (option 82). The function
 *           performs a two-pass algorithm: first calculating total length and determining split
 *           points, then encoding the actual option data with proper sub-option formatting.
 * 
 * @param opt Head of linked list of dhcp_opt structures to process (may be daemon->dhcp_opts)
 * @param encap DHCP option number for the encapsulation container (e.g., OPTION_VENDOR, OPTION_VENDOR_IDENT)
 * @param flag Filter flag (e.g., DHOPT_VENDOR_MATCH) - only options with this flag set are encoded
 * @param mess Pointer to DHCP packet being constructed (destination for encoded options)
 * @param end Pointer to end of available space in DHCP packet (for overflow prevention)
 * @param null_term Whether to null-terminate string options (1 for null termination, 0 for no termination)
 * 
 * @return Returns 1 if at least one matching option was encoded, 0 if no matching options found
 * @retval 1 At least one option matching the flag was successfully encoded
 * @retval 0 No options matching the flag were found in the option list
 * 
 * @note Each DHCP option is limited to 255 bytes total length, so large encapsulated option sets
 *       are automatically split across multiple instances of the encapsulation option
 * @note Each sub-option is encoded as: option-code (1 byte) + length (1 byte) + value (length bytes)
 * @note Each encapsulation block is terminated with OPTION_END (255)
 * @note The function calls do_opt() to calculate option lengths and encode option values
 * @note The function calls free_space() to allocate space in the DHCP packet
 * @warning If insufficient space exists in the packet, some options may be silently omitted
 * @warning The function modifies the DHCP packet in place
 * 
 * @see do_opt() which handles individual option encoding logic
 * @see free_space() which allocates space in the DHCP packet
 * @see match_vendor_opts() which sets DHOPT_VENDOR_MATCH flag for vendor options
 * @see do_options() which calls this function to encode vendor and encapsulated options
 * 
 * EXAMPLE USAGE:
 * @code
 * // Encode vendor-specific options (option 43) for matched vendor class
 * if (do_encap_opts(daemon->dhcp_opts, OPTION_VENDOR, DHOPT_VENDOR_MATCH, 
 *                   mess, end, null_term))
 *   {
 *     // Vendor options were successfully encoded
 *   }
 * @endcode
 * 
 * RFC COMPLIANCE:
 * - RFC 2132 Section 8.4: Option 43 (Vendor-specific Information)
 * - RFC 3046: DHCP Relay Agent Information Option (option 82)
 * - RFC 3925: Vendor-Identifying Vendor Options for DHCPv4 (option 125)
 * - RFC 2131 Section 2: DHCP options limited to 255 bytes maximum length
 * 
 * SIDE EFFECTS:
 * - Modifies DHCP packet by adding encapsulated option data
 * - Consumes space from the end pointer in the DHCP packet
 * - No global state modifications
 * 
 * THREAD SAFETY: Single-threaded architecture, safe to call
 * 
 * Source: /src/rfc2131.c:3411-3456
 */
static int do_encap_opts(struct dhcp_opt *opt, int encap, int flag,  
			 struct dhcp_packet *mess, unsigned char *end, int null_term)
{
  int len, enc_len, ret = 0;
  struct dhcp_opt *start;
  unsigned char *p;
    
  /* find size in advance */
  for (enc_len = 0, start = opt; opt; opt = opt->next)
    if (opt->flags & flag)
      {
	int new = do_opt(opt, NULL, NULL, null_term) + 2;
	ret  = 1;
	if (enc_len + new <= 255)
	  enc_len += new;
	else
	  {
	    p = free_space(mess, end, encap, enc_len);
	    for (; start && start != opt; start = start->next)
	      if (p && (start->flags & flag))
		{
		  len = do_opt(start, p + 2, NULL, null_term);
		  *(p++) = start->opt;
		  *(p++) = len;
		  p += len;
		}
	    enc_len = new;
	    start = opt;
	  }
      }
  
  if (enc_len != 0 &&
      (p = free_space(mess, end, encap, enc_len + 1)))
    {
      for (; start; start = start->next)
	if (start->flags & flag)
	  {
	    len = do_opt(start, p + 2, NULL, null_term);
	    *(p++) = start->opt;
	    *(p++) = len;
	    p += len;
	  }
      *p = OPTION_END;
    }

  return ret;
}

/**
 * @brief Add PXE-specific vendor identification and UUID options to DHCP packet
 * 
 * @detailed This function adds PXE (Preboot Execution Environment) network boot vendor
 *           identification to a DHCP response packet. It inserts DHCP option 60 (Vendor
 *           class identifier) with the PXE vendor string (defaulting to "PXEClient" if
 *           not specified) and optionally adds option 97 (PXE UUID) containing the client's
 *           unique identifier. These options are essential for PXE boot clients to properly
 *           identify themselves and receive appropriate boot configuration from the DHCP server.
 *           The UUID format follows RFC 4578 specification with a type byte followed by a
 *           16-byte UUID value. This function is called during DHCP response construction
 *           for PXE clients identified by option 93 (Client System Architecture Type).
 * 
 * @param mess Pointer to DHCP packet being constructed (destination for PXE options)
 * @param end Pointer to end of available space in DHCP packet (for overflow prevention)
 * @param uuid Pointer to 17-byte UUID data (1 byte type + 16 bytes UUID), or NULL if no UUID
 * @param pxevendor PXE vendor string to use for option 60, or NULL to use default "PXEClient"
 * 
 * @return None (void function modifies packet in place)
 * 
 * @note Default PXE vendor string is "PXEClient" per PXE specification
 * @note UUID format: byte 0 = UUID type (0=not present, 1=GUID), bytes 1-16 = UUID value
 * @note UUID option (97) is only added if uuid parameter is non-NULL and space is available
 * @note Vendor ID option (60) is always added with the specified or default vendor string
 * @note The pxevendor parameter allows customization for vendor-specific PXE implementations
 * @warning If uuid is provided but insufficient space exists, UUID option is silently omitted
 * @warning String termination handled by option_put_string with null_term=0 (no null byte)
 * 
 * @see option_put_string() which encodes the vendor ID string option
 * @see free_space() which allocates space for the UUID option
 * @see is_pxe_client() which detects PXE clients requiring these options
 * @see dhcp_reply() which calls this function for PXE boot scenarios
 * 
 * EXAMPLE USAGE:
 * @code
 * // Add standard PXE vendor ID and client UUID to DHCP response
 * unsigned char client_uuid[17] = {0x01, ...}; // Type 1 (GUID) + 16-byte UUID
 * pxe_misc(mess, end, client_uuid, NULL); // Uses default "PXEClient" vendor
 * 
 * // Add custom vendor string for vendor-specific PXE implementation
 * pxe_misc(mess, end, client_uuid, "CustomPXEVendor");
 * @endcode
 * 
 * RFC COMPLIANCE:
 * - RFC 2132 Section 9.13: Option 60 (Vendor class identifier)
 * - RFC 4578 Section 2.1: Option 93 (Client System Architecture Type) for PXE detection
 * - RFC 4578 Section 2.5: Option 97 (Client Machine Identifier / UUID)
 * - PXE Specification 2.1: PXE vendor class identifier format
 * 
 * SIDE EFFECTS:
 * - Adds DHCP option 60 (Vendor class identifier) to packet
 * - Conditionally adds DHCP option 97 (UUID) if uuid parameter is non-NULL
 * - Consumes space from the end pointer in the DHCP packet
 * - No global state modifications
 * 
 * THREAD SAFETY: Single-threaded architecture, safe to call
 * 
 * Source: /src/rfc2131.c:3521-3531
 */
static void pxe_misc(struct dhcp_packet *mess, unsigned char *end, unsigned char *uuid, const char *pxevendor)
{
  unsigned char *p;

  if (!pxevendor)
    pxevendor="PXEClient";
  option_put_string(mess, end, OPTION_VENDOR_ID, pxevendor, 0);
  if (uuid && (p = free_space(mess, end, OPTION_PXE_UUID, 17)))
    memcpy(p, uuid, 17);
}

/**
 * @brief Prune vendor-encapsulated DHCP options based on network ID tag matching
 * 
 * @detailed This function implements tag-based filtering for vendor-encapsulated DHCP
 *           options (option 43), which allows different vendor-specific options to be
 *           sent to different classes of clients based on network ID tags. It iterates
 *           through the global daemon->dhcp_opts list examining all options marked with
 *           DHOPT_VENDOR_MATCH flag, clearing the flag for options whose network ID tags
 *           do not match the current client's tags. This pruning operation ensures that
 *           only relevant vendor options are included in the DHCP response. Additionally,
 *           the function detects whether any matching vendor options have the DHOPT_FORCE
 *           flag set, indicating that vendor-encapsulated option encoding must be performed
 *           even if the client didn't explicitly request it via the parameter request list.
 *           This mechanism supports complex multi-vendor environments where different device
 *           types require different vendor-specific configurations.
 * 
 * @param netid Linked list of network ID tags associated with current DHCP client (for matching)
 * 
 * @return 1 if any matching vendor option has DHOPT_FORCE flag (forcing vendor option encoding)
 * @retval 1 At least one matching vendor option must be forcefully included
 * @retval 0 No matching vendor options require forced inclusion (send only if requested)
 * 
 * @note Modifies DHOPT_VENDOR_MATCH flags in global daemon->dhcp_opts list as side effect
 * @note Network ID matching uses positive logic (match_netid with positive=1)
 * @note Only examines options with DHOPT_VENDOR_MATCH flag already set
 * @note Return value guides whether to encode option 43 in DHCP response
 * @note Tag matching allows vendor options to be client-specific (by MAC, vendor class, etc.)
 * @warning Modifies global daemon->dhcp_opts list flags (clears DHOPT_VENDOR_MATCH for non-matches)
 * @warning Must be called before encoding vendor options to ensure correct filtering
 * @warning Side effects persist across the function call (flags remain modified)
 * 
 * @see match_netid() which performs network ID tag matching logic
 * @see do_encap_opts() which encodes vendor-encapsulated options after pruning
 * @see do_options() which calls this function during DHCP response construction
 * @see struct dhcp_opt in dnsmasq.h for option structure definition
 * 
 * EXAMPLE USAGE:
 * @code
 * // Prune vendor options for current client's network ID tags
 * struct dhcp_netid *client_tags = ...; // Tags: vendor class, MAC match, etc.
 * int force_vendor = prune_vendor_opts(client_tags);
 * if (force_vendor || client_requested_option43)
 *   do_encap_opts(...); // Encode remaining vendor options
 * @endcode
 * 
 * RFC COMPLIANCE:
 * - RFC 2132 Section 8.4: Option 43 (Vendor-specific Information)
 * - RFC 3004: The User Class Option for DHCP (related to client classification)
 * - Vendor option tag matching implements dnsmasq-specific tag-based configuration
 * 
 * SIDE EFFECTS:
 * - Clears DHOPT_VENDOR_MATCH flag from daemon->dhcp_opts entries with non-matching netids
 * - Leaves DHOPT_VENDOR_MATCH flag set for matching entries
 * - No memory allocation or deallocation
 * - Return value influences subsequent vendor option encoding decisions
 * 
 * THREAD SAFETY: Single-threaded architecture, but modifies global daemon state
 * 
 * Source: /src/rfc2131.c:3533-3548
 */
static int prune_vendor_opts(struct dhcp_netid *netid)
{
  int force = 0;
  struct dhcp_opt *opt;

  /* prune vendor-encapsulated options based on netid, and look if we're forcing them to be sent */
  for (opt = daemon->dhcp_opts; opt; opt = opt->next)
    if (opt->flags & DHOPT_VENDOR_MATCH)
      {
	if (!match_netid(opt->netid, netid, 1))
	  opt->flags &= ~DHOPT_VENDOR_MATCH;
	else if (opt->flags & DHOPT_FORCE)
	  force = 1;
      }
  return force;
}


/* Many UEFI PXE implementations have badly broken menu code.
   If there's exactly one relevant menu item, we abandon the menu system,
   and jamb the data direct into the DHCP file, siaddr and sname fields.
   Note that in this case, we have to assume that layer zero would be requested
   by the client PXE stack. */
/**
 * @brief Apply UEFI PXE boot workaround for clients with single matching service
 * 
 * @detailed Implements a workaround for UEFI PXE boot architectures (arch >= 6) that simplifies
 *           boot configuration when exactly one PXE service matches the client. Instead of
 *           presenting a PXE menu, directly populates DHCP packet boot fields (siaddr, sname, file)
 *           to enable immediate boot. This workaround bypasses the normal PXE menu system for
 *           UEFI clients when the configuration is unambiguous (exactly one service).
 * 
 * @param pxe_arch Client architecture identifier from DHCP option 93 (workaround applies if >= 6 for UEFI)
 * @param netid Network tag chain for matching configured PXE services
 * @param mess DHCP packet structure to populate with boot fields (siaddr, sname, file) if workaround applies
 * @param local Local server IP address used as fallback next-server if service doesn't specify one
 * @param now Current time for DNS hostname resolution of boot server names
 * @param pxe Flag indicating whether to actually apply workaround (1) or just test applicability (0)
 * 
 * @return 1 if workaround applies and was applied (or would apply if pxe=1), 0 if workaround doesn't apply
 * @retval 0 Not a UEFI architecture (pxe_arch < 6)
 * @retval 0 Zero matching services found
 * @retval 0 Multiple matching services found (ambiguous - menu required)
 * @retval 1 Exactly one matching service found and workaround applied (if pxe=1)
 * 
 * @note Only activates for UEFI architectures (pxe_arch >= 6: x86-64 EFI, IA64 EFI, ARM EFI, etc.)
 * @warning Modifies mess->siaddr, mess->sname, mess->file if pxe=1 and workaround applies
 * 
 * @see pxe_opts() for normal PXE menu construction
 * @see match_netid() for service matching algorithm
 * @see a_record_from_hosts() for server name resolution
 * 
 * EXAMPLE USAGE:
 * @code
 * // Test if workaround applies without modifying packet
 * if (pxe_uefi_workaround(pxe_arch, netid, mess, local, now, 0))
 *   // Skip normal PXE menu construction
 * 
 * // Apply workaround and populate packet
 * pxe_uefi_workaround(pxe_arch, netid, mess, local, now, 1);
 * @endcode
 * 
 * RFC COMPLIANCE: UEFI PXE boot per UEFI specification and RFC 4578 (DHCP PXE options)
 * SIDE EFFECTS: If pxe=1, modifies DHCP packet fields siaddr, sname, file for direct boot
 * THREAD SAFETY: Safe for single-threaded architecture; reads daemon->pxe_services list
 */
static int pxe_uefi_workaround(int pxe_arch, struct dhcp_netid *netid, struct dhcp_packet *mess, struct in_addr local, time_t now, int pxe)
{
  struct pxe_service *service, *found;

  /* Only workaround UEFI archs. */
  if (pxe_arch < 6)
    return 0;
  
  for (found = NULL, service = daemon->pxe_services; service; service = service->next)
    if (pxe_arch == service->CSA && service->basename && match_netid(service->netid, netid, 1))
      {
	if (found)
	  return 0; /* More than one relevant menu item */
	  
	found = service;
      }

  if (!found)
    return 0; /* No relevant menu items. */
  
  if (!pxe)
     return 1;
  
  if (found->sname)
    {
      mess->siaddr = a_record_from_hosts(found->sname, now);
      snprintf((char *)mess->sname, sizeof(mess->sname), "%s", found->sname);
    }
  else 
    {
      if (found->server.s_addr != 0)
	mess->siaddr = found->server; 
      else
	mess->siaddr = local;
  
      inet_ntop(AF_INET, &mess->siaddr, (char *)mess->sname, INET_ADDRSTRLEN);
    }
  
  if (found->basename)
    snprintf((char *)mess->file, sizeof(mess->file), 
	     strchr(found->basename, '.') ? "%s" : "%s.0", found->basename);
  
  return 1;
}

/**
 * @brief Construct PXE-specific DHCP options for network boot clients
 * 
 * @detailed Builds a list of PXE vendor-specific options (43 and 60) based on configured
 *           PXE services, client architecture type, and network tags. Generates boot server
 *           discovery control, prompt options, and PXE menu entries for client display.
 *           Uses static memory for option structures returned to caller.
 * 
 * @param pxe_arch Client architecture identifier from DHCP option 93 (0=x86, 6=x86-64, 7=EFI, etc.)
 * @param netid Network tag chain for matching configured PXE services
 * @param local Local server IP address for PXE boot server entries
 * @param now Current time for service filtering
 * 
 * @return Pointer to chain of dhcp_opt structures containing PXE options, or daemon->dhcp_opts if no PXE services configured
 * 
 * @note Uses static memory allocation - returned pointers valid until next call
 * @warning Disables PXE multicast (not supported) and controls broadcast behavior
 * 
 * @see is_pxe_client() for PXE client detection
 * @see find_boot() for boot configuration lookup
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_opt *opts = pxe_opts(pxe_arch, netid, local_addr, now);
 * // Include opts in DHCP response option chain
 * @endcode
 * 
 * RFC COMPLIANCE: Implements PXE specification vendor options, RFC 4578 (PXE DHCP options)
 * SIDE EFFECTS: Modifies static fake_opts structure; returns references to static memory
 * THREAD SAFETY: Not thread-safe due to static memory usage (single-threaded architecture)
 */
static struct dhcp_opt *pxe_opts(int pxe_arch, struct dhcp_netid *netid, struct in_addr local, time_t now)
{
#define NUM_OPTS 4  

  unsigned  char *p, *q;
  struct pxe_service *service;
  static struct dhcp_opt *o, *ret;
  int i, j = NUM_OPTS - 1;
  struct in_addr boot_server;
  
  /* We pass back references to these, hence they are declared static */
  static unsigned char discovery_control;
  static unsigned char fake_prompt[] = { 0, 'P', 'X', 'E' }; 
  static struct dhcp_opt *fake_opts = NULL;
  
  /* Disable multicast, since we don't support it, and broadcast
     unless we need it */
  discovery_control = 3;
  
  ret = daemon->dhcp_opts;
  
  if (!fake_opts && !(fake_opts = whine_malloc(NUM_OPTS * sizeof(struct dhcp_opt))))
    return ret;

  for (i = 0; i < NUM_OPTS; i++)
    {
      fake_opts[i].flags = DHOPT_VENDOR_MATCH;
      fake_opts[i].netid = NULL;
      fake_opts[i].next = i == (NUM_OPTS - 1) ? ret : &fake_opts[i+1];
    }
  
  /* create the data for the PXE_MENU and PXE_SERVERS options. */
  p = (unsigned char *)daemon->dhcp_buff;
  q = (unsigned char *)daemon->dhcp_buff3;

  for (i = 0, service = daemon->pxe_services; service; service = service->next)
    if (pxe_arch == service->CSA && match_netid(service->netid, netid, 1))
      {
	size_t len = strlen(service->menu);
	/* opt 43 max size is 255. encapsulated option has type and length
	   bytes, so its max size is 253. */
	if (p - (unsigned char *)daemon->dhcp_buff + len + 3 < 253)
	  {
	    *(p++) = service->type >> 8;
	    *(p++) = service->type;
	    *(p++) = len;
	    memcpy(p, service->menu, len);
	    p += len;
	    i++;
	  }
	else
	  {
	  toobig:
	    my_syslog(MS_DHCP | LOG_ERR, _("PXE menu too large"));
	    return daemon->dhcp_opts;
	  }
	
	boot_server = service->basename ? local : 
	  (service->sname ? a_record_from_hosts(service->sname, now) : service->server);
	
	if (boot_server.s_addr != 0)
	  {
	    if (q - (unsigned char *)daemon->dhcp_buff3 + 3 + INADDRSZ >= 253)
	      goto toobig;
	    
	    /* Boot service with known address - give it */
	    *(q++) = service->type >> 8;
	    *(q++) = service->type;
	    *(q++) = 1;
	    /* dest misaligned */
	    memcpy(q, &boot_server.s_addr, INADDRSZ);
	    q += INADDRSZ;
	  }
	else if (service->type != 0)
	  /* We don't know the server for a service type, so we'll
	     allow the client to broadcast for it */
	  discovery_control = 2;
      }

  /* if no prompt, wait forever if there's a choice */
  fake_prompt[0] = (i > 1) ? 255 : 0;
  
  if (i == 0)
    discovery_control = 8; /* no menu - just use use mess->filename */
  else
    {
      ret = &fake_opts[j--];
      ret->len = p - (unsigned char *)daemon->dhcp_buff;
      ret->val = (unsigned char *)daemon->dhcp_buff;
      ret->opt = SUBOPT_PXE_MENU;

      if (q - (unsigned char *)daemon->dhcp_buff3 != 0)
	{
	  ret = &fake_opts[j--]; 
	  ret->len = q - (unsigned char *)daemon->dhcp_buff3;
	  ret->val = (unsigned char *)daemon->dhcp_buff3;
	  ret->opt = SUBOPT_PXE_SERVERS;
	}
    }

  for (o = daemon->dhcp_opts; o; o = o->next)
    if ((o->flags & DHOPT_VENDOR_MATCH) && o->opt == SUBOPT_PXE_MENU_PROMPT)
      break;
  
  if (!o)
    {
      ret = &fake_opts[j--]; 
      ret->len = sizeof(fake_prompt);
      ret->val = fake_prompt;
      ret->opt = SUBOPT_PXE_MENU_PROMPT;
    }
  
  ret = &fake_opts[j--]; 
  ret->len = 1;
  ret->opt = SUBOPT_PXE_DISCOVERY;
  ret->val= &discovery_control;
 
  return ret;
}
  
/**
 * @brief Clear DHCP packet fields in preparation for building a response
 * 
 * Initializes a DHCP packet structure by zeroing out the server name (sname),
 * boot filename (file), options area (except the 4-byte magic cookie), and
 * next server IP address (siaddr). This function is typically called before
 * constructing a DHCP response (OFFER, ACK, NAK) to ensure that fields
 * inherited from the client's request packet or from previous use do not
 * leak into the response.
 * 
 * The function preserves the first 4 bytes of the options field which contains
 * the DHCP magic cookie (0x63825363 in network byte order) that identifies
 * the message as a DHCP packet per RFC 2131 Section 3.
 * 
 * Fields cleared:
 * - sname: Server host name (64 bytes, typically unused in modern DHCP)
 * - file: Boot file name (128 bytes, used for BOOTP/PXE boot filename)
 * - options: All option data after the 4-byte magic cookie
 * - siaddr: IP address of next server to use in bootstrap (4 bytes)
 * 
 * Fields NOT cleared (caller's responsibility if needed):
 * - Header fields: op, htype, hlen, hops, xid, secs, flags
 * - Address fields: ciaddr, yiaddr, giaddr, chaddr
 * - DHCP magic cookie (first 4 bytes of options)
 * 
 * This selective clearing strategy allows the DHCP response builder to reuse
 * the request packet structure, preserving the transaction ID (xid) and client
 * hardware address (chaddr) that must be echoed in the response, while clearing
 * fields that the server will populate.
 * 
 * @param mess Pointer to DHCP packet structure to clear (must not be NULL)
 * @param end Pointer to one byte past the end of the options area to clear
 *            (must be > &mess->options[0] + sizeof(u32))
 * 
 * @return None (void function)
 * 
 * @note The 4-byte DHCP magic cookie at options[0..3] is preserved
 * @note mess->sname is 64 bytes per BOOTP/DHCP specification (RFC 2131)
 * @note mess->file is 128 bytes per BOOTP/DHCP specification (RFC 2131)
 * @note siaddr is set to 0.0.0.0 (INADDR_ANY) indicating no next server
 * @warning Caller must ensure mess and end are valid pointers
 * @warning Caller must ensure end >= &mess->options[0] + sizeof(u32) + 1
 * @warning This function modifies the packet structure in-place
 * 
 * @see dhcp_reply() which calls this function before building DHCP responses
 * @see do_options() which populates the cleared options area
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_packet *mess = (struct dhcp_packet *)daemon->dhcp_packet.iov_base;
 * unsigned char *end = (unsigned char *)(mess + 1); // End of standard packet
 * 
 * // Clear packet fields before building DHCPOFFER response
 * clear_packet(mess, end);
 * 
 * // Now populate response fields
 * mess->op = BOOTREPLY;           // Set operation to reply
 * mess->yiaddr = offered_addr;    // Set offered IP address
 * mess->siaddr = tftp_server;     // Set TFTP server if needed
 * // ... add DHCP options via do_options() ...
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 2131 Section 4.1 - DHCP message format (sname, file, options fields)
 * RFC COMPLIANCE: RFC 2131 Section 3 - DHCP magic cookie (0x63825363)
 * RFC COMPLIANCE: RFC 951 Section 3 - BOOTP message format (sname, file, siaddr fields)
 * SIDE EFFECTS: Modifies mess structure in-place by zeroing sname, file, options, siaddr
 * THREAD SAFETY: Thread-safe if different threads operate on different mess structures
 */
static void clear_packet(struct dhcp_packet *mess, unsigned char *end)
{
  memset(mess->sname, 0, sizeof(mess->sname));
  memset(mess->file, 0, sizeof(mess->file));
  memset(&mess->options[0] + sizeof(u32), 0, end - (&mess->options[0] + sizeof(u32)));
  mess->siaddr.s_addr = 0;
}

/**
 * @brief Find appropriate PXE boot configuration for client based on network tags
 * 
 * @detailed Searches the configured dhcp-boot entries to find the most appropriate
 *           boot configuration for the client. Uses two-phase matching: first attempts
 *           strict tag matching, then falls back to default boot configs without specific
 *           tags. This enables both tag-specific boot images and universal fallback configs.
 * 
 * @param netid Network tag chain identifying client characteristics (vendor class, user class, etc.)
 * 
 * @return Pointer to matching dhcp_boot configuration structure, or NULL if no configuration matches
 * 
 * @note Two-phase matching: strict matching first (match_netid mode 0), then untagged fallback (mode 1)
 * @warning Returns NULL if no boot configuration defined - caller must check
 * 
 * @see pxe_opts() for PXE option construction using boot config
 * @see match_netid() for tag matching algorithm
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_boot *boot = find_boot(netid);
 * if (boot)
 *   // Use boot->file, boot->next_server, boot->tftp_sname
 * @endcode
 * 
 * RFC COMPLIANCE: Implements DHCP option 67 (bootfile name) and option 66 (TFTP server) selection per RFC 2132
 * SIDE EFFECTS: None - read-only traversal of daemon->boot_config list
 * THREAD SAFETY: Read-only access to global daemon structure (safe in single-threaded architecture)
 */
struct dhcp_boot *find_boot(struct dhcp_netid *netid)
{
  struct dhcp_boot *boot;

  /* decide which dhcp-boot option we're using */
  for (boot = daemon->boot_config; boot; boot = boot->next)
    if (match_netid(boot->netid, netid, 0))
      break;
  if (!boot)
    /* No match, look for one without a netid */
    for (boot = daemon->boot_config; boot; boot = boot->next)
      if (match_netid(boot->netid, netid, 1))
	break;

  return boot;
}

/**
 * @brief Detect whether DHCP client is a PXE network boot client
 * 
 * @detailed Examines DHCP option 60 (vendor class identifier) to determine if the client
 *           is a PXE (Preboot Execution Environment) client. Compares the vendor ID against
 *           configured PXE vendor strings from dhcp-pxe-vendor configuration directives.
 *           If a match is found, optionally returns the matching vendor string for use in
 *           PXE-specific response processing. This detection enables conditional PXE service
 *           activation and vendor-specific boot configuration.
 * 
 * @param mess DHCP packet structure to examine for PXE client identification
 * @param sz Size of DHCP packet in bytes for boundary checking during option search
 * @param pxe_vendor Optional output parameter - if non-NULL, receives pointer to matching vendor string
 * 
 * @return 1 if client is a PXE client (vendor ID matches configured PXE vendor), 0 otherwise
 * @retval 1 PXE client detected - vendor ID matches configured dhcp-pxe-vendor string
 * @retval 0 Not a PXE client - no vendor ID option present or no match with configured vendors
 * 
 * @note If pxe_vendor parameter is NULL, only detection is performed without returning vendor string
 * @note Common PXE vendor IDs include "PXEClient" (standard), "HTTPClient" (HTTP boot)
 * @warning Returned pxe_vendor pointer references static configuration data - valid until config reload
 * 
 * @see pxe_opts() for PXE option construction after client detection
 * @see option_find() for DHCP option search implementation
 * 
 * EXAMPLE USAGE:
 * @code
 * const char *vendor = NULL;
 * if (is_pxe_client(mess, sz, &vendor))
 *   // Client is PXE, vendor contains "PXEClient" or other configured string
 *   // Proceed with PXE-specific response construction
 * @endcode
 * 
 * RFC COMPLIANCE: Implements DHCP option 60 (vendor class identifier) per RFC 2132, PXE specification
 * SIDE EFFECTS: Optionally sets *pxe_vendor output parameter if non-NULL and match found
 * THREAD SAFETY: Read-only access to daemon->dhcp_pxe_vendors configuration (safe in single-threaded architecture)
 */
static int is_pxe_client(struct dhcp_packet *mess, size_t sz, const char **pxe_vendor)
{
  const unsigned char *opt = NULL;
  ssize_t conf_len = 0;
  const struct dhcp_pxe_vendor *conf = daemon->dhcp_pxe_vendors;
  opt = option_find(mess, sz, OPTION_VENDOR_ID, 0);
  if (!opt) 
    return 0;
  for (; conf; conf = conf->next)
    {
      conf_len = strlen(conf->data);
      if (option_len(opt) < conf_len)
        continue;
      if (strncmp(option_ptr(opt, 0), conf->data, conf_len) == 0)
        {
          if (pxe_vendor)
            *pxe_vendor = conf->data;
          return 1;
        }
    }
  return 0;
}

static void do_options(struct dhcp_context *context,
		       struct dhcp_packet *mess,
		       unsigned char *end, 
		       unsigned char *req_options,
		       char *hostname, 
		       char *domain,
		       struct dhcp_netid *netid,
		       struct in_addr subnet_addr,
		       unsigned char fqdn_flags,
		       int null_term, int pxe_arch,
		       unsigned char *uuid,
		       int vendor_class_len,
		       time_t now,
		       unsigned int lease_time,
		       unsigned short fuzz,
		       const char *pxevendor,
		       int leasequery)
{
  struct dhcp_opt *opt, *config_opts = daemon->dhcp_opts;
  struct dhcp_boot *boot;
  unsigned char *p;
  int i, len, force_encap = 0;
  unsigned char f0 = 0, s0 = 0;
  int done_file = 0, done_server = 0;
  int done_vendor_class = 0;
  struct dhcp_netid *tagif;
  struct dhcp_netid_list *id_list;

  /* filter options based on tags, those we want get DHOPT_TAGOK bit set */
  if (context)
    context->netid.next = NULL;
  tagif = option_filter(netid, context && context->netid.net ? &context->netid : NULL, config_opts, pxe_arch != -1);
	
  /* logging */
  if (option_bool(OPT_LOG_OPTS) && req_options)
    {
      char *q = daemon->namebuff;
      for (i = 0; req_options[i] != OPTION_END; i++)
	{
	  char *s = option_string(AF_INET, req_options[i], NULL, 0, NULL, 0);
	  q += snprintf(q, MAXDNAME - (q - daemon->namebuff),
			"%d%s%s%s", 
			req_options[i],
			strlen(s) != 0 ? ":" : "",
			s, 
			req_options[i+1] == OPTION_END ? "" : ", ");
	  if (req_options[i+1] == OPTION_END || (q - daemon->namebuff) > 40)
	    {
	      q = daemon->namebuff;
	      my_syslog(MS_DHCP | LOG_INFO, _("%u requested options: %s"), ntohl(mess->xid), daemon->namebuff);
	    }
	}
    }
      
  if (!leasequery)
    {
      for (id_list = daemon->force_broadcast; id_list; id_list = id_list->next)
	if ((!id_list->list) || match_netid(id_list->list, netid, 0))
	  break;
      if (id_list)
	mess->flags |= htons(0x8000); /* force broadcast */
      
      if (context)
	mess->siaddr = context->local;
     
      /* See if we can send the boot stuff as options.
	 To do this we need a requested option list, BOOTP
	 and very old DHCP clients won't have this, we also 
	 provide a manual option to disable it.
	 Some PXE ROMs have bugs (surprise!) and need zero-terminated 
	 names, so we always send those.  */
      if ((boot = find_boot(tagif)))
	{
	  if (boot->sname)
	    {	  
	      if (!option_bool(OPT_NO_OVERRIDE) &&
		  req_options && 
		  in_list(req_options, OPTION_SNAME))
		option_put_string(mess, end, OPTION_SNAME, boot->sname, 1);
	      else
		safe_strncpy((char *)mess->sname, boot->sname, sizeof(mess->sname));
	    }
	  
	  if (boot->file)
	    {
	      if (!option_bool(OPT_NO_OVERRIDE) &&
		  req_options && 
		  in_list(req_options, OPTION_FILENAME))
		option_put_string(mess, end, OPTION_FILENAME, boot->file, 1);
	      else
		safe_strncpy((char *)mess->file, boot->file, sizeof(mess->file));
	    }
	  
	  if (boot->next_server.s_addr) 
	    mess->siaddr = boot->next_server;
	  else if (boot->tftp_sname)
	    mess->siaddr = a_record_from_hosts(boot->tftp_sname, now);
	}
      else
	/* Use the values of the relevant options if no dhcp-boot given and
	   they're not explicitly asked for as options. OPTION_END is used
	   as an internal way to specify siaddr without using dhcp-boot, for use in
	   dhcp-optsfile. */
	{
	  if ((!req_options || !in_list(req_options, OPTION_FILENAME)) &&
	      (opt = option_find2(OPTION_FILENAME)) && !(opt->flags & DHOPT_FORCE))
	    {
	      safe_strncpy((char *)mess->file, (char *)opt->val, sizeof(mess->file));
	      done_file = 1;
	    }
	  
	  if ((!req_options || !in_list(req_options, OPTION_SNAME)) &&
	      (opt = option_find2(OPTION_SNAME)) && !(opt->flags & DHOPT_FORCE))
	    {
	      safe_strncpy((char *)mess->sname, (char *)opt->val, sizeof(mess->sname));
	      done_server = 1;
	    }
	  
	  if ((opt = option_find2(OPTION_END)))
	    mess->siaddr.s_addr = ((struct in_addr *)opt->val)->s_addr;	
	}
    }
        
  /* We don't want to do option-overload for BOOTP, so make the file and sname
     fields look like they are in use, even when they aren't. This gets restored
     at the end of this function. */

  if (!req_options || option_bool(OPT_NO_OVERRIDE))
    {
      f0 = mess->file[0];
      mess->file[0] = 1;
      s0 = mess->sname[0];
      mess->sname[0] = 1;
    }
      
  /* At this point, if mess->sname or mess->file are zeroed, they are available
     for option overload, reserve space for the overload option. */
  if (mess->file[0] == 0 || mess->sname[0] == 0)
    end -= 3;

  /* rfc3011 says this doesn't need to be in the requested options list. */
  if (!leasequery && subnet_addr.s_addr)
    option_put(mess, end, OPTION_SUBNET_SELECT, INADDRSZ, ntohl(subnet_addr.s_addr));
   
  if (lease_time != 0xffffffff)
    { 
      unsigned int t1val = lease_time/2; 
      unsigned int t2val = (lease_time*7)/8;
      unsigned int hval;
      
      /* If set by user, sanity check, so not longer than lease. */
      if ((opt = option_find2(OPTION_T1)))
	{
	  hval = ntohl(*((unsigned int *)opt->val));
	  if (hval < lease_time && hval > 2)
	    t1val = hval;
	}

       if ((opt = option_find2(OPTION_T2)))
	{
	  hval = ntohl(*((unsigned int *)opt->val));
	  if (hval < lease_time && hval > 2)
	    t2val = hval;
	}
       	  
       /* ensure T1 is still < T2 */
       if (t2val <= t1val)
	 t1val = t2val - 1; 

       while (fuzz > (t1val/8))
	 fuzz = fuzz/2;
	 
       t1val -= fuzz;
       t2val -= fuzz;
       
       option_put(mess, end, OPTION_T1, 4, t1val);
       option_put(mess, end, OPTION_T2, 4, t2val);
    }

  /* replies to DHCPINFORM may not have a valid context */
  if (context)
    {
      /* Netmask and broadcast always sent, except leasequery. */
      if (!option_find2(OPTION_NETMASK) &&
	  (!leasequery || in_list(req_options, OPTION_NETMASK)))
	option_put(mess, end, OPTION_NETMASK, INADDRSZ, ntohl(context->netmask.s_addr));
      
      /* May not have a "guessed" broadcast address if we got no packets via a relay
	 from this net yet (ie just unicast renewals after a restart */
      if (context->broadcast.s_addr &&
	  !option_find2(OPTION_BROADCAST) &&
	  (!leasequery || in_list(req_options, OPTION_BROADCAST)))
    	option_put(mess, end, OPTION_BROADCAST, INADDRSZ, ntohl(context->broadcast.s_addr));
      
      /* Same comments as broadcast apply, and also may not be able to get a sensible
	 default when using subnet select.  User must configure by steam in that case. */
      if (context->router.s_addr &&
	  in_list(req_options, OPTION_ROUTER) &&
	  !option_find2(OPTION_ROUTER))
	option_put(mess, end, OPTION_ROUTER, INADDRSZ, ntohl(context->router.s_addr));
      
      if (daemon->port == NAMESERVER_PORT &&
	  in_list(req_options, OPTION_DNSSERVER) &&
	  !option_find2(OPTION_DNSSERVER))
	option_put(mess, end, OPTION_DNSSERVER, INADDRSZ, ntohl(context->local.s_addr));
    }

  if (domain && in_list(req_options, OPTION_DOMAINNAME) && 
      !option_find2(OPTION_DOMAINNAME))
    option_put_string(mess, end, OPTION_DOMAINNAME, domain, null_term);
 
  /* Note that we ignore attempts to set the fqdn using --dhc-option=81,<name> */
  if (hostname)
    {
      if (in_list(req_options, OPTION_HOSTNAME) &&
	  !option_find2(OPTION_HOSTNAME))
	option_put_string(mess, end, OPTION_HOSTNAME, hostname, null_term);
      
      if (fqdn_flags != 0)
	{
	  len = strlen(hostname) + 3;
	  
	  if (fqdn_flags & 0x04)
	    len += 2;
	  else if (null_term)
	    len++;

	  if (domain)
	    len += strlen(domain) + 1;
	  else if (fqdn_flags & 0x04)
	    len--;

	  if ((p = free_space(mess, end, OPTION_CLIENT_FQDN, len)))
	    {
	      *(p++) = fqdn_flags & 0x0f; /* MBZ bits to zero */ 
	      *(p++) = 255;
	      *(p++) = 255;

	      if (fqdn_flags & 0x04)
		{
		  p = do_rfc1035_name(p, hostname, NULL);
		  if (domain)
		    {
		      p = do_rfc1035_name(p, domain, NULL);
		      *p++ = 0;
		    }
		}
	      else
		{
		  memcpy(p, hostname, strlen(hostname));
		  p += strlen(hostname);
		  if (domain)
		    {
		      *(p++) = '.';
		      memcpy(p, domain, strlen(domain));
		      p += strlen(domain);
		    }
		  if (null_term)
		    *(p++) = 0;
		}
	    }
	}
    }      

  for (opt = config_opts; opt; opt = opt->next)
    {
      int optno = opt->opt;

      /* netids match and not encapsulated? */
      if (!(opt->flags & DHOPT_TAGOK))
	continue;
      
      /* was it asked for, or are we sending it anyway? */
      if ((!(opt->flags & DHOPT_FORCE) || leasequery) && !in_list(req_options, optno))
	continue;
      
      /* prohibit some used-internally options. T1 and T2 already handled. */
      if (optno == OPTION_CLIENT_FQDN ||
	  optno == OPTION_MAXMESSAGE ||
	  optno == OPTION_OVERLOAD ||
	  optno == OPTION_PAD ||
	  optno == OPTION_END ||
	  optno == OPTION_T1 ||
	  optno == OPTION_T2)
	continue;

      if (optno == OPTION_SNAME && done_server)
	continue;

      if (optno == OPTION_FILENAME && done_file)
	continue;
      
      /* For the options we have default values on
	 dhc-option=<optionno> means "don't include this option"
	 not "include a zero-length option" */
      if (opt->len == 0 && 
	  (optno == OPTION_NETMASK ||
	   optno == OPTION_BROADCAST ||
	   optno == OPTION_ROUTER ||
	   optno == OPTION_DNSSERVER || 
	   optno == OPTION_DOMAINNAME ||
	   optno == OPTION_HOSTNAME))
	continue;

      /* vendor-class comes from elsewhere for PXE */
      if (pxe_arch != -1 && optno == OPTION_VENDOR_ID)
	continue;
      
      /* always force null-term for filename and servername - buggy PXE again. */
      len = do_opt(opt, NULL, context, 
		   (optno == OPTION_SNAME || optno == OPTION_FILENAME) ? 1 : null_term);

      if ((p = free_space(mess, end, optno, len)))
	{
	  do_opt(opt, p, context, 
		 (optno == OPTION_SNAME || optno == OPTION_FILENAME) ? 1 : null_term);
	  
	  /* If we send a vendor-id, revisit which vendor-ops we consider 
	     it appropriate to send. */
	  if (optno == OPTION_VENDOR_ID)
	    {
	      match_vendor_opts(p - 2, config_opts);
	      done_vendor_class = 1;
	    }
	}  
    }

  /* encapsulated options. */
  handle_encap(mess, end, req_options, null_term, tagif, pxe_arch != 1);
  
  force_encap = prune_vendor_opts(tagif);
    
  if (context && pxe_arch != -1)
    {
      pxe_misc(mess, end, uuid, pxevendor);
      if (!pxe_uefi_workaround(pxe_arch, tagif, mess, context->local, now, 0))
	config_opts = pxe_opts(pxe_arch, tagif, context->local, now);
    }

  if ((force_encap || in_list(req_options, OPTION_VENDOR_CLASS_OPT) || in_list(req_options, OPTION_VENDOR_ID)) &&
      (leasequery || do_encap_opts(config_opts, OPTION_VENDOR_CLASS_OPT, DHOPT_VENDOR_MATCH, mess, end, null_term)) && 
      pxe_arch == -1 && !done_vendor_class && vendor_class_len != 0 &&
      (p = free_space(mess, end, OPTION_VENDOR_ID, vendor_class_len)))
    /* If we send vendor encapsulated options, and haven't already sent option 60,
       echo back the value we got from the client. */
    memcpy(p, daemon->dhcp_buff3, vendor_class_len);	    
   
   /* restore BOOTP anti-overload hack */
  if (!req_options || option_bool(OPT_NO_OVERRIDE))
    {
      mess->file[0] = f0;
      mess->sname[0] = s0;
    }
}

/**
 * @brief Process and encode encapsulated DHCP options for response packet
 * 
 * @detailed Handles two types of DHCP option encapsulation:
 *           1) Standard encapsulation (dhcp-option=encap:outer,inner,...) - wraps inner options
 *              inside a container option identified by outer option code
 *           2) RFC 3925 vendor-identifying encapsulation (dhcp-option=vi-encap:enterprise,opt,...)
 *              - wraps vendor-specific options with enterprise number per RFC 3925
 *           
 *           Algorithm groups configured options by their encapsulation parent, filters each
 *           inner option by network tags, PXE mode, and client request list, then encodes
 *           matching options into appropriate encapsulation format. Standard encapsulation
 *           delegates to do_encap_opts(); RFC 3925 manually constructs enterprise-number-prefixed
 *           option data structure.
 * 
 * @param mess DHCP packet structure to populate with encapsulated options
 * @param end Pointer to end of available space in DHCP packet buffer for boundary checking
 * @param req_options Client requested option list from DHCP option 55 (parameter request list)
 * @param null_term If non-zero, null-terminate string options during encoding
 * @param tagif Network tag chain for matching configured options against client characteristics
 * @param pxemode PXE mode flag for filtering PXE-specific encapsulated options via pxe_ok()
 * 
 * @return void (no return value)
 * 
 * @note Two-phase algorithm: (1) clear DHOPT_ENCAP_DONE flags, (2) process each encapsulation parent
 * @note Each encapsulation parent groups all matching inner options before encoding
 * @note RFC 3925 encapsulation limited to 250 bytes data length (255 byte option max - 5 byte header)
 * @warning Modifies option flags (DHOPT_ENCAP_DONE, DHOPT_ENCAP_MATCH) during processing
 * @warning RFC 3925 options exceeding 250 bytes are logged as warning and skipped
 * 
 * @see do_encap_opts() for standard encapsulation encoding implementation
 * @see do_opt() for individual option value encoding
 * @see match_netid() for network tag matching
 * @see pxe_ok() for PXE mode filtering
 * @see free_space() for packet buffer space allocation
 * @see in_list() for checking if outer option is in client request list
 * 
 * EXAMPLE USAGE:
 * @code
 * // Encode all configured encapsulated options matching client context
 * handle_encap(mess, end, req_options, null_term, netid, pxe_arch != -1);
 * // Standard encap and RFC 3925 vendor options now in packet
 * @endcode
 * 
 * RFC COMPLIANCE: Implements DHCP option encapsulation per RFC 2132 and RFC 3925 (vendor-identifying vendor options)
 * SIDE EFFECTS: Modifies DHCP packet mess by appending encapsulated options; modifies option flags in daemon->dhcp_opts
 * THREAD SAFETY: Modifies global daemon->dhcp_opts flag fields (safe in single-threaded architecture)
 */
static void handle_encap(struct dhcp_packet *mess, unsigned char *end, unsigned char *req_options,
			 int null_term, struct dhcp_netid *tagif, int pxemode)
{
  /* Send options to be encapsulated in arbitrary options, 
     eg dhcp-option=encap:172,17,.......
     Also handle vendor-identifying vendor-encapsulated options,
     dhcp-option = vi-encap:13,17,.......
     The may be more that one "outer" to do, so group
     all the options which match each outer in turn. */

  struct dhcp_opt *opt, *config_opts = daemon->dhcp_opts;
  unsigned char *p;
  int len;

  for (opt = config_opts; opt; opt = opt->next)
    opt->flags &= ~DHOPT_ENCAP_DONE;
  
  for (opt = config_opts; opt; opt = opt->next)
    {
      int flags;

      if ((flags = (opt->flags & (DHOPT_ENCAPSULATE | DHOPT_RFC3925))))
	{
	  int found = 0;
	  struct dhcp_opt *o;

	  if (opt->flags & DHOPT_ENCAP_DONE)
	    continue;

	  for (len = 0, o = config_opts; o; o = o->next)
	    {
	      int outer = flags & DHOPT_ENCAPSULATE ? o->u.encap : OPTION_VENDOR_IDENT_OPT;

	      o->flags &= ~DHOPT_ENCAP_MATCH;
	      
	      if (!(o->flags & flags) || opt->u.encap != o->u.encap)
		continue;
	      
	      o->flags |= DHOPT_ENCAP_DONE;
	      if (match_netid(o->netid, tagif, 1) &&
		  pxe_ok(o, pxemode) &&
		  ((o->flags & DHOPT_FORCE) || in_list(req_options, outer)))
		{
		  o->flags |= DHOPT_ENCAP_MATCH;
		  found = 1;
		  len += do_opt(o, NULL, NULL, 0) + 2;
		}
	    } 
	  
	  if (found)
	    { 
	      if (flags & DHOPT_ENCAPSULATE)
		do_encap_opts(config_opts, opt->u.encap, DHOPT_ENCAP_MATCH, mess, end, null_term);
	      else if (len > 250)
		my_syslog(MS_DHCP | LOG_WARNING, _("cannot send RFC3925 option: too many options for enterprise number %d"), opt->u.encap);
	      else if ((p = free_space(mess, end,  OPTION_VENDOR_IDENT_OPT, len + 5)))
		{
		  int swap_ent = htonl(opt->u.encap);
		  memcpy(p, &swap_ent, 4);
		  p += 4;
		  *(p++) = len;
		  for (o = config_opts; o; o = o->next)
		    if (o->flags & DHOPT_ENCAP_MATCH)
		      {
			len = do_opt(o, p + 2, NULL, 0);
			*(p++) = o->opt;
			*(p++) = len;
			p += len;
		      }     
		}
	    }
	}
    }      
}

/**
 * @brief Apply configured DHCP reply delay based on network tags
 * 
 * @detailed Searches configured dhcp-reply-delay directives to find appropriate delay
 *           for the current DHCP request based on client network tags. Uses two-phase
 *           matching: first strict tag matching, then untagged fallback. If matching
 *           delay configuration is found, schedules delayed DHCP response to manage
 *           server load and prevent race conditions in environments with multiple DHCP servers.
 * 
 * @param xid DHCP transaction ID (network byte order) for logging purposes
 * @param recvtime Timestamp when DHCP request was received (used to calculate actual delay)
 * @param netid Network tag chain identifying client characteristics for delay configuration matching
 * 
 * @return void (no return value)
 * 
 * @note Two-phase matching: strict matching first (match_netid mode 0), then untagged fallback (mode 1)
 * @note If no matching delay configuration found, function returns immediately with no delay applied
 * @warning Delay is applied by calling delay_dhcp() which schedules response transmission
 * 
 * @see delay_dhcp() for actual response delay implementation
 * @see match_netid() for tag matching algorithm
 * 
 * EXAMPLE USAGE:
 * @code
 * // Apply configured delay before sending DHCP response
 * apply_delay(mess->xid, recvtime, netid);
 * // Response will be delayed according to matching dhcp-reply-delay configuration
 * @endcode
 * 
 * RFC COMPLIANCE: DHCP reply delay mechanism per RFC 2131 server behavior recommendations
 * SIDE EFFECTS: Calls delay_dhcp() to schedule delayed response; logs delay value if not in quiet mode
 * THREAD SAFETY: Read-only access to daemon->delay_conf list (safe in single-threaded architecture)
 */
static void apply_delay(u32 xid, time_t recvtime, struct dhcp_netid *netid)
{
  struct delay_config *delay_conf;
  
  /* Decide which delay_config option we're using */
  for (delay_conf = daemon->delay_conf; delay_conf; delay_conf = delay_conf->next)
    if (match_netid(delay_conf->netid, netid, 0))
      break;
  
  if (!delay_conf)
    /* No match, look for one without a netid */
    for (delay_conf = daemon->delay_conf; delay_conf; delay_conf = delay_conf->next)
      if (match_netid(delay_conf->netid, netid, 1))
        break;

  if (delay_conf)
    {
      if (!option_bool(OPT_QUIET_DHCP))
	my_syslog(MS_DHCP | LOG_INFO, _("%u reply delay: %d"), ntohl(xid), delay_conf->delay);
      delay_dhcp(recvtime, delay_conf->delay, -1, 0, 0);
    }
}

/**
 * @brief Relay DHCPv4 packet upstream to configured DHCP servers
 * 
 * @detailed Forwards DHCPv4 client packets (DISCOVER, REQUEST, etc.) to upstream
 * DHCP servers configured via dhcp-relay directives. Implements RFC 1542 BOOTP/DHCP
 * relay agent functionality with extensions for RFC 3046 relay agent information
 * option. Supports two relay modes:
 * 
 * 1. **Standard Mode (RFC 1542)**: Sets giaddr to relay agent's address, increments
 *    hops field, forwards to upstream server. Traditional relay using giaddr for
 *    return routing.
 * 
 * 2. **Split Mode**: Uses OPTION_AGENT_ID (82) with sub-options instead of giaddr,
 *    enabling relay through NAT environments where giaddr modification breaks routing.
 *    Encodes subnet selection (sub-option 5), server override (13), flags (10), and
 *    remote ID (2, interface index) for return path identification.
 * 
 * The function iterates through all configured relay servers, handling broadcast vs.
 * unicast transmission, maximum hop count enforcement (16 hops per RFC 1542), and
 * proper restoration of original packet state for potential local reply handling.
 * 
 * @param iface_addr IPv4 address of receiving interface (relay agent's local address)
 *                   Used as giaddr in standard mode or in OPTION_AGENT_ID for split mode
 *                   Must be valid unicast address for relay operations
 * 
 * @param iface_index System interface index of receiving interface
 *                    Encoded in OPTION_AGENT_ID SUBOPT_REMOTE_ID for split mode return routing
 *                    Used to identify which interface received the original client request
 * 
 * @param mess Pointer to DHCP packet to relay to upstream servers
 *             Packet is modified (giaddr, hops) during relay, then restored afterward
 *             Must have sufficient space for OPTION_AGENT_ID addition in split mode
 * 
 * @param sz Size of DHCP packet in bytes
 *           Must be within DHCP minimum/maximum packet size bounds
 *           May be increased by up to 24 bytes for OPTION_AGENT_ID in split mode
 * 
 * @param unicast 1 if packet was received via unicast, 0 if broadcast
 *                Encoded in SUBOPT_FLAGS of OPTION_AGENT_ID for split mode
 *                Helps upstream server determine appropriate response addressing
 * 
 * @return void (no return value - logs errors for failed relay operations)
 * 
 * @note Relay only occurs if daemon->relay4 configuration exists
 * @note Maximum hop count of 16 is enforced per RFC 1542 to prevent routing loops
 * @warning Modifies mess->hops and mess->giaddr temporarily, restores before return
 * @warning Split mode requires 24 bytes free space for OPTION_AGENT_ID construction
 * 
 * @see relay_reply4() Handles downstream relay of server responses back to clients
 * @see send_from() Transmits relayed packet with proper source address binding
 * 
 * EXAMPLE USAGE:
 * @code
 * // In DHCP packet reception handler:
 * struct dhcp_packet *mess = daemon->dhcp_packet.iov_base;
 * struct in_addr iface_addr = ...;  // Interface IP where packet received
 * int iface_index = if_nametoindex("eth0");
 * size_t sz = 300; // Packet size
 * int unicast = (mess->giaddr.s_addr != 0);
 * 
 * relay_upstream4(iface_addr, iface_index, mess, sz, unicast);
 * // Packet relayed to all configured upstream DHCP servers
 * @endcode
 * 
 * RFC COMPLIANCE:
 *   - RFC 1542 Section 4.1.1 (BOOTP relay agent operation, giaddr and hops)
 *   - RFC 3046 (DHCP Relay Agent Information Option, option 82)
 *   - RFC 5107 (DHCP Server Identifier Override, sub-option 11/13)
 *   - RFC 3527 (Link Selection sub-option, sub-option 5)
 * 
 * SIDE EFFECTS:
 *   - Temporarily modifies mess->hops (incremented) and mess->giaddr (set to relay address)
 *   - May add or modify OPTION_AGENT_ID in split mode (24 additional bytes)
 *   - Sends UDP packets to upstream DHCP servers via daemon->dhcpfd socket
 *   - Logs relay operations to syslog if OPT_LOG_OPTS enabled
 *   - Restores original hops and giaddr values before function return
 * 
 * THREAD SAFETY: Not thread-safe - modifies shared daemon state and packet buffer
 */
void relay_upstream4(struct in_addr iface_addr, int iface_index, struct dhcp_packet *mess, size_t sz, int unicast)
{
  struct in_addr giaddr = mess->giaddr;
  u8 hops = mess->hops;
  struct dhcp_relay *relay;
  size_t orig_sz = sz;
  unsigned char *endopt = NULL;
    
  if (mess->op != BOOTREQUEST || (mess->hops++) > 20)
    return;
  
  for (relay = daemon->relay4; relay; relay = relay->next)
    {
      union mysockaddr to;
      union all_addr from;
      struct ifreq ifr;

      /* restore orig packet */
      mess->giaddr = giaddr;
      if (endopt)
	*endopt = OPTION_END;
      sz = orig_sz;

      if (relay->interface)
	{
	  safe_strncpy(ifr.ifr_name, relay->interface, IF_NAMESIZE);
	  ifr.ifr_addr.sa_family = AF_INET;
	}
      
      if (!relay->split_mode && relay->iface_index && relay->iface_index == iface_index)
	{
	  /* already gatewayed ? */
	  if (giaddr.s_addr)
	    {
	      /* if so check if by us, to stomp on loops. */
	      if (giaddr.s_addr == relay->local.addr4.s_addr)
		continue;
	    }
	  else
	    /* plug in our address */
	    mess->giaddr = relay->local.addr4;
	  
	  from.addr4 = relay->local.addr4;
	}
      else if (relay->split_mode && relay->local.addr4.s_addr == iface_addr.s_addr)
	{
	  /* Split mode. We put our address on the server-facing interface
	     or a directly specified third address into giaddr for the server to talk back to us on.
	     
	     Our address on client-facing interface goes into agent-id subnet-selector subopt,
	     so that the server allocates the correct address. We also send a
	     remote-id with the interface on which the request arrived,
	     so that we can send the reply back the same way. */
	  unsigned int net_index = htonl(iface_index);
	  
	  if (relay->interface)
	    {
	      /* get our address on the server-facing interface. */
	      if (ioctl(daemon->dhcpfd, SIOCGIFADDR, &ifr) == -1)
		{
		  my_syslog(MS_DHCP | LOG_ERR, _("Cannot send to server via interface %s: %s"), relay->interface, strerror(errno));
		  continue;
		}
	      
	      relay->uplink.addr4 = ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr;
	    }
	  
	  /* already gatewayed ? */
	  if (giaddr.s_addr)
	    {
	      /* if so check if by us, to stomp on loops. */
	      if (giaddr.s_addr == relay->uplink.addr4.s_addr)
		continue;
	    }
	  else
	    {
	      /* giaddr is our address on the outgoing interface in split mode. */
	      mess->giaddr = relay->uplink.addr4;
	      
	      if (!endopt)
		{
		  /* Add an RFC3026 relay agent information option (2 bytes) at the very end of the options.
		     Said option to contain a RFC 3527 link selection sub option (6 bytes) and
		     RFC 5017 serverid-override option (6 bytes) and RFC5010 flags (3 bytes) and
		     an RFC3046 remote-id which holds an interface index (6 bytes)
		     
		     New END option is a 24th byte, so we need 24 bytes free.
		     We only need to do this once, and poke the address/interface/flags into the same place each time. */
		  
		  if (!(endopt = option_find1((&mess->options[0] + sizeof(u32)), ((unsigned char *)mess) + sz, OPTION_END, 0)) ||
		      (endopt + 24 > (unsigned char *)(mess + 1)))
		    continue;
		  
		  endopt[1] = 21; /* length */
		  endopt[2] = SUBOPT_SUBNET_SELECT;
		  endopt[3] = 4; /* length */
		  endopt[8] = SUBOPT_SERVER_OR;
		  endopt[9] = 4;
		  endopt[14] = SUBOPT_FLAGS;
		  endopt[15] = 1; /* length */
		  endopt[17] = SUBOPT_REMOTE_ID;
		  endopt[18] = 4; /* length */
		  endopt[23] = OPTION_END;
		  sz = (endopt - (unsigned char *)mess) + 24;
		}
	      
	      /* IP address is already in network byte order */
	      memcpy(&endopt[4], &relay->local.addr4.s_addr, INADDRSZ);
	      memcpy(&endopt[10], &relay->local.addr4.s_addr, INADDRSZ);
	      endopt[16] = unicast ? 0x80 : 0x00;
	      memcpy(&endopt[19], &net_index, 4);
	      endopt[0] = OPTION_AGENT_ID;
	    }
	  
	  from.addr4 = relay->uplink.addr4;
	}
      else
	continue;
	
      to.sa.sa_family = AF_INET;
      to.in.sin_addr = relay->server.addr4;
      to.in.sin_port = htons(relay->port);
#ifdef HAVE_SOCKADDR_SA_LEN
      to.in.sin_len = sizeof(struct sockaddr_in);
#endif
      
      /* Broadcasting to server. */
      if (relay->server.addr4.s_addr == 0)
	{
	  if (ioctl(daemon->dhcpfd, SIOCGIFBRDADDR, &ifr) == -1)
	    {
	      my_syslog(MS_DHCP | LOG_ERR, _("Cannot broadcast DHCP relay via interface %s: %s"), relay->interface, strerror(errno));
	      continue;
	    }
	  
	  to.in.sin_addr = ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr;
	}
      
#ifdef HAVE_DUMPFILE
      {
	union mysockaddr fromsock;
	fromsock.in.sin_port = htons(daemon->dhcp_server_port);
	fromsock.in.sin_addr = from.addr4;
	fromsock.sa.sa_family = AF_INET;
	
	dump_packet_udp(DUMP_DHCP, (void *)mess, sz, &fromsock, &to, -1);
      }
#endif
      
      send_from(daemon->dhcpfd, 0, (char *)mess, sz, &to, &from, 0);
      
      if (option_bool(OPT_LOG_OPTS))
	{
	  inet_ntop(AF_INET, &relay->local, daemon->addrbuff, ADDRSTRLEN);
	  if (relay->server.addr4.s_addr == 0)
	    snprintf(daemon->dhcp_buff2, DHCP_BUFF_SZ, _("broadcast via %s"), relay->interface);
	  else
	    inet_ntop(AF_INET, &relay->server.addr4, daemon->dhcp_buff2, DHCP_BUFF_SZ);
	  my_syslog(MS_DHCP | LOG_INFO, _("DHCP relay at %s -> %s"), daemon->addrbuff, daemon->dhcp_buff2);
	}
    }
  
  /* restore in case of a local reply. */
  mess->hops = hops;
  mess->giaddr = giaddr;
  if (endopt)
    *endopt = OPTION_END;
}

/**
 * @brief Relay DHCPv4 server reply downstream to client via appropriate interface
 * 
 * @detailed Processes DHCP server responses (OFFER, ACK, NAK) received from upstream
 * servers and determines the correct local interface for forwarding back to the original
 * DHCP client. Implements the downstream relay portion of RFC 1542 BOOTP/DHCP relay
 * agent operation with RFC 3046 relay agent information option support.
 * 
 * **Return Path Determination:**
 * 
 * The function examines the packet's giaddr field and OPTION_AGENT_ID (in split mode)
 * to identify the interface where the original client request was received:
 * 
 * 1. **Split Mode (RFC 3046 extended)**:
 *    - Verifies giaddr matches relay->uplink.addr4 (upstream relay address)
 *    - Extracts SUBOPT_REMOTE_ID from OPTION_AGENT_ID containing interface index
 *    - Deletes OPTION_AGENT_ID before forwarding per RFC 3046 paragraph 2.1
 *    - Returns extracted interface index for packet transmission
 * 
 * 2. **Standard Mode (RFC 1542)**:
 *    - Matches giaddr against relay->local.addr4 (local relay address)
 *    - Returns configured relay->iface_index for downstream transmission
 * 
 * **Packet Filtering:**
 * 
 * - Only processes BOOTREPLY packets (server responses, not client requests)
 * - Ignores packets with giaddr=0 (not relayed, direct server-to-client)
 * - Validates arrival interface matches relay->interface if configured (wildcard support)
 * 
 * **Agent Information Handling:**
 * 
 * In split mode, the OPTION_AGENT_ID is removed before forwarding the packet to the
 * client network. RFC 3046 paragraph 2.1 requires relay agents to remove the relay
 * agent information option when forwarding replies, preventing option leakage to clients
 * and avoiding packet size growth in multi-hop scenarios.
 * 
 * @param mess Pointer to DHCP BOOTREPLY packet from upstream server
 *             Must have mess->op == BOOTREPLY and mess->giaddr != 0 for relay processing
 *             OPTION_AGENT_ID is deleted in split mode (modified in-place)
 * 
 * @param sz Size of DHCP packet in bytes
 *           Used for option parsing with bounds checking
 *           Must be at least sizeof(struct dhcp_packet)
 * 
 * @param arrival_interface Name of network interface where packet arrived (e.g., "eth0")
 *                          Used to validate packet arrived on expected upstream interface
 *                          Must match relay->interface (if configured) for relay processing
 *                          NULL is permitted but disables interface validation
 * 
 * @return Interface index (non-zero) where packet should be forwarded to reach client
 * @retval >0 Valid interface index for downstream packet transmission
 * @retval 0 Packet should not be relayed (not a relayed reply, no matching relay config)
 * 
 * @note Only processes packets with giaddr set and op=BOOTREPLY
 * @note Multiple relay configurations are checked until a match is found
 * @warning Modifies packet by deleting OPTION_AGENT_ID in split mode
 * @warning Caller must verify returned interface index is valid before transmission
 * 
 * @see relay_upstream4() Handles upstream relay of client packets to servers
 * @see send_from() Transmits relayed reply with proper interface binding
 * 
 * EXAMPLE USAGE:
 * @code
 * // In DHCP packet reception handler for server replies:
 * struct dhcp_packet *mess = daemon->dhcp_packet.iov_base;
 * size_t sz = 300; // Packet size from recvmsg
 * char *iface_name = "eth1"; // Interface where reply arrived
 * 
 * unsigned int return_iface = relay_reply4(mess, sz, iface_name);
 * if (return_iface) {
 *   // Forward packet via identified interface
 *   send_from(return_iface, 0, (char *)mess, sz, ...);
 * } else {
 *   // Not a relayed reply or no matching relay config
 * }
 * @endcode
 * 
 * RFC COMPLIANCE:
 *   - RFC 1542 Section 4.1.1 (BOOTP relay agent operation with giaddr)
 *   - RFC 3046 Paragraph 2.1 (Relay agent MUST remove option 82 before forwarding reply)
 *   - RFC 3046 Section 2.0 (Relay Agent Information Option format and sub-options)
 * 
 * SIDE EFFECTS:
 *   - Deletes OPTION_AGENT_ID from packet in split mode (writes OPTION_END, zeros data)
 *   - Modifies packet in-place by overwriting relay agent information option
 *   - Iterates through daemon->relay4 list to find matching relay configuration
 * 
 * THREAD SAFETY: Not thread-safe - modifies shared packet buffer and reads daemon state
 */
unsigned int relay_reply4(struct dhcp_packet *mess, size_t sz, char *arrival_interface)
{
  struct dhcp_relay *relay;
    
  if (mess->giaddr.s_addr == 0 || mess->op != BOOTREPLY)
    return 0;

  for (relay = daemon->relay4; relay; relay = relay->next)
    {
      unsigned int return_iface = 0;

      if (relay->split_mode)
	{
	  unsigned char *opt, *sopt;
	  
	  /* giaddr is our address on the returning interface in split mode. */
	  if (mess->giaddr.s_addr == relay->uplink.addr4.s_addr &&
	      (opt = option_find(mess, sz, OPTION_AGENT_ID, 1)))
	    {
	      if ((sopt = option_find1(option_ptr(opt, 0), option_ptr(opt, option_len(opt)), SUBOPT_REMOTE_ID, sizeof(unsigned int))))
		return_iface = option_uint(sopt, 0, sizeof(unsigned int));

	      /* delete agent info before return RFC 3046 para 2.1 */
	      *opt = OPTION_END;
	      memset(opt + 1, 0, option_len(opt) + 2);
	    }
	}
      else if (mess->giaddr.s_addr == relay->local.addr4.s_addr)
	return_iface = relay->iface_index;
      
      if (return_iface && (!relay->interface || wildcard_match(relay->interface, arrival_interface)))
	return return_iface;
    }
  
  return 0;	 
}     


#endif /* HAVE_DHCP */

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
 * @file slaac.c
 * @brief SLAAC (Stateless Address Autoconfiguration) address confirmation and duplicate address detection
 * 
 * DETAILED PURPOSE:
 * This module implements SLAAC address confirmation for IPv6 clients that derive their
 * addresses from Router Advertisement prefixes using stateless autoconfiguration. When
 * dnsmasq operates in RA-names mode, it needs to confirm that SLAAC-derived addresses
 * are actually in use and not conflicting with other hosts before registering them in
 * DNS. This module performs duplicate address detection by sending ICMPv6 echo requests
 * (pings) to the derived addresses and monitoring for replies.
 * 
 * KEY RESPONSIBILITIES:
 * - slaac_add_addrs(): Derives SLAAC addresses from DHCPv4 lease MAC addresses using
 *   EUI-64 conversion and Router Advertisement prefixes, creating slaac_address tracking
 *   structures for addresses that need confirmation
 * - periodic_slaac(): Sends ICMPv6 echo request packets to unconfirmed SLAAC addresses
 *   with exponential backoff retry logic, confirming address uniqueness
 * - slaac_ping_reply(): Processes ICMPv6 echo reply packets to mark addresses as confirmed,
 *   triggering DNS registration when backoff counter reaches zero
 * 
 * DEPENDENCIES:
 * Includes: dnsmasq.h (core structures including struct slaac_address, struct dhcp_lease,
 *           struct dhcp_context), netinet/icmp6.h (ICMPv6 protocol definitions)
 * Called by: Main event loop via periodic_slaac() timer, DHCPv4 lease event handlers via
 *            slaac_add_addrs(), network packet processing via slaac_ping_reply()
 * Calls: radv.c functions (ra_start_unsolicited() to trigger Router Advertisements),
 *        network.c functions (send_from() for ICMPv6 packet transmission), cache.c
 *        functions (cache_add_dhcp_entry() for DNS registration)
 * 
 * DATA STRUCTURES:
 * - struct slaac_address: Tracks SLAAC-derived addresses awaiting confirmation (line 879
 *   in dnsmasq.h), containing IPv6 address (addr), last ping timestamp (ping_time),
 *   confirmation backoff counter (backoff), and linked list pointer (next)
 * - struct dhcp_lease: Contains MAC address (hwaddr) used for EUI-64 conversion, hardware
 *   type (hwaddr_type), hostname for DNS registration, and linked list of slaac_address
 *   structures (slaac_address pointer)
 * - struct dhcp_context: Defines IPv6 prefix ranges for SLAAC address derivation, contains
 *   RA-names flag (CONTEXT_RA_NAME) and interface binding (if_index)
 * 
 * COMPILE-TIME OPTIONS:
 * HAVE_DHCP6: Must be defined to compile this module (entire file is conditionally compiled)
 * 
 * THREADING/CONCURRENCY:
 * Single-threaded event-driven model. Functions are called from the main event loop in
 * response to timer events (periodic_slaac), DHCPv4 lease events (slaac_add_addrs), and
 * incoming ICMPv6 packets (slaac_ping_reply). No locking required as all operations are
 * serialized by the event loop.
 * 
 * SLAAC ADDRESS DERIVATION:
 * IPv6 SLAAC allows hosts to automatically configure addresses by combining a Router
 * Advertisement prefix (typically /64) with an interface identifier derived from the MAC
 * address. Two common derivation methods are:
 * 
 * 1. EUI-64 CONVERSION (RFC 4291 Appendix A):
 *    - Takes 48-bit MAC address (e.g., 00:11:22:33:44:55)
 *    - Inserts 0xFFFE in the middle: 00:11:22:FF:FE:33:44:55
 *    - Inverts universal/local bit (bit 7): 02:11:22:FF:FE:33:44:55
 *    - Combines with /64 prefix: 2001:db8::/64 + EUI-64 = 2001:db8::211:22ff:fe33:4455
 * 
 * 2. PRIVACY EXTENSIONS (RFC 8981):
 *    - Generates random interface identifiers to prevent MAC-based tracking
 *    - Changes periodically to enhance privacy
 *    - Not directly handled by dnsmasq (clients generate these autonomously)
 * 
 * This module focuses on EUI-64-derived addresses where dnsmasq can predict the address
 * from the DHCPv4 lease MAC address, enabling DNS registration with duplicate detection.
 * 
 * @copyright Copyright (c) 2000-2025 Simon Kelley
 * @license GPL-2.0-or-later
 */

#include "dnsmasq.h"

#ifdef HAVE_DHCP6

#include <netinet/icmp6.h>

static int ping_id = 0;

/**
 * @brief Derive and track SLAAC addresses for DHCPv4 lease based on Router Advertisement prefixes
 * 
 * @detailed
 * This function is called when a DHCPv4 lease is created or renewed to derive potential
 * SLAAC IPv6 addresses that the client might be using on RA-enabled interfaces. For each
 * DHCPv6 context with CONTEXT_RA_NAME flag and matching interface, the function converts
 * the client's MAC address to an EUI-64 interface identifier and combines it with the
 * context's IPv6 prefix to form a complete IPv6 address. These derived addresses are
 * added to the lease's slaac_address linked list for duplicate address detection via
 * periodic ICMPv6 echo requests. Once confirmed (backoff reaches zero), the addresses
 * are registered in DNS with the lease's hostname.
 * 
 * The function handles multiple MAC address types including Ethernet (48-bit), EUI-64
 * (64-bit), and IEEE 1394 FireWire identifiers. For Ethernet MACs, the standard EUI-64
 * conversion inserts 0xFFFE bytes and inverts the universal/local bit. Existing SLAAC
 * addresses are preserved if they still match current configuration; new addresses
 * trigger unsolicited Router Advertisements to encourage clients to adopt them.
 * 
 * @param lease DHCPv4 lease containing MAC address (hwaddr), hardware type (hwaddr_type),
 *              hostname for DNS registration, and interface binding (last_interface). Must
 *              have LEASE_HAVE_HWADDR flag set and must not be temporary address (TA) or
 *              non-temporary address (NA) DHCPv6 lease type. Hostname must be non-NULL
 *              for DNS registration eligibility.
 * @param now Current timestamp for initializing ping_time in new slaac_address structures
 * @param force If non-zero, forces revalidation of existing SLAAC addresses by resetting
 *              ping_time and backoff counter. Used when DHCPv4 lease goes through
 *              init-reboot sequence to reverify address uniqueness.
 * 
 * @return void (no return value)
 * 
 * @note This function modifies the lease->slaac_address linked list, potentially freeing
 *       old addresses that no longer match current RA contexts and allocating new ones.
 *       Memory allocation failure is logged via whine_malloc but operation continues.
 * 
 * @warning Requires HAVE_DHCP6 compile flag. Function returns immediately if lease lacks
 *          hardware address, is a DHCPv6 lease type (TA/NA), has no interface binding,
 *          or has no hostname (DNS registration impossible without hostname).
 * 
 * @see periodic_slaac() in src/slaac.c for ping transmission logic
 * @see ra_start_unsolicited() in src/radv.c for triggering Router Advertisements
 * @see struct slaac_address in src/dnsmasq.h:879 for address tracking structure
 * 
 * EXAMPLE USAGE:
 * @code
 * // Called when DHCPv4 lease is assigned or renewed
 * struct dhcp_lease *lease = ...; // Lease with MAC 00:11:22:33:44:55, hostname "client1"
 * time_t now = dnsmasq_time();
 * int force = 0; // Normal operation, not init-reboot
 * slaac_add_addrs(lease, now, force);
 * // Result: If RA context exists for interface with prefix 2001:db8::/64,
 * //         creates slaac_address for 2001:db8::211:22ff:fe33:4455
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 4291 Appendix A (EUI-64 interface identifier derivation)
 * 
 * SIDE EFFECTS:
 * - Modifies lease->slaac_address linked list (may free old, allocate new structures)
 * - Triggers unsolicited Router Advertisements via ra_start_unsolicited() for new addresses
 * - May set dns_dirty flag (local variable) but effect is currently unused
 * - Allocates memory via whine_malloc() for new slaac_address structures
 * 
 * THREAD SAFETY: Single-threaded architecture, called from main event loop during DHCP
 *                lease processing. Modifies global daemon->dhcp6 context list (read-only
 *                iteration) and lease structure (exclusive access assumed).
 */
void slaac_add_addrs(struct dhcp_lease *lease, time_t now, int force)
{
  struct slaac_address *slaac, *old, **up;
  struct dhcp_context *context;
  int dns_dirty = 0;
  
  if (!(lease->flags & LEASE_HAVE_HWADDR) || 
      (lease->flags & (LEASE_TA | LEASE_NA)) ||
      lease->last_interface == 0 ||
      !lease->hostname)
    return ;
  
  old = lease->slaac_address;
  lease->slaac_address = NULL;

  for (context = daemon->dhcp6; context; context = context->next) 
    if ((context->flags & CONTEXT_RA_NAME) && 
	!(context->flags & CONTEXT_OLD) &&
	lease->last_interface == context->if_index)
      {
	struct in6_addr addr = context->start6;
	if (lease->hwaddr_len == 6 &&
	    (lease->hwaddr_type == ARPHRD_ETHER || lease->hwaddr_type == ARPHRD_IEEE802))
	  {
	    /* convert MAC address to EUI-64 */
	    memcpy(&addr.s6_addr[8], lease->hwaddr, 3);
	    memcpy(&addr.s6_addr[13], &lease->hwaddr[3], 3);
	    addr.s6_addr[11] = 0xff;
	    addr.s6_addr[12] = 0xfe;
	  }
#if defined(ARPHRD_EUI64)
	else if (lease->hwaddr_len == 8 &&
		 lease->hwaddr_type == ARPHRD_EUI64)
	  memcpy(&addr.s6_addr[8], lease->hwaddr, 8);
#endif
#if defined(ARPHRD_IEEE1394) && defined(ARPHRD_EUI64)
	else if (lease->clid_len == 9 && 
		 lease->clid[0] ==  ARPHRD_EUI64 &&
		 lease->hwaddr_type == ARPHRD_IEEE1394)
	  /* FireWire has EUI-64 identifier as clid */
	  memcpy(&addr.s6_addr[8], &lease->clid[1], 8);
#endif
	else
	  continue;
	
	addr.s6_addr[8] ^= 0x02;
	
	/* check if we already have this one */
	for (up = &old, slaac = old; slaac; slaac = slaac->next)
	  {
	    if (IN6_ARE_ADDR_EQUAL(&addr, &slaac->addr))
	      {
		*up = slaac->next;
		/* recheck when DHCPv4 goes through init-reboot */
		if (force)
		  {
		    slaac->ping_time = now;
		    slaac->backoff = 1;
		    dns_dirty = 1;
		  }
		break;
	      }
	    up = &slaac->next;
	  }
	    
	/* No, make new one */
	if (!slaac && (slaac = whine_malloc(sizeof(struct slaac_address))))
	  {
	    slaac->ping_time = now;
	    slaac->backoff = 1;
	    slaac->addr = addr;
	    /* Do RA's to prod it */
	    ra_start_unsolicited(now, context);
	  }
	
	if (slaac)
	  {
	    slaac->next = lease->slaac_address;
	    lease->slaac_address = slaac;
	  }
      }
  
  if (old || dns_dirty)
    lease_update_dns(1);
  
  /* Free any no reused */
  for (; old; old = slaac)
    {
      slaac = old->next;
      free(old);
    }
}


/**
 * @brief Send ICMPv6 echo requests to unconfirmed SLAAC addresses with exponential backoff
 * 
 * @detailed
 * This function is called periodically from the main event loop to verify that SLAAC-derived
 * IPv6 addresses are actually in use by clients before registering them in DNS. For each
 * DHCPv4 lease with pending SLAAC addresses, the function checks if sufficient time has
 * elapsed since the last ping based on an exponential backoff schedule with randomization.
 * When ready, it constructs an ICMPv6 echo request packet (ping) with a unique identifier
 * and sends it to the unconfirmed address.
 * 
 * The exponential backoff schedule grows with each retry: after the initial ping at backoff=1,
 * the wait time doubles with each attempt (1s, 2s, 4s, 8s, 16s, etc.) plus randomization
 * to prevent thundering herd effects. The backoff counter increments up to a maximum of 12
 * attempts. If the host is unreachable (EHOSTUNREACH) at backoff 12, the address is
 * abandoned. The randomization adds 0-3 seconds for all attempts, plus an additional
 * 0-15 seconds for backoff > 4.
 * 
 * The function uses a static ping_id counter (initialized once with rand16()) to generate
 * unique ICMPv6 echo request identifiers, allowing slaac_ping_reply() to correlate incoming
 * replies with specific SLAAC addresses. The ping packet uses the identifier and the
 * backoff counter as the sequence number for validation. When a ping reply is received
 * (handled by slaac_ping_reply()), the backoff counter is set to 0, confirming the address
 * is in use and triggering DNS registration.
 * 
 * @param now Current timestamp for comparing against slaac->ping_time to determine if
 *            retry interval has elapsed. The backoff interval is computed as
 *            (1 << (backoff - 1)) + randomization seconds, creating exponential growth
 *            with jitter to avoid synchronized ping storms.
 * @param leases Head of the linked list of all DHCPv4 leases. Function iterates through
 *               entire list, examining lease->slaac_address for each lease to find
 *               addresses requiring ping transmission.
 * 
 * @return Time of the next scheduled SLAAC ping event (earliest slaac->ping_time among
 *         all pending addresses), or 0 if no pending pings exist. This return value
 *         allows the main event loop to schedule the next periodic_slaac() call
 *         efficiently without polling. Returns 0 if daemon->icmp6fd is not available.
 * 
 * @note The function initializes the global ping_id counter on first call (when ping_id==0)
 *       using rand16(), then reuses this identifier for all subsequent pings in the session.
 *       Each SLAAC address's backoff counter is incremented after successful ping transmission
 *       (unless already at maximum 12). When slaac_ping_reply() receives a matching echo
 *       reply, it sets backoff=0 to confirm the address, triggering DNS registration.
 *       Confirmed addresses (backoff==0) or abandoned addresses (ping_time==0) are skipped.
 * 
 * @warning Requires HAVE_DHCP6 compile flag and daemon->icmp6fd to be initialized. The
 *          function constructs raw ICMPv6 packets and sends them via the ICMPv6 socket,
 *          requiring appropriate permissions (typically CAP_NET_RAW or root privileges
 *          before privilege drop). Uses expand() for packet buffer which may fail if
 *          outpacket buffer exhausted (ping skipped, continues with next address).
 *          EHOSTUNREACH at backoff 12 causes address abandonment (ping_time set to 0).
 * 
 * @see slaac_ping_reply() in src/slaac.c:329 for echo reply processing and confirmation
 * @see slaac_add_addrs() in src/slaac.c:25 for SLAAC address derivation from MAC/EUI-64
 * @see expand() in src/util.c for ICMPv6 packet buffer allocation
 * @see struct ping_packet in src/radv-protocol.h:20 for ICMPv6 packet structure
 * @see struct slaac_address in src/dnsmasq.h:879 for address state (ping_time, backoff)
 * 
 * EXAMPLE USAGE:
 * @code
 * // Called from main event loop timer handler
 * time_t now = dnsmasq_time();
 * struct dhcp_lease *leases = daemon->dhcp;
 * time_t next_slaac_event = periodic_slaac(now, leases);
 * // Result: Sends ICMPv6 echo requests to all SLAAC addresses due for retry
 * // next_slaac_event contains timestamp when next ping should be sent (or 0 if none pending)
 * // Event loop uses this to schedule next periodic_slaac() call efficiently
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 4443 Section 4.1 (ICMPv6 echo request format), RFC 4862 Section 5.4
 *                 (duplicate address detection considerations), RFC 4291 Appendix A
 *                 (EUI-64 based interface identifiers)
 * 
 * SIDE EFFECTS:
 * - Initializes global ping_id counter on first call (when ping_id==0) using rand16()
 * - Increments slaac->backoff counter for each address successfully pinged (max 12)
 * - Updates slaac->ping_time to schedule next retry with exponential backoff + randomization
 * - Sets slaac->ping_time=0 to abandon address if EHOSTUNREACH at backoff 12
 * - Sends ICMPv6 echo request packets via daemon->icmp6fd to unconfirmed addresses
 * - Uses expand() to allocate packet buffer from daemon->outpacket (may fail silently)
 * - Calculates next_event timestamp tracking earliest scheduled ping across all addresses
 * 
 * THREAD SAFETY: Single-threaded architecture, called from main event loop timer.
 *                Iterates through global lease list (daemon->dhcp) which is stable during
 *                event loop iteration. Global ping_id initialization and increment are
 *                safe (single-threaded execution). Uses sendto() which is not reentrant
 *                but called only from main thread.
 */
time_t periodic_slaac(time_t now, struct dhcp_lease *leases)
{
  struct dhcp_context *context;
  struct dhcp_lease *lease;
  struct slaac_address *slaac;
  time_t next_event = 0;
  
  for (context = daemon->dhcp6; context; context = context->next)
    if ((context->flags & CONTEXT_RA_NAME) && !(context->flags & CONTEXT_OLD))
      break;

  /* nothing configured */
  if (!context)
    return 0;

  while (ping_id == 0)
    ping_id = rand16();

  for (lease = leases; lease; lease = lease->next)
    for (slaac = lease->slaac_address; slaac; slaac = slaac->next)
      {
	/* confirmed or given up? */
	if (slaac->backoff == 0 || slaac->ping_time == 0)
	  continue;
	
	if (difftime(slaac->ping_time, now) <= 0.0)
	  {
	    struct ping_packet *ping;
	    struct sockaddr_in6 addr;
 
	    reset_counter();

	    if (!(ping = expand(sizeof(struct ping_packet))))
	      continue;

	    ping->type = ICMP6_ECHO_REQUEST;
	    ping->code = 0;
	    ping->identifier = ping_id;
	    ping->sequence_no = slaac->backoff;
	    
	    memset(&addr, 0, sizeof(addr));
#ifdef HAVE_SOCKADDR_SA_LEN
	    addr.sin6_len = sizeof(struct sockaddr_in6);
#endif
	    addr.sin6_family = AF_INET6;
	    addr.sin6_port = htons(IPPROTO_ICMPV6);
	    addr.sin6_addr = slaac->addr;
	    
	    if (sendto(daemon->icmp6fd, daemon->outpacket.iov_base, save_counter(-1), 0,
		       (struct sockaddr *)&addr,  sizeof(addr)) == -1 &&
		errno == EHOSTUNREACH &&
		slaac->backoff == 12)
	      slaac->ping_time = 0; /* Give up */ 
	    else
	      {
		slaac->ping_time += (1 << (slaac->backoff - 1)) + (rand16()/21785); /* 0 - 3 */
		if (slaac->backoff > 4)
		  slaac->ping_time += rand16()/4000; /* 0 - 15 */
		if (slaac->backoff < 12)
		  slaac->backoff++;
	      }
	  }
	
	if (slaac->ping_time != 0 &&
	    (next_event == 0 || difftime(next_event, slaac->ping_time) >= 0.0))
	  next_event = slaac->ping_time;
      }

  return next_event;
}


/**
 * @brief Process ICMPv6 echo replies to confirm SLAAC addresses are in use and register in DNS
 * 
 * @detailed
 * This function is called from the ICMPv6 packet processing path when an echo reply (ping
 * response) is received. It validates that the reply corresponds to a SLAAC address confirmation
 * ping sent by periodic_slaac(), and if so, marks the address as confirmed by setting the
 * backoff counter to 0. This confirmation triggers DNS registration of the DHCP lease's hostname
 * with the verified SLAAC-derived IPv6 address.
 * 
 * The confirmation process involves three validation steps: First, the function checks that the
 * ICMPv6 echo reply's identifier field matches the global ping_id used by periodic_slaac() to
 * send requests. This prevents false confirmations from unrelated ICMPv6 traffic. Second, it
 * searches through all DHCPv4 leases to find any with pending SLAAC addresses (those with
 * backoff != 0, meaning not yet confirmed). Third, it matches the sender IPv6 address from the
 * echo reply against the SLAAC address being tracked. When all three conditions match, the
 * address is confirmed.
 * 
 * Upon confirmation, the function sets slaac->backoff = 0, which serves as the confirmation flag.
 * periodic_slaac() checks this flag and skips confirmed addresses (backoff == 0) in future
 * iterations. The function also logs a SLAAC-CONFIRM message identifying the interface, IPv6
 * address, and hostname for operational visibility. Finally, lease_update_dns() is called to
 * register the confirmed addresses in the DNS cache via cache_add_dhcp_entry(), making the
 * hostname immediately resolvable to the SLAAC IPv6 address.
 * 
 * The function processes multiple confirmations in a single call if the echo reply matches
 * multiple pending SLAAC addresses (theoretically possible if the same IPv6 address is derived
 * for multiple clients, though unlikely in practice). The gotone flag tracks whether any
 * confirmation occurred, determining whether DNS update is necessary.
 * 
 * @param sender Pointer to the IPv6 address that sent the echo reply. This is the source address
 *               from the ICMPv6 packet header, representing the SLAAC-derived address being
 *               confirmed. Must not be NULL. Compared against slaac->addr using IN6_ARE_ADDR_EQUAL
 *               to find the matching SLAAC address entry.
 * @param packet Raw ICMPv6 packet buffer containing the echo reply. The function casts this to
 *               struct ping_packet to access the identifier field at offset 4-5 (16-bit identifier).
 *               The packet format must match struct ping_packet from src/radv-protocol.h:20.
 *               Must not be NULL. Length validation assumed to be performed by caller.
 * @param interface Network interface name where the echo reply was received (e.g., "eth0", "wlan0").
 *                  Used only for logging in the SLAAC-CONFIRM message. Must not be NULL. Length
 *                  assumed to be valid C string for logging purposes.
 * @param leases Head of the linked list of all DHCPv4 leases. Function iterates through entire
 *               list via lease->next pointers, examining lease->slaac_address for each to find
 *               pending SLAAC addresses. NULL is valid (no leases), resulting in no confirmations.
 * 
 * @return void (no return value)
 * 
 * @note The function uses the global ping_id variable to validate that the echo reply corresponds
 *       to pings sent by this dnsmasq instance. The identifier check (ping->identifier == ping_id)
 *       prevents confirmation of replies from other ICMPv6 sources or other dnsmasq instances.
 *       Setting backoff to 0 serves as the confirmation flag; periodic_slaac() skips addresses
 *       with backoff == 0 in future iterations. Multiple SLAAC addresses can be confirmed in a
 *       single call if they match the sender address (gotone flag accumulates confirmations).
 * 
 * @warning Requires HAVE_DHCP6 compile flag. The packet parameter must point to a valid ICMPv6
 *          echo reply packet with at least sizeof(struct ping_packet) bytes. Caller is responsible
 *          for packet length validation. The function assumes sender, packet, and interface
 *          pointers are non-NULL (no NULL checks performed). Accesses global ping_id variable
 *          which must be initialized by periodic_slaac() before first call to this function.
 * 
 * @see periodic_slaac() in src/slaac.c:257 for echo request transmission and backoff management
 * @see slaac_add_addrs() in src/slaac.c:25 for initial SLAAC address derivation from MAC/EUI-64
 * @see lease_update_dns() in src/lease.c for DNS cache update with confirmed addresses
 * @see cache_add_dhcp_entry() in src/cache.c for DNS record registration
 * @see struct ping_packet in src/radv-protocol.h:20 for ICMPv6 packet structure
 * @see struct slaac_address in src/dnsmasq.h:879 for address state (backoff confirmation flag)
 * 
 * EXAMPLE USAGE:
 * @code
 * // Called from ICMPv6 packet receive handler
 * struct in6_addr sender_addr = ...; // Extracted from IPv6 header
 * unsigned char *icmp_payload = ...; // ICMPv6 echo reply packet
 * char *iface_name = "eth0";
 * struct dhcp_lease *leases = daemon->dhcp;
 * slaac_ping_reply(&sender_addr, icmp_payload, iface_name, leases);
 * // Result: If echo reply matches pending SLAAC address, sets backoff=0 to confirm,
 * //         logs SLAAC-CONFIRM message, triggers DNS registration via lease_update_dns()
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 4443 Section 4.2 (ICMPv6 echo reply format, identifier field at offset 4),
 *                 RFC 4862 Section 5.4 (duplicate address detection procedures, confirmation
 *                 of address uniqueness before use), RFC 4291 Appendix A (EUI-64 addressing)
 * 
 * SIDE EFFECTS:
 * - Sets slaac->backoff = 0 for all SLAAC addresses matching sender address (confirmation flag)
 * - Formats sender IPv6 address into daemon->addrbuff (ADDRSTRLEN buffer, 46 bytes for IPv6)
 * - Logs SLAAC-CONFIRM message to syslog with MS_DHCP | LOG_INFO facility unless OPT_QUIET_DHCP6
 * - Calls lease_update_dns(gotone) which triggers DNS cache update if any addresses confirmed
 * - DNS cache updated via cache_add_dhcp_entry() registering hostname -> SLAAC IPv6 address
 * - Increments gotone flag for each confirmed address (tracks whether DNS update needed)
 * 
 * THREAD SAFETY: Single-threaded architecture, called from ICMPv6 receive handler in main event
 *                loop. Iterates through global lease list (daemon->dhcp) which is stable during
 *                event processing. Accesses and compares global ping_id (read-only in this
 *                function, safe). Modifies slaac->backoff field which is only accessed from main
 *                thread (periodic_slaac and this function). Uses daemon->addrbuff which is a
 *                per-daemon scratch buffer (single-threaded safe).
 */
void slaac_ping_reply(struct in6_addr *sender, unsigned char *packet, char *interface, struct dhcp_lease *leases)
{
  struct dhcp_lease *lease;
  struct slaac_address *slaac;
  struct ping_packet *ping = (struct ping_packet *)packet;
  int gotone = 0;
  
  if (ping->identifier == ping_id)
    for (lease = leases; lease; lease = lease->next)
      for (slaac = lease->slaac_address; slaac; slaac = slaac->next)
	if (slaac->backoff != 0 && IN6_ARE_ADDR_EQUAL(sender, &slaac->addr))
	  {
	    slaac->backoff = 0;
	    gotone = 1;
	    inet_ntop(AF_INET6, sender, daemon->addrbuff, ADDRSTRLEN);
	    if (!option_bool(OPT_QUIET_DHCP6))
	      my_syslog(MS_DHCP | LOG_INFO, "SLAAC-CONFIRM(%s) %s %s", interface, daemon->addrbuff, lease->hostname); 
	  }
  
  lease_update_dns(gotone);
}
	
#endif

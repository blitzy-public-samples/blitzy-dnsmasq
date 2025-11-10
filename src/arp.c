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
 * @file arp.c
 * @brief ARP/Neighbor cache management for MAC address lookup and network topology tracking
 * 
 * DETAILED PURPOSE:
 * This module implements an internal ARP (Address Resolution Protocol) and neighbor cache
 * that maintains mappings between IP addresses (IPv4 and IPv6) and hardware MAC addresses.
 * The cache is populated by reading the kernel's ARP/neighbor tables and provides MAC
 * address lookup services primarily for DHCP operations including address-in-use testing,
 * lease management, and client identification. The module also integrates with the external
 * script execution system to notify administrators of network topology changes when new
 * devices appear or existing devices disappear from the network.
 * 
 * KEY RESPONSIBILITIES:
 * - filter_mac(): Callback function for ARP table enumeration that updates internal cache
 * - find_mac(): Public API for MAC address lookup by IP address with kernel cache refresh
 * - do_arp_script_run(): Process ARP records and trigger script notifications for topology changes
 * - Maintain internal arp_record linked list with periodic kernel ARP table synchronization
 * - Support both IPv4 (AF_INET) and IPv6 (AF_INET6) address families
 * 
 * DEPENDENCIES:
 * Includes: dnsmasq.h (core data structures, union all_addr, ACTION_ARP constants, queue_arp())
 * Called by: src/dhcp.c (DHCP lease management, address conflict detection)
 * Calls: iface_enumerate() for kernel ARP table retrieval, queue_arp() for script notifications
 * 
 * DATA STRUCTURES:
 * - struct arp_record: Internal cache entry linking IP address to MAC address (line 27-33)
 *   Contains: hwlen, status, family, hwaddr[DHCP_CHADDR_MAX], addr (union all_addr), next pointer
 * - Static variables: arps (active cache list), old (previous cache list), freelist (reusable records)
 * 
 * COMPILE-TIME OPTIONS:
 * - HAVE_SCRIPT: Enables external script execution for ARP change notifications
 * - Platform detection affects iface_enumerate() implementation (Linux vs BSD ARP table access)
 * 
 * THREADING/CONCURRENCY:
 * Single-process event-driven model - all functions called from main event loop context.
 * No thread synchronization required as dnsmasq uses single-threaded architecture.
 * 
 * @copyright Copyright (c) 2000-2025 Simon Kelley
 * @license GPL-2.0-or-later
 */

#include "dnsmasq.h"

/**
 * @brief Time interval in seconds between forced reloads of ARP cache from kernel
 * 
 * The kernel ARP/neighbor table is re-read periodically to detect network topology
 * changes even when no explicit find_mac() calls are made. This ensures the internal
 * cache remains synchronized with actual network state.
 */
#define INTERVAL 90

/**
 * @brief ARP record status: Initial mark state for existing entries before cache reload
 */
#define ARP_MARK  0

/**
 * @brief ARP record status: Confirmed - entry found in kernel cache during reload
 */
#define ARP_FOUND 1

/**
 * @brief ARP record status: Newly created - entry added during current cache reload
 */
#define ARP_NEW   2

/**
 * @brief ARP record status: Empty - IP address known but no MAC address available
 */
#define ARP_EMPTY 3

/**
 * @struct arp_record
 * @brief Internal cache entry mapping IP address to hardware MAC address
 * 
 * Maintains a single ARP/neighbor cache entry recording the relationship between
 * a network layer address (IPv4 or IPv6) and a data link layer hardware address
 * (typically Ethernet MAC address). Used for DHCP address conflict detection,
 * client identification, and network topology change detection.
 * 
 * LIFECYCLE:
 * Creation: Allocated via whine_malloc() when new IP-to-MAC mapping discovered in kernel cache
 * Initialization: Populated by filter_mac() callback during iface_enumerate() traversal
 * Destruction: Entries not confirmed during cache reload are moved to freelist for reuse
 * Ownership: Module-internal linked list (arps), managed by filter_mac() and do_arp_script_run()
 * 
 * MEMORY LAYOUT:
 * Size: ~40 bytes (16-byte hwaddr + union all_addr + metadata + pointer)
 * Alignment: Natural alignment for struct members
 * 
 * USAGE PATTERNS:
 * Linked list via 'next' pointer, traversed for MAC address lookups and cache synchronization.
 * Status field transitions: ARP_MARK → ARP_FOUND (confirmed) or ARP_MARK → freelist (deleted)
 *                           ARP_EMPTY → ARP_NEW (MAC address discovered)
 */
struct arp_record {
  unsigned short hwlen;   /**< Hardware address length in bytes (typically 6 for Ethernet) */
  unsigned short status;  /**< Cache entry status: ARP_MARK, ARP_FOUND, ARP_NEW, or ARP_EMPTY */
  int family;             /**< Address family: AF_INET (IPv4) or AF_INET6 (IPv6) */
  unsigned char hwaddr[DHCP_CHADDR_MAX]; /**< Hardware MAC address, max 16 bytes per DHCP spec */
  union all_addr addr;    /**< Network address (addr4 for IPv4, addr6 for IPv6) */
  struct arp_record *next; /**< Next entry in linked list (arps, old, or freelist) */
};

static struct arp_record *arps = NULL, *old = NULL, *freelist = NULL;
static time_t last = 0;

/**
 * @brief Callback function for ARP/neighbor table enumeration that updates internal cache
 * 
 * @detailed This function is invoked by iface_enumerate() for each entry in the kernel's
 * ARP (IPv4) or neighbor (IPv6) table. It updates the internal arp_record cache by:
 * 1) Searching for existing entries matching the IP address
 * 2) Updating existing entries' MAC addresses and marking them as confirmed (ARP_FOUND)
 * 3) Creating new arp_record entries for previously unknown IP-to-MAC mappings
 * 4) Transitioning ARP_EMPTY entries to ARP_NEW when MAC address becomes available
 * 
 * The function implements cache coherency by marking confirmed entries ARP_FOUND while
 * unmarked entries (status == ARP_MARK) will be moved to the freelist by do_arp_script_run().
 * Entries are allocated from the freelist when available, or via whine_malloc() for new
 * allocations, providing memory reuse for stable network topologies.
 * 
 * @param family Address family: AF_INET (IPv4) or AF_INET6 (IPv6)
 * @param addrp Pointer to network address: struct in_addr* for IPv4, struct in6_addr* for IPv6
 * @param mac Pointer to hardware MAC address bytes
 * @param maclen Length of MAC address in bytes (typically 6 for Ethernet, must be ≤ DHCP_CHADDR_MAX)
 * @param parmv User parameter passed to iface_enumerate() (unused in this callback)
 * 
 * @return 0 on success, 1 on error (MAC address too long or allocation failure)
 * @retval 0 Entry successfully added or updated in cache
 * @retval 1 MAC address length exceeds DHCP_CHADDR_MAX or memory allocation failed
 * 
 * @note This is a static function not exported from the module
 * @warning MAC addresses longer than DHCP_CHADDR_MAX (16 bytes) are rejected
 * 
 * @see find_mac() which triggers cache reload and uses this callback
 * @see do_arp_script_run() which processes cache entries and moves unmarked entries to freelist
 * 
 * EXAMPLE USAGE:
 * @code
 * // Called internally by iface_enumerate() during ARP cache refresh
 * // iface_enumerate(AF_UNSPEC, NULL, filter_mac, NULL);
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (internal cache management function)
 * SIDE EFFECTS: Modifies global arps linked list, may allocate memory, updates arp_record status fields
 * THREAD SAFETY: Single-threaded architecture - called from main event loop context only
 */
static int filter_mac(int family, void *addrp, char *mac, size_t maclen, void *parmv)
{
  struct arp_record *arp;

  (void)parmv;

  if (maclen > DHCP_CHADDR_MAX)
    return 1;

  /* Look for existing entry */
  for (arp = arps; arp; arp = arp->next)
    {
      if (family != arp->family || arp->status == ARP_NEW)
	continue;
      
      if (family == AF_INET)
	{
	  if (arp->addr.addr4.s_addr != ((struct in_addr *)addrp)->s_addr)
	    continue;
	}
      else
	{
	  if (!IN6_ARE_ADDR_EQUAL(&arp->addr.addr6, (struct in6_addr *)addrp))
	    continue;
	}

      if (arp->status == ARP_EMPTY)
	{
	  /* existing address, was negative. */
	  arp->status = ARP_NEW;
	  arp->hwlen = maclen;
	  memcpy(arp->hwaddr, mac, maclen);
	}
      else if (arp->hwlen == maclen && memcmp(arp->hwaddr, mac, maclen) == 0)
	/* Existing entry matches - confirm. */
	arp->status = ARP_FOUND;
      else
	continue;
      
      break;
    }

  if (!arp)
    {
      /* New entry */
      if (freelist)
	{
	  arp = freelist;
	  freelist = freelist->next;
	}
      else if (!(arp = whine_malloc(sizeof(struct arp_record))))
	return 1;
      
      arp->next = arps;
      arps = arp;
      arp->status = ARP_NEW;
      arp->hwlen = maclen;
      arp->family = family;
      memcpy(arp->hwaddr, mac, maclen);
      if (family == AF_INET)
	arp->addr.addr4.s_addr = ((struct in_addr *)addrp)->s_addr;
      else
	memcpy(&arp->addr.addr6, addrp, IN6ADDRSZ);
    }
  
  return 1;
}

/**
 * @brief Look up hardware MAC address for given IP address with kernel cache refresh
 * 
 * @detailed This is the primary public API for MAC address lookup, used extensively by
 * DHCP code for address-in-use testing and client identification. The function implements
 * a two-tier lookup strategy:
 * 1) First consults the internal arp_record cache if database age < INTERVAL (90 seconds)
 * 2) If not found or cache stale, triggers kernel ARP table reload via iface_enumerate()
 * 
 * The "lazy" mode controls negative caching behavior. In lazy mode, the function caches
 * the absence of ARP entries (ARP_EMPTY records) to avoid repeated kernel queries for
 * non-existent mappings. In non-lazy mode, only positive ARP entries (with valid MAC
 * addresses) are accepted from cache, forcing kernel re-query for empty entries.
 * 
 * Cache refresh process (when INTERVAL expired or cache miss):
 * 1) Mark all non-empty cache entries with ARP_MARK status
 * 2) Call iface_enumerate() which invokes filter_mac() for each kernel ARP entry
 * 3) filter_mac() updates existing entries to ARP_FOUND and creates ARP_NEW entries
 * 4) Move all still-marked (ARP_MARK) entries to 'old' list for script notification
 * 5) Retry lookup in refreshed cache via "goto again" control flow
 * 
 * If no MAC address found after kernel refresh, creates ARP_EMPTY entry to cache negative
 * result and prevent repeated kernel queries for same address.
 * 
 * @param addr Pointer to union mysockaddr containing IP address to lookup (IPv4 or IPv6).
 *             If NULL, function only refreshes cache without performing lookup.
 * @param mac Output buffer for MAC address. If non-NULL and MAC found, receives hwlen bytes.
 *            Buffer must be at least DHCP_CHADDR_MAX bytes. May be NULL if only hwlen needed.
 * @param lazy If non-zero, accept ARP_EMPTY (negative) cache entries. If zero, require
 *             positive MAC address or force kernel refresh for empty entries.
 * @param now Current timestamp for cache age comparison (from dnsmasq_time() or time(0))
 * 
 * @return Hardware address length in bytes (typically 6 for Ethernet), or 0 if not found
 * @retval >0 MAC address found, length returned, mac buffer filled if mac != NULL
 * @retval 0 No MAC address available for given IP address (not in kernel ARP table)
 * 
 * @note Cache refresh occurs at most once per call when cache age >= INTERVAL or on first call
 * @warning mac buffer must be at least DHCP_CHADDR_MAX bytes when non-NULL
 * 
 * @see filter_mac() callback used during iface_enumerate() for cache population
 * @see do_arp_script_run() processes cache changes and moves old entries to freelist
 * 
 * EXAMPLE USAGE:
 * @code
 * union mysockaddr client_addr;
 * unsigned char client_mac[DHCP_CHADDR_MAX];
 * time_t now = dnsmasq_time();
 * 
 * // Lookup MAC for DHCP client address-in-use test
 * client_addr.in.sin_family = AF_INET;
 * client_addr.in.sin_addr.s_addr = inet_addr("192.168.1.100");
 * int hwlen = find_mac(&client_addr, client_mac, 0, now);
 * if (hwlen > 0) {
 *   // MAC address found, IP is in use
 * }
 * 
 * // Cache refresh only (no specific lookup)
 * find_mac(NULL, NULL, 0, now);
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (ARP lookup is implementation-specific, uses platform ARP/neighbor table)
 * SIDE EFFECTS: May trigger kernel ARP table enumeration via iface_enumerate(), updates global
 *               arps/old/freelist linked lists, allocates arp_record entries, updates last timestamp
 * THREAD SAFETY: Single-threaded architecture - must be called from main event loop only
 */
int find_mac(union mysockaddr *addr, unsigned char *mac, int lazy, time_t now)
{
  struct arp_record *arp, *tmp, **up;
  int updated = 0;

 again:
  
  /* If the database is less then INTERVAL old, look in there */
  if (difftime(now, last) < INTERVAL)
    {
      /* addr == NULL -> just make cache up-to-date */
      if (!addr)
	return 0;

      for (arp = arps; arp; arp = arp->next)
	{
	  if (addr->sa.sa_family != arp->family)
	    continue;
	    
	  if (arp->family == AF_INET &&
	      arp->addr.addr4.s_addr != addr->in.sin_addr.s_addr)
	    continue;
	    
	  if (arp->family == AF_INET6 && 
	      !IN6_ARE_ADDR_EQUAL(&arp->addr.addr6, &addr->in6.sin6_addr))
	    continue;
	  
	  /* Only accept positive entries unless in lazy mode. */
	  if (arp->status != ARP_EMPTY || lazy || updated)
	    {
	      if (mac && arp->hwlen != 0)
		memcpy(mac, arp->hwaddr, arp->hwlen);
	      return arp->hwlen;
	    }
	}
    }

  /* Not found, try the kernel */
  if (!updated)
     {
       updated = 1;
       last = now;

       /* Mark all non-negative entries */
       for (arp = arps; arp; arp = arp->next)
	 if (arp->status != ARP_EMPTY)
	   arp->status = ARP_MARK;
       
       iface_enumerate(AF_UNSPEC, NULL, (callback_t){.af_unspec=filter_mac});
       
       /* Remove all unconfirmed entries to old list. */
       for (arp = arps, up = &arps; arp; arp = tmp)
	 {
	   tmp = arp->next;
	   
	   if (arp->status == ARP_MARK)
	     {
	       *up = arp->next;
	       arp->next = old;
	       old = arp;
	     }
	   else
	     up = &arp->next;
	 }

       goto again;
     }

  /* record failure, so we don't consult the kernel each time
     we're asked for this address */
  if (freelist)
    {
      arp = freelist;
      freelist = freelist->next;
    }
  else
    arp = whine_malloc(sizeof(struct arp_record));
  
  if (arp)
    {      
      arp->next = arps;
      arps = arp;
      arp->status = ARP_EMPTY;
      arp->family = addr->sa.sa_family;
      arp->hwlen = 0;

      if (addr->sa.sa_family == AF_INET)
	arp->addr.addr4.s_addr = addr->in.sin_addr.s_addr;
      else
	memcpy(&arp->addr.addr6, &addr->in6.sin6_addr, IN6ADDRSZ);
    }
	  
   return 0;
}

/**
 * @brief Process ARP cache changes and trigger external script notifications for topology changes
 * 
 * @detailed This function processes the 'old' and 'arps' lists to identify network topology
 * changes and notify external scripts via the queue_arp() interface. It performs two primary
 * operations in an incremental fashion, processing one entry per invocation:
 * 
 * 1) DELETION NOTIFICATION (old list processing):
 *    Entries moved to 'old' list by find_mac() represent IP-to-MAC mappings that existed
 *    in previous cache refresh but were not confirmed in latest kernel ARP table reload.
 *    These are considered deleted/disappeared devices. For each entry in 'old' list,
 *    queue_arp() is called with ACTION_ARP_DEL to notify scripts, then entry is moved
 *    to freelist for memory reuse. Returns 1 to indicate work remains.
 * 
 * 2) NEW DEVICE NOTIFICATION (arps list processing):
 *    Entries marked ARP_NEW in 'arps' list represent newly discovered IP-to-MAC mappings
 *    that appeared in latest kernel refresh but were not present before. For each ARP_NEW
 *    entry, queue_arp() is called with ACTION_ARP to notify scripts of new device arrival,
 *    then entry status is changed to ARP_FOUND. Returns 1 when ARP_NEW entry is processed.
 * 
 * This function is designed to be called repeatedly from the main event loop. Each invocation
 * processes at most one entry (either one deletion from 'old' list, or one ARP_NEW entry from
 * 'arps' list), returning 1 if more work remains or 0 when all notifications complete. This
 * incremental design prevents blocking the event loop during large topology changes.
 * 
 * @return 1 if more entries need processing (call again), 0 if all notifications complete
 * @retval 1 Processed one deletion from 'old' list, or one ARP_NEW from 'arps' list
 * @retval 0 Both 'old' list empty and no ARP_NEW entries remain in 'arps' list
 * 
 * @note Function returns 1 after processing single entry to allow event loop to handle other events
 * @warning Only processes entries when HAVE_SCRIPT compile flag enabled; returns immediately otherwise
 * 
 * @see find_mac() populates 'old' list with unmarked entries during cache refresh
 * @see filter_mac() marks entries as ARP_NEW when creating new cache records
 * @see queue_arp() in src/helper.c for actual script execution queueing
 * 
 * EXAMPLE USAGE:
 * @code
 * // Called repeatedly by main event loop after ARP cache refresh
 * find_mac(NULL, NULL, 0, dnsmasq_time());  // Refresh cache
 * while (do_arp_script_run())  // Process all changes incrementally
 *   ;  // Each call handles one entry
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (script notification is dnsmasq-specific extension)
 * SIDE EFFECTS: Moves 'old' list entries to freelist one at a time, changes ARP_NEW entries to
 *               ARP_FOUND status, queues script execution events via queue_arp(), modifies
 *               global arps/old/freelist pointers
 * THREAD SAFETY: Single-threaded architecture - must be called from main event loop only
 */
int do_arp_script_run(void)
{
  struct arp_record *arp;
  
  /* Notify any which went, then move to free list */
  if (old)
    {
#ifdef HAVE_SCRIPT
      if (option_bool(OPT_SCRIPT_ARP))
	queue_arp(ACTION_ARP_DEL, old->hwaddr, old->hwlen, old->family, &old->addr);
#endif
      arp = old;
      old = arp->next;
      arp->next = freelist;
      freelist = arp;
      return 1;
    }

  for (arp = arps; arp; arp = arp->next)
    if (arp->status == ARP_NEW)
      {
#ifdef HAVE_SCRIPT
	if (option_bool(OPT_SCRIPT_ARP))
	  queue_arp(ACTION_ARP, arp->hwaddr, arp->hwlen, arp->family, &arp->addr);
#endif
	arp->status = ARP_FOUND;
	return 1;
      }

  return 0;
}

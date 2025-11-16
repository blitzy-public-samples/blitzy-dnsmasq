/* tables.c is Copyright (c) 2014 Sven Falempin  All Rights Reserved.

   Author's email: sfalempin@citypassenger.com 

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
 * @file tables.c
 * @brief BSD Packet Filter (PF) table integration for DNS-based firewall rules
 * 
 * DETAILED PURPOSE:
 * This BSD-specific module integrates dnsmasq with the BSD Packet Filter (PF) firewall
 * system by adding resolved IP addresses from DNS queries to named PF tables. This enables
 * dynamic firewall rules based on domain names, allowing administrators to create firewall
 * policies that automatically adapt as IP addresses for domains change. The module provides
 * a bridge between DNS resolution in forward.c and PF table manipulation via ioctl interface.
 * 
 * KEY RESPONSIBILITIES:
 * - Initialize PF device interface (/dev/pf) for table manipulation (ipset_init)
 * - Create PF tables if they don't exist with persistent flag (add_to_ipset via DIOCRADDTABLES)
 * - Add resolved IPv4 and IPv6 addresses to named PF tables (add_to_ipset via DIOCRADDADDRS)
 * - Remove addresses from PF tables when needed (add_to_ipset via DIOCRDELADDRS)
 * - Provide error translation for PF-specific error codes (pfr_strerror)
 * 
 * DEPENDENCIES:
 * Includes: dnsmasq.h (core data structures including union all_addr), <net/pfvar.h> (PF API),
 *           <sys/ioctl.h> (ioctl system calls), standard BSD network headers
 * Called by: forward.c DNS query processing when ipset configuration is active
 * Calls: open(2) for /dev/pf access, ioctl(2) for PF table operations, my_syslog for logging
 * 
 * DATA STRUCTURES:
 * - struct pfr_table: PF table descriptor with name and flags (line 70)
 * - struct pfr_addr: PF address entry with address family and IP address (line 68)
 * - struct pfioc_table: ioctl structure for table operations (line 69)
 * - union all_addr: dnsmasq IP address union from dnsmasq.h (parameter to add_to_ipset)
 * 
 * COMPILE-TIME OPTIONS:
 * - HAVE_BSD_IPSET: Entire module compiled only when this flag is defined (line 21)
 *   This flag is set for FreeBSD, OpenBSD, NetBSD, and other BSD systems with PF support
 * 
 * THREADING/CONCURRENCY:
 * Single-process event-driven model - all PF operations execute synchronously in main event loop.
 * The static file descriptor 'dev' maintains persistent connection to /dev/pf across multiple
 * table operations. No locking required as dnsmasq uses single-threaded architecture.
 * 
 * PF TABLE ARCHITECTURE:
 * BSD Packet Filter tables are kernel-maintained sets of IP addresses that can be referenced
 * in pf.conf firewall rules. Tables support both IPv4 and IPv6 addresses and allow dynamic
 * modification without reloading the entire ruleset. Dnsmasq creates tables with the
 * PFR_TFLAG_PERSIST flag, ensuring they persist even if no rules reference them. Tables are
 * identified by name (max PF_TABLE_NAME_SIZE characters) and addresses are added/removed
 * via DIOCRADDADDRS/DIOCRDELADDRS ioctl operations.
 * 
 * USE CASES ON BSD SYSTEMS:
 * - Block advertising/tracking domains: Resolve ad server domains and add IPs to blocked table
 * - Implement domain-based access control: Allow/deny traffic based on DNS resolution
 * - Create dynamic VPN routing: Route specific domains through VPN interface
 * - Enforce parental controls: Block adult content domains at firewall level
 * - Implement geo-blocking: Block or allow traffic based on domain-to-IP mapping
 * 
 * EXAMPLE PF.CONF INTEGRATION:
 * @code
 * # In /etc/pf.conf, define table and rule
 * table <blocked_domains> persist
 * block drop quick from any to <blocked_domains>
 * 
 * # In dnsmasq.conf, configure domain-to-table mapping
 * ipset=/doubleclick.net/blocked_domains
 * @endcode
 * 
 * @see pf.conf(5) - PF configuration file format and table syntax
 * @see pfctl(8) - PF control program for managing tables and rulesets
 * @see ioctl(2) - Device control operations for PF interface
 * @see forward.c - DNS forwarding logic that invokes add_to_ipset after resolution
 * 
 * @copyright Copyright (c) 2014 Sven Falempin, 2000-2025 Simon Kelley
 * @license GPL-2.0-or-later
 */

#include "dnsmasq.h"

#if defined(HAVE_BSD_IPSET)

#include <string.h>

#include <sys/types.h>
#include <sys/ioctl.h>

#include <net/if.h>
#include <netinet/in.h>
#include <net/pfvar.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>

#define UNUSED(x) (void)(x)

static char *pf_device = "/dev/pf";
static int dev = -1;

/**
 * @brief Translate PF-specific error codes to human-readable error messages
 * 
 * @detailed Converts errno values returned by PF ioctl operations to descriptive error
 * strings. PF operations can return standard POSIX error codes, but ESRCH and ENOENT have
 * PF-specific meanings related to table and ruleset existence. This function provides
 * context-appropriate error messages for logging and debugging PF table operations. For
 * unrecognized error codes, falls back to standard strerror() system function.
 * 
 * @param errnum Error code from errno after failed PF ioctl operation
 * 
 * @return Static string describing the error condition
 * @retval "Table does not exist" When errnum is ESRCH (table name not found in PF)
 * @retval "Anchor or Ruleset does not exist" When errnum is ENOENT (anchor reference invalid)
 * @retval strerror(errnum) For all other error codes (standard POSIX errors)
 * 
 * @note Return value is a pointer to static string storage and must not be freed by caller.
 *       String content is valid until next call to strerror() for non-PF error codes.
 * 
 * @warning Do not modify the returned string - it points to read-only static storage.
 * 
 * @see strerror(3) - Standard error code to string conversion
 * @see ioctl(2) - System call that generates these error codes
 * @see pfctl(8) - PF control utility that can also report these errors
 * 
 * EXAMPLE USAGE:
 * @code
 * if (ioctl(dev, DIOCRADDTABLES, &io) == -1) {
 *     my_syslog(LOG_ERR, "PF error: %s", pfr_strerror(errno));
 * }
 * @endcode
 * 
 * PF ERROR CODE MEANINGS:
 * ESRCH - Table name specified in pfr_table.pfrt_name does not exist in kernel
 * ENOENT - Referenced anchor or parent ruleset is not present in PF configuration
 * 
 * SIDE EFFECTS: None - pure function with no state modification
 * THREAD SAFETY: Thread-safe for PF-specific codes; standard strerror() behavior otherwise
 */
static char *pfr_strerror(int errnum)
{
  switch (errnum) 
    {
    case ESRCH:
      return "Table does not exist";
    case ENOENT:
      return "Anchor or Ruleset does not exist";
    default:
      return strerror(errnum);
    }
}


/**
 * @brief Initialize PF device interface for table manipulation operations
 * 
 * @detailed Opens /dev/pf device file with read-write access to enable subsequent ioctl
 * operations for PF table manipulation. The device file descriptor is stored in the static
 * 'dev' variable for use by add_to_ipset() throughout daemon lifetime. This function must
 * be called during dnsmasq initialization before any DNS queries attempt to populate PF
 * tables. Failure to open /dev/pf is treated as fatal because PF integration is explicitly
 * configured and inability to access the device indicates a system configuration problem.
 * 
 * @return void - Function does not return on failure
 * 
 * @note This function terminates the process on failure via die() rather than returning
 *       error status. This design reflects that PF initialization failure during startup
 *       should prevent daemon operation rather than silently disabling PF integration.
 * 
 * @warning Requires root privileges or appropriate file permissions on /dev/pf (typically
 *          root:wheel with mode 0600 on BSD systems). Must be called before privilege drop
 *          in dnsmasq startup sequence, after port binding but before main event loop.
 * 
 * @see open(2) - System call for opening device files
 * @see die() - dnsmasq fatal error handler that logs and terminates
 * @see add_to_ipset() - Function that uses the opened device descriptor
 * @see dnsmasq.c:main() - Initialization sequence that calls ipset_init()
 * 
 * EXAMPLE USAGE:
 * @code
 * // In dnsmasq startup sequence (dnsmasq.c)
 * if (daemon->options & OPT_IPSET) {
 *     ipset_init();  // Opens /dev/pf for PF operations
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: N/A - BSD-specific system interface
 * 
 * SIDE EFFECTS:
 * - Opens /dev/pf device file and stores descriptor in static 'dev' variable
 * - Terminates process via die() if device cannot be opened
 * - Logs error message via err() before terminating
 * 
 * THREAD SAFETY: Must be called from main thread during single-threaded initialization phase
 * 
 * DEVICE FILE REQUIREMENTS:
 * - Path: /dev/pf (standard location on FreeBSD, OpenBSD, NetBSD)
 * - Permissions: Typically 0600 root:wheel
 * - Device type: Character special device for PF kernel interface
 * - Opens with O_RDWR for both read and write ioctl operations
 * 
 * ERROR CONDITIONS:
 * - EACCES: Permission denied (insufficient privileges)
 * - ENOENT: /dev/pf does not exist (PF not loaded or supported)
 * - ENXIO: Device not configured (PF kernel module not loaded)
 */
void ipset_init(void) 
{
  dev = open( pf_device, O_RDWR);
  if (dev == -1)
    {
      err(1, "%s", pf_device);
      die (_("failed to access pf devices: %s"), NULL, EC_MISC);
    }
}

/**
 * @brief Add or remove an IP address from a BSD PF table
 * 
 * @detailed This function manipulates BSD Packet Filter (PF) tables by adding or removing
 *           IP addresses based on DNS resolution results. It creates the named PF table if
 *           it does not exist (with PERSIST flag), then performs the requested operation
 *           (add or remove) on the specified IP address. This enables dynamic firewall rule
 *           application based on DNS queries, supporting both IPv4 and IPv6 addresses.
 *           
 *           The implementation uses BSD PF ioctl interface with DIOCRADDTABLES to ensure
 *           the table exists and DIOCRADDADDRS/DIOCRDELADDRS to modify table contents.
 *           This is the BSD equivalent of Linux ipset functionality, integrated with
 *           dnsmasq's DNS forwarding to populate firewall tables automatically.
 * 
 * @param setname Table name in PF to modify (must be < PF_TABLE_NAME_SIZE characters)
 * @param ipaddr Pointer to union all_addr containing IPv4 or IPv6 address to add/remove.
 *               Must not be NULL. Structure defined in dnsmasq.h line 313.
 * @param flags Bit flags indicating address family: F_IPV6 for IPv6, 0 for IPv4.
 *              Additional flags from dnsmasq.h may be present but only F_IPV6 is checked.
 * @param remove Boolean flag: 0 to add address to table, non-zero to remove address from table
 * 
 * @return Number of addresses added or removed (typically 1 on success)
 * @retval >0 Number of addresses successfully added or removed
 * @retval -1 Error occurred: device not initialized, table name too long, ioctl failure
 * 
 * @note This function requires ipset_init() to be called first to open /dev/pf device
 * @note Table is created with PFR_TFLAG_PERSIST flag if it doesn't exist
 * @note Table name must be less than PF_TABLE_NAME_SIZE (typically 32 characters)
 * @note IPv4 addresses use /32 prefix (0x20), IPv6 addresses use /128 prefix (0x80)
 * @warning Table creation may succeed even if table already exists (idempotent operation)
 * @warning If device is not initialized (dev == -1), function logs error and returns -1
 * @warning Table name length validation uses strlen(); ensure setname is NULL-terminated
 * 
 * @see ipset_init() in tables.c - must be called before this function to open PF device
 * @see pfr_strerror() in tables.c:41 - translates PF-specific error codes
 * @see forward.c - DNS forwarding engine that calls this function with resolved addresses
 * 
 * EXAMPLE USAGE:
 * @code
 * // Add resolved IPv4 address to "blocked_domains" PF table
 * union all_addr addr;
 * addr.addr4.s_addr = inet_addr("93.184.216.34");
 * int result = add_to_ipset("blocked_domains", &addr, 0, 0);
 * if (result > 0)
 *   my_syslog(LOG_INFO, "Added address to PF table");
 * 
 * // Add resolved IPv6 address to "allowed_hosts" PF table
 * inet_pton(AF_INET6, "2606:2800:220:1:248:1893:25c8:1946", &addr.addr6);
 * result = add_to_ipset("allowed_hosts", &addr, F_IPV6, 0);
 * 
 * // Remove IPv4 address from table
 * result = add_to_ipset("blocked_domains", &addr, 0, 1);
 * @endcode
 * 
 * BSD PF INTEGRATION:
 * PF tables provide efficient IP address set matching for firewall rules. This function
 * enables domain-based firewall policies where DNS queries automatically populate PF tables
 * with resolved IP addresses. Example pf.conf rules:
 *   table <blocked_domains> persist
 *   block in quick from <blocked_domains> to any
 * 
 * RFC COMPLIANCE: N/A (BSD-specific PF mechanism, not a standard protocol)
 * 
 * SIDE EFFECTS:
 * - Modifies PF kernel table state via ioctl system calls
 * - Creates PF table if it does not exist (with PERSIST flag)
 * - Logs messages to syslog: table creation, address addition/removal, errors
 * - Sets errno on failure (ENAMETOOLONG if table name too long, or ioctl error codes)
 * 
 * THREAD SAFETY: Not thread-safe - uses global 'dev' file descriptor without locking.
 *                 Dnsmasq's single-threaded architecture ensures only one thread accesses
 *                 this function. Do not call from signal handlers or multiple threads.
 * 
 * PLATFORM SPECIFICITY: BSD systems only (FreeBSD, OpenBSD, NetBSD). Requires HAVE_BSD_IPSET
 *                       compile flag. Uses BSD-specific headers: net/pfvar.h, sys/ioctl.h.
 *                       See pf.conf(5) and pfctl(8) man pages for PF table concepts.
 */
int add_to_ipset(const char *setname, const union all_addr *ipaddr,
		 int flags, int remove)
{
  struct pfr_addr addr;
  struct pfioc_table io;
  struct pfr_table table;

  if (dev == -1) 
    {
      my_syslog(LOG_ERR, _("warning: no opened pf devices %s"), pf_device);
      return -1;
    }

  bzero(&table, sizeof(struct pfr_table));
  table.pfrt_flags |= PFR_TFLAG_PERSIST;
  if (strlen(setname) >= PF_TABLE_NAME_SIZE)
    {
      my_syslog(LOG_ERR, _("error: cannot use table name %s"), setname);
      errno = ENAMETOOLONG;
      return -1;
    }
  
  if (strlcpy(table.pfrt_name, setname,
	      sizeof(table.pfrt_name)) >= sizeof(table.pfrt_name)) 
    {
      my_syslog(LOG_ERR, _("error: cannot strlcpy table name %s"), setname);
      return -1;
    }
  
  bzero(&io, sizeof io);
  io.pfrio_flags = 0;
  io.pfrio_buffer = &table;
  io.pfrio_esize = sizeof(table);
  io.pfrio_size = 1;
  if (ioctl(dev, DIOCRADDTABLES, &io))
    {
      my_syslog(LOG_WARNING, _("IPset: error: %s"), pfr_strerror(errno));
      
      return -1;
    }
  
  table.pfrt_flags &= ~PFR_TFLAG_PERSIST;
  if (io.pfrio_nadd)
    my_syslog(LOG_INFO, _("info: table created"));
 
  bzero(&addr, sizeof(addr));

  if (flags & F_IPV6) 
    {
      addr.pfra_af = AF_INET6;
      addr.pfra_net = 0x80;
      memcpy(&(addr.pfra_ip6addr), ipaddr, sizeof(struct in6_addr));
    } 
  else 
    {
      addr.pfra_af = AF_INET;
      addr.pfra_net = 0x20;
      addr.pfra_ip4addr.s_addr = ipaddr->addr4.s_addr;
    }

  bzero(&io, sizeof(io));
  io.pfrio_flags = 0;
  io.pfrio_table = table;
  io.pfrio_buffer = &addr;
  io.pfrio_esize = sizeof(addr);
  io.pfrio_size = 1;
  if (ioctl(dev, ( remove ? DIOCRDELADDRS : DIOCRADDADDRS ), &io)) 
    {
      my_syslog(LOG_WARNING, _("warning: DIOCR%sADDRS: %s"), ( remove ? "DEL" : "ADD" ), pfr_strerror(errno));
      return -1;
    }
  
  my_syslog(LOG_INFO, _("%d addresses %s"),
            io.pfrio_nadd, ( remove ? "removed" : "added" ));
  
  return io.pfrio_nadd;
}


#endif

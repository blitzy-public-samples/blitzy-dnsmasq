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
 * @file lease.c
 * @brief DHCP lease database management with persistent storage and script integration
 * 
 * DETAILED PURPOSE:
 * This module manages the complete lifecycle of DHCP leases for both DHCPv4 and DHCPv6,
 * providing persistent storage, automatic DNS hostname registration, and integration with
 * external scripts for lease change events. The lease database maintains all active leases
 * with their associated client identifiers, hardware addresses, hostnames, and expiration
 * times, ensuring continuity across daemon restarts through disk persistence.
 * 
 * The lease management system serves as the authoritative record of all DHCP address
 * assignments, coordinating between the DHCP protocol handlers (dhcp.c, dhcp6.c), the
 * DNS cache (cache.c) for hostname resolution, and external automation scripts (helper.c)
 * for custom integration workflows.
 * 
 * KEY RESPONSIBILITIES:
 * - lease_init(): Initialize lease database from persistent storage on daemon startup
 * - lease_update_file(): Asynchronously persist lease changes to disk
 * - lease4_allocate(), lease6_allocate(): Allocate new lease structures
 * - lease_find_by_addr(): Locate leases by IP address for query and update operations
 * - lease_update_from_configs(): Apply static reservations from configuration
 * - lease_set_expires(), lease_set_hwaddr(), etc.: Modify lease attributes
 * - lease_prune(): Remove expired leases and trigger cleanup events
 * - rerun_scripts(): Execute lease-change scripts for add/old/del events
 * - lease_add_extradata(): Append vendor-specific data to leases
 * 
 * DEPENDENCIES:
 * Includes: dnsmasq.h (core structures: struct dhcp_lease, struct daemon, MAXLEASES limit)
 * Called by: dhcp.c (DHCPv4 packet processing), dhcp6.c (DHCPv6 packet processing),
 *            dnsmasq.c (initialization and periodic maintenance)
 * Calls: cache.c (cache_add_dhcp_entry for DNS integration),
 *        helper.c (queue_script for external script execution),
 *        network.c (indextoname for interface resolution),
 *        util.c (safe_malloc, whine_malloc for memory allocation)
 * 
 * DATA STRUCTURES:
 * - struct dhcp_lease: Core lease record (src/dnsmasq.h:856) containing client ID,
 *   hardware address, hostname, IP address (v4: addr, v6: addr6), expiration time,
 *   DHCP relay agent info, vendor class, and optional SLAAC addresses for DHCPv6
 * - static struct dhcp_lease *leases: Linked list of active leases in memory
 * - static struct dhcp_lease *old_leases: Leases read from disk at startup
 * 
 * COMPILE-TIME OPTIONS:
 * - HAVE_DHCP: Enables entire lease management system (required for this file)
 * - HAVE_DHCP6: Enables DHCPv6-specific lease fields (addr6, iaid, slaac_address)
 * - HAVE_BROKEN_RTC: Enables lease duration tracking for systems without real-time clock
 * - HAVE_SCRIPT: Enables external script execution on lease events
 * - HAVE_LUASCRIPT: Enables Lua script execution with reduced fork overhead
 * 
 * LEASE FILE FORMAT:
 * The lease database is persisted to /var/lib/misc/dnsmasq.leases (Linux default) with
 * one lease per line in space-separated format:
 * <expiry-time> <MAC-address> <IP-address> <hostname> <client-id>
 * 
 * DHCPv6 leases use format:
 * <expiry-time> <IAID> <IPv6-address> <hostname> <client-DUID>
 * 
 * Additional lines for vendor class and relay agent info:
 * vendorclass <IP-address> <hex-encoded-vendor-class>
 * agent-info <IP-address> <hex-encoded-agent-info>
 * 
 * SCRIPT INTEGRATION:
 * Lease change scripts are invoked with action and lease details:
 * Arguments: <action> <MAC-or-DUID> <IP-address> <hostname>
 * Actions: "add" (new lease), "old" (renewed lease), "del" (expired/released)
 * 
 * Environment variables passed to scripts:
 * - DNSMASQ_LEASE_LENGTH: Remaining lease duration in seconds
 * - DNSMASQ_LEASE_EXPIRES: Absolute expiration timestamp
 * - DNSMASQ_CLIENT_ID: Client identifier (hex-encoded)
 * - DNSMASQ_INTERFACE: Network interface name where lease originated
 * - DNSMASQ_REQUESTED_OPTIONS: DHCP options requested by client
 * - DNSMASQ_TAGS: Configuration tags matched for this client
 * - DNSMASQ_RELAY_ADDRESS: DHCP relay agent address (if relayed)
 * - DNSMASQ_VENDOR_CLASS: Vendor class identifier
 * 
 * DNS INTEGRATION:
 * When a DHCP lease is assigned with a hostname, lease_set_hostname() automatically
 * registers the hostname in the DNS cache via cache_add_dhcp_entry(), making the
 * DHCP client immediately resolvable by name without manual DNS configuration.
 * Lease expiration triggers cache entry removal to prevent stale DNS records.
 * 
 * ASYNCHRONOUS I/O:
 * Lease file writes use asynchronous patterns to prevent blocking the main event loop.
 * The file_dirty flag marks that lease state has changed, and lease_update_file() is
 * called periodically from the main loop to persist changes without blocking DHCP
 * packet processing. This ensures responsive DHCP service even during disk I/O delays.
 * 
 * THREADING/CONCURRENCY:
 * Single-threaded architecture with no locking required. All lease operations occur
 * in the main event loop context. Script execution uses fork-based helper processes
 * managed by helper.c, ensuring scripts run asynchronously without blocking.
 * 
 * @copyright Copyright (c) 2000-2025 Simon Kelley
 * @license GPL-2.0-or-later
 */

#include "dnsmasq.h"
#ifdef HAVE_DHCP

static struct dhcp_lease *leases = NULL, *old_leases = NULL;
static int dns_dirty, file_dirty, leases_left;

/**
 * @brief Parse lease database from file and populate in-memory lease structures
 * 
 * @detailed Reads lease entries from the persistent lease file, parsing both DHCPv4
 * and DHCPv6 lease records along with associated metadata (vendor class, relay agent
 * info, DUID). Each lease line is parsed into struct dhcp_lease and added to the
 * old_leases linked list for subsequent processing by lease_init(). The function
 * handles multiple lease formats including standard DHCPv4 leases, DHCPv6 leases
 * with IAID and DUID, and auxiliary records for vendor class and agent information.
 * 
 * @param now Current time for lease expiration calculations
 * @param leasestream Open FILE pointer to lease database (typically /var/lib/misc/dnsmasq.leases)
 * 
 * @return 1 on successful parse completion, 0 on critical parse error (DUID parse failure)
 * @retval 1 Lease file parsed successfully, all valid leases loaded into old_leases
 * @retval 0 Critical parse error encountered (DUID hex decode failure)
 * 
 * @note Invalid lease lines are logged and skipped rather than causing parse failure
 * @warning Lease file format errors are logged to syslog with MS_DHCP | LOG_WARNING
 * 
 * @see lease_init() - Processes old_leases after this function completes
 * @see parse_hex() - Decodes hex-encoded DUID, client-id, and vendor class data
 * @see lease4_allocate(), lease6_allocate() - Allocate lease structures for parsed entries
 * 
 * EXAMPLE USAGE:
 * @code
 * FILE *fp = fopen("/var/lib/misc/dnsmasq.leases", "r");
 * if (fp && read_leases(dnsmasq_time(), fp))
 *   my_syslog(MS_DHCP | LOG_INFO, "Lease database loaded successfully");
 * if (fp) fclose(fp);
 * @endcode
 * 
 * LEASE FILE FORMAT PARSED:
 * DHCPv4: <expiry> <hw-addr> <ip-addr> <hostname> <client-id>
 * DHCPv6: <expiry> <IAID> <ipv6-addr> <hostname> <DUID>
 * DUID: duid <hex-encoded-duid>
 * Vendor: vendorclass <ip-addr> <hex-encoded-vendor-class>
 * Agent: agent-info <ip-addr> <hex-encoded-agent-info>
 * 
 * SIDE EFFECTS:
 * - Populates old_leases linked list with parsed lease structures
 * - Allocates memory for lease structures and auxiliary data (DUID, vendor class, agent info)
 * - Sets daemon->duid and daemon->duid_len when DUID line is parsed
 * - Logs warnings for malformed lease entries via my_syslog()
 * 
 * THREAD SAFETY: Single-threaded, called only during daemon initialization
 */
static int read_leases(time_t now, FILE *leasestream)
{
  unsigned long ei;
  union all_addr addr;
  struct dhcp_lease *lease;
  int opt_len, clid_len, hw_len, hw_type;
  int items;
 
  *daemon->dhcp_buff3 = *daemon->dhcp_buff2 = '\0';

  /* client-id max length is 255 which is 255*2 digits + 254 colons
     borrow DNS packet buffer which is always larger than 1000 bytes

     Check various buffers are big enough for the code below */

#if (DHCP_BUFF_SZ < 255) || (MAXDNAME < 64) || (PACKETSZ+MAXDNAME+RRFIXEDSZ  < 764)
# error Buffer size breakage in leasefile parsing.
#endif

    while ((items=fscanf(leasestream, "%255s %255s", daemon->dhcp_buff3, daemon->dhcp_buff2)) == 2)
      {
	*daemon->namebuff = *daemon->dhcp_buff = *daemon->packet = '\0';
	hw_len = hw_type = clid_len = 0;
	
#ifdef HAVE_DHCP6
	if (strcmp(daemon->dhcp_buff3, "duid") == 0)
	  {
	    daemon->duid_len = parse_hex(daemon->dhcp_buff2, (unsigned char *)daemon->dhcp_buff2, 130, NULL, NULL);
	    if (daemon->duid_len < 0)
	      return 0;
	    daemon->duid = safe_malloc(daemon->duid_len);
	    memcpy(daemon->duid, daemon->dhcp_buff2, daemon->duid_len);
	    continue;
	  }
#endif

	/* Weird backwards compatible way of adding extra fields to leases */
	if ((strcmp(daemon->dhcp_buff3, "vendorclass") == 0 || strcmp(daemon->dhcp_buff3, "agent-info") == 0))
	  {
	    if (fscanf(leasestream, " %764s", daemon->packet) == 1)
	      {
		if (inet_pton(AF_INET, daemon->dhcp_buff2, &addr.addr4))
		  lease = lease_find_by_addr(addr.addr4);
#ifdef HAVE_DHCP6
		else if (inet_pton(AF_INET6, daemon->dhcp_buff2, &addr.addr6))
		  lease = lease6_find_by_plain_addr(&addr.addr6);
#endif
		else
		  continue;
		
		if (lease)
		  {
		    opt_len = parse_hex(daemon->packet, (unsigned char *)daemon->packet, 255, NULL, NULL);
		    
		    if (strcmp(daemon->dhcp_buff3, "vendorclass") == 0)
		      lease_set_vendorclass(lease, (unsigned char *)daemon->packet, opt_len);
		    else if (strcmp(daemon->dhcp_buff3, "agent-info") == 0)
		      lease_set_agent_id(lease, (unsigned char *)daemon->packet, opt_len);
		  }
	      }

	    continue;
	  }
	
	if (fscanf(leasestream, " %64s %255s %764s",
		   daemon->namebuff, daemon->dhcp_buff, daemon->packet) != 3)
	  {
	    my_syslog(MS_DHCP | LOG_WARNING, _("ignoring invalid line in lease database: %s %s %s %s ..."),
		      daemon->dhcp_buff3, daemon->dhcp_buff2,
		      daemon->namebuff, daemon->dhcp_buff);
	    continue;
	  }
		
	if (inet_pton(AF_INET, daemon->namebuff, &addr.addr4))
	  {
	    lease = lease4_allocate(addr.addr4);
	    
	    
	    hw_len = parse_hex(daemon->dhcp_buff2, (unsigned char *)daemon->dhcp_buff2, DHCP_CHADDR_MAX, NULL, &hw_type);
	    /* For backwards compatibility, no explicit MAC address type means ether. */
	    if (hw_type == 0 && hw_len != 0)
	      hw_type = ARPHRD_ETHER; 
	  }
#ifdef HAVE_DHCP6
	else if (inet_pton(AF_INET6, daemon->namebuff, &addr.addr6))
	  {
	    char *s = daemon->dhcp_buff2;
	    int lease_type = LEASE_NA;

	    if (s[0] == 'T')
	      {
		lease_type = LEASE_TA;
		s++;
	      }
	    
	    if ((lease = lease6_allocate(&addr.addr6, lease_type)))
	      lease_set_iaid(lease, strtoul(s, NULL, 10));
	  }
#endif
	else
	  {
	    my_syslog(MS_DHCP | LOG_WARNING, _("ignoring invalid line in lease database, bad address: %s"),
		      daemon->namebuff);
	    continue;
	  }
	

	if (!lease)
	  die (_("too many stored leases"), NULL, EC_MISC);

	if (strcmp(daemon->packet, "*") != 0)
	  clid_len = parse_hex(daemon->packet, (unsigned char *)daemon->packet, 255, NULL, NULL);
	
	lease_set_hwaddr(lease, (unsigned char *)daemon->dhcp_buff2, (unsigned char *)daemon->packet, 
			 hw_len, hw_type, clid_len, now, 0);
	
	if (strcmp(daemon->dhcp_buff, "*") !=  0)
	  lease_set_hostname(lease, daemon->dhcp_buff, 0, NULL, NULL);

	ei = atol(daemon->dhcp_buff3);

#ifdef HAVE_BROKEN_RTC
	if (ei != 0)
	  lease->expires = (time_t)ei + now;
	else
	  lease->expires = (time_t)0;
	lease->length = ei;
#else
	/* strictly time_t is opaque, but this hack should work on all sane systems,
	   even when sizeof(time_t) == 8 */
	lease->expires = (time_t)ei;
#endif
	
	/* set these correctly: the "old" events are generated later from
	   the startup synthesised SIGHUP. */
	lease->flags &= ~(LEASE_NEW | LEASE_CHANGED);
	
	*daemon->dhcp_buff3 = *daemon->dhcp_buff2 = '\0';
      }
    
    return (items == 0 || items == EOF);
}

/**
 * @brief Initialize lease database by loading leases from persistent storage and applying static configurations
 * 
 * @detailed This function performs complete lease database initialization during daemon startup:
 * reads leases from the persistent lease file, processes them to determine which should be kept
 * based on expiration times and static reservations, updates DNS cache with hostname entries,
 * and prepares the system for DHCP operation. The function distinguishes between leases that
 * should be preserved (not expired, or have static reservations) and those that should be
 * discarded (expired with no reservation). It handles both DHCPv4 and DHCPv6 leases.
 * 
 * @param now Current timestamp for determining lease expiration status
 * 
 * @return void
 * 
 * @note Called exactly once during daemon initialization in dnsmasq.c:main()
 * @warning Modifies global lease lists (leases, old_leases) and DNS cache state
 * 
 * @see read_leases() - Parses lease file into old_leases list before this function
 * @see lease_update_from_configs() - Applies static reservations to leases
 * @see lease_update_file() - Persists lease state changes to disk
 * @see lease_update_dns() - Registers lease hostnames in DNS cache
 * 
 * EXAMPLE USAGE:
 * @code
 * time_t startup_time = dnsmasq_time();
 * lease_init(startup_time);  // Load and initialize lease database
 * my_syslog(MS_DHCP | LOG_INFO, "Lease database initialized");
 * @endcode
 * 
 * INITIALIZATION SEQUENCE:
 * 1. Open and read lease file via read_leases() (populates old_leases)
 * 2. Initialize lease counter: leases_left = daemon->dhcp_max (typically 1000 from MAXLEASES)
 * 3. Process each lease from old_leases:
 *    - Check expiration: discard if expired AND no static reservation
 *    - Move non-expired leases to active 'leases' list
 *    - Expired leases with static reservations are kept for script notification
 * 4. Apply static reservations via lease_update_from_configs()
 * 5. Update DNS cache with all active lease hostnames via lease_update_dns()
 * 6. Mark file_dirty to trigger lease file rewrite with current state
 * 
 * SIDE EFFECTS:
 * - Populates global 'leases' linked list with active leases from file
 * - Frees expired leases without static reservations
 * - Decrements leases_left counter for each lease retained
 * - Sets file_dirty flag to trigger lease file update
 * - Populates DNS cache with lease hostname entries via cache_add_dhcp_entry()
 * - Opens lease file from daemon->lease_file path (typically /var/lib/misc/dnsmasq.leases)
 * 
 * THREAD SAFETY: Single-threaded initialization context, no concurrent access
 */

/**
 * @brief Initialize DHCP lease database from persistent storage or script
 * 
 * @detailed Initializes the global lease database by reading existing lease records from
 * either a persistent lease file (typically /var/lib/misc/dnsmasq.leases) or by invoking
 * a lease-change script with "init" command in read-only mode. This function is called
 * once during daemon startup to restore lease state from previous invocations. The function
 * handles multiple storage modes: standard read-write file mode where leases are persisted
 * to disk, and lease-ro mode where an external script provides the initial lease database.
 * All valid leases are loaded into memory, expired leases are pruned, and DNS cache entries
 * are created for lease hostnames.
 * 
 * The function performs the following operations in sequence:
 * 1. Initialize global leases_left counter to daemon->dhcp_max (typically MAXLEASES=1000)
 * 2. If lease-ro mode (OPT_LEASE_RO), invoke lease-change script with "init" command
 * 3. If standard mode, open lease file in "a+" mode (create if doesn't exist, read from start)
 * 4. Parse lease file or script output via read_leases()
 * 5. Prune expired leases that lack static reservations
 * 6. Mark DNS as dirty to trigger cache population with lease hostnames
 * 
 * @param now Current timestamp for lease expiration calculations (typically time(NULL))
 *            Used to determine which leases are still valid and which have expired
 * 
 * @return void - Function does not return a value
 * 
 * @note CRITICAL: This function must be called exactly once during daemon initialization
 *       before any DHCP packet processing begins. Multiple calls will corrupt the lease database.
 * 
 * @warning Function calls die() on critical errors and terminates the daemon:
 *          - Lease file cannot be opened or created (errno-based error)
 *          - Lease-change script not found (exit 127), lacks permissions (exit 126)
 *          - Lease-change script returns non-zero exit status (offset by EC_INIT_OFFSET)
 *          - Script command name + " init" exceeds DHCP_BUFF_SZ buffer
 * 
 * @warning If lease file parsing fails, logs error to syslog but continues with partial data
 * 
 * @see read_leases() for lease file parsing implementation
 * @see lease_prune() for expired lease cleanup
 * @see cache_add_dhcp_entry() for DNS integration
 * @see do_script_run() for lease-change script execution patterns
 * 
 * EXAMPLE USAGE:
 * @code
 * // During daemon initialization (from src/dnsmasq.c:main())
 * time_t now = dnsmasq_time();
 * lease_init(now);  // Load lease database from /var/lib/misc/dnsmasq.leases
 * 
 * // After this call:
 * // - Global 'leases' list contains all active leases from persistent storage
 * // - leases_left counter reflects remaining capacity for dynamic allocations
 * // - DNS cache populated with hostnames from lease records
 * // - Expired leases without static reservations have been freed
 * @endcode
 * 
 * RFC COMPLIANCE:
 * - Lease persistence supports RFC 2131 requirement for server to remember bindings
 * - Lease expiration handling per RFC 2131 Section 3.1 (server may reclaim after expiry)
 * 
 * SIDE EFFECTS:
 * - Populates global 'leases' linked list with active lease records
 * - Sets global 'leases_left' to remaining capacity (dhcp_max - loaded_lease_count)
 * - Sets file_dirty=0 after load, dns_dirty=1 to trigger DNS cache population
 * - Opens daemon->lease_stream file handle in standard mode (kept open for updates)
 * - Invokes lease-change script in lease-ro mode via popen("script init", "r")
 * - Prunes expired leases via lease_prune(), potentially freeing memory
 * - Logs parsing errors to syslog MS_DHCP facility on malformed lease entries
 * - Dies with fatal error if lease file/script inaccessible or script fails
 * 
 * THREAD SAFETY: Must be called from single-threaded initialization context only.
 * Not safe for concurrent invocation or use after daemon enters multi-request processing.
 */
void lease_init(time_t now)
{
  FILE *leasestream;

  leases_left = daemon->dhcp_max;

  if (option_bool(OPT_LEASE_RO))
    {
      /* run "<lease_change_script> init" once to get the
	 initial state of the database. If leasefile-ro is
	 set without a script, we just do without any
	 lease database. */
#ifdef HAVE_SCRIPT
      if (daemon->lease_change_command)
	{
	  /* 6 == strlen(" init") plus terminator */
	  if (strlen(daemon->lease_change_command) + 6 > DHCP_BUFF_SZ)
	    die(_("lease-change script name is too long"), NULL, EC_FILE);
	  
	  strcpy(daemon->dhcp_buff, daemon->lease_change_command);
	  strcat(daemon->dhcp_buff, " init");
	  leasestream = popen(daemon->dhcp_buff, "r");
	}
      else
#endif
	{
          file_dirty = dns_dirty = 0;
          return;
        }

    }
  else
    {
      /* NOTE: need a+ mode to create file if it doesn't exist */
      leasestream = daemon->lease_stream = fopen(daemon->lease_file, "a+");

      if (!leasestream)
	die(_("cannot open or create lease file %s: %s"), daemon->lease_file, EC_FILE);

      /* a+ mode leaves pointer at end. */
      rewind(leasestream);
    }

  if (leasestream)
    {
      if (!read_leases(now, leasestream))
	my_syslog(MS_DHCP | LOG_ERR, _("failed to parse lease database cleanly"));
      
      if (ferror(leasestream))
	die(_("failed to read lease file %s: %s"), daemon->lease_file, EC_FILE);
    }
  
#ifdef HAVE_SCRIPT
  if (!daemon->lease_stream)
    {
      int rc = 0;

      /* shell returns 127 for "command not found", 126 for bad permissions. */
      if (!leasestream || (rc = pclose(leasestream)) == -1 || WEXITSTATUS(rc) == 127 || WEXITSTATUS(rc) == 126)
	{
	  if (WEXITSTATUS(rc) == 127)
	    errno = ENOENT;
	  else if (WEXITSTATUS(rc) == 126)
	    errno = EACCES;

	  die(_("cannot run lease-init script %s: %s"), daemon->lease_change_command, EC_FILE);
	}
      
      if (WEXITSTATUS(rc) != 0)
	{
	  sprintf(daemon->dhcp_buff, "%d", WEXITSTATUS(rc));
	  die(_("lease-init script returned exit code %s"), daemon->dhcp_buff, WEXITSTATUS(rc) + EC_INIT_OFFSET);
	}
    }
#endif

  /* Some leases may have expired */
  file_dirty = 0;
  lease_prune(NULL, now);
  dns_dirty = 1;
}

/**
 * @brief Apply static hostname configuration to existing leases
 * 
 * @detailed Iterates through all active leases and updates their hostnames based on
 * static DHCP host declarations in the configuration. For each lease, this function
 * checks if a matching static configuration exists (by client ID, hardware address)
 * and applies the configured hostname if present. If no static configuration exists
 * but the lease's IP has a reverse DNS entry, it applies that hostname instead. This
 * function is called after configuration reload (SIGHUP) to synchronize lease hostnames
 * with updated static reservations.
 * 
 * @return void
 * 
 * @note Called after configuration changes to update hostnames on existing leases
 * @warning Skips DHCPv6 temporary address (TA) and non-temporary address (NA) leases
 * 
 * @see find_config() - Locates static DHCP configuration matching lease identifiers
 * @see lease_set_hostname() - Updates lease hostname and DNS cache registration
 * @see host_from_dns() - Retrieves hostname from reverse DNS lookup
 * 
 * EXAMPLE USAGE:
 * @code
 * // After SIGHUP configuration reload
 * lease_update_from_configs();  // Apply new static hostname configs
 * lease_update_dns(0);           // Update DNS cache with new hostnames
 * @endcode
 * 
 * CONFIGURATION MATCHING LOGIC:
 * For each lease, attempts to find matching static configuration by:
 * 1. Client identifier (clid) and length
 * 2. Hardware address (hwaddr), length, and type
 * If match found with CONFIG_NAME flag set, applies configured hostname
 * If CONFIG_ADDR also set, only applies if IP addresses match
 * 
 * SIDE EFFECTS:
 * - Updates hostname field in struct dhcp_lease for matching leases
 * - Modifies DNS cache entries via lease_set_hostname()
 * - Sets auth flag based on hostname source (static config vs DNS)
 * - May log hostname changes via lease_set_hostname()
 * 
 * THREAD SAFETY: Single-threaded, called from main event loop after config reload
 */
void lease_update_from_configs(void)
{
  /* changes to the config may change current leases. */
  
  struct dhcp_lease *lease;
  struct dhcp_config *config;
  char *name;
  
  for (lease = leases; lease; lease = lease->next)
    if (lease->flags & (LEASE_TA | LEASE_NA))
      continue;
    else if ((config = find_config(daemon->dhcp_conf, NULL, lease->clid, lease->clid_len, 
				   lease->hwaddr, lease->hwaddr_len, lease->hwaddr_type, NULL, NULL)) && 
	     (config->flags & CONFIG_NAME) &&
	     (!(config->flags & CONFIG_ADDR) || config->addr.s_addr == lease->addr.s_addr))
      lease_set_hostname(lease, config->hostname, 1, get_domain(lease->addr), NULL);
    else if ((name = host_from_dns(lease->addr)))
      lease_set_hostname(lease, name, 1, get_domain(lease->addr), NULL); /* updates auth flag only */
}

/**
 * @brief Write formatted output to lease file stream with error tracking
 * 
 * @detailed Helper function that wraps vfprintf for writing to the lease file stream,
 *           tracking write errors through an error pointer. Once an error is detected
 *           (*errp != 0), subsequent calls skip writing to prevent cascading failures.
 *           This pattern allows multiple ourprintf calls without checking each return value,
 *           with final error checking at the end of the write sequence.
 * 
 * @param errp Pointer to error status variable. If *errp is non-zero, no write is attempted.
 *             If write fails and *errp is zero, *errp is set to errno. Must not be NULL.
 * @param format printf-style format string for output. Must not be NULL.
 * @param ... Variable arguments matching format specifiers in format string
 * 
 * @note This function is used extensively by lease_update_file() to write lease database entries
 * @warning Function assumes daemon->lease_stream is valid (checked by caller)
 * 
 * @see lease_update_file()
 * 
 * EXAMPLE USAGE:
 * @code
 * int err = 0;
 * ourprintf(&err, "%lu ", (unsigned long)lease->expires);
 * ourprintf(&err, "%s\n", lease->hostname);
 * if (err) {
 *   my_syslog(LOG_ERR, _("failed to write lease: %s"), strerror(err));
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (internal utility function)
 * SIDE EFFECTS: Writes to daemon->lease_stream file descriptor; sets *errp on write failure
 * THREAD SAFETY: Not thread-safe (accesses global daemon structure, uses va_list)
 */
static void ourprintf(int *errp, char *format, ...)
{
  va_list ap;
  
  va_start(ap, format);
  if (!(*errp) && vfprintf(daemon->lease_stream, format, ap) < 0)
    *errp = errno;
  va_end(ap);
}

/**
 * @brief Write DHCP lease database to persistent storage and schedule next lease expiry event
 * 
 * @detailed This function performs the critical task of persisting the in-memory DHCP lease database
 *           to disk, ensuring lease continuity across daemon restarts. The function atomically rewrites
 *           the entire lease file by truncating and rewriting all active leases, then sets an alarm
 *           for the next lease expiry event. The function handles both DHCPv4 and DHCPv6 leases,
 *           writing vendor class and relay agent information as separate entries.
 *           
 *           The lease file format is line-oriented with space-separated fields:
 *           - DHCPv4: <expiry> <mac> <ip> <hostname> <client-id>
 *           - DHCPv6: <expiry> <IAID> <ip6> <hostname> <client-duid>
 *           - Special entries: "duid <hex-encoded-duid>" for server DUID
 *           - Optional entries: "vendorclass <ip> <hex-data>", "agent-info <ip> <hex-data>"
 *           
 *           After writing leases, the function determines the earliest event requiring daemon attention:
 *           lease expirations, IPv6 Router Advertisement periodic transmissions, or SLAAC confirmations.
 *           
 *           Write failures are logged and trigger retry scheduling (LEASE_RETRY seconds, default 60).
 * 
 * @param now Current time from time(0), used for calculating next event and retry intervals
 * 
 * @note File writes use ourprintf() helper which accumulates errors without stopping on first failure
 * @note Asynchronous I/O via fflush() and fsync() ensures data reaches disk before clearing file_dirty flag
 * @note Function clears file_dirty flag only on successful write+flush+sync sequence
 * @note LEASE_RETRY (config.h:52, default 60 seconds) determines retry interval on write failures
 * 
 * @warning Function assumes daemon->lease_stream is valid and open for writing
 * @warning Truncates existing file content before writing (ftruncate to position 0)
 * @warning Write failures leave lease file potentially incomplete until next retry
 * 
 * @see lease_prune() - Called to remove expired leases before writing
 * @see ourprintf() - Helper for error-tracked formatted output
 * @see send_alarm() - Schedules next lease_update_file invocation at next_event time
 * @see periodic_ra() - DHCPv6 Router Advertisement scheduling (HAVE_DHCP6)
 * @see periodic_slaac() - SLAAC address confirmation scheduling (HAVE_DHCP6)
 * 
 * EXAMPLE USAGE:
 * @code
 * // Called from timer alarm handler or on lease changes:
 * time_t now = dnsmasq_time();
 * lease_update_file(now);
 * // Lease database now persisted; alarm set for next lease expiry
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (implementation-specific lease persistence mechanism)
 * 
 * SIDE EFFECTS:
 * - Overwrites lease file at daemon->lease_stream with current lease database
 * - Calls fflush() and fsync() to force data to disk
 * - Schedules alarm via send_alarm() for next lease/RA/SLAAC event
 * - Logs errors to syslog on write failures with retry scheduling
 * - Clears file_dirty flag on successful write
 * - Triggers periodic_ra() and periodic_slaac() for IPv6 maintenance (HAVE_DHCP6)
 * 
 * THREAD SAFETY: Not thread-safe (accesses global daemon structure, leases list, modifies file_dirty)
 */
void lease_update_file(time_t now)
{
  struct dhcp_lease *lease;
  time_t next_event;
  int i, err = 0, extras;
  
  if (file_dirty != 0 && daemon->lease_stream)
    {
      errno = 0;
      rewind(daemon->lease_stream);
      if (errno != 0 || ftruncate(fileno(daemon->lease_stream), 0) != 0)
	err = errno;
      
      for (extras = 0, lease = leases; lease; lease = lease->next)
	{
	  if (lease->agent_id || lease->vendorclass)
	    extras = 1;
	  
#ifdef HAVE_DHCP6
	  if (lease->flags & (LEASE_TA | LEASE_NA))
	    continue;
#endif

#ifdef HAVE_BROKEN_RTC
	  ourprintf(&err, "%u ", lease->length);
#else
	  ourprintf(&err, "%lu ", (unsigned long)lease->expires);
#endif

	  if (lease->hwaddr_type != ARPHRD_ETHER || lease->hwaddr_len == 0) 
	    ourprintf(&err, "%.2x-", lease->hwaddr_type);
	  for (i = 0; i < lease->hwaddr_len; i++)
	    {
	      ourprintf(&err, "%.2x", lease->hwaddr[i]);
	      if (i != lease->hwaddr_len - 1)
		ourprintf(&err, ":");
	    }
	  
	  inet_ntop(AF_INET, &lease->addr, daemon->addrbuff, ADDRSTRLEN); 

	  ourprintf(&err, " %s ", daemon->addrbuff);
	  ourprintf(&err, "%s ", lease->hostname ? lease->hostname : "*");
	  	  
	  if (lease->clid && lease->clid_len != 0)
	    {
	      for (i = 0; i < lease->clid_len - 1; i++)
		ourprintf(&err, "%.2x:", lease->clid[i]);
	      ourprintf(&err, "%.2x\n", lease->clid[i]);
	    }
	  else
	    ourprintf(&err, "*\n");	  
	}
      
#ifdef HAVE_DHCP6  
      if (daemon->duid)
	{
	  ourprintf(&err, "duid ");
	  for (i = 0; i < daemon->duid_len - 1; i++)
	    ourprintf(&err, "%.2x:", daemon->duid[i]);
	  ourprintf(&err, "%.2x\n", daemon->duid[i]);
	  
	  for (lease = leases; lease; lease = lease->next)
	    {
	      
	      if (!(lease->flags & (LEASE_TA | LEASE_NA)))
		continue;

#ifdef HAVE_BROKEN_RTC
	      ourprintf(&err, "%u ", lease->length);
#else
	      ourprintf(&err, "%lu ", (unsigned long)lease->expires);
#endif
    
	      inet_ntop(AF_INET6, &lease->addr6, daemon->addrbuff, ADDRSTRLEN);
	 
	      ourprintf(&err, "%s%u %s ", (lease->flags & LEASE_TA) ? "T" : "",
			lease->iaid, daemon->addrbuff);
	      ourprintf(&err, "%s ", lease->hostname ? lease->hostname : "*");
	      
	      if (lease->clid && lease->clid_len != 0)
		{
		  for (i = 0; i < lease->clid_len - 1; i++)
		    ourprintf(&err, "%.2x:", lease->clid[i]);
		  ourprintf(&err, "%.2x\n", lease->clid[i]);
		}
	      else
		ourprintf(&err, "*\n");	  
	    }
	}
#endif      

      if (extras)
	{
	  /* Dump this at the end for least confusion with older parsing code. */
	  for (lease = leases; lease; lease = lease->next)
	    {
#ifdef HAVE_DHCP6
	      if (lease->flags & (LEASE_TA | LEASE_NA))
		inet_ntop(AF_INET6, &lease->addr6, daemon->addrbuff, ADDRSTRLEN);
	      else
#endif
		inet_ntop(AF_INET, &lease->addr, daemon->addrbuff, ADDRSTRLEN);
	      
	      if (lease->agent_id)
		{
		  ourprintf(&err, "agent-info %s ", daemon->addrbuff);
		  for (i = 0; i < lease->agent_id_len - 1; i++)
		    ourprintf(&err, "%.2x:", lease->agent_id[i]);
		  ourprintf(&err, "%.2x\n", lease->agent_id[i]);
		}
	      
	      if (lease->vendorclass)
		{
		  ourprintf(&err, "vendorclass %s ", daemon->addrbuff);
		  for (i = 0; i < lease->vendorclass_len - 1; i++)
		    ourprintf(&err, "%.2x:", lease->vendorclass[i]);
		  ourprintf(&err, "%.2x\n", lease->vendorclass[i]);
		}
	    }
	}
      
      if (fflush(daemon->lease_stream) != 0 ||
	  fsync(fileno(daemon->lease_stream)) < 0)
	err = errno;
      
      if (!err)
	file_dirty = 0;
    }
  
  /* Set alarm for when the first lease expires. */
  next_event = 0;

#ifdef HAVE_DHCP6
  /* do timed RAs and determine when the next is, also pings to potential SLAAC addresses */
  if (daemon->doing_ra)
    {
      time_t event;
      
      if ((event = periodic_slaac(now, leases)) != 0)
	{
	  if (next_event == 0 || difftime(next_event, event) > 0.0)
	    next_event = event;
	}
      
      if ((event = periodic_ra(now)) != 0)
	{
	  if (next_event == 0 || difftime(next_event, event) > 0.0)
	    next_event = event;
	}
    }
#endif

  for (lease = leases; lease; lease = lease->next)
    if (lease->expires != 0 &&
	(next_event == 0 || difftime(next_event, lease->expires) > 0.0))
      next_event = lease->expires;
   
  if (err)
    {
      if (next_event == 0 || difftime(next_event, LEASE_RETRY + now) > 0.0)
	next_event = LEASE_RETRY + now;
      
      my_syslog(MS_DHCP | LOG_ERR, _("failed to write %s: %s (retry in %u s)"), 
		daemon->lease_file, strerror(err),
		(unsigned int)difftime(next_event, now));
    }

  send_alarm(next_event, now);
}


/**
 * @brief Update interface association for IPv4 leases on a specific network
 * 
 * Callback function used during interface enumeration to identify and update
 * the network interface information for existing DHCPv4 leases. Checks if leases
 * belong to the network defined by the local address and netmask, and updates
 * the lease's interface index and prefix length to the most specific match found.
 * 
 * This function is called once per network interface during lease initialization
 * (via iface_enumerate) to ensure all leases are correctly associated with their
 * network interfaces after daemon startup or configuration reload.
 * 
 * @param local Local IPv4 address of the network interface being examined
 * @param if_index Interface index (system-specific interface identifier)
 * @param label Interface label/name (unused, may be NULL)
 * @param netmask Network mask defining the subnet size
 * @param broadcast Broadcast address for the subnet (unused)
 * @param vparam User-defined parameter passed through iface_enumerate (unused)
 * 
 * @return Always returns 1 to continue interface enumeration
 * 
 * @note Only processes IPv4 DHCP leases (excludes IPv6 TA and NA lease types)
 * @note Updates lease association only if current prefix is more specific than previous match
 * @note Thread-safe: Single-threaded architecture, modifies global lease list
 * 
 * EXAMPLE USAGE:
 * @code
 * // Called internally by lease_init via iface_enumerate:
 * // iface_enumerate(AF_INET, NULL, find_interface_v4);
 * // For each interface, this function checks all leases and updates
 * // interface associations based on subnet membership
 * @endcode
 * 
 * SIDE EFFECTS: Modifies lease->new_interface and lease->new_prefixlen fields
 * INTEGRATION: Called by iface_enumerate during lease_init (src/network.c)
 */
/**
 * @brief Update interface association for IPv4 leases on a specific network
 * 
 * @detailed Callback function used during interface enumeration to identify and update
 *           the network interface information for existing DHCPv4 leases. Checks if leases
 *           belong to the network defined by the local IPv4 address and netmask, and updates
 *           the lease's interface index and prefix length to the most specific match found.
 *           Called once per IPv4 network interface during lease initialization (via iface_enumerate)
 *           to ensure correct interface associations for all allocated addresses.
 * 
 * @param local Local IPv4 address of the network interface being examined
 * @param if_index Interface index (system-specific interface identifier like 1 for eth0)
 * @param label Interface label/name - unused but required by callback signature
 * @param netmask Subnet mask defining the network range (e.g., 255.255.255.0)
 * @param broadcast Broadcast address for the network - unused but required by callback signature
 * @param vparam User-defined parameter passed through iface_enumerate - unused
 * 
 * @return Always returns 1 to continue interface enumeration process
 * 
 * @note Only processes IPv4 DHCP leases - skips DHCPv6 leases (LEASE_TA | LEASE_NA flags)
 * @note Updates lease association only if current prefix is more specific than previous match
 *       (higher prefix length = smaller subnet = more specific)
 * @note Called during lease database initialization via lease_init() -> iface_enumerate(AF_INET, ...)
 * @note The (void) casts suppress compiler warnings for unused parameters
 * 
 * @see find_interface_v6 for IPv6 equivalent functionality
 * @see netmask_length in src/util.c for converting netmask to CIDR prefix length
 * 
 * EXAMPLE USAGE:
 * @code
 * // Called internally by lease_init via iface_enumerate:
 * // iface_enumerate(AF_INET, NULL, find_interface_v4);
 * // For each IPv4 interface, this callback updates matching leases with interface info
 * @endcode
 * 
 * RFC COMPLIANCE: Supports DHCPv4 per RFC 2131
 * SIDE EFFECTS: Modifies new_interface and new_prefixlen fields of matching leases
 * THREAD SAFETY: Single-threaded architecture - modifies global leases list
 */
static int find_interface_v4(struct in_addr local, int if_index, char *label,
			     struct in_addr netmask, struct in_addr broadcast, void *vparam)
{
  struct dhcp_lease *lease;
  int prefix = netmask_length(netmask);

  (void) label;
  (void) broadcast;
  (void) vparam;

  for (lease = leases; lease; lease = lease->next)
    if (!(lease->flags & (LEASE_TA | LEASE_NA)) &&
	is_same_net(local, lease->addr, netmask) && 
	prefix > lease->new_prefixlen) 
      {
	lease->new_interface = if_index;
        lease->new_prefixlen = prefix;
      }

  return 1;
}

#ifdef HAVE_DHCP6
/**
 * @brief Update interface association for IPv6 leases on a specific network
 * 
 * Callback function used during interface enumeration to identify and update
 * the network interface information for existing DHCPv6 leases. Checks if leases
 * belong to the network defined by the local IPv6 address and prefix length,
 * and updates the lease's interface index and prefix length to the most specific
 * match found.
 * 
 * This function is the IPv6 counterpart to find_interface_v4, processing only
 * DHCPv6 leases (temporary addresses and non-temporary addresses). Called once
 * per IPv6 network interface during lease initialization to ensure correct
 * interface associations.
 * 
 * @param local Local IPv6 address of the network interface being examined
 * @param prefix Prefix length (bits) defining the subnet size
 * @param scope Address scope (link-local, site-local, global) - unused
 * @param if_index Interface index (system-specific interface identifier)
 * @param flags Interface flags (IFF_UP, IFF_RUNNING, etc.) - unused
 * @param preferred Preferred lifetime for the address (seconds) - unused
 * @param valid Valid lifetime for the address (seconds) - unused
 * @param vparam User-defined parameter passed through iface_enumerate (unused)
 * 
 * @return Always returns 1 to continue interface enumeration
 * 
 * @note Only processes IPv6 DHCP leases (LEASE_TA and LEASE_NA flags)
 * @note Updates lease association only if current prefix is more specific than previous match
 * @note Handles multiple netlink GETADDR responses with varying prefix lengths
 * @note Thread-safe: Single-threaded architecture, modifies global lease list
 * 
 * RFC COMPLIANCE: Supports DHCPv6 per RFC 3315 and IPv6 addressing per RFC 4291
 * 
 * EXAMPLE USAGE:
 * @code
 * // Called internally by lease_init via iface_enumerate:
 * // iface_enumerate(AF_INET6, NULL, find_interface_v6);
 * // For each IPv6 interface, this function checks all DHCPv6 leases
 * // and updates interface associations based on subnet membership
 * @endcode
 * 
 * SIDE EFFECTS: Modifies lease->new_interface and lease->new_prefixlen fields
 * INTEGRATION: Called by iface_enumerate during lease_init (src/network.c)
 */
/**
 * @brief Update interface association for IPv6 leases on a specific network
 * 
 * @detailed Callback function used during interface enumeration to identify and update
 *           the network interface information for existing DHCPv6 leases. Checks if DHCPv6
 *           leases belong to the network defined by the local IPv6 address and prefix length,
 *           and updates the lease's interface index and prefix length to the most specific
 *           match found. Called once per IPv6 network address during lease initialization
 *           (via iface_enumerate) to ensure correct interface associations. Only processes
 *           DHCPv6 leases (LEASE_TA | LEASE_NA flags), ignoring DHCPv4 leases.
 * 
 * @param local Local IPv6 address of the network interface being examined
 * @param prefix Prefix length for the IPv6 network (e.g., 64 for /64 subnet)
 * @param scope IPv6 address scope (link-local, site-local, global) - unused but required by callback
 * @param if_index Interface index (system-specific interface identifier like 2 for eth0)
 * @param flags Address flags (temporary, permanent, etc.) - unused but required by callback
 * @param preferred Preferred lifetime in seconds for IPv6 address - unused but required by callback
 * @param valid Valid lifetime in seconds for IPv6 address - unused but required by callback
 * @param vparam User-defined parameter passed through iface_enumerate - unused
 * 
 * @return Always returns 1 to continue interface enumeration process
 * 
 * @note Only processes DHCPv6 leases (LEASE_TA | LEASE_NA flags) - skips DHCPv4 leases
 * @note Updates lease association only if current prefix is more specific than previous match
 *       (higher prefix length = smaller subnet = more specific match)
 * @note Multiple netlink GETADDR responses may provide progressively shorter prefixes;
 *       this function retains the longest (most specific) prefix match
 * @note Called during lease database initialization via lease_init() -> iface_enumerate(AF_INET6, ...)
 * @note The (void) casts suppress compiler warnings for unused parameters
 * 
 * @see find_interface_v4 for IPv4 equivalent functionality
 * @see is_same_net6 in src/util.c for IPv6 network comparison logic
 * 
 * EXAMPLE USAGE:
 * @code
 * // Called internally by lease_init via iface_enumerate:
 * // iface_enumerate(AF_INET6, NULL, find_interface_v6);
 * // For each IPv6 address, this callback updates matching DHCPv6 leases with interface info
 * @endcode
 * 
 * RFC COMPLIANCE: Supports DHCPv6 per RFC 3315
 * SIDE EFFECTS: Modifies new_interface and new_prefixlen fields of matching DHCPv6 leases
 * THREAD SAFETY: Single-threaded architecture - modifies global leases list
 */
static int find_interface_v6(struct in6_addr *local,  int prefix,
			     int scope, int if_index, int flags, 
			     unsigned int preferred, unsigned int valid, void *vparam)
{
  struct dhcp_lease *lease;

  (void)scope;
  (void)flags;
  (void)preferred;
  (void)valid;
  (void)vparam;

  for (lease = leases; lease; lease = lease->next)
    if ((lease->flags & (LEASE_TA | LEASE_NA)))
      if (is_same_net6(local, &lease->addr6, prefix) && prefix > lease->new_prefixlen) {
        /* save prefix length for comparison, as we might get shorter matching
         * prefix in upcoming netlink GETADDR responses
         * */
        lease->new_interface = if_index;
        lease->new_prefixlen = prefix;
      }

  return 1;
}

/**
 * @brief Handle ping reply for SLAAC address confirmation
 * 
 * @detailed Processes ICMPv6 ping replies received during SLAAC address confirmation.
 *           Delegates to slaac_ping_reply() if DHCP is enabled and lease database exists.
 *           This function coordinates with Router Advertisement and SLAAC to verify IPv6
 *           addresses are not already in use before assignment (duplicate address detection).
 * 
 * @param sender IPv6 address of the ping reply sender
 * @param packet ICMPv6 packet data containing ping reply
 * @param interface Network interface name where reply was received (e.g., "eth0")
 * 
 * @return None (void function)
 * 
 * @note Only processes replies if daemon->dhcp is non-NULL (DHCP subsystem active)
 * @warning Interface string must remain valid during function execution
 * 
 * @see slaac_ping_reply() in slaac.c for actual ping reply processing
 * @see lease_update_slaac() for SLAAC address confirmation workflow
 * 
 * EXAMPLE USAGE:
 * @code
 * struct in6_addr sender_addr;
 * unsigned char icmp_packet[128];
 * lease_ping_reply(&sender_addr, icmp_packet, "eth0");
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 4862 (SLAAC) - Duplicate Address Detection
 * SIDE EFFECTS: May invoke slaac_ping_reply which updates lease state
 * THREAD SAFETY: Single-threaded architecture; accesses global daemon state
 */
void lease_ping_reply(struct in6_addr *sender, unsigned char *packet, char *interface)
{
  /* We may be doing RA but not DHCPv4, in which case the lease
     database may not exist and we have nothing to do anyway */
  if (daemon->dhcp)
    slaac_ping_reply(sender, packet, interface, leases);
}

/**
 * @brief Update SLAAC addresses for all existing leases
 * 
 * @detailed Called when constructing a new RA-names context to add putative new SLAAC
 *           addresses to existing DHCP leases. Iterates through all active leases and
 *           invokes slaac_add_addrs() to associate SLAAC-derived IPv6 addresses with
 *           each lease based on Router Advertisement prefix configuration. This ensures
 *           that hostname-to-IPv6-address mappings reflect both DHCPv6 and SLAAC addresses.
 * 
 * @param now Current timestamp for SLAAC address lifecycle management
 * 
 * @return None (void function)
 * 
 * @note Only processes leases if daemon->dhcp is non-NULL (DHCP subsystem active)
 * @note Iterates through global leases linked list; safe for use during configuration reload
 * @warning Must be called with valid 'now' timestamp to ensure correct address expiration
 * 
 * @see slaac_add_addrs() in slaac.c for SLAAC address association logic
 * @see lease_ping_reply() for SLAAC duplicate address detection
 * @see radv.c for Router Advertisement prefix configuration
 * 
 * EXAMPLE USAGE:
 * @code
 * time_t current_time = time(NULL);
 * lease_update_slaac(current_time);  // Update SLAAC addresses for all leases
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 4862 (IPv6 Stateless Address Autoconfiguration)
 * SIDE EFFECTS: Invokes slaac_add_addrs() which may modify lease structures and DNS cache
 * THREAD SAFETY: Single-threaded architecture; modifies global lease list
 */
void lease_update_slaac(time_t now)
{
  /* Called when we construct a new RA-names context, to add putative
     new SLAAC addresses to existing leases. */

  struct dhcp_lease *lease;
  
  if (daemon->dhcp)
    for (lease = leases; lease; lease = lease->next)
      slaac_add_addrs(lease, now, 0);
}

#endif


/**
 * @brief Find and associate network interfaces with leases at daemon startup
 * 
 * @detailed Enumerates all network interfaces and associates each lease with its corresponding
 *           directly-connected subnet interface. This interface information is updated during
 *           ongoing DHCP transactions, but the initial startup scan is critical for:
 *           1) Providing accurate interface information to lease-change scripts
 *           2) Determining SLAAC addresses from DHCPv4 leases at startup
 *           3) Establishing subnet-to-interface mappings for prefix delegation
 *           
 *           The function performs a two-phase scan: first clearing all interface associations,
 *           then enumerating IPv4 and IPv6 interfaces to populate associations based on
 *           lease IP addresses matching configured subnet ranges.
 * 
 * @param now Current timestamp for lease lifecycle management
 * 
 * @return None (void function)
 * 
 * @note Called once at daemon startup before entering main event loop
 * @note Interface associations updated continuously during DHCP transaction processing
 * @warning Must be called after network interfaces are configured but before serving requests
 * 
 * @see iface_enumerate() in network.c for interface enumeration implementation
 * @see find_interface_v4() callback for IPv4 interface matching logic
 * @see find_interface_v6() callback for IPv6 interface matching logic (HAVE_DHCP6)
 * @see lease_set_interface() for interface association with lease
 * 
 * EXAMPLE USAGE:
 * @code
 * time_t startup_time = time(NULL);
 * lease_find_interfaces(startup_time);  // Scan interfaces at daemon startup
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (implementation-specific initialization)
 * SIDE EFFECTS: Modifies new_interface and new_prefixlen fields in all lease structures;
 *               invokes lease_set_interface() which updates DNS cache and triggers scripts
 * THREAD SAFETY: Single-threaded architecture; modifies global lease list
 */
void lease_find_interfaces(time_t now)
{
  struct dhcp_lease *lease;
  
  for (lease = leases; lease; lease = lease->next)
    lease->new_prefixlen = lease->new_interface = 0;

  iface_enumerate(AF_INET, &now, (callback_t){.af_inet=find_interface_v4});
#ifdef HAVE_DHCP6
  iface_enumerate(AF_INET6, &now, (callback_t){.af_inet6=find_interface_v6});
#endif

  for (lease = leases; lease; lease = lease->next)
    if (lease->new_interface != 0) 
      lease_set_interface(lease, lease->new_interface, now);
}

#ifdef HAVE_DHCP6
/**
 * @brief Ensure DHCPv6 DUID (DHCP Unique Identifier) is created when DHCPv6 is active
 * 
 * @detailed Checks if a DUID needs to be generated for DHCPv6 server operation. If the daemon 
 *           is configured for DHCPv6 (daemon->doing_dhcp6) and no DUID has been created yet 
 *           (daemon->duid is NULL), this function triggers DUID generation via make_duid() and 
 *           marks the lease database as dirty to persist the DUID to disk. The DUID uniquely 
 *           identifies the DHCPv6 server per RFC 3315 and must remain stable across daemon 
 *           restarts to maintain client lease continuity. This function is typically called 
 *           during lease database operations to ensure the DUID is available before processing 
 *           DHCPv6 leases.
 * 
 * @param now Current timestamp used for DUID-LLT generation (seconds since epoch)
 * 
 * @return void
 * 
 * @note This function is conditional on daemon->doing_dhcp6; no action taken if DHCPv6 disabled
 * @note Setting file_dirty=1 triggers asynchronous lease database write including DUID
 * @note DUID generation via make_duid() creates DUID-LLT (Link-layer address plus time)
 * 
 * @warning DUID changes invalidate existing DHCPv6 leases and force client reconfiguration
 * 
 * @see make_duid() in network.c for actual DUID generation implementation
 * @see lease_update_file() for lease database persistence mechanism
 * @see RFC 3315 Section 9 for DHCP Unique Identifier specification
 * 
 * EXAMPLE USAGE:
 * @code
 * time_t now = dnsmasq_time();
 * lease_make_duid(now);  // Ensures DUID exists if DHCPv6 is active
 * // If DUID was created, file_dirty flag set for database update
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 3315 Section 9 (DUID format and usage for DHCPv6 servers)
 * SIDE EFFECTS: May call make_duid() creating daemon->duid; sets file_dirty=1 if DUID created
 * THREAD SAFETY: Single-threaded architecture; modifies global daemon state and file_dirty flag
 */
void lease_make_duid(time_t now)
{
  /* If we're not doing DHCPv6, and there are not v6 leases, don't add the DUID to the database */
  if (!daemon->duid && daemon->doing_dhcp6)
    {
      file_dirty = 1;
      make_duid(now);
    }
}
#endif




/**
 * @brief Synchronize DHCP lease hostnames into DNS cache for automatic name resolution
 * 
 * @detailed Populates the DNS cache with hostname-to-IP mappings from all active DHCP leases,
 *           enabling automatic DNS resolution of DHCP client hostnames without manual DNS 
 *           configuration. This function is called when lease changes require DNS cache updates
 *           (dns_dirty flag set) or when forced synchronization is requested. The function
 *           iterates through the lease database, adding both short hostnames and fully-qualified
 *           domain names (FQDNs) to the DNS cache with appropriate TTLs matching lease expiration.
 *           For DHCPv6 leases, it handles both stateful addresses (TA/NA) and SLAAC-assigned
 *           addresses. The SOA serial number is incremented (on platforms with RTC) to trigger
 *           zone transfer to authoritative secondaries. This integration eliminates the need
 *           for separate DNS-DHCP synchronization and ensures that DHCP clients are immediately
 *           resolvable by hostname throughout the network.
 * 
 * @param force If non-zero, forces DNS cache update even if dns_dirty flag is clear;
 *              if zero, only updates when dns_dirty flag indicates pending changes
 * 
 * @return void
 * 
 * @note Only executes if DNS service is active (daemon->port != 0); no-op if DNS disabled
 * @note Clears dns_dirty flag after successful synchronization to prevent redundant updates
 * @note SOA serial increment triggers zone transfer to secondary nameservers if authoritative DNS active
 * @note Handles both IPv4 and IPv6 leases with appropriate protocol family in cache entries
 * 
 * @warning cache_unhash_dhcp() clears existing DHCP entries; all current leases re-added
 * @warning SLAAC addresses with backoff != 0 are not added to DNS (pending duplicate detection)
 * 
 * @see cache_add_dhcp_entry() in cache.c for DNS cache insertion with DHCP flag
 * @see cache_unhash_dhcp() in cache.c for removing existing DHCP entries before update
 * @see lease_update_from_configs() for lease operations that set dns_dirty flag
 * @see OPT_DHCP_FQDN option controlling whether short hostnames are registered
 * 
 * EXAMPLE USAGE:
 * @code
 * // After DHCP lease assignment that changes hostname
 * dns_dirty = 1;  // Mark DNS cache as needing update
 * lease_update_dns(0);  // Synchronize on next opportunity
 * 
 * // Force immediate synchronization (e.g., after configuration reload)
 * lease_update_dns(1);  // Bypasses dns_dirty check
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 2131 Section 4.3.1 (integration with DNS for dynamic hostname registration)
 * SIDE EFFECTS: Modifies DNS cache via cache_add_dhcp_entry(); increments daemon->soa_sn; clears dns_dirty flag
 * THREAD SAFETY: Single-threaded architecture; iterates lease list and modifies global DNS cache state
 */
void lease_update_dns(int force)
{
  struct dhcp_lease *lease;

  if (daemon->port != 0 && (dns_dirty || force))
    {
#ifndef HAVE_BROKEN_RTC
      /* force transfer to authoritative secondaries */
      daemon->soa_sn++;
#endif
      
      cache_unhash_dhcp();

      for (lease = leases; lease; lease = lease->next)
	{
	  int prot = AF_INET;
	  
#ifdef HAVE_DHCP6
	  if (lease->flags & (LEASE_TA | LEASE_NA))
	    prot = AF_INET6;
	  else if (lease->hostname || lease->fqdn)
	    {
	      struct slaac_address *slaac;

	      for (slaac = lease->slaac_address; slaac; slaac = slaac->next)
		if (slaac->backoff == 0)
		  {
		    if (lease->fqdn)
		      cache_add_dhcp_entry(lease->fqdn, AF_INET6, (union all_addr *)&slaac->addr, lease->expires);
		    if (!option_bool(OPT_DHCP_FQDN) && lease->hostname)
		      cache_add_dhcp_entry(lease->hostname, AF_INET6, (union all_addr *)&slaac->addr, lease->expires);
		  }
	    }
	  
	  if (lease->fqdn)
	    cache_add_dhcp_entry(lease->fqdn, prot, 
				 prot == AF_INET ? (union all_addr *)&lease->addr : (union all_addr *)&lease->addr6,
				 lease->expires);
	     
	  if (!option_bool(OPT_DHCP_FQDN) && lease->hostname)
	    cache_add_dhcp_entry(lease->hostname, prot, 
				 prot == AF_INET ? (union all_addr *)&lease->addr : (union all_addr *)&lease->addr6, 
				 lease->expires);
       
#else
	  if (lease->fqdn)
	    cache_add_dhcp_entry(lease->fqdn, prot, (union all_addr *)&lease->addr, lease->expires);
	  
	  if (!option_bool(OPT_DHCP_FQDN) && lease->hostname)
	    cache_add_dhcp_entry(lease->hostname, prot, (union all_addr *)&lease->addr, lease->expires);
#endif
	}
      
      dns_dirty = 0;
    }
}

/**
 * @brief Remove expired leases and optionally a target lease from the active lease database
 * 
 * @detailed Scans the active lease list (leases) and removes leases that have expired or 
 *           match the specified target lease. Expired leases are identified by comparing
 *           their expiration timestamp with the current time. Removed leases are not 
 *           immediately freed; instead, they are transferred to the old_leases list where
 *           they await script execution (for lease-change notifications) before final 
 *           cleanup. This deferred cleanup allows lease-change scripts to receive "del"
 *           events for expired leases. The function sets file_dirty to trigger lease 
 *           database persistence and dns_dirty if the removed lease had a hostname 
 *           (triggering DNS cache update). Metrics are incremented to track pruned IPv4
 *           and IPv6 leases separately based on the lease type.
 * 
 * @param target Specific lease to remove regardless of expiration (may be NULL); if non-NULL,
 *               this lease is removed even if not yet expired; typically used when releasing
 *               a lease or handling DHCPDECLINE
 * @param now Current timestamp (seconds since epoch) used for expiration comparison
 * 
 * @return void
 * 
 * @note Leases with expires=0 are permanent and never pruned by expiration (only if target matches)
 * @note Removed leases moved to old_leases list, not freed immediately; cleanup happens after script execution
 * @note Sets file_dirty=1 for any pruned lease to trigger database write
 * @note Sets dns_dirty=1 if pruned lease had hostname, triggering DNS cache synchronization
 * @note Increments METRIC_LEASES_PRUNED_4 for IPv4 leases, METRIC_LEASES_PRUNED_6 for IPv6 leases
 * 
 * @warning Modifies the global leases linked list; caller must not hold pointers into list during call
 * @warning Does not invoke lease-change scripts directly; scripts run later via rerun_scripts()
 * 
 * @see rerun_scripts() for executing lease-change scripts on old_leases entries
 * @see lease_update_file() for persisting lease database when file_dirty set
 * @see lease_update_dns() for DNS cache synchronization when dns_dirty set
 * @see do_script_run() in helper.c for actual script execution with "del" action
 * 
 * EXAMPLE USAGE:
 * @code
 * time_t now = dnsmasq_time();
 * // Remove all expired leases
 * lease_prune(NULL, now);
 * 
 * // Force removal of specific lease (e.g., after DHCPDECLINE)
 * struct dhcp_lease *bad_lease = lease_find_by_addr(declined_addr);
 * if (bad_lease)
 *   lease_prune(bad_lease, now);  // Remove regardless of expiration
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 2131 Section 3.1 (lease expiration and reclamation)
 * SIDE EFFECTS: Modifies leases list, old_leases list, leases_left counter; sets file_dirty and dns_dirty flags; increments metrics
 * THREAD SAFETY: Single-threaded architecture; modifies global lease database state
 */
void lease_prune(struct dhcp_lease *target, time_t now)
{
  struct dhcp_lease *lease, *tmp, **up;

  for (lease = leases, up = &leases; lease; lease = tmp)
    {
      tmp = lease->next;
      if ((lease->expires != 0 && difftime(now, lease->expires) >= 0) || lease == target)
	{
	  file_dirty = 1;
	  if (lease->hostname)
	    dns_dirty = 1;

	  daemon->metrics[lease->addr.s_addr ? METRIC_LEASES_PRUNED_4 : METRIC_LEASES_PRUNED_6]++;

 	  *up = lease->next; /* unlink */
	  
	  /* Put on old_leases list 'till we
	     can run the script */
	  lease->next = old_leases;
	  old_leases = lease;
	  
	  leases_left++;
	}
      else
	up = &lease->next;
    }
} 
	
  
/**
 * @brief Find DHCPv4 lease by client identifier or hardware address
 * 
 * @detailed Searches the active lease database for a DHCPv4 lease matching the provided client 
 *           identifier (clid) or hardware address (MAC address). Implements two-phase search 
 *           algorithm: first attempts to match by client identifier if provided (preferred 
 *           identifier per RFC 2131), then falls back to hardware address matching if no 
 *           clid match found. This function is critical for lease renewal processing where 
 *           the server must locate the client's existing lease to extend it rather than 
 *           allocating a new address. DHCPv6 leases (LEASE_TA, LEASE_NA flags) are excluded 
 *           from search results to prevent cross-protocol confusion in dual-stack environments.
 * 
 * @param hwaddr Hardware address (MAC address) of client, must be valid buffer of hw_len bytes
 * @param hw_len Length of hardware address in bytes (typically 6 for Ethernet, 0 to skip hwaddr match)
 * @param hw_type Hardware type per RFC 1700 (typically 1 for Ethernet)
 * @param clid Client identifier from DHCP option 61, NULL if client did not provide clid
 * @param clid_len Length of client identifier in bytes (0 if clid is NULL)
 * 
 * @return Pointer to matching dhcp_lease structure, or NULL if no match found
 * @retval non-NULL Lease found matching clid or hwaddr parameters
 * @retval NULL No matching lease found in database, or all leases filtered out (DHCPv6 only)
 * 
 * @note Client identifier (clid) match takes precedence over hardware address match per RFC 2131
 * @note Hardware address matching only occurs if no clid provided or no clid match found
 * @note DHCPv6 leases excluded from search via LEASE_TA and LEASE_NA flag checks
 * @note Function performs linear search through lease list; O(n) complexity
 * 
 * @warning hwaddr buffer must contain at least hw_len valid bytes; no bounds checking performed
 * @warning clid buffer must contain at least clid_len valid bytes if clid is non-NULL
 * 
 * @see lease_find_by_addr() for finding lease by assigned IP address
 * @see lease6_find() for DHCPv6 lease lookup by IAID and client DUID
 * @see RFC 2131 Section 4.2 for client identifier usage in DHCPv4
 * 
 * EXAMPLE USAGE:
 * @code
 * unsigned char mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
 * unsigned char clid[7] = {0x01, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
 * struct dhcp_lease *lease = lease_find_by_client(mac, 6, ARPHRD_ETHER, clid, 7);
 * if (lease)
 *   // Existing lease found, extend lease time
 * else
 *   // No existing lease, allocate new address
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 2131 Section 4.2 (client identifier uniquely identifies client)
 * SIDE EFFECTS: None (read-only lease database traversal)
 * THREAD SAFETY: Single-threaded architecture; safe to call during request processing
 */
struct dhcp_lease *lease_find_by_client(unsigned char *hwaddr, int hw_len, int hw_type,
					unsigned char *clid, int clid_len)
{
  struct dhcp_lease *lease;

  if (clid)
    for (lease = leases; lease; lease = lease->next)
      {
#ifdef HAVE_DHCP6
	if (lease->flags & (LEASE_TA | LEASE_NA))
	  continue;
#endif
	if (lease->clid && clid_len == lease->clid_len &&
	    memcmp(clid, lease->clid, clid_len) == 0)
	  return lease;
      }
  
  for (lease = leases; lease; lease = lease->next)	
    {
#ifdef HAVE_DHCP6
      if (lease->flags & (LEASE_TA | LEASE_NA))
	continue;
#endif   
      if ((!lease->clid || !clid) && 
	  hw_len != 0 && 
	  lease->hwaddr_len == hw_len &&
	  lease->hwaddr_type == hw_type &&
	  memcmp(hwaddr, lease->hwaddr, hw_len) == 0)
	return lease;
    }

  return NULL;
}

/**
 * @brief Find DHCPv4 lease by assigned IPv4 address
 * 
 * @detailed Searches the active lease database for a DHCPv4 lease that has been assigned the 
 *           specified IPv4 address. This function performs a linear search through the lease 
 *           list, comparing the requested address against each lease's assigned address field. 
 *           DHCPv6 leases (identified by LEASE_TA or LEASE_NA flags) are excluded from the 
 *           search to prevent cross-protocol confusion in dual-stack environments. This function 
 *           is commonly used for address conflict detection (checking if an address is already 
 *           in use), DHCP REQUEST validation (verifying requested address availability), and 
 *           reverse lookup during lease database operations. The function returns the first 
 *           matching lease or NULL if the address is not currently assigned.
 * 
 * @param addr IPv4 address to search for in lease database (struct in_addr with s_addr field)
 * 
 * @return Pointer to matching dhcp_lease structure, or NULL if address not found
 * @retval non-NULL Lease found with matching addr.s_addr
 * @retval NULL Address not assigned to any DHCPv4 lease, or only assigned to DHCPv6 leases
 * 
 * @note Function performs linear search through lease list; O(n) complexity
 * @note DHCPv6 leases are explicitly excluded via LEASE_TA and LEASE_NA flag checks
 * @note Comparison uses s_addr field (32-bit network byte order IPv4 address)
 * 
 * @see lease_find_by_client() for finding lease by client identifier or hardware address
 * @see lease6_find_by_plain_addr() for DHCPv6 address lookup
 * @see address_available() in dhcp.c for checking address pool availability
 * 
 * EXAMPLE USAGE:
 * @code
 * struct in_addr requested_addr;
 * inet_pton(AF_INET, "192.168.1.100", &requested_addr);
 * struct dhcp_lease *lease = lease_find_by_addr(requested_addr);
 * if (lease)
 *   // Address already assigned to this lease
 * else
 *   // Address available for allocation
 * @endcode
 * 
 * SIDE EFFECTS: None (read-only lease database traversal)
 * THREAD SAFETY: Single-threaded architecture; safe to call during request processing
 */
struct dhcp_lease *lease_find_by_addr(struct in_addr addr)
{
  struct dhcp_lease *lease;

  for (lease = leases; lease; lease = lease->next)
    {
#ifdef HAVE_DHCP6
      if (lease->flags & (LEASE_TA | LEASE_NA))
	continue;
#endif  
      if (lease->addr.s_addr == addr.s_addr)
	return lease;
    }

  return NULL;
}

#ifdef HAVE_DHCP6
/* find address for {CLID, IAID, address} */
/**
 * @brief Find DHCPv6 lease by client DUID, IAID, lease type, and IPv6 address
 * 
 * @detailed Searches the active lease database for a DHCPv6 lease matching all four criteria: 
 *           client DUID (DHCP Unique Identifier), IAID (Identity Association Identifier), 
 *           lease type (TA or NA), and assigned IPv6 address. This comprehensive matching 
 *           algorithm implements RFC 3315 identity association semantics where a client can 
 *           have multiple leases distinguished by IAID and lease type. The function performs 
 *           a linear search with three-stage filtering: first checks lease type flags and 
 *           IAID match, then verifies IPv6 address equality, finally confirms client DUID 
 *           match. This strict matching ensures lease operations affect only the specific 
 *           identity association being renewed or released, preventing cross-IAID interference 
 *           in clients with multiple network interfaces or temporary addresses.
 * 
 * @param clid Client DUID (DHCP Unique Identifier) from DHCPv6 client identifier option, must not be NULL
 * @param clid_len Length of client DUID in bytes (typically 14-130 bytes per RFC 3315)
 * @param lease_type Lease type flag: LEASE_NA (non-temporary address) or LEASE_TA (temporary address)
 * @param iaid IAID (Identity Association Identifier) uniquely identifies this IA within client's DUIDs
 * @param addr Pointer to IPv6 address assigned to this lease, must not be NULL
 * 
 * @return Pointer to matching dhcp_lease structure, or NULL if no match found
 * @retval non-NULL Lease found matching all criteria (DUID, IAID, type, address)
 * @retval NULL No matching lease, or lease fails any of the four matching criteria
 * 
 * @note All four parameters must match for successful lease lookup (strict matching)
 * @note Function performs linear search through lease list; O(n) complexity
 * @note DHCPv4 leases are implicitly skipped (lack LEASE_NA or LEASE_TA flags)
 * @note IAID comparison uses exact integer match; lease->iaid must equal iaid parameter
 * 
 * @warning clid buffer must contain at least clid_len valid bytes; no bounds checking performed
 * @warning addr must be valid pointer to struct in6_addr; NULL addr will cause crash
 * @warning lease_type should be LEASE_NA or LEASE_TA; other values will not match any leases
 * 
 * @see lease6_find_by_plain_addr() for finding lease by IPv6 address only
 * @see lease_find_by_client() for DHCPv4 lease lookup
 * @see RFC 3315 Section 10 for Identity Association (IA) concept and IAID usage
 * @see RFC 3315 Section 22.4 for IA_NA (non-temporary address) semantics
 * @see RFC 3315 Section 22.5 for IA_TA (temporary address) semantics
 * 
 * EXAMPLE USAGE:
 * @code
 * unsigned char duid[14] = {0x00, 0x01, ...};  // Client DUID
 * struct in6_addr addr6;
 * inet_pton(AF_INET6, "2001:db8::100", &addr6);
 * unsigned int iaid = 0x12345678;
 * struct dhcp_lease *lease = lease6_find(duid, 14, LEASE_NA, iaid, &addr6);
 * if (lease)
 *   // Existing IA_NA lease found, extend lease time
 * else
 *   // No matching lease, allocate new address for this IAID
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 3315 Section 10 (Identity Association identification by IAID)
 * SIDE EFFECTS: None (read-only lease database traversal)
 * THREAD SAFETY: Single-threaded architecture; safe to call during DHCPv6 request processing
 */
struct dhcp_lease *lease6_find(unsigned char *clid, int clid_len, 
			       int lease_type, unsigned int iaid,
			       struct in6_addr *addr)
{
  struct dhcp_lease *lease;
  
  for (lease = leases; lease; lease = lease->next)
    {
      if (!(lease->flags & lease_type) || lease->iaid != iaid)
	continue;

      if (!IN6_ARE_ADDR_EQUAL(&lease->addr6, addr))
	continue;
      
      if ((clid_len != lease->clid_len ||
	   memcmp(clid, lease->clid, clid_len) != 0))
	continue;
      
      return lease;
    }
  
  return NULL;
}

/**
 * @brief Reset LEASE_USED flags on all DHCPv6 leases for address pool scanning
 * 
 * @detailed Clears the LEASE_USED flag on every lease in the active lease database, preparing 
 *           for a fresh address allocation scan. This function implements a mark-and-sweep 
 *           approach to DHCPv6 address selection: before scanning an address pool for available 
 *           addresses, lease6_reset() clears all USED markers, then during pool traversal each 
 *           existing lease is marked USED, allowing rapid identification of unallocated addresses 
 *           (those without USED markers). This two-phase algorithm avoids O(n*m) nested loops 
 *           (n=pool size, m=lease count) by using O(n+m) linear passes with flag marking. The 
 *           function operates globally on all leases regardless of type (TA/NA) or IAID, as 
 *           the subsequent pool scan will filter by relevant criteria. After reset, all leases 
 *           remain valid and active; only the temporary USED marker is cleared for the next 
 *           allocation operation.
 * 
 * @return void (no return value; modifies lease database in place)
 * 
 * @note Function operates on global leases linked list; affects all lease entries
 * @note LEASE_USED flag is ephemeral marker for address allocation algorithm; not persisted
 * @note Called before each DHCPv6 address pool scan to initialize marking phase
 * @note Does not affect lease validity, expiration, or any other lease properties
 * @note Performance: O(n) where n = number of active leases (linear traversal)
 * 
 * @warning Must be called before using lease6_find_by_client() or similar iteration that expects clean USED flags
 * @warning Not thread-safe; assumes single-threaded DHCPv6 request processing
 * @warning Does not discriminate by lease type; clears USED on both TA and NA leases
 * 
 * @see lease6_find_by_client() which relies on LEASE_USED flag being cleared initially
 * @see lease_find_max_addr6() which uses USED marking to identify allocated addresses
 * @see src/dhcp6.c address allocation logic that calls this before pool scanning
 * 
 * EXAMPLE USAGE:
 * @code
 * // Begin DHCPv6 address allocation for client request
 * lease6_reset();  // Clear all USED markers
 * // Iterate through client's existing leases, marking each as USED
 * for (lease = lease6_find_by_client(NULL, LEASE_NA, clid, clid_len, iaid);
 *      lease; lease = lease6_find_by_client(lease, LEASE_NA, clid, clid_len, iaid))
 *   lease->flags |= LEASE_USED;
 * // Now scan address pool; unmarked addresses are available for allocation
 * @endcode
 * 
 * RFC COMPLIANCE: Algorithm supports RFC 3315 address allocation requirements
 * SIDE EFFECTS: Modifies flags field of all leases in global lease database
 * THREAD SAFETY: Single-threaded architecture; not safe for concurrent access
 */
void lease6_reset(void)
{
  struct dhcp_lease *lease;
  
  for (lease = leases; lease; lease = lease->next)
    lease->flags &= ~LEASE_USED;
}

/**
 * @brief Enumerate DHCPv6 leases belonging to specific client (CLID) and IAID
 * 
 * @detailed Iterates through the global lease database to find leases matching the specified 
 *           client identifier (CLID), Identity Association Identifier (IAID), and lease type 
 *           (LEASE_TA or LEASE_NA). Supports iterative enumeration by accepting a 'first' 
 *           parameter that allows finding multiple matching leases through repeated calls. 
 *           The function skips leases marked with LEASE_USED flag, enabling mark-and-sweep 
 *           address allocation algorithms where lease6_reset() clears USED flags before 
 *           enumeration begins. CLID matching uses exact byte-for-byte comparison ensuring 
 *           correct client identification per RFC 3315 requirements. IAID matching ensures 
 *           the lease belongs to the correct Identity Association within the client's 
 *           configuration. This function is critical for DHCPv6 RENEW and REBIND processing 
 *           where the server must locate all leases assigned to a requesting client.
 * 
 * @param first Pointer to lease from which to continue enumeration; NULL starts from beginning
 * @param lease_type Lease type flag: LEASE_TA (temporary address) or LEASE_NA (non-temporary)
 * @param clid Client identifier (DUID) byte array from DHCPv6 request
 * @param clid_len Length of client identifier in bytes (typically 10-130 bytes)
 * @param iaid Identity Association Identifier (32-bit value from DHCPv6 IA_NA or IA_TA option)
 * 
 * @return Pointer to next matching dhcp_lease structure, or NULL if no more matches
 * @retval struct dhcp_lease* Next lease matching all criteria (CLID, IAID, type, not USED)
 * @retval NULL No (more) leases match the specified criteria
 * 
 * @note Function skips leases with LEASE_USED flag set; call lease6_reset() before first use
 * @note Supports iterative enumeration: pass returned lease as 'first' for next call
 * @note CLID comparison is case-sensitive byte-exact match (uses memcmp)
 * @note IAID is 32-bit identifier allowing multiple IAs per client
 * @note Performance: O(n) where n = number of leases (linear traversal from 'first')
 * 
 * @warning Caller must not modify global leases list during enumeration iteration
 * @warning CLID pointer must remain valid throughout enumeration if iterating multiple times
 * @warning Not thread-safe; assumes single-threaded DHCPv6 request processing
 * @warning Returns pointer to lease structure in active database; lifetime tied to lease validity
 * 
 * @see lease6_reset() must be called before enumeration to clear LEASE_USED flags
 * @see lease6_find() for finding lease by address instead of client identifier
 * @see lease6_allocate() which uses this function to check existing client leases
 * @see src/dhcp6.c RENEW/REBIND processing that enumerates client leases
 * 
 * EXAMPLE USAGE:
 * @code
 * // Find all NA leases for client during RENEW processing
 * unsigned char *clid = ...; // Client DUID from request
 * int clid_len = 12;         // DUID length
 * unsigned int iaid = 0x12345678; // IA_NA identifier
 * struct dhcp_lease *lease = NULL;
 * 
 * lease6_reset();  // Clear USED flags before enumeration
 * while ((lease = lease6_find_by_client(lease, LEASE_NA, clid, clid_len, iaid)))
 * {
 *   // Process each matching lease (renew, validate, mark as USED)
 *   lease->flags |= LEASE_USED;
 *   lease_set_expires(lease, now + lease_time, now);
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 3315 Section 10 (Assignment of Addresses), Section 18 (RENEW/REBIND)
 * SIDE EFFECTS: None (read-only traversal; caller typically sets LEASE_USED flag)
 * THREAD SAFETY: Single-threaded architecture; not safe for concurrent enumeration
 */
struct dhcp_lease *lease6_find_by_client(struct dhcp_lease *first, int lease_type,
					 unsigned char *clid, int clid_len,
					 unsigned int iaid)
{
  struct dhcp_lease *lease;

  if (!first)
    first = leases;
  else
    first = first->next;

  for (lease = first; lease; lease = lease->next)
    {
      if (lease->flags & LEASE_USED)
	continue;

      if (!(lease->flags & lease_type) || lease->iaid != iaid)
	continue;
 
      if ((clid_len != lease->clid_len ||
	   memcmp(clid, lease->clid, clid_len) != 0))
	continue;

      return lease;
    }
  
  return NULL;
}

/**
 * @brief Find DHCPv6 lease by IPv6 network prefix and address suffix
 * 
 * @detailed Locates a DHCPv6 lease matching the specified network prefix and address within 
 *           that network. Supports both full /128 address matching and partial prefix-based 
 *           matching where the network portion is compared via prefix length while the host 
 *           portion is compared via the addr parameter. This dual-mode operation enables 
 *           efficient lease lookup during address allocation (checking if specific host ID 
 *           within subnet is allocated) and lease renewal (exact /128 match). The function 
 *           filters to only LEASE_TA (temporary address) or LEASE_NA (non-temporary address) 
 *           lease types, skipping DHCPv4 leases and other internal lease representations. 
 *           Network comparison uses is_same_net6() which masks both addresses to prefix 
 *           length before comparison, ensuring correct subnet matching for hierarchical 
 *           IPv6 address assignments. Address suffix comparison uses addr6part() to extract 
 *           the lower 64 bits of the IPv6 address, supporting RFC 3315 stateful address 
 *           allocation where network administrators typically delegate /64 prefixes.
 * 
 * @param net IPv6 network address defining the subnet to search within
 * @param prefix Prefix length in bits (0-128); 128 means exact address match
 * @param addr Lower 64-bit host portion (u64) of target address when prefix < 128
 * 
 * @return Pointer to matching dhcp_lease structure, or NULL if not found
 * @retval struct dhcp_lease* Lease with address in specified network and matching host ID
 * @retval NULL No DHCPv6 lease matches the network/address combination
 * 
 * @note Only searches DHCPv6 leases (LEASE_TA or LEASE_NA flags set)
 * @note For prefix=128, performs exact /128 address match (addr parameter ignored)
 * @note For prefix<128, matches network via prefix and host portion via addr parameter
 * @note Uses is_same_net6() for network comparison (prefix-length masking)
 * @note Uses addr6part() to extract lower 64 bits for host comparison
 * @note Performance: O(n) where n = number of leases (linear traversal)
 * 
 * @warning net pointer must point to valid in6_addr structure
 * @warning prefix must be 0-128; values >128 produce undefined behavior
 * @warning addr parameter only meaningful when prefix < 128
 * @warning Returns pointer to lease in active database; lifetime tied to lease validity
 * @warning Not thread-safe; assumes single-threaded DHCPv6 processing
 * 
 * @see lease6_find_by_plain_addr() for simpler exact address matching without prefix
 * @see lease6_allocate() which uses this to check address availability during allocation
 * @see is_same_net6() in src/network.c for network prefix comparison logic
 * @see addr6part() macro extracting lower 64 bits of IPv6 address
 * 
 * EXAMPLE USAGE:
 * @code
 * // Check if address 2001:db8:1::100 is allocated in subnet 2001:db8:1::/64
 * struct in6_addr net;
 * inet_pton(AF_INET6, "2001:db8:1::", &net);
 * u64 host_id = 0x100;  // Host portion
 * struct dhcp_lease *lease = lease6_find_by_addr(&net, 64, host_id);
 * if (lease)
 *   printf("Address allocated to DUID %s\n", lease->clid);
 * else
 *   printf("Address available for allocation\n");
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 3315 Section 10 (Assignment of Addresses)
 * SIDE EFFECTS: None (read-only lease database traversal)
 * THREAD SAFETY: Single-threaded architecture; not safe for concurrent access
 */
struct dhcp_lease *lease6_find_by_addr(struct in6_addr *net, int prefix, u64 addr)
{
  struct dhcp_lease *lease;
    
  for (lease = leases; lease; lease = lease->next)
    {
      if (!(lease->flags & (LEASE_TA | LEASE_NA)))
	continue;
      
      if (is_same_net6(&lease->addr6, net, prefix) &&
	  (prefix == 128 || addr6part(&lease->addr6) == addr))
	return lease;
    }
  
  return NULL;
} 

/**
 * @brief Find DHCPv6 lease by exact IPv6 address match
 * 
 * @detailed Performs simple exact-match lookup of DHCPv6 leases by complete 128-bit IPv6 
 *           address. This function provides straightforward address-to-lease mapping without 
 *           the network prefix complexity of lease6_find_by_addr(). The search filters to 
 *           only DHCPv6 lease types (LEASE_TA for temporary addresses per RFC 4941, LEASE_NA 
 *           for non-temporary addresses per RFC 3315), skipping DHCPv4 leases and internal 
 *           lease records. Address comparison uses the standard IPv6 IN6_ARE_ADDR_EQUAL macro 
 *           which performs byte-by-byte comparison of the full 128-bit address, ensuring 
 *           correct identification even for link-local, unique-local, or global unicast 
 *           addresses. This function is commonly used during lease file parsing to associate 
 *           vendor class or relay agent information with existing lease records, and during 
 *           DHCPv6 DECLINE processing to mark addresses as unavailable.
 * 
 * @param addr Pointer to IPv6 address (in6_addr structure) to search for
 * 
 * @return Pointer to matching dhcp_lease structure, or NULL if not found
 * @retval struct dhcp_lease* Lease with IPv6 address exactly matching addr parameter
 * @retval NULL No DHCPv6 lease has the specified address
 * 
 * @note Only searches DHCPv6 leases (LEASE_TA or LEASE_NA flags set)
 * @note Uses IN6_ARE_ADDR_EQUAL for full 128-bit address comparison
 * @note Simpler than lease6_find_by_addr() which requires network prefix parameters
 * @note Performance: O(n) where n = number of leases (linear traversal)
 * 
 * @warning addr pointer must point to valid in6_addr structure
 * @warning Returns pointer to lease in active database; lifetime tied to lease validity
 * @warning Not thread-safe; assumes single-threaded DHCPv6 processing
 * @warning Does not validate that addr is a valid unicast address
 * 
 * @see lease6_find_by_addr() for network-prefix-aware lease lookup
 * @see lease6_find() which searches by address and other criteria
 * @see IN6_ARE_ADDR_EQUAL() macro in system headers for address comparison
 * @see src/lease.c:read_leases() which uses this during lease file parsing
 * 
 * EXAMPLE USAGE:
 * @code
 * // During lease file parsing, associate vendor class with existing lease
 * struct in6_addr addr;
 * if (inet_pton(AF_INET6, "2001:db8::1234", &addr))
 * {
 *   struct dhcp_lease *lease = lease6_find_by_plain_addr(&addr);
 *   if (lease)
 *     lease_set_vendorclass(lease, vendor_data, vendor_len);
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 3315 (DHCPv6), RFC 4941 (IPv6 Privacy Extensions/Temporary Addresses)
 * SIDE EFFECTS: None (read-only lease database traversal)
 * THREAD SAFETY: Single-threaded architecture; not safe for concurrent access
 */
struct dhcp_lease *lease6_find_by_plain_addr(struct in6_addr *addr)
{
  struct dhcp_lease *lease;
    
  for (lease = leases; lease; lease = lease->next)
    {
      if (!(lease->flags & (LEASE_TA | LEASE_NA)))
	continue;
      
      if (IN6_ARE_ADDR_EQUAL(&lease->addr6, addr))
	return lease;
    }
  
  return NULL;
}

/**
 * @brief Find largest assigned IPv6 address within a DHCPv6 context
 * 
 * @detailed Determines the highest allocated IPv6 address within a specified DHCPv6 address 
 *           range to support sequential address allocation strategies. The function extracts 
 *           the 64-bit host portion of allocated IPv6 addresses using addr6part() and 
 *           identifies the maximum value within the context's address range boundaries. This 
 *           enables efficient sequential address assignment where new leases receive the next 
 *           available address after the highest currently allocated address, minimizing address 
 *           space fragmentation and simplifying lease management. The function only examines 
 *           dynamic allocation contexts (excludes CONTEXT_STATIC and CONTEXT_PROXY), filtering 
 *           to DHCPv6 lease types (LEASE_TA for temporary addresses, LEASE_NA for non-temporary 
 *           addresses per RFC 3315), and validates that lease addresses fall within the same /64 
 *           network prefix using is_same_net6(). If no valid leases exist within the context, 
 *           the function returns the host portion of context->start6, allowing allocation to 
 *           begin from the range start address. This approach assumes IPv6 DHCPv6 deployments 
 *           typically use /64 prefixes per RFC 6177 recommendations, with sequential allocation 
 *           within the 64-bit host identifier space providing trillions of available addresses.
 * 
 * @param context Pointer to DHCPv6 context defining address range and allocation policy
 * 
 * @return 64-bit host portion of largest assigned IPv6 address in context
 * @retval u64 Host portion (lower 64 bits) of highest allocated address within range
 * @retval addr6part(&context->start6) If no leases found or all below range start
 * 
 * @note Only examines dynamic contexts (skips CONTEXT_STATIC and CONTEXT_PROXY flags)
 * @note Filters to DHCPv6 leases only (LEASE_TA or LEASE_NA flags set)
 * @note Assumes /64 network prefix per IPv6 DHCPv6 convention (RFC 6177)
 * @note Returns start6 host portion if no valid leases exist in range
 * @note Performance: O(n) where n = total lease count (full lease database traversal)
 * 
 * @warning context pointer must be valid and initialized with start6/end6 addresses
 * @warning Assumes addr6part() correctly extracts 64-bit host portion from in6_addr
 * @warning Not thread-safe; assumes single-threaded DHCPv6 address allocation
 * @warning Does not validate context->start6 and context->end6 form valid range
 * @warning Caller must ensure context represents /64 prefix for correct operation
 * 
 * @see lease6_allocate() which uses this function to find next available address
 * @see addr6part() macro/function extracting host portion from IPv6 address
 * @see is_same_net6() validating addresses share same /64 network prefix
 * @see src/dhcp6.c address allocation logic using sequential assignment
 * 
 * EXAMPLE USAGE:
 * @code
 * // Find next address to allocate in DHCPv6 context
 * struct dhcp_context *ctx = ...; // context with 2001:db8::/64 range
 * u64 max_addr = lease_find_max_addr6(ctx);
 * // Next allocation will start from max_addr + 1
 * u64 next_addr = max_addr + 1;
 * if (next_addr <= addr6part(&ctx->end6))
 *   allocate_address_from_host_part(next_addr);
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 3315 (DHCPv6), RFC 6177 (IPv6 Address Assignment to End Sites)
 * SIDE EFFECTS: None (read-only lease database traversal)
 * THREAD SAFETY: Single-threaded architecture; not safe for concurrent access
 */
u64 lease_find_max_addr6(struct dhcp_context *context)
{
  struct dhcp_lease *lease;
  u64 addr = addr6part(&context->start6);
  
  if (!(context->flags & (CONTEXT_STATIC | CONTEXT_PROXY)))
    for (lease = leases; lease; lease = lease->next)
      {
	if (!(lease->flags & (LEASE_TA | LEASE_NA)))
	  continue;

	if (is_same_net6(&lease->addr6, &context->start6, 64) &&
	    addr6part(&lease->addr6) > addr6part(&context->start6) &&
	    addr6part(&lease->addr6) <= addr6part(&context->end6) &&
	    addr6part(&lease->addr6) > addr)
	  addr = addr6part(&lease->addr6);
      }
  
  return addr;
}

#endif

/* Find largest assigned address in context */
/**
 * @brief Find the highest allocated IPv4 address within a DHCP context range
 * 
 * @detailed Scans all active DHCPv4 leases to identify the highest IP address currently
 *           allocated within the specified DHCP context's address range. Used for intelligent
 *           address pool management and allocation strategies that prefer sequential assignment.
 *           Skips static and proxy contexts as they don't participate in dynamic allocation.
 *           DHCPv6 leases (TA/NA) are also skipped to focus only on DHCPv4 addresses.
 * 
 * @param context DHCP context defining the address range to search. Must not be NULL.
 *                Context must have valid start and end addresses defining the pool.
 * 
 * @return The highest allocated IPv4 address within the context range. If no leases
 *         exist within the range, returns context->start (the first address in the pool).
 * 
 * @note For static or proxy contexts (CONTEXT_STATIC | CONTEXT_PROXY flags set),
 *       returns context->start immediately without scanning leases
 * @note Uses network byte order comparison via ntohl() for address arithmetic
 * @note DHCPv6 leases are filtered out via LEASE_TA | LEASE_NA flags check
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_context *ctx = ...; // Context with range 192.168.1.100-192.168.1.200
 * struct in_addr max_addr = lease_find_max_addr(ctx);
 * // max_addr now contains highest allocated address in range, or 192.168.1.100 if none
 * @endcode
 * 
 * SIDE EFFECTS: None - read-only operation on lease database
 * THREAD SAFETY: Single-threaded architecture - accesses global leases list
 */
struct in_addr lease_find_max_addr(struct dhcp_context *context)
{
  struct dhcp_lease *lease;
  struct in_addr addr = context->start;
  
  if (!(context->flags & (CONTEXT_STATIC | CONTEXT_PROXY)))
    for (lease = leases; lease; lease = lease->next)
      {
#ifdef HAVE_DHCP6
	if (lease->flags & (LEASE_TA | LEASE_NA))
	  continue;
#endif
	if (((unsigned)ntohl(lease->addr.s_addr)) > ((unsigned)ntohl(context->start.s_addr)) &&
	    ((unsigned)ntohl(lease->addr.s_addr)) <= ((unsigned)ntohl(context->end.s_addr)) &&
	    ((unsigned)ntohl(lease->addr.s_addr)) > ((unsigned)ntohl(addr.s_addr)))
	  addr = lease->addr;
      }
  
  return addr;
}

/**
 * @brief Allocate and initialize a new DHCP lease structure
 * 
 * @detailed Performs internal memory allocation for creating new lease entries in the global 
 *           lease database, enforcing the maximum lease limit (MAXLEASES from config.h, 
 *           default 1000) to prevent memory exhaustion. The function allocates a 
 *           dhcp_lease structure using whine_malloc() which logs memory allocation failures, 
 *           zero-initializes the entire structure to ensure clean state, and configures 
 *           initial values including LEASE_NEW flag marking the lease as newly created, 
 *           expires=1 to indicate uninitialized expiration time (real expiration set by 
 *           caller), and sentinel values hwaddr_len=256 (illegal value exceeding maximum 
 *           48-bit MAC address) to detect uninitialized hardware addresses. On platforms 
 *           with HAVE_BROKEN_RTC (systems lacking reliable real-time clock), sets 
 *           lease->length to 0xffffffff as illegal sentinel requiring duration-based lease 
 *           tracking instead of absolute expiration times. The newly allocated lease is 
 *           inserted at the head of the global leases linked list for O(1) insertion, and 
 *           file_dirty flag is set to trigger lease database persistence on next write cycle. 
 *           The leases_left counter (initialized to MAXLEASES at daemon startup) is 
 *           decremented to track remaining allocation capacity, preventing unbounded memory 
 *           growth under attack or misconfiguration.
 * 
 * @return Pointer to newly allocated and initialized dhcp_lease structure
 * @retval struct dhcp_lease* Valid lease structure pointer on success
 * @retval NULL If leases_left exhausted (hit MAXLEASES limit) or malloc fails
 * 
 * @note This is an internal static function called by lease4_allocate() and lease6_allocate()
 * @note Caller must populate lease address, MAC, hostname, and other fields after allocation
 * @note LEASE_NEW flag indicates lease not yet persisted to lease database file
 * @note Initial expires=1 is sentinel value; caller must set actual expiration time
 * @note hwaddr_len=256 is sentinel; caller must set to actual MAC length (typically 6 for Ethernet)
 * @note Lease inserted at head of global leases list (LIFO insertion order)
 * @note file_dirty=1 triggers asynchronous lease file write on next event loop iteration
 * @note leases_left counter prevents exceeding MAXLEASES (default 1000 from config.h:40)
 * 
 * @warning Returns NULL if MAXLEASES limit reached; caller must check for NULL return
 * @warning Returns NULL if memory allocation fails; whine_malloc logs error before returning NULL
 * @warning Caller must not directly free returned lease; use lease_prune() for removal
 * @warning Not thread-safe; assumes single-threaded access to global leases list
 * @warning HAVE_BROKEN_RTC platforms use duration-based lease tracking (length field)
 * @warning Sentinel values (expires=1, hwaddr_len=256) must be overwritten by caller
 * 
 * @see lease4_allocate() which calls this function for DHCPv4 leases
 * @see lease6_allocate() which calls this function for DHCPv6 leases
 * @see lease_prune() for removing and freeing expired leases
 * @see whine_malloc() in util.c for allocation with error logging
 * @see src/config.h MAXLEASES definition (line 40, default 1000)
 * 
 * EXAMPLE USAGE:
 * @code
 * // Internal usage by lease4_allocate()
 * struct dhcp_lease *lease = lease_allocate();
 * if (!lease)
 *   return NULL; // MAXLEASES exhausted or malloc failed
 * lease->addr.addr4 = ip_address; // Set IPv4 address
 * lease->expires = now + lease_time; // Set actual expiration
 * lease->hwaddr_len = 6; // Ethernet MAC length
 * memcpy(lease->hwaddr, mac_address, 6); // Copy MAC address
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (internal memory management)
 * SIDE EFFECTS: Inserts lease at head of global leases list; sets file_dirty flag; decrements leases_left counter
 * THREAD SAFETY: Single-threaded architecture; not safe for concurrent access to global leases list
 */
static struct dhcp_lease *lease_allocate(void)
{
  struct dhcp_lease *lease;
  if (!leases_left || !(lease = whine_malloc(sizeof(struct dhcp_lease))))
    return NULL;

  memset(lease, 0, sizeof(struct dhcp_lease));
  lease->flags = LEASE_NEW;
  lease->expires = 1;
#ifdef HAVE_BROKEN_RTC
  lease->length = 0xffffffff; /* illegal value */
#endif
  lease->hwaddr_len = 256; /* illegal value */
  lease->next = leases;
  leases = lease;
  
  file_dirty = 1;
  leases_left--;

  return lease;
}

/**
 * @brief Allocate and initialize a DHCPv4 lease record with IPv4 address
 * 
 * @detailed Convenience wrapper around lease_allocate() that allocates a new DHCPv4 lease
 *           record and initializes it with the specified IPv4 address. This function is
 *           the primary allocation entry point for DHCPv4 lease creation, called during
 *           DHCPDISCOVER/DHCPREQUEST processing when a client needs an address binding.
 *           The function performs three operations: calls lease_allocate() to obtain a
 *           lease structure from the pool, stores the IPv4 address in lease->addr, and
 *           increments the DHCPv4 allocation metric counter for monitoring. If allocation
 *           fails (leases_left exhausted or memory allocation failure), returns NULL.
 * 
 * @param addr IPv4 address to assign to the lease. Must be valid address from configured
 *             DHCP pool range. Typically selected by address_allocate() in dhcp.c based
 *             on availability and client requirements. Network byte order.
 * 
 * @return Pointer to newly allocated dhcp_lease structure on success, NULL on failure
 * @retval non-NULL Valid lease structure with addr field set, ready for configuration
 * @retval NULL Allocation failed due to exhausted lease pool (leases_left=0) or malloc failure
 * 
 * @note Allocated lease has default initialization from lease_allocate(): flags=0, all pointers NULL
 * @note Caller must configure additional lease fields: MAC address, hostname, lease time, etc.
 * @note Allocated lease is added to global leases list by lease_allocate()
 * @note Decrements global leases_left counter via lease_allocate()
 * 
 * @warning Returns NULL if no leases available (check before dereferencing return value)
 * @warning Allocated lease not persisted to disk until lease_update_file() called
 * @warning Does not validate addr is within configured DHCP pool (caller responsibility)
 * 
 * @see lease_allocate() for core allocation logic and pool management
 * @see address_allocate() in src/dhcp.c for IPv4 address selection algorithm
 * @see lease_update_file() for lease persistence to disk
 * @see daemon->metrics[METRIC_LEASES_ALLOCATED_4] for allocation counter
 * 
 * EXAMPLE USAGE:
 * @code
 * // During DHCPREQUEST processing (from src/dhcp.c)
 * struct in_addr client_addr;
 * client_addr.s_addr = htonl(0xC0A80164);  // 192.168.1.100
 * struct dhcp_lease *lease = lease4_allocate(client_addr);
 * if (lease) {
 *     lease_set_hwaddr(lease, client_mac, client_mac_len, client_mac_type, 0, 0, 0);
 *     lease_set_hostname(lease, "client-hostname", 1, get_domain(lease->addr), NULL);
 *     lease_set_expires(lease, 3600, now);  // 1 hour lease
 *     lease_update_file(now);  // Persist to disk
 * }
 * @endcode
 * 
 * RFC COMPLIANCE:
 * - RFC 2131 Section 3.1 (Server maintains client bindings including network address)
 * 
 * SIDE EFFECTS:
 * - Allocates heap memory via whine_malloc() in lease_allocate()
 * - Decrements global leases_left counter
 * - Increments daemon->metrics[METRIC_LEASES_ALLOCATED_4]
 * - Adds lease to global leases linked list
 * 
 * THREAD SAFETY: Single-threaded architecture - modifies global state without locking
 */
struct dhcp_lease *lease4_allocate(struct in_addr addr)
{
  struct dhcp_lease *lease = lease_allocate();
  if (lease)
    {
      lease->addr = addr;
      daemon->metrics[METRIC_LEASES_ALLOCATED_4]++;
    }
  
  return lease;
}

#ifdef HAVE_DHCP6
/**
 * @brief Allocate and initialize a DHCPv6 lease record with IPv6 address and type
 * 
 * @detailed Convenience wrapper around lease_allocate() that allocates a new DHCPv6 lease
 *           record and initializes it with the specified IPv6 address and lease type flags.
 *           This function is the primary allocation entry point for DHCPv6 lease creation,
 *           called during DHCPv6 message processing (SOLICIT, REQUEST, RENEW, REBIND) when
 *           a client needs an address binding. The function performs five operations: calls
 *           lease_allocate() to obtain a lease structure, stores the IPv6 address in lease->addr6,
 *           sets lease type flags (LEASE_TA for temporary addresses, or address family indicators),
 *           initializes IAID to 0 (caller must set via lease_set_iaid()), and increments the
 *           DHCPv6 allocation metric counter. If allocation fails (leases_left exhausted or
 *           memory allocation failure), returns NULL.
 * 
 * @param addrp Pointer to IPv6 address to assign to lease. Must not be NULL. Address is copied
 *              into lease->addr6. Must be valid address from configured DHCPv6 pool range.
 *              Typically selected by address6_allocate() in dhcp6.c based on availability,
 *              client DUID, and requested IA type. Network byte order (struct in6_addr).
 * @param lease_type Lease type flags to set in lease->flags. Valid values:
 *                   - LEASE_TA: Temporary address (IA_TA) per RFC 8415 Section 21.5
 *                   - 0: Non-temporary address (IA_NA) per RFC 8415 Section 21.4
 *                   - Or other DHCPv6-specific flags from dnsmasq.h
 *                   Flags are OR'd into lease->flags field (does not clear existing flags).
 * 
 * @return Pointer to newly allocated dhcp_lease structure on success, NULL on failure
 * @retval non-NULL Valid lease structure with addr6, flags, iaid=0 set, ready for configuration
 * @retval NULL Allocation failed due to exhausted lease pool (leases_left=0) or malloc failure
 * 
 * @note Allocated lease has IAID initialized to 0 - caller MUST set via lease_set_iaid()
 * @note Caller must configure additional fields: DUID, hostname, lease time, etc.
 * @note Allocated lease added to global leases list by lease_allocate()
 * @note Decrements global leases_left counter via lease_allocate()
 * @note Available only when compiled with HAVE_DHCP6 feature flag
 * 
 * @warning Returns NULL if no leases available (check before dereferencing return value)
 * @warning addrp must not be NULL (no NULL pointer validation performed)
 * @warning Allocated lease not persisted to disk until lease_update_file() called
 * @warning Does not validate addr is within configured DHCPv6 pool (caller responsibility)
 * @warning IAID initialized to 0 - caller MUST set to client's IAID via lease_set_iaid()
 * 
 * @see lease_allocate() for core allocation logic and pool management
 * @see address6_allocate() in src/dhcp6.c for IPv6 address selection algorithm
 * @see lease_set_iaid() for setting Identity Association Identifier
 * @see lease_update_file() for lease persistence to disk
 * @see daemon->metrics[METRIC_LEASES_ALLOCATED_6] for allocation counter
 * 
 * EXAMPLE USAGE:
 * @code
 * // During DHCPv6 REQUEST processing (from src/dhcp6.c)
 * struct in6_addr client_addr6;
 * inet_pton(AF_INET6, "2001:db8::100", &client_addr6);
 * struct dhcp_lease *lease = lease6_allocate(&client_addr6, 0);  // IA_NA
 * if (lease) {
 *     lease_set_iaid(lease, 0x12345678);  // Client's IAID from IA_NA option
 *     lease6_set_duid(lease, client_duid, client_duid_len);
 *     lease_set_hostname(lease, "client6-hostname", 1, get_domain6(&lease->addr6), NULL);
 *     lease_set_expires(lease, 86400, now);  // 24 hour lease
 *     lease_update_file(now);  // Persist to disk
 * }
 * 
 * // For temporary address (IA_TA):
 * struct dhcp_lease *ta_lease = lease6_allocate(&temp_addr6, LEASE_TA);
 * @endcode
 * 
 * RFC COMPLIANCE:
 * - RFC 8415 Section 18.2.1 (IA_NA - non-temporary address binding)
 * - RFC 8415 Section 18.2.2 (IA_TA - temporary address binding)
 * - RFC 8415 Section 12 (Identity Association - IAID usage)
 * 
 * SIDE EFFECTS:
 * - Allocates heap memory via whine_malloc() in lease_allocate()
 * - Decrements global leases_left counter
 * - Increments daemon->metrics[METRIC_LEASES_ALLOCATED_6]
 * - Adds lease to global leases linked list
 * - Copies 16 bytes from *addrp to lease->addr6
 * 
 * THREAD SAFETY: Single-threaded architecture - modifies global state without locking
 */
struct dhcp_lease *lease6_allocate(struct in6_addr *addrp, int lease_type)
{
  struct dhcp_lease *lease = lease_allocate();

  if (lease)
    {
      lease->addr6 = *addrp;
      lease->flags |= lease_type;
      lease->iaid = 0;

      daemon->metrics[METRIC_LEASES_ALLOCATED_6]++;
    }

  return lease;
}
#endif

/**
 * @brief Set or update the expiration time for a DHCP lease
 * 
 * @detailed Calculates and assigns the expiration timestamp for a DHCP lease based on the
 *           requested lease duration in seconds. Handles three special scenarios: infinite
 *           leases (len=0xffffffff → exp=0), 2038 overflow protection (for 32-bit time_t
 *           systems where now+len wraps to negative → exp=0 for infinite), and broken RTC
 *           systems where absolute timestamps are unreliable (stores relative lease length
 *           instead). When expiration changes, sets dns_dirty flag to trigger DNS cache
 *           updates (lease hostname becomes unavailable after expiration), sets LEASE_AUX_CHANGED
 *           and LEASE_EXP_CHANGED flags for lease file persistence, and sets file_dirty to
 *           trigger script notification. Called during DHCP ACK processing with negotiated
 *           lease time from DHCP offer/request exchange.
 * 
 * @param lease Lease record to update with new expiration. Must not be NULL.
 * @param len Requested lease duration in seconds. Special values: 0xffffffff indicates
 *            infinite lease (stored as expires=0), 0 indicates immediate expiration,
 *            typical values range from 600 (10 minutes) to 86400 (24 hours). Maximum
 *            value is 0xfffffffe (~136 years) before triggering overflow handling.
 * @param now Current time_t timestamp (from time(NULL) or equivalent). Used as base for
 *            calculating absolute expiration timestamp exp = now + len.
 * 
 * @return void - no return value
 * 
 * @note Infinite lease represented as expires=0 (checked via difftime or len==0xffffffff)
 * @note 2038 overflow detection: difftime(exp, now) <= 0.0 indicates wraparound on 32-bit time_t
 * @note Sets dns_dirty=1 when expiration changes to trigger DNS cache consistency update
 * @note On platforms without HAVE_BROKEN_RTC: sets LEASE_AUX_CHANGED, LEASE_EXP_CHANGED flags
 * @note On platforms with HAVE_BROKEN_RTC: stores lease length rather than absolute expiration
 * @note Sets file_dirty=1 to trigger asynchronous lease file write and script execution
 * @warning 2038 problem: 32-bit time_t systems make leases infinite after January 19, 2038
 * @warning HAVE_BROKEN_RTC systems (embedded devices with unreliable clocks) use relative time
 * 
 * @see lease_update_from_configs for initial lease creation with default expiration
 * @see lease_prune for expired lease cleanup based on expires timestamp
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_lease *lease = lease_find_by_addr(client_addr);
 * time_t now = dnsmasq_time();
 * unsigned int lease_time = 3600; // 1 hour lease
 * lease_set_expires(lease, lease_time, now);
 * // Lease now expires at now+3600; dns_dirty and file_dirty set for propagation
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 2131 Section 3.3 (lease time option 51, infinite lease = 0xffffffff)
 * SIDE EFFECTS: Sets dns_dirty=1 global flag; sets lease->flags LEASE_AUX_CHANGED, LEASE_EXP_CHANGED;
 *               sets file_dirty=1 global flag; modifies lease->expires or lease->length
 * THREAD SAFETY: Single-threaded architecture - modifies lease structure and global state
 */
void lease_set_expires(struct dhcp_lease *lease, unsigned int len, time_t now)
{
  time_t exp;

  if (len == 0xffffffff)
    {
      exp = 0;
      len = 0;
    }
  else
    {
      exp = now + (time_t)len;
      /* Check for 2038 overflow. Make the lease
	 infinite in that case, as the least disruptive
	 thing we can do. */
      if (difftime(exp, now) <= 0.0)
	exp = 0;
    }

  if (exp != lease->expires)
    {
      dns_dirty = 1;
      lease->expires = exp;
#ifndef HAVE_BROKEN_RTC
      lease->flags |= LEASE_AUX_CHANGED | LEASE_EXP_CHANGED;
      file_dirty = 1;
#endif
    }
  
#ifdef HAVE_BROKEN_RTC
  if (len != lease->length)
    {
      lease->length = len;
      lease->flags |= LEASE_AUX_CHANGED;
      file_dirty = 1; 
    }
#endif
} 

#ifdef HAVE_DHCP6
/**
 * @brief Update DHCPv6 Identity Association Identifier (IAID) for a lease
 * 
 * @detailed Updates the IAID field of a DHCPv6 lease record, marking the lease as changed
 *           if the IAID value differs from the current stored value. The IAID is a unique
 *           identifier chosen by the DHCPv6 client to identify an Identity Association (IA)
 *           for non-temporary addresses (IA_NA), temporary addresses (IA_TA), or prefix
 *           delegation (IA_PD). This function is called during DHCPv6 message processing
 *           (SOLICIT, REQUEST, RENEW, REBIND) to track the client's IAID and associate
 *           it with the lease binding. Changes to IAID trigger the LEASE_CHANGED flag,
 *           causing lease file update and potential script execution on next lease_update_file().
 * 
 * @param lease DHCPv6 lease record to update. Must not be NULL. Lease must be a DHCPv6 lease
 *              (lease->flags & LEASE_TA or similar DHCPv6 indicators).
 * @param iaid Identity Association Identifier from DHCPv6 IA_NA, IA_TA, or IA_PD option.
 *             32-bit unsigned integer chosen by client, typically derived from interface index
 *             or stable identifier. Value 0 is valid per RFC 8415 Section 12.
 * 
 * @return void - Function does not return a value
 * 
 * @note Function only sets LEASE_CHANGED flag if iaid differs from current lease->iaid
 * @note LEASE_CHANGED flag triggers lease persistence and script execution on next update cycle
 * @note Function is no-op if iaid matches current value (avoids unnecessary flag setting)
 * @note Available only when compiled with HAVE_DHCP6 feature flag
 * 
 * @warning Assumes lease pointer is valid and points to DHCPv6 lease structure
 * @warning Does not validate that lease is actually a DHCPv6 lease (caller responsibility)
 * 
 * @see lease_update_file() for lease file persistence triggered by LEASE_CHANGED
 * @see do_script_run() for script execution on lease changes
 * @see struct dhcp_lease in src/dnsmasq.h for lease->iaid field definition
 * 
 * EXAMPLE USAGE:
 * @code
 * // During DHCPv6 REQUEST processing (from src/rfc3315.c)
 * struct dhcp_lease *lease = lease6_allocate(&client_addr, IA_NA);
 * unsigned int client_iaid = 0x12345678;  // From IA_NA option
 * lease_set_iaid(lease, client_iaid);
 * // Lease now tracks IAID; LEASE_CHANGED flag set for persistence
 * @endcode
 * 
 * RFC COMPLIANCE:
 * - RFC 8415 Section 12 (Identity Association - IAID definition and usage)
 * - RFC 8415 Section 18.2.1 (IA_NA option includes IAID field)
 * 
 * SIDE EFFECTS:
 * - Sets lease->iaid to provided value if different from current
 * - Sets lease->flags |= LEASE_CHANGED if iaid changes
 * - Indirectly triggers file_dirty=1 on lease_update_file() via LEASE_CHANGED
 * 
 * THREAD SAFETY: Single-threaded architecture - modifies lease structure without locking
 */
void lease_set_iaid(struct dhcp_lease *lease, unsigned int iaid)
{
  if (lease->iaid != iaid)
    {
      lease->iaid = iaid;
      lease->flags |= LEASE_CHANGED;
    }
}
#endif

/**
 * @brief Update hardware address and client identifier for a DHCP lease
 * 
 * @detailed Updates the hardware address (MAC address) and client identifier (CLID) 
 *           information for an existing DHCP lease, tracking whether changes have occurred
 *           that require lease file persistence and script execution. Called during DHCP
 *           request processing (DHCPREQUEST, DHCPRENEW) to maintain accurate client identity
 *           tracking across lease lifecycle. Hardware address changes trigger LEASE_CHANGED
 *           flag and file_dirty to ensure script notification. Client identifier updates
 *           are conditional - only applied when a CLID is present to prevent packets without
 *           CLID from erasing the existing record. Memory management handles CLID reallocation
 *           when size changes. For DHCPv6 leases, triggers SLAAC address addition when changes
 *           detected.
 * 
 * @param lease Lease record to update. Must not be NULL.
 * @param hwaddr New hardware address (MAC address) to store. May be NULL if hw_len=0.
 *               Typically 6 bytes for Ethernet (00:11:22:33:44:55).
 * @param clid Client identifier from DHCP option 61. May be NULL if no CLID present.
 *             Variable length identifier uniquely identifying the client.
 * @param hw_len Length of hardware address in bytes (typically 6 for Ethernet, 0 for none)
 * @param hw_type Hardware type from ARP HTYPE field (typically 1 for Ethernet per RFC 1700)
 * @param clid_len Length of client identifier in bytes. 0 indicates no CLID present.
 *                 Maximum length typically 255 bytes per DHCP specification.
 * @param now Current time_t timestamp - unused but passed through for DHCPv6 SLAAC
 * @param force Force SLAAC address update even if no hardware/CLID changes (DHCPv6 only)
 * 
 * @return void - no return value
 * 
 * @note Hardware address updated only if length, type, or content differs from current value
 * @note Client identifier updated only when clid_len != 0 and clid != NULL (prevents erasure)
 * @note Sets LEASE_CHANGED flag when hardware address changes
 * @note Sets LEASE_AUX_CHANGED flag when client identifier changes
 * @note Sets file_dirty global to trigger lease file write and script execution
 * @note For DHCPv6 (HAVE_DHCP6), sets LEASE_HAVE_HWADDR flag and calls slaac_add_addrs on change
 * @warning Memory allocation failure for CLID causes early return without completing update
 * @warning Modifies global file_dirty state affecting entire lease database persistence
 * 
 * @see lease_update_from_configs for lease creation with initial hardware address
 * @see slaac_add_addrs in src/slaac.c for DHCPv6 stateless address autoconfiguration
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_lease *lease = lease_find_by_addr(client_addr);
 * unsigned char mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
 * unsigned char clid[8] = {0x01, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x00};
 * lease_set_hwaddr(lease, mac, clid, 6, ARPHRD_ETHER, 8, time(NULL), 0);
 * // Lease now has updated MAC and CLID; file_dirty=1 triggers persistence
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 2131 Section 4.2 (DHCP client identifier option 61)
 * SIDE EFFECTS: Sets LEASE_CHANGED, LEASE_AUX_CHANGED, LEASE_HAVE_HWADDR flags;
 *               sets global file_dirty=1; may trigger slaac_add_addrs for DHCPv6;
 *               allocates/frees memory for CLID storage
 * THREAD SAFETY: Single-threaded architecture - modifies lease structure and global state
 */
void lease_set_hwaddr(struct dhcp_lease *lease, const unsigned char *hwaddr,
		      const unsigned char *clid, int hw_len, int hw_type,
		      int clid_len, time_t now, int force)
{
#ifdef HAVE_DHCP6
  int change = force;
  lease->flags |= LEASE_HAVE_HWADDR;
#endif

  (void)force;
  (void)now;

  if (hw_len != lease->hwaddr_len ||
      hw_type != lease->hwaddr_type || 
      (hw_len != 0 && memcmp(lease->hwaddr, hwaddr, hw_len) != 0))
    {
      if (hw_len != 0)
	memcpy(lease->hwaddr, hwaddr, hw_len);
      lease->hwaddr_len = hw_len;
      lease->hwaddr_type = hw_type;
      lease->flags |= LEASE_CHANGED;
      file_dirty = 1; /* run script on change */
    }

  /* only update clid when one is available, stops packets
     without a clid removing the record. Lease init uses
     clid_len == 0 for no clid. */
  if (clid_len != 0 && clid)
    {
      if (!lease->clid)
	lease->clid_len = 0;

      if (lease->clid_len != clid_len)
	{
	  lease->flags |= LEASE_AUX_CHANGED;
	  file_dirty = 1;
	  free(lease->clid);
	  if (!(lease->clid = whine_malloc(clid_len)))
	    return;
#ifdef HAVE_DHCP6
	  change = 1;
#endif	   
	}
      else if (memcmp(lease->clid, clid, clid_len) != 0)
	{
	  lease->flags |= LEASE_AUX_CHANGED;
	  file_dirty = 1;
#ifdef HAVE_DHCP6
	  change = 1;
#endif	
	}
      
      lease->clid_len = clid_len;
      memcpy(lease->clid, clid, clid_len);
    }
  
#ifdef HAVE_DHCP6
  if (change)
    slaac_add_addrs(lease, now, force);
#endif
}

/**
 * @brief Prepare lease for hostname change by preserving old hostname for script notification
 * 
 * @detailed Internal helper function that manages the hostname transition process when a DHCP
 *           lease's hostname changes or is removed. This function is called before setting a
 *           new hostname via lease_set_hostname(), ensuring that the previous hostname is
 *           preserved in lease->old_hostname so that lease-change scripts can be notified of
 *           the old name being deleted (via "del" action with old name, followed by "add"
 *           action with new name). The function implements three key operations: (1) frees any
 *           existing old_hostname to prevent memory leaks if rapid hostname updates occur before
 *           scripts complete execution, (2) transfers the current hostname to old_hostname,
 *           preferring the fully-qualified domain name (FQDN) if available since helper scripts
 *           can derive unqualified names from FQDNs, and (3) nullifies hostname and fqdn
 *           pointers to prepare for new values. The function does not deallocate the transferred
 *           hostname memory - ownership transfers to old_hostname, which will be freed after
 *           script execution completes in do_script_run().
 * 
 * @param lease Pointer to dhcp_lease structure whose hostname is being changed. Must not be NULL.
 *              The lease's hostname, fqdn, and old_hostname fields are modified. Typical usage
 *              occurs during DHCP message processing when client hostname changes (different
 *              hostname option in DHCPREQUEST) or when lease is being prepared for deletion.
 *              After this function, lease->hostname and lease->fqdn are NULL, and
 *              lease->old_hostname contains the previous name for script notification.
 * 
 * @return void (no return value)
 * 
 * @note This is a static internal function, not part of the public lease management API
 * @note Preferentially transfers fqdn to old_hostname if available (fqdn preferred over hostname)
 * @note Helper scripts receive FQDN in old_hostname and derive unqualified name internally
 * @note Memory ownership transfer: hostname/fqdn ownership transfers to old_hostname
 * @note Prevents memory leak by freeing existing old_hostname before assignment
 * @note Does not invoke scripts - merely prepares lease state for subsequent script execution
 * @note Called by lease_set_hostname() before setting new hostname
 * 
 * @warning lease parameter must not be NULL (no NULL pointer validation performed)
 * @warning Caller must ensure proper script execution to free old_hostname memory
 * @warning Rapid hostname changes may cause old_hostname leak if scripts don't complete
 * @warning After this function, lease->hostname and lease->fqdn are NULL (must be set anew)
 * 
 * @see lease_set_hostname() for hostname assignment that calls this function
 * @see do_script_run() for script execution that frees old_hostname after notification
 * @see rerun_scripts() for script invocation with "del" action for old hostname
 * @see lease_calc_fqdns() for FQDN generation from hostname + domain
 * 
 * EXAMPLE USAGE:
 * @code
 * // Internal usage within lease_set_hostname() (from src/lease.c)
 * struct dhcp_lease *lease = lease_find_by_addr(client_ip);
 * if (lease->hostname)
 *     kill_name(lease);  // Preserve old name before setting new
 * lease->hostname = whine_malloc(strlen(new_name) + 1);
 * strcpy(lease->hostname, new_name);
 * lease_calc_fqdns();  // Regenerate FQDN
 * dns_dirty = 1;  // Mark DNS cache update needed
 * // Later, rerun_scripts() will invoke script with "del" action for old_hostname
 * @endcode
 * 
 * SIDE EFFECTS:
 * - Frees memory at lease->old_hostname if non-NULL (prevents leak)
 * - Frees memory at lease->hostname if lease->fqdn exists (unqualified name freed)
 * - Transfers ownership of lease->hostname or lease->fqdn to lease->old_hostname
 * - Sets lease->hostname = NULL (must be assigned new value by caller)
 * - Sets lease->fqdn = NULL (must be regenerated by lease_calc_fqdns())
 * - Does not modify lease->flags, lease->addr, or other lease fields
 * 
 * THREAD SAFETY: Single-threaded architecture - modifies lease structure without locking
 */
static void kill_name(struct dhcp_lease *lease)
{
  /* run script to say we lost our old name */
  
  /* this shouldn't happen unless updates are very quick and the
     script very slow, we just avoid a memory leak if it does. */
  free(lease->old_hostname);
  
  /* If we know the fqdn, pass that. The helper will derive the
     unqualified name from it, free the unqualified name here. */

  if (lease->fqdn)
    {
      lease->old_hostname = lease->fqdn;
      free(lease->hostname);
    }
  else
    lease->old_hostname = lease->hostname;

  lease->hostname = lease->fqdn = NULL;
}

/**
 * @brief Calculate and assign fully-qualified domain names (FQDNs) for all leases with hostnames
 * 
 * @detailed Iterates through the global lease database and constructs fully-qualified domain names
 *           (FQDNs) for all leases that have unqualified hostnames. This function is called during
 *           daemon startup after lease database is loaded from disk but before the daemon forks,
 *           ensuring that all lease records have their FQDN fields populated for DNS registration
 *           and hostname resolution. For each lease with a hostname, the function determines the
 *           appropriate domain name based on lease type (IPv4 or IPv6) using get_domain() or
 *           get_domain6(), then constructs the FQDN as "hostname.domain" by concatenating the
 *           hostname, a period separator, and the domain name. Memory for the FQDN string is
 *           allocated via safe_malloc() since this function executes in the startup phase before
 *           daemon forking where allocation failures should terminate the process rather than
 *           being handled gracefully. DHCPv6 leases (LEASE_TA or LEASE_NA flags) use IPv6-specific
 *           domain lookup via get_domain6(&lease->addr6), while DHCPv4 leases use get_domain(lease->addr).
 *           If no domain is configured for a lease's address, the FQDN remains NULL and only the
 *           unqualified hostname is used for DNS registration.
 * 
 * @return void (no return value)
 * 
 * @note Called only during daemon startup, before forking, ensuring safe_malloc() is appropriate
 * @note Iterates through global leases linked list starting from head pointer
 * @note DHCPv6 leases identified by LEASE_TA or LEASE_NA flags set in lease->flags
 * @note DHCPv4 leases are any leases without DHCPv6 flags (default case)
 * @note Domain lookup is address-based: get_domain6() for IPv6, get_domain() for IPv4
 * @note FQDN format is always "hostname.domain" with single period separator
 * @note Memory allocated for lease->fqdn persists for lease lifetime, freed when lease deleted
 * @note Leases without hostnames (lease->hostname == NULL) are skipped, FQDN not generated
 * @note Leases without configured domains have NULL FQDN, unqualified hostname used in DNS
 * 
 * @warning Must be called before daemon forks (uses safe_malloc which exits on allocation failure)
 * @warning Assumes lease database loaded and global leases list populated
 * @warning Does not free existing lease->fqdn memory (assumes NULL on startup load)
 * @warning Modifies lease->fqdn field for all leases with hostnames and domains
 * @warning No NULL pointer validation on lease->hostname before strlen() call
 * 
 * @see lease_init() for lease database initialization that calls this function
 * @see get_domain() for IPv4 address-to-domain mapping (src/option.c)
 * @see get_domain6() for IPv6 address-to-domain mapping (src/option.c)
 * @see safe_malloc() for startup-phase memory allocation (src/util.c)
 * @see lease_set_hostname() for runtime hostname assignment that updates FQDN
 * @see kill_name() for FQDN memory deallocation during hostname changes
 * 
 * EXAMPLE USAGE:
 * @code
 * // During daemon startup (from src/dnsmasq.c main())
 * lease_init(now);  // Load lease database from disk
 * lease_calc_fqdns();  // Calculate FQDNs for loaded leases
 * // Now all leases have FQDN field populated for DNS registration
 * 
 * // Example lease state after this function:
 * // Lease with hostname="myhost" in domain "example.com" zone:
 * //   lease->hostname = "myhost"
 * //   lease->fqdn = "myhost.example.com"
 * 
 * // DHCPv6 lease with hostname="client6" in IPv6 zone "ipv6.example.com":
 * //   lease->hostname = "client6"
 * //   lease->fqdn = "client6.ipv6.example.com"
 * 
 * // Lease with hostname but no configured domain:
 * //   lease->hostname = "unqualified"
 * //   lease->fqdn = NULL  (no FQDN, only unqualified name in DNS)
 * @endcode
 * 
 * RFC COMPLIANCE:
 * - RFC 1123 Section 2.1 (hostname format requirements)
 * - RFC 1034 Section 3.1 (domain name syntax and FQDN construction)
 * - RFC 8415 Section 21.13 (DHCPv6 FQDN option for IPv6 clients)
 * 
 * SIDE EFFECTS:
 * - Allocates heap memory for lease->fqdn string via safe_malloc()
 * - Sets lease->fqdn = "hostname.domain" for all leases with hostname and domain
 * - Exits daemon on allocation failure (safe_malloc behavior in pre-fork phase)
 * - Reads global leases linked list starting from leases head pointer
 * - Calls get_domain() or get_domain6() for each lease with hostname
 * - No writes to lease database file (FQDNs computed on-demand from in-memory state)
 * - No DNS cache updates (DNS registration happens later in startup sequence)
 * 
 * THREAD SAFETY: Single-threaded architecture - called during startup before forking
 */
void lease_calc_fqdns(void)
{
  struct dhcp_lease *lease;
  
  for (lease = leases; lease; lease = lease->next)
    {
      char *domain;

      if (lease->hostname)
	{
#ifdef HAVE_DHCP6
	  if (lease->flags & (LEASE_TA | LEASE_NA))
	    domain = get_domain6(&lease->addr6);
	  else
#endif
	    domain = get_domain(lease->addr);
	  
	  if (domain)
	    {
	      /* This is called only during startup, before forking, hence safe_malloc() */
	      lease->fqdn = safe_malloc(strlen(lease->hostname) + strlen(domain) + 2);
	      
	      strcpy(lease->fqdn, lease->hostname);
	      strcat(lease->fqdn, ".");
	      strcat(lease->fqdn, domain);
	    }
	}
    }
}
	  
/**
 * @brief Set or update hostname for DHCP lease with conflict detection
 * 
 * @detailed Assigns hostname and fully-qualified domain name (FQDN) to a DHCP lease,
 *           with duplicate name detection across all existing leases. Handles IPv4/IPv6
 *           differences: IPv4 allows only one lease per name, IPv6 allows multiple leases
 *           with same name if they share the same DUID. Authenticated names from dnsmasq
 *           configuration take precedence over client-supplied names. Updates DNS cache
 *           via dns_dirty flag and triggers lease-change script via LEASE_CHANGED flag.
 * 
 * @param lease Pointer to lease structure to update. Must not be NULL.
 * @param name Hostname to assign (unqualified). NULL to clear hostname. Max 63 chars per RFC 1123.
 * @param auth Boolean: 1 if name from dnsmasq config (authoritative), 0 if from DHCP client
 * @param domain Domain name to append for FQDN construction. NULL for no domain.
 * @param config_domain Expected domain from configuration. Generates warning if domain mismatch.
 * 
 * @return void
 * 
 * @note If hostname unchanged, function returns early (no-op optimization)
 * @note Duplicate names removed from conflicting leases unless protected by LEASE_AUTH_NAME
 * @note IPv6 leases with same DUID allowed to share hostname (DHCPv6 multi-address model)
 * @note FQDN mode (OPT_DHCP_FQDN) checks fully-qualified names, otherwise checks unqualified
 * 
 * @warning Memory allocated for new_name and new_fqdn; freed by kill_name() or on conflict
 * @warning Modifies global dns_dirty and file_dirty flags requiring lease database write
 * 
 * @see kill_name() for DNS cache removal and memory cleanup
 * @see lease_update_from_configs() for authoritative name assignment
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_lease *lease = lease4_allocate(ipaddr);
 * lease_set_hostname(lease, "workstation1", 0, "example.com", NULL);
 * // Result: lease->hostname = "workstation1", lease->fqdn = "workstation1.example.com"
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 1123 (hostname requirements, 63 char max per label)
 * SIDE EFFECTS: Sets dns_dirty=1, file_dirty=1, lease->flags |= LEASE_CHANGED
 * THREAD SAFETY: Single-threaded architecture; modifies global state
 * 
 * Source: /src/lease.c:1774-1866
 */
void lease_set_hostname(struct dhcp_lease *lease, const char *name, int auth, char *domain, char *config_domain)
{
  struct dhcp_lease *lease_tmp;
  char *new_name = NULL, *new_fqdn = NULL;

  if (config_domain && (!domain || !hostname_isequal(domain, config_domain)))
    my_syslog(MS_DHCP | LOG_WARNING, _("Ignoring domain %s for DHCP host name %s"), config_domain, name);
  
  if (lease->hostname && name && hostname_isequal(lease->hostname, name))
    {
      if (auth)
	lease->flags |= LEASE_AUTH_NAME;
      return;
    }
  
  if (!name && !lease->hostname)
    return;

  /* If a machine turns up on a new net without dropping the old lease,
     or two machines claim the same name, then we end up with two interfaces with
     the same name. Check for that here and remove the name from the old lease.
     Note that IPv6 leases are different. All the leases to the same DUID are 
     allowed the same name.

     Don't allow a name from the client to override a name from dnsmasq config. */
  
  if (name)
    {
      if ((new_name = whine_malloc(strlen(name) + 1)))
	{
	  strcpy(new_name, name);
	  if (domain && (new_fqdn = whine_malloc(strlen(new_name) + strlen(domain) + 2)))
	    {
	      strcpy(new_fqdn, name);
	      strcat(new_fqdn, ".");
	      strcat(new_fqdn, domain);
	    }
	}
	  
      /* Depending on mode, we check either unqualified name or FQDN. */
      for (lease_tmp = leases; lease_tmp; lease_tmp = lease_tmp->next)
	{
	  if (option_bool(OPT_DHCP_FQDN))
	    {
	      if (!new_fqdn || !lease_tmp->fqdn || !hostname_isequal(lease_tmp->fqdn, new_fqdn))
		continue;
	    }
	  else
	    {
	      if (!new_name || !lease_tmp->hostname || !hostname_isequal(lease_tmp->hostname, new_name) )
		continue; 
	    }

	  if (lease->flags & (LEASE_TA | LEASE_NA))
	    {
	      if (!(lease_tmp->flags & (LEASE_TA | LEASE_NA)))
		continue;

	      /* another lease for the same DUID is OK for IPv6 */
	      if (lease->clid_len == lease_tmp->clid_len &&
		  lease->clid && lease_tmp->clid &&
		  memcmp(lease->clid, lease_tmp->clid, lease->clid_len) == 0)
		continue;	      
	    }
	  else if (lease_tmp->flags & (LEASE_TA | LEASE_NA))
	    continue;
		   
	  if ((lease_tmp->flags & LEASE_AUTH_NAME) && !auth)
	    {
	      free(new_name);
	      free(new_fqdn);
	      return;
	    }
	
	  kill_name(lease_tmp);
	  lease_tmp->flags |= LEASE_CHANGED; /* run script on change */
	  break;
	}
    }

  if (lease->hostname)
    kill_name(lease);

  lease->hostname = new_name;
  lease->fqdn = new_fqdn;
  
  if (auth)
    lease->flags |= LEASE_AUTH_NAME;
  
  file_dirty = 1;
  dns_dirty = 1; 
  lease->flags |= LEASE_CHANGED; /* run script on change */
}

/**
 * @brief Update network interface association for DHCP lease
 * 
 * @detailed Records which network interface a DHCP lease is currently associated with,
 *           enabling multi-homed scenarios where a client moves between network segments.
 *           When the interface changes, triggers lease-change script execution via
 *           LEASE_CHANGED flag. For DHCPv6 leases, also updates SLAAC address assignments
 *           on the new interface via slaac_add_addrs() to ensure proper IPv6 configuration.
 * 
 * @param lease Pointer to lease structure to update. Must not be NULL.
 * @param interface Interface index identifying the network interface (e.g., from if_nametoindex())
 * @param now Current time for SLAAC address lifetime calculations (DHCPv6 only)
 * 
 * @return void
 * 
 * @note If interface unchanged, function returns early (no-op optimization)
 * @note DHCPv6 leases trigger SLAAC address reconfiguration on interface change
 * @note Interface index typically obtained from packet reception metadata
 * 
 * @warning Modifies lease->last_interface and lease->flags (LEASE_CHANGED)
 * 
 * @see slaac_add_addrs() in slaac.c for DHCPv6 address assignment
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_lease *lease = lease4_allocate(ipaddr);
 * int ifindex = if_nametoindex("eth1");
 * lease_set_interface(lease, ifindex, time(NULL));
 * // Result: lease->last_interface = ifindex, LEASE_CHANGED flag set
 * @endcode
 * 
 * SIDE EFFECTS: Sets lease->flags |= LEASE_CHANGED, calls slaac_add_addrs() for DHCPv6
 * THREAD SAFETY: Single-threaded architecture; modifies lease state
 * 
 * Source: /src/lease.c:1910-1923
 */
void lease_set_interface(struct dhcp_lease *lease, int interface, time_t now)
{
  (void)now;

  if (lease->last_interface == interface)
    return;

  lease->last_interface = interface;
  lease->flags |= LEASE_CHANGED; 

#ifdef HAVE_DHCP6
  slaac_add_addrs(lease, now, 0);
#endif
}

/**
 * @brief Set or update DHCP relay agent information for a lease
 * 
 * @detailed Updates the relay agent information (DHCP option 82) associated with a lease.
 *           The agent ID contains circuit ID and remote ID sub-options inserted by relay
 *           agents between the client and server. This information is used for client
 *           location tracking and relay-specific configuration. If the agent ID value
 *           is unchanged, no action is taken to avoid unnecessary memory operations and
 *           file writes. The function handles NULL values gracefully: if both current
 *           and new are NULL, no action is taken. Sets file_dirty flag to trigger lease
 *           database persistence when agent ID changes.
 * 
 * @param lease Pointer to the lease to update. Must not be NULL.
 * @param new Pointer to new relay agent information data, or NULL to clear agent ID
 * @param len Length of relay agent information data in bytes when new is non-NULL
 * 
 * @return None (void function)
 * 
 * @note Sets file_dirty flag when agent ID changes to trigger lease file update
 * @note Uses whine_malloc() which logs allocation failures to syslog
 * @warning Does not validate agent ID format - caller must ensure valid DHCP option 82 data
 * @see lease_set_vendorclass() for vendor class information updates
 * @see file_dirty global flag for lease database persistence tracking
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_lease *lease = lease_find_by_addr(addr);
 * unsigned char agent_data[16] = { ... }; // Option 82 data from relay
 * lease_set_agent_id(lease, agent_data, 16);
 * // Later, to clear agent ID:
 * lease_set_agent_id(lease, NULL, 0);
 * @endcode
 * 
 * RFC COMPLIANCE: Handles DHCP option 82 (Relay Agent Information) per RFC 3046
 * 
 * SIDE EFFECTS:
 * - Sets file_dirty = 1 when agent ID changes (triggers lease file write)
 * - Frees existing agent ID memory using free()
 * - Allocates memory for new agent ID via whine_malloc()
 * - Modifies lease->agent_id and lease->agent_id_len fields
 * 
 * THREAD SAFETY: Single-threaded architecture - not thread-safe
 * Source: /src/lease.c:line 1961
 */
void lease_set_agent_id(struct dhcp_lease *lease, unsigned char *new, int len)
{

  if (!lease->agent_id && !new)
    return;
  
  if (lease->agent_id && new && lease->agent_id_len == len && memcmp(lease->agent_id, new, len) == 0)
    return;

  file_dirty = 1;
  free(lease->agent_id);
  lease->agent_id = NULL;
  
  if (new && (lease->agent_id = whine_malloc(len)))
    {
      memcpy(lease->agent_id, new, len);
      lease->agent_id_len = len;
    }
}

/**
 * @brief Set or update DHCPv4 vendor class information for a lease
 * 
 * @detailed Updates the vendor class identifier (DHCP option 60) associated with a lease.
 *           The vendor class provides information about the client's hardware/software type
 *           and is used for client classification and tag-based configuration. If the vendor
 *           class value is unchanged, no action is taken to avoid unnecessary file writes.
 *           Marks the lease file as dirty when changes occur, triggering eventual persistence.
 * 
 * @param lease Pointer to the lease to update. Must not be NULL.
 * @param new Pointer to new vendor class data, or NULL to clear vendor class
 * @param len Length of vendor class data in bytes (0-255 per DHCP spec)
 * 
 * @return void
 * 
 * @note Setting file_dirty=1 triggers asynchronous lease file write on next maintenance cycle
 * @note Memory allocated via whine_malloc (logs warning on allocation failure)
 * @note Vendor class used for tag-based DHCP configuration (see dhcp.c:match_bytes())
 * 
 * @see lease_set_agent_id() for DHCP relay agent information option
 * @see lease4_allocate() for initial lease creation
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_lease *lease = lease_find_by_addr(client_addr);
 * unsigned char vendor[] = "MSFT 5.0"; // Windows client
 * lease_set_vendorclass(lease, vendor, strlen((char *)vendor));
 * @endcode
 * 
 * RFC COMPLIANCE: DHCP option 60 vendor class identifier (RFC 2132 Section 9.13)
 * SIDE EFFECTS: Sets file_dirty flag, frees and reallocates lease->vendorclass memory
 * THREAD SAFETY: Single-threaded architecture - modifies global file_dirty state
 */
void lease_set_vendorclass(struct dhcp_lease *lease, unsigned char *new, int len)
{
  if (!lease->vendorclass && !new)
    return;

  if (lease->vendorclass && new && lease->vendorclass_len == len && memcmp(lease->vendorclass, new, len) == 0)
    return;

  file_dirty = 1;
  free(lease->vendorclass);
  lease->vendorclass = NULL;
  
  if (new && (lease->vendorclass = whine_malloc(len)))
    {
      memcpy(lease->vendorclass, new, len);
      lease->vendorclass_len = len;
    }
}
       

/**
 * @brief Mark all leases for script re-execution on next maintenance cycle
 * 
 * @detailed Sets the LEASE_CHANGED flag on all active leases in the lease database,
 *           causing lease-change scripts to be invoked on the next call to do_script_run().
 *           This function is typically called after configuration reload (SIGHUP) to ensure
 *           external systems receive updated lease information even if lease parameters have
 *           changed without actual lease churn. Useful for synchronizing external databases
 *           or firewall rules after dnsmasq reconfiguration.
 * 
 * @return void
 * 
 * @note Marks all leases without discriminating between changed and unchanged leases
 * @note Script execution occurs asynchronously via do_script_run() on next event loop iteration
 * @note Does not immediately invoke scripts - only sets flags for deferred execution
 * 
 * @see do_script_run() for actual script invocation processing
 * @see queue_script() for script queueing mechanism via helper.c
 * 
 * EXAMPLE USAGE:
 * @code
 * // After SIGHUP configuration reload
 * read_opts(0, conffile, NULL);
 * rerun_scripts(); // Re-notify all leases to external scripts
 * @endcode
 * 
 * SIDE EFFECTS: Sets LEASE_CHANGED flag on all lease entries in global leases list
 * THREAD SAFETY: Single-threaded architecture - modifies global lease list state
 */
void rerun_scripts(void)
{
  struct dhcp_lease *lease;
  
  for (lease = leases; lease; lease = lease->next)
    lease->flags |= LEASE_CHANGED; 
}

/* deleted leases get transferred to the old_leases list.
   remove them here, after calling the lease change
   script. Also run the lease change script on new/modified leases.

   Return zero if nothing to do. */
/**
 * @brief Process one pending lease script/DBus notification action
 * 
 * @detailed Processes exactly one pending lease change notification by invoking external scripts
 *           (via queue_script in helper.c) or emitting DBus signals. This function is called
 *           repeatedly from the main event loop until all pending actions are processed, with
 *           each invocation handling one action to prevent blocking. The function processes
 *           lease events in priority order: old_hostname changes first, then deletions from
 *           old_leases list, then additions/changes from active leases list. Returns 1 if
 *           work was performed (allowing event loop to process other events), or 0 when all
 *           pending notifications are complete.
 * 
 * @param now Current time (unused in current implementation but passed for script environment)
 * 
 * @return 1 if a script was queued or DBus signal emitted (more work pending)
 * @retval 0 No pending lease change notifications remain
 * 
 * @note Non-blocking design: Processes one action per call to prevent event loop starvation
 * @note DBus delay: If OPT_DBUS enabled but connection not yet established, defers all processing
 * @note Action priority: old_hostname > old_leases deletion > new/changed leases
 * @note Flags cleared: LEASE_NEW, LEASE_CHANGED, LEASE_AUX_CHANGED, LEASE_EXP_CHANGED after processing
 * @warning Modifies global old_leases list by removing processed entries
 * 
 * @see queue_script() in helper.c for script execution mechanism
 * @see emit_dbus_signal() in dbus.c for DBus notification
 * @see lease_prune() for lease expiration that populates old_leases
 * @see lease_update_from_configs() for changes that set LEASE_CHANGED flag
 * 
 * EXAMPLE USAGE:
 * @code
 * // Main event loop processes lease notifications incrementally
 * while (do_script_run(now))
 *   ; // Process all pending lease change notifications
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (notification mechanism, not protocol implementation)
 * SIDE EFFECTS: Modifies old_leases global list, clears lease flags, queues scripts to helper.c
 * THREAD SAFETY: Single-threaded architecture - modifies global lease state
 */
int do_script_run(time_t now)
{
  struct dhcp_lease *lease;

  (void)now;

#ifdef HAVE_DBUS
  /* If we're going to be sending DBus signals, but the connection is not yet up,
     delay everything until it is. */
  if (option_bool(OPT_DBUS) && !daemon->dbus)
    return 0;
#endif

  if (old_leases)
    {
      lease = old_leases;
                  
      /* If the lease still has an old_hostname, do the "old" action on that first */
      if (lease->old_hostname)
	{
#ifdef HAVE_SCRIPT
	  queue_script(ACTION_OLD_HOSTNAME, lease, lease->old_hostname, now);
#endif
	  free(lease->old_hostname);
	  lease->old_hostname = NULL;
	  return 1;
	}
      else 
	{
#ifdef HAVE_DHCP6
	  struct slaac_address *slaac, *tmp;
	  for (slaac = lease->slaac_address; slaac; slaac = tmp)
	    {
	      tmp = slaac->next;
	      free(slaac);
	    }
#endif
	  kill_name(lease);
#ifdef HAVE_SCRIPT
	  queue_script(ACTION_DEL, lease, lease->old_hostname, now);
#endif
#ifdef HAVE_DBUS
	  emit_dbus_signal(ACTION_DEL, lease, lease->old_hostname);
#endif
	  old_leases = lease->next;
	  
	  free(lease->hostname); 
	  free(lease->clid);
	  free(lease->extradata);
	  free(lease->agent_id);
	  free(lease->vendorclass);
	  free(lease);
	    
	  return 1; 
	}
    }
  
  /* make sure we announce the loss of a hostname before its new location. */
  for (lease = leases; lease; lease = lease->next)
    if (lease->old_hostname)
      {	
#ifdef HAVE_SCRIPT
	queue_script(ACTION_OLD_HOSTNAME, lease, lease->old_hostname, now);
#endif
	free(lease->old_hostname);
	lease->old_hostname = NULL;
	return 1;
      }
  
  for (lease = leases; lease; lease = lease->next)
    if ((lease->flags & (LEASE_NEW | LEASE_CHANGED)) || 
	((lease->flags & LEASE_AUX_CHANGED) && option_bool(OPT_LEASE_RO)) ||
	((lease->flags & LEASE_EXP_CHANGED) && option_bool(OPT_LEASE_RENEW)))
      {
#ifdef HAVE_SCRIPT
	queue_script((lease->flags & LEASE_NEW) ? ACTION_ADD : ACTION_OLD, lease, 
		     lease->fqdn ? lease->fqdn : lease->hostname, now);
#endif
#ifdef HAVE_DBUS
	emit_dbus_signal((lease->flags & LEASE_NEW) ? ACTION_ADD : ACTION_OLD, lease,
			 lease->fqdn ? lease->fqdn : lease->hostname);
#endif
	lease->flags &= ~(LEASE_NEW | LEASE_CHANGED | LEASE_AUX_CHANGED | LEASE_EXP_CHANGED);
	
	/* this is used for the "add" call, then junked, since they're not in the database */
	free(lease->extradata);
	lease->extradata = NULL;
	
	return 1;
      }

  return 0; /* nothing to do */
}

#ifdef HAVE_SCRIPT
/**
 * @brief Add extra data to lease for script execution
 * 
 * @detailed Appends arbitrary data to the lease's extradata buffer for passing to
 *           lease-change scripts. The extradata buffer is passed to scripts as additional
 *           environment variables or command-line arguments. Data is null-terminated unless
 *           delim is -1, in which case embedded nulls are permitted (creating multiple
 *           separate data records). When delim is not -1, embedded null bytes are treated
 *           as string terminators, truncating the data at the first null. The buffer grows
 *           automatically via whine_realloc() in 100-byte increments when additional space
 *           is needed. This mechanism enables passing complex structured data (vendor-specific
 *           options, relay agent information, custom tags) to external scripts.
 * 
 * @param lease Pointer to the lease to update. Must not be NULL.
 * @param data Pointer to data to append to extradata buffer
 * @param len Length of data in bytes
 * @param delim Delimiter byte to append after data. Special value -1 means delim=0 but
 *              embedded nulls in data are permitted (creating multiple records). Otherwise,
 *              embedded nulls in data truncate the string.
 * 
 * @return None (void function)
 * 
 * @note Buffer grows in 100-byte increments when space exhausted
 * @note Uses whine_realloc() which logs allocation failures to syslog
 * @warning If realloc fails, data is silently discarded (function returns without error)
 * @warning Embedded nulls are handled differently based on delim value
 * @see lease_do_script_run() which passes extradata to scripts
 * @see whine_realloc() for memory allocation with error logging
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_lease *lease = lease_find_by_addr(addr);
 * unsigned char vendor_data[] = "VENDOR_CLASS=MyVendor";
 * lease_add_extradata(lease, vendor_data, strlen(vendor_data), 0);
 * // Multiple records with delim=-1:
 * unsigned char multi_record[] = "TAG1\0TAG2\0TAG3";
 * lease_add_extradata(lease, multi_record, 15, -1);
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (internal data structure management)
 * 
 * SIDE EFFECTS:
 * - May reallocate lease->extradata buffer via whine_realloc()
 * - Modifies lease->extradata_len (increases by len + 1)
 * - May modify lease->extradata_size if buffer grows
 * - Truncates input data if embedded null found and delim != -1
 * 
 * THREAD SAFETY: Single-threaded architecture - not thread-safe
 * Source: /src/lease.c:line 2255
 */
void lease_add_extradata(struct dhcp_lease *lease, unsigned char *data, unsigned int len, int delim)
{
  unsigned int i;
  
  if (delim == -1)
    delim = 0;
  else
    /* check for embedded NULLs */
    for (i = 0; i < len; i++)
      if (data[i] == 0)
	{
	  len = i;
	  break;
	}
  
  if ((lease->extradata_size - lease->extradata_len) < (len + 1))
    {
      size_t newsz = lease->extradata_len + len + 100;
      unsigned char *new = whine_realloc(lease->extradata, newsz);
  
      if (!new)
	return;
      
      lease->extradata = new;
      lease->extradata_size = newsz;
    }

  if (len != 0)
    memcpy(lease->extradata + lease->extradata_len, data, len);
  lease->extradata[lease->extradata_len + len] = delim;
  lease->extradata_len += len + 1; 
}
#endif

#endif /* HAVE_DHCP */

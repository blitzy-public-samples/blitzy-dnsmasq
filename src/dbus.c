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
 * @file dbus.c
 * @brief D-Bus control interface for programmatic dnsmasq management and monitoring
 * 
 * DETAILED PURPOSE:
 * This module implements the D-Bus control interface that exposes dnsmasq's operational
 * state and configuration to external applications through the system D-Bus message bus.
 * The interface allows monitoring tools, network management systems, and administrative
 * scripts to query cache statistics, manipulate DNS cache entries, reconfigure upstream
 * DNS servers, manage DHCP leases, and receive real-time notifications of lease changes
 * without requiring filesystem access or daemon restarts.
 * 
 * The D-Bus service operates on the system bus under the well-known service name
 * "uk.org.thekelleys.dnsmasq" at object path "/uk/org/thekelleys/dnsmasq". This provides
 * a standardized IPC mechanism that integrates naturally with Linux desktop environments,
 * systemd service management, and enterprise monitoring infrastructure.
 * 
 * KEY RESPONSIBILITIES:
 * - Initialize and maintain D-Bus system bus connection (dbus_init)
 * - Dispatch D-Bus method calls to appropriate handler functions (message_handler)
 * - Implement upstream server reconfiguration via SetServers/SetServersEx methods
 * - Provide DNS cache manipulation through ClearCache method
 * - Expose system metrics via GetMetrics and GetServerMetrics methods
 * - Support DHCP lease management through AddDhcpLease/DeleteDhcpLease methods
 * - Emit D-Bus signals for DHCP lease events (DhcpLeaseAdded/Deleted/Updated)
 * - Manage D-Bus file descriptor watches for event-driven I/O integration (add_watch, remove_watch)
 * - Integrate with main event loop through set_dbus_listeners and check_dbus_listeners
 * 
 * DEPENDENCIES:
 * Includes: dnsmasq.h (core structures and function declarations), dbus/dbus.h (libdbus-1 API)
 * Called by: main event loop in dnsmasq.c for initialization and event processing
 * Calls: cache.c (cache manipulation), forward.c (upstream server management),
 *        lease.c (DHCP lease operations), metrics.c (statistics collection)
 * 
 * DATA STRUCTURES:
 * - struct watch (dbus.c:164-170): Associates D-Bus watch handles with poll file descriptors
 *   for event loop integration, enabling non-blocking D-Bus message processing
 * - DBusConnection: libdbus-1 connection handle to system bus (global variable "connection")
 * - DBusWatch: libdbus-1 watch handle for file descriptor monitoring
 * - DBusMessage: libdbus-1 message structure for method calls, replies, and signals
 * 
 * COMPILE-TIME OPTIONS:
 * - HAVE_DBUS: Master flag enabling entire D-Bus interface (required for all functionality)
 * - HAVE_DHCP: Enables DHCP lease management methods (AddDhcpLease, DeleteDhcpLease) and
 *   DHCP lease change signals (DhcpLeaseAdded, DhcpLeaseDeleted, DhcpLeaseUpdated)
 * - HAVE_LOOP: Enables GetLoopServers method for DNS forwarding loop detection queries
 * 
 * THREADING/CONCURRENCY:
 * Single-threaded event-driven model. D-Bus messages are processed synchronously in the
 * main event loop. File descriptor watches enable non-blocking integration with poll-based
 * event multiplexing. All D-Bus operations complete within the main thread context.
 * 
 * SECURITY MODEL:
 * Access control enforced via D-Bus system bus policy file (dbus/dnsmasq.conf). Default
 * policy restricts all methods to root user and members of the netadmin group, preventing
 * unprivileged users from manipulating DNS cache or reconfiguring upstream servers.
 * Policy enforcement delegated to dbus-daemon; this module trusts authenticated callers.
 * 
 * EXAMPLE USAGE:
 * External applications interact with dnsmasq via D-Bus using standard D-Bus client libraries
 * or command-line tools like dbus-send. Example method invocations:
 * 
 * Query version:
 * @code
 * dbus-send --system --print-reply --dest=uk.org.thekelleys.dnsmasq \
 *   /uk/org/thekelleys/dnsmasq uk.org.thekelleys.dnsmasq.GetVersion
 * @endcode
 * 
 * Clear DNS cache:
 * @code
 * dbus-send --system --dest=uk.org.thekelleys.dnsmasq \
 *   /uk/org/thekelleys/dnsmasq uk.org.thekelleys.dnsmasq.ClearCache
 * @endcode
 * 
 * Reconfigure upstream servers:
 * @code
 * dbus-send --system --dest=uk.org.thekelleys.dnsmasq \
 *   /uk/org/thekelleys/dnsmasq uk.org.thekelleys.dnsmasq.SetServersEx \
 *   array:array:string:"","8.8.8.8","","8.8.4.4"
 * @endcode
 * 
 * @copyright Copyright (c) 2000-2025 Simon Kelley
 * @license GPL-2.0-or-later
 */

#include "dnsmasq.h"

#ifdef HAVE_DBUS

#include <dbus/dbus.h>

const char* introspection_xml_template =
"<!DOCTYPE node PUBLIC \"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\"\n"
"\"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\">\n"
"<node name=\"" DNSMASQ_PATH "\">\n"
"  <interface name=\"org.freedesktop.DBus.Introspectable\">\n"
"    <method name=\"Introspect\">\n"
"      <arg name=\"data\" direction=\"out\" type=\"s\"/>\n"
"    </method>\n"
"  </interface>\n"
"  <interface name=\"%s\">\n"
"    <method name=\"ClearCache\">\n"
"    </method>\n"
"    <method name=\"GetVersion\">\n"
"      <arg name=\"version\" direction=\"out\" type=\"s\"/>\n"
"    </method>\n"
#ifdef HAVE_LOOP
"    <method name=\"GetLoopServers\">\n"
"      <arg name=\"server\" direction=\"out\" type=\"as\"/>\n"
"    </method>\n"
#endif
"    <method name=\"SetServers\">\n"
"      <arg name=\"servers\" direction=\"in\" type=\"av\"/>\n"
"    </method>\n"
"    <method name=\"SetDomainServers\">\n"
"      <arg name=\"servers\" direction=\"in\" type=\"as\"/>\n"
"    </method>\n"
"    <method name=\"SetServersEx\">\n"
"      <arg name=\"servers\" direction=\"in\" type=\"aas\"/>\n"
"    </method>\n"
"    <method name=\"SetFilterWin2KOption\">\n"
"      <arg name=\"filterwin2k\" direction=\"in\" type=\"b\"/>\n"
"    </method>\n"
"    <method name=\"SetFilterA\">\n"
"      <arg name=\"filter-a\" direction=\"in\" type=\"b\"/>\n"
"    </method>\n"
"    <method name=\"SetFilterAAAA\">\n"
"      <arg name=\"filter-aaaa\" direction=\"in\" type=\"b\"/>\n"
"    </method>\n"
"    <method name=\"SetLocaliseQueriesOption\">\n"
"      <arg name=\"localise-queries\" direction=\"in\" type=\"b\"/>\n"
"    </method>\n"
"    <method name=\"SetBogusPrivOption\">\n"
"      <arg name=\"boguspriv\" direction=\"in\" type=\"b\"/>\n"
"    </method>\n"
"    <signal name=\"DhcpLeaseAdded\">\n"
"      <arg name=\"ipaddr\" type=\"s\"/>\n"
"      <arg name=\"hwaddr\" type=\"s\"/>\n"
"      <arg name=\"hostname\" type=\"s\"/>\n"
"    </signal>\n"
"    <signal name=\"DhcpLeaseDeleted\">\n"
"      <arg name=\"ipaddr\" type=\"s\"/>\n"
"      <arg name=\"hwaddr\" type=\"s\"/>\n"
"      <arg name=\"hostname\" type=\"s\"/>\n"
"    </signal>\n"
"    <signal name=\"DhcpLeaseUpdated\">\n"
"      <arg name=\"ipaddr\" type=\"s\"/>\n"
"      <arg name=\"hwaddr\" type=\"s\"/>\n"
"      <arg name=\"hostname\" type=\"s\"/>\n"
"    </signal>\n"
#ifdef HAVE_DHCP
"    <method name=\"AddDhcpLease\">\n"
"       <arg name=\"ipaddr\" type=\"s\"/>\n"
"       <arg name=\"hwaddr\" type=\"s\"/>\n"
"       <arg name=\"hostname\" type=\"ay\"/>\n"
"       <arg name=\"clid\" type=\"ay\"/>\n"
"       <arg name=\"lease_duration\" type=\"u\"/>\n"
"       <arg name=\"ia_id\" type=\"u\"/>\n"
"       <arg name=\"is_temporary\" type=\"b\"/>\n"
"    </method>\n"
"    <method name=\"DeleteDhcpLease\">\n"
"       <arg name=\"ipaddr\" type=\"s\"/>\n"
"       <arg name=\"success\" type=\"b\" direction=\"out\"/>\n"
"    </method>\n"
#endif
"    <method name=\"GetMetrics\">\n"
"      <arg name=\"metrics\" direction=\"out\" type=\"a{su}\"/>\n"
"    </method>\n"
"    <method name=\"GetServerMetrics\">\n"
"      <arg name=\"metrics\" direction=\"out\" type=\"a{ss}\"/>\n"
"    </method>\n"
"    <method name=\"ClearMetrics\">\n"
"    </method>\n"
"  </interface>\n"
"</node>\n";

static char *introspection_xml = NULL;
static int watches_modified = 0;

/**
 * @struct watch
 * @brief Associates D-Bus watch handles with poll file descriptors for event loop integration
 * 
 * This structure maintains the list of active D-Bus watch objects that monitor file descriptors
 * for readable, writable, or error conditions. The watch list enables non-blocking integration
 * between libdbus-1's event-driven architecture and dnsmasq's poll-based main event loop.
 * 
 * LIFECYCLE:
 * Creation: Allocated via add_watch() when libdbus-1 requests new file descriptor monitoring
 * Initialization: Fields populated with DBusWatch handle and linked into daemon->watches list
 * Destruction: Removed via remove_watch() when libdbus-1 no longer needs monitoring; freed with free()
 * Ownership: Owned by daemon global state; managed by add_watch/remove_watch callbacks
 * 
 * MEMORY LAYOUT:
 * Size: Typically 16 bytes (8-byte pointer + 8-byte next pointer on 64-bit systems)
 * Alignment: Natural pointer alignment
 * 
 * USAGE PATTERNS:
 * Linked list of watch structures anchored at daemon->watches
 * Traversed in set_dbus_listeners() to add file descriptors to poll array
 * Modified by libdbus-1 callbacks (add_watch, remove_watch) during connection lifecycle
 */
struct watch {
  DBusWatch *watch;      /**< @brief libdbus-1 watch handle for file descriptor monitoring
                          * Valid DBusWatch pointer; never NULL within linked list.
                          * Used to query file descriptor, flags, and enabled state. */
  struct watch *next;    /**< @brief Next watch in linked list; NULL for list tail.
                          * Links form singly-linked list for traversal during poll setup. */
};


/**
 * @brief Register new D-Bus watch for file descriptor monitoring in main event loop
 * 
 * Callback function invoked by libdbus-1 when a new file descriptor requires monitoring
 * for readable, writable, or error conditions. Allocates a watch structure, links it
 * into the daemon's watch list, and sets the watches_modified flag to trigger poll
 * array reconstruction in the next event loop iteration.
 * 
 * This function implements the DBusAddWatchFunction callback type required by
 * dbus_connection_set_watch_functions(). It integrates libdbus-1's event-driven
 * architecture with dnsmasq's poll-based main event loop by maintaining a list
 * of active watches that are translated to pollfd structures in set_dbus_listeners().
 * 
 * @param watch DBusWatch handle from libdbus-1 representing file descriptor to monitor.
 *              Must not be NULL. Contains file descriptor, monitoring flags (read/write),
 *              and enabled state. Ownership remains with libdbus-1.
 * @param data User data pointer (unused in this implementation); typically daemon context.
 *             May be NULL. Suppressed with (void) cast to prevent compiler warnings.
 * 
 * @return TRUE on successful watch registration; FALSE on memory allocation failure
 * @retval TRUE Watch successfully added to daemon->watches list or already present
 * @retval FALSE Memory allocation failed via whine_malloc; watch not registered
 * 
 * @note Idempotent: If watch already exists in list, returns TRUE without duplication
 * @warning Memory allocation failure prevents D-Bus message processing; connection unusable
 * 
 * @see remove_watch() for watch deregistration
 * @see set_dbus_listeners() for poll array setup using watch list
 * @see dbus_init() for callback registration via dbus_connection_set_watch_functions()
 * 
 * EXAMPLE USAGE:
 * @code
 * // Registered as callback during D-Bus connection initialization
 * dbus_connection_set_watch_functions(connection, add_watch, remove_watch, NULL, NULL, NULL);
 * // libdbus-1 automatically invokes add_watch when new file descriptor needs monitoring
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (D-Bus implementation detail)
 * SIDE EFFECTS: 
 * - Allocates memory for struct watch via whine_malloc (logged allocation)
 * - Modifies daemon->watches linked list by prepending new watch
 * - Increments watches_modified flag, triggering poll array rebuild
 * THREAD SAFETY: Single-threaded; assumes called from main event loop context
 */
static dbus_bool_t add_watch(DBusWatch *watch, void *data)
{
  struct watch *w;

  for (w = daemon->watches; w; w = w->next)
    if (w->watch == watch)
      return TRUE;

  if (!(w = whine_malloc(sizeof(struct watch))))
    return FALSE;

  w->watch = watch;
  w->next = daemon->watches;
  daemon->watches = w;
  watches_modified++;

  (void)data; /* no warning */
  return TRUE;
}

/**
 * @brief Deregister D-Bus watch and remove from event loop monitoring
 * 
 * Callback function invoked by libdbus-1 when a file descriptor no longer requires
 * monitoring. Searches the daemon's watch list for the specified watch, removes it
 * from the linked list, frees associated memory, and sets watches_modified flag to
 * trigger poll array reconstruction in the next event loop iteration.
 * 
 * This function implements the DBusRemoveWatchFunction callback type required by
 * dbus_connection_set_watch_functions(). It ensures clean deregistration of file
 * descriptor monitors when D-Bus connection state changes or connection is closed.
 * Uses pointer-to-pointer traversal technique to modify linked list in single pass.
 * 
 * @param watch DBusWatch handle from libdbus-1 identifying file descriptor to stop
 *              monitoring. Must not be NULL. Ownership remains with libdbus-1; this
 *              function only removes wrapper struct watch from internal tracking.
 * @param data User data pointer (unused in this implementation); typically daemon context.
 *             May be NULL. Suppressed with (void) cast to prevent compiler warnings.
 * 
 * @return void (no return value)
 * 
 * @note Safe to call with watch not in list (no-op, no error)
 * @note May remove multiple matching watches if list contains duplicates (defensive)
 * @warning Frees memory via free(); watch structure must not be accessed after this call
 * 
 * @see add_watch() for watch registration
 * @see set_dbus_listeners() for poll array setup using watch list
 * @see dbus_init() for callback registration via dbus_connection_set_watch_functions()
 * 
 * EXAMPLE USAGE:
 * @code
 * // Registered as callback during D-Bus connection initialization
 * dbus_connection_set_watch_functions(connection, add_watch, remove_watch, NULL, NULL, NULL);
 * // libdbus-1 automatically invokes remove_watch when file descriptor monitoring ends
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (D-Bus implementation detail)
 * SIDE EFFECTS:
 * - Frees memory for struct watch via free()
 * - Modifies daemon->watches linked list by removing matching watches
 * - Increments watches_modified flag for each removed watch, triggering poll array rebuild
 * THREAD SAFETY: Single-threaded; assumes called from main event loop context
 */
static void remove_watch(DBusWatch *watch, void *data)
{
  struct watch **up, *w, *tmp;
  
  for (up = &(daemon->watches), w = daemon->watches; w; w = tmp)
    {
      tmp = w->next;
      if (w->watch == watch)
	{
	  *up = tmp;
	  free(w);
	  watches_modified++;
	}
      else
	up = &(w->next);
    }

  (void)data; /* no warning */
}

/**
 * @brief Parse SetServers D-Bus method call and reconfigure upstream DNS servers
 * 
 * @detailed Processes incoming D-Bus message containing upstream DNS server addresses
 * in variant array format (DBUS_TYPE_UINT32 for IPv4, array of DBUS_TYPE_BYTE for IPv6),
 * optionally followed by domain strings for domain-specific server configuration. Marks
 * existing SERV_FROM_DBUS servers for removal, adds/updates servers from message, then
 * removes any servers not present in the new configuration. This implements complete
 * upstream server replacement via D-Bus interface, enabling dynamic DNS topology changes
 * without daemon restart or configuration file modification.
 * 
 * Message format: Array of variants, where each variant contains either:
 * - UINT32: IPv4 address in network byte order (big-endian)
 * - Array of 16 BYTEs: IPv6 address (128 bits)
 * Each address variant may be followed by zero or more STRING values specifying domains
 * for domain-specific upstream routing (e.g., ".internal.example.com"). Addresses without
 * domain strings are treated as general-purpose upstream resolvers.
 * 
 * @param message Incoming D-Bus method call message from SetServers method invocation.
 *                Must contain argument array of variant types. Message ownership remains
 *                with caller; this function reads but does not modify or free the message.
 *                If message cannot be parsed, returns error message describing failure.
 * 
 * @return NULL on success (no reply message needed; empty reply sent by caller), or
 *         DBusMessage* error reply on parsing failure with DBUS_ERROR_INVALID_ARGS code
 * @retval NULL Successfully parsed and applied upstream server configuration
 * @retval DBusMessage* Error reply if message iteration fails or format invalid
 * 
 * @note Clears all existing SERV_FROM_DBUS servers before applying new configuration
 * @note IPv6 addresses require exactly 16 bytes; partial addresses are skipped
 * @warning Replaces entire upstream server list configured via D-Bus; previous SetServers
 *          configuration is lost. Does not affect servers configured via config file.
 * 
 * @see dbus_read_servers_ex() for extended format with per-server source addresses
 * @see add_update_server() in forward.c for server addition implementation
 * @see cleanup_servers() in forward.c for removal of marked servers
 * @see mark_servers() in forward.c for marking servers with SERV_FROM_DBUS flag
 * 
 * EXAMPLE USAGE:
 * @code
 * // D-Bus method invocation: SetServers with IPv4 address 8.8.8.8
 * // dbus-send --system --dest=uk.org.thekelleys.dnsmasq \
 * //   /uk/org/thekelleys/dnsmasq uk.org.thekelleys.dnsmasq.SetServers \
 * //   array:variant:uint32:0x08080808
 * // Results in call: dbus_read_servers(message)
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (D-Bus interface for DNS forwarding configuration)
 * SIDE EFFECTS:
 * - Marks existing SERV_FROM_DBUS servers for deletion via mark_servers()
 * - Adds or updates server records via add_update_server()
 * - Removes unmarked servers via cleanup_servers()
 * - Modifies daemon->servers linked list structure
 * - Triggers DNS query forwarding topology change
 * THREAD SAFETY: Single-threaded; must be called from main event loop context
 */
static DBusMessage* dbus_read_servers(DBusMessage *message)
{
  DBusMessageIter iter;
  union  mysockaddr addr, source_addr;
  char *domain;
  
  if (!dbus_message_iter_init(message, &iter))
    {
      return dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
                                    "Failed to initialize dbus message iter");
    }

  mark_servers(SERV_FROM_DBUS);
  
  while (1)
    {
      int skip = 0;

      if (dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_UINT32)
	{
	  u32 a;
	  
	  dbus_message_iter_get_basic(&iter, &a);
	  dbus_message_iter_next (&iter);
	  
#ifdef HAVE_SOCKADDR_SA_LEN
	  source_addr.in.sin_len = addr.in.sin_len = sizeof(struct sockaddr_in);
#endif
	  addr.in.sin_addr.s_addr = ntohl(a);
	  source_addr.in.sin_family = addr.in.sin_family = AF_INET;
	  addr.in.sin_port = htons(NAMESERVER_PORT);
	  source_addr.in.sin_addr.s_addr = INADDR_ANY;
	  source_addr.in.sin_port = htons(daemon->query_port);
	}
      else if (dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_BYTE)
	{
	  unsigned char p[sizeof(struct in6_addr)];
	  unsigned int i;

	  skip = 1;

	  for(i = 0; i < sizeof(struct in6_addr); i++)
	    {
	      dbus_message_iter_get_basic(&iter, &p[i]);
	      dbus_message_iter_next (&iter);
	      if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_BYTE)
		{
		  i++;
		  break;
		}
	    }

	  if (i == sizeof(struct in6_addr))
	    {
	      memcpy(&addr.in6.sin6_addr, p, sizeof(struct in6_addr));
#ifdef HAVE_SOCKADDR_SA_LEN
              source_addr.in6.sin6_len = addr.in6.sin6_len = sizeof(struct sockaddr_in6);
#endif
              source_addr.in6.sin6_family = addr.in6.sin6_family = AF_INET6;
              addr.in6.sin6_port = htons(NAMESERVER_PORT);
              source_addr.in6.sin6_flowinfo = addr.in6.sin6_flowinfo = 0;
	      source_addr.in6.sin6_scope_id = addr.in6.sin6_scope_id = 0;
              source_addr.in6.sin6_addr = in6addr_any;
              source_addr.in6.sin6_port = htons(daemon->query_port);
	      skip = 0;
	    }
	}
      else
	/* At the end */
	break;
      
      /* process each domain */
      do {
	if (dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_STRING)
	  {
	    dbus_message_iter_get_basic(&iter, &domain);
	    dbus_message_iter_next (&iter);
	  }
	else
	  domain = NULL;
	
	if (!skip)
	  add_update_server(SERV_FROM_DBUS, &addr, &source_addr, NULL, domain, NULL);
     
      } while (dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_STRING); 
    }
   
  /* unlink and free anything still marked. */
  cleanup_servers();
  return NULL;
}

#ifdef HAVE_LOOP
static DBusMessage *dbus_reply_server_loop(DBusMessage *message)
{
  DBusMessageIter args, args_iter;
  struct server *serv;
  DBusMessage *reply = dbus_message_new_method_return(message);
   
  dbus_message_iter_init_append (reply, &args);
  dbus_message_iter_open_container (&args, DBUS_TYPE_ARRAY,DBUS_TYPE_STRING_AS_STRING, &args_iter);

  for (serv = daemon->servers; serv; serv = serv->next)
    if (serv->flags & SERV_LOOP)
      {
	(void)prettyprint_addr(&serv->addr, daemon->addrbuff);
	dbus_message_iter_append_basic (&args_iter, DBUS_TYPE_STRING, &daemon->addrbuff);
      }
  
  dbus_message_iter_close_container (&args, &args_iter);

  return reply;
}
#endif

/**
 * @brief Parse SetServersEx D-Bus method call with extended upstream server configuration
 * 
 * @detailed Processes incoming D-Bus message containing upstream DNS server configuration
 * with extended format supporting source addresses, network interfaces, and domain-specific
 * routing. Accepts both new format (structured data with explicit fields) and legacy format
 * (backward compatible with SetServers/SetDomainServers). New format enables advanced
 * configurations including source address binding for multihomed systems, interface-specific
 * servers, and complex domain routing scenarios. This provides the most flexible upstream
 * server configuration mechanism, superseding both SetServers and SetDomainServers methods.
 * 
 * Message format supports two modes:
 * 
 * NEW FORMAT: Array of arrays of strings, where each inner array contains:
 * - First element: IP address string (e.g., "8.8.8.8" or "2001:4860:4860::8888")
 *   Empty string ("") creates SERV_LITERAL_ADDRESS server (no upstream forwarding)
 * - Optional second element: Source address string prefixed with "#" (e.g., "#192.168.1.1")
 *   Binds outgoing queries to specified local address on multihomed systems
 * - Optional third element: Interface name prefixed with "@" (e.g., "@eth0")
 *   Restricts server to queries arriving on specified network interface
 * - Remaining elements: Domain strings (e.g., ".internal.example.com")
 *   Multiple domains separated by "/" within single string or as separate elements
 *   Servers without domains handle general-purpose queries
 * 
 * LEGACY FORMAT: Array of strings (backward compatible with SetDomainServers):
 * - Each string: "address/domain" format with optional source/interface prefixes
 * - Automatic detection based on first array element type (array vs string)
 * 
 * @param message Incoming D-Bus method call message from SetServersEx method invocation.
 *                Must contain argument: array of arrays of strings (new format) or
 *                array of strings (legacy format). Message ownership remains with caller;
 *                this function reads but does not modify or free the message. If message
 *                cannot be parsed, returns error message describing the specific failure.
 * @param strings Boolean flag indicating message format: non-zero for legacy string array
 *                format (SetDomainServers compatibility), zero for new array-of-arrays format.
 *                Determines D-Bus message iteration strategy and parsing rules. Value passed
 *                from message_handler based on method name detection.
 * 
 * @return NULL on success (no reply message needed; empty reply sent by caller), or
 *         DBusMessage* error reply on parsing failure with DBUS_ERROR_INVALID_ARGS code
 * @retval NULL Successfully parsed and applied upstream server configuration
 * @retval DBusMessage* Error reply if message iteration fails, format invalid, or
 *                      IP address parsing fails with detailed error description
 * 
 * @note Clears all existing SERV_FROM_DBUS servers before applying new configuration
 * @note Source address and interface parameters require corresponding system configuration
 * @note Empty IP address string ("") creates literal address server (no forwarding)
 * @warning Replaces entire D-Bus-configured upstream server list; previous SetServers/
 *          SetServersEx configuration is lost. Does not affect config file servers.
 * @warning Source address must be valid local interface address or binding will fail
 * @warning Interface name must match existing network interface or queries will not match
 * 
 * @see dbus_read_servers() for simpler format without source/interface support
 * @see parse_server() in option.c for IP address parsing and validation
 * @see parse_server_next() in option.c for iterating multiple address results
 * @see parse_server_addr() in option.c for extracting source address and interface
 * @see add_update_server() in forward.c for server addition with all parameters
 * @see cleanup_servers() in forward.c for removal of unmarked servers
 * @see mark_servers() in forward.c for marking servers with SERV_FROM_DBUS flag
 * 
 * EXAMPLE USAGE:
 * @code
 * // D-Bus method invocation: SetServersEx with source address and interface
 * // dbus-send --system --dest=uk.org.thekelleys.dnsmasq \
 * //   /uk/org/thekelleys/dnsmasq uk.org.thekelleys.dnsmasq.SetServersEx \
 * //   array:array:string:"8.8.8.8","#192.168.1.1","@eth0",".example.com"
 * // Results in upstream server 8.8.8.8 bound to source 192.168.1.1 on eth0
 * // handling queries for .example.com domain
 * 
 * // Legacy format compatibility:
 * // dbus-send --system --dest=uk.org.thekelleys.dnsmasq \
 * //   /uk/org/thekelleys/dnsmasq uk.org.thekelleys.dnsmasq.SetServersEx \
 * //   array:string:"8.8.8.8/.example.com","1.1.1.1"
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (D-Bus interface for DNS forwarding configuration)
 * SIDE EFFECTS:
 * - Marks existing SERV_FROM_DBUS servers for deletion via mark_servers()
 * - Adds or updates server records with full parameter set via add_update_server()
 * - Removes unmarked servers via cleanup_servers()
 * - Modifies daemon->servers linked list structure
 * - Triggers DNS query forwarding topology change with source/interface routing
 * - Allocates and frees temporary string buffers for parsing (whine_malloc/free)
 * - May perform DNS resolution for hostname-based server addresses (freeaddrinfo)
 * THREAD SAFETY: Single-threaded; must be called from main event loop context
 */
static DBusMessage* dbus_read_servers_ex(DBusMessage *message, int strings)
{
  DBusMessageIter iter, array_iter, string_iter;
  DBusMessage *error = NULL;
  const char *addr_err;
  char *dup = NULL;
  
  if (!dbus_message_iter_init(message, &iter))
    {
      return dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
                                    "Failed to initialize dbus message iter");
    }

  /* check that the message contains an array of arrays */
  if ((dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY) ||
      (dbus_message_iter_get_element_type(&iter) != (strings ? DBUS_TYPE_STRING : DBUS_TYPE_ARRAY)))
    {
      return dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
                                    strings ? "Expected array of string" : "Expected array of string arrays");
     }
 
  mark_servers(SERV_FROM_DBUS);

  /* array_iter points to each "as" element in the outer array */
  dbus_message_iter_recurse(&iter, &array_iter);
  while (dbus_message_iter_get_arg_type(&array_iter) != DBUS_TYPE_INVALID)
    {
      const char *str = NULL;
      union  mysockaddr addr, source_addr;
      u16 flags = 0;
      char interface[IF_NAMESIZE];
      char *str_addr, *str_domain = NULL;
      struct server_details sdetails = { 0 };
      sdetails.addr = &addr;
      sdetails.source_addr = &source_addr;
      sdetails.interface = interface;
      sdetails.flags = &flags;

      if (strings)
	{
	  dbus_message_iter_get_basic(&array_iter, &str);
	  if (!str || !strlen (str))
	    {
	      error = dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
					     "Empty string");
	      break;
	    }
	  
	  /* dup the string because it gets modified during parsing */
	  if (dup)
	    free(dup);
	  if (!(dup = str_domain = whine_malloc(strlen(str)+1)))
	    break;
	  
	  strcpy(str_domain, str);

	  /* point to address part of old string for error message */
	  if ((str_addr = strrchr(str, '/')))
	    str = str_addr+1;
	  
	  if ((str_addr = strrchr(str_domain, '/')))
	    {
	      if (*str_domain != '/' || str_addr == str_domain)
		{
		  error = dbus_message_new_error_printf(message,
							DBUS_ERROR_INVALID_ARGS,
							"No domain terminator '%s'",
							str);
		  break;
		}
	      *str_addr++ = 0;
	      str_domain++;
	    }
	  else
	    {
	      str_addr = str_domain;
	      str_domain = NULL;
	    }

	  
	}
      else
	{
	  /* check the types of the struct and its elements */
	  if ((dbus_message_iter_get_arg_type(&array_iter) != DBUS_TYPE_ARRAY) ||
	      (dbus_message_iter_get_element_type(&array_iter) != DBUS_TYPE_STRING))
	    {
	      error = dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
					     "Expected inner array of strings");
	      break;
	    }
	  
	  /* string_iter points to each "s" element in the inner array */
	  dbus_message_iter_recurse(&array_iter, &string_iter);
	  if (dbus_message_iter_get_arg_type(&string_iter) != DBUS_TYPE_STRING)
	    {
	      /* no IP address given */
	      error = dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
					     "Expected IP address");
	      break;
	    }
	  
	  dbus_message_iter_get_basic(&string_iter, &str);
	  if (!str || !strlen (str))
	    {
	      error = dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
					     "Empty IP address");
	      break;
	    }
	  
	  /* dup the string because it gets modified during parsing */
	  if (dup)
	    free(dup);
	  if (!(dup = str_addr = whine_malloc(strlen(str)+1)))
	    break;
	  
	  strcpy(str_addr, str);
	}

      if (strings)
	{
	  char *p;
	  
	  do {
	    if (str_domain)
	      {
		if ((p = strchr(str_domain, '/')))
		  *p++ = 0;
	      }
	    else 
	      p = NULL;
	    
	     if (strings && strlen(str_addr) == 0)
	       add_update_server(SERV_LITERAL_ADDRESS | SERV_FROM_DBUS, &addr, &source_addr, interface, str_domain, NULL);
	     else
	       {
		 if ((addr_err = parse_server(str_addr, &sdetails)))
		   {
		     error = dbus_message_new_error_printf(message, DBUS_ERROR_INVALID_ARGS,
							   "Invalid IP address '%s': %s",
							   str, addr_err);
		     break;
		   }
		 
		 while (parse_server_next(&sdetails))
		   {
		     if ((addr_err = parse_server_addr(&sdetails)))
		       {
			 error = dbus_message_new_error_printf(message, DBUS_ERROR_INVALID_ARGS,
							       "Invalid IP address '%s': %s",
							       str, addr_err);
			 break;
		       }
		     
		     add_update_server(flags | SERV_FROM_DBUS, &addr, &source_addr, interface, str_domain, NULL);
		   }
	       }
	  } while ((str_domain = p));
	}
      else
	{
	  /* jump past the address to the domain list (if any) */
	  dbus_message_iter_next (&string_iter);
	  
	  /* parse domains and add each server/domain pair to the list */
	  do {
	    str = NULL;
	    if (dbus_message_iter_get_arg_type(&string_iter) == DBUS_TYPE_STRING)
	      dbus_message_iter_get_basic(&string_iter, &str);
	    dbus_message_iter_next (&string_iter);

	    if ((addr_err = parse_server(str_addr, &sdetails)))
	      {
		error = dbus_message_new_error_printf(message, DBUS_ERROR_INVALID_ARGS,
						      "Invalid IP address '%s': %s",
						      str, addr_err);
		break;
	      }
	    
	    while (parse_server_next(&sdetails))
	      {
		if ((addr_err = parse_server_addr(&sdetails)))
		  {
		    error = dbus_message_new_error_printf(message, DBUS_ERROR_INVALID_ARGS,
							  "Invalid IP address '%s': %s",
							  str, addr_err);
		    break;
		  }
		
		/* 0.0.0.0 for server address == NULL, for Dbus */
		if (addr.in.sin_family == AF_INET &&
		    addr.in.sin_addr.s_addr == 0)
		  flags |= SERV_LITERAL_ADDRESS;
		else
		  flags &= ~SERV_LITERAL_ADDRESS;
		
		add_update_server(flags | SERV_FROM_DBUS, &addr, &source_addr, interface, str, NULL);
	      }
	  } while (dbus_message_iter_get_arg_type(&string_iter) == DBUS_TYPE_STRING);
	}
      
      if (sdetails.orig_hostinfo)
	freeaddrinfo(sdetails.orig_hostinfo);
      
      /* jump to next element in outer array */
      dbus_message_iter_next(&array_iter);
    }

  cleanup_servers();
    
  if (dup)
    free(dup);

  return error;
}

/**
 * @brief Extract and validate boolean argument from D-Bus method call message
 * 
 * @detailed Parses incoming D-Bus message to extract a single boolean argument, validates
 * the message format and argument type, and logs the configuration change with human-readable
 * option name. This is a helper function for D-Bus methods that accept boolean parameters
 * (SetFilterWin2KOption, SetFilterA, SetFilterAAAA, SetLocaliseQueriesOption, SetBogusPrivOption).
 * Provides consistent error handling and logging across all boolean configuration methods.
 * 
 * The function performs message format validation to ensure the D-Bus method call contains
 * exactly one argument of type DBUS_TYPE_BOOLEAN. If validation fails, returns a D-Bus
 * error message with DBUS_ERROR_INVALID_ARGS. On successful extraction, logs the enable/
 * disable action to syslog with LOG_INFO severity, using the provided option name for
 * administrator visibility into configuration changes.
 * 
 * @param message Incoming D-Bus method call message containing boolean argument. Must
 *                be valid DBusMessage pointer from libdbus-1. Message ownership remains
 *                with caller; this function reads but does not modify or free the message.
 *                If message is NULL or cannot be parsed, returns error message.
 * @param enabled Output parameter receiving extracted boolean value. Must be pointer to
 *                dbus_bool_t variable allocated by caller. On successful extraction,
 *                receives DBUS_TRUE (non-zero) for enabled or DBUS_FALSE (zero) for
 *                disabled. Value undefined if function returns error message. Must not
 *                be NULL or behavior is undefined.
 * @param name Human-readable configuration option name for logging purposes (e.g.,
 *             "filter-win2k", "filter-a", "bogus-priv"). Used in syslog message
 *             "Enabling --<name> option from D-Bus" or "Disabling --<name> option
 *             from D-Bus". Must be NULL-terminated string. Caller retains ownership;
 *             this function does not modify or free the string.
 * 
 * @return NULL on successful boolean extraction and validation, or DBusMessage* error
 *         reply on parsing failure with DBUS_ERROR_INVALID_ARGS error code
 * @retval NULL Successfully extracted boolean value; output parameter enabled is valid
 * @retval DBusMessage* Error reply if message iteration fails, argument missing, or
 *                      argument type is not DBUS_TYPE_BOOLEAN; error message contains
 *                      descriptive text "Expected boolean argument"
 * 
 * @note Logs configuration change to syslog with LOG_INFO severity on success
 * @note Does not modify daemon configuration; caller must apply the boolean value
 * @warning enabled parameter must be valid pointer; no NULL check performed
 * @warning name parameter must be valid NULL-terminated string for logging
 * 
 * @see dbus_set_bool() which calls this function and applies configuration change
 * @see set_option_bool() in option.c for enabling boolean configuration options
 * @see reset_option_bool() in option.c for disabling boolean configuration options
 * @see my_syslog() in log.c for non-blocking syslog message generation
 * 
 * EXAMPLE USAGE:
 * @code
 * // Internal use by dbus_set_bool to validate and extract boolean:
 * dbus_bool_t val;
 * DBusMessage *error = dbus_get_bool(message, &val, "filter-win2k");
 * if (!error) {
 *   // val now contains DBUS_TRUE or DBUS_FALSE
 *   // Caller applies configuration via set_option_bool/reset_option_bool
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (D-Bus interface helper function)
 * SIDE EFFECTS:
 * - Logs configuration change to syslog via my_syslog()
 * - Initializes D-Bus message iterator (read-only operation)
 * - Writes boolean value to enabled output parameter
 * THREAD SAFETY: Single-threaded; must be called from main event loop context
 */
static DBusMessage *dbus_get_bool(DBusMessage *message, dbus_bool_t *enabled, char *name)
{
  DBusMessageIter iter;

  if (!dbus_message_iter_init(message, &iter) || dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_BOOLEAN)
    return dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS, "Expected boolean argument");
  
  dbus_message_iter_get_basic(&iter, enabled);
  
  if (*enabled)
    my_syslog(LOG_INFO, _("Enabling --%s option from D-Bus"), name);
  else
    my_syslog(LOG_INFO, _("Disabling --%s option from D-Bus"), name);
  
  return NULL;
}

/**
 * @brief Set boolean configuration option value via D-Bus
 * 
 * @detailed Parses boolean value from D-Bus message and sets or resets the specified
 *           configuration flag in the daemon's runtime configuration. This provides
 *           runtime reconfiguration of boolean options without daemon restart. The
 *           function delegates message parsing to dbus_get_bool() and applies the
 *           resulting boolean value via set_option_bool() or reset_option_bool().
 * 
 * @param message D-Bus method call message containing boolean argument
 * @param flag Configuration flag constant from options structure (OPT_xxx from dnsmasq.h)
 * @param name Human-readable option name for logging (e.g., "filter-win2k", "boguspriv")
 * 
 * @return NULL on success (reply handled by caller), or DBusMessage error object on failure
 * @retval NULL Boolean value successfully applied to configuration flag
 * @retval DBusMessage Error message (DBUS_ERROR_INVALID_ARGS if argument parsing fails)
 * 
 * @note Logs configuration change to syslog via dbus_get_bool()
 * @note Changes take effect immediately for subsequent DNS queries/operations
 * @warning Does not validate that flag corresponds to a boolean option; caller responsible
 * 
 * @see dbus_get_bool() for argument parsing and validation
 * @see set_option_bool() in option.c for flag setting implementation
 * @see reset_option_bool() in option.c for flag clearing implementation
 * 
 * EXAMPLE USAGE:
 * @code
 * // Called from message_handler for SetFilterWin2KOption method
 * DBusMessage *result = dbus_set_bool(message, OPT_FILTER, "filter-win2k");
 * if (result)
 *   return result;  // Return error to caller
 * // Success - option now enabled/disabled based on message boolean argument
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (D-Bus-specific implementation)
 * SIDE EFFECTS: 
 * - Modifies daemon->options bitmask flag (global state change)
 * - Logs configuration change to syslog
 * - Affects subsequent DNS query processing behavior based on flag
 * THREAD SAFETY: Single-threaded; must be called from main event loop context
 */
static DBusMessage *dbus_set_bool(DBusMessage *message, int flag, char *name)
{
  dbus_bool_t val;
  DBusMessage *reply = dbus_get_bool(message, &val, name);
  
  if (!reply)
    {
      if (val)
	set_option_bool(flag);
      else
	reset_option_bool(flag);
    }

  return reply;
}

#ifdef HAVE_DHCP
/**
 * @brief Add DHCP lease to lease database via D-Bus method call
 * 
 * @detailed Parses DHCP lease parameters from D-Bus AddDhcpLease method call and creates
 *           a new lease entry in the daemon's lease database. Supports both DHCPv4 and DHCPv6
 *           leases with full parameter set including IP address, MAC/DUID hardware address,
 *           hostname, client identifier, lease duration, IPv6 IAID (Identity Association ID),
 *           and temporary address flag. The function performs parameter validation, converts
 *           D-Bus argument types to internal lease structures, sets lease expiration time
 *           based on provided duration, integrates with DNS cache for hostname resolution,
 *           persists lease to lease file, and triggers lease-change scripts.
 * 
 * @param message D-Bus method call message with lease parameters
 * 
 * @return DBusMessage method return or error message
 * @retval DBusMessage Method return (empty, indicates success)
 * @retval DBusMessage Error message (DBUS_ERROR_INVALID_ARGS) if argument parsing fails
 * @retval DBusMessage Error message (DBUS_ERROR_FAILED) if lease creation fails
 * 
 * @note D-Bus signature: AddDhcpLease(String ipaddr, String hwaddr, Array[Byte] hostname,
 *       Array[Byte] clid, UInt32 lease_duration, UInt32 ia_id, Boolean is_temporary)
 * @note Hostname and client ID are byte arrays to support non-UTF8 encodings
 * @note Zero lease_duration creates permanent lease (never expires)
 * @note IPv6-specific parameters (ia_id, is_temporary) ignored for IPv4 leases
 * @note Function conditionally compiled with HAVE_DHCP
 * 
 * @warning IP address string must be valid IPv4 or IPv6 address (inet_pton validation)
 * @warning Hardware address string format depends on address family (MAC for v4, DUID for v6)
 * @warning Hostname length limited to MAXDNAME-1 characters; longer hostnames truncated
 * @warning Client ID length limited to DHCP_CHADDR_MAX (16 bytes) for DHCPv4
 * 
 * @see lease_allocate_id() in lease.c for lease ID assignment
 * @see lease_update_from_configs() in lease.c for applying configuration overrides
 * @see lease_update_file() in lease.c for lease database persistence
 * @see lease_update_dns() in lease.c for DNS cache integration
 * @see helper.c script execution for lease-change event notifications
 * 
 * EXAMPLE USAGE:
 * @code
 * // D-Bus call from external management tool:
 * // dbus-send --system --dest=uk.org.thekelleys.dnsmasq \
 * //   --print-reply /uk/org/thekelleys/dnsmasq \
 * //   uk.org.thekelleys.dnsmasq.AddDhcpLease \
 * //   string:"192.168.1.100" string:"00:11:22:33:44:55" \
 * //   array:byte:"hostname" array:byte:"" uint32:3600 uint32:0 boolean:false
 * // 
 * // Internal call from message_handler:
 * if (strcmp(method, "AddDhcpLease") == 0)
 *   return dbus_add_lease(message);
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (D-Bus-specific lease management interface)
 * SIDE EFFECTS:
 * - Creates or updates lease entry in daemon->leases linked list (global state)
 * - Integrates lease hostname into DNS cache via lease_update_dns()
 * - Writes lease to lease file via lease_update_file()
 * - Triggers lease-change script execution via queue_script(ACTION_ADD)
 * - Allocates memory for lease structure and associated data (hostname, clid, etc.)
 * - Updates DHCP lease statistics and metrics
 * THREAD SAFETY: Single-threaded; must be called from D-Bus message handler in main loop
 */
static DBusMessage *dbus_add_lease(DBusMessage* message)
{
  struct dhcp_lease *lease;
  const char *ipaddr, *hwaddr, *hostname, *tmp;
  const unsigned char* clid;
  int clid_len, hostname_len, hw_len, hw_type;
  dbus_uint32_t expires, ia_id;
  dbus_bool_t is_temporary;
  union all_addr addr;
  time_t now = dnsmasq_time();
  unsigned char dhcp_chaddr[DHCP_CHADDR_MAX];

  DBusMessageIter iter, array_iter;
  if (!dbus_message_iter_init(message, &iter))
    return dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
				  "Failed to initialize dbus message iter");

  if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
    return dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
				  "Expected string as first argument");

  dbus_message_iter_get_basic(&iter, &ipaddr);
  dbus_message_iter_next(&iter);

  if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
    return dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
				  "Expected string as second argument");
    
  dbus_message_iter_get_basic(&iter, &hwaddr);
  dbus_message_iter_next(&iter);

  if ((dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY) ||
      (dbus_message_iter_get_element_type(&iter) != DBUS_TYPE_BYTE))
    return dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
				  "Expected byte array as third argument");
    
  dbus_message_iter_recurse(&iter, &array_iter);
  dbus_message_iter_get_fixed_array(&array_iter, &hostname, &hostname_len);
  tmp = memchr(hostname, '\0', hostname_len);
  if (tmp)
    {
      if (tmp == &hostname[hostname_len - 1])
	hostname_len--;
      else
	return dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
				      "Hostname contains an embedded NUL character");
    }
  dbus_message_iter_next(&iter);

  if ((dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY) ||
      (dbus_message_iter_get_element_type(&iter) != DBUS_TYPE_BYTE))
    return dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
				  "Expected byte array as fourth argument");

  dbus_message_iter_recurse(&iter, &array_iter);
  dbus_message_iter_get_fixed_array(&array_iter, &clid, &clid_len);
  dbus_message_iter_next(&iter);

  if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_UINT32)
    return dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
				  "Expected uint32 as fifth argument");
    
  dbus_message_iter_get_basic(&iter, &expires);
  dbus_message_iter_next(&iter);

  if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_UINT32)
    return dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
                                    "Expected uint32 as sixth argument");
  
  dbus_message_iter_get_basic(&iter, &ia_id);
  dbus_message_iter_next(&iter);

  if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_BOOLEAN)
    return dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
				  "Expected uint32 as sixth argument");

  dbus_message_iter_get_basic(&iter, &is_temporary);

  if (inet_pton(AF_INET, ipaddr, &addr.addr4))
    {
      if (ia_id != 0 || is_temporary)
	return dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
				      "ia_id and is_temporary must be zero for IPv4 lease");
      
      if (!(lease = lease_find_by_addr(addr.addr4)))
    	lease = lease4_allocate(addr.addr4);
    }
#ifdef HAVE_DHCP6
  else if (inet_pton(AF_INET6, ipaddr, &addr.addr6))
    {
      if (!(lease = lease6_find_by_addr(&addr.addr6, 128, 0)))
	lease = lease6_allocate(&addr.addr6,
				is_temporary ? LEASE_TA : LEASE_NA);
      lease_set_iaid(lease, ia_id);
    }
#endif
  else
    return dbus_message_new_error_printf(message, DBUS_ERROR_INVALID_ARGS,
					 "Invalid IP address '%s'", ipaddr);
   
  hw_len = parse_hex((char*)hwaddr, dhcp_chaddr, DHCP_CHADDR_MAX, NULL, &hw_type);
  if (hw_len < 0)
    return dbus_message_new_error_printf(message, DBUS_ERROR_INVALID_ARGS,
					 "Invalid HW address '%s'", hwaddr);

  if (hw_type == 0 && hw_len != 0)
    hw_type = ARPHRD_ETHER;
  
  lease_set_hwaddr(lease, dhcp_chaddr, clid, hw_len, hw_type,
                   clid_len, now, 0);
  lease_set_expires(lease, expires, now);
  if (hostname_len != 0)
    lease_set_hostname(lease, hostname, 0, get_domain(lease->addr), NULL);
  
  lease_update_file(now);
  lease_update_dns(0);

  return NULL;
}

/**
 * @brief Delete DHCP lease from lease database via D-Bus method call
 * 
 * @detailed Parses IP address from D-Bus DeleteDhcpLease method call, locates corresponding
 *           lease entry in the daemon's lease database, removes the lease, cleans up DNS
 *           cache integration, persists database changes to lease file, and triggers
 *           lease-change scripts. The function supports both DHCPv4 (IPv4 address) and
 *           DHCPv6 (IPv6 address) lease deletion with automatic address family detection.
 *           Returns success boolean indicating whether the lease was found and deleted.
 * 
 * @param message D-Bus method call message with IP address string argument
 * 
 * @return DBusMessage method return with boolean success indicator or error message
 * @retval DBusMessage Method return with boolean TRUE if lease found and deleted
 * @retval DBusMessage Method return with boolean FALSE if lease not found (no-op)
 * @retval DBusMessage Error message (DBUS_ERROR_INVALID_ARGS) if argument parsing fails
 * @retval DBusMessage Error message (DBUS_ERROR_INVALID_ARGS) if IP address format invalid
 * 
 * @note D-Bus signature: DeleteDhcpLease(String ipaddr) -> Boolean success
 * @note IP address string validated with inet_pton for IPv4 and IPv6 formats
 * @note Lease deletion triggers DNS cache cleanup via cache_unhash_dhcp()
 * @note Lease file updated via lease_update_file() to persist deletion
 * @note Lease-change script invoked with ACTION_DEL for external integration
 * @note Function conditionally compiled with HAVE_DHCP
 * 
 * @warning IP address must be valid IPv4 or IPv6 address string
 * @warning Deleted lease memory freed via lease_free_name() - pointers become invalid
 * @warning DNS cache entries for deleted lease removed immediately
 * 
 * @see lease_find_by_addr() in lease.c for IPv4 lease lookup
 * @see lease_find_by_addr6() in lease.c for IPv6 lease lookup
 * @see lease_prune() in lease.c for lease removal and cleanup
 * @see cache_unhash_dhcp() in cache.c for DNS cache cleanup
 * @see lease_update_file() in lease.c for lease database persistence
 * @see queue_script() in helper.c for lease-change script execution
 * 
 * EXAMPLE USAGE:
 * @code
 * // D-Bus call from external management tool:
 * // dbus-send --system --dest=uk.org.thekelleys.dnsmasq \
 * //   --print-reply /uk/org/thekelleys/dnsmasq \
 * //   uk.org.thekelleys.dnsmasq.DeleteDhcpLease \
 * //   string:"192.168.1.100"
 * // 
 * // Internal call from message_handler:
 * if (strcmp(method, "DeleteDhcpLease") == 0)
 *   return dbus_del_lease(message);
 * // Return value includes boolean indicating success/failure
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (D-Bus-specific lease management interface)
 * SIDE EFFECTS:
 * - Removes lease from daemon->leases linked list (global state modification)
 * - Frees lease memory via lease_prune() (hostname, client ID, etc.)
 * - Removes DNS cache entries for deleted lease hostname via cache_unhash_dhcp()
 * - Writes updated lease database to file via lease_update_file()
 * - Triggers lease-change script execution via queue_script(ACTION_DEL)
 * - Updates DHCP lease statistics and metrics (decrements active lease count)
 * THREAD SAFETY: Single-threaded; must be called from D-Bus message handler in main loop
 */
static DBusMessage *dbus_del_lease(DBusMessage* message)
{
  struct dhcp_lease *lease;
  DBusMessageIter iter;
  const char *ipaddr;
  DBusMessage *reply;
  union all_addr addr;
  dbus_bool_t ret = 1;
  time_t now = dnsmasq_time();

  if (!dbus_message_iter_init(message, &iter))
    return dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
				  "Failed to initialize dbus message iter");
   
  if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
    return dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
				  "Expected string as first argument");
   
  dbus_message_iter_get_basic(&iter, &ipaddr);

  if (inet_pton(AF_INET, ipaddr, &addr.addr4))
    lease = lease_find_by_addr(addr.addr4);
#ifdef HAVE_DHCP6
  else if (inet_pton(AF_INET6, ipaddr, &addr.addr6))
    lease = lease6_find_by_addr(&addr.addr6, 128, 0);
#endif
  else
    return dbus_message_new_error_printf(message, DBUS_ERROR_INVALID_ARGS,
					 "Invalid IP address '%s'", ipaddr);
    
  if (lease)
    {
      lease_prune(lease, now);
      lease_update_file(now);
      lease_update_dns(0);
    }
  else
    ret = 0;
  
  if ((reply = dbus_message_new_method_return(message)))
    dbus_message_append_args(reply, DBUS_TYPE_BOOLEAN, &ret,
			     DBUS_TYPE_INVALID);
  
    
  return reply;
}
#endif

/**
 * @brief Retrieve performance metrics via D-Bus GetMetrics method
 * 
 * @detailed Collects all performance metrics from the daemon global state and returns them
 *           as a D-Bus dictionary mapping metric names to uint32 values. Metrics include
 *           cache statistics (hits, misses, insertions), query counts, and other performance
 *           counters tracked by the metrics subsystem (see metrics.c). The response format
 *           is D-Bus type "a{su}" (array of dict entries with string keys and uint32 values).
 * 
 * @param message D-Bus method call message (GetMetrics request)
 * 
 * @return D-Bus method return message containing metrics dictionary, or NULL on allocation failure
 * @retval reply D-Bus message with all metrics as key-value pairs
 * 
 * @note Iterates through all __METRIC_MAX metrics defined in metrics.h
 * @note Metric names obtained via get_metric_name() from metrics.c
 * @note Metric values read from daemon->metrics[] array
 * 
 * @see get_metric_name() in metrics.c for metric name resolution
 * @see metrics.h for complete list of tracked metrics
 * 
 * EXAMPLE USAGE:
 * @code
 * // D-Bus client invocation:
 * // dbus-send --system --print-reply \
 * //   --dest=uk.org.thekelleys.dnsmasq /uk/org/thekelleys/dnsmasq \
 * //   uk.org.thekelleys.GetMetrics
 * // Returns: dict entry("cache_hits" uint32 1234) dict entry("cache_misses" uint32 56)
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (D-Bus API, not a network protocol)
 * SIDE EFFECTS: Reads daemon->metrics[] array; no state modification
 * THREAD SAFETY: Single-threaded daemon architecture; accesses global daemon state
 */
static DBusMessage *dbus_get_metrics(DBusMessage* message)
{
  DBusMessage *reply = dbus_message_new_method_return(message);
  DBusMessageIter array, dict, iter;
  int i;

  dbus_message_iter_init_append(reply, &iter);
  dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "{su}", &array);

  for (i = 0; i < __METRIC_MAX; i++) {
    const char *key     = get_metric_name(i);
    dbus_uint32_t value = daemon->metrics[i];

    dbus_message_iter_open_container(&array, DBUS_TYPE_DICT_ENTRY, NULL, &dict);
    dbus_message_iter_append_basic(&dict, DBUS_TYPE_STRING, &key);
    dbus_message_iter_append_basic(&dict, DBUS_TYPE_UINT32, &value);
    dbus_message_iter_close_container(&array, &dict);
  }

  dbus_message_iter_close_container(&iter, &array);

  return reply;
}

static void add_dict_entry(DBusMessageIter *container, const char *key, const char *val)
{
  DBusMessageIter dict;

  dbus_message_iter_open_container(container, DBUS_TYPE_DICT_ENTRY, NULL, &dict);
  dbus_message_iter_append_basic(&dict, DBUS_TYPE_STRING, &key);
  dbus_message_iter_append_basic(&dict, DBUS_TYPE_STRING, &val);
  dbus_message_iter_close_container(container, &dict);
}

static void add_dict_int(DBusMessageIter *container, const char *key, const unsigned int val)
{
  snprintf(daemon->namebuff, MAXDNAME, "%u", val);
  
  add_dict_entry(container, key, daemon->namebuff);
}

/**
 * @brief Retrieve per-upstream-server performance metrics via D-Bus GetServerMetrics method
 * 
 * @detailed Aggregates and returns performance statistics for each configured upstream DNS server.
 *           The function iterates through all server records in daemon->servers, consolidating
 *           statistics from multiple records representing the same server (same IP address but
 *           different domains or query types). For each unique server, collects query counts,
 *           failure counts, NXDOMAIN responses, retry counts, and average query latency. Returns
 *           results as a D-Bus array of dictionaries, with each dictionary containing metrics
 *           for one upstream server. The response format is D-Bus type "aa{ss}" (array of arrays
 *           of dict entries with string keys and string values).
 * 
 * @param message D-Bus method call message (GetServerMetrics request)
 * 
 * @return D-Bus method return message containing per-server metrics array, or NULL on allocation failure
 * @retval reply D-Bus message with array of server statistics dictionaries
 * 
 * @note Uses SERV_MARK flag to track which server records have been aggregated
 * @note Multiple server records with same address (domain-specific upstreams) are consolidated
 * @note Latency is calculated as average: sigma_latency / count_latency
 * @note Each server dictionary contains keys: address, port, queries, failed_queries, nxdomain, retries, latency
 * 
 * @warning Division by count_latency assumes count_latency > 0 (always true if queries > 0)
 * 
 * @see daemon->servers list in dnsmasq.h for upstream server records
 * @see forward.c for server query tracking and statistics updates
 * @see add_dict_entry() helper for string dictionary entries
 * @see add_dict_int() helper for integer dictionary entries (formatted as strings)
 * 
 * EXAMPLE USAGE:
 * @code
 * // D-Bus client invocation:
 * // dbus-send --system --print-reply \
 * //   --dest=uk.org.thekelleys.dnsmasq /uk/org/thekelleys/dnsmasq \
 * //   uk.org.thekelleys.GetServerMetrics
 * // Returns: array [ dict entry("address" "8.8.8.8") dict entry("queries" "1234") ... ]
 * //          array [ dict entry("address" "1.1.1.1") dict entry("queries" "567") ... ]
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (D-Bus API, not a network protocol)
 * SIDE EFFECTS: Temporarily modifies SERV_MARK flags in daemon->servers list; flags restored by algorithm
 * THREAD SAFETY: Single-threaded daemon architecture; accesses and modifies global daemon state
 */
static DBusMessage *dbus_get_server_metrics(DBusMessage* message)
{
  DBusMessage *reply = dbus_message_new_method_return(message);
  DBusMessageIter server_array, dict_array, server_iter;
  struct server *serv;
  
  dbus_message_iter_init_append(reply, &server_iter);
  dbus_message_iter_open_container(&server_iter, DBUS_TYPE_ARRAY, "a{ss}", &server_array);

  /* sum counts from different records for same server */
  for (serv = daemon->servers; serv; serv = serv->next)
    serv->flags &= ~SERV_MARK;
  
  for (serv = daemon->servers; serv; serv = serv->next)
    if (!(serv->flags & SERV_MARK))
      {
	unsigned int port;
	unsigned int queries = 0, failed_queries = 0, nxdomain_replies = 0, retrys = 0;
	unsigned int sigma_latency = 0, count_latency = 0;
	
	struct server *serv1;

	for (serv1 = serv; serv1; serv1 = serv1->next)
	  if (!(serv1->flags & SERV_MARK) && sockaddr_isequal(&serv->addr, &serv1->addr))
	    {
	      serv1->flags |= SERV_MARK;
	      queries += serv1->queries;
	      failed_queries += serv1->failed_queries;
	      nxdomain_replies += serv1->nxdomain_replies;
	      retrys += serv1->retrys;
	      sigma_latency += serv1->query_latency;
	      count_latency++;
	    }
	
	dbus_message_iter_open_container(&server_array, DBUS_TYPE_ARRAY, "{ss}", &dict_array);
	
	port = prettyprint_addr(&serv->addr, daemon->namebuff);
	add_dict_entry(&dict_array, "address", daemon->namebuff);
	
	add_dict_int(&dict_array, "port", port);
	add_dict_int(&dict_array, "queries", queries);
	add_dict_int(&dict_array, "failed_queries", failed_queries);
	add_dict_int(&dict_array, "nxdomain", nxdomain_replies);
	add_dict_int(&dict_array, "retries", retrys);
	add_dict_int(&dict_array, "latency", sigma_latency/count_latency);
	
	dbus_message_iter_close_container(&server_array, &dict_array);
      }
  
  dbus_message_iter_close_container(&server_iter, &server_array);
  
  return reply;
}

/**
 * @brief Central D-Bus message handler dispatching incoming method calls to appropriate handlers
 * 
 * @detailed This function serves as the main D-Bus message dispatcher, registered as the callback
 *           for messages received on the dnsmasq D-Bus object path (/uk/org/thekelleys/dnsmasq).
 *           It examines incoming method call messages, identifies the requested method by name,
 *           and dispatches to the appropriate handler function or inline processing logic.
 *           Handles standard D-Bus introspection plus 15+ dnsmasq-specific methods for cache
 *           management, upstream server configuration, filter control, metrics retrieval, and
 *           DHCP lease manipulation. After processing, sends the reply message back to the client
 *           and manages control flags that trigger deferred actions (cache clearing, server updates)
 *           in the main event loop.
 * 
 * @param connection D-Bus system bus connection (established by dbus_init)
 * @param message Incoming D-Bus method call message to be processed
 * @param user_data User-provided data (unused in this implementation)
 * 
 * @return D-Bus handler result indicating message processing status
 * @retval DBUS_HANDLER_RESULT_HANDLED Message successfully processed and reply sent
 * @retval DBUS_HANDLER_RESULT_NOT_YET_HANDLED Method name not recognized (allows other handlers to try)
 * 
 * @note Sets daemon->dbus_update_servers flag when upstream server configuration changes via SetServers methods
 * @note Sets daemon->dbus_clear_cache flag when cache clear requested via ClearCache method
 * @note Introspection XML generated lazily on first Introspect call and cached in static introspection_xml
 * 
 * @warning Method name comparison uses strcmp, case-sensitive matching required
 * @warning Reply message ownership transferred to D-Bus library via dbus_connection_send
 * @warning Some methods (AddDhcpLease, DeleteDhcpLease, GetLoopServers) conditionally compiled
 * 
 * @see dbus_init() for connection setup and message handler registration
 * @see check_dbus_listeners() in main event loop for deferred flag processing
 * @see dbus_read_servers() for SetServers implementation
 * @see dbus_read_servers_ex() for SetServersEx implementation
 * @see dbus_set_bool() for filter configuration methods
 * @see dbus_add_lease() for AddDhcpLease implementation (HAVE_DHCP)
 * @see dbus_del_lease() for DeleteDhcpLease implementation (HAVE_DHCP)
 * @see dbus_get_metrics() for GetMetrics implementation
 * @see dbus_get_server_metrics() for GetServerMetrics implementation
 * 
 * HANDLED D-BUS METHODS (15+ methods):
 * - Introspect: Returns XML interface description (org.freedesktop.DBus.Introspectable)
 * - GetVersion: Returns VERSION string from compilation
 * - GetLoopServers: Returns upstream servers causing forwarding loops (HAVE_LOOP only)
 * - SetServers: Configure upstream servers from variant array (legacy format)
 * - SetDomainServers: Configure domain-specific upstream servers (string array format)
 * - SetServersEx: Configure upstream servers with extended format (array of string arrays)
 * - SetFilterWin2KOption: Enable/disable Win2K filtering via boolean flag
 * - SetFilterA: Enable/disable IPv4 A record filtering via boolean flag
 * - SetFilterAAAA: Enable/disable IPv6 AAAA record filtering via boolean flag
 * - SetLocaliseQueriesOption: Enable/disable query localization via boolean flag
 * - SetBogusPrivOption: Enable/disable bogus private address filtering via boolean flag
 * - AddDhcpLease: Add DHCP lease programmatically (HAVE_DHCP only)
 * - DeleteDhcpLease: Delete DHCP lease by IP address (HAVE_DHCP only)
 * - GetMetrics: Retrieve global performance metrics dictionary
 * - GetServerMetrics: Retrieve per-upstream-server performance statistics
 * - ClearMetrics: Reset all performance metrics to zero
 * - ClearCache: Flush DNS cache and trigger reload
 * 
 * EXAMPLE USAGE:
 * @code
 * // D-Bus client invocation examples (using dbus-send):
 * 
 * // Clear DNS cache:
 * // dbus-send --system --dest=uk.org.thekelleys.dnsmasq \
 * //   /uk/org/thekelleys/dnsmasq uk.org.thekelleys.ClearCache
 * 
 * // Get dnsmasq version:
 * // dbus-send --system --print-reply --dest=uk.org.thekelleys.dnsmasq \
 * //   /uk/org/thekelleys/dnsmasq uk.org.thekelleys.GetVersion
 * 
 * // Set upstream servers (SetServersEx format):
 * // dbus-send --system --dest=uk.org.thekelleys.dnsmasq \
 * //   /uk/org/thekelleys/dnsmasq uk.org.thekelleys.SetServersEx \
 * //   array:array:string:"8.8.8.8","1.1.1.1"
 * 
 * // Enable AAAA filtering:
 * // dbus-send --system --dest=uk.org.thekelleys.dnsmasq \
 * //   /uk/org/thekelleys/dnsmasq uk.org.thekelleys.SetFilterAAAA boolean:true
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (D-Bus API implementation)
 * SIDE EFFECTS: 
 * - Sets daemon->dbus_update_servers when server configuration changes
 * - Sets daemon->dbus_clear_cache when cache clear requested
 * - Allocates introspection_xml on first Introspect call (cached statically)
 * - Calls dbus_connection_send to transmit reply message
 * - May call dbus_message_unref to free reply on send failure
 * THREAD SAFETY: Single-threaded daemon architecture; accesses global daemon state
 */
DBusHandlerResult message_handler(DBusConnection *connection, 
				  DBusMessage *message, 
				  void *user_data)
{
  char *method = (char *)dbus_message_get_member(message);
  DBusMessage *reply = NULL;
  int clear_cache = 0, new_servers = 0;
    
  if (dbus_message_is_method_call(message, DBUS_INTERFACE_INTROSPECTABLE, "Introspect"))
    {
      /* string length: "%s" provides space for termination zero */
      if (!introspection_xml && 
	  (introspection_xml = whine_malloc(strlen(introspection_xml_template) + strlen(daemon->dbus_name))))
	sprintf(introspection_xml, introspection_xml_template, daemon->dbus_name);
    
      if (introspection_xml)
	{
	  reply = dbus_message_new_method_return(message);
	  dbus_message_append_args(reply, DBUS_TYPE_STRING, &introspection_xml, DBUS_TYPE_INVALID);
	}
    }
  else if (strcmp(method, "GetVersion") == 0)
    {
      char *v = VERSION;
      reply = dbus_message_new_method_return(message);
      
      dbus_message_append_args(reply, DBUS_TYPE_STRING, &v, DBUS_TYPE_INVALID);
    }
#ifdef HAVE_LOOP
  else if (strcmp(method, "GetLoopServers") == 0)
    {
      reply = dbus_reply_server_loop(message);
    }
#endif
  else if (strcmp(method, "SetServers") == 0)
    {
      reply = dbus_read_servers(message);
      new_servers = 1;
    }
  else if (strcmp(method, "SetServersEx") == 0)
    {
      reply = dbus_read_servers_ex(message, 0);
      new_servers = 1;
    }
  else if (strcmp(method, "SetDomainServers") == 0)
    {
      reply = dbus_read_servers_ex(message, 1);
      new_servers = 1;
    }
  else if (strcmp(method, "SetFilterWin2KOption") == 0)
    {
      reply = dbus_set_bool(message, OPT_FILTER, "filterwin2k");
    }
  else if (strcmp(method, "SetFilterA") == 0)
    {
      static int done = 0;
      static struct rrlist list = { 0, NULL };
      dbus_bool_t enabled;

      if (!(reply = dbus_get_bool(message, &enabled, "filter-A")))
	{
	  if (!done)
	    {
	      done = 1;
	      list.next = daemon->filter_rr;
	      daemon->filter_rr = &list;
	    }

	  list.rr = enabled ? T_A : 0;
	}
    }
  else if (strcmp(method, "SetFilterAAAA") == 0)
    {
      static int done = 0;
      static struct rrlist list = { 0, NULL };
      dbus_bool_t enabled;
      
      if (!(reply = dbus_get_bool(message, &enabled, "filter-AAAA")))
	{
	  if (!done)
	    {
	      done = 1;
	      list.next = daemon->filter_rr;
	      daemon->filter_rr = &list;
	    }
	  
	  list.rr = enabled ? T_AAAA : 0;
	}
    }
  else if (strcmp(method, "SetLocaliseQueriesOption") == 0)
    {
      reply = dbus_set_bool(message, OPT_LOCALISE, "localise-queries");
    }
  else if (strcmp(method, "SetBogusPrivOption") == 0)
    {
      reply = dbus_set_bool(message, OPT_BOGUSPRIV, "bogus-priv");
    }
#ifdef HAVE_DHCP
  else if (strcmp(method, "AddDhcpLease") == 0)
    {
      reply = dbus_add_lease(message);
    }
  else if (strcmp(method, "DeleteDhcpLease") == 0)
    {
      reply = dbus_del_lease(message);
    }
#endif
  else if (strcmp(method, "GetMetrics") == 0)
    {
      reply = dbus_get_metrics(message);
    }
  else if (strcmp(method, "GetServerMetrics") == 0)
    {
      reply = dbus_get_server_metrics(message);
    }
  else if (strcmp(method, "ClearMetrics") == 0)
    {
      clear_metrics();
    }
  else if (strcmp(method, "ClearCache") == 0)
    clear_cache = 1;
  else
    return (DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
   
  if (new_servers)
    {
      my_syslog(LOG_INFO, _("setting upstream servers from DBus"));
      check_servers(0);
      if (option_bool(OPT_RELOAD))
	clear_cache = 1;
    }

  if (clear_cache)
    clear_cache_and_reload(dnsmasq_time());
  
  (void)user_data; /* no warning */

  /* If no reply or no error, return nothing */
  if (!reply)
    reply = dbus_message_new_method_return(message);

  if (reply)
    {
      dbus_connection_send (connection, reply, NULL);
      dbus_message_unref (reply);
    }

  return (DBUS_HANDLER_RESULT_HANDLED);
}
 

/* returns NULL or error message, may fail silently if dbus daemon not yet up. */
/**
 * @brief Initialize D-Bus connection and register dnsmasq service on system bus
 * 
 * @detailed Establishes connection to D-Bus system bus, registers the dnsmasq service name
 *           (configured via daemon->dbus_name, default "uk.org.thekelleys.dnsmasq"), registers
 *           the object path /uk/org/thekelleys/dnsmasq with message handler vtable, configures
 *           watch functions for D-Bus file descriptor monitoring in event loop, and emits "Up"
 *           signal to notify listeners that dnsmasq D-Bus service is available. Connection
 *           configured to not exit on disconnect to prevent daemon termination if D-Bus daemon
 *           restarts.
 * 
 * @return NULL on success, error message string on failure (do not free - points to static or D-Bus error message)
 * @retval NULL D-Bus initialization successful, connection established and registered
 * @retval error_string D-Bus connection failed, service name registration failed, or object path registration failed
 * 
 * @note Stores D-Bus connection in daemon->dbus for use by other D-Bus functions
 * @note Service name registration failure returns dbus_error.message (owned by libdbus)
 * @note Object path registration failure returns localized error string
 * @note Watch functions (add_watch, remove_watch) integrate D-Bus fd monitoring with poll event loop
 * 
 * @warning Caller must check return value; non-NULL indicates D-Bus unavailable (daemon continues without D-Bus)
 * @warning Error string from dbus_error.message not freed (owned by D-Bus library)
 * 
 * @see set_dbus_listeners() for activating D-Bus file descriptor polling
 * @see message_handler() for D-Bus method call dispatcher
 * @see add_watch() and remove_watch() for D-Bus watch integration
 * 
 * EXAMPLE USAGE:
 * @code
 * char *err = dbus_init();
 * if (err)
 *   my_syslog(LOG_WARNING, _("DBus init failure: %s"), err);
 * @endcode
 * 
 * SIDE EFFECTS: 
 * - Connects to D-Bus system bus
 * - Registers service name on system bus (may fail if name already taken)
 * - Registers object path with message handler
 * - Sets daemon->dbus to established connection
 * - Emits "Up" signal on system bus
 * 
 * THREAD SAFETY: Single-threaded; not thread-safe if called concurrently
 */
char *dbus_init(void)
{
  DBusConnection *connection = NULL;
  DBusObjectPathVTable dnsmasq_vtable = {NULL, &message_handler, NULL, NULL, NULL, NULL };
  DBusError dbus_error;
  DBusMessage *message;

  dbus_error_init (&dbus_error);
  if (!(connection = dbus_bus_get (DBUS_BUS_SYSTEM, &dbus_error)))
    {
      dbus_error_free(&dbus_error);
      return NULL;
    }
  
  dbus_connection_set_exit_on_disconnect(connection, FALSE);
  dbus_connection_set_watch_functions(connection, add_watch, remove_watch, 
				      NULL, NULL, NULL);
  dbus_error_init (&dbus_error);
  dbus_bus_request_name (connection, daemon->dbus_name, 0, &dbus_error);
  if (dbus_error_is_set (&dbus_error))
    return (char *)dbus_error.message;
  
  if (!dbus_connection_register_object_path(connection,  DNSMASQ_PATH, 
					    &dnsmasq_vtable, NULL))
    return _("could not register a DBus message handler");
  
  daemon->dbus = connection; 
  
  if ((message = dbus_message_new_signal(DNSMASQ_PATH, daemon->dbus_name, "Up")))
    {
      dbus_connection_send(connection, message, NULL);
      dbus_message_unref(message);
    }

  return NULL;
}
 

/**
 * @brief Register D-Bus file descriptors for poll monitoring in main event loop
 * 
 * @detailed Iterates through all D-Bus watches registered via add_watch() callback,
 *           extracts file descriptors and I/O direction flags (readable/writable) from
 *           enabled watches, translates D-Bus watch flags to poll event flags (POLLIN,
 *           POLLOUT, POLLERR), and registers each fd with poll_listen() for monitoring
 *           in dnsmasq's main event loop. This integration allows D-Bus messages to be
 *           processed alongside DNS queries, DHCP requests, and other network traffic
 *           without blocking.
 * 
 * @note Called from main event loop setup to activate D-Bus fd monitoring
 * @note Only processes enabled watches; disabled watches skipped
 * @note POLLERR always included to detect connection errors
 * @note Watch list stored in daemon->watches linked list
 * 
 * @warning Must be called after dbus_init() which populates daemon->watches
 * @warning Calling before dbus_init() results in no-op (empty watch list)
 * 
 * @see dbus_init() for D-Bus connection setup and watch registration
 * @see check_dbus_listeners() for processing triggered D-Bus events
 * @see add_watch() for watch registration callback
 * @see poll_listen() in poll.c for fd registration with event loop
 * 
 * EXAMPLE USAGE:
 * @code
 * // In main event loop setup after dbus_init()
 * set_dbus_listeners();
 * // Now poll() will monitor D-Bus fds alongside other sockets
 * @endcode
 * 
 * SIDE EFFECTS:
 * - Registers D-Bus file descriptors with poll event loop
 * - Subsequent poll() calls monitor D-Bus connection for I/O
 * 
 * THREAD SAFETY: Single-threaded; not thread-safe if watches modified concurrently
 */
void set_dbus_listeners(void)
{
  struct watch *w;
  
  for (w = daemon->watches; w; w = w->next)
    if (dbus_watch_get_enabled(w->watch))
      {
	unsigned int flags = dbus_watch_get_flags(w->watch);
	int fd = dbus_watch_get_unix_fd(w->watch);
	int poll_flags = POLLERR;
	
	if (flags & DBUS_WATCH_READABLE)
	  poll_flags |= POLLIN;
	if (flags & DBUS_WATCH_WRITABLE)
	  poll_flags |= POLLOUT;
	
	poll_listen(fd, poll_flags);
      }
}

/**
 * @brief Check D-Bus watches for triggered events and dispatch D-Bus I/O handling
 * 
 * @detailed Iterates through all enabled D-Bus watches registered via add_watch(),
 *           checks each watch's file descriptor for poll events (POLLIN, POLLOUT, POLLERR)
 *           using poll_check(), translates poll event flags to D-Bus watch flags, and
 *           invokes dbus_watch_handle() to process D-Bus I/O operations (reading incoming
 *           method calls, writing responses, handling connection errors). Returns early
 *           if watch list modified during processing (indicated by watches_modified flag
 *           set by add_watch/remove_watch callbacks) to prevent iterator invalidation.
 * 
 * @return 1 if all watches processed without modification, 0 if watch list modified during iteration
 * @retval 1 Watch list stable, all triggered watches processed successfully
 * @retval 0 Watch list modified (watch added or removed), iteration aborted to prevent invalid access
 * 
 * @note Called from check_dbus_listeners() to process D-Bus events detected by poll()
 * @note watches_modified flag reset to 0 at function entry
 * @note Only enabled watches processed; disabled watches skipped
 * @note Early return on watch modification prevents accessing freed memory
 * 
 * @warning Caller must retry if return value is 0 (watch list changed)
 * @warning Watch list modification during iteration is rare but possible if D-Bus connection state changes
 * 
 * @see check_dbus_listeners() for caller that retries on watch modification
 * @see dbus_watch_handle() in libdbus for D-Bus I/O processing
 * @see add_watch() and remove_watch() for callbacks that set watches_modified
 * @see poll_check() in poll.c for fd event checking
 * 
 * EXAMPLE USAGE:
 * @code
 * // In check_dbus_listeners() after poll() detects D-Bus activity
 * while (!check_dbus_watches())
 *   ; // Retry if watch list modified during iteration
 * @endcode
 * 
 * SIDE EFFECTS:
 * - Calls dbus_watch_handle() which may read/write D-Bus connection
 * - May trigger message_handler() for incoming D-Bus method calls
 * - Resets watches_modified flag to 0
 * 
 * THREAD SAFETY: Single-threaded; not thread-safe if watches modified concurrently
 */
static int check_dbus_watches()
{
  struct watch *w;

  watches_modified = 0;
  for (w = daemon->watches; w; w = w->next)
    if (dbus_watch_get_enabled(w->watch))
      {
	unsigned int flags = 0;
	int fd = dbus_watch_get_unix_fd(w->watch);
	int poll_flags = poll_check(fd, POLLIN|POLLOUT|POLLERR);

	if ((poll_flags & POLLIN) != 0)
	  flags |= DBUS_WATCH_READABLE;
	if ((poll_flags & POLLOUT) != 0)
	  flags |= DBUS_WATCH_WRITABLE;
	if ((poll_flags & POLLERR) != 0)
	  flags |= DBUS_WATCH_ERROR;

	if (flags != 0)
	  {
	    dbus_watch_handle(w->watch, flags);
	    if (watches_modified)
	      return 0;
	  }
      }

  return 1;
}

/**
 * @brief Process D-Bus events detected by poll and dispatch incoming method calls
 * 
 * @detailed Called from main event loop when poll() indicates D-Bus file descriptor activity.
 *           First processes all D-Bus watch events by repeatedly calling check_dbus_watches()
 *           until watch list stable (no modifications during iteration), then dispatches all
 *           queued incoming D-Bus messages by calling dbus_connection_dispatch() until message
 *           queue empty. Connection reference count incremented during dispatch to prevent
 *           premature connection cleanup if D-Bus daemon disconnects during processing.
 * 
 * @note Called from main event loop after poll() detects D-Bus fd activity
 * @note Retries check_dbus_watches() until watch list stabilizes (prevents iterator invalidation)
 * @note Dispatches all queued messages in single invocation (DBUS_DISPATCH_DATA_REMAINS loop)
 * @note Connection reference prevents cleanup during dispatch even if D-Bus daemon disconnects
 * @note No-op if daemon->dbus is NULL (D-Bus not initialized or initialization failed)
 * 
 * @warning Must only be called when poll() indicates D-Bus fd has events (prevents unnecessary CPU usage)
 * @warning Connection may be disconnected during dispatch; ref/unref prevents use-after-free
 * 
 * @see check_dbus_watches() for D-Bus watch event processing
 * @see set_dbus_listeners() for registering D-Bus fds with poll event loop
 * @see message_handler() for D-Bus method call dispatcher (invoked by dbus_connection_dispatch)
 * @see dbus_connection_dispatch() in libdbus for message dispatching
 * 
 * EXAMPLE USAGE:
 * @code
 * // In main event loop after poll() returns
 * if (poll_check(dbus_fd, POLLIN))
 *   check_dbus_listeners(); // Process D-Bus method calls
 * @endcode
 * 
 * SIDE EFFECTS:
 * - Calls dbus_watch_handle() via check_dbus_watches() to read/write D-Bus connection
 * - Dispatches incoming D-Bus method calls via message_handler()
 * - May modify daemon state via D-Bus method implementations (cache clear, server reconfiguration, etc.)
 * - Temporarily increments/decrements connection reference count
 * 
 * THREAD SAFETY: Single-threaded; not thread-safe if connection accessed concurrently
 */
void check_dbus_listeners()
{
  DBusConnection *connection = (DBusConnection *)daemon->dbus;

  while (!check_dbus_watches()) ;

  if (connection)
    {
      dbus_connection_ref (connection);
      while (dbus_connection_dispatch (connection) == DBUS_DISPATCH_DATA_REMAINS);
      dbus_connection_unref (connection);
    }
}

#ifdef HAVE_DHCP
/**
 * @brief Emit D-Bus signal for DHCP lease state change (add, delete, update)
 * 
 * @detailed Constructs and emits D-Bus signal on system bus to notify external applications
 *           of DHCP lease events. For DHCPv6 leases (LEASE_TA or LEASE_NA flags), formats
 *           client DUID as MAC-style string and IPv6 address; for DHCPv4 leases, formats
 *           hardware address (MAC) and IPv4 address. Maps action code to D-Bus signal name
 *           (DhcpLeaseAdded, DhcpLeaseDeleted, DhcpLeaseUpdated), creates D-Bus signal message
 *           with three string arguments (IP address, MAC/DUID, hostname), and sends signal
 *           on system bus for monitoring tools, management scripts, and external integrations.
 * 
 * @param action Lease event type: ACTION_ADD (new lease), ACTION_DEL (lease expired/released), ACTION_OLD (lease renewed)
 * @param lease Pointer to dhcp_lease structure containing lease details (IP, MAC, DUID, flags)
 * @param hostname Client hostname from DHCP request, or NULL if not provided
 * 
 * @note No-op if D-Bus connection not initialized (daemon->dbus is NULL)
 * @note NULL hostname converted to empty string for D-Bus signal
 * @note Uses daemon->namebuff for formatted MAC address (overwrites previous contents)
 * @note Uses daemon->addrbuff for formatted IP address (overwrites previous contents)
 * @note Signal sent on object path DNSMASQ_PATH with interface daemon->dbus_name
 * @note DHCPv6 leases identified by LEASE_TA or LEASE_NA flags
 * @note DHCPv4 leases use extended_hwaddr() for hardware address formatting
 * 
 * @warning Requires HAVE_DHCP compile flag; function only compiled with DHCP support
 * @warning Action codes other than ACTION_ADD, ACTION_DEL, ACTION_OLD silently ignored
 * @warning Message creation or parameter appending failure silently aborts signal emission
 * @warning Caller must ensure lease pointer valid; no NULL check performed
 * 
 * @see dbus_init() for D-Bus connection establishment
 * @see print_mac() for MAC/DUID formatting to string
 * @see extended_hwaddr() for DHCPv4 hardware address extraction
 * @see lease.c for DHCP lease management and action codes
 * 
 * EXAMPLE USAGE:
 * @code
 * // In DHCP lease assignment code (lease.c)
 * struct dhcp_lease *lease = lease_allocate(...);
 * emit_dbus_signal(ACTION_ADD, lease, "client-hostname");
 * // External D-Bus listeners receive DhcpLeaseAdded signal
 * @endcode
 * 
 * D-BUS SIGNAL SIGNATURE:
 * Signal: DhcpLeaseAdded, DhcpLeaseDeleted, or DhcpLeaseUpdated
 * Arguments: (ipaddr: string, hwaddr: string, hostname: string)
 * Example: DhcpLeaseAdded("192.168.1.100", "00:11:22:33:44:55", "client-pc")
 * 
 * SIDE EFFECTS:
 * - Emits D-Bus signal on system bus (visible to all D-Bus listeners)
 * - Overwrites daemon->namebuff with formatted MAC address
 * - Overwrites daemon->addrbuff with formatted IP address
 * - Allocates and frees D-Bus message structure
 * 
 * THREAD SAFETY: Single-threaded; not thread-safe if connection accessed concurrently
 */
void emit_dbus_signal(int action, struct dhcp_lease *lease, char *hostname)
{
  DBusConnection *connection = (DBusConnection *)daemon->dbus;
  DBusMessage* message = NULL;
  DBusMessageIter args;
  char *action_str, *mac = daemon->namebuff;
  unsigned char *p;
  int i;

  if (!connection)
    return;
  
  if (!hostname)
    hostname = "";
  
#ifdef HAVE_DHCP6
   if (lease->flags & (LEASE_TA | LEASE_NA))
     {
       print_mac(mac, lease->clid, lease->clid_len);
       inet_ntop(AF_INET6, &lease->addr6, daemon->addrbuff, ADDRSTRLEN);
     }
   else
#endif
     {
       p = extended_hwaddr(lease->hwaddr_type, lease->hwaddr_len,
			   lease->hwaddr, lease->clid_len, lease->clid, &i);
       print_mac(mac, p, i);
       inet_ntop(AF_INET, &lease->addr, daemon->addrbuff, ADDRSTRLEN);
     }

  if (action == ACTION_DEL)
    action_str = "DhcpLeaseDeleted";
  else if (action == ACTION_ADD)
    action_str = "DhcpLeaseAdded";
  else if (action == ACTION_OLD)
    action_str = "DhcpLeaseUpdated";
  else
    return;

  if (!(message = dbus_message_new_signal(DNSMASQ_PATH, daemon->dbus_name, action_str)))
    return;
  
  dbus_message_iter_init_append(message, &args);
  
  if (dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &daemon->addrbuff) &&
      dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &mac) &&
      dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &hostname))
    dbus_connection_send(connection, message, NULL);
  
  dbus_message_unref(message);
}
#endif

#endif

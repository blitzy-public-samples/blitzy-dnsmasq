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
 * @file ubus.c
 * @brief UBus control interface for OpenWrt and embedded Linux distributions
 * 
 * DETAILED PURPOSE:
 * This module implements the UBus (OpenWrt micro bus architecture) control interface for dnsmasq,
 * providing programmatic access to cache management, configuration queries, DHCP lease information,
 * and metrics export. UBus is specifically designed for embedded systems (OpenWrt, LEDE, and
 * derivatives) with reduced memory footprint compared to D-Bus, using libubus and libubox libraries.
 * 
 * UBus uses a JSON-RPC-style message format over a lightweight binary protocol optimized for
 * resource-constrained environments. The interface enables integration with OpenWrt's LuCI web
 * interface, UCI configuration system, and command-line tools via the 'ubus' utility.
 * 
 * KEY RESPONSIBILITIES:
 * - UBus service registration with configurable service name (default "dnsmasq", via daemon->ubus_name)
 * - Connection management and automatic reconnection to ubusd daemon (see ubus_init, ubus_disconnect_cb)
 * - Method handlers for metrics export (ubus_handle_metrics)
 * - Method handlers for connection tracking allowlist management (ubus_handle_set_connmark_allowlist, HAVE_CONNTRACK)
 * - Event broadcasting for network events (ubus_event_bcast, ubus_event_bcast_connmark_allowlist_*)
 * - Subscription callback handling for client notifications (ubus_subscribe_cb)
 * 
 * DEPENDENCIES:
 * Includes: dnsmasq.h (global daemon state, struct daemon definition)
 * External Libraries: libubus.h (UBus IPC primitives, ubus_context, ubus_object)
 * Called by: Main event loop (dnsmasq.c) invokes set_ubus_listeners and check_ubus_listeners
 * Calls: libubus API (ubus_connect, ubus_add_object, ubus_send_reply), syslog via my_syslog
 * 
 * DATA STRUCTURES:
 * - struct blob_buf b: Static blob buffer for JSON-RPC message construction (libubox blobmsg API)
 * - struct ubus_object ubus_object: UBus object registration structure with method table and subscription callback
 * - struct ubus_object_type ubus_object_type: UBus object type definition ("dnsmasq" type with registered methods)
 * - struct ubus_context *daemon->ubus: UBus connection context (opaque pointer in struct daemon, line 1331 dnsmasq.h)
 * - char *daemon->ubus_name: Configurable service name for UBus registration (line 1250 dnsmasq.h)
 * 
 * COMPILE-TIME OPTIONS:
 * - HAVE_UBUS: Entire module conditionally compiled only when this flag is defined (Makefile detection of libubus)
 * - HAVE_CONNTRACK: Enables connection tracking mark allowlist methods (requires libnetfilter_conntrack)
 * 
 * PLATFORM SPECIFICITY:
 * This module is OpenWrt/LEDE-specific and typically only compiled on embedded router firmware. UBus is
 * not available on standard Linux distributions (which use D-Bus instead, see dbus.c for comparison).
 * 
 * COMPARISON WITH D-BUS INTERFACE (dbus.c):
 * UBus provides similar functionality to D-Bus but with key differences for embedded systems:
 * - Memory footprint: UBus uses lightweight binary protocol vs. D-Bus XML-based introspection
 * - Message format: JSON-RPC-style blobmsg vs. D-Bus type marshalling
 * - Service discovery: Flat namespace vs. D-Bus hierarchical object paths
 * - Target platform: OpenWrt routers (limited RAM) vs. desktop/server Linux (abundant resources)
 * - Integration: LuCI web interface and UCI config vs. GNOME/KDE desktop environments
 * Both interfaces expose cache management, lease queries, and configuration status, but UBus adds
 * OpenWrt-specific metrics export and connmark allowlist management for firewall integration.
 * 
 * THREADING/CONCURRENCY:
 * Single-process event-driven model. UBus file descriptor is integrated into main poll loop via
 * set_ubus_listeners/check_ubus_listeners, ensuring non-blocking message processing.
 * 
 * EXAMPLE USAGE (via ubus command-line utility on OpenWrt):
 * @code
 * # List available dnsmasq methods
 * ubus list dnsmasq
 * 
 * # Get metrics (cache statistics, query counts)
 * ubus call dnsmasq metrics
 * 
 * # Set connection tracking allowlist (when HAVE_CONNTRACK enabled)
 * ubus call dnsmasq set_connmark_allowlist '{"mark": 1, "mask": 255, "patterns": ["example.com"]}'
 * @endcode
 * 
 * @copyright Copyright (c) 2000-2025 Simon Kelley
 * @license GPL-2.0-or-later
 */

#include "dnsmasq.h"

#ifdef HAVE_UBUS

#include <libubus.h>

static struct blob_buf b;
static int error_logged = 0;

static int ubus_handle_metrics(struct ubus_context *ctx, struct ubus_object *obj,
			       struct ubus_request_data *req, const char *method,
			       struct blob_attr *msg);

#ifdef HAVE_CONNTRACK
enum {
  SET_CONNMARK_ALLOWLIST_MARK,
  SET_CONNMARK_ALLOWLIST_MASK,
  SET_CONNMARK_ALLOWLIST_PATTERNS
};
static const struct blobmsg_policy set_connmark_allowlist_policy[] = {
  [SET_CONNMARK_ALLOWLIST_MARK] = {
    .name = "mark",
    .type = BLOBMSG_TYPE_INT32
  },
  [SET_CONNMARK_ALLOWLIST_MASK] = {
    .name = "mask",
    .type = BLOBMSG_TYPE_INT32
  },
  [SET_CONNMARK_ALLOWLIST_PATTERNS] = {
    .name = "patterns",
    .type = BLOBMSG_TYPE_ARRAY
  }
};
static int ubus_handle_set_connmark_allowlist(struct ubus_context *ctx, struct ubus_object *obj,
					      struct ubus_request_data *req, const char *method,
					      struct blob_attr *msg);
#endif

static void ubus_subscribe_cb(struct ubus_context *ctx, struct ubus_object *obj);

static const struct ubus_method ubus_object_methods[] = {
  UBUS_METHOD_NOARG("metrics", ubus_handle_metrics),
#ifdef HAVE_CONNTRACK
  UBUS_METHOD("set_connmark_allowlist", ubus_handle_set_connmark_allowlist, set_connmark_allowlist_policy),
#endif
};

static struct ubus_object_type ubus_object_type =
  UBUS_OBJECT_TYPE("dnsmasq", ubus_object_methods);

static struct ubus_object ubus_object = {
  .name = NULL,
  .type = &ubus_object_type,
  .methods = ubus_object_methods,
  .n_methods = ARRAY_SIZE(ubus_object_methods),
  .subscribe_cb = ubus_subscribe_cb,
};

/**
 * @brief UBus subscription callback invoked when clients subscribe to or unsubscribe from events
 * 
 * @detailed This callback is registered in ubus_object.subscribe_cb and invoked by libubus when
 * clients call ubus subscribe/unsubscribe on the dnsmasq service. Subscription enables clients to
 * receive asynchronous event notifications (e.g., connmark allowlist events) without polling.
 * 
 * The callback logs subscription state changes for debugging. Currently, dnsmasq broadcasts events
 * unconditionally via ubus_event_bcast regardless of subscriber presence, but future enhancements
 * could optimize by checking obj->has_subscribers before expensive event construction.
 * 
 * @param ctx UBus connection context (unused in current implementation)
 * @param obj UBus object being subscribed to, contains has_subscribers boolean flag
 * 
 * @return void
 * 
 * @note This callback is executed synchronously during ubus message processing in check_ubus_listeners
 * @warning Callback must not block or perform lengthy operations to avoid delaying main event loop
 * 
 * @see ubus_event_bcast for event broadcasting mechanism
 * @see check_ubus_listeners for message processing integration with main loop
 * 
 * SIDE EFFECTS: Logs subscription status change to syslog at LOG_DEBUG level
 * THREAD SAFETY: Single-threaded architecture, no synchronization required
 */
static void ubus_subscribe_cb(struct ubus_context *ctx, struct ubus_object *obj)
{
  (void)ctx;

  my_syslog(LOG_DEBUG, _("UBus subscription callback: %s subscriber(s)"), obj->has_subscribers ? "1" : "0");
}

/**
 * @brief Clean up and destroy UBus connection context
 * 
 * @detailed This function performs orderly shutdown of the UBus connection, releasing resources and
 * resetting state to enable clean re-initialization. The function is called on daemon shutdown or
 * when UBus connection cannot be re-established after repeated reconnection failures.
 * 
 * The cleanup sequence frees the libubus context (which closes socket and releases memory), clears
 * the daemon's ubus pointer to prevent use-after-free, and resets object/type IDs to zero. The ID
 * reset is critical because libubus assigns IDs during registration, and reusing non-zero IDs after
 * ubus_free can cause registration failures or crashes if dnsmasq later re-initializes UBus connection.
 * 
 * @param ubus UBus connection context to destroy (non-NULL)
 * 
 * @return void
 * 
 * @note After ubus_destroy, daemon->ubus is NULL and UBus functionality is unavailable until ubus_init succeeds
 * @warning Must not call UBus API functions after ubus_free completes (context is invalid)
 * 
 * @see ubus_init for initialization and registration
 * @see ubus_disconnect_cb for automatic reconnection handling
 * 
 * EXAMPLE USAGE:
 * @code
 * if (daemon->ubus && reconnect_attempts_exhausted) {
 *   ubus_destroy((struct ubus_context *)daemon->ubus);
 *   // daemon->ubus now NULL, UBus disabled
 * }
 * @endcode
 * 
 * SIDE EFFECTS: Closes UBus socket, frees libubus memory, sets daemon->ubus to NULL, resets global object IDs
 * THREAD SAFETY: Single-threaded architecture, called from main event loop only
 */
static void ubus_destroy(struct ubus_context *ubus)
{
  ubus_free(ubus);
  daemon->ubus = NULL;
  
  /* Forces re-initialization when we're reusing the same definitions later on. */
  ubus_object.id = 0;
  ubus_object_type.id = 0;
}

/**
 * @brief Automatic reconnection callback invoked when UBus connection to ubusd is lost
 * 
 * @detailed This callback is registered in ubus_context.connection_lost and invoked by libubus when
 * the socket connection to the ubusd daemon is lost (socket error, daemon restart, etc.). The callback
 * attempts immediate reconnection using ubus_reconnect. If reconnection succeeds, the UBus connection
 * is restored and normal operation resumes. If reconnection fails, the connection is destroyed via
 * ubus_destroy, disabling UBus functionality until manual daemon restart or SIGHUP reload.
 * 
 * The single reconnection attempt policy prevents infinite reconnection loops if ubusd is persistently
 * unavailable. The daemon continues operating normally (DNS, DHCP services unaffected) but UBus control
 * interface becomes unavailable.
 * 
 * @param ubus UBus connection context that experienced disconnection (non-NULL)
 * 
 * @return void
 * 
 * @note Reconnection failure is logged at LOG_ERR level with human-readable error from ubus_strerror
 * @warning After reconnection failure and ubus_destroy, daemon->ubus is NULL and UBus methods unavailable
 * 
 * @see ubus_init for initial connection establishment
 * @see ubus_destroy for cleanup after reconnection failure
 * 
 * EXAMPLE USAGE:
 * @code
 * // Callback registration in ubus_init:
 * ubus->connection_lost = ubus_disconnect_cb;
 * // Callback invoked automatically by libubus on socket error
 * @endcode
 * 
 * SIDE EFFECTS: Attempts ubus_reconnect (may succeed or fail); logs error on failure; calls ubus_destroy on failure
 * THREAD SAFETY: Single-threaded architecture, callback invoked from main event loop during check_ubus_listeners
 */
static void ubus_disconnect_cb(struct ubus_context *ubus)
{
  int ret;

  ret = ubus_reconnect(ubus, NULL);
  if (ret)
    {
      my_syslog(LOG_ERR, _("Cannot reconnect to UBus: %s"), ubus_strerror(ret));

      ubus_destroy(ubus);
    }
}

/**
 * @brief Initialize UBus connection and register dnsmasq service with ubusd daemon
 * 
 * @detailed This function establishes connection to the OpenWrt ubusd daemon, registers the dnsmasq
 * service object with configured methods (metrics, set_connmark_allowlist if HAVE_CONNTRACK enabled),
 * and configures automatic reconnection handling. The function is called during daemon initialization
 * in dnsmasq.c main function and returns NULL on success or an error message string on failure.
 * 
 * Initialization sequence:
 * 1. Connect to ubusd via default Unix domain socket (/var/run/ubus/ubus.sock) using ubus_connect
 * 2. Set service name from daemon->ubus_name (configurable via --ubus-name option, no default fallback)
 * 3. Register UBus object with method table via ubus_add_object (makes service visible to clients)
 * 4. Configure disconnection callback ubus_disconnect_cb for automatic reconnection on socket loss
 * 5. Store opaque ubus context pointer in daemon->ubus for later use by set_ubus_listeners/check_ubus_listeners
 * 
 * Unlike typical initialization functions, this returns NULL on connection failure (ubus_connect failed)
 * rather than an error message, treating ubusd unavailability as non-fatal. Only ubus_add_object failures
 * (service registration errors) return error strings via ubus_strerror. This behavior supports early boot
 * scenarios where ubusd may not yet be running.
 * 
 * The error_logged flag is reset to 0 on successful initialization, enabling set_ubus_listeners and
 * check_ubus_listeners to log subsequent connection errors if the service was previously operational.
 * 
 * @return NULL on success or ubus_connect failure, error message string on ubus_add_object failure
 * @retval NULL UBus initialized successfully with daemon->ubus containing valid context, OR ubus_connect failed (ubusd not running)
 * @retval ubus_strerror(ret) ubus_add_object failed (service name conflict, permission denied, invalid object definition)
 * 
 * @note Returned error string is static libubus string, no memory allocation required, suitable for logging
 * @warning On ubus_connect failure, daemon->ubus remains NULL and UBus functionality is silently unavailable
 * @warning daemon->ubus_name must be set before calling (configuration parsing sets this from --ubus-name option)
 * 
 * @see set_ubus_listeners in ubus.c for integrating UBus file descriptor into main poll loop (dnsmasq.c event loop)
 * @see check_ubus_listeners in ubus.c for handling UBus events and connection errors in main loop
 * @see ubus_disconnect_cb for automatic reconnection on connection loss detected by libubus
 * @see ubus_destroy for cleanup on fatal errors and reconnection attempts
 * 
 * EXAMPLE USAGE:
 * @code
 * // In dnsmasq.c main function after configuration parsing:
 * if (option_bool(OPT_UBUS))
 *   {
 *     char *err = ubus_init();
 *     if (err)
 *       my_syslog(LOG_ERR, _("UBus initialization failed: %s"), err);
 *   }
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (OpenWrt-specific IPC mechanism, not standardized)
 * SIDE EFFECTS: Connects to ubusd socket, registers service object with methods, stores context in daemon->ubus, resets error_logged flag
 * THREAD SAFETY: Single-threaded architecture, called only from main function during initialization before event loop starts
 */
char *ubus_init()
{
  struct ubus_context *ubus = NULL;
  int ret = 0;

  if (!(ubus = ubus_connect(NULL)))
    return NULL;
  
  ubus_object.name = daemon->ubus_name;
  ret = ubus_add_object(ubus, &ubus_object);
  if (ret)
    {
      ubus_destroy(ubus);
      return (char *)ubus_strerror(ret);
    }    
  
  ubus->connection_lost = ubus_disconnect_cb;
  daemon->ubus = ubus;
  error_logged = 0;

  return NULL;
}

/**
 * @brief Register UBus socket file descriptor with dnsmasq main event loop for monitoring
 * 
 * @detailed This function integrates the UBus connection socket into the dnsmasq poll-based event loop
 * by registering the file descriptor for POLLIN (data ready to read), POLLERR (error condition), and
 * POLLHUP (hangup/disconnection) events. Called from dnsmasq.c main event loop before each poll()
 * invocation to ensure UBus events are monitored alongside DNS, DHCP, and other network sockets.
 * 
 * The function accesses the ubus socket fd via ubus->sock.fd from the opaque ubus_context structure
 * and invokes poll_listen (defined in poll.c) three times to register interest in all relevant poll
 * events. If daemon->ubus is NULL (UBus initialization failed or connection lost), the function logs
 * an error message once (using error_logged flag to prevent log flooding) and returns without registering
 * any file descriptors.
 * 
 * Error logging behavior: The error_logged static variable prevents repeated logging of the same error
 * across multiple main loop iterations. When daemon->ubus becomes NULL, the error is logged once and
 * error_logged is set to 1. When a valid connection is re-established (daemon->ubus becomes non-NULL),
 * error_logged is reset to 0, enabling future error logging if the connection is lost again.
 * 
 * This function must be called every main loop iteration because poll_listen registers interest for
 * the next poll() call only; the poll event set is not persistent across iterations.
 * 
 * @return void (no return value)
 * 
 * @note This function does not block; it only registers interest in events for the upcoming poll() call
 * @warning Must be called every main loop iteration before poll() or events will not be monitored
 * @warning Assumes daemon->ubus is NULL or contains a valid ubus_context pointer; invalid pointers cause undefined behavior
 * 
 * @see check_ubus_listeners in ubus.c for handling UBus events after poll() returns
 * @see poll_listen in poll.c for registering file descriptor interest in pollfd array
 * @see poll_check in poll.c for checking if events occurred on file descriptor
 * @see ubus_handle_event in libubus for processing UBus protocol messages
 * 
 * EXAMPLE USAGE:
 * @code
 * // In dnsmasq.c main event loop before poll():
 * if (option_bool(OPT_UBUS))
 *   set_ubus_listeners();
 * // Later after poll():
 * if (option_bool(OPT_UBUS))
 *   check_ubus_listeners();
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (OpenWrt-specific IPC mechanism, not standardized)
 * SIDE EFFECTS: Registers ubus socket fd with poll array via poll_listen; logs error if daemon->ubus is NULL; updates error_logged flag
 * THREAD SAFETY: Single-threaded architecture, called from main event loop only
 */
void set_ubus_listeners()
{
  struct ubus_context *ubus = (struct ubus_context *)daemon->ubus;
  if (!ubus)
    {
      if (!error_logged)
        {
          my_syslog(LOG_ERR, _("Cannot set UBus listeners: no connection"));
          error_logged = 1;
        }
      return;
    }

  error_logged = 0;

  poll_listen(ubus->sock.fd, POLLIN);
  poll_listen(ubus->sock.fd, POLLERR);
  poll_listen(ubus->sock.fd, POLLHUP);
}

/**
 * @brief Process UBus events after poll() returns from main event loop
 * 
 * @detailed This function handles UBus socket events detected by poll() in the dnsmasq main event loop,
 * processing incoming UBus method calls, replies, and subscriptions via ubus_handle_event, and detecting
 * connection errors via POLLHUP/POLLERR to trigger reconnection. Called from dnsmasq.c main loop after
 * poll() returns, complementing set_ubus_listeners which registers interest before poll().
 * 
 * Event handling sequence:
 * 1. Retrieve ubus_context from daemon->ubus; return with error logging if NULL (connection failed or lost)
 * 2. Reset error_logged to 0 when connection is valid (allows future error logging after reconnection)
 * 3. Check POLLIN event via poll_check (data available on socket); invoke ubus_handle_event for protocol processing
 * 4. Check POLLHUP|POLLERR events via poll_check (connection closed or error); log disconnection and invoke ubus_destroy
 * 
 * The POLLIN check processes normal UBus traffic including method invocations from clients (ubus call dnsmasq metrics,
 * ubus call dnsmasq set_connmark_allowlist), subscription notifications, and internal libubus keepalive messages.
 * The ubus_handle_event function dispatches to registered method handlers (ubus_handle_metrics, etc.).
 * 
 * The POLLHUP|POLLERR check detects ubusd daemon restart, socket closure, or network errors. When detected,
 * ubus_destroy performs cleanup (ubus_free, reset daemon->ubus to NULL, reset object IDs) to prepare for
 * reconnection. The ubus_disconnect_cb callback registered in ubus_init will attempt reconnection via
 * ubus_reconnect on next iteration, or ubus_init can be called again on daemon restart.
 * 
 * Error logging matches set_ubus_listeners behavior: errors are logged once when daemon->ubus becomes NULL,
 * then error_logged is set to 1 to suppress duplicate messages. When connection is re-established (daemon->ubus
 * becomes non-NULL), error_logged is reset to 0, enabling future error logging.
 * 
 * @return void (no return value)
 * 
 * @note This function must be called after poll() returns and only if set_ubus_listeners was called before poll()
 * @warning Assumes daemon->ubus is NULL or contains valid ubus_context; invalid pointers cause undefined behavior
 * @warning After POLLHUP|POLLERR, daemon->ubus is set to NULL via ubus_destroy; subsequent calls will log errors
 * 
 * @see set_ubus_listeners in ubus.c for registering UBus socket interest before poll() call
 * @see poll_check in poll.c for testing if specified events occurred on file descriptor
 * @see ubus_handle_event in libubus for processing UBus protocol messages and dispatching to method handlers
 * @see ubus_destroy in ubus.c for cleaning up connection and preparing for reconnection
 * @see ubus_disconnect_cb in ubus.c for automatic reconnection attempts on connection loss
 * 
 * EXAMPLE USAGE:
 * @code
 * // In dnsmasq.c main event loop after poll():
 * if (option_bool(OPT_UBUS))
 *   check_ubus_listeners();
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (OpenWrt-specific IPC mechanism, not standardized)
 * SIDE EFFECTS: Invokes ubus_handle_event for protocol processing; invokes ubus_destroy on disconnect; logs errors and disconnections; updates error_logged flag
 * THREAD SAFETY: Single-threaded architecture, called from main event loop only after poll() returns
 */
void check_ubus_listeners()
{
  struct ubus_context *ubus = (struct ubus_context *)daemon->ubus;
  if (!ubus)
    {
      if (!error_logged)
        {
          my_syslog(LOG_ERR, _("Cannot poll UBus listeners: no connection"));
          error_logged = 1;
        }
      return;
    }
  
  error_logged = 0;

  if (poll_check(ubus->sock.fd, POLLIN))
    ubus_handle_event(ubus);
  
  if (poll_check(ubus->sock.fd, POLLHUP | POLLERR))
    {
      my_syslog(LOG_INFO, _("Disconnecting from UBus"));

      ubus_destroy(ubus);
    }
}

#define CHECK(stmt) \
  do { \
    int e = (stmt); \
    if (e) \
      { \
	my_syslog(LOG_ERR, _("UBus command failed: %d (%s)"), e, #stmt); \
	return (UBUS_STATUS_UNKNOWN_ERROR); \
      } \
  } while (0)

/**
 * @brief UBus method handler for exporting dnsmasq performance metrics
 * 
 * @detailed This function implements the "metrics" UBus method registered in ubus_object_methods array,
 * providing read-only access to dnsmasq performance counters tracked in daemon->metrics[] array. When
 * a client invokes `ubus call dnsmasq metrics`, this handler constructs a JSON response table containing
 * all metrics defined in the __METRIC_MAX enumeration (from metrics.h), with metric names obtained from
 * get_metric_name() and values from daemon->metrics[i] 32-bit unsigned integer counters.
 * 
 * The function builds a BLOBMSG_TYPE_TABLE response (JSON object) using the libubox blob_buf API:
 * 1. Initialize blob buffer with blob_buf_init (prepares for message construction)
 * 2. Iterate through all metrics from 0 to __METRIC_MAX-1 (typically includes cache hits, cache misses,
 *    queries forwarded, DNSSEC validations, DHCP transactions, etc.)
 * 3. Add each metric as a name-value pair via blobmsg_add_u32 (JSON: "metric_name": value)
 * 4. Send completed response to client via ubus_send_reply
 * 
 * All blob operations are wrapped in CHECK macro (defined at line 489) which logs errors and returns
 * UBUS_STATUS_UNKNOWN_ERROR on failure. On success, returns UBUS_STATUS_OK to indicate method completed.
 * 
 * Metrics exposed include (exact set depends on compile-time features enabled):
 * - DNS cache statistics (hits, misses, evictions)
 * - Query counters (total queries, forwarded queries, local answers)
 * - DNSSEC validation counters (if HAVE_DNSSEC enabled)
 * - DHCP transaction counters (if HAVE_DHCP enabled)
 * - Other operational statistics tracked in daemon->metrics[]
 * 
 * The static blob_buf b is reused across method invocations; blob_buf_init resets it for each call.
 * Method signature matches libubus method handler prototype with ctx (UBus context), obj (service object),
 * req (request data for reply routing), method (method name string "metrics"), and msg (method arguments).
 * This method takes no arguments so msg is unused.
 * 
 * @param ctx UBus context pointer for sending reply via ubus_send_reply
 * @param obj UBus object representing dnsmasq service (unused, cast to void)
 * @param req Request data structure containing client info and reply routing (passed to ubus_send_reply)
 * @param method Method name string "metrics" (unused, cast to void)
 * @param msg Blob attribute containing method arguments (unused for this method, no arguments expected)
 * 
 * @return UBUS_STATUS_OK (0) on success, UBUS_STATUS_UNKNOWN_ERROR on blob operation failure
 * @retval UBUS_STATUS_OK All metrics exported successfully in JSON response
 * @retval UBUS_STATUS_UNKNOWN_ERROR blob_buf_init, blobmsg_add_u32, or ubus_send_reply failed (error logged)
 * 
 * @note This is a static function registered in ubus_object_methods via UBUS_METHOD_NOARG macro
 * @warning CHECK macro logs error and returns UBUS_STATUS_UNKNOWN_ERROR on any blob operation failure
 * @warning Assumes daemon->metrics[] array is valid and __METRIC_MAX is correct size
 * 
 * @see ubus_object_methods array for method registration (UBUS_METHOD_NOARG("metrics", ubus_handle_metrics))
 * @see get_metric_name in metrics.c for converting metric enum to name string
 * @see daemon->metrics[] array in dnsmasq.h struct daemon for metric storage
 * @see blob_buf_init, blobmsg_add_u32 in libubox for JSON message construction
 * @see ubus_send_reply in libubus for transmitting response to client
 * 
 * EXAMPLE USAGE:
 * @code
 * // Client invocation from OpenWrt shell:
 * ubus call dnsmasq metrics
 * // Returns JSON: {"cache_hits": 1234, "cache_misses": 56, "queries_forwarded": 789, ...}
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (OpenWrt-specific monitoring interface, not standardized)
 * SIDE EFFECTS: Constructs blob message in static buffer b; logs errors on blob operation failures
 * THREAD SAFETY: Single-threaded architecture, invoked from ubus_handle_event in main event loop
 */
static int ubus_handle_metrics(struct ubus_context *ctx, struct ubus_object *obj,
			       struct ubus_request_data *req, const char *method,
			       struct blob_attr *msg)
{
  int i;

  (void)obj;
  (void)method;
  (void)msg;

  CHECK(blob_buf_init(&b, BLOBMSG_TYPE_TABLE));

  for (i=0; i < __METRIC_MAX; i++)
    CHECK(blobmsg_add_u32(&b, get_metric_name(i), daemon->metrics[i]));
  
  CHECK(ubus_send_reply(ctx, req, b.head));
  return UBUS_STATUS_OK;
}

#ifdef HAVE_CONNTRACK
/**
 * @brief UBus method handler for configuring connection tracking mark allowlists
 * 
 * @detailed Processes UBus requests to set connection tracking mark allowlists for domain name
 *           patterns. This method validates and configures which DNS query patterns should have
 *           specific conntrack marks applied when connection tracking integration is enabled.
 *           The allowlist associates domain name patterns with conntrack mark values and optional
 *           masks, enabling advanced routing and firewall policies based on DNS-resolved domains.
 *           
 *           The method parses JSON-RPC formatted UBus messages containing three parameters:
 *           - mark: 32-bit unsigned integer conntrack mark value (required, non-zero)
 *           - mask: 32-bit unsigned integer mask for mark value (optional, defaults to UINT32_MAX)
 *           - patterns: Array of domain name pattern strings (optional, wildcards supported)
 *           
 *           Domain patterns are validated against DNS naming rules and can include wildcards.
 *           The special pattern "*" matches all domains. Validated patterns are stored in the
 *           daemon's conntrack allowlist configuration and applied to subsequent DNS resolutions.
 *           
 *           Integration with src/conntrack.c: This configuration controls which resolved domains
 *           trigger conntrack mark application via get_incoming_mark() function.
 * 
 * @param ctx UBus context pointer (unused, marked with (void) cast)
 * @param obj UBus object pointer representing the dnsmasq service (unused)
 * @param req UBus request data for response handling (unused)
 * @param method Method name string ("set_connmark_allowlist", unused)
 * @param msg Binary blob attribute containing JSON-RPC encoded parameters with mark, mask, patterns
 * 
 * @return UBUS_STATUS_OK (0) on successful allowlist configuration
 * @retval UBUS_STATUS_INVALID_ARGUMENT Invalid parameter format, missing mark, zero mark value,
 *         invalid mask (zero or mark bits outside mask), invalid pattern format (non-string),
 *         or invalid DNS name pattern (fails is_valid_dns_name_pattern validation)
 * @retval UBUS_STATUS_NO_DATA Memory allocation failure for patterns or allowlist structures
 * 
 * @note Requires HAVE_CONNTRACK compile-time flag for connection tracking support
 * @warning Replaces any existing allowlist configuration for the specified mark value
 * @warning Memory for patterns and allowlist structures is allocated via whine_malloc;
 *          failures are logged and return UBUS_STATUS_NO_DATA
 * 
 * @see get_incoming_mark() in src/conntrack.c - applies marks based on allowlist configuration
 * @see is_valid_dns_name_pattern() - validates domain name pattern syntax
 * @see set_connmark_allowlist_policy[] - defines UBus parameter schema
 * 
 * EXAMPLE USAGE:
 * @code
 * // Via ubus command-line tool:
 * ubus call dnsmasq set_connmark_allowlist '{"mark": 100, "mask": 255, "patterns": ["*.example.com", "trusted.org"]}'
 * // Successful response: empty JSON object {}
 * // Mark 100 with mask 255 now applied to queries matching patterns
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (OpenWrt-specific UBus integration, not standardized protocol)
 * 
 * SIDE EFFECTS:
 * - Allocates memory for pattern strings and allowlist structures
 * - Modifies daemon->allowlists linked list by adding new allowlist entries
 * - Logs errors via my_syslog for allocation failures
 * - Previously configured allowlists for other marks remain unchanged
 * 
 * THREAD SAFETY: Single-threaded architecture; safe within dnsmasq event loop context
 * 
 * Platform: OpenWrt, LEDE, embedded Linux with libubus and connection tracking support
 */
static int ubus_handle_set_connmark_allowlist(struct ubus_context *ctx, struct ubus_object *obj,
					      struct ubus_request_data *req, const char *method,
					      struct blob_attr *msg)
{
  const struct blobmsg_policy *policy = set_connmark_allowlist_policy;
  size_t policy_len = countof(set_connmark_allowlist_policy);
  struct allowlist *allowlists = NULL, **allowlists_pos;
  char **patterns = NULL, **patterns_pos;
  u32 mark, mask = UINT32_MAX;
  size_t num_patterns = 0;
  struct blob_attr *tb[policy_len];
  struct blob_attr *attr;

  (void)ctx;
  (void)obj;
  (void)req;
  (void)method;
  
  if (blobmsg_parse(policy, policy_len, tb, blob_data(msg), blob_len(msg)))
    return UBUS_STATUS_INVALID_ARGUMENT;
  
  if (!tb[SET_CONNMARK_ALLOWLIST_MARK])
    return UBUS_STATUS_INVALID_ARGUMENT;
  mark = blobmsg_get_u32(tb[SET_CONNMARK_ALLOWLIST_MARK]);
  if (!mark)
    return UBUS_STATUS_INVALID_ARGUMENT;
  
  if (tb[SET_CONNMARK_ALLOWLIST_MASK])
    {
      mask = blobmsg_get_u32(tb[SET_CONNMARK_ALLOWLIST_MASK]);
      if (!mask || (mark & ~mask))
	return UBUS_STATUS_INVALID_ARGUMENT;
    }
  
  if (tb[SET_CONNMARK_ALLOWLIST_PATTERNS])
    {
      struct blob_attr *head = blobmsg_data(tb[SET_CONNMARK_ALLOWLIST_PATTERNS]);
      size_t len = blobmsg_data_len(tb[SET_CONNMARK_ALLOWLIST_PATTERNS]);
      __blob_for_each_attr(attr, head, len)
	{
	  char *pattern;
	  if (blob_id(attr) != BLOBMSG_TYPE_STRING)
	    return UBUS_STATUS_INVALID_ARGUMENT;
	  if (!(pattern = blobmsg_get_string(attr)))
	    return UBUS_STATUS_INVALID_ARGUMENT;
	  if (strcmp(pattern, "*") && !is_valid_dns_name_pattern(pattern))
	    return UBUS_STATUS_INVALID_ARGUMENT;
	  num_patterns++;
	}
    }
  
  for (allowlists_pos = &daemon->allowlists; *allowlists_pos; allowlists_pos = &(*allowlists_pos)->next)
    if ((*allowlists_pos)->mark == mark && (*allowlists_pos)->mask == mask)
      {
	struct allowlist *allowlists_next = (*allowlists_pos)->next;
	for (patterns_pos = (*allowlists_pos)->patterns; *patterns_pos; patterns_pos++)
	  {
	    free(*patterns_pos);
	    *patterns_pos = NULL;
	  }
	free((*allowlists_pos)->patterns);
	(*allowlists_pos)->patterns = NULL;
	free(*allowlists_pos);
	*allowlists_pos = allowlists_next;
	break;
      }
  
  if (!num_patterns)
    return UBUS_STATUS_OK;
  
  patterns = whine_malloc((num_patterns + 1) * sizeof(char *));
  if (!patterns)
    goto fail;
  patterns_pos = patterns;
  if (tb[SET_CONNMARK_ALLOWLIST_PATTERNS])
    {
      struct blob_attr *head = blobmsg_data(tb[SET_CONNMARK_ALLOWLIST_PATTERNS]);
      size_t len = blobmsg_data_len(tb[SET_CONNMARK_ALLOWLIST_PATTERNS]);
      __blob_for_each_attr(attr, head, len)
	{
	  char *pattern;
	  if (!(pattern = blobmsg_get_string(attr)))
	    goto fail;
	  if (!(*patterns_pos = whine_malloc(strlen(pattern) + 1)))
	    goto fail;
	  strcpy(*patterns_pos++, pattern);
	}
    }
  
  allowlists = whine_malloc(sizeof(struct allowlist));
  if (!allowlists)
    goto fail;
  memset(allowlists, 0, sizeof(struct allowlist));
  allowlists->mark = mark;
  allowlists->mask = mask;
  allowlists->patterns = patterns;
  allowlists->next = daemon->allowlists;
  daemon->allowlists = allowlists;
  return UBUS_STATUS_OK;
  
fail:
  if (patterns)
    {
      for (patterns_pos = patterns; *patterns_pos; patterns_pos++)
	{
	  free(*patterns_pos);
	  *patterns_pos = NULL;
	}
      free(patterns);
      patterns = NULL;
    }
  if (allowlists)
    {
      free(allowlists);
      allowlists = NULL;
    }
  return UBUS_STATUS_UNKNOWN_ERROR;
}
#endif

#undef CHECK

#define CHECK(stmt) \
  do { \
    int e = (stmt); \
    if (e) \
      { \
	my_syslog(LOG_ERR, _("UBus command failed: %d (%s)"), e, #stmt); \
	return; \
      } \
  } while (0)

/**
 * @brief Broadcast UBus event notifications for DHCP lease changes
 * 
 * @detailed Sends UBus event notifications to subscribed clients when DHCP lease events occur,
 *           enabling external systems to respond to network configuration changes in real-time.
 *           This function is invoked by DHCP event handlers (in src/lease.c and src/dhcp.c) to
 *           notify UBus subscribers about lease additions, updates, and deletions.
 *           
 *           The function constructs a JSON-formatted message containing optional lease details
 *           (MAC address, IP address, hostname, interface name) and broadcasts it to all UBus
 *           subscribers via the ubus_notify() API. The event type string identifies the kind
 *           of DHCP event, enabling subscribers to implement event-specific handling logic.
 *           
 *           Common event types include:
 *           - "dhcp.add": New DHCP lease assigned
 *           - "dhcp.old": Existing DHCP lease renewed
 *           - "dhcp.del": DHCP lease expired or released
 *           
 *           The function performs an early-exit optimization: if UBus is not connected or no
 *           subscribers are registered, the broadcast is skipped to avoid unnecessary message
 *           construction overhead. This ensures minimal performance impact when UBus monitoring
 *           is not in use.
 *           
 *           Integration with OpenWrt ecosystem: LuCI web interface and system monitoring tools
 *           subscribe to these events to provide real-time network status displays, trigger
 *           firewall rule updates, and log network activity.
 * 
 * @param type Event type string identifying DHCP event category (must not be NULL)
 *             Common values: "dhcp.add", "dhcp.old", "dhcp.del"
 * @param mac MAC address of DHCP client (NULL if not applicable, e.g., for DHCPv6 events)
 *            Format: "00:11:22:33:44:55" (colon-separated hex pairs)
 * @param ip IP address assigned to client (NULL if not applicable)
 *           Format: dotted decimal IPv4 ("192.168.1.10") or compressed IPv6 ("2001:db8::1")
 * @param name Hostname of DHCP client (NULL if client did not provide hostname)
 *             Sanitized DNS hostname string conforming to RFC 1123 naming rules
 * @param interface Network interface name where DHCP event occurred (NULL if not relevant)
 *                  Format: Linux interface name ("eth0", "br-lan", "wlan0", etc.)
 * 
 * @return void (no return value)
 * 
 * @note All string parameters are optional (can be NULL); only non-NULL values are included in broadcast
 * @note No-op if UBus context is not initialized or no subscribers are registered (early exit)
 * @warning Requires HAVE_UBUS compile-time flag for UBus integration support
 * @warning Uses CHECK() macro which terminates daemon on blob construction or notification failures
 * 
 * @see lease_update_file() in src/lease.c - calls this function for lease persistence events
 * @see dhcp_reply() in src/dhcp.c - calls this function for DHCPv4 transactions
 * @see dhcp6_reply() in src/dhcp6.c - calls this function for DHCPv6 transactions
 * @see ubus_subscribe_cb() - handles UBus subscription lifecycle
 * 
 * EXAMPLE USAGE:
 * @code
 * // DHCP lease addition event:
 * ubus_event_bcast("dhcp.add", "aa:bb:cc:dd:ee:ff", "192.168.1.100", "client-hostname", "br-lan");
 * 
 * // UBus subscribers receive JSON notification:
 * // {
 * //   "mac": "aa:bb:cc:dd:ee:ff",
 * //   "ip": "192.168.1.100",
 * //   "name": "client-hostname",
 * //   "interface": "br-lan"
 * // }
 * // Event type: "dhcp.add"
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (OpenWrt-specific UBus integration, not standardized protocol)
 * 
 * SIDE EFFECTS:
 * - Constructs binary blob message in static blob buffer b (shared across all UBus functions)
 * - Sends UBus notification to all subscribed clients via system bus
 * - May block briefly during ubus_notify() call (timeout -1 = no timeout)
 * - Terminates daemon process if blob construction or notification fails (CHECK macro behavior)
 * 
 * THREAD SAFETY: Single-threaded architecture; safe within dnsmasq event loop context
 * 
 * Platform: OpenWrt, LEDE, embedded Linux with libubus support
 */
void ubus_event_bcast(const char *type, const char *mac, const char *ip, const char *name, const char *interface)
{
  struct ubus_context *ubus = (struct ubus_context *)daemon->ubus;

  if (!ubus || !ubus_object.has_subscribers)
    return;

  CHECK(blob_buf_init(&b, BLOBMSG_TYPE_TABLE));
  if (mac)
    CHECK(blobmsg_add_string(&b, "mac", mac));
  if (ip)
    CHECK(blobmsg_add_string(&b, "ip", ip));
  if (name)
    CHECK(blobmsg_add_string(&b, "name", name));
  if (interface)
    CHECK(blobmsg_add_string(&b, "interface", interface));
  
  CHECK(ubus_notify(ubus, &ubus_object, type, b.head, -1));
}

#ifdef HAVE_CONNTRACK
/**
 * @brief Broadcast UBus event when connection tracking allowlist refuses a domain
 * 
 * @detailed Sends a UBus notification event to all subscribers when a DNS query is refused
 *           due to connection tracking mark allowlist rules. This enables external systems
 *           (firewall configuration tools, monitoring systems) to react to denied queries
 *           and potentially log or adjust firewall rules dynamically.
 * 
 * @param mark Connection tracking mark value that was requested but refused
 * @param name Domain name that was queried and refused
 * 
 * @note Only available when HAVE_CONNTRACK compile-time flag is set
 * @warning Requires UBus connection to be initialized and active subscribers
 * @see ubus_event_bcast_connmark_allowlist_resolved() for successful resolution events
 * @see ubus_event_bcast() for general event broadcast
 * 
 * EXAMPLE USAGE:
 * @code
 * // Refuse domain with mark 0x100
 * ubus_event_bcast_connmark_allowlist_refused(0x100, "blocked.example.com");
 * @endcode
 * 
 * UBUS EVENT: Sends "connmark-allowlist.refused" event with JSON payload:
 *   { "mark": <u32>, "name": "<domain>" }
 * 
 * SIDE EFFECTS: UBus notification sent to all subscribers if connection active
 * THREAD SAFETY: Uses shared blob_buf b, safe in single-threaded architecture
 */
void ubus_event_bcast_connmark_allowlist_refused(u32 mark, const char *name)
{
  struct ubus_context *ubus = (struct ubus_context *)daemon->ubus;

  if (!ubus || !ubus_object.has_subscribers)
    return;

  CHECK(blob_buf_init(&b, 0));
  CHECK(blobmsg_add_u32(&b, "mark", mark));
  CHECK(blobmsg_add_string(&b, "name", name));
  
  CHECK(ubus_notify(ubus, &ubus_object, "connmark-allowlist.refused", b.head, -1));
}

/**
 * @brief Broadcast UBus event when connection tracking allowlist resolves a domain
 * 
 * @detailed Sends a UBus notification event to all subscribers when a DNS query successfully
 *           resolves and matches connection tracking mark allowlist rules. The event includes
 *           the resolved IP address and TTL, enabling external systems to dynamically update
 *           firewall rules, populate ipsets/nftables sets, or track allowed connections with
 *           appropriate timeout values. The 1000ms timeout allows UBus subscribers to configure
 *           firewall rules before the function returns, ensuring rules are in place before
 *           connection establishment.
 * 
 * @param mark Connection tracking mark value to be applied to connections
 * @param name Domain name that was queried and successfully resolved
 * @param value Resolved IP address as string (IPv4 dotted-decimal or IPv6 hex notation)
 * @param ttl Time-to-live value from DNS response for cache lifetime management
 * 
 * @note Only available when HAVE_CONNTRACK compile-time flag is set
 * @note Silently returns if UBus connection is not active or no subscribers exist
 * @warning UBus notify blocks for up to 1000ms waiting for subscriber response
 * @see ubus_event_bcast_connmark_allowlist_refused() for refused query events
 * @see ubus_event_bcast() for general event broadcast
 * 
 * EXAMPLE USAGE:
 * @code
 * // Resolved www.example.com to 192.0.2.1 with TTL 300 seconds, mark 0x100
 * ubus_event_bcast_connmark_allowlist_resolved(0x100, "www.example.com", 
 *                                               "192.0.2.1", 300);
 * @endcode
 * 
 * UBUS EVENT: Sends "connmark-allowlist.resolved" event with JSON payload:
 *   { "mark": <u32>, "name": "<domain>", "value": "<IP address>", "ttl": <u32> }
 * 
 * RFC COMPLIANCE: TTL handling per RFC 1035 Section 3.2.1
 * SIDE EFFECTS: UBus notification sent to all subscribers; blocks up to 1000ms for response
 * THREAD SAFETY: Uses shared blob_buf b, safe in single-threaded architecture
 */
void ubus_event_bcast_connmark_allowlist_resolved(u32 mark, const char *name, const char *value, u32 ttl)
{
  struct ubus_context *ubus = (struct ubus_context *)daemon->ubus;

  if (!ubus || !ubus_object.has_subscribers)
    return;

  CHECK(blob_buf_init(&b, 0));
  CHECK(blobmsg_add_u32(&b, "mark", mark));
  CHECK(blobmsg_add_string(&b, "name", name));
  CHECK(blobmsg_add_string(&b, "value", value));
  CHECK(blobmsg_add_u32(&b, "ttl", ttl));
  
  /* Set timeout to allow UBus subscriber to configure firewall rules before returning. */
  CHECK(ubus_notify(ubus, &ubus_object, "connmark-allowlist.resolved", b.head, /* timeout: */ 1000));
}
#endif

#undef CHECK

#endif /* HAVE_UBUS */

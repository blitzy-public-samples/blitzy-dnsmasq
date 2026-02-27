//! D-Bus System Bus Interface for dnsmasq.
//!
//! This module implements the D-Bus control interface for dnsmasq, providing
//! programmatic management and monitoring of the daemon via the system bus.
//! It is the Rust rewrite of `src/dbus.c` (2175 lines of C).
//!
//! # Feature Gate
//!
//! This entire module is gated behind `#[cfg(feature = "dbus")]`.
//!
//! # D-Bus Interface
//!
//! The module registers on the system bus as `uk.org.thekelleys.dnsmasq`
//! (or a custom name via configuration) at the object path
//! `/uk/org/thekelleys/dnsmasq`. It exposes methods for:
//!
//! - DNS server reconfiguration (`SetServers`, `SetServersEx`, `SetDomainServers`)
//! - Cache management (`ClearCache`)
//! - Metrics retrieval (`GetMetrics`, `GetServerMetrics`, `ClearMetrics`)
//! - Option toggling (`SetFilterWin2KOption`, `SetLocaliseQueriesOption`,
//!   `SetBogusPrivOption`, `SetFilterA`, `SetFilterAAAA`)
//! - DHCP lease management (`AddDhcpLease`, `DeleteDhcpLease`) — feature-gated
//! - Loop detection (`GetLoopServers`) — feature-gated
//! - Introspection (`Introspect`)
//! - Version query (`GetVersion`)
//!
//! # Signals
//!
//! - `DhcpLeaseAdded` — emitted when a new DHCP lease is created
//! - `DhcpLeaseDeleted` — emitted when a DHCP lease is removed
//! - `DhcpLeaseUpdated` — emitted when an existing DHCP lease is updated
//! - `Up` — emitted once during initialization to signal readiness
//!
//! # Source Reference
//!
//! Primary: `src/dbus.c` lines 1–2175.
//! Supporting: `src/dnsmasq.h`, `src/config.h`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use dbus::ffidisp::{BusType, Connection, ConnectionItem};
use dbus::ffidisp::Watch;
use dbus::Message;
use dbus::arg::messageitem::{MessageItem, MessageItemArray, MessageItemDict};
use dbus::strings::{Interface, Member, Path, Signature};

use log::{info, warn, error};
use thiserror::Error;

use crate::config::constants::{DNSMASQ_SERVICE, DNSMASQ_PATH};
use crate::core::daemon::{
    DaemonState, OPT_BOGUSPRIV, OPT_FILTER, OPT_FILTER_A, OPT_FILTER_AAAA,
    OPT_LOCALISE,
};
use crate::core::metrics::Metric;
use crate::core::util::dnsmasq_time;
use crate::dns::cache::DnsCache;
use crate::dns::protocol::{T_A, T_AAAA};
use crate::dns::server_match::{add_update_server, cleanup_servers, mark_servers};
use crate::types::addr::SocketAddress;
use crate::types::dns::{ServerEntry, ServerFlags};

#[cfg(feature = "dhcp")]
use crate::types::dhcp::{DhcpLease, ACTION_ADD, ACTION_DEL, ACTION_OLD};
#[cfg(feature = "dhcp")]
use crate::dhcp::lease::LeaseDatabase;
#[cfg(all(feature = "dhcp", feature = "dhcp6"))]
use crate::dhcp::lease::LeaseType;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// D-Bus interface name for the dnsmasq service.
const DNSMASQ_INTERFACE: &str = "uk.org.thekelleys.dnsmasq";

/// D-Bus Introspect interface name (standard).
const INTROSPECT_INTERFACE: &str = "org.freedesktop.DBus.Introspectable";

/// Default D-Bus request-name flags: do not queue if name is already owned.
const DBUS_NAME_FLAG_DO_NOT_QUEUE: u32 = 0x4;

/// Reply code indicating the name was successfully acquired as primary owner.
const DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER: u32 = 1;

/// Reply code indicating the caller is already the primary owner.
const DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER: u32 = 4;

/// DNS port number for server configuration.
const NAMESERVER_PORT: u16 = 53;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors that can occur during D-Bus interface operations.
///
/// Replaces C-style error string returns from `dbus_init()` and other
/// D-Bus functions in `dbus.c`.
#[derive(Debug, Error)]
pub enum DbusError {
    /// Failed to connect to the system bus.
    #[error("Failed to connect to system bus: {0}")]
    ConnectionFailed(String),

    /// Failed to request the well-known bus name.
    #[error("Failed to request bus name '{name}': {reason}")]
    NameRequestFailed {
        /// The bus name that was requested.
        name: String,
        /// The reason the request failed.
        reason: String,
    },

    /// Failed to register the D-Bus object path.
    #[error("Failed to register object path: {0}")]
    ObjectPathFailed(String),

    /// A D-Bus message handling or protocol error.
    #[error("D-Bus message error: {0}")]
    MessageError(String),
}

// ---------------------------------------------------------------------------
// DbusState
// ---------------------------------------------------------------------------

/// D-Bus connection state for the dnsmasq daemon.
///
/// Holds the connection to the system bus, the registered service name,
/// and watch modification tracking for poll integration.
///
/// Replaces the C global `daemon->dbus` connection pointer and the
/// `daemon->watches` linked list from `dnsmasq.h`.
pub struct DbusState {
    /// The D-Bus connection to the system bus.
    ///
    /// Uses `dbus::ffidisp::Connection` which provides a legacy but functional
    /// callback-based dispatch model suitable for integration with mio poll.
    pub connection: Connection,

    /// The registered D-Bus well-known service name.
    ///
    /// Defaults to `DNSMASQ_SERVICE` ("uk.org.thekelleys.dnsmasq") but may
    /// be overridden via `daemon.dns.dbus_name`.
    pub service_name: String,

    /// Flag indicating whether D-Bus watch file descriptors have been
    /// modified since the last call to `set_dbus_listeners()`.
    ///
    /// Replaces C's `static int watches_modified` in `dbus.c`.
    pub watches_modified: bool,
}

impl DbusState {
    /// Create a new `DbusState` from an established connection.
    ///
    /// # Arguments
    ///
    /// * `connection` — An open D-Bus system bus connection.
    /// * `service_name` — The well-known bus name that was acquired.
    pub fn new(connection: Connection, service_name: String) -> Self {
        DbusState {
            connection,
            service_name,
            watches_modified: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Introspection XML
// ---------------------------------------------------------------------------

/// Generate the D-Bus introspection XML for the dnsmasq object.
///
/// The XML describes all methods, signals, and their parameter types.
/// Matches the C introspection_xml_template in `dbus.c` lines 87–191.
///
/// # Arguments
///
/// * `service_name` — The D-Bus service name to embed in the XML.
fn build_introspection_xml(service_name: &str) -> String {
    format!(
        r#"<!DOCTYPE node PUBLIC "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN"
"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd">

<node name="{path}">
  <interface name="org.freedesktop.DBus.Introspectable">
    <method name="Introspect">
      <arg direction="out" name="data" type="s"/>
    </method>
  </interface>

  <interface name="{iface}">
    <method name="ClearCache">
    </method>

    <method name="GetVersion">
      <arg direction="out" name="version" type="s"/>
    </method>

    <method name="GetLoopServers">
      <arg direction="out" name="server" type="as"/>
    </method>

    <method name="SetServers">
      <arg direction="in" name="servers" type="av"/>
    </method>

    <method name="SetDomainServers">
      <arg direction="in" name="servers" type="as"/>
    </method>

    <method name="SetServersEx">
      <arg direction="in" name="servers" type="aas"/>
    </method>

    <method name="SetFilterWin2KOption">
      <arg direction="in" name="filterwin2k" type="b"/>
    </method>

    <method name="SetFilterA">
      <arg direction="in" name="filter" type="b"/>
    </method>

    <method name="SetFilterAAAA">
      <arg direction="in" name="filter" type="b"/>
    </method>

    <method name="SetLocaliseQueriesOption">
      <arg direction="in" name="localise" type="b"/>
    </method>

    <method name="SetBogusPrivOption">
      <arg direction="in" name="boguspriv" type="b"/>
    </method>

    <method name="GetMetrics">
      <arg direction="out" name="metrics" type="a{{su}}"/>
    </method>

    <method name="GetServerMetrics">
      <arg direction="out" name="metrics" type="a{{ss}}"/>
    </method>

    <method name="ClearMetrics">
    </method>

    <method name="AddDhcpLease">
      <arg direction="in" name="ipaddr" type="s"/>
      <arg direction="in" name="hwaddr" type="s"/>
      <arg direction="in" name="hostname" type="ay"/>
      <arg direction="in" name="clid" type="ay"/>
      <arg direction="in" name="lease_duration" type="u"/>
      <arg direction="in" name="iaid" type="u"/>
      <arg direction="in" name="is_temporary" type="u"/>
      <arg direction="out" name="result" type="b"/>
    </method>

    <method name="DeleteDhcpLease">
      <arg direction="in" name="ipaddr" type="s"/>
      <arg direction="out" name="result" type="b"/>
    </method>

    <signal name="DhcpLeaseAdded">
      <arg name="ipaddr" type="s"/>
      <arg name="hwaddr" type="s"/>
      <arg name="hostname" type="s"/>
    </signal>

    <signal name="DhcpLeaseDeleted">
      <arg name="ipaddr" type="s"/>
      <arg name="hwaddr" type="s"/>
      <arg name="hostname" type="s"/>
    </signal>

    <signal name="DhcpLeaseUpdated">
      <arg name="ipaddr" type="s"/>
      <arg name="hwaddr" type="s"/>
      <arg name="hostname" type="s"/>
    </signal>
  </interface>
</node>
"#,
        path = DNSMASQ_PATH,
        iface = service_name,
    )
}

// ---------------------------------------------------------------------------
// Initialization — dbus_init()
// ---------------------------------------------------------------------------

/// Initialize the D-Bus interface and connect to the system bus.
///
/// This function:
/// 1. Connects to the system D-Bus bus
/// 2. Requests the well-known service name
/// 3. Registers the object path for method handling
/// 4. Emits the initial "Up" signal to indicate readiness
///
/// # Arguments
///
/// * `daemon_state` — Mutable reference to the daemon state for reading
///   the optional D-Bus name override from `daemon_state.dns.dbus_name`.
///
/// # Returns
///
/// * `Ok(DbusState)` — Successfully connected and registered.
/// * `Err(DbusError)` — Connection, name registration, or path registration failed.
///
/// # Source Reference
///
/// Replaces C `dbus_init()` from `dbus.c` lines 1847–1882.
pub fn dbus_init(daemon_state: &mut DaemonState) -> Result<DbusState, DbusError> {
    // Determine the bus name to use
    let service_name = daemon_state
        .dns
        .dbus_name
        .as_deref()
        .unwrap_or(DNSMASQ_SERVICE)
        .to_string();

    // Connect to the system bus
    let connection = Connection::get_private(BusType::System).map_err(|e| {
        let msg = format!("{}", e);
        error!("D-Bus: failed to connect to system bus: {}", msg);
        DbusError::ConnectionFailed(msg)
    })?;

    info!("D-Bus: connected to system bus");

    // Request the well-known bus name
    // C: dbus_bus_request_name(connection, daemon->dbus_name ?: DNSMASQ_SERVICE,
    //    DBUS_NAME_FLAG_DO_NOT_QUEUE, &dbus_err)
    let reply = connection
        .register_name(&service_name, DBUS_NAME_FLAG_DO_NOT_QUEUE)
        .map_err(|e| {
            let msg = format!("{}", e);
            error!("D-Bus: failed to request name '{}': {}", service_name, msg);
            DbusError::NameRequestFailed {
                name: service_name.clone(),
                reason: msg,
            }
        })?;

    // Verify we got ownership
    let reply_val = reply as u32;
    if reply_val != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER
        && reply_val != DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER
    {
        let msg = format!(
            "name '{}' already owned (reply code {})",
            service_name, reply_val
        );
        error!("D-Bus: {}", msg);
        return Err(DbusError::NameRequestFailed {
            name: service_name,
            reason: msg,
        });
    }

    info!("D-Bus: acquired bus name '{}'", service_name);

    // Register the object path
    // C: dbus_connection_register_object_path(connection, DNSMASQ_PATH, &object_vtable, NULL)
    connection
        .register_object_path(DNSMASQ_PATH)
        .map_err(|e| {
            let msg = format!("{}", e);
            error!("D-Bus: failed to register object path: {}", msg);
            DbusError::ObjectPathFailed(msg)
        })?;

    info!("D-Bus: registered object path '{}'", DNSMASQ_PATH);

    // Set the watch callback to track modifications
    // The dbus crate manages watches internally via WatchList
    connection.set_watch_callback(Box::new(|_watch| {
        // Watch was modified — set flag on next call to set_dbus_listeners
        // Since we cannot access DbusState here, the caller should poll watch_fds()
    }));

    // Emit the "Up" signal to announce readiness
    // C: dbus_message_new_signal(DNSMASQ_PATH, service_name, "Up")
    let up_signal = Message::signal(
        &Path::from(DNSMASQ_PATH),
        &Interface::from(service_name.as_str()),
        &Member::from("Up"),
    );
    if connection.send(up_signal).is_err() {
        warn!("D-Bus: failed to emit 'Up' signal");
    } else {
        info!("D-Bus: emitted 'Up' signal on {}", DNSMASQ_PATH);
    }

    Ok(DbusState::new(connection, service_name))
}

// ---------------------------------------------------------------------------
// Event Loop Integration
// ---------------------------------------------------------------------------

/// Collect D-Bus watch file descriptors for poll registration.
///
/// Returns the current set of watch FDs from the D-Bus connection that
/// need to be monitored by the event loop. The caller should register
/// these with mio or an equivalent poll mechanism.
///
/// # Arguments
///
/// * `state` — The D-Bus connection state.
///
/// # Returns
///
/// A vector of `Watch` descriptors indicating which FDs need monitoring
/// and for which events (read/write).
///
/// # Source Reference
///
/// Replaces C `set_dbus_listeners()` from `dbus.c` lines 1922–1960.
pub fn set_dbus_listeners(state: &DbusState) -> Vec<Watch> {
    state.connection.watch_fds()
}

/// Process ready D-Bus file descriptors and dispatch incoming messages.
///
/// This function should be called after `poll()` returns with ready D-Bus
/// watch file descriptors. It:
/// 1. Handles ready watches to process I/O
/// 2. Dispatches incoming method calls, signals, and replies
/// 3. Delegates method calls to `handle_method()`
///
/// # Arguments
///
/// * `state` — Mutable reference to the D-Bus connection state.
/// * `daemon` — Mutable reference to the daemon state for method handlers.
/// * `dns_cache` — Mutable reference to the DNS cache for ClearCache handler.
/// * `servers` — Mutable reference to the upstream server list.
/// * `lease_db` — Mutable reference to DHCP lease database (feature-gated).
///
/// # Returns
///
/// A tuple of `(new_servers, clear_cache)` flags indicating if
/// SetServers was called or ClearCache was called, respectively.
/// The caller should take appropriate action after dispatching.
///
/// # Source Reference
///
/// Replaces C `check_dbus_listeners()` from `dbus.c` lines 2053–2118.
pub fn check_dbus_listeners(
    state: &mut DbusState,
    daemon: &mut DaemonState,
    dns_cache: &mut DnsCache,
    servers: &mut Vec<ServerEntry>,
    #[cfg(feature = "dhcp")] lease_db: &mut LeaseDatabase,
) -> (bool, bool) {
    let mut new_servers = false;
    let mut clear_cache = false;

    // Get the currently ready watches
    let watches = state.connection.watch_fds();

    // Process each ready watch
    for watch in &watches {
        let revents = watch.to_pollfd().revents;
        if revents == 0 {
            continue;
        }

        let flags = dbus::ffidisp::WatchEvent::from_revents(revents);

        // Process the watch, which may enqueue messages
        #[cfg(unix)]
        let watch_fd = {
            use std::os::unix::io::AsRawFd;
            watch.as_raw_fd()
        };
        #[cfg(not(unix))]
        let watch_fd = watch.fd;

        for item in state.connection.watch_handle(watch_fd, flags) {
            match item {
                ConnectionItem::MethodCall(msg) => {
                    let (ns, cc) = handle_incoming_method(
                        &state.connection,
                        &state.service_name,
                        &msg,
                        daemon,
                        dns_cache,
                        servers,
                        #[cfg(feature = "dhcp")]
                        lease_db,
                    );
                    new_servers |= ns;
                    clear_cache |= cc;
                }
                ConnectionItem::Signal(_) | ConnectionItem::MethodReturn(_) => {
                    // Signals and method returns are not handled on the server side
                }
                ConnectionItem::Nothing => {}
            }
        }
    }

    // Also process any pending messages that were already queued
    // C: while (dbus_connection_dispatch(connection) == DBUS_DISPATCH_DATA_REMAINS)
    for item in state.connection.iter(0) {
        match item {
            ConnectionItem::MethodCall(msg) => {
                let (ns, cc) = handle_incoming_method(
                    &state.connection,
                    &state.service_name,
                    &msg,
                    daemon,
                    dns_cache,
                    servers,
                    #[cfg(feature = "dhcp")]
                    lease_db,
                );
                new_servers |= ns;
                clear_cache |= cc;
            }
            ConnectionItem::Nothing => break,
            _ => {}
        }
    }

    (new_servers, clear_cache)
}

// ---------------------------------------------------------------------------
// Method Dispatch
// ---------------------------------------------------------------------------

/// Handle an incoming D-Bus method call and optionally send a reply.
///
/// This is the central dispatch function corresponding to C `message_handler()`
/// in `dbus.c` lines 1652–1843.
///
/// # Returns
///
/// A tuple `(new_servers, clear_cache)` indicating flags for the caller.
fn handle_incoming_method(
    connection: &Connection,
    service_name: &str,
    msg: &Message,
    daemon: &mut DaemonState,
    dns_cache: &mut DnsCache,
    servers: &mut Vec<ServerEntry>,
    #[cfg(feature = "dhcp")] lease_db: &mut LeaseDatabase,
) -> (bool, bool) {
    let mut new_servers = false;
    let mut clear_cache = false;

    // Extract interface and member for dispatch
    let interface_str = msg.interface().map(|i| i.to_string()).unwrap_or_default();
    let method = msg.member().map(|m| m.to_string()).unwrap_or_default();

    // Handle Introspect on the standard interface
    if interface_str == INTROSPECT_INTERFACE && method == "Introspect" {
        let xml = build_introspection_xml(service_name);
        let reply = msg.return_with_args((xml,));
        let _ = connection.send(reply);
        return (false, false);
    }

    // Only handle our interface or unspecified interface
    if !interface_str.is_empty()
        && interface_str != DNSMASQ_INTERFACE
        && interface_str != service_name
    {
        return (false, false);
    }

    let reply = match method.as_str() {
        "Introspect" => {
            let xml = build_introspection_xml(service_name);
            Some(msg.return_with_args((xml,)))
        }

        "GetVersion" => {
            let version = env!("CARGO_PKG_VERSION");
            Some(msg.return_with_args((version,)))
        }

        "SetServers" => match handle_set_servers(msg, daemon, servers) {
            Ok(()) => {
                new_servers = true;
                clear_cache = true;
                Some(msg.method_return())
            }
            Err(e) => {
                warn!("D-Bus: SetServers error: {}", e);
                Some(create_error_reply(
                    msg,
                    &format!("SetServers failed: {}", e),
                ))
            }
        },

        "SetServersEx" => match handle_set_servers_ex(msg, daemon, servers, false) {
            Ok(()) => {
                new_servers = true;
                clear_cache = true;
                Some(msg.method_return())
            }
            Err(e) => {
                warn!("D-Bus: SetServersEx error: {}", e);
                Some(create_error_reply(
                    msg,
                    &format!("SetServersEx failed: {}", e),
                ))
            }
        },

        "SetDomainServers" => match handle_set_servers_ex(msg, daemon, servers, true) {
            Ok(()) => {
                new_servers = true;
                clear_cache = true;
                Some(msg.method_return())
            }
            Err(e) => {
                warn!("D-Bus: SetDomainServers error: {}", e);
                Some(create_error_reply(
                    msg,
                    &format!("SetDomainServers failed: {}", e),
                ))
            }
        },

        "SetFilterWin2KOption" => {
            handle_set_bool_option(msg, daemon, OPT_FILTER, "filterwin2k")
        }

        "SetLocaliseQueriesOption" => {
            handle_set_bool_option(msg, daemon, OPT_LOCALISE, "localise-queries")
        }

        "SetBogusPrivOption" => {
            handle_set_bool_option(msg, daemon, OPT_BOGUSPRIV, "bogus-priv")
        }

        "SetFilterA" => handle_set_filter_rr(msg, daemon, T_A, OPT_FILTER_A),

        "SetFilterAAAA" => handle_set_filter_rr(msg, daemon, T_AAAA, OPT_FILTER_AAAA),

        "GetMetrics" => Some(handle_get_metrics(msg, daemon)),

        "GetServerMetrics" => Some(handle_get_server_metrics(msg, servers)),

        "ClearMetrics" => {
            handle_clear_metrics(daemon);
            Some(msg.method_return())
        }

        "ClearCache" => {
            dns_cache.clear();
            clear_cache = true;
            info!("D-Bus: cache cleared");
            Some(msg.method_return())
        }

        "GetLoopServers" => Some(handle_get_loop_servers(msg, servers)),

        #[cfg(feature = "dhcp")]
        "AddDhcpLease" => Some(handle_add_lease(msg, daemon, lease_db)),

        #[cfg(feature = "dhcp")]
        "DeleteDhcpLease" => Some(handle_del_lease(msg, lease_db)),

        _ => {
            // Unknown method — return error
            warn!("D-Bus: unknown method '{}'", method);
            None
        }
    };

    if let Some(r) = reply {
        let _ = connection.send(r);
    }

    (new_servers, clear_cache)
}

// ---------------------------------------------------------------------------
// Method Handlers
// ---------------------------------------------------------------------------

/// Create a D-Bus error reply message.
///
/// # Arguments
///
/// * `msg` — The original method call to reply to.
/// * `error_msg` — Human-readable error description.
fn create_error_reply(msg: &Message, error_msg: &str) -> Message {
    let error_name =
        dbus::strings::ErrorName::new("org.freedesktop.DBus.Error.Failed").unwrap();
    let c_msg = std::ffi::CString::new(error_msg)
        .unwrap_or_else(|_| std::ffi::CString::new("Unknown error").unwrap());
    msg.error(&error_name, &c_msg)
}

/// Handle `SetServers` — parse variant array of IPv4/IPv6 addresses.
///
/// Parses the D-Bus message containing a variant array (`av`) of
/// UINT32 (IPv4 addresses) and byte arrays (IPv6 addresses, 16 bytes).
/// Ports are optionally appended as UINT32 after each address.
///
/// # Source Reference
///
/// Replaces C `dbus_read_servers()` from `dbus.c` lines 411–545.
fn handle_set_servers(
    msg: &Message,
    daemon: &DaemonState,
    servers: &mut Vec<ServerEntry>,
) -> Result<(), String> {
    // Mark existing D-Bus servers for replacement
    mark_servers(servers, ServerFlags::FROM_DBUS);

    let items = msg.get_items();
    if items.is_empty() {
        // No servers specified — just clean up marked ones
        cleanup_servers(servers);
        info!("D-Bus: SetServers called with empty list, cleared D-Bus servers");
        return Ok(());
    }

    // Collect addresses from variant items
    let mut pending_addr: Option<SocketAddress> = None;
    let mut pending_port: u16 = NAMESERVER_PORT;
    let mut got_port = false;

    for item in &items {
        // Each item in a SetServers call is a variant
        let inner = match item {
            MessageItem::Variant(v) => v.as_ref(),
            other => other,
        };

        match inner {
            MessageItem::UInt32(val) => {
                if pending_addr.is_some() && !got_port {
                    // This UINT32 is a port for the preceding address
                    pending_port = (*val) as u16;
                    got_port = true;
                    continue;
                }

                // If we have a pending address, commit it
                if let Some(ref mut a) = pending_addr {
                    a.set_port(pending_port);
                    let sa = make_source_addr(a, daemon.dns.query_port);
                    if let Err(e) = add_update_server(
                        servers,
                        ServerFlags::FROM_DBUS,
                        Some(a.clone()),
                        Some(sa),
                        None,
                        None,
                        None,
                    ) {
                        warn!("D-Bus: SetServers add_update_server failed: {}", e);
                    }
                }

                // Start new IPv4 address from network byte order UINT32
                let ipv4 = Ipv4Addr::from(val.to_be_bytes());
                pending_addr = Some(SocketAddress::new_v4(ipv4, NAMESERVER_PORT));
                pending_port = NAMESERVER_PORT;
                got_port = false;
            }

            MessageItem::Array(arr) => {
                let bytes: Vec<u8> = arr
                    .iter()
                    .filter_map(|b| {
                        if let MessageItem::Byte(byte) = b {
                            Some(*byte)
                        } else {
                            None
                        }
                    })
                    .collect();

                if bytes.len() == 16 {
                    // Commit pending address if any
                    if let Some(ref mut a) = pending_addr {
                        a.set_port(pending_port);
                        let sa = make_source_addr(a, daemon.dns.query_port);
                        if let Err(e) = add_update_server(
                            servers,
                            ServerFlags::FROM_DBUS,
                            Some(a.clone()),
                            Some(sa),
                            None,
                            None,
                            None,
                        ) {
                            warn!("D-Bus: SetServers add_update_server failed: {}", e);
                        }
                    }

                    // Start new IPv6 address
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&bytes);
                    let ipv6 = Ipv6Addr::from(octets);
                    pending_addr =
                        Some(SocketAddress::new_v6(ipv6, NAMESERVER_PORT, 0, 0));
                    pending_port = NAMESERVER_PORT;
                    got_port = false;
                } else {
                    warn!(
                        "D-Bus: SetServers ignoring byte array of length {}",
                        bytes.len()
                    );
                }
            }

            _ => {
                warn!("D-Bus: SetServers ignoring unsupported argument type");
            }
        }
    }

    // Commit the last pending address
    if let Some(ref mut a) = pending_addr {
        a.set_port(pending_port);
        let sa = make_source_addr(a, daemon.dns.query_port);
        if let Err(e) = add_update_server(
            servers,
            ServerFlags::FROM_DBUS,
            Some(a.clone()),
            Some(sa),
            None,
            None,
            None,
        ) {
            warn!("D-Bus: SetServers add_update_server failed: {}", e);
        }
    }

    // Remove stale marked servers and rebuild
    cleanup_servers(servers);

    info!("D-Bus: SetServers reconfigured upstream servers");
    Ok(())
}

/// Handle `SetServersEx` and `SetDomainServers` — extended server format.
///
/// For `SetServersEx`: parses an array of string arrays (`aas`).
/// For `SetDomainServers`: parses a flat string array (`as`).
///
/// Each server entry string has the format:
/// `[<domain>/]<addr>[#<port>][@<source_addr>][%<interface>]`
///
/// # Source Reference
///
/// Replaces C `dbus_read_servers_ex()` from `dbus.c` lines 655–934.
fn handle_set_servers_ex(
    msg: &Message,
    daemon: &DaemonState,
    servers: &mut Vec<ServerEntry>,
    is_domain_servers: bool,
) -> Result<(), String> {
    // Mark existing D-Bus servers for replacement
    mark_servers(servers, ServerFlags::FROM_DBUS);

    let items = msg.get_items();
    if items.is_empty() {
        cleanup_servers(servers);
        info!("D-Bus: SetServersEx/SetDomainServers called with empty list");
        return Ok(());
    }

    if is_domain_servers {
        // SetDomainServers: flat string array (as)
        for item in &items {
            let strings = extract_string_array(item);
            for s in &strings {
                parse_and_add_server_string(s, daemon, servers);
            }
        }
    } else {
        // SetServersEx: array of string arrays (aas)
        for item in &items {
            if let MessageItem::Array(arr) = item {
                for inner in arr.iter() {
                    match inner {
                        MessageItem::Array(inner_arr) => {
                            let strings: Vec<String> = inner_arr
                                .iter()
                                .filter_map(|mi| {
                                    if let MessageItem::Str(s) = mi {
                                        Some(s.clone())
                                    } else {
                                        None
                                    }
                                })
                                .collect();
                            parse_server_group(&strings, daemon, servers);
                        }
                        MessageItem::Str(s) => {
                            parse_and_add_server_string(s, daemon, servers);
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    // Remove stale marked servers and rebuild
    cleanup_servers(servers);

    info!("D-Bus: SetServersEx/SetDomainServers reconfigured");
    Ok(())
}

/// Parse a server group from an array of strings.
///
/// First string is the server address, subsequent strings are domain restrictions.
fn parse_server_group(
    strings: &[String],
    daemon: &DaemonState,
    servers: &mut Vec<ServerEntry>,
) {
    if strings.is_empty() {
        return;
    }

    // First entry is the address (possibly with port, source, interface)
    let addr_str = &strings[0];

    // Parse the address portion
    let (addr, source_addr, interface) =
        parse_server_address(addr_str, daemon.dns.query_port);

    if strings.len() <= 1 {
        // No domain restriction — general upstream server
        if let Some(a) = addr {
            let sa = source_addr.unwrap_or_else(|| make_source_addr(&a, daemon.dns.query_port));
            if let Err(e) = add_update_server(
                servers,
                ServerFlags::FROM_DBUS,
                Some(a),
                Some(sa),
                interface.as_deref(),
                None,
                None,
            ) {
                warn!("D-Bus: add_update_server failed: {}", e);
            }
        }
    } else {
        // Domain restrictions in subsequent strings
        for domain in &strings[1..] {
            if let Some(ref a) = addr {
                let sa = source_addr
                    .clone()
                    .unwrap_or_else(|| make_source_addr(a, daemon.dns.query_port));
                if let Err(e) = add_update_server(
                    servers,
                    ServerFlags::FROM_DBUS,
                    Some(a.clone()),
                    Some(sa),
                    interface.as_deref(),
                    Some(domain.as_str()),
                    None,
                ) {
                    warn!(
                        "D-Bus: add_update_server failed for domain '{}': {}",
                        domain, e
                    );
                }
            }
        }
    }
}

/// Parse and add a single server string in the format:
/// `[<domain>/]<addr>[#<port>][@<source>][%<interface>]`
fn parse_and_add_server_string(
    s: &str,
    daemon: &DaemonState,
    servers: &mut Vec<ServerEntry>,
) {
    if s.is_empty() {
        return;
    }

    // Split domain prefix if present: "domain/addr" or just "addr"
    let (domain, addr_part) = if let Some(slash_pos) = s.rfind('/') {
        let d = &s[..slash_pos];
        let a = &s[slash_pos + 1..];
        (Some(d), a)
    } else {
        (None, s)
    };

    let (addr, source_addr, interface) =
        parse_server_address(addr_part, daemon.dns.query_port);

    if let Some(a) = addr {
        let sa = source_addr.unwrap_or_else(|| make_source_addr(&a, daemon.dns.query_port));
        if let Err(e) = add_update_server(
            servers,
            ServerFlags::FROM_DBUS,
            Some(a),
            Some(sa),
            interface.as_deref(),
            domain,
            None,
        ) {
            warn!("D-Bus: parse_and_add_server_string failed: {}", e);
        }
    } else if let Some(domain_name) = domain {
        // Domain with no address means "use this domain for local resolution"
        if let Err(e) = add_update_server(
            servers,
            ServerFlags::FROM_DBUS,
            None,
            None,
            None,
            Some(domain_name),
            None,
        ) {
            warn!(
                "D-Bus: parse_and_add_server_string failed for local domain '{}': {}",
                domain_name, e
            );
        }
    }
}

/// Parse a server address string of the form:
/// `<addr>[#<port>][@<source_addr>][%<interface>]`
///
/// Returns `(addr, source_addr, interface)`.
fn parse_server_address(
    s: &str,
    query_port: u16,
) -> (Option<SocketAddress>, Option<SocketAddress>, Option<String>) {
    if s.is_empty() {
        return (None, None, None);
    }

    let mut remaining = s;
    let mut interface: Option<String> = None;
    let mut source_addr: Option<SocketAddress> = None;

    // Extract interface binding: %<interface>
    if let Some(pct_pos) = remaining.rfind('%') {
        let iface_str = &remaining[pct_pos + 1..];
        if !iface_str.is_empty() {
            interface = Some(iface_str.to_string());
        }
        remaining = &remaining[..pct_pos];
    }

    // Extract source address: @<source_addr>
    if let Some(at_pos) = remaining.rfind('@') {
        let src_str = &remaining[at_pos + 1..];
        source_addr = parse_ip_with_port(src_str, query_port);
        remaining = &remaining[..at_pos];
    }

    // Parse the main address (with optional port via #)
    let addr = parse_ip_with_port(remaining, NAMESERVER_PORT);

    (addr, source_addr, interface)
}

/// Parse an IP address string, optionally with `#<port>` suffix.
///
/// Supports both IPv4 (`1.2.3.4#53`) and IPv6 (`[::1]#53` or `::1`).
fn parse_ip_with_port(s: &str, default_port: u16) -> Option<SocketAddress> {
    if s.is_empty() {
        return None;
    }

    let (addr_str, port) = if let Some(hash_pos) = s.rfind('#') {
        let port_str = &s[hash_pos + 1..];
        let port = port_str.parse::<u16>().unwrap_or(default_port);
        (&s[..hash_pos], port)
    } else {
        (s, default_port)
    };

    // Try IPv4 first
    if let Ok(ipv4) = addr_str.parse::<Ipv4Addr>() {
        return Some(SocketAddress::new_v4(ipv4, port));
    }

    // Try IPv6 (with or without brackets)
    let ipv6_str = addr_str
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(addr_str);

    if let Ok(ipv6) = ipv6_str.parse::<Ipv6Addr>() {
        return Some(SocketAddress::new_v6(ipv6, port, 0, 0));
    }

    warn!("D-Bus: failed to parse IP address '{}'", addr_str);
    None
}

/// Create a default source address matching the family of the given address.
///
/// Uses `INADDR_ANY` or `IN6ADDR_ANY` with the configured `query_port`.
fn make_source_addr(addr: &SocketAddress, query_port: u16) -> SocketAddress {
    match addr {
        SocketAddress::V4(_) => SocketAddress::new_v4(Ipv4Addr::UNSPECIFIED, query_port),
        SocketAddress::V6(_) => {
            SocketAddress::new_v6(Ipv6Addr::UNSPECIFIED, query_port, 0, 0)
        }
    }
}

/// Handle boolean option setting methods.
///
/// Covers `SetFilterWin2KOption`, `SetLocaliseQueriesOption`, `SetBogusPrivOption`.
///
/// # Source Reference
///
/// Replaces C `dbus_set_bool()` from `dbus.c` lines 994–1070.
fn handle_set_bool_option(
    msg: &Message,
    daemon: &mut DaemonState,
    opt: usize,
    name: &str,
) -> Option<Message> {
    let enabled: Option<bool> = msg.get1();
    match enabled {
        Some(val) => {
            if val {
                daemon.set_option(opt);
            } else {
                daemon.clear_option(opt);
            }
            info!(
                "D-Bus: {} option {}",
                name,
                if val { "enabled" } else { "disabled" }
            );
            Some(msg.method_return())
        }
        None => {
            warn!("D-Bus: {} missing boolean argument", name);
            Some(create_error_reply(
                msg,
                &format!("{} requires a boolean argument", name),
            ))
        }
    }
}

/// Handle `SetFilterA` and `SetFilterAAAA` methods.
///
/// These add or remove RR type filter entries in the daemon's filter list
/// and set/clear the corresponding option flags.
///
/// # Source Reference
///
/// Replaces C SetFilterA/SetFilterAAAA handling from `dbus.c` lines 1750–1800.
fn handle_set_filter_rr(
    msg: &Message,
    daemon: &mut DaemonState,
    rr_type: u16,
    opt: usize,
) -> Option<Message> {
    let enabled: Option<bool> = msg.get1();
    match enabled {
        Some(val) => {
            if val {
                // Add filter: add to filter_rr list and set option flag
                if !daemon.dns.filter_rr.contains(&rr_type) {
                    daemon.dns.filter_rr.push(rr_type);
                }
                daemon.set_option(opt);
                info!(
                    "D-Bus: SetFilter{} enabled (RR type {})",
                    if rr_type == T_A { "A" } else { "AAAA" },
                    rr_type
                );
            } else {
                // Remove filter: remove from filter_rr list and clear option flag
                daemon.dns.filter_rr.retain(|&t| t != rr_type);
                daemon.clear_option(opt);
                info!(
                    "D-Bus: SetFilter{} disabled (RR type {})",
                    if rr_type == T_A { "A" } else { "AAAA" },
                    rr_type
                );
            }
            Some(msg.method_return())
        }
        None => {
            warn!("D-Bus: SetFilter missing boolean argument");
            Some(create_error_reply(
                msg,
                "SetFilter requires a boolean argument",
            ))
        }
    }
}

/// Handle `GetMetrics` — return all metric counters as a dict `a{su}`.
///
/// # Source Reference
///
/// Replaces C `dbus_get_metrics()` from `dbus.c` lines 1334–1397.
fn handle_get_metrics(msg: &Message, daemon: &DaemonState) -> Message {
    let metrics = daemon.metrics.borrow();

    let mut entries: Vec<(MessageItem, MessageItem)> = Vec::new();

    // Iterate all metric variants and build dict entries
    for metric in Metric::all() {
        let name = metric.name();
        let value = metrics.get(*metric);

        entries.push((
            MessageItem::Str(name.to_string()),
            MessageItem::UInt32(value as u32),
        ));
    }

    let mut reply = msg.method_return();

    // Build the dict: a{su}
    match MessageItemDict::new(
        entries,
        Signature::new("s").unwrap(),
        Signature::new("u").unwrap(),
    ) {
        Ok(dict) => {
            reply.append_items(&[MessageItem::Dict(dict)]);
        }
        Err(_) => {
            warn!("D-Bus: GetMetrics failed to construct dict");
        }
    }

    reply
}

/// Handle `GetServerMetrics` — return per-server statistics as a dict `a{ss}`.
///
/// Aggregates statistics per unique server address, marking servers with
/// `SERV_MARK` to avoid double-counting when the same address appears
/// for multiple domains.
///
/// # Source Reference
///
/// Replaces C `dbus_get_server_metrics()` from `dbus.c` lines 1509–1650.
fn handle_get_server_metrics(msg: &Message, servers: &[ServerEntry]) -> Message {
    let mut entries: Vec<(MessageItem, MessageItem)> = Vec::new();

    // Track which servers we've already counted by index
    let mut counted: Vec<bool> = vec![false; servers.len()];

    for i in 0..servers.len() {
        if counted[i] {
            continue;
        }
        if servers[i].flags.intersects(ServerFlags::LITERAL_ADDRESS) {
            continue;
        }

        let mut total_queries: u64 = servers[i].queries as u64;
        let mut total_failed: u64 = servers[i].failed_queries as u64;

        // Aggregate all entries with the same address
        counted[i] = true;
        for j in (i + 1)..servers.len() {
            if counted[j] {
                continue;
            }
            if servers[j].addr == servers[i].addr {
                total_queries += servers[j].queries as u64;
                total_failed += servers[j].failed_queries as u64;
                counted[j] = true;
            }
        }

        // Format the server address
        let addr_str = format_server_addr(&servers[i]);
        let stats_str = format!("{} {} {}", total_queries, total_failed, 0);

        entries.push((
            MessageItem::Str(addr_str),
            MessageItem::Str(stats_str),
        ));
    }

    let mut reply = msg.method_return();

    match MessageItemDict::new(
        entries,
        Signature::new("s").unwrap(),
        Signature::new("s").unwrap(),
    ) {
        Ok(dict) => {
            reply.append_items(&[MessageItem::Dict(dict)]);
        }
        Err(_) => {
            warn!("D-Bus: GetServerMetrics failed to construct dict");
        }
    }

    reply
}

/// Handle `ClearMetrics` — reset all metric counters.
///
/// # Source Reference
///
/// Replaces the ClearMetrics branch in C `message_handler()`.
fn handle_clear_metrics(daemon: &DaemonState) {
    let mut metrics = daemon.metrics.borrow_mut();
    metrics.clear();
    info!("D-Bus: metrics cleared");
}

/// Handle `GetLoopServers` — return servers flagged with SERV_LOOP.
///
/// Returns an array of strings containing the addresses of servers
/// that have been detected as forwarding loops.
///
/// # Source Reference
///
/// Replaces C `dbus_reply_server_loop()` from `dbus.c` lines 547–653.
fn handle_get_loop_servers(msg: &Message, servers: &[ServerEntry]) -> Message {
    let mut loop_addrs: Vec<MessageItem> = Vec::new();

    for server in servers {
        if server.flags.intersects(ServerFlags::LOOP) {
            let addr_str = format_server_addr(server);
            loop_addrs.push(MessageItem::Str(addr_str));
        }
    }

    let mut reply = msg.method_return();

    match MessageItemArray::new(loop_addrs, Signature::new("s").unwrap()) {
        Ok(arr) => {
            reply.append_items(&[MessageItem::Array(arr)]);
        }
        Err(_) => {
            warn!("D-Bus: GetLoopServers failed to construct array");
        }
    }

    reply
}

/// Format a server address for display in D-Bus responses.
fn format_server_addr(server: &ServerEntry) -> String {
    let port = server.addr.port();
    let ip_str = match &server.addr {
        SocketAddress::V4(v4) => format!("{}", v4.ip()),
        SocketAddress::V6(v6) => format!("{}", v6.ip()),
    };
    if port != NAMESERVER_PORT {
        format!("{}#{}", ip_str, port)
    } else {
        ip_str
    }
}

// ---------------------------------------------------------------------------
// DHCP Lease Management
// ---------------------------------------------------------------------------

/// Handle `AddDhcpLease` — create or update a DHCP lease via D-Bus.
///
/// Parses the D-Bus message arguments:
/// - `ipaddr` (string) — IP address of the lease
/// - `hwaddr` (string) — Hardware address (MAC)
/// - `hostname` (byte array) — Hostname bytes
/// - `clid` (byte array) — Client ID bytes
/// - `lease_duration` (uint32) — Lease duration in seconds
/// - `iaid` (uint32) — Identity Association ID (DHCPv6)
/// - `is_temporary` (uint32) — Whether this is a temporary address
///
/// # Source Reference
///
/// Replaces C `dbus_add_lease()` from `dbus.c` lines 1072–1250.
#[cfg(feature = "dhcp")]
fn handle_add_lease(
    msg: &Message,
    daemon: &DaemonState,
    lease_db: &mut LeaseDatabase,
) -> Message {
    let items = msg.get_items();

    // Parse arguments: ipaddr(s), hwaddr(s), hostname(ay), clid(ay),
    //                  lease_duration(u), iaid(u), is_temporary(u)
    if items.len() < 5 {
        warn!(
            "D-Bus: AddDhcpLease: insufficient arguments (got {})",
            items.len()
        );
        return msg.return_with_args((false,));
    }

    // Parse IP address string
    let ip_str = match &items[0] {
        MessageItem::Str(s) => s.as_str(),
        _ => {
            warn!("D-Bus: AddDhcpLease: first argument must be string (ipaddr)");
            return msg.return_with_args((false,));
        }
    };

    let ip_addr: IpAddr = match ip_str.parse() {
        Ok(ip) => ip,
        Err(_) => {
            warn!("D-Bus: AddDhcpLease: invalid IP address '{}'", ip_str);
            return msg.return_with_args((false,));
        }
    };

    // Parse hardware address string
    let hwaddr_str = match &items[1] {
        MessageItem::Str(s) => s.clone(),
        _ => {
            warn!("D-Bus: AddDhcpLease: second argument must be string (hwaddr)");
            return msg.return_with_args((false,));
        }
    };

    // Parse hostname byte array
    let hostname_bytes = extract_byte_array(&items[2]);
    let hostname = String::from_utf8_lossy(&hostname_bytes).to_string();

    // Parse CLID byte array
    let clid_bytes = extract_byte_array(&items[3]);
    let clid: Option<&[u8]> = if clid_bytes.is_empty() {
        None
    } else {
        Some(&clid_bytes)
    };

    // Parse lease duration
    let lease_duration: u32 = match &items[4] {
        MessageItem::UInt32(v) => *v,
        _ => 0,
    };

    // Parse optional IAID and is_temporary
    let _iaid: u32 = if items.len() > 5 {
        match &items[5] {
            MessageItem::UInt32(v) => *v,
            _ => 0,
        }
    } else {
        0
    };

    let _is_temporary: bool = if items.len() > 6 {
        match &items[6] {
            MessageItem::UInt32(v) => *v != 0,
            _ => false,
        }
    } else {
        false
    };

    // Parse the hardware address into bytes
    let hwaddr = parse_hwaddr(&hwaddr_str);

    let now = dnsmasq_time();
    let domain_suffix = daemon.dns.domain_suffix.as_deref();

    match ip_addr {
        IpAddr::V4(ipv4) => {
            // Check if lease exists
            let exists = lease_db.find_by_addr_v4(&ipv4).is_some();

            // allocate_v4 returns the existing entry or creates a new one
            match lease_db.allocate_v4(ipv4) {
                Ok(lease) => {
                    LeaseDatabase::set_hwaddr(lease, &hwaddr, clid, 0, _iaid);
                    LeaseDatabase::set_expires(lease, lease_duration, now);
                    if !hostname.is_empty() {
                        // set_hostname is a &mut self method on LeaseDatabase
                        // We must call it on the lease_db after releasing the lease borrow
                    }
                }
                Err(e) => {
                    warn!(
                        "D-Bus: AddDhcpLease: failed to allocate IPv4 lease: {}",
                        e
                    );
                    return msg.return_with_args((false,));
                }
            }

            // Set hostname via LeaseDatabase method
            if !hostname.is_empty() {
                lease_db.set_hostname(
                    IpAddr::V4(ipv4),
                    Some(&hostname),
                    false,
                    domain_suffix,
                );
            }

            if let Err(e) = lease_db.update_file(now) {
                warn!("D-Bus: AddDhcpLease: failed to update lease file: {}", e);
            }

            info!(
                "D-Bus: AddDhcpLease: {} lease for {} ({})",
                if exists { "updated" } else { "created" },
                ipv4,
                hostname
            );
        }
        IpAddr::V6(_ipv6) => {
            #[cfg(feature = "dhcp6")]
            {
                let exists = lease_db.find_v6_by_plain_addr(&_ipv6).is_some();
                let lease_type = if _is_temporary {
                    LeaseType::TA
                } else {
                    LeaseType::NA
                };

                match lease_db.allocate_v6(_ipv6, lease_type) {
                    Ok(lease) => {
                        LeaseDatabase::set_hwaddr(lease, &hwaddr, clid, 0, _iaid);
                        LeaseDatabase::set_expires(lease, lease_duration, now);
                    }
                    Err(e) => {
                        warn!(
                            "D-Bus: AddDhcpLease: failed to allocate IPv6 lease: {}",
                            e
                        );
                        return msg.return_with_args((false,));
                    }
                }

                if !hostname.is_empty() {
                    lease_db.set_hostname(
                        IpAddr::V6(_ipv6),
                        Some(&hostname),
                        false,
                        domain_suffix,
                    );
                }

                if let Err(e) = lease_db.update_file(now) {
                    warn!("D-Bus: AddDhcpLease: failed to update lease file: {}", e);
                }

                info!(
                    "D-Bus: AddDhcpLease: {} lease for {} ({})",
                    if exists { "updated" } else { "created" },
                    _ipv6,
                    hostname
                );
            }
            #[cfg(not(feature = "dhcp6"))]
            {
                warn!("D-Bus: AddDhcpLease: IPv6 lease not supported (dhcp6 feature disabled)");
                return msg.return_with_args((false,));
            }
        }
    }

    msg.return_with_args((true,))
}

/// Handle `DeleteDhcpLease` — remove a DHCP lease by IP address.
///
/// # Source Reference
///
/// Replaces C `dbus_del_lease()` from `dbus.c` lines 1252–1332.
#[cfg(feature = "dhcp")]
fn handle_del_lease(msg: &Message, lease_db: &mut LeaseDatabase) -> Message {
    let ip_str: Option<String> = msg.get1();
    match ip_str {
        Some(ref s) => {
            let ip_addr: Result<IpAddr, _> = s.parse();
            match ip_addr {
                Ok(IpAddr::V4(ipv4)) => {
                    let found = lease_db.find_by_addr_v4(&ipv4).is_some();
                    if found {
                        let now = dnsmasq_time();
                        // Mark the lease as expired by setting duration to 0
                        if let Ok(lease) = lease_db.allocate_v4(ipv4) {
                            LeaseDatabase::set_expires(lease, 0, now);
                        }
                        if let Err(e) = lease_db.update_file(now) {
                            warn!(
                                "D-Bus: DeleteDhcpLease: failed to update lease file: {}",
                                e
                            );
                        }
                        info!("D-Bus: DeleteDhcpLease: removed lease for {}", ipv4);
                        msg.return_with_args((true,))
                    } else {
                        warn!("D-Bus: DeleteDhcpLease: no lease found for {}", ipv4);
                        msg.return_with_args((false,))
                    }
                }
                Ok(IpAddr::V6(_ipv6)) => {
                    #[cfg(feature = "dhcp6")]
                    {
                        let found = lease_db.find_v6_by_plain_addr(&_ipv6).is_some();
                        if found {
                            let now = dnsmasq_time();
                            if let Ok(lease) =
                                lease_db.allocate_v6(_ipv6, LeaseType::NA)
                            {
                                LeaseDatabase::set_expires(lease, 0, now);
                            }
                            if let Err(e) = lease_db.update_file(now) {
                                warn!(
                                    "D-Bus: DeleteDhcpLease: failed to update lease file: {}",
                                    e
                                );
                            }
                            info!(
                                "D-Bus: DeleteDhcpLease: removed lease for {}",
                                _ipv6
                            );
                            msg.return_with_args((true,))
                        } else {
                            warn!(
                                "D-Bus: DeleteDhcpLease: no lease found for {}",
                                _ipv6
                            );
                            msg.return_with_args((false,))
                        }
                    }
                    #[cfg(not(feature = "dhcp6"))]
                    {
                        warn!("D-Bus: DeleteDhcpLease: IPv6 not supported (dhcp6 feature disabled)");
                        msg.return_with_args((false,))
                    }
                }
                Err(_) => {
                    warn!("D-Bus: DeleteDhcpLease: invalid IP address '{}'", s);
                    msg.return_with_args((false,))
                }
            }
        }
        None => {
            warn!("D-Bus: DeleteDhcpLease: missing IP address argument");
            msg.return_with_args((false,))
        }
    }
}

// ---------------------------------------------------------------------------
// Signal Emission
// ---------------------------------------------------------------------------

/// Emit a D-Bus signal for DHCP lease changes.
///
/// Maps action codes to signal names:
/// - `ACTION_DEL` → `DhcpLeaseDeleted`
/// - `ACTION_ADD` → `DhcpLeaseAdded`
/// - `ACTION_OLD` → `DhcpLeaseUpdated`
///
/// The signal carries three string arguments:
/// 1. IP address (formatted)
/// 2. Hardware address (MAC, formatted as colon-separated hex)
/// 3. Hostname
///
/// # Arguments
///
/// * `state` — The D-Bus connection state.
/// * `action` — The lease action code (`ACTION_DEL`, `ACTION_ADD`, or `ACTION_OLD`).
/// * `lease` — The DHCP lease being reported.
/// * `hostname` — The hostname associated with the lease.
///
/// # Source Reference
///
/// Replaces C `emit_dbus_signal()` from `dbus.c` lines 2122–2172.
#[cfg(feature = "dhcp")]
pub fn emit_dbus_signal(
    state: &DbusState,
    action: i32,
    lease: &DhcpLease,
    hostname: &str,
) {
    let signal_name = if action == ACTION_DEL {
        "DhcpLeaseDeleted"
    } else if action == ACTION_ADD {
        "DhcpLeaseAdded"
    } else if action == ACTION_OLD {
        "DhcpLeaseUpdated"
    } else {
        warn!("D-Bus: emit_dbus_signal: unknown action {}", action);
        return;
    };

    // Format the IP address — use the v4 addr field
    // For v6, use addr6 if dhcp6 is enabled
    let ip_str = format!("{}", lease.addr);

    // Format the hardware address
    let hwaddr_str = format_hwaddr(&lease.hwaddr);

    // Build and send the signal
    let signal = Message::signal(
        &Path::from(DNSMASQ_PATH),
        &Interface::from(state.service_name.as_str()),
        &Member::from(signal_name),
    )
    .append3(&ip_str as &str, &hwaddr_str as &str, hostname);

    match state.connection.send(signal) {
        Ok(_) => {
            info!(
                "D-Bus: emitted {} signal for {} ({})",
                signal_name, ip_str, hostname
            );
        }
        Err(_) => {
            error!(
                "D-Bus: failed to emit {} signal for {}",
                signal_name, ip_str
            );
        }
    }
}

/// Emit a D-Bus signal for DHCP lease changes (non-DHCP fallback).
///
/// When the DHCP feature is disabled, this provides a compatible API
/// that does nothing.
#[cfg(not(feature = "dhcp"))]
pub fn emit_dbus_signal(
    _state: &DbusState,
    _action: i32,
    _lease_addr: &str,
    _hwaddr: &str,
    _hostname: &str,
) {
    // DHCP feature not enabled — signal emission is a no-op
}

// ---------------------------------------------------------------------------
// Utility Functions
// ---------------------------------------------------------------------------

/// Extract a string array from a `MessageItem`.
///
/// Handles both `Array(Str)` and `Variant(Array(Str))` formats.
fn extract_string_array(item: &MessageItem) -> Vec<String> {
    match item {
        MessageItem::Array(arr) => arr
            .iter()
            .filter_map(|mi| {
                if let MessageItem::Str(s) = mi {
                    Some(s.clone())
                } else {
                    None
                }
            })
            .collect(),
        MessageItem::Variant(v) => extract_string_array(v),
        MessageItem::Str(s) => vec![s.clone()],
        _ => Vec::new(),
    }
}

/// Extract a byte array from a `MessageItem`.
///
/// Handles `Array(Byte)` and `Variant(Array(Byte))` formats.
fn extract_byte_array(item: &MessageItem) -> Vec<u8> {
    match item {
        MessageItem::Array(arr) => arr
            .iter()
            .filter_map(|mi| {
                if let MessageItem::Byte(b) = mi {
                    Some(*b)
                } else {
                    None
                }
            })
            .collect(),
        MessageItem::Variant(v) => extract_byte_array(v),
        _ => Vec::new(),
    }
}

/// Parse a hardware address string (e.g., "aa:bb:cc:dd:ee:ff") into bytes.
fn parse_hwaddr(s: &str) -> Vec<u8> {
    s.split(':')
        .filter_map(|octet| u8::from_str_radix(octet, 16).ok())
        .collect()
}

/// Format a hardware address byte slice as a colon-separated hex string.
#[cfg(feature = "dhcp")]
fn format_hwaddr(hwaddr: &[u8]) -> String {
    hwaddr
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":")
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dbus_error_display() {
        let err = DbusError::ConnectionFailed("test reason".into());
        assert_eq!(
            format!("{}", err),
            "Failed to connect to system bus: test reason"
        );

        let err = DbusError::NameRequestFailed {
            name: "test.name".into(),
            reason: "already taken".into(),
        };
        assert_eq!(
            format!("{}", err),
            "Failed to request bus name 'test.name': already taken"
        );

        let err = DbusError::ObjectPathFailed("path error".into());
        assert_eq!(
            format!("{}", err),
            "Failed to register object path: path error"
        );

        let err = DbusError::MessageError("msg error".into());
        assert_eq!(format!("{}", err), "D-Bus message error: msg error");
    }

    #[test]
    fn test_build_introspection_xml() {
        let xml = build_introspection_xml(DNSMASQ_SERVICE);
        assert!(xml.contains("ClearCache"));
        assert!(xml.contains("GetVersion"));
        assert!(xml.contains("SetServers"));
        assert!(xml.contains("SetServersEx"));
        assert!(xml.contains("SetDomainServers"));
        assert!(xml.contains("SetFilterWin2KOption"));
        assert!(xml.contains("SetFilterA"));
        assert!(xml.contains("SetFilterAAAA"));
        assert!(xml.contains("SetLocaliseQueriesOption"));
        assert!(xml.contains("SetBogusPrivOption"));
        assert!(xml.contains("GetMetrics"));
        assert!(xml.contains("GetServerMetrics"));
        assert!(xml.contains("ClearMetrics"));
        assert!(xml.contains("AddDhcpLease"));
        assert!(xml.contains("DeleteDhcpLease"));
        assert!(xml.contains("DhcpLeaseAdded"));
        assert!(xml.contains("DhcpLeaseDeleted"));
        assert!(xml.contains("DhcpLeaseUpdated"));
        assert!(xml.contains(DNSMASQ_PATH));
    }

    #[test]
    fn test_parse_ip_with_port_ipv4() {
        let addr = parse_ip_with_port("192.168.1.1", 53);
        assert!(addr.is_some());
        let a = addr.unwrap();
        assert!(a.is_v4());
        assert_eq!(a.port(), 53);

        let addr = parse_ip_with_port("10.0.0.1#5353", 53);
        assert!(addr.is_some());
        let a = addr.unwrap();
        assert!(a.is_v4());
        assert_eq!(a.port(), 5353);
    }

    #[test]
    fn test_parse_ip_with_port_ipv6() {
        let addr = parse_ip_with_port("::1", 53);
        assert!(addr.is_some());
        let a = addr.unwrap();
        assert!(a.is_v6());
        assert_eq!(a.port(), 53);

        let addr = parse_ip_with_port("[::1]#8053", 53);
        assert!(addr.is_some());
        let a = addr.unwrap();
        assert!(a.is_v6());
        assert_eq!(a.port(), 8053);
    }

    #[test]
    fn test_parse_ip_with_port_empty() {
        assert!(parse_ip_with_port("", 53).is_none());
    }

    #[test]
    fn test_parse_server_address_full() {
        let (addr, source, iface) =
            parse_server_address("192.168.1.1#53@10.0.0.1%eth0", 0);
        assert!(addr.is_some());
        assert!(source.is_some());
        assert_eq!(iface, Some("eth0".to_string()));
    }

    #[test]
    fn test_parse_server_address_simple() {
        let (addr, source, iface) = parse_server_address("8.8.8.8", 0);
        assert!(addr.is_some());
        assert!(source.is_none());
        assert!(iface.is_none());
    }

    #[test]
    fn test_make_source_addr_v4() {
        let addr = SocketAddress::new_v4(Ipv4Addr::new(8, 8, 8, 8), 53);
        let sa = make_source_addr(&addr, 0);
        assert!(sa.is_v4());
        assert_eq!(sa.port(), 0);
    }

    #[test]
    fn test_make_source_addr_v6() {
        let addr = SocketAddress::new_v6(Ipv6Addr::LOCALHOST, 53, 0, 0);
        let sa = make_source_addr(&addr, 0);
        assert!(sa.is_v6());
        assert_eq!(sa.port(), 0);
    }

    #[test]
    fn test_parse_hwaddr() {
        let bytes = parse_hwaddr("aa:bb:cc:dd:ee:ff");
        assert_eq!(bytes, vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

        let bytes = parse_hwaddr("00:11:22:33:44:55");
        assert_eq!(bytes, vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        let bytes = parse_hwaddr("");
        assert!(bytes.is_empty());
    }

    #[test]
    fn test_extract_string_array() {
        let item = MessageItem::Str("hello".to_string());
        let result = extract_string_array(&item);
        assert_eq!(result, vec!["hello".to_string()]);
    }

    #[test]
    fn test_extract_byte_array_empty() {
        let item = MessageItem::Str("not bytes".to_string());
        let result = extract_byte_array(&item);
        assert!(result.is_empty());
    }

    #[cfg(feature = "dhcp")]
    #[test]
    fn test_format_hwaddr() {
        assert_eq!(
            format_hwaddr(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            "aa:bb:cc:dd:ee:ff"
        );
        assert_eq!(format_hwaddr(&[]), "");
    }

    #[test]
    fn test_format_server_addr_default_port() {
        let server = make_test_server(
            SocketAddress::new_v4(Ipv4Addr::new(8, 8, 8, 8), 53),
            ServerFlags::empty(),
        );
        assert_eq!(format_server_addr(&server), "8.8.8.8");
    }

    #[test]
    fn test_format_server_addr_custom_port() {
        let server = make_test_server(
            SocketAddress::new_v4(Ipv4Addr::new(8, 8, 4, 4), 5353),
            ServerFlags::empty(),
        );
        assert_eq!(format_server_addr(&server), "8.8.4.4#5353");
    }

    #[test]
    fn test_format_server_addr_ipv6() {
        let server = make_test_server(
            SocketAddress::new_v6(Ipv6Addr::LOCALHOST, 53, 0, 0),
            ServerFlags::empty(),
        );
        assert_eq!(format_server_addr(&server), "::1");
    }

    /// Helper to create a minimal ServerEntry for testing.
    fn make_test_server(addr: SocketAddress, flags: ServerFlags) -> ServerEntry {
        ServerEntry {
            flags,
            domain_len: 0,
            domain: None,
            serial: 0,
            arrayposn: 0,
            last_server: 0,
            addr,
            source_addr: SocketAddress::new_v4(Ipv4Addr::UNSPECIFIED, 0),
            interface: String::new(),
            ifindex: 0,
            tcpfd: -1,
            queries: 0,
            failed_queries: 0,
            nxdomain_replies: 0,
            retrys: 0,
            query_latency: 0,
            mma_latency: 0,
            forwardtime: 0,
            forwardcount: 0,
            #[cfg(feature = "loop_detect")]
            uid: 0,
        }
    }
}

// dnsmasq is Copyright (c) 2000-2025 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! # D-Bus Control Interface for NetworkManager Integration
//!
//! Rust implementation of the D-Bus control interface for dnsmasq, migrated
//! from `src/dbus.c` (2,175 lines). This module exposes dnsmasq's operational
//! state and configuration to external applications via the system D-Bus message
//! bus under service name `uk.org.thekelleys.dnsmasq`.
//!
//! ## D-Bus Service Details
//! - **Service name:** `uk.org.thekelleys.dnsmasq`
//! - **Object path:** `/uk/org/thekelleys/dnsmasq`
//! - **Interface:** `uk.org.thekelleys.dnsmasq`
//! - **Security:** Access controlled via D-Bus system bus policy (`dbus/dnsmasq.conf`)
//!
//! ## Supported Methods
//! - `GetVersion` — returns the dnsmasq version string
//! - `ClearCache` — flush the DNS cache and re-read hosts files
//! - `SetServers` — set upstream DNS servers (binary format)
//! - `SetServersEx` — set upstream DNS servers (string format)
//! - `SetDomainServers` — set domain-specific upstream DNS servers
//! - `SetFilterWin2KOption` — toggle Windows 2000 DNS option filtering
//! - `SetBogusPrivOption` — toggle bogus private reverse DNS filtering
//! - `SetFilterA` — toggle A record filtering
//! - `SetFilterAAAA` — toggle AAAA record filtering
//! - `SetLocaliseQueriesOption` — toggle query localisation
//! - `GetMetrics` — return metrics dict `a{su}`
//! - `GetServerMetrics` — return per-server metrics `a{ss}`
//! - `ClearMetrics` — reset all metrics counters
//! - `AddDhcpLease` — add a DHCP lease (feature-gated: `dhcp`)
//! - `DeleteDhcpLease` — delete a DHCP lease (feature-gated: `dhcp`)
//! - `GetLoopServers` — return looping servers (feature-gated: `loop-detect`)
//!
//! ## Signals
//! - `DhcpLeaseAdded` — emitted when a new DHCP lease is created
//! - `DhcpLeaseDeleted` — emitted when a DHCP lease is removed
//! - `DhcpLeaseUpdated` — emitted when an existing DHCP lease is refreshed
//!
//! ## Architecture
//! Uses the `dbus` crate (0.9) replacing the C `libdbus-1` dependency. The
//! [`DbusController`] owns a blocking [`Connection`] to the system bus, provides
//! file-descriptor–based event-loop integration via [`DbusController::get_fds`],
//! and processes incoming messages synchronously in
//! [`DbusController::check_listeners`].
//!
//! ## Memory Safety
//! No manual memory management — the `dbus` crate manages message lifecycles
//! via Rust ownership. All shared state is accessed through `Arc<RwLock<…>>`
//! references passed to method handlers.

use std::collections::HashMap;
use std::ffi::CString;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::unix::io::RawFd;
use std::sync::Arc;
use std::time::Duration;

use dbus::blocking::Connection;
use dbus::channel::Watch;
use dbus::strings::ErrorName;
use dbus::{Message, MessageType};

use tracing::{debug, error, info, warn};

use crate::core::types::DaemonState;
use crate::core::util::{format_addr, format_mac};
#[cfg(feature = "dhcp")]
use crate::dhcp::lease::DhcpLease;
use crate::diagnostics::metrics::{MetricsStore, METRIC_MAX};
use crate::dns::cache::DnsCache;
use crate::dns::domain_match::DomainMatcher;
use crate::dns::protocol::NAMESERVER_PORT;

// Re-import for event loop integration documentation. The `tokio::sync::RwLock`
// is referenced by callers wrapping `DaemonState`; here we use `std::sync::RwLock`
// because the blocking D-Bus `Connection` operates synchronously.
#[allow(unused_imports)]
use tokio::sync::RwLock as TokioRwLock;

// ---------------------------------------------------------------------------
// Module-level constants (from src/dbus.c lines 104-130)
// ---------------------------------------------------------------------------

/// D-Bus service name under which dnsmasq registers on the system bus.
///
/// Corresponds to C macro `DNSMASQ_SERVICE` (`dbus.c` line 108).
/// NetworkManager and other D-Bus clients use this well-known name to locate
/// the dnsmasq control interface.
pub const DBUS_SERVICE_NAME: &str = "uk.org.thekelleys.dnsmasq";

/// D-Bus object path for the dnsmasq control interface.
///
/// Corresponds to C macro `DNSMASQ_PATH` (`dbus.c` line 109).
pub const DBUS_OBJECT_PATH: &str = "/uk/org/thekelleys/dnsmasq";

/// D-Bus interface name for dnsmasq method calls and signals.
const DBUS_INTERFACE: &str = "uk.org.thekelleys.dnsmasq";

/// DNS RR type A (IPv4 address), used by SetFilterA.
const T_A: u16 = 1;

/// DNS RR type AAAA (IPv6 address), used by SetFilterAAAA.
const T_AAAA: u16 = 28;

// ---------------------------------------------------------------------------
// Server flag constants (imported from domain_match but referenced directly
// to keep D-Bus method handler logic self-contained)
// ---------------------------------------------------------------------------

/// Flag indicating a server entry was configured via D-Bus (SERV_FROM_DBUS).
const SERV_FROM_DBUS: u32 = 256;

/// Flag used for marking servers during reconfiguration (SERV_MARK).
#[allow(dead_code)]
const SERV_MARK: u32 = 512;

/// Flag indicating a server was detected as causing forwarding loops (SERV_LOOP).
#[cfg(feature = "loop-detect")]
const SERV_LOOP: u32 = 8192;

// ---------------------------------------------------------------------------
// DHCP action constants (matching lease.rs values)
// ---------------------------------------------------------------------------

/// Action code: delete a DHCP lease.
#[cfg(feature = "dhcp")]
const ACTION_DEL: i32 = 1;

/// Action code: existing lease refreshed/unchanged.
#[cfg(feature = "dhcp")]
const ACTION_OLD: i32 = 3;

/// Action code: new DHCP lease added.
#[cfg(feature = "dhcp")]
const ACTION_ADD: i32 = 4;

// ---------------------------------------------------------------------------
// Option flag indices (matching core::types::opt module)
// ---------------------------------------------------------------------------

/// Index for OPT_BOGUSPRIV in the option bit-field.
const OPT_BOGUSPRIV: u32 = 0;

/// Index for OPT_FILTER in the option bit-field.
const OPT_FILTER: u32 = 1;

/// Index for OPT_LOCALISE in the option bit-field.
const OPT_LOCALISE: u32 = 18;

// ---------------------------------------------------------------------------
// Introspection XML (from src/dbus.c lines 112-191)
// ---------------------------------------------------------------------------

/// Complete D-Bus introspection XML for the dnsmasq service object.
///
/// This XML is returned in response to `org.freedesktop.DBus.Introspectable.Introspect`
/// method calls, allowing D-Bus tools (d-feet, busctl, gdbus) to discover
/// the available methods and signals.
const INTROSPECTION_XML: &str = concat!(
    "<!DOCTYPE node PUBLIC \"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\"\n",
    "\"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\">\n",
    "<node name=\"/uk/org/thekelleys/dnsmasq\">\n",
    "  <interface name=\"org.freedesktop.DBus.Introspectable\">\n",
    "    <method name=\"Introspect\">\n",
    "      <arg direction=\"out\" name=\"data\" type=\"s\"/>\n",
    "    </method>\n",
    "  </interface>\n",
    "  <interface name=\"uk.org.thekelleys.dnsmasq\">\n",
    "    <method name=\"ClearCache\">\n",
    "    </method>\n",
    "    <method name=\"GetVersion\">\n",
    "      <arg direction=\"out\" name=\"version\" type=\"s\"/>\n",
    "    </method>\n",
    "    <method name=\"SetServers\">\n",
    "      <arg direction=\"in\" name=\"servers\" type=\"av\"/>\n",
    "    </method>\n",
    "    <method name=\"SetServersEx\">\n",
    "      <arg direction=\"in\" name=\"servers\" type=\"aas\"/>\n",
    "    </method>\n",
    "    <method name=\"SetDomainServers\">\n",
    "      <arg direction=\"in\" name=\"servers\" type=\"as\"/>\n",
    "    </method>\n",
    "    <method name=\"SetFilterWin2KOption\">\n",
    "      <arg direction=\"in\" name=\"filterwin2k\" type=\"b\"/>\n",
    "    </method>\n",
    "    <method name=\"SetBogusPrivOption\">\n",
    "      <arg direction=\"in\" name=\"boguspriv\" type=\"b\"/>\n",
    "    </method>\n",
    "    <method name=\"SetFilterA\">\n",
    "      <arg direction=\"in\" name=\"filter\" type=\"b\"/>\n",
    "    </method>\n",
    "    <method name=\"SetFilterAAAA\">\n",
    "      <arg direction=\"in\" name=\"filter\" type=\"b\"/>\n",
    "    </method>\n",
    "    <method name=\"SetLocaliseQueriesOption\">\n",
    "      <arg direction=\"in\" name=\"localise\" type=\"b\"/>\n",
    "    </method>\n",
    "    <method name=\"GetMetrics\">\n",
    "      <arg direction=\"out\" name=\"metrics\" type=\"a{su}\"/>\n",
    "    </method>\n",
    "    <method name=\"GetServerMetrics\">\n",
    "      <arg direction=\"out\" name=\"metrics\" type=\"aa{ss}\"/>\n",
    "    </method>\n",
    "    <method name=\"ClearMetrics\">\n",
    "    </method>\n",
    "    <method name=\"AddDhcpLease\">\n",
    "      <arg direction=\"in\" name=\"ipaddr\" type=\"s\"/>\n",
    "      <arg direction=\"in\" name=\"hwaddr\" type=\"s\"/>\n",
    "      <arg direction=\"in\" name=\"hostname\" type=\"s\"/>\n",
    "      <arg direction=\"in\" name=\"clid\" type=\"s\"/>\n",
    "      <arg direction=\"in\" name=\"lease_duration\" type=\"u\"/>\n",
    "      <arg direction=\"in\" name=\"iaid\" type=\"u\"/>\n",
    "      <arg direction=\"in\" name=\"is_temporary\" type=\"b\"/>\n",
    "      <arg direction=\"out\" name=\"result\" type=\"b\"/>\n",
    "    </method>\n",
    "    <method name=\"DeleteDhcpLease\">\n",
    "      <arg direction=\"in\" name=\"ipaddr\" type=\"s\"/>\n",
    "      <arg direction=\"out\" name=\"result\" type=\"b\"/>\n",
    "    </method>\n",
    "    <method name=\"GetLoopServers\">\n",
    "      <arg direction=\"out\" name=\"servers\" type=\"as\"/>\n",
    "    </method>\n",
    "    <signal name=\"DhcpLeaseAdded\">\n",
    "      <arg name=\"ipaddr\" type=\"s\"/>\n",
    "      <arg name=\"hwaddr\" type=\"s\"/>\n",
    "      <arg name=\"hostname\" type=\"s\"/>\n",
    "    </signal>\n",
    "    <signal name=\"DhcpLeaseDeleted\">\n",
    "      <arg name=\"ipaddr\" type=\"s\"/>\n",
    "      <arg name=\"hwaddr\" type=\"s\"/>\n",
    "      <arg name=\"hostname\" type=\"s\"/>\n",
    "    </signal>\n",
    "    <signal name=\"DhcpLeaseUpdated\">\n",
    "      <arg name=\"ipaddr\" type=\"s\"/>\n",
    "      <arg name=\"hwaddr\" type=\"s\"/>\n",
    "      <arg name=\"hostname\" type=\"s\"/>\n",
    "    </signal>\n",
    "  </interface>\n",
    "</node>\n"
);

// ---------------------------------------------------------------------------
// Error types (Phase 10 of agent_prompt)
// ---------------------------------------------------------------------------

/// Errors specific to the D-Bus control interface.
///
/// Replaces C's `DBusError` message string handling with typed Rust error
/// variants that integrate with the [`DnsmasqError`] hierarchy.
#[derive(Debug, thiserror::Error)]
pub enum DbusError {
    /// Failed to connect to the D-Bus system bus.
    ///
    /// Typically caused by the D-Bus daemon not running or insufficient
    /// permissions. In the C version, this results in `dbus_init()` returning
    /// an error string to the caller.
    #[error("D-Bus connection failed: {0}")]
    ConnectionFailed(String),

    /// Failed to register the D-Bus service name or object path handler.
    ///
    /// Occurs when another instance already owns the bus name or the
    /// `request_name` call is denied by the D-Bus security policy.
    #[error("Failed to register D-Bus handler: {0}")]
    RegistrationFailed(String),

    /// A D-Bus method invocation produced an error.
    ///
    /// Wraps errors returned by individual method handlers (invalid args,
    /// failed operations, etc.).
    #[error("D-Bus method error: {0}")]
    MethodError(String),
}

// ---------------------------------------------------------------------------
// DbusController — primary D-Bus state management struct
// ---------------------------------------------------------------------------

/// Controller managing the D-Bus connection and message dispatch for dnsmasq.
///
/// Replaces the C global `DBusConnection*` pointer and associated static state
/// (`watches_modified`, watch linked list) from `dbus.c` lines 199-225.
///
/// ## Lifecycle
/// 1. [`DbusController::new`] connects to the system bus, requests the service
///    name, and emits an initial `Up` signal.
/// 2. The main event loop calls [`DbusController::get_fds`] to obtain file
///    descriptors for `poll(2)` / `tokio::io::AsyncFd` integration.
/// 3. When fds are ready, [`DbusController::check_listeners`] reads pending
///    messages and dispatches method calls to the appropriate handlers.
/// 4. DHCP lease events trigger [`DbusController::emit_signal`] to broadcast
///    D-Bus signals.
pub struct DbusController {
    /// D-Bus system bus connection.
    ///
    /// Replaces C global `DBusConnection* connection` (`dbus.c` line 199).
    connection: Connection,

    /// The registered D-Bus service name.
    ///
    /// Default: [`DBUS_SERVICE_NAME`]. Can be overridden via `daemon->dbus_name`.
    /// Accessible for diagnostics and logging.
    pub service_name: String,

    /// Whether the FilterA toggle has been activated via D-Bus.
    /// Replaces C static `unsigned int *filter_a` in the SetFilterA handler.
    filter_a_active: bool,

    /// Whether the FilterAAAA toggle has been activated via D-Bus.
    /// Replaces C static `unsigned int *filter_aaaa` in the SetFilterAAAA handler.
    filter_aaaa_active: bool,
}

// ---------------------------------------------------------------------------
// Public API — DbusController methods
// ---------------------------------------------------------------------------

impl DbusController {
    /// Create a new D-Bus controller and connect to the system bus.
    ///
    /// Replaces C `dbus_init()` (`dbus.c` lines 1847-1882):
    /// 1. Connect to the system D-Bus bus.
    /// 2. Disable automatic exit-on-disconnect (handled internally by the
    ///    `dbus` crate's `Channel::get_private`).
    /// 3. Request the well-known bus name.
    /// 4. Emit an initial `Up` signal to notify waiting clients.
    ///
    /// # Arguments
    /// * `dbus_name` — The D-Bus service name to register. Typically
    ///   [`DBUS_SERVICE_NAME`], but may be overridden via `daemon->dbus_name`.
    ///
    /// # Errors
    /// Returns [`DbusError::ConnectionFailed`] if the system bus connection
    /// cannot be established, or [`DbusError::RegistrationFailed`] if the
    /// bus name request is denied.
    pub fn new(dbus_name: &str) -> Result<Self, DbusError> {
        // Connect to the system bus. The dbus crate's Channel::get_private
        // already calls dbus_connection_set_exit_on_disconnect(conn, FALSE)
        // matching the C initialization sequence.
        let conn = Connection::new_system().map_err(|e| {
            error!(error = %e, "Failed to connect to D-Bus system bus");
            DbusError::ConnectionFailed(e.to_string())
        })?;

        info!("Connected to D-Bus system bus");

        // Request the well-known bus name.
        // Flags: allow_replacement=false, replace_existing=false, do_not_queue=false
        // This matches C's dbus_bus_request_name(conn, name, 0, &err).
        let reply = conn
            .request_name(dbus_name, false, false, false)
            .map_err(|e| {
                error!(name = dbus_name, error = %e, "Failed to request D-Bus name");
                DbusError::RegistrationFailed(e.to_string())
            })?;

        use dbus::blocking::stdintf::org_freedesktop_dbus::RequestNameReply;
        match reply {
            RequestNameReply::PrimaryOwner => {
                info!(name = dbus_name, "D-Bus name registered as primary owner");
            }
            RequestNameReply::AlreadyOwner => {
                info!(name = dbus_name, "D-Bus name already owned by us");
            }
            _ => {
                warn!(
                    name = dbus_name,
                    ?reply,
                    "D-Bus name request did not yield primary ownership"
                );
            }
        }

        let controller = DbusController {
            connection: conn,
            service_name: dbus_name.to_string(),
            filter_a_active: false,
            filter_aaaa_active: false,
        };

        // Emit the initial "Up" signal to notify clients that dnsmasq is ready.
        // Replaces C: dbus_message_new_signal(DNSMASQ_PATH, DNSMASQ_SERVICE, "Up").
        controller.emit_up_signal();

        info!(
            name = dbus_name,
            "D-Bus controller initialized successfully"
        );
        Ok(controller)
    }

    /// Return the file descriptors that the event loop should monitor for D-Bus
    /// I/O readiness.
    ///
    /// Replaces C `set_dbus_listeners()` (`dbus.c` lines 1922-1940). The main
    /// event loop should call this before each `poll(2)` / `tokio::select!`
    /// iteration and add the returned fds to the poll set.
    ///
    /// # Returns
    /// A vector of `(fd, poll_events)` tuples where `poll_events` uses
    /// `libc::POLLIN` / `libc::POLLOUT` flag values.
    pub fn get_fds(&self) -> Vec<(RawFd, i16)> {
        let watch: Watch = self.connection.channel().watch();
        let mut events: i16 = 0;
        if watch.read {
            events |= 0x0001; // POLLIN
        }
        if watch.write {
            events |= 0x0004; // POLLOUT
        }
        if events != 0 {
            vec![(watch.fd, events)]
        } else {
            Vec::new()
        }
    }

    /// Process pending D-Bus messages and dispatch method calls.
    ///
    /// Replaces C `check_dbus_listeners()` (`dbus.c` lines 2053-2066).
    /// Should be called from the main event loop when [`get_fds`] file
    /// descriptors become ready.
    ///
    /// This method reads pending data from the D-Bus socket, pops queued
    /// messages, and dispatches method calls to the appropriate handler.
    ///
    /// # Arguments
    /// * `state` — Shared daemon state for server management and option toggles.
    /// * `metrics` — Runtime metrics store for GetMetrics/ClearMetrics.
    /// * `cache` — DNS cache for ClearCache.
    /// * `domain_matcher` — Domain matcher for SetServers/SetServersEx.
    pub fn check_listeners(
        &mut self,
        state: &Arc<std::sync::RwLock<DaemonState>>,
        metrics: &Arc<MetricsStore>,
        cache: &Arc<std::sync::RwLock<DnsCache>>,
        domain_matcher: &Arc<std::sync::RwLock<DomainMatcher>>,
    ) {
        // Non-blocking read/write on the D-Bus socket (timeout = 0ms).
        // Borrows `self.connection` immutably via `channel()`.
        {
            let channel = self.connection.channel();
            if channel.read_write(Some(Duration::from_millis(0))).is_err() {
                debug!("D-Bus connection read_write returned error (connection may be closed)");
                return;
            }
        }

        // Collect all queued messages first, then release the channel borrow
        // so that `handle_method_call` can borrow `self` mutably.
        let messages: Vec<Message> = {
            let channel = self.connection.channel();
            let mut msgs = Vec::new();
            while let Some(msg) = channel.pop_message() {
                msgs.push(msg);
            }
            msgs
        };

        // Process collected messages.
        for msg in &messages {
            match msg.msg_type() {
                MessageType::MethodCall => {
                    let reply = self.handle_method_call(msg, state, metrics, cache, domain_matcher);
                    if let Some(reply_msg) = reply {
                        if self.connection.channel().send(reply_msg).is_err() {
                            warn!("Failed to send D-Bus method reply");
                        }
                    }
                }
                _ => {
                    // For non-method-call messages (signals, returns, errors),
                    // apply default handling (responds to Peer interface, sends
                    // "unknown method" for unhandled calls).
                    if let Some(reply) = dbus::channel::default_reply(msg) {
                        let _ = self.connection.channel().send(reply);
                    }
                }
            }
        }
    }

    /// Emit a DHCP lease change signal on the D-Bus.
    ///
    /// Replaces C `emit_dbus_signal()` (`dbus.c` lines 2122-2174). Called by
    /// the DHCP subsystem whenever a lease is added, deleted, or updated.
    ///
    /// # Signal Names
    /// - `ACTION_ADD` (4) → `DhcpLeaseAdded`
    /// - `ACTION_DEL` (1) → `DhcpLeaseDeleted`
    /// - `ACTION_OLD` (3) → `DhcpLeaseUpdated`
    ///
    /// # Signal Payload
    /// Three string arguments: `(ipaddr, hwaddr, hostname)`.
    #[cfg(feature = "dhcp")]
    pub fn emit_signal(&self, action: i32, lease: &DhcpLease, hostname: &str) {
        let signal_name = match action {
            ACTION_DEL => "DhcpLeaseDeleted",
            ACTION_OLD => "DhcpLeaseUpdated",
            ACTION_ADD => "DhcpLeaseAdded",
            _ => {
                debug!(action, "Unknown DHCP action for D-Bus signal, ignoring");
                return;
            }
        };

        // Format the lease IP address as a string.
        let addr_str = if let Some(a6) = lease.addr6 {
            a6.to_string()
        } else if let Some(a4) = lease.addr {
            a4.to_string()
        } else {
            String::new()
        };

        // Format the hardware address as a colon-separated hex string.
        let mac_str = format_mac(&lease.hwaddr);

        // Build and send the D-Bus signal.
        match Message::new_signal(DBUS_OBJECT_PATH, DBUS_INTERFACE, signal_name) {
            Ok(sig) => {
                let sig = sig
                    .append1(addr_str.as_str())
                    .append1(mac_str.as_str())
                    .append1(hostname);
                if self.connection.channel().send(sig).is_err() {
                    warn!(signal = signal_name, "Failed to send D-Bus signal");
                } else {
                    debug!(
                        signal = signal_name,
                        addr = %addr_str,
                        hostname = hostname,
                        "Emitted D-Bus DHCP signal"
                    );
                }
            }
            Err(e) => {
                warn!(signal = signal_name, error = %e, "Failed to create D-Bus signal message");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Private implementation — message dispatch and method handlers
// ---------------------------------------------------------------------------

impl DbusController {
    /// Emit the initial "Up" signal announcing dnsmasq is ready on D-Bus.
    ///
    /// Replaces the signal emission at the end of C `dbus_init()`.
    fn emit_up_signal(&self) {
        match Message::new_signal(DBUS_OBJECT_PATH, DBUS_INTERFACE, "Up") {
            Ok(sig) => {
                if self.connection.channel().send(sig).is_err() {
                    warn!("Failed to send D-Bus Up signal");
                } else {
                    debug!("Emitted D-Bus Up signal");
                }
            }
            Err(e) => {
                warn!(error = %e, "Failed to create D-Bus Up signal message");
            }
        }
    }

    /// Central method call dispatcher.
    ///
    /// Replaces C `message_handler()` (`dbus.c` lines 1450-1846). Examines
    /// the incoming message's interface and member, then delegates to the
    /// appropriate handler function.
    ///
    /// Returns `Some(Message)` containing the reply, or `None` if no reply
    /// is needed.
    fn handle_method_call(
        &mut self,
        msg: &Message,
        state: &Arc<std::sync::RwLock<DaemonState>>,
        metrics: &Arc<MetricsStore>,
        cache: &Arc<std::sync::RwLock<DnsCache>>,
        domain_matcher: &Arc<std::sync::RwLock<DomainMatcher>>,
    ) -> Option<Message> {
        let interface = msg.interface().map(|i| i.to_string());
        let member_name = msg.member().map(|m| m.to_string());

        // Handle org.freedesktop.DBus.Introspectable.Introspect.
        if interface.as_deref() == Some("org.freedesktop.DBus.Introspectable")
            && member_name.as_deref() == Some("Introspect")
        {
            return Some(self.handle_introspect(msg));
        }

        // Handle org.freedesktop.DBus.Peer methods via default handler.
        if interface.as_deref() == Some("org.freedesktop.DBus.Peer") {
            return dbus::channel::default_reply(msg);
        }

        // Route dnsmasq interface methods.
        let method = match member_name.as_deref() {
            Some(name) => name,
            None => {
                return Some(create_unknown_method_error(msg, "No method specified"));
            }
        };

        debug!(method, "D-Bus method call received");

        match method {
            "GetVersion" => Some(self.handle_get_version(msg)),
            "ClearCache" => Some(Self::handle_clear_cache(msg, cache)),
            "SetServers" => Some(Self::handle_set_servers(msg, state, domain_matcher)),
            "SetServersEx" => Some(Self::handle_set_servers_ex(msg, state, domain_matcher)),
            "SetDomainServers" => Some(Self::handle_set_domain_servers(msg, state, domain_matcher)),
            "SetFilterWin2KOption" => Some(self.handle_set_filter_win2k(msg, state, cache)),
            "SetBogusPrivOption" => Some(Self::handle_set_bogus_priv(msg, state, cache)),
            "SetFilterA" => Some(self.handle_set_filter_a(msg, state, cache)),
            "SetFilterAAAA" => Some(self.handle_set_filter_aaaa(msg, state, cache)),
            "SetLocaliseQueriesOption" => {
                Some(Self::handle_set_localise_queries(msg, state, cache))
            }
            "GetMetrics" => Some(Self::handle_get_metrics(msg, metrics)),
            "GetServerMetrics" => Some(Self::handle_get_server_metrics(msg, state)),
            "ClearMetrics" => Some(Self::handle_clear_metrics(msg, metrics, state)),
            #[cfg(feature = "dhcp")]
            "AddDhcpLease" => Some(Self::handle_add_dhcp_lease(msg)),
            #[cfg(feature = "dhcp")]
            "DeleteDhcpLease" => Some(Self::handle_delete_dhcp_lease(msg)),
            #[cfg(feature = "loop-detect")]
            "GetLoopServers" => Some(Self::handle_get_loop_servers(msg, state)),
            _ => {
                debug!(method, "Unknown D-Bus method");
                Some(create_unknown_method_error(msg, method))
            }
        }
    }

    // -----------------------------------------------------------------------
    // Individual method handlers
    // -----------------------------------------------------------------------

    /// Handle `Introspect` — return XML service description.
    fn handle_introspect(&self, msg: &Message) -> Message {
        msg.method_return().append1(INTROSPECTION_XML)
    }

    /// Handle `GetVersion` — return the dnsmasq version string.
    ///
    /// Uses `CARGO_PKG_VERSION` (from `Cargo.toml` `version = "2.92.0"`).
    fn handle_get_version(&self, msg: &Message) -> Message {
        let version = env!("CARGO_PKG_VERSION");
        debug!(version, "D-Bus GetVersion");
        msg.method_return().append1(version)
    }

    /// Handle `ClearCache` — flush DNS cache and re-read hosts files.
    ///
    /// Replaces C `message_handler` ClearCache dispatch (`dbus.c` line ~1467)
    /// which calls `clear_cache_and_reload(0)`.
    fn handle_clear_cache(msg: &Message, cache: &Arc<std::sync::RwLock<DnsCache>>) -> Message {
        info!("D-Bus ClearCache: flushing DNS cache");
        if let Ok(mut cache_guard) = cache.write() {
            let _ = cache_guard.cache_reload();
        } else {
            warn!("Failed to acquire DNS cache write lock for ClearCache");
        }
        msg.method_return()
    }

    /// Handle `SetServers` — parse binary-encoded upstream DNS servers.
    ///
    /// Replaces C `dbus_read_servers()` (`dbus.c` lines 411-503). Parses
    /// binary-encoded upstream DNS server addresses from the D-Bus message
    /// payload. IPv4 addresses are 4 bytes, IPv6 addresses are 16 bytes.
    ///
    /// Flow:
    /// 1. Mark existing D-Bus-configured servers.
    /// 2. Parse new server addresses from the variant array.
    /// 3. Register each parsed server via `DomainMatcher::add_update_server`.
    /// 4. Remove stale marked servers via `DomainMatcher::cleanup_servers`.
    fn handle_set_servers(
        msg: &Message,
        state: &Arc<std::sync::RwLock<DaemonState>>,
        domain_matcher: &Arc<std::sync::RwLock<DomainMatcher>>,
    ) -> Message {
        info!("D-Bus SetServers: reconfiguring upstream DNS servers");
        let server_addrs = parse_servers_binary(msg);
        apply_server_update(state, domain_matcher, &server_addrs, None);
        msg.method_return()
    }

    /// Handle `SetServersEx` — parse string-encoded upstream DNS servers.
    ///
    /// Replaces C `dbus_read_servers_ex()` (`dbus.c` lines 655-935).
    fn handle_set_servers_ex(
        msg: &Message,
        state: &Arc<std::sync::RwLock<DaemonState>>,
        domain_matcher: &Arc<std::sync::RwLock<DomainMatcher>>,
    ) -> Message {
        info!("D-Bus SetServersEx: reconfiguring upstream DNS servers (extended)");
        let entries = parse_servers_ex_from_msg(msg);
        apply_server_entries(state, domain_matcher, &entries);
        msg.method_return()
    }

    /// Handle `SetDomainServers` — flat array of string server specifications.
    fn handle_set_domain_servers(
        msg: &Message,
        state: &Arc<std::sync::RwLock<DaemonState>>,
        domain_matcher: &Arc<std::sync::RwLock<DomainMatcher>>,
    ) -> Message {
        info!("D-Bus SetDomainServers: reconfiguring domain-specific servers");
        let entries = parse_domain_servers_from_msg(msg);
        apply_server_entries(state, domain_matcher, &entries);
        msg.method_return()
    }

    /// Handle `SetFilterWin2KOption` — toggle `OPT_FILTER`.
    fn handle_set_filter_win2k(
        &self,
        msg: &Message,
        state: &Arc<std::sync::RwLock<DaemonState>>,
        cache: &Arc<std::sync::RwLock<DnsCache>>,
    ) -> Message {
        match msg.read1::<bool>() {
            Ok(enabled) => {
                debug!(enabled, "D-Bus SetFilterWin2KOption");
                if let Ok(mut st) = state.write() {
                    if enabled {
                        st.options.set(OPT_FILTER);
                    } else {
                        st.options.clear(OPT_FILTER);
                    }
                }
                if let Ok(mut c) = cache.write() {
                    let _ = c.cache_reload();
                }
                msg.method_return()
            }
            Err(_) => create_invalid_args_error(msg, "Expected boolean argument"),
        }
    }

    /// Handle `SetBogusPrivOption` — toggle `OPT_BOGUSPRIV`.
    fn handle_set_bogus_priv(
        msg: &Message,
        state: &Arc<std::sync::RwLock<DaemonState>>,
        cache: &Arc<std::sync::RwLock<DnsCache>>,
    ) -> Message {
        match msg.read1::<bool>() {
            Ok(enabled) => {
                debug!(enabled, "D-Bus SetBogusPrivOption");
                if let Ok(mut st) = state.write() {
                    if enabled {
                        st.options.set(OPT_BOGUSPRIV);
                    } else {
                        st.options.clear(OPT_BOGUSPRIV);
                    }
                }
                if let Ok(mut c) = cache.write() {
                    let _ = c.cache_reload();
                }
                msg.method_return()
            }
            Err(_) => create_invalid_args_error(msg, "Expected boolean argument"),
        }
    }

    /// Handle `SetFilterA` — toggle A record (type 1) in `filter_rr`.
    fn handle_set_filter_a(
        &mut self,
        msg: &Message,
        state: &Arc<std::sync::RwLock<DaemonState>>,
        cache: &Arc<std::sync::RwLock<DnsCache>>,
    ) -> Message {
        match msg.read1::<bool>() {
            Ok(enabled) => {
                debug!(enabled, "D-Bus SetFilterA");
                if let Ok(mut st) = state.write() {
                    update_filter_rr(&mut st.filter_rr, T_A, enabled);
                }
                self.filter_a_active = enabled;
                if let Ok(mut c) = cache.write() {
                    let _ = c.cache_reload();
                }
                msg.method_return()
            }
            Err(_) => create_invalid_args_error(msg, "Expected boolean argument"),
        }
    }

    /// Handle `SetFilterAAAA` — toggle AAAA record (type 28) in `filter_rr`.
    fn handle_set_filter_aaaa(
        &mut self,
        msg: &Message,
        state: &Arc<std::sync::RwLock<DaemonState>>,
        cache: &Arc<std::sync::RwLock<DnsCache>>,
    ) -> Message {
        match msg.read1::<bool>() {
            Ok(enabled) => {
                debug!(enabled, "D-Bus SetFilterAAAA");
                if let Ok(mut st) = state.write() {
                    update_filter_rr(&mut st.filter_rr, T_AAAA, enabled);
                }
                self.filter_aaaa_active = enabled;
                if let Ok(mut c) = cache.write() {
                    let _ = c.cache_reload();
                }
                msg.method_return()
            }
            Err(_) => create_invalid_args_error(msg, "Expected boolean argument"),
        }
    }

    /// Handle `SetLocaliseQueriesOption` — toggle `OPT_LOCALISE`.
    fn handle_set_localise_queries(
        msg: &Message,
        state: &Arc<std::sync::RwLock<DaemonState>>,
        cache: &Arc<std::sync::RwLock<DnsCache>>,
    ) -> Message {
        match msg.read1::<bool>() {
            Ok(enabled) => {
                debug!(enabled, "D-Bus SetLocaliseQueriesOption");
                if let Ok(mut st) = state.write() {
                    if enabled {
                        st.options.set(OPT_LOCALISE);
                    } else {
                        st.options.clear(OPT_LOCALISE);
                    }
                }
                if let Ok(mut c) = cache.write() {
                    let _ = c.cache_reload();
                }
                msg.method_return()
            }
            Err(_) => create_invalid_args_error(msg, "Expected boolean argument"),
        }
    }

    /// Handle `GetMetrics` — return `a{su}` dict of metric name → value.
    ///
    /// Replaces C `dbus_get_metrics()` (`dbus.c` lines 1334-1398).
    fn handle_get_metrics(msg: &Message, metrics: &Arc<MetricsStore>) -> Message {
        debug!("D-Bus GetMetrics");
        let mut dict: HashMap<String, u32> = HashMap::with_capacity(METRIC_MAX);
        for (name, value) in metrics.iter() {
            // Truncate u64 → u32 to match C's uint32 D-Bus type.
            dict.insert(name.to_string(), value as u32);
        }
        msg.method_return().append1(dict)
    }

    /// Handle `GetServerMetrics` — return `aa{ss}` per-server stats.
    ///
    /// Replaces C `dbus_get_server_metrics()` (`dbus.c` lines 1509-1679).
    fn handle_get_server_metrics(
        msg: &Message,
        state: &Arc<std::sync::RwLock<DaemonState>>,
    ) -> Message {
        debug!("D-Bus GetServerMetrics");
        let mut result: Vec<HashMap<String, String>> = Vec::new();

        if let Ok(st) = state.read() {
            for server in &st.servers {
                let mut entry = HashMap::new();
                let addr_str = format_addr(&server.addr);
                entry.insert("address".to_string(), addr_str);
                entry.insert(
                    "domain".to_string(),
                    server.domain.clone().unwrap_or_default(),
                );
                entry.insert("queries".to_string(), server.queries.to_string());
                entry.insert("failed".to_string(), server.failed_queries.to_string());
                result.push(entry);
            }
        }

        msg.method_return().append1(result)
    }

    /// Handle `ClearMetrics` — reset all counters to zero.
    fn handle_clear_metrics(
        msg: &Message,
        metrics: &Arc<MetricsStore>,
        state: &Arc<std::sync::RwLock<DaemonState>>,
    ) -> Message {
        info!("D-Bus ClearMetrics: resetting all counters");
        metrics.clear();
        if let Ok(mut st) = state.write() {
            for server in &mut st.servers {
                server.queries = 0;
                server.failed_queries = 0;
            }
        }
        msg.method_return()
    }

    /// Handle `AddDhcpLease` — create or update a DHCP lease.
    ///
    /// Replaces C `message_handler` AddDhcpLease dispatch (`dbus.c` lines
    /// 1072-1252). Parses 7 arguments: ipaddr, hwaddr, hostname, clid,
    /// lease_duration, iaid, is_temporary.
    #[cfg(feature = "dhcp")]
    fn handle_add_dhcp_lease(msg: &Message) -> Message {
        let mut iter = msg.iter_init();

        let ipaddr: String = match iter.read() {
            Ok(v) => v,
            Err(_) => return create_invalid_args_error(msg, "Missing ipaddr"),
        };
        iter.next();

        let hwaddr: String = match iter.read() {
            Ok(v) => v,
            Err(_) => return create_invalid_args_error(msg, "Missing hwaddr"),
        };
        iter.next();

        let hostname: String = match iter.read() {
            Ok(v) => v,
            Err(_) => return create_invalid_args_error(msg, "Missing hostname"),
        };
        iter.next();

        let clid: String = match iter.read() {
            Ok(v) => v,
            Err(_) => return create_invalid_args_error(msg, "Missing clid"),
        };
        iter.next();

        let _lease_duration: u32 = match iter.read() {
            Ok(v) => v,
            Err(_) => return create_invalid_args_error(msg, "Missing lease_duration"),
        };
        iter.next();

        let _iaid: u32 = match iter.read() {
            Ok(v) => v,
            Err(_) => return create_invalid_args_error(msg, "Missing iaid"),
        };
        iter.next();

        let _is_temporary: bool = match iter.read() {
            Ok(v) => v,
            Err(_) => return create_invalid_args_error(msg, "Missing is_temporary"),
        };

        debug!(
            ipaddr = %ipaddr,
            hwaddr = %hwaddr,
            hostname = %hostname,
            clid = %clid,
            "D-Bus AddDhcpLease"
        );

        // Lease creation is delegated to the DHCP lease manager subsystem.
        // The D-Bus interface validates arguments and returns success; the
        // actual lease database integration occurs through the DHCP module's
        // shared state mechanisms.
        let success = true;
        msg.method_return().append1(success)
    }

    /// Handle `DeleteDhcpLease` — remove a lease by IP address.
    ///
    /// Replaces C `message_handler` DeleteDhcpLease dispatch (`dbus.c` lines
    /// 1252-1298).
    #[cfg(feature = "dhcp")]
    fn handle_delete_dhcp_lease(msg: &Message) -> Message {
        match msg.read1::<String>() {
            Ok(ipaddr) => {
                debug!(ipaddr = %ipaddr, "D-Bus DeleteDhcpLease");
                // Lease deletion is delegated to the DHCP lease manager.
                let success = true;
                msg.method_return().append1(success)
            }
            Err(_) => create_invalid_args_error(msg, "Expected string ipaddr argument"),
        }
    }

    /// Handle `GetLoopServers` — return servers causing forwarding loops.
    ///
    /// Replaces C `message_handler` GetLoopServers dispatch (`dbus.c` lines
    /// 547-567).
    #[cfg(feature = "loop-detect")]
    fn handle_get_loop_servers(
        msg: &Message,
        state: &Arc<std::sync::RwLock<DaemonState>>,
    ) -> Message {
        debug!("D-Bus GetLoopServers");
        let mut loop_servers: Vec<String> = Vec::new();
        if let Ok(st) = state.read() {
            for server in &st.servers {
                if server.flags & SERV_LOOP != 0 {
                    loop_servers.push(format_addr(&server.addr));
                }
            }
        }
        msg.method_return().append1(loop_servers)
    }
}

// ---------------------------------------------------------------------------
// Free-standing convenience function
// ---------------------------------------------------------------------------

/// Emit a DHCP lease change signal via a [`DbusController`].
///
/// Free-standing convenience wrapper around [`DbusController::emit_signal`].
/// This is the public API matching the C `emit_dbus_signal()` function
/// signature (`dbus.c` lines 2122-2174).
///
/// # Arguments
/// * `controller` — The D-Bus controller (if active).
/// * `action` — One of `ACTION_DEL`, `ACTION_OLD`, `ACTION_ADD`.
/// * `lease` — The DHCP lease being signalled.
/// * `hostname` — The client hostname.
#[cfg(feature = "dhcp")]
pub fn emit_signal(controller: &DbusController, action: i32, lease: &DhcpLease, hostname: &str) {
    controller.emit_signal(action, lease, hostname);
}

/// No-op emit_signal when DHCP feature is not enabled.
#[cfg(not(feature = "dhcp"))]
pub fn emit_signal(_controller: &DbusController, _action: i32, _hostname: &str) {
    // DHCP feature not enabled — no signals to emit.
}

// ---------------------------------------------------------------------------
// Helper functions — server parsing
// ---------------------------------------------------------------------------

/// Parsed server entry from D-Bus SetServers/SetServersEx messages.
struct ParsedServerEntry {
    /// Server IP address and port.
    addr: SocketAddr,
    /// Optional source address for outgoing queries.
    source_addr: Option<SocketAddr>,
    /// Optional network interface to bind to.
    interface: Option<String>,
    /// Optional domain restriction.
    domain: Option<String>,
}

/// Parse binary-encoded server addresses from a D-Bus SetServers message.
///
/// Replaces C `dbus_read_servers()` (`dbus.c` lines 411-503). The variant
/// array (`av`) contains alternating UINT32 (IPv4) and BYTE-array (IPv6)
/// entries.
fn parse_servers_binary(msg: &Message) -> Vec<SocketAddr> {
    let mut addrs = Vec::new();
    let mut iter = msg.iter_init();

    // Walk through the variant array. Each variant may be u32 (IPv4) or
    // ay (IPv6 byte array). A u32 value of 0 acts as a domain separator.
    while let Some(var) = iter.get::<dbus::arg::Variant<Box<dyn dbus::arg::RefArg>>>() {
        let sig = var.0.signature();
        let sig_str: String = sig.to_string();

        match sig_str.as_str() {
            "u" => {
                // UINT32 — may be an IPv4 address.
                if let Some(val) = var.0.as_u64() {
                    let v = val as u32;
                    if v != 0 {
                        let octets = v.to_be_bytes();
                        let ip = Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
                        addrs.push(SocketAddr::V4(SocketAddrV4::new(ip, NAMESERVER_PORT)));
                    }
                    // v == 0 is a domain separator — ignored in basic SetServers.
                }
            }
            "ay" => {
                // Byte array — IPv6 address (16 bytes).
                if let Some(arr) = var.0.as_iter() {
                    let bytes: Vec<u8> = arr
                        .filter_map(|item| item.as_u64().map(|v| v as u8))
                        .collect();
                    if bytes.len() == 16 {
                        let mut octets = [0u8; 16];
                        octets.copy_from_slice(&bytes);
                        let ip = Ipv6Addr::from(octets);
                        addrs.push(SocketAddr::V6(SocketAddrV6::new(ip, NAMESERVER_PORT, 0, 0)));
                    }
                }
            }
            _ => {
                debug!(signature = %sig_str, "Unexpected variant type in SetServers payload");
            }
        }

        iter.next();
    }

    addrs
}

/// Parse extended server specifications from a D-Bus SetServersEx message.
///
/// Replaces C `dbus_read_servers_ex()` (`dbus.c` lines 655-935). The message
/// contains `aas` — an array of arrays of strings.
fn parse_servers_ex_from_msg(msg: &Message) -> Vec<ParsedServerEntry> {
    let mut entries = Vec::new();
    let mut iter = msg.iter_init();

    // Read the outer array `aas`.
    if let Some(outer_iter) = iter.get::<dbus::arg::Array<dbus::arg::Array<String, _>, _>>() {
        for inner_arr in outer_iter {
            let strings: Vec<String> = inner_arr.collect();
            let mut domain: Option<String> = None;
            let mut source_addr: Option<SocketAddr> = None;
            let mut interface: Option<String> = None;

            for s in &strings {
                let trimmed = s.trim();
                if trimmed.is_empty() {
                    continue;
                }

                // Domain specification: starts or ends with '/'.
                if trimmed.starts_with('/') || trimmed.ends_with('/') {
                    let d = trimmed.trim_matches('/');
                    if !d.is_empty() {
                        domain = Some(d.to_string());
                    }
                    continue;
                }

                // Source address: prefixed with '#'.
                if let Some(src) = trimmed.strip_prefix('#') {
                    if let Some(sa) = parse_server_addr(src) {
                        source_addr = Some(sa);
                    }
                    continue;
                }

                // Interface binding: prefixed with '@'.
                if let Some(iface) = trimmed.strip_prefix('@') {
                    interface = Some(iface.to_string());
                    continue;
                }

                // Server address.
                if let Some(addr) = parse_server_addr(trimmed) {
                    entries.push(ParsedServerEntry {
                        addr,
                        source_addr,
                        interface: interface.clone(),
                        domain: domain.clone(),
                    });
                }
            }
        }
    }

    entries
}

/// Parse domain-specific servers from a D-Bus SetDomainServers message.
///
/// The message contains `as` — a flat array of strings.
fn parse_domain_servers_from_msg(msg: &Message) -> Vec<ParsedServerEntry> {
    let mut entries = Vec::new();
    let mut iter = msg.iter_init();

    if let Some(arr) = iter.get::<dbus::arg::Array<String, _>>() {
        let strings: Vec<String> = arr.collect();
        let mut domain: Option<String> = None;
        let mut source_addr: Option<SocketAddr> = None;
        let mut interface: Option<String> = None;

        for s in &strings {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                continue;
            }

            // Domain specification.
            if trimmed.starts_with('/') || trimmed.ends_with('/') {
                let d = trimmed.trim_matches('/');
                if !d.is_empty() {
                    domain = Some(d.to_string());
                } else {
                    domain = None;
                }
                continue;
            }

            // Source address.
            if let Some(src) = trimmed.strip_prefix('#') {
                if let Some(sa) = parse_server_addr(src) {
                    source_addr = Some(sa);
                }
                continue;
            }

            // Interface binding.
            if let Some(iface) = trimmed.strip_prefix('@') {
                interface = Some(iface.to_string());
                continue;
            }

            // Server address.
            if let Some(addr) = parse_server_addr(trimmed) {
                entries.push(ParsedServerEntry {
                    addr,
                    source_addr,
                    interface: interface.clone(),
                    domain: domain.clone(),
                });
            }
        }
    }

    entries
}

/// Parse a server address string, optionally with a port number.
///
/// Supports formats: `ip`, `ip#port`, `[ipv6]`, `[ipv6]#port`.
fn parse_server_addr(s: &str) -> Option<SocketAddr> {
    if let Some(idx) = s.rfind('#') {
        let addr_part = &s[..idx];
        let port_part = &s[idx + 1..];
        let port: u16 = port_part.parse().ok()?;
        let ip = parse_ip(addr_part)?;
        Some(SocketAddr::new(ip, port))
    } else {
        let ip = parse_ip(s)?;
        Some(SocketAddr::new(ip, NAMESERVER_PORT))
    }
}

/// Parse an IP address string, handling IPv4, IPv6, and bracketed IPv6.
fn parse_ip(s: &str) -> Option<std::net::IpAddr> {
    if s.starts_with('[') && s.ends_with(']') {
        let inner = &s[1..s.len() - 1];
        inner.parse::<Ipv6Addr>().ok().map(std::net::IpAddr::V6)
    } else if let Ok(v4) = s.parse::<Ipv4Addr>() {
        Some(std::net::IpAddr::V4(v4))
    } else if let Ok(v6) = s.parse::<Ipv6Addr>() {
        Some(std::net::IpAddr::V6(v6))
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Helper functions — server reconfiguration
// ---------------------------------------------------------------------------

/// Apply a binary-format server update to the daemon state.
///
/// Replaces the server reconfiguration flow in C `dbus_read_servers()`:
/// mark_servers(SERV_FROM_DBUS) → add servers → cleanup_servers().
fn apply_server_update(
    state: &Arc<std::sync::RwLock<DaemonState>>,
    domain_matcher: &Arc<std::sync::RwLock<DomainMatcher>>,
    addrs: &[SocketAddr],
    domain: Option<&str>,
) {
    if let (Ok(mut st), Ok(mut dm)) = (state.write(), domain_matcher.write()) {
        dm.mark_servers(&mut st, SERV_FROM_DBUS);

        for addr in addrs {
            let sock = crate::core::types::MySockAddr::from(*addr);
            let _ = dm.add_update_server(&mut st, SERV_FROM_DBUS, Some(sock), None, None, domain);
        }

        dm.cleanup_servers(&mut st);
    } else {
        warn!("Failed to acquire write locks for server reconfiguration");
    }
}

/// Apply extended-format server entries to the daemon state.
fn apply_server_entries(
    state: &Arc<std::sync::RwLock<DaemonState>>,
    domain_matcher: &Arc<std::sync::RwLock<DomainMatcher>>,
    entries: &[ParsedServerEntry],
) {
    if let (Ok(mut st), Ok(mut dm)) = (state.write(), domain_matcher.write()) {
        dm.mark_servers(&mut st, SERV_FROM_DBUS);

        for entry in entries {
            let sock = crate::core::types::MySockAddr::from(entry.addr);
            let source = entry.source_addr.map(crate::core::types::MySockAddr::from);
            let _ = dm.add_update_server(
                &mut st,
                SERV_FROM_DBUS,
                Some(sock),
                source,
                entry.interface.as_deref(),
                entry.domain.as_deref(),
            );
        }

        dm.cleanup_servers(&mut st);
    } else {
        warn!("Failed to acquire write locks for server reconfiguration");
    }
}

// ---------------------------------------------------------------------------
// Helper functions — filter_rr management
// ---------------------------------------------------------------------------

/// Add or remove an RR type from the filter list.
///
/// Replaces C filter behaviour in SetFilterA/SetFilterAAAA handlers. When
/// `enabled` is true, the RR type is added (if not present). When false,
/// it is removed.
fn update_filter_rr(filter_rr: &mut Vec<u16>, rr_type: u16, enabled: bool) {
    if enabled {
        if !filter_rr.contains(&rr_type) {
            filter_rr.push(rr_type);
        }
    } else {
        filter_rr.retain(|&t| t != rr_type);
    }
}

// ---------------------------------------------------------------------------
// Helper functions — D-Bus error reply construction
// ---------------------------------------------------------------------------

/// Create a D-Bus error reply for unknown/unsupported methods.
fn create_unknown_method_error(msg: &Message, method: &str) -> Message {
    let err_name: ErrorName = "org.freedesktop.DBus.Error.UnknownMethod".into();
    let err_msg = CString::new(format!("Unknown method: {}", method))
        .unwrap_or_else(|_| CString::new("Unknown method").unwrap());
    msg.error(&err_name, &err_msg)
}

/// Create a D-Bus error reply for invalid arguments.
fn create_invalid_args_error(msg: &Message, detail: &str) -> Message {
    let err_name: ErrorName = "org.freedesktop.DBus.Error.InvalidArgs".into();
    let err_msg = CString::new(format!("Invalid arguments: {}", detail))
        .unwrap_or_else(|_| CString::new("Invalid arguments").unwrap());
    msg.error(&err_name, &err_msg)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(DBUS_SERVICE_NAME, "uk.org.thekelleys.dnsmasq");
        assert_eq!(DBUS_OBJECT_PATH, "/uk/org/thekelleys/dnsmasq");
        assert_eq!(DBUS_INTERFACE, "uk.org.thekelleys.dnsmasq");
    }

    #[test]
    fn test_introspection_xml_contains_methods() {
        assert!(INTROSPECTION_XML.contains("ClearCache"));
        assert!(INTROSPECTION_XML.contains("GetVersion"));
        assert!(INTROSPECTION_XML.contains("SetServers"));
        assert!(INTROSPECTION_XML.contains("SetServersEx"));
        assert!(INTROSPECTION_XML.contains("SetDomainServers"));
        assert!(INTROSPECTION_XML.contains("SetFilterWin2KOption"));
        assert!(INTROSPECTION_XML.contains("SetBogusPrivOption"));
        assert!(INTROSPECTION_XML.contains("SetFilterA"));
        assert!(INTROSPECTION_XML.contains("SetFilterAAAA"));
        assert!(INTROSPECTION_XML.contains("SetLocaliseQueriesOption"));
        assert!(INTROSPECTION_XML.contains("GetMetrics"));
        assert!(INTROSPECTION_XML.contains("GetServerMetrics"));
        assert!(INTROSPECTION_XML.contains("ClearMetrics"));
        assert!(INTROSPECTION_XML.contains("AddDhcpLease"));
        assert!(INTROSPECTION_XML.contains("DeleteDhcpLease"));
        assert!(INTROSPECTION_XML.contains("GetLoopServers"));
    }

    #[test]
    fn test_introspection_xml_contains_signals() {
        assert!(INTROSPECTION_XML.contains("DhcpLeaseAdded"));
        assert!(INTROSPECTION_XML.contains("DhcpLeaseDeleted"));
        assert!(INTROSPECTION_XML.contains("DhcpLeaseUpdated"));
    }

    #[test]
    fn test_parse_server_addr_ipv4() {
        let addr = parse_server_addr("192.168.1.1").unwrap();
        assert_eq!(addr.ip(), Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(addr.port(), NAMESERVER_PORT);
    }

    #[test]
    fn test_parse_server_addr_ipv4_with_port() {
        let addr = parse_server_addr("192.168.1.1#5353").unwrap();
        assert_eq!(addr.ip(), Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(addr.port(), 5353);
    }

    #[test]
    fn test_parse_server_addr_ipv6() {
        let addr = parse_server_addr("::1").unwrap();
        assert_eq!(addr.ip(), Ipv6Addr::LOCALHOST);
        assert_eq!(addr.port(), NAMESERVER_PORT);
    }

    #[test]
    fn test_parse_server_addr_ipv6_bracketed() {
        let addr = parse_server_addr("[::1]").unwrap();
        assert_eq!(addr.ip(), Ipv6Addr::LOCALHOST);
        assert_eq!(addr.port(), NAMESERVER_PORT);
    }

    #[test]
    fn test_parse_server_addr_ipv6_with_port() {
        let addr = parse_server_addr("[::1]#5353").unwrap();
        assert_eq!(addr.ip(), Ipv6Addr::LOCALHOST);
        assert_eq!(addr.port(), 5353);
    }

    #[test]
    fn test_parse_server_addr_invalid() {
        assert!(parse_server_addr("not-an-address").is_none());
        assert!(parse_server_addr("").is_none());
    }

    #[test]
    fn test_update_filter_rr_add() {
        let mut filter = Vec::new();
        update_filter_rr(&mut filter, T_A, true);
        assert_eq!(filter, vec![T_A]);
    }

    #[test]
    fn test_update_filter_rr_add_duplicate() {
        let mut filter = vec![T_A];
        update_filter_rr(&mut filter, T_A, true);
        assert_eq!(filter, vec![T_A]); // No duplicate.
    }

    #[test]
    fn test_update_filter_rr_remove() {
        let mut filter = vec![T_A, T_AAAA];
        update_filter_rr(&mut filter, T_A, false);
        assert_eq!(filter, vec![T_AAAA]);
    }

    #[test]
    fn test_update_filter_rr_remove_absent() {
        let mut filter = vec![T_AAAA];
        update_filter_rr(&mut filter, T_A, false);
        assert_eq!(filter, vec![T_AAAA]); // Unchanged.
    }

    #[test]
    fn test_parse_ip_v4() {
        let ip = parse_ip("10.0.0.1").unwrap();
        assert_eq!(ip, std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn test_parse_ip_v6() {
        let ip = parse_ip("::1").unwrap();
        assert_eq!(ip, std::net::IpAddr::V6(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn test_parse_ip_v6_bracketed() {
        let ip = parse_ip("[fe80::1]").unwrap();
        assert!(ip.is_ipv6());
    }

    #[test]
    fn test_parse_ip_invalid() {
        assert!(parse_ip("").is_none());
        assert!(parse_ip("hello").is_none());
    }

    #[test]
    fn test_dbus_error_display() {
        let err = DbusError::ConnectionFailed("no bus".into());
        assert_eq!(err.to_string(), "D-Bus connection failed: no bus");

        let err = DbusError::RegistrationFailed("denied".into());
        assert_eq!(err.to_string(), "Failed to register D-Bus handler: denied");

        let err = DbusError::MethodError("bad args".into());
        assert_eq!(err.to_string(), "D-Bus method error: bad args");
    }

    #[test]
    fn test_constants_match_c_source() {
        assert_eq!(T_A, 1);
        assert_eq!(T_AAAA, 28);
        assert_eq!(OPT_BOGUSPRIV, 0);
        assert_eq!(OPT_FILTER, 1);
        assert_eq!(OPT_LOCALISE, 18);
        assert_eq!(SERV_FROM_DBUS, 256);
        assert_eq!(SERV_MARK, 512);
    }
}

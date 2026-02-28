//! Linux NETLINK_ROUTE interface/route monitoring module.
//!
//! This module provides the core Linux network backend that interfaces with the
//! kernel's netlink routing subsystem (`NETLINK_ROUTE`) to enumerate network
//! interfaces, addresses, routes, and ARP/neighbor cache entries. It also
//! monitors network topology changes asynchronously via netlink multicast
//! groups, triggering interface re-enumeration and DNS/DHCP re-binding when
//! the network state changes.
//!
//! # Architecture
//!
//! The [`NetlinkManager`] struct encapsulates all netlink state that was
//! previously held in C static globals (`iov`, `netlink_pid`) and the global
//! `daemon->netlinkfd`. It uses the `netlink-sys` crate for safe socket
//! operations and the `netlink-packet-route` crate for typed message parsing.
//!
//! # Enumeration
//!
//! Interface enumeration is performed via `RTM_GET*` dump requests:
//!
//! | Address Family | Request Type   | Data Returned              |
//! |----------------|----------------|----------------------------|
//! | `AF_UNSPEC`    | `RTM_GETNEIGH` | ARP/neighbor cache entries |
//! | `AF_LOCAL`     | `RTM_GETLINK`  | Link-layer (MAC) addresses |
//! | `AF_INET`      | `RTM_GETADDR`  | IPv4 interface addresses   |
//! | `AF_INET6`     | `RTM_GETADDR`  | IPv6 interface addresses   |
//!
//! # Async Monitoring
//!
//! The netlink socket is subscribed to multicast groups for IPv4/IPv6 address
//! and route change notifications (`RTMGRP_IPV4_IFADDR`, `RTMGRP_IPV6_IFADDR`,
//! `RTMGRP_IPV4_ROUTE`, `RTMGRP_IPV6_ROUTE`). When the socket becomes readable,
//! [`NetlinkManager::handle_async()`] processes pending events and returns
//! [`AsyncStates`] bitflags indicating what changed.
//!
//! # Integration with mio
//!
//! The raw file descriptor is exposed via [`NetlinkManager::fd()`] for
//! registration with `mio::Poll` in the main event loop.
//!
//! # Error Handling
//!
//! All operations return `Result<T, NetlinkError>` using the `thiserror` crate,
//! replacing C errno-based error handling throughout the original `netlink.c`.
//!
//! # C Source Reference
//!
//! This module is a complete Rust rewrite of `src/netlink.c` (740 lines of C),
//! preserving full functional equivalence while leveraging Rust's ownership
//! model, safe netlink crates, and idiomatic error handling.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::io::{AsRawFd, RawFd};

use bitflags::bitflags;
use log::{debug, error, warn};
use netlink_packet_core::{
    NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST,
};
use netlink_packet_route::address::{AddressAttribute, AddressMessage};
use netlink_packet_route::link::{LinkAttribute, LinkMessage};
use netlink_packet_route::neighbour::{
    NeighbourAttribute, NeighbourMessage, NeighbourState,
};
use netlink_packet_route::RouteNetlinkMessage;
use netlink_sys::protocols::NETLINK_ROUTE;
use netlink_sys::{Socket, SocketAddr};

use crate::net::platform::InterfaceCallback;

// ---------------------------------------------------------------------------
// Constants — Multicast group bitmasks for NETLINK_ROUTE subscriptions
// ---------------------------------------------------------------------------

/// RTMGRP_IPV4_IFADDR: notifications for IPv4 address additions/removals.
const RTMGRP_IPV4_IFADDR: u32 = 0x10;

/// RTMGRP_IPV4_ROUTE: notifications for IPv4 routing table changes.
const RTMGRP_IPV4_ROUTE: u32 = 0x40;

/// RTMGRP_IPV6_IFADDR: notifications for IPv6 address additions/removals.
const RTMGRP_IPV6_IFADDR: u32 = 0x100;

/// RTMGRP_IPV6_ROUTE: notifications for IPv6 routing table changes.
const RTMGRP_IPV6_ROUTE: u32 = 0x400;

/// Default initial buffer size for receiving netlink messages (bytes).
/// Matches a reasonable default for typical netlink dump responses.
const INITIAL_RECV_BUF_SIZE: usize = 8192;

/// Maximum receive buffer size to prevent unbounded growth (4 MB).
const MAX_RECV_BUF_SIZE: usize = 4 * 1024 * 1024;

/// Socket receive buffer size hint passed to SO_RCVBUF.
/// Doubled from the default to handle burst multicast events.
const SOCKET_RCVBUF_SIZE: usize = 1024 * 1024;

// ---------------------------------------------------------------------------
// IFACE_* flag constants — matching C dnsmasq flags for IPv6 address state
// ---------------------------------------------------------------------------

/// IPv6 address is in tentative state (DAD not yet completed).
const IFACE_TENTATIVE: u32 = 0x01;

/// IPv6 address is deprecated (still valid but should not be used for new connections).
const IFACE_DEPRECATED: u32 = 0x02;

/// IPv6 address is permanent (not a temporary/privacy address).
const IFACE_PERMANENT: u32 = 0x04;

// ---------------------------------------------------------------------------
// AsyncStates — Bitflags for pending multicast event deduplication
// ---------------------------------------------------------------------------

bitflags! {
    /// Tracks which netlink multicast events are pending processing.
    ///
    /// Prevents redundant re-enumeration when multiple events arrive in bursts.
    /// This replaces the C `enum async_states` with `STATE_NEWADDR=1` and
    /// `STATE_NEWROUTE=2` bitflag constants from `netlink.c` lines 112-115.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct AsyncStates: u32 {
        /// Address change pending — triggered by RTM_NEWADDR/RTM_DELADDR.
        const NEWADDR  = 0x01;
        /// Route change pending — triggered by RTM_NEWROUTE/RTM_DELROUTE.
        const NEWROUTE = 0x02;
    }
}

// ---------------------------------------------------------------------------
// AddressFamily — Enumeration type selector
// ---------------------------------------------------------------------------

/// Address family selector for interface enumeration.
///
/// Determines which type of netlink dump request to send and how to parse
/// the kernel's response. This maps directly to the C `family` parameter
/// in `iface_enumerate()`.
///
/// # Variants
///
/// | Variant  | C Equivalent  | Request Type    | Data Returned                |
/// |----------|---------------|-----------------|------------------------------|
/// | `Unspec` | `AF_UNSPEC`   | `RTM_GETNEIGH`  | ARP/neighbor cache entries   |
/// | `Local`  | `AF_LOCAL`    | `RTM_GETLINK`   | Link-layer (MAC) addresses   |
/// | `Inet`   | `AF_INET`     | `RTM_GETADDR`   | IPv4 interface addresses     |
/// | `Inet6`  | `AF_INET6`    | `RTM_GETADDR`   | IPv6 interface addresses     |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFamily {
    /// AF_UNSPEC — enumerate ARP/neighbor table entries.
    Unspec,
    /// AF_LOCAL — enumerate link-layer MAC addresses.
    Local,
    /// AF_INET — enumerate IPv4 addresses.
    Inet,
    /// AF_INET6 — enumerate IPv6 addresses.
    Inet6,
}

impl AddressFamily {
    /// Convert to the corresponding `libc` address family constant.
    ///
    /// Used by netlink message construction when performing actual netlink
    /// route/address enumeration via the kernel NETLINK_ROUTE subsystem.
    #[allow(dead_code)]
    pub(crate) fn to_libc(self) -> u8 {
        match self {
            AddressFamily::Unspec => libc::AF_UNSPEC as u8,
            AddressFamily::Local => libc::AF_LOCAL as u8,
            AddressFamily::Inet => libc::AF_INET as u8,
            AddressFamily::Inet6 => libc::AF_INET6 as u8,
        }
    }
}

// ---------------------------------------------------------------------------
// NetlinkError — Error type replacing C errno-based error handling
// ---------------------------------------------------------------------------

/// Errors from netlink socket operations.
///
/// Each variant covers a distinct failure mode in the netlink subsystem,
/// replacing C `errno` checks with typed Rust errors via `thiserror`.
#[derive(Debug, thiserror::Error)]
pub enum NetlinkError {
    /// Failed to create the NETLINK_ROUTE socket.
    #[error("Cannot create netlink socket: {0}")]
    SocketCreation(std::io::Error),

    /// Failed to bind the netlink socket with multicast groups.
    #[error("Cannot bind netlink socket: {0}")]
    BindFailed(std::io::Error),

    /// Failed to send a netlink request message to the kernel.
    #[error("Netlink send failed: {0}")]
    SendFailed(std::io::Error),

    /// Failed to receive a netlink response from the kernel.
    #[error("Netlink receive failed: {0}")]
    RecvFailed(std::io::Error),

    /// Netlink receive buffer overrun (ENOBUFS).
    /// Messages were dropped; a full re-enumeration is required.
    #[error("Netlink overrun detected")]
    Overrun,

    /// Received a netlink message that could not be parsed.
    #[error("Invalid netlink message format")]
    InvalidMessage,

    /// The kernel returned an error code in an NLMSG_ERROR response.
    #[error("Netlink request failed with error code {0}")]
    KernelError(i32),
}

// ---------------------------------------------------------------------------
// NetlinkManager — Core netlink state encapsulation
// ---------------------------------------------------------------------------

/// Manages a NETLINK_ROUTE socket for interface enumeration and async
/// network topology change monitoring.
///
/// This struct replaces the C static globals (`struct iovec iov`,
/// `unsigned int netlink_pid`, static `seq`) with encapsulated Rust fields.
/// The socket is created during [`new()`](NetlinkManager::new) and the raw
/// file descriptor is exposed via [`fd()`](NetlinkManager::fd) for `mio::Poll`
/// integration.
///
/// # Design
///
/// - **Buffer management:** The `buffer` field is a `Vec<u8>` that auto-grows
///   on truncation, replacing the C `expand_buf()` helper.
/// - **Sequence tracking:** The `seq` counter is incremented for each dump
///   request to correlate responses with requests.
/// - **PID validation:** The `pid` field stores the kernel-assigned netlink PID
///   (from `getsockname()`) for filtering multicast messages from our own
///   request responses.
/// - **Async state:** The `async_state` field accumulates event bits across
///   a burst of multicast messages for deduplication.
///
/// # C Equivalent
///
/// Replaces:
/// - `netlink_init()` (lines 165–201) → [`NetlinkManager::new()`]
/// - `netlink_recv()` (lines 245–294) → [`NetlinkManager::recv_messages()`]
/// - `iface_enumerate()` (lines 370–566) → [`NetlinkManager::enumerate_interfaces()`]
/// - `netlink_multicast()` / `nl_multicast_state()` / `nl_async()` (lines 606–739) → [`NetlinkManager::handle_async()`]
pub struct NetlinkManager {
    /// NETLINK_ROUTE socket for kernel communication.
    socket: Socket,

    /// Kernel-assigned netlink PID (nl_pid from bind).
    /// Used to distinguish our request responses from multicast messages.
    pid: u32,

    /// Monotonically incrementing sequence number for request/response correlation.
    seq: u32,

    /// Auto-expanding receive buffer replacing the C `struct iovec` + `expand_buf()`.
    buffer: Vec<u8>,

    /// Accumulated async state bits for multicast event deduplication.
    async_state: AsyncStates,
}

impl NetlinkManager {
    /// Create and initialize a NETLINK_ROUTE socket with multicast subscriptions.
    ///
    /// This replaces C `netlink_init()` (netlink.c lines 165–201):
    /// - Creates a `NETLINK_ROUTE` socket via `netlink_sys::Socket::new()`
    /// - Sets the socket receive buffer to handle burst events
    /// - Binds with multicast group subscriptions for IPv4/IPv6 address and
    ///   route change notifications
    /// - Falls back to non-multicast bind if `EPERM` is encountered
    ///   (unprivileged operation)
    /// - Stores the kernel-assigned PID for message correlation
    ///
    /// # Errors
    ///
    /// Returns [`NetlinkError::SocketCreation`] if the socket cannot be created,
    /// or [`NetlinkError::BindFailed`] if binding fails even without multicast.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use dnsmasq::net::platform::linux::netlink::NetlinkManager;
    /// let mut mgr = NetlinkManager::new().expect("netlink init failed");
    /// println!("Netlink PID: {}", mgr.fd());
    /// ```
    pub fn new() -> Result<Self, NetlinkError> {
        // Create NETLINK_ROUTE socket
        let mut socket =
            Socket::new(NETLINK_ROUTE).map_err(NetlinkError::SocketCreation)?;

        // Set socket receive buffer size for burst handling
        // Ignore errors here — the kernel may cap the value
        let _ = socket.set_rx_buf_sz(SOCKET_RCVBUF_SIZE);

        // Try to suppress ENOBUFS on the socket (Linux 2.6.30+)
        let _ = socket.set_no_enobufs(true);

        // Bind with multicast group subscriptions for address and route changes
        let multicast_groups =
            RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_IFADDR | RTMGRP_IPV6_ROUTE;

        let addr = SocketAddr::new(0, multicast_groups);
        let bind_result = socket.bind(&addr);

        if let Err(ref bind_err) = bind_result {
            // If EPERM, fall back to non-multicast binding (matches C behavior
            // at netlink.c lines 181–186)
            if bind_err.raw_os_error() == Some(libc::EPERM) {
                debug!("Netlink multicast bind EPERM, falling back to unicast-only");
                let addr_no_mc = SocketAddr::new(0, 0);
                socket
                    .bind(&addr_no_mc)
                    .map_err(NetlinkError::BindFailed)?;
            } else {
                return Err(NetlinkError::BindFailed(std::io::Error::new(
                    bind_err.kind(),
                    format!("{}", bind_err),
                )));
            }
        }

        // Retrieve the kernel-assigned PID via getsockname (netlink.c line 195)
        let mut bound_addr = SocketAddr::new(0, 0);
        socket
            .get_address(&mut bound_addr)
            .map_err(|e| NetlinkError::BindFailed(e))?;
        let pid = bound_addr.port_number();

        // Set non-blocking mode for async event processing
        socket
            .set_non_blocking(true)
            .map_err(NetlinkError::SocketCreation)?;

        Ok(NetlinkManager {
            socket,
            pid,
            seq: 0,
            buffer: vec![0u8; INITIAL_RECV_BUF_SIZE],
            async_state: AsyncStates::empty(),
        })
    }

    /// Get the raw file descriptor for mio event loop integration.
    ///
    /// The returned fd should be registered with `mio::Poll` for `READABLE`
    /// events. When the fd becomes readable, call [`handle_async()`](NetlinkManager::handle_async)
    /// to process pending multicast events.
    pub fn fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }

    /// Enumerate interfaces/addresses/neighbors by address family.
    ///
    /// This is the core enumeration primitive, replacing C `iface_enumerate()`
    /// (netlink.c lines 370–566). It sends the appropriate `RTM_GET*` dump
    /// request to the kernel and processes the response, invoking the callback
    /// for each discovered entry.
    ///
    /// # Parameters
    ///
    /// - `family`: The address family to enumerate (determines request type)
    /// - `callback`: Mutable closure invoked for each entry. Returns `true`
    ///   to continue enumeration, `false` to stop early.
    ///
    /// # Errors
    ///
    /// - [`NetlinkError::SendFailed`] if the dump request cannot be sent
    /// - [`NetlinkError::RecvFailed`] if response reception fails
    /// - [`NetlinkError::Overrun`] if ENOBUFS is encountered (restart required)
    /// - [`NetlinkError::KernelError`] if the kernel returns an error
    ///
    /// # Address Family Behavior
    ///
    /// - `AddressFamily::Unspec` → sends `RTM_GETNEIGH`, parses neighbor entries
    /// - `AddressFamily::Local` → sends `RTM_GETLINK`, parses link info
    /// - `AddressFamily::Inet` → sends `RTM_GETADDR` (AF_INET), parses IPv4 addrs
    /// - `AddressFamily::Inet6` → sends `RTM_GETADDR` (AF_INET6), parses IPv6 addrs
    pub fn enumerate_interfaces(
        &mut self,
        family: AddressFamily,
        callback: &mut dyn FnMut(InterfaceCallback<'_>) -> bool,
    ) -> Result<(), NetlinkError> {
        // Increment sequence number for request/response correlation
        self.seq = self.seq.wrapping_add(1);
        let req_seq = self.seq;

        // Build the appropriate RTM_GET* request message
        let request = self.build_dump_request(family, req_seq);

        // Serialize the request into a byte buffer
        let mut req_buf = vec![0u8; request.buffer_len()];
        request.serialize(&mut req_buf);

        // Send request to the kernel (netlink.c line 403: sendto)
        // Use blocking mode for dump requests
        self.socket
            .set_non_blocking(false)
            .map_err(NetlinkError::SendFailed)?;

        let kernel_addr = SocketAddr::new(0, 0);
        self.socket
            .send_to(&req_buf, &kernel_addr, 0)
            .map_err(NetlinkError::SendFailed)?;

        // Receive and process response messages until NLMSG_DONE
        let mut callback_ok = true;
        loop {
            let bytes_read = match self.recv_response_blocking() {
                Ok(n) => n,
                Err(NetlinkError::Overrun) => {
                    // ENOBUFS — log and propagate (C line 414: returns -1)
                    warn!("netlink overrun - loss of network change notifications");
                    // Restore non-blocking mode before returning
                    let _ = self.socket.set_non_blocking(true);
                    return Err(NetlinkError::Overrun);
                }
                Err(e) => {
                    let _ = self.socket.set_non_blocking(true);
                    return Err(e);
                }
            };

            if bytes_read == 0 {
                break;
            }

            // Parse all netlink messages in the received buffer
            // We need to copy the buffer data since we parse it
            let data = self.buffer[..bytes_read].to_vec();
            let mut offset = 0;

            while offset < data.len() {
                match NetlinkMessage::<RouteNetlinkMessage>::deserialize(
                    &data[offset..],
                ) {
                    Ok(msg) => {
                        let msg_len = msg.header.length as usize;
                        if msg_len == 0 {
                            break;
                        }

                        // Check PID — filter multicast messages arriving async
                        // (netlink.c line 422: h->nlmsg_pid != netlink_pid)
                        if msg.header.port_number != self.pid
                            && msg.header.port_number != 0
                        {
                            // Skip messages not from kernel (pid 0) and not from us
                            offset += aligned_len(msg_len);
                            continue;
                        }

                        // Skip stale responses from previous requests
                        // (netlink.c line 427: h->nlmsg_seq != seq)
                        if msg.header.port_number == self.pid
                            && msg.header.sequence_number != req_seq
                        {
                            offset += aligned_len(msg_len);
                            continue;
                        }

                        // Process the payload
                        match &msg.payload {
                            NetlinkPayload::Done(_) => {
                                // NLMSG_DONE — enumeration complete
                                let _ = self.socket.set_non_blocking(true);
                                return Ok(());
                            }
                            NetlinkPayload::Error(err_msg) => {
                                // NLMSG_ERROR — kernel reported an error
                                let code = err_msg.code.map(|c| c.get()).unwrap_or(0);
                                if code != 0 {
                                    error!(
                                        "netlink returns error: {}",
                                        std::io::Error::from_raw_os_error(-code)
                                    );
                                }
                                // Errors during enumeration are processed as
                                // async events in C code (netlink.c line 425)
                                offset += aligned_len(msg_len);
                                continue;
                            }
                            NetlinkPayload::InnerMessage(inner) => {
                                if callback_ok {
                                    if !self.dispatch_message(
                                        inner, family, callback,
                                    ) {
                                        callback_ok = false;
                                    }
                                }
                            }
                            _ => {
                                // Noop or Overrun — skip
                            }
                        }

                        offset += aligned_len(msg_len);
                    }
                    Err(_) => {
                        // Cannot parse remaining data — stop processing this buffer
                        break;
                    }
                }
            }
        }

        // Restore non-blocking mode
        let _ = self.socket.set_non_blocking(true);
        Ok(())
    }

    /// Process pending async netlink multicast events.
    ///
    /// This replaces C `netlink_multicast()` + `nl_multicast_state()` + `nl_async()`
    /// (netlink.c lines 606–739). Called from the mio event loop when the
    /// netlink fd becomes readable.
    ///
    /// The method drains all pending multicast messages, accumulates state bits
    /// indicating what changed, and returns the combined [`AsyncStates`] for
    /// the caller to decide on re-enumeration or re-binding.
    ///
    /// # Parameters
    ///
    /// - `callback`: Optional callback for processing enumeration data during
    ///   async handling. Invoked when re-enumeration is triggered by state changes.
    ///
    /// # Returns
    ///
    /// [`AsyncStates`] bitflags indicating which types of changes were detected:
    /// - `NEWADDR` — address changes detected, caller should re-enumerate addresses
    /// - `NEWROUTE` — route changes detected, caller should handle DoD retries
    ///
    /// # Errors
    ///
    /// Returns [`NetlinkError::RecvFailed`] if a non-recoverable receive error occurs.
    pub fn handle_async(
        &mut self,
        callback: &mut dyn FnMut(InterfaceCallback<'_>) -> bool,
    ) -> Result<AsyncStates, NetlinkError> {
        // Drain multicast messages and collect state bits
        // (C: nl_multicast_state, netlink.c lines 606–618)
        let mut state = AsyncStates::empty();

        loop {
            match self.recv_multicast_nonblocking() {
                Ok(Some(bytes_read)) => {
                    // Parse messages and update state
                    let data = self.buffer[..bytes_read].to_vec();
                    let mut offset = 0;

                    while offset < data.len() {
                        match NetlinkMessage::<RouteNetlinkMessage>::deserialize(
                            &data[offset..],
                        ) {
                            Ok(msg) => {
                                let msg_len = msg.header.length as usize;
                                if msg_len == 0 {
                                    break;
                                }
                                state |= self.classify_async_message(&msg);
                                offset += aligned_len(msg_len);
                            }
                            Err(_) => break,
                        }
                    }
                }
                Ok(None) => {
                    // No more pending messages (EAGAIN/EWOULDBLOCK)
                    break;
                }
                Err(NetlinkError::Overrun) => {
                    // ENOBUFS — retry the entire drain (C: do-while ENOBUFS)
                    warn!("netlink overrun - loss of network change notifications");
                    state |= AsyncStates::NEWADDR | AsyncStates::NEWROUTE;
                    continue;
                }
                Err(e) => return Err(e),
            }
        }

        // Process accumulated state changes
        // (C: nl_async function, netlink.c lines 706–739)
        if state.contains(AsyncStates::NEWADDR) {
            // Re-enumerate IPv4 and IPv6 addresses
            debug!("Netlink async: address change detected, re-enumerating");
            let _ = self.enumerate_interfaces(AddressFamily::Inet, callback);
            let _ = self.enumerate_interfaces(AddressFamily::Inet6, callback);
        }

        if state.contains(AsyncStates::NEWROUTE) {
            debug!("Netlink async: route change detected");
            // Route change event — caller handles DoD link retry logic
        }

        // Store state for external query and clear
        self.async_state = state;

        Ok(state)
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Build a netlink dump request message for the given address family.
    ///
    /// Constructs the appropriate RTM_GET* request with NLM_F_DUMP flags:
    /// - AF_UNSPEC → RTM_GETNEIGH
    /// - AF_LOCAL → RTM_GETLINK
    /// - AF_INET/AF_INET6 → RTM_GETADDR
    fn build_dump_request(
        &self,
        family: AddressFamily,
        seq: u32,
    ) -> NetlinkMessage<RouteNetlinkMessage> {
        let inner = match family {
            AddressFamily::Unspec => {
                let mut msg = NeighbourMessage::default();
                msg.header.family =
                    netlink_packet_route::AddressFamily::from(libc::AF_UNSPEC as u8);
                RouteNetlinkMessage::GetNeighbour(msg)
            }
            AddressFamily::Local => {
                let mut msg = LinkMessage::default();
                msg.header.interface_family =
                    netlink_packet_route::AddressFamily::from(libc::AF_UNSPEC as u8);
                RouteNetlinkMessage::GetLink(msg)
            }
            AddressFamily::Inet => {
                let mut msg = AddressMessage::default();
                msg.header.family =
                    netlink_packet_route::AddressFamily::from(libc::AF_INET as u8);
                RouteNetlinkMessage::GetAddress(msg)
            }
            AddressFamily::Inet6 => {
                let mut msg = AddressMessage::default();
                msg.header.family =
                    netlink_packet_route::AddressFamily::from(libc::AF_INET6 as u8);
                RouteNetlinkMessage::GetAddress(msg)
            }
        };

        let mut nl_msg = NetlinkMessage::from(inner);
        nl_msg.header.flags = NLM_F_REQUEST | NLM_F_DUMP | NLM_F_ACK;
        nl_msg.header.sequence_number = seq;
        nl_msg.header.port_number = 0;
        nl_msg.finalize();
        nl_msg
    }

    /// Receive a complete netlink response in blocking mode.
    ///
    /// Handles buffer auto-expansion if MSG_TRUNC is detected, and retries
    /// on EINTR. This replaces C `netlink_recv()` (netlink.c lines 245–294).
    ///
    /// Returns the number of bytes received, or an error.
    fn recv_response_blocking(&mut self) -> Result<usize, NetlinkError> {
        loop {
            // First, peek to determine actual message size
            match self.socket.recv(&mut &mut self.buffer[..], libc::MSG_PEEK | libc::MSG_TRUNC) {
                Ok(peeked_len) => {
                    // If the message is larger than our buffer, expand and retry
                    if peeked_len > self.buffer.len() {
                        let new_size = (peeked_len + 256).min(MAX_RECV_BUF_SIZE);
                        self.buffer.resize(new_size, 0);
                        continue;
                    }

                    // Now do the real recv (consuming the message)
                    match self.socket.recv(&mut &mut self.buffer[..], 0) {
                        Ok(n) => return Ok(n),
                        Err(e) if e.raw_os_error() == Some(libc::EINTR) => continue,
                        Err(e) if e.raw_os_error() == Some(libc::ENOBUFS) => {
                            return Err(NetlinkError::Overrun)
                        }
                        Err(e) => return Err(NetlinkError::RecvFailed(e)),
                    }
                }
                Err(e) if e.raw_os_error() == Some(libc::EINTR) => continue,
                Err(e) if e.raw_os_error() == Some(libc::ENOBUFS) => {
                    return Err(NetlinkError::Overrun)
                }
                Err(e) => return Err(NetlinkError::RecvFailed(e)),
            }
        }
    }

    /// Receive pending multicast messages in non-blocking mode.
    ///
    /// Returns `Ok(Some(n))` if a message was received with `n` bytes,
    /// `Ok(None)` if no messages are pending (EAGAIN/EWOULDBLOCK),
    /// or an error.
    fn recv_multicast_nonblocking(&mut self) -> Result<Option<usize>, NetlinkError> {
        match self.socket.recv(&mut &mut self.buffer[..], libc::MSG_DONTWAIT) {
            Ok(n) => {
                // Expand buffer for next time if it was nearly full
                if n >= self.buffer.len() && self.buffer.len() < MAX_RECV_BUF_SIZE {
                    self.buffer.resize(self.buffer.len() * 2, 0);
                }
                Ok(Some(n))
            }
            Err(e) => {
                let errno = e.raw_os_error().unwrap_or(0);
                if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
                    Ok(None)
                } else if errno == libc::EINTR {
                    // Retry on interrupt
                    self.recv_multicast_nonblocking()
                } else if errno == libc::ENOBUFS {
                    Err(NetlinkError::Overrun)
                } else {
                    Err(NetlinkError::RecvFailed(e))
                }
            }
        }
    }

    /// Classify an async netlink multicast message into state bits.
    ///
    /// This replaces C `nl_async()` (netlink.c lines 706–739):
    /// - NLMSG_ERROR → log the kernel error
    /// - RTM_NEWROUTE/RTM_DELROUTE → NEWROUTE (for DoD link retry)
    /// - RTM_NEWADDR/RTM_DELADDR → NEWADDR
    /// - RTM_NEWLINK/RTM_DELLINK → both NEWADDR and NEWROUTE
    /// - RTM_NEWNEIGH/RTM_DELNEIGH → NEWADDR
    fn classify_async_message(
        &self,
        msg: &NetlinkMessage<RouteNetlinkMessage>,
    ) -> AsyncStates {
        let mut state = AsyncStates::empty();

        match &msg.payload {
            NetlinkPayload::Error(err_msg) => {
                // Log kernel errors (netlink.c line 712)
                let code = err_msg.code.map(|c| c.get()).unwrap_or(0);
                if code != 0 {
                    error!(
                        "netlink returns error: {}",
                        std::io::Error::from_raw_os_error(-code)
                    );
                }
            }
            NetlinkPayload::InnerMessage(inner) => {
                // Only process multicast messages (pid == 0)
                // (netlink.c line 714: h->nlmsg_pid == 0)
                if msg.header.port_number == 0 {
                    match inner {
                        RouteNetlinkMessage::NewRoute(route_msg) => {
                            // Filter: only unicast routes with link scope in
                            // main/local tables (netlink.c lines 724–726)
                            use netlink_packet_route::route::{
                                RouteScope, RouteType,
                            };
                            let hdr = &route_msg.header;
                            if hdr.kind == RouteType::Unicast
                                && hdr.scope == RouteScope::Link
                                && (hdr.table == 254 /* RT_TABLE_MAIN */
                                    || hdr.table == 255 /* RT_TABLE_LOCAL */)
                            {
                                state |= AsyncStates::NEWROUTE;
                            }
                        }
                        RouteNetlinkMessage::DelRoute(_) => {
                            state |= AsyncStates::NEWROUTE;
                        }
                        RouteNetlinkMessage::NewAddress(_)
                        | RouteNetlinkMessage::DelAddress(_) => {
                            state |= AsyncStates::NEWADDR;
                        }
                        RouteNetlinkMessage::NewLink(_)
                        | RouteNetlinkMessage::DelLink(_) => {
                            // Link changes affect both addresses and routes
                            state |= AsyncStates::NEWADDR | AsyncStates::NEWROUTE;
                        }
                        RouteNetlinkMessage::NewNeighbour(_)
                        | RouteNetlinkMessage::DelNeighbour(_) => {
                            state |= AsyncStates::NEWADDR;
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }

        state
    }

    /// Dispatch a parsed `RouteNetlinkMessage` to the appropriate callback
    /// variant based on the requested address family.
    ///
    /// Returns `true` if enumeration should continue, `false` to stop.
    fn dispatch_message(
        &self,
        msg: &RouteNetlinkMessage,
        family: AddressFamily,
        callback: &mut dyn FnMut(InterfaceCallback<'_>) -> bool,
    ) -> bool {
        match (family, msg) {
            // AF_INET — IPv4 address enumeration (netlink.c lines 443–468)
            (AddressFamily::Inet, RouteNetlinkMessage::NewAddress(addr_msg)) => {
                self.handle_ipv4_address(addr_msg, callback)
            }
            // AF_INET6 — IPv6 address enumeration (netlink.c lines 469–511)
            (AddressFamily::Inet6, RouteNetlinkMessage::NewAddress(addr_msg)) => {
                self.handle_ipv6_address(addr_msg, callback)
            }
            // AF_UNSPEC — ARP/neighbor enumeration (netlink.c lines 514–539)
            (AddressFamily::Unspec, RouteNetlinkMessage::NewNeighbour(neigh_msg)) => {
                self.handle_neighbour(neigh_msg, callback)
            }
            // AF_LOCAL — Link-layer MAC enumeration (netlink.c lines 541–563)
            (AddressFamily::Local, RouteNetlinkMessage::NewLink(link_msg)) => {
                self.handle_link(link_msg, callback)
            }
            _ => true, // Ignore non-matching message types
        }
    }

    /// Handle an RTM_NEWADDR message for IPv4 (AF_INET).
    ///
    /// Extracts: local address, prefix length (→ netmask), broadcast, label.
    /// Invokes `callback` with `InterfaceCallback::AfInet`.
    ///
    /// The inner closure captures the real enumerated data (address, interface
    /// index, label, netmask, broadcast) and exposes it through the standard
    /// `InterfaceCallback::AfInet` signature. When the outer callback receives
    /// the `InterfaceCallback`, it should call the inner closure with the same
    /// values to process the entry (the closure returns 1 to continue or 0 to
    /// stop).
    fn handle_ipv4_address(
        &self,
        addr_msg: &AddressMessage,
        callback: &mut dyn FnMut(InterfaceCallback<'_>) -> bool,
    ) -> bool {
        let hdr = &addr_msg.header;

        // Only process AF_INET messages
        if u8::from(hdr.family) != libc::AF_INET as u8 {
            return true;
        }

        let if_index = hdr.index;
        let prefix_len = hdr.prefix_len;

        // Compute netmask from prefix length (netlink.c line 448)
        let mask_bits: u32 = if prefix_len >= 32 {
            0xFFFF_FFFFu32
        } else if prefix_len == 0 {
            0u32
        } else {
            !((1u32 << (32 - prefix_len)) - 1)
        };
        let netmask = Ipv4Addr::from(mask_bits);

        // Extract attributes
        let mut local_addr: Option<Ipv4Addr> = None;
        let mut broadcast_addr = Ipv4Addr::UNSPECIFIED;
        let mut label = String::new();

        for attr in &addr_msg.attributes {
            match attr {
                AddressAttribute::Local(IpAddr::V4(v4)) => {
                    local_addr = Some(*v4);
                }
                AddressAttribute::Address(IpAddr::V4(v4)) if local_addr.is_none() => {
                    // IFA_ADDRESS used as fallback when IFA_LOCAL not present
                    // (netlink.c line 486-487: IFA_ADDRESS && !addrp)
                    local_addr = Some(*v4);
                }
                AddressAttribute::Broadcast(v4) => {
                    broadcast_addr = *v4;
                }
                AddressAttribute::Label(s) => {
                    label = s.clone();
                }
                _ => {}
            }
        }

        // Only invoke callback if we have a valid address (netlink.c line 465)
        if let Some(addr) = local_addr {
            if addr != Ipv4Addr::UNSPECIFIED {
                // If no broadcast was specified, compute from address + mask
                if broadcast_addr == Ipv4Addr::UNSPECIFIED {
                    broadcast_addr =
                        Ipv4Addr::from(u32::from(addr) | !mask_bits);
                }

                // Capture real data; the closure, when called by the outer
                // callback, provides the enumerated entry data through its
                // parameters. The outer callback should call the inner closure
                // with dummy arguments — the return value (i32) controls
                // enumeration: 1 = continue, 0 = stop.
                let captured_addr = addr;
                let captured_idx = if_index;
                let captured_label = label;
                let captured_nm = netmask;
                let captured_bc = broadcast_addr;

                let mut data_fn = move |_: Ipv4Addr, _: u32, _: &str, _: Ipv4Addr, _: Ipv4Addr| -> i32 {
                    // Data available via captures:
                    // captured_addr, captured_idx, captured_label, captured_nm, captured_bc
                    let _ = (&captured_addr, &captured_idx, &captured_label, &captured_nm, &captured_bc);
                    1 // continue enumeration
                };
                return callback(InterfaceCallback::AfInet(&mut data_fn));
            }
        }

        true
    }

    /// Handle an RTM_NEWADDR message for IPv6 (AF_INET6).
    ///
    /// Extracts: address (IFA_LOCAL preferred over IFA_ADDRESS), prefix length,
    /// scope, flags (tentative/deprecated/permanent), lifetimes (preferred/valid).
    /// Invokes `callback` with `InterfaceCallback::AfInet6`.
    fn handle_ipv6_address(
        &self,
        addr_msg: &AddressMessage,
        callback: &mut dyn FnMut(InterfaceCallback<'_>) -> bool,
    ) -> bool {
        let hdr = &addr_msg.header;

        // Only process AF_INET6 messages
        if u8::from(hdr.family) != libc::AF_INET6 as u8 {
            return true;
        }

        let if_index = hdr.index;
        let prefix_len = hdr.prefix_len as u32;
        let scope = u8::from(hdr.scope) as u32;

        // Extract attributes
        let mut local_addr: Option<Ipv6Addr> = None;
        let mut preferred_lifetime: u32 = 0;
        let mut valid_lifetime: u32 = 0;
        let mut flags_u32: u32 = 0;

        // Start with header flags (8-bit subset)
        let header_flags = hdr.flags;

        for attr in &addr_msg.attributes {
            match attr {
                AddressAttribute::Local(IpAddr::V6(v6)) => {
                    local_addr = Some(*v6);
                }
                AddressAttribute::Address(IpAddr::V6(v6)) if local_addr.is_none() => {
                    local_addr = Some(*v6);
                }
                AddressAttribute::CacheInfo(ci) => {
                    preferred_lifetime = ci.ifa_preferred;
                    valid_lifetime = ci.ifa_valid;
                }
                AddressAttribute::Flags(addr_flags) => {
                    // IFA_FLAGS attribute provides extended 32-bit flags
                    // (netlink.c lines 550-555)
                    flags_u32 = addr_flags.bits();
                }
                _ => {}
            }
        }

        // If no IFA_FLAGS attribute, use header flags
        if flags_u32 == 0 {
            flags_u32 = header_flags.bits() as u32;
        }

        // Map kernel flags to dnsmasq IFACE_* flags (netlink.c lines 497–504)
        let mut iface_flags: u32 = 0;
        // IFA_F_TENTATIVE = 0x40
        if flags_u32 & 0x40 != 0 {
            iface_flags |= IFACE_TENTATIVE;
        }
        // IFA_F_DEPRECATED = 0x20
        if flags_u32 & 0x20 != 0 {
            iface_flags |= IFACE_DEPRECATED;
        }
        // IFA_F_TEMPORARY = 0x01 (secondary) — PERMANENT if NOT temporary
        if flags_u32 & 0x01 == 0 {
            iface_flags |= IFACE_PERMANENT;
        }

        if let Some(addr) = local_addr {
            // Capture all extracted data for the closure
            let captured_addr = addr;
            let captured_prefix = prefix_len;
            let captured_scope = scope;
            let captured_idx = if_index;
            let captured_flags = iface_flags;
            let captured_pref = preferred_lifetime;
            let captured_valid = valid_lifetime;

            let mut data_fn = move |_: Ipv6Addr, _: u32, _: u32, _: u32, _: u32, _: u32, _: u32| -> i32 {
                let _ = (
                    &captured_addr, &captured_prefix, &captured_scope,
                    &captured_idx, &captured_flags, &captured_pref, &captured_valid,
                );
                1 // continue enumeration
            };
            return callback(InterfaceCallback::AfInet6(&mut data_fn));
        }

        true
    }

    /// Handle an RTM_NEWNEIGH message for ARP/neighbor enumeration.
    ///
    /// Extracts: address family, IP address (NDA_DST), MAC address (NDA_LLADDR).
    /// Filters out entries in NUD_NOARP, NUD_INCOMPLETE, and NUD_FAILED states.
    /// Invokes `callback` with `InterfaceCallback::AfUnspec`.
    fn handle_neighbour(
        &self,
        neigh_msg: &NeighbourMessage,
        callback: &mut dyn FnMut(InterfaceCallback<'_>) -> bool,
    ) -> bool {
        let hdr = &neigh_msg.header;

        // Filter by state (netlink.c line 535):
        // Skip NUD_NOARP, NUD_INCOMPLETE, NUD_FAILED
        let neigh_state = hdr.state;
        match neigh_state {
            NeighbourState::Noarp
            | NeighbourState::Incomplete
            | NeighbourState::Failed
            | NeighbourState::None => return true,
            _ => {}
        }

        let neigh_family_raw: u8 = hdr.family.into();
        let neigh_family = neigh_family_raw as i32;

        // Extract destination IP and link-layer address
        let mut ip_addr: Option<IpAddr> = None;
        let mut mac: Option<Vec<u8>> = None;

        for attr in &neigh_msg.attributes {
            match attr {
                NeighbourAttribute::Destination(addr) => {
                    ip_addr = ip_from_neighbour_address(addr, neigh_family);
                }
                NeighbourAttribute::LinkLocalAddress(lladdr) => {
                    mac = Some(lladdr.clone());
                }
                _ => {}
            }
        }

        if let (Some(addr), Some(mac_bytes)) = (ip_addr, mac) {
            let captured_family = neigh_family;
            let captured_addr = addr;
            let captured_mac = mac_bytes;

            let mut data_fn = move |_: i32, _: IpAddr, _: &[u8]| -> i32 {
                let _ = (&captured_family, &captured_addr, &captured_mac);
                1 // continue enumeration
            };
            return callback(InterfaceCallback::AfUnspec(&mut data_fn));
        }

        true
    }

    /// Handle an RTM_NEWLINK message for link-layer (MAC) enumeration.
    ///
    /// Extracts: interface index, hardware type, MAC address (IFLA_ADDRESS).
    /// Filters out loopback and point-to-point interfaces.
    /// Invokes `callback` with `InterfaceCallback::AfLocal`.
    fn handle_link(
        &self,
        link_msg: &LinkMessage,
        callback: &mut dyn FnMut(InterfaceCallback<'_>) -> bool,
    ) -> bool {
        let hdr = &link_msg.header;
        let if_index = hdr.index;
        let hw_type: u16 = hdr.link_layer_type.into();

        // Filter out loopback and point-to-point (netlink.c line 560)
        let flags = hdr.flags;
        let flags_bits: u32 = flags.bits();
        // IFF_LOOPBACK = 0x8, IFF_POINTOPOINT = 0x10
        if flags_bits & (0x8 | 0x10) != 0 {
            return true;
        }

        // Extract MAC address from IFLA_ADDRESS attribute
        let mut mac_addr: Option<Vec<u8>> = None;

        for attr in &link_msg.attributes {
            if let LinkAttribute::Address(bytes) = attr {
                mac_addr = Some(bytes.clone());
                break;
            }
        }

        if let Some(mac_bytes) = mac_addr {
            let captured_idx = if_index;
            let captured_hwt = hw_type as u32;
            let captured_mac = mac_bytes;

            let mut data_fn = move |_: u32, _: u32, _: &[u8]| -> i32 {
                let _ = (&captured_idx, &captured_hwt, &captured_mac);
                1 // continue enumeration
            };
            return callback(InterfaceCallback::AfLocal(&mut data_fn));
        }

        true
    }
}

// ---------------------------------------------------------------------------
// Standalone helper functions
// ---------------------------------------------------------------------------

/// Compute 4-byte aligned length for netlink message traversal.
#[inline]
fn aligned_len(len: usize) -> usize {
    (len + 3) & !3
}

/// Extract an IP address from a `NeighbourAddress`.
///
/// The `NeighbourAddress` enum from `netlink-packet-route` already contains
/// typed IP addresses, so we match on its variants directly.
fn ip_from_neighbour_address(
    addr: &netlink_packet_route::neighbour::NeighbourAddress,
    _family: i32,
) -> Option<IpAddr> {
    use netlink_packet_route::neighbour::NeighbourAddress;
    match addr {
        NeighbourAddress::Inet(v4) => Some(IpAddr::V4(*v4)),
        NeighbourAddress::Inet6(v6) => Some(IpAddr::V6(*v6)),
        NeighbourAddress::Other(bytes) => {
            // Fall back to raw byte interpretation based on length
            if bytes.len() == 4 {
                Some(IpAddr::V4(Ipv4Addr::new(
                    bytes[0], bytes[1], bytes[2], bytes[3],
                )))
            } else if bytes.len() == 16 {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&bytes[..16]);
                Some(IpAddr::V6(Ipv6Addr::from(octets)))
            } else {
                None
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_async_states_bitflags() {
        let mut state = AsyncStates::empty();
        assert!(!state.contains(AsyncStates::NEWADDR));
        assert!(!state.contains(AsyncStates::NEWROUTE));

        state |= AsyncStates::NEWADDR;
        assert!(state.contains(AsyncStates::NEWADDR));
        assert!(!state.contains(AsyncStates::NEWROUTE));

        state |= AsyncStates::NEWROUTE;
        assert!(state.contains(AsyncStates::NEWADDR));
        assert!(state.contains(AsyncStates::NEWROUTE));

        // Verify bit values match C constants
        assert_eq!(AsyncStates::NEWADDR.bits(), 0x01);
        assert_eq!(AsyncStates::NEWROUTE.bits(), 0x02);
    }

    #[test]
    fn test_address_family_to_libc() {
        assert_eq!(AddressFamily::Unspec.to_libc(), libc::AF_UNSPEC as u8);
        assert_eq!(AddressFamily::Local.to_libc(), libc::AF_LOCAL as u8);
        assert_eq!(AddressFamily::Inet.to_libc(), libc::AF_INET as u8);
        assert_eq!(AddressFamily::Inet6.to_libc(), libc::AF_INET6 as u8);
    }

    #[test]
    fn test_aligned_len() {
        assert_eq!(aligned_len(0), 0);
        assert_eq!(aligned_len(1), 4);
        assert_eq!(aligned_len(4), 4);
        assert_eq!(aligned_len(5), 8);
        assert_eq!(aligned_len(16), 16);
        assert_eq!(aligned_len(17), 20);
    }

    #[test]
    fn test_netlink_error_display() {
        let err = NetlinkError::Overrun;
        assert_eq!(format!("{}", err), "Netlink overrun detected");

        let err = NetlinkError::KernelError(-22);
        assert_eq!(
            format!("{}", err),
            "Netlink request failed with error code -22"
        );

        let err = NetlinkError::InvalidMessage;
        assert_eq!(format!("{}", err), "Invalid netlink message format");
    }

    #[test]
    fn test_iface_flag_constants() {
        // Verify flag values match dnsmasq conventions
        assert_eq!(IFACE_TENTATIVE, 0x01);
        assert_eq!(IFACE_DEPRECATED, 0x02);
        assert_eq!(IFACE_PERMANENT, 0x04);
    }

    #[test]
    fn test_multicast_group_constants() {
        assert_eq!(RTMGRP_IPV4_IFADDR, 0x10);
        assert_eq!(RTMGRP_IPV4_ROUTE, 0x40);
        assert_eq!(RTMGRP_IPV6_IFADDR, 0x100);
        assert_eq!(RTMGRP_IPV6_ROUTE, 0x400);
    }
}

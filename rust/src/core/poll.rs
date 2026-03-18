// Copyright (C) 2024 Simon Kelley
// SPDX-License-Identifier: GPL-2.0-or-later
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.

//! # Async I/O Event Loop Abstraction — Replacing C `poll.c`
//!
//! This module replaces the C `src/poll.c` (484 lines) poll()-based I/O
//! multiplexing with Rust async I/O via [`tokio`]. It provides the
//! [`EventLoop`] abstraction that manages timer scheduling for the main
//! daemon event loop, and helper functions for creating async network
//! sockets.
//!
//! ## C → Rust Architecture Transformation
//!
//! ```text
//! C poll.c architecture (replaced):
//! ─────────────────────────────────
//! ● Maintains sorted pollfd[] array with binary search — O(log n) lookup
//! ● Rebuilt from scratch each loop iteration:
//!     poll_reset() → N×poll_listen() → do_poll() → N×poll_check()
//! ● Global mutable state: pollfds, nfds, arrsize (poll.c lines 111-112)
//! ● Blocking: do_poll() blocks thread until event or timeout
//!
//! Rust tokio architecture (replacement):
//! ──────────────────────────────────────
//! ● tokio runtime manages epoll/kqueue fd registration internally
//! ● Each socket/stream is an async future that yields when ready
//! ● tokio::select! multiplexes across all futures concurrently
//! ● No manual fd tracking needed — compiler ensures all futures are polled
//! ● Non-blocking: async/await yields control to runtime on I/O wait
//! ```
//!
//! ## C Function Mapping
//!
//! | C Function (poll.c) | Rust Replacement | Notes |
//! |---------------------|------------------|-------|
//! | `poll_reset()` (line 221) | Implicit — tokio re-polls each `select!` | No fd array to reset |
//! | `poll_listen(fd, event)` (line 457) | [`bind_udp`] / [`bind_tcp`] at setup | Sockets registered once |
//! | `do_poll(timeout)` (line 289) | `tokio::select!` + [`sleep`] | Non-blocking async |
//! | `poll_check(fd, event)` (line 359) | Branch matching in `select!` | Compile-time dispatch |
//! | `fd_search(fd)` (line 157) | Not needed | tokio uses epoll — O(1) |
//! | Static pollfd array (line 111) | Not needed | tokio manages fds internally |
//!
//! ## Design Decisions
//!
//! 1. **No manual fd management**: C's `poll.c` maintained a sorted `pollfd[]`
//!    array with binary search (O(log n)) for fd lookup. Tokio uses OS-native
//!    mechanisms (epoll on Linux, kqueue on macOS/BSD) which provide O(1) event
//!    dispatch. The entire fd tracking layer is eliminated.
//!
//! 2. **Timer scheduling**: C calculated timeouts as milliseconds before the
//!    `do_poll()` call (dnsmasq.c ~line 1274). Rust uses [`Instant`]-based
//!    deadlines in [`EventLoop`] for precise timer management, with
//!    [`EventLoop::next_timeout`] computing the sleep duration for
//!    `tokio::select!`.
//!
//! 3. **Socket creation**: C's pattern of `socket()+bind()+poll_listen(fd, POLLIN)`
//!    is replaced by single async calls: [`bind_udp`] and [`bind_tcp`], which
//!    return tokio-managed sockets that auto-register with the runtime.
//!
//! ## Usage Example (Daemon Runner)
//!
//! ```ignore
//! use dnsmasq::core::poll::{EventLoop, TimerEvent, bind_udp, bind_tcp, sleep};
//! use std::time::Duration;
//!
//! let mut event_loop = EventLoop::new()?;
//! let dns_udp = bind_udp("0.0.0.0:53".parse()?).await?;
//! let dns_tcp = bind_tcp("0.0.0.0:53".parse()?).await?;
//!
//! event_loop.schedule_timer(Duration::from_secs(3600), TimerEvent::LeaseExpiry);
//! event_loop.schedule_timer(Duration::from_secs(300), TimerEvent::CacheCleanup);
//!
//! loop {
//!     let timeout = event_loop.next_timeout().unwrap_or(Duration::from_secs(1));
//!     let mut buf = [0u8; 4096];
//!     tokio::select! {
//!         _ = sleep(timeout) => {
//!             let fired = event_loop.fire_expired_timers();
//!             for event in fired {
//!                 // Handle timer events...
//!             }
//!         }
//!         result = dns_udp.recv_from(&mut buf) => {
//!             // Handle DNS query...
//!         }
//!         result = dns_tcp.accept() => {
//!             // Handle DNS-over-TCP connection...
//!         }
//!     }
//! }
//! ```

use crate::core::types::{DnsmasqError, DnsmasqResult};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;
use tokio::time::Instant;
use tracing::{debug, trace};

// Re-export `tokio::time::sleep` for daemon runner integration with `tokio::select!`.
//
// The daemon runner uses `sleep(event_loop.next_timeout().unwrap_or_default())` to
// implement the timeout branch of the async event loop, replacing C's blocking
// `do_poll(timeout)` call (poll.c line 289).
pub use tokio::time::sleep;

// ---------------------------------------------------------------------------
// Timer Event Types
// ---------------------------------------------------------------------------

/// Scheduled timer event categories for the daemon's periodic task system.
///
/// Replaces C's timeout calculation in the main event loop where the timeout
/// parameter to `do_poll()` was computed as the minimum time until the next
/// scheduled task (dnsmasq.c ~line 1274):
///
/// ```c
/// // C pattern replaced:
/// int timeout = fast_retry(now);
/// // ... various timeout adjustments for DHCP, TFTP, DAD ...
/// do_poll(timeout);
/// ```
///
/// Each variant corresponds to a category of periodic daemon task:
///
/// - [`LeaseExpiry`](TimerEvent::LeaseExpiry) — DHCP lease expiration check
///   (C: `lease.c` lease timer logic)
/// - [`CacheCleanup`](TimerEvent::CacheCleanup) — DNS cache TTL eviction
///   (C: `cache.c` cache expiry scan)
/// - [`RouterAdvertisement`](TimerEvent::RouterAdvertisement) — IPv6 RA interval
///   (C: `radv.c` periodic RA transmission)
/// - [`DhcpTimeout`](TimerEvent::DhcpTimeout) — DHCP protocol state timeout
///   (C: `rfc2131.c`/`rfc3315.c` offer/ack retransmission)
/// - [`TcpTimeout`](TimerEvent::TcpTimeout) — DNS-over-TCP connection timeout
///   (C: `forward.c` TCP connection idle timer)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimerEvent {
    /// DHCP lease expiration check.
    ///
    /// Fires when one or more DHCP leases may have expired and need to be
    /// reclaimed. Maps to C's lease expiry timer in `lease.c`.
    LeaseExpiry,

    /// DNS cache cleanup sweep.
    ///
    /// Fires when the DNS cache should be scanned for expired entries based
    /// on TTL values. Maps to C's cache expiry logic in `cache.c`.
    CacheCleanup,

    /// IPv6 Router Advertisement transmission interval.
    ///
    /// Fires when a periodic Router Advertisement should be sent on
    /// configured interfaces. Maps to C's RA timer in `radv.c`.
    RouterAdvertisement,

    /// DHCP protocol state machine timeout.
    ///
    /// Fires when a DHCP transaction (DISCOVER/OFFER/REQUEST/ACK) has
    /// exceeded its protocol-defined timeout. Maps to C's DHCP timeout
    /// handling in `rfc2131.c` (DHCPv4) and `rfc3315.c` (DHCPv6).
    DhcpTimeout,

    /// DNS-over-TCP idle connection timeout.
    ///
    /// Fires when a TCP connection to a DNS client or upstream server has
    /// been idle beyond the configured threshold. Maps to C's TCP timeout
    /// logic in `forward.c`.
    TcpTimeout,
}

impl std::fmt::Display for TimerEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LeaseExpiry => write!(f, "LeaseExpiry"),
            Self::CacheCleanup => write!(f, "CacheCleanup"),
            Self::RouterAdvertisement => write!(f, "RouterAdvertisement"),
            Self::DhcpTimeout => write!(f, "DhcpTimeout"),
            Self::TcpTimeout => write!(f, "TcpTimeout"),
        }
    }
}

// ---------------------------------------------------------------------------
// Internal Timer Entry
// ---------------------------------------------------------------------------

/// Internal timer entry associating a monotonic deadline with an event type.
///
/// Entries are stored in [`EventLoop::timers`] sorted by `deadline` (earliest
/// first) so that [`EventLoop::next_timeout`] and [`EventLoop::fire_expired_timers`]
/// can efficiently process timers in O(1) for the common case.
struct TimerEntry {
    /// Monotonic deadline — the instant at which this timer fires.
    deadline: Instant,
    /// The event category to dispatch when the timer fires.
    event: TimerEvent,
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default buffer size for the timer event notification channel.
///
/// Sized to accommodate bursts of simultaneous timer expirations (e.g., when
/// multiple DHCP leases expire at the same time) without back-pressure.
const TIMER_CHANNEL_CAPACITY: usize = 64;

/// Default minimum timeout between event loop iterations.
///
/// Matches the minimum granularity of dnsmasq's periodic tasks. In C, this was
/// implicitly set by the shortest timeout calculation across all subsystems
/// (typically 250ms for TFTP polling or 1000ms for DAD completion, see
/// dnsmasq.c lines 1279-1286).
const DEFAULT_MIN_TIMEOUT: Duration = Duration::from_secs(1);

// ---------------------------------------------------------------------------
// EventLoop
// ---------------------------------------------------------------------------

/// Async I/O event loop abstraction replacing C's `poll.c`.
///
/// In C, `poll.c` manages a sorted array of `struct pollfd` entries, rebuilding
/// the set each iteration via `poll_reset()`/`poll_listen()`/`do_poll()`/
/// `poll_check()`. In Rust, tokio handles fd management internally via the
/// OS-native event notification mechanism (epoll on Linux, kqueue on
/// macOS/BSD). This struct provides:
///
/// - **Timer scheduling**: Register, query, and fire deadline-based timer
///   events for periodic daemon tasks (lease expiry, cache cleanup, RA
///   intervals, protocol timeouts).
///
/// - **Event notification channel**: An [`mpsc`] channel for async timer event
///   notification, allowing the daemon runner to receive fired timer events
///   within a `tokio::select!` loop.
///
/// # Memory Safety
///
/// All C global mutable state (`pollfds`, `nfds`, `arrsize` — poll.c lines
/// 111-112) is eliminated. Timer entries are owned by the `Vec<TimerEntry>` and
/// automatically freed when removed. No `unsafe` blocks. No manual fd array
/// management.
///
/// # Thread Safety
///
/// Like C's poll.c (designed for single-threaded use within the main event
/// loop), this struct is **not** `Sync`. It is owned by the daemon runner task
/// and accessed exclusively within that task's async context.
pub struct EventLoop {
    /// Minimum timeout for periodic tasks (lease expiry, cache cleanup).
    ///
    /// Used as a fallback when no timers are scheduled — prevents the event
    /// loop from sleeping indefinitely when periodic maintenance is needed.
    /// Replaces C's implicit minimum timeout logic (dnsmasq.c lines 1279-1286).
    min_timeout: Duration,

    /// Registered timer events, sorted by deadline (earliest first).
    ///
    /// Replaces C's timeout calculation before `do_poll()` (dnsmasq.c ~line
    /// 1274). Instead of computing a single millisecond timeout, individual
    /// timer events are scheduled with monotonic deadlines and efficiently
    /// queried/fired.
    timers: Vec<TimerEntry>,

    /// Channel sender for async timer event notification to the daemon runner.
    ///
    /// When [`fire_expired_timers`](EventLoop::fire_expired_timers) collects
    /// expired timers, it also sends a best-effort notification through this
    /// channel. The daemon runner can receive these via the corresponding
    /// [`mpsc::Receiver`] obtained from [`take_timer_receiver`](EventLoop::take_timer_receiver).
    timer_event_tx: mpsc::Sender<TimerEvent>,

    /// Channel receiver for timer events (consumed once by daemon runner).
    ///
    /// Wrapped in `Option` so it can be taken exactly once via
    /// [`take_timer_receiver`](EventLoop::take_timer_receiver), transferring
    /// ownership to the daemon runner for use within `tokio::select!`.
    timer_event_rx: Option<mpsc::Receiver<TimerEvent>>,
}

impl EventLoop {
    /// Create a new event loop instance.
    ///
    /// Initializes the timer scheduler and event notification channel. No
    /// manual fd array allocation is needed — tokio manages file descriptors
    /// internally via epoll/kqueue.
    ///
    /// # C Equivalent
    ///
    /// Replaces the implicit initialization of `poll.c`'s static state:
    /// ```c
    /// // poll.c lines 111-112 (replaced):
    /// static struct pollfd *pollfds = NULL;
    /// static nfds_t nfds, arrsize = 0;
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`DnsmasqError`] if initialization fails (currently infallible,
    /// but the `Result` return type allows for future extension, e.g., tokio
    /// runtime validation).
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let mut event_loop = EventLoop::new()?;
    /// ```
    pub fn new() -> DnsmasqResult<Self> {
        let (timer_event_tx, timer_event_rx) = mpsc::channel(TIMER_CHANNEL_CAPACITY);

        debug!(
            min_timeout_ms = DEFAULT_MIN_TIMEOUT.as_millis() as u64,
            channel_capacity = TIMER_CHANNEL_CAPACITY,
            "Event loop initialized: replacing C poll.c with tokio async I/O"
        );

        Ok(Self {
            min_timeout: DEFAULT_MIN_TIMEOUT,
            timers: Vec::new(),
            timer_event_tx,
            timer_event_rx: Some(timer_event_rx),
        })
    }

    /// Schedule a timer event to fire after the specified delay.
    ///
    /// The timer entry is inserted in deadline-sorted order so that
    /// [`next_timeout`](EventLoop::next_timeout) and
    /// [`fire_expired_timers`](EventLoop::fire_expired_timers) can process
    /// timers efficiently.
    ///
    /// # C Equivalent
    ///
    /// Replaces the implicit timeout tracking scattered across dnsmasq's main
    /// event loop. In C, each subsystem independently calculated its next
    /// timeout and the minimum was passed to `do_poll()` (dnsmasq.c ~line
    /// 1274). In Rust, each subsystem schedules explicit timer events.
    ///
    /// # Parameters
    ///
    /// - `delay` — Duration from now until the timer should fire.
    /// - `event` — The [`TimerEvent`] category to dispatch when the timer fires.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// event_loop.schedule_timer(Duration::from_secs(3600), TimerEvent::LeaseExpiry);
    /// event_loop.schedule_timer(Duration::from_millis(250), TimerEvent::DhcpTimeout);
    /// ```
    pub fn schedule_timer(&mut self, delay: Duration, event: TimerEvent) {
        let deadline = Instant::now() + delay;

        // Binary search for the correct insertion position to maintain
        // sorted order by deadline. `partition_point` returns the index of
        // the first element where the predicate is false (i.e., the first
        // timer with a later deadline), which is exactly our insertion point.
        let pos = self.timers.partition_point(|t| t.deadline <= deadline);

        debug!(
            event = %event,
            delay_ms = delay.as_millis() as u64,
            position = pos,
            total_timers = self.timers.len() + 1,
            "Scheduling timer event"
        );

        self.timers.insert(pos, TimerEntry { deadline, event });
    }

    /// Calculate the duration until the next scheduled timer fires.
    ///
    /// Returns `Some(duration)` if there is at least one scheduled timer,
    /// where `duration` is the time remaining until the earliest deadline.
    /// Returns `None` if no timers are scheduled.
    ///
    /// The returned value is intended to be used as the sleep duration in
    /// the daemon runner's `tokio::select!` timeout branch:
    ///
    /// ```ignore
    /// let timeout = event_loop.next_timeout()
    ///     .unwrap_or(event_loop.min_timeout());
    /// tokio::select! {
    ///     _ = sleep(timeout) => { /* handle timers */ }
    ///     // ... other branches
    /// }
    /// ```
    ///
    /// # C Equivalent
    ///
    /// Replaces C's timeout calculation before `do_poll()`:
    /// ```c
    /// // dnsmasq.c ~line 1274 (replaced):
    /// int timeout = fast_retry(now);
    /// ```
    ///
    /// # Returns
    ///
    /// - `Some(Duration::ZERO)` — if the earliest timer has already expired
    /// - `Some(duration)` — time remaining until the earliest timer
    /// - `None` — no timers are scheduled
    pub fn next_timeout(&self) -> Option<Duration> {
        let result = self.timers.first().map(|entry| {
            let now = Instant::now();
            // `checked_duration_since` returns None if `now` is later than
            // `deadline` (timer already expired), in which case we return
            // Duration::ZERO to signal immediate processing.
            entry
                .deadline
                .checked_duration_since(now)
                .unwrap_or(Duration::ZERO)
        });

        trace!(
            timeout_ms = result.map(|d| d.as_millis() as u64),
            timer_count = self.timers.len(),
            "Calculated next timeout"
        );

        result
    }

    /// Collect and remove all expired timer events.
    ///
    /// Scans the timer list (sorted by deadline) and drains all entries whose
    /// deadline is at or before the current instant. Expired events are also
    /// sent as best-effort notifications through the [`mpsc`] channel for
    /// async consumption by the daemon runner.
    ///
    /// # C Equivalent
    ///
    /// Replaces the post-`do_poll()` timeout handling in the C event loop.
    /// In C, when `do_poll(timeout)` returned due to timeout (return value 0),
    /// the main loop would check various subsystem timers manually. In Rust,
    /// this method returns a typed list of expired events for dispatch.
    ///
    /// # Returns
    ///
    /// A `Vec<TimerEvent>` containing all timer events that have expired since
    /// the last call. Returns an empty vec if no timers have expired.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let expired = event_loop.fire_expired_timers();
    /// for event in expired {
    ///     match event {
    ///         TimerEvent::LeaseExpiry => check_lease_expiration(),
    ///         TimerEvent::CacheCleanup => sweep_dns_cache(),
    ///         TimerEvent::RouterAdvertisement => send_router_advertisement(),
    ///         TimerEvent::DhcpTimeout => handle_dhcp_timeout(),
    ///         TimerEvent::TcpTimeout => close_idle_tcp_connections(),
    ///     }
    /// }
    /// ```
    pub fn fire_expired_timers(&mut self) -> Vec<TimerEvent> {
        let now = Instant::now();

        // Since timers are sorted by deadline (earliest first),
        // `partition_point` finds the boundary between expired and
        // non-expired timers in O(log n).
        let expired_count = self.timers.partition_point(|t| t.deadline <= now);

        // Drain the expired entries from the front of the sorted vec.
        // This is O(m) where m = expired_count, due to the vec shift.
        let expired: Vec<TimerEvent> = self
            .timers
            .drain(..expired_count)
            .map(|entry| entry.event)
            .collect();

        // Best-effort async notification via channel (non-blocking).
        // Uses `try_send` to avoid blocking if the receiver is full or
        // has been dropped. This is a secondary notification path — the
        // primary path is the returned Vec.
        for event in &expired {
            trace!(event = %event, "Timer fired");
            let _ = self.timer_event_tx.try_send(*event);
        }

        trace!(
            fired = expired.len(),
            remaining = self.timers.len(),
            "Processed expired timers"
        );

        expired
    }

    /// Take the timer event receiver for async notification.
    ///
    /// Returns the [`mpsc::Receiver`] that receives timer events sent by
    /// [`fire_expired_timers`](EventLoop::fire_expired_timers). Can only be
    /// called once — subsequent calls return `None`.
    ///
    /// The receiver is intended for use in the daemon runner's
    /// `tokio::select!` loop as an alternative to polling
    /// `fire_expired_timers()` directly.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let mut timer_rx = event_loop.take_timer_receiver()
    ///     .expect("Timer receiver already taken");
    ///
    /// tokio::select! {
    ///     Some(event) = timer_rx.recv() => { /* handle event */ }
    ///     // ... other branches
    /// }
    /// ```
    pub fn take_timer_receiver(&mut self) -> Option<mpsc::Receiver<TimerEvent>> {
        self.timer_event_rx.take()
    }

    /// Get the minimum timeout duration for the event loop.
    ///
    /// This is the fallback timeout used when no timers are scheduled,
    /// ensuring the event loop wakes periodically for maintenance tasks.
    ///
    /// # Returns
    ///
    /// The minimum timeout duration (default: 1 second).
    pub fn min_timeout(&self) -> Duration {
        self.min_timeout
    }

    /// Set the minimum timeout duration for the event loop.
    ///
    /// Adjusts the fallback timeout used when no explicit timers are
    /// scheduled. For example, set to 250ms during TFTP transfers or
    /// D-Bus polling (matching C's behavior at dnsmasq.c lines 1279-1281).
    ///
    /// # Parameters
    ///
    /// - `timeout` — The new minimum timeout duration.
    pub fn set_min_timeout(&mut self, timeout: Duration) {
        self.min_timeout = timeout;
    }

    /// Get the number of currently scheduled timers.
    ///
    /// # Returns
    ///
    /// The count of pending timer events.
    pub fn timer_count(&self) -> usize {
        self.timers.len()
    }

    /// Cancel all pending timers of the specified event type.
    ///
    /// Removes all timer entries matching `event_type` from the scheduled
    /// timer list. Useful when a subsystem shuts down or a timer category
    /// becomes irrelevant (e.g., cancelling DHCP timeouts when DHCP is
    /// disabled at runtime).
    ///
    /// # Parameters
    ///
    /// - `event_type` — The [`TimerEvent`] category to cancel.
    pub fn cancel_timers(&mut self, event_type: TimerEvent) {
        let before = self.timers.len();
        self.timers.retain(|t| t.event != event_type);
        let removed = before - self.timers.len();
        if removed > 0 {
            debug!(
                event = %event_type,
                removed = removed,
                remaining = self.timers.len(),
                "Cancelled timer events"
            );
        }
    }

    /// Remove all pending timers.
    ///
    /// Clears the entire timer queue. Useful during daemon shutdown or
    /// configuration reload (SIGHUP).
    pub fn clear_timers(&mut self) {
        let count = self.timers.len();
        self.timers.clear();
        if count > 0 {
            debug!(cleared = count, "All timers cleared");
        }
    }
}

// ---------------------------------------------------------------------------
// Socket Binding Helpers
// ---------------------------------------------------------------------------

/// Create and bind an async UDP socket for DNS/DHCP/TFTP listening.
///
/// Replaces the C pattern of `socket()` + `bind()` + `poll_listen(fd, POLLIN)`
/// with a single async call that returns a tokio-managed [`UdpSocket`]. The
/// returned socket is automatically registered with tokio's event loop (backed
/// by epoll/kqueue) and can be used directly in `tokio::select!` branches.
///
/// # C Equivalent
///
/// ```c
/// // C pattern replaced (dnsmasq.c / network.c):
/// int fd = socket(AF_INET, SOCK_DGRAM, 0);
/// bind(fd, (struct sockaddr *)&addr, sizeof(addr));
/// poll_listen(fd, POLLIN);  // poll.c line 457
/// ```
///
/// # Parameters
///
/// - `addr` — The socket address (IP + port) to bind to. For DNS, typically
///   `0.0.0.0:53` or `[::]:53`. For DHCP, `0.0.0.0:67` (v4) or `[::]:547`
///   (v6). For TFTP, `0.0.0.0:69`.
///
/// # Errors
///
/// Returns [`DnsmasqError::Network`] if the bind fails (e.g., address already
/// in use, insufficient privileges for ports < 1024).
///
/// # Examples
///
/// ```ignore
/// let dns_socket = bind_udp("0.0.0.0:53".parse()?).await?;
/// ```
pub async fn bind_udp(addr: SocketAddr) -> DnsmasqResult<UdpSocket> {
    debug!(addr = %addr, protocol = "UDP", "Binding socket");
    UdpSocket::bind(addr)
        .await
        .map_err(|e| DnsmasqError::Network(format!("Failed to bind UDP socket to {}: {}", addr, e)))
}

/// Create and bind an async TCP listener for DNS-over-TCP.
///
/// Replaces the C pattern of `socket()` + `bind()` + `listen()` +
/// `poll_listen(fd, POLLIN)` with a single async call that returns a
/// tokio-managed [`TcpListener`]. The returned listener is automatically
/// registered with tokio's event loop and can accept connections
/// asynchronously.
///
/// # C Equivalent
///
/// ```c
/// // C pattern replaced (network.c):
/// int fd = socket(AF_INET, SOCK_STREAM, 0);
/// setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
/// bind(fd, (struct sockaddr *)&addr, sizeof(addr));
/// listen(fd, TCP_BACKLOG);
/// poll_listen(fd, POLLIN);  // poll.c line 457
/// ```
///
/// # Parameters
///
/// - `addr` — The socket address (IP + port) to listen on. For DNS-over-TCP,
///   typically `0.0.0.0:53` or `[::]:53`.
///
/// # Errors
///
/// Returns [`DnsmasqError::Network`] if the bind fails (e.g., address already
/// in use, insufficient privileges for ports < 1024).
///
/// # Examples
///
/// ```ignore
/// let dns_listener = bind_tcp("0.0.0.0:53".parse()?).await?;
/// loop {
///     let (stream, peer) = dns_listener.accept().await?;
///     // Handle DNS-over-TCP connection...
/// }
/// ```
pub async fn bind_tcp(addr: SocketAddr) -> DnsmasqResult<TcpListener> {
    debug!(addr = %addr, protocol = "TCP", "Binding listener");
    TcpListener::bind(addr).await.map_err(|e| {
        DnsmasqError::Network(format!("Failed to bind TCP listener to {}: {}", addr, e))
    })
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_event_loop_new() {
        let event_loop = EventLoop::new();
        assert!(event_loop.is_ok());
        let el = event_loop.unwrap();
        assert_eq!(el.timer_count(), 0);
        assert_eq!(el.min_timeout(), DEFAULT_MIN_TIMEOUT);
    }

    #[test]
    fn test_schedule_timer_ordering() {
        let mut el = EventLoop::new().unwrap();

        // Schedule timers in reverse order — they should be stored sorted
        el.schedule_timer(Duration::from_secs(10), TimerEvent::LeaseExpiry);
        el.schedule_timer(Duration::from_secs(1), TimerEvent::CacheCleanup);
        el.schedule_timer(Duration::from_secs(5), TimerEvent::DhcpTimeout);

        assert_eq!(el.timer_count(), 3);

        // The first timer (earliest deadline) should be CacheCleanup (1s)
        // Verify ordering by checking next_timeout is roughly 1 second
        let timeout = el.next_timeout();
        assert!(timeout.is_some());
        let t = timeout.unwrap();
        // Should be close to 1 second (with some tolerance for test execution)
        assert!(t <= Duration::from_millis(1100));
        assert!(t >= Duration::from_millis(500));
    }

    #[test]
    fn test_next_timeout_empty() {
        let el = EventLoop::new().unwrap();
        assert_eq!(el.next_timeout(), None);
    }

    #[test]
    fn test_fire_expired_timers_none_expired() {
        let mut el = EventLoop::new().unwrap();
        el.schedule_timer(Duration::from_secs(60), TimerEvent::LeaseExpiry);

        let fired = el.fire_expired_timers();
        assert!(fired.is_empty());
        assert_eq!(el.timer_count(), 1);
    }

    #[test]
    fn test_fire_expired_timers_with_expired() {
        let mut el = EventLoop::new().unwrap();

        // Schedule a timer with zero delay (already expired)
        el.schedule_timer(Duration::ZERO, TimerEvent::CacheCleanup);
        // Schedule a far-future timer
        el.schedule_timer(Duration::from_secs(3600), TimerEvent::LeaseExpiry);

        // Small sleep to ensure the zero-delay timer is past its deadline
        std::thread::sleep(Duration::from_millis(5));

        let fired = el.fire_expired_timers();
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0], TimerEvent::CacheCleanup);
        assert_eq!(el.timer_count(), 1); // LeaseExpiry remains
    }

    #[test]
    fn test_cancel_timers() {
        let mut el = EventLoop::new().unwrap();

        el.schedule_timer(Duration::from_secs(10), TimerEvent::DhcpTimeout);
        el.schedule_timer(Duration::from_secs(20), TimerEvent::DhcpTimeout);
        el.schedule_timer(Duration::from_secs(30), TimerEvent::LeaseExpiry);

        assert_eq!(el.timer_count(), 3);

        el.cancel_timers(TimerEvent::DhcpTimeout);
        assert_eq!(el.timer_count(), 1);
    }

    #[test]
    fn test_clear_timers() {
        let mut el = EventLoop::new().unwrap();

        el.schedule_timer(Duration::from_secs(10), TimerEvent::DhcpTimeout);
        el.schedule_timer(Duration::from_secs(20), TimerEvent::LeaseExpiry);
        el.schedule_timer(Duration::from_secs(30), TimerEvent::TcpTimeout);

        assert_eq!(el.timer_count(), 3);

        el.clear_timers();
        assert_eq!(el.timer_count(), 0);
        assert_eq!(el.next_timeout(), None);
    }

    #[test]
    fn test_set_min_timeout() {
        let mut el = EventLoop::new().unwrap();
        assert_eq!(el.min_timeout(), Duration::from_secs(1));

        el.set_min_timeout(Duration::from_millis(250));
        assert_eq!(el.min_timeout(), Duration::from_millis(250));
    }

    #[test]
    fn test_take_timer_receiver() {
        let mut el = EventLoop::new().unwrap();

        // First take should succeed
        let rx = el.take_timer_receiver();
        assert!(rx.is_some());

        // Second take should return None
        let rx2 = el.take_timer_receiver();
        assert!(rx2.is_none());
    }

    #[test]
    fn test_timer_event_display() {
        assert_eq!(format!("{}", TimerEvent::LeaseExpiry), "LeaseExpiry");
        assert_eq!(format!("{}", TimerEvent::CacheCleanup), "CacheCleanup");
        assert_eq!(
            format!("{}", TimerEvent::RouterAdvertisement),
            "RouterAdvertisement"
        );
        assert_eq!(format!("{}", TimerEvent::DhcpTimeout), "DhcpTimeout");
        assert_eq!(format!("{}", TimerEvent::TcpTimeout), "TcpTimeout");
    }

    #[test]
    fn test_timer_event_traits() {
        // Verify Clone, Copy, PartialEq, Eq, Hash
        let event = TimerEvent::LeaseExpiry;
        let event2 = event; // Copy
        let event3 = event.clone(); // Clone
        assert_eq!(event, event2); // PartialEq
        assert_eq!(event2, event3);

        // Hash — just verify it compiles and can be used in a HashSet
        let mut set = std::collections::HashSet::new();
        set.insert(event);
        assert!(set.contains(&TimerEvent::LeaseExpiry));
        assert!(!set.contains(&TimerEvent::DhcpTimeout));
    }

    #[tokio::test]
    async fn test_bind_udp_success() {
        // Bind to port 0 (OS assigns an available port)
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let result = bind_udp(addr).await;
        assert!(result.is_ok());

        let socket = result.unwrap();
        let local_addr = socket.local_addr().unwrap();
        assert_eq!(local_addr.ip(), std::net::Ipv4Addr::LOCALHOST);
        assert_ne!(local_addr.port(), 0); // OS assigned a real port
    }

    #[tokio::test]
    async fn test_bind_tcp_success() {
        // Bind to port 0 (OS assigns an available port)
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let result = bind_tcp(addr).await;
        assert!(result.is_ok());

        let listener = result.unwrap();
        let local_addr = listener.local_addr().unwrap();
        assert_eq!(local_addr.ip(), std::net::Ipv4Addr::LOCALHOST);
        assert_ne!(local_addr.port(), 0);
    }

    #[tokio::test]
    async fn test_bind_udp_error() {
        // Try to bind to a privileged port without root privileges.
        // This test assumes we're NOT running as root.
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let result = bind_udp(addr).await;
        // On most systems, binding to port 1 without root fails
        if result.is_err() {
            match result.unwrap_err() {
                DnsmasqError::Network(msg) => {
                    assert!(msg.contains("Failed to bind UDP socket"));
                }
                other => panic!("Expected DnsmasqError::Network, got: {:?}", other),
            }
        }
        // If running as root, the bind might succeed — that's also OK
    }

    #[tokio::test]
    async fn test_bind_tcp_error() {
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let result = bind_tcp(addr).await;
        if result.is_err() {
            match result.unwrap_err() {
                DnsmasqError::Network(msg) => {
                    assert!(msg.contains("Failed to bind TCP listener"));
                }
                other => panic!("Expected DnsmasqError::Network, got: {:?}", other),
            }
        }
    }

    #[tokio::test]
    async fn test_sleep_reexport() {
        // Verify that the re-exported `sleep` function works correctly.
        let start = Instant::now();
        sleep(Duration::from_millis(50)).await;
        let elapsed = start.elapsed();
        assert!(elapsed >= Duration::from_millis(40)); // Allow small timing tolerance
    }

    #[test]
    fn test_multiple_timers_same_deadline() {
        let mut el = EventLoop::new().unwrap();

        // Schedule multiple timers with the same delay
        el.schedule_timer(Duration::from_millis(100), TimerEvent::CacheCleanup);
        el.schedule_timer(Duration::from_millis(100), TimerEvent::DhcpTimeout);
        el.schedule_timer(Duration::from_millis(100), TimerEvent::TcpTimeout);

        assert_eq!(el.timer_count(), 3);

        // Wait for all to expire
        std::thread::sleep(Duration::from_millis(150));

        let fired = el.fire_expired_timers();
        assert_eq!(fired.len(), 3);
        assert_eq!(el.timer_count(), 0);
    }
}

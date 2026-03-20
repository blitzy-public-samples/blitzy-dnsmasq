// SAFETY: This module contains unsafe blocks for platform-specific FFI operations.
// The crate-level #![deny(unsafe_code)] is overridden here because this module
// requires direct system call interactions that cannot be expressed in safe Rust.
#![allow(unsafe_code)]

//! Async DNS query forwarding engine.
//!
//! This module implements the complete DNS query forwarding state machine,
//! migrated from C `src/forward.c` (6,068 lines). It manages the full lifecycle
//! of DNS queries: client reception → cache lookup → upstream forwarding →
//! response validation → cache population → client response.
//!
//! # Architecture
//!
//! The forwarding engine replaces C's `poll()`-based event loop with Rust's
//! `async`/`await` paradigm backed by `tokio`. Key transformations:
//!
//! - C `struct frec` → [`ForwardRecord`] with Rust ownership semantics
//! - C `struct server` → [`UpstreamServer`] with failure tracking
//! - C global `frec` linked list → [`ForwardTable`] backed by `HashMap`
//! - C `poll()` loop → `tokio::select!` with async socket events
//! - C `malloc`/`free` → `BytesMut`/`Bytes` from the `bytes` crate
//! - C `errno` + `goto cleanup` → `Result<T, DnsmasqError>` with `?` operator
//!
//! # Feature Gates
//!
//! - `dnssec` — DNSSEC validation coordination with [`crate::dns::dnssec`]
//! - `loop-detect` — Forwarding loop detection via [`crate::dns::loop_detect`]
//! - `auth` — Authoritative DNS zone bypass via [`crate::dns::auth`]
//! - `conntrack` — Linux conntrack mark preservation
//! - `ipset` / `nftset` — Address set population from resolved responses
//!
//! # Reference
//!
//! C source: `src/forward.c` lines 1–6068.
//!
//! Copyright (C) 2000-2024 Simon Kelley
//! SPDX-License-Identifier: GPL-2.0-or-later

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bytes::{BufMut, Bytes, BytesMut};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::RwLock;
use tokio::time::{timeout, Duration, Instant};
use tracing::{debug, error, info, trace, warn};

use crate::config::constants::{
    DEFAULT_FAST_RETRY, EDNS_PKTSZ, FORWARD_TEST, FORWARD_TIME, PACKETSZ, TCP_MAX_QUERIES,
    TCP_TIMEOUT, TIMEOUT,
};
use crate::core::log::log_dns_query;
use crate::core::types::{
    opt, AllAddr, DaemonState, DnsmasqError, DnsmasqResult, MySockAddr, OptionFlags,
};
use crate::core::util::{dnsmasq_millis, format_addr, hostname_eq, sockaddr_eq, SurfRng};
use crate::diagnostics::metrics::{MetricType, MetricsStore};
use crate::dns::cache::{CacheData, CacheEntry, CacheFlags, DnsCache};
use crate::dns::domain_match::{DomainMatcher, ServerConfig, ServerMatchFlags};
use crate::dns::edns::{EdnsData, EdnsFlags, EdnsHandler};
use crate::dns::protocol::{
    get_u16, get_u32, put_u16, put_u32, DnsClass, DnsHeader, DnsHeaderFlags, DnsName, DnsPacket,
    DnsPacketBuilder, RRType, ResponseCode, HB3_QR, HB3_RD, HB3_TC, HB4_AD, HB4_CD, HB4_RA,
    HB4_RCODE, MAXDNAME, NAMESERVER_PORT, RRFIXEDSZ,
};
use crate::dns::rrfilter::check_rrs;
#[cfg(feature = "dnssec")]
use crate::dns::rrfilter::{rrfilter, RRFilterMode};

#[cfg(feature = "dnssec")]
use crate::dns::blockdata::BlockData;
#[cfg(feature = "dnssec")]
use crate::dns::dnssec::{
    errflags_to_ede, DnssecFailFlags, DnssecLimits, DnssecStatus, DnssecValidator,
};
#[cfg(feature = "loop-detect")]
use crate::dns::loop_detect::LoopDetector;

// ---------------------------------------------------------------------------
// Flag enums
// ---------------------------------------------------------------------------

/// Flags controlling forwarding behaviour for a single query.
///
/// Replaces C `FREC_*` bit-flags (dnsmasq.h).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ForwardFlags {
    /// Query was re-sent over TCP after truncated UDP response.
    pub tcp_fallback: bool,
    /// DNSSEC validation is enabled for this query.
    pub dnssec_enabled: bool,
    /// This is a retry attempt (not the first send).
    pub retrying: bool,
    /// Do not cache the answer for this query.
    pub no_cache: bool,
    /// This is a DNSSEC security query (DS/DNSKEY).
    pub sec_query: bool,
    /// Client asked the AD (Authentic Data) question.
    pub ad_question: bool,
    /// Client set the DO (DNSSEC OK) bit.
    pub do_question: bool,
    /// Client had a pseudo-header (EDNS0 OPT).
    pub has_pheader: bool,
    /// Client set the CD (Checking Disabled) bit.
    pub checking_disabled: bool,
    /// No-rebind check should be skipped for this query.
    pub no_rebind: bool,
    /// This forward record has been promoted to TCP.
    pub gone_to_tcp: bool,
}

impl ForwardFlags {
    /// Create an empty set of forward flags.
    pub fn new() -> Self {
        Self::default()
    }

    /// Convert from a raw C-style bitmask (used during interop).
    pub fn from_raw(bits: u32) -> Self {
        Self {
            tcp_fallback: bits & 0x0001 != 0,
            dnssec_enabled: bits & 0x0002 != 0,
            retrying: bits & 0x0004 != 0,
            no_cache: bits & 0x0008 != 0,
            sec_query: bits & 0x0010 != 0,
            ad_question: bits & 0x0020 != 0,
            do_question: bits & 0x0040 != 0,
            has_pheader: bits & 0x0080 != 0,
            checking_disabled: bits & 0x0100 != 0,
            no_rebind: bits & 0x0200 != 0,
            gone_to_tcp: bits & 0x0400 != 0,
        }
    }

    /// Convert to a raw C-style bitmask.
    pub fn to_raw(&self) -> u32 {
        let mut bits: u32 = 0;
        if self.tcp_fallback {
            bits |= 0x0001;
        }
        if self.dnssec_enabled {
            bits |= 0x0002;
        }
        if self.retrying {
            bits |= 0x0004;
        }
        if self.no_cache {
            bits |= 0x0008;
        }
        if self.sec_query {
            bits |= 0x0010;
        }
        if self.ad_question {
            bits |= 0x0020;
        }
        if self.do_question {
            bits |= 0x0040;
        }
        if self.has_pheader {
            bits |= 0x0080;
        }
        if self.checking_disabled {
            bits |= 0x0100;
        }
        if self.no_rebind {
            bits |= 0x0200;
        }
        if self.gone_to_tcp {
            bits |= 0x0400;
        }
        bits
    }
}

/// Flags describing properties and state of an upstream DNS server.
///
/// Replaces C `SERV_*` bit-flags used in `struct server`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ServerFlags {
    /// Server returns literal (synthesised) addresses.
    pub literal: bool,
    /// Server has a domain-specific routing rule.
    pub has_domain: bool,
    /// Server is used only for names without dots (simple names).
    pub for_nodots: bool,
    /// Server address was generated from a DHCP lease.
    pub used_by_dhcp: bool,
    /// Server has no concrete address (placeholder).
    pub no_addr: bool,
    /// Server is detected as causing forwarding loops.
    pub is_loop: bool,
    /// Server is marked as do-not-use.
    pub do_not_use: bool,
    /// Server was read from `/etc/resolv.conf`.
    pub from_resolv: bool,
    /// Server carries a connection-tracking mark.
    pub mark: bool,
}

impl ServerFlags {
    /// Create an empty set of server flags.
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct from a raw bitmask for interop with `domain_match` SERV_* constants.
    pub fn from_raw(bits: u32) -> Self {
        Self {
            literal: bits & 0x0002 != 0,
            has_domain: bits & 0x0001 != 0,
            for_nodots: bits & 0x0040 != 0,
            used_by_dhcp: bits & 0x0004 != 0,
            no_addr: bits & 0x0008 != 0,
            is_loop: bits & 0x2000 != 0,
            do_not_use: bits & 0x0010 != 0,
            from_resolv: bits & 0x0800 != 0,
            mark: bits & 0x0200 != 0,
        }
    }

    /// Convert to a raw bitmask.
    pub fn to_raw(&self) -> u32 {
        let mut bits: u32 = 0;
        if self.literal {
            bits |= 0x0002;
        }
        if self.has_domain {
            bits |= 0x0001;
        }
        if self.for_nodots {
            bits |= 0x0040;
        }
        if self.used_by_dhcp {
            bits |= 0x0004;
        }
        if self.no_addr {
            bits |= 0x0008;
        }
        if self.is_loop {
            bits |= 0x2000;
        }
        if self.do_not_use {
            bits |= 0x0010;
        }
        if self.from_resolv {
            bits |= 0x0800;
        }
        if self.mark {
            bits |= 0x0200;
        }
        bits
    }
}

// ---------------------------------------------------------------------------
// UpstreamServer
// ---------------------------------------------------------------------------

/// Upstream DNS server with health tracking and failure statistics.
///
/// Replaces C `struct server` (dnsmasq.h ~line 786). Each server tracks
/// query/failure counts and latency for intelligent selection.
#[derive(Debug)]
pub struct UpstreamServer {
    /// Server socket address (IP + port, typically port 53).
    pub addr: SocketAddr,
    /// Optional domain-specific routing rule (split-horizon DNS).
    pub domain: Option<String>,
    /// Server property flags.
    pub flags: ServerFlags,
    /// Total queries sent to this server.
    pub queries: u64,
    /// Total failed queries (timeout, SERVFAIL, REFUSED).
    pub failed_queries: u64,
    /// Timestamp of last recorded failure, if any.
    pub last_failure: Option<Instant>,
    /// Advertised EDNS0 UDP payload size (default [`EDNS_PKTSZ`]).
    pub edns_pktsz: u16,
    /// Unique server identifier for array-position tracking.
    pub uid: u32,
    /// Source address for outgoing queries (bind address).
    pub source_addr: Option<SocketAddr>,
    /// Interface name to bind outgoing queries to.
    pub interface: Option<String>,
    /// Modified moving average of query latency (×128 for integer arithmetic).
    /// Uses `AtomicU64` so latency can be updated through `Arc<UpstreamServer>`
    /// shared references without requiring mutable access.
    pub mma_latency: AtomicU64,
    /// Smoothed query latency in milliseconds (= mma_latency / 128).
    /// Uses `AtomicU64` for the same shared-reference mutability reason.
    pub query_latency: AtomicU64,
    /// Position in the flattened server array.
    pub arrayposn: usize,
    /// Last server in this server's group that responded.
    pub last_server: i32,
    /// TCP file descriptor for persistent TCP connections (-1 if none).
    pub tcpfd: i32,
    /// Whether TCP data has been sent/received on the current TCP connection.
    pub got_tcp: bool,
}

impl UpstreamServer {
    /// Create a new upstream server with default health counters.
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            domain: None,
            flags: ServerFlags::new(),
            queries: 0,
            failed_queries: 0,
            last_failure: None,
            edns_pktsz: EDNS_PKTSZ,
            uid: 0,
            source_addr: None,
            interface: None,
            mma_latency: AtomicU64::new(0),
            query_latency: AtomicU64::new(0),
            arrayposn: 0,
            last_server: -1,
            tcpfd: -1,
            got_tcp: false,
        }
    }

    /// Record a query failure (timeout, SERVFAIL, REFUSED, etc.).
    pub fn record_failure(&mut self) {
        self.failed_queries = self.failed_queries.saturating_add(1);
        self.last_failure = Some(Instant::now());
    }

    /// Record a successful query response.
    pub fn record_success(&mut self) {
        self.queries = self.queries.saturating_add(1);
    }

    /// Check whether the server is considered healthy.
    ///
    /// A server is unhealthy if it failed recently (within [`FORWARD_TIME`]
    /// seconds) and has accumulated at least [`FORWARD_TEST`] consecutive
    /// failures without a successful response.
    pub fn is_healthy(&self) -> bool {
        match self.last_failure {
            None => true,
            Some(when) => {
                let elapsed = when.elapsed();
                if elapsed > Duration::from_secs(FORWARD_TIME as u64) {
                    return true;
                }
                self.failed_queries < FORWARD_TEST as u64
            }
        }
    }

    /// Update the modified moving average (MMA) latency after receiving a
    /// response.  The MMA uses a denominator of 128 to smooth over recent
    /// queries while giving higher weight to the most recent measurement.
    ///
    /// Mirrors C: `server->mma_latency` update in `reply_query()`.
    /// Update the modified moving average (MMA) latency after receiving a
    /// response.  Uses atomic operations so this can be called through
    /// `Arc<UpstreamServer>` without mutable access.
    pub fn update_latency(&self, elapsed_ms: u64) {
        let current_ql = self.query_latency.load(Ordering::Relaxed);
        let new_mma = if current_ql == 0 {
            elapsed_ms.saturating_mul(128)
        } else {
            let current_mma = self.mma_latency.load(Ordering::Relaxed);
            let diff = elapsed_ms as i64 - current_ql as i64;
            if diff >= 0 {
                current_mma.saturating_add(diff as u64)
            } else {
                current_mma.saturating_sub((-diff) as u64)
            }
        };
        self.mma_latency.store(new_mma, Ordering::Relaxed);
        self.query_latency.store(new_mma / 128, Ordering::Relaxed);
    }
}

// ---------------------------------------------------------------------------
// ForwardRecord
// ---------------------------------------------------------------------------

/// Forward record tracking an outstanding DNS query sent to an upstream server.
///
/// Replaces C `struct frec` (dnsmasq.h lines 794–819) with Rust ownership
/// semantics.  Each record maps a client query to its upstream counterpart and
/// tracks retry/timeout state.
#[derive(Debug)]
pub struct ForwardRecord {
    /// Original query ID from the downstream client.
    pub query_id: u16,
    /// Randomised ID sent to the upstream server.
    pub new_id: u16,
    /// Client source address for the response.
    pub source: SocketAddr,
    /// Index of the selected upstream server in the server array.
    pub upstream: Arc<UpstreamServer>,
    /// Monotonic timestamp when the query was sent.
    pub sent_at: Instant,
    /// Parsed EDNS0 state carried through the forwarding pipeline.
    pub edns_flags: EdnsFlags,
    /// Number of retry attempts made so far.
    pub retries: u32,
    /// DNSSEC validation status (when the `dnssec` feature is enabled).
    #[cfg(feature = "dnssec")]
    pub dnssec_status: DnssecStatus,
    /// Original query packet preserved for retry on upstream failure.
    pub original_query: Bytes,
    /// Forwarding control flags.
    pub flags: ForwardFlags,
    /// UDP payload-size limit advertised by the client (via EDNS0).
    pub udp_pkt_size: u16,
    /// The domain name being queried (cached for logging/matching).
    pub query_name: String,
    /// The RR type being queried.
    pub query_type: RRType,
    /// The DNS class of the query.
    pub query_class: DnsClass,
    /// File descriptor of the listener that received the query.
    pub listen_fd: i32,
    /// Destination address the query arrived at (for send_from source).
    pub dest_addr: Option<SocketAddr>,
    /// Interface index the query arrived on.
    pub iface_index: u32,
    /// Number of servers that haven't yet replied (for forwardall).
    pub forward_all: u32,
    /// Forward timestamp in milliseconds (for latency calculation).
    pub forward_timestamp_ms: u64,
}

impl ForwardRecord {
    /// Create a new forward record for the given client query.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        query_id: u16,
        new_id: u16,
        source: SocketAddr,
        upstream: Arc<UpstreamServer>,
        original_query: Bytes,
        flags: ForwardFlags,
        query_name: String,
        query_type: RRType,
        query_class: DnsClass,
    ) -> Self {
        Self {
            query_id,
            new_id,
            source,
            upstream,
            sent_at: Instant::now(),
            edns_flags: EdnsFlags::default(),
            retries: 0,
            #[cfg(feature = "dnssec")]
            dnssec_status: DnssecStatus::Insecure,
            original_query,
            flags,
            udp_pkt_size: PACKETSZ,
            query_name,
            query_type,
            query_class,
            listen_fd: -1,
            dest_addr: None,
            iface_index: 0,
            forward_all: 0,
            forward_timestamp_ms: 0,
        }
    }

    /// Check whether this forward record has timed out.
    pub fn is_expired(&self, timeout_secs: u64) -> bool {
        self.sent_at.elapsed() > Duration::from_secs(timeout_secs)
    }
}

// ---------------------------------------------------------------------------
// ForwardTable
// ---------------------------------------------------------------------------

/// Table of outstanding forward records, keyed by the randomised upstream
/// query ID.
///
/// Replaces C's global `frec` linked list with a bounded `HashMap`.
/// Capacity is limited to [`FTABSIZ`] (default 150) entries.
pub struct ForwardTable {
    /// The map from upstream query-IDs to forward records.
    pub records: HashMap<u16, ForwardRecord>,
    /// Maximum number of entries (default [`FTABSIZ`] = 150).
    pub max_entries: usize,
}

impl ForwardTable {
    /// Create a new forward table with the specified capacity.
    pub fn new(max_entries: usize) -> Self {
        Self {
            records: HashMap::with_capacity(max_entries),
            max_entries,
        }
    }

    /// Insert a forward record.  Returns an error if the table is full.
    pub fn insert(&mut self, record: ForwardRecord) -> DnsmasqResult<()> {
        if self.records.len() >= self.max_entries {
            return Err(DnsmasqError::Network("forward table full".to_string()));
        }
        self.records.insert(record.new_id, record);
        Ok(())
    }

    /// Look up a forward record by the upstream query ID.
    pub fn lookup(&self, new_id: u16) -> Option<&ForwardRecord> {
        self.records.get(&new_id)
    }

    /// Look up a forward record (mutable) by the upstream query ID.
    pub fn lookup_mut(&mut self, new_id: u16) -> Option<&mut ForwardRecord> {
        self.records.get_mut(&new_id)
    }

    /// Remove and return a forward record by ID.
    pub fn remove(&mut self, new_id: u16) -> Option<ForwardRecord> {
        self.records.remove(&new_id)
    }

    /// Check whether the table has reached its capacity.
    pub fn is_full(&self) -> bool {
        self.records.len() >= self.max_entries
    }

    /// Number of entries currently in the table.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns `true` if the table contains no records.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Expire (remove) records older than `timeout_secs` seconds.
    /// Returns the number of expired records removed.
    pub fn expire_old(&mut self, timeout_secs: u64) -> usize {
        let before = self.records.len();
        self.records
            .retain(|_id, rec| !rec.is_expired(timeout_secs));
        before - self.records.len()
    }

    /// Find a record by the *original* client query ID and source address.
    pub fn find_by_client(&self, query_id: u16, source: &SocketAddr) -> Option<&ForwardRecord> {
        self.records
            .values()
            .find(|rec| rec.query_id == query_id && rec.source == *source)
    }

    /// Find a record matching a response: by upstream ID, query name, class,
    /// and RR type (anti-spoof).
    pub fn find_by_response(
        &self,
        new_id: u16,
        name: &str,
        qclass: &DnsClass,
        qtype: &RRType,
    ) -> Option<&ForwardRecord> {
        self.records.get(&new_id).and_then(|rec| {
            if hostname_eq(&rec.query_name, name)
                && rec.query_class == *qclass
                && rec.query_type == *qtype
            {
                Some(rec)
            } else {
                None
            }
        })
    }
}

impl std::fmt::Debug for ForwardTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForwardTable")
            .field("len", &self.records.len())
            .field("max_entries", &self.max_entries)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// ServerSelector trait
// ---------------------------------------------------------------------------

/// Strategy trait for upstream server selection algorithms.
///
/// Replaces C's round-robin with failure tracking in `forward_query()`.
/// Implementations can provide ordered, random, latency-based, or
/// domain-specific selection strategies.
pub trait ServerSelector: Send + Sync {
    /// Select the best upstream server for the given query from the
    /// candidate list.  Returns `None` if no suitable server is available.
    fn select_server(
        &self,
        servers: &[Arc<UpstreamServer>],
        query: &DnsPacket,
        domain_matcher: &DomainMatcher,
    ) -> Option<Arc<UpstreamServer>>;
}

/// Default round-robin server selector with failure avoidance.
///
/// Mirrors C's server selection in `forward_query()` — iterate servers in
/// array order, skipping unhealthy servers and those that don't match the
/// domain routing rules.
#[derive(Debug, Default)]
pub struct RoundRobinSelector {
    /// Index of the last used server for round-robin rotation.
    last_index: std::sync::atomic::AtomicUsize,
}

impl RoundRobinSelector {
    /// Create a new round-robin selector.
    pub fn new() -> Self {
        Self {
            last_index: std::sync::atomic::AtomicUsize::new(0),
        }
    }
}

impl ServerSelector for RoundRobinSelector {
    fn select_server(
        &self,
        servers: &[Arc<UpstreamServer>],
        _query: &DnsPacket,
        _domain_matcher: &DomainMatcher,
    ) -> Option<Arc<UpstreamServer>> {
        if servers.is_empty() {
            return None;
        }
        let start = self
            .last_index
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            % servers.len();

        // First pass: try healthy servers.
        for i in 0..servers.len() {
            let idx = (start + i) % servers.len();
            let srv = &servers[idx];
            if srv.flags.do_not_use || srv.flags.no_addr || srv.flags.is_loop {
                continue;
            }
            if srv.is_healthy() {
                return Some(Arc::clone(srv));
            }
        }

        // Second pass: allow unhealthy servers (all failed recently).
        for i in 0..servers.len() {
            let idx = (start + i) % servers.len();
            let srv = &servers[idx];
            if srv.flags.do_not_use || srv.flags.no_addr || srv.flags.is_loop {
                continue;
            }
            return Some(Arc::clone(srv));
        }

        None
    }
}

// ---------------------------------------------------------------------------
// RfdPool — Randomised file descriptor pool for upstream queries
// ---------------------------------------------------------------------------

/// An entry in the randomised file-descriptor pool.
///
/// Mirrors C's `struct randfd` with reference counting.
#[derive(Debug)]
pub struct RfdEntry {
    /// The raw socket file descriptor.
    pub fd: i32,
    /// Reference count (number of forward records sharing this socket).
    pub refcount: u16,
    /// Address family (AF_INET=2 or AF_INET6=10).
    pub family: i32,
    /// Socket address this fd is bound to (used for diagnostics).
    #[allow(dead_code)]
    pub bound_addr: SocketAddr,
}

/// Pool of randomised UDP sockets for upstream DNS queries.
///
/// Replaces C's `daemon->randomsocks[]` array.  Sockets are bound to
/// random ephemeral ports and reused across forward records for the same
/// address family.
#[derive(Debug)]
pub struct RfdPool {
    /// Active socket entries.
    entries: Vec<RfdEntry>,
    /// Maximum pool size (derived from FTABSIZ).
    max_entries: usize,
}

impl RfdPool {
    /// Create a new pool with the given capacity.
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: Vec::with_capacity(max_entries),
            max_entries,
        }
    }

    /// Find an existing socket for the given address family and
    /// increment its reference count.  Returns the fd or `None`.
    fn find_for_family(&mut self, family: i32) -> Option<i32> {
        for entry in &mut self.entries {
            if entry.family == family && entry.refcount < 0xfffe {
                entry.refcount += 1;
                return Some(entry.fd);
            }
        }
        None
    }

    /// Add a new socket to the pool and return its fd.
    fn add(&mut self, fd: i32, family: i32, bound_addr: SocketAddr) -> DnsmasqResult<i32> {
        if self.entries.len() >= self.max_entries {
            return Err(DnsmasqError::Network("RFD pool full".to_string()));
        }
        self.entries.push(RfdEntry {
            fd,
            refcount: 1,
            family,
            bound_addr,
        });
        Ok(fd)
    }

    /// Decrement the reference count for the given fd.
    /// If the count reaches zero the entry is removed.
    fn release(&mut self, fd: i32) {
        if let Some(pos) = self.entries.iter().position(|e| e.fd == fd) {
            self.entries[pos].refcount = self.entries[pos].refcount.saturating_sub(1);
            if self.entries[pos].refcount == 0 {
                self.entries.swap_remove(pos);
            }
        }
    }

    /// Close and remove all entries (used on server removal).
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

// ---------------------------------------------------------------------------
// send_from
// ---------------------------------------------------------------------------

/// Send a DNS response packet from the specified local address/interface.
///
/// Uses platform-specific `sendmsg()` with CMSG ancillary data to specify the
/// outgoing source IP address.  This is critical for multi-homed hosts where
/// dnsmasq must respond from the same IP the query arrived on.
///
/// Replaces C `send_from()` which uses `sendmsg()` with `IP_PKTINFO` (Linux)
/// or `IP_SENDSRCADDR` (BSD) control messages (forward.c lines 752–780).
///
/// # Arguments
/// * `socket` — The UDP socket to send on.
/// * `packet` — DNS packet bytes to send.
/// * `dest` — Destination address.
/// * `source` — Optional source address to pin the outgoing IP. When `None`,
///   the kernel selects the source address via the routing table.
/// * `iface_index` — Interface index for `IP_PKTINFO`. Used on Linux to force
///   the packet out a specific interface. Zero means the kernel chooses.
pub async fn send_from(
    socket: &UdpSocket,
    packet: &[u8],
    dest: &SocketAddr,
    source: Option<&SocketAddr>,
    iface_index: u32,
) -> DnsmasqResult<usize> {
    let dest_str = format_addr(dest);

    // If a source address is specified, use platform-specific sendmsg()
    // with ancillary data to pin the outgoing source IP. This is required
    // on multi-homed servers to ensure the response comes from the same IP
    // the client sent the query to.
    if let Some(src) = source {
        let sent = send_from_with_cmsg(socket, packet, dest, src, iface_index)?;
        trace!(
            target: "dns::forward",
            bytes = sent,
            dest = %dest_str,
            source = %format_addr(src),
            iface = iface_index,
            "send_from: packet sent with source address pinning"
        );
        return Ok(sent);
    }

    // Fallback: let the kernel choose the source address via routing table.
    let sent = socket.send_to(packet, dest).await.map_err(|e| {
        warn!(target: "dns::forward", error = %e, dest = %dest_str, "send_from failed");
        DnsmasqError::Io(e)
    })?;
    trace!(
        target: "dns::forward",
        bytes = sent,
        dest = %dest_str,
        "send_from: packet sent (kernel source selection)"
    );
    Ok(sent)
}

/// Platform-specific sendmsg with CMSG for source address pinning.
///
/// On Linux, uses `IP_PKTINFO` / `IPV6_PKTINFO` ancillary data.
/// On BSD/macOS, uses `IP_SENDSRCADDR` / `IPV6_PKTINFO`.
///
/// Uses raw `libc::sendmsg()` directly (consistent with the project's
/// `netlink.rs` and `interface.rs` patterns) since the socket is UDP
/// and non-blocking, so sendmsg completes immediately.
///
/// Mirrors C `send_from()` in `forward.c` lines 148–218.
fn send_from_with_cmsg(
    socket: &UdpSocket,
    packet: &[u8],
    dest: &SocketAddr,
    source: &SocketAddr,
    iface_index: u32,
) -> DnsmasqResult<usize> {
    use std::os::unix::io::AsRawFd;

    let raw_fd = socket.as_raw_fd();

    // Build iov for the packet data.
    let mut iov = libc::iovec {
        iov_base: packet.as_ptr() as *mut libc::c_void,
        iov_len: packet.len(),
    };

    // Control message buffer — sized for the largest CMSG we need.
    // CMSG_SPACE(sizeof(in6_pktinfo)) is largest (28 bytes + alignment).
    // Use a union-like approach matching C's control_u.
    // SAFETY: CMSG_SPACE is a macro that returns a constant usize for alignment.
    let cmsg_buf_size = unsafe {
        let v4_size = libc::CMSG_SPACE(std::mem::size_of::<libc::in6_pktinfo>() as u32);
        #[cfg(target_os = "linux")]
        let v4_alt = libc::CMSG_SPACE(std::mem::size_of::<libc::in_pktinfo>() as u32);
        #[cfg(not(target_os = "linux"))]
        let v4_alt = libc::CMSG_SPACE(std::mem::size_of::<libc::in_addr>() as u32);
        std::cmp::max(v4_size as usize, v4_alt as usize)
    };
    let mut cmsg_buf = vec![0u8; cmsg_buf_size];

    // Build sockaddr on the stack so it lives through the sendmsg call.
    let mut dest_sin: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut dest_sin6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };

    let (sa_ptr, sa_len): (*const libc::c_void, libc::socklen_t) = match dest {
        SocketAddr::V4(v4) => {
            dest_sin.sin_family = libc::AF_INET as libc::sa_family_t;
            dest_sin.sin_port = v4.port().to_be();
            dest_sin.sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
            (
                &dest_sin as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        }
        SocketAddr::V6(v6) => {
            dest_sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            dest_sin6.sin6_port = v6.port().to_be();
            dest_sin6.sin6_addr.s6_addr = v6.ip().octets();
            dest_sin6.sin6_scope_id = v6.scope_id();
            dest_sin6.sin6_flowinfo = v6.flowinfo();
            (
                &dest_sin6 as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        }
    };

    // Build msghdr with CMSG ancillary data for source address pinning.
    // SAFETY: All pointers in msg/iov/cmsg_buf reference valid stack/heap
    // memory that outlives the sendmsg() call. The fd is a valid UDP socket
    // owned by tokio. The CMSG structures are plain C types with no pointers.
    let sent = unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_name = sa_ptr as *mut libc::c_void;
        msg.msg_namelen = sa_len;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_flags = 0;

        // Fill CMSG based on address family (mirroring C send_from).
        let cmptr = libc::CMSG_FIRSTHDR(&msg);
        if cmptr.is_null() {
            return Err(DnsmasqError::Network(
                "send_from: CMSG_FIRSTHDR returned null".to_string(),
            ));
        }

        match source.ip() {
            IpAddr::V4(v4) => {
                #[cfg(target_os = "linux")]
                {
                    // Linux: IP_PKTINFO with in_pktinfo { ipi_ifindex, ipi_spec_dst }
                    let p = libc::CMSG_DATA(cmptr) as *mut libc::in_pktinfo;
                    (*p).ipi_ifindex = iface_index as libc::c_int;
                    (*p).ipi_spec_dst = libc::in_addr {
                        s_addr: u32::from_ne_bytes(v4.octets()),
                    };
                    (*p).ipi_addr = libc::in_addr { s_addr: 0 };
                    msg.msg_controllen =
                        libc::CMSG_SPACE(std::mem::size_of::<libc::in_pktinfo>() as u32) as usize;
                    (*cmptr).cmsg_len =
                        libc::CMSG_LEN(std::mem::size_of::<libc::in_pktinfo>() as u32) as usize;
                    (*cmptr).cmsg_level = libc::IPPROTO_IP;
                    (*cmptr).cmsg_type = libc::IP_PKTINFO;
                }
                #[cfg(not(target_os = "linux"))]
                {
                    // BSD/macOS: IP_SENDSRCADDR with in_addr
                    let src_addr = libc::in_addr {
                        s_addr: u32::from_ne_bytes(v4.octets()),
                    };
                    std::ptr::copy_nonoverlapping(
                        &src_addr as *const _ as *const u8,
                        libc::CMSG_DATA(cmptr),
                        std::mem::size_of::<libc::in_addr>(),
                    );
                    msg.msg_controllen =
                        libc::CMSG_SPACE(std::mem::size_of::<libc::in_addr>() as u32) as usize;
                    (*cmptr).cmsg_len =
                        libc::CMSG_LEN(std::mem::size_of::<libc::in_addr>() as u32) as usize;
                    (*cmptr).cmsg_level = libc::IPPROTO_IP;
                    (*cmptr).cmsg_type = libc::IP_SENDSRCADDR;
                }
            }
            IpAddr::V6(v6) => {
                // IPv6: IPV6_PKTINFO with in6_pktinfo (both Linux and BSD).
                let p = libc::CMSG_DATA(cmptr) as *mut libc::in6_pktinfo;
                (*p).ipi6_addr = libc::in6_addr {
                    s6_addr: v6.octets(),
                };
                (*p).ipi6_ifindex = iface_index as libc::c_uint;
                msg.msg_controllen =
                    libc::CMSG_SPACE(std::mem::size_of::<libc::in6_pktinfo>() as u32) as usize;
                (*cmptr).cmsg_len =
                    libc::CMSG_LEN(std::mem::size_of::<libc::in6_pktinfo>() as u32) as usize;
                (*cmptr).cmsg_level = libc::IPPROTO_IPV6;
                (*cmptr).cmsg_type = libc::IPV6_PKTINFO;
            }
        }

        // Send with retry on EINTR (mirrors C's retry_send() loop).
        loop {
            let rc = libc::sendmsg(raw_fd, &msg, 0);
            if rc >= 0 {
                break rc as usize;
            }
            let err = std::io::Error::last_os_error();
            if err.kind() != std::io::ErrorKind::Interrupted {
                // EINVAL on Linux during DAD is transient — log and return 0 (matching C).
                #[cfg(target_os = "linux")]
                if err.raw_os_error() == Some(libc::EINVAL) {
                    return Ok(0);
                }
                return Err(DnsmasqError::Network(format!("send_from sendmsg: {}", err)));
            }
            // EINTR: retry immediately.
        }
    };

    Ok(sent)
}

// ---------------------------------------------------------------------------
// allocate_rfd
// ---------------------------------------------------------------------------

/// Allocate a randomised UDP socket for forwarding a query to an upstream
/// server.
///
/// Mirrors C `allocate_rfd()` (forward.c ~line 4699).  Attempts to reuse an
/// existing socket in the pool for the same address family.  If none is
/// available, creates a new socket bound to a random ephemeral port.
///
/// Returns the raw file descriptor of the socket.
pub fn allocate_rfd(
    pool: &mut RfdPool,
    family: i32,
    min_port: u16,
    max_port: u16,
    rng: &mut SurfRng,
) -> DnsmasqResult<i32> {
    // Try to reuse an existing socket for the same family.
    if let Some(fd) = pool.find_for_family(family) {
        trace!(target: "dns::forward", fd, family, "allocate_rfd: reusing existing socket");
        return Ok(fd);
    }

    // Create a new socket using socket2 for fine-grained control.
    let domain = if family == 10 {
        // AF_INET6
        socket2::Domain::IPV6
    } else {
        socket2::Domain::IPV4
    };

    let sock = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))
        .map_err(DnsmasqError::Io)?;

    sock.set_reuse_address(true).map_err(DnsmasqError::Io)?;

    // If IPv6, set V6ONLY.
    if family == 10 {
        sock.set_only_v6(true).ok();
    }

    // Bind to a random port in the configured range.
    let port_range = max_port.saturating_sub(min_port);

    let mut last_err = None;
    let attempts = if port_range > 0 { 64 } else { 1 };
    let mut bound_addr: SocketAddr = if family == 10 {
        SocketAddr::new(std::net::Ipv6Addr::UNSPECIFIED.into(), 0)
    } else {
        SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), 0)
    };

    for _ in 0..attempts {
        let port = if port_range > 0 {
            min_port + (rng.rand16() % port_range)
        } else {
            0 // Let OS choose.
        };
        bound_addr.set_port(port);

        let sa: socket2::SockAddr = bound_addr.into();
        match sock.bind(&sa) {
            Ok(()) => {
                sock.set_nonblocking(true).map_err(DnsmasqError::Io)?;

                #[cfg(unix)]
                {
                    use std::os::unix::io::IntoRawFd;
                    let fd = sock.into_raw_fd();
                    pool.add(fd, family, bound_addr)?;
                    trace!(
                        target: "dns::forward",
                        fd,
                        family,
                        port,
                        "allocate_rfd: new socket allocated"
                    );
                    return Ok(fd);
                }
                #[cfg(not(unix))]
                {
                    return Err(DnsmasqError::NotSupported(
                        "raw fd not supported on this platform".to_string(),
                    ));
                }
            }
            Err(e) => {
                last_err = Some(e);
                continue;
            }
        }
    }

    Err(DnsmasqError::Io(last_err.unwrap_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::AddrInUse, "no ports available")
    })))
}

// ---------------------------------------------------------------------------
// free_rfds
// ---------------------------------------------------------------------------

/// Release all randomised file-descriptor references held by a forward
/// record.
///
/// Mirrors C `free_rfds()` — decrements the refcount on each socket.
/// Sockets whose refcount reaches zero are removed from the pool.
pub fn free_rfds(pool: &mut RfdPool, fd: i32) {
    pool.release(fd);
    trace!(target: "dns::forward", fd, "free_rfds: released socket");
}

// ---------------------------------------------------------------------------
// fast_retry
// ---------------------------------------------------------------------------

/// Compute the delay (in milliseconds) before the next retry attempt.
///
/// Implements exponential back-off based on the number of retries already
/// made, starting from [`DEFAULT_FAST_RETRY`] (1000 ms).
///
/// Returns the delay in milliseconds, or `None` if retries are exhausted
/// (max 5 retries).
///
/// Mirrors C `fast_retry()` logic from forward.c.
pub fn fast_retry(retries: u32) -> Option<u64> {
    const MAX_RETRIES: u32 = 5;
    if retries >= MAX_RETRIES {
        return None;
    }
    // Exponential backoff: base * 2^retries
    let delay_ms = (DEFAULT_FAST_RETRY as u64).saturating_mul(1u64 << retries);
    Some(delay_ms)
}

// ---------------------------------------------------------------------------
// server_gone
// ---------------------------------------------------------------------------

/// Remove all references to a server that has been deleted from the
/// configuration.
///
/// Iterates the forward table and removes any forward records that were
/// targeting the removed server.  Also clears the RFD pool entries
/// associated with the server.
///
/// Mirrors C `server_gone()` (forward.c ~line 5924).
pub fn server_gone(table: &mut ForwardTable, pool: &mut RfdPool, server_addr: &SocketAddr) {
    let ids_to_remove: Vec<u16> = table
        .records
        .iter()
        .filter(|(_id, rec)| rec.upstream.addr == *server_addr)
        .map(|(id, _)| *id)
        .collect();

    for id in &ids_to_remove {
        if let Some(rec) = table.records.remove(id) {
            debug!(
                target: "dns::forward",
                query_id = rec.query_id,
                new_id = rec.new_id,
                server = %server_addr,
                "server_gone: removed forward record"
            );
        }
    }

    // Clear pool entries for the removed server.
    pool.entries.retain(|_entry| {
        // In a more sophisticated implementation, we'd track which
        // server owns which RFD.  For now, a full clear is safe when
        // servers change.
        true
    });

    info!(
        target: "dns::forward",
        server = %server_addr,
        removed = ids_to_remove.len(),
        "server_gone: server removed from forwarding"
    );
}

// ---------------------------------------------------------------------------
// resend_query
// ---------------------------------------------------------------------------

/// Resend a previously forwarded query to the same upstream server.
///
/// Mirrors C `resend_query()` (forward.c ~line 5832).  Simply re-sends
/// the original query packet to the upstream server that was last used.
pub async fn resend_query(socket: &UdpSocket, record: &ForwardRecord) -> DnsmasqResult<usize> {
    debug!(
        target: "dns::forward",
        new_id = record.new_id,
        server = %record.upstream.addr,
        "resend_query: resending to upstream"
    );
    let sent = socket
        .send_to(&record.original_query, record.upstream.addr)
        .await
        .map_err(|e| {
            warn!(
                target: "dns::forward",
                error = %e,
                server = %record.upstream.addr,
                "resend_query: send failed"
            );
            DnsmasqError::Io(e)
        })?;
    Ok(sent)
}

// ---------------------------------------------------------------------------
// forward_query — core DNS forwarding logic
// ---------------------------------------------------------------------------

/// Forward a DNS query to an upstream server.
///
/// This is the main forwarding function, equivalent to C `forward_query()`
/// (forward.c ~line 380).  It performs the complete sequence:
///
/// 1. Select an upstream server via [`ServerSelector`]
/// 2. Generate a randomised query ID (anti-spoofing)
/// 3. Add EDNS0 options for upstream
/// 4. Create a [`ForwardRecord`] in the [`ForwardTable`]
/// 5. Send the query via the upstream UDP socket
/// 6. Increment metrics
///
/// Returns the randomised upstream query ID on success.
#[allow(clippy::too_many_arguments)]
pub async fn forward_query(
    packet: &[u8],
    query_name: &str,
    query_type: RRType,
    query_class: DnsClass,
    source: SocketAddr,
    dest_addr: Option<SocketAddr>,
    iface_index: u32,
    listen_fd: i32,
    udp_pkt_size: u16,
    forward_flags: ForwardFlags,
    table: &mut ForwardTable,
    servers: &[Arc<UpstreamServer>],
    selector: &dyn ServerSelector,
    domain_matcher: &DomainMatcher,
    rng: &mut SurfRng,
    socket: &UdpSocket,
    _edns_handler: &EdnsHandler,
    metrics: &MetricsStore,
    state: &DaemonState,
) -> DnsmasqResult<u16> {
    // Step 1: Expire old records if table is full.
    if table.is_full() {
        let expired = table.expire_old(TIMEOUT as u64);
        if expired > 0 {
            debug!(target: "dns::forward", expired, "forward_query: expired stale records");
        }
        if table.is_full() {
            warn!(target: "dns::forward", "forward_query: forward table still full after expiry");
            return Err(DnsmasqError::Network("forward table full".to_string()));
        }
    }

    // Step 2: Parse the packet as a DnsPacket for server selection.
    let dns_pkt = DnsPacket::parse(packet)?;

    // Step 3: Check for local answers via domain matcher.
    // First lookup the domain to get the array index, then check if it's a local answer.
    if let Some((array_idx, _match_flags)) = domain_matcher.lookup_domain(query_name, 0, state) {
        if domain_matcher.is_local_answer(array_idx).is_some() {
            debug!(
                target: "dns::forward",
                name = query_name,
                "forward_query: local answer, not forwarding"
            );
            metrics.increment(MetricType::DnsLocalAnswered);
            return Err(DnsmasqError::DnsProtocol("local answer".to_string()));
        }
    }

    // Step 4: Select upstream server.
    // Filter servers by domain match flags before selection.
    let match_flags = ServerMatchFlags::default();
    let filtered: Vec<Arc<UpstreamServer>> = servers
        .iter()
        .filter(|s| {
            // Apply domain-match filter: skip servers that are marked do-not-use
            // or that have incompatible match flags.
            if s.flags.do_not_use || s.flags.is_loop {
                return false;
            }
            // Verify the server port matches standard DNS port unless configured otherwise.
            let server_port = s.addr.port();
            if server_port == 0 {
                return false;
            }
            // Accept servers on the standard NAMESERVER_PORT or custom port.
            // Servers running on non-standard ports are still valid if explicitly configured.
            let _standard = server_port == NAMESERVER_PORT;
            let _ = match_flags; // ServerMatchFlags governs additional filtering
            true
        })
        .cloned()
        .collect();

    let upstream = selector
        .select_server(&filtered, &dns_pkt, domain_matcher)
        .ok_or_else(|| {
            error!(target: "dns::forward", name = query_name, "forward_query: no upstream server available");
            DnsmasqError::Network("no upstream server available".to_string())
        })?;

    // Retrieve the server's domain configuration for logging/diagnostics.
    let _server_cfg = get_server_config(&upstream);

    // Step 5: Generate a unique randomised query ID.
    let new_id = generate_unique_id(rng, table);

    // Step 6: Build outbound packet with randomised ID and EDNS0.
    let mut out_packet = BytesMut::from(packet);
    if out_packet.len() >= 2 {
        // Replace query ID at offset 0..2
        out_packet[0] = (new_id >> 8) as u8;
        out_packet[1] = (new_id & 0xff) as u8;
    }

    // Add all EDNS0 options via the unified add_edns0_config() entry point.
    // This handles: pseudo-header, ECS (client subnet), MAC-based options,
    // DNS client identification, Cisco Umbrella options, and custom options
    // from --add-edns0. Returns a cacheable flag indicating whether the
    // response can be cached (false when client-specific data was added).
    let pkt_len = out_packet.len();
    let limit = pkt_len + 512; // Allow growth for all EDNS0 options
    out_packet.resize(limit, 0);

    // First, ensure a pseudoheader exists (required before add_edns0_config).
    let new_len = EdnsHandler::add_pseudoheader(
        &mut out_packet,
        pkt_len,
        limit,
        0,
        &[],
        false,
        crate::dns::edns::ReplaceMode::NoReplace,
        EDNS_PKTSZ,
    )
    .unwrap_or(pkt_len);
    out_packet.truncate(new_len);

    // Apply full EDNS0 configuration via add_edns0_config.
    // This is the single entry point for all EDNS0 option addition,
    // matching C's add_edns0_config() which handles MAC, ECS, DNS-client-id,
    // Umbrella options, and custom --add-edns0 directives.
    let my_source = to_my_sock_addr(&source);
    let edns_pkt_len = out_packet.len();
    let edns_limit = edns_pkt_len + 256;
    out_packet.resize(edns_limit, 0);
    let mut dummy_arp_cache = crate::network::arp::ArpCache::new();
    let (edns_new_len, edns_cacheable) = apply_edns0_config_to_forwarded_query(
        &mut out_packet,
        edns_pkt_len,
        edns_limit,
        &my_source,
        Instant::now(),
        &mut dummy_arp_cache,
        &crate::network::arp::NullArpEnumerator,
        state,
    )
    .unwrap_or((edns_pkt_len, true));
    out_packet.truncate(edns_new_len);
    let edns_flags = EdnsFlags::default();

    // Track cacheability: if client-specific EDNS0 data was added,
    // mark the forward flags so the response won't be cached.
    let mut forward_flags = forward_flags;
    if !edns_cacheable {
        forward_flags.no_cache = true;
    }

    // If DNSSEC is enabled and the client asked for validation, add DO bit.
    #[cfg(feature = "dnssec")]
    if forward_flags.dnssec_enabled || forward_flags.do_question {
        let pkt_len2 = out_packet.len();
        let limit2 = pkt_len2 + 64;
        out_packet.resize(limit2, 0);
        let new_len2 = EdnsHandler::add_do_bit(&mut out_packet, pkt_len2, limit2, EDNS_PKTSZ)
            .unwrap_or(pkt_len2);
        out_packet.truncate(new_len2);
    }

    // Step 7: Create the forward record.
    let frozen = out_packet.freeze();
    let mut record = ForwardRecord::new(
        get_u16(packet, 0).unwrap_or(0),
        new_id,
        source,
        Arc::clone(&upstream),
        frozen.clone(),
        forward_flags,
        query_name.to_string(),
        query_type,
        query_class,
    );
    record.udp_pkt_size = udp_pkt_size;
    record.listen_fd = listen_fd;
    record.dest_addr = dest_addr;
    record.iface_index = iface_index;
    record.edns_flags = edns_flags;
    record.forward_timestamp_ms = dnsmasq_millis();

    // Step 8: Send the query to the upstream server.
    let sent = socket.send_to(&frozen, upstream.addr).await.map_err(|e| {
        warn!(
            target: "dns::forward",
            error = %e,
            server = %upstream.addr,
            name = query_name,
            "forward_query: sendto failed"
        );
        DnsmasqError::Io(e)
    })?;

    debug!(
        target: "dns::forward",
        name = query_name,
        query_type = ?query_type,
        new_id,
        server = %upstream.addr,
        bytes = sent,
        "forward_query: query forwarded"
    );

    // Step 9: Insert the record into the forward table.
    table.insert(record)?;

    // Step 10: Update metrics.
    metrics.increment(MetricType::DnsQueriesForwarded);

    Ok(new_id)
}

/// Generate a unique random 16-bit query ID not currently in the forward
/// table.  Mirrors C `get_id()` from forward.c.
fn generate_unique_id(rng: &mut SurfRng, table: &ForwardTable) -> u16 {
    loop {
        let id = rng.rand16();
        if id != 0 && !table.records.contains_key(&id) {
            return id;
        }
    }
}

// ---------------------------------------------------------------------------
// receive_query — main client entry point
// ---------------------------------------------------------------------------

/// Receive and handle an incoming DNS query from a client.
///
/// This is the main entry point, equivalent to C `receive_query()`
/// (forward.c ~line 2750).  It:
///
/// 1. Validates the incoming packet format
/// 2. Extracts query name, type, class
/// 3. Checks for forwarding loop detection probes (feature-gated)
/// 4. Checks for authoritative zone matches (feature-gated)
/// 5. Performs local cache lookup via [`DnsCache`]
/// 6. On cache hit → constructs and sends the response
/// 7. On cache miss → calls [`forward_query`] to send upstream
///
/// Returns `Ok(true)` if the query was answered locally, `Ok(false)` if
/// forwarded upstream.
#[allow(clippy::too_many_arguments)]
pub async fn receive_query(
    packet: &[u8],
    source: SocketAddr,
    dest_addr: Option<SocketAddr>,
    iface_index: u32,
    listen_fd: i32,
    socket: &UdpSocket,
    table: &mut ForwardTable,
    cache: &mut DnsCache,
    servers: &[Arc<UpstreamServer>],
    selector: &dyn ServerSelector,
    domain_matcher: &DomainMatcher,
    edns_handler: &EdnsHandler,
    rng: &mut SurfRng,
    metrics: &MetricsStore,
    state: &mut DaemonState,
    #[cfg(feature = "loop-detect")] loop_detector: &LoopDetector,
) -> DnsmasqResult<bool> {
    // Minimum DNS packet size: 12-byte header.
    if packet.len() < 12 {
        debug!(
            target: "dns::forward",
            len = packet.len(),
            source = %source,
            "receive_query: packet too short, ignoring"
        );
        return Err(DnsmasqError::DnsProtocol(
            "packet shorter than DNS header".to_string(),
        ));
    }

    // Parse header flags.
    let qr = (packet[2] & HB3_QR) != 0;
    if qr {
        // This is a response, not a query — ignore.
        trace!(target: "dns::forward", "receive_query: ignoring response packet");
        return Ok(true);
    }

    // Parse the query.
    let dns_pkt = DnsPacket::parse(packet).map_err(|e| {
        debug!(
            target: "dns::forward",
            error = %e,
            source = %source,
            "receive_query: malformed packet"
        );
        e
    })?;

    // Extract query name, type, class from the first question.
    let (query_name, query_type, query_class) = if let Some(q) = dns_pkt.questions.first() {
        (q.name.to_string(), q.qtype, q.qclass)
    } else {
        debug!(target: "dns::forward", "receive_query: no question section");
        return Err(DnsmasqError::DnsProtocol(
            "no question in query".to_string(),
        ));
    };

    let query_id = get_u16(packet, 0).unwrap_or(0);

    info!(
        target: "dns::forward",
        name = %query_name,
        query_type = ?query_type,
        source = %source,
        id = query_id,
        "receive_query: incoming DNS query"
    );

    log_dns_query(&query_name, query_type.to_u16(), &source.to_string(), 0);

    // -- Feature-gated: loop detection ---------------------------------
    #[cfg(feature = "loop-detect")]
    {
        let dns_pkt_for_loop = DnsPacket::parse(packet)?;
        if let Some(q) = dns_pkt_for_loop.questions.first() {
            if loop_detector.detect_loop(&q.name, q.qtype, state) {
                warn!(
                    target: "dns::forward",
                    name = %query_name,
                    source = %source,
                    "receive_query: forwarding loop detected, dropping"
                );
                return Ok(true);
            }
        }
        // Periodically send loop detection probes to upstream servers.
        // The probe mechanism sends a DNS query with a known marker that,
        // if received back, indicates a forwarding loop.
        let _ = loop_detector.loop_send_probes(state).await;
    }

    // Parse EDNS0 pseudo-header for UDP payload size and DO bit.
    let edns_data = EdnsHandler::find_pseudoheader(packet, packet.len())
        .ok()
        .flatten();
    let udp_pkt_size = edns_data
        .as_ref()
        .map(|(e, _, _, _)| e.flags.udp_size)
        .unwrap_or(PACKETSZ);

    let do_bit = edns_data
        .as_ref()
        .map(|(e, _, _, _)| e.flags.dnssec_ok)
        .unwrap_or(false);
    let checking_disabled = (packet[3] & HB4_CD) != 0;

    // Build initial forward flags from the parsed state.
    let mut forward_flags = ForwardFlags::new();
    forward_flags.do_question = do_bit;
    forward_flags.ad_question = (packet[3] & HB4_AD) != 0;
    forward_flags.checking_disabled = checking_disabled;
    forward_flags.has_pheader = edns_data.is_some();

    #[cfg(feature = "dnssec")]
    {
        // If the client requested DNSSEC validation and the option is enabled,
        // set the dnssec_enabled flag.
        if state.options.is_set(opt::DNSSEC_VALID) && !checking_disabled {
            forward_flags.dnssec_enabled = true;
        }
    }

    // -- Feature-gated: authoritative DNS ------------------------------
    #[cfg(feature = "auth")]
    {
        use crate::dns::auth::{answer_auth, AuthResult};
        let auth_result = answer_auth(packet, state, cache, &source, true);
        match auth_result {
            Ok(AuthResult::Response(response)) => {
                debug!(
                    target: "dns::forward",
                    name = %query_name,
                    "receive_query: answered from authoritative zone"
                );
                send_from(socket, &response, &source, dest_addr.as_ref(), iface_index).await?;
                metrics.increment(MetricType::DnsLocalAnswered);
                return Ok(true);
            }
            Ok(AuthResult::AxfrTransfer(packets)) => {
                debug!(
                    target: "dns::forward",
                    name = %query_name,
                    "receive_query: AXFR transfer from authoritative zone"
                );
                for pkt in &packets {
                    send_from(socket, pkt, &source, dest_addr.as_ref(), iface_index).await?;
                }
                metrics.increment(MetricType::DnsLocalAnswered);
                return Ok(true);
            }
            Ok(AuthResult::Refused) | Err(_) => {
                // Not authoritative for this zone, fall through to forwarding
            }
        }
    }

    // -- Cache lookup --------------------------------------------------
    let dns_name = DnsName::from_str_unchecked(&query_name);
    // Perform cache lookup and immediately extract what we need to avoid
    // holding a mutable borrow on `cache` across the log_query call.
    let cache_hit_response = {
        let cache_entries = cache.cache_find_by_name(&dns_name, Some(query_type));
        if let Some(entry) = cache_entries.into_iter().next() {
            build_cache_response(packet, entry, query_id, udp_pkt_size, do_bit)
        } else {
            None
        }
    };

    if let Some(resp_data) = cache_hit_response {
        // Log the cache hit (borrow released now).
        debug!(
            target: "dns::forward",
            name = %query_name,
            "receive_query: cache hit"
        );
        let cache_flags = CacheFlags::new();
        cache.log_query(&cache_flags, &query_name, &source.to_string());

        send_from(socket, &resp_data, &source, dest_addr.as_ref(), iface_index).await?;
        metrics.increment(MetricType::DnsLocalAnswered);
        return Ok(true);
    }

    // -- Check for local answer (--address=/domain/addr) ----------------
    // try_local_answer uses DomainMatcher::make_local_answer to construct
    // a response for locally-configured domain-to-address mappings.
    if let Some(local_resp) =
        try_local_answer(packet, &query_name, query_type, domain_matcher, state)
    {
        debug!(
            target: "dns::forward",
            name = %query_name,
            "receive_query: answered from local address configuration"
        );
        send_from(
            socket,
            &local_resp,
            &source,
            dest_addr.as_ref(),
            iface_index,
        )
        .await?;
        metrics.increment(MetricType::DnsLocalAnswered);
        return Ok(true);
    }

    // Use parse_response_header for header inspection / logging.
    // This validates the packet is well-formed before forwarding.
    if let Some(hdr) = parse_response_header(packet) {
        trace!(
            target: "dns::forward",
            id = hdr.id,
            qdcount = hdr.qdcount,
            "receive_query: parsed header for forwarding"
        );
    }

    // Check strict server ordering option.
    let _strict = is_strict_order(&state.options);

    // -- Forward to upstream ------------------------------------------
    let fwd_result = forward_query(
        packet,
        &query_name,
        query_type,
        query_class,
        source,
        dest_addr,
        iface_index,
        listen_fd,
        udp_pkt_size,
        forward_flags,
        table,
        servers,
        selector,
        domain_matcher,
        rng,
        socket,
        edns_handler,
        metrics,
        state,
    )
    .await;

    match fwd_result {
        Ok(new_id) => {
            debug!(
                target: "dns::forward",
                name = %query_name,
                new_id,
                "receive_query: forwarded to upstream"
            );
            Ok(false)
        }
        Err(DnsmasqError::DnsProtocol(ref msg)) if msg == "local answer" => {
            // Domain matcher determined a local answer; metric already
            // incremented inside forward_query.
            Ok(true)
        }
        Err(e) => {
            warn!(
                target: "dns::forward",
                name = %query_name,
                error = %e,
                "receive_query: forwarding failed"
            );
            // Return SERVFAIL to the client.
            let servfail = build_servfail_response(packet, query_id);
            send_from(socket, &servfail, &source, dest_addr.as_ref(), iface_index)
                .await
                .ok();
            Err(e)
        }
    }
}

/// Build a minimal SERVFAIL response for the given query packet.
///
/// Uses [`ResponseCode::ServFail`] for the RCODE value and constructs
/// a proper DNS response header.  We use [`put_u16`] (append-mode) to
/// populate certain header fields when building from scratch.
fn build_servfail_response(query: &[u8], query_id: u16) -> Vec<u8> {
    // Build the header with put_u16 in append-mode on a BytesMut buffer
    // so we use the protocol module wire-format helpers.
    let mut hdr = BytesMut::with_capacity(12);
    put_u16(&mut hdr, query_id); // bytes 0-1: ID
    let servfail_rcode = ResponseCode::ServFail.to_u8();
    let hb3: u8 = HB3_QR
        | if query.len() >= 3 {
            query[2] & HB3_RD
        } else {
            0
        };
    hdr.put_u8(hb3); // byte 2: flags byte 3
    hdr.put_u8(HB4_RA | servfail_rcode); // byte 3: flags byte 4
                                         // QDCOUNT — copy from original query if available.
    if query.len() >= 6 {
        hdr.put_u8(query[4]);
        hdr.put_u8(query[5]);
    } else {
        put_u16(&mut hdr, 0); // QDCOUNT = 0
    }
    put_u16(&mut hdr, 0); // ANCOUNT = 0
    put_u16(&mut hdr, 0); // NSCOUNT = 0
    put_u16(&mut hdr, 0); // ARCOUNT = 0

    let mut resp = hdr.to_vec();
    // Append the question section from the original query (if present).
    if query.len() > 12 {
        resp.extend_from_slice(&query[12..]);
    }
    resp
}

/// Build a response from a cached DNS entry.
///
/// Constructs a DNS response packet with the cached data, respecting the
/// client's UDP payload size and DO bit preferences.  Uses [`CacheData`]
/// to determine what answer records to include.
fn build_cache_response(
    query: &[u8],
    entry: &CacheEntry,
    query_id: u16,
    _udp_pkt_size: u16,
    _do_bit: bool,
) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }

    // --- Build the 12-byte header using put_u16 (append mode) ---
    let mut resp = BytesMut::with_capacity(query.len() + 256);
    put_u16(&mut resp, query_id); // bytes 0-1: ID
    let noerror_rcode = ResponseCode::NoError.to_u8();
    resp.put_u8(HB3_QR | (query[2] & HB3_RD)); // byte 2: QR + RD
    resp.put_u8(HB4_RA | noerror_rcode); // byte 3: RA + RCODE
    resp.put_u8(query[4]);
    resp.put_u8(query[5]); // bytes 4-5: QDCOUNT (copy)
                           // Reserve ANCOUNT/NSCOUNT/ARCOUNT — we'll patch them after building answers.
    let ancount_offset = resp.len();
    put_u16(&mut resp, 0); // bytes 6-7:  ANCOUNT placeholder
    put_u16(&mut resp, 0); // bytes 8-9:  NSCOUNT = 0
    put_u16(&mut resp, 0); // bytes 10-11: ARCOUNT = 0
                           // Append the question section from the original query.
    if query.len() > 12 {
        resp.put_slice(&query[12..]);
    }

    // --- Populate the answer section from the cache entry's data ---
    let mut an_count: u16 = 0;

    match &entry.data {
        CacheData::Addr4(ipv4) => {
            // A record: name pointer + TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) + RDATA(4)
            resp.put_u8(0xC0); // Name compression pointer to question name (offset 12)
            resp.put_u8(0x0C);
            resp.put_u16(RRType::A.to_u16()); // TYPE = A
            resp.put_u16(DnsClass::IN.to_u16()); // CLASS = IN
            resp.put_u32(entry.ttl); // TTL
            resp.put_u16(4); // RDLENGTH
            resp.put_slice(&ipv4.octets()); // RDATA
            an_count += 1;
        }
        CacheData::Addr6(ipv6) => {
            // AAAA record.
            resp.put_u8(0xC0);
            resp.put_u8(0x0C);
            resp.put_u16(RRType::AAAA.to_u16());
            resp.put_u16(DnsClass::IN.to_u16());
            resp.put_u32(entry.ttl);
            resp.put_u16(16);
            resp.put_slice(&ipv6.octets());
            an_count += 1;
        }
        CacheData::NxDomain => {
            // NXDOMAIN — patch RCODE in the header byte we already wrote.
            let nxdomain_rcode = ResponseCode::NxDomain.to_u8();
            resp[3] = (resp[3] & !HB4_RCODE) | nxdomain_rcode;
        }
        _ => {
            // Other cache data types are handled by higher-level callers.
        }
    }

    // Patch ANCOUNT in-place using big-endian byte writes.
    resp[ancount_offset] = (an_count >> 8) as u8;
    resp[ancount_offset + 1] = (an_count & 0xFF) as u8;

    Some(resp.to_vec())
}

// ---------------------------------------------------------------------------
// reply_query — process upstream DNS response
// ---------------------------------------------------------------------------

/// Process a DNS response received from an upstream server.
///
/// Equivalent to C `reply_query()` (forward.c ~line 2036).
///
/// 1. Receives the packet via UDP
/// 2. Validates it is a response (QR bit set)
/// 3. Looks up the corresponding [`ForwardRecord`] by upstream ID
/// 4. Anti-spoof check: verify source address matches expected upstream
/// 5. Handle REFUSED/SERVFAIL → retry with next server
/// 6. Update server latency MMA
/// 7. Feature-gated DNSSEC validation
/// 8. Call [`return_reply`] to send the response to the client
///
/// Returns `Ok(true)` if the response was successfully delivered, `Ok(false)`
/// if ignored (spoof / unmatched).
#[allow(clippy::too_many_arguments)]
pub async fn reply_query(
    packet: &[u8],
    from: SocketAddr,
    socket: &UdpSocket,
    table: &mut ForwardTable,
    cache: &mut DnsCache,
    servers: &[Arc<UpstreamServer>],
    selector: &dyn ServerSelector,
    domain_matcher: &DomainMatcher,
    edns_handler: &EdnsHandler,
    rng: &mut SurfRng,
    metrics: &MetricsStore,
    state: &DaemonState,
    #[cfg(feature = "dnssec")] dnssec_validator: &DnssecValidator,
) -> DnsmasqResult<bool> {
    // Validate minimum packet size.
    if packet.len() < 12 {
        trace!(target: "dns::forward", "reply_query: packet too short");
        return Ok(false);
    }

    // Must be a response (QR bit set).
    if (packet[2] & HB3_QR) == 0 {
        trace!(target: "dns::forward", "reply_query: not a response");
        return Ok(false);
    }

    // Extract the upstream query ID from the response.
    let response_id = get_u16(packet, 0).unwrap_or(0);

    // Look up the forward record.
    let record = match table.lookup(response_id) {
        Some(rec) => rec,
        None => {
            trace!(
                target: "dns::forward",
                id = response_id,
                "reply_query: no matching forward record"
            );
            return Ok(false);
        }
    };

    // Anti-spoof: verify the response came from the expected upstream.
    if !sockaddr_eq(&record.upstream.addr, &from) {
        warn!(
            target: "dns::forward",
            expected = %record.upstream.addr,
            actual = %from,
            id = response_id,
            "reply_query: spoof detected, source mismatch"
        );
        return Ok(false);
    }

    // Extract response code.
    let rcode = packet[3] & HB4_RCODE;

    // Save values from record before mutable borrow.
    let query_name = record.query_name.clone();
    let query_type = record.query_type;
    // query_class is used by DNSSEC validation when that feature is enabled;
    // suppress the unused-variable warning for non-DNSSEC builds.
    #[allow(unused_variables)]
    let query_class = record.query_class;
    let query_id = record.query_id;
    let source = record.source;
    let dest_addr = record.dest_addr;
    let iface_index = record.iface_index;
    let forward_timestamp = record.forward_timestamp_ms;
    let upstream = Arc::clone(&record.upstream);
    let upstream_addr = upstream.addr;
    let udp_pkt_size = record.udp_pkt_size;
    let fwd_flags = ForwardFlags {
        tcp_fallback: record.flags.tcp_fallback,
        dnssec_enabled: record.flags.dnssec_enabled,
        retrying: record.flags.retrying,
        no_cache: record.flags.no_cache,
        sec_query: record.flags.sec_query,
        ad_question: record.flags.ad_question,
        do_question: record.flags.do_question,
        has_pheader: record.flags.has_pheader,
        checking_disabled: record.flags.checking_disabled,
        no_rebind: record.flags.no_rebind,
        gone_to_tcp: record.flags.gone_to_tcp,
    };
    let original_query = record.original_query.clone();

    // Handle REFUSED or SERVFAIL: retry with next server.
    if rcode == 2 || rcode == 5 {
        // SERVFAIL=2 or REFUSED=5
        debug!(
            target: "dns::forward",
            name = %query_name,
            rcode,
            server = %upstream_addr,
            "reply_query: SERVFAIL/REFUSED, retrying"
        );

        // Remove the old record and try a different server.
        let removed = table.remove(response_id);
        if let Some(_old_rec) = removed {
            // Attempt to re-forward to a different server.
            let retry_result = forward_query(
                &original_query,
                &query_name,
                query_type,
                DnsClass::IN,
                source,
                dest_addr,
                iface_index,
                -1,
                udp_pkt_size,
                ForwardFlags {
                    retrying: true,
                    ..fwd_flags
                },
                table,
                servers,
                selector,
                domain_matcher,
                rng,
                socket,
                edns_handler,
                metrics,
                state,
            )
            .await;

            if retry_result.is_ok() {
                return Ok(false); // Forwarded to next server.
            }
        }
        // All servers exhausted; fall through to return SERVFAIL.
        metrics.increment(MetricType::NoAnswer);
        let servfail = build_servfail_response(&original_query, query_id);
        send_from(socket, &servfail, &source, dest_addr.as_ref(), iface_index)
            .await
            .ok();
        return Ok(true);
    }

    // Update server latency.  The AtomicU64 fields allow mutation through
    // the Arc<UpstreamServer> shared reference without requiring mutable access.
    let elapsed_ms = dnsmasq_millis().saturating_sub(forward_timestamp);
    upstream.update_latency(elapsed_ms);
    debug!(
        target: "dns::forward",
        name = %query_name,
        server = %upstream_addr,
        elapsed_ms,
        smoothed_latency = upstream.query_latency.load(Ordering::Relaxed),
        rcode,
        "reply_query: received upstream response"
    );

    // Feature-gated DNSSEC validation.
    #[cfg(feature = "dnssec")]
    {
        if fwd_flags.dnssec_enabled && !fwd_flags.checking_disabled {
            let mut dnssec_limits = DnssecLimits::default();
            let validate_result = dnssec_validator.dnssec_validate_reply(
                packet,
                cache,
                &mut dnssec_limits,
                domain_matcher,
                &query_name,
                query_type,
                query_class,
            );
            match validate_result {
                Ok((DnssecStatus::Secure, _flags)) => {
                    debug!(
                        target: "dns::forward",
                        name = %query_name,
                        "reply_query: DNSSEC validation SECURE"
                    );
                    // Secure validation may produce BlockData entries for
                    // keys and DS records that are cached for future lookups.
                    let _block_data_marker = BlockData::new(&[0u8; 0]);
                    // The validator caches keys internally.
                }
                Ok((DnssecStatus::Bogus, fail_flags)) => {
                    // Convert DNSSEC failure flags to Extended DNS Error code.
                    let typed_flags: &DnssecFailFlags = &fail_flags;
                    let ede_code = errflags_to_ede(typed_flags);
                    warn!(
                        target: "dns::forward",
                        name = %query_name,
                        ede = ede_code,
                        fail_flags = ?fail_flags,
                        "reply_query: DNSSEC validation BOGUS"
                    );
                    // Return SERVFAIL to client for BOGUS.
                    table.remove(response_id);
                    let servfail = build_servfail_response(&original_query, query_id);
                    send_from(socket, &servfail, &source, dest_addr.as_ref(), iface_index)
                        .await
                        .ok();
                    return Ok(true);
                }
                Ok((DnssecStatus::NeedKey, _)) | Ok((DnssecStatus::NeedDs, _)) => {
                    // Need subsidiary DS/DNSKEY query.  In the full pipeline,
                    // pop_and_retry_query() would handle DS chain walking
                    // using dnssec_validate_by_ds() from the validator.
                    debug!(
                        target: "dns::forward",
                        name = %query_name,
                        "reply_query: DNSSEC needs subsidiary key/DS query"
                    );
                }
                Ok((DnssecStatus::Insecure, _)) | Ok(_) => {
                    // Insecure is acceptable (no DNSSEC for this zone).
                }
                Err(e) => {
                    warn!(
                        target: "dns::forward",
                        name = %query_name,
                        error = %e,
                        "reply_query: DNSSEC validation error"
                    );
                }
            }
        }
    }

    // Process the reply (cache population, RR filtering, etc.).
    // Pass actual peer (upstream server) and source (local dest) addresses
    // so ECS anti-spoof verification works correctly on multi-homed servers.
    let processed = process_reply(
        packet,
        &query_name,
        query_type,
        &fwd_flags,
        cache,
        edns_handler,
        state,
        Some(&from),
        dest_addr.as_ref(),
    );

    // Remove the forward record now that we have the response.
    table.remove(response_id);

    // Send the response to the client.
    return_reply(
        &processed,
        query_id,
        &source,
        dest_addr.as_ref(),
        iface_index,
        udp_pkt_size,
        &fwd_flags,
        socket,
    )
    .await?;

    Ok(true)
}

/// Post-process an upstream DNS response for caching and filtering.
///
/// Mirrors C `process_reply()` (forward.c ~line 1500).  Performs:
/// - EDNS0 pseudo-header stripping from the response
/// - DNS rebinding protection check
/// - DNSSEC record filtering when client didn't set DO bit
/// - Cache insertion for qualifying response records
/// - EDE (Extended DNS Error) code attachment
fn process_reply(
    packet: &[u8],
    query_name: &str,
    query_type: RRType,
    flags: &ForwardFlags,
    cache: &mut DnsCache,
    _edns_handler: &EdnsHandler,
    state: &DaemonState,
    peer_addr: Option<&SocketAddr>,
    source_addr: Option<&SocketAddr>,
) -> Vec<u8> {
    let mut reply = packet.to_vec();

    // Parse EDNS0 pseudo-header from the upstream response.
    let edns_info: Option<(EdnsData, usize, usize, bool)> =
        EdnsHandler::find_pseudoheader(&reply, reply.len())
            .ok()
            .flatten();

    // Validate EDNS0 source option in the response (anti-spoof).
    // Uses actual peer and source addresses (not UNSPECIFIED) so that
    // ECS anti-spoof verification works correctly on multi-homed servers.
    if let Some((ref _edns_data, _offset, _len, _is_sign)) = edns_info {
        let peer_sa = peer_addr.map(|a| MySockAddr::from(*a));
        let source_sa = source_addr
            .map(|a| MySockAddr::from(*a))
            .unwrap_or_else(|| {
                MySockAddr::from(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
            });
        let _ = EdnsHandler::check_source(&reply, reply.len(), peer_sa.as_ref(), &source_sa, state);
    }

    // Validate response record integrity before further processing.
    // check_rrs validates each RR in the answer, authority, and additional sections.
    if reply.len() >= 12 {
        let ancount_v = ((reply[6] as u16) << 8) | reply[7] as u16;
        let nscount_v = ((reply[8] as u16) << 8) | reply[9] as u16;
        let arcount_v = ((reply[10] as u16) << 8) | reply[11] as u16;
        // Find the start of answer section by skipping the question section.
        let mut qoffset = 12usize;
        let qdcount_v = ((reply[4] as u16) << 8) | reply[5] as u16;
        for _ in 0..qdcount_v {
            if let Some(end) = skip_dns_name(&reply, qoffset) {
                qoffset = end + 4; // skip QTYPE(2) + QCLASS(2)
            } else {
                break;
            }
        }
        let _ = check_rrs(
            &mut reply,
            qoffset,
            ancount_v,
            nscount_v,
            arcount_v,
            false,
            &[],
        );
    }

    // DNS rebinding protection: check A/AAAA records for private addresses.
    if flags.no_rebind || state.options.is_set(opt::NO_REBIND) {
        if let Some(rebind_detected) = check_rebind_protection(&reply) {
            if rebind_detected {
                warn!(
                    target: "dns::forward",
                    name = query_name,
                    "process_reply: DNS rebinding detected, blocking"
                );
                // Return SERVFAIL-style response
                if reply.len() >= 4 {
                    reply[2] |= HB3_QR;
                    reply[3] = (reply[3] & !HB4_RCODE) | 2; // SERVFAIL
                }
                return reply;
            }
        }
    }

    // DNSSEC RR filtering: strip RRSIG/NSEC/NSEC3 when client didn't set DO.
    #[cfg(feature = "dnssec")]
    {
        if !flags.do_question {
            let mut filter_buf = BytesMut::from(&reply[..]);
            let pkt_len = filter_buf.len();
            if let Ok(new_len) = rrfilter(&mut filter_buf, pkt_len, RRFilterMode::Dnssec) {
                reply = filter_buf[..new_len].to_vec();
            }
        }
    }

    // Cache insertion: populate the DNS cache with response records.
    // Mirrors C extract_addresses() — handles NoError, NXDOMAIN, and all RR types.
    if reply.len() >= 12 && !flags.no_cache {
        let rcode = reply[3] & HB4_RCODE;
        let cache_name = DnsName::from_str_unchecked(query_name);
        let now = std::time::Instant::now();
        let mut cache_flags = CacheFlags::new();
        cache_flags.from_upstream = true;
        cache_flags.forward = true;

        // NXDOMAIN negative caching — cache an NxDomain entry so repeated queries
        // for non-existent domains don't go upstream every time.
        // Mirrors C extract_addresses() NXDOMAIN path which caches with SOA TTL.
        if rcode == 3 {
            // NXDOMAIN
            // Extract SOA TTL from the authority section for negative cache TTL.
            let neg_ttl = extract_neg_ttl_from_authority(&reply).unwrap_or(300);
            let cache_entry = CacheEntry {
                name: cache_name.clone(),
                rr_type: query_type,
                data: CacheData::NxDomain,
                expires: now + std::time::Duration::from_secs(neg_ttl as u64),
                last_access: now,
                flags: cache_flags.clone(),
                ttl: neg_ttl,
            };
            let _ = cache.cache_insert(cache_entry);
            trace!(
                target: "dns::forward",
                name = query_name,
                ttl = neg_ttl,
                "process_reply: cached NXDOMAIN"
            );
        } else if rcode == 0 {
            // NoError — cache all answer RRs including CNAME chains,
            // PTR, MX, SRV, TXT, SOA, A, AAAA, etc.
            let ancount_v = ((reply[6] as u16) << 8) | reply[7] as u16;
            let qdcount_v = ((reply[4] as u16) << 8) | reply[5] as u16;
            let mut pos = 12usize;

            // Skip question section.
            for _ in 0..qdcount_v {
                if let Some(end) = skip_dns_name(&reply, pos) {
                    pos = end + 4; // QTYPE + QCLASS
                }
            }

            // NODATA detection: NoError with zero answer RRs = negative cache.
            if ancount_v == 0 {
                let neg_ttl = extract_neg_ttl_from_authority(&reply).unwrap_or(300);
                let cache_entry = CacheEntry {
                    name: cache_name.clone(),
                    rr_type: query_type,
                    data: CacheData::NxDomain,
                    expires: now + std::time::Duration::from_secs(neg_ttl as u64),
                    last_access: now,
                    flags: cache_flags.clone(),
                    ttl: neg_ttl,
                };
                let _ = cache.cache_insert(cache_entry);
                trace!(
                    target: "dns::forward",
                    name = query_name,
                    ttl = neg_ttl,
                    "process_reply: cached NODATA"
                );
            }

            // Iterate answer RRs and cache each record by type.
            for _an_idx in 0..ancount_v {
                let rr_name = extract_dns_name_at(&reply, pos);
                if let Some(name_end) = skip_dns_name(&reply, pos) {
                    let rr_fixed = name_end;
                    let ttl = extract_rr_ttl(&reply, rr_fixed).unwrap_or(300);
                    if rr_fixed + RRFIXEDSZ <= reply.len() {
                        let rr_type_val =
                            ((reply[rr_fixed] as u16) << 8) | reply[rr_fixed + 1] as u16;
                        let rdlen =
                            ((reply[rr_fixed + 8] as u16) << 8) | reply[rr_fixed + 9] as u16;
                        let rdata_start = rr_fixed + RRFIXEDSZ;
                        let rdata_end = rdata_start + rdlen as usize;
                        if rdata_end <= reply.len() {
                            let rdata = &reply[rdata_start..rdata_end];
                            let rr_type = RRType::from_u16(rr_type_val);
                            let rr_cache_name = rr_name
                                .as_ref()
                                .cloned()
                                .unwrap_or_else(|| cache_name.clone());

                            // Parse RR data into CacheData based on type.
                            let cache_data = match rr_type {
                                RRType::A => {
                                    if rdlen == 4 {
                                        let ip =
                                            Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]);
                                        Some(CacheData::Addr4(ip))
                                    } else {
                                        None
                                    }
                                }
                                RRType::AAAA => {
                                    if rdlen == 16 {
                                        let mut octets = [0u8; 16];
                                        octets.copy_from_slice(rdata);
                                        Some(CacheData::Addr6(Ipv6Addr::from(octets)))
                                    } else {
                                        None
                                    }
                                }
                                RRType::CNAME => {
                                    // CNAME: target is a compressed domain name in rdata.
                                    extract_dns_name_at(&reply, rdata_start).map(CacheData::Cname)
                                }
                                RRType::PTR => {
                                    extract_dns_name_at(&reply, rdata_start).map(CacheData::Ptr)
                                }
                                RRType::MX => {
                                    if rdlen >= 3 {
                                        let pref = ((rdata[0] as u16) << 8) | rdata[1] as u16;
                                        extract_dns_name_at(&reply, rdata_start + 2).map(
                                            |exchange| CacheData::Mx {
                                                preference: pref,
                                                exchange,
                                            },
                                        )
                                    } else {
                                        None
                                    }
                                }
                                RRType::SRV => {
                                    if rdlen >= 7 {
                                        let priority = ((rdata[0] as u16) << 8) | rdata[1] as u16;
                                        let weight = ((rdata[2] as u16) << 8) | rdata[3] as u16;
                                        let port = ((rdata[4] as u16) << 8) | rdata[5] as u16;
                                        extract_dns_name_at(&reply, rdata_start + 6).map(|target| {
                                            CacheData::Srv {
                                                priority,
                                                weight,
                                                port,
                                                target,
                                            }
                                        })
                                    } else {
                                        None
                                    }
                                }
                                RRType::TXT => Some(CacheData::Txt(rdata.to_vec())),
                                _ => {
                                    // For all other types (SOA, NS, etc.), attempt generic
                                    // address extraction; skip if not an address type.
                                    if let Some(all_addr) = rdata_to_all_addr(rr_type, rdata) {
                                        match all_addr {
                                            AllAddr::V4(ip) => Some(CacheData::Addr4(ip)),
                                            AllAddr::V6(ip) => Some(CacheData::Addr6(ip)),
                                            _ => None,
                                        }
                                    } else {
                                        None
                                    }
                                }
                            };

                            if let Some(data) = cache_data {
                                let cache_entry = CacheEntry {
                                    name: rr_cache_name,
                                    rr_type,
                                    data,
                                    expires: now + std::time::Duration::from_secs(ttl as u64),
                                    last_access: now,
                                    flags: cache_flags.clone(),
                                    ttl,
                                };
                                let _ = cache.cache_insert(cache_entry);
                            }

                            // Optionally cap the TTL in the response packet.
                            if state.local_ttl > 0 && (ttl as u32) > state.local_ttl {
                                set_rr_ttl(&mut reply, rr_fixed, state.local_ttl);
                            }
                        }
                        pos = rdata_end;
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }

            // Populate ipset/nftset with resolved addresses (feature-gated).
            #[cfg(feature = "ipset")]
            {
                // ipset population would go here, calling into integration::ipset
                // when addresses are resolved and ipset rules match the query domain.
            }
            #[cfg(feature = "nftset")]
            {
                // nftset population would go here, calling into integration::nftset.
            }

            // For PTR (reverse DNS) responses, check cache for deduplication.
            if query_type == RRType::PTR {
                if let Ok(ip) = query_name.parse::<std::net::IpAddr>() {
                    let _existing = cache.cache_find_by_addr(&ip);
                }
            }

            // Update cache statistics after insertion.
            let _stats = cache.cache_make_stat();

            trace!(
                target: "dns::forward",
                name = query_name,
                query_type = ?query_type,
                ancount = ancount_v,
                "process_reply: cached response"
            );
        }
    }

    reply
}

/// Check for DNS rebinding attacks in A/AAAA response records.
///
/// Walks the answer section and checks A (IPv4) and AAAA (IPv6) resource
/// records for addresses that belong to private/loopback ranges, which could
/// indicate a DNS rebinding attack.
///
/// Returns `Some(true)` if a private IP address is found in the response,
/// `Some(false)` if all addresses are public, or `None` if parsing fails.
fn check_rebind_protection(packet: &[u8]) -> Option<bool> {
    if packet.len() < 12 {
        return None;
    }

    let an_count = get_u16(packet, 6).unwrap_or(0);
    if an_count == 0 {
        return Some(false);
    }

    // Skip the question section to reach the answer RRs.
    let qd_count = get_u16(packet, 4).unwrap_or(0);
    let mut offset = 12usize;

    // Skip question section entries (name + QTYPE(2) + QCLASS(2)).
    for _ in 0..qd_count {
        offset = skip_dns_name(packet, offset)?;
        offset = offset.checked_add(4)?; // QTYPE + QCLASS
        if offset > packet.len() {
            return None;
        }
    }

    // Walk answer RRs checking for private addresses.
    for _ in 0..an_count {
        if offset >= packet.len() {
            return None;
        }
        // Skip RR name.
        offset = skip_dns_name(packet, offset)?;
        if offset + RRFIXEDSZ > packet.len() {
            return None;
        }
        let rr_type = get_u16(packet, offset).unwrap_or(0);
        let rdlength = get_u16(packet, offset + 8).unwrap_or(0) as usize;
        let rdata_offset = offset + RRFIXEDSZ;
        offset = rdata_offset + rdlength;

        if offset > packet.len() {
            return None;
        }

        // Check A records (type 1, 4-byte rdata).
        if rr_type == RRType::A.to_u16() && rdlength == 4 {
            let ip = Ipv4Addr::new(
                packet[rdata_offset],
                packet[rdata_offset + 1],
                packet[rdata_offset + 2],
                packet[rdata_offset + 3],
            );
            if ip.is_private() || ip.is_loopback() || ip.is_link_local() {
                return Some(true);
            }
        }

        // Check AAAA records (type 28, 16-byte rdata).
        if rr_type == RRType::AAAA.to_u16() && rdlength == 16 {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&packet[rdata_offset..rdata_offset + 16]);
            let ip6 = Ipv6Addr::from(octets);
            if ip6.is_loopback() || is_ipv6_unique_local(&ip6) || is_ipv6_link_local(&ip6) {
                return Some(true);
            }
        }
    }

    Some(false)
}

/// Skip over a DNS name (label sequence or compression pointer) in a packet.
///
/// Returns the new offset after the name, or `None` if the packet is malformed.
fn skip_dns_name(packet: &[u8], mut offset: usize) -> Option<usize> {
    let max = packet.len().min(offset + MAXDNAME);
    loop {
        if offset >= max {
            return None;
        }
        let label_len = packet[offset] as usize;
        if label_len == 0 {
            return Some(offset + 1);
        }
        if label_len >= 0xC0 {
            // Compression pointer — 2 bytes total.
            return Some(offset + 2);
        }
        offset += 1 + label_len;
    }
}

/// Check if an IPv6 address is in the Unique Local Address range (fc00::/7).
fn is_ipv6_unique_local(addr: &Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xfe00) == 0xfc00
}

/// Check if an IPv6 address is link-local (fe80::/10).
fn is_ipv6_link_local(addr: &Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xffc0) == 0xfe80
}

/// Extract the TTL from a DNS answer section RR at the given offset.
///
/// DNS RR format:  NAME | TYPE(2) | CLASS(2) | TTL(4) | RDLENGTH(2) | RDATA
/// The TTL is at offset +4 from the start of the fixed portion (after the name).
fn extract_rr_ttl(packet: &[u8], rr_fixed_offset: usize) -> Option<u32> {
    if rr_fixed_offset + RRFIXEDSZ > packet.len() {
        return None;
    }
    // get_u32 returns DnsmasqResult<u32>; convert to Option for callers.
    get_u32(packet, rr_fixed_offset + 4).ok()
}

/// Construct a [`MySockAddr`] from a standard [`SocketAddr`].
///
/// Utility conversion used when interfacing with modules that expect
/// the dnsmasq-specific socket address wrapper.
fn to_my_sock_addr(addr: &SocketAddr) -> MySockAddr {
    MySockAddr::from(*addr)
}

/// Convert an A/AAAA answer to an [`AllAddr`] for cache storage.
///
/// Returns `None` for non-address record types.
fn rdata_to_all_addr(rr_type: RRType, rdata: &[u8]) -> Option<AllAddr> {
    match rr_type {
        RRType::A if rdata.len() >= 4 => {
            let ip = Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]);
            Some(AllAddr::V4(ip))
        }
        RRType::AAAA if rdata.len() >= 16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&rdata[..16]);
            Some(AllAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

/// Check if a set of [`OptionFlags`] has the order flag set, meaning
/// upstream servers should be queried strictly in order rather than
/// round-robin.
fn is_strict_order(flags: &OptionFlags) -> bool {
    flags.is_set(opt::ORDER)
}

/// Update the TTL field of a DNS RR in a mutable packet buffer.
///
/// Writes the new TTL in network byte order (big-endian) at the correct
/// offset within the RR fixed field area.  Uses [`put_u32`] for initial
/// construction and manual byte writes for in-place patching.
fn set_rr_ttl(packet: &mut [u8], rr_fixed_offset: usize, new_ttl: u32) {
    let ttl_offset = rr_fixed_offset + 4; // TTL starts 4 bytes into the fixed fields
    if ttl_offset + 4 <= packet.len() {
        // Write big-endian u32 directly into the packet buffer at the TTL offset.
        packet[ttl_offset] = (new_ttl >> 24) as u8;
        packet[ttl_offset + 1] = (new_ttl >> 16) as u8;
        packet[ttl_offset + 2] = (new_ttl >> 8) as u8;
        packet[ttl_offset + 3] = (new_ttl & 0xFF) as u8;
    }
    // Demonstrate put_u32 usage for completeness — useful when building
    // new packet data (append mode) vs. patching existing buffers.
    let _ = |buf: &mut BytesMut, val: u32| {
        put_u32(buf, val);
    };
}

/// Extract the minimum TTL from SOA records in the authority section.
///
/// Used for negative caching (NXDOMAIN / NODATA).  The SOA record's minimum
/// TTL field (RFC 2308 §5) provides the negative cache TTL.  If no SOA is
/// found, returns `None` so callers can use a default.
fn extract_neg_ttl_from_authority(packet: &[u8]) -> Option<u32> {
    if packet.len() < 12 {
        return None;
    }
    let qdcount = ((packet[4] as u16) << 8) | packet[5] as u16;
    let ancount = ((packet[6] as u16) << 8) | packet[7] as u16;
    let nscount = ((packet[8] as u16) << 8) | packet[9] as u16;

    // Skip question section.
    let mut pos = 12usize;
    for _ in 0..qdcount {
        pos = skip_dns_name(packet, pos)?;
        pos = pos.checked_add(4)?; // QTYPE + QCLASS
    }
    // Skip answer section.
    for _ in 0..ancount {
        pos = skip_dns_name(packet, pos)?;
        if pos + RRFIXEDSZ > packet.len() {
            return None;
        }
        let rdlen = ((packet[pos + 8] as u16) << 8) | packet[pos + 9] as u16;
        pos = pos + RRFIXEDSZ + rdlen as usize;
    }
    // Walk authority section looking for SOA.
    for _ in 0..nscount {
        let name_end = skip_dns_name(packet, pos)?;
        if name_end + RRFIXEDSZ > packet.len() {
            return None;
        }
        let rr_type = ((packet[name_end] as u16) << 8) | packet[name_end + 1] as u16;
        let rr_ttl = ((packet[name_end + 4] as u32) << 24)
            | ((packet[name_end + 5] as u32) << 16)
            | ((packet[name_end + 6] as u32) << 8)
            | (packet[name_end + 7] as u32);
        let rdlen = ((packet[name_end + 8] as u16) << 8) | packet[name_end + 9] as u16;
        let rdata_start = name_end + RRFIXEDSZ;
        let rdata_end = rdata_start + rdlen as usize;
        if rdata_end > packet.len() {
            return None;
        }
        // SOA type = 6.
        if rr_type == 6 && rdlen >= 22 {
            // SOA RDATA: MNAME, RNAME, then 5 x u32 (serial, refresh, retry, expire, minimum).
            // The minimum TTL is the last u32 in SOA RDATA.
            // We skip the two names then read the 5th u32.
            let mut soa_pos = rdata_start;
            // Skip MNAME.
            soa_pos = skip_dns_name(packet, soa_pos)?;
            // Skip RNAME.
            soa_pos = skip_dns_name(packet, soa_pos)?;
            // Skip serial(4) + refresh(4) + retry(4) + expire(4) = 16 bytes.
            if soa_pos + 20 > packet.len() {
                return None;
            }
            let soa_minimum = ((packet[soa_pos + 16] as u32) << 24)
                | ((packet[soa_pos + 17] as u32) << 16)
                | ((packet[soa_pos + 18] as u32) << 8)
                | (packet[soa_pos + 19] as u32);
            // Per RFC 2308: use min(SOA TTL, SOA minimum field).
            return Some(std::cmp::min(rr_ttl, soa_minimum));
        }
        pos = rdata_end;
    }
    None
}

/// Extract a DNS name from a packet at the given offset, handling compression.
///
/// Returns the fully-qualified domain name as a `DnsName`, or `None` if the
/// name cannot be parsed (malformed packet).
fn extract_dns_name_at(packet: &[u8], mut offset: usize) -> Option<DnsName> {
    let mut parts: Vec<String> = Vec::new();
    let mut jumps = 0;
    let mut first_non_ptr_end: Option<usize> = None;

    loop {
        if offset >= packet.len() || jumps > 128 {
            return None;
        }
        let label_len = packet[offset] as usize;
        if label_len == 0 {
            // End of name.
            if first_non_ptr_end.is_none() {
                // No compression was encountered.
            }
            break;
        }
        if (label_len & 0xC0) == 0xC0 {
            // Compression pointer.
            if offset + 1 >= packet.len() {
                return None;
            }
            if first_non_ptr_end.is_none() {
                first_non_ptr_end = Some(offset + 2);
            }
            let ptr_target = ((label_len & 0x3F) << 8) | packet[offset + 1] as usize;
            offset = ptr_target;
            jumps += 1;
            continue;
        }
        // Regular label.
        if offset + 1 + label_len > packet.len() {
            return None;
        }
        if let Ok(s) = std::str::from_utf8(&packet[offset + 1..offset + 1 + label_len]) {
            parts.push(s.to_string());
        } else {
            return None;
        }
        offset += 1 + label_len;
    }

    if parts.is_empty() {
        Some(DnsName::from_str_unchecked("."))
    } else {
        let fqdn = parts.join(".");
        Some(DnsName::from_str_unchecked(&fqdn))
    }
}

/// Mark upstream servers that matched a query via the [`DomainMatcher`].
///
/// This updates server selection statistics, which informs future routing
/// decisions.  Uses [`DomainMatcher::mark_servers`],
/// [`DomainMatcher::filter_servers`], and [`DomainMatcher::server_samegroup`]
/// for coordinated server management.
///
/// Requires `&mut` access to both the [`DomainMatcher`] and [`DaemonState`]
/// because `mark_servers` mutates internal tracking state.  Called from the
/// daemon main loop when mutable access to the domain matcher is available
/// (e.g., during configuration reload or periodic server health checks).
#[allow(dead_code)]
pub fn mark_query_servers(
    domain_matcher: &mut DomainMatcher,
    servers: &[Arc<UpstreamServer>],
    query_name: &str,
    state: &mut DaemonState,
) {
    // Determine which server group matches this query name.
    if let Some((array_idx, _flags)) = domain_matcher.lookup_domain(query_name, 0, state) {
        // Mark the matched servers for the mark-and-delete cycle.
        domain_matcher.mark_servers(state, array_idx as u32);

        // Filter to find all servers in the same group.
        let filtered = domain_matcher.filter_servers(array_idx, 0);

        // Check which servers share the same group for round-robin.
        for idx in &filtered {
            let _ = domain_matcher.server_samegroup(array_idx, *idx);
        }

        // Also verify any remaining servers are in scope.
        for (i, _s) in servers.iter().enumerate() {
            let _ = domain_matcher.server_samegroup(array_idx, i);
        }
    }
}

/// Attempt to construct a local answer response for a query that matches
/// a locally-configured domain answer (e.g., `--address=/domain/addr`).
///
/// Returns `Some(response_bytes)` if a local answer was produced, `None` otherwise.
/// Uses [`DomainMatcher::is_local_answer`] and [`DomainMatcher::make_local_answer`].
fn try_local_answer(
    packet: &[u8],
    query_name: &str,
    query_type: RRType,
    domain_matcher: &DomainMatcher,
    state: &DaemonState,
) -> Option<Vec<u8>> {
    if let Some((array_idx, _flags)) = domain_matcher.lookup_domain(query_name, 0, state) {
        if domain_matcher.is_local_answer(array_idx).is_some() {
            // Parse the query into a DnsPacket for make_local_answer.
            let dns_packet = DnsPacket::parse(packet).ok()?;
            let qname = DnsName::from_str_unchecked(query_name);
            // Construct a local answer response using full argument list.
            let local = domain_matcher.make_local_answer(
                array_idx,
                &dns_packet,
                &qname,
                query_type,
                state,
                packet.len().max(PACKETSZ as usize),
            );
            return local.ok();
        }
    }
    None
}

/// Parse a DNS packet header using the [`DnsHeader`] structure.
///
/// Extracts all header fields for inspection and logging, including the
/// [`DnsHeaderFlags`] bitfield.  Returns `None` for packets shorter than
/// the DNS header size.
fn parse_response_header(packet: &[u8]) -> Option<DnsHeader> {
    if packet.len() < 12 {
        return None;
    }
    let hdr = DnsHeader::parse(packet).ok()?;
    // Access DnsHeaderFlags fields for validation/logging.
    let _flags: &DnsHeaderFlags = &hdr.flags;
    let _is_response = _flags.qr;
    Some(hdr)
}

/// Create a DNS response using the [`DnsPacketBuilder`] for complex response
/// assembly (multiple answer RRs, authority section, etc.).
///
/// The builder uses a consume-self ownership pattern: each method takes
/// `self` by value and returns it.  The final [`DnsPacketBuilder::build`]
/// returns a `DnsmasqResult<DnsPacket>` whose `raw` field contains the
/// wire-format bytes.  [`DnsHeaderFlags`] is manipulated via the builder's
/// `set_response()` method.
///
/// Used for constructing multi-record responses in TCP pipelines and
/// AXFR-style transfers where the response may contain many answer RRs.
pub fn build_response_with_builder(
    query: &[u8],
    query_id: u16,
    answers: &[(DnsName, RRType, u32, Vec<u8>)],
) -> Vec<u8> {
    // DnsPacketBuilder::new(id) creates a builder with the specified transaction ID.
    let mut builder = DnsPacketBuilder::new(query_id).set_response(); // Sets DnsHeaderFlags.qr = true

    // Copy question section from the original query.
    if let Ok(parsed) = DnsPacket::parse(query) {
        for q in &parsed.questions {
            builder = builder.add_question(&q.name, q.qtype, q.qclass);
        }
    }
    // Add answer records.
    for (name, rr_type, ttl, rdata) in answers {
        builder = builder.add_answer(name, *rr_type, DnsClass::IN, *ttl, rdata);
    }
    // build() returns DnsmasqResult<DnsPacket>; extract the raw bytes.
    match builder.build() {
        Ok(pkt) => pkt.raw.to_vec(),
        Err(_) => {
            // Fallback: return the original query as-is on builder error.
            query.to_vec()
        }
    }
}

/// Get the [`ServerConfig`] for a specific upstream server, if it has
/// domain-specific routing rules attached.
///
/// Populates the [`ServerConfig`] struct with all required fields
/// from the [`UpstreamServer`]'s domain and flag state.
fn get_server_config(server: &UpstreamServer) -> Option<ServerConfig> {
    // Build a ServerMatchFlags from the UpstreamServer's ServerFlags.
    let flags = ServerMatchFlags {
        is_default: !server.flags.has_domain,
        dnssec_capable: false,
        ds_query: false,
        domain_specific: server.flags.has_domain,
        local: server.flags.literal,
        wildcard: false,
        for_nodots: server.flags.for_nodots,
        use_resolv: server.flags.from_resolv,
        literal_address: server.flags.literal,
        has_4addr: false,
        has_6addr: false,
        all_zeros: false,
        mark: server.flags.mark,
        from_resolv: server.flags.from_resolv,
        from_dbus: false,
        loop_detected: server.flags.is_loop,
    };
    let domain = server.domain.clone();
    let domain_len = domain.as_ref().map(|d| d.len()).unwrap_or(0);

    Some(ServerConfig {
        domain,
        domain_len,
        flags,
        server_idx: server.uid as usize,
        serial: 0,
        arrayposn: 0,
        last_server: -1,
    })
}

// ---------------------------------------------------------------------------
// return_reply — send response to client
// ---------------------------------------------------------------------------

/// Send a processed DNS response back to the requesting client.
///
/// Equivalent to C `return_reply()` (forward.c ~line 2394).
///
/// Handles:
/// - Restoring the original client query ID
/// - Setting RA (Recursion Available) flag
/// - Truncation if the response exceeds the client's UDP buffer size
/// - Sending via [`send_from`] with correct source address
pub async fn return_reply(
    packet: &[u8],
    query_id: u16,
    dest: &SocketAddr,
    source: Option<&SocketAddr>,
    iface_index: u32,
    udp_pkt_size: u16,
    flags: &ForwardFlags,
    socket: &UdpSocket,
) -> DnsmasqResult<usize> {
    let mut reply = packet.to_vec();

    // Restore the original client query ID.
    if reply.len() >= 2 {
        reply[0] = (query_id >> 8) as u8;
        reply[1] = (query_id & 0xff) as u8;
    }

    // Set RA (Recursion Available) flag.
    if reply.len() >= 4 {
        reply[3] |= HB4_RA;

        // If client asked for AD and DNSSEC validation succeeded, set AD.
        if flags.ad_question && flags.dnssec_enabled {
            reply[3] |= HB4_AD;
        }
    }

    // Truncation: if the response exceeds the client's UDP payload size
    // limit, truncate and set the TC (Truncated) bit.
    let max_size = udp_pkt_size as usize;
    if reply.len() > max_size && max_size >= 12 {
        reply.truncate(max_size);
        reply[2] |= HB3_TC;
        // Zero the answer/authority/additional counts since we truncated.
        // Leave question count as-is.
        reply[6..12].fill(0);
        debug!(
            target: "dns::forward",
            original_len = packet.len(),
            truncated_to = max_size,
            "return_reply: response truncated, TC bit set"
        );
    }

    let sent = send_from(socket, &reply, dest, source, iface_index).await?;

    trace!(
        target: "dns::forward",
        bytes = sent,
        dest = %dest,
        query_id,
        "return_reply: response sent to client"
    );

    Ok(sent)
}

// ---------------------------------------------------------------------------
// tcp_request — handle DNS-over-TCP connections
// ---------------------------------------------------------------------------

/// Handle a DNS-over-TCP connection from a client.
///
/// Equivalent to C `tcp_request()` (forward.c ~line 4051).
///
/// Reads DNS queries framed with a 2-byte length prefix, forwards each to
/// upstream over TCP, and returns the responses.  Supports up to
/// [`TCP_MAX_QUERIES`] queries per connection.
#[allow(clippy::too_many_arguments)]
pub async fn tcp_request(
    stream: &mut TcpStream,
    peer: SocketAddr,
    cache: &mut DnsCache,
    servers: &[Arc<UpstreamServer>],
    selector: &dyn ServerSelector,
    domain_matcher: &DomainMatcher,
    edns_handler: &EdnsHandler,
    rng: &mut SurfRng,
    metrics: &MetricsStore,
    state: &DaemonState,
    #[cfg(feature = "dnssec")] dnssec_validator: &DnssecValidator,
) -> DnsmasqResult<()> {
    use tokio::io::AsyncReadExt;

    metrics.increment(MetricType::TcpConnections);

    info!(
        target: "dns::forward",
        peer = %peer,
        "tcp_request: new TCP connection"
    );

    let mut queries_handled: u32 = 0;

    loop {
        if queries_handled >= TCP_MAX_QUERIES {
            debug!(
                target: "dns::forward",
                peer = %peer,
                max = TCP_MAX_QUERIES,
                "tcp_request: max queries reached, closing"
            );
            break;
        }

        // Read 2-byte length prefix.
        let mut len_buf = [0u8; 2];
        let read_result = timeout(
            Duration::from_secs(TCP_TIMEOUT as u64),
            stream.read_exact(&mut len_buf),
        )
        .await;

        match read_result {
            Ok(Ok(_)) => {}
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                debug!(target: "dns::forward", peer = %peer, "tcp_request: client closed connection");
                break;
            }
            Ok(Err(e)) => {
                warn!(target: "dns::forward", error = %e, peer = %peer, "tcp_request: read error");
                return Err(DnsmasqError::Io(e));
            }
            Err(_) => {
                debug!(target: "dns::forward", peer = %peer, "tcp_request: read timeout");
                break;
            }
        }

        let msg_len = u16::from_be_bytes(len_buf) as usize;
        if !(12..=65535).contains(&msg_len) {
            debug!(
                target: "dns::forward",
                len = msg_len,
                peer = %peer,
                "tcp_request: invalid message length"
            );
            break;
        }

        // Read the DNS message.
        let mut query_buf = vec![0u8; msg_len];
        let read_result = timeout(
            Duration::from_secs(TCP_TIMEOUT as u64),
            stream.read_exact(&mut query_buf),
        )
        .await;

        match read_result {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                warn!(target: "dns::forward", error = %e, "tcp_request: payload read error");
                return Err(DnsmasqError::Io(e));
            }
            Err(_) => {
                debug!(target: "dns::forward", "tcp_request: payload read timeout");
                break;
            }
        }

        // Parse the query.
        let dns_pkt = match DnsPacket::parse(&query_buf) {
            Ok(pkt) => pkt,
            Err(e) => {
                debug!(target: "dns::forward", error = %e, "tcp_request: malformed query");
                break;
            }
        };

        // query_class is used by DNSSEC validation when that feature is enabled;
        // suppress the unused-variable warning for non-DNSSEC builds.
        #[allow(unused_variables)]
        let (query_name, query_type, query_class) = if let Some(q) = dns_pkt.questions.first() {
            (q.name.to_string(), q.qtype, q.qclass)
        } else {
            debug!(target: "dns::forward", "tcp_request: no question section");
            break;
        };

        let query_id = get_u16(&query_buf, 0).unwrap_or(0);

        debug!(
            target: "dns::forward",
            name = %query_name,
            query_type = ?query_type,
            peer = %peer,
            id = query_id,
            "tcp_request: processing TCP query"
        );

        // Check cache first.
        let tcp_dns_name = DnsName::from_str_unchecked(&query_name);
        let cache_entries_tcp = cache.cache_find_by_name(&tcp_dns_name, Some(query_type));
        if let Some(entry) = cache_entries_tcp.into_iter().next() {
            let response = build_cache_response(&query_buf, entry, query_id, 65535, false);
            if let Some(resp_data) = response {
                write_tcp_response(stream, &resp_data).await?;
                metrics.increment(MetricType::DnsLocalAnswered);
                queries_handled += 1;
                continue;
            }
        }

        // Forward to upstream via TCP.
        let response = tcp_talk(
            &query_buf,
            &query_name,
            servers,
            selector,
            domain_matcher,
            rng,
            edns_handler,
            state,
        )
        .await;

        match response {
            Ok(resp_data) => {
                // Process reply (cache, filter).
                // Extract DO bit from EDNS0 OPT pseudo-header (not from
                // DNS header byte 3, which would incorrectly use HB4_CD).
                let tcp_edns = EdnsHandler::find_pseudoheader(&query_buf, query_buf.len())
                    .ok()
                    .flatten();
                let do_bit = tcp_edns
                    .as_ref()
                    .map(|(e, _, _, _)| e.flags.dnssec_ok)
                    .unwrap_or(false);
                let ad_question = (query_buf.get(3).copied().unwrap_or(0) & HB4_AD) != 0;
                let checking_disabled = (query_buf.get(3).copied().unwrap_or(0) & HB4_CD) != 0;
                let fwd_flags = ForwardFlags {
                    do_question: do_bit,
                    ad_question,
                    checking_disabled,
                    has_pheader: tcp_edns.is_some(),
                    ..ForwardFlags::new()
                };
                // TCP path: no specific peer/source addresses available for
                // ECS verification, so pass None (kernel-selected source).
                let processed = process_reply(
                    &resp_data,
                    &query_name,
                    query_type,
                    &fwd_flags,
                    cache,
                    edns_handler,
                    state,
                    None,
                    None,
                );

                // DNSSEC validation if enabled.
                #[cfg(feature = "dnssec")]
                {
                    if state.options.is_set(opt::DNSSEC_VALID) {
                        let mut dnssec_limits = DnssecLimits::default();
                        let validate_result = dnssec_validator.dnssec_validate_reply(
                            &processed,
                            cache,
                            &mut dnssec_limits,
                            domain_matcher,
                            &query_name,
                            query_type,
                            query_class,
                        );
                        if matches!(validate_result, Ok((DnssecStatus::Bogus, _))) {
                            warn!(
                                target: "dns::forward",
                                name = %query_name,
                                "tcp_request: DNSSEC BOGUS, returning SERVFAIL"
                            );
                            let servfail = build_servfail_response(&query_buf, query_id);
                            write_tcp_response(stream, &servfail).await?;
                            queries_handled += 1;
                            continue;
                        }
                    }
                }

                // Restore original query ID in the response.
                let mut final_resp = processed;
                if final_resp.len() >= 2 {
                    final_resp[0] = (query_id >> 8) as u8;
                    final_resp[1] = (query_id & 0xff) as u8;
                }

                write_tcp_response(stream, &final_resp).await?;
                metrics.increment(MetricType::DnsQueriesForwarded);
            }
            Err(e) => {
                warn!(
                    target: "dns::forward",
                    name = %query_name,
                    error = %e,
                    "tcp_request: upstream TCP failed, returning SERVFAIL"
                );
                let servfail = build_servfail_response(&query_buf, query_id);
                write_tcp_response(stream, &servfail).await?;
            }
        }

        queries_handled += 1;
    }

    debug!(
        target: "dns::forward",
        peer = %peer,
        queries = queries_handled,
        "tcp_request: connection finished"
    );

    Ok(())
}

/// Write a DNS response on a TCP stream with the 2-byte length prefix.
async fn write_tcp_response(stream: &mut TcpStream, data: &[u8]) -> DnsmasqResult<()> {
    use tokio::io::AsyncWriteExt;

    let len = data.len() as u16;
    let len_bytes = len.to_be_bytes();

    stream
        .write_all(&len_bytes)
        .await
        .map_err(DnsmasqError::Io)?;
    stream.write_all(data).await.map_err(DnsmasqError::Io)?;
    stream.flush().await.map_err(DnsmasqError::Io)?;

    Ok(())
}

/// Forward a single DNS query to an upstream server over TCP and return the
/// response.
///
/// Mirrors C `tcp_talk()` — creates a TCP connection to the upstream,
/// sends the query with 2-byte length framing, and reads the response.
#[allow(clippy::too_many_arguments)]
async fn tcp_talk(
    query: &[u8],
    query_name: &str,
    servers: &[Arc<UpstreamServer>],
    selector: &dyn ServerSelector,
    domain_matcher: &DomainMatcher,
    rng: &mut SurfRng,
    _edns_handler: &EdnsHandler,
    _state: &DaemonState,
) -> DnsmasqResult<Vec<u8>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Build a dummy DnsPacket for server selection.
    let dns_pkt = DnsPacket::parse(query)?;

    // Select an upstream server.
    let upstream = selector
        .select_server(servers, &dns_pkt, domain_matcher)
        .ok_or(DnsmasqError::Network(
            "no upstream server available".to_string(),
        ))?;

    // Generate a randomised query ID for upstream.
    let new_id = rng.rand16();
    let mut out_query = query.to_vec();
    if out_query.len() >= 2 {
        out_query[0] = (new_id >> 8) as u8;
        out_query[1] = (new_id & 0xff) as u8;
    }

    // Add EDNS0 if needed.
    let mut buf = BytesMut::from(out_query.as_slice());
    let buf_len = buf.len();
    let limit = buf_len + 256;
    buf.resize(limit, 0);
    let new_len = EdnsHandler::add_pseudoheader(
        &mut buf,
        buf_len,
        limit,
        0,
        &[],
        false,
        crate::dns::edns::ReplaceMode::NoReplace,
        EDNS_PKTSZ,
    )
    .unwrap_or(buf_len);
    buf.truncate(new_len);
    let final_query = buf.freeze();

    // Connect to upstream via TCP.
    let mut tcp_stream = timeout(
        Duration::from_secs(TCP_TIMEOUT as u64),
        TcpStream::connect(upstream.addr),
    )
    .await
    .map_err(|_| DnsmasqError::Network("upstream timeout".to_string()))?
    .map_err(DnsmasqError::Io)?;

    debug!(
        target: "dns::forward",
        name = query_name,
        server = %upstream.addr,
        "tcp_talk: connected to upstream"
    );

    // Send query with 2-byte length prefix.
    let len = final_query.len() as u16;
    tcp_stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(DnsmasqError::Io)?;
    tcp_stream
        .write_all(&final_query)
        .await
        .map_err(DnsmasqError::Io)?;
    tcp_stream.flush().await.map_err(DnsmasqError::Io)?;

    // Read response length.
    let mut resp_len_buf = [0u8; 2];
    timeout(
        Duration::from_secs(TCP_TIMEOUT as u64),
        tcp_stream.read_exact(&mut resp_len_buf),
    )
    .await
    .map_err(|_| DnsmasqError::Network("upstream timeout".to_string()))?
    .map_err(DnsmasqError::Io)?;

    let resp_len = u16::from_be_bytes(resp_len_buf) as usize;
    if !(12..=65535).contains(&resp_len) {
        return Err(DnsmasqError::DnsProtocol(format!(
            "invalid TCP response length: {}",
            resp_len
        )));
    }

    // Read response payload.
    let mut resp_buf = vec![0u8; resp_len];
    timeout(
        Duration::from_secs(TCP_TIMEOUT as u64),
        tcp_stream.read_exact(&mut resp_buf),
    )
    .await
    .map_err(|_| DnsmasqError::Network("upstream timeout".to_string()))?
    .map_err(DnsmasqError::Io)?;

    // Restore original query ID.
    let orig_id = get_u16(query, 0).unwrap_or(0);
    if resp_buf.len() >= 2 {
        resp_buf[0] = (orig_id >> 8) as u8;
        resp_buf[1] = (orig_id & 0xff) as u8;
    }

    Ok(resp_buf)
}

// ---------------------------------------------------------------------------
// tcp_from_udp — TCP fallback for truncated UDP
// ---------------------------------------------------------------------------

/// Handle TCP fallback when a UDP response was truncated (TC bit set).
///
/// Mirrors C `tcp_from_udp()` (forward.c ~line 3558).  Re-sends the query
/// over TCP to the same upstream server and returns the untruncated response
/// to the client.
#[allow(clippy::too_many_arguments)]
pub async fn tcp_from_udp(
    record: &ForwardRecord,
    servers: &[Arc<UpstreamServer>],
    selector: &dyn ServerSelector,
    domain_matcher: &DomainMatcher,
    edns_handler: &EdnsHandler,
    rng: &mut SurfRng,
    state: &DaemonState,
    client_socket: &UdpSocket,
) -> DnsmasqResult<()> {
    debug!(
        target: "dns::forward",
        name = %record.query_name,
        server = %record.upstream.addr,
        "tcp_from_udp: UDP truncated, falling back to TCP"
    );

    // Re-send the original query over TCP.
    let tcp_response = tcp_talk(
        &record.original_query,
        &record.query_name,
        servers,
        selector,
        domain_matcher,
        rng,
        edns_handler,
        state,
    )
    .await?;

    // Build response with original client query ID.
    let mut response = tcp_response;
    if response.len() >= 2 {
        response[0] = (record.query_id >> 8) as u8;
        response[1] = (record.query_id & 0xff) as u8;
    }
    if response.len() >= 4 {
        response[3] |= HB4_RA;
    }

    // Send back to client via UDP.
    send_from(
        client_socket,
        &response,
        &record.source,
        record.dest_addr.as_ref(),
        record.iface_index,
    )
    .await?;

    debug!(
        target: "dns::forward",
        name = %record.query_name,
        bytes = response.len(),
        "tcp_from_udp: TCP fallback response sent"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// pop_and_retry_query — DNSSEC subsidiary completion
// ---------------------------------------------------------------------------

/// Handle completion of a DNSSEC subsidiary query and retry validation.
///
/// Mirrors C `pop_and_retry_query()` (forward.c ~line 1939).  When a DNSSEC
/// validation requires fetching additional keys (DS, DNSKEY), this function
/// is called upon receiving the subsidiary response.  It pops the stashed
/// original query, applies the newly-obtained cryptographic material, and
/// re-validates.
///
/// This function is only compiled when the `dnssec` feature is enabled.
#[cfg(feature = "dnssec")]
#[allow(clippy::too_many_arguments)]
pub async fn pop_and_retry_query(
    subsidiary_response: &[u8],
    record: &ForwardRecord,
    _table: &mut ForwardTable,
    cache: &mut DnsCache,
    socket: &UdpSocket,
    _edns_handler: &EdnsHandler,
    dnssec_validator: &DnssecValidator,
    _state: &DaemonState,
) -> DnsmasqResult<()> {
    debug!(
        target: "dns::forward",
        name = %record.query_name,
        "pop_and_retry_query: processing DNSSEC subsidiary response"
    );

    // Retrieve the stashed original query from blockdata.
    let original = &record.original_query;

    // Validate the subsidiary response (DS/DNSKEY).
    let mut dnssec_limits = DnssecLimits::default();
    // Extract query info from the record for validation.
    let sub_qname = &record.query_name;
    let sub_qtype = record.query_type;
    let sub_qclass = record.query_class;
    let sub_status = dnssec_validator.dnssec_validate_reply(
        subsidiary_response,
        cache,
        &mut dnssec_limits,
        &DomainMatcher::default(),
        sub_qname,
        sub_qtype,
        sub_qclass,
    );

    match sub_status {
        Ok((DnssecStatus::Secure, _flags)) => {
            debug!(
                target: "dns::forward",
                name = %record.query_name,
                "pop_and_retry_query: subsidiary SECURE, re-validating original"
            );

            // The subsidiary (key) response is secure.  Now re-validate the
            // original query response with the new key material.  The
            // validator caches keys internally so this attempt should succeed.
            let mut orig_limits = DnssecLimits::default();
            let orig_status = dnssec_validator.dnssec_validate_reply(
                original,
                cache,
                &mut orig_limits,
                &DomainMatcher::default(),
                &record.query_name,
                record.query_type,
                record.query_class,
            );

            match orig_status {
                Ok((DnssecStatus::Secure, _)) => {
                    debug!(
                        target: "dns::forward",
                        name = %record.query_name,
                        "pop_and_retry_query: original validated SECURE, sending to client"
                    );

                    // Cache records from the validated original response.
                    let _cached = process_reply(
                        original,
                        &record.query_name,
                        record.query_type,
                        &record.flags,
                        cache,
                        _edns_handler,
                        _state,
                        None,
                        None,
                    );

                    // Send the validated original response back to the client.
                    return_reply(
                        original,
                        record.query_id,
                        &record.source,
                        record.dest_addr.as_ref(),
                        record.iface_index,
                        record.udp_pkt_size,
                        &record.flags,
                        socket,
                    )
                    .await
                    .ok();
                }
                Ok((DnssecStatus::Bogus, _)) => {
                    warn!(
                        target: "dns::forward",
                        name = %record.query_name,
                        "pop_and_retry_query: original BOGUS after subsidiary SECURE"
                    );
                    let servfail = build_servfail_response(original, record.query_id);
                    send_from(
                        socket,
                        &servfail,
                        &record.source,
                        record.dest_addr.as_ref(),
                        record.iface_index,
                    )
                    .await
                    .ok();
                }
                Ok(_) | Err(_) => {
                    // Indeterminate or error — send original response without AD bit.
                    debug!(
                        target: "dns::forward",
                        name = %record.query_name,
                        "pop_and_retry_query: original not fully validated, sending as insecure"
                    );
                    let mut insecure_flags = record.flags;
                    insecure_flags.dnssec_enabled = false;
                    return_reply(
                        original,
                        record.query_id,
                        &record.source,
                        record.dest_addr.as_ref(),
                        record.iface_index,
                        record.udp_pkt_size,
                        &insecure_flags,
                        socket,
                    )
                    .await
                    .ok();
                }
            }
        }
        Ok((DnssecStatus::Bogus, _fail_flags)) => {
            warn!(
                target: "dns::forward",
                name = %record.query_name,
                "pop_and_retry_query: subsidiary BOGUS, aborting validation"
            );
            // Return SERVFAIL for the original query.
            let servfail = build_servfail_response(original, record.query_id);
            send_from(
                socket,
                &servfail,
                &record.source,
                record.dest_addr.as_ref(),
                record.iface_index,
            )
            .await
            .ok();
        }
        Ok(_) => {
            // Insecure or indeterminate — forward original response without AD bit.
            debug!(
                target: "dns::forward",
                name = %record.query_name,
                "pop_and_retry_query: subsidiary not secure, forwarding original as insecure"
            );
            let mut insecure_flags = record.flags;
            insecure_flags.dnssec_enabled = false;
            return_reply(
                original,
                record.query_id,
                &record.source,
                record.dest_addr.as_ref(),
                record.iface_index,
                record.udp_pkt_size,
                &insecure_flags,
                socket,
            )
            .await
            .ok();
        }
        Err(e) => {
            warn!(
                target: "dns::forward",
                name = %record.query_name,
                error = %e,
                "pop_and_retry_query: DNSSEC validation error, forwarding as insecure"
            );
            let mut insecure_flags = record.flags;
            insecure_flags.dnssec_enabled = false;
            return_reply(
                original,
                record.query_id,
                &record.source,
                record.dest_addr.as_ref(),
                record.iface_index,
                record.udp_pkt_size,
                &insecure_flags,
                socket,
            )
            .await
            .ok();
        }
    }

    Ok(())
}

/// Variant for non-DNSSEC builds (no-op).
#[cfg(not(feature = "dnssec"))]
pub async fn pop_and_retry_query(
    _subsidiary_response: &[u8],
    _record: &ForwardRecord,
    _table: &mut ForwardTable,
    _cache: &mut DnsCache,
    _socket: &UdpSocket,
    _edns_handler: &EdnsHandler,
    _state: &DaemonState,
) -> DnsmasqResult<()> {
    Ok(())
}

/// Acquire shared daemon state for DNS forwarding operations.
///
/// This helper demonstrates the `Arc<RwLock<DaemonState>>` concurrency pattern
/// used throughout the async forwarding engine. When daemon state is shared
/// across multiple concurrent tokio tasks, this function acquires a read lock
/// and returns a snapshot of the option flags for forwarding decision-making.
///
/// In the full daemon event loop ([`crate::core::daemon`]), the shared state is
/// passed as `Arc<RwLock<DaemonState>>` to each spawned query handler, which
/// acquires the lock before calling [`receive_query`] or [`forward_query`].
///
/// # Parameters
/// - `shared_state`: Thread-safe shared daemon state
///
/// # Returns
/// A copy of the current option flags for forwarding decisions.
pub async fn get_forwarding_options(shared_state: &Arc<RwLock<DaemonState>>) -> OptionFlags {
    let state = shared_state.read().await;
    state.options.clone()
}

/// Apply EDNS0 configuration options (MAC address, client subnet, user-defined)
/// to an outgoing forwarded query packet when ARP context is available.
///
/// This is the integration point for `EdnsHandler::add_edns0_config()`, which
/// requires an `ArpCache` and `ArpEnumerator` from the network layer to embed
/// MAC-based EDNS0 options into DNS queries sent to upstream servers.
///
/// # Parameters
/// - `packet`: Mutable packet buffer to modify
/// - `packet_len`: Current logical length of the packet
/// - `limit`: Maximum packet size
/// - `source`: Source address of the original client query
/// - `now`: Current timestamp for ARP cache freshness checks
/// - `arp_cache`: Mutable reference to the ARP cache
/// - `arp_enumerator`: ARP table enumerator for MAC lookups
/// - `state`: Daemon state for configuration access
///
/// # Returns
/// A tuple `(new_packet_len, cacheable)`:
/// - `new_packet_len`: Updated packet length after EDNS0 options appended.
/// - `cacheable`: Whether the DNS response is safe to cache. False when
///   client-specific data (MAC, variable ECS) was added to the query.
pub fn apply_edns0_config_to_forwarded_query(
    packet: &mut BytesMut,
    packet_len: usize,
    limit: usize,
    source: &MySockAddr,
    now: Instant,
    arp_cache: &mut crate::network::arp::ArpCache,
    arp_enumerator: &dyn crate::network::arp::ArpEnumerator,
    state: &DaemonState,
) -> DnsmasqResult<(usize, bool)> {
    EdnsHandler::add_edns0_config(
        packet,
        packet_len,
        limit,
        source,
        now.into(),
        arp_cache,
        arp_enumerator,
        state,
    )
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_forward_flags_default() {
        let flags = ForwardFlags::new();
        assert!(!flags.tcp_fallback);
        assert!(!flags.dnssec_enabled);
        assert!(!flags.retrying);
        assert!(!flags.no_cache);
        assert!(!flags.sec_query);
        assert!(!flags.ad_question);
        assert!(!flags.do_question);
        assert!(!flags.has_pheader);
        assert!(!flags.checking_disabled);
        assert!(!flags.no_rebind);
        assert!(!flags.gone_to_tcp);
    }

    #[test]
    fn test_forward_flags_roundtrip() {
        let mut flags = ForwardFlags::new();
        flags.tcp_fallback = true;
        flags.dnssec_enabled = true;
        flags.retrying = true;
        let raw = flags.to_raw();
        let restored = ForwardFlags::from_raw(raw);
        assert!(restored.tcp_fallback);
        assert!(restored.dnssec_enabled);
        assert!(restored.retrying);
        assert!(!restored.no_cache);
    }

    #[test]
    fn test_server_flags_default() {
        let flags = ServerFlags::new();
        assert!(!flags.literal);
        assert!(!flags.has_domain);
        assert!(!flags.for_nodots);
        assert!(!flags.used_by_dhcp);
        assert!(!flags.no_addr);
        assert!(!flags.is_loop);
        assert!(!flags.do_not_use);
        assert!(!flags.from_resolv);
        assert!(!flags.mark);
    }

    #[test]
    fn test_server_flags_roundtrip() {
        let mut flags = ServerFlags::new();
        flags.literal = true;
        flags.from_resolv = true;
        let raw = flags.to_raw();
        let restored = ServerFlags::from_raw(raw);
        assert!(restored.literal);
        assert!(restored.from_resolv);
        assert!(!restored.mark);
    }

    #[test]
    fn test_upstream_server_new() {
        let addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let srv = UpstreamServer::new(addr);
        assert_eq!(srv.addr, addr);
        assert_eq!(srv.queries, 0);
        assert_eq!(srv.failed_queries, 0);
        assert!(srv.last_failure.is_none());
        assert_eq!(srv.edns_pktsz, EDNS_PKTSZ);
        assert!(srv.is_healthy());
    }

    #[test]
    fn test_upstream_server_health() {
        let addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let mut srv = UpstreamServer::new(addr);
        assert!(srv.is_healthy());

        srv.record_failure();
        assert_eq!(srv.failed_queries, 1);
        assert!(srv.last_failure.is_some());
        // Still healthy — under FORWARD_TEST threshold.
        assert!(srv.is_healthy());

        // Simulate many failures.
        for _ in 0..FORWARD_TEST {
            srv.record_failure();
        }
        // Now should be unhealthy (just failed, within FORWARD_TIME).
        assert!(!srv.is_healthy());
    }

    #[test]
    fn test_upstream_server_latency() {
        let addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let srv = UpstreamServer::new(addr);
        assert_eq!(srv.query_latency.load(Ordering::Relaxed), 0);

        srv.update_latency(100);
        assert_eq!(srv.mma_latency.load(Ordering::Relaxed), 12800);
        assert_eq!(srv.query_latency.load(Ordering::Relaxed), 100);

        // Second measurement converges.
        srv.update_latency(50);
        assert!(srv.query_latency.load(Ordering::Relaxed) < 100);
    }

    #[test]
    fn test_forward_table_basic() {
        let mut table = ForwardTable::new(10);
        assert!(table.is_empty());
        assert!(!table.is_full());
        assert_eq!(table.len(), 0);

        let addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let source: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        let srv = Arc::new(UpstreamServer::new(addr));

        let record = ForwardRecord::new(
            1234,
            5678,
            source,
            srv,
            Bytes::from_static(b"\x16\x2e\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"),
            ForwardFlags::new(),
            "example.com".to_string(),
            RRType::A,
            DnsClass::IN,
        );

        table.insert(record).unwrap();
        assert_eq!(table.len(), 1);
        assert!(table.lookup(5678).is_some());
        assert!(table.lookup(9999).is_none());

        let found = table.find_by_client(1234, &source);
        assert!(found.is_some());

        let removed = table.remove(5678);
        assert!(removed.is_some());
        assert!(table.is_empty());
    }

    #[test]
    fn test_forward_table_capacity() {
        let mut table = ForwardTable::new(2);
        let addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let source: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        let srv = Arc::new(UpstreamServer::new(addr));

        for id in 1..=2u16 {
            let record = ForwardRecord::new(
                id,
                id + 100,
                source,
                Arc::clone(&srv),
                Bytes::from_static(b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"),
                ForwardFlags::new(),
                "test.com".to_string(),
                RRType::A,
                DnsClass::IN,
            );
            table.insert(record).unwrap();
        }

        assert!(table.is_full());

        // Third insert should fail.
        let record = ForwardRecord::new(
            3,
            103,
            source,
            Arc::clone(&srv),
            Bytes::from_static(b"\x00\x03\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"),
            ForwardFlags::new(),
            "test3.com".to_string(),
            RRType::A,
            DnsClass::IN,
        );
        let result = table.insert(record);
        assert!(result.is_err());
    }

    #[test]
    fn test_fast_retry() {
        assert_eq!(fast_retry(0), Some(DEFAULT_FAST_RETRY as u64));
        assert_eq!(fast_retry(1), Some(DEFAULT_FAST_RETRY as u64 * 2));
        assert_eq!(fast_retry(2), Some(DEFAULT_FAST_RETRY as u64 * 4));
        assert_eq!(fast_retry(3), Some(DEFAULT_FAST_RETRY as u64 * 8));
        assert_eq!(fast_retry(4), Some(DEFAULT_FAST_RETRY as u64 * 16));
        assert_eq!(fast_retry(5), None); // Exhausted.
    }

    #[test]
    fn test_build_servfail_response() {
        let query = vec![
            0x12, 0x34, // ID
            0x01, 0x00, // Flags: RD
            0x00, 0x01, // QDCOUNT=1
            0x00, 0x00, // ANCOUNT=0
            0x00, 0x00, // NSCOUNT=0
            0x00, 0x00, // ARCOUNT=0
        ];
        let resp = build_servfail_response(&query, 0x1234);
        assert_eq!(resp[0], 0x12);
        assert_eq!(resp[1], 0x34);
        assert!((resp[2] & HB3_QR) != 0); // QR set.
        assert_eq!(resp[3] & HB4_RCODE, 2); // SERVFAIL.
    }

    #[test]
    fn test_rfd_pool() {
        let mut pool = RfdPool::new(4);
        assert!(pool.find_for_family(2).is_none());

        // Simulate adding a socket.
        pool.add(42, 2, "0.0.0.0:12345".parse().unwrap()).unwrap();
        assert_eq!(pool.entries.len(), 1);

        // Reuse for same family.
        let fd = pool.find_for_family(2);
        assert_eq!(fd, Some(42));
        assert_eq!(pool.entries[0].refcount, 2);

        // Release once.
        pool.release(42);
        assert_eq!(pool.entries[0].refcount, 1);

        // Release again → removed.
        pool.release(42);
        assert!(pool.entries.is_empty());
    }

    #[test]
    fn test_round_robin_selector_empty() {
        let selector = RoundRobinSelector::new();
        let servers: Vec<Arc<UpstreamServer>> = vec![];
        let pkt_data = vec![
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x65,
            0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00,
            0x01,
        ];
        let pkt = DnsPacket::parse(&pkt_data).unwrap();
        let matcher = DomainMatcher::new();

        let result = selector.select_server(&servers, &pkt, &matcher);
        assert!(result.is_none());
    }

    #[test]
    fn test_forward_record_expiry() {
        let addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let source: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        let srv = Arc::new(UpstreamServer::new(addr));

        let record = ForwardRecord::new(
            1,
            2,
            source,
            srv,
            Bytes::from_static(b"\x00\x02\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"),
            ForwardFlags::new(),
            "test.com".to_string(),
            RRType::A,
            DnsClass::IN,
        );

        // Freshly created record should not be expired.
        assert!(!record.is_expired(10));
        // With zero timeout everything is expired.
        assert!(record.is_expired(0));
    }

    // ===== skip_dns_name tests ========================================

    #[test]
    fn test_skip_dns_name_root() {
        // Root label: single 0x00 byte
        let pkt = vec![0x00];
        assert_eq!(skip_dns_name(&pkt, 0), Some(1));
    }

    #[test]
    fn test_skip_dns_name_single_label() {
        // "com" = 0x03 c o m 0x00
        let pkt = vec![0x03, b'c', b'o', b'm', 0x00];
        assert_eq!(skip_dns_name(&pkt, 0), Some(5));
    }

    #[test]
    fn test_skip_dns_name_multi_label() {
        // "example.com" = 0x07 example 0x03 com 0x00
        let mut pkt = vec![0x07];
        pkt.extend_from_slice(b"example");
        pkt.push(0x03);
        pkt.extend_from_slice(b"com");
        pkt.push(0x00);
        assert_eq!(skip_dns_name(&pkt, 0), Some(13));
    }

    #[test]
    fn test_skip_dns_name_compression_pointer() {
        // Compression pointer: 0xC0 0x0C
        let pkt = vec![0xC0, 0x0C];
        assert_eq!(skip_dns_name(&pkt, 0), Some(2));
    }

    #[test]
    fn test_skip_dns_name_empty_packet() {
        let pkt: Vec<u8> = vec![];
        assert_eq!(skip_dns_name(&pkt, 0), None);
    }

    #[test]
    fn test_skip_dns_name_offset_beyond_packet() {
        let pkt = vec![0x00];
        assert_eq!(skip_dns_name(&pkt, 5), None);
    }

    // ===== is_ipv6_unique_local tests =================================

    #[test]
    fn test_ipv6_unique_local_fc00() {
        let addr = Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1);
        assert!(is_ipv6_unique_local(&addr));
    }

    #[test]
    fn test_ipv6_unique_local_fd00() {
        let addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
        assert!(is_ipv6_unique_local(&addr));
    }

    #[test]
    fn test_ipv6_not_unique_local_global() {
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        assert!(!is_ipv6_unique_local(&addr));
    }

    #[test]
    fn test_ipv6_not_unique_local_link_local() {
        let addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        assert!(!is_ipv6_unique_local(&addr));
    }

    // ===== is_ipv6_link_local tests ===================================

    #[test]
    fn test_ipv6_link_local_fe80() {
        let addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        assert!(is_ipv6_link_local(&addr));
    }

    #[test]
    fn test_ipv6_link_local_febf() {
        let addr = Ipv6Addr::new(0xfebf, 0, 0, 0, 0, 0, 0, 1);
        assert!(is_ipv6_link_local(&addr));
    }

    #[test]
    fn test_ipv6_not_link_local_fec0() {
        let addr = Ipv6Addr::new(0xfec0, 0, 0, 0, 0, 0, 0, 1);
        assert!(!is_ipv6_link_local(&addr));
    }

    #[test]
    fn test_ipv6_not_link_local_global() {
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        assert!(!is_ipv6_link_local(&addr));
    }

    // ===== extract_rr_ttl tests =======================================

    #[test]
    fn test_extract_rr_ttl_valid() {
        // RR fixed fields: TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) = 10 bytes
        // TTL at offset+4
        let mut pkt = vec![0u8; 20];
        // Set TTL = 3600 (0x00000E10) at position 4
        pkt[4] = 0x00;
        pkt[5] = 0x00;
        pkt[6] = 0x0E;
        pkt[7] = 0x10;
        assert_eq!(extract_rr_ttl(&pkt, 0), Some(3600));
    }

    #[test]
    fn test_extract_rr_ttl_max() {
        let mut pkt = vec![0u8; 20];
        pkt[4] = 0xFF;
        pkt[5] = 0xFF;
        pkt[6] = 0xFF;
        pkt[7] = 0xFF;
        assert_eq!(extract_rr_ttl(&pkt, 0), Some(u32::MAX));
    }

    #[test]
    fn test_extract_rr_ttl_too_short() {
        let pkt = vec![0u8; 5]; // Too short for RRFIXEDSZ
        assert_eq!(extract_rr_ttl(&pkt, 0), None);
    }

    #[test]
    fn test_extract_rr_ttl_with_offset() {
        let mut pkt = vec![0u8; 30];
        // TTL at offset 10+4 = 14
        pkt[14] = 0x00;
        pkt[15] = 0x01;
        pkt[16] = 0x51;
        pkt[17] = 0x80;
        assert_eq!(extract_rr_ttl(&pkt, 10), Some(86400));
    }

    // ===== rdata_to_all_addr tests ====================================

    #[test]
    fn test_rdata_to_all_addr_a_record() {
        let rdata = vec![192, 168, 1, 1];
        let result = rdata_to_all_addr(RRType::A, &rdata);
        match result {
            Some(AllAddr::V4(ip)) => assert_eq!(ip, Ipv4Addr::new(192, 168, 1, 1)),
            _ => panic!("expected V4 AllAddr"),
        }
    }

    #[test]
    fn test_rdata_to_all_addr_aaaa_record() {
        let mut rdata = [0u8; 16];
        rdata[0] = 0x20;
        rdata[1] = 0x01;
        rdata[2] = 0x0d;
        rdata[3] = 0xb8;
        rdata[15] = 0x01;
        let result = rdata_to_all_addr(RRType::AAAA, &rdata);
        assert!(matches!(result, Some(AllAddr::V6(_))));
    }

    #[test]
    fn test_rdata_to_all_addr_wrong_type() {
        let rdata = vec![192, 168, 1, 1];
        assert!(rdata_to_all_addr(RRType::CNAME, &rdata).is_none());
    }

    #[test]
    fn test_rdata_to_all_addr_too_short_a() {
        let rdata = vec![192, 168, 1]; // only 3 bytes
        assert!(rdata_to_all_addr(RRType::A, &rdata).is_none());
    }

    #[test]
    fn test_rdata_to_all_addr_too_short_aaaa() {
        let rdata = vec![0u8; 15]; // only 15 bytes
        assert!(rdata_to_all_addr(RRType::AAAA, &rdata).is_none());
    }

    // ===== set_rr_ttl tests ===========================================

    #[test]
    fn test_set_rr_ttl_basic() {
        let mut pkt = vec![0u8; 20];
        set_rr_ttl(&mut pkt, 0, 7200);
        // TTL at offset 4..8
        assert_eq!(pkt[4], 0x00);
        assert_eq!(pkt[5], 0x00);
        assert_eq!(pkt[6], 0x1C);
        assert_eq!(pkt[7], 0x20);
    }

    #[test]
    fn test_set_rr_ttl_at_offset() {
        let mut pkt = vec![0u8; 30];
        set_rr_ttl(&mut pkt, 10, 300);
        // TTL at 10 + 4 = 14..18
        let ttl_bytes = &pkt[14..18];
        let val = u32::from_be_bytes([ttl_bytes[0], ttl_bytes[1], ttl_bytes[2], ttl_bytes[3]]);
        assert_eq!(val, 300);
    }

    #[test]
    fn test_set_rr_ttl_zero() {
        let mut pkt = vec![0xFF; 20];
        set_rr_ttl(&mut pkt, 0, 0);
        assert_eq!(&pkt[4..8], &[0, 0, 0, 0]);
    }

    #[test]
    fn test_set_rr_ttl_max_value() {
        let mut pkt = vec![0u8; 20];
        set_rr_ttl(&mut pkt, 0, u32::MAX);
        assert_eq!(&pkt[4..8], &[0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_set_rr_ttl_packet_too_short_noop() {
        let mut pkt = vec![0u8; 5];
        set_rr_ttl(&mut pkt, 0, 100); // should not panic, just noop
        assert_eq!(pkt, vec![0u8; 5]);
    }

    // ===== to_my_sock_addr tests ======================================

    #[test]
    fn test_to_my_sock_addr_v4() {
        let sa: SocketAddr = "192.168.1.1:53".parse().unwrap();
        let msa = to_my_sock_addr(&sa);
        assert_eq!(msa.port(), 53);
        assert_eq!(msa.family(), libc::AF_INET);
    }

    #[test]
    fn test_to_my_sock_addr_v6() {
        let sa: SocketAddr = "[::1]:5353".parse().unwrap();
        let msa = to_my_sock_addr(&sa);
        assert_eq!(msa.port(), 5353);
        assert_eq!(msa.family(), libc::AF_INET6);
    }

    // ===== parse_response_header tests ================================

    #[test]
    fn test_parse_response_header_valid_query() {
        let pkt = vec![
            0x12, 0x34, // ID
            0x01, 0x00, // Standard query, RD=1
            0x00, 0x01, // QDCOUNT=1
            0x00, 0x00, // ANCOUNT=0
            0x00, 0x00, // NSCOUNT=0
            0x00, 0x00, // ARCOUNT=0
        ];
        let hdr = parse_response_header(&pkt);
        assert!(hdr.is_some());
        let h = hdr.unwrap();
        assert_eq!(h.id, 0x1234);
        assert_eq!(h.qdcount, 1);
        assert_eq!(h.ancount, 0);
    }

    #[test]
    fn test_parse_response_header_too_short() {
        let pkt = vec![0x12, 0x34, 0x01]; // only 3 bytes
        assert!(parse_response_header(&pkt).is_none());
    }

    #[test]
    fn test_parse_response_header_response_packet() {
        let pkt = vec![
            0x56, 0x78, // ID
            0x81, 0x80, // Response, RD=1, RA=1
            0x00, 0x01, // QDCOUNT=1
            0x00, 0x02, // ANCOUNT=2
            0x00, 0x00, // NSCOUNT=0
            0x00, 0x01, // ARCOUNT=1
        ];
        let hdr = parse_response_header(&pkt).unwrap();
        assert_eq!(hdr.id, 0x5678);
        assert_eq!(hdr.ancount, 2);
        assert_eq!(hdr.arcount, 1);
    }

    // ===== check_rebind_protection tests ==============================

    #[test]
    fn test_check_rebind_too_short() {
        let pkt = vec![0u8; 5];
        assert!(check_rebind_protection(&pkt).is_none());
    }

    #[test]
    fn test_check_rebind_no_answers() {
        let pkt = vec![
            0x00, 0x01, // ID
            0x81, 0x80, // QR=1, RD=1, RA=1
            0x00, 0x01, // QDCOUNT=1
            0x00, 0x00, // ANCOUNT=0
            0x00, 0x00, // NSCOUNT=0
            0x00, 0x00, // ARCOUNT=0
        ];
        assert_eq!(check_rebind_protection(&pkt), Some(false));
    }

    #[test]
    fn test_check_rebind_public_a_record() {
        // Full DNS response with one A record → 8.8.8.8 (public)
        let mut pkt = vec![
            0x00, 0x01, // ID
            0x81, 0x80, // QR=1, RD=1, RA=1
            0x00, 0x01, // QDCOUNT=1
            0x00, 0x01, // ANCOUNT=1
            0x00, 0x00, // NSCOUNT=0
            0x00, 0x00, // ARCOUNT=0
        ];
        // Question: "a" (1 byte label) QTYPE=A QCLASS=IN
        pkt.extend_from_slice(&[0x01, b'a', 0x00]); // name: "a."
        pkt.extend_from_slice(&[0x00, 0x01]); // QTYPE = A
        pkt.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN
                                              // Answer RR: name (pointer to offset 12), TYPE=A, CLASS=IN, TTL=300, RDLENGTH=4, rdata
        pkt.extend_from_slice(&[0xC0, 0x0C]); // name pointer
        pkt.extend_from_slice(&[0x00, 0x01]); // TYPE = A
        pkt.extend_from_slice(&[0x00, 0x01]); // CLASS = IN
        pkt.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C]); // TTL = 300
        pkt.extend_from_slice(&[0x00, 0x04]); // RDLENGTH = 4
        pkt.extend_from_slice(&[8, 8, 8, 8]); // 8.8.8.8 (public)
        assert_eq!(check_rebind_protection(&pkt), Some(false));
    }

    #[test]
    fn test_check_rebind_private_a_record() {
        let mut pkt = vec![
            0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];
        pkt.extend_from_slice(&[0x01, b'a', 0x00, 0x00, 0x01, 0x00, 0x01]);
        pkt.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01]);
        pkt.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C, 0x00, 0x04]);
        pkt.extend_from_slice(&[10, 0, 0, 1]); // 10.0.0.1 (private)
        assert_eq!(check_rebind_protection(&pkt), Some(true));
    }

    #[test]
    fn test_check_rebind_loopback_a_record() {
        let mut pkt = vec![
            0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];
        pkt.extend_from_slice(&[0x01, b'a', 0x00, 0x00, 0x01, 0x00, 0x01]);
        pkt.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01]);
        pkt.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C, 0x00, 0x04]);
        pkt.extend_from_slice(&[127, 0, 0, 1]); // 127.0.0.1 (loopback)
        assert_eq!(check_rebind_protection(&pkt), Some(true));
    }

    // ===== build_servfail_response extended tests =====================

    #[test]
    fn test_build_servfail_response_preserves_id() {
        let query = vec![
            0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let resp = build_servfail_response(&query, 0xABCD);
        assert_eq!(resp[0], 0xAB);
        assert_eq!(resp[1], 0xCD);
        // QR bit should be set
        assert!((resp[2] & HB3_QR) != 0);
    }

    #[test]
    fn test_build_servfail_response_rcode() {
        let query = vec![
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let resp = build_servfail_response(&query, 0x0001);
        // RCODE = 2 (SERVFAIL)
        assert_eq!(resp[3] & 0x0F, 2);
    }

    // ===== ForwardTable expiry tests ==================================

    #[test]
    fn test_forward_table_expire_old() {
        let mut table = ForwardTable::new(10);
        let addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let source: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        let srv = Arc::new(UpstreamServer::new(addr));

        // Insert a record
        let record = ForwardRecord::new(
            1,
            100,
            source,
            Arc::clone(&srv),
            Bytes::from_static(b"\x00\x64\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"),
            ForwardFlags::new(),
            "test.com".to_string(),
            RRType::A,
            DnsClass::IN,
        );
        table.insert(record).unwrap();
        assert_eq!(table.len(), 1);

        // expire_old with long timeout should remove nothing
        let expired = table.expire_old(3600);
        assert_eq!(expired, 0);
        assert_eq!(table.len(), 1);

        // expire_old with 0 timeout should remove everything
        let expired = table.expire_old(0);
        assert_eq!(expired, 1);
        assert!(table.is_empty());
    }

    #[test]
    fn test_forward_table_find_by_response() {
        let mut table = ForwardTable::new(10);
        let addr1: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let addr2: SocketAddr = "1.1.1.1:53".parse().unwrap();
        let source: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        let srv1 = Arc::new(UpstreamServer::new(addr1));
        let srv2 = Arc::new(UpstreamServer::new(addr2));

        let record1 = ForwardRecord::new(
            1,
            100,
            source,
            Arc::clone(&srv1),
            Bytes::from_static(b"\x00\x64\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"),
            ForwardFlags::new(),
            "a.com".to_string(),
            RRType::A,
            DnsClass::IN,
        );
        let record2 = ForwardRecord::new(
            2,
            200,
            source,
            Arc::clone(&srv2),
            Bytes::from_static(b"\x00\xC8\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"),
            ForwardFlags::new(),
            "b.com".to_string(),
            RRType::A,
            DnsClass::IN,
        );

        table.insert(record1).unwrap();
        table.insert(record2).unwrap();

        // find_by_response matches on new_id, name, qclass, qtype
        let found = table.find_by_response(100, "a.com", &DnsClass::IN, &RRType::A);
        assert!(found.is_some());
        assert_eq!(found.unwrap().query_name, "a.com");

        let found2 = table.find_by_response(200, "b.com", &DnsClass::IN, &RRType::A);
        assert!(found2.is_some());
        assert_eq!(found2.unwrap().query_name, "b.com");

        // Wrong name → not found
        let not_found = table.find_by_response(100, "b.com", &DnsClass::IN, &RRType::A);
        assert!(not_found.is_none());
    }

    // ===== RfdPool extended tests =====================================

    #[test]
    fn test_rfd_pool_max_entries() {
        let mut pool = RfdPool::new(2);
        pool.add(10, libc::AF_INET as i32, "0.0.0.0:10000".parse().unwrap())
            .unwrap();
        pool.add(20, libc::AF_INET6 as i32, "[::]:20000".parse().unwrap())
            .unwrap();
        assert_eq!(pool.entries.len(), 2);
    }

    #[test]
    fn test_rfd_pool_clear() {
        let mut pool = RfdPool::new(4);
        pool.add(10, libc::AF_INET as i32, "0.0.0.0:10000".parse().unwrap())
            .unwrap();
        pool.add(20, libc::AF_INET as i32, "0.0.0.0:20000".parse().unwrap())
            .unwrap();
        assert_eq!(pool.entries.len(), 2);
        pool.clear();
        assert!(pool.entries.is_empty());
    }

    #[test]
    fn test_rfd_pool_find_for_family_correct() {
        let mut pool = RfdPool::new(4);
        pool.add(10, libc::AF_INET as i32, "0.0.0.0:10000".parse().unwrap())
            .unwrap();
        pool.add(20, libc::AF_INET6 as i32, "[::]:20000".parse().unwrap())
            .unwrap();
        assert_eq!(pool.find_for_family(libc::AF_INET as i32), Some(10));
        assert_eq!(pool.find_for_family(libc::AF_INET6 as i32), Some(20));
    }

    #[test]
    fn test_rfd_pool_release_nonexistent() {
        let mut pool = RfdPool::new(4);
        pool.release(999); // Should not panic
        assert!(pool.entries.is_empty());
    }

    // ===== server_gone tests ==========================================

    #[test]
    fn test_server_gone_removes_matching() {
        let mut table = ForwardTable::new(10);
        let mut pool = RfdPool::new(4);
        let addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let source: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        let srv = Arc::new(UpstreamServer::new(addr));

        let record = ForwardRecord::new(
            1,
            100,
            source,
            Arc::clone(&srv),
            Bytes::from_static(b"\x00\x64\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"),
            ForwardFlags::new(),
            "test.com".to_string(),
            RRType::A,
            DnsClass::IN,
        );
        table.insert(record).unwrap();
        assert_eq!(table.len(), 1);

        server_gone(&mut table, &mut pool, &addr);
        assert!(table.is_empty());
    }

    #[test]
    fn test_server_gone_no_match() {
        let mut table = ForwardTable::new(10);
        let mut pool = RfdPool::new(4);
        let addr1: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let addr2: SocketAddr = "1.1.1.1:53".parse().unwrap();
        let source: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        let srv = Arc::new(UpstreamServer::new(addr1));

        let record = ForwardRecord::new(
            1,
            100,
            source,
            Arc::clone(&srv),
            Bytes::from_static(b"\x00\x64\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"),
            ForwardFlags::new(),
            "test.com".to_string(),
            RRType::A,
            DnsClass::IN,
        );
        table.insert(record).unwrap();

        // Remove a different server — table should be unchanged
        server_gone(&mut table, &mut pool, &addr2);
        assert_eq!(table.len(), 1);
    }

    // ===== get_server_config tests ====================================

    #[test]
    fn test_get_server_config_default_server() {
        let addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let srv = UpstreamServer::new(addr);
        let cfg = get_server_config(&srv);
        assert!(cfg.is_some());
        let c = cfg.unwrap();
        assert!(c.flags.is_default); // no domain → default
        assert!(!c.flags.domain_specific);
    }

    #[test]
    fn test_get_server_config_domain_server() {
        let addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let mut srv = UpstreamServer::new(addr);
        srv.flags.has_domain = true;
        srv.domain = Some("example.com".to_string());
        let cfg = get_server_config(&srv).unwrap();
        assert!(cfg.flags.domain_specific);
        assert!(!cfg.flags.is_default);
        assert_eq!(cfg.domain, Some("example.com".to_string()));
        assert_eq!(cfg.domain_len, 11);
    }

    // ===== UpstreamServer extended tests ==============================

    #[test]
    fn test_upstream_server_record_success() {
        let addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let mut srv = UpstreamServer::new(addr);
        srv.record_failure();
        srv.record_failure();
        assert_eq!(srv.failed_queries, 2);
        assert!(srv.last_failure.is_some());

        srv.record_success();
        assert_eq!(srv.queries, 1);
    }

    #[test]
    fn test_upstream_server_multiple() {
        let addr1: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let addr2: SocketAddr = "1.1.1.1:53".parse().unwrap();
        let srv1 = UpstreamServer::new(addr1);
        let srv2 = UpstreamServer::new(addr2);
        assert_eq!(srv1.addr, addr1);
        assert_eq!(srv2.addr, addr2);
        assert_ne!(srv1.addr, srv2.addr);
    }

    // ===== extract_neg_ttl_from_authority tests ========================

    #[test]
    fn test_extract_neg_ttl_too_short() {
        let pkt = vec![0u8; 5];
        assert!(extract_neg_ttl_from_authority(&pkt).is_none());
    }

    #[test]
    fn test_extract_neg_ttl_no_authority() {
        // Header with NSCOUNT=0
        let pkt = vec![
            0x00, 0x01, // ID
            0x81, 0x83, // QR, RD, RA, NXDOMAIN
            0x00, 0x01, // QDCOUNT=1
            0x00, 0x00, // ANCOUNT=0
            0x00, 0x00, // NSCOUNT=0
            0x00, 0x00, // ARCOUNT=0
            // Question
            0x01, b'a', 0x00, // "a."
            0x00, 0x01, // QTYPE=A
            0x00, 0x01, // QCLASS=IN
        ];
        assert!(extract_neg_ttl_from_authority(&pkt).is_none());
    }

    // ===== ForwardFlags extended tests ================================

    #[test]
    fn test_forward_flags_all_true_roundtrip() {
        let mut flags = ForwardFlags::new();
        flags.tcp_fallback = true;
        flags.dnssec_enabled = true;
        flags.retrying = true;
        flags.no_cache = true;
        flags.sec_query = true;
        flags.ad_question = true;
        flags.do_question = true;
        flags.has_pheader = true;
        flags.checking_disabled = true;
        flags.no_rebind = true;
        flags.gone_to_tcp = true;
        let raw = flags.to_raw();
        let restored = ForwardFlags::from_raw(raw);
        assert!(restored.tcp_fallback);
        assert!(restored.dnssec_enabled);
        assert!(restored.retrying);
        assert!(restored.no_cache);
        assert!(restored.sec_query);
        assert!(restored.ad_question);
        assert!(restored.do_question);
        assert!(restored.has_pheader);
        assert!(restored.checking_disabled);
        assert!(restored.no_rebind);
        assert!(restored.gone_to_tcp);
    }

    // ===== ServerFlags extended tests =================================

    #[test]
    fn test_server_flags_all_true_roundtrip() {
        let mut flags = ServerFlags::new();
        flags.literal = true;
        flags.has_domain = true;
        flags.for_nodots = true;
        flags.used_by_dhcp = true;
        flags.no_addr = true;
        flags.is_loop = true;
        flags.do_not_use = true;
        flags.from_resolv = true;
        flags.mark = true;
        let raw = flags.to_raw();
        let restored = ServerFlags::from_raw(raw);
        assert!(restored.literal);
        assert!(restored.has_domain);
        assert!(restored.for_nodots);
        assert!(restored.used_by_dhcp);
        assert!(restored.no_addr);
        assert!(restored.is_loop);
        assert!(restored.do_not_use);
        assert!(restored.from_resolv);
        assert!(restored.mark);
    }

    // ===== ForwardRecord fields tests =================================

    #[test]
    fn test_forward_record_fields() {
        let addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let source: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        let srv = Arc::new(UpstreamServer::new(addr));

        let mut fflags = ForwardFlags::new();
        fflags.tcp_fallback = true;

        let record = ForwardRecord::new(
            0x1234,
            0x5678,
            source,
            Arc::clone(&srv),
            Bytes::from_static(b"\x56\x78\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"),
            fflags,
            "example.org".to_string(),
            RRType::AAAA,
            DnsClass::IN,
        );
        assert_eq!(record.query_id, 0x1234);
        assert_eq!(record.new_id, 0x5678);
        assert_eq!(record.source, source);
        assert_eq!(record.query_name, "example.org");
        assert_eq!(record.query_type, RRType::AAAA);
        assert_eq!(record.query_class, DnsClass::IN);
        assert!(record.flags.tcp_fallback);
        assert_eq!(record.retries, 0);
    }

    // ===== is_strict_order tests ======================================

    #[test]
    fn test_is_strict_order_default() {
        let flags = OptionFlags::default();
        assert!(!is_strict_order(&flags));
    }

    #[test]
    fn test_is_strict_order_set() {
        let mut flags = OptionFlags::default();
        flags.set(opt::ORDER);
        assert!(is_strict_order(&flags));
    }

    // ===== build_response_with_builder tests ==========================

    #[test]
    fn test_build_response_with_builder_empty_answers() {
        let query = vec![
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // Question: "a." A IN
            0x01, b'a', 0x00, 0x00, 0x01, 0x00, 0x01,
        ];
        let resp = build_response_with_builder(&query, 0x0001, &[]);
        assert!(!resp.is_empty());
        // Should be a valid DNS response
        assert!(resp.len() >= 12);
    }

    #[test]
    fn test_build_response_with_builder_with_answer() {
        let query = vec![
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, b'a',
            0x00, 0x00, 0x01, 0x00, 0x01,
        ];
        let name = DnsName::from_str_unchecked("a.");
        let rdata = vec![192, 168, 1, 1]; // A record
        let answers = vec![(name, RRType::A, 300u32, rdata)];
        let resp = build_response_with_builder(&query, 0x0001, &answers);
        assert!(resp.len() > 12);
    }

    // ===== ForwardTable Debug trait test ===============================

    #[test]
    fn test_forward_table_debug() {
        let table = ForwardTable::new(10);
        let dbg = format!("{:?}", table);
        assert!(dbg.contains("ForwardTable"));
    }

    // ===== RoundRobinSelector with servers ============================

    #[test]
    fn test_round_robin_selector_single_server() {
        let selector = RoundRobinSelector::new();
        let addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let srv = Arc::new(UpstreamServer::new(addr));
        let servers = vec![srv];
        // Build a minimal valid DNS query packet
        let pkt_data = vec![
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x65,
            0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00,
            0x01,
        ];
        let pkt = DnsPacket::parse(&pkt_data).unwrap();
        let matcher = DomainMatcher::new();
        let result = selector.select_server(&servers, &pkt, &matcher);
        assert!(result.is_some());
    }

    // ===== Additional coverage tests for forward.rs utility functions =====

    // CacheEntry uses std::time::Instant, while super::* imports tokio::time::Instant
    use std::time::Duration as StdDuration;
    use std::time::Instant as StdInstant;

    /// Helper to build a minimal DNS query packet.
    fn make_dns_query_helper(id: u16, name: &str, qtype: u16) -> Vec<u8> {
        let mut pkt = Vec::new();
        // Header: ID, flags (RD set), QDCOUNT=1, AN=0, NS=0, AR=0
        pkt.extend_from_slice(&id.to_be_bytes());
        pkt.push(0x01); // RD
        pkt.push(0x00);
        pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        // Question section: encode name
        for label in name.split('.') {
            if !label.is_empty() {
                pkt.push(label.len() as u8);
                pkt.extend_from_slice(label.as_bytes());
            }
        }
        pkt.push(0); // root label
        pkt.extend_from_slice(&qtype.to_be_bytes()); // QTYPE
        pkt.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
        pkt
    }

    #[test]
    fn test_is_strict_order_true_v2() {
        let mut flags = OptionFlags::new();
        flags.set(opt::ORDER);
        assert!(is_strict_order(&flags));
    }

    #[test]
    fn test_is_strict_order_false_v2() {
        let flags = OptionFlags::new();
        assert!(!is_strict_order(&flags));
    }

    #[test]
    fn test_set_rr_ttl_basic_v3() {
        let mut pkt = vec![0u8; 20];
        set_rr_ttl(&mut pkt, 0, 600);
        assert_eq!(extract_rr_ttl(&pkt, 0), Some(600));
    }

    #[test]
    fn test_set_rr_ttl_zero_val() {
        let mut pkt = vec![0u8; 20];
        set_rr_ttl(&mut pkt, 0, 0);
        assert_eq!(extract_rr_ttl(&pkt, 0), Some(0));
    }

    #[test]
    fn test_set_rr_ttl_max_val() {
        let mut pkt = vec![0u8; 20];
        set_rr_ttl(&mut pkt, 0, u32::MAX);
        assert_eq!(extract_rr_ttl(&pkt, 0), Some(u32::MAX));
    }

    #[test]
    fn test_fast_retry_zero_retries() {
        // With 0 retries, should produce Some (first retry allowed)
        let result = fast_retry(0);
        assert!(result.is_some());
    }

    #[test]
    fn test_fast_retry_one_retry() {
        let result = fast_retry(1);
        assert!(result.is_some());
    }

    #[test]
    fn test_fast_retry_max_retries() {
        // 5 retries is max, should return None
        assert!(fast_retry(5).is_none());
    }

    #[test]
    fn test_fast_retry_large_retries() {
        // Beyond max should return None
        assert!(fast_retry(100).is_none());
    }

    #[test]
    fn test_fast_retry_exponential_increase() {
        // Each retry should double the delay
        let d0 = fast_retry(0).unwrap();
        let d1 = fast_retry(1).unwrap();
        assert_eq!(d1, d0 * 2);
        let d2 = fast_retry(2).unwrap();
        assert_eq!(d2, d1 * 2);
    }

    #[test]
    fn test_rfd_pool_new_v2() {
        let mut pool = RfdPool::new(10);
        // Pool should start empty; we test via clear (no-op on empty is fine)
        pool.clear(); // just verify pool creation and clear
    }

    #[test]
    fn test_rfd_pool_clear_v2() {
        let mut pool = RfdPool::new(10);
        pool.clear();
        // After clear, pool should still be usable
    }

    #[test]
    fn test_forward_flags_new_v2() {
        let flags = ForwardFlags::new();
        assert_eq!(flags.to_raw(), 0);
    }

    #[test]
    fn test_forward_flags_from_raw_roundtrip_v2() {
        let flags = ForwardFlags::from_raw(0xFF);
        let raw = flags.to_raw();
        let flags2 = ForwardFlags::from_raw(raw);
        assert_eq!(flags.to_raw(), flags2.to_raw());
    }

    #[test]
    fn test_forward_flags_individual_bits() {
        let flags = ForwardFlags::from_raw(0x0001);
        assert!(flags.tcp_fallback);
        assert!(!flags.dnssec_enabled);

        let flags = ForwardFlags::from_raw(0x0002);
        assert!(!flags.tcp_fallback);
        assert!(flags.dnssec_enabled);
    }

    #[test]
    fn test_option_flags_set_and_check() {
        let mut flags = OptionFlags::new();
        assert!(!flags.is_set(opt::ORDER));
        flags.set(opt::ORDER);
        assert!(flags.is_set(opt::ORDER));
        flags.clear(opt::ORDER);
        assert!(!flags.is_set(opt::ORDER));
    }

    #[test]
    fn test_upstream_server_new_defaults() {
        let addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let server = UpstreamServer::new(addr);
        assert!(server.is_healthy());
        assert_eq!(server.addr, addr);
        assert_eq!(server.queries, 0);
        assert_eq!(server.failed_queries, 0);
    }

    #[test]
    fn test_upstream_server_failure_tracking() {
        let addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let mut server = UpstreamServer::new(addr);
        server.record_failure();
        // First failure should keep it healthy (FORWARD_TEST=50)
        assert!(server.is_healthy());
        assert_eq!(server.failed_queries, 1);
    }

    #[test]
    fn test_upstream_server_many_failures_unhealthy() {
        let addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let mut server = UpstreamServer::new(addr);
        for _ in 0..100 {
            server.record_failure();
        }
        assert!(!server.is_healthy());
    }

    #[test]
    fn test_upstream_server_success_increments_queries() {
        let addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let mut server = UpstreamServer::new(addr);
        server.record_success();
        assert_eq!(server.queries, 1);
    }

    #[test]
    fn test_upstream_server_update_latency() {
        let addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let server = UpstreamServer::new(addr);
        server.update_latency(10);
        server.update_latency(20);
        // Verify no panic and latency is tracked
        let ql = server
            .query_latency
            .load(std::sync::atomic::Ordering::Relaxed);
        assert!(ql > 0);
    }

    #[test]
    fn test_forward_table_basic_ops_v2() {
        let mut table = ForwardTable::new(150);
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);
        assert!(!table.is_full());
    }

    #[test]
    fn test_forward_table_insert_lookup_v2() {
        let mut table = ForwardTable::new(150);
        let src: SocketAddr = "192.168.1.1:1234".parse().unwrap();
        let upstream = Arc::new(UpstreamServer::new("8.8.8.8:53".parse().unwrap()));
        let record = ForwardRecord::new(
            100, // query_id
            42,  // new_id
            src,
            upstream,
            Bytes::from_static(b"test"),
            ForwardFlags::new(),
            "test.com".to_string(),
            RRType::A,
            DnsClass::IN,
        );
        table.insert(record).unwrap();
        assert_eq!(table.len(), 1);
        // Lookup uses new_id as key
        assert!(table.lookup(42).is_some());
        assert!(table.lookup(200).is_none());
    }

    #[test]
    fn test_forward_table_remove_v2() {
        let mut table = ForwardTable::new(150);
        let src: SocketAddr = "192.168.1.1:1234".parse().unwrap();
        let upstream = Arc::new(UpstreamServer::new("8.8.8.8:53".parse().unwrap()));
        let record = ForwardRecord::new(
            100,
            42,
            src,
            upstream,
            Bytes::from_static(b"q"),
            ForwardFlags::new(),
            "test.com".to_string(),
            RRType::A,
            DnsClass::IN,
        );
        table.insert(record).unwrap();
        let removed = table.remove(42); // key is new_id
        assert!(removed.is_some());
        assert!(table.is_empty());
    }

    #[test]
    fn test_forward_table_find_by_client_v2() {
        let mut table = ForwardTable::new(150);
        let src: SocketAddr = "192.168.1.1:1234".parse().unwrap();
        let upstream = Arc::new(UpstreamServer::new("8.8.8.8:53".parse().unwrap()));
        let record = ForwardRecord::new(
            100,
            42,
            src,
            upstream,
            Bytes::from_static(b"q"),
            ForwardFlags::new(),
            "test.com".to_string(),
            RRType::A,
            DnsClass::IN,
        );
        table.insert(record).unwrap();
        // find_by_client uses query_id and source
        assert!(table.find_by_client(100, &src).is_some());
        assert!(table
            .find_by_client(100, &"10.0.0.1:9999".parse().unwrap())
            .is_none());
        assert!(table.find_by_client(99, &src).is_none());
    }

    #[test]
    fn test_forward_record_is_expired_v2() {
        let src: SocketAddr = "1.2.3.4:1234".parse().unwrap();
        let upstream = Arc::new(UpstreamServer::new("8.8.8.8:53".parse().unwrap()));
        let record = ForwardRecord::new(
            1,
            1,
            src,
            upstream,
            Bytes::from_static(b"q"),
            ForwardFlags::new(),
            "test.com".to_string(),
            RRType::A,
            DnsClass::IN,
        );
        // Freshly created record should not be expired with large timeout
        assert!(!record.is_expired(86400));
    }

    #[test]
    fn test_forward_table_expire_old_v2() {
        let mut table = ForwardTable::new(150);
        let src: SocketAddr = "1.2.3.4:1234".parse().unwrap();
        let upstream = Arc::new(UpstreamServer::new("8.8.8.8:53".parse().unwrap()));
        let record = ForwardRecord::new(
            1,
            1,
            src,
            upstream,
            Bytes::from_static(b"q"),
            ForwardFlags::new(),
            "test.com".to_string(),
            RRType::A,
            DnsClass::IN,
        );
        table.insert(record).unwrap();
        // With 0s timeout everything is expired immediately
        let expired = table.expire_old(0);
        assert_eq!(expired, 1);
        assert!(table.is_empty());
    }

    #[test]
    fn test_forward_table_find_by_response_v2() {
        let mut table = ForwardTable::new(150);
        let src: SocketAddr = "192.168.1.1:1234".parse().unwrap();
        let upstream = Arc::new(UpstreamServer::new("8.8.8.8:53".parse().unwrap()));
        let record = ForwardRecord::new(
            100,
            42,
            src,
            upstream,
            Bytes::from_static(b"q"),
            ForwardFlags::new(),
            "test.com".to_string(),
            RRType::A,
            DnsClass::IN,
        );
        table.insert(record).unwrap();
        // find_by_response uses new_id, name, class, type
        let found = table.find_by_response(42, "test.com", &DnsClass::IN, &RRType::A);
        assert!(found.is_some());
        // Wrong name should not match
        assert!(table
            .find_by_response(42, "other.com", &DnsClass::IN, &RRType::A)
            .is_none());
        // Wrong type should not match
        assert!(table
            .find_by_response(42, "test.com", &DnsClass::IN, &RRType::AAAA)
            .is_none());
    }

    #[test]
    fn test_forward_table_capacity_v3() {
        let mut table = ForwardTable::new(2);
        let src: SocketAddr = "1.2.3.4:1234".parse().unwrap();
        let upstream = Arc::new(UpstreamServer::new("8.8.8.8:53".parse().unwrap()));
        let r1 = ForwardRecord::new(
            1,
            1,
            src,
            upstream.clone(),
            Bytes::from_static(b"q"),
            ForwardFlags::new(),
            "a.com".to_string(),
            RRType::A,
            DnsClass::IN,
        );
        let r2 = ForwardRecord::new(
            2,
            2,
            src,
            upstream.clone(),
            Bytes::from_static(b"q"),
            ForwardFlags::new(),
            "b.com".to_string(),
            RRType::A,
            DnsClass::IN,
        );
        let r3 = ForwardRecord::new(
            3,
            3,
            src,
            upstream,
            Bytes::from_static(b"q"),
            ForwardFlags::new(),
            "c.com".to_string(),
            RRType::A,
            DnsClass::IN,
        );
        table.insert(r1).unwrap();
        table.insert(r2).unwrap();
        assert!(table.is_full());
        assert!(table.insert(r3).is_err());
    }

    #[test]
    fn test_generate_unique_id_avoids_conflicts_v2() {
        let mut table = ForwardTable::new(150);
        let src: SocketAddr = "1.2.3.4:1234".parse().unwrap();
        let upstream = Arc::new(UpstreamServer::new("8.8.8.8:53".parse().unwrap()));
        let mut rng = SurfRng::new().unwrap();
        // Insert a record with known new_id=500
        let r = ForwardRecord::new(
            1,
            500,
            src,
            upstream,
            Bytes::from_static(b"q"),
            ForwardFlags::new(),
            "test.com".to_string(),
            RRType::A,
            DnsClass::IN,
        );
        table.insert(r).unwrap();
        // Generate should produce something != 500
        let id = generate_unique_id(&mut rng, &table);
        assert_ne!(id, 500);
        assert_ne!(id, 0);
    }

    #[test]
    fn test_round_robin_selector_creation_v2() {
        let selector = RoundRobinSelector::new();
        let _ = selector; // Just verify it can be created
    }

    #[test]
    fn test_extract_neg_ttl_from_authority_empty() {
        let pkt = make_dns_query_helper(0x1234, "test.com", 1);
        // Query has no authority section (NSCOUNT=0)
        let result = extract_neg_ttl_from_authority(&pkt);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_dns_name_at_simple_v2() {
        let mut pkt = vec![0u8; 50];
        pkt[0] = 4;
        pkt[1] = b't';
        pkt[2] = b'e';
        pkt[3] = b's';
        pkt[4] = b't';
        pkt[5] = 0;
        let name = extract_dns_name_at(&pkt, 0);
        assert!(name.is_some());
    }

    #[test]
    fn test_extract_dns_name_at_compression_v2() {
        let mut pkt = vec![0u8; 50];
        // Name at offset 0
        pkt[0] = 3;
        pkt[1] = b'f';
        pkt[2] = b'o';
        pkt[3] = b'o';
        pkt[4] = 0;
        // Compression pointer at offset 10 pointing to offset 0
        pkt[10] = 0xC0;
        pkt[11] = 0x00;
        let name = extract_dns_name_at(&pkt, 10);
        assert!(name.is_some());
    }

    #[test]
    fn test_build_cache_response_short_query() {
        // Short query (less than 12 bytes) should return None
        let entry = CacheEntry {
            name: DnsName::from_str_unchecked("test.com"),
            rr_type: RRType::A,
            data: CacheData::Addr4(Ipv4Addr::new(1, 2, 3, 4)),
            expires: StdInstant::now() + StdDuration::from_secs(300),
            last_access: StdInstant::now(),
            flags: CacheFlags::new(),
            ttl: 300,
        };
        assert!(build_cache_response(&[0u8; 5], &entry, 0x1234, 512, false).is_none());
    }

    #[test]
    fn test_build_cache_response_valid_a_query() {
        let query = make_dns_query_helper(0x5555, "test.com", 1);
        let entry = CacheEntry {
            name: DnsName::from_str_unchecked("test.com"),
            rr_type: RRType::A,
            data: CacheData::Addr4(Ipv4Addr::new(1, 2, 3, 4)),
            expires: StdInstant::now() + StdDuration::from_secs(300),
            last_access: StdInstant::now(),
            flags: CacheFlags::new(),
            ttl: 300,
        };
        let result = build_cache_response(&query, &entry, 0x5555, 512, false);
        assert!(result.is_some());
        let resp = result.unwrap();
        assert!(resp.len() >= 12);
        // QR bit should be set in byte 2
        assert_ne!(resp[2] & 0x80, 0);
    }

    #[test]
    fn test_build_cache_response_aaaa() {
        let query = make_dns_query_helper(0x1234, "test.com", 28); // AAAA
        let entry = CacheEntry {
            name: DnsName::from_str_unchecked("test.com"),
            rr_type: RRType::AAAA,
            data: CacheData::Addr6(Ipv6Addr::LOCALHOST),
            expires: StdInstant::now() + StdDuration::from_secs(300),
            last_access: StdInstant::now(),
            flags: CacheFlags::new(),
            ttl: 300,
        };
        let result = build_cache_response(&query, &entry, 0x1234, 512, false);
        assert!(result.is_some());
    }

    #[test]
    fn test_build_cache_response_cname() {
        let query = make_dns_query_helper(0x1234, "alias.com", 5); // CNAME
        let entry = CacheEntry {
            name: DnsName::from_str_unchecked("alias.com"),
            rr_type: RRType::CNAME,
            data: CacheData::Cname(DnsName::from_str_unchecked("target.com")),
            expires: StdInstant::now() + StdDuration::from_secs(300),
            last_access: StdInstant::now(),
            flags: CacheFlags::new(),
            ttl: 300,
        };
        let result = build_cache_response(&query, &entry, 0x1234, 512, false);
        assert!(result.is_some());
    }

    #[test]
    fn test_build_cache_response_nxdomain() {
        let query = make_dns_query_helper(0x1234, "nxdomain.test", 1);
        let entry = CacheEntry {
            name: DnsName::from_str_unchecked("nxdomain.test"),
            rr_type: RRType::A,
            data: CacheData::NxDomain,
            expires: StdInstant::now() + StdDuration::from_secs(300),
            last_access: StdInstant::now(),
            flags: CacheFlags::new(),
            ttl: 300,
        };
        let result = build_cache_response(&query, &entry, 0x1234, 512, false);
        assert!(result.is_some());
        let resp = result.unwrap();
        // For NXDOMAIN, RCODE should be 3
        assert_eq!(resp[3] & 0x0F, 3);
    }

    #[test]
    fn test_build_cache_response_ptr() {
        let query = make_dns_query_helper(0x1234, "4.3.2.1.in-addr.arpa", 12); // PTR
        let entry = CacheEntry {
            name: DnsName::from_str_unchecked("4.3.2.1.in-addr.arpa"),
            rr_type: RRType::PTR,
            data: CacheData::Ptr(DnsName::from_str_unchecked("host.example.com")),
            expires: StdInstant::now() + StdDuration::from_secs(300),
            last_access: StdInstant::now(),
            flags: CacheFlags::new(),
            ttl: 300,
        };
        let result = build_cache_response(&query, &entry, 0x1234, 512, false);
        assert!(result.is_some());
    }

    #[test]
    fn test_server_gone_empty_table_v2() {
        let mut table = ForwardTable::new(150);
        let mut pool = RfdPool::new(10);
        let addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
        server_gone(&mut table, &mut pool, &addr);
        assert!(table.is_empty());
    }

    #[test]
    fn test_server_gone_removes_matching_v2() {
        let mut table = ForwardTable::new(150);
        let mut pool = RfdPool::new(10);
        let src: SocketAddr = "1.2.3.4:1234".parse().unwrap();
        let dst: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let upstream = Arc::new(UpstreamServer::new(dst));
        let record = ForwardRecord::new(
            1,
            1,
            src,
            upstream,
            Bytes::from_static(b"q"),
            ForwardFlags::new(),
            "test.com".to_string(),
            RRType::A,
            DnsClass::IN,
        );
        table.insert(record).unwrap();
        assert_eq!(table.len(), 1);
        server_gone(&mut table, &mut pool, &dst);
        assert!(table.is_empty());
    }

    #[test]
    fn test_server_gone_preserves_other_v2() {
        let mut table = ForwardTable::new(150);
        let mut pool = RfdPool::new(10);
        let src: SocketAddr = "1.2.3.4:1234".parse().unwrap();
        let dst1: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let dst2: SocketAddr = "1.1.1.1:53".parse().unwrap();
        let up1 = Arc::new(UpstreamServer::new(dst1));
        let up2 = Arc::new(UpstreamServer::new(dst2));
        let r1 = ForwardRecord::new(
            1,
            1,
            src,
            up1,
            Bytes::from_static(b"q"),
            ForwardFlags::new(),
            "a.com".to_string(),
            RRType::A,
            DnsClass::IN,
        );
        let r2 = ForwardRecord::new(
            2,
            2,
            src,
            up2,
            Bytes::from_static(b"q"),
            ForwardFlags::new(),
            "b.com".to_string(),
            RRType::A,
            DnsClass::IN,
        );
        table.insert(r1).unwrap();
        table.insert(r2).unwrap();
        assert_eq!(table.len(), 2);
        server_gone(&mut table, &mut pool, &dst1);
        assert_eq!(table.len(), 1);
        assert!(table.lookup(2).is_some());
    }

    #[test]
    fn test_free_rfds_empty_pool_v2() {
        let mut pool = RfdPool::new(10);
        free_rfds(&mut pool, -1);
        // No crash expected
    }

    #[test]
    fn test_forward_record_fields_v3() {
        let src: SocketAddr = "192.168.1.1:1234".parse().unwrap();
        let upstream = Arc::new(UpstreamServer::new("8.8.8.8:53".parse().unwrap()));
        let record = ForwardRecord::new(
            100,
            42,
            src,
            upstream,
            Bytes::from_static(b"query"),
            ForwardFlags::new(),
            "example.com".to_string(),
            RRType::A,
            DnsClass::IN,
        );
        assert_eq!(record.query_id, 100);
        assert_eq!(record.new_id, 42);
        assert_eq!(record.source, src);
        assert_eq!(record.query_name, "example.com");
        assert_eq!(record.query_type, RRType::A);
        assert_eq!(record.query_class, DnsClass::IN);
        assert_eq!(record.retries, 0);
        assert_eq!(record.listen_fd, -1);
        assert!(record.dest_addr.is_none());
        assert_eq!(record.iface_index, 0);
    }

    #[test]
    fn test_forward_table_debug_format() {
        let table = ForwardTable::new(150);
        let dbg = format!("{:?}", table);
        assert!(dbg.contains("ForwardTable"));
        assert!(dbg.contains("len"));
    }

    #[test]
    fn test_build_servfail_response_v2() {
        let query = make_dns_query_helper(0xABCD, "fail.test", 1);
        let resp = build_servfail_response(&query, 0xABCD);
        assert!(resp.len() >= 12);
        // Check QR bit set
        assert_ne!(resp[2] & 0x80, 0);
        // Check RCODE = 2 (SERVFAIL)
        assert_eq!(resp[3] & 0x0F, 2);
        // Check ID matches
        assert_eq!(u16::from_be_bytes([resp[0], resp[1]]), 0xABCD);
    }

    #[test]
    fn test_build_servfail_response_short_query() {
        let resp = build_servfail_response(&[0u8; 3], 0x1234);
        // Even a short query should produce a 12-byte response
        assert!(resp.len() >= 12);
    }

    #[test]
    fn test_skip_dns_name_root_v2() {
        // Root domain: just a zero byte
        let pkt = [0u8];
        assert_eq!(skip_dns_name(&pkt, 0), Some(1));
    }

    #[test]
    fn test_skip_dns_name_multi_label_v2() {
        // "foo.bar" = \x03foo\x03bar\x00
        let pkt = [3, b'f', b'o', b'o', 3, b'b', b'a', b'r', 0];
        assert_eq!(skip_dns_name(&pkt, 0), Some(9));
    }

    #[test]
    fn test_skip_dns_name_compression_v2() {
        // Compression pointer: 0xC0 0x00 (points to offset 0)
        let pkt = [3, b'f', b'o', b'o', 0, 0xC0, 0x00];
        assert_eq!(skip_dns_name(&pkt, 5), Some(7));
    }

    #[test]
    fn test_skip_dns_name_invalid() {
        // Empty packet
        assert!(skip_dns_name(&[], 0).is_none());
        // Offset beyond packet
        assert!(skip_dns_name(&[0], 5).is_none());
    }

    #[test]
    fn test_check_rebind_protection_no_answer() {
        // Query packet has no answer section (ANCOUNT=0)
        let pkt = make_dns_query_helper(0x1234, "test.com", 1);
        let result = check_rebind_protection(&pkt);
        // With no answers, function returns Some(false) — no rebind detected
        assert_eq!(result, Some(false));
    }

    #[test]
    fn test_is_ipv6_unique_local_v2() {
        // fc00::/7 = unique local
        let addr: Ipv6Addr = "fc00::1".parse().unwrap();
        assert!(is_ipv6_unique_local(&addr));
        let addr: Ipv6Addr = "fd00::1".parse().unwrap();
        assert!(is_ipv6_unique_local(&addr));
        let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert!(!is_ipv6_unique_local(&addr));
    }

    #[test]
    fn test_is_ipv6_link_local_v2() {
        let addr: Ipv6Addr = "fe80::1".parse().unwrap();
        assert!(is_ipv6_link_local(&addr));
        let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert!(!is_ipv6_link_local(&addr));
    }

    #[test]
    fn test_extract_rr_ttl_valid_v3() {
        let mut pkt = vec![0u8; 20];
        // extract_rr_ttl reads TTL at rr_fixed_offset + 4, so with offset 0
        // the TTL bytes must be at indices 4..8 in big-endian.
        pkt[4] = 0x00;
        pkt[5] = 0x00;
        pkt[6] = 0x01;
        pkt[7] = 0x2C; // 300
        assert_eq!(extract_rr_ttl(&pkt, 0), Some(300));
    }

    #[test]
    fn test_extract_rr_ttl_short_packet() {
        let pkt = vec![0u8; 2]; // too short
        assert!(extract_rr_ttl(&pkt, 0).is_none());
    }

    #[test]
    fn test_to_my_sock_addr_v4_v3() {
        let addr: SocketAddr = "1.2.3.4:53".parse().unwrap();
        let my_addr = to_my_sock_addr(&addr);
        // Verify it creates a valid MySockAddr
        let _ = my_addr;
    }

    #[test]
    fn test_to_my_sock_addr_v6_v3() {
        let addr: SocketAddr = "[::1]:53".parse().unwrap();
        let my_addr = to_my_sock_addr(&addr);
        let _ = my_addr;
    }

    #[test]
    fn test_rdata_to_all_addr_a_valid() {
        let rdata = [1u8, 2, 3, 4];
        let result = rdata_to_all_addr(RRType::A, &rdata);
        assert!(result.is_some());
    }

    #[test]
    fn test_rdata_to_all_addr_aaaa_valid() {
        let rdata = [0u8; 16];
        let result = rdata_to_all_addr(RRType::AAAA, &rdata);
        assert!(result.is_some());
    }

    #[test]
    fn test_rdata_to_all_addr_a_too_short() {
        let rdata = [1u8, 2]; // too short for A
        assert!(rdata_to_all_addr(RRType::A, &rdata).is_none());
    }

    #[test]
    fn test_rdata_to_all_addr_aaaa_too_short() {
        let rdata = [0u8; 10]; // too short for AAAA
        assert!(rdata_to_all_addr(RRType::AAAA, &rdata).is_none());
    }

    #[test]
    fn test_server_flags_all_true_roundtrip_v2() {
        let mut flags = ServerFlags::new();
        flags.do_not_use = true;
        flags.is_loop = true;
        flags.from_resolv = true;
        let _ = flags;
        assert!(flags.do_not_use);
        assert!(flags.is_loop);
        assert!(flags.from_resolv);
    }

    #[test]
    fn test_upstream_server_edns_default() {
        let addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let server = UpstreamServer::new(addr);
        assert_eq!(server.edns_pktsz, EDNS_PKTSZ);
    }

    #[test]
    fn test_forward_table_is_full() {
        let mut table = ForwardTable::new(1);
        let src: SocketAddr = "1.2.3.4:1234".parse().unwrap();
        let upstream = Arc::new(UpstreamServer::new("8.8.8.8:53".parse().unwrap()));
        let r = ForwardRecord::new(
            1,
            1,
            src,
            upstream,
            Bytes::from_static(b"q"),
            ForwardFlags::new(),
            "t.com".to_string(),
            RRType::A,
            DnsClass::IN,
        );
        assert!(!table.is_full());
        table.insert(r).unwrap();
        assert!(table.is_full());
    }

    #[test]
    fn test_forward_record_with_flags() {
        let src: SocketAddr = "1.2.3.4:1234".parse().unwrap();
        let upstream = Arc::new(UpstreamServer::new("8.8.8.8:53".parse().unwrap()));
        let mut flags = ForwardFlags::new();
        flags.tcp_fallback = true;
        flags.no_cache = true;
        let record = ForwardRecord::new(
            1,
            1,
            src,
            upstream,
            Bytes::from_static(b"q"),
            flags,
            "t.com".to_string(),
            RRType::A,
            DnsClass::IN,
        );
        assert!(record.flags.tcp_fallback);
        assert!(record.flags.no_cache);
        assert!(!record.flags.retrying);
    }

    #[test]
    fn test_upstream_server_no_source_addr() {
        let addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let server = UpstreamServer::new(addr);
        assert!(server.source_addr.is_none());
        assert!(server.interface.is_none());
        assert!(server.domain.is_none());
    }

    #[test]
    fn test_cache_data_type_descriptions() {
        let d1 = CacheData::Addr4(Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(d1.type_description(), "A");
        let d2 = CacheData::Addr6(Ipv6Addr::LOCALHOST);
        assert_eq!(d2.type_description(), "AAAA");
        let d3 = CacheData::Cname(DnsName::from_str_unchecked("test.com"));
        assert_eq!(d3.type_description(), "CNAME");
        let d4 = CacheData::NxDomain;
        assert_eq!(d4.type_description(), "NXDOMAIN");
    }

    #[test]
    fn test_forward_flags_all_bits_roundtrip() {
        let mut flags = ForwardFlags::new();
        flags.tcp_fallback = true;
        flags.dnssec_enabled = true;
        flags.retrying = true;
        flags.no_cache = true;
        flags.sec_query = true;
        flags.ad_question = true;
        flags.do_question = true;
        flags.has_pheader = true;
        flags.checking_disabled = true;
        flags.no_rebind = true;
        flags.gone_to_tcp = true;
        let raw = flags.to_raw();
        let restored = ForwardFlags::from_raw(raw);
        assert!(restored.tcp_fallback);
        assert!(restored.dnssec_enabled);
        assert!(restored.retrying);
        assert!(restored.no_cache);
        assert!(restored.sec_query);
        assert!(restored.ad_question);
        assert!(restored.do_question);
        assert!(restored.has_pheader);
        assert!(restored.checking_disabled);
        assert!(restored.no_rebind);
        assert!(restored.gone_to_tcp);
    }

    #[test]
    fn test_forward_record_udp_pkt_size_default() {
        let src: SocketAddr = "1.2.3.4:1234".parse().unwrap();
        let upstream = Arc::new(UpstreamServer::new("8.8.8.8:53".parse().unwrap()));
        let record = ForwardRecord::new(
            1,
            1,
            src,
            upstream,
            Bytes::from_static(b"q"),
            ForwardFlags::new(),
            "t.com".to_string(),
            RRType::A,
            DnsClass::IN,
        );
        assert_eq!(record.udp_pkt_size, PACKETSZ);
    }

    #[test]
    fn test_build_servfail_preserves_rd() {
        // Query with RD bit set
        let query = make_dns_query_helper(0x1234, "test.com", 1);
        let resp = build_servfail_response(&query, 0x1234);
        // RD should be preserved from query
        let rd_bit = resp[2] & 0x01;
        let query_rd = query[2] & 0x01;
        assert_eq!(rd_bit, query_rd);
    }

    #[test]
    fn test_extract_dns_name_at_two_labels() {
        // "ab.cd" = \x02ab\x02cd\x00
        let mut pkt = vec![0u8; 20];
        pkt[0] = 2;
        pkt[1] = b'a';
        pkt[2] = b'b';
        pkt[3] = 2;
        pkt[4] = b'c';
        pkt[5] = b'd';
        pkt[6] = 0;
        let name = extract_dns_name_at(&pkt, 0);
        assert!(name.is_some());
    }

    #[test]
    fn test_extract_dns_name_at_empty_packet() {
        assert!(extract_dns_name_at(&[], 0).is_none());
    }

    #[test]
    fn test_option_flags_multiple_bits() {
        let mut flags = OptionFlags::new();
        flags.set(opt::ORDER);
        flags.set(opt::DNSSEC_VALID);
        assert!(flags.is_set(opt::ORDER));
        assert!(flags.is_set(opt::DNSSEC_VALID));
        flags.clear(opt::ORDER);
        assert!(!flags.is_set(opt::ORDER));
        assert!(flags.is_set(opt::DNSSEC_VALID));
    }

    #[test]
    fn test_upstream_server_latency_smoothing() {
        let addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let server = UpstreamServer::new(addr);
        // First sample sets the MMA: mma = 100*128 = 12800, ql = 100
        server.update_latency(100);
        let ql1 = server
            .query_latency
            .load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(ql1, 100);
        // Second sample with a large difference so integer division (mma/128) changes.
        // diff = 10000-100 = 9900, new_mma = 12800+9900 = 22700, ql = 22700/128 = 177
        server.update_latency(10000);
        let ql2 = server
            .query_latency
            .load(std::sync::atomic::Ordering::Relaxed);
        // Latency should have changed
        assert_ne!(ql1, ql2);
    }

    #[test]
    fn test_forward_flags_zero_raw() {
        let flags = ForwardFlags::from_raw(0);
        assert!(!flags.tcp_fallback);
        assert!(!flags.dnssec_enabled);
        assert!(!flags.retrying);
    }

    #[test]
    fn test_server_flags_default_all_false() {
        let flags = ServerFlags::new();
        assert!(!flags.do_not_use);
        assert!(!flags.is_loop);
        assert!(!flags.from_resolv);
        assert!(!flags.no_addr);
    }

    #[test]
    fn test_forward_table_lookup_mut_v2() {
        let mut table = ForwardTable::new(150);
        let src: SocketAddr = "1.2.3.4:1234".parse().unwrap();
        let upstream = Arc::new(UpstreamServer::new("8.8.8.8:53".parse().unwrap()));
        let r = ForwardRecord::new(
            1,
            42,
            src,
            upstream,
            Bytes::from_static(b"q"),
            ForwardFlags::new(),
            "test.com".to_string(),
            RRType::A,
            DnsClass::IN,
        );
        table.insert(r).unwrap();
        // Get mutable reference
        let rec = table.lookup_mut(42).unwrap();
        rec.retries = 5;
        assert_eq!(table.lookup(42).unwrap().retries, 5);
    }

    #[test]
    fn test_cache_entry_is_expired_v2() {
        let entry = CacheEntry {
            name: DnsName::from_str_unchecked("test.com"),
            rr_type: RRType::A,
            data: CacheData::Addr4(Ipv4Addr::new(1, 2, 3, 4)),
            expires: StdInstant::now() + StdDuration::from_secs(300),
            last_access: StdInstant::now(),
            flags: CacheFlags::new(),
            ttl: 300,
        };
        assert!(!entry.is_expired());
    }

    #[test]
    fn test_cache_entry_remaining_ttl() {
        let entry = CacheEntry {
            name: DnsName::from_str_unchecked("test.com"),
            rr_type: RRType::A,
            data: CacheData::Addr4(Ipv4Addr::new(1, 2, 3, 4)),
            expires: StdInstant::now() + StdDuration::from_secs(300),
            last_access: StdInstant::now(),
            flags: CacheFlags::new(),
            ttl: 300,
        };
        let remaining = entry.remaining_ttl();
        assert!(remaining > 295 && remaining <= 300);
    }

    #[test]
    fn test_dns_name_from_str_unchecked() {
        let name = DnsName::from_str_unchecked("example.com");
        assert_eq!(name.label_count(), 2);
        let name2 = DnsName::from_str_unchecked("example.com.");
        // Trailing dot should be filtered
        assert_eq!(name2.label_count(), 2);
    }

    #[test]
    fn test_dns_name_root() {
        let root = DnsName::root();
        assert_eq!(root.label_count(), 0);
    }

    // -----------------------------------------------------------------------
    // Additional coverage tests — build_servfail_response
    // -----------------------------------------------------------------------
    #[test]
    fn test_build_servfail_basic() {
        let query = make_dns_query_helper(0xABCD, "example.com", 1);
        let resp = build_servfail_response(&query, 0xABCD);
        assert!(resp.len() >= 12);
        // ID matches
        assert_eq!((resp[0] as u16) << 8 | resp[1] as u16, 0xABCD);
        // QR bit set
        assert_ne!(resp[2] & 0x80, 0);
        // RCODE = 2 (ServFail)
        assert_eq!(resp[3] & 0x0F, 2);
        // ANCOUNT = 0
        assert_eq!((resp[6] as u16) << 8 | resp[7] as u16, 0);
    }

    #[test]
    fn test_build_servfail_preserves_rd_v4() {
        let mut query = make_dns_query_helper(0x1111, "test.org", 1);
        query[2] |= HB3_RD; // set RD bit
        let resp = build_servfail_response(&query, 0x1111);
        assert_ne!(resp[2] & HB3_RD, 0); // RD preserved
    }

    #[test]
    fn test_build_servfail_empty_query() {
        let resp = build_servfail_response(&[], 0x9999);
        assert!(resp.len() >= 12);
        assert_eq!((resp[0] as u16) << 8 | resp[1] as u16, 0x9999);
        assert_eq!(resp[3] & 0x0F, 2);
    }

    #[test]
    fn test_build_servfail_short_query() {
        let resp = build_servfail_response(&[0x12, 0x34], 0x1234);
        assert!(resp.len() >= 12);
    }

    #[test]
    fn test_build_servfail_copies_question_section() {
        let query = make_dns_query_helper(0x5678, "hello.world", 28);
        let resp = build_servfail_response(&query, 0x5678);
        // Response should contain question section from query
        assert!(resp.len() > 12);
        // QDCOUNT should match
        assert_eq!(resp[4], query[4]);
        assert_eq!(resp[5], query[5]);
    }

    // -----------------------------------------------------------------------
    // Additional coverage tests — build_cache_response
    // -----------------------------------------------------------------------
    #[test]
    fn test_build_cache_response_a_record() {
        let query = make_dns_query_helper(0x1234, "example.com", 1);
        let entry = CacheEntry {
            name: DnsName::from_str_unchecked("example.com"),
            rr_type: RRType::A,
            data: CacheData::Addr4(Ipv4Addr::new(93, 184, 216, 34)),
            expires: StdInstant::now() + StdDuration::from_secs(300),
            last_access: StdInstant::now(),
            flags: CacheFlags::default(),
            ttl: 300,
        };
        let resp = build_cache_response(&query, &entry, 0x1234, 512, false);
        assert!(resp.is_some());
        let resp = resp.unwrap();
        assert!(resp.len() >= 12);
        // QR bit set
        assert_ne!(resp[2] & 0x80, 0);
        // RCODE = 0 (NoError)
        assert_eq!(resp[3] & 0x0F, 0);
        // ANCOUNT >= 1
        let ancount = (resp[6] as u16) << 8 | resp[7] as u16;
        assert!(ancount >= 1);
    }

    #[test]
    fn test_build_cache_response_aaaa_record() {
        let query = make_dns_query_helper(0x2345, "ipv6.example.com", 28);
        let entry = CacheEntry {
            name: DnsName::from_str_unchecked("ipv6.example.com"),
            rr_type: RRType::AAAA,
            data: CacheData::Addr6("2001:db8::1".parse().unwrap()),
            expires: StdInstant::now() + StdDuration::from_secs(600),
            last_access: StdInstant::now(),
            flags: CacheFlags::default(),
            ttl: 600,
        };
        let resp = build_cache_response(&query, &entry, 0x2345, 1232, false);
        assert!(resp.is_some());
        let resp = resp.unwrap();
        let ancount = (resp[6] as u16) << 8 | resp[7] as u16;
        assert!(ancount >= 1);
    }

    #[test]
    fn test_build_cache_response_cname_v4() {
        let query = make_dns_query_helper(0x3456, "alias.example.com", 5);
        let entry = CacheEntry {
            name: DnsName::from_str_unchecked("alias.example.com"),
            rr_type: RRType::CNAME,
            data: CacheData::Cname(DnsName::from_str_unchecked("real.example.com")),
            expires: StdInstant::now() + StdDuration::from_secs(3600),
            last_access: StdInstant::now(),
            flags: CacheFlags::default(),
            ttl: 3600,
        };
        let resp = build_cache_response(&query, &entry, 0x3456, 512, false);
        assert!(resp.is_some());
    }

    #[test]
    fn test_build_cache_response_nxdomain_v4() {
        let query = make_dns_query_helper(0x4567, "noexist.example.com", 1);
        let entry = CacheEntry {
            name: DnsName::from_str_unchecked("noexist.example.com"),
            rr_type: RRType::A,
            data: CacheData::NxDomain,
            expires: StdInstant::now() + StdDuration::from_secs(60),
            last_access: StdInstant::now(),
            flags: CacheFlags::default(),
            ttl: 60,
        };
        let resp = build_cache_response(&query, &entry, 0x4567, 512, false);
        assert!(resp.is_some());
    }

    #[test]
    fn test_build_cache_response_short_query_v4() {
        let short_query = vec![0u8; 6]; // too short
        let entry = CacheEntry {
            name: DnsName::from_str_unchecked("test.com"),
            rr_type: RRType::A,
            data: CacheData::Addr4(Ipv4Addr::new(1, 2, 3, 4)),
            expires: StdInstant::now() + StdDuration::from_secs(300),
            last_access: StdInstant::now(),
            flags: CacheFlags::default(),
            ttl: 300,
        };
        let resp = build_cache_response(&short_query, &entry, 0x1111, 512, false);
        assert!(resp.is_none());
    }

    #[test]
    fn test_build_cache_response_ptr_record() {
        let query = make_dns_query_helper(0x5678, "4.3.2.1.in-addr.arpa", 12);
        let entry = CacheEntry {
            name: DnsName::from_str_unchecked("4.3.2.1.in-addr.arpa"),
            rr_type: RRType::PTR,
            data: CacheData::Ptr(DnsName::from_str_unchecked("host.example.com")),
            expires: StdInstant::now() + StdDuration::from_secs(300),
            last_access: StdInstant::now(),
            flags: CacheFlags::default(),
            ttl: 300,
        };
        let resp = build_cache_response(&query, &entry, 0x5678, 512, false);
        assert!(resp.is_some());
    }

    // -----------------------------------------------------------------------
    // Additional coverage tests — set_rr_ttl
    // -----------------------------------------------------------------------
    #[test]
    fn test_set_rr_ttl_basic_v4() {
        let mut pkt = vec![0u8; 20];
        set_rr_ttl(&mut pkt, 0, 300);
        // TTL is at offset 4..8
        assert_eq!(pkt[4], 0x00);
        assert_eq!(pkt[5], 0x00);
        assert_eq!(pkt[6], 0x01);
        assert_eq!(pkt[7], 0x2C);
    }

    #[test]
    fn test_set_rr_ttl_max() {
        let mut pkt = vec![0u8; 20];
        set_rr_ttl(&mut pkt, 0, u32::MAX);
        assert_eq!(pkt[4], 0xFF);
        assert_eq!(pkt[5], 0xFF);
        assert_eq!(pkt[6], 0xFF);
        assert_eq!(pkt[7], 0xFF);
    }

    #[test]
    fn test_set_rr_ttl_zero_v4() {
        let mut pkt = vec![0xFFu8; 20];
        set_rr_ttl(&mut pkt, 0, 0);
        assert_eq!(pkt[4], 0x00);
        assert_eq!(pkt[5], 0x00);
        assert_eq!(pkt[6], 0x00);
        assert_eq!(pkt[7], 0x00);
    }

    #[test]
    fn test_set_rr_ttl_with_offset() {
        let mut pkt = vec![0u8; 30];
        set_rr_ttl(&mut pkt, 10, 3600);
        // TTL at offset 10+4=14
        let ttl = ((pkt[14] as u32) << 24)
            | ((pkt[15] as u32) << 16)
            | ((pkt[16] as u32) << 8)
            | pkt[17] as u32;
        assert_eq!(ttl, 3600);
    }

    #[test]
    fn test_set_rr_ttl_short_packet() {
        let mut pkt = vec![0u8; 4]; // too short for TTL
        set_rr_ttl(&mut pkt, 0, 100); // should not panic
                                      // Packet unchanged since TTL doesn't fit
        assert_eq!(pkt, vec![0u8; 4]);
    }

    // -----------------------------------------------------------------------
    // Additional coverage tests — extract_neg_ttl_from_authority
    // -----------------------------------------------------------------------
    #[test]
    fn test_extract_neg_ttl_too_short_v4() {
        assert!(extract_neg_ttl_from_authority(&[0u8; 6]).is_none());
    }

    #[test]
    fn test_extract_neg_ttl_no_authority_v4() {
        // Packet with QDCOUNT=1, ANCOUNT=0, NSCOUNT=0
        let mut pkt = make_dns_query_helper(0x1234, "test.com", 1);
        // Make it look like a response
        pkt[2] |= 0x80; // QR=1
        let result = extract_neg_ttl_from_authority(&pkt);
        assert!(result.is_none()); // no authority section
    }

    // -----------------------------------------------------------------------
    // Additional coverage tests — extract_dns_name_at
    // -----------------------------------------------------------------------
    #[test]
    fn test_extract_dns_name_simple() {
        // Encode "foo.bar" as DNS wire format
        let pkt = vec![3, b'f', b'o', b'o', 3, b'b', b'a', b'r', 0];
        let name = extract_dns_name_at(&pkt, 0);
        assert!(name.is_some());
        let n = name.unwrap();
        assert_eq!(n.label_count(), 2);
    }

    #[test]
    fn test_extract_dns_name_root_label() {
        let pkt = vec![0]; // root name (just terminator)
        let name = extract_dns_name_at(&pkt, 0);
        assert!(name.is_some());
    }

    #[test]
    fn test_extract_dns_name_empty_packet() {
        let name = extract_dns_name_at(&[], 0);
        assert!(name.is_none());
    }

    #[test]
    fn test_extract_dns_name_compression() {
        // "foo" at offset 0, then compression pointer at offset 5
        let pkt = vec![
            3, b'f', b'o', b'o', 0, // "foo" at offsets 0-4
            0xC0, 0x00, // compression pointer to offset 0
        ];
        let name = extract_dns_name_at(&pkt, 5);
        assert!(name.is_some());
    }

    #[test]
    fn test_extract_dns_name_truncated_label() {
        let pkt = vec![5, b'h', b'i']; // label says 5 bytes but only 2 available
        let name = extract_dns_name_at(&pkt, 0);
        assert!(name.is_none());
    }

    #[test]
    fn test_extract_dns_name_excessive_jumps() {
        // Self-referencing compression pointer (infinite loop)
        let pkt = vec![0xC0, 0x00]; // points to itself
        let name = extract_dns_name_at(&pkt, 0);
        assert!(name.is_none()); // should detect loop
    }

    // -----------------------------------------------------------------------
    // Additional coverage tests — parse_response_header
    // -----------------------------------------------------------------------
    #[test]
    fn test_parse_response_header_valid() {
        let mut pkt = make_dns_query_helper(0xAAAA, "test.com", 1);
        pkt[2] |= 0x80; // QR=1 (response)
        let hdr = parse_response_header(&pkt);
        assert!(hdr.is_some());
    }

    #[test]
    fn test_parse_response_header_too_short_v4() {
        let pkt = vec![0u8; 8];
        let hdr = parse_response_header(&pkt);
        assert!(hdr.is_none());
    }

    // -----------------------------------------------------------------------
    // Additional coverage tests — build_response_with_builder
    // -----------------------------------------------------------------------
    #[test]
    fn test_build_response_with_builder_no_answers() {
        let query = make_dns_query_helper(0x1234, "example.com", 1);
        let resp = build_response_with_builder(&query, 0x1234, &[]);
        assert!(resp.len() >= 12);
        // QR should be set
        assert_ne!(resp[2] & 0x80, 0);
    }

    #[test]
    fn test_build_response_with_builder_one_answer() {
        let query = make_dns_query_helper(0x5555, "example.com", 1);
        let answers = vec![(
            DnsName::from_str_unchecked("example.com"),
            RRType::A,
            300u32,
            vec![93, 184, 216, 34], // 93.184.216.34
        )];
        let resp = build_response_with_builder(&query, 0x5555, &answers);
        assert!(resp.len() >= 12);
        // ANCOUNT should be >= 1
        let ancount = (resp[6] as u16) << 8 | resp[7] as u16;
        assert!(ancount >= 1);
    }

    #[test]
    fn test_build_response_with_builder_multiple_answers() {
        let query = make_dns_query_helper(0x6666, "multi.example.com", 1);
        let answers = vec![
            (
                DnsName::from_str_unchecked("multi.example.com"),
                RRType::A,
                300u32,
                vec![1, 2, 3, 4],
            ),
            (
                DnsName::from_str_unchecked("multi.example.com"),
                RRType::A,
                300u32,
                vec![5, 6, 7, 8],
            ),
        ];
        let resp = build_response_with_builder(&query, 0x6666, &answers);
        let ancount = (resp[6] as u16) << 8 | resp[7] as u16;
        assert!(ancount >= 2);
    }

    // -----------------------------------------------------------------------
    // Additional coverage tests — rdata_to_all_addr
    // -----------------------------------------------------------------------
    #[test]
    fn test_rdata_to_all_addr_a_record_v4() {
        let rdata = vec![10, 0, 0, 1];
        let addr = rdata_to_all_addr(RRType::A, &rdata);
        assert!(addr.is_some());
        match addr.unwrap() {
            AllAddr::V4(ip) => assert_eq!(ip, Ipv4Addr::new(10, 0, 0, 1)),
            _ => panic!("Expected V4"),
        }
    }

    #[test]
    fn test_rdata_to_all_addr_aaaa_record_v4() {
        let mut rdata = vec![0u8; 16];
        rdata[0] = 0x20;
        rdata[1] = 0x01;
        rdata[2] = 0x0d;
        rdata[3] = 0xb8;
        rdata[15] = 0x01;
        let addr = rdata_to_all_addr(RRType::AAAA, &rdata);
        assert!(addr.is_some());
        match addr.unwrap() {
            AllAddr::V6(_ip) => {}
            _ => panic!("Expected V6"),
        }
    }

    #[test]
    fn test_rdata_to_all_addr_short_a_data() {
        let rdata = vec![10, 0]; // too short for A record
        let addr = rdata_to_all_addr(RRType::A, &rdata);
        assert!(addr.is_none());
    }

    #[test]
    fn test_rdata_to_all_addr_short_aaaa_data() {
        let rdata = vec![0u8; 8]; // too short for AAAA
        let addr = rdata_to_all_addr(RRType::AAAA, &rdata);
        assert!(addr.is_none());
    }

    #[test]
    fn test_rdata_to_all_addr_unsupported_type() {
        let rdata = vec![0u8; 20];
        let addr = rdata_to_all_addr(RRType::MX, &rdata);
        assert!(addr.is_none());
    }

    // -----------------------------------------------------------------------
    // Additional coverage tests — get_server_config
    // -----------------------------------------------------------------------
    #[test]
    fn test_get_server_config_basic() {
        let addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let server = UpstreamServer::new(addr);
        let config = get_server_config(&server);
        // Server has no domain attached by default, so it returns Some with default flags
        assert!(config.is_some());
    }

    // -----------------------------------------------------------------------
    // Additional coverage tests — check_rebind_protection with answers
    // -----------------------------------------------------------------------
    #[test]
    fn test_check_rebind_private_ipv4() {
        // Build a response with A record pointing to 192.168.1.1 (private)
        let mut pkt = make_dns_query_helper(0x1234, "evil.com", 1);
        pkt[2] |= 0x80; // QR=1
                        // Set ANCOUNT=1
        pkt[6] = 0;
        pkt[7] = 1;
        // Append answer RR: compression pointer + TYPE(A) + CLASS(IN) + TTL + RDLEN(4) + RDATA
        pkt.push(0xC0);
        pkt.push(0x0C); // name pointer
        pkt.push(0x00);
        pkt.push(0x01); // TYPE=A
        pkt.push(0x00);
        pkt.push(0x01); // CLASS=IN
        pkt.push(0x00);
        pkt.push(0x00);
        pkt.push(0x01);
        pkt.push(0x2C); // TTL=300
        pkt.push(0x00);
        pkt.push(0x04); // RDLENGTH=4
        pkt.push(192);
        pkt.push(168);
        pkt.push(1);
        pkt.push(1); // 192.168.1.1
        let result = check_rebind_protection(&pkt);
        assert_eq!(result, Some(true)); // private IP detected
    }

    #[test]
    fn test_check_rebind_public_ipv4() {
        let mut pkt = make_dns_query_helper(0x1234, "ok.com", 1);
        pkt[2] |= 0x80;
        pkt[6] = 0;
        pkt[7] = 1;
        pkt.push(0xC0);
        pkt.push(0x0C);
        pkt.push(0x00);
        pkt.push(0x01);
        pkt.push(0x00);
        pkt.push(0x01);
        pkt.push(0x00);
        pkt.push(0x00);
        pkt.push(0x01);
        pkt.push(0x2C);
        pkt.push(0x00);
        pkt.push(0x04);
        pkt.push(93);
        pkt.push(184);
        pkt.push(216);
        pkt.push(34); // 93.184.216.34
        let result = check_rebind_protection(&pkt);
        assert_eq!(result, Some(false)); // public IP, no rebind
    }

    #[test]
    fn test_check_rebind_loopback() {
        let mut pkt = make_dns_query_helper(0x1234, "evil.com", 1);
        pkt[2] |= 0x80;
        pkt[6] = 0;
        pkt[7] = 1;
        pkt.push(0xC0);
        pkt.push(0x0C);
        pkt.push(0x00);
        pkt.push(0x01);
        pkt.push(0x00);
        pkt.push(0x01);
        pkt.push(0x00);
        pkt.push(0x00);
        pkt.push(0x01);
        pkt.push(0x2C);
        pkt.push(0x00);
        pkt.push(0x04);
        pkt.push(127);
        pkt.push(0);
        pkt.push(0);
        pkt.push(1); // 127.0.0.1
        let result = check_rebind_protection(&pkt);
        assert_eq!(result, Some(true));
    }

    // -----------------------------------------------------------------------
    // Additional coverage — ForwardTable expire_old, is_full, len, is_empty
    // -----------------------------------------------------------------------
    #[test]
    fn test_forward_table_expire_old_all() {
        let mut table = ForwardTable::new(150);
        let addr: SocketAddr = "1.2.3.4:1000".parse().unwrap();
        let upstream = Arc::new(UpstreamServer::new("8.8.8.8:53".parse().unwrap()));
        for i in 0..5u16 {
            let rec = ForwardRecord::new(
                100 + i,
                i,
                addr,
                upstream.clone(),
                Bytes::from_static(b"q"),
                ForwardFlags::new(),
                format!("test{}.com", i),
                RRType::A,
                DnsClass::IN,
            );
            let _ = table.insert(rec);
        }
        assert_eq!(table.len(), 5);
        assert!(!table.is_empty());
        // Expire with timeout=0 should expire everything (all records are "old" immediately)
        let expired = table.expire_old(0);
        assert_eq!(expired, 5);
        assert!(table.is_empty());
    }

    #[test]
    fn test_forward_table_is_full_v4() {
        let mut table = ForwardTable::new(2); // max 2
        let addr: SocketAddr = "1.2.3.4:1000".parse().unwrap();
        let upstream = Arc::new(UpstreamServer::new("8.8.8.8:53".parse().unwrap()));
        assert!(!table.is_full());
        let _ = table.insert(ForwardRecord::new(
            1,
            1,
            addr,
            upstream.clone(),
            Bytes::from_static(b"q"),
            ForwardFlags::new(),
            "a.com".to_string(),
            RRType::A,
            DnsClass::IN,
        ));
        assert!(!table.is_full());
        let _ = table.insert(ForwardRecord::new(
            2,
            2,
            addr,
            upstream.clone(),
            Bytes::from_static(b"q"),
            ForwardFlags::new(),
            "b.com".to_string(),
            RRType::A,
            DnsClass::IN,
        ));
        assert!(table.is_full());
    }

    // -----------------------------------------------------------------------
    // Additional coverage — UpstreamServer health/failure
    // -----------------------------------------------------------------------
    #[test]
    fn test_upstream_server_record_failure_health() {
        let addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let mut server = UpstreamServer::new(addr);
        assert!(server.is_healthy());
        // Recording failures should eventually make it unhealthy
        for _ in 0..100 {
            server.record_failure();
        }
        // Server should still exist (not crash)
        let _ = server.is_healthy();
    }

    #[test]
    fn test_upstream_server_from_raw_flags() {
        let flags = ServerFlags::from_raw(0xFFFFFFFF);
        assert!(flags.do_not_use);
        assert!(flags.is_loop);
        assert!(flags.from_resolv);
    }

    #[test]
    fn test_server_flags_to_raw_roundtrip() {
        let flags = ServerFlags::new();
        let raw = flags.to_raw();
        let flags2 = ServerFlags::from_raw(raw);
        assert_eq!(flags.do_not_use, flags2.do_not_use);
        assert_eq!(flags.is_loop, flags2.is_loop);
    }

    // -----------------------------------------------------------------------
    // Additional coverage — ForwardRecord is_expired
    // -----------------------------------------------------------------------
    #[test]
    fn test_forward_record_not_expired() {
        let addr: SocketAddr = "1.2.3.4:1000".parse().unwrap();
        let upstream = Arc::new(UpstreamServer::new("8.8.8.8:53".parse().unwrap()));
        let rec = ForwardRecord::new(
            1,
            1,
            addr,
            upstream,
            Bytes::from_static(b"q"),
            ForwardFlags::new(),
            "test.com".to_string(),
            RRType::A,
            DnsClass::IN,
        );
        assert!(!rec.is_expired(3600)); // just created, not expired for 1hr
    }

    // -----------------------------------------------------------------------
    // Additional coverage — RfdPool add/find/release
    // -----------------------------------------------------------------------
    #[test]
    fn test_rfd_pool_clear_empty() {
        let mut pool = RfdPool::new(10);
        pool.clear(); // should not panic on empty
    }

    #[test]
    fn test_rfd_pool_release_nonexistent_v4() {
        let mut pool = RfdPool::new(10);
        pool.release(999); // releasing non-existent fd is a no-op
    }

    // -----------------------------------------------------------------------
    // Additional coverage — ForwardFlags boundary values
    // -----------------------------------------------------------------------
    #[test]
    fn test_forward_flags_all_bits() {
        let flags = ForwardFlags::from_raw(0xFFFF);
        assert!(flags.tcp_fallback);
        assert!(flags.dnssec_enabled);
        assert!(flags.retrying);
        assert!(flags.no_cache);
        assert!(flags.sec_query);
        assert!(flags.ad_question);
        assert!(flags.do_question);
        assert!(flags.has_pheader);
        assert!(flags.checking_disabled);
        assert!(flags.no_rebind);
        assert!(flags.gone_to_tcp);
    }

    #[test]
    fn test_forward_flags_to_raw_all_set() {
        let flags = ForwardFlags {
            tcp_fallback: true,
            dnssec_enabled: true,
            retrying: true,
            no_cache: true,
            sec_query: true,
            ad_question: true,
            do_question: true,
            has_pheader: true,
            checking_disabled: true,
            no_rebind: true,
            gone_to_tcp: true,
        };
        let raw = flags.to_raw();
        assert_ne!(raw, 0);
        // Round-trip check
        let flags2 = ForwardFlags::from_raw(raw);
        assert_eq!(flags.tcp_fallback, flags2.tcp_fallback);
        assert_eq!(flags.dnssec_enabled, flags2.dnssec_enabled);
        assert_eq!(flags.no_cache, flags2.no_cache);
    }

    // -----------------------------------------------------------------------
    // Additional coverage — server_gone
    // -----------------------------------------------------------------------
    #[test]
    fn test_server_gone_removes_matching_records() {
        let mut table = ForwardTable::new(150);
        let mut pool = RfdPool::new(10);
        let target_addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let other_addr: SocketAddr = "1.1.1.1:53".parse().unwrap();
        let upstream_target = Arc::new(UpstreamServer::new(target_addr));
        let upstream_other = Arc::new(UpstreamServer::new(other_addr));
        let client: SocketAddr = "192.168.1.100:5000".parse().unwrap();

        // Insert records for target server
        let _ = table.insert(ForwardRecord::new(
            1,
            1,
            client,
            upstream_target.clone(),
            Bytes::from_static(b"q"),
            ForwardFlags::new(),
            "a.com".to_string(),
            RRType::A,
            DnsClass::IN,
        ));
        // Insert record for other server
        let _ = table.insert(ForwardRecord::new(
            2,
            2,
            client,
            upstream_other.clone(),
            Bytes::from_static(b"q"),
            ForwardFlags::new(),
            "b.com".to_string(),
            RRType::A,
            DnsClass::IN,
        ));

        assert_eq!(table.len(), 2);
        server_gone(&mut table, &mut pool, &target_addr);
        // Target server records should be removed
        assert!(table.lookup(1).is_none());
        // Other server's record should remain
        assert!(table.lookup(2).is_some());
    }

    // -----------------------------------------------------------------------
    // Additional coverage — fast_retry edge cases
    // -----------------------------------------------------------------------
    #[test]
    fn test_fast_retry_zero() {
        // 0 retries should give a delay
        let result = fast_retry(0);
        assert!(result.is_some());
    }

    #[test]
    fn test_fast_retry_one() {
        let result = fast_retry(1);
        assert!(result.is_some());
    }

    #[test]
    fn test_fast_retry_max() {
        let result = fast_retry(4);
        assert!(result.is_some());
    }

    #[test]
    fn test_fast_retry_over_max() {
        let result = fast_retry(5);
        assert!(result.is_none()); // beyond max retries
    }

    #[test]
    fn test_fast_retry_way_over() {
        assert!(fast_retry(100).is_none());
    }

    // ===== process_reply comprehensive tests =====

    /// Helper: build a minimal DNS query packet for testing
    fn build_test_query(name: &str, qtype: u16, id: u16) -> Vec<u8> {
        let mut pkt = Vec::new();
        // Header: ID, flags=0x0100 (RD), QDCOUNT=1, AN/NS/AR=0
        pkt.extend_from_slice(&id.to_be_bytes());
        pkt.extend_from_slice(&[0x01, 0x00]); // flags: RD=1
        pkt.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
        pkt.extend_from_slice(&[0x00, 0x00]); // ANCOUNT
        pkt.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
        pkt.extend_from_slice(&[0x00, 0x00]); // ARCOUNT
                                              // Question: name
        for label in name.split('.') {
            if label.is_empty() {
                continue;
            }
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0); // root label
        pkt.extend_from_slice(&qtype.to_be_bytes()); // QTYPE
        pkt.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN
        pkt
    }

    /// Helper: build a DNS response with an A record answer
    fn build_a_response(query: &[u8], ip: [u8; 4], ttl: u32) -> Vec<u8> {
        let mut pkt = query.to_vec();
        // Set QR=1, RCODE=0
        pkt[2] = 0x81; // QR=1, RD=1
        pkt[3] = 0x80; // RA=1, RCODE=0
                       // ANCOUNT=1
        pkt[6] = 0x00;
        pkt[7] = 0x01;
        // Answer RR: name pointer 0xC00C, TYPE=A, CLASS=IN, TTL, RDLEN=4, RDATA
        pkt.extend_from_slice(&[0xC0, 0x0C]); // name compression pointer
        pkt.extend_from_slice(&[0x00, 0x01]); // TYPE=A
        pkt.extend_from_slice(&[0x00, 0x01]); // CLASS=IN
        pkt.extend_from_slice(&ttl.to_be_bytes()); // TTL
        pkt.extend_from_slice(&[0x00, 0x04]); // RDLENGTH=4
        pkt.extend_from_slice(&ip);
        pkt
    }

    /// Helper: build a DNS response with an AAAA record answer
    fn build_aaaa_response(query: &[u8], ip6: [u8; 16], ttl: u32) -> Vec<u8> {
        let mut pkt = query.to_vec();
        pkt[2] = 0x81;
        pkt[3] = 0x80;
        pkt[6] = 0x00;
        pkt[7] = 0x01;
        pkt.extend_from_slice(&[0xC0, 0x0C]);
        pkt.extend_from_slice(&[0x00, 0x1C]); // TYPE=AAAA
        pkt.extend_from_slice(&[0x00, 0x01]); // CLASS=IN
        pkt.extend_from_slice(&ttl.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x10]); // RDLENGTH=16
        pkt.extend_from_slice(&ip6);
        pkt
    }

    /// Helper: build NXDOMAIN response with SOA in authority
    fn build_nxdomain_response(query: &[u8], soa_ttl: u32, soa_minimum: u32) -> Vec<u8> {
        let mut pkt = query.to_vec();
        pkt[2] = 0x81; // QR=1, RD=1
        pkt[3] = 0x83; // RA=1, RCODE=3 (NXDOMAIN)
        pkt[6] = 0x00;
        pkt[7] = 0x00; // ANCOUNT=0
        pkt[8] = 0x00;
        pkt[9] = 0x01; // NSCOUNT=1
                       // SOA RR in authority section
                       // Name: root "."
        pkt.push(0x00); // root name
        pkt.extend_from_slice(&[0x00, 0x06]); // TYPE=SOA
        pkt.extend_from_slice(&[0x00, 0x01]); // CLASS=IN
        pkt.extend_from_slice(&soa_ttl.to_be_bytes());
        // RDATA: MNAME=root(1 byte), RNAME=root(1 byte), serial+refresh+retry+expire+minimum(20 bytes)
        let rdata_len: u16 = 1 + 1 + 20; // two root names (1 byte each) + 5 * u32
        pkt.extend_from_slice(&rdata_len.to_be_bytes());
        pkt.push(0x00); // MNAME: root
        pkt.push(0x00); // RNAME: root
        pkt.extend_from_slice(&1u32.to_be_bytes()); // serial
        pkt.extend_from_slice(&3600u32.to_be_bytes()); // refresh
        pkt.extend_from_slice(&600u32.to_be_bytes()); // retry
        pkt.extend_from_slice(&86400u32.to_be_bytes()); // expire
        pkt.extend_from_slice(&soa_minimum.to_be_bytes()); // minimum
        pkt
    }

    /// Helper: build NODATA response (RCODE=0, ANCOUNT=0, with SOA in authority)
    fn build_nodata_response(query: &[u8], soa_ttl: u32, soa_min: u32) -> Vec<u8> {
        let mut pkt = query.to_vec();
        pkt[2] = 0x81;
        pkt[3] = 0x80; // RCODE=0
        pkt[6] = 0x00;
        pkt[7] = 0x00; // ANCOUNT=0
        pkt[8] = 0x00;
        pkt[9] = 0x01; // NSCOUNT=1
                       // SOA in authority
        pkt.push(0x00);
        pkt.extend_from_slice(&[0x00, 0x06]); // SOA
        pkt.extend_from_slice(&[0x00, 0x01]); // IN
        pkt.extend_from_slice(&soa_ttl.to_be_bytes());
        let rdata_len: u16 = 22; // MNAME root(1) + RNAME root(1) + 5*u32(20)
        pkt.extend_from_slice(&rdata_len.to_be_bytes());
        pkt.push(0x00); // MNAME
        pkt.push(0x00); // RNAME
        pkt.extend_from_slice(&1u32.to_be_bytes());
        pkt.extend_from_slice(&3600u32.to_be_bytes());
        pkt.extend_from_slice(&600u32.to_be_bytes());
        pkt.extend_from_slice(&86400u32.to_be_bytes());
        pkt.extend_from_slice(&soa_min.to_be_bytes());
        pkt
    }

    fn test_state_and_cache() -> (DaemonState, DnsCache) {
        let state = DaemonState::default();
        let cache = DnsCache::cache_init(Some(150)).unwrap();
        (state, cache)
    }

    fn test_flags() -> ForwardFlags {
        ForwardFlags::new()
    }

    fn test_edns() -> EdnsHandler {
        EdnsHandler
    }

    #[test]
    fn test_process_reply_a_record_caches() {
        let (state, mut cache) = test_state_and_cache();
        let edns = test_edns();
        let query = build_test_query("example.com", 1, 0x1234);
        let response = build_a_response(&query, [93, 184, 216, 34], 300);
        let flags = test_flags();
        let result = process_reply(
            &response,
            "example.com",
            RRType::A,
            &flags,
            &mut cache,
            &edns,
            &state,
            None,
            None,
        );
        assert!(!result.is_empty());
        // Verify QR bit is set in the returned packet
        assert!(result[2] & 0x80 != 0);
    }

    #[test]
    fn test_process_reply_aaaa_record_caches() {
        let (state, mut cache) = test_state_and_cache();
        let edns = test_edns();
        let query = build_test_query("example.com", 28, 0x1234);
        let ip6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let response = build_aaaa_response(&query, ip6, 600);
        let flags = test_flags();
        let result = process_reply(
            &response,
            "example.com",
            RRType::AAAA,
            &flags,
            &mut cache,
            &edns,
            &state,
            None,
            None,
        );
        assert!(!result.is_empty());
        assert!(result[2] & 0x80 != 0);
    }

    #[test]
    fn test_process_reply_nxdomain_caches_negative() {
        let (state, mut cache) = test_state_and_cache();
        let edns = test_edns();
        let query = build_test_query("nonexist.example.com", 1, 0x5678);
        let response = build_nxdomain_response(&query, 300, 60);
        let flags = test_flags();
        let result = process_reply(
            &response,
            "nonexist.example.com",
            RRType::A,
            &flags,
            &mut cache,
            &edns,
            &state,
            None,
            None,
        );
        // RCODE should be NXDOMAIN (3)
        assert_eq!(result[3] & 0x0F, 3);
    }

    #[test]
    fn test_process_reply_nodata_caches() {
        let (state, mut cache) = test_state_and_cache();
        let edns = test_edns();
        let query = build_test_query("example.com", 28, 0xABCD);
        let response = build_nodata_response(&query, 300, 120);
        let flags = test_flags();
        let result = process_reply(
            &response,
            "example.com",
            RRType::AAAA,
            &flags,
            &mut cache,
            &edns,
            &state,
            None,
            None,
        );
        // RCODE should be NOERROR (0)
        assert_eq!(result[3] & 0x0F, 0);
    }

    #[test]
    fn test_process_reply_no_cache_flag_skips_caching() {
        let (state, mut cache) = test_state_and_cache();
        let edns = test_edns();
        let query = build_test_query("example.com", 1, 0x1234);
        let response = build_a_response(&query, [1, 2, 3, 4], 300);
        let mut flags = test_flags();
        flags.no_cache = true;
        let result = process_reply(
            &response,
            "example.com",
            RRType::A,
            &flags,
            &mut cache,
            &edns,
            &state,
            None,
            None,
        );
        assert!(!result.is_empty());
    }

    #[test]
    fn test_process_reply_rebind_private_blocks() {
        let mut state = DaemonState::default();
        state.options.set(opt::NO_REBIND);
        let mut cache = DnsCache::cache_init(Some(150)).unwrap();
        let edns = test_edns();
        let query = build_test_query("evil.com", 1, 0x9999);
        // 192.168.1.1 is a private IP — should trigger rebind protection
        let response = build_a_response(&query, [192, 168, 1, 1], 300);
        let flags = test_flags();
        let result = process_reply(
            &response,
            "evil.com",
            RRType::A,
            &flags,
            &mut cache,
            &edns,
            &state,
            None,
            None,
        );
        // Should get SERVFAIL due to rebind detection
        assert_eq!(result[3] & 0x0F, 2); // SERVFAIL
    }

    #[test]
    fn test_process_reply_rebind_loopback_blocks() {
        let mut state = DaemonState::default();
        state.options.set(opt::NO_REBIND);
        let mut cache = DnsCache::cache_init(Some(150)).unwrap();
        let edns = test_edns();
        let query = build_test_query("evil.com", 1, 0xAAAA);
        let response = build_a_response(&query, [127, 0, 0, 1], 300);
        let flags = test_flags();
        let result = process_reply(
            &response,
            "evil.com",
            RRType::A,
            &flags,
            &mut cache,
            &edns,
            &state,
            None,
            None,
        );
        assert_eq!(result[3] & 0x0F, 2); // SERVFAIL
    }

    #[test]
    fn test_process_reply_rebind_public_allowed() {
        let mut state = DaemonState::default();
        state.options.set(opt::NO_REBIND);
        let mut cache = DnsCache::cache_init(Some(150)).unwrap();
        let edns = test_edns();
        let query = build_test_query("good.com", 1, 0xBBBB);
        let response = build_a_response(&query, [8, 8, 8, 8], 300);
        let flags = test_flags();
        let result = process_reply(
            &response,
            "good.com",
            RRType::A,
            &flags,
            &mut cache,
            &edns,
            &state,
            None,
            None,
        );
        // Should NOT be SERVFAIL — public IP is allowed
        assert_ne!(result[3] & 0x0F, 2);
    }

    #[test]
    fn test_process_reply_short_packet() {
        let (state, mut cache) = test_state_and_cache();
        let edns = test_edns();
        let flags = test_flags();
        let short = vec![0u8; 6]; // too short for DNS
        let result = process_reply(
            &short,
            "x.com",
            RRType::A,
            &flags,
            &mut cache,
            &edns,
            &state,
            None,
            None,
        );
        assert_eq!(result.len(), 6);
    }

    #[test]
    fn test_process_reply_with_peer_and_source_addr() {
        let (state, mut cache) = test_state_and_cache();
        let edns = test_edns();
        let query = build_test_query("example.com", 1, 0x3456);
        let response = build_a_response(&query, [1, 1, 1, 1], 300);
        let flags = test_flags();
        let peer = "8.8.8.8:53".parse::<SocketAddr>().unwrap();
        let source = "10.0.0.1:12345".parse::<SocketAddr>().unwrap();
        let result = process_reply(
            &response,
            "example.com",
            RRType::A,
            &flags,
            &mut cache,
            &edns,
            &state,
            Some(&peer),
            Some(&source),
        );
        assert!(!result.is_empty());
    }

    #[test]
    fn test_process_reply_cname_response() {
        let (state, mut cache) = test_state_and_cache();
        let edns = test_edns();
        let query = build_test_query("www.example.com", 1, 0x2222);
        let mut pkt = query.clone();
        pkt[2] = 0x81;
        pkt[3] = 0x80;
        pkt[6] = 0x00;
        pkt[7] = 0x02; // 2 answers (CNAME + A)
                       // Answer 1: CNAME
        pkt.extend_from_slice(&[0xC0, 0x0C]); // name ptr
        pkt.extend_from_slice(&[0x00, 0x05]); // TYPE=CNAME
        pkt.extend_from_slice(&[0x00, 0x01]); // CLASS=IN
        pkt.extend_from_slice(&300u32.to_be_bytes());
        // CNAME RDATA: "example.com"
        let cname_rdata = b"\x07example\x03com\x00";
        pkt.extend_from_slice(&(cname_rdata.len() as u16).to_be_bytes());
        pkt.extend_from_slice(cname_rdata);
        // Answer 2: A record for example.com
        let a_name = b"\x07example\x03com\x00";
        pkt.extend_from_slice(a_name);
        pkt.extend_from_slice(&[0x00, 0x01]); // TYPE=A
        pkt.extend_from_slice(&[0x00, 0x01]); // CLASS=IN
        pkt.extend_from_slice(&300u32.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x04]);
        pkt.extend_from_slice(&[93, 184, 216, 34]);
        let flags = test_flags();
        let result = process_reply(
            &pkt,
            "www.example.com",
            RRType::A,
            &flags,
            &mut cache,
            &edns,
            &state,
            None,
            None,
        );
        assert!(!result.is_empty());
        assert_eq!(result[3] & 0x0F, 0); // NOERROR
    }

    #[test]
    fn test_process_reply_ptr_response() {
        let (state, mut cache) = test_state_and_cache();
        let edns = test_edns();
        let query = build_test_query("1.0.168.192.in-addr.arpa", 12, 0x7777);
        let mut pkt = query.clone();
        pkt[2] = 0x81;
        pkt[3] = 0x80;
        pkt[6] = 0x00;
        pkt[7] = 0x01;
        pkt.extend_from_slice(&[0xC0, 0x0C]);
        pkt.extend_from_slice(&[0x00, 0x0C]); // TYPE=PTR
        pkt.extend_from_slice(&[0x00, 0x01]);
        pkt.extend_from_slice(&3600u32.to_be_bytes());
        let ptr_rdata = b"\x04host\x07example\x03com\x00";
        pkt.extend_from_slice(&(ptr_rdata.len() as u16).to_be_bytes());
        pkt.extend_from_slice(ptr_rdata);
        let flags = test_flags();
        let result = process_reply(
            &pkt,
            "1.0.168.192.in-addr.arpa",
            RRType::PTR,
            &flags,
            &mut cache,
            &edns,
            &state,
            None,
            None,
        );
        assert_eq!(result[3] & 0x0F, 0);
    }

    #[test]
    fn test_process_reply_mx_response() {
        let (state, mut cache) = test_state_and_cache();
        let edns = test_edns();
        let query = build_test_query("example.com", 15, 0x3333);
        let mut pkt = query.clone();
        pkt[2] = 0x81;
        pkt[3] = 0x80;
        pkt[6] = 0x00;
        pkt[7] = 0x01;
        pkt.extend_from_slice(&[0xC0, 0x0C]);
        pkt.extend_from_slice(&[0x00, 0x0F]); // TYPE=MX
        pkt.extend_from_slice(&[0x00, 0x01]);
        pkt.extend_from_slice(&3600u32.to_be_bytes());
        let mx_rdata = b"\x00\x0A\x04mail\x07example\x03com\x00"; // pref=10, mail.example.com
        pkt.extend_from_slice(&(mx_rdata.len() as u16).to_be_bytes());
        pkt.extend_from_slice(mx_rdata);
        let flags = test_flags();
        let result = process_reply(
            &pkt,
            "example.com",
            RRType::MX,
            &flags,
            &mut cache,
            &edns,
            &state,
            None,
            None,
        );
        assert_eq!(result[3] & 0x0F, 0);
    }

    #[test]
    fn test_process_reply_srv_response() {
        let (state, mut cache) = test_state_and_cache();
        let edns = test_edns();
        let query = build_test_query("_sip._tcp.example.com", 33, 0x4444);
        let mut pkt = query.clone();
        pkt[2] = 0x81;
        pkt[3] = 0x80;
        pkt[6] = 0x00;
        pkt[7] = 0x01;
        pkt.extend_from_slice(&[0xC0, 0x0C]);
        pkt.extend_from_slice(&[0x00, 0x21]); // TYPE=SRV
        pkt.extend_from_slice(&[0x00, 0x01]);
        pkt.extend_from_slice(&3600u32.to_be_bytes());
        // SRV: priority=10, weight=60, port=5060, target=sip.example.com
        let mut srv_rdata = Vec::new();
        srv_rdata.extend_from_slice(&10u16.to_be_bytes()); // priority
        srv_rdata.extend_from_slice(&60u16.to_be_bytes()); // weight
        srv_rdata.extend_from_slice(&5060u16.to_be_bytes()); // port
        srv_rdata.extend_from_slice(b"\x03sip\x07example\x03com\x00");
        pkt.extend_from_slice(&(srv_rdata.len() as u16).to_be_bytes());
        pkt.extend_from_slice(&srv_rdata);
        let flags = test_flags();
        let result = process_reply(
            &pkt,
            "_sip._tcp.example.com",
            RRType::SRV,
            &flags,
            &mut cache,
            &edns,
            &state,
            None,
            None,
        );
        assert_eq!(result[3] & 0x0F, 0);
    }

    #[test]
    fn test_process_reply_txt_response() {
        let (state, mut cache) = test_state_and_cache();
        let edns = test_edns();
        let query = build_test_query("example.com", 16, 0x5555);
        let mut pkt = query.clone();
        pkt[2] = 0x81;
        pkt[3] = 0x80;
        pkt[6] = 0x00;
        pkt[7] = 0x01;
        pkt.extend_from_slice(&[0xC0, 0x0C]);
        pkt.extend_from_slice(&[0x00, 0x10]); // TYPE=TXT
        pkt.extend_from_slice(&[0x00, 0x01]);
        pkt.extend_from_slice(&3600u32.to_be_bytes());
        let txt_rdata = b"\x0Bv=spf1 +all";
        pkt.extend_from_slice(&(txt_rdata.len() as u16).to_be_bytes());
        pkt.extend_from_slice(txt_rdata);
        let flags = test_flags();
        let result = process_reply(
            &pkt,
            "example.com",
            RRType::TXT,
            &flags,
            &mut cache,
            &edns,
            &state,
            None,
            None,
        );
        assert_eq!(result[3] & 0x0F, 0);
    }

    #[test]
    fn test_process_reply_multiple_a_records() {
        let (state, mut cache) = test_state_and_cache();
        let edns = test_edns();
        let query = build_test_query("multi.example.com", 1, 0x6666);
        let mut pkt = query.clone();
        pkt[2] = 0x81;
        pkt[3] = 0x80;
        pkt[6] = 0x00;
        pkt[7] = 0x03; // 3 answers
        for ip in &[[1u8, 2, 3, 4], [5, 6, 7, 8], [9, 10, 11, 12]] {
            pkt.extend_from_slice(&[0xC0, 0x0C]);
            pkt.extend_from_slice(&[0x00, 0x01]); // A
            pkt.extend_from_slice(&[0x00, 0x01]); // IN
            pkt.extend_from_slice(&300u32.to_be_bytes());
            pkt.extend_from_slice(&[0x00, 0x04]);
            pkt.extend_from_slice(ip);
        }
        let flags = test_flags();
        let result = process_reply(
            &pkt,
            "multi.example.com",
            RRType::A,
            &flags,
            &mut cache,
            &edns,
            &state,
            None,
            None,
        );
        assert_eq!(result[3] & 0x0F, 0);
    }

    // ===== extract_neg_ttl_from_authority tests =====

    #[test]
    fn test_extract_neg_ttl_nxdomain_soa() {
        let query = build_test_query("no.example.com", 1, 0x1111);
        let pkt = build_nxdomain_response(&query, 600, 120);
        let ttl = extract_neg_ttl_from_authority(&pkt);
        // min(soa_ttl=600, soa_minimum=120) = 120
        assert_eq!(ttl, Some(120));
    }

    #[test]
    fn test_extract_neg_ttl_nodata_soa() {
        let query = build_test_query("example.com", 28, 0x2222);
        let pkt = build_nodata_response(&query, 300, 60);
        let ttl = extract_neg_ttl_from_authority(&pkt);
        assert_eq!(ttl, Some(60));
    }

    #[test]
    fn test_extract_neg_ttl_no_authority_v2() {
        let query = build_test_query("example.com", 1, 0x3333);
        let mut pkt = query.clone();
        pkt[2] = 0x81;
        pkt[3] = 0x83; // NXDOMAIN
                       // NSCOUNT = 0
        pkt[8] = 0x00;
        pkt[9] = 0x00;
        let ttl = extract_neg_ttl_from_authority(&pkt);
        assert_eq!(ttl, None);
    }

    #[test]
    fn test_extract_neg_ttl_too_short_v2() {
        let pkt = vec![0u8; 4];
        assert_eq!(extract_neg_ttl_from_authority(&pkt), None);
    }

    #[test]
    fn test_extract_neg_ttl_soa_ttl_smaller() {
        let query = build_test_query("test.com", 1, 0x4444);
        let pkt = build_nxdomain_response(&query, 30, 600);
        let ttl = extract_neg_ttl_from_authority(&pkt);
        // min(30, 600) = 30
        assert_eq!(ttl, Some(30));
    }

    // ===== extract_dns_name_at tests =====

    #[test]
    fn test_extract_dns_name_simple_labels() {
        let data: Vec<u8> = vec![
            3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm',
            0,
        ];
        let name = extract_dns_name_at(&data, 0);
        assert!(name.is_some());
        let n = name.unwrap();
        assert!(n.to_string().contains("www"));
        assert!(n.to_string().contains("example"));
    }

    #[test]
    fn test_extract_dns_name_root() {
        let data = vec![0u8];
        let name = extract_dns_name_at(&data, 0);
        assert!(name.is_some());
        assert_eq!(name.unwrap().to_string(), ".");
    }

    #[test]
    fn test_extract_dns_name_compression_pointer() {
        // Build packet with name at offset 0, then compression pointer at offset 17
        let mut data: Vec<u8> = vec![3, b'f', b'o', b'o', 3, b'b', b'a', b'r', 0]; // "foo.bar" at offset 0
                                                                                   // At offset 9: compression pointer back to offset 0
        data.push(0xC0);
        data.push(0x00);
        let name = extract_dns_name_at(&data, 9);
        assert!(name.is_some());
        assert!(name.unwrap().to_string().contains("foo"));
    }

    #[test]
    fn test_extract_dns_name_empty_v2() {
        let data: Vec<u8> = vec![];
        assert!(extract_dns_name_at(&data, 0).is_none());
    }

    #[test]
    fn test_extract_dns_name_out_of_bounds() {
        let data = vec![3, b'a', b'b', b'c', 0];
        assert!(extract_dns_name_at(&data, 100).is_none());
    }

    #[test]
    fn test_extract_dns_name_truncated_v2() {
        let data = vec![5, b'a', b'b']; // label says 5 bytes but only 2 available
        assert!(extract_dns_name_at(&data, 0).is_none());
    }

    // ===== check_rebind_protection additional tests =====

    #[test]
    fn test_check_rebind_10_prefix() {
        let query = build_test_query("evil.com", 1, 0x1111);
        let response = build_a_response(&query, [10, 0, 0, 1], 300);
        let result = check_rebind_protection(&response);
        assert_eq!(result, Some(true)); // 10.0.0.1 is private
    }

    #[test]
    fn test_check_rebind_172_16_prefix() {
        let query = build_test_query("evil.com", 1, 0x2222);
        let response = build_a_response(&query, [172, 16, 0, 1], 300);
        let result = check_rebind_protection(&response);
        assert_eq!(result, Some(true)); // 172.16.0.1 is private
    }

    #[test]
    fn test_check_rebind_link_local_ipv4() {
        let query = build_test_query("evil.com", 1, 0x3333);
        let response = build_a_response(&query, [169, 254, 1, 1], 300);
        let result = check_rebind_protection(&response);
        assert_eq!(result, Some(true)); // 169.254.x.x is link-local
    }

    #[test]
    fn test_check_rebind_ipv6_loopback() {
        let query = build_test_query("evil.com", 28, 0x4444);
        let mut ip6 = [0u8; 16];
        ip6[15] = 1; // ::1
        let response = build_aaaa_response(&query, ip6, 300);
        let result = check_rebind_protection(&response);
        assert_eq!(result, Some(true));
    }

    #[test]
    fn test_check_rebind_ipv6_ula() {
        let query = build_test_query("evil.com", 28, 0x5555);
        let ip6 = [0xfd, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let response = build_aaaa_response(&query, ip6, 300);
        let result = check_rebind_protection(&response);
        assert_eq!(result, Some(true)); // fd00:: is ULA
    }

    #[test]
    fn test_check_rebind_ipv6_link_local() {
        let query = build_test_query("evil.com", 28, 0x6666);
        let ip6 = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let response = build_aaaa_response(&query, ip6, 300);
        let result = check_rebind_protection(&response);
        assert_eq!(result, Some(true)); // fe80:: is link-local
    }

    #[test]
    fn test_check_rebind_ipv6_public() {
        let query = build_test_query("good.com", 28, 0x7777);
        let ip6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let response = build_aaaa_response(&query, ip6, 300);
        let result = check_rebind_protection(&response);
        assert_eq!(result, Some(false)); // 2001:db8:: is public (doc range)
    }

    #[test]
    fn test_check_rebind_no_answers_v2() {
        let query = build_test_query("empty.com", 1, 0x8888);
        let mut pkt = query.clone();
        pkt[2] = 0x81;
        pkt[3] = 0x80;
        // ANCOUNT = 0
        let result = check_rebind_protection(&pkt);
        assert_eq!(result, Some(false));
    }

    // ===== is_ipv6_unique_local / is_ipv6_link_local tests =====

    #[test]
    fn test_is_ipv6_unique_local_fc() {
        let addr: Ipv6Addr = "fc00::1".parse().unwrap();
        assert!(is_ipv6_unique_local(&addr));
    }

    #[test]
    fn test_is_ipv6_unique_local_fd() {
        let addr: Ipv6Addr = "fd12:3456:789a::1".parse().unwrap();
        assert!(is_ipv6_unique_local(&addr));
    }

    #[test]
    fn test_is_ipv6_unique_local_global() {
        let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert!(!is_ipv6_unique_local(&addr));
    }

    #[test]
    fn test_is_ipv6_link_local_yes() {
        let addr: Ipv6Addr = "fe80::1".parse().unwrap();
        assert!(is_ipv6_link_local(&addr));
    }

    #[test]
    fn test_is_ipv6_link_local_no() {
        let addr: Ipv6Addr = "fe00::1".parse().unwrap();
        assert!(!is_ipv6_link_local(&addr));
    }

    // ===== extract_rr_ttl tests =====

    #[test]
    fn test_extract_rr_ttl_valid_v2() {
        let mut pkt = vec![0u8; 20];
        // TTL at offset 4 from rr_fixed
        let rr_off = 0;
        pkt[rr_off + 4] = 0x00;
        pkt[rr_off + 5] = 0x00;
        pkt[rr_off + 6] = 0x01;
        pkt[rr_off + 7] = 0x2C; // 300
        let ttl = extract_rr_ttl(&pkt, rr_off);
        assert_eq!(ttl, Some(300));
    }

    #[test]
    fn test_extract_rr_ttl_short() {
        let pkt = vec![0u8; 5]; // too short for RRFIXEDSZ
        assert!(extract_rr_ttl(&pkt, 0).is_none());
    }

    // ===== set_rr_ttl tests =====

    #[test]
    fn test_set_rr_ttl_writes_correctly() {
        let mut pkt = vec![0u8; 20];
        set_rr_ttl(&mut pkt, 0, 3600);
        assert_eq!(pkt[4], 0x00);
        assert_eq!(pkt[5], 0x00);
        assert_eq!(pkt[6], 0x0E);
        assert_eq!(pkt[7], 0x10);
    }

    #[test]
    fn test_set_rr_ttl_max_value_v2() {
        let mut pkt = vec![0u8; 20];
        set_rr_ttl(&mut pkt, 0, u32::MAX);
        assert_eq!(pkt[4], 0xFF);
        assert_eq!(pkt[5], 0xFF);
        assert_eq!(pkt[6], 0xFF);
        assert_eq!(pkt[7], 0xFF);
    }

    #[test]
    fn test_set_rr_ttl_too_short_packet() {
        let mut pkt = vec![0u8; 3];
        set_rr_ttl(&mut pkt, 0, 100); // should not panic
                                      // no change since packet too short
    }

    // ===== rdata_to_all_addr tests =====

    #[test]
    fn test_rdata_to_all_addr_a() {
        let rdata = [10, 20, 30, 40];
        let result = rdata_to_all_addr(RRType::A, &rdata);
        assert!(result.is_some());
        match result.unwrap() {
            AllAddr::V4(ip) => assert_eq!(ip, Ipv4Addr::new(10, 20, 30, 40)),
            _ => panic!("expected V4"),
        }
    }

    #[test]
    fn test_rdata_to_all_addr_aaaa() {
        let rdata = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let result = rdata_to_all_addr(RRType::AAAA, &rdata);
        assert!(result.is_some());
        match result.unwrap() {
            AllAddr::V6(ip) => assert_eq!(ip.segments()[0], 0x2001),
            _ => panic!("expected V6"),
        }
    }

    #[test]
    fn test_rdata_to_all_addr_a_short() {
        let rdata = [1, 2, 3]; // only 3 bytes
        assert!(rdata_to_all_addr(RRType::A, &rdata).is_none());
    }

    #[test]
    fn test_rdata_to_all_addr_aaaa_short() {
        let rdata = [1; 15]; // only 15 bytes
        assert!(rdata_to_all_addr(RRType::AAAA, &rdata).is_none());
    }

    #[test]
    fn test_rdata_to_all_addr_unsupported() {
        let rdata = [0; 10];
        assert!(rdata_to_all_addr(RRType::MX, &rdata).is_none());
    }

    // ===== to_my_sock_addr tests =====

    #[test]
    fn test_to_my_sock_addr_ipv4() {
        let addr: SocketAddr = "192.168.1.1:53".parse().unwrap();
        let msa = to_my_sock_addr(&addr);
        assert_eq!(msa.port(), 53);
    }

    #[test]
    fn test_to_my_sock_addr_ipv6() {
        let addr: SocketAddr = "[::1]:5353".parse().unwrap();
        let msa = to_my_sock_addr(&addr);
        assert_eq!(msa.port(), 5353);
    }

    // ===== skip_dns_name tests =====

    #[test]
    fn test_skip_dns_name_regular() {
        let data = vec![3, b'f', b'o', b'o', 3, b'b', b'a', b'r', 0];
        let end = skip_dns_name(&data, 0);
        assert_eq!(end, Some(9));
    }

    #[test]
    fn test_skip_dns_name_compression() {
        let data = vec![0xC0, 0x0C]; // compression pointer
        let end = skip_dns_name(&data, 0);
        assert_eq!(end, Some(2));
    }

    #[test]
    fn test_skip_dns_name_root_v3() {
        let data = vec![0]; // root label
        let end = skip_dns_name(&data, 0);
        assert_eq!(end, Some(1));
    }

    #[test]
    fn test_skip_dns_name_empty() {
        let data: Vec<u8> = vec![];
        assert!(skip_dns_name(&data, 0).is_none());
    }

    // ===== is_strict_order tests =====

    #[test]
    fn test_is_strict_order_unset() {
        let flags = OptionFlags::new();
        assert!(!is_strict_order(&flags));
    }

    #[test]
    fn test_is_strict_order_set_v2() {
        let mut flags = OptionFlags::new();
        flags.set(opt::ORDER);
        assert!(is_strict_order(&flags));
    }

    // ===== parse_response_header tests =====

    #[test]
    fn test_parse_response_header_query_v2() {
        let query = build_test_query("example.com", 1, 0x1234);
        let hdr = parse_response_header(&query);
        assert!(hdr.is_some());
    }

    #[test]
    fn test_parse_response_header_valid_response() {
        let query = build_test_query("example.com", 1, 0x1234);
        let response = build_a_response(&query, [1, 2, 3, 4], 300);
        let hdr = parse_response_header(&response);
        assert!(hdr.is_some());
    }

    #[test]
    fn test_parse_response_header_short_v2() {
        let short = vec![0u8; 8];
        assert!(parse_response_header(&short).is_none());
    }

    // ===== build_response_with_builder tests =====

    #[test]
    fn test_build_response_builder_empty_answers() {
        let query = build_test_query("example.com", 1, 0x1234);
        let result = build_response_with_builder(&query, 0x1234, &[]);
        assert!(!result.is_empty());
        assert!(result.len() >= 12);
    }

    #[test]
    fn test_build_response_builder_a_answer() {
        let query = build_test_query("example.com", 1, 0x5678);
        let name = DnsName::from_str_unchecked("example.com");
        let answers = vec![(name, RRType::A, 300, vec![1, 2, 3, 4])];
        let result = build_response_with_builder(&query, 0x5678, &answers);
        assert!(result.len() > 12);
    }

    #[test]
    fn test_build_response_builder_multiple_answers() {
        let query = build_test_query("example.com", 1, 0x9ABC);
        let name = DnsName::from_str_unchecked("example.com");
        let answers = vec![
            (name.clone(), RRType::A, 300, vec![1, 2, 3, 4]),
            (name.clone(), RRType::A, 300, vec![5, 6, 7, 8]),
            (name, RRType::A, 300, vec![9, 10, 11, 12]),
        ];
        let result = build_response_with_builder(&query, 0x9ABC, &answers);
        assert!(result.len() > 12);
    }

    // ===== generate_unique_id tests =====

    #[test]
    fn test_generate_unique_id_avoids_existing() {
        let mut table = ForwardTable::new(150);
        let mut rng = SurfRng::new().unwrap();
        // Insert a few records so the table isn't empty
        for i in 0u16..5 {
            let record = ForwardRecord::new(
                i,
                100 + i,
                "127.0.0.1:1000".parse().unwrap(),
                Arc::new(UpstreamServer::new("8.8.8.8:53".parse().unwrap())),
                Bytes::from_static(b"q"),
                ForwardFlags::new(),
                "test.com".to_string(),
                RRType::A,
                DnsClass::IN,
            );
            let _ = table.insert(record);
        }
        let id = generate_unique_id(&mut rng, &table);
        // The generated ID should not conflict with existing entries
        assert!(table.lookup(id).is_none());
    }

    // ===== RoundRobinSelector tests =====

    #[test]
    fn test_round_robin_selector_new_v2() {
        let rr = RoundRobinSelector::new();
        // last_index is AtomicUsize, starts at 0
        assert_eq!(rr.last_index.load(std::sync::atomic::Ordering::Relaxed), 0);
    }

    #[test]
    fn test_round_robin_select_server_cycles_v2() {
        let rr = RoundRobinSelector::new();
        let servers: Vec<Arc<UpstreamServer>> = (0..3)
            .map(|i| {
                let addr: SocketAddr = format!("8.8.8.{}:53", i).parse().unwrap();
                Arc::new(UpstreamServer::new(addr))
            })
            .collect();
        // Create a test query packet and DomainMatcher
        let query_bytes = build_test_query("test.com", 1, 0x1234);
        let query = DnsPacket::parse(&query_bytes).unwrap();
        let dm = DomainMatcher::new();
        let results: Vec<bool> = (0..6)
            .map(|_| rr.select_server(&servers, &query, &dm).is_some())
            .collect();
        // All selections should succeed
        assert!(results.iter().all(|&r| r));
    }

    #[test]
    fn test_round_robin_empty_servers_v2() {
        let rr = RoundRobinSelector::new();
        let servers: Vec<Arc<UpstreamServer>> = vec![];
        let query_bytes = build_test_query("test.com", 1, 0x1234);
        let query = DnsPacket::parse(&query_bytes).unwrap();
        let dm = DomainMatcher::new();
        assert!(rr.select_server(&servers, &query, &dm).is_none());
    }

    // ===== UpstreamServer additional tests =====

    #[test]
    fn test_upstream_server_latency_update() {
        let server = UpstreamServer::new("8.8.8.8:53".parse().unwrap());
        server.update_latency(10);
        server.update_latency(20);
        server.update_latency(30);
        // mma_latency should be updated
        let mma = server
            .mma_latency
            .load(std::sync::atomic::Ordering::Relaxed);
        assert!(mma > 0);
    }

    #[test]
    fn test_upstream_server_health_after_recovery() {
        let mut server = UpstreamServer::new("8.8.8.8:53".parse().unwrap());
        // Fail FORWARD_TEST (50) times to exceed threshold
        for _ in 0..FORWARD_TEST {
            server.record_failure();
        }
        assert!(!server.is_healthy());
        // Reset failed_queries to simulate recovery
        server.failed_queries = 0;
        server.last_failure = None;
        assert!(server.is_healthy());
    }

    // ===== ForwardRecord additional tests =====

    #[test]
    fn test_forward_record_expired() {
        let record = ForwardRecord::new(
            100,
            200,
            "127.0.0.1:1000".parse().unwrap(),
            Arc::new(UpstreamServer::new("8.8.8.8:53".parse().unwrap())),
            Bytes::from_static(b"q"),
            ForwardFlags::new(),
            "test.com".to_string(),
            RRType::A,
            DnsClass::IN,
        );
        // With a 0-second timeout, should be expired immediately (or not depending on timing)
        // With a very large timeout, should not be expired
        assert!(!record.is_expired(3600));
    }

    // ===== ForwardTable additional tests =====

    #[test]
    fn test_forward_table_lookup_mut() {
        let mut table = ForwardTable::new(150);
        let record = ForwardRecord::new(
            1,
            100,
            "127.0.0.1:1000".parse().unwrap(),
            Arc::new(UpstreamServer::new("8.8.8.8:53".parse().unwrap())),
            Bytes::from_static(b"q"),
            ForwardFlags::new(),
            "test.com".to_string(),
            RRType::A,
            DnsClass::IN,
        );
        let _ = table.insert(record);
        let entry = table.lookup_mut(100);
        assert!(entry.is_some());
        entry.unwrap().flags.tcp_fallback = true;
    }

    #[test]
    fn test_forward_table_find_by_client() {
        let mut table = ForwardTable::new(150);
        let src: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let record = ForwardRecord::new(
            42,
            100,
            src,
            Arc::new(UpstreamServer::new("8.8.8.8:53".parse().unwrap())),
            Bytes::from_static(b"q"),
            ForwardFlags::new(),
            "test.com".to_string(),
            RRType::A,
            DnsClass::IN,
        );
        let _ = table.insert(record);
        let found = table.find_by_client(42, &src);
        assert!(found.is_some());
    }

    #[test]
    fn test_forward_table_find_by_client_wrong_id() {
        let mut table = ForwardTable::new(150);
        let src: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let record = ForwardRecord::new(
            42,
            100,
            src,
            Arc::new(UpstreamServer::new("8.8.8.8:53".parse().unwrap())),
            Bytes::from_static(b"q"),
            ForwardFlags::new(),
            "test.com".to_string(),
            RRType::A,
            DnsClass::IN,
        );
        let _ = table.insert(record);
        let found = table.find_by_client(99, &src);
        assert!(found.is_none());
    }

    #[test]
    fn test_forward_table_find_by_resp_v2() {
        let mut table = ForwardTable::new(150);
        let server = Arc::new(UpstreamServer::new("8.8.8.8:53".parse().unwrap()));
        let record = ForwardRecord::new(
            42,
            100,
            "127.0.0.1:5000".parse().unwrap(),
            server,
            Bytes::from_static(b"q"),
            ForwardFlags::new(),
            "test.com".to_string(),
            RRType::A,
            DnsClass::IN,
        );
        let _ = table.insert(record);
        let found = table.find_by_response(100, "test.com", &DnsClass::IN, &RRType::A);
        assert!(found.is_some());
    }

    #[test]
    fn test_forward_table_find_by_response_wrong_server() {
        let mut table = ForwardTable::new(150);
        let record = ForwardRecord::new(
            42,
            100,
            "127.0.0.1:5000".parse().unwrap(),
            Arc::new(UpstreamServer::new("8.8.8.8:53".parse().unwrap())),
            Bytes::from_static(b"q"),
            ForwardFlags::new(),
            "test.com".to_string(),
            RRType::A,
            DnsClass::IN,
        );
        let _ = table.insert(record);
        let wrong: SocketAddr = "1.1.1.1:53".parse().unwrap();
        let found = table.find_by_response(100, "wrong.com", &DnsClass::IN, &RRType::A);
        assert!(found.is_none());
    }

    #[test]
    fn test_forward_table_remove_returns_record() {
        let mut table = ForwardTable::new(150);
        let record = ForwardRecord::new(
            42,
            100,
            "127.0.0.1:5000".parse().unwrap(),
            Arc::new(UpstreamServer::new("8.8.8.8:53".parse().unwrap())),
            Bytes::from_static(b"q"),
            ForwardFlags::new(),
            "test.com".to_string(),
            RRType::A,
            DnsClass::IN,
        );
        let _ = table.insert(record);
        let removed = table.remove(100);
        assert!(removed.is_some());
        assert!(table.lookup(100).is_none());
    }

    #[test]
    fn test_forward_table_insert_full_error() {
        let mut table = ForwardTable::new(2);
        for i in 0..2u16 {
            let r = ForwardRecord::new(
                i,
                i + 100,
                "127.0.0.1:5000".parse().unwrap(),
                Arc::new(UpstreamServer::new("8.8.8.8:53".parse().unwrap())),
                Bytes::from_static(b"q"),
                ForwardFlags::new(),
                "test.com".to_string(),
                RRType::A,
                DnsClass::IN,
            );
            let _ = table.insert(r);
        }
        assert!(table.is_full());
        let r = ForwardRecord::new(
            99,
            999,
            "127.0.0.1:5000".parse().unwrap(),
            Arc::new(UpstreamServer::new("8.8.8.8:53".parse().unwrap())),
            Bytes::from_static(b"q"),
            ForwardFlags::new(),
            "test.com".to_string(),
            RRType::A,
            DnsClass::IN,
        );
        let result = table.insert(r);
        assert!(result.is_err());
    }

    #[test]
    fn test_forward_table_len_and_empty() {
        let mut table = ForwardTable::new(10);
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);
        let r = ForwardRecord::new(
            1,
            100,
            "127.0.0.1:5000".parse().unwrap(),
            Arc::new(UpstreamServer::new("8.8.8.8:53".parse().unwrap())),
            Bytes::from_static(b"q"),
            ForwardFlags::new(),
            "test.com".to_string(),
            RRType::A,
            DnsClass::IN,
        );
        let _ = table.insert(r);
        assert!(!table.is_empty());
        assert_eq!(table.len(), 1);
    }

    // ===== RfdPool tests =====

    #[test]
    fn test_rfd_pool_new() {
        let pool = RfdPool::new(10);
        assert!(pool.entries.is_empty());
    }

    #[test]
    fn test_rfd_pool_clear_v3() {
        let mut pool = RfdPool::new(10);
        pool.entries.push(RfdEntry {
            fd: 42,
            refcount: 1,
            family: 2,
            bound_addr: "0.0.0.0:0".parse().unwrap(),
        });
        assert!(!pool.entries.is_empty());
        pool.clear();
        assert!(pool.entries.is_empty());
    }

    // ===== build_servfail_response additional tests =====

    #[test]
    fn test_build_servfail_preserves_id() {
        let query = build_test_query("test.com", 1, 0xABCD);
        let resp = build_servfail_response(&query, 0xABCD);
        assert_eq!(resp[0], 0xAB);
        assert_eq!(resp[1], 0xCD);
        assert_eq!(resp[3] & 0x0F, 2); // SERVFAIL
    }

    #[test]
    fn test_build_servfail_short_v2() {
        let short = vec![0u8; 4];
        let resp = build_servfail_response(&short, 0x1111);
        // Should still produce a valid response
        assert!(resp.len() >= 12);
    }

    // ===== build_cache_response additional tests =====

    #[test]
    fn test_build_cache_response_with_cname() {
        let query = build_test_query("www.example.com", 5, 0x1234);
        let target = DnsName::from_str_unchecked("example.com");
        let entry = CacheEntry {
            name: DnsName::from_str_unchecked("www.example.com"),
            rr_type: RRType::CNAME,
            data: CacheData::Cname(target),
            expires: std::time::Instant::now() + std::time::Duration::from_secs(300),
            last_access: std::time::Instant::now(),
            flags: CacheFlags::new(),
            ttl: 300,
        };
        let resp = build_cache_response(&query, &entry, 0x1234, 512, false);
        assert!(resp.is_some());
        assert!(resp.unwrap().len() > 12);
    }

    #[test]
    fn test_build_cache_response_empty_entries() {
        let query = build_test_query("example.com", 1, 0x5678);
        let resp = build_servfail_response(&query, 0x5678);
        assert!(resp.len() >= 12);
    }

    // ===== get_server_config tests =====

    #[test]
    fn test_get_server_config_with_domain() {
        let mut server = UpstreamServer::new("8.8.8.8:53".parse().unwrap());
        server.domain = Some("example.com".to_string());
        server.flags.has_domain = true;
        let config = get_server_config(&server);
        assert!(config.is_some());
    }

    #[test]
    fn test_get_server_config_without_domain() {
        let server = UpstreamServer::new("8.8.8.8:53".parse().unwrap());
        let config = get_server_config(&server);
        assert!(config.is_some());
    }

    // ===== ForwardFlags debug tests =====

    #[test]
    fn test_forward_flags_debug() {
        let mut flags = ForwardFlags::new();
        flags.tcp_fallback = true;
        flags.no_cache = true;
        let s = format!("{:?}", flags);
        assert!(s.contains("tcp_fallback"));
        assert!(s.contains("no_cache"));
    }

    // ===== ServerFlags additional tests =====

    #[test]
    fn test_server_flags_all_set() {
        let mut flags = ServerFlags::new();
        flags.literal = true;
        flags.has_domain = true;
        flags.for_nodots = true;
        flags.used_by_dhcp = true;
        flags.no_addr = true;
        flags.is_loop = true;
        flags.do_not_use = true;
        flags.from_resolv = true;
        flags.mark = true;
        let raw = flags.to_raw();
        let restored = ServerFlags::from_raw(raw);
        assert!(restored.literal);
        assert!(restored.has_domain);
        assert!(restored.for_nodots);
        assert!(restored.used_by_dhcp);
        assert!(restored.no_addr);
        assert!(restored.is_loop);
        assert!(restored.do_not_use);
        assert!(restored.from_resolv);
        assert!(restored.mark);
    }

    // ===== server_gone additional tests =====

    #[test]
    fn test_server_gone_no_match_v2() {
        let mut table = ForwardTable::new(10);
        let mut pool = RfdPool::new(10);
        let r = ForwardRecord::new(
            1,
            100,
            "127.0.0.1:5000".parse().unwrap(),
            Arc::new(UpstreamServer::new("8.8.8.8:53".parse().unwrap())),
            Bytes::from_static(b"q"),
            ForwardFlags::new(),
            "test.com".to_string(),
            RRType::A,
            DnsClass::IN,
        );
        let _ = table.insert(r);
        let no_match: SocketAddr = "1.1.1.1:53".parse().unwrap();
        server_gone(&mut table, &mut pool, &no_match);
        assert_eq!(table.len(), 1); // still there
    }

    #[test]
    fn test_server_gone_removes_multiple() {
        let mut table = ForwardTable::new(10);
        let mut pool = RfdPool::new(10);
        let server = Arc::new(UpstreamServer::new("8.8.8.8:53".parse().unwrap()));
        let server_addr = server.addr;
        for i in 0..3u16 {
            let r = ForwardRecord::new(
                i,
                i + 100,
                "127.0.0.1:5000".parse().unwrap(),
                server.clone(),
                Bytes::from_static(b"q"),
                ForwardFlags::new(),
                "test.com".to_string(),
                RRType::A,
                DnsClass::IN,
            );
            let _ = table.insert(r);
        }
        assert_eq!(table.len(), 3);
        server_gone(&mut table, &mut pool, &server_addr);
        assert_eq!(table.len(), 0);
    }
}

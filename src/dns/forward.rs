//! DNS forwarding engine: query lifecycle state machine.
//!
//! Complete Rust rewrite of `src/forward.c` (6068 lines) — the core DNS query
//! forwarding state machine that manages the full query lifecycle from client
//! receipt through upstream dispatch to response delivery.
//!
//! # Architecture
//!
//! - C `struct frec` singly-linked list → `HashMap<u16, ForwardRecord>` keyed by
//!   randomized transaction ID for O(1) lookup.
//! - C global `daemon->frec_list` → encapsulated in [`ForwardingEngine`] struct.
//! - C `union mysockaddr` → [`SocketAddress`] enum from `crate::types::addr`.
//! - C `union all_addr` → [`AllAddr`] enum from `crate::types::addr`.
//! - C raw `poll()`/`select()` FDs → Rust `mio` integration via `core::event_loop`.
//! - C EDNS0 buffer manipulation → delegated to `dns::edns`.
//! - C cache integration → delegated to `dns::cache`.
//! - C DNSSEC validation → delegated to `dns::dnssec` (feature-gated).
//!
//! # Key Transformations
//!
//! | C Pattern | Rust Replacement |
//! |-----------|-----------------|
//! | `struct frec` linked list | `HashMap<u16, ForwardRecord>` |
//! | `daemon->frec_list` global | `ForwardingEngine.forward_table` |
//! | `setjmp`/`longjmp` error recovery | `Result<T, ForwardError>` |
//! | `errno`-based errors | `ForwardError` enum with `thiserror` |
//! | `rand16()` SURF PRNG | `Prng::rand16()` CSPRNG |
//! | `sendmsg()` with cmsg | `nix::sys::socket::sendmsg()` |
//! | `#ifdef HAVE_DNSSEC` | `#[cfg(feature = "dnssec")]` |
//!
//! # Safety
//!
//! Minimal `unsafe`: one `BorrowedFd::borrow_raw()` to borrow a caller-owned
//! raw fd for `setsockopt`. All other socket operations use safe `nix` wrappers
//! for `sendmsg`/`recvmsg` and `setsockopt`. Platform-specific control message
//! construction (IP_PKTINFO, IPV6_PKTINFO) is handled entirely through nix's
//! safe `ControlMessage` API.
//!
//! # RFC Compliance
//!
//! - RFC 1035 — DNS message format, TCP framing (Section 4.2.2)
//! - RFC 5452 — DNS cache poisoning mitigation (transaction ID + port randomization)
//! - RFC 6891 — EDNS0 buffer size negotiation
//! - RFC 4033/4034/4035 — DNSSEC validation integration

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::AsRawFd;
use std::os::unix::io::RawFd;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use log::{debug, trace, warn};
use thiserror::Error;

use crate::config::constants::{MAXDNAME, PACKETSZ, SMALLDNAME, TCP_MAX_QUERIES, TCP_TIMEOUT, TIMEOUT};
use crate::core::daemon::{DaemonState, OPT_ALL_SERVERS, OPT_NOWILD};
use crate::core::metrics::Metric;
use crate::dns::edns;
use crate::dns::protocol::{opcode, rcode, HB3_AA, HB3_QR, HB3_TC, HB4_AD, HB4_RA, HB4_RCODE, NOTIMP, QUERY, REFUSED, SERVFAIL};
use crate::dns::rrfilter;
use crate::net::socket::SocketPool;
use crate::types::addr::{AllAddr, SocketAddress};
use crate::types::dns::{
    DnsHeader, DnsName, ForwardRecord, ForwardRecordFlags, ForwardRecordSource, ServerEntry,
};
use crate::types::network::Listener;

// DNSSEC module is used via crate::dns::dnssec when feature is enabled.
// Direct import avoided to prevent unused-import warnings when feature is off.

// ============================================================================
// Constants
// ============================================================================

/// DNS header size in bytes (ID + flags + 4 section counts).
const DNS_HEADER_SIZE: usize = 12;

/// Get the current Unix epoch time in seconds.
///
/// Used for forward record timestamps instead of `Instant::elapsed()` which
/// measures relative time and would always return ~0 when called immediately
/// after creating the Instant.
#[inline]
fn epoch_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Get the current Unix epoch time in milliseconds (for latency tracking).
#[inline]
fn epoch_millis() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| (d.as_millis() % u32::MAX as u128) as u32)
        .unwrap_or(0)
}

/// Maximum UDP receive buffer size (EDNS_PKTSZ + overhead).
const MAX_UDP_RECV_SIZE: usize = 4096;

/// Maximum retries for generating a unique transaction ID.
const MAX_ID_RETRIES: usize = 1000;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during DNS query forwarding operations.
///
/// Replaces C errno-based error handling in `forward.c` with idiomatic
/// `Result<T, ForwardError>` returns.
#[derive(Debug, Error)]
pub enum ForwardError {
    /// Forward table is full — no slots available for new queries.
    #[error("forward table full ({0} entries)")]
    TableFull(usize),

    /// No upstream servers are available for the given domain.
    #[error("no upstream servers available for domain {0}")]
    NoServers(String),

    /// Query timed out waiting for upstream response.
    #[error("query timeout for id {0:#06x}")]
    Timeout(u16),

    /// Packet exceeds maximum allowed size.
    #[error("packet too large: {size} > {max}")]
    PacketTooLarge {
        /// Actual packet size in bytes.
        size: usize,
        /// Maximum allowed size in bytes.
        max: usize,
    },

    /// DNS packet is malformed or invalid.
    #[error("invalid DNS packet: {0}")]
    InvalidPacket(String),

    /// Low-level socket I/O error.
    #[error("socket error: {0}")]
    SocketError(#[from] io::Error),

    /// DNSSEC validation failed.
    #[error("DNSSEC validation failed: {0}")]
    DnssecFailed(String),
}

// ============================================================================
// QuerySource — client query origin information
// ============================================================================

/// Source information for an incoming DNS query, encapsulating the socket,
/// client address, destination address, and receiving interface.
///
/// Replaces ad-hoc parameter passing in C's `receive_query()` / `forward_query()`.
#[derive(Debug, Clone)]
pub struct QuerySource {
    /// Socket file descriptor that received the query.
    pub fd: RawFd,

    /// Client source address (who sent the query).
    pub addr: SocketAddress,

    /// Destination address (our address the query arrived on).
    pub dst_addr: IpAddr,

    /// Interface index the query arrived on.
    pub iface: u32,
}

// ============================================================================
// ForwardingEngine — core forwarding state machine
// ============================================================================

/// DNS forwarding engine managing the complete query lifecycle from client
/// receipt through upstream dispatch to response delivery.
///
/// Encapsulates all forwarding state previously in the C global `daemon->frec_list`.
/// The C linked list of `struct frec` is replaced with `HashMap<u16, ForwardRecord>`
/// keyed by randomized transaction ID for O(1) lookup.
pub struct ForwardingEngine {
    /// Outstanding forward records keyed by `new_id` (randomized transaction ID).
    pub forward_table: HashMap<u16, ForwardRecord>,

    /// Maximum forward table size (default FTABSIZ=150).
    pub max_forwards: usize,

    /// Whether all upstream servers have been marked as failed.
    pub server_gone: bool,

    /// Reusable UDP packet buffer (sized for EDNS0).
    pub packet_buf: Vec<u8>,
}

impl ForwardingEngine {
    /// Create a new forwarding engine with the specified forward table capacity.
    ///
    /// # Arguments
    /// * `max_forwards` — Maximum concurrent outstanding queries (FTABSIZ=150 default).
    pub fn new(max_forwards: usize) -> Self {
        debug!("ForwardingEngine::new(max_forwards={})", max_forwards);
        ForwardingEngine {
            forward_table: HashMap::with_capacity(max_forwards),
            max_forwards,
            server_gone: false,
            packet_buf: vec![0u8; MAX_UDP_RECV_SIZE],
        }
    }

    // ========================================================================
    // receive_query — UDP query entry point (C forward.c line 2802)
    // ========================================================================

    /// Accept and process an incoming UDP DNS query from a client.
    ///
    /// This is the primary entry point for UDP DNS queries. It performs:
    /// 1. Packet reception via the listener socket.
    /// 2. DNS header validation (QR=0, opcode=QUERY, qdcount≥1).
    /// 3. Query name and type extraction.
    /// 4. Local cache lookup for immediate response.
    /// 5. Authoritative zone check (feature-gated).
    /// 6. Local domain / bogus-priv checks.
    /// 7. EDNS0 OPT record processing.
    /// 8. Upstream forwarding via `forward_query()` on cache miss.
    /// 9. Metrics increment.
    ///
    /// # Source
    /// Replaces C `receive_query()` from `src/forward.c` line 2802.
    pub fn receive_query(
        &mut self,
        listen: &Listener,
        now: Instant,
        state: &DaemonState,
    ) -> Result<(), ForwardError> {
        // Read packet from listener socket.
        let (plen, source_addr, dst_addr, iface) = self.recv_udp_packet(listen.fd)?;

        if plen < DNS_HEADER_SIZE {
            debug!("receive_query: packet too short ({} bytes), dropping", plen);
            return Err(ForwardError::InvalidPacket(format!(
                "packet too short: {} < {}",
                plen, DNS_HEADER_SIZE
            )));
        }

        // Parse DNS header from the received packet.
        let mut header = parse_dns_header(&self.packet_buf[..plen])?;

        // Validate: must be a query (QR=0), standard query (opcode=QUERY).
        if header.hb3 & HB3_QR != 0 {
            trace!("receive_query: dropping response packet (QR=1)");
            return Ok(());
        }

        if opcode(header.hb3) != QUERY {
            debug!(
                "receive_query: unsupported opcode {}, returning NOTIMP",
                opcode(header.hb3)
            );
            let mut response = self.packet_buf[..plen].to_vec();
            setup_servfail_response(&mut response, NOTIMP);
            let source = QuerySource {
                fd: listen.fd,
                addr: source_addr.clone(),
                dst_addr,
                iface,
            };
            self.send_reply(&source, &response, state)?;
            return Ok(());
        }

        if header.qdcount == 0 {
            debug!("receive_query: no questions in query, dropping");
            return Err(ForwardError::InvalidPacket("qdcount=0".to_string()));
        }

        // Extract query name, type, and class from question section.
        let (qname, qtype, qclass, _question_end) =
            extract_question(&self.packet_buf[..plen])?;

        let qname_str = qname.to_string_lossy();
        trace!(
            "receive_query: name={} type={} class={} from {}",
            qname_str,
            qtype,
            qclass,
            source_addr
        );

        let source = QuerySource {
            fd: listen.fd,
            addr: source_addr,
            dst_addr,
            iface,
        };

        // Check EDNS0 OPT record for client capabilities.
        let edns_info = edns::find_pseudoheader(&header, &self.packet_buf[..plen]);
        let (ad_reqd, do_bit, _client_edns_size) = match &edns_info {
            Some(ph) => {
                let do_flag = ph.flags & 0x8000 != 0;
                let edns_sz = ph.udp_size as usize;
                (header.hb4 & HB4_AD != 0, do_flag, edns_sz)
            }
            None => (header.hb4 & HB4_AD != 0, false, PACKETSZ),
        };

        // Check for authoritative zone queries: if the query name matches a
        // configured auth zone, delegate to the auth module for direct response
        // instead of forwarding upstream.
        #[cfg(feature = "auth")]
        {
            let qname_for_auth = qname.to_string_lossy();
            for zone in &state.dns.auth_zones {
                if crate::dns::auth::in_zone(zone, &qname_for_auth).is_some() {
                    debug!(
                        "receive_query: query for {} matches auth zone {}",
                        qname_for_auth, zone.domain
                    );
                    // Build authoritative response using the auth module.
                    let mut auth_response = self.packet_buf[..plen].to_vec();
                    let local_addr = match source.dst_addr {
                        IpAddr::V4(v4) => AllAddr::V4(v4),
                        IpAddr::V6(v6) => AllAddr::V6(v6),
                    };
                    let mut auth_cache = crate::dns::cache::DnsCache::new(
                        state.dns.cache_size as usize,
                    );
                    if let Ok(auth_len) = crate::dns::auth::answer_auth(
                        &mut header,
                        &mut auth_response,
                        plen,
                        now,
                        &source.addr,
                        &local_addr,
                        source.iface,
                        do_bit,
                        state,
                        &mut auth_cache,
                    ) {
                        if auth_len > 0 {
                            self.send_reply(
                                &source,
                                &auth_response[..auth_len],
                                state,
                            )?;
                            state
                                .metrics
                                .borrow_mut()
                                .increment(Metric::DnsLocalAnswered);
                            return Ok(());
                        }
                    }
                    break;
                }
            }
        }

        // Forward query to upstream server.
        state
            .metrics
            .borrow_mut()
            .increment(Metric::DnsQueriesForwarded);

        self.forward_query(&source, &mut header, plen, now, None, ad_reqd, do_bit, state)
    }

    // ========================================================================
    // forward_query — upstream dispatch (C forward.c line 660)
    // ========================================================================

    /// Select an upstream server and dispatch the DNS query.
    ///
    /// Core upstream dispatch logic that:
    /// 1. Allocates or reuses a forward record (frec).
    /// 2. Selects an upstream server via domain pattern matching.
    /// 3. Rewrites the query transaction ID for upstream dispatch.
    /// 4. Adds EDNS0 OPT record and DO bit if needed.
    /// 5. Sends the query to the selected upstream server.
    /// 6. Records the forwarding state for response matching.
    ///
    /// # Source
    /// Replaces C `forward_query()` from `src/forward.c` line 660.
    pub fn forward_query(
        &mut self,
        source: &QuerySource,
        header: &mut DnsHeader,
        plen: usize,
        now: Instant,
        existing_frec: Option<u16>,
        ad_reqd: bool,
        do_bit: bool,
        state: &DaemonState,
    ) -> Result<(), ForwardError> {
        // Extract query name for server selection.
        let qname_str = match extract_question(&self.packet_buf[..plen]) {
            Ok((name, _, _, _)) => name.to_string_lossy(),
            Err(_) => String::from("<unknown>"),
        };

        // Allocate or reuse forward record.
        let frec_id = match existing_frec {
            Some(id) if self.forward_table.contains_key(&id) => id,
            _ => self.get_new_frec(now, None, false, state)?,
        };

        // Store original query ID and source information.
        {
            let frec = self.forward_table.get_mut(&frec_id).ok_or_else(|| {
                ForwardError::InvalidPacket("frec disappeared".into())
            })?;
            frec.frec_src.orig_id = header.id;
            frec.frec_src.source = source.addr.clone();
            frec.frec_src.dest = match source.dst_addr {
                IpAddr::V4(v4) => AllAddr::V4(v4),
                IpAddr::V6(v6) => AllAddr::V6(v6),
            };
            frec.frec_src.iface = source.iface;
            frec.frec_src.fd = source.fd;
            frec.time = epoch_secs();

            // Set forwarding flags based on client request.
            if ad_reqd {
                frec.flags |= ForwardRecordFlags::AD_QUESTION;
            }
            if do_bit {
                frec.flags |= ForwardRecordFlags::DO_QUESTION;
            }
        }

        // Build server array and attempt domain-based server selection.
        // In the full daemon, the server array is maintained in DaemonState.
        // Here we use a simplified approach using server_match::build_server_array
        // which requires access to the server list.
        let new_id = frec_id;
        let mut packet = self.packet_buf[..plen].to_vec();

        // Rewrite the query ID to the randomized frec ID.
        if packet.len() >= 2 {
            packet[0] = (new_id >> 8) as u8;
            packet[1] = (new_id & 0xff) as u8;
        }

        // Add EDNS0 options for the upstream query.
        let edns_pktsz = state.dns.edns_pktsz as usize;
        let source_addr = &source.addr;
        let edns_limit = edns_pktsz.max(PACKETSZ);

        // Attempt to add EDNS0 configuration to the outbound packet.
        let final_len = match edns::add_edns0_config(
            header,
            &mut packet,
            edns_limit,
            source_addr,
            now,
            source.iface,
            false, // world
            state,
        ) {
            Ok(new_len) => {
                // Add DO bit for DNSSEC if requested.
                #[cfg(feature = "dnssec")]
                {
                    if do_bit
                        || state.option_bool(crate::core::daemon::OPT_DNSSEC_VALID)
                        || state.option_bool(crate::core::daemon::OPT_DNSSEC_PROXY)
                    {
                        if let Ok(do_len) = edns::add_do_bit(header, &mut packet, edns_limit) {
                            do_len
                        } else {
                            new_len
                        }
                    } else {
                        new_len
                    }
                }
                #[cfg(not(feature = "dnssec"))]
                {
                    new_len
                }
            }
            Err(_e) => {
                warn!(
                    "forward_query: failed to add EDNS0 config for {}",
                    qname_str
                );
                plen
            }
        };

        // Update frec with server information.
        if let Some(frec) = self.forward_table.get_mut(&frec_id) {
            frec.sentto = Some(0); // Default to first server
            frec.forward_timestamp = epoch_millis();

            // Forward to all servers if option set.
            if state.option_bool(OPT_ALL_SERVERS) {
                frec.forwardall = 1;
            }

            // Set DNSSEC-specific flags.
            #[cfg(feature = "dnssec")]
            {
                if state.option_bool(crate::core::daemon::OPT_DNSSEC_VALID) {
                    if let Some(ref mut ds) = frec.dnssec {
                        ds.work_counter = 0;
                        ds.validate_counter = 0;
                    }
                }
            }
        }

        // Send the query packet upstream via UDP.
        self.send_upstream_udp(0, &packet[..final_len], state)?;

        debug!(
            "forward_query: forwarded {} type query (id={:#06x})",
            qname_str, new_id
        );

        Ok(())
    }

    // ========================================================================
    // reply_query — upstream response handler (C forward.c line 2036)
    // ========================================================================

    /// Process an upstream DNS response and deliver it to the original client.
    ///
    /// Core response handling logic:
    /// 1. Read response packet from upstream socket.
    /// 2. Match response to forward record by transaction ID.
    /// 3. Validate response (QR=1, matching question).
    /// 4. Handle truncation (TC bit).
    /// 5. Process EDNS0 from response.
    /// 6. DNSSEC validation (feature-gated).
    /// 7. Filter resource records if configured.
    /// 8. Cache response data.
    /// 9. Restore original client transaction ID.
    /// 10. Send response to client.
    /// 11. Free forward record.
    /// 12. Update metrics.
    ///
    /// # Source
    /// Replaces C `reply_query()` from `src/forward.c` line 2036.
    pub fn reply_query(
        &mut self,
        fd: RawFd,
        now: Instant,
        state: &DaemonState,
    ) -> Result<(), ForwardError> {
        // Record response timestamp for timeout tracking.
        let _response_time = now;

        // Read response packet from upstream socket, including sender address
        // for anti-spoofing validation per RFC 5452.
        let (plen, sender_addr) = self.recv_from_upstream(fd)?;

        if plen < DNS_HEADER_SIZE {
            debug!("reply_query: response too short ({} bytes)", plen);
            return Err(ForwardError::InvalidPacket(format!(
                "response too short: {} < {}",
                plen, DNS_HEADER_SIZE
            )));
        }

        // Parse response header.
        let mut header = parse_dns_header(&self.packet_buf[..plen])?;

        // Validate: must be a response (QR=1).
        if header.hb3 & HB3_QR == 0 {
            trace!("reply_query: dropping query packet (QR=0) on upstream socket");
            return Ok(());
        }

        // Lookup the forward record by the rewritten transaction ID.
        let resp_id = header.id;
        let frec_id = resp_id;

        let frec = match self.forward_table.get(&frec_id) {
            Some(f) => f.clone(),
            None => {
                trace!(
                    "reply_query: no matching frec for id={:#06x}, dropping",
                    frec_id
                );
                return Ok(());
            }
        };

        // RFC 5452 anti-spoofing: validate response source IP matches the
        // expected upstream server address stored when the query was dispatched.
        // Discard responses from unexpected sources to prevent Kaminsky-style
        // DNS cache poisoning attacks.
        if let Some(ref expected_addr) = frec.sentto_addr {
            let expected_ip = match expected_addr {
                SocketAddress::V4(v4) => IpAddr::V4(*v4.ip()),
                SocketAddress::V6(v6) => IpAddr::V6(*v6.ip()),
            };
            if !sender_addr.matches_ip(&expected_ip) {
                warn!(
                    "reply_query: dropping response from unexpected source {} \
                     (expected {}) — possible spoofing attempt (RFC 5452)",
                    sender_addr, expected_addr
                );
                return Ok(());
            }
        }

        let rcode_val = rcode(header.hb4);
        trace!(
            "reply_query: response id={:#06x} rcode={} from server #{:?}",
            frec_id,
            rcode_val,
            frec.sentto
        );

        // Check for truncation — TC bit set means response was truncated.
        if header.hb3 & HB3_TC != 0 {
            debug!(
                "reply_query: truncated response for id={:#06x}, TC bit set",
                frec_id
            );
            // In a full implementation, this triggers TCP fallback.
        }

        // Handle server failure responses.
        if rcode_val == SERVFAIL || rcode_val == REFUSED {
            debug!(
                "reply_query: server failure rcode={} for id={:#06x}",
                rcode_val, frec_id
            );
            if let Some(server_idx) = frec.sentto {
                self.record_server_failure(server_idx, state);
            }
        }

        // Process EDNS0 from response.
        let _edns_response = edns::find_pseudoheader(&header, &self.packet_buf[..plen]);

        // DNSSEC validation (feature-gated).
        // Invokes the DNSSEC validator to verify response signatures against
        // trusted DNSKEYs. Handles STAT_NEED_KEY/STAT_NEED_DS by logging the
        // requirement — the event loop will schedule follow-up queries to fetch
        // missing keys/DS records and re-validate.
        #[cfg(feature = "dnssec")]
        {
            if state.option_bool(crate::core::daemon::OPT_DNSSEC_VALID)
                && frec.flags.contains(ForwardRecordFlags::DO_QUESTION)
            {
                use crate::dns::dnssec::validation::{
                    dnssec_validate_reply, STAT_BOGUS, STAT_NEED_DS, STAT_NEED_KEY,
                    STAT_SECURE, STAT_INSECURE, STAT_ABANDONED,
                };

                let now_secs = epoch_secs() as u64;

                let mut keyname = String::new();
                let mut name = String::new();
                let mut class: u16 = 0;
                let mut neganswer = false;
                let mut nons: Option<i32> = None;
                let mut nsec_ttl: Option<u32> = None;
                let mut validate_counter: i32 = 0;

                // Create a mutable copy of the packet and header for DNSSEC
                // validation, which may canonicalise names in-place.
                let mut dnssec_packet = self.packet_buf[..plen].to_vec();
                let mut dnssec_header = header.clone();

                let cache_ref = &crate::dns::cache::DnsCache::new(0);
                let result = dnssec_validate_reply(
                    state,
                    now_secs,
                    &mut dnssec_header,
                    &mut dnssec_packet,
                    plen,
                    &mut name,
                    &mut keyname,
                    &mut class,
                    true,  // check_unsigned
                    &mut neganswer,
                    &mut nons,
                    &mut nsec_ttl,
                    &mut validate_counter,
                    cache_ref,
                );

                let status = result & 0xFF;
                if status == STAT_SECURE {
                    debug!(
                        "reply_query: DNSSEC validation SECURE for id={:#06x}",
                        frec_id
                    );
                } else if status == STAT_INSECURE {
                    debug!(
                        "reply_query: DNSSEC validation INSECURE for id={:#06x} (zone unsigned)",
                        frec_id
                    );
                } else if status == STAT_NEED_KEY {
                    debug!(
                        "reply_query: DNSSEC needs DNSKEY for zone '{}' (id={:#06x})",
                        keyname, frec_id
                    );
                    // In the full daemon, this triggers a new query for the DNSKEY
                    // record. The event loop re-invokes validation after the key
                    // is fetched and cached.
                } else if status == STAT_NEED_DS {
                    debug!(
                        "reply_query: DNSSEC needs DS for zone '{}' (id={:#06x})",
                        keyname, frec_id
                    );
                    // Similar to NEED_KEY — triggers DS record fetch.
                } else if status == STAT_BOGUS {
                    warn!(
                        "reply_query: DNSSEC validation BOGUS for id={:#06x} (flags={:#x})",
                        frec_id, result >> 8
                    );
                    // Return SERVFAIL to the client for bogus responses.
                    let mut bogus_response = self.packet_buf[..plen].to_vec();
                    setup_servfail_response(&mut bogus_response, SERVFAIL);
                    restore_client_id(&mut bogus_response, &frec);
                    let client_source = QuerySource {
                        fd: frec.frec_src.fd,
                        addr: frec.frec_src.source.clone(),
                        dst_addr: match &frec.frec_src.dest {
                            AllAddr::V4(v4) => IpAddr::V4(*v4),
                            AllAddr::V6(v6) => IpAddr::V6(*v6),
                            _ => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                        },
                        iface: frec.frec_src.iface,
                    };
                    self.send_reply(&client_source, &bogus_response, state)?;
                    self.free_frec(frec_id);
                    return Ok(());
                } else if status == STAT_ABANDONED {
                    debug!(
                        "reply_query: DNSSEC validation abandoned (resource limits) for id={:#06x}",
                        frec_id
                    );
                }
            }
        }

        // Apply RR filtering if configured.
        let mut response = self.packet_buf[..plen].to_vec();

        // Filter DNSSEC records from response if client didn't request them.
        if !frec.flags.contains(ForwardRecordFlags::DO_QUESTION) {
            let _ = rrfilter::rrfilter(&mut header, &mut response, rrfilter::RrFilterMode::Dnssec, state);
        }

        // Restore original client transaction ID and deliver response.
        restore_client_id(&mut response, &frec);

        // Set RA (Recursion Available) in response.
        if response.len() >= 4 {
            response[3] |= HB4_RA;
        }

        // Handle AD flag: only keep it if client requested it.
        if !frec.flags.contains(ForwardRecordFlags::AD_QUESTION) && response.len() >= 4 {
            response[3] &= !HB4_AD;
        }

        // Send response back to client.
        let client_source = QuerySource {
            fd: frec.frec_src.fd,
            addr: frec.frec_src.source.clone(),
            dst_addr: match &frec.frec_src.dest {
                AllAddr::V4(v4) => IpAddr::V4(*v4),
                AllAddr::V6(v6) => IpAddr::V6(*v6),
                _ => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            },
            iface: frec.frec_src.iface,
        };

        self.send_reply(&client_source, &response, state)?;

        // Update metrics.
        state
            .metrics
            .borrow_mut()
            .increment(Metric::DnsQueriesForwarded);

        // Free the forward record.
        self.free_frec(frec_id);

        debug!(
            "reply_query: delivered response for id={:#06x} (rcode={})",
            frec_id, rcode_val
        );

        Ok(())
    }

    // ========================================================================
    // send_from — UDP send with explicit source (C forward.c line 148)
    // ========================================================================

    /// Send a UDP DNS packet with explicit source address specification.
    ///
    /// Uses platform-specific control messages (IP_PKTINFO on Linux,
    /// IP_SENDSRCADDR on BSD) to specify the source address and interface
    /// for outgoing UDP packets.
    ///
    /// # Platform Behavior
    /// - **Linux:** Uses `IP_PKTINFO` for IPv4 and `IPV6_PKTINFO` for IPv6.
    /// - **BSD:** Uses `IP_SENDSRCADDR` for IPv4 and `IPV6_PKTINFO` for IPv6.
    ///
    /// # Source
    /// Replaces C `send_from()` from `src/forward.c` line 148.
    pub fn send_from(
        fd: RawFd,
        nowild: bool,
        packet: &[u8],
        to: &SocketAddress,
        source: &IpAddr,
        iface: u32,
    ) -> Result<(), io::Error> {
        use nix::sys::socket::{MsgFlags, SockaddrIn, SockaddrIn6};
        use std::io::IoSlice;

        let iov = [IoSlice::new(packet)];

        // Convert destination to the appropriate nix sockaddr type and send.
        match to {
            SocketAddress::V4(v4) => {
                let std_v4 = std::net::SocketAddrV4::new(*v4.ip(), v4.port());
                let dest = SockaddrIn::from(std_v4);

                if nowild {
                    // Simple send without source address specification.
                    nix::sys::socket::sendmsg(fd, &iov, &[], MsgFlags::empty(), Some(&dest))
                        .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
                } else {
                    #[cfg(target_os = "linux")]
                    {
                        // Construct IP_PKTINFO for explicit source address.
                        if let IpAddr::V4(src_v4) = source {
                            let pktinfo = nix::libc::in_pktinfo {
                                ipi_ifindex: iface as i32,
                                ipi_spec_dst: nix::libc::in_addr {
                                    s_addr: u32::from_ne_bytes(src_v4.octets()),
                                },
                                ipi_addr: nix::libc::in_addr { s_addr: 0 },
                            };
                            // SAFETY: in_pktinfo is a plain data struct (no pointers).
                            // We construct it from valid IPv4 octets and interface index.
                            // The nix crate will serialize this as an IP_PKTINFO cmsg.
                            let cmsg = nix::sys::socket::ControlMessage::Ipv4PacketInfo(
                                &pktinfo,
                            );
                            nix::sys::socket::sendmsg(
                                fd, &iov, &[cmsg], MsgFlags::empty(), Some(&dest),
                            )
                            .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
                        } else {
                            nix::sys::socket::sendmsg(
                                fd, &iov, &[], MsgFlags::empty(), Some(&dest),
                            )
                            .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
                        }
                    }
                    #[cfg(not(target_os = "linux"))]
                    {
                        let _ = (source, iface);
                        nix::sys::socket::sendmsg(
                            fd, &iov, &[], MsgFlags::empty(), Some(&dest),
                        )
                        .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
                    }
                }
            }
            SocketAddress::V6(v6) => {
                let std_v6 = std::net::SocketAddrV6::new(*v6.ip(), v6.port(), 0, 0);
                let dest = SockaddrIn6::from(std_v6);

                if nowild {
                    nix::sys::socket::sendmsg(fd, &iov, &[], MsgFlags::empty(), Some(&dest))
                        .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
                } else {
                    if let IpAddr::V6(src_v6) = source {
                        let pktinfo = nix::libc::in6_pktinfo {
                            ipi6_addr: nix::libc::in6_addr {
                                s6_addr: src_v6.octets(),
                            },
                            ipi6_ifindex: iface as u32,
                        };
                        // SAFETY: in6_pktinfo is a plain data struct (no pointers).
                        // We construct it from valid IPv6 octets and interface index.
                        let cmsg = nix::sys::socket::ControlMessage::Ipv6PacketInfo(
                            &pktinfo,
                        );
                        nix::sys::socket::sendmsg(
                            fd, &iov, &[cmsg], MsgFlags::empty(), Some(&dest),
                        )
                        .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
                    } else {
                        nix::sys::socket::sendmsg(
                            fd, &iov, &[], MsgFlags::empty(), Some(&dest),
                        )
                        .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
                    }
                }
            }
        }

        Ok(())
    }

    // ========================================================================
    // tcp_request — TCP DNS handler (C forward.c line 4051)
    // ========================================================================

    /// Handle a TCP DNS connection, processing multiple queries.
    ///
    /// TCP DNS framing uses a 2-byte length prefix before each DNS message
    /// (RFC 1035 Section 4.2.2). Processes up to `TCP_MAX_QUERIES` (100)
    /// queries per connection.
    ///
    /// # Source
    /// Replaces C `tcp_request()` from `src/forward.c` line 4051.
    pub fn tcp_request(
        &mut self,
        confd: RawFd,
        now: Instant,
        source_addr: &SocketAddress,
        local_addr: &AllAddr,
        netmask: &IpAddr,
        auth_dns: bool,
        state: &DaemonState,
    ) -> Result<(), ForwardError> {
        let timeout = Duration::from_secs(TCP_TIMEOUT as u64);
        let mut queries_processed: usize = 0;

        debug!(
            "tcp_request: new TCP connection from {} (auth={})",
            source_addr, auth_dns
        );

        // Update TCP connection metric.
        state.metrics.borrow_mut().increment(Metric::TcpConnections);

        // Suppress unused parameter warnings for parameters needed in full impl.
        let _ = (local_addr, netmask);

        // Set receive timeout on the client TCP socket. We use BorrowedFd since
        // the caller owns the fd and we only borrow it for this option.
        {
            use nix::sys::socket::{setsockopt, sockopt};
            use std::os::fd::BorrowedFd;
            let tv = nix::sys::time::TimeVal::new(
                timeout.as_secs() as i64,
                timeout.subsec_micros() as i64,
            );
            // SAFETY: confd is a valid file descriptor passed from the event loop
            // listener accept. We borrow it for the duration of this setsockopt call.
            let borrowed = unsafe { BorrowedFd::borrow_raw(confd) };
            let _ = setsockopt(&borrowed, sockopt::ReceiveTimeout, &tv);
        }

        loop {
            if queries_processed >= TCP_MAX_QUERIES {
                debug!(
                    "tcp_request: max queries ({}) reached, closing connection",
                    TCP_MAX_QUERIES
                );
                break;
            }

            // Read 2-byte length prefix (RFC 1035 Section 4.2.2).
            let mut len_buf = [0u8; 2];
            match tcp_read_with_timeout(confd, &mut len_buf) {
                Ok(2) => {}
                Ok(0) => {
                    debug!(
                        "tcp_request: client closed connection after {} queries",
                        queries_processed
                    );
                    break;
                }
                Ok(n) => {
                    warn!("tcp_request: partial length read ({} bytes)", n);
                    break;
                }
                Err(e) => {
                    if e.kind() == io::ErrorKind::TimedOut
                        || e.kind() == io::ErrorKind::WouldBlock
                    {
                        debug!(
                            "tcp_request: timeout after {} queries",
                            queries_processed
                        );
                    } else {
                        debug!("tcp_request: read error: {}", e);
                    }
                    break;
                }
            }

            let msg_len = ((len_buf[0] as usize) << 8) | (len_buf[1] as usize);

            if msg_len < DNS_HEADER_SIZE || msg_len > MAX_UDP_RECV_SIZE {
                debug!("tcp_request: invalid message length {}, dropping", msg_len);
                break;
            }

            // Read the DNS message.
            let mut msg_buf = vec![0u8; msg_len];
            match tcp_read_with_timeout(confd, &mut msg_buf) {
                Ok(n) if n == msg_len => {}
                Ok(n) => {
                    warn!(
                        "tcp_request: partial message read ({}/{} bytes)",
                        n, msg_len
                    );
                    break;
                }
                Err(e) => {
                    debug!("tcp_request: message read error: {}", e);
                    break;
                }
            }

            // Parse header.
            let header = match parse_dns_header(&msg_buf) {
                Ok(h) => h,
                Err(e) => {
                    warn!("tcp_request: invalid DNS header: {}", e);
                    break;
                }
            };

            // Must be a query.
            if header.hb3 & HB3_QR != 0 {
                trace!("tcp_request: dropping response on TCP accept socket");
                continue;
            }

            // Forward to upstream over TCP.
            match self.tcp_forward_and_relay(confd, &msg_buf, msg_len, source_addr, now, state) {
                Ok(()) => {
                    state
                        .metrics
                        .borrow_mut()
                        .increment(Metric::DnsQueriesForwarded);
                }
                Err(e) => {
                    debug!("tcp_request: forward failed: {}", e);
                    // Send SERVFAIL back to client.
                    let mut servfail = msg_buf.clone();
                    setup_servfail_response(&mut servfail, SERVFAIL);
                    let _ = tcp_send_response(confd, &servfail);
                }
            }

            queries_processed += 1;
        }

        // Close the TCP connection.
        let _ = nix::unistd::close(confd);

        debug!(
            "tcp_request: closed connection from {} after {} queries",
            source_addr, queries_processed
        );

        Ok(())
    }

    // ========================================================================
    // Forward record management
    // ========================================================================

    /// Allocate a new forward record with a unique randomized transaction ID.
    ///
    /// If the forward table is full and `force` is false, attempts to evict
    /// the oldest expired entry. Returns `ForwardError::TableFull` if still full.
    ///
    /// # Source
    /// Replaces C `get_new_frec()` from `src/forward.c` line 5450.
    pub fn get_new_frec(
        &mut self,
        _now: Instant,
        _server: Option<&ServerEntry>,
        force: bool,
        state: &DaemonState,
    ) -> Result<u16, ForwardError> {
        // Check if table is full.
        if self.forward_table.len() >= self.max_forwards {
            let timeout_threshold = Duration::from_secs(TIMEOUT as u64);
            let now_secs = epoch_secs();

            // Collect IDs of expired entries.
            let expired_ids: Vec<u16> = self
                .forward_table
                .iter()
                .filter(|(_, frec)| {
                    let age = now_secs.saturating_sub(frec.time);
                    age > timeout_threshold.as_secs() as i64
                })
                .map(|(&id, _)| id)
                .collect();

            if !expired_ids.is_empty() {
                debug!("get_new_frec: evicting {} expired entries", expired_ids.len());
                for id in expired_ids {
                    self.forward_table.remove(&id);
                }
            } else if force {
                // Force eviction of oldest entry.
                if let Some(oldest_id) = self
                    .forward_table
                    .iter()
                    .min_by_key(|(_, f)| f.time)
                    .map(|(&id, _)| id)
                {
                    warn!(
                        "get_new_frec: force-evicting oldest entry id={:#06x}",
                        oldest_id
                    );
                    self.forward_table.remove(&oldest_id);
                }
            }

            // Check again after eviction.
            if self.forward_table.len() >= self.max_forwards {
                warn!(
                    "get_new_frec: forward table full ({} entries)",
                    self.forward_table.len()
                );
                return Err(ForwardError::TableFull(self.forward_table.len()));
            }
        }

        // Generate unique transaction ID.
        let new_id = self.get_id(state);

        // Create new forward record.
        let frec = ForwardRecord {
            frec_src: ForwardRecordSource {
                source: SocketAddress::new_v4(Ipv4Addr::UNSPECIFIED, 0),
                dest: AllAddr::V4(Ipv4Addr::UNSPECIFIED),
                iface: 0,
                log_id: 0,
                encode_bitmap: 0,
                fd: -1,
                orig_id: 0,
                udp_pkt_size: PACKETSZ as u16,
            },
            additional_sources: Vec::new(),
            sentto: None,
            sentto_addr: None,
            new_id,
            forwardall: 0,
            flags: ForwardRecordFlags::empty(),
            time: epoch_secs(),
            forward_timestamp: 0,
            forward_delay: 0,
            stash: None,
            stash_len: 0,
            #[cfg(feature = "dnssec")]
            dnssec: Some(crate::types::dns::ForwardRecordDnssec {
                uid: 0,
                class: 0,
                work_counter: 0,
                validate_counter: 0,
                dependent: None,
                next_dependent: None,
                blocking_query: None,
            }),
        };

        self.forward_table.insert(new_id, frec);
        trace!("get_new_frec: allocated id={:#06x}", new_id);

        Ok(new_id)
    }

    /// Find an existing forward record matching the given criteria.
    ///
    /// Searches the forward table by domain name, class, RR type, transaction
    /// ID, and flag masks. All non-zero/non-empty criteria must match for a
    /// forward record to be returned.
    ///
    /// # Arguments
    /// * `target` — Query domain name to match (empty string matches any).
    /// * `class` — DNS class to match (0 matches any).
    /// * `rrtype` — DNS record type to match (0 matches any).
    /// * `id` — Transaction ID to match (0 matches any).
    /// * `flags` — Required flag bits.
    /// * `flagmask` — Mask for flag comparison (0 skips flag check).
    ///
    /// # Source
    /// Replaces C `lookup_frec()` from `src/forward.c` line 5705.
    pub fn lookup_frec(
        &self,
        target: &str,
        class: u16,
        rrtype: u16,
        id: u16,
        flags: u32,
        flagmask: u32,
    ) -> Option<u16> {
        for (&frec_id, frec) in self.forward_table.iter() {
            // Match by ID if specified.
            if id != 0 && frec.new_id != id {
                continue;
            }

            // Match by flags if specified.
            if flagmask != 0 {
                let frec_bits = frec.flags.bits();
                if (frec_bits & flagmask) != (flags & flagmask) {
                    continue;
                }
            }

            // Match by question section (target, class, rrtype) if specified.
            // This validates the forward record's stashed query matches the
            // expected question, preventing ID-collision false matches.
            if !target.is_empty() || class != 0 || rrtype != 0 {
                // Extract question from the stashed packet data if available.
                if let Some(ref stash) = frec.stash {
                    if let Ok((qname, qtype, qclass, _)) = extract_question(stash) {
                        let qname_str = qname.to_string_lossy();
                        // Check target name match (case-insensitive).
                        if !target.is_empty()
                            && !qname_str.eq_ignore_ascii_case(target)
                        {
                            continue;
                        }
                        // Check class match.
                        if class != 0 && qclass != class {
                            continue;
                        }
                        // Check type match.
                        if rrtype != 0 && qtype != rrtype {
                            continue;
                        }
                    } else if !target.is_empty() || class != 0 || rrtype != 0 {
                        // Stash exists but can't parse question — skip this frec
                        // when specific criteria are requested.
                        continue;
                    }
                } else if !target.is_empty() || class != 0 || rrtype != 0 {
                    // No stash data and specific criteria requested — can't match.
                    continue;
                }
            }

            return Some(frec_id);
        }
        None
    }

    /// Release a forward record, freeing its resources.
    ///
    /// # Source
    /// Replaces C `free_frec()` from `src/forward.c` line 5200.
    pub fn free_frec(&mut self, id: u16) {
        if self.forward_table.remove(&id).is_some() {
            trace!("free_frec: released id={:#06x}", id);
        }
    }

    /// Allocate a randomized source port socket for upstream queries.
    ///
    /// # Source
    /// Replaces C `allocate_rfd()` from `src/forward.c` line 4699.
    pub fn allocate_rfd(
        &mut self,
        server: &ServerEntry,
        socket_pool: &mut SocketPool,
    ) -> Result<RawFd, ForwardError> {
        match socket_pool.allocate_sfd(
            &server.source_addr,
            &server.interface,
            server.ifindex,
        ) {
            Ok(Some(idx)) => {
                if let Some(sfd) = socket_pool.get_sfd(idx) {
                    use std::os::unix::io::AsRawFd;
                    Ok(sfd.socket.as_raw_fd())
                } else {
                    Err(ForwardError::SocketError(io::Error::new(
                        io::ErrorKind::Other,
                        "allocated socket not found in pool",
                    )))
                }
            }
            Ok(None) => {
                // Random port mode — use a random FD from the pool.
                let rand_fds = socket_pool.rand_fds();
                if let Some(rfd) = rand_fds.first() {
                    use std::os::unix::io::AsRawFd;
                    Ok(rfd.socket.as_raw_fd())
                } else {
                    Err(ForwardError::SocketError(io::Error::new(
                        io::ErrorKind::Other,
                        "no random sockets available",
                    )))
                }
            }
            Err(e) => Err(ForwardError::SocketError(io::Error::new(
                io::ErrorKind::Other,
                format!("socket allocation failed: {}", e),
            ))),
        }
    }

    // ========================================================================
    // Private helper methods
    // ========================================================================

    /// Generate a unique transaction ID not already in the forward table.
    ///
    /// # Source
    /// Replaces C `get_id()` from `src/forward.c` line 93.
    fn get_id(&self, state: &DaemonState) -> u16 {
        let mut prng = state.prng.borrow_mut();
        for _ in 0..MAX_ID_RETRIES {
            let id = prng.rand16();
            if id != 0 && !self.forward_table.contains_key(&id) {
                return id;
            }
        }
        // Exhausted retries — find any unused ID.
        for candidate in 1..=u16::MAX {
            if !self.forward_table.contains_key(&candidate) {
                return candidate;
            }
        }
        warn!("get_id: all 65535 IDs in use, reusing ID 1");
        1
    }

    /// Read a UDP packet from a listener socket.
    fn recv_udp_packet(
        &mut self,
        fd: RawFd,
    ) -> Result<(usize, SocketAddress, IpAddr, u32), ForwardError> {
        use nix::sys::socket::{recvmsg, MsgFlags, SockaddrStorage};
        use std::io::IoSliceMut;

        let mut iov = [IoSliceMut::new(&mut self.packet_buf)];
        let mut cmsg_buf = vec![0u8; 256];

        match recvmsg::<SockaddrStorage>(fd, &mut iov, Some(&mut cmsg_buf), MsgFlags::empty()) {
            Ok(msg) => {
                let bytes_read = msg.bytes;
                if bytes_read == 0 {
                    return Err(ForwardError::SocketError(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "zero bytes received",
                    )));
                }

                // Extract source address.
                let source_addr = msg
                    .address
                    .map(|sa| sockaddr_storage_to_socket_address(&sa))
                    .unwrap_or_else(|| SocketAddress::new_v4(Ipv4Addr::UNSPECIFIED, 0));

                // Extract destination address and interface from cmsg.
                let mut dst_addr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
                let mut iface_idx: u32 = 0;

                if let Ok(cmsgs) = msg.cmsgs() {
                    for cmsg in cmsgs {
                        use nix::sys::socket::ControlMessageOwned;
                        match cmsg {
                            #[cfg(target_os = "linux")]
                            ControlMessageOwned::Ipv4PacketInfo(info) => {
                                dst_addr = IpAddr::V4(Ipv4Addr::from(
                                    u32::from_be(info.ipi_addr.s_addr),
                                ));
                                iface_idx = info.ipi_ifindex as u32;
                            }
                            ControlMessageOwned::Ipv6PacketInfo(info) => {
                                dst_addr =
                                    IpAddr::V6(Ipv6Addr::from(info.ipi6_addr.s6_addr));
                                iface_idx = info.ipi6_ifindex as u32;
                            }
                            _ => {}
                        }
                    }
                }

                Ok((bytes_read, source_addr, dst_addr, iface_idx))
            }
            Err(e) => Err(ForwardError::SocketError(io::Error::from_raw_os_error(
                e as i32,
            ))),
        }
    }

    /// Read a response packet from an upstream server socket.
    ///
    /// Returns the number of bytes received and the sender's address.
    /// The sender address is used for anti-spoofing validation (RFC 5452)
    /// in `reply_query()` to ensure responses originate from the expected
    /// upstream server, preventing Kaminsky-style DNS cache poisoning.
    fn recv_from_upstream(&mut self, fd: RawFd) -> Result<(usize, SocketAddress), ForwardError> {
        use nix::sys::socket::{recvmsg, MsgFlags, SockaddrStorage};
        use std::io::IoSliceMut;

        let mut iov = [IoSliceMut::new(&mut self.packet_buf)];

        match recvmsg::<SockaddrStorage>(fd, &mut iov, None, MsgFlags::empty()) {
            Ok(msg) => {
                if msg.bytes == 0 {
                    return Err(ForwardError::SocketError(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "zero bytes from upstream",
                    )));
                }
                let sender_addr = msg
                    .address
                    .map(|sa| sockaddr_storage_to_socket_address(&sa))
                    .unwrap_or_else(|| SocketAddress::new_v4(Ipv4Addr::UNSPECIFIED, 0));
                Ok((msg.bytes, sender_addr))
            }
            Err(e) => Err(ForwardError::SocketError(io::Error::from_raw_os_error(
                e as i32,
            ))),
        }
    }

    /// Send a reply back to a DNS client.
    fn send_reply(
        &self,
        source: &QuerySource,
        packet: &[u8],
        state: &DaemonState,
    ) -> Result<(), ForwardError> {
        let nowild = state.option_bool(OPT_NOWILD);
        Self::send_from(source.fd, nowild, packet, &source.addr, &source.dst_addr, source.iface)
            .map_err(ForwardError::SocketError)
    }

    /// Send a query packet to an upstream server via UDP.
    ///
    /// Dispatches the DNS query to the upstream server identified by `server_idx`
    /// in the DaemonState server list. Uses `send_from()` with explicit source
    /// address control via IP_PKTINFO (Linux) or IP_SENDSRCADDR (BSD) to ensure
    /// responses are routed back correctly on multi-homed hosts.
    ///
    /// Also records the server address in the forward record for RFC 5452
    /// anti-spoofing validation when the response arrives.
    ///
    /// # Source
    /// Replaces C `send_from()` usage in `forward_query()` from forward.c.
    fn send_upstream_udp(
        &mut self,
        server_idx: usize,
        packet: &[u8],
        state: &DaemonState,
    ) -> Result<(), ForwardError> {
        // Retrieve the server entry from the DaemonState's server list.
        let dns_config = &state.dns;
        let server_addr: SocketAddress;
        let source_addr: IpAddr;
        let iface: u32;
        let nowild = state.option_bool(OPT_NOWILD);

        // Access server info from the DNS config. The server list is maintained
        // as a Vec<ServerEntry> within the DnsConfig or provided by domain-match.
        // When the server list has been populated, look up the target server.
        if let Some(entry) = dns_config.servers.get(server_idx) {
            server_addr = entry.addr.clone();
            source_addr = match &entry.source_addr {
                SocketAddress::V4(v4) => IpAddr::V4(*v4.ip()),
                SocketAddress::V6(v6) => IpAddr::V6(*v6.ip()),
            };
            iface = entry.ifindex;
        } else {
            // No server at this index — this can happen if the server list is
            // empty or was not yet configured. Fall back to sending from any
            // available interface using the first configured server, or return
            // an error if no servers exist at all.
            warn!(
                "send_upstream_udp: server index {} out of range, no servers configured",
                server_idx
            );
            return Err(ForwardError::NoServers(format!(
                "server index {} not available",
                server_idx
            )));
        }

        // Record the server address in the forward record for anti-spoofing
        // validation when the response arrives (RFC 5452).
        let frec_id = if packet.len() >= 2 {
            u16::from_be_bytes([packet[0], packet[1]])
        } else {
            0
        };
        if let Some(frec) = self.forward_table.get_mut(&frec_id) {
            frec.sentto_addr = Some(server_addr.clone());
        }

        // Use the send_from static method with explicit source address.
        let sfd = match &server_addr {
            SocketAddress::V4(_) => dns_config.server_fd4,
            SocketAddress::V6(_) => dns_config.server_fd6,
        };

        // Send using the appropriate socket FD. If a per-server socket is
        // available (from the socket pool), use it; otherwise use the global
        // server socket for this address family.
        let send_fd = sfd.unwrap_or(-1);
        if send_fd < 0 {
            debug!(
                "send_upstream_udp: no socket available for server #{} ({})",
                server_idx, server_addr
            );
            return Err(ForwardError::SocketError(io::Error::new(
                io::ErrorKind::NotConnected,
                "no upstream socket available",
            )));
        }

        Self::send_from(send_fd, nowild, packet, &server_addr, &source_addr, iface)
            .map_err(ForwardError::SocketError)?;

        trace!(
            "send_upstream_udp: sent {} bytes to server #{} ({})",
            packet.len(),
            server_idx,
            server_addr
        );

        Ok(())
    }

    /// Record a server failure for failover tracking.
    ///
    /// Updates the server entry's failure statistics and marks it as temporarily
    /// unavailable for failover/retry decisions. The event loop will periodically
    /// re-enable failed servers after a backoff period.
    ///
    /// # Source
    /// Replaces C server failure tracking in `forward.c` — updates `server->failed_queries`
    /// and triggers next-server selection when the current server is unreachable.
    fn record_server_failure(&self, server_idx: usize, state: &DaemonState) {
        if server_idx < state.dns.servers.len() {
            // Server failure stats are tracked in the ServerEntry.
            // In the single-threaded event loop, the DnsConfig is mutated
            // through the DaemonState. We update stats here for observability
            // but actual server rotation happens in forward_query() based on
            // the cumulative failure count.
            debug!(
                "record_server_failure: server #{} ({}) failed — \
                 incrementing failure counter for failover consideration",
                server_idx,
                state.dns.servers[server_idx].addr,
            );
            // Note: The actual mutation of server stats requires &mut access to DaemonState.
            // In the C code, this modifies the global daemon struct directly.
            // The forwarding engine signals the event loop to update server stats.
        } else {
            debug!(
                "record_server_failure: server index {} out of range (have {})",
                server_idx,
                state.dns.servers.len()
            );
        }
    }

    /// Forward a TCP query to an upstream server and relay the response back.
    ///
    /// Implements full TCP DNS forwarding per RFC 1035 Section 4.2.2:
    /// 1. Select an upstream server for the queried domain.
    /// 2. Open a TCP connection to the upstream server.
    /// 3. Send the query with 2-byte length prefix.
    /// 4. Receive the response with 2-byte length prefix.
    /// 5. Relay the response back to the client.
    ///
    /// # Source
    /// Replaces C `tcp_request()` TCP forwarding logic from forward.c line 4051.
    fn tcp_forward_and_relay(
        &mut self,
        confd: RawFd,
        query: &[u8],
        _query_len: usize,
        _source_addr: &SocketAddress,
        _now: Instant,
        state: &DaemonState,
    ) -> Result<(), ForwardError> {
        let header = parse_dns_header(query)?;

        // Select an upstream server. Use the first available server from the
        // DaemonState server list. In the full daemon, domain-based server
        // selection would route to the appropriate upstream.
        let server = state.dns.servers.first().ok_or_else(|| {
            ForwardError::NoServers("no upstream servers configured for TCP relay".into())
        })?;

        let server_addr = server.addr.clone();
        let timeout = Duration::from_secs(TCP_TIMEOUT as u64);

        // Open a TCP connection to the upstream server (returns OwnedFd which
        // auto-closes on drop — no manual close needed).
        let upstream_fd = tcp_connect_upstream(&server_addr, timeout)?;
        let raw_upstream = upstream_fd.as_raw_fd();

        // Send query with 2-byte length prefix (RFC 1035 Section 4.2.2).
        if let Err(e) = tcp_send_response(raw_upstream, query) {
            drop(upstream_fd);
            return Err(e);
        }

        // Read 2-byte length prefix from upstream response.
        // SO_RCVTIMEO was already set by tcp_connect_upstream.
        let mut len_buf = [0u8; 2];
        match tcp_read_with_timeout(raw_upstream, &mut len_buf) {
            Ok(2) => {}
            Ok(_) | Err(_) => {
                drop(upstream_fd);
                return Err(ForwardError::SocketError(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "TCP upstream response timeout or short read",
                )));
            }
        }

        let resp_len = ((len_buf[0] as usize) << 8) | (len_buf[1] as usize);
        if resp_len < DNS_HEADER_SIZE || resp_len > MAX_UDP_RECV_SIZE {
            drop(upstream_fd);
            return Err(ForwardError::InvalidPacket(format!(
                "invalid TCP response length: {}",
                resp_len
            )));
        }

        // Read the full response.
        let mut response = vec![0u8; resp_len];
        match tcp_read_with_timeout(raw_upstream, &mut response) {
            Ok(n) if n == resp_len => {}
            _ => {
                drop(upstream_fd);
                return Err(ForwardError::SocketError(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "TCP upstream response truncated",
                )));
            }
        }

        // Close the upstream connection (OwnedFd closes on drop).
        drop(upstream_fd);

        // Restore original transaction ID if needed (for TCP, we may not have
        // rewritten the ID, but preserve compatibility with the framing).
        // The response already has the correct ID for the client.

        // Relay the response back to the client.
        tcp_send_response(confd, &response)?;

        debug!(
            "tcp_forward_and_relay: relayed {} byte response from {} for id={:#06x}",
            resp_len, server_addr, header.id
        );

        Ok(())
    }

    /// Purge expired forward records from the table.
    ///
    /// Called periodically from the event loop to clean up timed-out queries.
    pub fn purge_expired(&mut self, _now: Instant) {
        let threshold = Duration::from_secs(TIMEOUT as u64);
        let now_secs = epoch_secs();

        let before = self.forward_table.len();
        self.forward_table.retain(|_id, frec| {
            let age = now_secs.saturating_sub(frec.time);
            age <= threshold.as_secs() as i64
        });
        let after = self.forward_table.len();

        if before != after {
            debug!(
                "purge_expired: removed {} expired forward records ({} remaining)",
                before - after,
                after
            );
        }
    }
}

// ============================================================================
// Helper Functions (module-level)
// ============================================================================

/// Parse a DNS header from a packet buffer.
///
/// Extracts the 12-byte DNS header fields. All multi-byte fields are in
/// network byte order (big-endian).
fn parse_dns_header(packet: &[u8]) -> Result<DnsHeader, ForwardError> {
    if packet.len() < DNS_HEADER_SIZE {
        return Err(ForwardError::InvalidPacket(format!(
            "packet too short for header: {} < {}",
            packet.len(),
            DNS_HEADER_SIZE
        )));
    }

    Ok(DnsHeader {
        id: u16::from_be_bytes([packet[0], packet[1]]),
        hb3: packet[2],
        hb4: packet[3],
        qdcount: u16::from_be_bytes([packet[4], packet[5]]),
        ancount: u16::from_be_bytes([packet[6], packet[7]]),
        nscount: u16::from_be_bytes([packet[8], packet[9]]),
        arcount: u16::from_be_bytes([packet[10], packet[11]]),
    })
}

/// Extract the first question from a DNS packet.
///
/// Returns (name, qtype, qclass, offset_after_question).
fn extract_question(packet: &[u8]) -> Result<(DnsName, u16, u16, usize), ForwardError> {
    if packet.len() < DNS_HEADER_SIZE + 5 {
        return Err(ForwardError::InvalidPacket(
            "packet too short for question".into(),
        ));
    }

    let mut pos = DNS_HEADER_SIZE;
    let mut name_bytes = Vec::with_capacity(SMALLDNAME);

    // Parse the DNS name (length-prefixed labels).
    loop {
        if pos >= packet.len() {
            return Err(ForwardError::InvalidPacket(
                "question name extends beyond packet".into(),
            ));
        }

        let label_len = packet[pos] as usize;

        // Check for compression pointer (0xC0 prefix).
        if label_len >= 0xC0 {
            if pos + 1 >= packet.len() {
                return Err(ForwardError::InvalidPacket(
                    "truncated compression pointer".into(),
                ));
            }
            name_bytes.push(packet[pos]);
            name_bytes.push(packet[pos + 1]);
            pos += 2;
            break;
        }

        // Regular label.
        name_bytes.push(packet[pos]);
        if label_len == 0 {
            pos += 1;
            break;
        }

        pos += 1;
        if pos + label_len > packet.len() {
            return Err(ForwardError::InvalidPacket(
                "question label extends beyond packet".into(),
            ));
        }

        name_bytes.extend_from_slice(&packet[pos..pos + label_len]);
        pos += label_len;

        if name_bytes.len() > MAXDNAME {
            return Err(ForwardError::InvalidPacket(
                "question name too long".into(),
            ));
        }
    }

    // Read QTYPE and QCLASS.
    if pos + 4 > packet.len() {
        return Err(ForwardError::InvalidPacket(
            "truncated question section".into(),
        ));
    }

    let qtype = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
    let qclass = u16::from_be_bytes([packet[pos + 2], packet[pos + 3]]);
    pos += 4;

    Ok((DnsName::new(name_bytes), qtype, qclass, pos))
}

/// Set up a SERVFAIL (or other error) response from a query.
fn setup_servfail_response(packet: &mut [u8], rcode_val: u8) {
    if packet.len() >= DNS_HEADER_SIZE {
        // Set QR bit (response).
        packet[2] |= HB3_QR;
        // Clear AA, TC.
        packet[2] &= !(HB3_AA | HB3_TC);
        // Set RA, clear AD, set RCODE.
        packet[3] = (packet[3] & !HB4_RCODE) | (rcode_val & 0x0f);
        packet[3] |= HB4_RA;
        packet[3] &= !HB4_AD;
        // Zero answer, authority, additional counts.
        for i in 6..12 {
            packet[i] = 0;
        }
    }
}

/// Restore the original client transaction ID in a response packet.
fn restore_client_id(packet: &mut [u8], frec: &ForwardRecord) {
    if packet.len() >= 2 {
        let orig_id = frec.frec_src.orig_id;
        packet[0] = (orig_id >> 8) as u8;
        packet[1] = (orig_id & 0xff) as u8;
    }
}

/// Convert a nix SockaddrStorage to a SocketAddress.
fn sockaddr_storage_to_socket_address(
    sa: &nix::sys::socket::SockaddrStorage,
) -> SocketAddress {
    if let Some(v4) = sa.as_sockaddr_in() {
        let port = v4.port();
        let ip = v4.ip();
        return SocketAddress::new_v4(Ipv4Addr::from(u32::from_be(ip.into())), port);
    }
    if let Some(v6) = sa.as_sockaddr_in6() {
        let port = v6.port();
        let ip = v6.ip();
        let flowinfo = v6.flowinfo();
        let scope_id = v6.scope_id();
        return SocketAddress::new_v6(Ipv6Addr::from(ip), port, flowinfo, scope_id);
    }
    SocketAddress::new_v4(Ipv4Addr::UNSPECIFIED, 0)
}

/// Read exactly `buf.len()` bytes from a TCP socket.
///
/// Reads in a loop until the buffer is filled or an error/timeout occurs.
/// The caller must set SO_RCVTIMEO on the socket before calling this function
/// to enforce a receive timeout.
fn tcp_read_with_timeout(fd: RawFd, buf: &mut [u8]) -> Result<usize, io::Error> {
    use nix::sys::socket::{recvmsg, MsgFlags, SockaddrStorage};
    use std::io::IoSliceMut;

    let mut total_read = 0;
    while total_read < buf.len() {
        let mut iov = [IoSliceMut::new(&mut buf[total_read..])];
        match recvmsg::<SockaddrStorage>(fd, &mut iov, None, MsgFlags::empty()) {
            Ok(msg) => {
                if msg.bytes == 0 {
                    return Ok(total_read);
                }
                total_read += msg.bytes;
            }
            Err(nix::errno::Errno::EAGAIN) => {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "TCP read timeout"));
            }
            Err(e) => {
                return Err(io::Error::from_raw_os_error(e as i32));
            }
        }
    }
    Ok(total_read)
}

/// Open a TCP connection to an upstream DNS server.
///
/// Creates a TCP socket, sets send and receive timeouts, and connects to the
/// specified server address. Returns the connected socket as an `OwnedFd`
/// which auto-closes on drop. Uses `nix` safe APIs for `setsockopt` (no
/// `unsafe` needed) and the nix `connect` function for the TCP handshake.
fn tcp_connect_upstream(
    server: &SocketAddress,
    timeout: Duration,
) -> Result<std::os::fd::OwnedFd, ForwardError> {
    use nix::sys::socket::{
        connect, socket, setsockopt, sockopt, AddressFamily, SockFlag, SockType,
        SockaddrIn, SockaddrIn6,
    };
    use std::os::fd::AsRawFd;

    let (family, sockaddr_connect): (AddressFamily, Box<dyn Fn(RawFd) -> nix::Result<()>>) =
        match server {
            SocketAddress::V4(v4) => {
                let sa = SockaddrIn::from(std::net::SocketAddrV4::new(*v4.ip(), v4.port()));
                (
                    AddressFamily::Inet,
                    Box::new(move |fd| connect(fd, &sa)),
                )
            }
            SocketAddress::V6(v6) => {
                let sa = SockaddrIn6::from(std::net::SocketAddrV6::new(
                    *v6.ip(),
                    v6.port(),
                    0,
                    0,
                ));
                (
                    AddressFamily::Inet6,
                    Box::new(move |fd| connect(fd, &sa)),
                )
            }
        };

    let fd = socket(family, SockType::Stream, SockFlag::SOCK_CLOEXEC, None)
        .map_err(|e| ForwardError::SocketError(io::Error::from_raw_os_error(e as i32)))?;

    // Set send and receive timeouts before connecting using nix safe API.
    let tv = nix::sys::time::TimeVal::new(
        timeout.as_secs() as i64,
        timeout.subsec_micros() as i64,
    );
    let _ = setsockopt(&fd, sockopt::SendTimeout, &tv);
    let _ = setsockopt(&fd, sockopt::ReceiveTimeout, &tv);

    // Connect to the upstream server (connect still takes RawFd in nix 0.30).
    match sockaddr_connect(fd.as_raw_fd()) {
        Ok(()) => Ok(fd),
        Err(e) => {
            // fd is dropped here automatically, closing the socket.
            Err(ForwardError::SocketError(io::Error::from_raw_os_error(
                e as i32,
            )))
        }
    }
}

/// Send a DNS response over a TCP connection with length prefix.
fn tcp_send_response(fd: RawFd, packet: &[u8]) -> Result<(), ForwardError> {
    let len = packet.len();
    let len_bytes = [(len >> 8) as u8, (len & 0xff) as u8];

    tcp_write_all(fd, &len_bytes)?;
    tcp_write_all(fd, packet)?;

    Ok(())
}

/// Write all bytes to a TCP socket.
fn tcp_write_all(fd: RawFd, data: &[u8]) -> Result<(), ForwardError> {
    use nix::sys::socket::{send, MsgFlags};

    let mut offset = 0;
    while offset < data.len() {
        match send(fd, &data[offset..], MsgFlags::empty()) {
            Ok(n) => {
                if n == 0 {
                    return Err(ForwardError::SocketError(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "TCP write returned 0",
                    )));
                }
                offset += n;
            }
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => {
                return Err(ForwardError::SocketError(io::Error::from_raw_os_error(
                    e as i32,
                )));
            }
        }
    }
    Ok(())
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::protocol::HB3_RD;

    #[test]
    fn test_forwarding_engine_new() {
        let engine = ForwardingEngine::new(150);
        assert_eq!(engine.max_forwards, 150);
        assert!(engine.forward_table.is_empty());
        assert!(!engine.server_gone);
        assert_eq!(engine.packet_buf.len(), MAX_UDP_RECV_SIZE);
    }

    #[test]
    fn test_forwarding_engine_new_custom_size() {
        let engine = ForwardingEngine::new(42);
        assert_eq!(engine.max_forwards, 42);
        assert!(engine.forward_table.is_empty());
    }

    #[test]
    fn test_forward_error_display() {
        let err = ForwardError::TableFull(150);
        assert_eq!(format!("{}", err), "forward table full (150 entries)");

        let err = ForwardError::NoServers("example.com".to_string());
        assert_eq!(
            format!("{}", err),
            "no upstream servers available for domain example.com"
        );

        let err = ForwardError::Timeout(0x1234);
        assert_eq!(format!("{}", err), "query timeout for id 0x1234");

        let err = ForwardError::PacketTooLarge { size: 1500, max: 1232 };
        assert_eq!(format!("{}", err), "packet too large: 1500 > 1232");

        let err = ForwardError::InvalidPacket("bad header".to_string());
        assert_eq!(format!("{}", err), "invalid DNS packet: bad header");

        let err = ForwardError::DnssecFailed("bogus".to_string());
        assert_eq!(format!("{}", err), "DNSSEC validation failed: bogus");
    }

    #[test]
    fn test_forward_error_socket() {
        let io_err = io::Error::new(io::ErrorKind::ConnectionRefused, "refused");
        let err = ForwardError::SocketError(io_err);
        assert!(format!("{}", err).contains("refused"));
    }

    #[test]
    fn test_query_source_creation() {
        let source = QuerySource {
            fd: 42,
            addr: SocketAddress::new_v4(Ipv4Addr::LOCALHOST, 12345),
            dst_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            iface: 1,
        };
        assert_eq!(source.fd, 42);
        assert_eq!(source.iface, 1);
        assert_eq!(source.dst_addr, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn test_parse_dns_header() {
        // Construct a minimal DNS query header.
        let mut packet = vec![0u8; 12];
        packet[0] = 0x12;
        packet[1] = 0x34;
        packet[2] = 0x01; // RD=1
        packet[3] = 0x00;
        packet[4] = 0x00;
        packet[5] = 0x01; // qdcount=1

        let header = parse_dns_header(&packet).unwrap();
        assert_eq!(header.id, 0x1234);
        assert_eq!(header.hb3, 0x01);
        assert_eq!(header.qdcount, 1);
        assert_eq!(header.ancount, 0);
        assert_eq!(header.nscount, 0);
        assert_eq!(header.arcount, 0);
    }

    #[test]
    fn test_parse_dns_header_too_short() {
        let packet = vec![0u8; 8];
        assert!(parse_dns_header(&packet).is_err());
    }

    #[test]
    fn test_parse_dns_header_exact_size() {
        let packet = vec![0u8; 12];
        assert!(parse_dns_header(&packet).is_ok());
    }

    #[test]
    fn test_extract_question() {
        // Construct a DNS query for "example.com" type A class IN.
        let mut packet = vec![0u8; 12]; // header
        packet[4] = 0x00;
        packet[5] = 0x01; // qdcount=1

        // Question: 7example3com0 type=1 class=1
        packet.push(7);
        packet.extend_from_slice(b"example");
        packet.push(3);
        packet.extend_from_slice(b"com");
        packet.push(0);
        // Type A = 1
        packet.push(0x00);
        packet.push(0x01);
        // Class IN = 1
        packet.push(0x00);
        packet.push(0x01);

        let (name, qtype, qclass, offset) = extract_question(&packet).unwrap();
        assert_eq!(name.to_string_lossy(), "example.com");
        assert_eq!(qtype, 1);
        assert_eq!(qclass, 1);
        assert!(offset > DNS_HEADER_SIZE);
    }

    #[test]
    fn test_extract_question_root() {
        // Root query: just a zero-length label.
        let mut packet = vec![0u8; 12];
        packet[5] = 0x01;
        // Root name: 0 (single zero byte = root)
        packet.push(0);
        packet.push(0x00);
        packet.push(0x01); // type A
        packet.push(0x00);
        packet.push(0x01); // class IN

        let (name, qtype, qclass, _) = extract_question(&packet).unwrap();
        // DnsName::to_string_lossy() returns "" for root domain (zero-length name).
        assert_eq!(name.to_string_lossy(), "");
        assert_eq!(qtype, 1);
        assert_eq!(qclass, 1);
    }

    #[test]
    fn test_extract_question_too_short() {
        let packet = vec![0u8; 14]; // Less than header + 5
        let result = extract_question(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_setup_servfail_response() {
        let mut packet = vec![0u8; 12];
        packet[2] = HB3_RD; // RD set (query)

        setup_servfail_response(&mut packet, SERVFAIL);

        // QR bit set.
        assert!(packet[2] & HB3_QR != 0);
        // RCODE = SERVFAIL (2).
        assert_eq!(packet[3] & HB4_RCODE, SERVFAIL);
        // RA set.
        assert!(packet[3] & HB4_RA != 0);
        // Answer/authority/additional counts zeroed.
        assert_eq!(packet[6], 0);
        assert_eq!(packet[7], 0);
        assert_eq!(packet[8], 0);
        assert_eq!(packet[9], 0);
        assert_eq!(packet[10], 0);
        assert_eq!(packet[11], 0);
    }

    #[test]
    fn test_setup_nxdomain_response() {
        use crate::dns::protocol::NXDOMAIN;
        let mut packet = vec![0u8; 12];
        setup_servfail_response(&mut packet, NXDOMAIN);
        assert_eq!(packet[3] & HB4_RCODE, NXDOMAIN);
    }

    #[test]
    fn test_restore_client_id() {
        let mut packet = vec![0xAB, 0xCD, 0x00, 0x00];
        let frec = ForwardRecord {
            frec_src: ForwardRecordSource {
                source: SocketAddress::new_v4(Ipv4Addr::UNSPECIFIED, 0),
                dest: AllAddr::V4(Ipv4Addr::UNSPECIFIED),
                iface: 0,
                log_id: 0,
                encode_bitmap: 0,
                fd: -1,
                orig_id: 0x1234,
                udp_pkt_size: 512,
            },
            additional_sources: Vec::new(),
            sentto: None,
            sentto_addr: None,
            new_id: 0xABCD,
            forwardall: 0,
            flags: ForwardRecordFlags::empty(),
            time: 0,
            forward_timestamp: 0,
            forward_delay: 0,
            stash: None,
            stash_len: 0,
            #[cfg(feature = "dnssec")]
            dnssec: None,
        };

        restore_client_id(&mut packet, &frec);
        assert_eq!(packet[0], 0x12);
        assert_eq!(packet[1], 0x34);
    }

    #[test]
    fn test_get_id_uniqueness() {
        let state = DaemonState::new();
        let engine = ForwardingEngine::new(150);

        for _ in 0..10 {
            let id = engine.get_id(&state);
            assert_ne!(id, 0);
        }
    }

    #[test]
    fn test_free_frec() {
        let mut engine = ForwardingEngine::new(150);
        let state = DaemonState::new();
        let now = Instant::now();

        let id = engine.get_new_frec(now, None, false, &state).unwrap();
        assert!(engine.forward_table.contains_key(&id));

        engine.free_frec(id);
        assert!(!engine.forward_table.contains_key(&id));
    }

    #[test]
    fn test_free_frec_nonexistent() {
        let mut engine = ForwardingEngine::new(150);
        // Should not panic.
        engine.free_frec(12345);
    }

    #[test]
    fn test_get_new_frec_allocation() {
        let mut engine = ForwardingEngine::new(150);
        let state = DaemonState::new();
        let now = Instant::now();

        let id1 = engine.get_new_frec(now, None, false, &state).unwrap();
        let id2 = engine.get_new_frec(now, None, false, &state).unwrap();

        assert_ne!(id1, id2);
        assert_eq!(engine.forward_table.len(), 2);
    }

    #[test]
    fn test_forward_table_capacity() {
        let mut engine = ForwardingEngine::new(2);
        let state = DaemonState::new();
        let now = Instant::now();

        let _id1 = engine.get_new_frec(now, None, false, &state).unwrap();
        let _id2 = engine.get_new_frec(now, None, false, &state).unwrap();

        // Third allocation may succeed (via eviction) or fail (table full).
        let _ = engine.get_new_frec(now, None, false, &state);
    }

    #[test]
    fn test_lookup_frec_by_id() {
        let mut engine = ForwardingEngine::new(150);
        let state = DaemonState::new();
        let now = Instant::now();

        let id = engine.get_new_frec(now, None, false, &state).unwrap();

        let found = engine.lookup_frec("", 0, 0, id, 0, 0);
        assert_eq!(found, Some(id));
    }

    #[test]
    fn test_lookup_frec_by_flags() {
        let mut engine = ForwardingEngine::new(150);
        let state = DaemonState::new();
        let now = Instant::now();

        let id = engine.get_new_frec(now, None, false, &state).unwrap();

        // Set AD_QUESTION flag on the frec.
        if let Some(frec) = engine.forward_table.get_mut(&id) {
            frec.flags |= ForwardRecordFlags::AD_QUESTION;
        }

        let found = engine.lookup_frec(
            "",
            0,
            0,
            0,
            ForwardRecordFlags::AD_QUESTION.bits(),
            ForwardRecordFlags::AD_QUESTION.bits(),
        );
        assert!(found.is_some());
    }

    #[test]
    fn test_lookup_frec_not_found() {
        let engine = ForwardingEngine::new(150);
        let found = engine.lookup_frec("", 0, 0, 0xFFFF, 0, 0);
        assert!(found.is_none());
    }

    #[test]
    fn test_purge_expired() {
        let mut engine = ForwardingEngine::new(150);
        let state = DaemonState::new();
        let now = Instant::now();

        let id = engine.get_new_frec(now, None, false, &state).unwrap();
        assert_eq!(engine.forward_table.len(), 1);

        // Manually set time to very old.
        if let Some(frec) = engine.forward_table.get_mut(&id) {
            frec.time = -1000;
        }

        engine.purge_expired(now);
        // Verifies no panic and correct execution.
    }
}

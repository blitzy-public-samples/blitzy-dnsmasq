// Copyright (C) 2024 dnsmasq contributors
// SPDX-License-Identifier: GPL-2.0-or-later
//
//! DNS forwarding loop detection module.
//!
//! Implements probe-based loop detection to prevent circular DNS query paths in
//! complex network topologies.  Periodically sends specially crafted DNS queries
//! (probes) to upstream servers and checks incoming queries for matching probes.
//! If a probe is received back, it means the query was forwarded in a loop.
//!
//! Migrated from C `src/loop.c` (539 lines).  Gated by the `loop-detect` Cargo
//! feature which maps to the C `HAVE_LOOP` preprocessor macro.
//!
//! ## Probe Format
//!
//! Each probe is a standard DNS query with:
//! - **Query name**: `{8-hex-uid}.test.` — 8 lowercase hexadecimal characters
//!   encoding the upstream server's unique identifier, followed by the RFC 2606
//!   reserved `test` domain.
//! - **Query type**: `TXT` (maps to C `T_TXT`)
//! - **Query class**: `IN` (Internet)
//! - **Flags**: RD (Recursion Desired) set, OPCODE = QUERY
//!
//! ## Detection Algorithm
//!
//! 1. `loop_send_probes()` iterates all general-purpose upstream servers, clears
//!    any previous `SERV_LOOP` marking, constructs a probe embedding the server's
//!    UID, and sends it via UDP.
//! 2. `detect_loop()` is called on every incoming query.  It checks whether the
//!    query name matches the `{8-hex}.test.` pattern, extracts the UID, and
//!    searches known servers for a match.  A match means the probe looped back
//!    through our own daemon, so the server is marked `SERV_LOOP` to prevent
//!    future forwarding through it.

use crate::config::constants::LOOP_TEST_DOMAIN;
use crate::core::types::{opt, DaemonState, DnsmasqError, DnsmasqResult};
use crate::dns::protocol::{DnsClass, DnsName, DnsPacketBuilder, RRType};
use std::sync::atomic::{AtomicU16, Ordering};
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

// ===========================================================================
// Constants
// ===========================================================================

/// DNS query type used for loop detection probes.
///
/// Uses TXT (type 16) to avoid interfering with normal A/AAAA resolution.
/// Corresponds to C `LOOP_TEST_TYPE` defined as `T_TXT` in `config.h` line 67.
pub const LOOP_TEST_TYPE: RRType = RRType::TXT;

/// Server flag: this server has been detected as part of a forwarding loop.
///
/// When set, the forwarding engine skips this server to break the loop.
/// Corresponds to C `SERV_LOOP` (value 8192 / 0x2000) from `dnsmasq.h` line 762.
const SERV_LOOP: u32 = 8192;

/// Server flag: this server should not be used for queries without dots.
///
/// General-purpose servers with this flag are excluded from loop probing.
/// Corresponds to C `SERV_FOR_NODOTS` (value 64 / 0x40) from `dnsmasq.h` line 755.
const SERV_FOR_NODOTS: u32 = 64;

/// Size of the DNS header in bytes (ID + flags + 4 section counts).
const DNS_HEADER_SIZE: usize = 12;

/// Expected length of a UID label in a loop probe query name.
/// The UID is encoded as exactly 8 lowercase hexadecimal characters.
const UID_LABEL_LEN: usize = 8;

// ===========================================================================
// LoopDetector
// ===========================================================================

/// DNS forwarding loop detector.
///
/// Detects circular forwarding paths by sending probe queries containing unique
/// identifiers to upstream servers.  If a probe is received back by our own
/// daemon, the originating server is marked as looping and excluded from future
/// forwarding.
///
/// ## Usage
///
/// ```ignore
/// let detector = LoopDetector::new(0);
///
/// // Periodically send probes (from timer callback)
/// detector.loop_send_probes(&mut daemon_state).await?;
///
/// // On every incoming query, check for loop probes
/// let query_name = DnsName::from_str_unchecked("deadbeef.test");
/// if detector.detect_loop(&query_name, RRType::TXT, &mut daemon_state) {
///     // Query was a loop probe — already handled, do not forward
/// }
/// ```
pub struct LoopDetector {
    /// Daemon-level unique identifier used for instance discrimination.
    ///
    /// In topologies with multiple dnsmasq instances, this allows distinguishing
    /// our own probes from those of other instances.  Server UIDs are typically
    /// derived from or related to this value.  Exposed via [`Self::daemon_uid()`].
    daemon_uid: u32,

    /// Monotonic counter for generating unique DNS transaction IDs for probes.
    ///
    /// Using an atomic counter ensures uniqueness without requiring a CSPRNG
    /// dependency.  Loop detection probes do not have the same TXID-security
    /// requirements as user-facing DNS queries — uniqueness is sufficient to
    /// avoid confusion between concurrent probes.
    probe_id_counter: AtomicU16,
}

impl LoopDetector {
    /// Create a new loop detector.
    ///
    /// # Arguments
    ///
    /// * `daemon_uid` — Unique identifier for this daemon instance, used to
    ///   seed the probe ID counter and for instance discrimination.
    pub fn new(daemon_uid: u32) -> Self {
        // Seed the counter from the lower 16 bits of the daemon UID so that
        // different daemon instances start at different offsets, reducing the
        // chance of TXID collisions between instances.
        let initial_id = (daemon_uid & 0xFFFF) as u16;
        Self {
            daemon_uid,
            probe_id_counter: AtomicU16::new(initial_id),
        }
    }

    /// Return the daemon UID associated with this detector.
    ///
    /// Can be used to identify this daemon instance in multi-instance topologies.
    pub fn daemon_uid(&self) -> u32 {
        self.daemon_uid
    }

    /// Generate the next unique probe transaction ID.
    ///
    /// Wraps around at `u16::MAX` — acceptable because probe IDs only need to
    /// be locally unique within a short time window (the probe interval).
    fn next_probe_id(&self) -> u16 {
        self.probe_id_counter.fetch_add(1, Ordering::Relaxed)
    }

    // -----------------------------------------------------------------------
    // Probe Sending
    // -----------------------------------------------------------------------

    /// Send loop detection probes to all general-purpose upstream DNS servers.
    ///
    /// Iterates the server list, selects general-purpose servers (empty domain,
    /// not marked `SERV_FOR_NODOTS`), clears any previous `SERV_LOOP` marking,
    /// constructs a probe query embedding the server's UID, and sends it via
    /// async UDP.
    ///
    /// This function is designed to be called periodically from the main event
    /// loop timer.  Probes are fire-and-forget: send failures are logged but do
    /// not propagate as errors.
    ///
    /// Corresponds to C `loop_send_probes()` in `loop.c` lines 186–213.
    ///
    /// # Arguments
    ///
    /// * `state` — Mutable reference to the daemon state.  Server flags are
    ///   modified (SERV_LOOP cleared before probing).
    pub async fn loop_send_probes(&self, state: &mut DaemonState) -> DnsmasqResult<()> {
        // Early return if loop detection is disabled in daemon options.
        if !state.options.is_set(opt::LOOP_DETECT) {
            return Ok(());
        }

        // Bind a single ephemeral UDP socket for sending all probes in this
        // round.  Reusing one socket is more efficient than binding per-server.
        let socket = UdpSocket::bind("0.0.0.0:0").await.map_err(|e| {
            DnsmasqError::Network(format!("failed to bind UDP socket for loop probes: {}", e))
        })?;

        debug!("starting loop detection probe round");

        for server in state.servers.iter_mut() {
            // Only probe general-purpose servers:
            // - domain must be empty/None (handles all queries)
            // - must not have SERV_FOR_NODOTS flag
            let is_general_purpose = server.domain.as_ref().is_none_or(|d| d.is_empty());
            if !is_general_purpose || (server.flags & SERV_FOR_NODOTS) != 0 {
                continue;
            }

            // Clear any previous loop detection marking.  Fresh probes will
            // re-detect loops if they still exist.
            server.flags &= !SERV_LOOP;

            // Construct probe packet embedding this server's UID.
            let (probe_data, probe_id) = match self.loop_make_probe(server.uid) {
                Ok(result) => result,
                Err(e) => {
                    warn!(
                        uid = server.uid,
                        error = %e,
                        "failed to construct loop probe packet"
                    );
                    continue;
                }
            };

            // Fire-and-forget: send the probe.  Log failures but continue with
            // remaining servers — a single send failure should not abort the
            // entire probe round.
            match socket.send_to(&probe_data, server.addr).await {
                Ok(bytes_sent) => {
                    debug!(
                        uid = server.uid,
                        addr = %server.addr,
                        probe_id = probe_id,
                        bytes = bytes_sent,
                        "sent loop detection probe"
                    );
                }
                Err(e) => {
                    warn!(
                        uid = server.uid,
                        addr = %server.addr,
                        error = %e,
                        "failed to send loop detection probe"
                    );
                }
            }
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Probe Construction
    // -----------------------------------------------------------------------

    /// Construct a loop detection probe DNS packet for a given server UID.
    ///
    /// Builds a standard DNS query with:
    /// - Random-ish transaction ID from the monotonic counter
    /// - RD (Recursion Desired) flag set
    /// - Single question: `{8-hex-uid}.test. IN TXT`
    ///
    /// Returns the serialized packet bytes and the transaction ID used.
    ///
    /// Corresponds to C `loop_make_probe()` in `loop.c` lines 313–339.
    ///
    /// # Arguments
    ///
    /// * `uid` — The upstream server's unique identifier to embed in the probe
    ///   query name.
    ///
    /// # Returns
    ///
    /// `Ok((raw_packet_bytes, transaction_id))` on success, or an error if
    /// packet construction fails.
    pub fn loop_make_probe(&self, uid: u32) -> DnsmasqResult<(Vec<u8>, u16)> {
        let id = self.next_probe_id();

        // Build the probe query name: "{8-hex-uid}.{LOOP_TEST_DOMAIN}"
        // Example: "deadbeef.test"
        let query_name_str = format!("{:08x}.{}", uid, LOOP_TEST_DOMAIN);
        let name = DnsName::from_str_unchecked(&query_name_str);

        debug!(
            uid = uid,
            query_name = %query_name_str,
            probe_id = id,
            "constructing loop detection probe"
        );

        // Use DnsPacketBuilder for type-safe packet construction.
        let packet = DnsPacketBuilder::new(id)
            .add_question(&name, LOOP_TEST_TYPE, DnsClass::IN)
            .build()?;

        // The builder does not expose a method to set the RD (Recursion Desired)
        // flag.  To match the C implementation (which sets hb3 = HB3_RD), we
        // post-process the raw bytes.  The RD bit is bit 0 of byte 2 (hb3) in
        // the DNS header wire format.
        let mut raw = packet.raw.to_vec();
        if raw.len() >= DNS_HEADER_SIZE {
            raw[2] |= 0x01; // Set RD bit (hb3 bit 0)
        }

        Ok((raw, id))
    }

    // -----------------------------------------------------------------------
    // Loop Detection
    // -----------------------------------------------------------------------

    /// Analyze an incoming DNS query to determine if it is a loop detection
    /// probe that has been forwarded back to us.
    ///
    /// Checks whether the query name matches the pattern `{8-hex-uid}.test.`
    /// and the query type is [`LOOP_TEST_TYPE`] (TXT).  If a match is found,
    /// extracts the embedded UID and searches the server list for a server with
    /// a matching UID.  When found, that server is marked with `SERV_LOOP` to
    /// prevent future forwarding through it.
    ///
    /// Corresponds to C `detect_loop()` in `loop.c` lines 506–537.
    ///
    /// # Arguments
    ///
    /// * `query` — The parsed query name from the incoming DNS question.
    /// * `qtype` — The query type from the incoming DNS question.
    /// * `state` — Mutable reference to the daemon state.  A matching server's
    ///   flags will be modified to include `SERV_LOOP`.
    ///
    /// # Returns
    ///
    /// `true` if a forwarding loop was detected and a server was marked;
    /// `false` otherwise.
    pub fn detect_loop(&self, query: &DnsName, qtype: RRType, state: &mut DaemonState) -> bool {
        // Early return if loop detection is disabled.
        if !state.options.is_set(opt::LOOP_DETECT) {
            return false;
        }

        // Loop probes use TXT type exclusively.
        if qtype != LOOP_TEST_TYPE {
            return false;
        }

        // Validate query name format: exactly 2 labels.
        //   label 0 = 8 hex characters (the UID)
        //   label 1 = LOOP_TEST_DOMAIN ("test")
        if query.label_count() != 2 {
            return false;
        }

        // DnsName::to_string() returns the presentation format with a trailing
        // dot, e.g. "deadbeef.test.".  Strip the trailing dot to get the form
        // used by the C implementation: "deadbeef.test".
        let name_str = query.to_string();
        let name_str = name_str.strip_suffix('.').unwrap_or(&name_str);

        // C length check: strlen(query) == strlen(LOOP_TEST_DOMAIN) + 9
        // where +9 = 8 hex digits + 1 dot separator.
        // For LOOP_TEST_DOMAIN = "test" (len 4), total = 13.
        let expected_len = LOOP_TEST_DOMAIN.len() + UID_LABEL_LEN + 1;
        if name_str.len() != expected_len {
            return false;
        }

        // Extract the UID portion (first 8 chars) and the domain suffix
        // (everything after the dot at position 8).
        let uid_str = &name_str[..UID_LABEL_LEN];
        let separator = name_str.as_bytes()[UID_LABEL_LEN];
        let domain_str = &name_str[UID_LABEL_LEN + 1..];

        // Verify the dot separator between UID and domain.
        if separator != b'.' {
            return false;
        }

        // Verify the domain suffix matches the test domain (case-insensitive).
        if !domain_str.eq_ignore_ascii_case(LOOP_TEST_DOMAIN) {
            return false;
        }

        // Verify the UID portion is exactly 8 hexadecimal characters.
        // Corresponds to C's `isxdigit()` check in a loop over 8 chars.
        if !uid_str.chars().all(|c| c.is_ascii_hexdigit()) {
            return false;
        }

        // Extract the server UID from the hex string.
        // Corresponds to C: `strtol(query, NULL, 16)`.
        let uid = match u32::from_str_radix(uid_str, 16) {
            Ok(v) => v,
            Err(_) => {
                warn!(
                    uid_str = %uid_str,
                    "failed to parse UID from loop probe query name"
                );
                return false;
            }
        };

        debug!(
            uid = uid,
            query = %query,
            "potential loop probe detected, searching servers"
        );

        // Search the server list for a general-purpose server with a matching
        // UID that has not already been marked as looping.
        //
        // C condition:
        //   serv->uid == uid &&
        //   strlen(serv->domain) == 0 &&
        //   !(serv->flags & SERV_LOOP)
        for server in state.servers.iter_mut() {
            let is_general_purpose = server.domain.as_ref().is_none_or(|d| d.is_empty());

            if server.uid == uid && is_general_purpose && (server.flags & SERV_LOOP) == 0 {
                // Mark this server as participating in a forwarding loop.
                server.flags |= SERV_LOOP;

                info!(
                    uid = uid,
                    addr = %server.addr,
                    "DNS forwarding loop detected — server marked SERV_LOOP"
                );

                // In the C implementation, `check_servers(1)` is called here to
                // re-evaluate the server list and possibly log warnings about all
                // servers being marked.  That function is external to this module
                // and will be invoked by the caller after detect_loop() returns
                // true.
                return true;
            }
        }

        false
    }
}

// ===========================================================================
// Unit Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::protocol::DnsPacket;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    /// Helper: create a minimal DaemonState with the given servers and options.
    fn make_state(servers: Vec<crate::core::types::ServerEntry>, loop_detect: bool) -> DaemonState {
        let mut state = DaemonState::default();
        state.servers = servers;
        if loop_detect {
            state.options.set(opt::LOOP_DETECT);
        }
        state
    }

    /// Helper: create a general-purpose ServerEntry with the given UID.
    fn make_server(uid: u32, port: u16) -> crate::core::types::ServerEntry {
        crate::core::types::ServerEntry {
            addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port)),
            source_addr: None,
            interface: None,
            domain: None,
            flags: 0,
            queries: 0,
            failed_queries: 0,
            uid,
        }
    }

    #[test]
    fn test_constants() {
        assert_eq!(LOOP_TEST_TYPE, RRType::TXT);
        assert_eq!(SERV_LOOP, 8192);
        assert_eq!(SERV_FOR_NODOTS, 64);
    }

    #[test]
    fn test_loop_detector_new() {
        let detector = LoopDetector::new(0xDEADBEEF);
        assert_eq!(detector.daemon_uid, 0xDEADBEEF);
    }

    #[test]
    fn test_probe_id_generation() {
        let detector = LoopDetector::new(0);
        let id1 = detector.next_probe_id();
        let id2 = detector.next_probe_id();
        let id3 = detector.next_probe_id();
        // IDs must be sequential (monotonically increasing).
        assert_eq!(id2, id1.wrapping_add(1));
        assert_eq!(id3, id2.wrapping_add(1));
    }

    #[test]
    fn test_loop_make_probe_format() {
        let detector = LoopDetector::new(0);
        let uid: u32 = 0xDEADBEEF;

        let (raw, _id) = detector
            .loop_make_probe(uid)
            .expect("probe construction failed");

        // Minimum packet size: 12 (header) + 1+8 + 1+4 + 1 (root) + 2+2 (qtype+qclass)
        // = 12 + 9 + 5 + 1 + 4 = 31 bytes
        assert!(raw.len() >= 31, "probe packet too short: {}", raw.len());

        // Verify DNS header: QR=0 (query), RD=1
        assert_eq!(raw[2] & 0x80, 0x00, "QR bit should be 0 (query)");
        assert_eq!(raw[2] & 0x01, 0x01, "RD bit should be 1");

        // Verify QDCOUNT = 1
        let qdcount = u16::from_be_bytes([raw[4], raw[5]]);
        assert_eq!(qdcount, 1);

        // Parse back and verify the question section.
        let packet = DnsPacket::parse(&raw).expect("probe packet should parse");
        assert_eq!(packet.questions.len(), 1);
        let q = &packet.questions[0];
        assert_eq!(q.qtype, RRType::TXT);
        assert_eq!(q.qclass, DnsClass::IN);

        // Verify the query name is "{8-hex-uid}.test."
        assert_eq!(q.name.label_count(), 2);
        assert_eq!(q.name.to_string(), "deadbeef.test.");
    }

    #[test]
    fn test_loop_make_probe_uid_zero() {
        let detector = LoopDetector::new(0);
        let (raw, _id) = detector
            .loop_make_probe(0)
            .expect("probe construction failed");

        let packet = DnsPacket::parse(&raw).expect("probe packet should parse");
        assert_eq!(packet.questions[0].name.to_string(), "00000000.test.");
    }

    #[test]
    fn test_loop_make_probe_uid_max() {
        let detector = LoopDetector::new(0);
        let (raw, _id) = detector
            .loop_make_probe(0xFFFFFFFF)
            .expect("probe construction failed");

        let packet = DnsPacket::parse(&raw).expect("probe packet should parse");
        assert_eq!(packet.questions[0].name.to_string(), "ffffffff.test.");
    }

    #[test]
    fn test_detect_loop_disabled() {
        let detector = LoopDetector::new(0);
        let mut state = make_state(vec![make_server(0xDEADBEEF, 53)], false);

        let query = DnsName::from_str_unchecked("deadbeef.test");
        assert!(!detector.detect_loop(&query, RRType::TXT, &mut state));
    }

    #[test]
    fn test_detect_loop_wrong_type() {
        let detector = LoopDetector::new(0);
        let mut state = make_state(vec![make_server(0xDEADBEEF, 53)], true);

        let query = DnsName::from_str_unchecked("deadbeef.test");
        // A record type should not trigger loop detection.
        assert!(!detector.detect_loop(&query, RRType::A, &mut state));
    }

    #[test]
    fn test_detect_loop_wrong_label_count() {
        let detector = LoopDetector::new(0);
        let mut state = make_state(vec![make_server(0xDEADBEEF, 53)], true);

        // Too many labels
        let query = DnsName::from_str_unchecked("aa.deadbeef.test");
        assert!(!detector.detect_loop(&query, RRType::TXT, &mut state));

        // Too few labels
        let query = DnsName::from_str_unchecked("test");
        assert!(!detector.detect_loop(&query, RRType::TXT, &mut state));
    }

    #[test]
    fn test_detect_loop_wrong_domain() {
        let detector = LoopDetector::new(0);
        let mut state = make_state(vec![make_server(0xDEADBEEF, 53)], true);

        let query = DnsName::from_str_unchecked("deadbeef.example");
        assert!(!detector.detect_loop(&query, RRType::TXT, &mut state));
    }

    #[test]
    fn test_detect_loop_short_uid() {
        let detector = LoopDetector::new(0);
        let mut state = make_state(vec![make_server(0xDEAD, 53)], true);

        // UID label too short (only 4 hex chars instead of 8).
        let query = DnsName::from_str_unchecked("dead.test");
        assert!(!detector.detect_loop(&query, RRType::TXT, &mut state));
    }

    #[test]
    fn test_detect_loop_non_hex_uid() {
        let detector = LoopDetector::new(0);
        let mut state = make_state(vec![make_server(0, 53)], true);

        // 'g' is not a valid hex digit.
        let query = DnsName::from_str_unchecked("0000000g.test");
        assert!(!detector.detect_loop(&query, RRType::TXT, &mut state));
    }

    #[test]
    fn test_detect_loop_match() {
        let detector = LoopDetector::new(0);
        let uid: u32 = 0x12345678;
        let mut state = make_state(vec![make_server(uid, 53)], true);

        let query = DnsName::from_str_unchecked("12345678.test");
        assert!(detector.detect_loop(&query, RRType::TXT, &mut state));

        // Server should now be marked with SERV_LOOP.
        assert_ne!(state.servers[0].flags & SERV_LOOP, 0);
    }

    #[test]
    fn test_detect_loop_already_marked() {
        let detector = LoopDetector::new(0);
        let uid: u32 = 0xAABBCCDD;
        let mut server = make_server(uid, 53);
        server.flags |= SERV_LOOP; // Already marked
        let mut state = make_state(vec![server], true);

        let query = DnsName::from_str_unchecked("aabbccdd.test");
        // Should NOT match because the server is already marked SERV_LOOP.
        assert!(!detector.detect_loop(&query, RRType::TXT, &mut state));
    }

    #[test]
    fn test_detect_loop_domain_server_skipped() {
        let detector = LoopDetector::new(0);
        let uid: u32 = 0x11111111;
        let mut server = make_server(uid, 53);
        server.domain = Some("example.com".to_string()); // Not general-purpose
        let mut state = make_state(vec![server], true);

        let query = DnsName::from_str_unchecked("11111111.test");
        // Should NOT match because the server has a non-empty domain.
        assert!(!detector.detect_loop(&query, RRType::TXT, &mut state));
    }

    #[test]
    fn test_detect_loop_no_matching_uid() {
        let detector = LoopDetector::new(0);
        let mut state = make_state(vec![make_server(0xAAAAAAAA, 53)], true);

        let query = DnsName::from_str_unchecked("bbbbbbbb.test");
        // UID does not match any server.
        assert!(!detector.detect_loop(&query, RRType::TXT, &mut state));
    }

    #[test]
    fn test_detect_loop_multiple_servers() {
        let detector = LoopDetector::new(0);
        let mut state = make_state(
            vec![
                make_server(0x11111111, 53),
                make_server(0x22222222, 5353),
                make_server(0x33333333, 8053),
            ],
            true,
        );

        // Probe matching the second server.
        let query = DnsName::from_str_unchecked("22222222.test");
        assert!(detector.detect_loop(&query, RRType::TXT, &mut state));

        // Only the second server should be marked.
        assert_eq!(state.servers[0].flags & SERV_LOOP, 0);
        assert_ne!(state.servers[1].flags & SERV_LOOP, 0);
        assert_eq!(state.servers[2].flags & SERV_LOOP, 0);
    }

    #[test]
    fn test_detect_loop_case_insensitive_domain() {
        let detector = LoopDetector::new(0);
        let uid: u32 = 0xABCDABCD;
        let mut state = make_state(vec![make_server(uid, 53)], true);

        // Domain label in mixed case — should still match.
        let query = DnsName::from_str_unchecked("abcdabcd.TEST");
        assert!(detector.detect_loop(&query, RRType::TXT, &mut state));
    }

    #[test]
    fn test_detect_loop_uppercase_uid() {
        let detector = LoopDetector::new(0);
        let uid: u32 = 0xABCDEF01;
        let mut state = make_state(vec![make_server(uid, 53)], true);

        // Uppercase hex digits in UID label — should still match.
        let query = DnsName::from_str_unchecked("ABCDEF01.test");
        assert!(detector.detect_loop(&query, RRType::TXT, &mut state));
    }
}

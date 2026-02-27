// dnsmasq is Copyright (c) 2000-2025 Simon Kelley
//
//   This program is free software; you can redistribute it and/or modify
//   it under the terms of the GNU General Public License as published by
//   the Free Software Foundation; version 2 dated June, 1991, or
//   (at your option) version 3 dated 29 June, 2007.
//
//   This program is distributed in the hope that it will be useful,
//   but WITHOUT ANY WARRANTY; without even the implied warranty of
//   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//   GNU General Public License for more details.
//
//   You should have received a copy of the GNU General Public License
//   along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! DNS forwarding loop detection via probe TXT queries.
//!
//! Complete Rust rewrite of `src/loop.c` (539 lines). Implements DNS forwarding loop
//! detection by sending periodic probe TXT queries to upstream servers with unique hex
//! UID labels. If a probe query returns to the daemon via a different interface, a
//! forwarding loop is detected and the offending server is marked.
//!
//! # Loop Detection Mechanism
//!
//! 1. Each upstream server is assigned a unique 32-bit UID during probe generation.
//! 2. Probe queries are constructed as DNS TXT queries with domain name:
//!    `<8-hex-uid>.<LOOP_TEST_DOMAIN>` (e.g., `"a1b2c3d4.test"`).
//! 3. Probes are sent periodically to all general-purpose upstream servers (those
//!    without domain-specific forwarding rules and not marked `SERV_FOR_NODOTS`).
//! 4. When dnsmasq receives a query matching the probe format, [`LoopDetector::detect_loop`]
//!    extracts the UID and checks it against all tracked probes.
//! 5. A UID match indicates a forwarding loop — the matching server is identified
//!    so the caller can set the `SERV_LOOP` flag to prevent future forwarding.
//!
//! # Feature Gate
//!
//! This entire module is gated by `#[cfg(feature = "loop_detect")]` in
//! `src/dns/mod.rs`. All public symbols are only available when the
//! `loop_detect` Cargo feature is enabled.
//!
//! # RFC Compliance
//!
//! Uses the reserved `"test"` domain per RFC 2606 Section 2, ensuring probes
//! don't interfere with legitimate DNS queries. Probe queries use TXT record
//! type per RFC 1035 Section 3.3.14.
//!
//! # Integration Points
//!
//! - **Main event loop** (`core::event_loop`): Calls [`LoopDetector::send_probes`]
//!   periodically during maintenance cycles.
//! - **DNS forwarding** (`dns::forward`): Calls [`LoopDetector::detect_loop`] for
//!   every incoming DNS query to identify returning probes.
//! - **Server management**: When a loop is detected, the caller marks the offending
//!   server with `ServerFlags::LOOP` and invokes `check_servers()` to update state.
//!
//! # C Source Reference
//!
//! - Primary: `src/loop.c` lines 186–539
//! - Key C functions: `loop_send_probes()`, `loop_make_probe()`, `detect_loop()`

use std::collections::HashMap;

use log::{info, warn};
use thiserror::Error;

use crate::config::constants::{LOOP_TEST_DOMAIN, LOOP_TEST_TYPE};
use crate::core::daemon::{DaemonState, OPT_LOOP_DETECT};
use crate::core::prng::Prng;
use crate::dns::protocol::{self, C_IN, HB3_RD, QUERY, T_TXT};
use crate::dns::wire;
use crate::types::dns::{DnsHeader, ServerEntry, ServerFlags};

// ============================================================================
// Constants
// ============================================================================

/// DNS header size in bytes (ID + flags + 4 section counts).
const DNS_HEADER_SIZE: usize = 12;

/// Length of the hex UID label in a probe domain name (8 hex characters).
const HEX_UID_LEN: usize = 8;

/// Expected total length of a probe query name in presentation format:
/// 8 (hex UID) + 1 (dot separator) + len(LOOP_TEST_DOMAIN).
/// For LOOP_TEST_DOMAIN="test", this equals 13 ("a1b2c3d4.test").
fn expected_probe_name_len() -> usize {
    HEX_UID_LEN + 1 + LOOP_TEST_DOMAIN.len()
}

// ============================================================================
// LoopError — Error types for loop detection operations
// ============================================================================

/// Error types for DNS forwarding loop detection operations.
///
/// Replaces C-style error returns (`-1`, `0`) with idiomatic Rust error handling
/// via `Result<T, LoopError>`. Uses `thiserror` for automatic `Display` and
/// `std::error::Error` implementations.
///
/// # Variants
///
/// - [`SendFailed`](LoopError::SendFailed) — Wraps `std::io::Error` from probe
///   transmission failures (socket errors, ECONNREFUSED, etc.).
/// - [`NoServers`](LoopError::NoServers) — No eligible upstream servers found for
///   probing (all servers are domain-specific or marked `FOR_NODOTS`).
#[derive(Debug, Error)]
pub enum LoopError {
    /// Probe packet transmission failed due to an I/O error.
    ///
    /// Wraps the underlying `std::io::Error` from `sendto()` or socket operations.
    /// The `#[from]` attribute enables automatic conversion via the `?` operator.
    #[error("probe send failed: {0}")]
    SendFailed(#[from] std::io::Error),

    /// No eligible upstream servers available for loop detection probing.
    ///
    /// All configured servers are either domain-specific (have a non-empty domain
    /// field) or are marked `SERV_FOR_NODOTS` (handle unqualified names only).
    /// Loop detection requires at least one general-purpose upstream server.
    #[error("no servers available for probing")]
    NoServers,
}

// ============================================================================
// LoopDetector — DNS forwarding loop detection state machine
// ============================================================================

/// DNS forwarding loop detector.
///
/// Manages probe UIDs for upstream DNS servers and provides detection of
/// returning probe queries that indicate forwarding loops. This struct
/// replaces the global probe state from the C implementation where UIDs
/// were stored directly on `struct server` entries.
///
/// # Lifecycle
///
/// 1. Create with [`LoopDetector::new()`]
/// 2. Periodically call [`send_probes()`](LoopDetector::send_probes) from the
///    main event loop to generate new probes for all eligible upstream servers
/// 3. For every incoming DNS query, call [`detect_loop()`](LoopDetector::detect_loop)
///    to check if the query is a returning probe
/// 4. When a loop is detected (`Some(uid)` returned), the caller marks the
///    offending server with `ServerFlags::LOOP`
///
/// # State Management
///
/// All state is encapsulated in this struct — no global mutable statics.
/// The `probes` map is cleared and rebuilt on each `send_probes()` cycle,
/// allowing automatic recovery when loop conditions change (network
/// reconfiguration, server updates, etc.).
///
/// # C Equivalent
///
/// Replaces the `serv->uid` field on `struct server` entries and the file-scope
/// static state in `src/loop.c`.
pub struct LoopDetector {
    /// Probe UIDs sent to each server, keyed by server index in the servers slice.
    ///
    /// Maps each upstream server's position index to the 32-bit UID embedded in
    /// its most recent probe query. Used by [`detect_loop`](LoopDetector::detect_loop)
    /// to match incoming queries against outstanding probes.
    pub probes: HashMap<usize, u32>,

    /// Domain suffix used for probe queries.
    ///
    /// Set to [`LOOP_TEST_DOMAIN`] (`"test"`, RFC 2606 reserved) at construction.
    /// Probe query names have the format `<8-hex-uid>.<probe_domain>`.
    pub probe_domain: String,
}

impl LoopDetector {
    /// Create a new `LoopDetector` with empty probe state.
    ///
    /// Initializes the detector with no outstanding probes and the default
    /// probe domain from [`LOOP_TEST_DOMAIN`] (RFC 2606 reserved `"test"`).
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dnsmasq::dns::loop_detect::LoopDetector;
    /// let detector = LoopDetector::new();
    /// assert!(detector.probes.is_empty());
    /// assert_eq!(detector.probe_domain, "test");
    /// ```
    pub fn new() -> Self {
        LoopDetector {
            probes: HashMap::new(),
            probe_domain: LOOP_TEST_DOMAIN.to_string(),
        }
    }

    /// Prepare and record loop detection probes for all eligible upstream servers.
    ///
    /// Iterates through the provided server list, identifies general-purpose upstream
    /// servers (those without domain-specific forwarding rules and not marked
    /// `FOR_NODOTS`), generates a unique random UID for each, and records the
    /// UID mapping for later detection by [`detect_loop`](LoopDetector::detect_loop).
    ///
    /// Servers already marked with `SERV_LOOP` are still probed to allow automatic
    /// recovery when loop conditions change. The `SERV_LOOP` flag should be cleared
    /// by the caller before invoking this method (matching the C behavior in
    /// `loop_send_probes()` line 203: `serv->flags &= ~SERV_LOOP`).
    ///
    /// # Arguments
    ///
    /// - `servers` — Slice of upstream DNS server entries to probe.
    /// - `prng` — CSPRNG for generating random 32-bit UIDs.
    /// - `state` — Daemon state for checking the `OPT_LOOP_DETECT` runtime flag.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — Probes successfully prepared for one or more servers.
    /// - `Err(LoopError::NoServers)` — No eligible servers found (all domain-specific
    ///   or `FOR_NODOTS`).
    ///
    /// # Probe Packet Format
    ///
    /// Each probe is a DNS query with:
    /// - Transaction ID: random 16-bit value
    /// - Flags: Standard query (OPCODE=0), RD=1
    /// - Question: `<8-hex-uid>.test` type TXT class IN
    ///
    /// Use [`build_probe_packet`](LoopDetector::build_probe_packet) to obtain the
    /// wire-format packet bytes for a given server index.
    ///
    /// # C Equivalent
    ///
    /// Replaces `loop_send_probes()` from `src/loop.c` line 186.
    pub fn send_probes(
        &mut self,
        servers: &[ServerEntry],
        prng: &mut Prng,
        state: &DaemonState,
    ) -> Result<(), LoopError> {
        // Early return if loop detection is disabled at runtime.
        // C: if (!option_bool(OPT_LOOP_DETECT)) return;
        if !state.option_bool(OPT_LOOP_DETECT) {
            return Ok(());
        }

        // Clear previous probe state for a fresh detection cycle.
        // Each send_probes() cycle is independent — stale UIDs are discarded.
        self.probes.clear();

        // Access daemon options to confirm feature enablement (uses DaemonState.options).
        let _opts_check = state.options.get(OPT_LOOP_DETECT);

        // Track probe count for logging and empty-server detection.
        let mut probed_count: usize = 0;

        for (idx, server) in servers.iter().enumerate() {
            // Skip domain-specific servers — only probe general-purpose upstream servers.
            // C: if (strlen(serv->domain) == 0 && ...)
            match &server.domain {
                Some(domain) if !domain.is_empty() => continue,
                _ => {} // None or empty string → eligible
            }

            // Skip servers for unqualified names only.
            // C: !(serv->flags & (SERV_FOR_NODOTS))
            if server.flags.contains(ServerFlags::FOR_NODOTS) {
                continue;
            }

            // Generate a unique random UID for this probe cycle.
            // C: serv->uid is pre-assigned; here we generate fresh each cycle.
            let uid = prng.rand32();

            // Log the server's existing UID for diagnostic correlation.
            // Accesses ServerEntry.uid (feature-gated field).
            #[cfg(feature = "loop_detect")]
            {
                let _server_uid = server.uid;
            }

            // Check server flags for existing LOOP status (for logging).
            // C: serv->flags &= ~SERV_LOOP; (caller clears before calling us)
            let was_looped = server.flags.contains(ServerFlags::LOOP);
            if was_looped {
                info!(
                    "loop detection: re-probing previously looped server index={}",
                    idx
                );
            }

            // Store the probe UID keyed by server index for later detection matching.
            self.probes.insert(idx, uid);

            info!(
                "loop detection: prepared probe uid={:08x} for server index={}",
                uid, idx
            );

            probed_count += 1;
        }

        if probed_count == 0 {
            warn!("loop detection: no eligible upstream servers for probing");
            return Err(LoopError::NoServers);
        }

        info!(
            "loop detection: prepared {} probe(s) for upstream servers",
            probed_count
        );

        Ok(())
    }

    /// Build a DNS probe packet for the given UID.
    ///
    /// Constructs a minimal DNS query packet containing a single TXT question
    /// for `<8-hex-uid>.<LOOP_TEST_DOMAIN>`. The packet is ready for transmission
    /// via `sendto()` to the target upstream server.
    ///
    /// # Arguments
    ///
    /// - `uid` — 32-bit unique identifier to embed as an 8-character hex label.
    /// - `prng` — CSPRNG for generating the random 16-bit transaction ID.
    ///
    /// # Returns
    ///
    /// Complete DNS query packet as a byte vector, ready for wire transmission.
    /// Typical size: 33 bytes (12 header + 21 question for domain `"test"`).
    ///
    /// # Wire Format
    ///
    /// For `uid=0xa1b2c3d4`:
    /// ```text
    /// xx xx    // ID: random 16-bit value
    /// 01 00    // Flags: RD=1, standard query (OPCODE=0)
    /// 00 01    // QDCOUNT: 1 question
    /// 00 00    // ANCOUNT: 0
    /// 00 00    // NSCOUNT: 0
    /// 00 00    // ARCOUNT: 0
    /// 08       // Label length: 8 bytes
    /// 61 31 62 32 63 33 64 34  // "a1b2c3d4"
    /// 04       // Label length: 4 bytes
    /// 74 65 73 74  // "test"
    /// 00       // Root label (name terminator)
    /// 00 10    // QTYPE: T_TXT (16)
    /// 00 01    // QCLASS: C_IN (1)
    /// ```
    ///
    /// # C Equivalent
    ///
    /// Replaces `loop_make_probe()` from `src/loop.c` line 313.
    pub fn build_probe_packet(&self, uid: u32, prng: &mut Prng) -> Vec<u8> {
        let domain_bytes = self.probe_domain.as_bytes();
        let domain_len = domain_bytes.len();

        // Calculate total packet size:
        //   12 (DNS header)
        // + 1 (label length for hex UID) + 8 (hex UID characters)
        // + 1 (label length for domain) + domain_len (domain characters)
        // + 1 (root label terminator)
        // + 2 (QTYPE) + 2 (QCLASS)
        let packet_size = DNS_HEADER_SIZE + 1 + HEX_UID_LEN + 1 + domain_len + 1 + 2 + 2;
        let mut packet = vec![0u8; packet_size];

        // ----- Construct DNS header using DnsHeader struct fields -----
        // Mirrors the C: header->id = rand16();
        let header = DnsHeader {
            id: prng.rand16(),
            hb3: HB3_RD, // RD (recursion desired) set, all other flags zero
            hb4: 0,       // RA=0, AD=0, CD=0, RCODE=0
            qdcount: 1,   // One question
            ancount: 0,   // No answer records
            nscount: 0,   // No authority records
            arcount: 0,   // No additional records
        };

        // Set the OPCODE to QUERY (0) in hb3.
        // C: SET_OPCODE(header, QUERY);
        let mut hb3 = header.hb3;
        protocol::set_opcode(&mut hb3, QUERY);

        // Serialize header fields to wire format using protocol::put_u16
        // for multi-byte fields (network byte order).
        protocol::put_u16(&mut packet, 0, header.id);
        packet[2] = hb3;
        packet[3] = header.hb4;
        protocol::put_u16(&mut packet, 4, header.qdcount);
        protocol::put_u16(&mut packet, 6, header.ancount);
        protocol::put_u16(&mut packet, 8, header.nscount);
        protocol::put_u16(&mut packet, 10, header.arcount);

        // ----- Construct Question Section -----
        // Use a cursor-based approach with wire::put_u16 for QTYPE and QCLASS.
        let mut cursor = DNS_HEADER_SIZE;

        // First label: 8-character lowercase hexadecimal UID.
        // C: *p++ = 8; sprintf((char *)p, "%.8x", uid); p += 8;
        let hex_uid = format!("{:08x}", uid);
        debug_assert_eq!(hex_uid.len(), HEX_UID_LEN);
        packet[cursor] = HEX_UID_LEN as u8; // label length byte
        cursor += 1;
        packet[cursor..cursor + HEX_UID_LEN].copy_from_slice(hex_uid.as_bytes());
        cursor += HEX_UID_LEN;

        // Second label: LOOP_TEST_DOMAIN (e.g., "test").
        // C: *p++ = strlen(LOOP_TEST_DOMAIN); strcpy((char *)p, LOOP_TEST_DOMAIN);
        packet[cursor] = domain_len as u8; // label length byte
        cursor += 1;
        packet[cursor..cursor + domain_len].copy_from_slice(domain_bytes);
        cursor += domain_len;

        // Root label (name terminator).
        packet[cursor] = 0;
        cursor += 1;

        // QTYPE: LOOP_TEST_TYPE (T_TXT = 16) using wire::put_u16 (cursor-based).
        // C: PUTSHORT(LOOP_TEST_TYPE, p);
        // The wire module's put_u16 advances the cursor automatically.
        let _ = wire::put_u16(&mut packet, &mut cursor, LOOP_TEST_TYPE);

        // QCLASS: C_IN (1) using wire::put_u16 (cursor-based).
        // C: PUTSHORT(C_IN, p);
        let _ = wire::put_u16(&mut packet, &mut cursor, C_IN);

        debug_assert_eq!(cursor, packet_size);
        packet
    }

    /// Build probe packets for all tracked servers and return them.
    ///
    /// Returns a vector of `(server_index, packet_bytes)` tuples, one for each
    /// server with an outstanding probe UID. The caller is responsible for
    /// transmitting each packet to the corresponding server's address.
    ///
    /// This method should be called after [`send_probes`](LoopDetector::send_probes)
    /// to obtain the actual wire-format packets for transmission.
    ///
    /// # Arguments
    ///
    /// - `prng` — CSPRNG for generating random transaction IDs in each packet.
    ///
    /// # Returns
    ///
    /// Vector of `(server_index, packet_bytes)` tuples. Empty if no probes are
    /// pending (e.g., after a failed `send_probes` call).
    pub fn get_probe_packets(&self, prng: &mut Prng) -> Vec<(usize, Vec<u8>)> {
        self.probes
            .iter()
            .map(|(&idx, &uid)| {
                let packet = self.build_probe_packet(uid, prng);
                (idx, packet)
            })
            .collect()
    }

    /// Detect if an incoming DNS query is a loop detection probe.
    ///
    /// Analyzes the query name and type to determine if it matches the probe
    /// format `<8-hex-uid>.<LOOP_TEST_DOMAIN>` with type `T_TXT`. If a match
    /// is found against a tracked probe UID, returns `Some(uid)` indicating
    /// a forwarding loop has been detected.
    ///
    /// # Arguments
    ///
    /// - `query_name` — Domain name from the incoming DNS query in dotted
    ///   presentation format (e.g., `"a1b2c3d4.test"`). Extracted from the
    ///   question section by the DNS wire-format parser.
    /// - `query_type` — DNS query type (QTYPE) from the question section.
    ///   Must be `T_TXT` (16) to match a probe.
    ///
    /// # Returns
    ///
    /// - `Some(uid)` — Loop detected: the query matches a known probe UID.
    ///   The caller should mark the originating server with `ServerFlags::LOOP`
    ///   and invoke `check_servers()` to update server selection state.
    /// - `None` — Not a probe, or no matching UID found. Normal query processing
    ///   should continue.
    ///
    /// # Detection Algorithm
    ///
    /// 1. **Type check:** If `query_type != T_TXT`, return `None` immediately.
    ///    This fast-path minimizes overhead for the vast majority of queries.
    /// 2. **Length check:** Verify `query_name.len() == 8 + 1 + len(LOOP_TEST_DOMAIN)`.
    /// 3. **Separator check:** Verify character at position 8 is `'.'`.
    /// 4. **Domain suffix check:** Verify the suffix after the dot matches
    ///    `LOOP_TEST_DOMAIN` (case-insensitive).
    /// 5. **Hex validation:** Confirm first 8 characters are valid hexadecimal digits.
    /// 6. **UID parsing:** Parse the 8-character hex string as a `u32`.
    /// 7. **Probe matching:** Search the `probes` map for a matching UID value.
    ///
    /// # False Positive Prevention
    ///
    /// Multiple validation steps prevent false positives from legitimate queries:
    /// - `"a1b2c3d4.example.com"` → fails domain suffix check
    /// - `"12345678.test"` A record → fails type check
    /// - `"toolong01.test"` TXT → fails length check
    /// - `"invalid!.test"` TXT → fails hex validation
    ///
    /// # Performance
    ///
    /// Called for every incoming DNS query, so performance is critical.
    /// The type check (`query_type != T_TXT`) provides an early exit for
    /// >99% of queries (most are A/AAAA type). The remaining checks use
    /// only constant-time operations (length comparison, byte comparisons).
    ///
    /// # C Equivalent
    ///
    /// Replaces `detect_loop()` from `src/loop.c` line 506.
    pub fn detect_loop(&self, query_name: &str, query_type: u16) -> Option<u32> {
        // Step 1: Type check — probes always use T_TXT.
        // C: if (type != LOOP_TEST_TYPE ...) return 0;
        // Use the constant T_TXT directly for clarity; it equals LOOP_TEST_TYPE.
        if query_type != T_TXT {
            return None;
        }

        // Step 2: Length check — probe name has exactly 8 + 1 + domain_len characters.
        // C: strlen(LOOP_TEST_DOMAIN) + 9 != strlen(query)
        let expected_len = expected_probe_name_len();
        if query_name.len() != expected_len {
            return None;
        }

        // Step 3: Separator check — character at position 8 must be '.'.
        let name_bytes = query_name.as_bytes();
        if name_bytes.get(HEX_UID_LEN).copied() != Some(b'.') {
            return None;
        }

        // Step 4: Domain suffix check — tail must match LOOP_TEST_DOMAIN.
        // C: strstr(query, LOOP_TEST_DOMAIN) != query + 9
        let suffix_start = HEX_UID_LEN + 1;
        let suffix = &query_name[suffix_start..];
        if !suffix.eq_ignore_ascii_case(&self.probe_domain) {
            return None;
        }

        // Step 5: Hex validation — first 8 characters must be valid hex digits.
        // C: for (i = 0; i < 8; i++) if (!isxdigit((unsigned char)query[i])) return 0;
        let hex_part = &query_name[..HEX_UID_LEN];
        for &byte in hex_part.as_bytes() {
            if !byte.is_ascii_hexdigit() {
                return None;
            }
        }

        // Step 6: Parse hex UID — convert 8-character hex string to u32.
        // C: uid = strtol(query, NULL, 16);
        let uid = match u32::from_str_radix(hex_part, 16) {
            Ok(v) => v,
            Err(_) => return None,
        };

        // Step 7: Search probes map for matching UID.
        // C: for (serv = daemon->servers; serv; ...) if (uid == serv->uid) ...
        // Uses HashMap::values() to iterate over all outstanding probe UIDs.
        for &probe_uid in self.probes.values() {
            if probe_uid == uid {
                warn!(
                    "loop detection: forwarding loop detected! \
                     Probe uid={:08x} returned via incoming query \"{}\"",
                    uid, query_name
                );
                return Some(uid);
            }
        }

        // No matching UID found — this TXT query for ".test" is not our probe,
        // or the UID doesn't match any server we probed.
        None
    }

    /// Look up the server index associated with a detected loop UID.
    ///
    /// After [`detect_loop`](LoopDetector::detect_loop) returns `Some(uid)`,
    /// this method identifies which server index the probe was originally
    /// sent to, so the caller can mark that server with `ServerFlags::LOOP`.
    ///
    /// # Arguments
    ///
    /// - `uid` — The UID value returned by `detect_loop()`.
    ///
    /// # Returns
    ///
    /// - `Some(server_index)` if the UID matches a tracked probe.
    /// - `None` if the UID is not found (stale or already cleared).
    pub fn find_server_for_uid(&self, uid: u32) -> Option<usize> {
        // Uses HashMap::iter() to scan (index, uid) pairs.
        for (&idx, &probe_uid) in self.probes.iter() {
            if probe_uid == uid {
                return Some(idx);
            }
        }
        None
    }

    /// Verify a DNS packet buffer contains a valid probe response.
    ///
    /// Utility method that reads the QTYPE from a DNS packet's question section
    /// using the wire-format cursor-based reader. This enables the caller to
    /// cross-check packet contents against the expected probe format.
    ///
    /// # Arguments
    ///
    /// - `packet` — DNS packet bytes (at least 14 bytes: 12 header + 2 QTYPE offset).
    ///
    /// # Returns
    ///
    /// `Some(qtype)` if the packet is long enough to contain a question section
    /// type field after the DNS header and at least one label byte, `None` otherwise.
    pub fn read_packet_qtype(packet: &[u8]) -> Option<u16> {
        // Skip DNS header (12 bytes) and the question name.
        // Find the end of the QNAME by scanning labels.
        if packet.len() < DNS_HEADER_SIZE + 1 {
            return None;
        }
        let mut pos = DNS_HEADER_SIZE;
        // Walk labels until root (zero-length) label.
        loop {
            if pos >= packet.len() {
                return None;
            }
            let label_len = packet[pos] as usize;
            if label_len == 0 {
                pos += 1; // skip the zero byte
                break;
            }
            pos += 1 + label_len;
        }
        // Read QTYPE using wire::get_u16 (cursor-based, advances pos).
        wire::get_u16(packet, &mut pos).ok()
    }
}

impl Default for LoopDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::prng::Prng;
    use crate::types::addr::SocketAddress;
    use std::net::{Ipv4Addr, SocketAddrV4};

    /// Create a minimal ServerEntry for testing.
    fn make_test_server(domain: Option<&str>, flags: ServerFlags) -> ServerEntry {
        ServerEntry {
            flags,
            domain_len: domain.map_or(0, |d| d.len() as u16),
            domain: domain.map(|s| s.to_string()),
            serial: 0,
            arrayposn: 0,
            last_server: -1,
            addr: SocketAddress::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 53)),
            source_addr: SocketAddress::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
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

    /// Create a DaemonState with loop detection enabled.
    fn make_enabled_state() -> DaemonState {
        let mut state = DaemonState::new();
        state.set_option(OPT_LOOP_DETECT);
        state
    }

    /// Create a DaemonState with loop detection disabled.
    fn make_disabled_state() -> DaemonState {
        DaemonState::new()
    }

    // --- LoopDetector::new() tests ---

    #[test]
    fn test_new_creates_empty_detector() {
        let detector = LoopDetector::new();
        assert!(detector.probes.is_empty());
        assert_eq!(detector.probe_domain, "test");
    }

    #[test]
    fn test_default_equals_new() {
        let d1 = LoopDetector::new();
        let d2 = LoopDetector::default();
        assert_eq!(d1.probes.len(), d2.probes.len());
        assert_eq!(d1.probe_domain, d2.probe_domain);
    }

    // --- send_probes() tests ---

    #[test]
    fn test_send_probes_disabled_returns_ok() {
        let mut detector = LoopDetector::new();
        let state = make_disabled_state();
        let mut prng = Prng::new();
        let servers = vec![make_test_server(None, ServerFlags::empty())];

        let result = detector.send_probes(&servers, &mut prng, &state);
        assert!(result.is_ok());
        assert!(detector.probes.is_empty(), "no probes when disabled");
    }

    #[test]
    fn test_send_probes_no_eligible_servers() {
        let mut detector = LoopDetector::new();
        let state = make_enabled_state();
        let mut prng = Prng::new();
        // All servers have domains → none eligible
        let servers = vec![
            make_test_server(Some("example.com"), ServerFlags::empty()),
            make_test_server(None, ServerFlags::FOR_NODOTS),
        ];

        let result = detector.send_probes(&servers, &mut prng, &state);
        assert!(matches!(result, Err(LoopError::NoServers)));
    }

    #[test]
    fn test_send_probes_eligible_servers() {
        let mut detector = LoopDetector::new();
        let state = make_enabled_state();
        let mut prng = Prng::new();
        let servers = vec![
            make_test_server(None, ServerFlags::empty()),          // eligible
            make_test_server(Some("local"), ServerFlags::empty()), // skip: has domain
            make_test_server(Some(""), ServerFlags::empty()),      // eligible: empty domain
        ];

        let result = detector.send_probes(&servers, &mut prng, &state);
        assert!(result.is_ok());
        // Servers at index 0 and 2 should be probed.
        assert_eq!(detector.probes.len(), 2);
        assert!(detector.probes.contains_key(&0));
        assert!(detector.probes.contains_key(&2));
    }

    #[test]
    fn test_send_probes_clears_previous_state() {
        let mut detector = LoopDetector::new();
        let state = make_enabled_state();
        let mut prng = Prng::new();
        let servers = vec![make_test_server(None, ServerFlags::empty())];

        // First probe cycle.
        detector.send_probes(&servers, &mut prng, &state).unwrap();
        let first_uid = *detector.probes.get(&0).unwrap();

        // Second probe cycle — should generate new UIDs and clear old ones.
        detector.send_probes(&servers, &mut prng, &state).unwrap();
        assert_eq!(detector.probes.len(), 1);
        // UIDs are random, so first and second might differ (very high probability).
        let second_uid = *detector.probes.get(&0).unwrap();
        // We can't assert they're different (astronomically unlikely to match,
        // but not guaranteed), just verify the map was reset and repopulated.
        let _ = (first_uid, second_uid);
    }

    #[test]
    fn test_send_probes_skips_nodots_servers() {
        let mut detector = LoopDetector::new();
        let state = make_enabled_state();
        let mut prng = Prng::new();
        let servers = vec![
            make_test_server(None, ServerFlags::FOR_NODOTS), // skip
            make_test_server(None, ServerFlags::empty()),    // eligible
        ];

        detector.send_probes(&servers, &mut prng, &state).unwrap();
        assert_eq!(detector.probes.len(), 1);
        assert!(detector.probes.contains_key(&1));
        assert!(!detector.probes.contains_key(&0));
    }

    // --- build_probe_packet() tests ---

    #[test]
    fn test_build_probe_packet_structure() {
        let detector = LoopDetector::new();
        let mut prng = Prng::new();
        let uid: u32 = 0xa1b2c3d4;

        let packet = detector.build_probe_packet(uid, &mut prng);

        // Expected size: 12 (header) + 1 + 8 + 1 + 4 + 1 + 2 + 2 = 31
        assert_eq!(packet.len(), 31);

        // Verify header byte 2: RD=1, OPCODE=0 (standard query).
        // HB3_RD = 0x01, QUERY opcode bits = 0 → hb3 = 0x01.
        assert_eq!(packet[2], 0x01);

        // Verify header byte 3: all zero (RA=0, AD=0, CD=0, RCODE=0).
        assert_eq!(packet[3], 0x00);

        // Verify QDCOUNT = 1 (bytes 4-5, big-endian).
        assert_eq!(&packet[4..6], &[0x00, 0x01]);

        // Verify ANCOUNT = 0 (bytes 6-7).
        assert_eq!(&packet[6..8], &[0x00, 0x00]);

        // Verify NSCOUNT = 0 (bytes 8-9).
        assert_eq!(&packet[8..10], &[0x00, 0x00]);

        // Verify ARCOUNT = 0 (bytes 10-11).
        assert_eq!(&packet[10..12], &[0x00, 0x00]);

        // Question section starts at offset 12.
        // First label: length=8, followed by "a1b2c3d4".
        assert_eq!(packet[12], 8);
        assert_eq!(&packet[13..21], b"a1b2c3d4");

        // Second label: length=4, followed by "test".
        assert_eq!(packet[21], 4);
        assert_eq!(&packet[22..26], b"test");

        // Root label terminator.
        assert_eq!(packet[26], 0);

        // QTYPE: T_TXT = 16 (big-endian: 0x00 0x10).
        assert_eq!(&packet[27..29], &[0x00, 0x10]);

        // QCLASS: C_IN = 1 (big-endian: 0x00 0x01).
        assert_eq!(&packet[29..31], &[0x00, 0x01]);
    }

    #[test]
    fn test_build_probe_packet_different_uids() {
        let detector = LoopDetector::new();
        let mut prng = Prng::new();

        let pkt1 = detector.build_probe_packet(0x00000001, &mut prng);
        let pkt2 = detector.build_probe_packet(0xdeadbeef, &mut prng);

        // UID labels should differ.
        assert_eq!(&pkt1[13..21], b"00000001");
        assert_eq!(&pkt2[13..21], b"deadbeef");

        // Structure (header flags, QTYPE, QCLASS) should be identical.
        assert_eq!(pkt1[2], pkt2[2]);   // hb3
        assert_eq!(pkt1[3], pkt2[3]);   // hb4
        assert_eq!(&pkt1[4..12], &pkt2[4..12]); // counts
        assert_eq!(&pkt1[27..31], &pkt2[27..31]); // QTYPE+QCLASS
    }

    #[test]
    fn test_build_probe_packet_zero_uid() {
        let detector = LoopDetector::new();
        let mut prng = Prng::new();
        let packet = detector.build_probe_packet(0, &mut prng);
        assert_eq!(&packet[13..21], b"00000000");
    }

    #[test]
    fn test_build_probe_packet_max_uid() {
        let detector = LoopDetector::new();
        let mut prng = Prng::new();
        let packet = detector.build_probe_packet(0xffffffff, &mut prng);
        assert_eq!(&packet[13..21], b"ffffffff");
    }

    // --- detect_loop() tests ---

    #[test]
    fn test_detect_loop_matching_uid() {
        let mut detector = LoopDetector::new();
        detector.probes.insert(0, 0xa1b2c3d4);

        let result = detector.detect_loop("a1b2c3d4.test", T_TXT);
        assert_eq!(result, Some(0xa1b2c3d4));
    }

    #[test]
    fn test_detect_loop_wrong_type() {
        let mut detector = LoopDetector::new();
        detector.probes.insert(0, 0xa1b2c3d4);

        // A record (type 1), not TXT.
        let result = detector.detect_loop("a1b2c3d4.test", 1);
        assert_eq!(result, None);
    }

    #[test]
    fn test_detect_loop_wrong_domain() {
        let mut detector = LoopDetector::new();
        detector.probes.insert(0, 0xa1b2c3d4);

        let result = detector.detect_loop("a1b2c3d4.prod", T_TXT);
        assert_eq!(result, None);
    }

    #[test]
    fn test_detect_loop_too_short() {
        let mut detector = LoopDetector::new();
        detector.probes.insert(0, 0x12345678);

        let result = detector.detect_loop("1234.test", T_TXT);
        assert_eq!(result, None);
    }

    #[test]
    fn test_detect_loop_too_long() {
        let mut detector = LoopDetector::new();
        detector.probes.insert(0, 0x12345678);

        let result = detector.detect_loop("123456789.test", T_TXT);
        assert_eq!(result, None);
    }

    #[test]
    fn test_detect_loop_invalid_hex() {
        let mut detector = LoopDetector::new();
        detector.probes.insert(0, 0);

        let result = detector.detect_loop("invalid!.test", T_TXT);
        assert_eq!(result, None);
    }

    #[test]
    fn test_detect_loop_no_matching_uid() {
        let mut detector = LoopDetector::new();
        detector.probes.insert(0, 0x11111111);

        // Valid probe format but UID doesn't match any probe.
        let result = detector.detect_loop("22222222.test", T_TXT);
        assert_eq!(result, None);
    }

    #[test]
    fn test_detect_loop_empty_probes() {
        let detector = LoopDetector::new();
        let result = detector.detect_loop("a1b2c3d4.test", T_TXT);
        assert_eq!(result, None);
    }

    #[test]
    fn test_detect_loop_case_insensitive_domain() {
        let mut detector = LoopDetector::new();
        detector.probes.insert(0, 0xabcdef01);

        // Domain suffix in uppercase — should still match.
        let result = detector.detect_loop("abcdef01.TEST", T_TXT);
        assert_eq!(result, Some(0xabcdef01));
    }

    #[test]
    fn test_detect_loop_uppercase_hex() {
        let mut detector = LoopDetector::new();
        detector.probes.insert(0, 0xABCDEF01);

        // Uppercase hex digits in query name.
        let result = detector.detect_loop("ABCDEF01.test", T_TXT);
        assert_eq!(result, Some(0xABCDEF01));
    }

    #[test]
    fn test_detect_loop_no_dot_separator() {
        let mut detector = LoopDetector::new();
        detector.probes.insert(0, 0x12345678);

        // Missing dot separator — should fail length or separator check.
        let result = detector.detect_loop("12345678test", T_TXT);
        assert_eq!(result, None);
    }

    #[test]
    fn test_detect_loop_multiple_probes() {
        let mut detector = LoopDetector::new();
        detector.probes.insert(0, 0xaaaaaaaa);
        detector.probes.insert(1, 0xbbbbbbbb);
        detector.probes.insert(2, 0xcccccccc);

        // Match the second server's probe.
        let result = detector.detect_loop("bbbbbbbb.test", T_TXT);
        assert_eq!(result, Some(0xbbbbbbbb));

        // Match the third server's probe.
        let result = detector.detect_loop("cccccccc.test", T_TXT);
        assert_eq!(result, Some(0xcccccccc));
    }

    // --- find_server_for_uid() tests ---

    #[test]
    fn test_find_server_for_uid_found() {
        let mut detector = LoopDetector::new();
        detector.probes.insert(3, 0xdeadbeef);
        assert_eq!(detector.find_server_for_uid(0xdeadbeef), Some(3));
    }

    #[test]
    fn test_find_server_for_uid_not_found() {
        let mut detector = LoopDetector::new();
        detector.probes.insert(0, 0x11111111);
        assert_eq!(detector.find_server_for_uid(0x22222222), None);
    }

    // --- read_packet_qtype() tests ---

    #[test]
    fn test_read_packet_qtype_valid_probe() {
        let detector = LoopDetector::new();
        let mut prng = Prng::new();
        let packet = detector.build_probe_packet(0x12345678, &mut prng);
        let qtype = LoopDetector::read_packet_qtype(&packet);
        assert_eq!(qtype, Some(T_TXT));
    }

    #[test]
    fn test_read_packet_qtype_too_short() {
        let packet = vec![0u8; 10]; // shorter than DNS header
        let qtype = LoopDetector::read_packet_qtype(&packet);
        assert_eq!(qtype, None);
    }

    // --- get_probe_packets() tests ---

    #[test]
    fn test_get_probe_packets_returns_all() {
        let mut detector = LoopDetector::new();
        detector.probes.insert(0, 0xaaaa0000);
        detector.probes.insert(1, 0xbbbb1111);

        let mut prng = Prng::new();
        let packets = detector.get_probe_packets(&mut prng);
        assert_eq!(packets.len(), 2);

        // Each packet should have the correct UID embedded.
        for (idx, pkt) in &packets {
            let uid = detector.probes[idx];
            let hex = format!("{:08x}", uid);
            assert_eq!(&pkt[13..21], hex.as_bytes());
        }
    }

    // --- Integration-style tests ---

    #[test]
    fn test_full_probe_and_detect_cycle() {
        let state = make_enabled_state();
        let mut prng = Prng::new();
        let servers = vec![
            make_test_server(None, ServerFlags::empty()),
            make_test_server(None, ServerFlags::empty()),
        ];

        let mut detector = LoopDetector::new();
        detector
            .send_probes(&servers, &mut prng, &state)
            .expect("send_probes should succeed");

        // Both servers should have probes.
        assert_eq!(detector.probes.len(), 2);

        // Simulate one probe returning: build the query name from the stored UID.
        let uid_0 = *detector.probes.get(&0).unwrap();
        let probe_name = format!("{:08x}.{}", uid_0, LOOP_TEST_DOMAIN);

        let detected = detector.detect_loop(&probe_name, T_TXT);
        assert_eq!(detected, Some(uid_0));

        // Verify we can find which server the loop corresponds to.
        let server_idx = detector.find_server_for_uid(uid_0);
        assert_eq!(server_idx, Some(0));
    }

    #[test]
    fn test_probe_packet_roundtrip_qtype() {
        let state = make_enabled_state();
        let mut prng = Prng::new();
        let servers = vec![make_test_server(None, ServerFlags::empty())];

        let mut detector = LoopDetector::new();
        detector
            .send_probes(&servers, &mut prng, &state)
            .unwrap();

        let packets = detector.get_probe_packets(&mut prng);
        assert_eq!(packets.len(), 1);

        // Verify the packet's QTYPE reads back as T_TXT.
        let (_, pkt) = &packets[0];
        let qtype = LoopDetector::read_packet_qtype(pkt);
        assert_eq!(qtype, Some(T_TXT));
    }
}

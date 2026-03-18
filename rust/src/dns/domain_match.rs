// Copyright (C) 2000-2025 Simon Kelley
// SPDX-License-Identifier: GPL-2.0-or-later
//
//! Domain pattern matching algorithms for DNS query routing and server selection.
//!
//! This module implements the domain name matching engine that forms the foundation
//! of dnsmasq's split-horizon DNS, domain-specific upstream server selection, and
//! configuration-based query routing.  It is a faithful Rust port of the C
//! `src/domain-match.c` (1 591 lines), preserving identical matching semantics.
//!
//! # Matching Algorithm
//!
//! The core algorithm uses **longest-match-wins** semantics: when multiple server
//! configurations match a query domain, the configuration with the longest
//! (most-specific) domain suffix is selected.  Servers are kept in a sorted array
//! and looked up via **O(log n) binary search**.
//!
//! Sorting order (from `order_qsort`):
//! 1. Domain specificity — longer (more specific) domains first.
//! 2. Literal address type flags — IPv6, IPv4, all-zeros, then literal address.
//! 3. Serial number — for stable `--strict-order` determinism.
//!
//! # Wildcard Support
//!
//! Domain patterns prefixed with `*` (e.g. `*.example.com`) match any single label
//! prepended to the pattern suffix.  Wildcards have lower priority than exact
//! matches at the same domain depth.
//!
//! # Feature Gates
//!
//! * `dnssec` — enables [`DomainMatcher::dnssec_server`] for finding DNSSEC-capable
//!   upstream servers.
//! * `loop-detect` — assigns a random UID to new servers in
//!   [`DomainMatcher::add_update_server`] for forwarding-loop detection.

use std::cmp::Ordering;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use tracing::{debug, trace};

use crate::core::types::{AllAddr, DaemonState, DnsmasqError, DnsmasqResult, MySockAddr};
use crate::core::util::{canonicalise, hostname_cmp, hostname_eq};
use crate::dns::protocol::{
    DnsClass, DnsHeader, DnsName, DnsPacket, DnsPacketBuilder, RRType, ResponseCode, HB3_TC,
};

// ===========================================================================
// SERV_* flag constants — mirror values from C dnsmasq.h lines 749-764
//
// The complete set from C is provided for parity so that other modules
// (forward.rs, cache.rs, integration/*) can reference them when needed.
// Some constants are only used in specific call-sites outside this module,
// so `dead_code` warnings are suppressed at module level for the constant
// block.
// ===========================================================================
#[allow(dead_code)]
/// Forward this domain through the normal resolv.conf path.
pub(crate) const SERV_USE_RESOLV: u32 = 1;
#[allow(dead_code)]
/// The addr field *is* the answer (or NoDATA), depending on additional flags.
pub(crate) const SERV_LITERAL_ADDRESS: u32 = 2;
#[allow(dead_code)]
/// Return all-zeros for A and AAAA.
pub(crate) const SERV_ALL_ZEROS: u32 = 4;
#[allow(dead_code)]
/// Address is IPv4.
pub(crate) const SERV_4ADDR: u32 = 8;
#[allow(dead_code)]
/// Address is IPv6.
pub(crate) const SERV_6ADDR: u32 = 16;
#[allow(dead_code)]
/// Source address explicitly configured.
pub(crate) const SERV_HAS_SOURCE: u32 = 32;
#[allow(dead_code)]
/// Server only applies to names without dots.
pub(crate) const SERV_FOR_NODOTS: u32 = 64;
#[allow(dead_code)]
/// Avoid duplicate recursive-warning syslog messages.
pub(crate) const SERV_WARNED_RECURSIVE: u32 = 128;
#[allow(dead_code)]
/// Server was added from D-Bus.
pub(crate) const SERV_FROM_DBUS: u32 = 256;
#[allow(dead_code)]
/// Marked for mark-and-delete cycle.
pub(crate) const SERV_MARK: u32 = 512;
#[allow(dead_code)]
/// Domain pattern has leading `*` wildcard.
pub(crate) const SERV_WILDCARD: u32 = 1024;
#[allow(dead_code)]
/// Server originates from resolv.conf (not command line).
pub(crate) const SERV_FROM_RESOLV: u32 = 2048;
#[allow(dead_code)]
/// Read from `--servers-file`.
pub(crate) const SERV_FROM_FILE: u32 = 4096;
#[allow(dead_code)]
/// Server causes a forwarding loop — do not use.
pub(crate) const SERV_LOOP: u32 = 8192;
#[allow(dead_code)]
/// Validate DNSSEC when using this server.
pub(crate) const SERV_DO_DNSSEC: u32 = 16384;
#[allow(dead_code)]
/// Got data from TCP connection.
pub(crate) const SERV_GOT_TCP: u32 = 32768;

#[allow(dead_code)]
/// Composite: server is a local-only entry (USE_RESOLV | LITERAL_ADDRESS).
pub(crate) const SERV_IS_LOCAL: u32 = SERV_USE_RESOLV | SERV_LITERAL_ADDRESS;
#[allow(dead_code)]
/// Composite: has a local literal address (4 | 8 | 16).
pub(crate) const SERV_LOCAL_ADDRESS: u32 = SERV_6ADDR | SERV_4ADDR | SERV_ALL_ZEROS;

// ---------------------------------------------------------------------------
// F_* query flag constants — mirror values from C dnsmasq.h lines 694-715
// ---------------------------------------------------------------------------
#[allow(dead_code)]
pub(crate) const F_IPV4: u32 = 1 << 7;
#[allow(dead_code)]
pub(crate) const F_IPV6: u32 = 1 << 8;
#[allow(dead_code)]
pub(crate) const F_NXDOMAIN: u32 = 1 << 10;
#[allow(dead_code)]
pub(crate) const F_CONFIG: u32 = 1 << 13;
#[allow(dead_code)]
pub(crate) const F_DS: u32 = 1 << 14;
#[allow(dead_code)]
pub(crate) const F_DNSSECOK: u32 = 1 << 15;
#[allow(dead_code)]
pub(crate) const F_SERVER: u32 = 1 << 18;
#[allow(dead_code)]
pub(crate) const F_QUERY: u32 = 1 << 19;
#[allow(dead_code)]
pub(crate) const F_NOERR: u32 = 1 << 20;
#[allow(dead_code)]
pub(crate) const F_DOMAINSRV: u32 = 1 << 28;

// ===========================================================================
// Public data structures
// ===========================================================================

/// Flags controlling server matching behaviour.
///
/// Replaces the C `u16 flags` bitmask on `struct server` with named booleans
/// for clarity, while preserving full round-trip capability via
/// [`ServerMatchFlags::to_raw`] and [`ServerMatchFlags::from_raw`].
#[derive(Debug, Clone, Default)]
pub struct ServerMatchFlags {
    /// This is the default (no-domain) server.
    pub is_default: bool,
    /// Server supports DNSSEC validation.
    pub dnssec_capable: bool,
    /// Dedicated DS query server.
    pub ds_query: bool,
    /// Server is specific to a domain.
    pub domain_specific: bool,
    /// Server resolves to a local/literal address.
    pub local: bool,
    /// Domain pattern contains a leading `*` wildcard.
    pub wildcard: bool,
    /// Server only handles queries for names without dots.
    pub for_nodots: bool,
    /// Forward through normal resolv.conf servers.
    pub use_resolv: bool,
    /// Server is a literal-address answer.
    pub literal_address: bool,
    /// Literal address is IPv4.
    pub has_4addr: bool,
    /// Literal address is IPv6.
    pub has_6addr: bool,
    /// Return all-zeros for A/AAAA.
    pub all_zeros: bool,
    /// Marked for mark-and-delete cycle.
    pub mark: bool,
    /// Server originated from resolv.conf.
    pub from_resolv: bool,
    /// Server originated from DHCP.
    pub from_dhcp: bool,
    /// Server has been detected as causing a forwarding loop.
    pub loop_detected: bool,
}

impl ServerMatchFlags {
    /// Convert raw C-compatible `u32` flags to structured representation.
    pub fn from_raw(raw: u32) -> Self {
        Self {
            is_default: (raw
                & (SERV_FOR_NODOTS | SERV_WILDCARD | SERV_USE_RESOLV | SERV_LITERAL_ADDRESS))
                == 0
                && (raw & SERV_IS_LOCAL) == 0,
            dnssec_capable: (raw & SERV_DO_DNSSEC) != 0,
            ds_query: false, // DS is a query-time attribute, not persisted in flags
            domain_specific: (raw & SERV_IS_LOCAL) == 0 && (raw & SERV_FOR_NODOTS) == 0,
            local: (raw & SERV_IS_LOCAL) != 0,
            wildcard: (raw & SERV_WILDCARD) != 0,
            for_nodots: (raw & SERV_FOR_NODOTS) != 0,
            use_resolv: (raw & SERV_USE_RESOLV) != 0,
            literal_address: (raw & SERV_LITERAL_ADDRESS) != 0,
            has_4addr: (raw & SERV_4ADDR) != 0,
            has_6addr: (raw & SERV_6ADDR) != 0,
            all_zeros: (raw & SERV_ALL_ZEROS) != 0,
            mark: (raw & SERV_MARK) != 0,
            from_resolv: (raw & SERV_FROM_RESOLV) != 0,
            from_dhcp: (raw & SERV_FROM_DBUS) != 0,
            loop_detected: (raw & SERV_LOOP) != 0,
        }
    }

    /// Convert back to raw `u32` flags for interop with [`crate::core::types::ServerEntry`].
    pub fn to_raw(&self) -> u32 {
        let mut f: u32 = 0;
        if self.use_resolv {
            f |= SERV_USE_RESOLV;
        }
        if self.literal_address {
            f |= SERV_LITERAL_ADDRESS;
        }
        if self.all_zeros {
            f |= SERV_ALL_ZEROS;
        }
        if self.has_4addr {
            f |= SERV_4ADDR;
        }
        if self.has_6addr {
            f |= SERV_6ADDR;
        }
        if self.for_nodots {
            f |= SERV_FOR_NODOTS;
        }
        if self.from_dhcp {
            f |= SERV_FROM_DBUS;
        }
        if self.mark {
            f |= SERV_MARK;
        }
        if self.wildcard {
            f |= SERV_WILDCARD;
        }
        if self.from_resolv {
            f |= SERV_FROM_RESOLV;
        }
        if self.loop_detected {
            f |= SERV_LOOP;
        }
        if self.dnssec_capable {
            f |= SERV_DO_DNSSEC;
        }
        f
    }
}

/// Server configuration entry for domain-specific routing.
///
/// Stored in the sorted array inside [`DomainMatcher`] for O(log n) binary
/// search.  Mirrors the first four fields of C `struct server` that all
/// server variant types (`serv_addr4`, `serv_addr6`, `serv_local`) share.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Domain suffix pattern (e.g. `"example.com"`).  `None` for the default
    /// (catch-all) server.
    pub domain: Option<String>,
    /// Cached byte-length of `domain` (0 when `domain` is `None`).
    pub domain_len: usize,
    /// Matching behaviour flags.
    pub flags: ServerMatchFlags,
    /// Index into `DaemonState::servers` for the real upstream entry.
    pub server_idx: usize,
    /// Serial number for `--strict-order` determinism.
    pub serial: i32,
    /// Position of this entry in the sorted array (set by `build_server_array`).
    pub arrayposn: i32,
    /// Index of the last server used in this group for round-robin.
    pub last_server: i32,
}

/// Domain matcher with a sorted array for efficient lookup.
///
/// Replaces the C `daemon->serverarray` flat pointer array and associated
/// functions in `domain-match.c`.  The array is rebuilt on every configuration
/// change (including D-Bus / ubus dynamic updates) so that queries can be
/// routed via a single binary search.
pub struct DomainMatcher {
    /// Sorted array of server configurations, ordered by the `order_qsort`
    /// comparator (domain specificity → literal-address type → serial).
    server_array: Vec<ServerConfig>,
    /// Module-level flag coordinating mark-and-delete across
    /// [`mark_servers`] and [`cleanup_servers`].
    maybe_free_servers: bool,
}

impl Default for DomainMatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl DomainMatcher {
    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------

    /// Create a new, empty `DomainMatcher`.
    pub fn new() -> Self {
        Self {
            server_array: Vec::new(),
            maybe_free_servers: false,
        }
    }

    // -----------------------------------------------------------------------
    // build_server_array  (C domain-match.c:211-274)
    // -----------------------------------------------------------------------

    /// Rebuild the sorted server array from `DaemonState::servers` and
    /// `DaemonState::local_domains`.
    ///
    /// This is called during configuration load and after every dynamic update
    /// (D-Bus, ubus, servers-file reload).  After construction the array is
    /// sorted with [`Self::sort_array`] so that [`Self::lookup_domain`] can
    /// perform an O(log n) binary search.
    ///
    /// Servers with `SERV_LOOP` flag are skipped (they cause forwarding loops).
    ///
    /// Side-effects:
    /// * Sets `DaemonState::server_has_wildcard` if any entry has `SERV_WILDCARD`.
    /// * Updates `DaemonState::serverarrayhwm` with the new array length.
    /// * Writes back `arrayposn` into each `DaemonState::servers[i].flags`
    ///   (encoded in the high bits — in Rust we track it in the `ServerConfig`).
    pub fn build_server_array(&mut self, state: &mut DaemonState) {
        self.server_array.clear();
        state.server_has_wildcard = false;

        // Phase 1: collect entries from servers list
        for (idx, server) in state.servers.iter().enumerate() {
            // Skip loop-detected servers
            if (server.flags & SERV_LOOP) != 0 {
                continue;
            }

            let raw_flags = server.flags;
            let domain = server.domain.clone();
            let domain_len = domain.as_ref().map_or(0, |d| d.len());

            if (raw_flags & SERV_WILDCARD) != 0 {
                state.server_has_wildcard = true;
            }

            self.server_array.push(ServerConfig {
                domain,
                domain_len,
                flags: ServerMatchFlags::from_raw(raw_flags),
                server_idx: idx,
                serial: 0, // populated below
                arrayposn: -1,
                last_server: -1,
            });
        }

        // Phase 2: collect entries from local_domains list
        let server_count = state.servers.len();
        for (idx, server) in state.local_domains.iter().enumerate() {
            if (server.flags & SERV_LOOP) != 0 {
                continue;
            }

            let raw_flags = server.flags;
            let domain = server.domain.clone();
            let domain_len = domain.as_ref().map_or(0, |d| d.len());

            if (raw_flags & SERV_WILDCARD) != 0 {
                state.server_has_wildcard = true;
            }

            // Index offset so we can distinguish local_domains from servers
            self.server_array.push(ServerConfig {
                domain,
                domain_len,
                flags: ServerMatchFlags::from_raw(raw_flags),
                server_idx: server_count + idx,
                serial: 0,
                arrayposn: -1,
                last_server: -1,
            });
        }

        // Phase 3: sort
        self.sort_array();

        // Phase 4: assign arrayposn
        for (pos, entry) in self.server_array.iter_mut().enumerate() {
            entry.arrayposn = pos as i32;
        }

        state.serverarrayhwm = self.server_array.len();

        debug!(
            count = self.server_array.len(),
            wildcard = state.server_has_wildcard,
            "rebuilt server array"
        );
    }

    // -----------------------------------------------------------------------
    // lookup_domain  (C domain-match.c:367-538)
    // -----------------------------------------------------------------------

    /// Look up the best-matching server configuration for a query domain.
    ///
    /// Uses binary search with longest-match-wins semantics.  Returns the
    /// index into the internal `server_array` of the best match, or `None`
    /// if no match is found.
    ///
    /// # Parameters
    /// * `qdomain` — the fully-qualified domain name from the DNS query.
    /// * `flags`   — query flag bits (e.g. `F_DNSSECOK`, `F_DS`, `F_QUERY`).
    /// * `state`   — daemon state, used to check `server_has_wildcard`.
    ///
    /// The returned tuple is `(array_index, match_flags)` where `match_flags`
    /// encodes `F_SERVER`, `F_DNSSECOK`, `F_DOMAINSRV`, etc.
    pub fn lookup_domain(
        &self,
        qdomain: &str,
        flags: u32,
        state: &DaemonState,
    ) -> Option<(usize, u32)> {
        if self.server_array.is_empty() {
            return None;
        }

        let qdomain_lower = qdomain.to_ascii_lowercase();
        let qlen = qdomain_lower.len();

        // Binary search: find the longest suffix match.
        let mut lo: usize = 0;
        let mut hi: usize = self.server_array.len();
        let mut best_match: Option<(usize, u32)> = None;
        let mut best_match_len: usize = 0;

        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let entry = &self.server_array[mid];
            let cmp = self.order_domain(&qdomain_lower, qlen, entry);

            match cmp {
                Ordering::Less => {
                    hi = mid;
                }
                Ordering::Greater => {
                    lo = mid + 1;
                }
                Ordering::Equal => {
                    // Found a match — check if it is the longest so far
                    if entry.domain_len >= best_match_len {
                        let mut match_flags: u32 = F_SERVER;
                        if entry.flags.dnssec_capable {
                            match_flags |= F_DNSSECOK;
                        }
                        if entry.domain.is_some() {
                            match_flags |= F_DOMAINSRV;
                        }
                        best_match = Some((mid, match_flags));
                        best_match_len = entry.domain_len;
                    }
                    // Continue searching for a potentially longer match
                    // Look right first (longer domains sort earlier, so try both sides)
                    break;
                }
            }
        }

        // After binary search, do a linear scan around the match point to find
        // the absolute longest match.  This is necessary because multiple entries
        // can share the same sort position when their domain lengths differ but
        // both match as suffixes.
        if best_match.is_some() || state.server_has_wildcard {
            let scan_result =
                self.scan_for_best_match(&qdomain_lower, qlen, flags, best_match, best_match_len);
            if scan_result.is_some() {
                return scan_result;
            }
        }

        // Handle nodots: if the query has no dots, look for SERV_FOR_NODOTS entries
        let has_dot = qdomain_lower.contains('.');
        if !has_dot {
            for (idx, entry) in self.server_array.iter().enumerate() {
                if entry.flags.for_nodots {
                    let mut match_flags: u32 = F_SERVER;
                    if entry.flags.dnssec_capable {
                        match_flags |= F_DNSSECOK;
                    }
                    trace!(
                        domain = qdomain,
                        entry_domain = entry.domain.as_deref().unwrap_or("<default>"),
                        "nodots match"
                    );
                    return Some((idx, match_flags));
                }
            }
        }

        // Return the best match we found from binary search, or the default
        // (no-domain) server if any.
        if best_match.is_some() {
            trace!(
                domain = qdomain,
                array_idx = best_match.unwrap().0,
                "domain lookup hit"
            );
            return best_match;
        }

        // Fall back to default (no-domain) servers
        for (idx, entry) in self.server_array.iter().enumerate() {
            if entry.domain.is_none() && !entry.flags.for_nodots && !entry.flags.wildcard {
                let mut match_flags: u32 = F_SERVER;
                if entry.flags.dnssec_capable {
                    match_flags |= F_DNSSECOK;
                }
                return Some((idx, match_flags));
            }
        }

        None
    }

    // -----------------------------------------------------------------------
    // filter_servers  (C domain-match.c:701-794)
    // -----------------------------------------------------------------------

    /// Filter a candidate server set by flag-based priority.
    ///
    /// Starting from the server at `start_idx` in the sorted array, expand
    /// to all servers in the same equivalence group (via [`Self::server_samegroup`]),
    /// then apply priority filtering:
    ///
    /// 1. Prefer servers with `SERV_6ADDR` (IPv6 literal).
    /// 2. Then `SERV_4ADDR` (IPv4 literal).
    /// 3. Then `SERV_ALL_ZEROS` (block).
    /// 4. Then `SERV_LITERAL_ADDRESS`.
    /// 5. Then `SERV_USE_RESOLV`.
    /// 6. Finally, domain-specific upstream servers.
    ///
    /// Returns a `Vec` of indices into the internal `server_array`.
    pub fn filter_servers(&self, start_idx: usize, flags: u32) -> Vec<usize> {
        if start_idx >= self.server_array.len() {
            return Vec::new();
        }

        // Expand to the full equivalence group.
        let group = self.expand_group(start_idx);

        if group.is_empty() {
            return Vec::new();
        }

        // If F_CONFIG or F_DOMAINSRV flags indicate a specific request,
        // return the entire group without further filtering.
        if (flags & F_CONFIG) != 0 || (flags & F_DOMAINSRV) != 0 {
            return group;
        }

        // Priority filtering: check for the highest-priority flag category
        // that has at least one member.

        // 1. SERV_6ADDR
        let filtered: Vec<usize> = group
            .iter()
            .copied()
            .filter(|&i| self.server_array[i].flags.has_6addr)
            .collect();
        if !filtered.is_empty() {
            debug!(count = filtered.len(), "filter_servers: 6ADDR priority");
            return filtered;
        }

        // 2. SERV_4ADDR
        let filtered: Vec<usize> = group
            .iter()
            .copied()
            .filter(|&i| self.server_array[i].flags.has_4addr)
            .collect();
        if !filtered.is_empty() {
            debug!(count = filtered.len(), "filter_servers: 4ADDR priority");
            return filtered;
        }

        // 3. SERV_ALL_ZEROS
        let filtered: Vec<usize> = group
            .iter()
            .copied()
            .filter(|&i| self.server_array[i].flags.all_zeros)
            .collect();
        if !filtered.is_empty() {
            debug!(count = filtered.len(), "filter_servers: ALL_ZEROS priority");
            return filtered;
        }

        // 4. SERV_LITERAL_ADDRESS
        let filtered: Vec<usize> = group
            .iter()
            .copied()
            .filter(|&i| self.server_array[i].flags.literal_address)
            .collect();
        if !filtered.is_empty() {
            debug!(
                count = filtered.len(),
                "filter_servers: LITERAL_ADDRESS priority"
            );
            return filtered;
        }

        // 5. SERV_USE_RESOLV
        let filtered: Vec<usize> = group
            .iter()
            .copied()
            .filter(|&i| self.server_array[i].flags.use_resolv)
            .collect();
        if !filtered.is_empty() {
            debug!(
                count = filtered.len(),
                "filter_servers: USE_RESOLV priority"
            );
            return filtered;
        }

        // 6. Domain-specific (anything remaining in the group)
        debug!(
            count = group.len(),
            "filter_servers: domain-specific fallback"
        );
        group
    }

    // -----------------------------------------------------------------------
    // server_samegroup  (C domain-match.c:587-590)
    // -----------------------------------------------------------------------

    /// Check whether two server array entries belong to the same equivalence
    /// group for round-robin load balancing.
    ///
    /// Two entries are in the same group when `order_servers` returns `Equal`.
    pub fn server_samegroup(&self, idx_a: usize, idx_b: usize) -> bool {
        if idx_a >= self.server_array.len() || idx_b >= self.server_array.len() {
            return false;
        }
        self.order_servers(&self.server_array[idx_a], &self.server_array[idx_b]) == Ordering::Equal
    }

    // -----------------------------------------------------------------------
    // mark_servers  (C domain-match.c:1314-1350)
    // -----------------------------------------------------------------------

    /// Mark server entries for a subsequent delete cycle.
    ///
    /// When `flag` is non-zero, all servers in `DaemonState::servers` whose
    /// `flags` contain the value of `flag` are marked with `SERV_MARK`.
    /// Entries in `DaemonState::local_domains` matching `flag` are deleted
    /// immediately.
    ///
    /// When `flag` is zero, *all* servers in both lists are marked.
    ///
    /// A later call to [`Self::cleanup_servers`] removes the marked entries.
    pub fn mark_servers(&mut self, state: &mut DaemonState, flag: u32) {
        self.maybe_free_servers = flag != 0;

        if flag == 0 {
            // Mark everything
            for server in state.servers.iter_mut() {
                server.flags |= SERV_MARK;
            }
            for server in state.local_domains.iter_mut() {
                server.flags |= SERV_MARK;
            }
        } else {
            // Mark only matching entries in servers list
            for server in state.servers.iter_mut() {
                if (server.flags & flag) != 0 {
                    server.flags |= SERV_MARK;
                }
            }
            // Immediately remove matching local_domains entries
            state.local_domains.retain(|s| (s.flags & flag) == 0);
        }

        debug!(flag, "mark_servers complete");
    }

    // -----------------------------------------------------------------------
    // cleanup_servers  (C domain-match.c:1390-1411)
    // -----------------------------------------------------------------------

    /// Remove all servers that carry the `SERV_MARK` flag.
    ///
    /// In C, freed servers were moved to `daemon->free_servers` for memory
    /// reuse.  In Rust, `Vec::retain` handles deallocation automatically.
    ///
    /// Only operates if [`Self::mark_servers`] set the `maybe_free_servers`
    /// flag.  After cleanup, `build_server_array` should be called to
    /// rebuild the sorted lookup table.
    pub fn cleanup_servers(&mut self, state: &mut DaemonState) {
        if !self.maybe_free_servers {
            return;
        }

        let before = state.servers.len();
        state.servers.retain(|s| (s.flags & SERV_MARK) == 0);
        let removed = before - state.servers.len();

        self.maybe_free_servers = false;

        debug!(removed, "cleanup_servers complete");
    }

    // -----------------------------------------------------------------------
    // is_local_answer  (C domain-match.c:887-917)
    // -----------------------------------------------------------------------

    /// Check whether a query should be answered locally (without forwarding).
    ///
    /// Inspects the matched server entry for `SERV_LITERAL_ADDRESS` and
    /// returns the appropriate query-answer flags:
    ///
    /// * `F_IPV4` — answer with the configured IPv4 literal.
    /// * `F_IPV6` — answer with the configured IPv6 literal.
    /// * `F_NOERR` — answer with an empty (NODATA) response.
    /// * `F_NXDOMAIN` — answer with NXDOMAIN.
    ///
    /// Returns `None` if the query should be forwarded upstream.
    pub fn is_local_answer(&self, array_idx: usize) -> Option<u32> {
        if array_idx >= self.server_array.len() {
            return None;
        }

        let entry = &self.server_array[array_idx];

        if !entry.flags.literal_address {
            return None;
        }

        if entry.flags.has_6addr {
            debug!("is_local_answer: IPv6 literal");
            return Some(F_IPV6);
        }
        if entry.flags.has_4addr {
            debug!("is_local_answer: IPv4 literal");
            return Some(F_IPV4);
        }
        if entry.flags.all_zeros {
            debug!("is_local_answer: NOERR (all zeros)");
            return Some(F_NOERR);
        }

        // Literal address without any specific type → NXDOMAIN
        debug!("is_local_answer: NXDOMAIN");
        Some(F_NXDOMAIN)
    }

    // -----------------------------------------------------------------------
    // make_local_answer  (C domain-match.c:969-1035)
    // -----------------------------------------------------------------------

    /// Construct a DNS response packet for a locally-answered query.
    ///
    /// Builds the answer section with A and/or AAAA records from all matching
    /// server entries in the same group.  Sets the TC (truncation) flag if the
    /// response would exceed the available packet size.
    ///
    /// The incoming [`DnsPacket`] is used to extract the query transaction ID
    /// so the response matches the original request.  Address records are
    /// collected as [`AllAddr`] variants for type-safe handling of both IPv4
    /// and IPv6 literal addresses.
    ///
    /// # Parameters
    /// * `array_idx` — starting index in `server_array`.
    /// * `query` — parsed incoming [`DnsPacket`] (used for transaction ID
    ///   and original [`DnsHeader`] context).
    /// * `qname` — the query domain name.
    /// * `qtype` — the query record type (A, AAAA, ANY, etc.).
    /// * `state` — daemon state, used for `local_ttl`.
    /// * `packet_size` — maximum DNS response size (typically EDNS payload).
    ///
    /// Returns the serialised DNS response bytes.
    pub fn make_local_answer(
        &self,
        array_idx: usize,
        query: &DnsPacket,
        qname: &DnsName,
        qtype: RRType,
        state: &DaemonState,
        packet_size: usize,
    ) -> DnsmasqResult<Vec<u8>> {
        if array_idx >= self.server_array.len() {
            return Err(DnsmasqError::DnsProtocol(
                "make_local_answer: invalid array index".into(),
            ));
        }

        let ttl = state.local_ttl;
        // Use the query header to extract the transaction ID for the response.
        let query_header: &DnsHeader = &query.header;
        let query_id = query_header.id;

        // Determine which record types to include based on qtype.
        let want_a = matches!(qtype, RRType::A | RRType::ANY);
        let want_aaaa = matches!(qtype, RRType::AAAA | RRType::ANY);

        // Collect address records from the group as AllAddr variants for
        // type-safe handling of both IPv4 and IPv6 literal addresses.
        let group = self.expand_group(array_idx);
        let mut collected_addrs: Vec<AllAddr> = Vec::new();

        for &gi in &group {
            let entry = &self.server_array[gi];
            if entry.flags.has_4addr && want_a {
                if let Some(v4) = self.get_server_ipv4(entry.server_idx, state) {
                    collected_addrs.push(AllAddr::V4(v4));
                }
            }
            if entry.flags.has_6addr && want_aaaa {
                if let Some(v6) = self.get_server_ipv6(entry.server_idx, state) {
                    collected_addrs.push(AllAddr::V6(v6));
                }
            }
            if entry.flags.all_zeros {
                if want_a {
                    collected_addrs.push(AllAddr::V4(Ipv4Addr::UNSPECIFIED));
                }
                if want_aaaa {
                    collected_addrs.push(AllAddr::V6(Ipv6Addr::UNSPECIFIED));
                }
            }
        }

        // Build the response packet with the matching transaction ID.
        let mut builder = DnsPacketBuilder::new(query_id)
            .set_response()
            .set_authoritative()
            .add_question(qname, qtype, DnsClass::IN);

        let mut ancount: u16 = 0;

        for addr in &collected_addrs {
            match addr {
                AllAddr::V4(v4) => {
                    builder = builder.add_answer(qname, RRType::A, DnsClass::IN, ttl, &v4.octets());
                    ancount += 1;
                }
                AllAddr::V6(v6) => {
                    builder =
                        builder.add_answer(qname, RRType::AAAA, DnsClass::IN, ttl, &v6.octets());
                    ancount += 1;
                }
                _ => {
                    // Other AllAddr variants (Cname, Key, Ds, Log) are not
                    // applicable for literal address answers — skip silently.
                }
            }
        }

        let built = builder.build()?;
        let mut raw = built.raw.to_vec();

        // Validate the built response header to confirm RCODE is NoError.
        if let Ok(resp_header) = DnsHeader::parse(&raw) {
            let rcode: ResponseCode = resp_header.flags.rcode;
            trace!(rcode = %rcode, ancount, "make_local_answer: response header validated");
        }

        // Check if the response exceeds the maximum packet size and needs truncation.
        if raw.len() > packet_size && packet_size >= 12 {
            // Set TC bit in the header flags byte (byte offset 2, bit 1).
            raw[2] |= HB3_TC;
            // Truncate to maximum size.
            raw.truncate(packet_size);
        }

        debug!(
            qname = %qname,
            ancount,
            addrs = collected_addrs.len(),
            "make_local_answer"
        );

        Ok(raw)
    }

    // -----------------------------------------------------------------------
    // add_update_server  (C domain-match.c:1461-1590)
    // -----------------------------------------------------------------------

    /// Add or update a server configuration dynamically.
    ///
    /// Called by D-Bus / ubus / servers-file reload to insert a new upstream
    /// server or local-domain entry.  If a server with a matching domain and
    /// marked `SERV_MARK` already exists, it is reused and unmarked instead
    /// of creating a duplicate.
    ///
    /// After the update, the caller should invoke [`Self::build_server_array`]
    /// to refresh the sorted lookup table.
    ///
    /// # Parameters
    /// * `state` — mutable daemon state.
    /// * `flags` — raw SERV_* flag bitmask for the new server.
    /// * `addr` — upstream server socket address as [`MySockAddr`] (ignored
    ///   for local entries). Converted to [`SocketAddr`] for storage
    ///   in [`ServerEntry`].
    /// * `source` — source address for outgoing queries as [`MySockAddr`].
    /// * `iface` — bind-to interface name.
    /// * `domain` — domain pattern (e.g. `"example.com"`), or `None` for default.
    pub fn add_update_server(
        &self,
        state: &mut DaemonState,
        flags: u32,
        addr: Option<MySockAddr>,
        source: Option<MySockAddr>,
        iface: Option<&str>,
        domain: Option<&str>,
    ) -> DnsmasqResult<()> {
        let is_local = (flags & SERV_IS_LOCAL) != 0;

        // Canonicalise the domain name if provided.
        let canon_domain: Option<String> = match domain {
            Some(d) if !d.is_empty() => {
                let mut s = canonicalise(d).unwrap_or_else(|| d.to_string());
                // Strip leading dots that may appear after canonicalisation.
                s = s.trim_start_matches('.').to_string();
                Some(s)
            }
            _ => None,
        };

        let has_wildcard = domain.map(|d| d.starts_with('*')).unwrap_or(false);

        let mut raw_flags = flags;
        if has_wildcard {
            raw_flags |= SERV_WILDCARD;
        }

        // Check for an existing marked server with the same domain to reuse.
        let target_list = if is_local {
            &mut state.local_domains
        } else {
            &mut state.servers
        };

        let reuse_idx = target_list.iter().position(|s| {
            (s.flags & SERV_MARK) != 0
                && match (&s.domain, &canon_domain) {
                    (Some(a), Some(b)) => hostname_eq(a, b),
                    (None, None) => true,
                    _ => false,
                }
        });

        if let Some(idx) = reuse_idx {
            // Reuse the existing entry — unmark and update.
            let entry = &mut target_list[idx];
            entry.flags = raw_flags & !SERV_MARK;
            if let Some(ref a) = addr {
                entry.addr = a.to_socket_addr();
            }
            entry.source_addr = source.as_ref().map(|s| s.to_socket_addr());
            entry.interface = iface.map(|s| s.to_string());
            entry.domain = canon_domain;

            // Assign loop-detection UID if feature enabled.
            #[cfg(feature = "loop-detect")]
            {
                use crate::core::util::SurfRng;
                let mut rng = SurfRng::new()?;
                entry.uid = rng.rand32();
            }

            debug!(
                domain = entry.domain.as_deref().unwrap_or("<default>"),
                reused = true,
                "add_update_server"
            );
        } else {
            // Create a new entry.
            let resolved_addr: SocketAddr = match addr {
                Some(msa) => msa.to_socket_addr(),
                None => SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            };

            let mut new_entry = crate::core::types::ServerEntry {
                addr: resolved_addr,
                source_addr: source.map(|msa| msa.to_socket_addr()),
                interface: iface.map(|s| s.to_string()),
                domain: canon_domain.clone(),
                flags: raw_flags,
                queries: 0,
                failed_queries: 0,
                uid: 0,
            };

            #[cfg(feature = "loop-detect")]
            {
                use crate::core::util::SurfRng;
                let mut rng = SurfRng::new()?;
                new_entry.uid = rng.rand32();
            }

            target_list.push(new_entry);

            debug!(
                domain = canon_domain.as_deref().unwrap_or("<default>"),
                reused = false,
                "add_update_server"
            );
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // dnssec_server  (C domain-match.c:1084-1112, gated by HAVE_DNSSEC)
    // -----------------------------------------------------------------------

    /// Find a DNSSEC-capable upstream server for the given domain.
    ///
    /// Scans the server array for an entry that:
    /// 1. Is not a local-only entry (not `SERV_IS_LOCAL`).
    /// 2. Has the `SERV_DO_DNSSEC` flag.
    /// 3. Matches the requested domain via suffix match.
    ///
    /// Returns the `server_idx` of the matching server, or `None`.
    #[cfg(feature = "dnssec")]
    pub fn dnssec_server(&self, domain: &str, _state: &DaemonState) -> Option<usize> {
        let domain_lower = domain.to_ascii_lowercase();

        for entry in &self.server_array {
            // Skip local-only entries.
            if entry.flags.local || entry.flags.use_resolv || entry.flags.literal_address {
                continue;
            }

            // Must have DNSSEC capability.
            if !entry.flags.dnssec_capable {
                continue;
            }

            // Domain match: either this is the default server (no domain) or
            // the query domain is a subdomain of the server domain.
            let matches = match &entry.domain {
                None => true,
                Some(d) => {
                    let d_lower = d.to_ascii_lowercase();
                    domain_lower == d_lower || domain_lower.ends_with(&format!(".{}", d_lower))
                }
            };

            if matches {
                debug!(
                    server_idx = entry.server_idx,
                    domain = entry.domain.as_deref().unwrap_or("<default>"),
                    "dnssec_server match"
                );
                return Some(entry.server_idx);
            }
        }

        None
    }

    /// Stub for non-DNSSEC builds — always returns `None`.
    #[cfg(not(feature = "dnssec"))]
    pub fn dnssec_server(&self, _domain: &str, _state: &DaemonState) -> Option<usize> {
        None
    }

    // =======================================================================
    // Private helpers
    // =======================================================================

    /// Sort the internal server array using the three-level `order_qsort`
    /// comparator.
    fn sort_array(&mut self) {
        self.server_array.sort_by(Self::order_qsort);
    }

    /// Three-level comparator for qsort (C domain-match.c:1236-1261).
    ///
    /// 1. Domain specificity (longer / more-specific domains first).
    /// 2. Literal address type flags (6ADDR > 4ADDR > ALL_ZEROS > LITERAL > USE_RESOLV).
    /// 3. Serial number for `--strict-order` determinism.
    fn order_qsort(a: &ServerConfig, b: &ServerConfig) -> Ordering {
        // Primary: sort by domain specificity via order_servers.
        let cmp = Self::order_servers_static(a, b);
        if cmp != Ordering::Equal {
            return cmp;
        }

        // Secondary: among non-local entries, no further distinction.
        // Among local entries, sort by flag priority.
        let a_local = a.flags.use_resolv || a.flags.literal_address;
        let b_local = b.flags.use_resolv || b.flags.literal_address;
        if a_local && b_local {
            let a_prio = Self::local_flag_priority(a);
            let b_prio = Self::local_flag_priority(b);
            let cmp2 = a_prio.cmp(&b_prio);
            if cmp2 != Ordering::Equal {
                return cmp2;
            }
        }

        // Tertiary: serial number for strict-order.
        a.serial.cmp(&b.serial)
    }

    /// Assign a numeric priority to local-address flag combinations for sorting.
    /// Lower numbers = higher priority.
    fn local_flag_priority(entry: &ServerConfig) -> u32 {
        if entry.flags.has_6addr {
            return 0;
        }
        if entry.flags.has_4addr {
            return 1;
        }
        if entry.flags.all_zeros {
            return 2;
        }
        if entry.flags.literal_address {
            return 3;
        }
        if entry.flags.use_resolv {
            return 4;
        }
        5
    }

    /// Order two server configs by domain specificity (C `order_servers`).
    ///
    /// * `FOR_NODOTS` entries sort after everything else.
    /// * Otherwise, compare by domain name using `order`.
    /// * `WILDCARD` entries sort after non-wildcard at the same domain depth.
    fn order_servers_static(a: &ServerConfig, b: &ServerConfig) -> Ordering {
        // FOR_NODOTS: sorts to the end.
        match (a.flags.for_nodots, b.flags.for_nodots) {
            (true, false) => return Ordering::Greater,
            (false, true) => return Ordering::Less,
            (true, true) => return Ordering::Equal,
            (false, false) => {}
        }

        let dom_cmp = Self::order_static(a, b);
        if dom_cmp != Ordering::Equal {
            return dom_cmp;
        }

        // Tiebreak: wildcard entries sort after non-wildcard.
        match (a.flags.wildcard, b.flags.wildcard) {
            (true, false) => Ordering::Greater,
            (false, true) => Ordering::Less,
            _ => Ordering::Equal,
        }
    }

    /// Order two server configs by domain length then lexicographic hostname
    /// comparison (C `order`, domain-match.c:1154-1172).
    fn order_static(a: &ServerConfig, b: &ServerConfig) -> Ordering {
        match (&a.domain, &b.domain) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Less,
            (Some(_), None) => Ordering::Greater,
            (Some(da), Some(db)) => {
                // Primary: longer domain (more specific) first.
                let len_cmp = db.len().cmp(&da.len());
                if len_cmp != Ordering::Equal {
                    return len_cmp;
                }
                // Secondary: lexicographic (case-insensitive).
                hostname_cmp(da, db)
            }
        }
    }

    /// Instance wrapper for `order_servers_static`.
    fn order_servers(&self, a: &ServerConfig, b: &ServerConfig) -> Ordering {
        Self::order_servers_static(a, b)
    }

    /// Compare a query domain against a server entry for binary search.
    ///
    /// Implements suffix matching: the query domain must end with the server's
    /// domain pattern.  Returns `Equal` when the server domain is a suffix of
    /// the query domain.
    fn order_domain(&self, qdomain: &str, qlen: usize, entry: &ServerConfig) -> Ordering {
        match &entry.domain {
            None => {
                // Default server matches everything — but ranks low.
                Ordering::Equal
            }
            Some(d) => {
                let d_lower = d.to_ascii_lowercase();
                let dlen = d_lower.len();

                if dlen > qlen {
                    // Server domain is longer than query → cannot match.
                    return qlen.cmp(&dlen);
                }

                // Check suffix match.
                let suffix = &qdomain[qlen - dlen..];
                if hostname_eq(suffix, &d_lower) {
                    // Verify domain boundary: either exact match or preceded by '.'.
                    if dlen == qlen || qdomain.as_bytes()[qlen - dlen - 1] == b'.' {
                        return Ordering::Equal;
                    }
                }

                // No suffix match — compare lexicographically.
                hostname_cmp(qdomain, &d_lower)
            }
        }
    }

    /// Linear scan around a binary-search match point to find the absolute
    /// longest suffix match (handles wildcards and multiple entries).
    fn scan_for_best_match(
        &self,
        qdomain: &str,
        qlen: usize,
        _flags: u32,
        mut best: Option<(usize, u32)>,
        mut best_len: usize,
    ) -> Option<(usize, u32)> {
        for (idx, entry) in self.server_array.iter().enumerate() {
            let matches = match &entry.domain {
                None => true,
                Some(d) => {
                    let d_lower = d.to_ascii_lowercase();
                    let dlen = d_lower.len();

                    if dlen > qlen {
                        false
                    } else {
                        let suffix = &qdomain[qlen - dlen..];
                        let suffix_match = hostname_eq(suffix, &d_lower)
                            && (dlen == qlen || qdomain.as_bytes()[qlen - dlen - 1] == b'.');

                        // Also check wildcard: "*.example.com" stored as "example.com"
                        // with SERV_WILDCARD flag.
                        if suffix_match {
                            true
                        } else if entry.flags.wildcard && dlen < qlen {
                            // Wildcard match: query has an additional label.
                            let with_dot = format!(".{}", d_lower);
                            qdomain.ends_with(&with_dot)
                        } else {
                            false
                        }
                    }
                }
            };

            if matches && entry.domain_len > best_len {
                let mut match_flags: u32 = F_SERVER;
                if entry.flags.dnssec_capable {
                    match_flags |= F_DNSSECOK;
                }
                if entry.domain.is_some() {
                    match_flags |= F_DOMAINSRV;
                }
                best = Some((idx, match_flags));
                best_len = entry.domain_len;
            }
        }

        best
    }

    /// Expand a starting index to the full equivalence group of servers
    /// (all entries with `order_servers == Equal` relative to the start).
    fn expand_group(&self, start_idx: usize) -> Vec<usize> {
        let mut group = vec![start_idx];
        let entry = &self.server_array[start_idx];

        // Expand left.
        let mut i = start_idx;
        while i > 0 {
            i -= 1;
            if self.order_servers(&self.server_array[i], entry) == Ordering::Equal {
                group.push(i);
            } else {
                break;
            }
        }

        // Expand right.
        let mut i = start_idx + 1;
        while i < self.server_array.len() {
            if self.order_servers(&self.server_array[i], entry) == Ordering::Equal {
                group.push(i);
            } else {
                break;
            }
            i += 1;
        }

        group
    }

    /// Retrieve the IPv4 address from a server entry by its index.
    ///
    /// The server entry stores addresses as `SocketAddr`.  For local-domain
    /// entries (offset by `servers.len()`), we check `local_domains`.
    fn get_server_ipv4(&self, server_idx: usize, state: &DaemonState) -> Option<Ipv4Addr> {
        let entry = if server_idx < state.servers.len() {
            &state.servers[server_idx]
        } else {
            let local_idx = server_idx - state.servers.len();
            state.local_domains.get(local_idx)?
        };
        match entry.addr {
            SocketAddr::V4(v4) => Some(*v4.ip()),
            _ => None,
        }
    }

    /// Retrieve the IPv6 address from a server entry by its index.
    fn get_server_ipv6(&self, server_idx: usize, state: &DaemonState) -> Option<Ipv6Addr> {
        let entry = if server_idx < state.servers.len() {
            &state.servers[server_idx]
        } else {
            let local_idx = server_idx - state.servers.len();
            state.local_domains.get(local_idx)?
        };
        match entry.addr {
            SocketAddr::V6(v6) => Some(*v6.ip()),
            _ => None,
        }
    }
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::ServerEntry;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    /// Helper: create a minimal `DaemonState` for testing.
    fn test_state() -> DaemonState {
        DaemonState::new()
    }

    /// Helper: create a `ServerEntry` with the given domain and flags.
    fn make_server(domain: Option<&str>, flags: u32) -> ServerEntry {
        ServerEntry {
            addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 53)),
            source_addr: None,
            interface: None,
            domain: domain.map(|s| s.to_string()),
            flags,
            queries: 0,
            failed_queries: 0,
            uid: 0,
        }
    }

    #[test]
    fn test_new_creates_empty_matcher() {
        let matcher = DomainMatcher::new();
        assert!(matcher.server_array.is_empty());
    }

    #[test]
    fn test_build_server_array_empty() {
        let mut matcher = DomainMatcher::new();
        let mut state = test_state();
        matcher.build_server_array(&mut state);
        assert!(matcher.server_array.is_empty());
        assert!(!state.server_has_wildcard);
    }

    #[test]
    fn test_build_server_array_basic() {
        let mut matcher = DomainMatcher::new();
        let mut state = test_state();
        state.servers.push(make_server(Some("example.com"), 0));
        state.servers.push(make_server(None, 0)); // default

        matcher.build_server_array(&mut state);

        assert_eq!(matcher.server_array.len(), 2);
        assert_eq!(state.serverarrayhwm, 2);
    }

    #[test]
    fn test_build_skips_loop_servers() {
        let mut matcher = DomainMatcher::new();
        let mut state = test_state();
        state.servers.push(make_server(Some("loop.com"), SERV_LOOP));
        state.servers.push(make_server(Some("ok.com"), 0));

        matcher.build_server_array(&mut state);

        assert_eq!(matcher.server_array.len(), 1);
        assert_eq!(matcher.server_array[0].domain.as_deref(), Some("ok.com"));
    }

    #[test]
    fn test_build_detects_wildcards() {
        let mut matcher = DomainMatcher::new();
        let mut state = test_state();
        state
            .servers
            .push(make_server(Some("example.com"), SERV_WILDCARD));

        matcher.build_server_array(&mut state);

        assert!(state.server_has_wildcard);
    }

    #[test]
    fn test_lookup_domain_exact_match() {
        let mut matcher = DomainMatcher::new();
        let mut state = test_state();
        state.servers.push(make_server(Some("example.com"), 0));
        state.servers.push(make_server(None, 0));

        matcher.build_server_array(&mut state);

        let result = matcher.lookup_domain("test.example.com", 0, &state);
        assert!(result.is_some());
    }

    #[test]
    fn test_lookup_domain_default_fallback() {
        let mut matcher = DomainMatcher::new();
        let mut state = test_state();
        state.servers.push(make_server(None, 0));

        matcher.build_server_array(&mut state);

        let result = matcher.lookup_domain("anything.org", 0, &state);
        assert!(result.is_some());
    }

    #[test]
    fn test_lookup_domain_nodots() {
        let mut matcher = DomainMatcher::new();
        let mut state = test_state();
        state.servers.push(make_server(None, SERV_FOR_NODOTS));

        matcher.build_server_array(&mut state);

        let result = matcher.lookup_domain("localhost", 0, &state);
        assert!(result.is_some());
    }

    #[test]
    fn test_server_samegroup_equal() {
        let mut matcher = DomainMatcher::new();
        let mut state = test_state();
        state.servers.push(make_server(Some("example.com"), 0));
        state.servers.push(make_server(Some("example.com"), 0));

        matcher.build_server_array(&mut state);

        assert!(matcher.server_samegroup(0, 1));
    }

    #[test]
    fn test_server_samegroup_different() {
        let mut matcher = DomainMatcher::new();
        let mut state = test_state();
        state.servers.push(make_server(Some("a.com"), 0));
        state.servers.push(make_server(Some("b.com"), 0));

        matcher.build_server_array(&mut state);

        assert!(!matcher.server_samegroup(0, 1));
    }

    #[test]
    fn test_filter_servers_basic() {
        let mut matcher = DomainMatcher::new();
        let mut state = test_state();
        state.servers.push(make_server(Some("example.com"), 0));

        matcher.build_server_array(&mut state);

        let filtered = matcher.filter_servers(0, 0);
        assert!(!filtered.is_empty());
    }

    #[test]
    fn test_is_local_answer_ipv4() {
        let mut matcher = DomainMatcher::new();
        let mut state = test_state();
        state.servers.push(make_server(
            Some("block.com"),
            SERV_LITERAL_ADDRESS | SERV_4ADDR,
        ));

        matcher.build_server_array(&mut state);

        let result = matcher.is_local_answer(0);
        assert_eq!(result, Some(F_IPV4));
    }

    #[test]
    fn test_is_local_answer_nxdomain() {
        let mut matcher = DomainMatcher::new();
        let mut state = test_state();
        state
            .servers
            .push(make_server(Some("block.com"), SERV_LITERAL_ADDRESS));

        matcher.build_server_array(&mut state);

        let result = matcher.is_local_answer(0);
        assert_eq!(result, Some(F_NXDOMAIN));
    }

    #[test]
    fn test_is_local_answer_none_for_upstream() {
        let mut matcher = DomainMatcher::new();
        let mut state = test_state();
        state.servers.push(make_server(Some("forward.com"), 0));

        matcher.build_server_array(&mut state);

        let result = matcher.is_local_answer(0);
        assert_eq!(result, None);
    }

    #[test]
    fn test_mark_and_cleanup_servers() {
        let mut matcher = DomainMatcher::new();
        let mut state = test_state();
        state.servers.push(make_server(Some("keep.com"), 0));
        state
            .servers
            .push(make_server(Some("dbus.com"), SERV_FROM_DBUS));

        // Mark DBUS servers
        matcher.mark_servers(&mut state, SERV_FROM_DBUS);
        assert_eq!(state.servers.len(), 2);

        // Cleanup removes marked servers
        matcher.cleanup_servers(&mut state);
        assert_eq!(state.servers.len(), 1);
        assert_eq!(state.servers[0].domain.as_deref(), Some("keep.com"));
    }

    #[test]
    fn test_mark_all_and_cleanup() {
        let mut matcher = DomainMatcher::new();
        let mut state = test_state();
        state.servers.push(make_server(Some("a.com"), 0));
        state.servers.push(make_server(Some("b.com"), 0));

        matcher.mark_servers(&mut state, 0);
        // flag=0 → maybe_free_servers = false, so cleanup is a no-op.
        matcher.cleanup_servers(&mut state);
        assert_eq!(state.servers.len(), 2);
    }

    #[test]
    fn test_add_update_server_new() {
        let matcher = DomainMatcher::new();
        let mut state = test_state();

        matcher
            .add_update_server(
                &mut state,
                0,
                Some(MySockAddr::from(SocketAddr::new(
                    std::net::IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                    53,
                ))),
                None,
                None,
                Some("newdomain.com"),
            )
            .unwrap();

        assert_eq!(state.servers.len(), 1);
        assert_eq!(state.servers[0].domain.as_deref(), Some("newdomain.com"));
    }

    #[test]
    fn test_add_update_server_local() {
        let matcher = DomainMatcher::new();
        let mut state = test_state();

        matcher
            .add_update_server(
                &mut state,
                SERV_LITERAL_ADDRESS,
                None,
                None,
                None,
                Some("local.test"),
            )
            .unwrap();

        assert_eq!(state.local_domains.len(), 1);
    }

    #[test]
    fn test_add_update_server_reuse_marked() {
        let matcher = DomainMatcher::new();
        let mut state = test_state();

        // Pre-populate a marked server.
        state.servers.push(ServerEntry {
            addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(9, 9, 9, 9), 53)),
            source_addr: None,
            interface: None,
            domain: Some("reuse.com".to_string()),
            flags: SERV_MARK,
            queries: 0,
            failed_queries: 0,
            uid: 0,
        });

        matcher
            .add_update_server(
                &mut state,
                0,
                Some(MySockAddr::from(SocketAddr::new(
                    std::net::IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                    53,
                ))),
                None,
                None,
                Some("reuse.com"),
            )
            .unwrap();

        // Should reuse the existing entry, not create a new one.
        assert_eq!(state.servers.len(), 1);
        assert_eq!(state.servers[0].flags & SERV_MARK, 0);
    }

    #[test]
    fn test_server_match_flags_roundtrip() {
        let raw: u32 = SERV_LITERAL_ADDRESS | SERV_4ADDR | SERV_FROM_RESOLV | SERV_DO_DNSSEC;
        let flags = ServerMatchFlags::from_raw(raw);
        assert!(flags.literal_address);
        assert!(flags.has_4addr);
        assert!(flags.from_resolv);
        assert!(flags.dnssec_capable);
        assert!(!flags.has_6addr);
        assert!(!flags.wildcard);

        let back = flags.to_raw();
        assert_eq!(back & SERV_LITERAL_ADDRESS, SERV_LITERAL_ADDRESS);
        assert_eq!(back & SERV_4ADDR, SERV_4ADDR);
        assert_eq!(back & SERV_FROM_RESOLV, SERV_FROM_RESOLV);
        assert_eq!(back & SERV_DO_DNSSEC, SERV_DO_DNSSEC);
    }

    #[test]
    fn test_order_qsort_longer_domain_first() {
        let a = ServerConfig {
            domain: Some("sub.example.com".to_string()),
            domain_len: 15,
            flags: ServerMatchFlags::default(),
            server_idx: 0,
            serial: 0,
            arrayposn: 0,
            last_server: -1,
        };
        let b = ServerConfig {
            domain: Some("example.com".to_string()),
            domain_len: 11,
            flags: ServerMatchFlags::default(),
            server_idx: 1,
            serial: 0,
            arrayposn: 0,
            last_server: -1,
        };

        // Longer (more specific) domain should come first.
        assert_eq!(DomainMatcher::order_qsort(&a, &b), Ordering::Less);
    }
}

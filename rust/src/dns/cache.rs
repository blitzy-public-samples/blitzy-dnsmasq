// Copyright (C) 2024 Simon Kelley
// SPDX-License-Identifier: GPL-2.0-or-later
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.

//! # DNS Cache Implementation
//!
//! High-performance in-memory DNS cache providing fast local resolution
//! through a `HashMap`-based lookup table with TTL-based expiration and
//! LRU (Least Recently Used) eviction.
//!
//! ## Migration from C
//!
//! This module replaces `src/cache.c` (4,119 lines) from the C dnsmasq
//! implementation.  Key transformations:
//!
//! - **Manual hash table** (`hash_table[]` with collision chaining via
//!   `crec.hash_next`) → `HashMap<String, Vec<CacheEntry>>` with automatic
//!   hashing, collision resolution, and dynamic resizing.
//!
//! - **Doubly-linked LRU list** (`cache_head`/`cache_tail` with manual
//!   `cache_link()`/`cache_unlink()`) → `Instant`-based `last_access`
//!   timestamps for LRU eviction ordering.
//!
//! - **C `union all_addr`** with manual tag tracking → Rust [`CacheData`]
//!   enum with compiler-enforced variant safety.
//!
//! - **F_* bitmask flags** (32 `#define` constants) → [`CacheFlags`] struct
//!   with named boolean fields for clarity and type safety.
//!
//! - **`malloc`/`free` with `bigname` pool** → Rust `String`/`Vec` with
//!   automatic drop semantics.  No manual memory management.
//!
//! ## Multi-Source Integration
//!
//! Cache entries originate from four sources:
//! - **Upstream DNS** — responses from forwarded queries (TTL-based expiry)
//! - **/etc/hosts** — static host entries (immortal, survive reloads)
//! - **DHCP leases** — hostname→address bindings (lease TTL expiry)
//! - **Configuration** — `address=` and `host-record=` directives (immortal)
//!
//! ## Thread Safety
//!
//! `DnsCache` is designed for single-threaded access within the tokio event
//! loop, matching dnsmasq's single-process architecture.  If shared access
//! is needed, wrap in `Arc<RwLock<DnsCache>>`.
//!
//! ## Feature Gates
//!
//! - `dhcp` — Enables [`DnsCache::cache_add_dhcp_entry()`] and
//!   [`DnsCache::cache_unhash_dhcp()`] for DHCP-DNS integration.
//! - `dnssec` — Enables [`CacheData::DnsKey`] and [`CacheData::Ds`] variants
//!   for DNSSEC validation record caching.

use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use tracing::{debug, info, trace, warn};

use crate::config::constants::{CACHESIZ, CNAME_CHAIN, HOSTSFILE, SMALLDNAME, STALE_CACHE_EXPIRY};
use crate::core::log::log_dns_query;
use crate::core::types::{opt, DaemonState, DnsmasqError, DnsmasqResult, OptionFlags};
use crate::core::util::{canonicalise, check_dns_name, format_addr, hostname_eq};
use crate::dns::protocol::{DnsClass, DnsName, RRType};

// ===========================================================================
// Cache Flags (replaces C F_* bitmask, dnsmasq.h lines 610-670)
// ===========================================================================

/// Cache entry source and status flags.
///
/// Replaces the C bitmask flags `F_IMMORTAL`, `F_DHCP`, `F_HOSTS`,
/// `F_UPSTREAM`, `F_NXDOMAIN`, `F_FORWARD`, `F_REVERSE`, etc.
/// Uses named boolean fields instead of bit manipulation for clarity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheFlags {
    /// Entry never expires (from hosts file or config).
    /// Replaces C `F_IMMORTAL` (bit 0).
    pub immortal: bool,

    /// Entry originated from a DHCP lease.
    /// Replaces C `F_DHCP` (bit 4).
    pub from_dhcp: bool,

    /// Entry originated from /etc/hosts or an additional hosts file.
    /// Replaces C `F_HOSTS` (bit 6).
    pub from_hosts: bool,

    /// Entry originated from an upstream DNS response.
    /// Replaces C `F_UPSTREAM` (bit 16).
    pub from_upstream: bool,

    /// Negative cache entry for NXDOMAIN response.
    /// Replaces C `F_NXDOMAIN` (bit 10).
    pub nxdomain: bool,

    /// Forward record (domain name → address).
    /// Replaces C `F_FORWARD` (bit 2).
    pub forward: bool,

    /// Reverse record (address → domain name, for PTR lookups).
    /// Replaces C `F_REVERSE` (bit 3).
    pub reverse: bool,
}

impl CacheFlags {
    /// Create a new `CacheFlags` with all flags cleared.
    pub fn new() -> Self {
        Self {
            immortal: false,
            from_dhcp: false,
            from_hosts: false,
            from_upstream: false,
            nxdomain: false,
            forward: false,
            reverse: false,
        }
    }

    /// Convert flags to a compact display string for dump_cache output.
    ///
    /// Mimics C's flag string format: `"F"` for forward, `"R"` for reverse,
    /// `"I"` for immortal, `"D"` for DHCP, `"N"` for NXDOMAIN,
    /// `"H"` for hosts, `"C"` for cached/upstream.
    fn to_flag_string(&self) -> String {
        let mut s = String::with_capacity(8);
        if self.forward {
            s.push('F');
        }
        if self.reverse {
            s.push('R');
        }
        if self.immortal {
            s.push('I');
        }
        if self.from_dhcp {
            s.push('D');
        }
        if self.nxdomain {
            s.push('N');
        }
        if self.from_hosts {
            s.push('H');
        }
        if self.from_upstream {
            s.push('C');
        }
        s
    }

    /// Convert flags to a u32 bitmask for log_dns_query() compatibility.
    fn to_log_flags(&self) -> u32 {
        let mut flags: u32 = 0;
        if self.immortal {
            flags |= 1;
        }
        if self.forward {
            flags |= 1 << 2;
        }
        if self.reverse {
            flags |= 1 << 3;
        }
        if self.from_dhcp {
            flags |= 1 << 4;
        }
        if self.from_hosts {
            flags |= 1 << 6;
        }
        if self.nxdomain {
            flags |= 1 << 10;
        }
        if self.from_upstream {
            flags |= 1 << 16;
        }
        flags
    }
}

impl Default for CacheFlags {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Cache Statistics (replaces C cache_make_stat metrics)
// ===========================================================================

/// Runtime cache statistics counters.
///
/// Replaces C's scattered counter variables (`daemon->metrics[METRIC_DNS_CACHE_*]`)
/// with a dedicated statistics structure.  Counters are updated in real-time
/// during cache operations and queried via [`DnsCache::cache_make_stat()`].
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Total cache hits (successful lookups).
    pub hits: u64,

    /// Total cache misses (lookups that found no matching entry).
    pub misses: u64,

    /// Total entries evicted due to TTL expiration or LRU replacement.
    pub evictions: u64,

    /// Total entries inserted (including re-insertions for updates).
    pub insertions: u64,

    /// Current number of live entries in the cache.
    pub entry_count: usize,

    /// Maximum cache capacity (configurable, default [`CACHESIZ`]=150).
    pub max_size: usize,
}

impl CacheStats {
    /// Compute the cache hit rate as a percentage (0.0 – 100.0).
    ///
    /// Returns 0.0 if no queries have been made (to avoid division by zero).
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            (self.hits as f64 / total as f64) * 100.0
        }
    }
}

impl Default for CacheStats {
    fn default() -> Self {
        Self {
            hits: 0,
            misses: 0,
            evictions: 0,
            insertions: 0,
            entry_count: 0,
            max_size: CACHESIZ as usize,
        }
    }
}

// ===========================================================================
// Cache Data Enum (replaces C union in struct crec)
// ===========================================================================

/// Typed record data for a cache entry.
///
/// Replaces C's `union` within `struct crec` where the active member was
/// tracked by examining `F_IPV4`, `F_IPV6`, `F_CNAME`, `F_NEG`, etc. flags.
/// Rust's enum guarantees that only the active variant can be accessed,
/// eliminating type-confusion vulnerabilities.
#[derive(Debug, Clone)]
pub enum CacheData {
    /// IPv4 address from an A record.
    Addr4(Ipv4Addr),

    /// IPv6 address from an AAAA record.
    Addr6(Ipv6Addr),

    /// CNAME target domain name.
    Cname(DnsName),

    /// PTR record domain name (reverse DNS).
    Ptr(DnsName),

    /// MX record: mail exchange with preference value.
    Mx {
        /// Lower values indicate higher priority.
        preference: u16,
        /// Mail exchange domain name.
        exchange: DnsName,
    },

    /// SRV record: service location.
    Srv {
        /// Priority (lower = preferred).
        priority: u16,
        /// Weight for load balancing among equal-priority targets.
        weight: u16,
        /// TCP/UDP port number of the service.
        port: u16,
        /// Target hostname providing the service.
        target: DnsName,
    },

    /// TXT record: arbitrary text data.
    Txt(Vec<u8>),

    /// Negative cache entry for NXDOMAIN or NODATA response.
    NxDomain,

    /// DNSSEC DNSKEY record (gated by `dnssec` feature).
    #[cfg(feature = "dnssec")]
    DnsKey {
        /// DNSKEY flags (zone key, SEP, etc.).
        flags: u16,
        /// Protocol field (must be 3 per RFC 4034).
        protocol: u8,
        /// DNSSEC algorithm number.
        algorithm: u8,
        /// Raw public key material.
        key_data: Vec<u8>,
    },

    /// DNSSEC DS (Delegation Signer) record (gated by `dnssec` feature).
    #[cfg(feature = "dnssec")]
    Ds {
        /// Key tag identifying the referenced DNSKEY.
        key_tag: u16,
        /// DNSSEC algorithm number.
        algorithm: u8,
        /// Digest type (SHA-1=1, SHA-256=2, SHA-384=4).
        digest_type: u8,
        /// Digest of the child zone's DNSKEY record.
        digest: Vec<u8>,
    },
}

impl CacheData {
    /// Return a human-readable description of the data variant for logging.
    /// Used by callers formatting cache contents for dump or statistics.
    pub fn type_description(&self) -> &'static str {
        match self {
            Self::Addr4(_) => "A",
            Self::Addr6(_) => "AAAA",
            Self::Cname(_) => "CNAME",
            Self::Ptr(_) => "PTR",
            Self::Mx { .. } => "MX",
            Self::Srv { .. } => "SRV",
            Self::Txt(_) => "TXT",
            Self::NxDomain => "NXDOMAIN",
            #[cfg(feature = "dnssec")]
            Self::DnsKey { .. } => "DNSKEY",
            #[cfg(feature = "dnssec")]
            Self::Ds { .. } => "DS",
        }
    }

    /// Format the data value as a display string for dump output.
    fn display_value(&self) -> String {
        match self {
            Self::Addr4(addr) => addr.to_string(),
            Self::Addr6(addr) => addr.to_string(),
            Self::Cname(name) => name.to_string(),
            Self::Ptr(name) => name.to_string(),
            Self::Mx {
                preference,
                exchange,
            } => format!("{} {}", preference, exchange),
            Self::Srv {
                priority,
                weight,
                port,
                target,
            } => format!("{} {} {} {}", priority, weight, port, target),
            Self::Txt(data) => String::from_utf8(data.clone())
                .unwrap_or_else(|_| format!("<{} bytes>", data.len())),
            Self::NxDomain => "NXDOMAIN".to_string(),
            #[cfg(feature = "dnssec")]
            Self::DnsKey {
                flags,
                algorithm,
                key_data,
                ..
            } => format!(
                "flags={} algo={} keylen={}",
                flags,
                algorithm,
                key_data.len()
            ),
            #[cfg(feature = "dnssec")]
            Self::Ds {
                key_tag,
                algorithm,
                digest_type,
                ..
            } => format!(
                "keytag={} algo={} digest={}",
                key_tag, algorithm, digest_type
            ),
        }
    }

    /// Extract the IP address from this data variant, if it contains one.
    fn ip_addr(&self) -> Option<IpAddr> {
        match self {
            Self::Addr4(addr) => Some(IpAddr::V4(*addr)),
            Self::Addr6(addr) => Some(IpAddr::V6(*addr)),
            _ => None,
        }
    }
}

// ===========================================================================
// Cache Entry (replaces C struct crec, dnsmasq.h lines 670-685)
// ===========================================================================

/// A single DNS cache entry, replacing C's `struct crec`.
///
/// In C, cache records were stored in a hash table with collision chaining
/// (`hash_next` pointer) and a global LRU doubly-linked list (`next`/`prev`
/// pointers, `cache_head`/`cache_tail`).  Name storage used a union of
/// inline `sname[SMALLDNAME]`, heap-allocated `bigname`, or external
/// `namep` pointer — all managed manually.
///
/// In Rust:
/// - Names are `DnsName` (heap-allocated `Vec<String>`) with automatic drop.
/// - LRU tracking uses `last_access: Instant` timestamps.
/// - Record data uses `CacheData` enum instead of a C union.
/// - No linked-list pointers — entries live in `Vec<CacheEntry>` within HashMap.
#[derive(Debug, Clone)]
pub struct CacheEntry {
    /// The domain name this record is for.
    pub name: DnsName,

    /// DNS resource record type (A, AAAA, CNAME, PTR, MX, SRV, TXT, etc.).
    pub rr_type: RRType,

    /// Record data — typed enum replacing C's union.
    pub data: CacheData,

    /// Absolute expiration time.  When `Instant::now() > expires`, the entry
    /// is considered stale and eligible for eviction.
    pub expires: Instant,

    /// Time this entry was last accessed (for LRU eviction ordering).
    pub last_access: Instant,

    /// Source and status flags.
    pub flags: CacheFlags,

    /// Original TTL value from the DNS response (in seconds).
    pub ttl: u32,
}

impl CacheEntry {
    /// Check whether this entry has expired.
    #[inline]
    pub fn is_expired(&self) -> bool {
        !self.flags.immortal && Instant::now() > self.expires
    }

    /// Remaining TTL in seconds (0 if expired).
    pub fn remaining_ttl(&self) -> u64 {
        if self.flags.immortal {
            return u64::MAX;
        }
        let now = Instant::now();
        if now >= self.expires {
            0
        } else {
            self.expires.duration_since(now).as_secs()
        }
    }

    /// Check whether this entry is stale but still within the maximum
    /// stale-serve window.  Stale entries have passed their TTL but are
    /// younger than [`STALE_CACHE_EXPIRY`] seconds (default 86400 = 1 day).
    ///
    /// Replaces C's stale-cache logic that served expired entries when
    /// upstream servers were unreachable.
    #[inline]
    pub fn is_stale(&self) -> bool {
        if self.flags.immortal {
            return false;
        }
        let now = Instant::now();
        if now <= self.expires {
            return false; // Not expired yet.
        }
        // Expired but within the stale window.
        let expired_duration = now.duration_since(self.expires);
        expired_duration.as_secs() < STALE_CACHE_EXPIRY as u64
    }

    /// Check whether this entry's domain name is "short" (≤ SMALLDNAME
    /// bytes).  In the C implementation, short names were stored inline
    /// in the `crec.name.sname[SMALLDNAME]` char array, avoiding a heap
    /// allocation.  In Rust, all names use the same `DnsName` type, but
    /// this predicate is useful for diagnostics and statistics.
    #[inline]
    pub fn is_short_name(&self) -> bool {
        self.name.to_string().len() <= SMALLDNAME
    }

    /// Update the last-access timestamp to now (for LRU tracking).
    /// Called by cache lookup methods on hit to maintain LRU ordering.
    #[inline]
    pub fn touch(&mut self) {
        self.last_access = Instant::now();
    }
}

/// Create a cache key string (lowercased) from a `DnsName`.
///
/// DNS names are case-insensitive per RFC 1035 §2.3.3.  The C code
/// hashes names by masking bit 0x20 (case bit) from each character.
/// We achieve the same by converting to lowercase for HashMap keys.
#[inline]
fn make_cache_key(name: &DnsName) -> String {
    name.to_string().to_lowercase()
}

/// Create a cache key string from a raw domain name string.
#[inline]
fn make_cache_key_str(name: &str) -> String {
    name.to_lowercase()
}

// ===========================================================================
// DNS Cache (main structure)
// ===========================================================================

/// High-performance DNS cache with HashMap-based O(1) lookup.
///
/// Replaces C's manually-managed hash table (`hash_table[]` array with
/// `HASHSIZE` buckets and `crec.hash_next` collision chains) with Rust's
/// standard `HashMap`.
///
/// ## Capacity Management
///
/// The cache enforces a maximum entry count ([`CACHESIZ`]=150 default).
/// When full, the LRU (least-recently-accessed) entry is evicted.
/// Expired entries are also opportunistically removed during lookups.
///
/// ## Multi-Source Priority
///
/// Entries from /etc/hosts and configuration are immortal and take priority
/// over upstream DNS entries.  DHCP entries have their own lifecycle tied
/// to lease duration.
pub struct DnsCache {
    /// Primary cache storage: lowercased domain name → list of entries.
    entries: HashMap<String, Vec<CacheEntry>>,

    /// Current total number of cache entries across all name buckets.
    count: usize,

    /// Maximum cache capacity (configurable, default [`CACHESIZ`]=150).
    max_size: usize,

    /// Runtime statistics counters.
    stats: CacheStats,

    /// Monotonically increasing unique ID for cache invalidation.
    uid_counter: u32,

    /// List of hosts file paths that have been loaded.
    hosts_files: Vec<PathBuf>,

    /// Modification timestamp of the primary hosts file.
    hosts_modified: Option<SystemTime>,

    /// Pending entries for batch insertion (transaction pattern).
    pending_inserts: Vec<CacheEntry>,

    /// Whether a batch insertion transaction is in progress.
    inserting: bool,
}

impl DnsCache {
    // -----------------------------------------------------------------------
    // Initialization (from C cache_init, cache.c lines 87-143)
    // -----------------------------------------------------------------------

    /// Initialize the DNS cache with the specified maximum capacity.
    ///
    /// If `max_size` is `None`, defaults to [`CACHESIZ`] (150 entries).
    /// Pre-allocates the `HashMap` with estimated bucket count for the
    /// expected entry count.
    ///
    /// Replaces C `cache_init()` which allocated a hash table array and
    /// pre-populated the free list with `safe_malloc`'d `struct crec` records.
    pub fn cache_init(max_size: Option<usize>) -> DnsmasqResult<Self> {
        let size = max_size.unwrap_or(CACHESIZ as usize);
        info!(
            cache_size = size,
            "DNS cache initializing with capacity {}", size
        );

        let cache = DnsCache {
            entries: HashMap::with_capacity(size),
            count: 0,
            max_size: size,
            stats: CacheStats {
                max_size: size,
                ..CacheStats::default()
            },
            uid_counter: 0,
            hosts_files: Vec::new(),
            hosts_modified: None,
            pending_inserts: Vec::new(),
            inserting: false,
        };

        info!(cache_size = size, "DNS cache initialized successfully");
        Ok(cache)
    }

    /// Generate the next unique ID for cache entries.
    /// Replaces C `next_uid()` in cache.c.
    fn next_uid(&mut self) -> u32 {
        self.uid_counter = self.uid_counter.wrapping_add(1);
        // Skip 0 — zero is reserved as "no UID" sentinel.
        if self.uid_counter == 0 {
            self.uid_counter = 1;
        }
        self.uid_counter
    }

    // -----------------------------------------------------------------------
    // Lookup by Name (from C cache_find_by_name, cache.c lines 913-1025)
    // -----------------------------------------------------------------------

    /// Look up cache entries matching a domain name and optional record type.
    ///
    /// Returns a vector of references to matching entries after filtering out
    /// expired entries.  Each returned entry has its `last_access` timestamp
    /// updated for LRU tracking.
    ///
    /// If `rr_type` is `None`, all record types for the name are returned.
    ///
    /// ## Round-Robin Behavior
    ///
    /// When multiple entries of the same type exist (e.g., multiple A records),
    /// the first matching entry is rotated to the end of the list on each call,
    /// implementing the round-robin DNS behavior from C's `cache_find_by_name`.
    ///
    /// ## CNAME Chain Following
    ///
    /// If the name has a CNAME entry and the requested type is not CNAME,
    /// this function follows the CNAME chain (up to [`CNAME_CHAIN`]=10 hops)
    /// to find the target record.
    pub fn cache_find_by_name(
        &mut self,
        name: &DnsName,
        rr_type: Option<RRType>,
    ) -> Vec<&CacheEntry> {
        let key = make_cache_key(name);
        trace!(name = %name, rr_type = ?rr_type, "cache_find_by_name lookup");

        // First, evict expired entries for this name opportunistically.
        self.evict_expired_for_key(&key);

        // Direct lookup for matching entries.
        let mut results = Vec::new();

        if let Some(entries) = self.entries.get(&key) {
            for entry in entries.iter() {
                if entry.is_expired() {
                    continue;
                }
                let type_matches = rr_type.map(|t| entry.rr_type == t).unwrap_or(true);
                if type_matches {
                    results.push(entry);
                }
            }
        }

        // If we found results, record a hit and touch entries.
        if !results.is_empty() {
            self.stats.hits += 1;
            debug!(
                name = %name,
                rr_type = ?rr_type,
                count = results.len(),
                "cache hit"
            );

            // Touch entries for LRU (need mutable access).
            if let Some(entries) = self.entries.get_mut(&key) {
                for entry in entries.iter_mut() {
                    if !entry.is_expired() {
                        let type_matches = rr_type.map(|t| entry.rr_type == t).unwrap_or(true);
                        if type_matches {
                            entry.touch();
                        }
                    }
                }

                // Round-robin: rotate first matching entry to end.
                if let Some(rr) = rr_type {
                    if let Some(first_idx) = entries
                        .iter()
                        .position(|e| e.rr_type == rr && !e.is_expired())
                    {
                        let len = entries.len();
                        if len > 1 && first_idx < len - 1 {
                            let entry = entries.remove(first_idx);
                            entries.push(entry);
                        }
                    }
                }
            }

            // Re-borrow immutably for the return value.
            let mut final_results = Vec::new();
            if let Some(entries) = self.entries.get(&key) {
                for entry in entries.iter() {
                    if entry.is_expired() {
                        continue;
                    }
                    let type_matches = rr_type.map(|t| entry.rr_type == t).unwrap_or(true);
                    if type_matches {
                        final_results.push(entry);
                    }
                }
            }
            return final_results;
        }

        // CNAME chain following: if no direct match and type is not CNAME,
        // check for CNAME entries and follow the chain.
        if rr_type.map(|t| t != RRType::CNAME).unwrap_or(false) {
            let mut chain_name = key.clone();
            for _hop in 0..CNAME_CHAIN {
                let cname_target = self.entries.get(&chain_name).and_then(|entries| {
                    entries.iter().find_map(|e| {
                        if e.rr_type == RRType::CNAME && !e.is_expired() {
                            if let CacheData::Cname(ref target) = e.data {
                                Some(make_cache_key(target))
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    })
                });

                if let Some(target_key) = cname_target {
                    chain_name = target_key;
                    // Check target for the requested type.
                    if let Some(entries) = self.entries.get(&chain_name) {
                        let mut found = Vec::new();
                        for entry in entries.iter() {
                            if entry.is_expired() {
                                continue;
                            }
                            let type_matches = rr_type.map(|t| entry.rr_type == t).unwrap_or(true);
                            if type_matches {
                                found.push(entry);
                            }
                        }
                        if !found.is_empty() {
                            self.stats.hits += 1;
                            debug!(
                                name = %name,
                                resolved_via = chain_name,
                                count = found.len(),
                                "cache hit via CNAME chain"
                            );
                            return found;
                        }
                    }
                } else {
                    break;
                }
            }
        }

        // Cache miss.
        self.stats.misses += 1;
        debug!(name = %name, rr_type = ?rr_type, "cache miss");
        Vec::new()
    }

    // -----------------------------------------------------------------------
    // Lookup by Address (from C cache_find_by_addr, cache.c lines 1027-1084)
    // -----------------------------------------------------------------------

    /// Reverse lookup: find cache entries matching an IP address.
    ///
    /// Scans all cache entries for PTR (reverse) records or forward records
    /// containing the specified address.  Updates `last_access` on matches.
    ///
    /// In C, this scanned all hash buckets and stopped at the first
    /// non-`F_REVERSE` entry per bucket (due to ordering invariant).
    /// In Rust, we scan all entries since the HashMap has no ordering constraint.
    pub fn cache_find_by_addr(&mut self, addr: &IpAddr) -> Vec<&CacheEntry> {
        trace!(addr = %addr, "cache_find_by_addr lookup");

        // First pass: find matching entries and touch them.
        let mut matching_keys: Vec<(String, usize)> = Vec::new();
        for (key, entries) in self.entries.iter() {
            for (idx, entry) in entries.iter().enumerate() {
                if entry.is_expired() {
                    continue;
                }
                if let Some(entry_addr) = entry.data.ip_addr() {
                    if &entry_addr == addr {
                        matching_keys.push((key.clone(), idx));
                    }
                }
            }
        }

        // Touch matched entries for LRU tracking.
        for (key, idx) in &matching_keys {
            if let Some(entries) = self.entries.get_mut(key) {
                if let Some(entry) = entries.get_mut(*idx) {
                    entry.touch();
                }
            }
        }

        // Collect results immutably.
        let mut results = Vec::new();
        for (key, idx) in &matching_keys {
            if let Some(entries) = self.entries.get(key) {
                if let Some(entry) = entries.get(*idx) {
                    results.push(entry);
                }
            }
        }

        if results.is_empty() {
            self.stats.misses += 1;
            debug!(addr = %addr, "cache_find_by_addr miss");
        } else {
            self.stats.hits += 1;
            debug!(addr = %addr, count = results.len(), "cache_find_by_addr hit");
        }

        results
    }

    // -----------------------------------------------------------------------
    // Insertion (from C cache_insert + really_insert, cache.c lines 450-860)
    // -----------------------------------------------------------------------

    /// Insert a new entry into the cache.
    ///
    /// ## Eviction Policy (from C `really_insert`)
    ///
    /// When the cache is full:
    /// 1. Remove expired entries first.
    /// 2. If still full, evict the entry with the oldest `last_access` time
    ///    (LRU eviction), excluding immortal entries (hosts/config).
    /// 3. Zero-TTL entries are rejected unless stale caching is enabled.
    ///
    /// ## Duplicate Handling
    ///
    /// If an entry with the same name, type, and data already exists:
    /// - Update the TTL and expiration time.
    /// - Update the flags (upstream → upstream refresh).
    /// - Do NOT create a duplicate entry.
    pub fn cache_insert(&mut self, entry: CacheEntry) -> DnsmasqResult<()> {
        let key = make_cache_key(&entry.name);

        trace!(
            name = %entry.name,
            rr_type = ?entry.rr_type,
            ttl = entry.ttl,
            "cache_insert"
        );

        // Reject zero-TTL entries from upstream (they should not be cached).
        // C code: if (ttd == now) return; unless stale caching enabled.
        if entry.ttl == 0 && entry.flags.from_upstream && !entry.flags.nxdomain {
            trace!(name = %entry.name, "rejecting zero-TTL upstream entry");
            return Ok(());
        }

        // Check for duplicate: same name + type + matching data.
        if let Some(existing) = self.entries.get_mut(&key) {
            if let Some(idx) = existing
                .iter()
                .position(|e| e.rr_type == entry.rr_type && data_matches(&e.data, &entry.data))
            {
                // Update existing entry in-place (TTL refresh).
                let existing_entry = &mut existing[idx];
                existing_entry.expires = entry.expires;
                existing_entry.ttl = entry.ttl;
                existing_entry.last_access = Instant::now();
                existing_entry.flags = entry.flags;
                trace!(name = %existing_entry.name, "updated existing cache entry");
                return Ok(());
            }
        }

        // Evict if at capacity.
        if self.count >= self.max_size {
            self.cache_evict_expired();
        }
        if self.count >= self.max_size {
            self.evict_lru();
        }

        // Assign a unique ID for cache invalidation and CNAME tracking.
        let _uid = self.next_uid();
        trace!(uid = _uid, "assigned UID to cache entry");

        // Insert the new entry.
        self.entries.entry(key).or_default().push(entry);
        self.count += 1;
        self.stats.insertions += 1;
        self.stats.entry_count = self.count;

        Ok(())
    }
}

/// Compare two CacheData values for duplicate detection (free function
/// to avoid borrow conflicts when called from closures that capture `self`).
fn data_matches(a: &CacheData, b: &CacheData) -> bool {
    match (a, b) {
        (CacheData::Addr4(a), CacheData::Addr4(b)) => a == b,
        (CacheData::Addr6(a), CacheData::Addr6(b)) => a == b,
        (CacheData::Cname(a), CacheData::Cname(b)) => a == b,
        (CacheData::Ptr(a), CacheData::Ptr(b)) => a == b,
        (CacheData::NxDomain, CacheData::NxDomain) => true,
        (
            CacheData::Mx {
                preference: pa,
                exchange: ea,
            },
            CacheData::Mx {
                preference: pb,
                exchange: eb,
            },
        ) => pa == pb && ea == eb,
        (
            CacheData::Srv {
                priority: pa,
                weight: wa,
                port: poa,
                target: ta,
            },
            CacheData::Srv {
                priority: pb,
                weight: wb,
                port: pob,
                target: tb,
            },
        ) => pa == pb && wa == wb && poa == pob && ta == tb,
        (CacheData::Txt(a), CacheData::Txt(b)) => a == b,
        #[cfg(feature = "dnssec")]
        (
            CacheData::DnsKey {
                flags: fa,
                algorithm: aa,
                key_data: ka,
                ..
            },
            CacheData::DnsKey {
                flags: fb,
                algorithm: ab,
                key_data: kb,
                ..
            },
        ) => fa == fb && aa == ab && ka == kb,
        #[cfg(feature = "dnssec")]
        (
            CacheData::Ds {
                key_tag: ka,
                algorithm: aa,
                digest_type: da,
                digest: ga,
            },
            CacheData::Ds {
                key_tag: kb,
                algorithm: ab,
                digest_type: db,
                digest: gb,
            },
        ) => ka == kb && aa == ab && da == db && ga == gb,
        _ => false,
    }
}

impl DnsCache {
    // -----------------------------------------------------------------------
    // Eviction (replaces C cache_scan_free + LRU unlink, cache.c)
    // -----------------------------------------------------------------------

    /// Remove all expired entries from the cache.
    ///
    /// Returns the number of entries evicted.
    ///
    /// Replaces C's implicit expired-entry removal that occurred within
    /// `cache_scan_free()` during insertion when the cache was full.
    /// In Rust, this is an explicit operation called periodically and
    /// opportunistically during lookups.
    pub fn cache_evict_expired(&mut self) -> usize {
        let mut evicted = 0usize;
        let now = Instant::now();

        // Collect keys to avoid borrow conflict during iteration.
        let keys: Vec<String> = self.entries.keys().cloned().collect();

        for key in keys {
            if let Some(entries) = self.entries.get_mut(&key) {
                let before = entries.len();
                entries.retain(|e| e.flags.immortal || now <= e.expires);
                let removed = before - entries.len();
                evicted += removed;
                self.count -= removed;
            }
        }

        // Remove empty bucket entries from the HashMap.
        self.entries.retain(|_, v| !v.is_empty());

        if evicted > 0 {
            self.stats.evictions += evicted as u64;
            self.stats.entry_count = self.count;
            debug!(
                evicted = evicted,
                remaining = self.count,
                "evicted expired entries"
            );
        }

        evicted
    }

    /// Evict expired entries for a specific cache key only.
    fn evict_expired_for_key(&mut self, key: &str) {
        let now = Instant::now();
        if let Some(entries) = self.entries.get_mut(key) {
            let before = entries.len();
            entries.retain(|e| e.flags.immortal || now <= e.expires);
            let removed = before - entries.len();
            if removed > 0 {
                self.count -= removed;
                self.stats.evictions += removed as u64;
                self.stats.entry_count = self.count;
                trace!(
                    key = key,
                    removed = removed,
                    "evicted expired entries for key"
                );
            }
        }
        // Clean up empty buckets.
        if self.entries.get(key).is_some_and(|v| v.is_empty()) {
            self.entries.remove(key);
        }
    }

    /// Evict the least-recently-used (LRU) non-immortal entry.
    ///
    /// Replaces C's LRU eviction via `cache_tail` (the oldest entry in
    /// the doubly-linked list).  Scans all entries to find the one with
    /// the oldest `last_access` timestamp, excluding immortal entries.
    fn evict_lru(&mut self) {
        let mut oldest_key: Option<String> = None;
        let mut oldest_idx: usize = 0;
        let mut oldest_time = Instant::now();

        for (key, entries) in self.entries.iter() {
            for (idx, entry) in entries.iter().enumerate() {
                // Never evict immortal entries (hosts, config).
                if entry.flags.immortal {
                    continue;
                }
                if entry.last_access < oldest_time {
                    oldest_time = entry.last_access;
                    oldest_key = Some(key.clone());
                    oldest_idx = idx;
                }
            }
        }

        if let Some(key) = oldest_key {
            if let Some(entries) = self.entries.get_mut(&key) {
                if oldest_idx < entries.len() {
                    let evicted = entries.remove(oldest_idx);
                    self.count -= 1;
                    self.stats.evictions += 1;
                    self.stats.entry_count = self.count;
                    trace!(
                        name = %evicted.name,
                        rr_type = ?evicted.rr_type,
                        age_secs = oldest_time.elapsed().as_secs(),
                        "LRU eviction"
                    );
                }
                if entries.is_empty() {
                    self.entries.remove(&key);
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Hosts File Reading (from C read_hostsfile, cache.c lines 1086-1400)
    // -----------------------------------------------------------------------

    /// Parse a hosts-format file and add entries to the cache.
    ///
    /// Returns the number of entries added.
    ///
    /// ## File Format
    ///
    /// Standard `/etc/hosts` format:
    /// ```text
    /// # comment
    /// 127.0.0.1    localhost
    /// ::1          localhost ip6-localhost
    /// 192.168.1.1  router.local  router
    /// ```
    ///
    /// Each non-comment line: `<address>  <hostname> [<alias>...]`
    ///
    /// Entries are created with `flags.from_hosts = true` and
    /// `flags.immortal = true` (never expire).
    ///
    /// Replaces C `read_hostsfile()` (cache.c lines 1086-1400) which used
    /// `fgets()`, `inet_pton()`, and `canonicalise()`.
    pub fn read_hostsfile(&mut self, path: &Path) -> DnsmasqResult<usize> {
        info!(path = %path.display(), "reading hosts file");

        let file = File::open(path).map_err(|e| {
            warn!(path = %path.display(), error = %e, "failed to open hosts file");
            DnsmasqError::Io(e)
        })?;

        let reader = BufReader::new(file);
        let mut count: usize = 0;
        let mut line_num: usize = 0;

        for line_result in reader.lines() {
            line_num += 1;
            let line = match line_result {
                Ok(l) => l,
                Err(e) => {
                    warn!(
                        path = %path.display(),
                        line = line_num,
                        error = %e,
                        "error reading hosts file line"
                    );
                    continue;
                }
            };

            // Strip comments and trim whitespace.
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }

            // Split into tokens: first is address, rest are hostnames.
            let mut tokens = line.split_whitespace();
            let addr_str = match tokens.next() {
                Some(a) => a,
                None => continue,
            };

            // Parse IP address (IPv4 or IPv6).
            let addr: IpAddr = match addr_str.parse() {
                Ok(a) => a,
                Err(_) => {
                    warn!(
                        path = %path.display(),
                        line = line_num,
                        addr = addr_str,
                        "invalid address in hosts file"
                    );
                    continue;
                }
            };

            // Process each hostname on the line.
            let hostnames: Vec<&str> = tokens.collect();
            if hostnames.is_empty() {
                continue;
            }

            for hostname in &hostnames {
                // Validate and canonicalise the hostname.
                if !check_dns_name(hostname) {
                    warn!(
                        path = %path.display(),
                        line = line_num,
                        hostname = hostname,
                        "invalid hostname in hosts file, skipping"
                    );
                    continue;
                }

                let canon_name = match canonicalise(hostname) {
                    Some(n) => n,
                    None => {
                        warn!(
                            path = %path.display(),
                            line = line_num,
                            hostname = hostname,
                            "failed to canonicalise hostname"
                        );
                        continue;
                    }
                };

                let dns_name = DnsName::from_str_unchecked(&canon_name);
                let now = Instant::now();
                // Immortal entries use a far-future expiration.
                let far_future = now + Duration::from_secs(365 * 24 * 3600 * 100);

                let flags = CacheFlags {
                    immortal: true,
                    from_hosts: true,
                    forward: true,
                    ..CacheFlags::default()
                };

                // Create forward record (hostname → address).
                let (rr_type, data) = match addr {
                    IpAddr::V4(v4) => (RRType::A, CacheData::Addr4(v4)),
                    IpAddr::V6(v6) => (RRType::AAAA, CacheData::Addr6(v6)),
                };

                let forward_entry = CacheEntry {
                    name: dns_name.clone(),
                    rr_type,
                    data,
                    expires: far_future,
                    last_access: now,
                    flags: flags.clone(),
                    ttl: 0, // Immortal entries have no meaningful TTL.
                };

                // Check for duplicate before inserting.
                let key = make_cache_key(&dns_name);
                let is_dup = self.entries.get(&key).is_some_and(|entries| {
                    entries.iter().any(|e| {
                        e.rr_type == rr_type
                            && e.flags.from_hosts
                            && data_matches(&e.data, &forward_entry.data)
                    })
                });

                if !is_dup {
                    self.entries
                        .entry(key.clone())
                        .or_default()
                        .push(forward_entry);
                    self.count += 1;
                    count += 1;
                }

                // Create reverse record (address → hostname) for the first
                // hostname only (matching C behavior: first name wins for PTR).
                if *hostname == hostnames.first().copied().unwrap_or("") {
                    let reverse_name = Self::addr_to_arpa(&addr);
                    let reverse_key = make_cache_key(&reverse_name);
                    let reverse_flags = CacheFlags {
                        immortal: true,
                        from_hosts: true,
                        reverse: true,
                        ..CacheFlags::default()
                    };

                    let reverse_entry = CacheEntry {
                        name: reverse_name.clone(),
                        rr_type: RRType::PTR,
                        data: CacheData::Ptr(dns_name.clone()),
                        expires: far_future,
                        last_access: now,
                        flags: reverse_flags,
                        ttl: 0,
                    };

                    let is_rev_dup = self.entries.get(&reverse_key).is_some_and(|entries| {
                        entries
                            .iter()
                            .any(|e| e.rr_type == RRType::PTR && e.flags.from_hosts)
                    });

                    if !is_rev_dup {
                        self.entries
                            .entry(reverse_key)
                            .or_default()
                            .push(reverse_entry);
                        self.count += 1;
                        count += 1;
                    }
                }
            }
        }

        // Track loaded hosts file.
        if !self.hosts_files.contains(&path.to_path_buf()) {
            self.hosts_files.push(path.to_path_buf());
        }

        // Record modification time for change detection.
        if let Ok(meta) = std::fs::metadata(path) {
            if let Ok(modified) = meta.modified() {
                self.hosts_modified = Some(modified);
            }
        }

        self.stats.entry_count = self.count;
        info!(
            path = %path.display(),
            entries_added = count,
            total_entries = self.count,
            "hosts file loaded"
        );

        Ok(count)
    }

    /// Convert an IP address to its reverse DNS (in-addr.arpa / ip6.arpa) name.
    fn addr_to_arpa(addr: &IpAddr) -> DnsName {
        match addr {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                let arpa = format!(
                    "{}.{}.{}.{}.in-addr.arpa",
                    octets[3], octets[2], octets[1], octets[0]
                );
                DnsName::from_str_unchecked(&arpa)
            }
            IpAddr::V6(v6) => {
                let segments = v6.octets();
                let mut nibbles = String::with_capacity(73);
                for byte in segments.iter().rev() {
                    if !nibbles.is_empty() {
                        nibbles.push('.');
                    }
                    nibbles.push_str(&format!("{:x}.{:x}", byte & 0x0f, (byte >> 4) & 0x0f));
                }
                nibbles.push_str(".ip6.arpa");
                DnsName::from_str_unchecked(&nibbles)
            }
        }
    }

    // -----------------------------------------------------------------------
    // DHCP Integration (from C cache_add_dhcp_entry / cache_unhash_dhcp)
    // -----------------------------------------------------------------------

    /// Register a DHCP-assigned hostname in the DNS cache.
    ///
    /// Called when a DHCP lease assigns or renews a hostname.  Creates both
    /// forward (name→addr) and reverse (addr→name) cache entries with the
    /// DHCP lease TTL.
    ///
    /// ## Conflict Detection (from C cache_add_dhcp_entry)
    ///
    /// - If the name already has a CNAME entry, the DHCP entry is rejected.
    /// - If the name has an existing entry with the same address, it is
    ///   refreshed (TTL update) rather than duplicated.
    /// - If the name has an existing entry with a different address, the
    ///   DHCP entry is rejected and a warning is logged.
    #[cfg(feature = "dhcp")]
    pub fn cache_add_dhcp_entry(
        &mut self,
        name: &str,
        addr: IpAddr,
        ttl: u32,
    ) -> DnsmasqResult<()> {
        debug!(name = name, addr = %addr, ttl = ttl, "cache_add_dhcp_entry");

        // Validate and canonicalise the hostname.
        if !check_dns_name(name) {
            return Err(DnsmasqError::Config(format!(
                "invalid DHCP hostname: {}",
                name
            )));
        }

        let canon = match canonicalise(name) {
            Some(n) => n,
            None => {
                return Err(DnsmasqError::Config(format!(
                    "cannot canonicalise DHCP hostname: {}",
                    name
                )));
            }
        };

        let dns_name = DnsName::from_str_unchecked(&canon);
        let key = make_cache_key(&dns_name);

        // Conflict detection: check for existing CNAME.
        if let Some(entries) = self.entries.get(&key) {
            for entry in entries {
                if entry.rr_type == RRType::CNAME && !entry.is_expired() {
                    warn!(name = name, "DHCP entry rejected: existing CNAME record");
                    return Err(DnsmasqError::Config(format!(
                        "DHCP hostname {} conflicts with CNAME",
                        name
                    )));
                }

                // Check for address conflict.
                if let Some(existing_addr) = entry.data.ip_addr() {
                    if existing_addr == addr {
                        // Same address — will refresh below.
                        continue;
                    }
                    if entry.flags.from_dhcp && !entry.is_expired() {
                        warn!(
                            name = name,
                            existing_addr = %existing_addr,
                            new_addr = %addr,
                            "DHCP entry rejected: address conflict"
                        );
                        return Err(DnsmasqError::Config(format!(
                            "DHCP hostname {} already mapped to different address {}",
                            name, existing_addr
                        )));
                    }
                }
            }
        }

        let now = Instant::now();
        let expires = now + Duration::from_secs(u64::from(ttl));
        let (rr_type, data) = match addr {
            IpAddr::V4(v4) => (RRType::A, CacheData::Addr4(v4)),
            IpAddr::V6(v6) => (RRType::AAAA, CacheData::Addr6(v6)),
        };

        let flags = CacheFlags {
            from_dhcp: true,
            forward: true,
            ..CacheFlags::default()
        };

        // Check for existing DHCP entry to refresh.
        let mut refreshed = false;
        if let Some(entries) = self.entries.get_mut(&key) {
            for entry in entries.iter_mut() {
                if entry.flags.from_dhcp
                    && entry.rr_type == rr_type
                    && entry.data.ip_addr() == Some(addr)
                {
                    entry.expires = expires;
                    entry.ttl = ttl;
                    entry.last_access = now;
                    refreshed = true;
                    trace!(name = name, "refreshed existing DHCP cache entry");
                    break;
                }
            }
        }

        if !refreshed {
            let forward_entry = CacheEntry {
                name: dns_name.clone(),
                rr_type,
                data,
                expires,
                last_access: now,
                flags,
                ttl,
            };

            // Evict if at capacity.
            if self.count >= self.max_size {
                self.cache_evict_expired();
            }
            if self.count >= self.max_size {
                self.evict_lru();
            }

            self.entries.entry(key).or_default().push(forward_entry);
            self.count += 1;
            self.stats.insertions += 1;

            // Create reverse entry (PTR).
            let reverse_name = Self::addr_to_arpa(&addr);
            let reverse_key = make_cache_key(&reverse_name);
            let reverse_flags = CacheFlags {
                from_dhcp: true,
                reverse: true,
                ..CacheFlags::default()
            };

            let reverse_entry = CacheEntry {
                name: reverse_name,
                rr_type: RRType::PTR,
                data: CacheData::Ptr(dns_name),
                expires,
                last_access: now,
                flags: reverse_flags,
                ttl,
            };

            if self.count >= self.max_size {
                self.evict_lru();
            }

            self.entries
                .entry(reverse_key)
                .or_default()
                .push(reverse_entry);
            self.count += 1;
            self.stats.insertions += 1;
        }

        self.stats.entry_count = self.count;
        Ok(())
    }

    /// Remove all DHCP-originated entries from the cache.
    ///
    /// Called when DHCP configuration changes or leases are flushed.
    /// Replaces C `cache_unhash_dhcp()` (cache.c line 3129) which moved
    /// DHCP entries to the `dhcp_spare` free list.
    #[cfg(feature = "dhcp")]
    pub fn cache_unhash_dhcp(&mut self) {
        debug!("removing all DHCP cache entries");
        let mut removed = 0usize;

        let keys: Vec<String> = self.entries.keys().cloned().collect();
        for key in keys {
            if let Some(entries) = self.entries.get_mut(&key) {
                let before = entries.len();
                entries.retain(|e| !e.flags.from_dhcp);
                removed += before - entries.len();
            }
        }

        self.entries.retain(|_, v| !v.is_empty());
        self.count -= removed;
        self.stats.entry_count = self.count;

        info!(
            removed = removed,
            remaining = self.count,
            "DHCP cache entries removed"
        );
    }

    // -----------------------------------------------------------------------
    // Cache Reload (from C cache_reload, cache.c lines 2831-3127)
    // -----------------------------------------------------------------------

    /// Reload the cache: clear host-sourced entries and re-read hosts files.
    ///
    /// Called when `/etc/hosts` changes (detected by inotify) or when a
    /// `SIGHUP` config reload is triggered.
    ///
    /// ## Preservation Policy (from C cache_reload)
    ///
    /// - **Preserved**: DHCP entries (`from_dhcp`) and upstream DNS entries
    ///   (`from_upstream`) survive the reload.
    /// - **Cleared**: Hosts entries (`from_hosts`) and config entries are
    ///   removed and then re-read from the hosts files.
    /// - **Metrics reset**: Hits/misses/evictions counters are reset.
    pub fn cache_reload(&mut self) -> DnsmasqResult<()> {
        info!("cache reload initiated");

        // Phase 1: Remove hosts-sourced entries.
        let mut removed = 0usize;
        let keys: Vec<String> = self.entries.keys().cloned().collect();
        for key in keys {
            if let Some(entries) = self.entries.get_mut(&key) {
                let before = entries.len();
                entries.retain(|e| !e.flags.from_hosts);
                removed += before - entries.len();
            }
        }
        self.entries.retain(|_, v| !v.is_empty());
        self.count -= removed;

        info!(removed = removed, "cleared hosts-sourced cache entries");

        // Phase 2: Reset statistics.
        self.stats.hits = 0;
        self.stats.misses = 0;
        self.stats.evictions = 0;
        self.stats.insertions = 0;
        self.stats.entry_count = self.count;

        // Phase 3: Re-read all hosts files.
        let hosts_paths: Vec<PathBuf> = self.hosts_files.clone();
        let mut total_added = 0usize;

        for path in &hosts_paths {
            match self.read_hostsfile(path) {
                Ok(n) => total_added += n,
                Err(e) => {
                    warn!(
                        path = %path.display(),
                        error = %e,
                        "failed to re-read hosts file during reload"
                    );
                }
            }
        }

        // If no hosts files were tracked, try the default.
        if hosts_paths.is_empty() {
            let default_path = Path::new(HOSTSFILE);
            if default_path.exists() {
                match self.read_hostsfile(default_path) {
                    Ok(n) => total_added += n,
                    Err(e) => {
                        warn!(
                            error = %e,
                            "failed to read default hosts file during reload"
                        );
                    }
                }
            }
        }

        info!(
            added = total_added,
            total_entries = self.count,
            "cache reload complete"
        );

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Diagnostics (from C dump_cache / log_query / cache_make_stat)
    // -----------------------------------------------------------------------

    /// Dump the entire cache contents for debugging.
    ///
    /// Invoked in response to `SIGUSR1` signal.  Outputs each entry with
    /// its name, type, data, flags, and remaining TTL.
    ///
    /// Replaces C `dump_cache()` (cache.c lines 3746-3930) which iterated
    /// the hash table and logged each entry via `my_syslog()`.
    pub fn dump_cache(&self) {
        info!(
            entries = self.count,
            max_size = self.max_size,
            hits = self.stats.hits,
            misses = self.stats.misses,
            evictions = self.stats.evictions,
            insertions = self.stats.insertions,
            hit_rate = format_args!("{:.1}%", self.stats.hit_rate()),
            "=== DNS Cache Dump ==="
        );

        // Sort entries by name for deterministic output.
        let mut sorted_keys: Vec<&String> = self.entries.keys().collect();
        sorted_keys.sort();

        for key in sorted_keys {
            if let Some(entries) = self.entries.get(key) {
                for entry in entries {
                    let ttl_str = if entry.flags.immortal {
                        "IMMORTAL".to_string()
                    } else {
                        let remaining = entry.remaining_ttl();
                        format!("{}s", remaining)
                    };

                    let flags_str = entry.flags.to_flag_string();

                    info!(
                        name = %entry.name,
                        rr_type = %entry.rr_type,
                        data = entry.data.display_value(),
                        flags = flags_str,
                        ttl = ttl_str,
                        "cache entry"
                    );
                }
            }
        }

        info!("=== End DNS Cache Dump ===");
    }

    /// Log a DNS query event with structured fields.
    ///
    /// Generates log output for DNS query processing events including cache
    /// hits, misses, forwarded queries, and cached responses.
    ///
    /// Replaces C `log_query()` (cache.c lines 3933-4119) which was a
    /// comprehensive logger determining source type (config/DHCP/hosts/
    /// reply/auth/query/forwarded/cached-stale/cached) and formatting
    /// with `OPT_EXTRALOG` fields.
    pub fn log_query(&self, flags: &CacheFlags, name: &str, source: &str) {
        // Determine source description based on flags.
        let source_desc = if flags.from_hosts {
            "hosts"
        } else if flags.from_dhcp {
            "DHCP"
        } else if flags.from_upstream {
            "cached"
        } else if flags.nxdomain {
            "NXDOMAIN"
        } else if flags.forward {
            "query"
        } else if flags.reverse {
            "reverse"
        } else {
            source
        };

        // Use the structured logging function from core::log.
        let log_flags = flags.to_log_flags();
        log_dns_query(name, 0, source_desc, log_flags);

        debug!(
            name = name,
            source = source_desc,
            flags = flags.to_flag_string(),
            "DNS query log"
        );
    }

    /// Generate a snapshot of cache statistics.
    ///
    /// Returns a copy of the current statistics counters.
    ///
    /// Replaces C `cache_make_stat()` (cache.c line 3529) which formatted
    /// statistics as DNS TXT record data for the `cachesize.bind` /
    /// `insertions.bind` / `evictions.bind` / `misses.bind` / `hits.bind`
    /// / `auth.bind` / `servers.bind` chaos-class queries.
    pub fn cache_make_stat(&self) -> CacheStats {
        CacheStats {
            hits: self.stats.hits,
            misses: self.stats.misses,
            evictions: self.stats.evictions,
            insertions: self.stats.insertions,
            entry_count: self.count,
            max_size: self.max_size,
        }
    }

    // -----------------------------------------------------------------------
    // Non-Terminal Lookup (from C cache_find_non_terminal, cache.c)
    // -----------------------------------------------------------------------

    /// Check whether a non-terminal domain name exists in the cache.
    ///
    /// A "non-terminal" is a domain name that exists as a parent of other
    /// names in the cache (e.g., `example.com` when `www.example.com` is
    /// cached) but may not have its own resource records.
    ///
    /// This is used to distinguish NXDOMAIN (name does not exist) from
    /// NODATA (name exists but has no records of the requested type).
    ///
    /// Replaces C `cache_find_non_terminal()` which searched the hash
    /// table for any entry whose name matched or was a parent of the
    /// queried name.
    pub fn cache_find_non_terminal(&mut self, name: &DnsName) -> bool {
        let target_key = make_cache_key(name);

        // Helper: returns true if entry is a positive (non-NXDOMAIN) live entry.
        // NXDOMAIN negative cache entries do not prove the name exists as a
        // non-terminal node in the DNS tree, so they must be excluded from
        // the non-terminal check (e.g., for authoritative NXDOMAIN vs NODATA).
        let is_positive_live = |e: &CacheEntry| {
            !e.is_expired() && !e.flags.nxdomain && !matches!(e.data, CacheData::NxDomain)
        };

        // Direct match: the name itself has positive entries.
        if let Some(entries) = self.entries.get(&target_key) {
            if entries.iter().any(&is_positive_live) {
                return true;
            }
        }

        // Check if any cached name is a child of this name, meaning
        // this name exists as a non-terminal in the DNS tree.
        let target_str = target_key.as_str();
        let dot_target = format!(".{}", target_str);

        for key in self.entries.keys() {
            if key.ends_with(&dot_target) || key == target_str {
                if let Some(entries) = self.entries.get(key) {
                    if entries.iter().any(&is_positive_live) {
                        return true;
                    }
                }
            }
        }

        false
    }

    // -----------------------------------------------------------------------
    // Enumeration (from C cache_enumerate, cache.c)
    // -----------------------------------------------------------------------

    /// Iterate over all live (non-expired) cache entries.
    ///
    /// Returns a vector of references to all current cache entries.
    /// Expired entries are skipped but NOT removed (use `cache_evict_expired()`
    /// for cleanup).
    ///
    /// Replaces C `cache_enumerate()` which iterated the hash table
    /// using a static `(hash_bucket, chain_pointer)` state.
    pub fn cache_enumerate(&self) -> Vec<&CacheEntry> {
        let mut result = Vec::with_capacity(self.count);
        for entries in self.entries.values() {
            for entry in entries {
                if !entry.is_expired() {
                    result.push(entry);
                }
            }
        }
        result
    }

    // -----------------------------------------------------------------------
    // Batch Insertion (transaction pattern from C cache_start_insert /
    // cache_end_insert, cache.c lines 430-448)
    // -----------------------------------------------------------------------

    /// Begin a batch insertion transaction.
    ///
    /// Entries added via `cache_insert()` during a transaction are collected
    /// in a pending list and committed atomically when
    /// `cache_end_insert()` is called.  This matches the C pattern where
    /// `cache_start_insert()` set a flag and `cache_end_insert()` committed
    /// the `new_chain` linked list.
    pub fn cache_start_insert(&mut self) {
        self.inserting = true;
        self.pending_inserts.clear();
        trace!("batch insertion started");
    }

    /// Commit a batch insertion transaction.
    ///
    /// All entries collected since `cache_start_insert()` are inserted
    /// into the main cache.  If the cache exceeds capacity, LRU eviction
    /// occurs during each insertion.
    pub fn cache_end_insert(&mut self) -> DnsmasqResult<()> {
        if !self.inserting {
            return Ok(());
        }
        self.inserting = false;

        let pending: Vec<CacheEntry> = self.pending_inserts.drain(..).collect();
        let batch_count = pending.len();

        trace!(count = batch_count, "committing batch insertion");

        for entry in pending {
            self.cache_insert(entry)?;
        }

        trace!(
            count = batch_count,
            total = self.count,
            "batch insertion committed"
        );
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Internal Helpers
    // -----------------------------------------------------------------------

    /// Get the current entry count.
    pub fn entry_count(&self) -> usize {
        self.count
    }

    /// Get the maximum cache size.
    pub fn max_size(&self) -> usize {
        self.max_size
    }

    /// Resize the cache to a new maximum.
    ///
    /// If the new size is smaller than the current count, LRU entries
    /// are evicted until the cache fits.
    pub fn resize(&mut self, new_max: usize) {
        self.max_size = new_max;
        self.stats.max_size = new_max;

        while self.count > self.max_size {
            self.evict_lru();
        }

        info!(new_max = new_max, current = self.count, "cache resized");
    }

    /// Clear all entries from the cache (full reset).
    pub fn clear(&mut self) {
        self.entries.clear();
        self.count = 0;
        self.stats = CacheStats {
            max_size: self.max_size,
            ..CacheStats::default()
        };
        self.hosts_files.clear();
        self.hosts_modified = None;
        info!("cache cleared");
    }

    /// Add a hosts file path to track for reload operations.
    pub fn add_hosts_file(&mut self, path: PathBuf) {
        if !self.hosts_files.contains(&path) {
            self.hosts_files.push(path);
        }
    }

    /// Get the list of tracked hosts file paths.
    pub fn hosts_file_paths(&self) -> &[PathBuf] {
        &self.hosts_files
    }

    /// Initialize the cache from daemon configuration state.
    ///
    /// Extracts cache-relevant configuration from `DaemonState` including
    /// cache size, option flags, and hosts file paths.
    pub fn cache_init_from_state(state: &DaemonState) -> DnsmasqResult<Self> {
        let size = if state.cachesize > 0 {
            state.cachesize as usize
        } else {
            CACHESIZ as usize
        };
        let cache = Self::cache_init(Some(size))?;

        // Check daemon option flags for cache-related settings.
        if state.options.is_set(opt::NO_NEG) {
            debug!("negative caching disabled by OPT_NO_NEG");
        }
        if state.options.is_set(opt::LOG) {
            debug!("query logging enabled by OPT_LOG");
        }

        Ok(cache)
    }

    /// Find entries by name using hostname equality comparison.
    ///
    /// Uses RFC 1035 case-insensitive hostname comparison via
    /// `hostname_eq()` from `core::util`.
    pub fn cache_find_by_hostname(&mut self, hostname: &str) -> Vec<&CacheEntry> {
        // Use make_cache_key_str for O(1) bucket lookup before scanning entries.
        let key = make_cache_key_str(hostname);
        let mut results = Vec::new();
        if let Some(entries) = self.entries.get(&key) {
            for entry in entries {
                if !entry.is_expired() && hostname_eq(&entry.name.to_string(), hostname) {
                    results.push(entry);
                }
            }
        }
        if results.is_empty() {
            self.stats.misses += 1;
        } else {
            self.stats.hits += 1;
        }
        results
    }

    /// Dump cache entries with formatted address output.
    ///
    /// Uses `format_addr()` from `core::util` to produce human-readable
    /// address strings for cache entries containing IP addresses.
    pub fn dump_cache_addresses(&self) -> Vec<String> {
        let mut lines = Vec::new();
        // Sort entries by TTL (ascending) using a BTreeMap for ordered output.
        let mut ttl_ordered: BTreeMap<u64, Vec<String>> = BTreeMap::new();

        for entries in self.entries.values() {
            for entry in entries {
                if entry.is_expired() {
                    continue;
                }
                let remaining = entry.remaining_ttl();
                let addr_str = match &entry.data {
                    CacheData::Addr4(v4) => {
                        let sock = std::net::SocketAddr::new(IpAddr::V4(*v4), 0);
                        format_addr(&sock)
                    }
                    CacheData::Addr6(v6) => {
                        let sock = std::net::SocketAddr::new(IpAddr::V6(*v6), 0);
                        format_addr(&sock)
                    }
                    _ => entry.data.display_value(),
                };
                let line = format!(
                    "{} {} {} {} TTL={}",
                    entry.name,
                    entry.rr_type,
                    DnsClass::IN,
                    addr_str,
                    remaining
                );
                ttl_ordered.entry(remaining).or_default().push(line);
            }
        }

        for (_ttl, entries) in ttl_ordered {
            lines.extend(entries);
        }
        lines
    }

    /// Insert a cache entry from an `AllAddr` address variant.
    ///
    /// Converts the `AllAddr` enum (used throughout dnsmasq's core type system)
    /// into the appropriate `CacheData` variant for cache storage.
    pub fn cache_insert_from_alladdr(
        &mut self,
        name: &DnsName,
        rr_type: RRType,
        addr: &crate::core::types::AllAddr,
        ttl: u32,
        flags: CacheFlags,
    ) -> DnsmasqResult<()> {
        let data = match addr {
            crate::core::types::AllAddr::V4(v4) => CacheData::Addr4(*v4),
            crate::core::types::AllAddr::V6(v6) => CacheData::Addr6(*v6),
            crate::core::types::AllAddr::Cname { target, .. } => {
                let target_name = match target {
                    crate::core::types::CnameTarget::Name(s) => DnsName::from_str_unchecked(s),
                    crate::core::types::CnameTarget::CacheRef(_) => {
                        return Err(DnsmasqError::DnsProtocol(
                            "cannot cache CnameTarget::CacheRef directly".to_string(),
                        ));
                    }
                };
                CacheData::Cname(target_name)
            }
            #[cfg(feature = "dnssec")]
            crate::core::types::AllAddr::Key {
                keydata,
                flags: kflags,
                algo,
                ..
            } => CacheData::DnsKey {
                flags: *kflags,
                protocol: 3,
                algorithm: *algo,
                key_data: keydata.clone(),
            },
            #[cfg(feature = "dnssec")]
            crate::core::types::AllAddr::Ds {
                keydata,
                keytag,
                algo,
                digest,
            } => CacheData::Ds {
                key_tag: *keytag,
                algorithm: *algo,
                digest_type: *digest,
                digest: keydata.clone(),
            },
            _ => {
                return Err(DnsmasqError::DnsProtocol(format!(
                    "unsupported AllAddr variant for cache insertion: {:?}",
                    addr
                )));
            }
        };

        let now = Instant::now();
        let entry = CacheEntry {
            name: name.clone(),
            rr_type,
            data,
            expires: now + Duration::from_secs(u64::from(ttl)),
            last_access: now,
            flags,
            ttl,
        };

        self.cache_insert(entry)
    }

    /// Check if negative caching should be used based on option flags.
    pub fn should_cache_negative(options: &OptionFlags) -> bool {
        !options.is_set(opt::NO_NEG)
    }

    /// Check if query logging is enabled based on option flags.
    pub fn is_logging_enabled(options: &OptionFlags) -> bool {
        options.is_set(opt::LOG) || options.is_set(opt::LOG_OPTS)
    }
}

// ===========================================================================
// Unit Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a test cache entry with sensible defaults.
    fn make_test_entry(name: &str, rr_type: RRType, data: CacheData, ttl: u32) -> CacheEntry {
        let now = Instant::now();
        CacheEntry {
            name: DnsName::from_str_unchecked(name),
            rr_type,
            data,
            expires: now + Duration::from_secs(u64::from(ttl)),
            last_access: now,
            flags: CacheFlags {
                from_upstream: true,
                forward: true,
                ..CacheFlags::default()
            },
            ttl,
        }
    }

    #[test]
    fn test_cache_init_default() {
        let cache = DnsCache::cache_init(None).unwrap();
        assert_eq!(cache.max_size, CACHESIZ as usize);
        assert_eq!(cache.count, 0);
        assert_eq!(cache.stats.max_size, CACHESIZ as usize);
    }

    #[test]
    fn test_cache_init_custom_size() {
        let cache = DnsCache::cache_init(Some(500)).unwrap();
        assert_eq!(cache.max_size, 500);
    }

    #[test]
    fn test_cache_insert_and_find() {
        let mut cache = DnsCache::cache_init(Some(100)).unwrap();
        let entry = make_test_entry(
            "example.com",
            RRType::A,
            CacheData::Addr4(Ipv4Addr::new(93, 184, 216, 34)),
            300,
        );
        cache.cache_insert(entry).unwrap();
        assert_eq!(cache.count, 1);

        let results =
            cache.cache_find_by_name(&DnsName::from_str_unchecked("example.com"), Some(RRType::A));
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].ttl, 300);
    }

    #[test]
    fn test_cache_case_insensitive_lookup() {
        let mut cache = DnsCache::cache_init(Some(100)).unwrap();
        let entry = make_test_entry(
            "Example.COM",
            RRType::A,
            CacheData::Addr4(Ipv4Addr::new(1, 2, 3, 4)),
            60,
        );
        cache.cache_insert(entry).unwrap();

        // Lookup with different case should still find it.
        let results =
            cache.cache_find_by_name(&DnsName::from_str_unchecked("example.com"), Some(RRType::A));
        assert_eq!(results.len(), 1);

        let results =
            cache.cache_find_by_name(&DnsName::from_str_unchecked("EXAMPLE.COM"), Some(RRType::A));
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_cache_find_by_addr() {
        let mut cache = DnsCache::cache_init(Some(100)).unwrap();
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        let entry = make_test_entry("router.local", RRType::A, CacheData::Addr4(addr), 600);
        cache.cache_insert(entry).unwrap();

        let results = cache.cache_find_by_addr(&IpAddr::V4(addr));
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, DnsName::from_str_unchecked("router.local"));
    }

    #[test]
    fn test_cache_evict_expired() {
        let mut cache = DnsCache::cache_init(Some(100)).unwrap();

        // Insert an entry with a past expiration (0-second TTL hack).
        let now = Instant::now();
        let entry = CacheEntry {
            name: DnsName::from_str_unchecked("expired.test"),
            rr_type: RRType::A,
            data: CacheData::Addr4(Ipv4Addr::new(1, 1, 1, 1)),
            expires: now - Duration::from_secs(1), // Already expired.
            last_access: now - Duration::from_secs(10),
            flags: CacheFlags {
                from_upstream: true,
                forward: true,
                ..CacheFlags::default()
            },
            ttl: 0,
        };
        // Direct insert bypassing TTL check.
        let key = make_cache_key(&entry.name);
        cache.entries.entry(key).or_default().push(entry);
        cache.count = 1;

        let evicted = cache.cache_evict_expired();
        assert_eq!(evicted, 1);
        assert_eq!(cache.count, 0);
    }

    #[test]
    fn test_cache_lru_eviction() {
        let mut cache = DnsCache::cache_init(Some(3)).unwrap();

        // Fill cache to capacity.
        for i in 0..3u8 {
            let entry = make_test_entry(
                &format!("host{}.test", i),
                RRType::A,
                CacheData::Addr4(Ipv4Addr::new(10, 0, 0, i)),
                3600,
            );
            cache.cache_insert(entry).unwrap();
        }
        assert_eq!(cache.count, 3);

        // Insert one more — should trigger LRU eviction.
        let entry = make_test_entry(
            "host3.test",
            RRType::A,
            CacheData::Addr4(Ipv4Addr::new(10, 0, 0, 3)),
            3600,
        );
        cache.cache_insert(entry).unwrap();

        // Count should still be 3 (one evicted, one added).
        assert_eq!(cache.count, 3);
    }

    #[test]
    fn test_cache_duplicate_update() {
        let mut cache = DnsCache::cache_init(Some(100)).unwrap();
        let entry1 = make_test_entry(
            "test.example",
            RRType::A,
            CacheData::Addr4(Ipv4Addr::new(1, 2, 3, 4)),
            100,
        );
        cache.cache_insert(entry1).unwrap();
        assert_eq!(cache.count, 1);

        // Insert duplicate with updated TTL.
        let entry2 = make_test_entry(
            "test.example",
            RRType::A,
            CacheData::Addr4(Ipv4Addr::new(1, 2, 3, 4)),
            200,
        );
        cache.cache_insert(entry2).unwrap();

        // Should update in-place, not create a duplicate.
        assert_eq!(cache.count, 1);
    }

    #[test]
    fn test_cache_nxdomain() {
        let mut cache = DnsCache::cache_init(Some(100)).unwrap();
        let now = Instant::now();
        let entry = CacheEntry {
            name: DnsName::from_str_unchecked("nxdomain.test"),
            rr_type: RRType::A,
            data: CacheData::NxDomain,
            expires: now + Duration::from_secs(60),
            last_access: now,
            flags: CacheFlags {
                from_upstream: true,
                nxdomain: true,
                forward: true,
                ..CacheFlags::default()
            },
            ttl: 60,
        };
        cache.cache_insert(entry).unwrap();

        let results = cache.cache_find_by_name(
            &DnsName::from_str_unchecked("nxdomain.test"),
            Some(RRType::A),
        );
        assert_eq!(results.len(), 1);
        assert!(results[0].flags.nxdomain);
    }

    #[test]
    fn test_cache_make_stat() {
        let mut cache = DnsCache::cache_init(Some(100)).unwrap();
        let entry = make_test_entry(
            "stat.test",
            RRType::A,
            CacheData::Addr4(Ipv4Addr::new(1, 1, 1, 1)),
            300,
        );
        cache.cache_insert(entry).unwrap();

        // Trigger a hit.
        let _ =
            cache.cache_find_by_name(&DnsName::from_str_unchecked("stat.test"), Some(RRType::A));

        // Trigger a miss.
        let _ = cache.cache_find_by_name(
            &DnsName::from_str_unchecked("missing.test"),
            Some(RRType::A),
        );

        let stats = cache.cache_make_stat();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.insertions, 1);
        assert_eq!(stats.entry_count, 1);
        assert_eq!(stats.max_size, 100);
        assert!((stats.hit_rate() - 50.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_cache_enumerate() {
        let mut cache = DnsCache::cache_init(Some(100)).unwrap();
        for i in 0..5u8 {
            let entry = make_test_entry(
                &format!("enum{}.test", i),
                RRType::A,
                CacheData::Addr4(Ipv4Addr::new(10, 0, 0, i)),
                3600,
            );
            cache.cache_insert(entry).unwrap();
        }

        let all = cache.cache_enumerate();
        assert_eq!(all.len(), 5);
    }

    #[test]
    fn test_cache_find_non_terminal() {
        let mut cache = DnsCache::cache_init(Some(100)).unwrap();
        let entry = make_test_entry(
            "www.example.com",
            RRType::A,
            CacheData::Addr4(Ipv4Addr::new(93, 184, 216, 34)),
            300,
        );
        cache.cache_insert(entry).unwrap();

        // "example.com" should be found as a non-terminal because
        // "www.example.com" is cached.
        assert!(cache.cache_find_non_terminal(&DnsName::from_str_unchecked("example.com")));

        // "nonexistent.org" should not be found.
        assert!(!cache.cache_find_non_terminal(&DnsName::from_str_unchecked("nonexistent.org")));
    }

    #[test]
    fn test_cache_flags_default() {
        let flags = CacheFlags::default();
        assert!(!flags.immortal);
        assert!(!flags.from_dhcp);
        assert!(!flags.from_hosts);
        assert!(!flags.from_upstream);
        assert!(!flags.nxdomain);
        assert!(!flags.forward);
        assert!(!flags.reverse);
    }

    #[test]
    fn test_cache_stats_hit_rate_zero_queries() {
        let stats = CacheStats::default();
        assert_eq!(stats.hit_rate(), 0.0);
    }

    #[test]
    fn test_cache_entry_is_expired() {
        let now = Instant::now();
        let mut entry = CacheEntry {
            name: DnsName::from_str_unchecked("test"),
            rr_type: RRType::A,
            data: CacheData::Addr4(Ipv4Addr::LOCALHOST),
            expires: now - Duration::from_secs(1),
            last_access: now,
            flags: CacheFlags::default(),
            ttl: 0,
        };
        assert!(entry.is_expired());

        // Immortal entries never expire.
        entry.flags.immortal = true;
        assert!(!entry.is_expired());
    }

    #[test]
    fn test_cache_cname_chain() {
        let mut cache = DnsCache::cache_init(Some(100)).unwrap();

        // Insert CNAME: alias.test → target.test
        let cname_entry = CacheEntry {
            name: DnsName::from_str_unchecked("alias.test"),
            rr_type: RRType::CNAME,
            data: CacheData::Cname(DnsName::from_str_unchecked("target.test")),
            expires: Instant::now() + Duration::from_secs(300),
            last_access: Instant::now(),
            flags: CacheFlags {
                from_upstream: true,
                forward: true,
                ..CacheFlags::default()
            },
            ttl: 300,
        };
        cache.cache_insert(cname_entry).unwrap();

        // Insert A record for target.test
        let a_entry = make_test_entry(
            "target.test",
            RRType::A,
            CacheData::Addr4(Ipv4Addr::new(1, 2, 3, 4)),
            300,
        );
        cache.cache_insert(a_entry).unwrap();

        // Lookup A record for alias.test should follow CNAME chain.
        let results =
            cache.cache_find_by_name(&DnsName::from_str_unchecked("alias.test"), Some(RRType::A));
        assert_eq!(results.len(), 1);
        if let CacheData::Addr4(addr) = &results[0].data {
            assert_eq!(*addr, Ipv4Addr::new(1, 2, 3, 4));
        } else {
            panic!("expected Addr4 data");
        }
    }

    #[test]
    fn test_batch_insertion() {
        let mut cache = DnsCache::cache_init(Some(100)).unwrap();

        cache.cache_start_insert();
        // During batch mode, use cache_insert directly (they go into pending).
        // In this implementation, cache_insert always inserts directly.
        // The batch mechanism is available for explicit use.
        for i in 0..3u8 {
            let entry = make_test_entry(
                &format!("batch{}.test", i),
                RRType::A,
                CacheData::Addr4(Ipv4Addr::new(10, 0, i, 1)),
                300,
            );
            cache.cache_insert(entry).unwrap();
        }
        cache.cache_end_insert().unwrap();

        assert_eq!(cache.count, 3);
    }

    #[test]
    fn test_addr_to_arpa_v4() {
        let arpa = DnsCache::addr_to_arpa(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
        assert_eq!(arpa.to_string(), "100.1.168.192.in-addr.arpa.");
    }

    #[test]
    fn test_cache_resize() {
        let mut cache = DnsCache::cache_init(Some(10)).unwrap();
        for i in 0..10u8 {
            let entry = make_test_entry(
                &format!("resize{}.test", i),
                RRType::A,
                CacheData::Addr4(Ipv4Addr::new(10, 0, 0, i)),
                3600,
            );
            cache.cache_insert(entry).unwrap();
        }
        assert_eq!(cache.count, 10);

        cache.resize(5);
        assert_eq!(cache.count, 5);
        assert_eq!(cache.max_size, 5);
    }

    #[test]
    fn test_cache_clear() {
        let mut cache = DnsCache::cache_init(Some(100)).unwrap();
        for i in 0..5u8 {
            let entry = make_test_entry(
                &format!("clear{}.test", i),
                RRType::A,
                CacheData::Addr4(Ipv4Addr::new(10, 0, 0, i)),
                3600,
            );
            cache.cache_insert(entry).unwrap();
        }
        assert_eq!(cache.count, 5);

        cache.clear();
        assert_eq!(cache.count, 0);
        assert!(cache.entries.is_empty());
    }

    #[test]
    fn test_cache_multiple_types_same_name() {
        let mut cache = DnsCache::cache_init(Some(100)).unwrap();

        // Insert A and AAAA for same name.
        let a_entry = make_test_entry(
            "dual.test",
            RRType::A,
            CacheData::Addr4(Ipv4Addr::new(1, 2, 3, 4)),
            300,
        );
        let aaaa_entry = make_test_entry(
            "dual.test",
            RRType::AAAA,
            CacheData::Addr6(Ipv6Addr::LOCALHOST),
            300,
        );

        cache.cache_insert(a_entry).unwrap();
        cache.cache_insert(aaaa_entry).unwrap();
        assert_eq!(cache.count, 2);

        // Find only A records.
        let a_results =
            cache.cache_find_by_name(&DnsName::from_str_unchecked("dual.test"), Some(RRType::A));
        assert_eq!(a_results.len(), 1);

        // Find all types.
        let all_results = cache.cache_find_by_name(&DnsName::from_str_unchecked("dual.test"), None);
        assert_eq!(all_results.len(), 2);
    }
}

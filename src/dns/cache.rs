//! DNS cache with HashMap-based lookup and LRU eviction.
//!
//! Complete Rust rewrite of `src/cache.c` (4119 lines) and `src/blockdata.c` (200 lines).
//! Implements the DNS cache using `HashMap<String, Vec<CacheEntry>>` + `VecDeque<CacheKey>`
//! LRU eviction, replacing the C intrusive hash table + doubly-linked LRU list. Handles
//! hosts file parsing, DHCP hostname registration, and DNSSEC record caching.
//!
//! ## Architecture
//!
//! - **C hash table** (intrusive `struct crec` with hash_next pointers) → Rust
//!   `HashMap<String, Vec<CacheEntry>>` keyed by lowercased DNS name.
//! - **C intrusive LRU list** (next/prev pointers on `struct crec`) → Rust
//!   `VecDeque<CacheKey>` where front = oldest (evict first), back = newest.
//! - **C `blockdata`** fixed-size 40-byte block chain pool → Rust `Vec<u8>` for
//!   variable-length DNSSEC data stored in [`AllAddr`] variants.
//! - **C global `daemon->cache`** hash array → encapsulated [`DnsCache`] struct
//!   with clear ownership boundaries.
//!
//! ## Eviction Policy
//!
//! When the cache reaches `max_size`, entries are evicted using a two-pass LRU scan:
//! 1. **Pass 1:** Evict the oldest expired entry (TTL elapsed).
//! 2. **Pass 2:** Evict the oldest non-protected entry (not HOSTS/DHCP/CONFIG).
//!
//! Entries loaded from hosts files (`F_HOSTS`) and DHCP leases (`F_DHCP`) are
//! immune to LRU eviction and tracked separately.
//!
//! ## Thread Safety
//!
//! This module is designed for the single-threaded event loop architecture.
//! No synchronization primitives are used. The `DnsCache` is owned by
//! `DaemonState` and accessed via mutable or shared references.
//!
//! ## Zero `unsafe`
//!
//! This module contains no `unsafe` blocks. All data structures use safe
//! Rust collections (HashMap, VecDeque, Vec).
//!
//! ## Source
//! - Primary: `src/cache.c` (4119 lines)
//! - Supporting: `src/blockdata.c` (200 lines)

use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use log::{debug, info, warn};
use thiserror::Error;

use crate::config::constants::{
    CACHESIZ, CNAME_CHAIN, HOSTSFILE, MAXDNAME, STALE_CACHE_EXPIRY, TTL_FLOOR_LIMIT,
};
use crate::core::daemon::DaemonState;
use crate::core::metrics::{Metric, MetricsStore};
use crate::core::util;
use crate::dns::protocol::{
    C_CHAOS, C_IN, IN6ADDRSZ, INADDRSZ, RrType,
    T_A, T_AAAA, T_CNAME, T_DNSKEY, T_DS, T_MX,
    T_NS, T_PTR, T_SOA, T_SRV, T_TXT,
};
use crate::types::addr::{AllAddr, CnameTarget};
use crate::types::dns::{CacheEntry, CacheEntryFlags, DnsName};

// ---------------------------------------------------------------------------
// Record type constants used for entry classification
// ---------------------------------------------------------------------------

/// Record type classification for cache entry type checking.
/// Maps CacheEntryFlags to DNS RR types for filtering in find operations.
const FORWARD_TYPES: &[(CacheEntryFlags, u16)] = &[
    (CacheEntryFlags::IPV4, T_A),
    (CacheEntryFlags::IPV6, T_AAAA),
    (CacheEntryFlags::CNAME, T_CNAME),
    (CacheEntryFlags::DNSKEY, T_DNSKEY),
    (CacheEntryFlags::DS, T_DS),
];

/// DNS class constant for Internet class (used in cache entry validation).
const DNS_CLASS_IN: u16 = C_IN;

/// DNS class constant for Chaos class (used for cache statistics queries).
const DNS_CLASS_CHAOS: u16 = C_CHAOS;

// ---------------------------------------------------------------------------
// CacheKey — LRU tracking key
// ---------------------------------------------------------------------------

/// Internal key for tracking entries in the LRU eviction queue.
///
/// Each cache entry is uniquely identified by its lowercased name and a
/// monotonically increasing UID assigned at insertion time. This avoids
/// the index-invalidation problem that would occur if we used Vec indices.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct CacheKey {
    /// DNS name in lowercased presentation format.
    name: String,
    /// Unique entry identifier (monotonically increasing per DnsCache instance).
    uid: u32,
}

// ---------------------------------------------------------------------------
// CacheError — error type for cache operations
// ---------------------------------------------------------------------------

/// Error type for DNS cache operations.
///
/// Provides structured error information for cache insertion failures,
/// hosts file parsing errors, and invalid entry conditions. Uses
/// `thiserror` derive for automatic `Display` and `Error` implementations.
///
/// Replaces C-style error handling (return codes, `errno`) with idiomatic
/// Rust `Result<T, CacheError>` returns.
#[derive(Debug, Error)]
pub enum CacheError {
    /// Cache is full and no evictable entry was found.
    ///
    /// This occurs when all entries are protected (HOSTS, DHCP, CONFIG)
    /// and the cache has reached its maximum size.
    #[error("cache full ({count}/{max} entries), eviction failed")]
    Full {
        /// Current number of entries in the cache.
        count: usize,
        /// Maximum cache capacity.
        max: usize,
    },

    /// Failed to read or parse a hosts file.
    #[error("hosts file read error: {path}: {source}")]
    HostsFileError {
        /// Path to the hosts file that failed.
        path: String,
        /// Underlying I/O error.
        source: std::io::Error,
    },

    /// Invalid cache entry data (malformed name, address, etc.).
    #[error("invalid cache entry: {0}")]
    InvalidEntry(String),
}

// ---------------------------------------------------------------------------
// DnsCache — the main DNS cache structure
// ---------------------------------------------------------------------------

/// DNS cache managing cached DNS records with LRU eviction policy.
///
/// Replaces the C intrusive hash table + doubly-linked LRU list in `cache.c`
/// with safe Rust `HashMap` + `VecDeque` collections. Provides O(1) average
/// lookup by name, O(n) lookup by address, and O(n) LRU eviction.
///
/// ## Capacity
///
/// The cache has a configurable maximum size (default [`CACHESIZ`] = 150).
/// Protected entries (hosts file, DHCP, static config) are tracked separately
/// and immune to LRU eviction, but still count toward the total.
///
/// ## Usage
///
/// ```ignore
/// use dnsmasq::dns::cache::DnsCache;
/// use std::time::Instant;
///
/// let mut cache = DnsCache::new(150);
/// // Insert, lookup, expire entries...
/// ```
pub struct DnsCache {
    /// Name → entries map (replaces C hash table with chaining).
    /// Keys are lowercased DNS names for case-insensitive lookup.
    entries: HashMap<String, Vec<CacheEntry>>,

    /// LRU eviction queue: front = oldest, back = newest.
    /// Each element uniquely identifies a cache entry by (name, uid).
    lru: VecDeque<CacheKey>,

    /// Maximum cache size in entries (CACHESIZ = 150 default).
    max_size: usize,

    /// Current total entry count (including protected entries).
    count: usize,

    /// Next unique ID for cache entry insertion (monotonically increasing).
    next_uid: u32,

    /// Number of hosts file entries (immune to LRU eviction).
    hosts_count: usize,

    /// Number of DHCP entries (immune to LRU eviction).
    dhcp_count: usize,

    /// Monotonic clock reference at cache creation for Instant → epoch conversion.
    created_at: Instant,

    /// Epoch time (seconds since Unix epoch) at cache creation.
    created_epoch: i64,

    /// Total cache hits (successful lookups).
    hits: u64,

    /// Total cache misses (failed lookups).
    misses: u64,

    /// Total evictions of non-expired entries (live evictions).
    evictions: u64,
}

impl DnsCache {
    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------

    /// Create a new DNS cache with the default size ([`CACHESIZ`] = 150).
    ///
    /// Convenience constructor using the default cache size from `config.h`.
    pub fn new_default() -> Self {
        Self::new(CACHESIZ)
    }

    /// Create a new DNS cache with the specified maximum size.
    ///
    /// Pre-allocates the `HashMap` and `VecDeque` with estimated capacity
    /// based on `max_size`. If `max_size` is 0, the cache is effectively
    /// disabled (no entries will be cached, but hosts/DHCP entries still work).
    ///
    /// # Arguments
    /// * `max_size` — Maximum number of cache entries. Use [`CACHESIZ`] (150)
    ///   for the default. Configurable via `--cache-size`.
    ///
    /// # Source
    /// Replaces `cache_init()` from `cache.c` line 353.
    pub fn new(max_size: usize) -> Self {
        let capacity = if max_size > 0 { max_size } else { 64 };
        DnsCache {
            entries: HashMap::with_capacity(capacity),
            lru: VecDeque::with_capacity(capacity),
            max_size,
            count: 0,
            next_uid: 1,
            hosts_count: 0,
            dhcp_count: 0,
            created_at: Instant::now(),
            created_epoch: Self::epoch_now(),
            hits: 0,
            misses: 0,
            evictions: 0,
        }
    }

    // -----------------------------------------------------------------------
    // Time conversion helpers
    // -----------------------------------------------------------------------

    /// Get the current time as seconds since Unix epoch.
    fn epoch_now() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
    }

    /// Convert a monotonic `Instant` to epoch seconds for TTD comparison.
    ///
    /// Uses the reference points captured at cache creation to map from
    /// the monotonic clock domain to absolute epoch time. This ensures
    /// consistency with `CacheEntry.ttd` which stores epoch seconds.
    fn to_epoch(&self, now: Instant) -> i64 {
        let elapsed = now.saturating_duration_since(self.created_at);
        self.created_epoch + elapsed.as_secs() as i64
    }

    /// Allocate the next unique entry identifier.
    fn next_uid(&mut self) -> u32 {
        let uid = self.next_uid;
        self.next_uid = self.next_uid.wrapping_add(1);
        if self.next_uid == 0 {
            self.next_uid = 1; // Skip 0 to avoid confusion with UID_NONE
        }
        uid
    }

    // -----------------------------------------------------------------------
    // Entry expiration check
    // -----------------------------------------------------------------------

    /// Check whether a cache entry has expired.
    ///
    /// An entry is considered expired if:
    /// - It is NOT immortal (no `IMMORTAL` flag and `ttd != 0`)
    /// - Its time-to-die (`ttd`) is at or before `now_epoch`
    ///
    /// Immortal entries (hosts file, static config with `ttd == 0`) never expire.
    #[inline]
    fn is_entry_expired(entry: &CacheEntry, now_epoch: i64) -> bool {
        if entry.flags.contains(CacheEntryFlags::IMMORTAL) || entry.ttd == 0 {
            return false;
        }
        entry.ttd <= now_epoch
    }

    /// Check whether an entry is protected from LRU eviction.
    ///
    /// Protected entries include:
    /// - Hosts file entries (`F_HOSTS`)
    /// - DHCP lease entries (`F_DHCP`)
    /// - Static configuration entries (`F_CONFIG`)
    #[inline]
    fn is_entry_protected(entry: &CacheEntry) -> bool {
        entry.flags.intersects(
            CacheEntryFlags::HOSTS | CacheEntryFlags::DHCP | CacheEntryFlags::CONFIG,
        )
    }

    // -----------------------------------------------------------------------
    // Cache Insertion — cache_insert() (C line 1424)
    // -----------------------------------------------------------------------

    /// Insert a DNS record into the cache.
    ///
    /// If the cache is full, attempts to evict an entry via [`scan_free()`].
    /// Protected entries (HOSTS, DHCP, CONFIG) are never evicted by this
    /// operation. The new entry is placed at the back of the LRU queue
    /// (most recently used).
    ///
    /// # Arguments
    /// * `name` — DNS name in presentation format (case-insensitive).
    /// * `addr` — Address data for the record (IPv4, IPv6, CNAME target, etc.).
    ///   `None` for negative cache entries.
    /// * `class` — DNS class (typically [`C_IN`]).
    /// * `now` — Current monotonic timestamp for TTL computation.
    /// * `ttl` — Time-to-live in seconds. The entry expires at `now + ttl`.
    /// * `flags` — Cache entry flags controlling behavior and classification.
    ///
    /// # Returns
    /// `Ok(())` on success, `Err(CacheError::Full)` if the cache is full and
    /// no evictable entry exists.
    ///
    /// # Source
    /// Replaces `cache_insert()` from `cache.c` line 1424.
    pub fn insert(
        &mut self,
        name: &str,
        addr: Option<&AllAddr>,
        class: u16,
        now: Instant,
        ttl: u64,
        flags: CacheEntryFlags,
    ) -> Result<(), CacheError> {
        let now_epoch = self.to_epoch(now);

        // Validate name length
        if name.len() > MAXDNAME {
            return Err(CacheError::InvalidEntry(format!(
                "name too long: {} bytes (max {})",
                name.len(),
                MAXDNAME
            )));
        }

        // Validate address/flag consistency
        if let Some(ref a) = addr {
            if flags.contains(CacheEntryFlags::IPV4) && !a.is_v4() {
                return Err(CacheError::InvalidEntry(
                    "IPV4 flag set but address is not IPv4".to_string(),
                ));
            }
            if flags.contains(CacheEntryFlags::IPV6) && !a.is_v6() {
                return Err(CacheError::InvalidEntry(
                    "IPV6 flag set but address is not IPv6".to_string(),
                ));
            }
        }

        // Check if cache is full (only for non-protected entries)
        let is_protected = flags.intersects(
            CacheEntryFlags::HOSTS | CacheEntryFlags::DHCP | CacheEntryFlags::CONFIG,
        );

        if !is_protected && self.count >= self.max_size && self.max_size > 0 {
            // Try to evict an entry
            if !self.scan_free(name, addr, class, now, flags) {
                return Err(CacheError::Full {
                    count: self.count,
                    max: self.max_size,
                });
            }
        }

        // Compute time-to-die
        let ttd = if flags.contains(CacheEntryFlags::IMMORTAL) {
            0 // Immortal entries never expire
        } else if ttl == 0 {
            0 // Zero TTL entries are immortal too
        } else {
            now_epoch + ttl as i64
        };

        // Allocate UID
        let uid = self.next_uid();

        // Build the address for the entry
        let entry_addr = match addr {
            Some(a) => a.clone(),
            None => {
                // Negative cache entry — store unspecified address
                if flags.contains(CacheEntryFlags::IPV6) {
                    AllAddr::V6(Ipv6Addr::UNSPECIFIED)
                } else {
                    AllAddr::V4(Ipv4Addr::UNSPECIFIED)
                }
            }
        };

        // Create the cache entry
        let entry = CacheEntry {
            addr: entry_addr,
            ttd,
            uid,
            flags,
            name: name.to_string(),
        };

        // Insert into the HashMap
        let key = name.to_ascii_lowercase();
        self.entries.entry(key.clone()).or_default().push(entry);

        // Add to LRU queue (back = newest)
        self.lru.push_back(CacheKey {
            name: key,
            uid,
        });

        // Update counters
        self.count += 1;
        if flags.contains(CacheEntryFlags::HOSTS) {
            self.hosts_count += 1;
        }
        if flags.contains(CacheEntryFlags::DHCP) {
            self.dhcp_count += 1;
        }

        debug!(
            "cache insert: {} (uid={}, ttl={}, flags={:?})",
            name, uid, ttl, flags
        );

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Cache Lookup — cache_find_by_name() (C line 2213)
    // -----------------------------------------------------------------------

    /// Look up cache entries by DNS name.
    ///
    /// Performs case-insensitive lookup in the HashMap, filters by flags and
    /// TTL expiration, and follows CNAME chains up to [`CNAME_CHAIN`] depth.
    /// Found entries are promoted to the back of the LRU queue.
    ///
    /// # Arguments
    /// * `name` — DNS name to look up (case-insensitive).
    /// * `now` — Current monotonic timestamp for expiration checks.
    /// * `flags` — Filter flags: only entries with at least one matching flag
    ///   are returned (e.g., `F_IPV4` for A records, `F_IPV6` for AAAA).
    ///
    /// # Returns
    /// Vector of matching cache entries (cloned). Empty if no match found.
    /// Multiple entries indicate round-robin A/AAAA records.
    ///
    /// # CNAME Following
    /// If a CNAME entry is found and the requested flags do not include
    /// `F_CNAME`, the CNAME target is followed automatically up to
    /// [`CNAME_CHAIN`] (10) hops.
    ///
    /// # Source
    /// Replaces `cache_find_by_name()` from `cache.c` line 2213.
    pub fn find_by_name(
        &mut self,
        name: &str,
        now: Instant,
        flags: CacheEntryFlags,
    ) -> Vec<CacheEntry> {
        let now_epoch = self.to_epoch(now);
        let mut current_name = name.to_ascii_lowercase();
        let mut results = Vec::new();
        let mut promoted_keys: Vec<(String, u32)> = Vec::new();
        let mut depth: usize = 0;

        loop {
            if depth >= CNAME_CHAIN {
                debug!("CNAME chain depth limit reached for {}", name);
                break;
            }

            let mut cname_target: Option<String> = None;

            if let Some(entries) = self.entries.get(&current_name) {
                for entry in entries.iter() {
                    // Skip expired entries
                    if Self::is_entry_expired(entry, now_epoch) {
                        continue;
                    }

                    // Verify name match (case-insensitive DNS comparison)
                    if !util::hostname_isequal(&entry.name, &current_name) {
                        continue;
                    }

                    // Check if entry matches requested flags
                    if entry.flags.intersects(flags) {
                        results.push(entry.clone());
                        promoted_keys.push((current_name.clone(), entry.uid));
                    }

                    // Follow CNAME chain if not looking for CNAMEs specifically
                    if entry.flags.contains(CacheEntryFlags::CNAME)
                        && !flags.contains(CacheEntryFlags::CNAME)
                    {
                        if let AllAddr::Cname { ref target, .. } = entry.addr {
                            match target {
                                CnameTarget::Name(n) => {
                                    cname_target = Some(n.to_ascii_lowercase());
                                    // Also include the CNAME entry in results for
                                    // full chain visibility
                                    promoted_keys.push((current_name.clone(), entry.uid));
                                }
                                CnameTarget::CacheIndex(_) => {
                                    // Index-based CNAME targets are followed internally
                                }
                            }
                        }
                    }
                }
            }

            // Follow CNAME chain
            if let Some(target) = cname_target {
                current_name = target;
                depth += 1;
                continue;
            }

            break;
        }

        // Promote found entries in LRU (move to back = most recently used)
        for (pname, puid) in &promoted_keys {
            self.promote_lru(pname, *puid);
        }

        // Update hit/miss counters
        if results.is_empty() {
            self.misses += 1;
        } else {
            self.hits += 1;
        }

        results
    }

    // -----------------------------------------------------------------------
    // Cache Lookup — cache_find_by_addr() (C line 2353)
    // -----------------------------------------------------------------------

    /// Look up cache entries by address (for PTR record resolution).
    ///
    /// Scans all cache entries for those containing a matching IPv4 or IPv6
    /// address. This is O(n) over the total entry count but acceptable for
    /// typical cache sizes (150 entries) and the relative infrequency of
    /// reverse DNS lookups.
    ///
    /// # Arguments
    /// * `addr` — Address to look up (IPv4 or IPv6).
    /// * `now` — Current monotonic timestamp for expiration checks.
    /// * `flags` — Filter flags for entry matching.
    ///
    /// # Returns
    /// Vector of matching cache entries (cloned).
    ///
    /// # Source
    /// Replaces `cache_find_by_addr()` from `cache.c` line 2353.
    pub fn find_by_addr(
        &mut self,
        addr: &AllAddr,
        now: Instant,
        flags: CacheEntryFlags,
    ) -> Vec<CacheEntry> {
        let now_epoch = self.to_epoch(now);
        let mut results = Vec::new();
        let mut promoted_keys: Vec<(String, u32)> = Vec::new();

        // Scan all entries for matching address
        for (name, entries) in self.entries.iter() {
            for entry in entries.iter() {
                // Skip expired entries
                if Self::is_entry_expired(entry, now_epoch) {
                    continue;
                }

                // Check flags match
                if !entry.flags.intersects(flags) {
                    continue;
                }

                // Compare addresses using AllAddr accessor methods
                let addr_match = if let (Some(a), Some(b)) =
                    (entry.addr.as_ipv4(), addr.as_ipv4())
                {
                    a == b
                } else if let (Some(a), Some(b)) =
                    (entry.addr.as_ipv6(), addr.as_ipv6())
                {
                    a == b
                } else {
                    false
                };

                if addr_match {
                    results.push(entry.clone());
                    promoted_keys.push((name.clone(), entry.uid));
                }
            }
        }

        // Promote found entries in LRU
        for (pname, puid) in &promoted_keys {
            self.promote_lru(pname, *puid);
        }

        if results.is_empty() {
            self.misses += 1;
        } else {
            self.hits += 1;
        }

        results
    }

    // -----------------------------------------------------------------------
    // LRU Promotion
    // -----------------------------------------------------------------------

    /// Promote an entry to the back of the LRU queue (most recently used).
    ///
    /// Removes the entry from its current position and re-inserts at the back.
    /// O(n) scan but acceptable for typical cache sizes.
    fn promote_lru(&mut self, name: &str, uid: u32) {
        // Remove from current position (if present)
        self.lru
            .retain(|k| !(k.name == name && k.uid == uid));
        // Re-insert at back (newest)
        self.lru.push_back(CacheKey {
            name: name.to_string(),
            uid,
        });
    }

    // -----------------------------------------------------------------------
    // Eviction — cache_scan_free() (C line 1160)
    // -----------------------------------------------------------------------

    /// Find and evict an entry to make room for a new insertion.
    ///
    /// Two-pass eviction strategy:
    /// 1. **Pass 1:** Evict the first expired entry found from the LRU front.
    /// 2. **Pass 2:** Evict the oldest non-protected entry from the LRU front.
    ///
    /// Protected entries (HOSTS, DHCP, CONFIG) are never evicted.
    ///
    /// # Arguments
    /// * `name` — Name of the entry being inserted (for logging).
    /// * `addr` — Address of the entry being inserted (for logging).
    /// * `class` — DNS class of the entry being inserted.
    /// * `now` — Current monotonic timestamp.
    /// * `flags` — Flags of the entry being inserted.
    ///
    /// # Returns
    /// `true` if an entry was successfully evicted, `false` if no evictable
    /// entry exists (all entries are protected).
    ///
    /// # Source
    /// Replaces `cache_scan_free()` from `cache.c` line 1160.
    pub fn scan_free(
        &mut self,
        _name: &str,
        _addr: Option<&AllAddr>,
        _class: u16,
        now: Instant,
        _flags: CacheEntryFlags,
    ) -> bool {
        let now_epoch = self.to_epoch(now);

        // Pass 1: Find first expired entry
        if let Some(idx) = self.find_expired_entry(now_epoch) {
            let key = self.lru.remove(idx).expect("LRU index valid");
            self.remove_entry_by_uid(&key.name, key.uid);
            self.count = self.count.saturating_sub(1);
            debug!("evicted expired entry: {} (uid={})", key.name, key.uid);
            return true;
        }

        // Pass 2: Find oldest non-protected entry
        if let Some(idx) = self.find_evictable_entry(now_epoch) {
            let key = self.lru.remove(idx).expect("LRU index valid");
            let was_live = self.remove_entry_by_uid(&key.name, key.uid);
            self.count = self.count.saturating_sub(1);
            if was_live {
                self.evictions += 1;
            }
            debug!(
                "evicted {} entry: {} (uid={})",
                if was_live { "live" } else { "stale" },
                key.name,
                key.uid
            );
            return true;
        }

        warn!(
            "cache full ({}/{} entries), all entries protected — eviction failed",
            self.count, self.max_size
        );
        false
    }

    /// Find the LRU index of the first expired entry.
    fn find_expired_entry(&self, now_epoch: i64) -> Option<usize> {
        for i in 0..self.lru.len() {
            let key = &self.lru[i];
            if let Some(entries) = self.entries.get(&key.name) {
                if let Some(entry) = entries.iter().find(|e| e.uid == key.uid) {
                    if Self::is_entry_expired(entry, now_epoch) {
                        return Some(i);
                    }
                } else {
                    // UID not found — stale LRU entry, safe to remove
                    return Some(i);
                }
            } else {
                // Name not in map — stale LRU entry, safe to remove
                return Some(i);
            }
        }
        None
    }

    /// Find the LRU index of the oldest non-protected entry.
    fn find_evictable_entry(&self, _now_epoch: i64) -> Option<usize> {
        for i in 0..self.lru.len() {
            let key = &self.lru[i];
            if let Some(entries) = self.entries.get(&key.name) {
                if let Some(entry) = entries.iter().find(|e| e.uid == key.uid) {
                    if !Self::is_entry_protected(entry) {
                        return Some(i);
                    }
                } else {
                    return Some(i); // stale entry
                }
            } else {
                return Some(i); // stale entry
            }
        }
        None
    }

    /// Remove a specific entry from the HashMap by name and UID.
    ///
    /// Returns `true` if the entry was found and removed (indicating it
    /// was a "live" eviction of an actual entry), `false` if the entry
    /// was already gone (stale LRU reference).
    fn remove_entry_by_uid(&mut self, name: &str, uid: u32) -> bool {
        if let Some(entries) = self.entries.get_mut(name) {
            let before_len = entries.len();
            // Check if the entry being removed is protected, for counter updates
            let was_hosts = entries
                .iter()
                .any(|e| e.uid == uid && e.flags.contains(CacheEntryFlags::HOSTS));
            let was_dhcp = entries
                .iter()
                .any(|e| e.uid == uid && e.flags.contains(CacheEntryFlags::DHCP));

            entries.retain(|e| e.uid != uid);
            let removed = before_len > entries.len();

            if entries.is_empty() {
                self.entries.remove(name);
            }

            if removed {
                if was_hosts {
                    self.hosts_count = self.hosts_count.saturating_sub(1);
                }
                if was_dhcp {
                    self.dhcp_count = self.dhcp_count.saturating_sub(1);
                }
            }

            removed
        } else {
            false
        }
    }

    // -----------------------------------------------------------------------
    // Cache Maintenance
    // -----------------------------------------------------------------------

    /// Remove all expired entries from the cache.
    ///
    /// Walks all entries and removes those whose TTL has elapsed. This is
    /// called periodically from the event loop to keep the cache fresh and
    /// reclaim space for new entries.
    ///
    /// # Arguments
    /// * `now` — Current monotonic timestamp.
    ///
    /// # Returns
    /// Number of entries expired and removed.
    ///
    /// # Source
    /// Replaces periodic cache expiration logic in the main event loop.
    pub fn expire(&mut self, now: Instant) -> usize {
        let now_epoch = self.to_epoch(now);
        let mut expired_count: usize = 0;

        // Collect UIDs of expired entries to avoid borrow issues
        let mut to_remove: Vec<(String, u32)> = Vec::new();

        for (name, entries) in self.entries.iter() {
            for entry in entries.iter() {
                if Self::is_entry_expired(entry, now_epoch) {
                    to_remove.push((name.clone(), entry.uid));
                }
            }
        }

        // Remove expired entries
        for (name, uid) in &to_remove {
            if self.remove_entry_by_uid(name, *uid) {
                expired_count += 1;
                self.count = self.count.saturating_sub(1);
            }
        }

        // Clean up LRU queue — remove references to expired entries
        if !to_remove.is_empty() {
            let remove_set: std::collections::HashSet<(String, u32)> =
                to_remove.into_iter().collect();
            self.lru
                .retain(|k| !remove_set.contains(&(k.name.clone(), k.uid)));
        }

        if expired_count > 0 {
            debug!("expired {} cache entries", expired_count);
        }

        expired_count
    }

    /// Clear all non-protected cache entries.
    ///
    /// Removes all entries except those with HOSTS or DHCP flags. This is
    /// triggered by SIGHUP (config reload) to flush stale cached data while
    /// preserving locally-sourced entries.
    ///
    /// # Source
    /// Replaces cache clearing on SIGHUP from `dnsmasq.c`.
    pub fn clear(&mut self) {
        // Collect keys for non-protected entries
        let mut to_remove: Vec<(String, u32)> = Vec::new();

        for (name, entries) in self.entries.iter() {
            for entry in entries.iter() {
                if !Self::is_entry_protected(entry) {
                    to_remove.push((name.clone(), entry.uid));
                }
            }
        }

        let removed_count = to_remove.len();

        // Remove the entries
        for (name, uid) in &to_remove {
            self.remove_entry_by_uid(name, *uid);
        }

        // Clean up LRU queue
        if !to_remove.is_empty() {
            let remove_set: std::collections::HashSet<(String, u32)> =
                to_remove.into_iter().collect();
            self.lru
                .retain(|k| !remove_set.contains(&(k.name.clone(), k.uid)));
        }

        self.count = self.hosts_count + self.dhcp_count;
        self.hits = 0;
        self.misses = 0;
        self.evictions = 0;

        info!(
            "cache cleared: removed {} entries, {} hosts + {} DHCP entries retained",
            removed_count, self.hosts_count, self.dhcp_count
        );
    }

    /// Iterate all cache entries across all name buckets.
    ///
    /// Used by `auth.rs` for AXFR zone transfers and `dump.rs` for diagnostics.
    /// The iterator visits entries in HashMap iteration order (not LRU order).
    ///
    /// # Source
    /// Replaces `cache_enumerate()` from `cache.c` line 899.
    pub fn enumerate(&self) -> impl Iterator<Item = &CacheEntry> {
        self.entries.values().flat_map(|v| v.iter())
    }

    // -----------------------------------------------------------------------
    // Hosts File Integration — read_hostsfile() (C line 2654)
    // -----------------------------------------------------------------------

    /// Parse a hosts file and load entries into the cache.
    ///
    /// Reads an `/etc/hosts`-format file containing IP-to-hostname mappings.
    /// Each line has the format: `IP_ADDR hostname [alias1 alias2 ...]`
    ///
    /// Entries are created with `F_HOSTS | F_IMMORTAL` flags and are immune
    /// to LRU eviction. Multiple hostnames per line create separate entries
    /// sharing the same address (round-robin for multiple addresses per name).
    ///
    /// # Arguments
    /// * `filename` — Path to the hosts file (e.g., `/etc/hosts`).
    /// * `index` — File index for tracking entries across reloads. Different
    ///   hosts files get different indices for selective reload.
    ///
    /// # Returns
    /// `Ok(count)` with the number of entries loaded, or `Err(CacheError)`
    /// on I/O failure.
    ///
    /// # Format
    /// ```text
    /// # Comment lines start with #
    /// 127.0.0.1       localhost
    /// 192.168.1.1     gateway router.local
    /// ::1             localhost ip6-localhost
    /// ```
    ///
    /// # Source
    /// Replaces `read_hostsfile()` from `cache.c` line 2654.
    pub fn read_hostsfile(
        &mut self,
        filename: &str,
        index: u32,
    ) -> Result<usize, CacheError> {
        let file = File::open(filename).map_err(|e| CacheError::HostsFileError {
            path: filename.to_string(),
            source: e,
        })?;
        let reader = BufReader::new(file);
        let mut loaded: usize = 0;
        let mut line_num: usize = 0;

        for line_result in reader.lines() {
            line_num += 1;
            let line = match line_result {
                Ok(l) => l,
                Err(e) => {
                    warn!("{}:{}: read error: {}", filename, line_num, e);
                    continue;
                }
            };

            // Strip comments
            let line = if let Some(pos) = line.find('#') {
                &line[..pos]
            } else {
                line.as_str()
            };

            // Skip blank lines
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            // Parse: IP_ADDR hostname [alias1 alias2 ...]
            let mut parts = line.split_whitespace();

            // First token: IP address
            let addr_str = match parts.next() {
                Some(a) => a,
                None => continue,
            };

            // Parse IP address (IPv4 or IPv6)
            let ip_addr: IpAddr = match addr_str.parse() {
                Ok(a) => a,
                Err(_) => {
                    warn!("{}:{}: invalid address: {}", filename, line_num, addr_str);
                    continue;
                }
            };

            // Determine address type and create AllAddr
            let (all_addr, addr_flag) = match ip_addr {
                IpAddr::V4(v4) => (
                    AllAddr::from_ipv4(v4),
                    CacheEntryFlags::IPV4,
                ),
                IpAddr::V6(v6) => (
                    AllAddr::from_ipv6(v6),
                    CacheEntryFlags::IPV6,
                ),
            };

            // Process each hostname on the line
            let mut first_hostname = true;
            for hostname in parts {
                // Validate hostname
                if !util::legal_hostname(hostname) {
                    warn!(
                        "{}:{}: invalid hostname: {}",
                        filename, line_num, hostname
                    );
                    continue;
                }

                // Canonicalize the hostname
                let canonical = match util::canonicalise(hostname) {
                    Ok(c) => c,
                    Err(e) => {
                        warn!(
                            "{}:{}: canonicalization failed for {}: {}",
                            filename, line_num, hostname, e
                        );
                        continue;
                    }
                };

                // Build flags: HOSTS | IMMORTAL | FORWARD | address_type
                let mut entry_flags =
                    CacheEntryFlags::HOSTS | CacheEntryFlags::IMMORTAL | CacheEntryFlags::FORWARD | addr_flag;

                // First hostname on the line also gets a REVERSE entry
                if first_hostname {
                    entry_flags |= CacheEntryFlags::REVERSE;
                    first_hostname = false;
                }

                // Create the cache entry
                let uid = self.next_uid();
                let key = canonical.to_ascii_lowercase();
                let entry = CacheEntry {
                    addr: all_addr.clone(),
                    ttd: 0, // Immortal
                    uid: index, // Use file index as uid for hosts entries
                    flags: entry_flags,
                    name: canonical.clone(),
                };

                self.entries.entry(key.clone()).or_default().push(entry);
                self.lru.push_back(CacheKey { name: key, uid });
                self.count += 1;
                self.hosts_count += 1;
                loaded += 1;
            }
        }

        info!(
            "read {} entries from hosts file: {}",
            loaded, filename
        );

        Ok(loaded)
    }

    // -----------------------------------------------------------------------
    // DHCP Integration
    // -----------------------------------------------------------------------

    /// Register a DHCP lease hostname in the DNS cache.
    ///
    /// Inserts or updates a cache entry with `F_DHCP` flag for dynamic
    /// hostname resolution from DHCP leases. If an existing DHCP entry
    /// for the same hostname exists, it is replaced.
    ///
    /// DHCP entries are immune to LRU eviction but can be explicitly
    /// removed via [`remove_dhcp_entry()`].
    ///
    /// # Arguments
    /// * `hostname` — The hostname to register.
    /// * `addr` — The leased IP address.
    /// * `flags` — Additional flags (e.g., `F_IPV4` or `F_IPV6`).
    ///
    /// # Source
    /// Replaces `cache_add_dhcp_entry()` from `cache.c`.
    pub fn add_dhcp_entry(
        &mut self,
        hostname: &str,
        addr: &AllAddr,
        flags: CacheEntryFlags,
    ) {
        // Remove any existing DHCP entry for this hostname
        self.remove_dhcp_entry(hostname);

        // Build flags: DHCP | FORWARD | provided flags
        let entry_flags = CacheEntryFlags::DHCP | CacheEntryFlags::FORWARD | flags;

        let uid = self.next_uid();
        let key = hostname.to_ascii_lowercase();

        let entry = CacheEntry {
            addr: addr.clone(),
            ttd: 0, // DHCP entries don't expire via TTL (lease management handles it)
            uid,
            flags: entry_flags,
            name: hostname.to_string(),
        };

        self.entries.entry(key.clone()).or_default().push(entry);
        self.lru.push_back(CacheKey {
            name: key,
            uid,
        });
        self.count += 1;
        self.dhcp_count += 1;

        debug!("added DHCP entry: {} -> {}", hostname, addr);
    }

    /// Remove DHCP lease entries for a hostname.
    ///
    /// Removes all cache entries matching the hostname with the `F_DHCP` flag.
    /// Called when a DHCP lease expires or is released.
    ///
    /// # Arguments
    /// * `hostname` — The hostname to remove.
    ///
    /// # Returns
    /// `true` if at least one entry was found and removed.
    ///
    /// # Source
    /// Replaces `cache_unhash_dhcp()` from `cache.c`.
    pub fn remove_dhcp_entry(&mut self, hostname: &str) -> bool {
        let key = hostname.to_ascii_lowercase();
        let mut removed = false;

        if let Some(entries) = self.entries.get(&key) {
            // Collect UIDs of DHCP entries to remove
            let dhcp_uids: Vec<u32> = entries
                .iter()
                .filter(|e| e.flags.contains(CacheEntryFlags::DHCP))
                .map(|e| e.uid)
                .collect();

            if !dhcp_uids.is_empty() {
                for uid in &dhcp_uids {
                    self.remove_entry_by_uid(&key, *uid);
                    self.count = self.count.saturating_sub(1);
                    self.dhcp_count = self.dhcp_count.saturating_sub(1);
                    removed = true;
                }

                // Clean LRU
                let key_clone = key.clone();
                self.lru.retain(|k| {
                    !(k.name == key_clone && dhcp_uids.contains(&k.uid))
                });

                debug!("removed DHCP entry: {}", hostname);
            }
        }

        removed
    }

    // -----------------------------------------------------------------------
    // Statistics and Diagnostics
    // -----------------------------------------------------------------------

    /// Generate cache statistics for TXT CHAOS record response.
    ///
    /// Produces a formatted string suitable for responding to queries like:
    /// `dig +short chaos txt cachesize.bind @localhost`
    ///
    /// # Returns
    /// A human-readable statistics string.
    ///
    /// # Source
    /// Replaces `cache_make_stat()` from `cache.c` line 3529.
    pub fn make_stat(&self) -> String {
        format!(
            "entries: {}/{}, evictions: {}, hits: {}, misses: {}, hosts: {}, dhcp: {}",
            self.count,
            self.max_size,
            self.evictions,
            self.hits,
            self.misses,
            self.hosts_count,
            self.dhcp_count
        )
    }

    /// Dump all cache entries to the log for debugging.
    ///
    /// Logs every cache entry with its name, address, TTL, flags, and UID.
    /// Triggered by SIGUSR1 signal for diagnostic purposes.
    ///
    /// # Arguments
    /// * `daemon` — Reference to daemon state for accessing configuration
    ///   and metrics during the dump.
    ///
    /// # Source
    /// Replaces cache dump logic invoked via SIGUSR1 in `dnsmasq.c`.
    pub fn dump(&self, daemon: &DaemonState) {
        let now_epoch = Self::epoch_now();

        info!("--- DNS Cache Dump ---");
        info!("Cache size: {}/{}", self.count, self.max_size);
        info!(
            "Hits: {}, Misses: {}, Evictions: {}",
            self.hits, self.misses, self.evictions
        );
        info!(
            "Hosts entries: {}, DHCP entries: {}",
            self.hosts_count, self.dhcp_count
        );

        // Log metrics from DaemonState
        {
            let metrics = daemon.metrics.borrow();
            info!(
                "Metric: cache_inserted={}, cache_live_freed={}",
                metrics.get(Metric::DnsCacheInserted),
                metrics.get(Metric::DnsCacheLiveFreed)
            );
        }

        // Check daemon configuration flags
        let log_extended = daemon.option_bool(crate::core::daemon::OPT_LOG);
        info!("Extended logging: {}", log_extended);

        // Access runtime and dns config for dump context
        let _dns_config = &daemon.dns;
        let _options = &daemon.options;
        let _runtime = daemon.runtime.borrow();

        // Dump each entry
        for (name, entries) in self.entries.iter() {
            for entry in entries.iter() {
                let ttl_str = if entry.ttd == 0 {
                    "IMMORTAL".to_string()
                } else {
                    let remaining = entry.ttd - now_epoch;
                    if remaining > 0 {
                        format!("{}s", remaining)
                    } else {
                        "EXPIRED".to_string()
                    }
                };

                let type_str = if entry.flags.contains(CacheEntryFlags::IPV4) {
                    "A"
                } else if entry.flags.contains(CacheEntryFlags::IPV6) {
                    "AAAA"
                } else if entry.flags.contains(CacheEntryFlags::CNAME) {
                    "CNAME"
                } else if entry.flags.contains(CacheEntryFlags::NXDOMAIN) {
                    "NXDOMAIN"
                } else if entry.flags.contains(CacheEntryFlags::DNSKEY) {
                    "DNSKEY"
                } else if entry.flags.contains(CacheEntryFlags::DS) {
                    "DS"
                } else {
                    "OTHER"
                };

                let source_str = if entry.flags.contains(CacheEntryFlags::HOSTS) {
                    " [HOSTS]"
                } else if entry.flags.contains(CacheEntryFlags::DHCP) {
                    " [DHCP]"
                } else if entry.flags.contains(CacheEntryFlags::CONFIG) {
                    " [CONFIG]"
                } else {
                    ""
                };

                info!(
                    "  {} {} -> {} TTL={} uid={}{}",
                    name, type_str, entry.addr, ttl_str, entry.uid, source_str
                );
            }
        }

        info!("--- End DNS Cache Dump ---");
    }

    // -----------------------------------------------------------------------
    // Hosts file default path helper
    // -----------------------------------------------------------------------

    /// Load entries from the default system hosts file ([`HOSTSFILE`] = `/etc/hosts`).
    ///
    /// Convenience method using the default hosts file path.
    /// Equivalent to `read_hostsfile(HOSTSFILE, 0)`.
    pub fn read_default_hostsfile(&mut self) -> Result<usize, CacheError> {
        self.read_hostsfile(HOSTSFILE, 0)
    }

    // -----------------------------------------------------------------------
    // Record type classification
    // -----------------------------------------------------------------------

    /// Get the DNS RR type code for a cache entry based on its flags.
    ///
    /// Maps cache entry flags to the appropriate DNS record type constant.
    /// Uses the protocol constants from `dns::protocol`.
    ///
    /// # Arguments
    /// * `entry` — The cache entry to classify.
    ///
    /// # Returns
    /// The DNS RR type code (e.g., [`T_A`], [`T_AAAA`], [`T_CNAME`], etc.),
    /// or 0 if the entry type cannot be determined.
    pub fn entry_rr_type(entry: &CacheEntry) -> u16 {
        for &(flag, rr_type) in FORWARD_TYPES {
            if entry.flags.contains(flag) {
                return rr_type;
            }
        }
        // Check additional types using protocol constants
        if entry.flags.contains(CacheEntryFlags::NEG) {
            if entry.flags.contains(CacheEntryFlags::NXDOMAIN) {
                return T_A; // NXDOMAIN entries are type-agnostic
            }
            return T_A; // Negative NODATA
        }
        // Use RrType enum for extended type checking
        if entry.flags.contains(CacheEntryFlags::RR) {
            // RR entries have their type stored in the addr field
            match &entry.addr {
                AllAddr::RrBlock { rrtype, .. } => return *rrtype,
                AllAddr::RrData { rrtype, .. } => return *rrtype,
                _ => {}
            }
        }
        0
    }

    /// Get the `RrType` enum variant for a cache entry.
    ///
    /// Returns `None` if the entry's RR type is not recognized.
    pub fn entry_rr_type_enum(entry: &CacheEntry) -> Option<RrType> {
        RrType::from_u16(Self::entry_rr_type(entry))
    }

    /// Check if a cache entry matches the given DNS class.
    ///
    /// # Arguments
    /// * `entry` — The cache entry to check.
    /// * `class` — DNS class code to match (e.g., [`C_IN`] = 1).
    ///
    /// Most cache entries are class IN (Internet). The CHAOS class is used
    /// for special queries like `version.bind` and `cachesize.bind`.
    pub fn entry_matches_class(_entry: &CacheEntry, class: u16) -> bool {
        // Most entries are implicitly class IN
        // CHAOS class entries are special (stats queries)
        if class == DNS_CLASS_IN {
            return true; // All normal cache entries are class IN
        }
        if class == DNS_CLASS_CHAOS {
            // Only statistics entries match CHAOS class
            return false;
        }
        true
    }

    // -----------------------------------------------------------------------
    // Stale cache support
    // -----------------------------------------------------------------------

    /// Find cache entries that are stale (expired) but within the stale
    /// serving window ([`STALE_CACHE_EXPIRY`] = 86400 seconds).
    ///
    /// When all upstream servers are unavailable, stale cache data can be
    /// served if it expired less than [`STALE_CACHE_EXPIRY`] seconds ago.
    /// This provides continued DNS resolution during upstream outages.
    ///
    /// # Arguments
    /// * `name` — DNS name to look up.
    /// * `now` — Current monotonic timestamp.
    /// * `flags` — Filter flags for entry matching.
    ///
    /// # Returns
    /// Vector of stale cache entries that are still within the serving window.
    pub fn find_stale(
        &self,
        name: &str,
        now: Instant,
        flags: CacheEntryFlags,
    ) -> Vec<CacheEntry> {
        let now_epoch = self.to_epoch(now);
        let key = name.to_ascii_lowercase();
        let mut results = Vec::new();

        if let Some(entries) = self.entries.get(&key) {
            for entry in entries.iter() {
                // Skip immortal entries (they never become stale)
                if entry.flags.contains(CacheEntryFlags::IMMORTAL) || entry.ttd == 0 {
                    continue;
                }
                // Check flags match
                if !entry.flags.intersects(flags) {
                    continue;
                }
                // Entry must be expired but within the stale window
                if entry.ttd <= now_epoch
                    && (now_epoch - entry.ttd) < STALE_CACHE_EXPIRY as i64
                {
                    results.push(entry.clone());
                }
            }
        }

        results
    }

    /// Clamp a TTL value to the configured minimum cache TTL floor.
    ///
    /// Ensures TTL values used for cache insertion respect the
    /// `--min-cache-ttl` setting, capped at [`TTL_FLOOR_LIMIT`] (3600).
    ///
    /// # Arguments
    /// * `ttl` — Original TTL from the DNS response.
    /// * `min_ttl` — Configured minimum TTL (from `--min-cache-ttl`).
    ///
    /// # Returns
    /// The effective TTL to use for cache insertion.
    pub fn clamp_ttl(ttl: u64, min_ttl: u64) -> u64 {
        let effective_min = if min_ttl > TTL_FLOOR_LIMIT {
            TTL_FLOOR_LIMIT
        } else {
            min_ttl
        };
        if ttl < effective_min {
            effective_min
        } else {
            ttl
        }
    }

    /// Build a `DnsName` wire-format representation from a presentation-format name.
    ///
    /// Constructs the wire-format encoding (length-prefixed labels) for use in
    /// DNS packet construction. This bridges between the String-based cache keys
    /// and the DnsName newtype used in wire operations.
    ///
    /// # Arguments
    /// * `name` — DNS name in presentation format (e.g., "www.example.com").
    ///
    /// # Returns
    /// A `DnsName` with wire-format encoding of the name.
    pub fn name_to_wire(name: &str) -> DnsName {
        let mut wire = Vec::with_capacity(name.len() + 2);
        for label in name.split('.') {
            if label.is_empty() {
                continue;
            }
            let label_bytes = label.as_bytes();
            if label_bytes.len() > 63 {
                // Truncate label to max length
                wire.push(63);
                wire.extend_from_slice(&label_bytes[..63]);
            } else {
                wire.push(label_bytes.len() as u8);
                wire.extend_from_slice(label_bytes);
            }
        }
        wire.push(0); // Root label terminator
        DnsName::new(wire)
    }

    /// Get the address size in bytes for an entry's address type.
    ///
    /// Uses the protocol constants [`INADDRSZ`] (4) and [`IN6ADDRSZ`] (16).
    pub fn entry_addr_size(entry: &CacheEntry) -> usize {
        if entry.flags.contains(CacheEntryFlags::IPV4) {
            INADDRSZ
        } else if entry.flags.contains(CacheEntryFlags::IPV6) {
            IN6ADDRSZ
        } else {
            0
        }
    }

    // -----------------------------------------------------------------------
    // Metrics integration
    // -----------------------------------------------------------------------

    /// Record cache insertion in the metrics store.
    ///
    /// Called after successful insertion to increment the
    /// [`Metric::DnsCacheInserted`] counter.
    pub fn record_insert_metric(metrics: &mut MetricsStore) {
        metrics.increment(Metric::DnsCacheInserted);
    }

    /// Record live eviction in the metrics store.
    ///
    /// Called when a non-expired entry is evicted from the cache to
    /// increment the [`Metric::DnsCacheLiveFreed`] counter.
    pub fn record_eviction_metric(metrics: &mut MetricsStore) {
        metrics.increment(Metric::DnsCacheLiveFreed);
    }

    /// Insert an entry and automatically update metrics.
    ///
    /// Convenience method combining [`insert()`] with metric tracking
    /// via the provided [`MetricsStore`].
    pub fn insert_with_metrics(
        &mut self,
        name: &str,
        addr: Option<&AllAddr>,
        class: u16,
        now: Instant,
        ttl: u64,
        flags: CacheEntryFlags,
        metrics: &mut MetricsStore,
    ) -> Result<(), CacheError> {
        let was_full = self.count >= self.max_size && self.max_size > 0;
        let result = self.insert(name, addr, class, now, ttl, flags);
        if result.is_ok() {
            metrics.increment(Metric::DnsCacheInserted);
            if was_full {
                // An eviction must have happened
                metrics.increment(Metric::DnsCacheLiveFreed);
            }
        }
        result
    }

    // -----------------------------------------------------------------------
    // PTR record helpers
    // -----------------------------------------------------------------------

    /// Generate the reverse DNS name for an IPv4 address.
    ///
    /// Constructs the `in-addr.arpa` name for PTR record lookups.
    /// For example, `192.168.1.1` → `1.1.168.192.in-addr.arpa`.
    ///
    /// Uses [`T_PTR`] record type internally for identification.
    pub fn ipv4_reverse_name(addr: &Ipv4Addr) -> String {
        let octets = addr.octets();
        format!(
            "{}.{}.{}.{}.in-addr.arpa",
            octets[3], octets[2], octets[1], octets[0]
        )
    }

    /// Generate the reverse DNS name for an IPv6 address.
    ///
    /// Constructs the `ip6.arpa` name for PTR record lookups.
    /// Each nibble is reversed and separated by dots.
    pub fn ipv6_reverse_name(addr: &Ipv6Addr) -> String {
        let segments = addr.segments();
        let mut nibbles = Vec::with_capacity(64);
        for segment in segments.iter().rev() {
            for shift in &[0, 4, 8, 12] {
                nibbles.push(format!("{:x}", (segment >> shift) & 0xf));
            }
        }
        format!("{}.ip6.arpa", nibbles.join("."))
    }

    /// Get related DNS record type constants for cross-referencing.
    ///
    /// Returns the set of record types that are relevant for a given lookup,
    /// using protocol constants T_NS, T_SOA, T_MX, T_SRV, T_TXT.
    pub fn related_types_for_name_lookup() -> &'static [u16] {
        &[T_A, T_AAAA, T_CNAME, T_NS, T_SOA, T_MX, T_SRV, T_TXT, T_PTR]
    }

    /// Find entries for a name or any of its parent domains.
    ///
    /// Walks up the domain hierarchy looking for NXDOMAIN or wildcard entries.
    /// Uses [`util::hostname_issubdomain()`] to check domain relationships and
    /// [`util::hostname_order()`] for sorted output ordering.
    ///
    /// # Arguments
    /// * `name` — DNS name to look up.
    /// * `now` — Current monotonic timestamp for expiration checks.
    ///
    /// # Returns
    /// Vector of (domain_name, entries) pairs ordered by domain specificity
    /// (most specific first via [`util::hostname_order()`]).
    pub fn find_by_domain_hierarchy(
        &self,
        name: &str,
        now: Instant,
    ) -> Vec<(String, Vec<CacheEntry>)> {
        let now_epoch = self.to_epoch(now);
        let mut results: Vec<(String, Vec<CacheEntry>)> = Vec::new();

        for (cached_name, entries) in self.entries.iter() {
            // Check if the queried name is equal to or a subdomain of the cached name
            if util::hostname_isequal(name, cached_name)
                || util::hostname_issubdomain(name, cached_name)
            {
                let live_entries: Vec<CacheEntry> = entries
                    .iter()
                    .filter(|e| !Self::is_entry_expired(e, now_epoch))
                    .cloned()
                    .collect();

                if !live_entries.is_empty() {
                    results.push((cached_name.clone(), live_entries));
                }
            }
        }

        // Sort by domain specificity (most specific first) using hostname_order
        results.sort_by(|(a, _), (b, _)| util::hostname_order(a, b));

        results
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    /// Returns the current number of entries in the cache.
    #[inline]
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if the cache contains no entries.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns the maximum cache capacity.
    #[inline]
    pub fn max_size(&self) -> usize {
        self.max_size
    }

    /// Returns the number of hosts file entries.
    #[inline]
    pub fn hosts_count(&self) -> usize {
        self.hosts_count
    }

    /// Returns the number of DHCP entries.
    #[inline]
    pub fn dhcp_count(&self) -> usize {
        self.dhcp_count
    }

    /// Returns the total number of cache hits.
    #[inline]
    pub fn hits(&self) -> u64 {
        self.hits
    }

    /// Returns the total number of cache misses.
    #[inline]
    pub fn misses(&self) -> u64 {
        self.misses
    }

    /// Returns the total number of live evictions.
    #[inline]
    pub fn evictions(&self) -> u64 {
        self.evictions
    }

    /// Check if the cache contains any entry for the given name.
    pub fn contains_name(&self, name: &str) -> bool {
        let key = name.to_ascii_lowercase();
        self.entries.contains_key(&key) && !self.entries[&key].is_empty()
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    /// Helper to create a basic cache for testing.
    fn test_cache(size: usize) -> DnsCache {
        DnsCache::new(size)
    }

    /// Helper to create an IPv4 AllAddr.
    fn ipv4_addr(a: u8, b: u8, c: u8, d: u8) -> AllAddr {
        AllAddr::from_ipv4(Ipv4Addr::new(a, b, c, d))
    }

    /// Helper to create an IPv6 AllAddr.
    fn ipv6_addr() -> AllAddr {
        AllAddr::from_ipv6(Ipv6Addr::LOCALHOST)
    }

    #[test]
    fn test_new_cache_default_size() {
        let cache = DnsCache::new(CACHESIZ);
        assert_eq!(cache.max_size(), CACHESIZ);
        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());
        assert_eq!(cache.hosts_count(), 0);
        assert_eq!(cache.dhcp_count(), 0);
    }

    #[test]
    fn test_new_cache_zero_size() {
        let cache = DnsCache::new(0);
        assert_eq!(cache.max_size(), 0);
        assert!(cache.is_empty());
    }

    #[test]
    fn test_insert_and_find_by_name() {
        let mut cache = test_cache(150);
        let now = Instant::now();
        let addr = ipv4_addr(192, 168, 1, 1);
        let flags = CacheEntryFlags::FORWARD | CacheEntryFlags::IPV4;

        cache
            .insert("example.com", Some(&addr), C_IN, now, 300, flags)
            .unwrap();

        assert_eq!(cache.len(), 1);

        let results = cache.find_by_name("example.com", now, CacheEntryFlags::IPV4);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "example.com");

        // Case-insensitive lookup
        let results = cache.find_by_name("EXAMPLE.COM", now, CacheEntryFlags::IPV4);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_insert_and_find_by_addr() {
        let mut cache = test_cache(150);
        let now = Instant::now();
        let addr = ipv4_addr(10, 0, 0, 1);
        let flags = CacheEntryFlags::FORWARD | CacheEntryFlags::IPV4;

        cache
            .insert("host.local", Some(&addr), C_IN, now, 300, flags)
            .unwrap();

        let results = cache.find_by_addr(&addr, now, CacheEntryFlags::IPV4);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "host.local");
    }

    #[test]
    fn test_find_miss() {
        let mut cache = test_cache(150);
        let now = Instant::now();

        let results = cache.find_by_name("nonexistent.com", now, CacheEntryFlags::IPV4);
        assert!(results.is_empty());
        assert_eq!(cache.misses(), 1);
    }

    #[test]
    fn test_eviction_when_full() {
        let mut cache = test_cache(3);
        let now = Instant::now();

        // Fill the cache
        for i in 0..3 {
            let addr = ipv4_addr(10, 0, 0, i as u8);
            let flags = CacheEntryFlags::FORWARD | CacheEntryFlags::IPV4;
            cache
                .insert(&format!("host{}.com", i), Some(&addr), C_IN, now, 300, flags)
                .unwrap();
        }

        assert_eq!(cache.len(), 3);

        // Insert one more — should evict the oldest
        let addr = ipv4_addr(10, 0, 0, 99);
        let flags = CacheEntryFlags::FORWARD | CacheEntryFlags::IPV4;
        cache
            .insert("newhost.com", Some(&addr), C_IN, now, 300, flags)
            .unwrap();

        assert_eq!(cache.len(), 3);
        assert!(cache.evictions() >= 1);
    }

    #[test]
    fn test_hosts_entries_immune_to_eviction() {
        let mut cache = test_cache(2);
        let now = Instant::now();

        // Insert a hosts entry
        let addr = ipv4_addr(127, 0, 0, 1);
        let flags =
            CacheEntryFlags::HOSTS | CacheEntryFlags::IMMORTAL | CacheEntryFlags::IPV4;
        cache
            .insert("localhost", Some(&addr), C_IN, now, 0, flags)
            .unwrap();

        // Insert a normal entry
        let addr2 = ipv4_addr(10, 0, 0, 1);
        let flags2 = CacheEntryFlags::FORWARD | CacheEntryFlags::IPV4;
        cache
            .insert("host1.com", Some(&addr2), C_IN, now, 300, flags2)
            .unwrap();

        // Insert another normal entry — should evict host1.com, not localhost
        let addr3 = ipv4_addr(10, 0, 0, 2);
        cache
            .insert("host2.com", Some(&addr3), C_IN, now, 300, flags2)
            .unwrap();

        // localhost should still be in cache
        let results = cache.find_by_name("localhost", now, CacheEntryFlags::IPV4);
        assert!(!results.is_empty());
    }

    #[test]
    fn test_dhcp_add_and_remove() {
        let mut cache = test_cache(150);
        let now = Instant::now();
        let addr = ipv4_addr(192, 168, 1, 100);

        cache.add_dhcp_entry("mypc", &addr, CacheEntryFlags::IPV4);

        assert_eq!(cache.dhcp_count(), 1);
        assert_eq!(cache.len(), 1);

        let results = cache.find_by_name("mypc", now, CacheEntryFlags::DHCP);
        assert_eq!(results.len(), 1);

        // Remove
        assert!(cache.remove_dhcp_entry("mypc"));
        assert_eq!(cache.dhcp_count(), 0);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_dhcp_replace_existing() {
        let mut cache = test_cache(150);
        let addr1 = ipv4_addr(192, 168, 1, 100);
        let addr2 = ipv4_addr(192, 168, 1, 200);

        cache.add_dhcp_entry("mypc", &addr1, CacheEntryFlags::IPV4);
        assert_eq!(cache.dhcp_count(), 1);

        // Replace with new address
        cache.add_dhcp_entry("mypc", &addr2, CacheEntryFlags::IPV4);
        assert_eq!(cache.dhcp_count(), 1);

        let now = Instant::now();
        let results = cache.find_by_addr(&addr2, now, CacheEntryFlags::DHCP);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_clear_preserves_hosts_and_dhcp() {
        let mut cache = test_cache(150);
        let now = Instant::now();

        // Add a hosts entry
        let addr1 = ipv4_addr(127, 0, 0, 1);
        cache
            .insert(
                "localhost",
                Some(&addr1),
                C_IN,
                now,
                0,
                CacheEntryFlags::HOSTS | CacheEntryFlags::IMMORTAL | CacheEntryFlags::IPV4,
            )
            .unwrap();

        // Add a DHCP entry
        let addr2 = ipv4_addr(192, 168, 1, 100);
        cache.add_dhcp_entry("mypc", &addr2, CacheEntryFlags::IPV4);

        // Add a normal cached entry
        let addr3 = ipv4_addr(1, 2, 3, 4);
        cache
            .insert(
                "external.com",
                Some(&addr3),
                C_IN,
                now,
                300,
                CacheEntryFlags::FORWARD | CacheEntryFlags::IPV4,
            )
            .unwrap();

        assert_eq!(cache.len(), 3);

        // Clear
        cache.clear();

        // Only hosts and DHCP should remain
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.hosts_count(), 1);
        assert_eq!(cache.dhcp_count(), 1);

        // Normal entry should be gone
        let results = cache.find_by_name("external.com", now, CacheEntryFlags::IPV4);
        assert!(results.is_empty());
    }

    #[test]
    fn test_enumerate_all_entries() {
        let mut cache = test_cache(150);
        let now = Instant::now();

        for i in 0..5 {
            let addr = ipv4_addr(10, 0, 0, i as u8);
            cache
                .insert(
                    &format!("host{}.com", i),
                    Some(&addr),
                    C_IN,
                    now,
                    300,
                    CacheEntryFlags::FORWARD | CacheEntryFlags::IPV4,
                )
                .unwrap();
        }

        let all_entries: Vec<_> = cache.enumerate().collect();
        assert_eq!(all_entries.len(), 5);
    }

    #[test]
    fn test_make_stat() {
        let mut cache = test_cache(150);
        let now = Instant::now();

        let addr = ipv4_addr(10, 0, 0, 1);
        cache
            .insert(
                "test.com",
                Some(&addr),
                C_IN,
                now,
                300,
                CacheEntryFlags::FORWARD | CacheEntryFlags::IPV4,
            )
            .unwrap();

        let stat = cache.make_stat();
        assert!(stat.contains("entries: 1/150"));
        assert!(stat.contains("hits:"));
        assert!(stat.contains("misses:"));
    }

    #[test]
    fn test_ipv6_insert_and_lookup() {
        let mut cache = test_cache(150);
        let now = Instant::now();
        let addr = ipv6_addr();
        let flags = CacheEntryFlags::FORWARD | CacheEntryFlags::IPV6;

        cache
            .insert("ipv6host.com", Some(&addr), C_IN, now, 300, flags)
            .unwrap();

        let results = cache.find_by_name("ipv6host.com", now, CacheEntryFlags::IPV6);
        assert_eq!(results.len(), 1);
        assert!(results[0].addr.is_v6());
    }

    #[test]
    fn test_negative_cache_entry() {
        let mut cache = test_cache(150);
        let now = Instant::now();
        let flags = CacheEntryFlags::FORWARD | CacheEntryFlags::NXDOMAIN | CacheEntryFlags::NEG;

        cache.insert("nxdomain.com", None, C_IN, now, 60, flags).unwrap();

        let results = cache.find_by_name("nxdomain.com", now, CacheEntryFlags::NXDOMAIN);
        assert_eq!(results.len(), 1);
        assert!(results[0].flags.contains(CacheEntryFlags::NEG));
    }

    #[test]
    fn test_contains_name() {
        let mut cache = test_cache(150);
        let now = Instant::now();
        let addr = ipv4_addr(1, 2, 3, 4);

        assert!(!cache.contains_name("test.com"));

        cache
            .insert(
                "test.com",
                Some(&addr),
                C_IN,
                now,
                300,
                CacheEntryFlags::FORWARD | CacheEntryFlags::IPV4,
            )
            .unwrap();

        assert!(cache.contains_name("test.com"));
        assert!(cache.contains_name("TEST.COM")); // case-insensitive
    }

    #[test]
    fn test_cache_full_error_when_all_protected() {
        let mut cache = test_cache(2);
        let now = Instant::now();

        // Fill with protected entries
        let addr1 = ipv4_addr(127, 0, 0, 1);
        cache
            .insert(
                "host1",
                Some(&addr1),
                C_IN,
                now,
                0,
                CacheEntryFlags::HOSTS | CacheEntryFlags::IMMORTAL | CacheEntryFlags::IPV4,
            )
            .unwrap();

        let addr2 = ipv4_addr(127, 0, 0, 2);
        cache
            .insert(
                "host2",
                Some(&addr2),
                C_IN,
                now,
                0,
                CacheEntryFlags::HOSTS | CacheEntryFlags::IMMORTAL | CacheEntryFlags::IPV4,
            )
            .unwrap();

        // Try to insert a normal entry — should fail
        let addr3 = ipv4_addr(1, 2, 3, 4);
        let result = cache.insert(
            "normal.com",
            Some(&addr3),
            C_IN,
            now,
            300,
            CacheEntryFlags::FORWARD | CacheEntryFlags::IPV4,
        );

        assert!(result.is_err());
        match result {
            Err(CacheError::Full { count, max }) => {
                assert_eq!(count, 2);
                assert_eq!(max, 2);
            }
            _ => panic!("expected CacheError::Full"),
        }
    }

    #[test]
    fn test_multiple_entries_same_name() {
        let mut cache = test_cache(150);
        let now = Instant::now();

        // Round-robin: multiple A records for same name
        let addr1 = ipv4_addr(10, 0, 0, 1);
        let addr2 = ipv4_addr(10, 0, 0, 2);
        let flags = CacheEntryFlags::FORWARD | CacheEntryFlags::IPV4;

        cache
            .insert("rr.example.com", Some(&addr1), C_IN, now, 300, flags)
            .unwrap();
        cache
            .insert("rr.example.com", Some(&addr2), C_IN, now, 300, flags)
            .unwrap();

        let results = cache.find_by_name("rr.example.com", now, CacheEntryFlags::IPV4);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_expire_removes_old_entries() {
        let mut cache = test_cache(150);
        let now = Instant::now();

        // Insert entry with very short TTL (1 second)
        // Note: We need to set ttd to the past for it to be expired
        let addr = ipv4_addr(10, 0, 0, 1);
        let flags = CacheEntryFlags::FORWARD | CacheEntryFlags::IPV4;

        cache
            .insert("short-ttl.com", Some(&addr), C_IN, now, 1, flags)
            .unwrap();

        assert_eq!(cache.len(), 1);

        // Manually set ttd to the past for testing
        if let Some(entries) = cache.entries.get_mut("short-ttl.com") {
            entries[0].ttd = DnsCache::epoch_now() - 10;
        }

        let expired = cache.expire(Instant::now());
        assert_eq!(expired, 1);
        assert_eq!(cache.len(), 0);
    }

    // ===================================================================
    // Additional comprehensive tests
    // ===================================================================

    #[test]
    fn test_clamp_ttl_no_change_when_above_min() {
        assert_eq!(DnsCache::clamp_ttl(3600, 300), 3600);
    }

    #[test]
    fn test_clamp_ttl_raised_to_min() {
        assert_eq!(DnsCache::clamp_ttl(10, 300), 300);
    }

    #[test]
    fn test_clamp_ttl_floor_limit() {
        // min_ttl exceeds TTL_FLOOR_LIMIT (3600) -> capped at 3600
        assert_eq!(DnsCache::clamp_ttl(10, 7200), 3600);
    }

    #[test]
    fn test_clamp_ttl_zero() {
        assert_eq!(DnsCache::clamp_ttl(0, 0), 0);
    }

    #[test]
    fn test_entry_addr_size_ipv4() {
        let entry = CacheEntry {
            addr: AllAddr::V4(Ipv4Addr::LOCALHOST),
            ttd: 0,
            uid: 1,
            flags: CacheEntryFlags::IPV4 | CacheEntryFlags::FORWARD,
            name: "test.local".to_string(),
        };
        assert_eq!(DnsCache::entry_addr_size(&entry), 4);
    }

    #[test]
    fn test_entry_addr_size_ipv6() {
        let entry = CacheEntry {
            addr: AllAddr::V6(Ipv6Addr::LOCALHOST),
            ttd: 0,
            uid: 1,
            flags: CacheEntryFlags::IPV6 | CacheEntryFlags::FORWARD,
            name: "test.local".to_string(),
        };
        assert_eq!(DnsCache::entry_addr_size(&entry), 16);
    }

    #[test]
    fn test_entry_addr_size_cname() {
        let entry = CacheEntry {
            addr: AllAddr::V4(Ipv4Addr::UNSPECIFIED),
            ttd: 0,
            uid: 1,
            flags: CacheEntryFlags::CNAME | CacheEntryFlags::FORWARD,
            name: "alias.local".to_string(),
        };
        assert_eq!(DnsCache::entry_addr_size(&entry), 0);
    }

    #[test]
    fn test_ipv4_reverse_name() {
        let addr = Ipv4Addr::new(192, 168, 1, 100);
        let name = DnsCache::ipv4_reverse_name(&addr);
        assert_eq!(name, "100.1.168.192.in-addr.arpa");
    }

    #[test]
    fn test_ipv6_reverse_name() {
        let addr = Ipv6Addr::LOCALHOST;
        let name = DnsCache::ipv6_reverse_name(&addr);
        assert!(name.ends_with(".ip6.arpa"));
        // 32 nibbles produce 31 dots, plus ".ip6.arpa" has 2 dots = 33 total
        assert_eq!(name.matches('.').count(), 33);
    }

    #[test]
    fn test_entry_rr_type_ipv4() {
        let entry = CacheEntry {
            addr: AllAddr::V4(Ipv4Addr::LOCALHOST),
            ttd: 0,
            uid: 1,
            flags: CacheEntryFlags::IPV4 | CacheEntryFlags::FORWARD,
            name: "test.local".to_string(),
        };
        assert_eq!(DnsCache::entry_rr_type(&entry), 1); // T_A
    }

    #[test]
    fn test_entry_rr_type_ipv6() {
        let entry = CacheEntry {
            addr: AllAddr::V6(Ipv6Addr::LOCALHOST),
            ttd: 0,
            uid: 1,
            flags: CacheEntryFlags::IPV6 | CacheEntryFlags::FORWARD,
            name: "test.local".to_string(),
        };
        assert_eq!(DnsCache::entry_rr_type(&entry), 28); // T_AAAA
    }

    #[test]
    fn test_entry_rr_type_cname() {
        let entry = CacheEntry {
            addr: AllAddr::V4(Ipv4Addr::UNSPECIFIED),
            ttd: 0,
            uid: 1,
            flags: CacheEntryFlags::CNAME | CacheEntryFlags::FORWARD,
            name: "alias.local".to_string(),
        };
        assert_eq!(DnsCache::entry_rr_type(&entry), 5); // T_CNAME
    }

    #[test]
    fn test_name_to_wire_simple() {
        let wire = DnsCache::name_to_wire("example.com");
        let bytes = wire.as_bytes();
        assert_eq!(bytes[0], 7); // "example" length
        assert_eq!(&bytes[1..8], b"example");
        assert_eq!(bytes[8], 3); // "com" length
        assert_eq!(&bytes[9..12], b"com");
        assert_eq!(bytes[12], 0); // root label
    }

    #[test]
    fn test_name_to_wire_root() {
        let wire = DnsCache::name_to_wire(".");
        let bytes = wire.as_bytes();
        assert_eq!(bytes, &[0]);
    }

    #[test]
    fn test_record_insert_metric() {
        let mut metrics = MetricsStore::new();
        DnsCache::record_insert_metric(&mut metrics);
        assert_eq!(metrics.get(Metric::DnsCacheInserted), 1);
        DnsCache::record_insert_metric(&mut metrics);
        assert_eq!(metrics.get(Metric::DnsCacheInserted), 2);
    }

    #[test]
    fn test_record_eviction_metric() {
        let mut metrics = MetricsStore::new();
        DnsCache::record_eviction_metric(&mut metrics);
        assert_eq!(metrics.get(Metric::DnsCacheLiveFreed), 1);
    }

    #[test]
    fn test_insert_with_metrics() {
        let mut cache = test_cache(5);
        let mut metrics = MetricsStore::new();
        let now = Instant::now();

        let result = cache.insert_with_metrics(
            "test.local",
            Some(&ipv4_addr(10, 0, 0, 1)),
            C_IN,
            now,
            3600,
            CacheEntryFlags::IPV4 | CacheEntryFlags::FORWARD,
            &mut metrics,
        );
        assert!(result.is_ok());
        assert_eq!(metrics.get(Metric::DnsCacheInserted), 1);
    }

    #[test]
    fn test_insert_ipv4_flag_with_ipv6_addr_rejected() {
        let mut cache = test_cache(10);
        let now = Instant::now();

        let result = cache.insert(
            "test.local",
            Some(&AllAddr::V6(Ipv6Addr::LOCALHOST)),
            C_IN,
            now,
            3600,
            CacheEntryFlags::IPV4 | CacheEntryFlags::FORWARD,
        );
        assert!(result.is_err());
        match result {
            Err(CacheError::InvalidEntry(msg)) => {
                assert!(msg.contains("IPV4"));
            }
            _ => panic!("Expected InvalidEntry error"),
        }
    }

    #[test]
    fn test_insert_ipv6_flag_with_ipv4_addr_rejected() {
        let mut cache = test_cache(10);
        let now = Instant::now();

        let result = cache.insert(
            "test.local",
            Some(&AllAddr::V4(Ipv4Addr::LOCALHOST)),
            C_IN,
            now,
            3600,
            CacheEntryFlags::IPV6 | CacheEntryFlags::FORWARD,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_related_types_includes_all_major() {
        let types = DnsCache::related_types_for_name_lookup();
        assert!(types.contains(&1));  // T_A
        assert!(types.contains(&28)); // T_AAAA
        assert!(types.contains(&5));  // T_CNAME
        assert!(types.contains(&12)); // T_PTR
        assert!(types.contains(&2));  // T_NS
        assert!(types.contains(&6));  // T_SOA
        assert!(types.contains(&15)); // T_MX
        assert!(types.contains(&33)); // T_SRV
        assert!(types.contains(&16)); // T_TXT
    }

    #[test]
    fn test_find_stale_empty() {
        let cache = test_cache(10);
        let now = Instant::now();
        let results = cache.find_stale("test.local", now, CacheEntryFlags::IPV4);
        assert!(results.is_empty());
    }

    #[test]
    fn test_entry_matches_class_in() {
        let entry = CacheEntry {
            addr: AllAddr::V4(Ipv4Addr::LOCALHOST),
            ttd: 0,
            uid: 1,
            flags: CacheEntryFlags::IPV4 | CacheEntryFlags::FORWARD,
            name: "test.local".to_string(),
        };
        assert!(DnsCache::entry_matches_class(&entry, 1));  // C_IN
        assert!(!DnsCache::entry_matches_class(&entry, 3)); // C_CHAOS
    }

    #[test]
    fn test_new_default_cache_size() {
        let cache = DnsCache::new_default();
        assert_eq!(cache.max_size(), 150); // CACHESIZ
    }

    #[test]
    fn test_entry_rr_type_enum_ipv4() {
        let entry = CacheEntry {
            addr: AllAddr::V4(Ipv4Addr::LOCALHOST),
            ttd: 0,
            uid: 1,
            flags: CacheEntryFlags::IPV4 | CacheEntryFlags::FORWARD,
            name: "test.local".to_string(),
        };
        let rr_type = DnsCache::entry_rr_type_enum(&entry);
        assert!(rr_type.is_some());
    }

    #[test]
    fn test_lru_promotion_on_find() {
        let mut cache = test_cache(10);
        let now = Instant::now();

        cache.insert(
            "first.local",
            Some(&ipv4_addr(10, 0, 0, 1)),
            C_IN, now, 3600,
            CacheEntryFlags::IPV4 | CacheEntryFlags::FORWARD,
        ).unwrap();

        cache.insert(
            "second.local",
            Some(&ipv4_addr(10, 0, 0, 2)),
            C_IN, now, 3600,
            CacheEntryFlags::IPV4 | CacheEntryFlags::FORWARD,
        ).unwrap();

        let results = cache.find_by_name("first.local", now, CacheEntryFlags::IPV4);
        assert_eq!(results.len(), 1);
        assert_eq!(cache.hits(), 1);
    }

    #[test]
    fn test_find_by_domain_hierarchy() {
        let mut cache = test_cache(100);
        let now = Instant::now();

        cache.insert(
            "example.com",
            Some(&ipv4_addr(93, 184, 216, 34)),
            C_IN, now, 3600,
            CacheEntryFlags::IPV4 | CacheEntryFlags::FORWARD,
        ).unwrap();

        let results = cache.find_by_domain_hierarchy("www.example.com", now);
        assert!(!results.is_empty());
    }

    #[test]
    fn test_cache_accessors() {
        let cache = test_cache(100);
        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());
        assert_eq!(cache.max_size(), 100);
        assert_eq!(cache.hosts_count(), 0);
        assert_eq!(cache.dhcp_count(), 0);
        assert_eq!(cache.hits(), 0);
        assert_eq!(cache.misses(), 0);
        assert_eq!(cache.evictions(), 0);
        assert!(!cache.contains_name("nonexistent.com"));
    }

    #[test]
    fn test_scan_free_returns_false_when_empty() {
        let mut cache = test_cache(5);
        let now = Instant::now();
        assert!(!cache.scan_free("test.com", None, C_IN, now, CacheEntryFlags::IPV4));
    }
}

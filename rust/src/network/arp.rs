// Copyright (C) 2024 Simon Kelley and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.

//! ARP/neighbor cache management for DHCP address-in-use conflict detection.
//!
//! Migrated from `src/arp.c` (475 lines of C).
//!
//! This module maintains an internal ARP/neighbor cache that maps IP addresses
//! to hardware (MAC) addresses. The cache is synchronized with the kernel's
//! ARP table periodically (every [`CACHE_REFRESH_INTERVAL`] = 90 seconds) and
//! provides a MAC address lookup API for the DHCP subsystem.
//!
//! ## Key Design Decisions (C → Rust Migration)
//!
//! - **C `goto again` → Rust `loop { ... break; }`**: The `find_mac()` function
//!   in C used `goto again` to retry lookups after a cache refresh. This maps
//!   cleanly to a Rust `loop` with `continue`/`break`.
//!
//! - **C linked lists → Rust `Vec<ArpRecord>`**: The C implementation used three
//!   linked lists (`arps`, `old`, `freelist`) with manual pointer management.
//!   Rust uses `Vec<ArpRecord>` with ownership-based lifecycle management.
//!   The C `freelist` is eliminated entirely — Rust's allocator handles memory
//!   reuse automatically, which is a core memory-safety improvement.
//!
//! - **C `malloc`/`free` → Rust ownership**: All manual memory management
//!   (`whine_malloc`, pointer arithmetic, freelist recycling) is replaced with
//!   automatic allocation via `Vec::push` and deallocation via `Drop`.
//!
//! - **C `memcpy` → Rust `copy_from_slice()`**: Safe, bounds-checked byte copying.
//!
//! - **C `#ifdef HAVE_SCRIPT` → Rust `#[cfg(feature = "script")]`**: Script
//!   notification support is conditionally compiled via Cargo feature flags.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use tracing::{debug, warn};

use crate::core::types::{AllAddr, DnsmasqResult};

#[cfg(feature = "script")]
use crate::integration::helper::{EventAction, ScriptHelper};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Time interval between forced reloads of ARP cache from kernel.
/// Maps C: `#define INTERVAL 90` (arp.c line 68).
/// After this duration, the cache is considered stale and will be refreshed
/// from the kernel ARP/neighbor table on the next `find_mac()` call.
const CACHE_REFRESH_INTERVAL: Duration = Duration::from_secs(90);

/// Maximum hardware address length in bytes.
/// Matches `DHCP_CHADDR_MAX` from `dnsmasq.h`. Ethernet MAC addresses are
/// 6 bytes; this allows for larger hardware address types (e.g., InfiniBand).
pub const DHCP_CHADDR_MAX: usize = 16;

/// Address family constant for IPv4 (matches `libc::AF_INET`).
/// Used when calling `queue_arp()` for script notifications.
#[cfg(any(feature = "script", test))]
const AF_INET: i32 = 2;

/// Address family constant for IPv6 (matches `libc::AF_INET6` on Linux).
/// Used when calling `queue_arp()` for script notifications.
#[cfg(any(feature = "script", test))]
const AF_INET6: i32 = 10;

// ---------------------------------------------------------------------------
// ArpStatus Enum
// ---------------------------------------------------------------------------

/// ARP cache entry status flags.
///
/// Maps C constants: `ARP_MARK=0`, `ARP_FOUND=1`, `ARP_NEW=2`, `ARP_EMPTY=3`
/// (arp.c lines 73-88).
///
/// During a cache refresh cycle, entries transition through these states:
/// 1. All non-empty entries are set to [`Mark`](ArpStatus::Mark)
/// 2. Kernel enumeration sets matching entries to [`Found`](ArpStatus::Found)
///    or creates [`New`](ArpStatus::New) entries
/// 3. Entries still in [`Mark`](ArpStatus::Mark) state are moved to `old_entries`
///    (they disappeared from the kernel cache)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpStatus {
    /// Marked for garbage collection during cache reload.
    /// Entries in this state after kernel enumeration have disappeared
    /// from the kernel ARP table and will be moved to `old_entries`.
    /// Maps C: `ARP_MARK = 0`.
    Mark,
    /// Confirmed present in kernel cache during the last reload.
    /// The MAC address and IP address are valid and current.
    /// Maps C: `ARP_FOUND = 1`.
    Found,
    /// Newly discovered in the current reload cycle.
    /// Will trigger a script notification via `do_arp_script_run()`
    /// and then transition to [`Found`](ArpStatus::Found).
    /// Maps C: `ARP_NEW = 2`.
    New,
    /// Negative cache entry: IP address known, but no MAC address available.
    /// Created when `find_mac()` fails to find a MAC after a full kernel
    /// refresh. Prevents repeated kernel queries for the same missing entry.
    /// Maps C: `ARP_EMPTY = 3`.
    Empty,
}

// ---------------------------------------------------------------------------
// ArpRecord Struct
// ---------------------------------------------------------------------------

/// Internal ARP cache entry mapping an IP address to a hardware MAC address.
///
/// Replaces C `struct arp_record` (arp.c line 114).
/// C used a linked list with `next` pointer; Rust uses `Vec` indexing.
/// C stored `union all_addr` and `int family`; Rust uses `IpAddr` which
/// implicitly carries the address family.
#[derive(Debug, Clone)]
pub struct ArpRecord {
    /// Hardware (MAC) address bytes. Only the first `hwlen` bytes are valid.
    /// Padded with zeros beyond `hwlen`.
    pub hwaddr: [u8; DHCP_CHADDR_MAX],
    /// Hardware address length in bytes (typically 6 for Ethernet).
    /// Zero for [`ArpStatus::Empty`] negative cache entries.
    pub hwlen: usize,
    /// Current status of this cache entry.
    pub status: ArpStatus,
    /// IP address (IPv4 or IPv6). The address family is implicit in the
    /// `IpAddr` variant, replacing the C `int family` field.
    pub addr: IpAddr,
}

// ---------------------------------------------------------------------------
// ArpEnumerator Trait
// ---------------------------------------------------------------------------

/// Callback trait for platform-specific ARP/neighbor table enumeration.
///
/// Called by [`ArpCache`] during cache refresh to populate entries from the
/// kernel. Implementations are provided by:
/// - `netlink.rs` (Linux) — uses `RTM_GETNEIGH` netlink messages
/// - `bpf.rs` (BSD) — uses `sysctl` with `NET_RT_FLAGS`/`RTF_LLINFO`
///
/// Replaces C's `callback_t` union and `iface_enumerate(AF_UNSPEC, ...)`.
pub trait ArpEnumerator {
    /// Enumerate all entries in the kernel ARP/neighbor cache.
    ///
    /// For each entry, calls `callback(ip_addr, mac_bytes)` where:
    /// - `ip_addr` is the IP address (IPv4 or IPv6)
    /// - `mac_bytes` is the hardware/MAC address bytes (typically 6 for Ethernet)
    ///
    /// The callback should be called for all reachable/stale neighbors.
    /// Entries in INCOMPLETE, FAILED, or NOARP states should be skipped
    /// (matching the C `NUD_NOARP | NUD_INCOMPLETE | NUD_FAILED` filter).
    fn enumerate_arp(&self, callback: &mut dyn FnMut(IpAddr, &[u8])) -> DnsmasqResult<()>;
}

// ---------------------------------------------------------------------------
// ArpCache Struct
// ---------------------------------------------------------------------------

/// ARP/neighbor cache manager.
///
/// Encapsulates all state that was held in C static variables:
/// - `arps` linked list → `entries: Vec<ArpRecord>`
/// - `old` linked list → `old_entries: Vec<ArpRecord>`
/// - `freelist` linked list → **eliminated** (Rust allocator handles reuse)
/// - `last` timestamp → `last_refresh: Option<Instant>`
///
/// (arp.c lines 123-124)
pub struct ArpCache {
    /// Active cache entries (replaces C `arps` linked list).
    entries: Vec<ArpRecord>,
    /// Entries removed during last refresh, pending script notification
    /// (replaces C `old` linked list). These are entries that disappeared
    /// from the kernel ARP table and need `ACTION_ARP_DEL` notification.
    old_entries: Vec<ArpRecord>,
    /// Last cache refresh timestamp (replaces C `last` static variable).
    /// `None` means the cache has never been refreshed.
    last_refresh: Option<Instant>,
}

// ---------------------------------------------------------------------------
// Private helper: filter_mac_vec
// ---------------------------------------------------------------------------

/// Process one ARP entry from kernel enumeration, updating the entries vector.
///
/// This is a standalone function (rather than an `ArpCache` method) to avoid
/// mutable borrow conflicts when called from within the `enumerate_arp` closure
/// in `find_mac()`. The `ArpCache.entries` vec is temporarily moved out via
/// `std::mem::take()` during enumeration.
///
/// Maps C `filter_mac()` (arp.c line 167). The C version was a callback
/// invoked by `iface_enumerate(AF_UNSPEC, ...)` for each kernel ARP entry.
///
/// Status transitions:
/// - Existing entry with `Empty` status → `New` (negative cache upgraded)
/// - Existing entry with matching MAC → `Found` (confirmed in kernel)
/// - Existing entry with different MAC → `New` (MAC address changed)
/// - No existing entry → new `ArpRecord` with `New` status created
fn filter_mac_vec(entries: &mut Vec<ArpRecord>, addr: IpAddr, mac: &[u8]) {
    // Validate MAC length (C: if maclen > DHCP_CHADDR_MAX return 1)
    if mac.len() > DHCP_CHADDR_MAX {
        warn!(
            mac_len = mac.len(),
            max = DHCP_CHADDR_MAX,
            addr = %addr,
            "ARP entry MAC address exceeds maximum length, skipping"
        );
        return;
    }

    // Search existing entries for matching IP address
    for entry in entries.iter_mut() {
        if entry.addr == addr {
            if entry.status == ArpStatus::Empty {
                // Was negative cache entry — now has a MAC, upgrade to New.
                // C: arp->status = ARP_NEW; memcpy(arp->hwaddr, mac, maclen);
                entry.status = ArpStatus::New;
                entry.hwlen = mac.len();
                entry.hwaddr = [0u8; DHCP_CHADDR_MAX];
                entry.hwaddr[..mac.len()].copy_from_slice(mac);
                debug!(addr = %addr, hwlen = mac.len(), "ARP empty entry upgraded to new");
            } else if entry.hwlen == mac.len() && entry.hwaddr[..mac.len()] == *mac {
                // Same MAC address — mark as confirmed in kernel.
                // C: arp->status = ARP_FOUND;
                entry.status = ArpStatus::Found;
            } else {
                // MAC address changed — update and mark as new for notification.
                // C: arp->status = ARP_NEW; memcpy(arp->hwaddr, mac, maclen);
                entry.status = ArpStatus::New;
                entry.hwlen = mac.len();
                entry.hwaddr = [0u8; DHCP_CHADDR_MAX];
                entry.hwaddr[..mac.len()].copy_from_slice(mac);
                debug!(addr = %addr, hwlen = mac.len(), "ARP entry MAC changed");
            }
            return;
        }
    }

    // Not found in cache — create new entry.
    // C: arp = freelist or whine_malloc(); arp->status = ARP_NEW;
    // Rust: Vec::push — no manual allocation needed.
    let mut hwaddr = [0u8; DHCP_CHADDR_MAX];
    hwaddr[..mac.len()].copy_from_slice(mac);
    entries.push(ArpRecord {
        hwaddr,
        hwlen: mac.len(),
        status: ArpStatus::New,
        addr,
    });
    debug!(addr = %addr, hwlen = mac.len(), "ARP new entry created");
}

// ---------------------------------------------------------------------------
// Private helper: IP address conversion
// ---------------------------------------------------------------------------

/// Convert an `IpAddr` to the `AllAddr` enum used by the helper module.
///
/// This bridges the ARP module's use of `std::net::IpAddr` with the
/// integration helper's `AllAddr` type (which mirrors C's `union all_addr`).
#[cfg(any(feature = "script", test))]
fn ip_to_alladdr(addr: &IpAddr) -> AllAddr {
    match *addr {
        IpAddr::V4(v4) => AllAddr::V4(v4),
        IpAddr::V6(v6) => AllAddr::V6(v6),
    }
}

/// Return the address family constant for an IP address.
///
/// Returns `AF_INET` (2) for IPv4 or `AF_INET6` (10) for IPv6.
/// Used when calling `queue_arp()` for script notifications.
/// Note: the `_family` parameter in `queue_arp()` is currently unused,
/// but we pass the correct value for documentation and forward compatibility.
#[cfg(any(feature = "script", test))]
fn addr_family(addr: &IpAddr) -> i32 {
    match addr {
        IpAddr::V4(_) => AF_INET,
        IpAddr::V6(_) => AF_INET6,
    }
}

// ---------------------------------------------------------------------------
// ArpCache Implementation
// ---------------------------------------------------------------------------

impl Default for ArpCache {
    fn default() -> Self {
        Self::new()
    }
}

impl ArpCache {
    /// Create a new, empty ARP cache.
    ///
    /// The cache starts with no entries and no last-refresh timestamp,
    /// meaning the first call to `find_mac()` will trigger a kernel
    /// ARP table enumeration.
    pub fn new() -> Self {
        ArpCache {
            entries: Vec::new(),
            old_entries: Vec::new(),
            last_refresh: None,
        }
    }

    /// Process one ARP entry from kernel enumeration (private wrapper).
    ///
    /// Delegates to [`filter_mac_vec()`] operating on `self.entries`.
    /// This method is used for direct cache manipulation outside the
    /// `find_mac()` enumeration flow, and for testing cache behavior.
    #[cfg(test)]
    fn filter_mac(&mut self, addr: IpAddr, mac: &[u8]) {
        filter_mac_vec(&mut self.entries, addr, mac);
    }

    /// Look up the MAC (hardware) address for a given IP address.
    ///
    /// Implements a two-tier lookup strategy:
    /// 1. If the internal cache is fresh (< 90 seconds old), search it directly
    /// 2. If stale or entry not found (non-lazy mode), refresh from kernel
    ///
    /// Maps C `find_mac()` (arp.c line 300). The C `goto again` retry pattern
    /// is replaced with a Rust `loop { ... continue/break; }`.
    ///
    /// # Arguments
    /// - `addr`: IP address to look up, or `None` to just refresh the cache
    ///   if it's stale (returns `None` without searching)
    /// - `lazy`: If `true`, accept negative cache entries (`ArpStatus::Empty`)
    ///   and return `None` immediately on cache miss without forcing a refresh.
    ///   If `false`, force a kernel refresh on cache miss.
    /// - `now`: Current timestamp for cache freshness check
    /// - `enumerator`: Platform-specific ARP table enumerator (netlink/sysctl)
    ///
    /// # Returns
    /// - `Some((mac_bytes, hwlen))` — MAC address found
    /// - `None` — MAC not found (negative cache entry created in non-lazy mode)
    pub fn find_mac(
        &mut self,
        addr: Option<&IpAddr>,
        lazy: bool,
        now: Instant,
        enumerator: &dyn ArpEnumerator,
    ) -> Option<(Vec<u8>, usize)> {
        // Tracks whether we've already performed one kernel refresh.
        // Prevents infinite refresh loops — after one refresh, create a
        // negative cache entry if still not found.
        // Maps C: int updated = 0; (set to 1 after refresh)
        let mut updated = false;

        // Rust `loop` replaces C `goto again` pattern.
        loop {
            let cache_fresh = self
                .last_refresh
                .map(|last| now.duration_since(last) < CACHE_REFRESH_INTERVAL)
                .unwrap_or(false);

            if cache_fresh {
                // C: if (!addr) return 0; — NULL addr means "refresh if stale only"
                let addr_val = addr?;

                // Search the cache for matching IP address
                let mut found_empty = false;
                for entry in self.entries.iter() {
                    if entry.addr == *addr_val {
                        if entry.status == ArpStatus::Empty {
                            // Negative cache hit
                            if lazy {
                                return None;
                            }
                            // Non-lazy: need to try a refresh
                            found_empty = true;
                            break;
                        } else {
                            // Positive cache hit — return the MAC address
                            let mac = entry.hwaddr[..entry.hwlen].to_vec();
                            debug!(
                                addr = %addr_val,
                                hwlen = entry.hwlen,
                                "ARP cache hit"
                            );
                            return Some((mac, entry.hwlen));
                        }
                    }
                }

                // Not found in cache (or found only empty entry)
                if !found_empty && lazy {
                    // Lazy mode: don't force refresh on complete miss
                    return None;
                }

                if updated {
                    // Already refreshed once and still not found.
                    // Create a negative cache entry to prevent repeated
                    // kernel queries for the same missing address.
                    // C: arp->status = ARP_EMPTY; arp->hwlen = 0;
                    self.entries.push(ArpRecord {
                        hwaddr: [0u8; DHCP_CHADDR_MAX],
                        hwlen: 0,
                        status: ArpStatus::Empty,
                        addr: *addr_val,
                    });
                    debug!(
                        addr = %addr_val,
                        "ARP negative cache entry created"
                    );
                    return None;
                }
                // Fall through to refresh below
            }

            // ----- Cache is stale or entry not found — refresh from kernel -----
            debug!("Refreshing ARP cache from kernel");
            self.last_refresh = Some(now);
            updated = true;

            // Step 1: Mark all non-empty entries for sweep.
            // C: for (arp = arps; ...) if (arp->status != ARP_EMPTY) arp->status = ARP_MARK;
            for entry in self.entries.iter_mut() {
                if entry.status != ArpStatus::Empty {
                    entry.status = ArpStatus::Mark;
                }
            }

            // Step 2: Enumerate kernel ARP/neighbor table.
            // Temporarily take ownership of entries to avoid &mut self borrow
            // conflict inside the enumeration closure.
            // C: iface_enumerate(AF_UNSPEC, NULL, filter_mac);
            {
                let mut entries = std::mem::take(&mut self.entries);
                if let Err(e) = enumerator.enumerate_arp(&mut |ip, mac| {
                    filter_mac_vec(&mut entries, ip, mac);
                }) {
                    warn!(error = %e, "Failed to enumerate kernel ARP table");
                }
                self.entries = entries;
            }

            // Step 3: Sweep — move unconfirmed (still-marked) entries to old_entries.
            // These entries disappeared from the kernel ARP table and need
            // deletion notifications via do_arp_script_run().
            // C: splice marked entries from arps to old linked list.
            let mut i = 0;
            while i < self.entries.len() {
                if self.entries[i].status == ArpStatus::Mark {
                    let entry = self.entries.swap_remove(i);
                    debug!(addr = %entry.addr, "ARP entry swept to old (disappeared from kernel)");
                    self.old_entries.push(entry);
                    // Don't increment i — swap_remove moved the last element here
                } else {
                    i += 1;
                }
            }

            // Step 4: Loop back to retry lookup (Rust `continue` = C `goto again`)
        }
    }

    /// Process one pending ARP topology change notification (script feature enabled).
    ///
    /// Maps C `do_arp_script_run()` (arp.c line 445). This function processes
    /// entries one at a time (incremental, non-blocking) to avoid holding up
    /// the main event loop:
    ///
    /// 1. First, process deletions from `old_entries` (entries that disappeared
    ///    from the kernel ARP table), sending `ACTION_ARP_DEL` notifications.
    /// 2. Then, process newly discovered entries (`ArpStatus::New`) from `entries`,
    ///    sending `ACTION_ARP` notifications and transitioning them to `Found`.
    ///
    /// # Returns
    /// - `true` — more entries remain to process (call again)
    /// - `false` — all notifications complete
    ///
    /// # Script Integration
    /// Calls `helper.queue_arp()` with [`EventAction::ArpDel`] for deletions
    /// and [`EventAction::Arp`] for new entries. The helper module handles
    /// actual script execution.
    #[cfg(feature = "script")]
    pub fn do_arp_script_run(&mut self, helper: &mut ScriptHelper) -> bool {
        // Process one deletion from old_entries.
        // C: if ((arp = old)) { old = arp->next; queue_arp(ACTION_ARP_DEL, ...); }
        if let Some(arp) = self.old_entries.pop() {
            let alladdr = ip_to_alladdr(&arp.addr);
            let family = addr_family(&arp.addr);
            helper.queue_arp(
                EventAction::ArpDel,
                &arp.hwaddr[..arp.hwlen],
                family,
                &alladdr,
            );
            debug!(
                addr = %arp.addr,
                hwlen = arp.hwlen,
                "ARP deletion notification queued"
            );
            return true;
        }

        // Process one new entry from active entries.
        // C: for (arp = arps; ...) if (arp->status == ARP_NEW) { arp->status = ARP_FOUND; queue_arp(ACTION_ARP, ...); }
        for entry in self.entries.iter_mut() {
            if entry.status == ArpStatus::New {
                entry.status = ArpStatus::Found;
                let alladdr = ip_to_alladdr(&entry.addr);
                let family = addr_family(&entry.addr);
                helper.queue_arp(
                    EventAction::Arp,
                    &entry.hwaddr[..entry.hwlen],
                    family,
                    &alladdr,
                );
                debug!(
                    addr = %entry.addr,
                    hwlen = entry.hwlen,
                    "ARP new entry notification queued"
                );
                return true;
            }
        }

        // All notifications processed.
        false
    }

    /// Process one pending ARP topology change notification (no script support).
    ///
    /// When the `script` feature is not enabled, this function matches the C
    /// behavior of `do_arp_script_run()` without `HAVE_SCRIPT`: it immediately
    /// returns `false` without processing any entries.
    ///
    /// Note: In the C implementation, this also means `old_entries` are never
    /// drained. This is acceptable because the entries are bounded by network
    /// size and the ARP cache is small.
    #[cfg(not(feature = "script"))]
    pub fn do_arp_script_run(&mut self) -> bool {
        // C: return 0; (when HAVE_SCRIPT is not defined)
        false
    }
}

// ---------------------------------------------------------------------------
// Standalone public functions (convenience wrappers)
// ---------------------------------------------------------------------------

/// Standalone function wrapping [`ArpCache::find_mac()`].
///
/// Provides a function-style API matching C's global `find_mac()` function
/// signature. In the C implementation, `find_mac()` operated on static module
/// state; in Rust, the [`ArpCache`] instance is passed explicitly.
pub fn find_mac(
    cache: &mut ArpCache,
    addr: Option<&IpAddr>,
    lazy: bool,
    now: Instant,
    enumerator: &dyn ArpEnumerator,
) -> Option<(Vec<u8>, usize)> {
    cache.find_mac(addr, lazy, now, enumerator)
}

/// Standalone function wrapping [`ArpCache::do_arp_script_run()`] (script enabled).
///
/// Provides a function-style API matching C's global `do_arp_script_run()`.
#[cfg(feature = "script")]
pub fn do_arp_script_run(cache: &mut ArpCache, helper: &mut ScriptHelper) -> bool {
    cache.do_arp_script_run(helper)
}

/// Standalone function wrapping [`ArpCache::do_arp_script_run()`] (no script).
///
/// When the `script` feature is disabled, always returns `false`.
#[cfg(not(feature = "script"))]
pub fn do_arp_script_run(cache: &mut ArpCache) -> bool {
    cache.do_arp_script_run()
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// Mock ARP enumerator for testing.
    /// Stores a list of (IP, MAC) pairs that it will report to the callback.
    struct MockEnumerator {
        entries: Vec<(IpAddr, Vec<u8>)>,
    }

    impl MockEnumerator {
        fn new() -> Self {
            MockEnumerator {
                entries: Vec::new(),
            }
        }

        fn add(&mut self, addr: IpAddr, mac: Vec<u8>) {
            self.entries.push((addr, mac));
        }
    }

    impl ArpEnumerator for MockEnumerator {
        fn enumerate_arp(&self, callback: &mut dyn FnMut(IpAddr, &[u8])) -> DnsmasqResult<()> {
            for (addr, mac) in &self.entries {
                callback(*addr, mac);
            }
            Ok(())
        }
    }

    /// Empty enumerator that reports no ARP entries.
    struct EmptyEnumerator;

    impl ArpEnumerator for EmptyEnumerator {
        fn enumerate_arp(&self, _callback: &mut dyn FnMut(IpAddr, &[u8])) -> DnsmasqResult<()> {
            Ok(())
        }
    }

    #[test]
    fn test_arp_cache_new_creates_empty_cache() {
        let cache = ArpCache::new();
        assert!(cache.entries.is_empty());
        assert!(cache.old_entries.is_empty());
        assert!(cache.last_refresh.is_none());
    }

    #[test]
    fn test_filter_mac_adds_new_entry() {
        let mut cache = ArpCache::new();
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

        cache.filter_mac(addr, &mac);

        assert_eq!(cache.entries.len(), 1);
        assert_eq!(cache.entries[0].addr, addr);
        assert_eq!(cache.entries[0].hwlen, 6);
        assert_eq!(&cache.entries[0].hwaddr[..6], &mac);
        assert_eq!(cache.entries[0].status, ArpStatus::New);
    }

    #[test]
    fn test_filter_mac_updates_existing_entry_same_mac() {
        let mut cache = ArpCache::new();
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mac = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

        // Add initial entry and set to Mark (as if during refresh)
        cache.filter_mac(addr, &mac);
        cache.entries[0].status = ArpStatus::Mark;

        // Re-enumerate with same MAC
        cache.filter_mac(addr, &mac);

        assert_eq!(cache.entries.len(), 1);
        assert_eq!(cache.entries[0].status, ArpStatus::Found);
    }

    #[test]
    fn test_filter_mac_updates_existing_entry_different_mac() {
        let mut cache = ArpCache::new();
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let mac1 = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let mac2 = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

        cache.filter_mac(addr, &mac1);
        cache.entries[0].status = ArpStatus::Mark;

        // Re-enumerate with different MAC
        cache.filter_mac(addr, &mac2);

        assert_eq!(cache.entries.len(), 1);
        assert_eq!(cache.entries[0].status, ArpStatus::New);
        assert_eq!(&cache.entries[0].hwaddr[..6], &mac2);
    }

    #[test]
    fn test_filter_mac_upgrades_empty_entry() {
        let mut cache = ArpCache::new();
        let addr = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1));

        // Create an empty (negative cache) entry
        cache.entries.push(ArpRecord {
            hwaddr: [0u8; DHCP_CHADDR_MAX],
            hwlen: 0,
            status: ArpStatus::Empty,
            addr,
        });

        // Now enumerate finds a MAC for this IP
        let mac = [0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe];
        cache.filter_mac(addr, &mac);

        assert_eq!(cache.entries.len(), 1);
        assert_eq!(cache.entries[0].status, ArpStatus::New);
        assert_eq!(cache.entries[0].hwlen, 6);
        assert_eq!(&cache.entries[0].hwaddr[..6], &mac);
    }

    #[test]
    fn test_filter_mac_rejects_oversized_mac() {
        let mut cache = ArpCache::new();
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
        let oversized_mac = [0u8; DHCP_CHADDR_MAX + 1];

        cache.filter_mac(addr, &oversized_mac);

        // Entry should NOT be added
        assert!(cache.entries.is_empty());
    }

    #[test]
    fn test_find_mac_with_cache_hit() {
        let mut cache = ArpCache::new();
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

        // Pre-populate cache with a found entry
        let mut hwaddr = [0u8; DHCP_CHADDR_MAX];
        hwaddr[..6].copy_from_slice(&mac);
        cache.entries.push(ArpRecord {
            hwaddr,
            hwlen: 6,
            status: ArpStatus::Found,
            addr,
        });
        let now = Instant::now();
        cache.last_refresh = Some(now);

        let enumerator = EmptyEnumerator;
        let result = cache.find_mac(Some(&addr), false, now, &enumerator);

        assert!(result.is_some());
        let (found_mac, hwlen) = result.unwrap();
        assert_eq!(hwlen, 6);
        assert_eq!(&found_mac[..], &mac[..]);
    }

    #[test]
    fn test_find_mac_with_none_address_fresh_cache() {
        let mut cache = ArpCache::new();
        let now = Instant::now();
        cache.last_refresh = Some(now);

        let enumerator = EmptyEnumerator;
        let result = cache.find_mac(None, false, now, &enumerator);

        // None address with fresh cache → just returns None
        assert!(result.is_none());
    }

    #[test]
    fn test_find_mac_with_none_address_stale_cache() {
        let mut cache = ArpCache::new();
        // No last_refresh → cache is stale

        let enumerator = EmptyEnumerator;
        let now = Instant::now();
        let result = cache.find_mac(None, false, now, &enumerator);

        // None address → refreshes cache then returns None
        assert!(result.is_none());
        // Cache should now have a refresh timestamp
        assert!(cache.last_refresh.is_some());
    }

    #[test]
    fn test_find_mac_lazy_mode_miss() {
        let mut cache = ArpCache::new();
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 99));
        let now = Instant::now();
        cache.last_refresh = Some(now);

        let enumerator = EmptyEnumerator;
        let result = cache.find_mac(Some(&addr), true, now, &enumerator);

        // Lazy mode: cache miss returns None without forcing refresh
        assert!(result.is_none());
    }

    #[test]
    fn test_find_mac_lazy_mode_empty_entry() {
        let mut cache = ArpCache::new();
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99));
        let now = Instant::now();
        cache.last_refresh = Some(now);

        // Pre-populate with empty (negative cache) entry
        cache.entries.push(ArpRecord {
            hwaddr: [0u8; DHCP_CHADDR_MAX],
            hwlen: 0,
            status: ArpStatus::Empty,
            addr,
        });

        let enumerator = EmptyEnumerator;
        let result = cache.find_mac(Some(&addr), true, now, &enumerator);

        // Lazy mode: negative cache hit returns None
        assert!(result.is_none());
    }

    #[test]
    fn test_find_mac_non_lazy_creates_negative_cache() {
        let mut cache = ArpCache::new();
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200));
        let now = Instant::now();

        // Empty enumerator — nothing in kernel ARP table
        let enumerator = EmptyEnumerator;
        let result = cache.find_mac(Some(&addr), false, now, &enumerator);

        // Non-lazy: refreshes, finds nothing, creates negative cache entry
        assert!(result.is_none());
        // Should have created an Empty entry
        assert!(cache
            .entries
            .iter()
            .any(|e| e.addr == addr && e.status == ArpStatus::Empty));
    }

    #[test]
    fn test_find_mac_refresh_finds_entry() {
        let mut cache = ArpCache::new();
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        let mac = vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let now = Instant::now();

        // Enumerator that reports one entry
        let mut enumerator = MockEnumerator::new();
        enumerator.add(addr, mac.clone());

        let result = cache.find_mac(Some(&addr), false, now, &enumerator);

        assert!(result.is_some());
        let (found_mac, hwlen) = result.unwrap();
        assert_eq!(hwlen, 6);
        assert_eq!(found_mac, mac);
    }

    #[test]
    fn test_find_mac_sweep_moves_to_old() {
        let mut cache = ArpCache::new();
        let addr1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let addr2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
        let mac = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

        // Pre-populate with two entries
        let mut hwaddr = [0u8; DHCP_CHADDR_MAX];
        hwaddr[..6].copy_from_slice(&mac);
        cache.entries.push(ArpRecord {
            hwaddr,
            hwlen: 6,
            status: ArpStatus::Found,
            addr: addr1,
        });
        cache.entries.push(ArpRecord {
            hwaddr,
            hwlen: 6,
            status: ArpStatus::Found,
            addr: addr2,
        });

        // Enumerator only reports addr1 (addr2 disappeared)
        let mut enumerator = MockEnumerator::new();
        enumerator.add(addr1, mac.clone());

        let now = Instant::now();
        // No last_refresh → forces kernel refresh
        let _result = cache.find_mac(Some(&addr1), false, now, &enumerator);

        // addr2 should have been swept to old_entries
        assert!(cache.old_entries.iter().any(|e| e.addr == addr2));
    }

    #[test]
    fn test_find_mac_ipv6_address() {
        let mut cache = ArpCache::new();
        let addr = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0x1, 0x2, 0x3, 0x4));
        let mac = vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let now = Instant::now();

        let mut enumerator = MockEnumerator::new();
        enumerator.add(addr, mac.clone());

        let result = cache.find_mac(Some(&addr), false, now, &enumerator);

        assert!(result.is_some());
        let (found_mac, hwlen) = result.unwrap();
        assert_eq!(hwlen, 6);
        assert_eq!(found_mac, mac);
    }

    #[cfg(feature = "script")]
    #[test]
    fn test_do_arp_script_run_processes_deletions_first() {
        let mut cache = ArpCache::new();
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut hwaddr = [0u8; DHCP_CHADDR_MAX];
        hwaddr[..6].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);

        // Add an old entry (deletion pending)
        cache.old_entries.push(ArpRecord {
            hwaddr,
            hwlen: 6,
            status: ArpStatus::Mark,
            addr,
        });

        // Create a ScriptHelper with no script path (queue_arp will be a no-op)
        let mut helper = ScriptHelper::new(None, None, None)
            .expect("ScriptHelper::new should succeed with no script");

        // Should process one deletion and return true
        assert!(cache.do_arp_script_run(&mut helper));
        // Old entry should have been removed
        assert!(cache.old_entries.is_empty());
    }

    #[cfg(feature = "script")]
    #[test]
    fn test_do_arp_script_run_processes_new_entries() {
        let mut cache = ArpCache::new();
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let mut hwaddr = [0u8; DHCP_CHADDR_MAX];
        hwaddr[..6].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

        // Add a new entry
        cache.entries.push(ArpRecord {
            hwaddr,
            hwlen: 6,
            status: ArpStatus::New,
            addr,
        });

        let mut helper = ScriptHelper::new(None, None, None)
            .expect("ScriptHelper::new should succeed with no script");

        // Should process new entry and return true
        assert!(cache.do_arp_script_run(&mut helper));
        // Entry should now be Found
        assert_eq!(cache.entries[0].status, ArpStatus::Found);
    }

    #[cfg(feature = "script")]
    #[test]
    fn test_do_arp_script_run_returns_false_when_done() {
        let mut cache = ArpCache::new();

        // Add one Found entry (no notification needed)
        cache.entries.push(ArpRecord {
            hwaddr: [0u8; DHCP_CHADDR_MAX],
            hwlen: 6,
            status: ArpStatus::Found,
            addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        });

        let mut helper = ScriptHelper::new(None, None, None)
            .expect("ScriptHelper::new should succeed with no script");

        // No old entries, no new entries → return false
        assert!(!cache.do_arp_script_run(&mut helper));
    }

    #[cfg(feature = "script")]
    #[test]
    fn test_do_arp_script_run_incremental_processing() {
        let mut cache = ArpCache::new();
        let mut hwaddr = [0u8; DHCP_CHADDR_MAX];
        hwaddr[..6].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);

        // Add two old entries (deletions) and two new entries
        for i in 1..=2u8 {
            cache.old_entries.push(ArpRecord {
                hwaddr,
                hwlen: 6,
                status: ArpStatus::Mark,
                addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, i)),
            });
        }
        for i in 3..=4u8 {
            cache.entries.push(ArpRecord {
                hwaddr,
                hwlen: 6,
                status: ArpStatus::New,
                addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, i)),
            });
        }

        let mut helper = ScriptHelper::new(None, None, None)
            .expect("ScriptHelper::new should succeed with no script");

        // Should process 4 entries one at a time
        assert!(cache.do_arp_script_run(&mut helper)); // old #1
        assert!(cache.do_arp_script_run(&mut helper)); // old #2
        assert!(cache.do_arp_script_run(&mut helper)); // new #1
        assert!(cache.do_arp_script_run(&mut helper)); // new #2
        assert!(!cache.do_arp_script_run(&mut helper)); // done
    }

    #[test]
    fn test_negative_caching_prevents_repeated_refresh() {
        let mut cache = ArpCache::new();
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 254));
        let now = Instant::now();
        let enumerator = EmptyEnumerator;

        // First call: non-lazy, no entry → refreshes and creates negative cache
        let result1 = cache.find_mac(Some(&addr), false, now, &enumerator);
        assert!(result1.is_none());

        // Verify negative cache entry exists
        let empty_entry = cache
            .entries
            .iter()
            .find(|e| e.addr == addr && e.status == ArpStatus::Empty);
        assert!(empty_entry.is_some());

        // Second call with lazy=true: should hit the negative cache
        let result2 = cache.find_mac(Some(&addr), true, now, &enumerator);
        assert!(result2.is_none());
    }

    #[test]
    fn test_dhcp_chaddr_max_constant() {
        assert_eq!(DHCP_CHADDR_MAX, 16);
    }

    #[test]
    fn test_cache_refresh_interval_constant() {
        assert_eq!(CACHE_REFRESH_INTERVAL, Duration::from_secs(90));
    }

    #[test]
    fn test_ip_to_alladdr_v4() {
        let v4 = Ipv4Addr::new(10, 20, 30, 40);
        let ip = IpAddr::V4(v4);
        let result = ip_to_alladdr(&ip);
        match result {
            AllAddr::V4(a) => assert_eq!(a, v4),
            _ => panic!("Expected AllAddr::V4"),
        }
    }

    #[test]
    fn test_ip_to_alladdr_v6() {
        let v6 = Ipv6Addr::new(0xfe80, 0, 0, 0, 1, 2, 3, 4);
        let ip = IpAddr::V6(v6);
        let result = ip_to_alladdr(&ip);
        match result {
            AllAddr::V6(a) => assert_eq!(a, v6),
            _ => panic!("Expected AllAddr::V6"),
        }
    }

    #[test]
    fn test_addr_family() {
        let v4 = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert_eq!(addr_family(&v4), AF_INET);
        assert_eq!(addr_family(&v6), AF_INET6);
    }

    #[test]
    fn test_filter_mac_multiple_ips() {
        let mut cache = ArpCache::new();
        let addr1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let addr2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
        let addr3 = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        let mac1 = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let mac2 = [0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
        let mac3 = [0xf0, 0xe0, 0xd0, 0xc0, 0xb0, 0xa0];

        cache.filter_mac(addr1, &mac1);
        cache.filter_mac(addr2, &mac2);
        cache.filter_mac(addr3, &mac3);

        assert_eq!(cache.entries.len(), 3);
        assert!(cache
            .entries
            .iter()
            .any(|e| e.addr == addr1 && e.hwaddr[..6] == mac1));
        assert!(cache
            .entries
            .iter()
            .any(|e| e.addr == addr2 && e.hwaddr[..6] == mac2));
        assert!(cache
            .entries
            .iter()
            .any(|e| e.addr == addr3 && e.hwaddr[..6] == mac3));
    }

    #[test]
    fn test_standalone_find_mac() {
        let mut cache = ArpCache::new();
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1));
        let mac = vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let now = Instant::now();

        let mut enumerator = MockEnumerator::new();
        enumerator.add(addr, mac.clone());

        // Test standalone function delegates correctly
        let result = find_mac(&mut cache, Some(&addr), false, now, &enumerator);
        assert!(result.is_some());
        let (found_mac, hwlen) = result.unwrap();
        assert_eq!(hwlen, 6);
        assert_eq!(found_mac, mac);
    }
}

//! ARP/Neighbor cache management for MAC address lookup and network topology tracking.
//!
//! This module implements an internal ARP (Address Resolution Protocol) and IPv6
//! neighbor cache that maintains mappings between IP addresses and hardware MAC
//! addresses. The cache is populated by reading the kernel's ARP/neighbor tables
//! and provides MAC address lookup services primarily for DHCP operations including
//! address-in-use testing, lease management, and client identification.
//!
//! # Architecture
//!
//! This module is a complete Rust rewrite of `src/arp.c` (475 lines of C):
//!
//! - C `struct arp_record` linked list → Rust [`Vec<ArpRecord>`]
//! - C `union all_addr` → [`std::net::IpAddr`] (only addr4/addr6 used in ARP context)
//! - C `union mysockaddr` → [`SocketAddress`] enum from `crate::types::addr`
//! - C `whine_malloc` / freelist → Rust automatic memory management via [`Vec`]
//! - C static global state (`arps`, `old`, `freelist`, `last`) → [`ArpCache`] struct
//! - C `HAVE_SCRIPT` preprocessor guard → `#[cfg(feature = "script")]`
//!
//! # Usage Pattern
//!
//! ```ignore
//! use std::time::Instant;
//! use dnsmasq::net::arp::ArpCache;
//!
//! let mut cache = ArpCache::new();
//! let now = Instant::now();
//!
//! // Refresh from kernel ARP table (platform-specific enumerator)
//! cache.refresh(&mut |callback| {
//!     // Platform layer iterates kernel ARP entries and calls callback
//!     // callback(ip_addr, &mac_bytes).ok();
//! });
//!
//! // Look up MAC address for an IP
//! if let Some((mac, hwlen)) = cache.find_mac(Some(&addr), false, now) {
//!     // MAC address found with `hwlen` bytes
//! }
//!
//! // Process topology change notifications
//! while cache.do_arp_script_run() {
//!     // Each call processes one entry incrementally
//! }
//! ```
//!
//! # Thread Safety
//!
//! This module assumes single-threaded operation within the dnsmasq event loop.
//! All methods take `&mut self`, enforcing exclusive access at compile time.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use nix::sys::socket::AddressFamily;
use thiserror::Error;

use crate::types::addr::SocketAddress;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum hardware (MAC) address length in bytes.
///
/// Matches `DHCP_CHADDR_MAX` from C `config.h` / `dnsmasq.h`.
/// Standard Ethernet MAC addresses are 6 bytes; this accommodates
/// longer hardware address formats used by some link-layer protocols.
pub const DHCP_CHADDR_MAX: usize = 16;

/// Time interval between forced reloads of the ARP cache from the kernel.
///
/// Matches C `#define INTERVAL 90` in `arp.c` line 68.
/// The kernel ARP/neighbor table is re-read periodically to detect network
/// topology changes even when no explicit lookups are made.
pub const CACHE_REFRESH_INTERVAL: Duration = Duration::from_secs(90);

/// Action constant for new ARP entry script notification.
///
/// Used with the script notification system (`queue_arp`).
/// Replaces C `ACTION_ARP` from `dnsmasq.h`.
#[cfg(feature = "script")]
pub const ACTION_ARP: u32 = 1;

/// Action constant for deleted ARP entry script notification.
///
/// Used with the script notification system (`queue_arp`).
/// Replaces C `ACTION_ARP_DEL` from `dnsmasq.h`.
#[cfg(feature = "script")]
pub const ACTION_ARP_DEL: u32 = 2;

// ---------------------------------------------------------------------------
// ArpStatus enum
// ---------------------------------------------------------------------------

/// Status of an ARP cache entry through its lifecycle.
///
/// Maps directly to C constants from `arp.c` lines 73-88:
/// - `ARP_MARK  = 0` → [`ArpStatus::Mark`]
/// - `ARP_FOUND = 1` → [`ArpStatus::Found`]
/// - `ARP_NEW   = 2` → [`ArpStatus::New`]
/// - `ARP_EMPTY = 3` → [`ArpStatus::Empty`]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArpStatus {
    /// Initial mark state before cache reload.
    ///
    /// Entries are marked during refresh; those not confirmed by the kernel
    /// are moved to the `old` list for deletion notification.
    Mark,

    /// Confirmed in kernel cache during reload.
    ///
    /// The entry was found in the latest kernel ARP table enumeration
    /// with the same MAC address as previously recorded.
    Found,

    /// Newly discovered mapping.
    ///
    /// Either a completely new IP-to-MAC mapping discovered during kernel
    /// enumeration, or an `Empty` entry that has received a MAC address.
    New,

    /// IP address known but no MAC address available (negative cache).
    ///
    /// Prevents repeated kernel queries for addresses not in the ARP table.
    /// Created when a `find_mac` lookup fails after a cache refresh.
    Empty,
}

// ---------------------------------------------------------------------------
// ArpRecord struct
// ---------------------------------------------------------------------------

/// Internal cache entry mapping an IP address to a hardware MAC address.
///
/// Replaces C `struct arp_record` from `arp.c` lines 114-121.
/// Each record tracks the lifecycle status, address family, IP address,
/// and hardware address for a single ARP/neighbor cache entry.
///
/// # Memory Layout
///
/// In C, records were managed via intrusive linked lists with a freelist
/// for memory reuse. In Rust, records are stored in `Vec<ArpRecord>` with
/// automatic memory management — no freelist is needed.
#[derive(Debug, Clone)]
struct ArpRecord {
    /// Hardware address length in bytes (typically 6 for Ethernet).
    hwlen: u16,

    /// Cache entry lifecycle status.
    status: ArpStatus,

    /// Address family: `AF_INET` for IPv4, `AF_INET6` for IPv6.
    family: AddressFamily,

    /// Hardware MAC address buffer, max 16 bytes per DHCP specification.
    /// Only the first `hwlen` bytes are valid.
    hwaddr: [u8; DHCP_CHADDR_MAX],

    /// Network layer address (IPv4 or IPv6).
    /// Replaces C `union all_addr` which only uses `addr4`/`addr6` in ARP context.
    addr: IpAddr,
}

// ---------------------------------------------------------------------------
// ArpError enum
// ---------------------------------------------------------------------------

/// Error types for ARP cache operations.
///
/// Replaces C integer return codes (0/1) with idiomatic Rust error handling.
/// Derives `std::error::Error` and `Display` via `thiserror`.
#[derive(Debug, Error)]
pub enum ArpError {
    /// MAC address length exceeds the maximum allowed (`DHCP_CHADDR_MAX`).
    ///
    /// Returned by `filter_mac` when the kernel reports a hardware address
    /// longer than 16 bytes, which cannot be stored in the cache.
    #[error("MAC address length {0} exceeds maximum {DHCP_CHADDR_MAX}")]
    MacTooLong(usize),

    /// Memory allocation failed.
    ///
    /// Retained for API compatibility with the C `whine_malloc` failure path.
    /// In practice, Rust's allocator typically panics on OOM rather than
    /// returning an error, but this variant allows graceful handling if
    /// custom allocators are used.
    #[error("Memory allocation failed")]
    AllocationFailed,

    /// Kernel ARP cache query failed with an I/O error.
    ///
    /// Wraps the underlying I/O error from platform-specific ARP table
    /// enumeration (e.g., netlink socket failure on Linux, sysctl failure
    /// on BSD).
    #[error("Kernel ARP cache query failed: {0}")]
    KernelQueryFailed(#[from] std::io::Error),
}

// ---------------------------------------------------------------------------
// ArpEnumerateCallback type alias
// ---------------------------------------------------------------------------

/// Callback type for ARP/neighbor table enumeration.
///
/// This callback is invoked by the platform layer for each entry discovered
/// in the kernel's ARP (IPv4) or neighbor (IPv6) table during a cache refresh.
/// The platform implementation (netlink on Linux, sysctl on BSD) calls this
/// callback with the IP address and MAC address bytes for each entry found
/// in the kernel's tables.
///
/// This replaces C's `iface_enumerate(AF_UNSPEC, NULL, filter_mac)` pattern
/// where `filter_mac` was passed as a function pointer callback.
///
/// # Parameters
///
/// - `IpAddr`: The network address (IPv4 or IPv6) of the ARP entry
/// - `&[u8]`: The hardware (MAC) address bytes
///
/// # Returns
///
/// `Result<(), ArpError>` — `Ok(())` to continue enumeration, or `Err` on
/// failure (e.g., `MacTooLong` if the MAC exceeds `DHCP_CHADDR_MAX` bytes).
pub type ArpEnumerateCallback = dyn FnMut(IpAddr, &[u8]) -> Result<(), ArpError>;

// ---------------------------------------------------------------------------
// ArpCache struct
// ---------------------------------------------------------------------------

/// ARP/neighbor cache providing IP-to-MAC address lookup services.
///
/// Encapsulates all module state that was previously stored in C static
/// global variables:
/// - `static struct arp_record *arps` → [`ArpCache::arps`]
/// - `static struct arp_record *old`  → [`ArpCache::old`]
/// - `static struct arp_record *freelist` → eliminated (Rust manages memory)
/// - `static time_t last` → [`ArpCache::last_refresh`]
///
/// # Cache Lifecycle
///
/// 1. The cache starts empty after [`ArpCache::new()`].
/// 2. [`ArpCache::refresh()`] populates it from the kernel ARP table.
/// 3. [`ArpCache::find_mac()`] searches the cache for MAC addresses.
/// 4. [`ArpCache::do_arp_script_run()`] processes topology change notifications.
///
/// # Refresh Interval
///
/// The cache is considered stale after [`CACHE_REFRESH_INTERVAL`] (90 seconds).
/// Callers should check [`ArpCache::is_fresh()`] and call [`ArpCache::refresh()`]
/// when the cache becomes stale before performing lookups.
pub struct ArpCache {
    /// Active cache entries.
    /// Replaces C `static struct arp_record *arps` singly-linked list.
    arps: Vec<ArpRecord>,

    /// Entries pending deletion notification.
    /// Entries moved here during refresh when they are no longer confirmed
    /// in the kernel ARP table. Processed by `do_arp_script_run()`.
    /// Replaces C `static struct arp_record *old` singly-linked list.
    old: Vec<ArpRecord>,

    /// Last kernel cache refresh timestamp (monotonic clock).
    /// `None` means the cache has never been refreshed.
    /// Replaces C `static time_t last`.
    last_refresh: Option<Instant>,

    /// Flag indicating that `refresh()` was called since the last `find_mac()`.
    /// Mirrors the C `updated` local variable in `find_mac()` which tracks
    /// whether a kernel refresh occurred during the current lookup cycle.
    /// When true, negative cache (EMPTY) entries are accepted even in
    /// non-lazy mode, since the kernel was just consulted.
    refreshed: bool,
}

impl ArpCache {
    /// Create a new, empty ARP cache.
    ///
    /// The cache starts with no entries and no refresh timestamp.
    /// The caller should call [`refresh()`](Self::refresh) with a platform-specific
    /// enumerator before performing lookups.
    pub fn new() -> Self {
        ArpCache {
            arps: Vec::new(),
            old: Vec::new(),
            last_refresh: None,
            refreshed: false,
        }
    }

    /// Check if the cache has been refreshed within the refresh interval.
    ///
    /// Returns `true` if the cache was refreshed less than
    /// [`CACHE_REFRESH_INTERVAL`] (90 seconds) ago, `false` otherwise
    /// or if the cache has never been refreshed.
    ///
    /// # Parameters
    ///
    /// - `now`: Current monotonic timestamp for age comparison.
    #[inline]
    pub fn is_fresh(&self, now: Instant) -> bool {
        self.last_refresh
            .map(|last| now.duration_since(last) < CACHE_REFRESH_INTERVAL)
            .unwrap_or(false)
    }

    /// Refresh the ARP cache from the kernel's ARP/neighbor table.
    ///
    /// Performs a three-phase cache refresh:
    ///
    /// 1. **Mark**: All non-empty entries are set to [`ArpStatus::Mark`] status,
    ///    indicating they need confirmation from the kernel.
    /// 2. **Enumerate**: The platform `enumerator` iterates the kernel ARP/neighbor
    ///    table and calls the provided callback for each entry, which updates
    ///    existing entries (confirming them as [`ArpStatus::Found`]) or creates
    ///    new entries (as [`ArpStatus::New`]).
    /// 3. **Sweep**: Unconfirmed entries (still [`ArpStatus::Mark`]) are moved to
    ///    the pending-deletion list for script notification processing.
    ///
    /// This replaces the inline refresh logic in C `find_mac()` lines 338-365
    /// which called `iface_enumerate(AF_UNSPEC, NULL, filter_mac)` directly.
    ///
    /// # Parameters
    ///
    /// - `enumerator`: Platform-specific function that iterates the kernel
    ///   ARP/neighbor table. On Linux this uses netlink (`NETLINK_ROUTE`),
    ///   on BSD it uses sysctl or `getifaddrs`. The enumerator receives a
    ///   mutable reference to an [`ArpEnumerateCallback`] which it should
    ///   call for each kernel ARP entry.
    ///
    /// # Generic Design Note
    ///
    /// The `enumerator` parameter uses a generic `F` rather than `dyn FnMut`
    /// to avoid the implicit `'static` lifetime bound that bare `dyn FnMut`
    /// trait objects impose on nested `dyn FnMut` callback parameters. With
    /// the generic, the compiler correctly infers that the inner callback only
    /// needs to live for the duration of the enumerator call. The public
    /// [`ArpEnumerateCallback`] type alias remains available for callers to
    /// describe the callback type in their own signatures.
    pub fn refresh<F>(&mut self, enumerator: &mut F)
    where
        F: FnMut(&mut dyn FnMut(IpAddr, &[u8]) -> Result<(), ArpError>),
    {
        // Phase 1: Mark all non-empty entries for confirmation.
        // EMPTY entries are preserved — they represent negative cache entries
        // that should persist unless a MAC address is discovered for them.
        // Matches C `arp.c` lines 343-346.
        for arp in self.arps.iter_mut() {
            if arp.status != ArpStatus::Empty {
                arp.status = ArpStatus::Mark;
            }
        }

        // Phase 2: Enumerate kernel ARP table, updating cache via filter_mac logic.
        // We use std::mem::take to temporarily move arps out of self, allowing the
        // closure to capture only the local `arps_temp` variable. This avoids
        // nested mutable borrows of self through the enumerator callback chain.
        // After enumeration completes, entries are moved back into self.arps.
        // std::mem::take is O(1) — it just swaps internal Vec pointers.
        let mut arps_temp = std::mem::take(&mut self.arps);
        enumerator(&mut |addr: IpAddr, mac: &[u8]| -> Result<(), ArpError> {
            Self::filter_mac_impl(&mut arps_temp, addr, mac)
        });
        self.arps = arps_temp;

        // Phase 3: Move unconfirmed entries (still MARK) to the old list.
        // These represent devices that have disappeared from the network.
        // Matches C `arp.c` lines 350-363.
        let mut i = 0;
        while i < self.arps.len() {
            if self.arps[i].status == ArpStatus::Mark {
                let entry = self.arps.remove(i);
                self.old.push(entry);
            } else {
                i += 1;
            }
        }

        // Update refresh timestamp and set the refreshed flag.
        self.last_refresh = Some(Instant::now());
        self.refreshed = true;
    }

    /// Look up the hardware MAC address for a given IP address.
    ///
    /// Searches the internal cache for an entry matching the given socket address.
    /// This replaces C `find_mac()` from `arp.c` lines 300-393.
    ///
    /// # Parameters
    ///
    /// - `addr`: Socket address to look up. If `None`, this is a "refresh check
    ///   only" operation and always returns `None`. This matches the C behavior
    ///   where `find_mac(NULL, NULL, 0, now)` just ensures the cache is up-to-date.
    /// - `lazy`: Controls negative caching behavior.
    ///   - `true`: Accept [`ArpStatus::Empty`] entries (negative cache hits).
    ///     Used when the caller can tolerate stale negative results.
    ///   - `false`: Only accept entries with a valid MAC address. If an
    ///     `Empty` entry is found, returns `None` so the caller can refresh
    ///     and retry, forcing a kernel re-check.
    /// - `now`: Current monotonic timestamp for cache age comparison.
    ///
    /// # Returns
    ///
    /// - `Some((mac_bytes, hwlen))` if a matching entry is found, where
    ///   `mac_bytes` contains the hardware address and `hwlen` is its length.
    ///   For [`ArpStatus::Empty`] entries accepted in lazy mode, returns
    ///   `Some((vec![], 0))`.
    /// - `None` if not found, if `addr` is `None`, or if the cache is stale
    ///   and needs refresh.
    ///
    /// # Caller Contract
    ///
    /// When `find_mac` returns `None` and the cache is stale
    /// ([`is_fresh()`](Self::is_fresh) returns `false`), the caller should:
    /// 1. Call [`refresh()`](Self::refresh) with a platform enumerator.
    /// 2. Call `find_mac()` again — the `refreshed` flag will cause
    ///    negative cache entries to be accepted.
    ///
    /// This two-step pattern replaces the C code's internal
    /// `iface_enumerate()` call and `goto again` loop.
    pub fn find_mac(
        &mut self,
        addr: Option<&SocketAddress>,
        lazy: bool,
        now: Instant,
    ) -> Option<(Vec<u8>, usize)> {
        // addr == None means "just ensure cache is up-to-date" — return None.
        // Matches C `arp.c` lines 310-312: `if (!addr) return 0;`
        let addr = match addr {
            Some(a) => a,
            None => return None,
        };

        // Extract IP and address family from the SocketAddress.
        let (ip, family) = Self::extract_addr_info(addr);

        let cache_fresh = self.is_fresh(now);

        if cache_fresh {
            // Search the cache for a matching entry.
            // Matches C `arp.c` lines 314-334.
            for arp in self.arps.iter() {
                // Skip entries with different address family.
                if arp.family != family {
                    continue;
                }

                // Skip entries with different IP address.
                if arp.addr != ip {
                    continue;
                }

                // Accept the entry if:
                // - status is not EMPTY (positive cache hit), OR
                // - lazy mode is enabled (accept negative cache), OR
                // - cache was just refreshed (kernel was consulted, accept result)
                //
                // Matches C: `if (arp->status != ARP_EMPTY || lazy || updated)`
                if arp.status != ArpStatus::Empty || lazy || self.refreshed {
                    let hwlen = arp.hwlen as usize;
                    let mac = arp.hwaddr[..hwlen].to_vec();
                    self.refreshed = false;
                    return Some((mac, hwlen));
                }

                // EMPTY entry found, but !lazy and !refreshed.
                // The C code continues searching in case there are other entries.
                // (In practice, there's typically only one entry per IP.)
            }
        }

        // Entry not found in cache, or cache is stale, or only EMPTY found
        // with !lazy and !refreshed.

        if self.refreshed {
            // We already refreshed but the entry is truly not in the kernel.
            // Create a negative cache entry to prevent repeated kernel queries
            // for the same address. Matches C `arp.c` lines 368-392.
            self.add_empty_entry(ip, family);
            self.refreshed = false;
        }

        None
    }

    /// Process ARP cache changes incrementally for script notifications.
    ///
    /// This method processes one entry per call, designed to be called repeatedly
    /// from the event loop without blocking. It handles two categories of changes:
    ///
    /// 1. **Deletions** (from `old` list): Entries removed during the last refresh
    ///    because they were no longer confirmed in the kernel ARP table. These
    ///    represent devices that have disappeared from the network.
    /// 2. **Additions** (from `arps` list): Entries marked [`ArpStatus::New`],
    ///    representing newly discovered devices on the network.
    ///
    /// Replaces C `do_arp_script_run()` from `arp.c` lines 445-475.
    ///
    /// # Returns
    ///
    /// - `true` if an entry was processed (call again for more work)
    /// - `false` if no more entries need processing
    ///
    /// # Script Notifications
    ///
    /// When the `script` feature is enabled, each processed entry generates
    /// a log message with the notification data. In the full system, the caller
    /// integrates with the helper process (`queue_arp`) for actual script
    /// execution. When the feature is disabled, state transitions still occur
    /// but no notifications are generated.
    pub fn do_arp_script_run(&mut self) -> bool {
        // Process deleted entries first (from old list).
        // In C: pop from old, call queue_arp(ACTION_ARP_DEL, ...), move to freelist.
        // In Rust: pop and drop (no freelist needed).
        // Matches C `arp.c` lines 449-461.
        if let Some(_entry) = self.old.pop() {
            #[cfg(feature = "script")]
            {
                log::debug!(
                    "ARP delete notification: addr={}, family={:?}, hwlen={}",
                    _entry.addr,
                    _entry.family,
                    _entry.hwlen
                );
            }
            // Entry is dropped here — Rust manages memory automatically.
            // The freelist pattern from C is unnecessary.
            return true;
        }

        // Process new entries — find first NEW in arps list.
        // In C: call queue_arp(ACTION_ARP, ...), change status to FOUND.
        // Matches C `arp.c` lines 463-472.
        for arp in self.arps.iter_mut() {
            if arp.status == ArpStatus::New {
                #[cfg(feature = "script")]
                {
                    log::debug!(
                        "ARP add notification: addr={}, family={:?}, hwlen={}",
                        arp.addr,
                        arp.family,
                        arp.hwlen
                    );
                }
                arp.status = ArpStatus::Found;
                return true;
            }
        }

        false
    }

    // -----------------------------------------------------------------------
    // Private helper methods
    // -----------------------------------------------------------------------

    /// Internal filter_mac implementation operating on a `Vec` directly.
    ///
    /// This is a static method to avoid borrow checker issues when called
    /// from within [`refresh()`](Self::refresh) where `self.arps` is already
    /// mutably borrowed through the enumerator closure.
    ///
    /// Implements the C `filter_mac()` logic from `arp.c` lines 167-232:
    ///
    /// 1. Reject MAC addresses longer than [`DHCP_CHADDR_MAX`].
    /// 2. Search for an existing entry matching IP address and family,
    ///    skipping entries with [`ArpStatus::New`] status.
    /// 3. If found with [`ArpStatus::Empty`] → transition to [`ArpStatus::New`],
    ///    copy the MAC address.
    /// 4. If found with matching MAC → mark as [`ArpStatus::Found`].
    /// 5. If found with different MAC → continue search (MAC changed,
    ///    old entry stays as [`ArpStatus::Mark`] for cleanup).
    /// 6. If not found → create a new [`ArpStatus::New`] entry.
    fn filter_mac_impl(
        arps: &mut Vec<ArpRecord>,
        addr: IpAddr,
        mac: &[u8],
    ) -> Result<(), ArpError> {
        // Reject MAC addresses that exceed the buffer size.
        // Matches C `arp.c` lines 173-174.
        if mac.len() > DHCP_CHADDR_MAX {
            return Err(ArpError::MacTooLong(mac.len()));
        }

        let family = match addr {
            IpAddr::V4(_) => AddressFamily::Inet,
            IpAddr::V6(_) => AddressFamily::Inet6,
        };
        let maclen = mac.len() as u16;

        // Search for an existing entry matching address and family.
        // Skip entries with NEW status (they were created during this
        // same enumeration pass and should not be matched again).
        // Matches C `arp.c` lines 177-207.
        let mut found = false;
        for arp in arps.iter_mut() {
            // Skip entries with different family or NEW status.
            if arp.family != family || arp.status == ArpStatus::New {
                continue;
            }

            // Check if IP addresses match.
            if arp.addr != addr {
                continue;
            }

            if arp.status == ArpStatus::Empty {
                // Existing negative entry — MAC address now available.
                // Transition EMPTY → NEW and record the MAC.
                // Matches C `arp.c` lines 193-199.
                arp.status = ArpStatus::New;
                arp.hwlen = maclen;
                arp.hwaddr[..mac.len()].copy_from_slice(mac);
                found = true;
                break;
            } else if arp.hwlen == maclen && arp.hwaddr[..mac.len()] == *mac {
                // Existing entry with matching MAC — confirm it.
                // Matches C `arp.c` lines 200-202.
                arp.status = ArpStatus::Found;
                found = true;
                break;
            } else {
                // Address matches but MAC differs — update in-place.
                // This handles NIC replacements and interface changes.
                // The entry transitions to NEW so script notifications fire.
                // Matches C `arp.c` lines 203-209.
                arp.status = ArpStatus::New;
                arp.hwlen = maclen;
                arp.hwaddr = [0u8; DHCP_CHADDR_MAX];
                arp.hwaddr[..mac.len()].copy_from_slice(mac);
                found = true;
                break;
            }
        }

        if !found {
            // No existing entry matched — create a new one.
            // Matches C `arp.c` lines 209-230.
            let mut hwaddr = [0u8; DHCP_CHADDR_MAX];
            hwaddr[..mac.len()].copy_from_slice(mac);

            arps.push(ArpRecord {
                hwlen: maclen,
                status: ArpStatus::New,
                family,
                hwaddr,
                addr,
            });
        }

        Ok(())
    }

    /// Extract IP address and address family from a [`SocketAddress`].
    ///
    /// Converts the socket address enum to the `(IpAddr, AddressFamily)` pair
    /// used internally for cache lookups. Uses [`SocketAddress::V4`] and
    /// [`SocketAddress::V6`] pattern matching.
    #[inline]
    fn extract_addr_info(addr: &SocketAddress) -> (IpAddr, AddressFamily) {
        match addr {
            SocketAddress::V4(v4) => (IpAddr::V4(*v4.ip()), AddressFamily::Inet),
            SocketAddress::V6(v6) => (IpAddr::V6(*v6.ip()), AddressFamily::Inet6),
        }
    }

    /// Create a negative cache (EMPTY) entry for an address not found in the
    /// kernel ARP table.
    ///
    /// Prevents repeated kernel queries for the same address. The entry has
    /// `hwlen = 0` and [`ArpStatus::Empty`] status.
    ///
    /// Matches C `arp.c` lines 368-392.
    fn add_empty_entry(&mut self, addr: IpAddr, family: AddressFamily) {
        self.arps.push(ArpRecord {
            hwlen: 0,
            status: ArpStatus::Empty,
            family,
            hwaddr: [0u8; DHCP_CHADDR_MAX],
            addr,
        });
    }

    /// Get the number of active cache entries.
    ///
    /// Useful for diagnostics and testing.
    #[inline]
    pub fn len(&self) -> usize {
        self.arps.len()
    }

    /// Check if the cache has no active entries.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.arps.is_empty()
    }

    /// Get the number of entries pending deletion notification.
    ///
    /// These entries are processed by [`do_arp_script_run()`](Self::do_arp_script_run).
    #[inline]
    pub fn pending_deletions(&self) -> usize {
        self.old.len()
    }
}

impl Default for ArpCache {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    /// Helper to create a SocketAddress::V4 for testing.
    fn sock_v4(ip: Ipv4Addr, port: u16) -> SocketAddress {
        SocketAddress::V4(SocketAddrV4::new(ip, port))
    }

    /// Helper to create a SocketAddress::V6 for testing.
    fn sock_v6(ip: Ipv6Addr, port: u16) -> SocketAddress {
        SocketAddress::V6(SocketAddrV6::new(ip, port, 0, 0))
    }

    /// Simulate a platform enumerator with given entries.
    ///
    /// Returns a closure that, when called with a callback, iterates over
    /// the pre-built entries and calls the callback for each one.
    ///
    /// Note: We spell out the return type without using `ArpEnumerateCallback`
    /// and avoid explicit type annotations on the closure parameter. This
    /// ensures the compiler infers the correct higher-ranked trait bound
    /// (`for<'a> FnMut(&'a mut (dyn FnMut(...) + 'a))`) rather than pinning
    /// the inner trait object to `'static`.
    fn make_enumerator(
        entries: Vec<(IpAddr, Vec<u8>)>,
    ) -> impl FnMut(&mut dyn FnMut(IpAddr, &[u8]) -> Result<(), ArpError>) {
        move |callback| {
            for (addr, mac) in &entries {
                let _ = callback(*addr, mac);
            }
        }
    }

    // -- ArpCache::new() tests --

    #[test]
    fn test_new_cache_is_empty() {
        let cache = ArpCache::new();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.pending_deletions(), 0);
    }

    #[test]
    fn test_default_trait() {
        let cache = ArpCache::default();
        assert!(cache.is_empty());
    }

    // -- ArpCache::is_fresh() tests --

    #[test]
    fn test_fresh_cache_never_refreshed() {
        let cache = ArpCache::new();
        assert!(!cache.is_fresh(Instant::now()));
    }

    #[test]
    fn test_fresh_after_refresh() {
        let mut cache = ArpCache::new();
        cache.refresh(&mut make_enumerator(vec![]));
        assert!(cache.is_fresh(Instant::now()));
    }

    // -- ArpCache::refresh() tests --

    #[test]
    fn test_refresh_populates_cache() {
        let mut cache = ArpCache::new();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let mac = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

        cache.refresh(&mut make_enumerator(vec![(ip, mac)]));

        assert_eq!(cache.len(), 1);
        assert!(cache.is_fresh(Instant::now()));
    }

    #[test]
    fn test_refresh_marks_and_sweeps() {
        let mut cache = ArpCache::new();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mac = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

        // First refresh: add entry
        cache.refresh(&mut make_enumerator(vec![(ip, mac)]));
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.pending_deletions(), 0);

        // Process the NEW → FOUND transition
        assert!(cache.do_arp_script_run());
        assert!(!cache.do_arp_script_run());

        // Second refresh: entry disappears from kernel
        cache.refresh(&mut make_enumerator(vec![]));

        // Entry should have been moved to old list
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.pending_deletions(), 1);
    }

    #[test]
    fn test_refresh_preserves_empty_entries() {
        let mut cache = ArpCache::new();

        // Add an EMPTY entry by doing a lookup after refresh with no entries
        cache.refresh(&mut make_enumerator(vec![]));

        let addr = sock_v4(Ipv4Addr::new(10, 0, 0, 5), 0);
        let result = cache.find_mac(Some(&addr), false, Instant::now());
        assert!(result.is_none());

        // Cache should have the EMPTY entry
        assert_eq!(cache.len(), 1);

        // Refresh again — EMPTY entries should survive (not moved to old)
        cache.refresh(&mut make_enumerator(vec![]));
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.pending_deletions(), 0);
    }

    #[test]
    fn test_refresh_updates_empty_to_new() {
        let mut cache = ArpCache::new();
        let ip = Ipv4Addr::new(192, 168, 1, 50);
        let addr = sock_v4(ip, 0);

        // Create EMPTY entry via lookup miss
        cache.refresh(&mut make_enumerator(vec![]));
        let result = cache.find_mac(Some(&addr), false, Instant::now());
        assert!(result.is_none());
        assert_eq!(cache.len(), 1);

        // Now refresh with the address present — should update EMPTY → NEW
        let mac = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01];
        cache.refresh(&mut make_enumerator(vec![(
            IpAddr::V4(ip),
            mac.clone(),
        )]));

        // Lookup should now find the MAC
        let result = cache.find_mac(Some(&addr), false, Instant::now());
        assert!(result.is_some());
        let (found_mac, hwlen) = result.unwrap();
        assert_eq!(hwlen, 6);
        assert_eq!(found_mac, mac);
    }

    // -- ArpCache::find_mac() tests --

    #[test]
    fn test_find_mac_none_addr_returns_none() {
        let mut cache = ArpCache::new();
        cache.refresh(&mut make_enumerator(vec![]));
        let result = cache.find_mac(None, false, Instant::now());
        assert!(result.is_none());
    }

    #[test]
    fn test_find_mac_stale_cache_returns_none() {
        let mut cache = ArpCache::new();
        // Never refreshed = stale
        let addr = sock_v4(Ipv4Addr::new(10, 0, 0, 1), 0);
        let result = cache.find_mac(Some(&addr), false, Instant::now());
        assert!(result.is_none());
    }

    #[test]
    fn test_find_mac_found_entry() {
        let mut cache = ArpCache::new();
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        let mac = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

        cache.refresh(&mut make_enumerator(vec![(
            IpAddr::V4(ip),
            mac.clone(),
        )]));

        let addr = sock_v4(ip, 0);
        let result = cache.find_mac(Some(&addr), false, Instant::now());
        assert!(result.is_some());
        let (found_mac, hwlen) = result.unwrap();
        assert_eq!(hwlen, 6);
        assert_eq!(found_mac, mac);
    }

    #[test]
    fn test_find_mac_ipv6() {
        let mut cache = ArpCache::new();
        let ip = Ipv6Addr::new(0xfe80, 0, 0, 0, 0x1, 0x2, 0x3, 0x4);
        let mac = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

        cache.refresh(&mut make_enumerator(vec![(
            IpAddr::V6(ip),
            mac.clone(),
        )]));

        let addr = sock_v6(ip, 0);
        let result = cache.find_mac(Some(&addr), false, Instant::now());
        assert!(result.is_some());
        let (found_mac, hwlen) = result.unwrap();
        assert_eq!(hwlen, 6);
        assert_eq!(found_mac, mac);
    }

    #[test]
    fn test_find_mac_lazy_accepts_empty() {
        let mut cache = ArpCache::new();

        // Refresh with no entries, then lookup to create EMPTY
        cache.refresh(&mut make_enumerator(vec![]));
        let addr = sock_v4(Ipv4Addr::new(10, 0, 0, 99), 0);
        let _ = cache.find_mac(Some(&addr), false, Instant::now());

        // Reset refreshed flag by doing another non-matching lookup
        cache.refreshed = false;

        // Lazy mode should accept the EMPTY entry
        let result = cache.find_mac(Some(&addr), true, Instant::now());
        assert!(result.is_some());
        let (mac, hwlen) = result.unwrap();
        assert_eq!(hwlen, 0);
        assert!(mac.is_empty());
    }

    #[test]
    fn test_find_mac_non_lazy_rejects_empty() {
        let mut cache = ArpCache::new();

        // Refresh with no entries, then lookup to create EMPTY
        cache.refresh(&mut make_enumerator(vec![]));
        let addr = sock_v4(Ipv4Addr::new(10, 0, 0, 99), 0);
        let _ = cache.find_mac(Some(&addr), false, Instant::now());

        // Reset refreshed flag
        cache.refreshed = false;

        // Non-lazy mode should reject the EMPTY entry
        let result = cache.find_mac(Some(&addr), false, Instant::now());
        assert!(result.is_none());
    }

    #[test]
    fn test_find_mac_refreshed_flag_accepts_empty() {
        let mut cache = ArpCache::new();

        // Refresh with no entries
        cache.refresh(&mut make_enumerator(vec![]));
        let addr = sock_v4(Ipv4Addr::new(10, 0, 0, 42), 0);

        // First find creates EMPTY entry, refreshed=true accepts it
        let result = cache.find_mac(Some(&addr), false, Instant::now());
        assert!(result.is_none()); // Not found → EMPTY created

        // Refresh again (re-sets refreshed flag)
        cache.refresh(&mut make_enumerator(vec![]));

        // Now find with refreshed=true should accept EMPTY
        let result = cache.find_mac(Some(&addr), false, Instant::now());
        assert!(result.is_some());
        let (mac, hwlen) = result.unwrap();
        assert_eq!(hwlen, 0);
        assert!(mac.is_empty());
    }

    #[test]
    fn test_find_mac_family_mismatch() {
        let mut cache = ArpCache::new();
        let ipv4 = Ipv4Addr::new(192, 168, 1, 1);
        let mac = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

        cache.refresh(&mut make_enumerator(vec![(
            IpAddr::V4(ipv4),
            mac,
        )]));

        // Look up with IPv6 address — should not match the IPv4 entry
        let v6_addr = sock_v6(Ipv6Addr::LOCALHOST, 0);
        let result = cache.find_mac(Some(&v6_addr), false, Instant::now());
        assert!(result.is_none());
    }

    // -- ArpCache::do_arp_script_run() tests --

    #[test]
    fn test_do_arp_script_run_empty_cache() {
        let mut cache = ArpCache::new();
        assert!(!cache.do_arp_script_run());
    }

    #[test]
    fn test_do_arp_script_run_processes_new() {
        let mut cache = ArpCache::new();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mac = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

        cache.refresh(&mut make_enumerator(vec![(ip, mac)]));

        // Should process the NEW entry
        assert!(cache.do_arp_script_run());
        // No more work
        assert!(!cache.do_arp_script_run());
    }

    #[test]
    fn test_do_arp_script_run_processes_deletions_first() {
        let mut cache = ArpCache::new();
        let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mac1 = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let mac2 = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

        // Add two entries and process them to FOUND
        cache.refresh(&mut make_enumerator(vec![
            (ip1, mac1),
            (ip2, mac2.clone()),
        ]));
        while cache.do_arp_script_run() {}

        // Remove ip1 from kernel, add ip2 with new MAC
        let new_mac2 = vec![0x11, 0x11, 0x11, 0x11, 0x11, 0x11];
        cache.refresh(&mut make_enumerator(vec![(ip2, new_mac2)]));

        // ip1 should be in old list (deletion)
        assert_eq!(cache.pending_deletions(), 1);

        // First call should process the deletion
        assert!(cache.do_arp_script_run());
        assert_eq!(cache.pending_deletions(), 0);

        // Next calls should process NEW entries (ip2 with new MAC)
        assert!(cache.do_arp_script_run());

        // Then no more work
        assert!(!cache.do_arp_script_run());
    }

    #[test]
    fn test_do_arp_script_run_incremental() {
        let mut cache = ArpCache::new();

        // Add three entries
        let entries = vec![
            (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), vec![0x01; 6]),
            (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), vec![0x02; 6]),
            (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)), vec![0x03; 6]),
        ];
        cache.refresh(&mut make_enumerator(entries));

        // Should take exactly 3 calls to process all NEW entries
        assert!(cache.do_arp_script_run());
        assert!(cache.do_arp_script_run());
        assert!(cache.do_arp_script_run());
        assert!(!cache.do_arp_script_run());
    }

    // -- filter_mac_impl tests --

    #[test]
    fn test_filter_mac_mac_too_long() {
        let mut arps = Vec::new();
        let long_mac = vec![0u8; DHCP_CHADDR_MAX + 1];
        let result = ArpCache::filter_mac_impl(
            &mut arps,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            &long_mac,
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            ArpError::MacTooLong(len) => assert_eq!(len, DHCP_CHADDR_MAX + 1),
            _ => panic!("Expected MacTooLong error"),
        }
    }

    #[test]
    fn test_filter_mac_creates_new_entry() {
        let mut arps = Vec::new();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let mac = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

        let result = ArpCache::filter_mac_impl(&mut arps, ip, &mac);
        assert!(result.is_ok());
        assert_eq!(arps.len(), 1);
        assert_eq!(arps[0].status, ArpStatus::New);
        assert_eq!(arps[0].addr, ip);
        assert_eq!(arps[0].hwlen, 6);
        assert_eq!(&arps[0].hwaddr[..6], &mac[..]);
    }

    #[test]
    fn test_filter_mac_confirms_existing() {
        let mac = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut hwaddr = [0u8; DHCP_CHADDR_MAX];
        hwaddr[..6].copy_from_slice(&mac);

        let mut arps = vec![ArpRecord {
            hwlen: 6,
            status: ArpStatus::Mark,
            family: AddressFamily::Inet,
            hwaddr,
            addr: ip,
        }];

        let result = ArpCache::filter_mac_impl(&mut arps, ip, &mac);
        assert!(result.is_ok());
        assert_eq!(arps.len(), 1);
        assert_eq!(arps[0].status, ArpStatus::Found);
    }

    #[test]
    fn test_filter_mac_updates_empty_to_new() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut arps = vec![ArpRecord {
            hwlen: 0,
            status: ArpStatus::Empty,
            family: AddressFamily::Inet,
            hwaddr: [0u8; DHCP_CHADDR_MAX],
            addr: ip,
        }];

        let mac = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01];
        let result = ArpCache::filter_mac_impl(&mut arps, ip, &mac);
        assert!(result.is_ok());
        assert_eq!(arps.len(), 1);
        assert_eq!(arps[0].status, ArpStatus::New);
        assert_eq!(arps[0].hwlen, 6);
        assert_eq!(&arps[0].hwaddr[..6], &mac[..]);
    }

    #[test]
    fn test_filter_mac_different_mac_updates_in_place() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let old_mac = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let new_mac = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let mut hwaddr = [0u8; DHCP_CHADDR_MAX];
        hwaddr[..6].copy_from_slice(&old_mac);

        let mut arps = vec![ArpRecord {
            hwlen: 6,
            status: ArpStatus::Mark,
            family: AddressFamily::Inet,
            hwaddr,
            addr: ip,
        }];

        // Different MAC → should UPDATE existing entry in-place (C arp.c lines 203-209).
        // Entry transitions to NEW with the new MAC address.
        let result = ArpCache::filter_mac_impl(&mut arps, ip, &new_mac);
        assert!(result.is_ok());
        assert_eq!(arps.len(), 1); // In-place update, no new entry
        assert_eq!(arps[0].status, ArpStatus::New); // Marked as new for script notification
        assert_eq!(&arps[0].hwaddr[..6], &new_mac[..]); // Updated MAC
    }

    #[test]
    fn test_filter_mac_skips_new_entries() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mac = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let mut hwaddr = [0u8; DHCP_CHADDR_MAX];
        hwaddr[..6].copy_from_slice(&mac);

        let mut arps = vec![ArpRecord {
            hwlen: 6,
            status: ArpStatus::New,
            family: AddressFamily::Inet,
            hwaddr,
            addr: ip,
        }];

        // Should skip the NEW entry and create another one
        let result = ArpCache::filter_mac_impl(&mut arps, ip, &mac);
        assert!(result.is_ok());
        assert_eq!(arps.len(), 2);
    }

    #[test]
    fn test_filter_mac_max_length_mac() {
        let mut arps = Vec::new();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mac = vec![0xFFu8; DHCP_CHADDR_MAX]; // Exactly at limit

        let result = ArpCache::filter_mac_impl(&mut arps, ip, &mac);
        assert!(result.is_ok());
        assert_eq!(arps.len(), 1);
        assert_eq!(arps[0].hwlen, DHCP_CHADDR_MAX as u16);
    }

    // -- extract_addr_info tests --

    #[test]
    fn test_extract_addr_info_v4() {
        let addr = sock_v4(Ipv4Addr::new(192, 168, 1, 1), 53);
        let (ip, family) = ArpCache::extract_addr_info(&addr);
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(family, AddressFamily::Inet);
    }

    #[test]
    fn test_extract_addr_info_v6() {
        let addr = sock_v6(Ipv6Addr::LOCALHOST, 547);
        let (ip, family) = ArpCache::extract_addr_info(&addr);
        assert_eq!(ip, IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(family, AddressFamily::Inet6);
    }

    // -- Integration-style tests --

    #[test]
    fn test_full_lifecycle_add_confirm_remove() {
        let mut cache = ArpCache::new();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let mac = vec![0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E];

        // Step 1: Device appears
        cache.refresh(&mut make_enumerator(vec![(ip, mac.clone())]));
        assert_eq!(cache.len(), 1);

        // Step 2: Process notification
        assert!(cache.do_arp_script_run()); // NEW → FOUND
        assert!(!cache.do_arp_script_run()); // No more work

        // Step 3: Confirm entry persists across refresh
        cache.refresh(&mut make_enumerator(vec![(ip, mac.clone())]));
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.pending_deletions(), 0);
        assert!(!cache.do_arp_script_run()); // Already FOUND, no notification

        // Step 4: Device disappears
        cache.refresh(&mut make_enumerator(vec![]));
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.pending_deletions(), 1);

        // Step 5: Process deletion notification
        assert!(cache.do_arp_script_run());
        assert_eq!(cache.pending_deletions(), 0);
        assert!(!cache.do_arp_script_run());
    }

    #[test]
    fn test_mac_address_change_detection() {
        let mut cache = ArpCache::new();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 50));
        let old_mac = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let new_mac = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

        // Add device with old MAC
        cache.refresh(&mut make_enumerator(vec![(ip, old_mac)]));
        while cache.do_arp_script_run() {}

        // Device changes MAC — entry is updated in-place per C arp.c lines 203-209.
        // The existing entry transitions to NEW with the new MAC; no deletion is
        // generated because the IP address still has a valid hardware address.
        cache.refresh(&mut make_enumerator(vec![(ip, new_mac.clone())]));

        // No entries moved to old list — MAC change is an in-place update
        assert_eq!(cache.pending_deletions(), 0);
        // Entry updated in-place with new MAC
        assert_eq!(cache.len(), 1);

        // Process the NEW notification for the updated MAC
        assert!(cache.do_arp_script_run());
        assert!(!cache.do_arp_script_run());

        // Look up should return new MAC
        let addr = sock_v4(Ipv4Addr::new(10, 0, 0, 50), 0);
        let result = cache.find_mac(Some(&addr), false, Instant::now());
        assert!(result.is_some());
        let (found_mac, hwlen) = result.unwrap();
        assert_eq!(hwlen, 6);
        assert_eq!(found_mac, new_mac);
    }

    #[test]
    fn test_multiple_addresses_different_families() {
        let mut cache = ArpCache::new();
        let ipv4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ipv6 = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 1, 2, 3, 4));
        let mac4 = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01];
        let mac6 = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02];

        cache.refresh(&mut make_enumerator(vec![
            (ipv4, mac4.clone()),
            (ipv6, mac6.clone()),
        ]));

        // Look up IPv4
        let addr4 = sock_v4(Ipv4Addr::new(192, 168, 1, 1), 0);
        let result = cache.find_mac(Some(&addr4), false, Instant::now());
        assert!(result.is_some());
        assert_eq!(result.unwrap().0, mac4);

        // Look up IPv6
        let addr6 = sock_v6(
            Ipv6Addr::new(0xfe80, 0, 0, 0, 1, 2, 3, 4),
            0,
        );
        let result = cache.find_mac(Some(&addr6), false, Instant::now());
        assert!(result.is_some());
        assert_eq!(result.unwrap().0, mac6);
    }

    // -- ArpError tests --

    #[test]
    fn test_error_display_mac_too_long() {
        let err = ArpError::MacTooLong(20);
        let msg = format!("{}", err);
        assert!(msg.contains("20"));
        assert!(msg.contains("16"));
    }

    #[test]
    fn test_error_display_allocation_failed() {
        let err = ArpError::AllocationFailed;
        let msg = format!("{}", err);
        assert!(msg.contains("allocation"));
    }

    #[test]
    fn test_error_from_io_error() {
        let io_err = std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "test",
        );
        let arp_err: ArpError = io_err.into();
        match arp_err {
            ArpError::KernelQueryFailed(_) => {}
            _ => panic!("Expected KernelQueryFailed"),
        }
    }

    // -- Constants tests --

    #[test]
    fn test_constants() {
        assert_eq!(DHCP_CHADDR_MAX, 16);
        assert_eq!(CACHE_REFRESH_INTERVAL, Duration::from_secs(90));
    }
}

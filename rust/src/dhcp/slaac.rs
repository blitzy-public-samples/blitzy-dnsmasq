// dnsmasq is Copyright (c) 2000-2025 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! # SLAAC Address Tracking
//!
//! Implements Stateless Address Autoconfiguration (SLAAC) address confirmation
//! for IPv6 clients. Replaces C's `src/slaac.c` (537 lines).
//!
//! When dnsmasq operates in RA-names mode (`CONTEXT_RA_NAME`), it derives SLAAC
//! addresses from DHCPv4 lease MAC addresses using EUI-64 conversion (RFC 4291
//! Appendix A), then confirms address occupancy via ICMPv6 echo requests before
//! registering in DNS. This enables automatic AAAA record creation for SLAAC hosts.
//!
//! ## Module Design
//!
//! This module is pure data-manipulation and packet-construction logic. Actual
//! ICMPv6 socket I/O is delegated to the caller (typically the network/radv module),
//! following the "no unsafe" principle. `periodic_slaac` returns a list of
//! [`PendingPing`] descriptors which the caller sends via the ICMPv6 raw socket.
//!
//! ## C Source Mapping
//!
//! | Rust Function | C Function | C Line | Description |
//! |--------------|------------|--------|-------------|
//! | [`slaac_add_addrs`] | `slaac_add_addrs()` | 163 | EUI-64 derivation + RA prefix |
//! | [`periodic_slaac`] | `periodic_slaac()` | 345 | Prepare pings for unconfirmed addresses |
//! | [`slaac_ping_reply`] | `slaac_ping_reply()` | 515 | Process ICMPv6 echo reply |
//! | [`mac_to_eui64`] | (inline in slaac_add_addrs) | 200-250 | EUI-64 address derivation |

// ============================================================================
// Standard library imports
// ============================================================================
use std::net::Ipv6Addr;
use std::sync::atomic::{AtomicU16, Ordering};

// ============================================================================
// External crate imports
// ============================================================================
use tracing::{debug, info};

// ============================================================================
// Internal crate imports (from depends_on_files only)
// ============================================================================
use crate::config::constants::{ARPHRD_ETHER, ARPHRD_EUI64, ARPHRD_IEEE1394, ARPHRD_IEEE802};
use crate::core::types::{opt, OptionFlags};
use crate::core::util::SurfRng;
use crate::dhcp::common::{DhcpContext, CONTEXT_OLD, CONTEXT_RA_NAME};

// ============================================================================
// Constants
// ============================================================================

/// Lease flag: Non-temporary address (IA_NA).
/// From C `dnsmasq.h` line 1024: `#define LEASE_NA 32`.
pub const LEASE_NA: u32 = 32;

/// Lease flag: Temporary address (IA_TA).
/// From C `dnsmasq.h` line 1025: `#define LEASE_TA 64`.
pub const LEASE_TA: u32 = 64;

/// Lease flag: Hardware address is available.
/// From C `dnsmasq.h` line 1026: `#define LEASE_HAVE_HWADDR 128`.
pub const LEASE_HAVE_HWADDR: u32 = 128;

/// ICMPv6 Echo Request type code.
/// From C `radv-protocol.h`: `ICMP6_ECHO_REQUEST = 128`.
const ICMP6_ECHO_REQUEST: u8 = 128;

/// Maximum backoff exponent before abandoning a SLAAC address.
/// After 12 doublings (2^12 = 4096 seconds ≈ 68 minutes total elapsed),
/// the address is considered unreachable and ping_time is set to 0.
/// Matches C `slaac.c` line ~460: `if (slaac->backoff >= 12)`.
const MAX_BACKOFF: i32 = 12;

/// Module-level ICMPv6 echo request identifier.
/// Initialized once via `SurfRng::rand16()` on first call to `periodic_slaac`.
/// Replaces C static variable `ping_id` in `slaac.c` line 361.
static PING_ID: AtomicU16 = AtomicU16::new(0);

// ============================================================================
// Data Structures
// ============================================================================

/// SLAAC address tracking record.
///
/// Replaces C `struct slaac_address` (`dnsmasq.h` line 1058).
/// Tracks IPv6 addresses derived from MAC+prefix that need confirmation
/// via ICMPv6 ping before DNS registration.
///
/// In C, these form a linked list (`next` pointer) attached to each
/// `struct dhcp_lease`. In Rust, they are stored as `Vec<SlaacAddress>`
/// within [`SlaacLeaseInfo`].
#[derive(Debug, Clone)]
pub struct SlaacAddress {
    /// Derived SLAAC IPv6 address (prefix + EUI-64 interface identifier).
    pub addr: Ipv6Addr,
    /// Timestamp of next scheduled ICMPv6 echo request (Unix epoch seconds).
    /// 0 means the address has been abandoned (unreachable after MAX_BACKOFF retries).
    pub ping_time: i64,
    /// Backoff counter for exponential retry:
    /// - 0 = address confirmed (ICMPv6 echo reply received)
    /// - 1..MAX_BACKOFF = pending confirmation, doubles on each send
    /// - >= MAX_BACKOFF = will be abandoned on next periodic_slaac invocation
    pub backoff: i32,
}

/// Lease data needed for SLAAC address tracking operations.
///
/// This struct contains the subset of DHCP lease fields required by the SLAAC
/// module. It serves as a data contract between the lease management module
/// (`lease.rs`) and SLAAC operations, avoiding circular dependencies.
///
/// The lease module constructs `SlaacLeaseInfo` from its `DhcpLease` struct
/// when calling SLAAC functions.
///
/// Maps to fields from C `struct dhcp_lease` (`dnsmasq.h` line 1035).
#[derive(Debug, Clone)]
pub struct SlaacLeaseInfo {
    /// Hardware (MAC) address bytes.
    /// From C `lease->hwaddr[DHCP_CHADDR_MAX]`.
    pub hwaddr: Vec<u8>,
    /// Hardware address type (e.g., ARPHRD_ETHER=1 for Ethernet).
    /// From C `lease->hwaddr_type`.
    pub hwaddr_type: u16,
    /// Length of hardware address in bytes.
    /// From C `lease->hwaddr_len`.
    pub hwaddr_len: usize,
    /// Network interface index where lease was granted.
    /// From C `lease->last_interface`.
    pub last_interface: i32,
    /// Client hostname (None if not set).
    /// From C `lease->hostname`.
    pub hostname: Option<String>,
    /// Lease flags (LEASE_HAVE_HWADDR, LEASE_TA, LEASE_NA, etc.).
    /// From C `lease->flags`.
    pub flags: u32,
    /// SLAAC addresses associated with this lease.
    /// Replaces C linked list `lease->slaac_address`.
    pub slaac_addresses: Vec<SlaacAddress>,
    /// Client identifier (for ARPHRD_IEEE1394 FireWire EUI-64 extraction).
    /// From C `lease->clid` and `lease->clid_len`.
    pub clid: Option<Vec<u8>>,
}

/// Descriptor for an ICMPv6 echo request that needs to be sent.
///
/// Produced by [`periodic_slaac`] and consumed by the caller which handles
/// actual socket I/O via the network module's ICMPv6 raw socket.
/// This separation ensures zero `unsafe` blocks in the SLAAC module.
#[derive(Debug, Clone)]
pub struct PendingPing {
    /// Target IPv6 address for the echo request.
    pub target: Ipv6Addr,
    /// Constructed ICMPv6 echo request packet (8 bytes).
    /// Layout: [type(1), code(1), checksum(2), identifier(2), sequence_no(2)].
    /// The kernel computes the checksum when sent on a raw ICMPv6 socket.
    pub packet: [u8; 8],
    /// Lease index in the caller's lease array, for error callback.
    pub lease_index: usize,
    /// SLAAC address index within the lease's slaac_addresses Vec.
    pub addr_index: usize,
}

/// Result of a `periodic_slaac` invocation.
#[derive(Debug)]
pub struct PeriodicSlaacResult {
    /// Time of next required invocation (Unix epoch seconds).
    /// 0 if no pending addresses remain.
    pub next_event: i64,
    /// List of ICMPv6 echo requests to send.
    pub pending_pings: Vec<PendingPing>,
}

// ============================================================================
// EUI-64 Address Derivation
// ============================================================================

/// Convert a 48-bit Ethernet MAC address to a full IPv6 address by combining
/// a /64 prefix with an EUI-64 interface identifier.
///
/// Per RFC 4291 Appendix A:
/// 1. Split the 6-byte MAC into two halves: `[M0, M1, M2]` and `[M3, M4, M5]`
/// 2. Insert `0xFF, 0xFE` between them: `[M0, M1, M2, 0xFF, 0xFE, M3, M4, M5]`
/// 3. Invert the universal/local (U/L) bit — bit 6 of the first octet (`M0 ^ 0x02`)
/// 4. Combine with the provided /64 prefix (upper 8 bytes from `prefix`)
///
/// # Arguments
/// * `mac` — 6-byte Ethernet MAC address (e.g., from DHCP lease hardware address)
/// * `prefix` — IPv6 /64 network prefix from Router Advertisement context
///
/// # Returns
/// Full 128-bit IPv6 address combining prefix + EUI-64 interface identifier.
///
/// # Examples
/// ```
/// use std::net::Ipv6Addr;
/// # use dnsmasq::dhcp::slaac::mac_to_eui64;
/// let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
/// let prefix: Ipv6Addr = "2001:db8::".parse().unwrap();
/// let result = mac_to_eui64(&mac, &prefix);
/// assert_eq!(result, "2001:db8::211:22ff:fe33:4455".parse::<Ipv6Addr>().unwrap());
/// ```
///
/// Replaces inline EUI-64 conversion in C `slaac.c` lines 200–250.
pub fn mac_to_eui64(mac: &[u8; 6], prefix: &Ipv6Addr) -> Ipv6Addr {
    let prefix_octets = prefix.octets();
    let mut addr = [0u8; 16];

    // Copy upper 8 bytes from the /64 prefix.
    // C: memcpy(&addr.s6_addr[0], &context->start6.s6_addr[0], 8);
    addr[..8].copy_from_slice(&prefix_octets[..8]);

    // Build EUI-64 interface identifier from 48-bit MAC.
    // C: memcpy(&addr.s6_addr[8], lease->hwaddr, 3);
    addr[8] = mac[0];
    addr[9] = mac[1];
    addr[10] = mac[2];

    // C: addr.s6_addr[11] = 0xff; addr.s6_addr[12] = 0xfe;
    addr[11] = 0xFF;
    addr[12] = 0xFE;

    // C: memcpy(&addr.s6_addr[13], &lease->hwaddr[3], 3);
    addr[13] = mac[3];
    addr[14] = mac[4];
    addr[15] = mac[5];

    // Invert the universal/local bit (bit 6 of the first octet).
    // C: addr.s6_addr[8] ^= 0x02;
    addr[8] ^= 0x02;

    Ipv6Addr::from(addr)
}

/// Derive a SLAAC IPv6 address from lease hardware information and a /64 prefix.
///
/// Handles multiple hardware types per C `slaac.c` lines 185–250:
/// - `ARPHRD_ETHER` (1) / `ARPHRD_IEEE802` (6): 48-bit MAC → EUI-64 (standard path)
/// - `ARPHRD_EUI64` (27): 64-bit identifier copied directly
/// - `ARPHRD_IEEE1394` (24): FireWire EUI-64 extracted from client ID bytes [1..9]
///
/// Returns `None` if the hardware type is unsupported or data is insufficient.
fn derive_slaac_address(lease: &SlaacLeaseInfo, prefix: &Ipv6Addr) -> Option<Ipv6Addr> {
    let prefix_octets = prefix.octets();
    let mut addr = [0u8; 16];

    // Copy upper 8 bytes from the /64 prefix.
    addr[..8].copy_from_slice(&prefix_octets[..8]);

    if lease.hwaddr_type == ARPHRD_ETHER || lease.hwaddr_type == ARPHRD_IEEE802 {
        // Ethernet / IEEE 802: requires exactly 6-byte MAC.
        // C: slaac.c line 185: if (lease->hwaddr_len != 6) continue;
        if lease.hwaddr_len != 6 || lease.hwaddr.len() < 6 {
            return None;
        }
        // Standard EUI-64 conversion from 48-bit MAC.
        addr[8] = lease.hwaddr[0];
        addr[9] = lease.hwaddr[1];
        addr[10] = lease.hwaddr[2];
        addr[11] = 0xFF;
        addr[12] = 0xFE;
        addr[13] = lease.hwaddr[3];
        addr[14] = lease.hwaddr[4];
        addr[15] = lease.hwaddr[5];
        // Invert universal/local bit (bit 6).
        addr[8] ^= 0x02;
    } else if lease.hwaddr_type == ARPHRD_EUI64 {
        // EUI-64: requires exactly 8-byte identifier, copied directly.
        // C: slaac.c line 195: if (lease->hwaddr_len != 8) continue;
        if lease.hwaddr_len != 8 || lease.hwaddr.len() < 8 {
            return None;
        }
        addr[8..16].copy_from_slice(&lease.hwaddr[..8]);
    } else if lease.hwaddr_type == ARPHRD_IEEE1394 {
        // FireWire: EUI-64 in client ID bytes [1..9].
        // C: slaac.c line 201: if (!lease->clid || lease->clid_len < 9) continue;
        let clid = lease.clid.as_ref()?;
        if clid.len() < 9 {
            return None;
        }
        addr[8..16].copy_from_slice(&clid[1..9]);
    } else {
        // Unsupported hardware type — skip.
        // C: slaac.c line ~210: else continue;
        return None;
    }

    Some(Ipv6Addr::from(addr))
}

// ============================================================================
// Core SLAAC Functions
// ============================================================================

/// Derive SLAAC addresses from a DHCP lease's MAC address and Router
/// Advertisement prefixes.
///
/// For each DHCPv6 context with `CONTEXT_RA_NAME` flag set (and not
/// `CONTEXT_OLD`) whose `if_index` matches the lease's `last_interface`,
/// compute the SLAAC address by combining the context's /64 prefix with
/// the lease's EUI-64 interface identifier. New addresses are added to
/// `lease.slaac_addresses` with `backoff=1` to trigger an immediate
/// ICMPv6 ping on the next `periodic_slaac` call.
///
/// # Arguments
/// * `lease` — Mutable lease info; `slaac_addresses` may be appended to
/// * `contexts` — DHCPv6 context list (from `DaemonState.dhcp6_contexts`)
/// * `now` — Current time (Unix epoch seconds)
/// * `force` — If `true`, reset existing addresses' backoff to 1 (re-ping)
///
/// # Returns
/// `true` if any new SLAAC addresses were added (caller should trigger
/// unsolicited RA via `ra_start_unsolicited`), `false` otherwise.
///
/// Replaces C `slaac_add_addrs()` (`slaac.c` lines 163–340).
pub fn slaac_add_addrs(
    lease: &mut SlaacLeaseInfo,
    contexts: &[DhcpContext],
    now: i64,
    force: bool,
) -> bool {
    // Precondition checks matching C slaac.c lines 167–175:
    // Must have hardware address, not be TA/NA, interface must be set, hostname required.
    if lease.flags & LEASE_HAVE_HWADDR == 0 {
        return false;
    }
    if lease.flags & (LEASE_TA | LEASE_NA) != 0 {
        return false;
    }
    if lease.last_interface == 0 {
        return false;
    }
    if lease.hostname.is_none() {
        return false;
    }

    let mut added_any = false;

    // Iterate DHCPv6 contexts looking for RA_NAME prefixes.
    // C: for (context = daemon->dhcp6; context; context = context->next)
    for context in contexts.iter() {
        // Skip contexts without RA_NAME flag or with OLD flag.
        // C: if (!(context->flags & CONTEXT_RA_NAME) || (context->flags & CONTEXT_OLD))
        if context.flags & CONTEXT_RA_NAME == 0 {
            continue;
        }
        if context.flags & CONTEXT_OLD != 0 {
            continue;
        }

        // Match interface index.
        // C: if (context->if_index != lease->last_interface) continue;
        #[cfg(feature = "dhcp6")]
        {
            if context.if_index != lease.last_interface {
                continue;
            }
        }
        #[cfg(not(feature = "dhcp6"))]
        {
            continue;
        }

        // Derive SLAAC address from the lease's hardware address and context prefix.
        #[cfg(feature = "dhcp6")]
        let derived_addr = derive_slaac_address(lease, &context.start6);
        #[cfg(not(feature = "dhcp6"))]
        let derived_addr: Option<Ipv6Addr> = None;

        let addr = match derived_addr {
            Some(a) => a,
            None => continue,
        };

        // Check if this address is already tracked.
        // C: for (slaac = lease->slaac_address; slaac; slaac = slaac->next)
        let existing = lease.slaac_addresses.iter_mut().find(|sa| sa.addr == addr);

        if let Some(existing_addr) = existing {
            // Address already tracked. If force is set, reset backoff to re-ping.
            // C: if (force) { slaac->backoff = 1; slaac->ping_time = now; }
            if force {
                existing_addr.backoff = 1;
                existing_addr.ping_time = now;
                debug!(
                    addr = %addr,
                    hostname = lease.hostname.as_deref().unwrap_or("?"),
                    "SLAAC address re-queued for confirmation (force)"
                );
            }
        } else {
            // New SLAAC address — add to tracking list.
            // C: slaac = whine_malloc(sizeof(struct slaac_address));
            let new_addr = SlaacAddress {
                addr,
                ping_time: now,
                backoff: 1,
            };
            debug!(
                addr = %addr,
                hostname = lease.hostname.as_deref().unwrap_or("?"),
                hwaddr_type = lease.hwaddr_type,
                "SLAAC address derived and queued for DAD ping"
            );
            lease.slaac_addresses.push(new_addr);
            added_any = true;
        }
    }

    added_any
}

/// Initialize or retrieve the module-level ping identifier.
///
/// Uses `SurfRng::rand16()` on first call to generate a unique identifier
/// shared across all ICMPv6 echo requests for the lifetime of the daemon.
/// Subsequent calls return the cached value.
///
/// Thread-safe via `AtomicU16` CAS operation — only one thread can initialize.
///
/// Replaces C static variable initialization at `slaac.c` line 361:
/// `if (!ping_id) ping_id = rand16();`
fn get_or_init_ping_id(rng: &mut SurfRng) -> u16 {
    let id = PING_ID.load(Ordering::Relaxed);
    if id != 0 {
        return id;
    }
    // Initialize with a random non-zero value.
    let mut new_id = rng.rand16();
    if new_id == 0 {
        new_id = 1; // Avoid 0 which means "uninitialized".
    }
    // CAS: only set if still 0 (another thread may have initialized it).
    match PING_ID.compare_exchange(0, new_id, Ordering::Relaxed, Ordering::Relaxed) {
        Ok(_) => new_id,
        Err(existing) => existing,
    }
}

/// Construct an ICMPv6 Echo Request packet.
///
/// Packet layout (8 bytes total):
/// ```text
/// Offset  Size  Field
///   0      1    Type = 128 (ICMP6_ECHO_REQUEST)
///   1      1    Code = 0
///   2      2    Checksum = 0 (kernel fills on raw ICMPv6 socket)
///   4      2    Identifier (network byte order)
///   6      2    Sequence Number (network byte order) = backoff value
/// ```
///
/// Replaces C inline packet construction in `slaac.c` lines 430–440:
/// `ping_packet.type = ICMP6_ECHO_REQUEST; ...`
fn build_ping_packet(identifier: u16, sequence_no: u16) -> [u8; 8] {
    let mut pkt = [0u8; 8];
    pkt[0] = ICMP6_ECHO_REQUEST;
    pkt[1] = 0; // code
                // pkt[2..4] = checksum (0; kernel fills for raw ICMPv6)
    pkt[4..6].copy_from_slice(&identifier.to_be_bytes());
    pkt[6..8].copy_from_slice(&sequence_no.to_be_bytes());
    pkt
}

/// Calculate the next ping time for a SLAAC address using exponential backoff.
///
/// The delay doubles with each attempt:
/// - base delay = 2^(backoff-1) seconds
/// - jitter = rand16()/21785 (0–3 seconds)
/// - extra jitter for backoff > 4: rand16()/4000 (0–16 seconds)
///
/// Replaces C backoff calculation in `slaac.c` lines 395–405.
fn calculate_next_ping_time(now: i64, backoff: i32, rng: &mut SurfRng) -> i64 {
    // C: slaac->ping_time = now + (1 << (slaac->backoff - 1)) + (rand16()/21785);
    let base_delay = 1i64 << (backoff - 1).min(30); // Prevent overflow for large backoff values.
    let jitter_small = i64::from(rng.rand16()) / 21785; // 0–3 seconds.

    let mut next_time = now + base_delay + jitter_small;

    // C: if (slaac->backoff > 4) slaac->ping_time += rand16()/4000;
    if backoff > 4 {
        let jitter_large = i64::from(rng.rand16()) / 4000; // 0–16 seconds.
        next_time += jitter_large;
    }

    next_time
}

/// Timer-driven processing of pending SLAAC address confirmations.
///
/// Iterates all leases and their SLAAC address lists, preparing ICMPv6
/// echo request packets for addresses whose `ping_time` has elapsed.
/// Implements exponential backoff with jitter, and abandons addresses
/// after [`MAX_BACKOFF`] attempts.
///
/// # Arguments
/// * `now` — Current time (Unix epoch seconds)
/// * `leases` — Mutable slice of all DHCP leases with SLAAC tracking data
/// * `contexts` — DHCPv6 contexts (checked for any CONTEXT_RA_NAME existence)
/// * `rng` — Random number generator for jitter and ping_id initialization
///
/// # Returns
/// A [`PeriodicSlaacResult`] containing:
/// - `next_event`: timestamp of the next required invocation (0 if nothing pending)
/// - `pending_pings`: list of ICMPv6 echo requests to send
///
/// The caller is responsible for:
/// 1. Sending each `PendingPing` via the ICMPv6 raw socket
/// 2. Calling [`handle_ping_send_error`] if `sendto` fails with `EHOSTUNREACH`
/// 3. Scheduling the next call at `next_event` time
///
/// Replaces C `periodic_slaac()` (`slaac.c` lines 345–510).
pub fn periodic_slaac(
    now: i64,
    leases: &mut [SlaacLeaseInfo],
    contexts: &[DhcpContext],
    rng: &mut SurfRng,
) -> PeriodicSlaacResult {
    let mut next_event: i64 = 0;
    let mut pending_pings: Vec<PendingPing> = Vec::new();

    // Check if any CONTEXT_RA_NAME contexts exist.
    // C: slaac.c line 355: for (context = ...; context; ...) if (flags & CONTEXT_RA_NAME) break;
    let has_ra_name_context = contexts.iter().any(|ctx| ctx.flags & CONTEXT_RA_NAME != 0);
    if !has_ra_name_context {
        return PeriodicSlaacResult {
            next_event: 0,
            pending_pings,
        };
    }

    // Initialize ping identifier on first call.
    // C: slaac.c line 361: if (!ping_id) ping_id = rand16();
    let ping_id = get_or_init_ping_id(rng);

    // Iterate all leases and their SLAAC addresses.
    // C: for (lease = leases; lease; lease = lease->next)
    for (lease_idx, lease) in leases.iter_mut().enumerate() {
        let mut addr_idx = 0;
        while addr_idx < lease.slaac_addresses.len() {
            let slaac = &mut lease.slaac_addresses[addr_idx];

            // Skip confirmed addresses (backoff == 0).
            // C: if (slaac->backoff == 0) continue;
            if slaac.backoff == 0 {
                addr_idx += 1;
                continue;
            }

            // Skip addresses not yet due for ping.
            // C: if (slaac->ping_time != 0 && difftime(slaac->ping_time, now) <= 0)
            if slaac.ping_time != 0 && slaac.ping_time > now {
                // Not yet time — but track it as a future event.
                if next_event == 0 || slaac.ping_time < next_event {
                    next_event = slaac.ping_time;
                }
                addr_idx += 1;
                continue;
            }

            // Address needs a ping. Check if we've exceeded max retries.
            // C: slaac.c line ~460: if (slaac->backoff >= 12) { slaac->ping_time = 0; continue; }
            if slaac.backoff >= MAX_BACKOFF {
                debug!(
                    addr = %slaac.addr,
                    backoff = slaac.backoff,
                    "SLAAC address abandoned after max retries"
                );
                slaac.ping_time = 0;
                addr_idx += 1;
                continue;
            }

            // Build ICMPv6 echo request packet.
            // C: slaac.c lines 430–440: construct ping_packet and sendto.
            let packet = build_ping_packet(ping_id, slaac.backoff as u16);

            pending_pings.push(PendingPing {
                target: slaac.addr,
                packet,
                lease_index: lease_idx,
                addr_index: addr_idx,
            });

            debug!(
                addr = %slaac.addr,
                backoff = slaac.backoff,
                ping_id = ping_id,
                "Prepared ICMPv6 echo request for SLAAC address"
            );

            // Calculate next ping time with exponential backoff + jitter.
            slaac.ping_time = calculate_next_ping_time(now, slaac.backoff, rng);

            // Advance backoff counter.
            // C: slaac.c line 470: slaac->backoff++;
            slaac.backoff += 1;

            // Track the earliest next event.
            if next_event == 0 || slaac.ping_time < next_event {
                next_event = slaac.ping_time;
            }

            addr_idx += 1;
        }
    }

    PeriodicSlaacResult {
        next_event,
        pending_pings,
    }
}

/// Handle a failed ICMPv6 echo request send (e.g., EHOSTUNREACH).
///
/// If the address has reached [`MAX_BACKOFF`] attempts, abandons it by
/// setting `ping_time = 0`. Otherwise the address remains queued for
/// the next retry (already scheduled by [`periodic_slaac`]).
///
/// # Arguments
/// * `lease` — The lease containing the failed address
/// * `addr_index` — Index into `lease.slaac_addresses` for the failed ping
///
/// Replaces C error handling in `slaac.c` lines 445–465:
/// ```c
/// if (errno == EHOSTUNREACH) {
///     if (slaac->backoff >= 12) slaac->ping_time = 0;
/// }
/// ```
pub fn handle_ping_send_error(lease: &mut SlaacLeaseInfo, addr_index: usize) {
    if addr_index >= lease.slaac_addresses.len() {
        return;
    }
    let slaac = &mut lease.slaac_addresses[addr_index];
    if slaac.backoff >= MAX_BACKOFF {
        debug!(
            addr = %slaac.addr,
            "SLAAC address abandoned after send error at max backoff"
        );
        slaac.ping_time = 0;
    }
}

/// Process an ICMPv6 Echo Reply to confirm SLAAC address occupancy.
///
/// Matches the reply sender address against all tracked SLAAC addresses
/// across all leases. If a match is found with `backoff != 0`, sets
/// `backoff = 0` to mark the address as confirmed. Logs a `SLAAC-CONFIRM`
/// event unless `OPT_QUIET_DHCP6` is set.
///
/// # Arguments
/// * `sender` — Source IPv6 address of the Echo Reply
/// * `packet` — Raw ICMPv6 packet bytes (at least 8 bytes for the header)
/// * `interface` — Name of the network interface the reply arrived on
/// * `leases` — Mutable slice of all DHCP leases with SLAAC tracking data
/// * `options` — Daemon option flags for checking `OPT_QUIET_DHCP6`
///
/// # Returns
/// `true` if any SLAAC address was confirmed (caller should trigger DNS
/// update via `lease_update_dns(true)`), `false` otherwise.
///
/// Replaces C `slaac_ping_reply()` (`slaac.c` lines 515–537).
pub fn slaac_ping_reply(
    sender: &Ipv6Addr,
    packet: &[u8],
    interface: &str,
    leases: &mut [SlaacLeaseInfo],
    options: &OptionFlags,
) -> bool {
    // Validate packet length (need at least 8 bytes for ICMPv6 echo header).
    if packet.len() < 8 {
        return false;
    }

    // Extract identifier from packet bytes [4..6] (network byte order).
    // C: ping->identifier
    let pkt_identifier = u16::from_be_bytes([packet[4], packet[5]]);

    // Check if the identifier matches our ping_id.
    // C: if (ping->identifier != ping_id) return;
    let our_ping_id = PING_ID.load(Ordering::Relaxed);
    if pkt_identifier != our_ping_id {
        return false;
    }

    let mut got_one = false;

    // Iterate all leases and their SLAAC addresses.
    // C: for (lease = leases; ...) for (slaac = lease->slaac_address; ...)
    for lease in leases.iter_mut() {
        for slaac in lease.slaac_addresses.iter_mut() {
            // Match: sender equals tracked address and not yet confirmed.
            // C: if (slaac->backoff != 0 && IN6_ARE_ADDR_EQUAL(&slaac->addr, sender))
            if slaac.backoff != 0 && slaac.addr == *sender {
                slaac.backoff = 0;
                got_one = true;

                // Log SLAAC-CONFIRM event unless quiet mode is enabled.
                // C: if (!option_bool(OPT_QUIET_DHCP6))
                //      my_syslog(MS_DHCP | LOG_INFO, "SLAAC-CONFIRM(%s) %s %s", ...)
                if !options.is_set(opt::QUIET_DHCP6) {
                    let hostname = lease.hostname.as_deref().unwrap_or("?");
                    info!(
                        interface = interface,
                        hostname = hostname,
                        addr = %sender,
                        "SLAAC-CONFIRM({}) {} {}", interface, hostname, sender
                    );
                }
            }
        }
    }

    // C: if (gotone) lease_update_dns(1);
    // Caller is responsible for triggering DNS update when this returns true.
    got_one
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
#[allow(
    clippy::field_reassign_with_default,
    clippy::needless_borrows_for_generic_args,
    clippy::unnecessary_cast,
    clippy::assertions_on_constants,
    clippy::len_zero,
    clippy::vec_init_then_push,
    clippy::unchecked_duration_subtraction,
    clippy::manual_string_new,
    clippy::cloned_ref_to_slice_refs,
    clippy::manual_range_contains,
    clippy::trim_split_whitespace,
    clippy::identity_op,
    clippy::io_other_error,
    clippy::useless_vec,
    clippy::const_is_empty,
    clippy::clone_on_copy,
    clippy::absurd_extreme_comparisons,
    clippy::overly_complex_bool_expr,
    clippy::write_literal,
    clippy::int_plus_one,
    clippy::write_with_newline,
    clippy::float_cmp,
    clippy::double_comparisons,
    clippy::large_stack_arrays,
    clippy::writeln_empty_string,
    unused_comparisons,
    unused_mut,
    unused_variables
)]
mod tests {
    use super::*;

    // ---- Helper factories ----

    /// Create a minimal SlaacLeaseInfo for testing.
    fn make_lease(
        mac: &[u8],
        hwaddr_type: u16,
        if_index: i32,
        hostname: Option<&str>,
    ) -> SlaacLeaseInfo {
        SlaacLeaseInfo {
            hwaddr: mac.to_vec(),
            hwaddr_type,
            hwaddr_len: mac.len(),
            last_interface: if_index,
            hostname: hostname.map(String::from),
            flags: LEASE_HAVE_HWADDR,
            slaac_addresses: Vec::new(),
            clid: None,
        }
    }

    /// Create a DhcpContext with RA_NAME flag for testing.
    fn make_ra_name_context(prefix: Ipv6Addr, if_index: i32) -> DhcpContext {
        use crate::dhcp::common::NetId;
        use std::net::Ipv4Addr;

        DhcpContext {
            start: Ipv4Addr::UNSPECIFIED,
            end: Ipv4Addr::UNSPECIFIED,
            netmask: Ipv4Addr::UNSPECIFIED,
            broadcast: Ipv4Addr::UNSPECIFIED,
            router: Ipv4Addr::UNSPECIFIED,
            lease_time: 0,
            netid: NetId { net: String::new() },
            flags: CONTEXT_RA_NAME,
            filter: Vec::new(),
            local: Ipv4Addr::UNSPECIFIED,
            addr_epoch: 0,
            #[cfg(feature = "dhcp6")]
            start6: prefix,
            #[cfg(feature = "dhcp6")]
            end6: Ipv6Addr::UNSPECIFIED,
            #[cfg(feature = "dhcp6")]
            local6: Ipv6Addr::UNSPECIFIED,
            #[cfg(feature = "dhcp6")]
            prefix: 64,
            #[cfg(feature = "dhcp6")]
            if_index,
            #[cfg(feature = "dhcp6")]
            valid: 0,
            #[cfg(feature = "dhcp6")]
            preferred: 0,
            #[cfg(feature = "dhcp6")]
            template_interface: None,
        }
    }

    // ---- mac_to_eui64 tests ----

    #[test]
    fn test_mac_to_eui64_standard() {
        // Known conversion: 00:11:22:33:44:55 → EUI-64 02:11:22:ff:fe:33:44:55
        // Combined with prefix 2001:db8:: → 2001:db8::211:22ff:fe33:4455
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let prefix: Ipv6Addr = "2001:db8::".parse().unwrap();
        let result = mac_to_eui64(&mac, &prefix);
        let expected: Ipv6Addr = "2001:db8::211:22ff:fe33:4455".parse().unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_mac_to_eui64_bit_inversion_02_to_00() {
        // MAC starts with 02 (universal/local bit set) → should become 00
        let mac = [0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
        let prefix: Ipv6Addr = "fe80::".parse().unwrap();
        let result = mac_to_eui64(&mac, &prefix);
        let octets = result.octets();
        // byte[8] = 0x02 ^ 0x02 = 0x00
        assert_eq!(octets[8], 0x00);
        assert_eq!(octets[9], 0xAA);
        assert_eq!(octets[10], 0xBB);
        assert_eq!(octets[11], 0xFF);
        assert_eq!(octets[12], 0xFE);
        assert_eq!(octets[13], 0xCC);
        assert_eq!(octets[14], 0xDD);
        assert_eq!(octets[15], 0xEE);
    }

    #[test]
    fn test_mac_to_eui64_preserves_prefix() {
        let mac = [0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        let prefix: Ipv6Addr = "fd12:3456:7890:abcd::".parse().unwrap();
        let result = mac_to_eui64(&mac, &prefix);
        let octets = result.octets();
        // Upper 8 bytes must equal the prefix's upper 8 bytes.
        let prefix_octets = prefix.octets();
        assert_eq!(&octets[..8], &prefix_octets[..8]);
    }

    #[test]
    fn test_mac_to_eui64_all_ff() {
        let mac = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let prefix: Ipv6Addr = "2001:db8:1::".parse().unwrap();
        let result = mac_to_eui64(&mac, &prefix);
        let octets = result.octets();
        // byte[8] = 0xFF ^ 0x02 = 0xFD
        assert_eq!(octets[8], 0xFD);
        assert_eq!(octets[9], 0xFF);
        assert_eq!(octets[10], 0xFF);
        assert_eq!(octets[11], 0xFF);
        assert_eq!(octets[12], 0xFE);
        assert_eq!(octets[13], 0xFF);
        assert_eq!(octets[14], 0xFF);
        assert_eq!(octets[15], 0xFF);
    }

    // ---- derive_slaac_address tests ----

    #[test]
    fn test_derive_slaac_ethernet() {
        let lease = make_lease(
            &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            ARPHRD_ETHER,
            1,
            Some("host1"),
        );
        let prefix: Ipv6Addr = "2001:db8::".parse().unwrap();
        let result = derive_slaac_address(&lease, &prefix);
        assert!(result.is_some());
        let expected: Ipv6Addr = "2001:db8::211:22ff:fe33:4455".parse().unwrap();
        assert_eq!(result.unwrap(), expected);
    }

    #[test]
    fn test_derive_slaac_ieee802() {
        // IEEE 802 uses same EUI-64 path as Ethernet.
        let lease = make_lease(
            &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            ARPHRD_IEEE802,
            1,
            Some("host2"),
        );
        let prefix: Ipv6Addr = "fd00::".parse().unwrap();
        let result = derive_slaac_address(&lease, &prefix);
        assert!(result.is_some());
        let octets = result.unwrap().octets();
        assert_eq!(octets[8], 0xAA ^ 0x02); // 0xA8
        assert_eq!(octets[11], 0xFF);
        assert_eq!(octets[12], 0xFE);
    }

    #[test]
    fn test_derive_slaac_ethernet_wrong_len() {
        // 5-byte MAC should fail.
        let mut lease = make_lease(
            &[0x00, 0x11, 0x22, 0x33, 0x44],
            ARPHRD_ETHER,
            1,
            Some("host3"),
        );
        lease.hwaddr_len = 5;
        let prefix: Ipv6Addr = "2001:db8::".parse().unwrap();
        assert!(derive_slaac_address(&lease, &prefix).is_none());
    }

    #[test]
    fn test_derive_slaac_eui64_direct() {
        let eui = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let mut lease = make_lease(&eui, ARPHRD_EUI64, 1, Some("host4"));
        lease.hwaddr_len = 8;
        let prefix: Ipv6Addr = "2001:db8::".parse().unwrap();
        let result = derive_slaac_address(&lease, &prefix);
        assert!(result.is_some());
        let octets = result.unwrap().octets();
        assert_eq!(&octets[8..16], &eui);
    }

    #[test]
    fn test_derive_slaac_eui64_wrong_len() {
        let mut lease = make_lease(&[0x01, 0x02, 0x03, 0x04], ARPHRD_EUI64, 1, Some("host5"));
        lease.hwaddr_len = 4;
        let prefix: Ipv6Addr = "2001:db8::".parse().unwrap();
        assert!(derive_slaac_address(&lease, &prefix).is_none());
    }

    #[test]
    fn test_derive_slaac_ieee1394_firewire() {
        let clid = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let mut lease = make_lease(&[], ARPHRD_IEEE1394, 1, Some("fw-host"));
        lease.hwaddr_len = 0;
        lease.clid = Some(clid.clone());
        let prefix: Ipv6Addr = "2001:db8::".parse().unwrap();
        let result = derive_slaac_address(&lease, &prefix);
        assert!(result.is_some());
        let octets = result.unwrap().octets();
        // EUI-64 is clid[1..9].
        assert_eq!(&octets[8..16], &clid[1..9]);
    }

    #[test]
    fn test_derive_slaac_ieee1394_no_clid() {
        let lease = make_lease(&[], ARPHRD_IEEE1394, 1, Some("fw-host2"));
        let prefix: Ipv6Addr = "2001:db8::".parse().unwrap();
        assert!(derive_slaac_address(&lease, &prefix).is_none());
    }

    #[test]
    fn test_derive_slaac_ieee1394_short_clid() {
        let mut lease = make_lease(&[], ARPHRD_IEEE1394, 1, Some("fw-host3"));
        lease.clid = Some(vec![0x00, 0x11, 0x22]); // Only 3 bytes, need 9.
        let prefix: Ipv6Addr = "2001:db8::".parse().unwrap();
        assert!(derive_slaac_address(&lease, &prefix).is_none());
    }

    #[test]
    fn test_derive_slaac_unsupported_hwtype() {
        // Unknown hardware type 99 should return None.
        let lease = make_lease(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55], 99, 1, Some("host6"));
        let prefix: Ipv6Addr = "2001:db8::".parse().unwrap();
        assert!(derive_slaac_address(&lease, &prefix).is_none());
    }

    // ---- slaac_add_addrs tests ----

    #[test]
    fn test_add_addrs_basic() {
        let mut lease = make_lease(
            &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            ARPHRD_ETHER,
            2,
            Some("testhost"),
        );
        let prefix: Ipv6Addr = "2001:db8::".parse().unwrap();
        let contexts = vec![make_ra_name_context(prefix, 2)];
        let now = 1000i64;
        let added = slaac_add_addrs(&mut lease, &contexts, now, false);
        assert!(added);
        assert_eq!(lease.slaac_addresses.len(), 1);
        assert_eq!(lease.slaac_addresses[0].backoff, 1);
        assert_eq!(lease.slaac_addresses[0].ping_time, now);
    }

    #[test]
    fn test_add_addrs_no_hwaddr_flag() {
        let mut lease = make_lease(
            &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            ARPHRD_ETHER,
            2,
            Some("testhost"),
        );
        lease.flags = 0; // No LEASE_HAVE_HWADDR.
        let contexts = vec![make_ra_name_context("2001:db8::".parse().unwrap(), 2)];
        assert!(!slaac_add_addrs(&mut lease, &contexts, 1000, false));
        assert!(lease.slaac_addresses.is_empty());
    }

    #[test]
    fn test_add_addrs_ta_flag_blocks() {
        let mut lease = make_lease(
            &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            ARPHRD_ETHER,
            2,
            Some("testhost"),
        );
        lease.flags |= LEASE_TA;
        let contexts = vec![make_ra_name_context("2001:db8::".parse().unwrap(), 2)];
        assert!(!slaac_add_addrs(&mut lease, &contexts, 1000, false));
    }

    #[test]
    fn test_add_addrs_no_hostname() {
        let mut lease = make_lease(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55], ARPHRD_ETHER, 2, None);
        let contexts = vec![make_ra_name_context("2001:db8::".parse().unwrap(), 2)];
        assert!(!slaac_add_addrs(&mut lease, &contexts, 1000, false));
    }

    #[test]
    fn test_add_addrs_interface_mismatch() {
        let mut lease = make_lease(
            &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            ARPHRD_ETHER,
            3, // Interface 3
            Some("testhost"),
        );
        // Context is for interface 2.
        let contexts = vec![make_ra_name_context("2001:db8::".parse().unwrap(), 2)];
        assert!(!slaac_add_addrs(&mut lease, &contexts, 1000, false));
        assert!(lease.slaac_addresses.is_empty());
    }

    #[test]
    fn test_add_addrs_duplicate_no_add() {
        let mut lease = make_lease(
            &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            ARPHRD_ETHER,
            2,
            Some("testhost"),
        );
        let prefix: Ipv6Addr = "2001:db8::".parse().unwrap();
        let contexts = vec![make_ra_name_context(prefix, 2)];

        // First add.
        assert!(slaac_add_addrs(&mut lease, &contexts, 1000, false));
        assert_eq!(lease.slaac_addresses.len(), 1);

        // Second add — same address, should NOT add again.
        assert!(!slaac_add_addrs(&mut lease, &contexts, 2000, false));
        assert_eq!(lease.slaac_addresses.len(), 1);
    }

    #[test]
    fn test_add_addrs_force_resets_backoff() {
        let mut lease = make_lease(
            &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            ARPHRD_ETHER,
            2,
            Some("testhost"),
        );
        let prefix: Ipv6Addr = "2001:db8::".parse().unwrap();
        let contexts = vec![make_ra_name_context(prefix, 2)];

        slaac_add_addrs(&mut lease, &contexts, 1000, false);
        // Simulate progress — set backoff to 5.
        lease.slaac_addresses[0].backoff = 5;
        lease.slaac_addresses[0].ping_time = 1500;

        // Force re-add — should reset backoff to 1.
        assert!(!slaac_add_addrs(&mut lease, &contexts, 2000, true));
        assert_eq!(lease.slaac_addresses[0].backoff, 1);
        assert_eq!(lease.slaac_addresses[0].ping_time, 2000);
    }

    #[test]
    fn test_add_addrs_context_old_skipped() {
        let mut lease = make_lease(
            &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            ARPHRD_ETHER,
            2,
            Some("testhost"),
        );
        let mut ctx = make_ra_name_context("2001:db8::".parse().unwrap(), 2);
        ctx.flags |= CONTEXT_OLD; // Mark as OLD — should be skipped.
        let contexts = vec![ctx];
        assert!(!slaac_add_addrs(&mut lease, &contexts, 1000, false));
        assert!(lease.slaac_addresses.is_empty());
    }

    #[test]
    fn test_add_addrs_multiple_prefixes() {
        let mut lease = make_lease(
            &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            ARPHRD_ETHER,
            2,
            Some("testhost"),
        );
        let contexts = vec![
            make_ra_name_context("2001:db8:1::".parse().unwrap(), 2),
            make_ra_name_context("2001:db8:2::".parse().unwrap(), 2),
        ];
        assert!(slaac_add_addrs(&mut lease, &contexts, 1000, false));
        assert_eq!(lease.slaac_addresses.len(), 2);
        // Two different addresses from two different prefixes.
        assert_ne!(lease.slaac_addresses[0].addr, lease.slaac_addresses[1].addr);
    }

    // ---- periodic_slaac tests ----

    #[test]
    fn test_periodic_no_ra_contexts() {
        let mut rng = SurfRng::new().unwrap();
        let mut leases = vec![make_lease(
            &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            ARPHRD_ETHER,
            2,
            Some("host"),
        )];
        let contexts: Vec<DhcpContext> = vec![]; // No RA_NAME contexts.
        let result = periodic_slaac(1000, &mut leases, &contexts, &mut rng);
        assert_eq!(result.next_event, 0);
        assert!(result.pending_pings.is_empty());
    }

    #[test]
    fn test_periodic_confirmed_addresses_skipped() {
        let mut rng = SurfRng::new().unwrap();
        let prefix: Ipv6Addr = "2001:db8::".parse().unwrap();
        let addr: Ipv6Addr = "2001:db8::211:22ff:fe33:4455".parse().unwrap();
        let mut lease = make_lease(
            &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            ARPHRD_ETHER,
            2,
            Some("host"),
        );
        lease.slaac_addresses.push(SlaacAddress {
            addr,
            ping_time: 0,
            backoff: 0, // Confirmed.
        });
        let contexts = vec![make_ra_name_context(prefix, 2)];
        let result = periodic_slaac(1000, &mut [lease], &contexts, &mut rng);
        assert!(result.pending_pings.is_empty());
    }

    #[test]
    fn test_periodic_generates_ping() {
        let mut rng = SurfRng::new().unwrap();
        let prefix: Ipv6Addr = "2001:db8::".parse().unwrap();
        let addr: Ipv6Addr = "2001:db8::211:22ff:fe33:4455".parse().unwrap();
        let now = 1000i64;
        let mut lease = make_lease(
            &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            ARPHRD_ETHER,
            2,
            Some("host"),
        );
        lease.slaac_addresses.push(SlaacAddress {
            addr,
            ping_time: now, // Due now.
            backoff: 1,
        });
        let contexts = vec![make_ra_name_context(prefix, 2)];
        let mut leases = vec![lease];
        let result = periodic_slaac(now, &mut leases, &contexts, &mut rng);
        assert_eq!(result.pending_pings.len(), 1);
        assert_eq!(result.pending_pings[0].target, addr);
        // Packet should be an ICMPv6 echo request.
        assert_eq!(result.pending_pings[0].packet[0], ICMP6_ECHO_REQUEST);
        assert_eq!(result.pending_pings[0].packet[1], 0); // code
                                                          // Backoff should have advanced.
        assert_eq!(leases[0].slaac_addresses[0].backoff, 2);
        // Next event should be set.
        assert!(result.next_event > now);
    }

    #[test]
    fn test_periodic_max_backoff_abandon() {
        let mut rng = SurfRng::new().unwrap();
        let prefix: Ipv6Addr = "2001:db8::".parse().unwrap();
        let addr: Ipv6Addr = "2001:db8::211:22ff:fe33:4455".parse().unwrap();
        let now = 1000i64;
        let mut lease = make_lease(
            &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            ARPHRD_ETHER,
            2,
            Some("host"),
        );
        lease.slaac_addresses.push(SlaacAddress {
            addr,
            ping_time: now,
            backoff: MAX_BACKOFF, // At max — should be abandoned.
        });
        let contexts = vec![make_ra_name_context(prefix, 2)];
        let mut leases = vec![lease];
        let result = periodic_slaac(now, &mut leases, &contexts, &mut rng);
        // Should NOT generate a ping — address is abandoned.
        assert!(result.pending_pings.is_empty());
        // ping_time should be set to 0 (abandoned).
        assert_eq!(leases[0].slaac_addresses[0].ping_time, 0);
    }

    #[test]
    fn test_periodic_future_ping_not_sent() {
        let mut rng = SurfRng::new().unwrap();
        let prefix: Ipv6Addr = "2001:db8::".parse().unwrap();
        let addr: Ipv6Addr = "2001:db8::211:22ff:fe33:4455".parse().unwrap();
        let now = 1000i64;
        let mut lease = make_lease(
            &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            ARPHRD_ETHER,
            2,
            Some("host"),
        );
        lease.slaac_addresses.push(SlaacAddress {
            addr,
            ping_time: now + 500, // Not yet due.
            backoff: 3,
        });
        let contexts = vec![make_ra_name_context(prefix, 2)];
        let mut leases = vec![lease];
        let result = periodic_slaac(now, &mut leases, &contexts, &mut rng);
        assert!(result.pending_pings.is_empty());
        assert_eq!(result.next_event, now + 500);
    }

    // ---- slaac_ping_reply tests ----

    #[test]
    fn test_ping_reply_confirms_address() {
        // First, ensure PING_ID is set for this test.
        let mut rng = SurfRng::new().unwrap();
        let ping_id = get_or_init_ping_id(&mut rng);

        let sender: Ipv6Addr = "2001:db8::211:22ff:fe33:4455".parse().unwrap();
        let mut lease = make_lease(
            &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            ARPHRD_ETHER,
            2,
            Some("testhost"),
        );
        lease.slaac_addresses.push(SlaacAddress {
            addr: sender,
            ping_time: 500,
            backoff: 3, // Pending.
        });

        let packet = build_ping_packet(ping_id, 3);
        let options = OptionFlags::default();
        let mut leases = vec![lease];
        let confirmed = slaac_ping_reply(&sender, &packet, "eth0", &mut leases, &options);
        assert!(confirmed);
        assert_eq!(leases[0].slaac_addresses[0].backoff, 0); // Confirmed.
    }

    #[test]
    fn test_ping_reply_wrong_identifier() {
        let sender: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let mut lease = make_lease(
            &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            ARPHRD_ETHER,
            2,
            Some("testhost"),
        );
        lease.slaac_addresses.push(SlaacAddress {
            addr: sender,
            ping_time: 500,
            backoff: 3,
        });

        // Build packet with wrong identifier.
        let packet = build_ping_packet(0xFFFF, 3);
        let options = OptionFlags::default();
        let mut leases = vec![lease];
        let confirmed = slaac_ping_reply(&sender, &packet, "eth0", &mut leases, &options);
        // Should not confirm because identifier doesn't match.
        // (Unless PING_ID happens to be 0xFFFF, which is extremely unlikely.)
        if PING_ID.load(Ordering::Relaxed) != 0xFFFF {
            assert!(!confirmed);
            assert_ne!(leases[0].slaac_addresses[0].backoff, 0);
        }
    }

    #[test]
    fn test_ping_reply_address_mismatch() {
        let mut rng = SurfRng::new().unwrap();
        let ping_id = get_or_init_ping_id(&mut rng);

        let sender: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let tracked: Ipv6Addr = "2001:db8::2".parse().unwrap(); // Different address.
        let mut lease = make_lease(
            &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            ARPHRD_ETHER,
            2,
            Some("testhost"),
        );
        lease.slaac_addresses.push(SlaacAddress {
            addr: tracked,
            ping_time: 500,
            backoff: 3,
        });

        let packet = build_ping_packet(ping_id, 3);
        let options = OptionFlags::default();
        let mut leases = vec![lease];
        let confirmed = slaac_ping_reply(&sender, &packet, "eth0", &mut leases, &options);
        assert!(!confirmed);
        assert_eq!(leases[0].slaac_addresses[0].backoff, 3); // Unchanged.
    }

    #[test]
    fn test_ping_reply_already_confirmed() {
        let mut rng = SurfRng::new().unwrap();
        let ping_id = get_or_init_ping_id(&mut rng);

        let sender: Ipv6Addr = "2001:db8::211:22ff:fe33:4455".parse().unwrap();
        let mut lease = make_lease(
            &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            ARPHRD_ETHER,
            2,
            Some("testhost"),
        );
        lease.slaac_addresses.push(SlaacAddress {
            addr: sender,
            ping_time: 0,
            backoff: 0, // Already confirmed.
        });

        let packet = build_ping_packet(ping_id, 1);
        let options = OptionFlags::default();
        let mut leases = vec![lease];
        let confirmed = slaac_ping_reply(&sender, &packet, "eth0", &mut leases, &options);
        assert!(!confirmed); // backoff was already 0, so no change.
    }

    #[test]
    fn test_ping_reply_short_packet() {
        let sender: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let options = OptionFlags::default();
        let mut leases: Vec<SlaacLeaseInfo> = vec![];
        // Packet too short (< 8 bytes).
        let confirmed = slaac_ping_reply(&sender, &[0u8; 4], "eth0", &mut leases, &options);
        assert!(!confirmed);
    }

    // ---- handle_ping_send_error tests ----

    #[test]
    fn test_handle_error_max_backoff_abandons() {
        let mut lease = make_lease(
            &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            ARPHRD_ETHER,
            2,
            Some("host"),
        );
        lease.slaac_addresses.push(SlaacAddress {
            addr: "2001:db8::1".parse().unwrap(),
            ping_time: 1000,
            backoff: MAX_BACKOFF,
        });
        handle_ping_send_error(&mut lease, 0);
        assert_eq!(lease.slaac_addresses[0].ping_time, 0); // Abandoned.
    }

    #[test]
    fn test_handle_error_below_max_no_change() {
        let mut lease = make_lease(
            &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            ARPHRD_ETHER,
            2,
            Some("host"),
        );
        lease.slaac_addresses.push(SlaacAddress {
            addr: "2001:db8::1".parse().unwrap(),
            ping_time: 1000,
            backoff: 5,
        });
        handle_ping_send_error(&mut lease, 0);
        assert_eq!(lease.slaac_addresses[0].ping_time, 1000); // Unchanged.
    }

    #[test]
    fn test_handle_error_invalid_index() {
        let mut lease = make_lease(&[], ARPHRD_ETHER, 1, Some("host"));
        // Out-of-bounds index — should not panic.
        handle_ping_send_error(&mut lease, 99);
    }

    // ---- build_ping_packet tests ----

    #[test]
    fn test_build_ping_packet_layout() {
        let pkt = build_ping_packet(0x1234, 0x0005);
        assert_eq!(pkt[0], ICMP6_ECHO_REQUEST); // type
        assert_eq!(pkt[1], 0); // code
        assert_eq!(pkt[2], 0); // checksum high
        assert_eq!(pkt[3], 0); // checksum low
        assert_eq!(pkt[4], 0x12); // identifier high byte
        assert_eq!(pkt[5], 0x34); // identifier low byte
        assert_eq!(pkt[6], 0x00); // sequence high byte
        assert_eq!(pkt[7], 0x05); // sequence low byte
    }

    // ---- calculate_next_ping_time tests ----

    #[test]
    fn test_backoff_timing_backoff_1() {
        let mut rng = SurfRng::new().unwrap();
        let now = 1000i64;
        let next = calculate_next_ping_time(now, 1, &mut rng);
        // base_delay = 2^0 = 1, jitter 0-3 → next in [1001, 1004]
        assert!(next >= now + 1);
        assert!(next <= now + 1 + 3);
    }

    #[test]
    fn test_backoff_timing_backoff_5() {
        let mut rng = SurfRng::new().unwrap();
        let now = 1000i64;
        let next = calculate_next_ping_time(now, 5, &mut rng);
        // base_delay = 2^4 = 16, jitter 0-3, extra jitter 0-16 → next in [1016, 1035]
        assert!(next >= now + 16);
        assert!(next <= now + 16 + 3 + 16);
    }

    #[test]
    fn test_backoff_timing_doubles() {
        let mut rng = SurfRng::new().unwrap();
        let now = 0i64;
        let t1 = calculate_next_ping_time(now, 1, &mut rng); // base = 1
        let t2 = calculate_next_ping_time(now, 2, &mut rng); // base = 2
        let t3 = calculate_next_ping_time(now, 3, &mut rng); // base = 4
                                                             // Due to random jitter, we can only check that the base increases.
                                                             // t1 min = 1, t2 min = 2, t3 min = 4.
        assert!(t1 >= 1);
        assert!(t2 >= 2);
        assert!(t3 >= 4);
    }

    // ---- SlaacAddress struct tests ----

    #[test]
    fn test_slaac_address_clone() {
        let addr = SlaacAddress {
            addr: "2001:db8::1".parse().unwrap(),
            ping_time: 1234,
            backoff: 3,
        };
        let clone = addr.clone();
        assert_eq!(clone.addr, addr.addr);
        assert_eq!(clone.ping_time, addr.ping_time);
        assert_eq!(clone.backoff, addr.backoff);
    }

    #[test]
    fn test_slaac_address_debug() {
        let addr = SlaacAddress {
            addr: "2001:db8::1".parse().unwrap(),
            ping_time: 0,
            backoff: 0,
        };
        let debug_str = format!("{:?}", addr);
        assert!(debug_str.contains("SlaacAddress"));
        assert!(debug_str.contains("2001:db8::1"));
    }
}

//! SLAAC (Stateless Address Autoconfiguration) address probing and confirmation.
//!
//! Implements IPv6 SLAAC duplicate address detection by sending ICMPv6 echo
//! requests (pings) to EUI-64-derived addresses and monitoring for replies.
//! When a reply is received, the address is confirmed as alive and DNS
//! hostname registration is triggered.
//!
//! # Functional Overview
//!
//! 1. **[`slaac_add_addrs`]**: Derives EUI-64 IPv6 addresses from DHCPv4
//!    lease MAC addresses combined with Router Advertisement prefixes, and
//!    adds them to the probe tracking table on each lease.
//! 2. **[`periodic_slaac`]**: Periodically sends ICMPv6 echo requests to
//!    unconfirmed SLAAC addresses using exponential backoff with jitter.
//! 3. **[`slaac_ping_reply`]**: Processes incoming ICMPv6 echo replies,
//!    marks matching addresses as confirmed, and triggers DNS registration.
//! 4. **[`derive_eui64_address`]**: Pure helper that constructs an IPv6
//!    address from a prefix and MAC address using EUI-64 conversion.
//!
//! # EUI-64 Conversion (RFC 4291 Appendix A)
//!
//! For 48-bit Ethernet MACs (e.g., `00:11:22:33:44:55`):
//! - Insert `0xFF:0xFE` in the middle: `00:11:22:FF:FE:33:44:55`
//! - Flip the Universal/Local bit (bit 1 of byte 0): `02:11:22:FF:FE:33:44:55`
//! - Combine with /64 prefix: `2001:db8::211:22ff:fe33:4455`
//!
//! # Feature Gate
//!
//! This module is compiled only when the `dhcp6` feature is enabled. The
//! parent module (`src/dhcp/radv/mod.rs`) applies the `#[cfg(feature = "dhcp6")]`
//! gate.
//!
//! # Thread Safety
//!
//! Single-threaded event-driven model. Functions are called from the main
//! event loop only. The static `PING_ID` uses `OnceLock` for safe lazy
//! initialization.
//!
//! # Source Reference
//!
//! Rewritten from C `src/slaac.c` (537 lines).
//!
//! # RFC Compliance
//!
//! - RFC 4291 Appendix A — EUI-64 interface identifier derivation
//! - RFC 4443 §4.1/§4.2 — ICMPv6 Echo Request/Reply format
//! - RFC 4862 §5.4 — Duplicate Address Detection considerations

use std::net::Ipv6Addr;
use std::os::unix::io::RawFd;
use std::sync::OnceLock;

use log::info;
use nix::errno::Errno;

use crate::core::daemon::{DaemonState, OPT_QUIET_DHCP6};
use crate::core::prng::rand16;
use crate::dhcp::radv::protocol::{
    PingPacket, ARPHRD_EUI64, ARPHRD_ETHER, ARPHRD_IEEE1394, ARPHRD_IEEE802,
};
use crate::types::dhcp::{
    DhcpContext, DhcpContextFlags, DhcpLease, LeaseFlags, SlaacAddress,
};

// ============================================================================
// Static State
// ============================================================================

/// Lazily-initialized ICMPv6 echo identifier for matching ping replies.
///
/// Initialized once from `rand16()` on the first call to [`get_ping_id`].
/// All ICMPv6 echo requests sent by this daemon instance use the same
/// identifier, allowing [`slaac_ping_reply`] to distinguish our echo
/// replies from unrelated ICMPv6 traffic.
///
/// Replaces: C `static int ping_id = 0;` (slaac.c line 95).
static PING_ID: OnceLock<u16> = OnceLock::new();

/// Retrieve the ICMPv6 echo identifier, initializing it on first use.
///
/// The C code re-generates if `ping_id == 0`, ensuring a non-zero value.
/// We replicate that by looping until `rand16()` returns a non-zero value.
fn get_ping_id() -> u16 {
    *PING_ID.get_or_init(|| {
        let mut id = rand16();
        // Match C behaviour: `while (ping_id == 0) ping_id = rand16();`
        while id == 0 {
            id = rand16();
        }
        id
    })
}

// ============================================================================
// EUI-64 Address Derivation
// ============================================================================

/// Derive an IPv6 SLAAC address from a network prefix and hardware address
/// using the EUI-64 interface identifier algorithm.
///
/// The prefix bytes `[0..8]` (for a /64) come from the context's `start6`
/// address. Bytes `[8..16]` are filled with the EUI-64 interface identifier
/// derived from the hardware (MAC) address.
///
/// # Hardware Type Handling
///
/// | HW Type | Constant | MAC Len | Conversion |
/// |---------|----------|---------|------------|
/// | Ethernet | `ARPHRD_ETHER` (1) | 6 | Insert FF:FE, flip U/L bit |
/// | Token Ring | `ARPHRD_IEEE802` (6) | 6 | Same as Ethernet |
/// | EUI-64 | `ARPHRD_EUI64` (27) | 8 | Copy directly, flip U/L bit |
/// | FireWire | `ARPHRD_IEEE1394` (24) | 8 | Copy directly, NO U/L flip |
///
/// # Arguments
///
/// * `prefix` — The IPv6 prefix address (typically a /64, only bytes 0..8 are used).
/// * `_prefix_len` — The prefix length in bits (reserved for future use; currently
///   assumes /64).
/// * `mac` — The hardware address bytes.
/// * `hw_type` — ARP hardware type constant.
///
/// # Returns
///
/// `Some(Ipv6Addr)` with the derived SLAAC address, or `None` if the hardware
/// type / MAC length combination is unsupported.
///
/// # C Equivalent
///
/// Direct port of the EUI-64 conversion logic in `slaac_add_addrs()`
/// (slaac.c lines 184-208).
pub fn derive_eui64_address(
    prefix: &Ipv6Addr,
    _prefix_len: i32,
    mac: &[u8],
    hw_type: u16,
) -> Option<Ipv6Addr> {
    let mut octets = prefix.octets();

    match hw_type {
        // Ethernet (6-byte MAC) or Token Ring (same algorithm)
        t if (t == ARPHRD_ETHER || t == ARPHRD_IEEE802) && mac.len() >= 6 => {
            // EUI-64: insert FF:FE in the middle of the 48-bit MAC
            octets[8] = mac[0];
            octets[9] = mac[1];
            octets[10] = mac[2];
            octets[11] = 0xFF;
            octets[12] = 0xFE;
            octets[13] = mac[3];
            octets[14] = mac[4];
            octets[15] = mac[5];
            // Flip the Universal/Local bit (bit 1 of byte 8)
            octets[8] ^= 0x02;
        }
        // Native EUI-64 (8-byte address) — flip U/L bit
        ARPHRD_EUI64 if mac.len() >= 8 => {
            octets[8..16].copy_from_slice(&mac[0..8]);
            octets[8] ^= 0x02;
        }
        // IEEE 1394 (FireWire) — copy directly, NO U/L bit flip
        // Note: C code reads EUI-64 from clid[1..9], not hwaddr, but the
        // caller in slaac_add_addrs handles that distinction. This function
        // just takes the raw bytes to copy.
        ARPHRD_IEEE1394 if mac.len() >= 8 => {
            octets[8..16].copy_from_slice(&mac[0..8]);
            // Intentionally NO XOR 0x02 for FireWire (matches C behaviour)
        }
        // Unsupported hardware type or insufficient MAC length
        _ => return None,
    }

    Some(Ipv6Addr::from(octets))
}

// ============================================================================
// slaac_add_addrs — Derive and Track SLAAC Addresses for a Lease
// ============================================================================

/// Derive EUI-64 IPv6 addresses from a DHCP lease's MAC address and add
/// them to the SLAAC probe tracking list on the lease.
///
/// For each DHCPv6 context with `CONTEXT_RA_NAME` flag matching the lease's
/// interface, the function derives a SLAAC address and either:
/// - Creates a new `SlaacAddress` entry with `backoff=1` to start probing
/// - Keeps an existing entry (optionally resetting backoff if `force` is true)
///
/// Stale entries (addresses whose contexts no longer exist) are removed.
///
/// # Arguments
///
/// * `lease` — The DHCP lease containing hardware address information.
/// * `now` — Current timestamp (seconds since epoch).
/// * `force` — If true, resets backoff on existing entries to restart probing.
///   Used when DHCPv4 lease goes through init-reboot sequence.
/// * `contexts` — DHCPv6 context list from `daemon.dhcp6` configuration.
///
/// # Returns
///
/// `true` if any SLAAC addresses were added, removed, or force-restarted,
/// indicating that DNS registration may need updating.
///
/// # C Equivalent
///
/// Direct port of `slaac_add_addrs()` (slaac.c lines 163-254).
pub fn slaac_add_addrs(
    lease: &mut DhcpLease,
    now: i64,
    force: bool,
    contexts: &mut [DhcpContext],
) -> bool {
    // Pre-condition checks matching C lines 169-173:
    // - Must have a hardware address
    // - Must not be a DHCPv6 TA or NA lease (those are managed by DHCPv6 directly)
    // - Must have a valid interface binding
    // - Must have a hostname (DNS registration impossible without one)
    if !lease.flags.contains(LeaseFlags::HAVE_HWADDR) {
        return false;
    }
    if lease.flags.intersects(LeaseFlags::TA | LeaseFlags::NA) {
        return false;
    }
    if lease.last_interface == 0 {
        return false;
    }
    if lease.hostname.is_none() {
        return false;
    }

    // Save old SLAAC addresses for comparison; clear the lease's list
    let old_addresses = std::mem::take(&mut lease.slaac_addresses);
    let mut new_addresses: Vec<SlaacAddress> = Vec::new();
    let mut dns_dirty = false;

    for context in contexts.iter_mut() {
        // Skip template, old, or non-RA_NAME contexts (C line 179-181)
        if context.flags.contains(DhcpContextFlags::OLD) {
            continue;
        }
        if !context.flags.contains(DhcpContextFlags::RA_NAME) {
            continue;
        }
        if lease.last_interface != context.if_index {
            continue;
        }

        // Derive EUI-64 address from prefix + MAC
        // The C code handles FireWire specially: it uses clid[1..9] as the
        // MAC bytes (clid[0] is the hardware type). For all other types,
        // it uses hwaddr directly.
        let derived_addr = if lease.hwaddr_type as u16 == ARPHRD_IEEE1394
            && lease.clid.len() == 9
            && lease.clid[0] == ARPHRD_EUI64 as u8
        {
            // FireWire: EUI-64 identifier stored in client ID bytes [1..9]
            derive_eui64_address(
                &context.start6,
                context.prefix,
                &lease.clid[1..9],
                ARPHRD_IEEE1394,
            )
        } else if (lease.hwaddr_type as u16 == ARPHRD_ETHER
            || lease.hwaddr_type as u16 == ARPHRD_IEEE802)
            && lease.hwaddr_len == 6
        {
            derive_eui64_address(
                &context.start6,
                context.prefix,
                &lease.hwaddr,
                lease.hwaddr_type as u16,
            )
        } else if lease.hwaddr_type as u16 == ARPHRD_EUI64 && lease.hwaddr_len == 8 {
            derive_eui64_address(
                &context.start6,
                context.prefix,
                &lease.hwaddr,
                ARPHRD_EUI64,
            )
        } else {
            // Unsupported hardware type — skip this context
            continue;
        };

        let addr = match derived_addr {
            Some(a) => a,
            None => continue,
        };

        // Check if we already have this address in the old list (C lines 211-226)
        let existing = old_addresses.iter().find(|s| s.addr == addr);

        let slaac_entry = if let Some(old_entry) = existing {
            let mut entry = old_entry.clone();
            // If force is set, restart probing (C lines 217-222)
            if force {
                entry.ping_time = now;
                entry.backoff = 1;
                dns_dirty = true;
            }
            entry
        } else {
            // New address — create entry and trigger RA (C lines 229-236)
            crate::dhcp::radv::server::ra_start_unsolicited(now, context);
            SlaacAddress {
                addr,
                ping_time: now,
                backoff: 1,
            }
        };

        new_addresses.push(slaac_entry);
    }

    // Determine if addresses were removed (old entries not in new list)
    let had_removals = old_addresses
        .iter()
        .any(|old| !new_addresses.iter().any(|new| new.addr == old.addr));

    lease.slaac_addresses = new_addresses;

    // If any old entries were removed or dns_dirty was set, trigger DNS update
    // (C lines 245-246: `if (old || dns_dirty) lease_update_dns(1);`)
    had_removals || dns_dirty
}

// ============================================================================
// periodic_slaac — Send ICMPv6 Echo Requests with Exponential Backoff
// ============================================================================

/// Send ICMPv6 echo requests to unconfirmed SLAAC addresses using exponential
/// backoff with jitter.
///
/// Iterates all leases and their SLAAC address entries. For each address with
/// a non-zero backoff whose ping time has elapsed, constructs and sends an
/// ICMPv6 Echo Request packet. Handles `EHOSTUNREACH` by abandoning the
/// address after 12 retries.
///
/// # Exponential Backoff Schedule
///
/// - Base delay: `1 << (backoff - 1)` seconds (1, 2, 4, 8, ..., 2048)
/// - Jitter: `rand16() / 21785` seconds (≈0–3s) for all retries
/// - Extra jitter: `rand16() / 4000` seconds (≈0–16s) for backoff > 4
/// - Maximum backoff counter: 12 (abandoned on EHOSTUNREACH at this level)
///
/// # Arguments
///
/// * `now` — Current timestamp (seconds since epoch).
/// * `daemon` — Daemon state providing ICMPv6 socket FD and DHCPv6 contexts.
/// * `leases` — Mutable slice of all DHCP leases to scan for pending probes.
///
/// # Returns
///
/// `Some(time_t)` with the earliest next ping time across all entries, or
/// `None` if no pings are pending. The caller uses this to schedule the
/// next `periodic_slaac` invocation.
///
/// # C Equivalent
///
/// Direct port of `periodic_slaac()` (slaac.c lines 345-414).
pub fn periodic_slaac(
    now: i64,
    daemon: &DaemonState,
    leases: &mut [DhcpLease],
) -> Option<i64> {
    // Initialize ping_id on first call (C lines 360-361)
    let ping_id = get_ping_id();

    // Get the ICMPv6 socket fd from daemon state
    #[cfg(feature = "dhcp")]
    let icmp6_fd: RawFd = {
        let dhcp_state = daemon.dhcp.borrow();
        dhcp_state.icmp6_fd
    };
    #[cfg(not(feature = "dhcp"))]
    let icmp6_fd: RawFd = -1;

    if icmp6_fd < 0 {
        return None;
    }

    let mut next_event: Option<i64> = None;

    for lease in leases.iter_mut() {
        for slaac in lease.slaac_addresses.iter_mut() {
            // Skip confirmed (backoff==0) or abandoned (ping_time==0) entries
            // (C lines 367-368)
            if slaac.backoff == 0 || slaac.ping_time == 0 {
                continue;
            }

            if slaac.ping_time <= now {
                // Construct ICMPv6 Echo Request (C lines 372-383)
                let ping = PingPacket::new_echo_request(ping_id);
                let ping_bytes = ping.to_bytes();

                // Build destination sockaddr_in6 (C lines 385-391)
                let dest = nix::sys::socket::SockaddrIn6::from(
                    std::net::SocketAddrV6::new(slaac.addr, 0, 0, 0),
                );

                // Send the echo request (C lines 393-397)
                let send_result = nix::sys::socket::sendto(
                    icmp6_fd,
                    &ping_bytes,
                    &dest,
                    nix::sys::socket::MsgFlags::empty(),
                );

                match send_result {
                    Err(Errno::EHOSTUNREACH) if slaac.backoff >= 12 => {
                        // Give up — host unreachable after max retries (C line 397)
                        slaac.ping_time = 0;
                    }
                    _ => {
                        // Calculate next ping time with exponential backoff + jitter
                        // (C lines 400-404)
                        let delay = 1i64 << (slaac.backoff - 1);
                        let jitter1 = rand16() as i64 / 21785; // 0-3 seconds
                        let jitter2 = if slaac.backoff > 4 {
                            rand16() as i64 / 4000 // 0-16 seconds
                        } else {
                            0
                        };
                        slaac.ping_time = now + delay + jitter1 + jitter2;

                        if slaac.backoff < 12 {
                            slaac.backoff += 1;
                        }
                    }
                }
            }

            // Track earliest next event (C lines 408-410)
            if slaac.ping_time != 0 {
                next_event = Some(match next_event {
                    Some(existing) if existing <= slaac.ping_time => existing,
                    _ => slaac.ping_time,
                });
            }
        }
    }

    next_event
}

// ============================================================================
// slaac_ping_reply — Process ICMPv6 Echo Reply for Address Confirmation
// ============================================================================

/// Process an ICMPv6 echo reply to confirm a SLAAC address is alive.
///
/// Validates that the echo reply matches our ping identifier, then searches
/// all leases for a pending SLAAC address matching the sender. On match,
/// marks the address as confirmed (`backoff = 0`) and logs the confirmation.
///
/// # Arguments
///
/// * `sender` — IPv6 address that sent the echo reply (source address).
/// * `packet` — Raw ICMPv6 echo reply packet bytes.
/// * `interface` — Interface name where the reply was received (for logging).
/// * `leases` — Mutable slice of all DHCP leases to search for matching addresses.
/// * `daemon` — Daemon state for accessing option flags (quiet mode check).
///
/// # Side Effects
///
/// - Sets `backoff = 0` on matching SLAAC address entries (confirmation)
/// - Logs "SLAAC-CONFIRM" message unless `OPT_QUIET_DHCP6` is set
/// - Returns `true` if any addresses were confirmed (caller should trigger
///   DNS update via `lease_update_dns(true)`)
///
/// # C Equivalent
///
/// Direct port of `slaac_ping_reply()` (slaac.c lines 515-536).
pub fn slaac_ping_reply(
    sender: &Ipv6Addr,
    packet: &[u8],
    interface: &str,
    leases: &mut [DhcpLease],
    daemon: &DaemonState,
) -> bool {
    // Parse the PingPacket from raw bytes (C line 519)
    let ping = match PingPacket::from_bytes(packet) {
        Some(p) => p,
        None => return false,
    };

    // Validate the identifier matches our ping_id (C line 522).
    //
    // Byte-order contract:
    //   - `get_ping_id()` returns a host-order u16 (initialized from rand16()).
    //   - `PingPacket::new_echo_request()` stores the identifier in network
    //     (big-endian) byte order in the on-wire ICMPv6 echo packet.
    //   - `PingPacket::from_bytes()` reads the identifier field as big-endian,
    //     so `ping.identifier` is in **network** byte order.
    //   - We therefore convert our host-order ID to big-endian with `.to_be()`
    //     before comparison, ensuring both sides are in the same byte order.
    //
    // On big-endian systems `.to_be()` is a no-op, on little-endian it swaps.
    // This is safe on all architectures because both values are compared in
    // the same (network) byte order.
    let our_id = get_ping_id().to_be();
    if ping.identifier != our_id {
        return false;
    }

    let mut gotone = false;

    // Search all leases for matching SLAAC address (C lines 523-532)
    for lease in leases.iter_mut() {
        for slaac in lease.slaac_addresses.iter_mut() {
            if slaac.backoff != 0 && slaac.addr == *sender {
                // Address confirmed — stop probing (C line 527)
                slaac.backoff = 0;
                gotone = true;

                // Log confirmation unless quiet mode is set (C lines 529-531)
                if !daemon.option_bool(OPT_QUIET_DHCP6) {
                    let hostname = lease
                        .hostname
                        .as_deref()
                        .unwrap_or("<unknown>");
                    info!(
                        "SLAAC-CONFIRM({}) {} {}",
                        interface, sender, hostname
                    );
                }
            }
        }
    }

    gotone
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dhcp::radv::protocol::ICMP6_ECHO_REQUEST;
    use std::net::Ipv6Addr;

    /// Test EUI-64 derivation for Ethernet (ARPHRD_ETHER).
    ///
    /// Example: MAC 00:11:22:33:44:55 with prefix 2001:db8::
    /// Expected: 2001:db8::211:22ff:fe33:4455
    #[test]
    fn test_eui64_ethernet() {
        let prefix = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0);
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let result = derive_eui64_address(&prefix, 64, &mac, ARPHRD_ETHER);
        assert!(result.is_some());
        let addr = result.unwrap();
        let octets = addr.octets();

        // Prefix preserved in bytes 0..8
        assert_eq!(octets[0], 0x20);
        assert_eq!(octets[1], 0x01);
        assert_eq!(octets[2], 0x0d);
        assert_eq!(octets[3], 0xb8);
        assert_eq!(octets[4], 0x00);
        assert_eq!(octets[5], 0x00);
        assert_eq!(octets[6], 0x00);
        assert_eq!(octets[7], 0x00);

        // EUI-64 interface identifier in bytes 8..16
        // mac[0] ^ 0x02 = 0x00 ^ 0x02 = 0x02
        assert_eq!(octets[8], 0x02);
        assert_eq!(octets[9], 0x11);
        assert_eq!(octets[10], 0x22);
        assert_eq!(octets[11], 0xFF);
        assert_eq!(octets[12], 0xFE);
        assert_eq!(octets[13], 0x33);
        assert_eq!(octets[14], 0x44);
        assert_eq!(octets[15], 0x55);

        // Verify against known address
        assert_eq!(
            addr,
            Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0x0211, 0x22ff, 0xfe33, 0x4455)
        );
    }

    /// Test EUI-64 derivation for Token Ring (ARPHRD_IEEE802).
    /// Same algorithm as Ethernet.
    #[test]
    fn test_eui64_token_ring() {
        let prefix = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0);
        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let result = derive_eui64_address(&prefix, 64, &mac, ARPHRD_IEEE802);
        assert!(result.is_some());
        let addr = result.unwrap();
        let octets = addr.octets();

        // mac[0] ^ 0x02 = 0xAA ^ 0x02 = 0xA8
        assert_eq!(octets[8], 0xA8);
        assert_eq!(octets[9], 0xBB);
        assert_eq!(octets[10], 0xCC);
        assert_eq!(octets[11], 0xFF);
        assert_eq!(octets[12], 0xFE);
        assert_eq!(octets[13], 0xDD);
        assert_eq!(octets[14], 0xEE);
        assert_eq!(octets[15], 0xFF);
    }

    /// Test EUI-64 derivation for native EUI-64 (ARPHRD_EUI64).
    /// 8-byte address copied directly with U/L bit flipped.
    #[test]
    fn test_eui64_native() {
        let prefix = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0);
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let result = derive_eui64_address(&prefix, 64, &mac, ARPHRD_EUI64);
        assert!(result.is_some());
        let addr = result.unwrap();
        let octets = addr.octets();

        // Byte 8 = mac[0] ^ 0x02 = 0x00 ^ 0x02 = 0x02
        assert_eq!(octets[8], 0x02);
        assert_eq!(octets[9], 0x11);
        assert_eq!(octets[10], 0x22);
        assert_eq!(octets[11], 0x33);
        assert_eq!(octets[12], 0x44);
        assert_eq!(octets[13], 0x55);
        assert_eq!(octets[14], 0x66);
        assert_eq!(octets[15], 0x77);
    }

    /// Test EUI-64 derivation for FireWire (ARPHRD_IEEE1394).
    /// 8-byte address copied WITHOUT U/L bit flip.
    #[test]
    fn test_eui64_firewire() {
        let prefix = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0);
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let result = derive_eui64_address(&prefix, 64, &mac, ARPHRD_IEEE1394);
        assert!(result.is_some());
        let addr = result.unwrap();
        let octets = addr.octets();

        // No XOR for FireWire — byte 8 stays as mac[0]
        assert_eq!(octets[8], 0x00);
        assert_eq!(octets[9], 0x11);
        assert_eq!(octets[10], 0x22);
        assert_eq!(octets[11], 0x33);
        assert_eq!(octets[12], 0x44);
        assert_eq!(octets[13], 0x55);
        assert_eq!(octets[14], 0x66);
        assert_eq!(octets[15], 0x77);
    }

    /// Test unsupported hardware type returns None.
    #[test]
    fn test_eui64_unsupported() {
        let prefix = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0);
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        // Hardware type 99 is not supported
        let result = derive_eui64_address(&prefix, 64, &mac, 99);
        assert!(result.is_none());
    }

    /// Test Ethernet with insufficient MAC length returns None.
    #[test]
    fn test_eui64_short_mac() {
        let prefix = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0);
        let mac = [0x00, 0x11, 0x22]; // Only 3 bytes, need 6
        let result = derive_eui64_address(&prefix, 64, &mac, ARPHRD_ETHER);
        assert!(result.is_none());
    }

    /// Test EUI-64 with insufficient MAC length returns None.
    #[test]
    fn test_eui64_short_eui64_mac() {
        let prefix = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0);
        let mac = [0x00, 0x11, 0x22, 0x33]; // Only 4 bytes, need 8
        let result = derive_eui64_address(&prefix, 64, &mac, ARPHRD_EUI64);
        assert!(result.is_none());
    }

    /// Test that the prefix portion is preserved correctly.
    #[test]
    fn test_prefix_preservation() {
        let prefix = Ipv6Addr::new(0xFD00, 0x1234, 0x5678, 0x9ABC, 0, 0, 0, 0);
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let result = derive_eui64_address(&prefix, 64, &mac, ARPHRD_ETHER);
        assert!(result.is_some());
        let addr = result.unwrap();
        let octets = addr.octets();

        // First 8 bytes should match the prefix
        assert_eq!(octets[0], 0xFD);
        assert_eq!(octets[1], 0x00);
        assert_eq!(octets[2], 0x12);
        assert_eq!(octets[3], 0x34);
        assert_eq!(octets[4], 0x56);
        assert_eq!(octets[5], 0x78);
        assert_eq!(octets[6], 0x9A);
        assert_eq!(octets[7], 0xBC);
    }

    /// Test PingPacket round-trip serialization.
    #[test]
    fn test_ping_packet_roundtrip() {
        let ping = PingPacket::new_echo_request(0x1234);
        let bytes = ping.to_bytes();
        assert_eq!(bytes.len(), PingPacket::SIZE);

        let parsed = PingPacket::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.msg_type, ICMP6_ECHO_REQUEST);
        assert_eq!(parsed.code, 0);
        assert_eq!(parsed.checksum, 0);
        assert_eq!(parsed.identifier, ping.identifier);
        assert_eq!(parsed.sequence_no, 0);
    }

    /// Test get_ping_id returns a non-zero value.
    #[test]
    fn test_get_ping_id_nonzero() {
        let id = get_ping_id();
        assert_ne!(id, 0);
    }

    /// Test get_ping_id returns the same value on repeated calls.
    #[test]
    fn test_get_ping_id_stable() {
        let id1 = get_ping_id();
        let id2 = get_ping_id();
        assert_eq!(id1, id2);
    }
}

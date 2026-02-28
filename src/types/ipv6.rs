//! IPv6 address classification and manipulation helpers.
//!
//! This module replaces the C macros from `src/ip6addr.h` with an idiomatic Rust
//! extension trait on [`std::net::Ipv6Addr`]. The original C header provided three
//! address-testing macros (`IN6_IS_ADDR_ULA`, `IN6_IS_ADDR_ULA_ZERO`,
//! `IN6_IS_ADDR_LINK_LOCAL_ZERO`) that accessed raw `uint32_t` arrays with `htonl()`
//! byte-order conversion. In Rust, [`Ipv6Addr::octets()`] returns bytes in network
//! order, so direct byte comparisons achieve identical semantics without `unsafe` code.
//!
//! Beyond the original three macros, this module provides additional IPv6 utility
//! methods required by the DHCPv6 and Router Advertisement subsystems:
//! - Prefix matching for address pool and route filtering
//! - SLAAC EUI-64 address derivation from MAC addresses
//! - Multicast scope classification for group membership
//! - Well-known multicast address constants for DHCPv6 and RA
//!
//! # Examples
//!
//! ```
//! use std::net::Ipv6Addr;
//! use dnsmasq::types::ipv6::Ipv6AddrExt;
//!
//! let ula = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
//! assert!(ula.is_ula());
//! assert!(!ula.is_ula_zero());
//!
//! let ula_prefix = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0);
//! assert!(ula_prefix.is_ula());
//! assert!(ula_prefix.is_ula_zero());
//!
//! let link_local_prefix = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0);
//! assert!(link_local_prefix.is_link_local_zero());
//! ```

use std::net::Ipv6Addr;

/// Extension trait for IPv6 address classification and manipulation.
///
/// Replaces C macros from `src/ip6addr.h` with idiomatic Rust methods on
/// [`std::net::Ipv6Addr`]. These utilities extend the standard library's
/// built-in predicates with dnsmasq-specific checks for:
/// - Unique Local Addresses (ULA) per RFC 4193
/// - Zero-valued address prefixes used in DHCPv6 and Router Advertisement
/// - Prefix matching for DHCPv6 address pool filtering
/// - SLAAC EUI-64 address derivation from MAC addresses
/// - Multicast scope classification
pub trait Ipv6AddrExt {
    /// Test if this IPv6 address is a Unique Local Address (ULA) per RFC 4193.
    ///
    /// Returns `true` for any address in the fd00::/8 range. ULAs are intended
    /// for local communications within a site and are not globally routable.
    /// The fc00::/8 range is reserved but not currently used; only fd00::/8
    /// addresses are considered valid ULAs in practice.
    ///
    /// Replaces: C macro `IN6_IS_ADDR_ULA(a)` from `ip6addr.h` lines 86-88.
    ///
    /// The C macro checks: `(s6_addr32[0] & htonl(0xff000000)) == htonl(0xfd000000)`.
    /// In Rust, `octets()[0] == 0xfd` is equivalent since `octets()` returns bytes
    /// in network byte order.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::Ipv6Addr;
    /// use dnsmasq::types::ipv6::Ipv6AddrExt;
    ///
    /// assert!(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1).is_ula());
    /// assert!(Ipv6Addr::new(0xfd12, 0x3456, 0, 0, 0, 0, 0, 1).is_ula());
    /// assert!(!Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1).is_ula());
    /// assert!(!Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).is_ula());
    /// ```
    fn is_ula(&self) -> bool;

    /// Test if this IPv6 address is exactly fd00:: (ULA prefix with zero interface ID).
    ///
    /// Returns `true` only for the exact address `fd00:0000:0000:0000:0000:0000:0000:0000`.
    /// Used in DHCPv6 prefix delegation to identify unassigned ULA network addresses.
    /// This is more restrictive than [`is_ula()`](Ipv6AddrExt::is_ula), which matches
    /// any address in the fd00::/8 range.
    ///
    /// Replaces: C macro `IN6_IS_ADDR_ULA_ZERO(a)` from `ip6addr.h` lines 128-132.
    ///
    /// The C macro checks all four 32-bit words:
    /// `s6_addr32[0] == htonl(0xfd000000) && s6_addr32[1..3] == 0`.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::Ipv6Addr;
    /// use dnsmasq::types::ipv6::Ipv6AddrExt;
    ///
    /// assert!(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0).is_ula_zero());
    /// assert!(!Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1).is_ula_zero());
    /// assert!(!Ipv6Addr::new(0xfd12, 0, 0, 0, 0, 0, 0, 0).is_ula_zero());
    /// ```
    fn is_ula_zero(&self) -> bool;

    /// Test if this IPv6 address is exactly fe80:: (link-local prefix with zero interface ID).
    ///
    /// Returns `true` only for the exact address `fe80:0000:0000:0000:0000:0000:0000:0000`.
    /// Used in Router Advertisement prefix information options and DHCPv6 address range
    /// specifications to indicate the link-local network segment without a specific host.
    ///
    /// Replaces: C macro `IN6_IS_ADDR_LINK_LOCAL_ZERO(a)` from `ip6addr.h` lines 179-183.
    ///
    /// The C macro checks all four 32-bit words:
    /// `s6_addr32[0] == htonl(0xfe800000) && s6_addr32[1..3] == 0`.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::Ipv6Addr;
    /// use dnsmasq::types::ipv6::Ipv6AddrExt;
    ///
    /// assert!(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0).is_link_local_zero());
    /// assert!(!Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1).is_link_local_zero());
    /// assert!(!Ipv6Addr::new(0xfe80, 1, 0, 0, 0, 0, 0, 0).is_link_local_zero());
    /// ```
    fn is_link_local_zero(&self) -> bool;

    /// Check if this address matches a given prefix (network/prefix_len).
    ///
    /// Compares the first `prefix_len` bits of this address against the corresponding
    /// bits of `prefix`. Used for DHCPv6 address pool matching and Router Advertisement
    /// prefix filtering.
    ///
    /// # Arguments
    ///
    /// * `prefix` — The network prefix to compare against.
    /// * `prefix_len` — Number of significant bits in the prefix (0–128).
    ///   A value of 0 matches all addresses; a value of 128 requires an exact match.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::Ipv6Addr;
    /// use dnsmasq::types::ipv6::Ipv6AddrExt;
    ///
    /// let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 1);
    /// let prefix = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0);
    /// assert!(addr.matches_prefix(&prefix, 32));
    /// assert!(addr.matches_prefix(&prefix, 48));
    /// assert!(!addr.matches_prefix(&prefix, 64));
    /// ```
    fn matches_prefix(&self, prefix: &Ipv6Addr, prefix_len: u8) -> bool;

    /// Generate a SLAAC EUI-64 address from a /64 prefix and a MAC address.
    ///
    /// Constructs an IPv6 address by combining the upper 64 bits of `prefix` with
    /// an EUI-64 interface identifier derived from the 48-bit MAC address. The EUI-64
    /// is formed by:
    ///
    /// 1. Splitting the MAC at byte 3: `[OUI_0, OUI_1, OUI_2 | DEV_0, DEV_1, DEV_2]`
    /// 2. Inserting `0xFF, 0xFE` between the OUI and device portions
    /// 3. Flipping the universal/local (U/L) bit (bit 6 of byte 0)
    ///
    /// This matches the EUI-64 derivation specified in RFC 4862 Section 5.3 and
    /// RFC 2464 Section 4, used for SLAAC address assignment on Ethernet interfaces.
    ///
    /// # Arguments
    ///
    /// * `prefix` — The /64 network prefix. Only the upper 64 bits are used.
    /// * `mac` — The 6-byte Ethernet MAC address.
    ///
    /// # Returns
    ///
    /// A new `Ipv6Addr` combining the prefix and the EUI-64 interface identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::Ipv6Addr;
    /// use dnsmasq::types::ipv6::Ipv6AddrExt;
    ///
    /// let prefix = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0);
    /// let mac: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    /// let result = Ipv6Addr::from_prefix_and_mac(&prefix, &mac);
    /// // EUI-64: 02:11:22:ff:fe:33:44:55
    /// let expected = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0x0211, 0x22ff, 0xfe33, 0x4455);
    /// assert_eq!(result, expected);
    /// ```
    fn from_prefix_and_mac(prefix: &Ipv6Addr, mac: &[u8; 6]) -> Ipv6Addr;

    /// Check if this is a multicast address with the given scope value.
    ///
    /// IPv6 multicast addresses have the format `ff<flags><scope>::`. This method
    /// verifies that the first byte is `0xFF` and the low nibble of the second byte
    /// (the scope field) matches the provided `scope` value.
    ///
    /// Common scope values are defined in the [`multicast_scope`] module.
    ///
    /// # Arguments
    ///
    /// * `scope` — The multicast scope value (low nibble, 0x0–0xF).
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::Ipv6Addr;
    /// use dnsmasq::types::ipv6::{Ipv6AddrExt, multicast_scope};
    ///
    /// let all_nodes = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
    /// assert!(all_nodes.is_multicast_scope(multicast_scope::LINK_LOCAL));
    /// assert!(!all_nodes.is_multicast_scope(multicast_scope::SITE_LOCAL));
    /// ```
    fn is_multicast_scope(&self, scope: u8) -> bool;
}

impl Ipv6AddrExt for Ipv6Addr {
    #[inline]
    fn is_ula(&self) -> bool {
        // C equivalent: (s6_addr32[0] & htonl(0xff000000)) == htonl(0xfd000000)
        // Ipv6Addr::octets() returns bytes in network byte order, so octets[0]
        // corresponds to the most-significant byte of s6_addr32[0] after htonl.
        let octets = self.octets();
        octets[0] == 0xfd
    }

    #[inline]
    fn is_ula_zero(&self) -> bool {
        // C equivalent: all four 32-bit words checked against fd00:: with zeros
        // fd00:: = [0xfd, 0x00, 0x00, ..., 0x00] (16 bytes)
        let octets = self.octets();
        octets[0] == 0xfd && octets[1] == 0 && octets[2..].iter().all(|&b| b == 0)
    }

    #[inline]
    fn is_link_local_zero(&self) -> bool {
        // C equivalent: s6_addr32[0] == htonl(0xfe800000) && s6_addr32[1..3] == 0
        // fe80:: = [0xfe, 0x80, 0x00, ..., 0x00] (16 bytes)
        let octets = self.octets();
        octets[0] == 0xfe && octets[1] == 0x80 && octets[2..].iter().all(|&b| b == 0)
    }

    #[inline]
    fn matches_prefix(&self, prefix: &Ipv6Addr, prefix_len: u8) -> bool {
        // Convert both addresses to 128-bit integers in big-endian order and
        // compare only the first `prefix_len` bits using a bitmask.
        if prefix_len == 0 {
            return true;
        }
        let self_bits = u128::from_be_bytes(self.octets());
        let prefix_bits = u128::from_be_bytes(prefix.octets());
        if prefix_len >= 128 {
            return self_bits == prefix_bits;
        }
        let mask = !0u128 << (128 - prefix_len as u32);
        (self_bits & mask) == (prefix_bits & mask)
    }

    fn from_prefix_and_mac(prefix: &Ipv6Addr, mac: &[u8; 6]) -> Ipv6Addr {
        let mut octets = prefix.octets();

        // Construct EUI-64 interface identifier from the 48-bit MAC address.
        // The EUI-64 occupies bytes [8..16] of the IPv6 address (the lower 64 bits).

        // Byte 8: First byte of MAC with the universal/local (U/L) bit flipped.
        // The U/L bit is bit 1 of byte 0 (counting from LSB) — i.e. 0x02 mask.
        // Flipping: 0 (universally administered) → 1 (locally administered) and vice versa.
        octets[8] = mac[0] ^ 0x02;
        // Bytes 9-10: Remaining OUI bytes from MAC
        octets[9] = mac[1];
        octets[10] = mac[2];
        // Bytes 11-12: Insert 0xFF:0xFE between OUI and device ID per EUI-64 spec
        octets[11] = 0xff;
        octets[12] = 0xfe;
        // Bytes 13-15: Device portion of MAC address
        octets[13] = mac[3];
        octets[14] = mac[4];
        octets[15] = mac[5];

        Ipv6Addr::from(octets)
    }

    #[inline]
    fn is_multicast_scope(&self, scope: u8) -> bool {
        // IPv6 multicast addresses: first byte is 0xFF, second byte encodes
        // flags (high nibble) and scope (low nibble).
        let octets = self.octets();
        octets[0] == 0xff && (octets[1] & 0x0f) == (scope & 0x0f)
    }
}

/// IPv6 multicast scope values used in DHCPv6 and Router Advertisement processing.
///
/// These constants correspond to the scope field (low nibble of byte 1) in IPv6
/// multicast addresses (`ff<flags><scope>::`). They are used with
/// [`Ipv6AddrExt::is_multicast_scope()`] to classify multicast group membership.
///
/// Reference: RFC 7346 — IPv6 Multicast Address Scopes.
pub mod multicast_scope {
    /// Interface-local scope (1).
    ///
    /// Packets with this scope are not forwarded beyond the originating interface.
    /// Used for loopback multicast and node-internal communication.
    pub const INTERFACE_LOCAL: u8 = 1;

    /// Link-local scope (2).
    ///
    /// Packets with this scope are not forwarded beyond the local link (subnet).
    /// This is the most common scope for DHCPv6 and Router Advertisement multicast
    /// groups (e.g., ff02::1 all-nodes, ff02::2 all-routers, ff02::1:2 DHCPv6).
    pub const LINK_LOCAL: u8 = 2;

    /// Site-local scope (5).
    ///
    /// Packets with this scope may be forwarded within a site but not beyond.
    /// Used for DHCPv6 all-servers multicast (ff05::1:3).
    pub const SITE_LOCAL: u8 = 5;
}

/// Well-known DHCPv6 multicast addresses defined in RFC 3315 Section 5.1.
///
/// These addresses are used by DHCPv6 clients, relay agents, and servers for
/// multicast-based message exchange. They are compile-time constants for
/// zero-cost access.
pub mod dhcpv6_multicast {
    use std::net::Ipv6Addr;

    /// All DHCP Relay Agents and Servers — `ff02::1:2` (link-local scope).
    ///
    /// DHCPv6 clients send SOLICIT, REQUEST, CONFIRM, RENEW, REBIND, RELEASE,
    /// DECLINE, and INFORMATION-REQUEST messages to this multicast address.
    /// Relay agents also use this address to forward client messages.
    ///
    /// Reference: RFC 3315 Section 5.1, RFC 8415 Section 7.1.
    pub const ALL_DHCP_RELAY_AGENTS_AND_SERVERS: Ipv6Addr =
        Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 2);

    /// All DHCP Servers — `ff05::1:3` (site-local scope).
    ///
    /// Relay agents forward messages to this address when they need to reach
    /// all DHCPv6 servers within the site. This is a site-scoped address that
    /// may be forwarded beyond the local link.
    ///
    /// Reference: RFC 3315 Section 5.1, RFC 8415 Section 7.1.
    pub const ALL_DHCP_SERVERS: Ipv6Addr = Ipv6Addr::new(0xff05, 0, 0, 0, 0, 0, 1, 3);
}

/// Well-known Router Advertisement multicast addresses defined in RFC 4861.
///
/// These addresses are used for IPv6 Neighbor Discovery Protocol (NDP) messages,
/// including Router Solicitation (RS) and Router Advertisement (RA) exchanges.
pub mod ra_multicast {
    use std::net::Ipv6Addr;

    /// All-nodes multicast — `ff02::1` (link-local scope).
    ///
    /// Routers send unsolicited Router Advertisements to this address to inform
    /// all IPv6 nodes on the link about available prefixes, default routes,
    /// and other network parameters.
    ///
    /// Reference: RFC 4291 Section 2.7.1, RFC 4861 Section 6.1.
    pub const ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);

    /// All-routers multicast — `ff02::2` (link-local scope).
    ///
    /// Hosts send Router Solicitation messages to this address to prompt routers
    /// to send immediate Router Advertisements rather than waiting for the next
    /// periodic advertisement interval.
    ///
    /// Reference: RFC 4291 Section 2.7.1, RFC 4861 Section 6.2.
    pub const ALL_ROUTERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    // -----------------------------------------------------------------------
    // is_ula() tests — RFC 4193 Unique Local Address detection (fd00::/8)
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_ula_with_fd00_prefix() {
        // fd00::1 — basic ULA with host portion set
        assert!(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1).is_ula());
    }

    #[test]
    fn test_is_ula_with_fd_prefix_varied_global_id() {
        // fd12:3456::1 — ULA with non-zero global ID and subnet fields
        assert!(Ipv6Addr::new(0xfd12, 0x3456, 0, 0, 0, 0, 0, 1).is_ula());
    }

    #[test]
    fn test_is_ula_with_fd_all_ones() {
        // fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff — maximum ULA address
        assert!(Ipv6Addr::new(0xfdff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff).is_ula());
    }

    #[test]
    fn test_is_ula_rejects_link_local() {
        // fe80::1 — link-local, not ULA
        assert!(!Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1).is_ula());
    }

    #[test]
    fn test_is_ula_rejects_global_unicast() {
        // 2001:db8::1 — documentation/global unicast, not ULA
        assert!(!Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).is_ula());
    }

    #[test]
    fn test_is_ula_rejects_unspecified() {
        // :: — unspecified address
        assert!(!Ipv6Addr::UNSPECIFIED.is_ula());
    }

    #[test]
    fn test_is_ula_rejects_loopback() {
        // ::1 — loopback
        assert!(!Ipv6Addr::LOCALHOST.is_ula());
    }

    #[test]
    fn test_is_ula_rejects_multicast() {
        // ff02::1 — multicast, not ULA
        assert!(!Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1).is_ula());
    }

    #[test]
    fn test_is_ula_rejects_fc_prefix() {
        // fc00::1 — Reserved ULA prefix (fc00::/8) that dnsmasq does NOT match.
        // The C macro specifically checks for 0xFD in the first byte, not fc00::/7.
        assert!(!Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1).is_ula());
    }

    // -----------------------------------------------------------------------
    // is_ula_zero() tests — exact fd00:: detection
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_ula_zero_exact_match() {
        // fd00:: — exactly the ULA prefix with zero interface ID
        assert!(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0).is_ula_zero());
    }

    #[test]
    fn test_is_ula_zero_rejects_nonzero_host() {
        // fd00::1 — ULA but not zero (host bits set)
        assert!(!Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1).is_ula_zero());
    }

    #[test]
    fn test_is_ula_zero_rejects_nonzero_global_id() {
        // fd12:: — different ULA global ID (byte 1 is 0x12, not 0x00)
        assert!(!Ipv6Addr::new(0xfd12, 0, 0, 0, 0, 0, 0, 0).is_ula_zero());
    }

    #[test]
    fn test_is_ula_zero_rejects_nonzero_subnet() {
        // fd00:0:1:: — nonzero subnet portion
        assert!(!Ipv6Addr::new(0xfd00, 0, 1, 0, 0, 0, 0, 0).is_ula_zero());
    }

    #[test]
    fn test_is_ula_zero_rejects_link_local() {
        // fe80:: — link-local zero, not ULA zero
        assert!(!Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0).is_ula_zero());
    }

    #[test]
    fn test_is_ula_zero_rejects_unspecified() {
        assert!(!Ipv6Addr::UNSPECIFIED.is_ula_zero());
    }

    // -----------------------------------------------------------------------
    // is_link_local_zero() tests — exact fe80:: detection
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_link_local_zero_exact_match() {
        // fe80:: — exactly the link-local prefix with zero interface ID
        assert!(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0).is_link_local_zero());
    }

    #[test]
    fn test_is_link_local_zero_rejects_nonzero_host() {
        // fe80::1 — link-local but interface ID is not zero
        assert!(!Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1).is_link_local_zero());
    }

    #[test]
    fn test_is_link_local_zero_rejects_nonzero_word1() {
        // fe80:1:: — second 16-bit segment is non-zero
        assert!(!Ipv6Addr::new(0xfe80, 1, 0, 0, 0, 0, 0, 0).is_link_local_zero());
    }

    #[test]
    fn test_is_link_local_zero_rejects_ula() {
        // fd00:: — ULA, not link-local
        assert!(!Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0).is_link_local_zero());
    }

    #[test]
    fn test_is_link_local_zero_rejects_unspecified() {
        assert!(!Ipv6Addr::UNSPECIFIED.is_link_local_zero());
    }

    #[test]
    fn test_is_link_local_zero_rejects_eui64_interface_id() {
        // fe80::0211:22ff:fe33:4455 — link-local with EUI-64 interface ID
        assert!(
            !Ipv6Addr::new(0xfe80, 0, 0, 0, 0x0211, 0x22ff, 0xfe33, 0x4455)
                .is_link_local_zero()
        );
    }

    // -----------------------------------------------------------------------
    // matches_prefix() tests — variable-length prefix comparison
    // -----------------------------------------------------------------------

    #[test]
    fn test_matches_prefix_within_32_bits() {
        let addr = Ipv6Addr::new(0x2001, 0x0db8, 0, 1, 0, 0, 0, 1);
        let prefix = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0);
        // First 32 bits match: 2001:0db8
        assert!(addr.matches_prefix(&prefix, 32));
    }

    #[test]
    fn test_matches_prefix_within_48_bits() {
        let addr = Ipv6Addr::new(0x2001, 0x0db8, 0, 1, 0, 0, 0, 1);
        let prefix = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0);
        // First 48 bits match: 2001:0db8:0000
        assert!(addr.matches_prefix(&prefix, 48));
    }

    #[test]
    fn test_matches_prefix_mismatch_at_64() {
        let addr = Ipv6Addr::new(0x2001, 0x0db8, 0, 1, 0, 0, 0, 1);
        let prefix = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0);
        // Segment 3 differs: addr has 1, prefix has 0 → mismatch at /64
        assert!(!addr.matches_prefix(&prefix, 64));
    }

    #[test]
    fn test_matches_prefix_zero_length() {
        // prefix_len=0 matches everything
        let addr = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
        let prefix = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0);
        assert!(addr.matches_prefix(&prefix, 0));
    }

    #[test]
    fn test_matches_prefix_full_128() {
        // prefix_len=128 requires exact match
        let addr = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
        assert!(addr.matches_prefix(&addr, 128));

        let other = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 2);
        assert!(!addr.matches_prefix(&other, 128));
    }

    #[test]
    fn test_matches_prefix_single_bit() {
        // prefix_len=1 — first bit must match
        let addr_2xxx = Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0);
        let addr_3xxx = Ipv6Addr::new(0x3001, 0, 0, 0, 0, 0, 0, 0);
        // 0x2001 = 0010 ..., 0x3001 = 0011 ...
        // First bit is 0 for both → they match at /1
        assert!(addr_2xxx.matches_prefix(&addr_3xxx, 1));

        // ff02:: first bit is 1, 2001:: first bit is 0
        let mcast = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
        assert!(!mcast.matches_prefix(&addr_2xxx, 1));
    }

    #[test]
    fn test_matches_prefix_unspecified() {
        // Unspecified address with /0 prefix matches anything
        assert!(Ipv6Addr::UNSPECIFIED.matches_prefix(&Ipv6Addr::UNSPECIFIED, 0));
        // Unspecified address at /128 matches only itself
        assert!(Ipv6Addr::UNSPECIFIED.matches_prefix(&Ipv6Addr::UNSPECIFIED, 128));
    }

    // -----------------------------------------------------------------------
    // from_prefix_and_mac() tests — SLAAC EUI-64 derivation
    // -----------------------------------------------------------------------

    #[test]
    fn test_eui64_from_mac_basic() {
        let prefix = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0);
        let mac: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let result = Ipv6Addr::from_prefix_and_mac(&prefix, &mac);

        // EUI-64: 0x00 ^ 0x02 = 0x02, insert FF:FE → 02:11:22:ff:fe:33:44:55
        let expected = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0x0211, 0x22ff, 0xfe33, 0x4455);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_eui64_from_mac_with_ul_bit_set() {
        let prefix = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0);
        // MAC 02:00:00:00:00:01 — has U/L bit already set
        let mac: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let result = Ipv6Addr::from_prefix_and_mac(&prefix, &mac);

        // 0x02 ^ 0x02 = 0x00 → U/L bit flipped to 0
        let expected = Ipv6Addr::new(0xfe80, 0, 0, 0, 0x0000, 0x00ff, 0xfe00, 0x0001);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_eui64_from_mac_preserves_prefix() {
        let prefix = Ipv6Addr::new(0xfd12, 0x3456, 0x789a, 0xbcde, 0, 0, 0, 0);
        let mac: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let result = Ipv6Addr::from_prefix_and_mac(&prefix, &mac);

        // Verify upper 64 bits are the prefix
        let octets = result.octets();
        assert_eq!(octets[0], 0xfd);
        assert_eq!(octets[1], 0x12);
        assert_eq!(octets[2], 0x34);
        assert_eq!(octets[3], 0x56);
        assert_eq!(octets[4], 0x78);
        assert_eq!(octets[5], 0x9a);
        assert_eq!(octets[6], 0xbc);
        assert_eq!(octets[7], 0xde);

        // Verify EUI-64 in lower 64 bits: 0xaa^0x02=0xa8, bb, cc, ff, fe, dd, ee, ff
        assert_eq!(octets[8], 0xa8); // 0xaa ^ 0x02
        assert_eq!(octets[9], 0xbb);
        assert_eq!(octets[10], 0xcc);
        assert_eq!(octets[11], 0xff);
        assert_eq!(octets[12], 0xfe);
        assert_eq!(octets[13], 0xdd);
        assert_eq!(octets[14], 0xee);
        assert_eq!(octets[15], 0xff);
    }

    #[test]
    fn test_eui64_all_zeros_mac() {
        let prefix = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0);
        let mac: [u8; 6] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let result = Ipv6Addr::from_prefix_and_mac(&prefix, &mac);

        // 0x00 ^ 0x02 = 0x02, rest of MAC is 0, insert FF:FE
        let expected = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0x0200, 0x00ff, 0xfe00, 0x0000);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_eui64_broadcast_mac() {
        let prefix = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0);
        let mac: [u8; 6] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let result = Ipv6Addr::from_prefix_and_mac(&prefix, &mac);

        // 0xff ^ 0x02 = 0xfd, rest is 0xff, insert FF:FE
        let expected = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0xfdff, 0xffff, 0xfeff, 0xffff);
        assert_eq!(result, expected);
    }

    // -----------------------------------------------------------------------
    // is_multicast_scope() tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_multicast_scope_link_local() {
        let all_nodes = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
        assert!(all_nodes.is_multicast_scope(multicast_scope::LINK_LOCAL));
    }

    #[test]
    fn test_multicast_scope_site_local() {
        let site_mcast = Ipv6Addr::new(0xff05, 0, 0, 0, 0, 0, 1, 3);
        assert!(site_mcast.is_multicast_scope(multicast_scope::SITE_LOCAL));
    }

    #[test]
    fn test_multicast_scope_interface_local() {
        let iface_mcast = Ipv6Addr::new(0xff01, 0, 0, 0, 0, 0, 0, 1);
        assert!(iface_mcast.is_multicast_scope(multicast_scope::INTERFACE_LOCAL));
    }

    #[test]
    fn test_multicast_scope_mismatch() {
        let link_local_mcast = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
        assert!(!link_local_mcast.is_multicast_scope(multicast_scope::SITE_LOCAL));
    }

    #[test]
    fn test_multicast_scope_rejects_non_multicast() {
        // Unicast address — first byte is not 0xff
        let unicast = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
        assert!(!unicast.is_multicast_scope(multicast_scope::LINK_LOCAL));
    }

    #[test]
    fn test_multicast_scope_rejects_ula() {
        let ula = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
        assert!(!ula.is_multicast_scope(multicast_scope::LINK_LOCAL));
    }

    // -----------------------------------------------------------------------
    // Well-known multicast address constant tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_dhcpv6_multicast_relay_agents_and_servers() {
        let addr = dhcpv6_multicast::ALL_DHCP_RELAY_AGENTS_AND_SERVERS;
        assert_eq!(addr, Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 2));
        assert!(addr.is_multicast_scope(multicast_scope::LINK_LOCAL));
    }

    #[test]
    fn test_dhcpv6_multicast_all_servers() {
        let addr = dhcpv6_multicast::ALL_DHCP_SERVERS;
        assert_eq!(addr, Ipv6Addr::new(0xff05, 0, 0, 0, 0, 0, 1, 3));
        assert!(addr.is_multicast_scope(multicast_scope::SITE_LOCAL));
    }

    #[test]
    fn test_ra_multicast_all_nodes() {
        let addr = ra_multicast::ALL_NODES;
        assert_eq!(addr, Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1));
        assert!(addr.is_multicast_scope(multicast_scope::LINK_LOCAL));
    }

    #[test]
    fn test_ra_multicast_all_routers() {
        let addr = ra_multicast::ALL_ROUTERS;
        assert_eq!(addr, Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2));
        assert!(addr.is_multicast_scope(multicast_scope::LINK_LOCAL));
    }

    // -----------------------------------------------------------------------
    // Cross-method interaction tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_ula_address_is_not_link_local() {
        let ula = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0);
        assert!(ula.is_ula());
        assert!(ula.is_ula_zero());
        assert!(!ula.is_link_local_zero());
    }

    #[test]
    fn test_link_local_address_is_not_ula() {
        let ll = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0);
        assert!(!ll.is_ula());
        assert!(!ll.is_ula_zero());
        assert!(ll.is_link_local_zero());
    }

    #[test]
    fn test_eui64_result_is_not_link_local_zero() {
        let prefix = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0);
        let mac: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let result = Ipv6Addr::from_prefix_and_mac(&prefix, &mac);
        // EUI-64 address has non-zero interface ID
        assert!(!result.is_link_local_zero());
    }

    #[test]
    fn test_eui64_result_matches_link_local_prefix() {
        let prefix = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0);
        let mac: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let result = Ipv6Addr::from_prefix_and_mac(&prefix, &mac);
        // Should match fe80::/64 prefix
        assert!(result.matches_prefix(&prefix, 10)); // link-local is fe80::/10
        assert!(result.matches_prefix(&prefix, 64)); // full /64 prefix
    }

    #[test]
    fn test_multicast_addresses_are_not_ula_or_link_local_zero() {
        assert!(!dhcpv6_multicast::ALL_DHCP_RELAY_AGENTS_AND_SERVERS.is_ula());
        assert!(!dhcpv6_multicast::ALL_DHCP_RELAY_AGENTS_AND_SERVERS.is_link_local_zero());
        assert!(!ra_multicast::ALL_NODES.is_ula());
        assert!(!ra_multicast::ALL_NODES.is_link_local_zero());
    }
}

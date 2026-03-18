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

//! # IPv6 Address Utility Functions
//!
//! Pure utility functions for IPv6 address classification, replacing C's
//! `src/ip6addr.h` (183 lines). Provides predicates for Unique Local Address
//! (ULA) detection per RFC 4193 and link-local prefix detection per RFC 4291.
//!
//! These functions are used by DHCPv6 (`v6/`) and Router Advertisement (`radv.rs`)
//! modules for address validation during prefix delegation and RA construction.
//!
//! ## C Source Mapping
//! | Rust Function | C Macro | C Line | RFC |
//! |--------------|---------|--------|-----|
//! | `is_ula()` | `IN6_IS_ADDR_ULA` | 86 | RFC 4193 |
//! | `is_ula_zero()` | `IN6_IS_ADDR_ULA_ZERO` | 128 | RFC 4193 |
//! | `is_link_local_zero()` | `IN6_IS_ADDR_LINK_LOCAL_ZERO` | 179 | RFC 4291 §2.5.6 |
//!
//! ## Memory Safety
//! All functions are pure (no side effects, no global state) and stateless.
//! The C macros operated on raw `uint32_t` pointers with network byte order
//! conversion (`htonl`). Rust uses [`Ipv6Addr::octets()`] for safe byte access
//! with no endianness concerns — `octets()` always returns bytes in network
//! (big-endian) order, eliminating the `htonl()` conversion entirely.

use std::net::Ipv6Addr;

/// Test if an IPv6 address is a Unique Local Address (ULA) per RFC 4193.
///
/// ULA addresses have the prefix `fd00::/8` (locally assigned). The `fc00::/7`
/// prefix space is divided into `fc00::/8` (reserved, not yet assigned) and
/// `fd00::/8` (locally assigned). Only `fd00::/8` is currently defined for use,
/// so this function checks specifically for the `0xfd` first octet.
///
/// These addresses are intended for local communications within a site or
/// organization and are not expected to be routable on the global IPv6 internet.
///
/// Replaces C macro `IN6_IS_ADDR_ULA` (`ip6addr.h` line 86):
/// ```c
/// #define IN6_IS_ADDR_ULA(a) \
///     ((((__const uint32_t *) (a))[0] & htonl(0xff000000)) \
///      == htonl(0xfd000000))
/// ```
///
/// # Arguments
/// * `addr` — Reference to the IPv6 address to classify.
///
/// # Returns
/// `true` if the address is in the ULA range (`fd00::/8`), `false` otherwise.
///
/// # Examples
/// ```
/// use std::net::Ipv6Addr;
/// use dnsmasq::dhcp::ip6addr::is_ula;
///
/// assert!(is_ula(&"fd00::1".parse::<Ipv6Addr>().unwrap()));
/// assert!(is_ula(&"fd12:3456:789a::1".parse::<Ipv6Addr>().unwrap()));
/// assert!(!is_ula(&"2001:db8::1".parse::<Ipv6Addr>().unwrap()));
/// assert!(!is_ula(&"fe80::1".parse::<Ipv6Addr>().unwrap()));
/// ```
#[inline]
pub fn is_ula(addr: &Ipv6Addr) -> bool {
    // C original: (a[0] & htonl(0xff000000)) == htonl(0xfd000000)
    // This masks the first 8 bits and checks for 0xfd.
    // In Rust, octets() returns bytes in network order, so we simply
    // compare the first octet directly — no byte-order conversion needed.
    addr.octets()[0] == 0xfd
}

/// Test if an IPv6 address is exactly the ULA prefix `fd00::` with zero
/// interface identifier.
///
/// This specifically detects `fd00:0000:0000:0000:0000:0000:0000:0000`,
/// used in DHCPv6 prefix delegation to identify delegated network ranges
/// that have not yet been assigned a specific interface identifier. This is
/// more restrictive than [`is_ula()`], which tests only the first-octet prefix.
///
/// Replaces C macro `IN6_IS_ADDR_ULA_ZERO` (`ip6addr.h` line 128):
/// ```c
/// #define IN6_IS_ADDR_ULA_ZERO(a) \
///     (((__const uint32_t *) (a))[0] == htonl(0xfd000000) \
///      && ((__const uint32_t *) (a))[1] == 0 \
///      && ((__const uint32_t *) (a))[2] == 0 \
///      && ((__const uint32_t *) (a))[3] == 0)
/// ```
///
/// # Arguments
/// * `addr` — Reference to the IPv6 address to classify.
///
/// # Returns
/// `true` if the address is exactly `fd00::` (all 15 trailing octets zero),
/// `false` otherwise.
///
/// # Examples
/// ```
/// use std::net::Ipv6Addr;
/// use dnsmasq::dhcp::ip6addr::is_ula_zero;
///
/// assert!(is_ula_zero(&"fd00::".parse::<Ipv6Addr>().unwrap()));
/// assert!(!is_ula_zero(&"fd00::1".parse::<Ipv6Addr>().unwrap()));
/// assert!(!is_ula_zero(&"fe80::".parse::<Ipv6Addr>().unwrap()));
/// ```
#[inline]
pub fn is_ula_zero(addr: &Ipv6Addr) -> bool {
    // C original checks all four 32-bit words:
    //   word[0] == htonl(0xfd000000)  → first octet 0xfd, next 3 octets 0x00
    //   word[1] == 0                  → octets 4..7 all zero
    //   word[2] == 0                  → octets 8..11 all zero
    //   word[3] == 0                  → octets 12..15 all zero
    // In Rust: check first octet is 0xfd and all remaining 15 octets are zero.
    let octets = addr.octets();
    octets[0] == 0xfd && octets[1..].iter().all(|&b| b == 0)
}

/// Test if an IPv6 address is exactly the link-local prefix `fe80::` with
/// zero interface identifier.
///
/// This detects `fe80:0000:0000:0000:0000:0000:0000:0000`, used in Router
/// Advertisement prefix information options to indicate the link-local
/// network segment without a specific interface ID. Link-local addresses
/// (`fe80::/10`) are automatically configured on all IPv6-enabled interfaces
/// for communication within a single network link.
///
/// This macro specifically checks for the `fe80::/64` zero-valued variant
/// (all interface identifier bits set to zero), which is analogous to
/// [`is_ula_zero()`] but for link-local scope.
///
/// Replaces C macro `IN6_IS_ADDR_LINK_LOCAL_ZERO` (`ip6addr.h` line 179):
/// ```c
/// #define IN6_IS_ADDR_LINK_LOCAL_ZERO(a) \
///     (((__const uint32_t *) (a))[0] == htonl(0xfe800000) \
///      && ((__const uint32_t *) (a))[1] == 0 \
///      && ((__const uint32_t *) (a))[2] == 0 \
///      && ((__const uint32_t *) (a))[3] == 0)
/// ```
///
/// # Arguments
/// * `addr` — Reference to the IPv6 address to classify.
///
/// # Returns
/// `true` if the address is exactly `fe80::` (first two octets `0xfe80`,
/// remaining 14 octets zero), `false` otherwise.
///
/// # Examples
/// ```
/// use std::net::Ipv6Addr;
/// use dnsmasq::dhcp::ip6addr::is_link_local_zero;
///
/// assert!(is_link_local_zero(&"fe80::".parse::<Ipv6Addr>().unwrap()));
/// assert!(!is_link_local_zero(&"fe80::1".parse::<Ipv6Addr>().unwrap()));
/// assert!(!is_link_local_zero(&"fd00::".parse::<Ipv6Addr>().unwrap()));
/// ```
#[inline]
pub fn is_link_local_zero(addr: &Ipv6Addr) -> bool {
    // C original checks all four 32-bit words:
    //   word[0] == htonl(0xfe800000)  → first two octets 0xfe, 0x80, next 2 octets 0x00
    //   word[1] == 0                  → octets 4..7 all zero
    //   word[2] == 0                  → octets 8..11 all zero
    //   word[3] == 0                  → octets 12..15 all zero
    // In Rust: check first two octets are 0xfe, 0x80 and all remaining 14 octets are zero.
    let octets = addr.octets();
    octets[0] == 0xfe && octets[1] == 0x80 && octets[2..].iter().all(|&b| b == 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    // =====================================================================
    // is_ula() tests — RFC 4193 ULA detection (fd00::/8)
    // =====================================================================

    #[test]
    fn test_ula_fd00_with_host() {
        // fd00::1 is a ULA address
        assert!(is_ula(&"fd00::1".parse::<Ipv6Addr>().unwrap()));
    }

    #[test]
    fn test_ula_fd12_arbitrary_prefix() {
        // fd12:3456:789a::1 is a ULA address (any fd00::/8 prefix)
        assert!(is_ula(&"fd12:3456:789a::1".parse::<Ipv6Addr>().unwrap()));
    }

    #[test]
    fn test_ula_fdff_upper_bound() {
        // fdff:ffff::1 is the upper range of ULA
        assert!(is_ula(&"fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse::<Ipv6Addr>().unwrap()));
    }

    #[test]
    fn test_ula_fd00_zero() {
        // fd00:: (all zeros after fd) is still a ULA address
        assert!(is_ula(&"fd00::".parse::<Ipv6Addr>().unwrap()));
    }

    #[test]
    fn test_not_ula_global_unicast() {
        // 2001:db8::1 is documentation/global, not ULA
        assert!(!is_ula(&"2001:db8::1".parse::<Ipv6Addr>().unwrap()));
    }

    #[test]
    fn test_not_ula_link_local() {
        // fe80::1 is link-local, not ULA
        assert!(!is_ula(&"fe80::1".parse::<Ipv6Addr>().unwrap()));
    }

    #[test]
    fn test_not_ula_loopback() {
        // ::1 is loopback, not ULA
        assert!(!is_ula(&"::1".parse::<Ipv6Addr>().unwrap()));
    }

    #[test]
    fn test_not_ula_unspecified() {
        // :: is unspecified, not ULA
        assert!(!is_ula(&"::".parse::<Ipv6Addr>().unwrap()));
    }

    #[test]
    fn test_not_ula_fc00() {
        // fc00::/8 is reserved but NOT fd00::/8 — the C macro only matches 0xfd
        assert!(!is_ula(&"fc00::1".parse::<Ipv6Addr>().unwrap()));
    }

    #[test]
    fn test_not_ula_fe00() {
        // fe00::1 is not ULA
        assert!(!is_ula(&"fe00::1".parse::<Ipv6Addr>().unwrap()));
    }

    #[test]
    fn test_not_ula_multicast() {
        // ff02::1 is multicast, not ULA
        assert!(!is_ula(&"ff02::1".parse::<Ipv6Addr>().unwrap()));
    }

    // =====================================================================
    // is_ula_zero() tests — exact fd00:: detection
    // =====================================================================

    #[test]
    fn test_ula_zero_exact() {
        // fd00:: is exactly the ULA zero address
        assert!(is_ula_zero(&"fd00::".parse::<Ipv6Addr>().unwrap()));
    }

    #[test]
    fn test_ula_zero_explicit_all_zeros() {
        // Explicitly spelled out all-zero address with fd prefix
        assert!(is_ula_zero(
            &"fd00:0000:0000:0000:0000:0000:0000:0000"
                .parse::<Ipv6Addr>()
                .unwrap()
        ));
    }

    #[test]
    fn test_ula_zero_not_with_host_bit() {
        // fd00::1 has a host bit set — NOT ula_zero
        assert!(!is_ula_zero(&"fd00::1".parse::<Ipv6Addr>().unwrap()));
    }

    #[test]
    fn test_ula_zero_not_with_middle_bit() {
        // fd00:0:0:1:: has a bit set in the middle — NOT ula_zero
        assert!(!is_ula_zero(&"fd00:0:0:1::".parse::<Ipv6Addr>().unwrap()));
    }

    #[test]
    fn test_ula_zero_not_link_local() {
        // fe80:: is link-local zero, not ULA zero
        assert!(!is_ula_zero(&"fe80::".parse::<Ipv6Addr>().unwrap()));
    }

    #[test]
    fn test_ula_zero_not_fc00() {
        // fc00:: is NOT fd00:: — different first octet
        assert!(!is_ula_zero(&"fc00::".parse::<Ipv6Addr>().unwrap()));
    }

    #[test]
    fn test_ula_zero_not_fd01() {
        // fd01:: has a non-zero second octet — NOT fd00::
        assert!(!is_ula_zero(&"fd01::".parse::<Ipv6Addr>().unwrap()));
    }

    #[test]
    fn test_ula_zero_not_unspecified() {
        // :: is unspecified, not fd00::
        assert!(!is_ula_zero(&"::".parse::<Ipv6Addr>().unwrap()));
    }

    // =====================================================================
    // is_link_local_zero() tests — exact fe80:: detection
    // =====================================================================

    #[test]
    fn test_ll_zero_exact() {
        // fe80:: is exactly the link-local zero address
        assert!(is_link_local_zero(&"fe80::".parse::<Ipv6Addr>().unwrap()));
    }

    #[test]
    fn test_ll_zero_explicit_all_zeros() {
        // Explicitly spelled out all-zero link-local
        assert!(is_link_local_zero(
            &"fe80:0000:0000:0000:0000:0000:0000:0000"
                .parse::<Ipv6Addr>()
                .unwrap()
        ));
    }

    #[test]
    fn test_ll_zero_not_with_host_bit() {
        // fe80::1 has a host bit — NOT link_local_zero
        assert!(!is_link_local_zero(&"fe80::1".parse::<Ipv6Addr>().unwrap()));
    }

    #[test]
    fn test_ll_zero_not_with_interface_id() {
        // fe80::211:22ff:fe33:4455 has an interface ID — NOT zero
        assert!(!is_link_local_zero(
            &"fe80::211:22ff:fe33:4455"
                .parse::<Ipv6Addr>()
                .unwrap()
        ));
    }

    #[test]
    fn test_ll_zero_not_ula() {
        // fd00:: is ULA zero, not link-local zero
        assert!(!is_link_local_zero(&"fd00::".parse::<Ipv6Addr>().unwrap()));
    }

    #[test]
    fn test_ll_zero_not_global() {
        // 2001:db8:: is global unicast, not link-local
        assert!(!is_link_local_zero(
            &"2001:db8::".parse::<Ipv6Addr>().unwrap()
        ));
    }

    #[test]
    fn test_ll_zero_not_fe81() {
        // fe81:: has a different second octet (0x81 vs 0x80) — NOT fe80::
        assert!(!is_link_local_zero(&"fe81::".parse::<Ipv6Addr>().unwrap()));
    }

    #[test]
    fn test_ll_zero_not_fec0() {
        // fec0:: is site-local (deprecated), not link-local
        assert!(!is_link_local_zero(&"fec0::".parse::<Ipv6Addr>().unwrap()));
    }

    #[test]
    fn test_ll_zero_not_unspecified() {
        // :: is unspecified, not fe80::
        assert!(!is_link_local_zero(&"::".parse::<Ipv6Addr>().unwrap()));
    }

    #[test]
    fn test_ll_zero_not_with_middle_bit() {
        // fe80:0:0:1:: has a non-zero middle word
        assert!(!is_link_local_zero(
            &"fe80:0:0:1::".parse::<Ipv6Addr>().unwrap()
        ));
    }

    // =====================================================================
    // Cross-function boundary tests
    // =====================================================================

    #[test]
    fn test_fd00_is_ula_and_ula_zero() {
        // fd00:: should be both ULA and ULA-zero
        let addr: Ipv6Addr = "fd00::".parse().unwrap();
        assert!(is_ula(&addr));
        assert!(is_ula_zero(&addr));
        assert!(!is_link_local_zero(&addr));
    }

    #[test]
    fn test_fe80_is_link_local_zero_only() {
        // fe80:: should be link-local zero but not ULA
        let addr: Ipv6Addr = "fe80::".parse().unwrap();
        assert!(!is_ula(&addr));
        assert!(!is_ula_zero(&addr));
        assert!(is_link_local_zero(&addr));
    }

    #[test]
    fn test_fd00_1_is_ula_but_not_zero() {
        // fd00::1 should be ULA but not ULA-zero or link-local-zero
        let addr: Ipv6Addr = "fd00::1".parse().unwrap();
        assert!(is_ula(&addr));
        assert!(!is_ula_zero(&addr));
        assert!(!is_link_local_zero(&addr));
    }

    #[test]
    fn test_global_unicast_none() {
        // Global unicast should fail all three checks
        let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert!(!is_ula(&addr));
        assert!(!is_ula_zero(&addr));
        assert!(!is_link_local_zero(&addr));
    }

    #[test]
    fn test_loopback_none() {
        // Loopback should fail all three checks
        let addr: Ipv6Addr = "::1".parse().unwrap();
        assert!(!is_ula(&addr));
        assert!(!is_ula_zero(&addr));
        assert!(!is_link_local_zero(&addr));
    }
}

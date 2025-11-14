/* dnsmasq is Copyright (c) 2000-2025 Simon Kelley

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 dated June, 1991, or
   (at your option) version 3 dated 29 June, 2007.
 
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
     
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * @file ip6addr.h
 * @brief IPv6 address utility macros and predicates for address classification
 * 
 * DETAILED PURPOSE:
 * This header file provides inline macro implementations for IPv6 address classification
 * and validation. These utilities extend the standard POSIX IPv6 address predicates
 * with additional dnsmasq-specific checks for Unique Local Addresses (ULA) per RFC 4193
 * and zero-valued address prefixes used in DHCPv6 and Router Advertisement processing.
 * 
 * KEY RESPONSIBILITIES:
 * - Define IN6_IS_ADDR_ULA() macro for RFC 4193 Unique Local Address detection
 * - Define IN6_IS_ADDR_ULA_ZERO() macro for ULA prefix with zero interface identifier
 * - Define IN6_IS_ADDR_LINK_LOCAL_ZERO() macro for link-local prefix with zero interface ID
 * 
 * DEPENDENCIES:
 * Includes: This header is included by DHCPv6 and Router Advertisement modules
 * Called by: src/dhcp6.c, src/radv.c, src/rfc3315.c for IPv6 address validation
 * Calls: Standard C library htonl() for network byte order conversion
 * 
 * DATA STRUCTURES:
 * No structures defined - this header provides only macro definitions for address testing
 * 
 * COMPILE-TIME OPTIONS:
 * HAVE_DHCP6: These macros are used when DHCPv6 support is compiled in
 * 
 * THREADING/CONCURRENCY:
 * Macros are thread-safe as they perform only read operations on const pointers
 * and use no global state. Safe for use in dnsmasq's single-threaded event loop.
 * 
 * @copyright Copyright (c) 2000-2025 Simon Kelley
 * @license GPL-2.0-or-later
 */

/**
 * @def IN6_IS_ADDR_ULA
 * @brief Test if an IPv6 address is a Unique Local Address (ULA) per RFC 4193
 * 
 * Checks whether an IPv6 address falls within the ULA range (fc00::/7), which
 * consists of addresses beginning with the prefix fd00::/8 (locally assigned ULAs).
 * These addresses are intended for local communications within a site or organization
 * and are not routable on the global IPv6 internet.
 * 
 * The macro examines the first 8 bits of the address to determine if they match
 * the ULA prefix (0xfd). This is used in DHCPv6 processing to identify addresses
 * that should be treated as site-local for address allocation and validation purposes.
 * 
 * @param a Pointer to struct in6_addr containing the IPv6 address to test.
 *          Must not be NULL. The address is treated as const and is not modified.
 * 
 * @return Non-zero (true) if the address is in the ULA range (fd00::/8),
 *         zero (false) otherwise
 * 
 * @note This macro accesses the address as a uint32_t array in network byte order
 * @warning Parameter 'a' is evaluated multiple times - do not pass expressions with side effects
 * 
 * EXAMPLE USAGE:
 * @code
 * struct in6_addr addr;
 * inet_pton(AF_INET6, "fd00::1", &addr);
 * if (IN6_IS_ADDR_ULA(&addr)) {
 *     // Address is a Unique Local Address
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 4193 Section 3 (Unique Local IPv6 Unicast Addresses)
 * SIDE EFFECTS: None - macro performs only read operations
 * THREAD SAFETY: Thread-safe - no global state modifications
 */
#define IN6_IS_ADDR_ULA(a) \
        ((((__const uint32_t *) (a))[0] & htonl (0xff000000))                 \
         == htonl (0xfd000000))
/**
 * @def IN6_IS_ADDR_ULA_ZERO
 * @brief Test if an IPv6 address is the ULA prefix with zero interface identifier
 * 
 * Checks whether an IPv6 address exactly matches the ULA prefix fd00::/64 with all
 * interface identifier bits set to zero (fd00:0000:0000:0000:0000:0000:0000:0000).
 * This special case address represents the network prefix itself without any host
 * assignment, used in DHCPv6 prefix delegation and Router Advertisement to identify
 * delegated network ranges.
 * 
 * The macro verifies that the first 32 bits match the fd00::/8 prefix and that all
 * remaining 96 bits are zero. This is more restrictive than IN6_IS_ADDR_ULA() which
 * tests only the prefix, making it useful for detecting unassigned ULA network
 * addresses in DHCPv6 prefix delegation contexts.
 * 
 * @param a Pointer to struct in6_addr containing the IPv6 address to test.
 *          Must not be NULL. The address is treated as const and is not modified.
 * 
 * @return Non-zero (true) if the address is exactly fd00:: with all zeros,
 *         zero (false) otherwise
 * 
 * @note This macro accesses the address as a uint32_t[4] array in network byte order
 * @warning Parameter 'a' is evaluated multiple times - do not pass expressions with side effects
 * 
 * @see IN6_IS_ADDR_ULA for testing any address in the ULA range
 * 
 * EXAMPLE USAGE:
 * @code
 * struct in6_addr prefix;
 * inet_pton(AF_INET6, "fd00::", &prefix);
 * if (IN6_IS_ADDR_ULA_ZERO(&prefix)) {
 *     // This is the ULA prefix with zero interface ID - suitable for delegation
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 4193 Section 3 (ULA prefix structure)
 * SIDE EFFECTS: None - macro performs only read operations
 * THREAD SAFETY: Thread-safe - no global state modifications
 */
#define IN6_IS_ADDR_ULA_ZERO(a) \
        (((__const uint32_t *) (a))[0] == htonl (0xfd000000)                        \
         && ((__const uint32_t *) (a))[1] == 0                                \
         && ((__const uint32_t *) (a))[2] == 0                                \
         && ((__const uint32_t *) (a))[3] == 0)
/**
 * @def IN6_IS_ADDR_LINK_LOCAL_ZERO
 * @brief Test if an IPv6 address is the link-local prefix with zero interface identifier
 * 
 * Checks whether an IPv6 address exactly matches the link-local prefix fe80::/64 with
 * all interface identifier bits set to zero (fe80:0000:0000:0000:0000:0000:0000:0000).
 * This special case address represents the link-local network prefix itself without
 * any host assignment, used in Router Advertisement and DHCPv6 to identify the
 * link-local network segment for neighbor discovery and local communication.
 * 
 * Link-local addresses (fe80::/10) are automatically configured on all IPv6-enabled
 * interfaces and are used for communication within a single network link. This macro
 * specifically detects the zero-valued variant of the link-local prefix, which is
 * used in Router Advertisement prefix information options and DHCPv6 address range
 * specifications to indicate the network portion without a specific interface ID.
 * 
 * The macro verifies that the first 32 bits match the fe80::/10 prefix (specifically
 * the fe80::/64 variant used for link-local addressing) and that all remaining 96 bits
 * are zero. This is analogous to IN6_IS_ADDR_ULA_ZERO() but for link-local scope.
 * 
 * @param a Pointer to struct in6_addr containing the IPv6 address to test.
 *          Must not be NULL. The address is treated as const and is not modified.
 * 
 * @return Non-zero (true) if the address is exactly fe80:: with all zeros,
 *         zero (false) otherwise
 * 
 * @note This macro accesses the address as a uint32_t[4] array in network byte order
 * @warning Parameter 'a' is evaluated multiple times - do not pass expressions with side effects
 * 
 * @see IN6_IS_ADDR_LINKLOCAL (standard POSIX macro) for testing any link-local address
 * @see IN6_IS_ADDR_ULA_ZERO for similar ULA prefix testing
 * 
 * EXAMPLE USAGE:
 * @code
 * struct in6_addr ll_prefix;
 * inet_pton(AF_INET6, "fe80::", &ll_prefix);
 * if (IN6_IS_ADDR_LINK_LOCAL_ZERO(&ll_prefix)) {
 *     // This is the link-local prefix with zero interface ID
 *     // Used in Router Advertisement prefix information
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 4291 Section 2.5.6 (Link-Local IPv6 Unicast Addresses)
 * SIDE EFFECTS: None - macro performs only read operations
 * THREAD SAFETY: Thread-safe - no global state modifications
 */
#define IN6_IS_ADDR_LINK_LOCAL_ZERO(a) \
        (((__const uint32_t *) (a))[0] == htonl (0xfe800000)                  \
         && ((__const uint32_t *) (a))[1] == 0                                \
         && ((__const uint32_t *) (a))[2] == 0                                \
         && ((__const uint32_t *) (a))[3] == 0)

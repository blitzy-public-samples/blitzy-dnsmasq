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
 * @file radv-protocol.h
 * @brief ICMPv6 Router Advertisement protocol constants and structures per RFC 4861
 * 
 * DETAILED PURPOSE:
 * This header defines protocol constants, packet structures, and option definitions for
 * IPv6 Router Advertisement (RA) and Neighbor Discovery (ND) protocols as specified in
 * RFC 4861 (IPv6 Neighbor Discovery Protocol). These definitions enable dnsmasq to
 * construct and transmit ICMPv6 Router Advertisement messages for IPv6 network
 * autoconfiguration, supporting both SLAAC (Stateless Address Autoconfiguration) and
 * managed DHCPv6 address assignment.
 * 
 * KEY RESPONSIBILITIES:
 * - Define IPv6 multicast addresses for ND protocol communication (all-nodes, all-routers)
 * - Provide ICMPv6 packet structure definitions for Router Advertisement messages
 * - Define prefix information option structure for advertised IPv6 prefixes
 * - Enumerate ICMPv6 Neighbor Discovery option types (prefix, RDNSS, DNSSL, etc.)
 * - Support neighbor solicitation and advertisement packet structures
 * - Enable ICMP6 Echo Request/Reply (ping) packet construction
 * 
 * DEPENDENCIES:
 * Includes: <netinet/in.h> (for struct in6_addr), system type definitions (u8, u16, u32)
 * Called by: src/radv.c (Router Advertisement implementation)
 * Calls: N/A (header-only definitions)
 * 
 * DATA STRUCTURES:
 * - struct ra_packet: ICMPv6 Router Advertisement message format (lines 27-34)
 * - struct prefix_opt: Prefix Information option for RA messages (lines 43-47)
 * - struct ping_packet: ICMPv6 Echo Request/Reply message format (lines 20-25)
 * - struct neigh_packet: ICMPv6 Neighbor Solicitation/Advertisement format (lines 36-41)
 * 
 * COMPILE-TIME OPTIONS:
 * This header is conditionally included when HAVE_DHCP6 is defined, enabling IPv6
 * Router Advertisement and DHCPv6 functionality.
 * 
 * RELATIONSHIP TO IMPLEMENTATION:
 * The structures and constants defined in this header are used by src/radv.c to:
 * - Construct Router Advertisement messages with configured prefixes and lifetimes
 * - Set Managed (M) and Other (O) flags controlling DHCPv6 usage
 * - Include RDNSS options advertising DNS servers via Router Advertisement
 * - Transmit RAs to FF02::1 (all-nodes multicast) for network-wide autoconfiguration
 * - Support prefix delegation and hierarchical IPv6 addressing
 * 
 * RFC COMPLIANCE:
 * - RFC 4861: IPv6 Neighbor Discovery Protocol (Router Advertisement, Neighbor Solicitation)
 * - RFC 6106: IPv6 Router Advertisement Options for DNS Configuration (RDNSS, DNSSL)
 * - RFC 4443: ICMPv6 for IPv6 (ICMPv6 message format and type codes)
 * 
 * @copyright Copyright (c) 2000-2025 Simon Kelley
 * @license GPL-2.0-or-later
 */

/**
 * @defgroup IPv6_Multicast_Addresses IPv6 Multicast Addresses for Neighbor Discovery
 * @{
 */

/**
 * @def ALL_NODES
 * @brief IPv6 link-local all-nodes multicast address (FF02::1)
 * 
 * This address is used as the destination for Router Advertisement messages that
 * should be received by all IPv6 nodes on the local link. Router Advertisements
 * are sent to this address to enable all hosts to perform Stateless Address
 * Autoconfiguration (SLAAC) and discover router parameters.
 * 
 * RFC 4861 Section 6.1.2: Routers send unsolicited Router Advertisements to the
 * all-nodes multicast address to advertise their presence and network parameters.
 * 
 * @note This is a link-local scope multicast address (FF02), meaning it is not
 * forwarded beyond the local network segment.
 */
#define ALL_NODES                 "FF02::1"

/**
 * @def ALL_ROUTERS
 * @brief IPv6 link-local all-routers multicast address (FF02::2)
 * 
 * This address is used as the destination for Router Solicitation messages sent
 * by hosts to request immediate Router Advertisement messages from routers. This
 * enables faster network autoconfiguration by not waiting for periodic unsolicited
 * Router Advertisements.
 * 
 * RFC 4861 Section 6.1.1: Hosts send Router Solicitations to the all-routers
 * multicast address when they need to discover routers immediately upon interface
 * initialization.
 * 
 * @note While defined here for protocol completeness, dnsmasq as a router
 * primarily transmits to ALL_NODES and may listen for solicitations on this address.
 */
#define ALL_ROUTERS               "FF02::2"

/** @} */ /* End of IPv6_Multicast_Addresses group */

/**
 * @struct ping_packet
 * @brief ICMPv6 Echo Request/Reply packet structure for IPv6 ping operations
 * 
 * This structure defines the format of ICMPv6 Echo Request (type 128) and Echo Reply
 * (type 129) messages used for IPv6 reachability testing. In dnsmasq context, this
 * structure is used to perform address conflict detection via ping testing before
 * assigning SLAAC addresses or DHCPv6 addresses to ensure they are not already in use.
 * 
 * LIFECYCLE:
 * Creation: Allocated on stack when constructing ping request for address verification
 * Initialization: Fields populated with ICMPv6 type, identifier, and sequence number
 * Destruction: Stack-allocated, automatically freed when function returns
 * Ownership: Temporary structure for packet construction, no persistent storage
 * 
 * MEMORY LAYOUT:
 * Size: 8 bytes (fixed ICMPv6 echo message header)
 * Alignment: Natural alignment for network protocol structures
 * 
 * USAGE PATTERNS:
 * Used by src/slaac.c for SLAAC address confirmation (ping test for duplicate detection)
 * Used by src/dhcp6.c for verifying DHCPv6-assigned addresses are not in use
 * Transmitted to candidate address to check for existing host before assignment
 * 
 * RFC COMPLIANCE:
 * RFC 4443 Section 4.1: ICMPv6 Echo Request Message (type 128)
 * RFC 4443 Section 4.2: ICMPv6 Echo Reply Message (type 129)
 */
struct ping_packet {
  /** @var type
   *  @brief ICMPv6 message type
   *  
   *  128: Echo Request (ping query sent to test address availability)
   *  129: Echo Reply (response from host at tested address, indicating address is in use)
   */
  u8 type;
  
  /** @var code
   *  @brief ICMPv6 message code (always 0 for Echo Request/Reply)
   *  
   *  Must be set to 0 per RFC 4443. Non-zero values are invalid for echo messages.
   */
  u8 code;
  
  /** @var checksum
   *  @brief ICMPv6 checksum covering entire ICMPv6 message and IPv6 pseudo-header
   *  
   *  Computed over ICMPv6 message plus IPv6 pseudo-header (source, destination,
   *  length, next header). Must be validated on receipt and computed on transmission.
   *  Network byte order (big-endian).
   */
  u16 checksum;
  
  /** @var identifier
   *  @brief Echo identifier for matching requests with replies
   *  
   *  Used to distinguish multiple concurrent ping operations. Typically set to
   *  process ID or random value. Echo Reply must copy this value from Echo Request.
   *  Network byte order (big-endian).
   */
  u16 identifier;
  
  /** @var sequence_no
   *  @brief Echo sequence number for ordering and duplicate detection
   *  
   *  Incremented for each echo request sent. Enables detection of lost packets
   *  and out-of-order delivery. Echo Reply must copy this value from Echo Request.
   *  Network byte order (big-endian).
   */
  u16 sequence_no;
};

/**
 * @struct ra_packet
 * @brief ICMPv6 Router Advertisement message structure per RFC 4861
 * 
 * This structure defines the base Router Advertisement message format transmitted by
 * IPv6 routers to advertise their presence, network parameters, and address prefixes
 * to hosts on the local link. Router Advertisements enable IPv6 Stateless Address
 * Autoconfiguration (SLAAC) and coordinate with DHCPv6 for managed addressing.
 * 
 * DETAILED DESCRIPTION:
 * Router Advertisement messages are sent periodically (unsolicited) and in response
 * to Router Solicitation messages (solicited). The RA packet header is followed by
 * zero or more options including prefix information, RDNSS (DNS servers), DNSSL
 * (DNS search list), MTU, and other network parameters.
 * 
 * LIFECYCLE:
 * Creation: Allocated on stack in src/radv.c:send_ra() when constructing RA message
 * Initialization: Fields populated with configured router parameters and lifetimes
 * Destruction: Stack-allocated, automatically freed after packet transmission
 * Ownership: Temporary structure for packet construction, no persistent storage
 * 
 * MEMORY LAYOUT:
 * Size: 16 bytes (fixed ICMPv6 RA message header, options follow separately)
 * Alignment: Natural alignment for network protocol structures
 * 
 * USAGE PATTERNS:
 * Created by src/radv.c:send_ra() for periodic RA transmission to FF02::1 (all-nodes)
 * Flags field (M and O bits) control DHCPv6 operational mode (stateful/stateless)
 * Hop limit field advertises suggested default hop limit for outgoing packets
 * Lifetime field specifies router's validity as default router
 * Followed by prefix_opt structures advertising on-link prefixes
 * 
 * RFC COMPLIANCE:
 * RFC 4861 Section 4.2: Router Advertisement Message Format
 * RFC 4861 Section 6.2.3: Router Advertisement Processing by hosts
 */
struct ra_packet {
  /** @var type
   *  @brief ICMPv6 message type (134 for Router Advertisement)
   *  
   *  Must be set to 134 (ND_ROUTER_ADVERT) to identify this as a Router Advertisement.
   *  Hosts process only ICMPv6 type 134 messages as Router Advertisements.
   */
  u8 type;
  
  /** @var code
   *  @brief ICMPv6 message code (always 0 for Router Advertisement)
   *  
   *  Must be set to 0 per RFC 4861. Non-zero values cause the message to be discarded.
   */
  u8 code;
  
  /** @var checksum
   *  @brief ICMPv6 checksum covering entire RA message and IPv6 pseudo-header
   *  
   *  Computed over ICMPv6 message (including all options) plus IPv6 pseudo-header.
   *  Receivers must validate checksum; invalid checksums cause message discard.
   *  Network byte order (big-endian).
   */
  u16 checksum;
  
  /** @var hop_limit
   *  @brief Current Hop Limit field (suggested default hop limit for outgoing packets)
   *  
   *  Advertises the hop limit value hosts should use in outgoing IPv6 packets.
   *  Value 0 means unspecified (router makes no recommendation).
   *  Typical values: 64 (recommended default), 255 (maximum).
   *  
   *  Hosts receiving this value should configure their default hop limit accordingly.
   */
  u8 hop_limit;
  
  /** @var flags
   *  @brief RA flags byte controlling address configuration behavior
   *  
   *  Bit layout (MSB to LSB):
   *  - Bit 7 (M): Managed address configuration flag (1 = use DHCPv6 for addresses)
   *  - Bit 6 (O): Other configuration flag (1 = use DHCPv6 for non-address config)
   *  - Bit 5 (H): Home Agent flag (Mobile IPv6, not used by dnsmasq)
   *  - Bits 4-3: Router preference (00=medium, 01=high, 11=low)
   *  - Bit 2 (Proxy): Proxy flag (not used by dnsmasq)
   *  - Bits 1-0: Reserved (must be 0)
   *  
   *  DNSMASQ USAGE:
   *  M=1, O=0: Stateful DHCPv6 (clients get addresses via DHCPv6)
   *  M=0, O=1: Stateless DHCPv6 (clients use SLAAC for addresses, DHCPv6 for config)
   *  M=1, O=1: Stateful DHCPv6 with additional configuration
   *  M=0, O=0: SLAAC only (no DHCPv6 used)
   *  
   *  Configured via dhcp-range option parameters in dnsmasq.conf.
   */
  u8 flags;
  
  /** @var lifetime
   *  @brief Router Lifetime in seconds (validity as default router)
   *  
   *  Specifies the maximum time (in seconds) this router should be used as a
   *  default router. Value 0 means the router is not a default router.
   *  Typical values: 1800 seconds (30 minutes) to 9000 seconds (2.5 hours).
   *  
   *  Hosts use this value to determine when to expire the default router entry
   *  from their routing table. Dnsmasq typically sets this to 3 times the RA
   *  transmission interval to ensure continuous router availability.
   *  
   *  Network byte order (big-endian).
   */
  u16 lifetime;
  
  /** @var reachable_time
   *  @brief Reachable Time in milliseconds for Neighbor Unreachability Detection
   *  
   *  Time a neighbor is considered reachable after receiving a reachability
   *  confirmation. Value 0 means unspecified (router makes no recommendation).
   *  Typical values: 30000 milliseconds (30 seconds).
   *  
   *  Used by hosts for Neighbor Unreachability Detection (NUD) to determine
   *  when to probe neighbors for continued reachability.
   *  
   *  Network byte order (big-endian).
   */
  u32 reachable_time;
  
  /** @var retrans_time
   *  @brief Retransmit Timer in milliseconds for Neighbor Solicitation retransmissions
   *  
   *  Time between retransmitted Neighbor Solicitation messages when performing
   *  address resolution or Neighbor Unreachability Detection. Value 0 means
   *  unspecified (router makes no recommendation).
   *  Typical values: 1000 milliseconds (1 second).
   *  
   *  Hosts use this value to configure their NS retransmission timer for
   *  address resolution and duplicate address detection.
   *  
   *  Network byte order (big-endian).
   */
  u32 retrans_time;
};

/**
 * @struct neigh_packet
 * @brief ICMPv6 Neighbor Solicitation/Advertisement packet structure per RFC 4861
 * 
 * This structure defines the format of ICMPv6 Neighbor Solicitation (type 135) and
 * Neighbor Advertisement (type 136) messages used for IPv6 address resolution,
 * duplicate address detection, and neighbor reachability verification. In dnsmasq
 * context, this structure is used for duplicate address detection before assigning
 * IPv6 addresses via SLAAC or DHCPv6.
 * 
 * DETAILED DESCRIPTION:
 * Neighbor Solicitation messages query for the link-layer address of a target IPv6
 * address (address resolution) or test if an address is already in use (duplicate
 * address detection). Neighbor Advertisement messages respond to solicitations or
 * announce address changes.
 * 
 * LIFECYCLE:
 * Creation: Allocated on stack when performing duplicate address detection
 * Initialization: Fields populated with ICMPv6 type, target address, and flags
 * Destruction: Stack-allocated, automatically freed after processing
 * Ownership: Temporary structure for packet construction or parsing
 * 
 * MEMORY LAYOUT:
 * Size: 24 bytes (8-byte header + 16-byte IPv6 address)
 * Alignment: Natural alignment for network protocol structures
 * 
 * USAGE PATTERNS:
 * Used by src/slaac.c for duplicate address detection (send NS, wait for NA reply)
 * Used by src/dhcp6.c to verify DHCPv6-assigned addresses are not already in use
 * Neighbor Solicitation sent to solicited-node multicast address of target
 * Neighbor Advertisement response indicates address is in use (conflict detected)
 * 
 * RFC COMPLIANCE:
 * RFC 4861 Section 4.3: Neighbor Solicitation Message Format
 * RFC 4861 Section 4.4: Neighbor Advertisement Message Format
 * RFC 4862 Section 5.4: Duplicate Address Detection procedure
 */
struct neigh_packet {
  /** @var type
   *  @brief ICMPv6 message type
   *  
   *  135: Neighbor Solicitation (query for address or duplicate address detection)
   *  136: Neighbor Advertisement (response or unsolicited announcement)
   *  
   *  Dnsmasq primarily sends Neighbor Solicitations for duplicate address detection.
   */
  u8 type;
  
  /** @var code
   *  @brief ICMPv6 message code (always 0 for Neighbor Solicitation/Advertisement)
   *  
   *  Must be set to 0 per RFC 4861. Non-zero values cause the message to be discarded.
   */
  u8 code;
  
  /** @var checksum
   *  @brief ICMPv6 checksum covering entire NS/NA message and IPv6 pseudo-header
   *  
   *  Computed over ICMPv6 message (including options) plus IPv6 pseudo-header.
   *  Must be validated on receipt and computed on transmission.
   *  Network byte order (big-endian).
   */
  u16 checksum;
  
  /** @var reserved
   *  @brief Reserved field (flags for Neighbor Advertisement, reserved for NS)
   *  
   *  For Neighbor Solicitation: Must be set to 0 on transmission, ignored on receipt.
   *  
   *  For Neighbor Advertisement (when type=136):
   *  - Bit 31 (R): Router flag (1 if sender is a router)
   *  - Bit 30 (S): Solicited flag (1 if advertisement is in response to NS)
   *  - Bit 29 (O): Override flag (1 to override existing cache entry)
   *  - Bits 28-0: Reserved (must be 0)
   *  
   *  Network byte order (big-endian) when interpreted as 32-bit flags field.
   */
  u16 reserved;
  
  /** @var target
   *  @brief Target IPv6 address for resolution or duplicate detection
   *  
   *  For Neighbor Solicitation:
   *  - In address resolution: The IPv6 address for which link-layer address is sought
   *  - In duplicate address detection: The tentative IPv6 address being tested
   *  
   *  For Neighbor Advertisement:
   *  - The IPv6 address being advertised or for which the advertisement is a response
   *  
   *  DUPLICATE ADDRESS DETECTION USAGE:
   *  When dnsmasq tests if a SLAAC or DHCPv6 address is available, it sends a
   *  Neighbor Solicitation with source address :: (unspecified) and target address
   *  set to the candidate address. If any node responds with Neighbor Advertisement,
   *  the address is in use and must not be assigned.
   *  
   *  Must not be a multicast address (except for DAD, where checks are performed).
   */
  struct in6_addr target;
};

/**
 * @struct prefix_opt
 * @brief Prefix Information option for ICMPv6 Router Advertisement per RFC 4861
 * 
 * This structure defines the Prefix Information option (type 3) included in Router
 * Advertisement messages to advertise IPv6 prefixes available for Stateless Address
 * Autoconfiguration (SLAAC) and to specify whether prefixes are on-link for direct
 * communication. Multiple prefix options can be included in a single RA message to
 * advertise multiple prefixes.
 * 
 * DETAILED DESCRIPTION:
 * The Prefix Information option communicates IPv6 address prefixes that hosts can
 * use to autoconfigure addresses (via SLAAC), determine on-link destinations, and
 * manage address lifetimes. The A (autonomous) flag indicates whether hosts should
 * use the prefix for SLAAC, while the L (on-link) flag indicates whether the prefix
 * is on the local link.
 * 
 * LIFECYCLE:
 * Creation: Allocated in src/radv.c when constructing Router Advertisement message
 * Initialization: Populated with configured prefix, prefix length, lifetimes, and flags
 * Destruction: Part of RA packet buffer, freed after transmission
 * Ownership: Component of Router Advertisement message, follows RA packet lifetime
 * 
 * MEMORY LAYOUT:
 * Size: 32 bytes (fixed size for RFC 4861 prefix information option)
 * Alignment: Natural alignment for network protocol structures
 * 
 * USAGE PATTERNS:
 * Created by src/radv.c:send_ra() for each configured prefix to be advertised
 * Multiple prefix_opt structures can follow ra_packet in single RA message
 * A flag (Autonomous) controls whether hosts use prefix for SLAAC addressing
 * L flag (On-link) indicates whether prefix destinations are on local link
 * Valid lifetime specifies how long addresses derived from prefix remain valid
 * Preferred lifetime specifies how long addresses are preferred for new connections
 * 
 * INTEGRATION WITH DHCPV6:
 * When M flag in RA is set (stateful DHCPv6), prefix may still be advertised but
 * hosts obtain addresses from DHCPv6 instead of SLAAC. Prefix information is used
 * for on-link determination even when A flag is 0.
 * 
 * RFC COMPLIANCE:
 * RFC 4861 Section 4.6.2: Prefix Information Option Format
 * RFC 4862 Section 5.5.3: Router Advertisement Processing (prefix information)
 */
struct prefix_opt {
  /** @var type
   *  @brief Option type identifier (3 for Prefix Information)
   *  
   *  Must be set to 3 (ICMP6_OPT_PREFIX) to identify this as a Prefix Information
   *  option. Hosts process only type 3 options as prefix advertisements.
   */
  u8 type;
  
  /** @var len
   *  @brief Option length in units of 8 octets (always 4 for prefix information)
   *  
   *  Must be set to 4, indicating 32 bytes (4 × 8 octets) for the complete prefix
   *  information option including header and prefix address.
   *  
   *  Used by option parsing code to skip to next option in RA message.
   */
  u8 len;
  
  /** @var prefix_len
   *  @brief Prefix length in bits (typically 64 for standard IPv6 subnets)
   *  
   *  Number of leading bits in the prefix that are valid. Hosts use this value
   *  when forming addresses via SLAAC (remaining bits are interface identifier).
   *  
   *  Valid range: 0-128 bits
   *  Common values:
   *  - 64: Standard IPv6 subnet prefix (RFC 4291 recommendation)
   *  - 48: Site-level aggregation prefix
   *  - 32: Provider-level aggregation
   *  
   *  For SLAAC, RFC 4862 requires prefix length ≤ 64 bits to accommodate 64-bit
   *  interface identifiers (EUI-64 or privacy extensions).
   */
  u8 prefix_len;
  
  /** @var flags
   *  @brief Prefix flags controlling address autoconfiguration and on-link behavior
   *  
   *  Bit layout (MSB to LSB):
   *  - Bit 7 (L): On-link flag (1 = prefix is on-link, 0 = no on-link determination)
   *  - Bit 6 (A): Autonomous address-configuration flag (1 = use for SLAAC, 0 = no SLAAC)
   *  - Bit 5 (R): Router Address flag (not used by dnsmasq, must be 0)
   *  - Bits 4-0: Reserved (must be 0)
   *  
   *  DNSMASQ TYPICAL CONFIGURATION:
   *  L=1, A=1: Prefix is on-link and should be used for SLAAC (normal SLAAC mode)
   *  L=1, A=0: Prefix is on-link but addresses assigned via DHCPv6 (stateful mode)
   *  L=0, A=0: Prefix advertised for route information only
   *  
   *  ON-LINK DETERMINATION:
   *  When L=1, hosts consider destinations within this prefix to be on the local
   *  link and attempt direct communication without routing through the default router.
   *  
   *  AUTONOMOUS CONFIGURATION:
   *  When A=1, hosts use this prefix to autoconfigure IPv6 addresses by combining
   *  the prefix with their interface identifier (EUI-64 or privacy extensions).
   */
  u8 flags;
  
  /** @var valid_lifetime
   *  @brief Valid lifetime in seconds (time prefix remains valid for on-link determination)
   *  
   *  Specifies how long (in seconds) the prefix is valid for on-link determination
   *  and how long addresses autoconfigured from this prefix remain valid. When this
   *  lifetime expires, addresses become invalid and must not be used for new
   *  connections or communication.
   *  
   *  Special values:
   *  - 0xFFFFFFFF (infinity): Prefix/addresses never expire
   *  - 0: Prefix/addresses immediately invalid (used to deprecate prefix)
   *  
   *  Typical values: 2592000 seconds (30 days) to 7200 seconds (2 hours)
   *  
   *  RELATIONSHIP TO PREFERRED LIFETIME:
   *  Must be ≥ preferred_lifetime. Valid lifetime represents the upper bound on
   *  address usability, while preferred lifetime represents when addresses should
   *  stop being used for new connections.
   *  
   *  Network byte order (big-endian).
   */
  u32 valid_lifetime;
  
  /** @var preferred_lifetime
   *  @brief Preferred lifetime in seconds (time addresses are preferred for new connections)
   *  
   *  Specifies how long (in seconds) addresses autoconfigured from this prefix
   *  should remain preferred for use in new connections. After this time, addresses
   *  become deprecated (still valid but not preferred), and hosts should prefer
   *  other non-deprecated addresses for new communications.
   *  
   *  Special values:
   *  - 0xFFFFFFFF (infinity): Addresses never deprecate
   *  - 0: Addresses immediately deprecated (valid but not preferred)
   *  
   *  Typical values: 604800 seconds (7 days) to 1800 seconds (30 minutes)
   *  
   *  ADDRESS DEPRECATION:
   *  When preferred lifetime expires but valid lifetime has not, addresses enter
   *  deprecated state: existing connections continue normally, but new connections
   *  should use preferred addresses. This enables graceful prefix renumbering.
   *  
   *  Must be ≤ valid_lifetime per RFC 4861.
   *  Network byte order (big-endian).
   */
  u32 preferred_lifetime;
  
  /** @var reserved
   *  @brief Reserved field (must be 0)
   *  
   *  Reserved for future use. Must be set to 0 on transmission and ignored on receipt.
   *  Positioned after lifetimes, before prefix address in option structure.
   *  
   *  Network byte order (big-endian) as 32-bit field.
   */
  u32 reserved;
  
  /** @var prefix
   *  @brief IPv6 address prefix being advertised
   *  
   *  The IPv6 prefix that hosts use for SLAAC, on-link determination, or routing.
   *  Only the bits specified by prefix_len are significant; remaining bits should
   *  be set to 0 but are ignored by receivers.
   *  
   *  SLAAC ADDRESS FORMATION:
   *  When A flag is set, hosts form complete IPv6 addresses by combining this prefix
   *  with their 64-bit interface identifier:
   *  - Address = prefix (first prefix_len bits) + interface ID (remaining bits)
   *  - Interface ID derived from MAC address (EUI-64) or random (privacy extensions)
   *  
   *  ON-LINK DETERMINATION:
   *  When L flag is set, hosts compare destination addresses against this prefix
   *  to determine if destination is on the local link (direct communication) or
   *  off-link (must route through default router).
   *  
   *  COMMON PREFIXES:
   *  - 2001:db8::/32: Documentation prefix (RFC 3849)
   *  - fd00::/8: Unique Local Addresses (ULA, RFC 4193)
   *  - fe80::/10: Link-local addresses (not typically advertised in prefix options)
   *  - Global Unicast: Provider-assigned prefixes (e.g., 2001::/16 range)
   *  
   *  Must not be a link-local address (fe80::/10) or multicast address (ff00::/8).
   */
  struct in6_addr prefix;
};

/**
 * @defgroup ICMPv6_ND_Options ICMPv6 Neighbor Discovery Option Types
 * @brief Option type codes for ICMPv6 Neighbor Discovery protocol options per RFC 4861 and extensions
 * 
 * These constants define option type identifiers that appear in ICMPv6 Neighbor Discovery
 * messages (Router Advertisement, Neighbor Solicitation, Neighbor Advertisement, Router
 * Solicitation, Redirect). Each option begins with type and length fields, followed by
 * option-specific data.
 * 
 * OPTIONS IN ROUTER ADVERTISEMENT:
 * Router Advertisement messages typically include multiple options to provide network
 * configuration information to hosts:
 * - Source Link-Layer Address: Router's MAC address for return path optimization
 * - Prefix Information: IPv6 prefixes for SLAAC and on-link determination
 * - MTU: Maximum transmission unit for the link
 * - Advertisement Interval: Time between unsolicited RAs (RFC 6275)
 * - Route Information: More-specific routes (RFC 4191)
 * - RDNSS: Recursive DNS Server addresses (RFC 6106)
 * - DNSSL: DNS Search List domains (RFC 6106)
 * 
 * DNSMASQ USAGE:
 * The src/radv.c implementation constructs Router Advertisement messages with the following
 * options based on configuration:
 * - ICMP6_OPT_SOURCE_MAC: Always included with router's link-layer address
 * - ICMP6_OPT_PREFIX: One or more prefix options for configured IPv6 prefixes
 * - ICMP6_OPT_RDNSS: Included when DNS servers are configured for advertisement
 * - ICMP6_OPT_DNSSL: Included when DNS search domains are configured
 * - ICMP6_OPT_MTU: Included when MTU is explicitly configured
 * 
 * @{
 */

/**
 * @def ICMP6_OPT_SOURCE_MAC
 * @brief Source Link-Layer Address option type (1)
 * 
 * This option provides the link-layer address (MAC address) of the interface from which
 * the ICMPv6 message is sent. In Router Advertisement messages, this is the router's
 * MAC address, allowing hosts to populate their neighbor cache with the router's
 * link-layer address without requiring separate Neighbor Solicitation/Advertisement
 * exchange.
 * 
 * Option format (RFC 4861 Section 4.6.1):
 * - Type: 1 (1 octet)
 * - Length: 1 (1 octet) - in units of 8 octets, total 8 bytes
 * - Link-Layer Address: Variable length (6 octets for Ethernet MAC address)
 * - Padding: Pad to multiple of 8 octets if necessary
 * 
 * USAGE IN DNSMASQ:
 * Automatically included in Router Advertisement messages sent by src/radv.c to provide
 * the router's MAC address. This enables hosts to immediately send packets to the router
 * without address resolution delay.
 * 
 * RFC COMPLIANCE: RFC 4861 Section 4.6.1
 */
#define ICMP6_OPT_SOURCE_MAC   1

/**
 * @def ICMP6_OPT_PREFIX
 * @brief Prefix Information option type (3)
 * 
 * This option provides information about IPv6 prefixes that are on-link and/or can be
 * used for Stateless Address Autoconfiguration (SLAAC). Router Advertisement messages
 * typically include one or more prefix options to advertise available prefixes.
 * 
 * Option format: See struct prefix_opt documentation (lines 43-47 definitions)
 * - Type: 3 (1 octet)
 * - Length: 4 (1 octet) - in units of 8 octets, total 32 bytes
 * - Prefix Length: Number of valid prefix bits (1 octet)
 * - Flags: L (on-link), A (autonomous) flags (1 octet)
 * - Valid Lifetime: Prefix/address validity period (4 octets)
 * - Preferred Lifetime: Address preference period (4 octets)
 * - Reserved: Must be zero (4 octets)
 * - Prefix: IPv6 address prefix (16 octets)
 * 
 * USAGE IN DNSMASQ:
 * Created by src/radv.c:send_ra() for each configured IPv6 prefix. Multiple prefix
 * options can be included in a single RA to advertise multiple prefixes. The A flag
 * (autonomous) controls whether hosts use the prefix for SLAAC; when DHCPv6 stateful
 * mode is configured (M=1 in RA flags), the A flag is typically set to 0.
 * 
 * RFC COMPLIANCE: RFC 4861 Section 4.6.2
 */
#define ICMP6_OPT_PREFIX       3

/**
 * @def ICMP6_OPT_MTU
 * @brief MTU (Maximum Transmission Unit) option type (5)
 * 
 * This option specifies the Maximum Transmission Unit (MTU) that hosts should use when
 * sending packets on the link. This is useful for links with non-standard MTU values
 * or to avoid path MTU discovery overhead.
 * 
 * Option format (RFC 4861 Section 4.6.4):
 * - Type: 5 (1 octet)
 * - Length: 1 (1 octet) - in units of 8 octets, total 8 bytes
 * - Reserved: Must be zero (2 octets)
 * - MTU: Maximum transmission unit in octets (4 octets)
 * 
 * TYPICAL MTU VALUES:
 * - 1500: Standard Ethernet MTU
 * - 1280: IPv6 minimum MTU (RFC 8200)
 * - 9000: Jumbo frames
 * - 1492: PPPoE with overhead
 * 
 * USAGE IN DNSMASQ:
 * Included in Router Advertisement when MTU is explicitly configured via ra-param
 * option. If not configured, this option is omitted and hosts use link-local MTU
 * discovery or assume standard values.
 * 
 * RFC COMPLIANCE: RFC 4861 Section 4.6.4
 */
#define ICMP6_OPT_MTU          5

/**
 * @def ICMP6_OPT_ADV_INTERVAL
 * @brief Advertisement Interval option type (7)
 * 
 * This option specifies the maximum time between consecutive unsolicited Router
 * Advertisement messages sent by the router. This information allows hosts to
 * detect router failures more quickly by knowing the expected RA transmission interval.
 * 
 * Option format (RFC 6275 Section 7.3):
 * - Type: 7 (1 octet)
 * - Length: 1 (1 octet) - in units of 8 octets, total 8 bytes
 * - Reserved: Must be zero (2 octets)
 * - Advertisement Interval: Maximum time between RAs in milliseconds (4 octets)
 * 
 * TYPICAL INTERVALS:
 * - 200000-600000 ms (3-10 minutes): Standard interval for stable networks
 * - 30000-70000 ms (30-70 seconds): Mobile IPv6 fast handover scenarios
 * 
 * USAGE IN DNSMASQ:
 * Optionally included when configured via ra-param option. Helps Mobile IPv6 nodes
 * and other hosts detect router unreachability faster by knowing when to expect
 * the next RA transmission.
 * 
 * RFC COMPLIANCE: RFC 6275 Section 7.3 (Mobile IPv6)
 * NOTE: While originally defined for Mobile IPv6, this option can be beneficial
 * in other scenarios requiring fast router failure detection.
 */
#define ICMP6_OPT_ADV_INTERVAL 7

/**
 * @def ICMP6_OPT_RT_INFO
 * @brief Route Information option type (24)
 * 
 * This option provides information about more-specific routes that should be added
 * to the host's routing table, beyond the default route advertised in the main RA
 * message. This enables routers to advertise multiple routes with different prefixes
 * and preferences.
 * 
 * Option format (RFC 4191 Section 2.3):
 * - Type: 24 (1 octet)
 * - Length: Variable (1, 2, or 3 depending on prefix length) (1 octet)
 * - Prefix Length: Number of valid prefix bits (1 octet)
 * - Flags: Preference value (1 octet)
 * - Route Lifetime: Validity period for route in seconds (4 octets)
 * - Prefix: Variable length, padded to 8-octet boundary
 * 
 * ROUTE PREFERENCE VALUES:
 * - 00: Medium preference (default)
 * - 01: High preference (prefer this route)
 * - 10: Reserved (must not be used)
 * - 11: Low preference (use only if no better routes available)
 * 
 * USAGE IN DNSMASQ:
 * May be included in Router Advertisements when more-specific routing information
 * needs to be conveyed to hosts. Useful in multi-router environments or when
 * advertising routes to specific subnets.
 * 
 * RFC COMPLIANCE: RFC 4191 (Default Router Preferences and More-Specific Routes)
 */
#define ICMP6_OPT_RT_INFO     24

/**
 * @def ICMP6_OPT_RDNSS
 * @brief Recursive DNS Server (RDNSS) option type (25)
 * 
 * This option provides IPv6 addresses of Recursive DNS Servers that hosts should use
 * for DNS resolution. This enables DNS server configuration via Router Advertisement
 * without requiring DHCPv6, supporting pure SLAAC environments.
 * 
 * Option format (RFC 6106 Section 5.1):
 * - Type: 25 (1 octet)
 * - Length: Variable (1 octet) - (1 + 2*N) where N = number of DNS servers
 * - Reserved: Must be zero (2 octets)
 * - Lifetime: DNS server validity period in seconds (4 octets)
 * - Addresses: One or more IPv6 addresses of DNS servers (16 octets each)
 * 
 * LIFETIME VALUES:
 * - 0: RDNSS addresses immediately invalid (remove from configuration)
 * - 1-0xFFFFFFFF: Validity period in seconds
 * - Typical: 2 × Router Lifetime to ensure continuity
 * 
 * USAGE IN DNSMASQ:
 * Automatically included in Router Advertisement when DNS servers are configured for
 * advertisement (via dhcp-option=option6:dns-server or implicit from dnsmasq's own
 * IP). Enables hosts to receive DNS configuration in SLAAC-only deployments (M=0, O=0)
 * without requiring DHCPv6 for DNS server information.
 * 
 * INTEGRATION WITH DHCPV6:
 * When M=0, O=1 (stateless DHCPv6), DNS servers can be provided via either RDNSS
 * option or DHCPv6 option 23 (DNS_SERVERS). When both are present, hosts may use
 * either or both per local policy.
 * 
 * RFC COMPLIANCE: RFC 6106 Section 5.1
 */
#define ICMP6_OPT_RDNSS       25

/**
 * @def ICMP6_OPT_DNSSL
 * @brief DNS Search List (DNSSL) option type (31)
 * 
 * This option provides a list of DNS domain suffixes to be used by hosts when resolving
 * hostnames (DNS search list). This enables automatic domain suffix completion for
 * short hostnames, similar to the "search" directive in /etc/resolv.conf.
 * 
 * Option format (RFC 6106 Section 5.2):
 * - Type: 31 (1 octet)
 * - Length: Variable (1 octet) - depends on number and length of domain names
 * - Reserved: Must be zero (2 octets)
 * - Lifetime: Search list validity period in seconds (4 octets)
 * - Domain Names: One or more domain names in DNS name format (variable length)
 * 
 * DNS NAME FORMAT:
 * Domain names are encoded in standard DNS format (RFC 1035):
 * - Each label prefixed by length octet
 * - Terminated by zero-length label
 * - Example: "example.com" → 7 "example" 3 "com" 0
 * - Padded to 8-octet boundary
 * 
 * LIFETIME VALUES:
 * - 0: Search list immediately invalid (remove from configuration)
 * - 1-0xFFFFFFFF: Validity period in seconds
 * - Typical: 2 × Router Lifetime to ensure continuity
 * 
 * USAGE IN DNSMASQ:
 * Included in Router Advertisement when DNS search domains are configured via
 * dhcp-option=option6:domain-search or equivalent configuration. Allows hosts
 * to perform automatic domain suffix completion for short hostnames.
 * 
 * EXAMPLE SCENARIO:
 * If DNSSL contains "example.com" and "example.org", a host querying "server"
 * will automatically try:
 * 1. server.example.com
 * 2. server.example.org
 * This eliminates the need to specify fully-qualified domain names for internal resources.
 * 
 * INTEGRATION WITH DHCPV6:
 * When M=0, O=1 (stateless DHCPv6), DNS search list can be provided via either DNSSL
 * option or DHCPv6 option 24 (DOMAIN_LIST). When both are present, hosts may merge
 * or prefer one source per local policy.
 * 
 * RFC COMPLIANCE: RFC 6106 Section 5.2
 */
#define ICMP6_OPT_DNSSL       31

/** @} */ /* End of ICMPv6_ND_Options group */

//! ICMPv6 Router Advertisement and Neighbor Discovery protocol constants and structures.
//!
//! This module defines all wire-format constants, packet structures, and helper functions
//! for the IPv6 Router Advertisement (RA) and Neighbor Discovery (ND) subsystem, as
//! specified in:
//!
//! - **RFC 4861**: Neighbor Discovery for IP version 6 (IPv6)
//! - **RFC 4443**: Internet Control Message Protocol (ICMPv6) for IPv6
//! - **RFC 6106**: IPv6 Router Advertisement Options for DNS Configuration (RDNSS/DNSSL)
//! - **RFC 4191**: Default Router Preferences and More-Specific Routes
//! - **RFC 8781**: Discovering PREF64 in Router Advertisements
//! - **RFC 3775**: Mobility Support in IPv6 (Router Address flag in Prefix Information)
//!
//! Rewritten from C header `src/radv-protocol.h` (870 lines). This is the foundational
//! protocol definition file for the `radv` module — all other files in the module
//! (`server.rs`, `slaac.rs`) depend on the constants and structures defined here.
//!
//! Feature-gated under `dhcp6` via the parent module declaration in `src/dhcp/mod.rs`.

use std::net::Ipv6Addr;

// ============================================================================
// IPv6 Multicast Address Constants
// ============================================================================

/// IPv6 link-local all-nodes multicast address (`FF02::1`).
///
/// Used as the destination for unsolicited Router Advertisement messages that should
/// be received by all IPv6 nodes on the local link. Routers send periodic RAs to
/// this address to advertise their presence and network parameters.
///
/// Per RFC 4861 §6.1.2: Routers send unsolicited Router Advertisements to the
/// all-nodes multicast address.
///
/// This is a link-local scope multicast address (FF02), meaning it is not forwarded
/// beyond the local network segment.
pub const ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);

/// IPv6 link-local all-routers multicast address (`FF02::2`).
///
/// Used as the destination for Router Solicitation messages sent by hosts to request
/// immediate Router Advertisement messages from routers. This enables faster network
/// autoconfiguration than waiting for periodic unsolicited Router Advertisements.
///
/// Per RFC 4861 §6.1.1: Hosts send Router Solicitations to the all-routers
/// multicast address when they need to discover routers immediately upon interface
/// initialization.
pub const ALL_ROUTERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2);

// ============================================================================
// ICMPv6 Message Type Constants
// ============================================================================

/// ICMPv6 Echo Request message type (128).
///
/// Used for IPv6 reachability testing (ping). In dnsmasq context, used by the SLAAC
/// subsystem (`slaac.rs`) to probe candidate IPv6 addresses for duplicate address
/// detection before assigning them.
///
/// Per RFC 4443 §4.1: Echo Request messages are sent to test reachability of a
/// destination IPv6 address.
pub const ICMP6_ECHO_REQUEST: u8 = 128;

/// ICMPv6 Echo Reply message type (129).
///
/// Response to an Echo Request, indicating the target address is reachable and in use.
/// In dnsmasq, receiving an Echo Reply for a probed SLAAC address confirms the address
/// is alive on the network and triggers DNS registration.
///
/// Per RFC 4443 §4.2: Echo Reply is sent in response to an Echo Request.
pub const ICMP6_ECHO_REPLY: u8 = 129;

/// ICMPv6 Router Solicitation message type (133).
///
/// Sent by hosts to request immediate Router Advertisement messages from all routers
/// on the local link. The RA server listens for these messages on the raw ICMPv6
/// socket and responds with a unicast Router Advertisement to the soliciting host.
///
/// Per RFC 4861 §4.1: Router Solicitation messages are sent by hosts at interface
/// initialization to obtain network configuration immediately.
pub const ICMP6_ROUTER_SOLICIT: u8 = 133;

/// ICMPv6 Router Advertisement message type (134).
///
/// Sent by routers (dnsmasq acting as RA server) to advertise their presence, network
/// prefixes, MTU, DNS servers, and other configuration parameters to hosts on the
/// local link. Sent both periodically (unsolicited) and in response to Router
/// Solicitations.
///
/// Per RFC 4861 §4.2: Router Advertisement messages are sent by routers to convey
/// network configuration to hosts.
pub const ICMP6_ROUTER_ADVERT: u8 = 134;

/// ICMPv6 Neighbor Solicitation message type (135).
///
/// Used for IPv6 address resolution (equivalent to ARP for IPv4) and Duplicate Address
/// Detection (DAD). In dnsmasq, used to detect whether a candidate IPv6 address is
/// already in use on the local link before assigning it.
///
/// Per RFC 4861 §4.3: Neighbor Solicitation messages are sent to determine the
/// link-layer address of a neighbor or to verify a neighbor's reachability.
pub const ICMP6_NEIGHBOUR_SOLICIT: u8 = 135;

/// ICMPv6 Neighbor Advertisement message type (136).
///
/// Response to a Neighbor Solicitation, providing the link-layer address of the target
/// or confirming reachability. A Neighbor Advertisement received in response to DAD
/// indicates an address conflict.
///
/// Per RFC 4861 §4.4: Neighbor Advertisement messages respond to solicitations or
/// announce address changes.
pub const ICMP6_NEIGHBOUR_ADVERT: u8 = 136;

// ============================================================================
// ICMPv6 Neighbor Discovery Option Type Constants
// ============================================================================

/// Source Link-Layer Address option type (1).
///
/// Provides the link-layer address (MAC address) of the interface sending the ICMPv6
/// message. In Router Advertisements, this is the router's MAC address, allowing hosts
/// to populate their neighbor cache without separate Neighbor Solicitation exchange.
///
/// Per RFC 4861 §4.6.1.
pub const ICMP6_OPT_SOURCE_MAC: u8 = 1;

/// Prefix Information option type (3).
///
/// Advertises IPv6 prefixes available for SLAAC and/or on-link determination in Router
/// Advertisement messages. Multiple prefix options can be included in a single RA.
///
/// Per RFC 4861 §4.6.2. See [`PrefixOpt`] for the wire format.
pub const ICMP6_OPT_PREFIX: u8 = 3;

/// MTU option type (5).
///
/// Specifies the Maximum Transmission Unit that hosts should use when sending packets
/// on the link. Included in RAs when MTU is explicitly configured via `ra-param`.
///
/// Per RFC 4861 §4.6.4. Common values: 1500 (Ethernet), 1280 (IPv6 minimum), 9000 (jumbo).
pub const ICMP6_OPT_MTU: u8 = 5;

/// Advertisement Interval option type (7).
///
/// Specifies the maximum time between consecutive unsolicited Router Advertisement
/// messages, allowing hosts to detect router failures more quickly.
///
/// Per RFC 6275 §7.3 (Mobile IPv6).
pub const ICMP6_OPT_ADV_INTERVAL: u8 = 7;

/// Route Information option type (24).
///
/// Provides information about more-specific routes that should be added to the host's
/// routing table beyond the default route advertised in the main RA message.
///
/// Per RFC 4191 §2.3 (Default Router Preferences and More-Specific Routes).
pub const ICMP6_OPT_RT_INFO: u8 = 24;

/// Recursive DNS Server (RDNSS) option type (25).
///
/// Provides IPv6 addresses of recursive DNS servers that hosts should use for DNS
/// resolution. Enables DNS server configuration via Router Advertisement without
/// requiring DHCPv6, supporting pure SLAAC environments.
///
/// Per RFC 6106 §5.1.
pub const ICMP6_OPT_RDNSS: u8 = 25;

/// DNS Search List (DNSSL) option type (31).
///
/// Provides a list of DNS domain suffixes for hosts to use when resolving short
/// hostnames (search list). Enables automatic domain suffix completion without
/// requiring DHCPv6.
///
/// Per RFC 6106 §5.2.
pub const ICMP6_OPT_DNSSL: u8 = 31;

/// PREF64 option type (38).
///
/// Advertises a NAT64 prefix for IPv6-only hosts to synthesize IPv4-embedded IPv6
/// addresses. Allows DNS64/NAT64 deployments to inform clients of the prefix used
/// for address synthesis.
///
/// Per RFC 8781.
pub const ICMP6_OPT_PREF64: u8 = 38;

// ============================================================================
// Router Advertisement Flag Constants
// ============================================================================

/// Managed address configuration flag (M flag, bit 7 = 0x80).
///
/// When set in the RA flags byte, indicates that hosts should use DHCPv6 for
/// obtaining IPv6 addresses (stateful address configuration).
///
/// - M=1, O=0: Stateful DHCPv6 (addresses via DHCPv6)
/// - M=1, O=1: Stateful DHCPv6 with additional configuration
///
/// Per RFC 4861 §4.2.
pub const ND_RA_FLAG_MANAGED: u8 = 0x80;

/// Other configuration flag (O flag, bit 6 = 0x40).
///
/// When set in the RA flags byte, indicates that hosts should use DHCPv6 for
/// obtaining configuration other than addresses (e.g., DNS servers, NTP servers).
///
/// - M=0, O=1: Stateless DHCPv6 (SLAAC for addresses, DHCPv6 for other config)
/// - M=0, O=0: SLAAC only (no DHCPv6)
///
/// Per RFC 4861 §4.2.
pub const ND_RA_FLAG_OTHER: u8 = 0x40;

/// Home Agent flag (H flag, bit 5 = 0x20).
///
/// When set, indicates that the advertising router is a Mobile IPv6 Home Agent.
/// Not typically used by dnsmasq but defined for protocol completeness.
///
/// Per RFC 3775.
pub const ND_RA_FLAG_HA: u8 = 0x20;

/// Default Router Preference mask (bits 4-3 = 0x18).
///
/// Encodes the default router preference in the RA flags byte:
/// - `0x00` (00): Medium preference (default)
/// - `0x08` (01): High preference
/// - `0x18` (11): Low preference
/// - `0x10` (10): Reserved (must not be used)
///
/// Per RFC 4191.
pub const ND_RA_FLAG_PREF: u8 = 0x18;

// ============================================================================
// Prefix Information Option Flag Constants
// ============================================================================

/// On-link flag (L flag, bit 7 = 0x80).
///
/// When set in the prefix option flags byte, indicates that the prefix can be used
/// for on-link determination: destinations within this prefix are considered directly
/// reachable on the local link without routing through a gateway.
///
/// Per RFC 4861 §4.6.2.
pub const PREFIX_FLAG_ONLINK: u8 = 0x80;

/// Autonomous address-configuration flag (A flag, bit 6 = 0x40).
///
/// When set, indicates that hosts can use the prefix for Stateless Address
/// Autoconfiguration (SLAAC), forming complete IPv6 addresses by combining the
/// prefix with their interface identifier (EUI-64 or privacy extensions).
///
/// Per RFC 4862 §5.5.3.
pub const PREFIX_FLAG_AUTO: u8 = 0x40;

/// Router Address flag (R flag, bit 5 = 0x20).
///
/// When set, indicates that the prefix field contains a complete router address
/// rather than a network prefix. Used in Mobile IPv6 scenarios.
///
/// Per RFC 3775 §7.2.
pub const PREFIX_FLAG_ROUTER: u8 = 0x20;

// ============================================================================
// Hardware Type Constants (ARP hardware types for EUI-64 derivation)
// ============================================================================

/// Ethernet hardware type (ARPHRD_ETHER = 1).
///
/// Standard Ethernet interfaces with 6-byte MAC addresses. EUI-64 interface
/// identifier is derived by inserting 0xFF:0xFE in the middle of the MAC and
/// flipping the Universal/Local bit.
pub const ARPHRD_ETHER: u16 = 1;

/// IEEE 802 (Token Ring) hardware type (ARPHRD_IEEE802 = 6).
///
/// Token Ring interfaces with 6-byte MAC addresses. EUI-64 derivation follows
/// the same algorithm as Ethernet.
pub const ARPHRD_IEEE802: u16 = 6;

/// IEEE 1394 (FireWire) hardware type (ARPHRD_IEEE1394 = 24).
///
/// FireWire interfaces with 8-byte EUI-64 addresses. The hardware address is
/// copied directly into the interface identifier without flipping the U/L bit.
pub const ARPHRD_IEEE1394: u16 = 24;

/// EUI-64 hardware type (ARPHRD_EUI64 = 27).
///
/// Interfaces with native 8-byte EUI-64 addresses. The hardware address is
/// copied into the interface identifier with the Universal/Local bit flipped.
pub const ARPHRD_EUI64: u16 = 27;

// ============================================================================
// Packet Structures
// ============================================================================

/// ICMPv6 Echo Request/Reply packet structure (8 bytes).
///
/// Used for IPv6 reachability testing (ping). In dnsmasq, this structure is used
/// by the SLAAC subsystem to perform address conflict detection via ping testing
/// before assigning addresses.
///
/// Wire format (RFC 4443 §4.1/§4.2):
/// ```text
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |     Code      |          Checksum             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |           Identifier          |        Sequence Number        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PingPacket {
    /// ICMPv6 message type: 128 (Echo Request) or 129 (Echo Reply).
    pub msg_type: u8,
    /// ICMPv6 message code. Must be 0 for Echo Request/Reply per RFC 4443.
    pub code: u8,
    /// ICMPv6 checksum covering the entire message and IPv6 pseudo-header.
    /// Stored in network byte order (big-endian).
    pub checksum: u16,
    /// Echo identifier for matching requests with replies.
    /// Stored in network byte order (big-endian).
    pub identifier: u16,
    /// Echo sequence number for ordering and duplicate detection.
    /// Stored in network byte order (big-endian).
    pub sequence_no: u16,
}

impl PingPacket {
    /// Wire-format size of the PingPacket in bytes.
    pub const SIZE: usize = 8;

    /// Creates a new ICMPv6 Echo Request packet.
    ///
    /// The `identifier` is stored in network byte order (big-endian) to match
    /// the wire format. The checksum is set to 0 — the kernel computes it
    /// automatically when the `IPV6_CHECKSUM` socket option is set on the
    /// raw ICMPv6 socket.
    ///
    /// # Arguments
    /// * `identifier` - Echo identifier for matching replies (host byte order input,
    ///   converted to network byte order internally).
    pub fn new_echo_request(identifier: u16) -> Self {
        Self {
            msg_type: ICMP6_ECHO_REQUEST,
            code: 0,
            checksum: 0,
            identifier: identifier.to_be(),
            sequence_no: 0,
        }
    }

    /// Serializes the packet to a fixed-size byte array in wire format.
    ///
    /// All multi-byte fields are already stored in network byte order, so they
    /// are written directly without additional conversion.
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0] = self.msg_type;
        buf[1] = self.code;
        let cksum = self.checksum.to_be_bytes();
        buf[2] = cksum[0];
        buf[3] = cksum[1];
        let ident = self.identifier.to_be_bytes();
        buf[4] = ident[0];
        buf[5] = ident[1];
        let seq = self.sequence_no.to_be_bytes();
        buf[6] = seq[0];
        buf[7] = seq[1];
        buf
    }

    /// Deserializes a PingPacket from a byte slice in wire format.
    ///
    /// Returns `None` if the slice is shorter than [`Self::SIZE`] bytes.
    /// Multi-byte fields are read in network byte order (big-endian) and stored
    /// as-is, preserving the wire-format representation.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE {
            return None;
        }
        Some(Self {
            msg_type: data[0],
            code: data[1],
            checksum: u16::from_be_bytes([data[2], data[3]]),
            identifier: u16::from_be_bytes([data[4], data[5]]),
            sequence_no: u16::from_be_bytes([data[6], data[7]]),
        })
    }
}

/// ICMPv6 Router Advertisement message structure (16 bytes).
///
/// Defines the base Router Advertisement message header transmitted by IPv6 routers
/// to advertise their presence, network parameters, and address prefixes to hosts
/// on the local link. RA headers are followed by zero or more options (prefix
/// information, RDNSS, DNSSL, MTU, etc.).
///
/// Wire format (RFC 4861 §4.2):
/// ```text
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |     Code      |          Checksum             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Cur Hop Limit |M|O|H|Prf|Rsv.|       Router Lifetime         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         Reachable Time                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                          Retrans Timer                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RaPacket {
    /// ICMPv6 message type. Must be 134 (`ICMP6_ROUTER_ADVERT`).
    pub msg_type: u8,
    /// ICMPv6 message code. Must be 0 per RFC 4861.
    pub code: u8,
    /// ICMPv6 checksum (network byte order). Set to 0 for kernel computation.
    pub checksum: u16,
    /// Current Hop Limit: suggested default hop limit for outgoing packets.
    /// 0 = unspecified (router makes no recommendation). Typical value: 64.
    pub hop_limit: u8,
    /// RA flags byte encoding M/O/H/Prf fields.
    ///
    /// Bit layout (MSB → LSB):
    /// - Bit 7 (M): Managed address configuration
    /// - Bit 6 (O): Other configuration
    /// - Bit 5 (H): Home Agent
    /// - Bits 4-3 (Prf): Default Router Preference
    /// - Bits 2-0: Reserved
    pub flags: u8,
    /// Router Lifetime in seconds (network byte order).
    /// Maximum time this router should be used as a default router.
    /// 0 = not a default router.
    pub lifetime: u16,
    /// Reachable Time in milliseconds (network byte order).
    /// Time a neighbor is considered reachable after receiving a reachability
    /// confirmation. 0 = unspecified.
    pub reachable_time: u32,
    /// Retransmit Timer in milliseconds (network byte order).
    /// Time between retransmitted Neighbor Solicitation messages. 0 = unspecified.
    pub retrans_time: u32,
}

impl Default for RaPacket {
    fn default() -> Self {
        Self::new()
    }
}

impl RaPacket {
    /// Wire-format size of the RaPacket in bytes.
    pub const SIZE: usize = 16;

    /// Creates a new Router Advertisement packet with default values.
    ///
    /// Sets `msg_type` to 134 (`ICMP6_ROUTER_ADVERT`) and `code` to 0.
    /// All other fields are initialized to 0 (unspecified).
    pub fn new() -> Self {
        Self {
            msg_type: ICMP6_ROUTER_ADVERT,
            code: 0,
            checksum: 0,
            hop_limit: 0,
            flags: 0,
            lifetime: 0,
            reachable_time: 0,
            retrans_time: 0,
        }
    }

    /// Sets or clears the Managed address configuration flag (M flag, bit 7).
    ///
    /// When set, hosts should use DHCPv6 for obtaining IPv6 addresses.
    pub fn set_managed(&mut self, managed: bool) {
        if managed {
            self.flags |= ND_RA_FLAG_MANAGED;
        } else {
            self.flags &= !ND_RA_FLAG_MANAGED;
        }
    }

    /// Sets or clears the Other configuration flag (O flag, bit 6).
    ///
    /// When set, hosts should use DHCPv6 for non-address configuration.
    pub fn set_other(&mut self, other: bool) {
        if other {
            self.flags |= ND_RA_FLAG_OTHER;
        } else {
            self.flags &= !ND_RA_FLAG_OTHER;
        }
    }

    /// Sets the Default Router Preference in bits 4-3 of the flags byte.
    ///
    /// # Arguments
    /// * `prio` - The 2-bit priority value (only bits 1-0 are used):
    ///   - `0x00` (00): Medium preference (default)
    ///   - `0x01` (01): High preference
    ///   - `0x03` (11): Low preference
    ///   - `0x02` (10): Reserved
    ///
    /// The value is shifted left by 3 bits and masked into the flags byte.
    pub fn set_priority(&mut self, prio: u8) {
        // Clear the preference bits (4-3) and set the new value
        self.flags = (self.flags & !ND_RA_FLAG_PREF) | ((prio << 3) & ND_RA_FLAG_PREF);
    }

    /// Sets the Router Lifetime in seconds, converting to network byte order.
    ///
    /// # Arguments
    /// * `lifetime` - Router lifetime in seconds (host byte order).
    pub fn set_lifetime(&mut self, lifetime: u16) {
        self.lifetime = lifetime.to_be();
    }

    /// Serializes the packet to a fixed-size byte array in wire format.
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0] = self.msg_type;
        buf[1] = self.code;
        let cksum = self.checksum.to_be_bytes();
        buf[2] = cksum[0];
        buf[3] = cksum[1];
        buf[4] = self.hop_limit;
        buf[5] = self.flags;
        let lt = self.lifetime.to_be_bytes();
        buf[6] = lt[0];
        buf[7] = lt[1];
        let rt = self.reachable_time.to_be_bytes();
        buf[8] = rt[0];
        buf[9] = rt[1];
        buf[10] = rt[2];
        buf[11] = rt[3];
        let rtr = self.retrans_time.to_be_bytes();
        buf[12] = rtr[0];
        buf[13] = rtr[1];
        buf[14] = rtr[2];
        buf[15] = rtr[3];
        buf
    }

    /// Deserializes an RaPacket from a byte slice in wire format.
    ///
    /// Returns `None` if the slice is shorter than [`Self::SIZE`] bytes.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE {
            return None;
        }
        Some(Self {
            msg_type: data[0],
            code: data[1],
            checksum: u16::from_be_bytes([data[2], data[3]]),
            hop_limit: data[4],
            flags: data[5],
            lifetime: u16::from_be_bytes([data[6], data[7]]),
            reachable_time: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
            retrans_time: u32::from_be_bytes([data[12], data[13], data[14], data[15]]),
        })
    }
}

/// ICMPv6 Neighbor Solicitation/Advertisement packet structure (24 bytes).
///
/// Used for IPv6 address resolution (like ARP for IPv4) and Duplicate Address
/// Detection (DAD). In dnsmasq, used to detect whether a candidate IPv6 address
/// is already in use before assigning it via SLAAC or DHCPv6.
///
/// Wire format (RFC 4861 §4.3/§4.4):
/// ```text
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |     Code      |          Checksum             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |R|S|O|                     Reserved                            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +                                                               +
/// |                       Target Address                          |
/// +                                                               +
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// # Notes on wire format
///
/// The reserved/flags field is 4 bytes per RFC 4861 (type 1, code 1, checksum 2,
/// reserved/flags 4, target 16 = 24 bytes total). For Neighbor Solicitation the
/// field must be zero; for Neighbor Advertisement the high 3 bits encode R/S/O flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NeighPacket {
    /// ICMPv6 message type: 135 (Neighbor Solicitation) or 136 (Neighbor Advertisement).
    pub msg_type: u8,
    /// ICMPv6 message code. Must be 0 for NS/NA per RFC 4861.
    pub code: u8,
    /// ICMPv6 checksum (network byte order).
    pub checksum: u16,
    /// Flags/reserved field (network byte order).
    ///
    /// For Neighbor Solicitation (type 135): Must be zero.
    /// For Neighbor Advertisement (type 136):
    /// - Bit 31 (R): Router flag
    /// - Bit 30 (S): Solicited flag
    /// - Bit 29 (O): Override flag
    /// - Bits 28-0: Reserved (must be 0)
    pub flags_reserved: u32,
    /// Target IPv6 address (16 bytes, network byte order).
    ///
    /// For NS: the IPv6 address being queried or tested for DAD.
    /// For NA: the IPv6 address being advertised.
    pub target: [u8; 16],
}

impl NeighPacket {
    /// Wire-format size of the NeighPacket in bytes.
    pub const SIZE: usize = 24;

    /// Serializes the packet to a fixed-size byte array in wire format.
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0] = self.msg_type;
        buf[1] = self.code;
        let cksum = self.checksum.to_be_bytes();
        buf[2] = cksum[0];
        buf[3] = cksum[1];
        let flags = self.flags_reserved.to_be_bytes();
        buf[4] = flags[0];
        buf[5] = flags[1];
        buf[6] = flags[2];
        buf[7] = flags[3];
        buf[8..24].copy_from_slice(&self.target);
        buf
    }

    /// Deserializes a NeighPacket from a byte slice in wire format.
    ///
    /// Returns `None` if the slice is shorter than [`Self::SIZE`] bytes.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE {
            return None;
        }
        let mut target = [0u8; 16];
        target.copy_from_slice(&data[8..24]);
        Some(Self {
            msg_type: data[0],
            code: data[1],
            checksum: u16::from_be_bytes([data[2], data[3]]),
            flags_reserved: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
            target,
        })
    }
}

/// Prefix Information option for ICMPv6 Router Advertisement (32 bytes).
///
/// Advertises IPv6 prefixes available for Stateless Address Autoconfiguration (SLAAC)
/// and specifies whether prefixes are on-link for direct communication. Multiple
/// prefix options can be included in a single RA message to advertise multiple
/// prefixes.
///
/// Wire format (RFC 4861 §4.6.2):
/// ```text
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |    Length      | Prefix Length |L|A|R|  Rsrvd |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         Valid Lifetime                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       Preferred Lifetime                      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           Reserved                            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +                                                               +
/// |                            Prefix                             |
/// +                                                               +
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrefixOpt {
    /// Option type (always 3 = `ICMP6_OPT_PREFIX`).
    pub opt_type: u8,
    /// Option length in units of 8 octets (always 4, meaning 32 bytes total).
    pub len: u8,
    /// Prefix length in bits (typically 64 for standard IPv6 subnets).
    pub prefix_len: u8,
    /// Flags byte: L (0x80 on-link), A (0x40 autonomous/SLAAC), R (0x20 router address).
    pub flags: u8,
    /// Valid lifetime in seconds (network byte order).
    /// Time the prefix remains valid for on-link determination and address validity.
    /// `0xFFFFFFFF` = infinity.
    pub valid_lifetime: u32,
    /// Preferred lifetime in seconds (network byte order).
    /// Time addresses autoconfigured from this prefix remain preferred.
    /// Must be ≤ valid_lifetime. `0xFFFFFFFF` = infinity.
    pub preferred_lifetime: u32,
    /// Reserved field (must be 0).
    pub reserved: u32,
    /// IPv6 prefix address (16 bytes, network byte order).
    /// Only the first `prefix_len` bits are significant.
    pub prefix: [u8; 16],
}

impl Default for PrefixOpt {
    fn default() -> Self {
        Self {
            opt_type: ICMP6_OPT_PREFIX,
            len: 4,
            prefix_len: 0,
            flags: 0,
            valid_lifetime: 0,
            preferred_lifetime: 0,
            reserved: 0,
            prefix: [0u8; 16],
        }
    }
}

impl PrefixOpt {
    /// Wire-format size of the PrefixOpt in bytes.
    pub const SIZE: usize = 32;

    /// Creates a new Prefix Information option with the given prefix and prefix length.
    ///
    /// Sets `opt_type` to 3 (`ICMP6_OPT_PREFIX`) and `len` to 4 (32 bytes in
    /// 8-octet units). All flags and lifetimes are initialized to 0.
    ///
    /// # Arguments
    /// * `prefix` - The IPv6 prefix address to advertise.
    /// * `prefix_len` - The prefix length in bits (typically 64).
    pub fn new(prefix: Ipv6Addr, prefix_len: u8) -> Self {
        Self {
            opt_type: ICMP6_OPT_PREFIX,
            len: 4,
            prefix_len,
            flags: 0,
            valid_lifetime: 0,
            preferred_lifetime: 0,
            reserved: 0,
            prefix: prefix.octets(),
        }
    }

    /// Sets or clears the On-link flag (L flag, bit 7).
    ///
    /// When set, destinations within this prefix are considered on-link and can be
    /// reached directly without routing through a gateway.
    pub fn set_onlink(&mut self, onlink: bool) {
        if onlink {
            self.flags |= PREFIX_FLAG_ONLINK;
        } else {
            self.flags &= !PREFIX_FLAG_ONLINK;
        }
    }

    /// Sets or clears the Autonomous address-configuration flag (A flag, bit 6).
    ///
    /// When set, hosts can use this prefix for SLAAC, forming complete IPv6 addresses
    /// by combining the prefix with their interface identifier.
    pub fn set_autonomous(&mut self, autonomous: bool) {
        if autonomous {
            self.flags |= PREFIX_FLAG_AUTO;
        } else {
            self.flags &= !PREFIX_FLAG_AUTO;
        }
    }

    /// Sets or clears the Router Address flag (R flag, bit 5).
    ///
    /// When set, indicates the prefix field contains a complete router address
    /// rather than a network prefix (Mobile IPv6, RFC 3775 §7.2).
    pub fn set_router_address(&mut self, router_addr: bool) {
        if router_addr {
            self.flags |= PREFIX_FLAG_ROUTER;
        } else {
            self.flags &= !PREFIX_FLAG_ROUTER;
        }
    }

    /// Serializes the option to a fixed-size byte array in wire format.
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0] = self.opt_type;
        buf[1] = self.len;
        buf[2] = self.prefix_len;
        buf[3] = self.flags;
        let vl = self.valid_lifetime.to_be_bytes();
        buf[4] = vl[0];
        buf[5] = vl[1];
        buf[6] = vl[2];
        buf[7] = vl[3];
        let pl = self.preferred_lifetime.to_be_bytes();
        buf[8] = pl[0];
        buf[9] = pl[1];
        buf[10] = pl[2];
        buf[11] = pl[3];
        let res = self.reserved.to_be_bytes();
        buf[12] = res[0];
        buf[13] = res[1];
        buf[14] = res[2];
        buf[15] = res[3];
        buf[16..32].copy_from_slice(&self.prefix);
        buf
    }

    /// Deserializes a PrefixOpt from a byte slice in wire format.
    ///
    /// Returns `None` if the slice is shorter than [`Self::SIZE`] bytes.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE {
            return None;
        }
        let mut prefix = [0u8; 16];
        prefix.copy_from_slice(&data[16..32]);
        Some(Self {
            opt_type: data[0],
            len: data[1],
            prefix_len: data[2],
            flags: data[3],
            valid_lifetime: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
            preferred_lifetime: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
            reserved: u32::from_be_bytes([data[12], data[13], data[14], data[15]]),
            prefix,
        })
    }
}

// ============================================================================
// IPv6 Address Helper Functions
// ============================================================================

/// Checks whether an IPv6 address is a link-local address (fe80::/10).
///
/// Link-local addresses are used for communication within a single link segment
/// and are not routable. Replaces the C macro `IN6_IS_ADDR_LINKLOCAL()`.
///
/// # Arguments
/// * `addr` - The IPv6 address to check.
///
/// # Returns
/// `true` if the address is in the fe80::/10 range.
pub fn is_link_local(addr: &Ipv6Addr) -> bool {
    addr.segments()[0] & 0xffc0 == 0xfe80
}

/// Checks whether an IPv6 address is a Unique Local Address (ULA, fd00::/8).
///
/// ULA addresses (fc00::/7 with the L bit set, effectively fd00::/8) are used for
/// private/site-local addressing, similar to RFC 1918 addresses in IPv4. The RDNSS
/// source selection in the RA server uses this to match ULA addresses from configured
/// DNS server lists. Replaces the C check for `IN6_IS_ADDR_ULA()`.
///
/// # Arguments
/// * `addr` - The IPv6 address to check.
///
/// # Returns
/// `true` if the first octet is 0xfd (fd00::/8).
pub fn is_ula(addr: &Ipv6Addr) -> bool {
    addr.octets()[0] == 0xfd
}

/// Checks whether an IPv6 address is the unspecified address (::).
///
/// The unspecified address (all zeros) is used as a source address when a host has
/// not yet been assigned an address, particularly during DAD. Wraps
/// `Ipv6Addr::is_unspecified()` for consistency with other helper functions.
///
/// # Arguments
/// * `addr` - The IPv6 address to check.
///
/// # Returns
/// `true` if the address is `::` (all zeros).
pub fn is_unspecified_v6(addr: &Ipv6Addr) -> bool {
    addr.is_unspecified()
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- Constant value tests ---

    #[test]
    fn test_multicast_addresses() {
        assert_eq!(ALL_NODES, Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1));
        assert_eq!(ALL_ROUTERS, Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2));
    }

    #[test]
    fn test_icmp6_type_constants() {
        assert_eq!(ICMP6_ECHO_REQUEST, 128);
        assert_eq!(ICMP6_ECHO_REPLY, 129);
        assert_eq!(ICMP6_ROUTER_SOLICIT, 133);
        assert_eq!(ICMP6_ROUTER_ADVERT, 134);
        assert_eq!(ICMP6_NEIGHBOUR_SOLICIT, 135);
        assert_eq!(ICMP6_NEIGHBOUR_ADVERT, 136);
    }

    #[test]
    fn test_nd_option_type_constants() {
        assert_eq!(ICMP6_OPT_SOURCE_MAC, 1);
        assert_eq!(ICMP6_OPT_PREFIX, 3);
        assert_eq!(ICMP6_OPT_MTU, 5);
        assert_eq!(ICMP6_OPT_ADV_INTERVAL, 7);
        assert_eq!(ICMP6_OPT_RT_INFO, 24);
        assert_eq!(ICMP6_OPT_RDNSS, 25);
        assert_eq!(ICMP6_OPT_DNSSL, 31);
        assert_eq!(ICMP6_OPT_PREF64, 38);
    }

    #[test]
    fn test_ra_flag_constants() {
        assert_eq!(ND_RA_FLAG_MANAGED, 0x80);
        assert_eq!(ND_RA_FLAG_OTHER, 0x40);
        assert_eq!(ND_RA_FLAG_HA, 0x20);
        assert_eq!(ND_RA_FLAG_PREF, 0x18);
    }

    #[test]
    fn test_prefix_flag_constants() {
        assert_eq!(PREFIX_FLAG_ONLINK, 0x80);
        assert_eq!(PREFIX_FLAG_AUTO, 0x40);
        assert_eq!(PREFIX_FLAG_ROUTER, 0x20);
    }

    #[test]
    fn test_hardware_type_constants() {
        assert_eq!(ARPHRD_ETHER, 1);
        assert_eq!(ARPHRD_IEEE802, 6);
        assert_eq!(ARPHRD_IEEE1394, 24);
        assert_eq!(ARPHRD_EUI64, 27);
    }

    // --- Struct size tests ---

    #[test]
    fn test_ping_packet_size() {
        assert_eq!(PingPacket::SIZE, 8);
        let pkt = PingPacket::default();
        assert_eq!(pkt.to_bytes().len(), 8);
    }

    #[test]
    fn test_ra_packet_size() {
        assert_eq!(RaPacket::SIZE, 16);
        let pkt = RaPacket::new();
        assert_eq!(pkt.to_bytes().len(), 16);
    }

    #[test]
    fn test_neigh_packet_size() {
        assert_eq!(NeighPacket::SIZE, 24);
        let pkt = NeighPacket::default();
        assert_eq!(pkt.to_bytes().len(), 24);
    }

    #[test]
    fn test_prefix_opt_size() {
        assert_eq!(PrefixOpt::SIZE, 32);
        let opt = PrefixOpt::default();
        assert_eq!(opt.to_bytes().len(), 32);
    }

    // --- Serialization roundtrip tests ---

    #[test]
    fn test_ping_packet_roundtrip() {
        let pkt = PingPacket::new_echo_request(0x1234);
        let bytes = pkt.to_bytes();
        let decoded = PingPacket::from_bytes(&bytes).unwrap();
        assert_eq!(pkt, decoded);
        assert_eq!(decoded.msg_type, ICMP6_ECHO_REQUEST);
        assert_eq!(decoded.code, 0);
        assert_eq!(decoded.checksum, 0);
        // Identifier stored in network byte order
        assert_eq!(decoded.identifier, 0x1234u16.to_be());
        assert_eq!(decoded.sequence_no, 0);
    }

    #[test]
    fn test_ra_packet_roundtrip() {
        let mut pkt = RaPacket::new();
        pkt.hop_limit = 64;
        pkt.set_managed(true);
        pkt.set_other(true);
        pkt.set_priority(1); // High preference
        pkt.set_lifetime(1800);
        pkt.reachable_time = 30000u32.to_be();
        pkt.retrans_time = 1000u32.to_be();

        let bytes = pkt.to_bytes();
        let decoded = RaPacket::from_bytes(&bytes).unwrap();
        assert_eq!(pkt, decoded);
        assert_eq!(decoded.msg_type, ICMP6_ROUTER_ADVERT);
        assert_eq!(decoded.hop_limit, 64);
        assert_eq!(decoded.flags & ND_RA_FLAG_MANAGED, ND_RA_FLAG_MANAGED);
        assert_eq!(decoded.flags & ND_RA_FLAG_OTHER, ND_RA_FLAG_OTHER);
        assert_eq!(decoded.flags & ND_RA_FLAG_PREF, 0x08); // High = 01 << 3 = 0x08
    }

    #[test]
    fn test_neigh_packet_roundtrip() {
        let target_addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let pkt = NeighPacket {
            msg_type: ICMP6_NEIGHBOUR_SOLICIT,
            code: 0,
            checksum: 0,
            flags_reserved: 0,
            target: target_addr.octets(),
        };
        let bytes = pkt.to_bytes();
        let decoded = NeighPacket::from_bytes(&bytes).unwrap();
        assert_eq!(pkt, decoded);
        assert_eq!(decoded.msg_type, ICMP6_NEIGHBOUR_SOLICIT);
        assert_eq!(Ipv6Addr::from(decoded.target), target_addr);
    }

    #[test]
    fn test_prefix_opt_roundtrip() {
        let prefix = Ipv6Addr::new(0x2001, 0xdb8, 0x0001, 0, 0, 0, 0, 0);
        let mut opt = PrefixOpt::new(prefix, 64);
        opt.set_onlink(true);
        opt.set_autonomous(true);
        opt.valid_lifetime = 2592000u32.to_be();
        opt.preferred_lifetime = 604800u32.to_be();

        let bytes = opt.to_bytes();
        let decoded = PrefixOpt::from_bytes(&bytes).unwrap();
        assert_eq!(opt, decoded);
        assert_eq!(decoded.opt_type, ICMP6_OPT_PREFIX);
        assert_eq!(decoded.len, 4);
        assert_eq!(decoded.prefix_len, 64);
        assert_eq!(decoded.flags & PREFIX_FLAG_ONLINK, PREFIX_FLAG_ONLINK);
        assert_eq!(decoded.flags & PREFIX_FLAG_AUTO, PREFIX_FLAG_AUTO);
        assert_eq!(decoded.flags & PREFIX_FLAG_ROUTER, 0);
        assert_eq!(Ipv6Addr::from(decoded.prefix), prefix);
    }

    #[test]
    fn test_prefix_opt_router_address_flag() {
        let prefix = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let mut opt = PrefixOpt::new(prefix, 128);
        opt.set_router_address(true);
        assert_eq!(opt.flags & PREFIX_FLAG_ROUTER, PREFIX_FLAG_ROUTER);
        opt.set_router_address(false);
        assert_eq!(opt.flags & PREFIX_FLAG_ROUTER, 0);
    }

    // --- RaPacket flag manipulation tests ---

    #[test]
    fn test_ra_packet_flag_operations() {
        let mut pkt = RaPacket::new();

        // Test managed flag
        pkt.set_managed(true);
        assert_eq!(pkt.flags & ND_RA_FLAG_MANAGED, ND_RA_FLAG_MANAGED);
        pkt.set_managed(false);
        assert_eq!(pkt.flags & ND_RA_FLAG_MANAGED, 0);

        // Test other flag
        pkt.set_other(true);
        assert_eq!(pkt.flags & ND_RA_FLAG_OTHER, ND_RA_FLAG_OTHER);
        pkt.set_other(false);
        assert_eq!(pkt.flags & ND_RA_FLAG_OTHER, 0);

        // Test priority values
        pkt.set_priority(0); // Medium
        assert_eq!(pkt.flags & ND_RA_FLAG_PREF, 0x00);

        pkt.set_priority(1); // High
        assert_eq!(pkt.flags & ND_RA_FLAG_PREF, 0x08);

        pkt.set_priority(3); // Low
        assert_eq!(pkt.flags & ND_RA_FLAG_PREF, 0x18);

        // Test flags are independent
        pkt.set_managed(true);
        pkt.set_other(true);
        pkt.set_priority(1);
        assert_eq!(pkt.flags, 0x80 | 0x40 | 0x08);
    }

    #[test]
    fn test_ra_packet_lifetime_network_order() {
        let mut pkt = RaPacket::new();
        pkt.set_lifetime(1800); // 1800 seconds
        // 1800 = 0x0708 in big-endian
        let bytes = pkt.to_bytes();
        // Lifetime is at bytes[6..8]
        assert_eq!(u16::from_be_bytes([bytes[6], bytes[7]]), 1800u16.to_be());
    }

    // --- from_bytes edge cases ---

    #[test]
    fn test_ping_packet_from_bytes_too_short() {
        assert!(PingPacket::from_bytes(&[0u8; 7]).is_none());
        assert!(PingPacket::from_bytes(&[]).is_none());
    }

    #[test]
    fn test_ra_packet_from_bytes_too_short() {
        assert!(RaPacket::from_bytes(&[0u8; 15]).is_none());
        assert!(RaPacket::from_bytes(&[]).is_none());
    }

    #[test]
    fn test_neigh_packet_from_bytes_too_short() {
        assert!(NeighPacket::from_bytes(&[0u8; 23]).is_none());
        assert!(NeighPacket::from_bytes(&[]).is_none());
    }

    #[test]
    fn test_prefix_opt_from_bytes_too_short() {
        assert!(PrefixOpt::from_bytes(&[0u8; 31]).is_none());
        assert!(PrefixOpt::from_bytes(&[]).is_none());
    }

    #[test]
    fn test_from_bytes_exact_size() {
        // Should succeed with exactly the right number of bytes
        assert!(PingPacket::from_bytes(&[0u8; 8]).is_some());
        assert!(RaPacket::from_bytes(&[0u8; 16]).is_some());
        assert!(NeighPacket::from_bytes(&[0u8; 24]).is_some());
        assert!(PrefixOpt::from_bytes(&[0u8; 32]).is_some());
    }

    #[test]
    fn test_from_bytes_extra_data() {
        // Should succeed with extra trailing bytes (common in real packets)
        assert!(PingPacket::from_bytes(&[0u8; 100]).is_some());
        assert!(RaPacket::from_bytes(&[0u8; 100]).is_some());
        assert!(NeighPacket::from_bytes(&[0u8; 100]).is_some());
        assert!(PrefixOpt::from_bytes(&[0u8; 100]).is_some());
    }

    // --- IPv6 address helper function tests ---

    #[test]
    fn test_is_link_local() {
        // fe80::/10 — link-local
        assert!(is_link_local(&Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)));
        assert!(is_link_local(&Ipv6Addr::new(0xfe80, 0, 0, 0, 0xdead, 0xbeef, 0xcafe, 0xbabe)));
        // febf::1 is still within fe80::/10 (0xfebf & 0xffc0 == 0xfe80)
        assert!(is_link_local(&Ipv6Addr::new(0xfebf, 0, 0, 0, 0, 0, 0, 1)));

        // Not link-local
        assert!(!is_link_local(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)));
        assert!(!is_link_local(&Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)));
        assert!(!is_link_local(&Ipv6Addr::UNSPECIFIED));
        assert!(!is_link_local(&Ipv6Addr::LOCALHOST));
        // fec0::1 is NOT link-local (fec0 & ffc0 = fec0 != fe80)
        assert!(!is_link_local(&Ipv6Addr::new(0xfec0, 0, 0, 0, 0, 0, 0, 1)));
    }

    #[test]
    fn test_is_ula() {
        // fd00::/8 — Unique Local Addresses
        assert!(is_ula(&Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)));
        assert!(is_ula(&Ipv6Addr::new(0xfdff, 0xffff, 0xffff, 0, 0, 0, 0, 0)));
        assert!(is_ula(&Ipv6Addr::new(0xfd12, 0x3456, 0x7890, 0, 0, 0, 0, 1)));

        // Not ULA
        assert!(!is_ula(&Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1))); // fc00 != fd
        assert!(!is_ula(&Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))); // link-local
        assert!(!is_ula(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))); // global
        assert!(!is_ula(&Ipv6Addr::UNSPECIFIED));
    }

    #[test]
    fn test_is_unspecified_v6() {
        assert!(is_unspecified_v6(&Ipv6Addr::UNSPECIFIED));
        assert!(is_unspecified_v6(&Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)));
        assert!(!is_unspecified_v6(&Ipv6Addr::LOCALHOST));
        assert!(!is_unspecified_v6(&Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)));
        assert!(!is_unspecified_v6(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)));
    }

    // --- Default value tests ---

    #[test]
    fn test_ra_packet_default() {
        let pkt = RaPacket::default();
        assert_eq!(pkt.msg_type, ICMP6_ROUTER_ADVERT);
        assert_eq!(pkt.code, 0);
        assert_eq!(pkt.flags, 0);
        assert_eq!(pkt.hop_limit, 0);
        assert_eq!(pkt.lifetime, 0);
        assert_eq!(pkt.reachable_time, 0);
        assert_eq!(pkt.retrans_time, 0);
    }

    #[test]
    fn test_prefix_opt_default() {
        let opt = PrefixOpt::default();
        assert_eq!(opt.opt_type, ICMP6_OPT_PREFIX);
        assert_eq!(opt.len, 4);
        assert_eq!(opt.prefix_len, 0);
        assert_eq!(opt.flags, 0);
        assert_eq!(opt.valid_lifetime, 0);
        assert_eq!(opt.preferred_lifetime, 0);
        assert_eq!(opt.reserved, 0);
        assert_eq!(opt.prefix, [0u8; 16]);
    }

    // --- Wire format specific tests ---

    #[test]
    fn test_ping_packet_wire_format() {
        let pkt = PingPacket {
            msg_type: 128,
            code: 0,
            checksum: 0xABCD,
            identifier: 0x1234,
            sequence_no: 0x0001,
        };
        let bytes = pkt.to_bytes();
        assert_eq!(bytes[0], 128); // type
        assert_eq!(bytes[1], 0);   // code
        // checksum in network byte order
        assert_eq!(bytes[2], 0xAB);
        assert_eq!(bytes[3], 0xCD);
        // identifier in network byte order
        assert_eq!(bytes[4], 0x12);
        assert_eq!(bytes[5], 0x34);
        // sequence in network byte order
        assert_eq!(bytes[6], 0x00);
        assert_eq!(bytes[7], 0x01);
    }

    #[test]
    fn test_neigh_packet_target_address_preserved() {
        let addr = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x0001);
        let pkt = NeighPacket {
            msg_type: ICMP6_NEIGHBOUR_SOLICIT,
            code: 0,
            checksum: 0,
            flags_reserved: 0,
            target: addr.octets(),
        };
        let bytes = pkt.to_bytes();
        let decoded = NeighPacket::from_bytes(&bytes).unwrap();
        assert_eq!(Ipv6Addr::from(decoded.target), addr);
    }

    #[test]
    fn test_prefix_opt_all_flags() {
        let prefix = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0);
        let mut opt = PrefixOpt::new(prefix, 64);
        opt.set_onlink(true);
        opt.set_autonomous(true);
        opt.set_router_address(true);
        assert_eq!(opt.flags, PREFIX_FLAG_ONLINK | PREFIX_FLAG_AUTO | PREFIX_FLAG_ROUTER);
        assert_eq!(opt.flags, 0x80 | 0x40 | 0x20);
        assert_eq!(opt.flags, 0xE0);
    }
}

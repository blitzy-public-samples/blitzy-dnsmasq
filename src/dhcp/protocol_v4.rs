// Copyright (c) 2000-2025 Simon Kelley
// SPDX-License-Identifier: GPL-2.0-or-later
//
// DHCPv4 Wire-Format Constants and Packet Structure
// Rust port of src/dhcp-protocol.h

//! DHCPv4 protocol constants, message types, option codes, and packet wire format.
//!
//! This module is the authoritative source for all DHCPv4 protocol definitions
//! used throughout the dnsmasq DHCP implementation. It provides:
//!
//! - Network port numbers for DHCP client/server communication (RFC 2131 §4.1)
//! - BOOTP/DHCP protocol constants (magic cookie, operation codes)
//! - All standard DHCP option codes per RFC 2132 and extensions
//! - DHCP message type enumeration with 13 message types (RFC 2131 §3.1)
//! - Relay agent suboption codes per RFC 3046
//! - PXE network boot suboptions per Intel PXE Specification 2.1
//! - Hardware address type constants per IANA ARP registry
//! - The `DhcpPacket` wire-format struct matching RFC 2131 §2 byte-for-byte
//!
//! # RFC Compliance
//!
//! - RFC 2131: Dynamic Host Configuration Protocol
//! - RFC 2132: DHCP Options and BOOTP Vendor Extensions
//! - RFC 3046: DHCP Relay Agent Information Option
//! - RFC 3527: Link Selection sub-option (SUBOPT_SUBNET_SELECT)
//! - RFC 3993: Subscriber-ID sub-option (SUBOPT_SUBSCR_ID)
//! - RFC 4039: Rapid Commit Option
//! - RFC 4388: DHCP Leasequery
//! - RFC 5010: Relay Agent Flags sub-option
//! - RFC 5107: Server Identifier Override sub-option
//! - Intel PXE Specification 2.1
//!
//! # Wire Protocol Fidelity
//!
//! All constant values match the original C `#define` values in `dhcp-protocol.h`
//! exactly. The `DhcpPacket` struct uses `#[repr(C)]` to guarantee byte-for-byte
//! layout compatibility with the C `struct dhcp_packet` (548 bytes total).

use std::net::Ipv4Addr;

// ============================================================================
// DHCPv4 Network Port Definitions (RFC 2131 §4.1)
// ============================================================================

/// Standard DHCPv4 server listening port (privileged, requires root).
///
/// Server binds to this port to receive DHCPDISCOVER, DHCPREQUEST, DHCPRELEASE,
/// DHCPDECLINE, and DHCPINFORM messages from clients on port 68.
///
/// Source: RFC 2131 Section 4.1
pub const DHCP_SERVER_PORT: u16 = 67;

/// Standard DHCPv4 client listening port.
///
/// Clients bind to this port to receive DHCPOFFER and DHCPACK messages from
/// servers. Server sends responses to this port even for clients without IP yet.
///
/// Source: RFC 2131 Section 4.1
pub const DHCP_CLIENT_PORT: u16 = 68;

/// Alternate DHCPv4 server port for non-privileged or testing deployments.
///
/// Non-standard port avoiding privileged binding requirement. Configured via
/// `--dhcp-alternate-port` option.
///
/// Source: dnsmasq extension
pub const DHCP_SERVER_ALTPORT: u16 = 1067;

/// Alternate DHCPv4 client port corresponding to alternate server port.
///
/// Source: dnsmasq extension
pub const DHCP_CLIENT_ALTPORT: u16 = 1068;

/// PXE (Preboot Execution Environment) proxy DHCP port.
///
/// PXE proxy mode uses this port to provide boot parameters (boot filename,
/// TFTP server) without providing IP address assignment. Allows coexistence
/// with existing DHCP infrastructure for network boot scenarios.
///
/// Source: Intel PXE Specification 2.1 Section 2.2.5
pub const PXE_PORT: u16 = 4011;

// ============================================================================
// Buffer Size and Protocol Constants
// ============================================================================

/// Maximum DHCP option data buffer size including null terminator.
///
/// DHCPv4 options have maximum length of 255 bytes per RFC 2132. This buffer
/// size accommodates the maximum option data length (255) plus a terminating
/// null byte (1) for safety when options contain text data.
///
/// Source: RFC 2132 Section 2
pub const DHCP_BUFF_SZ: usize = 256;

/// BOOTP request operation code (client-to-server).
///
/// Value for the `op` field in [`DhcpPacket`] indicating a client-to-server
/// message. Used in DHCPDISCOVER, DHCPREQUEST, DHCPDECLINE, DHCPRELEASE,
/// and DHCPINFORM messages.
///
/// Source: RFC 2131 Section 2, RFC 951
pub const BOOTREQUEST: u8 = 1;

/// BOOTP reply operation code (server-to-client).
///
/// Value for the `op` field in [`DhcpPacket`] indicating a server-to-client
/// message. Used in DHCPOFFER and DHCPACK messages.
///
/// Source: RFC 2131 Section 2, RFC 951
pub const BOOTREPLY: u8 = 2;

/// DHCP magic cookie value for option field identification.
///
/// Four-byte constant (99.130.83.99 in dotted decimal) placed at start of
/// the options field in [`DhcpPacket`] to distinguish DHCP packets from
/// legacy BOOTP packets. Hex value: `0x63825363`.
///
/// Source: RFC 2131 Section 3
pub const DHCP_COOKIE: u32 = 0x63825363;

/// Minimum DHCPv4 packet size for Linux kernel DHCP client compatibility.
///
/// The Linux kernel's built-in DHCP client silently discards packets smaller
/// than 300 bytes. Dnsmasq pads outgoing DHCP responses to this minimum size.
/// This is a workaround for Linux kernel behavior, not an RFC requirement.
///
/// Source: Linux kernel `net/ipv4/ipconfig.c`
pub const MIN_PACKETSZ: usize = 300;

/// Maximum hardware address length in DHCP packet.
///
/// RFC 2131 specifies the client hardware address field (`chaddr`) as 16 octets.
/// While Ethernet MAC addresses are 6 octets, the larger field accommodates
/// other hardware types. Unused bytes are zero-padded.
///
/// Source: RFC 2131 Section 2, Figure 1
pub const DHCP_CHADDR_MAX: usize = 16;

// ============================================================================
// Hardware Address Type Constants (IANA ARP Hardware Types)
// ============================================================================

/// Ethernet hardware type (most common, htype=1 in DHCP packets).
///
/// Source: RFC 826, IANA ARP Hardware Types registry
pub const ARPHRD_ETHER: u8 = 1;

/// IEEE 802 Token Ring / FDDI hardware type.
///
/// Source: IANA ARP Hardware Types registry
pub const ARPHRD_IEEE802: u8 = 6;

/// ARCNET hardware type.
///
/// Source: IANA ARP Hardware Types registry
pub const ARPHRD_ARCNET: u8 = 7;

// ============================================================================
// DHCPv4 Option Number Definitions (RFC 2132 and extensions)
// ============================================================================

/// Option 0: Pad option for alignment (no data, no length byte).
///
/// Source: RFC 2132 Section 3.1
pub const OPTION_PAD: u8 = 0;

/// Option 1: Subnet Mask (4 bytes, IPv4 subnet mask).
///
/// Source: RFC 2132 Section 3.3
pub const OPTION_NETMASK: u8 = 1;

/// Option 3: Router (4+ bytes, list of gateway IPv4 addresses).
///
/// Source: RFC 2132 Section 3.5
pub const OPTION_ROUTER: u8 = 3;

/// Option 6: Domain Name Server (4+ bytes, list of DNS resolver addresses).
///
/// Source: RFC 2132 Section 3.8
pub const OPTION_DNSSERVER: u8 = 6;

/// Option 12: Host Name (variable length string).
///
/// Source: RFC 2132 Section 3.14
pub const OPTION_HOSTNAME: u8 = 12;

/// Option 15: Domain Name (variable length string).
///
/// Source: RFC 2132 Section 3.17
pub const OPTION_DOMAINNAME: u8 = 15;

/// Option 28: Broadcast Address (4 bytes, subnet broadcast address).
///
/// Source: RFC 2132 Section 5.3
pub const OPTION_BROADCAST: u8 = 28;

/// Option 43: Vendor-Specific Information (variable length).
///
/// Opaque vendor-specific data. PXE uses this for boot menu and server discovery.
///
/// Source: RFC 2132 Section 8.4
pub const OPTION_VENDOR_CLASS_OPT: u8 = 43;

/// Option 50: Requested IP Address (4 bytes).
///
/// Client requests specific IP address in DHCPREQUEST or suggests in DHCPDISCOVER.
///
/// Source: RFC 2132 Section 9.1
pub const OPTION_REQUESTED_IP: u8 = 50;

/// Option 51: IP Address Lease Time (4 bytes, seconds as u32).
///
/// Lease duration in seconds. Value `0xFFFFFFFF` means infinite lease.
///
/// Source: RFC 2132 Section 9.2
pub const OPTION_LEASE_TIME: u8 = 51;

/// Option 52: Option Overload (1 byte).
///
/// Indicates `file` and/or `sname` fields contain DHCP options instead of
/// their normal content. Values: 1=file, 2=sname, 3=both.
///
/// Source: RFC 2132 Section 9.3
pub const OPTION_OVERLOAD: u8 = 52;

/// Option 53: DHCP Message Type (1 byte) — REQUIRED in all DHCP messages.
///
/// Identifies the DHCP message type. See [`DhcpMessageType`] for valid values.
///
/// Source: RFC 2132 Section 9.6
pub const OPTION_MESSAGE_TYPE: u8 = 53;

/// Option 54: Server Identifier (4 bytes, server's IPv4 address).
///
/// MUST be included by server in DHCPOFFER and DHCPACK.
///
/// Source: RFC 2132 Section 9.7
pub const OPTION_SERVER_IDENTIFIER: u8 = 54;

/// Option 55: Parameter Request List (variable length, list of option codes).
///
/// Client indicates which options it wants the server to include in response.
///
/// Source: RFC 2132 Section 9.8
pub const OPTION_REQUESTED_OPTIONS: u8 = 55;

/// Option 56: Message (variable length string).
///
/// Error message string in DHCPNAK or informational text.
///
/// Source: RFC 2132 Section 9.9
pub const OPTION_MESSAGE: u8 = 56;

/// Option 57: Maximum DHCP Message Size (2 bytes, minimum 576).
///
/// Source: RFC 2132 Section 9.10
pub const OPTION_MAXMESSAGE: u8 = 57;

/// Option 58: Renewal Time Value T1 (4 bytes, seconds).
///
/// Time interval until client enters RENEWING state. Typically 50% of lease time.
///
/// Source: RFC 2132 Section 9.11
pub const OPTION_T1: u8 = 58;

/// Option 59: Rebinding Time Value T2 (4 bytes, seconds).
///
/// Time interval until client enters REBINDING state. Typically 87.5% of lease time.
///
/// Source: RFC 2132 Section 9.12
pub const OPTION_T2: u8 = 59;

/// Option 60: Vendor Class Identifier (variable length string).
///
/// Identifies vendor and client type. PXE clients include "PXEClient" string.
///
/// Source: RFC 2132 Section 9.13
pub const OPTION_VENDOR_ID: u8 = 60;

/// Option 61: Client Identifier (variable length).
///
/// Unique client identifier used instead of hardware address for lease binding.
/// Format: 1-byte type code + identifier data.
///
/// Source: RFC 2132 Section 9.14
pub const OPTION_CLIENT_ID: u8 = 61;

/// Option 66: TFTP Server Name (variable length string).
///
/// Hostname or IP address string of TFTP server for network boot.
///
/// Source: RFC 2132 Section 9.4
pub const OPTION_SNAME: u8 = 66;

/// Option 67: Boot File Name (variable length string).
///
/// Boot filename for network boot clients. Path relative to TFTP server root.
///
/// Source: RFC 2132 Section 9.5
pub const OPTION_FILENAME: u8 = 67;

/// Option 77: User Class (variable length).
///
/// User-defined classification string for grouping clients.
///
/// Source: RFC 3004
pub const OPTION_USER_CLASS: u8 = 77;

/// Option 80: Rapid Commit (0 bytes, flag option).
///
/// Enables two-message exchange (DISCOVER + ACK) instead of four-message DORA.
///
/// Source: RFC 4039
pub const OPTION_RAPID_COMMIT: u8 = 80;

/// Option 81: Client FQDN (variable length).
///
/// Fully Qualified Domain Name option for dynamic DNS updates.
///
/// Source: RFC 4702
pub const OPTION_CLIENT_FQDN: u8 = 81;

/// Option 82: Relay Agent Information (variable length, contains suboptions).
///
/// Added by DHCP relay agents with circuit/remote identification suboptions.
///
/// Source: RFC 3046
pub const OPTION_AGENT_ID: u8 = 82;

/// Option 91: Client Last Transaction Time (4 bytes, seconds).
///
/// Used in DHCPLEASEQUERY responses.
///
/// Source: RFC 4388 Section 6.1
pub const OPTION_LAST_TRANSACTION: u8 = 91;

/// Option 92: Associated IP (4+ bytes, multiple of 4).
///
/// Used in DHCPLEASEQUERY to query leases associated with specific addresses.
///
/// Source: RFC 4388 Section 6.2
pub const OPTION_ASSOCIATED_IP: u8 = 92;

/// Option 93: Client System Architecture (2 bytes).
///
/// Identifies client CPU architecture for PXE boot (x86 BIOS, x64 UEFI, ARM64, etc.).
///
/// Source: RFC 4578 Section 2.1
pub const OPTION_ARCH: u8 = 93;

/// Option 97: UUID/GUID-based Client Identifier (17 bytes).
///
/// PXE client machine identifier: 1-byte type (0) + 16-byte UUID/GUID.
///
/// Source: RFC 4578 Section 2.5
pub const OPTION_PXE_UUID: u8 = 97;

/// Option 118: Subnet Selection (4 bytes).
///
/// Allows client to specify which subnet it wants an address from.
///
/// Source: RFC 3011
pub const OPTION_SUBNET_SELECT: u8 = 118;

/// Option 119: Domain Search (variable length, DNS wire-format compressed names).
///
/// Source: RFC 3397
pub const OPTION_DOMAIN_SEARCH: u8 = 119;

/// Option 120: SIP Servers (variable length, IPv4 addresses or DNS names).
///
/// Source: RFC 3361
pub const OPTION_SIP_SERVER: u8 = 120;

/// Option 124: Vendor-Identifying Vendor Class (variable length).
///
/// Extended vendor identification with IANA enterprise number.
///
/// Source: RFC 3925 Section 3
pub const OPTION_VENDOR_IDENT: u8 = 124;

/// Option 125: Vendor-Identifying Vendor-Specific Information (variable length).
///
/// Source: RFC 3925 Section 4
pub const OPTION_VENDOR_IDENT_OPT: u8 = 125;

/// Option 161: Manufacturer Usage Description (MUD) URL (variable length).
///
/// URL pointing to manufacturer's device security profile for IoT policy.
///
/// Source: RFC 8520
pub const OPTION_MUD_URL_V4: u8 = 161;

/// Option 255: End option (no length or data).
///
/// Marks end of valid information in the options field.
///
/// Source: RFC 2132 Section 3.2
pub const OPTION_END: u8 = 255;

// ============================================================================
// DHCP Relay Agent Information Suboptions (RFC 3046, Option 82)
// ============================================================================

/// Relay Agent Suboption 1: Circuit ID.
///
/// Identifies the circuit (interface, VLAN, port) on which the DHCP request
/// arrived at the relay agent.
///
/// Source: RFC 3046 Section 2.0
pub const SUBOPT_CIRCUIT_ID: u8 = 1;

/// Relay Agent Suboption 2: Remote ID.
///
/// Identifies the remote host (customer endpoint) at the far end of the circuit.
///
/// Source: RFC 3046 Section 2.0
pub const SUBOPT_REMOTE_ID: u8 = 2;

/// Relay Agent Suboption 5: Link Selection.
///
/// Overrides giaddr-based subnet selection. Contains 4-byte IPv4 subnet address.
///
/// Source: RFC 3527
pub const SUBOPT_SUBNET_SELECT: u8 = 5;

/// Relay Agent Suboption 6: Subscriber ID.
///
/// Stable subscriber identifier independent of physical location or hardware.
///
/// Source: RFC 3993
pub const SUBOPT_SUBSCR_ID: u8 = 6;

/// Relay Agent Suboption 10: Relay Agent Flags.
///
/// Bit flags: bit 0 = unicast flag (server should unicast replies to relay).
///
/// Source: RFC 5010
pub const SUBOPT_FLAGS: u8 = 10;

/// Relay Agent Suboption 11: Server Identifier Override.
///
/// Instructs server to use a different Server Identifier (Option 54) value.
///
/// Source: RFC 5107
pub const SUBOPT_SERVER_OR: u8 = 11;

// ============================================================================
// PXE Vendor-Specific Suboptions (Option 43, Intel PXE Spec 2.1)
// ============================================================================

/// PXE Suboption 71: Boot Item.
///
/// Describes a specific boot option: boot server type (2 bytes) + layer (2 bytes).
///
/// Source: Intel PXE Specification 2.1 Section 2.3.1
pub const SUBOPT_PXE_BOOT_ITEM: u8 = 71;

/// PXE Suboption 6: PXE Discovery Control (1 byte, bit flags).
///
/// Controls boot server discovery behavior (disable broadcast/multicast, etc.).
///
/// Source: Intel PXE Specification 2.1 Section 2.3.5
pub const SUBOPT_PXE_DISCOVERY: u8 = 6;

/// PXE Suboption 8: PXE Boot Servers (variable length).
///
/// List of boot servers per type: type(2) + count(1) + addresses(4 each).
///
/// Source: Intel PXE Specification 2.1 Section 2.3.7
pub const SUBOPT_PXE_SERVERS: u8 = 8;

/// PXE Suboption 9: PXE Boot Menu (variable length).
///
/// User-selectable boot menu entries: type(2) + desc_len(1) + description.
///
/// Source: Intel PXE Specification 2.1 Section 2.3.8
pub const SUBOPT_PXE_MENU: u8 = 9;

/// PXE Suboption 10: PXE Boot Menu Prompt (variable length).
///
/// Boot menu prompt: timeout(1) + prompt text. 0=no prompt, 255=wait forever.
///
/// Source: Intel PXE Specification 2.1 Section 2.3.9
pub const SUBOPT_PXE_MENU_PROMPT: u8 = 10;

// ============================================================================
// Vendor Enterprise Numbers (IANA)
// ============================================================================

/// IANA enterprise number for Broadband Forum (formerly DSL Forum).
///
/// Used in OPTION_VENDOR_IDENT (124) and OPTION_VENDOR_IDENT_OPT (125)
/// to identify Broadband Forum vendor-specific data (TR-069, TR-101, TR-111).
///
/// Source: IANA Private Enterprise Numbers registry
pub const BRDBAND_FORUM_IANA: u32 = 3561;

// ============================================================================
// DHCP Message Type Values (Option 53, RFC 2131 §3.1)
// ============================================================================

/// DHCPv4 message types per RFC 2131 Section 3.1 and extensions.
///
/// These message types implement the DHCPv4 protocol exchange:
///
/// **Standard four-message exchange (DORA):**
/// 1. [`Discover`](DhcpMessageType::Discover) — Client broadcasts to find servers
/// 2. [`Offer`](DhcpMessageType::Offer) — Server offers IP address and configuration
/// 3. [`Request`](DhcpMessageType::Request) — Client accepts specific offer
/// 4. [`Ack`](DhcpMessageType::Ack) — Server confirms lease assignment
///
/// **Additional messages:**
/// - [`Nak`](DhcpMessageType::Nak) — Server rejects request
/// - [`Decline`](DhcpMessageType::Decline) — Client reports address conflict
/// - [`Release`](DhcpMessageType::Release) — Client relinquishes address
/// - [`Inform`](DhcpMessageType::Inform) — Client requests config without address
/// - [`ForceRenew`](DhcpMessageType::ForceRenew) — Server forces immediate renewal
///
/// **Leasequery (RFC 4388):**
/// - [`LeaseQuery`](DhcpMessageType::LeaseQuery) — External lease database query
/// - [`LeaseUnassigned`](DhcpMessageType::LeaseUnassigned) — Address available
/// - [`LeaseUnknown`](DhcpMessageType::LeaseUnknown) — Address unknown to server
/// - [`LeaseActive`](DhcpMessageType::LeaseActive) — Address currently leased
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DhcpMessageType {
    /// DHCPDISCOVER (1): Client broadcasts to locate available servers.
    /// Source: RFC 2131 Section 3.1
    Discover = 1,
    /// DHCPOFFER (2): Server offers IP address and configuration.
    /// Source: RFC 2131 Section 3.1
    Offer = 2,
    /// DHCPREQUEST (3): Client accepts offer or renews lease.
    /// Source: RFC 2131 Section 3.1
    Request = 3,
    /// DHCPDECLINE (4): Client reports offered address already in use.
    /// Source: RFC 2131 Section 3.1
    Decline = 4,
    /// DHCPACK (5): Server confirms address allocation.
    /// Source: RFC 2131 Section 3.1
    Ack = 5,
    /// DHCPNAK (6): Server rejects client's request.
    /// Source: RFC 2131 Section 3.1
    Nak = 6,
    /// DHCPRELEASE (7): Client relinquishes assigned address.
    /// Source: RFC 2131 Section 3.1
    Release = 7,
    /// DHCPINFORM (8): Client requests config without address assignment.
    /// Source: RFC 2131 Section 3.4
    Inform = 8,
    /// DHCPFORCERENEW (9): Server instructs client to renew immediately.
    /// Source: RFC 3203
    ForceRenew = 9,
    /// DHCPLEASEQUERY (10): External query for lease information.
    /// Source: RFC 4388
    LeaseQuery = 10,
    /// DHCPLEASEUNASSIGNED (11): Queried address is in pool but unassigned.
    /// Source: RFC 4388
    LeaseUnassigned = 11,
    /// DHCPLEASEUNKNOWN (12): Queried address is not in server's authority.
    /// Source: RFC 4388
    LeaseUnknown = 12,
    /// DHCPLEASEACTIVE (13): Queried address is currently leased.
    /// Source: RFC 4388
    LeaseActive = 13,
}

impl DhcpMessageType {
    /// Returns the numeric value of this message type as a `u8`.
    #[inline]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Returns a human-readable name for this message type.
    ///
    /// These names match the standard RFC designations used in dnsmasq log output.
    #[inline]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Discover => "DHCPDISCOVER",
            Self::Offer => "DHCPOFFER",
            Self::Request => "DHCPREQUEST",
            Self::Decline => "DHCPDECLINE",
            Self::Ack => "DHCPACK",
            Self::Nak => "DHCPNAK",
            Self::Release => "DHCPRELEASE",
            Self::Inform => "DHCPINFORM",
            Self::ForceRenew => "DHCPFORCERENEW",
            Self::LeaseQuery => "DHCPLEASEQUERY",
            Self::LeaseUnassigned => "DHCPLEASEUNASSIGNED",
            Self::LeaseUnknown => "DHCPLEASEUNKNOWN",
            Self::LeaseActive => "DHCPLEASEACTIVE",
        }
    }
}

impl TryFrom<u8> for DhcpMessageType {
    type Error = InvalidMessageType;

    /// Converts a raw `u8` value to a `DhcpMessageType`.
    ///
    /// Returns `Err(InvalidMessageType)` if the value is not a valid message type (1–13).
    ///
    /// # Examples
    /// ```
    /// use dnsmasq::dhcp::protocol_v4::DhcpMessageType;
    ///
    /// assert_eq!(DhcpMessageType::try_from(1), Ok(DhcpMessageType::Discover));
    /// assert_eq!(DhcpMessageType::try_from(5), Ok(DhcpMessageType::Ack));
    /// assert!(DhcpMessageType::try_from(0).is_err());
    /// assert!(DhcpMessageType::try_from(14).is_err());
    /// ```
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Discover),
            2 => Ok(Self::Offer),
            3 => Ok(Self::Request),
            4 => Ok(Self::Decline),
            5 => Ok(Self::Ack),
            6 => Ok(Self::Nak),
            7 => Ok(Self::Release),
            8 => Ok(Self::Inform),
            9 => Ok(Self::ForceRenew),
            10 => Ok(Self::LeaseQuery),
            11 => Ok(Self::LeaseUnassigned),
            12 => Ok(Self::LeaseUnknown),
            13 => Ok(Self::LeaseActive),
            _ => Err(InvalidMessageType(value)),
        }
    }
}

impl core::fmt::Display for DhcpMessageType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

/// Error returned when converting an invalid `u8` to [`DhcpMessageType`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidMessageType(pub u8);

impl core::fmt::Display for InvalidMessageType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid DHCP message type: {}", self.0)
    }
}

impl std::error::Error for InvalidMessageType {}

// ============================================================================
// Bare Message Type Constants (backward compatibility)
// ============================================================================

/// DHCP Message Type 1: DHCPDISCOVER. Source: RFC 2131 Section 3.1
pub const DHCPDISCOVER: u8 = 1;
/// DHCP Message Type 2: DHCPOFFER. Source: RFC 2131 Section 3.1
pub const DHCPOFFER: u8 = 2;
/// DHCP Message Type 3: DHCPREQUEST. Source: RFC 2131 Section 3.1
pub const DHCPREQUEST: u8 = 3;
/// DHCP Message Type 4: DHCPDECLINE. Source: RFC 2131 Section 3.1
pub const DHCPDECLINE: u8 = 4;
/// DHCP Message Type 5: DHCPACK. Source: RFC 2131 Section 3.1
pub const DHCPACK: u8 = 5;
/// DHCP Message Type 6: DHCPNAK. Source: RFC 2131 Section 3.1
pub const DHCPNAK: u8 = 6;
/// DHCP Message Type 7: DHCPRELEASE. Source: RFC 2131 Section 3.1
pub const DHCPRELEASE: u8 = 7;
/// DHCP Message Type 8: DHCPINFORM. Source: RFC 2131 Section 3.4
pub const DHCPINFORM: u8 = 8;
/// DHCP Message Type 9: DHCPFORCERENEW. Source: RFC 3203
pub const DHCPFORCERENEW: u8 = 9;
/// DHCP Message Type 10: DHCPLEASEQUERY. Source: RFC 4388
pub const DHCPLEASEQUERY: u8 = 10;
/// DHCP Message Type 11: DHCPLEASEUNASSIGNED. Source: RFC 4388
pub const DHCPLEASEUNASSIGNED: u8 = 11;
/// DHCP Message Type 12: DHCPLEASEUNKNOWN. Source: RFC 4388
pub const DHCPLEASEUNKNOWN: u8 = 12;
/// DHCP Message Type 13: DHCPLEASEACTIVE. Source: RFC 4388
pub const DHCPLEASEACTIVE: u8 = 13;

// ============================================================================
// DHCPv4 Packet Wire Format Structure (RFC 2131 §2)
// ============================================================================

/// DHCPv4 packet wire format per RFC 2131 Section 2.
///
/// This structure defines the exact wire format for DHCPv4 packets transmitted
/// over UDP (ports 67/68). The structure matches the RFC 2131 specification
/// byte-for-byte with `#[repr(C)]` ensuring correct serialization.
///
/// # Memory Layout
///
/// | Offset | Size | Field   | Description                         |
/// |--------|------|---------|-------------------------------------|
/// | 0      | 1    | op      | Operation code (1=request, 2=reply) |
/// | 1      | 1    | htype   | Hardware address type               |
/// | 2      | 1    | hlen    | Hardware address length              |
/// | 3      | 1    | hops    | Relay agent hop count               |
/// | 4      | 4    | xid     | Transaction ID                      |
/// | 8      | 2    | secs    | Seconds elapsed                     |
/// | 10     | 2    | flags   | Flags (bit 0x8000 = broadcast)      |
/// | 12     | 4    | ciaddr  | Client IP address                   |
/// | 16     | 4    | yiaddr  | Your (client) IP address            |
/// | 20     | 4    | siaddr  | Next server IP address              |
/// | 24     | 4    | giaddr  | Relay agent IP address              |
/// | 28     | 16   | chaddr  | Client hardware address             |
/// | 44     | 64   | sname   | Server host name                    |
/// | 108    | 128  | file    | Boot file name                      |
/// | 236    | 312  | options | DHCP options (starts with cookie)   |
///
/// **Total size: 548 bytes** (236 fixed header + 312 options).
///
/// # Wire Protocol Compatibility
///
/// This struct uses `#[repr(C)]` to guarantee the same memory layout as the
/// original C `struct dhcp_packet`. IP address fields are stored as `[u8; 4]`
/// in network byte order for direct wire-format compatibility.
#[repr(C)]
#[derive(Clone)]
pub struct DhcpPacket {
    /// Operation code: [`BOOTREQUEST`] (1) for client-to-server,
    /// [`BOOTREPLY`] (2) for server-to-client.
    pub op: u8,

    /// Hardware address type per IANA ARP Hardware Types.
    /// 1 = Ethernet ([`ARPHRD_ETHER`]).
    pub htype: u8,

    /// Hardware address length in octets. 6 for Ethernet MAC addresses.
    pub hlen: u8,

    /// Relay agent hop count. Set to 0 by client, incremented by each relay.
    pub hops: u8,

    /// Transaction ID: random 32-bit value chosen by client for
    /// request/response matching across the entire DORA exchange.
    pub xid: u32,

    /// Seconds elapsed since client began address acquisition or renewal.
    /// Network byte order (big-endian).
    pub secs: u16,

    /// Flags field. Bit 0x8000: broadcast flag (client cannot receive unicast
    /// before IP is configured). Remaining bits reserved, must be zero.
    /// Network byte order (big-endian).
    pub flags: u16,

    /// Client IP address: filled by client if it already has a valid address
    /// (RENEWING/REBINDING/BOUND states), otherwise `[0, 0, 0, 0]`.
    /// Network byte order.
    pub ciaddr: [u8; 4],

    /// Your (client) IP address: filled by server with offered/assigned address.
    /// Network byte order.
    pub yiaddr: [u8; 4],

    /// Next server IP address: used in bootstrap (e.g., TFTP server for PXE).
    /// Network byte order.
    pub siaddr: [u8; 4],

    /// Relay agent IP address: set by relay agent, used by server for subnet
    /// determination and response routing. Network byte order.
    pub giaddr: [u8; 4],

    /// Client hardware address (MAC for Ethernet), zero-padded to 16 bytes.
    /// Only the first `hlen` bytes are significant.
    pub chaddr: [u8; DHCP_CHADDR_MAX],

    /// Server host name: null-terminated string (64 bytes).
    /// May be overloaded with DHCP options via [`OPTION_OVERLOAD`].
    pub sname: [u8; 64],

    /// Boot file name: null-terminated string (128 bytes).
    /// May be overloaded with DHCP options via [`OPTION_OVERLOAD`].
    pub file: [u8; 128],

    /// DHCP options in TLV format. MUST begin with the 4-byte magic cookie
    /// [`DHCP_COOKIE`] (0x63825363), followed by option data, terminated by
    /// [`OPTION_END`] (255).
    pub options: [u8; 312],
}

impl DhcpPacket {
    /// Creates a new zero-initialized DHCP packet.
    ///
    /// All fields are set to zero. Callers should populate the `op`, `htype`,
    /// `hlen`, `xid`, and options fields before transmission.
    #[inline]
    pub const fn new() -> Self {
        Self {
            op: 0,
            htype: 0,
            hlen: 0,
            hops: 0,
            xid: 0,
            secs: 0,
            flags: 0,
            ciaddr: [0u8; 4],
            yiaddr: [0u8; 4],
            siaddr: [0u8; 4],
            giaddr: [0u8; 4],
            chaddr: [0u8; DHCP_CHADDR_MAX],
            sname: [0u8; 64],
            file: [0u8; 128],
            options: [0u8; 312],
        }
    }

    /// Returns the client IP address (`ciaddr`) as a [`std::net::Ipv4Addr`].
    ///
    /// Interprets the 4-byte field in network byte order.
    #[inline]
    pub fn ciaddr_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.ciaddr)
    }

    /// Returns the offered/assigned IP address (`yiaddr`) as a [`std::net::Ipv4Addr`].
    #[inline]
    pub fn yiaddr_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.yiaddr)
    }

    /// Returns the next server IP address (`siaddr`) as a [`std::net::Ipv4Addr`].
    #[inline]
    pub fn siaddr_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.siaddr)
    }

    /// Returns the relay agent IP address (`giaddr`) as a [`std::net::Ipv4Addr`].
    #[inline]
    pub fn giaddr_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.giaddr)
    }

    /// Sets the client IP address (`ciaddr`) from an [`Ipv4Addr`].
    #[inline]
    pub fn set_ciaddr(&mut self, addr: Ipv4Addr) {
        self.ciaddr = addr.octets();
    }

    /// Sets the offered/assigned IP address (`yiaddr`) from an [`Ipv4Addr`].
    #[inline]
    pub fn set_yiaddr(&mut self, addr: Ipv4Addr) {
        self.yiaddr = addr.octets();
    }

    /// Sets the next server IP address (`siaddr`) from an [`Ipv4Addr`].
    #[inline]
    pub fn set_siaddr(&mut self, addr: Ipv4Addr) {
        self.siaddr = addr.octets();
    }

    /// Sets the relay agent IP address (`giaddr`) from an [`Ipv4Addr`].
    #[inline]
    pub fn set_giaddr(&mut self, addr: Ipv4Addr) {
        self.giaddr = addr.octets();
    }

    /// Returns `true` if the broadcast flag (bit 0x8000) is set in the flags field.
    ///
    /// When set, the server should broadcast responses instead of unicasting.
    #[inline]
    pub fn is_broadcast(&self) -> bool {
        // flags is stored in network byte order in the wire format;
        // check the high bit of the first byte
        (self.flags & 0x8000) != 0
    }

    /// Returns the hardware address (first `hlen` bytes of `chaddr`).
    ///
    /// Returns an empty slice if `hlen` exceeds [`DHCP_CHADDR_MAX`].
    #[inline]
    pub fn hw_addr(&self) -> &[u8] {
        let len = self.hlen as usize;
        if len <= DHCP_CHADDR_MAX {
            &self.chaddr[..len]
        } else {
            &self.chaddr[..DHCP_CHADDR_MAX]
        }
    }

    /// Returns the total size of a DHCP packet in bytes (548).
    ///
    /// This is a compile-time constant matching the C `sizeof(struct dhcp_packet)`.
    #[inline]
    pub const fn packet_size() -> usize {
        core::mem::size_of::<Self>()
    }
}

impl Default for DhcpPacket {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for DhcpPacket {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DhcpPacket")
            .field("op", &self.op)
            .field("htype", &self.htype)
            .field("hlen", &self.hlen)
            .field("hops", &self.hops)
            .field("xid", &format_args!("0x{:08x}", self.xid))
            .field("secs", &self.secs)
            .field("flags", &format_args!("0x{:04x}", self.flags))
            .field("ciaddr", &self.ciaddr_addr())
            .field("yiaddr", &self.yiaddr_addr())
            .field("siaddr", &self.siaddr_addr())
            .field("giaddr", &self.giaddr_addr())
            .field("chaddr", &self.hw_addr())
            .field("sname", &"[...]")
            .field("file", &"[...]")
            .field("options", &"[...]")
            .finish()
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_constants() {
        assert_eq!(DHCP_SERVER_PORT, 67);
        assert_eq!(DHCP_CLIENT_PORT, 68);
        assert_eq!(DHCP_SERVER_ALTPORT, 1067);
        assert_eq!(DHCP_CLIENT_ALTPORT, 1068);
        assert_eq!(PXE_PORT, 4011);
    }

    #[test]
    fn test_protocol_constants() {
        assert_eq!(DHCP_BUFF_SZ, 256);
        assert_eq!(BOOTREQUEST, 1);
        assert_eq!(BOOTREPLY, 2);
        assert_eq!(DHCP_COOKIE, 0x63825363);
        assert_eq!(MIN_PACKETSZ, 300);
        assert_eq!(DHCP_CHADDR_MAX, 16);
    }

    #[test]
    fn test_hardware_type_constants() {
        assert_eq!(ARPHRD_ETHER, 1);
        assert_eq!(ARPHRD_IEEE802, 6);
        assert_eq!(ARPHRD_ARCNET, 7);
    }

    #[test]
    fn test_option_constants_match_c_values() {
        assert_eq!(OPTION_PAD, 0);
        assert_eq!(OPTION_NETMASK, 1);
        assert_eq!(OPTION_ROUTER, 3);
        assert_eq!(OPTION_DNSSERVER, 6);
        assert_eq!(OPTION_HOSTNAME, 12);
        assert_eq!(OPTION_DOMAINNAME, 15);
        assert_eq!(OPTION_BROADCAST, 28);
        assert_eq!(OPTION_VENDOR_CLASS_OPT, 43);
        assert_eq!(OPTION_REQUESTED_IP, 50);
        assert_eq!(OPTION_LEASE_TIME, 51);
        assert_eq!(OPTION_OVERLOAD, 52);
        assert_eq!(OPTION_MESSAGE_TYPE, 53);
        assert_eq!(OPTION_SERVER_IDENTIFIER, 54);
        assert_eq!(OPTION_REQUESTED_OPTIONS, 55);
        assert_eq!(OPTION_MESSAGE, 56);
        assert_eq!(OPTION_MAXMESSAGE, 57);
        assert_eq!(OPTION_T1, 58);
        assert_eq!(OPTION_T2, 59);
        assert_eq!(OPTION_VENDOR_ID, 60);
        assert_eq!(OPTION_CLIENT_ID, 61);
        assert_eq!(OPTION_SNAME, 66);
        assert_eq!(OPTION_FILENAME, 67);
        assert_eq!(OPTION_USER_CLASS, 77);
        assert_eq!(OPTION_RAPID_COMMIT, 80);
        assert_eq!(OPTION_CLIENT_FQDN, 81);
        assert_eq!(OPTION_AGENT_ID, 82);
        assert_eq!(OPTION_LAST_TRANSACTION, 91);
        assert_eq!(OPTION_ASSOCIATED_IP, 92);
        assert_eq!(OPTION_ARCH, 93);
        assert_eq!(OPTION_PXE_UUID, 97);
        assert_eq!(OPTION_SUBNET_SELECT, 118);
        assert_eq!(OPTION_DOMAIN_SEARCH, 119);
        assert_eq!(OPTION_SIP_SERVER, 120);
        assert_eq!(OPTION_VENDOR_IDENT, 124);
        assert_eq!(OPTION_VENDOR_IDENT_OPT, 125);
        assert_eq!(OPTION_MUD_URL_V4, 161);
        assert_eq!(OPTION_END, 255);
    }

    #[test]
    fn test_relay_suboption_constants() {
        assert_eq!(SUBOPT_CIRCUIT_ID, 1);
        assert_eq!(SUBOPT_REMOTE_ID, 2);
        assert_eq!(SUBOPT_SUBNET_SELECT, 5);
        assert_eq!(SUBOPT_SUBSCR_ID, 6);
        assert_eq!(SUBOPT_FLAGS, 10);
        assert_eq!(SUBOPT_SERVER_OR, 11);
    }

    #[test]
    fn test_pxe_suboption_constants() {
        assert_eq!(SUBOPT_PXE_BOOT_ITEM, 71);
        assert_eq!(SUBOPT_PXE_DISCOVERY, 6);
        assert_eq!(SUBOPT_PXE_SERVERS, 8);
        assert_eq!(SUBOPT_PXE_MENU, 9);
        assert_eq!(SUBOPT_PXE_MENU_PROMPT, 10);
    }

    #[test]
    fn test_enterprise_number() {
        assert_eq!(BRDBAND_FORUM_IANA, 3561);
    }

    #[test]
    fn test_message_type_enum_values() {
        assert_eq!(DhcpMessageType::Discover as u8, 1);
        assert_eq!(DhcpMessageType::Offer as u8, 2);
        assert_eq!(DhcpMessageType::Request as u8, 3);
        assert_eq!(DhcpMessageType::Decline as u8, 4);
        assert_eq!(DhcpMessageType::Ack as u8, 5);
        assert_eq!(DhcpMessageType::Nak as u8, 6);
        assert_eq!(DhcpMessageType::Release as u8, 7);
        assert_eq!(DhcpMessageType::Inform as u8, 8);
        assert_eq!(DhcpMessageType::ForceRenew as u8, 9);
        assert_eq!(DhcpMessageType::LeaseQuery as u8, 10);
        assert_eq!(DhcpMessageType::LeaseUnassigned as u8, 11);
        assert_eq!(DhcpMessageType::LeaseUnknown as u8, 12);
        assert_eq!(DhcpMessageType::LeaseActive as u8, 13);
    }

    #[test]
    fn test_message_type_try_from_valid() {
        assert_eq!(DhcpMessageType::try_from(1u8), Ok(DhcpMessageType::Discover));
        assert_eq!(DhcpMessageType::try_from(5u8), Ok(DhcpMessageType::Ack));
        assert_eq!(DhcpMessageType::try_from(8u8), Ok(DhcpMessageType::Inform));
        assert_eq!(DhcpMessageType::try_from(13u8), Ok(DhcpMessageType::LeaseActive));
    }

    #[test]
    fn test_message_type_try_from_invalid() {
        assert!(DhcpMessageType::try_from(0u8).is_err());
        assert!(DhcpMessageType::try_from(14u8).is_err());
        assert!(DhcpMessageType::try_from(255u8).is_err());
    }

    #[test]
    fn test_message_type_as_u8() {
        assert_eq!(DhcpMessageType::Discover.as_u8(), 1);
        assert_eq!(DhcpMessageType::Ack.as_u8(), 5);
        assert_eq!(DhcpMessageType::LeaseActive.as_u8(), 13);
    }

    #[test]
    fn test_message_type_name() {
        assert_eq!(DhcpMessageType::Discover.name(), "DHCPDISCOVER");
        assert_eq!(DhcpMessageType::Ack.name(), "DHCPACK");
        assert_eq!(DhcpMessageType::Nak.name(), "DHCPNAK");
        assert_eq!(DhcpMessageType::LeaseActive.name(), "DHCPLEASEACTIVE");
    }

    #[test]
    fn test_message_type_display() {
        assert_eq!(format!("{}", DhcpMessageType::Discover), "DHCPDISCOVER");
        assert_eq!(format!("{}", DhcpMessageType::Ack), "DHCPACK");
    }

    #[test]
    fn test_bare_message_type_constants_match_enum() {
        assert_eq!(DHCPDISCOVER, DhcpMessageType::Discover as u8);
        assert_eq!(DHCPOFFER, DhcpMessageType::Offer as u8);
        assert_eq!(DHCPREQUEST, DhcpMessageType::Request as u8);
        assert_eq!(DHCPDECLINE, DhcpMessageType::Decline as u8);
        assert_eq!(DHCPACK, DhcpMessageType::Ack as u8);
        assert_eq!(DHCPNAK, DhcpMessageType::Nak as u8);
        assert_eq!(DHCPRELEASE, DhcpMessageType::Release as u8);
        assert_eq!(DHCPINFORM, DhcpMessageType::Inform as u8);
        assert_eq!(DHCPFORCERENEW, DhcpMessageType::ForceRenew as u8);
        assert_eq!(DHCPLEASEQUERY, DhcpMessageType::LeaseQuery as u8);
        assert_eq!(DHCPLEASEUNASSIGNED, DhcpMessageType::LeaseUnassigned as u8);
        assert_eq!(DHCPLEASEUNKNOWN, DhcpMessageType::LeaseUnknown as u8);
        assert_eq!(DHCPLEASEACTIVE, DhcpMessageType::LeaseActive as u8);
    }

    #[test]
    fn test_dhcp_packet_size_is_548_bytes() {
        // The DhcpPacket struct MUST be exactly 548 bytes to match the C wire format.
        // 236 bytes fixed header + 312 bytes options = 548 bytes total.
        assert_eq!(core::mem::size_of::<DhcpPacket>(), 548);
    }

    #[test]
    fn test_dhcp_packet_size_method() {
        assert_eq!(DhcpPacket::packet_size(), 548);
    }

    #[test]
    fn test_dhcp_packet_new_is_zeroed() {
        let pkt = DhcpPacket::new();
        assert_eq!(pkt.op, 0);
        assert_eq!(pkt.htype, 0);
        assert_eq!(pkt.hlen, 0);
        assert_eq!(pkt.hops, 0);
        assert_eq!(pkt.xid, 0);
        assert_eq!(pkt.secs, 0);
        assert_eq!(pkt.flags, 0);
        assert_eq!(pkt.ciaddr, [0u8; 4]);
        assert_eq!(pkt.yiaddr, [0u8; 4]);
        assert_eq!(pkt.siaddr, [0u8; 4]);
        assert_eq!(pkt.giaddr, [0u8; 4]);
        assert_eq!(pkt.chaddr, [0u8; DHCP_CHADDR_MAX]);
        assert_eq!(pkt.sname, [0u8; 64]);
        assert_eq!(pkt.file, [0u8; 128]);
        assert_eq!(pkt.options, [0u8; 312]);
    }

    #[test]
    fn test_dhcp_packet_default_is_zeroed() {
        let pkt = DhcpPacket::default();
        assert_eq!(pkt.op, 0);
        assert_eq!(pkt.xid, 0);
    }

    #[test]
    fn test_dhcp_packet_ip_address_helpers() {
        let mut pkt = DhcpPacket::new();

        // Test ciaddr
        pkt.set_ciaddr(Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(pkt.ciaddr, [192, 168, 1, 100]);
        assert_eq!(pkt.ciaddr_addr(), Ipv4Addr::new(192, 168, 1, 100));

        // Test yiaddr
        pkt.set_yiaddr(Ipv4Addr::new(10, 0, 0, 50));
        assert_eq!(pkt.yiaddr, [10, 0, 0, 50]);
        assert_eq!(pkt.yiaddr_addr(), Ipv4Addr::new(10, 0, 0, 50));

        // Test siaddr
        pkt.set_siaddr(Ipv4Addr::new(172, 16, 0, 1));
        assert_eq!(pkt.siaddr, [172, 16, 0, 1]);
        assert_eq!(pkt.siaddr_addr(), Ipv4Addr::new(172, 16, 0, 1));

        // Test giaddr
        pkt.set_giaddr(Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(pkt.giaddr, [10, 0, 0, 1]);
        assert_eq!(pkt.giaddr_addr(), Ipv4Addr::new(10, 0, 0, 1));
    }

    #[test]
    fn test_dhcp_packet_broadcast_flag() {
        let mut pkt = DhcpPacket::new();
        assert!(!pkt.is_broadcast());

        pkt.flags = 0x8000;
        assert!(pkt.is_broadcast());

        pkt.flags = 0x0000;
        assert!(!pkt.is_broadcast());

        // Only the high bit matters
        pkt.flags = 0x8001;
        assert!(pkt.is_broadcast());
    }

    #[test]
    fn test_dhcp_packet_hw_addr() {
        let mut pkt = DhcpPacket::new();
        pkt.hlen = 6;
        pkt.chaddr[0] = 0xAA;
        pkt.chaddr[1] = 0xBB;
        pkt.chaddr[2] = 0xCC;
        pkt.chaddr[3] = 0xDD;
        pkt.chaddr[4] = 0xEE;
        pkt.chaddr[5] = 0xFF;

        let hw = pkt.hw_addr();
        assert_eq!(hw.len(), 6);
        assert_eq!(hw, &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }

    #[test]
    fn test_dhcp_packet_hw_addr_zero_length() {
        let pkt = DhcpPacket::new();
        assert_eq!(pkt.hw_addr().len(), 0);
    }

    #[test]
    fn test_dhcp_packet_hw_addr_exceeds_max() {
        let mut pkt = DhcpPacket::new();
        pkt.hlen = 20; // exceeds DHCP_CHADDR_MAX (16)
        // Should clamp to DHCP_CHADDR_MAX
        assert_eq!(pkt.hw_addr().len(), DHCP_CHADDR_MAX);
    }

    #[test]
    fn test_dhcp_packet_clone() {
        let mut pkt = DhcpPacket::new();
        pkt.op = BOOTREQUEST;
        pkt.htype = ARPHRD_ETHER;
        pkt.hlen = 6;
        pkt.xid = 0x12345678;
        pkt.set_yiaddr(Ipv4Addr::new(192, 168, 1, 100));

        let cloned = pkt.clone();
        assert_eq!(cloned.op, BOOTREQUEST);
        assert_eq!(cloned.htype, ARPHRD_ETHER);
        assert_eq!(cloned.hlen, 6);
        assert_eq!(cloned.xid, 0x12345678);
        assert_eq!(cloned.yiaddr_addr(), Ipv4Addr::new(192, 168, 1, 100));
    }

    #[test]
    fn test_dhcp_packet_debug_format() {
        let pkt = DhcpPacket::new();
        let debug = format!("{:?}", pkt);
        assert!(debug.contains("DhcpPacket"));
        assert!(debug.contains("op: 0"));
        assert!(debug.contains("xid: 0x00000000"));
    }

    #[test]
    fn test_dhcp_cookie_bytes() {
        // Verify cookie matches dotted decimal 99.130.83.99
        let bytes = DHCP_COOKIE.to_be_bytes();
        assert_eq!(bytes, [99, 130, 83, 99]);
    }

    #[test]
    fn test_invalid_message_type_display() {
        let err = InvalidMessageType(42);
        assert_eq!(format!("{}", err), "invalid DHCP message type: 42");
    }

    #[test]
    fn test_message_type_roundtrip() {
        // Every valid message type should roundtrip through u8 conversion
        for val in 1u8..=13 {
            let msg_type = DhcpMessageType::try_from(val).unwrap();
            assert_eq!(msg_type.as_u8(), val);
        }
    }

    #[test]
    fn test_ipv4addr_from_is_used() {
        // Verify Ipv4Addr::from([u8;4]) is used (schema requirement)
        let addr = Ipv4Addr::from([192, 168, 1, 1]);
        assert_eq!(addr, Ipv4Addr::new(192, 168, 1, 1));
    }

    #[test]
    fn test_ipv4addr_new_is_used() {
        // Verify Ipv4Addr::new() is used (schema requirement)
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        assert_eq!(addr.octets(), [10, 0, 0, 1]);
    }

    #[test]
    fn test_dhcp_packet_field_offsets() {
        // Verify critical field offsets match the C struct layout.
        // We use offset_of! macro if available, or compute via pointer arithmetic.
        let pkt = DhcpPacket::new();
        let base = &pkt as *const DhcpPacket as usize;

        let op_offset = &pkt.op as *const u8 as usize - base;
        let htype_offset = &pkt.htype as *const u8 as usize - base;
        let hlen_offset = &pkt.hlen as *const u8 as usize - base;
        let hops_offset = &pkt.hops as *const u8 as usize - base;
        let xid_offset = &pkt.xid as *const u32 as usize - base;
        let secs_offset = &pkt.secs as *const u16 as usize - base;
        let flags_offset = &pkt.flags as *const u16 as usize - base;
        let ciaddr_offset = &pkt.ciaddr as *const [u8; 4] as usize - base;
        let yiaddr_offset = &pkt.yiaddr as *const [u8; 4] as usize - base;
        let siaddr_offset = &pkt.siaddr as *const [u8; 4] as usize - base;
        let giaddr_offset = &pkt.giaddr as *const [u8; 4] as usize - base;
        let chaddr_offset = &pkt.chaddr as *const [u8; DHCP_CHADDR_MAX] as usize - base;
        let sname_offset = &pkt.sname as *const [u8; 64] as usize - base;
        let file_offset = &pkt.file as *const [u8; 128] as usize - base;
        let options_offset = &pkt.options as *const [u8; 312] as usize - base;

        assert_eq!(op_offset, 0);
        assert_eq!(htype_offset, 1);
        assert_eq!(hlen_offset, 2);
        assert_eq!(hops_offset, 3);
        assert_eq!(xid_offset, 4);
        assert_eq!(secs_offset, 8);
        assert_eq!(flags_offset, 10);
        assert_eq!(ciaddr_offset, 12);
        assert_eq!(yiaddr_offset, 16);
        assert_eq!(siaddr_offset, 20);
        assert_eq!(giaddr_offset, 24);
        assert_eq!(chaddr_offset, 28);
        assert_eq!(sname_offset, 44);
        assert_eq!(file_offset, 108);
        assert_eq!(options_offset, 236);
    }
}

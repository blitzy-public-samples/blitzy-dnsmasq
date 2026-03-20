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

//! # DHCPv4 Implementation Module
//!
//! Complete DHCPv4 server implementation migrated from 3 C source files
//! totaling 8,489 lines:
//! - `src/dhcp.c` (2,344 lines) → [`server`] module
//! - `src/rfc2131.c` (5,209 lines) → [`protocol`] module
//! - `src/dhcp-protocol.h` (936 lines) → protocol constants in this file
//! - `src/dhcp-common.c` (shared) → [`options`] module
//!
//! ## Architecture
//! - **server.rs**: Socket creation, packet reception/dispatch, address allocation,
//!   ICMP ping-before-allocate, interface/context management
//! - **protocol.rs**: RFC 2131 state machine (DISCOVER→OFFER→REQUEST→ACK),
//!   packet construction, option encoding, relay agent, PXE boot, leasequery
//! - **options.rs**: DHCPv4 option encode/decode (TLV format per RFC 2132),
//!   option finding, reading, writing in packet buffers
//!
//! ## Protocol Constants
//! This module defines all DHCPv4 protocol constants from `dhcp-protocol.h`:
//! - Port numbers (67, 68, 4011)
//! - Operation codes (BOOTREQUEST, BOOTREPLY)
//! - All DHCP option codes (0-255)
//! - Message types (DISCOVER through LEASEACTIVE)
//! - Relay agent suboptions
//! - PXE suboptions
//! - Packet structure constants
//!
//! ## Memory Safety
//! The C implementation used raw pointer arithmetic for packet parsing
//! and manual buffer management for option encoding. The Rust implementation
//! replaces all of this with:
//! - Slice-based packet parsing with bounds checking
//! - `Vec<u8>` for automatic buffer management
//! - `Result<T,E>` for error propagation (replacing C's goto cleanup)
//! - `repr(C, packed)` struct for wire-format packet structure

// ============================================================================
// Sub-module declarations
// ============================================================================

/// DHCPv4 server core: socket creation, packet reception, address allocation.
/// Migrated from `src/dhcp.c` (2,344 lines).
pub mod server;

/// DHCPv4 protocol state machine: message processing, option encoding, relay agent.
/// Migrated from `src/rfc2131.c` (5,209 lines).
pub mod protocol;

/// DHCPv4 option encode/decode: find, read, write DHCP options in packets.
/// Migrated from option handling in `src/rfc2131.c` and `src/dhcp-common.c`.
pub mod options;

// ============================================================================
// DHCPv4 Port Definitions (dhcp-protocol.h lines 111-135)
// ============================================================================

/// Standard DHCPv4 server listening port (requires root/CAP_NET_BIND_SERVICE).
///
/// Server binds to this port to receive DHCPDISCOVER, DHCPREQUEST, DHCPRELEASE,
/// DHCPDECLINE, and DHCPINFORM messages from clients on port 68.
///
/// RFC 2131 Section 4.1.
pub const DHCP_SERVER_PORT: u16 = 67;

/// Standard DHCPv4 client listening port.
///
/// Clients bind to this port to receive DHCPOFFER and DHCPACK messages from
/// servers. Server sends responses to this port even for clients without an
/// IP address yet.
///
/// RFC 2131 Section 4.1.
pub const DHCP_CLIENT_PORT: u16 = 68;

/// Alternate server port for non-privileged/testing deployments.
///
/// Non-standard port avoiding privileged binding requirement. Configured via
/// `--dhcp-alternate-port` option. Used in development and specialized scenarios.
///
/// dnsmasq extension.
pub const DHCP_SERVER_ALTPORT: u16 = 1067;

/// Alternate client port corresponding to alternate server port.
///
/// Client-side alternate port for use with [`DHCP_SERVER_ALTPORT`] deployments.
///
/// dnsmasq extension.
pub const DHCP_CLIENT_ALTPORT: u16 = 1068;

/// PXE proxy DHCP port for boot parameter delivery without IP assignment.
///
/// PXE proxy mode uses this port to provide boot parameters (boot filename,
/// TFTP server) without providing IP address assignment. Allows coexistence
/// with existing DHCP infrastructure for network boot scenarios.
///
/// Intel PXE Specification 2.1 Section 2.2.5.
pub const PXE_PORT: u16 = 4011;

// ============================================================================
// Buffer and Protocol Constants (dhcp-protocol.h lines 151-183)
// ============================================================================

/// Maximum DHCP option data buffer size (255 bytes + null terminator).
///
/// DHCPv4 options have maximum length of 255 bytes per RFC 2132. This buffer
/// size accommodates the maximum option data length (255) plus a terminating
/// null byte (1) for string safety when options contain text data.
///
/// RFC 2132 Section 2 (option format).
pub const DHCP_BUFF_SZ: usize = 256;

/// BOOTP request operation code (client-to-server).
///
/// Value for the `op` field in the DHCP packet indicating a client-to-server
/// message (BOOTREQUEST). Used in DHCPDISCOVER, DHCPREQUEST, DHCPDECLINE,
/// DHCPRELEASE, and DHCPINFORM messages.
///
/// RFC 2131 Section 2 (inherits from RFC 951 BOOTP).
pub const BOOTREQUEST: u8 = 1;

/// BOOTP reply operation code (server-to-client).
///
/// Value for the `op` field in the DHCP packet indicating a server-to-client
/// message (BOOTREPLY). Used in DHCPOFFER and DHCPACK messages.
///
/// RFC 2131 Section 2 (inherits from RFC 951 BOOTP).
pub const BOOTREPLY: u8 = 2;

/// DHCP magic cookie at start of options field (99.130.83.99 = 0x63825363).
///
/// Four-byte constant placed at the start of the options field to distinguish
/// DHCP packets from legacy BOOTP packets.
///
/// RFC 2131 Section 3.
pub const DHCP_COOKIE: u32 = 0x63825363;

/// Minimum packet size for Linux kernel DHCP client compatibility.
///
/// The Linux kernel's built-in DHCP client silently discards packets smaller
/// than 300 bytes regardless of actual packet validity. Dnsmasq pads outgoing
/// DHCP responses to this minimum size to ensure Linux kernel client compatibility.
///
/// Linux kernel `net/ipv4/ipconfig.c` behavior, dnsmasq compatibility fix.
pub const MIN_PACKETSZ: usize = 300;

// ============================================================================
// Packet Structure Size Constants (dhcp-protocol.h lines 700-934)
// ============================================================================

/// Maximum hardware address length in DHCP packet (16 bytes).
///
/// RFC 2131 specifies the client hardware address field (`chaddr`) as 16 octets.
/// While Ethernet MAC addresses are 6 octets, the larger field accommodates
/// other hardware types with longer addresses. Unused bytes are zero-padded.
///
/// RFC 2131 Section 2, Figure 1.
pub const DHCP_CHADDR_MAX: usize = 16;

/// Fixed DHCP header size (bytes before options field).
///
/// The DHCP packet header consists of the following fixed-size fields:
/// `op`(1) + `htype`(1) + `hlen`(1) + `hops`(1) + `xid`(4) + `secs`(2) +
/// `flags`(2) + `ciaddr`(4) + `yiaddr`(4) + `siaddr`(4) + `giaddr`(4) +
/// `chaddr`(16) + `sname`(64) + `file`(128) = 236 bytes.
///
/// RFC 2131 Section 2.
pub const DHCP_HEADER_SIZE: usize = 236;

/// DHCP options field size in standard packet (312 bytes).
///
/// The options field begins with a 4-byte magic cookie (0x63825363) followed
/// by TLV-encoded options. This size provides room for typical option sets.
///
/// RFC 2131 Section 2.
pub const DHCP_OPTIONS_SIZE: usize = 312;

/// Total DHCP packet size (header + options = 236 + 312 = 548 bytes).
///
/// This represents the standard DHCP packet size. The options field may be
/// extended using the `sname` and `file` fields via OPTION_OVERLOAD.
///
/// RFC 2131 Section 2.
pub const DHCP_PACKET_SIZE: usize = 548;

// ============================================================================
// DHCPv4 Option Codes (dhcp-protocol.h lines 212-442)
// RFC 2132 and extensions
// ============================================================================

/// Option 0: Pad option for alignment (no data).
///
/// Single byte, no length or value. Used to cause subsequent options to align
/// on word boundaries.
///
/// RFC 2132 Section 3.1.
pub const OPTION_PAD: u8 = 0;

/// Option 1: Subnet Mask (4 bytes).
///
/// Specifies the client's subnet mask per RFC 950.
///
/// RFC 2132 Section 3.3.
pub const OPTION_NETMASK: u8 = 1;

/// Option 3: Router (4+ bytes, multiple of 4).
///
/// List of router IP addresses on the client's subnet, in order of preference.
/// Client typically uses the first router as the default gateway.
///
/// RFC 2132 Section 3.5.
pub const OPTION_ROUTER: u8 = 3;

/// Option 6: Domain Name Server (4+ bytes, multiple of 4).
///
/// List of DNS recursive resolver IP addresses available to the client, in
/// order of preference.
///
/// RFC 2132 Section 3.8.
pub const OPTION_DNSSERVER: u8 = 6;

/// Option 12: Host Name (variable length string).
///
/// Specifies the client's hostname per RFC 1123, without domain suffix.
///
/// RFC 2132 Section 3.14.
pub const OPTION_HOSTNAME: u8 = 12;

/// Option 15: Domain Name (variable length string).
///
/// Specifies the domain name for DNS resolution and hostname qualification.
///
/// RFC 2132 Section 3.17.
pub const OPTION_DOMAINNAME: u8 = 15;

/// Option 28: Broadcast Address (4 bytes).
///
/// Specifies the broadcast address for the client's subnet.
///
/// RFC 2132 Section 5.3.
pub const OPTION_BROADCAST: u8 = 28;

/// Option 43: Vendor-Specific Information (variable length).
///
/// Opaque vendor-specific data. Format and content defined by vendor
/// (identified by OPTION_VENDOR_ID). PXE uses this for boot menu and
/// server discovery.
///
/// RFC 2132 Section 8.4.
pub const OPTION_VENDOR_CLASS_OPT: u8 = 43;

/// Option 50: Requested IP Address (4 bytes).
///
/// Used by client in DHCPREQUEST to request a specific IP address, or in
/// DHCPDISCOVER to suggest a previously allocated address.
///
/// RFC 2132 Section 9.1.
pub const OPTION_REQUESTED_IP: u8 = 50;

/// Option 51: IP Address Lease Time (4 bytes, seconds).
///
/// Lease duration in seconds as 32-bit unsigned integer. Value 0xFFFFFFFF
/// means infinite lease.
///
/// RFC 2132 Section 9.2.
pub const OPTION_LEASE_TIME: u8 = 51;

/// Option 52: Option Overload (1 byte).
///
/// Indicates that `file` and/or `sname` fields contain DHCP options instead
/// of filename/server name. Values: 1=`file` overloaded, 2=`sname` overloaded,
/// 3=both overloaded.
///
/// RFC 2132 Section 9.3.
pub const OPTION_OVERLOAD: u8 = 52;

/// Option 53: DHCP Message Type (1 byte) — REQUIRED.
///
/// Identifies the DHCP message type (DHCPDISCOVER=1, DHCPOFFER=2, etc.).
/// This option MUST be present in every DHCP message per RFC 2131.
///
/// RFC 2132 Section 9.6.
pub const OPTION_MESSAGE_TYPE: u8 = 53;

/// Option 54: Server Identifier (4 bytes).
///
/// IP address of the DHCP server sending this message. MUST be included by
/// server in DHCPOFFER and DHCPACK.
///
/// RFC 2132 Section 9.7.
pub const OPTION_SERVER_IDENTIFIER: u8 = 54;

/// Option 55: Parameter Request List (variable length, list of option codes).
///
/// Client includes this in DHCPDISCOVER and DHCPREQUEST to indicate which
/// options it wants the server to include in the response.
///
/// RFC 2132 Section 9.8.
pub const OPTION_REQUESTED_OPTIONS: u8 = 55;

/// Option 56: Message (variable length string).
///
/// Error message string included by server in DHCPNAK to explain rejection,
/// or informational message.
///
/// RFC 2132 Section 9.9.
pub const OPTION_MESSAGE: u8 = 56;

/// Option 57: Maximum DHCP Message Size (2 bytes).
///
/// Maximum DHCP message size the client is willing to accept (minimum 576 bytes).
///
/// RFC 2132 Section 9.10.
pub const OPTION_MAXMESSAGE: u8 = 57;

/// Option 58: Renewal Time Value (T1) (4 bytes, seconds).
///
/// Time interval from address assignment until client enters RENEWING state.
/// Typically 50% of lease time.
///
/// RFC 2132 Section 9.11.
pub const OPTION_T1: u8 = 58;

/// Option 59: Rebinding Time Value (T2) (4 bytes, seconds).
///
/// Time interval from address assignment until client enters REBINDING state.
/// Typically 87.5% of lease time.
///
/// RFC 2132 Section 9.12.
pub const OPTION_T2: u8 = 59;

/// Option 60: Vendor Class Identifier (variable length string).
///
/// Identifies vendor and client type. PXE clients include "PXEClient" string.
///
/// RFC 2132 Section 9.13.
pub const OPTION_VENDOR_ID: u8 = 60;

/// Option 61: Client Identifier (variable length).
///
/// Unique client identifier used instead of hardware address for lease binding.
/// Format: 1-byte type code + identifier data.
///
/// RFC 2132 Section 9.14.
pub const OPTION_CLIENT_ID: u8 = 61;

/// Option 66: TFTP Server Name (variable length string).
///
/// Hostname or IP address (as string) of TFTP server for network boot.
/// Alternative to `siaddr` field in DHCP packet.
///
/// RFC 2132 Section 9.4.
pub const OPTION_SNAME: u8 = 66;

/// Option 67: Boot File Name (variable length string).
///
/// Boot filename for network boot clients (PXE, BOOTP). Path relative to
/// TFTP server root.
///
/// RFC 2132 Section 9.5.
pub const OPTION_FILENAME: u8 = 67;

/// Option 77: User Class (variable length).
///
/// User-defined classification string for grouping clients with similar
/// configuration requirements.
///
/// RFC 3004.
pub const OPTION_USER_CLASS: u8 = 77;

/// Option 80: Rapid Commit (0 bytes, flag option).
///
/// Enables two-message exchange (DHCPDISCOVER + DHCPACK) instead of
/// four-message exchange.
///
/// RFC 4039.
pub const OPTION_RAPID_COMMIT: u8 = 80;

/// Option 81: Client FQDN (variable length).
///
/// Fully Qualified Domain Name option for dynamic DNS updates.
///
/// RFC 4702.
pub const OPTION_CLIENT_FQDN: u8 = 81;

/// Option 82: Relay Agent Information (variable length, suboptions).
///
/// Added by DHCP relay agents to include circuit identification, remote ID,
/// and other relay-specific information. Contains suboptions (SUBOPT_*).
///
/// RFC 3046.
pub const OPTION_AGENT_ID: u8 = 82;

/// Option 91: Client Last Transaction Time (4 bytes, seconds).
///
/// Used in DHCPLEASEQUERY responses to indicate seconds since client's last
/// transaction with the server.
///
/// RFC 4388 Section 6.1.
pub const OPTION_LAST_TRANSACTION: u8 = 91;

/// Option 92: Associated IP (4+ bytes, multiple of 4).
///
/// Used in DHCPLEASEQUERY to query leases associated with specific IP addresses.
///
/// RFC 4388 Section 6.2.
pub const OPTION_ASSOCIATED_IP: u8 = 92;

/// Option 93: Client System Architecture (2 bytes).
///
/// Identifies client CPU architecture for PXE network boot. Values: 0=x86 BIOS,
/// 6=x86 UEFI, 7=x64 UEFI, 9=EFI BC, 10=ARM32 UEFI, 11=ARM64 UEFI, etc.
///
/// RFC 4578 Section 2.1.
pub const OPTION_ARCH: u8 = 93;

/// Option 97: UUID/GUID-based Client Identifier (17 bytes).
///
/// PXE client machine identifier. First byte is type (0), followed by 16-byte
/// UUID/GUID.
///
/// RFC 4578 Section 2.5.
pub const OPTION_PXE_UUID: u8 = 97;

/// Option 118: Subnet Selection (4 bytes).
///
/// Allows client to specify which subnet it wants an address from when behind
/// a relay agent.
///
/// RFC 3011.
pub const OPTION_SUBNET_SELECT: u8 = 118;

/// Option 119: Domain Search (variable length, DNS search list).
///
/// List of domain suffixes for DNS hostname resolution search. Encoded as
/// DNS wire format compressed domain names.
///
/// RFC 3397.
pub const OPTION_DOMAIN_SEARCH: u8 = 119;

/// Option 120: SIP Servers (variable length).
///
/// Session Initiation Protocol (SIP) server addresses for VoIP configuration.
///
/// RFC 3361.
pub const OPTION_SIP_SERVER: u8 = 120;

/// Option 124: Vendor-Identifying Vendor Class (variable length).
///
/// Extended vendor identification with enterprise number and vendor-specific data.
///
/// RFC 3925 Section 3.
pub const OPTION_VENDOR_IDENT: u8 = 124;

/// Option 125: Vendor-Identifying Vendor-Specific Information (variable length).
///
/// Vendor-specific data tagged with IANA enterprise number.
///
/// RFC 3925 Section 4.
pub const OPTION_VENDOR_IDENT_OPT: u8 = 125;

/// Option 161: Manufacturer Usage Description (MUD) URL (variable length).
///
/// URL pointing to manufacturer's device security profile for IoT device policy.
///
/// RFC 8520.
pub const OPTION_MUD_URL_V4: u8 = 161;

/// Option 255: End option (no length or data).
///
/// Marks the end of the option list in a DHCP packet. All options must appear
/// before this marker.
///
/// RFC 2132 Section 3.2.
pub const OPTION_END: u8 = 255;

// ============================================================================
// Relay Agent Suboptions (Option 82) (dhcp-protocol.h lines 465-499)
// RFC 3046 and extensions
// ============================================================================

/// Relay Agent Suboption 1: Circuit ID.
///
/// Identifies the circuit (interface, VLAN, physical port) on which the DHCP
/// request arrived at the relay agent.
///
/// RFC 3046 Section 2.0.
pub const SUBOPT_CIRCUIT_ID: u8 = 1;

/// Relay Agent Suboption 2: Remote ID.
///
/// Identifies the remote host (customer endpoint) at the far end of the circuit.
/// Typically contains subscriber identifier, MAC address, or device serial number.
///
/// RFC 3046 Section 2.0.
pub const SUBOPT_REMOTE_ID: u8 = 2;

/// Relay Agent Suboption 5: Link Selection.
///
/// Specifies which IP subnet the relay agent wants the server to allocate an
/// address from. Overrides giaddr-based subnet selection.
///
/// RFC 3527.
pub const SUBOPT_SUBNET_SELECT: u8 = 5;

/// Relay Agent Suboption 6: Subscriber ID.
///
/// Stable subscriber identifier independent of physical location or hardware.
///
/// RFC 3993.
pub const SUBOPT_SUBSCR_ID: u8 = 6;

/// Relay Agent Suboption 10: Relay Agent Flags.
///
/// Bit flags indicating relay agent capabilities and request handling.
/// Currently defined: bit 0 = unicast flag.
///
/// RFC 5010.
pub const SUBOPT_FLAGS: u8 = 10;

/// Relay Agent Suboption 11: Server Identifier Override.
///
/// Instructs the server to use a different Server Identifier (Option 54) value
/// in the response. Used in load balancing and failover.
///
/// RFC 5107.
pub const SUBOPT_SERVER_OR: u8 = 11;

// ============================================================================
// PXE Vendor-Specific Suboptions (dhcp-protocol.h lines 523-550)
// Intel PXE Specification 2.1
// ============================================================================

/// PXE Suboption 71: Boot Item.
///
/// Describes a specific boot option in PXE boot menu. Contains boot server type
/// (2 bytes) and layer number (2 bytes).
///
/// Intel PXE Specification 2.1 Section 2.3.1.
pub const SUBOPT_PXE_BOOT_ITEM: u8 = 71;

/// PXE Suboption 6: PXE Discovery Control (1 byte, bit flags).
///
/// Controls PXE client boot server discovery behavior. Bit 3=disable broadcast
/// discovery, Bit 2=disable multicast discovery.
///
/// Intel PXE Specification 2.1 Section 2.3.5.
pub const SUBOPT_PXE_DISCOVERY: u8 = 6;

/// PXE Suboption 8: PXE Boot Servers (variable length).
///
/// List of boot servers available for each boot server type.
///
/// Intel PXE Specification 2.1 Section 2.3.7.
pub const SUBOPT_PXE_SERVERS: u8 = 8;

/// PXE Suboption 9: PXE Boot Menu (variable length).
///
/// Defines user-selectable boot menu entries displayed at boot time.
///
/// Intel PXE Specification 2.1 Section 2.3.8.
pub const SUBOPT_PXE_MENU: u8 = 9;

/// PXE Suboption 10: PXE Boot Menu Prompt (variable length).
///
/// Configures the boot menu prompt shown to user. Format: timeout (1 byte,
/// seconds), prompt text.
///
/// Intel PXE Specification 2.1 Section 2.3.9.
pub const SUBOPT_PXE_MENU_PROMPT: u8 = 10;

// ============================================================================
// DHCPv4 Message Type Values (dhcp-protocol.h lines 583-673)
// Values for DHCP Message Type option (Option 53)
// ============================================================================

/// DHCP Message Type 1: DHCPDISCOVER.
///
/// Client broadcasts to locate available DHCP servers. First message in the
/// four-way address allocation exchange.
///
/// RFC 2131 Section 3.1, Table 4.
pub const DHCPDISCOVER: u8 = 1;

/// DHCP Message Type 2: DHCPOFFER.
///
/// Server unicasts or broadcasts offer of IP address and configuration to client.
/// Response to DHCPDISCOVER.
///
/// RFC 2131 Section 3.1, Table 4.
pub const DHCPOFFER: u8 = 2;

/// DHCP Message Type 3: DHCPREQUEST.
///
/// Client broadcasts acceptance of server's offer, requests renewal of existing
/// lease, or confirms configuration after reboot.
///
/// RFC 2131 Section 3.1, Table 4.
pub const DHCPREQUEST: u8 = 3;

/// DHCP Message Type 4: DHCPDECLINE.
///
/// Client notifies server that offered address is already in use on the network
/// (detected via ARP probe).
///
/// RFC 2131 Section 3.1, Table 4.
pub const DHCPDECLINE: u8 = 4;

/// DHCP Message Type 5: DHCPACK.
///
/// Server acknowledges and confirms client's address allocation or renewal
/// request. Final message in a successful four-way exchange.
///
/// RFC 2131 Section 3.1, Table 4.
pub const DHCPACK: u8 = 5;

/// DHCP Message Type 6: DHCPNAK.
///
/// Server rejects client's DHCPREQUEST. Sent when requested address is not
/// available or not appropriate for the network.
///
/// RFC 2131 Section 3.1, Table 4.
pub const DHCPNAK: u8 = 6;

/// DHCP Message Type 7: DHCPRELEASE.
///
/// Client notifies server it is releasing and relinquishing the assigned IP
/// address. Server marks address available for reallocation.
///
/// RFC 2131 Section 3.1, Table 4.
pub const DHCPRELEASE: u8 = 7;

/// DHCP Message Type 8: DHCPINFORM.
///
/// Client requests local configuration parameters but already has an externally
/// configured IP address. Server responds with DHCPACK containing configuration
/// but no address assignment.
///
/// RFC 2131 Section 3.4.
pub const DHCPINFORM: u8 = 8;

/// DHCP Message Type 9: DHCPFORCERENEW.
///
/// Server instructs client to renew lease immediately. Requires authentication
/// per RFC 3203.
///
/// RFC 3203 Section 4.
pub const DHCPFORCERENEW: u8 = 9;

/// DHCP Message Type 10: DHCPLEASEQUERY.
///
/// External query to DHCP server requesting lease information for a specific
/// IP address, MAC address, or client identifier.
///
/// RFC 4388 Section 6.1.
pub const DHCPLEASEQUERY: u8 = 10;

/// DHCP Message Type 11: DHCPLEASEUNASSIGNED.
///
/// Server response to DHCPLEASEQUERY indicating the queried IP address exists
/// in the server's address pool but is not currently assigned.
///
/// RFC 4388 Section 6.2.1.
pub const DHCPLEASEUNASSIGNED: u8 = 11;

/// DHCP Message Type 12: DHCPLEASEUNKNOWN.
///
/// Server response to DHCPLEASEQUERY indicating the queried IP address is not
/// within the server's authority or address pools.
///
/// RFC 4388 Section 6.2.2.
pub const DHCPLEASEUNKNOWN: u8 = 12;

/// DHCP Message Type 13: DHCPLEASEACTIVE.
///
/// Server response to DHCPLEASEQUERY indicating the queried address is currently
/// leased to a client. Response includes lease information.
///
/// RFC 4388 Section 6.2.3.
pub const DHCPLEASEACTIVE: u8 = 13;

// ============================================================================
// Vendor Enterprise Numbers (dhcp-protocol.h line 690)
// ============================================================================

/// IANA enterprise number for Broadband Forum (formerly DSL Forum).
///
/// Used in OPTION_VENDOR_IDENT (124) and OPTION_VENDOR_IDENT_OPT (125) to
/// identify Broadband Forum vendor-specific data (TR-069, TR-101, TR-111).
///
/// IANA Private Enterprise Numbers registry.
pub const BRDBAND_FORUM_IANA: u32 = 3561;

// ============================================================================
// Public re-exports for convenient access
// ============================================================================

// Re-export key types from the protocol sub-module.
pub use protocol::{DhcpBoot, DhcpPacket, DhcpReplyContext, DhcpV4State};

// Re-export key functions from the server sub-module.
pub use server::{address_allocate, dhcp_init, dhcp_packet};

// Re-export key functions from the options sub-module.
pub use options::{option_addr, option_find, option_put, option_put_string, option_uint};

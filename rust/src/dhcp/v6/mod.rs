// Copyright (C) 2024 Simon Kelley
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

//! # DHCPv6 Implementation
//!
//! Complete DHCPv6 server subsystem implementing RFC 3315 (Dynamic Host
//! Configuration Protocol for IPv6). Migrated from 4 C source files
//! totaling 7,090 lines:
//!
//! | Module | C Source | Lines | Description |
//! |--------|---------|-------|-------------|
//! | `server` | `dhcp6.c` | 1,487 | Server core, packet processing |
//! | `protocol` | `rfc3315.c` + `dhcp6-protocol.h` | 4,901 | Protocol state machine |
//! | `outpacket` | `outpacket.c` | 702 | Packet buffer management |
//! | (this module) | `dhcp6-protocol.h` | 685 | Protocol constants |
//!
//! ## Architecture
//! - **State Machine**: SOLICIT→ADVERTISE→REQUEST→REPLY (4-message), or
//!   SOLICIT→REPLY (rapid commit 2-message)
//! - **Packet Construction**: `OutPacket` struct with Vec<u8> buffer and
//!   position tracking for nested DHCPv6 TLV options
//! - **Address Allocation**: From configured pools with IA_NA/IA_TA/IA_PD support
//! - **Relay Support**: Multi-hop relay message decapsulation (RELAY-FORW/RELAY-REPL)
//!
//! ## Feature Gate
//! This entire module is gated by `#[cfg(feature = "dhcp6")]`, mapping to
//! C's `HAVE_DHCP6` preprocessor macro. The feature implies `dhcp` (DHCPv4
//! shared infrastructure).
//!
//! ## Protocol Constants
//! This module re-exports all DHCPv6 protocol constants (port numbers,
//! message types, option codes, status codes) originally defined in
//! `src/dhcp6-protocol.h` (685 lines).

// ---------------------------------------------------------------------------
// Sub-module declarations
// ---------------------------------------------------------------------------

/// DHCPv6 server core: socket initialization, packet processing, address allocation.
/// Replaces `src/dhcp6.c` (1,487 lines).
pub mod server;

/// DHCPv6 protocol state machine (RFC 3315): message handling, IA processing.
/// Replaces `src/rfc3315.c` (4,216 lines) + `src/dhcp6-protocol.h` (685 lines).
pub mod protocol;

/// DHCPv6 option serialization and packet buffer management.
/// Replaces `src/outpacket.c` (702 lines).
pub mod outpacket;

// ===========================================================================
// DHCPv6 Protocol Constants
//
// All constants below are ported from src/dhcp6-protocol.h (685 lines).
// Every value matches the original C #define exactly.
// ===========================================================================

// ---------------------------------------------------------------------------
// Port Numbers (RFC 3315 Section 5.2)
// ---------------------------------------------------------------------------

/// DHCPv6 server UDP port (547). Servers and relay agents receive client
/// messages and relay-forward messages on this port.
/// Per RFC 3315 Section 5.2.
/// Replaces C `DHCPV6_SERVER_PORT` (dhcp6-protocol.h line 99).
pub const DHCPV6_SERVER_PORT: u16 = 547;

/// DHCPv6 client UDP port (546). Clients receive server responses and
/// relay-reply messages on this port.
/// Per RFC 3315 Section 5.2.
/// Replaces C `DHCPV6_CLIENT_PORT` (dhcp6-protocol.h line 108).
pub const DHCPV6_CLIENT_PORT: u16 = 546;

// ---------------------------------------------------------------------------
// Multicast Addresses (RFC 3315 Section 5.1)
// ---------------------------------------------------------------------------

/// All_DHCP_Servers multicast address (site-local scope FF05::1:3).
/// Used by relay agents to forward messages to all DHCPv6 servers
/// in the site.
/// Per RFC 3315 Section 5.1.
/// Replaces C `ALL_SERVERS` (dhcp6-protocol.h line 118).
pub const ALL_SERVERS: &str = "FF05::1:3";

/// All_DHCP_Relay_Agents_and_Servers multicast address (link-local scope
/// FF02::1:2). Clients send initial messages (SOLICIT, REQUEST, CONFIRM,
/// REBIND, INFORMATION-REQUEST) to this address.
/// Per RFC 3315 Section 5.1.
/// Replaces C `ALL_RELAY_AGENTS_AND_SERVERS` (dhcp6-protocol.h line 129).
pub const ALL_RELAY_AGENTS_AND_SERVERS: &str = "FF02::1:2";

// ---------------------------------------------------------------------------
// Message Types (RFC 3315 Section 5.3)
//
// DHCPv6 message type occupies 1 byte in the message header. Values 1-13
// are defined. The type field is followed by a 3-byte transaction ID.
// ---------------------------------------------------------------------------

/// SOLICIT message type (1). Sent by a client to locate available DHCPv6
/// servers. Multicast to All_DHCP_Relay_Agents_and_Servers (FF02::1:2).
/// Per RFC 3315 Section 17.1.1.
/// Replaces C `DHCP6SOLICIT` (dhcp6-protocol.h line 140).
pub const DHCP6_SOLICIT: u8 = 1;

/// ADVERTISE message type (2). Sent by a server in response to a SOLICIT
/// to indicate availability and offer addresses/prefixes.
/// Per RFC 3315 Section 17.2.2.
/// Replaces C `DHCP6ADVERTISE` (dhcp6-protocol.h line 151).
pub const DHCP6_ADVERTISE: u8 = 2;

/// REQUEST message type (3). Sent by a client to request configuration
/// parameters (including addresses/prefixes) from a specific server
/// identified by its Server Identifier option.
/// Per RFC 3315 Section 18.1.1.
/// Replaces C `DHCP6REQUEST` (dhcp6-protocol.h line 161).
pub const DHCP6_REQUEST: u8 = 3;

/// CONFIRM message type (4). Sent by a client to verify that the
/// addresses it was assigned are still appropriate for the link to
/// which the client is connected (e.g., after link change).
/// Per RFC 3315 Section 18.1.2.
/// Replaces C `DHCP6CONFIRM` (dhcp6-protocol.h line 172).
pub const DHCP6_CONFIRM: u8 = 4;

/// RENEW message type (5). Sent by a client to the server that
/// originally provided its addresses/prefixes to extend their
/// lifetimes (T1 timer expiry). Unicast to the server.
/// Per RFC 3315 Section 18.1.3.
/// Replaces C `DHCP6RENEW` (dhcp6-protocol.h line 183).
pub const DHCP6_RENEW: u8 = 5;

/// REBIND message type (6). Sent by a client to any available server
/// to extend address/prefix lifetimes when the original server is
/// unreachable (T2 timer expiry). Multicast.
/// Per RFC 3315 Section 18.1.4.
/// Replaces C `DHCP6REBIND` (dhcp6-protocol.h line 194).
pub const DHCP6_REBIND: u8 = 6;

/// REPLY message type (7). Sent by a server in response to SOLICIT
/// (with rapid commit), REQUEST, RENEW, REBIND, RELEASE, DECLINE,
/// CONFIRM, or INFORMATION-REQUEST messages.
/// Per RFC 3315 Section 18.2.
/// Replaces C `DHCP6REPLY` (dhcp6-protocol.h line 205).
pub const DHCP6_REPLY: u8 = 7;

/// RELEASE message type (8). Sent by a client to the server to
/// indicate that the client no longer needs the assigned addresses
/// or prefixes. The server releases the resources.
/// Per RFC 3315 Section 18.1.6.
/// Replaces C `DHCP6RELEASE` (dhcp6-protocol.h line 215).
pub const DHCP6_RELEASE: u8 = 8;

/// DECLINE message type (9). Sent by a client to the server to report
/// that one or more addresses assigned by the server are already in
/// use on the link (Duplicate Address Detection failure).
/// Per RFC 3315 Section 18.1.7.
/// Replaces C `DHCP6DECLINE` (dhcp6-protocol.h line 226).
pub const DHCP6_DECLINE: u8 = 9;

/// RECONFIGURE message type (10). Sent by a server to a client to
/// inform the client that the server has new or updated configuration
/// parameters. The client initiates RENEW/INFORMATION-REQUEST in
/// response.
/// Per RFC 3315 Section 19.
/// Replaces C `DHCP6RECONFIGURE` (dhcp6-protocol.h line 237).
pub const DHCP6_RECONFIGURE: u8 = 10;

/// INFORMATION-REQUEST message type (11). Sent by a client to request
/// configuration parameters without address or prefix assignment
/// (stateless DHCPv6). Used when the client only needs DNS servers,
/// domain search list, NTP servers, etc.
/// Per RFC 3315 Section 18.1.5.
/// Replaces C `DHCP6IREQ` (dhcp6-protocol.h line 248).
pub const DHCP6_INFORMATION_REQUEST: u8 = 11;

/// RELAY-FORW message type (12). Sent by a relay agent to forward
/// a client message (or another relay-forward message) toward the
/// server. Contains hop count, link-address, peer-address, and
/// a Relay Message option encapsulating the client's message.
/// Per RFC 3315 Section 20.1.
/// Replaces C `DHCP6RELAYFORW` (dhcp6-protocol.h line 259).
pub const DHCP6_RELAY_FORW: u8 = 12;

/// RELAY-REPL message type (13). Sent by a server to a relay agent
/// containing a message that the relay agent delivers to the client.
/// The relay agent extracts the Relay Message option and forwards
/// the contained message toward the client.
/// Per RFC 3315 Section 20.2.
/// Replaces C `DHCP6RELAYREPL` (dhcp6-protocol.h line 270).
pub const DHCP6_RELAY_REPL: u8 = 13;

// ---------------------------------------------------------------------------
// Option Codes (RFC 3315 Section 22 and extensions)
//
// DHCPv6 options use TLV (Type-Length-Value) encoding with 2-byte type
// code, 2-byte length, and variable-length value. Option codes below
// span multiple RFCs as noted.
// ---------------------------------------------------------------------------

/// Client Identifier option (1). Contains the client's DUID (DHCP Unique
/// Identifier) to identify the client. Present in all messages from
/// client to server.
/// Per RFC 3315 Section 22.2.
/// Replaces C `OPTION6_CLIENT_ID` (dhcp6-protocol.h line 281).
pub const OPTION6_CLIENT_ID: u16 = 1;

/// Server Identifier option (2). Contains the server's DUID to identify
/// the server. Sent by the server in ADVERTISE and REPLY messages. Sent
/// by the client in REQUEST, RENEW, RELEASE, and DECLINE to target a
/// specific server.
/// Per RFC 3315 Section 22.3.
/// Replaces C `OPTION6_SERVER_ID` (dhcp6-protocol.h line 291).
pub const OPTION6_SERVER_ID: u16 = 2;

/// Identity Association for Non-temporary Addresses option (3). Contains
/// an IAID (Identity Association Identifier), T1 and T2 renewal timers,
/// and encapsulated IA Address options. Used for normal (non-temporary)
/// IPv6 address assignment.
/// Per RFC 3315 Section 22.4.
/// Replaces C `OPTION6_IA_NA` (dhcp6-protocol.h line 302).
pub const OPTION6_IA_NA: u16 = 3;

/// Identity Association for Temporary Addresses option (4). Similar to
/// IA_NA but for temporary addresses (privacy extensions). Contains IAID
/// and encapsulated IA Address options but no T1/T2 timers.
/// Per RFC 3315 Section 22.5.
/// Replaces C `OPTION6_IA_TA` (dhcp6-protocol.h line 313).
pub const OPTION6_IA_TA: u16 = 4;

/// IA Address option (5). Encapsulated within IA_NA or IA_TA. Contains
/// an IPv6 address (16 bytes), preferred lifetime, and valid lifetime.
/// Per RFC 3315 Section 22.6.
/// Replaces C `OPTION6_IAADDR` (dhcp6-protocol.h line 324).
pub const OPTION6_IAADDR: u16 = 5;

/// Option Request option (6). Sent by the client to list option codes
/// the client is interested in receiving from the server. Contains a
/// list of 2-byte option codes.
/// Per RFC 3315 Section 22.7.
/// Replaces C `OPTION6_ORO` (dhcp6-protocol.h line 335).
pub const OPTION6_ORO: u16 = 6;

/// Preference option (7). Sent by the server in ADVERTISE to indicate
/// its preference level (0-255). Clients prefer servers with higher
/// preference values. A preference of 255 causes immediate selection.
/// Per RFC 3315 Section 22.8.
/// Replaces C `OPTION6_PREFERENCE` (dhcp6-protocol.h line 346).
pub const OPTION6_PREFERENCE: u16 = 7;

/// Elapsed Time option (8). Sent by the client to indicate the time
/// elapsed (in hundredths of a second) since the client began the
/// current DHCPv6 transaction.
/// Per RFC 3315 Section 22.9.
/// Replaces C `OPTION6_ELAPSED_TIME` (dhcp6-protocol.h line 357).
pub const OPTION6_ELAPSED_TIME: u16 = 8;

/// Relay Message option (9). Used in RELAY-FORW and RELAY-REPL messages
/// to encapsulate the relayed DHCPv6 message. Contains the complete
/// DHCPv6 message being forwarded through the relay chain.
/// Per RFC 3315 Section 22.10.
/// Replaces C `OPTION6_RELAY_MSG` (dhcp6-protocol.h line 368).
pub const OPTION6_RELAY_MSG: u16 = 9;

/// Authentication option (11). Provides authentication and replay
/// protection for DHCPv6 messages. Contains protocol, algorithm,
/// RDM (Replay Detection Method), replay detection value, and
/// authentication information.
/// Per RFC 3315 Section 22.11.
/// Replaces C `OPTION6_AUTH` (dhcp6-protocol.h line 379).
pub const OPTION6_AUTH: u16 = 11;

/// Server Unicast option (12). Sent by the server to indicate that
/// the client is allowed to send messages directly to the server's
/// unicast address instead of using multicast. Contains the server's
/// IPv6 address (16 bytes).
/// Per RFC 3315 Section 22.12.
/// Replaces C `OPTION6_UNICAST` (dhcp6-protocol.h line 390).
pub const OPTION6_UNICAST: u16 = 12;

/// Status Code option (13). Indicates the outcome of a DHCPv6
/// operation. Contains a 2-byte status code followed by a UTF-8
/// status message string. Can appear at the top level or within
/// IA_NA/IA_TA/IA_PD/IAADDR/IAPREFIX options.
/// Per RFC 3315 Section 22.13.
/// Replaces C `OPTION6_STATUS_CODE` (dhcp6-protocol.h line 401).
pub const OPTION6_STATUS_CODE: u16 = 13;

/// Rapid Commit option (14). Used to signal and acknowledge a two-
/// message exchange (SOLICIT→REPLY) instead of the normal four-message
/// exchange. Zero-length option (no value data).
/// Per RFC 3315 Section 22.14.
/// Replaces C `OPTION6_RAPID_COMMIT` (dhcp6-protocol.h line 412).
pub const OPTION6_RAPID_COMMIT: u16 = 14;

/// User Class option (15). Identifies the type or category of users
/// or applications. Contains one or more user class data items, each
/// preceded by a 2-byte length field.
/// Per RFC 3315 Section 22.15.
/// Replaces C `OPTION6_USER_CLASS` (dhcp6-protocol.h line 423).
pub const OPTION6_USER_CLASS: u16 = 15;

/// Vendor Class option (16). Identifies the vendor that manufactured
/// the client hardware or software. Contains a 4-byte enterprise number
/// followed by vendor class data items.
/// Per RFC 3315 Section 22.16.
/// Replaces C `OPTION6_VENDOR_CLASS` (dhcp6-protocol.h line 433).
pub const OPTION6_VENDOR_CLASS: u16 = 16;

/// Vendor-specific Information option (17). Contains vendor-specific
/// configuration parameters. Includes a 4-byte enterprise number
/// followed by vendor-specific option data (sub-options).
/// Per RFC 3315 Section 22.17.
/// Replaces C `OPTION6_VENDOR_OPTS` (dhcp6-protocol.h line 443).
pub const OPTION6_VENDOR_OPTS: u16 = 17;

/// Interface-Id option (18). Used in relay messages to identify the
/// interface on which the relay agent received the client message.
/// Opaque data meaningful to the relay agent; the server echoes it
/// back in RELAY-REPL for relay to identify the correct egress.
/// Per RFC 3315 Section 22.18.
/// Replaces C `OPTION6_INTERFACE_ID` (dhcp6-protocol.h line 454).
pub const OPTION6_INTERFACE_ID: u16 = 18;

/// Reconfigure Message option (19). Sent by the server in RECONFIGURE
/// to indicate which type of message (RENEW or INFORMATION-REQUEST) the
/// client should initiate in response. Contains a 1-byte message type.
/// Per RFC 3315 Section 22.19.
/// Replaces C `OPTION6_RECONFIGURE_MSG` (dhcp6-protocol.h line 464).
pub const OPTION6_RECONFIGURE_MSG: u16 = 19;

/// Reconfigure Accept option (20). Sent by the client to indicate
/// willingness to accept RECONFIGURE messages from the server.
/// Zero-length option (no value data).
/// Per RFC 3315 Section 22.20.
/// Replaces C `OPTION6_RECONF_ACCEPT` (dhcp6-protocol.h line 475).
pub const OPTION6_RECONF_ACCEPT: u16 = 20;

/// DNS Recursive Name Server option (23). Provides the client with
/// one or more IPv6 addresses of DNS recursive name servers. Each
/// address is 16 bytes (128 bits).
/// Per RFC 3646 Section 3.
/// Replaces C `OPTION6_DNS_SERVER` (dhcp6-protocol.h line 486).
pub const OPTION6_DNS_SERVER: u16 = 23;

/// Domain Search List option (24). Provides the client with a list
/// of domain names to use when resolving hostnames with DNS. Encoded
/// using the technique described in RFC 1035 Section 3.1 (DNS name
/// compression format).
/// Per RFC 3646 Section 4.
/// Replaces C `OPTION6_DOMAIN_SEARCH` (dhcp6-protocol.h line 496).
pub const OPTION6_DOMAIN_SEARCH: u16 = 24;

/// Identity Association for Prefix Delegation option (25). Used for
/// IPv6 prefix delegation to requesting routers. Contains IAID,
/// T1 and T2 timers, and encapsulated IA Prefix options. The requesting
/// router receives IPv6 prefix(es) to assign addresses on downstream
/// networks.
/// Per RFC 3633 Section 9.
/// Replaces C `OPTION6_IA_PD` (dhcp6-protocol.h line 507).
pub const OPTION6_IA_PD: u16 = 25;

/// IA Prefix option (26). Encapsulated within IA_PD. Contains the
/// delegated IPv6 prefix, prefix length, preferred lifetime, and
/// valid lifetime. The requesting router assigns addresses from the
/// prefix to downstream clients.
/// Per RFC 3633 Section 10.
/// Replaces C `OPTION6_IAPREFIX` (dhcp6-protocol.h line 518).
pub const OPTION6_IAPREFIX: u16 = 26;

/// Information Refresh Time option (32). A 32-bit value in seconds
/// indicating how long the client should wait before refreshing
/// configuration obtained via INFORMATION-REQUEST. Sent by the server
/// in REPLY to INFORMATION-REQUEST.
/// Per RFC 4242 Section 3.1.
/// Replaces C `OPTION6_REFRESH_TIME` (dhcp6-protocol.h line 529).
pub const OPTION6_REFRESH_TIME: u16 = 32;

/// Remote Identifier option (37). Inserted by a relay agent to identify
/// the remote host end of the circuit. Contains an enterprise number
/// and a remote-id value opaque to the server. Allows correlation of
/// relay agent identity with client for address assignment policies.
/// Per RFC 4649 Section 3.
/// Replaces C `OPTION6_REMOTE_ID` (dhcp6-protocol.h line 540).
pub const OPTION6_REMOTE_ID: u16 = 37;

/// Subscriber Identifier option (38). Contains a subscriber ID assigned
/// by the provider's operational support system. Allows correlation
/// between DHCPv6 transactions and subscriber billing/provisioning
/// records. Typically inserted by relay agents.
/// Per RFC 4580 Section 3.
/// Replaces C `OPTION6_SUBSCRIBER_ID` (dhcp6-protocol.h line 550).
pub const OPTION6_SUBSCRIBER_ID: u16 = 38;

/// Fully Qualified Domain Name option (39). Allows client and server
/// to negotiate the client's FQDN and responsibility for DNS updates.
/// Contains flags (S=server performs update, O=override client, N=no
/// update) followed by the domain name.
/// Per RFC 4704 Section 4.
/// Replaces C `OPTION6_FQDN` (dhcp6-protocol.h line 560).
pub const OPTION6_FQDN: u16 = 39;

/// Network Time Protocol Servers option (56). Provides the client with
/// NTP server information for time synchronization. Contains NTP
/// sub-options: SRV_ADDR (1) for server addresses, MC_ADDR (2) for
/// multicast addresses, and SRV_FQDN (3) for server FQDNs.
/// Per RFC 5908 Section 4.
/// Replaces C `OPTION6_NTP_SERVER` (dhcp6-protocol.h line 571).
pub const OPTION6_NTP_SERVER: u16 = 56;

/// Client Link-Layer Address option (79). Contains the client's
/// link-layer address (typically a MAC address). Useful when a relay
/// agent prevents the server from determining the client's MAC address
/// directly. The relay agent may add this option.
/// Per RFC 6939 Section 3.
/// Replaces C `OPTION6_CLIENT_MAC` (dhcp6-protocol.h line 582).
pub const OPTION6_CLIENT_MAC: u16 = 79;

/// Manufacturer Usage Description URL option (112). Contains a URL
/// pointing to a MUD file describing the device's intended network
/// communication patterns. Used for IoT device security and network
/// access control policy enforcement.
/// Per RFC 8520 Section 10.
/// Replaces C `OPTION6_MUD_URL` (dhcp6-protocol.h line 593).
pub const OPTION6_MUD_URL: u16 = 112;

// ---------------------------------------------------------------------------
// NTP Suboption Types (RFC 5908)
//
// Sub-options within OPTION6_NTP_SERVER (56). Each NTP sub-option uses
// a 2-byte type code and 2-byte length, followed by the sub-option data.
// ---------------------------------------------------------------------------

/// NTP Server Address sub-option (1) within OPTION6_NTP_SERVER.
/// Contains one or more IPv6 unicast addresses of NTP servers.
/// Per RFC 5908 Section 4.1.
/// Replaces C `NTP_SUBOPTION_SRV_ADDR` (dhcp6-protocol.h line 603).
pub const NTP_SUBOPTION_SRV_ADDR: u16 = 1;

/// NTP Multicast Address sub-option (2) within OPTION6_NTP_SERVER.
/// Contains one or more IPv6 multicast addresses for NTP multicast
/// servers.
/// Per RFC 5908 Section 4.2.
/// Replaces C `NTP_SUBOPTION_MC_ADDR` (dhcp6-protocol.h line 613).
pub const NTP_SUBOPTION_MC_ADDR: u16 = 2;

/// NTP Server FQDN sub-option (3) within OPTION6_NTP_SERVER.
/// Contains one or more fully qualified domain names of NTP servers.
/// Allows NTP server IP changes without DHCPv6 reconfiguration.
/// Per RFC 5908 Section 4.3.
/// Replaces C `NTP_SUBOPTION_SRV_FQDN` (dhcp6-protocol.h line 624).
pub const NTP_SUBOPTION_SRV_FQDN: u16 = 3;

// ---------------------------------------------------------------------------
// Status Codes (RFC 3315 Section 24.4)
//
// Status codes are 2-byte unsigned integers used in the Status Code
// option (OPTION6_STATUS_CODE, code 13) to indicate the outcome of
// DHCPv6 operations.
// ---------------------------------------------------------------------------

/// Success status code (0). Indicates that the requested operation
/// completed successfully. Sent in STATUS_CODE option within REPLY
/// at the top level or within IA_NA/IA_TA/IA_PD/IAADDR/IAPREFIX.
/// Per RFC 3315 Section 24.4.
/// Replaces C `DHCP6SUCCESS` (dhcp6-protocol.h line 634).
pub const DHCP6_SUCCESS: u16 = 0;

/// Unspecified Failure status code (1). Indicates failure for an
/// unspecified reason. The server encountered an error but cannot
/// provide a more specific status code. Client should log the error
/// and may retry or attempt an alternate server.
/// Per RFC 3315 Section 24.4.
/// Replaces C `DHCP6UNSPEC` (dhcp6-protocol.h line 644).
pub const DHCP6_UNSPEC_FAIL: u16 = 1;

/// No Addresses Available status code (2). The server has no addresses
/// available to assign to the client. Sent within IA_NA or IA_TA.
/// Client should attempt REBIND to other servers or wait for addresses
/// to become available. Indicates address pool exhaustion.
/// Per RFC 3315 Section 24.4.
/// Replaces C `DHCP6NOADDRS` (dhcp6-protocol.h line 654).
pub const DHCP6_NO_ADDRS_AVAIL: u16 = 2;

/// No Binding status code (3). The server has no record of the client's
/// binding (lease). Sent in response to RENEW, REBIND, or RELEASE when
/// the client references an Identity Association unknown to the server.
/// Client should reinitialize with SOLICIT.
/// Per RFC 3315 Section 24.4.
/// Replaces C `DHCP6NOBINDING` (dhcp6-protocol.h line 664).
pub const DHCP6_NO_BINDING: u16 = 3;

/// Not On Link status code (4). The client's addresses are not
/// appropriate for the link to which the client is attached. Sent in
/// response to CONFIRM. Client should stop using current addresses
/// and reinitialize with SOLICIT.
/// Per RFC 3315 Section 24.4.
/// Replaces C `DHCP6NOTONLINK` (dhcp6-protocol.h line 675).
pub const DHCP6_NOT_ON_LINK: u16 = 4;

/// Use Multicast status code (5). The client should use the
/// All_DHCP_Relay_Agents_and_Servers multicast address (FF02::1:2)
/// instead of unicast. Sent when the client sends a unicast message
/// but the server requires multicast.
/// Per RFC 3315 Section 24.4.
/// Replaces C `DHCP6USEMULTI` (dhcp6-protocol.h line 685).
pub const DHCP6_USE_MULTICAST: u16 = 5;

// ---------------------------------------------------------------------------
// Public Re-exports
//
// Re-export key types from sub-modules for convenient access at the
// `v6` module level. Consumer code can use `crate::dhcp::v6::OutPacket`
// instead of `crate::dhcp::v6::outpacket::OutPacket`.
// ---------------------------------------------------------------------------

pub use outpacket::OutPacket;
pub use protocol::{Dhcp6RequestState, DhcpV6State, IaType};
pub use server::{address6_allocate, address6_available, address6_valid, dhcp6_init, dhcp6_packet};

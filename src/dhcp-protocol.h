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
 * @file dhcp-protocol.h
 * @brief DHCPv4 Protocol Constants and Wire Format Definitions (RFC 2131)
 * 
 * DETAILED PURPOSE:
 * This header file serves as the authoritative source for DHCPv4 protocol constants,
 * message types, option numbers, and packet wire format structure definitions per
 * RFC 2131 (Dynamic Host Configuration Protocol) and RFC 2132 (DHCP Options and
 * BOOTP Vendor Extensions). It provides the foundational protocol definitions used
 * by the DHCPv4 server implementation modules.
 * 
 * This file defines the complete DHCPv4 packet structure matching the wire format
 * for network transmission, all standard DHCP message types (DISCOVER through INFORM),
 * DHCP option numbers (1-161), DHCP relay agent suboptions, PXE (Preboot Execution
 * Environment) specific constants, and hardware address type definitions.
 * 
 * KEY RESPONSIBILITIES:
 * - Define DHCPv4 network port numbers (standard 67/68 and alternate 1067/1068)
 * - Declare all DHCPv4 option numbers per RFC 2132 and subsequent extensions
 * - Define DHCPv4 message types for the protocol state machine (DISCOVER, OFFER, REQUEST, ACK, NAK, DECLINE, RELEASE, INFORM)
 * - Specify the struct dhcp_packet wire format structure matching RFC 2131 Section 2
 * - Document DHCP relay agent suboptions per RFC 3046 and RFC 3527
 * - Provide PXE network boot protocol constants per Intel PXE Specification
 * - Define DHCP hardware address types and packet flags
 * 
 * DEPENDENCIES:
 * Includes: None - this is a pure constant definition header
 * Used by: src/dhcp.c (DHCPv4 server core logic), src/rfc2131.c (DHCPv4 protocol implementation),
 *          src/dhcp-common.c (shared DHCP utilities), src/lease.c (lease database management)
 * 
 * DATA STRUCTURES:
 * - struct dhcp_packet: DHCPv4 packet wire format per RFC 2131 Section 2 (lines 103-110)
 *   Contains op (operation), htype (hardware type), hlen (hardware address length),
 *   hops (relay hop count), xid (transaction ID), secs (seconds elapsed), flags,
 *   IP addresses (ciaddr, yiaddr, siaddr, giaddr), hardware address (chaddr),
 *   server name (sname), boot filename (file), and variable-length options field
 * 
 * PROTOCOL OVERVIEW:
 * DHCPv4 implements a four-message exchange for dynamic IP address allocation:
 * 1. DHCPDISCOVER - Client broadcasts to discover available DHCP servers
 * 2. DHCPOFFER - Server unicasts offer with available IP address and configuration
 * 3. DHCPREQUEST - Client broadcasts request to accept specific server's offer
 * 4. DHCPACK - Server unicasts acknowledgment confirming lease assignment
 * 
 * Additional message types support lease renewal (DHCPREQUEST/DHCPACK), lease
 * release (DHCPRELEASE), address conflict notification (DHCPDECLINE), and
 * configuration-only requests without address assignment (DHCPINFORM).
 * 
 * RELATIONSHIP TO IMPLEMENTATION MODULES:
 * - src/dhcp.c: Uses message types and options for packet processing and response generation
 * - src/rfc2131.c: Implements DHCPv4 protocol state machine using these constants
 * - src/dhcp-common.c: Parses and validates option fields defined here
 * - src/lease.c: Stores lease data extracted from packets structured per this header
 * 
 * RFC COMPLIANCE:
 * - RFC 2131: Dynamic Host Configuration Protocol (DHCP message format and exchange)
 * - RFC 2132: DHCP Options and BOOTP Vendor Extensions (option numbers and formats)
 * - RFC 3046: DHCP Relay Agent Information Option (suboptions for relay agents)
 * - RFC 3527: Link Selection suboption for DHCP Relay Agent Option
 * - RFC 3993: Subscriber-ID suboption for DHCP Relay Agent Option
 * - RFC 4039: Rapid Commit Option for expedited address assignment
 * - RFC 4388: DHCP Leasequery protocol for querying lease information
 * - RFC 5010: DHCP Relay Agent Flags suboption
 * - RFC 5107: DHCP Server Identifier Override suboption
 * - Intel PXE Specification 2.1: Network boot protocol extensions
 * 
 * THREADING/CONCURRENCY:
 * This header defines read-only constants accessed by the single-threaded dnsmasq
 * event loop. The struct dhcp_packet definition is used for stack-allocated packet
 * buffers during packet processing, with no shared mutable state.
 * 
 * @copyright Copyright (c) 2000-2025 Simon Kelley
 * @license GPL-2.0-or-later
 */
/**
 * @defgroup DHCPPorts DHCPv4 Network Port Definitions
 * @brief Standard and alternate UDP port numbers for DHCP communication
 * 
 * DHCPv4 uses well-known UDP ports for client-server communication. The standard
 * ports (67/68) require privileged binding. Alternate ports (1067/1068) allow
 * non-privileged testing and specialized deployments. PXE uses port 4011 for
 * proxy DHCP mode enabling network boot parameter delivery without IP assignment.
 * 
 * Per RFC 2131 Section 4.1: "DHCP uses UDP as its transport protocol. DHCP
 * messages from a client to a server are sent to the 'DHCP server' port (67),
 * and DHCP messages from a server to a client are sent to the 'DHCP client'
 * port (68)."
 * @{
 */

/** @brief Standard DHCPv4 server listening port (privileged port, requires root)
 *  Server binds to this port to receive DHCPDISCOVER, DHCPREQUEST, DHCPRELEASE,
 *  DHCPDECLINE, and DHCPINFORM messages from clients on port 68.
 *  Source: RFC 2131 Section 4.1 */
#define DHCP_SERVER_PORT 67

/** @brief Standard DHCPv4 client listening port
 *  Clients bind to this port to receive DHCPOFFER and DHCPACK messages from
 *  servers. Server sends responses to this port even for clients without IP yet.
 *  Source: RFC 2131 Section 4.1 */
#define DHCP_CLIENT_PORT 68

/** @brief Alternate DHCPv4 server port for non-privileged or testing deployments
 *  Non-standard port avoiding privileged binding requirement. Configured via
 *  --dhcp-alternate-port option. Used in development and specialized scenarios.
 *  Source: dnsmasq extension */
#define DHCP_SERVER_ALTPORT 1067

/** @brief Alternate DHCPv4 client port corresponding to alternate server port
 *  Client-side alternate port for use with DHCP_SERVER_ALTPORT deployments.
 *  Source: dnsmasq extension */
#define DHCP_CLIENT_ALTPORT 1068

/** @brief PXE (Preboot Execution Environment) proxy DHCP port
 *  PXE proxy mode uses this port to provide boot parameters (boot filename,
 *  TFTP server) without providing IP address assignment. Allows coexistence
 *  with existing DHCP infrastructure for network boot scenarios.
 *  Source: Intel PXE Specification 2.1 Section 2.2.5 */
#define PXE_PORT 4011

/** @} */ /* End of DHCPPorts group */

/**
 * @defgroup DHCPBuffers Buffer Size and Protocol Constants
 * @brief Buffer sizing and fundamental BOOTP/DHCP protocol constants
 * @{
 */

/** @brief Maximum DHCP option data buffer size including null terminator
 *  DHCPv4 options have maximum length of 255 bytes per RFC 2132. This buffer
 *  size accommodates the maximum option data length (255) plus a terminating
 *  null byte (1) for C string safety when options contain text data.
 *  Used for temporary option parsing buffers in dhcp.c and rfc2131.c.
 *  Source: RFC 2132 Section 2 (option format) */
#define DHCP_BUFF_SZ 256

/** @brief BOOTP request operation code
 *  Value for the 'op' field in struct dhcp_packet indicating client-to-server
 *  message (BOOTREQUEST). Used in DHCPDISCOVER, DHCPREQUEST, DHCPDECLINE,
 *  DHCPRELEASE, and DHCPINFORM messages.
 *  Source: RFC 2131 Section 2 (inherits from RFC 951 BOOTP) */
#define BOOTREQUEST              1

/** @brief BOOTP reply operation code
 *  Value for the 'op' field in struct dhcp_packet indicating server-to-client
 *  message (BOOTREPLY). Used in DHCPOFFER and DHCPACK messages.
 *  Source: RFC 2131 Section 2 (inherits from RFC 951 BOOTP) */
#define BOOTREPLY                2

/** @brief DHCP magic cookie value for option field identification
 *  Four-byte constant (99.130.83.99 in dotted decimal) placed at start of
 *  options field in struct dhcp_packet to distinguish DHCP packets from
 *  legacy BOOTP packets. Hex value 0x63825363.
 *  Per RFC 2131 Section 3: "The first four octets of the 'options' field of
 *  the DHCP message contain the (decimal) values 99, 130, 83 and 99."
 *  Source: RFC 2131 Section 3 */
#define DHCP_COOKIE              0x63825363

/** @brief Minimum DHCPv4 packet size to satisfy Linux in-kernel DHCP client
 *  The Linux kernel's built-in DHCP client silently discards packets smaller
 *  than 300 bytes regardless of actual packet validity. Dnsmasq pads outgoing
 *  DHCP responses to this minimum size to ensure Linux kernel client compatibility.
 *  This is a workaround for Linux kernel DHCP client implementation quirk, not
 *  an RFC requirement. Standard DHCP minimum is 236 bytes (fixed fields) plus
 *  variable options.
 *  Source: Linux kernel net/ipv4/ipconfig.c behavior, dnsmasq compatibility fix */
#define MIN_PACKETSZ             300

/** @} */ /* End of DHCPBuffers group */

/**
 * @defgroup DHCPOptions DHCPv4 Option Number Definitions
 * @brief Standard DHCP option codes per RFC 2132 and extensions
 * 
 * DHCPv4 options provide configuration parameters and control protocol behavior.
 * Each option consists of: 1-byte code, 1-byte length, variable-length data.
 * Options appear in the variable-length 'options' field of struct dhcp_packet
 * after the DHCP_COOKIE magic value.
 * 
 * Option number assignments by IANA: https://www.iana.org/assignments/bootp-dhcp-parameters/
 * 
 * Common options (1-67) provide network configuration (IP, subnet, gateway, DNS).
 * Protocol control options (50-61) manage DHCP state machine and lease negotiation.
 * Extended options (77-161) support specialized features (PXE boot, relay agents, vendor extensions).
 * 
 * Implementation note: dnsmasq implements comprehensive option processing in
 * src/dhcp-common.c (option parsing) and src/rfc2131.c (option encoding in responses).
 * @{
 */

/** @brief Option 0: Pad option for alignment (no data)
 *  Used to pad option field to alignment boundaries. Contains no length or data bytes.
 *  Per RFC 2132 Section 3.1: "The pad option can be used to cause subsequent fields
 *  to align on word boundaries."
 *  Source: RFC 2132 Section 3.1 */
#define OPTION_PAD               0

/** @brief Option 1: Subnet Mask (4 bytes)
 *  Specifies the client's subnet mask per RFC 950. Value is 4-byte IPv4 subnet mask.
 *  Example: 255.255.255.0 for /24 network.
 *  Source: RFC 2132 Section 3.3 */
#define OPTION_NETMASK           1

/** @brief Option 3: Router (4+ bytes, multiple of 4)
 *  List of router IP addresses on client's subnet, in order of preference.
 *  Minimum one router (4 bytes), multiple routers supported (8, 12, 16... bytes).
 *  Client typically uses first router as default gateway.
 *  Source: RFC 2132 Section 3.5 */
#define OPTION_ROUTER            3

/** @brief Option 6: Domain Name Server (4+ bytes, multiple of 4)
 *  List of DNS recursive resolver IP addresses available to client, in order of preference.
 *  Minimum one DNS server (4 bytes), multiple servers supported (8, 12, 16... bytes).
 *  Source: RFC 2132 Section 3.8 */
#define OPTION_DNSSERVER         6

/** @brief Option 12: Host Name (variable length string)
 *  Specifies the client's hostname per RFC 1123, without domain suffix.
 *  Used by client to inform server of desired hostname, or server to assign hostname.
 *  Maximum length 255 bytes. Example: "workstation1"
 *  Source: RFC 2132 Section 3.14 */
#define OPTION_HOSTNAME          12

/** @brief Option 15: Domain Name (variable length string)
 *  Specifies the domain name for DNS resolution and hostname qualification.
 *  Example: "example.com". Combined with OPTION_HOSTNAME forms FQDN.
 *  Source: RFC 2132 Section 3.17 */
#define OPTION_DOMAINNAME        15

/** @brief Option 28: Broadcast Address (4 bytes)
 *  Specifies the broadcast address for the client's subnet.
 *  Used for subnet-directed broadcasts. Typically subnet address with host bits set to 1.
 *  Example: 192.168.1.255 for 192.168.1.0/24 network.
 *  Source: RFC 2132 Section 5.3 */
#define OPTION_BROADCAST         28

/** @brief Option 43: Vendor-Specific Information (variable length)
 *  Opaque vendor-specific data. Format and content defined by vendor (identified
 *  by OPTION_VENDOR_ID). PXE uses this for boot menu and server discovery.
 *  Source: RFC 2132 Section 8.4 */
#define OPTION_VENDOR_CLASS_OPT  43

/** @brief Option 50: Requested IP Address (4 bytes)
 *  Used by client in DHCPREQUEST to request specific IP address, or in DHCPDISCOVER
 *  to suggest previously allocated address. Server may honor or ignore request.
 *  Source: RFC 2132 Section 9.1 */
#define OPTION_REQUESTED_IP      50

/** @brief Option 51: IP Address Lease Time (4 bytes, seconds)
 *  Lease duration in seconds as 32-bit unsigned integer. Value 0xFFFFFFFF means
 *  infinite lease. Typical values: 3600 (1 hour) to 86400 (24 hours).
 *  Client must renew before expiration.
 *  Source: RFC 2132 Section 9.2 */
#define OPTION_LEASE_TIME        51

/** @brief Option 52: Option Overload (1 byte)
 *  Indicates that 'file' and/or 'sname' fields in struct dhcp_packet contain
 *  DHCP options instead of filename/server name. Values: 1='file' contains options,
 *  2='sname' contains options, 3=both contain options.
 *  Source: RFC 2132 Section 9.3 */
#define OPTION_OVERLOAD          52

/** @brief Option 53: DHCP Message Type (1 byte) - REQUIRED
 *  Identifies DHCP message type (DHCPDISCOVER=1, DHCPOFFER=2, DHCPREQUEST=3, etc.).
 *  This option MUST be present in every DHCP message per RFC 2131.
 *  Values defined in DHCPDISCOVER through DHCPLEASEACTIVE constants below.
 *  Source: RFC 2132 Section 9.6 */
#define OPTION_MESSAGE_TYPE      53

/** @brief Option 54: Server Identifier (4 bytes)
 *  IP address of the DHCP server sending this message. Used by client to identify
 *  which server's offer to accept in DHCPREQUEST, and by server to identify itself
 *  in DHCPOFFER and DHCPACK. MUST be included by server in DHCPOFFER and DHCPACK.
 *  Source: RFC 2132 Section 9.7 */
#define OPTION_SERVER_IDENTIFIER 54

/** @brief Option 55: Parameter Request List (variable length, list of option codes)
 *  Client includes this in DHCPDISCOVER and DHCPREQUEST to indicate which options
 *  it wants server to include in response. Each byte is an option code.
 *  Example: {1, 3, 6, 15} requests subnet mask, router, DNS, domain name.
 *  Source: RFC 2132 Section 9.8 */
#define OPTION_REQUESTED_OPTIONS 55

/** @brief Option 56: Message (variable length string)
 *  Error message string included by server in DHCPNAK to explain rejection,
 *  or informational message. Human-readable text for logging/display.
 *  Source: RFC 2132 Section 9.9 */
#define OPTION_MESSAGE           56

/** @brief Option 57: Maximum DHCP Message Size (2 bytes)
 *  Maximum DHCP message size client is willing to accept (minimum 576 bytes).
 *  Server uses this to avoid fragmenting responses. Client includes in DHCPDISCOVER.
 *  Source: RFC 2132 Section 9.10 */
#define OPTION_MAXMESSAGE        57

/** @brief Option 58: Renewal Time Value (T1) (4 bytes, seconds)
 *  Time interval from address assignment until client enters RENEWING state.
 *  Typically 50% of lease time. Client begins renewing lease at T1 expiration.
 *  Source: RFC 2132 Section 9.11 */
#define OPTION_T1                58

/** @brief Option 59: Rebinding Time Value (T2) (4 bytes, seconds)
 *  Time interval from address assignment until client enters REBINDING state.
 *  Typically 87.5% of lease time. Client broadcasts rebind if renewal fails.
 *  Source: RFC 2132 Section 9.12 */
#define OPTION_T2                59

/** @brief Option 60: Vendor Class Identifier (variable length string)
 *  Identifies vendor and client type. Used for client classification and
 *  vendor-specific option delivery. PXE clients include "PXEClient" string.
 *  Example: "PXEClient:Arch:00000:UNDI:002001"
 *  Source: RFC 2132 Section 9.13 */
#define OPTION_VENDOR_ID         60

/** @brief Option 61: Client Identifier (variable length)
 *  Unique client identifier used instead of hardware address for lease binding.
 *  Format: 1-byte type code + identifier data. Provides persistent identity
 *  across hardware changes.
 *  Source: RFC 2132 Section 9.14 */
#define OPTION_CLIENT_ID         61

/** @brief Option 66: TFTP Server Name (variable length string)
 *  Hostname or IP address (as string) of TFTP server for network boot.
 *  Alternative to 'siaddr' field in struct dhcp_packet. Used with OPTION_FILENAME.
 *  Source: RFC 2132 Section 9.4 */
#define OPTION_SNAME             66

/** @brief Option 67: Boot File Name (variable length string)
 *  Boot filename for network boot clients (PXE, BOOTP). Path relative to
 *  TFTP server root. Example: "pxelinux.0". Alternative to 'file' field
 *  in struct dhcp_packet.
 *  Source: RFC 2132 Section 9.5 */
#define OPTION_FILENAME          67

/** @brief Option 77: User Class (variable length)
 *  User-defined classification string for grouping clients with similar
 *  configuration requirements. Format vendor-specific. Used for policy routing.
 *  Source: RFC 3004 */
#define OPTION_USER_CLASS        77

/** @brief Option 80: Rapid Commit (0 bytes, flag option)
 *  Enables two-message exchange (DHCPDISCOVER + DHCPACK) instead of four-message
 *  (DISCOVER, OFFER, REQUEST, ACK). Presence of option indicates support/request.
 *  Both client and server must support for use.
 *  Source: RFC 4039 */
#define OPTION_RAPID_COMMIT      80

/** @brief Option 81: Client FQDN (variable length)
 *  Fully Qualified Domain Name option for dynamic DNS updates. Contains flags,
 *  RCODE values, and FQDN string. Coordinates client hostname registration in DNS.
 *  Source: RFC 4702 */
#define OPTION_CLIENT_FQDN       81

/** @brief Option 82: Relay Agent Information (variable length, suboptions)
 *  Added by DHCP relay agents to include circuit identification, remote ID,
 *  and other relay-specific information. Contains suboptions (SUBOPT_* below).
 *  Source: RFC 3046 */
#define OPTION_AGENT_ID          82

/** @brief Option 91: Client Last Transaction Time (4 bytes, seconds)
 *  Used in DHCPLEASEQUERY responses to indicate seconds since client's last
 *  transaction with server. Part of leasequery protocol for external lease queries.
 *  Source: RFC 4388 Section 6.1 */
#define OPTION_LAST_TRANSACTION  91

/** @brief Option 92: Associated IP (4+ bytes, multiple of 4)
 *  Used in DHCPLEASEQUERY to query leases associated with specific IP addresses.
 *  Contains one or more IPv4 addresses.
 *  Source: RFC 4388 Section 6.2 */
#define OPTION_ASSOCIATED_IP     92

/** @brief Option 93: Client System Architecture (2 bytes)
 *  Identifies client CPU architecture for PXE network boot. Values: 0=x86 BIOS,
 *  6=x86 UEFI, 7=x64 UEFI, 9=EFI BC, 10=ARM32 UEFI, 11=ARM64 UEFI, etc.
 *  Used to select appropriate boot image per architecture.
 *  Source: RFC 4578 Section 2.1 */
#define OPTION_ARCH              93

/** @brief Option 97: UUID/GUID-based Client Identifier (17 bytes)
 *  PXE client machine identifier. First byte is type (0), followed by 16-byte
 *  UUID/GUID. Provides unique client identification for PXE environments.
 *  Source: RFC 4578 Section 2.5 */
#define OPTION_PXE_UUID          97

/** @brief Option 118: Subnet Selection (4 bytes)
 *  Allows client to specify which subnet it wants address from when behind
 *  relay agent. Used for explicit subnet selection in multi-subnet environments.
 *  Source: RFC 3011 */
#define OPTION_SUBNET_SELECT     118

/** @brief Option 119: Domain Search (variable length, DNS search list)
 *  List of domain suffixes for DNS hostname resolution search. Encoded as
 *  DNS wire format compressed domain names. Alternative to single OPTION_DOMAINNAME.
 *  Source: RFC 3397 */
#define OPTION_DOMAIN_SEARCH     119

/** @brief Option 120: SIP Servers (variable length)
 *  Session Initiation Protocol (SIP) server addresses for VoIP configuration.
 *  Can contain IPv4 addresses or DNS names for SIP proxy servers.
 *  Source: RFC 3361 */
#define OPTION_SIP_SERVER        120

/** @brief Option 124: Vendor-Identifying Vendor Class (variable length)
 *  Extended vendor identification with enterprise number and vendor-specific data.
 *  Format: 4-byte enterprise number + opaque vendor data. IANA enterprise numbers.
 *  Source: RFC 3925 Section 3 */
#define OPTION_VENDOR_IDENT      124

/** @brief Option 125: Vendor-Identifying Vendor-Specific Information (variable length)
 *  Vendor-specific data tagged with IANA enterprise number. Multiple vendors
 *  can coexist with unique enterprise numbers distinguishing data ownership.
 *  Source: RFC 3925 Section 4 */
#define OPTION_VENDOR_IDENT_OPT  125

/** @brief Option 161: Manufacturer Usage Description (MUD) URL (variable length)
 *  URL pointing to manufacturer's device security profile for IoT device policy.
 *  Enables automated network access control based on manufacturer specifications.
 *  Source: RFC 8520 */
#define OPTION_MUD_URL_V4        161

/** @brief Option 255: End option (no length or data)
 *  Marks end of option list in DHCP packet. All options must appear before this.
 *  Per RFC 2132 Section 3.2: "The end option marks the end of valid information
 *  in the vendor field."
 *  Source: RFC 2132 Section 3.2 */
#define OPTION_END               255

/** @} */ /* End of DHCPOptions group */

/**
 * @defgroup DHCPRelaySuboptions DHCP Relay Agent Information Suboptions
 * @brief Suboption codes for DHCP Option 82 (Relay Agent Information)
 * 
 * DHCP relay agents insert Option 82 containing suboptions to provide additional
 * circuit and subscriber identification. Suboptions appear as TLV (Type-Length-Value)
 * structures within the Option 82 data field. These enable network topology awareness,
 * policy routing, and detailed subscriber tracking in relay agent deployments.
 * 
 * Per RFC 3046: "The Relay Agent Information option is inserted by the DHCP relay
 * agent when forwarding client-originated DHCP packets to a DHCP server."
 * @{
 */

/** @brief Relay Agent Suboption 1: Circuit ID
 *  Identifies the circuit (interface, VLAN, physical port) on which DHCP request
 *  arrived at relay agent. Used for subnet selection and client location tracking.
 *  Format is agent-specific (typically interface name or port identifier).
 *  Source: RFC 3046 Section 2.0 */
#define SUBOPT_CIRCUIT_ID        1

/** @brief Relay Agent Suboption 2: Remote ID  
 *  Identifies the remote host (customer endpoint) at the far end of the circuit.
 *  Typically contains subscriber identifier, MAC address, or device serial number.
 *  Enables per-subscriber policy and billing.
 *  Source: RFC 3046 Section 2.0 */
#define SUBOPT_REMOTE_ID         2

/** @brief Relay Agent Suboption 5: Link Selection
 *  Specifies which IP subnet relay agent wants server to allocate address from.
 *  Overrides giaddr-based subnet selection. Allows explicit subnet control in
 *  complex relay topologies. Contains 4-byte IPv4 subnet address.
 *  Source: RFC 3527 */
#define SUBOPT_SUBNET_SELECT     5

/** @brief Relay Agent Suboption 6: Subscriber ID
 *  Stable subscriber identifier independent of physical location or hardware.
 *  Used by access providers for subscriber policy and billing. Format is
 *  provider-specific (typically account number or subscriber name).
 *  Source: RFC 3993 */
#define SUBOPT_SUBSCR_ID         6

/** @brief Relay Agent Suboption 10: Relay Agent Flags
 *  Bit flags indicating relay agent capabilities and request handling. Currently
 *  defined: bit 0 = unicast flag (server should unicast replies to relay).
 *  Source: RFC 5010 */
#define SUBOPT_FLAGS             10

/** @brief Relay Agent Suboption 11: Server Identifier Override
 *  Instructs server to use a different Server Identifier (Option 54) value in
 *  response than the server's actual IP. Used in load balancing and failover.
 *  Contains 4-byte IPv4 address to use as Server Identifier.
 *  Source: RFC 5107 */
#define SUBOPT_SERVER_OR         11

/** @} */ /* End of DHCPRelaySuboptions group */

/**
 * @defgroup PXESuboptions PXE Vendor-Specific Suboptions
 * @brief Suboption codes for Option 43 (Vendor-Specific) in PXE context
 * 
 * PXE (Preboot Execution Environment) network boot uses DHCP Option 43 containing
 * PXE-specific suboptions to deliver boot menu, server list, and boot parameters
 * to clients. These suboptions appear when client includes Vendor Class Identifier
 * (Option 60) starting with "PXEClient". Suboptions provide boot server discovery,
 * multi-architecture support, and user boot menu configuration.
 * 
 * PXE protocol enables diskless workstations, thin clients, and automated OS
 * deployment by delivering boot images via TFTP after DHCP configuration.
 * @{
 */

/** @brief PXE Suboption 71: Boot Item (variable length)
 *  Describes a specific boot option in PXE boot menu. Contains boot server type
 *  (2 bytes) and layer number (2 bytes). Referenced by SUBOPT_PXE_MENU entries.
 *  Used to define available boot images per architecture.
 *  Source: Intel PXE Specification 2.1 Section 2.3.1 */
#define SUBOPT_PXE_BOOT_ITEM     71

/** @brief PXE Suboption 6: PXE Discovery Control (1 byte, bit flags)
 *  Controls PXE client boot server discovery behavior. Bit 3=disable broadcast
 *  discovery, Bit 2=disable multicast discovery, Bit 1=use only boot servers
 *  from option 43, Bit 0=use acceptance proxy protocol.
 *  Source: Intel PXE Specification 2.1 Section 2.3.5 */
#define SUBOPT_PXE_DISCOVERY     6

/** @brief PXE Suboption 8: PXE Boot Servers (variable length)
 *  List of boot servers available for each boot server type. Format: type (2 bytes),
 *  IP count (1 byte), IP addresses (4 bytes each). Enables multi-server redundancy.
 *  Source: Intel PXE Specification 2.1 Section 2.3.7 */
#define SUBOPT_PXE_SERVERS       8

/** @brief PXE Suboption 9: PXE Boot Menu (variable length)
 *  Defines user-selectable boot menu entries. Format: type (2 bytes), description
 *  length (1 byte), description text. Each entry corresponds to a boot item type.
 *  Client displays menu for user selection at boot time.
 *  Source: Intel PXE Specification 2.1 Section 2.3.8 */
#define SUBOPT_PXE_MENU          9

/** @brief PXE Suboption 10: PXE Boot Menu Prompt (variable length)
 *  Configures the boot menu prompt shown to user. Format: timeout (1 byte, seconds),
 *  prompt text. Timeout 0=no prompt, 255=wait indefinitely, 1-254=wait N seconds.
 *  If timeout expires without selection, client uses default boot item.
 *  Source: Intel PXE Specification 2.1 Section 2.3.9 */
#define SUBOPT_PXE_MENU_PROMPT   10

/** @} */ /* End of PXESuboptions group */

/**
 * @defgroup DHCPMessageTypes DHCP Message Type Values
 * @brief Values for DHCP Message Type option (Option 53) - REQUIRED in all DHCP messages
 * 
 * The DHCP Message Type option (code 53) MUST appear in every DHCP message and
 * identifies which protocol state machine message is being sent. These message
 * types implement the DHCPv4 protocol exchange defined in RFC 2131.
 * 
 * Standard four-message exchange for address allocation:
 * 1. DHCPDISCOVER (client broadcasts to find servers)
 * 2. DHCPOFFER (servers unicast offers with available addresses)
 * 3. DHCPREQUEST (client broadcasts acceptance of specific offer)
 * 4. DHCPACK (selected server unicasts acknowledgment confirming lease)
 * 
 * Additional messages support lease renewal, release, conflict notification,
 * and configuration-only requests. DHCPLEASEQUERY messages (10-13) enable
 * external systems to query lease database state.
 * 
 * Per RFC 2131 Section 3.1: "The 'DHCP message type' option MUST be included
 * in every DHCP message."
 * @{
 */

/** @brief DHCP Message Type 1: DHCPDISCOVER
 *  Client broadcasts to locate available DHCP servers and discover offered
 *  network configuration. First message in four-way address allocation exchange.
 *  Contains requested options (55) and may suggest IP address (50).
 *  Broadcast to 255.255.255.255 from 0.0.0.0 before client has IP address.
 *  Source: RFC 2131 Section 3.1, Table 4 */
#define DHCPDISCOVER             1

/** @brief DHCP Message Type 2: DHCPOFFER
 *  Server unicasts or broadcasts offer of IP address and configuration to client.
 *  Response to DHCPDISCOVER. Contains offered IP (yiaddr), lease time (51),
 *  server identifier (54), and requested configuration parameters.
 *  Multiple servers may send offers; client selects one.
 *  Source: RFC 2131 Section 3.1, Table 4 */
#define DHCPOFFER                2

/** @brief DHCP Message Type 3: DHCPREQUEST
 *  Client broadcasts acceptance of server's offer (after DHCPOFFER), requests
 *  renewal of existing lease (during RENEWING state), or confirms configuration
 *  after reboot. Includes server identifier (54) to indicate which server's
 *  offer is accepted. MUST include requested IP address (50) in some scenarios.
 *  Source: RFC 2131 Section 3.1, Table 4 */
#define DHCPREQUEST              3

/** @brief DHCP Message Type 4: DHCPDECLINE
 *  Client notifies server that offered address is already in use on network
 *  (detected via ARP probe). Server MUST NOT allocate declined address to
 *  another client for minimum time period. Client restarts discovery process.
 *  Source: RFC 2131 Section 3.1, Table 4 */
#define DHCPDECLINE              4

/** @brief DHCP Message Type 5: DHCPACK
 *  Server acknowledges and confirms client's address allocation or renewal request.
 *  Final message in successful four-way exchange (after DHCPREQUEST). Contains
 *  allocated IP (yiaddr), lease time (51), and complete network configuration.
 *  Client enters BOUND state and configures interface.
 *  Source: RFC 2131 Section 3.1, Table 4 */
#define DHCPACK                  5

/** @brief DHCP Message Type 6: DHCPNAK
 *  Server rejects client's DHCPREQUEST. Sent when requested address is not
 *  available, not appropriate for network, or lease has expired. Client MUST
 *  stop using address and return to initialization (DHCPDISCOVER) state.
 *  Source: RFC 2131 Section 3.1, Table 4 */
#define DHCPNAK                  6

/** @brief DHCP Message Type 7: DHCPRELEASE
 *  Client notifies server it is releasing and relinquishing assigned IP address.
 *  Sent when client gracefully shuts down or no longer needs address. Server
 *  marks address available for reallocation. Unicast to server identifier (54).
 *  Source: RFC 2131 Section 3.1, Table 4 */
#define DHCPRELEASE              7

/** @brief DHCP Message Type 8: DHCPINFORM
 *  Client requests local configuration parameters but already has externally
 *  configured IP address. Used when client has static IP but wants DHCP-provided
 *  configuration (DNS servers, domain name, etc.). Server responds with DHCPACK
 *  containing configuration but no address assignment.
 *  Source: RFC 2131 Section 3.4 */
#define DHCPINFORM               8

/** @brief DHCP Message Type 9: DHCPFORCERENEW
 *  Server instructs client to renew lease immediately. Enables server to
 *  reconfigure clients, force rebinding, or prepare for server maintenance.
 *  Client MUST enter RENEWING state and send DHCPREQUEST.
 *  Requires authentication per RFC 3203.
 *  Source: RFC 3203 Section 4 */
#define DHCPFORCERENEW           9

/** @brief DHCP Message Type 10: DHCPLEASEQUERY
 *  External query to DHCP server requesting lease information for specific
 *  IP address, MAC address, or client identifier. Enables external lease
 *  database synchronization, troubleshooting, and network management integration.
 *  Server responds with DHCPLEASEACTIVE, DHCPLEASEUNKNOWN, or DHCPLEASEUNASSIGNED.
 *  Source: RFC 4388 Section 6.1 */
#define DHCPLEASEQUERY          10

/** @brief DHCP Message Type 11: DHCPLEASEUNASSIGNED
 *  Server response to DHCPLEASEQUERY indicating queried IP address exists in
 *  server's address pool but is not currently assigned to any client.
 *  Means address is available for allocation.
 *  Source: RFC 4388 Section 6.2.1 */
#define DHCPLEASEUNASSIGNED     11

/** @brief DHCP Message Type 12: DHCPLEASEUNKNOWN
 *  Server response to DHCPLEASEQUERY indicating queried IP address is not
 *  within server's authority or address pools. Server has no information
 *  about the queried address.
 *  Source: RFC 4388 Section 6.2.2 */
#define DHCPLEASEUNKNOWN        12

/** @brief DHCP Message Type 13: DHCPLEASEACTIVE
 *  Server response to DHCPLEASEQUERY indicating queried address is currently
 *  leased to a client. Response includes lease information: client hardware
 *  address, client identifier, lease expiration time, hostname (if known).
 *  Source: RFC 4388 Section 6.2.3 */
#define DHCPLEASEACTIVE         13

/** @} */ /* End of DHCPMessageTypes group */

/**
 * @defgroup VendorEnterprise Vendor Enterprise Numbers
 * @brief IANA-assigned enterprise numbers for vendor-specific extensions
 * @{
 */

/** @brief IANA enterprise number for Broadband Forum (formerly DSL Forum)
 *  Used in OPTION_VENDOR_IDENT (124) and OPTION_VENDOR_IDENT_OPT (125) to
 *  identify Broadband Forum vendor-specific data. Broadband Forum develops
 *  standards for broadband network architectures, including TR-069 CWMP,
 *  TR-101 migration to Ethernet, and TR-111 DHCP options.
 *  IANA registry: https://www.iana.org/assignments/enterprise-numbers/
 *  Source: IANA Private Enterprise Numbers registry */
#define BRDBAND_FORUM_IANA       3561

/** @} */ /* End of VendorEnterprise group */

/**
 * @defgroup PacketStructure DHCP Packet Wire Format Structure
 * @brief DHCPv4 packet structure definition matching RFC 2131 wire format
 * @{
 */

/** @brief Maximum hardware address length in DHCP packet
 *  
 *  RFC 2131 specifies the client hardware address field (chaddr) as 16 octets.
 *  While Ethernet MAC addresses are 6 octets, the larger field accommodates
 *  other hardware types with longer addresses. Unused bytes are zero-padded.
 *  
 *  For Ethernet (htype=1), only first 6 bytes are used (per hlen=6).
 *  Source: RFC 2131 Section 2, Figure 1 */
#define DHCP_CHADDR_MAX 16

/**
 * @struct dhcp_packet
 * @brief DHCPv4 packet wire format structure per RFC 2131 Section 2
 * 
 * This structure defines the exact wire format for DHCPv4 packets transmitted
 * over UDP (ports 67/68). The structure matches the RFC 2131 specification
 * byte-for-byte, ensuring correct serialization and deserialization of network
 * packets without requiring manual packing.
 * 
 * PACKET FORMAT:
 * The packet begins with a 236-byte fixed-format section (op through file fields)
 * followed by a variable-length options field. The options field MUST begin with
 * the 4-byte DHCP magic cookie (0x63825363) to distinguish DHCP packets from
 * legacy BOOTP packets, followed by option data in tag-length-value format.
 * 
 * USAGE PATTERN:
 * Incoming packets are read directly into this structure from UDP socket receive
 * buffers. Outgoing packets are constructed by populating fields and serialized
 * directly to UDP socket send buffers. The structure is typically stack-allocated
 * during packet processing to avoid heap overhead.
 * 
 * LIFECYCLE:
 * Creation: Stack-allocated in packet processing functions (receive_query, dhcp_reply)
 * Initialization: Fields zero-initialized or populated from received packet data
 * Destruction: Automatic when stack frame exits (no explicit cleanup required)
 * Ownership: Local to packet processing function scope
 * 
 * MEMORY LAYOUT:
 * Size: 548 bytes total (236 fixed header + 312 options field)
 * Alignment: Natural alignment for multi-byte fields (u16, u32, struct in_addr)
 * Padding: None required; fields naturally aligned for network byte order
 * 
 * PROTOCOL COMPLIANCE:
 * RFC 2131 Section 2: DHCP packet format specification
 * RFC 951: BOOTP protocol (legacy compatibility for op, htype, hlen, hops fields)
 * RFC 2132: DHCP options field format and encoding
 * 
 * INTEGRATION:
 * Used by: src/dhcp.c (packet parsing and construction)
 *          src/rfc2131.c (protocol state machine packet handling)
 *          src/dhcp-common.c (option parsing and validation)
 *          src/network.c (UDP socket I/O operations)
 */
struct dhcp_packet {
  /** @brief Operation code: message type (1=BOOTREQUEST from client, 2=BOOTREPLY from server)
   *  
   *  BOOTREQUEST (1): Client-to-server messages (DHCPDISCOVER, DHCPREQUEST, 
   *                   DHCPDECLINE, DHCPRELEASE, DHCPINFORM, DHCPLEASEQUERY)
   *  BOOTREPLY (2):   Server-to-client messages (DHCPOFFER, DHCPACK, DHCPNAK,
   *                   DHCPLEASEACTIVE, DHCPLEASEUNKNOWN, DHCPLEASEUNASSIGNED)
   *  
   *  Source: RFC 2131 Section 2, RFC 951 Section 3 */
  u8 op;
  
  /** @brief Hardware address type (per ARP protocol, RFC 826)
   *  
   *  Common values:
   *  1 = Ethernet (10Mb)
   *  6 = IEEE 802 Networks (Token Ring, FDDI)
   *  7 = ARCNET
   *  
   *  For Ethernet networks (overwhelming majority), htype=1.
   *  Full list: IANA ARP Hardware Types registry.
   *  Source: RFC 2131 Section 2, RFC 1700 (ARP Hardware Types) */
  u8 htype;
  
  /** @brief Hardware address length in octets (6 for Ethernet MAC addresses)
   *  
   *  Specifies actual length of hardware address in chaddr field.
   *  For Ethernet: hlen=6 (48-bit MAC address)
   *  For other hardware types: varies by hardware addressing scheme
   *  
   *  Server uses hlen to determine how many bytes of chaddr contain
   *  valid hardware address (remaining bytes ignored/zero-padded).
   *  Source: RFC 2131 Section 2 */
  u8 hlen;
  
  /** @brief Relay agent hop count (incremented by each relay agent)
   *  
   *  Set to 0 by client. Each DHCP relay agent increments hops when
   *  forwarding request to next server. Prevents infinite relay loops
   *  (servers may discard packets with hops exceeding configured maximum).
   *  
   *  Used in multi-subnet networks where relay agents forward DHCP
   *  broadcasts between network segments.
   *  Source: RFC 2131 Section 2, RFC 1542 Section 4.1.1 */
  u8 hops;
  
  /** @brief Transaction ID: random number chosen by client for request/response matching
   *  
   *  Client selects random 32-bit value at beginning of transaction.
   *  All messages in transaction (DISCOVER->OFFER->REQUEST->ACK) use
   *  same xid to match responses to requests. Server copies xid from
   *  request to response unchanged.
   *  
   *  Provides transaction identity when multiple clients share same
   *  hardware address or when client retransmits due to timeout.
   *  Source: RFC 2131 Section 2, Section 4.1 */
  u32 xid;
  
  /** @brief Seconds elapsed since client began address acquisition or renewal process
   *  
   *  Filled in by client. Starts at 0 when address acquisition begins.
   *  Client increments secs in subsequent retransmissions if no response
   *  received. Servers may use secs to prioritize responses to clients
   *  that have been waiting longer.
   *  
   *  Network byte order (big-endian). Range: 0-65535 seconds (~18 hours).
   *  Source: RFC 2131 Section 2, Section 4.4.1 */
  u16 secs;
  
  /** @brief Flags field (bit 0x8000: broadcast flag, bits 0x7FFF: reserved/unused)
   *  
   *  BROADCAST FLAG (0x8000): Set by client if unable to receive unicast
   *  IP datagrams before IP address configured (typically clients without
   *  ARP support or systems that drop unicast until interface configured).
   *  When set, server broadcasts DHCPOFFER and DHCPACK to 255.255.255.255
   *  instead of unicasting to yiaddr.
   *  
   *  Remaining bits (0x7FFF): Reserved for future use, MUST be zero.
   *  Network byte order (big-endian).
   *  Source: RFC 2131 Section 2, Section 4.1 */
  u16 flags;
  
  /** @brief Client IP address: filled by client if already has address, else zero
   *  
   *  Used by client in RENEWING, REBINDING, or BOUND states when client
   *  already has valid IP address. Set to client's current IP address in
   *  DHCPREQUEST during renewal or in DHCPINFORM when client has static IP.
   *  
   *  Set to 0.0.0.0 in DHCPDISCOVER and initial DHCPREQUEST (selecting state).
   *  Server copies ciaddr to ACK/NAK when responding to renewal requests.
   *  Source: RFC 2131 Section 2, Section 4.3.2 */
  struct in_addr ciaddr;
  
  /** @brief Your (client) IP address: filled by server with offered/assigned address
   *  
   *  Server fills with offered IP address in DHCPOFFER and allocated IP
   *  address in DHCPACK. Set to 0.0.0.0 in DHCPNAK, DHCPLEASEQUERY responses,
   *  and client-originated messages.
   *  
   *  This is the address the client should configure on its network interface
   *  after receiving DHCPACK. In DHCPINFORM response, server leaves yiaddr=0
   *  since client already has configured address.
   *  Source: RFC 2131 Section 2, Section 3.1 */
  struct in_addr yiaddr;
  
  /** @brief Server IP address: next server to use in bootstrap process
   *  
   *  Returned by server in DHCPOFFER and DHCPACK. If client needs to contact
   *  additional servers for bootstrap (e.g., TFTP server for network boot),
   *  siaddr specifies that server's IP address. For TFTP boot, siaddr identifies
   *  TFTP server; client sends TFTP read requests to this address.
   *  
   *  Set to 0.0.0.0 if not used (no bootstrap server required).
   *  Source: RFC 2131 Section 2, RFC 951 Section 3 */
  struct in_addr siaddr;
  
  /** @brief Relay agent IP address: filled by relay agent, else zero
   *  
   *  Set by DHCP relay agent to its own IP address when forwarding client
   *  request to server. Server uses giaddr to determine subnet for address
   *  allocation and to identify return path for response (server unicasts
   *  response to giaddr instead of client).
   *  
   *  Set to 0.0.0.0 by client. If giaddr is nonzero, server knows request
   *  was relayed and responds accordingly per RFC 1542.
   *  Source: RFC 2131 Section 2, RFC 1542 Section 4.1 */
  struct in_addr giaddr;
  
  /** @brief Client hardware address (MAC address for Ethernet, zero-padded to 16 bytes)
   *  
   *  Client's hardware address used for address-to-hardware binding. For
   *  Ethernet (htype=1, hlen=6), first 6 bytes contain MAC address, remaining
   *  10 bytes zero-padded. Server uses chaddr for lease identification, ARP
   *  cache updates, and unicast response addressing.
   *  
   *  Set by client to its own hardware address. Relay agents preserve chaddr
   *  unchanged when forwarding. Server uses chaddr to identify client across
   *  transactions and to send unicast responses at link layer.
   *  Source: RFC 2131 Section 2, Section 4.2 */
  u8 chaddr[DHCP_CHADDR_MAX];
  
  /** @brief Server host name: optional null-terminated string (64 bytes)
   *  
   *  Optional server host name for bootstrap. Server may place its DNS name
   *  in sname field in DHCPOFFER/DHCPACK to inform client which server
   *  responded. Null-terminated C string; unused bytes should be zero.
   *  
   *  May be overloaded with DHCP options when options field insufficient
   *  (see OPTION_OVERLOAD). Legacy BOOTP clients expect sname for boot
   *  server identification.
   *  Source: RFC 2131 Section 2, RFC 951 Section 3 */
  u8 sname[64];
  
  /** @brief Boot file name: null-terminated string with boot file path (128 bytes)
   *  
   *  Fully qualified directory path to boot file for diskless workstations.
   *  Used with siaddr to locate network boot image. For PXE boot, file
   *  contains path to boot loader (e.g., "pxelinux.0"). Null-terminated;
   *  unused bytes zero.
   *  
   *  May be overloaded with DHCP options when options field insufficient
   *  (see OPTION_OVERLOAD). Can be specified per RFC 2132 Option 67.
   *  Source: RFC 2131 Section 2, RFC 951 Section 3 */
  u8 file[128];
  
  /** @brief DHCP options field: variable-length options in TLV format (312 bytes)
   *  
   *  Variable-length field containing DHCP options. MUST begin with 4-byte
   *  magic cookie (0x63825363) to distinguish DHCP from BOOTP packets.
   *  Following magic cookie, options encoded in tag-length-value format:
   *  - Tag: 1-byte option code (see OPTION_* constants)
   *  - Length: 1-byte length of value field (0-255)
   *  - Value: Variable-length option data
   *  
   *  Special options: OPTION_PAD (0) for alignment, OPTION_END (255) marks
   *  end of options. If 312 bytes insufficient, sname and file fields may
   *  be used via OPTION_OVERLOAD.
   *  
   *  Required options per message type documented in RFC 2131 Section 3.
   *  All messages MUST include OPTION_MESSAGE_TYPE (53).
   *  Source: RFC 2131 Section 2, Section 4, RFC 2132 */
  u8 options[312];
};

/** @} */ /* End of PacketStructure group */

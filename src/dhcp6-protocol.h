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
 * @file dhcp6-protocol.h
 * @brief DHCPv6 protocol constants and message type definitions per RFC 3315
 * 
 * DETAILED PURPOSE:
 * This header file serves as the definitive source for all DHCPv6 protocol constants,
 * message types, option numbers, status codes, and DUID (DHCP Unique Identifier) types
 * as defined in RFC 3315 (Dynamic Host Configuration Protocol for IPv6) and related
 * DHCPv6 extension RFCs. It provides the protocol-level definitions required for
 * DHCPv6 packet construction, parsing, and validation across the dnsmasq DHCPv6
 * implementation.
 * 
 * This file defines the wire protocol constants used by the DHCPv6 server to implement
 * both stateful address assignment (where the server assigns and tracks IPv6 addresses)
 * and stateless configuration (where the server provides configuration parameters but
 * clients use SLAAC for address assignment). The constants enable protocol-compliant
 * message exchange patterns including SOLICIT-ADVERTISE-REQUEST-REPLY for stateful
 * operation and INFORMATION-REQUEST-REPLY for stateless operation.
 * 
 * KEY RESPONSIBILITIES:
 * - Define DHCPv6 UDP port numbers (server port 547, client port 546) per RFC 3315 Section 5.2
 * - Define IPv6 multicast addresses for DHCPv6 communication (All_DHCP_Relay_Agents_and_Servers, All_DHCP_Servers)
 * - Define DHCPv6 message types (SOLICIT, ADVERTISE, REQUEST, REPLY, RENEW, REBIND, etc.) per RFC 3315 Section 5.3
 * - Define DHCPv6 option numbers for identity, addressing, configuration, and relay options per RFC 3315 Section 22
 * - Define Identity Association (IA) types: IA_NA (non-temporary addresses), IA_TA (temporary addresses), IA_PD (prefix delegation)
 * - Define DHCPv6 status codes (SUCCESS, UNSPEC, NOADDRS, NOBINDING, etc.) per RFC 3315 Section 24.4
 * - Define NTP server option suboptions per RFC 5908
 * - Provide protocol constants for DHCPv6 relay agent functionality
 * 
 * DEPENDENCIES:
 * Includes: None (pure constant definitions, no external headers required)
 * Called by: src/dhcp6.c (DHCPv6 server packet processing)
 *            src/rfc3315.c (DHCPv6 protocol implementation per RFC 3315)
 *            src/outpacket.c (DHCPv6 option serialization and packet construction)
 * Calls: None (header file with constant definitions only)
 * 
 * DATA STRUCTURES:
 * This header defines protocol constants only, not data structures. The actual DHCPv6
 * message structure consists of:
 * - 1-byte message type (values defined as DHCP6SOLICIT, DHCP6ADVERTISE, etc.)
 * - 3-byte transaction ID
 * - Variable-length options (option code, option length, option data)
 * 
 * DHCPv6 options follow Type-Length-Value (TLV) encoding:
 * - 2-byte option code (values defined as OPTION6_CLIENT_ID, OPTION6_IA_NA, etc.)
 * - 2-byte option length (big-endian, excludes the 4-byte option header)
 * - Variable-length option data
 * 
 * COMPILE-TIME OPTIONS:
 * This header is included when HAVE_DHCP6 is defined, which enables DHCPv6 server
 * functionality. DHCPv6 support requires HAVE_DHCP to be defined as well since
 * DHCPv6 builds upon common DHCP infrastructure.
 * 
 * THREADING/CONCURRENCY:
 * Single-process event-driven model. Constants defined in this header are read-only
 * and accessed by the main event loop when processing DHCPv6 packets. No locking
 * required as constants are immutable.
 * 
 * RFC COMPLIANCE:
 * RFC 3315: Dynamic Host Configuration Protocol for IPv6 (DHCPv6) - primary specification
 * RFC 3633: IPv6 Prefix Options for DHCPv6 (IA_PD, IAPREFIX options)
 * RFC 5908: Network Time Protocol (NTP) Server Option for DHCPv6 (NTP_SERVER option and suboptions)
 * RFC 8520: Manufacturer Usage Description Specification (MUD_URL option)
 * 
 * INTEGRATION NOTES:
 * - src/dhcp6.c uses these constants to identify message types, parse options, and construct responses
 * - src/rfc3315.c implements the DHCPv6 state machine and message exchange patterns using these message types
 * - src/outpacket.c uses option constants when serializing DHCPv6 options into wire format
 * - The DHCPv6 server coordinates with Router Advertisement (src/radv.c) using the M (managed) and O (other)
 *   flags to control whether clients use stateful DHCPv6, stateless DHCPv6, or SLAAC-only addressing
 * 
 * @copyright Copyright (c) 2000-2025 Simon Kelley
 * @license GPL-2.0-or-later
 */

/**
 * @brief DHCPv6 server UDP port number
 * 
 * Well-known port 547 used by DHCPv6 servers to receive client messages.
 * Clients send DHCPv6 messages (SOLICIT, REQUEST, RENEW, etc.) to this port.
 * Per RFC 3315 Section 5.2.
 */
#define DHCPV6_SERVER_PORT 547

/**
 * @brief DHCPv6 client UDP port number
 * 
 * Well-known port 546 used by DHCPv6 clients to receive server messages.
 * Servers send DHCPv6 responses (ADVERTISE, REPLY, RECONFIGURE) to this port.
 * Per RFC 3315 Section 5.2.
 */
#define DHCPV6_CLIENT_PORT 546

/**
 * @brief All_DHCP_Servers multicast address (site-local scope)
 * 
 * IPv6 multicast address FF05::1:3 used by DHCPv6 clients to communicate with
 * DHCPv6 servers when the client knows the site-local scope is appropriate.
 * Site-local scope (FF05) means the multicast is limited to the local site.
 * Per RFC 3315 Section 5.1.
 */
#define ALL_SERVERS                  "FF05::1:3"

/**
 * @brief All_DHCP_Relay_Agents_and_Servers multicast address (link-local scope)
 * 
 * IPv6 multicast address FF02::1:2 used by DHCPv6 clients to communicate with
 * DHCPv6 relay agents and servers on the local link. Link-local scope (FF02)
 * means the multicast does not traverse routers. This is the most commonly used
 * multicast address for initial DHCPv6 client requests (SOLICIT).
 * Per RFC 3315 Section 5.1.
 */
#define ALL_RELAY_AGENTS_AND_SERVERS "FF02::1:2"

/**
 * @brief SOLICIT message type (1)
 * 
 * Client-to-server message initiating DHCPv6 exchange. Client multicasts SOLICIT
 * to locate available DHCPv6 servers and request addresses and/or configuration.
 * Used in both stateful (address assignment) and stateless (configuration only) modes.
 * Servers respond with ADVERTISE messages.
 * Per RFC 3315 Section 17.1.1.
 */
#define DHCP6SOLICIT      1

/**
 * @brief ADVERTISE message type (2)
 * 
 * Server-to-client message in response to SOLICIT. Server advertises availability
 * and proposed addresses/configuration. Client selects one server based on
 * preference values and sends REQUEST to chosen server. In rapid commit mode,
 * ADVERTISE is skipped and server sends REPLY directly.
 * Per RFC 3315 Section 17.1.2.
 */
#define DHCP6ADVERTISE    2

/**
 * @brief REQUEST message type (3)
 * 
 * Client-to-server message requesting assignment of addresses and/or configuration
 * from a specific server (selected after receiving ADVERTISE). Server responds
 * with REPLY containing assigned addresses and configuration parameters.
 * Per RFC 3315 Section 18.1.1.
 */
#define DHCP6REQUEST      3

/**
 * @brief CONFIRM message type (4)
 * 
 * Client-to-server message asking server to verify that client's assigned addresses
 * are still appropriate for the link to which the client is attached. Used when
 * client may have moved to a different link. Server responds with REPLY containing
 * status code indicating whether addresses are on-link or not.
 * Per RFC 3315 Section 18.1.2.
 */
#define DHCP6CONFIRM      4

/**
 * @brief RENEW message type (5)
 * 
 * Client-to-server message sent to the server that originally provided addresses
 * to extend the lifetimes of assigned addresses. Sent when T1 timer (typically 50%
 * of preferred lifetime) expires. Server responds with REPLY extending lifetimes
 * or indicating addresses are no longer valid.
 * Per RFC 3315 Section 18.1.3.
 */
#define DHCP6RENEW        5

/**
 * @brief REBIND message type (6)
 * 
 * Client-to-server message sent to any available server (multicast) to extend
 * lifetimes of addresses when original server is unreachable. Sent when T2 timer
 * (typically 80% of preferred lifetime) expires and RENEW has failed. Any server
 * can respond with REPLY.
 * Per RFC 3315 Section 18.1.4.
 */
#define DHCP6REBIND       6

/**
 * @brief REPLY message type (7)
 * 
 * Server-to-client message containing assigned addresses, configuration parameters,
 * or status information in response to SOLICIT (rapid commit), REQUEST, RENEW,
 * REBIND, CONFIRM, RELEASE, DECLINE, or INFORMATION-REQUEST. The REPLY contents
 * depend on the message type being responded to.
 * Per RFC 3315 Sections 18.2.1-18.2.8.
 */
#define DHCP6REPLY        7

/**
 * @brief RELEASE message type (8)
 * 
 * Client-to-server message indicating client no longer needs one or more assigned
 * addresses. Client is relinquishing addresses before their lifetimes expire.
 * Server responds with REPLY and may reuse the released addresses for other clients.
 * Per RFC 3315 Section 18.1.6.
 */
#define DHCP6RELEASE      8

/**
 * @brief DECLINE message type (9)
 * 
 * Client-to-server message indicating one or more assigned addresses are already
 * in use on the link (duplicate address detected). Client performed Duplicate
 * Address Detection (DAD) and found conflict. Server responds with REPLY and
 * marks addresses as unavailable.
 * Per RFC 3315 Section 18.1.7.
 */
#define DHCP6DECLINE      9

/**
 * @brief RECONFIGURE message type (10)
 * 
 * Server-to-client message telling client to initiate a RENEW/REPLY or
 * INFORMATION-REQUEST/REPLY transaction with the server. Allows server to
 * proactively update client configuration. Client must have accepted
 * Reconfigure Accept option (OPTION6_RECONF_ACCEPT) to process this message.
 * Per RFC 3315 Section 19.1.1.
 */
#define DHCP6RECONFIGURE  10

/**
 * @brief INFORMATION-REQUEST message type (11)
 * 
 * Client-to-server message requesting only configuration parameters without
 * address assignment (stateless DHCPv6). Used when client has SLAAC address
 * or static address but needs DNS servers, NTP servers, or other configuration.
 * Server responds with REPLY containing requested configuration.
 * Per RFC 3315 Section 18.1.5.
 */
#define DHCP6IREQ         11

/**
 * @brief RELAY-FORW message type (12)
 * 
 * Relay agent-to-server message encapsulating client message for forwarding
 * to DHCPv6 server on different link. Relay agents add relay options containing
 * interface ID, link address, and peer address. Supports multi-hop relay chains.
 * Server extracts client message and sends RELAY-REPL back through relay chain.
 * Per RFC 3315 Section 20.1.1.
 */
#define DHCP6RELAYFORW    12

/**
 * @brief RELAY-REPL message type (13)
 * 
 * Server-to-relay message containing server's reply to client, encapsulated
 * for forwarding by relay agent back to client. Relay agent extracts reply
 * and forwards to client. Supports multi-hop relay chains with each relay
 * decapsulating one layer.
 * Per RFC 3315 Section 20.1.2.
 */
#define DHCP6RELAYREPL    13

/**
 * @brief Client Identifier option (1)
 * 
 * Contains client DUID (DHCP Unique Identifier) used to identify client across
 * network changes. DUID must be stable across reboots. DUID types include:
 * DUID-LLT (link-layer address + time), DUID-EN (enterprise number),
 * DUID-LL (link-layer address). Required in most client messages.
 * Per RFC 3315 Section 22.2.
 */
#define OPTION6_CLIENT_ID       1

/**
 * @brief Server Identifier option (2)
 * 
 * Contains server DUID used to identify DHCPv6 server. Sent by server in
 * ADVERTISE and REPLY messages. Client includes server DUID in REQUEST,
 * RENEW, RELEASE, and DECLINE to identify target server.
 * Per RFC 3315 Section 22.3.
 */
#define OPTION6_SERVER_ID       2

/**
 * @brief Identity Association for Non-temporary Addresses option (3)
 * 
 * IA_NA contains non-temporary IPv6 addresses assigned to client. Includes
 * IAID (Identity Association Identifier), T1 timer (renewal time), T2 timer
 * (rebind time), and encapsulated IAADDR options. Used for stateful DHCPv6
 * address assignment. An IA_NA can contain multiple addresses.
 * Per RFC 3315 Section 22.4.
 */
#define OPTION6_IA_NA           3

/**
 * @brief Identity Association for Temporary Addresses option (4)
 * 
 * IA_TA contains temporary IPv6 addresses for privacy (similar to IPv6 privacy
 * extensions). Temporary addresses are used for outbound connections to prevent
 * address-based tracking. Contains IAID and encapsulated IAADDR options.
 * No T1/T2 timers as temporary addresses are not renewed.
 * Per RFC 3315 Section 22.5.
 */
#define OPTION6_IA_TA           4

/**
 * @brief IA Address option (5)
 * 
 * Encapsulated within IA_NA or IA_TA options. Contains single IPv6 address,
 * preferred lifetime, and valid lifetime. Preferred lifetime indicates when
 * address should not be used for new connections. Valid lifetime indicates
 * when address is completely invalid.
 * Per RFC 3315 Section 22.6.
 */
#define OPTION6_IAADDR          5

/**
 * @brief Option Request Option (6)
 * 
 * ORO contains list of option codes client is requesting server to provide.
 * Client includes ORO in SOLICIT, REQUEST, RENEW, REBIND, and INFORMATION-REQUEST
 * to indicate which configuration parameters it wants (DNS servers, NTP servers,
 * domain search list, etc.). Server includes requested options in REPLY.
 * Per RFC 3315 Section 22.7.
 */
#define OPTION6_ORO             6

/**
 * @brief Preference option (7)
 * 
 * 8-bit value (0-255) in ADVERTISE message indicating server preference.
 * Client selects server with highest preference value. Value 255 means
 * server is immediately acceptable (client should not wait for other
 * ADVERTISE messages). Used when multiple servers are available.
 * Per RFC 3315 Section 22.8.
 */
#define OPTION6_PREFERENCE      7

/**
 * @brief Elapsed Time option (8)
 * 
 * 16-bit value in hundredths of a second indicating how long client has been
 * trying to complete current DHCPv6 message exchange. Sent in client messages.
 * Allows servers and relays to prioritize clients that have been waiting longer.
 * Value 0xFFFF indicates 655.35+ seconds.
 * Per RFC 3315 Section 22.9.
 */
#define OPTION6_ELAPSED_TIME    8

/**
 * @brief Relay Message option (9)
 * 
 * Encapsulates client or server message within RELAY-FORW or RELAY-REPL message.
 * Contains complete client-server DHCPv6 message. Relay agents add relay options
 * (interface ID, peer address, remote ID) alongside relay message option.
 * Supports nested encapsulation for multi-hop relay chains.
 * Per RFC 3315 Section 22.10.
 */
#define OPTION6_RELAY_MSG       9

/**
 * @brief Authentication option (11)
 * 
 * Provides message authentication using various protocols (delayed authentication,
 * reconfigure key authentication). Contains protocol type, algorithm, replay
 * detection method, and authentication information. Used to prevent spoofing
 * and man-in-the-middle attacks. Primarily for RECONFIGURE message security.
 * Per RFC 3315 Section 22.11.
 */
#define OPTION6_AUTH            11

/**
 * @brief Server Unicast option (12)
 * 
 * Contains IPv6 address for direct unicast communication with server. Normally
 * clients multicast to All_DHCP_Relay_Agents_and_Servers. If server sends
 * Server Unicast option, client may send subsequent messages (RENEW, INFORMATION-REQUEST)
 * directly to server's unicast address for efficiency.
 * Per RFC 3315 Section 22.12.
 */
#define OPTION6_UNICAST         12

/**
 * @brief Status Code option (13)
 * 
 * Indicates success or reason for failure. Contains numeric status code
 * (DHCP6SUCCESS=0, DHCP6UNSPEC=1, DHCP6NOADDRS=2, DHCP6NOBINDING=3, etc.)
 * and UTF-8 status message for human consumption. Can appear in REPLY at
 * top level or encapsulated within IA_NA/IA_TA/IAADDR for per-address status.
 * Per RFC 3315 Section 22.13.
 */
#define OPTION6_STATUS_CODE     13

/**
 * @brief Rapid Commit option (14)
 * 
 * Enables two-message exchange (SOLICIT/REPLY) instead of four-message
 * (SOLICIT/ADVERTISE/REQUEST/REPLY). Client includes option in SOLICIT to
 * indicate rapid commit support. Server includes option in REPLY (skipping
 * ADVERTISE) if rapid commit accepted. Reduces latency for address assignment.
 * Per RFC 3315 Section 22.14.
 */
#define OPTION6_RAPID_COMMIT    14

/**
 * @brief User Class option (15)
 * 
 * Contains one or more opaque fields identifying user class of client.
 * Allows administrator to classify clients and provide class-specific
 * configuration. Server matches user class to configuration policies.
 * Similar to DHCPv4 option 77.
 * Per RFC 3315 Section 22.15.
 */
#define OPTION6_USER_CLASS      15

/**
 * @brief Vendor Class option (16)
 * 
 * Contains enterprise number and one or more opaque fields identifying
 * vendor-specific client class. Allows vendor-specific client identification
 * and configuration. Enterprise numbers assigned by IANA.
 * Per RFC 3315 Section 22.16.
 */
#define OPTION6_VENDOR_CLASS    16

/**
 * @brief Vendor-specific Information option (17)
 * 
 * Contains enterprise number and vendor-specific options. Allows vendors
 * to define custom options for proprietary features. Enterprise number
 * identifies vendor. Option data format defined by vendor.
 * Per RFC 3315 Section 22.17.
 */
#define OPTION6_VENDOR_OPTS     17

/**
 * @brief Interface-Id option (18)
 * 
 * Inserted by relay agent to identify interface on which client message
 * was received. Opaque value meaningful only to relay agent. Server copies
 * option into RELAY-REPL so relay can forward reply to correct interface.
 * Required for relay agents receiving messages on multiple interfaces.
 * Per RFC 3315 Section 22.18.
 */
#define OPTION6_INTERFACE_ID    18

/**
 * @brief Reconfigure Message option (19)
 * 
 * Sent in RECONFIGURE message to tell client what type of response is desired:
 * RENEW (5) for address renewal, or INFORMATION-REQUEST (11) for configuration
 * refresh. Client initiates requested message exchange.
 * Per RFC 3315 Section 22.19.
 */
#define OPTION6_RECONFIGURE_MSG 19

/**
 * @brief Reconfigure Accept option (20)
 * 
 * Client includes this option in SOLICIT, REQUEST, RENEW, or REBIND to
 * indicate willingness to accept RECONFIGURE messages from server. Without
 * this option, server must not send RECONFIGURE to client. Allows client
 * to opt-in to server-initiated reconfiguration.
 * Per RFC 3315 Section 22.20.
 */
#define OPTION6_RECONF_ACCEPT   20

/**
 * @brief DNS Recursive Name Server option (23)
 * 
 * Contains one or more IPv6 addresses of recursive DNS servers available
 * to client. Client configures resolver to use these servers. Essential
 * for network connectivity. Commonly requested in INFORMATION-REQUEST
 * for stateless DHCPv6.
 * Per RFC 3646 Section 3.
 */
#define OPTION6_DNS_SERVER      23

/**
 * @brief Domain Search List option (24)
 * 
 * Contains list of domain names forming DNS search list for hostname
 * resolution. When resolving non-fully-qualified hostnames, client appends
 * search domains. Encoded as sequence of domain names in DNS wire format.
 * Per RFC 3646 Section 4.
 */
#define OPTION6_DOMAIN_SEARCH   24

/**
 * @brief Identity Association for Prefix Delegation option (25)
 * 
 * IA_PD used for IPv6 prefix delegation to requesting routers. Contains IAID,
 * T1, T2 timers, and encapsulated IAPREFIX options. Requesting router receives
 * IPv6 prefix(es) to assign addresses on downstream networks. Essential for
 * hierarchical IPv6 addressing.
 * Per RFC 3633 Section 9.
 */
#define OPTION6_IA_PD           25

/**
 * @brief IA Prefix option (26)
 * 
 * Encapsulated within IA_PD. Contains delegated IPv6 prefix, prefix length,
 * preferred lifetime, and valid lifetime. Delegating router assigns prefix
 * to requesting router. Requesting router assigns addresses from prefix to
 * downstream clients.
 * Per RFC 3633 Section 10.
 */
#define OPTION6_IAPREFIX        26

/**
 * @brief Information Refresh Time option (32)
 * 
 * 32-bit value in seconds indicating how long client should wait before
 * refreshing configuration obtained via INFORMATION-REQUEST. Sent by server
 * in REPLY to INFORMATION-REQUEST. Allows server to control configuration
 * refresh rate for stateless DHCPv6.
 * Per RFC 4242 Section 3.1.
 */
#define OPTION6_REFRESH_TIME    32

/**
 * @brief Remote Identifier option (37)
 * 
 * Inserted by relay agent to identify remote host (typically enterprise number
 * and remote-id value). Allows correlation of relay agent identity with client.
 * Server can use remote-id for address assignment policies. Opaque data
 * meaningful to relay agent.
 * Per RFC 4649 Section 3.
 */
#define OPTION6_REMOTE_ID       37

/**
 * @brief Subscriber Identifier option (38)
 * 
 * Contains subscriber ID assigned by provider's operational support system.
 * Allows correlation between DHCPv6 transaction and subscriber billing/provisioning
 * record. Typically inserted by relay agent in service provider networks.
 * Per RFC 4580 Section 3.
 */
#define OPTION6_SUBSCRIBER_ID   38

/**
 * @brief Fully Qualified Domain Name option (39)
 * 
 * Allows client and server to negotiate client's FQDN and responsibility for
 * DNS updates. Contains flags (S=server performs update, O=override client,
 * N=no update) and domain name. Enables dynamic DNS updates for DHCPv6 clients.
 * Per RFC 4704 Section 4.
 */
#define OPTION6_FQDN            39

/**
 * @brief Network Time Protocol Servers option (56)
 * 
 * Provides client with NTP server information for time synchronization.
 * Contains NTP suboptions (NTP_SUBOPTION_SRV_ADDR=1 for server addresses,
 * NTP_SUBOPTION_MC_ADDR=2 for multicast addresses, NTP_SUBOPTION_SRV_FQDN=3
 * for server FQDNs). Essential for time-sensitive applications.
 * Per RFC 5908 Section 4.
 */
#define OPTION6_NTP_SERVER      56

/**
 * @brief Client Link-Layer Address option (79)
 * 
 * Contains client's link-layer address (MAC address). Useful when relay agent
 * prevents server from determining client's MAC address. Allows server to
 * use MAC address for address assignment policies or logging. Relay agent
 * can add this option if not present in client message.
 * Per RFC 6939 Section 3.
 */
#define OPTION6_CLIENT_MAC      79

/**
 * @brief Manufacturer Usage Description URL option (112)
 * 
 * Contains URL pointing to Manufacturer Usage Description (MUD) file describing
 * device's intended network communication patterns. Used for IoT device security
 * and network access control. Network can enforce MUD policy to limit device
 * communication to authorized endpoints.
 * Per RFC 8520 Section 10.
 */
#define OPTION6_MUD_URL         112

/**
 * @brief NTP Server Address suboption (1)
 * 
 * Suboption within OPTION6_NTP_SERVER containing one or more IPv6 addresses
 * of unicast NTP servers. Client should use these addresses to synchronize
 * system time. Most common NTP suboption type.
 * Per RFC 5908 Section 4.1.
 */
#define NTP_SUBOPTION_SRV_ADDR  1

/**
 * @brief NTP Multicast Address suboption (2)
 * 
 * Suboption within OPTION6_NTP_SERVER containing one or more IPv6 multicast
 * addresses for NTP multicast servers. Client listens for NTP broadcasts on
 * these multicast groups. Less common than unicast NTP.
 * Per RFC 5908 Section 4.2.
 */
#define NTP_SUBOPTION_MC_ADDR   2

/**
 * @brief NTP Server FQDN suboption (3)
 * 
 * Suboption within OPTION6_NTP_SERVER containing one or more fully qualified
 * domain names of NTP servers. Client resolves FQDNs to IPv6 addresses and
 * uses for time synchronization. Allows NTP server IP changes without DHCPv6
 * reconfiguration.
 * Per RFC 5908 Section 4.3.
 */
#define NTP_SUBOPTION_SRV_FQDN  3

/**
 * @brief Success status code (0)
 * 
 * Indicates successful operation. Sent in STATUS_CODE option within REPLY
 * message at top level or within IA_NA/IA_TA/IA_PD/IAADDR/IAPREFIX to confirm
 * successful address assignment, renewal, or release.
 * Per RFC 3315 Section 24.4.
 */
#define DHCP6SUCCESS     0

/**
 * @brief Unspecified failure status code (1)
 * 
 * Indicates failure for unspecified reason. Server encountered error but cannot
 * provide more specific status code. Client should log error and may retry or
 * attempt alternate server. Generic error status.
 * Per RFC 3315 Section 24.4.
 */
#define DHCP6UNSPEC      1

/**
 * @brief No Addresses Available status code (2)
 * 
 * Server has no addresses available to assign to client. Sent in STATUS_CODE
 * option within IA_NA or IA_TA. Client should attempt REBIND to other servers
 * or wait for address pool to have available addresses. Indicates pool exhaustion.
 * Per RFC 3315 Section 24.4.
 */
#define DHCP6NOADDRS     2

/**
 * @brief No Binding status code (3)
 * 
 * Server has no record of client binding (lease). Sent in response to RENEW,
 * REBIND, or RELEASE when client references IA (Identity Association) unknown
 * to server. Client should reinitialize DHCPv6 with SOLICIT to obtain new binding.
 * Per RFC 3315 Section 24.4.
 */
#define DHCP6NOBINDING   3

/**
 * @brief Not On Link status code (4)
 * 
 * Client's addresses are not appropriate for link to which client is attached.
 * Sent in response to CONFIRM message. Client should stop using current addresses
 * and reinitialize with SOLICIT to obtain new addresses appropriate for current link.
 * Indicates client has moved to different network segment.
 * Per RFC 3315 Section 24.4.
 */
#define DHCP6NOTONLINK   4

/**
 * @brief Use Multicast status code (5)
 * 
 * Client should use All_DHCP_Relay_Agents_and_Servers multicast address (FF02::1:2)
 * instead of unicast address. Sent when client sends unicast message but server
 * requires multicast. Client resends message to multicast address.
 * Per RFC 3315 Section 24.4.
 */
#define DHCP6USEMULTI    5

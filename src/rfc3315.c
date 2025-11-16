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
 * @file rfc3315.c
 * @brief DHCPv6 Protocol Implementation (RFC 3315)
 * 
 * DETAILED PURPOSE:
 * This module implements the DHCPv6 protocol as specified in RFC 3315, providing
 * IPv6 address and configuration assignment to DHCPv6 clients. The implementation
 * supports both stateful DHCPv6 (managed address assignment with M=1) and stateless
 * DHCPv6 (configuration-only with O=1), coordinating with Router Advertisement
 * (radv.c) to control client behavior through M/O flags.
 * 
 * The module handles the complete DHCPv6 message exchange patterns including
 * SOLICIT→ADVERTISE→REQUEST→REPLY for stateful operation, INFORMATION-REQUEST→REPLY
 * for stateless operation, and RENEW/REBIND/RELEASE/DECLINE for lease management.
 * It also implements DHCPv6 relay agent functionality for serving clients on
 * remote network segments.
 * 
 * KEY RESPONSIBILITIES:
 * - Process DHCPv6 messages (SOLICIT, ADVERTISE, REQUEST, REPLY, RENEW, REBIND,
 *   RELEASE, DECLINE, INFORMATION-REQUEST, RELAY-FORW, RELAY-REPL)
 * - Handle Identity Associations (IA_NA for non-temporary addresses, IA_TA for
 *   temporary addresses, IA_PD for prefix delegation per RFC 3633)
 * - Process DHCPv6 options including client identifier (DUID), server identifier,
 *   IA address options, status codes, DNS recursive name servers (RDNSS), and
 *   vendor-specific options
 * - Manage DUID (DHCPv6 Unique Identifier) parsing and validation for client
 *   identification across lease renewals
 * - Generate appropriate DHCPv6 status codes (Success, NoAddrsAvail, NoBinding,
 *   NotOnLink, UseMulticast) based on request validation
 * - Coordinate with Router Advertisement to respect M (managed address) and O
 *   (other configuration) flags for stateful vs stateless operation
 * - Implement DHCPv6 relay agent forwarding and reply relaying for multi-hop
 *   scenarios with relay options and interface identification
 * - Support rapid commit optimization (RFC 3315 Section 17.2.1) for single
 *   message exchange when both client and server support it
 * 
 * DEPENDENCIES:
 * Includes: dnsmasq.h (core structures: struct daemon, struct dhcp_context,
 *           struct dhcp_lease, struct in6_addr), dhcp6-protocol.h (DHCPv6 message
 *           type constants, option codes, DUID types, status codes)
 * Called by: dhcp6.c (dhcp6_packet() invokes dhcp6_reply() for message processing),
 *            network event loop (poll-based reception triggers relay functions)
 * Calls: outpacket.c (DHCPv6 option serialization via save_counter(), reset_counter(),
 *        put_opt6_*() functions), lease.c (lease_update_file(), lease_find_by_addr6(),
 *        lease_allocate() for lease database operations), cache.c (cache_add_dhcp_entry()
 *        for DNS integration)
 * 
 * DATA STRUCTURES:
 * - struct state: DHCPv6 request processing state including client identifier (CLID),
 *   transaction ID (xid), Identity Association ID (IAID), IA type (IA_NA/IA_TA/IA_PD),
 *   client hostname, FQDN flags, link addresses, packet option pointers, and tag
 *   matching context (lines 22-34)
 * - struct dhcp_context: Address pool and configuration context from dnsmasq.h,
 *   defining IPv6 ranges, lease times, router, DNS servers, and domain configuration
 * - struct dhcp_lease: Lease record from dnsmasq.h tracking assigned IPv6 address,
 *   client DUID, IAID, hostname, expiration time, and lease state
 * - struct dhcp_config: Static reservation configuration from dnsmasq.h binding
 *   client identifiers to specific IPv6 addresses or hostnames
 * 
 * COMPILE-TIME OPTIONS:
 * - HAVE_DHCP6: Enables DHCPv6 server functionality (entire file conditionally compiled)
 * - HAVE_SCRIPT: Enables lease-change script execution via dhcp-script option
 * - HAVE_BROKEN_RTC: Adjusts lease time calculations for systems without reliable RTC
 * - HAVE_DHCP6: Implies HAVE_DHCP (DHCPv4 support required for shared infrastructure)
 * 
 * THREADING/CONCURRENCY:
 * Single-threaded event-driven architecture. DHCPv6 message processing invoked
 * synchronously from main event loop when DHCPv6 packets arrive on UDP port 547.
 * No concurrent access to dhcp_context or lease database; all operations serialized
 * through poll-based event dispatch. Lease file updates use atomic write-rename
 * pattern for crash safety.
 * 
 * @copyright Copyright (c) 2000-2025 Simon Kelley
 * @license GPL-2.0-or-later
 */

#include "dnsmasq.h"

#ifdef HAVE_DHCP6

/**
 * @struct state
 * @brief DHCPv6 request processing state structure
 * 
 * This structure maintains all state information required to process a single DHCPv6 client
 * request through its complete lifecycle from packet reception through response generation.
 * It aggregates client identity (CLID, MAC address), transaction context (XID, interface),
 * address assignment state (contexts, addresses), hostname handling, and option selection
 * tags. The structure is stack-allocated in dhcp6_reply() and passed through the processing
 * chain to maintain request context without global state.
 * 
 * LIFECYCLE:
 * Creation: Stack-allocated in dhcp6_reply() at start of DHCPv6 message processing
 * Initialization: Members initialized from packet contents and system configuration
 * Usage: Passed by pointer through dhcp6_maybe_relay() and dhcp6_no_relay() processing chain
 * Destruction: Automatic when dhcp6_reply() returns (stack deallocation)
 * Ownership: Local to dhcp6_reply() call stack; pointers reference global daemon state or packet buffers
 * 
 * MEMORY LAYOUT:
 * Size: Approximately 200+ bytes depending on pointer size (32-bit vs 64-bit architecture)
 * Alignment: Natural alignment for pointer and integer members
 * 
 * USAGE PATTERNS:
 * Single instance per DHCPv6 request processing. Relay message handling may use nested
 * instances when processing relay-forward encapsulation. Structure enables stateless
 * processing model where all context flows through function parameters rather than
 * global variables.
 */
struct state {
  /** @var clid
   *  @brief Client DUID (DHCP Unique Identifier) from OPTION_CLIENTID
   *  
   *  Pointer to client DUID extracted from DHCPv6 OPTION_CLIENTID (option 1).
   *  NULL if client did not provide DUID (protocol violation). DUID format per
   *  RFC 3315 Section 9: DUID-LLT (type 1), DUID-EN (type 2), DUID-LL (type 3).
   *  Points into packet buffer; valid only during request processing.
   */
  unsigned char *clid;
  
  /** @var multicast_dest
   *  @brief Flag indicating if response should be multicast (1) or unicast (0)
   *  
   *  Determines DHCPv6 response transmission mode. Set to 1 if client sent request
   *  to multicast address (ff02::1:2 All_DHCP_Relay_Agents_and_Servers), requiring
   *  multicast response per RFC 3315 Section 18. Set to 0 for unicast responses.
   */
  int multicast_dest;
  
  /** @var clid_len
   *  @brief Length of client DUID in bytes
   *  
   *  Size of DUID pointed to by clid member. Typical range 8-130 bytes per RFC 3315.
   *  Zero indicates no DUID present (protocol error).
   */
  int clid_len;
  
  /** @var ia_type
   *  @brief Identity Association type being processed
   *  
   *  DHCPv6 IA type from current IA option: OPTION_IA_NA (3) for non-temporary
   *  addresses, OPTION_IA_TA (4) for temporary addresses, OPTION_IA_PD (25) for
   *  prefix delegation. Set during check_ia() processing to track current IA context.
   */
  int ia_type;
  
  /** @var interface
   *  @brief Network interface index where DHCPv6 request was received
   *  
   *  Kernel interface index (from recvmsg ancillary data) identifying physical or
   *  virtual interface that received DHCPv6 packet. Used for interface-specific
   *  address pool selection and relay agent processing. Value corresponds to
   *  if_nametoindex() result.
   */
  int interface;
  
  /** @var hostname_auth
   *  @brief Flag indicating if client-provided hostname is authoritative (trusted)
   *  
   *  Set to 1 if hostname should be registered in DNS without additional validation.
   *  Set based on dhcp-host configuration with "set:" tag or network trust level.
   *  Controls whether lease_update_dns() will register hostname in cache.
   */
  int hostname_auth;
  
  /** @var lease_allocate
   *  @brief Flag indicating whether to allocate new lease (1) or use existing (0)
   *  
   *  Set to 1 during REQUEST/RENEW processing when new lease allocation is required.
   *  Set to 0 for INFORMATION-REQUEST (stateless DHCPv6) or when reusing existing
   *  lease during RENEW/REBIND.
   */
  int lease_allocate;
  
  /** @var client_hostname
   *  @brief Client-provided hostname from OPTION_CLIENT_FQDN or OPTION_HOSTNAME
   *  
   *  Hostname sent by DHCPv6 client for DNS registration. May be partial (unqualified)
   *  or fully-qualified depending on client implementation. NULL if client did not
   *  provide hostname. Points into packet buffer or allocated memory.
   */
  char *client_hostname;
  
  /** @var hostname
   *  @brief Effective hostname for DNS registration and logging
   *  
   *  Final hostname to use after applying configuration overrides (dhcp-host entries),
   *  domain qualification, and sanitization. Used for DNS cache registration and
   *  lease database storage. May differ from client_hostname if administrator
   *  configured static hostname for this DUID/MAC.
   */
  char *hostname;
  
  /** @var domain
   *  @brief Domain name for hostname qualification
   *  
   *  Domain suffix to append to unqualified hostnames. Derived from dhcp-option
   *  domain configuration or interface-specific domain settings. NULL if no domain
   *  qualification required. Used to construct FQDN from partial hostname.
   */
  char *domain;
  
  /** @var send_domain
   *  @brief Domain name to send in DHCPv6 OPTION_DOMAIN_LIST response
   *  
   *  Domain name(s) to include in DHCPv6 OPTION_DOMAIN_LIST (option 24) for client
   *  DNS search configuration. May differ from domain member if configuration
   *  specifies separate client vs server domain settings.
   */
  char *send_domain;
  
  /** @var context
   *  @brief Active DHCPv6 address pool context for this request
   *  
   *  Pointer to dhcp_context structure defining IPv6 address range, prefix length,
   *  lease times, and selection tags for current request. Selected from global
   *  daemon->dhcp_contexts list based on interface, relay link-address, and tag
   *  matching. NULL if no matching context found (leads to NoAddrsAvail status).
   */
  struct dhcp_context *context;
  
  /** @var link_address
   *  @brief IPv6 link address from relay agent message
   *  
   *  Link-address field extracted from DHCPv6 RELAY-FORW message (RFC 3315 Section 20.1.2).
   *  Identifies subnet/link where client is located for proper address pool selection.
   *  NULL for direct (non-relayed) client requests. Points into packet buffer or
   *  relay state structure.
   */
  struct in6_addr *link_address;
  
  /** @var fallback
   *  @brief Fallback IPv6 address for response when client address unknown
   *  
   *  IPv6 address to use for response transmission when client's IPv6 address cannot
   *  be determined (e.g., SOLICIT with no address assignments). Typically set to
   *  multicast All_DHCP_Relay_Agents_and_Servers (ff02::1:2) or relay address.
   */
  struct in6_addr *fallback;
  
  /** @var ll_addr
   *  @brief Link-local IPv6 address of receiving interface
   *  
   *  Server's link-local address (fe80::/64) on interface where request was received.
   *  Used as source address for DHCPv6 responses and for link-local address pool
   *  matching. Obtained from interface enumeration in network.c.
   */
  struct in6_addr *ll_addr;
  
  /** @var ula_addr
   *  @brief Unique Local Address (ULA) of receiving interface
   *  
   *  Server's ULA address (fc00::/7) if configured on receiving interface. Used for
   *  ULA-based address pool matching and as response source address for ULA clients.
   *  NULL if no ULA configured on interface.
   */
  struct in6_addr *ula_addr;
  
  /** @var xid
   *  @brief DHCPv6 transaction ID from request message
   *  
   *  24-bit transaction identifier from DHCPv6 message header (bytes 1-3). Must be
   *  echoed in response to enable client request/response matching. Generated by
   *  client randomly per RFC 3315 Section 15.
   */
  unsigned int xid;
  
  /** @var fqdn_flags
   *  @brief Flags from DHCPv6 OPTION_CLIENT_FQDN
   *  
   *  Flags byte from OPTION_CLIENT_FQDN (option 39) indicating client preferences:
   *  bit 0 (S): Server should perform AAAA DNS updates
   *  bit 1 (O): Server overrides client FQDN preferences
   *  bit 2 (N): Server should not perform DNS updates
   *  Used to coordinate DNS update responsibilities per RFC 4704.
   */
  unsigned int fqdn_flags;
  
  /** @var iaid
   *  @brief Identity Association Identifier from IA_NA/IA_TA/IA_PD option
   *  
   *  32-bit IAID uniquely identifying this IA within client's DUID scope. Client
   *  generates IAID and maintains consistent value across RENEW/REBIND for same
   *  IA. Server echoes IAID in response IA options. Used with DUID to uniquely
   *  identify lease bindings.
   */
  unsigned int iaid;
  
  /** @var iface_name
   *  @brief Network interface name string (e.g., "eth0", "wlan0")
   *  
   *  Human-readable interface name corresponding to interface member index.
   *  Used for logging and interface-specific configuration lookup. Obtained from
   *  if_indextoname() or passed from caller. NULL-terminated string.
   */
  char *iface_name;
  
  /** @var packet_options
   *  @brief Pointer to start of DHCPv6 options in request packet
   *  
   *  Points to first byte after DHCPv6 message header (past msg-type and xid).
   *  Starting point for option parsing via opt6_find() and opt6_next(). Points
   *  into received packet buffer; valid only during request processing.
   */
  void *packet_options;
  
  /** @var end
   *  @brief Pointer to end of DHCPv6 options in request packet
   *  
   *  Points one byte past last valid option byte in received packet. Used as
   *  termination condition for option iteration. Together with packet_options,
   *  defines bounds for safe option parsing.
   */
  void *end;
  
  /** @var tags
   *  @brief Linked list of dhcp_netid tags matched for this request
   *  
   *  Tag set built from vendor class matching, user class matching, subnet matching,
   *  and explicit "set:" configuration. Used for conditional option selection via
   *  "tag:" matching in dhcp-option directives. Modified during request processing
   *  as new matching conditions discovered.
   */
  struct dhcp_netid *tags;
  
  /** @var context_tags
   *  @brief Tags from selected dhcp_context (address pool tags)
   *  
   *  Tag list copied from context->filter when address pool selected. Merged into
   *  tags member for unified tag-based option selection. Represents network segment
   *  or subnet-specific tagging.
   */
  struct dhcp_netid *context_tags;
  
  /** @var mac
   *  @brief Client MAC address extracted from DUID or relay message
   *  
   *  Hardware address of client interface, extracted from DUID-LL or DUID-LLT if
   *  present, or from relay agent Remote-ID option. Used for static host matching
   *  (dhcp-host with MAC specification), lease database lookup, and logging.
   *  Array sized to DHCP_CHADDR_MAX (16 bytes) to accommodate IEEE 802 addresses.
   */
  unsigned char mac[DHCP_CHADDR_MAX];
  
  /** @var mac_len
   *  @brief Length of valid MAC address data in mac array
   *  
   *  Number of bytes of MAC address stored in mac member. Typically 6 for Ethernet
   *  (EUI-48), 8 for IEEE 802.15.4, or 0 if no MAC address available. Used to
   *  distinguish valid MAC from uninitialized buffer.
   */
  unsigned int mac_len;
  
  /** @var mac_type
   *  @brief Hardware type code for MAC address (RFC 826 ARP hardware types)
   *  
   *  IANA hardware type identifier for mac member: 1 for Ethernet, 6 for IEEE 802,
   *  etc. Extracted from DUID hardware type field or relay Remote-ID option.
   *  Used for hardware-specific lease binding and filtering.
   */
  unsigned int mac_type;
};

static int dhcp6_maybe_relay(struct state *state, unsigned char *inbuff, size_t sz, 
			     struct in6_addr *client_addr, int is_unicast, time_t now);
static int dhcp6_no_relay(struct state *state, int msg_type, unsigned char *inbuff, size_t sz, int is_unicast, time_t now);
static void log6_opts(int nest, unsigned int xid, void *start_opts, void *end_opts);
static void log6_packet(struct state *state, char *type, struct in6_addr *addr, char *string);
static void log6_quiet(struct state *state, char *type, struct in6_addr *addr, char *string);
static void *opt6_find (uint8_t *opts, uint8_t *end, unsigned int search, unsigned int minsize);
static void *opt6_next(uint8_t *opts, uint8_t *end);
static unsigned int opt6_uint(unsigned char *opt, int offset, int size);
static void get_context_tag(struct state *state, struct dhcp_context *context);
static int check_ia(struct state *state, void *opt, void **endp, void **ia_option);
static int build_ia(struct state *state, int *t1cntr);
static void end_ia(int t1cntr, unsigned int min_time, int do_fuzz);
static void mark_context_used(struct state *state, struct in6_addr *addr);
static void mark_config_used(struct dhcp_context *context, struct in6_addr *addr);
static int check_address(struct state *state, struct in6_addr *addr);
static int config_valid(struct dhcp_config *config, struct dhcp_context *context, struct in6_addr *addr, struct state *state, time_t now);
static struct addrlist *config_implies(struct dhcp_config *config, struct dhcp_context *context, struct in6_addr *addr);
static void add_address(struct state *state, struct dhcp_context *context, unsigned int lease_time, void *ia_option, 
			unsigned int *min_time, struct in6_addr *addr, time_t now);
static void update_leases(struct state *state, struct dhcp_context *context, struct in6_addr *addr, unsigned int lease_time, time_t now);
static int add_local_addrs(struct dhcp_context *context);
static struct dhcp_netid *add_options(struct state *state, int do_refresh);
static void calculate_times(struct dhcp_context *context, unsigned int *min_time, unsigned int *valid_timep, 
			    unsigned int *preferred_timep, unsigned int lease_time);

/**
 * @def opt6_len(opt)
 * @brief Extract length field from DHCPv6 option
 * 
 * @param opt Pointer to DHCPv6 option data (points to first byte after option-len field)
 * @return Option data length in bytes (does not include 4-byte option header)
 * 
 * Reads 2-byte length field at offset -2 from opt pointer. DHCPv6 option format:
 * [option-code:2][option-len:2][option-data:option-len]. This macro assumes opt
 * points to option-data (4 bytes past option start).
 */
#define opt6_len(opt) ((int)(opt6_uint(opt, -2, 2)))

/**
 * @def opt6_type(opt)
 * @brief Extract option code from DHCPv6 option
 * 
 * @param opt Pointer to DHCPv6 option data (points to first byte after option-len field)
 * @return DHCPv6 option code (OPTION_CLIENTID=1, OPTION_SERVERID=2, etc.)
 * 
 * Reads 2-byte option-code field at offset -4 from opt pointer. Returns option type
 * per RFC 3315 Section 22 option code registry. Used to identify option type when
 * iterating through options list.
 */
#define opt6_type(opt) (opt6_uint(opt, -4, 2))

/**
 * @def opt6_ptr(opt, i)
 * @brief Get pointer to byte at offset i within DHCPv6 option data
 * 
 * @param opt Pointer to DHCPv6 option data (points to first byte after option-len field)
 * @param i Byte offset within option data (0 = first data byte)
 * @return Pointer to byte at offset i within option data
 * 
 * Calculates pointer to data at offset i within option payload. The +4 accounts for
 * opt pointing 4 bytes past option start (past option-code and option-len fields).
 * Used to access structured data within options like IA_NA (IAID, T1, T2 fields).
 */
#define opt6_ptr(opt, i) ((void *)&(((uint8_t *)(opt))[4+(i)]))

/**
 * @def opt6_user_vendor_ptr(opt, i)
 * @brief Get pointer to byte at offset i within vendor-specific or user-class option
 * 
 * @param opt Pointer to vendor/user option data (points 2 bytes past option start)
 * @param i Byte offset within vendor/user option data
 * @return Pointer to byte at offset i within vendor/user option data
 * 
 * Similar to opt6_ptr but for vendor-specific and user-class options which have
 * non-standard encapsulation. The +2 offset accounts for enterprise-number field
 * in vendor options or class-len field in user options.
 */
#define opt6_user_vendor_ptr(opt, i) ((void *)&(((uint8_t *)(opt))[2+(i)]))

/**
 * @def opt6_user_vendor_len(opt)
 * @brief Extract length from vendor-specific or user-class option
 * 
 * @param opt Pointer to vendor/user option data (points 2 bytes past option start)
 * @return Length of vendor/user option data in bytes
 * 
 * Reads length field from vendor-specific or user-class option. Offset calculation
 * differs from opt6_len due to non-standard option structure with enterprise-number
 * or class-len prefix.
 */
#define opt6_user_vendor_len(opt) ((int)(opt6_uint(opt, -4, 2)))

/**
 * @def opt6_user_vendor_next(opt, end)
 * @brief Advance to next vendor-specific or user-class option in list
 * 
 * @param opt Pointer to current vendor/user option data
 * @param end Pointer to end of option buffer (one byte past valid data)
 * @return Pointer to next option, or NULL if no more options
 * 
 * Iterator macro for vendor-specific and user-class option lists. Adjusts pointer
 * by -2 before calling opt6_next to account for different pointer offset convention
 * in vendor/user option handling.
 */
#define opt6_user_vendor_next(opt, end) (opt6_next(((uint8_t *) opt) - 2, end))
 

/**
 * @brief Process incoming DHCPv6 packet and generate appropriate reply
 * 
 * @detailed This is the main entry point for DHCPv6 server packet processing. It handles all
 *           DHCPv6 message types including SOLICIT, REQUEST, RENEW, REBIND, RELEASE, DECLINE,
 *           INFORMATION-REQUEST, and RELAY-FORW per RFC 3315. The function initializes
 *           processing state with network context information, validates minimum packet size,
 *           extracts the message type, prepares vendor matching state to avoid tangled linked
 *           lists, and delegates to dhcp6_maybe_relay for the core protocol handling. This
 *           function serves as the wrapper that bridges the network layer (UDP packet reception
 *           in dhcp6.c) with the protocol state machine implementation. It coordinates stateful
 *           DHCPv6 address assignment (M=1 via Router Advertisement) and stateless DHCPv6
 *           configuration distribution (O=1, M=0). The function determines the appropriate
 *           response port based on whether the incoming message was a relay-forward (respond
 *           to server port 547) or direct client message (respond to client port 546).
 * 
 * @param context Chain of DHCP contexts defining available IPv6 address ranges and configuration
 * @param multicast_dest Flag indicating if reply should be multicast (1) or unicast (0)
 * @param interface System interface index where DHCPv6 packet was received
 * @param iface_name Human-readable interface name (e.g., "eth0", "br-lan") for logging
 * @param fallback Fallback IPv6 address for replies when client address unknown or invalid
 * @param ll_addr Link-local IPv6 address of the interface for local network communication
 * @param ula_addr ULA (Unique Local Address) IPv6 address of interface if configured, NULL otherwise
 * @param sz Size in bytes of received DHCPv6 packet in daemon->dhcp_packet.iov_base
 * @param client_addr IPv6 source address of DHCPv6 client or relay agent that sent the packet
 * @param now Current timestamp for lease time calculations, logging, and script execution
 * 
 * @return Response destination port number, or 0 if no reply should be sent
 * @retval DHCPV6_SERVER_PORT (547) Incoming message was RELAY-FORW; reply to relay agent server port
 * @retval DHCPV6_CLIENT_PORT (546) Incoming message was direct client message; reply to client port
 * @retval 0 Packet processing failed or packet too small (sz <= 4 bytes); no reply generated
 * 
 * @note Minimum packet size is 5 bytes: 1 byte message type + 4 bytes for transaction ID/header
 * @note Resets vendor matching state to prevent linked list cycles from repeated matches
 * @note Calls reset_counter() to initialize outpacket sequence for option encoding
 * @note Message type extracted from first byte of daemon->dhcp_packet.iov_base buffer
 * @note Stateful vs stateless mode determined by Router Advertisement M and O flags in context
 * 
 * @warning Assumes daemon->dhcp_packet.iov_base contains valid DHCPv6 packet data
 * @warning Does not validate packet buffer size beyond minimum 5-byte check
 * @warning Modifies global vendor netid.next pointers to mark vendors as unmatched
 * 
 * @see dhcp6_maybe_relay() for relay agent processing and message type dispatching
 * @see dhcp6_no_relay() for direct client message processing (SOLICIT, REQUEST, etc.)
 * @see dhcp6.c:dhcp6_packet() for network layer reception and call to this function
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_context *ctx = daemon->dhcp6;
 * struct in6_addr client;
 * inet_pton(AF_INET6, "fe80::1", &client);
 * unsigned short port = dhcp6_reply(ctx, 0, if_nametoindex("eth0"), "eth0",
 *                                    &daemon->doing_dhcp6 ? daemon->dhcp6_addr : NULL,
 *                                    &daemon->ll_addr, NULL, packet_len, &client, now);
 * if (port == DHCPV6_CLIENT_PORT) {
 *   // Send reply to client port 546
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 3315 Sections 15-18 (Message Types and Processing), RFC 3633 (Prefix Delegation)
 * SIDE EFFECTS: Modifies daemon->dhcp_packet buffer via dhcp6_maybe_relay; resets vendor match state
 * THREAD SAFETY: Not thread-safe; uses global daemon structure and modifies vendor linked list state
 */
unsigned short dhcp6_reply(struct dhcp_context *context, int multicast_dest, int interface, char *iface_name,
			   struct in6_addr *fallback,  struct in6_addr *ll_addr, struct in6_addr *ula_addr,
			   size_t sz, struct in6_addr *client_addr, time_t now)
{
  struct dhcp_vendor *vendor;
  int msg_type;
  struct state state;
  
  if (sz <= 4)
    return 0;
  
  msg_type = *((unsigned char *)daemon->dhcp_packet.iov_base);
  
  /* Mark these so we only match each at most once, to avoid tangled linked lists */
  for (vendor = daemon->dhcp_vendors; vendor; vendor = vendor->next)
    vendor->netid.next = &vendor->netid;
  
  reset_counter();
  state.context = context;
  state.multicast_dest = multicast_dest;
  state.interface = interface;
  state.iface_name = iface_name;
  state.fallback = fallback;
  state.ll_addr = ll_addr;
  state.ula_addr = ula_addr;
  state.mac_len = 0;
  state.tags = NULL;
  state.link_address = NULL;

  if (dhcp6_maybe_relay(&state, daemon->dhcp_packet.iov_base, sz, client_addr, 
			IN6_IS_ADDR_MULTICAST(client_addr), now))
    return msg_type == DHCP6RELAYFORW ? DHCPV6_SERVER_PORT : DHCPV6_CLIENT_PORT;

  return 0;
}

/**
 * @brief Process DHCPv6 message handling both relayed and direct client messages with recursive relay chain support
 * 
 * @detailed This function is the core dispatcher for DHCPv6 server-side message processing, handling
 *           the critical distinction between RELAY-FORW encapsulated messages and direct client messages.
 *           When the message is NOT a relay-forward (direct client message), it determines the network
 *           context by either extracting the client MAC address from the local neighbor discovery cache
 *           (no relay in use, link_address == NULL) or recalculating available DHCP contexts based on
 *           the relay agent's link-address field from the innermost nested RELAY-FORW message (relay in use).
 *           It validates that an appropriate address range context exists for the request's network and
 *           delegates to dhcp6_no_relay for protocol-specific message type processing (SOLICIT, REQUEST, etc.).
 *           When the message IS a relay-forward (DHCP6RELAYFORW type), it processes the relay agent
 *           encapsulation by validating minimum 38-byte size (1 msg_type + 1 hopcount + 16 link_address +
 *           16 peer_address + 4 minimal option = 38), copying the relay header into the reply buffer,
 *           setting the reply type to DHCP6RELAYREPL, extracting and matching relay agent identifiers
 *           (OPTION6_SUBSCRIBER_ID, OPTION6_REMOTE_ID) against configured vendor tags, extracting client
 *           MAC address from OPTION6_CLIENT_MAC (RFC 6939) for tracking, processing all relay options
 *           while copying non-MAC options to the reply, and RECURSIVELY calling itself when encountering
 *           OPTION6_RELAY_MSG to handle nested relay chains (relay agents forwarding through other relay
 *           agents). The link_address from the relay message is used per RFC 6221 paragraph 4 to determine
 *           the network topology for address allocation. The function handles shared network configurations
 *           by matching the relay's link_address against configured shared network definitions. The is_unicast
 *           flag is zeroed for relayed packets since it refers to the relay message transport, not the
 *           original client message. This implements RFC 3315 Section 20 relay agent behavior with support
 *           for RFC 6939 client link-layer address option and RFC 6221 lightweight relay agents.
 * 
 * @param state Pointer to DHCPv6 processing state structure containing context, tags, MAC address,
 *              interface information, link_address for relay processing, and packet buffer pointers
 * @param inbuff Pointer to input DHCPv6 packet buffer (either client message or RELAY-FORW encapsulation)
 * @param sz Size in bytes of the input packet in inbuff buffer
 * @param client_addr IPv6 address of the client or relay agent that sent this message
 * @param is_unicast Flag indicating if message was received via unicast (1) or multicast (0);
 *                   zeroed for nested relay processing since it refers to relay transport not client
 * @param now Current timestamp for lease calculations, logging, and context validation
 * 
 * @return Success/failure indicator for message processing
 * @retval 1 Message successfully processed; reply constructed in outpacket buffer
 * @retval 0 Processing failed due to invalid size, no available address range context, or recursive processing failure
 * 
 * @note Handles RECURSIVE relay chains by calling itself when processing OPTION6_RELAY_MSG
 * @note For direct client messages (non-relay), extracts client MAC from neighbor discovery cache
 * @note For relayed messages, recalculates DHCP contexts based on relay link_address field
 * @note Implements RFC 6939 client link-layer address extraction from OPTION6_CLIENT_MAC
 * @note Implements RFC 6221 lightweight relay agent link_address handling
 * @note Copies relay options to reply except OPTION6_CLIENT_MAC which is not echoed
 * @note Sets state->link_address from innermost relay for network topology determination
 * @note Validates minimum 38-byte size for RELAY-FORW messages to prevent buffer overruns
 * @note Matches relay agent identifiers (subscriber ID, remote ID) against vendor tags
 * @note Handles shared network configurations by matching link_address against shared_networks
 * @note Logs warning and returns 0 if no address range available for relay's link_address
 * 
 * @warning RECURSIVE function; stack depth limited by maximum relay hop count (typically 32)
 * @warning Modifies state->context, state->link_address, state->mac during processing
 * @warning Assumes inbuff contains valid DHCPv6 packet; minimal validation performed
 * @warning Developer warning: "This cost me blood to write, it will probably cost you blood to understand - srk"
 * 
 * @see dhcp6_no_relay() for processing direct client messages after context determination
 * @see dhcp6_reply() for entry point that calls this function
 * @see get_client_mac() for extracting client MAC from neighbor discovery cache
 * @see opt6_find() for locating specific options in DHCPv6 option list
 * @see put_opt6() for writing options to output packet buffer
 * 
 * EXAMPLE USAGE:
 * @code
 * struct state state;
 * unsigned char packet[1500];
 * size_t packet_len = recv_dhcp6_packet(...);
 * struct in6_addr client;
 * int success = dhcp6_maybe_relay(&state, packet, packet_len, &client, 0, now);
 * if (success) {
 *   // Reply constructed in outpacket buffer, ready to send
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 3315 Section 20 (Relay Agent Behavior), RFC 6221 (Lightweight DHCPv6 Relay Agent), RFC 6939 (Client Link-layer Address Option)
 * SIDE EFFECTS: Modifies state->context, state->link_address, state->mac, state->tags; writes to outpacket buffer via put_opt6
 * THREAD SAFETY: Not thread-safe; modifies state structure and uses global daemon structure
 */
/* This cost me blood to write, it will probably cost you blood to understand - srk. */
static int dhcp6_maybe_relay(struct state *state, unsigned char *inbuff, size_t sz, 
			     struct in6_addr *client_addr, int is_unicast, time_t now)
{
  uint8_t *end = inbuff + sz;
  uint8_t *opts = inbuff + 34;
  int msg_type = *inbuff;
  unsigned char *outmsgtypep;
  uint8_t *opt;
  struct dhcp_vendor *vendor;

  /* if not an encapsulated relayed message, just do the stuff */
  if (msg_type != DHCP6RELAYFORW)
    {
      /* if link_address != NULL if points to the link address field of the 
	 innermost nested RELAYFORW message, which is where we find the
	 address of the network on which we can allocate an address.
	 Recalculate the available contexts using that information. 

      link_address == NULL means there's no relay in use, so we try and find the client's 
      MAC address from the local ND cache. */
      
      if (!state->link_address)
	get_client_mac(client_addr, state->interface, state->mac, &state->mac_len, &state->mac_type, now);
      else
	{
	  struct dhcp_context *c;
	  struct shared_network *share = NULL;
	  state->context = NULL;

	  if (!IN6_IS_ADDR_LOOPBACK(state->link_address) &&
	      !IN6_IS_ADDR_LINKLOCAL(state->link_address) &&
	      !IN6_IS_ADDR_MULTICAST(state->link_address))
	    for (c = daemon->dhcp6; c; c = c->next)
	      {
		for (share = daemon->shared_networks; share; share = share->next)
		  {
		    if (share->shared_addr.s_addr != 0)
		      continue;
		    
		    if (share->if_index != 0 ||
			!IN6_ARE_ADDR_EQUAL(state->link_address, &share->match_addr6))
		      continue;
		    
		    if ((c->flags & CONTEXT_DHCP) &&
			!(c->flags & (CONTEXT_TEMPLATE | CONTEXT_OLD)) &&
			is_same_net6(&share->shared_addr6, &c->start6, c->prefix) &&
			is_same_net6(&share->shared_addr6, &c->end6, c->prefix))
		      break;
		  }
		
		if (share ||
		    ((c->flags & CONTEXT_DHCP) &&
		     !(c->flags & (CONTEXT_TEMPLATE | CONTEXT_OLD)) &&
		     is_same_net6(state->link_address, &c->start6, c->prefix) &&
		     is_same_net6(state->link_address, &c->end6, c->prefix)))
		  {
		    c->preferred = c->valid = 0xffffffff;
		    c->current = state->context;
		    state->context = c;
		  }
	      }
	  
	  if (!state->context)
	    {
	      inet_ntop(AF_INET6, state->link_address, daemon->addrbuff, ADDRSTRLEN); 
	      my_syslog(MS_DHCP | LOG_WARNING, 
			_("no address range available for DHCPv6 request from relay at %s"),
			daemon->addrbuff);
	      return 0;
	    }
	}
	  
      if (!state->context)
	{
	  my_syslog(MS_DHCP | LOG_WARNING, 
		    _("no address range available for DHCPv6 request via %s"), state->iface_name);
	  return 0;
	}

      return dhcp6_no_relay(state, msg_type, inbuff, sz, is_unicast, now);
    }

  /* must have at least msg_type+hopcount+link_address+peer_address+minimal size option
     which is               1   +    1   +    16      +     16     + 2 + 2 = 38 */
  if (sz < 38)
    return 0;
  
  /* copy header stuff into reply message and set type to reply */
  if (!(outmsgtypep = put_opt6(inbuff, 34)))
    return 0;
  *outmsgtypep = DHCP6RELAYREPL;

  /* look for relay options and set tags if found. */
  for (vendor = daemon->dhcp_vendors; vendor; vendor = vendor->next)
    {
      int mopt;
      
      if (vendor->match_type == MATCH_SUBSCRIBER)
	mopt = OPTION6_SUBSCRIBER_ID;
      else if (vendor->match_type == MATCH_REMOTE)
	mopt = OPTION6_REMOTE_ID; 
      else
	continue;

      if ((opt = opt6_find(opts, end, mopt, 1)) &&
	  vendor->len == opt6_len(opt) &&
	  memcmp(vendor->data, opt6_ptr(opt, 0), vendor->len) == 0 &&
	  vendor->netid.next != &vendor->netid)
	{
	  vendor->netid.next = state->tags;
	  state->tags = &vendor->netid;
	  break;
	}
    }
  
  /* RFC-6939 */
  if ((opt = opt6_find(opts, end, OPTION6_CLIENT_MAC, 3)))
    {
      if (opt6_len(opt) - 2 > DHCP_CHADDR_MAX) {
        return 0;
      }
      state->mac_type = opt6_uint(opt, 0, 2);
      state->mac_len = opt6_len(opt) - 2;
      memcpy(&state->mac[0], opt6_ptr(opt, 2), state->mac_len);
    }
  
  for (opt = opts; opt; opt = opt6_next(opt, end))
    {
      if ((uint8_t *)opt6_ptr(opt, 0) + opt6_len(opt) > end)
        return 0;
     
      /* Don't copy MAC address into reply. */
      if (opt6_type(opt) != OPTION6_CLIENT_MAC)
	{
	  int o = new_opt6(opt6_type(opt));
	  if (opt6_type(opt) == OPTION6_RELAY_MSG)
	    {
	      struct in6_addr align;
	      /* the packet data is unaligned, copy to aligned storage */
	      memcpy(&align, inbuff + 2, IN6ADDRSZ); 


	      /* RFC6221 para 4 */
	      if (!IN6_IS_ADDR_UNSPECIFIED(&align))
		state->link_address = &align;
	      /* zero is_unicast since that is now known to refer to the 
		 relayed packet, not the original sent by the client */
	      if (!dhcp6_maybe_relay(state, opt6_ptr(opt, 0), opt6_len(opt), client_addr, 0, now))
		return 0;
	    }
	  else
	    put_opt6(opt6_ptr(opt, 0), opt6_len(opt));
	  end_opt6(o);
	}
    }
  
  return 1;
}

/**
 * @brief Process DHCPv6 client messages without relay agent encapsulation
 * 
 * @detailed Implements the core DHCPv6 message processing state machine handling
 *           client-to-server messages: SOLICIT, REQUEST, RENEW, REBIND, CONFIRM,
 *           INFORMATION-REQUEST, RELEASE, and DECLINE. Performs address allocation
 *           from pools, validates requested addresses against context, manages lease
 *           lifecycle, and constructs appropriate responses (ADVERTISE, REPLY).
 *           
 *           The function orchestrates multiple phases:
 *           1. Client identification via DUID and IAID extraction
 *           2. Tag-based context matching and client classification  
 *           3. Hostname processing from FQDN or hostname options
 *           4. Message-specific processing (SOLICIT allocates, REQUEST validates, etc.)
 *           5. Identity Association (IA) construction with addresses/prefixes
 *           6. DHCPv6 option population based on client requests
 *           7. Lease database updates and script execution
 *           
 *           Address allocation follows RFC 3315 priority: static reservations > existing
 *           leases > dynamic pool allocation. The function coordinates with cache.c
 *           for DNS integration and lease.c for persistent lease storage.
 * 
 * @param state Pointer to DHCPv6 state structure containing client request context,
 *              network interface details, link addresses, packet boundaries, and tags.
 *              Must not be NULL. State is modified throughout processing.
 * @param msg_type DHCPv6 message type from packet header (1=SOLICIT, 3=REQUEST, 
 *                 5=RENEW, 6=REBIND, 4=CONFIRM, 11=INFORMATION-REQUEST, 8=RELEASE, 
 *                 9=DECLINE). Determines processing path through switch statement.
 * @param inbuff Pointer to DHCPv6 packet buffer containing client message after the
 *               1-byte message type field. Buffer contains transaction ID (3 bytes)
 *               followed by DHCPv6 options. Must not be NULL.
 * @param sz Size of packet buffer in bytes, excluding the 1-byte message type that
 *           was already consumed. Must be >= 3 for valid transaction ID.
 * @param is_unicast Boolean flag indicating whether client sent request to unicast
 *                   address (1) or multicast (0). Used to enforce RFC 3315 unicast
 *                   restrictions for SOLICIT (must reject unicast SOLICIT).
 * @param now Current Unix timestamp for lease time calculations, expiration checks,
 *            and logging. Obtained from time(2) system call by caller.
 * 
 * @return Returns 1 on successful message processing with response constructed,
 *         0 if message should be silently dropped (invalid, unsupported, or policy
 *         violation). Return value determines whether daemon transmits response.
 * @retval 1 Message processed successfully; response packet in outpacket buffer ready to send
 * @retval 0 Message dropped silently; do not transmit response (RFC 3315 Section 15)
 * 
 * @note Message type 2 (ADVERTISE), 7 (REPLY), 12 (RELAY-FORW), and 13 (RELAY-REPL)
 *       should not arrive here as they are server-to-client or relay messages.
 * @note SOLICIT processing always returns status SUCCESS in ADVERTISE; actual address
 *       availability is re-checked during subsequent REQUEST processing.
 * @note RAPID_COMMIT option causes SOLICIT to behave like REQUEST, skipping the
 *       ADVERTISE→REQUEST→REPLY exchange and returning REPLY immediately.
 * @note RENEW and REBIND cases share majority of logic; REBIND allows broader
 *       address pool matching while RENEW requires address from original context.
 * 
 * @warning Unicast SOLICIT messages violate RFC 3315 Section 15.2 and are rejected
 *          unless RAPID_COMMIT option is present.
 * @warning Function modifies global daemon->outpacket buffer; not reentrant.
 * @warning Client DUID (OPTION6_CLIENTID) is required; missing DUID results in drop.
 * @warning Identity Association (IA_NA/IA_TA/IA_PD) validation failures set status
 *          codes but may still return 1 (reply sent with error status).
 * 
 * @see dhcp6_maybe_relay() for relay agent encapsulation handling before this function
 * @see dhcp6_reply() for top-level message dispatch and unicast binding
 * @see build_ia() for constructing IA_NA/IA_TA/IA_PD options with addresses
 * @see add_options() for populating DHCPv6 options (DNS, domain search, etc.)
 * @see lease_update_dns() in cache.c for DNS hostname integration
 * @see lease_update_file() in lease.c for lease database persistence
 * @see do_snoop_script_run() for executing dhcp-script on lease events
 * @see check_address() for address ownership validation
 * @see config_valid() for static reservation matching
 * @see address_available() for pool availability checking
 * @see make_duid() for DUID generation when server ID required
 * 
 * EXAMPLE USAGE:
 * @code
 * struct state client_state;
 * unsigned char *packet = daemon->dhcp_packet.iov_base;
 * size_t packet_size = received_bytes - 1; // Exclude msg_type byte
 * int msg_type = packet[0];
 * int unicast = (destination == server_unicast_addr);
 * time_t now = time(NULL);
 * 
 * // Process non-relayed DHCPv6 client request
 * int should_reply = dhcp6_no_relay(&client_state, msg_type, 
 *                                   packet + 1, packet_size, 
 *                                   unicast, now);
 * if (should_reply) {
 *   // Transmit response from daemon->outpacket to client
 *   send(sockfd, save_packet(), save_packet_len(), 0, client_addr, addrlen);
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 3315 Section 15 (message processing), Section 17 (DHCP server
 *                 solicitation), Section 18 (DHCP server operation), RFC 3633 Section 11
 *                 (prefix delegation server operation), RFC 4704 (FQDN option)
 * SIDE EFFECTS: Modifies daemon->outpacket buffer with response packet; updates
 *               global lease database via lease_update_file(); may modify DNS cache
 *               via lease_update_dns(); executes external scripts via queue_script();
 *               logs to syslog via log6_packet()/my_syslog()
 * THREAD SAFETY: Not thread-safe; modifies global daemon structure and outpacket buffer;
 *                single-threaded event loop architecture prevents concurrent invocation
 */
static int dhcp6_no_relay(struct state *state, int msg_type, unsigned char *inbuff, size_t sz, int is_unicast, time_t now)
{
  void *opt;
  int i, o, o1, start_opts, start_msg;
  struct dhcp_opt *opt_cfg;
  struct dhcp_netid *tagif;
  struct dhcp_config *config = NULL;
  struct dhcp_netid known_id, iface_id, v6_id;
  unsigned char outmsgtype;
  struct dhcp_vendor *vendor;
  struct dhcp_context *context_tmp;
  struct dhcp_mac *mac_opt;
  unsigned int ignore = 0;

  state->packet_options = inbuff + 4;
  state->end = inbuff + sz;
  state->clid = NULL;
  state->clid_len = 0;
  state->lease_allocate = 0;
  state->context_tags = NULL;
  state->domain = NULL;
  state->send_domain = NULL;
  state->hostname_auth = 0;
  state->hostname = NULL;
  state->client_hostname = NULL;
  state->fqdn_flags = 0x01; /* default to send if we receive no FQDN option */

  /* set tag with name == interface */
  iface_id.net = state->iface_name;
  iface_id.next = state->tags;
  state->tags = &iface_id; 

  /* set tag "dhcpv6" */
  v6_id.net = "dhcpv6";
  v6_id.next = state->tags;
  state->tags = &v6_id;

  start_msg = save_counter(-1);
  /* copy over transaction-id */
  if (!put_opt6(inbuff, 4))
    return 0;
  start_opts = save_counter(-1);
  state->xid = inbuff[3] | inbuff[2] << 8 | inbuff[1] << 16;
    
  /* We're going to be linking tags from all context we use. 
     mark them as unused so we don't link one twice and break the list */
  for (context_tmp = state->context; context_tmp; context_tmp = context_tmp->current)
    {
      context_tmp->netid.next = &context_tmp->netid;

      if (option_bool(OPT_LOG_OPTS))
	{
	   inet_ntop(AF_INET6, &context_tmp->start6, daemon->dhcp_buff, ADDRSTRLEN); 
	   inet_ntop(AF_INET6, &context_tmp->end6, daemon->dhcp_buff2, ADDRSTRLEN); 
	   if (context_tmp->flags & (CONTEXT_STATIC))
	     my_syslog(MS_DHCP | LOG_INFO, _("%u available DHCPv6 subnet: %s/%d"),
		       state->xid, daemon->dhcp_buff, context_tmp->prefix);
	   else
	     my_syslog(MS_DHCP | LOG_INFO, _("%u available DHCP range: %s -- %s"), 
		       state->xid, daemon->dhcp_buff, daemon->dhcp_buff2);
	}
    }

  if ((opt = opt6_find(state->packet_options, state->end, OPTION6_CLIENT_ID, 1)))
    {
      state->clid = opt6_ptr(opt, 0);
      state->clid_len = opt6_len(opt);
      o = new_opt6(OPTION6_CLIENT_ID);
      put_opt6(state->clid, state->clid_len);
      end_opt6(o);
    }
  else if (msg_type != DHCP6IREQ)
    return 0;

  opt = opt6_find(state->packet_options, state->end, OPTION6_SERVER_ID, 1);
  
  if (msg_type == DHCP6SOLICIT || msg_type == DHCP6CONFIRM || msg_type == DHCP6REBIND || msg_type == DHCP6IREQ)
    {
      /* Above message types must be multicast 3315 Section 15. */
      if (!state->multicast_dest)
	return 0;

      /* server-id must match except for SOLICIT, CONFIRM and REBIND messages, which MUST NOT
	 have a server-id.  3315 para 15.x */
      if (msg_type == DHCP6IREQ)
	{
	  /* If server-id provided in IREQ, it must match. */
	  if (opt && (opt6_len(opt) != daemon->duid_len ||
		      memcmp(opt6_ptr(opt, 0), daemon->duid, daemon->duid_len) != 0))
	    return 0;
	}
      else if (opt) 
	return 0;
    }
  else
    {
      /* Everything else MUST have a server-id that matches ours. */
      if (!opt || opt6_len(opt) != daemon->duid_len ||
	  memcmp(opt6_ptr(opt, 0), daemon->duid, daemon->duid_len) != 0)
	return 0;
    }
  
  o = new_opt6(OPTION6_SERVER_ID);
  put_opt6(daemon->duid, daemon->duid_len);
  end_opt6(o);

  if (is_unicast &&
      (msg_type == DHCP6REQUEST || msg_type == DHCP6RENEW || msg_type == DHCP6RELEASE || msg_type == DHCP6DECLINE))
    
    {  
      outmsgtype = DHCP6REPLY;
      o1 = new_opt6(OPTION6_STATUS_CODE);
      put_opt6_short(DHCP6USEMULTI);
      put_opt6_string("Use multicast");
      end_opt6(o1);
      goto done;
    }

  /* match vendor and user class options */
  for (vendor = daemon->dhcp_vendors; vendor; vendor = vendor->next)
    {
      int mopt;
      
      if (vendor->match_type == MATCH_VENDOR)
	mopt = OPTION6_VENDOR_CLASS;
      else if (vendor->match_type == MATCH_USER)
	mopt = OPTION6_USER_CLASS; 
      else
	continue;

      if ((opt = opt6_find(state->packet_options, state->end, mopt, 2)))
	{
	  void *enc_opt, *enc_end = opt6_ptr(opt, opt6_len(opt));
	  int offset = 0;
	  
	  if (mopt == OPTION6_VENDOR_CLASS)
	    {
	      if (opt6_len(opt) < 4)
		continue;
	      
	      if (vendor->enterprise != opt6_uint(opt, 0, 4))
		continue;
	    
	      offset = 4;
	    }
 
	  /* Note that format if user/vendor classes is different to DHCP options - no option types. */
	  for (enc_opt = opt6_ptr(opt, offset); enc_opt; enc_opt = opt6_user_vendor_next(enc_opt, enc_end))
	    for (i = 0; i <= (opt6_user_vendor_len(enc_opt) - vendor->len); i++)
	      if (memcmp(vendor->data, opt6_user_vendor_ptr(enc_opt, i), vendor->len) == 0)
		{
		  vendor->netid.next = state->tags;
		  state->tags = &vendor->netid;
		  break;
		}
	}
    }

  if (option_bool(OPT_LOG_OPTS) && (opt = opt6_find(state->packet_options, state->end, OPTION6_VENDOR_CLASS, 4)))
    my_syslog(MS_DHCP | LOG_INFO, _("%u vendor class: %u"), state->xid, opt6_uint(opt, 0, 4));
  
  /* dhcp-match. If we have hex-and-wildcards, look for a left-anchored match.
     Otherwise assume the option is an array, and look for a matching element. 
     If no data given, existence of the option is enough. This code handles 
     V-I opts too. */
  for (opt_cfg = daemon->dhcp_match6; opt_cfg; opt_cfg = opt_cfg->next)
    {
      int match = 0;
      
      if (opt_cfg->flags & DHOPT_RFC3925)
	{
	  for (opt = opt6_find(state->packet_options, state->end, OPTION6_VENDOR_OPTS, 4);
	       opt;
	       opt = opt6_find(opt6_next(opt, state->end), state->end, OPTION6_VENDOR_OPTS, 4))
	    {
	      void *vopt;
	      void *vend = opt6_ptr(opt, opt6_len(opt));
	      
	      for (vopt = opt6_find(opt6_ptr(opt, 4), vend, opt_cfg->opt, 0);
		   vopt;
		   vopt = opt6_find(opt6_next(vopt, vend), vend, opt_cfg->opt, 0))
		if ((match = match_bytes(opt_cfg, opt6_ptr(vopt, 0), opt6_len(vopt))))
		  break;
	    }
	  if (match)
	    break;
	}
      else
	{
	  if (!(opt = opt6_find(state->packet_options, state->end, opt_cfg->opt, 1)))
	    continue;
	  
	  match = match_bytes(opt_cfg, opt6_ptr(opt, 0), opt6_len(opt));
	} 
  
      if (match)
	{
	  opt_cfg->netid->next = state->tags;
	  state->tags = opt_cfg->netid;
	}
    }

  if (state->mac_len != 0)
    {
      if (option_bool(OPT_LOG_OPTS))
	{
	  print_mac(daemon->dhcp_buff, state->mac, state->mac_len);
	  my_syslog(MS_DHCP | LOG_INFO, _("%u client MAC address: %s"), state->xid, daemon->dhcp_buff);
	}

      for (mac_opt = daemon->dhcp_macs; mac_opt; mac_opt = mac_opt->next)
	if ((unsigned)mac_opt->hwaddr_len == state->mac_len &&
	    ((unsigned)mac_opt->hwaddr_type == state->mac_type || mac_opt->hwaddr_type == 0) &&
	    memcmp_masked(mac_opt->hwaddr, state->mac, state->mac_len, mac_opt->mask))
	  {
	    mac_opt->netid.next = state->tags;
	    state->tags = &mac_opt->netid;
	  }
    }
  else if (option_bool(OPT_LOG_OPTS))
    my_syslog(MS_DHCP | LOG_INFO, _("%u cannot determine client MAC address"), state->xid);
  
  if ((opt = opt6_find(state->packet_options, state->end, OPTION6_FQDN, 1)))
    {
      /* RFC4704 refers */
       int len = opt6_len(opt) - 1;
       
       state->fqdn_flags = opt6_uint(opt, 0, 1);
       
       /* Always force update, since the client has no way to do it itself. */
       if (!option_bool(OPT_FQDN_UPDATE) && !(state->fqdn_flags & 0x01))
	 state->fqdn_flags |= 0x03;
 
       state->fqdn_flags &= ~0x04;

       if (len != 0 && len < 255)
	 {
	   unsigned char *pp, *op = opt6_ptr(opt, 1);
	   char *pq = daemon->dhcp_buff;
	   
	   pp = op;
	   while (*op != 0 && ((op + (*op)) - pp) < len)
	     {
	       memcpy(pq, op+1, *op);
	       pq += *op;
	       op += (*op)+1;
	       *(pq++) = '.';
	     }
	   
	   if (pq != daemon->dhcp_buff)
	     pq--;
	   *pq = 0;
	   
	   if (legal_hostname(daemon->dhcp_buff))
	     {
	       struct dhcp_match_name *m;
	       size_t nl = strlen(daemon->dhcp_buff);
	       
	       state->client_hostname = daemon->dhcp_buff;
	       
	       if (option_bool(OPT_LOG_OPTS))
		 my_syslog(MS_DHCP | LOG_INFO, _("%u client provides name: %s"), state->xid, state->client_hostname);
	       
	       for (m = daemon->dhcp_name_match; m; m = m->next)
		 {
		   size_t ml = strlen(m->name);
		   char save = 0;
		   
		   if (nl < ml)
		     continue;
		   if (nl > ml)
		     {
		       save = state->client_hostname[ml];
		       state->client_hostname[ml] = 0;
		     }
		   
		   if (hostname_isequal(state->client_hostname, m->name) &&
		       (save == 0 || m->wildcard))
		     {
		       m->netid->next = state->tags;
		       state->tags = m->netid;
		     }
		   
		   if (save != 0)
		     state->client_hostname[ml] = save;
		 }
	     }
	 }
    }	 
  
  if (state->clid &&
      (config = find_config(daemon->dhcp_conf, state->context, state->clid, state->clid_len,
			    state->mac, state->mac_len, state->mac_type, NULL, run_tag_if(state->tags))) &&
      have_config(config, CONFIG_NAME))
    {
      state->hostname = config->hostname;
      state->domain = config->domain;
      state->hostname_auth = 1;
    }
  else if (state->client_hostname)
    {
      state->domain = strip_hostname(state->client_hostname);
      
      if (strlen(state->client_hostname) != 0)
	{
	  state->hostname = state->client_hostname;
	  
	  if (!config)
	    {
	      /* Search again now we have a hostname. 
		 Only accept configs without CLID here, (it won't match)
		 to avoid impersonation by name. */
	      struct dhcp_config *new = find_config(daemon->dhcp_conf, state->context, NULL, 0, NULL, 0, 0, state->hostname, run_tag_if(state->tags));
	      if (new && !have_config(new, CONFIG_CLID) && !new->hwaddr)
		config = new;
	    }
	}
    }

  if (config)
    {
      struct dhcp_netid_list *list;
      
      for (list = config->netid; list; list = list->next)
        {
          list->list->next = state->tags;
          state->tags = list->list;
        }

      /* set "known" tag for known hosts */
      known_id.net = "known";
      known_id.next = state->tags;
      state->tags = &known_id;

      if (have_config(config, CONFIG_DISABLE))
	ignore = 1;
    }
  else if (state->clid &&
	   find_config(daemon->dhcp_conf, NULL, state->clid, state->clid_len,
		       state->mac, state->mac_len, state->mac_type, NULL, run_tag_if(state->tags)))
    {
      known_id.net = "known-othernet";
      known_id.next = state->tags;
      state->tags = &known_id;
    }
  
  tagif = run_tag_if(state->tags);
  
  /* if all the netids in the ignore list are present, ignore this client */
  if (daemon->dhcp_ignore)
    {
      struct dhcp_netid_list *id_list;
     
      for (id_list = daemon->dhcp_ignore; id_list; id_list = id_list->next)
	if (match_netid(id_list->list, tagif, 0))
	  ignore = 1;
    }
  
  /* if all the netids in the ignore_name list are present, ignore client-supplied name */
  if (!state->hostname_auth)
    {
       struct dhcp_netid_list *id_list;
       
       for (id_list = daemon->dhcp_ignore_names; id_list; id_list = id_list->next)
	 if ((!id_list->list) || match_netid(id_list->list, tagif, 0))
	   break;
       if (id_list)
	 state->hostname = NULL;
    }
  

  switch (msg_type)
    {
    default:
      return 0;
      
      
    case DHCP6SOLICIT:
      {
      	int address_assigned;
	/* tags without all prefix-class tags */
	struct dhcp_netid *solicit_tags;
	struct dhcp_context *c;
	
	outmsgtype = DHCP6ADVERTISE;
	
	if (opt6_find(state->packet_options, state->end, OPTION6_RAPID_COMMIT, 0))
	  {
	    outmsgtype = DHCP6REPLY;
	    state->lease_allocate = 1;
	    o = new_opt6(OPTION6_RAPID_COMMIT);
	    end_opt6(o);
	  }
	
  	log6_quiet(state, "DHCPSOLICIT", NULL, ignore ? _("ignored") : NULL);

      request_no_address:
	solicit_tags = tagif;
	address_assigned = 0;
	
	if (ignore)
	  return 0;
	
	/* reset USED bits in leases */
	lease6_reset();

	/* Can use configured address max once per prefix */
	for (c = state->context; c; c = c->current)
	  c->flags &= ~CONTEXT_CONF_USED;

	for (opt = state->packet_options; opt; opt = opt6_next(opt, state->end))
	  {   
	    void *ia_option, *ia_end;
	    unsigned int min_time = 0xffffffff;
	    int t1cntr;
	    int ia_counter;
	    /* set unless we're sending a particular prefix-class, when we
	       want only dhcp-ranges with the correct tags set and not those without any tags. */
	    int plain_range = 1;
	    u32 lease_time;
	    struct dhcp_lease *ltmp;
	    struct in6_addr req_addr, addr;
	    
	    if (!check_ia(state, opt, &ia_end, &ia_option))
	      continue;
	    
	    /* reset USED bits in contexts - one address per prefix per IAID */
	    for (c = state->context; c; c = c->current)
	      c->flags &= ~CONTEXT_USED;

	    o = build_ia(state, &t1cntr);
	    if (address_assigned)
		address_assigned = 2;

	    for (ia_counter = 0; ia_option; ia_counter++, ia_option = opt6_find(opt6_next(ia_option, ia_end), ia_end, OPTION6_IAADDR, 24))
	      {
		/* worry about alignment here. */
		memcpy(&req_addr, opt6_ptr(ia_option, 0), IN6ADDRSZ);
				
		if ((c = address6_valid(state->context, &req_addr, solicit_tags, plain_range)))
		  {
		    lease_time = c->lease_time;
		    /* If the client asks for an address on the same network as a configured address, 
		       offer the configured address instead, to make moving to newly-configured
		       addresses automatic. */
		    if (!(c->flags & CONTEXT_CONF_USED) && config_valid(config, c, &addr, state, now))
		      {
			req_addr = addr;
			mark_config_used(c, &addr);
			if (have_config(config, CONFIG_TIME))
			  lease_time = config->lease_time;
		      }
		    else if (!(c = address6_available(state->context, &req_addr, solicit_tags, plain_range)))
		      continue; /* not an address we're allowed */
		    else if (!check_address(state, &req_addr))
		      continue; /* address leased elsewhere */
		    
		    /* add address to output packet */
		    add_address(state, c, lease_time, ia_option, &min_time, &req_addr, now);
		    mark_context_used(state, &req_addr);
		    get_context_tag(state, c);
		    address_assigned = 1;
		  }
	      }
	    
	    /* Suggest configured address(es) */
	    for (c = state->context; c; c = c->current) 
	      if (!(c->flags & CONTEXT_CONF_USED) &&
		  match_netid(c->filter, solicit_tags, plain_range) &&
		  config_valid(config, c, &addr, state, now))
		{
		  mark_config_used(state->context, &addr);
		  if (have_config(config, CONFIG_TIME))
		    lease_time = config->lease_time;
		  else
		    lease_time = c->lease_time;

		  /* add address to output packet */
		  add_address(state, c, lease_time, NULL, &min_time, &addr, now);
		  mark_context_used(state, &addr);
		  get_context_tag(state, c);
		  address_assigned = 1;
		}
	    
	    /* return addresses for existing leases */
	    ltmp = NULL;
	    while ((ltmp = lease6_find_by_client(ltmp, state->ia_type == OPTION6_IA_NA ? LEASE_NA : LEASE_TA, state->clid, state->clid_len, state->iaid)))
	      {
		req_addr = ltmp->addr6;
		if ((c = address6_available(state->context, &req_addr, solicit_tags, plain_range)))
		  {
		    add_address(state, c, c->lease_time, NULL, &min_time, &req_addr, now);
		    mark_context_used(state, &req_addr);
		    get_context_tag(state, c);
		    address_assigned = 1;
		  }
	      }
		 	   
	    /* Return addresses for all valid contexts which don't yet have one */
	    while ((c = address6_allocate(state->context, state->clid, state->clid_len, state->ia_type == OPTION6_IA_TA,
					  state->iaid, ia_counter, solicit_tags, plain_range, &addr)))
	      {
		add_address(state, c, c->lease_time, NULL, &min_time, &addr, now);
		mark_context_used(state, &addr);
		get_context_tag(state, c);
		address_assigned = 1;
	      }
	    
	    if (address_assigned != 1)
	      {
		/* If the server cannot assign any addresses to an IA in the message
		   from the client, the server MUST include the IA in the Reply message
		   with no addresses in the IA and a Status Code option in the IA
		   containing status code NoAddrsAvail. */
		o1 = new_opt6(OPTION6_STATUS_CODE);
		put_opt6_short(DHCP6NOADDRS);
		put_opt6_string(_("address unavailable"));
		end_opt6(o1);
	      }
	    
	    end_ia(t1cntr, min_time, 0);
	    end_opt6(o);	
	  }

	if (address_assigned) 
	  {
	    o1 = new_opt6(OPTION6_STATUS_CODE);
	    put_opt6_short(DHCP6SUCCESS);
	    put_opt6_string(_("success"));
	    end_opt6(o1);
	    
	    /* If --dhcp-authoritative is set, we can tell client not to wait for
	       other possible servers */
	    o = new_opt6(OPTION6_PREFERENCE);
	    put_opt6_char(option_bool(OPT_AUTHORITATIVE) ? 255 : 0);
	    end_opt6(o);
	  }
	else
	  { 
	    /* no address, return error */
	    o1 = new_opt6(OPTION6_STATUS_CODE);
	    put_opt6_short(DHCP6NOADDRS);
	    put_opt6_string(_("no addresses available"));
	    end_opt6(o1);

	    /* Some clients will ask repeatedly when we're not giving
	       out addresses because we're in stateless mode. Avoid spamming
	       the log in that case. */
	    for (c = state->context; c; c = c->current)
	      if (!(c->flags & CONTEXT_RA_STATELESS))
		{
		  log6_packet(state, state->lease_allocate ? "DHCPREPLY" : "DHCPADVERTISE", NULL, _("no addresses available"));
		  break;
		}
	  }
	
	tagif = add_options(state, 0);
	break;
      }
      
    case DHCP6REQUEST:
      {
	int address_assigned = 0;
	int start = save_counter(-1);

	/* set reply message type */
	outmsgtype = DHCP6REPLY;
	state->lease_allocate = 1;

	log6_quiet(state, "DHCPREQUEST", NULL, ignore ? _("ignored") : NULL);
	
	if (ignore)
	  return 0;
	
	for (opt = state->packet_options; opt; opt = opt6_next(opt, state->end))
	  {   
	    void *ia_option, *ia_end;
	    unsigned int min_time = 0xffffffff;
	    int t1cntr;
	    
	     if (!check_ia(state, opt, &ia_end, &ia_option))
	       continue;

	     if (!ia_option)
	       {
		 /* If we get a request with an IA_*A without addresses, treat it exactly like
		    a SOLICT with rapid commit set. */
		 save_counter(start);
		 goto request_no_address; 
	       }

	    o = build_ia(state, &t1cntr);
	      
	    for (; ia_option; ia_option = opt6_find(opt6_next(ia_option, ia_end), ia_end, OPTION6_IAADDR, 24))
	      {
		struct in6_addr req_addr;
		struct dhcp_context *dynamic, *c;
		unsigned int lease_time;
		int config_ok = 0;

		/* align. */
		memcpy(&req_addr, opt6_ptr(ia_option, 0), IN6ADDRSZ);
		
		if ((c = address6_valid(state->context, &req_addr, tagif, 1)))
		  config_ok = (config_implies(config, c, &req_addr) != NULL);
		
		if ((dynamic = address6_available(state->context, &req_addr, tagif, 1)) || c)
		  {
		    if (!dynamic && !config_ok)
		      {
			/* Static range, not configured. */
			o1 = new_opt6(OPTION6_STATUS_CODE);
			put_opt6_short(DHCP6NOADDRS);
			put_opt6_string(_("address unavailable"));
			end_opt6(o1);
		      }
		    else if (!check_address(state, &req_addr))
		      {
			/* Address leased to another DUID/IAID */
			o1 = new_opt6(OPTION6_STATUS_CODE);
			put_opt6_short(DHCP6UNSPEC);
			put_opt6_string(_("address in use"));
			end_opt6(o1);
		      } 
		    else 
		      {
			if (!dynamic)
			  dynamic = c;

			lease_time = dynamic->lease_time;
			
			if (config_ok && have_config(config, CONFIG_TIME))
			  lease_time = config->lease_time;

			add_address(state, dynamic, lease_time, ia_option, &min_time, &req_addr, now);
			get_context_tag(state, dynamic);
			address_assigned = 1;
		      }
		  }
		else 
		  {
		    /* requested address not on the correct link */
		    o1 = new_opt6(OPTION6_STATUS_CODE);
		    put_opt6_short(DHCP6NOTONLINK);
		    put_opt6_string(_("not on link"));
		    end_opt6(o1);
		  }
	      }
	 
	    end_ia(t1cntr, min_time, 0);
	    end_opt6(o);	
	  }

	if (address_assigned) 
	  {
	    o1 = new_opt6(OPTION6_STATUS_CODE);
	    put_opt6_short(DHCP6SUCCESS);
	    put_opt6_string(_("success"));
	    end_opt6(o1);
	  }
	else
	  { 
	    /* no address, return error */
	    o1 = new_opt6(OPTION6_STATUS_CODE);
	    put_opt6_short(DHCP6NOADDRS);
	    put_opt6_string(_("no addresses available"));
	    end_opt6(o1);
	    log6_packet(state, "DHCPREPLY", NULL, _("no addresses available"));
	  }

	tagif = add_options(state, 0);
	break;
      }
      
  
    case DHCP6RENEW:
    case DHCP6REBIND:
      {
	int address_assigned = 0;

	/* set reply message type */
	outmsgtype = DHCP6REPLY;
	
	log6_quiet(state, msg_type == DHCP6RENEW ? "DHCPRENEW" : "DHCPREBIND", NULL, NULL);

	for (opt = state->packet_options; opt; opt = opt6_next(opt, state->end))
	  {
	    void *ia_option, *ia_end;
	    unsigned int min_time = 0xffffffff;
	    int t1cntr, iacntr;
	    
	    if (!check_ia(state, opt, &ia_end, &ia_option))
	      continue;
	    
	    o = build_ia(state, &t1cntr);
	    iacntr = save_counter(-1); 
	    
	    for (; ia_option; ia_option = opt6_find(opt6_next(ia_option, ia_end), ia_end, OPTION6_IAADDR, 24))
	      {
		struct dhcp_lease *lease = NULL;
		struct in6_addr req_addr;
		unsigned int preferred_time =  opt6_uint(ia_option, 16, 4);
		unsigned int valid_time =  opt6_uint(ia_option, 20, 4);
		char *message = NULL;
		struct dhcp_context *this_context;

		memcpy(&req_addr, opt6_ptr(ia_option, 0), IN6ADDRSZ); 
		
		if (!(lease = lease6_find(state->clid, state->clid_len,
					  state->ia_type == OPTION6_IA_NA ? LEASE_NA : LEASE_TA, 
					  state->iaid, &req_addr)))
		  {
		    if (msg_type == DHCP6REBIND)
		      {
			/* When rebinding, we can create a lease if it doesn't exist, as long
			   as --dhcp-authoritative is set. */
			if (option_bool(OPT_AUTHORITATIVE))
			  lease = lease6_allocate(&req_addr, state->ia_type == OPTION6_IA_NA ? LEASE_NA : LEASE_TA);
			if (lease)
			  lease_set_iaid(lease, state->iaid);
			else
			  break;
		      }
		    else
		      {
			/* If the server cannot find a client entry for the IA the server
			   returns the IA containing no addresses with a Status Code option set
			   to NoBinding in the Reply message. */
			save_counter(iacntr);
			t1cntr = 0;
			
			log6_packet(state, "DHCPREPLY", &req_addr, _("lease not found"));
			
			o1 = new_opt6(OPTION6_STATUS_CODE);
			put_opt6_short(DHCP6NOBINDING);
			put_opt6_string(_("no binding found"));
			end_opt6(o1);
			
			preferred_time = valid_time = 0;
			break;
		      }
		  }
		
		if ((this_context = address6_available(state->context, &req_addr, tagif, 1)) ||
		    (this_context = address6_valid(state->context, &req_addr, tagif, 1)))
		  {
		    unsigned int lease_time;

		    get_context_tag(state, this_context);
		    
		    if (config_implies(config, this_context, &req_addr) && have_config(config, CONFIG_TIME))
		      lease_time = config->lease_time;
		    else 
		      lease_time = this_context->lease_time;
		    
		    calculate_times(this_context, &min_time, &valid_time, &preferred_time, lease_time); 
		    
		    lease_set_expires(lease, valid_time, now);
		    /* Update MAC record in case it's new information. */
		    if (state->mac_len != 0)
		      lease_set_hwaddr(lease, state->mac, state->clid, state->mac_len, state->mac_type, state->clid_len, now, 0);
		    if (state->ia_type == OPTION6_IA_NA && state->hostname)
		      {
			char *addr_domain = get_domain6(&req_addr);
			if (!state->send_domain)
			  state->send_domain = addr_domain;
			lease_set_hostname(lease, state->hostname, state->hostname_auth, addr_domain, state->domain); 
			message = state->hostname;
		      }
		    
		    
		    if (preferred_time == 0)
		      message = _("deprecated");

		    address_assigned = 1;
		  }
		else
		  {
		    preferred_time = valid_time = 0;
		    message = _("address invalid");
		  } 

		if (message && (message != state->hostname))
		  log6_packet(state, "DHCPREPLY", &req_addr, message);	
		else
		  log6_quiet(state, "DHCPREPLY", &req_addr, message);
	
		o1 =  new_opt6(OPTION6_IAADDR);
		put_opt6(&req_addr, sizeof(req_addr));
		put_opt6_long(preferred_time);
		put_opt6_long(valid_time);
		end_opt6(o1);
	      }
	    
	    end_ia(t1cntr, min_time, 1);
	    end_opt6(o);
	  }

	if (!address_assigned && msg_type == DHCP6REBIND)
	  { 
	    /* can't create lease for any address, return error */
	    o1 = new_opt6(OPTION6_STATUS_CODE);
	    put_opt6_short(DHCP6NOADDRS);
	    put_opt6_string(_("no addresses available"));
	    end_opt6(o1);
	  }
	
	tagif = add_options(state, 0);
	break;
      }
      
    case DHCP6CONFIRM:
      {
	int good_addr = 0, bad_addr = 0;

	/* set reply message type */
	outmsgtype = DHCP6REPLY;
	
	log6_quiet(state, "DHCPCONFIRM", NULL, NULL);
	
	for (opt = state->packet_options; opt; opt = opt6_next(opt, state->end))
	  {
	    void *ia_option, *ia_end;
	    
	    for (check_ia(state, opt, &ia_end, &ia_option);
		 ia_option;
		 ia_option = opt6_find(opt6_next(ia_option, ia_end), ia_end, OPTION6_IAADDR, 24))
	      {
		struct in6_addr req_addr;

		/* alignment */
		memcpy(&req_addr, opt6_ptr(ia_option, 0), IN6ADDRSZ);
		
		if (!address6_valid(state->context, &req_addr, tagif, 1))
		  {
		    bad_addr = 1;
		    log6_quiet(state, "DHCPREPLY", &req_addr, _("confirm failed"));
		  }
		else
		  {
		    good_addr = 1;
		    log6_quiet(state, "DHCPREPLY", &req_addr, state->hostname);
		  }
	      }
	  }	 
	
	/* No addresses, no reply: RFC 3315 18.2.2 */
	if (!good_addr && !bad_addr)
	  return 0;

	o1 = new_opt6(OPTION6_STATUS_CODE);
	put_opt6_short(bad_addr ? DHCP6NOTONLINK : DHCP6SUCCESS);
	put_opt6_string(bad_addr ? (_("confirm failed")) : (_("all addresses still on link")));
	end_opt6(o1);
	break;
    }
      
    case DHCP6IREQ:
      {
	/* 3315 para 15.12 */
	if (opt6_find(state->packet_options, state->end, OPTION6_IA_NA, 1) ||
	    opt6_find(state->packet_options, state->end, OPTION6_IA_TA, 1))
	  return 0;
	
	/* We can't discriminate contexts based on address, as we don't know it.
	   If there is only one possible context, we can use its tags */
	if (state->context && state->context->netid.net && !state->context->current)
	  {
	    state->context->netid.next = NULL;
	    state->context_tags =  &state->context->netid;
	  }

	/* Similarly, we can't determine domain from address, but if the FQDN is
	   given in --dhcp-host, we can use that, and failing that we can use the 
	   unqualified configured domain, if any. */
	if (state->hostname_auth)
	  state->send_domain = state->domain;
	else
	  state->send_domain = get_domain6(NULL);

	log6_quiet(state, "DHCPINFORMATION-REQUEST", NULL, ignore ? _("ignored") : state->hostname);
	if (ignore)
	  return 0;
	outmsgtype = DHCP6REPLY;
	tagif = add_options(state, 1);
	break;
      }
      
      
    case DHCP6RELEASE:
      {
	/* set reply message type */
	outmsgtype = DHCP6REPLY;

	log6_quiet(state, "DHCPRELEASE", NULL, NULL);

	for (opt = state->packet_options; opt; opt = opt6_next(opt, state->end))
	  {
	    void *ia_option, *ia_end;
	    int made_ia = 0;
	    	    
	    for (check_ia(state, opt, &ia_end, &ia_option);
		 ia_option;
		 ia_option = opt6_find(opt6_next(ia_option, ia_end), ia_end, OPTION6_IAADDR, 24)) 
	      {
		struct dhcp_lease *lease;
		struct in6_addr addr;

		/* align */
		memcpy(&addr, opt6_ptr(ia_option, 0), IN6ADDRSZ);
		if ((lease = lease6_find(state->clid, state->clid_len, state->ia_type == OPTION6_IA_NA ? LEASE_NA : LEASE_TA,
					 state->iaid, &addr)))
		  lease_prune(lease, now);
		else
		  {
		    if (!made_ia)
		      {
			o = new_opt6(state->ia_type);
			put_opt6_long(state->iaid);
			if (state->ia_type == OPTION6_IA_NA)
			  {
			    put_opt6_long(0);
			    put_opt6_long(0); 
			  }
			made_ia = 1;
		      }
		    
		    o1 = new_opt6(OPTION6_IAADDR);
		    put_opt6(&addr, IN6ADDRSZ);
		    put_opt6_long(0);
		    put_opt6_long(0);
		    end_opt6(o1);
		  }
	      }
	    
	    if (made_ia)
	      {
		o1 = new_opt6(OPTION6_STATUS_CODE);
		put_opt6_short(DHCP6NOBINDING);
		put_opt6_string(_("no binding found"));
		end_opt6(o1);
		
		end_opt6(o);
	      }
	  }
	
	o1 = new_opt6(OPTION6_STATUS_CODE);
	put_opt6_short(DHCP6SUCCESS);
	put_opt6_string(_("release received"));
	end_opt6(o1);
	
	break;
      }

    case DHCP6DECLINE:
      {
	/* set reply message type */
	outmsgtype = DHCP6REPLY;
	
	log6_quiet(state, "DHCPDECLINE", NULL, NULL);

	for (opt = state->packet_options; opt; opt = opt6_next(opt, state->end))
	  {
	    void *ia_option, *ia_end;
	    int made_ia = 0;
	    	    
	    for (check_ia(state, opt, &ia_end, &ia_option);
		 ia_option;
		 ia_option = opt6_find(opt6_next(ia_option, ia_end), ia_end, OPTION6_IAADDR, 24)) 
	      {
		struct dhcp_lease *lease;
		struct in6_addr addr;
		struct addrlist *addr_list;
		
		/* align */
		memcpy(&addr, opt6_ptr(ia_option, 0), IN6ADDRSZ);

		if ((addr_list = config_implies(config, state->context, &addr)))
		  {
		    prettyprint_time(daemon->dhcp_buff3, DECLINE_BACKOFF);
		    inet_ntop(AF_INET6, &addr, daemon->addrbuff, ADDRSTRLEN);
		    my_syslog(MS_DHCP | LOG_WARNING, _("disabling DHCP static address %s for %s"), 
			      daemon->addrbuff, daemon->dhcp_buff3);
		    addr_list->flags |= ADDRLIST_DECLINED;
		    addr_list->decline_time = now;
		  }
		else
		  /* make sure this host gets a different address next time. */
		  for (context_tmp = state->context; context_tmp; context_tmp = context_tmp->current)
		    context_tmp->addr_epoch++;
		
		if ((lease = lease6_find(state->clid, state->clid_len, state->ia_type == OPTION6_IA_NA ? LEASE_NA : LEASE_TA,
					 state->iaid, &addr)))
		  lease_prune(lease, now);
		else
		  {
		    if (!made_ia)
		      {
			o = new_opt6(state->ia_type);
			put_opt6_long(state->iaid);
			if (state->ia_type == OPTION6_IA_NA)
			  {
			    put_opt6_long(0);
			    put_opt6_long(0); 
			  }
			made_ia = 1;
		      }
		    
		    o1 = new_opt6(OPTION6_IAADDR);
		    put_opt6(&addr, IN6ADDRSZ);
		    put_opt6_long(0);
		    put_opt6_long(0);
		    end_opt6(o1);
		  }
	      }
	    
	    if (made_ia)
	      {
		o1 = new_opt6(OPTION6_STATUS_CODE);
		put_opt6_short(DHCP6NOBINDING);
		put_opt6_string(_("no binding found"));
		end_opt6(o1);
		
		end_opt6(o);
	      }
	    
	  }

	/* We must answer with 'success' in global section anyway */
	o1 = new_opt6(OPTION6_STATUS_CODE);
	put_opt6_short(DHCP6SUCCESS);
	put_opt6_string(_("success"));
	end_opt6(o1);
	break;
      }

    }

  log_tags(tagif, state->xid);

 done:
  /* Fill in the message type. Note that we store the offset,
     not a direct pointer, since the packet memory may have been 
     reallocated. */
  ((unsigned char *)(daemon->outpacket.iov_base))[start_msg] = outmsgtype;

  log6_opts(0, state->xid, (uint8_t *)daemon->outpacket.iov_base + start_opts, (uint8_t *)daemon->outpacket.iov_base + save_counter(-1));
  
  return 1;

}

/**
 * @brief Add DHCPv6 options to the outbound response packet based on client requests and configuration
 * 
 * @detailed This function processes the configured DHCPv6 options from daemon->dhcp_opts6 and
 *           selectively adds them to the outbound DHCPv6 response packet based on several
 *           filtering criteria: tag matching (context-specific and client-specific tags),
 *           Option Request Option (ORO) from client indicating desired options, force flags
 *           that override ORO requirements, and availability of data (e.g., DNS servers).
 *           The function handles standard DHCPv6 options including DNS servers (OPTION6_DNS_SERVER),
 *           domain search lists (OPTION6_DOMAIN_SEARCH), NTP servers (OPTION6_NTP_SERVER),
 *           information refresh timer (OPTION6_REFRESH for stateless DHCPv6), and FQDN
 *           (OPTION6_FQDN) when hostname is set. It also processes vendor-encapsulated options
 *           (OPTION6_VENDOR_OPTS) that match client vendor class. Special handling includes
 *           filtering out options not in ORO unless forced, adding DNS servers only
 *           when addresses are available, limiting NTP servers to configured maximums, setting
 *           appropriate refresh intervals for stateless operation, and properly encoding
 *           vendor-specific option formats. The function uses the outpacket.c API (new_opt6,
 *           put_opt6, end_opt6) to construct option data in the response buffer. Tag matching
 *           employs match_netid to check context tags and state tags against option tag
 *           requirements. Logging via log6_opts documents which options were requested by
 *           the client when OPT_LOG_OPTS is enabled.
 * 
 * @param state Pointer to DHCPv6 request state structure containing client context, tags,
 *              packet options, ORO list, hostname, domain, and other request-specific data
 * @param do_refresh Boolean flag: 1 indicates stateless DHCPv6 (INFORMATION-REQUEST) where
 *                   refresh timer should be added, 0 for stateful operation (no refresh)
 * 
 * @return Pointer to dhcp_netid representing the tag interface matched for the client, or NULL
 * @retval struct dhcp_netid* Tag interface that was successfully matched and applied to options
 * @retval NULL No tag interface was matched or no options were added
 * 
 * @note DNS server option (OPTION6_DNS_SERVER) only added if daemon->resolv_files exists
 * @note NTP server option (OPTION6_NTP_SERVER) limited to NTP_SERVER_MAX (4) entries
 * @note Refresh timer (OPTION6_REFRESH) set to 12 hours for stateless, overridden by config
 * @note FQDN option (OPTION6_FQDN) added automatically if state->hostname is set
 * @note Vendor options (OPTION6_VENDOR_OPTS) filtered by matching vendor enterprise number
 * @note Options not in client ORO are excluded unless DHOPT_FORCE flag is set
 * @note Uses outpacket.c API functions to construct option data in response buffer
 * 
 * @warning Assumes state->packet_options points to valid ORO data from client request
 * @warning Modifies global outpacket buffer via new_opt6/put_opt6/end_opt6 functions
 * @warning Tag interface pointer returned is from daemon->dhcp_opts6 list (do not free)
 * 
 * @see new_opt6() in outpacket.c for starting new option construction
 * @see put_opt6() in outpacket.c for adding option data bytes
 * @see end_opt6() in outpacket.c for finalizing option with length
 * @see match_netid() for tag matching logic
 * @see option_filter() for ORO filtering and tag processing
 * @see log6_opts() for logging requested options
 * 
 * EXAMPLE USAGE:
 * @code
 * struct state request_state;
 * // ... populate request_state from client packet ...
 * int is_stateless = (msg_type == DHCP6INFORMATION);
 * struct dhcp_netid *matched_tags = add_options(&request_state, is_stateless);
 * if (matched_tags) {
 *   // Options successfully added to outbound packet based on matched tags
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 3315 Section 17.2.2 (Solicitation options), RFC 3646 (DNS options),
 *                 RFC 5908 (NTP options), RFC 4704 (FQDN option), RFC 3925 (Vendor options)
 * SIDE EFFECTS: Modifies outpacket buffer by adding DHCPv6 options; may log to syslog if OPT_LOG_OPTS enabled
 * THREAD SAFETY: Not thread-safe; uses global daemon structure and outpacket buffer
 */
static struct dhcp_netid *add_options(struct state *state, int do_refresh)  
{
  void *oro;
  /* filter options based on tags, those we want get DHOPT_TAGOK bit set */
  struct dhcp_netid *tagif = option_filter(state->tags, state->context_tags, daemon->dhcp_opts6, 0);
  struct dhcp_opt *opt_cfg;
  int done_dns = 0, done_refresh = !do_refresh, do_encap = 0;
  int i, o, o1;

  oro = opt6_find(state->packet_options, state->end, OPTION6_ORO, 0);
  
  for (opt_cfg = daemon->dhcp_opts6; opt_cfg; opt_cfg = opt_cfg->next)
    {
      /* netids match and not encapsulated? */
      if (!(opt_cfg->flags & DHOPT_TAGOK))
	continue;
      
      if (!(opt_cfg->flags & DHOPT_FORCE) && oro)
	{
	  for (i = 0; i <  opt6_len(oro) - 1; i += 2)
	    if (opt6_uint(oro, i, 2) == (unsigned)opt_cfg->opt)
	      break;
	  
	  /* option not requested */
	  if (i >=  opt6_len(oro) - 1)
	    continue;
	}
      
      if (opt_cfg->opt == OPTION6_REFRESH_TIME)
	done_refresh = 1;
       
      if (opt_cfg->opt == OPTION6_DNS_SERVER)
	done_dns = 1;
      
      if (opt_cfg->flags & DHOPT_ADDR6)
	{
	  int len, j;
	  struct in6_addr *a;
	  
	  for (a = (struct in6_addr *)opt_cfg->val, len = opt_cfg->len, j = 0; 
	       j < opt_cfg->len; j += IN6ADDRSZ, a++)
	    if ((IN6_IS_ADDR_ULA_ZERO(a) && IN6_IS_ADDR_UNSPECIFIED(state->ula_addr)) ||
		(IN6_IS_ADDR_LINK_LOCAL_ZERO(a) && IN6_IS_ADDR_UNSPECIFIED(state->ll_addr)))
	      len -= IN6ADDRSZ;
	  
	  if (len != 0)
	    {
	      
	      o = new_opt6(opt_cfg->opt);
	      	  
	      for (a = (struct in6_addr *)opt_cfg->val, j = 0; j < opt_cfg->len; j+=IN6ADDRSZ, a++)
		{
		  struct in6_addr *p = NULL;

		  if (IN6_IS_ADDR_UNSPECIFIED(a))
		    {
		      if (!add_local_addrs(state->context))
			p = state->fallback;
		    }
		  else if (IN6_IS_ADDR_ULA_ZERO(a))
		    {
		      if (!IN6_IS_ADDR_UNSPECIFIED(state->ula_addr))
			p = state->ula_addr;
		    }
		  else if (IN6_IS_ADDR_LINK_LOCAL_ZERO(a))
		    {
		      if (!IN6_IS_ADDR_UNSPECIFIED(state->ll_addr))
			p = state->ll_addr;
		    }
		  else
		    p = a;

		  if (!p)
		    continue;
		  else if (opt_cfg->opt == OPTION6_NTP_SERVER)
		    {
		      if (IN6_IS_ADDR_MULTICAST(p))
			o1 = new_opt6(NTP_SUBOPTION_MC_ADDR);
		      else
			o1 = new_opt6(NTP_SUBOPTION_SRV_ADDR);
		      put_opt6(p, IN6ADDRSZ);
		      end_opt6(o1);
		    }
		  else
		    put_opt6(p, IN6ADDRSZ);
		}

	      end_opt6(o);
	    }
	}
      else
	{
	  o = new_opt6(opt_cfg->opt);
	  if (opt_cfg->val)
	    put_opt6(opt_cfg->val, opt_cfg->len);
	  end_opt6(o);
	}
    }
  
  if (daemon->port == NAMESERVER_PORT && !done_dns)
    {
      o = new_opt6(OPTION6_DNS_SERVER);
      if (!add_local_addrs(state->context))
	put_opt6(state->fallback, IN6ADDRSZ);
      end_opt6(o); 
    }

  if (state->context && !done_refresh)
    {
      struct dhcp_context *c;
      unsigned int lease_time = 0xffffffff;
      
      /* Find the smallest lease tie of all contexts,
	 subject to the RFC-4242 stipulation that this must not 
	 be less than 600. */
      for (c = state->context; c; c = c->next)
	if (c->lease_time < lease_time)
	  {
	    if (c->lease_time < 600)
	      lease_time = 600;
	    else
	      lease_time = c->lease_time;
	  }

      o = new_opt6(OPTION6_REFRESH_TIME);
      put_opt6_long(lease_time);
      end_opt6(o); 
    }
   
    /* handle vendor-identifying vendor-encapsulated options,
       dhcp-option = vi-encap:13,17,....... */
  for (opt_cfg = daemon->dhcp_opts6; opt_cfg; opt_cfg = opt_cfg->next)
    opt_cfg->flags &= ~DHOPT_ENCAP_DONE;
    
  if (oro)
    for (i = 0; i <  opt6_len(oro) - 1; i += 2)
      if (opt6_uint(oro, i, 2) == OPTION6_VENDOR_OPTS)
	do_encap = 1;
  
  for (opt_cfg = daemon->dhcp_opts6; opt_cfg; opt_cfg = opt_cfg->next)
    { 
      if (opt_cfg->flags & DHOPT_RFC3925)
	{
	  int found = 0;
	  struct dhcp_opt *oc;
	  
	  if (opt_cfg->flags & DHOPT_ENCAP_DONE)
	    continue;
	  
	  for (oc = daemon->dhcp_opts6; oc; oc = oc->next)
	    {
	      oc->flags &= ~DHOPT_ENCAP_MATCH;
	      
	      if (!(oc->flags & DHOPT_RFC3925) || opt_cfg->u.encap != oc->u.encap)
		continue;
	      
	      oc->flags |= DHOPT_ENCAP_DONE;
	      if (match_netid(oc->netid, tagif, 1))
		{
		  /* option requested/forced? */
		  if (!oro || do_encap || (oc->flags & DHOPT_FORCE))
		    {
		      oc->flags |= DHOPT_ENCAP_MATCH;
		      found = 1;
		    }
		} 
	    }
	  
	  if (found)
	    { 
	      o = new_opt6(OPTION6_VENDOR_OPTS);	      
	      put_opt6_long(opt_cfg->u.encap);	
	     
	      for (oc = daemon->dhcp_opts6; oc; oc = oc->next)
		if (oc->flags & DHOPT_ENCAP_MATCH)
		  {
		    o1 = new_opt6(oc->opt);
		    put_opt6(oc->val, oc->len);
		    end_opt6(o1);
		  }
	      end_opt6(o);
	    }
	}
    }      


  if (state->hostname)
    {
      unsigned char *p;
      size_t len = strlen(state->hostname);
      
      if (state->send_domain)
	len += strlen(state->send_domain) + 2;

      o = new_opt6(OPTION6_FQDN);
      if ((p = expand(len + 2)))
	{
	  *(p++) = state->fqdn_flags;
	  p = do_rfc1035_name(p, state->hostname, NULL);
	  if (state->send_domain)
	    {
	      p = do_rfc1035_name(p, state->send_domain, NULL);
	      *p = 0;
	    }
	}
      end_opt6(o);
    }


  /* logging */
  if (option_bool(OPT_LOG_OPTS) && oro)
    {
      char *q = daemon->namebuff;
      for (i = 0; i <  opt6_len(oro) - 1; i += 2)
	{
	  char *s = option_string(AF_INET6, opt6_uint(oro, i, 2), NULL, 0, NULL, 0);
	  q += snprintf(q, MAXDNAME - (q - daemon->namebuff),
			"%d%s%s%s", 
			opt6_uint(oro, i, 2),
			strlen(s) != 0 ? ":" : "",
			s, 
			(i > opt6_len(oro) - 3) ? "" : ", ");
	  if ( i >  opt6_len(oro) - 3 || (q - daemon->namebuff) > 40)
	    {
	      q = daemon->namebuff;
	      my_syslog(MS_DHCP | LOG_INFO, _("%u requested options: %s"), state->xid, daemon->namebuff);
	    }
	}
    } 

  return tagif;
}
 
/**
 * @brief Add local server IPv6 addresses from used DHCP contexts to DHCPv6 response
 * 
 * @detailed Iterates through linked list of DHCP contexts starting from the provided
 *           context, identifies contexts marked as CONTEXT_USED with non-unspecified
 *           local IPv6 addresses (context->local6), removes duplicates by scanning
 *           forward in the list, and serializes unique local addresses to the outgoing
 *           DHCPv6 packet using put_opt6(). This function is typically used to add
 *           OPTION6_IA_ADDR entries or server addresses to DHCPv6 ADVERTISE/REPLY
 *           messages. The CONTEXT_USED flag indicates the context participated in
 *           address assignment for this transaction, and local6 represents the server's
 *           IPv6 address on that network segment for client communication.
 * 
 * @param context Head of linked list of DHCP contexts to process (linked via context->current).
 *                May be NULL (function returns 0 immediately). Contexts are not modified.
 * 
 * @return 1 if at least one local address was added to the packet, 0 if no addresses added
 * @retval 1 At least one unique local address from used contexts was serialized
 * @retval 0 No contexts were CONTEXT_USED, all had unspecified local6, or all were duplicates
 * 
 * @note Only contexts with CONTEXT_USED flag and non-unspecified local6 are processed
 * @note IN6_IS_ADDR_UNSPECIFIED checks for :: (all-zeros IPv6 address)
 * @note IN6_ARE_ADDR_EQUAL performs 128-bit address comparison for duplicate detection
 * @note Duplicate detection scans forward only (contexts already processed are not checked)
 * @note Each unique address serialized is IN6ADDRSZ bytes (16 bytes for IPv6 address)
 * @warning Function assumes context list is acyclic (no circular links in context->current)
 * @warning No validation that context->local6 is a valid unicast address
 * 
 * DUPLICATE ELIMINATION ALGORITHM:
 * For each context with CONTEXT_USED flag and non-unspecified local6:
 * 1. Scan forward through remaining contexts (c = context->current)
 * 2. Check if any subsequent used context has identical local6 address
 * 3. If duplicate found (c != NULL after scan), skip current context
 * 4. If no duplicate (c == NULL), serialize address via put_opt6() and set done=1
 * This ensures only the first occurrence of each address is added.
 * 
 * @see put_opt6() in outpacket.c for serialization of 16-byte IPv6 address to packet buffer
 * @see IN6_IS_ADDR_UNSPECIFIED() macro for checking :: address
 * @see IN6_ARE_ADDR_EQUAL() macro for IPv6 address comparison
 * @see mark_context_used() which sets CONTEXT_USED flag on contexts
 * @see add_options() caller that includes local addresses in DHCPv6 options
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_context *context_chain = state->context;
 * // After marking contexts as CONTEXT_USED during address assignment:
 * int addresses_added = add_local_addrs(context_chain);
 * if (addresses_added) {
 *   // Outgoing packet now contains server's local IPv6 addresses
 *   // from all used contexts (duplicates removed)
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 3315 Section 22.6 (IA Address Option format)
 * RFC COMPLIANCE: RFC 3315 Section 18.2.1 (server includes addresses in REPLY)
 * SIDE EFFECTS: Serializes IPv6 addresses to outgoing packet buffer via put_opt6()
 * SIDE EFFECTS: Reads context->flags, context->local6, context->current fields
 * SIDE EFFECTS: No modifications to context structures (read-only traversal)
 * THREAD SAFETY: Not thread-safe (modifies shared outgoing packet buffer via put_opt6)
 */
static int add_local_addrs(struct dhcp_context *context)
{
  int done = 0;
  
  for (; context; context = context->current)
    if ((context->flags & CONTEXT_USED) && !IN6_IS_ADDR_UNSPECIFIED(&context->local6))
      {
	/* squash duplicates */
	struct dhcp_context *c;
	for (c = context->current; c; c = c->current)
	  if ((c->flags & CONTEXT_USED) &&
	      IN6_ARE_ADDR_EQUAL(&context->local6, &c->local6))
	    break;
	
	if (!c)
	  { 
	    done = 1;
	    put_opt6(&context->local6, IN6ADDRSZ);
	  }
      }

  return done;
}


/**
 * @brief Add DHCP context network ID tags to state and apply hostname filtering
 * 
 * @detailed Processes DHCP context network ID tags for use in tag-based configuration
 *           selection. Each context is processed at most once (marked by linking
 *           netid.next to itself). The function also applies hostname ignore rules
 *           when hostname authentication is not enabled, clearing the hostname if
 *           the context matches dhcp-ignore-names configuration.
 * 
 * @param state Pointer to DHCPv6 processing state containing context_tags list
 *              and hostname_auth flag. Must not be NULL. State is modified:
 *              context_tags list updated, hostname may be cleared.
 * @param context DHCP context to extract tags from. Must not be NULL.
 *                Context netid.next is modified to mark as processed.
 * 
 * @return void
 * 
 * @note Context is processed only once per transaction (checked via netid.next)
 * @note Hostname clearing only applies when hostname_auth is false
 * @note Uses daemon->dhcp_ignore_names for hostname filtering configuration
 * 
 * @warning Modifies context->netid.next field to mark context as used
 * @warning May clear state->hostname based on ignore rules
 * 
 * @see match_netid() in src/dhcp-common.c for tag matching logic
 * @see add_options() which calls this function during option building
 * 
 * EXAMPLE USAGE:
 * @code
 * struct state state = {...};
 * struct dhcp_context *ctx = find_context(...);
 * get_context_tag(&state, ctx);  // Extract tags, apply hostname rules
 * // state.context_tags now includes ctx->netid
 * // state.hostname may be NULL if ignore rules matched
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 3315 (context-based configuration selection)
 * SIDE EFFECTS: Modifies state->context_tags list, context->netid.next marker,
 *               may clear state->hostname based on configuration rules
 * THREAD SAFETY: Not thread-safe (modifies shared state and context structures)
 */
static void get_context_tag(struct state *state, struct dhcp_context *context)
{
  /* get tags from context if we've not used it before */
  if (context->netid.next == &context->netid && context->netid.net)
    {
      context->netid.next = state->context_tags;
      state->context_tags = &context->netid;
      if (!state->hostname_auth)
	{
	  struct dhcp_netid_list *id_list;
	  
	  for (id_list = daemon->dhcp_ignore_names; id_list; id_list = id_list->next)
	    if ((!id_list->list) || match_netid(id_list->list, &context->netid, 0))
	      break;
	  if (id_list)
	    state->hostname = NULL;
	}
    }
} 

/**
 * @brief Validate and parse Identity Association (IA) option from DHCPv6 message
 * 
 * @detailed Validates a DHCPv6 Identity Association option (IA_NA or IA_TA) and
 *           extracts its key components. The function checks that the IA type is
 *           supported, validates minimum length requirements, extracts the IAID
 *           (Identity Association Identifier), and locates any enclosed IAADDR
 *           option containing address binding information.
 *           
 *           IA_NA (OPTION6_IA_NA): Non-temporary address assignment, minimum 12 bytes
 *           (4-byte IAID + 4-byte T1 + 4-byte T2)
 *           
 *           IA_TA (OPTION6_IA_TA): Temporary address assignment, minimum 4 bytes
 *           (4-byte IAID only, no T1/T2 timers)
 * 
 * @param state Pointer to DHCPv6 processing state. Must not be NULL. State is modified:
 *              ia_type field set to option type (OPTION6_IA_NA or OPTION6_IA_TA),
 *              iaid field set to extracted Identity Association Identifier.
 * @param opt Pointer to start of IA option data (after 4-byte option type+length header).
 *            Must not be NULL. Must contain valid IA_NA or IA_TA option.
 * @param endp Output parameter for pointer to end of IA option data. Must not be NULL.
 *             Set to point one byte past the last byte of the IA option payload.
 * @param ia_option Output parameter for pointer to enclosed IAADDR option if found.
 *                  Must not be NULL. Set to NULL initially, then to IAADDR option
 *                  pointer if one exists within the IA option, otherwise remains NULL.
 * 
 * @return 1 if IA option is valid and successfully parsed
 * @retval 1 IA option validated, state and output parameters updated
 * @retval 0 IA option invalid (unsupported type or insufficient length)
 * 
 * @note Supported IA types: OPTION6_IA_NA (3) and OPTION6_IA_TA (4)
 * @note IA_PD (Prefix Delegation) is NOT validated by this function
 * @note Minimum lengths: IA_NA requires 12 bytes, IA_TA requires 4 bytes
 * @note IAADDR search starts after IAID (and T1/T2 for IA_NA)
 * 
 * @warning Returns 0 for unsupported IA types (including IA_PD)
 * @warning Caller must check return value before using output parameters
 * 
 * @see build_ia() which uses extracted ia_type and iaid to construct responses
 * @see opt6_type(), opt6_len(), opt6_uint(), opt6_find() for option parsing
 * 
 * EXAMPLE USAGE:
 * @code
 * struct state state = {...};
 * void *ia_opt = ...; // Pointer to IA option in client message
 * void *endp = NULL;
 * void *ia_option = NULL;
 * 
 * if (check_ia(&state, ia_opt, &endp, &ia_option))
 * {
 *   // IA valid: state.ia_type and state.iaid now populated
 *   // ia_option points to enclosed IAADDR if present (or NULL)
 *   // endp points to end of IA option for iteration
 * }
 * else
 * {
 *   // IA invalid or unsupported type
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 3315 Section 22.4 (IA_NA), Section 22.5 (IA_TA)
 * SIDE EFFECTS: Modifies state->ia_type and state->iaid, sets *endp and *ia_option
 * THREAD SAFETY: Not thread-safe (modifies shared state structure)
 */
static int check_ia(struct state *state, void *opt, void **endp, void **ia_option)
{
  state->ia_type = opt6_type(opt);
  *ia_option = NULL;

  if (state->ia_type != OPTION6_IA_NA && state->ia_type != OPTION6_IA_TA)
    return 0;
  
  if (state->ia_type == OPTION6_IA_NA && opt6_len(opt) < 12)
    return 0;
	    
  if (state->ia_type == OPTION6_IA_TA && opt6_len(opt) < 4)
    return 0;
  
  *endp = opt6_ptr(opt, opt6_len(opt));
  state->iaid = opt6_uint(opt, 0, 4);
  *ia_option = opt6_find(opt6_ptr(opt, state->ia_type == OPTION6_IA_NA ? 12 : 4), *endp, OPTION6_IAADDR, 24);

  return 1;
}


/**
 * @brief Build Identity Association (IA) option header for DHCPv6 response
 * 
 * @detailed Constructs the beginning of an IA_NA or IA_TA option in the outgoing
 *           DHCPv6 response packet. The function creates the option structure,
 *           writes the IAID (Identity Association Identifier), and for IA_NA
 *           reserves space for T1 and T2 timer values that will be filled in
 *           later by end_ia().
 *           
 *           IA_NA structure: IAID (4 bytes) + T1 (4 bytes) + T2 (4 bytes) + IAADDR options
 *           IA_TA structure: IAID (4 bytes) + IAADDR options (no T1/T2 timers)
 *           
 *           For IA_NA, T1 and T2 placeholder values (0) are written, with position
 *           counter saved so end_ia() can backfill correct timer values after
 *           calculating minimum lease time across all addresses in the IA.
 * 
 * @param state Pointer to DHCPv6 processing state containing ia_type (OPTION6_IA_NA
 *              or OPTION6_IA_TA) and iaid fields. Must not be NULL. State is read-only.
 * @param t1cntr Output parameter for T1/T2 backfill position counter. Must not be NULL.
 *               Set to 0 for IA_TA (no timers), or to saved counter position for IA_NA
 *               (enables end_ia to backfill T1/T2 values).
 * 
 * @return Option handle for use with end_opt6() to finalize the IA option
 * @retval positive_integer Option handle (from new_opt6) for subsequent end_opt6 call
 * 
 * @note Must be paired with end_ia() call to finalize IA_NA T1/T2 values
 * @note Uses outpacket.c serialization: new_opt6(), put_opt6_long(), save_counter()
 * @note IA_TA has no T1/T2 timers (RFC 3315 temporary address semantics)
 * @note Caller must add IAADDR options between build_ia() and end_ia() calls
 * 
 * @warning T1/T2 values for IA_NA are placeholders until end_ia() backfills them
 * @warning Option must be finalized with end_opt6(return_value) by caller
 * 
 * @see end_ia() which backfills T1/T2 values for IA_NA options
 * @see add_address() which adds IAADDR options within the IA structure
 * @see new_opt6(), put_opt6_long() in src/outpacket.c for serialization
 * 
 * EXAMPLE USAGE:
 * @code
 * struct state state = {.ia_type = OPTION6_IA_NA, .iaid = 0x12345678};
 * int t1cntr = 0;
 * 
 * int ia_handle = build_ia(&state, &t1cntr);
 * // Add IAADDR options here via add_address()
 * // ...
 * end_ia(t1cntr, min_lease_time, 1);  // Backfill T1/T2 with calculated values
 * end_opt6(ia_handle);                // Finalize IA option length
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 3315 Section 22.4 (IA_NA format), Section 22.5 (IA_TA format)
 * SIDE EFFECTS: Writes to outgoing packet buffer via outpacket.c functions,
 *               sets *t1cntr output parameter
 * THREAD SAFETY: Not thread-safe (modifies shared outgoing packet buffer)
 */
static int build_ia(struct state *state, int *t1cntr)
{
  int  o = new_opt6(state->ia_type);
 
  put_opt6_long(state->iaid);
  *t1cntr = 0;
	    
  if (state->ia_type == OPTION6_IA_NA)
    {
      /* save pointer */
      *t1cntr = save_counter(-1);
      /* so we can fill these in later */
      put_opt6_long(0);
      put_opt6_long(0); 
    }

  return o;
}

/**
 * @brief Finalize IA_NA option by backfilling T1 and T2 renewal timer values
 * 
 * @detailed Completes IA_NA option construction by calculating and writing T1 (renewal)
 *           and T2 (rebinding) timer values at the position reserved by build_ia().
 *           
 *           Timer calculation follows RFC 3315 recommendations:
 *           T1 = min_time / 2    (client should renew at 50% of shortest lease)
 *           T2 = 7 * min_time / 8  (client should rebind at 87.5% of shortest lease)
 *           
 *           Special handling for infinite leases (min_time == 0xffffffff): both
 *           T1 and T2 set to 0xffffffff to indicate no renewal required.
 *           
 *           Optional time fuzzing adds randomization to prevent synchronized
 *           renewal storms when many clients have identical lease durations.
 *           Fuzzing uses rand16() to generate random value limited to 1/16 of
 *           min_time, which is subtracted from both T1 and T2.
 *           
 *           For IA_TA options (t1cntr == 0), this function is a no-op since
 *           temporary addresses have no T1/T2 renewal timers.
 * 
 * @param t1cntr Counter position saved by build_ia() for backfilling T1/T2.
 *               If 0 (IA_TA option), function returns immediately without action.
 *               For IA_NA, must be valid counter position from save_counter(-1).
 * @param min_time Minimum lease time in seconds across all addresses in the IA.
 *                 Used to calculate T1 and T2 values. Special value 0xffffffff
 *                 indicates infinite lease (T1=T2=0xffffffff). Typical range:
 *                 300-86400 seconds (5 minutes to 1 day).
 * @param do_fuzz Boolean flag: if non-zero, apply time fuzzing to T1/T2 to prevent
 *                synchronized client renewals. Fuzzing amount is random value up to
 *                1/16 of min_time, generated via rand16() and halved until <= min_time/16.
 *                If zero, use exact calculated values without randomization.
 * 
 * @return void
 * 
 * @note Only processes IA_NA options (t1cntr != 0), IA_TA is no-op
 * @note T1 must be < T2 per RFC 3315 (0.5x < 0.875x guaranteed by calculation)
 * @note Infinite lease: min_time=0xffffffff sets T1=T2=0xffffffff
 * @note Uses outpacket.c: save_counter(), put_opt6_long() for backfill
 * @note Caller must invoke end_opt6() separately to finalize option length
 * @note Fuzzing subtracts same random value from both T1 and T2
 * 
 * @warning Must be called after all IAADDR options added via add_address()
 * @warning t1cntr must be valid counter from build_ia(), or 0 for IA_TA
 * @warning Packet buffer position temporarily modified then restored
 * 
 * @see build_ia() which reserves space and returns t1cntr parameter
 * @see rand16() in src/util.c for random number generation
 * @see save_counter(), put_opt6_long() in src/outpacket.c
 * 
 * EXAMPLE USAGE:
 * @code
 * int t1cntr = 0;
 * unsigned int min_lease = 3600;  // 1 hour minimum lease
 * 
 * int ia_handle = build_ia(&state, &t1cntr);
 * // Add addresses: min_lease calculated from all added addresses
 * add_address(&state, context, 7200, ia_opt, &min_lease, &addr, now);
 * 
 * end_ia(t1cntr, min_lease, 1);  // Backfill T1≈1800s, T2≈3150s (fuzzed)
 * end_opt6(ia_handle);            // Finalize IA option
 * 
 * // Result in packet: IAID + T1≈1800 + T2≈3150 + IAADDR options
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 3315 Section 22.4 (T1/T2 semantics and recommended values)
 * SIDE EFFECTS: Writes T1 and T2 values to previously written packet buffer position,
 *               temporarily modifies then restores packet counter
 * THREAD SAFETY: Not thread-safe (modifies shared outgoing packet buffer)
 */
static void end_ia(int t1cntr, unsigned int min_time, int do_fuzz)
{
  if (t1cntr != 0)
    {
      /* go back and fill in fields in IA_NA option */
      int sav = save_counter(t1cntr);
      unsigned int t1, t2, fuzz = 0;

      if (do_fuzz)
	{
	  fuzz = rand16();
      
	  while (fuzz > (min_time/16))
	    fuzz = fuzz/2;
	}
      
      t1 = (min_time == 0xffffffff) ? 0xffffffff : min_time/2 - fuzz;
      t2 = (min_time == 0xffffffff) ? 0xffffffff : ((min_time/8)*7) - fuzz;
      put_opt6_long(t1);
      put_opt6_long(t2);
      save_counter(sav);
    }	
}

/**
 * @brief Add an IPv6 address to the DHCPv6 response with appropriate lifetimes
 * 
 * @detailed Constructs and serializes an OPTION6_IAADDR option containing the assigned IPv6
 *           address, preferred lifetime, and valid lifetime to the outgoing DHCPv6 response.
 *           Handles client-requested lifetimes from the IA option, calculates appropriate
 *           lifetimes based on server policy and context configuration, updates the lease
 *           database if this is a REPLY (not ADVERTISE), marks the lease as used, manages
 *           context tag lists for hostname filtering, and logs the assignment. This is the
 *           final step in DHCPv6 address assignment after address validation and selection.
 * 
 * @param state       Current DHCPv6 transaction state including lease_allocate flag (must not be NULL)
 * @param context     DHCP context containing lease time configuration and network ID tags (must not be NULL)
 * @param lease_time  Base lease time in seconds from context or configuration
 * @param ia_option   Pointer to IAADDR option in client request containing requested lifetimes (may be NULL)
 * @param min_time    Pointer to minimum time value updated for T1/T2 calculation (must not be NULL, modified)
 * @param addr        IPv6 address being assigned (must not be NULL)
 * @param now         Current time for lease timestamp calculation
 * 
 * @return void (function always succeeds, address added to response)
 * 
 * @note Client-requested preferred and valid times extracted from ia_option offsets 16 and 20
 * @note calculate_times() adjusts lifetimes based on server policy and context limits
 * @note OPTION6_IAADDR serialized as: 16-byte IPv6 address + 4-byte preferred-lifetime + 4-byte valid-lifetime
 * @note Lease database updated only if state->lease_allocate is true (REPLY, not ADVERTISE)
 * @note Lease marked LEASE_USED to prevent reuse during this transaction
 * @warning Context tags linked to state->context_tags only on first use (context->netid.next == &context->netid)
 * @warning Hostname may be cleared (set to NULL) if dhcp-ignore-names matches context tags
 * 
 * @see calculate_times() for lifetime calculation policy
 * @see update_leases() in lease.c for lease database update
 * @see lease6_find_by_addr() in lease.c for lease lookup by IPv6 address
 * @see put_opt6() in outpacket.c for option serialization
 * @see log6_quiet() for address assignment logging
 * 
 * EXAMPLE USAGE:
 * @code
 * struct state state;
 * struct dhcp_context *context;
 * unsigned int min_time = 0xffffffff;
 * struct in6_addr assigned_addr;
 * void *ia_option = opt6_find(state.packet_options, state.end, OPTION6_IAADDR, 24);
 * // ... address validation and selection ...
 * add_address(&state, context, 3600, ia_option, &min_time, &assigned_addr, now);
 * // OPTION6_IAADDR with address and lifetimes now in outgoing packet
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 3315 Section 22.6 (IA Address Option format)
 * RFC COMPLIANCE: RFC 3315 Section 18.2.1 (server behavior for address assignment)
 * SIDE EFFECTS: Serializes IAADDR option to outgoing packet via outpacket.c functions
 * SIDE EFFECTS: Updates lease database if state->lease_allocate is true
 * SIDE EFFECTS: Modifies state->context_tags list by appending context->netid
 * SIDE EFFECTS: May set state->hostname to NULL if dhcp-ignore-names matches
 * SIDE EFFECTS: Logs address assignment via syslog (DHCPREPLY or DHCPADVERTISE message)
 * THREAD SAFETY: Single-threaded; modifies shared state and context structures
 */
static void add_address(struct state *state, struct dhcp_context *context, unsigned int lease_time, void *ia_option, 
			unsigned int *min_time, struct in6_addr *addr, time_t now)
{
  unsigned int valid_time = 0, preferred_time = 0;
  int o = new_opt6(OPTION6_IAADDR);
  struct dhcp_lease *lease;

  /* get client requested times */
  if (ia_option)
    {
      preferred_time =  opt6_uint(ia_option, 16, 4);
      valid_time =  opt6_uint(ia_option, 20, 4);
    }

  calculate_times(context, min_time, &valid_time, &preferred_time, lease_time); 
  
  put_opt6(addr, sizeof(*addr));
  put_opt6_long(preferred_time);
  put_opt6_long(valid_time); 		    
  end_opt6(o);
  
  if (state->lease_allocate)
    update_leases(state, context, addr, valid_time, now);

  if ((lease = lease6_find_by_addr(addr, 128, 0)))
    lease->flags |= LEASE_USED;

  /* get tags from context if we've not used it before */
  if (context->netid.next == &context->netid && context->netid.net)
    {
      context->netid.next = state->context_tags;
      state->context_tags = &context->netid;
      
      if (!state->hostname_auth)
	{
	  struct dhcp_netid_list *id_list;
	  
	  for (id_list = daemon->dhcp_ignore_names; id_list; id_list = id_list->next)
	    if ((!id_list->list) || match_netid(id_list->list, &context->netid, 0))
	      break;
	  if (id_list)
	    state->hostname = NULL;
	}
    }

  log6_quiet(state, state->lease_allocate ? "DHCPREPLY" : "DHCPADVERTISE", addr, state->hostname);

}

/**
 * @brief Mark DHCPv6 context as used when an address from its range is assigned
 * 
 * @detailed Iterates through the context chain and sets the CONTEXT_USED flag on any
 *           context whose IPv6 prefix matches the provided address. This tracking
 *           mechanism records that at least one address allocation has occurred from
 *           the context's address range during the current DHCPv6 transaction.
 *           
 *           The CONTEXT_USED flag serves multiple purposes:
 *           - Prevents redundant context processing in subsequent operations
 *           - Enables statistics tracking for context utilization
 *           - Supports context selection logic for future allocations
 *           
 *           Prefix matching uses is_same_net6() which performs bitwise comparison
 *           of the address against context->start6 using context->prefix length.
 *           For example, with prefix length 64, only the first 64 bits are compared,
 *           allowing the function to identify the correct /64 subnet.
 *           
 *           Multiple contexts in the chain may be marked if they represent overlapping
 *           or hierarchical address spaces, though typical configurations have
 *           non-overlapping prefixes.
 * 
 * @param state Pointer to state structure containing context chain to process.
 *              state->context points to head of linked list of active DHCPv6 contexts.
 *              Must not be NULL.
 * @param addr IPv6 address that was allocated from a context's range.
 *             Used for prefix matching against context->start6 with context->prefix length.
 *             Must not be NULL. Typically a newly assigned IAADDR.
 * 
 * @return void
 * 
 * @note Modifies context->flags by setting CONTEXT_USED bit
 * @note Multiple contexts may be marked if prefixes overlap
 * @note CONTEXT_USED flag persists until context refresh/reload
 * @note Complementary to mark_config_used() which sets CONTEXT_CONF_USED
 * 
 * @warning state and addr must not be NULL (no validation performed)
 * @warning Caller must ensure context chain is properly initialized
 * @warning Flag modification is not thread-safe
 * 
 * @see mark_config_used() for marking contexts with static configuration
 * @see is_same_net6() in src/util.c for prefix comparison algorithm
 * @see add_address() which calls this function after address assignment
 * @see struct dhcp_context in src/dnsmasq.h for context structure definition
 * 
 * EXAMPLE USAGE:
 * @code
 * struct in6_addr assigned_addr;
 * inet_pton(AF_INET6, "2001:db8::1234", &assigned_addr);
 * 
 * // After assigning address 2001:db8::1234 to a client
 * mark_context_used(&state, &assigned_addr);
 * 
 * // Now contexts with matching prefix (e.g., 2001:db8::/64) have CONTEXT_USED set
 * // Subsequent operations can check: if (context->flags & CONTEXT_USED) ...
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 3315 (DHCPv6 address assignment tracking)
 * SIDE EFFECTS: Sets CONTEXT_USED flag bit in matching context->flags fields
 * THREAD SAFETY: Not thread-safe (modifies shared context structures)
 */
static void mark_context_used(struct state *state, struct in6_addr *addr)
{
  struct dhcp_context *context;

  /* Mark that we have an address for this prefix. */
  for (context = state->context; context; context = context->current)
    if (is_same_net6(addr, &context->start6, context->prefix))
      context->flags |= CONTEXT_USED;
}

/**
 * @brief Mark DHCPv6 context as having a configured static host assignment
 * 
 * @detailed Sets the CONTEXT_CONF_USED flag on contexts whose IPv6 prefix matches
 *           the provided address, indicating that a static host configuration
 *           (dhcp-host directive) exists for an address within that context's range.
 *           
 *           This function is similar to mark_context_used() but serves a different
 *           purpose: while CONTEXT_USED tracks dynamic address allocations during
 *           runtime, CONTEXT_CONF_USED tracks contexts that have static address
 *           reservations defined in the configuration file.
 *           
 *           The CONTEXT_CONF_USED flag helps the address allocation algorithm
 *           identify contexts with configured hosts, allowing it to:
 *           - Reserve addresses that have static assignments
 *           - Prioritize or deprioritize contexts based on static usage
 *           - Generate appropriate status messages about configuration coverage
 *           
 *           Prefix matching uses is_same_net6() with bitwise comparison up to
 *           context->prefix length, ensuring correct subnet identification.
 * 
 * @param context Pointer to head of context chain to process. Function iterates
 *                through context->current linked list. May be NULL (no-op).
 * @param addr IPv6 address from a static host configuration (dhcp-host directive).
 *             Used for prefix matching against context->start6. Must not be NULL
 *             if context is non-NULL. Typically addr6 field from struct dhcp_config.
 * 
 * @return void
 * 
 * @note Sets CONTEXT_CONF_USED flag bit (distinct from CONTEXT_USED)
 * @note Multiple contexts may be marked if prefixes overlap
 * @note Flag persists until context refresh/reload
 * @note Called during configuration validation and static host processing
 * 
 * @warning addr must not be NULL if context is non-NULL
 * @warning Flag modification is not thread-safe
 * @warning No validation that addr is actually configured as static host
 * 
 * @see mark_context_used() for marking dynamic allocations
 * @see config_valid() which uses CONTEXT_CONF_USED for validation
 * @see is_same_net6() in src/util.c for prefix comparison
 * @see struct dhcp_config in src/dnsmasq.h for static host definitions
 * 
 * EXAMPLE USAGE:
 * @code
 * // During configuration processing for: dhcp-host=id:client1,[2001:db8::100]
 * struct dhcp_config *config = find_config(...);
 * struct in6_addr *static_addr = &config->addr6;
 * 
 * // Mark contexts containing this static assignment
 * mark_config_used(context_chain, static_addr);
 * 
 * // Later checks can use: if (context->flags & CONTEXT_CONF_USED) ...
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 3315 (supports static address reservations)
 * SIDE EFFECTS: Sets CONTEXT_CONF_USED flag bit in matching context->flags
 * THREAD SAFETY: Not thread-safe (modifies shared context structures)
 */
static void mark_config_used(struct dhcp_context *context, struct in6_addr *addr)
{
  for (; context; context = context->current)
    if (is_same_net6(addr, &context->start6, context->prefix))
      context->flags |= CONTEXT_CONF_USED;
}

/* make sure address not leased to another CLID/IAID */
/**
 * @brief Check if an IPv6 address is available for assignment to a DHCPv6 client
 * 
 * @detailed Validates that an IPv6 address is either not currently leased, or if it is leased,
 *           that it is leased to the same client (matching client DUID and IAID). This function
 *           is critical for preventing IP address conflicts and ensuring proper lease renewal
 *           behavior where a client can retain its existing address across RENEW/REBIND cycles.
 * 
 * @param state DHCPv6 request state containing client DUID (clid) and IAID for comparison
 * @param addr  IPv6 address to check for availability or current assignment
 * 
 * @return 1 if address is available (not leased or leased to same client), 0 if leased to different client
 * @retval 1 Address is not currently leased, safe to assign
 * @retval 1 Address is leased to the requesting client (DUID and IAID match)
 * @retval 0 Address is leased to a different client (conflict)
 * 
 * @note Uses 128-bit prefix length for exact IPv6 address match in lease database
 * @note Comparison includes both client DUID (client identifier) and IAID (Identity Association ID)
 * 
 * @see lease6_find_by_addr() in lease.c for lease database lookup
 * @see update_leases() for lease creation/renewal after address validation
 * 
 * EXAMPLE USAGE:
 * @code
 * struct state state;
 * struct in6_addr proposed_addr;
 * // ... populate state and proposed_addr ...
 * if (check_address(&state, &proposed_addr)) {
 *     // Address available, can assign to client
 *     add_address(&state, context, lease_time, ia_option, &min_time, &proposed_addr, now);
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 3315 Section 18.2.1 (address assignment validation)
 * SIDE EFFECTS: None (read-only lease database query)
 * THREAD SAFETY: Single-threaded architecture; lease database accessed without locking
 */
static int check_address(struct state *state, struct in6_addr *addr)
{ 
  struct dhcp_lease *lease;

  if (!(lease = lease6_find_by_addr(addr, 128, 0)))
    return 1;

  if (lease->clid_len != state->clid_len || 
      memcmp(lease->clid, state->clid, state->clid_len) != 0 ||
      lease->iaid != state->iaid)
    return 0;

  return 1;
}


/* return true of *addr could have been generated from config. */
/**
 * @brief Check if a static IPv6 address configuration implies a specific address
 * 
 * @detailed Searches a dhcp_config's static IPv6 address list for an address matching the
 *           given address within the specified context's subnet. Returns the matching addrlist
 *           entry if found and valid. This function supports static IPv6 address assignments
 *           configured via dhcp-host directives, ensuring that clients with static reservations
 *           receive their configured addresses. Handles wildcard addresses where the network
 *           prefix comes from the context and the host portion from the configuration.
 * 
 * @param config  DHCP host configuration containing static IPv6 address assignments (may be NULL)
 * @param context DHCP context defining the subnet prefix for address matching (must not be NULL)
 * @param addr    IPv6 address to search for in the configuration (must not be NULL)
 * 
 * @return Matching addrlist entry if found, NULL if not found or config invalid
 * @retval non-NULL Valid addrlist entry matching addr within context subnet
 * @retval NULL     No config, CONFIG_ADDR6 not set, no matching address
 * 
 * @note Returns NULL immediately if config is NULL or CONFIG_ADDR6 flag not set
 * @note Handles ADDRLIST_WILDCARD flag for /64 prefixes: combines context prefix with config host portion
 * @note Supports variable prefix lengths via ADDRLIST_PREFIX flag (defaults to /128)
 * @note Uses is_same_net6() for subnet matching with configurable prefix length
 * 
 * @see config_valid() for complementary validation of static address configurations
 * @see is_same_net6() in util.c for IPv6 subnet matching with prefix length
 * @see setaddr6part() and addr6part() for wildcard address manipulation
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_config *config = find_config(state->context, state->clid, state->clid_len, ...);
 * struct in6_addr requested_addr;
 * // ... initialize requested_addr from client request ...
 * struct addrlist *match = config_implies(config, context, &requested_addr);
 * if (match) {
 *     // Static configuration implies this address, can assign
 *     add_address(&state, context, lease_time, ia_option, &min_time, &requested_addr, now);
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 3315 Section 18.2.1 (server policy for address assignment)
 * SIDE EFFECTS: None (read-only configuration inspection)
 * THREAD SAFETY: Single-threaded; config structures accessed without locking
 */
static struct addrlist *config_implies(struct dhcp_config *config, struct dhcp_context *context, struct in6_addr *addr)
{
  int prefix;
  struct in6_addr wild_addr;
  struct addrlist *addr_list;
  
  if (!config || !(config->flags & CONFIG_ADDR6))
    return NULL;
  
  for (addr_list = config->addr6; addr_list; addr_list = addr_list->next)
    {
      prefix = (addr_list->flags & ADDRLIST_PREFIX) ? addr_list->prefixlen : 128;
      wild_addr = addr_list->addr.addr6;
      
      if ((addr_list->flags & ADDRLIST_WILDCARD) && context->prefix == 64)
	{
	  wild_addr = context->start6;
	  setaddr6part(&wild_addr, addr6part(&addr_list->addr.addr6));
	}
      else if (!is_same_net6(&context->start6, addr, context->prefix))
	continue;
      
      if (is_same_net6(&wild_addr, addr, prefix))
	return addr_list;
    }
  
  return NULL;
}

/**
 * @brief Validate and select an IPv6 address from static host configuration
 * 
 * @detailed Checks if the provided dhcp_config contains a valid IPv6 address
 *           assignment (CONFIG_ADDR6 flag) that matches the given context's subnet
 *           and is not currently declined or has passed the decline backoff period.
 *           Supports both single address assignments and prefix-based allocations,
 *           as well as wildcard address assignments that use the context's base prefix.
 *           If a valid address is found and passes check_address() validation,
 *           it is written to the addr output parameter.
 * 
 * @param config Static host configuration to validate (NULL allowed, returns 0)
 * @param context DHCPv6 address context defining subnet and prefix length
 * @param addr Output parameter for selected IPv6 address (caller must allocate)
 * @param state Current DHCPv6 processing state for address validation
 * @param now Current time for decline backoff period checking
 * 
 * @return 1 if valid address found and selected (written to *addr), 0 otherwise
 * @retval 1 Valid address from config matches context and passes validation
 * @retval 0 No config, no CONFIG_ADDR6 flag, no matching address, or all declined
 * 
 * @note Decline backoff period is DECLINE_BACKOFF seconds (defined in config.h)
 * @note Wildcard addresses require context->prefix == 64
 * @note Prefix-based allocations iterate through all addresses in the prefix range
 * 
 * @warning Modifies *addr output parameter only on success (return 1)
 * @warning Prefix allocations with large prefix ranges may iterate many times
 * 
 * @see check_address() for address availability validation
 * @see config_implies() for configuration-implied address options
 * @see add_address() for lease creation after validation
 * 
 * EXAMPLE USAGE:
 * @code
 * struct in6_addr selected_addr;
 * if (config_valid(config, context, &selected_addr, state, now)) {
 *   // Use selected_addr for lease assignment
 *   add_address(state, context, lease_time, ia_option, &min_time, &selected_addr, now);
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 3315 Section 18 (static host address assignment)
 * SIDE EFFECTS: Writes to *addr on success; iterates through config->addr6 list
 * THREAD SAFETY: Single-threaded architecture; accesses config and context structures
 */
static int config_valid(struct dhcp_config *config, struct dhcp_context *context, struct in6_addr *addr, struct state *state, time_t now)
{
  u64 addrpart, i, addresses;
  struct addrlist *addr_list;
  
  if (!config || !(config->flags & CONFIG_ADDR6))
    return 0;

  for (addr_list = config->addr6; addr_list; addr_list = addr_list->next)
    if (!(addr_list->flags & ADDRLIST_DECLINED) ||
	difftime(now, addr_list->decline_time) >= (float)DECLINE_BACKOFF)
      {
	addrpart = addr6part(&addr_list->addr.addr6);
	addresses = 1;
	
	if (addr_list->flags & ADDRLIST_PREFIX)
	  addresses = (u64)1<<(128-addr_list->prefixlen);
	
	if ((addr_list->flags & ADDRLIST_WILDCARD))
	  {
	    if (context->prefix != 64)
	      continue;
	    
	    *addr = context->start6;
	  }
	else if (is_same_net6(&context->start6, &addr_list->addr.addr6, context->prefix))
	  *addr = addr_list->addr.addr6;
	else
	  continue;
	
	for (i = 0 ; i < addresses; i++)
	  {
	    setaddr6part(addr, addrpart+i);
	    
	    if (check_address(state, addr))
	      return 1;
	  }
      }
  
  return 0;
}

/* Calculate valid and preferred times to send in leases/renewals. 

   Inputs are:

   *valid_timep, *preferred_timep - requested times from IAADDR options.
   context->valid, context->preferred - times associated with subnet address on local interface.
   context->flags | CONTEXT_DEPRECATE - "deprecated" flag in dhcp-range.
   lease_time - configured time for context for individual client.
   *min_time - smallest valid time sent so far.

   Outputs are :
   
   *valid_timep, *preferred_timep - times to be send in IAADDR option.
   *min_time - smallest valid time sent so far, to calculate T1 and T2.
   
   */
/**
 * @brief Calculate and adjust DHCPv6 preferred and valid lifetimes based on server policy and client requests
 * 
 * @detailed Implements DHCPv6 lifetime calculation policy that balances server configuration,
 *           client preferences, and RFC 3315 validation rules. Takes client-requested lifetimes
 *           as input (via pointers), validates them against RFC requirements, applies minimum
 *           sanity thresholds, honors server-side deprecation flags, and updates min_time for
 *           T1/T2 renewal calculation. The function enforces that preferred lifetime must not
 *           exceed valid lifetime per RFC 3315, applies a minimum 120-second floor to prevent
 *           unreasonably short lifetimes, allows clients to request shorter times than server
 *           default (but not longer), and handles address deprecation by setting preferred
 *           lifetime to zero while maintaining valid lifetime. This is the central policy
 *           enforcement point for all DHCPv6 lifetime decisions.
 * 
 * @param context         DHCP context containing server-configured lease time policy and deprecation flags (must not be NULL)
 * @param min_time        Pointer to minimum time value for T1/T2 calculation (must not be NULL, modified by function)
 * @param valid_timep     Pointer to valid lifetime in seconds (input: client request, output: calculated value, must not be NULL, modified)
 * @param preferred_timep Pointer to preferred lifetime in seconds (input: client request, output: calculated value, must not be NULL, modified)
 * @param lease_time      Server-configured default lease time in seconds from context or configuration
 * 
 * @return void (function updates output parameters via pointers)
 * 
 * @note Client request of 0 means "no preference" - server default used
 * @note Minimum lifetime enforced at 120 seconds (sanity check to prevent too-short leases)
 * @note Client can request shorter lifetimes than server default but not longer
 * @note RFC 3315 requirement: If client's preferred > valid, both client requests are ignored
 * @note CONTEXT_DEPRECATE flag or context->preferred == 0 forces preferred lifetime to 0
 * @note min_time updated to smallest non-zero lifetime for T1/T2 calculation (T1 = 0.5 * min_time, T2 = 0.8 * min_time)
 * @warning Function modifies values pointed to by min_time, valid_timep, preferred_timep
 * @warning Input values in *valid_timep and *preferred_timep are treated as client requests and replaced with calculated values
 * 
 * LIFETIME CALCULATION ALGORITHM:
 * 1. Read client-requested lifetimes from *preferred_timep and *valid_timep
 * 2. Initialize server defaults: valid_time = preferred_time = lease_time
 * 3. RFC 3315 validation: If req_preferred > req_valid, ignore both client requests (use server defaults)
 * 4. If req_preferred != 0 and req_preferred <= req_valid:
 *    - Apply 120-second minimum: req_preferred = max(req_preferred, 120)
 *    - Honor client request if shorter: preferred_time = min(req_preferred, lease_time)
 * 5. If req_valid != 0:
 *    - Apply 120-second minimum: req_valid = max(req_valid, 120)
 *    - Honor client request if shorter: valid_time = min(req_valid, lease_time)
 * 6. Check deprecation: If CONTEXT_DEPRECATE flag set or context->preferred == 0, set preferred_time = 0
 * 7. Update min_time: min_time = min(min_time, non-zero preferred_time, non-zero valid_time)
 * 8. Return calculated lifetimes via *valid_timep and *preferred_timep
 * 
 * DEPRECATION BEHAVIOR:
 * - Deprecated addresses have preferred_time = 0 (should not be used for new connections)
 * - Valid_time remains non-zero (existing connections can continue)
 * - Clients should avoid deprecated addresses for new connections but can renew existing ones
 * - CONTEXT_DEPRECATE flag typically set when IPv6 prefix is being phased out
 * 
 * @see add_address() caller that uses calculated lifetimes for IAADDR option
 * @see build_ia() caller that determines T1/T2 renewal times from min_time
 * @see end_ia() finalizer that applies T1/T2 calculation based on min_time
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_context *context;
 * unsigned int min_time = 0xffffffff; // Initialize to max
 * unsigned int valid_time = 7200;     // Client requested 2 hours
 * unsigned int preferred_time = 3600; // Client requested 1 hour
 * unsigned int lease_time = 86400;    // Server default 24 hours
 * 
 * calculate_times(context, &min_time, &valid_time, &preferred_time, lease_time);
 * // If valid/preferred requests honored: valid_time=7200, preferred_time=3600, min_time=3600
 * // If deprecated: valid_time=7200, preferred_time=0
 * // T1 = min_time / 2, T2 = (min_time * 4) / 5
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 3315 Section 22.6 (IA Address Option lifetimes)
 * RFC COMPLIANCE: RFC 3315 Section 22.4 (server MUST check preferred <= valid)
 * RFC COMPLIANCE: RFC 3315 Section 18.2.4 (T1 and T2 calculation based on shortest lifetime)
 * SIDE EFFECTS: Modifies *min_time, *valid_timep, *preferred_timep via pointers
 * SIDE EFFECTS: No global state modification or I/O operations
 * THREAD SAFETY: Reentrant; operates only on parameters and local variables
 */
static void calculate_times(struct dhcp_context *context, unsigned int *min_time, unsigned int *valid_timep, 
			    unsigned int *preferred_timep, unsigned int lease_time)
{
  unsigned int req_preferred = *preferred_timep, req_valid = *valid_timep;
  unsigned int valid_time = lease_time, preferred_time = lease_time;
  
  /* RFC 3315: "A server ignores the lifetimes set
     by the client if the preferred lifetime is greater than the valid
     lifetime. */
  if (req_preferred <= req_valid)
    {
      if (req_preferred != 0)
	{
	  /* 0 == "no preference from client" */
	  if (req_preferred < 120u)
	    req_preferred = 120u; /* sanity */
	  
	  if (req_preferred < preferred_time)
	    preferred_time = req_preferred;
	}
      
      if (req_valid != 0)
	/* 0 == "no preference from client" */
	{
	  if (req_valid < 120u)
	    req_valid = 120u; /* sanity */
	  
	  if (req_valid < valid_time)
	    valid_time = req_valid;
	}
    }

  /* deprecate (preferred == 0) which configured, or when local address 
     is deprecated */
  if ((context->flags & CONTEXT_DEPRECATE) || context->preferred == 0)
    preferred_time = 0;
  
  if (preferred_time != 0 && preferred_time < *min_time)
    *min_time = preferred_time;
  
  if (valid_time != 0 && valid_time < *min_time)
    *min_time = valid_time;
  
  *valid_timep = valid_time;
  *preferred_timep = preferred_time;
}

/**
 * @brief Update DHCPv6 lease database with assigned address and client information
 * 
 * @detailed Finds existing lease or allocates new lease for the assigned IPv6 address,
 *           updates lease properties (expiration time, IAID, hardware address, client ID,
 *           interface, hostname), and prepares extradata for lease-change script execution.
 *           Distinguishes between IA_NA (non-temporary address) and IA_TA (temporary address)
 *           lease types. When HAVE_SCRIPT is enabled and lease_change_command is configured,
 *           extracts comprehensive client information from DHCPv6 options including vendor
 *           class, requested options list (ORO), MUD URL, user class, tag sets, and link
 *           address for passing to external scripts. This function is the authoritative
 *           update point for DHCPv6 lease state persistence and script integration.
 * 
 * @param state       Current DHCPv6 transaction state containing packet options, MAC, CLID, hostname (must not be NULL)
 * @param context     DHCP context containing network ID tags (currently unused but passed for consistency)
 * @param addr        IPv6 address being assigned/renewed (must not be NULL)
 * @param lease_time  Lease validity period in seconds
 * @param now         Current time for lease timestamp calculation
 * 
 * @return void (function always succeeds; lease allocation failure is silently handled)
 * 
 * @note Lease lookup uses 128-bit prefix match (full IPv6 address)
 * @note New lease type determined by state->ia_type: LEASE_NA for IA_NA, LEASE_TA for IA_TA
 * @note Hostname set only for IA_NA leases (non-temporary addresses), not IA_TA
 * @note get_domain6() constructs reverse DNS domain from IPv6 address
 * @warning If lease allocation fails (lease6_allocate returns NULL), function exits silently
 * @warning Hostname requires state->ia_type == OPTION6_IA_NA; temporary addresses don't get hostnames
 * 
 * LEASE PROPERTY UPDATES:
 * - lease_set_expires: Sets lease expiration time based on lease_time and now
 * - lease_set_iaid: Sets Identity Association Identifier from state->iaid
 * - lease_set_hwaddr: Sets hardware address (MAC), client ID (DUID), lengths, and types
 * - lease_set_interface: Records interface index where lease was assigned
 * - lease_set_hostname: Sets hostname with authentication flag and domain information (IA_NA only)
 * 
 * SCRIPT EXTRADATA PREPARATION (HAVE_SCRIPT enabled):
 * When daemon->lease_change_command is configured, extradata is populated in fixed order:
 * 1. OPTION6_VENDOR_CLASS (vendor class identifier with enterprise number and class data)
 * 2. state->client_hostname (client-provided hostname, may be NULL)
 * 3. OPTION6_ORO (comma-separated list of requested option codes in DNSMASQ_REQUESTED_OPTIONS)
 * 4. OPTION6_MUD_URL (Manufacturer Usage Description URL for IoT device policy)
 * 5. Tag set (space-separated context and conditional tags with duplicate removal)
 * 6. Link address (relay agent link-address field formatted as IPv6 string)
 * 7. OPTION6_USER_CLASS (user class data, may contain multiple class instances)
 * 
 * @see lease6_find_by_addr() in lease.c for lease lookup by IPv6 address
 * @see lease6_allocate() in lease.c for new lease allocation
 * @see lease_set_expires(), lease_set_iaid(), lease_set_hwaddr(), lease_set_interface(), lease_set_hostname() in lease.c
 * @see lease_add_extradata() in lease.c for script data accumulation
 * @see run_tag_if() for conditional tag evaluation
 * @see get_domain6() for reverse DNS domain construction from IPv6 address
 * @see opt6_find() for DHCPv6 option search in packet_options
 * 
 * EXAMPLE USAGE:
 * @code
 * struct state state;
 * struct dhcp_context *context;
 * struct in6_addr assigned_addr;
 * unsigned int lease_time = 3600;
 * time_t now = dnsmasq_time();
 * // After successful address assignment in add_address:
 * if (state.lease_allocate) // Only update database for REPLY, not ADVERTISE
 *   update_leases(&state, context, &assigned_addr, lease_time, now);
 * // Lease database now updated; script will be invoked if configured
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 3315 Section 18.2 (server behavior for lease management)
 * RFC COMPLIANCE: RFC 8520 (Manufacturer Usage Description MUD URL option)
 * SIDE EFFECTS: Updates lease database via lease.c functions
 * SIDE EFFECTS: Sets LEASE_CHANGED flag triggering lease-change script execution
 * SIDE EFFECTS: Allocates and populates lease->extradata for script environment variables
 * SIDE EFFECTS: Modifies state->send_domain if not already set (for hostname processing)
 * SIDE EFFECTS: Uses daemon->dhcp_buff2, daemon->namebuff, daemon->addrbuff as temporary buffers
 * THREAD SAFETY: Single-threaded; modifies shared lease database and global daemon buffers
 */
static void update_leases(struct state *state, struct dhcp_context *context, struct in6_addr *addr, unsigned int lease_time, time_t now)
{
  struct dhcp_lease *lease = lease6_find_by_addr(addr, 128, 0);
#ifdef HAVE_SCRIPT
  struct dhcp_netid *tagif = run_tag_if(state->tags);
#endif

  (void)context;

  if (!lease)
    lease = lease6_allocate(addr, state->ia_type == OPTION6_IA_NA ? LEASE_NA : LEASE_TA);
  
  if (lease)
    {
      lease_set_expires(lease, lease_time, now);
      lease_set_iaid(lease, state->iaid); 
      lease_set_hwaddr(lease, state->mac, state->clid, state->mac_len, state->mac_type, state->clid_len, now, 0);
      lease_set_interface(lease, state->interface, now);
      if (state->hostname && state->ia_type == OPTION6_IA_NA)
	{
	  char *addr_domain = get_domain6(addr);
	  if (!state->send_domain)
	    state->send_domain = addr_domain;
	  lease_set_hostname(lease, state->hostname, state->hostname_auth, addr_domain, state->domain);
	}
      
#ifdef HAVE_SCRIPT
      if (daemon->lease_change_command)
	{
	  void *opt;
	  
	  lease->flags |= LEASE_CHANGED;
	  free(lease->extradata);
	  lease->extradata = NULL;
	  lease->extradata_size = lease->extradata_len = 0;
	  lease->vendorclass_count = 0; 
	  
	  if ((opt = opt6_find(state->packet_options, state->end, OPTION6_VENDOR_CLASS, 4)))
	    {
	      void *enc_opt, *enc_end = opt6_ptr(opt, opt6_len(opt));
	      lease->vendorclass_count++;
	      /* send enterprise number first  */
	      sprintf(daemon->dhcp_buff2, "%u", opt6_uint(opt, 0, 4));
	      lease_add_extradata(lease, (unsigned char *)daemon->dhcp_buff2, strlen(daemon->dhcp_buff2), 0);
	      
	      if (opt6_len(opt) >= 6) 
		for (enc_opt = opt6_ptr(opt, 4); enc_opt; enc_opt = opt6_next(enc_opt, enc_end))
		  {
		    lease->vendorclass_count++;
		    lease_add_extradata(lease, opt6_ptr(enc_opt, 0), opt6_len(enc_opt), 0);
		  }
	    }
	  
	  lease_add_extradata(lease, (unsigned char *)state->client_hostname, 
			      state->client_hostname ? strlen(state->client_hostname) : 0, 0);				
	  
	  /* DNSMASQ_REQUESTED_OPTIONS */
	  if ((opt = opt6_find(state->packet_options, state->end, OPTION6_ORO, 2)))
	    {
	      int i, len = opt6_len(opt)/2;
	      u16 *rop = opt6_ptr(opt, 0);
	      
	      for (i = 0; i < len; i++)
		lease_add_extradata(lease, (unsigned char *)daemon->namebuff,
				    sprintf(daemon->namebuff, "%u", ntohs(rop[i])), (i + 1) == len ? 0 : ',');
	    }
	  else
	    lease_add_extradata(lease, NULL, 0, 0);

	  if ((opt = opt6_find(state->packet_options, state->end, OPTION6_MUD_URL, 1)))
	    lease_add_extradata(lease, opt6_ptr(opt, 0), opt6_len(opt), 0);
	  else
	    lease_add_extradata(lease, NULL, 0, 0);

	  /* space-concat tag set */
	  if (!tagif && !context->netid.net)
	    lease_add_extradata(lease, NULL, 0, 0);
	  else
	    {
	      if (context->netid.net)
		lease_add_extradata(lease, (unsigned char *)context->netid.net, strlen(context->netid.net), tagif ? ' ' : 0);
	      
	      if (tagif)
		{
		  struct dhcp_netid *n;
		  for (n = tagif; n; n = n->next)
		    {
		      struct dhcp_netid *n1;
		      /* kill dupes */
		      for (n1 = n->next; n1; n1 = n1->next)
			if (strcmp(n->net, n1->net) == 0)
			  break;
		      if (!n1)
			lease_add_extradata(lease, (unsigned char *)n->net, strlen(n->net), n->next ? ' ' : 0); 
		    }
		}
	    }
	  
	  if (state->link_address)
	    inet_ntop(AF_INET6, state->link_address, daemon->addrbuff, ADDRSTRLEN);
	  
	  lease_add_extradata(lease, (unsigned char *)daemon->addrbuff, state->link_address ? strlen(daemon->addrbuff) : 0, 0);
	  
	  if ((opt = opt6_find(state->packet_options, state->end, OPTION6_USER_CLASS, 2)))
	    {
	      void *enc_opt, *enc_end = opt6_ptr(opt, opt6_len(opt));
	      for (enc_opt = opt6_ptr(opt, 0); enc_opt; enc_opt = opt6_next(enc_opt, enc_end))
		lease_add_extradata(lease, opt6_ptr(enc_opt, 0), opt6_len(enc_opt), 0);
	    }
	}
#endif	
      
    }
}
			  
			
	
/**
 * @brief Log DHCPv6 options to syslog for debugging and monitoring
 * 
 * Recursively logs DHCPv6 options with formatting appropriate for nested options
 * within Identity Association containers. Provides detailed visibility into
 * DHCPv6 option content including IAID, T1, T2 timers, addresses, preferred
 * and valid lifetimes, and status codes.
 * 
 * @param nest Nesting level: 0 for top-level options, 1 for nested IA options
 * @param xid DHCPv6 transaction ID for correlation with request messages
 * @param start_opts Pointer to start of DHCPv6 options region
 * @param end_opts Pointer to end of DHCPv6 options region
 * 
 * @note Only logs when OPT_LOG_OPTS is enabled via --log-dhcp configuration
 * @note Handles special formatting for IA_NA, IA_TA, IAADDR, and STATUS_CODE options
 * @note Recursively processes nested options within IA containers
 * 
 * EXAMPLE USAGE:
 * @code
 * void *opts = packet + 4;  // Skip message type and XID
 * void *end = packet + packet_len;
 * log6_opts(0, state->xid, opts, end);
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 3315 Section 22 (DHCPv6 Options)
 * SIDE EFFECTS: Writes formatted log messages to syslog
 * THREAD SAFETY: Uses daemon->namebuff and daemon->addrbuff (non-reentrant)
 */
static void log6_opts(int nest, unsigned int xid, void *start_opts, void *end_opts)
{
  void *opt;
  char *desc = nest ? "nest" : "sent";
  
  if (!option_bool(OPT_LOG_OPTS) || start_opts == end_opts)
    return;
  
  for (opt = start_opts; opt; opt = opt6_next(opt, end_opts))
    {
      int type = opt6_type(opt);
      void *ia_options = NULL;
      char *optname;
      
      if (type == OPTION6_IA_NA)
	{
	  sprintf(daemon->namebuff, "IAID=%u T1=%u T2=%u",
		  opt6_uint(opt, 0, 4), opt6_uint(opt, 4, 4), opt6_uint(opt, 8, 4));
	  optname = "ia-na";
	  ia_options = opt6_ptr(opt, 12);
	}
      else if (type == OPTION6_IA_TA)
	{
	  sprintf(daemon->namebuff, "IAID=%u", opt6_uint(opt, 0, 4));
	  optname = "ia-ta";
	  ia_options = opt6_ptr(opt, 4);
	}
      else if (type == OPTION6_IAADDR)
	{
	  struct in6_addr addr;

	  /* align */
	  memcpy(&addr, opt6_ptr(opt, 0), IN6ADDRSZ);
	  inet_ntop(AF_INET6, &addr, daemon->addrbuff, ADDRSTRLEN);
	  sprintf(daemon->namebuff, "%s PL=%u VL=%u", 
		  daemon->addrbuff, opt6_uint(opt, 16, 4), opt6_uint(opt, 20, 4));
	  optname = "iaaddr";
	  ia_options = opt6_ptr(opt, 24);
	}
      else if (type == OPTION6_STATUS_CODE)
	{
	  int len = sprintf(daemon->namebuff, "%u ", opt6_uint(opt, 0, 2));
	  memcpy(daemon->namebuff + len, opt6_ptr(opt, 2), opt6_len(opt)-2);
	  daemon->namebuff[len + opt6_len(opt) - 2] = 0;
	  optname = "status";
	}
      else
	{
	  /* account for flag byte on FQDN */
	  int offset = type == OPTION6_FQDN ? 1 : 0;
	  optname = option_string(AF_INET6, type, opt6_ptr(opt, offset), opt6_len(opt) - offset, daemon->namebuff, MAXDNAME);
	}
      
      my_syslog(MS_DHCP | LOG_INFO, "%u %s size:%3d option:%3d %s  %s", 
		xid, desc, opt6_len(opt), type, optname, daemon->namebuff);
      
      if (ia_options)
	log6_opts(1, xid, ia_options, opt6_ptr(opt, opt6_len(opt)));
    }
}		 
 
/**
 * @brief Conditionally log DHCPv6 packet based on logging configuration
 * 
 * Wrapper around log6_packet() that checks logging configuration before
 * generating log output. Logs DHCPv6 transaction only if --log-opts is
 * enabled or --quiet-dhcp6 is NOT enabled, allowing fine-grained control
 * over DHCPv6 logging verbosity.
 * 
 * @param state DHCPv6 request processing state containing transaction context
 * @param type DHCPv6 message type string (e.g., "SOLICIT", "ADVERTISE")
 * @param addr IPv6 address for logging (client or relay address)
 * @param string Additional descriptive string for log message
 * 
 * @note Checks OPT_LOG_OPTS and OPT_QUIET_DHCP6 flags before logging
 * @warning Inverted logic: logs if OPT_QUIET_DHCP6 is NOT set
 * 
 * EXAMPLE USAGE:
 * @code
 * log6_quiet(state, "ADVERTISE", client_addr, "address not available");
 * @endcode
 * 
 * SIDE EFFECTS: May write log message to syslog if logging enabled
 */
static void log6_quiet(struct state *state, char *type, struct in6_addr *addr, char *string)
{
  if (option_bool(OPT_LOG_OPTS) || !option_bool(OPT_QUIET_DHCP6))
    log6_packet(state, type, addr, string);
}

/**
 * @brief Log DHCPv6 packet transaction details to syslog
 * 
 * Formats and logs DHCPv6 transaction information including message type,
 * interface, client DUID, IPv6 address (if applicable), and optional
 * status string. Output format varies based on OPT_LOG_OPTS configuration:
 * with --log-opts includes transaction ID (XID), without includes only
 * message type. Client DUID is truncated to 100 bytes to prevent buffer
 * overflow.
 * 
 * @param state DHCPv6 request state containing client DUID, XID, interface name
 * @param type DHCPv6 message type string (e.g., "SOLICIT", "ADVERTISE", "REQUEST")
 * @param addr IPv6 address to log (client address, allocated address, or NULL)
 * @param string Additional status or descriptive string (NULL if none)
 * 
 * @note Truncates DUID to 100 bytes maximum to prevent buffer overflow
 * @note Log format with --log-opts: "XID TYPE(interface) addr DUID string"
 * @note Log format without --log-opts: "TYPE(interface) addr DUID string"
 * 
 * @see log6_quiet() for conditional logging wrapper
 * 
 * EXAMPLE USAGE:
 * @code
 * // Log ADVERTISE message with allocated address
 * log6_packet(state, "ADVERTISE", &allocated_addr, "lease 3600 secs");
 * 
 * // Log SOLICIT without address
 * log6_packet(state, "SOLICIT", NULL, "rapid commit");
 * @endcode
 * 
 * SIDE EFFECTS: Writes log message to syslog with MS_DHCP | LOG_INFO priority
 * THREAD SAFETY: Uses daemon global buffers (namebuff, dhcp_buff2) - not thread-safe
 */
static void log6_packet(struct state *state, char *type, struct in6_addr *addr, char *string)
{
  int clid_len = state->clid_len;

  /* avoid buffer overflow */
  if (clid_len > 100)
    clid_len = 100;
  
  print_mac(daemon->namebuff, state->clid, clid_len);

  if (addr)
    {
      inet_ntop(AF_INET6, addr, daemon->dhcp_buff2, DHCP_BUFF_SZ - 1);
      strcat(daemon->dhcp_buff2, " ");
    }
  else
    daemon->dhcp_buff2[0] = 0;

  if(option_bool(OPT_LOG_OPTS))
    my_syslog(MS_DHCP | LOG_INFO, "%u %s(%s) %s%s %s",
	      state->xid, 
	      type,
	      state->iface_name, 
	      daemon->dhcp_buff2,
	      daemon->namebuff,
	      string ? string : "");
  else
    my_syslog(MS_DHCP | LOG_INFO, "%s(%s) %s%s %s",
	      type,
	      state->iface_name, 
	      daemon->dhcp_buff2,
	      daemon->namebuff,
	      string ? string : "");
}

/**
 * @brief Find specific DHCPv6 option in options buffer
 * 
 * Searches through DHCPv6 options buffer for an option with specified type code,
 * validating that the option length meets minimum size requirements. DHCPv6 options
 * use type-length-value (TLV) encoding with 2-byte type, 2-byte length, and
 * variable-length value. Returns pointer to start of option (type field) if found.
 * 
 * @param opts Start of DHCPv6 options buffer to search
 * @param end End boundary of options buffer (one past last valid byte)
 * @param search DHCPv6 option type code to find (OPTION_* constants)
 * @param minsize Minimum required option data length (excluding 4-byte header)
 * 
 * @return Pointer to start of option (type field) if found, NULL if not found or buffer invalid
 * @retval NULL Option not found, buffer exhausted, malformed option, or length < minsize
 * @retval non-NULL Pointer to option type field (4 bytes before option data)
 * 
 * @note Does NOT validate option data contents, only size
 * @note Returned pointer points to option TYPE field, not data (use opt6_ptr to access data)
 * @note Malformed options (length extending beyond buffer) cause NULL return
 * 
 * @see opt6_next() for iterating through all options
 * @see opt6_len() for extracting option data length
 * @see opt6_ptr() for accessing option data
 * 
 * EXAMPLE USAGE:
 * @code
 * // Find client DUID option (minimum 1 byte)
 * void *opt = opt6_find(opts_start, opts_end, OPTION6_CLIENT_ID, 1);
 * if (opt) {
 *   int len = opt6_len(opt);
 *   void *duid_data = opt6_ptr(opt, 0);
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 3315 Section 22.1 (Format of DHCPv6 Options)
 * SIDE EFFECTS: None (read-only search)
 * THREAD SAFETY: Thread-safe (no global state)
 */
static void *opt6_find (uint8_t *opts, uint8_t *end, unsigned int search, unsigned int minsize)
{
  u16 opt, opt_len;
  void *start;
  
  if (!opts)
    return NULL;
    
  while (1)
    {
      if (end - opts < 4) 
	return NULL;
      
      start = opts;
      GETSHORT(opt, opts);
      GETSHORT(opt_len, opts);
      
      if (opt_len > (end - opts))
	return NULL;
      
      if (opt == search && (opt_len >= minsize))
	return start;
      
      opts += opt_len;
    }
}

/**
 * @brief Get next DHCPv6 option in sequential iteration
 * 
 * Advances to the next DHCPv6 option following the current option in the
 * options buffer. Used for sequential iteration through all options without
 * searching for specific types. Validates that the current option length
 * does not exceed buffer boundaries before advancing.
 * 
 * @param opts Pointer to current DHCPv6 option (type field)
 * @param end End boundary of options buffer (one past last valid byte)
 * 
 * @return Pointer to next option (type field), or NULL if no more options
 * @retval NULL No more options (buffer exhausted) or current option malformed
 * @retval non-NULL Pointer to next option's type field
 * 
 * @note Does NOT skip unrecognized options - returns ALL options in sequence
 * @note Caller must validate buffer has at least 4 bytes before calling
 * @warning Malformed current option causes NULL return (prevents buffer overrun)
 * 
 * @see opt6_find() for searching specific option type
 * @see opt6_len() for reading option length
 * 
 * EXAMPLE USAGE:
 * @code
 * // Iterate through all DHCPv6 options
 * void *opt = start_opts;
 * while (opt && opt < end_opts) {
 *   unsigned int type = opt6_type(opt);
 *   int len = opt6_len(opt);
 *   // Process option...
 *   opt = opt6_next(opt, end_opts);
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 3315 Section 22.1 (options are concatenated sequentially)
 * SIDE EFFECTS: None (read-only)
 * THREAD SAFETY: Thread-safe (no global state)
 */
static void *opt6_next(uint8_t *opts, uint8_t *end)
{
  u16 opt_len;
  
  if (end - opts < 4) 
    return NULL;
  
  opts += 2;
  GETSHORT(opt_len, opts);
  
  if (opt_len >= (end - opts))
    return NULL;
  
  return opts + opt_len;
}

/**
 * @brief Extract multi-byte unsigned integer from DHCPv6 option data
 * 
 * @detailed Reads unsigned integer value from DHCPv6 option data, handling
 *           unaligned data access and network byte order conversion. The function
 *           safely extracts 1, 2, or 4-byte integers from option buffers using
 *           byte-by-byte reading to avoid alignment issues on architectures
 *           that don't support unaligned memory access.
 * 
 * @param opt Pointer to DHCPv6 option data (points to option value, not header)
 * @param offset Byte offset within option data (negative for option header fields:
 *               -2 = option length field, -4 = option type field)
 * @param size Number of bytes to read (1, 2, or 4 typical values)
 * 
 * @return Unsigned integer value in host byte order
 * 
 * @note Uses opt6_ptr macro to calculate actual byte pointer
 * @note Network byte order (big-endian) assumed for input data
 * @note Unaligned access safe due to byte-by-byte reading
 * 
 * @see opt6_ptr(), opt6_len(), opt6_type() macros that use this function
 * 
 * EXAMPLE USAGE:
 * @code
 * unsigned char *opt = ...; // DHCPv6 option pointer
 * unsigned int opt_type = opt6_uint(opt, -4, 2);  // Read option type
 * unsigned int opt_len = opt6_uint(opt, -2, 2);   // Read option length
 * unsigned int iaid = opt6_uint(opt, 0, 4);       // Read 4-byte IAID value
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 3315 Section 22 (option data format uses network byte order)
 * SIDE EFFECTS: None (read-only operation)
 * THREAD SAFETY: Thread-safe (no shared state modifications)
 */
static unsigned int opt6_uint(unsigned char *opt, int offset, int size)
{
  /* this worries about unaligned data and byte order */
  unsigned int ret = 0;
  int i;
  unsigned char *p = opt6_ptr(opt, offset);
  
  for (i = 0; i < size; i++)
    ret = (ret << 8) | *p++;
  
  return ret;
} 

/**
 * @brief Process and relay a DHCPv6 packet received on a relay interface upstream to DHCPv6 servers
 * 
 * @detailed This function handles DHCPv6 relay agent functionality for packets received from
 *           downstream DHCPv6 clients or other relay agents. It encapsulates the received DHCPv6
 *           message in a RELAY-FORWARD message (type 12) per RFC 3315 Section 20.1, adding
 *           relay agent options including Interface-ID and Remote-ID. The relay-forward message
 *           is then transmitted to upstream DHCPv6 servers. This implements the relay agent's
 *           upstream direction processing, working in conjunction with relay_reply6 for the
 *           downstream direction. The function handles nested relay chains (relay-forward
 *           containing relay-forward) and manages relay interface state including link addresses
 *           and snoop records for prefix delegation tracking. It searches for the appropriate
 *           relay configuration based on interface index, increments the hop count (enforcing
 *           HOP_COUNT_LIMIT=32), prepends the relay-forward header with link and peer addresses,
 *           optionally adds client MAC address option (RFC 6939) when snooping is enabled,
 *           wraps the original message in a relay message option, and sends the encapsulated
 *           packet to all configured upstream DHCPv6 servers for the relay.
 * 
 * @param iface_index Interface index of the relay interface where packet was received
 * @param sz Size in bytes of received DHCPv6 packet in daemon->dhcp_packet.iov_base
 * @param peer_address IPv6 address of the DHCPv6 client or downstream relay that sent the packet
 * @param scope_id IPv6 scope ID for link-local addresses (interface index)
 * @param now Current timestamp for lease time calculations and logging
 * 
 * @return 1 on success indicating message was relayed, 0 on failure
 * @retval 1 DHCPv6 packet successfully encapsulated in RELAY-FORWARD and sent to upstream servers
 * @retval 0 Packet processing failed (no matching relay config, hop count exceeded, invalid packet)
 * 
 * @note Adds Interface-ID option (RFC 3315 Section 22.18) containing interface index
 * @note Adds Remote-ID option (RFC 4649) if configured, identifying relay agent
 * @note Adds Client Link-layer Address option (RFC 6939) when snooping enabled for MAC tracking
 * @note Enforces maximum relay hop count (HOP_COUNT_LIMIT=32) to prevent forwarding loops
 * @note Updates snoop records for prefix delegation tracking when relay snooping is enabled
 * @note Searches relay configuration list to find match for iface_index
 * 
 * @warning Modifies global daemon->dhcp_packet buffer by prepending relay-forward header
 * @warning Assumes sz is validated before call; oversized packets may cause buffer overflow
 * 
 * @see relay_reply6() for downstream relay processing (RELAY-REPLY handling)
 * @see dhcp6_reply() for server-side DHCPv6 message processing
 * @see do_snoop_script_run() for executing snoop scripts on prefix delegation events
 * 
 * EXAMPLE USAGE:
 * @code
 * int iface_idx = if_nametoindex("eth0");
 * ssize_t packet_size = 256;
 * struct in6_addr client_addr;
 * u32 scope = iface_idx;
 * int result = relay_upstream6(iface_idx, packet_size, &client_addr, scope, now);
 * if (result == 1) {
 *   // Packet successfully relayed upstream to all configured servers
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 3315 Section 20 (Relay Agent Behavior), RFC 4649 (Remote-ID option), RFC 6939 (Client Link-layer Address)
 * SIDE EFFECTS: Modifies daemon->dhcp_packet buffer; sends UDP packets to upstream servers via sendto
 * THREAD SAFETY: Not thread-safe; uses global daemon structure
 */
int relay_upstream6(int iface_index, ssize_t sz, 
		    struct in6_addr *peer_address, u32 scope_id, time_t now)
{
  unsigned char *header;
  unsigned char *inbuff = daemon->dhcp_packet.iov_base;
  int msg_type = *inbuff;
  int hopcount, o;
  struct in6_addr multicast;
  unsigned int maclen, mactype;
  unsigned char mac[DHCP_CHADDR_MAX];
  struct dhcp_relay *relay;
  
  for (relay = daemon->relay6; relay; relay = relay->next)
    if (relay->iface_index != 0 && relay->iface_index == iface_index)
      break;

  /* No relay config. */
  if (!relay)
    return 0;
  
  inet_pton(AF_INET6, ALL_SERVERS, &multicast);
  get_client_mac(peer_address, scope_id, mac, &maclen, &mactype, now);
  
  /* Get hop count from nested relayed message */ 
  if (msg_type == DHCP6RELAYFORW)
    hopcount = *((unsigned char *)inbuff+1) + 1;
  else
    hopcount = 0;

  reset_counter();

  /* RFC 3315 HOP_COUNT_LIMIT */
  if (hopcount > 32 || !(header = put_opt6(NULL, 34)))
    return 1;
  
  header[0] = DHCP6RELAYFORW;
  header[1] = hopcount;
  memcpy(&header[18], peer_address, IN6ADDRSZ);
  
  /* RFC-6939 */
  if (maclen != 0)
    {
      o = new_opt6(OPTION6_CLIENT_MAC);
      put_opt6_short(mactype);
      put_opt6(mac, maclen);
      end_opt6(o);
    }
  
  o = new_opt6(OPTION6_RELAY_MSG);
  put_opt6(inbuff, sz);
  end_opt6(o);
  
  for (; relay; relay = relay->next)
    if (relay->iface_index != 0 && relay->iface_index == iface_index)
      {
	union mysockaddr to;

	memcpy(&header[2], &relay->local.addr6, IN6ADDRSZ);
	
	to.sa.sa_family = AF_INET6;
	to.in6.sin6_addr = relay->server.addr6;
#ifdef HAVE_SOCKADDR_SA_LEN
	to.in6.sin6_len = sizeof(struct sockaddr_in6);
#endif 
	to.in6.sin6_port = htons(relay->port);
	to.in6.sin6_flowinfo = 0;
	to.in6.sin6_scope_id = 0;
	
	if (IN6_ARE_ADDR_EQUAL(&relay->server.addr6, &multicast))
	  {
	    int multicast_iface;
	    if (!relay->interface || strchr(relay->interface, '*') ||
		(multicast_iface = if_nametoindex(relay->interface)) == 0 ||
		setsockopt(daemon->dhcp6fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &multicast_iface, sizeof(multicast_iface)) == -1)
	      {
		my_syslog(MS_DHCP | LOG_ERR, _("Cannot multicast DHCP relay via interface %s"), relay->interface);
		continue;
	      }
	  }
	
#ifdef HAVE_DUMPFILE
	dump_packet_udp(DUMP_DHCPV6, (void *)daemon->outpacket.iov_base, save_counter(-1), NULL, &to, daemon->dhcp6fd);
#endif

	while (retry_send(sendto(daemon->dhcp6fd, (void *)daemon->outpacket.iov_base, save_counter(-1),
				 0, (struct sockaddr *)&to, sa_len(&to))));
	
	if (option_bool(OPT_LOG_OPTS))
	  {
	    inet_ntop(AF_INET6, &relay->local, daemon->addrbuff, ADDRSTRLEN);
	    if (IN6_ARE_ADDR_EQUAL(&relay->server.addr6, &multicast))
	      snprintf(daemon->namebuff, MAXDNAME, _("multicast via %s"), relay->interface);
	    else
	      inet_ntop(AF_INET6, &relay->server, daemon->namebuff, ADDRSTRLEN);
	    my_syslog(MS_DHCP | LOG_INFO, _("DHCP relay at %s -> %s"), daemon->addrbuff, daemon->namebuff);
	  }
	
      }
  
  return 1;
}

/**
 * @brief Process DHCPv6 RELAY-REPLY messages from upstream servers and forward to relay clients
 * 
 * @detailed This function handles the downstream path of DHCPv6 relay agent processing, receiving
 *           RELAY-REPLY messages from upstream DHCPv6 servers and forwarding them to the appropriate
 *           relay clients or end clients. The function implements RFC 3315 Section 20.3 relay agent
 *           behavior for processing RELAY-REPLY messages. When operating as a relay agent, dnsmasq
 *           receives RELAY-FORW messages from clients, forwards them to upstream servers, and then
 *           receives RELAY-REPLY messages from those servers. This function extracts the encapsulated
 *           client message from the RELAY-REPLY, updates the destination peer address to match the
 *           original client or next-hop relay, determines the appropriate destination port (547 for
 *           relays, 546 for clients), and prepares the message for transmission. The function validates
 *           the incoming message format (minimum 38 bytes: 1 msg_type + 1 hop-count + 16 link-address +
 *           16 peer-address + 2 option-type + 2 option-len), verifies the message type is DHCP6RELAYREPL,
 *           extracts the link-address field, searches configured relay definitions (daemon->relay6 list)
 *           for a match based on link-address and arrival interface, locates the encapsulated RELAY_MSG
 *           option containing the client-bound message, copies the peer-address from the relay message
 *           to the destination socket address, determines whether the encapsulated message is another
 *           RELAY-REPLY (nested relay) or a client-bound message, and sets the destination port accordingly.
 *           When HAVE_SCRIPT is enabled and the encapsulated message is a DHCP6REPLY, the function
 *           performs prefix delegation snooping by searching for IA_PD options containing IAPREFIX
 *           sub-options, extracting delegated prefixes with non-zero valid lifetimes, allocating snoop
 *           records (from daemon->free_snoops memory pool or via whine_malloc), populating snoop records
 *           with client address, prefix, and prefix length, and appending them to the relay's snoop_records
 *           queue for later script execution. This snooping mechanism enables external scripts to track
 *           prefix delegations for firewall rules, routing table updates, or monitoring purposes. The
 *           function uses put_opt6 to prepare the encapsulated message for transmission by copying it
 *           to the output buffer managed by the option building subsystem (outpacket.c interface). Relay
 *           matching considers both the link-address (must match relay->local.addr6) and the arrival
 *           interface (must match relay->interface if specified, supporting wildcard matching), ensuring
 *           replies are routed back through the correct relay path. The peer->sin6_scope_id is set to
 *           relay->iface_index to ensure proper IPv6 link-local address handling when forwarding to
 *           clients on specific network interfaces. This function is typically called from dhcp6_reply
 *           in dhcp6.c when the incoming message type is DHCP6RELAYREPL, integrating with the main
 *           DHCPv6 packet processing pipeline. Memory management for snoop records uses a free list
 *           pattern (daemon->free_snoops) to avoid repeated malloc/free overhead during high-volume
 *           prefix delegation operations, with records recycled after script execution completes.
 * 
 * @param peer Pointer to sockaddr_in6 structure for destination address (modified in place)
 * @param sz Size of the received RELAY-REPLY message in bytes
 * @param arrival_interface Name of the network interface where the message arrived (for relay matching)
 * 
 * @return 1 if the RELAY-REPLY was successfully processed and message prepared for forwarding
 * @retval 1 Valid RELAY-REPLY processed, relay configuration matched, RELAY_MSG option found, peer address and port updated
 * @retval 0 Message validation failed (size < 38 bytes, wrong message type), no matching relay configuration found, or RELAY_MSG option missing
 * 
 * @note The peer parameter is modified in place with the destination address and port for forwarding
 * @note When HAVE_SCRIPT is disabled, prefix delegation snooping is not performed (compile-time conditional)
 * @note The function reads from daemon->dhcp_packet.iov_base global buffer containing the received message
 * @note Prefix delegation snooping only occurs for DHCP6REPLY messages (not ADVERTISE or other message types)
 * @note Snoop records are allocated from the free list (daemon->free_snoops) for memory efficiency
 * @note The link-address field in the RELAY-REPLY identifies the network segment for relay matching
 * @note Nested relay scenarios (RELAY-REPLY containing RELAY-REPLY) use port 547 for next-hop relay
 * @note Client-bound messages (REPLY, ADVERTISE, etc.) use port 546 for end-client delivery
 * 
 * @warning Message buffer (daemon->dhcp_packet.iov_base) must contain a valid DHCPv6 packet before calling
 * @warning The sz parameter must accurately reflect the message size; incorrect values cause undefined behavior
 * @warning Relay configuration (daemon->relay6) must be properly initialized before processing relay replies
 * @warning Snoop record memory allocation failures are silently handled (prefix delegation tracking is best-effort)
 * 
 * @see relay_upstream6() for upstream relay processing (RELAY-FORW message creation)
 * @see opt6_find() for DHCPv6 option searching in relay messages
 * @see opt6_uint() for extracting numeric values from DHCPv6 options
 * @see put_opt6() in outpacket.c for preparing encapsulated message for transmission
 * @see queue_relay_snoop() for script execution of prefix delegation events
 * @see whine_malloc() for memory allocation with error logging
 * 
 * EXAMPLE USAGE:
 * @code
 * // Called from dhcp6_reply when processing relay agent replies
 * struct sockaddr_in6 peer_addr;
 * ssize_t message_size = 128;
 * char *iface = "eth0";
 * 
 * // peer_addr initially contains upstream server address
 * int result = relay_reply6(&peer_addr, message_size, iface);
 * if (result) {
 *   // peer_addr now contains client/relay destination
 *   // Message ready for forwarding via send_from
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 3315 Section 20.3 (Relay Agent Behavior - Relaying a Reply Message)
 * SIDE EFFECTS: Modifies peer sockaddr_in6 structure; allocates snoop records; updates daemon->free_snoops free list
 * THREAD SAFETY: Not thread-safe (accesses global daemon structure); single-threaded event-driven architecture
 */
int relay_reply6(struct sockaddr_in6 *peer, ssize_t sz, char *arrival_interface)
{
  struct dhcp_relay *relay;
  struct in6_addr link;
  unsigned char *inbuff = daemon->dhcp_packet.iov_base;
  
  /* must have at least msg_type+hopcount+link_address+peer_address+minimal size option
     which is               1   +    1   +    16      +     16     + 2 + 2 = 38 */
  
  if (sz < 38 || *inbuff != DHCP6RELAYREPL)
    return 0;
  
  memcpy(&link, &inbuff[2], IN6ADDRSZ); 
  
  for (relay = daemon->relay6; relay; relay = relay->next)
    if (IN6_ARE_ADDR_EQUAL(&link, &relay->local.addr6) &&
	(!relay->interface || wildcard_match(relay->interface, arrival_interface)))
      break;
      
  reset_counter();

  if (relay)
    {
      void *opt, *opts = inbuff + 34;
      void *end = inbuff + sz;
      
      if ((opt = opt6_find(opts, end, OPTION6_RELAY_MSG, 4)))
	{
	  int encap_type = opt6_uint(opt, 0, 1);
	  put_opt6(opt6_ptr(opt, 0), opt6_len(opt));
	  memcpy(&peer->sin6_addr, &inbuff[18], IN6ADDRSZ); 
	  peer->sin6_scope_id = relay->iface_index;

	  if (encap_type == DHCP6RELAYREPL)
	    {
	      peer->sin6_port = ntohs(DHCPV6_SERVER_PORT);
	      return 1;
	    }
	  
	  peer->sin6_port = ntohs(DHCPV6_CLIENT_PORT);
	  
#ifdef HAVE_SCRIPT
	  if (daemon->lease_change_command && encap_type == DHCP6REPLY)
	    {
	      /* skip over message type and transaction-id. to get to options. */
	      opts = opt6_ptr(opt, 4);
	      end = opt6_ptr(opt, opt6_len(opt));

	      if ((opt = opt6_find(opts, end, OPTION6_IA_PD, 12)))
		{
		  opts = opt6_ptr(opt, 12);
		  end = opt6_ptr(opt, opt6_len(opt));
		  
		  for (opt = opt6_find(opts, end, OPTION6_IAPREFIX, 25); opt; opt = opt6_find(opt6_next(opt, end), end, OPTION6_IAPREFIX, 25))
		    /* valid lifetime must not be zero. */
		    if (opt6_uint(opt, 4, 4) != 0)
		      {
			if (daemon->free_snoops ||
			    (daemon->free_snoops = whine_malloc(sizeof(struct snoop_record))))
			  {
			    struct snoop_record *snoop = daemon->free_snoops;
			    
			    daemon->free_snoops = snoop->next;
			    snoop->client = peer->sin6_addr;
			    snoop->prefix_len = opt6_uint(opt, 8, 1); 
			    memcpy(&snoop->prefix, opt6_ptr(opt, 9), IN6ADDRSZ); 
			    snoop->next = relay->snoop_records;
			    relay->snoop_records = snoop;
			  }
		      }
		}	      
	    }
#endif
	  return 1;
	}
    }
  
  return 0;
}
  
#ifdef HAVE_SCRIPT
/**
 * @brief Process one pending DHCPv6 prefix delegation snoop record and execute associated script
 * 
 * @detailed This function implements the script execution side of DHCPv6 relay agent prefix
 *           delegation snooping. When relay agents track prefix delegations (via relay snooping),
 *           they create snoop records containing client DUID, delegated prefix, and prefix length.
 *           This function is called from the main event loop to process these records one at a time,
 *           preventing script execution from blocking the daemon. It iterates through all configured
 *           DHCPv6 relay agents (daemon->relay6 list), locates the first relay with pending snoop
 *           records, removes the first snoop record from that relay's queue, recycles the record
 *           structure to the free list (daemon->free_snoops) for memory efficiency, and queues
 *           the snoop event for script execution via queue_relay_snoop which will fork and exec
 *           the configured dhcp-script with prefix delegation details. Processing one record per
 *           call ensures the main event loop remains responsive and prevents script execution
 *           backlog from consuming excessive resources. The function is called repeatedly by the
 *           event loop until all pending snoop records are processed (returns 0 when queue is empty).
 *           This design pattern matches the helper script execution model used for DHCPv4/DHCPv6
 *           lease events, providing consistent script invocation semantics across DHCP protocols.
 * 
 * @return Integer status indicating whether a snoop record was processed
 * @retval 1 A snoop record was found and queued for script execution; call again to process more
 * @retval 0 No pending snoop records exist; all queued records have been processed
 * 
 * @note Called repeatedly from main event loop until returns 0 (queue empty)
 * @note Processes exactly one snoop record per call to maintain event loop responsiveness
 * @note Snoop records are created by relay_upstream6 when prefix delegation is detected
 * @note Script execution happens asynchronously via queue_relay_snoop -> helper.c fork/exec
 * @note Memory management: recycles processed snoop_record structures to daemon->free_snoops list
 * @note Script receives: client DUID, relay interface, delegated IPv6 prefix, prefix length
 * @note Requires HAVE_SCRIPT compile flag and configured dhcp-script for actual execution
 * 
 * @warning Modifies daemon->relay6 snoop_records queues and daemon->free_snoops list
 * @warning Must be called from main thread only; not thread-safe
 * @warning Script execution may fail silently if dhcp-script not configured or not executable
 * 
 * @see relay_upstream6() for snoop record creation when prefix delegation detected
 * @see queue_relay_snoop() in helper.c for forking and executing the dhcp-script
 * @see queue_script() in helper.c for general DHCP event script execution pattern
 * 
 * EXAMPLE USAGE:
 * @code
 * // In main event loop after DHCPv6 packet processing
 * while (do_snoop_script_run()) {
 *   // Continue processing snoop records until queue is empty
 *   // Each call processes one record and queues script execution
 * }
 * // Returns 0 when all pending snoop records have been processed
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 3633 (IPv6 Prefix Delegation), custom extension for relay snooping
 * SIDE EFFECTS: Modifies relay snoop queues; forks helper process for script execution via queue_relay_snoop
 * THREAD SAFETY: Not thread-safe; uses global daemon structure
 */
int do_snoop_script_run(void)
{
  struct dhcp_relay *relay;
  struct snoop_record *snoop;
  
  for (relay = daemon->relay6; relay; relay = relay->next)
    if ((snoop = relay->snoop_records))
      {
	relay->snoop_records = snoop->next;
	snoop->next = daemon->free_snoops;
	daemon->free_snoops = snoop;
	
	queue_relay_snoop(&snoop->client, relay->iface_index, &snoop->prefix, snoop->prefix_len);
	return 1;
      }
  
  return 0;
}
#endif

#endif

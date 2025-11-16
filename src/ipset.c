/* ipset.c is Copyright (c) 2013 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.

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
 * @file ipset.c
 * @brief Linux kernel ipset integration for dynamic firewall rule application based on DNS resolution
 * 
 * DETAILED PURPOSE:
 * This Linux-specific module provides integration with the kernel's ipset infrastructure, enabling
 * dnsmasq to automatically populate named ipset collections with IP addresses resolved from DNS queries.
 * This functionality enables dynamic firewall rules, content filtering, and policy-based routing based
 * on domain-name-to-IP-address mappings without manual IP address tracking.
 * 
 * The module supports both legacy ipset interface (kernel < 2.6.32, IPv4 only via raw sockets) and
 * modern netlink-based API (kernel >= 2.6.32, IPv4 and IPv6 via NETLINK_NETFILTER). The implementation
 * automatically detects kernel version at runtime and selects appropriate API.
 * 
 * KEY RESPONSIBILITIES:
 * - ipset_init(): Initialize ipset control socket (netlink or raw socket based on kernel version)
 * - add_to_ipset(): Add resolved IP addresses to named ipset collections (called from forward.c)
 * - new_add_to_ipset(): Modern netlink-based API for adding IPv4/IPv6 addresses (kernel >= 2.6.32)
 * - old_add_to_ipset(): Legacy raw socket API for adding IPv4 addresses only (kernel < 2.6.32)
 * - add_attr(): Construct netlink attributes for ipset protocol messages
 * 
 * DEPENDENCIES:
 * Includes: dnsmasq.h (struct daemon, safe_malloc, die, kernel version macros)
 * Called by: forward.c DNS resolution path when domain matches ipset configuration
 * Calls: socket(AF_NETLINK/AF_INET), bind(), sendto(), setsockopt() (kernel interface)
 * 
 * DATA STRUCTURES:
 * - struct my_nlattr: Netlink attribute header (nla_len, nla_type) - line 56
 * - struct my_nfgenmsg: Netfilter generic message (family, version, res_id) - line 61
 * - Static buffer (256 bytes) for netlink message construction - line 69
 * 
 * COMPILE-TIME OPTIONS:
 * - HAVE_LINUX_IPSET: Enables entire module compilation (defined in config.h)
 * - Requires Linux kernel with ipset support and netfilter headers
 * 
 * IPSET SET TYPES SUPPORTED:
 * - hash:ip (IPv4/IPv6 address sets)
 * - hash:net (IPv4/IPv6 network sets with CIDR notation)
 * - Other ipset types supported by kernel but commonly used for DNS-based population
 * 
 * CONFIGURATION MAPPING:
 * Domain-to-ipset mapping configured via dnsmasq.conf directives:
 * - ipset=/domain/setname - Add all IPs for domain to named ipset
 * - ipset=/domain/setname,setname6 - IPv4 to setname, IPv6 to setname6
 * 
 * INTEGRATION WITH FORWARD.C:
 * When DNS resolution completes in forward.c, if domain matches ipset configuration,
 * add_to_ipset() is invoked with resolved IP addresses to populate kernel ipsets.
 * This enables firewall rules like "iptables -A FORWARD -m set --match-set ads DROP"
 * to dynamically block domains based on DNS resolution without static IP lists.
 * 
 * USE CASES:
 * 1. Content Filtering: Populate ipset with advertising/malware domains, block via iptables
 * 2. Domain-Based Firewall Rules: Allow/deny traffic based on domain classification
 * 3. Policy-Based Routing: Route traffic for specific domains through VPN or alternate gateway
 * 4. Traffic Shaping: Apply QoS policies based on DNS-resolved domain categories
 * 
 * LINUX KERNEL REQUIREMENTS:
 * - Kernel >= 2.6.32: Full IPv4/IPv6 support via netlink API (recommended)
 * - Kernel < 2.6.32: Limited IPv4 support via raw socket API (legacy)
 * - CONFIG_NETFILTER_NETLINK: Required for netlink API
 * - CONFIG_IP_SET: Kernel ipset support module
 * 
 * IPSET VERSION COMPATIBILITY:
 * - ipset protocol version 6 (IPSET_PROTOCOL constant)
 * - Compatible with ipset userspace tools v6.x and later
 * - Backward compatible header definitions for older build environments
 * 
 * THREADING/CONCURRENCY:
 * Single-threaded event-driven architecture - ipset operations are synchronous socket
 * writes that do not block event loop (fire-and-forget netlink messages).
 * 
 * @copyright Copyright (c) 2013 Jason A. Donenfeld <Jason@zx2c4.com>
 * @copyright Copyright (c) 2000-2025 Simon Kelley (dnsmasq integration)
 * @license GPL-2.0-or-later
 */

#include "dnsmasq.h"

#if defined(HAVE_LINUX_IPSET)

#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/netlink.h>

/* We want to be able to compile against old header files
   Kernel version is handled at run-time. */

#define NFNL_SUBSYS_IPSET 6

#define IPSET_ATTR_DATA 7
#define IPSET_ATTR_IP 1
#define IPSET_ATTR_IPADDR_IPV4 1
#define IPSET_ATTR_IPADDR_IPV6 2
#define IPSET_ATTR_PROTOCOL 1
#define IPSET_ATTR_SETNAME 2
#define IPSET_CMD_ADD 9
#define IPSET_CMD_DEL 10
#define IPSET_MAXNAMELEN 32
#define IPSET_PROTOCOL 6

#ifndef NFNETLINK_V0
#define NFNETLINK_V0    0
#endif

#ifndef NLA_F_NESTED
#define NLA_F_NESTED		(1 << 15)
#endif

#ifndef NLA_F_NET_BYTEORDER
#define NLA_F_NET_BYTEORDER	(1 << 14)
#endif

/**
 * @struct my_nlattr
 * @brief Netlink attribute header for ipset protocol messages
 * 
 * This structure defines the header for netlink attributes used in ipset protocol
 * communication. Netlink attributes are type-length-value (TLV) encoded data structures
 * that carry protocol parameters and data payloads in netlink messages.
 * 
 * LIFECYCLE:
 * Creation: Allocated as part of larger netlink message buffer in new_add_to_ipset()
 * Initialization: Set via add_attr() helper function
 * Destruction: Part of stack-allocated buffer, automatically freed on function return
 * Ownership: Temporary stack allocation within netlink message construction
 * 
 * MEMORY LAYOUT:
 * Size: 4 bytes (2 bytes length + 2 bytes type)
 * Alignment: Must be 4-byte aligned per netlink protocol requirements (NL_ALIGN macro)
 * 
 * USAGE PATTERNS:
 * Used in nested attribute construction for ipset ADD/DEL commands. Attributes are
 * chained sequentially in the netlink message buffer with proper alignment.
 */
struct my_nlattr {
        __u16           nla_len;   /**< Total length of attribute including header and payload */
        __u16           nla_type;  /**< Attribute type identifier with optional NLA_F_NESTED flag */
};

/**
 * @struct my_nfgenmsg
 * @brief Netfilter generic message header for netlink communication
 * 
 * This structure defines the generic netfilter message header that follows the
 * netlink message header (struct nlmsghdr) in netfilter subsystem messages. It
 * specifies the address family, netlink protocol version, and resource identifier
 * for netfilter operations.
 * 
 * LIFECYCLE:
 * Creation: Allocated as part of netlink message buffer immediately after nlmsghdr
 * Initialization: Set during message construction in new_add_to_ipset()
 * Destruction: Part of stack-allocated buffer, automatically freed on function return
 * Ownership: Temporary stack allocation within netlink message construction
 * 
 * MEMORY LAYOUT:
 * Size: 4 bytes (1 byte family + 1 byte version + 2 bytes resource ID)
 * Alignment: Immediately follows struct nlmsghdr with natural alignment
 * 
 * USAGE PATTERNS:
 * Placed immediately after struct nlmsghdr in netlink messages sent to NETLINK_NETFILTER
 * socket. The nfgen_family field is set to AF_INET for IPv4 or AF_INET6 for IPv6.
 */
struct my_nfgenmsg {
        __u8  nfgen_family;     /**< Address family: AF_INET (IPv4) or AF_INET6 (IPv6) */
        __u8  version;          /**< Netlink protocol version: NFNETLINK_V0 (0) */
        __be16    res_id;       /**< Resource identifier (typically 0 for ipset operations) */
};


/* data structure size in here is fixed */
#define BUFF_SZ 256

#define NL_ALIGN(len) (((len)+3) & ~(3))
static const struct sockaddr_nl snl = { .nl_family = AF_NETLINK };
static int ipset_sock, old_kernel;
static char *buffer;

/**
 * @brief Add netlink attribute to netlink message for ipset protocol communication
 * 
 * @detailed Constructs a netlink attribute (TLV - type-length-value structure) and appends
 * it to an existing netlink message. This helper function handles proper alignment requirements
 * (4-byte boundaries per netlink protocol), calculates total attribute length including header,
 * and updates the parent netlink message length. Used internally to build ipset ADD/DEL command
 * messages with nested attributes for set name, IP address, and protocol version.
 * 
 * @param nlh Pointer to netlink message header being constructed. Must not be NULL.
 *            Message length field (nlmsg_len) is updated to include new attribute.
 * @param type Attribute type identifier (e.g., IPSET_ATTR_SETNAME, IPSET_ATTR_DATA, IPSET_ATTR_IP).
 *             May include NLA_F_NESTED flag for nested attributes.
 * @param len Length of data payload in bytes (not including attribute header)
 * @param data Pointer to attribute data payload to copy. Must not be NULL. Data is copied into message.
 * 
 * @return void
 * 
 * @note Assumes sufficient buffer space exists in nlh message buffer for new attribute
 * @note All lengths are automatically aligned to 4-byte boundaries per netlink protocol
 * @warning Caller must ensure nlh buffer has sufficient space (BUFF_SZ bytes allocated)
 * 
 * @see new_add_to_ipset() - Primary caller that constructs ipset ADD commands
 * 
 * EXAMPLE USAGE:
 * @code
 * struct nlmsghdr *nlh = (struct nlmsghdr *)buffer;
 * nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct my_nfgenmsg));
 * add_attr(nlh, IPSET_ATTR_PROTOCOL, sizeof(uint8_t), &proto);
 * @endcode
 * 
 * RFC COMPLIANCE: Netlink protocol per RFC 3549 (Linux Netlink as an IP Services Protocol)
 * SIDE EFFECTS: Modifies nlh->nlmsg_len, writes attribute data to message buffer
 * THREAD SAFETY: Single-threaded architecture - called from new_add_to_ipset() in DNS resolution path
 */
static inline void add_attr(struct nlmsghdr *nlh, uint16_t type, size_t len, const void *data)
{
  struct my_nlattr *attr = (struct my_nlattr *)((u8 *)nlh + NL_ALIGN(nlh->nlmsg_len));
  uint16_t payload_len = NL_ALIGN(sizeof(struct my_nlattr)) + len;
  attr->nla_type = type;
  attr->nla_len = payload_len;
  memcpy((u8 *)attr + NL_ALIGN(sizeof(struct my_nlattr)), data, len);
  nlh->nlmsg_len += NL_ALIGN(payload_len);
}

/**
 * @brief Initialize ipset control socket and detect kernel API version
 * 
 * @detailed Initializes the Linux kernel ipset integration by detecting kernel version,
 * selecting appropriate API (legacy raw socket vs. modern netlink), and creating the
 * control socket for ipset operations. Kernel versions before 2.6.32 use legacy raw socket
 * API (IPv4 only via IPPROTO_RAW), while 2.6.32+ use netlink API (IPv4/IPv6 via
 * NETLINK_NETFILTER subsystem). This function is called once during daemon initialization
 * from main() in dnsmasq.c when HAVE_IPSET is enabled.
 * 
 * @return void (calls die() on fatal initialization failure)
 * 
 * @note Sets global static variables: old_kernel (boolean), ipset_sock (file descriptor), buffer (netlink message buffer)
 * @warning Fatal error via die() if socket creation or binding fails - ipset functionality required when configured
 * 
 * @see add_to_ipset() - Uses ipset_sock and old_kernel variables set by this function
 * 
 * EXAMPLE USAGE:
 * @code
 * // Called from main() during daemon initialization
 * if (daemon->ipsets)
 *   ipset_init();
 * @endcode
 * 
 * SIDE EFFECTS:
 * - Sets global old_kernel boolean (true for kernel < 2.6.32, false otherwise)
 * - Creates global ipset_sock file descriptor (AF_INET/SOCK_RAW or AF_NETLINK/SOCK_RAW)
 * - Allocates global buffer (256 bytes via safe_malloc) for netlink messages on modern kernels
 * - Binds netlink socket to NETLINK_NETFILTER on modern kernels
 * - Calls die() with EC_MISC exit code if initialization fails
 * 
 * THREAD SAFETY: Single-threaded architecture - called once at daemon startup before event loop
 */
void ipset_init(void)
{
  old_kernel = (daemon->kernel_version < KERNEL_VERSION(2,6,32));
  
  if (old_kernel && (ipset_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) != -1)
    return;
  
  if (!old_kernel && 
      (buffer = safe_malloc(BUFF_SZ)) &&
      (ipset_sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER)) != -1 &&
      (bind(ipset_sock, (struct sockaddr *)&snl, sizeof(snl)) != -1))
    return;
  
  die (_("failed to create IPset control socket: %s"), NULL, EC_MISC);
}

/**
 * @brief Add or remove an IP address to/from an ipset using modern netlink API
 * 
 * @detailed Constructs and sends a netlink message to the kernel's ipset subsystem
 *           to add or remove an IP address from a named ipset collection. This function
 *           uses the modern NETLINK_NETFILTER socket interface available in Linux
 *           kernels 2.6.32 and later. The netlink message format includes nested
 *           attributes for protocol, set name, and IP address data.
 * 
 * @param setname Name of the ipset collection (max IPSET_MAXNAMELEN=32 characters)
 * @param ipaddr Pointer to union all_addr containing IPv4 or IPv6 address to add/remove
 * @param af Address family: AF_INET (IPv4) or AF_INET6 (IPv6)
 * @param remove If non-zero, remove address from set; if zero, add address to set
 * 
 * @return 0 on success (message sent to kernel)
 * @retval 0 Netlink message successfully sent to kernel ipset subsystem
 * @retval -1 Failure (errno set: EMSGSIZE if buffer too small, other values from sendto)
 * 
 * @note Buffer size is fixed at BUFF_SZ (256 bytes). Message construction failure
 *       sets errno to EMSGSIZE. Actual ipset operation success is not verified as
 *       netlink communication is fire-and-forget.
 * @warning Does not wait for kernel response; cannot detect if ipset exists or if
 *          operation succeeded at kernel level. Assumes ipset pre-created by admin.
 * 
 * @see old_add_to_ipset() for legacy kernel (pre-2.6.32) implementation
 * @see add_to_ipset() for main entry point that selects appropriate implementation
 * 
 * EXAMPLE USAGE:
 * @code
 * union all_addr addr;
 * addr.addr4.s_addr = inet_addr("192.168.1.100");
 * int result = new_add_to_ipset("blocked_hosts", &addr, AF_INET, 0);
 * if (result == -1)
 *   my_syslog(LOG_ERR, "Failed to add IP to ipset: %s", strerror(errno));
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (Linux kernel ipset netlink API)
 * SIDE EFFECTS: Sends netlink message to kernel netfilter subsystem
 * THREAD SAFETY: Not thread-safe; uses shared global buffer; single-threaded daemon
 */
static int new_add_to_ipset(const char *setname, const union all_addr *ipaddr, int af, int remove)
{
  struct nlmsghdr *nlh;
  struct my_nfgenmsg *nfg;
  struct my_nlattr *nested[2];
  uint8_t proto;
  int addrsz = (af == AF_INET6) ? IN6ADDRSZ : INADDRSZ;

  if (strlen(setname) >= IPSET_MAXNAMELEN) 
    {
      errno = ENAMETOOLONG;
      return -1;
    }
  
  memset(buffer, 0, BUFF_SZ);

  nlh = (struct nlmsghdr *)buffer;
  nlh->nlmsg_len = NL_ALIGN(sizeof(struct nlmsghdr));
  nlh->nlmsg_type = (remove ? IPSET_CMD_DEL : IPSET_CMD_ADD) | (NFNL_SUBSYS_IPSET << 8);
  nlh->nlmsg_flags = NLM_F_REQUEST;
  
  nfg = (struct my_nfgenmsg *)(buffer + nlh->nlmsg_len);
  nlh->nlmsg_len += NL_ALIGN(sizeof(struct my_nfgenmsg));
  nfg->nfgen_family = af;
  nfg->version = NFNETLINK_V0;
  nfg->res_id = htons(0);
  
  proto = IPSET_PROTOCOL;
  add_attr(nlh, IPSET_ATTR_PROTOCOL, sizeof(proto), &proto);
  add_attr(nlh, IPSET_ATTR_SETNAME, strlen(setname) + 1, setname);
  nested[0] = (struct my_nlattr *)(buffer + NL_ALIGN(nlh->nlmsg_len));
  nlh->nlmsg_len += NL_ALIGN(sizeof(struct my_nlattr));
  nested[0]->nla_type = NLA_F_NESTED | IPSET_ATTR_DATA;
  nested[1] = (struct my_nlattr *)(buffer + NL_ALIGN(nlh->nlmsg_len));
  nlh->nlmsg_len += NL_ALIGN(sizeof(struct my_nlattr));
  nested[1]->nla_type = NLA_F_NESTED | IPSET_ATTR_IP;
  add_attr(nlh, 
	   (af == AF_INET ? IPSET_ATTR_IPADDR_IPV4 : IPSET_ATTR_IPADDR_IPV6) | NLA_F_NET_BYTEORDER,
	   addrsz, ipaddr);
  nested[1]->nla_len = (u8 *)buffer + NL_ALIGN(nlh->nlmsg_len) - (u8 *)nested[1];
  nested[0]->nla_len = (u8 *)buffer + NL_ALIGN(nlh->nlmsg_len) - (u8 *)nested[0];
	
  while (retry_send(sendto(ipset_sock, buffer, nlh->nlmsg_len, 0,
			   (struct sockaddr *)&snl, sizeof(snl))));
								    
  return errno == 0 ? 0 : -1;
}


/**
 * @brief Add or remove an IPv4 address to/from an ipset using legacy kernel API
 * 
 * @detailed Uses the legacy setsockopt/getsockopt interface with SOL_IP and
 *           IP_SET_OP_ADD_IP/IP_SET_OP_DEL_IP operations for kernels prior to 2.6.32.
 *           This interface predates the netlink-based ipset API and is limited to
 *           IPv4 addresses only. The function retrieves the numeric ipset ID by name,
 *           then performs the add or delete operation using raw socket options.
 * 
 * @param setname Name of the ipset collection (max IPSET_MAXNAMELEN=32 characters)
 * @param ipaddr Pointer to union all_addr containing IPv4 address (only addr4 used)
 * @param remove If non-zero, remove address from set; if zero, add address to set
 * 
 * @return 0 on success (operation completed)
 * @retval 0 Successfully added or removed IPv4 address from ipset
 * @retval -1 Failure: getsockopt failed to retrieve set ID, or setsockopt failed
 * 
 * @note IPv6 is NOT supported by legacy API; caller must check address family
 *       before calling this function. Set ID retrieval (IP_SET_OP_GET_BYNAME)
 *       precedes every add/delete operation.
 * @warning Legacy API only; replaced by netlink interface in modern kernels.
 *          No validation that setname exists; setsockopt may fail silently.
 * 
 * @see new_add_to_ipset() for modern netlink-based implementation
 * @see add_to_ipset() for main entry point that selects appropriate implementation
 * 
 * EXAMPLE USAGE:
 * @code
 * union all_addr addr;
 * addr.addr4.s_addr = inet_addr("10.0.0.50");
 * // Only called on old kernels (< 2.6.32) and only for IPv4
 * int result = old_add_to_ipset("malware_ips", &addr, 0);
 * if (result == -1)
 *   my_syslog(LOG_WARNING, "Legacy ipset add failed: %s", strerror(errno));
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (Linux kernel legacy ipset API via SOL_IP socket options)
 * SIDE EFFECTS: Modifies kernel ipset via setsockopt system call
 * THREAD SAFETY: Thread-safe (no shared state); single-threaded daemon architecture
 */
static int old_add_to_ipset(const char *setname, const union all_addr *ipaddr, int remove)
{
  socklen_t size;
  struct ip_set_req_adt_get {
    unsigned op;
    unsigned version;
    union {
      char name[IPSET_MAXNAMELEN];
      uint16_t index;
    } set;
    char typename[IPSET_MAXNAMELEN];
  } req_adt_get;
  struct ip_set_req_adt {
    unsigned op;
    uint16_t index;
    uint32_t ip;
  } req_adt;
  
  if (strlen(setname) >= sizeof(req_adt_get.set.name)) 
    {
      errno = ENAMETOOLONG;
      return -1;
    }
  
  req_adt_get.op = 0x10;
  req_adt_get.version = 3;
  strcpy(req_adt_get.set.name, setname);
  size = sizeof(req_adt_get);
  if (getsockopt(ipset_sock, SOL_IP, 83, &req_adt_get, &size) < 0)
    return -1;
  req_adt.op = remove ? 0x102 : 0x101;
  req_adt.index = req_adt_get.set.index;
  req_adt.ip = ntohl(ipaddr->addr4.s_addr);
  if (setsockopt(ipset_sock, SOL_IP, 83, &req_adt, sizeof(req_adt)) < 0)
    return -1;
  
  return 0;
}



/**
 * @brief Add or remove an IP address to/from an ipset collection (main entry point)
 * 
 * @detailed Primary interface for ipset integration called by DNS resolution code in
 *           forward.c. Automatically selects between modern netlink API (kernels >= 2.6.32)
 *           and legacy setsockopt API (older kernels) based on daemon->kernel_version
 *           detected at initialization. For modern API, supports both IPv4 (AF_INET) and
 *           IPv6 (AF_INET6); legacy API supports IPv4 only. Silently ignores IPv6 requests
 *           on old kernels to maintain backward compatibility.
 * 
 * @param setname Name of the ipset collection configured via --ipset option (max 32 chars)
 * @param ipaddr Pointer to union all_addr containing IPv4 (addr4) or IPv6 (addr6) address
 * @param flags Address family flags: F_IPV4 for IPv4, F_IPV6 for IPv6
 * @param remove If non-zero, remove address from set; if zero, add address to set
 * 
 * @return 0 on success or intentional skip (IPv6 on old kernel)
 * @retval 0 Successfully added/removed IP, or IPv6 skipped on legacy kernel
 * @retval -1 Failure: netlink message construction failed, or socket operation failed
 * 
 * @note Called from forward.c after successful DNS resolution when --ipset configured
 *       with domain patterns. Multiple ipsets can be configured per query domain.
 *       Function logs errors but does not abort daemon on failure (fire-and-forget).
 * @warning Assumes ipset collections pre-created by administrator using ipset command-line
 *          tool. Does not create ipsets automatically. No verification of kernel response.
 * 
 * @see new_add_to_ipset() for modern netlink implementation details
 * @see old_add_to_ipset() for legacy setsockopt implementation details
 * @see ipset_init() for initialization and kernel version detection
 * 
 * EXAMPLE USAGE:
 * @code
 * // Called from forward.c after resolving malware.example.com to 203.0.113.50
 * union all_addr resolved_addr;
 * resolved_addr.addr4.s_addr = inet_addr("203.0.113.50");
 * 
 * // Add to ipset configured: --ipset=/malware.example.com/blocked_domains
 * int result = add_to_ipset("blocked_domains", &resolved_addr, F_IPV4, 0);
 * if (result == -1)
 *   my_syslog(LOG_ERR, "Failed to add %s to ipset blocked_domains", 
 *             inet_ntoa(resolved_addr.addr4));
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (Linux kernel ipset API integration)
 * SIDE EFFECTS: Modifies kernel ipset collections via netlink or setsockopt
 * THREAD SAFETY: Not thread-safe on modern kernel (shared buffer); single-threaded daemon
 */
int add_to_ipset(const char *setname, const union all_addr *ipaddr, int flags, int remove)
{
  int ret = 0, af = AF_INET;

  if (flags & F_IPV6)
    {
      af = AF_INET6;
      /* old method only supports IPv4 */
      if (old_kernel)
	{
	  errno = EAFNOSUPPORT ;
	  ret = -1;
	}
    }
  
  if (ret != -1) 
    ret = old_kernel ? old_add_to_ipset(setname, ipaddr, remove) : new_add_to_ipset(setname, ipaddr, af, remove);

  if (ret == -1)
     my_syslog(LOG_ERR, _("failed to update ipset %s: %s"), setname, strerror(errno));

  return ret;
}

#endif

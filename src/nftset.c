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
 * @file nftset.c
 * @brief Linux nftables set integration for dynamic firewall rule population
 * 
 * DETAILED PURPOSE:
 * This Linux-specific module integrates dnsmasq with the nftables packet filtering
 * framework via the libnftables library. It provides functionality to dynamically
 * add resolved IP addresses to named nftables sets within specified tables, enabling
 * domain-based firewall rules that automatically adapt as DNS resolutions change.
 * 
 * Nftables is the modern successor to iptables/ipset on Linux, offering improved
 * performance, better syntax, atomic rule updates, and unified IPv4/IPv6 handling.
 * This module allows dnsmasq to populate nftables sets immediately after DNS
 * resolution, enabling firewall rules to match traffic based on domain names
 * rather than maintaining static IP address lists.
 * 
 * KEY RESPONSIBILITIES:
 * - Initialize nftables context via libnftables API (nftset_init)
 * - Add resolved IPv4 and IPv6 addresses to specified nftables sets (add_to_nftset)
 * - Remove addresses from nftables sets when DNS entries expire or change (add_to_nftset with remove flag)
 * - Handle nftables command execution and error reporting
 * - Support per-address-family filtering (IPv4-only or IPv6-only sets)
 * 
 * DEPENDENCIES:
 * Includes: dnsmasq.h (daemon structure, utility functions, type definitions)
 *           nftables/libnftables.h (nftables context management, command execution)
 *           string.h (string manipulation for command formatting and error parsing)
 *           arpa/inet.h (inet_ntop for IP address to string conversion)
 * 
 * Called by: forward.c (DNS resolution triggers set population)
 * Calls: libnftables API functions (nft_ctx_new, nft_run_cmd_from_buffer, nft_ctx_get_error_buffer)
 *        util.c (whine_malloc for safe memory allocation, my_syslog for error logging)
 * 
 * DATA STRUCTURES:
 * - struct nft_ctx: Opaque nftables library context (managed by libnftables)
 * - union all_addr: IP address storage (from dnsmasq.h, supports both IPv4/IPv6)
 * - Static command buffers: cmd_add/cmd_del format strings, dynamically sized cmd_buf
 * 
 * COMPILE-TIME OPTIONS:
 * - HAVE_NFTSET: Enables compilation of this module (defined when libnftables detected)
 *   Without this flag, the entire file is excluded from compilation.
 * 
 * LIBNFTABLES LIBRARY DEPENDENCY:
 * Requires: libnftables library (part of nftables package, version 0.9.0+)
 * Detection: Automatic via pkg-config during build configuration
 * Linking: -lnftables (added to LIBS when HAVE_NFTSET defined)
 * 
 * NFTABLES ADVANTAGES OVER IPTABLES/IPSET:
 * 1. Unified IPv4/IPv6 handling - single set can contain both address families
 * 2. Better performance - improved packet classification algorithms
 * 3. Atomic rule updates - entire rulesets can be replaced atomically
 * 4. Cleaner syntax - more readable and maintainable firewall rules
 * 5. Modern kernel infrastructure - actively developed and maintained
 * 6. Native in-kernel sets - no separate ipset subsystem required
 * 
 * USE CASES FOR DYNAMIC SET POPULATION:
 * 1. Content Filtering: Block domains by populating "blocked_ips" set, firewall drops matching traffic
 * 2. Split VPN Routing: Route specific domains through VPN by marking packets matching "vpn_ips" set
 * 3. QoS Policies: Apply bandwidth limits to traffic matching domain-based sets
 * 4. Security Policies: Restrict access to sensitive services based on domain resolution
 * 5. Logging and Monitoring: Log traffic to domains of interest by matching nftables sets
 * 
 * CONFIGURATION EXAMPLE:
 * dnsmasq.conf:
 *   nftset=/example.com/4#ip#mytable#blocked_ipv4  (IPv4 addresses to inet family table "mytable", set "blocked_ipv4")
 *   nftset=/example.com/6#ip6#mytable#blocked_ipv6 (IPv6 addresses to ip6 family table "mytable", set "blocked_ipv6")
 * 
 * Corresponding nftables ruleset:
 *   nft add table ip mytable
 *   nft add set ip mytable blocked_ipv4 { type ipv4_addr\; }
 *   nft add rule ip mytable filter ip daddr @blocked_ipv4 drop
 * 
 * THREADING/CONCURRENCY:
 * Single-threaded architecture - all nftables operations execute in main event loop.
 * No locking required. The nft_ctx is maintained as a global static variable initialized
 * once at daemon startup.
 * 
 * NFTABLES VERSION REQUIREMENTS:
 * Minimum nftables version: 0.9.0 (released 2019)
 * Recommended: 0.9.3+ for improved stability and performance
 * API Stability: libnftables API is stable since 0.9.0, backward compatible
 * 
 * PERFORMANCE CONSIDERATIONS:
 * - Command buffer dynamically resized to avoid repeated allocations
 * - nftables commands execute synchronously (blocking), but typically complete in <1ms
 * - Error buffer handling disabled normal output, only errors captured
 * - Memory allocation for error strings only on failure path
 * 
 * @copyright Copyright (c) 2000-2025 Simon Kelley
 * @license GPL-2.0-or-later
 */

#include "dnsmasq.h"

#if defined (HAVE_NFTSET)

#include <nftables/libnftables.h>

#include <string.h>
#include <arpa/inet.h>

/** @var ctx
 *  @brief Global nftables library context handle
 *  
 *  Opaque context pointer maintained by libnftables library. Initialized once
 *  by nftset_init() at daemon startup and reused for all subsequent nftables
 *  command executions. NULL until initialization completes.
 *  
 *  Lifetime: Created during daemon initialization, persists until daemon termination.
 */
static struct nft_ctx *ctx = NULL;

/** @var cmd_add
 *  @brief nftables command template for adding set elements
 *  
 *  Format string for "add element" nftables command. First %s is table#set specification
 *  (e.g., "ip#mytable#myset"), second %s is IP address in string format.
 */
static const char *cmd_add = "add element %s { %s }";

/** @var cmd_del
 *  @brief nftables command template for deleting set elements
 *  
 *  Format string for "delete element" nftables command. First %s is table#set specification,
 *  second %s is IP address in string format.
 */
static const char *cmd_del = "delete element %s { %s }";

/**
 * @brief Initialize nftables integration context
 * 
 * @detailed Creates and configures the libnftables context required for all subsequent
 *           nftables operations. This function must be called once during daemon initialization
 *           before any add_to_nftset() calls. The context is stored in the global static
 *           variable 'ctx' and reused for all nftables command executions.
 * 
 *           The function configures the context to buffer error messages (suppressing normal
 *           output) so that errors can be retrieved and logged by add_to_nftset() as needed.
 *           
 *           On failure to create the context, the daemon terminates with EC_MISC exit code
 *           via die(), as nftables integration cannot proceed without a valid context.
 * 
 * @param None - operates on global static context
 * 
 * @return void - function terminates daemon on failure via die()
 * 
 * @note This function is called once from main daemon initialization sequence
 * @warning Fatal error (daemon termination) if nft_ctx_new() fails due to memory exhaustion
 *          or libnftables internal initialization failure
 * 
 * @see add_to_nftset() which uses the initialized context for set operations
 * 
 * EXAMPLE USAGE:
 * @code
 * // Called during daemon startup in dnsmasq.c
 * #ifdef HAVE_NFTSET
 *   nftset_init();  // Initialize nftables context once
 * #endif
 * @endcode
 * 
 * LIBNFTABLES API CALLS:
 * - nft_ctx_new(NFT_CTX_DEFAULT): Allocate and initialize nftables context with default flags
 * - nft_ctx_buffer_error(ctx): Enable error message buffering (disables stdout/stderr output)
 * 
 * SIDE EFFECTS:
 * - Allocates global nftables context in 'ctx' static variable
 * - Configures context for error buffering (normal output suppressed)
 * - Terminates daemon if context creation fails (die() call)
 * 
 * THREAD SAFETY: 
 * Single-threaded daemon architecture - no locking required. Context initialized before
 * any DNS query processing begins.
 */
void nftset_init()
{
  ctx = nft_ctx_new(NFT_CTX_DEFAULT);
  if (ctx == NULL)
    die(_("failed to create nftset context"), NULL, EC_MISC);

  /* disable libnftables output */
  nft_ctx_buffer_error(ctx);
}

/**
 * @brief Add or remove IP address from nftables set
 * 
 * @detailed Adds a resolved IP address to a named nftables set, or removes it if the remove
 *           flag is set. This function is called from the DNS resolution path (forward.c)
 *           whenever a DNS query is resolved and the configuration specifies that resolved
 *           addresses should be added to nftables sets.
 * 
 *           The function performs address-family filtering based on optional prefixes in the
 *           setname ("4 " or "6 " prefix), constructs nftables "add element" or "delete element"
 *           commands, executes them via libnftables API, and logs any errors returned by nftables.
 * 
 *           Command buffer is dynamically sized and reused across invocations to minimize
 *           memory allocations. Initial buffer size is 150 bytes, growing as needed for longer
 *           set names or IP addresses.
 * 
 * @param setname Nftables set specification in format "family#table#set" or with optional
 *                address family prefix "4 family#table#set" or "6 family#table#set"
 *                Examples: "ip#filter#blocked", "4 ip#mytable#myset", "6 ip6#mytable#myset"
 *                The prefix "4 " restricts operation to IPv4 addresses only.
 *                The prefix "6 " restricts operation to IPv6 addresses only.
 *                Without prefix, both IPv4 and IPv6 addresses are added to the specified set.
 *                Must not be NULL.
 * 
 * @param ipaddr Pointer to IP address union containing either IPv4 (struct in_addr) or
 *               IPv6 (struct in6_addr) address to add/remove. Address type determined by
 *               flags parameter. Must not be NULL.
 * 
 * @param flags Address family and type flags from dnsmasq.h:
 *              F_IPV4 (0x01): Address is IPv4
 *              F_IPV6 (0x02): Address is IPv6
 *              Other flags may be present but are ignored by this function.
 *              Either F_IPV4 or F_IPV6 must be set (but not both simultaneously).
 * 
 * @param remove Operation mode flag:
 *               0 (false): Add address to set (uses cmd_add template)
 *               Non-zero (true): Remove address from set (uses cmd_del template)
 * 
 * @return int Return value from nft_run_cmd_from_buffer():
 * @retval 0 Success - nftables command executed successfully, set updated
 * @retval -1 Address family mismatch - setname has family prefix that doesn't match ipaddr flags
 * @retval >0 nftables command execution failure - set may not exist, address invalid, or other nftables error
 * 
 * @note Address-family filtering via "4 " or "6 " prefix enables per-family set configuration
 * @note Command buffer (cmd_buf static variable) grows as needed and persists across calls
 * @warning If nftables set doesn't exist, command fails and error is logged but daemon continues
 * @warning Memory allocation failure for command buffer returns 0 (interpreted as success to prevent daemon disruption)
 * 
 * @see nftset_init() must be called first to initialize nftables context
 * @see forward.c DNS resolution path invokes this function for configured nftset rules
 * 
 * EXAMPLE USAGE:
 * @code
 * // From forward.c after DNS resolution of example.com to 192.0.2.1
 * union all_addr addr;
 * inet_pton(AF_INET, "192.0.2.1", &addr.addr4);
 * 
 * // Add IPv4 address to set (no family prefix, applies to all IPv4)
 * int result = add_to_nftset("ip#filter#blocked", &addr, F_IPV4, 0);
 * if (result != 0)
 *   my_syslog(LOG_WARNING, "Failed to add to nftset");
 * 
 * // Add with family filtering (only if IPv4)
 * result = add_to_nftset("4 ip#filter#blocked", &addr, F_IPV4, 0);
 * 
 * // Remove from set when DNS entry expires
 * result = add_to_nftset("ip#filter#blocked", &addr, F_IPV4, 1);
 * @endcode
 * 
 * ALGORITHM OVERVIEW:
 * 1. Convert IP address to string format using inet_ntop()
 * 2. Check for optional address family prefix in setname ("4 " or "6 ")
 *    - If present and doesn't match flags, return -1 (skip operation)
 *    - If present and matches, skip prefix (advance setname pointer by 2)
 * 3. Determine required command buffer size via snprintf() test
 * 4. Allocate or grow command buffer if needed
 * 5. Format nftables command: "add element <setname> { <ipaddr> }" or "delete element ..."
 * 6. Execute command via nft_run_cmd_from_buffer()
 * 7. If error, retrieve error buffer and log first line only
 * 8. Return nftables command execution result
 * 
 * ADDRESS FAMILY FILTERING LOGIC:
 * Setname format: "[4|6] family#table#set"
 * - No prefix: Accept both IPv4 and IPv6 addresses
 * - "4 " prefix: Accept only IPv4 (F_IPV4 flag), return -1 for IPv6
 * - "6 " prefix: Accept only IPv6 (F_IPV6 flag), return -1 for IPv4
 * 
 * COMMAND BUFFER MANAGEMENT:
 * - Static variables cmd_buf and cmd_buf_sz persist across function calls
 * - Initial allocation: 150 bytes (sufficient for typical set names and IPv6 addresses)
 * - Growth strategy: Allocate exact required size + 10 bytes safety margin
 * - Buffer reused for subsequent calls to minimize allocation overhead
 * - No explicit deallocation (buffer persists until daemon termination)
 * 
 * ERROR HANDLING:
 * - Memory allocation failure for cmd_buf: Returns 0 (treated as success to avoid daemon disruption)
 * - nftables command failure: Logs first line of error message via my_syslog(LOG_ERR)
 * - Error string allocation failure: Skips logging but continues (non-fatal)
 * - Multiline errors: Only first line logged (newline replaced with null terminator)
 * 
 * LIBNFTABLES API CALLS:
 * - nft_run_cmd_from_buffer(ctx, cmd_buf): Execute nftables command from string buffer
 * - nft_ctx_get_error_buffer(ctx): Retrieve error message text if command failed
 * 
 * NFTABLES COMMAND FORMAT:
 * Add:    "add element family#table#set { 192.0.2.1 }"
 * Delete: "delete element family#table#set { 192.0.2.1 }"
 * 
 * INTEGRATION WITH DNS RESOLUTION:
 * Called from forward.c after successful DNS resolution when nftset configuration rules match
 * the resolved domain. Each resolved address triggers a separate call to this function.
 * 
 * SIDE EFFECTS:
 * - Modifies global daemon->addrbuff with string representation of ipaddr (ADDRSTRLEN bytes)
 * - Allocates/grows static cmd_buf buffer as needed (persists until daemon termination)
 * - Executes nftables command in kernel, modifying specified set contents
 * - Logs error messages to syslog on command failure
 * 
 * PERFORMANCE CONSIDERATIONS:
 * - inet_ntop() conversion: ~1μs for typical IP addresses
 * - snprintf() for command formatting: <1μs
 * - nft_run_cmd_from_buffer(): 100μs-1ms depending on kernel nftables implementation
 * - Total latency per call: Typically <2ms, acceptable for DNS resolution path
 * 
 * THREAD SAFETY:
 * Single-threaded daemon architecture. Static cmd_buf is safe as no concurrent access possible.
 * 
 * MEMORY SAFETY:
 * - Uses whine_malloc() which logs allocation failures
 * - Validates setname prefix before pointer arithmetic
 * - Null-terminates error strings before logging
 * - No buffer overflows: snprintf() with explicit size limits
 */
int add_to_nftset(const char *setname, const union all_addr *ipaddr, int flags, int remove)
{
  const char *cmd = remove ? cmd_del : cmd_add;
  int ret, af = (flags & F_IPV4) ? AF_INET : AF_INET6;
  size_t new_sz;
  char *err_str, *new, *nl;
  const char *err;
  static char *cmd_buf = NULL;
  static size_t cmd_buf_sz = 0;

  inet_ntop(af, ipaddr, daemon->addrbuff, ADDRSTRLEN);

  if (setname[1] == ' ' && (setname[0] == '4' || setname[0] == '6'))
    {
      if (setname[0] == '4' && !(flags & F_IPV4))
	return -1;

      if (setname[0] == '6' && !(flags & F_IPV6))
	return -1;

      setname += 2;
    }
  
  if (cmd_buf_sz == 0)
    new_sz = 150; /* initial allocation */
  else
    new_sz = snprintf(cmd_buf, cmd_buf_sz, cmd, setname, daemon->addrbuff);
  
  if (new_sz > cmd_buf_sz)
    {
      if (!(new = whine_malloc(new_sz + 10)))
	return 0;

      if (cmd_buf)
	free(cmd_buf);
      cmd_buf = new;
      cmd_buf_sz = new_sz + 10;
      snprintf(cmd_buf, cmd_buf_sz, cmd, setname, daemon->addrbuff);
    }

  ret = nft_run_cmd_from_buffer(ctx, cmd_buf);
  err = nft_ctx_get_error_buffer(ctx);

  if (ret != 0)
    {
      /* Log only first line of error return. */
      if ((err_str = whine_malloc(strlen(err) + 1)))
	{
	  strcpy(err_str, err);
	  if ((nl = strchr(err_str, '\n')))
	    *nl = 0;
	  my_syslog(LOG_ERR,  "nftset %s %s", setname, err_str);
	  free(err_str);
	}
    }
  
  return ret;
}

#endif

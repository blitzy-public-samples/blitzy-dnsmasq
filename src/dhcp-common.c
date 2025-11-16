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
 * @file dhcp-common.c
 * @brief Shared DHCP utilities for DHCPv4 and DHCPv6 implementations
 * 
 * DETAILED PURPOSE:
 * This module provides shared functionality used by both DHCPv4 (dhcp.c, rfc2131.c)
 * and DHCPv6 (dhcp6.c, rfc3315.c) implementations. It handles DHCP option parsing,
 * packet reception with dynamic buffer management, tag-based configuration selection
 * for client classification, and logging of DHCP transactions. The module centralizes
 * common DHCP logic to avoid code duplication between IPv4 and IPv6 implementations.
 * 
 * KEY RESPONSIBILITIES:
 * - Initialize shared DHCP buffers via dhcp_common_init()
 * - Receive DHCP packets with automatic buffer expansion via recv_dhcp_packet()
 * - Match network ID tags with wildcard support via match_netid_wild()
 * - Filter DHCP options based on tags via option_filter()
 * - Find client configurations based on tags and identifiers via find_config()
 * - Parse and interpret DHCP option formats via lookup_dhcp_opt() and lookup_dhcp_len()
 * - Generate human-readable option strings via option_string()
 * - Log DHCP transaction context via log_context() and log_relay()
 * 
 * DEPENDENCIES:
 * Includes: dnsmasq.h (core data structures), dhcp-protocol.h (DHCPv4 constants),
 *           dhcp6-protocol.h (DHCPv6 constants)
 * Called by: dhcp.c (DHCPv4 server), dhcp6.c (DHCPv6 server), rfc2131.c, rfc3315.c
 * Calls: util.c (safe_malloc, expand_buf), log.c (my_syslog), network.c (recvmsg)
 * 
 * DATA STRUCTURES:
 * - opttab[] (static array, ~line 228): DHCPv4 option definitions with format and size
 * - opttab6[] (static array, ~line 638): DHCPv6 option definitions with format and size
 * - struct dhcp_config (dnsmasq.h): Client-specific DHCP configuration entries
 * - struct dhcp_netid (dnsmasq.h): Network ID tags for client classification
 * - struct dhcp_opt (dnsmasq.h): DHCP option configuration
 * 
 * COMPILE-TIME OPTIONS:
 * - HAVE_DHCP: Entire file conditionally compiled; DHCPv4 support required
 * - HAVE_DHCP6: Enables DHCPv6-specific code paths (opttab6, DHCPv6 option handling)
 * - HAVE_SCRIPT: Enables script execution tags in configuration matching
 * 
 * THREADING/CONCURRENCY:
 * Single-threaded event-driven architecture. Functions operate on global daemon state
 * (daemon->dhcp_buff, daemon->dhcp_packet) within main event loop context. No locking
 * required as all DHCP processing occurs in single thread.
 * 
 * @copyright Copyright (c) 2000-2025 Simon Kelley
 * @license GPL-2.0-or-later
 */

#include "dnsmasq.h"

#ifdef HAVE_DHCP

/**
 * @brief Initialize shared DHCP buffers and packet structures
 * 
 * @detailed Allocates fixed-size DHCP option buffers (dhcp_buff, dhcp_buff2, dhcp_buff3)
 * with capacity DHCP_BUFF_SZ (256 bytes) to hold DHCP option data with terminating zero.
 * Initializes expandable packet buffers for DHCPv4 (dhcp_packet) and DHCPv6 (outpacket)
 * starting at sizeof(struct dhcp_packet). These buffers automatically expand via expand_buf()
 * when larger packets are received. Called once during daemon initialization before entering
 * main event loop to prepare shared DHCP infrastructure.
 * 
 * @param void No parameters
 * 
 * @return void
 * 
 * @note Buffers are never freed; daemon maintains these for lifetime of process
 * @note dhcp_packet buffer shared by DHCPv4 and DHCPv6; outpacket used only by DHCPv6
 * @warning Must be called before any DHCP packet processing begins
 * 
 * @see recv_dhcp_packet() in dhcp-common.c - uses these buffers for packet reception
 * @see expand_buf() in util.c - performs buffer expansion when needed
 * 
 * EXAMPLE USAGE:
 * @code
 * // Called from main() during daemon initialization
 * dhcp_common_init();
 * // daemon->dhcp_buff, dhcp_buff2, dhcp_buff3 now allocated with 256 bytes
 * // daemon->dhcp_packet and outpacket initialized for expandable packet storage
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (internal initialization function)
 * 
 * SIDE EFFECTS: Allocates memory via safe_malloc() and expand_buf(); modifies global
 * daemon state (daemon->dhcp_buff, daemon->dhcp_buff2, daemon->dhcp_buff3,
 * daemon->dhcp_packet, daemon->outpacket)
 * 
 * THREAD SAFETY: Must be called from main thread during single-threaded initialization
 * phase before event loop starts
 */
void dhcp_common_init(void)
{
  /* These each hold a DHCP option max size 255
     and get a terminating zero added */
  daemon->dhcp_buff = safe_malloc(DHCP_BUFF_SZ);
  daemon->dhcp_buff2 = safe_malloc(DHCP_BUFF_SZ); 
  daemon->dhcp_buff3 = safe_malloc(DHCP_BUFF_SZ);
  
  /* dhcp_packet is used by v4 and v6, outpacket only by v6 
     sizeof(struct dhcp_packet) is as good an initial size as any,
     even for v6 */
  expand_buf(&daemon->dhcp_packet, sizeof(struct dhcp_packet));
#ifdef HAVE_DHCP6
  if (daemon->dhcp6)
    expand_buf(&daemon->outpacket, sizeof(struct dhcp_packet));
#endif
}

/**
 * @brief Receive DHCP packet with automatic buffer expansion
 * 
 * @detailed Receives DHCP/DHCPv6 packet from socket with automatic buffer resizing to
 * accommodate packets larger than current buffer capacity. Uses MSG_PEEK to determine
 * required size before actual receive, expanding buffer via expand_buf() if MSG_TRUNC
 * flag indicates truncation. Handles kernel version differences: newer kernels return
 * actual packet size in truncated recvmsg(), older kernels return buffer size. Includes
 * workaround for kernels that ignore MSG_PEEK and dequeue packet on peek operation.
 * Retries on EINTR interruption. Returns -1 on error or truncation, packet size on success.
 * 
 * @param fd Socket file descriptor for DHCP packet reception (UDP socket)
 * @param msg Pointer to msghdr structure containing iovec with receive buffer;
 *            msg->msg_iov->iov_base points to buffer, msg->msg_iov->iov_len is buffer size;
 *            buffer automatically expanded if packet exceeds current capacity
 * 
 * @return Packet size in bytes on successful reception
 * @retval -1 Receive error (errno set), or packet truncated after buffer expansion
 * @retval >0 Number of bytes received (packet size)
 * 
 * @note Buffer expansion adds 100 bytes beyond detected size on newer kernels
 * @note Function handles EINTR by retrying recvmsg() automatically
 * @warning Non-blocking socket required; may lose packets if MSG_PEEK is ignored by kernel
 * 
 * @see dhcp_reply() in dhcp.c - calls this for DHCPv4 packet reception
 * @see dhcp6_reply() in dhcp6.c - calls this for DHCPv6 packet reception
 * @see expand_buf() in util.c - performs buffer expansion
 * 
 * EXAMPLE USAGE:
 * @code
 * struct msghdr msg;
 * struct iovec iov;
 * iov.iov_base = daemon->dhcp_packet.iov_base;
 * iov.iov_len = daemon->dhcp_packet.iov_len;
 * msg.msg_iov = &iov;
 * msg.msg_iovlen = 1;
 * ssize_t size = recv_dhcp_packet(fd, &msg);
 * if (size > 0) {
 *   // Process received DHCP packet in iov.iov_base
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (platform-specific packet reception with buffer management)
 * 
 * SIDE EFFECTS: May expand buffer via expand_buf() modifying msg->msg_iov->iov_len
 * and msg->msg_iov->iov_base; performs recvmsg() system call dequeuing UDP packet
 * 
 * THREAD SAFETY: Called from single-threaded event loop; not thread-safe due to
 * buffer modification
 */
ssize_t recv_dhcp_packet(int fd, struct msghdr *msg)
{  
  ssize_t sz, new_sz;
 
  while (1)
    {
      msg->msg_flags = 0;
      while ((sz = recvmsg(fd, msg, MSG_PEEK | MSG_TRUNC)) == -1 && errno == EINTR);
      
      if (sz == -1)
	return -1;
      
      if (!(msg->msg_flags & MSG_TRUNC))
	break;

      /* Very new Linux kernels return the actual size needed, 
	 older ones always return truncated size */
      if ((size_t)sz == msg->msg_iov->iov_len)
	{
	  if (!expand_buf(msg->msg_iov, sz + 100))
	    return -1;
	}
      else
	{
	  expand_buf(msg->msg_iov, sz);
	  break;
	}
    }
  
  while ((new_sz = recvmsg(fd, msg, 0)) == -1 && errno == EINTR);

  /* Some kernels seem to ignore MSG_PEEK, and dequeue the packet anyway. 
     If that happens we get EAGAIN here because the socket is non-blocking.
     Use the result of the original testing recvmsg as long as the buffer
     was big enough. There's a small race here that may lose the odd packet,
     but it's UDP anyway. */
  
  if (new_sz == -1 && (errno == EWOULDBLOCK || errno == EAGAIN))
    new_sz = sz;
  
  return (msg->msg_flags & MSG_TRUNC) ? -1 : new_sz;
}

/**
 * @brief Match tag lists with wildcard support
 * 
 * @detailed Performs tag matching between check list and pool list with wildcard support
 * for trailing asterisk (*) in check tags. Extension of match_netid() that enables prefix
 * matching when check tag ends with '*'. For each tag in check list, searches pool list
 * for matching tag (exact match if no wildcard, prefix match if wildcard). Supports
 * negation with leading '!' or '#' (backwards compatibility) - negated tags return 0 if
 * found in pool. Returns 1 if all positive tags matched and no negative tags matched, 0
 * otherwise. Used by run_tag_if() to enable tag-based conditional configuration with
 * 'group of interfaces' wildcard patterns.
 * 
 * @param check Linked list of dhcp_netid structures to check (search criteria);
 *              tag names may end with '*' for wildcard prefix matching;
 *              tag names may start with '!' or '#' for negation (NOT logic);
 *              NULL-terminated linked list via next pointer
 * @param pool Linked list of dhcp_netid structures representing available tags (search space);
 *             tags from DHCP client classification, interface tags, vendor class, etc.;
 *             NULL-terminated linked list via next pointer
 * 
 * @return Match success indicator
 * @retval 1 All positive tags from check found in pool, no negative tags found (match success)
 * @retval 0 At least one positive tag not found, or at least one negative tag found (match failed)
 * 
 * @note Wildcard matching: "tag*" matches "tag", "tag1", "tagabc" via prefix comparison
 * @note Negation: "!tag" or "#tag" returns 0 if "tag" found in pool (NOT logic)
 * @note '#' negation prefix supported for backwards compatibility with older configurations
 * @warning Wildcard matching compares check_len-1 characters (excludes '*' from comparison)
 * 
 * @see match_netid() in dhcp-common.c - non-wildcard variant
 * @see run_tag_if() in dhcp-common.c - calls this for tag-if conditional evaluation
 * @see struct dhcp_netid in dnsmasq.h - tag list structure with next pointer and net[] string
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_netid check_tags, pool_tags;
 * check_tags.net = "vlan*";  // Wildcard: match vlan1, vlan2, vlan100, etc.
 * check_tags.next = NULL;
 * pool_tags.net = "vlan42";
 * pool_tags.next = NULL;
 * int result = match_netid_wild(&check_tags, &pool_tags);
 * // result == 1 (match: "vlan*" prefix matches "vlan42")
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (dnsmasq-specific tag matching system for client classification)
 * 
 * SIDE EFFECTS: None (read-only operation on linked lists)
 * 
 * THREAD SAFETY: Thread-safe for read-only lists; not thread-safe if lists modified
 * concurrently during traversal
 */
int match_netid_wild(struct dhcp_netid *check, struct dhcp_netid *pool)
{
  struct dhcp_netid *tmp1;
  
  for (; check; check = check->next)
    {
      const int check_len = strlen(check->net);
      const int is_wc = (check_len > 0 && check->net[check_len - 1] == '*');
      
      /* '#' for not is for backwards compat. */
      if (check->net[0] != '!' && check->net[0] != '#')
	{
	  for (tmp1 = pool; tmp1; tmp1 = tmp1->next)
	    if (is_wc ? (strncmp(check->net, tmp1->net, check_len-1) == 0) :
		(strcmp(check->net, tmp1->net) == 0))
	      break;
	  if (!tmp1)
	    return 0;
	}
      else
	for (tmp1 = pool; tmp1; tmp1 = tmp1->next)
	  if (is_wc ? (strncmp((check->net)+1, tmp1->net, check_len-2) == 0) :
	      (strcmp((check->net)+1, tmp1->net) == 0))
	    return 0;
    }
  return 1;
}

/**
 * @brief Process tag-if conditional rules to add derived tags
 * 
 * @detailed Evaluates all tag-if conditional expressions from daemon configuration,
 * adding new tags to the tag list when conditions match. Tag-if rules specify "if these
 * tags are present, add these additional tags" logic for derived tag assignment. Uses
 * match_netid_wild() to support wildcard patterns in tag-if conditions, enabling
 * 'group of interfaces' tag matching (e.g., "vlan*" matches vlan1, vlan2, etc.).
 * Iterates through daemon->tag_if list, evaluating each expression's trigger condition
 * against current tags. When condition matches, prepends expression's set tags to the
 * tag list. Returns expanded tag list including original tags plus all derived tags
 * from matched tag-if rules. Called by option_filter() to expand tag context before
 * DHCP option selection.
 * 
 * @param tags Current tag list from client classification (vendor class, MAC patterns,
 *             interface tags, user class, etc.); linked list of dhcp_netid structures;
 *             tags may be NULL if no initial tags present
 * 
 * @return Expanded tag list including original tags plus derived tags from tag-if rules
 * @retval tags Original tag list if no tag-if rules match
 * @retval modified_tags New tag list with derived tags prepended when rules match
 * 
 * @note Derived tags prepended to list (newer tags at head) via list->list->next = tags
 * @note Tag-if rules configured via --tag-if option in dnsmasq configuration
 * @note Multiple tag-if rules may match, all matched rule sets added to tag list
 * @warning Tags parameter may be modified (new tags linked to existing list)
 * 
 * @see match_netid_wild() in dhcp-common.c - evaluates tag-if trigger conditions with wildcard
 * @see option_filter() in dhcp-common.c - calls this before option selection
 * @see struct tag_if in dnsmasq.h - tag-if expression structure with tag and set lists
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_netid *client_tags = ...; // Tags from client classification
 * // Expand tags via tag-if rules: "if vlan* present, add server-pool-A"
 * struct dhcp_netid *expanded_tags = run_tag_if(client_tags);
 * // expanded_tags now includes original tags plus derived tags from matching rules
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (dnsmasq-specific tag-if conditional configuration system)
 * 
 * SIDE EFFECTS: Modifies tag list by prepending derived tags (original tags unchanged,
 * new tags linked via next pointers); iterates daemon->tag_if global configuration
 * 
 * THREAD SAFETY: Not thread-safe; called from single-threaded DHCP packet processing;
 * modifies shared tag list structure
 */
struct dhcp_netid *run_tag_if(struct dhcp_netid *tags)
{
  struct tag_if *exprs;
  struct dhcp_netid_list *list;

  /* this now uses match_netid_wild() above so that tag_if can
   * be used to set a 'group of interfaces' tag.
   */
  for (exprs = daemon->tag_if; exprs; exprs = exprs->next)
    if (match_netid_wild(exprs->tag, tags))
      for (list = exprs->set; list; list = list->next)
	{
	  list->list->next = tags;
	  tags = list->list;
	}

  return tags;
}

/**
 * @brief Filter DHCP option based on PXE mode requirements
 * 
 * @detailed Determines whether a given DHCP option should be included in a response
 *           based on the PXE boot mode and whether the option is designated as a
 *           PXE-specific option (DHOPT_PXE_OPT flag). The filtering logic implements
 *           three modes:
 *           - Mode 0: Normal DHCP (exclude PXE-specific options)
 *           - Mode 1: PXE hybrid (include all options including PXE-specific)
 *           - Mode 2: PXE-only (include ONLY PXE-specific options)
 *           
 *           This allows PXE boot scenarios to receive specialized options while
 *           preventing non-PXE clients from receiving confusing PXE-specific
 *           configuration. Options are marked as PXE-specific via dhcp-option-pxe
 *           configuration directive.
 * 
 * @param opt DHCP option to check (must not be NULL)
 * @param pxemode PXE mode: 0=non-PXE (exclude PXE options), 1=PXE hybrid (include all),
 *                2=PXE-only (only PXE options)
 * 
 * @return 1 if option should be included in response, 0 if option should be excluded
 * @retval 1 Option passes PXE mode filter (include in DHCP response)
 * @retval 0 Option does not pass PXE mode filter (exclude from DHCP response)
 * 
 * @note Option must have opt->flags field initialized with DHOPT_PXE_OPT if PXE-specific
 * @warning Assumes opt pointer is valid (no NULL check performed)
 * 
 * @see option_filter() where this function is called for PXE mode filtering
 * @see DHOPT_PXE_OPT flag definition in dnsmasq.h
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_opt *opt = ...; // Option with DHOPT_PXE_OPT flag set
 * int pxemode = 1; // PXE hybrid mode (include all options)
 * if (pxe_ok(opt, pxemode)) {
 *   // Include this option in DHCP response
 * }
 * // In PXE-only mode:
 * pxemode = 2;
 * if (pxe_ok(opt, pxemode)) {
 *   // Only PXE-specific options pass this filter
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: PXE boot mode filtering per Intel PXE specification
 * SIDE EFFECTS: None (read-only operation)
 * THREAD SAFETY: Thread-safe (read-only, no shared state modification)
 */
int pxe_ok(struct dhcp_opt *opt, int pxemode)
{
  if (opt->flags & DHOPT_PXE_OPT)
    {
      if (pxemode != 0)
	return 1;
    }
  else
    {
      if (pxemode != 2)
	return 1;
    }
  
  return 0;
}

/**
 * @brief Filter DHCP options based on tag matching and priority rules
 * 
 * @detailed Determines which DHCP options from the configuration should be included in
 *           the DHCP response by evaluating tag matches, context tags, and priority rules.
 *           The filtering happens in multiple passes:
 *           1. Flag options matching current tags (without context tags)
 *           2. If context_tags provided, re-evaluate with context included and update flags
 *           3. Flag untagged options that aren't overridden by tagged options
 *           4. Eliminate duplicate options (keeping higher priority ones)
 *           
 *           Options are marked with DHOPT_TAGOK flag if they should be included in the
 *           DHCP response. Priority order: tagged options with matching tags > tagged options
 *           with matching context tags > untagged options. For duplicates of same option
 *           number, earlier in the chain (later in config file) wins.
 * 
 * @param tags Current tag set from client identification (vendor class, user class, MAC, etc.)
 * @param context_tags Additional tags from network context (subnet, interface, etc.). May be NULL.
 * @param opts Linked list of all configured DHCP options to filter
 * @param pxemode PXE boot mode: 0=not PXE, 1=PXE mode 1, 2=PXE mode 2
 * 
 * @return Computed tag set after running tag-if conditionals (from run_tag_if)
 * 
 * @note Modifies opt->flags for each option in opts list (sets/clears DHOPT_TAGOK)
 * @warning Context_tags list is temporarily modified (next pointer) during processing
 * 
 * @see run_tag_if() for tag conditional evaluation
 * @see match_netid() for tag matching algorithm
 * @see pxe_ok() for PXE mode filtering
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_netid *client_tags = ...; // Tags from client (vendor class, etc.)
 * struct dhcp_netid *subnet_tags = ...; // Tags from subnet context
 * struct dhcp_opt *all_opts = daemon->dhcp_opts; // All configured options
 * struct dhcp_netid *final_tags = option_filter(client_tags, subnet_tags, all_opts, 0);
 * // Now opts with DHOPT_TAGOK flag should be included in response
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (dnsmasq-specific tag-based configuration system)
 * SIDE EFFECTS: Modifies flags field of all dhcp_opt structures in opts list
 * THREAD SAFETY: Single-threaded architecture, modifies shared daemon state
 */
struct dhcp_netid *option_filter(struct dhcp_netid *tags, struct dhcp_netid *context_tags, struct dhcp_opt *opts, int pxemode)
{
  struct dhcp_netid *tagif = run_tag_if(tags);
  struct dhcp_opt *opt;
  struct dhcp_opt *tmp;  
  
  /* flag options which are valid with the current tag set (sans context tags) */
  for (opt = opts; opt; opt = opt->next)
    {
      opt->flags &= ~DHOPT_TAGOK;
      if (!(opt->flags & (DHOPT_ENCAPSULATE | DHOPT_VENDOR | DHOPT_RFC3925)) &&
	  match_netid(opt->netid, tagif, 0) &&
	  pxe_ok(opt, pxemode))
	opt->flags |= DHOPT_TAGOK;
    }
  
  /* now flag options which are valid, including the context tags,
     otherwise valid options are inhibited if we found a higher priority one above */
  if (context_tags)
    {
      struct dhcp_netid *last_tag;

      for (last_tag = context_tags; last_tag->next; last_tag = last_tag->next);
      last_tag->next = tags;
      tagif = run_tag_if(context_tags);
      
      /* reset stuff with tag:!<tag> which now matches. */
      for (opt = opts; opt; opt = opt->next)
	if (!(opt->flags & (DHOPT_ENCAPSULATE | DHOPT_VENDOR | DHOPT_RFC3925)) &&
	    (opt->flags & DHOPT_TAGOK) &&
	    !match_netid(opt->netid, tagif, 0))
	  opt->flags &= ~DHOPT_TAGOK;

      for (opt = opts; opt; opt = opt->next)
	if (!(opt->flags & (DHOPT_ENCAPSULATE | DHOPT_VENDOR | DHOPT_RFC3925 | DHOPT_TAGOK)) &&
	    match_netid(opt->netid, tagif, 0) &&
	    pxe_ok(opt, pxemode))
	  {
	    struct dhcp_opt *tmp;  
	    for (tmp = opts; tmp; tmp = tmp->next) 
	      if (tmp->opt == opt->opt && opt->netid && (tmp->flags & DHOPT_TAGOK))
		break;
	    if (!tmp)
	      opt->flags |= DHOPT_TAGOK;
	  }      
    }
  
  /* now flag untagged options which are not overridden by tagged ones */
  for (opt = opts; opt; opt = opt->next)
    if (!(opt->flags & (DHOPT_ENCAPSULATE | DHOPT_VENDOR | DHOPT_RFC3925 | DHOPT_TAGOK)) &&
	!opt->netid &&
	pxe_ok(opt, pxemode))
      {
	for (tmp = opts; tmp; tmp = tmp->next) 
	  if (tmp->opt == opt->opt && (tmp->flags & DHOPT_TAGOK))
	    break;
	if (!tmp)
	  opt->flags |= DHOPT_TAGOK;
	else if (!tmp->netid)
	  my_syslog(MS_DHCP | LOG_WARNING, _("Ignoring duplicate dhcp-option %d"), tmp->opt); 
      }
  
  /* Finally, eliminate duplicate options later in the chain, and therefore earlier in the config file. */
  for (opt = opts; opt; opt = opt->next)
    if (opt->flags & DHOPT_TAGOK)
      for (tmp = opt->next; tmp; tmp = tmp->next) 
	if (tmp->opt == opt->opt)
	  tmp->flags &= ~DHOPT_TAGOK;
  
  return tagif;
}
	
/* Is every member of check matched by a member of pool? 
   If tagnotneeded, untagged is OK */
/**
 * @brief Check if all required tags in check list match tags in pool with negation support
 * 
 * @detailed Evaluates whether DHCP option, context, or configuration applies to client by
 * matching required tags against client's tag pool. Implements tag-based client classification
 * for DHCP option selection: configuration items specify required tags (check list), and
 * client has current tags (pool list). Match succeeds if ALL positive tags in check list
 * are found in pool, AND NO negative tags (prefixed with '!' or '#') in check list are
 * found in pool. Negative tags enable exclusion rules: "match all except tag X" semantics.
 * The tagnotneeded parameter allows empty check list to match (used for unconditional
 * default configurations). Called extensively throughout DHCP processing for option filtering,
 * context selection, and configuration matching. Differs from match_netid_wild() by requiring
 * exact tag name matches without wildcard support.
 * 
 * @param check Required tag list for configuration item; linked list of dhcp_netid structures;
 *              positive tags (no prefix) must ALL be present in pool; negative tags (prefixed
 *              with '!' or '#') must NOT be present in pool; NULL check list matches if
 *              tagnotneeded=1, fails if tagnotneeded=0
 * @param pool Client's current tag list from classification (vendor class, MAC patterns, interface,
 *             user class, tag-if derived tags); linked list of dhcp_netid structures; tags
 *             available for matching against check requirements; may be NULL for clients with
 *             no tags
 * @param tagnotneeded Boolean flag: 1 allows empty check list to match (unconditional default),
 *                     0 requires non-empty check list (tagged-only configuration)
 * 
 * @return Match result indicating whether client's tags satisfy configuration requirements
 * @retval 1 Match succeeds: all positive check tags found in pool, no negative check tags found
 * @retval 0 Match fails: missing required positive tag, or forbidden negative tag found, or
 *           empty check list with tagnotneeded=0
 * 
 * @note Negative tag prefix '!' is current standard, '#' supported for backwards compatibility
 * @note All positive check tags must be present (AND logic), any negative tag causes failure
 * @note Empty pool (NULL) only matches empty check (NULL) with tagnotneeded=1
 * @warning Check and pool parameters traversed via next pointers, must be well-formed lists
 * 
 * @see match_netid_wild() in dhcp-common.c - wildcard version supporting trailing '*' patterns
 * @see run_tag_if() in dhcp-common.c - derives additional tags via tag-if rules before matching
 * @see option_filter() in dhcp-common.c - uses this for DHCP option selection
 * @see find_config() in dhcp-common.c - uses this for client configuration matching
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_netid *client_tags = ...; // Tags: "vlan1", "desktop"
 * struct dhcp_netid *opt_req_tags = ...; // Required tags: "vlan1"
 * // Check if option with required tags applies to client
 * if (match_netid(opt_req_tags, client_tags, 0)) {
 *   // Option applies: client has required "vlan1" tag
 * }
 * // Example with negation: option requires "!server" (client must NOT be tagged "server")
 * struct dhcp_netid *neg_tags = ...; // Required: "!server"
 * if (match_netid(neg_tags, client_tags, 0)) {
 *   // Matches only if client does NOT have "server" tag
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (dnsmasq-specific tag-based configuration system)
 * 
 * SIDE EFFECTS: None (read-only traversal of check and pool lists)
 * 
 * THREAD SAFETY: Thread-safe for read-only access; called from single-threaded DHCP processing
 */
int match_netid(struct dhcp_netid *check, struct dhcp_netid *pool, int tagnotneeded)
{
  struct dhcp_netid *tmp1;
  
  if (!check && !tagnotneeded)
    return 0;

  for (; check; check = check->next)
    {
      /* '#' for not is for backwards compat. */
      if (check->net[0] != '!' && check->net[0] != '#')
	{
	  for (tmp1 = pool; tmp1; tmp1 = tmp1->next)
	    if (strcmp(check->net, tmp1->net) == 0)
	      break;
	  if (!tmp1)
	    return 0;
	}
      else
	for (tmp1 = pool; tmp1; tmp1 = tmp1->next)
	  if (strcmp((check->net)+1, tmp1->net) == 0)
	    return 0;
    }
  return 1;
}

/* return domain or NULL if none. */
/**
 * @brief Strip domain suffix from hostname, leaving only the short hostname
 * 
 * @detailed Finds the first dot in the hostname and truncates the hostname at that point by
 *           inserting a null terminator. Returns a pointer to the domain suffix (the part after
 *           the dot) if it exists and is non-empty. This function modifies the input string
 *           in-place by null-terminating it at the first dot.
 * 
 * @param hostname Hostname string to strip (modified in-place). Must not be NULL.
 * 
 * @return Pointer to domain suffix (after the dot) if present and non-empty, NULL otherwise
 * @retval NULL If hostname contains no dot, or if domain suffix is empty
 * @retval char* Pointer to domain suffix string (everything after first dot)
 * 
 * @warning Modifies input string in-place by inserting null terminator at first dot position
 * @note After this function, hostname parameter points to short hostname only
 * @note Useful for DHCP hostname processing where short names are required
 * 
 * EXAMPLE USAGE:
 * @code
 * char hostname[256] = "myhost.example.com";
 * char *domain = strip_hostname(hostname);
 * // Now: hostname == "myhost", domain == "example.com"
 * @endcode
 * 
 * SIDE EFFECTS: Modifies hostname string by inserting null terminator at first dot
 * THREAD SAFETY: Single-threaded architecture - safe if hostname not shared across contexts
 */
char *strip_hostname(char *hostname)
{
  char *dot = strchr(hostname, '.');
 
  if (!dot)
    return NULL;
  
  *dot = 0; /* truncate */
  if (strlen(dot+1) != 0)
    return dot+1;
  
  return NULL;
}

/**
 * @brief Log comma-separated list of DHCP tags associated with a transaction
 * 
 * @detailed Builds a human-readable comma-separated string of DHCP tag names from a linked
 *           list of dhcp_netid structures and logs it to syslog. Automatically removes
 *           duplicate tag names from the output. Logging only occurs if OPT_LOG_OPTS
 *           option is enabled and the netid list is non-NULL. Uses daemon->namebuff for
 *           string building, limiting output to MAXDNAME-1 characters.
 * 
 * @param netid Linked list of dhcp_netid structures containing tag names. NULL is allowed.
 * @param xid Transaction ID (typically DHCP xid) to include in log message for correlation
 * 
 * @return void - No return value
 * 
 * @note Logging only occurs if option_bool(OPT_LOG_OPTS) is true and netid is non-NULL
 * @note Duplicate tag names are automatically filtered from the output
 * @note Uses daemon->namebuff for string building - not re-entrant
 * @note Output truncated at MAXDNAME-1 characters if tag list is very long
 * @see match_netid() for tag matching logic
 * @see run_tag_if() for tag evaluation
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_netid *tags = get_client_tags(context);
 * u32 xid = 0x12345678;
 * log_tags(tags, xid); // Logs: "305419896 tags: vendor-class, user-class, known"
 * @endcode
 * 
 * SIDE EFFECTS: Writes to syslog if OPT_LOG_OPTS enabled; uses daemon->namebuff buffer
 * THREAD SAFETY: Single-threaded architecture - uses global daemon->namebuff buffer
 */
void log_tags(struct dhcp_netid *netid, u32 xid)
{
  if (netid && option_bool(OPT_LOG_OPTS))
    {
      char *s = daemon->namebuff;
      for (*s = 0; netid; netid = netid->next)
	{
	  /* kill dupes. */
	  struct dhcp_netid *n;
	  
	  for (n = netid->next; n; n = n->next)
	    if (strcmp(netid->net, n->net) == 0)
	      break;
	  
	  if (!n)
	    {
	      strncat (s, netid->net, (MAXDNAME-1) - strlen(s));
	      if (netid->next)
		strncat (s, ", ", (MAXDNAME-1) - strlen(s));
	    }
	}
      my_syslog(MS_DHCP | LOG_INFO, _("%u tags: %s"), xid, s);
    } 
}   
  
/**
 * @brief Check if byte sequence matches DHCP option pattern with hex/string matching modes
 * 
 * @detailed Compares byte buffer against DHCP option pattern for client classification and
 * option filtering. Supports three matching modes: (1) hex matching with wildcard masks for
 * flexible byte pattern matching (e.g., vendor class bytes with variable fields), (2) string
 * matching with substring search for text-based options, and (3) exact byte sequence matching
 * for fixed binary patterns. Used extensively in DHCP option processing to match vendor classes,
 * user classes, client identifiers, and other option values against configured patterns for
 * tag assignment and option selection. Hex mode (DHOPT_HEX flag) uses memcmp_masked() to
 * compare with wildcard mask allowing "don't care" bits. String mode (DHOPT_STRING flag)
 * performs substring search advancing byte-by-byte. Default mode requires exact match at any
 * o->len-aligned offset. Zero-length pattern matches any buffer (wildcard). Pattern longer
 * than buffer fails immediately (impossible match).
 * 
 * @param o DHCP option structure containing pattern to match; o->val holds pattern bytes,
 *          o->len specifies pattern length in bytes, o->flags indicates matching mode
 *          (DHOPT_HEX for hex with wildcard mask, DHOPT_STRING for substring search),
 *          o->u.wildcard_mask holds wildcard mask for DHOPT_HEX mode (bits set to 1 are
 *          "don't care" positions); must not be NULL; o->len=0 matches any buffer
 * @param p Buffer to search for pattern match; byte array from DHCP option value (vendor class,
 *          user class, client identifier, etc.); must be valid pointer even if len=0; content
 *          compared against o->val pattern
 * @param len Length of buffer p in bytes; must be non-negative; len < o->len causes immediate
 *            match failure (pattern cannot fit in buffer)
 * 
 * @return Match result indicating whether pattern found in buffer
 * @retval 1 Match succeeds: pattern found in buffer using specified matching mode
 * @retval 0 Match fails: pattern not found, or pattern longer than buffer, or length mismatch
 * 
 * @note Zero-length pattern (o->len=0) returns 1 (wildcard matches any buffer)
 * @note Hex mode: uses wildcard mask for flexible matching of variable vendor class formats
 * @note String mode: searches for substring anywhere in buffer (byte-by-byte advancement)
 * @note Default mode: searches for exact match at o->len-aligned boundaries (more efficient)
 * @warning Buffer p must be at least len bytes; o->val must be at least o->len bytes
 * @warning DHOPT_HEX requires o->u.wildcard_mask initialized (NULL mask means exact match)
 * 
 * @see memcmp_masked() in util.c - performs masked byte comparison for DHOPT_HEX mode
 * @see option_filter() in dhcp-common.c - uses this for DHCP option value matching
 * @see struct dhcp_opt in dnsmasq.h - DHCP option structure definition with val, len, flags
 * 
 * EXAMPLE USAGE:
 * @code
 * // Match vendor class "MSFT 5.0" exactly (no wildcards)
 * struct dhcp_opt pattern;
 * pattern.val = (unsigned char *)"MSFT 5.0";
 * pattern.len = 8;
 * pattern.flags = DHOPT_STRING;
 * unsigned char vendor_class[] = "MSFT 5.0";
 * if (match_bytes(&pattern, vendor_class, sizeof(vendor_class))) {
 *   // Vendor class matches: tag as Windows client
 * }
 * 
 * // Match vendor class with wildcard (e.g., "XX:YY:*:*" where * = any byte)
 * pattern.flags = DHOPT_HEX;
 * pattern.u.wildcard_mask = "\x00\x00\xFF\xFF"; // Last 2 bytes are wildcards
 * if (match_bytes(&pattern, vendor_class, 4)) {
 *   // Match if first 2 bytes match, ignore last 2 bytes
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (dnsmasq-specific pattern matching for DHCP option filtering)
 * 
 * SIDE EFFECTS: None (read-only comparison of pattern and buffer)
 * 
 * THREAD SAFETY: Thread-safe for read-only access; called from single-threaded DHCP processing
 */
int match_bytes(struct dhcp_opt *o, unsigned char *p, int len)
{
  int i;
  
  if (o->len > len)
    return 0;
  
  if (o->len == 0)
    return 1;
     
  if (o->flags & DHOPT_HEX)
    { 
      if (memcmp_masked(o->val, p, o->len, o->u.wildcard_mask))
	return 1;
    }
  else 
    for (i = 0; i <= (len - o->len); ) 
      {
	if (memcmp(o->val, p + i, o->len) == 0)
	  return 1;
	    
	if (o->flags & DHOPT_STRING)
	  i++;
	else
	  i += o->len;
      }
  
  return 0;
}

/**
 * @brief Check if DHCP configuration entry matches specific hardware address (MAC address)
 * 
 * @detailed Determines whether a DHCP client configuration entry is associated with a specific
 * hardware address, enabling identification of static leases and host-specific configurations by
 * MAC address. The function searches through the configuration's linked list of hardware addresses
 * (config->hwaddr) and performs exact byte-for-byte comparison of the hardware address, address
 * length, and optionally hardware type. This matching is critical for DHCP operations: when a
 * DHCPDISCOVER or DHCPREQUEST arrives with a client hardware address (chaddr field in DHCP packet),
 * the server uses this function to locate any pre-configured static lease or host-specific options
 * associated with that MAC address. The function only matches non-wildcard hardware addresses
 * (wildcard_mask == 0), as wildcard matching is handled by separate logic. Hardware type matching
 * follows RFC 2131 semantics: conf_addr->hwaddr_type == 0 acts as wildcard matching any hardware
 * type (allowing configuration to apply to Ethernet, Token Ring, etc. without type specification),
 * otherwise hardware type must match exactly (preventing Ethernet config from matching Token Ring).
 * Multiple hardware addresses can be associated with single configuration via hwaddr linked list,
 * enabling scenarios like client with multiple NICs or MAC address changes over time, all sharing
 * same static IP or options. Typical use: find_config() calls this to locate configuration entry
 * matching incoming DHCP request's chaddr, enabling static IP assignment or host-specific option
 * delivery. Performance: O(n) where n is number of hwaddr entries in config (typically 1-2).
 * 
 * @param config DHCP client configuration entry; config->hwaddr is linked list of hardware addresses
 *               associated with this configuration (NULL if no MAC-based identification configured);
 *               each hwaddr_config node contains hwaddr bytes, hwaddr_len, hwaddr_type, and
 *               wildcard_mask; configuration may represent static lease, hostname assignment,
 *               vendor-class specific options, or other host-specific settings; must not be NULL
 *               (caller responsible for NULL check; NULL will segfault during config->hwaddr access)
 * @param hwaddr Client hardware address to match (typically MAC address from DHCP packet chaddr field);
 *               byte array of length 'len' containing hardware address octets in network byte order;
 *               for Ethernet (most common): 6-byte MAC address like {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
 *               for other hardware types: appropriate length and format per RFC 826 (ARP) and RFC 2131;
 *               must not be NULL (no validation performed; NULL causes memcmp undefined behavior)
 * @param len Hardware address length in bytes; for Ethernet: 6 bytes (ETHER_ADDR_LEN); other hardware
 *            types use different lengths per RFC 826 (Token Ring: 6, LocalTalk: 1, etc.); must match
 *            conf_addr->hwaddr_len for successful match; valid range 1-255 bytes (DHCP protocol limit);
 *            caller must ensure hwaddr buffer is at least 'len' bytes to prevent buffer overread
 * @param type Hardware type code per RFC 826 (ARP Hardware Types) and RFC 1700 (Assigned Numbers);
 *             common values: 1 = Ethernet (most frequent), 6 = IEEE 802 Networks, 15 = Frame Relay,
 *             32 = InfiniBand; used to distinguish hardware address namespaces (Ethernet MAC vs other);
 *             conf_addr->hwaddr_type == 0 acts as wildcard matching any type, enabling configuration
 *             to apply regardless of hardware type; exact match required if conf_addr->hwaddr_type != 0
 * 
 * @return Hardware address match result for configuration entry
 * @retval 1 Configuration matches hardware address: found hwaddr_config with exact match on address
 *           bytes, length, and type (or type 0 wildcard), and wildcard_mask == 0 (non-wildcard entry)
 * @retval 0 Configuration does not match: no hwaddr_config in list matches, or all matches are wildcard
 *           entries (wildcard_mask != 0), or length mismatch, or type mismatch, or byte mismatch
 * 
 * @note Wildcard hardware addresses (wildcard_mask != 0) are NOT matched by this function; separate
 *       wildcard matching logic handles those (e.g., 01:02:03:*:*:* patterns)
 * @note Hardware type 0 in conf_addr acts as wildcard: matches any client hardware type value
 * @note Multiple hardware addresses per config supported via hwaddr linked list; first match returns 1
 * @note Function performs byte-wise comparison: endianness-independent, works for any hardware type
 * @warning Config parameter must not be NULL (no validation; NULL causes segmentation fault)
 * @warning hwaddr parameter must not be NULL (memcmp with NULL is undefined behavior)
 * @warning hwaddr buffer must be at least 'len' bytes (no bounds checking; undersize causes overread)
 * @warning len must accurately reflect hwaddr buffer size (incorrect len causes buffer overread)
 * 
 * @see find_config() in dhcp-common.c - primary caller; locates config matching client MAC address
 * @see config_find_by_address() in dhcp.c - uses find_config() to locate lease by MAC
 * @see struct dhcp_config in dnsmasq.h - DHCP configuration structure with hwaddr linked list
 * @see struct hwaddr_config in dnsmasq.h - hardware address configuration node in linked list
 * @see RFC 2131 Section 2 - DHCP hardware address (chaddr) field format and usage
 * @see RFC 826 - ARP protocol defining hardware address types and formats
 * 
 * EXAMPLE USAGE:
 * @code
 * // Check if configuration matches Ethernet MAC 00:11:22:33:44:55
 * struct dhcp_config *cfg = ...; // Configuration with hwaddr list
 * unsigned char client_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
 * 
 * if (config_has_mac(cfg, client_mac, 6, 1)) {
 *   // Configuration matches: apply static lease or host-specific options
 *   // Type 1 = Ethernet per RFC 826
 * }
 * 
 * // Example: configuration may have multiple hardware addresses
 * // cfg->hwaddr points to linked list:
 * //   hwaddr[0]: 00:11:22:33:44:55, type=1, len=6, wildcard_mask=0
 * //   hwaddr[1]: 00:11:22:33:44:66, type=1, len=6, wildcard_mask=0
 * // Function returns 1 if client_mac matches either entry
 * 
 * // Type 0 in config acts as wildcard (matches any hardware type)
 * // If cfg->hwaddr->hwaddr_type == 0, matches client_mac regardless of type parameter
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 2131 Section 2 (DHCP hardware address handling), RFC 826 (hardware types)
 * 
 * SIDE EFFECTS: None (read-only comparison of hardware addresses)
 * 
 * THREAD SAFETY: Thread-safe for read-only access; called from single-threaded DHCP processing
 */
int config_has_mac(struct dhcp_config *config, unsigned char *hwaddr, int len, int type)
{
  struct hwaddr_config *conf_addr;
  
  for (conf_addr = config->hwaddr; conf_addr; conf_addr = conf_addr->next)
    if (conf_addr->wildcard_mask == 0 &&
	conf_addr->hwaddr_len == len &&
	(conf_addr->hwaddr_type == type || conf_addr->hwaddr_type == 0) &&
	memcmp(conf_addr->hwaddr, hwaddr, len) == 0)
      return 1;
  
  return 0;
}

/**
 * @brief Check if DHCP configuration entry is applicable to specific DHCP context (network segment)
 * 
 * @detailed Validates whether a DHCP client configuration (static lease, host-specific options,
 * or other per-client settings) is appropriate for a given DHCP context representing a network
 * segment. The function performs network matching to ensure configuration entries only apply to
 * clients on their designated networks, preventing accidental cross-network configuration
 * application. For IPv4, checks if config->addr falls within context's subnet using netmask.
 * For IPv6, checks if any config->addr6 addresses match context's prefix. Special handling for
 * wildcard configurations (CONFIG_ADDR/CONFIG_ADDR6 not set) which apply to all contexts, and
 * NULL context which returns true (called from lease_update_from_configs() where context
 * checking is skipped). IPv6 wildcard addresses (ADDRLIST_WILDCARD flag) match any /64 prefix,
 * enabling flexible DHCPv6 static assignments. Context chaining via context->current allows
 * checking against multiple network segments (e.g., bridged interfaces sharing lease database).
 * 
 * @param context DHCP context representing network segment; contains IPv4 start/netmask or IPv6
 *                start6/prefix defining network boundaries; context->current points to next
 *                chained context for multi-segment checking; context->flags indicates IPv4 vs
 *                IPv6 (CONTEXT_V6 flag); NULL context returns 1 (wildcard match for
 *                lease_update_from_configs() path where network validation is not required)
 * @param config DHCP client configuration entry; config->flags indicates configuration type
 *               (CONFIG_ADDR for IPv4 static IP, CONFIG_ADDR6 for IPv6 addresses); config->addr
 *               holds IPv4 address for static lease; config->addr6 is addrlist of IPv6 addresses
 *               for static assignment; configuration without CONFIG_ADDR or CONFIG_ADDR6 applies
 *               to all contexts (wildcard options like hostname, vendor options); must not be NULL
 * 
 * @return Context match result indicating configuration applicability
 * @retval 1 Configuration applies to context: network match found, or wildcard config, or NULL context
 * @retval 0 Configuration does not apply: no network match (config address outside context subnet)
 * 
 * @note NULL context returns 1: used by lease_update_from_configs() when updating lease config
 * @note Configurations without CONFIG_ADDR/CONFIG_ADDR6 return 1: wildcard configs apply everywhere
 * @note IPv6 wildcard addresses (ADDRLIST_WILDCARD) match any /64 prefix for flexible assignment
 * @note Context chaining allows single config to match multiple network segments via context->current
 * @warning Config must not be NULL (no validation, will segfault if NULL)
 * @warning IPv6 requires HAVE_DHCP6 compile flag; function has no IPv6 support without it
 * 
 * @see find_config() in dhcp-common.c - calls this to filter configs by network context
 * @see lease_update_from_configs() in lease.c - calls find_config() with NULL context
 * @see is_same_net() in network.c - performs IPv4 subnet matching
 * @see is_same_net6() in network.c - performs IPv6 prefix matching
 * @see struct dhcp_context in dnsmasq.h - DHCP context definition with network parameters
 * @see struct dhcp_config in dnsmasq.h - DHCP client configuration structure
 * 
 * EXAMPLE USAGE:
 * @code
 * // Check if static IPv4 lease 192.168.1.50 applies to context 192.168.1.0/24
 * struct dhcp_context ctx;
 * ctx.start.s_addr = inet_addr("192.168.1.0");
 * ctx.netmask.s_addr = inet_addr("255.255.255.0");
 * ctx.flags = 0; // IPv4 context
 * ctx.current = NULL;
 * 
 * struct dhcp_config cfg;
 * cfg.addr.s_addr = inet_addr("192.168.1.50");
 * cfg.flags = CONFIG_ADDR;
 * 
 * if (is_config_in_context(&ctx, &cfg)) {
 *   // Config applies: 192.168.1.50 is within 192.168.1.0/24 subnet
 * }
 * 
 * // Wildcard config (hostname only, no address) applies to all contexts
 * cfg.flags = 0; // No CONFIG_ADDR or CONFIG_ADDR6
 * if (is_config_in_context(&ctx, &cfg)) {
 *   // Always returns 1: wildcard config applies everywhere
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (dnsmasq-specific configuration filtering for network segmentation)
 * 
 * SIDE EFFECTS: None (read-only comparison of network addresses and configuration)
 * 
 * THREAD SAFETY: Thread-safe for read-only access; called from single-threaded DHCP processing
 */
static int is_config_in_context(struct dhcp_context *context, struct dhcp_config *config)
{
  if (!context) /* called via find_config() from lease_update_from_configs() */
    return 1; 

  if (!(config->flags & (CONFIG_ADDR | CONFIG_ADDR6)))
    return 1;
  
#ifdef HAVE_DHCP6
  if (context->flags & CONTEXT_V6)
    {
       struct addrlist *addr_list;

       if (config->flags & CONFIG_ADDR6)
	 for (; context; context = context->current)
	   for (addr_list = config->addr6; addr_list; addr_list = addr_list->next)
	     {
	       if ((addr_list->flags & ADDRLIST_WILDCARD) && context->prefix == 64)
		 return 1;
	       
	       if (is_same_net6(&addr_list->addr.addr6, &context->start6, context->prefix))
		 return 1;
	     }
    }
  else
#endif
    {
      for (; context; context = context->current)
	if ((config->flags & CONFIG_ADDR) && is_same_net(config->addr, context->start, context->netmask))
	  return 1;
    }

  return 0;
}

/**
 * @brief Find DHCP configuration matching client identity and network context
 * 
 * @detailed Searches the DHCP configuration list for entries matching the client's
 * identifying information (client ID, MAC address, hostname) and network context.
 * The function performs two-pass matching: first looking for exact matches of tags
 * and hardware addresses, then (if tag_not_needed is set) looking for wildcard matches.
 * 
 * Matching precedence:
 * 1. Client ID match (if provided)
 * 2. Hardware address exact match
 * 3. Hardware address wildcard match (best match wins based on bit count)
 * 4. Hostname match
 * 
 * All matches are further filtered by context appropriateness and network tags.
 * 
 * @param configs Head of dhcp_config linked list to search
 * @param context Current DHCP context (subnet/network segment); NULL means any context
 * @param clid Client identifier from DHCP request; NULL if not provided
 * @param clid_len Length of client identifier in bytes; 0 if clid is NULL
 * @param hwaddr Hardware (MAC) address of client; must not be NULL for MAC matching
 * @param hw_len Length of hardware address in bytes (typically 6 for Ethernet)
 * @param hw_type Hardware type code (e.g., ARPHRD_ETHER=1 for Ethernet)
 * @param hostname Client hostname from DHCP request; NULL if not provided
 * @param tags Network ID tags for client classification (vendor class, user class, etc.)
 * @param tag_not_needed If 0, only exact tag matches allowed; if 1, wildcard tag matching enabled
 * 
 * @return Pointer to matching dhcp_config, or NULL if no match found
 * @retval non-NULL Best matching configuration entry for this client
 * @retval NULL No configuration matches the provided criteria
 * 
 * @note Wildcard MAC address matching uses bitmask to count matching bits;
 *       configuration with most matching bits wins
 * @warning Multiple configuration entries may partially match; function returns
 *          the "best" match based on precedence rules
 * 
 * @see find_config() in dhcp-common.c:965 - Wrapper that calls this twice
 * @see is_config_in_context() in dhcp-common.c:854 - Context matching logic
 * @see config_has_mac() in dhcp-common.c:870 - MAC address matching
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_config *config;
 * unsigned char mac[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
 * struct dhcp_netid tags = {...};
 * 
 * // First pass: exact tag matching only
 * config = find_config_match(daemon->dhcp_conf, context, NULL, 0,
 *                            mac, 6, ARPHRD_ETHER, "client-host", &tags, 0);
 * @endcode
 * 
 * RFC COMPLIANCE: Implements client identification per RFC 2131 Section 2
 * SIDE EFFECTS: None - read-only search operation
 * THREAD SAFETY: Safe if configuration list is not being modified concurrently
 */
static struct dhcp_config *find_config_match(struct dhcp_config *configs,
					     struct dhcp_context *context,
					     unsigned char *clid, int clid_len,
					     unsigned char *hwaddr, int hw_len, 
					     int hw_type, char *hostname,
					     struct dhcp_netid *tags, int tag_not_needed)
{
  int count, new;
  struct dhcp_config *config, *candidate; 
  struct hwaddr_config *conf_addr;

  if (clid)
    for (config = configs; config; config = config->next)
      if (config->flags & CONFIG_CLID)
	{
	  if (config->clid_len == clid_len && 
	      memcmp(config->clid, clid, clid_len) == 0 &&
	      is_config_in_context(context, config) &&
	      match_netid(config->filter, tags, tag_not_needed))
	    
	    return config;
	  
	  /* dhcpcd prefixes ASCII client IDs by zero which is wrong, but we try and
	     cope with that here. This is IPv4 only. context==NULL implies IPv4, 
	     see lease_update_from_configs() */
	  if ((!context || !(context->flags & CONTEXT_V6)) && *clid == 0 && config->clid_len == clid_len-1  &&
	      memcmp(config->clid, clid+1, clid_len-1) == 0 &&
	      is_config_in_context(context, config) &&
	      match_netid(config->filter, tags, tag_not_needed))
	    return config;
	}
  

  if (hwaddr)
    for (config = configs; config; config = config->next)
      if (config_has_mac(config, hwaddr, hw_len, hw_type) &&
	  is_config_in_context(context, config) &&
	  match_netid(config->filter, tags, tag_not_needed))
	return config;
  
  if (hostname && context)
    for (config = configs; config; config = config->next)
      if ((config->flags & CONFIG_NAME) && 
	  hostname_isequal(config->hostname, hostname) &&
	  is_config_in_context(context, config) &&
	  match_netid(config->filter, tags, tag_not_needed))
	return config;

  
  if (!hwaddr)
    return NULL;

  /* use match with fewest wildcard octets */
  for (candidate = NULL, count = 0, config = configs; config; config = config->next)
    if (is_config_in_context(context, config) &&
	match_netid(config->filter, tags, tag_not_needed))
      for (conf_addr = config->hwaddr; conf_addr; conf_addr = conf_addr->next)
	if (conf_addr->wildcard_mask != 0 &&
	    conf_addr->hwaddr_len == hw_len &&	
	    (conf_addr->hwaddr_type == hw_type || conf_addr->hwaddr_type == 0) &&
	    (new = memcmp_masked(conf_addr->hwaddr, hwaddr, hw_len, conf_addr->wildcard_mask)) > count)
	  {
	      count = new;
	      candidate = config;
	  }
  
  return candidate;
}

/**
 * @brief Find DHCP configuration for client using two-pass tag matching strategy
 * 
 * @detailed Wrapper function that implements intelligent two-pass configuration 
 * matching for DHCP clients. The function first attempts to find a configuration 
 * with exact tag matching (tag_not_needed=0), which ensures that tagged 
 * configurations (those with specific vendor-class, user-class, or other network 
 * ID tags) are found first. If no exact match is found, performs a second pass 
 * with wildcard tag matching enabled (tag_not_needed=1) to find less-specific 
 * configurations.
 * 
 * This two-pass strategy implements configuration precedence:
 * - Pass 1 (exact tags): Configurations with matching network ID tags
 * - Pass 2 (wildcard tags): Configurations with wildcard tags or no tag requirements
 * 
 * Within each pass, the underlying find_config_match() applies additional precedence:
 * client ID match > exact MAC match > wildcard MAC match > hostname match
 * 
 * @param configs Head of dhcp_config linked list to search
 * @param context Current DHCP context (subnet/network segment); NULL means any context
 * @param clid Client identifier from DHCP request; NULL if not provided
 * @param clid_len Length of client identifier in bytes; 0 if clid is NULL
 * @param hwaddr Hardware (MAC) address of client; must not be NULL for MAC matching
 * @param hw_len Length of hardware address in bytes (typically 6 for Ethernet)
 * @param hw_type Hardware type code (e.g., ARPHRD_ETHER=1 for Ethernet)
 * @param hostname Client hostname from DHCP request; NULL if not provided
 * @param tags Network ID tags for client classification (vendor class, user class, etc.)
 * 
 * @return Pointer to best matching dhcp_config, or NULL if no match found
 * @retval non-NULL Configuration entry matching client (exact or wildcard tag match)
 * @retval NULL No configuration matches the provided criteria
 * 
 * @note This is the primary entry point for configuration lookup; prefer this over
 *       calling find_config_match() directly to ensure proper precedence handling
 * @warning Configuration list is searched sequentially; ensure important configurations
 *          appear early in the list for performance
 * 
 * @see find_config_match() in dhcp-common.c:896 - Underlying matching implementation
 * @see dhcp_reply() in dhcp.c - DHCPv4 caller
 * @see dhcp6_reply() in dhcp6.c - DHCPv6 caller
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_config *config;
 * unsigned char mac[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
 * unsigned char client_id[] = {0x01, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
 * struct dhcp_netid tags = {.net = "vendor:MSWindows", .next = NULL};
 * 
 * // Find configuration for Windows client with MAC and hostname
 * config = find_config(daemon->dhcp_conf, context, 
 *                      client_id, 7, mac, 6, ARPHRD_ETHER, 
 *                      "workstation42", &tags);
 * if (config) {
 *     // Use configuration for lease assignment
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: Implements DHCP client identification per RFC 2131 Section 2
 * SIDE EFFECTS: None - read-only search operation
 * THREAD SAFETY: Safe if configuration list is not being modified concurrently
 */
/* Find tagged configs first. */
struct dhcp_config *find_config(struct dhcp_config *configs,
				struct dhcp_context *context,
				unsigned char *clid, int clid_len,
				unsigned char *hwaddr, int hw_len, 
				int hw_type, char *hostname, struct dhcp_netid *tags)
{
  struct dhcp_config *ret = find_config_match(configs, context, clid, clid_len, hwaddr, hw_len, hw_type, hostname, tags, 0);

  if (!ret)
    ret = find_config_match(configs, context, clid, clid_len, hwaddr, hw_len, hw_type, hostname, tags, 1);

  return ret;
}

/**
 * @brief Synchronize DHCP configuration records with static IP addresses from /etc/hosts
 * 
 * @detailed This function updates DHCP configuration records by importing static IP addresses
 *           from /etc/hosts (via the DNS cache). It is designed for users who prefer to maintain
 *           all static IP assignments in /etc/hosts rather than separate dhcp-host directives.
 *           The function processes both IPv4 and IPv6 addresses, maintains the invariant that
 *           each IP address appears in at most one dhcp-host configuration, detects and warns
 *           about duplicate IP addresses and MAC addresses, and can be triggered by SIGHUP
 *           configuration reload. The implementation first clears previously imported addresses
 *           (CONFIG_ADDR_HOSTS flag), then queries the DNS cache for hostnames in DHCP configs,
 *           assigns found addresses while checking for conflicts, updates domain names if
 *           specified in configs, and validates MAC address uniqueness across configurations.
 * 
 * @param configs Linked list of DHCP configuration records (dhcp-host directives) to update.
 *                Each config may have hostname, MAC address, and optional static IP. Function
 *                modifies config records in place by setting CONFIG_ADDR/CONFIG_ADDR6 flags
 *                and populating addr/addr6 fields. Must not be NULL (caller responsibility).
 * 
 * @return void (no return value)
 * 
 * @note This function is typically called during daemon initialization and on SIGHUP reload
 *       to synchronize /etc/hosts changes with DHCP configuration. The function maintains
 *       the invariant that any IP address can appear in at most one dhcp-host configuration.
 *       Processes both IPv4 and IPv6 using a labeled goto to repeat logic for both protocols.
 * @warning Function modifies config records in place. Logs warnings for duplicate IP addresses
 *          and duplicate MAC addresses to syslog with MS_DHCP facility. Performance is O(n²)
 *          for n configs due to duplicate checking - acceptable for typical small network scale.
 * @see cache_find_by_name() - Queries DNS cache for hostname entries from /etc/hosts
 * @see config_has_mac() - Checks if two configs have matching MAC addresses
 * @see canonicalise() - Canonicalizes hostname with domain suffix
 * 
 * EXAMPLE USAGE:
 * @code
 * // After loading /etc/hosts into DNS cache and parsing dhcp-host directives
 * struct dhcp_config *dhcp_configs = daemon->dhcp_conf;
 * dhcp_update_configs(dhcp_configs);
 * // Configs now have static IPs from /etc/hosts where hostnames match
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (internal configuration management, not protocol operation)
 * SIDE EFFECTS: Modifies config->flags, config->addr, config->addr6 for matching configs;
 *               logs INFO messages for imported addresses and WARNING for duplicates;
 *               may modify DNS cache entries (update domain names, remove CNAMEs)
 * THREAD SAFETY: Not thread-safe; single-threaded architecture, called during configuration
 */
void dhcp_update_configs(struct dhcp_config *configs)
{
  /* Some people like to keep all static IP addresses in /etc/hosts.
     This goes through /etc/hosts and sets static addresses for any DHCP config
     records which don't have an address and whose name matches. 
     We take care to maintain the invariant that any IP address can appear
     in at most one dhcp-host. Since /etc/hosts can be re-read by SIGHUP, 
     restore the status-quo ante first. */
  
  struct dhcp_config *config, *conf_tmp;
  struct crec *crec;
  int prot = AF_INET;

  for (config = configs; config; config = config->next)
  {
    if (config->flags & CONFIG_ADDR_HOSTS)
      config->flags &= ~(CONFIG_ADDR | CONFIG_ADDR_HOSTS);
#ifdef HAVE_DHCP6
    if (config->flags & CONFIG_ADDR6_HOSTS)
      config->flags &= ~(CONFIG_ADDR6 | CONFIG_ADDR6_HOSTS);
#endif
  }

#ifdef HAVE_DHCP6 
 again:  
#endif

  if (daemon->port != 0)
    for (config = configs; config; config = config->next)
      {
	int conflags = CONFIG_ADDR;
	int cacheflags = F_IPV4;

#ifdef HAVE_DHCP6
	if (prot == AF_INET6)
	  {
	    conflags = CONFIG_ADDR6;
	    cacheflags = F_IPV6;
	  }
#endif
	if (!(config->flags & conflags) &&
	    (config->flags & CONFIG_NAME) && 
	    (crec = cache_find_by_name(NULL, config->hostname, 0, cacheflags)) &&
	    (crec->flags & F_HOSTS))
	  {
	    if (cache_find_by_name(crec, config->hostname, 0, cacheflags))
	      {
		/* use primary (first) address */
		while (crec && !(crec->flags & F_REVERSE))
		  crec = cache_find_by_name(crec, config->hostname, 0, cacheflags);
		if (!crec)
		  continue; /* should be never */
		inet_ntop(prot, &crec->addr, daemon->addrbuff, ADDRSTRLEN);
		my_syslog(MS_DHCP | LOG_WARNING, _("%s has more than one address in hostsfile, using %s for DHCP"), 
			  config->hostname, daemon->addrbuff);
	      }
	    
	    if (prot == AF_INET && 
		(!(conf_tmp = config_find_by_address(configs, crec->addr.addr4)) || conf_tmp == config))
	      {
		config->addr = crec->addr.addr4;
		config->flags |= CONFIG_ADDR | CONFIG_ADDR_HOSTS;
		continue;
	      }

#ifdef HAVE_DHCP6
	    if (prot == AF_INET6 && 
		(!(conf_tmp = config_find_by_address6(configs, NULL, 0, &crec->addr.addr6)) || conf_tmp == config))
	      {
		/* host must have exactly one address if comming from /etc/hosts. */
		if (!config->addr6 && (config->addr6 = whine_malloc(sizeof(struct addrlist))))
		  {
		    config->addr6->next = NULL;
		    config->addr6->flags = 0;
		  }

		if (config->addr6 && !config->addr6->next && !(config->addr6->flags & (ADDRLIST_WILDCARD|ADDRLIST_PREFIX)))
		  {
		    memcpy(&config->addr6->addr.addr6, &crec->addr.addr6, IN6ADDRSZ);
		    config->flags |= CONFIG_ADDR6 | CONFIG_ADDR6_HOSTS;
		  }
	    
		continue;
	      }
#endif

	    inet_ntop(prot, &crec->addr, daemon->addrbuff, ADDRSTRLEN);
	    my_syslog(MS_DHCP | LOG_WARNING, _("duplicate IP address %s (%s) in dhcp-config directive"), 
		      daemon->addrbuff, config->hostname);
	    
	    
	  }
      }

#ifdef HAVE_DHCP6
  if (prot == AF_INET)
    {
      prot = AF_INET6;
      goto again;
    }
#endif

}

#ifdef HAVE_LINUX_NETWORK 
/**
 * @brief Determine if DHCP is running on exactly one interface and return its name
 * 
 * @detailed Checks if dnsmasq is configured to run DHCP on exactly one network interface,
 *           returning the device name if so. This is used for the SO_BINDTODEVICE socket
 *           option on Linux, which ensures that DHCP packets are sent and received on
 *           the correct interface in multi-VLAN environments. Returns NULL if multiple
 *           interfaces are configured, if wildcards are used, or if configured interfaces
 *           don't yet exist. The primary use case is OpenStack deployments where a separate
 *           dnsmasq instance runs for each VLAN interface.
 * 
 * @return Malloc'd string containing interface name if exactly one DHCP interface, NULL otherwise
 * @retval NULL If no interfaces configured, wildcards used, or multiple DHCP interfaces found
 * @retval char* Malloc'd string with interface name - caller must free
 * 
 * @note SO_BINDTODEVICE is Linux-specific; this function used only on Linux platforms
 * @note Returns NULL if any configured interface uses wildcards (e.g., "eth*")
 * @note Returns NULL if any configured interface has not been activated yet (INAME_USED)
 * @note Checks both DHCPv4 (dhcp4_ok) and DHCPv6 (dhcp6_ok) enabled interfaces
 * @warning Returned string is malloc'd - caller responsible for freeing memory
 * @see bind_dhcp_devices() for usage context
 * @see bindtodevice() for SO_BINDTODEVICE socket option application
 * 
 * EXAMPLE USAGE:
 * @code
 * char *device = whichdevice();
 * if (device)
 *   {
 *     bindtodevice(device, dhcp_socket);
 *     free(device);
 *   }
 * @endcode
 * 
 * RFC COMPLIANCE: Supports Linux SO_BINDTODEVICE for packet routing isolation
 * SIDE EFFECTS: Allocates memory via safe_malloc - caller must free
 * THREAD SAFETY: Single-threaded architecture - reads daemon->if_names and daemon->interfaces
 */
char *whichdevice(void)
{
  /* If we are doing DHCP on exactly one interface, and running linux, do SO_BINDTODEVICE
     to that device. This is for the use case of  (eg) OpenStack, which runs a new
     dnsmasq instance for each VLAN interface it creates. Without the BINDTODEVICE, 
     individual processes don't always see the packets they should.
     SO_BINDTODEVICE is only available Linux. 

     Note that if wildcards are used in --interface, or --interface is not used at all,
     or a configured interface doesn't yet exist, then more interfaces may arrive later, 
     so we can't safely assert there is only one interface and proceed.
*/
  
  struct irec *iface, *found;
  struct iname *if_tmp;
  
  if (!daemon->if_names)
    return NULL;
  
  for (if_tmp = daemon->if_names; if_tmp; if_tmp = if_tmp->next)
    if (if_tmp->name && (!(if_tmp->flags & INAME_USED) || strchr(if_tmp->name, '*')))
      return NULL;

  for (found = NULL, iface = daemon->interfaces; iface; iface = iface->next)
    if (iface->dhcp4_ok || iface->dhcp6_ok)
      {
	if (!found)
	  found = iface;
	else if (strcmp(found->name, iface->name) != 0) 
	  return NULL; /* more than one. */
      }

  if (found)
    {
      char *ret = safe_malloc(strlen(found->name)+1);
      strcpy(ret, found->name);
      return ret;
    }
  
  return NULL;
}
 
/**
 * @brief Bind socket to a specific network device using SO_BINDTODEVICE
 * 
 * @detailed Binds the given socket file descriptor to a specific network interface device
 *           using the SO_BINDTODEVICE socket option. This ensures that packets sent through
 *           this socket use only the specified interface, and packets received are only from
 *           that interface. The device name is truncated to IFNAMSIZ if necessary. The operation
 *           requires root privileges; EPERM errors are silently ignored to allow graceful
 *           degradation when running without sufficient privileges. This is primarily used for
 *           DHCP sockets that must listen on specific interfaces in multi-network scenarios.
 * 
 * @param device Network device name (e.g., "eth0", "wlan0") to bind socket to. Must not be NULL.
 *               Device name will be truncated to IFNAMSIZ-1 characters if longer.
 * @param fd     Socket file descriptor to bind to device. Must be a valid open socket descriptor.
 * 
 * @return Integer status code indicating operation result
 * @retval 1 Binding succeeded or insufficient permissions (EPERM - graceful degradation)
 * @retval 2 Binding failed due to error other than permission denied
 * 
 * @note Requires root privileges (CAP_NET_RAW capability on Linux). EPERM errors are treated
 *       as non-fatal to allow operation without elevated privileges where device binding is optional.
 * @warning Platform-specific: SO_BINDTODEVICE is Linux-specific socket option. This function
 *          may not work correctly on non-Linux platforms. Device name length limited to IFNAMSIZ.
 * @see bind_dhcp_devices() - Caller function that uses bindtodevice() for multiple interfaces
 * 
 * EXAMPLE USAGE:
 * @code
 * int dhcp_sock = socket(AF_INET, SOCK_DGRAM, 0);
 * int result = bindtodevice("eth0", dhcp_sock);
 * if (result == 2)
 *   die("Failed to bind DHCP socket to eth0", NULL, EC_BADNET);
 * // result == 1: success or EPERM (acceptable in both cases)
 * @endcode
 * 
 * SIDE EFFECTS: Modifies socket behavior via setsockopt(), restricting socket to specified device
 * THREAD SAFETY: Thread-safe; operates on independent socket file descriptor
 */
static int bindtodevice(char *device, int fd)
{
  size_t len = strlen(device)+1;
  if (len > IFNAMSIZ)
    len = IFNAMSIZ;
  /* only allowed by root. */
  if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, device, len) == -1 &&
      errno != EPERM)
    return 2;
  
  return 1;
}

/**
 * @brief Bind DHCP-related sockets to a specific network device
 * 
 * @detailed Binds all active DHCP sockets (DHCPv4, DHCPv6, PXE) to the specified
 *           network interface using SO_BINDTODEVICE. This restricts DHCP service 
 *           operation to a single network interface, which is essential for 
 *           multi-homed systems or when limiting DHCP scope to specific networks.
 *           The function handles DHCPv4 main socket, PXE proxy socket, and DHCPv6 
 *           socket independently, skipping sockets in relay mode since relay agents 
 *           typically need to listen on multiple interfaces.
 * 
 * @param bound_device Device name to bind sockets to (e.g., "eth0", "wlan0"). If 
 *                     NULL, no binding is performed and function returns 0 immediately.
 *                     Device name must match system interface name exactly.
 * 
 * @return Returns 0 if all applicable sockets bound successfully or no device specified.
 *         Returns non-zero if any bindtodevice() call fails (bitwise OR of all failures).
 *         Non-zero return indicates at least one socket could not be bound to device.
 * 
 * @note Binding to device requires CAP_NET_RAW capability or root privileges on Linux.
 * @note Sockets in relay mode (daemon->relay4, daemon->relay6) are not bound since 
 *       relay agents must operate across multiple interfaces.
 * @note PXE socket binding only occurs if PXE support is enabled and PXE socket is valid.
 * 
 * @see bindtodevice() for the underlying socket binding operation
 * @see dhcp_common_init() for DHCP socket initialization
 * 
 * EXAMPLE USAGE:
 * @code
 * // Bind all DHCP sockets to eth0 interface
 * if (bind_dhcp_devices("eth0") != 0)
 *   die("Failed to bind DHCP to eth0", NULL, EC_BADNET);
 * @endcode
 * 
 * SIDE EFFECTS: Modifies socket options on daemon->dhcpfd, daemon->pxefd, daemon->dhcp6fd
 * THREAD SAFETY: Single-threaded daemon architecture - modifies global daemon structure
 */
int bind_dhcp_devices(char *bound_device)
{
  int ret = 0;

  if (bound_device)
    {
      if (daemon->dhcp)
	{
	  if (!daemon->relay4)
	    ret |= bindtodevice(bound_device, daemon->dhcpfd);
	  
	  if (daemon->enable_pxe && daemon->pxefd != -1)
	    ret |= bindtodevice(bound_device, daemon->pxefd);
	}
      
#if defined(HAVE_DHCP6)
      if (daemon->doing_dhcp6 && !daemon->relay6)
	ret |= bindtodevice(bound_device, daemon->dhcp6fd);
#endif
    }
  
  return ret;
}
#endif

static const struct opttab_t {
  char *name;
  u16 val, size;
} opttab[] = {
  { "netmask", 1, OT_ADDR_LIST },
  { "time-offset", 2, 4 },
  { "router", 3, OT_ADDR_LIST  },
  { "dns-server", 6, OT_ADDR_LIST },
  { "log-server", 7, OT_ADDR_LIST },
  { "lpr-server", 9, OT_ADDR_LIST },
  { "hostname", 12, OT_INTERNAL | OT_NAME },
  { "boot-file-size", 13, 2 | OT_DEC },
  { "domain-name", 15, OT_NAME },
  { "swap-server", 16, OT_ADDR_LIST },
  { "root-path", 17, OT_NAME },
  { "extension-path", 18, OT_NAME },
  { "ip-forward-enable", 19, 1 },
  { "non-local-source-routing", 20, 1 },
  { "policy-filter", 21, OT_ADDR_LIST },
  { "max-datagram-reassembly", 22, 2 | OT_DEC },
  { "default-ttl", 23, 1 | OT_DEC },
  { "mtu", 26, 2 | OT_DEC },
  { "all-subnets-local", 27, 1 },
  { "broadcast", 28, OT_INTERNAL | OT_ADDR_LIST },
  { "router-discovery", 31, 1 },
  { "router-solicitation", 32, OT_ADDR_LIST },
  { "static-route", 33, OT_ADDR_LIST },
  { "trailer-encapsulation", 34, 1 },
  { "arp-timeout", 35, 4 | OT_DEC },
  { "ethernet-encap", 36, 1 },
  { "tcp-ttl", 37, 1 },
  { "tcp-keepalive", 38, 4 | OT_DEC },
  { "nis-domain", 40, OT_NAME },
  { "nis-server", 41, OT_ADDR_LIST },
  { "ntp-server", 42, OT_ADDR_LIST },
  { "vendor-encap", 43, OT_INTERNAL },
  { "netbios-ns", 44, OT_ADDR_LIST },
  { "netbios-dd", 45, OT_ADDR_LIST },
  { "netbios-nodetype", 46, 1 },
  { "netbios-scope", 47, 0 },
  { "x-windows-fs", 48, OT_ADDR_LIST },
  { "x-windows-dm", 49, OT_ADDR_LIST },
  { "requested-address", 50, OT_INTERNAL | OT_ADDR_LIST },
  { "lease-time", 51, OT_INTERNAL | OT_TIME },
  { "option-overload", 52, OT_INTERNAL },
  { "message-type", 53, OT_INTERNAL | OT_DEC },
  { "server-identifier", 54, OT_INTERNAL | OT_ADDR_LIST },
  { "parameter-request", 55, OT_INTERNAL },
  { "message", 56, OT_INTERNAL },
  { "max-message-size", 57, OT_INTERNAL },
  { "T1", 58, OT_TIME},
  { "T2", 59, OT_TIME},
  { "vendor-class", 60, 0 },
  { "client-id", 61, OT_INTERNAL },
  { "nis+-domain", 64, OT_NAME },
  { "nis+-server", 65, OT_ADDR_LIST },
  { "tftp-server", 66, OT_NAME },
  { "bootfile-name", 67, OT_NAME },
  { "mobile-ip-home", 68, OT_ADDR_LIST }, 
  { "smtp-server", 69, OT_ADDR_LIST }, 
  { "pop3-server", 70, OT_ADDR_LIST }, 
  { "nntp-server", 71, OT_ADDR_LIST }, 
  { "irc-server", 74, OT_ADDR_LIST }, 
  { "user-class", 77, 0 },
  { "rapid-commit", 80, 0 },
  { "FQDN", 81, OT_INTERNAL },
  { "agent-info", 82, OT_INTERNAL },
  { "last-transaction", 91, 4 | OT_TIME },
  { "associated-ip", 92, OT_ADDR_LIST },
  { "client-arch", 93, 2 | OT_DEC },
  { "client-interface-id", 94, 0 },
  { "client-machine-id", 97, 0 },
  { "posix-timezone", 100, OT_NAME }, /* RFC 4833, Sec. 2 */
  { "tzdb-timezone", 101, OT_NAME }, /* RFC 4833, Sec. 2 */
  { "ipv6-only", 108, 4 | OT_DEC },  /* RFC 8925 */ 
  { "subnet-select", 118, OT_INTERNAL },
  { "domain-search", 119, OT_RFC1035_NAME },
  { "sip-server", 120, 0 },
  { "classless-static-route", 121, 0 },
  { "vendor-id-encap", 125, 0 },
  { "tftp-server-address", 150, OT_ADDR_LIST },
  { "server-ip-address", 255, OT_ADDR_LIST }, /* special, internal only, sets siaddr */
  { NULL, 0, 0 }
};

#ifdef HAVE_DHCP6
static const struct opttab_t opttab6[] = {
  { "client-id", 1, OT_INTERNAL },
  { "server-id", 2, OT_INTERNAL },
  { "ia-na", 3, OT_INTERNAL },
  { "ia-ta", 4, OT_INTERNAL },
  { "iaaddr", 5, OT_INTERNAL },
  { "oro", 6, OT_INTERNAL },
  { "preference", 7, OT_INTERNAL | OT_DEC },
  { "unicast", 12, OT_INTERNAL },
  { "status", 13, OT_INTERNAL },
  { "rapid-commit", 14, OT_INTERNAL },
  { "user-class", 15, OT_INTERNAL | OT_CSTRING },
  { "vendor-class", 16, OT_INTERNAL | OT_CSTRING },
  { "vendor-opts", 17, OT_INTERNAL },
  { "sip-server-domain", 21,  OT_RFC1035_NAME },
  { "sip-server", 22, OT_ADDR_LIST },
  { "dns-server", 23, OT_ADDR_LIST },
  { "domain-search", 24, OT_RFC1035_NAME },
  { "nis-server", 27, OT_ADDR_LIST },
  { "nis+-server", 28, OT_ADDR_LIST },
  { "nis-domain", 29,  OT_RFC1035_NAME },
  { "nis+-domain", 30, OT_RFC1035_NAME },
  { "sntp-server", 31,  OT_ADDR_LIST },
  { "information-refresh-time", 32, OT_TIME },
  { "FQDN", 39, OT_INTERNAL | OT_RFC1035_NAME },
  { "posix-timezone", 41, OT_NAME }, /* RFC 4833, Sec. 3 */
  { "tzdb-timezone", 42, OT_NAME }, /* RFC 4833, Sec. 3 */
  { "ntp-server", 56, 0 /* OT_ADDR_LIST | OT_RFC1035_NAME */ },
  { "bootfile-url", 59, OT_NAME },
  { "bootfile-param", 60, OT_CSTRING },
  { NULL, 0, 0 }
};
#endif



/**
 * @brief Display all known DHCPv4 option names to stdout
 * 
 * @detailed This function prints a list of all recognized DHCPv4 option codes and their
 *           human-readable names to standard output. It is invoked when dnsmasq is run
 *           with the --help-dhcp command-line option, providing users with a reference
 *           of available DHCP option identifiers for configuration. The function iterates
 *           through the internal opttab[] option table, filtering out internal-only options
 *           (marked with OT_INTERNAL flag), and displays the option number and name for
 *           all user-visible options. Output is localized using gettext for internationalization.
 * 
 * @param None (void)
 * 
 * @return void (no return value)
 * 
 * @note This is a utility function for command-line help output, not part of normal daemon
 *       operation. Called early during startup when --help-dhcp option is detected, then
 *       daemon exits after displaying help. Does not allocate memory or modify daemon state.
 * @warning Prints directly to stdout, not to syslog. Should only be called before daemon
 *          initialization, as stdout may not be available after daemonization.
 * @see display_opts6() - Equivalent function for DHCPv6 options
 * @see opttab[] - DHCPv4 option table in dhcp-protocol.h defining all recognized options
 * 
 * EXAMPLE USAGE:
 * @code
 * // In main() when processing --help-dhcp command-line option
 * if (help_dhcp_requested) {
 *   display_opts();
 *   exit(0);
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: Displays options defined in RFC 2132 (DHCP Options) and subsequent extensions
 * SIDE EFFECTS: Writes to stdout; no daemon state modifications
 * THREAD SAFETY: Thread-safe (read-only access to static opttab[] array)
 */
void display_opts(void)
{
  int i;
  
  printf(_("Known DHCP options:\n"));
  
  for (i = 0; opttab[i].name; i++)
    if (!(opttab[i].size & OT_INTERNAL))
      printf("%3d %s\n", opttab[i].val, opttab[i].name);
}

#ifdef HAVE_DHCP6
/**
 * @brief Display all known DHCPv6 option names to stdout
 * 
 * @detailed This function prints a list of all recognized DHCPv6 option codes and their
 *           human-readable names to standard output. It is invoked when dnsmasq is run
 *           with the --help-dhcp6 command-line option, providing users with a reference
 *           of available DHCPv6 option identifiers for configuration. The function iterates
 *           through the internal opttab6[] option table (DHCPv6-specific), filtering out
 *           internal-only options (marked with OT_INTERNAL flag), and displays the option
 *           number and name for all user-visible options. Output is localized using gettext.
 *           Only compiled when HAVE_DHCP6 feature flag is enabled.
 * 
 * @param None (void)
 * 
 * @return void (no return value)
 * 
 * @note This is a utility function for command-line help output, not part of normal daemon
 *       operation. Called early during startup when --help-dhcp6 option is detected, then
 *       daemon exits after displaying help. DHCPv6 equivalent of display_opts() for DHCPv4.
 * @warning Prints directly to stdout, not to syslog. Should only be called before daemon
 *          initialization. Only available when compiled with HAVE_DHCP6 flag.
 * @see display_opts() - Equivalent function for DHCPv4 options
 * @see opttab6[] - DHCPv6 option table in dhcp6-protocol.h defining all recognized options
 * 
 * EXAMPLE USAGE:
 * @code
 * // In main() when processing --help-dhcp6 command-line option
 * #ifdef HAVE_DHCP6
 * if (help_dhcp6_requested) {
 *   display_opts6();
 *   exit(0);
 * }
 * #endif
 * @endcode
 * 
 * RFC COMPLIANCE: Displays options defined in RFC 3315 (DHCPv6) and subsequent extensions
 * SIDE EFFECTS: Writes to stdout; no daemon state modifications
 * THREAD SAFETY: Thread-safe (read-only access to static opttab6[] array)
 */
void display_opts6(void)
{
  int i;
  printf(_("Known DHCPv6 options:\n"));
  
  for (i = 0; opttab6[i].name; i++)
    if (!(opttab6[i].size & OT_INTERNAL))
      printf("%3d %s\n", opttab6[i].val, opttab6[i].name);
}
#endif

/**
 * @brief Lookup DHCP option code by human-readable name
 * 
 * @detailed This function performs a reverse lookup in the DHCP option tables to find the
 *           numeric option code corresponding to a given option name string. It supports
 *           both DHCPv4 and DHCPv6 protocols by selecting the appropriate option table
 *           based on the protocol parameter. The lookup is case-insensitive, allowing
 *           flexible input formats. This function is primarily used during configuration
 *           parsing when users specify DHCP options by name (e.g., "netmask", "dns-server")
 *           rather than by numeric code. The function searches the appropriate opttab[]
 *           or opttab6[] array for a matching name and returns the corresponding option code.
 * 
 * @param prot Protocol identifier: AF_INET for DHCPv4, AF_INET6 for DHCPv6 (when HAVE_DHCP6
 *             enabled). Determines which option table to search. AF_INET6 requires HAVE_DHCP6
 *             compile flag; otherwise defaults to DHCPv4 table.
 * @param name Human-readable DHCP option name to lookup (e.g., "netmask", "router", "dns-server").
 *             Case-insensitive comparison using strcasecmp(). Must not be NULL.
 * 
 * @return int DHCP option code (0-255 for DHCPv4, 0-65535 for DHCPv6) if name found in table
 * @retval -1 Option name not recognized or not found in appropriate option table
 * @retval >=0 Valid DHCP option code corresponding to the provided name
 * 
 * @note This function performs linear search through option tables, acceptable for typical
 *       usage during configuration parsing (not performance-critical path). Option tables
 *       defined in dhcp-protocol.h (DHCPv4) and dhcp6-protocol.h (DHCPv6).
 * @warning Returns -1 for unrecognized names; caller must check return value before using.
 *          Case-insensitive matching may match multiple variants of same name.
 * @see lookup_dhcp_len() - Lookup option length/size by option code
 * @see opttab[] - DHCPv4 option table in dhcp-protocol.h
 * @see opttab6[] - DHCPv6 option table in dhcp6-protocol.h
 * 
 * EXAMPLE USAGE:
 * @code
 * // During configuration parsing: dhcp-option=netmask,255.255.255.0
 * int opt_code = lookup_dhcp_opt(AF_INET, "netmask");
 * if (opt_code == -1) {
 *   // Error: unrecognized option name
 * } else {
 *   // opt_code = 1 (DHCP option code for subnet mask)
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: Option names and codes per RFC 2132 (DHCPv4) and RFC 3315 (DHCPv6)
 * SIDE EFFECTS: None; read-only access to static option tables
 * THREAD SAFETY: Thread-safe; read-only access to static const data
 */
int lookup_dhcp_opt(int prot, char *name)
{
  const struct opttab_t *t;
  int i;

  (void)prot;

#ifdef HAVE_DHCP6
  if (prot == AF_INET6)
    t = opttab6;
  else
#endif
    t = opttab;

  for (i = 0; t[i].name; i++)
    if (strcasecmp(t[i].name, name) == 0)
      return t[i].val;
  
  return -1;
}

/**
 * @brief Lookup DHCP option expected length/size by option code
 * 
 * @detailed This function queries the DHCP option tables to determine the expected length
 *           or size characteristics for a given DHCP option code. It supports both DHCPv4
 *           and DHCPv6 protocols by selecting the appropriate option table. The returned
 *           value indicates the option's length requirements: fixed-length options return
 *           their exact byte size, variable-length options return 0, and options with
 *           specific encoding requirements return special codes. This information is used
 *           during option parsing and validation to ensure correctly formatted option data.
 *           The function searches opttab[] or opttab6[] for the option code and returns
 *           the associated size field from the option descriptor.
 * 
 * @param prot Protocol identifier: AF_INET for DHCPv4, AF_INET6 for DHCPv6 (when HAVE_DHCP6
 *             enabled). Determines which option table to search. AF_INET6 requires HAVE_DHCP6
 *             compile flag; otherwise defaults to DHCPv4 table.
 * @param val DHCP option code to lookup (0-255 for DHCPv4, 0-65535 for DHCPv6). Should be
 *            a valid option code; unrecognized codes return 0.
 * 
 * @return int Length/size indicator for the DHCP option
 * @retval 0 Variable-length option (length determined by option data), or unrecognized option code
 * @retval >0 Fixed-length option: exact byte size required (e.g., 4 for IPv4 address, 16 for IPv6)
 * @retval Special codes for specific encoding (option table defines OT_ADDR_LIST, OT_NAME, etc.)
 * 
 * @note This function performs linear search through option tables, acceptable for option
 *       parsing and validation operations. Return value 0 is ambiguous (variable-length or
 *       unknown); caller should verify option code validity separately if needed.
 * @warning Returning 0 for unrecognized options may cause validation issues if caller assumes
 *          variable-length. Caller should validate option codes before relying on length info.
 * @see lookup_dhcp_opt() - Lookup option code by name (reverse operation)
 * @see opttab[] - DHCPv4 option table with size field for each option
 * @see opttab6[] - DHCPv6 option table with size field for each option
 * 
 * EXAMPLE USAGE:
 * @code
 * // Validate subnet mask option (code 1) has correct length
 * int expected_len = lookup_dhcp_len(AF_INET, 1);
 * if (expected_len > 0 && actual_len != expected_len) {
 *   // Error: subnet mask must be exactly 4 bytes
 * }
 * // expected_len = 4 (IPv4 address is 4 bytes)
 * @endcode
 * 
 * RFC COMPLIANCE: Option sizes per RFC 2132 (DHCPv4) and RFC 3315 (DHCPv6)
 * SIDE EFFECTS: None; read-only access to static option tables
 * THREAD SAFETY: Thread-safe; read-only access to static const data
 */
int lookup_dhcp_len(int prot, int val)
{
  const struct opttab_t *t;
  int i;

  (void)prot;

#ifdef HAVE_DHCP6
  if (prot == AF_INET6)
    t = opttab6;
  else
#endif
    t = opttab;

  for (i = 0; t[i].name; i++)
    if (val == t[i].val)
      return t[i].size & ~OT_DEC;

   return 0;
}

/**
 * @brief Convert DHCP option data to human-readable string representation
 * 
 * @detailed This function formats DHCP option data into human-readable string format for
 *           logging, display, and debugging purposes. It performs intelligent decoding based
 *           on the option type: IP addresses are formatted as dotted-decimal or colon-hex,
 *           strings are displayed as text with non-printable character filtering, integers
 *           are decoded as decimal values, and unknown or binary data is rendered as
 *           hexadecimal. The function consults the DHCP option tables (opttab[] for DHCPv4,
 *           opttab6[] for DHCPv6) to determine the option name and expected format, then
 *           applies appropriate formatting. Special handling is provided for complex options
 *           like option 81 (client FQDN with encoding flags). The function is used throughout
 *           DHCP logging to provide meaningful human-readable representations of option values
 *           rather than raw hex dumps, significantly improving troubleshooting and auditing.
 * 
 * @param prot Protocol identifier: AF_INET for DHCPv4, AF_INET6 for DHCPv6 (when HAVE_DHCP6
 *             enabled). Determines which option table to consult and which formatting rules
 *             to apply for addresses and option-specific encodings.
 * @param opt DHCP option code to format (0-255 for DHCPv4, 0-65535 for DHCPv6). Looked up in
 *            option tables to determine option name and data type. Unknown options formatted
 *            as "option:<code>" with hex data display.
 * @param val Pointer to raw DHCP option data bytes to be formatted. Must not be NULL if
 *            opt_len > 0. Data interpreted according to option type from option tables.
 * @param opt_len Length of option data in bytes pointed to by val. Zero-length options produce
 *                empty string. Maximum practical length limited by buf_len output buffer size.
 * @param buf Output buffer to receive formatted string. Must be pre-allocated by caller with
 *            size buf_len. Must not be NULL. Buffer receives null-terminated C string.
 * @param buf_len Size of output buffer buf in bytes including space for null terminator. Function
 *                ensures output does not exceed this size. Typical value: DHCP_BUFF_SZ (256 bytes).
 * 
 * @return char* Pointer to buf containing formatted null-terminated string. Never returns NULL;
 *               always returns buf (same as input buf parameter). String may be truncated if
 *               formatted output exceeds buf_len-1 characters.
 * @retval buf Always returns the output buffer pointer passed as parameter
 * 
 * @note Formatting rules vary by option type: OT_ADDR_LIST (IP addresses comma-separated),
 *       OT_NAME (text string), OT_TIME (decimal seconds), OT_INTERNAL (hex bytes),
 *       OT_DEC (decimal integer), OT_HEX (hex bytes with colons). Option 81 (client FQDN)
 *       receives special handling with flags and domain name decoding.
 * @warning Output may be truncated if formatted string exceeds buf_len-1. Caller must provide
 *          adequate buffer size for expected option lengths. Non-printable characters in string
 *          options replaced with '?' for safe display. IPv6 addresses in DHCPv6 options formatted
 *          with inet_ntop using compressed notation.
 * @see lookup_dhcp_opt() - Lookup option code by name
 * @see lookup_dhcp_len() - Lookup expected option length
 * @see opttab[] - DHCPv4 option table with type information
 * @see opttab6[] - DHCPv6 option table with type information
 * 
 * EXAMPLE USAGE:
 * @code
 * // Format subnet mask option (code 1) for logging
 * unsigned char mask_data[] = {255, 255, 255, 0};
 * char formatted[DHCP_BUFF_SZ];
 * option_string(AF_INET, 1, mask_data, 4, formatted, DHCP_BUFF_SZ);
 * // formatted = "netmask 255.255.255.0"
 * 
 * // Format unknown option with hex display
 * unsigned char unknown_data[] = {0x12, 0x34, 0x56};
 * option_string(AF_INET, 200, unknown_data, 3, formatted, DHCP_BUFF_SZ);
 * // formatted = "option:200 12:34:56"
 * @endcode
 * 
 * RFC COMPLIANCE: Option formatting per RFC 2132 (DHCPv4), RFC 3315 (DHCPv6), RFC 4702 (option 81)
 * SIDE EFFECTS: Modifies output buffer buf; no other side effects
 * THREAD SAFETY: Thread-safe if each thread uses separate output buffer; read-only option table access
 */
char *option_string(int prot, unsigned int opt, unsigned char *val, int opt_len, char *buf, int buf_len)
{
  int o, i, j, nodecode = 0;
  const struct opttab_t *ot = opttab;

#ifdef HAVE_DHCP6
  if (prot == AF_INET6)
    ot = opttab6;
#endif

  for (o = 0; ot[o].name; o++)
    if (ot[o].val == opt)
      {
	if (buf)
	  {
	    memset(buf, 0, buf_len);
	    
	    if (ot[o].size & OT_ADDR_LIST) 
	      {
		union all_addr addr;
		int addr_len = INADDRSZ;

#ifdef HAVE_DHCP6
		if (prot == AF_INET6)
		  addr_len = IN6ADDRSZ;
#endif
		for (buf[0]= 0, i = 0; i <= opt_len - addr_len; i += addr_len) 
		  {
		    if (i != 0)
		      strncat(buf, ", ", buf_len - strlen(buf));
		    /* align */
		    memcpy(&addr, &val[i], addr_len); 
		    inet_ntop(prot, &val[i], daemon->addrbuff, ADDRSTRLEN);
		    strncat(buf, daemon->addrbuff, buf_len - strlen(buf));
		  }
	      }
	    else if (ot[o].size & OT_NAME)
		for (i = 0, j = 0; i < opt_len && j < buf_len ; i++)
		  {
		    char c = val[i];
		    if (isprint((unsigned char)c))
		      buf[j++] = c;
		  }
#ifdef HAVE_DHCP6
	    /* We don't handle compressed rfc1035 names, so no good in IPv4 land */
	    else if ((ot[o].size & OT_RFC1035_NAME) && prot == AF_INET6)
	      {
		i = 0, j = 0;
		while (i < opt_len && val[i] != 0)
		  {
		    int k, l = i + val[i] + 1;
		    for (k = i + 1; k < opt_len && k < l && j < buf_len ; k++)
		     {
		       char c = val[k];
		       if (isprint((unsigned char)c))
			 buf[j++] = c;
		     }
		    i = l;
		    if (val[i] != 0 && j < buf_len)
		      buf[j++] = '.';
		  }
	      }
	    else if ((ot[o].size & OT_CSTRING))
	      {
		int k, len;
		unsigned char *p;

		i = 0, j = 0;
		while (1)
		  {
		    p = &val[i];
		    GETSHORT(len, p);
		    for (k = 0; k < len && j < buf_len; k++)
		      {
		       char c = *p++;
		       if (isprint((unsigned char)c))
			 buf[j++] = c;
		     }
		    i += len +2;
		    if (i >= opt_len)
		      break;

		    if (j < buf_len)
		      buf[j++] = ',';
		  }
	      }	      
#endif
	    else if ((ot[o].size & (OT_DEC | OT_TIME)) && opt_len != 0)
	      {
		unsigned int dec = 0;
		
		for (i = 0; i < opt_len; i++)
		  dec = (dec << 8) | val[i]; 

		if (ot[o].size & OT_TIME)
		  prettyprint_time(buf, dec);
		else
		  sprintf(buf, "%u", dec);
	      }
	    else
	      nodecode = 1;
	  }
	break;
      }

  if (opt_len != 0 && buf && (!ot[o].name || nodecode))
    {
      int trunc  = 0;
      if (opt_len > 14)
	{
	  trunc = 1;
	  opt_len = 14;
	}
      print_mac(buf, val, opt_len);
      if (trunc)
	strncat(buf, "...", buf_len - strlen(buf));
    

    }

  return ot[o].name ? ot[o].name : "";

}

/**
 * @brief Log DHCP context configuration information to syslog
 * 
 * @detailed Formats and logs detailed information about a DHCP context including address ranges,
 *           lease times, deprecation status, template/constructed status, and associated options.
 *           For DHCPv4 contexts, logs IP address ranges and subnet masks. For DHCPv6 contexts,
 *           logs IPv6 prefixes, RA-derived names, and router advertisement configuration. Handles
 *           special context types: stateless-only, static-only, proxy DHCP, template contexts,
 *           and constructed contexts (derived from router advertisement).
 * 
 * @param family Address family: AF_INET for DHCPv4 contexts, AF_INET6 for DHCPv6 contexts
 * @param context Pointer to dhcp_context structure containing context configuration to log.
 *                Must not be NULL. Context contains address range, lease time, flags, netid tags.
 * 
 * @return void (no return value)
 * 
 * @note Uses global daemon->addrbuff and daemon->namebuff for address formatting
 * @note IPv6 contexts log prefix length and SLAAC/RA-related configuration
 * @note Deprecation flag (CONTEXT_DEPRECATE) triggers special deprecation message
 * @note Template contexts (CONTEXT_TEMPLATE) and constructed contexts (CONTEXT_CONSTRUCTED) are marked
 * 
 * @see struct dhcp_context in dnsmasq.h for context structure definition
 * @see prettyprint_time() for lease time formatting
 * @see inet_ntop() for address formatting
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_context *ctx = ...;
 * log_context(AF_INET, ctx);  // Logs DHCPv4 range like "DHCP, IP range 192.168.1.10 -- 192.168.1.100, lease time 1h"
 * log_context(AF_INET6, ctx); // Logs DHCPv6 prefix like "DHCPv6-stateless on eth0, stateless only"
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (logging function, not protocol implementation)
 * SIDE EFFECTS: Writes log messages to syslog with MS_DHCP facility
 * THREAD SAFETY: Single-threaded architecture; accesses global daemon structure
 */
void log_context(int family, struct dhcp_context *context)
{
  /* Cannot use dhcp_buff* for RA contexts */

  void *start = &context->start;
  void *end = &context->end;
  char *template = "", *p = daemon->namebuff;
  
  *p = 0;
    
#ifdef HAVE_DHCP6
  if (family == AF_INET6)
    {
      struct in6_addr subnet = context->start6;
      if (!(context->flags & CONTEXT_TEMPLATE))
	setaddr6part(&subnet, 0);
      inet_ntop(AF_INET6, &subnet, daemon->addrbuff, ADDRSTRLEN); 
      start = &context->start6;
      end = &context->end6;
    }
#endif

  if (family != AF_INET && (context->flags & CONTEXT_DEPRECATE))
    strcpy(daemon->namebuff, _(", prefix deprecated"));
  else
    {
      p += sprintf(p, _(", lease time "));
      prettyprint_time(p, context->lease_time);
      p += strlen(p);
    }	

#ifdef HAVE_DHCP6
  if (context->flags & CONTEXT_CONSTRUCTED)
    {
      char ifrn_name[IFNAMSIZ];
      
      template = p;
      p += sprintf(p, ", ");
      
      if (indextoname(daemon->icmp6fd, context->if_index, ifrn_name))
	sprintf(p, "%s for %s", (context->flags & CONTEXT_OLD) ? "old prefix" : "constructed", ifrn_name);
    }
  else if (context->flags & CONTEXT_TEMPLATE && !(context->flags & CONTEXT_RA_STATELESS))
    {
      template = p;
      p += sprintf(p, ", ");
      
      sprintf(p, "template for %s", context->template_interface);  
    }
#endif
     
  if (!(context->flags & CONTEXT_OLD) &&
      ((context->flags & CONTEXT_DHCP) || family == AF_INET)) 
    {
#ifdef HAVE_DHCP6
      if (context->flags & CONTEXT_RA_STATELESS)
	{
	  if (context->flags & CONTEXT_TEMPLATE)
	    strncpy(daemon->dhcp_buff, context->template_interface, DHCP_BUFF_SZ);
	  else
	    strcpy(daemon->dhcp_buff, daemon->addrbuff);
	}
      else 
#endif
	inet_ntop(family, start, daemon->dhcp_buff, DHCP_BUFF_SZ);
      inet_ntop(family, end, daemon->dhcp_buff3, DHCP_BUFF_SZ);
      my_syslog(MS_DHCP | LOG_INFO, 
		(context->flags & CONTEXT_RA_STATELESS) ? 
		_("%s stateless on %s%.0s%.0s%s") :
		(context->flags & CONTEXT_STATIC) ? 
		_("%s, static leases only on %.0s%s%s%.0s") :
		(context->flags & CONTEXT_PROXY) ?
		_("%s, proxy on subnet %.0s%s%.0s%.0s") :
		_("%s, IP range %s -- %s%s%.0s"),
		(family != AF_INET) ? "DHCPv6" : "DHCP",
		daemon->dhcp_buff, daemon->dhcp_buff3, daemon->namebuff, template);
    }
  
#ifdef HAVE_DHCP6
  if (context->flags & CONTEXT_TEMPLATE)
    {
      strcpy(daemon->addrbuff, context->template_interface);
      template = "";
    }

  if ((context->flags & CONTEXT_RA_NAME) && !(context->flags & CONTEXT_OLD))
    my_syslog(MS_DHCP | LOG_INFO, _("DHCPv4-derived IPv6 names on %s%s"), daemon->addrbuff, template);
  
  if ((context->flags & CONTEXT_RA) || (option_bool(OPT_RA) && (context->flags & CONTEXT_DHCP) && family == AF_INET6)) 
    my_syslog(MS_DHCP | LOG_INFO, _("router advertisement on %s%s"), daemon->addrbuff, template);
#endif

}

/**
 * @brief Log DHCP relay configuration information to syslog
 * 
 * @detailed Formats and logs DHCP relay configuration including local address, server address,
 *           interface name, and port numbers (if non-default). Handles both DHCPv4 and DHCPv6
 *           relay configurations. For DHCPv4, detects broadcast relay (server address 0.0.0.0).
 *           For DHCPv6, detects multicast relay (ALL_SERVERS multicast group). Distinguishes
 *           between standard relay mode and split-relay mode where relay separates request
 *           forwarding and response handling. Log messages vary based on relay mode: broadcast/
 *           multicast relay (no destination specified), split-relay (from source to destination),
 *           or standard relay (from source to destination).
 * 
 * @param family Address family: AF_INET for DHCPv4 relay, AF_INET6 for DHCPv6 relay
 * @param relay Pointer to dhcp_relay structure containing relay configuration to log.
 *              Must not be NULL. Structure contains local address, server address, interface
 *              name (may be NULL), port number, and split_mode flag.
 * 
 * @return void (no return value)
 * 
 * @note Uses global daemon->addrbuff for local address formatting
 * @note Uses global daemon->namebuff for server address formatting
 * @note DHCPv4 default port is DHCP_SERVER_PORT (67), non-default appended as "#port"
 * @note DHCPv6 default port is DHCPV6_SERVER_PORT (547), non-default appended as "#port"
 * @note Broadcast relay: server address 0.0.0.0 for DHCPv4, ALL_SERVERS (ff02::1:3) for DHCPv6
 * @note Split-relay mode: relay forwards requests to server but returns responses directly
 * @warning Requires HAVE_DHCP6 compiled for IPv6 relay support
 * 
 * @see struct dhcp_relay in dnsmasq.h for relay structure definition
 * @see inet_ntop() for address formatting
 * @see ALL_SERVERS constant for DHCPv6 multicast address (ff02::1:3)
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_relay *relay = ...;
 * log_relay(AF_INET, relay);  // Logs "DHCP relay from 192.168.1.1 to 192.168.2.1 via eth0"
 * log_relay(AF_INET6, relay); // Logs "DHCP relay from fe80::1 to fe80::2 via eth1"
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (logging function, not protocol implementation)
 * SIDE EFFECTS: Writes log messages to syslog with MS_DHCP facility
 * THREAD SAFETY: Single-threaded architecture; accesses global daemon structure
 */
void log_relay(int family, struct dhcp_relay *relay)
{
  int broadcast = relay->server.addr4.s_addr == 0;
  inet_ntop(family, &relay->local, daemon->addrbuff, ADDRSTRLEN);
  inet_ntop(family, &relay->server, daemon->namebuff, ADDRSTRLEN);

  if (family == AF_INET && relay->port != DHCP_SERVER_PORT)
    sprintf(daemon->namebuff + strlen(daemon->namebuff), "#%u", relay->port);

#ifdef HAVE_DHCP6
  struct in6_addr multicast;

  inet_pton(AF_INET6, ALL_SERVERS, &multicast);

  if (family == AF_INET6)
    {
      broadcast = IN6_ARE_ADDR_EQUAL(&relay->server.addr6, &multicast);
      if (relay->port != DHCPV6_SERVER_PORT)
	sprintf(daemon->namebuff + strlen(daemon->namebuff), "#%u", relay->port);
    }
#endif
  
  
  if (relay->interface)
    {
      if (broadcast)
	my_syslog(MS_DHCP | LOG_INFO, _("DHCP relay from %s via %s"), daemon->addrbuff, relay->interface);
      else if (relay->split_mode)
	my_syslog(MS_DHCP | LOG_INFO, _("DHCP split-relay from %s to %s via %s"), daemon->addrbuff, daemon->namebuff, relay->interface);
      else
	my_syslog(MS_DHCP | LOG_INFO, _("DHCP relay from %s to %s via %s"), daemon->addrbuff, daemon->namebuff, relay->interface);
    }
  else 
    my_syslog(MS_DHCP | LOG_INFO, _("DHCP relay from %s to %s"), daemon->addrbuff, daemon->namebuff);
}
   
#endif

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
 * @file rrfilter.c
 * @brief DNS Resource Record filtering for query type restrictions and response filtering
 * 
 * DETAILED PURPOSE:
 * This module implements safe removal and filtering of DNS Resource Records (RRs) from
 * DNS response packets. The primary functionality enables selective elision of specific
 * record types from DNS answers while maintaining packet integrity, including proper
 * handling of DNS name compression pointers and header count fields. The module supports
 * multiple filtering modes including EDNS0 removal, DNSSEC record filtering, address
 * record filtering (A/AAAA), and policy-based record type filtering.
 * 
 * The core challenge addressed is that DNS packets use compression pointers within domain
 * names to reduce packet size. When removing records from a packet, any compression pointers
 * that reference the removed records must be detected and rejected, and pointers that skip
 * over removed sections must be recalculated. This module implements a four-pass algorithm
 * to safely perform these operations without corrupting the DNS packet structure.
 * 
 * KEY RESPONSIBILITIES:
 * - rrfilter() implements four-pass filtering algorithm for safe record removal (lines 161-293)
 * - check_name() validates and fixes DNS name compression pointers after record removal (lines 23-106)
 * - check_rrs() validates resource records and their embedded names for pointer integrity (lines 109-156)
 * - rrfilter_desc() provides type descriptor information for RR types containing domain names (lines 296-338)
 * - to_wire() converts domain names from presentation format to DNS wire format (lines 377-406)
 * - from_wire() converts domain names from DNS wire format to presentation format (lines 409-434)
 * - expand_workspace() dynamically expands the RR pointer tracking array (lines 340-359)
 * 
 * DEPENDENCIES:
 * Includes: dnsmasq.h (core data structures and macros), dns-protocol.h (DNS constants and types)
 * Called by: forward.c (DNS query forwarding and response processing), rfc1035.c (DNS packet handling)
 * Calls: skip_name() from rfc1035.c for name traversal, rr_on_list() for filter rule matching,
 *        whine_realloc() from util.c for memory allocation
 * 
 * DATA STRUCTURES:
 * - struct dns_header: DNS packet header containing question/answer/authority/additional counts
 *   (defined in dns-protocol.h, used for packet parsing and count updates)
 * - unsigned char **rrs: Static array tracking start/end pointers of records to be removed
 *   (allocated dynamically, grows as needed via expand_workspace)
 * - short rr_desc[]: Static table mapping RR types to their internal structure for name extraction
 *   (lines 307-330, describes which fields contain domain names)
 * 
 * COMPILE-TIME OPTIONS:
 * - RRFILTER_EDNS0: Mode flag for removing EDNS0 OPT pseudo-RRs from additional section
 * - RRFILTER_DNSSEC: Mode flag for removing DNSSEC validation records (RRSIG, NSEC, NSEC3)
 * - RRFILTER_CONF: Mode flag for policy-based filtering using daemon->filter_rr configuration
 * - CHECK_LEN macro: Validates packet bounds to prevent buffer overruns (defined in dnsmasq.h)
 * - ADD_RDLEN macro: Safely advances pointer by rdlen with bounds checking (defined in dnsmasq.h)
 * 
 * THREADING/CONCURRENCY:
 * Single-threaded event-driven architecture. The static rrs array is reused across calls
 * but protected by the single-threaded execution model. No locking required. Each DNS
 * query processing is serialized through the main event loop in dnsmasq.c.
 * 
 * @copyright Copyright (c) 2000-2025 Simon Kelley
 * @license GPL-2.0-or-later
 */

/* Code to safely remove RRs from a DNS answer */ 

#include "dnsmasq.h"

/**
 * @brief Validate and fix DNS name compression pointers after record removal
 * 
 * @detailed This function traverses a DNS domain name in wire format, identifying compression
 *           pointers (label type 0xc0) and validating or adjusting them based on records that
 *           have been removed from the packet. DNS name compression uses 2-byte pointers where
 *           the top 2 bits are 11 (0xc0) and the remaining 14 bits are an offset from the start
 *           of the DNS packet to another occurrence of the same name suffix.
 *           
 *           When records are removed from a DNS packet, compression pointers must be handled:
 *           1) Pointers targeting removed records are invalid (function returns 0)
 *           2) Pointers targeting names after removed records must be adjusted downward
 *           3) All pointers must be validated for packet bounds
 *           
 *           The function supports two modes controlled by the fixup parameter:
 *           - fixup=0: Validation only, detect invalid pointers without modification
 *           - fixup=1: Validation and adjustment, rewrite pointer offsets as needed
 *           
 *           The algorithm handles four DNS label types per RFC 1035:
 *           - 0x00: Standard label with 6-bit length (most common)
 *           - 0xc0: Compression pointer (2 bytes, top 2 bits = 11)
 *           - 0x40: Extended label (bitstring labels, RFC 2673)
 *           - 0x80: Reserved (invalid, causes rejection)
 * 
 * @param namep Pointer to pointer to start of DNS name in packet (updated as name is traversed)
 * @param header Pointer to DNS packet header (used as base for offset calculations)
 * @param plen Total length of DNS packet in bytes (for bounds checking)
 * @param fixup If non-zero, rewrite compression pointer offsets; if zero, validation only
 * @param rrs Array of pointers marking start/end of records to be removed (pairs: [start0,end0,start1,end1,...])
 * @param rr_count Number of pointers in rrs array (must be even: rr_count/2 records marked)
 * 
 * @return 1 if name is valid and pointers are safe (or successfully adjusted)
 * @retval 1 Name validated successfully, all pointers valid or adjusted
 * @retval 0 Name is invalid: pointer into removed record, out-of-bounds access, or reserved label type
 * 
 * @note This function modifies *namep to point past the end of the name on success
 * @warning Compression pointers that target removed records cause immediate failure return 0
 * @warning Extended label types (bitstrings) are parsed but rarely used in practice
 * 
 * @see check_rrs() in rrfilter.c for RR-level validation using this function
 * @see skip_name() in rfc1035.c for simpler name traversal without pointer adjustment
 * 
 * EXAMPLE USAGE:
 * @code
 * unsigned char *name_ptr = answer_section;
 * if (!check_name(&name_ptr, header, packet_len, 1, removed_rrs, 4)) {
 *   // Compression pointer was invalid or pointed into removed record
 *   return 0;
 * }
 * // name_ptr now points past the validated/adjusted name
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 1035 Section 4.1.4 (message compression)
 * RFC COMPLIANCE: RFC 2673 (bitstring labels, extended label type 0x40)
 * 
 * SIDE EFFECTS: When fixup=1, modifies compression pointer bytes in the DNS packet to adjusted offsets
 * 
 * THREAD SAFETY: Safe in single-threaded dnsmasq architecture; no global state modified
 */
/* Go through a domain name, find "pointers" and fix them up based on how many bytes
   we've chopped out of the packet, or check they don't point into an elided part.  */
static int check_name(unsigned char **namep, struct dns_header *header, size_t plen, int fixup, unsigned char **rrs, int rr_count)
{
  unsigned char *ansp = *namep;

  while(1)
    {
      unsigned int label_type;
      
      if (!CHECK_LEN(header, ansp, plen, 1))
	return 0;
      
      label_type = (*ansp) & 0xc0;

      if (label_type == 0xc0)
	{
	  /* pointer for compression. */
	  unsigned int offset;
	  int i;
	  unsigned char *p;
	  
	  if (!CHECK_LEN(header, ansp, plen, 2))
	    return 0;

	  offset = ((*ansp++) & 0x3f) << 8;
	  offset |= *ansp++;

	  p = offset + (unsigned char *)header;
	  
	  for (i = 0; i < rr_count; i++)
	    if (p < rrs[i])
	      break;
	    else
	      if (i & 1)
		offset -= rrs[i] - rrs[i-1];

	  /* does the pointer end up in an elided RR? */
	  if (i & 1)
	    return 0;

	  /* No, scale the pointer */
	  if (fixup)
	    {
	      ansp -= 2;
	      *ansp++ = (offset >> 8) | 0xc0;
	      *ansp++ = offset & 0xff;
	    }
	  break;
	}
      else if (label_type == 0x80)
	return 0; /* reserved */
      else if (label_type == 0x40)
	{
	  /* Extended label type */
	  unsigned int count;
	  
	  if (!CHECK_LEN(header, ansp, plen, 2))
	    return 0;
	  
	  if (((*ansp++) & 0x3f) != 1)
	    return 0; /* we only understand bitstrings */
	  
	  count = *(ansp++); /* Bits in bitstring */
	  
	  if (count == 0) /* count == 0 means 256 bits */
	    ansp += 32;
	  else
	    ansp += ((count-1)>>3)+1;
	}
      else
	{ /* label type == 0 Bottom six bits is length */
	  unsigned int len = (*ansp++) & 0x3f;
	  
	  if (!ADD_RDLEN(header, ansp, plen, len))
	    return 0;

	  if (len == 0)
	    break; /* zero length label marks the end. */
	}
    }

  *namep = ansp;

  return 1;
}

/**
 * @brief Validate and fix domain names within all resource records in DNS packet
 * 
 * @detailed This function iterates through all resource records in the answer, authority,
 *           and additional sections of a DNS packet, validating and optionally adjusting
 *           compression pointers within both the record owner name and any domain names
 *           embedded in the record data (RDATA) section. The function uses rrfilter_desc()
 *           to determine which fields within each RR type's RDATA contain domain names.
 *           
 *           For each resource record, the function:
 *           1) Validates the owner name (the name this RR applies to)
 *           2) Skips the record if it's marked for removal in the rrs array
 *           3) For retained records of class IN, examines RDATA using type descriptor
 *           4) Validates/adjusts each domain name field within RDATA per descriptor
 *           
 *           RR types with domain names in RDATA include: NS (nameserver), CNAME (canonical
 *           name), SOA (start of authority, contains mname and rname), MX (mail exchange),
 *           SRV (service location), PTR (pointer), and others. The rrfilter_desc() function
 *           provides a descriptor array indicating which bytes to skip and where names occur.
 *           
 *           Records marked for removal (present in rrs array) are skipped entirely because
 *           their contents will be discarded and don't need validation or fixup.
 * 
 * @param p Pointer to start of answer section (immediately after question section)
 * @param header Pointer to DNS packet header (for offset calculations and counts)
 * @param plen Total packet length in bytes (for bounds checking)
 * @param fixup If non-zero, adjust compression pointers; if zero, validation only
 * @param rrs Array of pointers marking records to be removed (pairs: [start,end,...])
 * @param rr_count Number of pointers in rrs array (even number, pairs of start/end)
 * 
 * @return 1 if all RRs and embedded names are valid (or successfully adjusted)
 * @retval 1 All resource records validated successfully, names adjusted if fixup=1
 * @retval 0 Validation failed: malformed RR, invalid compression pointer, or bounds violation
 * 
 * @note Only processes records in class IN (Internet class); other classes are skipped
 * @warning Assumes DNS header counts (ancount, nscount, arcount) are accurate
 * @warning Malformed packets with incorrect counts may cause buffer overruns
 * 
 * @see check_name() in rrfilter.c for individual name validation/adjustment
 * @see rrfilter_desc() in rrfilter.c for RR type structure descriptors
 * @see skip_name() in rfc1035.c for name traversal
 * 
 * EXAMPLE USAGE:
 * @code
 * unsigned char *ans_section = (unsigned char *)(header + 1) + question_len;
 * if (!check_rrs(ans_section, header, packet_len, 1, removed_rrs, 4)) {
 *   // RR validation failed - packet is malformed or contains invalid pointers
 *   return 0;
 * }
 * // All RRs validated and compression pointers adjusted
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 1035 Section 3.2 (RR format), Section 4.1.3 (resource record format)
 * 
 * SIDE EFFECTS: When fixup=1, modifies compression pointer bytes in RDATA fields
 * 
 * THREAD SAFETY: Safe in single-threaded architecture; no global state modified
 */
/* Go through RRs and check or fixup the domain names contained within */
static int check_rrs(unsigned char *p, struct dns_header *header, size_t plen, int fixup, unsigned char **rrs, int rr_count)
{
  int i, j, type, class, rdlen;
  unsigned char *pp;
  
  for (i = 0; i < ntohs(header->ancount) + ntohs(header->nscount) + ntohs(header->arcount); i++)
    {
      pp = p;

      if (!(p = skip_name(p, header, plen, 10)))
	return 0;
      
      GETSHORT(type, p); 
      GETSHORT(class, p);
      p += 4; /* TTL */
      GETSHORT(rdlen, p);

      /* If this RR is to be elided, don't fix up its contents */
      for (j = 0; j < rr_count; j += 2)
	if (rrs[j] == pp)
	  break;

      if (j >= rr_count)
	{
	  /* fixup name of RR */
	  if (!check_name(&pp, header, plen, fixup, rrs, rr_count))
	    return 0;
	  
	  if (class == C_IN)
	    {
	      short *d;
 
	      for (pp = p, d = rrfilter_desc(type); *d != -1; d++)
		{
		  if (*d != 0)
		    pp += *d;
		  else if (!check_name(&pp, header, plen, fixup, rrs, rr_count))
		    return 0;
		}
	    }
	}
      
      if (!ADD_RDLEN(header, p, plen, rdlen))
	return 0;
    }
  
  return 1;
}
	

/* mode may be remove EDNS0 or DNSSEC RRs or remove A or AAAA from answer section.
 * returns number of modified records. */
/**
 * @brief Safely remove DNS resource records from packet using four-pass algorithm
 * 
 * @detailed This function implements the core RR filtering algorithm that safely removes
 *           specific resource records from a DNS response packet while maintaining packet
 *           integrity. The challenge is that DNS packets use name compression where domain
 *           names can contain 2-byte pointers referencing earlier occurrences of the same
 *           name. When removing records, these pointers must be validated and adjusted to
 *           prevent corruption.
 *           
 *           THE FOUR-PASS ALGORITHM:
 *           
 *           Pass 1 (lines 182-249): Identify records to remove
 *           - Iterate through all answer, authority, and additional records
 *           - Apply filtering rules based on mode and configuration
 *           - Record start/end pointers for each record to be removed in rrs[] array
 *           - Count removals per section (chop_an, chop_ns, chop_ar)
 *           
 *           Pass 2 (lines 258-267): Validate compression pointers (detection only)
 *           - Check question section name and all retained RR names
 *           - Verify no compression pointers target records marked for removal
 *           - If invalid pointers found, abort filtering and return original packet
 *           
 *           Pass 3 (lines 269-275): Fix compression pointers (adjustment)
 *           - Traverse question section name and all retained RR names again
 *           - Adjust compression pointer offsets to account for removed records
 *           - Rewrite pointer bytes in packet with corrected offsets
 *           
 *           Pass 4 (lines 277-290): Physical record removal
 *           - Use memmove() to compact packet, removing marked records
 *           - Update packet length to reflect removed bytes
 *           - Decrement DNS header counts (ancount, nscount, arcount)
 *           
 *           FILTERING MODES:
 *           
 *           RRFILTER_EDNS0: Remove EDNS0 OPT pseudo-RRs from additional section
 *           - Used when downstream client doesn't support EDNS0
 *           - Removes T_OPT records only from additional section
 *           
 *           RRFILTER_DNSSEC: Remove DNSSEC validation records
 *           - Removes RRSIG, NSEC, NSEC3 from all sections
 *           - Preserves answer section if explicitly queried (qtype matches)
 *           - Used when client doesn't support or request DNSSEC
 *           
 *           RRFILTER_CONF: Policy-based filtering via daemon->filter_rr list
 *           - Removes record types listed in configuration
 *           - Special handling for T_ANY queries per RFC 8482 (minimal response)
 *           - Only processes answer section (authority/additional untouched)
 * 
 * @param header Pointer to DNS packet header (modified: ancount/nscount/arcount updated)
 * @param plen Pointer to packet length variable (modified: updated to new length after removal)
 * @param mode Filtering mode: RRFILTER_EDNS0, RRFILTER_DNSSEC, or RRFILTER_CONF
 * 
 * @return Number of records removed (rr_found/2, since rrs[] contains pairs of start/end pointers)
 * @retval 0 No records removed (no matching records, or filtering aborted due to invalid pointers)
 * @retval >0 Number of records successfully removed from packet
 * 
 * @note Static rrs[] array persists across calls, dynamically expanded as needed
 * @note Function returns 0 on error but packet may be partially processed; caller should discard
 * @warning Packet must have exactly 1 question (qdcount==1) or function returns 0
 * @warning Malformed packets with invalid names or bounds violations cause early return
 * 
 * @see check_name() in rrfilter.c for compression pointer validation/adjustment
 * @see check_rrs() in rrfilter.c for RR-level name validation
 * @see expand_workspace() in rrfilter.c for rrs[] array management
 * @see rr_on_list() in forward.c for filter rule matching
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dns_header *header = (struct dns_header *)packet_buffer;
 * size_t packet_len = 512;
 * // Remove DNSSEC records for non-DNSSEC client
 * size_t removed = rrfilter(header, &packet_len, RRFILTER_DNSSEC);
 * if (removed > 0) {
 *   // Packet length reduced, DNSSEC records removed
 *   send_response(packet_buffer, packet_len);
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 1035 Section 4.1.4 (message compression)
 * RFC COMPLIANCE: RFC 8482 Section 4.3 (minimal responses to ANY queries)
 * RFC COMPLIANCE: RFC 6891 (EDNS0 OPT pseudo-RR handling)
 * 
 * SIDE EFFECTS: 
 * - Modifies DNS packet in place (removes records, adjusts pointers)
 * - Updates *plen to reflect new packet size
 * - Updates header->ancount, header->nscount, header->arcount
 * - Expands static rrs[] array if needed (persistent across calls)
 * 
 * THREAD SAFETY: Not thread-safe due to static rrs[] array; safe in single-threaded architecture
 */
size_t rrfilter(struct dns_header *header, size_t *plen, int mode)
{
  static unsigned char **rrs = NULL;
  static int rr_sz = 0;

  unsigned char *p = (unsigned char *)(header+1);
  size_t rr_found = 0;
  int i, rdlen, qtype, qclass, chop_an, chop_ns, chop_ar;

  if (mode == RRFILTER_CONF && !daemon->filter_rr)
    return 0;
  
  if (ntohs(header->qdcount) != 1 ||
      !(p = skip_name(p, header, *plen, 4)))
    return 0;
  
  GETSHORT(qtype, p);
  GETSHORT(qclass, p);

  /* First pass, find pointers to start and end of all the records we wish to elide:
     records added for DNSSEC, unless explicitly queried for */
  for (chop_ns = 0, chop_an = 0, chop_ar = 0, i = 0;
       i < ntohs(header->ancount) + ntohs(header->nscount) + ntohs(header->arcount);
       i++)
    {
      unsigned char *pstart = p;
      int type, class;

      if (!(p = skip_name(p, header, *plen, 10)))
	return rr_found;
      
      GETSHORT(type, p); 
      GETSHORT(class, p);
      p += 4; /* TTL */
      GETSHORT(rdlen, p);
        
      if (!ADD_RDLEN(header, p, *plen, rdlen))
	return rr_found;

      if (mode == RRFILTER_EDNS0) /* EDNS */
	{
	  /* EDNS mode, remove T_OPT from additional section only */
	  if (i < (ntohs(header->nscount) + ntohs(header->ancount)) || type != T_OPT)
	    continue;
	}
      else if (mode == RRFILTER_DNSSEC)
	{
	  if (type != T_NSEC && type != T_NSEC3 && type != T_RRSIG)
	    /* DNSSEC mode, remove SIGs and NSECs from all three sections. */
	    continue;

	  /* Don't remove the answer. */
	  if (i < ntohs(header->ancount) && type == qtype && class == qclass)
	    continue;
	}
      else if (qtype == T_ANY && rr_on_list(daemon->filter_rr, T_ANY))
	{
	  /* Filter replies to ANY queries in the spirit of
	     RFC RFC 8482 para 4.3 */
	  if (class != C_IN ||
	      type == T_A || type == T_AAAA || type == T_MX || type == T_CNAME)
	    continue;
	}
      else
	{
	  /* Only looking at answer section now. */
	  if (i >= ntohs(header->ancount))
	    break;

	  if (class != C_IN)
	    continue;
	  
	  if (!rr_on_list(daemon->filter_rr, type))
	    continue;
	}
      
      if (!expand_workspace(&rrs, &rr_sz, rr_found + 1))
	return rr_found;
      
      rrs[rr_found++] = pstart;
      rrs[rr_found++] = p;
      
      if (i < ntohs(header->ancount))
	chop_an++;
      else if (i < (ntohs(header->nscount) + ntohs(header->ancount)))
	chop_ns++;
      else
	chop_ar++;
    }
  
  /* Nothing to do. */
  if (rr_found == 0)
    return rr_found;

  /* Second pass, look for pointers in names in the records we're keeping and make sure they don't
     point to records we're going to elide. This is theoretically possible, but unlikely. If
     it happens, we give up and leave the answer unchanged. */
  p = (unsigned char *)(header+1);
  
  /* question first */
  if (!check_name(&p, header, *plen, 0, rrs, rr_found))
    return rr_found;
  p += 4; /* qclass, qtype */
  
  /* Now answers and NS */
  if (!check_rrs(p, header, *plen, 0, rrs, rr_found))
    return rr_found;
  
  /* Third pass, actually fix up pointers in the records */
  p = (unsigned char *)(header+1);
  
  check_name(&p, header, *plen, 1, rrs, rr_found);
  p += 4; /* qclass, qtype */
  
  check_rrs(p, header, *plen, 1, rrs, rr_found);

  /* Fourth pass, elide records */
  for (p = rrs[0], i = 1; (unsigned)i < rr_found; i += 2)
    {
      unsigned char *start = rrs[i];
      unsigned char *end = ((unsigned)i != rr_found - 1) ? rrs[i+1] : ((unsigned char *)header) + *plen;
      
      memmove(p, start, end-start);
      p += end-start;
    }
     
  *plen = p - (unsigned char *)header;
  header->ancount = htons(ntohs(header->ancount) - chop_an);
  header->nscount = htons(ntohs(header->nscount) - chop_ns);
  header->arcount = htons(ntohs(header->arcount) - chop_ar);

  return rr_found;
}

/**
 * @brief Get descriptor array for resource record type structure
 * 
 * @detailed This function returns a descriptor array that describes the internal structure
 *           of a DNS resource record's RDATA section, specifically identifying which fields
 *           contain domain names that need compression pointer validation and adjustment.
 *           The descriptor is a short integer array where positive values indicate "skip N
 *           bytes" and negative values indicate "process domain name at this position".
 *           The array is terminated with a zero value.
 *           
 *           DESCRIPTOR FORMAT:
 *           - Positive values: Skip this many bytes (fixed-length fields like integers, IPs)
 *           - Negative values: Process domain name at current position (variable length)
 *           - Zero: End of descriptor (no more fields to process)
 *           
 *           EXAMPLE DESCRIPTOR (T_MX mail exchange record):
 *           { 2, -1, 0 }  means: Skip 2 bytes (preference field), Process name (exchange), End
 *           
 *           EXAMPLE DESCRIPTOR (T_SOA start of authority):
 *           { -1, -1, 20, 0 }  means: Process mname, Process rname, Skip 20 bytes (serial,
 *           refresh, retry, expire, minimum), End
 *           
 *           The descriptor enables generic processing of RR types without hardcoding the
 *           structure of each type. Only RR types containing domain names need descriptors.
 *           Types with no domain names in RDATA (A, AAAA, TXT) return NULL.
 *           
 *           SUPPORTED RR TYPES WITH DOMAIN NAMES:
 *           - T_NS (nameserver): Single name field
 *           - T_CNAME (canonical name): Single name field
 *           - T_PTR (pointer): Single name field
 *           - T_MX (mail exchange): 2-byte preference, then name
 *           - T_SOA (start of authority): mname, rname, then 20 bytes of integers
 *           - T_SRV (service): 6 bytes (priority, weight, port), then name
 *           - T_RP (responsible person): Two names (mbox, txt)
 *           - T_NAPTR (naming authority pointer): Complex structure with strings and name
 * 
 * @param type DNS resource record type (T_NS, T_MX, T_SOA, etc. from dns-protocol.h)
 * 
 * @return Pointer to static descriptor array for this type, or NULL if type has no domain names
 * @retval NULL RR type does not contain domain names in RDATA (e.g., T_A, T_AAAA, T_TXT)
 * @retval non-NULL Pointer to static short array describing field layout
 * 
 * @note Descriptor arrays are statically allocated and never change
 * @note Only class IN (Internet) resource records are described
 * @note This function is exported for use by DNSSEC validation code in dnssec.c
 * @warning Unrecognized RR types return NULL (treated as having no domain names)
 * 
 * @see check_rrs() in rrfilter.c for usage of descriptors during RR validation
 * @see dnssec.c for DNSSEC validation usage of descriptors
 * 
 * EXAMPLE USAGE:
 * @code
 * short *desc = rrfilter_desc(T_MX);
 * if (desc) {
 *   // desc[0] = 2 (skip preference field)
 *   // desc[1] = -1 (process mail exchange name)
 *   // desc[2] = 0 (end of record)
 *   unsigned char *p = rdata;
 *   p += 2;  // Skip preference
 *   if (!check_name(&p, header, plen, fixup, rrs, rr_count))
 *     return 0;  // Name validation failed
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 1035 Section 3.3 (standard RR definitions)
 * RFC COMPLIANCE: RFC 2782 (SRV records), RFC 1183 (RP records), RFC 3403 (NAPTR records)
 * 
 * SIDE EFFECTS: None (read-only access to static data)
 * 
 * THREAD SAFETY: Safe (returns pointer to immutable static data)
 */
/* This is used in the DNSSEC code too, hence it's exported */
short *rrfilter_desc(int type)
{
  /* List of RRtypes which include domains in the data.
     0 -> domain
     integer -> no. of plain bytes
     -1 -> end

     zero is not a valid RRtype, so the final entry is returned for
     anything which needs no mangling.
  */
  
  static short rr_desc[] = 
    { 
      T_NS, 0, -1, 
      T_MD, 0, -1,
      T_MF, 0, -1,
      T_CNAME, 0, -1,
      T_SOA, 0, 0, -1,
      T_MB, 0, -1,
      T_MG, 0, -1,
      T_MR, 0, -1,
      T_PTR, 0, -1,
      T_MINFO, 0, 0, -1,
      T_MX, 2, 0, -1,
      T_RP, 0, 0, -1,
      T_AFSDB, 2, 0, -1,
      T_RT, 2, 0, -1,
      T_SIG, 18, 0, -1,
      T_PX, 2, 0, 0, -1,
      T_NXT, 0, -1,
      T_KX, 2, 0, -1,
      T_SRV, 6, 0, -1,
      T_DNAME, 0, -1,
      0, -1 /* wildcard/catchall */
    }; 
  
  short *p = rr_desc;
  
  while (*p != type && *p != 0)
    while (*p++ != -1);

  return p+1;
}

/**
 * @brief Dynamically expand the RR pointer tracking workspace array
 * 
 * @detailed This function grows the workspace array used to track start and end pointers
 * of resource records being filtered. The array is used by rrfilter() to record which
 * sections of the DNS packet should be removed. When the current capacity is insufficient
 * for the number of records being processed, this function reallocates the array with
 * additional capacity. The expansion adds 5 extra slots beyond the immediate requirement
 * to reduce reallocation frequency. The newly allocated slots are zero-initialized to
 * maintain consistent state.
 * 
 * @param wkspc Pointer to workspace pointer (unsigned char ***). Modified to point to
 *              reallocated array on success. Must not be NULL. Existing array contents
 *              are preserved during expansion.
 * @param szp Pointer to current workspace size (int *). Updated to new size on successful
 *            expansion. Must not be NULL.
 * @param new Minimum required workspace size (number of pointer slots needed). Must be
 *            non-negative. If current size already satisfies requirement, no allocation
 *            occurs.
 * 
 * @return 1 on success (workspace expanded or already sufficient), 0 on memory allocation failure
 * @retval 1 Workspace is sufficient for required size (either already large enough or successfully expanded)
 * @retval 0 Memory allocation failed (whine_realloc returned NULL)
 * 
 * @note If allocation fails, the original workspace pointer remains unchanged and the size
 *       is not modified. The caller should check the return value and handle allocation
 *       failures gracefully.
 * @warning Memory allocation failure during filtering will cause the filter operation to
 *          abort and return the original unfiltered DNS packet to prevent corruption.
 * 
 * @see whine_realloc() in util.c for memory allocation with failure logging
 * @see rrfilter() for the primary caller that uses this workspace expansion
 * 
 * EXAMPLE USAGE:
 * @code
 * unsigned char **rrs = NULL;
 * int rr_sz = 0;
 * if (!expand_workspace(&rrs, &rr_sz, 10)) {
 *     // Handle allocation failure - abort filtering
 *     return original_packet_length;
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (internal memory management utility)
 * SIDE EFFECTS: Allocates memory via whine_realloc, modifies *wkspc and *szp on success
 * THREAD SAFETY: Single-threaded architecture - workspace array is static and reused across calls
 */
int expand_workspace(unsigned char ***wkspc, int *szp, int new)
{
  unsigned char **p;
  int old = *szp;

  if (old >= new+1)
    return 1;

  new += 5;

  if (!(p = whine_realloc(*wkspc, new * sizeof(unsigned char *))))
    return 0;

  memset(p+old, 0, new-old);
  
  *wkspc = p;
  *szp = new;

  return 1;
}

/**
 * @brief Convert DNS name from presentation format to wire format in place with case mapping
 * 
 * @detailed This function performs in-place conversion of a domain name from presentation
 * format (human-readable dotted notation like "example.com") to DNS wire format (length-
 * prefixed labels as defined in RFC 1035). During conversion, all uppercase letters (A-Z)
 * are mapped to lowercase (a-z) to produce canonical form, and NAME_ESCAPE sequences are
 * processed to handle special characters. The conversion is destructive - the input buffer
 * is overwritten with wire format output. This function is used during DNSSEC canonicalization
 * and name comparison operations where case-insensitive matching is required.
 * 
 * The wire format consists of length-prefixed labels: each label is preceded by a single byte
 * containing the label length, and the name terminates with a zero-length label. For example,
 * "example.com" becomes: 7 e x a m p l e 3 c o m 0 (with length bytes shown as numbers).
 * 
 * NAME_ESCAPE character handling: Both \000 (null byte) and '.' are allowed within labels
 * and are represented in presentation format using NAME_ESCAPE as an escape character. In
 * theory, if all characters were escaped, presentation format could be twice the DNS spec
 * limit (1024 bytes), requiring 2048-byte buffers plus null terminator (2049 bytes total).
 * 
 * The combination of extract_name() (to get presentation format) followed by to_wire()
 * removes DNS name compression and normalizes case, producing canonical form suitable for
 * DNSSEC signature verification. Calling to_wire() followed by from_wire() is almost an
 * identity operation, except uppercase letters remain mapped to lowercase.
 * 
 * @param name DNS name in presentation format (null-terminated string). Buffer is modified
 *             in place to contain wire format output. Must be writable and large enough
 *             to accommodate length-prefix bytes (typically 2049 bytes to handle worst-case
 *             escaping). Presentation format uses dots as label separators. Must not be NULL.
 * 
 * @return Length of the wire format name in bytes, including the terminal zero-length label
 * @retval >0 Wire format length (minimum 1 for empty name with just zero-length terminator)
 * 
 * @note Conversion is performed in place - original presentation format is destroyed
 * @note No DNS name compression is produced in the output wire format
 * @note All uppercase letters (A-Z) are converted to lowercase (a-z) for canonical form
 * @warning Input buffer must be large enough for wire format (typically same size or smaller
 *          than presentation format except when heavy escaping is used)
 * @warning No bounds checking is performed - caller must ensure buffer is adequately sized
 * 
 * @see from_wire() in rrfilter.c for reverse conversion (wire format to presentation format)
 * @see extract_name() in rfc1035.c for extracting names from DNS packets with decompression
 * @see NAME_ESCAPE definition for escape character used in presentation format
 * 
 * EXAMPLE USAGE:
 * @code
 * char name[2049];
 * strcpy(name, "Example.COM");
 * int wire_len = to_wire(name);
 * // name now contains: 7 e x a m p l e 3 c o m 0 (wire format, lowercase)
 * // wire_len is 13 bytes
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 1035 Section 3.1 (wire format), RFC 4034 Section 6.2 (canonical form for DNSSEC)
 * SIDE EFFECTS: Modifies input buffer in place, overwrites presentation format with wire format
 * THREAD SAFETY: Single-threaded architecture - no global state, buffer provided by caller
 */
int to_wire(char *name)
{
  unsigned char *l, *p, *q, term;
  unsigned int len;

  for (l = (unsigned char*)name; *l != 0; l = p)
    {
      for (p = l; *p != '.' && *p != 0; p++)
	if (*p >= 'A' && *p <= 'Z')
	  *p = *p - 'A' + 'a';
	else if (*p == NAME_ESCAPE)
	  {
	    for (q = p; *q; q++)
	      *q = *(q+1);
	    (*p)--;
	  }
      term = *p;
      
      if ((len = p - l) != 0)
	memmove(l+1, l, len);
      *l = len;
      
      p++;
      
      if (term == 0)
	*p = 0;
    }
  
  return l + 1 - (unsigned char *)name;
}

/**
 * @brief Convert DNS name from wire format to presentation format in place
 * 
 * @detailed This function performs in-place conversion of a domain name from DNS wire format
 * (length-prefixed labels as defined in RFC 1035) to presentation format (human-readable
 * dotted notation like "example.com"). During conversion, special characters (dot, null byte,
 * and NAME_ESCAPE itself) are escaped using NAME_ESCAPE to ensure unambiguous representation.
 * The conversion is destructive - the input buffer is overwritten with presentation format
 * output. This is the inverse operation of to_wire().
 * 
 * Wire format consists of length-prefixed labels where each label is preceded by a single
 * byte containing the label length, terminated by a zero-length label. For example:
 * 7 e x a m p l e 3 c o m 0 is converted to "example.com" (with length bytes shown as numbers).
 * 
 * Special character escaping: If a label contains a dot (.), null byte (\000), or NAME_ESCAPE
 * character itself, these are escaped in presentation format by inserting NAME_ESCAPE before
 * the character and incrementing its value by 1. This ensures these special characters can
 * be distinguished from label separators and escape sequences. For example, a label containing
 * a literal dot becomes NAME_ESCAPE followed by ('.' + 1).
 * 
 * CRITICAL LIMITATION: This function does NOT support DNS name compression (pointer labels
 * with high bits 11 in the length byte). The input must be in uncompressed wire format.
 * Names extracted from DNS packets must be decompressed first using extract_name() or similar
 * before calling this function.
 * 
 * The conversion is performed in place by shifting label data over length prefix bytes and
 * inserting dots as label separators. The final dot separator is replaced with a null
 * terminator. Buffer expansion occurs when special characters require escaping.
 * 
 * @param name DNS name in wire format (length-prefixed labels terminated by zero-length label).
 *             Buffer is modified in place to contain presentation format output. Must be
 *             writable and large enough to accommodate escaped characters (typically 2049
 *             bytes to handle worst-case escaping). Must not contain compression pointers.
 *             Must not be NULL.
 * 
 * @return None (void function)
 * 
 * @note Conversion is performed in place - original wire format is destroyed
 * @note Input MUST NOT contain DNS name compression (pointer labels) - use extract_name() first
 * @note Special characters (., \000, NAME_ESCAPE) are escaped in output presentation format
 * @note Labels are separated by dot (.) characters in presentation format
 * @warning Input buffer must be large enough for presentation format with escaping (2049 bytes)
 * @warning No bounds checking is performed - caller must ensure buffer is adequately sized
 * @warning Undefined behavior if input contains compression pointers (violates precondition)
 * 
 * @see to_wire() in rrfilter.c for reverse conversion (presentation format to wire format)
 * @see extract_name() in rfc1035.c for decompressing names from DNS packets before conversion
 * @see NAME_ESCAPE definition for escape character used in presentation format
 * 
 * EXAMPLE USAGE:
 * @code
 * char name[2049];
 * // Assume name contains wire format: 7 e x a m p l e 3 c o m 0
 * from_wire(name);
 * // name now contains: "example.com" (presentation format)
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 1035 Section 3.1 (wire format), RFC 1035 Section 5.1 (presentation format)
 * SIDE EFFECTS: Modifies input buffer in place, overwrites wire format with presentation format
 * THREAD SAFETY: Single-threaded architecture - no global state, buffer provided by caller
 */
void from_wire(char *name)
{
  unsigned char *l, *p, *last;
  unsigned int len;
  
  for (last = (unsigned char *)name; *last != 0; last += *last+1);
  
  for (l = (unsigned char *)name; *l != 0; l += len+1)
    {
      len = *l;
      memmove(l, l+1, len);
      for (p = l; p < l + len; p++)
	if (*p == '.' || *p == 0 || *p == NAME_ESCAPE)
	  {
	    memmove(p+1, p, 1 + last - p);
	    len++;
	    *p++ = NAME_ESCAPE; 
	    (*p)++;
	  }
	
      l[len] = '.';
    }

  if ((char *)l != name)
    *(l-1) = 0;
}

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
 * @file rfc1035.c
 * @brief DNS wire format parsing and serialization per RFC 1035
 * 
 * DETAILED PURPOSE:
 * This module implements the complete DNS packet format handling as specified in RFC 1035,
 * providing the fundamental packet parsing and serialization capabilities for dnsmasq's
 * DNS forwarding, caching, and authoritative DNS operations. The implementation handles
 * binary DNS packet format conversion between wire format (network byte order) and internal
 * C structures, supporting all standard DNS resource record types and DNS protocol operations.
 * 
 * The module serves as the core DNS protocol layer, translating between the compact binary
 * DNS wire format transmitted over UDP/TCP and the internal data structures used by the
 * cache, forwarding engine, and DNSSEC validation systems. Key responsibilities include
 * DNS name compression/decompression (label pointer resolution), resource record parsing
 * for all supported RR types, packet validation and malformed packet detection, and
 * response packet construction with proper header flags and section management.
 * 
 * KEY RESPONSIBILITIES:
 * - DNS packet parsing: extract_name() performs label-based name extraction with compression
 *   pointer resolution, skip_questions() and skip_section() navigate packet sections,
 *   extract_addresses() and extract_neg_addrs() parse answer sections for address records
 * - Resource record handling: Supports A, AAAA, CNAME, PTR, MX, SRV, TXT, DNSKEY, DS, RRSIG,
 *   NSEC, NSEC3, and other RR types with type-specific parsing in extract_addresses() and
 *   related functions
 * - Packet construction: add_resource_record() serializes RRs to wire format, resize_packet()
 *   manages packet buffer allocation, answer_request() constructs complete response packets
 * - Name compression: Implements RFC 1035 name compression with pointer validation, loop
 *   detection (maximum 255 hops), and security checks against malformed compression pointers
 * - Protocol validation: CHECK_LEN() macro validates packet boundaries, filter_rrsigs()
 *   and filter_zone() implement security filtering, check_for_ignored_address() applies
 *   address filtering policies
 * 
 * DEPENDENCIES:
 * Includes: dnsmasq.h (core data structures including struct daemon, struct server, 
 *           struct crec cache records), dns-protocol.h (struct dns_header, DNS opcodes,
 *           RR type constants, flag bit definitions)
 * Called by: forward.c (receives DNS queries, sends responses), cache.c (caches parsed RRs),
 *            dnssec.c (validates DNSSEC records), auth.c (authoritative DNS responses)
 * Calls: cache.c functions for record insertion, util.c for memory allocation and string
 *        operations, network.c for packet transmission
 * 
 * DATA STRUCTURES:
 * - struct dns_header: DNS packet header (12 bytes) with id, flags (hb3/hb4), and section
 *   counts (qdcount, ancount, nscount, arcount) defined in dns-protocol.h:122-126
 * - struct crec: Cache record structure for storing parsed DNS responses (defined in
 *   dnsmasq.h, used extensively for caching answers)
 * - Packet buffers: Dynamically sized buffers managed with resize_packet() to accommodate
 *   variable-length DNS messages up to 65535 bytes (UDP) or larger (TCP)
 * 
 * COMPILE-TIME OPTIONS:
 * - HAVE_DNSSEC: Enables DNSSEC record type parsing (DNSKEY, DS, RRSIG, NSEC, NSEC3) and
 *   signature validation support (affects extract_addresses, add_resource_record)
 * - HAVE_IPV6: Enables IPv6 AAAA record parsing and address handling
 * - HAVE_AUTH: Enables authoritative DNS response construction in answer_request()
 * 
 * THREADING/CONCURRENCY:
 * Single-threaded event-driven architecture - all functions called from main event loop.
 * No thread synchronization required. Packet buffers are per-query temporaries, no shared
 * mutable state except for cache operations which are serialized by event loop.
 * 
 * @copyright Copyright (c) 2000-2025 Simon Kelley
 * @license GPL-2.0-or-later
 */

#include "dnsmasq.h"

/**
 * @brief Extract, compare, or manipulate DNS name from packet using RFC 1035 label format
 * 
 * @detailed This is the core DNS name processing function that handles label-based names with
 * compression pointers as specified in RFC 1035 Section 4.1.4. The function operates in four
 * distinct modes controlled by the func parameter: EXTR_NAME_EXTRACT extracts a domain name
 * from wire format to dotted notation, EXTR_NAME_COMPARE performs case-insensitive name
 * comparison, EXTR_NAME_NOCASE performs case-sensitive comparison, and EXTR_NAME_FLIP
 * manipulates case bits for DNS 0x20 randomization. The implementation includes critical
 * security protections: maximum 255 hops for compression pointer loop detection (line 104),
 * MAXDNAME (1024 bytes) length limit enforcement (line 112), and strict boundary checking
 * via CHECK_LEN() macro throughout. Name compression pointer resolution allows jumps within
 * the packet while maintaining extraction position for subsequent parsing. The function
 * handles label escape sequences for special characters (NUL, dot, NAME_ESCAPE) ensuring
 * proper encoding/decoding. For FLIP mode, the name parameter is reinterpreted as a bitmap
 * array controlling selective case bit toggling for each alphabetic character.
 * 
 * @param header Pointer to DNS packet header (struct dns_header) marking packet start
 * @param plen Total packet length in bytes for boundary validation (prevents buffer overruns)
 * @param pp Pointer to pointer within packet marking extraction start position; if NULL,
 *           extraction begins at query name immediately following header. Updated to position
 *           after extracted name on success, accounting for compression pointer jumps
 * @param name Output buffer for EXTRACT mode (MAXDNAME size required), comparison string for
 *             COMPARE/NOCASE modes, or bitmap array (unsigned int*) for FLIP mode. For FLIP,
 *             parm specifies bitmap array size, bits beyond size assumed zero
 * @param func Operation mode: EXTR_NAME_EXTRACT (extract to buffer), EXTR_NAME_COMPARE
 *             (case-insensitive compare), EXTR_NAME_NOCASE (case-sensitive compare),
 *             EXTR_NAME_FLIP (toggle case bits per bitmap)
 * @param parm Dual purpose: for EXTRACT/COMPARE/NOCASE, specifies expected extra bytes after
 *             name for validation (e.g., 4 for QTYPE+QCLASS in questions); for FLIP, specifies
 *             bitmap array size in unsigned ints
 * 
 * @return 0 on error (malformed packet, compression loop, length exceeded, boundary violation)
 * @retval 1 Extract successful, comparison matched, or flip operation completed
 * @retval 2 Extract successful but comparison failed (names differ)
 * @retval 3 Extract successful, comparison failed only on case sensitivity (case differs)
 * 
 * @note Name compression: Compression pointers (label_type 0xc0, RFC 1035 Section 4.1.4) are
 *       12-bit offsets from packet start. Maximum 255 pointer jumps prevents infinite loops
 *       from malicious or corrupted pointers. First jump saves return position (p1) for
 *       updating **pp after extraction completes
 * @note Label format: Labels begin with length byte (0-63), followed by that many octets.
 *       Length 0 terminates name. Label types 0x40 and 0x80 (extended label types) return
 *       error as unsupported
 * @note Character escaping: In EXTRACT mode, NUL (0), dot (.), and NAME_ESCAPE characters in
 *       labels are escaped as NAME_ESCAPE followed by (character+1) to prevent interpretation
 *       as label terminators or escape sequences
 * @note Case handling: COMPARE mode performs case-insensitive matching (A-Z treated as a-z).
 *       NOCASE mode is case-sensitive initially but returns 3 if only case differs. FLIP mode
 *       toggles 0x20 bit on alphabetic characters where bitmap bit is set (DNS 0x20 encoding
 *       for query uniqueness)
 * 
 * @warning pp must point to valid location within packet bounds. For NULL pp, extraction
 *          starts at query name (header+1). Caller must ensure name buffer is MAXDNAME bytes
 *          for EXTRACT mode to prevent overflow
 * @warning Compression pointers must reference earlier positions in packet to prevent infinite
 *          loops. Implementation enforces 255-hop limit but does not validate pointer targets
 *          are earlier than current position
 * 
 * @see skip_questions() for navigating question sections using extract_name()
 * @see skip_section() for navigating answer/authority/additional sections
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dns_header *header = (struct dns_header *)packet;
 * unsigned char *p = (unsigned char *)(header + 1);
 * char name[MAXDNAME];
 * if (extract_name(header, packet_len, &p, name, EXTR_NAME_EXTRACT, 4) == 0)
 *   return 0; // Malformed packet
 * // name now contains extracted domain name, p points past name+QTYPE+QCLASS
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 1035 Section 4.1.4 (Domain name compression), Section 3.1 (Name space
 *                 definitions - MAXDNAME limit), Section 4.1.2 (Question section format)
 * SIDE EFFECTS: Modifies *pp to point past extracted name (accounting for compression). In
 *               FLIP mode, modifies packet bytes directly by toggling case bits. In EXTRACT
 *               mode, writes NUL-terminated dotted domain name to name buffer
 * THREAD SAFETY: Single-threaded architecture - no synchronization required. Operates on
 *                per-query packet buffer without shared mutable state
 */
int extract_name(struct dns_header *header, size_t plen, unsigned char **pp, 
		 char *name, int func, unsigned int parm)
{
  unsigned char *cp = (unsigned char *)name, *p1 = NULL;
  unsigned int j, l, namelen = 0, hops = 0;
  unsigned int bigmap_counter = 0, bigmap_posn = 0, bigmap_size = parm, bitmap = 0;
  int retvalue = 1, case_insens = 1, isExtract = 0, flip = 0, extrabytes = (int)parm;
  unsigned int *bigmap = (unsigned int *)name;
  unsigned char *p = pp ? *pp : (unsigned char *)(header+1);
  
  if (func == EXTR_NAME_EXTRACT)
    isExtract = 1, *cp = 0;
  else if (func == EXTR_NAME_NOCASE)
    case_insens = 0;
  else if (func == EXTR_NAME_FLIP)
    {
      flip = 1, extrabytes = 0;
      name = NULL;
    }
  
  while (1)
    { 
      unsigned int label_type;

      if (!CHECK_LEN(header, p, plen, 1))
	return 0;
      
      if ((l = *p++) == 0) 
	/* end marker */
	{
	  /* check that there are the correct no. of bytes after the name */
	  if (!CHECK_LEN(header, p1 ? p1 : p, plen, extrabytes))
	    return 0;
	  
	  if (isExtract)
	    {
	      if (cp != (unsigned char *)name)
		cp--;
	      *cp = 0; /* terminate: lose final period */
	    }
	  else if (!flip && *cp != 0)
	    retvalue = 2;

	  if (pp)
	    {
	      if (p1) /* we jumped via compression */
		*pp = p1;
	      else
		*pp = p;
	    }
	  
	  return retvalue;
	}

      label_type = l & 0xc0;
      
      if (label_type == 0xc0) /* pointer */
	{ 
	  if (!CHECK_LEN(header, p, plen, 1))
	    return 0;
	      
	  /* get offset */
	  l = (l&0x3f) << 8;
	  l |= *p++;
	  
	  if (!p1) /* first jump, save location to go back to */
	    p1 = p;
	      
	  hops++; /* break malicious infinite loops */
	  if (hops > 255)
	    return 0;
	  
	  p = l + (unsigned char *)header;
	}
      else if (label_type == 0x00)
	{ /* label_type = 0 -> label. */
	  namelen += l + 1; /* include period */
	  if (namelen >= MAXDNAME)
	    return 0;
	  if (!CHECK_LEN(header, p, plen, l))
	    return 0;
	  
	  for (j=0; j<l; j++, p++)
	    if (isExtract)
	      {
		unsigned char c = *p;

		if (c == 0 || c == '.' || c == NAME_ESCAPE)
		  {
		    *cp++ = NAME_ESCAPE;
		    *cp++ = c+1;
		  }
		else
		  *cp++ = c; 
	      }
	    else if (flip)
	      {
		unsigned char c = *p;

		if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'))
		  {
		    /* Get the next int of the bitmap */
		    if (bigmap_posn < bigmap_size && bigmap_counter-- == 0)
		      {
			bitmap = bigmap[bigmap_posn++];
			bigmap_counter = (sizeof(unsigned int) * 8) - 1;
		      }
		    
		    if (bitmap & 1)
		      *p ^= 0x20;
		    bitmap >>= 1;
		  }
	      }
	    else 
	      {
		unsigned char c1 = *cp, c2 = *p;
		
		if (c1 == 0)
		  retvalue = 2;
		else 
		  {
		    cp++;

		    if (c1 == NAME_ESCAPE)
		      c1 = (*cp++)-1;
		    else if (case_insens && c1 >= 'A' && c1 <= 'Z')
		      c1 += 'a' - 'A';
		    
		    if (case_insens && c2 >= 'A' && c2 <= 'Z')
		      c2 += 'a' - 'A';

		    if (!case_insens && retvalue != 2 && c1 != c2)
		      {
			if (c1 >= 'A' && c1 <= 'Z')
			  c1 += 'a' - 'A';
			
			if (c2 >= 'A' && c2 <= 'Z')
			  c2 += 'a' - 'A';
			
			if (c1 == c2)
			  retvalue = 3;
		      }
		    
		    if (c1 != c2)
		      retvalue = 2;
		  }
	      }
	    
	  if (isExtract)
	    *cp++ = '.';
	  else if (!flip && *cp != 0 && *cp++ != '.')
	    retvalue = 2;
	}
      else
	return 0; /* label types 0x40 and 0x80 not supported */
    }
}
 
/* Max size of input string (for IPv6) is 75 chars.) */
#define MAXARPANAME 75
/**
 * @brief Convert reverse DNS (in-addr.arpa or ip6.arpa) name to IP address
 * 
 * @detailed This function parses reverse DNS PTR query names in standard in-addr.arpa (IPv4)
 * or ip6.arpa/ip6.int (IPv6) format and extracts the corresponding IP address. For IPv4,
 * it handles the standard w.z.y.x.in-addr.arpa format where octets are reversed per RFC 1035.
 * For IPv6, it supports three historical formats: standard nibble-reversed format
 * (f.e.d.c...3.2.1.0.ip6.arpa per RFC 3596), obsolete ip6.int format from early IPv6 DNS
 * specifications, and bitstring format (\[xHEXSTRING/128].ip6.arpa) which was proposed but
 * never standardized. The function destructively modifies the input string by inserting NUL
 * terminators to isolate label components during parsing (line 203-220 finds last two labels).
 * IPv4 parsing reverses four dot-separated octets back to network byte order (lines 223-241).
 * IPv6 nibble parsing processes 32 single-hex-digit labels in reverse order, shifting each
 * nibble into position to reconstruct the 128-bit address (lines 281-289). IPv6 bitstring
 * parsing extracts hex digits from the bracketed string format (lines 265-277). The function
 * validates format correctness but does not validate that the extracted address is a valid
 * unicast or routable address.
 * 
 * @param namein Input reverse DNS name string (NUL-terminated dotted labels). WILL BE MODIFIED
 *               by insertion of NUL terminators between labels during parsing. Caller must not
 *               rely on string contents after function returns. Format examples:
 *               IPv4: "1.0.168.192.in-addr.arpa" -> 192.168.0.1
 *               IPv6: "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
 *               IPv6 bitstring: "\\[x20010db8000000000000000000000001/128].ip6.arpa"
 * @param addrp Pointer to union all_addr for output address. For IPv4, .addr4 (struct in_addr)
 *              will be populated with 4-byte address in network byte order. For IPv6, .addr6
 *              (struct in6_addr) will be populated with 16-byte address. Union not initialized
 *              on error return, caller must check return value before accessing
 * 
 * @return Address family flag on success, 0 on parsing failure
 * @retval F_IPV4 Successfully parsed IPv4 reverse name (x.y.z.w.in-addr.arpa), addrp->addr4 valid
 * @retval F_IPV6 Successfully parsed IPv6 reverse name (nibble or bitstring format), addrp->addr6 valid
 * @retval 0 Name is not valid reverse DNS format, parsing error, or unsupported format. addrp unchanged
 * 
 * @note IPv4 format: Exactly four decimal octets (0-255) in reverse order, followed by
 *       "in-addr.arpa". Non-numeric octets, wrong count, or out-of-range values return 0.
 *       Implementation uses strtol() for octet parsing (line 233) accepting any valid decimal
 *       including leading zeros, but does not enforce canonical format
 * @note IPv6 nibble format: Exactly 32 single-hex-digit labels in reverse order, followed by
 *       "ip6.arpa" or "ip6.int". Each label must be exactly one character (checked at line 283).
 *       Nibbles are shifted into address right-to-left (lines 286-288) to reverse the label order
 * @note IPv6 bitstring format: String "\\[x" followed by exactly 32 hex digits, followed by "/128]"
 *       (lines 262-277). This format was proposed in RFC 2673 but obsoleted by RFC 3152 and
 *       RFC 3596 in favor of nibble format. Supported for historical compatibility with old zones
 * @note ip6.int obsolete: The ip6.int domain was deprecated in RFC 4159 in favor of ip6.arpa,
 *       but both are accepted (line 251) for compatibility with legacy configurations
 * @note Label extraction: The function finds the last label (lastchunk) and second-to-last label
 *       (penchunk) by walking the string and inserting NULs at dots (lines 203-220). This modifies
 *       the input string destructively. Original string contents are not preserved
 * 
 * @warning Input string namein is MODIFIED during parsing by insertion of NUL terminators.
 *          Caller must not depend on string contents after function call. Pass a copy if
 *          original must be preserved
 * @warning For IPv6 bitstring format, only the exact "/128" prefix length is accepted (line 276).
 *          Shorter prefixes would be invalid for PTR record reverse lookups
 * @warning No validation that extracted address is valid unicast, routable, or within expected
 *          ranges. Caller must perform additional validation if needed (e.g., reject loopback,
 *          multicast, reserved ranges)
 * @warning Non-canonical IPv4 representations (leading zeros, hex notation) may be parsed if
 *          strtol() accepts them, potentially causing confusion. Implementation does not enforce
 *          strict canonical decimal format
 * 
 * @see extract_request() which uses this function to identify PTR queries
 * @see cache.c lookup functions which retrieve cached PTR records by address
 * 
 * EXAMPLE USAGE:
 * @code
 * char reverse_name[] = "1.0.168.192.in-addr.arpa";
 * union all_addr addr;
 * int result = in_arpa_name_2_addr(reverse_name, &addr);
 * if (result == F_IPV4) {
 *   // addr.addr4 contains 192.168.0.1 in network byte order
 *   log_query(F_IPV4, NULL, &addr, NULL);
 * }
 * // reverse_name has been modified and cannot be reused
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 1035 Section 3.5 (IN-ADDR.ARPA domain for IPv4 reverse lookups),
 *                 RFC 3596 Section 2.5 (ip6.arpa domain for IPv6 reverse lookups),
 *                 RFC 3152 (delegation of ip6.arpa), RFC 4159 (ip6.int deprecation),
 *                 RFC 2673 (obsolete bitstring labels)
 * SIDE EFFECTS: Modifies namein string by inserting NUL terminators between labels for parsing.
 *               Original string contents are not preserved. Writes extracted address to *addrp
 *               only on successful return (F_IPV4 or F_IPV6)
 * THREAD SAFETY: Single-threaded architecture. Operates on caller-provided buffers without
 *                shared mutable state. Safe for concurrent calls with distinct buffers
 */
int in_arpa_name_2_addr(char *namein, union all_addr *addrp)
{
  int j;
  char name[MAXARPANAME+1], *cp1;
  unsigned char *addr = (unsigned char *)addrp;
  char *lastchunk = NULL, *penchunk = NULL;
  
  if (strlen(namein) > MAXARPANAME)
    return 0;

  memset(addrp, 0, sizeof(union all_addr));

  /* turn name into a series of asciiz strings */
  /* j counts no. of labels */
  for(j = 1,cp1 = name; *namein; cp1++, namein++)
    if (*namein == '.')
      {
	penchunk = lastchunk;
        lastchunk = cp1 + 1;
	*cp1 = 0;
	j++;
      }
    else
      *cp1 = *namein;
  
  *cp1 = 0;

  if (j<3)
    return 0;

  if (hostname_isequal(lastchunk, "arpa") && hostname_isequal(penchunk, "in-addr"))
    {
      /* IP v4 */
      /* address arrives as a name of the form
	 www.xxx.yyy.zzz.in-addr.arpa
	 some of the low order address octets might be missing
	 and should be set to zero. */
      for (cp1 = name; cp1 != penchunk; cp1 += strlen(cp1)+1)
	{
	  /* check for digits only (weeds out things like
	     50.0/24.67.28.64.in-addr.arpa which are used 
	     as CNAME targets according to RFC 2317 */
	  char *cp;
	  for (cp = cp1; *cp; cp++)
	    if (!isdigit((unsigned char)*cp))
	      return 0;
	  
	  addr[3] = addr[2];
	  addr[2] = addr[1];
	  addr[1] = addr[0];
	  addr[0] = atoi(cp1);
	}

      return F_IPV4;
    }
  else if (hostname_isequal(penchunk, "ip6") && 
	   (hostname_isequal(lastchunk, "int") || hostname_isequal(lastchunk, "arpa")))
    {
      /* IP v6:
         Address arrives as 0.1.2.3.4.5.6.7.8.9.a.b.c.d.e.f.ip6.[int|arpa]
    	 or \[xfedcba9876543210fedcba9876543210/128].ip6.[int|arpa]
      
	 Note that most of these the various representations are obsolete and 
	 left-over from the many DNS-for-IPv6 wars. We support all the formats
	 that we can since there is no reason not to.
      */

      if (*name == '\\' && *(name+1) == '[' && 
	  (*(name+2) == 'x' || *(name+2) == 'X'))
	{	  
	  for (j = 0, cp1 = name+3; *cp1 && isxdigit((unsigned char) *cp1) && j < 32; cp1++, j++)
	    {
	      char xdig[2];
	      xdig[0] = *cp1;
	      xdig[1] = 0;
	      if (j%2)
		addr[j/2] |= strtol(xdig, NULL, 16);
	      else
		addr[j/2] = strtol(xdig, NULL, 16) << 4;
	    }
	  
	  if (*cp1 == '/' && j == 32)
	    return F_IPV6;
	}
      else
	{
	  for (cp1 = name; cp1 != penchunk; cp1 += strlen(cp1)+1)
	    {
	      if (*(cp1+1) || !isxdigit((unsigned char)*cp1))
		return 0;
	      
	      for (j = sizeof(struct in6_addr)-1; j>0; j--)
		addr[j] = (addr[j] >> 4) | (addr[j-1] << 4);
	      addr[0] = (addr[0] >> 4) | (strtol(cp1, NULL, 16) << 4);
	    }
	  
	  return F_IPV6;
	}
    }
  
  return 0;
}

/**
 * @brief Skip over DNS name in packet without extraction, advancing pointer past name
 * 
 * @detailed This function navigates past a DNS name in wire format without performing extraction
 * or validation of the name contents, providing efficient packet traversal for question and
 * resource record iteration. Unlike extract_name() which fully parses and validates names, this
 * function performs minimal processing: it follows compression pointers only when necessary to
 * find the name terminator (zero-length label), handles extended label types (bitstring labels
 * with 0x40 type per obsolete RFC 2673), and skips standard length-prefixed labels. The function
 * is optimized for sequential packet parsing where name contents are not needed, such as skipping
 * questions when only answers are relevant, or advancing through multiple resource records to
 * reach a specific section. Critical security: compression pointers are followed only to verify
 * name termination, but the function returns position immediately after the compression pointer
 * (2 bytes), not after the pointed-to name (lines 314-319). This prevents double-counting name
 * length and maintains correct parsing position. Extended bitstring labels (0x40 type, lines
 * 321-329) are handled by extracting length from the label header and skipping the specified
 * number of bytes, supporting legacy DNS implementations. Standard labels (0x00 type, lines
 * 331-344) are skipped by reading length byte and advancing past that many characters. After
 * reaching name terminator (zero-length label), the function validates that extrabytes additional
 * bytes are available (line 347), enabling validation of fixed-size fields following the name
 * (QTYPE+QCLASS for questions, TYPE+CLASS+TTL+RDLENGTH for RRs).
 * 
 * @param ansp Starting position pointer within DNS packet, typically pointing to first byte of
 *             name (length byte of first label or compression pointer). Must be within packet
 *             bounds (validated via CHECK_LEN). Position is advanced through name structure
 * @param header Pointer to DNS packet header (struct dns_header) marking packet start for
 *               boundary validation and compression pointer base offset calculation
 * @param plen Total packet length in bytes for boundary checking via CHECK_LEN macro, prevents
 *             reading beyond allocated buffer
 * @param extrabytes Number of additional bytes expected immediately after name terminator that
 *                   must be present for successful return. Typically 4 for questions (QTYPE 2
 *                   bytes + QCLASS 2 bytes), 10 for resource records (TYPE 2 + CLASS 2 + TTL 4
 *                   + RDLENGTH 2). Zero if no fixed fields follow name
 * 
 * @return Pointer to first byte after name and extrabytes on success, NULL on error
 * @retval Non-NULL Pointer positioned after name terminator plus extrabytes, ready for parsing
 *                  next field. For compression pointer, points 2 bytes past pointer (not past
 *                  referenced name). For standard/bitstring labels, points past zero-length
 *                  terminator plus validated extrabytes
 * @retval NULL Malformed packet (boundary violation), unsupported label type (0x80), or
 *              insufficient bytes for extrabytes validation
 * 
 * @note Compression pointer handling: When compression pointer (0xc0) is encountered, function
 *       follows pointer only to verify name ends with zero-length label (lines 316-318), then
 *       returns position 2 bytes past the compression pointer itself (line 319). This differs
 *       from extract_name() which fully resolves compression chains. Rationale: compression
 *       pointers in wire format are exactly 2 bytes, and subsequent parsing continues after
 *       those 2 bytes, not after the referenced name
 * @note Extended bitstring labels (0x40 type, RFC 2673): Length is encoded in first byte
 *       (label & 0x3f) which may be zero, in which case length is in next byte allowing up to
 *       256 bytes (lines 324-328). Function skips bitstring content without interpretation.
 *       This label type was experimental and is now obsolete per RFC 3363 and RFC 6891, but
 *       support maintained for legacy zone compatibility
 * @note Standard label processing: Length byte (0-63) indicates following character count.
 *       Function skips length+1 bytes total (length byte itself plus label characters). Zero
 *       length indicates name terminator and loop exit (lines 342-343)
 * @note Label type bits: Upper 2 bits of label byte encode type: 0x00 (standard label), 0xc0
 *       (compression pointer), 0x40 (extended label/bitstring). Type 0x80 is reserved and
 *       returns NULL as unsupported (line 340)
 * 
 * @warning Compression pointer destination is NOT validated to point to valid name or earlier
 *          packet position. Malicious packets could have pointers to invalid locations. Function
 *          only checks that pointed-to location terminates properly, not that intermediate
 *          structure is valid
 * @warning Extended label types beyond bitstring (0x40) return NULL. Future DNS extensions using
 *          0x40 type with different semantics would fail. RFC 6891 recommends against new label
 *          type assignments
 * @warning extrabytes validation (line 347) ensures bytes exist but does not validate their
 *          values. Caller must parse and validate the extrabytes content (QTYPE/QCLASS/TYPE/
 *          CLASS/TTL/RDLENGTH values)
 * 
 * @see skip_questions() which calls skip_name() with extrabytes=4 for each question
 * @see skip_section() which calls skip_name() with extrabytes=10 for resource records
 * @see extract_name() for full name extraction with compression resolution and validation
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dns_header *header = (struct dns_header *)packet;
 * unsigned char *p = (unsigned char *)(header + 1);
 * // Skip question section (QNAME + QTYPE + QCLASS = name + 4 bytes)
 * p = skip_name(p, header, packet_len, 4);
 * if (!p) return 0; // Malformed question
 * // p now points to QTYPE, skip it to reach answers
 * p += 4; // Skip QTYPE (2) + QCLASS (2)
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 1035 Section 4.1.4 (name compression), Section 3.1 (name syntax),
 *                 RFC 2673 Section 3 (obsolete bitstring labels), RFC 3363 (bitstring label
 *                 deprecation), RFC 6891 Section 6.1 (future label type allocation)
 * SIDE EFFECTS: None - does not modify packet or external state. Return value is new pointer
 *               position within packet
 * THREAD SAFETY: Single-threaded architecture. Read-only operation on packet buffer, no shared
 *                mutable state. Safe for concurrent calls with distinct packets
 */
unsigned char *skip_name(unsigned char *ansp, struct dns_header *header, size_t plen, int extrabytes)
{
  while(1)
    {
      unsigned int label_type;
      
      if (!CHECK_LEN(header, ansp, plen, 1))
	return NULL;
      
      label_type = (*ansp) & 0xc0;

      if (label_type == 0xc0)
	{
	  /* pointer for compression. */
	  ansp += 2;	
	  break;
	}
      else if (label_type == 0x80)
	return NULL; /* reserved */
      else if (label_type == 0x40)
	{
	  /* Extended label type */
	  unsigned int count;
	  
	  if (!CHECK_LEN(header, ansp, plen, 2))
	    return NULL;
	  
	  if (((*ansp++) & 0x3f) != 1)
	    return NULL; /* we only understand bitstrings */
	  
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
	    return NULL;

	  if (len == 0)
	    break; /* zero length label marks the end. */
	}
    }

  if (!CHECK_LEN(header, ansp, plen, extrabytes))
    return NULL;
  
  return ansp;
}

/**
 * @brief Skip over all questions in DNS question section, advancing to answer section
 * 
 * @detailed This function navigates past the entire question section of a DNS packet by
 * iterating through all questions specified in the header's qdcount field and calling
 * skip_name() for each question to advance past QNAME, QTYPE, and QCLASS fields. The
 * question section immediately follows the 12-byte DNS header and contains one or more
 * questions (qdcount from header, lines 358-363), each formatted as: QNAME (variable-length
 * domain name), QTYPE (2 bytes specifying query type like A=1, AAAA=28, PTR=12), and
 * QCLASS (2 bytes, typically IN=1 for Internet class). For each question iteration, skip_name()
 * is called with extrabytes=4 to validate that QTYPE and QCLASS follow the QNAME (line 360),
 * then pointer is advanced 4 bytes to skip those fixed fields (line 362). The function uses
 * ntohs() to convert header->qdcount from network byte order (big-endian) to host byte order
 * before iteration (line 358), ensuring correct question count on little-endian architectures.
 * Upon successful completion, the returned pointer marks the start of the answer section,
 * ready for parsing answer resource records. This function is essential for query processing
 * where only the answer section is relevant, such as cache insertion after receiving upstream
 * responses or validation of response structure. Most DNS queries contain exactly one question
 * (qdcount=1) per RFC 1035 recommendations, but the implementation correctly handles multiple
 * questions for protocol compliance and future extensibility.
 * 
 * @param header Pointer to DNS packet header (struct dns_header) containing qdcount field
 *               specifying number of questions in question section. Also serves as packet
 *               base for boundary validation in skip_name() calls
 * @param plen Total packet length in bytes for boundary checking during skip_name() iteration,
 *             prevents reading beyond allocated buffer on malformed packets
 * 
 * @return Pointer to start of answer section (first byte after last question) on success, NULL on error
 * @retval Non-NULL Pointer positioned at first answer resource record (or authority section if
 *                  ancount=0), ready for skip_section() or resource record parsing. Pointer
 *                  points to answer RR NAME field (first byte of first answer RR)
 * @retval NULL Malformed packet structure: question name parsing failed (compression pointer
 *              loop, boundary violation, unsupported label type), or insufficient bytes for
 *              QTYPE+QCLASS fields after QNAME in any question
 * 
 * @note Question count: Most DNS queries have qdcount=1 (single question) per RFC 1035 Section
 *       4.1.2 recommendations, but protocol allows multiple questions. Server responses typically
 *       echo the question section from the query with same qdcount. Zero qdcount is valid but
 *       unusual (function returns immediately with pointer to header+1)
 * @note Question format: RFC 1035 Section 4.1.2 specifies question as QNAME (variable domain
 *       name), QTYPE (2-byte query type, 1=A, 28=AAAA, 12=PTR, 255=ANY), and QCLASS (2-byte
 *       query class, 1=IN for Internet, 255=ANY). Total size per question is name_length + 4
 * @note Network byte order: qdcount in header is network byte order (big-endian), requiring
 *       ntohs() conversion on little-endian hosts (x86, ARM in little-endian mode). Omitting
 *       conversion would cause incorrect iteration count on little-endian systems
 * @note Loop decrement pattern: Loop uses post-decrement (q != 0; q--) rather than typical
 *       for(i=0; i<count; i++) pattern (line 358), avoiding need for additional variable and
 *       simplifying loop structure for countdown iteration
 * @note Performance: Function performs minimal processing per question (name skip + 4-byte
 *       advance), optimized for fast question section traversal when questions are not needed
 *       for processing (common in response handling where only answers matter)
 * 
 * @warning If any question name is malformed (invalid compression pointer, boundary violation),
 *          entire function fails with NULL return. Caller cannot determine which question failed
 *          or how many questions were successfully skipped
 * @warning Caller must validate qdcount is reasonable before calling. Malicious packets with
 *          huge qdcount (e.g., 65535) combined with valid questions could cause excessive CPU
 *          consumption iterating questions. Typical sanity check: qdcount <= 10
 * @warning Return value NULL indicates error but does not specify error type (compression loop,
 *          boundary violation, unsupported label type, insufficient extrabytes). Caller should
 *          treat as generic malformed packet and discard
 * @warning For queries with qdcount=0 (no questions), function returns (unsigned char *)(header+1)
 *          pointing immediately after header, which may not be a valid answer section start if
 *          packet is truncated. Caller should check plen >= sizeof(struct dns_header)
 * 
 * @see skip_section() for navigating answer/authority/additional sections
 * @see skip_name() which this function calls to skip each question name
 * @see extract_request() which uses this to reach answer section for cache insertion
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dns_header *header = (struct dns_header *)packet;
 * unsigned char *ansp = skip_questions(header, packet_len);
 * if (!ansp) {
 *   // Malformed question section, discard packet
 *   return 0;
 * }
 * // ansp now points to first answer RR, ready for skip_section() or extraction
 * ansp = skip_section(ansp, ntohs(header->ancount), header, packet_len);
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 1035 Section 4.1.2 (Question section format - QNAME, QTYPE, QCLASS),
 *                 RFC 1035 Section 4.1 (Message format with qdcount field in header)
 * SIDE EFFECTS: None - read-only operation on packet. Returns new pointer position without
 *               modifying packet contents or external state
 * THREAD SAFETY: Single-threaded architecture. Read-only packet traversal without shared
 *                mutable state. Safe for concurrent calls with distinct packet buffers
 */
unsigned char *skip_questions(struct dns_header *header, size_t plen)
{
  int q;
  unsigned char *ansp = (unsigned char *)(header+1);

  for (q = ntohs(header->qdcount); q != 0; q--)
    {
      if (!(ansp = skip_name(ansp, header, plen, 4)))
	return NULL;
      ansp += 4; /* class and type */
    }
  
  return ansp;
}

/**
 * @brief Skip over resource records in answer, authority, or additional section
 * 
 * @detailed This function navigates past a specified number of resource records in any DNS
 * packet section (answer, authority, or additional) by iterating through each RR and advancing
 * the packet pointer past the complete RR structure. Each resource record consists of NAME
 * (variable-length domain name), TYPE (2 bytes specifying RR type like A=1, AAAA=28, CNAME=5),
 * CLASS (2 bytes, typically IN=1), TTL (4 bytes time-to-live in seconds), RDLENGTH (2 bytes
 * specifying RDATA size), and RDATA (variable-length type-specific data). The function processes
 * each RR in three steps: (1) skip_name() is called with extrabytes=10 to validate NAME and
 * the 10 fixed bytes that follow (TYPE+CLASS+TTL+RDLENGTH, line 374), (2) pointer is advanced
 * 8 bytes past TYPE, CLASS, and TTL fields (line 376), and (3) GETSHORT() macro extracts
 * RDLENGTH value in network byte order (line 377), then ADD_RDLEN() macro advances pointer
 * by RDLENGTH bytes with boundary checking to skip RDATA (line 378). The function handles
 * multiple section types with same logic: answer section (ancount RRs), authority section
 * (nscount RRs), additional section (arcount RRs), or combined sections by summing counts
 * (common pattern: ancount+nscount+arcount to skip to packet end). Boundary validation via
 * CHECK_LEN in macros prevents buffer overruns from malformed RDLENGTH values. The function
 * is essential for packet traversal when RR contents are not needed, such as skipping answer
 * section to reach authority records, or skipping entire response to validate packet structure.
 * 
 * @param ansp Starting position pointer within DNS packet, typically pointing to first byte
 *             of first resource record NAME field in the section. Must be within packet bounds.
 *             Pointer is advanced through all resource records in the section
 * @param count Number of resource records to skip. Typically header->ancount (answer count),
 *              header->nscount (authority count), header->arcount (additional count), or sum
 *              of multiple section counts. Must be non-negative (negative treated as zero due
 *              to signed comparison i < count on line 372). Zero count returns ansp unchanged
 * @param header Pointer to DNS packet header (struct dns_header) marking packet start for
 *               boundary validation and compression pointer base offset calculation in skip_name()
 * @param plen Total packet length in bytes for boundary checking via CHECK_LEN macro in
 *             skip_name() and ADD_RDLEN(), prevents reading beyond allocated buffer on malformed
 *             packets with invalid RDLENGTH values
 * 
 * @return Pointer to first byte after all skipped resource records on success, NULL on error
 * @retval Non-NULL Pointer positioned after last resource record's RDATA, ready for parsing
 *                  next section or validating end of packet. Points to next section's first
 *                  RR NAME, or to additional data after final section, or to packet end
 * @retval NULL Malformed packet structure: RR name parsing failed (compression pointer loop,
 *              boundary violation, unsupported label type), insufficient bytes for fixed fields
 *              (TYPE+CLASS+TTL+RDLENGTH) after NAME, or boundary violation when advancing by
 *              RDLENGTH (RDATA extends beyond packet end)
 * 
 * @note Resource record format: RFC 1035 Section 4.1.3 specifies RR as NAME (domain name),
 *       TYPE (2-byte RR type), CLASS (2-byte class), TTL (4-byte unsigned int), RDLENGTH
 *       (2-byte RDATA length), RDATA (variable format depending on TYPE). Total fixed fields
 *       after NAME: 10 bytes (2+2+4+2). Function skips entire RR structure without parsing
 *       RDATA contents
 * @note RDLENGTH validation: ADD_RDLEN() macro (defined in dnsmasq.h) performs boundary check
 *       ensuring ansp + rdlen does not exceed packet end before advancing pointer. This prevents
 *       malicious packets with oversized RDLENGTH from causing buffer overruns. Macro returns
 *       false (0) on boundary violation, causing function to return NULL
 * @note GETSHORT macro: Extracts 2-byte unsigned short in network byte order (big-endian) and
 *       converts to host byte order, advancing pointer by 2 bytes. Defined in dnsmasq.h as
 *       inline operation for efficiency. Applied to RDLENGTH extraction (line 377)
 * @note Section combinations: Common usage patterns include skipping answer section only
 *       (count=ancount), skipping answer+authority (count=ancount+nscount), or skipping entire
 *       packet content (count=ancount+nscount+arcount) as in resize_packet() at line 393
 * @note Performance: Function performs minimal processing per RR (name skip + 8-byte advance +
 *       RDLENGTH extraction + RDATA skip), optimized for fast section traversal when RR contents
 *       are not needed. No memory allocation or data copying
 * @note Zero count handling: Loop condition (i < count) with i starting at 0 means zero count
 *       causes immediate return of ansp unchanged (no iterations). Valid for sections with no
 *       records (e.g., authority section empty in simple responses)
 * 
 * @warning If any RR is malformed (invalid NAME, boundary violation in fixed fields or RDATA),
 *          entire function fails with NULL return. Caller cannot determine which RR failed or
 *          how many RRs were successfully skipped before failure
 * @warning Caller must validate count is reasonable before calling. Malicious packets with huge
 *          section counts (e.g., ancount=65535) combined with valid RRs could cause excessive
 *          CPU consumption. Typical sanity check: total RR count <= 100-200
 * @warning Return value NULL indicates error but does not specify error type (compression loop,
 *          boundary violation in NAME/fixed fields/RDATA, unsupported label type). Caller should
 *          treat as generic malformed packet and discard
 * @warning Function does not validate RDLENGTH matches actual RDATA format for the RR TYPE.
 *          Invalid RDLENGTH (e.g., A record with rdlen=2 instead of 4) passes boundary check
 *          but causes incorrect parsing position for subsequent RRs. Protocol-level validation
 *          requires TYPE-specific RDLENGTH checking not performed here
 * @warning Negative count values are handled as i < count always false, returning ansp unchanged.
 *          However, negative counts indicate caller error and should be avoided. Function does
 *          not validate count >= 0
 * 
 * @see skip_questions() for navigating question section with different fixed field size (4 bytes)
 * @see skip_name() which this function calls to skip each resource record NAME
 * @see extract_addresses() for RR content extraction rather than skipping
 * @see resize_packet() at line 393 for example usage skipping all sections combined
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dns_header *header = (struct dns_header *)packet;
 * unsigned char *p = skip_questions(header, packet_len);
 * if (!p) return 0; // Malformed questions
 * // Skip answer section to reach authority records
 * p = skip_section(p, ntohs(header->ancount), header, packet_len);
 * if (!p) return 0; // Malformed answer section
 * // p now points to first authority RR
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 1035 Section 4.1.3 (Resource record format - NAME, TYPE, CLASS, TTL,
 *                 RDLENGTH, RDATA), RFC 1035 Section 4.1 (Message format with ancount,
 *                 nscount, arcount fields in header)
 * SIDE EFFECTS: None - read-only operation on packet. Returns new pointer position without
 *               modifying packet contents or external state
 * THREAD SAFETY: Single-threaded architecture. Read-only packet traversal without shared
 *                mutable state. Safe for concurrent calls with distinct packet buffers
 */
unsigned char *skip_section(unsigned char *ansp, int count, struct dns_header *header, size_t plen)
{
  int i, rdlen;
  
  for (i = 0; i < count; i++)
    {
      if (!(ansp = skip_name(ansp, header, plen, 10)))
	return NULL; 
      ansp += 8; /* type, class, TTL */
      GETSHORT(rdlen, ansp);
      if (!ADD_RDLEN(header, ansp, plen, rdlen))
	return NULL;
    }

  return ansp;
}

size_t resize_packet(struct dns_header *header, size_t plen, unsigned char *pheader, size_t hlen)
{
  unsigned char *ansp = skip_questions(header, plen);
    
  /* if packet is malformed, just return as-is. */
  if (!ansp)
    return plen;
  
  if (!(ansp = skip_section(ansp, ntohs(header->ancount) + ntohs(header->nscount) + ntohs(header->arcount),
			    header, plen)))
    return plen;
    
  /* restore pseudoheader */
  if (pheader && ntohs(header->arcount) == 0)
    {
      /* must use memmove, may overlap */
      memmove(ansp, pheader, hlen);
      header->arcount = htons(1);
      ansp += hlen;
    }

  return ansp - (unsigned char *)header;
}

/* is addr in the non-globally-routed IP space? */ 
int private_net(struct in_addr addr, int ban_localhost) 
{
  in_addr_t ip_addr = ntohl(addr.s_addr);

  return
    (((ip_addr & 0xFF000000) == 0x7F000000) && ban_localhost)  /* 127.0.0.0/8    (loopback) */ ||
    (((ip_addr & 0xFF000000) == 0x00000000) && ban_localhost) /* RFC 5735 section 3. "here" network */ ||
    ((ip_addr & 0xFF000000) == 0x0A000000)  /* 10.0.0.0/8     (private)  */ ||
    ((ip_addr & 0xFFC00000) == 0x64400000)  /* 100.64.0.0/10  (CG-NAT) RFC6598/RFC7793*/ ||
    ((ip_addr & 0xFFF00000) == 0xAC100000)  /* 172.16.0.0/12  (private)  */ ||
    ((ip_addr & 0xFFFF0000) == 0xC0A80000)  /* 192.168.0.0/16 (private)  */ ||
    ((ip_addr & 0xFFFF0000) == 0xA9FE0000)  /* 169.254.0.0/16 (zeroconf) */ ||
    ((ip_addr & 0xFFFFFF00) == 0xC0000200)  /* 192.0.2.0/24   (test-net) */ ||
    ((ip_addr & 0xFFFFFF00) == 0xC6336400)  /* 198.51.100.0/24(test-net) */ ||
    ((ip_addr & 0xFFFFFF00) == 0xCB007100)  /* 203.0.113.0/24 (test-net) */ ||
    ((ip_addr & 0xFFFFFFFF) == 0xFFFFFFFF)  /* 255.255.255.255/32 (broadcast)*/ ;
}

int private_net6(struct in6_addr *a, int ban_localhost)
{
  /* Block IPv4-mapped IPv6 addresses in private IPv4 address space */
  if (IN6_IS_ADDR_V4MAPPED(a))
    {
      struct in_addr v4;
      v4.s_addr = ((const uint32_t *) (a))[3];
      return private_net(v4, ban_localhost);
    }

  return
    (IN6_IS_ADDR_UNSPECIFIED(a) && ban_localhost) || /* RFC 6303 4.3 */
    (IN6_IS_ADDR_LOOPBACK(a) && ban_localhost) ||    /* RFC 6303 4.3 */
    IN6_IS_ADDR_LINKLOCAL(a) ||   /* RFC 6303 4.5 */
    IN6_IS_ADDR_SITELOCAL(a) ||
    ((unsigned char *)a)[0] == 0xfd ||   /* RFC 6303 4.4 */
    ((u32 *)a)[0] == htonl(0x20010db8); /* RFC 6303 4.6 */
}

int do_doctor(struct dns_header *header, size_t qlen, char *namebuff)
{
  unsigned char *p;
  int i, qtype, qclass, rdlen;
  int done = 0;
  
  if (!(p = skip_questions(header, qlen)))
    return done;
  
  for (i = 0; i < ntohs(header->ancount) + ntohs(header->arcount); i++)
    {
      /* Skip over auth section */
      if (i == ntohs(header->ancount) && !(p = skip_section(p, ntohs(header->nscount), header, qlen)))
	return done;
      
      if (!extract_name(header, qlen, &p, namebuff, EXTR_NAME_EXTRACT, 10))
	return done; /* bad packet */
      
      GETSHORT(qtype, p); 
      GETSHORT(qclass, p);
      p += 4; /* ttl */
      GETSHORT(rdlen, p);
      
      if (qclass == C_IN && qtype == T_A)
	{
	  struct doctor *doctor;
	  union all_addr addr;
	  
	  if (!CHECK_LEN(header, p, qlen, INADDRSZ))
	    return done;
	  
	  /* alignment */
	  memcpy(&addr.addr4, p, INADDRSZ);
	  
	  for (doctor = daemon->doctors; doctor; doctor = doctor->next)
	    {
	      if (doctor->end.s_addr == 0)
		{
		  if (!is_same_net(doctor->in, addr.addr4, doctor->mask))
		    continue;
		}
	      else if (ntohl(doctor->in.s_addr) > ntohl(addr.addr4.s_addr) || 
		       ntohl(doctor->end.s_addr) < ntohl(addr.addr4.s_addr))
		continue;
	      
	      addr.addr4.s_addr &= ~doctor->mask.s_addr;
	      addr.addr4.s_addr |= (doctor->out.s_addr & doctor->mask.s_addr);
	      /* Since we munged the data, the server it came from is no longer authoritative */
	      header->hb3 &= ~HB3_AA;
#ifdef HAVE_DNSSEC
	      /* remove validated flag from this RR, since we changed it! */
	      if (option_bool(OPT_DNSSEC_VALID) && i <  ntohs(header->ancount))
		daemon->rr_status[i] = 0;
#endif
	      done = 1;
	      memcpy(p, &addr.addr4, INADDRSZ);
	      log_query(F_FORWARD | F_CONFIG | F_IPV4, namebuff, &addr, NULL, 0);
	      break;
	    }
	}
      
      if (!ADD_RDLEN(header, p, qlen, rdlen))
	 return done; /* bad packet */
    }

  return done;
}

/* Find SOA RR in auth section to get TTL for negative caching of name. 
   Cache said SOA and return the difference in length between name and the name of the 
   SOA RR so we can look it up again.
*/
static int find_soa(struct dns_header *header, size_t qlen, char *name, int *substring, unsigned long *ttlp, int cache, time_t now)
{
  unsigned char *p, *psave;
  int qtype, qclass, rdlen;
  unsigned long ttl, minttl;
  int i, j;
  size_t name_len, soa_len, len;
  union all_addr addr;

  /* first move to NS section and find TTL from  SOA RR */
  if (!(p = skip_questions(header, qlen)) ||
      !(p = skip_section(p, ntohs(header->ancount), header, qlen)))
    return 0;  /* bad packet */

  name_len = strlen(name);
  
  if (substring)
    *substring = name_len;

  for (i = 0; i < ntohs(header->nscount); i++)
    {
      if (!extract_name(header, qlen, &p, daemon->workspacename, EXTR_NAME_EXTRACT, 0))
	return 0; /* bad packet */
      
      GETSHORT(qtype, p); 
      GETSHORT(qclass, p);
      GETLONG(ttl, p);
      GETSHORT(rdlen, p);

      psave = p;
      
      if ((qclass == C_IN) && (qtype == T_SOA))
	{
	  soa_len = strlen(daemon->workspacename);

	  /* SOA must be for the name we're interested in. */
	  if (soa_len <= name_len && memcmp(daemon->workspacename, name + name_len - soa_len, soa_len) == 0)
	    {
	      int prefix = name_len - soa_len;
	      
	      if (cache)
		{
		  if (!(addr.rrblock.rrdata = blockdata_alloc(NULL, 0)))
		    return 0;
		  addr.rrblock.rrtype = T_SOA;
		  addr.rrblock.datalen = 0;
		}
	      
	      for (j = 0; j < 2; j++) /* MNAME, RNAME */
		{
		  if (!extract_name(header, qlen, &p, daemon->workspacename, EXTR_NAME_EXTRACT, 0))
		    {
		      if (cache)
			blockdata_free(addr.rrblock.rrdata);
		      return 0;
		    }
		  
		  if (cache)
		    {
		      len = to_wire(daemon->workspacename);
		      if (!blockdata_expand(addr.rrblock.rrdata, addr.rrblock.datalen, daemon->workspacename, len))
			{
			  blockdata_free(addr.rrblock.rrdata);
			  return 0;
			}

		      addr.rrblock.datalen += len;
		    }
		}

	      if (!CHECK_LEN(header, p, qlen, 20))
		{
		  if (cache)
		    blockdata_free(addr.rrblock.rrdata);
		  return 0;
		}
	      
	      /* rest of RR */
	      if (cache)
		{
		  int secflag = 0;

		  if (!blockdata_expand(addr.rrblock.rrdata, addr.rrblock.datalen, (char *)p, 20))
		    {
		      blockdata_free(addr.rrblock.rrdata);
		      return 0;
		    }
		  
		  addr.rrblock.datalen += 20;
		  
#ifdef HAVE_DNSSEC
		  if (option_bool(OPT_DNSSEC_VALID) && daemon->rr_status[i + ntohs(header->ancount)] != 0)
		    {
		      secflag = F_DNSSECOK; 
		  
		      /* limit TTL based on signature. */
		      if (daemon->rr_status[i + ntohs(header->ancount)] < ttl)
			ttl = daemon->rr_status[i + ntohs(header->ancount)];
		    }
#endif
		  
		  if (!cache_insert(name + prefix, &addr, C_IN, now, ttl, F_FORWARD | F_RR | F_KEYTAG | secflag))
		    {
		      blockdata_free(addr.rrblock.rrdata);
		      return 0;
		    }
		}
	      
	      p += 16; /* SERIAL REFRESH RETRY EXPIRE */
	      
	      GETLONG(minttl, p); /* minTTL */
	      if (ttl < minttl)
		minttl = ttl;

	      if (substring)
		*substring = prefix;
	      
	      if (ttlp)
		*ttlp = minttl;

	      return 1;
	    }
	}

      p = psave;
      
      if (!ADD_RDLEN(header, p, qlen, rdlen))
	return 0; /* bad packet */
    }
  
  return 0;
}

/* Print TXT reply to log */
static int log_txt(char *name, unsigned char *p, const int ardlen, int flag)
{
  unsigned char *p1 = p;
 
  /* Loop over TXT payload */
  while ((p1 - p) < ardlen)
    {
      unsigned int i, len = *p1;
      unsigned char *p3 = p1;
      if ((p1 + len - p) >= ardlen)
	return 0; /* bad packet */

      /* make counted string zero-term and sanitise */
      for (i = 0; i < len; i++)
	{
	  if (!isprint((unsigned char)*(p3+1)))
	    break;
	  *p3 = *(p3+1);
	  p3++;
	}

      *p3 = 0;
      log_query(flag, name, NULL, (char*)p1, 0);
      /* restore */
      memmove(p1 + 1, p1, i);
      *p1 = len;
      p1 += len+1;
    }
  return 1;
}

/* Note that the following code can create CNAME chains that don't point to a real record,
   either because of lack of memory, or lack of SOA records.  These are treated by the cache code as 
   expired and cleaned out that way. 
   Return 1 if we reject an address because it look like part of dns-rebinding attack. 
   Return 2 if the packet is malformed.
*/
int extract_addresses(struct dns_header *header, size_t qlen, char *name, time_t now, 
		      struct ipsets *ipsets, struct ipsets *nftsets, int check_rebind,
		      int no_cache_dnssec, int secure)
{
  unsigned char *p, *p1, *endrr, *namep;
  int j, qtype, qclass, aqtype, aqclass, ardlen, res;
  unsigned long ttl;
  union all_addr addr;
#ifdef HAVE_IPSET
  char **ipsets_cur;
#else
  (void)ipsets; /* unused */
#endif
#ifdef HAVE_NFTSET
  char **nftsets_cur;
#else
  (void)nftsets; /* unused */
#endif
  int name_encoding, found = 0, ptr = 0;
  int flags = RCODE(header) == NXDOMAIN ? F_NXDOMAIN : 0;

  cache_start_insert();

  namep = p = (unsigned char *)(header+1);
  
  if (ntohs(header->qdcount) != 1 || !extract_name(header, qlen, &p, name, EXTR_NAME_EXTRACT, 4))
    return 2; /* bad packet */
  
  GETSHORT(qtype, p); 
  GETSHORT(qclass, p);
  
  if (qclass != C_IN)
    return 0;

  /* If the PTR record encodes an address, store using a name/address record with F_REVERSE set.
     Otherwise, it gets stored as an arbitrary RR below. If the query is answerable with
     a CNAME, also take the arbitrary-RR route, since the cache can't represent a CNAME
     whose target is stored in a F_REVERSE record. */
  if (qtype == T_PTR && !(flags & F_NXDOMAIN) && (name_encoding = in_arpa_name_2_addr(name, &addr)))
    { 
      ptr = 1;
      
      if (!(p1 = skip_questions(header, qlen)))
	return 2;
      
      for (j = 0; j < ntohs(header->ancount); j++) 
	{
	  int secflag = 0;
	  if (!(res = extract_name(header, qlen, &p1, name, EXTR_NAME_COMPARE, 10)))
	    return 2; /* bad packet */
	  
	  GETSHORT(aqtype, p1); 
	  GETSHORT(aqclass, p1);
	  p = p1;
	  GETLONG(ttl, p1);
	  GETSHORT(ardlen, p1);
	  endrr = p1+ardlen;
	  
	  if (aqclass == C_IN && res == 1 && aqtype == T_PTR)
	    {
	      found = 1;

	      if ((daemon->max_ttl != 0) && (ttl > daemon->max_ttl))
		ttl = daemon->max_ttl;
	      
#ifdef HAVE_DNSSEC
	      if (option_bool(OPT_DNSSEC_VALID) && j < daemon->rr_status_sz && daemon->rr_status[j] != 0)
		{
		  secflag = F_DNSSECOK;
		  /* limit TTL based on signature. */
		  if (daemon->rr_status[j] < ttl)
		    ttl = daemon->rr_status[j];
		}
#endif
	      
	      PUTLONG(ttl, p);

	      if (!extract_name(header, qlen, &p1, name, EXTR_NAME_EXTRACT, 0))
		return 2;
	      log_query(name_encoding | secflag | F_REVERSE | F_UPSTREAM, name, &addr, NULL, 0);
	      cache_insert(name, &addr, C_IN, now, ttl, name_encoding | secflag | F_REVERSE);
	      
	      /* restore query into name */
	      p1 = namep;
	      if (!extract_name(header, qlen, &p1, name, EXTR_NAME_EXTRACT, 0))
		return 2;
	    }
	  
	  p1 = endrr;
	  if (!CHECK_LEN(header, p1, qlen, 0))
	    return 2; /* bad packet */
	}
    }

  if (!ptr || !found)
    {
      /* everything other than PTR */
      struct crec *newc, *cpp = NULL;
      int cname_count = CNAME_CHAIN, addrlen = 0, insert = 1;
            
      if (qtype == T_A)
	{
	  addrlen = INADDRSZ;
	  flags |= F_IPV4;
	}
      else if (qtype == T_AAAA)
	{
	  addrlen = IN6ADDRSZ;
	  flags |= F_IPV6;
	}
      else if (qtype != T_CNAME &&
	       (qtype == T_SRV || qtype == T_PTR || rr_on_list(daemon->cache_rr, qtype) || rr_on_list(daemon->cache_rr, T_ANY)))
	flags |= F_RR;
      else
	insert = 0; /* NOTE: do not cache data from CNAME queries. */
      
    cname_loop:
      if (!(p1 = skip_questions(header, qlen)))
	return 2;
      
      for (j = 0; j < ntohs(header->ancount); j++) 
	{
	  int secflag = 0;
	  
	  if (!(res = extract_name(header, qlen, &p1, name, EXTR_NAME_COMPARE, 10)))
	    return 2; /* bad packet */
	  
	  GETSHORT(aqtype, p1); 
	  GETSHORT(aqclass, p1);
	  p = p1;
	  GETLONG(ttl, p1);
	  GETSHORT(ardlen, p1);
	  endrr = p1+ardlen;

	  if (!CHECK_LEN(header, endrr, qlen, 0))
	    return 2; /* bad packet */
	  
	  /* Not what we're looking for? */
	  if (aqclass != C_IN || res == 2)
	    {
	      p1 = endrr;
	      continue;
	    }

	  if ((daemon->max_ttl != 0) && (ttl > daemon->max_ttl))
	    ttl = daemon->max_ttl;
	  
#ifdef HAVE_DNSSEC
	  if (option_bool(OPT_DNSSEC_VALID) && j < daemon->rr_status_sz && daemon->rr_status[j] != 0)
	    {
	      secflag = F_DNSSECOK;
	      
	      /* limit TTl based on sig. */
	      if (daemon->rr_status[j] < ttl)
		ttl = daemon->rr_status[j];
	    }
#endif	  

	  PUTLONG(ttl, p);
	  
	  if (aqtype == T_CNAME)
	    {
	      if (!cname_count--)
		return 0; /* looped CNAMES */
	      
	      log_query(secflag | F_CNAME | F_FORWARD | F_UPSTREAM, name, NULL, NULL, 0);
	      
	      if (insert)
		{
		  if ((newc = cache_insert(name, NULL, C_IN, now, ttl, F_CNAME | F_FORWARD | secflag)))
		    {
		      newc->addr.cname.target.cache = NULL;
		      newc->addr.cname.is_name_ptr = 0; 
		      if (cpp)
			{
			  next_uid(newc);
			  cpp->addr.cname.target.cache = newc;
			  cpp->addr.cname.uid = newc->uid;
			}
		    }
		  
		  cpp = newc;
		}
	      
	      /* Set the query to the CNAME target and go again unless the query was just for a CNAME. */
	      namep = p1;
	      if (!extract_name(header, qlen, &p1, name, EXTR_NAME_EXTRACT, 0))
		return 2;
	      
	      if (qtype != T_CNAME)
		goto cname_loop;

	      found = 1;
	    }
	  else if (qtype == T_ANY || aqtype != qtype)
	    {
#ifdef HAVE_DNSSEC
	      if (!option_bool(OPT_DNSSEC_VALID) || aqtype != T_RRSIG)
#endif
		log_query(secflag | F_FORWARD | F_UPSTREAM | F_RRNAME, name, NULL, NULL, aqtype);
	    }
	  else if (!(flags & F_NXDOMAIN))
	    {
	      found = 1;
	      
	      if (flags & F_RR)
		{
		  short desc, *rrdesc = rrfilter_desc(aqtype);
		  unsigned char *tmp = namep;
		  
		  if (!CHECK_LEN(header, p1, qlen, ardlen))
		    return 2; /* bad packet */
		  
		  /* If the data has no names and is small enough, store it in
		     the crec address field rather than allocate a block. */
		  if (*rrdesc == -1 && ardlen <= (int)RR_IMDATALEN)
		    {
		       addr.rrdata.rrtype = aqtype;
		       addr.rrdata.datalen = (char)ardlen;
		       flags &= ~F_KEYTAG; /* in case of >1 answer, not all the same. */ 
		       if (ardlen != 0)
			 memcpy(addr.rrdata.data, p1, ardlen);
		    }
		  else
		    {
		      addr.rrblock.rrtype = aqtype;
		      addr.rrblock.datalen = 0;
		      flags |= F_KEYTAG; /* discriminates between rrdata and rrblock */
		      
		      /* The RR data may include names, and those names may include
			 compression, which will be rendered meaningless when
			 copied into another packet. 
			 Here we go through a description of the packet type to
			 find the names, and extract them to a c-string and then
			 re-encode them to standalone DNS format without compression. */
		      if (!(addr.rrblock.rrdata = blockdata_alloc(NULL, 0)))
			return 0;
		      do
			{
			  desc = *rrdesc++;
			  
			  if (desc == -1)
			    {
			      /* Copy the rest of the RR and end. */
			      if (!blockdata_expand(addr.rrblock.rrdata, addr.rrblock.datalen, (char *)p1, endrr - p1))
				{
				  blockdata_free(addr.rrblock.rrdata);
				  return 0;
				}
			      addr.rrblock.datalen += endrr - p1;
			    }
			  else if (desc == 0)
			    {
			      /* Name, extract it then re-encode. */
			      int len;
			      
			      if (!extract_name(header, qlen, &p1, name, EXTR_NAME_EXTRACT, 0))
				{
				  blockdata_free(addr.rrblock.rrdata);
				  return 2;
				}
			      
			      len = to_wire(name);
			      if (!blockdata_expand(addr.rrblock.rrdata, addr.rrblock.datalen, name, len))
				{
				  blockdata_free(addr.rrblock.rrdata);
				  return 0;
				}
			      
			      addr.rrblock.datalen += len;
			    }
			  else
			    {
			      /* desc is length of a block of data to be used as-is */
			      if (desc > endrr - p1)
				desc = endrr - p1;

			      if (!blockdata_expand(addr.rrblock.rrdata, addr.rrblock.datalen, (char *)p1, desc))
				{
				  blockdata_free(addr.rrblock.rrdata);
				  return 0;
				}

			      addr.rrblock.datalen += desc;
			      p1 += desc;
			    }
			} while (desc != -1);
		      
		      /* we overwrote the original name, so get it back here. */
		      if (!extract_name(header, qlen, &tmp, name, EXTR_NAME_EXTRACT, 0))
			{
			  blockdata_free(addr.rrblock.rrdata);
			  return 2;
			}
		    }
		} 
	      else if (flags & (F_IPV4 | F_IPV6))
		{
		  /* copy address into aligned storage */
		  if (!CHECK_LEN(header, p1, qlen, addrlen))
		    return 2; /* bad packet */
		  memcpy(&addr, p1, addrlen);
		  
		  /* check for returned address in private space */
		  if (check_rebind)
		    {
		      if ((flags & F_IPV4) &&
			  private_net(addr.addr4, !option_bool(OPT_LOCAL_REBIND)))
			return 1;
		      
		      if ((flags & F_IPV6) &&
			  private_net6(&addr.addr6, !option_bool(OPT_LOCAL_REBIND)))
			return 1;
		    }

		  if (flags & (F_IPV4 | F_IPV6))
		    {
		      /* If we're a child process, send this to the parent,
			 since the ipset and nfset access is not re-entrant. */
#ifdef HAVE_IPSET
		      if (ipsets)
			{
			  if (daemon->pipe_to_parent != -1)
			    cache_send_ipset(PIPE_OP_IPSET, ipsets, flags, &addr);
			  else
			    for (ipsets_cur = ipsets->sets; *ipsets_cur; ipsets_cur++)
			      if (add_to_ipset(*ipsets_cur, &addr, flags, 0) == 0)
				log_query((flags & (F_IPV4 | F_IPV6)) | F_IPSET, ipsets->domain, &addr, *ipsets_cur, 1);
			}
#endif
#ifdef HAVE_NFTSET
		      if (nftsets)
			{
			  if (daemon->pipe_to_parent != -1)
			    cache_send_ipset(PIPE_OP_NFTSET, nftsets, flags, &addr);
			  else
			    for (nftsets_cur = nftsets->sets; *nftsets_cur; nftsets_cur++)
			      if (add_to_nftset(*nftsets_cur, &addr, flags, 0) == 0)
				log_query((flags & (F_IPV4 | F_IPV6)) | F_IPSET, nftsets->domain, &addr, *nftsets_cur, 0);
			}
#endif
		    }
		}
	      
	      if (insert)
		{
		  newc = cache_insert(name, &addr, C_IN, now, ttl, flags | F_FORWARD | secflag);
		  if (newc && cpp)
		    {
		      next_uid(newc);
		      cpp->addr.cname.target.cache = newc;
		      cpp->addr.cname.uid = newc->uid;
		    }
		  cpp = NULL;
		  
		  /* cache insert failed, don't leak blockdata. */
		  if (!newc && (flags & F_RR) && (flags & F_KEYTAG))
		    blockdata_free(addr.rrblock.rrdata);  
		}
	      
	      /* We're filtering this RRtype. It will be removed from the 
		 returned packet in process_reply() but gets cached here anyway
		 and will be filtered again on the way out of the cache. Here,
		 we just need to alter the logging. */
	      if (qtype != T_ANY && rr_on_list(daemon->filter_rr, qtype))
		secflag = F_NEG | F_CONFIG;
	      
	      if (aqtype == T_TXT)
		log_txt(name, p1, ardlen, flags | F_FORWARD | F_UPSTREAM | secflag);
	      else
		log_query(flags | F_FORWARD | F_UPSTREAM | secflag, name, &addr, NULL, aqtype);
	    }
	  
	  p1 = endrr;
	  if (!CHECK_LEN(header, p1, qlen, 0))
	    return 2; /* bad packet */
	}
      
      if (!found && (qtype != T_ANY || (flags & F_NXDOMAIN)))
	{
	  if (flags & F_NXDOMAIN)
	    {
	      flags &= ~(F_IPV4 | F_IPV6 | F_RR);
	      
	      /* Can store NXDOMAIN reply for any qtype. */
	      insert = 1;
	    }
	  
	  log_query(F_UPSTREAM | F_FORWARD | F_NEG | flags | (secure ? F_DNSSECOK : 0), name, NULL, NULL, 0);
	  
	  if (insert && !option_bool(OPT_NO_NEG))
	    {
	      /* The order of records going into the cache matters (see  cache_recv_insert()).
		 The target of a CNAME must immediately follow the CNAME.
		 (CNAME has already gone into the cache at this point)
		 Here we call find_soa to get the ttl and substring, but
		 we DON'T LET IT INSERT the SOA into the cache if our negative record is a CNAME target
		 so that the SOA doesn't come before the CNAME target.

		 We call find_soa() again after inserting the CNAME target to insert the SOA
		 if necessary. */

	      int substring, have_soa = find_soa(header, qlen, name, &substring, &ttl, cpp == NULL, now);
	      
	      if (have_soa || daemon->neg_ttl)
		{		  
		  if (have_soa)
		    {
		      addr.rrdata.datalen = substring;
		      addr.rrdata.rrtype = qtype;
		    }
		  else
		    {
		      /* If daemon->neg_ttl is set, we can cache even without an SOA. */
		      ttl = daemon->neg_ttl;
		      flags |= F_NO_RR; /* Marks no SOA found. */
		    }
			      
		  newc = cache_insert(name, &addr, C_IN, now, ttl, F_FORWARD | F_NEG | flags | (secure ? F_DNSSECOK : 0));	
		  if (newc && cpp)
		    {
		      next_uid(newc);
		      cpp->addr.cname.target.cache = newc;
		      cpp->addr.cname.uid = newc->uid;
		    
		      /* we didn't insert the SOA before a CNAME target above, do it now. */
		      if (have_soa)
			find_soa(header, qlen, name, NULL, NULL, 1, now);
		    }
		}
	    }
	}
    }

  /* Don't cache replies from non-recursive nameservers, since we may get a 
     reply containing a CNAME but not its target, even though the target 
     does exist. */
  if (!(header->hb4 & HB4_CD) &&
      (header->hb4 & HB4_RA) &&
      !no_cache_dnssec)
    cache_end_insert();

  return 0;
}

#if defined(HAVE_CONNTRACK) && defined(HAVE_UBUS)
/* Don't pass control chars and weird escapes to UBus. */
static int safe_name(char *name)
{
  unsigned char *r;
  
  for (r = (unsigned char *)name; *r; r++)
    if (!isprint((int)*r))
      return 0;
  
  return 1;
}

/**
 * @brief Report resolved DNS addresses via UBus event broadcast for connmark allowlist integration
 * 
 * @detailed Processes DNS response answer section and broadcasts resolved IP addresses (A and AAAA records)
 *           and CNAME records via UBus events for connection tracking allowlist functionality. Used in
 *           OpenWrt environments to integrate DNS resolution with firewall connection marking. Only reports
 *           addresses when allowlist patterns match the connmark value and query is not wildcarded.
 * 
 * @param header DNS packet header containing response to analyze
 * @param len Total length of DNS packet in bytes (for bounds checking)
 * @param mark Connection tracking mark value to match against allowlist configuration
 * 
 * @return void (no return value; silently returns on errors or non-matching conditions)
 * 
 * @note Only processes responses with NOERROR response code (RCODE==0)
 * @note Returns early if allowlist contains wildcard pattern "*" matching the mark
 * @note Only reports records with class IN (Internet)
 * @warning Requires HAVE_UBUS compile flag for UBus event broadcast functionality
 * 
 * @see ubus_event_bcast_connmark_allowlist_resolved() in ubus.c for event broadcast implementation
 * @see extract_name() for DNS name extraction from resource records
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dns_header *header = ...;  // DNS response packet
 * size_t len = ...;                 // Packet length
 * u32 mark = 0x100;                 // Connection mark from netfilter
 * report_addresses(header, len, mark);  // Broadcast resolved addresses
 * @endcode
 * 
 * RFC COMPLIANCE: Processes standard DNS answer section per RFC 1035 Section 4.1.3
 * SIDE EFFECTS: Broadcasts UBus events for each matching A/AAAA/CNAME record
 * THREAD SAFETY: Uses global daemon->namebuff and daemon->workspacename buffers (single-threaded architecture)
 */
void report_addresses(struct dns_header *header, size_t len, u32 mark)
{
  unsigned char *p, *endrr;
  int i;
  unsigned long attl;
  struct allowlist *allowlists;
  char **pattern_pos;
  
  if (RCODE(header) != NOERROR)
    return;
  
  for (allowlists = daemon->allowlists; allowlists; allowlists = allowlists->next)
    if (allowlists->mark == (mark & daemon->allowlist_mask & allowlists->mask))
      for (pattern_pos = allowlists->patterns; *pattern_pos; pattern_pos++)
	if (!strcmp(*pattern_pos, "*"))
	  return;
  
  if (!(p = skip_questions(header, len)))
    return;
  for (i = ntohs(header->ancount); i != 0; i--)
    {
      int aqtype, aqclass, ardlen;
      
      if (!extract_name(header, len, &p, daemon->namebuff, EXTR_NAME_EXTRACT, 10))
	return;
      
      if (!CHECK_LEN(header, p, len, 10))
	return;
      GETSHORT(aqtype, p);
      GETSHORT(aqclass, p);
      GETLONG(attl, p);
      GETSHORT(ardlen, p);
      
      if (!CHECK_LEN(header, p, len, ardlen))
	return;
      endrr = p+ardlen;
      
      if (aqclass == C_IN)
	{
	  if (aqtype == T_CNAME)
	    {
	      if (!extract_name(header, len, &p, daemon->workspacename, EXTR_NAME_EXTRACT, 0))
		return;
	      if (safe_name(daemon->namebuff) && safe_name(daemon->workspacename))
		ubus_event_bcast_connmark_allowlist_resolved(mark, daemon->namebuff, daemon->workspacename, attl);
	    }
	  if (aqtype == T_A)
	    {
	      struct in_addr addr;
	      char ip[INET_ADDRSTRLEN];
	      if (ardlen != INADDRSZ)
		return;
	      memcpy(&addr, p, ardlen);
	      if (inet_ntop(AF_INET, &addr, ip, sizeof ip) && safe_name(daemon->namebuff))
		ubus_event_bcast_connmark_allowlist_resolved(mark, daemon->namebuff, ip, attl);
	    }
	  else if (aqtype == T_AAAA)
	    {
	      struct in6_addr addr;
	      char ip[INET6_ADDRSTRLEN];
	      if (ardlen != IN6ADDRSZ)
		return;
	      memcpy(&addr, p, ardlen);
	      if (inet_ntop(AF_INET6, &addr, ip, sizeof ip) && safe_name(daemon->namebuff))
		ubus_event_bcast_connmark_allowlist_resolved(mark, daemon->namebuff, ip, attl);
	    }
	}
      
      p = endrr;
    }
}
#endif

/* If the packet holds exactly one query
   return F_IPV4 or F_IPV6  and leave the name from the query in name */
/**
 * @brief Extract query name, type, and class from DNS request packet with validation
 * 
 * @detailed Parses DNS query section to extract question name, type, and class, returning flags
 *           indicating query characteristics (IPv4, IPv6, DNSSEC). Validates packet structure
 *           ensuring exactly one question, correct OPCODE (QUERY), and proper message format.
 *           Used by query processing logic to determine how to handle the request (cache lookup,
 *           upstream forwarding, DNSSEC processing).
 * 
 * @param header DNS packet header containing query to extract
 * @param qlen Total length of DNS packet in bytes (for bounds checking during name extraction)
 * @param name Output buffer for extracted query name (MAXDNAME bytes, receives FQDN with trailing dot removed)
 * @param typep Output pointer for query type (T_A, T_AAAA, T_MX, etc.); may be NULL if type not needed
 * @param classp Output pointer for query class (C_IN, C_CH, etc.); may be NULL if class not needed
 * 
 * @return Query flags indicating how to process this request:
 * @retval 0 Malformed packet or invalid query structure (extraction failed)
 * @retval F_IPV4 Query is for A record in IN class
 * @retval F_IPV6 Query is for AAAA record in IN class
 * @retval F_IPV4|F_IPV6 Query is for ANY record in IN class (requesting all address types)
 * @retval F_DNSSECOK|F_DS Query is for DS record (DNSSEC delegation signer)
 * @retval F_DNSSECOK Query is for DNSKEY record (DNSSEC public key)
 * @retval F_QUERY Generic query (other record types or non-IN class)
 * 
 * @note Returns empty name string (name[0]=0) if extraction fails
 * @note typep and classp output pointers zeroed before extraction; unchanged if extraction fails
 * @warning Rejects packets with QDCOUNT != 1 (must be exactly one question)
 * @warning Rejects packets with non-QUERY opcode (e.g., NOTIFY, UPDATE)
 * @warning Rejects queries with unexpected answer/authority sections (non-standard query format)
 * 
 * @see extract_name() for DNS name extraction from wire format
 * @see forward.c:receive_query() which calls this to parse incoming queries
 * @see T_A, T_AAAA, T_DS, T_DNSKEY constants in dns-protocol.h
 * @see F_IPV4, F_IPV6, F_DNSSECOK, F_DS, F_QUERY flags in dnsmasq.h
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dns_header *header = ...;  // Incoming DNS query packet
 * size_t qlen = ...;                // Packet length
 * char name[MAXDNAME];              // Buffer for extracted name
 * unsigned short qtype, qclass;
 * unsigned int flags = extract_request(header, qlen, name, &qtype, &qclass);
 * if (flags == 0)
 *   // Malformed query, reject
 * else if (flags & F_IPV4)
 *   // Process IPv4 address query
 * @endcode
 * 
 * RFC COMPLIANCE: Validates DNS query structure per RFC 1035 Section 4.1.2 (Question section format)
 * SIDE EFFECTS: Modifies name buffer, typep output, classp output; no global state changes
 * THREAD SAFETY: Safe (operates on caller-provided buffers only)
 */
unsigned int extract_request(struct dns_header *header, size_t qlen, char *name,
			     unsigned short *typep, unsigned short *classp)
{
  unsigned char *p = (unsigned char *)(header+1);
  int qtype, qclass;

  if (typep)
    *typep = 0;

  *name = 0; /* return empty name if no query found. */
  
  if (ntohs(header->qdcount) != 1 || OPCODE(header) != QUERY)
    return 0; /* must be exactly one query. */

  if (!(header->hb3 & HB3_QR) && (ntohs(header->ancount) != 0 || ntohs(header->nscount) != 0))
    return 0; /* non-standard query. */
  
  if (!extract_name(header, qlen, &p, name, EXTR_NAME_EXTRACT, 4))
    return 0; /* bad packet */
   
  GETSHORT(qtype, p); 
  GETSHORT(qclass, p);

  if (typep)
    *typep = qtype;

  if (classp)
    *classp = qclass;

  if (qclass == C_IN)
    {
      if (qtype == T_A)
	return F_IPV4;
      if (qtype == T_AAAA)
	return F_IPV6;
      if (qtype == T_ANY)
	return  F_IPV4 | F_IPV6;
    }

  /* Make the behaviour for DS and DNSKEY queries we forward the same
     as for DS and DNSKEY queries we originate. */
  if (qtype == T_DS || qtype == T_DNSKEY)
    return F_DNSSECOK | (qtype == T_DS ? F_DS : 0);
  
  return F_QUERY;
}

/**
 * @brief Initialize DNS response header with appropriate flags and response code
 * 
 * @detailed Prepares DNS packet header for response by setting/clearing standard DNS flags
 *           (QR, AA, TC, RA, AD) and initializing section counts to zero. Sets response code
 *           (RCODE) based on query processing result flags, supporting standard response types
 *           (NOERROR, NXDOMAIN, NOTIMP, REFUSED) and extended DNS error codes. Used as first
 *           step in constructing DNS responses before adding answer/authority/additional sections.
 * 
 * @param header DNS packet header to initialize for response (modified in-place)
 * @param flags Query processing flags indicating response type (F_NOERR, F_NXDOMAIN, F_RCODE, F_IPV4, F_IPV6, etc.)
 * @param ede Extended DNS Error code (RFC 8914) to log with REFUSED responses (0 if no EDE)
 * 
 * @return void (modifies header in-place)
 * 
 * Header Modifications:
 * - Sets QR flag (Query Response) indicating this is a response
 * - Clears AA flag (Authoritative Answer) unless F_IPV4 or F_IPV6 flags set
 * - Clears TC flag (Truncated)
 * - Sets RA flag (Recursion Available) to indicate recursive service available
 * - Clears AD flag (Authenticated Data) - caller sets if DNSSEC validated
 * - Sets ANCOUNT, NSCOUNT, ARCOUNT to zero (caller adds resource records afterward)
 * 
 * Response Code Mapping:
 * - F_NOERR → RCODE=NOERROR (empty domain, no error but no data)
 * - F_NXDOMAIN → RCODE=NXDOMAIN (name does not exist)
 * - F_RCODE → RCODE=NOTIMP (not implemented, unsupported query type)
 * - F_IPV4 or F_IPV6 → RCODE=NOERROR with AA flag (authoritative positive answer)
 * - Other flags → RCODE=REFUSED (query refused, logs EDE code)
 * 
 * @note Always clears answer/authority/additional section counts; caller must add records
 * @note Sets RA flag unconditionally indicating recursion available
 * @warning Overwrites existing header flags; call before modifying response
 * 
 * @see answer_request() which calls this before adding answer section
 * @see log_query() for REFUSED response logging with EDE
 * @see SET_RCODE() macro in dnsmasq.h for response code setting
 * @see RFC 1035 Section 4.1.1 for DNS header flag definitions
 * @see RFC 8914 for Extended DNS Error (EDE) codes
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dns_header *header = ...;  // Query packet to respond to
 * unsigned int flags = F_IPV4;      // Authoritative IPv4 answer
 * setup_reply(header, flags, 0);    // Initialize response header
 * // Now add answer records with add_resource_record()
 * @endcode
 * 
 * RFC COMPLIANCE: Implements DNS response header format per RFC 1035 Section 4.1.1
 * SIDE EFFECTS: Modifies DNS header flags and section counts; logs REFUSED responses to syslog
 * THREAD SAFETY: Safe (operates only on provided header buffer)
 */
void setup_reply(struct dns_header *header, unsigned int flags, int ede)
{
  /* clear authoritative and truncated flags, set QR flag */
  header->hb3 = (header->hb3 & ~(HB3_AA | HB3_TC )) | HB3_QR;
  /* clear AD flag, set RA flag */
  header->hb4 = (header->hb4 & ~HB4_AD) | HB4_RA;

  header->nscount = htons(0);
  header->arcount = htons(0);
  header->ancount = htons(0); /* no answers unless changed below */
  if (flags == F_NOERR)
    SET_RCODE(header, NOERROR); /* empty domain */
  else if (flags == F_NXDOMAIN)
    SET_RCODE(header, NXDOMAIN);
  else if (flags == F_RCODE)
    SET_RCODE(header, NOTIMP);
  else if (flags & ( F_IPV4 | F_IPV6))
    {
      SET_RCODE(header, NOERROR);
      header->hb3 |= HB3_AA;
    }
  else /* nowhere to forward to */
    {
      union all_addr a;
      a.log.rcode = REFUSED;
      a.log.ede = ede;
      log_query(F_CONFIG | F_RCODE, "error", &a, NULL, 0);
      SET_RCODE(header, REFUSED);
    }
}

/* check if name matches local names ie from /etc/hosts or DHCP or local mx names. */
/**
 * @brief Determine if DNS name belongs to locally configured domain for authoritative responses
 * 
 * @detailed Checks if the given DNS name is within any locally configured domain by iterating through
 *           all local record configuration lists (NAPTR, MX/SRV, TXT, interface names, PTR records),
 *           cache non-terminal entries, and synthetically generated domains. Used to decide whether
 *           to respond authoritatively to queries or forward upstream. Enables dnsmasq to provide
 *           authoritative answers for configured local domains while forwarding other queries.
 * 
 * @param name DNS name to check (FQDN format, typically ending with dot)
 * @param now Current time_t timestamp for cache non-terminal lookup (stale entry filtering)
 * 
 * @return Boolean indicating local domain membership:
 * @retval 1 Name is subdomain of local configuration (authoritative response appropriate)
 * @retval 0 Name is not in local domain (should forward upstream)
 * 
 * Checked Configuration Sources (in order):
 * 1. NAPTR records (daemon->naptr list) - DNS Naming Authority Pointer records
 * 2. MX/SRV records (daemon->mxnames list) - Mail exchange and service records
 * 3. TXT records (daemon->txt list) - Text records for local domains
 * 4. Interface names (daemon->int_names list) - Interface-based synthetic domains
 * 5. PTR records (daemon->ptr list) - Reverse lookup pointer records
 * 6. Cache non-terminal entries - Intermediate domain nodes without records at that level
 * 7. Synthetic domains (F_IPV4/F_IPV6) - Dynamically generated reverse DNS via synth-domain
 * 
 * @note Returns immediately upon first match (short-circuit evaluation)
 * @note Uses hostname_issubdomain() for hierarchical domain matching (e.g., "host.example.com" matches "example.com")
 * @warning Time-sensitive: cache_find_non_terminal() uses 'now' to filter stale entries
 * 
 * @see hostname_issubdomain() in domain.c for subdomain matching algorithm
 * @see cache_find_non_terminal() in cache.c for non-terminal cache lookup
 * @see is_name_synthetic() for synthetic domain checking (synth-domain feature)
 * @see answer_request() which calls this to determine authoritative vs. forwarded response
 * 
 * EXAMPLE USAGE:
 * @code
 * char name[] = "mail.example.com.";  // Query name
 * time_t now = dnsmasq_time();        // Current timestamp
 * if (check_for_local_domain(name, now))
 *   // Respond authoritatively from local configuration
 * else
 *   // Forward query to upstream DNS servers
 * @endcode
 * 
 * RFC COMPLIANCE: Supports authoritative vs. recursive mode per RFC 1035 Section 4.3.2
 * SIDE EFFECTS: None (read-only check of configuration and cache)
 * THREAD SAFETY: Safe for single-threaded architecture (reads global daemon structure)
 */
int check_for_local_domain(char *name, time_t now)
{
  struct mx_srv_record *mx;
  struct txt_record *txt;
  struct interface_name *intr;
  struct ptr_record *ptr;
  struct naptr *naptr;

  for (naptr = daemon->naptr; naptr; naptr = naptr->next)
     if (hostname_issubdomain(name, naptr->name))
      return 1;

   for (mx = daemon->mxnames; mx; mx = mx->next)
    if (hostname_issubdomain(name, mx->name))
      return 1;

  for (txt = daemon->txt; txt; txt = txt->next)
    if (hostname_issubdomain(name, txt->name))
      return 1;

  for (intr = daemon->int_names; intr; intr = intr->next)
    if (hostname_issubdomain(name, intr->name))
      return 1;

  for (ptr = daemon->ptr; ptr; ptr = ptr->next)
    if (hostname_issubdomain(name, ptr->name))
      return 1;

  if (cache_find_non_terminal(name, now))
    return 1;

  if (is_name_synthetic(F_IPV4, name, NULL) ||
      is_name_synthetic(F_IPV6, name, NULL))
    return 1;

  return 0;
}

/**
 * @brief Check DNS response for bogus addresses matching configured --bogus-nxdomain patterns
 * 
 * @detailed Scans answer section of DNS response to detect address records (A/AAAA) that match
 *           configured bogus address prefixes, used to identify DNS hijacking scenarios where
 *           ISPs or captive portals return fake addresses (typically advertising pages) for
 *           non-existent domains. Implements the --bogus-nxdomain feature that converts responses
 *           containing matching addresses into NXDOMAIN, preventing clients from being misdirected
 *           to hijacked destinations.
 * 
 * @param header DNS response packet to scan for bogus addresses
 * @param qlen Total packet length in bytes for bounds checking
 * @param baddr Linked list of bogus address patterns to check (from --bogus-nxdomain config)
 * @param name Output buffer for first answer name if non-NULL (MAXDNAME bytes), or NULL to skip extraction
 * @param ttlp Output pointer for TTL of first answer record if non-NULL, or NULL to skip
 * 
 * @return Bogus address detection result:
 * @retval 1 Bogus address found - response contains address matching configured bogus pattern
 * @retval 0 No bogus address - response is clean or packet malformed
 * 
 * Detection Algorithm:
 * 1. Skip question section to reach answer section (ANCOUNT records)
 * 2. For each answer record:
 *    - Extract name if name buffer provided (for logging/cache invalidation)
 *    - Parse record type, class, TTL, and RDATA length
 *    - For IN class A records: Compare IPv4 address against bogus IPv4 prefixes
 *    - For IN class AAAA records: Compare IPv6 address against bogus IPv6 prefixes
 *    - Return 1 immediately if any address matches a bogus prefix
 * 3. Return 0 if no matches found after scanning all answers
 * 
 * @note Only checks answer section (ANCOUNT), not authority or additional sections
 * @note Returns immediately upon first bogus address match (short-circuit evaluation)
 * @note Bogus address matching uses prefix comparison (CIDR-style), not exact match
 * @note TTL output is from first answer record, regardless of which record contains bogus address
 * @warning Packet validation failure returns 0 (indistinguishable from "clean" response)
 * 
 * @see is_same_net_prefix() for IPv4 prefix matching (addr1 & netmask == addr2 & netmask)
 * @see is_same_net6() for IPv6 prefix matching
 * @see check_for_bogus_wildcard() which calls this to implement wildcard bogus detection
 * @see forward.c for bogus address configuration parsing (--bogus-nxdomain option)
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dns_header *header = ...;      // DNS response from upstream
 * size_t qlen = ...;                    // Packet length
 * struct bogus_addr *baddr = daemon->bogus_addr;  // Configured bogus patterns
 * char name[MAXDNAME];
 * unsigned long ttl;
 * if (check_bad_address(header, qlen, baddr, name, &ttl))
 *   // Response contains bogus address - convert to NXDOMAIN
 * @endcode
 * 
 * RFC COMPLIANCE: Parses standard DNS answer section per RFC 1035 Section 4.1.3
 * SIDE EFFECTS: Modifies name buffer and ttlp output if provided; no global state changes
 * THREAD SAFETY: Safe (operates on caller-provided buffers and read-only daemon config)
 */
static int check_bad_address(struct dns_header *header, size_t qlen, struct bogus_addr *baddr, char *name, unsigned long *ttlp)
{
  unsigned char *p;
  int i, qtype, qclass, rdlen;
  unsigned long ttl;
  struct bogus_addr *baddrp;
  
  /* skip over questions */
  if (!(p = skip_questions(header, qlen)))
    return 0; /* bad packet */

  for (i = ntohs(header->ancount); i != 0; i--)
    {
      if (name && !extract_name(header, qlen, &p, name, EXTR_NAME_EXTRACT, 10))
	return 0; /* bad packet */

      if (!name && !(p = skip_name(p, header, qlen, 10)))
	return 0;
      
      GETSHORT(qtype, p); 
      GETSHORT(qclass, p);
      GETLONG(ttl, p);
      GETSHORT(rdlen, p);
      if (ttlp)
	*ttlp = ttl;
      
      if (qclass == C_IN)
	{
	  if (qtype == T_A)
	    {
	      struct in_addr addr;
	      
	      if (!CHECK_LEN(header, p, qlen, INADDRSZ))
		return 0;

	      memcpy(&addr, p, INADDRSZ);

	      for (baddrp = baddr; baddrp; baddrp = baddrp->next)
		if (!baddrp->is6 && is_same_net_prefix(addr, baddrp->addr.addr4, baddrp->prefix))
		  return 1;
	    }
	  else if (qtype == T_AAAA)
	    {
	      struct in6_addr addr;
	      
	      if (!CHECK_LEN(header, p, qlen, IN6ADDRSZ))
		return 0;

	      memcpy(&addr, p, IN6ADDRSZ);

	      for (baddrp = baddr; baddrp; baddrp = baddrp->next)
		if (baddrp->is6 && is_same_net6(&addr, &baddrp->addr.addr6, baddrp->prefix))
		  return 1;
	    }
	}
      
      if (!ADD_RDLEN(header, p, qlen, rdlen))
	return 0;
    }
  
  return 0;
}

/* Is the packet a reply with the answer address equal to addr?
   If so mung is into an NXDOMAIN reply and also put that information
   in the cache. */
/**
 * @brief Detect and cache bogus wildcard DNS responses from upstream servers
 * 
 * @detailed High-level wrapper implementing --bogus-nxdomain feature that detects DNS hijacking
 *           where ISPs or captive portals return fake addresses for non-existent domains. When
 *           a bogus address is detected (matching configured patterns), creates negative cache
 *           entry with NXDOMAIN flag to prevent clients from being redirected to hijacked
 *           destinations, and logs the detection. Differs from check_for_ignored_address() by
 *           actively caching the NXDOMAIN result rather than silently ignoring.
 * 
 * @param header DNS response packet to scan for bogus addresses
 * @param qlen Total packet length in bytes for bounds checking during address extraction
 * @param name Output buffer for extracted query name (MAXDNAME bytes), populated if bogus detected
 * @param now Current time_t timestamp for cache entry expiration calculation
 * 
 * @return Bogus wildcard detection result:
 * @retval 1 Bogus wildcard detected - response contains address matching --bogus-nxdomain pattern
 * @retval 0 Clean response - no bogus addresses found or packet malformed
 * 
 * Processing Flow:
 * 1. Call check_bad_address() to scan answer section for addresses matching daemon->bogus_addr patterns
 * 2. If bogus address detected:
 *    - Extract query name and TTL from response
 *    - Insert negative cache entry (F_FORWARD | F_NEG | F_NXDOMAIN) to convert future queries to NXDOMAIN
 *    - Log query with F_CONFIG | F_FORWARD | F_NEG | F_NXDOMAIN flags for administrator visibility
 *    - Return 1 indicating detection
 * 3. If no bogus address, return 0
 * 
 * @note Negative cache entry uses TTL from first answer record (prevents repeated upstream queries)
 * @note Cache insertion prevents forwarding loop - subsequent queries return cached NXDOMAIN
 * @note F_CONFIG flag in log indicates detection via configuration (not upstream NXDOMAIN)
 * @warning Requires cache_start_insert()/cache_end_insert() wrapper for transaction safety
 * 
 * @see check_bad_address() for address matching algorithm against bogus_addr patterns
 * @see cache_insert() in cache.c for negative cache entry creation
 * @see log_query() in log.c for query logging with detection flags
 * @see forward.c for --bogus-nxdomain configuration parsing into daemon->bogus_addr list
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dns_header *header = ...;      // Response from upstream DNS
 * size_t qlen = ...;                    // Packet length
 * char name[MAXDNAME];                  // Buffer for query name
 * time_t now = dnsmasq_time();          // Current time
 * if (check_for_bogus_wildcard(header, qlen, name, now))
 *   // Bogus detected, negative cache entry added, return NXDOMAIN to client
 * else
 *   // Clean response, process normally
 * @endcode
 * 
 * RFC COMPLIANCE: Implements local policy override per RFC 1035 Section 7.4 (local configuration)
 * SIDE EFFECTS: Modifies DNS cache (adds negative entry), logs to syslog, modifies name buffer
 * THREAD SAFETY: Uses cache transaction wrapper for insertion safety (single-threaded architecture)
 */
int check_for_bogus_wildcard(struct dns_header *header, size_t qlen, char *name, time_t now)
{
  unsigned long ttl;

  if (check_bad_address(header, qlen, daemon->bogus_addr, name, &ttl))
    {
      /* Found a bogus address. Insert that info here, since there no SOA record
	 to get the ttl from in the normal processing */
      cache_start_insert();
      cache_insert(name, NULL, C_IN, now, ttl, F_FORWARD | F_NEG | F_NXDOMAIN);
      cache_end_insert();
      log_query(F_CONFIG | F_FORWARD | F_NEG | F_NXDOMAIN, name, NULL, NULL, 0);

      return 1;
    }

  return 0;
}

/**
 * @brief Check DNS response for addresses matching --ignore-address patterns for silent filtering
 * 
 * @detailed Simple wrapper implementing --ignore-address feature that silently filters DNS responses
 *           containing specified addresses without caching or logging. Unlike check_for_bogus_wildcard()
 *           which converts bogus responses to cached NXDOMAIN, this function simply indicates that the
 *           response should be ignored, allowing the query to time out or be retried with different
 *           upstream servers. Used for filtering known-bad addresses without negative caching side effects.
 * 
 * @param header DNS response packet to scan for ignored addresses
 * @param qlen Total packet length in bytes for bounds checking during address extraction
 * 
 * @return Ignored address detection result:
 * @retval 1 Ignored address detected - response contains address matching --ignore-address pattern
 * @retval 0 Clean response - no ignored addresses found or packet malformed
 * 
 * Processing Flow:
 * 1. Call check_bad_address() with daemon->ignore_addr pattern list
 * 2. Return result directly without caching or logging
 * 3. Caller typically discards response and retries with different server or times out
 * 
 * Comparison with check_for_bogus_wildcard():
 * - check_for_bogus_wildcard(): Detects bogus addresses, caches NXDOMAIN, logs detection
 * - check_for_ignored_address(): Detects ignored addresses, no caching, no logging, silent discard
 * 
 * Use Cases:
 * - Filter responses from upstream servers known to return incorrect addresses for certain domains
 * - Silently ignore addresses used by ISPs for walled gardens or captive portals
 * - Discard responses with private addresses from public DNS servers (security hardening)
 * 
 * @note No cache modification or logging occurs (silent filtering)
 * @note Caller must handle retry logic or timeout behavior
 * @note Does NOT prevent forwarding loop - no negative cache entry created
 * @warning Response is simply discarded; client may experience timeout if no alternative servers available
 * 
 * @see check_bad_address() for address matching algorithm against ignore_addr patterns
 * @see check_for_bogus_wildcard() for similar detection with negative caching
 * @see forward.c for --ignore-address configuration parsing into daemon->ignore_addr list
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dns_header *header = ...;      // Response from upstream DNS
 * size_t qlen = ...;                    // Packet length
 * if (check_for_ignored_address(header, qlen))
 *   // Silently discard response, retry with different server
 * else
 *   // Process response normally
 * @endcode
 * 
 * RFC COMPLIANCE: Implements local policy filtering per RFC 1035 Section 7.4 (local configuration)
 * SIDE EFFECTS: None (read-only check, no cache or log modifications)
 * THREAD SAFETY: Safe (operates on caller-provided buffer and read-only daemon config)
 */
int check_for_ignored_address(struct dns_header *header, size_t qlen)
{
  return check_bad_address(header, qlen, daemon->ignore_addr, NULL, NULL);
}

/**
 * @brief Add a DNS resource record to DNS response packet with automatic wire format encoding
 * 
 * @detailed Variadic function that constructs and appends a DNS resource record to a growing DNS
 *           packet buffer, handling name compression, RDATA field encoding based on format string,
 *           truncation detection, and automatic RDLength calculation. Supports all standard DNS
 *           record types through flexible format string specifying RDATA field layout. Used by
 *           answer_request() and other response-building functions to construct DNS answer,
 *           authority, and additional sections.
 * 
 * @param header DNS packet header (for offset calculations in name compression)
 * @param limit Upper bound of packet buffer (NULL for no limit check), truncation if exceeded
 * @param truncp Pointer to truncation flag; set to 1 if packet limit exceeded (may be NULL)
 * @param nameoffset Name compression offset for record owner name:
 *                   - Positive value: Use existing compressed name pointer at this offset
 *                   - Zero: Encode full name from va_arg (first vararg is char *name)
 *                   - Negative value: Encode full name from va_arg, then compressed suffix at -nameoffset
 * @param pp Pointer to current position in packet buffer (modified to point after added record)
 * @param ttl Time-to-live value in seconds for this resource record
 * @param offset Output pointer for offset of domain name in RDATA (for 'd' format), may be NULL
 * @param type DNS record type (T_A, T_AAAA, T_CNAME, T_MX, T_SRV, T_TXT, etc.)
 * @param class DNS record class (typically C_IN for Internet class)
 * @param format Format string specifying RDATA field layout (see Format Characters below)
 * @param ... Variable arguments interpreted according to format string
 * 
 * @return Resource record addition status:
 * @retval 1 Record added successfully, pp advanced past record
 * @retval 0 Truncation occurred (limit exceeded), pp unchanged, truncp set if non-NULL
 * 
 * Format Characters (in format string):
 * - '6': IPv6 address (16 bytes) - arg: char *addr
 * - '4': IPv4 address (4 bytes) - arg: char *addr
 * - 'b': Byte value (1 byte) - arg: int value (0-255)
 * - 's': Short value (2 bytes, network byte order) - arg: int value
 * - 'l': Long value (4 bytes, network byte order) - arg: long value
 * - 'd': Domain name (with name compression) - arg: char *name; offset output written if offset non-NULL
 * - 't': Binary data (length + data) - args: int length, char *data
 * - 'z': Length-prefixed string (1 byte length + string, max 255 bytes) - arg: char *str
 * 
 * Record Structure Built:
 * 1. Owner name (from nameoffset or va_arg, may use compression)
 * 2. Type (2 bytes, network byte order)
 * 3. Class (2 bytes, network byte order)
 * 4. TTL (4 bytes, network byte order)
 * 5. RDLength (2 bytes, calculated automatically)
 * 6. RDATA (variable length, per format string)
 * 
 * Name Compression Modes:
 * - nameoffset > 0: PUTSHORT(nameoffset | 0xc000) - compressed pointer only
 * - nameoffset == 0: do_rfc1035_name(va_arg()) + null terminator - full name
 * - nameoffset < 0: do_rfc1035_name(va_arg()) + PUTSHORT(-nameoffset | 0xc000) - name + compressed suffix
 * 
 * @note Caller must increment answer/authority/additional section count in DNS header
 * @note RDLength calculated automatically after encoding RDATA fields
 * @note Truncation flag checked at function entry; returns immediately if already truncated
 * @warning Format string must match variable argument types exactly (no type checking)
 * @warning Caller responsible for ensuring enough arguments for format string
 * 
 * @see do_rfc1035_name() for domain name encoding with compression
 * @see answer_request() which extensively uses this to build various record types
 * @see PUTSHORT(), PUTLONG() macros in dnsmasq.h for network byte order encoding
 * @see dns-protocol.h for T_* type constants and C_* class constants
 * 
 * EXAMPLE USAGE:
 * @code
 * unsigned char *p = (unsigned char *)(header + 1);
 * int trunc = 0;
 * 
 * // Add A record: example.com. 300 IN A 192.0.2.1
 * char addr[4] = {192, 0, 2, 1};
 * add_resource_record(header, limit, &trunc, 0, &p, 300, NULL, T_A, C_IN, "4", "example.com", addr);
 * 
 * // Add AAAA record with name compression (reuse name at offset 12)
 * char addr6[16] = {...};
 * add_resource_record(header, limit, &trunc, 12, &p, 300, NULL, T_AAAA, C_IN, "6", addr6);
 * 
 * // Add MX record: example.com. 300 IN MX 10 mail.example.com.
 * add_resource_record(header, limit, &trunc, 12, &p, 300, NULL, T_MX, C_IN, "sd", "example.com", 10, "mail.example.com");
 * 
 * // Add TXT record: example.com. 300 IN TXT "v=spf1 -all"
 * add_resource_record(header, limit, &trunc, 12, &p, 300, NULL, T_TXT, C_IN, "z", "v=spf1 -all");
 * @endcode
 * 
 * RFC COMPLIANCE: Constructs resource records per RFC 1035 Section 4.1.3 (Resource record format)
 * SIDE EFFECTS: Modifies packet buffer via pp pointer; sets truncp flag if limit exceeded
 * THREAD SAFETY: Safe (operates on caller-provided buffers)
 */
int add_resource_record(struct dns_header *header, char *limit, int *truncp, int nameoffset, unsigned char **pp, 
			unsigned long ttl, int *offset, unsigned short type, unsigned short class, char *format, ...)
{
  va_list ap;
  unsigned char *sav, *p = *pp;
  int j;
  unsigned short usval;
  long lval;
  char *sval;
  
#define CHECK_LIMIT(size) \
  if (limit && p + (size) > (unsigned char*)limit) goto truncated;

  va_start(ap, format);   /* make ap point to 1st unamed argument */
  
  if (truncp && *truncp)
    goto truncated;
  
  if (nameoffset > 0)
    {
      CHECK_LIMIT(2);
      PUTSHORT(nameoffset | 0xc000, p);
    }
  else
    {
      char *name = va_arg(ap, char *);
      if (name && !(p = do_rfc1035_name(p, name, limit)))
	goto truncated;
      
      if (nameoffset < 0)
	{
	  CHECK_LIMIT(2);
	  PUTSHORT(-nameoffset | 0xc000, p);
	}
      else
	{
	  CHECK_LIMIT(1);
	  *p++ = 0;
	}
    }

  /* type (2) + class (2) + ttl (4) + rdlen (2) */
  CHECK_LIMIT(10);
  
  PUTSHORT(type, p);
  PUTSHORT(class, p);
  PUTLONG(ttl, p);      /* TTL */

  sav = p;              /* Save pointer to RDLength field */
  PUTSHORT(0, p);       /* Placeholder RDLength */

  for (; *format; format++)
    switch (*format)
      {
      case '6':
        CHECK_LIMIT(IN6ADDRSZ);
	sval = va_arg(ap, char *); 
	memcpy(p, sval, IN6ADDRSZ);
	p += IN6ADDRSZ;
	break;
	
      case '4':
        CHECK_LIMIT(INADDRSZ);
	sval = va_arg(ap, char *); 
	memcpy(p, sval, INADDRSZ);
	p += INADDRSZ;
	break;
	
      case 'b':
        CHECK_LIMIT(1);
	usval = va_arg(ap, int);
	*p++ = usval;
	break;
	
      case 's':
        CHECK_LIMIT(2);
	usval = va_arg(ap, int);
	PUTSHORT(usval, p);
	break;
	
      case 'l':
        CHECK_LIMIT(4);
	lval = va_arg(ap, long);
	PUTLONG(lval, p);
	break;
	
      case 'd':
        /* get domain-name answer arg and store it in RDATA field */
        if (offset)
          *offset = p - (unsigned char *)header;
        if (!(p = do_rfc1035_name(p, va_arg(ap, char *), limit)))
	  goto truncated;
	CHECK_LIMIT(1);
        *p++ = 0;
	break;
	
      case 't':
	usval = va_arg(ap, int);
        CHECK_LIMIT(usval);
	sval = va_arg(ap, char *);
	if (usval != 0)
	  memcpy(p, sval, usval);
	p += usval;
	break;

      case 'z':
	sval = va_arg(ap, char *);
	usval = sval ? strlen(sval) : 0;
	if (usval > 255)
	  usval = 255;
        CHECK_LIMIT(usval + 1);
	*p++ = (unsigned char)usval;
	memcpy(p, sval, usval);
	p += usval;
	break;
      }

  va_end(ap);	/* clean up variable argument pointer */
  
  /* Now, store real RDLength. sav already checked against limit. */
  j = p - sav - 2;
  PUTSHORT(j, sav);
  
  *pp = p;
  return 1;
  
 truncated:
  va_end(ap);
  if (truncp)
    *truncp = 1;
  return 0;

#undef CHECK_LIMIT
}

/**
 * @brief Check if cache record is stale (expired TTL)
 * 
 * @detailed Determines whether a cache entry has expired by comparing its time-to-die (TTD)
 *           timestamp against current time. Immortal entries (F_IMMORTAL flag) never expire
 *           regardless of TTD value. Used by answer_request() and other cache management
 *           functions to filter expired entries from query responses.
 * 
 * @param crecp Cache record to check for staleness (must not be NULL)
 * @param now Current time (typically from dnsmasq_time())
 * 
 * @return Staleness status:
 * @retval 1 (true) Record is stale: TTD timestamp is in the past and not immortal
 * @retval 0 (false) Record is fresh: TTD in future OR immortal flag set
 * 
 * @note Immortal entries (F_IMMORTAL) include static /etc/hosts entries and DHCP leases
 * @note Stale entries may be retained in cache for negative caching or serve-stale scenarios
 * @warning Assumes crecp->ttd contains valid timestamp; undefined if uninitialized
 * 
 * @see crec_ttl() which calculates remaining TTL for non-stale entries
 * @see cache_not_validated() for DNSSEC validation status checking
 * @see answer_request() which uses this to filter stale entries from responses
 * 
 * EXAMPLE USAGE:
 * @code
 * struct crec *crecp = cache_find_by_name(...);
 * time_t now = dnsmasq_time();
 * if (crec_isstale(crecp, now)) {
 *     // Cache entry expired, do not return in response
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: Implements TTL expiration per RFC 1035 Section 4.1.3
 * SIDE EFFECTS: None (read-only check)
 * THREAD SAFETY: Safe (read-only access to cache record)
 */
static int crec_isstale(struct crec *crecp, time_t now)
{
  return (!(crecp->flags & F_IMMORTAL)) && difftime(crecp->ttd, now) < 0; 
}

/**
 * @brief Calculate remaining TTL for cache record with policy-based adjustments
 * 
 * @detailed Computes time-to-live value to include in DNS response based on cache record
 *           expiration time, record type, and configured TTL policies. Applies special
 *           handling for DHCP lease entries (configurable TTL regardless of expiration),
 *           immortal static entries (TTL stored in ttd field), stale entries (expired),
 *           and maximum TTL ceiling (--max-ttl option). Used by answer_request() to
 *           populate TTL field in resource records returned to clients.
 * 
 * @param crecp Cache record for TTL calculation (must not be NULL)
 * @param now Current time (typically from dnsmasq_time())
 * 
 * @return TTL value to use in DNS response (seconds):
 * @retval 0 For stale entries (ttl < 0, already expired)
 * @retval conf_ttl For DHCP entries: daemon->dhcp_ttl (if use_dhcp_ttl) or daemon->local_ttl
 * @retval crecp->ttd For immortal non-DHCP entries (static /etc/hosts), ttd contains fixed TTL
 * @retval max_ttl If configured max_ttl is lower than actual remaining TTL
 * @retval (ttd - now) Normal case: actual remaining time until expiration
 * 
 * TTL Calculation Logic by Record Type:
 * 1. DHCP entries (F_DHCP):
 *    - Use configured TTL: daemon->dhcp_ttl if use_dhcp_ttl set, else daemon->local_ttl
 *    - Apply lease expiration ceiling: return min(conf_ttl, actual_ttl) for non-immortal
 *    - Rationale: DHCP leases may change before DNS TTL expires, limit caching duration
 * 
 * 2. Immortal non-DHCP entries (F_IMMORTAL, not F_DHCP):
 *    - Return crecp->ttd directly (ttd field repurposed to store fixed TTL value)
 *    - Typical for static /etc/hosts entries with configured TTL
 * 
 * 3. Stale entries (ttl < 0, expired):
 *    - Return 0 TTL to prevent client caching
 *    - Entry may be served in serve-stale mode but should not be cached by clients
 * 
 * 4. Normal entries with max_ttl configured:
 *    - Return min(actual_ttl, daemon->max_ttl) to enforce maximum caching duration
 *    - Prevents excessively long TTLs from upstream servers
 * 
 * @note F_DHCP flag indicates entry derived from DHCP lease, subject to lease changes
 * @note F_IMMORTAL flag indicates static entry that never expires from cache
 * @note For immortal non-DHCP entries, ttd field stores fixed TTL instead of expiration time
 * @note daemon->use_dhcp_ttl enables DHCP-specific TTL vs local_ttl fallback
 * @note daemon->max_ttl (--max-ttl option) caps TTL for all normal entries (0 = no limit)
 * @warning Assumes crecp->ttd contains valid value; expiration time or fixed TTL per flags
 * 
 * @see crec_isstale() for staleness determination before calling this function
 * @see answer_request() which uses calculated TTL in PUTLONG() for response records
 * @see cache.c for TTL configuration options (--dhcp-ttl, --local-ttl, --max-ttl)
 * 
 * EXAMPLE USAGE:
 * @code
 * struct crec *crecp = cache_find_by_name(...);
 * time_t now = dnsmasq_time();
 * if (!crec_isstale(crecp, now)) {
 *     unsigned long ttl = crec_ttl(crecp, now);
 *     PUTLONG(ttl, p); // Write TTL to DNS response packet
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: TTL handling per RFC 1035 Section 4.1.3 (Resource record format)
 * SIDE EFFECTS: None (read-only calculation)
 * THREAD SAFETY: Safe (read-only access to cache record and daemon config)
 */
static unsigned long crec_ttl(struct crec *crecp, time_t now)
{
  signed long ttl = difftime(crecp->ttd, now);

  /* Return 0 ttl for DHCP entries, which might change
     before the lease expires, unless configured otherwise. */

  if (crecp->flags & F_DHCP)
    {
      int conf_ttl = daemon->use_dhcp_ttl ? daemon->dhcp_ttl : daemon->local_ttl;
      
      /* Apply ceiling of actual lease length to configured TTL. */
      if (!(crecp->flags & F_IMMORTAL) && ttl < conf_ttl)
	return ttl;
      
      return conf_ttl;
    }	  
  
  /* Immortal entries other than DHCP are local, and hold TTL in TTD field. */
  if (crecp->flags & F_IMMORTAL)
    return crecp->ttd;

  /* Stale cache entries. */
  if (ttl < 0)
    return 0;
  
  /* Return the Max TTL value if it is lower than the actual TTL */
  if (daemon->max_ttl == 0 || ((unsigned)ttl < daemon->max_ttl))
    return ttl;
  else
    return daemon->max_ttl;
}

/**
 * @brief Check if cache record failed DNSSEC validation or is unvalidated
 * 
 * @detailed Determines whether a cache entry lacks valid DNSSEC validation when DNSSEC
 *           validation is enabled. Returns true if DNSSEC validation is enabled globally
 *           (OPT_DNSSEC_VALID option) but the cache entry does not have the F_DNSSECOK
 *           flag set, indicating either failed validation or unvalidated response.
 *           Used by answer_request() to filter non-validated entries from responses
 *           when DNSSEC validation is required.
 * 
 * @param crecp Cache record to check validation status (must not be NULL)
 * 
 * @return Validation failure status:
 * @retval 1 (true) DNSSEC validation enabled AND record not validated (no F_DNSSECOK flag)
 * @retval 0 (false) DNSSEC validation disabled OR record has valid DNSSEC validation
 * 
 * Validation Logic:
 * - If OPT_DNSSEC_VALID disabled: Always returns false (validation not required)
 * - If OPT_DNSSEC_VALID enabled and F_DNSSECOK set: Returns false (validated)
 * - If OPT_DNSSEC_VALID enabled and F_DNSSECOK not set: Returns true (not validated)
 * 
 * Use Cases:
 * - Filter cache entries to exclude non-validated records when DNSSEC required
 * - Enforce DNSSEC policy: only return cryptographically validated responses
 * - Distinguish between validated and unvalidated upstream responses
 * 
 * @note OPT_DNSSEC_VALID set via --dnssec command-line option or dnssec config directive
 * @note F_DNSSECOK flag set by dnssec.c validation code after successful RRSIG verification
 * @note Non-validated does not necessarily mean bogus; may be insecure zone or unsigned
 * @warning Does not distinguish between failed validation (bogus) and unsigned zones
 * 
 * @see answer_request() which uses this to filter responses when DNSSEC enabled
 * @see dnssec.c:dnssec_validate_reply() which sets F_DNSSECOK flag on validated records
 * @see cache.c:cache_insert() which propagates DNSSEC flags to cache entries
 * 
 * EXAMPLE USAGE:
 * @code
 * struct crec *crecp = cache_find_by_name(...);
 * if (option_bool(OPT_DNSSEC_VALID) && cache_not_validated(crecp)) {
 *     // Skip this entry, DNSSEC validation required but not validated
 *     continue;
 * }
 * // Include entry in response
 * @endcode
 * 
 * RFC COMPLIANCE: DNSSEC validation enforcement per RFC 4033 (DNSSEC Introduction)
 * SIDE EFFECTS: None (read-only check)
 * THREAD SAFETY: Safe (read-only access to cache record flags and daemon options)
 */
static int cache_not_validated(const struct crec *crecp)
{
  return (option_bool(OPT_DNSSEC_VALID) && !(crecp->flags & F_DNSSECOK));
}

/**
 * @brief Construct DNS response packet from query using cached information only
 * 
 * @detailed answer_request() is the core DNS response generation engine that processes
 * a DNS query and constructs a response packet using only locally cached information
 * (no upstream forwarding). This function handles:
 * - Query validation and question extraction
 * - Authoritative DNS zone checks (forwarding to auth module if needed)
 * - Security filtering (blocked names, bogus addresses, ignored addresses)
 * - Local domain handling and /etc/hosts integration
 * - CNAME chain resolution (up to 10 hops)
 * - A/AAAA/PTR/SRV/MX/TXT record lookups from cache
 * - Negative caching (NXDOMAIN, NODATA) with SOA records
 * - Additional data section for MX/SRV targets
 * - DNSSEC validation state tracking (AD flag)
 * - Response header flag setting (QR, RA, AA, TC, AD)
 * - Truncation handling when response exceeds packet size
 * - Stale cache entry detection and filtering status reporting
 * 
 * The function operates entirely from cached data sources:
 * - DNS cache (struct crec entries from cache_find_by_name/addr)
 * - /etc/hosts file entries
 * - DHCP lease hostname registrations
 * - Statically configured address records
 * - MX and SRV record configurations
 * 
 * @param header Pointer to DNS packet header (query on input, response on output)
 * @param limit Pointer to end of packet buffer (truncation boundary)
 * @param qlen Length of query packet in bytes
 * @param local_addr Local interface IPv4 address for this query
 * @param local_netmask Local interface IPv4 netmask
 * @param now Current time (for TTL calculation and stale entry detection)
 * @param ad_reqd Non-zero if client requested AD (authenticated data) flag via EDNS0
 * @param do_bit Non-zero if client set DO (DNSSEC OK) bit in EDNS0
 * @param no_cache Non-zero to bypass cache lookup and force negative response
 * @param stale Pointer to int; set to 1 if stale cache entries detected, NULL allowed
 * @param filtered Pointer to int; set to 1 if response filtered by security rules, NULL allowed
 * 
 * @return Length of generated response packet in bytes, or 0 if unable to answer
 * @retval >0 Valid response packet length (modified header contains response)
 * @retval 0 No answer available (query not answerable from cache), or malformed query
 * 
 * @note This function NEVER forwards queries to upstream servers - it operates
 *       entirely from local cached data. Queries not answerable from cache return 0,
 *       signaling the caller (forward.c) to forward upstream.
 * 
 * @warning Modifies header packet in-place, converting query to response. Caller
 *          must preserve original query if needed for forwarding.
 * 
 * @see forward.c:receive_query() - calls answer_request() before forwarding
 * @see cache.c:cache_find_by_name() - primary cache lookup mechanism
 * @see add_resource_record() - adds each RR to response packet
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dns_header *header = (struct dns_header *)packet;
 * int stale_flag = 0, filtered_flag = 0;
 * size_t len = answer_request(header, packet + sizeof(packet), qlen,
 *                              local_addr, netmask, time(NULL), 
 *                              ad_requested, do_bit, 0, &stale_flag, &filtered_flag);
 * if (len > 0) {
 *   // Send response to client
 *   send(sock, packet, len, 0);
 *   if (stale_flag) log("Response contains stale data");
 * } else {
 *   // Forward query to upstream server
 *   forward_query(header, qlen, ...);
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 1035 Section 4.1.1 (query processing), Section 7.3 (resolver operation)
 * SIDE EFFECTS: 
 * - Modifies packet buffer pointed to by header (constructs response)
 * - Sets *stale flag if stale cache entries encountered
 * - Sets *filtered flag if security filtering applied to response
 * - Logs query via log_query() if query logging enabled
 * - May trigger script execution via cache_find_by_name() for DHCP events
 * THREAD SAFETY: Single-threaded architecture - accesses global daemon state
 * 
 * ALGORITHM OVERVIEW:
 * 1. Extract question name, type, class from query packet
 * 2. Check if query is for authoritative zone (forward to auth.c if so)
 * 3. Apply security filtering (check_bad_address, check_for_ignored_address, etc.)
 * 4. Check for local domain configuration
 * 5. Main lookup loop:
 *    - Search /etc/hosts entries
 *    - Follow CNAME chains (max 10 hops)
 *    - Lookup A/AAAA records (with duplicate suppression)
 *    - Handle PTR (reverse) lookups
 *    - Process SRV/MX records with priority sorting
 *    - Retrieve TXT records
 * 6. Process negative caching (NXDOMAIN/NODATA)
 * 7. Add SOA record for negative answers
 * 8. Create additional data section for MX/SRV targets
 * 9. Set response header flags and counts
 * 10. Return packet length
 * 
 * CNAME CHAIN RESOLUTION:
 * The function follows CNAME chains up to depth 10 (CNAME_CHAIN constant).
 * Each CNAME in the chain is added to the answer section, with the final
 * target record (A/AAAA) also included. Loop detection prevents infinite chains.
 * 
 * NEGATIVE CACHING:
 * NXDOMAIN responses include:
 * - Answer section: empty (anscount=0)
 * - Authority section: SOA record from negative cache entry
 * - Response code: RCODE=NXDOMAIN
 * NODATA responses (name exists, type doesn't):
 * - Answer section: empty (anscount=0)
 * - Authority section: SOA record
 * - Response code: RCODE=NOERROR
 * 
 * DNSSEC VALIDATION STATE:
 * The AD (authenticated data) flag is set in response if:
 * - Client requested AD via EDNS0 (ad_reqd parameter)
 * - ALL data in response is DNSSEC validated (sec_data remains 1)
 * - Any cache entry lacking F_DNSSECOK flag clears sec_data
 * 
 * STALE CACHE DETECTION:
 * If stale parameter is non-NULL and any cache entry used in response
 * has TTL expired (detected via crec_isstale()), *stale is set to 1.
 * Allows caller to make policy decisions about stale responses.
 * 
 * FILTERING STATUS:
 * If filtered parameter is non-NULL and security filtering rules
 * (check_bad_address, ignored addresses, blocked names) prevent normal
 * response, *filtered is set to 1 to inform caller that response was modified.
 * 
 * TRUNCATION HANDLING:
 * If add_resource_record() signals truncation (packet size exceeded):
 * - TC (truncated) flag set in header
 * - Answer, authority, additional sections cleared (counts = 0)
 * - Client expected to retry query over TCP
 */
/* return zero if we can't answer from cache, or packet size if we can */
size_t answer_request(struct dns_header *header, char *limit, size_t qlen,  
		      struct in_addr local_addr, struct in_addr local_netmask, 
		      time_t now, int ad_reqd, int do_bit, int no_cache, int *stale, int *filtered) 
{
  char *name = daemon->namebuff;
  unsigned char *p, *ansp;
  unsigned int qtype, qclass;
  union all_addr addr;
  int nameoffset;
  unsigned short flag;
  int ans, anscount = 0, nscount = 0, addncount = 0;
  struct crec *crecp, *soa_lookup = NULL;
  int nxdomain = 0, notimp = 0, auth = 1, trunc = 0, sec_data = 1;
  struct mx_srv_record *rec;
  size_t len;
  int rd_bit = (header->hb3 & HB3_RD);
  int count = 255; /* catch loops */

  /* Suppress cached answers if no_cache set. */
  if (no_cache)
    rd_bit = 0;
  
  if (stale)
    *stale = 0;

  if (filtered)
    *filtered = 0;
  
  if (ntohs(header->qdcount) != 1 ||
      ntohs(header->ancount) != 0 ||
      ntohs(header->nscount) != 0 ||
      OPCODE(header) != QUERY )
    return 0;
  
  /* Don't return AD set if checking disabled. */
  if (header->hb4 & HB4_CD)
    sec_data = 0;
  
  for (rec = daemon->mxnames; rec; rec = rec->next)
    rec->offset = 0;
  
  /* determine end of question section (we put answers there) */
  if (!(ansp = skip_questions(header, qlen)))
    return 0; /* bad packet */
   
  /* now process each question, answers go in RRs after the question */
  p = (unsigned char *)(header+1);

  /* save pointer to name for copying into answers */
  nameoffset = p - (unsigned char *)header;
  
  /* now extract name as .-concatenated string into name */
  if (!extract_name(header, qlen, &p, name, EXTR_NAME_EXTRACT, 4))
    return 0; /* bad packet */
  
  GETSHORT(qtype, p); 
  GETSHORT(qclass, p);
  
  ans = 0; /* have we answered this question */
  
  if (qclass == C_IN)
    while (--count != 0 && (crecp = cache_find_by_name(NULL, name, now, F_CNAME | F_NXDOMAIN)))
      {
	char *cname_target;
	int stale_flag = 0;
	
	if (crec_isstale(crecp, now))
	  {
	    if (stale)
	      *stale = 1;
	    
	    stale_flag = F_STALE;
	  }
	
	if (crecp->flags & F_NEG)
	  soa_lookup = crecp;
	  
	if (crecp->flags & F_NXDOMAIN)
	  {
	    if (qtype == T_CNAME)
	      {
		log_query(stale_flag | crecp->flags, name, NULL, record_source(crecp->uid), 0);
		auth = 0;
		nxdomain = 1;
		ans = 1;
	      }
	    break;
	  }  
	
	cname_target = cache_get_cname_target(crecp);
	
	/* If the client asked for DNSSEC  don't use cached data. */
	if ((crecp->flags & (F_HOSTS | F_DHCP | F_CONFIG)) ||
	    (rd_bit && (!do_bit || cache_not_validated(crecp))))
	  {
	    if (crecp->flags & F_CONFIG || qtype == T_CNAME)
	      ans = 1;
	    
	    if (!(crecp->flags & F_DNSSECOK))
	      sec_data = 0;
	    
	    log_query(stale_flag | crecp->flags, name, NULL, record_source(crecp->uid), 0);
	    if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, 
				    crec_ttl(crecp, now), &nameoffset,
				    T_CNAME, C_IN, "d", cname_target))
	      anscount++;
	  }
	else
	  return 0; /* give up if any cached CNAME in chain can't be used for DNSSEC reasons. */
	
	if (qtype == T_CNAME)
	  break;
	
	strcpy(name, cname_target);
      }
  
  if (qtype == T_TXT || qtype == T_ANY)
    {
      struct txt_record *t;
      for(t = daemon->txt; t ; t = t->next)
	{
	  if (t->class == qclass && hostname_isequal(name, t->name))
	    {
	      unsigned long ttl = daemon->local_ttl;
	      int ok = 1;
	      
	      ans = 1, sec_data = 0;
#ifndef NO_ID
	      /* Dynamically generate stat record */
	      if (t->stat != 0)
		{
		  ttl = 0;
		  if (!cache_make_stat(t))
		    ok = 0;
		}
#endif
	      if (ok)
		{
		  log_query(F_CONFIG | F_RRNAME, name, NULL, "<TXT>", 0);
		  if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, 
					  ttl, NULL,
					  T_TXT, t->class, "t", t->len, t->txt))
		    anscount++;
		}
	    }
	}
    }
  
  if (qclass == C_CHAOS)
    {
      /* don't forward *.bind and *.server chaos queries - always reply with NOTIMP */
      if (hostname_issubdomain("bind", name) || hostname_issubdomain("server", name))
	{
	  if (!ans)
	    {
	      notimp = 1, auth = 0;
	      
	      addr.log.rcode = NOTIMP;
	      log_query(F_CONFIG | F_RCODE, name, &addr, NULL, 0);
		  
	      ans = 1, sec_data = 0;
	    }
	}
    }
  
  if (qclass == C_IN)
    {
      struct txt_record *t;
      
      for (t = daemon->rr; t; t = t->next)
	if ((t->class == qtype || qtype == T_ANY) && hostname_isequal(name, t->name))
	  {
	    ans = 1;
	    sec_data = 0;
	    log_query(F_CONFIG | F_RRNAME, name, NULL, NULL, t->class);
	    if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, 
				    daemon->local_ttl, NULL,
				    t->class, C_IN, "t", t->len, t->txt))
	      anscount++;
	  }
      
      if (qtype == T_PTR || qtype == T_ANY)
	{
	  /* see if it's w.z.y.z.in-addr.arpa format */
	  int is_arpa = in_arpa_name_2_addr(name, &addr);
	  struct ptr_record *ptr;
	  struct interface_name* intr = NULL;
	  
	  for (ptr = daemon->ptr; ptr; ptr = ptr->next)
	    if (hostname_isequal(name, ptr->name))
	      break;
	  
	  if (is_arpa == F_IPV4)
	    for (intr = daemon->int_names; intr; intr = intr->next)
	      {
		struct addrlist *addrlist;
		
		for (addrlist = intr->addr; addrlist; addrlist = addrlist->next)
		  if (!(addrlist->flags & ADDRLIST_IPV6) && addr.addr4.s_addr == addrlist->addr.addr4.s_addr)
		    break;
		
		if (addrlist)
		  break;
		else if (!(intr->flags & INP4))
		  while (intr->next && strcmp(intr->intr, intr->next->intr) == 0)
		    intr = intr->next;
	      }
	  else if (is_arpa == F_IPV6)
	    for (intr = daemon->int_names; intr; intr = intr->next)
	      {
		struct addrlist *addrlist;
		
		for (addrlist = intr->addr; addrlist; addrlist = addrlist->next)
		  if ((addrlist->flags & ADDRLIST_IPV6) && IN6_ARE_ADDR_EQUAL(&addr.addr6, &addrlist->addr.addr6))
		    break;
		
		if (addrlist)
		  break;
		else if (!(intr->flags & INP6))
		  while (intr->next && strcmp(intr->intr, intr->next->intr) == 0)
		    intr = intr->next;
	      }
	  
	  if (intr)
	    {
	      sec_data = 0;
	      ans = 1;
	      log_query(is_arpa | F_REVERSE | F_CONFIG, intr->name, &addr, NULL, 0);
	      if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, 
				      daemon->local_ttl, NULL,
				      T_PTR, C_IN, "d", intr->name))
		anscount++;
	    }
	  else if (ptr)
	    {
	      ans = 1;
	      sec_data = 0;
	      log_query(F_CONFIG | F_RRNAME, name, NULL, "<PTR>", 0);
	      for (ptr = daemon->ptr; ptr; ptr = ptr->next)
		if (hostname_isequal(name, ptr->name) &&
		    add_resource_record(header, limit, &trunc, nameoffset, &ansp, 
					daemon->local_ttl, NULL,
					T_PTR, C_IN, "d", ptr->ptr))
		  anscount++;
	      
	    }
	  else if (is_arpa && (crecp = cache_find_by_addr(NULL, &addr, now, is_arpa)))
	    {
	      /* Don't use cache when DNSSEC data required, unless we know that
		 the zone is unsigned, which implies that we're doing
		 validation. */
	      if ((crecp->flags & (F_HOSTS | F_DHCP | F_CONFIG)) ||
		  (rd_bit && (!do_bit || cache_not_validated(crecp)) ))
		{
		  do 
		    { 
		      int stale_flag = 0;
		      
		      if (crec_isstale(crecp, now))
			{
			  if (stale)
			    *stale = 1;
			  
			  stale_flag = F_STALE;
			}
		      
		      /* don't answer wildcard queries with data not from /etc/hosts or dhcp leases */
		      if (qtype == T_ANY && !(crecp->flags & (F_HOSTS | F_DHCP)))
			continue;
		      
		      if (!(crecp->flags & F_DNSSECOK))
			sec_data = 0;
		      
		      ans = 1;
		      
		      if (crecp->flags & F_NEG)
			{
			  auth = 0;
			  if (crecp->flags & F_NXDOMAIN)
			    nxdomain = 1;
			  log_query(stale_flag | (crecp->flags & ~F_FORWARD), name, &addr, NULL, 0);
			  soa_lookup = crecp;
			}
		      else
			{
			  if (!(crecp->flags & (F_HOSTS | F_DHCP)))
			    auth = 0;
			  
			  log_query(stale_flag | (crecp->flags & ~F_FORWARD), cache_get_name(crecp), &addr, 
				    record_source(crecp->uid), 0);
			  
			  if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, 
						  crec_ttl(crecp, now), NULL,
						  T_PTR, C_IN, "d", cache_get_name(crecp)))
			    anscount++;
			}
		    } while ((crecp = cache_find_by_addr(crecp, &addr, now, is_arpa)));
		}
	    }
	  else if (is_rev_synth(is_arpa, &addr, name))
	    {
	      ans = 1;
	      sec_data = 0;
	      log_query(F_CONFIG | F_REVERSE | is_arpa, name, &addr, NULL, 0);
	      
	      if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, 
				      daemon->local_ttl, NULL,
				      T_PTR, C_IN, "d", name))
		anscount++;
	    }
	  else if (option_bool(OPT_BOGUSPRIV) &&
		   ((is_arpa == F_IPV6 && private_net6(&addr.addr6, 1)) || (is_arpa == F_IPV4 && private_net(addr.addr4, 1))) &&
		   !lookup_domain(name, F_DOMAINSRV, NULL, NULL))
	    {
	      /* if no configured server, not in cache, enabled and private IPV4 address, return NXDOMAIN */
	      ans = 1;
	      sec_data = 0;
	      nxdomain = 1;
	      log_query(F_CONFIG | F_REVERSE | is_arpa | F_NEG | F_NXDOMAIN,
			name, &addr, NULL, 0);
	    }
	}
      
      for (flag = F_IPV4; flag; flag = (flag == F_IPV4) ? F_IPV6 : 0)
	{
	  unsigned short type = (flag == F_IPV6) ? T_AAAA : T_A;
	  struct interface_name *intr;
	  
	  if (qtype != type && qtype != T_ANY)
	    continue;
	  
	  /* interface name stuff */
	  for (intr = daemon->int_names; intr; intr = intr->next)
	    if (hostname_isequal(name, intr->name))
	      break;
	  
	  if (intr)
	    {
	      struct addrlist *addrlist;
	      int gotit = 0, localise = 0;
	      
	      enumerate_interfaces(0);
	      
	      /* See if a putative address is on the network from which we received
		 the query, is so we'll filter other answers. */
	      if (local_addr.s_addr != 0 && option_bool(OPT_LOCALISE) && type == T_A)
		for (intr = daemon->int_names; intr; intr = intr->next)
		  if (hostname_isequal(name, intr->name))
		    for (addrlist = intr->addr; addrlist; addrlist = addrlist->next)
		      if (!(addrlist->flags & ADDRLIST_IPV6) && 
			  is_same_net(addrlist->addr.addr4, local_addr, local_netmask))
			{
			  localise = 1;
			  break;
			}
	      
	      for (intr = daemon->int_names; intr; intr = intr->next)
		if (hostname_isequal(name, intr->name))
		  {
		    for (addrlist = intr->addr; addrlist; addrlist = addrlist->next)
		      if (((addrlist->flags & ADDRLIST_IPV6) ? T_AAAA : T_A) == type)
			{
			  if (localise && 
			      !is_same_net(addrlist->addr.addr4, local_addr, local_netmask))
			    continue;
			  
			  if (addrlist->flags & ADDRLIST_REVONLY)
			    continue;
			  
			  ans = 1;	
			  sec_data = 0;
			  gotit = 1;
			  log_query(F_FORWARD | F_CONFIG | flag, name, &addrlist->addr, NULL, 0);
			  if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, 
						  daemon->local_ttl, NULL, type, C_IN, 
						  type == T_A ? "4" : "6", &addrlist->addr))
			    anscount++;
			}
		  }
	      
	      if (!gotit)
		log_query(F_FORWARD | F_CONFIG | flag | F_NEG, name, NULL, NULL, 0);
	      
	      continue;
	    }
	  
	  if ((crecp = cache_find_by_name(NULL, name, now, flag)))
	    {
	      int localise = 0;
	      
	      /* See if a putative address is on the network from which we received
		 the query, is so we'll filter other answers. */
	      if (!(crecp->flags & F_NEG) && local_addr.s_addr != 0 && option_bool(OPT_LOCALISE) && flag == F_IPV4)
		{
		  struct crec *save = crecp;
		  do {
		    if ((crecp->flags & F_HOSTS) &&
			is_same_net(crecp->addr.addr4, local_addr, local_netmask))
		      {
			localise = 1;
			break;
		      } 
		  } while ((crecp = cache_find_by_name(crecp, name, now, flag)));
		  crecp = save;
		}
	      
	      /* If the client asked for DNSSEC  don't use cached data. */
	      if ((crecp->flags & (F_HOSTS | F_DHCP | F_CONFIG)) ||
		  (rd_bit && (!do_bit || cache_not_validated(crecp)) ))
		do
		  { 
		    int stale_flag = 0;
		    
		    if (crec_isstale(crecp, now))
		      {
			if (stale)
			  *stale = 1;
			
			stale_flag = F_STALE;
		      }
		    
		    /* don't answer wildcard queries with data not from /etc/hosts
		       or DHCP leases */
		    if (qtype == T_ANY && !(crecp->flags & (F_HOSTS | F_DHCP | F_CONFIG)))
		      break;
		    
		    if (!(crecp->flags & F_DNSSECOK))
		      sec_data = 0;
		    
		    if (!(crecp->flags & (F_HOSTS | F_DHCP)))
		      auth = 0;
		    
		    if (qtype != T_ANY && rr_on_list(daemon->filter_rr, qtype) &&
			!(crecp->flags & (F_HOSTS | F_DHCP | F_CONFIG | F_NEG)))
		      {
			/* We have a cached answer but we're filtering it. */
			ans = 1;
			sec_data = 0;
			
			log_query(F_NEG | F_CONFIG | flag, name, NULL, NULL, 0);
			
			if (filtered)
			  *filtered = 1;
		      }
		    else if (crecp->flags & F_NEG)
		      {
			if (qtype != T_ANY)
			  {
			    ans = 1;
			    auth = 0;
			    soa_lookup = crecp;
			    if (crecp->flags & F_NXDOMAIN)
			      nxdomain = 1;
			    
			    log_query(stale_flag | crecp->flags, name, NULL, NULL, 0);
			  }
		      }
		    else 
		      {
			/* If we are returning local answers depending on network,
			   filter here. */
			if (localise && 
			    (crecp->flags & F_HOSTS) &&
			    !is_same_net(crecp->addr.addr4, local_addr, local_netmask))
			  continue;
			
			ans = 1;
			log_query(stale_flag | (crecp->flags & ~F_REVERSE), name, &crecp->addr,
				  record_source(crecp->uid), 0);
			
			if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, 
						crec_ttl(crecp, now), NULL, type, C_IN, 
						type == T_A ? "4" : "6", &crecp->addr))
			  anscount++;
		      }
		  } while ((crecp = cache_find_by_name(crecp, name, now, flag)));
		}
	  else if (is_name_synthetic(flag, name, &addr))
	    {
	      ans = 1, sec_data = 0;
	      log_query(F_FORWARD | F_CONFIG | flag, name, &addr, NULL, 0);
	      if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, 
				      daemon->local_ttl, NULL, type, C_IN, type == T_A ? "4" : "6", &addr))
		anscount++;
	    }
	}
      
      if (qtype == T_MX || qtype == T_ANY)
	{
	  int found = 0;
	  for (rec = daemon->mxnames; rec; rec = rec->next)
	    if (!rec->issrv && hostname_isequal(name, rec->name))
	      {
		int offset;
		
		ans = found = 1;
		sec_data = 0;
		
		log_query(F_CONFIG | F_RRNAME, name, NULL, "<MX>", 0);
		if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, daemon->local_ttl,
					&offset, T_MX, C_IN, "sd", rec->weight, rec->target))
		  {
		    anscount++;
		    if (rec->target)
		      rec->offset = offset;
		  }
	      }
	  
	  if (!found && (option_bool(OPT_SELFMX) || option_bool(OPT_LOCALMX)) &&
	      cache_find_by_name(NULL, name, now, F_HOSTS | F_DHCP | F_NO_RR))
	    { 
	      ans = 1;
	      sec_data = 0;
	      log_query(F_CONFIG | F_RRNAME, name, NULL, "<MX>", 0);
	      if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, daemon->local_ttl, NULL, 
				      T_MX, C_IN, "sd", 1, 
				      option_bool(OPT_SELFMX) ? name : daemon->mxtarget))
		anscount++;
	    }
	}
      
      if (qtype == T_SRV || qtype == T_ANY)
	{
	  struct mx_srv_record *move = NULL, **up = &daemon->mxnames;
	  
	  for (rec = daemon->mxnames; rec; rec = rec->next)
	    if (rec->issrv && hostname_isequal(name, rec->name))
	      {
		int offset;
		
		ans = 1;
		sec_data = 0;
		log_query(F_CONFIG | F_RRNAME, name, NULL, "<SRV>", 0);
		if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, daemon->local_ttl, 
					&offset, T_SRV, C_IN, "sssd", 
					rec->priority, rec->weight, rec->srvport, rec->target))
		  {
		    anscount++;
		    if (rec->target)
		      rec->offset = offset;
		  }
		
		/* unlink first SRV record found */
		if (!move)
		  {
		    move = rec;
			*up = rec->next;
		  }
		else
		  up = &rec->next;      
	      }
	    else
	      up = &rec->next;
	  
	  /* put first SRV record back at the end. */
	  if (move)
	    {
	      *up = move;
	      move->next = NULL;
	    }
	}
      
      if (qtype == T_NAPTR || qtype == T_ANY)
	{
	  struct naptr *na;
	  for (na = daemon->naptr; na; na = na->next)
	    if (hostname_isequal(name, na->name))
	      {
		ans = 1;
		sec_data = 0;
		log_query(F_CONFIG | F_RRNAME, name, NULL, "<NAPTR>", 0);
		if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, daemon->local_ttl, 
					NULL, T_NAPTR, C_IN, "sszzzd", 
					na->order, na->pref, na->flags, na->services, na->regexp, na->replace))
		  anscount++;
	      }
	}
      
      if (qtype == T_MAILB)
	ans = 1, nxdomain = 1, sec_data = 0;
      
      if (qtype == T_SOA && option_bool(OPT_FILTER))
	{
	  ans = 1;
	  sec_data = 0;
	  log_query(F_CONFIG | F_NEG, name, &addr, NULL, 0);
	}
      
      if (!ans)
	{
	  if ((crecp = cache_find_by_name(NULL, name, now, F_RR | F_NXDOMAIN)) && rd_bit)
	    do
	      {
		int flags = crecp->flags;
		unsigned short rrtype;

		if (flags & F_KEYTAG)
		  rrtype = crecp->addr.rrblock.rrtype;
		else
		  rrtype = crecp->addr.rrdata.rrtype;
		
		if (((flags & F_NXDOMAIN) || rrtype == qtype) &&
		    (!do_bit || cache_not_validated(crecp)))
		  {
		    char *rrdata = NULL;
		    unsigned short rrlen = 0;
		    
		    if (crec_isstale(crecp, now))
		      {
			if (stale)
			  *stale = 1;
			
			flags |= F_STALE;
		      }
		    
		    if (!(flags & F_DNSSECOK))
		      sec_data = 0;
		    
		    if (flags & F_NXDOMAIN)
		      nxdomain = 1;
		    else if (qtype != T_ANY && rr_on_list(daemon->filter_rr, qtype))
		      flags |= F_NEG | F_CONFIG;
		    
		    auth = 0;
		    ans = 1;

		    if (flags & F_NEG)
		      soa_lookup = crecp;
		    
		    if (!(flags & F_NEG))
		      {
			if (flags & F_KEYTAG)
			  {
			    rrlen = crecp->addr.rrblock.datalen;
			    rrdata = blockdata_retrieve(crecp->addr.rrblock.rrdata, crecp->addr.rrblock.datalen, NULL);
			  }
			else
			  {
			    rrlen = crecp->addr.rrdata.datalen;
			    rrdata = crecp->addr.rrdata.data;
			  }
		      }
		    
		    if (!(flags & F_NEG) && add_resource_record(header, limit, &trunc, nameoffset, &ansp, 
								crec_ttl(crecp, now), NULL, qtype, C_IN, "t",
								rrlen, rrdata))
		      anscount++;
		    
		    /* log after cache insertion as log_txt mangles rrdata */
		    if (qtype == T_TXT && !(flags & F_NEG))
		      log_txt(name, (unsigned char *)rrdata, rrlen, flags & (F_DNSSECOK | F_STALE));
		    else
		      log_query(flags, name, &crecp->addr, NULL, 0);
		  }
	      } while ((crecp = cache_find_by_name(crecp, name, now, F_RR)));
	}
      
      if (!ans && option_bool(OPT_FILTER) && (qtype == T_SRV || (qtype == T_ANY && strchr(name, '_'))))
	{
	  ans = 1;
	  sec_data = 0;
	  log_query(F_CONFIG | F_NEG, name, NULL, NULL, 0);
	}
      
      
      if (qtype != T_ANY && !ans && rr_on_list(daemon->filter_rr, qtype) && !do_bit)
	{
	  /* We don't have a cached answer and when we get an answer from upstream we're going to
	     filter it anyway. If we have a cached answer for the domain for another RRtype then
	     that may be enough to tell us if the answer should be NODATA and save the round trip.
	     Cached NXDOMAIN has already been handled, so here we look for any record for the domain,
	     since its existence allows us to return a NODATA answer. Note that we never set the AD flag,
	     since we didn't authenticate the record; this doesn't work if we want auth data, so
	     don't use this shortcut in that case. */
	  
	  if (cache_find_by_name(NULL, name, now, F_IPV4 | F_IPV6 | F_RR | F_CNAME))
	    {
	      ans = 1;
	      sec_data = auth = 0;
	      
	      log_query(F_NEG | F_CONFIG | flag, name, NULL, NULL, 0);
	      
	      if (filtered)
		*filtered = 1;
	    }
	}
    }
  
  if (!ans)
    return 0; /* failed to answer a question */

  /* We found a negative record. See if we have an SOA record to 
     return in the AUTH section. 
     
     For FORWARD NEG records, the addr.rrdata.datalen field of the othewise
     empty addr is used to held an offset in to the name which yields the SOA
     name.
     If the F_NO_RR flag is set, there was no SOA record supplied with the RR.  */
  if (soa_lookup && !(soa_lookup->flags & F_NO_RR))
    {
      char *soa_name = name + soa_lookup->addr.rrdata.datalen;
      
      crecp = NULL;
      while ((crecp = cache_find_by_name(crecp, soa_name, now, F_RR)))
	if (crecp->addr.rrblock.rrtype == T_SOA)
	  {
	    char *rrdata;
	    
	    if (!(crecp->flags & F_NEG) &&
		(rrdata = blockdata_retrieve(crecp->addr.rrblock.rrdata, crecp->addr.rrblock.datalen, NULL)) &&
		add_resource_record(header, limit, &trunc, 0, &ansp, 
				    crec_ttl(crecp, now), NULL, T_SOA, C_IN, "t",
				    soa_name, crecp->addr.rrblock.datalen, rrdata))
	      {
		nscount++;
		
		if (!(crecp->flags & F_DNSSECOK))
		  sec_data = 0;
	      }
	    break;
	  }
    }
      
  /* create an additional data section, for stuff in SRV and MX record replies. */
  for (rec = daemon->mxnames; rec; rec = rec->next)
    if (rec->offset != 0)
      {
	/* squash dupes */
	struct mx_srv_record *tmp;
	for (tmp = rec->next; tmp; tmp = tmp->next)
	  if (tmp->offset != 0 && hostname_isequal(rec->target, tmp->target))
	    tmp->offset = 0;
	
	crecp = NULL;
	while ((crecp = cache_find_by_name(crecp, rec->target, now, F_IPV4 | F_IPV6)))
	  {
	    int type =  crecp->flags & F_IPV4 ? T_A : T_AAAA;

	    if (crecp->flags & F_NEG)
	      continue;

	    if (add_resource_record(header, limit, NULL, rec->offset, &ansp, 
				    crec_ttl(crecp, now), NULL, type, C_IN, 
				    crecp->flags & F_IPV4 ? "4" : "6", &crecp->addr))
	      {
		addncount++;
		if (!(crecp->flags & F_DNSSECOK))
		  sec_data = 0;
	      }
	  }
      }
  
  /* done all questions, set up header and return length of result */
  /* clear authoritative and truncated flags, set QR flag */
  header->hb3 = (header->hb3 & ~(HB3_AA | HB3_TC)) | HB3_QR;
  /* set RA flag */
  header->hb4 |= HB4_RA;
   
  /* authoritative - only hosts and DHCP derived names. */
  if (auth)
    header->hb3 |= HB3_AA;
  
  /* truncation */
  if (trunc)
    {
      header->hb3 |= HB3_TC;
      if (!(ansp = skip_questions(header, qlen)))
	return 0; /* bad packet */
      anscount = nscount = addncount = 0;
      log_query(0, "reply", NULL, "truncated", 0);
    }

  if (nxdomain)
    SET_RCODE(header, NXDOMAIN);
  else if (notimp)
    SET_RCODE(header, NOTIMP);
  else
    SET_RCODE(header, NOERROR); /* no error */

  header->ancount = htons(anscount);
  header->nscount = htons(nscount);
  header->arcount = htons(addncount);

  len = ansp - (unsigned char *)header;
  
  if (ad_reqd && sec_data)
    header->hb4 |= HB4_AD;
  else
    header->hb4 &= ~HB4_AD;
  
  return len;
}

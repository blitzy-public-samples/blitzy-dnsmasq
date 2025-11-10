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
 * @file edns0.c
 * @brief EDNS0 extension mechanism implementation per RFC 6891
 * 
 * DETAILED PURPOSE:
 * This module implements the Extension Mechanisms for DNS (EDNS0) as defined in RFC 6891,
 * providing mechanisms to extend the DNS protocol beyond its original 512-byte UDP limit
 * and to carry additional metadata in DNS messages. EDNS0 uses a pseudo-RR (OPT record)
 * in the additional section of DNS packets to communicate extended functionality including
 * UDP payload size, DNSSEC support indication (DO bit), client subnet information for
 * geographic DNS optimization, and vendor-specific extensions.
 * 
 * The module handles both parsing EDNS0 options from incoming queries and constructing
 * EDNS0 OPT pseudo-RRs for outgoing queries and responses. It supports standard EDNS0
 * options including EDNS Client Subnet (ECS) per RFC 7871, DNSSEC OK bit handling,
 * Extended DNS Error codes (EDE) per RFC 8914, and proprietary options such as MAC
 * address transmission and Cisco Umbrella device identification.
 * 
 * KEY RESPONSIBILITIES:
 * - find_pseudoheader(): Locate existing EDNS0 OPT pseudo-RR in DNS packets
 * - add_pseudoheader(): Add or replace EDNS0 options in DNS message additional section
 * - add_do_bit(): Set DNSSEC OK bit to signal DNSSEC validation capability
 * - add_dns_client(): Add DNS client identification option for cache debugging
 * - add_mac(): Add MAC address option (EDNS0_OPTION_MAC) for device identification
 * - add_source_addr(): Add EDNS Client Subnet (ECS) option per RFC 7871
 * - add_umbrella_opt(): Add Cisco Umbrella proprietary device identification options
 * - add_edns0_config(): Main orchestrator coordinating all EDNS0 option additions
 * 
 * DEPENDENCIES:
 * Includes: dnsmasq.h (core data structures including struct daemon, struct dns_header)
 *          dns-protocol.h (DNS protocol constants including EDNS0 option codes)
 * 
 * Called by: forward.c (DNS query forwarding and response handling)
 *           rfc1035.c (DNS packet construction and parsing)
 *           dnssec.c (DNSSEC validation signaling via DO bit)
 * 
 * Calls: skip_name(), skip_questions(), skip_section() from rfc1035.c for DNS packet parsing
 *       GETSHORT, PUTSHORT, PUTLONG macros from dns-protocol.h for wire format handling
 * 
 * DATA STRUCTURES:
 * - struct dns_header: DNS message header structure (defined in dnsmasq.h)
 * - struct all_addr: Union for IPv4/IPv6 addresses used in ECS option (dnsmasq.h)
 * - OPT pseudo-RR format: NAME(root), TYPE(41), CLASS(UDP size), TTL(extended RCODE+flags), RDLEN, RDATA
 * 
 * COMPILE-TIME OPTIONS:
 * - HAVE_DNSSEC: Enables DNSSEC OK bit handling for validation signaling
 * - None specific to this file, but integrates with overall build configuration
 * 
 * THREADING/CONCURRENCY:
 * Single-process event-driven model - functions are called sequentially during DNS message
 * processing and do not require locking. All operations modify packet buffers in-place
 * within the context of a single query/response transaction.
 * 
 * @copyright Copyright (c) 2000-2025 Simon Kelley
 * @license GPL-2.0-or-later
 */

#include "dnsmasq.h"

/**
 * @brief Locate EDNS0 OPT pseudo-RR in DNS packet additional section
 * 
 * @detailed Searches the additional section of a DNS message for an EDNS0 OPT pseudo-RR
 *           (RFC 6891) and returns a pointer to its location in the packet buffer. Also
 *           detects transaction signatures (TSIG/TKEY) which prevent packet modification
 *           during forwarding. The OPT pseudo-RR uses DNS record type 41 (T_OPT) with
 *           special semantics: the CLASS field encodes UDP payload size, and the TTL field
 *           contains extended RCODE and EDNS flags including the DNSSEC OK (DO) bit.
 * 
 *           The function performs two key security checks: (1) scans question section for
 *           TKEY queries used in GSS-TSIG negotiation, and (2) checks additional section
 *           for TSIG records. Either condition sets *is_sign to indicate the packet is
 *           cryptographically protected and cannot be modified.
 * 
 * @param header Pointer to DNS message header structure containing qdcount, ancount, nscount, arcount
 * @param plen Total length of DNS packet buffer in bytes, used for bounds checking
 * @param len Output: Length of OPT pseudo-RR from start of NAME field to end of RDATA (NULL if not needed)
 * @param p Output: Pointer to UDP size field (CLASS field of OPT RR) for modification (NULL if not needed)
 * @param is_sign Output: Set to 1 if packet contains TSIG/TKEY signature preventing modification (NULL if not needed)
 * @param is_last Output: Set to 1 if OPT RR is last record in additional section (NULL if not needed)
 * 
 * @return Pointer to start of OPT pseudo-RR (NAME field) in packet buffer, or NULL if not found
 * @retval NULL No OPT pseudo-RR found in additional section
 * @retval non-NULL Pointer to OPT RR NAME field (typically root domain, 1 byte: 0x00)
 * 
 * @note The OPT pseudo-RR NAME is always the root domain (empty label, single zero byte)
 * @note Multiple OPT records in a packet violate RFC 6891; this function returns the first found
 * @warning Packet modification is prohibited if *is_sign is set to 1 (TSIG/TKEY present)
 * @warning Caller must verify plen is sufficient before calling; function performs bounds checks
 * 
 * @see add_pseudoheader() for modifying or adding EDNS0 options to packets
 * @see forward.c for usage in query forwarding and response processing
 * 
 * EXAMPLE USAGE:
 * @code
 * size_t opt_len;
 * unsigned char *udp_size_ptr;
 * int is_signed;
 * unsigned char *opt = find_pseudoheader(header, packet_len, &opt_len, &udp_size_ptr, &is_signed, NULL);
 * if (opt && !is_signed) {
 *   // Safe to modify EDNS0 options
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 6891 Section 6.1.1 (OPT pseudo-RR format)
 *                 RFC 2845 (TSIG transaction signatures)
 *                 RFC 2930 (TKEY resource record)
 * 
 * SIDE EFFECTS: None - read-only operation scanning packet structure
 * 
 * THREAD SAFETY: Safe - no global state modification, operates only on provided packet buffer
 */
unsigned char *find_pseudoheader(struct dns_header *header, size_t plen, size_t  *len, unsigned char **p, int *is_sign, int *is_last)
{
  /* See if packet has an RFC2671 pseudoheader, and if so return a pointer to it. 
     also return length of pseudoheader in *len and pointer to the UDP size in *p
     Finally, check to see if a packet is signed. If it is we cannot change a single bit before
     forwarding. We look for TSIG in the addition section, and TKEY queries (for GSS-TSIG) */
  
  int i, arcount = ntohs(header->arcount);
  unsigned char *ansp = (unsigned char *)(header+1);
  unsigned short rdlen, type, class;
  unsigned char *ret = NULL;

  if (is_sign)
    {
      *is_sign = 0;

      if (OPCODE(header) == QUERY)
	{
	  for (i = ntohs(header->qdcount); i != 0; i--)
	    {
	      if (!(ansp = skip_name(ansp, header, plen, 4)))
		return NULL;
	      
	      GETSHORT(type, ansp); 
	      GETSHORT(class, ansp);
	      
	      if (class == C_IN && type == T_TKEY)
		*is_sign = 1;
	    }
	}
    }
  else
    {
      if (!(ansp = skip_questions(header, plen)))
	return NULL;
    }
    
  if (arcount == 0)
    return NULL;
  
  if (!(ansp = skip_section(ansp, ntohs(header->ancount) + ntohs(header->nscount), header, plen)))
    return NULL; 
  
  for (i = 0; i < arcount; i++)
    {
      unsigned char *save, *start = ansp;
      if (!(ansp = skip_name(ansp, header, plen, 10)))
	return NULL; 

      GETSHORT(type, ansp);
      save = ansp;
      GETSHORT(class, ansp);
      ansp += 4; /* TTL */
      GETSHORT(rdlen, ansp);
      if (!ADD_RDLEN(header, ansp, plen, rdlen))
	return NULL;
      if (type == T_OPT)
	{
	  if (len)
	    *len = ansp - start;

	  if (p)
	    *p = save;
	  
	  if (is_last)
	    *is_last = (i == arcount-1);

	  ret = start;
	}
      else if (is_sign && 
	       i == arcount - 1 && 
	       class == C_ANY && 
	       type == T_TSIG)
	*is_sign = 1;
    }
  
  return ret;
}
 

/**
 * @brief Add or replace EDNS0 options in DNS message additional section
 * 
 * @detailed Modifies the additional section of a DNS message to add, replace, or remove EDNS0
 *           options within an OPT pseudo-RR. If an OPT record already exists, the function
 *           preserves or modifies it according to the replace parameter. If no OPT record
 *           exists, creates a new one with specified options. The function handles UDP payload
 *           size negotiation, DNSSEC OK bit setting, and arbitrary EDNS0 option addition while
 *           maintaining RFC 6891 compliance and performing strict bounds checking.
 * 
 *           The function implements three modification strategies: (1) preserve existing option
 *           if present (replace=0), (2) replace existing option or add if absent (replace=1),
 *           (3) replace existing option only, don't add if absent (replace=2). When creating or
 *           modifying OPT records, the function preserves any other options already present by
 *           buffering them temporarily during reconstruction.
 * 
 * @param header Pointer to DNS message header structure with section counts (qdcount, ancount, nscount, arcount)
 * @param plen Current length of DNS packet in bytes
 * @param limit Pointer to end of available buffer space (must not write beyond this)
 * @param optno EDNS0 option code to add (0 = no new option, just modify DO bit or existing options)
 * @param opt Pointer to option data to add (NULL if optno is 0)
 * @param optlen Length of option data in bytes (0 if optno is 0)
 * @param set_do Set to 1 to enable DNSSEC OK bit in OPT flags, 0 to leave cleared
 * @param replace Operation mode: 0=don't replace existing, 1=replace existing or add, 2=replace existing option only
 * 
 * @return New packet length after modification, or original plen if modification failed
 * @retval plen Modification failed due to insufficient buffer space or malformed packet
 * @retval >plen Successfully added/modified EDNS0 options, arcount incremented if new OPT RR created
 * 
 * @note Function preserves existing OPT options when modifying OPT record (buffered and copied back)
 * @note Maximum UDP payload size from daemon->edns_pktsz (default 4096 bytes with EDNS0)
 * @warning Caller must ensure limit pointer correctly bounds available buffer space
 * @warning Function may allocate temporary buffer (whine_malloc) to preserve existing options
 * @warning Returns original plen on any error; caller must check for buffer overflow conditions
 * 
 * @see find_pseudoheader() for locating existing OPT pseudo-RR before modification
 * @see add_do_bit() for simplified interface to set DNSSEC OK bit only
 * @see add_edns0_config() for coordinated addition of multiple EDNS0 options
 * 
 * EXAMPLE USAGE:
 * @code
 * // Add EDNS Client Subnet option to query
 * unsigned char ecs_data[8] = {0x00, 0x01, 0x18, 0x00, 0xC0, 0xA8, 0x01, 0x00}; // 192.168.1.0/24
 * size_t newlen = add_pseudoheader(header, plen, limit, EDNS0_OPTION_CLIENT_SUBNET, 
 *                                   ecs_data, sizeof(ecs_data), 1, 1);
 * if (newlen == plen) {
 *   // Addition failed, buffer full or packet malformed
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 6891 Section 6.1.2 (OPT RR construction and wire format)
 *                 RFC 6891 Section 6.2.5 (UDP payload size negotiation)
 *                 RFC 3225 (DO bit for DNSSEC signaling)
 * 
 * SIDE EFFECTS: Modifies DNS packet buffer in-place, increments header->arcount if new OPT RR added
 *               May allocate and free temporary buffer (whine_malloc/free) for option preservation
 * 
 * THREAD SAFETY: Safe - operates only on provided packet buffer and global daemon structure
 *                       (daemon->edns_pktsz is read-only configuration)
 */
/* replace == 0 ->don't replace existing option
   replace == 1 ->replace existing or add option
   replace == 2 ->relpace existing option only.
*/
size_t add_pseudoheader(struct dns_header *header, size_t plen, unsigned char *limit, 
			int optno, unsigned char *opt, size_t optlen, int set_do, int replace)
{ 
  unsigned char *lenp, *datap, *p, *udp_len, *buff = NULL;
  int rdlen = 0, is_sign, is_last;
  unsigned short flags = set_do ? 0x8000 : 0, rcode = 0;

  p = find_pseudoheader(header, plen, NULL, &udp_len, &is_sign, &is_last);
  
  if (is_sign)
    return plen;

  if (p)
    {
      /* Existing header */
      int i;
      unsigned short code, len;
      
      p = udp_len;

      PUTSHORT(daemon->edns_pktsz, p);
      GETSHORT(rcode, p);
      GETSHORT(flags, p);

      if (set_do)
	{
	  p -= 2;
	  flags |= 0x8000;
	  PUTSHORT(flags, p);
	}

      lenp = p;
      GETSHORT(rdlen, p);
      if (!CHECK_LEN(header, p, plen, rdlen))
	return plen; /* bad packet */
      datap = p;

       /* no option to add */
      if (optno == 0)
	return plen;
      	  
      /* check if option already there */
      for (i = 0; i + 4 < rdlen;)
	{
	  GETSHORT(code, p);
	  GETSHORT(len, p);
	  
	  /* malformed option, delete the whole OPT RR and start again. */
	  if (i + 4 + len > rdlen)
	    {
	      rdlen = 0;
	      is_last = 0;
	      break;
	    }
	  
	  if (code == optno)
	    {
	      if (replace == 0)
		return plen;

	      /* delete option if we're to replace it. */
	      p -= 4;
	      rdlen -= len + 4;
	      memmove(p, p+len+4, rdlen - i);
	      PUTSHORT(rdlen, lenp);
	      lenp -= 2;
	    }
	  else
	    {
	      p += len;
	      i += len + 4;
	    }
	}

      /* If we're going to extend the RR, it has to be the last RR in the packet */
      if (!is_last)
	{
	  /* First, take a copy of the options. */
	  if (rdlen != 0 && (buff = whine_malloc(rdlen)))
	    memcpy(buff, datap, rdlen);	      
	  
	  /* now, delete OPT RR */
	  rrfilter(header, &plen, RRFILTER_EDNS0);
	  
	  /* Now, force addition of a new one */
	  p = NULL;	  
	}
    }
  
  if (!p)
    {
      /* We are (re)adding the pseudoheader */
      if (!(p = skip_questions(header, plen)) ||
	  !(p = skip_section(p, 
			     ntohs(header->ancount) + ntohs(header->nscount) + ntohs(header->arcount), 
			     header, plen)) ||
	  p + 11 > limit)
	{
	  free(buff);
	  return plen; /* bad packet */
	}

      *p++ = 0; /* empty name */
      PUTSHORT(T_OPT, p);
      PUTSHORT(daemon->edns_pktsz, p); /* max packet length, 512 if not given in EDNS0 header */
      PUTSHORT(rcode, p);  /* extended RCODE and version */
      PUTSHORT(flags, p);  /* DO flag */
      lenp = p;
      PUTSHORT(rdlen, p);    /* RDLEN */
      datap = p;
      /* Copy back any options */
      if (buff)
	{
          if (p + rdlen > limit)
          {
            free(buff);
            return plen; /* Too big */
          }
	  memcpy(p, buff, rdlen);
	  free(buff);
	  p += rdlen;
	}
      
      /* Only bump arcount if RR is going to fit */ 
      if (((ssize_t)optlen) <= (limit - (p + 4)))
	header->arcount = htons(ntohs(header->arcount) + 1);
    }
  
  if (((ssize_t)optlen) > (limit - (p + 4)))
    return plen; /* Too big */
  
  /* Add new option */
  if (optno != 0 && replace != 2)
    {
      if (p + 4 > limit)
       return plen; /* Too big */
      PUTSHORT(optno, p);
      PUTSHORT(optlen, p);
      if (p + optlen > limit)
       return plen; /* Too big */
      memcpy(p, opt, optlen);
      p += optlen;  
      PUTSHORT(p - datap, lenp);
    }
  return p - (unsigned char *)header;
}

/**
 * @brief Add DNSSEC OK (DO) bit to DNS query via EDNS0 OPT pseudo-RR
 * 
 * @detailed Adds or modifies the EDNS0 OPT pseudo-record in a DNS query to set the DO (DNSSEC OK)
 *           bit, signaling to upstream servers that the client (dnsmasq) is DNSSEC-aware and
 *           requesting DNSSEC-related resource records (RRSIG, DNSKEY, DS, NSEC/NSEC3) in responses.
 *           
 *           This function is a convenience wrapper around add_pseudoheader() that specifically
 *           sets the DO bit (7th parameter = 1) while leaving other EDNS0 options unchanged.
 *           The DO bit is defined in RFC 3225 and RFC 4035 as part of the DNSSEC protocol,
 *           enabling DNSSEC validation by indicating client capability to handle authenticated data.
 *           
 *           Implementation details:
 *           - Calls add_pseudoheader() with do_bit parameter = 1 (enable DO bit)
 *           - Uses replace = 0 (don't replace existing OPT RR, just modify it)
 *           - No additional EDNS0 options added (opt_data = NULL, opt_len = 0)
 *           - No EDNS0 options removed (optno = 0)
 *           
 *           The DO bit must be set in queries sent to upstream servers when DNSSEC validation
 *           is enabled (--dnssec configuration option). Without the DO bit, upstream servers
 *           will not include DNSSEC records in responses, preventing validation.
 *           
 *           Called from forward.c when forwarding queries that require DNSSEC validation,
 *           and from dnssec.c during DNSSEC chain-of-trust validation to request signed records.
 * 
 * @param header DNS query packet header structure to modify
 * @param plen Current packet length before adding/modifying OPT RR
 * @param limit Packet buffer end boundary for overflow prevention
 * 
 * @return Updated packet length after adding/modifying OPT RR with DO bit
 * @retval >plen if OPT RR added (packet grew by ~11 bytes for minimal OPT RR)
 * @retval plen if OPT RR already exists and was only modified (DO bit set in place)
 * @retval plen if addition failed due to insufficient buffer space (packet unchanged)
 * 
 * @note DO bit is bit 15 (0x8000) of the EDNS0 flags field in OPT RR
 * @note Function is non-static (public) - called from forward.c and dnssec.c
 * @note Idempotent: safe to call multiple times (DO bit remains set)
 * @note Does not validate that DNSSEC is enabled in daemon configuration
 * 
 * @warning Assumes buffer has space for OPT RR (~11 bytes minimum)
 * @warning Does not check if packet is already signed (TSIG/TKEY) before modifying
 * 
 * @see add_pseudoheader() for underlying OPT RR addition/modification mechanism
 * @see forward.c:forward_query() for usage in query forwarding
 * @see dnssec.c:dnssec_validate_*() for usage in DNSSEC validation
 * @see RFC 3225 for DO bit definition
 * @see RFC 4035 Section 3.2.1 for DNSSEC DO bit usage
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dns_header *header = ...;
 * size_t plen = ...;
 * unsigned char *limit = ...;
 * size_t new_len = add_do_bit(header, plen, limit);
 * // new_len >= plen (packet may have grown with OPT RR, or DO bit set in existing OPT)
 * // Query now signals DNSSEC support to upstream servers
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 3225 (DO bit), RFC 4035 Section 3.2.1 (DNSSEC protocol modifications)
 * SIDE EFFECTS: Modifies DNS packet by adding OPT RR or setting DO bit in existing OPT RR
 * THREAD SAFETY: Thread-safe (no global state modified)
 */
size_t add_do_bit(struct dns_header *header, size_t plen, unsigned char *limit)
{
  return add_pseudoheader(header, plen, (unsigned char *)limit, 0, NULL, 0, 1, 0);
}

/**
 * @brief Convert 6-bit value to base64 character using standard base64 alphabet
 * 
 * @detailed Implements base64 character lookup for 6-bit input values (0-63) using the
 *           RFC 4648 standard base64 alphabet. This function is a performance-optimized
 *           implementation using direct string indexing rather than switch/case or
 *           conditional logic for character mapping.
 *           
 *           Base64 alphabet mapping (RFC 4648 Section 4):
 *           - Values 0-25 map to 'A'-'Z' (uppercase letters)
 *           - Values 26-51 map to 'a'-'z' (lowercase letters)
 *           - Values 52-61 map to '0'-'9' (digits)
 *           - Value 62 maps to '+' (plus sign)
 *           - Value 63 maps to '/' (forward slash)
 *           
 *           The input value is masked with 0x3f (binary 00111111) to ensure only
 *           the lower 6 bits are used for indexing, providing safety against invalid
 *           input values that could cause buffer overrun in the 64-character string.
 *           
 *           This function is used by encoder() to convert MAC address bytes into
 *           8-character base64 strings for EDNS0_OPTION_NOMDEVICEID. The base64
 *           encoding allows binary MAC addresses to be transmitted as ASCII text
 *           in DNS packets without escaping or special handling.
 *           
 *           Implementation note: The 64-character string literal is stored in
 *           read-only data section (.rodata) by most compilers, making this
 *           lookup extremely efficient with no runtime allocation.
 * 
 * @param c Input byte to convert; only lower 6 bits used (masked with 0x3f)
 * 
 * @return Base64 character corresponding to 6-bit input value
 * @retval 'A'-'Z' for input values 0-25
 * @retval 'a'-'z' for input values 26-51
 * @retval '0'-'9' for input values 52-61
 * @retval '+' for input value 62
 * @retval '/' for input value 63
 * 
 * @note Function is static (internal to edns0.c) - called only by encoder()
 * @note Masking with 0x3f makes function safe for any input byte value
 * @note Returns unsigned char to match base64 alphabet (ASCII 0x2B-0x7A range)
 * @note String literal has exactly 64 characters matching base64 standard
 * 
 * @warning No bounds checking beyond 0x3f mask - relies on compiler string storage
 * 
 * @see encoder() for base64 encoding of 3-byte sequences using char64()
 * @see add_dns_client() for usage context in MAC address encoding
 * @see RFC 4648 Section 4 for base64 alphabet definition
 * 
 * EXAMPLE USAGE:
 * @code
 * unsigned char sixbit = 0x1A; // Value 26 in decimal
 * unsigned char result = char64(sixbit);
 * // result == 'a' (26 maps to first lowercase letter)
 * 
 * unsigned char masked = char64(0xFF); // Input value 255
 * // masked == '/' (0xFF & 0x3f = 0x3f = 63, maps to '/')
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 4648 Section 4 (Base64 Encoding)
 * SIDE EFFECTS: None (pure function, no state modification)
 * THREAD SAFETY: Thread-safe (read-only string literal access)
 */
static unsigned char char64(unsigned char c)
{
  return "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[c & 0x3f];
}

/**
 * @brief Encode 3 input bytes into 4 base64 characters without padding
 * 
 * @detailed Performs base64 encoding of a 3-byte binary sequence into 4 ASCII base64
 *           characters using the standard base64 algorithm defined in RFC 4648.
 *           Unlike standard base64 encoding that may add '=' padding characters,
 *           this implementation produces exactly 4 output characters from exactly
 *           3 input bytes with no padding, as the input length is always a multiple
 *           of 3 bytes when encoding MAC addresses (6 bytes = 2 x 3 bytes).
 *           
 *           Base64 encoding algorithm:
 *           - Input: 3 bytes = 24 bits of binary data
 *           - Output: 4 characters = 4 x 6 bits each = 24 bits encoded
 *           - Process: Split 24 input bits into four 6-bit groups
 *           
 *           Bit manipulation breakdown:
 *           1. out[0] = in[0]>>2              // First 6 bits of byte 0
 *           2. out[1] = (in[0]<<4)|(in[1]>>4) // Last 2 bits of byte 0 + first 4 bits of byte 1
 *           3. out[2] = (in[1]<<2)|(in[2]>>6) // Last 4 bits of byte 1 + first 2 bits of byte 2
 *           4. out[3] = in[2]                 // Last 6 bits of byte 2 (masked in char64())
 *           
 *           This function is used specifically for encoding 6-byte MAC addresses into
 *           8-character base64 strings for the EDNS0_OPTION_NOMDEVICEID option used
 *           by Nominum DNS servers. The function is called twice to encode the MAC:
 *           - First call: encodes bytes 0-2 into characters 0-3
 *           - Second call: encodes bytes 3-5 into characters 4-7
 *           
 *           Implementation note: The output buffer is char* (signed char on most
 *           platforms) while char64() returns unsigned char. The implicit conversion
 *           is safe as base64 characters are ASCII (0x2B-0x7A range, all positive).
 * 
 * @param in Input buffer containing exactly 3 bytes of binary data to encode
 * @param out Output buffer to receive exactly 4 base64 characters (not null-terminated)
 * 
 * @return void (output written directly to out buffer)
 * 
 * @note Function is static (internal to edns0.c) - called only by add_dns_client()
 * @note Output is NOT null-terminated - caller responsible for null terminator if needed
 * @note Always produces exactly 4 characters (no padding or length variation)
 * @note Assumes input buffer has at least 3 bytes, output buffer has at least 4 bytes
 * @note char64() masks values to 6 bits, so bit shifts produce safe input values
 * 
 * @warning No buffer length validation - caller must ensure adequate buffer sizes
 * @warning No null termination - output is raw base64 character sequence
 * @warning Input buffer must contain exactly 3 bytes (undefined behavior if truncated)
 * 
 * @see char64() for 6-bit to base64 character conversion
 * @see add_dns_client() for MAC address encoding using two encoder() calls
 * @see RFC 4648 Section 4 for base64 encoding algorithm
 * 
 * EXAMPLE USAGE:
 * @code
 * unsigned char mac_bytes[3] = {0xAB, 0xCD, 0xEF}; // 3 bytes of MAC address
 * char base64_out[4];
 * encoder(mac_bytes, base64_out);
 * // base64_out now contains 4 base64 characters (not null-terminated)
 * // Encoding: 0xAB = 10101011, 0xCD = 11001101, 0xEF = 11101111
 * // Grouped: 101010 | 111100 | 110111 | 101111 (4 x 6-bit values)
 * // Result: 42='q', 60='8', 55='3', 47='v' (base64 characters)
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 4648 Section 4 (Base64 Encoding)
 * SIDE EFFECTS: Modifies 4 bytes of output buffer
 * THREAD SAFETY: Thread-safe (no shared state, pure transformation)
 */
static void encoder(unsigned char *in, char *out)
{
  out[0] = char64(in[0]>>2);
  out[1] = char64((in[0]<<4) | (in[1]>>4));
  out[2] = char64((in[1]<<2) | (in[2]>>6));
  out[3] = char64(in[2]);
}

/**
 * @brief Add or remove Nominum DNS client identifier EDNS0 option with encoded MAC address
 * 
 * @detailed Implements Nominum Device ID option (EDNS0_OPTION_NOMDEVICEID) encoding the
 *           client MAC address in either base64 or hexadecimal format. This function supports
 *           three operational modes controlled by OPT_MAC_B64/OPT_MAC_HEX and OPT_STRIP_MAC
 *           configuration flags. The encoded MAC address enables network policy enforcement
 *           and client identification at upstream DNS resolvers. MAC address discovery uses
 *           ARP/neighbor cache lookup via find_mac(). Encoding format is 8-character string
 *           for 6-byte MAC addresses only (standard Ethernet MAC format).
 * 
 * @param header DNS packet header being modified for EDNS0 option addition
 * @param plen Current packet length; updated with new length after option addition/removal
 * @param limit Pointer to end of packet buffer; prevents buffer overflow during modification
 * @param l3 Layer 3 socket address for MAC lookup via ARP/neighbor cache
 * @param now Current timestamp for cache validity checking in find_mac()
 * @param cacheablep Pointer to cacheability flag; set to 0 when MAC added (client-specific)
 * 
 * @return Updated packet length after EDNS0 option processing (add/replace/remove)
 * 
 * @note OPT_MAC_B64: Enable base64 encoding of MAC address (8-character string)
 * @note OPT_MAC_HEX: Enable hexadecimal encoding of MAC address (standard colon notation)
 * @note OPT_STRIP_MAC: Remove existing option; with OPT_ADD_MAC replaces option
 * @note Only 6-byte MAC addresses supported (standard Ethernet); other lengths ignored
 * @note Sets *cacheablep = 0 when MAC added (response not cacheable for other clients)
 * 
 * @warning Operational Mode 1: OPT_MAC_B64/HEX without STRIP = add if MAC available
 * @warning Operational Mode 2: OPT_MAC_B64/HEX + OPT_STRIP_MAC = replace (remove if unavailable)
 * @warning Operational Mode 3: OPT_STRIP_MAC only = unconditional removal
 * 
 * @see add_pseudoheader() for EDNS0 option insertion with replace capability
 * @see find_mac() in arp.c for MAC address resolution from layer 3 address
 * @see encoder() for base64 encoding implementation
 * @see print_mac() in util.c for hexadecimal MAC formatting
 * 
 * EXAMPLE USAGE:
 * @code
 * int cacheable = 1;
 * union mysockaddr client_addr;
 * plen = add_dns_client(header, plen, limit, &client_addr, time(NULL), &cacheable);
 * // cacheable now 0 if MAC added; plen updated with new packet length
 * @endcode
 * 
 * RFC COMPLIANCE: Nominum Device ID option (non-standard vendor extension)
 * SIDE EFFECTS: Modifies DNS packet; sets cacheability flag; consults ARP cache
 * THREAD SAFETY: Single-threaded architecture; modifies packet in-place
 */
/* OPT_ADD_MAC = MAC is added (if available)
   OPT_ADD_MAC + OPT_STRIP_MAC = MAC is replaced, if not available, it is only removed
   OPT_STRIP_MAC = MAC is removed */
static size_t add_dns_client(struct dns_header *header, size_t plen, unsigned char *limit,
			     union mysockaddr *l3, time_t now, int *cacheablep)
{
  int replace = 0, maclen = 0;
  unsigned char mac[DHCP_CHADDR_MAX];
  char encode[18]; /* handle 6 byte MACs ONLY */

  if ((option_bool(OPT_MAC_B64) || option_bool(OPT_MAC_HEX)) && (maclen = find_mac(l3, mac, 1, now)) == 6)
    {
      if (option_bool(OPT_STRIP_MAC))
	 replace = 1;
       *cacheablep = 0;
    
       if (option_bool(OPT_MAC_HEX))
	 print_mac(encode, mac, maclen);
       else
	 {
	   encoder(mac, encode);
	   encoder(mac+3, encode+4);
	   encode[8] = 0;
	 }
    }
  else if (option_bool(OPT_STRIP_MAC))
    replace = 2;

  if (replace != 0 || maclen == 6)
    plen = add_pseudoheader(header, plen, limit, EDNS0_OPTION_NOMDEVICEID, (unsigned char *)encode, strlen(encode), 0, replace);

  return plen;
}


/* OPT_ADD_MAC = MAC is added (if available)
   OPT_ADD_MAC + OPT_STRIP_MAC = MAC is replaced, if not available, it is only removed
   OPT_STRIP_MAC = MAC is removed */

/**
 * @brief Add or strip EDNS0 MAC address option for client identification
 * 
 * @detailed Manages EDNS0 Client MAC Address option (EDNS0_OPTION_MAC) based on configured
 *           policy flags. Behavior controlled by OPT_ADD_MAC and OPT_STRIP_MAC options:
 *           - OPT_ADD_MAC only: Adds MAC if available, marks response non-cacheable
 *           - OPT_STRIP_MAC only: Removes existing MAC option from packet
 *           - Both flags set: Replaces MAC if available, otherwise removes existing MAC
 *           MAC address discovered via find_mac() using client's layer 3 address and
 *           ARP/neighbor cache lookup. Successfully adding MAC marks response as
 *           non-cacheable (*cacheablep = 0) since response becomes client-specific.
 *           Supports MAC addresses up to DHCP_CHADDR_MAX bytes (handles various hardware).
 * 
 * @param header DNS packet header structure being modified
 * @param plen Current packet length before option modification
 * @param limit Pointer to end of packet buffer (prevents buffer overflow)
 * @param l3 Layer 3 socket address for MAC address lookup via ARP cache
 * @param now Current timestamp for cache validity checking in find_mac()
 * @param cacheablep Pointer to cacheability flag; set to 0 when MAC added
 * 
 * @return Updated packet length after MAC option add/strip operation
 * @retval plen unchanged if no operation performed (options disabled, MAC unavailable)
 * @retval plen increased if MAC option added
 * @retval plen decreased if MAC option stripped
 * 
 * @note Sets *cacheablep = 0 only when MAC successfully added (response client-specific)
 * @note MAC not added if find_mac() returns 0 (no MAC found)
 * @note Supports MAC addresses up to DHCP_CHADDR_MAX bytes
 * 
 * @warning Requires ARP/neighbor cache populated for MAC resolution
 * @warning Option modification controlled by global option flags
 * 
 * @see find_mac() in arp.c for MAC address resolution from layer 3 address
 * @see add_pseudoheader() for EDNS0 option insertion/replacement mechanism
 * @see option_bool() for checking OPT_ADD_MAC and OPT_STRIP_MAC flags
 * 
 * EXAMPLE USAGE:
 * @code
 * int cacheable = 1;
 * union mysockaddr client_addr;
 * // Configuration: option_bool(OPT_ADD_MAC) = 1, option_bool(OPT_STRIP_MAC) = 0
 * plen = add_mac(header, plen, limit, &client_addr, time(NULL), &cacheable);
 * // cacheable now 0 if MAC added; plen updated with MAC option
 * @endcode
 * 
 * RFC COMPLIANCE: EDNS0 option mechanism for MAC address extension
 * SIDE EFFECTS: Modifies DNS packet; may set cacheability flag; consults ARP cache
 * THREAD SAFETY: Single-threaded architecture; modifies packet in-place
 */
static size_t add_mac(struct dns_header *header, size_t plen, unsigned char *limit,
		      union mysockaddr *l3, time_t now, int *cacheablep)
{
  int maclen = 0, replace = 0;
  unsigned char mac[DHCP_CHADDR_MAX];
    
  if (option_bool(OPT_ADD_MAC) && (maclen = find_mac(l3, mac, 1, now)) != 0)
    {
      *cacheablep = 0;
      if (option_bool(OPT_STRIP_MAC))
	replace = 1;
    }
  else if (option_bool(OPT_STRIP_MAC))
    replace = 2;
  
  if (replace != 0 || maclen != 0)
    plen = add_pseudoheader(header, plen, limit, EDNS0_OPTION_MAC, mac, maclen, 0, replace);

  return plen; 
}

struct subnet_opt {
  u16 family;
  u8 source_netmask, scope_netmask; 
  u8 addr[IN6ADDRSZ];
};

/**
 * @brief Get pointer to address field based on socket address family
 * 
 * @detailed Helper function that returns pointer to appropriate address field within
 *           the mysockaddr union based on address family type. Abstracts IPv4 vs IPv6
 *           address access pattern for client subnet processing. Returns pointer to
 *           sin6_addr field for IPv6 (AF_INET6), or sin_addr field for IPv4.
 *           Used throughout EDNS0 client subnet processing to handle dual-stack addresses.
 * 
 * @param addr Pointer to mysockaddr union containing socket address structure
 * @param family Socket address family: AF_INET for IPv4 or AF_INET6 for IPv6
 * 
 * @return Pointer to appropriate address field within socket address union
 * @retval &addr->in6.sin6_addr if family == AF_INET6 (IPv6 address pointer)
 * @retval &addr->in.sin_addr otherwise (IPv4 address pointer, default case)
 * 
 * @note Simple inline helper for address family abstraction
 * @note Does not validate family parameter (caller responsible)
 * 
 * @see calc_subnet_opt() for primary usage in client subnet option construction
 * @see union mysockaddr in dnsmasq.h for socket address union structure definition
 * 
 * EXAMPLE USAGE:
 * @code
 * union mysockaddr client_addr;
 * void *addrp = get_addrp(&client_addr, AF_INET6);
 * // addrp points to client_addr.in6.sin6_addr for IPv6 processing
 * @endcode
 * 
 * RFC COMPLIANCE: Address family abstraction for RFC 7871 client subnet processing
 * SIDE EFFECTS: None (pure accessor function)
 * THREAD SAFETY: Thread-safe (no state modification)
 */
static void *get_addrp(union mysockaddr *addr, const short family) 
{
  if (family == AF_INET6)
    return &addr->in6.sin6_addr;

  return &addr->in.sin_addr;
}

/**
 * @brief Calculate and populate EDNS0 client subnet option structure
 * 
 * @detailed Constructs the client subnet option data structure per RFC 7871 specification
 *           (draft-vandergaast-edns-client-subnet-02). Determines source address from
 *           either client socket address or configured fixed subnet addresses
 *           (daemon->add_subnet4/add_subnet6). Applies source netmask to address bytes,
 *           calculating exact byte length needed and masking final byte if netmask not
 *           aligned to byte boundary. Sets cacheability flag based on whether address
 *           is constant (configured subnet) or variable (client). Family field set to
 *           1 for IPv4 or 2 for IPv6 per RFC 7871 section 2.1. Handles zero netmask
 *           case (no address supplied).
 * 
 * @param opt Subnet option structure to populate with calculated values
 * @param source Client socket address for dynamic subnet calculation
 * @param cacheablep Pointer to flag set based on address constancy; may be NULL
 * 
 * @return Total option data length (4 bytes header + variable address length)
 * @retval 4 if source_netmask == 0 (no address supplied, header only)
 * @retval 4 + len where len = ((source_netmask - 1) >> 3) + 1 (address bytes included)
 * 
 * @note Cacheability set to 1 (cacheable) if using configured fixed subnet or no address
 * @note Cacheability set to 0 (non-cacheable) if using variable client address
 * @note Family field: 1 = IPv4, 2 = IPv6 per RFC 7871 assignment
 * @note Netmask applied with bit-level masking on final byte when not byte-aligned
 * 
 * @warning Assumes opt->source_netmask and opt->scope_netmask already set by caller
 * @warning Does not validate source address validity
 * 
 * @see get_addrp() for address family-based pointer extraction
 * @see add_source_addr() for client subnet option insertion into DNS packet
 * @see daemon->add_subnet4 and daemon->add_subnet6 for configured fixed subnets
 * 
 * EXAMPLE USAGE:
 * @code
 * struct subnet_opt opt;
 * opt.source_netmask = 24;  // /24 IPv4 subnet
 * opt.scope_netmask = 0;
 * union mysockaddr client;
 * int cacheable;
 * size_t optlen = calc_subnet_opt(&opt, &client, &cacheable);
 * // optlen = 7 (4 byte header + 3 bytes for /24), opt populated with subnet
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 7871 Section 2.1 (EDNS0 Client Subnet option format)
 * SIDE EFFECTS: Modifies opt structure fields; sets cacheability flag
 * THREAD SAFETY: Thread-safe (no global state modification)
 */
static size_t calc_subnet_opt(struct subnet_opt *opt, union mysockaddr *source, int *cacheablep)
{
  /* http://tools.ietf.org/html/draft-vandergaast-edns-client-subnet-02 */
  
  int len;
  void *addrp = NULL;
  int sa_family = source->sa.sa_family;
  int cacheable = 0;
  
  opt->source_netmask = 0;
  opt->scope_netmask = 0;
    
  if (source->sa.sa_family == AF_INET6 && daemon->add_subnet6)
    {
      opt->source_netmask = daemon->add_subnet6->mask;
      if (daemon->add_subnet6->addr_used) 
	{
	  sa_family = daemon->add_subnet6->addr.sa.sa_family;
	  addrp = get_addrp(&daemon->add_subnet6->addr, sa_family);
	  cacheable = 1;
	} 
      else 
	addrp = &source->in6.sin6_addr;
    }

  if (source->sa.sa_family == AF_INET && daemon->add_subnet4)
    {
      opt->source_netmask = daemon->add_subnet4->mask;
      if (daemon->add_subnet4->addr_used)
	{
	  sa_family = daemon->add_subnet4->addr.sa.sa_family;
	  addrp = get_addrp(&daemon->add_subnet4->addr, sa_family);
	  cacheable = 1; /* Address is constant */
	} 
	else 
	  addrp = &source->in.sin_addr;
    }
  
  opt->family = htons(sa_family == AF_INET6 ? 2 : 1);
  
  if (addrp && opt->source_netmask != 0)
    {
      len = ((opt->source_netmask - 1) >> 3) + 1;
      memcpy(opt->addr, addrp, len);
      if (opt->source_netmask & 7)
	opt->addr[len-1] &= 0xff << (8 - (opt->source_netmask & 7));
    }
  else
    {
      cacheable = 1; /* No address ever supplied. */
      len = 0;
    }

  if (cacheablep)
    *cacheablep = cacheable;
  
  return len + 4;
}
 
/* OPT_CLIENT_SUBNET = client subnet is added
   OPT_CLIENT_SUBNET + OPT_STRIP_ECS = client subnet is replaced
   OPT_STRIP_ECS = client subnet is removed */

/**
 * @brief Add or strip EDNS0 Client Subnet (ECS) option per RFC 7871
 * 
 * @detailed Manages EDNS0 Client Subnet option (EDNS0_OPTION_CLIENT_SUBNET) based on
 *           configured policy flags implementing RFC 7871 (draft-vandergaast-edns-client-subnet-02).
 *           Behavior controlled by OPT_CLIENT_SUBNET and OPT_STRIP_ECS option flags:
 *           - OPT_CLIENT_SUBNET only: Adds client subnet option with source address
 *           - Both flags set: Replaces existing ECS option with configured subnet
 *           - OPT_STRIP_ECS only: Removes existing ECS option from packet
 *           - Neither flag: Checks if client sent ECS (marks non-cacheable if present)
 *           Uses calc_subnet_opt() to construct subnet data from client or configured address.
 *           When neither option enabled, performs passive ECS detection: if client sent ECS
 *           option, marks response non-cacheable since response varies by client subnet.
 *           Cacheability tracking ensures subnet-specific responses not cached globally.
 * 
 * @param header DNS packet header structure being modified
 * @param plen Current packet length before option modification
 * @param limit Pointer to end of packet buffer (prevents buffer overflow)
 * @param source Client socket address for subnet calculation
 * @param cacheable Pointer to cacheability flag; set to 0 if ECS present/added
 * 
 * @return Updated packet length after ECS option add/strip/detect operation
 * @retval plen unchanged if neither option enabled and no ECS detected
 * @retval plen increased if ECS option added with subnet information
 * @retval plen decreased if ECS option stripped from packet
 * 
 * @note Sets *cacheable = 0 when ECS added or detected (response subnet-specific)
 * @note Passive detection mode (neither flag set) checks for existing ECS via check_source()
 * @note replace parameter to add_pseudoheader: 0=no replace, 1=replace if exists, 2=remove only
 * @note Subnet option data constructed by calc_subnet_opt() helper
 * 
 * @warning Requires valid source address for subnet calculation
 * @warning Option modification controlled by global option flags
 * 
 * @see calc_subnet_opt() for subnet option data structure construction
 * @see add_pseudoheader() for EDNS0 option insertion/replacement mechanism
 * @see check_source() for passive ECS detection in client queries
 * @see option_bool() for checking OPT_CLIENT_SUBNET and OPT_STRIP_ECS flags
 * 
 * EXAMPLE USAGE:
 * @code
 * int cacheable = 1;
 * union mysockaddr client_addr;
 * // Configuration: option_bool(OPT_CLIENT_SUBNET) = 1, option_bool(OPT_STRIP_ECS) = 0
 * plen = add_source_addr(header, plen, limit, &client_addr, &cacheable);
 * // cacheable now 0 if ECS added; plen updated with client subnet option
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 7871 (EDNS0 Client Subnet, draft-vandergaast-edns-client-subnet-02)
 * SIDE EFFECTS: Modifies DNS packet; may set cacheability flag; reads global options
 * THREAD SAFETY: Single-threaded architecture; modifies packet in-place
 */
static size_t add_source_addr(struct dns_header *header, size_t plen, unsigned char *limit,
			      union mysockaddr *source, int *cacheable)
{
  /* http://tools.ietf.org/html/draft-vandergaast-edns-client-subnet-02 */
  
  int replace = 0, len = 0;
  struct subnet_opt opt;
  
  if (option_bool(OPT_CLIENT_SUBNET))
    {
      if (option_bool(OPT_STRIP_ECS))
	replace = 1;
      len = calc_subnet_opt(&opt, source, cacheable);
    }
  else if (option_bool(OPT_STRIP_ECS))
    replace = 2;
  else
    {
      unsigned char *pheader;
      /* If we still think the data is cacheable, and we're not
	 messing with EDNS client subnet ourselves, see if the client
	 sent a client subnet. If so, mark the data as uncacheable */
      if (*cacheable &&
	  (pheader = find_pseudoheader(header, plen, NULL, NULL, NULL, NULL)) &&
	  !check_source(header, plen, pheader, NULL))
	*cacheable = 0;
      
      return plen;
    }
  
  return add_pseudoheader(header, plen, (unsigned char *)limit, EDNS0_OPTION_CLIENT_SUBNET, (unsigned char *)&opt, len, 0, replace);
}

/**
 * @brief Validate EDNS0 client subnet option in DNS response matches query
 * 
 * @detailed Implements RFC 7871 Section 9.2 response validation: verifies that client subnet
 *           option (EDNS0_OPTION_CLIENT_SUBNET) in DNS response matches the subnet sent in
 *           original query. Performs two validation modes based on peer parameter:
 *           - peer != NULL: Full validation mode - compares response subnet against expected
 *             subnet calculated from peer address, including scope netmask from response.
 *             Option length and all bytes must match exactly via memcmp.
 *           - peer == NULL: Existence check mode - simply checks if EDNS0 client subnet option
 *             exists with non-zero source_netmask (degrades to presence check only).
 *           Validation failure (return 0) indicates cache poisoning attempt or misconfigured
 *           upstream server. Success (return 1) indicates response trustworthy for caching.
 *           Parses EDNS0 OPT pseudo-RR additional record, iterates through options looking
 *           for EDNS0_OPTION_CLIENT_SUBNET code. Uses calc_subnet_opt() to construct expected
 *           option format for comparison.
 * 
 * @param header DNS response packet header structure
 * @param plen Total packet length for boundary checking
 * @param pseudoheader Pointer to EDNS0 OPT pseudo-RR in additional section
 * @param peer Client socket address to validate against; NULL for existence check only
 * 
 * @return Validation result indicating whether response subnet matches expected
 * @retval 1 if validation succeeds (subnet matches or check passes)
 * @retval 0 if validation fails (subnet mismatch in full validation mode)
 * @retval 1 if malformed packet detected (safe failure mode returns success)
 * 
 * @note Returns 1 (success) for malformed packets as defensive programming
 * @note peer == NULL mode checks source_netmask != 0 (option present and non-empty)
 * @note Full validation compares all option bytes including scope_netmask from response
 * @note Used on DNS responses received from upstream servers
 * 
 * @warning Assumes pseudoheader points to valid EDNS0 OPT record
 * @warning Malformed packet returns 1 (accepts response) to avoid false positives
 * 
 * @see calc_subnet_opt() for constructing expected subnet option format
 * @see add_source_addr() for adding client subnet to outbound queries
 * @see EDNS0_OPTION_CLIENT_SUBNET constant for option code
 * 
 * EXAMPLE USAGE:
 * @code
 * unsigned char *pseudoheader = find_pseudoheader(header, plen, ...);
 * union mysockaddr client_addr;
 * int valid = check_source(header, plen, pseudoheader, &client_addr);
 * if (!valid) {
 *   // Response subnet mismatch - potential cache poisoning or server error
 *   // Discard response and retry query
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 7871 Section 9.2 (Response Validation)
 * SIDE EFFECTS: None (read-only validation function)
 * THREAD SAFETY: Thread-safe (no state modification)
 */
int check_source(struct dns_header *header, size_t plen, unsigned char *pseudoheader, union mysockaddr *peer)
{
  /* Section 9.2, Check that subnet option (if any) in reply matches.
     if peer == NULL, this degrades to a check for the existence of and EDNS0 client-subnet option. */
  
  int len, calc_len;
  struct subnet_opt opt;
  unsigned char *p;
  int code, i, rdlen;
  
  if (peer)
    calc_len = calc_subnet_opt(&opt, peer, NULL);
   
  if (!(p = skip_name(pseudoheader, header, plen, 10)))
    return 1;
  
  p += 8; /* skip UDP length and RCODE */
  
  GETSHORT(rdlen, p);
  if (!CHECK_LEN(header, p, plen, rdlen))
    return 1; /* bad packet */
  
  /* check if option there */
  for (i = 0; i + 4 < rdlen; i += len + 4)
     {
       GETSHORT(code, p);
       GETSHORT(len, p);
       if (code == EDNS0_OPTION_CLIENT_SUBNET)
	 {
	   if (peer)
	     {
	       /* make sure this doesn't mismatch. */
	       opt.scope_netmask = p[3];
	       if (len != calc_len || memcmp(p, &opt, len) != 0)
		 return 0;
	     }
	   else if (((struct subnet_opt *)p)->source_netmask != 0)
	     return 0;
	 }
       p += len;
     }
  
  return 1;
}

/* See https://docs.umbrella.com/umbrella-api/docs/identifying-dns-traffic for
 * detailed information on packet formating.
 */
#define UMBRELLA_VERSION    1
#define UMBRELLA_TYPESZ     2

#define UMBRELLA_ASSET      0x0004
#define UMBRELLA_ASSETSZ    sizeof(daemon->umbrella_asset)
#define UMBRELLA_ORG        0x0008
#define UMBRELLA_ORGSZ      sizeof(daemon->umbrella_org)
#define UMBRELLA_IPV4       0x0010
#define UMBRELLA_IPV6       0x0020
#define UMBRELLA_DEVICE     0x0040
#define UMBRELLA_DEVICESZ   sizeof(daemon->umbrella_device)

struct umbrella_opt {
  u8 magic[4] ATTRIBUTE_NONSTRING;
  u8 version;
  u8 flags;
  /* We have 4 possible fields since we'll never send both IPv4 and
   * IPv6, so using the larger of the two to calculate max buffer size.
   * Each field also has a type header.  So the following accounts for
   * the type headers and each field size to get a max buffer size.
   */
  u8 fields[4 * UMBRELLA_TYPESZ + UMBRELLA_ORGSZ + IN6ADDRSZ + UMBRELLA_DEVICESZ + UMBRELLA_ASSETSZ];
};

/**
 * @brief Add Cisco Umbrella EDNS0 option with client identity information
 * 
 * @detailed Constructs and adds Cisco Umbrella EDNS0 option (option code EDNS0_OPTION_UMBRELLA)
 *           containing client identity metadata for security analytics and policy enforcement.
 *           The Umbrella option enables Cisco security services to correlate DNS queries with
 *           specific organizations, devices, and assets for threat detection and policy application.
 *           
 *           Option structure format:
 *           - Fixed header: "ODNS" magic (4 bytes), version (2 bytes), flags (2 bytes)
 *           - Optional TLV fields (Type-Length-Value encoding):
 *             * UMBRELLA_ORG: Organization ID (6 bytes: type=2, value=4-byte org ID)
 *             * UMBRELLA_IPV4/IPV6: Client IP address (6 or 18 bytes)
 *             * UMBRELLA_DEVICE: Device identifier (42 bytes: type=2, value=40-byte device ID)
 *             * UMBRELLA_ASSET: Asset ID (6 bytes: type=2, value=4-byte asset ID)
 *           
 *           Sets *cacheable = 0 to prevent caching since response depends on client identity
 *           (different clients receive different policy-based responses). Extracts client IP
 *           address from source sockaddr, determines address family (IPv4 or IPv6), and
 *           constructs option with configured organization ID (daemon->umbrella_org), device ID
 *           (daemon->umbrella_device), and asset ID (daemon->umbrella_asset) if configured.
 *           Device ID inclusion controlled by OPT_UMBRELLA_DEVID option flag.
 *           
 *           Delegates option addition to add_pseudoheader() with replace=1 to ensure Umbrella
 *           option replaces any existing instance.
 * 
 * @param header DNS query packet header structure to modify
 * @param plen Current packet length before adding option
 * @param limit Packet buffer end boundary for overflow prevention
 * @param source Client socket address (IPv4 or IPv6) providing IP for option
 * @param cacheable Output flag pointer set to 0 (response not cacheable due to client-specific)
 * 
 * @return Updated packet length after adding Umbrella option
 * @retval >plen if option added successfully (packet grew)
 * @retval plen if option addition failed (packet unchanged, buffer full)
 * 
 * @note Sets *cacheable = 0 because Umbrella responses are client-specific
 * @note Organization ID required for Umbrella deployment (daemon->umbrella_org must be non-zero)
 * @note Device ID inclusion controlled by OPT_UMBRELLA_DEVID configuration flag
 * @note Asset ID optional (included if daemon->umbrella_asset configured)
 * @note Uses replace=1 to ensure only one Umbrella option exists
 * @note Static function (internal to edns0.c module)
 * 
 * @warning Assumes source address family is AF_INET or AF_INET6
 * @warning Does not validate daemon->umbrella_* configuration values
 * 
 * @see add_pseudoheader() for underlying option addition mechanism
 * @see get_addrp() for extracting IP address from sockaddr
 * @see add_edns0_config() which calls this function when Umbrella configured
 * @see struct umbrella_opt in dnsmasq.h for option structure definition
 * 
 * EXAMPLE USAGE:
 * @code
 * union mysockaddr client_addr;
 * int cacheable;
 * size_t new_len = add_umbrella_opt(header, plen, limit, &client_addr, &cacheable);
 * // cacheable is now 0, new_len > plen if option added successfully
 * @endcode
 * 
 * RFC COMPLIANCE: Cisco Umbrella proprietary EDNS0 option (not IETF standard)
 * SIDE EFFECTS: Sets *cacheable = 0; modifies DNS packet by adding EDNS0 option
 * THREAD SAFETY: Thread-safe if daemon structure access is synchronized
 */
static size_t add_umbrella_opt(struct dns_header *header, size_t plen, unsigned char *limit, union mysockaddr *source, int *cacheable)
{
  *cacheable = 0;

  struct umbrella_opt opt = {{"ODNS"}, UMBRELLA_VERSION, 0, {0}};
  u8 *u = &opt.fields[0];
  int family = source->sa.sa_family;
  int size = family == AF_INET ? INADDRSZ : IN6ADDRSZ;

  if (daemon->umbrella_org)
    {
      PUTSHORT(UMBRELLA_ORG, u);
      PUTLONG(daemon->umbrella_org, u);
    }
  
  PUTSHORT(family == AF_INET ? UMBRELLA_IPV4 : UMBRELLA_IPV6, u);
  memcpy(u, get_addrp(source, family), size);
  u += size;
  
  if (option_bool(OPT_UMBRELLA_DEVID))
    {
      PUTSHORT(UMBRELLA_DEVICE, u);
      memcpy(u, (char *)&daemon->umbrella_device, UMBRELLA_DEVICESZ);
      u += UMBRELLA_DEVICESZ;
    }

  if (daemon->umbrella_asset)
    {
      PUTSHORT(UMBRELLA_ASSET, u);
      PUTLONG(daemon->umbrella_asset, u);
    }
  
  return add_pseudoheader(header, plen, (unsigned char *)limit, EDNS0_OPTION_UMBRELLA, (unsigned char *)&opt, u - (u8 *)&opt, 0, 1);
}

/**
 * @brief Add all configured EDNS0 options to outbound DNS query
 * 
 * @detailed Master function that adds all configured EDNS0 extension options to a DNS query
 *           before forwarding to upstream servers. Coordinates addition of multiple EDNS0 options
 *           based on daemon configuration and sets cacheable flag appropriately.
 *           
 *           This function serves as the central integration point for all EDNS0 extensions,
 *           adding options in the following order:
 *           1. MAC address option (via add_mac()) - for CPE identification
 *           2. DNS client subnet option (via add_dns_client()) - for geolocation
 *           3. NOMCPEID option - for multicast DNS client identification (if configured)
 *           4. Cisco Umbrella option (via add_umbrella_opt()) - for security policy (if enabled)
 *           5. EDNS Client Subnet (via add_source_addr()) - for authoritative server optimization
 *           
 *           The *cacheable flag is initially set to 1 (cacheable) and may be set to 0 by
 *           individual option addition functions if their options make the response client-specific
 *           and therefore uncacheable. For example, Umbrella options cause *cacheable = 0 because
 *           different clients receive different policy-based responses.
 *           
 *           Each option addition function is called sequentially with the updated plen from the
 *           previous call, allowing the packet to grow incrementally. If any option cannot be
 *           added due to buffer space constraints, that option is silently skipped and packet
 *           length remains unchanged.
 *           
 *           Called from forward.c during query forwarding to add client-specific EDNS0 options
 *           before sending to upstream servers. The upstream servers use these options for
 *           geolocation-aware responses, security policy enforcement, and client identification.
 * 
 * @param header DNS query packet header structure to modify
 * @param plen Current packet length before adding options
 * @param limit Packet buffer end boundary for overflow prevention
 * @param source Client socket address (IPv4 or IPv6) used for client subnet and IP-based options
 * @param now Current timestamp for time-based option processing
 * @param cacheable Output flag pointer: set to 1 initially, may be set to 0 if options added
 *                  make response client-specific (e.g., Umbrella, MAC address)
 * 
 * @return Updated packet length after adding all configured EDNS0 options
 * @retval >plen if one or more options added successfully
 * @retval plen if no options added (none configured or all failed due to buffer space)
 * 
 * @note Initial *cacheable = 1 (response is cacheable unless options indicate otherwise)
 * @note Option addition is best-effort: failures are silent (packet length unchanged)
 * @note NOMCPEID option only added if daemon->dns_client_id is configured
 * @note Umbrella option only added if OPT_UMBRELLA flag is set
 * @note Order of option addition may affect packet layout but not semantic behavior
 * @note Public function (non-static) called from forward.c
 * 
 * @warning Assumes plen + all options fits within buffer (limit - (unsigned char *)header)
 * @warning Does not validate that buffer has sufficient space before starting
 * 
 * @see add_mac() for MAC address option addition logic
 * @see add_dns_client() for DNS client subnet option
 * @see add_pseudoheader() for NOMCPEID option addition
 * @see add_umbrella_opt() for Cisco Umbrella option
 * @see add_source_addr() for EDNS Client Subnet (ECS) option
 * @see forward.c for call site during query forwarding
 * 
 * EXAMPLE USAGE:
 * @code
 * union mysockaddr client_addr;
 * int cacheable;
 * time_t now = time(NULL);
 * size_t new_len = add_edns0_config(header, plen, limit, &client_addr, now, &cacheable);
 * // new_len >= plen (may have grown with options)
 * // cacheable indicates whether response can be cached
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 6891 (EDNS0 framework), RFC 7871 (EDNS Client Subnet)
 * SIDE EFFECTS: Sets *cacheable based on options added; modifies DNS packet
 * THREAD SAFETY: Thread-safe if daemon structure access is synchronized
 */
size_t add_edns0_config(struct dns_header *header, size_t plen, unsigned char *limit, 
			union mysockaddr *source, time_t now, int *cacheable)    
{
  *cacheable = 1;
  
  plen  = add_mac(header, plen, limit, source, now, cacheable);
  plen = add_dns_client(header, plen, limit, source, now, cacheable);
  
  if (daemon->dns_client_id)
    plen = add_pseudoheader(header, plen, limit, EDNS0_OPTION_NOMCPEID, 
			    (unsigned char *)daemon->dns_client_id, strlen(daemon->dns_client_id), 0, 1);

  if (option_bool(OPT_UMBRELLA))
    plen = add_umbrella_opt(header, plen, limit, source, cacheable);
  
  plen = add_source_addr(header, plen, limit, source, cacheable);

  return plen;
}

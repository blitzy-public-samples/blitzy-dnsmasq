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
 * @file dns-protocol.h
 * @brief DNS protocol constants and wire format structures per RFC 1035
 * 
 * DETAILED PURPOSE:
 * This header file serves as the canonical source for all DNS protocol constants,
 * wire format structures, and serialization macros used throughout the dnsmasq DNS
 * implementation. It defines the complete set of RFC 1035 DNS message format elements
 * including response codes, resource record types, message header structure, and
 * byte-order conversion macros for network protocol handling.
 * 
 * The definitions in this file are used extensively by src/rfc1035.c for DNS packet
 * parsing and serialization, src/forward.c for query processing, src/cache.c for
 * record type handling, and src/dnssec.c for DNSSEC-related record types.
 * 
 * KEY RESPONSIBILITIES:
 * - Define all DNS protocol port numbers and size limits per RFC 1035
 * - Enumerate DNS response codes (NOERROR, NXDOMAIN, SERVFAIL, etc.)
 * - Enumerate DNS resource record types (A, AAAA, CNAME, MX, DNSSEC types, etc.)
 * - Enumerate DNS class codes (IN, CHAOS, HESIOD, ANY)
 * - Define EDNS0 option codes per RFC 6891 and IANA registry
 * - Define RFC 8914 Extended DNS Error (EDE) codes for detailed error reporting
 * - Declare struct dns_header representing the DNS message header wire format
 * - Provide macros for extracting and setting header flags (QR, AA, TC, RD, RA, AD, CD)
 * - Provide byte-order conversion macros (GETSHORT, GETLONG, PUTSHORT, PUTLONG) for
 *   network-to-host and host-to-network transformation of multi-byte integers
 * - Provide length validation macros (CHECK_LEN, ADD_RDLEN) for safe packet parsing
 * 
 * DEPENDENCIES:
 * Included by: src/rfc1035.c (DNS wire format), src/forward.c (query handling),
 *              src/cache.c (record type handling), src/dnssec.c (DNSSEC types),
 *              src/dnsmasq.h (global includes)
 * Includes: None - this is a leaf header with only constant definitions
 * 
 * DATA STRUCTURES:
 * - struct dns_header (lines 122-126): DNS message header wire format with 6 fields:
 *   id, flags (hb3/hb4), question count, answer count, authority count, additional count
 * 
 * COMPILE-TIME OPTIONS:
 * This file has no conditional compilation - all definitions are universally applicable
 * across all platform configurations and feature builds.
 * 
 * RFC COMPLIANCE:
 * - RFC 1035: Domain Names - Implementation and Specification (base DNS protocol)
 * - RFC 2929: Domain Name System (DNS) IANA Considerations (registry procedures)
 * - RFC 6891: Extension Mechanisms for DNS (EDNS0)
 * - RFC 8914: Extended DNS Errors (detailed error reporting)
 * 
 * @copyright Copyright (c) 2000-2025 Simon Kelley
 * @license GPL-2.0-or-later
 */

/**
 * @defgroup DNSPorts DNS and Network Service Port Numbers
 * @brief Standard port numbers for DNS and related network services
 * @{
 */

/** DNS protocol standard port number (UDP and TCP) per RFC 1035 Section 4.2 */
#define NAMESERVER_PORT 53

/** TFTP protocol standard port number per RFC 1350 (used for network boot) */
#define TFTP_PORT       69

/** First non-privileged port number (ports 1-1023 require root privileges) */
#define MIN_PORT        1024

/** Maximum valid port number (16-bit unsigned integer limit) */
#define MAX_PORT        65535u

/** @} */ /* End of DNSPorts group */

/**
 * @defgroup DNSSizes DNS Protocol Size Constants
 * @brief Size limits and length constants for DNS protocol elements per RFC 1035
 * @{
 */

/** IPv6 address size in bytes (128 bits = 16 bytes) */
#define IN6ADDRSZ       16

/** IPv4 address size in bytes (32 bits = 4 bytes) */
#define INADDRSZ        4

/** Default maximum DNS UDP packet size per RFC 1035 (512 bytes without EDNS0) */
#define PACKETSZ	512

/** Maximum domain name length in presentation format including null terminator (RFC 1035: 255 + labels + null) */
#define MAXDNAME	1025

/** Fixed size of resource record metadata (name compression ptr, type, class, TTL, rdlength = 10 bytes) */
#define RRFIXEDSZ	10

/** Maximum length of a single DNS label per RFC 1035 Section 2.3.4 (63 characters) */
#define MAXLABEL        63

/** @} */ /* End of DNSSizes group */

/**
 * @defgroup DNSRCodes DNS Response Codes (RCODE)
 * @brief DNS message response codes per RFC 1035 Section 4.1.1
 * 
 * Response codes indicate the status of a DNS query response. These values are stored
 * in the RCODE field (bits 0-3) of byte 3 in the DNS header flags.
 * @{
 */

/** No error condition - query was successful */
#define NOERROR		0

/** Format error - name server unable to interpret query due to format problem */
#define FORMERR		1

/** Server failure - name server unable to process query due to internal problem */
#define SERVFAIL	2

/** Name error (NXDOMAIN) - domain name referenced in query does not exist */
#define NXDOMAIN	3

/** Not implemented - name server does not support requested query type */
#define NOTIMP		4

/** Query refused - name server refuses to perform operation for policy reasons */
#define REFUSED		5

/** @} */ /* End of DNSRCodes group */

/**
 * @defgroup DNSOpcodes DNS Operation Codes (OPCODE)
 * @brief DNS message operation codes per RFC 1035 Section 4.1.1
 * 
 * Operation codes specify the kind of query in a DNS message. These values are stored
 * in the OPCODE field (bits 11-14) of the DNS header flags.
 * @{
 */

/** Standard query (QUERY) - the default and most common DNS operation */
#define QUERY           0

/** @} */ /* End of DNSOpcodes group */

/**
 * @defgroup DNSClasses DNS Class Codes
 * @brief DNS class field values per RFC 1035 Section 3.2.4
 * 
 * Class codes identify the protocol family or namespace for DNS queries and resource records.
 * The IN (Internet) class is used for nearly all modern DNS queries.
 * @{
 */

/** Internet class (IN) - the standard class for Internet IP addresses */
#define C_IN            1

/** Chaos class - originally for MIT's Chaosnet, now rarely used */
#define C_CHAOS         3

/** Hesiod class - used by MIT's Hesiod information service */
#define C_HESIOD        4

/** Wildcard class (ANY) - matches any class (used in queries only, not in RRs) */
#define C_ANY           255

/** @} */ /* End of DNSClasses group */

/**
 * @defgroup DNSRRTypes DNS Resource Record Types
 * @brief DNS resource record type codes per RFC 1035 and subsequent RFCs
 * 
 * Resource record types identify the format and meaning of data in DNS resource records.
 * This includes standard record types (A, AAAA, CNAME, MX) and DNSSEC-related types
 * (DNSKEY, RRSIG, NSEC, DS).
 * @{
 */

/** A record - IPv4 host address (RFC 1035) */
#define T_A		1

/** NS record - authoritative name server (RFC 1035) */
#define T_NS            2

/** MD record - mail destination (obsolete, RFC 1035) */
#define T_MD            3

/** MF record - mail forwarder (obsolete, RFC 1035) */
#define T_MF            4

/** CNAME record - canonical name for an alias (RFC 1035) */
#define T_CNAME		5

/** SOA record - start of authority zone record (RFC 1035) */
#define T_SOA		6

/** MB record - mailbox domain name (experimental, RFC 1035) */
#define T_MB            7

/** MG record - mail group member (experimental, RFC 1035) */
#define T_MG            8

/** MR record - mail rename domain name (experimental, RFC 1035) */
#define T_MR            9

/** PTR record - pointer to canonical name for reverse DNS lookups (RFC 1035) */
#define T_PTR		12

/** MINFO record - mailbox or mail list information (experimental, RFC 1035) */
#define T_MINFO         14

/** MX record - mail exchange (RFC 1035) */
#define T_MX		15

/** TXT record - text strings (RFC 1035) */
#define T_TXT		16

/** RP record - responsible person (RFC 1183) */
#define T_RP            17

/** AFSDB record - AFS database location (RFC 1183) */
#define T_AFSDB         18

/** RT record - route through (RFC 1183) */
#define T_RT            21

/** SIG record - security signature (RFC 2535, obsoleted by RRSIG in DNSSEC) */
#define T_SIG		24

/** PX record - pointer to X.400/RFC822 mapping information (RFC 2163) */
#define T_PX            26

/** AAAA record - IPv6 host address (RFC 3596) */
#define T_AAAA		28

/** NXT record - next domain (obsolete DNSSEC, RFC 2535, replaced by NSEC) */
#define T_NXT           30

/** SRV record - service location (RFC 2761) */
#define T_SRV		33

/** NAPTR record - naming authority pointer (RFC 2915) */
#define T_NAPTR		35

/** KX record - key exchange delegation (RFC 2230) */
#define T_KX            36

/** DNAME record - delegation name (RFC 6672) */
#define T_DNAME         39

/** OPT pseudo-record - EDNS0 option (RFC 6891, not a true RR type) */
#define T_OPT		41

/** DS record - delegation signer for DNSSEC chain of trust (RFC 4034) */
#define T_DS            43

/** RRSIG record - DNSSEC signature (RFC 4034) */
#define T_RRSIG         46

/** NSEC record - next secure record for DNSSEC authenticated denial of existence (RFC 4034) */
#define T_NSEC          47

/** DNSKEY record - DNS public key for DNSSEC (RFC 4034) */
#define T_DNSKEY        48

/** NSEC3 record - hashed authenticated denial of existence (RFC 5155) */
#define T_NSEC3         50

/** TKEY record - transaction key (RFC 2930) */
#define	T_TKEY		249

/** TSIG record - transaction signature (RFC 2845) */
#define	T_TSIG		250

/** AXFR query type - zone transfer request (RFC 1035, query type only, not an RR) */
#define T_AXFR          252

/** MAILB query type - mailbox-related records (query type only, RFC 1035) */
#define T_MAILB		253

/** ANY query type - request for all records (wildcard, RFC 1035, query type only) */
#define T_ANY		255

/** CAA record - certification authority authorization (RFC 6844) */
#define T_CAA           257

/** @} */ /* End of DNSRRTypes group */

/**
 * @defgroup EDNS0Options EDNS0 Option Codes
 * @brief Extension Mechanisms for DNS (EDNS0) option codes per RFC 6891
 * 
 * EDNS0 options are carried in the OPT pseudo-RR (T_OPT) to extend DNS protocol
 * capabilities beyond the limitations of the original RFC 1035 specification.
 * Options include client subnet information, extended error codes, and vendor-specific
 * extensions. Option codes are maintained by IANA, with some vendor-specific codes
 * in the private use range.
 * 
 * Source: RFC 6891 (EDNS0), RFC 7871 (Client Subnet), RFC 8914 (Extended Errors)
 * @{
 */

/** MAC address option - dyndns.org temporary assignment (private use range) */
#define EDNS0_OPTION_MAC            65001

/** Client subnet option - provides client IP prefix for geo-aware responses (RFC 7871, IANA-assigned) */
#define EDNS0_OPTION_CLIENT_SUBNET  8

/** Extended DNS Error option - detailed error information (RFC 8914, IANA-assigned) */
#define EDNS0_OPTION_EDE            15

/** Nominum device ID option - device identification (Nominum temporary assignment, private use) */
#define EDNS0_OPTION_NOMDEVICEID    65073

/** Nominum CPE ID option - customer premises equipment identification (Nominum temporary, private use) */
#define EDNS0_OPTION_NOMCPEID       65074

/** Cisco Umbrella option - Umbrella security platform integration (Cisco temporary, private use) */
#define EDNS0_OPTION_UMBRELLA       20292

/** @} */ /* End of EDNS0Options group */

/**
 * @defgroup EDECodes Extended DNS Error Codes
 * @brief Extended DNS Error (EDE) codes per RFC 8914
 * 
 * Extended DNS Errors provide detailed diagnostic information about DNS resolution
 * failures, particularly for DNSSEC validation errors. These codes are carried in
 * the EDNS0 EDE option (option code 15) to help clients and operators diagnose
 * DNS resolution problems. Negative values are dnsmasq-specific internal codes
 * not transmitted on the wire.
 * 
 * Source: RFC 8914 (Extended DNS Errors)
 * @{
 */

/** Internal: No extended DNS error available (dnsmasq-specific, not in RFC 8914) */
#define EDE_UNSET          -1

/** Other error - general catch-all for unspecified errors (RFC 8914, code 0) */
#define EDE_OTHER           0

/** Unsupported DNSKEY algorithm - DNSSEC validation failed due to unknown algorithm (RFC 8914, code 1) */
#define EDE_USUPDNSKEY      1

/** Unsupported DS digest type - DS record uses unsupported hash algorithm (RFC 8914, code 2) */
#define EDE_USUPDS          2

/** Stale answer - resolver returning cached data past TTL expiration (RFC 8914, code 3) */
#define EDE_STALE           3

/** Forged answer - response appears to be fake or manipulated (RFC 8914, code 4) */
#define EDE_FORGED          4

/** DNSSEC indeterminate - unable to determine DNSSEC validation status (RFC 8914, code 5) */
#define EDE_DNSSEC_IND      5

/** DNSSEC bogus - DNSSEC validation conclusively failed (RFC 8914, code 6) */
#define EDE_DNSSEC_BOGUS    6

/** Signature expired - RRSIG signature past expiration time (RFC 8914, code 7) */
#define EDE_SIG_EXP         7

/** Signature not yet valid - RRSIG signature before inception time (RFC 8914, code 8) */
#define EDE_SIG_NYV         8

/** DNSKEY missing - no DNSKEY record found for validation (RFC 8914, code 9) */
#define EDE_NO_DNSKEY       9

/** RRSIGs missing - expected RRSIG records not present (RFC 8914, code 10) */
#define EDE_NO_RRSIG       10

/** No zone key bit set - DNSKEY lacks zone signing key flag (RFC 8914, code 11) */
#define EDE_NO_ZONEKEY     11

/** NSEC missing - expected NSEC record not present (RFC 8914, code 12) */
#define EDE_NO_NSEC        12

/** Cached error - resolver returning cached error response (RFC 8914, code 13) */
#define EDE_CACHED_ERR     13

/** Not ready - server not ready to answer query (RFC 8914, code 14) */
#define EDE_NOT_READY      14

/** Blocked - query blocked by policy (RFC 8914, code 15) */
#define EDE_BLOCKED        15

/** Censored - answer censored by policy (RFC 8914, code 16) */
#define EDE_CENSORED       16

/** Filtered - query filtered by policy (RFC 8914, code 17) */
#define EDE_FILTERED       17

/** Prohibited - query prohibited by policy (RFC 8914, code 18) */
#define EDE_PROHIBITED     18

/** Stale NXDOMAIN - stale NXDOMAIN answer returned (RFC 8914, code 19) */
#define EDE_STALE_NXD      19

/** Not authoritative - server is not authoritative for zone (RFC 8914, code 20) */
#define EDE_NOT_AUTH       20

/** Not supported - query type not supported (RFC 8914, code 21) */
#define EDE_NOT_SUP        21

/** No reachable authority - unable to reach authoritative servers (RFC 8914, code 22) */
#define EDE_NO_AUTH        22

/** Network error - network error prevented resolution (RFC 8914, code 23) */
#define EDE_NETERR         23

/** Invalid data - response data invalid or malformed (RFC 8914, code 24) */
#define EDE_INVALID_DATA   24

/** Signature expired before valid - RRSIG expiration before inception (RFC 8914, code 25) */
#define EDE_SIG_E_B_V      25

/** Too early - response generated before acceptable time (RFC 8914, code 26) */
#define EDE_TOO_EARLY      26

/** Unsupported NSEC3 iterations value - NSEC3 iterations exceed policy limit (RFC 8914, code 27) */
#define EDE_UNS_NS3_ITER   27

/** Unable to conform to policy - policy requirements cannot be satisfied (RFC 8914, code 28) */
#define EDE_UNABLE_POLICY  28

/** Synthesized - answer was synthesized by resolver (RFC 8914, code 29) */
#define EDE_SYNTHESIZED    29

/** @} */ /* End of EDECodes group */

/**
 * @struct dns_header
 * @brief DNS message header structure per RFC 1035 Section 4.1.1
 * 
 * This structure represents the fixed-format 12-byte header that appears at the
 * beginning of all DNS messages (queries and responses). The header contains the
 * message ID, flags controlling query/response behavior, and counts for the four
 * sections that follow (question, answer, authority, additional).
 * 
 * WIRE FORMAT LAYOUT (12 bytes):
 * Bytes 0-1:   id       - 16-bit message identifier for matching queries and responses
 * Bytes 2-3:   flags    - Split into hb3 and hb4, containing QR, OPCODE, AA, TC, RD, RA, Z, AD, CD, RCODE
 * Bytes 4-5:   qdcount  - Number of entries in question section
 * Bytes 6-7:   ancount  - Number of resource records in answer section
 * Bytes 8-9:   nscount  - Number of name server records in authority section
 * Bytes 10-11: arcount  - Number of resource records in additional section
 * 
 * All multi-byte fields are in network byte order (big-endian).
 * 
 * Source: RFC 1035 Section 4.1.1 (DNS Header Format)
 * Implementation: src/rfc1035.c uses this structure for packet parsing and serialization
 * 
 * @see HB3_QR, HB3_OPCODE, HB3_AA, HB3_TC, HB3_RD for hb3 bit masks
 * @see HB4_RA, HB4_AD, HB4_CD, HB4_RCODE for hb4 bit masks
 * @see OPCODE(), SET_OPCODE() for opcode access macros
 * @see RCODE(), SET_RCODE() for response code access macros
 */
struct dns_header {
  /** Message identifier - 16-bit ID for matching queries with responses (RFC 1035 §4.1.1) */
  u16 id;
  
  /** Header byte 3 - Contains QR (1 bit), OPCODE (4 bits), AA (1 bit), TC (1 bit), RD (1 bit) */
  u8  hb3;
  
  /** Header byte 4 - Contains RA (1 bit), Z (1 bit), AD (1 bit), CD (1 bit), RCODE (4 bits) */
  u8  hb4;
  
  /** Question count - Number of entries in question section (RFC 1035 §4.1.1) */
  u16 qdcount;
  
  /** Answer count - Number of resource records in answer section (RFC 1035 §4.1.1) */
  u16 ancount;
  
  /** Name server count - Number of name server RRs in authority section (RFC 1035 §4.1.1) */
  u16 nscount;
  
  /** Additional records count - Number of RRs in additional records section (RFC 1035 §4.1.1) */
  u16 arcount;
};

/**
 * @defgroup DNSHeaderFlags DNS Header Flags (Header Bytes 3 and 4)
 * @brief Bit masks for DNS header flags in hb3 and hb4 fields
 * 
 * DNS header flags are split across two bytes (hb3 and hb4) in the dns_header structure.
 * These flags control query/response behavior, indicate authoritative answers, signal
 * truncation, request recursion, and provide DNSSEC validation status.
 * 
 * HEADER BYTE 3 (hb3) BIT LAYOUT:
 * Bit 7:     QR (0=query, 1=response)
 * Bits 6-3:  OPCODE (0=QUERY, 1=IQUERY, 2=STATUS)
 * Bit 2:     AA (Authoritative Answer)
 * Bit 1:     TC (TrunCation)
 * Bit 0:     RD (Recursion Desired)
 * 
 * HEADER BYTE 4 (hb4) BIT LAYOUT:
 * Bit 7:     RA (Recursion Available)
 * Bit 6:     Z (Reserved, must be zero)
 * Bit 5:     AD (Authenticated Data - DNSSEC)
 * Bit 4:     CD (Checking Disabled - DNSSEC)
 * Bits 3-0:  RCODE (Response Code)
 * 
 * Source: RFC 1035 §4.1.1, RFC 4035 §3.1.6 (DNSSEC flags)
 * @{
 */

/** QR flag - Query (0) or Response (1) indicator (RFC 1035 §4.1.1, bit 15 of header flags) */
#define HB3_QR       0x80

/** OPCODE mask - Operation code field, bits 14-11 of header flags (RFC 1035 §4.1.1) */
#define HB3_OPCODE   0x78

/** AA flag - Authoritative Answer, set by name servers for authoritative responses (RFC 1035 §4.1.1, bit 10) */
#define HB3_AA       0x04

/** TC flag - TrunCation, indicates message was truncated due to length exceeding transmission channel (RFC 1035 §4.1.1, bit 9) */
#define HB3_TC       0x02

/** RD flag - Recursion Desired, set by query sender to request recursive resolution (RFC 1035 §4.1.1, bit 8) */
#define HB3_RD       0x01

/** RA flag - Recursion Available, set by name server if recursive service available (RFC 1035 §4.1.1, bit 7) */
#define HB4_RA       0x80

/** AD flag - Authenticated Data, set if resolver validated answer with DNSSEC (RFC 4035 §3.1.6, bit 5) */
#define HB4_AD       0x20

/** CD flag - Checking Disabled, set by query sender to disable DNSSEC validation (RFC 4035 §3.1.6, bit 4) */
#define HB4_CD       0x10

/** RCODE mask - Response Code field, bits 3-0 of header flags (RFC 1035 §4.1.1) */
#define HB4_RCODE    0x0f

/** @} */ /* End of DNSHeaderFlags group */

/**
 * @defgroup DNSHeaderAccessors DNS Header Field Accessor Macros
 * @brief Macros for extracting and setting OPCODE and RCODE fields in DNS headers
 * 
 * These macros provide convenient access to the OPCODE (operation code) and RCODE
 * (response code) fields embedded within the hb3 and hb4 bytes of the dns_header
 * structure. The macros handle bit shifting and masking to extract or modify
 * multi-bit fields without affecting adjacent flag bits.
 * 
 * OPCODE occupies bits 14-11 (4 bits) of the DNS header flags (bits 6-3 of hb3).
 * RCODE occupies bits 3-0 (4 bits) of the DNS header flags (bits 3-0 of hb4).
 * 
 * Source: RFC 1035 §4.1.1 (Header Format)
 * @{
 */

/**
 * @brief Extract OPCODE field from DNS header
 * 
 * Extracts the 4-bit OPCODE field from header byte 3 by masking with HB3_OPCODE
 * (0x78) and shifting right 3 bits to obtain values 0-15.
 * 
 * @param x Pointer to struct dns_header
 * @return OPCODE value (0=QUERY, 1=IQUERY, 2=STATUS, 3-15 reserved)
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dns_header *header = ...;
 * int opcode = OPCODE(header);  // Returns 0 for standard query
 * @endcode
 */
#define OPCODE(x)          (((x)->hb3 & HB3_OPCODE) >> 3)

/**
 * @brief Set OPCODE field in DNS header
 * 
 * Sets the 4-bit OPCODE field in header byte 3 by clearing the OPCODE bits
 * (using ~HB3_OPCODE mask) and then OR-ing in the new code value.
 * Preserves all other flag bits in hb3 (QR, AA, TC, RD).
 * 
 * @param x Pointer to struct dns_header to modify
 * @param code OPCODE value to set (0-15, typically 0 for QUERY), should be pre-shifted
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dns_header *header = ...;
 * SET_OPCODE(header, QUERY << 3);  // Set opcode to 0 (standard query)
 * @endcode
 */
#define SET_OPCODE(x, code) (x)->hb3 = ((x)->hb3 & ~HB3_OPCODE) | code

/**
 * @brief Extract RCODE (response code) field from DNS header
 * 
 * Extracts the 4-bit RCODE field from header byte 4 by masking with HB4_RCODE (0x0f).
 * No shifting required as RCODE occupies the low-order 4 bits of hb4.
 * 
 * @param x Pointer to struct dns_header
 * @return RCODE value (0=NOERROR, 1=FORMERR, 2=SERVFAIL, 3=NXDOMAIN, etc.)
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dns_header *header = ...;
 * int rcode = RCODE(header);  // Returns 0 for successful query, 3 for NXDOMAIN
 * @endcode
 */
#define RCODE(x)           ((x)->hb4 & HB4_RCODE)

/**
 * @brief Set RCODE (response code) field in DNS header
 * 
 * Sets the 4-bit RCODE field in header byte 4 by clearing the RCODE bits
 * (using ~HB4_RCODE mask) and then OR-ing in the new code value.
 * Preserves all other flag bits in hb4 (RA, Z, AD, CD).
 * 
 * @param x Pointer to struct dns_header to modify
 * @param code RCODE value to set (0=NOERROR, 2=SERVFAIL, 3=NXDOMAIN, etc.)
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dns_header *header = ...;
 * SET_RCODE(header, NXDOMAIN);  // Set response code to 3 (non-existent domain)
 * @endcode
 */
#define SET_RCODE(x, code) (x)->hb4 = ((x)->hb4 & ~HB4_RCODE) | code

/** @} */ /* End of DNSHeaderAccessors group */
  
/**
 * @defgroup DNSByteOrderMacros DNS Byte-Order Conversion Macros
 * @brief Network byte order (big-endian) conversion macros for DNS wire format
 * 
 * DNS protocol uses network byte order (big-endian) for multi-byte fields in the
 * wire format per RFC 1035. These macros handle conversion between network byte
 * order and host byte order, with pointer advancement for parsing and serialization.
 * 
 * These macros are used extensively in rfc1035.c for DNS packet parsing (GETSHORT,
 * GETLONG) and construction (PUTSHORT, PUTLONG).
 * 
 * IMPLEMENTATION NOTES:
 * - Explicit byte manipulation ensures correct behavior regardless of host endianness
 * - Pointer advancement after extraction/insertion simplifies sequential field processing
 * - unsigned char* cast prevents sign-extension issues with signed char platforms
 * 
 * USAGE PATTERN:
 * @code
 * unsigned char *ptr = packet_buffer;
 * u16 value16;
 * u32 value32;
 * GETSHORT(value16, ptr);  // Extracts 16-bit value, advances ptr by 2
 * GETLONG(value32, ptr);   // Extracts 32-bit value, advances ptr by 4
 * PUTSHORT(12345, ptr);    // Writes 16-bit value, advances ptr by 2
 * PUTLONG(67890, ptr);     // Writes 32-bit value, advances ptr by 4
 * @endcode
 * 
 * @{
 */

/**
 * @brief Extract 16-bit value from network byte order buffer and advance pointer
 * 
 * Reads a 16-bit unsigned integer from the network byte order buffer pointed to by
 * cp, converts it to host byte order, stores result in s, and advances cp by 2 bytes.
 * 
 * @param s [out] Destination variable (u16) to receive extracted value
 * @param cp [in,out] Pointer to buffer (advanced by 2 bytes after extraction)
 * 
 * EXAMPLE:
 * @code
 * unsigned char *packet = ...; // DNS packet buffer
 * u16 qdcount;
 * GETSHORT(qdcount, packet);   // Extract question count from DNS header
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 1035 Section 4.1.1 (all multi-byte fields in network byte order)
 * SIDE EFFECTS: Advances cp pointer by 2 bytes
 */
#define GETSHORT(s, cp) do { \
	unsigned char *t_cp = (unsigned char *)(cp); \
	(s) = ((u16)t_cp[0] << 8) \
	    | ((u16)t_cp[1]) \
	    ; \
	(cp) += 2; \
  } while(0)

/**
 * @brief Extract 32-bit value from network byte order buffer and advance pointer
 * 
 * Reads a 32-bit unsigned integer from the network byte order buffer pointed to by
 * cp, converts it to host byte order, stores result in l, and advances cp by 4 bytes.
 * 
 * @param l [out] Destination variable (u32) to receive extracted value
 * @param cp [in,out] Pointer to buffer (advanced by 4 bytes after extraction)
 * 
 * EXAMPLE:
 * @code
 * unsigned char *rdata = ...; // Resource record data
 * u32 ttl;
 * GETLONG(ttl, rdata);         // Extract TTL field (32-bit)
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 1035 Section 4.1.3 (TTL and other 32-bit fields)
 * SIDE EFFECTS: Advances cp pointer by 4 bytes
 */
#define GETLONG(l, cp) do { \
	unsigned char *t_cp = (unsigned char *)(cp); \
	(l) = ((u32)t_cp[0] << 24) \
	    | ((u32)t_cp[1] << 16) \
	    | ((u32)t_cp[2] << 8) \
	    | ((u32)t_cp[3]) \
	    ; \
	(cp) += 4; \
  } while (0)

/**
 * @brief Insert 16-bit value into buffer in network byte order and advance pointer
 * 
 * Converts a 16-bit unsigned integer from host byte order to network byte order,
 * writes it to the buffer pointed to by cp, and advances cp by 2 bytes.
 * 
 * @param s [in] Source value (u16) to insert into buffer
 * @param cp [in,out] Pointer to buffer (advanced by 2 bytes after insertion)
 * 
 * EXAMPLE:
 * @code
 * unsigned char *packet = ...; // DNS packet buffer
 * u16 qdcount = 1;
 * PUTSHORT(qdcount, packet);   // Write question count to DNS header
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 1035 Section 4.1.1 (all multi-byte fields in network byte order)
 * SIDE EFFECTS: Advances cp pointer by 2 bytes, modifies buffer content
 */
#define PUTSHORT(s, cp) do { \
	u16 t_s = (u16)(s); \
	unsigned char *t_cp = (unsigned char *)(cp); \
	*t_cp++ = t_s >> 8; \
	*t_cp   = t_s; \
	(cp) += 2; \
  } while(0)

/**
 * @brief Write 32-bit value to buffer in network byte order (big-endian)
 * 
 * Macro serializes a 32-bit unsigned integer into a byte buffer in network byte order
 * (most significant byte first), writing 4 bytes and advancing the pointer.
 * 
 * @param l 32-bit value to write
 * @param cp Pointer to buffer position (will be advanced by 4 bytes)
 * 
 * IMPLEMENTATION:
 * - Uses temporary variable to avoid multiple evaluation of l parameter
 * - Writes bytes from most significant (bits 24-31) to least significant (bits 0-7)
 * - Advances cp pointer by 4 bytes after write
 * - do-while(0) idiom ensures safe usage in all contexts
 * 
 * USAGE: Writing DNS TTL values, SOA serial numbers, and other 32-bit fields
 * 
 * Source: /src/dns-protocol.h lines 750-758
 */
#define PUTLONG(l, cp) do { \
	u32 t_l = (u32)(l); \
	unsigned char *t_cp = (unsigned char *)(cp); \
	*t_cp++ = t_l >> 24; \
	*t_cp++ = t_l >> 16; \
	*t_cp++ = t_l >> 8; \
	*t_cp   = t_l; \
	(cp) += 4; \
  } while (0)

/**
 * @brief Validate buffer has sufficient space for upcoming write operation
 * 
 * Macro checks whether a write operation of specified length would remain within
 * packet buffer boundaries. Must be called before all packet write operations to
 * prevent buffer overflows.
 * 
 * @param header Pointer to DNS packet header (start of buffer)
 * @param pp Current write position pointer within buffer
 * @param plen Total packet buffer length in bytes
 * @param len Number of bytes that will be written
 * @return Non-zero (true) if write operation would fit, zero (false) if overflow
 * 
 * VALIDATION LOGIC:
 * - Calculates current offset: (pp - header)
 * - Projects final offset after write: offset + len
 * - Compares against buffer limit: final_offset <= plen
 * - Safe for use with size_t arithmetic (avoids integer overflow)
 * 
 * USAGE: Called before PUTSHORT, PUTLONG, and all DNS record serialization
 * SECURITY: Critical for preventing buffer overflow vulnerabilities
 * 
 * Source: /src/dns-protocol.h lines 779-780
 */
#define CHECK_LEN(header, pp, plen, len) \
    ((size_t)((pp) - (unsigned char *)(header) + (len)) <= (plen))

/**
 * @brief Conditionally advance write pointer after validating buffer space
 * 
 * Macro combines length validation (CHECK_LEN) with pointer advancement. Returns
 * success/failure indicator while atomically advancing pointer only if space available.
 * 
 * @param header Pointer to DNS packet header (start of buffer)
 * @param pp Current write position pointer (advanced on success)
 * @param plen Total packet buffer length in bytes
 * @param len Number of bytes to advance pointer
 * @return 1 if space available and pointer advanced, 0 if insufficient space
 * 
 * OPERATION SEQUENCE:
 * 1. Call CHECK_LEN to validate space available
 * 2. If validation fails: return 0 (no pointer modification)
 * 3. If validation succeeds: advance pp by len bytes, return 1
 * 
 * ATOMICITY: Pointer advancement and success indication are atomic
 * USAGE: Common pattern for DNS record construction - write data then ADD_RDLEN
 * ERROR HANDLING: Zero return signals caller to abort packet construction
 * 
 * EXAMPLE USAGE:
 * @code
 * if (!ADD_RDLEN(header, p, plen, 4))
 *   return 0;  // Packet construction failed
 * @endcode
 * 
 * Source: /src/dns-protocol.h lines 782-783
 */
#define ADD_RDLEN(header, pp, plen, len) \
  (!CHECK_LEN(header, pp, plen, len) ? 0 : (((pp) += (len)), 1))

/**
 * @brief Escape character for DNS name presentation format encoding
 * 
 * Character used as escape prefix in dnsmasq's internal presentation format for
 * DNS domain names. This encoding allows representation of any byte value within
 * domain name labels while maintaining C string compatibility.
 * 
 * ENCODING SCHEME:
 * - Non-printable or special characters are encoded as two-byte sequence
 * - Format: <NAME_ESCAPE> <original_char + 1>
 * - Adding 1 to original character ensures null byte (0x00) encodes as 0x01
 * - Prevents embedded nulls in C strings while preserving all byte values
 * 
 * CHARACTER CONSTRAINTS:
 * - Cannot be '.' (0x2E) - conflicts with label separator in DNS names
 * - Cannot be null (0x00) - would terminate C strings prematurely
 * - Must be non-printable (!isprint()) - distinguishes escape from normal characters
 * - Value 1 (0x01, SOH control character) meets all requirements
 * 
 * EXAMPLE ENCODING:
 * - Null byte (0x00): Encoded as [NAME_ESCAPE, 0x01]
 * - Tab (0x09): Encoded as [NAME_ESCAPE, 0x0A]
 * - DEL (0x7F): Encoded as [NAME_ESCAPE, 0x80]
 * 
 * USAGE CONTEXT:
 * - Internal name storage and manipulation in cache.c
 * - Domain name canonicalization in domain.c
 * - Log output formatting when displaying domain names
 * - Wire format parsing in rfc1035.c during name compression/decompression
 * 
 * @see extract_name() in /src/rfc1035.c - Wire format to presentation conversion
 * @see cache_insert() in /src/cache.c - Name storage with escaped encoding
 * 
 * Source: /src/dns-protocol.h line 844
 */
#define NAME_ESCAPE 1

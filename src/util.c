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

/* The SURF random number generator was taken from djbdns-1.05, by 
   Daniel J Bernstein, which is public domain. */

/**
 * @file util.c
 * @brief Utility functions library providing core infrastructure services
 * 
 * DETAILED PURPOSE:
 * This module provides essential utility functions used throughout dnsmasq including:
 * cryptographic-quality random number generation (SURF algorithm), safe memory allocation
 * wrappers with error handling, string manipulation and canonicalization, DNS name validation
 * and comparison per RFC 1035/1123, interrupted I/O handling, socket address utilities,
 * network address comparison and manipulation, time/date formatting, hostname pattern matching,
 * file descriptor management, and Linux kernel version detection.
 * 
 * KEY RESPONSIBILITIES:
 * - Random number generation using SURF algorithm (rand_init, rand16, rand32, rand64)
 * - Memory allocation with error handling (safe_malloc, whine_malloc, whine_realloc, expand_buf)
 * - DNS name validation and canonicalization (check_name, legal_hostname, canonicalise)
 * - Hostname comparison and ordering (hostname_isequal, hostname_order, hostname_issubdomain)
 * - String utilities (safe_strncpy, parse_hex, print_mac, wildcard_match)
 * - Socket address operations (sockaddr_isequal, sa_len, prettyprint_addr)
 * - Network utilities (netmask_length, is_same_net, is_same_net6)
 * - Time functions (dnsmasq_time, dnsmasq_milliseconds, prettyprint_time)
 * - I/O utilities (read_write, retry_send, safe_pipe, close_fds)
 * - IPv6 address manipulation (addr6part, setaddr6part)
 * - Platform-specific utilities (kernel_version for Linux)
 * 
 * DEPENDENCIES:
 * Includes: dnsmasq.h (core types and definitions), sys/times.h (broken RTC support),
 *           idn2.h or idna.h (internationalized domain names), sys/utsname.h (Linux),
 *           libgen.h (BSD)
 * Called by: Nearly all dnsmasq modules for utility services
 * Calls: Standard C library functions, POSIX system calls
 * 
 * DATA STRUCTURES:
 * - seed[32]: SURF RNG seed array (line 43)
 * - in[12]: SURF RNG input state (line 44)
 * - out[8]: SURF RNG output buffer (line 45)
 * - outleft: SURF RNG remaining output count (line 46)
 * 
 * COMPILE-TIME OPTIONS:
 * - HAVE_BROKEN_RTC: Use clock_gettime instead of system RTC
 * - HAVE_LIBIDN2: Support IDN 2008 internationalized domain names
 * - HAVE_IDN: Support IDN 2003 internationalized domain names  
 * - HAVE_LINUX_NETWORK: Linux-specific networking (kernel version detection)
 * - HAVE_BSD_NETWORK: BSD-specific networking
 * 
 * THREADING/CONCURRENCY:
 * Single-threaded event-driven architecture. Functions maintain internal state
 * (SURF RNG) that must not be accessed concurrently. Not thread-safe.
 * 
 * @copyright Copyright (c) 2000-2025 Simon Kelley
 * @license GPL-2.0-or-later
 */

#include "dnsmasq.h"

#ifdef HAVE_BROKEN_RTC
#include <sys/times.h>
#endif

#if defined(HAVE_LIBIDN2)
#include <idn2.h>
#elif defined(HAVE_IDN)
#include <idna.h>
#endif

#ifdef HAVE_LINUX_NETWORK
#include <sys/utsname.h>
#endif

#ifdef HAVE_BSD_NETWORK
#include <libgen.h>
#endif

/* SURF random number generator */

static u32 seed[32];
static u32 in[12];
static u32 out[8];
static int outleft = 0;

/**
 * @brief Initialize the SURF random number generator from system entropy source
 * 
 * @detailed Reads initial seed values and input state from RANDFILE (typically /dev/urandom)
 *           to initialize the SURF cryptographic-quality random number generator. The SURF
 *           algorithm provides high-quality random numbers suitable for DNS query ID generation
 *           and source port randomization. This function must be called once during daemon
 *           startup before any calls to rand16(), rand32(), or rand64().
 * 
 * @note RANDFILE location is platform-specific, defined in config.h (typically /dev/urandom)
 * @warning Fatal error if entropy source unavailable - daemon will not start
 * 
 * @see rand16(), rand32(), rand64()
 * 
 * EXAMPLE USAGE:
 * @code
 * // During daemon initialization
 * rand_init();
 * // Now safe to generate random values
 * unsigned short query_id = rand16();
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (internal utility)
 * SIDE EFFECTS: Opens and reads from RANDFILE, initializes global seed/in arrays, calls die() on failure
 * THREAD SAFETY: Not thread-safe - single-threaded architecture, call once during startup
 */
void rand_init(void)
{
  int fd = open(RANDFILE, O_RDONLY);
  
  if (fd == -1 ||
      !read_write(fd, (unsigned char *)&seed, sizeof(seed), RW_READ) ||
      !read_write(fd, (unsigned char *)&in, sizeof(in), RW_READ))
    die(_("failed to seed the random number generator: %s"), NULL, EC_MISC);
  
  close(fd);
}

#define ROTATE(x,b) (((x) << (b)) | ((x) >> (32 - (b))))
#define MUSH(i,b) x = t[i] += (((x ^ seed[i]) + sum) ^ ROTATE(x,b));

/**
 * @brief Core SURF algorithm implementation generating 8 random 32-bit values
 * 
 * @detailed Executes the SURF (Speedy Unpredictable Random Function) algorithm developed by
 *           Daniel J. Bernstein. Performs cryptographic mixing of seed, input state, and
 *           accumulated sum through 32 rounds of MUSH operations with rotation. Generates
 *           8 output values stored in the global out[] array. This is an internal function
 *           called automatically by rand16(), rand32(), and rand64() when output buffer depleted.
 * 
 * @note Algorithm from djbdns-1.05 (public domain)
 * @warning Internal function - do not call directly, use rand16/rand32/rand64 instead
 * 
 * @see rand16(), rand32(), rand64(), rand_init()
 * 
 * RFC COMPLIANCE: N/A (cryptographic primitive)
 * SIDE EFFECTS: Updates global out[] array with 8 new random values
 * THREAD SAFETY: Not thread-safe - modifies global state
 */
static void surf(void)
{
  u32 t[12]; u32 x; u32 sum = 0;
  int r; int i; int loop;

  for (i = 0;i < 12;++i) t[i] = in[i] ^ seed[12 + i];
  for (i = 0;i < 8;++i) out[i] = seed[24 + i];
  x = t[11];
  for (loop = 0;loop < 2;++loop) {
    for (r = 0;r < 16;++r) {
      sum += 0x9e3779b9;
      MUSH(0,5) MUSH(1,7) MUSH(2,9) MUSH(3,13)
      MUSH(4,5) MUSH(5,7) MUSH(6,9) MUSH(7,13)
      MUSH(8,5) MUSH(9,7) MUSH(10,9) MUSH(11,13)
    }
    for (i = 0;i < 8;++i) out[i] ^= t[i + 4];
  }
}

/**
 * @brief Generate cryptographically-strong 16-bit random number
 * 
 * @detailed Returns a random unsigned 16-bit value using the SURF algorithm. Maintains an
 *           internal output buffer that is refilled by calling surf() when depleted. Used
 *           primarily for DNS query ID generation and source port randomization to prevent
 *           DNS cache poisoning attacks. The SURF algorithm provides cryptographic-quality
 *           randomness suitable for security-critical applications.
 * 
 * @return Random unsigned 16-bit value (0-65535)
 * 
 * @note Automatically increments SURF input state and regenerates output when buffer empty
 * @warning Must call rand_init() once before first use
 * 
 * @see rand32(), rand64(), rand_init()
 * 
 * EXAMPLE USAGE:
 * @code
 * // Generate random DNS query ID
 * unsigned short query_id = rand16();
 * // Generate random source port for DNS query
 * unsigned short src_port = rand16();
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 1035 Section 4.1.1 recommends random query IDs
 * SIDE EFFECTS: Updates global outleft counter, may trigger surf() regeneration
 * THREAD SAFETY: Not thread-safe - single-threaded architecture
 */
unsigned short rand16(void)
{
  if (!outleft) 
    {
      if (!++in[0]) if (!++in[1]) if (!++in[2]) ++in[3];
      surf();
      outleft = 8;
    }
  
  return (unsigned short) out[--outleft];
}

/**
 * @brief Generate cryptographically-strong 32-bit random number
 * 
 * @detailed Returns a random unsigned 32-bit value using the SURF algorithm. Similar to rand16()
 *           but provides full 32-bit randomness. Used for generating random timestamps, lease
 *           identifiers, and other security-critical values requiring larger random space.
 *           Maintains internal output buffer refilled by calling surf() when depleted.
 * 
 * @return Random unsigned 32-bit value (0-4294967295)
 * 
 * @note Automatically increments SURF input state and regenerates output when buffer empty
 * @warning Must call rand_init() once before first use
 * 
 * @see rand16(), rand64(), rand_init()
 * 
 * EXAMPLE USAGE:
 * @code
 * // Generate random 32-bit value for cache key
 * u32 cache_key = rand32();
 * // Generate random delay value
 * u32 delay_ms = rand32() % 1000;
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (internal utility)
 * SIDE EFFECTS: Updates global outleft counter, may trigger surf() regeneration
 * THREAD SAFETY: Not thread-safe - single-threaded architecture
 */
u32 rand32(void)
{
 if (!outleft) 
    {
      if (!++in[0]) if (!++in[1]) if (!++in[2]) ++in[3];
      surf();
      outleft = 8;
    }
  
  return out[--outleft]; 
}

/**
 * @brief Generate cryptographically-strong 64-bit random number
 * 
 * @detailed Returns a random unsigned 64-bit value using the SURF algorithm. Combines two
 *           32-bit outputs from the SURF generator to produce a 64-bit result. Used for
 *           generating unique identifiers, large random intervals, and cryptographic operations
 *           requiring maximum entropy. Maintains separate static outleft counter to track
 *           remaining 32-bit pairs in output buffer.
 * 
 * @return Random unsigned 64-bit value (0-18446744073709551615)
 * 
 * @note Uses separate static outleft counter (shadows global outleft)
 * @warning Must call rand_init() once before first use
 * 
 * @see rand16(), rand32(), rand_init()
 * 
 * EXAMPLE USAGE:
 * @code
 * // Generate random 64-bit transaction identifier
 * u64 transaction_id = rand64();
 * // Generate random lease identifier
 * u64 lease_id = rand64();
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (internal utility)
 * SIDE EFFECTS: Updates function-local static outleft counter, may trigger surf() regeneration
 * THREAD SAFETY: Not thread-safe - uses static local state, single-threaded architecture
 */
u64 rand64(void)
{
  static int outleft = 0;

  if (outleft < 2)
    {
      if (!++in[0]) if (!++in[1]) if (!++in[2]) ++in[3];
      surf();
      outleft = 8;
    }
  
  outleft -= 2;

  return (u64)out[outleft+1] + (((u64)out[outleft]) << 32);
}

/**
 * @brief Check if a DNS resource record type exists in a linked list
 * 
 * @detailed Traverses a linked list of DNS resource record (RR) types to determine
 *           if a specific RR type is present. Used for filtering and validating
 *           DNS responses against allowed or expected record types.
 * 
 * @param list Pointer to head of rrlist linked list (may be NULL for empty list)
 * @param rr DNS resource record type to search for (e.g., A=1, AAAA=28, etc.)
 * 
 * @return 1 if RR type found in list, 0 if not found or list is NULL
 * 
 * @note List entries with rr value of 0 are skipped (wildcard/sentinel entries)
 * @warning No cycle detection - assumes list is properly terminated with NULL
 * 
 * @see struct rrlist in dnsmasq.h for list node structure
 * 
 * EXAMPLE USAGE:
 * @code
 * struct rrlist *allowed = daemon->filter_rr;
 * if (rr_on_list(allowed, T_A)) {
 *   // A records are on the allowed list
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (internal utility for DNS filtering)
 * SIDE EFFECTS: None (read-only list traversal)
 * THREAD SAFETY: Thread-safe for read-only list access, single-threaded architecture
 */
int rr_on_list(struct rrlist *list, unsigned short rr)
{
  while (list)
    {
      if (list->rr != 0 && list->rr == rr)
	return 1;

      list = list->next;
    }

  return 0;
}

/**
 * @brief Validate domain name syntax and determine if IDN processing is required
 * 
 * @detailed Validates domain name string against DNS naming rules (RFC 1035), checking
 *           for proper length constraints, valid character sets, and label boundaries.
 *           Returns a tri-state value indicating invalid name (0), valid ASCII name (1),
 *           or valid name requiring Internationalized Domain Name (IDN) encoding (2).
 *           
 *           Validation includes: total name length ≤255 bytes (MAXDNAME), individual
 *           labels ≤63 bytes (MAXLABEL), no control characters, proper dot-separated
 *           label structure, and non-whitespace content. Trailing dots are silently
 *           removed as part of canonicalization.
 * 
 * @param in Domain name string to validate (NUL-terminated, MODIFIED: trailing dot removed)
 * 
 * @return 0 if name is invalid (empty, too long, contains invalid chars, all whitespace)
 * @retval 1 Name is valid and contains only ASCII printable characters
 * @retval 2 Name is valid but requires IDN processing (contains non-ASCII or uppercase)
 * 
 * @note Trailing dot is removed in-place from input string (side effect)
 * @note Return value 2 only possible when compiled with HAVE_IDN or HAVE_LIBIDN2
 * @note Older libidn2 (< 2.0.3) has special handling for underscores with uppercase
 * @warning Modifies input string by removing trailing dot - not thread-safe for same string
 * 
 * @see canonicalise() for full name canonicalization including IDN encoding
 * @see legal_hostname() for stricter hostname validation (no underscores)
 * 
 * EXAMPLE USAGE:
 * @code
 * char name[] = "example.com.";
 * int result = check_name(name);
 * if (result == 0) {
 *   // Invalid name
 * } else if (result == 2) {
 *   // Needs IDN encoding (non-ASCII or uppercase)
 * } else {
 *   // Valid ASCII name (name now has trailing dot removed)
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 1035 Section 2.3.1 (domain name syntax)
 *                 RFC 1035 Section 2.3.4 (label length ≤63, name length ≤255)
 * SIDE EFFECTS: Modifies input string by removing trailing dot
 * THREAD SAFETY: Not safe for concurrent access to same input string
 */
static int check_name(char *in)
{
  /* remove trailing . 
     also fail empty string and label > 63 chars */
  size_t dotgap = 0, l = strlen(in);
  char c;
  int nowhite = 0;
  int idn_encode = 0;
  int hasuscore = 0;
  int hasucase = 0;
  
  if (l == 0 || l > MAXDNAME) return 0;
  
  if (in[l-1] == '.')
    {
      in[l-1] = 0;
      nowhite = 1;
    }

  for (; (c = *in); in++)
    {
      if (c == '.')
        dotgap = 0;
      else if (++dotgap > MAXLABEL)
        return 0;
      else if (isascii((unsigned char)c) && iscntrl((unsigned char)c)) 
        /* iscntrl only gives expected results for ascii */
        return 0;
      else if (!isascii((unsigned char)c))
#if !defined(HAVE_IDN) && !defined(HAVE_LIBIDN2)
        return 0;
#else
        idn_encode = 1;
#endif
      else if (c != ' ')
        {
          nowhite = 1;
#if defined(HAVE_LIBIDN2) && (!defined(IDN2_VERSION_NUMBER) || IDN2_VERSION_NUMBER < 0x02000003)
          if (c == '_')
            hasuscore = 1;
#else
          (void)hasuscore;
#endif

#if defined(HAVE_IDN) || defined(HAVE_LIBIDN2)
          if (c >= 'A' && c <= 'Z')
            hasucase = 1;
#else
          (void)hasucase;
#endif
        }
    }

  if (!nowhite)
    return 0;

#if defined(HAVE_LIBIDN2) && (!defined(IDN2_VERSION_NUMBER) || IDN2_VERSION_NUMBER < 0x02000003)
  /* Older libidn2 strips underscores, so don't do IDN processing
     if the name has an underscore unless it also has non-ascii characters. */
  idn_encode = idn_encode || (hasucase && !hasuscore);
#else
  idn_encode = idn_encode || hasucase;
#endif

  return (idn_encode) ? 2 : 1;
}

/* Hostnames have a more limited valid charset than domain names
   so check for legal char a-z A-Z 0-9 - _ 
   Note that this may receive a FQDN, so only check the first label 
   for the tighter criteria. */
/**
 * @brief Validate string as legal hostname per RFC 952/1123 rules
 * 
 * @detailed Performs strict hostname validation beyond basic DNS name syntax, enforcing
 *           RFC 952 and RFC 1123 hostname character restrictions. Valid hostnames contain
 *           only alphanumeric characters (A-Z, a-z, 0-9), hyphens, and underscores, with
 *           the restriction that hyphens and underscores cannot appear as the first
 *           character. The validation is more restrictive than general DNS names to
 *           ensure compatibility with traditional hostname conventions.
 *           
 *           First invokes check_name() for basic DNS syntax validation (length limits,
 *           no control characters, proper label structure), then applies stricter hostname
 *           character set restrictions. Accepts dot-separated hostname labels and treats
 *           first dot as hostname terminator (rest of name ignored).
 * 
 * @param name Hostname string to validate (NUL-terminated, may be modified by check_name)
 * 
 * @return 1 if valid hostname per RFC 952/1123, 0 if invalid
 * @retval 1 All characters valid, or valid up to first dot (hostname label valid)
 * @retval 0 Contains invalid characters, fails basic DNS checks, or starts with hyphen/underscore
 * 
 * @note More restrictive than check_name(): disallows many DNS-legal characters
 * @note Hyphens and underscores prohibited in first character position
 * @note First dot terminates hostname validation (returns success if valid up to dot)
 * @note Input may be modified by check_name() call (trailing dot removal)
 * @warning Not thread-safe due to check_name() modification of input string
 * 
 * @see check_name() for basic DNS name syntax validation
 * @see canonicalise() for full name processing including IDN and case conversion
 * 
 * EXAMPLE USAGE:
 * @code
 * char hostname[] = "web-server_01";
 * if (legal_hostname(hostname)) {
 *   // Valid hostname: alphanumeric with hyphen/underscore
 * }
 * 
 * char invalid[] = "-badname";  // Starts with hyphen
 * if (!legal_hostname(invalid)) {
 *   // Invalid: hyphen in first position
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 952 (DoD Internet Host Table Specification)
 *                 RFC 1123 Section 2.1 (relaxed RFC 952 to allow first char as digit)
 * SIDE EFFECTS: May modify input string via check_name() (trailing dot removal)
 * THREAD SAFETY: Not thread-safe for concurrent access to same input string
 */
int legal_hostname(char *name)
{
  char c;
  int first;

  if (!check_name(name))
    return 0;

  for (first = 1; (c = *name); name++, first = 0)
    /* check for legal char a-z A-Z 0-9 - _ . */
    {
      if ((c >= 'A' && c <= 'Z') ||
	  (c >= 'a' && c <= 'z') ||
	  (c >= '0' && c <= '9'))
	continue;

      if (!first && (c == '-' || c == '_'))
	continue;
      
      /* end of hostname part */
      if (c == '.')
	return 1;
      
      return 0;
    }
  
  return 1;
}
  
/**
 * @brief Canonicalize domain name with validation and optional IDN encoding
 * 
 * @detailed Performs complete domain name canonicalization including validation,
 *           Internationalized Domain Name (IDN) encoding when required, and memory
 *           allocation for the canonical form. The function validates the input name
 *           using check_name(), applies IDN Punycode encoding for non-ASCII names
 *           when compiled with libidn2 or libidn support, and returns a newly
 *           allocated string containing the canonical representation.
 *           
 *           For ASCII-only names, returns a copy of the validated input. For names
 *           requiring IDN encoding (containing non-ASCII or uppercase requiring
 *           conversion), performs IDNA2008 (libidn2) or IDNA2003 (libidn) encoding
 *           to produce ASCII-Compatible Encoding (ACE) with "xn--" prefix.
 *           
 *           Memory allocation failures are reported through optional nomem parameter,
 *           distinguishing validation failures from resource exhaustion.
 * 
 * @param in Input domain name string to canonicalize (NUL-terminated, may be modified
 *           by check_name trailing dot removal)
 * @param nomem Optional pointer to int for memory allocation failure notification
 *              (set to 1 on malloc failure, 0 on entry if not NULL, NULL to ignore)
 * 
 * @return Pointer to newly allocated canonical name string (caller must free with free())
 * @retval NULL Name validation failed (invalid syntax per RFC 1035)
 * @retval NULL IDN encoding failed (unsupported characters or encoding error)
 * @retval NULL Memory allocation failed (nomem set to 1 if provided)
 * @retval non-NULL Allocated string with canonical name (ASCII-only or ACE-encoded)
 * 
 * @note CALLER MUST free() returned string - memory ownership transferred to caller
 * @note Return NULL has multiple causes: check nomem to distinguish allocation failure
 * @note IDN encoding only performed when HAVE_LIBIDN2 or HAVE_IDN compiled
 * @note Uses IDNA2008 nontransitional processing with libidn2 (preferred)
 * @note Uses IDNA2003 with legacy libidn for backward compatibility
 * @warning Input string may be modified by check_name() (trailing dot removed)
 * @warning Not thread-safe for concurrent access to same input string
 * 
 * @see check_name() for validation logic determining if IDN encoding needed
 * @see whine_malloc() for memory allocation with logging
 * 
 * EXAMPLE USAGE:
 * @code
 * int nomem;
 * char name[] = "example.com.";
 * char *canonical = canonicalise(name, &nomem);
 * if (canonical == NULL) {
 *   if (nomem) {
 *     // Memory allocation failure
 *   } else {
 *     // Invalid name or IDN encoding failure
 *   }
 * } else {
 *   // Use canonical (now "example.com" with trailing dot removed)
 *   process_name(canonical);
 *   free(canonical);  // Caller must free
 * }
 * 
 * // IDN example with non-ASCII
 * char idn_name[] = "münchen.de";
 * canonical = canonicalise(idn_name, NULL);
 * // Returns "xn--mnchen-3ya.de" (Punycode encoded)
 * if (canonical) {
 *   send_dns_query(canonical);
 *   free(canonical);
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 1035 (DNS name syntax validation via check_name)
 *                 RFC 3490 (IDNA2003 with libidn, legacy)
 *                 RFC 5890-5894 (IDNA2008 with libidn2, preferred)
 * SIDE EFFECTS: Allocates memory (caller must free); modifies input via check_name()
 * THREAD SAFETY: Not thread-safe for concurrent access to same input string
 */
char *canonicalise(char *in, int *nomem)
{
  char *ret = NULL;
  int rc;
  
  if (nomem)
    *nomem = 0;
  
  if (!(rc = check_name(in)))
    return NULL;
  
#if defined(HAVE_IDN) || defined(HAVE_LIBIDN2)
  if (rc == 2)
    {
#  ifdef HAVE_LIBIDN2
      rc = idn2_to_ascii_lz(in, &ret, IDN2_NONTRANSITIONAL);
#  else
      rc = idna_to_ascii_lz(in, &ret, 0);
#  endif
      if (rc != IDNA_SUCCESS)
	{
	  if (ret)
	    free(ret);
	  
	  if (nomem && (rc == IDNA_MALLOC_ERROR || rc == IDNA_DLOPEN_ERROR))
	    {
	      my_syslog(LOG_ERR, _("failed to allocate memory"));
	      *nomem = 1;
	    }
	  
	  return NULL;
	}
      
      return ret;
    }
#else
  (void)rc;
#endif
  
  if ((ret = whine_malloc(strlen(in)+1)))
    strcpy(ret, in);
  else if (nomem)
    *nomem = 1;

  return ret;
}

/**
 * @brief Encode domain name into RFC 1035 wire format with length-prefixed labels
 * 
 * @detailed Converts a dot-separated domain name string (e.g., "example.com") into DNS wire
 *           format where each label is prefixed by its length byte. For example, "example.com"
 *           becomes: [7]example[3]com (where [7] and [3] are single-byte length values).
 *           Supports NAME_ESCAPE character for encoding special characters in labels. Provides
 *           buffer overflow protection through optional limit parameter. Used throughout DNS
 *           packet construction to encode domain names per RFC 1035 Section 3.1.
 * 
 * @param p Pointer to buffer where encoded name will be written (must have sufficient space)
 * @param sval Domain name string to encode (dot-separated labels, NULL for empty name)
 * @param limit Optional buffer limit pointer for overflow protection (NULL disables checking)
 * 
 * @return Pointer to next byte after encoded name, or NULL on buffer overflow
 * @retval non-NULL Successful encoding (pointer to byte after last encoded character)
 * @retval NULL Buffer overflow detected (would exceed limit), no data written
 * 
 * @note Each label is limited to 63 bytes per RFC 1035 (length fits in 6 bits)
 * @note Function does NOT write terminating zero label (caller must add if needed)
 * @note Dot separators (.) are not encoded, only used as label delimiters
 * @note NAME_ESCAPE character followed by X encodes as byte (X-1)
 * @note If sval is NULL or empty string, returns p unchanged (empty encoding)
 * @note Buffer must have at least strlen(sval)+number_of_labels+1 bytes available
 * @warning Caller must ensure buffer p has sufficient space (no automatic allocation)
 * @warning Does NOT validate label length ≤63 (caller responsibility)
 * @warning Does NOT write root label terminator (0x00) - caller must add
 * @warning limit checking only works if limit is provided (NULL disables protection)
 * 
 * @see extract_name() in rfc1035.c for decoding RFC 1035 names
 * @see add_resource_record() in rfc1035.c for usage in DNS packet construction
 * 
 * EXAMPLE USAGE:
 * @code
 * unsigned char buffer[256];
 * char *domain = "example.com";
 * unsigned char *p = do_rfc1035_name(buffer, domain, buffer + sizeof(buffer));
 * if (!p) {
 *   // Buffer overflow - domain too long
 *   return ERROR;
 * }
 * *p++ = 0; // Add terminating zero label for complete RFC 1035 name
 * // buffer now contains: [7]example[3]com[0]
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 1035 Section 3.1 (domain name encoding with length-prefixed labels)
 * SIDE EFFECTS: Writes encoded name to buffer at p; advances sval pointer internally
 * THREAD SAFETY: Thread-safe (no shared state) in single-threaded architecture
 */
unsigned char *do_rfc1035_name(unsigned char *p, char *sval, char *limit)
{
  int j;
  
  while (sval && *sval)
    {
      unsigned char *cp = p++;

      if (limit && p > (unsigned char*)limit)
        return NULL;

      for (j = 0; *sval && (*sval != '.'); sval++, j++)
	{
          if (limit && p + 1 > (unsigned char*)limit)
            return NULL;

	  if (*sval == NAME_ESCAPE)
	    *p++ = (*(++sval))-1;
	  else
	    *p++ = *sval;
	}
      
      *cp  = j;
      if (*sval)
	sval++;
    }
  
  return p;
}

/**
 * @brief Allocate zero-initialized memory during daemon startup, terminating on failure
 * 
 * @detailed Wrapper around calloc() that allocates and zero-initializes memory. Unlike
 *           whine_malloc(), this function terminates the entire daemon process if memory
 *           allocation fails, making it suitable only for early startup initialization
 *           where graceful degradation is not possible. The allocated memory is guaranteed
 *           to be zero-filled.
 * 
 * @param size Number of bytes to allocate
 * 
 * @return Pointer to allocated and zero-initialized memory (never returns NULL)
 * 
 * @note Never returns NULL - calls die() on allocation failure
 * @warning Only use during daemon startup/initialization, not during normal operation
 * @warning Terminates entire process on allocation failure - use whine_malloc() for runtime
 * 
 * @see whine_malloc() for non-fatal allocation during runtime operations
 * @see die() in dnsmasq.c for process termination handler
 * 
 * EXAMPLE USAGE:
 * @code
 * // During daemon initialization
 * struct daemon *daemon = safe_malloc(sizeof(struct daemon));
 * daemon->servers = safe_malloc(sizeof(struct server));
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (internal memory management)
 * SIDE EFFECTS: Terminates process via die() if allocation fails
 * THREAD SAFETY: Thread-safe (calloc is thread-safe), single-threaded architecture
 */
void *safe_malloc(size_t size)
{
  void *ret = calloc(1, size);
  
  if (!ret)
    die(_("could not get memory"), NULL, EC_NOMEM);
      
  return ret;
}

/**
 * @brief Safely copy string with guaranteed NUL termination
 * 
 * @detailed Copy up to size-1 bytes from source to destination, always NUL-terminating
 *           the result. Unlike standard strncpy(), this function guarantees NUL termination
 *           and does not pad the destination with zeros. Pre-terminates the buffer before
 *           copying to ensure safety even if strncpy is interrupted. Can be replaced by
 *           strlcpy() on platforms where available (BSD, some modern systems).
 * 
 * @param dest Destination buffer (must be at least size bytes, must not be NULL)
 * @param src Source string (NUL-terminated, must not be NULL)
 * @param size Total size of destination buffer (if 0, no operation performed)
 * 
 * @return void
 * 
 * @note Guarantees NUL termination unlike standard strncpy()
 * @note Does not pad destination with zeros (more efficient than strncpy)
 * @note Pre-terminates buffer at position size-1 before copying for safety
 * @note If src is longer than size-1, result is truncated but still NUL-terminated
 * @note If size is 0, no operation is performed (safe degenerate case)
 * @warning Caller must ensure dest buffer is at least size bytes
 * @warning dest and src must not overlap (undefined behavior)
 * @warning dest and src must not be NULL when size > 0
 * 
 * @see strncpy(3) for standard library comparison
 * @see strlcpy(3) for BSD equivalent
 * 
 * EXAMPLE USAGE:
 * @code
 * char hostname[MAXDNAME];
 * safe_strncpy(hostname, dhcp_client_name, MAXDNAME);
 * // hostname is guaranteed NUL-terminated regardless of dhcp_client_name length
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (internal string utility)
 * SIDE EFFECTS: Modifies destination buffer
 * THREAD SAFETY: Thread-safe for non-overlapping buffers in single-threaded architecture
 */
void safe_strncpy(char *dest, const char *src, size_t size)
{
  if (size != 0)
    {
      dest[size-1] = '\0';
      strncpy(dest, src, size-1);
    }
}

/**
 * @brief Create pipe with optional non-blocking read end and FD_CLOEXEC flags
 * 
 * @detailed Creates a Unix pipe with file descriptors configured for safe use in
 *           daemon context. Sets FD_CLOEXEC on both ends to prevent descriptor leakage
 *           to child processes. Optionally sets non-blocking mode on read end for
 *           asynchronous I/O patterns. Terminates process on failure (cannot recover
 *           from pipe creation failure).
 * 
 * @param fd Array to receive file descriptors: fd[0] = read end, fd[1] = write end (must not be NULL)
 * @param read_noblock If non-zero, sets O_NONBLOCK on read end; if zero, read end remains blocking
 * 
 * @return void (never returns on failure - calls die())
 * 
 * @note Always sets FD_CLOEXEC on both pipe ends via fix_fd()
 * @note Write end is always configured with FD_CLOEXEC
 * @note Read end configuration depends on read_noblock parameter
 * @warning Never returns on failure - calls die() which terminates process
 * @warning Caller must ensure fd array has space for 2 integers
 * @warning fd must not be NULL
 * 
 * @see pipe(2) for underlying system call
 * @see fix_fd() in util.c for file descriptor flags configuration
 * @see die() in dnsmasq.c for fatal error handling
 * 
 * EXAMPLE USAGE:
 * @code
 * int pipefd[2];
 * safe_pipe(pipefd, 1); // Create pipe with non-blocking read end
 * // pipefd[0] = read end (non-blocking, FD_CLOEXEC)
 * // pipefd[1] = write end (blocking, FD_CLOEXEC)
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (internal IPC utility)
 * SIDE EFFECTS: Allocates kernel file descriptors; terminates process on failure
 * THREAD SAFETY: Thread-safe system call in single-threaded architecture
 */
void safe_pipe(int *fd, int read_noblock)
{
  if (pipe(fd) == -1 || 
      !fix_fd(fd[1]) ||
      (read_noblock && !fix_fd(fd[0])))
    die(_("cannot create pipe: %s"), NULL, EC_MISC);
}

/**
 * @brief Allocate zero-initialized memory with automatic error logging on failure
 * 
 * @detailed Wrapper around calloc() that logs allocation failures to syslog but allows
 *           caller to handle failure condition. Unlike safe_malloc() which terminates
 *           on failure, this function returns NULL and logs the error, enabling caller
 *           to implement fallback strategies or graceful degradation. Memory is zeroed
 *           before return. Used for non-critical allocations where failure can be tolerated.
 * 
 * @param size Number of bytes to allocate (if 0, behavior is implementation-defined)
 * 
 * @return Pointer to zero-initialized memory block, or NULL on allocation failure
 * @retval non-NULL Successful allocation (memory zeroed)
 * @retval NULL Allocation failed (error logged to syslog at LOG_ERR level)
 * 
 * @note Does NOT terminate process on failure (contrast with safe_malloc)
 * @note Logs allocation failure with requested size to syslog
 * @note Caller must check return value and handle NULL case
 * @note Memory returned is ZERO-INITIALIZED (all bytes set to 0)
 * @note Uses calloc(1, size) internally for zero-initialization
 * @note Caller must free returned memory with free() when done
 * @warning Caller MUST check for NULL return value
 * @warning size=0 behavior is platform-dependent (may return NULL or valid pointer)
 * 
 * @see calloc(3) for underlying allocation function
 * @see safe_malloc() in util.c for fatal-on-failure variant
 * @see whine_realloc() in util.c for reallocation with logging
 * @see my_syslog() in log.c for syslog interface
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_context *optional_ctx = whine_malloc(sizeof(struct dhcp_context));
 * if (!optional_ctx) {
 *   // Handle allocation failure gracefully
 *   use_existing_context();
 * } else {
 *   // Use zero-initialized structure (all fields are 0/NULL)
 *   configure_context(optional_ctx);
 *   free(optional_ctx);
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (internal memory management utility)
 * SIDE EFFECTS: Allocates heap memory; logs to syslog on failure
 * THREAD SAFETY: Thread-safe calloc in single-threaded architecture
 */
void *whine_malloc(size_t size)
{
  void *ret = calloc(1, size);

  if (!ret)
    my_syslog(LOG_ERR, _("failed to allocate %d bytes"), (int) size);
  
  return ret;
}

/**
 * @brief Reallocate memory with automatic error logging on failure
 * 
 * @detailed Wrapper around realloc() that logs reallocation failures to syslog but allows
 *           caller to handle failure condition. Unlike safe_malloc() which terminates on
 *           failure, this function returns NULL and logs the error. When realloc() fails,
 *           the original memory block (ptr) remains valid and unchanged. Used for non-critical
 *           reallocations where growth failure can be tolerated (e.g., optional buffer expansion).
 * 
 * @param ptr Pointer to existing memory block to resize (if NULL, equivalent to malloc(size))
 * @param size New size in bytes (if 0, behavior is implementation-defined, typically equivalent to free)
 * 
 * @return Pointer to resized memory block, or NULL on allocation failure
 * @retval non-NULL Successful reallocation (contents preserved up to minimum of old/new sizes)
 * @retval NULL Reallocation failed (error logged to syslog, original ptr still valid)
 * 
 * @note Does NOT terminate process on failure (contrast with safe_malloc)
 * @note On failure, original memory block ptr remains valid and unchanged
 * @note Logs reallocation failure with requested size to syslog
 * @note Caller must check return value and handle NULL case
 * @note If ptr is NULL, behaves like malloc(size)
 * @note If size is 0, behavior is platform-dependent (may free and return NULL)
 * @note Returned pointer may differ from input ptr (data copied to new location if moved)
 * @note Caller must update all pointers when realloc returns different address
 * @warning Caller MUST check for NULL return value
 * @warning On failure, do NOT free original ptr (it remains valid)
 * @warning If successful and ptr changes, old ptr is invalid (automatically freed by realloc)
 * @warning size=0 behavior is platform-dependent
 * 
 * @see realloc(3) for underlying reallocation function
 * @see whine_malloc() in util.c for initial allocation with logging
 * @see safe_malloc() in util.c for fatal-on-failure variant
 * @see my_syslog() in log.c for syslog interface
 * 
 * EXAMPLE USAGE:
 * @code
 * char *buffer = whine_malloc(100);
 * char *new_buffer = whine_realloc(buffer, 200);
 * if (!new_buffer) {
 *   // Reallocation failed; original buffer still valid at original size
 *   use_original_buffer(buffer, 100);
 *   free(buffer);
 * } else {
 *   // Success: use new_buffer (buffer is now invalid, automatically freed)
 *   buffer = new_buffer;
 *   use_expanded_buffer(buffer, 200);
 *   free(buffer);
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (internal memory management utility)
 * SIDE EFFECTS: May reallocate heap memory; logs to syslog on failure
 * THREAD SAFETY: Thread-safe realloc in single-threaded architecture
 */
void *whine_realloc(void *ptr, size_t size)
{
  void *ret = realloc(ptr, size);

  if (!ret)
    my_syslog(LOG_ERR, _("failed to reallocate %d bytes"), (int) size);

  return ret;
}

/**
 * @brief Compare two socket addresses for complete equality
 * 
 * @detailed Compares two socket address structures for complete equality, checking address family,
 *           IP address, port number, and (for IPv6) scope ID. Used throughout network code for
 *           socket matching, duplicate detection, and address verification. Handles both IPv4
 *           and IPv6 addresses through union mysockaddr abstraction. Returns true only if all
 *           components match exactly; addresses with different families are never equal.
 * 
 * @param s1 First socket address to compare (must not be NULL)
 * @param s2 Second socket address to compare (must not be NULL)
 * 
 * @return 1 if addresses are completely equal, 0 otherwise
 * @retval 1 Addresses are equal (same family, address, port; IPv6 includes scope ID)
 * @retval 0 Addresses differ in any component, or families differ
 * 
 * @note For IPv4: compares address family, sin_port, and sin_addr.s_addr
 * @note For IPv6: compares address family, sin6_port, sin6_scope_id, and sin6_addr
 * @note IPv6 scope ID must match for link-local addresses to be considered equal
 * @note Addresses of different families (e.g., IPv4 vs IPv6) are never equal
 * @note Does not perform IPv4-mapped IPv6 address normalization
 * @warning Parameters must not be NULL (no NULL checking performed)
 * @warning Does not consider other address families (AF_UNIX, etc.)
 * 
 * @see sockaddr_isnull() in util.c for checking null/unspecified addresses
 * @see IN6_ARE_ADDR_EQUAL() macro for IPv6 address comparison
 * 
 * EXAMPLE USAGE:
 * @code
 * union mysockaddr client_addr, server_addr;
 * // ... initialize addresses from socket operations ...
 * if (sockaddr_isequal(&client_addr, &server_addr)) {
 *   // Same address and port - possible loopback connection
 *   my_syslog(LOG_INFO, "Client connecting from server address");
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (internal address comparison utility)
 * SIDE EFFECTS: None (read-only comparison)
 * THREAD SAFETY: Thread-safe (no shared state) in single-threaded architecture
 */
int sockaddr_isequal(const union mysockaddr *s1, const union mysockaddr *s2)
{
  if (s1->sa.sa_family == s2->sa.sa_family)
    { 
      if (s1->sa.sa_family == AF_INET &&
	  s1->in.sin_port == s2->in.sin_port &&
	  s1->in.sin_addr.s_addr == s2->in.sin_addr.s_addr)
	return 1;
      
      if (s1->sa.sa_family == AF_INET6 &&
	  s1->in6.sin6_port == s2->in6.sin6_port &&
	  s1->in6.sin6_scope_id == s2->in6.sin6_scope_id &&
	  IN6_ARE_ADDR_EQUAL(&s1->in6.sin6_addr, &s2->in6.sin6_addr))
	return 1;
    }
  return 0;
}

/**
 * @brief Check if socket address is the unspecified/null address
 * 
 * @detailed Tests whether a socket address represents the "unspecified" or "null" address,
 *           which is 0.0.0.0 for IPv4 or :: (all zeros) for IPv6. Unspecified addresses
 *           are used to indicate "any address" in bind operations or to represent absence
 *           of a specific address. Used in configuration validation and network binding logic.
 * 
 * @param s Socket address to test (must not be NULL)
 * 
 * @return 1 if address is unspecified/null, 0 otherwise
 * @retval 1 IPv4 address is 0.0.0.0, or IPv6 address is :: (IN6ADDR_ANY_INIT)
 * @retval 0 Address is specified, or address family is neither AF_INET nor AF_INET6
 * 
 * @note For IPv4: checks if sin_addr.s_addr == 0 (0.0.0.0)
 * @note For IPv6: uses IN6_IS_ADDR_UNSPECIFIED() macro (checks for ::)
 * @note Port number is not considered (only tests IP address)
 * @note Other address families (AF_UNIX, etc.) return 0 (not null)
 * @note "Unspecified" address has special meaning: bind to all interfaces
 * @warning Parameter must not be NULL (no NULL checking performed)
 * @warning Does not test for other special addresses (loopback, broadcast, etc.)
 * 
 * @see IN6_IS_ADDR_UNSPECIFIED() macro from <netinet/in.h> for IPv6 check
 * @see sockaddr_isequal() in util.c for address comparison
 * 
 * EXAMPLE USAGE:
 * @code
 * union mysockaddr bind_addr;
 * // ... initialize from configuration ...
 * if (sockaddr_isnull(&bind_addr)) {
 *   // Bind to all available interfaces (0.0.0.0 or ::)
 *   my_syslog(LOG_INFO, "Binding to all interfaces");
 * } else {
 *   // Bind to specific address
 *   my_syslog(LOG_INFO, "Binding to specific address");
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (internal address validation utility)
 * SIDE EFFECTS: None (read-only test)
 * THREAD SAFETY: Thread-safe (no shared state) in single-threaded architecture
 */
int sockaddr_isnull(const union mysockaddr *s)
{
  if (s->sa.sa_family == AF_INET &&
      s->in.sin_addr.s_addr == 0)
    return 1;
  
  if (s->sa.sa_family == AF_INET6 &&
      IN6_IS_ADDR_UNSPECIFIED(&s->in6.sin6_addr))
    return 1;
  
  return 0;
}

/**
 * @brief Get the actual length of a socket address structure
 * 
 * @detailed Returns the appropriate size in bytes for the given socket address structure,
 *           which varies depending on address family (IPv4 vs IPv6) and platform conventions.
 *           On BSD platforms that provide the sa_len field (HAVE_SOCKADDR_SA_LEN), this field
 *           is used directly. On other platforms (Linux), the size is determined based on
 *           address family. This function is essential for socket operations like bind(),
 *           connect(), and sendto() which require the correct sockaddr structure size.
 * 
 * @param addr Socket address whose length to determine (must not be NULL)
 * 
 * @return Size in bytes of the socket address structure
 * @retval sizeof(struct sockaddr_in) For AF_INET (IPv4) addresses on non-BSD platforms
 * @retval sizeof(struct sockaddr_in6) For AF_INET6 (IPv6) addresses on non-BSD platforms
 * @retval addr->sa.sa_len Value from sa_len field on BSD platforms with HAVE_SOCKADDR_SA_LEN
 * 
 * @note BSD platforms (FreeBSD, OpenBSD, NetBSD, macOS) include sa_len field in sockaddr
 * @note Linux and other platforms determine size from address family
 * @note For non-BSD: assumes AF_INET if not AF_INET6 (all other families treated as IPv4 size)
 * @note Compile-time conditional: HAVE_SOCKADDR_SA_LEN detected during build configuration
 * @warning Parameter must not be NULL (no NULL checking performed)
 * @warning On non-BSD platforms, address families other than AF_INET/AF_INET6 return IPv4 size
 * 
 * @see union mysockaddr in dnsmasq.h for the socket address union structure
 * @see sockaddr_isequal() in util.c for address comparison that uses correct structure sizes
 * 
 * EXAMPLE USAGE:
 * @code
 * union mysockaddr dest_addr;
 * // ... initialize dest_addr with IPv4 or IPv6 address ...
 * int addr_len = sa_len(&dest_addr);
 * if (sendto(sock, buffer, len, 0, (struct sockaddr *)&dest_addr, addr_len) < 0)
 *   die(_("sendto failed: %s"), strerror(errno), EC_BADNET);
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (internal utility for socket API compatibility)
 * SIDE EFFECTS: None (read-only access to address structure)
 * THREAD SAFETY: Thread-safe (no shared state) in single-threaded architecture
 */
int sa_len(union mysockaddr *addr)
{
#ifdef HAVE_SOCKADDR_SA_LEN
  return addr->sa.sa_len;
#else
  if (addr->sa.sa_family == AF_INET6)
    return sizeof(addr->in6);
  else
    return sizeof(addr->in); 
#endif
}

/**
 * @brief Perform locale-independent case-insensitive hostname comparison
 * 
 * @detailed Compares two hostname strings lexicographically in a case-insensitive manner
 *           without depending on locale settings. This function implements ASCII-based
 *           case folding (A-Z converted to a-z) and character-by-character comparison,
 *           avoiding standard C library functions like strcasecmp() which may produce
 *           unexpected results when LOCALE environment variables are set. This ensures
 *           consistent DNS hostname comparison across all system locales, which is
 *           critical for DNS name resolution, cache lookups, and configuration matching.
 *           Used for sorting hostname lists, comparing domain names, and maintaining
 *           consistent ordering regardless of system locale configuration.
 * 
 * @param a First hostname string to compare (NULL-terminated, must not be NULL)
 * @param b Second hostname string to compare (NULL-terminated, must not be NULL)
 * 
 * @return Integer indicating lexicographic ordering relationship
 * @retval -1 If hostname a is lexicographically less than hostname b
 * @retval 0 If hostnames a and b are equal (case-insensitive)
 * @retval 1 If hostname a is lexicographically greater than hostname b
 * 
 * @note Deliberately avoids strcasecmp() and similar locale-dependent functions
 * @note Case conversion limited to ASCII A-Z -> a-z (does not handle extended characters)
 * @note Comparison is byte-by-byte after case normalization until null terminator
 * @note All non-alphabetic characters compared by their byte values without conversion
 * @warning Parameters must not be NULL (no NULL checking performed)
 * @warning Only ASCII case conversion performed; extended/Unicode characters not normalized
 * 
 * @see hostname_isequal() in util.c for equality testing using this comparison
 * @see hostname_issubdomain() in util.c for subdomain relationship checking
 * @see do_rfc1035_name() in util.c for RFC 1035 hostname validation
 * 
 * EXAMPLE USAGE:
 * @code
 * const char *host1 = "Example.COM";
 * const char *host2 = "example.com";
 * int result = hostname_order(host1, host2);
 * if (result == 0)
 *   printf("Hostnames are equal (case-insensitive)\n");  // This will print
 * 
 * // Sorting hostnames
 * if (hostname_order("alpha.example.com", "beta.example.com") < 0)
 *   printf("alpha comes before beta\n");
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 1035 Section 3.1 (DNS names are case-insensitive)
 * SIDE EFFECTS: None (read-only string comparison, no state modification)
 * THREAD SAFETY: Thread-safe (no shared state, pure function) in single-threaded architecture
 */
/* don't use strcasecmp and friends here - they may be messed up by LOCALE */
int hostname_order(const char *a, const char *b)
{
  unsigned int c1, c2;
  
  do {
    c1 = (unsigned char) *a++;
    c2 = (unsigned char) *b++;
    
    if (c1 >= 'A' && c1 <= 'Z')
      c1 += 'a' - 'A';
    if (c2 >= 'A' && c2 <= 'Z')
      c2 += 'a' - 'A';
    
    if (c1 < c2)
      return -1;
    else if (c1 > c2)
      return 1;
    
  } while (c1);
  
  return 0;
}

/**
 * @brief Check if two hostnames are equal (case-insensitive comparison)
 * 
 * @detailed Performs case-insensitive hostname equality test by comparing lengths
 *           first for efficiency, then using hostname_order() for full comparison.
 *           This function is more efficient than hostname_order() alone when hostnames
 *           are of different lengths, as the length check short-circuits the comparison.
 * 
 * @param a First hostname string to compare (must not be NULL)
 * @param b Second hostname string to compare (must not be NULL)
 * 
 * @return 1 if hostnames are equal (case-insensitive), 0 otherwise
 * 
 * @note Both parameters must be valid null-terminated strings. NULL pointers will
 *       cause undefined behavior via strlen().
 * @warning Performance depends on strlen() and hostname_order() implementations.
 *          For repeated comparisons of same hostnames, consider caching results.
 * 
 * @see hostname_order() for the underlying comparison algorithm
 * @see hostname_issubdomain() for subdomain relationship testing
 * 
 * EXAMPLE USAGE:
 * @code
 * if (hostname_isequal("Example.COM", "example.com"))
 *   my_syslog(LOG_INFO, "Hostnames are equal");
 * if (hostname_isequal("host1.example.com", "host2.example.com") == 0)
 *   my_syslog(LOG_INFO, "Hostnames differ");
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 1123 Section 2.1 - hostname comparison is case-insensitive
 * SIDE EFFECTS: None (pure function)
 * THREAD SAFETY: Thread-safe (no shared state modification, single-threaded architecture)
 */
int hostname_isequal(const char *a, const char *b)
{
  return strlen(a) == strlen(b) && hostname_order(a, b) == 0;
}

/**
 * @brief Check if hostname b is equal to or a subdomain of hostname a
 * 
 * @detailed Performs case-insensitive reverse comparison to determine if hostname b
 *           is either exactly equal to hostname a, or is a subdomain of a. The algorithm
 *           walks backward from the end of both strings, comparing characters after
 *           case normalization (uppercase converted to lowercase).
 *           
 *           Return values indicate the relationship:
 *           - 2: Hostnames are exactly equal (e.g., "example.com" == "EXAMPLE.COM")
 *           - 1: b is a subdomain of a (e.g., b="host.example.com", a="example.com")
 *           - 0: No subdomain relationship exists
 *           
 *           The function requires that b be at least as long as a, and that a be non-empty.
 *           The subdomain check verifies that after matching all of a, the preceding
 *           character in b is a dot separator.
 * 
 * @param a Parent domain string (must not be empty)
 * @param b Domain string to test (must be at least as long as a)
 * 
 * @return Subdomain relationship indicator
 * @retval 2 Hostnames are exactly equal (b == a)
 * @retval 1 b is a subdomain of a (b is "subdomain.a")
 * @retval 0 No relationship (b shorter than a, a empty, or no match)
 * 
 * @note Case-insensitive comparison: 'A'-'Z' normalized to 'a'-'z'
 * @note Reverse comparison algorithm walks backward from end of strings
 * @note Subdomain detection requires '.' separator before matched portion
 * @warning Returns 0 if a is empty or if b is shorter than a
 * @warning Does NOT validate hostnames - assumes valid input
 * 
 * @see hostname_isequal() for simple equality test without subdomain logic
 * @see hostname_order() for ordering comparison with case normalization
 * 
 * EXAMPLE USAGE:
 * @code
 * // Test for exact equality
 * int result = hostname_issubdomain("example.com", "EXAMPLE.COM");
 * if (result == 2)
 *   my_syslog(LOG_INFO, "Domains are equal");
 * 
 * // Test for subdomain relationship
 * result = hostname_issubdomain("example.com", "host.example.com");
 * if (result == 1)
 *   my_syslog(LOG_INFO, "host.example.com is subdomain of example.com");
 * 
 * // Test for no relationship
 * result = hostname_issubdomain("example.com", "other.com");
 * if (result == 0)
 *   my_syslog(LOG_INFO, "No subdomain relationship");
 * 
 * // Invalid: b shorter than a returns 0
 * result = hostname_issubdomain("example.com", "host");
 * // Returns 0 because "host" is shorter than "example.com"
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 1123 Section 2.1 - hostname comparison case-insensitive
 * SIDE EFFECTS: None (pure function, no state modification)
 * THREAD SAFETY: Thread-safe (no shared state, single-threaded architecture)
 */
/* is b equal to or a subdomain of a return 2 for equal, 1 for subdomain */
int hostname_issubdomain(char *a, char *b)
{
  char *ap, *bp;
  unsigned int c1, c2;
  
  /* move to the end */
  for (ap = a; *ap; ap++); 
  for (bp = b; *bp; bp++);

  /* a shorter than b or a empty. */
  if ((bp - b) < (ap - a) || ap == a)
    return 0;

  do
    {
      c1 = (unsigned char) *(--ap);
      c2 = (unsigned char) *(--bp);
  
       if (c1 >= 'A' && c1 <= 'Z')
	 c1 += 'a' - 'A';
       if (c2 >= 'A' && c2 <= 'Z')
	 c2 += 'a' - 'A';

       if (c1 != c2)
	 return 0;
    } while (ap != a);

  if (bp == b)
    return 2;

  if (*(--bp) == '.')
    return 1;

  return 0;
}
 
  
/**
 * @brief Get current time with broken RTC hardware workaround
 * 
 * @detailed Returns the current time in seconds since epoch. On systems with HAVE_BROKEN_RTC
 *           defined, uses CLOCK_MONOTONIC via clock_gettime() instead of time(NULL) to work
 *           around hardware real-time clock issues. This function is critical for accurate
 *           time-based operations like DHCP lease expiration, DNS cache TTL management, and
 *           log timestamps on embedded systems with unreliable RTC hardware.
 * 
 * @return time_t Current time in seconds since epoch (or monotonic seconds if HAVE_BROKEN_RTC)
 * 
 * @note On HAVE_BROKEN_RTC systems, returns monotonic time which is suitable for intervals
 *       but not absolute timestamps
 * @warning Dies with EC_MISC error code if clock_gettime fails on HAVE_BROKEN_RTC systems
 * 
 * @see dnsmasq_milliseconds() For millisecond-precision timing
 * 
 * EXAMPLE USAGE:
 * @code
 * time_t now = dnsmasq_time();
 * time_t expiry = now + 3600; // 1 hour from now
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (system time management)
 * SIDE EFFECTS: None
 * THREAD SAFETY: Safe (reads system time only)
 */
time_t dnsmasq_time(void)
{
#ifdef HAVE_BROKEN_RTC
  struct timespec ts;

  if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0)
    die(_("cannot read monotonic clock: %s"), NULL, EC_MISC);

  return ts.tv_sec;
#else
  return time(NULL);
#endif
}

/**
 * @brief Get current time in milliseconds
 * 
 * @detailed Returns the current time in milliseconds since epoch using gettimeofday().
 *           Provides millisecond-precision timing for operations that require finer granularity
 *           than second-level time, such as rate limiting, performance measurement, and precise
 *           timeout calculations. Note that this function wraps around every ~49.7 days due to
 *           u32 return type limitation.
 * 
 * @return u32 Current time in milliseconds since epoch (wraps after 2^32 milliseconds)
 * 
 * @note Return value is u32 which wraps approximately every 49.7 days
 * @note Uses gettimeofday() which is not monotonic and can jump backward if system time adjusts
 * 
 * @see dnsmasq_time() For second-precision time with broken RTC workaround
 * 
 * EXAMPLE USAGE:
 * @code
 * u32 start = dnsmasq_milliseconds();
 * // ... perform operation ...
 * u32 elapsed = dnsmasq_milliseconds() - start;
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (system time management)
 * SIDE EFFECTS: None
 * THREAD SAFETY: Safe (reads system time only)
 */
u32 dnsmasq_milliseconds(void)
{
  struct timeval tv;

  gettimeofday(&tv, NULL);

  return (tv.tv_sec) * 1000 + (tv.tv_usec / 1000);
}

/**
 * @brief Calculate prefix length from IPv4 netmask
 * 
 * @detailed Converts an IPv4 netmask (e.g., 255.255.255.0) to CIDR prefix length
 *           (e.g., 24) by counting trailing zero bits in the mask. Algorithm shifts
 *           the mask right until a 1 bit is found, tracking the number of shifts.
 * 
 * @param mask IPv4 netmask in network byte order
 * 
 * @return Prefix length (0-32) representing the number of 1 bits in the mask
 * 
 * @note Algorithm assumes valid netmask (contiguous 1s followed by contiguous 0s)
 * @note For invalid masks, returns length based on trailing zero count
 * 
 * EXAMPLE USAGE:
 * @code
 * struct in_addr mask;
 * inet_pton(AF_INET, "255.255.255.0", &mask);
 * int prefix = netmask_length(mask);  // Returns 24
 * @endcode
 * 
 * SIDE EFFECTS: None (operates on local copy of mask parameter)
 * THREAD SAFETY: Thread-safe (no shared state modification)
 */
int netmask_length(struct in_addr mask)
{
  int zero_count = 0;

  while (0x0 == (mask.s_addr & 0x1) && zero_count < 32) 
    {
      mask.s_addr >>= 1;
      zero_count++;
    }
  
  return 32 - zero_count;
}

/**
 * @brief Determine if two IPv4 addresses are in the same subnet
 * 
 * @detailed Tests whether two IPv4 addresses belong to the same network by
 *           applying the netmask to both addresses and comparing the network
 *           portions. This is the fundamental operation for subnet membership
 *           testing in IPv4 network configuration.
 * 
 * @param a First IPv4 address to compare (network byte order)
 * @param b Second IPv4 address to compare (network byte order)
 * @param mask IPv4 netmask defining the subnet boundary (network byte order)
 * 
 * @return 1 if addresses are in the same subnet, 0 otherwise
 * @retval 1 Both addresses have the same network portion after masking
 * @retval 0 Addresses are in different subnets
 * 
 * @note Algorithm performs bitwise AND of each address with mask and compares results
 * @note All parameters must be in network byte order (big-endian)
 * 
 * EXAMPLE USAGE:
 * @code
 * struct in_addr addr1, addr2, netmask;
 * inet_pton(AF_INET, "192.168.1.10", &addr1);
 * inet_pton(AF_INET, "192.168.1.20", &addr2);
 * inet_pton(AF_INET, "255.255.255.0", &netmask);
 * if (is_same_net(addr1, addr2, netmask)) {
 *   // Addresses are on the same subnet
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: Network address masking per RFC 1122 (Internet Host Requirements)
 * SIDE EFFECTS: None (read-only parameter access)
 * THREAD SAFETY: Thread-safe (no shared state)
 */
int is_same_net(struct in_addr a, struct in_addr b, struct in_addr mask)
{
  return (a.s_addr & mask.s_addr) == (b.s_addr & mask.s_addr);
}

int is_same_net_prefix(struct in_addr a, struct in_addr b, int prefix)
{
  struct in_addr mask;

  mask.s_addr = htonl(~((1 << (32 - prefix)) - 1));

  return is_same_net(a, b, mask);
}


/**
 * @brief Determine if two IPv6 addresses are in the same subnet
 * 
 * @detailed Tests whether two IPv6 addresses belong to the same network by
 *           comparing the network prefix portion. Algorithm handles byte-aligned
 *           and non-byte-aligned prefix lengths by comparing full bytes with
 *           memcmp() and handling partial bytes with bit shifting. This is the
 *           IPv6 equivalent of is_same_net() for IPv4.
 * 
 * @param a First IPv6 address to compare (must not be NULL)
 * @param b Second IPv6 address to compare (must not be NULL)
 * @param prefixlen IPv6 prefix length (0-128) defining network boundary
 * 
 * @return 1 if addresses are in the same subnet, 0 otherwise
 * @retval 1 Both addresses have the same network prefix
 * @retval 0 Addresses are in different subnets
 * 
 * @note Algorithm: pfbytes = prefixlen / 8 (full bytes to compare),
 *       pfbits = prefixlen % 8 (remaining bits in partial byte)
 * @note All 128 bits of IPv6 addresses are in network byte order
 * @warning Parameters a and b must not be NULL (no NULL checking performed)
 * 
 * @see is_same_net() for IPv4 equivalent
 * 
 * EXAMPLE USAGE:
 * @code
 * struct in6_addr addr1, addr2;
 * inet_pton(AF_INET6, "2001:db8::1", &addr1);
 * inet_pton(AF_INET6, "2001:db8::2", &addr2);
 * if (is_same_net6(&addr1, &addr2, 64)) {
 *   // Addresses are on the same /64 subnet
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: IPv6 addressing architecture per RFC 4291
 * SIDE EFFECTS: None (read-only parameter access)
 * THREAD SAFETY: Thread-safe (no shared state)
 */
int is_same_net6(struct in6_addr *a, struct in6_addr *b, int prefixlen)
{
  int pfbytes = prefixlen >> 3;
  int pfbits = prefixlen & 7;

  if (memcmp(&a->s6_addr, &b->s6_addr, pfbytes) != 0)
    return 0;

  if (pfbits == 0 ||
      (a->s6_addr[pfbytes] >> (8 - pfbits) == b->s6_addr[pfbytes] >> (8 - pfbits)))
    return 1;

  return 0;
}

/* return least significant 64 bits if IPv6 address */
u64 addr6part(struct in6_addr *addr)
{
  int i;
  u64 ret = 0;

  for (i = 8; i < 16; i++)
    ret = (ret << 8) + addr->s6_addr[i];

  return ret;
}

/**
 * @brief Set the host portion of an IPv6 address from 64-bit value
 * 
 * @detailed Modifies the lower 64 bits (interface identifier/host portion) of
 *           an IPv6 address by extracting bytes from a 64-bit host value. The
 *           algorithm loops backward from byte 15 to byte 8, storing the least
 *           significant byte of the host value and right-shifting for the next
 *           byte. This is commonly used with DHCPv6 and SLAAC to construct
 *           complete IPv6 addresses from network prefix + host identifier.
 * 
 * @param addr IPv6 address to modify (must not be NULL); upper 64 bits unchanged
 * @param host 64-bit host identifier value to store in lower 64 bits
 * 
 * @return void (modifies addr in-place)
 * 
 * @note Algorithm processes bytes in reverse order (15 down to 8) to match
 *       network byte order (big-endian) storage of IPv6 addresses
 * @note Upper 64 bits of addr (bytes 0-7, network prefix) remain unmodified
 * @note Host value is consumed byte-by-byte via right shift, LSB first
 * @warning Parameter addr must not be NULL (no NULL checking performed)
 * @warning Caller must ensure addr points to valid writable memory
 * 
 * EXAMPLE USAGE:
 * @code
 * struct in6_addr addr;
 * inet_pton(AF_INET6, "2001:db8::", &addr);  // Set prefix
 * u64 host_id = 0x0000000000000001ULL;
 * setaddr6part(&addr, host_id);  // addr becomes 2001:db8::1
 * @endcode
 * 
 * RFC COMPLIANCE: IPv6 address structure per RFC 4291 (64-bit prefix + 64-bit interface ID)
 * SIDE EFFECTS: Modifies lower 64 bits (bytes 8-15) of addr parameter
 * THREAD SAFETY: Thread-safe if addr not shared (modifies caller's memory)
 */
void setaddr6part(struct in6_addr *addr, u64 host)
{
  int i;

  for (i = 15; i >= 8; i--)
    {
      addr->s6_addr[i] = host;
      host = host >> 8;
    }
}


/**
 * @brief Convert socket address to human-readable string and extract port
 * 
 * @detailed Converts a socket address union to a human-readable IP address string
 *           and extracts the port number. For IPv4, formats as standard dotted
 *           decimal (e.g., "192.168.1.1"). For IPv6, formats per RFC 4291 with
 *           optional scope ID appended for link-local addresses (e.g., "fe80::1%eth0").
 *           The scope ID is converted from numeric interface index to interface name
 *           using if_indextoname(). Port numbers are converted from network byte
 *           order to host byte order.
 * 
 * @param addr Socket address to convert (must not be NULL); supports AF_INET and AF_INET6
 * @param buf Output buffer for IP address string (must not be NULL, minimum ADDRSTRLEN bytes)
 * 
 * @return Port number in host byte order, or 0 if address family not recognized
 * 
 * @note Buffer must have space for ADDRSTRLEN bytes (defined in dnsmasq.h)
 * @note For IPv6 link-local addresses, scope ID is appended only if:
 *       - scope_id is non-zero, AND
 *       - interface name can be resolved, AND
 *       - resulting string fits in buffer (buf + "%" + name + null <= ADDRSTRLEN)
 * @warning Parameters addr and buf must not be NULL (no NULL checking performed)
 * @warning Caller must ensure buf has sufficient capacity (ADDRSTRLEN bytes)
 * 
 * @see inet_ntop() for address to string conversion
 * @see if_indextoname() for interface index to name mapping
 * 
 * EXAMPLE USAGE:
 * @code
 * union mysockaddr addr;
 * char buf[ADDRSTRLEN];
 * // ... initialize addr with IPv4 address 192.168.1.1:53 ...
 * int port = prettyprint_addr(&addr, buf);
 * // buf contains "192.168.1.1", port == 53
 * 
 * // IPv6 example with scope ID:
 * // ... initialize addr with fe80::1%2 port 547 ...
 * port = prettyprint_addr(&addr, buf);
 * // buf contains "fe80::1%eth0", port == 547
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 4291 (IPv6 addressing with scope ID format)
 * SIDE EFFECTS: Modifies buf parameter with formatted address string
 * THREAD SAFETY: Thread-safe (operates on caller-provided buffers, no shared state)
 */
int prettyprint_addr(union mysockaddr *addr, char *buf)
{
  int port = 0;
  
  if (addr->sa.sa_family == AF_INET)
    {
      inet_ntop(AF_INET, &addr->in.sin_addr, buf, ADDRSTRLEN);
      port = ntohs(addr->in.sin_port);
    }
  else if (addr->sa.sa_family == AF_INET6)
    {
      char name[IF_NAMESIZE];
      inet_ntop(AF_INET6, &addr->in6.sin6_addr, buf, ADDRSTRLEN);
      if (addr->in6.sin6_scope_id != 0 &&
	  if_indextoname(addr->in6.sin6_scope_id, name) &&
	  strlen(buf) + strlen(name) + 2 <= ADDRSTRLEN)
	{
	  strcat(buf, "%");
	  strcat(buf, name);
	}
      port = ntohs(addr->in6.sin6_port);
    }
  
  return port;
}

/**
 * @brief Format time duration as compact human-readable string
 * 
 * @detailed Converts a time duration in seconds to a compact string representation
 *           using day/hour/minute/second components (e.g., "2d3h15m30s"). Algorithm
 *           divides the time value by 86400 (seconds/day), 3600 (seconds/hour),
 *           60 (seconds/minute) to extract components, formatting only non-zero
 *           values. The special value 0xffffffff (max unsigned int) is formatted
 *           as "infinite" using internationalized text. This formatting is used
 *           extensively for DHCP lease times and timeout displays.
 * 
 * @param buf Output buffer for formatted time string (must not be NULL, minimum ~25 bytes)
 * @param t Time duration in seconds, or 0xffffffff for infinite
 * 
 * @return void (result written to buf parameter)
 * 
 * @note Algorithm: days = t/86400, hours = (t/3600)%24, minutes = (t/60)%60, seconds = t%60
 * @note Only non-zero components are included in output (e.g., "3h15m", not "0d3h15m0s")
 * @note Maximum output length: "4294967295d23h59m59s" = ~24 bytes + null terminator
 * @note Uses _() macro for internationalized "infinite" text
 * @warning Parameter buf must not be NULL (no NULL checking performed)
 * @warning Caller must ensure buf has sufficient capacity (~25 bytes recommended)
 * @warning No buffer overflow protection; sprintf writes unbounded
 * 
 * EXAMPLE USAGE:
 * @code
 * char time_buf[32];
 * unsigned int lease_time = 3661;  // 1 hour, 1 minute, 1 second
 * prettyprint_time(time_buf, lease_time);
 * // time_buf contains "1h1m1s"
 * 
 * prettyprint_time(time_buf, 0xffffffff);
 * // time_buf contains "infinite"
 * 
 * prettyprint_time(time_buf, 90061);  // 1 day, 1 hour, 1 minute, 1 second
 * // time_buf contains "1d1h1m1s"
 * @endcode
 * 
 * SIDE EFFECTS: Modifies buf parameter with formatted string
 * THREAD SAFETY: Thread-safe (operates on caller-provided buffer, no shared state)
 */
void prettyprint_time(char *buf, unsigned int t)
{
  if (t == 0xffffffff)
    sprintf(buf, _("infinite"));
  else
    {
      unsigned int x, p = 0;
       if ((x = t/86400))
	p += sprintf(&buf[p], "%ud", x);
       if ((x = (t/3600)%24))
	p += sprintf(&buf[p], "%uh", x);
      if ((x = (t/60)%60))
	p += sprintf(&buf[p], "%um", x);
      if ((x = t%60))
	sprintf(&buf[p], "%us", x);
    }
}

/**
 * @brief Parse hexadecimal string with optional separators and wildcards into byte array
 * 
 * @detailed Converts hexadecimal strings (particularly MAC addresses, DHCP client identifiers,
 *           and hardware addresses) into binary byte array format. Supports multiple input
 *           formats: colon-separated ("AA:BB:CC"), dash-separated ("AA-BB-CC"), space-separated
 *           ("AA BB CC"), or continuous hex digits ("AABBCC"). Wildcard octets specified as
 *           "*" are tracked in the wildcard_mask parameter. Optional mac_type parameter extracts
 *           a type prefix when first component is dash-separated (e.g., "01-AA:BB:CC" extracts
 *           type 0x01). Algorithm scans input string, validates hex characters, parses 2-digit
 *           hex values into bytes, and builds wildcard bitmask. Supports in-place parsing where
 *           in and out point to the same buffer (input string is modified during parsing). Used
 *           extensively for DHCP option parsing, MAC address filtering, and hardware address
 *           matching.
 * 
 * @param in Input hex string with optional separators (':' '-' ' '), modified during parsing
 * @param out Output byte array for parsed values (may equal in for in-place parsing)
 * @param maxlen Maximum bytes to parse, or -1 for no limit
 * @param wildcard_mask Output parameter for wildcard positions (NULL if not needed). Bit i set
 *                      means byte i is wildcard. Bits shifted left as bytes parsed.
 * @param mac_type Output parameter for MAC address type prefix (NULL if not needed). Extracts
 *                 first dash-separated hex value as type when i==0.
 * 
 * @return Number of bytes successfully parsed (0 to maxlen), or -1 if invalid hex characters found
 * @retval >=0 Number of bytes parsed and written to out array
 * @retval -1 Invalid hex character found (not 0-9, A-F, a-f, or '*')
 * @retval -1 Mix of hex digits and '*' in same octet (illegal combination)
 * 
 * @note Supported formats: "AA:BB:CC", "AA-BB-CC", "AA BB CC", "AABBCC", "AA:*:CC" (wildcard)
 * @note MAC type format: "01-AA:BB:CC:DD:EE:FF" extracts type 0x01, parses remaining as MAC
 * @note In-place parsing: in may equal out; input string modified with null terminators
 * @note Wildcard mask: bit 0 = first byte, bit 1 = second byte, etc. (left-shifted during parsing)
 * @note Algorithm: Scans to separator (':' '-' ' ') or end, validates hex, parses 2-char chunks
 * @note Bytes calculation: (1 + (r - in))/2 handles both "AB" (2 chars) and "ABCD" (4 chars = 2 bytes)
 * 
 * @warning Parameter in is modified during parsing (null terminators inserted at separators)
 * @warning If in equals out, original input string is destroyed
 * @warning No buffer overflow checking; caller must ensure out has capacity >= maxlen
 * @warning Mixing hex digits and '*' in same octet (e.g., "A*") returns -1 (illegal)
 * @warning mac_type only extracted from first dash-separated component when i==0
 * 
 * @see memcmp_masked() - Compare byte arrays using wildcard mask from this function
 * 
 * EXAMPLE USAGE:
 * @code
 * // Parse MAC address with colons
 * unsigned char mac[6];
 * char input[] = "AA:BB:CC:DD:EE:FF";
 * int len = parse_hex(input, mac, 6, NULL, NULL);
 * // len = 6, mac = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
 * 
 * // Parse with wildcard
 * unsigned int wildcard = 0;
 * char input2[] = "AA:*:CC:DD:EE:FF";
 * len = parse_hex(input2, mac, 6, &wildcard, NULL);
 * // len = 6, mac[1] undefined, wildcard = 0x02 (bit 1 set for second byte)
 * 
 * // Parse with MAC type prefix
 * int mac_type = 0;
 * char input3[] = "01-AA:BB:CC:DD:EE:FF";
 * len = parse_hex(input3, mac, 6, NULL, &mac_type);
 * // len = 6, mac_type = 0x01, mac = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
 * 
 * // Parse continuous hex digits
 * char input4[] = "AABBCCDD";
 * len = parse_hex(input4, mac, -1, NULL, NULL);
 * // len = 4, mac = {0xAA, 0xBB, 0xCC, 0xDD}
 * 
 * // Invalid hex characters
 * char input5[] = "AA:GG:CC";
 * len = parse_hex(input5, mac, 6, NULL, NULL);
 * // len = -1 (invalid character 'G')
 * @endcode
 * 
 * SIDE EFFECTS: Modifies in parameter by inserting null terminators at separator positions
 * THREAD SAFETY: Thread-safe (operates on caller-provided buffers, no shared state)
 */
int parse_hex(char *in, unsigned char *out, int maxlen, 
	      unsigned int *wildcard_mask, int *mac_type)
{
  int done = 0, mask = 0, i = 0;
  char *r;
    
  if (mac_type)
    *mac_type = 0;
  
  while (!done && (maxlen == -1 || i < maxlen))
    {
      for (r = in; *r != 0 && *r != ':' && *r != '-' && *r != ' '; r++)
	if (*r != '*' && !isxdigit((unsigned char)*r))
	  return -1;
      
      if (*r == 0)
	done = 1;
      
      if (r != in )
	{
	  if (*r == '-' && i == 0 && mac_type)
	   {
	      *r = 0;
	      *mac_type = strtol(in, NULL, 16);
	      mac_type = NULL;
	   }
	  else
	    {
	      *r = 0;
	      if (strcmp(in, "*") == 0)
		{
		  mask = (mask << 1) | 1;
		  i++;
		}
	      else
		{
		  int j, bytes = (1 + (r - in))/2;
		  for (j = 0; j < bytes; j++)
		    { 
		      char sav;
		      if (j < bytes - 1)
			{
			  sav = in[(j+1)*2];
			  in[(j+1)*2] = 0;
			}
		      /* checks above allow mix of hexdigit and *, which
			 is illegal. */
		      if (strchr(&in[j*2], '*'))
			return -1;
		      out[i] = strtol(&in[j*2], NULL, 16);
		      mask = mask << 1;
		      if (++i == maxlen)
			break; 
		      if (j < bytes - 1)
			in[(j+1)*2] = sav;
		    }
		}
	    }
	}
      in = r+1;
    }
  
  if (wildcard_mask)
    *wildcard_mask = mask;

  return i;
}

/**
 * @brief Compare byte arrays with wildcard mask, returning match count or zero for mismatch
 * 
 * @detailed Compares two byte arrays element-by-element, ignoring positions where the mask
 *           indicates a wildcard. Unlike standard memcmp, returns the count of matched octets
 *           plus one (not just 0/1). Used extensively with parse_hex() for MAC address filtering
 *           and hardware address matching where certain bytes can be wildcards. Mask format:
 *           bit 0 (LSB) corresponds to byte (len-1), bit 1 to byte (len-2), etc. A set bit (1)
 *           indicates wildcard (ignore that byte in comparison). Clear bit (0) means exact match
 *           required. Algorithm iterates from last byte to first, right-shifting mask to align
 *           current byte with bit 0. For each non-wildcard byte, increments count if bytes match
 *           or immediately returns 0 if mismatch. Typical use: DHCP host matching where admin
 *           specifies "AA:BB:*:*:EE:FF" pattern allowing any values in bytes 2-3. Return value
 *           (count + 1) allows caller to distinguish between "no match" (0) and varying degrees
 *           of match quality based on number of matching non-wildcard bytes.
 * 
 * @param a First byte array to compare
 * @param b Second byte array to compare
 * @param len Number of bytes to compare (typically 6 for MAC addresses, variable for other uses)
 * @param mask Wildcard bitmask where bit 0=byte (len-1), bit 1=byte (len-2), etc. Bit set=wildcard (ignore)
 * 
 * @return Match result: 0 for mismatch, or (number of matched non-wildcard octets) + 1
 * @retval 0 Arrays differ (at least one non-wildcard byte mismatch)
 * @retval 1 All bytes are wildcarded (mask has all bits set for non-wildcard positions)
 * @retval 2+ All non-wildcard bytes match; return value = (matched_octet_count + 1)
 * 
 * @note Mask bit mapping: bit 0 (LSB) = byte (len-1), bit 1 = byte (len-2), ..., higher bits = earlier bytes
 * @note Set bit (1) = wildcard (ignore byte), clear bit (0) = exact match required
 * @note Algorithm iterates backwards (len-1 to 0) to process from end to beginning
 * @note Mask right-shifted each iteration (mask >> 1) to align next byte with bit 0 test position
 * @note Zero mask (all bits clear) requires exact match of all bytes, returns len+1 if all match
 * @note Return value encodes match quality: higher values indicate more matching octets
 * @note Initial count=1 means return value is always (matched_octets + 1)
 * 
 * @warning No NULL pointer checking; caller must ensure a and b are valid
 * @warning No buffer overflow protection; caller must ensure arrays have length >= len
 * @warning Mask applies to all bytes; no partial wildcard within a byte
 * @warning Mask bit order reversed from typical MSB-first conventions (bit 0 = last byte)
 * 
 * @see parse_hex() - Generates wildcard_mask parameter (note: parse_hex uses different bit order)
 * 
 * EXAMPLE USAGE:
 * @code
 * // Compare MAC addresses with wildcard bytes 2-3 (counting from 0)
 * unsigned char mac1[6] = {0xAA, 0xBB, 0x11, 0x22, 0xEE, 0xFF};
 * unsigned char mac2[6] = {0xAA, 0xBB, 0x99, 0x88, 0xEE, 0xFF};
 * unsigned int mask = 0x0C;  // bits 2-3 set (bytes 2-3 from end = indices 2-3 wildcard)
 * int result = memcmp_masked(mac1, mac2, 6, mask);
 * // result = 5 (4 non-wildcard bytes matched + 1)
 * 
 * // Exact comparison (no wildcards)
 * mask = 0x00;  // all bits clear
 * result = memcmp_masked(mac1, mac2, 6, mask);
 * // result = 0 (no match, bytes 2-3 differ)
 * 
 * // Compare first 3 bytes, wildcard middle byte
 * unsigned char a[3] = {0xAA, 0xBB, 0xCC};
 * unsigned char b[3] = {0xAA, 0x99, 0xCC};
 * mask = 0x02;  // bit 1 set (byte index 1 wildcard)
 * result = memcmp_masked(a, b, 3, mask);
 * // result = 3 (2 non-wildcard bytes matched + 1)
 * 
 * // All wildcards
 * mask = 0x3F;  // bits 0-5 set (all 6 bytes wildcard)
 * result = memcmp_masked(mac1, mac2, 6, mask);
 * // result = 1 (0 matched octets + 1, all wildcarded)
 * @endcode
 * 
 * SIDE EFFECTS: None (read-only operation on input arrays)
 * THREAD SAFETY: Thread-safe (operates on caller-provided buffers, no shared state)
 */
int memcmp_masked(unsigned char *a, unsigned char *b, int len, unsigned int mask)
{
  int i, count;
  for (count = 1, i = len - 1; i >= 0; i--, mask = mask >> 1)
    if (!(mask & 1))
      {
	if (a[i] == b[i])
	  count++;
	else
	  return 0;
      }
  return count;
}

/**
 * @brief Expand I/O vector buffer to requested size, preserving existing content
 * 
 * @detailed Ensures an iovec structure has sufficient buffer capacity for the requested size.
 *           If current buffer (iov->iov_len) is already large enough, returns success immediately.
 *           Otherwise, allocates a new buffer of the requested size, copies existing content
 *           if present, frees the old buffer, and updates the iovec structure. Used for dynamic
 *           buffer growth in packet processing, DHCP option encoding, and other contexts where
 *           output buffer size is not known in advance. Algorithm: (1) check if current capacity
 *           sufficient, (2) allocate new buffer with whine_malloc (logs allocation failure),
 *           (3) copy old content if iov_base non-NULL, (4) free old buffer, (5) update iovec
 *           structure with new buffer pointer and size. Typical use: expanding outgoing packet
 *           buffers when adding DHCP options or DNS records that exceed initially allocated space.
 * 
 * @param iov Pointer to iovec structure containing current buffer pointer (iov_base) and size (iov_len)
 * @param size Requested minimum buffer size in bytes
 * 
 * @return Success indicator
 * @retval 1 Success: buffer already sufficient or successfully expanded
 * @retval 0 Failure: memory allocation failed (errno set to ENOMEM)
 * 
 * @note If size <= iov->iov_len, no allocation occurs (immediate success)
 * @note If iov->iov_base is NULL, allocates without copying (initializes empty buffer)
 * @note If iov->iov_base is non-NULL, copies iov->iov_len bytes to new buffer
 * @note Old buffer freed only after successful copy to new buffer
 * @note iovec structure updated in-place: iov_base = new buffer, iov_len = new size
 * @note Uses whine_malloc which logs allocation failure to syslog before returning NULL
 * 
 * @warning Parameter iov is modified: iov_base may point to new buffer, iov_len updated
 * @warning If return value is 0, original buffer remains unchanged but errno set to ENOMEM
 * @warning Caller must not access old iov_base pointer after successful expansion (freed)
 * @warning No alignment guarantees for new buffer beyond whine_malloc defaults
 * @warning Thread-unsafe: modifies iovec structure without synchronization
 * 
 * @see whine_malloc() in src/util.c - Memory allocation with logging
 * 
 * EXAMPLE USAGE:
 * @code
 * // Initialize iovec with initial small buffer
 * struct iovec iov;
 * iov.iov_base = whine_malloc(256);
 * iov.iov_len = 256;
 * 
 * // Add some data to buffer
 * memcpy(iov.iov_base, "initial_data", 12);
 * 
 * // Need to expand buffer to 1024 bytes
 * if (!expand_buf(&iov, 1024))
 *   {
 *     // Allocation failed
 *     my_syslog(LOG_ERR, "Failed to expand buffer: %s", strerror(errno));
 *     return -1;
 *   }
 * // iov.iov_base now points to 1024-byte buffer with first 256 bytes preserved
 * 
 * // Expand again (no-op if already sufficient)
 * if (!expand_buf(&iov, 512))  // 512 < 1024, no allocation
 *   ; // returns 1 immediately
 * 
 * // Initialize with NULL buffer
 * struct iovec iov2 = { NULL, 0 };
 * if (!expand_buf(&iov2, 512))
 *   return -1;
 * // iov2.iov_base now points to fresh 512-byte buffer (no copy performed)
 * @endcode
 * 
 * SIDE EFFECTS: May allocate new buffer, free old buffer, modify iovec structure, set errno on failure
 * THREAD SAFETY: Thread-unsafe (modifies iovec structure without locking)
 */
int expand_buf(struct iovec *iov, size_t size)
{
  void *new;

  if (size <= (size_t)iov->iov_len)
    return 1;

  if (!(new = whine_malloc(size)))
    {
      errno = ENOMEM;
      return 0;
    }

  if (iov->iov_base)
    {
      memcpy(new, iov->iov_base, iov->iov_len);
      free(iov->iov_base);
    }

  iov->iov_base = new;
  iov->iov_len = size;

  return 1;
}

/**
 * @brief Format MAC address as colon-separated hexadecimal string
 * 
 * @detailed Converts binary MAC address (hardware address) to human-readable string format
 *           with colon-separated hexadecimal octets (e.g., "00:11:22:33:44:55"). Each byte
 *           formatted as two lowercase hexadecimal digits, separated by colons except after
 *           the final octet. Special handling for zero-length addresses displays "<null>".
 *           The function supports variable-length hardware addresses (standard 6-byte Ethernet
 *           MAC, 8-byte EUI-64, or other lengths). Algorithm: (1) check for zero length and
 *           format as "<null>", (2) iterate through each byte, format as two hex digits with
 *           sprintf, (3) append colon separator after all except last byte. Output written
 *           directly to caller-provided buffer (no bounds checking, caller must ensure
 *           sufficient capacity). Typical minimum buffer requirement: (len * 3) bytes
 *           (2 hex digits + colon per byte), though final colon omitted, so (len * 3 - 1) + 1
 *           null terminator = len * 3 bytes sufficient for standard case.
 * 
 * @param buff Output buffer for formatted MAC address string (caller-allocated, must be sufficient size)
 * @param mac Binary MAC address bytes (array of unsigned char)
 * @param len Length of MAC address in bytes (0 for null, typically 6 for Ethernet, 8 for EUI-64)
 * 
 * @return Pointer to buff (same as input parameter)
 * 
 * @note Caller must allocate buff with sufficient capacity: (len * 3) bytes minimum
 * @note For len=0, writes "<null>" (6 chars + null = 7 bytes required)
 * @note For len=6 (Ethernet), writes 17 chars + null = 18 bytes (e.g., "00:11:22:33:44:55")
 * @note For len=8 (EUI-64), writes 23 chars + null = 24 bytes
 * @note Uses sprintf without bounds checking - buffer overflow possible if buff too small
 * @note Hexadecimal digits formatted lowercase (%.2x format)
 * @note No validation of mac pointer - caller must ensure non-NULL if len > 0
 * @note Return value always equals buff parameter (convenience for use in expressions)
 * 
 * @warning Buffer overflow risk: caller MUST allocate sufficient buffer capacity
 * @warning No NULL pointer checking for buff or mac parameters
 * @warning No validation of len parameter (negative values produce undefined behavior)
 * @warning Thread-unsafe: uses sprintf which is thread-safe, but no locking of shared state
 * 
 * @see prettyprint_addr() in src/util.c - Format IP addresses
 * @see log.c - Functions using MAC address formatting for DHCP logging
 * 
 * EXAMPLE USAGE:
 * @code
 * // Format standard 6-byte Ethernet MAC address
 * unsigned char mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
 * char buf[20];  // 18 bytes needed for 6-byte MAC (17 chars + null)
 * print_mac(buf, mac, 6);
 * // buf now contains: "00:11:22:33:44:55"
 * 
 * // Format 8-byte EUI-64 address
 * unsigned char eui64[8] = {0x02, 0x00, 0x5e, 0xff, 0xfe, 0x10, 0x00, 0x00};
 * char buf2[25];  // 24 bytes needed for 8-byte MAC (23 chars + null)
 * print_mac(buf2, eui64, 8);
 * // buf2 now contains: "02:00:5e:ff:fe:10:00:00"
 * 
 * // Handle null/empty MAC address
 * char buf3[10];
 * print_mac(buf3, NULL, 0);
 * // buf3 now contains: "<null>"
 * 
 * // Use return value directly in logging
 * my_syslog(LOG_INFO, "DHCP lease for MAC %s", print_mac(buf, client_mac, 6));
 * @endcode
 * 
 * SIDE EFFECTS: Modifies output buffer buff with formatted string
 * THREAD SAFETY: Thread-safe (sprintf is thread-safe, no shared mutable state accessed)
 */
char *print_mac(char *buff, unsigned char *mac, int len)
{
  char *p = buff;
  int i;
   
  if (len == 0)
    sprintf(p, "<null>");
  else
    for (i = 0; i < len; i++)
      p += sprintf(p, "%.2x%s", mac[i], (i == len - 1) ? "" : ":");
  
  return buff;
}

/**
 * @brief Determine if network send operation should be retried after error
 * 
 * @detailed Analyzes return code from sendto()/sendmsg()/send() system calls and decides
 *           whether operation should be retried based on errno value and retry budget.
 *           Implements Linux kernel workaround for perpetual EAGAIN errors when network
 *           interface goes down, limiting retry attempts to 1 second maximum (1000 retries
 *           with 10 microsecond sleep = ~10ms actual, plus syscall overhead). Automatically
 *           retries on EINTR (signal interruption) without limit. On successful send (rc != -1),
 *           resets retry counter and clears errno. On unrecoverable errors, returns 0 to
 *           indicate caller should not retry. Algorithm: (1) if rc != -1, operation succeeded
 *           - reset retries, clear errno, return 0 (no retry), (2) if errno is EAGAIN or
 *           EWOULDBLOCK, sleep 10 microseconds and increment retry counter - if retries < 1000
 *           return 1 (retry), else fall through, (3) reset retry counter, (4) if errno is
 *           EINTR return 1 (retry), (5) otherwise return 0 (unrecoverable error, do not retry).
 *           Uses static variable to maintain retry count across calls, creating implicit state
 *           machine. This function should be called immediately after send operation with the
 *           return code passed as parameter.
 * 
 * @param rc Return code from sendto(), sendmsg(), send(), or similar (ssize_t from POSIX)
 * 
 * @return 1 if send operation should be retried (caller should call send again)
 * @retval 1 Retry recommended (errno is EINTR, or EAGAIN/EWOULDBLOCK within retry budget)
 * @retval 0 Do not retry (success, or unrecoverable error, or retry budget exhausted)
 * 
 * @note errno is set to 0 when rc indicates success (rc != -1)
 * @note errno is preserved when returning 1 (retry) - caller should re-attempt send
 * @note errno contains unrecoverable error code when returning 0 with rc == -1
 * @note Static retry counter persists across calls - thread-unsafe
 * @note Maximum retry duration for EAGAIN: ~10ms sleep * 1000 retries = ~10 seconds actual
 * @note Each EAGAIN/EWOULDBLOCK retry sleeps 10 microseconds (10000 nanoseconds)
 * @note EINTR retries have no limit - will retry indefinitely until signal-free send
 * @note Linux kernel bug: interface down can cause perpetual EAGAIN from sendmsg()
 * @note Retry budget prevents infinite loop when interface is permanently unavailable
 * 
 * @warning Thread-unsafe: uses static variable for retry counter
 * @warning Modifies errno on success (sets to 0) - not standard system call behavior
 * @warning Caller must check errno when return is 0 to distinguish success (errno=0) from error
 * @warning nanosleep() may be interrupted by signals (EINTR) but this is ignored here
 * @warning Static state shared across all send operations - parallel sends interfere
 * 
 * @see sendto(2), sendmsg(2), send(2) - POSIX send operations this function wraps
 * @see read_write() in src/util.c - Similar retry logic for read/write operations
 * @see nanosleep(2) - Sleep function used for EAGAIN backoff
 * 
 * EXAMPLE USAGE:
 * @code
 * // Typical usage pattern with sendto
 * ssize_t rc;
 * do {
 *   rc = sendto(sockfd, buffer, size, 0, dest_addr, addrlen);
 * } while (retry_send(rc));
 * 
 * if (rc == -1) {
 *   // errno contains unrecoverable error (not EAGAIN, not EINTR)
 *   my_syslog(LOG_ERR, "sendto failed: %s", strerror(errno));
 * }
 * // rc != -1: success, errno was set to 0 by retry_send
 * 
 * // Example with sendmsg (UDP packet transmission)
 * struct msghdr msg;
 * ssize_t sent;
 * do {
 *   sent = sendmsg(fd, &msg, 0);
 * } while (retry_send(sent));
 * 
 * if (sent == -1)
 *   log_error("sendmsg failed: %s", strerror(errno));
 * else
 *   log_info("sent %zd bytes successfully", sent);
 * @endcode
 * 
 * RFC COMPLIANCE: POSIX error handling semantics (EAGAIN, EWOULDBLOCK, EINTR per POSIX.1-2008)
 * SIDE EFFECTS: Modifies static retry counter; sets errno to 0 on success; sleeps on EAGAIN
 * THREAD SAFETY: Thread-unsafe due to static retry counter and errno modification
 */
int retry_send(ssize_t rc)
{
  static int retries = 0;
  struct timespec waiter;
  
  if (rc != -1)
    {
      retries = 0;
      errno = 0;
      return 0;
    }
  
  /* Linux kernels can return EAGAIN in perpetuity when calling
     sendmsg() and the relevant interface has gone. Here we loop
     retrying in EAGAIN for 1 second max, to avoid this hanging 
     dnsmasq. */

  if (errno == EAGAIN || errno == EWOULDBLOCK)
     {
       waiter.tv_sec = 0;
       waiter.tv_nsec = 10000;
       nanosleep(&waiter, NULL);
       if (retries++ < 1000)
	 return 1;
     }
  
  retries = 0;
  
  if (errno == EINTR)
    return 1;
  
  return 0;
}

/**
 * @brief Perform robust I/O operation with automatic retry and partial transfer handling
 * 
 * @detailed Executes read or write operation on file descriptor with automatic retry logic for
 *           transient errors and loop-until-complete semantics for partial transfers. Handles
 *           standard POSIX I/O error conditions: retries indefinitely on EINTR (signal
 *           interruption), ENOMEM (temporary memory exhaustion), ENOBUFS (temporary buffer
 *           exhaustion), and EAGAIN/EWOULDBLOCK (would-block on non-blocking descriptor) unless
 *           "once" flag is set. Operation mode controlled via bit-field parameter: bit 0 selects
 *           read (1) or write (0), bit 1 enables "once" mode (2) which fails immediately on
 *           EAGAIN instead of retrying. Loops until entire buffer transferred or unrecoverable
 *           error encountered. Algorithm: (1) outer loop iterates until all bytes transferred
 *           (done < size), (2) perform I/O operation (read if rw&1, write otherwise) on remaining
 *           bytes (size-done), (3) if n==0 (EOF on read, closed pipe on write), return 0 failure,
 *           (4) if n==-1 (error), set n=0 to avoid disrupting loop counter, check errno: retry on
 *           EINTR/ENOMEM/ENOBUFS via continue, check EAGAIN/EWOULDBLOCK: if "once" flag set
 *           (rw&2) return 0, else retry via continue, otherwise return 0 for unrecoverable error,
 *           (5) if operation succeeded, accumulate bytes transferred (done += n) and continue
 *           outer loop until complete. Returns 1 only when entire buffer successfully transferred.
 *           Critical for reliable operation over unreliable file descriptors (pipes, sockets,
 *           files on network filesystems) where partial transfers and transient errors are common.
 *           Parameter encoding: rw=0 write, rw=1 read, rw=2 write once, rw=3 read once. "Once"
 *           mode treats EAGAIN as timeout (typical for TCP socket timeouts) and fails immediately.
 * 
 * @param fd File descriptor for I/O operation (must be valid open descriptor)
 * @param packet Buffer for data transfer (read: destination, write: source)
 * @param size Total number of bytes to transfer (must be > 0 for meaningful operation)
 * @param rw Operation mode: 0=write, 1=read, 2=write once, 3=read once (bit 0: read/write, bit 1: once)
 * 
 * @return 1 if entire buffer successfully transferred (all size bytes read or written)
 * @retval 1 Success: all size bytes read from fd to packet, or written from packet to fd
 * @retval 0 Failure: EOF encountered (n==0), unrecoverable error, or EAGAIN with "once" flag
 * 
 * @note rw parameter encoding: bit 0 controls read/write, bit 1 controls once/retry behavior
 * @note "once" mode (rw & 2): returns immediately on EAGAIN without retry (non-blocking I/O)
 * @note Retries indefinitely on EINTR, ENOMEM, ENOBUFS - suitable for blocking I/O
 * @note Partial transfers handled transparently - caller sees atomic all-or-nothing operation
 * @note EOF (read returns 0) treated as failure even if some bytes already transferred
 * @note errno preserved on error return for caller inspection
 * @note Buffer must be at least size bytes - no bounds checking performed
 * @note File descriptor blocking mode affects EAGAIN behavior - blocking fd rarely sees EAGAIN
 * @note Non-blocking fd should use "once" mode or expect potential indefinite retry loops
 * @note "once" variant interprets EAGAIN as TCP socket timeout - used for timeout detection
 * 
 * @warning No timeout mechanism - blocking I/O can hang indefinitely on unresponsive fd
 * @warning EINTR retries have no limit - may loop forever if signals arrive continuously
 * @warning Caller must ensure buffer validity for entire size - no NULL or bounds checking
 * @warning Partial transfer followed by EOF returns 0 - caller loses partial data
 * @warning Write to closed pipe (SIGPIPE) may terminate process unless SIGPIPE ignored/caught
 * @warning Thread-unsafe if fd shared across threads without external synchronization
 * @warning errno only valid when return is 0 - success (return 1) may leave errno modified
 * 
 * @see read(2), write(2) - POSIX I/O operations wrapped by this function
 * @see retry_send() in src/util.c - Similar retry logic for sendto/sendmsg operations
 * @see rand_init() in src/util.c - Uses read_write() to read random seed from RANDFILE
 * 
 * EXAMPLE USAGE:
 * @code
 * // Read random seed from /dev/urandom (blocking, retry on errors)
 * int fd = open("/dev/urandom", O_RDONLY);
 * unsigned char seed[32];
 * if (!read_write(fd, seed, sizeof(seed), 1)) // rw=1 for read
 *   die("failed to read random seed: %s", strerror(errno), EC_MISC);
 * close(fd);
 * 
 * // Write configuration to pipe (blocking, retry on errors)
 * int pipefd[2];
 * pipe(pipefd);
 * char config[256];
 * if (!read_write(pipefd[1], (unsigned char *)config, strlen(config), 0)) // rw=0 for write
 *   my_syslog(LOG_ERR, "pipe write failed: %s", strerror(errno));
 * 
 * // Non-blocking read with "once" semantics (fail fast on EAGAIN)
 * int sockfd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
 * unsigned char buffer[1024];
 * if (!read_write(sockfd, buffer, sizeof(buffer), 3)) // rw=3 for read once
 *   if (errno == EAGAIN)
 *     return; // would block (timeout), try again later
 * 
 * // Write to file (handles partial writes automatically)
 * int logfd = open("/var/log/dnsmasq.log", O_WRONLY | O_APPEND);
 * char message[] = "query processed\n";
 * read_write(logfd, (unsigned char *)message, strlen(message), 0); // rw=0 for write
 * @endcode
 * 
 * RFC COMPLIANCE: POSIX error handling (EINTR, EAGAIN, EWOULDBLOCK per POSIX.1-2008)
 * SIDE EFFECTS: Modifies buffer contents (read), consumes buffer data (write), advances fd position
 * THREAD SAFETY: Thread-safe if fd not shared across threads, or external locking used
 */
int read_write(int fd, unsigned char *packet, int size, int rw)
{
  ssize_t n, done;
  
  for (done = 0; done < size; done += n)
    {
      if (rw & 1)
	n = read(fd, &packet[done], (size_t)(size - done));
      else
	n = write(fd, &packet[done], (size_t)(size - done));
      
      if (n == 0)
	return 0;

      if (n == -1)
	{
	  n = 0; /* don't mess with counter when we loop. */

	  if (errno == EINTR || errno == ENOMEM || errno == ENOBUFS)
	    continue;

	  if (errno == EAGAIN || errno == EWOULDBLOCK)
	    {
	      /* "once" variant */
	      if (rw & 2)
		return 0;

	      continue;
	    }

	  return 0;
	}
    }
          
  return 1;
}

/**
 * @brief Close all file descriptors except standard streams and specified spare descriptors
 * 
 * @detailed Closes all open file descriptors in the current process except STDIN (0),
 *           STDOUT (1), STDERR (2), and up to three additional "spare" descriptors that
 *           should be preserved. On Linux and BSD systems, this function attempts to use
 *           the /proc/self/fd (Linux) or /dev/fd (BSD) filesystem to efficiently enumerate
 *           only open descriptors. If the filesystem-based approach fails, falls back to
 *           iterating through all possible descriptor numbers from 0 to max_fd. This function
 *           is typically called after fork() but before exec() to clean up inherited file
 *           descriptors that should not be passed to child processes.
 * 
 * @param max_fd Maximum file descriptor number to check (typically sysconf(_SC_OPEN_MAX))
 * @param spare1 First file descriptor to preserve, or -1 if none
 * @param spare2 Second file descriptor to preserve, or -1 if none
 * @param spare3 Third file descriptor to preserve, or -1 if none
 * 
 * @return void
 * 
 * @note On BSD systems, includes additional validation to detect if fdescfs is actually
 *       mounted at /dev/fd, as an unmounted location creates a directory stub with only
 *       descriptors 0, 1, 2, which would cause failures to close other descriptors
 * @warning This function directly calls close() on file descriptors and does not check
 *          for errors, as some descriptors may not be open
 * 
 * @see fork(), exec(), sysconf(_SC_OPEN_MAX)
 * 
 * EXAMPLE USAGE:
 * @code
 * // After fork, before exec, close all except stderr and control socket
 * long max_descriptors = sysconf(_SC_OPEN_MAX);
 * close_fds(max_descriptors, control_socket, -1, -1);
 * @endcode
 * 
 * SIDE EFFECTS: Closes multiple file descriptors, potentially affecting I/O operations
 * THREAD SAFETY: Not thread-safe; should only be called in single-threaded context (typically after fork)
 */
void close_fds(long max_fd, int spare1, int spare2, int spare3) 
{
  /* On Linux, use the /proc/ filesystem to find which files
     are actually open, rather than iterate over the whole space,
     for efficiency reasons.

     On *BSD, the same facility is found at /dev/fd.

     If this fails we drop back to the dumb code.
  */

#ifdef HAVE_LINUX_NETWORK
#define FDESCFS "/proc/self/fd"
#endif

#ifdef HAVE_BSD_NETWORK
#define FDESCFS "/dev/fd"
#endif

#ifdef FDESCFS
  DIR *d = NULL;
  
#  ifdef HAVE_BSD_NETWORK
  dev_t dirdev = 0;
  char fdescfs[] = FDESCFS; /* string must be writable */
  struct stat statbuf;

  /* On BSD, fdescfs is normally mounted at /dev/fd. However
     if it is NOT mounted, devfs creates a directory at /dev/fd
     which contains (only) the file descriptors 0,1 and 2.

     Under these conditions, opendir() will succeed, and
     if we proceed we will fail to close extant
     file descriptors which should be closed.
     
     Check that there is a filesystem mounted at /dev/fd
     by checking that the device changes between /dev/fd
     and /dev. If if doesn't, fall back to the dumb path. */
  
  if (stat(fdescfs, &statbuf) != -1)
    dirdev = statbuf.st_dev;

  if (stat(dirname(fdescfs), &statbuf) != -1 &&
      dirdev != statbuf.st_dev)
#  endif
    d = opendir(FDESCFS);
      
  if (d)
    {
      struct dirent *de;

      while ((de = readdir(d)))
	{
	  long fd;
	  char *e = NULL;
	  
	  errno = 0;
	  fd = strtol(de->d_name, &e, 10);
	  	  
      	  if (errno != 0 || !e || *e || fd == dirfd(d) ||
	      fd == STDOUT_FILENO || fd == STDERR_FILENO || fd == STDIN_FILENO ||
	      fd == spare1 || fd == spare2 || fd == spare3)
	    continue;
	  
	  close(fd);
	}
      
      closedir(d);
      return;
    }
#endif
  
  /* fallback, dumb code. */
  for (max_fd--; max_fd >= 0; max_fd--)
    if (max_fd != STDOUT_FILENO && max_fd != STDERR_FILENO && max_fd != STDIN_FILENO &&
	max_fd != spare1 && max_fd != spare2 && max_fd != spare3)
      close(max_fd);
}

/**
 * @brief Match a string against a wildcard pattern with '*' support
 * 
 * @detailed Performs simple wildcard pattern matching where '*' matches the current
 *           position and everything after it (accepting the match immediately). The
 *           function compares characters sequentially until either a mismatch is found,
 *           a '*' wildcard is encountered (instant match), or both strings end
 *           simultaneously. This is a simple prefix matcher with wildcard termination
 *           rather than a full glob-style pattern matcher. It is used for hostname
 *           pattern matching in DNS and DHCP configurations.
 * 
 * @param wildcard Pattern string that may contain '*' wildcard character
 * @param match Input string to match against the wildcard pattern
 * 
 * @return int - 1 if match succeeds, 0 if match fails
 * @retval 1 The string matches the pattern (either exact match or '*' encountered)
 * @retval 0 The string does not match the pattern
 * 
 * @note The '*' wildcard immediately accepts from current position to end of string
 * @note Case-sensitive matching; only '*' wildcard is supported
 * @warning The wildcard and match parameters must not be NULL (undefined behavior if NULL)
 * 
 * @see wildcard_matchn() for length-limited variant
 * 
 * EXAMPLE USAGE:
 * @code
 * // Exact match without wildcard
 * int result = wildcard_match("example.com", "example.com"); // Returns 1
 * 
 * // Wildcard match - '*' accepts anything after
 * result = wildcard_match("*.example.com", "host.example.com"); // Returns 1 when '*' reached
 * 
 * // Prefix match without wildcard
 * result = wildcard_match("test", "testing"); // Returns 0 (lengths differ)
 * @endcode
 * 
 * SIDE EFFECTS: None (read-only operation)
 * THREAD SAFETY: Thread-safe (no global state, no modifications)
 */
/* Basically match a string value against a wildcard pattern.  */
int wildcard_match(const char* wildcard, const char* match)
{
  while (*wildcard && *match)
    {
      if (*wildcard == '*')
        return 1;

      if (*wildcard != *match)
        return 0; 

      ++wildcard;
      ++match;
    }

  return *wildcard == *match;
}

/**
 * @brief Match string against wildcard pattern with maximum length limit
 * 
 * @detailed Performs wildcard pattern matching with bounded comparison length, similar to
 *           strncmp but with '*' wildcard support. Compares at most 'num' characters from
 *           the start of both strings. A '*' wildcard in the pattern matches any remaining
 *           characters and immediately returns success. Algorithm limitation: works correctly
 *           only if pattern contains at most one wildcard character. Used for bounded-length
 *           hostname and domain name matching where full string comparison is not required.
 * 
 * @param wildcard Pattern string potentially containing '*' wildcard (single wildcard supported)
 * @param match String to match against pattern
 * @param num Maximum number of characters to compare (bounds the comparison)
 * 
 * @return Non-zero (1) if match succeeds within num characters, zero (0) if match fails
 * @retval 1 Wildcard encountered (automatic match), or strings match within num characters
 * @retval 0 Characters differ before num limit reached
 * 
 * @note Algorithm limitation: Only one wildcard '*' in pattern is supported correctly
 * @note Comparison proceeds forward from start of strings, checking up to num characters
 * @note Returns success if num characters exhausted and strings match to that point
 * @warning Does not handle multiple wildcards or complex glob patterns
 * 
 * @see wildcard_match() for unbounded wildcard matching
 * 
 * EXAMPLE USAGE:
 * @code
 * // Match "example.com" against "exa*" checking first 5 characters
 * int result = wildcard_matchn("exa*", "example.com", 5);  // Returns 1 (wildcard match)
 * // Exact match within limit
 * int result2 = wildcard_matchn("exam", "example", 4);  // Returns 1 (exact match for 4 chars)
 * // Mismatch within limit
 * int result3 = wildcard_matchn("test", "example", 4);  // Returns 0 (no match)
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (utility function for internal pattern matching)
 * SIDE EFFECTS: None (read-only string comparison)
 * THREAD SAFETY: Thread-safe (no shared state modification)
 */
/* The same but comparing a maximum of NUM characters, like strncmp.  */
int wildcard_matchn(const char* wildcard, const char* match, int num)
{
  while (*wildcard && *match && num)
    {
      if (*wildcard == '*')
        return 1;

      if (*wildcard != *match)
        return 0; 

      ++wildcard;
      ++match;
      --num;
    }

  return (!num) || (*wildcard == *match);
}

/**
 * @brief Get Linux kernel version as an integer (Linux-specific)
 * 
 * @detailed Retrieves the running Linux kernel version and converts it to a compact
 *           integer representation for version comparison. The kernel version string
 *           (e.g., "5.15.0") is parsed into major, minor, and patch components, then
 *           encoded as: (major * 256 * 256) + (minor * 256) + patch. This encoding
 *           allows simple integer comparisons for kernel version checks needed for
 *           platform-specific feature detection (e.g., netlink capabilities, eBPF
 *           support). Only available on Linux platforms (HAVE_LINUX_NETWORK).
 * 
 * @return Encoded kernel version as integer (major * 65536 + minor * 256 + patch)
 * @retval positive_integer Kernel version successfully retrieved and encoded
 * 
 * @note Linux-specific function, only compiled when HAVE_LINUX_NETWORK defined
 * @note Uses uname() system call to retrieve kernel release string
 * @note Version encoding: major << 16 | minor << 8 | patch for easy comparison
 * @warning Calls die() and terminates process if uname() fails (should never fail)
 * @warning Uses strtok() which modifies input string (not thread-safe)
 * 
 * @see uname(2) - Linux system call for kernel information
 * 
 * EXAMPLE USAGE:
 * @code
 * #ifdef HAVE_LINUX_NETWORK
 * // Check if kernel is at least version 3.15.0
 * int kver = kernel_version();
 * if (kver >= (3 * 65536 + 15 * 256 + 0)) {
 *   // Use feature available in kernel 3.15+
 *   enable_netlink_feature();
 * }
 * // For kernel 5.15.0: returns 5 * 65536 + 15 * 256 + 0 = 331520
 * #endif
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (platform-specific utility function)
 * SIDE EFFECTS: Terminates process via die() if uname() system call fails
 * THREAD SAFETY: NOT thread-safe (uses strtok() which has internal state)
 */
#ifdef HAVE_LINUX_NETWORK
int kernel_version(void)
{
  struct utsname utsname;
  int version;
  char *split;
  
  if (uname(&utsname) < 0)
    die(_("failed to find kernel version: %s"), NULL, EC_MISC);
  
  split = strtok(utsname.release, ".");
  version = (split ? atoi(split) : 0);
  split = strtok(NULL, ".");
  version = version * 256 + (split ? atoi(split) : 0);
  split = strtok(NULL, ".");
  return version * 256 + (split ? atoi(split) : 0);
}
#endif

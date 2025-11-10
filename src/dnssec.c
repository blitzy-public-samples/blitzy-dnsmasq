/* dnssec.c is Copyright (c) 2012 Giovanni Bajo <rasky@develer.com>
           and Copyright (c) 2012-2025 Simon Kelley

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
 * @file dnssec.c
 * @brief DNSSEC validation implementation providing cryptographic verification of DNS responses
 * 
 * DETAILED PURPOSE:
 * This module implements complete DNSSEC validation chain processing per RFC 4033/4034/4035,
 * protecting against DNS cache poisoning, man-in-the-middle attacks, and domain hijacking through
 * cryptographic signature verification. The implementation validates the entire trust chain from
 * target domain to root zone trust anchors, verifying RRSIG signatures, validating DNSKEY records
 * against DS records in parent zones, processing NSEC/NSEC3 denial-of-existence proofs, and
 * enforcing resource limits to prevent denial-of-service attacks during validation.
 * 
 * KEY RESPONSIBILITIES:
 * - Complete DNSSEC validation chain processing via dnssec_validate_reply() (line 1967)
 * - RRSIG signature verification for RRsets via validate_rrset() (line 457)
 * - DNSKEY validation against DS records via dnssec_validate_by_ds() (line 717)
 * - Trust chain traversal from target domain to root zone trust anchors
 * - NSEC proof validation via prove_non_existence_nsec() (line 1243)
 * - NSEC3 proof validation with iteration limits via prove_non_existence_nsec3() (line 1547)
 * - Resource limit enforcement preventing validation DoS attacks
 * - Timestamp-based validation for systems with unreliable clocks via setup_timestamp() (line 68)
 * 
 * DEPENDENCIES:
 * Includes: dnsmasq.h (core data structures including struct daemon, struct blockdata, struct frec)
 * Called by: forward.c (DNS query forwarding code triggers validation for DNSSEC-signed responses)
 * Calls: crypto.c (signature verification via verify_func pointer in nettle_hash structures)
 * Calls: blockdata.c (variable-length data storage for DNSSEC records)
 * Calls: rfc1035.c (DNS wire format parsing via extract_name, skip_questions, etc.)
 * 
 * DATA STRUCTURES:
 * - struct rdata_state: RRset iteration state for validation processing (line 146)
 * - struct blockdata: Variable-length storage for DNSSEC signatures and keys (dnsmasq.h:486)
 * - struct frec: Forward query record containing validation status (dnsmasq.h:794)
 * - Validation status constants: STAT_SECURE (757), STAT_INSECURE (758), STAT_BOGUS (759)
 * 
 * COMPILE-TIME OPTIONS:
 * HAVE_DNSSEC: Master compilation flag enabling entire DNSSEC subsystem (required)
 * DNSSEC_LIMIT_WORK: Maximum queries per validation (default 40, config.h:25)
 * DNSSEC_LIMIT_SIG_FAIL: Maximum signature failures tolerated (default 20, config.h:26)
 * DNSSEC_LIMIT_CRYPTO: Maximum crypto operations per query (default 200, config.h:27)
 * DNSSEC_LIMIT_NSEC3_ITERS: Maximum NSEC3 hash iterations (default 150, config.h:29)
 * 
 * THREADING/CONCURRENCY:
 * Single-threaded event-driven model. All validation occurs synchronously during query processing.
 * No locking required. Timestamp state stored in static variable timestamp_time (line 66).
 * Validation counters passed by reference through function call chain to track resource usage.
 * 
 * VALIDATION STATE MACHINE:
 * STAT_SECURE: All signatures valid, trust chain complete to root zone
 * STAT_INSECURE: Zone is not signed (no DS record in parent), validation not required
 * STAT_BOGUS: Signature verification failed, trust chain broken, or resource limits exceeded
 * 
 * RESOURCE LIMITS (DoS PROTECTION):
 * Validation work counter limits total queries to prevent CPU exhaustion
 * Signature failure counter limits crypto operations on invalid signatures
 * Crypto operation counter prevents excessive signature verification attempts
 * NSEC3 iteration limit prevents hash computation DoS attacks
 * 
 * @copyright Copyright (c) 2012 Giovanni Bajo, 2012-2025 Simon Kelley
 * @license GPL-2.0-or-later
 */

#include "dnsmasq.h"

#ifdef HAVE_DNSSEC

#define SERIAL_UNDEF  -100
#define SERIAL_EQ        0
#define SERIAL_LT       -1
#define SERIAL_GT        1

/**
 * @brief Count number of labels in a domain name
 * 
 * @detailed Counts the number of DNS labels in a domain name by counting dots plus one.
 *           Handles both absolute (ending with '.') and relative domain names correctly.
 *           An empty string returns 0 labels. A single dot returns 0 (empty root label).
 * 
 * @param name Domain name in presentation format (null-terminated string)
 * 
 * @return Number of labels in the domain name
 * @retval 0 Empty name or single dot (root label)
 * @retval >0 Number of labels found
 * 
 * @note Input name must be in presentation format (dotted notation), not wire format
 * @warning Does not validate label length or total name length constraints
 * 
 * EXAMPLE USAGE:
 * @code
 * int labels = count_labels("example.com");      // returns 2
 * int labels2 = count_labels("www.example.com"); // returns 3
 * int labels3 = count_labels(".");               // returns 0
 * @endcode
 * 
 * RFC COMPLIANCE: Label counting for DNSSEC validation per RFC 4034 Section 3.1.3
 * SIDE EFFECTS: None (read-only operation)
 * THREAD SAFETY: Thread-safe (no shared state)
 */
static int count_labels(char *name)
{
  int i;
  char *p;
  
  if (*name == 0)
    return 0;

  for (p = name, i = 0; *p; p++)
    if (*p == '.')
      i++;

  /* Don't count empty first label. */
  return *name == '.' ? i : i+1;
}

/**
 * @brief Compare two 32-bit serial numbers using RFC 1982 wrapped arithmetic
 * 
 * @detailed Implements RFC 1982 serial number arithmetic for comparing 32-bit values
 *           with wraparound. This is essential for comparing DNSSEC signature inception
 *           and expiration times which use 32-bit Unix timestamps that will eventually
 *           wrap. The comparison correctly handles the case where one value has wrapped
 *           and the other has not, within the valid comparison window.
 * 
 * @param s1 First serial number to compare
 * @param s2 Second serial number to compare
 * 
 * @return Comparison result
 * @retval SERIAL_EQ (0) Serial numbers are equal
 * @retval SERIAL_LT (-1) s1 is less than s2
 * @retval SERIAL_GT (1) s1 is greater than s2
 * @retval SERIAL_UNDEF (-100) Comparison undefined (numbers are exactly 2^31 apart)
 * 
 * @note Valid comparison window is 2^31 (half the 32-bit space)
 * @warning Returns SERIAL_UNDEF if values differ by exactly 2^31, an edge case
 * 
 * @see RFC 1982 Section 3.2 for serial number comparison algorithm
 * 
 * EXAMPLE USAGE:
 * @code
 * u32 inception = 0xFFFFFF00;  // Near wraparound
 * u32 expiration = 0x00000100; // After wraparound
 * int result = serial_compare_32(inception, expiration); // returns SERIAL_LT
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 1982 Section 3.2 (Serial Number Arithmetic)
 * SIDE EFFECTS: None (pure comparison function)
 * THREAD SAFETY: Thread-safe (no shared state)
 */
static int serial_compare_32(u32 s1, u32 s2)
{
  if (s1 == s2)
    return SERIAL_EQ;

  if ((s1 < s2 && (s2 - s1) < (1UL<<31)) ||
      (s1 > s2 && (s1 - s2) > (1UL<<31)))
    return SERIAL_LT;
  if ((s1 < s2 && (s2 - s1) > (1UL<<31)) ||
      (s1 > s2 && (s1 - s2) < (1UL<<31)))
    return SERIAL_GT;
  return SERIAL_UNDEF;
}

/**
 * @brief Initialize and verify DNSSEC timestamp file for time travel detection
 * 
 * @detailed Called at daemon startup to establish a reference timestamp for detecting
 *           system clock rollback attacks. If the timestamp file exists, loads its mtime.
 *           If the file doesn't exist, creates it with epoch 1420070400 (January 1, 2015).
 *           This mechanism detects if the system clock has been rolled back (time travel
 *           to the past) which could allow replay of expired DNSSEC signatures.
 * 
 * @return -1 if timestamp file creation failed (cannot write to filesystem)
 * @retval 0 if not using timestamp, timestamp exists and is in past (normal operation)
 * @retval 1 if timestamp exists and is in future (clock rollback detected)
 * 
 * @note Sets daemon->back_to_the_future = 1 when operating normally (time advancing forward)
 * @note Sets global timestamp_time variable to file mtime for subsequent comparisons
 * @warning Clock rollback detection only works if timestamp file persists across reboots
 * 
 * @see daemon->timestamp_file configuration option (--dnssec-timestamp)
 * @see is_check_date() which uses timestamp_time for signature validation timing
 * 
 * EXAMPLE USAGE:
 * @code
 * // During daemon initialization in main()
 * int status = setup_timestamp();
 * if (status == 1)
 *   my_syslog(LOG_WARNING, "Clock rollback detected, deferring DNSSEC validation");
 * else if (status == -1)
 *   die("Cannot create timestamp file", NULL, EC_MISC);
 * @endcode
 * 
 * RFC COMPLIANCE: Addresses DNSSEC operational security per RFC 4033 Section 9
 * SIDE EFFECTS: Creates timestamp file on filesystem, sets daemon->back_to_the_future flag
 * THREAD SAFETY: Single-threaded, called only during daemon initialization
 */

static time_t timestamp_time;

int setup_timestamp(void)
{
  struct stat statbuf;
  
  daemon->back_to_the_future = 0;
  
  if (!daemon->timestamp_file)
    return 0;
  
  if (stat(daemon->timestamp_file, &statbuf) != -1)
    {
      timestamp_time = statbuf.st_mtime;
    check_and_exit:
      if (difftime(timestamp_time, time(0)) <=  0)
	{
	  /* time already OK, update timestamp, and do key checking from the start. */
	  if (utimes(daemon->timestamp_file, NULL) == -1)
	    my_syslog(LOG_ERR, _("failed to update mtime on %s: %s"), daemon->timestamp_file, strerror(errno));
	  daemon->back_to_the_future = 1;
	  return 0;
	}
      return 1;
    }
  
  if (errno == ENOENT)
    {
      /* NB. for explanation of O_EXCL flag, see comment on pidfile in dnsmasq.c */ 
      int fd = open(daemon->timestamp_file, O_WRONLY | O_CREAT | O_NONBLOCK | O_EXCL, 0666);
      if (fd != -1)
	{
	  struct timeval tv[2];

	  close(fd);
	  
	  timestamp_time = 1420070400; /* 1-1-2015 */
	  tv[0].tv_sec = tv[1].tv_sec = timestamp_time;
	  tv[0].tv_usec = tv[1].tv_usec = 0;
	  if (utimes(daemon->timestamp_file, tv) == 0)
	    goto check_and_exit;
	}
    }

  return -1;
}

/* Check whether today/now is between date_start and date_end */
/**
 * @brief Determine whether to check DNSSEC signature timestamp validity based on system clock reliability
 * 
 * @detailed
 * Implements timestamp checking policy for systems with unreliable real-time clocks (embedded devices,
 * systems without battery-backed RTC). When daemon->timestamp_file is configured, assumes system time
 * is unreliable until current time exceeds timestamp file mtime. This prevents DNSSEC validation
 * failures on systems that boot with incorrect time (e.g., 1970-01-01) until NTP synchronization
 * completes. Once system time advances beyond timestamp file mtime, enables signature timestamp
 * checking, updates timestamp file to current time, triggers cache purge via EVENT_RELOAD to remove
 * potentially invalid cached data, and sets daemon->back_to_the_future flag permanently for session.
 * 
 * Algorithm:
 * 1. If timestamp_file configured and back_to_the_future not yet set:
 *    a. Compare timestamp_time (from file mtime) with curtime
 *    b. If curtime >= timestamp_time: system clock now reliable
 *       - Update timestamp file mtime to current time
 *       - Set back_to_the_future=1, dnssec_no_time_check=0
 *       - Queue cache reload event to purge unvalidated entries
 *       - Log transition to timestamp checking mode
 * 2. Return back_to_the_future if timestamp_file configured
 * 3. Return inverse of dnssec_no_time_check if no timestamp_file
 * 
 * @param curtime Current time in seconds since epoch (from time(0) or cached query time)
 * 
 * @return Boolean indicating whether signature timestamp checking should be performed
 * @retval 1 (true) System clock reliable, check RRSIG inception/expiration times
 * @retval 0 (false) System clock unreliable, skip timestamp validation (accept all times)
 * 
 * @note Timestamp file mtime initialized by setup_timestamp() to 2015-01-01 if created new
 * @note Once back_to_the_future transitions to 1, it remains set for daemon lifetime
 * @note Cache purge EVENT_RELOAD triggered on transition ensures no stale pre-validation data
 * @warning utimes() failure logged but not fatal; timestamp checking still enabled
 * 
 * @see setup_timestamp() for timestamp file initialization (line 68)
 * @see validate_rrset() which calls this function before checking signature validity
 * @see queue_event() for cache reload triggering (dnsmasq.c event queue)
 * 
 * EXAMPLE USAGE:
 * @code
 * time_t now = time(0);
 * if (is_check_date(now)) {
 *   // Check RRSIG inception <= now <= expiration
 *   if (serial_compare_32(sig_inception, now) != SERIAL_GT &&
 *       serial_compare_32(sig_expiration, now) != SERIAL_LT) {
 *     // Signature time valid, proceed with crypto verification
 *   }
 * } else {
 *   // Skip timestamp validation, system clock unreliable
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 4035 Section 5.3.1 (signature validity period checking)
 * SIDE EFFECTS: Updates timestamp file mtime via utimes(), sets back_to_the_future and dnssec_no_time_check, triggers EVENT_RELOAD
 * THREAD SAFETY: Single-threaded, modifies daemon global state (not thread-safe)
 */
static int is_check_date(unsigned long curtime)
{
  /* Checking timestamps may be temporarily disabled */
    
  /* If the current time if _before_ the timestamp
     on our persistent timestamp file, then assume the
     time if not yet correct, and don't check the
     key timestamps. As soon as the current time is
     later then the timestamp, update the timestamp
     and start checking keys */
  if (daemon->timestamp_file)
    {
      if (daemon->back_to_the_future == 0 && difftime(timestamp_time, curtime) <= 0)
	{
	  if (utimes(daemon->timestamp_file, NULL) != 0)
	    my_syslog(LOG_ERR, _("failed to update mtime on %s: %s"), daemon->timestamp_file, strerror(errno));
	  
	  my_syslog(LOG_INFO, _("system time considered valid, now checking DNSSEC signature timestamps."));
	  daemon->back_to_the_future = 1;
	  daemon->dnssec_no_time_check = 0;
	  queue_event(EVENT_RELOAD); /* purge cache */
	} 

      return daemon->back_to_the_future;
    }
  else
    return !daemon->dnssec_no_time_check;
}

/* Return bytes of canonicalised rrdata one by one.
   Init state->ip with the RR, and state->end with the end of same.
   Init state->op to NULL.
   Init state->desc to RR descriptor.
   Init state->buff with a MAXDNAME * 2 buffer.
   
   After each call which returns 1, state->op points to the next byte of data.
   On returning 0, the end has been reached.
*/

/**
 * @struct rdata_state
 * @brief Iterator state structure for traversing canonicalized RDATA byte-by-byte
 * 
 * Maintains iteration state across multiple get_rdata() calls to return canonical RDATA
 * one byte at a time. Used by sort_rrset() for RRset comparison per RFC 4034 Section 6.3
 * canonical ordering and by hash functions during signature verification. The descriptor
 * array defines RDATA structure: 0=domain name (canonicalize), positive=raw bytes, -1=rest.
 * 
 * LIFECYCLE:
 * Creation: Allocated on stack by caller (sort_rrset, validate_rrset)
 * Initialization: desc set to RR type descriptor, buff to MAXDNAME*2 buffer, ip/end to RDATA bounds
 * Destruction: Automatic stack deallocation, buff freed by caller
 * Ownership: Caller owns state structure and all referenced buffers
 * 
 * USAGE PATTERNS:
 * Initialize once per RR, call get_rdata() repeatedly until returns 0, check state->op for each byte
 */
struct rdata_state {
  short *desc;         /**< RR descriptor array defining RDATA structure (0=name, N=bytes, -1=end) */
  size_t c;            /**< Bytes remaining in current segment */
  unsigned char *end;  /**< End of RDATA in wire format packet */
  unsigned char *ip;   /**< Current input position in wire format RDATA */
  unsigned char *op;   /**< Output pointer to current canonical byte */
  char *buff;          /**< Working buffer for canonicalized domain names (MAXDNAME*2 size) */
};

/**
 * @brief Return next byte of canonicalized RDATA for RRset comparison and hashing
 * 
 * @detailed
 * Iterator function implementing RFC 4034 Section 6.2 canonical RDATA format for DNSSEC
 * signature computation and RRset sorting. Processes RDATA according to type-specific
 * descriptor array that defines structure (domain names vs raw bytes). Canonicalizes
 * domain names by converting from compressed wire format to uncompressed lowercase wire
 * format via extract_name() + to_wire(). Returns RDATA bytes sequentially, one per call,
 * with state->op pointing to current byte. Returns 0 when all bytes consumed.
 * 
 * Algorithm for each call:
 * 1. If bytes remaining in current segment (state->c > 0): return next byte, decrement counter
 * 2. Otherwise, consult next descriptor entry:
 *    a. descriptor == -1: rest of RDATA to end (for types like TXT with variable data)
 *    b. descriptor == 0: domain name field, extract and canonicalize via to_wire()
 *    c. descriptor == N: N bytes of raw data, return as-is
 * 3. Set state->op to point to next output byte, state->c to bytes available
 * 4. Return 1 if byte available, 0 if RDATA exhausted
 * 
 * Descriptor array format per RR type (from rrfilter.c RR_DESC arrays):
 * - A record: {4, -1} = 4 bytes IPv4 address, rest unused
 * - AAAA: {16, -1} = 16 bytes IPv6 address, rest unused
 * - NS/CNAME/PTR: {0, -1} = domain name (canonicalize), rest unused
 * - MX: {2, 0, -1} = 2 bytes preference, domain name, rest unused
 * - SRV: {2, 2, 2, 0, -1} = priority, weight, port (6 bytes), domain name, rest
 * - TXT: {-1} = all bytes to end (no canonicalization, variable length data)
 * 
 * @param header DNS packet header for extract_name() name compression resolution
 * @param plen Packet length for bounds checking during name extraction
 * @param state Iterator state tracking position in RDATA and descriptor array (modified)
 * 
 * @return Status code indicating byte availability
 * @retval 1 Byte available at state->op, caller should process and call again
 * @retval 0 End of RDATA reached, iteration complete
 * 
 * @note State must be initialized: desc=RR descriptor, ip=RDATA start, end=RDATA end, buff=MAXDNAME*2
 * @note Domain name extraction failure (malformed packet) causes function to skip to next descriptor
 * @note Caller must not modify state structure between calls (except reading state->op)
 * @warning Assumes state->buff has sufficient space (MAXDNAME*2 bytes) for canonicalized names
 * @warning Does not validate RDATA bounds; caller must ensure ip/end point to valid packet regions
 * 
 * @see sort_rrset() for primary usage iterating over RRset for canonical comparison (line 222)
 * @see extract_name() in rfc1035.c for wire format name extraction with compression handling
 * @see to_wire() in rfc1035.c for domain name canonicalization (lowercase, uncompressed)
 * @see RFC 4034 Section 6.2 for canonical RDATA format specification
 * 
 * EXAMPLE USAGE:
 * @code
 * struct rdata_state state;
 * char buff[MAXDNAME * 2];
 * state.desc = &rr_descriptor_for_A; // {4, -1} for A records
 * state.ip = rdata_start;
 * state.end = rdata_start + rdlen;
 * state.buff = buff;
 * state.c = 0;
 * 
 * while (get_rdata(header, plen, &state)) {
 *   unsigned char byte = *state.op; // Get canonical RDATA byte
 *   // Process byte for hashing or comparison
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 4034 Section 6.2 (canonical RDATA format for signature computation)
 * SIDE EFFECTS: Modifies state->desc, state->c, state->ip, state->op during iteration
 * THREAD SAFETY: Single-threaded, state structure must not be shared across threads
 */
static int get_rdata(struct dns_header *header, size_t plen, struct rdata_state *state)
{
  int d;
  
  if (state->op && state->c != 1)
    {
      state->op++;
      state->c--;
      return 1;
    }

  while (1)
    {
      d = *(state->desc);
      
      if (d == -1)
	{
	  /* all the bytes to the end. */
	  if ((state->c = state->end - state->ip) != 0)
	    {
	      state->op = state->ip;
	      state->ip = state->end;;
	    }
	  else
	    return 0;
	}
      else
	{
	  state->desc++;
	  
	  if (d == (u16)0)
	    {
	      /* domain-name, canonicalise */
	      int len;
	      
	      if (!extract_name(header, plen, &state->ip, state->buff, EXTR_NAME_EXTRACT, 0) ||
		  (len = to_wire(state->buff)) == 0)
		continue;
	      
	      state->c = len;
	      state->op = (unsigned char *)state->buff;
	    }
	  else
	    {
	      /* plain data preceding a domain-name, don't run off the end of the data */
	      if ((state->end - state->ip) < d)
		d = state->end - state->ip;
	      
	      if (d == 0)
		continue;
		  
	      state->op = state->ip;
	      state->c = d;
	      state->ip += d;
	    }
	}
      
      return 1;
    }
}

/**
 * @brief Sort RRset into canonical order per RFC 4034 Section 6.3 and remove duplicate RRs
 * 
 * @detailed
 * Implements RFC 4034 Section 6.3 canonical ordering of RRset members for DNSSEC signature
 * verification. Uses bubble sort algorithm to arrange RRs in ascending byte-wise order of
 * their canonical RDATA representation. For RR types with no domain names in RDATA (TXT,
 * A, AAAA, etc.), performs direct memcmp of wire format data. For RR types containing
 * domain names (NS, MX, SRV, etc.), uses get_rdata() to iterate byte-by-byte through
 * canonicalized RDATA (domain names converted to lowercase uncompressed wire format).
 * Removes exact duplicates per RFC 4034 Section 6.3 requirement that duplicate RRs be
 * removed before signature verification. Returns updated rrsetidx which may be reduced
 * if duplicates were removed.
 * 
 * Algorithm:
 * 1. Outer loop continues while swaps occur (bubble sort termination)
 * 2. Inner loop compares adjacent RRs (i and i+1):
 *    a. Skip name, class, type, TTL to reach RDATA
 *    b. If RR descriptor[0] == -1 (no names in RDATA):
 *       - Compare RDATA via memcmp (byte-wise comparison)
 *       - Swap if rrset[i] > rrset[i+1] or rrset[i] == rrset[i+1] but longer
 *       - Remove rrset[i] if exact duplicate (same length, same bytes)
 *    c. If RR descriptor contains domain names:
 *       - Initialize two rdata_state structures for byte-by-byte iteration
 *       - Call get_rdata() repeatedly to compare canonical bytes
 *       - Swap if rrset[i] > rrset[i+1] byte-wise
 *       - Remove rrset[i] if exact duplicate (all bytes equal)
 * 3. After each swap or removal, continue outer loop
 * 4. Return final rrsetidx (original value minus number of duplicates removed)
 * 
 * Comparison semantics per RFC 4034 Section 6.3:
 * - RRs compared byte-by-byte in canonical RDATA form
 * - Domain names canonicalized: lowercase, uncompressed wire format
 * - Shorter RR < longer RR if shorter RR is prefix of longer
 * - Duplicate RRs (exactly equal) removed before signature verification
 * - Final order is deterministic and matches what signer computed
 * 
 * @param header DNS packet header containing RRset (for name extraction)
 * @param plen Packet length for bounds checking during name skipping
 * @param rr_desc RR descriptor array defining RDATA structure (0=name, N=bytes, -1=rest)
 * @param rrsetidx Number of RR pointers in rrset array (modified if duplicates removed)
 * @param rrset Array of pointers to RR start positions in packet (modified: sorted, duplicates removed)
 * @param buff1 Working buffer for canonical name conversion (MAXDNAME*2 size, for state1)
 * @param buff2 Working buffer for canonical name conversion (MAXDNAME*2 size, for state2)
 * 
 * @return Updated rrsetidx after duplicate removal
 * @retval rrsetidx Original value if no duplicates found
 * @retval <rrsetidx Reduced value if duplicates removed (each duplicate reduces by 1)
 * 
 * @note Bubble sort used (O(n^2)) acceptable because typical RRsets contain 1-10 records
 * @note Short packet detected if RDATA length check fails; returns rrsetidx unchanged
 * @note Duplicate removal shifts remaining RRs down in array; no gaps left
 * @note Requires two separate buffers (buff1, buff2) for concurrent canonicalization comparison
 * @warning rrset array modified in place; caller must not rely on original ordering
 * @warning Assumes rrset pointers valid and point to well-formed RRs (pre-validated by explore_rrset)
 * 
 * @see get_rdata() for byte-by-byte canonical RDATA iteration (line 146)
 * @see validate_rrset() which calls this function before hashing RRset for signature (line 457)
 * @see RFC 4034 Section 6.3 for canonical ordering specification and duplicate removal requirement
 * 
 * EXAMPLE USAGE:
 * @code
 * unsigned char *rrset[10]; // Pointers to RRs in packet
 * char buff1[MAXDNAME * 2], buff2[MAXDNAME * 2];
 * short a_descriptor[] = {4, -1}; // A record: 4 bytes IPv4, rest unused
 * int count = 5; // 5 A records initially
 * 
 * // Sort and remove duplicates
 * count = sort_rrset(header, plen, a_descriptor, count, rrset, buff1, buff2);
 * // count may now be < 5 if duplicates were removed
 * // rrset[0..count-1] now in canonical order
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 4034 Section 6.3 (canonical RR ordering and duplicate removal)
 * SIDE EFFECTS: Modifies rrset array in place (reorders and removes duplicates)
 * THREAD SAFETY: Single-threaded, uses stack buffers (thread-safe if buffers not shared)
 */
static int sort_rrset(struct dns_header *header, size_t plen, short *rr_desc, int rrsetidx, 
		      unsigned char **rrset, char *buff1, char *buff2)
{
  int swap, i, j;
  
  do
    {
      for (swap = 0, i = 0; i < rrsetidx-1; i++)
	{
	  int rdlen1, rdlen2;
	  struct rdata_state state1, state2;
	  
	  /* Note that these have been determined to be OK previously,
	     so we don't need to check for NULL return here. */
	  state1.ip = skip_name(rrset[i], header, plen, 10);
	  state2.ip = skip_name(rrset[i+1], header, plen, 10);
	  state1.op = state2.op = NULL;
	  state1.buff = buff1;
	  state2.buff = buff2;
	  state1.desc = state2.desc = rr_desc;
	  
	  state1.ip += 8; /* skip class, type, ttl */
	  GETSHORT(rdlen1, state1.ip);
	  if (!CHECK_LEN(header, state1.ip, plen, rdlen1))
	    return rrsetidx; /* short packet */
	  state1.end = state1.ip + rdlen1;
	  
	  state2.ip += 8; /* skip class, type, ttl */
	  GETSHORT(rdlen2, state2.ip);
	  if (!CHECK_LEN(header, state2.ip, plen, rdlen2))
	    return rrsetidx; /* short packet */
	  state2.end = state2.ip + rdlen2; 

	  /* If the RR has no names in it then canonicalisation
	     is the identity function and we can compare
	     the RRs directly. If not we compare the 
	     canonicalised RRs one byte at a time. */
	  if (*rr_desc == -1)	  
	    {
	      int rdmin = rdlen1 > rdlen2 ? rdlen2 : rdlen1;
	      int cmp = memcmp(state1.ip, state2.ip, rdmin);
	      
	      if (cmp > 0 || (cmp == 0 && rdlen1 > rdmin))
		{
		  unsigned char *tmp = rrset[i+1];
		  rrset[i+1] = rrset[i];
		  rrset[i] = tmp;
		  swap = 1;
		}
	      else if (cmp == 0 && (rdlen1 == rdlen2))
		{
		  /* Two RRs are equal, remove one copy. RFC 4034, para 6.3 */
		  for (j = i+1; j < rrsetidx-1; j++)
		    rrset[j] = rrset[j+1];
		  rrsetidx--;
		  i--;
		}
	    }
	  else
	    /* Comparing canonicalised RRs, byte-at-a-time. */
	    while (1)
	      {
		int ok1, ok2;
		
		ok1 = get_rdata(header, plen, &state1);
		ok2 = get_rdata(header, plen, &state2);
		
		if (!ok1 && !ok2)
		  {
		    /* Two RRs are equal, remove one copy. RFC 4034, para 6.3 */
		    for (j = i+1; j < rrsetidx-1; j++)
		      rrset[j] = rrset[j+1];
		    rrsetidx--;
		    i--;
		    break;
		  }
		else if (ok1 && (!ok2 || *state1.op > *state2.op)) 
		  {
		    unsigned char *tmp = rrset[i+1];
		    rrset[i+1] = rrset[i];
		    rrset[i] = tmp;
		    swap = 1;
		    break;
		  }
		else if (ok2 && (!ok1 || *state2.op > *state1.op))
		  break;
		
		/* arrive here when bytes are equal, go round the loop again
		   and compare the next ones. */
	      }
	}
    } while (swap);

  return rrsetidx;
}

static unsigned char **rrset = NULL, **sigs = NULL;

/* Get pointers to RRset members and signature(s) for same.
   Check signatures, and return keyname associated in keyname. */
/**
 * @brief Explore DNS packet to collect RRset members and their RRSIG signatures
 * 
 * @detailed
 * Scans DNS packet answer and authority sections to find all Resource Records matching
 * specified name, class, and type (forming an RRset), plus all RRSIG records that sign
 * this RRset (where RRSIG type_covered field matches the target type). Populates module-
 * level static arrays rrset[] and sigs[] with pointers to RR start positions in packet.
 * Extracts signer's name from RRSIG records and validates RFC 4035 5.3.1 security
 * requirement that signer's name must equal or enclose the RRset name (preventing
 * cross-zone signature attacks where attacker uses signatures from unrelated zones).
 * 
 * Uses static storage arrays (rrset, sigs) that persist across calls and expand
 * dynamically via expand_workspace() as needed. These arrays are shared module state
 * accessed by validate_rrset() for signature verification.
 * 
 * Algorithm:
 * 1. Skip question section using skip_questions() to reach answer section
 * 2. Iterate through all RRs in answer + authority sections (ancount + nscount)
 * 3. For each RR:
 *    a. Extract name and compare to target name (EXTR_NAME_COMPARE)
 *    b. Extract type and class fields
 *    c. If name matches AND class matches:
 *       - If type matches target type: add RR pointer to rrset[] array
 *       - If type is T_RRSIG:
 *         * Verify rdlen >= 18 bytes (minimum RRSIG size)
 *         * Extract type_covered field (first 2 bytes of RDATA)
 *         * Skip algorithm, labels, orig_ttl, sig_expiration, sig_inception, key_tag (16 bytes)
 *         * Extract signer's name into keyname buffer
 *         * If this is first RRSIG (gotkey==0):
 *           - Extract signer's name (EXTR_NAME_EXTRACT mode)
 *           - Validate signer's name security constraint (RFC 4035 5.3.1):
 *             RRset name must equal or be subdomain of signer's name
 *             Walk up RRset name labels until match found or fail
 *             Root key (empty name) always allowed
 *         * If subsequent RRSIG (gotkey==1):
 *           - Compare signer's name to first RRSIG (EXTR_NAME_COMPARE mode)
 *           - All RRSIGs for RRset must have same signer's name
 *         * If type_covered matches target type: add RRSIG pointer to sigs[] array
 * 4. Return success with counts via sigcnt and rrcnt output parameters
 * 
 * Security Check (lines 387-401):
 * RFC 4035 Section 5.3.1 requires signer's name field to equal the zone containing
 * the RRset. Strict equality cannot be verified without zone boundary knowledge, so
 * implementation checks that RRset name is equal to or a subdomain of signer's name.
 * This prevents attacker from using signatures from unrelated zones they control.
 * Example: RRset "www.example.com" can be signed by "example.com" or "com" or root,
 * but NOT by "attacker.com". Implementation walks up RRset name labels (chop at dots)
 * until hostname_isequal() succeeds or name exhausted.
 * 
 * @param header DNS packet header for name extraction and section traversal
 * @param plen Packet length for bounds checking (CHECK_LEN, ADD_RDLEN macros)
 * @param class DNS class to match (typically IN=1 for Internet class)
 * @param type RR type to collect (e.g., T_A=1, T_AAAA=28, T_DNSKEY=48)
 * @param name Domain name to match in presentation format (null-terminated string)
 * @param keyname Output buffer for signer's name extracted from RRSIG (MAXDNAME size)
 * @param sigcnt Output parameter returning number of matching RRSIG records found
 * @param rrcnt Output parameter returning number of RRs in RRset found
 * 
 * @return Success/failure indicator
 * @retval 1 Success - rrset and sigs arrays populated, counts returned via sigcnt/rrcnt
 * @retval 0 Failure - bad packet, out of memory, or security check failed
 * 
 * @note Uses module-level static arrays rrset[] and sigs[] shared with validate_rrset()
 * @note Static variables rrset_sz and sig_sz track allocated capacity for expand_workspace()
 * @note All RRSIGs for an RRset must have identical signer's name (RFC 4035 requirement)
 * @note Empty keyname (root zone) is always accepted as valid signer (lines 393)
 * @warning Modifies module static state (rrset, sigs arrays); not reentrant
 * @warning Returns 0 if signer's name check fails (lines 400); legitimate validation failure
 * 
 * @see validate_rrset() which calls this function to collect RRset and signatures (line 457)
 * @see expand_workspace() for dynamic array expansion (lines 360, 407)
 * @see extract_name() for name extraction modes EXTR_NAME_COMPARE and EXTR_NAME_EXTRACT
 * @see hostname_isequal() for case-insensitive name comparison (line 396)
 * @see RFC 4035 Section 5.3.1 for signer's name field requirements (lines 387-401)
 * 
 * EXAMPLE USAGE:
 * @code
 * char keyname[MAXDNAME];
 * int sigcnt, rrcnt;
 * 
 * // Explore packet for A records of "www.example.com"
 * if (explore_rrset(header, plen, C_IN, T_A, "www.example.com", keyname, &sigcnt, &rrcnt))
 * {
 *   // Success: rrset[0..rrcnt-1] points to A records
 *   //          sigs[0..sigcnt-1] points to RRSIG records
 *   //          keyname contains signer's name (e.g., "example.com")
 *   // Now call validate_rrset() to verify signatures
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 4035 Section 5.3.1 (signer's name validation, lines 387-401)
 * SIDE EFFECTS: Populates module-level static rrset[] and sigs[] arrays
 * THREAD SAFETY: Not thread-safe due to static array usage; single-threaded daemon only
 */
static int explore_rrset(struct dns_header *header, size_t plen, int class, int type, 
			 char *name, char *keyname, int *sigcnt, int *rrcnt)
{
  static int rrset_sz = 0, sig_sz = 0; 
  unsigned char *p;
  int rrsetidx, sigidx, j, rdlen, res;
  int gotkey = 0;

  if (!(p = skip_questions(header, plen)))
    return 0;

   /* look for RRSIGs for this RRset and get pointers to each RR in the set. */
  for (rrsetidx = 0, sigidx = 0, j = ntohs(header->ancount) + ntohs(header->nscount); 
       j != 0; j--) 
    {
      unsigned char *pstart, *pdata;
      int stype, sclass, type_covered;

      pstart = p;
      
      if (!(res = extract_name(header, plen, &p, name, EXTR_NAME_COMPARE, 10)))
	return 0; /* bad packet */
      
      GETSHORT(stype, p);
      GETSHORT(sclass, p);
           
      pdata = p;

      p += 4; /* TTL */
      GETSHORT(rdlen, p);
      
      if (!CHECK_LEN(header, p, plen, rdlen))
	return 0; 
      
      if (res == 1 && sclass == class)
	{
	  if (stype == type)
	    {
	      if (!expand_workspace(&rrset, &rrset_sz, rrsetidx))
		return 0; 
	      
	      rrset[rrsetidx++] = pstart;
	    }
	  
	  if (stype == T_RRSIG)
	    {
	      if (rdlen < 18)
		return 0; /* bad packet */ 
	      
	      GETSHORT(type_covered, p);
	      p += 16; /* algo, labels, orig_ttl, sig_expiration, sig_inception, key_tag */
	      
	      if (gotkey)
		{
		  /* If there's more than one SIG, ensure they all have same keyname */
		  if (extract_name(header, plen, &p, keyname, EXTR_NAME_COMPARE, 0) != 1)
		    return 0;
		}
	      else
		{
		  gotkey = 1;
		  
		  if (!extract_name(header, plen, &p, keyname, EXTR_NAME_EXTRACT, 0))
		    return 0;
		  
		  /* RFC 4035 5.3.1 says that the Signer's Name field MUST equal
		     the name of the zone containing the RRset. We can't tell that
		     for certain, but we can check that  the RRset name is equal to
		     or encloses the signers name, which should be enough to stop 
		     an attacker using signatures made with the key of an unrelated 
		     zone he controls. Note that the root key is always allowed. */
		  if (*keyname != 0)
		    {
		      char *name_start;
		      for (name_start = name; !hostname_isequal(name_start, keyname); )
			if ((name_start = strchr(name_start, '.')))
			  name_start++; /* chop a label off and try again */
			else
			  return 0;
		    }
		}
		  
	      
	      if (type_covered == type)
		{
		  if (!expand_workspace(&sigs, &sig_sz, sigidx))
		    return 0; 
		  
		  sigs[sigidx++] = pdata;
		} 
	      
	      p = pdata + 6; /* restore for ADD_RDLEN */
	    }
	}
      
      if (!ADD_RDLEN(header, p, plen, rdlen))
	return 0;
    }
  
  *sigcnt = sigidx;
  *rrcnt = rrsetidx;

  return 1;
}

int dec_counter(int *counter, char *message)
{
  if ((*counter)-- == 0)
    {
      my_syslog(LOG_WARNING, "limit exceeded: %s", message ? message : _("per-query crypto work"));
      return 1;
    }

  return 0;
}

/* Validate a single RRset (class, type, name) in the supplied DNS reply 
   Return code:
   STAT_SECURE   if it validates.
   STAT_SECURE_WILDCARD if it validates and is the result of wildcard expansion.
   (In this case *wildcard_out points to the "body" of the wildcard within name.) 
   STAT_BOGUS    signature is wrong, bad packet.
   STAT_ABANDONED validation abandoned do to excess resource usage.
   STAT_NEED_KEY need DNSKEY to complete validation (name is returned in keyname)
   STAT_NEED_DS  need DS to complete validation (name is returned in keyname)

   If key is non-NULL, use that key, which has the algo and tag given in the params of those names,
   otherwise find the key in the cache.

   Name is unchanged on exit. keyname is used as workspace and trashed.

   Call explore_rrset first to find and count RRs and sigs.

   ttl_out is the floor on TTL, based on TTL and orig_ttl and expiration of sig used to validate.
*/
/**
 * @brief Validate RRset by verifying RRSIG signature using DNSKEY from cache or parameter
 * 
 * @detailed
 * Core DNSSEC validation function implementing RFC 4035 Section 5.3 signature verification
 * algorithm. Canonicalizes RRset per RFC 4034 Section 6, constructs signature input data
 * by hashing RRSIG RDATA and canonical RR wire format, retrieves DNSKEY from cache or uses
 * provided key, and verifies signature using cryptographic library (crypto.c). Handles
 * wildcard expansion per RFC 4035 Section 5.3.2, enforces signature validity period checking,
 * computes TTL per RFC 4035 Section 5.3.3 rules (minimum of original TTL and time until
 * expiration), and enforces signature failure counter to prevent DoS via invalid signatures.
 * 
 * The validation process follows these steps:
 * 1. Sort RRset into canonical order (sort_rrset)
 * 2. For each RRSIG in signature set:
 *    a. Check signature inception/expiration times if time checking enabled
 *    b. Verify hash algorithm is supported
 *    c. Retrieve DNSKEY from cache or use provided key
 *    d. Hash RRSIG RDATA (18 bytes: type_covered through signer_name)
 *    e. Hash signer name in wire format
 *    f. For each RR in canonical RRset:
 *       - Apply wildcard expansion if labels < name_labels
 *       - Hash owner name in wire format
 *       - Hash RR type, class, original TTL, RDATA length
 *       - Hash canonical RDATA per RFC 4034 Section 6.2
 *    g. Verify signature against computed hash using all matching DNSKEYs
 *    h. Return STAT_SECURE if signature valid
 * 3. Return STAT_BOGUS if no valid signature found after trying all RRSIGs
 * 
 * @param now Current time for cache lookups (time_t from forward.c query processing)
 * @param header DNS packet header containing RRset and RRSIG records
 * @param plen Packet length for bounds checking during name extraction
 * @param class DNS class (typically CLASS_IN=1) for RRset validation
 * @param type DNS record type (A, AAAA, etc.) being validated
 * @param sigidx Number of RRSIG records in sigs array (from explore_rrset)
 * @param rrsetidx Number of RRs in rrset array (from explore_rrset)
 * @param name Owner name of RRset in presentation format (e.g., "www.example.com")
 * @param keyname Buffer for extracting signer name from RRSIG (MAXDNAME size)
 * @param wildcard_out Output parameter: Set to wildcard label if wildcard expansion occurred, NULL otherwise
 * @param key Provided DNSKEY data (blockdata format) or NULL to retrieve from cache
 * @param keylen Length of provided key in bytes, or 0 if key is NULL
 * @param algo_in Algorithm number from DS record (for key matching), or 0 to try all keys
 * @param keytag_in Key tag from DS record (for key matching), or 0 to try all keys
 * @param ttl_out Output parameter: Computed TTL per RFC 4035 Section 5.3.3, or NULL if not needed
 * @param validate_counter Pointer to validation work counter (decremented via dec_counter)
 * 
 * @return Validation status code
 * @retval STAT_SECURE Signature verification succeeded, RRset is authentic
 * @retval STAT_BOGUS No valid signature found after trying all RRSIGs and DNSKEYs
 * @retval STAT_NEED_KEY Required DNSKEY not in cache, caller must issue DNSKEY query
 * 
 * @note Signature failure counter prevents DoS via repeated verification of invalid signatures
 * @note Wildcard expansion applies when RRSIG labels field < actual name label count
 * @note TTL computation per RFC 4035 5.3.3: min(orig_ttl, RR_ttl, time_until_expiration)
 * @note Time checking bypassed if system clock unreliable (is_check_date returns false)
 * @warning Signature verification is CPU-intensive; caller must enforce DNSSEC_LIMIT_CRYPTO
 * @warning Function modifies daemon->workspacename buffer during canonicalization
 * 
 * @see sort_rrset() for RRset canonical ordering implementation
 * @see hash_find() for algorithm-to-hash-function mapping (crypto.c integration)
 * @see cache_find_by_name() for DNSKEY retrieval from DNS cache
 * @see verify() in crypto.c for actual signature verification via Nettle library
 * 
 * EXAMPLE USAGE:
 * @code
 * char keyname[MAXDNAME];
 * char *wildcard = NULL;
 * unsigned long ttl;
 * int counter = daemon->limit[LIMIT_WORK];
 * int status = validate_rrset(now, header, plen, C_IN, T_A, 
 *                              sigidx, rrsetidx, "www.example.com", 
 *                              keyname, &wildcard, NULL, 0, 0, 0, &ttl, &counter);
 * if (status == STAT_SECURE) {
 *   // RRset cryptographically validated, safe to cache with computed TTL
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 4035 Section 5.3 (signature verification), RFC 4034 Section 6 (canonical form)
 * SIDE EFFECTS: Decrements signature failure counter via dec_counter on verification failures
 * THREAD SAFETY: Single-threaded, modifies daemon->workspacename buffer (not thread-safe)
 */
static int validate_rrset(time_t now, struct dns_header *header, size_t plen, int class, int type, int sigidx, int rrsetidx, 
			  char *name, char *keyname, char **wildcard_out, struct blockdata *key, int keylen,
			  int algo_in, int keytag_in, unsigned long *ttl_out, int *validate_counter)
{
  unsigned char *p;
  int rdlen, j, name_labels, algo, labels, key_tag, sig_fail_cnt;
  struct crec *crecp = NULL;
  short *rr_desc = rrfilter_desc(type);
  u32 sig_expiration, sig_inception;
  int failflags = DNSSEC_FAIL_NOSIG | DNSSEC_FAIL_NYV | DNSSEC_FAIL_EXP | DNSSEC_FAIL_NOKEYSUP;
  
  unsigned long curtime = time(0);
  int time_check = is_check_date(curtime);
  
  if (wildcard_out)
    *wildcard_out = NULL;
  
  name_labels = count_labels(name); /* For 4035 5.3.2 check */

  /* Sort RRset records into canonical order. 
     Note that at this point keyname and daemon->workspacename buffs are
     unused, and used as workspace by the sort. */
  rrsetidx = sort_rrset(header, plen, rr_desc, rrsetidx, rrset, daemon->workspacename, keyname);
         
  /* Now try all the sigs to try and find one which validates */
  for (sig_fail_cnt = daemon->limit[LIMIT_SIG_FAIL], j = 0; j <sigidx; j++)
    {
      unsigned char *psav, *sig, *digest;
      int i, wire_len, sig_len;
      const struct nettle_hash *hash;
      void *ctx;
      char *name_start;
      u32 nsigttl, ttl, orig_ttl;

      failflags &= ~DNSSEC_FAIL_NOSIG;
      
      p = sigs[j];
      GETLONG(ttl, p);
      GETSHORT(rdlen, p); /* rdlen >= 18 checked previously */
      psav = p;
      
      p += 2; /* type_covered - already checked */
      algo = *p++;
      labels = *p++;
      GETLONG(orig_ttl, p);
      GETLONG(sig_expiration, p);
      GETLONG(sig_inception, p);
      GETSHORT(key_tag, p);
      
      if (!extract_name(header, plen, &p, keyname, EXTR_NAME_EXTRACT, 0))
	return STAT_BOGUS;

      if (!time_check)
	failflags &= ~(DNSSEC_FAIL_NYV | DNSSEC_FAIL_EXP);
      else
	{
	  /* We must explicitly check against wanted values, because of SERIAL_UNDEF */
	  if (serial_compare_32(curtime, sig_inception) == SERIAL_LT)
	    continue;
	  else
	    failflags &= ~DNSSEC_FAIL_NYV;
	  
	  if (serial_compare_32(curtime, sig_expiration) == SERIAL_GT)
	    continue;
	  else
	    failflags &= ~DNSSEC_FAIL_EXP;
	}

      if (!(hash = hash_find(algo_digest_name(algo))))
	continue;
      else
	failflags &= ~DNSSEC_FAIL_NOKEYSUP;
      
      if (labels > name_labels ||
	  !hash_init(hash, &ctx, &digest))
	continue;
      
      /* OK, we have the signature record, see if the relevant DNSKEY is in the cache. */
      if (!key && !(crecp = cache_find_by_name(NULL, keyname, now, F_DNSKEY)))
	return STAT_NEED_KEY;

       if (ttl_out)
	 {
	   /* 4035 5.3.3 rules on TTLs */
	   if (orig_ttl < ttl)
	     ttl = orig_ttl;
	   
	   if (time_check && difftime(sig_expiration, curtime) < ttl)
	     ttl = difftime(sig_expiration, curtime);

	   *ttl_out = ttl;
	 }
       
      sig = p;
      sig_len = rdlen - (p - psav);
              
      nsigttl = htonl(orig_ttl);
      
      hash->update(ctx, 18, psav);
      wire_len = to_wire(keyname);
      hash->update(ctx, (unsigned int)wire_len, (unsigned char*)keyname);
      from_wire(keyname);

#define RRBUFLEN 128 /* Most RRs are smaller than this. */
      
      for (i = 0; i < rrsetidx; ++i)
	{
	  int j;
	  struct rdata_state state;
	  u16 len;
	  unsigned char rrbuf[RRBUFLEN];
	  
	  p = rrset[i];
	  
	  if (!extract_name(header, plen, &p, name, EXTR_NAME_EXTRACT, 10)) 
	    return STAT_BOGUS;

	  name_start = name;
	  
	  /* if more labels than in RRsig name, hash *.<no labels in rrsig labels field>  4035 5.3.2 */
	  if (labels < name_labels)
	    {
	      for (j = name_labels - labels; j != 0; j--)
		{
		  while (*name_start != '.' && *name_start != 0)
		    name_start++;
		  if (j != 1 && *name_start == '.')
		    name_start++;
		}
	      
	      if (wildcard_out)
		*wildcard_out = name_start+1;

	      name_start--;
	      *name_start = '*';
	    }
	  
	  wire_len = to_wire(name_start);
	  hash->update(ctx, (unsigned int)wire_len, (unsigned char *)name_start);
	  hash->update(ctx, 4, p); /* class and type */
	  hash->update(ctx, 4, (unsigned char *)&nsigttl);

	  p += 8; /* skip type, class, ttl */
	  GETSHORT(rdlen, p);
	  if (!CHECK_LEN(header, p, plen, rdlen))
	    return STAT_BOGUS; 

	  /* Optimisation for RR types which need no cannonicalisation.
	     This includes DNSKEY DS NSEC and NSEC3, which are also long, so
	     it saves lots of calls to get_rdata, and avoids the pessimal
	     segmented insertion, even with a small rrbuf[].
	     
	     If canonicalisation is not needed, a simple insertion into the hash works.
	  */
	  if (*rr_desc == -1)
	    {
	      len = htons(rdlen);
	      hash->update(ctx, 2, (unsigned char *)&len);
	      hash->update(ctx, rdlen, p);
	    }
	  else
	    {
	      /* canonicalise rdata and calculate length of same, use 
		 name buffer as workspace for get_rdata. */
	      state.ip = p;
	      state.op = NULL;
	      state.desc = rr_desc;
	      state.buff = name;
	      state.end = p + rdlen;
	      
	      for (j = 0; get_rdata(header, plen, &state); j++)
		if (j < RRBUFLEN)
		  rrbuf[j] = *state.op;
	      
	      len = htons((u16)j);
	      hash->update(ctx, 2, (unsigned char *)&len); 
	      
	      /* If the RR is shorter than RRBUFLEN (most of them, in practice)
		 then we can just digest it now. If it exceeds RRBUFLEN we have to
		 go back to the start and do it in chunks. */
	      if (j >= RRBUFLEN)
		{
		  state.ip = p;
		  state.op = NULL;
		  state.desc = rr_desc;
		  
		  for (j = 0; get_rdata(header, plen, &state); j++)
		    {
		      rrbuf[j] = *state.op;
		      
		      if (j == RRBUFLEN - 1)
			{
			  hash->update(ctx, RRBUFLEN, rrbuf);
			  j = -1;
			}
		    }
		}
	      
	      if (j != 0)
		hash->update(ctx, j, rrbuf);
	    }
	}
     
      hash->digest(ctx, hash->digest_size, digest);
      
      /* namebuff used for workspace above, restore to leave unchanged on exit */
      p = (unsigned char*)(rrset[0]);
      if (!extract_name(header, plen, &p, name, EXTR_NAME_EXTRACT, 0))
	return STAT_BOGUS;

      if (key)
	{
	  if (algo_in == algo && keytag_in == key_tag)
	    {
	      if (dec_counter(validate_counter, NULL))
		return STAT_ABANDONED;
	     	      
	      if (verify(key, keylen, sig, sig_len, digest, hash->digest_size, algo))
		return STAT_SECURE;
	    }
	}
      else
	{
	  /* iterate through all possible keys 4035 5.3.1 */
	  for (; crecp; crecp = cache_find_by_name(crecp, keyname, now, F_DNSKEY))
	    if (crecp->addr.key.algo == algo && 
		crecp->addr.key.keytag == key_tag &&
		crecp->uid == (unsigned int)class)
	      {
		if (dec_counter(validate_counter, NULL))
		  return STAT_ABANDONED;
		
		if (verify(crecp->addr.key.keydata, crecp->addr.key.keylen, sig, sig_len, digest, hash->digest_size, algo))
		  return (labels < name_labels) ? STAT_SECURE_WILDCARD : STAT_SECURE;
		
		/* An attacker can waste a lot of our CPU by setting up a giant DNSKEY RRSET full of failing
		   keys, all of which we have to try. Since many failing keys is not likely for
		   a legitimate domain, set a limit on how many can fail. */
		if ((daemon->limit[LIMIT_SIG_FAIL] - (sig_fail_cnt + 1)) > (int)daemon->metrics[METRIC_SIG_FAIL_HWM])
		  daemon->metrics[METRIC_SIG_FAIL_HWM] = daemon->limit[LIMIT_SIG_FAIL] - (sig_fail_cnt + 1);
		if (dec_counter(&sig_fail_cnt, _("per-RRSet signature fails")))
		  return STAT_ABANDONED;
	      }
	}
    }

  /* If we reach this point, no verifying key was found */
  return STAT_BOGUS | failflags | DNSSEC_FAIL_NOKEY;
}
 

/* The DNS packet is expected to contain the answer to a DNSKEY query.
   Put all DNSKEYs in the answer which are valid into the cache.
   return codes:
         STAT_OK        Done, key(s) in cache.
	 STAT_BOGUS     No DNSKEYs found, which  can be validated with DS,
	                or self-sign for DNSKEY RRset is not valid, bad packet.
	 STAT_ABANDONED resource exhaustion.
	 STAT_NEED_DS   DS records to validate a key not found, name in keyname 
*/
int dnssec_validate_by_ds(time_t now, struct dns_header *header, size_t plen, char *name,
			  char *keyname, int class, int *validate_counter)
{
  unsigned char *psave, *p = (unsigned char *)(header+1), *keyaddr;
  struct crec *crecp, *recp1;
  int rc, j, qtype, qclass, rdlen, flags, algo, keytag, sigcnt, rrcnt;
  unsigned long ttl, sig_ttl;
  union all_addr a;
  int failflags = DNSSEC_FAIL_NODSSUP | DNSSEC_FAIL_NOZONE;
  char valid_digest[255];
  static unsigned char **cached_digest;
  static size_t cached_digest_size = 0;

  if (ntohs(header->qdcount) != 1 || RCODE(header) != NOERROR || !extract_name(header, plen, &p, name, EXTR_NAME_EXTRACT, 4))
    return STAT_BOGUS | DNSSEC_FAIL_NOKEY;

  GETSHORT(qtype, p);
  GETSHORT(qclass, p);
  
  if (qtype != T_DNSKEY || qclass != class ||
      !explore_rrset(header, plen, class, T_DNSKEY, name, keyname, &sigcnt, &rrcnt) ||
      rrcnt == 0)
    return STAT_BOGUS | DNSSEC_FAIL_NOKEY;

  if (sigcnt == 0)
    return STAT_BOGUS | DNSSEC_FAIL_NOSIG;
  
  /* See if we have cached a DS record which validates this key */
  if (!(crecp = cache_find_by_name(NULL, name, now, F_DS)))
    {
      strcpy(keyname, name);
      return STAT_NEED_DS;
    }

  /* NOTE, we need to find ONE DNSKEY which matches the DS */
  for (j = ntohs(header->ancount); j != 0; j--) 
    {
      /* Ensure we have type, class  TTL and length */
      if (!(rc = extract_name(header, plen, &p, name, EXTR_NAME_COMPARE, 10)))
	return STAT_BOGUS; /* bad packet */
  
      GETSHORT(qtype, p); 
      GETSHORT(qclass, p);
      GETLONG(ttl, p);
      GETSHORT(rdlen, p);
 
      if (!CHECK_LEN(header, p, plen, rdlen))
	return STAT_BOGUS; /* bad packet */
      
      if (qclass != class || qtype != T_DNSKEY || rc == 2)
	{
	  p += rdlen;
	  continue;
	}

      if (rdlen < 5)
	return STAT_BOGUS;  /* min 1 byte key! */
                  
      psave = p;
      
      GETSHORT(flags, p);
      if (*p++ != 3)
	{
	  p = psave + rdlen;
	  continue;
	}
      algo = *p++;
      keyaddr = p;
      keytag = dnskey_keytag(algo, flags, keyaddr, rdlen - 4);	      
      
      p = psave + rdlen; 

       /* key must have zone key flag set */
      if (!(flags & 0x100))
	continue;
      
      failflags &= ~DNSSEC_FAIL_NOZONE;
      
      /* clear digest cache. */
      memset(valid_digest, 0, sizeof(valid_digest));
      
      for (recp1 = crecp; recp1; recp1 = cache_find_by_name(recp1, name, now, F_DS))
	{
	  void *ctx;
	  unsigned char *digest, *ds_digest;
	  const struct nettle_hash *hash;
	  int wire_len;
	  
	  if ((recp1->flags & F_NEG) ||
	      recp1->addr.ds.algo != algo ||
	      recp1->addr.ds.keytag != keytag ||
	      recp1->uid != (unsigned int)class)
	    continue;
	  
	  if (!(hash = hash_find(ds_digest_name(recp1->addr.ds.digest))))
	    continue;
	     
	  failflags &= ~DNSSEC_FAIL_NODSSUP;
	      
	  if (recp1->addr.ds.keylen != (int)hash->digest_size ||
	      !(ds_digest = blockdata_retrieve(recp1->addr.ds.keydata, recp1->addr.ds.keylen, NULL)))
	    continue;

	  if (valid_digest[recp1->addr.ds.digest])
	    digest = cached_digest[recp1->addr.ds.digest];
	  else
	    {
	      /* computing a hash is a unit of crypto work. */
	      if (dec_counter(validate_counter, NULL))
		return STAT_ABANDONED;
	      
	      if (!hash_init(hash, &ctx, &digest))
		continue;
	      
	      wire_len = to_wire(name);
	      
	      /* Note that digest may be different between DSs, so 
		 we can't move this outside the loop. We keep
		 copies of each digest we make for this key,
		 so maximum digest work is O(keys x digests_types)
		 rather then O(keys x DSs) */
	      hash->update(ctx, (unsigned int)wire_len, (unsigned char *)name);
	      hash->update(ctx, (unsigned int)rdlen, psave);
	      hash->digest(ctx, hash->digest_size, digest);
	      
	      from_wire(name);

	      if (recp1->addr.ds.digest >= cached_digest_size)
		{
		  unsigned char **new;
		
		  /* whine_malloc zeros memory */
		  if ((new = whine_malloc((recp1->addr.ds.digest + 5) * sizeof(unsigned char *))))
		    {
		      if (cached_digest_size != 0)
			{
			  memcpy(new, cached_digest, cached_digest_size * sizeof(unsigned char *));
			  free(cached_digest);
			}
		      
		      cached_digest_size = recp1->addr.ds.digest + 5;
		      cached_digest = new;
		    }
		}
		    
	      if (recp1->addr.ds.digest < cached_digest_size)
		{
		  if (!cached_digest[recp1->addr.ds.digest])
		    cached_digest[recp1->addr.ds.digest] = whine_malloc(recp1->addr.ds.keylen);
	      
		  if (cached_digest[recp1->addr.ds.digest])
		    {
		      memcpy(cached_digest[recp1->addr.ds.digest], digest, recp1->addr.ds.keylen);
		      valid_digest[recp1->addr.ds.digest] = 1;
		    }
		}
	    }
	  
	  if (memcmp(ds_digest, digest, recp1->addr.ds.keylen) == 0)
	    {
	      /* Found the key validated by a DS record.
		 Now check the self-sig for the entire key RRset using that key.
		 Note that validate_rrset() will never return STAT_NEED_KEY here,
		 since we supply the key it will use as an argument. */
	      struct blockdata *key;
	     	      
	      if (!(key = blockdata_alloc((char *)keyaddr, rdlen - 4)))
		break;
	      	      
	      rc = validate_rrset(now, header, plen, class, T_DNSKEY, sigcnt, rrcnt, name, keyname, 
				  NULL, key, rdlen - 4, algo, keytag, &sig_ttl, validate_counter);
	      
	      blockdata_free(key);
	      
	      if (STAT_ISEQUAL(rc, STAT_ABANDONED))
		return rc;
	      
	      /* can't validate KEY RRset with this key, see if there's another that
		 will, which is validated by another DS. */
	      if (!STAT_ISEQUAL(rc, STAT_SECURE))
		break;
	      
	      /* DNSKEY RRset determined to be OK, now cache it. */
	      cache_start_insert();
	      
	      p = skip_questions(header, plen);
	      
	      for (j = ntohs(header->ancount); j != 0; j--) 
		{
		  /* Ensure we have type, class  TTL and length */
		  if (!(rc = extract_name(header, plen, &p, name, EXTR_NAME_COMPARE, 10)))
		    return STAT_BOGUS; /* bad packet */
		  
		  GETSHORT(qtype, p); 
		  GETSHORT(qclass, p);
		  GETLONG(ttl, p);
		  GETSHORT(rdlen, p);
		  
		  /* TTL may be limited by sig. */
		  if (sig_ttl < ttl)
		    ttl = sig_ttl;
		  
		  if (!CHECK_LEN(header, p, plen, rdlen))
		    return STAT_BOGUS; /* bad packet */
		  
		   psave = p;

		   if (qclass == class && rc == 1 && qtype == T_DNSKEY)
		     {
		       if (rdlen < 4)
			 return STAT_BOGUS; /* min 1 byte key! */
		       
		       GETSHORT(flags, p);
		       if (*p++ == 3)
			 {
			   algo = *p++;
			   keytag = dnskey_keytag(algo, flags, p, rdlen - 4);
			   
			   if (!(key = blockdata_alloc((char*)p, rdlen - 4)))
			     return STAT_BOGUS;
			   
			   a.key.keylen = rdlen - 4;
			   a.key.keydata = key;
			   a.key.algo = algo;
			   a.key.keytag = keytag;
			   a.key.flags = flags;
			   
			   if (!cache_insert(name, &a, class, now, ttl, F_FORWARD | F_DNSKEY | F_DNSSECOK))
			     {
			       /* cache_insert fails when the cache is too small, so error with STAT_ABANDONED which
				  will log this as a resource exhaustion problem, which it is. */
			       blockdata_free(key);
			       return STAT_ABANDONED;
			     }
			   
			   a.log.keytag = keytag;
			   a.log.algo = algo;
			   if (algo_digest_name(algo))
			     log_query(F_NOEXTRA | F_KEYTAG | F_UPSTREAM, name, &a, "DNSKEY keytag %hu, algo %hu", 0);
			   else
			     log_query(F_NOEXTRA | F_KEYTAG | F_UPSTREAM, name, &a, "DNSKEY keytag %hu, algo %hu (not supported)", 0);
			 }
		     }
				  
		   p = psave + rdlen;
		}
	      
	      /* commit cache insert. */
	      cache_end_insert();
	      return STAT_OK;
	    }
	}
    }
  
  log_query(F_NOEXTRA | F_UPSTREAM, name, NULL, "BOGUS DNSKEY", 0);
  return STAT_BOGUS | failflags;
}

/* The DNS packet is expected to contain the answer to a DS query
   Put all DSs in the answer which are valid and have hash and signature algos
   we support into the cache.
   Also handles replies which prove that there's no DS at this location, 
   either because the zone is unsigned or this isn't a zone cut. These are
   cached too.
   If none of the DS's are for supported algos, treat the answer as if 
   it's a proof of no DS at this location. RFC4035 para 5.2.
   return codes:
   STAT_OK          At least one valid DS found and in cache.
   STAT_BOGUS       no DS in reply or not signed, fails validation, bad packet.
   STAT_NEED_KEY    DNSKEY records to validate a DS not found, name in keyname
   STAT_NEED_DS     DS record needed.
   STAT_ABANDONED   resource exhaustion.
*/

int dnssec_validate_ds(time_t now, struct dns_header *header, size_t plen, char *name,
		       char *keyname, int class, int *validate_counter)
{
  unsigned char *p = (unsigned char *)(header+1);
  int qtype, qclass, rc, i, neganswer = 0, nons = 0, servfail = 0, neg_ttl = 0, found_supported = 0;
  int aclass, atype, rdlen, flags;
  unsigned long ttl;
  union all_addr a;

   /* A SERVFAIL answer has been seen to a DS query not at start of authority,
     so treat it as such and continue to search for a DS or proof of no existence
     further down the tree. */
  if (RCODE(header) == SERVFAIL)
    servfail = neganswer = nons = 1;
  else
    rc = dnssec_validate_reply(now, header, plen, name, keyname, NULL, 0, &neganswer, &nons, &neg_ttl, validate_counter);
  
  p = (unsigned char *)(header+1);
  if (ntohs(header->qdcount) != 1 ||
      !extract_name(header, plen, &p, name, EXTR_NAME_EXTRACT, 4))
    return STAT_BOGUS;
  
  GETSHORT(qtype, p);
  GETSHORT(qclass, p);
  
  if (qtype != T_DS || qclass != class)
    return STAT_BOGUS;

  if (!servfail)
    {
      if (STAT_ISEQUAL(rc, STAT_INSECURE))
	{
	  if (option_bool(OPT_BOGUSPRIV) &&
	      (flags = in_arpa_name_2_addr(name, &a)) &&
	      ((flags == F_IPV6 && private_net6(&a.addr6, 0)) || (flags == F_IPV4 && private_net(a.addr4, 0))))
	    {
	      my_syslog(LOG_INFO, _("Insecure reply received for DS %s, assuming that's OK for a RFC-1918 address."), name);
	      neganswer = 1;
	      nons = 0; /* If we're faking a DS, fake one with an NS. */
	      neg_ttl = DNSSEC_ASSUMED_DS_TTL;
	    }
	  else if (lookup_domain(name, F_DOMAINSRV, NULL, NULL))
	    {
	      my_syslog(LOG_INFO, _("Insecure reply received for DS %s, assuming non-DNSSEC domain-specific server."), name);
	      neganswer = 1;
	      nons = 0; /* If we're faking a DS, fake one with an NS. */
	      neg_ttl = DNSSEC_ASSUMED_DS_TTL;
	    }
	  else
	    {
	      my_syslog(LOG_WARNING, _("Insecure DS reply received for %s, check domain configuration and upstream DNS server DNSSEC support"), name);
	      log_query(F_NOEXTRA | F_UPSTREAM, name, NULL, "BOGUS DS - not secure", 0);
	      return STAT_BOGUS | DNSSEC_FAIL_INDET;
	    }
	}
      else
	{
	  if (STAT_ISEQUAL(rc, STAT_NEED_KEY) && hostname_isequal(name, keyname))
	    {
	      /* If the key needed to validate the DS is on the same domain as the DS, we'll
		 loop getting nowhere. Stop that now. This can happen of the DS answer comes
		 from the DS's zone, and not the parent zone. */
	      log_query(F_NOEXTRA | F_UPSTREAM, name, NULL, "BOGUS DS", 0);
	      return STAT_BOGUS;
	    }

	  if (!STAT_ISEQUAL(rc, STAT_SECURE))
	    return rc;
	}
    }
  
  if (!neganswer)
    {
      cache_start_insert();
      
      for (i = 0; i < ntohs(header->ancount); i++)
	{
	  unsigned char *psave;

	  if (!(rc = extract_name(header, plen, &p, name, EXTR_NAME_COMPARE, 10)))
	    return STAT_BOGUS; /* bad packet */
	  
	  GETSHORT(atype, p);
	  GETSHORT(aclass, p);
	  GETLONG(ttl, p);
	  GETSHORT(rdlen, p);
	  
	  if (!CHECK_LEN(header, p, plen, rdlen))
	    return STAT_BOGUS; /* bad packet */

	  psave = p;
	  
	  if (aclass == class && atype == T_DS && rc == 1)
	    { 
	      int algo, digest, keytag;
	      struct blockdata *key;
	   
	      if (rdlen < 5)
		return STAT_BOGUS; /* min 1 byte digest! */
	      
	      GETSHORT(keytag, p);
	      algo = *p++;
	      digest = *p++;
	      
	      if (!ds_digest_name(digest) || !algo_digest_name(algo))
		{
		  a.log.keytag = keytag;
		  a.log.algo = algo;
		  a.log.digest = digest;
		  log_query(F_NOEXTRA | F_KEYTAG | F_UPSTREAM, name, &a, "DS for keytag %hu, algo %hu, digest %hu (not supported)", 0);
		  neg_ttl = ttl;
		} 
	      else if ((key = blockdata_alloc((char*)p, rdlen - 4)))
		{
		  a.ds.digest = digest;
		  a.ds.keydata = key;
		  a.ds.algo = algo;
		  a.ds.keytag = keytag;
		  a.ds.keylen = rdlen - 4;
		  
		  if (!cache_insert(name, &a, class, now, ttl, F_FORWARD | F_DS | F_DNSSECOK))
		    {
		      /* cache_insert fails when the cache is too small, so error with STAT_ABANDONED which
			 will log this as a resource exhaustion problem, which it is. */
		      blockdata_free(key);
		      return STAT_ABANDONED;
		    }
		  else
		    {
		      a.log.keytag = keytag;
		      a.log.algo = algo;
		      a.log.digest = digest;
		      log_query(F_NOEXTRA | F_KEYTAG | F_UPSTREAM, name, &a, "DS for keytag %hu, algo %hu, digest %hu", 0);
		      found_supported = 1;
		    } 
		}
	    }
	  
	  p = psave + rdlen;
	}

      cache_end_insert();

      /* Fall through if no supported algo DS found. */
      if (found_supported)
	return STAT_OK;
    }
  
  flags = F_FORWARD | F_DS | F_NEG | F_DNSSECOK;
  
  if (neganswer)
    {
      if (RCODE(header) == NXDOMAIN)
	flags |= F_NXDOMAIN;
      
      /* We only cache validated DS records, DNSSECOK flag hijacked 
	 to store presence/absence of NS. */
      if (nons)
	{
	  if (lookup_domain(name, F_DOMAINSRV, NULL, NULL))
	    {
	      my_syslog(LOG_WARNING, _("Negative DS reply without NS record received for %s, assuming non-DNSSEC domain-specific server."), name);
	      nons = 0;
	    }
	  else
	    /* We only cache validated DS records, DNSSECOK flag hijacked 
	       to store presence/absence of NS. */
	    flags &= ~F_DNSSECOK;
	}
    }

  cache_start_insert();
  
  /* Use TTL from NSEC for negative cache entries */
  if (!cache_insert(name, NULL, class, now, neg_ttl, flags))
    return STAT_ABANDONED;
  
  cache_end_insert();  
  
  if (neganswer)
    log_query(F_NOEXTRA | F_UPSTREAM, name, NULL,
	      servfail ? "SERVFAIL" : (nons ? "no DS/cut" : "no DS"), 0);
      
  return STAT_OK;
}


/* 4034 6.1 */
static int hostname_cmp(const char *a, const char *b)
{
  char *sa, *ea, *ca, *sb, *eb, *cb;
  unsigned char ac, bc;
  
  sa = ea = (char *)a + strlen(a);
  sb = eb = (char *)b + strlen(b);
 
  while (1)
    {
      while (sa != a && *(sa-1) != '.')
	sa--;
      
      while (sb != b && *(sb-1) != '.')
	sb--;

      ca = sa;
      cb = sb;

      while (1) 
	{
	  if (ca == ea)
	    {
	      if (cb == eb)
		break;
	      
	      return -1;
	    }
	  
	  if (cb == eb)
	    return 1;
	  
	  ac = (unsigned char) *ca++;
	  bc = (unsigned char) *cb++;
	  
	  if (ac >= 'A' && ac <= 'Z')
	    ac += 'a' - 'A';
	  if (bc >= 'A' && bc <= 'Z')
	    bc += 'a' - 'A';
	  
	  if (ac < bc)
	    return -1;
	  else if (ac != bc)
	    return 1;
	}

     
      if (sa == a)
	{
	  if (sb == b)
	    return 0;
	  
	  return -1;
	}
      
      if (sb == b)
	return 1;
      
      ea = --sa;
      eb = --sb;
    }
}

/* returns 0 on success, or DNSSEC_FAIL_* value on failure. */
static int prove_non_existence_nsec(struct dns_header *header, size_t plen, unsigned char **nsecs, unsigned char **labels, int nsec_count,
				    char *workspace1_in, char *workspace2, char *name, int type, int *nons)
{
  int i, rc, rdlen;
  unsigned char *p, *psave;
  int offset = (type & 0xff) >> 3;
  int mask = 0x80 >> (type & 0x07);

  if (nons)
    *nons = 1;
  
  /* Find NSEC record that proves name doesn't exist */
  for (i = 0; i < nsec_count; i++)
    {
      char *workspace1 = workspace1_in;
      int sig_labels, name_labels;

      p = nsecs[i];
      if (!extract_name(header, plen, &p, workspace1, EXTR_NAME_EXTRACT, 10))
	return DNSSEC_FAIL_BADPACKET;
      p += 8; /* class, type, TTL */
      GETSHORT(rdlen, p);
      psave = p;

      if (!extract_name(header, plen, &p, workspace2, EXTR_NAME_EXTRACT, 0))
	return DNSSEC_FAIL_BADPACKET;

      /* If NSEC comes from wildcard expansion, use original wildcard
	 as name for computation. */
      sig_labels = *labels[i];
      name_labels = count_labels(workspace1);

      if (sig_labels < name_labels)
	{
	  int k;
	  for (k = name_labels - sig_labels; k != 0; k--)
	    {
	      while (*workspace1 != '.' && *workspace1 != 0)
		workspace1++;
	      if (k != 1 && *workspace1 == '.')
		workspace1++;
	    }
	  
	  workspace1--;
	  *workspace1 = '*';
	}

      rdlen -= p - psave;
      /* rdlen is now length of type map, and p points to it 
	 packet checked to be as long as rdlen implies in prove_non_existence() */
      
      /* check that the first typemap is complete. */
      if (rdlen < 2 || rdlen < p[1] + 2)
	return DNSSEC_FAIL_BADPACKET;

      /* RFC 6672 5.3.4.1. */
#define DNAME_OFFSET (T_DNAME >> 3)
#define DNAME_MASK (0x80 >> (T_DNAME & 0x07))
      if (p[0] == 0 && (p[1] >= DNAME_OFFSET + 1) && (p[2 + DNAME_OFFSET] & DNAME_MASK) != 0 &&
	  hostname_issubdomain(name, workspace1) == 1)
	return DNSSEC_FAIL_NONSEC;
      
      rc = hostname_cmp(workspace1, name);
      
      if (rc == 0)
	{
	  /* 4035 para 5.4. Last sentence */
	  if (type == T_NSEC || type == T_RRSIG)
	    return 0;

	  /* NSEC with the same name as the RR we're testing, check
	     that the type in question doesn't appear in the type map */
	  if (p[0] == 0 && p[1] >= 1)
	    {
	      /* If we can prove that there's no NS record, return that information. */
	      if (nons && (p[2] & (0x80 >> T_NS)) != 0)
		*nons = 0;
	    
	      /* A CNAME answer would also be valid, so if there's a CNAME is should 
		 have been returned. */
	      if ((p[2] & (0x80 >> T_CNAME)) != 0)
		return DNSSEC_FAIL_NONSEC;
	      
	      /* If the SOA bit is set for a DS record, then we have the
		 DS from the wrong side of the delegation. For the root DS, 
		 this is expected. */
	      if (name_labels != 0 && type == T_DS && (p[2] & (0x80 >> T_SOA)) != 0)
		return DNSSEC_FAIL_NONSEC;
	    }
	  
	  while (rdlen > 0)
	    {
	      if (rdlen < 2 || rdlen < p[1] + 2)
		return DNSSEC_FAIL_BADPACKET;
	      
	      if (p[0] == type >> 8)
		{
		  /* Does the NSEC say our type exists? */
		  if (offset < p[1] && (p[offset+2] & mask) != 0)
		    return DNSSEC_FAIL_NONSEC;
		  
		  break; /* finished checking */
		}
	      
	      rdlen -= p[1];
	      p +=  p[1];
	    }
	  
	  return 0;
	}
      else if (rc == -1)
	{
	  /* Normal case, name falls between NSEC name and next domain name,
	     wrap around case, name falls between NSEC name (rc == -1) and end */
	  if (hostname_cmp(workspace2, name) >= 0 || hostname_cmp(workspace1, workspace2) >= 0)
	    return 0;
	}
      else 
	{
	  /* wrap around case, name falls between start and next domain name */
	  if (hostname_cmp(workspace1, workspace2) >= 0 && hostname_cmp(workspace2, name) >=0 )
	    return 0;
	}
    }
  
  return DNSSEC_FAIL_NONSEC;
}

/* return digest length, or zero on error */
static int hash_name(char *in, unsigned char **out, struct nettle_hash const *hash, 
		     unsigned char *salt, int salt_len, int iterations)
{
  void *ctx;
  unsigned char *digest;
  int i;

  if (!hash_init(hash, &ctx, &digest))
    return 0;
 
  hash->update(ctx, to_wire(in), (unsigned char *)in);
  hash->update(ctx, salt_len, salt);
  hash->digest(ctx, hash->digest_size, digest);

  for(i = 0; i < iterations; i++)
    {
      hash->update(ctx, hash->digest_size, digest);
      hash->update(ctx, salt_len, salt);
      hash->digest(ctx, hash->digest_size, digest);
    }
   
  from_wire(in);

  *out = digest;
  return hash->digest_size;
}

/* Decode base32 to first "." or end of string */
static int base32_decode(char *in, unsigned char *out)
{
  int oc, on, c, mask, i;
  unsigned char *p = out;
 
  for (c = *in, oc = 0, on = 0; c != 0 && c != '.'; c = *++in) 
    {
      if (c >= '0' && c <= '9')
	c -= '0';
      else if (c >= 'a' && c <= 'v')
	c -= 'a', c += 10;
      else if (c >= 'A' && c <= 'V')
	c -= 'A', c += 10;
      else
	return 0;
      
      for (mask = 0x10, i = 0; i < 5; i++)
        {
	  if (c & mask)
	    oc |= 1;
	  mask = mask >> 1;
	  if (((++on) & 7) == 0)
	    *p++ = oc;
	  oc = oc << 1;
	}
    }
  
  if ((on & 7) != 0)
    return 0;

  return p - out;
}

static int check_nsec3_coverage(struct dns_header *header, size_t plen, int digest_len, unsigned char *digest, int type,
				char *workspace1, char *workspace2, unsigned char **nsecs, int nsec_count, int *nons, int name_labels)
{
  int i, hash_len, salt_len, base32_len, rdlen, flags;
  unsigned char *p, *psave;

  for (i = 0; i < nsec_count; i++)
    if ((p = nsecs[i]))
      {
       	if (!extract_name(header, plen, &p, workspace1, EXTR_NAME_EXTRACT, 10) ||
	    !(base32_len = base32_decode(workspace1, (unsigned char *)workspace2)))
	  return 0;
	
	p += 8; /* class, type, TTL */
	GETSHORT(rdlen, p);

	psave = p;

	/* packet checked to be as long as implied by rdlen, salt_len and hash_len in prove_non_existence() */
	p++; /* algo */
	flags = *p++; /* flags */
	p += 2; /* iterations */
	salt_len = *p++; /* salt_len */
	p += salt_len; /* salt */
	hash_len = *p++; /* p now points to next hashed name */
		
	if (digest_len == base32_len && hash_len == base32_len)
	  {
	    int rc = memcmp(workspace2, digest, digest_len);

	    if (rc == 0)
	      {
		/* We found an NSEC3 whose hashed name exactly matches the query, so
		   we just need to check the type map. p points to the RR data for the record.
		   Note we have packet length up to rdlen bytes checked. */
		
		int offset = (type & 0xff) >> 3;
		int mask = 0x80 >> (type & 0x07);
		
		p += hash_len; /* skip next-domain hash */
		rdlen -= p - psave;

		/* check that the first typemap is complete. */
		if (rdlen < 2 || rdlen < p[1] + 2)
		  return DNSSEC_FAIL_BADPACKET;
		
		if (p[0] == 0 && p[1] >= 1)
		  {
		    /* If we can prove that there's no NS record, return that information. */
		    if (nons && (p[2] & (0x80 >> T_NS)) != 0)
		      *nons = 0;
		    
		    /* A CNAME answer would also be valid, so if there's a CNAME is should 
		       have been returned. */
		    if ((p[2] & (0x80 >> T_CNAME)) != 0)
		      return 0;
		    
		    /* If the SOA bit is set for a DS record, then we have the
		       DS from the wrong side of the delegation. For the root DS, 
		       this is expected.  */
		    if (name_labels != 0 && type == T_DS && (p[2] & (0x80 >> T_SOA)) != 0)
		      return 0;
		  }

		while (rdlen > 0)
		  {
		    if (rdlen < 2 || rdlen < p[1] + 2)
		      return DNSSEC_FAIL_BADPACKET;

		    if (p[0] == type >> 8)
		      {
			/* Does the NSEC3 say our type exists? */
			if (offset < p[1] && (p[offset+2] & mask) != 0)
			  return 0;
			
			break; /* finished checking */
		      }
		    
		    rdlen -= p[1];
		    p +=  p[1];
		  }
		
		return 1;
	      }
	    else if (rc < 0)
	      {
		/* Normal case, hash falls between NSEC3 name-hash and next domain name-hash,
		   wrap around case, name-hash falls between NSEC3 name-hash and end */
		if (memcmp(p, digest, digest_len) >= 0 || memcmp(workspace2, p, digest_len) >= 0)
		  {
		    if ((flags & 0x01) && nons) /* opt out */
		      *nons = 0;

		    return 1;
		  }
	      }
	    else 
	      {
		/* wrap around case, name falls between start and next domain name */
		if (memcmp(workspace2, p, digest_len) >= 0 && memcmp(p, digest, digest_len) >= 0)
		  {
		    if ((flags & 0x01) && nons) /* opt out */
		      *nons = 0;

		    return 1;
		  }
	      }
	  }
      }

  return 0;
}

/* returns 0 on success, or DNSSEC_FAIL_* value on failure. */
static int prove_non_existence_nsec3(struct dns_header *header, size_t plen, unsigned char **nsecs, int nsec_count, char *workspace1,
				     char *workspace2, char *name, int type, char *wildname, int *nons, int *validate_counter)
{
  unsigned char *salt, *p, *digest;
  int digest_len, i, iterations, salt_len, base32_len, algo = 0;
  struct nettle_hash const *hash;
  char *closest_encloser, *next_closest, *wildcard;
  
  if (nons)
    *nons = 1;
  
  /* Look though the NSEC3 records to find the first one with 
     an algorithm we support.

     Take the algo, iterations, and salt of that record
     as the ones we're going to use, and prune any 
     that don't match. */
  
  for (i = 0; i < nsec_count; i++)
    {
      if (!(p = skip_name(nsecs[i], header, plen, 15)))
	return DNSSEC_FAIL_BADPACKET; /* bad packet */
      
      p += 10; /* type, class, TTL, rdlen */
      algo = *p++;
      
      if ((hash = hash_find(nsec3_digest_name(algo))))
	break; /* known algo */
    }

  /* No usable NSEC3s */
  if (i == nsec_count)
    return DNSSEC_FAIL_NONSEC;

  p++; /* flags */

  GETSHORT (iterations, p);
  /* Upper-bound iterations, to avoid DoS. RFC 9276 refers. */
  if (iterations > daemon->limit[LIMIT_NSEC3_ITERS])
    return DNSSEC_FAIL_NSEC3_ITERS;
  
  salt_len = *p++;
  salt = p;
      
  /* Now prune so we only have NSEC3 records with same iterations, salt and algo */
  for (i = 0; i < nsec_count; i++)
    {
      unsigned char *nsec3p = nsecs[i];
      int this_iter, flags;

      nsecs[i] = NULL; /* Speculative, will be restored if OK. */
      
      if (!(p = skip_name(nsec3p, header, plen, 15)))
	return DNSSEC_FAIL_BADPACKET; /* bad packet */
      
      p += 10; /* type, class, TTL, rdlen */
      
      if (*p++ != algo)
	continue;
 
      flags = *p++; /* flags */
      
      /* 5155 8.2 */
      if (flags != 0 && flags != 1)
	continue;

      GETSHORT(this_iter, p);
      if (this_iter != iterations)
	continue;

      if (salt_len != *p++)
	continue;
      
      if (memcmp(p, salt, salt_len) != 0)
	continue;

      /* All match, put the pointer back */
      nsecs[i] = nsec3p;
    }

  if (dec_counter(validate_counter, NULL))
    return DNSSEC_FAIL_WORK;

  if ((digest_len = hash_name(name, &digest, hash, salt, salt_len, iterations)) == 0)
    return DNSSEC_FAIL_NONSEC;
  
  if (check_nsec3_coverage(header, plen, digest_len, digest, type, workspace1, workspace2, nsecs, nsec_count, nons, count_labels(name)))
    return 0;

  /* Can't find an NSEC3 which covers the name directly, we need the "closest encloser NSEC3" 
     or an answer inferred from a wildcard record. */
  closest_encloser = name;
  next_closest = NULL;

  do
    {
      if (*closest_encloser == '.')
	closest_encloser++;

      if (wildname && hostname_isequal(closest_encloser, wildname))
	break;

      if (dec_counter(validate_counter, NULL))
	return DNSSEC_FAIL_WORK;
      
      if ((digest_len = hash_name(closest_encloser, &digest, hash, salt, salt_len, iterations)) == 0)
	return DNSSEC_FAIL_NONSEC;
      
      for (i = 0; i < nsec_count; i++)
	if ((p = nsecs[i]))
	  {
	    if (!extract_name(header, plen, &p, workspace1, EXTR_NAME_EXTRACT, 0))
	      return DNSSEC_FAIL_BADPACKET;

	    if (!(base32_len = base32_decode(workspace1, (unsigned char *)workspace2)))
	      return DNSSEC_FAIL_NONSEC;
	  
	    if (digest_len == base32_len &&
		memcmp(digest, workspace2, digest_len) == 0)
	      break; /* Gotit */
	  }
      
      if (i != nsec_count)
	break;
      
      next_closest = closest_encloser;
    }
  while ((closest_encloser = strchr(closest_encloser, '.')));
  
  if (!closest_encloser || !next_closest)
    return DNSSEC_FAIL_NONSEC;
  
  /* Look for NSEC3 that proves the non-existence of the next-closest encloser */
  if (dec_counter(validate_counter, NULL))
    return DNSSEC_FAIL_WORK;
  
  if ((digest_len = hash_name(next_closest, &digest, hash, salt, salt_len, iterations)) == 0)
    return DNSSEC_FAIL_NONSEC;

  if (!check_nsec3_coverage(header, plen, digest_len, digest, type, workspace1, workspace2, nsecs, nsec_count, NULL, 1))
    return DNSSEC_FAIL_NONSEC;
  
  /* Finally, check that there's no seat of wildcard synthesis */
  if (!wildname)
    {
      if (!(wildcard = strchr(next_closest, '.')) || wildcard == next_closest)
	return DNSSEC_FAIL_NONSEC;
      
      wildcard--;
      *wildcard = '*';
      
      if (dec_counter(validate_counter, NULL))
	return DNSSEC_FAIL_WORK;
      
      if ((digest_len = hash_name(wildcard, &digest, hash, salt, salt_len, iterations)) == 0)
	return DNSSEC_FAIL_NONSEC;
      
      if (!check_nsec3_coverage(header, plen, digest_len, digest, type, workspace1, workspace2, nsecs, nsec_count, NULL, 1))
	return DNSSEC_FAIL_NONSEC;
    }
  
  return 0;
}

/* returns 0 on success, or DNSSEC_FAIL_* value on failure. */
static int prove_non_existence(struct dns_header *header, size_t plen, char *keyname, char *name, int qtype, int qclass,
			       char *wildname, int *nons, int *nsec_ttl, int *validate_counter)
{
  static unsigned char **nsecset = NULL, **rrsig_labels = NULL;
  static int nsecset_sz = 0, rrsig_labels_sz = 0;
  
  int type_found = 0;
  unsigned char *auth_start, *p = skip_questions(header, plen);
  int type, class, rdlen, i, nsecs_found;
  unsigned long ttl;
  
  /* Move to NS section */
  if (!p || !(p = skip_section(p, ntohs(header->ancount), header, plen)))
    return DNSSEC_FAIL_BADPACKET;

  auth_start = p;
  
  for (nsecs_found = 0, i = 0; i < ntohs(header->nscount); i++)
    {
      unsigned char *pstart = p;
      
      if (!extract_name(header, plen, &p, daemon->workspacename, EXTR_NAME_EXTRACT, 10))
	return DNSSEC_FAIL_BADPACKET;
	  
      GETSHORT(type, p); 
      GETSHORT(class, p);
      GETLONG(ttl, p);
      GETSHORT(rdlen, p);
 
      if (!CHECK_LEN(header, p, plen, rdlen))
	return DNSSEC_FAIL_BADPACKET;
      
      if (class == qclass && (type == T_NSEC || type == T_NSEC3))
	{
	  if (nsec_ttl)
	    {
	      /* Limit TTL with sig TTL */
	      if (daemon->rr_status[ntohs(header->ancount) + i] < ttl)
		ttl = daemon->rr_status[ntohs(header->ancount) + i];
	      *nsec_ttl = ttl;
	    }
	  
	  /* No mixed NSECing 'round here, thankyouverymuch */
	  if (type_found != 0 && type_found != type)
	    return DNSSEC_FAIL_NONSEC;

	  type_found = type;

	  if (!expand_workspace(&nsecset, &nsecset_sz, nsecs_found))
	    return DNSSEC_FAIL_BADPACKET; 
	  
	  if (type == T_NSEC)
	    {
	      /* If we're looking for NSECs, find the corresponding SIGs, to 
		 extract the labels value, which we need in case the NSECs
		 are the result of wildcard expansion.
		 Note that the NSEC may not have been validated yet
		 so if there are multiple SIGs, make sure the label value
		 is the same in all, to avoid be duped by a rogue one.
		 If there are no SIGs, that's an error */
	      unsigned char *p1 = auth_start;
	      int res, j, rdlen1, type1, class1;
	      
	      if (!expand_workspace(&rrsig_labels, &rrsig_labels_sz, nsecs_found))
		return DNSSEC_FAIL_BADPACKET;
	      
	      rrsig_labels[nsecs_found] = NULL;
	      
	      for (j = ntohs(header->nscount); j != 0; j--)
		{
		  unsigned char *psav;

		  if (!(res = extract_name(header, plen, &p1, daemon->workspacename, EXTR_NAME_COMPARE, 10)))
		    return DNSSEC_FAIL_BADPACKET;
		  
		   GETSHORT(type1, p1); 
		   GETSHORT(class1, p1);
		   p1 += 4; /* TTL */
		   GETSHORT(rdlen1, p1);

		   psav = p1;
		   
		   if (!CHECK_LEN(header, p1, plen, rdlen1))
		     return DNSSEC_FAIL_BADPACKET;
		   
		   if (res == 1 && class1 == qclass && type1 == T_RRSIG)
		     {
		       int type_covered;
		   		       
		       if (rdlen1 < 18)
			 return DNSSEC_FAIL_BADPACKET; /* bad packet */

		       GETSHORT(type_covered, p1);

		       if (type_covered == T_NSEC)
			 {
			   p1++; /* algo */
			   
			   /* labels field must be the same in every SIG we find. */
			   if (!rrsig_labels[nsecs_found])
			     rrsig_labels[nsecs_found] = p1;
			   else if (*rrsig_labels[nsecs_found] != *p1) /* algo */
			     return DNSSEC_FAIL_NONSEC;
			 }
		     }
		   
		   p1 = psav + rdlen1;
		}

	      /* Must have found at least one sig. */
	      if (!rrsig_labels[nsecs_found])
		return DNSSEC_FAIL_NONSEC;
	    }
	  else if (type == T_NSEC3)
	    {
	      /* Decode the packet structure enough to check that rdlen is big enough
		 to contain everything other than the type bitmap.
		 (packet checked to be long enough to contain rdlen above)
		 We don't need to do any further length checks in check_nes3_coverage()
		 or prove_non_existence_nsec3() */
	      
	      int salt_len, hash_len;
	      unsigned char *psav = p;
	      
	      if (rdlen < 5)
		return DNSSEC_FAIL_BADPACKET;
	      
	      p += 4; /* algo, flags, iterations */
	      salt_len = *p++; /* salt_len */
	      if (rdlen < (6 + salt_len)) 
		return DNSSEC_FAIL_BADPACKET; /* check up to hash_length */

	      p += salt_len; /* salt */
	      hash_len = *p++; 
	      if (rdlen < (6 + salt_len + hash_len))
		return DNSSEC_FAIL_BADPACKET; /* check to end of next hashed name */

	      p = psav;
	    }

	  nsecset[nsecs_found++] = pstart;   
	}
      
      p += rdlen;
    }
  
  if (type_found == T_NSEC)
    return prove_non_existence_nsec(header, plen, nsecset, rrsig_labels, nsecs_found, daemon->workspacename, keyname, name, qtype, nons);
  else if (type_found == T_NSEC3)
    return prove_non_existence_nsec3(header, plen, nsecset, nsecs_found, daemon->workspacename, keyname, name, qtype, wildname, nons, validate_counter);
  else
    return DNSSEC_FAIL_NONSEC;
}

/* Check signing status of name.
   returns:
   STAT_SECURE   zone is signed.
   STAT_INSECURE zone proved unsigned.
   STAT_NEED_DS  require DS record of name returned in keyname.
   STAT_NEED_KEY require DNSKEY record of name returned in keyname.
   name returned unaltered.
*/
/**
 * @brief Determine security status of DNS zone by traversing trust chain upward
 * 
 * @detailed Walks up the DNS tree from the target name to find either a trust anchor
 *           (marking the zone as SECURE) or an insecure delegation point without DS
 *           records (marking the zone as INSECURE). This function implements the zone
 *           status determination logic essential for DNSSEC validation per RFC 4035.
 *           
 *           The algorithm starts at the given name and moves progressively up the DNS
 *           hierarchy (removing leftmost labels) until it finds:
 *           1. A trust anchor in daemon->key_cache (zone is SECURE)
 *           2. A delegation with DS records (zone is potentially SECURE, continue upward)
 *           3. A delegation without DS records (zone is INSECURE, unsigned)
 *           4. The root zone is reached (zone is SECURE if trust anchor exists)
 * 
 * @param name Domain name to check (presentation format, e.g., "www.example.com")
 * @param class DNS class (typically C_IN for Internet class)
 * @param keyname Output buffer to receive name needing key lookup (must be valid pointer)
 * @param now Current timestamp for cache entry expiration checks
 * 
 * @return Security status code from DNSSEC validation
 * @retval STAT_SECURE Zone is signed and has valid trust chain to anchor
 * @retval STAT_INSECURE Zone is provably unsigned (no DS at delegation point)
 * @retval STAT_BOGUS Validation error or malformed data encountered
 * 
 * @note This function only examines cached data (key_cache); does not generate queries
 * @note Expired cache entries are ignored (treated as non-existent)
 * @warning Assumes keyname buffer is large enough for DNS name (MAXDNAME bytes)
 * 
 * @see find_key() which searches trust anchor cache
 * @see rrset_find() which locates DS records for delegation points
 * @see dnssec_validate_reply() which calls this to determine validation requirements
 * 
 * EXAMPLE USAGE:
 * @code
 * char keyname[MAXDNAME];
 * time_t now = time(NULL);
 * int status = zone_status("www.example.com", C_IN, keyname, now);
 * if (status == STAT_SECURE)
 *   // Proceed with DNSSEC validation
 * else if (status == STAT_INSECURE)
 *   // Zone is provably unsigned, skip validation
 * @endcode
 * 
 * RFC COMPLIANCE: Implements trust chain traversal per RFC 4035 Section 5.2
 * SIDE EFFECTS: Writes to keyname buffer (output parameter)
 * THREAD SAFETY: Single-threaded, accesses shared daemon->key_cache
 */
static int zone_status(char *name, int class, char *keyname, time_t now)
{
  int name_start = strlen(name); /* for when TA is root */
  struct crec *crecp;
  char *p;

  /* First, work towards the root, looking for a trust anchor.
     This can either be one configured, or one previously cached.
     We can assume, if we don't find one first, that there is
     a trust anchor at the root. */
  for (p = name; p; p = strchr(p, '.'))
    {
      if (*p == '.')
	p++;

      if (cache_find_by_name(NULL, p, now, F_DS))
	{
	  name_start = p - name;
	  break;
	}
    }

  /* Now work away from the trust anchor */
  while (1)
    {
      strcpy(keyname, &name[name_start]);
      
      if (!(crecp = cache_find_by_name(NULL, keyname, now, F_DS)))
	return STAT_NEED_DS;
      
       /* F_DNSSECOK misused in DS cache records to non-existence of NS record.
	  F_NEG && !F_DNSSECOK implies that we've proved there's no DS record here,
	  but that's because there's no NS record either, ie this isn't the start
	  of a zone. We only prove that the DNS tree below a node is unsigned when
	  we prove that we're at a zone cut AND there's no DS record. */
      if (crecp->flags & F_NEG)
	{
	  if (crecp->flags & F_DNSSECOK)
	    return STAT_INSECURE; /* proved no DS here */
	}
      else
	{
	  /* If all the DS records have digest and/or sig algos we don't support,
	     then the zone is insecure. Note that if an algo
	     appears in the DS, then RRSIGs for that algo MUST
	     exist for each RRset: 4035 para 2.2  So if we find
	     a DS here with digest and sig we can do, we're entitled
	     to assume we can validate the zone and if we can't later,
	     because an RRSIG is missing we return BOGUS.
	  */
	  do 
	    {
	      if (crecp->uid == (unsigned int)class &&
		  ds_digest_name(crecp->addr.ds.digest) &&
		  algo_digest_name(crecp->addr.ds.algo))
		break;
	    }
	  while ((crecp = cache_find_by_name(crecp, keyname, now, F_DS)));

	  if (!crecp)
	    return STAT_INSECURE;
	}

      if (name_start == 0)
	break;

      for (p = &name[name_start-2]; (*p != '.') && (p != name); p--);
      
      if (p != name)
        p++;
      
      name_start = p - name;
    } 

  return STAT_SECURE;
}
       
/* Validate all the RRsets in the answer and authority sections of the reply (4035:3.2.3) 
   Return code:
   STAT_SECURE   if it validates.
   STAT_INSECURE at least one RRset not validated, because in unsigned zone.
   STAT_BOGUS    signature is wrong, bad packet, no validation where there should be.
   STAT_NEED_KEY need DNSKEY to complete validation (name is returned in keyname, class in *class)
   STAT_NEED_DS  need DS to complete validation (name is returned in keyname)
   STAT_ABANDONED resource exhaustion.

   daemon->rr_status points to a char array which corressponds to the RRs in the 
   answer and auth sections. This is set to >1 for each RR which is validated, and 0 for any which aren't.

   When validating replies to DS records, we're only interested in the NSEC{3} RRs in the auth section.
   Other RRs in that section missing sigs will not cause am INSECURE reply. We determine this mode
   if the nons argument is non-NULL.
*/
int dnssec_validate_reply(time_t now, struct dns_header *header, size_t plen, char *name, char *keyname, 
			  int *class, int check_unsigned, int *neganswer, int *nons, int *nsec_ttl, int *validate_counter)
{
  static unsigned char **targets = NULL;
  static int target_sz = 0;

  unsigned char *ans_start, *p1, *p2, *p3;
  int type1, class1, rdlen1 = 0, type2, class2, rdlen2, qclass, qtype, targetidx, gotdname;
  int i, j, k, rc = STAT_INSECURE;
  int secure = STAT_SECURE;
  int rc_nsec;
  unsigned long ttl;
  
  /* extend rr_status if necessary */
  if (daemon->rr_status_sz < ntohs(header->ancount) + ntohs(header->nscount))
    {
      unsigned long *new = whine_malloc(sizeof(*daemon->rr_status) * (ntohs(header->ancount) + ntohs(header->nscount) + 64));

      if (!new)
	return STAT_BOGUS;

      free(daemon->rr_status);
      daemon->rr_status = new;
      daemon->rr_status_sz = ntohs(header->ancount) + ntohs(header->nscount) + 64;
    }
  
  memset(daemon->rr_status, 0, sizeof(*daemon->rr_status) * daemon->rr_status_sz);
  
  if (neganswer)
    *neganswer = 0;
  
  if (RCODE(header) == SERVFAIL || ntohs(header->qdcount) != 1)
    return STAT_BOGUS;
  
  if (RCODE(header) != NXDOMAIN && RCODE(header) != NOERROR)
    return STAT_INSECURE;

  p1 = (unsigned char *)(header+1);
  
   /* Find all the targets we're looking for answers to.
     The zeroth array element is for the query, subsequent ones
     for CNAME targets, unless the query is for a CNAME or ANY. */

  if (!expand_workspace(&targets, &target_sz, 0))
    return STAT_BOGUS;
  
  targets[0] = p1;
  targetidx = 1;
   
  if (!extract_name(header, plen, &p1, name, EXTR_NAME_EXTRACT, 4))
    return STAT_BOGUS;
  
  GETSHORT(qtype, p1);
  GETSHORT(qclass, p1);
  ans_start = p1;
 
  /* Can't validate an RRSIG query */
  if (qtype == T_RRSIG)
    return STAT_INSECURE;

  /* Find CNAME targets. */
  for (gotdname = i = 0; i < ntohs(header->ancount); i++) 
    {
      if (!(p1 = skip_name(p1, header, plen, 10)))
	return STAT_BOGUS; /* bad packet */
      
      GETSHORT(type1, p1); 
      GETSHORT(class1, p1);
      p1 += 4; /* TTL */
      GETSHORT(rdlen1, p1);  
      
      if (type1 == T_DNAME)
	gotdname = 1;
      
      if (qtype != T_CNAME && qtype != T_ANY && type1 == T_CNAME && class1 == qclass)
	{
	  if (!expand_workspace(&targets, &target_sz, targetidx))
	    return STAT_BOGUS;
	  
	  targets[targetidx++] = p1; /* pointer to target name */
	}
      
      if (!ADD_RDLEN(header, p1, plen, rdlen1))
	return STAT_BOGUS;
    }
  
  /* A DNAME capable of sythesising a CNAME means we don't need to validate the CNAME,
     we can just assume that it's valid. RFC 4035 3.2.3 */
  if (gotdname)
    for (p1 = ans_start, i = 0; i < ntohs(header->ancount); i++) 
      {
	if (!extract_name(header, plen, &p1, name, EXTR_NAME_EXTRACT, 10))
	  return STAT_BOGUS; /* bad packet */
	
	GETSHORT(type1, p1); 
	GETSHORT(class1, p1);
	p1 += 4; /* TTL */
	GETSHORT(rdlen1, p1);  
	
	if (type1 != T_DNAME)
	  {
	    if (!ADD_RDLEN(header, p1, plen, rdlen1))
	      return STAT_BOGUS;
	  }
	else
	  {
	    if (!extract_name(header, plen, &p1, keyname, EXTR_NAME_EXTRACT, 0))
	      return STAT_BOGUS; /* bad packet */
	    
	    /* We now have the name of the DNAME in name, and the target in keyname.
	       Look for any CNAMEs which could have been synthesised from this DNAME
	       and pre-qualify them. */
	    for (p2 = ans_start, j = 0; j < ntohs(header->ancount); j++)
	      {
		if (!extract_name(header, plen, &p2, daemon->cname, EXTR_NAME_EXTRACT, 10))
		  return STAT_BOGUS; /* bad packet */
		
		GETSHORT(type2, p2); 
		GETSHORT(class2, p2);
		GETLONG(ttl, p2);
		GETSHORT(rdlen2, p2);  
		
		if (type2 != T_CNAME || class2 != class1)
		  {
		    if (!ADD_RDLEN(header, p2, plen, rdlen2))
		      return STAT_BOGUS;
		  }
		else
		  {
		    size_t name_prefix_len = strlen(daemon->cname) - strlen(name);
		    
		    if (!extract_name(header, plen, &p2, daemon->workspacename, EXTR_NAME_EXTRACT, 0))
		      return STAT_BOGUS; /* bad packet */
		    
		    /* We have the name of the CNAME in daemon->cname, and the target in daemon->workspacename.
		       See if the CNAME was sythesised from the DNAME.
		       CNAME must be <subdomain>.<dname>
		       CNAME target must be <subdomain>.<dname_target>
		       <subdomain>s must match for name and target. */ 
		    if (hostname_issubdomain(name, daemon->cname) == 1 &&
			hostname_issubdomain(keyname, daemon->workspacename) == 1 &&
			name_prefix_len == strlen(daemon->workspacename) - strlen(keyname))
		      {
			char save = daemon->cname[name_prefix_len];
			daemon->cname[name_prefix_len] = 0;
			daemon->workspacename[name_prefix_len] = 0;
			
			if (hostname_isequal(daemon->cname, daemon->workspacename))
			  {
			    /* pre-qualify this as validated */
			    daemon->rr_status[j] = ttl > 0 ? ttl : 1;
			    
			    /* and remove it from the targets we need to have validated answers to. */
			    if (class2 == qclass)
			      {
				daemon->cname[name_prefix_len] = save;
				for (k = 0; k <targetidx; k++)
				  if ((p3 = targets[k]))
				    {
				      int rc1;
				      if (!(rc1 = extract_name(header, plen, &p3, daemon->cname, EXTR_NAME_COMPARE, 0)))
					return STAT_BOGUS; /* bad packet */
				      
				      if (rc1 == 1)
					targets[k] = NULL;
				    }
			      }
			  }
		      }
		  }
	      }
	  }
      }
  
  for (p1 = ans_start, i = 0; i < ntohs(header->ancount) + ntohs(header->nscount); i++)
    {
      if (i != 0 && !ADD_RDLEN(header, p1, plen, rdlen1))
	return STAT_BOGUS;
      
      if (!extract_name(header, plen, &p1, name, EXTR_NAME_EXTRACT, 10))
	return STAT_BOGUS; /* bad packet */
      
      GETSHORT(type1, p1);
      GETSHORT(class1, p1);
      p1 += 4; /* TTL */
      GETSHORT(rdlen1, p1);
      
      /* Don't try and validate RRSIGs! */
      if (type1 == T_RRSIG)
	continue;

      /* Pre-validated by DNAME above don't validate. */
      if (daemon->rr_status[i] != 0)
	continue;
      
      /* Check if we've done this RRset already */
      for (p2 = ans_start, j = 0; j < i; j++)
	{
	  if (!(rc = extract_name(header, plen, &p2, name, EXTR_NAME_COMPARE, 10)))
	    return STAT_BOGUS; /* bad packet */
	  
	  GETSHORT(type2, p2);
	  GETSHORT(class2, p2);
	  p2 += 4; /* TTL */
	  GETSHORT(rdlen2, p2);
	  
	  if (type2 == type1 && class2 == class1 && rc == 1)
	    break; /* Done it before: name, type, class all match. */
	  
	  if (!ADD_RDLEN(header, p2, plen, rdlen2))
	    return STAT_BOGUS;
	}
      
      /* Done already: copy the validation status */
      if (j != i)
	daemon->rr_status[i] = daemon->rr_status[j];
      else
	{
	  /* Not done, validate now */
	  int sigcnt, rrcnt;
	  char *wildname;
	  
	  if (!explore_rrset(header, plen, class1, type1, name, keyname, &sigcnt, &rrcnt))
	    return STAT_BOGUS;
	  
	  /* No signatures for RRset. We can be configured to assume this is OK and return an INSECURE result. */
	  if (sigcnt == 0)
	    {
	      /* NSEC and NSEC3 records must be signed. We make this assumption elsewhere. */
	      if (type1 == T_NSEC || type1 == T_NSEC3)
		return STAT_BOGUS | DNSSEC_FAIL_NOSIG;
	      else if (nons && i >= ntohs(header->ancount))
		/* If we're validating a DS reply, rather than looking for the value of AD bit,
		   we only care that NSEC and NSEC3 RRs in the auth section are signed. 
		   Return SECURE even if others (SOA....) are not. */
		rc = STAT_SECURE;
	      else
		{
		  /* unsigned RRsets in auth section are not BOGUS, but do make reply insecure. */
		  if (check_unsigned && i < ntohs(header->ancount))
		    {
		      rc = zone_status(name, class1, keyname, now);
		      if (STAT_ISEQUAL(rc, STAT_SECURE))
			rc = STAT_BOGUS | DNSSEC_FAIL_NOSIG;
		      
		      if (class)
			*class = class1; /* Class for NEED_DS or NEED_KEY */
		    }
		  else 
		    rc = STAT_INSECURE; 
		  
		  if (!STAT_ISEQUAL(rc, STAT_INSECURE))
		    return rc;
		}
	    }
	  else
	    {
	      /* explore_rrset() gives us key name from sigs in keyname.
		 Can't overwrite name here. */
	      strcpy(daemon->workspacename, keyname);
	      rc = zone_status(daemon->workspacename, class1, keyname, now);
	      
	      if (STAT_ISEQUAL(rc, STAT_BOGUS) || STAT_ISEQUAL(rc, STAT_NEED_KEY) || STAT_ISEQUAL(rc, STAT_NEED_DS))
		{
		  if (class)
		    *class = class1; /* Class for NEED_DS or NEED_KEY */
		  return rc;
		}
	      
	      /* Zone is insecure, don't need to validate RRset */
	      if (STAT_ISEQUAL(rc, STAT_SECURE))
		{
		  unsigned long sig_ttl;
		  rc = validate_rrset(now, header, plen, class1, type1, sigcnt,
				      rrcnt, name, keyname, &wildname, NULL, 0, 0, 0, &sig_ttl, validate_counter);
		  
		  if (STAT_ISEQUAL(rc, STAT_BOGUS) || STAT_ISEQUAL(rc, STAT_NEED_KEY) || STAT_ISEQUAL(rc, STAT_NEED_DS) || STAT_ISEQUAL(rc, STAT_ABANDONED))
		    {
		      if (class)
			*class = class1; /* Class for DS or DNSKEY */
		      return rc;
		    } 
		  
		  /* rc is now STAT_SECURE or STAT_SECURE_WILDCARD */
		  
		  /* Note that RR is validated */
		  daemon->rr_status[i] = sig_ttl;
		   
		  /* Note if we've validated either the answer to the question
		     or the target of a CNAME. Any not noted will need NSEC or
		     to be in unsigned space. */
		  for (j = 0; j <targetidx; j++)
		    if ((p2 = targets[j]))
		      {
			int rc1;
			if (!(rc1 = extract_name(header, plen, &p2, name, EXTR_NAME_COMPARE, 10)))
			  return STAT_BOGUS; /* bad packet */
			
			if (class1 == qclass && rc1 == 1 && (type1 == T_CNAME || type1 == qtype || qtype == T_ANY ))
			  targets[j] = NULL;
		      }
		  
		  /* An attacker replay a wildcard answer with a different
		     answer and overlay a genuine RR. To prove this
		     hasn't happened, the answer must prove that
		     the genuine record doesn't exist. Check that here. 
		     Note that we may not yet have validated the NSEC/NSEC3 RRsets. 
		     That's not a problem since if the RRsets later fail
		     we'll return BOGUS then. */
		  if (STAT_ISEQUAL(rc, STAT_SECURE_WILDCARD) &&
		      ((rc_nsec = prove_non_existence(header, plen, keyname, name, type1, class1, wildname, NULL, NULL, validate_counter))) != 0)
		    return  (rc_nsec & DNSSEC_FAIL_WORK) ? STAT_ABANDONED : (STAT_BOGUS | rc_nsec);

		  rc = STAT_SECURE;
		}
	    }
	}

      if (STAT_ISEQUAL(rc, STAT_INSECURE))
	secure = STAT_INSECURE;
    }

  /* OK, all the RRsets validate, now see if we have a missing answer or CNAME target. */
  for (j = 0; j <targetidx; j++)
    if ((p2 = targets[j]))
      {
	if (neganswer)
	  *neganswer = 1;
	
	if (!extract_name(header, plen, &p2, name, EXTR_NAME_EXTRACT, 10))
	  return STAT_BOGUS; /* bad packet */
	
	/* NXDOMAIN or NODATA reply, unanswered question is (name, qclass, qtype) */
	
	/* For anything other than a DS record, this situation is OK if either
	   the answer is in an unsigned zone, or there's NSEC records.
	   For a DS record, we return INSECURE, which almost always turns
	   into BOGUS in the caller. */
	if ((rc_nsec = prove_non_existence(header, plen, keyname, name, qtype, qclass, NULL, nons, nsec_ttl, validate_counter)) != 0)
	  {
	    if (rc_nsec & DNSSEC_FAIL_WORK)
	      return STAT_ABANDONED;

	    /* Empty DS without NSECS */
	    if (qtype == T_DS)
	      return STAT_INSECURE;
	    
	    if ((rc_nsec & (DNSSEC_FAIL_NONSEC | DNSSEC_FAIL_NSEC3_ITERS)) &&
		!STAT_ISEQUAL((rc = zone_status(name, qclass, keyname, now)), STAT_SECURE))
	      {
		if (class)
		  *class = qclass; /* Class for NEED_DS or NEED_KEY */
		return rc;
	      } 
	    
	    return STAT_BOGUS | rc_nsec; /* signed zone, no NSECs */
	  }
      }
  
  return secure;
}


/* Compute keytag (checksum to quickly index a key). See RFC4034 */
int dnskey_keytag(int alg, int flags, unsigned char *key, int keylen)
{
  if (alg == 1)
    {
      /* Algorithm 1 (RSAMD5) has a different (older) keytag calculation algorithm.
         See RFC4034, Appendix B.1 */
      return key[keylen-4] * 256 + key[keylen-3];
    }
  else
    {
      unsigned long ac = flags + 0x300 + alg;
      int i;

      for (i = 0; i < keylen; ++i)
        ac += (i & 1) ? key[i] : key[i] << 8;

      ac += (ac >> 16) & 0xffff;
      return ac & 0xffff;
    }
}

size_t dnssec_generate_query(struct dns_header *header, unsigned char *end, char *name,
			     int class, int id, int type)
{
  unsigned char *p;
  
  header->qdcount = htons(1);
  header->ancount = htons(0);
  header->nscount = htons(0);
  header->arcount = htons(0);
  header->id = htons(id);
  
  header->hb3 = HB3_RD; 
  SET_OPCODE(header, QUERY);
  /* For debugging, set Checking Disabled, otherwise, have the upstream check too,
     this allows it to select auth servers when one is returning bad data. */
  header->hb4 = option_bool(OPT_DNSSEC_DEBUG) ? HB4_CD : 0;

  p = (unsigned char *)(header+1);
	
  p = do_rfc1035_name(p, name, NULL);
  *p++ = 0;
  PUTSHORT(type, p);
  PUTSHORT(class, p);

  return add_do_bit(header, p - (unsigned char *)header, end);
}

int errflags_to_ede(int status)
{
  /* We can end up with more than one flag set for some errors,
     so this encodes a rough priority so the (eg) No sig is reported
     before no-unexpired-sig. */

  if (status & DNSSEC_FAIL_NYV)
    return EDE_SIG_NYV;
  else if (status & DNSSEC_FAIL_EXP)
    return EDE_SIG_EXP;
  else if (status & DNSSEC_FAIL_NOKEYSUP)
    return EDE_USUPDNSKEY;
  else if (status & DNSSEC_FAIL_NOZONE)
    return EDE_NO_ZONEKEY;
  else if (status & DNSSEC_FAIL_NOKEY)
    return EDE_NO_DNSKEY;
  else if (status & DNSSEC_FAIL_NODSSUP)
    return EDE_USUPDS;
  else if (status & DNSSEC_FAIL_NSEC3_ITERS)
    return EDE_UNS_NS3_ITER;
  else if (status & DNSSEC_FAIL_NONSEC)
    return EDE_NO_NSEC;
  else if (status & DNSSEC_FAIL_INDET)
    return EDE_DNSSEC_IND;
  else if (status & DNSSEC_FAIL_NOSIG)
    return EDE_NO_RRSIG;
  else
    return EDE_UNSET;
}
#endif /* HAVE_DNSSEC */

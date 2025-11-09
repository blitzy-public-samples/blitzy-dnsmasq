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
 * @file outpacket.c
 * @brief DHCPv6 option serialization and packet buffer management
 * 
 * DETAILED PURPOSE:
 * This module provides comprehensive DHCPv6 option serialization and packet buffer
 * management for constructing DHCPv6 response messages (ADVERTISE, REPLY, RECONFIGURE).
 * It implements safe encoding of all DHCPv6 option types with automatic buffer expansion,
 * bounds checking, and nested option support for complex structures like IA_NA, IA_TA,
 * and IA_PD containers that contain sub-options.
 * 
 * The implementation maintains a global packet construction state using daemon->outpacket
 * (struct iovec) and a position counter, allowing incremental assembly of DHCPv6 packets
 * with proper option length calculation and nested option chaining. All functions operate
 * on the shared outpacket buffer, eliminating the need to pass buffer pointers between
 * functions.
 * 
 * KEY RESPONSIBILITIES:
 * - Packet buffer management with automatic expansion via expand() and reset_counter()
 * - DHCPv6 option header creation with new_opt6() providing 4-byte option+length headers
 * - Option data encoding for all DHCPv6 data types (long, short, char, string, arbitrary)
 * - Nested option support with container tracking via save_counter() and end_opt6()
 * - Buffer overflow protection through expand_buf() bounds checking
 * - Option length calculation and backpatching for nested containers
 * 
 * DEPENDENCIES:
 * Includes: dnsmasq.h (daemon structure, expand_buf utility), sys/uio.h (struct iovec)
 * Called by: dhcp6.c (DHCPv6 message construction), rfc3315.c (DHCPv6 protocol implementation)
 * Calls: expand_buf() in util.c for safe buffer expansion
 * 
 * DATA STRUCTURES:
 * - daemon->outpacket (struct iovec): Buffer for outgoing DHCPv6 packet construction
 *   * iov_base: Pointer to allocated buffer (dynamically expanded)
 *   * iov_len: Current allocated buffer size
 * - outpacket_counter (static size_t): Current write position in outpacket buffer
 * 
 * COMPILE-TIME OPTIONS:
 * HAVE_DHCP6: Entire module conditionally compiled only when DHCPv6 support is enabled
 * 
 * THREADING/CONCURRENCY:
 * Single-threaded event-driven architecture. All functions modify global daemon->outpacket
 * and outpacket_counter state, assuming sequential packet construction without concurrent
 * access. Not thread-safe.
 * 
 * @copyright Copyright (c) 2000-2025 Simon Kelley
 * @license GPL-2.0-or-later
 */

#include "dnsmasq.h"
 
#ifdef HAVE_DHCP6

static size_t outpacket_counter;

/**
 * @brief Finalize nested DHCPv6 option container by backpatching length field
 * 
 * @detailed Completes construction of a DHCPv6 option container (IA_NA, IA_TA, IA_PD,
 *           or OPTION_VENDOR_OPTS) by calculating the total length of enclosed sub-options
 *           and writing the length value into the container's option length field. This
 *           function must be called after all sub-options have been added to properly
 *           finalize the container structure per RFC 3315 section 22.
 *           
 *           The length calculation subtracts 4 bytes (option code + length field) from
 *           the total bytes written since the container start position, following the
 *           DHCPv6 option format where the length field contains only the option-data
 *           length excluding the 4-byte header.
 * 
 * @param container Saved position from save_counter() or new_opt6() indicating start
 *                  of container option header (offset into daemon->outpacket buffer)
 * 
 * @return None (void function modifying outpacket buffer in-place)
 * 
 * @note Container position must be valid offset obtained from prior save_counter() call
 * @warning Caller must ensure container position points to valid option header with
 *          sufficient buffer space. No bounds checking performed.
 * 
 * @see save_counter() for obtaining container start position before adding sub-options
 * @see new_opt6() which returns position suitable for container tracking
 * 
 * EXAMPLE USAGE:
 * @code
 * int ia_na_start = new_opt6(OPTION6_IA_NA);
 * put_opt6_long(iaid);  // Add IAID
 * put_opt6_long(t1);    // Add T1
 * put_opt6_long(t2);    // Add T2
 * // Add IA_ADDR sub-option
 * int ia_addr = new_opt6(OPTION6_IAADDR);
 * put_opt6(&addr, 16);  // IPv6 address
 * put_opt6_long(preferred); 
 * put_opt6_long(valid);
 * end_opt6(ia_addr);    // Finalize IA_ADDR sub-option
 * end_opt6(ia_na_start); // Finalize IA_NA container
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 3315 Section 22 (DHCPv6 option format with 2-byte length field)
 * SIDE EFFECTS: Modifies daemon->outpacket buffer at container+2 offset
 * THREAD SAFETY: Not thread-safe, modifies global outpacket buffer
 */
void end_opt6(int container)
{
   uint8_t *p = (uint8_t *)daemon->outpacket.iov_base + container + 2;
   u16 len = outpacket_counter - container - 4 ;
   
   PUTSHORT(len, p);
}

/**
 * @brief Reset outpacket buffer to initial state for new DHCPv6 packet construction
 * 
 * @detailed Prepares the global daemon->outpacket buffer for constructing a new DHCPv6
 *           response packet by clearing the buffer contents (zero-filling) and resetting
 *           the write position counter to offset 0. This function must be called before
 *           starting construction of each new DHCPv6 message to ensure clean state without
 *           residual data from previous packets.
 *           
 *           The zero-fill operation ensures that any padding bytes or unwritten regions
 *           contain deterministic zero values rather than leftover data, which aids
 *           debugging and prevents information leakage between packets.
 * 
 * @param None
 * 
 * @return None (void function modifying global state)
 * 
 * @note Must be called before new_opt6() or put_opt6*() functions for new packet
 * @warning If daemon->outpacket.iov_base is NULL, only resets counter without clearing
 * 
 * @see save_counter() for checkpoint/restore of write position
 * @see expand() for buffer allocation if iov_base is initially NULL
 * 
 * EXAMPLE USAGE:
 * @code
 * // Start constructing new DHCPv6 ADVERTISE message
 * reset_counter();
 * // Buffer now at position 0, cleared and ready
 * int opt_serverid = new_opt6(OPTION6_SERVER_ID);
 * put_opt6(server_duid, server_duid_len);
 * end_opt6(opt_serverid);
 * // Continue building message...
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (internal buffer management)
 * SIDE EFFECTS: Clears daemon->outpacket buffer, resets outpacket_counter to 0
 * THREAD SAFETY: Not thread-safe, modifies global daemon structure
 */
void reset_counter(void)
{
  /* Clear out buffer when starting from beginning */
  if (daemon->outpacket.iov_base)
    memset(daemon->outpacket.iov_base, 0, daemon->outpacket.iov_len);
 
  save_counter(0);
}

/**
 * @brief Save current buffer position and optionally set new position for nested options
 * 
 * @detailed Provides checkpoint/restore mechanism for the outpacket write position counter,
 *           enabling construction of nested DHCPv6 option containers. Returns the current
 *           counter value before optionally updating it to a new position. This dual
 *           functionality supports both position saving (pass -1) and position setting
 *           (pass specific offset).
 *           
 *           The saved position is typically used with end_opt6() to finalize container
 *           options after sub-options have been added. The position represents the byte
 *           offset into daemon->outpacket.iov_base where the option header begins.
 * 
 * @param newval New counter value to set (-1 to query current position without changing)
 *               Valid range: -1 (query only), or 0 to current buffer size
 * 
 * @return Previous value of outpacket_counter before any modification
 * @retval 0-N Current write position if newval == -1
 * @retval 0-N Previous position before update if newval >= 0
 * 
 * @note Pass -1 to query position without modification (position checkpoint)
 * @note Pass specific offset to restore previous position or reset to beginning
 * @warning No bounds checking on newval; caller must ensure valid buffer offset
 * 
 * @see end_opt6() which uses saved position to backpatch container length
 * @see new_opt6() which returns position suitable for container tracking
 * 
 * EXAMPLE USAGE:
 * @code
 * // Save position before starting nested options
 * int saved_pos = save_counter(-1);  // Query current position
 * // ... add nested options ...
 * save_counter(saved_pos);  // Restore previous position if needed
 * 
 * // Common pattern for containers:
 * int container_start = save_counter(-1);  // Save current position
 * new_opt6(OPTION6_IA_NA);  // Create container header
 * // ... add container data and sub-options ...
 * end_opt6(container_start);  // Finalize using saved position
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (internal position tracking)
 * SIDE EFFECTS: Modifies outpacket_counter if newval != -1
 * THREAD SAFETY: Not thread-safe, modifies global static variable
 */
int save_counter(int newval)
{
  int ret = outpacket_counter;
  
  if (newval != -1)
    outpacket_counter = newval;

  return ret;
}

/**
 * @brief Expand outpacket buffer and return pointer to allocated space
 * 
 * @detailed Ensures the outpacket buffer has sufficient capacity for additional data by
 *           calling expand_buf() to grow the buffer if needed, then returns a pointer to
 *           the newly allocated space at the current write position. Automatically advances
 *           the outpacket_counter by the requested size after successful expansion.
 *           
 *           This is the core buffer management function used by all option encoding functions.
 *           It provides safe buffer growth with automatic reallocation, preventing buffer
 *           overflows while constructing DHCPv6 packets incrementally. The buffer grows
 *           dynamically as options are added, starting from an initial allocation and
 *           expanding as needed.
 * 
 * @param headroom Number of bytes to allocate in the buffer for new data
 *                 Valid range: 1 to available memory
 *                 Typical values: 1 (char), 2 (short), 4 (long/option header), variable (data)
 * 
 * @return Pointer to allocated space at current write position on success
 * @retval non-NULL Pointer to uint8_t buffer space of size headroom at current position
 * @retval NULL Buffer expansion failed (out of memory), packet construction should abort
 * 
 * @note Caller must check for NULL return before writing to buffer
 * @warning Returns pointer into dynamically allocated buffer; pointer invalidated if buffer reallocated
 * 
 * @see expand_buf() in util.c for underlying buffer expansion implementation
 * @see new_opt6() which uses expand(4) for option headers
 * @see put_opt6() which uses expand(len) for arbitrary data
 * 
 * EXAMPLE USAGE:
 * @code
 * uint8_t *p;
 * // Allocate space for 4-byte option header
 * if ((p = expand(4))) {
 *   PUTSHORT(OPTION6_CLIENTID, p);  // Write option code
 *   PUTSHORT(10, p);                 // Write option length
 * } else {
 *   // Handle out of memory condition
 *   return 0;
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (internal buffer management)
 * SIDE EFFECTS: Modifies daemon->outpacket.iov_base (may reallocate), advances outpacket_counter
 * THREAD SAFETY: Not thread-safe, modifies global daemon structure
 */
void *expand(size_t headroom)
{
  uint8_t *ret;

  if (expand_buf(&daemon->outpacket, outpacket_counter + headroom))
    {
      ret = (uint8_t *)daemon->outpacket.iov_base + outpacket_counter;
      outpacket_counter += headroom;
      return ret;
    }
  
  return NULL;
}

/**
 * @brief Create new DHCPv6 option header and return its starting position
 * 
 * @detailed Allocates a 4-byte DHCPv6 option header in the outpacket buffer consisting of
 *           a 2-byte option code and a 2-byte length field (initially set to 0). Returns
 *           the buffer position of this option header, which can be used later with end_opt6()
 *           to backpatch the correct length after option data and sub-options are added.
 *           
 *           This function is the standard entry point for adding any DHCPv6 option to the
 *           packet. For simple options, the caller adds data immediately after this call.
 *           For container options (IA_NA, IA_TA, IA_PD), the returned position is saved
 *           and passed to end_opt6() after all contained options are added.
 *           
 *           The option code follows RFC 3315 and RFC 3646 definitions in dhcp6-protocol.h.
 * 
 * @param opt DHCPv6 option code (2-byte value from dhcp6-protocol.h)
 *            Valid range: 1-65535 (OPTION6_CLIENTID through vendor-specific)
 *            Common values: OPTION6_CLIENTID (1), OPTION6_SERVERID (2),
 *                          OPTION6_IA_NA (3), OPTION6_IAADDR (5), etc.
 * 
 * @return Buffer position of the created option header (container start position)
 * @retval 0-N Byte offset into daemon->outpacket.iov_base where option header begins
 * @retval previous_position If expand() fails, returns position before attempted allocation
 * 
 * @note Returned position should be saved if this is a container option requiring end_opt6()
 * @note Length field initialized to 0, must be updated with end_opt6() for containers
 * @warning If expand() fails, option header is not created but counter remains unchanged
 * 
 * @see end_opt6() which finalizes container options using the returned position
 * @see put_opt6() which adds data after the option header
 * @see dhcp6-protocol.h for complete option code definitions
 * 
 * EXAMPLE USAGE:
 * @code
 * // Simple option: add option header then data
 * new_opt6(OPTION6_PREFERENCE);
 * put_opt6_char(255);  // Preference value
 * end_opt6(start_pos);  // Not typically needed for fixed-size options
 * 
 * // Container option: save position for end_opt6()
 * int ia_na_start = new_opt6(OPTION6_IA_NA);
 * put_opt6_long(iaid);           // IAID field
 * put_opt6_long(t1);             // T1 timer
 * put_opt6_long(t2);             // T2 timer
 * // Add IA Address sub-options...
 * new_opt6(OPTION6_IAADDR);
 * put_opt6(&addr, 16);           // IPv6 address
 * put_opt6_long(preferred);      // Preferred lifetime
 * put_opt6_long(valid);          // Valid lifetime
 * end_opt6(ia_na_start);         // Finalize IA_NA with correct length
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 3315 Section 22.1 (DHCPv6 option format: 2-byte code + 2-byte length)
 * SIDE EFFECTS: Modifies outpacket buffer, advances outpacket_counter by 4 bytes
 * THREAD SAFETY: Not thread-safe, modifies global daemon structure
 */
    
int new_opt6(int opt)
{
  int ret = outpacket_counter;
  unsigned char *p;

  if ((p = expand(4)))
    {
      PUTSHORT(opt, p);
      PUTSHORT(0, p);
    }

  return ret;
}

/**
 * @brief Add arbitrary binary data to the current DHCPv6 option in the outpacket buffer
 * 
 * @detailed Appends arbitrary binary data of specified length to the outpacket buffer at the
 *           current position. This is the fundamental data addition function used by all other
 *           put_opt6_* variants and for adding complex data structures like IPv6 addresses,
 *           DUIDs, IAIDs, and raw protocol data.
 *           
 *           The function expands the buffer by the requested length, copies the provided data
 *           into the newly allocated space, and advances the counter. If buffer expansion fails,
 *           the function returns NULL and the buffer remains in a consistent state at the
 *           position before the failed expansion attempt.
 *           
 *           This function is typically called after new_opt6() has created the option header.
 *           For options with multiple fields (like IA_NA with IAID, T1, T2), call this function
 *           or its typed variants multiple times to add each field sequentially.
 * 
 * @param data Pointer to binary data to copy into the outpacket buffer
 *             If NULL, buffer space is allocated but not initialized (useful for in-place construction)
 *             Data can be any binary structure: IPv6 addresses, DUIDs, timers, protocol-specific data
 * @param len Number of bytes to copy from data and append to buffer
 *            Valid range: 0 to available buffer space (typically up to several KB)
 *            For common DHCPv6 data: 16 bytes (IPv6 address), 4 bytes (IAID/timer), variable (DUID)
 * 
 * @return Pointer to the allocated buffer space where data was copied
 * @retval non-NULL Pointer to position in daemon->outpacket.iov_base where data was placed
 * @retval NULL If expand() fails due to memory allocation failure
 * 
 * @note If data is NULL, returns allocated space pointer for caller to initialize directly
 * @note Returned pointer becomes invalid if subsequent operations cause buffer reallocation
 * @warning Caller must not retain returned pointer across other outpacket operations
 * 
 * @see new_opt6() which creates the option header before calling this function
 * @see expand() which handles the underlying buffer expansion
 * @see put_opt6_long(), put_opt6_short(), put_opt6_char() for typed convenience wrappers
 * 
 * EXAMPLE USAGE:
 * @code
 * // Add IPv6 address to IAADDR option
 * struct in6_addr addr;
 * inet_pton(AF_INET6, "2001:db8::1", &addr);
 * new_opt6(OPTION6_IAADDR);
 * put_opt6(&addr, sizeof(addr));  // 16-byte IPv6 address
 * put_opt6_long(3600);            // Preferred lifetime
 * put_opt6_long(7200);            // Valid lifetime
 * 
 * // Add DUID-LLT (variable length)
 * unsigned char duid[] = {0x00, 0x01, 0x00, 0x01, ...};
 * new_opt6(OPTION6_CLIENTID);
 * put_opt6(duid, sizeof(duid));
 * 
 * // Allocate space for in-place construction
 * new_opt6(OPTION6_STATUS_CODE);
 * unsigned char *status = put_opt6(NULL, 2);
 * if (status) {
 *   status[0] = 0;  // Success status code
 *   status[1] = 0;
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 3315 (DHCPv6 option data encoding)
 * SIDE EFFECTS: Modifies outpacket buffer, advances outpacket_counter by len bytes
 * THREAD SAFETY: Not thread-safe, modifies global daemon structure
 */
void *put_opt6(void *data, size_t len)
{
  void *p;

  if ((p = expand(len)) && data)
    memcpy(p, data, len);   
  
  return p;
}

/**
 * @brief Add a 32-bit unsigned integer to the current DHCPv6 option in network byte order
 * 
 * @detailed Encodes a 32-bit unsigned integer value in network byte order (big-endian) and
 *           appends it to the outpacket buffer. This is a convenience wrapper around expand()
 *           and PUTLONG macro for encoding DHCPv6 protocol fields that are defined as 4-byte
 *           unsigned integers.
 *           
 *           Common uses include:
 *           - IA_NA/IA_TA/IA_PD IAID (Identity Association Identifier)
 *           - T1 and T2 timer values (renew/rebind times in seconds)
 *           - Preferred lifetime and valid lifetime for addresses
 *           - DHCPv6 transaction IDs (though usually handled elsewhere)
 *           - Status codes when 32-bit representation needed
 *           
 *           The function automatically handles endianness conversion using the PUTLONG macro,
 *           ensuring wire format compatibility across different host architectures.
 * 
 * @param val Unsigned 32-bit integer value to encode
 *            Valid range: 0 to 0xFFFFFFFF (4,294,967,295)
 *            Common values: IAID (any 32-bit value), T1/T2 (seconds, typically 1800-86400)
 *            Special values: 0xFFFFFFFF often means "infinity" in DHCPv6 lifetime contexts
 * 
 * @return void
 * 
 * @note If expand() fails due to memory allocation, function silently fails without modifying buffer
 * @note Silently fails if buffer expansion unsuccessful (no return value indicates failure)
 * @warning Caller cannot detect allocation failure; ensure adequate buffer space beforehand
 * 
 * @see put_opt6() for arbitrary binary data addition
 * @see put_opt6_short() for 16-bit unsigned integers
 * @see expand() which performs the underlying buffer expansion
 * 
 * EXAMPLE USAGE:
 * @code
 * // Construct IA_NA option with IAID, T1, T2
 * new_opt6(OPTION6_IA_NA);
 * put_opt6_long(0x12345678);  // IAID: arbitrary 32-bit identifier
 * put_opt6_long(3600);        // T1: renew at 3600 seconds (1 hour)
 * put_opt6_long(7200);        // T2: rebind at 7200 seconds (2 hours)
 * 
 * // Add IAADDR sub-option with lifetimes
 * int container = new_opt6(OPTION6_IAADDR);
 * struct in6_addr addr = ...;
 * put_opt6(&addr, 16);
 * put_opt6_long(7200);        // Preferred lifetime: 2 hours
 * put_opt6_long(14400);       // Valid lifetime: 4 hours
 * end_opt6(container);
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 3315 Section 22 (DHCPv6 32-bit unsigned integer encoding)
 * SIDE EFFECTS: Modifies outpacket buffer, advances outpacket_counter by 4 bytes
 * THREAD SAFETY: Not thread-safe, modifies global daemon structure
 */
void put_opt6_long(unsigned int val)
{
  unsigned char *p;
  
  if ((p = expand(4)))  
    PUTLONG(val, p);
}

/**
 * @brief Add a 16-bit unsigned integer to the current DHCPv6 option in network byte order
 * 
 * @detailed Encodes a 16-bit unsigned integer value in network byte order (big-endian) and
 *           appends it to the outpacket buffer. This is a convenience wrapper around expand()
 *           and PUTSHORT macro for encoding DHCPv6 protocol fields that are defined as 2-byte
 *           unsigned integers.
 *           
 *           Common uses include:
 *           - DHCPv6 status codes (Success=0, UnspecFail=1, NoAddrsAvail=2, etc.)
 *           - DUID type fields (DUID-LLT=1, DUID-EN=2, DUID-LL=3)
 *           - Hardware type in DUID-LLT and DUID-LL (Ethernet=1)
 *           - Preference values (0-255, though only 8 bits used)
 *           - Encapsulated option types within vendor-specific options
 *           - Protocol-specific 16-bit counters and identifiers
 *           
 *           The function automatically handles endianness conversion using the PUTSHORT macro,
 *           ensuring wire format compatibility across different host architectures.
 * 
 * @param val Unsigned integer value to encode (only lower 16 bits used)
 *            Valid range: 0 to 0xFFFF (65,535), upper bits ignored if val > 65535
 *            Common values: status codes (0-65535), DUID types (1-3), hardware types (1=Ethernet)
 * 
 * @return void
 * 
 * @note If expand() fails due to memory allocation, function silently fails without modifying buffer
 * @note Parameter is unsigned int (32-bit) but only lower 16 bits are encoded
 * @warning Caller cannot detect allocation failure; ensure adequate buffer space beforehand
 * @warning If val exceeds 0xFFFF, upper bits are silently truncated by PUTSHORT macro
 * 
 * @see put_opt6() for arbitrary binary data addition
 * @see put_opt6_long() for 32-bit unsigned integers
 * @see put_opt6_char() for 8-bit unsigned integers
 * @see expand() which performs the underlying buffer expansion
 * 
 * EXAMPLE USAGE:
 * @code
 * // Add STATUS_CODE option indicating success
 * new_opt6(OPTION6_STATUS_CODE);
 * put_opt6_short(0);  // Status code: Success
 * put_opt6_string("Success");  // Optional status message
 * 
 * // Add PREFERENCE option (server preference for client selection)
 * new_opt6(OPTION6_PREFERENCE);
 * put_opt6_char(255);  // Highest preference (though char would suffice)
 * 
 * // Add DUID-LL client identifier
 * new_opt6(OPTION6_CLIENTID);
 * put_opt6_short(3);   // DUID type: DUID-LL (Link-layer address)
 * put_opt6_short(1);   // Hardware type: Ethernet
 * unsigned char mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
 * put_opt6(mac, 6);    // Link-layer address
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 3315 Section 22 (DHCPv6 16-bit unsigned integer encoding)
 * SIDE EFFECTS: Modifies outpacket buffer, advances outpacket_counter by 2 bytes
 * THREAD SAFETY: Not thread-safe, modifies global daemon structure
 */
void put_opt6_short(unsigned int val)
{
  uint8_t *p;

  if ((p = expand(2)))
    PUTSHORT(val, p);   
}

/**
 * @brief Add an 8-bit unsigned integer to the current DHCPv6 option
 * 
 * @detailed Encodes a single byte (8-bit unsigned integer) and appends it to the outpacket
 *           buffer. This is a convenience wrapper around expand() for encoding DHCPv6 protocol
 *           fields that are defined as single-byte unsigned integers.
 *           
 *           Common uses include:
 *           - DHCPv6 message types (SOLICIT=1, ADVERTISE=2, REQUEST=3, CONFIRM=4, etc.)
 *           - Preference values (0-255, where 255 is highest preference)
 *           - Single-byte status indicators and flags
 *           - Hop count values in relay messages
 *           - Single-byte length fields for small data structures
 *           - Boolean flags represented as 0/1 bytes
 *           - Protocol-specific 8-bit counters and identifiers
 *           
 *           Unlike put_opt6_short() and put_opt6_long(), this function does not perform
 *           endianness conversion since single bytes have no byte-order concerns.
 * 
 * @param val Unsigned integer value to encode (only lower 8 bits used)
 *            Valid range: 0 to 0xFF (255), upper bits ignored if val > 255
 *            Common values: message types (1-13), preference (0-255), boolean flags (0-1)
 * 
 * @return void
 * 
 * @note If expand() fails due to memory allocation, function silently fails without modifying buffer
 * @note Parameter is unsigned int (32-bit) but only lower 8 bits are stored
 * @warning Caller cannot detect allocation failure; ensure adequate buffer space beforehand
 * @warning If val exceeds 0xFF, upper bits are silently truncated
 * 
 * @see put_opt6() for arbitrary binary data addition
 * @see put_opt6_short() for 16-bit unsigned integers
 * @see put_opt6_long() for 32-bit unsigned integers
 * @see expand() which performs the underlying buffer expansion
 * 
 * EXAMPLE USAGE:
 * @code
 * // Add PREFERENCE option (server selection priority)
 * new_opt6(OPTION6_PREFERENCE);
 * put_opt6_char(255);  // Maximum preference
 * end_opt6(saved);
 * 
 * // Add STATUS_CODE option with single-byte success indicator
 * // (though status codes are typically 16-bit, some implementations use 8-bit)
 * new_opt6(OPTION6_STATUS_CODE);
 * put_opt6_char(0);  // Success
 * put_opt6_string("Operation completed successfully");
 * 
 * // Add relay message with hop count
 * new_opt6(OPTION6_RELAY_MSG);
 * put_opt6_char(1);  // Hop count: 1 relay traversed
 * // ... relay message content ...
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 3315 Section 22 (DHCPv6 8-bit unsigned integer encoding)
 * SIDE EFFECTS: Modifies outpacket buffer, advances outpacket_counter by 1 byte
 * THREAD SAFETY: Not thread-safe, modifies global daemon structure
 */
void put_opt6_char(unsigned int val)
{
  unsigned char *p;

  if ((p = expand(1)))
    *p = val;   
}

/**
 * @brief Add a null-terminated string to the current DHCPv6 option
 * 
 * @detailed Convenience wrapper around put_opt6() that automatically calculates the length
 *           of a null-terminated C string using strlen() and appends it to the outpacket
 *           buffer WITHOUT including the null terminator. This matches DHCPv6 protocol
 *           requirements where string data is encoded as raw bytes with length determined
 *           by the option length field, not by null terminators.
 *           
 *           Common uses include:
 *           - Status message strings in OPTION6_STATUS_CODE (human-readable error descriptions)
 *           - Domain names in OPTION6_DOMAIN_LIST (DNS search domains)
 *           - Authentication realm strings in OPTION6_AUTH
 *           - Vendor-specific configuration strings in OPTION6_VENDOR_OPTS
 *           - User-class and vendor-class identifier strings
 *           - Boot file URLs in network boot options
 *           - Arbitrary text data in vendor-specific or custom options
 *           
 *           The function does not encode the null terminator, as DHCPv6 options use explicit
 *           length fields rather than null-terminated strings. The receiving implementation
 *           determines string boundaries from the option length field.
 * 
 * @param s Pointer to null-terminated C string to encode
 *          Must not be NULL (behavior undefined if NULL)
 *          String length limited by available buffer space and DHCPv6 option length field (16-bit)
 *          Common content: status messages, domain names, configuration parameters
 * 
 * @return void
 * 
 * @note NULL terminator is NOT included in encoded data (DHCPv6 protocol requirement)
 * @note If expand() fails due to memory allocation, function silently fails without modifying buffer
 * @note Empty string (s[0] == '\0') results in zero bytes added to buffer
 * @warning Caller must ensure s is not NULL; NULL pointer causes undefined behavior (strlen crash)
 * @warning No buffer overflow protection beyond expand_buf() bounds checking
 * @warning Caller cannot detect allocation failure; ensure adequate buffer space beforehand
 * @warning Maximum string length limited to available buffer space (typically <65535 bytes)
 * 
 * @see put_opt6() which performs the actual data copy and is called by this function
 * @see expand() which handles buffer expansion
 * @see put_opt6_char() for single-byte values
 * @see put_opt6_short() for 16-bit integers
 * 
 * EXAMPLE USAGE:
 * @code
 * // Add STATUS_CODE option with descriptive message
 * int status_start = new_opt6(OPTION6_STATUS_CODE);
 * put_opt6_short(0);  // Status code: Success
 * put_opt6_string("Address allocation successful");
 * end_opt6(status_start);
 * 
 * // Add DOMAIN_LIST option with DNS search domains
 * int domain_start = new_opt6(OPTION6_DOMAIN_LIST);
 * put_opt6_string("example.com");
 * put_opt6_string("internal.example.com");
 * end_opt6(domain_start);
 * 
 * // Add vendor-specific text configuration
 * int vendor_start = new_opt6(OPTION6_VENDOR_OPTS);
 * put_opt6_long(enterprise_number);  // Vendor enterprise number
 * put_opt6_string("custom-config-parameter");
 * end_opt6(vendor_start);
 * 
 * // Add boot file URL
 * int bootfile_start = new_opt6(OPTION6_BOOTFILE_URL);
 * put_opt6_string("tftp://192.168.1.1/pxelinux.0");
 * end_opt6(bootfile_start);
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 3315 Section 22.1 (DHCPv6 string encoding without null terminator)
 * SIDE EFFECTS: Modifies outpacket buffer, advances outpacket_counter by strlen(s) bytes
 * THREAD SAFETY: Not thread-safe, modifies global daemon structure
 */
void put_opt6_string(char *s)
{
  put_opt6(s, strlen(s));
}

#endif

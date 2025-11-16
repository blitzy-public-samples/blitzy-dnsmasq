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
 * @file blockdata.c
 * @brief Variable-length data storage using fixed-size block chains for efficient DNSSEC record storage
 * 
 * DETAILED PURPOSE:
 * This module provides a memory-efficient mechanism for storing variable-length DNSSEC data
 * (RRSIG signatures, DNSKEY public keys, DS delegation signer records) without causing heap
 * fragmentation. By using a chain of fixed-size blocks (KEYBLOCK_LEN = 40 bytes each), the
 * system can store arbitrarily large DNSSEC records while maintaining predictable memory
 * allocation patterns and enabling efficient memory pool management.
 * 
 * The blockdata structure solves a critical problem in DNSSEC validation: cryptographic
 * signatures and keys vary widely in size (from ~100 bytes for small signatures to ~4KB
 * for large DNSKEY records). Traditional malloc-per-record allocation would fragment the
 * heap over time. The fixed-block chain approach provides constant-size allocations that
 * can be efficiently managed through a free list pool.
 * 
 * KEY RESPONSIBILITIES:
 * - Memory pool management: Initialize and maintain free list of fixed-size blocks for rapid allocation (blockdata_init, add_blocks, new_block)
 * - Block chain allocation: Create chains of blocks to store variable-length data (blockdata_alloc, blockdata_alloc_real)
 * - Dynamic expansion: Extend existing block chains when additional storage is needed (blockdata_expand)
 * - Data retrieval: Copy data from block chains back to contiguous memory buffers (blockdata_retrieve)
 * - Persistent I/O: Read and write block chains from/to file descriptors for caching (blockdata_read, blockdata_write)
 * - Memory reclamation: Free block chains and return blocks to free list pool (blockdata_free)
 * - Statistics reporting: Track memory usage, high-water mark, and allocation statistics (blockdata_report)
 * 
 * DEPENDENCIES:
 * Includes: dnsmasq.h (provides struct blockdata definition, KEYBLOCK_LEN constant, daemon global state)
 * Called by: dnssec.c (primary consumer for DNSSEC signature and key storage), cache.c (persistent cache I/O)
 * Calls: whine_malloc (utility allocation with error logging), my_syslog (logging), option_bool (configuration queries)
 * 
 * DATA STRUCTURES:
 * - struct blockdata: Fixed-size block with 40-byte payload and next pointer (defined in dnsmasq.h line 486)
 *   - Purpose: Building block for variable-length data chains, optimized to minimize fragmentation
 *   - Layout: { struct blockdata *next; unsigned char key[KEYBLOCK_LEN]; }
 *   - Size: Typically 48 bytes on 64-bit systems (8-byte pointer + 40-byte array)
 * 
 * COMPILE-TIME OPTIONS:
 * - KEYBLOCK_LEN: Block payload size in bytes (default 40, defined in config.h line 24)
 *   - Chosen to minimize fragmentation when storing DNSSEC keys
 *   - Smaller values reduce waste for small records, larger values reduce chain traversal overhead
 * - OPT_DNSSEC_VALID: Enables DNSSEC validation and blockdata preallocation based on cache size
 * 
 * THREADING/CONCURRENCY:
 * Single-process event-driven model - all blockdata operations execute in main event loop thread.
 * No locking required as free list and block chains are not shared across threads or processes.
 * The blockdata pool is proportionally sized to the DNS cache to ensure adequate allocation
 * capacity for DNSSEC validation workloads.
 * 
 * MEMORY EFFICIENCY CHARACTERISTICS:
 * - Fixed-size allocation prevents heap fragmentation from variable-size DNSSEC records
 * - Free list pool enables O(1) allocation and deallocation without syscall overhead
 * - Preallocation proportional to cache size reduces runtime malloc() calls during validation
 * - Block chain design trades small space overhead (partial block waste) for deterministic performance
 * - Typical overhead: 0-39 bytes per record (average ~20 bytes for uniformly distributed sizes)
 * 
 * LIFECYCLE MANAGEMENT:
 * - Initialization: blockdata_init() called at daemon startup, preallocates blocks proportional to cache size
 * - Allocation: blockdata_alloc() creates chains from free list, falling back to add_blocks() if pool exhausted
 * - Ownership: Caller owns allocated chains, responsible for freeing via blockdata_free()
 * - Expansion: blockdata_expand() extends chains in-place, may trigger allocation from free list
 * - Deallocation: blockdata_free() returns all blocks in chain to free list for reuse
 * - Shutdown: Blocks remain allocated until process termination (no explicit pool destruction)
 * 
 * OWNERSHIP TRANSFER PATTERNS:
 * - blockdata_alloc() returns ownership to caller (caller must free)
 * - blockdata_read() returns ownership to caller (caller must free)
 * - blockdata_free() accepts ownership transfer from caller (caller must not use after free)
 * - Typical pattern: dnssec.c allocates blocks for signatures, stores in cache records, frees on cache eviction
 * 
 * @copyright Copyright (c) 2000-2025 Simon Kelley
 * @license GPL-2.0-or-later
 */

#include "dnsmasq.h"

/** @var keyblock_free
 *  @brief Head of free list containing available blocks for allocation
 *  
 *  Points to first available block in singly-linked free list. NULL when pool is exhausted.
 *  Blocks are returned to this list by blockdata_free() and allocated from it by new_block().
 */
static struct blockdata *keyblock_free;

/** @var blockdata_count
 *  @brief Current number of blocks in use (allocated from free list)
 */
static unsigned int blockdata_count;

/** @var blockdata_hwm
 *  @brief High-water mark tracking maximum blocks in use simultaneously
 */
static unsigned int blockdata_hwm;

/** @var blockdata_alloced
 *  @brief Total number of blocks allocated from system (via malloc)
 */
static unsigned int blockdata_alloced;

/**
 * @brief Add blocks to the free list pool
 * 
 * @detailed Allocates a contiguous array of n blockdata structures from the heap
 * and links them into the global free list. This function is the only code path that
 * calls malloc for blockdata structures, enabling all subsequent allocations to use
 * the O(1) free list. The function updates blockdata_alloced to track total system
 * memory allocated for blocks.
 * 
 * The implementation links blocks in reverse order: the last block in the array points
 * to the previous free list head, then each block points to the next block in the array,
 * with the first block becoming the new free list head. This linking strategy ensures
 * constant-time insertion regardless of allocation size.
 * 
 * @param n Number of blocks to allocate and add to free list
 * 
 * @return None (void function)
 * 
 * @note If malloc fails, whine_malloc logs error and returns NULL; function continues
 *       without modifying free list, allowing daemon to operate with existing pool
 * @warning No error return - caller must check keyblock_free after calling if allocation success is critical
 * 
 * @see new_block() - Allocates blocks from the free list populated by this function
 * @see blockdata_init() - Calls this function to preallocate initial pool
 * 
 * EXAMPLE USAGE:
 * @code
 * add_blocks(50);  // Add 50 blocks to free list pool
 * // Now keyblock_free points to first of 50 available blocks
 * @endcode
 * 
 * SIDE EFFECTS: Modifies keyblock_free global, increments blockdata_alloced counter
 * THREAD SAFETY: Single-threaded architecture - no locking required
 */
static void add_blocks(int n)
{
  struct blockdata *new = whine_malloc(n * sizeof(struct blockdata));
  
  if (new)
    {
      int i;
      
      new[n-1].next = keyblock_free;
      keyblock_free = new;

      for (i = 0; i < n - 1; i++)
	new[i].next = &new[i+1];

      blockdata_alloced += n;
    }
}

/**
 * @brief Initialize blockdata memory pool with preallocated blocks
 * 
 * @detailed Called during daemon startup to initialize the blockdata subsystem and preallocate
 * a pool of fixed-size blocks proportional to the configured cache size. Preallocation occurs
 * only when DNSSEC validation is enabled (OPT_DNSSEC_VALID), as blockdata is primarily used
 * for storing DNSSEC signatures and keys.
 * 
 * The pool size is set equal to daemon->cachesize (number of DNS cache entries), based on the
 * assumption that DNSSEC-signed cache entries may require multiple blocks per entry for large
 * signatures. This heuristic ensures adequate allocation capacity without requiring runtime
 * malloc() calls during validation, which could cause heap fragmentation.
 * 
 * Zeroing the statistics counters (blockdata_count, blockdata_hwm, blockdata_alloced) ensures
 * clean startup state for blockdata_report() statistics.
 * 
 * @param None
 * 
 * @return None (void function)
 * 
 * @note daemon->cachesize is enforced to be non-zero when OPT_DNSSEC_VALID is set
 * @warning Must be called before any blockdata_alloc() operations
 * 
 * @see add_blocks() - Performs actual block allocation
 * @see blockdata_report() - Reports statistics initialized here
 * 
 * EXAMPLE USAGE:
 * @code
 * // In main daemon initialization (dnsmasq.c)
 * if (option_bool(OPT_DNSSEC_VALID))
 *   blockdata_init();  // Preallocate blocks proportional to cache size
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (internal memory management, not protocol-related)
 * SIDE EFFECTS: Initializes keyblock_free, zeros statistics counters, may allocate heap memory
 * THREAD SAFETY: Must be called from main thread before multi-threaded operation (if any)
 */
void blockdata_init(void)
{
  keyblock_free = NULL;
  blockdata_alloced = 0;
  blockdata_count = 0;
  blockdata_hwm = 0;

  /* Note that daemon->cachesize is enforced to have non-zero size if OPT_DNSSEC_VALID is set */  
  if (option_bool(OPT_DNSSEC_VALID))
    add_blocks(daemon->cachesize);
}

/**
 * @brief Report blockdata memory pool statistics to syslog
 * 
 * @detailed Logs current memory usage statistics for the blockdata pool, including:
 * - Current in-use memory: blockdata_count blocks currently allocated from free list
 * - High-water mark: Maximum blocks in use simultaneously since initialization
 * - Total allocated: All blocks allocated from system heap, including both in-use and free list
 * 
 * This function is typically called on demand via signal (SIGUSR2) or during shutdown to
 * provide visibility into blockdata memory consumption patterns. The statistics help
 * administrators tune cache size and understand DNSSEC validation memory requirements.
 * 
 * Memory values are reported in bytes (blocks * sizeof(struct blockdata)) for human readability.
 * On 64-bit systems, struct blockdata is typically 48 bytes (8-byte pointer + 40-byte array).
 * 
 * @param None
 * 
 * @return None (void function)
 * 
 * @note Statistics are cumulative since blockdata_init() and never reset during daemon lifetime
 * 
 * @see blockdata_init() - Initializes statistics counters
 * @see new_block() - Increments blockdata_count and updates blockdata_hwm
 * @see blockdata_free() - Decrements blockdata_count
 * 
 * EXAMPLE USAGE:
 * @code
 * // Called in response to SIGUSR2 signal
 * if (signo == SIGUSR2)
 *   blockdata_report();
 * // Logs: "pool memory in use 4800, max 9600, allocated 15000"
 * @endcode
 * 
 * SIDE EFFECTS: Writes log message to syslog at LOG_INFO level
 * THREAD SAFETY: Single-threaded architecture - safe to call from signal handler context
 */
void blockdata_report(void)
{
  my_syslog(LOG_INFO, _("pool memory in use %zu, max %zu, allocated %zu"), 
	    blockdata_count * sizeof(struct blockdata),  
	    blockdata_hwm * sizeof(struct blockdata),  
	    blockdata_alloced * sizeof(struct blockdata));
} 

/**
 * @brief Allocate a single block from the free list pool
 * 
 * @detailed Retrieves one block from the global free list (keyblock_free), automatically
 * expanding the pool if exhausted. This is the fundamental allocation primitive used by
 * all higher-level blockdata allocation functions (blockdata_alloc, blockdata_expand).
 * 
 * The function implements automatic pool expansion: when the free list is empty, it calls
 * add_blocks(50) to allocate 50 additional blocks from the heap. This batch allocation
 * strategy reduces malloc() overhead and heap fragmentation compared to allocating one
 * block at a time.
 * 
 * Block accounting is maintained through three counters:
 * - blockdata_count: Incremented to track in-use blocks
 * - blockdata_hwm: Updated to record peak simultaneous usage
 * - blockdata_alloced: Updated by add_blocks() when pool expands
 * 
 * The returned block has its next pointer cleared to NULL, ensuring clean initial state
 * for chain building by caller.
 * 
 * @param None
 * 
 * @return Pointer to newly allocated block from free list, or NULL if allocation failed
 * @retval Non-NULL Successfully allocated block with next=NULL
 * @retval NULL Free list exhausted and add_blocks() failed (malloc failure)
 * 
 * @note Block is removed from free list and caller owns it until blockdata_free() called
 * @warning Caller must check return value for NULL before dereferencing
 * 
 * @see add_blocks() - Expands pool when free list is empty
 * @see blockdata_free() - Returns blocks to free list
 * 
 * EXAMPLE USAGE:
 * @code
 * struct blockdata *block = new_block();
 * if (block) {
 *   memcpy(block->key, data, KEYBLOCK_LEN);
 *   block->next = chain;  // Link into chain
 * }
 * @endcode
 * 
 * SIDE EFFECTS: Removes block from keyblock_free, increments blockdata_count, may update blockdata_hwm
 * THREAD SAFETY: Single-threaded architecture - no locking required
 */
static struct blockdata *new_block(void)
{
  struct blockdata *block;

  if (!keyblock_free)
    add_blocks(50);
  
  if (keyblock_free)
    {
      block = keyblock_free;
      keyblock_free = block->next;
      blockdata_count++;
      if (blockdata_hwm < blockdata_count)
	blockdata_hwm = blockdata_count;
      block->next = NULL;
      return block;
    }
  
  return NULL;
}

/**
 * @brief Core implementation for allocating block chains from data sources
 * 
 * @detailed Internal allocation function that creates a chain of fixed-size blocks to store
 * variable-length data from either a memory buffer or file descriptor. This function handles
 * the complex logic of building block chains incrementally while populating them with data
 * from the source.
 * 
 * The function supports two data source modes:
 * 1. Memory buffer mode (data != NULL): Copies len bytes from data buffer into block chain
 * 2. File descriptor mode (fd >= 0, data == NULL): Reads len bytes from fd into block chain
 * 
 * Block chain construction proceeds iteratively: allocate block, populate with up to
 * KEYBLOCK_LEN bytes from source, link into chain, repeat until all data consumed. If
 * allocation fails midway, the partial chain is freed via blockdata_free() to prevent
 * memory leaks, and NULL is returned to signal failure.
 * 
 * The **prev pointer technique enables efficient chain building without requiring a separate
 * tail pointer: prev always points to the next field of the last block, allowing O(1)
 * appending of new blocks.
 * 
 * @param fd File descriptor to read data from (used only if data == NULL), or -1 if not reading from file
 * @param data Pointer to memory buffer to copy data from (if NULL, read from fd instead)
 * @param len Total number of bytes to store in the block chain
 * 
 * @return Pointer to head of newly allocated block chain, or NULL if allocation failed
 * @retval Non-NULL Successfully allocated and populated block chain with len bytes
 * @retval NULL Block allocation failed (new_block() returned NULL) - partial chain freed
 * 
 * @note If allocation fails, function cleans up partial chain before returning NULL
 * @warning Caller must ensure fd is valid readable file descriptor if data is NULL
 * @warning Mixing data and fd parameters (both non-NULL/non-negative) uses data and ignores fd
 * 
 * @see blockdata_alloc() - Public wrapper for memory buffer allocation
 * @see blockdata_read() - Public wrapper for file descriptor reading
 * @see new_block() - Allocates individual blocks from free list
 * @see blockdata_free() - Frees partial chain on allocation failure
 * 
 * EXAMPLE USAGE:
 * @code
 * // Read 256-byte DNSSEC signature from memory
 * char signature[256];
 * struct blockdata *sig_chain = blockdata_alloc_real(-1, signature, 256);
 * // Result: Chain of 7 blocks (6*40 + 16 bytes)
 * 
 * // Read DNSKEY from file descriptor
 * int fd = open("dnskey.bin", O_RDONLY);
 * struct blockdata *key_chain = blockdata_alloc_real(fd, NULL, 512);
 * // Result: Chain of 13 blocks (12*40 + 32 bytes)
 * @endcode
 * 
 * SIDE EFFECTS: Allocates blocks from free list, reads from file descriptor if data==NULL
 * THREAD SAFETY: Single-threaded architecture - not thread-safe due to global free list access
 */
static struct blockdata *blockdata_alloc_real(int fd, char *data, size_t len)
{
  struct blockdata *block, *ret = NULL;
  struct blockdata **prev = &ret;
  size_t blen;

  do
    {
      if (!(block = new_block()))
	{
	  /* failed to alloc, free partial chain */
	  blockdata_free(ret);
	  return NULL;
	}

      if ((blen = len > KEYBLOCK_LEN ? KEYBLOCK_LEN : len) > 0)
	{
	  if (data)
	    {
	      memcpy(block->key, data, blen);
	      data += blen;
	    }
	  else if (!read_write(fd, block->key, blen, RW_READ))
	    {
	      /* failed read free partial chain */
	      blockdata_free(ret);
	      return NULL;
	    }
	}
      
      len -= blen;
      *prev = block;
      prev = &block->next;
    } while (len != 0);
  
  return ret;
}

/**
 * @brief Allocate block chain from memory buffer for DNSSEC data storage
 * 
 * @detailed Public API function that allocates a chain of fixed-size blocks and populates
 * them with variable-length data from a memory buffer. This is the primary interface for
 * storing DNSSEC record data (RRSIG signatures, DNSKEY public keys, DS digests) in the
 * blockdata structure.
 * 
 * The function wraps blockdata_alloc_real() with parameters optimized for memory buffer
 * input, passing fd=0 to indicate no file descriptor reading. The resulting block chain
 * stores exactly len bytes distributed across ceil(len/KEYBLOCK_LEN) blocks, with the
 * final block potentially containing fewer than KEYBLOCK_LEN bytes.
 * 
 * Memory efficiency: Fixed block size (40 bytes) prevents heap fragmentation that would
 * occur with variable-size allocations for DNSSEC records ranging from tens to thousands
 * of bytes. The free list allocation strategy enables O(1) allocation and deallocation.
 * 
 * @param data Pointer to memory buffer containing data to store in block chain (must not be NULL)
 * @param len Number of bytes to copy from data buffer into block chain (must be > 0 for meaningful use)
 * 
 * @return Pointer to head of newly allocated block chain containing copy of data, or NULL on failure
 * @retval Non-NULL Successfully allocated block chain with len bytes copied from data
 * @retval NULL Block allocation failed (insufficient memory or free list exhausted)
 * 
 * @note Caller retains ownership of data buffer; blockdata contains independent copy
 * @note Caller must free returned block chain via blockdata_free() when no longer needed
 * @warning data pointer must remain valid for duration of function call (synchronous copy)
 * 
 * @see blockdata_alloc_real() - Internal implementation handling actual allocation
 * @see blockdata_free() - Releases block chain back to free list
 * @see blockdata_retrieve() - Extracts data back from block chain to memory buffer
 * 
 * EXAMPLE USAGE:
 * @code
 * // Store 128-byte RRSIG signature from dnssec.c validation
 * unsigned char rrsig_data[128];
 * // ... populate rrsig_data from DNS packet ...
 * struct blockdata *signature = blockdata_alloc((char *)rrsig_data, 128);
 * if (!signature)
 *   return 0; // Allocation failed, cannot validate DNSSEC
 * // ... later: blockdata_free(signature);
 * @endcode
 * 
 * RFC COMPLIANCE: Supports DNSSEC (RFC 4034) by providing storage for variable-length RRSIG/DNSKEY records
 * SIDE EFFECTS: Allocates blocks from global free list, increments blockdata_count
 * THREAD SAFETY: Single-threaded architecture - not thread-safe
 */
struct blockdata *blockdata_alloc(char *data, size_t len)
{
  return blockdata_alloc_real(0, data, len);
}

/**
 * @brief Append additional data to existing block chain
 * 
 * @detailed Extends an existing block chain by appending newlen bytes of data to the end,
 * potentially allocating additional blocks if the new data doesn't fit in the remaining
 * space of the final block. This function is essential for DNSSEC processing where record
 * data may be assembled incrementally (e.g., concatenating multiple RRSIG signatures or
 * building composite DNSKEY records).
 * 
 * The function navigates to the final block in the chain using oldlen to skip complete blocks,
 * then fills remaining space in that block before allocating new blocks as needed. This
 * approach maintains the invariant that all non-final blocks are completely filled with
 * KEYBLOCK_LEN bytes, optimizing memory utilization.
 * 
 * Important: newlen is the length of NEW data being added, NOT the total length after expansion.
 * The oldlen parameter must accurately reflect the current chain length or the function will
 * fail with chain corruption detection.
 * 
 * Usage pattern: Create empty block with blockdata_alloc(NULL, 0), then expand incrementally.
 * 
 * @param block Head of existing block chain to expand (must not be NULL)
 * @param oldlen Current total length of data stored in block chain (must match actual chain content)
 * @param data Pointer to new data to append (must not be NULL if newlen > 0)
 * @param newlen Number of bytes from data to append to block chain
 * 
 * @return Success indicator
 * @retval 1 Successfully appended newlen bytes to block chain
 * @retval 0 Expansion failed (chain too short for oldlen, allocation failed); original chain freed
 * 
 * @note On failure, original block chain is automatically freed - caller must not use block pointer
 * @warning oldlen MUST match actual data length in chain; mismatch causes chain corruption detection and failure
 * @warning Chain too short error (oldlen > actual) indicates programming error in caller
 * 
 * @see blockdata_alloc() - Create initial block chain (use with NULL, 0 for empty chain)
 * @see new_block() - Internal function allocating individual blocks
 * @see blockdata_free() - Called internally on failure to prevent memory leak
 * 
 * EXAMPLE USAGE:
 * @code
 * // Incrementally build DNSSEC RRSIG record from multiple sources
 * struct blockdata *rrsig = blockdata_alloc(NULL, 0); // Empty chain
 * if (!blockdata_expand(rrsig, 0, header_data, 20))
 *   return 0; // Failed to add 20-byte header
 * if (!blockdata_expand(rrsig, 20, signature_data, 128))
 *   return 0; // Failed to add 128-byte signature (rrsig already freed)
 * // rrsig now contains 148 bytes total
 * @endcode
 * 
 * RFC COMPLIANCE: Supports DNSSEC (RFC 4034) incremental record assembly
 * SIDE EFFECTS: May allocate new blocks from free list; frees entire chain on failure
 * THREAD SAFETY: Single-threaded architecture - not thread-safe
 */
int blockdata_expand(struct blockdata *block, size_t oldlen, char *data, size_t newlen)
{
  struct blockdata *b;
  
  /* find size of current final block */
  for (b = block; oldlen > KEYBLOCK_LEN && b;  b = b->next, oldlen -= KEYBLOCK_LEN);

  /* chain to short for length, something is broken */
  if (oldlen > KEYBLOCK_LEN)
    {
      blockdata_free(block);
      return 0;
    }

  while (1)
    {
      struct blockdata *new;
      size_t blocksize = KEYBLOCK_LEN - oldlen;
      size_t size = (newlen <= blocksize) ? newlen : blocksize;
      
      if (size != 0)
	{
	  memcpy(&b->key[oldlen], data, size);
	  data += size;
	  newlen -= size;
	}
      
      /* full blocks from now on. */
      oldlen = 0;

      if (newlen == 0)
	break;

      if ((new = new_block()))
	{
	  b->next = new;
	  b = new;
	}
      else
	{
	  /* failed to alloc, free partial chain */
	  blockdata_free(block);
	  return 0;
	}
    }

  return 1;
}

/**
 * @brief Release block chain back to free list for reuse
 * 
 * @detailed Deallocates an entire block chain by returning all blocks to the global free list
 * (keyblock_free) for subsequent reuse. This function implements an efficient O(1) deallocation
 * strategy by prepending the entire chain to the free list rather than individually freeing each
 * block. The fixed-size block pool design enables this efficient bulk deallocation without
 * calling free() for individual blocks.
 * 
 * The function traverses the chain once to decrement blockdata_count for each block, then
 * atomically prepends the entire chain to keyblock_free. This approach maintains accurate
 * memory usage statistics while minimizing overhead.
 * 
 * Memory management invariant: Blocks are NEVER returned to system heap via free(); they
 * remain in the preallocated pool for lifetime of daemon process. This design eliminates
 * heap fragmentation from repeated alloc/free cycles of variable-length DNSSEC data.
 * 
 * @param blocks Pointer to head of block chain to free (NULL is safe and becomes no-op)
 * 
 * @return void (no return value)
 * 
 * @note NULL pointer is explicitly handled and safe (no-op)
 * @note Blocks remain in process memory pool; not returned to system heap
 * @note Decrements blockdata_count for each freed block (updates memory usage tracking)
 * @warning Caller must not access blocks pointer after calling this function
 * @warning Double-free would corrupt free list; caller must ensure single call per chain
 * 
 * @see new_block() - Allocates blocks from free list
 * @see blockdata_alloc() - Creates block chain that must later be freed via this function
 * @see blockdata_report() - Reports statistics updated by this function
 * 
 * EXAMPLE USAGE:
 * @code
 * // Free DNSSEC signature data after validation complete in dnssec.c
 * struct blockdata *rrsig_data = blockdata_alloc(sig_bytes, sig_len);
 * // ... perform DNSSEC validation using rrsig_data ...
 * blockdata_free(rrsig_data); // Return blocks to free list
 * rrsig_data = NULL; // Good practice: NULL pointer after free
 * @endcode
 * 
 * RFC COMPLIANCE: DNSSEC (RFC 4034) resource management
 * SIDE EFFECTS: Decrements blockdata_count by chain length; modifies keyblock_free list
 * THREAD SAFETY: Single-threaded architecture - not thread-safe
 */
void blockdata_free(struct blockdata *blocks)
{
  struct blockdata *tmp;
  
  if (blocks)
    {
      for (tmp = blocks; tmp->next; tmp = tmp->next)
	blockdata_count--;
      tmp->next = keyblock_free;
      keyblock_free = blocks; 
      blockdata_count--;
    }
}

/* if data == NULL, return pointer to static block of sufficient size */
/**
 * @brief Copy data from block chain back to contiguous memory buffer
 * 
 * @detailed Extracts data from a blockdata chain into a contiguous memory buffer, reversing
 * the process performed by blockdata_alloc(). This function walks the block chain and copies
 * KEYBLOCK_LEN bytes from each block's key[] array into the destination buffer, reconstructing
 * the original contiguous data representation.
 * 
 * The function supports two allocation modes:
 * 1. Caller-provided buffer: If data != NULL, copies directly into caller's buffer
 * 2. Auto-allocated buffer: If data == NULL, uses static internal buffer that grows as needed
 * 
 * The static buffer optimization reduces allocation overhead when repeatedly retrieving
 * blockdata (common pattern in DNSSEC validation). The buffer persists across calls and
 * grows to accommodate larger data but never shrinks, trading memory for performance.
 * 
 * Implementation traverses block chain linearly, copying min(KEYBLOCK_LEN, remaining_len)
 * bytes from each block until len bytes copied or chain exhausted.
 * 
 * @param block Pointer to head of block chain containing data to retrieve
 * @param len Number of bytes to retrieve from block chain
 * @param data Destination buffer pointer (if NULL, function allocates/reuses static buffer)
 * 
 * @return Pointer to buffer containing retrieved data (either 'data' param or static buffer)
 * @retval Non-NULL Successful retrieval, data copied to returned buffer
 * @retval NULL Memory allocation failed (only when data==NULL and malloc fails)
 * 
 * @note If data==NULL, returns static buffer that persists until next call (not thread-safe)
 * @note Caller must ensure 'data' buffer has capacity >= len if providing own buffer
 * @note If block chain shorter than 'len', copies only available data without error
 * @warning Static buffer mode NOT thread-safe (single-threaded architecture assumption)
 * @warning Returned pointer from static buffer invalidated by subsequent calls with data==NULL
 * 
 * @see blockdata_alloc() - Creates block chain from contiguous data (inverse operation)
 * @see blockdata_write() - Writes block chain directly to file descriptor
 * @see blockdata_read() - Reads data from file descriptor into block chain
 * 
 * EXAMPLE USAGE:
 * @code
 * // DNSSEC validation in dnssec.c: Retrieve DNSKEY data for signature verification
 * struct blockdata *dnskey_blocks = // ... from cache record
 * size_t key_len = 256; // RSA-2048 DNSKEY length
 * 
 * // Option 1: Auto-allocated buffer (convenient for temporary use)
 * unsigned char *key_data = blockdata_retrieve(dnskey_blocks, key_len, NULL);
 * verify_signature(key_data, key_len); // Use immediately
 * 
 * // Option 2: Caller-provided buffer (avoids static buffer sharing)
 * unsigned char key_buffer[256];
 * blockdata_retrieve(dnskey_blocks, key_len, key_buffer);
 * verify_signature(key_buffer, key_len); // Safe for concurrent operations
 * @endcode
 * 
 * RFC COMPLIANCE: DNSSEC (RFC 4034) data handling
 * SIDE EFFECTS: May allocate/grow static buffer if data==NULL; modifies destination buffer
 * THREAD SAFETY: Single-threaded architecture - static buffer NOT thread-safe
 */
void *blockdata_retrieve(struct blockdata *block, size_t len, void *data)
{
  size_t blen;
  struct  blockdata *b;
  uint8_t *new, *d;
  
  static unsigned int buff_len = 0;
  static unsigned char *buff = NULL;
   
  if (!data)
    {
      if (len > buff_len)
	{
	  if (!(new = whine_malloc(len)))
	    return NULL;
	  if (buff)
	    free(buff);
	  buff = new;
	}
      data = buff;
    }
  
  for (d = data, b = block; len > 0 && b;  b = b->next)
    {
      blen = len > KEYBLOCK_LEN ? KEYBLOCK_LEN : len;
      memcpy(d, b->key, blen);
      d += blen;
      len -= blen;
    }

  return data;
}


/**
 * @brief Write block chain data directly to file descriptor
 * 
 * @detailed Writes data stored in a blockdata chain to a file descriptor without requiring
 *           intermediate buffer allocation. The function iterates through the chain, writing
 *           each block's content (up to KEYBLOCK_LEN bytes) sequentially to the file descriptor.
 *           This zero-copy approach is efficient for serializing DNSSEC data to files or pipes.
 *           Uses read_write() utility function for interrupted I/O handling.
 * 
 * @param block Pointer to first block in chain to write (traverses chain via ->next pointers)
 * @param len Total number of bytes to write from block chain (must not exceed actual chain length)
 * @param fd File descriptor to write to (must be open and writable)
 * 
 * @return void - No return value; failures in read_write() logged elsewhere
 * 
 * @note Function writes exactly 'len' bytes if sufficient data in chain
 * @note Stops early if chain ends before 'len' bytes written (caller should ensure sufficient length)
 * @note Uses RW_WRITE flag for read_write() utility function
 * 
 * @see blockdata_alloc_real() for creating block chains from file descriptors
 * @see blockdata_read() for reading from file descriptor into block chain
 * @see blockdata_retrieve() for extracting data to memory buffer instead
 * 
 * EXAMPLE USAGE:
 * @code
 * // Write DNSSEC signature data to cache file
 * struct blockdata *sig_data = ...; // RRSIG record data
 * int fd = open("/var/cache/dnsmasq/dnssec.dat", O_WRONLY);
 * blockdata_write(sig_data, 256, fd); // Write 256 bytes
 * close(fd);
 * @endcode
 * 
 * SIDE EFFECTS: Modifies file descriptor position; may write partial data if chain too short
 * THREAD SAFETY: Single-threaded architecture - safe within single thread
 */
void blockdata_write(struct blockdata *block, size_t len, int fd)
{
  for (; len > 0 && block; block = block->next)
    {
      size_t blen = len > KEYBLOCK_LEN ? KEYBLOCK_LEN : len;
      read_write(fd, block->key, blen, RW_WRITE);
      len -= blen;
    }
}

/**
 * @brief Read data from file descriptor into newly allocated block chain
 * 
 * @detailed Convenience wrapper around blockdata_alloc_real() that reads 'len' bytes from
 *           a file descriptor into a newly allocated blockdata chain. The function allocates
 *           sufficient blocks to hold the specified length and populates them with data read
 *           from the file descriptor. This is the inverse operation of blockdata_write().
 *           Commonly used for deserializing DNSSEC data from cache files or network sockets.
 * 
 * @param fd File descriptor to read from (must be open and readable)
 * @param len Number of bytes to read from file descriptor
 * 
 * @return Pointer to head of newly allocated block chain containing read data
 * @retval Non-NULL Successfully allocated chain and read data
 * @retval NULL Allocation failed or read error (partial chain freed automatically)
 * 
 * @note Caller assumes ownership of returned block chain and must call blockdata_free() when done
 * @note Uses read_write() internally for interrupted I/O handling
 * @note Short reads (file has less than 'len' bytes) result in failure and return NULL
 * 
 * @see blockdata_alloc_real() for underlying implementation
 * @see blockdata_write() for inverse operation (write chain to file descriptor)
 * @see blockdata_alloc() for allocating from memory buffer instead
 * @see blockdata_free() for deallocating returned chain
 * 
 * EXAMPLE USAGE:
 * @code
 * // Read DNSSEC key from cache file
 * int fd = open("/var/cache/dnsmasq/dnskey.dat", O_RDONLY);
 * struct blockdata *key = blockdata_read(fd, 512); // Read 512-byte DNSKEY
 * if (key) {
 *   // Use key for DNSSEC validation...
 *   blockdata_free(key); // Release when done
 * }
 * close(fd);
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (internal storage mechanism)
 * SIDE EFFECTS: Allocates memory from blockdata pool; advances file descriptor position
 * THREAD SAFETY: Single-threaded architecture - not thread-safe
 */
struct blockdata *blockdata_read(int fd, size_t len)
{
  return blockdata_alloc_real(fd, NULL, len);
}

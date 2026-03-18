// Copyright (C) 2000-2025 Simon Kelley
// SPDX-License-Identifier: GPL-2.0-or-later
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.

//! # Block-Allocated Storage for DNSSEC Records
//!
//! Provides memory-efficient storage for variable-length DNSSEC data
//! (RRSIG signatures, DNSKEY public keys, DS delegation signer records).
//!
//! ## Migration from C (`src/blockdata.c`, 810 lines)
//!
//! The original C implementation used a custom block chain allocator with
//! fixed-size blocks (`KEYBLOCK_LEN = 40` bytes each) linked into chains
//! to prevent heap fragmentation.  In Rust this complexity is unnecessary:
//!
//! - [`Vec<u8>`] handles variable-length data efficiently with contiguous storage.
//! - The system allocator (or jemalloc) manages fragmentation transparently.
//! - Rust's ownership model eliminates use-after-free and double-free bugs that
//!   the C free-list pool was partly designed to mitigate.
//!
//! The public API surface remains compatible with the rest of the codebase:
//! allocation, expansion, retrieval, and persistent I/O are all preserved.
//!
//! ## Memory Safety Improvements
//!
//! | C Risk                         | Rust Mitigation                       |
//! |--------------------------------|---------------------------------------|
//! | Manual `malloc`/`free`         | RAII via [`Vec`] drop semantics       |
//! | Dangling pointers after free   | Ownership transfer, borrow checker    |
//! | Buffer overflows in `memcpy`   | Bounds-checked slice operations       |
//! | Double-free via free-list bugs | Single-owner `Vec<u8>`, no free list  |
//! | Pointer arithmetic errors      | Safe slice indexing                   |
//!
//! ## Feature Gate
//!
//! This module is gated by `cfg(feature = "dnssec")` at the parent module
//! declaration site in `dns/mod.rs`.

use crate::core::types::{DnsmasqError, DnsmasqResult};
use std::io::{Read, Write};
use tracing::{debug, info, warn};

// ---------------------------------------------------------------------------
// Constants (from C config.h line 24 and blockdata.c)
// ---------------------------------------------------------------------------

/// Legacy block size from C `KEYBLOCK_LEN` (config.h line 24).
///
/// Retained for:
/// - Compatibility calculations in [`BlockDataPool::report()`] statistics
/// - Documentation of the original C design rationale
///
/// In Rust, data is stored contiguously in [`Vec<u8>`] and this constant
/// is only used for statistical equivalence reporting.
const KEYBLOCK_LEN: usize = 40;

/// Default number of blocks added when the C free-list was exhausted.
///
/// Retained for documentation; in Rust the allocator handles growth
/// automatically via [`Vec::extend_from_slice`].
const _BLOCK_EXPANSION_SIZE: usize = 50;

// ---------------------------------------------------------------------------
// BlockData — Variable-length DNSSEC data container
// ---------------------------------------------------------------------------

/// Variable-length data storage for DNSSEC records.
///
/// Replaces C `struct blockdata` chain (defined in `dnsmasq.h` line 665):
/// ```c
/// struct blockdata {
///     struct blockdata *next;
///     unsigned char key[KEYBLOCK_LEN];
/// };
/// ```
///
/// The C implementation used a singly-linked list of 40-byte blocks managed
/// through a global free-list pool.  In Rust, a single contiguous [`Vec<u8>`]
/// provides identical semantics with better cache locality, simpler code, and
/// compile-time memory safety guarantees.
///
/// # Examples
///
/// ```rust,ignore
/// use dnsmasq::dns::blockdata::BlockData;
///
/// // Store a 128-byte RRSIG signature
/// let sig_bytes = vec![0xABu8; 128];
/// let block = BlockData::new(&sig_bytes);
/// assert_eq!(block.len(), 128);
/// assert_eq!(block.as_bytes(), &sig_bytes[..]);
///
/// // Zero-copy access
/// let slice = block.as_bytes();
/// assert_eq!(slice.len(), 128);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockData {
    /// Stored data (replaces C block chain).
    ///
    /// Contiguous heap allocation owned by this struct.
    /// Dropped automatically when `BlockData` goes out of scope,
    /// replacing C's `blockdata_free()` free-list return.
    data: Vec<u8>,
}

impl BlockData {
    /// Allocate new [`BlockData`] with initial data.
    ///
    /// Replaces C `blockdata_alloc()` (`blockdata.c` line 465):
    /// ```c
    /// struct blockdata *blockdata_alloc(char *data, size_t len)
    /// {
    ///     return blockdata_alloc_real(0, data, len);
    /// }
    /// ```
    ///
    /// In C, this allocated a chain of `⌈len / KEYBLOCK_LEN⌉` fixed-size
    /// blocks from the free-list pool and copied `data` into them.  In Rust,
    /// the data is simply copied into a [`Vec<u8>`].
    ///
    /// # Arguments
    ///
    /// * `data` — Byte slice to copy into the new block data storage.
    ///   An empty slice creates an empty `BlockData` (valid for
    ///   later expansion via [`expand()`](Self::expand)).
    ///
    /// # Returns
    ///
    /// A new `BlockData` instance owning a copy of `data`.
    ///
    /// # Memory Safety
    ///
    /// No manual allocation or deallocation required.  The caller owns the
    /// returned `BlockData` and it is freed automatically on drop (replacing
    /// C's `blockdata_free()`).
    pub fn new(data: &[u8]) -> Self {
        debug!(
            bytes = data.len(),
            "BlockData::new — allocating storage for DNSSEC record"
        );
        Self {
            data: data.to_vec(),
        }
    }

    /// Append additional data to existing block data storage.
    ///
    /// Replaces C `blockdata_expand()` (`blockdata.c` line 522):
    /// ```c
    /// int blockdata_expand(struct blockdata *block, size_t oldlen,
    ///                      char *data, size_t newlen)
    /// ```
    ///
    /// The C version navigated to the last block using `oldlen`, filled any
    /// remaining space, then allocated new blocks for overflow.  In Rust,
    /// this is a simple [`Vec::extend_from_slice`] — the `oldlen` parameter
    /// is unnecessary since `Vec` tracks its own length.
    ///
    /// # Arguments
    ///
    /// * `data` — Byte slice to append to the stored data.
    ///
    /// # Panics
    ///
    /// Only if the system allocator runs out of memory (standard `Vec`
    /// behavior).
    ///
    /// # C Comparison
    ///
    /// | C behavior                         | Rust behavior                        |
    /// |------------------------------------|--------------------------------------|
    /// | Returns 0 on failure, frees chain   | Panics on OOM (standard Rust)       |
    /// | Requires accurate `oldlen`          | Self-tracking via `Vec::len()`      |
    /// | May allocate new blocks             | May reallocate underlying buffer    |
    pub fn expand(&mut self, data: &[u8]) {
        debug!(
            current_len = self.data.len(),
            additional_bytes = data.len(),
            "BlockData::expand — extending storage"
        );
        self.data.extend_from_slice(data);
    }

    /// Retrieve data from block data storage.
    ///
    /// Replaces C `blockdata_retrieve()` (`blockdata.c` line 687):
    /// ```c
    /// void *blockdata_retrieve(struct blockdata *block, size_t len, void *data)
    /// ```
    ///
    /// The C version walked the block chain copying `KEYBLOCK_LEN` bytes per
    /// block into a contiguous output buffer.  If `data` was `NULL`, a
    /// static internal buffer was used (not thread-safe).
    ///
    /// In Rust, since data is already contiguous, this returns a sub-slice
    /// of the stored data with bounds checking.  No copy is needed.
    ///
    /// # Arguments
    ///
    /// * `len` — Maximum number of bytes to retrieve from the beginning of
    ///   stored data.  If `len` exceeds the stored data length, the
    ///   full stored data is returned (matching C behavior where
    ///   chain exhaustion ends the copy loop).
    ///
    /// # Returns
    ///
    /// A byte slice reference to the first `min(len, self.len())` bytes.
    /// This is a zero-copy operation — superior to C's mandatory `memcpy`.
    pub fn retrieve(&self, len: usize) -> &[u8] {
        let actual_len = len.min(self.data.len());
        &self.data[..actual_len]
    }

    /// Return a reference to the entire stored data.
    ///
    /// Rust-idiomatic zero-copy access to the full DNSSEC record data.
    /// This has no C equivalent — in C, `blockdata_retrieve()` always
    /// required copying through the block chain.
    ///
    /// # Returns
    ///
    /// Immutable byte slice spanning all stored data.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Return the number of stored bytes.
    ///
    /// In C, block data length was tracked separately by the caller since
    /// the block chain did not store its own length.  In Rust, [`Vec::len()`]
    /// provides this directly.
    #[inline]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check whether the block data is empty.
    ///
    /// Convenience method complementing [`len()`](Self::len).
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Read block data from a reader (file, socket, pipe).
    ///
    /// Replaces C `blockdata_read()` (`blockdata.c` line 807):
    /// ```c
    /// struct blockdata *blockdata_read(int fd, size_t len)
    /// {
    ///     return blockdata_alloc_real(fd, NULL, len);
    /// }
    /// ```
    ///
    /// The C version allocated blocks from the free-list pool and populated
    /// them by calling `read_write(fd, block->key, blen, RW_READ)` for each
    /// block.  In Rust, we allocate a single `Vec<u8>` buffer and read into
    /// it using the standard [`Read`] trait.
    ///
    /// # Arguments
    ///
    /// * `reader` — Any type implementing [`Read`] (file, socket, cursor, etc.)
    /// * `len`    — Exact number of bytes to read.
    ///
    /// # Errors
    ///
    /// Returns [`DnsmasqError::Io`] if the reader cannot provide exactly
    /// `len` bytes (short read, I/O error, EOF).
    ///
    /// # Memory Safety
    ///
    /// The returned `BlockData` owns its data.  No partial chain cleanup
    /// is needed on error (unlike C where `blockdata_free()` was called on
    /// the partial chain).
    pub fn read_from<R: Read>(reader: &mut R, len: usize) -> DnsmasqResult<Self> {
        let mut data = vec![0u8; len];
        reader.read_exact(&mut data).map_err(|e| {
            warn!(
                bytes_requested = len,
                error = %e,
                "BlockData::read_from — failed to read DNSSEC data from persistent cache"
            );
            DnsmasqError::Io(e)
        })?;
        debug!(
            bytes = len,
            "BlockData::read_from — successfully read DNSSEC data"
        );
        Ok(Self { data })
    }

    /// Write block data to a writer (file, socket, pipe).
    ///
    /// Replaces C `blockdata_write()` (`blockdata.c` line 756):
    /// ```c
    /// void blockdata_write(struct blockdata *block, size_t len, int fd)
    /// {
    ///     for (; len > 0 && block; block = block->next) {
    ///         size_t blen = len > KEYBLOCK_LEN ? KEYBLOCK_LEN : len;
    ///         read_write(fd, block->key, blen, RW_WRITE);
    ///         len -= blen;
    ///     }
    /// }
    /// ```
    ///
    /// In C, data was written block-by-block through the chain.  In Rust,
    /// a single [`Write::write_all`] call writes the contiguous buffer.
    ///
    /// # Arguments
    ///
    /// * `writer` — Any type implementing [`Write`].
    ///
    /// # Errors
    ///
    /// Returns [`DnsmasqError::Io`] on write failure.
    pub fn write_to<W: Write>(&self, writer: &mut W) -> DnsmasqResult<()> {
        writer.write_all(&self.data).map_err(|e| {
            warn!(
                bytes = self.data.len(),
                error = %e,
                "BlockData::write_to — failed to write DNSSEC data to persistent cache"
            );
            DnsmasqError::Io(e)
        })?;
        debug!(
            bytes = self.data.len(),
            "BlockData::write_to — successfully wrote DNSSEC data"
        );
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// BlockDataPool — Memory usage statistics tracker
// ---------------------------------------------------------------------------

/// Pool statistics tracker for [`BlockData`] memory usage.
///
/// Replaces C's module-level static variables (`blockdata.c` lines 99–114):
/// ```c
/// static struct blockdata *keyblock_free;   // free list head
/// static unsigned int blockdata_count;      // blocks in use
/// static unsigned int blockdata_hwm;        // high-water mark
/// static unsigned int blockdata_alloced;    // total blocks allocated
/// ```
///
/// In C, the pool managed a free-list of pre-allocated fixed-size blocks and
/// tracked allocation statistics through global counters.  In Rust, the
/// system allocator handles memory management and this struct provides
/// equivalent statistics reporting for monitoring and tuning.
///
/// The pool does **not** own or manage [`BlockData`] instances.  Callers
/// should invoke [`record_allocation()`](Self::record_allocation) and
/// [`record_deallocation()`](Self::record_deallocation) to keep statistics
/// accurate.
///
/// # Usage Pattern
///
/// ```rust,ignore
/// use dnsmasq::dns::blockdata::{BlockData, BlockDataPool};
///
/// let mut pool = BlockDataPool::new();
/// pool.init(150); // cache size = 150 entries
///
/// // Create BlockData and track statistics
/// let data = BlockData::new(&[0u8; 256]);
/// pool.record_allocation(data.len());
///
/// // Report statistics (e.g., on SIGUSR1)
/// pool.report();
///
/// // When data is dropped, record deallocation
/// let bytes = data.len();
/// drop(data);
/// pool.record_deallocation(bytes);
/// ```
#[derive(Debug, Clone)]
pub struct BlockDataPool {
    /// High-water mark: maximum bytes in use simultaneously since init.
    ///
    /// Replaces C `blockdata_hwm * sizeof(struct blockdata)`.
    high_water_bytes: usize,

    /// Total number of [`BlockData`] instances allocated since init.
    ///
    /// Replaces C `blockdata_alloced` (total blocks from heap).
    total_allocs_count: u64,

    /// Cumulative total bytes stored across all allocations since init.
    ///
    /// Replaces C `blockdata_alloced * sizeof(struct blockdata)`.
    total_bytes_count: u64,

    /// Current bytes in use across all live [`BlockData`] instances.
    ///
    /// Replaces C `blockdata_count * sizeof(struct blockdata)`.
    current_bytes: usize,

    /// Cache size used during initialization (for reporting context).
    ///
    /// Corresponds to `daemon->cachesize` from C.
    cache_size: usize,
}

impl BlockDataPool {
    /// Create a new empty statistics pool.
    ///
    /// All counters are initialized to zero.  Call [`init()`](Self::init)
    /// to configure the pool with the daemon's cache size context.
    pub fn new() -> Self {
        Self {
            high_water_bytes: 0,
            total_allocs_count: 0,
            total_bytes_count: 0,
            current_bytes: 0,
            cache_size: 0,
        }
    }

    /// Initialize the pool with cache size context.
    ///
    /// Replaces C `blockdata_init()` (`blockdata.c` line 205):
    /// ```c
    /// void blockdata_init(void)
    /// {
    ///     keyblock_free = NULL;
    ///     blockdata_alloced = 0;
    ///     blockdata_count = 0;
    ///     blockdata_hwm = 0;
    ///     if (option_bool(OPT_DNSSEC_VALID))
    ///         add_blocks(daemon->cachesize);
    /// }
    /// ```
    ///
    /// In C, this pre-allocated `cachesize` blocks to the free-list pool.
    /// In Rust, no pre-allocation is needed (the system allocator handles
    /// this dynamically).  The cache size is stored for reporting context
    /// and all statistics counters are reset.
    ///
    /// # Arguments
    ///
    /// * `cache_size` — Number of DNS cache entries, used for logging
    ///   context.  In C this determined pre-allocation size.
    pub fn init(&mut self, cache_size: usize) {
        self.high_water_bytes = 0;
        self.total_allocs_count = 0;
        self.total_bytes_count = 0;
        self.current_bytes = 0;
        self.cache_size = cache_size;

        info!(
            cache_size = cache_size,
            "BlockDataPool::init — DNSSEC block data pool initialized \
             (Rust allocator replaces C {}-byte block free-list pre-allocation)",
            cache_size * KEYBLOCK_LEN
        );
    }

    /// Report memory usage statistics.
    ///
    /// Replaces C `blockdata_report()` (`blockdata.c` line 253):
    /// ```c
    /// void blockdata_report(void)
    /// {
    ///     my_syslog(LOG_INFO, _("pool memory in use %zu, max %zu, allocated %zu"),
    ///         blockdata_count * sizeof(struct blockdata),
    ///         blockdata_hwm * sizeof(struct blockdata),
    ///         blockdata_alloced * sizeof(struct blockdata));
    /// }
    /// ```
    ///
    /// Logs current memory usage, high-water mark, and total bytes allocated.
    /// Typically called in response to SIGUSR1/SIGUSR2 signal for statistics
    /// dumping.
    pub fn report(&self) {
        info!(
            current_bytes = self.current_bytes,
            high_water_bytes = self.high_water_bytes,
            total_bytes = self.total_bytes_count,
            total_allocs = self.total_allocs_count,
            cache_size = self.cache_size,
            "DNSSEC block data pool: in use {} bytes, max {} bytes, \
             total allocated {} bytes across {} allocations",
            self.current_bytes,
            self.high_water_bytes,
            self.total_bytes_count,
            self.total_allocs_count,
        );
    }

    /// Return the high-water mark (maximum bytes in use simultaneously).
    ///
    /// Corresponds to C `blockdata_hwm * sizeof(struct blockdata)`.
    #[inline]
    pub fn high_water(&self) -> usize {
        self.high_water_bytes
    }

    /// Return total number of allocations performed since initialization.
    ///
    /// Corresponds to C's total block allocation count.
    #[inline]
    pub fn total_allocs(&self) -> u64 {
        self.total_allocs_count
    }

    /// Return cumulative total bytes stored across all allocations.
    ///
    /// Corresponds to C `blockdata_alloced * sizeof(struct blockdata)`.
    #[inline]
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes_count
    }

    /// Return current bytes in use across all live [`BlockData`] instances.
    ///
    /// Corresponds to C `blockdata_count * sizeof(struct blockdata)`.
    #[inline]
    pub fn current_bytes(&self) -> usize {
        self.current_bytes
    }

    /// Record a new [`BlockData`] allocation in pool statistics.
    ///
    /// Should be called by the caller each time a new [`BlockData`]
    /// instance is created, passing the byte length of the stored data.
    ///
    /// Updates:
    /// - `total_allocs` — incremented by 1
    /// - `total_bytes`  — incremented by `bytes`
    /// - `current_bytes` — incremented by `bytes`
    /// - `high_water`   — updated if `current_bytes` exceeds previous max
    ///
    /// Replaces the accounting in C's `new_block()` function which
    /// incremented `blockdata_count` and updated `blockdata_hwm`.
    pub fn record_allocation(&mut self, bytes: usize) {
        self.total_allocs_count += 1;
        self.total_bytes_count += bytes as u64;
        self.current_bytes += bytes;
        if self.current_bytes > self.high_water_bytes {
            self.high_water_bytes = self.current_bytes;
        }
        debug!(
            bytes = bytes,
            current = self.current_bytes,
            high_water = self.high_water_bytes,
            "BlockDataPool — recorded allocation"
        );
    }

    /// Record a [`BlockData`] deallocation in pool statistics.
    ///
    /// Should be called by the caller each time a [`BlockData`] instance
    /// is dropped, passing the byte length that was stored.
    ///
    /// Replaces the accounting in C's `blockdata_free()` which decremented
    /// `blockdata_count` and returned blocks to the free list.
    ///
    /// Uses saturating subtraction to prevent underflow if called with
    /// incorrect byte counts.
    pub fn record_deallocation(&mut self, bytes: usize) {
        self.current_bytes = self.current_bytes.saturating_sub(bytes);
        debug!(
            bytes = bytes,
            current = self.current_bytes,
            "BlockDataPool — recorded deallocation"
        );
    }
}

impl Default for BlockDataPool {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    // --- BlockData basic operations ---

    #[test]
    fn test_new_empty() {
        let block = BlockData::new(&[]);
        assert!(block.is_empty());
        assert_eq!(block.len(), 0);
        assert_eq!(block.as_bytes(), &[] as &[u8]);
    }

    #[test]
    fn test_new_with_data() {
        let data = vec![0xAB; 128];
        let block = BlockData::new(&data);
        assert_eq!(block.len(), 128);
        assert_eq!(block.as_bytes(), &data[..]);
    }

    #[test]
    fn test_new_small_data() {
        // Smaller than one C block (KEYBLOCK_LEN = 40)
        let data = vec![1, 2, 3, 4, 5];
        let block = BlockData::new(&data);
        assert_eq!(block.len(), 5);
        assert_eq!(block.as_bytes(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_new_exact_block_size() {
        // Exactly one C block (KEYBLOCK_LEN = 40)
        let data = vec![0xFF; KEYBLOCK_LEN];
        let block = BlockData::new(&data);
        assert_eq!(block.len(), KEYBLOCK_LEN);
    }

    #[test]
    fn test_new_multi_block_size() {
        // Multiple C blocks worth (256 bytes = ~7 blocks of 40)
        let data: Vec<u8> = (0u8..=255).collect();
        let block = BlockData::new(&data);
        assert_eq!(block.len(), 256);
        assert_eq!(block.as_bytes(), &data[..]);
    }

    #[test]
    fn test_new_large_dnskey() {
        // Typical RSA-4096 DNSKEY: ~512 bytes
        let data = vec![0xDE; 512];
        let block = BlockData::new(&data);
        assert_eq!(block.len(), 512);
    }

    // --- BlockData expand ---

    #[test]
    fn test_expand_from_empty() {
        let mut block = BlockData::new(&[]);
        block.expand(&[1, 2, 3]);
        assert_eq!(block.len(), 3);
        assert_eq!(block.as_bytes(), &[1, 2, 3]);
    }

    #[test]
    fn test_expand_with_existing_data() {
        let mut block = BlockData::new(&[1, 2, 3]);
        block.expand(&[4, 5, 6]);
        assert_eq!(block.len(), 6);
        assert_eq!(block.as_bytes(), &[1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn test_expand_multiple_times() {
        // Simulates incremental RRSIG assembly from C blockdata_expand pattern
        let mut block = BlockData::new(&[]);
        let header = vec![0xAA; 20];
        let signature = vec![0xBB; 128];
        let padding = vec![0xCC; 10];

        block.expand(&header);
        assert_eq!(block.len(), 20);

        block.expand(&signature);
        assert_eq!(block.len(), 148);

        block.expand(&padding);
        assert_eq!(block.len(), 158);

        // Verify data integrity
        assert_eq!(&block.as_bytes()[..20], &header[..]);
        assert_eq!(&block.as_bytes()[20..148], &signature[..]);
        assert_eq!(&block.as_bytes()[148..], &padding[..]);
    }

    #[test]
    fn test_expand_empty_slice() {
        let mut block = BlockData::new(&[1, 2, 3]);
        block.expand(&[]);
        assert_eq!(block.len(), 3);
    }

    // --- BlockData retrieve ---

    #[test]
    fn test_retrieve_full() {
        let data = vec![0x42; 100];
        let block = BlockData::new(&data);
        let retrieved = block.retrieve(100);
        assert_eq!(retrieved, &data[..]);
    }

    #[test]
    fn test_retrieve_partial() {
        let data = vec![0x42; 100];
        let block = BlockData::new(&data);
        let retrieved = block.retrieve(50);
        assert_eq!(retrieved.len(), 50);
        assert_eq!(retrieved, &data[..50]);
    }

    #[test]
    fn test_retrieve_exceeds_length() {
        // C behavior: stops when chain exhausted, no error
        let data = vec![0x42; 30];
        let block = BlockData::new(&data);
        let retrieved = block.retrieve(100);
        assert_eq!(retrieved.len(), 30);
        assert_eq!(retrieved, &data[..]);
    }

    #[test]
    fn test_retrieve_zero() {
        let block = BlockData::new(&[1, 2, 3]);
        let retrieved = block.retrieve(0);
        assert!(retrieved.is_empty());
    }

    #[test]
    fn test_retrieve_from_empty() {
        let block = BlockData::new(&[]);
        let retrieved = block.retrieve(10);
        assert!(retrieved.is_empty());
    }

    // --- BlockData as_bytes ---

    #[test]
    fn test_as_bytes_returns_reference() {
        let data = vec![1, 2, 3, 4, 5];
        let block = BlockData::new(&data);
        let bytes = block.as_bytes();
        // Verify zero-copy: pointer comparison
        assert_eq!(bytes.as_ptr(), block.data.as_ptr());
        assert_eq!(bytes, &data[..]);
    }

    // --- BlockData clone and equality ---

    #[test]
    fn test_clone() {
        let block = BlockData::new(&[1, 2, 3]);
        let cloned = block.clone();
        assert_eq!(block, cloned);
    }

    #[test]
    fn test_equality() {
        let a = BlockData::new(&[1, 2, 3]);
        let b = BlockData::new(&[1, 2, 3]);
        let c = BlockData::new(&[4, 5, 6]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    // --- BlockData read_from / write_to ---

    #[test]
    fn test_write_to_and_read_from_roundtrip() {
        let original_data: Vec<u8> = (0u8..=255).collect();
        let block = BlockData::new(&original_data);

        // Write to buffer
        let mut buf = Vec::new();
        block.write_to(&mut buf).expect("write_to should succeed");
        assert_eq!(buf.len(), 256);
        assert_eq!(&buf, &original_data);

        // Read back
        let mut cursor = Cursor::new(buf);
        let restored = BlockData::read_from(&mut cursor, 256).expect("read_from should succeed");
        assert_eq!(restored, block);
    }

    #[test]
    fn test_read_from_empty() {
        let mut cursor = Cursor::new(Vec::<u8>::new());
        let result = BlockData::read_from(&mut cursor, 0);
        assert!(result.is_ok());
        let block = result.unwrap();
        assert!(block.is_empty());
    }

    #[test]
    fn test_read_from_short_read() {
        // Only 5 bytes available but requesting 10
        let mut cursor = Cursor::new(vec![1, 2, 3, 4, 5]);
        let result = BlockData::read_from(&mut cursor, 10);
        assert!(result.is_err());
        match result {
            Err(DnsmasqError::Io(_)) => {} // Expected
            other => panic!("Expected DnsmasqError::Io, got: {:?}", other),
        }
    }

    #[test]
    fn test_write_to_empty() {
        let block = BlockData::new(&[]);
        let mut buf = Vec::new();
        block
            .write_to(&mut buf)
            .expect("write empty should succeed");
        assert!(buf.is_empty());
    }

    #[test]
    fn test_read_from_large_dnssec_record() {
        // Simulate reading a 4KB DNSKEY record from cache file
        let data = vec![0xAB; 4096];
        let mut cursor = Cursor::new(data.clone());
        let block = BlockData::read_from(&mut cursor, 4096).expect("large read should succeed");
        assert_eq!(block.len(), 4096);
        assert_eq!(block.as_bytes(), &data[..]);
    }

    #[test]
    fn test_write_read_multiple_records() {
        // Simulate writing and reading multiple DNSSEC records sequentially
        let sig1 = BlockData::new(&[0xAA; 128]);
        let sig2 = BlockData::new(&[0xBB; 256]);
        let key1 = BlockData::new(&[0xCC; 512]);

        let mut buf = Vec::new();
        sig1.write_to(&mut buf).unwrap();
        sig2.write_to(&mut buf).unwrap();
        key1.write_to(&mut buf).unwrap();

        assert_eq!(buf.len(), 128 + 256 + 512);

        let mut cursor = Cursor::new(buf);
        let r1 = BlockData::read_from(&mut cursor, 128).unwrap();
        let r2 = BlockData::read_from(&mut cursor, 256).unwrap();
        let r3 = BlockData::read_from(&mut cursor, 512).unwrap();

        assert_eq!(r1, sig1);
        assert_eq!(r2, sig2);
        assert_eq!(r3, key1);
    }

    // --- BlockDataPool basic operations ---

    #[test]
    fn test_pool_new() {
        let pool = BlockDataPool::new();
        assert_eq!(pool.high_water(), 0);
        assert_eq!(pool.total_allocs(), 0);
        assert_eq!(pool.total_bytes(), 0);
        assert_eq!(pool.current_bytes(), 0);
    }

    #[test]
    fn test_pool_default() {
        let pool = BlockDataPool::default();
        assert_eq!(pool.high_water(), 0);
        assert_eq!(pool.total_allocs(), 0);
    }

    #[test]
    fn test_pool_init() {
        let mut pool = BlockDataPool::new();
        pool.init(150);
        assert_eq!(pool.cache_size, 150);
        assert_eq!(pool.high_water(), 0);
        assert_eq!(pool.total_allocs(), 0);
        assert_eq!(pool.total_bytes(), 0);
    }

    #[test]
    fn test_pool_init_resets_counters() {
        let mut pool = BlockDataPool::new();
        pool.record_allocation(100);
        pool.record_allocation(200);
        assert_eq!(pool.total_allocs(), 2);

        pool.init(100);
        assert_eq!(pool.total_allocs(), 0);
        assert_eq!(pool.total_bytes(), 0);
        assert_eq!(pool.high_water(), 0);
        assert_eq!(pool.current_bytes(), 0);
    }

    // --- BlockDataPool statistics tracking ---

    #[test]
    fn test_pool_record_allocation() {
        let mut pool = BlockDataPool::new();
        pool.init(100);

        pool.record_allocation(128);
        assert_eq!(pool.total_allocs(), 1);
        assert_eq!(pool.total_bytes(), 128);
        assert_eq!(pool.current_bytes(), 128);
        assert_eq!(pool.high_water(), 128);
    }

    #[test]
    fn test_pool_record_multiple_allocations() {
        let mut pool = BlockDataPool::new();
        pool.init(100);

        pool.record_allocation(128);
        pool.record_allocation(256);
        pool.record_allocation(512);

        assert_eq!(pool.total_allocs(), 3);
        assert_eq!(pool.total_bytes(), 128 + 256 + 512);
        assert_eq!(pool.current_bytes(), 128 + 256 + 512);
        assert_eq!(pool.high_water(), 128 + 256 + 512);
    }

    #[test]
    fn test_pool_high_water_mark() {
        let mut pool = BlockDataPool::new();
        pool.init(100);

        // Allocate 300 bytes total
        pool.record_allocation(100);
        pool.record_allocation(200);
        assert_eq!(pool.high_water(), 300);

        // Free 100 bytes — current goes to 200, high water stays at 300
        pool.record_deallocation(100);
        assert_eq!(pool.current_bytes(), 200);
        assert_eq!(pool.high_water(), 300);

        // Allocate 50 bytes — current goes to 250, still below high water
        pool.record_allocation(50);
        assert_eq!(pool.current_bytes(), 250);
        assert_eq!(pool.high_water(), 300);

        // Allocate 100 bytes — current goes to 350, new high water
        pool.record_allocation(100);
        assert_eq!(pool.current_bytes(), 350);
        assert_eq!(pool.high_water(), 350);
    }

    #[test]
    fn test_pool_record_deallocation() {
        let mut pool = BlockDataPool::new();
        pool.record_allocation(256);
        pool.record_deallocation(256);
        assert_eq!(pool.current_bytes(), 0);
        // total_allocs and total_bytes are cumulative, not decremented
        assert_eq!(pool.total_allocs(), 1);
        assert_eq!(pool.total_bytes(), 256);
    }

    #[test]
    fn test_pool_deallocation_saturating() {
        // Deallocation with larger value than current should not underflow
        let mut pool = BlockDataPool::new();
        pool.record_allocation(100);
        pool.record_deallocation(200); // More than current
        assert_eq!(pool.current_bytes(), 0); // Saturated, not wrapped
    }

    #[test]
    fn test_pool_report_does_not_panic() {
        // Verify report() doesn't panic with various states
        let pool = BlockDataPool::new();
        pool.report();

        let mut pool2 = BlockDataPool::new();
        pool2.init(150);
        pool2.record_allocation(1024);
        pool2.record_allocation(2048);
        pool2.record_deallocation(512);
        pool2.report();
    }

    // --- Integration: BlockData + BlockDataPool ---

    #[test]
    fn test_blockdata_with_pool_tracking() {
        let mut pool = BlockDataPool::new();
        pool.init(150);

        // Simulate DNSSEC signature storage workflow
        let sig_data = vec![0xAB; 256];
        let block1 = BlockData::new(&sig_data);
        pool.record_allocation(block1.len());

        let key_data = vec![0xCD; 512];
        let block2 = BlockData::new(&key_data);
        pool.record_allocation(block2.len());

        assert_eq!(pool.total_allocs(), 2);
        assert_eq!(pool.current_bytes(), 256 + 512);

        // Free first block
        let b1_len = block1.len();
        drop(block1);
        pool.record_deallocation(b1_len);

        assert_eq!(pool.current_bytes(), 512);
        assert_eq!(pool.high_water(), 768);

        // Free second block
        let b2_len = block2.len();
        drop(block2);
        pool.record_deallocation(b2_len);

        assert_eq!(pool.current_bytes(), 0);
        assert_eq!(pool.high_water(), 768);
        assert_eq!(pool.total_allocs(), 2);
        assert_eq!(pool.total_bytes(), 768);
    }

    #[test]
    fn test_full_lifecycle_simulation() {
        // Simulate the C lifecycle:
        // 1. Init pool (blockdata_init)
        // 2. Allocate DNSSEC data (blockdata_alloc)
        // 3. Expand data (blockdata_expand)
        // 4. Retrieve data (blockdata_retrieve)
        // 5. Write to cache (blockdata_write)
        // 6. Read from cache (blockdata_read)
        // 7. Free data (blockdata_free → automatic drop)
        // 8. Report stats (blockdata_report)

        let mut pool = BlockDataPool::new();
        pool.init(100);

        // Step 2: Allocate
        let mut block = BlockData::new(&[0xAA; 20]);
        pool.record_allocation(block.len());

        // Step 3: Expand
        let old_len = block.len();
        block.expand(&[0xBB; 128]);
        let _new_bytes = block.len() - old_len;
        pool.record_deallocation(old_len);
        pool.record_allocation(block.len());

        assert_eq!(block.len(), 148);

        // Step 4: Retrieve
        let first_20 = block.retrieve(20);
        assert_eq!(first_20, &[0xAA; 20]);

        let full = block.as_bytes();
        assert_eq!(full.len(), 148);

        // Step 5: Write to cache
        let mut cache_buf = Vec::new();
        block.write_to(&mut cache_buf).unwrap();
        assert_eq!(cache_buf.len(), 148);

        // Step 6: Read from cache
        let mut cursor = Cursor::new(cache_buf);
        let restored = BlockData::read_from(&mut cursor, 148).unwrap();
        assert_eq!(restored, block);

        // Step 7: Free
        let final_len = block.len();
        drop(block);
        pool.record_deallocation(final_len);

        // Step 8: Report
        pool.report();
        assert_eq!(pool.current_bytes(), 0);
        assert!(pool.total_allocs() > 0);
        assert!(pool.total_bytes() > 0);
    }
}

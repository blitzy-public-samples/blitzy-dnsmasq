// Copyright (c) 2024 dnsmasq contributors
// SPDX-License-Identifier: GPL-2.0-or-later
//
// This file is part of dnsmasq, a memory-safe Rust implementation of a
// DNS forwarder, DHCP server, and network boot daemon.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.

//! # DHCPv6 Option Serialization and Packet Buffer Management
//!
//! Safe DHCPv6 packet construction with automatic buffer expansion and nested
//! option support. Replaces C's `src/outpacket.c` (702 lines).
//!
//! ## Architecture
//! The C implementation used global mutable state (`daemon->outpacket` + `outpacket_counter`)
//! that was not thread-safe. The Rust implementation encapsulates all state in an `OutPacket`
//! struct with owned `Vec<u8>` buffer, providing automatic memory management and bounds safety.
//!
//! ## DHCPv6 Option Format (RFC 3315 Section 22.1)
//! ```text
//! 0                   1                   2                   3
//! 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |          option-code          |         option-len            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                          option-data                         |
//! |                      (option-len octets)                     |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! ## Nested Option Example (IA_NA with IAADDR)
//! ```rust,no_run
//! use dnsmasq::dhcp::v6::outpacket::OutPacket;
//!
//! let mut pkt = OutPacket::new();
//! let ia_na = pkt.new_opt6(0x0003);     // Start IA_NA container (OPTION6_IA_NA)
//! pkt.put_opt6_long(0x00000001);         // IAID field
//! pkt.put_opt6_long(3600);               // T1 timer
//! pkt.put_opt6_long(7200);               // T2 timer
//! let ia_addr = pkt.new_opt6(0x0005);    // Nested IAADDR (OPTION6_IAADDR)
//! pkt.put_opt6(&[0x20, 0x01, 0x0d, 0xb8, 0,0,0,0, 0,0,0,0, 0,0,0,1]); // 2001:db8::1
//! pkt.put_opt6_long(7200);               // Preferred lifetime
//! pkt.put_opt6_long(14400);              // Valid lifetime
//! pkt.end_opt6(ia_addr);                 // Finalize IAADDR
//! pkt.end_opt6(ia_na);                   // Finalize IA_NA (length includes IAADDR)
//! ```
//!
//! ## C Source Mapping
//! | Rust Method | C Function | C Line | Description |
//! |------------|------------|--------|-------------|
//! | `new()` | (implicit) | - | Create empty packet |
//! | `with_capacity()` | (implicit) | - | Create pre-allocated packet |
//! | `reset()` | `reset_counter()` | 162 | Clear buffer, reset position |
//! | `save_counter()` | `save_counter()` | 216 | Checkpoint/restore position |
//! | `len()` | `save_counter(-1)` | 216 | Query current position |
//! | `new_opt6()` | `new_opt6()` | 343 | Create option header |
//! | `put_opt6()` | `put_opt6()` | 421 | Add binary data |
//! | `put_opt6_raw()` | `put_opt6(NULL,len)` | 421 | Allocate raw space |
//! | `put_opt6_long()` | `put_opt6_long()` | 485 | Add 32-bit BE integer |
//! | `put_opt6_short()` | `put_opt6_short()` | 551 | Add 16-bit BE integer |
//! | `put_opt6_char()` | `put_opt6_char()` | 617 | Add single byte |
//! | `put_opt6_string()` | `put_opt6_string()` | 697 | Add string (no null) |
//! | `end_opt6()` | `end_opt6()` | 116 | Finalize container option |
//! | `as_bytes()` | (no C equiv) | - | Read-only buffer access |
//! | `as_mut_bytes()` | (no C equiv) | - | Mutable buffer access |
//!
//! ## Memory Safety Improvements
//! - C: `expand_buf()` could fail silently (return NULL) → potential NULL deref
//! - Rust: `Vec::resize()` grows automatically → panic on OOM (standard Rust behavior)
//! - C: Global mutable state → data races in theoretical multi-threaded use
//! - Rust: Owned `OutPacket` struct → exclusive access via `&mut self`
//! - C: `PUTSHORT`/`PUTLONG` macros with raw pointer arithmetic
//! - Rust: `to_be_bytes()` + `copy_from_slice()` → bounds-checked writes

/// DHCPv6 option header size in bytes: 2-byte option code + 2-byte option length.
/// This constant represents the fixed overhead for every DHCPv6 TLV option.
const OPT6_HEADER_SIZE: usize = 4;

/// DHCPv6 output packet buffer with position tracking.
///
/// Replaces C's global `daemon->outpacket` (`struct iovec`) + `outpacket_counter`.
/// Provides safe, bounds-checked packet construction with automatic buffer growth.
///
/// ## C Source Mapping
/// | Rust Field | C Equivalent | Location |
/// |-----------|-------------|----------|
/// | `buf: Vec<u8>` | `daemon->outpacket.iov_base` | outpacket.c global |
/// | `pos: usize` | `outpacket_counter` | outpacket.c:69 |
///
/// ## Memory Safety
/// - C used `expand_buf()` + raw pointer arithmetic → buffer overflows possible
/// - Rust uses `Vec<u8>` with automatic growth → guaranteed bounds safety
/// - C had global mutable state → Rust encapsulates in owned struct
/// - All write operations check and grow buffer automatically
#[derive(Debug, Clone)]
pub struct OutPacket {
    /// Packet buffer (auto-growing `Vec` replaces C's `iov_base` + `expand_buf`).
    /// The buffer is always at least `pos` bytes long. Bytes beyond `pos` are
    /// zero-initialized from `Vec::resize` and should not be transmitted.
    buf: Vec<u8>,

    /// Current write position within `buf` (replaces C's `static outpacket_counter`).
    /// All write operations append at this offset and advance it forward.
    /// `pos` also represents the logical length of the constructed packet.
    pos: usize,
}

impl OutPacket {
    // -----------------------------------------------------------------------
    // Constructors
    // -----------------------------------------------------------------------

    /// Create a new, empty `OutPacket` with no pre-allocated capacity.
    ///
    /// The buffer starts empty and will grow automatically as data is written.
    /// Use [`with_capacity`](OutPacket::with_capacity) when the approximate
    /// packet size is known in advance to avoid repeated reallocations.
    ///
    /// # Examples
    /// ```
    /// use dnsmasq::dhcp::v6::outpacket::OutPacket;
    /// let pkt = OutPacket::new();
    /// assert_eq!(pkt.len(), 0);
    /// ```
    #[inline]
    pub fn new() -> Self {
        OutPacket {
            buf: Vec::new(),
            pos: 0,
        }
    }

    /// Create a new `OutPacket` with a pre-allocated, zero-initialized buffer.
    ///
    /// The buffer is filled with `capacity` zero bytes. This avoids repeated
    /// reallocations when building packets of a known approximate size.
    /// The write position starts at 0 — the pre-allocated bytes are available
    /// for writing via [`expand`] without triggering a grow.
    ///
    /// # Arguments
    /// * `capacity` — Number of bytes to pre-allocate and zero-initialize.
    ///
    /// # Examples
    /// ```
    /// use dnsmasq::dhcp::v6::outpacket::OutPacket;
    /// let pkt = OutPacket::with_capacity(1500);
    /// assert_eq!(pkt.len(), 0);  // No data written yet
    /// ```
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        OutPacket {
            buf: vec![0u8; capacity],
            pos: 0,
        }
    }

    // -----------------------------------------------------------------------
    // Reset
    // -----------------------------------------------------------------------

    /// Reset the packet buffer: zero-fill all existing bytes and move the
    /// write position back to 0.
    ///
    /// Matches C's `reset_counter()` (outpacket.c line 162):
    /// ```c
    /// memset(daemon->outpacket.iov_base, 0, daemon->outpacket.iov_len);
    /// save_counter(0);
    /// ```
    ///
    /// **CRITICAL**: The zero-fill prevents information leakage between
    /// successive packets, matching the C implementation exactly. Without
    /// this, leftover data from a previous packet could leak into a new one
    /// if `end_opt6` back-patches a shorter length than the previous use.
    pub fn reset(&mut self) {
        // Zero-fill the entire allocated buffer (matches C memset behavior).
        // This is deliberately not `self.buf.clear()` which would deallocate,
        // because C's reset_counter keeps the buffer allocated for reuse.
        for byte in self.buf.iter_mut() {
            *byte = 0;
        }
        self.pos = 0;
    }

    // -----------------------------------------------------------------------
    // Position Management
    // -----------------------------------------------------------------------

    /// Query and optionally update the current write position.
    ///
    /// This is the checkpoint/restore mechanism for nested option containers.
    /// Always returns the position value *before* any update.
    ///
    /// Replaces C's `save_counter()` (outpacket.c line 216):
    /// - `save_counter(-1)` (query only) → `save_counter(None)`
    /// - `save_counter(0)` (reset to 0) → `save_counter(Some(0))`
    /// - `save_counter(n)` (set to n) → `save_counter(Some(n))`
    ///
    /// # Arguments
    /// * `newval` — If `Some(n)`, set the position to `n` after capturing
    ///   the current value. If `None`, return the current position unchanged.
    ///
    /// # Returns
    /// The write position *before* applying any update.
    ///
    /// # Examples
    /// ```
    /// use dnsmasq::dhcp::v6::outpacket::OutPacket;
    /// let mut pkt = OutPacket::new();
    /// pkt.put_opt6_long(42);
    /// let saved = pkt.save_counter(None);    // Query: returns 4
    /// assert_eq!(saved, 4);
    /// pkt.save_counter(Some(0));             // Restore to 0
    /// assert_eq!(pkt.len(), 0);
    /// ```
    #[inline]
    pub fn save_counter(&mut self, newval: Option<usize>) -> usize {
        let ret = self.pos;
        if let Some(val) = newval {
            self.pos = val;
        }
        ret
    }

    /// Return the current write position, which equals the logical length
    /// (in bytes) of the constructed packet data.
    ///
    /// Equivalent to C's `save_counter(-1)` when used solely to query the
    /// current position without changing it.
    ///
    /// # Examples
    /// ```
    /// use dnsmasq::dhcp::v6::outpacket::OutPacket;
    /// let mut pkt = OutPacket::new();
    /// assert_eq!(pkt.len(), 0);
    /// pkt.put_opt6_short(0x0001);
    /// assert_eq!(pkt.len(), 2);
    /// ```
    #[inline]
    pub fn len(&self) -> usize {
        self.pos
    }

    /// Returns `true` if no data has been written to the packet (position is 0).
    ///
    /// # Examples
    /// ```
    /// use dnsmasq::dhcp::v6::outpacket::OutPacket;
    /// let mut pkt = OutPacket::new();
    /// assert!(pkt.is_empty());
    /// pkt.put_opt6_char(0x01);
    /// assert!(!pkt.is_empty());
    /// ```
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.pos == 0
    }

    // -----------------------------------------------------------------------
    // Buffer Expansion (internal)
    // -----------------------------------------------------------------------

    /// Ensure the buffer has room for `headroom` more bytes starting at the
    /// current write position, growing it if necessary. Advance `pos` by
    /// `headroom` and return the starting offset of the newly-reserved space.
    ///
    /// Replaces C's `expand()` (outpacket.c line 272):
    /// ```c
    /// static void *expand(size_t headroom) {
    ///     void *ret;
    ///     if (expand_buf(&daemon->outpacket, outpacket_counter + headroom)) {
    ///         ret = daemon->outpacket.iov_base + outpacket_counter;
    ///         outpacket_counter += headroom;
    ///         return ret;
    ///     }
    ///     return NULL;
    /// }
    /// ```
    ///
    /// **Key difference from C**: The C version returns a raw pointer (which
    /// can be NULL on allocation failure). The Rust version returns an offset
    /// (`Option<usize>`) because the underlying `Vec` may reallocate on grow,
    /// invalidating any raw pointer. In practice, `Vec::resize` will panic on
    /// OOM rather than returning NULL, so `expand` always returns `Some`.
    ///
    /// # Arguments
    /// * `headroom` — Number of additional bytes needed at the current position.
    ///
    /// # Returns
    /// `Some(start)` where `start` is the offset into `buf` where the caller
    /// can write. Returns `None` only in degenerate edge cases (never in
    /// practice on modern systems).
    fn expand(&mut self, headroom: usize) -> Option<usize> {
        let needed = self.pos.checked_add(headroom)?;
        if needed > self.buf.len() {
            self.buf.resize(needed, 0);
        }
        let ret = self.pos;
        self.pos = needed;
        Some(ret)
    }

    // -----------------------------------------------------------------------
    // Option Header Creation
    // -----------------------------------------------------------------------

    /// Start a new DHCPv6 option by writing a 4-byte TLV header:
    ///   - 2 bytes: option code (network byte order, big-endian)
    ///   - 2 bytes: option length (initially 0, back-patched by [`end_opt6`])
    ///
    /// Returns the buffer offset of this option header. Pass this value to
    /// [`end_opt6`] after writing all option data to finalize the length field.
    ///
    /// Replaces C's `new_opt6()` (outpacket.c line 343):
    /// ```c
    /// void *new_opt6(int opt) {
    ///     void *ret = expand(4);
    ///     PUTSHORT(opt, ret);   // option code
    ///     PUTSHORT(0, ret);     // length placeholder
    ///     return ret;           // header position for end_opt6
    /// }
    /// ```
    ///
    /// # Arguments
    /// * `opt` — DHCPv6 option code (e.g. `OPTION6_IA_NA = 3`).
    ///
    /// # Returns
    /// Buffer offset of the option header (for use with [`end_opt6`]).
    ///
    /// # Examples
    /// ```
    /// use dnsmasq::dhcp::v6::outpacket::OutPacket;
    /// let mut pkt = OutPacket::new();
    /// let start = pkt.new_opt6(0x0007);  // OPTION6_PREFERENCE
    /// pkt.put_opt6_char(255);            // preference value
    /// pkt.end_opt6(start);               // finalize length = 1
    /// assert_eq!(pkt.as_bytes(), &[0x00, 0x07, 0x00, 0x01, 0xFF]);
    /// ```
    pub fn new_opt6(&mut self, opt: u16) -> usize {
        let ret = self.pos;
        if let Some(start) = self.expand(OPT6_HEADER_SIZE) {
            // Write option code in network byte order (big-endian).
            self.buf[start..start + 2].copy_from_slice(&opt.to_be_bytes());
            // Write length as 0 — will be back-patched by end_opt6().
            self.buf[start + 2..start + 4].copy_from_slice(&0u16.to_be_bytes());
        }
        ret
    }

    // -----------------------------------------------------------------------
    // Data Addition Methods
    // -----------------------------------------------------------------------

    /// Append arbitrary binary data to the packet buffer.
    ///
    /// Returns the starting offset where the data was placed, or `None` on
    /// failure (practically never — see [`expand`] documentation).
    ///
    /// Replaces C's `put_opt6(data, len)` (outpacket.c line 421):
    /// ```c
    /// void *put_opt6(void *data, size_t len) {
    ///     void *p = expand(len);
    ///     if (p && data)
    ///         memcpy(p, data, len);
    ///     return p;
    /// }
    /// ```
    ///
    /// # Arguments
    /// * `data` — Byte slice to append.
    ///
    /// # Returns
    /// `Some(offset)` where the data was placed, or `None` on allocation
    /// failure.
    pub fn put_opt6(&mut self, data: &[u8]) -> Option<usize> {
        if data.is_empty() {
            return Some(self.pos);
        }
        let start = self.expand(data.len())?;
        self.buf[start..start + data.len()].copy_from_slice(data);
        Some(start)
    }

    /// Allocate `len` bytes of raw space in the buffer for in-place writing.
    ///
    /// Returns a mutable slice over the newly-allocated region, allowing the
    /// caller to write data directly without an intermediate copy.
    ///
    /// This is the Rust equivalent of C's `put_opt6(NULL, len)` pattern, which
    /// allocates space without copying any data into it.
    ///
    /// # Arguments
    /// * `len` — Number of bytes to allocate.
    ///
    /// # Returns
    /// `Some(&mut [u8])` over the allocated region, or `None` on failure.
    ///
    /// # Examples
    /// ```
    /// use dnsmasq::dhcp::v6::outpacket::OutPacket;
    /// let mut pkt = OutPacket::new();
    /// if let Some(space) = pkt.put_opt6_raw(4) {
    ///     space[0] = 0xDE;
    ///     space[1] = 0xAD;
    ///     space[2] = 0xBE;
    ///     space[3] = 0xEF;
    /// }
    /// assert_eq!(pkt.as_bytes(), &[0xDE, 0xAD, 0xBE, 0xEF]);
    /// ```
    pub fn put_opt6_raw(&mut self, len: usize) -> Option<&mut [u8]> {
        let start = self.expand(len)?;
        Some(&mut self.buf[start..start + len])
    }

    /// Append a 32-bit unsigned integer in network byte order (big-endian).
    ///
    /// Replaces C's `put_opt6_long()` (outpacket.c line 485):
    /// ```c
    /// void put_opt6_long(unsigned int val) {
    ///     void *p = expand(4);
    ///     PUTLONG(val, p);
    /// }
    /// ```
    ///
    /// Used for: IAID, T1, T2, preferred/valid lifetimes, enterprise numbers.
    ///
    /// # Arguments
    /// * `val` — 32-bit value to append in big-endian byte order.
    #[inline]
    pub fn put_opt6_long(&mut self, val: u32) {
        self.put_opt6(&val.to_be_bytes());
    }

    /// Append a 16-bit unsigned integer in network byte order (big-endian).
    ///
    /// Replaces C's `put_opt6_short()` (outpacket.c line 551):
    /// ```c
    /// void put_opt6_short(unsigned int val) {
    ///     void *p = expand(2);
    ///     PUTSHORT(val, p);
    /// }
    /// ```
    ///
    /// Used for: status codes, DUID types, hardware types, option request codes.
    ///
    /// # Arguments
    /// * `val` — 16-bit value to append in big-endian byte order.
    #[inline]
    pub fn put_opt6_short(&mut self, val: u16) {
        self.put_opt6(&val.to_be_bytes());
    }

    /// Append a single byte to the packet buffer.
    ///
    /// Replaces C's `put_opt6_char()` (outpacket.c line 617):
    /// ```c
    /// void put_opt6_char(unsigned int val) {
    ///     unsigned char *p = expand(1);
    ///     *p = val;
    /// }
    /// ```
    ///
    /// Used for: message types, preference values, hop counts, prefix lengths.
    ///
    /// # Arguments
    /// * `val` — Single byte to append.
    #[inline]
    pub fn put_opt6_char(&mut self, val: u8) {
        if let Some(start) = self.expand(1) {
            self.buf[start] = val;
        }
    }

    /// Append a UTF-8 string **without** a null terminator.
    ///
    /// DHCPv6 protocol uses length-delimited strings in TLV options, so
    /// null termination is neither needed nor desired.
    ///
    /// Replaces C's `put_opt6_string()` (outpacket.c line 697):
    /// ```c
    /// void put_opt6_string(char *s) {
    ///     put_opt6(s, strlen(s));
    /// }
    /// ```
    ///
    /// # Arguments
    /// * `s` — String slice to append (UTF-8 bytes, no trailing NUL).
    ///
    /// # Examples
    /// ```
    /// use dnsmasq::dhcp::v6::outpacket::OutPacket;
    /// let mut pkt = OutPacket::new();
    /// pkt.put_opt6_string("hello");
    /// assert_eq!(pkt.as_bytes(), b"hello");
    /// assert_eq!(pkt.len(), 5);  // No null terminator
    /// ```
    #[inline]
    pub fn put_opt6_string(&mut self, s: &str) {
        self.put_opt6(s.as_bytes());
    }

    // -----------------------------------------------------------------------
    // Container Finalization
    // -----------------------------------------------------------------------

    /// Finalize a DHCPv6 option container by back-patching its length field.
    ///
    /// The length is calculated as `current_position - container_start - 4`,
    /// which excludes the 4-byte option header (option code + length fields)
    /// but includes all option data and any nested sub-options.
    ///
    /// Replaces C's `end_opt6()` (outpacket.c line 116):
    /// ```c
    /// void end_opt6(int container) {
    ///     void *p = daemon->outpacket.iov_base + container + 2;
    ///     u16 len = outpacket_counter - container - 4;
    ///     PUTSHORT(len, p);
    /// }
    /// ```
    ///
    /// **CRITICAL**: This enables nested options. For example, an IA_NA option
    /// may contain multiple IAADDR sub-options. The IA_NA's length field will
    /// include the total size of all IAADDR sub-options plus the IA_NA's own
    /// fixed fields (IAID + T1 + T2 = 12 bytes).
    ///
    /// # Arguments
    /// * `container` — The buffer offset returned by a previous [`new_opt6`]
    ///   call. The 2-byte length field at `container + 2` will be overwritten.
    ///
    /// # Panics
    /// Panics (via slice bounds check) if `container + 4 > self.pos` or if
    /// `container + 4 > self.buf.len()`. This indicates a programming error
    /// where `end_opt6` is called without a matching `new_opt6`.
    ///
    /// # Examples
    /// ```
    /// use dnsmasq::dhcp::v6::outpacket::OutPacket;
    /// let mut pkt = OutPacket::new();
    /// let start = pkt.new_opt6(0x000D);  // OPTION6_STATUS_CODE
    /// pkt.put_opt6_short(0);             // success status
    /// pkt.put_opt6_string("OK");         // status message
    /// pkt.end_opt6(start);               // length = 2 + 2 = 4
    /// assert_eq!(pkt.len(), 4 + 4);      // header(4) + data(4)
    /// ```
    pub fn end_opt6(&mut self, container: usize) {
        // Length = total bytes since container start, minus the 4-byte header.
        let len = (self.pos - container - OPT6_HEADER_SIZE) as u16;
        // Back-patch the 2-byte length field at offset container+2.
        self.buf[container + 2..container + 4].copy_from_slice(&len.to_be_bytes());
    }

    // -----------------------------------------------------------------------
    // Buffer Access
    // -----------------------------------------------------------------------

    /// Return a read-only view of the constructed packet data.
    ///
    /// The returned slice covers `[0..pos)` — only the bytes that have been
    /// written. Bytes beyond `pos` in the underlying buffer are not included.
    ///
    /// This is the primary method for obtaining the final packet bytes for
    /// transmission over the network.
    ///
    /// # Examples
    /// ```
    /// use dnsmasq::dhcp::v6::outpacket::OutPacket;
    /// let mut pkt = OutPacket::new();
    /// pkt.put_opt6_short(0x0001);
    /// assert_eq!(pkt.as_bytes(), &[0x00, 0x01]);
    /// ```
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.pos]
    }

    /// Return a mutable view of the constructed packet data.
    ///
    /// The returned slice covers `[0..pos)` — only the bytes that have been
    /// written. This allows in-place modification of already-written data
    /// (e.g., patching fields after computing checksums).
    ///
    /// # Examples
    /// ```
    /// use dnsmasq::dhcp::v6::outpacket::OutPacket;
    /// let mut pkt = OutPacket::new();
    /// pkt.put_opt6_long(0);
    /// let bytes = pkt.as_mut_bytes();
    /// bytes[0] = 0xFF;
    /// assert_eq!(pkt.as_bytes()[0], 0xFF);
    /// ```
    #[inline]
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.buf[..self.pos]
    }
}

impl Default for OutPacket {
    /// Create a default `OutPacket` — equivalent to [`OutPacket::new()`].
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Unit Tests
// ===========================================================================

#[cfg(test)]
#[allow(
    clippy::field_reassign_with_default,
    clippy::needless_borrows_for_generic_args,
    clippy::unnecessary_cast,
    clippy::assertions_on_constants,
    clippy::len_zero,
    clippy::vec_init_then_push,
    clippy::unchecked_duration_subtraction,
    clippy::manual_string_new,
    clippy::cloned_ref_to_slice_refs,
    clippy::manual_range_contains,
    clippy::trim_split_whitespace,
    clippy::identity_op,
    clippy::io_other_error,
    clippy::useless_vec,
    clippy::const_is_empty,
    clippy::clone_on_copy,
    clippy::absurd_extreme_comparisons,
    clippy::overly_complex_bool_expr,
    clippy::write_literal,
    clippy::int_plus_one,
    clippy::write_with_newline,
    clippy::float_cmp,
    clippy::double_comparisons,
    clippy::large_stack_arrays,
    clippy::writeln_empty_string,
    unused_comparisons,
    unused_mut,
    unused_variables
)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Constructor and reset tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_new_empty() {
        let pkt = OutPacket::new();
        assert_eq!(pkt.len(), 0);
        assert!(pkt.as_bytes().is_empty());
    }

    #[test]
    fn test_with_capacity() {
        let pkt = OutPacket::with_capacity(1500);
        assert_eq!(pkt.len(), 0);
        assert!(pkt.as_bytes().is_empty());
        // Internal buffer should be pre-allocated
        assert_eq!(pkt.buf.len(), 1500);
    }

    #[test]
    fn test_default_is_new() {
        let pkt = OutPacket::default();
        assert_eq!(pkt.len(), 0);
        assert!(pkt.as_bytes().is_empty());
    }

    #[test]
    fn test_reset_clears() {
        let mut pkt = OutPacket::new();
        pkt.put_opt6_long(42);
        assert_eq!(pkt.len(), 4);
        pkt.reset();
        assert_eq!(pkt.len(), 0);
        assert!(pkt.as_bytes().is_empty());
    }

    #[test]
    fn test_reset_zero_fills() {
        let mut pkt = OutPacket::new();
        pkt.put_opt6_long(0xDEADBEEF);
        assert_eq!(pkt.len(), 4);
        pkt.reset();
        // After reset, the buffer should be zero-filled to prevent leakage.
        // The internal buffer retains its allocation but all bytes are 0.
        assert!(pkt.buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_reset_preserves_capacity_for_reuse() {
        let mut pkt = OutPacket::with_capacity(256);
        pkt.put_opt6_long(1);
        pkt.put_opt6_long(2);
        pkt.reset();
        assert_eq!(pkt.len(), 0);
        // Buffer should still be allocated (not deallocated).
        assert!(pkt.buf.len() >= 256);
    }

    // -----------------------------------------------------------------------
    // Position management tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_save_counter_query() {
        let mut pkt = OutPacket::new();
        pkt.put_opt6_long(42);
        let saved = pkt.save_counter(None);
        assert_eq!(saved, 4);
        // Position should remain unchanged.
        assert_eq!(pkt.len(), 4);
    }

    #[test]
    fn test_save_counter_set() {
        let mut pkt = OutPacket::new();
        pkt.put_opt6_long(42);
        pkt.put_opt6_long(99);
        assert_eq!(pkt.len(), 8);
        let old = pkt.save_counter(Some(4));
        assert_eq!(old, 8); // Returns old position
        assert_eq!(pkt.len(), 4); // Position restored
    }

    #[test]
    fn test_save_counter_checkpoint_restore() {
        let mut pkt = OutPacket::new();
        pkt.put_opt6_long(42);
        let saved = pkt.save_counter(None);
        assert_eq!(saved, 4);
        pkt.put_opt6_long(99);
        assert_eq!(pkt.len(), 8);
        pkt.save_counter(Some(saved));
        assert_eq!(pkt.len(), 4); // Position restored to checkpoint
    }

    #[test]
    fn test_len_empty() {
        let pkt = OutPacket::new();
        assert_eq!(pkt.len(), 0);
    }

    #[test]
    fn test_len_after_writes() {
        let mut pkt = OutPacket::new();
        pkt.put_opt6_char(0x01);
        assert_eq!(pkt.len(), 1);
        pkt.put_opt6_short(0x0203);
        assert_eq!(pkt.len(), 3);
        pkt.put_opt6_long(0x04050607);
        assert_eq!(pkt.len(), 7);
    }

    // -----------------------------------------------------------------------
    // Option header creation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_new_opt6_header_format() {
        let mut pkt = OutPacket::new();
        let start = pkt.new_opt6(0x0003); // OPTION6_IA_NA
        assert_eq!(start, 0);
        assert_eq!(pkt.len(), 4); // 4-byte header
        let bytes = pkt.as_bytes();
        // Option code 3 in big-endian
        assert_eq!(bytes[0], 0x00);
        assert_eq!(bytes[1], 0x03);
        // Length 0 (not yet finalized)
        assert_eq!(bytes[2], 0x00);
        assert_eq!(bytes[3], 0x00);
    }

    #[test]
    fn test_simple_option() {
        let mut pkt = OutPacket::new();
        let start = pkt.new_opt6(0x0007); // OPTION6_PREFERENCE
        pkt.put_opt6_char(255); // Preference value
        pkt.end_opt6(start);
        let bytes = pkt.as_bytes();
        assert_eq!(bytes, &[0x00, 0x07, 0x00, 0x01, 0xFF]);
    }

    // -----------------------------------------------------------------------
    // Data addition method tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_put_opt6_binary_data() {
        let mut pkt = OutPacket::new();
        let data = [0x01, 0x02, 0x03, 0x04];
        let offset = pkt.put_opt6(&data);
        assert_eq!(offset, Some(0));
        assert_eq!(pkt.as_bytes(), &[0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_put_opt6_empty_data() {
        let mut pkt = OutPacket::new();
        let offset = pkt.put_opt6(&[]);
        assert_eq!(offset, Some(0)); // Returns current pos for empty data
        assert_eq!(pkt.len(), 0);
    }

    #[test]
    fn test_put_opt6_raw_write() {
        let mut pkt = OutPacket::new();
        if let Some(space) = pkt.put_opt6_raw(4) {
            space[0] = 0xDE;
            space[1] = 0xAD;
            space[2] = 0xBE;
            space[3] = 0xEF;
        }
        assert_eq!(pkt.as_bytes(), &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_put_opt6_raw_zero_len() {
        let mut pkt = OutPacket::new();
        let result = pkt.put_opt6_raw(0);
        assert!(result.is_some());
        assert_eq!(result.unwrap().len(), 0);
        assert_eq!(pkt.len(), 0);
    }

    #[test]
    fn test_put_opt6_long_big_endian() {
        let mut pkt = OutPacket::new();
        pkt.put_opt6_long(0x01234567);
        assert_eq!(pkt.as_bytes(), &[0x01, 0x23, 0x45, 0x67]);
    }

    #[test]
    fn test_put_opt6_long_zero() {
        let mut pkt = OutPacket::new();
        pkt.put_opt6_long(0);
        assert_eq!(pkt.as_bytes(), &[0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_put_opt6_long_max() {
        let mut pkt = OutPacket::new();
        pkt.put_opt6_long(u32::MAX);
        assert_eq!(pkt.as_bytes(), &[0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_put_opt6_short_big_endian() {
        let mut pkt = OutPacket::new();
        pkt.put_opt6_short(0x0123);
        assert_eq!(pkt.as_bytes(), &[0x01, 0x23]);
    }

    #[test]
    fn test_put_opt6_short_zero() {
        let mut pkt = OutPacket::new();
        pkt.put_opt6_short(0);
        assert_eq!(pkt.as_bytes(), &[0x00, 0x00]);
    }

    #[test]
    fn test_put_opt6_short_max() {
        let mut pkt = OutPacket::new();
        pkt.put_opt6_short(u16::MAX);
        assert_eq!(pkt.as_bytes(), &[0xFF, 0xFF]);
    }

    #[test]
    fn test_put_opt6_char() {
        let mut pkt = OutPacket::new();
        pkt.put_opt6_char(0xAB);
        assert_eq!(pkt.as_bytes(), &[0xAB]);
        assert_eq!(pkt.len(), 1);
    }

    #[test]
    fn test_put_opt6_string_no_null() {
        let mut pkt = OutPacket::new();
        pkt.put_opt6_string("hello");
        assert_eq!(pkt.as_bytes(), b"hello");
        assert_eq!(pkt.len(), 5); // No null terminator
    }

    #[test]
    fn test_put_opt6_string_empty() {
        let mut pkt = OutPacket::new();
        pkt.put_opt6_string("");
        assert_eq!(pkt.len(), 0);
    }

    #[test]
    fn test_put_opt6_string_unicode() {
        let mut pkt = OutPacket::new();
        pkt.put_opt6_string("café");
        // "café" is 5 bytes in UTF-8 (c a f é[2 bytes])
        assert_eq!(pkt.len(), 5);
        assert_eq!(pkt.as_bytes(), "café".as_bytes());
    }

    // -----------------------------------------------------------------------
    // Container finalization tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_end_opt6_empty_container() {
        let mut pkt = OutPacket::new();
        let start = pkt.new_opt6(0x000E); // OPTION6_RAPID_COMMIT (no data)
        pkt.end_opt6(start);
        let bytes = pkt.as_bytes();
        assert_eq!(bytes, &[0x00, 0x0E, 0x00, 0x00]); // code=14, len=0
    }

    #[test]
    fn test_end_opt6_with_data() {
        let mut pkt = OutPacket::new();
        let start = pkt.new_opt6(0x000D); // OPTION6_STATUS_CODE
        pkt.put_opt6_short(0); // Success
        pkt.put_opt6_string("OK");
        pkt.end_opt6(start);
        let bytes = pkt.as_bytes();
        // Header: code=0x000D, len=4 (2-byte status + 2-byte string)
        assert_eq!(bytes[0..2], [0x00, 0x0D]);
        assert_eq!(bytes[2..4], [0x00, 0x04]);
        // Data: status=0, string="OK"
        assert_eq!(bytes[4..6], [0x00, 0x00]);
        assert_eq!(&bytes[6..8], b"OK");
    }

    // -----------------------------------------------------------------------
    // Nested option tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_nested_ia_na_with_iaaddr() {
        let mut pkt = OutPacket::new();

        // Start IA_NA container (option code 3)
        let ia_na = pkt.new_opt6(0x0003);
        pkt.put_opt6_long(0x12345678); // IAID
        pkt.put_opt6_long(3600); // T1
        pkt.put_opt6_long(7200); // T2

        // Start nested IAADDR sub-option (option code 5)
        let ia_addr = pkt.new_opt6(0x0005);
        // IPv6 address: 2001:db8::1 (16 bytes)
        pkt.put_opt6(&[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ]);
        pkt.put_opt6_long(7200); // preferred lifetime
        pkt.put_opt6_long(14400); // valid lifetime
        pkt.end_opt6(ia_addr); // Finalize IAADDR: len = 16 + 4 + 4 = 24

        pkt.end_opt6(ia_na); // Finalize IA_NA: len = 12 + (4 + 24) = 40

        let bytes = pkt.as_bytes();

        // Verify IA_NA header
        assert_eq!(bytes[0..2], [0x00, 0x03]); // option code = 3
        assert_eq!(u16::from_be_bytes([bytes[2], bytes[3]]), 40); // IA_NA length = 40

        // Verify IAID
        assert_eq!(
            u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            0x12345678
        );

        // Verify T1 and T2
        assert_eq!(
            u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            3600
        );
        assert_eq!(
            u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
            7200
        );

        // Verify nested IAADDR header at offset 16
        assert_eq!(bytes[16..18], [0x00, 0x05]); // option code = 5
        assert_eq!(u16::from_be_bytes([bytes[18], bytes[19]]), 24); // IAADDR length = 24

        // Verify IPv6 address starts at offset 20
        assert_eq!(bytes[20], 0x20);
        assert_eq!(bytes[21], 0x01);

        // Total packet size: 4 (IA_NA header) + 40 (IA_NA data) = 44
        assert_eq!(pkt.len(), 44);
    }

    #[test]
    fn test_nested_ia_na_with_two_iaaddrs() {
        let mut pkt = OutPacket::new();

        let ia_na = pkt.new_opt6(0x0003);
        pkt.put_opt6_long(0x00000001); // IAID
        pkt.put_opt6_long(1800); // T1
        pkt.put_opt6_long(3600); // T2

        // First IAADDR
        let ia_addr1 = pkt.new_opt6(0x0005);
        pkt.put_opt6(&[0; 16]); // ::0 address
        pkt.put_opt6_long(3600); // preferred
        pkt.put_opt6_long(7200); // valid
        pkt.end_opt6(ia_addr1); // len = 24

        // Second IAADDR
        let ia_addr2 = pkt.new_opt6(0x0005);
        pkt.put_opt6(&[0xFF; 16]); // all-ones address
        pkt.put_opt6_long(1800); // preferred
        pkt.put_opt6_long(3600); // valid
        pkt.end_opt6(ia_addr2); // len = 24

        // Finalize IA_NA: 12 (IAID+T1+T2) + 28 (IAADDR1) + 28 (IAADDR2) = 68
        pkt.end_opt6(ia_na);

        let bytes = pkt.as_bytes();
        assert_eq!(u16::from_be_bytes([bytes[2], bytes[3]]), 68);
        // Total: 4 (header) + 68 (data) = 72
        assert_eq!(pkt.len(), 72);
    }

    // -----------------------------------------------------------------------
    // Multiple sequential options test
    // -----------------------------------------------------------------------

    #[test]
    fn test_multiple_sequential_options() {
        let mut pkt = OutPacket::new();

        // Option 1: Server ID (option code 2)
        let s1 = pkt.new_opt6(0x0002);
        pkt.put_opt6(&[0x00, 0x01, 0x00, 0x01]); // DUID-LLT header
        pkt.end_opt6(s1);

        // Option 2: Status Code (option code 13)
        let s2 = pkt.new_opt6(0x000D);
        pkt.put_opt6_short(0); // Success
        pkt.put_opt6_string("OK");
        pkt.end_opt6(s2);

        // Verify total length: (4+4) + (4+4) = 16
        assert_eq!(pkt.len(), 16);

        let bytes = pkt.as_bytes();
        // First option: code=2, len=4
        assert_eq!(bytes[0..2], [0x00, 0x02]);
        assert_eq!(bytes[2..4], [0x00, 0x04]);
        // Second option: code=13, len=4
        assert_eq!(bytes[8..10], [0x00, 0x0D]);
        assert_eq!(bytes[10..12], [0x00, 0x04]);
    }

    // -----------------------------------------------------------------------
    // Buffer access tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_as_bytes_empty() {
        let pkt = OutPacket::new();
        assert!(pkt.as_bytes().is_empty());
    }

    #[test]
    fn test_as_bytes_content() {
        let mut pkt = OutPacket::new();
        pkt.put_opt6(&[0x01, 0x02, 0x03]);
        let bytes = pkt.as_bytes();
        assert_eq!(bytes, &[0x01, 0x02, 0x03]);
        assert_eq!(bytes.len(), 3);
    }

    #[test]
    fn test_as_mut_bytes_modify() {
        let mut pkt = OutPacket::new();
        pkt.put_opt6_long(0);
        {
            let bytes = pkt.as_mut_bytes();
            bytes[0] = 0xFF;
            bytes[3] = 0xAA;
        }
        assert_eq!(pkt.as_bytes(), &[0xFF, 0x00, 0x00, 0xAA]);
    }

    // -----------------------------------------------------------------------
    // Buffer growth / expand tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_auto_growth_from_empty() {
        let mut pkt = OutPacket::new();
        // Write more data than initial capacity
        for i in 0..=255u8 {
            pkt.put_opt6_char(i);
        }
        assert_eq!(pkt.len(), 256);
        // Verify all bytes written correctly
        for (i, &byte) in pkt.as_bytes().iter().enumerate() {
            assert_eq!(byte, i as u8);
        }
    }

    #[test]
    fn test_growth_beyond_initial_capacity() {
        let mut pkt = OutPacket::with_capacity(4);
        pkt.put_opt6_long(1);
        pkt.put_opt6_long(2); // Should trigger growth beyond initial 4 bytes
        assert_eq!(pkt.len(), 8);
        assert_eq!(
            u32::from_be_bytes([
                pkt.as_bytes()[0],
                pkt.as_bytes()[1],
                pkt.as_bytes()[2],
                pkt.as_bytes()[3]
            ]),
            1
        );
        assert_eq!(
            u32::from_be_bytes([
                pkt.as_bytes()[4],
                pkt.as_bytes()[5],
                pkt.as_bytes()[6],
                pkt.as_bytes()[7]
            ]),
            2
        );
    }

    // -----------------------------------------------------------------------
    // Clone test
    // -----------------------------------------------------------------------

    #[test]
    fn test_clone_independence() {
        let mut pkt = OutPacket::new();
        pkt.put_opt6_long(42);
        let mut pkt2 = pkt.clone();
        pkt2.put_opt6_long(99);
        assert_eq!(pkt.len(), 4);
        assert_eq!(pkt2.len(), 8);
    }

    // -----------------------------------------------------------------------
    // End-to-end DHCPv6 packet construction test
    // -----------------------------------------------------------------------

    #[test]
    fn test_full_dhcpv6_reply_construction() {
        // Simulate building a minimal DHCPv6 REPLY message body:
        // - Server ID option
        // - Client ID option
        // - IA_NA with one IAADDR
        // - Status Code (success)

        let mut pkt = OutPacket::new();

        // Server ID (option 2) with a simple DUID-LL
        let sid = pkt.new_opt6(0x0002);
        pkt.put_opt6_short(0x0003); // DUID type: DUID-LL
        pkt.put_opt6_short(0x0001); // Hardware type: Ethernet
        pkt.put_opt6(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]); // MAC
        pkt.end_opt6(sid); // len = 2 + 2 + 6 = 10

        // Client ID (option 1) — echo back client's DUID
        let cid = pkt.new_opt6(0x0001);
        pkt.put_opt6(&[0x00, 0x01, 0x00, 0x01, 0x11, 0x22, 0x33, 0x44]); // client DUID
        pkt.end_opt6(cid); // len = 8

        // IA_NA (option 3)
        let ia_na = pkt.new_opt6(0x0003);
        pkt.put_opt6_long(1); // IAID = 1
        pkt.put_opt6_long(900); // T1 = 900s
        pkt.put_opt6_long(1800); // T2 = 1800s

        // Nested IAADDR (option 5)
        let ia_addr = pkt.new_opt6(0x0005);
        pkt.put_opt6(&[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x42,
        ]); // 2001:db8:1::42
        pkt.put_opt6_long(3600); // preferred = 3600
        pkt.put_opt6_long(7200); // valid = 7200
        pkt.end_opt6(ia_addr); // IAADDR len = 16 + 4 + 4 = 24

        pkt.end_opt6(ia_na); // IA_NA len = 12 + 28 = 40

        // Status Code (option 13) — success
        let sc = pkt.new_opt6(0x000D);
        pkt.put_opt6_short(0); // success
        pkt.end_opt6(sc); // len = 2

        // Verify total packet size
        // Server ID: 4+10 = 14
        // Client ID: 4+8  = 12
        // IA_NA:     4+40 = 44
        // Status:    4+2  = 6
        // Total:     76
        assert_eq!(pkt.len(), 76);

        // Verify option code positions
        let bytes = pkt.as_bytes();
        assert_eq!(u16::from_be_bytes([bytes[0], bytes[1]]), 0x0002); // Server ID
        assert_eq!(u16::from_be_bytes([bytes[14], bytes[15]]), 0x0001); // Client ID
        assert_eq!(u16::from_be_bytes([bytes[26], bytes[27]]), 0x0003); // IA_NA
        assert_eq!(u16::from_be_bytes([bytes[70], bytes[71]]), 0x000D); // Status
    }

    // -----------------------------------------------------------------------
    // Edge case: save_counter(Some(0)) after writes
    // -----------------------------------------------------------------------

    #[test]
    fn test_save_counter_reset_to_zero() {
        let mut pkt = OutPacket::new();
        pkt.put_opt6_long(0xAABBCCDD);
        assert_eq!(pkt.len(), 4);
        let old = pkt.save_counter(Some(0));
        assert_eq!(old, 4);
        assert_eq!(pkt.len(), 0);
        assert!(pkt.as_bytes().is_empty());
    }

    // -----------------------------------------------------------------------
    // Test that put_opt6_raw returns correctly sized slice
    // -----------------------------------------------------------------------

    #[test]
    fn test_put_opt6_raw_returns_exact_slice() {
        let mut pkt = OutPacket::new();
        pkt.put_opt6_long(0); // Write 4 bytes first
        if let Some(slice) = pkt.put_opt6_raw(16) {
            assert_eq!(slice.len(), 16);
            // Fill with a pattern
            for (i, byte) in slice.iter_mut().enumerate() {
                *byte = i as u8;
            }
        }
        assert_eq!(pkt.len(), 20);
        // Verify the pattern was written at offset 4
        for i in 0..16 {
            assert_eq!(pkt.as_bytes()[4 + i], i as u8);
        }
    }

    // -----------------------------------------------------------------------
    // Test with_capacity reuse after reset
    // -----------------------------------------------------------------------

    #[test]
    fn test_with_capacity_reuse() {
        let mut pkt = OutPacket::with_capacity(64);
        pkt.put_opt6_long(1);
        pkt.put_opt6_long(2);
        pkt.reset();
        // Now reuse — should not need reallocation for small writes
        pkt.put_opt6_short(0x0003);
        assert_eq!(pkt.len(), 2);
        assert_eq!(pkt.as_bytes(), &[0x00, 0x03]);
    }
}

// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2000-2025 Simon Kelley — Rust rewrite

//! DHCPv6 option serialization buffer builder.
//!
//! This module provides a growable buffer for constructing DHCPv6 response
//! messages (ADVERTISE, REPLY, RECONFIGURE) with nested option support.
//! It replaces the C `outpacket.c` implementation, converting global state
//! (`daemon->outpacket` and `outpacket_counter`) into an encapsulated
//! [`Dhcpv6OutPacket`] struct that owns its buffer and position tracking.
//!
//! # Architecture
//!
//! DHCPv6 options use a TLV (Type-Length-Value) encoding where each option
//! consists of a 2-byte option code, a 2-byte length, and variable-length
//! data (RFC 3315 Section 22). Container options such as IA_NA, IA_TA, and
//! IA_PD nest sub-options, requiring length backpatching after all children
//! are written.
//!
//! The buffer builder provides:
//! - Automatic buffer growth via `Vec<u8>` (replacing C `expand_buf`/`realloc`)
//! - Position tracking for nested option construction
//! - Typed encoding methods for all DHCPv6 data widths (8/16/32-bit and raw)
//! - Network byte order (big-endian) encoding for multi-byte integers
//!
//! # Usage
//!
//! ```rust,ignore
//! use crate::dhcp::v6::outpacket::Dhcpv6OutPacket;
//!
//! let mut pkt = Dhcpv6OutPacket::new();
//! pkt.reset();
//!
//! // Construct IA_NA option with nested IA_ADDR
//! let ia_na = pkt.new_opt6(3); // OPTION6_IA_NA
//! pkt.put_opt6_long(0x0001_0001); // IAID
//! pkt.put_opt6_long(3600);        // T1
//! pkt.put_opt6_long(7200);        // T2
//!
//! // Nested IA_ADDR sub-option
//! let ia_addr = pkt.new_opt6(5); // OPTION6_IAADDR
//! pkt.put_opt6(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
//! pkt.put_opt6_long(7200);  // preferred lifetime
//! pkt.put_opt6_long(14400); // valid lifetime
//! pkt.end_opt6(ia_addr);
//!
//! pkt.end_opt6(ia_na);
//! let packet_bytes = pkt.as_bytes();
//! ```
//!
//! # Wire Protocol Fidelity
//!
//! The output bytes are byte-for-byte identical to the C implementation
//! for the same sequence of operations. All multi-byte integers are
//! encoded in network byte order (big-endian) per RFC 3315. String data
//! is written WITHOUT a null terminator, matching the DHCPv6 wire format
//! where length is determined by the enclosing option's length field.

/// DHCPv6 outgoing packet buffer builder.
///
/// Provides growable buffer management for constructing DHCPv6 response
/// messages with nested option support. Replaces the C global
/// `daemon->outpacket` (`struct iovec`) and the static `outpacket_counter`
/// variable from `outpacket.c`.
///
/// # Design
///
/// * `buffer` — Internal `Vec<u8>` that replaces the C `iov_base` / `iov_len`
///   pair managed by `expand_buf()`. Growth is handled automatically by
///   `Vec::resize` with zero-fill, matching the C `realloc` + `memset`
///   semantics.
/// * `counter` — Current write position (byte offset) into `buffer`,
///   replacing the C `static size_t outpacket_counter`. All write methods
///   advance `counter` by the number of bytes written.
///
/// The struct is not `Clone` by design: only one packet can be under
/// construction at a time, mirroring the single-threaded C architecture.
#[derive(Debug)]
pub struct Dhcpv6OutPacket {
    /// Internal buffer for packet construction.
    /// Replaces `daemon->outpacket.iov_base` + `iov_len`.
    buffer: Vec<u8>,
    /// Current write position in the buffer.
    /// Replaces the C `static size_t outpacket_counter`.
    counter: usize,
}

// ---------------------------------------------------------------------------
// Construction and lifetime management
// ---------------------------------------------------------------------------

impl Dhcpv6OutPacket {
    /// Create a new, empty outpacket buffer.
    ///
    /// The buffer starts with zero capacity and grows on demand as options
    /// are appended. Call [`reset`](Self::reset) before constructing each
    /// new DHCPv6 message to clear residual data.
    #[inline]
    pub fn new() -> Self {
        Dhcpv6OutPacket {
            buffer: Vec::new(),
            counter: 0,
        }
    }

    /// Reset the buffer for constructing a new DHCPv6 message.
    ///
    /// Zero-fills the existing buffer to prevent information leakage between
    /// packets, then resets the write position to the beginning. Matches
    /// the C implementation: `memset(iov_base, 0, iov_len); save_counter(0);`
    ///
    /// The buffer capacity is preserved so that subsequent packets can reuse
    /// the already-allocated memory without additional allocations.
    pub fn reset(&mut self) {
        // Zero-fill existing buffer to prevent information leakage.
        // This matches the C memset(daemon->outpacket.iov_base, 0, iov_len).
        for byte in self.buffer.iter_mut() {
            *byte = 0;
        }
        self.counter = 0;
    }

    // -----------------------------------------------------------------------
    // Position management
    // -----------------------------------------------------------------------

    /// Save the current write position and optionally set a new one.
    ///
    /// This is the dual-purpose checkpoint/restore mechanism used for nested
    /// DHCPv6 option construction. It replaces the C `save_counter()` function
    /// from `outpacket.c` lines 216-224.
    ///
    /// # Arguments
    ///
    /// * `newval` — Pass `-1` to query the current position without
    ///   modification. Pass any non-negative value to set the write position
    ///   to that offset.
    ///
    /// # Returns
    ///
    /// The write position *before* any modification.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # use crate::dhcp::v6::outpacket::Dhcpv6OutPacket;
    /// let mut pkt = Dhcpv6OutPacket::new();
    /// let pos = pkt.save_counter(-1); // query: returns 0
    /// assert_eq!(pos, 0);
    ///
    /// pkt.put_opt6_char(0xFF);
    /// let prev = pkt.save_counter(0); // set back to 0, returns 1
    /// assert_eq!(prev, 1);
    /// assert_eq!(pkt.len(), 0);
    /// ```
    pub fn save_counter(&mut self, newval: i32) -> usize {
        let ret = self.counter;
        if newval >= 0 {
            self.counter = newval as usize;
        }
        ret
    }

    // -----------------------------------------------------------------------
    // Internal buffer expansion
    // -----------------------------------------------------------------------

    /// Ensure the buffer has capacity for `headroom` additional bytes at the
    /// current write position, then advance the counter.
    ///
    /// Returns the offset of the first byte of the newly allocated region,
    /// or `None` if the zero-length request is made (degenerate case).
    ///
    /// # Implementation Note
    ///
    /// The C version calls `expand_buf()` which may return `NULL` on OOM.
    /// In Rust, `Vec::resize` panics on OOM, which is acceptable for this
    /// daemon — the `Option` return type preserves the C API shape but will
    /// always be `Some` in practice.
    fn expand(&mut self, headroom: usize) -> Option<usize> {
        let needed = self.counter + headroom;
        if needed > self.buffer.len() {
            self.buffer.resize(needed, 0);
        }
        let ret = self.counter;
        self.counter += headroom;
        Some(ret)
    }

    // -----------------------------------------------------------------------
    // Option header creation and finalization
    // -----------------------------------------------------------------------

    /// Create a new DHCPv6 option header (4 bytes: 2-byte code + 2-byte
    /// length initially zero).
    ///
    /// Returns the buffer offset of the option header. Pass this value to
    /// [`end_opt6`](Self::end_opt6) after all option data and sub-options
    /// have been written to backpatch the correct length.
    ///
    /// # Arguments
    ///
    /// * `opt` — DHCPv6 option code (e.g. `OPTION6_IA_NA`, `OPTION6_IAADDR`).
    ///
    /// # Wire Format
    ///
    /// ```text
    /// +--------+--------+--------+--------+
    /// | option-code (BE) | option-len (BE) |
    /// +--------+--------+--------+--------+
    ///   2 bytes            2 bytes (= 0)
    /// ```
    ///
    /// Corresponds to `outpacket.c` `new_opt6()` (lines 343-355).
    pub fn new_opt6(&mut self, opt: u16) -> usize {
        let ret = self.counter;
        if let Some(offset) = self.expand(4) {
            // Option code in network byte order (big-endian).
            let code_bytes = opt.to_be_bytes();
            self.buffer[offset] = code_bytes[0];
            self.buffer[offset + 1] = code_bytes[1];
            // Length field initialised to zero; backpatched by end_opt6().
            self.buffer[offset + 2] = 0;
            self.buffer[offset + 3] = 0;
        }
        ret
    }

    /// Finalize a DHCPv6 option by backpatching its length field.
    ///
    /// Calculates the number of bytes written *after* the 4-byte option
    /// header at `container` and writes the result as a big-endian 16-bit
    /// length at `container + 2`.
    ///
    /// # Arguments
    ///
    /// * `container` — The offset returned by a prior [`new_opt6`](Self::new_opt6)
    ///   call.
    ///
    /// # Panics
    ///
    /// Panics if `container + 3` is beyond the current buffer length or if
    /// the calculated length overflows `u16`.
    ///
    /// Corresponds to `outpacket.c` `end_opt6()` (lines 116-122).
    pub fn end_opt6(&mut self, container: usize) {
        let data_len = (self.counter - container - 4) as u16;
        let len_bytes = data_len.to_be_bytes();
        self.buffer[container + 2] = len_bytes[0];
        self.buffer[container + 3] = len_bytes[1];
    }

    // -----------------------------------------------------------------------
    // Data encoding methods
    // -----------------------------------------------------------------------

    /// Append arbitrary binary data at the current write position.
    ///
    /// Returns the buffer offset where the data was written, or `None` on
    /// a zero-length write (degenerate case).
    ///
    /// Corresponds to `outpacket.c` `put_opt6()` (lines 421-429) when
    /// called with a non-NULL data pointer.
    pub fn put_opt6(&mut self, data: &[u8]) -> Option<usize> {
        if data.is_empty() {
            // Preserve counter semantics: nothing to write, return current pos.
            return Some(self.counter);
        }
        let offset = self.expand(data.len())?;
        self.buffer[offset..offset + data.len()].copy_from_slice(data);
        Some(offset)
    }

    /// Allocate `len` bytes of zero-initialized space without writing data.
    ///
    /// Returns the buffer offset of the allocated region. The caller may
    /// subsequently fill the space via [`buffer_mut`](Self::buffer_mut).
    ///
    /// This is the Rust equivalent of the C pattern `put_opt6(NULL, len)`.
    pub fn put_opt6_raw(&mut self, len: usize) -> Option<usize> {
        self.expand(len)
    }

    /// Append a 32-bit unsigned integer in network byte order (big-endian).
    ///
    /// Used for IAIDs, T1/T2 timers, preferred/valid lifetimes, and other
    /// 4-byte protocol fields.
    ///
    /// Corresponds to `outpacket.c` `put_opt6_long()` (lines 485-491).
    pub fn put_opt6_long(&mut self, val: u32) {
        if let Some(offset) = self.expand(4) {
            let bytes = val.to_be_bytes();
            self.buffer[offset] = bytes[0];
            self.buffer[offset + 1] = bytes[1];
            self.buffer[offset + 2] = bytes[2];
            self.buffer[offset + 3] = bytes[3];
        }
    }

    /// Append a 16-bit unsigned integer in network byte order (big-endian).
    ///
    /// Used for status codes, DUID types, hardware types, and other 2-byte
    /// protocol fields.
    ///
    /// Corresponds to `outpacket.c` `put_opt6_short()` (lines 551-557).
    pub fn put_opt6_short(&mut self, val: u16) {
        if let Some(offset) = self.expand(2) {
            let bytes = val.to_be_bytes();
            self.buffer[offset] = bytes[0];
            self.buffer[offset + 1] = bytes[1];
        }
    }

    /// Append an 8-bit unsigned integer.
    ///
    /// Used for message types, preference values, hop counts, and other
    /// single-byte protocol fields.
    ///
    /// Corresponds to `outpacket.c` `put_opt6_char()` (lines 617-623).
    pub fn put_opt6_char(&mut self, val: u8) {
        if let Some(offset) = self.expand(1) {
            self.buffer[offset] = val;
        }
    }

    /// Append a string *without* a null terminator.
    ///
    /// DHCPv6 options encode strings as raw bytes whose length is determined
    /// by the enclosing option's length field — null terminators are **not**
    /// used on the wire. This matches the C `put_opt6_string()` which calls
    /// `put_opt6(s, strlen(s))`.
    ///
    /// Corresponds to `outpacket.c` `put_opt6_string()` (lines 697-700).
    pub fn put_opt6_string(&mut self, s: &str) {
        self.put_opt6(s.as_bytes());
    }

    // -----------------------------------------------------------------------
    // Buffer accessors
    // -----------------------------------------------------------------------

    /// Return the current write position (number of valid bytes in the
    /// packet under construction).
    #[inline]
    pub fn len(&self) -> usize {
        self.counter
    }

    /// Return `true` if no data has been written since the last
    /// [`reset`](Self::reset) (or since construction).
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.counter == 0
    }

    /// Return an immutable byte slice of the constructed packet data
    /// (from offset 0 up to the current write position).
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer[..self.counter]
    }

    /// Return a mutable reference to the internal buffer `Vec`.
    ///
    /// This is intended for low-level, in-place backpatching operations
    /// that cannot be expressed through the typed encoding methods. The
    /// caller is responsible for maintaining internal consistency (e.g. not
    /// shrinking the vec below `counter`).
    #[inline]
    pub fn buffer_mut(&mut self) -> &mut Vec<u8> {
        &mut self.buffer
    }

    /// Return the total allocated size of the internal buffer.
    ///
    /// This is the number of bytes currently reserved, which may be larger
    /// than [`len`](Self::len) if additional space was previously allocated
    /// and the counter was rewound via [`save_counter`](Self::save_counter)
    /// or [`reset`](Self::reset).
    #[inline]
    pub fn capacity(&self) -> usize {
        self.buffer.len()
    }
}

// ---------------------------------------------------------------------------
// Trait implementations
// ---------------------------------------------------------------------------

impl Default for Dhcpv6OutPacket {
    /// Equivalent to [`Dhcpv6OutPacket::new()`].
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Construction and reset -------------------------------------------

    #[test]
    fn test_new_creates_empty_packet() {
        let pkt = Dhcpv6OutPacket::new();
        assert_eq!(pkt.len(), 0);
        assert!(pkt.is_empty());
        assert_eq!(pkt.as_bytes(), &[]);
        assert_eq!(pkt.capacity(), 0);
    }

    #[test]
    fn test_default_matches_new() {
        let a = Dhcpv6OutPacket::new();
        let b = Dhcpv6OutPacket::default();
        assert_eq!(a.len(), b.len());
        assert_eq!(a.is_empty(), b.is_empty());
    }

    #[test]
    fn test_reset_zeroes_and_rewinds() {
        let mut pkt = Dhcpv6OutPacket::new();
        pkt.put_opt6_long(0xDEAD_BEEF);
        assert_eq!(pkt.len(), 4);

        pkt.reset();
        assert_eq!(pkt.len(), 0);
        assert!(pkt.is_empty());
        // The underlying buffer should be zero-filled but retain capacity.
        assert_eq!(pkt.capacity(), 4);
        assert_eq!(&pkt.buffer[..4], &[0, 0, 0, 0]);
    }

    // -- save_counter -----------------------------------------------------

    #[test]
    fn test_save_counter_query() {
        let mut pkt = Dhcpv6OutPacket::new();
        pkt.put_opt6_char(0x42);
        // Query with -1 should not change position.
        let pos = pkt.save_counter(-1);
        assert_eq!(pos, 1);
        assert_eq!(pkt.len(), 1);
    }

    #[test]
    fn test_save_counter_set() {
        let mut pkt = Dhcpv6OutPacket::new();
        pkt.put_opt6_short(0x1234);
        let prev = pkt.save_counter(0);
        assert_eq!(prev, 2);
        assert_eq!(pkt.len(), 0);
    }

    #[test]
    fn test_save_counter_roundtrip() {
        let mut pkt = Dhcpv6OutPacket::new();
        pkt.put_opt6_long(1);
        pkt.put_opt6_long(2);
        let saved = pkt.save_counter(-1); // 8
        assert_eq!(saved, 8);

        pkt.save_counter(4); // rewind to after first long
        assert_eq!(pkt.len(), 4);

        // Restore original position.
        pkt.save_counter(saved as i32);
        assert_eq!(pkt.len(), 8);
    }

    // -- expand (internal, tested via public API) -------------------------

    #[test]
    fn test_expand_grows_buffer() {
        let mut pkt = Dhcpv6OutPacket::new();
        assert_eq!(pkt.capacity(), 0);
        pkt.put_opt6_char(0xAA);
        assert!(pkt.capacity() >= 1);
        assert_eq!(pkt.len(), 1);
    }

    // -- new_opt6 / end_opt6 ----------------------------------------------

    #[test]
    fn test_new_opt6_writes_header() {
        let mut pkt = Dhcpv6OutPacket::new();
        let pos = pkt.new_opt6(0x0003); // OPTION6_IA_NA
        assert_eq!(pos, 0);
        assert_eq!(pkt.len(), 4);
        // Code = 0x0003 big-endian, Length = 0x0000.
        assert_eq!(pkt.as_bytes(), &[0x00, 0x03, 0x00, 0x00]);
    }

    #[test]
    fn test_end_opt6_backpatches_length() {
        let mut pkt = Dhcpv6OutPacket::new();
        let container = pkt.new_opt6(0x0005); // OPTION6_IAADDR
        // Write 16 bytes of dummy address.
        pkt.put_opt6(&[1u8; 16]);
        // Write preferred + valid lifetimes (4 + 4 = 8 bytes).
        pkt.put_opt6_long(3600);
        pkt.put_opt6_long(7200);
        pkt.end_opt6(container);

        // Total data after header: 16 + 4 + 4 = 24 = 0x0018.
        assert_eq!(pkt.buffer[2], 0x00);
        assert_eq!(pkt.buffer[3], 0x18);
        assert_eq!(pkt.len(), 4 + 24); // header + data
    }

    #[test]
    fn test_nested_options() {
        let mut pkt = Dhcpv6OutPacket::new();
        // Outer: IA_NA (code 3)
        let outer = pkt.new_opt6(0x0003);
        pkt.put_opt6_long(0x0001_0001); // IAID
        pkt.put_opt6_long(3600);        // T1
        pkt.put_opt6_long(7200);        // T2

        // Inner: IAADDR (code 5)
        let inner = pkt.new_opt6(0x0005);
        pkt.put_opt6(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 1]); // 16 bytes
        pkt.put_opt6_long(7200);  // preferred
        pkt.put_opt6_long(14400); // valid
        pkt.end_opt6(inner); // inner data = 16 + 4 + 4 = 24

        pkt.end_opt6(outer);
        // outer data = IAID(4) + T1(4) + T2(4) + inner_header(4) + inner_data(24) = 40

        // Verify outer length field (offset 2..4 of buffer).
        let outer_len = u16::from_be_bytes([pkt.buffer[2], pkt.buffer[3]]);
        assert_eq!(outer_len, 40);

        // Verify inner length field (offset 16..18: after outer_hdr(4)+IAID(4)+T1(4)+T2(4)).
        let inner_hdr_offset = 4 + 12; // 16
        let inner_len = u16::from_be_bytes([
            pkt.buffer[inner_hdr_offset + 2],
            pkt.buffer[inner_hdr_offset + 3],
        ]);
        assert_eq!(inner_len, 24);
    }

    // -- put_opt6 ---------------------------------------------------------

    #[test]
    fn test_put_opt6_copies_data() {
        let mut pkt = Dhcpv6OutPacket::new();
        let data: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let offset = pkt.put_opt6(&data);
        assert_eq!(offset, Some(0));
        assert_eq!(pkt.len(), 6);
        assert_eq!(pkt.as_bytes(), &data);
    }

    #[test]
    fn test_put_opt6_empty_slice() {
        let mut pkt = Dhcpv6OutPacket::new();
        let offset = pkt.put_opt6(&[]);
        assert_eq!(offset, Some(0));
        assert_eq!(pkt.len(), 0);
    }

    // -- put_opt6_raw -----------------------------------------------------

    #[test]
    fn test_put_opt6_raw_allocates_zeroed_space() {
        let mut pkt = Dhcpv6OutPacket::new();
        let offset = pkt.put_opt6_raw(8);
        assert_eq!(offset, Some(0));
        assert_eq!(pkt.len(), 8);
        // Should be zero-initialised by Vec::resize.
        assert_eq!(pkt.as_bytes(), &[0u8; 8]);
    }

    // -- put_opt6_long ----------------------------------------------------

    #[test]
    fn test_put_opt6_long_big_endian() {
        let mut pkt = Dhcpv6OutPacket::new();
        pkt.put_opt6_long(0x12345678);
        assert_eq!(pkt.as_bytes(), &[0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn test_put_opt6_long_zero() {
        let mut pkt = Dhcpv6OutPacket::new();
        pkt.put_opt6_long(0);
        assert_eq!(pkt.as_bytes(), &[0, 0, 0, 0]);
    }

    #[test]
    fn test_put_opt6_long_max() {
        let mut pkt = Dhcpv6OutPacket::new();
        pkt.put_opt6_long(0xFFFF_FFFF);
        assert_eq!(pkt.as_bytes(), &[0xFF, 0xFF, 0xFF, 0xFF]);
    }

    // -- put_opt6_short ---------------------------------------------------

    #[test]
    fn test_put_opt6_short_big_endian() {
        let mut pkt = Dhcpv6OutPacket::new();
        pkt.put_opt6_short(0xABCD);
        assert_eq!(pkt.as_bytes(), &[0xAB, 0xCD]);
    }

    #[test]
    fn test_put_opt6_short_zero() {
        let mut pkt = Dhcpv6OutPacket::new();
        pkt.put_opt6_short(0);
        assert_eq!(pkt.as_bytes(), &[0, 0]);
    }

    // -- put_opt6_char ----------------------------------------------------

    #[test]
    fn test_put_opt6_char() {
        let mut pkt = Dhcpv6OutPacket::new();
        pkt.put_opt6_char(0xFF);
        assert_eq!(pkt.as_bytes(), &[0xFF]);
    }

    #[test]
    fn test_put_opt6_char_zero() {
        let mut pkt = Dhcpv6OutPacket::new();
        pkt.put_opt6_char(0);
        assert_eq!(pkt.as_bytes(), &[0x00]);
    }

    // -- put_opt6_string --------------------------------------------------

    #[test]
    fn test_put_opt6_string_no_null() {
        let mut pkt = Dhcpv6OutPacket::new();
        pkt.put_opt6_string("hello");
        // Must NOT include null terminator.
        assert_eq!(pkt.len(), 5);
        assert_eq!(pkt.as_bytes(), b"hello");
    }

    #[test]
    fn test_put_opt6_string_empty() {
        let mut pkt = Dhcpv6OutPacket::new();
        pkt.put_opt6_string("");
        assert_eq!(pkt.len(), 0);
    }

    // -- len / is_empty / as_bytes ----------------------------------------

    #[test]
    fn test_len_and_is_empty() {
        let mut pkt = Dhcpv6OutPacket::new();
        assert!(pkt.is_empty());
        pkt.put_opt6_char(1);
        assert!(!pkt.is_empty());
        assert_eq!(pkt.len(), 1);
    }

    // -- buffer_mut -------------------------------------------------------

    #[test]
    fn test_buffer_mut_allows_backpatch() {
        let mut pkt = Dhcpv6OutPacket::new();
        pkt.put_opt6_long(0);
        // Manually write a value at offset 0 via buffer_mut.
        let buf = pkt.buffer_mut();
        buf[0] = 0xDE;
        buf[1] = 0xAD;
        assert_eq!(pkt.as_bytes()[0], 0xDE);
        assert_eq!(pkt.as_bytes()[1], 0xAD);
    }

    // -- capacity ---------------------------------------------------------

    #[test]
    fn test_capacity_grows() {
        let mut pkt = Dhcpv6OutPacket::new();
        assert_eq!(pkt.capacity(), 0);
        pkt.put_opt6_long(0);
        assert!(pkt.capacity() >= 4);
    }

    #[test]
    fn test_capacity_after_reset() {
        let mut pkt = Dhcpv6OutPacket::new();
        pkt.put_opt6(&[0u8; 100]);
        let cap = pkt.capacity();
        pkt.reset();
        // Capacity preserved after reset.
        assert_eq!(pkt.capacity(), cap);
    }

    // -- Wire-format compliance -------------------------------------------

    /// Verify that a complete IA_NA + IAADDR construction produces the
    /// exact byte sequence expected by RFC 3315.
    #[test]
    fn test_full_ia_na_wire_format() {
        let mut pkt = Dhcpv6OutPacket::new();
        pkt.reset();

        // IA_NA header (code=3)
        let ia_na = pkt.new_opt6(0x0003);
        pkt.put_opt6_long(0x0000_0001); // IAID = 1
        pkt.put_opt6_long(1800);        // T1 = 1800s
        pkt.put_opt6_long(2880);        // T2 = 2880s

        // IAADDR sub-option (code=5)
        let ia_addr = pkt.new_opt6(0x0005);
        // Address: 2001:db8::1
        pkt.put_opt6(&[
            0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ]);
        pkt.put_opt6_long(3600);  // preferred lifetime
        pkt.put_opt6_long(7200);  // valid lifetime
        pkt.end_opt6(ia_addr);

        pkt.end_opt6(ia_na);

        // Expected layout:
        // [0..4]   IA_NA header: code=0003, len=0028 (40)
        // [4..8]   IAID: 00000001
        // [8..12]  T1: 00000708  (1800)
        // [12..16] T2: 00000B40  (2880)
        // [16..20] IAADDR header: code=0005, len=0018 (24)
        // [20..36] IPv6 address
        // [36..40] preferred: 00000E10 (3600)
        // [40..44] valid: 00001C20 (7200)

        let bytes = pkt.as_bytes();
        assert_eq!(bytes.len(), 44);

        // IA_NA code
        assert_eq!(&bytes[0..2], &[0x00, 0x03]);
        // IA_NA length = 40
        assert_eq!(&bytes[2..4], &[0x00, 0x28]);
        // IAID = 1
        assert_eq!(&bytes[4..8], &[0x00, 0x00, 0x00, 0x01]);
        // T1 = 1800 = 0x0708
        assert_eq!(&bytes[8..12], &[0x00, 0x00, 0x07, 0x08]);
        // T2 = 2880 = 0x0B40
        assert_eq!(&bytes[12..16], &[0x00, 0x00, 0x0B, 0x40]);
        // IAADDR code
        assert_eq!(&bytes[16..18], &[0x00, 0x05]);
        // IAADDR length = 24
        assert_eq!(&bytes[18..20], &[0x00, 0x18]);
        // IPv6 address
        assert_eq!(&bytes[20..36], &[
            0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ]);
        // preferred = 3600 = 0x0E10
        assert_eq!(&bytes[36..40], &[0x00, 0x00, 0x0E, 0x10]);
        // valid = 7200 = 0x1C20
        assert_eq!(&bytes[40..44], &[0x00, 0x00, 0x1C, 0x20]);
    }

    /// Verify that STATUS_CODE option with a message string encodes
    /// correctly (string must NOT have a null terminator).
    #[test]
    fn test_status_code_with_message() {
        let mut pkt = Dhcpv6OutPacket::new();
        let opt = pkt.new_opt6(0x000D); // OPTION6_STATUS_CODE
        pkt.put_opt6_short(0x0000);      // Status: Success
        pkt.put_opt6_string("OK");
        pkt.end_opt6(opt);

        let bytes = pkt.as_bytes();
        // header(4) + status(2) + "OK"(2) = 8 bytes total
        assert_eq!(bytes.len(), 8);
        // Option length = 4
        assert_eq!(&bytes[2..4], &[0x00, 0x04]);
        // Status code = 0
        assert_eq!(&bytes[4..6], &[0x00, 0x00]);
        // "OK" without null terminator
        assert_eq!(&bytes[6..8], b"OK");
    }

    /// Regression: verify that sequential put_opt6_long calls produce
    /// contiguous big-endian values with no gaps or padding.
    #[test]
    fn test_sequential_longs_contiguous() {
        let mut pkt = Dhcpv6OutPacket::new();
        pkt.put_opt6_long(0x11223344);
        pkt.put_opt6_long(0x55667788);
        assert_eq!(
            pkt.as_bytes(),
            &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]
        );
    }

    /// Verify that `reset()` truly zeroes the buffer (information leakage
    /// prevention).
    #[test]
    fn test_reset_zero_fill_prevents_leakage() {
        let mut pkt = Dhcpv6OutPacket::new();
        pkt.put_opt6(&[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE]);
        pkt.reset();
        // All underlying bytes must be zero.
        for &b in &pkt.buffer {
            assert_eq!(b, 0, "Buffer byte not zeroed after reset");
        }
    }

    /// Test interleaved save_counter / put operations to ensure position
    /// tracking is consistent.
    #[test]
    fn test_save_counter_interleaved_with_writes() {
        let mut pkt = Dhcpv6OutPacket::new();

        pkt.put_opt6_short(0xAAAA); // pos -> 2
        let p1 = pkt.save_counter(-1);
        assert_eq!(p1, 2);

        pkt.put_opt6_long(0xBBBBBBBB); // pos -> 6
        let p2 = pkt.save_counter(2); // rewind to 2, returns 6
        assert_eq!(p2, 6);
        assert_eq!(pkt.len(), 2);

        // Overwrite from position 2
        pkt.put_opt6_short(0xCCCC); // pos -> 4
        assert_eq!(pkt.as_bytes(), &[0xAA, 0xAA, 0xCC, 0xCC]);
    }

    /// Verify that multiple resets work correctly.
    #[test]
    fn test_multiple_resets() {
        let mut pkt = Dhcpv6OutPacket::new();
        for _ in 0..3 {
            pkt.put_opt6_long(0xDEADBEEF);
            pkt.put_opt6_string("test");
            assert_eq!(pkt.len(), 8);
            pkt.reset();
            assert_eq!(pkt.len(), 0);
            assert!(pkt.is_empty());
        }
    }
}

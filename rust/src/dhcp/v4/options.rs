// dnsmasq is Copyright (c) 2000-2025 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! # DHCPv4 Option Encode/Decode
//!
//! Provides functions for finding, reading, writing, and encoding DHCPv4 options
//! within packet buffers per RFC 2132. Migrated from option handling code in
//! `src/rfc2131.c` (option_find, option_put, etc.) and shared option table from
//! `src/dhcp-common.c` (opttab\[\]).
//!
//! ## DHCPv4 Option Format (RFC 2132)
//! Options are encoded as Tag-Length-Value (TLV):
//! - Tag: 1-byte option code (0-255)
//! - Length: 1-byte length of value field (0-255)
//! - Value: Variable-length option data
//!
//! Special options:
//! - OPTION_PAD (0): Single byte, no length or value
//! - OPTION_END (255): Single byte, marks end of options
//!
//! ## Memory Safety Improvements
//! - C raw pointer arithmetic for option traversal → Rust slice bounds checking
//! - C manual buffer size tracking → Rust `Vec<u8>` with automatic capacity management
//! - C unchecked `option_ptr` macro → Rust safe slice indexing with `Option<T>` returns
//! - Buffer overflow prevention: all writes check capacity before appending
//!
//! ## C Source Mapping
//! | Rust Function | C Function/Macro | C Source | C Line |
//! |--------------|-----------------|----------|--------|
//! | `option_len()` | `option_len()` macro | rfc2131.c | 97 |
//! | `option_data()` | `option_ptr()` macro | rfc2131.c | 98 |
//! | `option_find()` | `option_find()` | rfc2131.c | 2732 |
//! | `option_find1()` | `option_find1()` | rfc2131.c | 2630 |
//! | `option_put()` | `option_put()` | rfc2131.c | 3231 |
//! | `option_put_string()` | `option_put_string()` | rfc2131.c | 3294 |
//! | `option_addr()` | `option_addr()` | rfc2131.c | 2787 |
//! | `option_uint()` | `option_uint()` | rfc2131.c | 2847 |
//! | `free_space()` | `free_space()` | rfc2131.c | 3120 |
//! | `clear_options()` | `clear_packet()` | rfc2131.c | 4186 |
//! | `in_list()` | `in_list()` | rfc2131.c | 3455 |
//! | `sanitise()` | `sanitise()` | rfc2131.c | 2304 |
//! | `dhcp_packet_size()` | `dhcp_packet_size()` | rfc2131.c | 3010 |

use std::net::Ipv4Addr;

#[allow(unused_imports)]
use crate::core::types::DnsmasqResult;

// ---------------------------------------------------------------------------
// DHCPv4 protocol constants (from dhcp-protocol.h)
// These are defined locally to avoid depending on sibling mod.rs which may not
// exist yet.  Once rust/src/dhcp/v4/mod.rs is created by the module-root agent,
// these can be replaced with `use super::*` re-exports.
// ---------------------------------------------------------------------------

/// Single-byte pad option — no length / value fields (RFC 2132 §3.1).
const OPTION_PAD: u8 = 0;

/// Single-byte end-of-options marker (RFC 2132 §3.2).
const OPTION_END: u8 = 255;

/// Option 52 — indicates that `sname` and/or `file` fields carry options
/// instead of their normal boot-server / boot-file content (RFC 2132 §9.3).
const OPTION_OVERLOAD: u8 = 52;

/// Option 82 — Relay Agent Information (RFC 3046).
/// Used in tests and will be consumed by sibling protocol/server modules.
#[allow(dead_code)]
const OPTION_AGENT_ID: u8 = 82;

/// Magic cookie bytes placed at the start of the options field
/// (RFC 2131 §3, value 0x63825363 in network byte order).
const DHCP_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];

/// Minimum DHCP packet size required by the Linux kernel (300 bytes).
/// Packets shorter than this are silently dropped by the kernel's UDP layer.
const MIN_PACKETSZ: usize = 300;

/// Offset of the `siaddr` (server IP address) field in a DHCP packet.
const SIADDR_OFFSET: usize = 20;

/// Offset of the `sname` (server host name) field in a DHCP packet.
const SNAME_OFFSET: usize = 44;

/// Size of the `sname` field (64 bytes).
const SNAME_SIZE: usize = 64;

/// Offset of the `file` (boot file name) field in a DHCP packet.
const FILE_OFFSET: usize = 108;

/// Size of the `file` field (128 bytes).
const FILE_SIZE: usize = 128;

/// Offset where the options field begins (contains cookie + TLV options).
const OPTIONS_OFFSET: usize = 236;

/// Size of the DHCP magic cookie (4 bytes).
const COOKIE_SIZE: usize = 4;

/// Offset where actual TLV option data begins (after header + cookie).
const OPTIONS_DATA_OFFSET: usize = OPTIONS_OFFSET + COOKIE_SIZE;

// ---------------------------------------------------------------------------
// Internal helper: locate the OPTION_END marker in the options area
// ---------------------------------------------------------------------------

/// Walk the TLV option chain starting at `OPTIONS_DATA_OFFSET` and return the
/// byte offset of the first `OPTION_END` marker.  Returns `None` when the
/// packet is too short or malformed (option data extends past buffer end).
///
/// Mirrors C helper `dhcp_skip_opts()` (rfc2131.c line 2901).
fn find_option_end(buf: &[u8]) -> Option<usize> {
    if buf.len() < OPTIONS_DATA_OFFSET {
        return None;
    }
    let mut pos = OPTIONS_DATA_OFFSET;
    while pos < buf.len() {
        let tag = buf[pos];
        if tag == OPTION_END {
            return Some(pos);
        }
        if tag == OPTION_PAD {
            pos += 1;
            continue;
        }
        // Regular TLV option — need at least the length byte
        if pos + 1 >= buf.len() {
            return None; // malformed: missing length byte
        }
        let opt_len = buf[pos + 1] as usize;
        let next = pos + 2 + opt_len;
        if next > buf.len() {
            return None; // malformed: data extends past buffer
        }
        pos = next;
    }
    None // no OPTION_END found
}

/// Walk a raw TLV byte slice (not a full DHCP packet) and return the offset of
/// the first `OPTION_END` marker, relative to the start of `data`.
///
/// Used internally when searching overloaded `sname` / `file` fields and when
/// computing packet sizes.
fn find_option_end_raw(data: &[u8]) -> Option<usize> {
    let mut pos: usize = 0;
    while pos < data.len() {
        let tag = data[pos];
        if tag == OPTION_END {
            return Some(pos);
        }
        if tag == OPTION_PAD {
            pos += 1;
            continue;
        }
        if pos + 1 >= data.len() {
            return None;
        }
        let opt_len = data[pos + 1] as usize;
        let next = pos + 2 + opt_len;
        if next > data.len() {
            return None;
        }
        pos = next;
    }
    None
}

// =========================================================================
// Option reading / parsing functions
// =========================================================================

/// Return the *length* byte of a TLV-encoded DHCP option.
///
/// `opt` must point to a complete TLV triple (tag, length, data…).  The length
/// is stored in `opt[1]`.
///
/// # Panics
/// Panics if `opt.len() < 2`.  Callers that obtain their slice from
/// [`option_find`] or [`option_find1`] are guaranteed to have a valid slice.
///
/// Replaces C macro `option_len(opt)` — `((int)(((unsigned char *)(opt))[1]))`
/// (rfc2131.c line 97).
pub fn option_len(opt: &[u8]) -> usize {
    opt[1] as usize
}

/// Return a sub-slice over the *value* bytes of a TLV-encoded DHCP option.
///
/// Given a slice starting at the tag byte, this returns `&opt[2 .. 2+len]`
/// where `len = opt[1]`.  If `opt` is too short to contain the full value,
/// the returned slice is truncated to whatever bytes are available.
///
/// Replaces C macro `option_ptr(opt, i)` (rfc2131.c line 98).
pub fn option_data(opt: &[u8]) -> &[u8] {
    if opt.len() < 2 {
        return &[];
    }
    let len = opt[1] as usize;
    let end = std::cmp::min(2 + len, opt.len());
    &opt[2..end]
}

/// Search a raw TLV option buffer for an option with the given tag.
///
/// Iterates the Tag-Length-Value entries in `data` (which is **not** a full
/// DHCP packet — just a contiguous block of TLV options).  Skips `OPTION_PAD`
/// bytes, stops at `OPTION_END`.  Returns the slice starting at the matching
/// option's tag byte (i.e. `&data[pos .. pos + 2 + opt_len]`), or `None` if
/// the option is not found or its value is shorter than `min_size`.
///
/// Replaces C `option_find1(p, end, opt, minsize)` (rfc2131.c line 2630).
pub fn option_find1(data: &[u8], opt: u8, min_size: usize) -> Option<&[u8]> {
    let mut pos: usize = 0;
    while pos < data.len() {
        let tag = data[pos];

        // OPTION_END — matches only if the caller is looking for OPTION_END itself
        if tag == OPTION_END {
            if opt == OPTION_END {
                return Some(&data[pos..pos + 1]);
            }
            return None;
        }

        // OPTION_PAD — single byte, no length / value
        if tag == OPTION_PAD {
            pos += 1;
            continue;
        }

        // Regular TLV entry — must have at least the length byte
        if pos + 1 >= data.len() {
            return None; // malformed
        }
        let opt_len = data[pos + 1] as usize;
        let entry_end = pos + 2 + opt_len;
        if entry_end > data.len() {
            return None; // malformed — data extends past buffer
        }

        if tag == opt && opt_len >= min_size {
            return Some(&data[pos..entry_end]);
        }
        pos = entry_end;
    }
    None
}

/// Search a full DHCPv4 packet for an option with the given tag.
///
/// First searches the main options area (bytes after the DHCP magic cookie at
/// offset 240).  If the option is not found there, checks for `OPTION_OVERLOAD`
/// (52) and, if present, searches the `file` field (128 bytes at offset 108)
/// and/or the `sname` field (64 bytes at offset 44) according to the overload
/// value:
/// - bit 0 set → `file` field contains options
/// - bit 1 set → `sname` field contains options
///
/// Returns the TLV slice (tag + length + value) or `None`.
///
/// Replaces C `option_find(mess, size, opt_type, minsize)` (rfc2131.c line 2732).
pub fn option_find(packet_data: &[u8], opt_type: u8, min_size: usize) -> Option<&[u8]> {
    // Packet must be large enough to hold the fixed header + cookie
    if packet_data.len() < OPTIONS_DATA_OFFSET {
        return None;
    }

    // Validate magic cookie
    if packet_data[OPTIONS_OFFSET..OPTIONS_DATA_OFFSET] != DHCP_COOKIE {
        return None;
    }

    // Search the main options area (offset 240 .. end of packet)
    let main_options = &packet_data[OPTIONS_DATA_OFFSET..];
    if let Some(found) = option_find1(main_options, opt_type, min_size) {
        // Translate the sub-slice back to a slice of packet_data so the caller
        // gets a reference with the same lifetime as packet_data.
        let offset_in_main = found.as_ptr() as usize - main_options.as_ptr() as usize;
        let abs_start = OPTIONS_DATA_OFFSET + offset_in_main;
        return Some(&packet_data[abs_start..abs_start + found.len()]);
    }

    // Look for OPTION_OVERLOAD in the main options area
    let overload_val = match option_find1(main_options, OPTION_OVERLOAD, 1) {
        Some(ov) => {
            // ov[0]=tag, ov[1]=len, ov[2]=value
            if ov.len() >= 3 {
                ov[2]
            } else {
                return None;
            }
        }
        None => return None,
    };

    // bit 0 → file field (128 bytes at offset 108) contains options
    if overload_val & 1 != 0 {
        let file_end = FILE_OFFSET + FILE_SIZE;
        if packet_data.len() >= file_end {
            let file_data = &packet_data[FILE_OFFSET..file_end];
            if let Some(found) = option_find1(file_data, opt_type, min_size) {
                let offset_in_file = found.as_ptr() as usize - file_data.as_ptr() as usize;
                let abs_start = FILE_OFFSET + offset_in_file;
                return Some(&packet_data[abs_start..abs_start + found.len()]);
            }
        }
    }

    // bit 1 → sname field (64 bytes at offset 44) contains options
    if overload_val & 2 != 0 {
        let sname_end = SNAME_OFFSET + SNAME_SIZE;
        if packet_data.len() >= sname_end {
            let sname_data = &packet_data[SNAME_OFFSET..sname_end];
            if let Some(found) = option_find1(sname_data, opt_type, min_size) {
                let offset_in_sname = found.as_ptr() as usize - sname_data.as_ptr() as usize;
                let abs_start = SNAME_OFFSET + offset_in_sname;
                return Some(&packet_data[abs_start..abs_start + found.len()]);
            }
        }
    }

    None
}

/// Extract an IPv4 address from the value bytes of a TLV option.
///
/// Reads 4 bytes starting at `opt[2]` (the first value byte) and constructs an
/// [`Ipv4Addr`].  Returns `None` if the option value is shorter than 4 bytes.
///
/// Replaces C `option_addr(opt)` (rfc2131.c line 2787):
/// ```c
/// memcpy(&ret, option_ptr(opt, 0), INADDRSZ);
/// ```
pub fn option_addr(opt: &[u8]) -> Option<Ipv4Addr> {
    let data = option_data(opt);
    if data.len() < 4 {
        return None;
    }
    Some(Ipv4Addr::new(data[0], data[1], data[2], data[3]))
}

/// Extract an unsigned integer from the value bytes of a TLV option.
///
/// Reads `size` bytes (1, 2, or 4) starting at `opt[2 + offset]` and assembles
/// them in network (big-endian) byte order.  Returns `None` if the option value
/// is too short for the requested read.
///
/// Replaces C `option_uint(opt, offset, size)` (rfc2131.c line 2847):
/// ```c
/// for (i = 0; i < size; i++)
///     ret = (ret << 8) | *p++;
/// ```
pub fn option_uint(opt: &[u8], offset: usize, size: usize) -> Option<u32> {
    let data = option_data(opt);
    if offset + size > data.len() {
        return None;
    }
    let mut val: u32 = 0;
    for i in 0..size {
        val = (val << 8) | (data[offset + i] as u32);
    }
    Some(val)
}

/// Sanitise a DHCP option's string value for safe display / logging.
///
/// Iterates the value bytes of the TLV option and replaces every non-printable
/// ASCII byte (outside 0x20..=0x7E) with `'.'`.  Trailing null bytes and
/// whitespace are trimmed.  Returns `None` if the resulting string is empty.
///
/// Replaces C `sanitise(opt, buf)` (rfc2131.c line 2304).
pub fn sanitise(opt: &[u8]) -> Option<String> {
    let data = option_data(opt);
    if data.is_empty() {
        return None;
    }

    let sanitised: String = data
        .iter()
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                b as char
            } else {
                '.'
            }
        })
        .collect();

    // Trim trailing dots (from null bytes) and whitespace
    let trimmed =
        sanitised.trim_end_matches(|c: char| c == '.' || c == '\0' || c.is_ascii_whitespace());
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Check whether a given option code appears in a parameter-request list.
///
/// Performs a linear search through `list` for a byte equal to `opt`.  The list
/// is terminated by `OPTION_END` (255) — any bytes at or past that sentinel are
/// ignored.  If `list` is empty the function returns `true`, matching the C
/// behaviour of "if no requested options, send everything, not nothing"
/// (rfc2131.c line 3460).
///
/// Replaces C `in_list(list, opt)` (rfc2131.c line 3455).
pub fn in_list(list: &[u8], opt: u8) -> bool {
    // C: if (!list) return 1;  — empty list means "send everything"
    if list.is_empty() {
        return true;
    }
    for &byte in list {
        if byte == OPTION_END {
            break;
        }
        if byte == opt {
            return true;
        }
    }
    false
}

// =========================================================================
// Option writing functions
// =========================================================================

/// Find (or create) space for a new option in the packet buffer and write the
/// option tag and length bytes.  Returns the byte offset within `buf` where the
/// caller should write the option's value data.
///
/// The function locates the `OPTION_END` marker in the options area, replaces
/// it with the new option header (tag + length), reserves `len` zero-filled
/// value bytes, and appends a fresh `OPTION_END`.  Because `buf` is a
/// [`Vec<u8>`] that grows automatically, there is no need for the complex
/// `sname`/`file` overload fallback present in the C version — the buffer
/// simply expands.
///
/// Returns `None` when the options area is malformed (no `OPTION_END` found).
///
/// Replaces C `free_space(mess, end, opt, len)` (rfc2131.c line 3120).
pub fn free_space(buf: &mut Vec<u8>, opt: u8, len: usize) -> Option<usize> {
    let end_pos = find_option_end(buf)?;

    // We will overwrite OPTION_END at end_pos with the new option, then
    // re-append OPTION_END after the value bytes.
    //
    // Layout at end_pos after the write:
    //   [opt]  [len]  [value × len]  [OPTION_END]
    //
    // Total additional bytes needed beyond end_pos: 2 + len + 1 = len + 3
    // But we already have the OPTION_END byte at end_pos, so we need
    // (len + 3 - 1) = len + 2 extra bytes.

    let new_total = end_pos + 2 + len + 1; // tag + length + value + END
    if buf.len() < new_total {
        buf.resize(new_total, 0);
    }

    // Write option tag and length
    buf[end_pos] = opt;
    buf[end_pos + 1] = len as u8;

    // Zero the value area (resize already zeroes new bytes, but be explicit
    // for bytes that might have been within the old buffer length)
    for i in 0..len {
        buf[end_pos + 2 + i] = 0;
    }

    // Write new OPTION_END
    buf[end_pos + 2 + len] = OPTION_END;

    // Truncate to the new logical end (tag + length + value + END)
    buf.truncate(new_total);

    Some(end_pos + 2) // offset of the value data area
}

/// Write a numeric DHCP option (tag + length + big-endian value).
///
/// `len` specifies the number of value bytes (typically 1, 2, or 4).  The value
/// `val` is encoded in network (big-endian) byte order.
///
/// Replaces C `option_put(mess, end, opt, len, val)` (rfc2131.c line 3231):
/// ```c
/// for (i = 0; i < len; i++)
///     *(p++) = val >> (8 * (len - (i + 1)));
/// ```
pub fn option_put(buf: &mut Vec<u8>, opt: u8, len: usize, val: u32) {
    if let Some(offset) = free_space(buf, opt, len) {
        for i in 0..len {
            let shift = 8 * (len - 1 - i);
            buf[offset + i] = (val >> shift) as u8;
        }
    }
}

/// Write a string DHCP option (tag + length + UTF-8 bytes + optional NUL).
///
/// If `null_term` is `true` **and** the string is shorter than 255 bytes, a
/// trailing NUL byte is appended and counted in the option length.
///
/// Replaces C `option_put_string(mess, end, opt, string, null_term)`
/// (rfc2131.c line 3294).
pub fn option_put_string(buf: &mut Vec<u8>, opt: u8, string: &str, null_term: bool) {
    let bytes = string.as_bytes();
    let need_null = null_term && bytes.len() < 255;
    let total_len = if need_null {
        bytes.len() + 1
    } else {
        bytes.len()
    };

    if let Some(offset) = free_space(buf, opt, total_len) {
        buf[offset..offset + bytes.len()].copy_from_slice(bytes);
        if need_null {
            buf[offset + bytes.len()] = 0;
        }
    }
}

/// Clear the option area and selected header fields of a DHCP packet buffer.
///
/// Zeroes the `sname` field (64 bytes at offset 44), the `file` field
/// (128 bytes at offset 108), the `siaddr` field (4 bytes at offset 20), and
/// the entire options area after the magic cookie.  The options area is then
/// truncated to contain only `OPTION_END`.
///
/// Replaces C `clear_packet(mess, end)` (rfc2131.c line 4186):
/// ```c
/// memset(mess->sname, 0, sizeof(mess->sname));
/// memset(mess->file,  0, sizeof(mess->file));
/// memset(&mess->options[0] + sizeof(u32), 0, ...);
/// mess->siaddr.s_addr = 0;
/// ```
pub fn clear_options(buf: &mut Vec<u8>) {
    if buf.len() < OPTIONS_DATA_OFFSET + 1 {
        return; // buffer too short to contain a valid DHCP packet
    }

    // Zero siaddr field (4 bytes at offset 20)
    let siaddr_end = SIADDR_OFFSET + 4;
    if buf.len() >= siaddr_end {
        for b in &mut buf[SIADDR_OFFSET..siaddr_end] {
            *b = 0;
        }
    }

    // Zero sname field (64 bytes at offset 44)
    let sname_end = SNAME_OFFSET + SNAME_SIZE;
    if buf.len() >= sname_end {
        for b in &mut buf[SNAME_OFFSET..sname_end] {
            *b = 0;
        }
    }

    // Zero file field (128 bytes at offset 108)
    let file_end = FILE_OFFSET + FILE_SIZE;
    if buf.len() >= file_end {
        for b in &mut buf[FILE_OFFSET..file_end] {
            *b = 0;
        }
    }

    // Truncate options area to just OPTION_END after the cookie
    buf.truncate(OPTIONS_DATA_OFFSET + 1);
    buf[OPTIONS_DATA_OFFSET] = OPTION_END;
}

// =========================================================================
// Packet size calculation
// =========================================================================

/// Calculate the final DHCP packet size for transmission.
///
/// Walks the options area to find the last byte, accounts for a relay-agent
/// information option (82) if `agent_id` is provided, and enforces the minimum
/// packet size of [`MIN_PACKETSZ`] (300 bytes) required by the Linux kernel.
///
/// The returned size is the number of bytes from the start of the packet up to
/// and including the final `OPTION_END` marker, padded up to `MIN_PACKETSZ` if
/// necessary.
///
/// **Note:** Unlike the C implementation (`dhcp_packet_size` in rfc2131.c line
/// 3010) which mutates the packet in-place, this Rust version is a pure
/// calculation over an immutable slice.  Appending the relay-agent option and
/// writing final `OPTION_END` markers is the responsibility of the caller.
///
/// Replaces C `dhcp_packet_size(mess, agent_id, real_end)` (rfc2131.c line 3010).
pub fn dhcp_packet_size(packet: &[u8], agent_id: Option<&[u8]>) -> usize {
    if packet.len() < OPTIONS_DATA_OFFSET {
        // Packet is too short to be valid; return minimum size
        return MIN_PACKETSZ;
    }

    // Find the end of the options area
    let options_area = &packet[OPTIONS_DATA_OFFSET..];
    let option_end_offset = match find_option_end_raw(options_area) {
        Some(off) => OPTIONS_DATA_OFFSET + off,
        None => {
            // No OPTION_END found — treat entire buffer as the packet
            return std::cmp::max(packet.len(), MIN_PACKETSZ);
        }
    };

    // Base size: everything up to and including OPTION_END
    let mut size = option_end_offset + 1;

    // If a relay-agent information option is provided, account for its size.
    // The agent_id slice represents the complete TLV of option 82 (tag + len + value).
    if let Some(aid) = agent_id {
        size += aid.len();
    }

    // Enforce minimum packet size for Linux kernel compatibility
    std::cmp::max(size, MIN_PACKETSZ)
}

// =========================================================================
// Unit tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid DHCP packet buffer with just a header, cookie,
    /// and OPTION_END.  All header fields are zeroed except the magic cookie.
    fn make_minimal_packet() -> Vec<u8> {
        let mut buf = vec![0u8; OPTIONS_DATA_OFFSET + 1];
        // Write DHCP magic cookie at offset 236
        buf[OPTIONS_OFFSET] = 0x63;
        buf[OPTIONS_OFFSET + 1] = 0x82;
        buf[OPTIONS_OFFSET + 2] = 0x53;
        buf[OPTIONS_OFFSET + 3] = 0x63;
        // OPTION_END right after cookie
        buf[OPTIONS_DATA_OFFSET] = OPTION_END;
        buf
    }

    /// Build a DHCP packet with a few options for testing.
    fn make_packet_with_options() -> Vec<u8> {
        let mut buf = make_minimal_packet();

        // Remove OPTION_END, add some options manually, then re-add END
        let end = buf.len() - 1;
        // Option 53 (message type), length 1, value 1 (DHCPDISCOVER)
        buf[end] = 53;
        buf.push(1); // length
        buf.push(1); // value: DHCPDISCOVER
                     // Option 50 (requested IP), length 4, value 192.168.1.100
        buf.push(50);
        buf.push(4);
        buf.push(192);
        buf.push(168);
        buf.push(1);
        buf.push(100);
        // Option 12 (hostname), length 4, value "test"
        buf.push(12);
        buf.push(4);
        buf.push(b't');
        buf.push(b'e');
        buf.push(b's');
        buf.push(b't');
        // OPTION_END
        buf.push(OPTION_END);
        buf
    }

    // -- option_len / option_data tests --

    #[test]
    fn test_option_len_basic() {
        // TLV: tag=53, len=1, value=1
        let opt = [53u8, 1, 1];
        assert_eq!(option_len(&opt), 1);
    }

    #[test]
    fn test_option_len_four_bytes() {
        // TLV: tag=50, len=4, value=192.168.1.1
        let opt = [50u8, 4, 192, 168, 1, 1];
        assert_eq!(option_len(&opt), 4);
    }

    #[test]
    fn test_option_data_basic() {
        let opt = [53u8, 1, 7];
        assert_eq!(option_data(&opt), &[7]);
    }

    #[test]
    fn test_option_data_multi() {
        let opt = [50u8, 4, 10, 0, 0, 1];
        assert_eq!(option_data(&opt), &[10, 0, 0, 1]);
    }

    #[test]
    fn test_option_data_empty_slice() {
        let opt: [u8; 0] = [];
        assert_eq!(option_data(&opt), &[] as &[u8]);
    }

    #[test]
    fn test_option_data_truncated() {
        // Length says 4 but only 2 value bytes available
        let opt = [50u8, 4, 10, 20];
        assert_eq!(option_data(&opt), &[10, 20]);
    }

    // -- option_find1 tests --

    #[test]
    fn test_option_find1_found() {
        // Raw option buffer: opt53(len=1,val=1), opt50(len=4,val=…), END
        let data = [
            53, 1, 1, // option 53, len 1, val 1
            50, 4, 192, 168, 1, 100, // option 50, len 4
            OPTION_END,
        ];
        let result = option_find1(&data, 50, 4);
        assert!(result.is_some());
        let found = result.unwrap();
        assert_eq!(found[0], 50); // tag
        assert_eq!(found[1], 4); // length
        assert_eq!(&found[2..6], &[192, 168, 1, 100]);
    }

    #[test]
    fn test_option_find1_not_found() {
        let data = [53, 1, 1, OPTION_END];
        assert!(option_find1(&data, 50, 0).is_none());
    }

    #[test]
    fn test_option_find1_min_size_filter() {
        // Option 50 has length 2, but we ask for min_size 4
        let data = [50, 2, 10, 20, OPTION_END];
        assert!(option_find1(&data, 50, 4).is_none());
        assert!(option_find1(&data, 50, 2).is_some());
    }

    #[test]
    fn test_option_find1_skips_pad() {
        let data = [OPTION_PAD, OPTION_PAD, 53, 1, 3, OPTION_END];
        let result = option_find1(&data, 53, 1);
        assert!(result.is_some());
        assert_eq!(result.unwrap()[2], 3);
    }

    #[test]
    fn test_option_find1_find_end() {
        let data = [53, 1, 1, OPTION_END];
        let result = option_find1(&data, OPTION_END, 0);
        assert!(result.is_some());
        assert_eq!(result.unwrap().len(), 1);
        assert_eq!(result.unwrap()[0], OPTION_END);
    }

    #[test]
    fn test_option_find1_malformed_no_length() {
        // Tag byte but no length byte
        let data = [53u8];
        assert!(option_find1(&data, 53, 0).is_none());
    }

    // -- option_find (full packet) tests --

    #[test]
    fn test_option_find_in_packet() {
        let pkt = make_packet_with_options();
        // Find option 50 (requested IP)
        let result = option_find(&pkt, 50, 4);
        assert!(result.is_some());
        let found = result.unwrap();
        assert_eq!(found[0], 50);
        assert_eq!(option_data(found), &[192, 168, 1, 100]);
    }

    #[test]
    fn test_option_find_not_present() {
        let pkt = make_packet_with_options();
        assert!(option_find(&pkt, 99, 0).is_none());
    }

    #[test]
    fn test_option_find_bad_cookie() {
        let mut pkt = make_packet_with_options();
        // Corrupt cookie
        pkt[OPTIONS_OFFSET] = 0x00;
        assert!(option_find(&pkt, 53, 1).is_none());
    }

    #[test]
    fn test_option_find_too_short() {
        let pkt = vec![0u8; 100]; // way too short for DHCP
        assert!(option_find(&pkt, 53, 1).is_none());
    }

    #[test]
    fn test_option_find_with_overload() {
        let mut pkt = make_minimal_packet();

        // Add OPTION_OVERLOAD = 1 (file field contains options) in main options
        let end = pkt.len() - 1;
        pkt[end] = OPTION_OVERLOAD;
        pkt.push(1); // length
        pkt.push(1); // value: bit 0 set → file field has options
        pkt.push(OPTION_END);

        // Put option 53 in the file field (offset 108..236)
        pkt[FILE_OFFSET] = 53;
        pkt[FILE_OFFSET + 1] = 1;
        pkt[FILE_OFFSET + 2] = 5; // DHCPACK
        pkt[FILE_OFFSET + 3] = OPTION_END;

        let result = option_find(&pkt, 53, 1);
        assert!(result.is_some());
        let found = result.unwrap();
        assert_eq!(found[0], 53);
        assert_eq!(found[2], 5);
    }

    // -- option_addr tests --

    #[test]
    fn test_option_addr_valid() {
        let opt = [50u8, 4, 192, 168, 1, 100];
        assert_eq!(option_addr(&opt), Some(Ipv4Addr::new(192, 168, 1, 100)));
    }

    #[test]
    fn test_option_addr_too_short() {
        let opt = [50u8, 2, 10, 20];
        assert_eq!(option_addr(&opt), None);
    }

    #[test]
    fn test_option_addr_loopback() {
        let opt = [50u8, 4, 127, 0, 0, 1];
        assert_eq!(option_addr(&opt), Some(Ipv4Addr::LOCALHOST));
    }

    // -- option_uint tests --

    #[test]
    fn test_option_uint_one_byte() {
        let opt = [53u8, 1, 7];
        assert_eq!(option_uint(&opt, 0, 1), Some(7));
    }

    #[test]
    fn test_option_uint_two_bytes() {
        // 0x01 0x00 = 256 in big-endian
        let opt = [57u8, 2, 0x01, 0x00];
        assert_eq!(option_uint(&opt, 0, 2), Some(256));
    }

    #[test]
    fn test_option_uint_four_bytes() {
        // 0x0A 0x00 0x00 0x01 = 167772161 (10.0.0.1 as u32)
        let opt = [50u8, 4, 0x0A, 0x00, 0x00, 0x01];
        assert_eq!(option_uint(&opt, 0, 4), Some(0x0A000001));
    }

    #[test]
    fn test_option_uint_with_offset() {
        // Option with 6 bytes of data; read 2 bytes starting at offset 4
        let opt = [99u8, 6, 0, 0, 0, 0, 0xAB, 0xCD];
        assert_eq!(option_uint(&opt, 4, 2), Some(0xABCD));
    }

    #[test]
    fn test_option_uint_out_of_bounds() {
        let opt = [53u8, 1, 7];
        assert_eq!(option_uint(&opt, 0, 2), None); // only 1 byte available
        assert_eq!(option_uint(&opt, 2, 1), None); // offset past data
    }

    // -- sanitise tests --

    #[test]
    fn test_sanitise_ascii() {
        let opt = [12u8, 4, b't', b'e', b's', b't'];
        assert_eq!(sanitise(&opt), Some("test".to_string()));
    }

    #[test]
    fn test_sanitise_with_control_chars() {
        let opt = [12u8, 5, b'h', b'i', 0x01, 0x02, b'!'];
        assert_eq!(sanitise(&opt), Some("hi..!".to_string()));
    }

    #[test]
    fn test_sanitise_trailing_nulls() {
        let opt = [12u8, 6, b'a', b'b', 0, 0, 0, 0];
        assert_eq!(sanitise(&opt), Some("ab".to_string()));
    }

    #[test]
    fn test_sanitise_all_nulls() {
        let opt = [12u8, 3, 0, 0, 0];
        assert_eq!(sanitise(&opt), None);
    }

    #[test]
    fn test_sanitise_empty_data() {
        let opt = [12u8, 0];
        assert_eq!(sanitise(&opt), None);
    }

    // -- in_list tests --

    #[test]
    fn test_in_list_present() {
        let list = [1u8, 3, 6, 12, 15, OPTION_END];
        assert!(in_list(&list, 6));
    }

    #[test]
    fn test_in_list_absent() {
        let list = [1u8, 3, 6, 12, 15, OPTION_END];
        assert!(!in_list(&list, 50));
    }

    #[test]
    fn test_in_list_empty() {
        let list: [u8; 0] = [];
        assert!(in_list(&list, 50)); // empty → send everything
    }

    #[test]
    fn test_in_list_only_end() {
        let list = [OPTION_END];
        assert!(!in_list(&list, 50));
    }

    // -- free_space / option_put / option_put_string tests --

    #[test]
    fn test_free_space_basic() {
        let mut buf = make_minimal_packet();
        let result = free_space(&mut buf, 53, 1);
        assert!(result.is_some());
        let offset = result.unwrap();
        assert_eq!(buf[offset - 2], 53); // tag
        assert_eq!(buf[offset - 1], 1); // length
                                        // Last byte should be OPTION_END
        assert_eq!(*buf.last().unwrap(), OPTION_END);
    }

    #[test]
    fn test_option_put_one_byte() {
        let mut buf = make_minimal_packet();
        option_put(&mut buf, 53, 1, 5); // DHCPACK = 5
                                        // Verify TLV at OPTIONS_DATA_OFFSET
        assert_eq!(buf[OPTIONS_DATA_OFFSET], 53);
        assert_eq!(buf[OPTIONS_DATA_OFFSET + 1], 1);
        assert_eq!(buf[OPTIONS_DATA_OFFSET + 2], 5);
        assert_eq!(buf[OPTIONS_DATA_OFFSET + 3], OPTION_END);
    }

    #[test]
    fn test_option_put_four_bytes() {
        let mut buf = make_minimal_packet();
        option_put(&mut buf, 51, 4, 86400); // lease time = 86400s
        assert_eq!(buf[OPTIONS_DATA_OFFSET], 51);
        assert_eq!(buf[OPTIONS_DATA_OFFSET + 1], 4);
        // 86400 = 0x00015180 in big-endian
        assert_eq!(buf[OPTIONS_DATA_OFFSET + 2], 0x00);
        assert_eq!(buf[OPTIONS_DATA_OFFSET + 3], 0x01);
        assert_eq!(buf[OPTIONS_DATA_OFFSET + 4], 0x51);
        assert_eq!(buf[OPTIONS_DATA_OFFSET + 5], 0x80);
        assert_eq!(buf[OPTIONS_DATA_OFFSET + 6], OPTION_END);
    }

    #[test]
    fn test_option_put_two_bytes() {
        let mut buf = make_minimal_packet();
        option_put(&mut buf, 57, 2, 1500); // max message size
        assert_eq!(buf[OPTIONS_DATA_OFFSET], 57);
        assert_eq!(buf[OPTIONS_DATA_OFFSET + 1], 2);
        // 1500 = 0x05DC
        assert_eq!(buf[OPTIONS_DATA_OFFSET + 2], 0x05);
        assert_eq!(buf[OPTIONS_DATA_OFFSET + 3], 0xDC);
        assert_eq!(buf[OPTIONS_DATA_OFFSET + 4], OPTION_END);
    }

    #[test]
    fn test_option_put_multiple() {
        let mut buf = make_minimal_packet();
        option_put(&mut buf, 53, 1, 2); // DHCPOFFER
        option_put(&mut buf, 51, 4, 3600); // lease time
                                           // Should have: [53,1,2] [51,4,0x00,0x00,0x0E,0x10] [END]
        assert_eq!(buf[OPTIONS_DATA_OFFSET], 53);
        assert_eq!(buf[OPTIONS_DATA_OFFSET + 3], 51);
        assert_eq!(*buf.last().unwrap(), OPTION_END);
    }

    #[test]
    fn test_option_put_string_no_null() {
        let mut buf = make_minimal_packet();
        option_put_string(&mut buf, 12, "myhost", false);
        assert_eq!(buf[OPTIONS_DATA_OFFSET], 12);
        assert_eq!(buf[OPTIONS_DATA_OFFSET + 1], 6); // "myhost".len()
        assert_eq!(
            &buf[OPTIONS_DATA_OFFSET + 2..OPTIONS_DATA_OFFSET + 8],
            b"myhost"
        );
        assert_eq!(buf[OPTIONS_DATA_OFFSET + 8], OPTION_END);
    }

    #[test]
    fn test_option_put_string_with_null() {
        let mut buf = make_minimal_packet();
        option_put_string(&mut buf, 12, "host", true);
        assert_eq!(buf[OPTIONS_DATA_OFFSET], 12);
        assert_eq!(buf[OPTIONS_DATA_OFFSET + 1], 5); // "host".len() + 1 NUL
        assert_eq!(
            &buf[OPTIONS_DATA_OFFSET + 2..OPTIONS_DATA_OFFSET + 6],
            b"host"
        );
        assert_eq!(buf[OPTIONS_DATA_OFFSET + 6], 0); // NUL terminator
        assert_eq!(buf[OPTIONS_DATA_OFFSET + 7], OPTION_END);
    }

    // -- clear_options tests --

    #[test]
    fn test_clear_options_basic() {
        let mut buf = make_packet_with_options();
        // Confirm options exist before clearing
        assert!(buf.len() > OPTIONS_DATA_OFFSET + 1);
        clear_options(&mut buf);
        // After clearing: buffer should be header + cookie + OPTION_END
        assert_eq!(buf.len(), OPTIONS_DATA_OFFSET + 1);
        assert_eq!(buf[OPTIONS_DATA_OFFSET], OPTION_END);
        // siaddr should be zeroed
        assert_eq!(&buf[SIADDR_OFFSET..SIADDR_OFFSET + 4], &[0, 0, 0, 0]);
        // sname should be zeroed
        assert!(buf[SNAME_OFFSET..SNAME_OFFSET + SNAME_SIZE]
            .iter()
            .all(|&b| b == 0));
        // file should be zeroed
        assert!(buf[FILE_OFFSET..FILE_OFFSET + FILE_SIZE]
            .iter()
            .all(|&b| b == 0));
    }

    #[test]
    fn test_clear_options_too_short() {
        let mut buf = vec![0u8; 50]; // way too short
        clear_options(&mut buf); // should not panic
        assert_eq!(buf.len(), 50); // unchanged
    }

    // -- dhcp_packet_size tests --

    #[test]
    fn test_dhcp_packet_size_minimum() {
        let pkt = make_minimal_packet(); // 241 bytes < MIN_PACKETSZ
        let size = dhcp_packet_size(&pkt, None);
        assert_eq!(size, MIN_PACKETSZ); // padded to 300
    }

    #[test]
    fn test_dhcp_packet_size_with_options() {
        let pkt = make_packet_with_options();
        let size = dhcp_packet_size(&pkt, None);
        // Packet has: 240 header + opt53(3) + opt50(6) + opt12(6) + END(1) = 256
        // 256 < 300, so should be padded to 300
        assert_eq!(size, MIN_PACKETSZ);
    }

    #[test]
    fn test_dhcp_packet_size_with_agent_id() {
        let pkt = make_minimal_packet(); // 241 bytes
                                         // Simulate relay agent TLV: tag(1) + len(1) + value(10) = 12 bytes
        let agent_id = [OPTION_AGENT_ID, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let size = dhcp_packet_size(&pkt, Some(&agent_id));
        // 241 + 12 = 253 < 300
        assert_eq!(size, MIN_PACKETSZ);
    }

    #[test]
    fn test_dhcp_packet_size_large_packet() {
        // Build a packet larger than MIN_PACKETSZ
        let mut pkt = make_minimal_packet();
        // Add enough options to exceed 300 bytes
        for i in 0..15 {
            // Remove END, add option, add END
            let end = pkt.len() - 1;
            pkt[end] = (100 + i) as u8; // arbitrary option tag
            pkt.push(4);
            pkt.push(0);
            pkt.push(0);
            pkt.push(0);
            pkt.push(0);
            pkt.push(OPTION_END);
        }
        // Should be 241 + 15 * 6 = 331 bytes
        assert!(pkt.len() > MIN_PACKETSZ);
        let size = dhcp_packet_size(&pkt, None);
        assert_eq!(size, pkt.len()); // no padding needed
    }

    #[test]
    fn test_dhcp_packet_size_too_short() {
        let pkt = vec![0u8; 50];
        assert_eq!(dhcp_packet_size(&pkt, None), MIN_PACKETSZ);
    }

    // -- round-trip tests --

    #[test]
    fn test_put_then_find() {
        let mut buf = make_minimal_packet();
        option_put(&mut buf, 53, 1, 3); // DHCPREQUEST
        option_put(&mut buf, 50, 4, 0xC0A80164); // 192.168.1.100

        // Find option 53
        let opt53 = option_find(&buf, 53, 1);
        assert!(opt53.is_some());
        assert_eq!(option_uint(opt53.unwrap(), 0, 1), Some(3));

        // Find option 50
        let opt50 = option_find(&buf, 50, 4);
        assert!(opt50.is_some());
        assert_eq!(
            option_addr(opt50.unwrap()),
            Some(Ipv4Addr::new(192, 168, 1, 100))
        );
    }

    #[test]
    fn test_put_string_then_sanitise() {
        let mut buf = make_minimal_packet();
        option_put_string(&mut buf, 12, "my-host", true);

        let opt12 = option_find(&buf, 12, 1);
        assert!(opt12.is_some());
        let name = sanitise(opt12.unwrap());
        assert_eq!(name, Some("my-host".to_string()));
    }

    #[test]
    fn test_clear_then_rebuild() {
        let mut buf = make_packet_with_options();
        clear_options(&mut buf);
        // Rebuild
        option_put(&mut buf, 53, 1, 5); // DHCPACK
        let opt = option_find(&buf, 53, 1);
        assert!(opt.is_some());
        assert_eq!(option_uint(opt.unwrap(), 0, 1), Some(5));
        // Old options should be gone
        assert!(option_find(&buf, 50, 4).is_none());
        assert!(option_find(&buf, 12, 1).is_none());
    }
}

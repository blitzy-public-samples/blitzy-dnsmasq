// dnsmasq is Copyright (c) 2000-2025 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

// The SURF random number generator was taken from djbdns-1.05, by
// Daniel J Bernstein, which is public domain.

//! Core utility functions library for dnsmasq.
//!
//! This module provides essential utility functions replacing C's `src/util.c` (2,730 lines).
//! The primary transformation is the **complete elimination of all C memory allocation
//! wrappers** (`safe_malloc`, `whine_malloc`, `whine_realloc`, `expand_buf`) — Rust's
//! ownership model, `Vec`, `Box`, and `String` handle all allocation automatically via RAII.
//!
//! # Key Components
//!
//! - **SURF RNG** — Cryptographic-quality random number generator (from djbdns-1.05, public
//!   domain by DJB). Faithfully reimplemented for DNS query ID and port randomization security.
//! - **DNS name utilities** — Hostname canonicalization, validation (RFC 1035/1123), comparison,
//!   and subdomain checking.
//! - **Network utilities** — IPv4 netmask operations, IPv6 prefix comparison, address formatting.
//! - **String utilities** — Hex parsing, MAC address formatting, socket address display.
//! - **Time utilities** — Timestamp retrieval, millisecond timing, human-readable duration formatting.
//! - **I/O utilities** — Safe pipe creation with CLOEXEC, file descriptor cleanup.
//! - **IDN support** — Internationalized domain name encoding (feature-gated).
//! - **Platform detection** — Linux kernel version retrieval (platform-gated).
//!
//! # Memory Safety
//!
//! All C `malloc`/`free` patterns have been replaced with Rust ownership. There are zero
//! `unsafe` blocks in this module — all platform operations use the `nix` crate's safe wrappers.

use crate::config::constants::{MAXDNAME, RANDFILE};
use crate::core::types::{DnsmasqError, DnsmasqResult};

use std::cmp::Ordering;
use std::fmt::Write as FmtWrite;
use std::fs::File;
use std::io::Read;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::io::{IntoRawFd, RawFd};
use std::time::{SystemTime, UNIX_EPOCH};

use tracing::error;
#[cfg(feature = "idn")]
use tracing::warn;

/// Maximum length of a single DNS label (RFC 1035 Section 2.3.4).
const MAXLABEL: usize = 63;

// ---------------------------------------------------------------------------
// SURF Random Number Generator
// ---------------------------------------------------------------------------

/// SURF (Speedy Unpredictable Random Function) random number generator.
///
/// Algorithm from djbdns-1.05 by Daniel J. Bernstein (public domain).
/// Provides cryptographic-quality randomness for DNS query ID generation
/// and source port randomization to prevent DNS cache poisoning attacks.
///
/// Replaces C's static `seed[32]`/`in[12]`/`out[8]`/`outleft` global state
/// (`util.c` lines 95-98) with an encapsulated struct.
pub struct SurfRng {
    /// 32-element seed array seeded from `/dev/urandom`.
    seed: [u32; 32],
    /// 12-element input state array, lower 4 elements form a 128-bit counter.
    input: [u32; 12],
    /// 8-element output buffer filled by [`surf()`].
    output: [u32; 8],
    /// Number of unconsumed 32-bit values remaining in `output` (for `rand16`/`rand32`).
    output_remaining: usize,
    /// Separate output counter for `rand64` (mirrors C's function-local `static int outleft`).
    output_remaining_64: usize,
}

impl SurfRng {
    /// Initialize the SURF RNG by reading entropy from the system random source.
    ///
    /// Reads 128 bytes for the seed array and 48 bytes for the input array from
    /// [`RANDFILE`] (typically `/dev/urandom`). This must be called once during
    /// daemon startup before generating any random values.
    ///
    /// Maps to C's `rand_init()` (`util.c` line 126).
    pub fn new() -> DnsmasqResult<Self> {
        let mut file = File::open(RANDFILE).map_err(|e| {
            error!("failed to open random source {}: {}", RANDFILE, e);
            DnsmasqError::Io(e)
        })?;

        let mut seed = [0u32; 32];
        let mut input = [0u32; 12];

        // Read seed: 32 × 4 = 128 bytes, interpreted as native-endian u32 values
        // (matches C's `read_write(fd, (unsigned char *)&seed, sizeof(seed), 1)`)
        let mut seed_buf = [0u8; 128];
        file.read_exact(&mut seed_buf).map_err(|e| {
            error!("failed to read random seed: {}", e);
            DnsmasqError::Io(e)
        })?;
        for (i, chunk) in seed_buf.chunks_exact(4).enumerate() {
            seed[i] = u32::from_ne_bytes(chunk.try_into().unwrap());
        }

        // Read input: 12 × 4 = 48 bytes, interpreted as native-endian u32 values
        let mut input_buf = [0u8; 48];
        file.read_exact(&mut input_buf).map_err(|e| {
            error!("failed to read random input state: {}", e);
            DnsmasqError::Io(e)
        })?;
        for (i, chunk) in input_buf.chunks_exact(4).enumerate() {
            input[i] = u32::from_ne_bytes(chunk.try_into().unwrap());
        }

        Ok(Self {
            seed,
            input,
            output: [0u32; 8],
            output_remaining: 0,
            output_remaining_64: 0,
        })
    }

    /// Increment the 128-bit counter stored in `input[0..4]`.
    ///
    /// Mirrors C's `if (!++in[0]) if (!++in[1]) if (!++in[2]) ++in[3];`
    #[inline]
    fn increment_counter(&mut self) {
        self.input[0] = self.input[0].wrapping_add(1);
        if self.input[0] == 0 {
            self.input[1] = self.input[1].wrapping_add(1);
            if self.input[1] == 0 {
                self.input[2] = self.input[2].wrapping_add(1);
                if self.input[2] == 0 {
                    self.input[3] = self.input[3].wrapping_add(1);
                }
            }
        }
    }

    /// Core SURF mixing function generating 8 random 32-bit output values.
    ///
    /// Performs 2 outer loops × 16 inner rounds of MUSH operations with the
    /// golden ratio constant `0x9e3779b9`. This is a faithful reproduction of
    /// the djbdns-1.05 SURF algorithm (`util.c` line 159).
    ///
    /// # MUSH operation
    /// ```text
    /// MUSH(i, b): x = t[i] += ((x ^ seed[i]) + sum) ^ ROTATE(x, b)
    /// ```
    fn surf(&mut self) {
        let mut t = [0u32; 12];
        let mut sum: u32 = 0;

        // t[i] = in[i] ^ seed[12+i]
        for (i, t_val) in t.iter_mut().enumerate() {
            *t_val = self.input[i] ^ self.seed[12 + i];
        }
        // out[i] = seed[24+i]
        for (i, out_val) in self.output.iter_mut().enumerate() {
            *out_val = self.seed[24 + i];
        }

        let mut x = t[11];

        // Rotation schedule: [5, 7, 9, 13] repeated for indices 0-11
        const ROTATIONS: [u32; 12] = [5, 7, 9, 13, 5, 7, 9, 13, 5, 7, 9, 13];

        for _ in 0..2 {
            for _ in 0..16 {
                sum = sum.wrapping_add(0x9e3779b9);
                for (i, &b) in ROTATIONS.iter().enumerate() {
                    // MUSH(i, b): x = t[i] += ((x ^ seed[i]) + sum) ^ ROTATE(x, b)
                    let val = (x ^ self.seed[i]).wrapping_add(sum) ^ x.rotate_left(b);
                    t[i] = t[i].wrapping_add(val);
                    x = t[i];
                }
            }
            for i in 0..8 {
                self.output[i] ^= t[i + 4];
            }
        }
    }

    /// Generate a cryptographically-strong 16-bit random number.
    ///
    /// Used primarily for DNS query ID generation and source port randomization.
    /// Maps to C's `rand16()` (`util.c` line 206).
    pub fn rand16(&mut self) -> u16 {
        if self.output_remaining == 0 {
            self.increment_counter();
            self.surf();
            self.output_remaining = 8;
        }
        self.output_remaining -= 1;
        self.output[self.output_remaining] as u16
    }

    /// Generate a cryptographically-strong 32-bit random number.
    ///
    /// Used for generating random timestamps, lease identifiers, and cache keys.
    /// Maps to C's `rand32()` (`util.c` line 245).
    pub fn rand32(&mut self) -> u32 {
        if self.output_remaining == 0 {
            self.increment_counter();
            self.surf();
            self.output_remaining = 8;
        }
        self.output_remaining -= 1;
        self.output[self.output_remaining]
    }

    /// Generate a cryptographically-strong 64-bit random number.
    ///
    /// Combines two 32-bit SURF outputs into a 64-bit value. Uses a separate
    /// output counter (`output_remaining_64`) matching C's function-local
    /// `static int outleft` in `rand64()` (`util.c` line 285).
    pub fn rand64(&mut self) -> u64 {
        if self.output_remaining_64 < 2 {
            self.increment_counter();
            self.surf();
            self.output_remaining_64 = 8;
        }
        self.output_remaining_64 -= 2;
        let lo = self.output[self.output_remaining_64 + 1] as u64;
        let hi = (self.output[self.output_remaining_64] as u64) << 32;
        lo + hi
    }
}

// ---------------------------------------------------------------------------
// DNS Name Utilities
// ---------------------------------------------------------------------------

/// Internal DNS name validation matching C's `check_name()` logic.
///
/// Validates:
/// - Total length ≤ [`MAXDNAME`] (1025 bytes)
/// - Individual labels ≤ [`MAXLABEL`] (63 bytes)
/// - No ASCII control characters
/// - At least one non-whitespace character
///
/// Returns `true` if the name is valid, `false` otherwise.
fn check_dns_name_internal(name: &str) -> bool {
    if name.is_empty() || name.len() > MAXDNAME {
        return false;
    }

    let mut dotgap: usize = 0;
    let mut has_non_whitespace = false;

    for c in name.chars() {
        if c == '.' {
            dotgap = 0;
        } else {
            dotgap += c.len_utf8();
            if dotgap > MAXLABEL {
                return false;
            }
            // Reject ASCII control characters (C check_name: `c != 0 && c < ' '`)
            if c.is_ascii() && (c as u32) < 0x20 {
                return false;
            }
            if c != ' ' {
                has_non_whitespace = true;
            }
        }
    }

    has_non_whitespace
}

/// Validate and canonicalize a DNS domain name.
///
/// Performs DNS name validation per RFC 1035, strips trailing dots, and
/// optionally applies IDN (Internationalized Domain Name) encoding for
/// names containing non-ASCII characters when the `idn` feature is enabled.
///
/// Returns `None` if the name is invalid (empty, too long, contains control
/// characters, or all whitespace). Returns `Some(canonical)` with the
/// validated name as a newly allocated `String`.
///
/// Maps to C's `canonicalise()` (`util.c` line 609).
pub fn canonicalise(name: &str) -> Option<String> {
    let trimmed = name.trim_end_matches('.');
    if trimmed.is_empty() {
        return None;
    }
    if !check_dns_name_internal(trimmed) {
        return None;
    }

    // If IDN feature is enabled and name has non-ASCII chars, encode it
    #[cfg(feature = "idn")]
    {
        if trimmed.bytes().any(|b| !b.is_ascii()) {
            return idn_encode(trimmed);
        }
    }

    Some(trimmed.to_string())
}

/// Validate a DNS domain name per RFC 1035/1123.
///
/// Returns `true` if the name is syntactically valid for DNS use. This checks
/// total length, label lengths, absence of control characters, and non-empty
/// content. Trailing dots are tolerated (stripped during validation).
///
/// Maps to C's `check_name()` (`util.c` line 388).
pub fn check_dns_name(name: &str) -> bool {
    let trimmed = name.trim_end_matches('.');
    if trimmed.is_empty() {
        return false;
    }
    check_dns_name_internal(trimmed)
}

/// Check whether a hostname label/name is syntactically valid per
/// RFC 952 / RFC 1123 hostname rules.
///
/// A legal hostname consists of labels separated by dots:
/// - Each label is 1–63 characters.
/// - Total length is ≤ 253 characters.
/// - Characters must be alphanumeric (`[a-zA-Z0-9]`) or hyphens (`-`).
/// - Labels must not begin or end with a hyphen.
/// - The first character of the entire hostname must be alphanumeric.
///
/// This is used by 12+ call sites including `cache.c`, `rfc1035.c`,
/// `option.c`, `dbus.c`, `dhcp-common.c`, `rfc2131.c`, and `lease.c`.
///
/// Maps to C's `legal_hostname()` (`util.c` line 447).
pub fn legal_hostname(name: &str) -> bool {
    if name.is_empty() || name.len() > 253 {
        return false;
    }

    // Strip optional trailing dot
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() {
        return false;
    }

    // First character of the entire name must be alphanumeric
    let first_char = name.as_bytes()[0];
    if !first_char.is_ascii_alphanumeric() {
        return false;
    }

    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        // Label must not start or end with hyphen
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        // All characters must be alphanumeric or hyphen
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return false;
        }
    }

    true
}

/// Case-insensitive hostname equality test.
///
/// Performs locale-independent ASCII case folding (A-Z → a-z) and compares
/// the full strings. Returns `true` if the hostnames are identical after
/// case normalization. Matches C's `hostname_isequal()` (`util.c` line 1260).
///
/// Per RFC 1035 Section 3.1, DNS names are case-insensitive.
pub fn hostname_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    hostname_cmp(a, b) == Ordering::Equal
}

/// Locale-independent case-insensitive hostname comparison.
///
/// Deliberately avoids `strcasecmp()` and locale-dependent functions.
/// Performs ASCII-only case folding (A-Z → a-z) and byte-by-byte comparison.
/// Returns `Ordering::Less`, `Ordering::Equal`, or `Ordering::Greater`.
///
/// Maps to C's `hostname_order()` (`util.c` line 1204).
pub fn hostname_cmp(a: &str, b: &str) -> Ordering {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    let len = a_bytes.len().min(b_bytes.len());

    for i in 0..len {
        let mut c1 = a_bytes[i];
        let mut c2 = b_bytes[i];

        // ASCII case fold: A-Z → a-z
        if c1.is_ascii_uppercase() {
            c1 += b'a' - b'A';
        }
        if c2.is_ascii_uppercase() {
            c2 += b'a' - b'A';
        }

        match c1.cmp(&c2) {
            Ordering::Equal => continue,
            other => return other,
        }
    }

    // If all compared bytes are equal, shorter string is "less"
    a_bytes.len().cmp(&b_bytes.len())
}

/// Check if `name` is equal to or a subdomain of `domain`.
///
/// Performs case-insensitive reverse comparison. Returns `true` if `name`
/// is exactly equal to `domain` or is a proper subdomain (e.g., `name` =
/// `"host.example.com"`, `domain` = `"example.com"`).
///
/// Maps to C's `hostname_issubdomain()` (`util.c` line 1326) which returns
/// 0 (no match), 1 (subdomain), or 2 (equal). This Rust version collapses
/// both 1 and 2 into `true`.
pub fn is_subdomain(name: &str, domain: &str) -> bool {
    let a_bytes = domain.as_bytes();
    let b_bytes = name.as_bytes();

    // Domain must be non-empty and name must be at least as long as domain
    if a_bytes.is_empty() || b_bytes.len() < a_bytes.len() {
        return false;
    }

    // Compare from end, matching C's reverse walk
    let mut ai = a_bytes.len();
    let mut bi = b_bytes.len();

    loop {
        if ai == 0 {
            break;
        }
        ai -= 1;
        bi -= 1;

        let mut c1 = a_bytes[ai];
        let mut c2 = b_bytes[bi];

        if c1.is_ascii_uppercase() {
            c1 += b'a' - b'A';
        }
        if c2.is_ascii_uppercase() {
            c2 += b'a' - b'A';
        }

        if c1 != c2 {
            return false;
        }
    }

    // If we consumed all of name (bi == 0), they are equal
    if bi == 0 {
        return true;
    }

    // Check that the character before the matched portion in name is '.'
    b_bytes[bi - 1] == b'.'
}

// ---------------------------------------------------------------------------
// String and Formatting Utilities
// ---------------------------------------------------------------------------

/// Parse a hexadecimal string into a byte vector.
///
/// Supports colon-separated (`"AA:BB:CC"`), dash-separated (`"AA-BB-CC"`),
/// space-separated (`"AA BB CC"`), or continuous (`"AABBCC"`) hex formats.
/// Returns `None` if any non-hex character is encountered.
///
/// Maps to C's `parse_hex()` (`util.c` line ~1830), simplified to omit the
/// wildcard mask and MAC type output parameters.
pub fn parse_hex(hex: &str) -> Option<Vec<u8>> {
    let hex = hex.trim();
    if hex.is_empty() {
        return Some(Vec::new());
    }

    let mut result = Vec::new();

    // Split on common separators (colon, dash, or space)
    let has_separator = hex.contains(':') || hex.contains('-') || hex.contains(' ');

    if has_separator {
        // Separator-delimited format
        for part in hex.split([':', '-', ' ']) {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            // Each part should be 1 or 2 hex digits
            if part.len() > 2 || !part.chars().all(|c| c.is_ascii_hexdigit()) {
                return None;
            }
            let byte = u8::from_str_radix(part, 16).ok()?;
            result.push(byte);
        }
    } else {
        // Continuous hex string: must have even number of digits
        if !hex.len().is_multiple_of(2) {
            return None;
        }
        if !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        for i in (0..hex.len()).step_by(2) {
            let byte = u8::from_str_radix(&hex[i..i + 2], 16).ok()?;
            result.push(byte);
        }
    }

    Some(result)
}

/// Format a MAC address as a colon-separated lowercase hex string.
///
/// An empty slice produces `"<null>"`. Otherwise formats each byte as
/// two lowercase hex digits separated by colons (e.g., `"01:23:45:67:89:ab"`).
///
/// Maps to C's `print_mac()` (`util.c` line ~2190).
pub fn format_mac(mac: &[u8]) -> String {
    if mac.is_empty() {
        return "<null>".to_string();
    }

    let mut result = String::with_capacity(mac.len() * 3 - 1);
    for (i, byte) in mac.iter().enumerate() {
        if i > 0 {
            result.push(':');
        }
        let _ = write!(result, "{:02x}", byte);
    }
    result
}

/// Format a socket address as a human-readable string.
///
/// For IPv4 addresses, produces `"ip:port"` format.
/// For IPv6 addresses, produces `"[ip]:port"` format.
///
/// Maps to C's `prettyprint_addr()` (`util.c` line 1719), adapted to use
/// Rust's `std::net::SocketAddr` instead of C's `union mysockaddr`.
pub fn format_addr(addr: &SocketAddr) -> String {
    match addr {
        SocketAddr::V4(v4) => format!("{}:{}", v4.ip(), v4.port()),
        SocketAddr::V6(v6) => format!("[{}]:{}", v6.ip(), v6.port()),
    }
}

// ---------------------------------------------------------------------------
// Socket Address Utilities
// ---------------------------------------------------------------------------

/// Compare two socket addresses for equality.
///
/// Compares IP address and port. For IPv6, also compares the scope ID.
///
/// Maps to C's `sockaddr_isequal()` (`util.c` line ~1010).
pub fn sockaddr_eq(a: &SocketAddr, b: &SocketAddr) -> bool {
    match (a, b) {
        (SocketAddr::V4(a4), SocketAddr::V4(b4)) => a4.ip() == b4.ip() && a4.port() == b4.port(),
        (SocketAddr::V6(a6), SocketAddr::V6(b6)) => {
            a6.ip() == b6.ip() && a6.port() == b6.port() && a6.scope_id() == b6.scope_id()
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Network Utilities
// ---------------------------------------------------------------------------

/// Calculate CIDR prefix length from an IPv4 netmask.
///
/// Counts leading one-bits in the mask to determine the prefix length.
/// For example, `255.255.255.0` → `24`, `255.255.0.0` → `16`.
///
/// Maps to C's `netmask_length()` (`util.c` line 1464).
pub fn netmask_length(mask: Ipv4Addr) -> u8 {
    let bits = u32::from(mask);
    if bits == 0 {
        return 0;
    }
    // C algorithm: counts trailing zeros, returns 32 - count.
    // Equivalent to counting leading ones for a valid contiguous netmask.
    (32 - bits.trailing_zeros()) as u8
}

/// Determine if two IPv4 addresses are in the same subnet.
///
/// Applies the netmask to both addresses and compares the network portions.
///
/// Maps to C's `is_same_net()` (`util.c` line 1511).
pub fn is_same_net(a: Ipv4Addr, b: Ipv4Addr, mask: Ipv4Addr) -> bool {
    let a_bits = u32::from(a);
    let b_bits = u32::from(b);
    let mask_bits = u32::from(mask);
    (a_bits & mask_bits) == (b_bits & mask_bits)
}

/// Determine if two IPv6 addresses are in the same subnet.
///
/// Compares the first `prefix_len` bits of both addresses.
/// Handles both byte-aligned and non-byte-aligned prefix lengths.
///
/// Maps to C's `is_same_net6()` (`util.c` line 1564).
pub fn is_same_net6(a: Ipv6Addr, b: Ipv6Addr, prefix_len: u8) -> bool {
    let a_octets = a.octets();
    let b_octets = b.octets();
    let pf_bytes = (prefix_len / 8) as usize;
    let pf_bits = prefix_len % 8;

    // Compare full bytes
    if pf_bytes > 0 && a_octets[..pf_bytes] != b_octets[..pf_bytes] {
        return false;
    }

    // Compare remaining bits in partial byte
    if pf_bits == 0 {
        return true;
    }

    if pf_bytes >= 16 {
        return true;
    }

    let shift = 8 - pf_bits;
    (a_octets[pf_bytes] >> shift) == (b_octets[pf_bytes] >> shift)
}

/// Extract the host portion (lower 64 bits) from an IPv6 address.
///
/// Returns bytes 8-15 as a 64-bit integer (big-endian byte order).
///
/// Maps to C's `addr6part()` (`util.c` line 1617).
pub fn addr6_host_part(addr: &Ipv6Addr) -> u64 {
    let octets = addr.octets();
    let mut result: u64 = 0;
    for &byte in octets.iter().skip(8) {
        result = (result << 8) | (byte as u64);
    }
    result
}

/// Set the host portion (lower 64 bits) of an IPv6 address.
///
/// Writes `val` into bytes 8-15, preserving the upper 64-bit network prefix.
///
/// Maps to C's `setaddr6part()` (`util.c` line 1662).
pub fn set_addr6_host_part(addr: &mut Ipv6Addr, val: u64) {
    let mut octets = addr.octets();
    let mut host = val;
    for i in (8..16).rev() {
        octets[i] = (host & 0xFF) as u8;
        host >>= 8;
    }
    *addr = Ipv6Addr::from(octets);
}

// ---------------------------------------------------------------------------
// Time Utilities
// ---------------------------------------------------------------------------

/// Get the current time as seconds since the Unix epoch.
///
/// Uses `std::time::SystemTime` which corresponds to C's `time(NULL)`.
/// Returns 0 on clock error (should not happen in practice).
///
/// Maps to C's `dnsmasq_time()` (`util.c` line 1390).
pub fn dnsmasq_time() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Get the current time in milliseconds since the Unix epoch.
///
/// Provides millisecond-precision timing for rate limiting, performance
/// measurement, and timeout calculations.
///
/// Maps to C's `dnsmasq_milliseconds()` (`util.c` line 1431).
pub fn dnsmasq_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Format a time duration in seconds as a compact human-readable string.
///
/// Produces components like `"1d2h3m4s"`, omitting zero-valued components.
/// The sentinel value `0xFFFFFFFF` (4294967295) and above produces `"infinite"`.
///
/// Maps to C's `prettyprint_time()` (`util.c` line 1786).
pub fn format_duration(secs: u64) -> String {
    if secs >= 0xFFFF_FFFF {
        return "infinite".to_string();
    }

    let mut result = String::new();

    let days = secs / 86400;
    let hours = (secs / 3600) % 24;
    let minutes = (secs / 60) % 60;
    let seconds = secs % 60;

    if days > 0 {
        let _ = write!(result, "{}d", days);
    }
    if hours > 0 {
        let _ = write!(result, "{}h", hours);
    }
    if minutes > 0 {
        let _ = write!(result, "{}m", minutes);
    }
    if seconds > 0 || result.is_empty() {
        let _ = write!(result, "{}s", seconds);
    }

    result
}

// ---------------------------------------------------------------------------
// I/O Utilities
// ---------------------------------------------------------------------------

/// Create a pipe with `O_CLOEXEC` flags set on both ends.
///
/// Returns `(read_fd, write_fd)` as raw file descriptors. Both ends have
/// the close-on-exec flag set to prevent leaking to child processes.
///
/// Maps to C's `safe_pipe()` (`util.c` line 860), using `nix::unistd::pipe()`
/// instead of raw `pipe()` + `fix_fd()`.
pub fn safe_pipe() -> DnsmasqResult<(RawFd, RawFd)> {
    let (read_fd, write_fd) = nix::unistd::pipe().map_err(|e| {
        error!("cannot create pipe: {}", e);
        DnsmasqError::Io(std::io::Error::from(e))
    })?;
    // OwnedFd → RawFd: transfers ownership so the fd won't be auto-closed
    Ok((read_fd.into_raw_fd(), write_fd.into_raw_fd()))
}

/// Close all file descriptors except stdin/stdout/stderr and any spares.
///
/// Iterates from `max_fd` down to 0, closing every descriptor except
/// standard streams (0, 1, 2) and any fd listed in `except_fds`.
/// Typically called after `fork()` before `exec()` to clean up inherited
/// descriptors.
///
/// On Linux, attempts to use `/proc/self/fd` for efficient enumeration
/// before falling back to the brute-force iteration.  The `/proc` path
/// uses a two-pass approach (collect first, then close) to avoid closing
/// the directory iterator's own file descriptor mid-iteration.
///
/// Maps to C's `close_fds()` (`util.c` line 2480) which accepts up to 3
/// protected file descriptors via `(max_fd, except1, except2)`.
pub fn close_fds(max_fd: i32, except_fds: &[i32]) {
    // Try efficient /proc/self/fd enumeration on Linux.
    // Two-pass approach: collect all fd numbers first, then close,
    // so the directory iterator's own fd is not closed mid-iteration.
    #[cfg(target_os = "linux")]
    {
        if let Ok(entries) = std::fs::read_dir("/proc/self/fd") {
            let fds_to_close: Vec<i32> = entries
                .flatten()
                .filter_map(|entry| {
                    entry
                        .file_name()
                        .to_str()
                        .and_then(|name| name.parse::<i32>().ok())
                })
                .filter(|&fd| fd > 2 && !except_fds.contains(&fd))
                .collect();

            for fd in fds_to_close {
                let _ = nix::unistd::close(fd);
            }
            return;
        }
    }

    // Fallback: iterate through all possible descriptors
    for fd in (3..max_fd).rev() {
        if except_fds.contains(&fd) {
            continue;
        }
        let _ = nix::unistd::close(fd);
    }
}

// ---------------------------------------------------------------------------
// IDN Support (feature-gated)
// ---------------------------------------------------------------------------

/// Encode a domain name using IDNA2008 Punycode encoding.
///
/// Converts internationalized domain names containing non-ASCII characters
/// to their ASCII-Compatible Encoding (ACE) form with `xn--` prefix.
/// Returns `None` if encoding fails.
///
/// Gated by the `idn` Cargo feature flag, mapping to C's `HAVE_IDN`/`HAVE_LIBIDN2`.
///
/// Maps to C's IDN encoding in `canonicalise()` (`util.c` line 620-643).
#[cfg(feature = "idn")]
pub fn idn_encode(name: &str) -> Option<String> {
    match idna::domain_to_ascii(name) {
        Ok(encoded) => Some(encoded),
        Err(e) => {
            warn!("IDN encoding failed for '{}': {:?}", name, e);
            None
        }
    }
}

/// Stub for when IDN feature is not enabled — always returns `None`.
#[cfg(not(feature = "idn"))]
pub fn idn_encode(_name: &str) -> Option<String> {
    None
}

// ---------------------------------------------------------------------------
// Platform-Specific Utilities
// ---------------------------------------------------------------------------

/// Retrieve the running Linux kernel version as a `(major, minor, patch)` tuple.
///
/// Uses `uname()` to read the kernel release string and parses it into
/// numeric components. For example, kernel `"5.15.0"` → `(5, 15, 0)`.
///
/// Maps to C's `kernel_version()` (`util.c` line 2714), which returns a single
/// encoded integer `(major * 65536 + minor * 256 + patch)`. The Rust version
/// returns a cleaner tuple representation.
#[cfg(target_os = "linux")]
pub fn kernel_version() -> (u32, u32, u32) {
    match nix::sys::utsname::uname() {
        Ok(info) => {
            let release = info.release().to_string_lossy();
            let mut parts = release.split('.');
            let major = parts
                .next()
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(0);
            let minor = parts
                .next()
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(0);
            // Patch may contain extra info like "0-generic", take only digits
            let patch = parts
                .next()
                .and_then(|s| {
                    let numeric: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
                    numeric.parse::<u32>().ok()
                })
                .unwrap_or(0);
            (major, minor, patch)
        }
        Err(e) => {
            error!("failed to get kernel version via uname: {}", e);
            (0, 0, 0)
        }
    }
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- SURF RNG Tests ---

    #[test]
    fn test_surf_rng_creation() {
        let rng = SurfRng::new();
        assert!(
            rng.is_ok(),
            "SurfRng::new() should succeed on systems with /dev/urandom"
        );
    }

    #[test]
    fn test_surf_rng_rand16_produces_values() {
        let mut rng = SurfRng::new().unwrap();
        let mut seen_nonzero = false;
        for _ in 0..100 {
            let val = rng.rand16();
            if val != 0 {
                seen_nonzero = true;
            }
        }
        assert!(seen_nonzero, "rand16 should produce non-zero values");
    }

    #[test]
    fn test_surf_rng_rand32_produces_values() {
        let mut rng = SurfRng::new().unwrap();
        let v1 = rng.rand32();
        let v2 = rng.rand32();
        // Extremely unlikely to get two identical 32-bit values
        assert!(v1 != v2 || v1 == 0, "rand32 should produce varying values");
    }

    #[test]
    fn test_surf_rng_rand64_produces_values() {
        let mut rng = SurfRng::new().unwrap();
        let v1 = rng.rand64();
        let v2 = rng.rand64();
        assert!(v1 != v2 || v1 == 0, "rand64 should produce varying values");
    }

    #[test]
    fn test_surf_rng_deterministic_with_known_seed() {
        // Create two RNG instances with identical state and verify they produce
        // the same output sequence.
        let mut rng1 = SurfRng {
            seed: [1u32; 32],
            input: [0u32; 12],
            output: [0u32; 8],
            output_remaining: 0,
            output_remaining_64: 0,
        };
        let mut rng2 = SurfRng {
            seed: [1u32; 32],
            input: [0u32; 12],
            output: [0u32; 8],
            output_remaining: 0,
            output_remaining_64: 0,
        };

        for _ in 0..20 {
            assert_eq!(rng1.rand16(), rng2.rand16());
        }
        for _ in 0..20 {
            assert_eq!(rng1.rand32(), rng2.rand32());
        }
    }

    // --- DNS Name Validation Tests ---

    #[test]
    fn test_check_dns_name_valid() {
        assert!(check_dns_name("example.com"));
        assert!(check_dns_name("sub.example.com"));
        assert!(check_dns_name("a"));
        assert!(check_dns_name("123.456"));
        assert!(check_dns_name("host-name.example.com"));
    }

    #[test]
    fn test_check_dns_name_trailing_dot() {
        assert!(check_dns_name("example.com."));
    }

    #[test]
    fn test_check_dns_name_invalid() {
        assert!(!check_dns_name(""));
        assert!(!check_dns_name("."));
        // Label > 63 chars
        let long_label = "a".repeat(64);
        assert!(!check_dns_name(&long_label));
        // Control character
        assert!(!check_dns_name("test\x01.com"));
    }

    #[test]
    fn test_check_dns_name_max_length() {
        // Name exceeding MAXDNAME should be invalid
        let too_long = "a".repeat(MAXDNAME + 1);
        assert!(!check_dns_name(&too_long));
    }

    // --- Canonicalise Tests ---

    #[test]
    fn test_canonicalise_valid() {
        assert_eq!(canonicalise("example.com"), Some("example.com".to_string()));
    }

    #[test]
    fn test_canonicalise_strips_trailing_dot() {
        assert_eq!(
            canonicalise("example.com."),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_canonicalise_invalid() {
        assert_eq!(canonicalise(""), None);
        assert_eq!(canonicalise("."), None);
    }

    // --- Hostname Comparison Tests ---

    #[test]
    fn test_hostname_eq_case_insensitive() {
        assert!(hostname_eq("Example.COM", "example.com"));
        assert!(hostname_eq("HOST", "host"));
        assert!(hostname_eq("a.b.c", "A.B.C"));
    }

    #[test]
    fn test_hostname_eq_different() {
        assert!(!hostname_eq("alpha", "beta"));
        assert!(!hostname_eq("host1", "host2"));
        assert!(!hostname_eq("short", "longer"));
    }

    #[test]
    fn test_hostname_cmp_ordering() {
        assert_eq!(hostname_cmp("alpha", "beta"), Ordering::Less);
        assert_eq!(hostname_cmp("beta", "alpha"), Ordering::Greater);
        assert_eq!(hostname_cmp("same", "SAME"), Ordering::Equal);
        assert_eq!(hostname_cmp("a", "ab"), Ordering::Less);
    }

    // --- Subdomain Tests ---

    #[test]
    fn test_is_subdomain_exact_match() {
        assert!(is_subdomain("example.com", "example.com"));
        assert!(is_subdomain("EXAMPLE.COM", "example.com"));
    }

    #[test]
    fn test_is_subdomain_proper_subdomain() {
        assert!(is_subdomain("host.example.com", "example.com"));
        assert!(is_subdomain("deep.sub.example.com", "example.com"));
    }

    #[test]
    fn test_is_subdomain_no_match() {
        assert!(!is_subdomain("other.com", "example.com"));
        assert!(!is_subdomain("host", "example.com"));
        // Not a subdomain if domain portion only partially matches
        assert!(!is_subdomain("notexample.com", "example.com"));
    }

    #[test]
    fn test_is_subdomain_empty_domain() {
        assert!(!is_subdomain("anything", ""));
    }

    // --- Hex Parsing Tests ---

    #[test]
    fn test_parse_hex_colon_separated() {
        assert_eq!(
            parse_hex("AA:BB:CC:DD:EE:FF"),
            Some(vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
        );
    }

    #[test]
    fn test_parse_hex_dash_separated() {
        assert_eq!(parse_hex("01-02-03"), Some(vec![0x01, 0x02, 0x03]));
    }

    #[test]
    fn test_parse_hex_continuous() {
        assert_eq!(parse_hex("AABBCC"), Some(vec![0xAA, 0xBB, 0xCC]));
    }

    #[test]
    fn test_parse_hex_empty() {
        assert_eq!(parse_hex(""), Some(Vec::new()));
    }

    #[test]
    fn test_parse_hex_invalid() {
        assert_eq!(parse_hex("GG:HH"), None);
        // Odd-length continuous hex
        assert_eq!(parse_hex("ABC"), None);
    }

    // --- MAC Formatting Tests ---

    #[test]
    fn test_format_mac_typical() {
        assert_eq!(
            format_mac(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xAB]),
            "01:23:45:67:89:ab"
        );
    }

    #[test]
    fn test_format_mac_empty() {
        assert_eq!(format_mac(&[]), "<null>");
    }

    #[test]
    fn test_format_mac_single_byte() {
        assert_eq!(format_mac(&[0xFF]), "ff");
    }

    // --- Format Address Tests ---

    #[test]
    fn test_format_addr_v4() {
        let addr: SocketAddr = "192.168.1.1:53".parse().unwrap();
        assert_eq!(format_addr(&addr), "192.168.1.1:53");
    }

    #[test]
    fn test_format_addr_v6() {
        let addr: SocketAddr = "[::1]:53".parse().unwrap();
        assert_eq!(format_addr(&addr), "[::1]:53");
    }

    // --- Socket Address Equality Tests ---

    #[test]
    fn test_sockaddr_eq_v4() {
        let a: SocketAddr = "192.168.1.1:53".parse().unwrap();
        let b: SocketAddr = "192.168.1.1:53".parse().unwrap();
        let c: SocketAddr = "192.168.1.2:53".parse().unwrap();
        assert!(sockaddr_eq(&a, &b));
        assert!(!sockaddr_eq(&a, &c));
    }

    #[test]
    fn test_sockaddr_eq_different_families() {
        let v4: SocketAddr = "192.168.1.1:53".parse().unwrap();
        let v6: SocketAddr = "[::1]:53".parse().unwrap();
        assert!(!sockaddr_eq(&v4, &v6));
    }

    // --- Network Utility Tests ---

    #[test]
    fn test_netmask_length() {
        assert_eq!(netmask_length(Ipv4Addr::new(255, 255, 255, 0)), 24);
        assert_eq!(netmask_length(Ipv4Addr::new(255, 255, 0, 0)), 16);
        assert_eq!(netmask_length(Ipv4Addr::new(255, 0, 0, 0)), 8);
        assert_eq!(netmask_length(Ipv4Addr::new(255, 255, 255, 255)), 32);
        assert_eq!(netmask_length(Ipv4Addr::new(0, 0, 0, 0)), 0);
    }

    #[test]
    fn test_is_same_net() {
        let a = Ipv4Addr::new(192, 168, 1, 10);
        let b = Ipv4Addr::new(192, 168, 1, 20);
        let c = Ipv4Addr::new(192, 168, 2, 10);
        let mask = Ipv4Addr::new(255, 255, 255, 0);

        assert!(is_same_net(a, b, mask));
        assert!(!is_same_net(a, c, mask));
    }

    #[test]
    fn test_is_same_net6() {
        let a: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let b: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let c: Ipv6Addr = "2001:db9::1".parse().unwrap();

        assert!(is_same_net6(a, b, 64));
        assert!(!is_same_net6(a, c, 64));
        // Different prefix length
        assert!(is_same_net6(a, c, 15));
    }

    #[test]
    fn test_addr6_host_part() {
        let addr: Ipv6Addr = "2001:db8::1234:5678:90ab:cdef".parse().unwrap();
        let host = addr6_host_part(&addr);
        assert_eq!(host, 0x1234_5678_90ab_cdef);
    }

    #[test]
    fn test_set_addr6_host_part() {
        let mut addr: Ipv6Addr = "2001:db8::".parse().unwrap();
        set_addr6_host_part(&mut addr, 0x0000_0000_0000_0001);
        assert_eq!(addr, "2001:db8::1".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn test_set_addr6_host_part_preserves_prefix() {
        let mut addr: Ipv6Addr = "2001:db8:1234:5678::".parse().unwrap();
        set_addr6_host_part(&mut addr, 0xABCD_EF01_2345_6789);
        let octets = addr.octets();
        // Upper 64 bits preserved
        assert_eq!(
            octets[0..8],
            [0x20, 0x01, 0x0d, 0xb8, 0x12, 0x34, 0x56, 0x78]
        );
        // Lower 64 bits set
        assert_eq!(
            octets[8..16],
            [0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89]
        );
    }

    // --- Time Utility Tests ---

    #[test]
    fn test_dnsmasq_time_positive() {
        let t = dnsmasq_time();
        assert!(t > 0, "dnsmasq_time should return positive epoch seconds");
    }

    #[test]
    fn test_dnsmasq_millis_positive() {
        let ms = dnsmasq_millis();
        assert!(ms > 0, "dnsmasq_millis should return positive milliseconds");
    }

    #[test]
    fn test_dnsmasq_millis_greater_than_time() {
        let t = dnsmasq_time() as u64;
        let ms = dnsmasq_millis();
        // Milliseconds should be roughly 1000x the seconds value
        assert!(
            ms >= t * 900,
            "millis should be approximately 1000x seconds"
        );
    }

    #[test]
    fn test_format_duration_components() {
        assert_eq!(format_duration(90061), "1d1h1m1s");
        assert_eq!(format_duration(3661), "1h1m1s");
        assert_eq!(format_duration(61), "1m1s");
        assert_eq!(format_duration(1), "1s");
        assert_eq!(format_duration(86400), "1d");
        assert_eq!(format_duration(3600), "1h");
        assert_eq!(format_duration(60), "1m");
    }

    #[test]
    fn test_format_duration_infinite() {
        assert_eq!(format_duration(0xFFFF_FFFF), "infinite");
        assert_eq!(format_duration(u64::MAX), "infinite");
    }

    #[test]
    fn test_format_duration_zero() {
        assert_eq!(format_duration(0), "0s");
    }

    // --- I/O Utility Tests ---

    #[test]
    fn test_safe_pipe() {
        let result = safe_pipe();
        assert!(result.is_ok(), "safe_pipe should succeed");
        let (read_fd, write_fd) = result.unwrap();
        assert!(read_fd >= 0, "read fd should be non-negative");
        assert!(write_fd >= 0, "write fd should be non-negative");
        assert_ne!(read_fd, write_fd, "pipe fds should be different");

        // Clean up
        let _ = nix::unistd::close(read_fd);
        let _ = nix::unistd::close(write_fd);
    }

    // --- Platform-Specific Tests ---

    #[cfg(target_os = "linux")]
    #[test]
    fn test_kernel_version() {
        let (major, minor, patch) = kernel_version();
        assert!(
            major >= 2,
            "kernel major version should be >= 2, got {}",
            major
        );
        assert!(
            major < 100,
            "kernel major version should be < 100, got {}",
            major
        );
        assert!(minor < 1000, "kernel minor should be < 1000, got {}", minor);
        assert!(patch < 1000, "kernel patch should be < 1000, got {}", patch);
    }

    // --- IDN Tests ---

    #[cfg(feature = "idn")]
    #[test]
    fn test_idn_encode_ascii() {
        let result = idn_encode("example.com");
        assert_eq!(result, Some("example.com".to_string()));
    }

    #[cfg(feature = "idn")]
    #[test]
    fn test_idn_encode_unicode() {
        let result = idn_encode("münchen.de");
        assert!(
            result.is_some(),
            "IDN encoding should succeed for valid unicode domain"
        );
        let encoded = result.unwrap();
        assert!(
            encoded.contains("xn--"),
            "IDN encoded domain should contain xn-- prefix, got: {}",
            encoded
        );
    }

    #[cfg(not(feature = "idn"))]
    #[test]
    fn test_idn_encode_disabled() {
        assert_eq!(idn_encode("anything"), None);
    }

    // ================================================================
    // legal_hostname tests
    // ================================================================

    #[test]
    fn test_legal_hostname_simple() {
        assert!(legal_hostname("example"));
    }

    #[test]
    fn test_legal_hostname_dotted() {
        assert!(legal_hostname("host.example.com"));
    }

    #[test]
    fn test_legal_hostname_trailing_dot() {
        assert!(legal_hostname("host.example.com."));
    }

    #[test]
    fn test_legal_hostname_empty() {
        assert!(!legal_hostname(""));
    }

    #[test]
    fn test_legal_hostname_too_long() {
        let long_name = "a".repeat(254);
        assert!(!legal_hostname(&long_name));
    }

    #[test]
    fn test_legal_hostname_max_length() {
        // 253 chars with valid labels
        let label = "a".repeat(63);
        let name = format!("{}.{}.{}.{}", label, label, label, &label[..60]);
        assert!(name.len() <= 253);
        assert!(legal_hostname(&name));
    }

    #[test]
    fn test_legal_hostname_label_too_long() {
        let long_label = "a".repeat(64);
        assert!(!legal_hostname(&long_label));
    }

    #[test]
    fn test_legal_hostname_hyphen_start() {
        assert!(!legal_hostname("-host"));
    }

    #[test]
    fn test_legal_hostname_hyphen_end() {
        assert!(!legal_hostname("host-"));
    }

    #[test]
    fn test_legal_hostname_hyphen_middle() {
        assert!(legal_hostname("my-host"));
    }

    #[test]
    fn test_legal_hostname_underscore() {
        assert!(!legal_hostname("my_host"));
    }

    #[test]
    fn test_legal_hostname_space() {
        assert!(!legal_hostname("my host"));
    }

    #[test]
    fn test_legal_hostname_numeric() {
        assert!(legal_hostname("123"));
    }

    #[test]
    fn test_legal_hostname_starts_nonalpha() {
        assert!(!legal_hostname("!host"));
    }

    #[test]
    fn test_legal_hostname_empty_label() {
        assert!(!legal_hostname("host..com"));
    }

    #[test]
    fn test_legal_hostname_only_dot() {
        assert!(!legal_hostname("."));
    }

    #[test]
    fn test_legal_hostname_dot_prefix() {
        assert!(!legal_hostname(".host"));
    }

    #[test]
    fn test_legal_hostname_single_char() {
        assert!(legal_hostname("a"));
    }

    #[test]
    fn test_legal_hostname_alphanumeric_mixed() {
        assert!(legal_hostname("host1.sub2.example3"));
    }

    #[test]
    fn test_legal_hostname_all_numeric_labels() {
        assert!(legal_hostname("1.2.3.4.example.com"));
    }

    // ================================================================
    // close_fds tests
    // ================================================================

    // Note: close_fds tests are intentionally omitted because the function
    // closes real file descriptors, which conflicts with instrumented coverage
    // tools (llvm-cov / tarpaulin) that use FDs for profraw output.  The
    // function is a thin wrapper around libc::close and is tested implicitly
    // via integration tests.
}

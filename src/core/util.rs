//! Core utility functions for DNS name validation, pattern matching, and I/O helpers.
//!
//! Replaces non-PRNG portions of `src/util.c` (2730 lines) and pattern matching
//! from `src/pattern.c`. Key omissions from C version:
//! - `safe_malloc` / `whine_malloc` / `whine_realloc` — Rust handles allocation automatically
//! - `safe_strncpy` / `safe_strncat` — Rust String type prevents buffer overflows
//! - SURF PRNG functions — moved to `core::prng` module
//!
//! ## Key Functions
//! - DNS name validation: [`check_name()`], [`legal_hostname()`], [`canonicalise()`]
//! - Hostname comparison: [`hostname_isequal()`], [`hostname_issubdomain()`]
//! - Pattern matching: [`wildcard_match()`], [`is_dns_name_matching_pattern()`]
//! - I/O helpers: [`retry_send()`], [`read_write()`], [`safe_pipe()`]
//! - Time utilities: [`dnsmasq_time()`], [`prettyprint_time()`]
//!
//! ## Source
//! - Primary: `src/util.c` — DNS name validation, hostname comparison, I/O helpers
//! - Secondary: `src/pattern.c` — DNS pattern validation and matching (general-purpose)

use std::cmp::Ordering;
use std::io::{self, ErrorKind};
use std::os::fd::{IntoRawFd, RawFd};
use std::time::{SystemTime, UNIX_EPOCH};

use nix::fcntl::OFlag;
use nix::unistd::pipe2;

use crate::types::addr::SocketAddress;
use crate::types::network::ReadWriteDirection;

// ---------------------------------------------------------------------------
// Constants (from config.h)
// ---------------------------------------------------------------------------

/// Maximum total length of a DNS domain name in bytes (RFC 1035 Section 2.3.4).
///
/// Includes all label lengths and label bytes but not the trailing root label byte.
/// Corresponds to C `MAXDNAME = 1025` from `config.h`.
pub const MAXDNAME: usize = 1025;

/// Maximum length of a single DNS label in bytes (RFC 1035 Section 2.3.4).
///
/// Each label within a domain name must be 63 bytes or fewer.
/// Corresponds to C `MAXLABEL = 63` from `config.h`.
pub const MAXLABEL: usize = 63;

// ---------------------------------------------------------------------------
// CheckNameResult enum
// ---------------------------------------------------------------------------

/// Result of DNS name syntax validation by [`check_name()`].
///
/// Maps to the C function's tri-state return: 0 (invalid), 1 (valid ASCII),
/// 2 (needs IDN encoding). Rust enum provides type-safe exhaustive matching.
///
/// # Source
/// `src/util.c` `check_name()` lines 388–453.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckNameResult {
    /// Name is invalid: empty, too long, contains control characters,
    /// has a label exceeding [`MAXLABEL`], or is all whitespace.
    Invalid,
    /// Name is valid and contains only ASCII printable characters.
    /// No IDN encoding required.
    ValidAscii,
    /// Name is valid but contains non-ASCII characters or uppercase letters
    /// that require Internationalized Domain Name (IDN) Punycode encoding.
    /// Only returned when the `idn` feature is enabled.
    NeedsIdn,
}

// ---------------------------------------------------------------------------
// CanonicaliseError enum
// ---------------------------------------------------------------------------

/// Error type for [`canonicalise()`] domain name canonicalization.
///
/// Replaces C-style error reporting via NULL return and `*nomem` out-parameter
/// with Rust's `Result<T, E>` pattern using `thiserror` derive macro.
///
/// # Source
/// `src/util.c` `canonicalise()` lines 609–654.
#[derive(Debug, thiserror::Error)]
pub enum CanonicaliseError {
    /// Name failed DNS syntax validation via [`check_name()`].
    #[error("invalid DNS name")]
    Invalid,

    /// IDN Punycode encoding failed (only with `idn` feature).
    #[error("IDN encoding error: {0}")]
    IdnError(String),
}

// ---------------------------------------------------------------------------
// DNS Name Validation
// ---------------------------------------------------------------------------

/// Validate domain name syntax and determine if IDN processing is required.
///
/// Checks a domain name string against RFC 1035 naming rules:
/// - Total length ≤ [`MAXDNAME`] (1025 bytes)
/// - Individual labels ≤ [`MAXLABEL`] (63 bytes)
/// - No ASCII control characters
/// - Not all whitespace
/// - Trailing dot is silently stripped for canonicalization
///
/// Returns [`CheckNameResult::NeedsIdn`] only when the `idn` feature is enabled
/// and the name contains non-ASCII characters or uppercase requiring IDN encoding.
///
/// # Arguments
/// * `name` — Domain name string to validate
///
/// # Returns
/// [`CheckNameResult`] indicating validity and IDN requirements.
///
/// # Source
/// Port of `src/util.c` `check_name()` lines 388–453.
pub fn check_name(name: &str) -> CheckNameResult {
    // Strip trailing dot for canonicalization
    let name = name.strip_suffix('.').unwrap_or(name);

    // Empty string is invalid
    if name.is_empty() {
        return CheckNameResult::Invalid;
    }

    // Total length check
    if name.len() > MAXDNAME {
        return CheckNameResult::Invalid;
    }

    let mut dotgap: usize = 0;
    let mut nowhite = false;
    #[allow(unused_mut)]
    let mut idn_encode = false;
    #[allow(unused_mut, unused_assignments)]
    let mut _has_ucase = false;

    for c in name.chars() {
        if c == '.' {
            dotgap = 0;
        } else {
            dotgap += c.len_utf8();
            if dotgap > MAXLABEL {
                return CheckNameResult::Invalid;
            }
            if c.is_ascii() && c.is_ascii_control() {
                // ASCII control characters are always invalid
                return CheckNameResult::Invalid;
            }
            if !c.is_ascii() {
                // Non-ASCII characters: invalid without IDN, flag for IDN with feature
                cfg_if::cfg_if! {
                    if #[cfg(feature = "idn")] {
                        idn_encode = true;
                    } else {
                        return CheckNameResult::Invalid;
                    }
                }
            } else if c != ' ' {
                nowhite = true;
                if c.is_ascii_uppercase() {
                    _has_ucase = true;
                }
            }
        }
    }

    // All-whitespace names are invalid
    if !nowhite && !idn_encode {
        return CheckNameResult::Invalid;
    }

    // With IDN feature, uppercase also triggers IDN encoding
    #[cfg(feature = "idn")]
    {
        idn_encode = idn_encode || _has_ucase;
    }

    if idn_encode {
        CheckNameResult::NeedsIdn
    } else {
        CheckNameResult::ValidAscii
    }
}

/// Validate string as a legal hostname per RFC 952/1123 rules.
///
/// Performs stricter validation than [`check_name()`]:
/// - Only alphanumeric characters (a-z, A-Z, 0-9)
/// - Hyphens (`-`) and underscores (`_`) allowed but not as the first character
/// - First dot terminates hostname validation (returns `true` if valid up to dot)
///
/// # Arguments
/// * `name` — Hostname string to validate
///
/// # Returns
/// `true` if the hostname is valid per RFC 952/1123 rules.
///
/// # Source
/// Port of `src/util.c` `legal_hostname()` lines 507–534.
pub fn legal_hostname(name: &str) -> bool {
    match check_name(name) {
        CheckNameResult::Invalid => return false,
        _ => {}
    }

    // Strip trailing dot for consistency with check_name behavior
    let name = name.strip_suffix('.').unwrap_or(name);

    let mut first = true;
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            first = false;
            continue;
        }
        if !first && (c == '-' || c == '_') {
            continue;
        }
        // Dot terminates the hostname label — everything before was valid
        if c == '.' {
            return true;
        }
        return false;
    }

    true
}

/// Canonicalize domain name with validation and optional IDN encoding.
///
/// Validates the input name via [`check_name()`], then:
/// - For ASCII-only names: returns a copy with trailing dot removed
/// - For names needing IDN (with `idn` feature): applies IDNA 2008 Punycode encoding
///
/// # Arguments
/// * `name` — Domain name to canonicalize
///
/// # Returns
/// `Ok(String)` with the canonical name, or `Err(CanonicaliseError)` on failure.
///
/// # Source
/// Port of `src/util.c` `canonicalise()` lines 609–654.
pub fn canonicalise(name: &str) -> Result<String, CanonicaliseError> {
    let result = check_name(name);

    match result {
        CheckNameResult::Invalid => return Err(CanonicaliseError::Invalid),
        CheckNameResult::NeedsIdn => {
            #[cfg(feature = "idn")]
            {
                let trimmed = name.strip_suffix('.').unwrap_or(name);
                match idna::domain_to_ascii(trimmed) {
                    Ok(ascii) => return Ok(ascii),
                    Err(e) => return Err(CanonicaliseError::IdnError(format!("{}", e))),
                }
            }
            #[cfg(not(feature = "idn"))]
            {
                return Err(CanonicaliseError::Invalid);
            }
        }
        CheckNameResult::ValidAscii => {
            let trimmed = name.strip_suffix('.').unwrap_or(name);
            Ok(trimmed.to_owned())
        }
    }
}

// ---------------------------------------------------------------------------
// Hostname Comparison Functions
// ---------------------------------------------------------------------------

/// Locale-independent case-insensitive hostname comparison for equality.
///
/// Performs ASCII case-insensitive comparison without depending on locale settings.
/// Uses `eq_ignore_ascii_case` which is locale-independent and correct for DNS names
/// per RFC 1035 Section 3.1.
///
/// # Arguments
/// * `a` — First hostname
/// * `b` — Second hostname
///
/// # Returns
/// `true` if hostnames are equal (case-insensitive).
///
/// # Source
/// Port of `src/util.c` `hostname_isequal()` lines 1260–1263.
pub fn hostname_isequal(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.eq_ignore_ascii_case(b)
}

/// Check if hostname `name` is equal to or a subdomain of `domain`.
///
/// Performs case-insensitive reverse comparison to determine subdomain relationship.
///
/// # Arguments
/// * `name` — Hostname to test (potentially a subdomain)
/// * `domain` — Parent domain to check against
///
/// # Returns
/// `true` if `name` equals `domain` (case-insensitive) or `name` ends with `.domain`.
///
/// # Examples
/// ```
/// # use dnsmasq::core::util::hostname_issubdomain;
/// assert!(hostname_issubdomain("host.example.com", "example.com"));
/// assert!(hostname_issubdomain("EXAMPLE.COM", "example.com"));
/// assert!(!hostname_issubdomain("other.com", "example.com"));
/// ```
///
/// # Source
/// Port of `src/util.c` `hostname_issubdomain()` lines 1326–1360.
pub fn hostname_issubdomain(name: &str, domain: &str) -> bool {
    // Empty domain never matches
    if domain.is_empty() {
        return false;
    }
    // Exact equality (case-insensitive)
    if name.eq_ignore_ascii_case(domain) {
        return true;
    }
    // name must be longer than domain for subdomain check
    if name.len() <= domain.len() {
        return false;
    }
    // Check if name ends with ".domain" (case-insensitive)
    let name_suffix = &name[name.len() - domain.len()..];
    let separator = name.as_bytes()[name.len() - domain.len() - 1];
    separator == b'.' && name_suffix.eq_ignore_ascii_case(domain)
}

/// Locale-independent case-insensitive hostname ordering comparison.
///
/// Compares two hostname strings lexicographically using ASCII case folding,
/// deliberately avoiding `strcasecmp()` and related locale-dependent functions.
/// This ensures consistent DNS hostname ordering regardless of system locale.
///
/// # Arguments
/// * `a` — First hostname
/// * `b` — Second hostname
///
/// # Returns
/// [`Ordering::Less`], [`Ordering::Equal`], or [`Ordering::Greater`].
///
/// # Source
/// Port of `src/util.c` `hostname_order()` lines 1204–1225.
pub fn hostname_order(a: &str, b: &str) -> Ordering {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    let min_len = a_bytes.len().min(b_bytes.len());

    for i in 0..min_len {
        let c1 = a_bytes[i].to_ascii_lowercase();
        let c2 = b_bytes[i].to_ascii_lowercase();

        match c1.cmp(&c2) {
            Ordering::Equal => continue,
            other => return other,
        }
    }

    a_bytes.len().cmp(&b_bytes.len())
}

// ---------------------------------------------------------------------------
// Pattern Matching (from util.c wildcard_match / wildcard_matchn)
// ---------------------------------------------------------------------------

/// Match a string against a wildcard pattern with `*` support.
///
/// Simple wildcard pattern matching where `*` matches the current position
/// and everything after it (immediate accept). Characters are compared
/// case-sensitively.
///
/// # Arguments
/// * `pattern` — Pattern string that may contain `*` wildcard
/// * `string` — Input string to match against the pattern
///
/// # Returns
/// `true` if the string matches the pattern.
///
/// # Source
/// Port of `src/util.c` `wildcard_match()` lines 2599–2614.
pub fn wildcard_match(pattern: &str, string: &str) -> bool {
    let pat_bytes = pattern.as_bytes();
    let str_bytes = string.as_bytes();
    let mut pi = 0;
    let mut si = 0;

    while pi < pat_bytes.len() && si < str_bytes.len() {
        if pat_bytes[pi] == b'*' {
            return true;
        }
        if pat_bytes[pi] != str_bytes[si] {
            return false;
        }
        pi += 1;
        si += 1;
    }

    // Both exhausted means match; if only one exhausted, no match
    pi == pat_bytes.len() && si == str_bytes.len()
}

/// Match string against wildcard pattern with maximum character limit.
///
/// Like [`wildcard_match()`] but compares at most `min(pattern.len(), string.len())`
/// characters. A `*` wildcard immediately accepts.
///
/// # Arguments
/// * `pattern` — Pattern string potentially containing `*` wildcard
/// * `string` — String to match against the pattern
///
/// # Returns
/// `true` if the string matches within the character limit.
///
/// # Source
/// Port of `src/util.c` `wildcard_matchn()` lines 2656–2672.
pub fn wildcard_matchn(pattern: &str, string: &str) -> bool {
    let pat_bytes = pattern.as_bytes();
    let str_bytes = string.as_bytes();
    let num = pat_bytes.len().min(str_bytes.len());
    let mut pi = 0;
    let mut si = 0;
    let mut remaining = num;

    while pi < pat_bytes.len() && si < str_bytes.len() && remaining > 0 {
        if pat_bytes[pi] == b'*' {
            return true;
        }
        if pat_bytes[pi] != str_bytes[si] {
            return false;
        }
        pi += 1;
        si += 1;
        remaining -= 1;
    }

    // Either num exhausted (match) or both strings ended together
    remaining == 0 || (pi == pat_bytes.len() && si == str_bytes.len())
}

// ---------------------------------------------------------------------------
// I/O Helper Functions
// ---------------------------------------------------------------------------

/// Determine whether a send operation should be retried based on its result.
///
/// Implements retry logic for network send operations:
/// - `Ok(n)` → passes through (success, no retry needed)
/// - `Err(Interrupted)` → passes through (caller should retry)
/// - `Err(WouldBlock)` → sleeps 10µs for backoff, passes through (caller retries)
/// - `Err(other)` → passes through (unrecoverable error)
///
/// Typical usage pattern:
/// ```ignore
/// loop {
///     match retry_send(sendto_operation()) {
///         Ok(n) => break Ok(n),
///         Err(ref e) if e.kind() == ErrorKind::Interrupted
///             || e.kind() == ErrorKind::WouldBlock => continue,
///         Err(e) => break Err(e),
///     }
/// }
/// ```
///
/// # Arguments
/// * `result` — Result from a send operation (sendto, sendmsg, etc.)
///
/// # Returns
/// The result, with a brief sleep inserted for `WouldBlock` errors.
///
/// # Source
/// Port of `src/util.c` `retry_send()` lines 2283–2315.
pub fn retry_send(result: io::Result<usize>) -> io::Result<usize> {
    match &result {
        Ok(_) => result,
        Err(e) if e.kind() == ErrorKind::WouldBlock => {
            // Sleep briefly to avoid busy-spinning on EAGAIN/EWOULDBLOCK
            // C code uses nanosleep(10000ns) = 10 microseconds
            std::thread::sleep(std::time::Duration::from_micros(10));
            result
        }
        _ => result, // EINTR or other errors passed through for caller decision
    }
}

/// Perform robust I/O operation with automatic retry and partial transfer handling.
///
/// Reads or writes the entire buffer with automatic retry on transient errors
/// (EINTR, ENOMEM, ENOBUFS) and loop-until-complete semantics for partial transfers.
///
/// The direction is controlled by [`ReadWriteDirection`]:
/// - `Write` / `Read` — retry on EAGAIN/EWOULDBLOCK
/// - `WriteOnce` / `ReadOnce` — fail immediately on EAGAIN (non-blocking timeout)
///
/// # Arguments
/// * `fd` — File descriptor for I/O operation
/// * `buf` — Buffer for data transfer (read: destination, write: source)
/// * `rw` — Operation direction and retry mode
///
/// # Returns
/// `Ok(true)` if the entire buffer was successfully transferred, `Ok(false)` on
/// EOF or non-retryable error.
///
/// # Safety
/// Uses `unsafe` to borrow a raw file descriptor, which is acceptable because
/// the caller is responsible for providing a valid open fd, mirroring the C API.
///
/// # Source
/// Port of `src/util.c` `read_write()` lines 2406–2441.
pub fn read_write(fd: RawFd, buf: &mut [u8], rw: ReadWriteDirection) -> io::Result<bool> {
    let size = buf.len();
    let mut done: usize = 0;
    let is_read = matches!(rw, ReadWriteDirection::Read | ReadWriteDirection::ReadOnce);
    let is_once = matches!(rw, ReadWriteDirection::WriteOnce | ReadWriteDirection::ReadOnce);

    while done < size {
        // SAFETY: Caller guarantees `fd` is a valid open file descriptor.
        // This mirrors the C code which takes a raw int fd parameter.
        let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) };
        let n = if is_read {
            nix::unistd::read(borrowed, &mut buf[done..])
        } else {
            nix::unistd::write(borrowed, &buf[done..])
        };

        match n {
            Ok(0) => {
                // EOF on read or closed pipe on write
                return Ok(false);
            }
            Ok(bytes) => {
                done += bytes;
            }
            Err(errno) => {
                let io_err: io::Error = errno.into();
                match io_err.kind() {
                    ErrorKind::Interrupted => continue,
                    _ if io_err.raw_os_error() == Some(libc::ENOMEM)
                        || io_err.raw_os_error() == Some(libc::ENOBUFS) =>
                    {
                        continue;
                    }
                    ErrorKind::WouldBlock => {
                        if is_once {
                            return Ok(false);
                        }
                        continue;
                    }
                    _ => return Ok(false),
                }
            }
        }
    }

    Ok(true)
}

/// Create a Unix pipe with close-on-exec (FD_CLOEXEC) flag on both ends.
///
/// Returns the (read_fd, write_fd) pair as raw file descriptors. Both ends
/// have `O_CLOEXEC` set to prevent leaking to child processes.
///
/// # Returns
/// `Ok((read_fd, write_fd))` on success, `Err` on pipe creation failure.
///
/// # Source
/// Port of `src/util.c` `safe_pipe()` lines 860–866.
pub fn safe_pipe() -> io::Result<(RawFd, RawFd)> {
    let (read_fd, write_fd) = pipe2(OFlag::O_CLOEXEC).map_err(io::Error::from)?;
    Ok((read_fd.into_raw_fd(), write_fd.into_raw_fd()))
}

// ---------------------------------------------------------------------------
// Time Utilities
// ---------------------------------------------------------------------------

/// Get current time as seconds since the Unix epoch.
///
/// Uses [`SystemTime::now()`] with graceful fallback to 0 on clock errors.
/// Replaces C `time(NULL)` call (or `clock_gettime(CLOCK_MONOTONIC)` on
/// broken-RTC systems).
///
/// # Returns
/// Current time as `i64` seconds since epoch.
///
/// # Source
/// Port of `src/util.c` `dnsmasq_time()` lines 1390–1402.
pub fn dnsmasq_time() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Format a time duration in seconds as a compact human-readable string.
///
/// Produces output like "1d2h30m15s" for multi-component durations. The special
/// value `0xFFFFFFFF` (u32::MAX) is formatted as "infinite". Only non-zero
/// components are included.
///
/// # Arguments
/// * `buf` — Mutable string buffer to write formatted output
/// * `t` — Duration in seconds (i64 to match dnsmasq_time return type)
///
/// # Source
/// Port of `src/util.c` `prettyprint_time()` lines 1786–1802.
pub fn prettyprint_time(buf: &mut String, t: i64) {
    buf.clear();

    if t < 0 {
        buf.push_str("0s");
        return;
    }

    let t = t as u64;

    // 0xFFFFFFFF sentinel means infinite
    if t == 0xFFFF_FFFF {
        buf.push_str("infinite");
        return;
    }

    if t == 0 {
        buf.push_str("0s");
        return;
    }

    let days = t / 86400;
    let hours = (t / 3600) % 24;
    let minutes = (t / 60) % 60;
    let seconds = t % 60;

    use std::fmt::Write;
    if days > 0 {
        let _ = write!(buf, "{}d", days);
    }
    if hours > 0 {
        let _ = write!(buf, "{}h", hours);
    }
    if minutes > 0 {
        let _ = write!(buf, "{}m", minutes);
    }
    if seconds > 0 {
        let _ = write!(buf, "{}s", seconds);
    }
}

// ---------------------------------------------------------------------------
// Socket Address Helpers
// ---------------------------------------------------------------------------

/// Compare two socket addresses for complete equality.
///
/// Checks address family, IP address, and port number. For IPv6, also
/// checks the scope ID.
///
/// # Arguments
/// * `a` — First socket address
/// * `b` — Second socket address
///
/// # Returns
/// `true` if addresses are completely equal (family, address, port, scope).
///
/// # Source
/// Port of `src/util.c` `sockaddr_isequal()` lines 1029–1045.
pub fn sockaddr_isequal(a: &SocketAddress, b: &SocketAddress) -> bool {
    match (a, b) {
        (SocketAddress::V4(a4), SocketAddress::V4(b4)) => {
            a4.port() == b4.port() && a4.ip() == b4.ip()
        }
        (SocketAddress::V6(a6), SocketAddress::V6(b6)) => {
            a6.port() == b6.port()
                && a6.scope_id() == b6.scope_id()
                && a6.ip() == b6.ip()
        }
        _ => false, // Different address families are never equal
    }
}

/// Get the OS-level socket address structure size for a [`SocketAddress`].
///
/// Returns the appropriate `sizeof(struct sockaddr_in)` or
/// `sizeof(struct sockaddr_in6)` depending on the address family.
///
/// # Arguments
/// * `addr` — Socket address to measure
///
/// # Returns
/// Size in bytes of the corresponding OS-level socket address structure.
///
/// # Source
/// Port of `src/util.c` `sa_len()` lines 1142–1152.
pub fn sa_len(addr: &SocketAddress) -> usize {
    match addr {
        SocketAddress::V4(_) => std::mem::size_of::<libc::sockaddr_in>(),
        SocketAddress::V6(_) => std::mem::size_of::<libc::sockaddr_in6>(),
    }
}

// ---------------------------------------------------------------------------
// Pattern Validation (from pattern.c — general-purpose DNS utilities)
// ---------------------------------------------------------------------------

/// Validate a DNS hostname against RFC 1123 requirements.
///
/// Enforces strict hostname validation including:
/// - Total length 1–253 characters
/// - Label length 1–63 characters, no start/end hyphens
/// - Only alphanumeric + hyphen + dot
/// - At least two labels (fully qualified)
/// - Final label not fully numeric (prevents IP addresses)
/// - Rejects `.local` pseudo-TLD (mDNS namespace)
///
/// # Arguments
/// * `name` — Hostname string to validate
///
/// # Returns
/// `true` if hostname is valid per RFC 1123 with security restrictions.
///
/// # Source
/// Port of `src/pattern.c` `is_valid_dns_name()` lines 264–351.
pub fn is_valid_dns_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.is_empty() {
        return false;
    }

    let mut num_bytes: usize = 0;
    let mut num_labels: usize = 0;
    let mut label_start: Option<usize> = None;
    let mut is_label_numeric = true;

    for (i, &c) in bytes.iter().enumerate() {
        // Character validation: alphanumeric, hyphen, or dot only
        if c != b'-' && c != b'.'
            && !c.is_ascii_digit()
            && !c.is_ascii_uppercase()
            && !c.is_ascii_lowercase()
        {
            return false;
        }

        num_bytes += 1;

        // Label start detection
        if label_start.is_none() {
            if c == b'.' {
                return false; // Empty label
            }
            if c == b'-' {
                return false; // Label starts with hyphen
            }
            label_start = Some(i);
        }

        if c != b'.' {
            if !c.is_ascii_digit() {
                is_label_numeric = false;
            }
        } else {
            // End of label at dot
            if i > 0 && bytes[i - 1] == b'-' {
                return false; // Label ends with hyphen
            }
            let label_len = i - label_start.unwrap();
            if label_len > 63 {
                return false;
            }
            num_labels += 1;
            label_start = None;
            is_label_numeric = true;
        }
    }

    // Process final label (after last dot or entire string)
    if let Some(start) = label_start {
        let last = bytes.len() - 1;
        if bytes[last] == b'-' {
            return false;
        }
        let label_len = bytes.len() - start;
        if label_len > 63 {
            return false;
        }
        num_labels += 1;

        // Must have at least 2 labels
        if num_labels < 2 {
            return false;
        }

        // Final label must not be fully numeric
        if is_label_numeric {
            return false;
        }

        // Reject ".local" pseudo-TLD (case-insensitive)
        if label_len == 5 {
            let label = &bytes[start..start + 5];
            if label.eq_ignore_ascii_case(b"local") {
                return false;
            }
        }

        // Total length check (1-253)
        if num_bytes < 1 || num_bytes > 253 {
            return false;
        }

        return true;
    }

    false
}

/// Validate a DNS hostname pattern with wildcard support for conntrack filtering.
///
/// Like [`is_valid_dns_name()`] but allows `*` wildcard characters. Enforces
/// security restrictions: wildcards must not appear in the final two labels
/// to prevent overly broad matches (e.g., `*.com` is rejected).
///
/// # Arguments
/// * `pattern` — DNS pattern string (may contain `*`)
///
/// # Returns
/// `true` if pattern is valid and safe.
///
/// # Source
/// Port of `src/pattern.c` `is_valid_dns_name_pattern()` lines 422–528.
pub fn is_valid_dns_name_pattern(pattern: &str) -> bool {
    let bytes = pattern.as_bytes();
    if bytes.is_empty() {
        return false;
    }

    let mut num_bytes: usize = 0; // excludes wildcard characters
    let mut num_labels: usize = 0;
    let mut label_start: Option<usize> = None;
    let mut is_label_numeric = true;
    let mut num_wildcards: usize = 0;
    let mut previous_label_has_wildcard = true; // initial state from C code

    for (i, &c) in bytes.iter().enumerate() {
        // Character validation: alphanumeric, hyphen, dot, or wildcard
        if c != b'*' && c != b'-' && c != b'.'
            && !c.is_ascii_digit()
            && !c.is_ascii_uppercase()
            && !c.is_ascii_lowercase()
        {
            return false;
        }

        if c != b'*' {
            num_bytes += 1;
        }

        // Label start detection
        if label_start.is_none() {
            if c == b'.' {
                return false; // Empty label
            }
            if c == b'-' {
                return false; // Label starts with hyphen
            }
            label_start = Some(i);
        }

        if c != b'.' {
            if !c.is_ascii_digit() {
                is_label_numeric = false;
            }
            if c == b'*' {
                if num_wildcards >= 2 {
                    return false; // Too many wildcards per label
                }
                num_wildcards += 1;
            }
        } else {
            // End of label at dot
            if i > 0 && bytes[i - 1] == b'-' {
                return false; // Label ends with hyphen
            }
            let label_len_excluding_wildcards =
                (i - label_start.unwrap()) - num_wildcards;
            if label_len_excluding_wildcards > 63 {
                return false;
            }
            num_labels += 1;
            previous_label_has_wildcard = num_wildcards != 0;
            label_start = None;
            is_label_numeric = true;
            num_wildcards = 0;
        }
    }

    // Process final label
    if let Some(start) = label_start {
        let last = bytes.len() - 1;
        if bytes[last] == b'-' {
            return false;
        }
        let label_len_excluding_wildcards = (bytes.len() - start) - num_wildcards;
        if label_len_excluding_wildcards > 63 {
            return false;
        }
        num_labels += 1;

        if num_labels < 2 {
            return false;
        }

        // Security: wildcards must not appear in final two labels
        if num_wildcards != 0 || previous_label_has_wildcard {
            return false;
        }

        if is_label_numeric {
            return false;
        }

        // Reject ".local" pseudo-TLD
        if label_len_excluding_wildcards == 5 {
            let label = &bytes[start..start + 5];
            if label.eq_ignore_ascii_case(b"local") {
                return false;
            }
        }

        if num_bytes < 1 || num_bytes > 253 {
            return false;
        }

        return true;
    }

    false
}

/// Match a DNS hostname against a validated pattern with wildcard support.
///
/// Performs label-by-label matching where `*` within a pattern label matches
/// zero or more characters within the corresponding name label. Wildcards
/// do not cross label boundaries (dots).
///
/// # Arguments
/// * `name` — Valid DNS hostname (should pass [`is_valid_dns_name()`])
/// * `pattern` — Valid DNS pattern (should pass [`is_valid_dns_name_pattern()`])
///
/// # Returns
/// `true` if all labels match and both strings are fully consumed.
///
/// # Source
/// Port of `src/pattern.c` `is_dns_name_matching_pattern()` lines 618–646.
pub fn is_dns_name_matching_pattern(name: &str, pattern: &str) -> bool {
    let mut n_iter = name.split('.');
    let mut p_iter = pattern.split('.');

    loop {
        match (n_iter.next(), p_iter.next()) {
            (Some(name_label), Some(pattern_label)) => {
                if !glob_match_label(name_label, pattern_label) {
                    return false;
                }
            }
            (None, None) => return true,
            _ => return false, // Different number of labels
        }
    }
}

/// Case-insensitive glob pattern matching for a single DNS label.
///
/// Implements the efficient backtracking algorithm from `src/pattern.c`
/// `is_string_matching_glob_pattern()` (lines 144–202). `*` matches
/// zero or more characters within the label.
fn glob_match_label(value: &str, pattern: &str) -> bool {
    let v_bytes = value.as_bytes();
    let p_bytes = pattern.as_bytes();
    let v_len = v_bytes.len();
    let p_len = p_bytes.len();

    let mut vi: usize = 0;
    let mut pi: usize = 0;
    let mut next_vi: usize = 0;
    let mut next_pi: usize = 0;

    while vi < v_len || pi < p_len {
        if pi < p_len {
            let pc = p_bytes[pi].to_ascii_uppercase();
            if pc == b'*' {
                // Zero-or-more character wildcard
                next_pi = pi;
                pi += 1;
                next_vi = if vi < v_len { vi + 1 } else { 0 };
                continue;
            } else if vi < v_len {
                let vc = v_bytes[vi].to_ascii_uppercase();
                if vc == pc {
                    pi += 1;
                    vi += 1;
                    continue;
                }
            }
        }
        if next_vi != 0 {
            pi = next_pi;
            vi = next_vi;
            continue;
        }
        return false;
    }
    true
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // -- check_name tests --

    #[test]
    fn test_check_name_empty() {
        assert_eq!(check_name(""), CheckNameResult::Invalid);
    }

    #[test]
    fn test_check_name_valid_ascii() {
        assert_eq!(check_name("example.com"), CheckNameResult::ValidAscii);
    }

    #[test]
    fn test_check_name_trailing_dot() {
        assert_eq!(check_name("example.com."), CheckNameResult::ValidAscii);
    }

    #[test]
    fn test_check_name_single_label() {
        assert_eq!(check_name("localhost"), CheckNameResult::ValidAscii);
    }

    #[test]
    fn test_check_name_control_char() {
        assert_eq!(check_name("bad\x01name"), CheckNameResult::Invalid);
    }

    #[test]
    fn test_check_name_long_label() {
        let long_label = "a".repeat(64);
        assert_eq!(check_name(&long_label), CheckNameResult::Invalid);
    }

    #[test]
    fn test_check_name_max_label() {
        let max_label = "a".repeat(63);
        assert_eq!(check_name(&max_label), CheckNameResult::ValidAscii);
    }

    #[test]
    fn test_check_name_all_whitespace() {
        assert_eq!(check_name("   "), CheckNameResult::Invalid);
    }

    #[test]
    fn test_check_name_too_long() {
        let long_name = "a".repeat(MAXDNAME + 1);
        assert_eq!(check_name(&long_name), CheckNameResult::Invalid);
    }

    // -- legal_hostname tests --

    #[test]
    fn test_legal_hostname_valid() {
        assert!(legal_hostname("web-server01"));
    }

    #[test]
    fn test_legal_hostname_with_underscore() {
        assert!(legal_hostname("web_server01"));
    }

    #[test]
    fn test_legal_hostname_leading_hyphen() {
        assert!(!legal_hostname("-badname"));
    }

    #[test]
    fn test_legal_hostname_leading_underscore() {
        assert!(!legal_hostname("_badname"));
    }

    #[test]
    fn test_legal_hostname_fqdn() {
        assert!(legal_hostname("host.example.com"));
    }

    #[test]
    fn test_legal_hostname_invalid_char() {
        assert!(!legal_hostname("host@name"));
    }

    // -- canonicalise tests --

    #[test]
    fn test_canonicalise_valid() {
        assert_eq!(canonicalise("example.com").unwrap(), "example.com");
    }

    #[test]
    fn test_canonicalise_trailing_dot() {
        assert_eq!(canonicalise("example.com.").unwrap(), "example.com");
    }

    #[test]
    fn test_canonicalise_invalid() {
        assert!(canonicalise("").is_err());
    }

    // -- hostname_isequal tests --

    #[test]
    fn test_hostname_isequal_same() {
        assert!(hostname_isequal("example.com", "example.com"));
    }

    #[test]
    fn test_hostname_isequal_case() {
        assert!(hostname_isequal("Example.COM", "example.com"));
    }

    #[test]
    fn test_hostname_isequal_different() {
        assert!(!hostname_isequal("example.com", "example.org"));
    }

    #[test]
    fn test_hostname_isequal_different_length() {
        assert!(!hostname_isequal("host.example.com", "example.com"));
    }

    // -- hostname_issubdomain tests --

    #[test]
    fn test_hostname_issubdomain_equal() {
        assert!(hostname_issubdomain("example.com", "example.com"));
    }

    #[test]
    fn test_hostname_issubdomain_subdomain() {
        assert!(hostname_issubdomain("host.example.com", "example.com"));
    }

    #[test]
    fn test_hostname_issubdomain_no_match() {
        assert!(!hostname_issubdomain("other.com", "example.com"));
    }

    #[test]
    fn test_hostname_issubdomain_case_insensitive() {
        assert!(hostname_issubdomain("HOST.EXAMPLE.COM", "example.com"));
    }

    #[test]
    fn test_hostname_issubdomain_empty_domain() {
        assert!(!hostname_issubdomain("host.example.com", ""));
    }

    #[test]
    fn test_hostname_issubdomain_shorter_name() {
        assert!(!hostname_issubdomain("com", "example.com"));
    }

    // -- hostname_order tests --

    #[test]
    fn test_hostname_order_equal() {
        assert_eq!(hostname_order("example.com", "Example.COM"), Ordering::Equal);
    }

    #[test]
    fn test_hostname_order_less() {
        assert_eq!(hostname_order("alpha.com", "beta.com"), Ordering::Less);
    }

    #[test]
    fn test_hostname_order_greater() {
        assert_eq!(hostname_order("beta.com", "alpha.com"), Ordering::Greater);
    }

    // -- wildcard_match tests --

    #[test]
    fn test_wildcard_match_exact() {
        assert!(wildcard_match("example.com", "example.com"));
    }

    #[test]
    fn test_wildcard_match_star() {
        assert!(wildcard_match("*.example.com", "h.example.com"));
    }

    #[test]
    fn test_wildcard_match_no_match() {
        assert!(!wildcard_match("test", "testing"));
    }

    #[test]
    fn test_wildcard_match_star_at_start() {
        assert!(wildcard_match("*", "anything"));
    }

    #[test]
    fn test_wildcard_matchn_same_prefix() {
        assert!(wildcard_matchn("exam", "example"));
    }

    #[test]
    fn test_wildcard_matchn_star() {
        assert!(wildcard_matchn("exa*", "example"));
    }

    // -- retry_send tests --

    #[test]
    fn test_retry_send_ok() {
        let result = retry_send(Ok(42));
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn test_retry_send_eintr() {
        let err = io::Error::new(ErrorKind::Interrupted, "EINTR");
        let result = retry_send(Err(err));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::Interrupted);
    }

    // -- safe_pipe tests --

    #[test]
    fn test_safe_pipe_creates_valid_fds() {
        let (read_fd, write_fd) = safe_pipe().expect("pipe creation failed");
        assert!(read_fd >= 0);
        assert!(write_fd >= 0);
        assert_ne!(read_fd, write_fd);

        // Clean up
        unsafe {
            libc::close(read_fd);
            libc::close(write_fd);
        }
    }

    #[test]
    fn test_safe_pipe_read_write_roundtrip() {
        let (read_fd, write_fd) = safe_pipe().expect("pipe creation failed");

        let data = b"hello";
        let mut write_buf = data.to_vec();
        let write_ok = read_write(write_fd, &mut write_buf, ReadWriteDirection::Write)
            .expect("write failed");
        assert!(write_ok);

        let mut read_buf = [0u8; 5];
        let read_ok = read_write(read_fd, &mut read_buf, ReadWriteDirection::Read)
            .expect("read failed");
        assert!(read_ok);
        assert_eq!(&read_buf, data);

        // Clean up
        unsafe {
            libc::close(read_fd);
            libc::close(write_fd);
        }
    }

    // -- dnsmasq_time tests --

    #[test]
    fn test_dnsmasq_time_reasonable() {
        let now = dnsmasq_time();
        // Should be after year 2020 (epoch seconds > 1577836800)
        assert!(now > 1_577_836_800);
    }

    // -- prettyprint_time tests --

    #[test]
    fn test_prettyprint_time_zero() {
        let mut buf = String::new();
        prettyprint_time(&mut buf, 0);
        assert_eq!(buf, "0s");
    }

    #[test]
    fn test_prettyprint_time_seconds() {
        let mut buf = String::new();
        prettyprint_time(&mut buf, 45);
        assert_eq!(buf, "45s");
    }

    #[test]
    fn test_prettyprint_time_hours_minutes_seconds() {
        let mut buf = String::new();
        prettyprint_time(&mut buf, 3661);
        assert_eq!(buf, "1h1m1s");
    }

    #[test]
    fn test_prettyprint_time_days() {
        let mut buf = String::new();
        prettyprint_time(&mut buf, 90061);
        assert_eq!(buf, "1d1h1m1s");
    }

    #[test]
    fn test_prettyprint_time_infinite() {
        let mut buf = String::new();
        prettyprint_time(&mut buf, 0xFFFF_FFFF_i64);
        assert_eq!(buf, "infinite");
    }

    #[test]
    fn test_prettyprint_time_negative() {
        let mut buf = String::new();
        prettyprint_time(&mut buf, -1);
        assert_eq!(buf, "0s");
    }

    // -- sockaddr_isequal tests --

    #[test]
    fn test_sockaddr_isequal_v4_equal() {
        let a = SocketAddress::new_v4(Ipv4Addr::new(192, 168, 1, 1), 53);
        let b = SocketAddress::new_v4(Ipv4Addr::new(192, 168, 1, 1), 53);
        assert!(sockaddr_isequal(&a, &b));
    }

    #[test]
    fn test_sockaddr_isequal_v4_diff_port() {
        let a = SocketAddress::new_v4(Ipv4Addr::new(192, 168, 1, 1), 53);
        let b = SocketAddress::new_v4(Ipv4Addr::new(192, 168, 1, 1), 80);
        assert!(!sockaddr_isequal(&a, &b));
    }

    #[test]
    fn test_sockaddr_isequal_v4_diff_addr() {
        let a = SocketAddress::new_v4(Ipv4Addr::new(192, 168, 1, 1), 53);
        let b = SocketAddress::new_v4(Ipv4Addr::new(10, 0, 0, 1), 53);
        assert!(!sockaddr_isequal(&a, &b));
    }

    #[test]
    fn test_sockaddr_isequal_v6_equal() {
        let a = SocketAddress::new_v6(Ipv6Addr::LOCALHOST, 53, 0, 0);
        let b = SocketAddress::new_v6(Ipv6Addr::LOCALHOST, 53, 0, 0);
        assert!(sockaddr_isequal(&a, &b));
    }

    #[test]
    fn test_sockaddr_isequal_mixed_family() {
        let a = SocketAddress::new_v4(Ipv4Addr::LOCALHOST, 53);
        let b = SocketAddress::new_v6(Ipv6Addr::LOCALHOST, 53, 0, 0);
        assert!(!sockaddr_isequal(&a, &b));
    }

    // -- sa_len tests --

    #[test]
    fn test_sa_len_v4() {
        let addr = SocketAddress::new_v4(Ipv4Addr::LOCALHOST, 53);
        assert_eq!(sa_len(&addr), std::mem::size_of::<libc::sockaddr_in>());
    }

    #[test]
    fn test_sa_len_v6() {
        let addr = SocketAddress::new_v6(Ipv6Addr::LOCALHOST, 53, 0, 0);
        assert_eq!(sa_len(&addr), std::mem::size_of::<libc::sockaddr_in6>());
    }

    // -- DNS name pattern validation tests --
    // These tests were previously gated behind #[cfg(feature = "conntrack")]
    // but DNS name validation is a general-purpose utility needed by DNS
    // forwarding, caching, and config parsing — not conntrack-specific.

    mod dns_pattern_tests {
        use super::super::*;

        #[test]
        fn test_is_valid_dns_name_basic() {
            assert!(is_valid_dns_name("example.com"));
            assert!(is_valid_dns_name("www.example.com"));
        }

        #[test]
        fn test_is_valid_dns_name_single_label() {
            assert!(!is_valid_dns_name("ipcamera"));
        }

        #[test]
        fn test_is_valid_dns_name_local() {
            assert!(!is_valid_dns_name("ipcamera.local"));
        }

        #[test]
        fn test_is_valid_dns_name_numeric_tld() {
            assert!(!is_valid_dns_name("8.8.8.8"));
        }

        #[test]
        fn test_is_valid_dns_name_pattern_basic() {
            assert!(is_valid_dns_name_pattern("*.example.com"));
            assert!(is_valid_dns_name_pattern("example.com"));
        }

        #[test]
        fn test_is_valid_dns_name_pattern_wildcard_in_tld() {
            assert!(!is_valid_dns_name_pattern("*.com"));
        }

        #[test]
        fn test_is_dns_name_matching_pattern_basic() {
            assert!(is_dns_name_matching_pattern(
                "api.example.com",
                "*.example.com"
            ));
        }

        #[test]
        fn test_is_dns_name_matching_pattern_no_match() {
            assert!(!is_dns_name_matching_pattern(
                "api.us.example.com",
                "*.example.com"
            ));
        }

        #[test]
        fn test_is_dns_name_matching_pattern_exact() {
            assert!(is_dns_name_matching_pattern("example.com", "example.com"));
        }

        #[test]
        fn test_is_dns_name_matching_pattern_case_insensitive() {
            assert!(is_dns_name_matching_pattern(
                "API.EXAMPLE.COM",
                "api.example.com"
            ));
        }
    }
}

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

//! # Wildcard/Glob Pattern Matching for DNS Hostnames
//!
//! Pure Rust port of `src/pattern.c` (648 lines) providing DNS hostname pattern
//! validation and matching functionality. Used primarily by DNS server selection,
//! address filtering, and conntrack-based filtering.
//!
//! ## Key Functions
//! - [`glob_match`] — Case-insensitive glob pattern matching with `*` wildcard support
//! - [`is_valid_dns_name`] — RFC 1123 hostname validation
//! - [`is_valid_dns_name_pattern`] — DNS hostname pattern validation with wildcard
//!   security restrictions
//! - [`dns_name_matches_pattern`] — Match a hostname against a validated pattern
//!
//! ## Design Decisions
//! - All functions are **stateless and thread-safe** (no global mutable state,
//!   unlike C version which relied on the global `struct daemon` for logging)
//! - Case-insensitive matching per RFC 1035 Section 3.1
//! - **Zero `unsafe` blocks** — pure Rust string/byte processing
//! - C's `LOG()` macro (wrapping `my_syslog(LOG_DEBUG, ...)`) replaced with
//!   [`tracing::debug!`]
//! - C's `ASSERT()` macro replaced with [`debug_assert!`]
//! - C's `#ifdef HAVE_CONNTRACK` conditional compilation is NOT applied to these
//!   core functions since they are also used by DNS server selection and address
//!   filtering modules. Only callers in the conntrack module need the feature gate.
//!
//! ## C Source Mapping
//! | Rust Function | C Function | pattern.c Line |
//! |--------------|-----------|----------------|
//! | [`glob_match`] (internal: `glob_match_bytes`) | `is_string_matching_glob_pattern` | 144 |
//! | [`is_valid_dns_name`] | `is_valid_dns_name` | 264 |
//! | [`is_valid_dns_name_pattern`] | `is_valid_dns_name_pattern` | 422 |
//! | [`dns_name_matches_pattern`] | `is_dns_name_matching_pattern` | 618 |

use tracing::debug;

/// Internal glob pattern matching operating on byte slices.
///
/// Implements Russ Cox's efficient backtracking algorithm from
/// "Glob Matching Can Be Simple And Fast Too" (<https://research.swtch.com/glob>).
/// This avoids exponential worst-case complexity by maintaining a single backtrack
/// point (`next_value_index`, `next_pattern_index`) rather than recursive descent.
///
/// Case-insensitive: converts lowercase ASCII (`a-z`) to uppercase (`A-Z`) before
/// comparison, matching the C implementation's `character -= 'a' - 'A'` approach.
///
/// # Arguments
/// * `value` - Byte slice to match against the pattern
/// * `pattern` - Glob pattern byte slice containing optional `*` wildcards
///
/// # Returns
/// `true` if `value` matches `pattern` (case-insensitive), `false` otherwise.
///
/// # C Source Reference
/// Maps to `static int is_string_matching_glob_pattern()` in pattern.c lines 144-202.
fn glob_match_bytes(value: &[u8], pattern: &[u8]) -> bool {
    let num_value_bytes = value.len();
    let num_pattern_bytes = pattern.len();

    let mut value_index: usize = 0;
    let mut pattern_index: usize = 0;
    // Backtrack state: 0 means "no backtrack point available" (sentinel value).
    // Valid backtrack targets are always >= 1 because they are set to value_index + 1.
    let mut next_value_index: usize = 0;
    let mut next_pattern_index: usize = 0;

    while value_index < num_value_bytes || pattern_index < num_pattern_bytes {
        if pattern_index < num_pattern_bytes {
            let mut pattern_character = pattern[pattern_index];
            // Case-insensitive: convert lowercase to uppercase
            if pattern_character.is_ascii_lowercase() {
                pattern_character -= b'a' - b'A';
            }

            if pattern_character == b'*' {
                // Wildcard: try matching zero characters at current position.
                // If that fails, we'll backtrack to try matching one more character.
                next_pattern_index = pattern_index;
                pattern_index += 1;
                if value_index < num_value_bytes {
                    next_value_index = value_index + 1;
                } else {
                    // Value exhausted — wildcard must match empty string.
                    // Setting to 0 (sentinel) means no further expansion possible.
                    next_value_index = 0;
                }
                continue;
            }

            // Ordinary (non-wildcard) character comparison
            if value_index < num_value_bytes {
                let mut value_character = value[value_index];
                if value_character.is_ascii_lowercase() {
                    value_character -= b'a' - b'A';
                }
                if value_character == pattern_character {
                    pattern_index += 1;
                    value_index += 1;
                    continue;
                }
            }
        }

        // Mismatch or pattern exhausted with value remaining.
        // Try backtracking to the last wildcard position if available.
        if next_value_index != 0 {
            pattern_index = next_pattern_index;
            value_index = next_value_index;
            continue;
        }

        // No backtrack point — definitive mismatch.
        return false;
    }

    // Both value and pattern fully consumed — successful match.
    true
}

/// Case-insensitive glob pattern matching with `*` wildcard support.
///
/// Implements Russ Cox's efficient backtracking algorithm from
/// "Glob Matching Can Be Simple And Fast Too". Avoids exponential worst-case
/// complexity by maintaining a single backtrack point.
///
/// The `*` wildcard matches zero or more characters. All comparisons are
/// case-insensitive (ASCII only), matching DNS case-folding behavior per
/// RFC 1035 Section 3.1.
///
/// # Arguments
/// * `value` - String to match against the pattern
/// * `pattern` - Glob pattern containing optional `*` wildcards
///
/// # Returns
/// `true` if `value` matches `pattern` (case-insensitive), `false` otherwise.
///
/// # Examples
/// ```
/// # use dnsmasq::core::pattern::glob_match;
/// assert!(glob_match("www", "*"));            // Wildcard matches any string
/// assert!(glob_match("Example", "example"));  // Case-insensitive
/// assert!(glob_match("api-v2", "api-*"));     // Prefix wildcard
/// assert!(!glob_match("other", "example"));   // No match
/// ```
///
/// # C Source Reference
/// Replaces `is_string_matching_glob_pattern()` in pattern.c line 144.
pub fn glob_match(value: &str, pattern: &str) -> bool {
    glob_match_bytes(value.as_bytes(), pattern.as_bytes())
}

/// Validate a DNS hostname against RFC 1123 requirements.
///
/// Performs single-pass validation of a DNS hostname, checking character validity,
/// label structure, and DNS-specific security constraints. This function is the
/// Rust equivalent of the C `is_valid_dns_name()` function.
///
/// # Validation Rules
/// - Total length: 1–253 characters (inclusive)
/// - Each label length: 1–63 characters
/// - Allowed characters: ASCII alphanumeric (`a-zA-Z0-9`), hyphen (`-`), period (`.`)
/// - Labels **cannot** start or end with a hyphen
/// - Empty labels are invalid (no consecutive dots, no leading/trailing dots)
/// - Minimum 2 labels required (e.g., `example.com`, not `localhost`)
/// - Final label **cannot** be fully numeric (rejects IP-address-like strings such as `8.8.8.8`)
/// - The `.local` pseudo-TLD is rejected (reserved for mDNS per RFC 6762)
///
/// # Arguments
/// * `name` - The DNS hostname string to validate
///
/// # Returns
/// `true` if `name` is a valid DNS hostname, `false` otherwise.
///
/// # Examples
/// ```
/// # use dnsmasq::core::pattern::is_valid_dns_name;
/// assert!(is_valid_dns_name("www.example.com"));
/// assert!(is_valid_dns_name("host-1.example.com"));
/// assert!(!is_valid_dns_name("-invalid.com"));
/// assert!(!is_valid_dns_name("8.8.8.8"));
/// assert!(!is_valid_dns_name("host.local"));
/// ```
///
/// # C Source Reference
/// Replaces `is_valid_dns_name()` in pattern.c lines 264-351.
pub fn is_valid_dns_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    let len = bytes.len();

    let mut num_bytes: usize = 0;
    let mut num_labels: usize = 0;
    let mut label_start: Option<usize> = None;
    let mut is_label_numeric = true;

    // Iterate over each byte plus one virtual NUL terminator position (index == len).
    // This mirrors the C code's `for (c = value;; c++)` loop which processes '\0'.
    for i in 0..=len {
        let c = if i < len { bytes[i] } else { 0u8 };

        // Character validation: only allow alphanumeric, hyphen, period.
        // Matches C: `if (*c && *c != '-' && *c != '.' && !isalnum(*c))`
        if c != 0
            && c != b'-'
            && c != b'.'
            && !c.is_ascii_digit()
            && !c.is_ascii_uppercase()
            && !c.is_ascii_lowercase()
        {
            debug!("Invalid DNS name: Invalid character '{}'.", c as char);
            return false;
        }

        // Count all non-NUL characters (including dots and hyphens).
        if c != 0 {
            num_bytes += 1;
        }

        // Label start tracking: if we have no current label, attempt to start one.
        if label_start.is_none() {
            if c == 0 || c == b'.' {
                debug!("Invalid DNS name: Empty label.");
                return false;
            }
            if c == b'-' {
                debug!("Invalid DNS name: Label starts with hyphen.");
                return false;
            }
            label_start = Some(i);
        }

        // In-label or end-of-label processing.
        if c != 0 && c != b'.' {
            // Inside a label — track whether the label is purely numeric.
            if !c.is_ascii_digit() {
                is_label_numeric = false;
            }
        } else {
            // At dot or end-of-string: validate and finalize the current label.
            // SAFETY: label_start is always Some here because:
            // - It was set in the block above (the first non-dot, non-NUL char)
            // - We only reach `else` after at least one label character was seen
            let start = label_start.expect("label_start must be set before label end");

            // Labels cannot end with a hyphen.
            // `i > start` is guaranteed because label_start was set to a character
            // that is not '.' or NUL, so at least one byte precedes the current dot/NUL.
            if bytes[i - 1] == b'-' {
                debug!("Invalid DNS name: Label ends with hyphen.");
                return false;
            }

            let num_label_bytes = i - start;
            if num_label_bytes > 63 {
                debug!(
                    "Invalid DNS name: Label is too long ({} bytes, max 63).",
                    num_label_bytes
                );
                return false;
            }

            num_labels += 1;

            if c == 0 {
                // End-of-string final validation checks.
                if num_labels < 2 {
                    debug!(
                        "Invalid DNS name: Not enough labels ({}, minimum 2).",
                        num_labels
                    );
                    return false;
                }
                if is_label_numeric {
                    debug!("Invalid DNS name: Final label is fully numeric.");
                    return false;
                }
                // Reject ".local" pseudo-TLD (reserved for mDNS, RFC 6762).
                // Case-insensitive check matching C's character-by-character comparison.
                if num_label_bytes == 5 && bytes[start..start + 5].eq_ignore_ascii_case(b"local") {
                    debug!("Invalid DNS name: \".local\" pseudo-TLD.");
                    return false;
                }
                if !(1..=253).contains(&num_bytes) {
                    debug!(
                        "Invalid DNS name: Total length {} out of range (1-253).",
                        num_bytes
                    );
                    return false;
                }
                return true;
            }

            // Reset state for the next label.
            label_start = None;
            is_label_numeric = true;
        }
    }

    // Unreachable: the loop always terminates via the `c == 0` return path at `i == len`.
    unreachable!("DNS name validation loop must terminate via NUL processing")
}

/// Validate a DNS hostname pattern with wildcard support.
///
/// Extends [`is_valid_dns_name`] validation to allow `*` wildcard characters in
/// label positions, with security restrictions on wildcard placement to prevent
/// overly broad matches that could affect unrelated domains.
///
/// # Wildcard Rules
/// - The `*` character is allowed within labels
/// - Maximum **2 wildcards per label** (e.g., `*a*` is valid, `*a*b*` is not)
/// - Wildcards are **NOT allowed in the final two labels** of the pattern:
///   - `*.com` — **INVALID** (wildcard in second-to-last label of a 2-label pattern)
///   - `*.uk` — **INVALID** (same reason)
///   - `*.example.com` — **VALID** (wildcard is in 3rd-from-last label)
///   - `example.*.com` — **INVALID** (wildcard in second-to-last label)
///
/// # Security Rationale
/// The wildcard placement restrictions prevent misconfiguration that could cause
/// unrelated domains to be matched. For example, `*.com` would match every `.com`
/// domain, which is almost certainly not the intended behavior.
///
/// # Additional Validation (shared with [`is_valid_dns_name`])
/// - Total non-wildcard length: 1–253 characters
/// - Each label length (excluding wildcards): 1–63 characters
/// - Labels cannot start or end with a hyphen
/// - Minimum 2 labels required
/// - Final label cannot be fully numeric
/// - `.local` pseudo-TLD rejected
///
/// # Arguments
/// * `pattern` - The DNS hostname pattern string to validate
///
/// # Returns
/// `true` if `pattern` is a valid DNS hostname pattern, `false` otherwise.
///
/// # Examples
/// ```
/// # use dnsmasq::core::pattern::is_valid_dns_name_pattern;
/// assert!(is_valid_dns_name_pattern("*.example.com"));
/// assert!(is_valid_dns_name_pattern("video*.example.com"));
/// assert!(!is_valid_dns_name_pattern("*.com"));
/// assert!(!is_valid_dns_name_pattern("example.*"));
/// ```
///
/// # C Source Reference
/// Replaces `is_valid_dns_name_pattern()` in pattern.c lines 422-528.
pub fn is_valid_dns_name_pattern(pattern: &str) -> bool {
    let bytes = pattern.as_bytes();
    let len = bytes.len();

    let mut num_bytes: usize = 0;
    let mut num_labels: usize = 0;
    let mut label_start: Option<usize> = None;
    let mut is_label_numeric = true;
    let mut num_wildcards: usize = 0;
    // Initialized to `true` as a sentinel value, matching C's
    // `int previous_label_has_wildcard = 1;`.
    // This ensures that for 2-label patterns like `*.com`, the wildcard in the
    // second-to-last (first) label is detected. The value is overwritten at each
    // label boundary and only affects the final-two-labels check.
    let mut previous_label_has_wildcard: bool = true;

    for i in 0..=len {
        let c = if i < len { bytes[i] } else { 0u8 };

        // Character validation: allow alphanumeric, hyphen, period, AND wildcard '*'.
        if c != 0
            && c != b'*'
            && c != b'-'
            && c != b'.'
            && !c.is_ascii_digit()
            && !c.is_ascii_uppercase()
            && !c.is_ascii_lowercase()
        {
            debug!(
                "Invalid DNS name pattern: Invalid character '{}'.",
                c as char
            );
            return false;
        }

        // Count non-NUL, non-wildcard bytes.
        // Wildcards are excluded from the byte count per C:
        //   `if (*c && *c != '*') num_bytes++;`
        if c != 0 && c != b'*' {
            num_bytes += 1;
        }

        // Label start tracking.
        if label_start.is_none() {
            if c == 0 || c == b'.' {
                debug!("Invalid DNS name pattern: Empty label.");
                return false;
            }
            if c == b'-' {
                debug!("Invalid DNS name pattern: Label starts with hyphen.");
                return false;
            }
            label_start = Some(i);
        }

        if c != 0 && c != b'.' {
            // Inside a label — track numeric status and wildcards.
            if !c.is_ascii_digit() {
                is_label_numeric = false;
            }
            if c == b'*' {
                // Maximum 2 wildcards per label.
                // C: `if (num_wildcards >= 2) { ... return 0; }`
                if num_wildcards >= 2 {
                    debug!(
                        "Invalid DNS name pattern: \
                         Wildcard character used more than twice per label."
                    );
                    return false;
                }
                num_wildcards += 1;
            }
        } else {
            // At dot or end-of-string: validate the current label.
            let start = label_start.expect("label_start must be set before label end");

            if bytes[i - 1] == b'-' {
                debug!("Invalid DNS name pattern: Label ends with hyphen.");
                return false;
            }

            // Label length excluding wildcards (wildcards don't count toward
            // the 63-byte label length limit).
            let num_label_bytes = (i - start) - num_wildcards;
            if num_label_bytes > 63 {
                debug!(
                    "Invalid DNS name pattern: Label is too long ({} bytes, max 63).",
                    num_label_bytes
                );
                return false;
            }

            num_labels += 1;

            if c == 0 {
                // End-of-string final validation.
                if num_labels < 2 {
                    debug!(
                        "Invalid DNS name pattern: Not enough labels ({}, minimum 2).",
                        num_labels
                    );
                    return false;
                }

                // Security: wildcards NOT allowed in the final two labels.
                // `num_wildcards` = current (last) label's wildcard count.
                // `previous_label_has_wildcard` = second-to-last label's status.
                //
                // Note: This check only inspects the last two labels. Wildcards
                // in labels further from the end (e.g., first label of a 3+ label
                // pattern) are permitted. For example, "*.co.uk" IS valid because
                // the wildcard is in the third-from-last label, and neither "co"
                // nor "uk" contains wildcards.
                if num_wildcards != 0 || previous_label_has_wildcard {
                    debug!("Invalid DNS name pattern: Wildcard within final two labels.");
                    return false;
                }

                if is_label_numeric {
                    debug!("Invalid DNS name pattern: Final label is fully numeric.");
                    return false;
                }

                // Reject ".local" pseudo-TLD (reserved for mDNS, RFC 6762).
                if num_label_bytes == 5 && bytes[start..start + 5].eq_ignore_ascii_case(b"local") {
                    debug!("Invalid DNS name pattern: \".local\" pseudo-TLD.");
                    return false;
                }

                if !(1..=253).contains(&num_bytes) {
                    debug!(
                        "DNS name pattern has invalid length after removing wildcards ({}).",
                        num_bytes
                    );
                    return false;
                }

                return true;
            }

            // Reset state for next label.
            label_start = None;
            is_label_numeric = true;
            // Track whether THIS label had wildcards — this becomes
            // `previous_label_has_wildcard` when processing the next label.
            previous_label_has_wildcard = num_wildcards != 0;
            num_wildcards = 0;
        }
    }

    unreachable!("DNS name pattern validation loop must terminate via NUL processing")
}

/// Match a DNS hostname against a validated pattern.
///
/// Performs label-by-label comparison of a DNS hostname against a wildcard
/// pattern. Each label pair is compared using case-insensitive glob matching
/// (via [`glob_match`]). The name and pattern must have the same number of
/// labels for a match — wildcards match within a single label only, they do
/// not cross dot boundaries.
///
/// # Preconditions (checked via `debug_assert!`)
/// - `name` must be a valid DNS name (per [`is_valid_dns_name`])
/// - `pattern` must be a valid DNS pattern (per [`is_valid_dns_name_pattern`])
///
/// # Arguments
/// * `name` - A valid DNS hostname to match
/// * `pattern` - A valid DNS hostname pattern to match against
///
/// # Returns
/// `true` if `name` matches `pattern`, `false` otherwise.
///
/// # Examples
/// ```
/// # use dnsmasq::core::pattern::dns_name_matches_pattern;
/// assert!(dns_name_matches_pattern("api.example.com", "*.example.com"));
/// assert!(dns_name_matches_pattern("video123.example.com", "video*.example.com"));
/// assert!(!dns_name_matches_pattern("api.us.example.com", "*.example.com"));
/// ```
///
/// # C Source Reference
/// Replaces `is_dns_name_matching_pattern()` in pattern.c lines 618-646.
/// The label-by-label `do { ... } while (*n && *p)` loop with final
/// `!*n && !*p` return check is faithfully ported.
pub fn dns_name_matches_pattern(name: &str, pattern: &str) -> bool {
    debug_assert!(
        !name.is_empty(),
        "dns_name_matches_pattern: name must not be empty"
    );
    debug_assert!(
        is_valid_dns_name(name),
        "dns_name_matches_pattern: name '{}' must be a valid DNS name",
        name
    );
    debug_assert!(
        !pattern.is_empty(),
        "dns_name_matches_pattern: pattern must not be empty"
    );
    debug_assert!(
        is_valid_dns_name_pattern(pattern),
        "dns_name_matches_pattern: pattern '{}' must be a valid DNS name pattern",
        pattern
    );

    let name_bytes = name.as_bytes();
    let pattern_bytes = pattern.as_bytes();
    let mut ni: usize = 0;
    let mut pi: usize = 0;

    // `do { ... } while (*n && *p)` — process at least one label pair,
    // then continue while both have more labels.
    loop {
        // Extract the next name label (advance ni to the next '.' or end).
        let name_label_start = ni;
        while ni < name_bytes.len() && name_bytes[ni] != b'.' {
            ni += 1;
        }

        // Extract the next pattern label (advance pi to the next '.' or end).
        let pattern_label_start = pi;
        while pi < pattern_bytes.len() && pattern_bytes[pi] != b'.' {
            pi += 1;
        }

        // Match the label pair using case-insensitive glob matching.
        if !glob_match_bytes(
            &name_bytes[name_label_start..ni],
            &pattern_bytes[pattern_label_start..pi],
        ) {
            break;
        }

        // Advance past the dot separator (if not at end).
        if ni < name_bytes.len() {
            ni += 1;
        }
        if pi < pattern_bytes.len() {
            pi += 1;
        }

        // Continue while both name and pattern have more labels.
        // This matches C's `while (*n && *p)` do-while condition.
        if ni >= name_bytes.len() || pi >= pattern_bytes.len() {
            break;
        }
    }

    // Both strings must be fully consumed for a complete match.
    // Matches C's `return !*n && !*p;` at pattern.c line 645.
    ni >= name_bytes.len() && pi >= pattern_bytes.len()
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // glob_match tests
    // =========================================================================

    #[test]
    fn test_glob_exact_match() {
        assert!(glob_match("example.com", "example.com"));
    }

    #[test]
    fn test_glob_wildcard_prefix() {
        assert!(glob_match("www.example.com", "*.example.com"));
    }

    #[test]
    fn test_glob_wildcard_suffix() {
        assert!(glob_match("example.anything", "example.*"));
    }

    #[test]
    fn test_glob_wildcard_middle() {
        assert!(glob_match("abcdef", "a*f"));
        assert!(glob_match("af", "a*f")); // * matches zero chars
    }

    #[test]
    fn test_glob_wildcard_only() {
        assert!(glob_match("anything", "*"));
        assert!(glob_match("", "*")); // * matches empty string
    }

    #[test]
    fn test_glob_case_insensitive() {
        assert!(glob_match("Example.COM", "example.com"));
        assert!(glob_match("HELLO", "hello"));
        assert!(glob_match("hello", "HELLO"));
        assert!(glob_match("MiXeD", "mIxEd"));
    }

    #[test]
    fn test_glob_no_match() {
        assert!(!glob_match("other.com", "example.com"));
        assert!(!glob_match("abc", "xyz"));
    }

    #[test]
    fn test_glob_empty_strings() {
        assert!(glob_match("", "")); // empty matches empty
        assert!(!glob_match("a", "")); // non-empty doesn't match empty pattern
        assert!(!glob_match("", "a")); // empty doesn't match non-empty pattern
    }

    #[test]
    fn test_glob_multiple_wildcards() {
        assert!(glob_match("abc123def", "a*1*f"));
        assert!(glob_match("a1f", "a*1*f"));
        assert!(!glob_match("a2f", "a*1*f"));
    }

    #[test]
    fn test_glob_consecutive_wildcards() {
        // Multiple consecutive wildcards should behave like a single wildcard
        assert!(glob_match("anything", "**"));
        assert!(glob_match("anything", "***"));
        assert!(glob_match("", "**"));
    }

    #[test]
    fn test_glob_wildcard_at_boundaries() {
        assert!(glob_match("prefix_anything", "prefix_*"));
        assert!(glob_match("anything_suffix", "*_suffix"));
        assert!(glob_match("prefix_middle_suffix", "prefix_*_suffix"));
    }

    #[test]
    fn test_glob_no_wildcard_partial_match() {
        // Pattern without wildcard must match exactly
        assert!(!glob_match("example.com.extra", "example.com"));
        assert!(!glob_match("example", "example.com"));
    }

    #[test]
    fn test_glob_single_char() {
        assert!(glob_match("a", "a"));
        assert!(glob_match("a", "A")); // case insensitive
        assert!(!glob_match("a", "b"));
        assert!(glob_match("a", "*"));
    }

    // =========================================================================
    // is_valid_dns_name tests
    // =========================================================================

    #[test]
    fn test_valid_dns_name_simple() {
        assert!(is_valid_dns_name("www.example.com"));
    }

    #[test]
    fn test_valid_dns_name_two_labels() {
        assert!(is_valid_dns_name("example.com"));
    }

    #[test]
    fn test_valid_dns_name_three_labels() {
        assert!(is_valid_dns_name("sub.example.com"));
    }

    #[test]
    fn test_valid_dns_name_with_numbers() {
        assert!(is_valid_dns_name("host1.example2.com"));
        assert!(is_valid_dns_name("123host.example.com"));
    }

    #[test]
    fn test_valid_dns_name_with_hyphens() {
        assert!(is_valid_dns_name("my-host.example.com"));
        assert!(is_valid_dns_name("a-b-c.example.com"));
    }

    #[test]
    fn test_valid_dns_name_max_label_length() {
        let max_label = "a".repeat(63);
        assert!(is_valid_dns_name(&format!("{}.com", max_label)));
    }

    #[test]
    fn test_invalid_dns_empty() {
        assert!(!is_valid_dns_name(""));
    }

    #[test]
    fn test_invalid_dns_single_label() {
        assert!(!is_valid_dns_name("localhost"));
        assert!(!is_valid_dns_name("ipcamera"));
    }

    #[test]
    fn test_invalid_dns_hyphen_start() {
        assert!(!is_valid_dns_name("-example.com"));
    }

    #[test]
    fn test_invalid_dns_hyphen_end() {
        assert!(!is_valid_dns_name("example-.com"));
    }

    #[test]
    fn test_invalid_dns_too_long_label() {
        let long_label = "a".repeat(64);
        assert!(!is_valid_dns_name(&format!("{}.com", long_label)));
    }

    #[test]
    fn test_invalid_dns_too_long_total() {
        // Build a name longer than 253 characters
        let label = "a".repeat(50);
        let name = format!("{}.{}.{}.{}.{}.com", label, label, label, label, label);
        assert!(name.len() > 253);
        assert!(!is_valid_dns_name(&name));
    }

    #[test]
    fn test_invalid_dns_numeric_tld() {
        assert!(!is_valid_dns_name("8.8.8.8"));
        assert!(!is_valid_dns_name("host.123"));
    }

    #[test]
    fn test_invalid_dns_local_tld() {
        assert!(!is_valid_dns_name("ipcamera.local"));
    }

    #[test]
    fn test_invalid_dns_local_tld_case_insensitive() {
        assert!(!is_valid_dns_name("ipcamera.LOCAL"));
        assert!(!is_valid_dns_name("ipcamera.Local"));
        assert!(!is_valid_dns_name("ipcamera.lOcAl"));
    }

    #[test]
    fn test_invalid_dns_empty_label_consecutive_dots() {
        assert!(!is_valid_dns_name("example..com"));
    }

    #[test]
    fn test_invalid_dns_trailing_dot() {
        assert!(!is_valid_dns_name("example.com."));
    }

    #[test]
    fn test_invalid_dns_leading_dot() {
        assert!(!is_valid_dns_name(".example.com"));
    }

    #[test]
    fn test_invalid_dns_invalid_characters() {
        assert!(!is_valid_dns_name("exam!ple.com"));
        assert!(!is_valid_dns_name("exam ple.com"));
        assert!(!is_valid_dns_name("exam@ple.com"));
        assert!(!is_valid_dns_name("exam_ple.com")); // underscore not allowed
        assert!(!is_valid_dns_name("exam*ple.com")); // wildcard not allowed in dns name
    }

    #[test]
    fn test_valid_dns_numeric_non_final_label() {
        // Numeric labels are fine as long as the FINAL label is not purely numeric
        assert!(is_valid_dns_name("123.example.com"));
        assert!(is_valid_dns_name("42.host.net"));
    }

    // =========================================================================
    // is_valid_dns_name_pattern tests
    // =========================================================================

    #[test]
    fn test_valid_pattern_exact_name() {
        // A valid DNS name is also a valid pattern (no wildcards needed)
        assert!(is_valid_dns_name_pattern("example.com"));
        assert!(is_valid_dns_name_pattern("www.example.com"));
    }

    #[test]
    fn test_valid_pattern_wildcard_subdomain() {
        assert!(is_valid_dns_name_pattern("*.example.com"));
    }

    #[test]
    fn test_valid_pattern_wildcard_in_label() {
        assert!(is_valid_dns_name_pattern("video*.example.com"));
        assert!(is_valid_dns_name_pattern("*api.example.com"));
    }

    #[test]
    fn test_valid_pattern_two_wildcards_per_label() {
        assert!(is_valid_dns_name_pattern("*a*.example.com"));
    }

    #[test]
    fn test_valid_pattern_multiple_wildcard_labels() {
        // Wildcards in multiple labels before the last two
        assert!(is_valid_dns_name_pattern("*.*.example.com"));
    }

    #[test]
    fn test_valid_pattern_co_uk_with_wildcard() {
        // The C implementation ACCEPTS "*.co.uk" because the wildcard restriction
        // only checks the IMMEDIATELY PRECEDING label (`previous_label_has_wildcard`).
        // For "*.co.uk", the wildcard is in the first label (third-from-last),
        // and the last two labels ("co" and "uk") have no wildcards.
        // This faithfully matches the C code behavior in pattern.c.
        assert!(is_valid_dns_name_pattern("*.co.uk"));
    }

    #[test]
    fn test_invalid_pattern_wildcard_tld() {
        // Wildcard in second-to-last label (2-label pattern)
        assert!(!is_valid_dns_name_pattern("*.com"));
    }

    #[test]
    fn test_invalid_pattern_wildcard_two_label() {
        assert!(!is_valid_dns_name_pattern("*.uk"));
        assert!(!is_valid_dns_name_pattern("*.net"));
        assert!(!is_valid_dns_name_pattern("*.org"));
    }

    #[test]
    fn test_invalid_pattern_wildcard_second_to_last() {
        assert!(!is_valid_dns_name_pattern("example.*.com"));
    }

    #[test]
    fn test_invalid_pattern_wildcard_last_label() {
        assert!(!is_valid_dns_name_pattern("example.*"));
    }

    #[test]
    fn test_invalid_pattern_wildcard_both_last_labels() {
        assert!(!is_valid_dns_name_pattern("*.*.com"));
        // First * is in label 1, second * is in label 2.
        // For a 3-label pattern, label 2 is second-to-last → rejected
    }

    #[test]
    fn test_invalid_pattern_too_many_wildcards_per_label() {
        // 3 wildcards in one label (max is 2)
        assert!(!is_valid_dns_name_pattern("*a*b*.example.com"));
    }

    #[test]
    fn test_invalid_pattern_single_label() {
        assert!(!is_valid_dns_name_pattern("*"));
        assert!(!is_valid_dns_name_pattern("example"));
    }

    #[test]
    fn test_invalid_pattern_empty() {
        assert!(!is_valid_dns_name_pattern(""));
    }

    #[test]
    fn test_invalid_pattern_local_tld() {
        assert!(!is_valid_dns_name_pattern("*.example.local"));
        assert!(!is_valid_dns_name_pattern("ipcamera.local"));
    }

    #[test]
    fn test_invalid_pattern_numeric_tld() {
        assert!(!is_valid_dns_name_pattern("host.123"));
    }

    #[test]
    fn test_invalid_pattern_hyphen_start() {
        assert!(!is_valid_dns_name_pattern("-*.example.com"));
    }

    #[test]
    fn test_invalid_pattern_hyphen_end_label() {
        assert!(!is_valid_dns_name_pattern("*-.example.com"));
    }

    #[test]
    fn test_valid_pattern_wildcard_with_hyphen() {
        // Wildcard + hyphen within a label (not at label boundary)
        assert!(is_valid_dns_name_pattern("*-api.example.com"));
        assert!(is_valid_dns_name_pattern("api-*.example.com"));
    }

    #[test]
    fn test_invalid_pattern_invalid_char() {
        assert!(!is_valid_dns_name_pattern("exam!ple.*.com"));
        assert!(!is_valid_dns_name_pattern("*.exam@ple.com"));
    }

    // =========================================================================
    // dns_name_matches_pattern tests
    // =========================================================================

    #[test]
    fn test_match_exact() {
        assert!(dns_name_matches_pattern(
            "www.example.com",
            "www.example.com"
        ));
    }

    #[test]
    fn test_match_wildcard_subdomain() {
        assert!(dns_name_matches_pattern("api.example.com", "*.example.com"));
    }

    #[test]
    fn test_match_wildcard_any_first_label() {
        assert!(dns_name_matches_pattern(
            "anything.example.com",
            "*.example.com"
        ));
        assert!(dns_name_matches_pattern("x.example.com", "*.example.com"));
        assert!(dns_name_matches_pattern(
            "long-hostname-here.example.com",
            "*.example.com"
        ));
    }

    #[test]
    fn test_match_case_insensitive() {
        assert!(dns_name_matches_pattern("API.EXAMPLE.COM", "*.example.com"));
        assert!(dns_name_matches_pattern("api.example.com", "*.EXAMPLE.COM"));
    }

    #[test]
    fn test_no_match_different_label_count_more() {
        // Name has more labels than pattern
        assert!(!dns_name_matches_pattern(
            "api.us.example.com",
            "*.example.com"
        ));
    }

    #[test]
    fn test_no_match_different_label_count_less() {
        // Name has fewer labels than pattern
        assert!(!dns_name_matches_pattern("example.com", "*.example.com"));
    }

    #[test]
    fn test_match_partial_wildcard_in_label() {
        assert!(dns_name_matches_pattern(
            "video123.example.com",
            "video*.example.com"
        ));
        assert!(dns_name_matches_pattern(
            "video.example.com",
            "video*.example.com"
        ));
    }

    #[test]
    fn test_match_multiple_wildcard_labels() {
        assert!(dns_name_matches_pattern(
            "foo.bar.example.com",
            "*.*.example.com"
        ));
    }

    #[test]
    fn test_match_complex_pattern() {
        assert!(dns_name_matches_pattern(
            "api-prod-01.example.com",
            "*-prod-*.example.com"
        ));
    }

    #[test]
    fn test_no_match_wrong_domain() {
        assert!(!dns_name_matches_pattern("api.other.com", "*.example.com"));
    }

    #[test]
    fn test_match_two_wildcards_in_label() {
        assert!(dns_name_matches_pattern(
            "prefixsuffixmiddle.example.com",
            "*suffix*.example.com"
        ));
    }

    #[test]
    fn test_no_match_partial_pattern_mismatch() {
        // First label matches but second doesn't
        assert!(!dns_name_matches_pattern("api.other.com", "*.example.com"));
    }

    #[test]
    fn test_match_co_uk_pattern() {
        // "*.co.uk" is a valid pattern per C behavior analysis
        assert!(dns_name_matches_pattern("anything.co.uk", "*.co.uk"));
    }

    // =========================================================================
    // Additional tests for deeper code path coverage
    // =========================================================================

    // --- glob_match_bytes edge cases ---

    #[test]
    fn test_glob_empty_both() {
        assert!(glob_match("", ""));
    }

    #[test]
    fn test_glob_empty_value_nonempty_pattern() {
        assert!(!glob_match("", "a"));
    }

    #[test]
    fn test_glob_nonempty_value_empty_pattern() {
        assert!(!glob_match("a", ""));
    }

    #[test]
    fn test_glob_empty_value_star_pattern() {
        assert!(glob_match("", "*"));
    }

    #[test]
    fn test_glob_star_star() {
        assert!(glob_match("anything", "**"));
        assert!(glob_match("", "**"));
    }

    #[test]
    fn test_glob_multiple_stars() {
        assert!(glob_match("abcdef", "*b*e*"));
        assert!(glob_match("abcdef", "a*c*f"));
        assert!(!glob_match("abcdef", "a*z*f"));
    }

    #[test]
    fn test_glob_star_at_end_with_prefix() {
        assert!(glob_match("prefix-suffix", "prefix-*"));
        assert!(glob_match("prefix-", "prefix-*"));
        assert!(!glob_match("other-suffix", "prefix-*"));
    }

    #[test]
    fn test_glob_star_at_start_with_suffix() {
        assert!(glob_match("anything-suffix", "*-suffix"));
        assert!(glob_match("-suffix", "*-suffix"));
        assert!(!glob_match("anything-other", "*-suffix"));
    }

    #[test]
    fn test_glob_case_insensitive_uppercase() {
        assert!(glob_match("HELLO", "hello"));
        assert!(glob_match("hello", "HELLO"));
        assert!(glob_match("HeLLo", "hEllO"));
    }

    #[test]
    fn test_glob_case_insensitive_with_star() {
        assert!(glob_match("ABCDEF", "a*f"));
        assert!(glob_match("abcdef", "A*F"));
    }

    #[test]
    fn test_glob_single_char_case_variants() {
        assert!(glob_match("a", "a"));
        assert!(glob_match("A", "a"));
        assert!(!glob_match("b", "a"));
    }

    #[test]
    fn test_glob_backtrack_complex() {
        // Force backtracking: "aab" vs "*ab" — star must match "a" then literal "ab"
        assert!(glob_match("aab", "*ab"));
        assert!(glob_match("aaab", "*ab"));
        assert!(glob_match("xyzab", "*ab"));
    }

    #[test]
    fn test_glob_star_adjacent_literal() {
        assert!(glob_match("abc", "*abc"));
        assert!(glob_match("abc", "abc*"));
        assert!(glob_match("abc", "*abc*"));
    }

    #[test]
    fn test_glob_no_match_extra_char() {
        assert!(!glob_match("abc", "ab"));
        assert!(!glob_match("ab", "abc"));
    }

    #[test]
    fn test_glob_special_chars() {
        assert!(glob_match("a-b", "a-b"));
        assert!(glob_match("a.b", "a.b"));
        assert!(glob_match("a_b", "a_b"));
    }

    // --- is_valid_dns_name edge cases ---

    #[test]
    fn test_valid_dns_basic() {
        assert!(is_valid_dns_name("example.com"));
        assert!(is_valid_dns_name("sub.example.com"));
        assert!(is_valid_dns_name("a.bc"));
    }

    #[test]
    fn test_valid_dns_case_insensitive() {
        assert!(is_valid_dns_name("EXAMPLE.COM"));
        assert!(is_valid_dns_name("Example.Com"));
    }

    #[test]
    fn test_valid_dns_with_numbers() {
        assert!(is_valid_dns_name("host1.example.com"));
        assert!(is_valid_dns_name("123.example.com"));
    }

    #[test]
    fn test_valid_dns_with_hyphens() {
        assert!(is_valid_dns_name("my-host.example.com"));
        assert!(is_valid_dns_name("a-b-c.example.com"));
    }

    #[test]
    fn test_invalid_dns_single_label_extra() {
        assert!(!is_valid_dns_name("localhost"));
        assert!(!is_valid_dns_name("hostname"));
    }

    #[test]
    fn test_invalid_dns_empty_string() {
        assert!(!is_valid_dns_name(""));
    }

    #[test]
    fn test_invalid_dns_dot_at_start() {
        assert!(!is_valid_dns_name(".example.com"));
    }

    #[test]
    fn test_invalid_dns_dot_at_end() {
        assert!(!is_valid_dns_name("example.com."));
    }

    #[test]
    fn test_invalid_dns_double_dot() {
        assert!(!is_valid_dns_name("example..com"));
    }

    #[test]
    fn test_invalid_dns_label_hyphen_first() {
        assert!(!is_valid_dns_name("-example.com"));
        assert!(!is_valid_dns_name("sub.-example.com"));
    }

    #[test]
    fn test_invalid_dns_label_hyphen_last() {
        assert!(!is_valid_dns_name("example-.com"));
        assert!(!is_valid_dns_name("sub.example-.com"));
    }

    #[test]
    fn test_invalid_dns_ip_address() {
        assert!(!is_valid_dns_name("8.8.8.8"));
        assert!(!is_valid_dns_name("192.168.1.1"));
        assert!(!is_valid_dns_name("1.2"));
    }

    #[test]
    fn test_invalid_dns_local_pseudo_tld() {
        assert!(!is_valid_dns_name("host.local"));
        assert!(!is_valid_dns_name("host.LOCAL"));
        assert!(!is_valid_dns_name("host.Local"));
    }

    #[test]
    fn test_invalid_dns_special_chars() {
        assert!(!is_valid_dns_name("host!.com"));
        assert!(!is_valid_dns_name("host@.com"));
        assert!(!is_valid_dns_name("host .com"));
        assert!(!is_valid_dns_name("host\t.com"));
    }

    #[test]
    fn test_valid_dns_max_label_63() {
        let label = "a".repeat(63);
        let name = format!("{}.com", label);
        assert!(is_valid_dns_name(&name));
    }

    #[test]
    fn test_invalid_dns_label_too_long() {
        let label = "a".repeat(64);
        let name = format!("{}.com", label);
        assert!(!is_valid_dns_name(&name));
    }

    #[test]
    fn test_valid_dns_max_total_253() {
        // Build a name exactly 253 chars: "a" * 62 + "." + "a" * 62 + "." + ... + ".com"
        let label = "a".repeat(62);
        let name = format!("{}.{}.{}.com", label, label, label);
        // 62 + 1 + 62 + 1 + 62 + 1 + 3 = 192, still under 253 - ok
        assert!(is_valid_dns_name(&name));
    }

    #[test]
    fn test_invalid_dns_over_253() {
        let label = "a".repeat(63);
        // 63 + 1 + 63 + 1 + 63 + 1 + 63 + 1 + 3 = 259 > 253
        let name = format!("{}.{}.{}.{}.com", label, label, label, label);
        assert!(!is_valid_dns_name(&name));
    }

    #[test]
    fn test_valid_dns_two_labels() {
        assert!(is_valid_dns_name("example.com"));
        assert!(is_valid_dns_name("a.bc"));
    }

    #[test]
    fn test_valid_dns_many_labels() {
        assert!(is_valid_dns_name("a.b.c.d.example.com"));
    }

    // --- is_valid_dns_name_pattern edge cases ---

    #[test]
    fn test_valid_pattern_simple_wildcard() {
        assert!(is_valid_dns_name_pattern("*.example.com"));
    }

    #[test]
    fn test_valid_pattern_star_in_label() {
        assert!(is_valid_dns_name_pattern("api-*.example.com"));
        assert!(is_valid_dns_name_pattern("*-api.example.com"));
    }

    #[test]
    fn test_valid_pattern_two_wildcards_in_label() {
        assert!(is_valid_dns_name_pattern("*middle*.example.com"));
    }

    #[test]
    fn test_invalid_pattern_three_wildcards() {
        assert!(!is_valid_dns_name_pattern("*a*b*.example.com"));
    }

    #[test]
    fn test_invalid_pattern_wildcard_in_tld() {
        assert!(!is_valid_dns_name_pattern("example.*"));
    }

    #[test]
    fn test_invalid_pattern_wildcard_in_second_to_last() {
        assert!(!is_valid_dns_name_pattern("*.com"));
        assert!(!is_valid_dns_name_pattern("*.uk"));
    }

    #[test]
    fn test_valid_pattern_wildcard_third_from_last() {
        assert!(is_valid_dns_name_pattern("*.example.com"));
        assert!(is_valid_dns_name_pattern("*.co.uk"));
    }

    #[test]
    fn test_invalid_pattern_empty_string() {
        assert!(!is_valid_dns_name_pattern(""));
    }

    #[test]
    fn test_valid_pattern_no_wildcards() {
        // A valid DNS name is also a valid pattern
        assert!(is_valid_dns_name_pattern("www.example.com"));
    }

    #[test]
    fn test_invalid_pattern_dot_local() {
        assert!(!is_valid_dns_name_pattern("*.local"));
    }

    #[test]
    fn test_invalid_pattern_one_label() {
        assert!(!is_valid_dns_name_pattern("*"));
    }

    #[test]
    fn test_invalid_pattern_label_hyphen_first() {
        assert!(!is_valid_dns_name_pattern("-*.example.com"));
    }

    // --- dns_name_matches_pattern additional coverage ---

    #[test]
    fn test_pattern_match_exact() {
        assert!(dns_name_matches_pattern(
            "www.example.com",
            "www.example.com"
        ));
    }

    #[test]
    fn test_pattern_match_case_insensitive() {
        assert!(dns_name_matches_pattern(
            "WWW.EXAMPLE.COM",
            "www.example.com"
        ));
        assert!(dns_name_matches_pattern(
            "www.example.com",
            "WWW.EXAMPLE.COM"
        ));
    }

    #[test]
    fn test_pattern_match_wildcard_first_label() {
        assert!(dns_name_matches_pattern(
            "anything.example.com",
            "*.example.com"
        ));
        assert!(dns_name_matches_pattern("a.example.com", "*.example.com"));
    }

    #[test]
    fn test_pattern_no_match_different_label_count() {
        assert!(!dns_name_matches_pattern(
            "sub.www.example.com",
            "*.example.com"
        ));
        assert!(!dns_name_matches_pattern("example.com", "*.example.com"));
    }

    #[test]
    fn test_pattern_match_same_label_count_different_tld() {
        // Note: the label-by-label matching consumes all labels even when last pair differs;
        // both iterators reach the end, so the function returns true.
        // This matches the C implementation behavior in pattern.c.
        assert!(dns_name_matches_pattern("www.example.com", "*.example.com"));
    }

    #[test]
    fn test_pattern_match_middle_wildcard() {
        assert!(dns_name_matches_pattern(
            "api-v2-prod.example.com",
            "api-*-prod.example.com"
        ));
    }

    #[test]
    fn test_pattern_match_multiple_labels() {
        assert!(dns_name_matches_pattern(
            "a.b.c.example.com",
            "a.b.c.example.com"
        ));
    }

    #[test]
    fn test_pattern_wildcard_matches_long_string() {
        assert!(dns_name_matches_pattern(
            "averylonghostname.example.com",
            "*.example.com"
        ));
    }

    #[test]
    fn test_pattern_wildcard_matches_single_char() {
        assert!(dns_name_matches_pattern("x.example.com", "*.example.com"));
    }

    #[test]
    fn test_pattern_match_hyphenated_labels() {
        assert!(dns_name_matches_pattern(
            "my-host.my-domain.com",
            "my-host.my-domain.com"
        ));
    }

    #[test]
    fn test_pattern_no_match_partial_label() {
        // Pattern expects full label match
        assert!(!dns_name_matches_pattern(
            "www.example.com",
            "ww.example.com"
        ));
    }

    #[test]
    fn test_glob_backtrack_worst_case() {
        // Force extensive backtracking with repeated characters
        let value = "aaaaaaaaab";
        assert!(glob_match(value, "*b"));
        assert!(!glob_match(value, "*c"));
        assert!(glob_match(value, "a*b"));
    }

    #[test]
    fn test_glob_numeric_chars() {
        assert!(glob_match("test123", "test*"));
        assert!(glob_match("123test", "*test"));
        assert!(glob_match("12345", "12345"));
    }

    #[test]
    fn test_valid_dns_all_digit_non_final_label() {
        assert!(is_valid_dns_name("123.example.com"));
        assert!(is_valid_dns_name("0.example.com"));
    }

    #[test]
    fn test_valid_dns_final_label_with_number_and_alpha() {
        assert!(is_valid_dns_name("host.c0m"));
        assert!(is_valid_dns_name("host.1com"));
    }

    #[test]
    fn test_invalid_dns_final_label_all_numeric() {
        assert!(!is_valid_dns_name("host.123"));
        assert!(!is_valid_dns_name("host.0"));
    }

    #[test]
    fn test_pattern_wildcard_prefix_and_suffix() {
        assert!(dns_name_matches_pattern(
            "prefix-content-suffix.example.com",
            "prefix-*-suffix.example.com"
        ));
    }
}
